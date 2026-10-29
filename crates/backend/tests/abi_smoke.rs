use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use onyx_backend::{
    onyx_aa_analyze, onyx_aa_parse, onyx_abi_free_string, onyx_hook_engine_free,
    onyx_hook_engine_install, onyx_hook_engine_len, onyx_hook_engine_new,
    onyx_hook_engine_remove_by_name, onyx_manual_map_dll,
};

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

#[test]
fn aa_parse_simple_returns_json() {
    let src = cstr("[ENABLE]\nalloc(mem,1024)\nregistersymbol(mem)\n[DISABLE]\ndealloc(mem)\n");
    let mut out: *mut c_char = ptr::null_mut();
    let rc = unsafe { onyx_aa_parse(src.as_ptr(), &mut out) };
    assert_eq!(rc, 0, "parse should succeed");
    assert!(!out.is_null());
    let json_text = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_string();
    unsafe { onyx_abi_free_string(out) };
    let v: serde_json::Value = serde_json::from_str(&json_text).unwrap();
    assert!(v.get("sections").is_some(), "json contains sections");
    let sections = v["sections"].as_array().unwrap();
    assert!(!sections.is_empty());
}

#[test]
fn aa_analyze_valid_script_ok() {
    let src = cstr("[ENABLE]\nalloc(mem,1024)\n[DISABLE]\ndealloc(mem)\n");
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe { onyx_aa_analyze(src.as_ptr(), &mut err) };
    if !err.is_null() {
        let s = unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned();
        unsafe { onyx_abi_free_string(err) };
        panic!("analyze failed: {}", s);
    }
    assert_eq!(rc, 0);
}

#[test]
fn aa_analyze_invalid_script_fails() {
    let src = cstr("[ENABLE]\ndealloc(nao_existe)\n[DISABLE]\n");
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe { onyx_aa_analyze(src.as_ptr(), &mut err) };
    assert_ne!(rc, 0);
    if !err.is_null() {
        let _s = unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned();
        unsafe { onyx_abi_free_string(err) };
    }
}

#[test]
fn aa_parse_null_input_errors() {
    let mut out: *mut c_char = ptr::null_mut();
    let rc = unsafe { onyx_aa_parse(ptr::null(), &mut out) };
    assert!(rc < 0);
}

#[test]
fn hook_engine_create_and_free_roundtrip() {
    let engine = onyx_hook_engine_new();
    assert!(!engine.is_null());
    assert_eq!(unsafe { onyx_hook_engine_len(engine) }, 0);
    unsafe { onyx_hook_engine_free(engine) };
}

#[cfg(windows)]
#[test]
fn hook_engine_install_and_remove_on_live_fn() {
    use std::ffi::c_void;

    #[inline(never)]
    #[no_mangle]
    extern "C" fn abi_test_target_fn() -> i32 {
        let mut acc: i32 = 1;
        for i in 0..8 {
            acc = acc.wrapping_add(i);
        }
        acc
    }

    #[inline(never)]
    #[no_mangle]
    extern "C" fn abi_test_hook_fn() -> i32 {
        777
    }

    let target_ptr = abi_test_target_fn as *const c_void;
    let hook_ptr = abi_test_hook_fn as *const c_void;

    let engine = onyx_hook_engine_new();
    assert!(!engine.is_null());

    let name = cstr("abi_test_hook");
    let mut orig: *const c_void = ptr::null();
    let rc = unsafe {
        onyx_hook_engine_install(engine, name.as_ptr(), target_ptr, hook_ptr, &mut orig)
    };
    assert_eq!(rc, 0, "install should succeed");
    assert!(!orig.is_null());
    assert_eq!(unsafe { onyx_hook_engine_len(engine) }, 1);

    let fp_raw = std::hint::black_box(target_ptr);
    let fp: extern "C" fn() -> i32 = unsafe {
        std::mem::transmute::<*const c_void, extern "C" fn() -> i32>(fp_raw)
    };
    let patched_val = std::hint::black_box(fp)();
    assert_eq!(patched_val, 777, "redirected call must return hook value");

    let rc = unsafe { onyx_hook_engine_remove_by_name(engine, name.as_ptr()) };
    assert_eq!(rc, 0, "remove should succeed");
    assert_eq!(unsafe { onyx_hook_engine_len(engine) }, 0);

    unsafe { onyx_hook_engine_free(engine) };
}

#[test]
fn manual_map_stub_returns_not_implemented() {
    let path = cstr("fake.dll");
    let rc = onyx_manual_map_dll(0, path.as_ptr());
    assert_eq!(rc, -99);
}

#[test]
fn gdb_abi_roundtrip_with_mock_target() {
    use onyx_backend::{onyx_gdb_start, onyx_gdb_stop, OnyxGdbRegisters, OnyxGdbTargetVTable};
    use std::ffi::c_void;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::{Arc, Mutex};

    struct Backing {
        regs: OnyxGdbRegisters,
    }

    static MEM: std::sync::OnceLock<Arc<Mutex<Backing>>> = std::sync::OnceLock::new();

    fn backing() -> Arc<Mutex<Backing>> {
        MEM.get_or_init(|| {
            Arc::new(Mutex::new(Backing {
                regs: OnyxGdbRegisters {
                    rax: 0xdead_beef, rbx: 0, rcx: 0, rdx: 0,
                    rsi: 0, rdi: 0, rbp: 0, rsp: 0,
                    r8: 0, r9: 0, r10: 0, r11: 0, r12: 0, r13: 0, r14: 0, r15: 0,
                    rip: 0x1000,
                },
            }))
        })
        .clone()
    }

    unsafe extern "C" fn read_regs(_user: *mut c_void, out: *mut OnyxGdbRegisters) -> i32 {
        let b = backing();
        let g = b.lock().unwrap();
        *out = g.regs;
        0
    }
    unsafe extern "C" fn write_regs(_user: *mut c_void, regs: *const OnyxGdbRegisters) -> i32 {
        let b = backing();
        let mut g = b.lock().unwrap();
        g.regs = *regs;
        0
    }
    unsafe extern "C" fn read_mem(_user: *mut c_void, _addr: u64, out_buf: *mut u8, len: usize) -> i32 {
        for i in 0..len {
            *out_buf.add(i) = 0xAB;
        }
        0
    }
    unsafe extern "C" fn write_mem(_user: *mut c_void, _addr: u64, _buf: *const u8, _len: usize) -> i32 {
        0
    }

    let vt = OnyxGdbTargetVTable {
        read_registers: Some(read_regs),
        write_registers: Some(write_regs),
        read_memory: Some(read_mem),
        write_memory: Some(write_mem),
        cont: None,
        step: None,
        add_sw_breakpoint: None,
        remove_sw_breakpoint: None,
        add_hw_breakpoint: None,
        remove_hw_breakpoint: None,
    };

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let endpoint = format!("127.0.0.1:{}", port);
    let addr = cstr(&endpoint);

    let mut handle: *mut c_void = ptr::null_mut();
    let rc = unsafe { onyx_gdb_start(addr.as_ptr(), &vt, ptr::null_mut(), &mut handle) };
    assert_eq!(rc, 0, "gdb start");
    assert!(!handle.is_null());

    let mut stream = None;
    for _ in 0..50 {
        if let Ok(s) = TcpStream::connect(&endpoint) {
            stream = Some(s);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let mut stream = stream.expect("gdb server accept");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();

    fn pkt(payload: &[u8]) -> Vec<u8> {
        let sum: u32 = payload.iter().map(|b| *b as u32).sum::<u32>() & 0xff;
        let mut v = vec![b'$'];
        v.extend_from_slice(payload);
        v.push(b'#');
        v.extend_from_slice(format!("{:02x}", sum).as_bytes());
        v
    }

    fn read_until<F: Fn(&str) -> bool>(stream: &mut TcpStream, want: F) -> String {
        let mut acc = String::new();
        let mut buf = [0u8; 1024];
        for _ in 0..40 {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if want(&acc) {
                        return acc;
                    }
                }
                Err(_) => break,
            }
        }
        acc
    }

    stream.write_all(&pkt(b"?")).unwrap();
    let resp = read_until(&mut stream, |s| s.contains("$S05"));
    assert!(resp.contains("$S05"), "stop reason reply, got {:?}", resp);
    stream.write_all(b"+").unwrap();

    stream.write_all(&pkt(b"g")).unwrap();
    let resp = read_until(&mut stream, |s| s.contains("efbeadde"));
    assert!(resp.contains("efbeadde"), "rax little-endian should appear, got {:?}", resp);
    stream.write_all(b"+").unwrap();

    stream.write_all(&pkt(b"k")).unwrap();
    let _ = read_until(&mut stream, |_| false);

    let rc = unsafe { onyx_gdb_stop(handle) };
    assert_eq!(rc, 0);
}
