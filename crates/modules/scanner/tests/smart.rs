use onyx_scanner::smart::{smart_scan, ScanType, SmartTarget};

fn seeded_rand(seed: u64, len: usize) -> Vec<u8> {
    let mut s = seed;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        out.push((s & 0xFF) as u8);
    }
    out
}

/// Monta um buffer determinista com valores conhecidos:
///   offset 0x100: i32 = 42
///   offset 0x200: f32 = 2.5
///   offset 0x300: i64 = 1234567890123
///   offset 0x400: f64 = 3.14159
///   offset 0x500: pointer = 0x1000_1000
///   offset 0x600: ascii "hello\0"
fn build_known_buffer() -> Vec<u8> {
    let mut buf = vec![0u8; 0x1000];
    buf[0x100..0x104].copy_from_slice(&42i32.to_le_bytes());
    buf[0x200..0x204].copy_from_slice(&2.5f32.to_le_bytes());
    buf[0x300..0x308].copy_from_slice(&1_234_567_890_123i64.to_le_bytes());
    buf[0x400..0x408].copy_from_slice(&3.14159f64.to_le_bytes());
    buf[0x500..0x508].copy_from_slice(&0x1000_1000u64.to_le_bytes());
    buf[0x600..0x606].copy_from_slice(b"hello\0");
    buf
}

#[test]
fn numeric_scan_finds_i32() {
    let buf = build_known_buffer();
    let hits = smart_scan(&buf, 0, SmartTarget::Numeric(42.0));
    assert!(hits
        .iter()
        .any(|h| h.scan_type == ScanType::I32 && h.address == 0x100));
}

#[test]
fn numeric_scan_finds_f32() {
    let buf = build_known_buffer();
    let hits = smart_scan(&buf, 0, SmartTarget::Numeric(2.5));
    assert!(hits
        .iter()
        .any(|h| h.scan_type == ScanType::F32 && h.address == 0x200));
}

#[test]
fn numeric_scan_finds_i64() {
    let buf = build_known_buffer();
    let hits = smart_scan(&buf, 0, SmartTarget::Numeric(1_234_567_890_123.0));
    assert!(hits
        .iter()
        .any(|h| h.scan_type == ScanType::I64 && h.address == 0x300));
}

#[test]
fn numeric_scan_finds_f64() {
    let buf = build_known_buffer();
    let hits = smart_scan(&buf, 0, SmartTarget::Numeric(3.14159));
    assert!(hits
        .iter()
        .any(|h| h.scan_type == ScanType::F64 && h.address == 0x400));
}

#[test]
fn any_scan_enumerates_pointer_and_strings() {
    let buf = build_known_buffer();
    let hits = smart_scan(&buf, 0x7FF_0000_0000, SmartTarget::Any);
    assert!(hits
        .iter()
        .any(|h| h.scan_type == ScanType::Pointer && h.interpreted.contains("0x10001000")));
    assert!(hits
        .iter()
        .any(|h| h.scan_type == ScanType::StringAscii && h.interpreted == "hello"));
}

#[test]
fn exact_bytes_match() {
    let buf = build_known_buffer();
    let target: Vec<u8> = 42i32.to_le_bytes().to_vec();
    let hits = smart_scan(&buf, 0, SmartTarget::Exact(target));
    assert!(hits
        .iter()
        .any(|h| h.scan_type == ScanType::I32 && h.address == 0x100));
}

#[test]
fn single_pass_vs_four_passes_benchmark() {
    // 10 MB.
    let mut buf = seeded_rand(0xC0FFEE, 10 * 1024 * 1024);
    // Inserimos alvos conhecidos.
    buf[0x1_000..0x1_004].copy_from_slice(&12345i32.to_le_bytes());
    buf[0x2_000..0x2_004].copy_from_slice(&12345.0f32.to_le_bytes());
    buf[0x3_000..0x3_008].copy_from_slice(&12345i64.to_le_bytes());
    buf[0x4_000..0x4_008].copy_from_slice(&12345.0f64.to_le_bytes());

    let n = 3;
    let mut smart_total = std::time::Duration::ZERO;
    let mut typed_total = std::time::Duration::ZERO;

    for _ in 0..n {
        let t0 = std::time::Instant::now();
        let hits = smart_scan(&buf, 0, SmartTarget::Numeric(12345.0));
        smart_total += t0.elapsed();
        assert!(hits.iter().any(|h| h.scan_type == ScanType::I32 && h.address == 0x1_000));
        assert!(hits.iter().any(|h| h.scan_type == ScanType::F32 && h.address == 0x2_000));
        assert!(hits.iter().any(|h| h.scan_type == ScanType::I64 && h.address == 0x3_000));
        assert!(hits.iter().any(|h| h.scan_type == ScanType::F64 && h.address == 0x4_000));

        // 4 passagens tipadas separadas sobre o mesmo buffer.
        let t1 = std::time::Instant::now();
        let _ = scan_typed_i32(&buf, 12345);
        let _ = scan_typed_i64(&buf, 12345);
        let _ = scan_typed_f32(&buf, 12345.0);
        let _ = scan_typed_f64(&buf, 12345.0);
        typed_total += t1.elapsed();
    }

    let smart_ms = smart_total.as_secs_f64() * 1000.0 / n as f64;
    let typed_ms = typed_total.as_secs_f64() * 1000.0 / n as f64;
    let single_typed_ms = typed_ms / 4.0;

    // Nota: um scan tipado faz 1 comparacao de bytes por offset com stride igual
    // ao tamanho do tipo; o smart_scan faz 5 inferencias (i32/f32/i64/f64/ptr)
    // por offset alinhado. O criterio justo e vs o custo total das 4 passagens.
    eprintln!(
        "BENCHMARK smart_scan: {:.2} ms | 4 typed passes: {:.2} ms | 1 typed pass: {:.2} ms | ratio smart/4typed: {:.2}x | ratio smart/1typed: {:.2}x",
        smart_ms,
        typed_ms,
        single_typed_ms,
        smart_ms / typed_ms,
        smart_ms / single_typed_ms
    );

    // smart_scan em uma passagem substitui as 4 passagens tipadas; exigimos que
    // seu custo nao ultrapasse 1.5x o custo total das 4 passagens equivalentes.
    assert!(
        smart_ms <= typed_ms * 1.5,
        "smart_scan ({:.2}ms) excedeu 1.5x das 4 passagens tipadas ({:.2}ms)",
        smart_ms,
        typed_ms
    );
}

fn scan_typed_i32(buf: &[u8], target: i32) -> Vec<usize> {
    let bytes = target.to_le_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= buf.len() {
        if buf[i..i + 4] == bytes {
            out.push(i);
        }
        i += 4;
    }
    out
}

fn scan_typed_i64(buf: &[u8], target: i64) -> Vec<usize> {
    let bytes = target.to_le_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 8 <= buf.len() {
        if buf[i..i + 8] == bytes {
            out.push(i);
        }
        i += 8;
    }
    out
}

fn scan_typed_f32(buf: &[u8], target: f32) -> Vec<usize> {
    let bytes = target.to_le_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= buf.len() {
        if buf[i..i + 4] == bytes {
            out.push(i);
        }
        i += 4;
    }
    out
}

fn scan_typed_f64(buf: &[u8], target: f64) -> Vec<usize> {
    let bytes = target.to_le_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 8 <= buf.len() {
        if buf[i..i + 8] == bytes {
            out.push(i);
        }
        i += 8;
    }
    out
}

#[cfg(windows)]
mod e2e_windows {
    use super::*;

    use std::ffi::c_void;
    use std::mem::MaybeUninit;
    use std::ptr::null_mut;

    #[allow(non_camel_case_types)]
    type HANDLE = *mut c_void;
    #[allow(non_camel_case_types)]
    type DWORD = u32;
    #[allow(non_camel_case_types)]
    type BOOL = i32;
    #[allow(non_camel_case_types)]
    type SIZE_T = usize;
    #[allow(non_camel_case_types)]
    type LPVOID = *mut c_void;
    #[allow(non_camel_case_types)]
    type LPCVOID = *const c_void;

    const CREATE_SUSPENDED: DWORD = 0x4;
    const MEM_COMMIT: DWORD = 0x1000;
    const MEM_RESERVE: DWORD = 0x2000;
    const MEM_RELEASE: DWORD = 0x8000;
    const PAGE_READWRITE: DWORD = 0x4;

    #[repr(C)]
    struct StartupInfoA {
        cb: DWORD,
        lp_reserved: *mut u8,
        lp_desktop: *mut u8,
        lp_title: *mut u8,
        dw_x: DWORD,
        dw_y: DWORD,
        dw_x_size: DWORD,
        dw_y_size: DWORD,
        dw_x_count_chars: DWORD,
        dw_y_count_chars: DWORD,
        dw_fill_attribute: DWORD,
        dw_flags: DWORD,
        w_show_window: u16,
        cb_reserved2: u16,
        lp_reserved2: *mut u8,
        h_std_input: HANDLE,
        h_std_output: HANDLE,
        h_std_error: HANDLE,
    }

    #[repr(C)]
    struct ProcessInformation {
        h_process: HANDLE,
        h_thread: HANDLE,
        dw_process_id: DWORD,
        dw_thread_id: DWORD,
    }

    extern "system" {
        fn CreateProcessA(
            lp_application_name: *const u8,
            lp_command_line: *mut u8,
            lp_process_attributes: *mut c_void,
            lp_thread_attributes: *mut c_void,
            b_inherit_handles: BOOL,
            dw_creation_flags: DWORD,
            lp_environment: *mut c_void,
            lp_current_directory: *const u8,
            lp_startup_info: *mut StartupInfoA,
            lp_process_information: *mut ProcessInformation,
        ) -> BOOL;
        fn TerminateProcess(h_process: HANDLE, u_exit_code: u32) -> BOOL;
        fn CloseHandle(h: HANDLE) -> BOOL;
        fn VirtualAllocEx(
            h_process: HANDLE,
            lp_address: LPVOID,
            dw_size: SIZE_T,
            fl_allocation_type: DWORD,
            fl_protect: DWORD,
        ) -> LPVOID;
        fn VirtualFreeEx(
            h_process: HANDLE,
            lp_address: LPVOID,
            dw_size: SIZE_T,
            dw_free_type: DWORD,
        ) -> BOOL;
        fn WriteProcessMemory(
            h_process: HANDLE,
            lp_base_address: LPVOID,
            lp_buffer: LPCVOID,
            n_size: SIZE_T,
            lp_number_of_bytes_written: *mut SIZE_T,
        ) -> BOOL;
        fn ReadProcessMemory(
            h_process: HANDLE,
            lp_base_address: LPCVOID,
            lp_buffer: LPVOID,
            n_size: SIZE_T,
            lp_number_of_bytes_read: *mut SIZE_T,
        ) -> BOOL;
    }

    struct TestProc {
        pi: ProcessInformation,
    }

    impl Drop for TestProc {
        fn drop(&mut self) {
            unsafe {
                TerminateProcess(self.pi.h_process, 0);
                CloseHandle(self.pi.h_thread);
                CloseHandle(self.pi.h_process);
            }
        }
    }

    fn spawn_cobaia() -> Option<TestProc> {
        // cmd.exe /K pause -> fica rodando ate ser morto
        let mut cmd: Vec<u8> = b"cmd.exe /c pause\0".to_vec();
        let mut si: StartupInfoA = unsafe { MaybeUninit::zeroed().assume_init() };
        si.cb = std::mem::size_of::<StartupInfoA>() as u32;
        let mut pi: ProcessInformation = unsafe { MaybeUninit::zeroed().assume_init() };
        let ok = unsafe {
            CreateProcessA(
                std::ptr::null(),
                cmd.as_mut_ptr(),
                null_mut(),
                null_mut(),
                0,
                CREATE_SUSPENDED,
                null_mut(),
                std::ptr::null(),
                &mut si,
                &mut pi,
            )
        };
        if ok == 0 {
            return None;
        }
        Some(TestProc { pi })
    }

    #[test]
    fn e2e_cobaia_write_and_scan() {
        let proc = match spawn_cobaia() {
            Some(p) => p,
            None => {
                eprintln!("E2E skip: nao foi possivel spawn cmd.exe");
                return;
            }
        };

        let region_size = 0x1000usize;
        let region = unsafe {
            VirtualAllocEx(
                proc.pi.h_process,
                null_mut(),
                region_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        assert!(!region.is_null(), "VirtualAllocEx falhou");

        // Struct conhecida: i32 42 @ +0x00, f32 2.5 @ +0x10, pointer @ +0x20, string "hello" @ +0x40
        let mut payload = vec![0u8; region_size];
        payload[0x00..0x04].copy_from_slice(&42i32.to_le_bytes());
        payload[0x10..0x14].copy_from_slice(&2.5f32.to_le_bytes());
        let fake_ptr = region as u64 + 0x200;
        payload[0x20..0x28].copy_from_slice(&fake_ptr.to_le_bytes());
        payload[0x40..0x46].copy_from_slice(b"hello\0");

        let mut written: SIZE_T = 0;
        let ok = unsafe {
            WriteProcessMemory(
                proc.pi.h_process,
                region,
                payload.as_ptr() as LPCVOID,
                region_size,
                &mut written,
            )
        };
        assert_ne!(ok, 0, "WriteProcessMemory falhou");
        assert_eq!(written, region_size);

        // Le de volta e roda smart_scan.
        let mut readback = vec![0u8; region_size];
        let mut read: SIZE_T = 0;
        let ok = unsafe {
            ReadProcessMemory(
                proc.pi.h_process,
                region as LPCVOID,
                readback.as_mut_ptr() as LPVOID,
                region_size,
                &mut read,
            )
        };
        assert_ne!(ok, 0, "ReadProcessMemory falhou");
        assert_eq!(read, region_size);

        let base = region as u64;

        // Numeric(42) encontra o i32.
        let hits = smart_scan(&readback, base, SmartTarget::Numeric(42.0));
        assert!(
            hits.iter().any(|h| h.scan_type == ScanType::I32 && h.address == base + 0x00),
            "nao encontrou i32=42 em +0x00"
        );

        // Any enumera tudo relevante.
        let hits_any = smart_scan(&readback, base, SmartTarget::Any);
        assert!(
            hits_any.iter().any(|h| h.scan_type == ScanType::F32 && h.address == base + 0x10),
            "nao encontrou f32=2.5"
        );
        assert!(
            hits_any.iter().any(|h| h.scan_type == ScanType::Pointer && h.address == base + 0x20),
            "nao encontrou pointer"
        );
        assert!(
            hits_any.iter().any(|h| h.scan_type == ScanType::StringAscii && h.interpreted == "hello"),
            "nao encontrou string hello"
        );

        unsafe {
            VirtualFreeEx(proc.pi.h_process, region, 0, MEM_RELEASE);
        }
    }
}
