use onyx_scanner::value_scan::{
    avx2_supported, avx512_supported, scan_exact, scan_exact_avx2, scan_exact_avx512,
    scan_exact_scalar, Needle,
};

fn xorshift_buf(seed: u64, len: usize) -> Vec<u8> {
    let mut s = seed;
    let mut v = Vec::with_capacity(len);
    for _ in 0..len {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        v.push((s & 0xFF) as u8);
    }
    v
}

#[test]
fn known_offsets_i32() {
    let mut buf = vec![0u8; 1 << 20];
    let target: i32 = -42;
    let offs = [0usize, 128, 4096, 100_000, 999_996];
    for &o in &offs {
        buf[o..o + 4].copy_from_slice(&target.to_le_bytes());
    }
    let hits = scan_exact(&buf, Needle::I32(target), 4);
    for o in &offs {
        assert!(hits.contains(o), "missing offset {o}");
    }
}

#[test]
fn known_offsets_i64() {
    let mut buf = vec![0u8; 1 << 20];
    let target: i64 = 0x0BAD_C0FFEE_12345i64;
    let offs = [0usize, 256, 65536, 500_000, 999_992];
    for &o in &offs {
        buf[o..o + 8].copy_from_slice(&target.to_le_bytes());
    }
    let hits = scan_exact(&buf, Needle::I64(target), 8);
    for o in &offs {
        assert!(hits.contains(o));
    }
}

#[test]
fn equivalence_scalar_simd_i32() {
    // garante que os tres caminhos retornam o MESMO conjunto de hits
    let mut buf = xorshift_buf(0xC0FFEE, 10 * 1024 * 1024);
    // injeta alguns valores pra forcar hits
    let target: i32 = 0x7F7F_7F7F;
    for i in 0..256 {
        let off = (i * 40_000 + 8) & !3;
        if off + 4 <= buf.len() {
            buf[off..off + 4].copy_from_slice(&target.to_le_bytes());
        }
    }

    let s = scan_exact_scalar(&buf, Needle::I32(target), 4);
    let a = scan_exact_avx2(&buf, Needle::I32(target), 4);
    assert_eq!(s, a, "scalar vs avx2 divergem (i32)");

    if avx512_supported() {
        let z = scan_exact_avx512(&buf, Needle::I32(target), 4);
        assert_eq!(s, z, "scalar vs avx512 divergem (i32)");
    }
    assert!(avx2_supported(), "ambiente de teste sem AVX2 (improvavel)");
}

#[test]
fn equivalence_scalar_simd_i64() {
    let mut buf = xorshift_buf(0xDEADBEEF, 10 * 1024 * 1024);
    let target: i64 = 0x1122_3344_5566_7788i64;
    for i in 0..256 {
        let off = (i * 40_000 + 8) & !7;
        if off + 8 <= buf.len() {
            buf[off..off + 8].copy_from_slice(&target.to_le_bytes());
        }
    }

    let s = scan_exact_scalar(&buf, Needle::I64(target), 8);
    let a = scan_exact_avx2(&buf, Needle::I64(target), 8);
    assert_eq!(s, a, "scalar vs avx2 divergem (i64)");
    if avx512_supported() {
        let z = scan_exact_avx512(&buf, Needle::I64(target), 8);
        assert_eq!(s, z, "scalar vs avx512 divergem (i64)");
    }
}

#[test]
fn equivalence_random_no_injection() {
    // sem injetar valores: as 3 implementacoes devem concordar mesmo sem hits
    let buf = xorshift_buf(0xABCDEF, 4 * 1024 * 1024);
    for &needle in &[0i32, 1, -1, 0x7F7F_7F7F, 0x8000_0000u32 as i32] {
        let s = scan_exact_scalar(&buf, Needle::I32(needle), 4);
        let a = scan_exact_avx2(&buf, Needle::I32(needle), 4);
        assert_eq!(s, a);
    }
}

#[test]
fn alignment_respected() {
    let mut buf = vec![0u8; 1024];
    let target: i32 = 7;
    buf[5..9].copy_from_slice(&target.to_le_bytes());
    buf[12..16].copy_from_slice(&target.to_le_bytes());

    let aligned = scan_exact(&buf, Needle::I32(target), 4);
    assert_eq!(aligned, vec![12]);

    let unaligned = scan_exact(&buf, Needle::I32(target), 1);
    assert!(unaligned.contains(&5) && unaligned.contains(&12));
}

#[test]
fn benchmark_100mb() {
    use std::time::Instant;
    const N: usize = 100 * 1024 * 1024;
    let mut buf = xorshift_buf(0xBEEFCAFE, N);
    let target: i32 = 0x1234_5678;
    // injeta alguns hits conhecidos
    for i in 0..1000 {
        let off = (i * 100_000 + 16) & !3;
        if off + 4 <= buf.len() {
            buf[off..off + 4].copy_from_slice(&target.to_le_bytes());
        }
    }

    let t0 = Instant::now();
    let s = scan_exact_scalar(&buf, Needle::I32(target), 4);
    let t_scalar = t0.elapsed();

    let t0 = Instant::now();
    let a = scan_exact_avx2(&buf, Needle::I32(target), 4);
    let t_avx2 = t0.elapsed();

    let mb = (N as f64) / (1024.0 * 1024.0);
    let scalar_mb_s = mb / t_scalar.as_secs_f64();
    let avx2_mb_s = mb / t_avx2.as_secs_f64();

    println!(
        "BENCH 100MB i32 exact: scalar={:.1} MB/s ({:?}) avx2={:.1} MB/s ({:?}) speedup={:.2}x",
        scalar_mb_s,
        t_scalar,
        avx2_mb_s,
        t_avx2,
        avx2_mb_s / scalar_mb_s
    );

    if avx512_supported() {
        let t0 = Instant::now();
        let z = scan_exact_avx512(&buf, Needle::I32(target), 4);
        let t_avx512 = t0.elapsed();
        let avx512_mb_s = mb / t_avx512.as_secs_f64();
        println!(
            "BENCH 100MB i32 exact: avx512={:.1} MB/s ({:?}) speedup={:.2}x",
            avx512_mb_s,
            t_avx512,
            avx512_mb_s / scalar_mb_s
        );
        assert_eq!(s, z);
    } else {
        println!("BENCH 100MB i32 exact: avx512 nao suportado neste host");
    }

    assert_eq!(s, a, "divergencia scalar vs avx2 no benchmark");
    // Nota: a referencia escalar e auto-vetorizada pelo LLVM em release, entao
    // o "scalar" ja atinge >4 GB/s. O ganho real sobre uma varredura puramente
    // escalar e muito maior; aqui exigimos ao menos 2.5x sobre a referencia
    // auto-vetorizada, e AVX-512 (quando presente) chega a 10x+.
    assert!(
        avx2_mb_s >= scalar_mb_s * 2.5,
        "avx2 speedup insuficiente: scalar={:.1} MB/s avx2={:.1} MB/s",
        scalar_mb_s,
        avx2_mb_s
    );
}

#[test]
fn benchmark_100mb_f32() {
    use std::time::Instant;
    const N: usize = 100 * 1024 * 1024;
    let mut buf = xorshift_buf(0xF007BA11, N);
    let target: f32 = 1.4142135;
    for i in 0..500 {
        let off = (i * 200_000 + 16) & !3;
        if off + 4 <= buf.len() {
            buf[off..off + 4].copy_from_slice(&target.to_le_bytes());
        }
    }
    let t0 = Instant::now();
    let s = scan_exact_scalar(&buf, Needle::F32(target), 4);
    let t_scalar = t0.elapsed();
    let t0 = Instant::now();
    let a = scan_exact_avx2(&buf, Needle::F32(target), 4);
    let t_avx2 = t0.elapsed();
    let mb = (N as f64) / (1024.0 * 1024.0);
    println!(
        "BENCH 100MB f32 exact: scalar={:.1} MB/s avx2={:.1} MB/s speedup={:.2}x",
        mb / t_scalar.as_secs_f64(),
        mb / t_avx2.as_secs_f64(),
        (mb / t_avx2.as_secs_f64()) / (mb / t_scalar.as_secs_f64())
    );
    assert_eq!(s, a);
}

#[cfg(windows)]
#[test]
fn e2e_scan_process_cmd() {
    use onyx_scanner::value_scan::process_pipeline::scan_process;
    use std::ffi::c_void;
    use std::process::{Command, Stdio};
    use std::ptr::null_mut;

    // sobe uma cobaia: cmd.exe pausando
    let mut child = Command::new("cmd.exe")
        .args(["/C", "ping -n 15 127.0.0.1 >nul"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn cmd");

    // da tempo pro processo iniciar
    std::thread::sleep(std::time::Duration::from_millis(300));
    let pid = child.id();

    // aloca memoria no processo cobaia e escreve valor conhecido
    use onyx_core::process::win32::*;
    let target: i32 = 0x5A5A_1234u32 as i32;
    let addrs = unsafe {
        let h = OpenProcess(
            PROCESS_VM_READ
                | PROCESS_VM_WRITE
                | PROCESS_VM_OPERATION
                | PROCESS_QUERY_INFORMATION,
            FALSE,
            pid,
        );
        assert!(!h.is_null(), "OpenProcess falhou pid={pid}");
        // VirtualAllocEx 4KB RW
        let base = VirtualAllocEx(
            h,
            null_mut::<c_void>(),
            4096,
            0x1000 | 0x2000, // MEM_COMMIT | MEM_RESERVE
            PAGE_READWRITE,
        );
        assert!(!base.is_null(), "VirtualAllocEx falhou");

        // escreve o target em 3 offsets conhecidos
        let known = [0usize, 256, 1024];
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&target.to_le_bytes());
        for off in known {
            let mut written: SIZE_T = 0;
            let ok = WriteProcessMemory(
                h,
                (base as usize + off) as *mut c_void,
                buf.as_ptr() as *const c_void,
                4,
                &mut written,
            );
            assert_eq!(ok, 1);
            assert_eq!(written, 4);
        }
        CloseHandle(h);
        known
            .iter()
            .map(|o| (base as usize + o) as u64)
            .collect::<Vec<_>>()
    };

    // roda o scan via pipeline
    let hits = scan_process(pid, Needle::I32(target), 4);
    let _ = child.kill();

    for a in addrs {
        assert!(
            hits.contains(&a),
            "endereco esperado {a:#x} nao encontrado; total hits={}",
            hits.len()
        );
    }
}
