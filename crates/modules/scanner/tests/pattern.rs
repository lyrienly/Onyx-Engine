use onyx_scanner::pattern::{
    find_all, find_all_scalar, find_all_with, find_pattern, find_pattern_scalar,
    find_pattern_with, Pattern,
};

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

#[test]
fn known_offset_no_wildcards() {
    let mut hay = seeded_rand(0xDEADBEEF, 1_000_000);
    let needle = [0x48u8, 0x8B, 0x15, 0x11, 0x22, 0x33, 0x44, 0xE8, 0x99];
    let off = 777_777;
    hay[off..off + needle.len()].copy_from_slice(&needle);

    let r = find_pattern(&hay, "48 8B 15 11 22 33 44 E8 99");
    assert_eq!(r, Some(off));
}

#[test]
fn known_offset_with_wildcards() {
    let mut hay = seeded_rand(0xCAFEBABE, 2_000_000);
    let needle = [0x48u8, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xE8, 0x11, 0x22, 0x33, 0x44];
    let off = 1_234_567;
    hay[off..off + needle.len()].copy_from_slice(&needle);

    let r = find_pattern(&hay, "48 8B ?? ?? ?? ?? ?? E8 ?? ?? ?? ??");
    assert_eq!(r, Some(off));
}

#[test]
fn find_all_matches_scalar_result() {
    let hay = seeded_rand(0x12345, 500_000);
    let p = Pattern::parse("48 8B ?? 00").unwrap();

    let a = find_all_with(&hay, &p);
    let b = find_all_scalar(&hay, &p.bytes, &p.mask);
    assert_eq!(a, b);
}

#[test]
fn avx2_equals_scalar_random() {
    let hay = seeded_rand(0xABCDEF01, 5_000_000);

    let patterns = [
        "DE AD BE EF",
        "48 8B ?? ?? E8",
        "?? AA ?? BB ?? CC",
        "FF",
        "00 00 00 00",
    ];
    for ps in patterns {
        let p = Pattern::parse(ps).unwrap();
        let a = find_pattern_with(&hay, &p);
        let b = find_pattern_scalar(&hay, &p.bytes, &p.mask);
        assert_eq!(a, b, "mismatch for {ps}");

        let aa = find_all_with(&hay, &p);
        let bb = find_all_scalar(&hay, &p.bytes, &p.mask);
        assert_eq!(aa, bb, "find_all mismatch for {ps}");
    }
}

#[test]
fn benchmark_avx2_vs_scalar_100mb() {
    const SIZE: usize = 100 * 1024 * 1024;
    let mut hay = seeded_rand(0x9876_5432_10AB_CDEF, SIZE);

    let needle = [0x48u8, 0x8B, 0x15, 0xDE, 0xAD, 0xBE, 0xEF, 0xE8, 0x11, 0x22, 0x33, 0x44];
    let off = SIZE - needle.len() - 1024;
    hay[off..off + needle.len()].copy_from_slice(&needle);

    let p = Pattern::parse("48 8B ?? ?? ?? ?? ?? E8 ?? ?? ?? ??").unwrap();

    let _ = find_pattern_scalar(&hay[..1024 * 1024], &p.bytes, &p.mask);
    let _ = find_pattern_with(&hay[..1024 * 1024], &p);

    let t0 = std::time::Instant::now();
    let r_scalar = find_pattern_scalar(&hay, &p.bytes, &p.mask);
    let d_scalar = t0.elapsed();

    let t1 = std::time::Instant::now();
    let r_avx = find_pattern_with(&hay, &p);
    let d_avx = t1.elapsed();

    assert_eq!(r_scalar, Some(off));
    assert_eq!(r_avx, Some(off));

    let scalar_mbps = SIZE as f64 / d_scalar.as_secs_f64() / (1024.0 * 1024.0);
    let avx_mbps = SIZE as f64 / d_avx.as_secs_f64() / (1024.0 * 1024.0);
    let speedup = d_scalar.as_secs_f64() / d_avx.as_secs_f64();

    eprintln!(
        "[BENCH] 100MB scalar={:?} ({:.1} MB/s) avx2={:?} ({:.1} MB/s) speedup={:.2}x",
        d_scalar, scalar_mbps, d_avx, avx_mbps, speedup
    );

    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            assert!(
                speedup >= 3.0,
                "AVX2 nao atingiu 3x speedup (medido={:.2}x)",
                speedup
            );
        }
    }
}

#[test]
fn pattern_at_start_and_end() {
    let needle = [0xDEu8, 0xAD, 0xBE, 0xEF];
    let mut hay = vec![0x00u8; 10_000];
    hay[..4].copy_from_slice(&needle);
    assert_eq!(find_pattern(&hay, "DE AD BE EF"), Some(0));

    let mut hay2 = vec![0x00u8; 10_000];
    let off = 10_000 - 4;
    hay2[off..].copy_from_slice(&needle);
    assert_eq!(find_pattern(&hay2, "DE AD BE EF"), Some(off));
}

#[test]
fn find_all_api() {
    let mut hay = vec![0u8; 100_000];
    let needle = [0x48u8, 0x8B, 0x05];
    let positions = [100, 5_000, 50_000, 99_000];
    for &p in &positions {
        hay[p..p + 3].copy_from_slice(&needle);
    }
    let got = find_all(&hay, "48 8B 05");
    assert_eq!(got, positions.to_vec());
}
