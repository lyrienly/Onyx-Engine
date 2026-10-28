#![cfg(target_os = "windows")]

use std::path::PathBuf;

use onyx_core::symbols::{read_codeview_from_file, SymbolCache};

fn ntdll_path() -> PathBuf {
    let sys = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    PathBuf::from(sys).join("System32").join("ntdll.dll")
}

#[test]
fn codeview_from_ntdll_is_rsds() {
    let p = ntdll_path();
    assert!(p.exists(), "ntdll.dll not found at {}", p.display());
    let info = read_codeview_from_file(&p).expect("codeview parse");
    assert_eq!(info.pdb_basename(), "ntdll.pdb");
    assert_ne!(info.guid, [0u8; 16]);
    let key = info.guid_age_key();
    assert!(key.len() >= 33, "unexpected key length: {}", key);
    eprintln!("ntdll pdb_name={} guid_age_key={}", info.pdb_name, key);
}

#[test]
fn resolve_ntquery_information_process_via_symsrv() {
    let p = ntdll_path();
    assert!(p.exists());
    let cache = SymbolCache::new().expect("cache init");
    eprintln!("cache dir: {}", cache.cache_dir().display());

    let pdb_path = cache
        .ensure_pdb(&p)
        .expect("download ntdll.pdb from Microsoft SymSrv");
    eprintln!("pdb at: {}", pdb_path.display());
    assert!(pdb_path.exists());

    let rva = cache
        .lookup_by_name(&p, "NtQueryInformationProcess")
        .expect("NtQueryInformationProcess must resolve");
    eprintln!("NtQueryInformationProcess rva=0x{:x}", rva);
    assert!(rva != 0);

    let name = cache
        .resolve_symbol(&p, rva as u32)
        .expect("reverse resolve rva->name");
    eprintln!("reverse: 0x{:x} -> {}", rva, name);
    assert!(
        name.starts_with("NtQueryInformationProcess"),
        "unexpected reverse symbol: {}",
        name
    );
}
