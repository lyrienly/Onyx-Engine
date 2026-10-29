use onyx_disasm::{build_cfg, cfg_to_dot, disassemble, FlowType};

#[test]
fn decodes_known_mov_sequence() {

    let code: &[u8] = &[
        0x48, 0x89, 0x5C, 0x24, 0x08,
        0x48, 0x89, 0x74, 0x24, 0x10,
        0x57,
        0xC3,
    ];
    let insns = disassemble(code, 0x1000);
    assert_eq!(insns.len(), 4, "expected 4 instructions, got {}", insns.len());
    assert_eq!(insns[0].address, 0x1000);
    assert_eq!(insns[0].mnemonic, "mov");
    assert!(insns[0].operands.contains("rsp"));
    assert_eq!(insns[0].length, 5);
    assert_eq!(insns[1].mnemonic, "mov");
    assert_eq!(insns[2].mnemonic, "push");
    assert_eq!(insns[3].mnemonic, "ret");
    assert_eq!(insns[3].flow_type, FlowType::Return);
}

#[test]
fn cfg_splits_on_conditional_jump() {

    let code: &[u8] = &[
        0x83, 0xF8, 0x00,
        0x74, 0x02,
        0x90,
        0x90,
        0xC3,
    ];
    let insns = disassemble(code, 0x1000);
    assert!(!insns.is_empty());
    let graph = build_cfg(&insns);
    assert_eq!(graph.entry, 0x1000);
    assert!(graph.blocks.len() >= 2, "expected at least 2 blocks");
    let first = graph.blocks.get(&0x1000).expect("entry block");
    assert_eq!(first.entry, 0x1000);

    assert_eq!(first.successors.len(), 2);
    assert!(first.successors.contains(&0x1007));
}

#[test]
fn dot_export_contains_graph() {
    let code: &[u8] = &[0x90, 0x90, 0xC3];
    let insns = disassemble(code, 0x4000);
    let graph = build_cfg(&insns);
    let dot = cfg_to_dot(&graph);
    assert!(dot.starts_with("digraph cfg"));
    assert!(dot.contains("bb_4000"));
}

#[cfg(windows)]
#[test]
fn e2e_disassembles_ntdll_function_and_dumps_cfg() {
    use std::ffi::CString;
    use std::io::Write;
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    let module_name = CString::new("ntdll.dll").unwrap();
    let proc_name = CString::new("NtQueryInformationProcess").unwrap();

    let h = unsafe { GetModuleHandleA(module_name.as_ptr() as *const u8) };
    assert!(h != 0, "ntdll not loaded");
    let func = unsafe { GetProcAddress(h, proc_name.as_ptr() as *const u8) };
    let func_addr = func.expect("NtQueryInformationProcess not found") as *const u8;
    let base = func_addr as u64;

    let mut raw = vec![0u8; 512];
    unsafe { std::ptr::copy_nonoverlapping(func_addr, raw.as_mut_ptr(), raw.len()); }

    let insns = disassemble(&raw, base);
    assert!(!insns.is_empty(), "no instructions decoded from ntdll");
    assert_eq!(insns[0].address, base, "first instruction must start at base");

    let graph = build_cfg(&insns);
    assert!(!graph.blocks.is_empty(), "cfg must have >= 1 block");
    let first = graph.blocks.values().next().unwrap();
    assert_eq!(first.entry, base, "first block entry must == base_addr");

    let dot = cfg_to_dot(&graph);
    assert!(dot.contains("digraph"));

    let scratch = std::path::Path::new(
        r"C:\Users\susboy\AppData\Local\Temp\claude\c--Users-susboy-Documents-Projects-OnyxEngine\1591b72f-b222-4e3c-8a1f-7cf2a08d69d7\scratchpad",
    );
    if scratch.exists() {
        let dot_path = scratch.join("cfg_feat_issue_14.dot");
        if let Ok(mut f) = std::fs::File::create(&dot_path) {
            let _ = f.write_all(dot.as_bytes());
        }
        let log_path = scratch.join("e2e_feat_issue_14.log");
        if let Ok(mut f) = std::fs::File::create(&log_path) {
            let _ = writeln!(f, "NtQueryInformationProcess @ 0x{:X}", base);
            let _ = writeln!(f, "decoded {} instructions, {} blocks", insns.len(), graph.blocks.len());
            for insn in &insns {
                let _ = writeln!(f, "{}", onyx_disasm::format_instruction(insn));
            }
        }
    }
}
