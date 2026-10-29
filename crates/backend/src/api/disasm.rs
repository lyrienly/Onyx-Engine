use onyx_core::process::Process;
use onyx_core::disasm::Disassembler;
use onyx_core::debugger::dissect_code::{DissectCodeEngine, BranchKind};
use onyx_core::debugger::string_referencer::StringReferencer;
use crate::types::{OnyxDisasmInsn, OnyxDissectBranch, OnyxXRefEntry, OnyxStringReference};

#[no_mangle]
pub unsafe extern "C" fn onyx_disasm_instruction(
    address: usize,
    bytes: *const u8,
    length: usize,
    out_insn: *mut OnyxDisasmInsn,
) -> i32 {
    if bytes.is_null() || length == 0 || out_insn.is_null() {
        return 0;
    }

    let slice = std::slice::from_raw_parts(bytes, length);
    let list = Disassembler::disassemble_block(address, slice, 1);
    match list.into_iter().next() {
        Some(insn) => {
            let mut result = OnyxDisasmInsn {
                address: insn.address,
                length: insn.length as u32,
                bytes: [0u8; 16],
                mnemonic: [0u8; 32],
                operands: [0u8; 96],
            };

            let byte_count = insn.bytes.len().min(16);
            result.bytes[..byte_count].copy_from_slice(&insn.bytes[..byte_count]);

            let m_bytes = insn.mnemonic.as_bytes();
            let m_len = m_bytes.len().min(31);
            result.mnemonic[..m_len].copy_from_slice(&m_bytes[..m_len]);

            let o_bytes = insn.operands.as_bytes();
            let o_len = o_bytes.len().min(95);
            result.operands[..o_len].copy_from_slice(&o_bytes[..o_len]);

            *out_insn = result;
            1
        }
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_disasm_block(
    address: usize,
    bytes: *const u8,
    length: usize,
    max_instructions: u32,
    out_insns: *mut OnyxDisasmInsn,
    out_count: *mut u32,
) -> i32 {
    if bytes.is_null() || length == 0 || out_insns.is_null() || max_instructions == 0 {
        return 0;
    }

    let slice = std::slice::from_raw_parts(bytes, length);
    let list = Disassembler::disassemble_block(address, slice, max_instructions as usize);
    let count = list.len();

    if !out_count.is_null() {
        *out_count = count as u32;
    }

    for (i, insn) in list.iter().enumerate() {
        let mut entry = OnyxDisasmInsn {
            address: insn.address,
            length: insn.length as u32,
            bytes: [0u8; 16],
            mnemonic: [0u8; 32],
            operands: [0u8; 96],
        };

        let b_len = insn.bytes.len().min(16);
        entry.bytes[..b_len].copy_from_slice(&insn.bytes[..b_len]);

        let m_bytes = insn.mnemonic.as_bytes();
        let m_len = m_bytes.len().min(31);
        entry.mnemonic[..m_len].copy_from_slice(&m_bytes[..m_len]);

        let o_bytes = insn.operands.as_bytes();
        let o_len = o_bytes.len().min(95);
        entry.operands[..o_len].copy_from_slice(&o_bytes[..o_len]);

        *out_insns.add(i) = entry;
    }

    count as i32
}

#[no_mangle]
pub unsafe extern "C" fn onyx_dissect_code(
    handle: *mut Process,
    start: usize,
    stop: usize,
    out_branches: *mut OnyxDissectBranch,
    max_branches: u32,
    out_branch_count: *mut u32,
    out_xrefs: *mut OnyxXRefEntry,
    max_xrefs: u32,
    out_xref_count: *mut u32,
) -> i32 {
    if handle.is_null() {
        return -1;
    }

    match DissectCodeEngine::dissect_range(&*handle, start, stop) {
        Ok(result) => {
            if !out_branch_count.is_null() {
                *out_branch_count = result.branches.len() as u32;
            }
            if !out_branches.is_null() && max_branches > 0 {
                let write_b = result.branches.len().min(max_branches as usize);
                for i in 0..write_b {
                    let b = &result.branches[i];
                    let kind_idx = match b.kind {
                        BranchKind::Call => 0,
                        BranchKind::UnconditionalJump => 1,
                        BranchKind::ConditionalJump => 2,
                        BranchKind::Return => 3,
                    };
                    *out_branches.add(i) = OnyxDissectBranch {
                        from_address: b.from_address,
                        to_address: b.to_address,
                        kind: kind_idx,
                    };
                }
            }

            let mut flat_xrefs = Vec::new();
            for (callee, callers) in result.xrefs {
                for caller in callers {
                    flat_xrefs.push(OnyxXRefEntry {
                        target_address: callee,
                        caller_address: caller,
                    });
                }
            }

            if !out_xref_count.is_null() {
                *out_xref_count = flat_xrefs.len() as u32;
            }
            if !out_xrefs.is_null() && max_xrefs > 0 {
                let write_x = flat_xrefs.len().min(max_xrefs as usize);
                for i in 0..write_x {
                    *out_xrefs.add(i) = flat_xrefs[i];
                }
            }

            1
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_scan_string_references(
    handle: *mut Process,
    start: usize,
    stop: usize,
    min_string_len: usize,
    out_refs: *mut OnyxStringReference,
    max_refs: u32,
    out_count: *mut u32,
) -> i32 {
    if handle.is_null() || out_refs.is_null() || max_refs == 0 {
        return -1;
    }

    match StringReferencer::scan_process(&*handle, start, stop, min_string_len) {
        Ok(matches) => {
            if !out_count.is_null() {
                *out_count = matches.len() as u32;
            }

            let write_len = matches.len().min(max_refs as usize);
            for i in 0..write_len {
                let mut entry = OnyxStringReference {
                    instruction_address: matches[i].instruction_address,
                    string_address: matches[i].string_address,
                    text: [0u8; 128],
                    is_unicode: if matches[i].is_unicode { 1 } else { 0 },
                    mnemonic: [0u8; 32],
                    operands: [0u8; 96],
                };

                let t_bytes = matches[i].text.as_bytes();
                let t_len = t_bytes.len().min(127);
                entry.text[..t_len].copy_from_slice(&t_bytes[..t_len]);

                let m_bytes = matches[i].mnemonic.as_bytes();
                let m_len = m_bytes.len().min(31);
                entry.mnemonic[..m_len].copy_from_slice(&m_bytes[..m_len]);

                let o_bytes = matches[i].operands.as_bytes();
                let o_len = o_bytes.len().min(95);
                entry.operands[..o_len].copy_from_slice(&o_bytes[..o_len]);

                *out_refs.add(i) = entry;
            }

            write_len as i32
        }
        Err(_) => -1,
    }
}
