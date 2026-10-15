// OnyxEngine Disassembler Backend API
// x86_64 native instruction decoder for Pascal / Lazarus

use onyx_core::disasm::Disassembler;
use crate::types::OnyxDisasmInsn;

/// Disassemble a single instruction from a raw byte slice
/// Returns 1 on success, 0 on failure
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

/// Disassemble a block of bytes into an array of OnyxDisasmInsn
/// Returns number of instructions decoded
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
