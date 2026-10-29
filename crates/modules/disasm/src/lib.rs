use onyx_core::disasm::Disassembler;

pub mod zydis_backend;
pub mod cfg;

pub use zydis_backend::{disassemble, format_instruction, FlowType, Instruction};
pub use cfg::{build_cfg, cfg_to_dot, BasicBlock, ControlFlowGraph};

#[no_mangle]
pub unsafe extern "C" fn onyx_disasm_cfg_dot(
    base_addr: u64,
    bytes: *const u8,
    length: usize,
    out_buf: *mut u8,
    out_cap: usize,
) -> usize {
    if bytes.is_null() || length == 0 || out_buf.is_null() || out_cap == 0 {
        return 0;
    }
    let slice = std::slice::from_raw_parts(bytes, length);
    let insns = zydis_backend::disassemble(slice, base_addr);
    let graph = cfg::build_cfg(&insns);
    let dot = cfg::cfg_to_dot(&graph);
    let data = dot.as_bytes();
    if data.len() + 1 > out_cap {
        return 0;
    }
    std::ptr::copy_nonoverlapping(data.as_ptr(), out_buf, data.len());
    *out_buf.add(data.len()) = 0;
    data.len()
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OnyxDisasmInsn {
    pub address: usize,
    pub length: u32,
    pub bytes: [u8; 16],
    pub mnemonic: [u8; 32],
    pub operands: [u8; 96],
}

impl Default for OnyxDisasmInsn {
    fn default() -> Self {
        Self {
            address: 0,
            length: 0,
            bytes: [0u8; 16],
            mnemonic: [0u8; 32],
            operands: [0u8; 96],
        }
    }
}

#[no_mangle]
pub extern "C" fn onyx_disasm_module_ping() -> i32 {
    1
}

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
            let mut result = OnyxDisasmInsn::default();
            result.address = insn.address;
            result.length = insn.length as u32;

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
    let out_slice = std::slice::from_raw_parts_mut(out_insns, max_instructions as usize);
    let count = list.len().min(max_instructions as usize);

    for (i, insn) in list.into_iter().take(count).enumerate() {
        let mut entry = OnyxDisasmInsn::default();
        entry.address = insn.address;
        entry.length = insn.length as u32;

        let byte_count = insn.bytes.len().min(16);
        entry.bytes[..byte_count].copy_from_slice(&insn.bytes[..byte_count]);

        let m_bytes = insn.mnemonic.as_bytes();
        let m_len = m_bytes.len().min(31);
        entry.mnemonic[..m_len].copy_from_slice(&m_bytes[..m_len]);

        let o_bytes = insn.operands.as_bytes();
        let o_len = o_bytes.len().min(95);
        entry.operands[..o_len].copy_from_slice(&o_bytes[..o_len]);

        out_slice[i] = entry;
    }

    if !out_count.is_null() {
        *out_count = count as u32;
    }

    count as i32
}
