// language: Rust, file: hook.rs, target: Windows 11, MSVC
// Code injection, detours, and trampoline hooking engine

use crate::disasm::Disassembler;
use crate::process::Process;
use crate::win32::*;

#[derive(Debug, Clone)]
pub struct Hook {
    pub target_address: usize,
    pub allocated_address: usize,
    pub hook_size: usize,
    pub original_bytes: Vec<u8>,
}

pub struct HookEngine;

impl HookEngine {
    /// Creates a 64-bit absolute detour hook:
    /// Target will jump to allocated memory, execute custom payload, execute stolen bytes, and jump back.
    pub fn install_detour_64(
        proc: &Process,
        target_addr: usize,
        payload_bytes: &[u8],
    ) -> Result<Hook, String> {
        // 14-byte absolute jump: FF 25 00 00 00 00 [addr64]
        const HOOK_SIZE_MIN: usize = 14;

        // Disassemble instructions at target until we have at least 14 bytes
        let preview = proc.read_bytes(target_addr, 32)?;
        let insns = Disassembler::disassemble_block(target_addr, &preview, 10);

        let mut hook_len = 0;
        for insn in &insns {
            hook_len += insn.length;
            if hook_len >= HOOK_SIZE_MIN {
                break;
            }
        }

        if hook_len < HOOK_SIZE_MIN {
            return Err(format!(
                "Could not decode enough instructions at 0x{:X} to place a 14-byte hook (got {} bytes)",
                target_addr, hook_len
            ));
        }

        let original_bytes = proc.read_bytes(target_addr, hook_len)?;

        // Total trampoline memory needed:
        // [payload] + [stolen bytes] + [14-byte jmp back]
        let stolen_len = hook_len;
        let return_addr = target_addr + hook_len;
        let total_size = payload_bytes.len() + stolen_len + 14 + 16; // extra padding

        let alloc_addr = proc.alloc(total_size, PAGE_EXECUTE_READWRITE)?;

        let mut trampoline_code = Vec::new();
        // 1. User payload
        trampoline_code.extend_from_slice(payload_bytes);
        // 2. Stolen instructions
        trampoline_code.extend_from_slice(&original_bytes);
        // 3. JMP back to (target_addr + hook_len)
        let jmp_back = make_absolute_jmp_64(return_addr);
        trampoline_code.extend_from_slice(&jmp_back);

        // Write trampoline code to allocated memory
        proc.write_raw(alloc_addr, &trampoline_code)?;

        // Write detour at target:
        // JMP to alloc_addr, followed by NOPs (0x90) for remaining stolen bytes
        let mut detour = make_absolute_jmp_64(alloc_addr);
        while detour.len() < hook_len {
            detour.push(0x90);
        }

        let old_protect = proc.protect(target_addr, hook_len, PAGE_EXECUTE_READWRITE)?;
        proc.write_raw(target_addr, &detour)?;
        let _ = proc.protect(target_addr, hook_len, old_protect);

        Ok(Hook {
            target_address: target_addr,
            allocated_address: alloc_addr,
            hook_size: hook_len,
            original_bytes,
        })
    }

    /// Restores original code and frees allocated trampoline
    pub fn uninstall(proc: &Process, hook: &Hook) -> Result<(), String> {
        let old_protect = proc.protect(hook.target_address, hook.hook_size, PAGE_EXECUTE_READWRITE)?;
        proc.write_raw(hook.target_address, &hook.original_bytes)?;
        let _ = proc.protect(hook.target_address, hook.hook_size, old_protect);
        proc.free(hook.allocated_address)?;
        Ok(())
    }
}

pub fn make_absolute_jmp_64(destination: usize) -> Vec<u8> {
    let mut code = vec![0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
    code.extend_from_slice(&(destination as u64).to_le_bytes());
    code
}
