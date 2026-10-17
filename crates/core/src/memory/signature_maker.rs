// language: Rust, file: signature_maker.rs, target: Windows 11, MSVC
// Unique AOB Signature Generator
// Automatically decodes instructions at target address, masks variable offsets/displacements,
// and tests uniqueness in the target module/region.

use crate::process::Process;
use crate::debugger::disasm::Disassembler;
use crate::memory::scanner::AobByte;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniqueSignatureResult {
    pub pattern: String,
    pub length: usize,
    pub match_count: usize,
    pub is_unique: bool,
}

pub struct SignatureMaker;

impl SignatureMaker {
    /// Masks variable portions of decoded instruction bytes.
    /// E.g. for RIP-relative instructions, the 4 displacement bytes are masked as ??.
    pub fn mask_instruction(insn_bytes: &[u8], is_rip_relative: bool) -> (Vec<AobByte>, String) {
        let mut aob_bytes = Vec::new();
        let mut pattern_parts = Vec::new();

        if is_rip_relative && insn_bytes.len() >= 4 {
            let fixed_len = insn_bytes.len() - 4;
            for &b in &insn_bytes[..fixed_len] {
                aob_bytes.push(AobByte::exact(b));
                pattern_parts.push(format!("{:02X}", b));
            }
            for _ in 0..4 {
                aob_bytes.push(AobByte::wildcard());
                pattern_parts.push("??".to_string());
            }
        } else {
            for &b in insn_bytes {
                aob_bytes.push(AobByte::exact(b));
                pattern_parts.push(format!("{:02X}", b));
            }
        }

        (aob_bytes, pattern_parts.join(" "))
    }

    /// Tests how many times pattern matches in a byte slice.
    pub fn count_matches_in_buffer(haystack: &[u8], pattern: &[AobByte]) -> usize {
        if pattern.is_empty() || haystack.len() < pattern.len() {
            return 0;
        }

        let mut count = 0;
        let max_idx = haystack.len() - pattern.len();

        for i in 0..=max_idx {
            let mut matches = true;
            for (p_idx, p_byte) in pattern.iter().enumerate() {
                if !p_byte.matches(haystack[i + p_idx]) {
                    matches = false;
                    break;
                }
            }
            if matches {
                count += 1;
            }
        }

        count
    }

    /// Automatically generates a unique AOB signature for the instruction/function at `target_addr`
    /// within module or address range `[scan_start, scan_stop]`.
    pub fn generate_signature(
        proc: &Process,
        target_addr: usize,
        scan_start: usize,
        scan_stop: usize,
        max_signature_len: usize,
    ) -> Result<UniqueSignatureResult, String> {
        let read_len = (scan_stop.saturating_sub(scan_start)).min(32 * 1024 * 1024);
        let module_bytes = proc.read_bytes(scan_start, read_len)?;

        let max_target_read = max_signature_len.max(64) * 2;
        let target_code = proc.read_bytes(target_addr, max_target_read)?;

        let mut current_offset = 0;
        let mut accumulated_aob: Vec<AobByte> = Vec::new();
        let mut accumulated_pattern_parts: Vec<String> = Vec::new();

        while current_offset < target_code.len() && accumulated_aob.len() < max_signature_len {
            let insn_addr = target_addr + current_offset;
            let insn = Disassembler::decode_one(insn_addr, &target_code[current_offset..]);
            let len = insn.length.max(1);

            let is_rip = insn.target_addr.is_some() && insn.operands.to_lowercase().contains("rip");
            let insn_slice = &target_code[current_offset..current_offset + len];
            let (insn_aob, insn_str) = Self::mask_instruction(insn_slice, is_rip);

            accumulated_aob.extend(insn_aob);
            accumulated_pattern_parts.push(insn_str);
            current_offset += len;

            // Check uniqueness
            let matches = Self::count_matches_in_buffer(&module_bytes, &accumulated_aob);
            if matches == 1 {
                return Ok(UniqueSignatureResult {
                    pattern: accumulated_pattern_parts.join(" "),
                    length: accumulated_aob.len(),
                    match_count: 1,
                    is_unique: true,
                });
            }
        }

        // Return best attempt
        let total_matches = Self::count_matches_in_buffer(&module_bytes, &accumulated_aob);
        Ok(UniqueSignatureResult {
            pattern: accumulated_pattern_parts.join(" "),
            length: accumulated_aob.len(),
            match_count: total_matches,
            is_unique: total_matches == 1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_matches_in_buffer() {
        let haystack = vec![0x48, 0x89, 0x5C, 0x24, 0x08, 0x90, 0x48, 0x89, 0x5C, 0x24, 0x10];
        // 48 89 5C 24 ??
        let pattern = vec![
            AobByte::exact(0x48),
            AobByte::exact(0x89),
            AobByte::exact(0x5C),
            AobByte::exact(0x24),
            AobByte::wildcard(),
        ];

        let count = SignatureMaker::count_matches_in_buffer(&haystack, &pattern);
        assert_eq!(count, 2);

        // 48 89 5C 24 08 (exact)
        let exact_pattern = vec![
            AobByte::exact(0x48),
            AobByte::exact(0x89),
            AobByte::exact(0x5C),
            AobByte::exact(0x24),
            AobByte::exact(0x08),
        ];
        let exact_count = SignatureMaker::count_matches_in_buffer(&haystack, &exact_pattern);
        assert_eq!(exact_count, 1);
    }
}
