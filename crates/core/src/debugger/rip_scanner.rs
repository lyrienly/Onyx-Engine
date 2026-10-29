use crate::debugger::disasm::Disassembler;
use crate::process::Process;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RipRelativeMatch {
    pub instruction_address: usize,
    pub target_address: usize,
    pub mnemonic: String,
    pub operands: String,
    pub bytes: Vec<u8>,
}

pub struct RipRelativeScanner;

impl RipRelativeScanner {
    pub fn scan_buffer(
        code: &[u8],
        base_address: usize,
        target_filter: Option<usize>,
    ) -> Vec<RipRelativeMatch> {
        let mut matches = Vec::new();
        let mut offset = 0;

        while offset < code.len() {
            if offset + 1 < code.len() && code[offset] == 0 && code[offset + 1] == 0 {
                let current_addr = base_address + offset;
                let align_skip = 8 - (current_addr % 8);
                offset += align_skip;
                continue;
            }

            let insn_addr = base_address + offset;
            let insn = Disassembler::decode_one(insn_addr, &code[offset..]);
            let len = insn.length.max(1);

            if let Some(target) = insn.target_addr {
                let matches_filter = match target_filter {
                    Some(expected) => target == expected,
                    None => true,
                };

                if matches_filter {
                    matches.push(RipRelativeMatch {
                        instruction_address: insn_addr,
                        target_address: target,
                        mnemonic: insn.mnemonic,
                        operands: insn.operands,
                        bytes: insn.bytes,
                    });
                }
            }

            offset += len;
        }

        matches
    }

    pub fn scan_range(
        proc: &Process,
        start: usize,
        stop: usize,
        target_filter: Option<usize>,
    ) -> Result<Vec<RipRelativeMatch>, String> {
        let regions = proc.regions(false)?;
        let mut results = Vec::new();

        for r in regions {
            if r.base >= stop || (r.base + r.size) <= start {
                continue;
            }
            if !r.is_readable() || !r.is_executable() {
                continue;
            }

            let region_start = r.base.max(start);
            let region_end = (r.base + r.size).min(stop);
            let read_len = region_end.saturating_sub(region_start);
            if read_len == 0 {
                continue;
            }

            if let Ok(data) = proc.read_bytes(region_start, read_len) {
                let matches = Self::scan_buffer(&data, region_start, target_filter);
                results.extend(matches);
            }
        }

        Ok(results)
    }

    pub fn scan_module(
        proc: &Process,
        module_name: &str,
        target_filter: Option<usize>,
    ) -> Result<Vec<RipRelativeMatch>, String> {
        let m = proc
            .find_module(module_name)
            .ok_or_else(|| format!("Module '{}' not found", module_name))?;

        Self::scan_range(proc, m.base, m.base + m.size, target_filter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_buffer_rip_relative() {
        let mut code = vec![0x48, 0x8B, 0x05, 0x0A, 0x00, 0x00, 0x00];

        code.extend(vec![0x90, 0x90, 0x90]);

        let matches = RipRelativeScanner::scan_buffer(&code, 0x140001000, None);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].instruction_address, 0x140001000);
        assert_eq!(matches[0].target_address, 0x140001011);

        let filtered = RipRelativeScanner::scan_buffer(&code, 0x140001000, Some(0x140001011));
        assert_eq!(filtered.len(), 1);

        let non_matching = RipRelativeScanner::scan_buffer(&code, 0x140001000, Some(0x140009999));
        assert_eq!(non_matching.len(), 0);
    }
}
