use std::collections::{HashMap, HashSet};
use crate::process::Process;
use crate::debugger::disasm::Disassembler;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchKind {
    Call,
    UnconditionalJump,
    ConditionalJump,
    Return,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DissectBranch {
    pub from_address: usize,
    pub to_address: usize,
    pub kind: BranchKind,
}

#[derive(Debug, Clone, Default)]
pub struct DissectCodeResult {
    pub branches: Vec<DissectBranch>,
    pub function_starts: Vec<usize>,

    pub xrefs: HashMap<usize, Vec<usize>>,
}

pub struct DissectCodeEngine;

impl DissectCodeEngine {

    pub fn dissect_buffer(code: &[u8], base_address: usize) -> DissectCodeResult {
        let mut result = DissectCodeResult::default();
        let mut function_starts = HashSet::new();
        let mut xrefs: HashMap<usize, Vec<usize>> = HashMap::new();

        let mut offset = 0;
        let mut last_was_ret = true;

        while offset < code.len() {

            if code[offset] == 0xCC || code[offset] == 0x90 {
                last_was_ret = true;
                offset += 1;
                continue;
            }
            if offset + 1 < code.len() && code[offset] == 0 && code[offset + 1] == 0 {
                let current_addr = base_address + offset;
                let align_skip = 8 - (current_addr % 8);
                last_was_ret = true;
                offset += align_skip;
                continue;
            }

            let insn_addr = base_address + offset;
            let insn = Disassembler::decode_one(insn_addr, &code[offset..]);
            let len = insn.length.max(1);

            if last_was_ret {
                function_starts.insert(insn_addr);
                last_was_ret = false;
            }

            let m = insn.mnemonic.to_lowercase();

            if m == "ret" || m == "retn" || m == "retf" {
                result.branches.push(DissectBranch {
                    from_address: insn_addr,
                    to_address: 0,
                    kind: BranchKind::Return,
                });
                last_was_ret = true;
            } else if m == "call" {
                if let Some(target) = insn.target_addr {
                    result.branches.push(DissectBranch {
                        from_address: insn_addr,
                        to_address: target,
                        kind: BranchKind::Call,
                    });
                    function_starts.insert(target);
                    xrefs.entry(target).or_default().push(insn_addr);
                }
            } else if m == "jmp" {
                if let Some(target) = insn.target_addr {
                    result.branches.push(DissectBranch {
                        from_address: insn_addr,
                        to_address: target,
                        kind: BranchKind::UnconditionalJump,
                    });
                    xrefs.entry(target).or_default().push(insn_addr);
                }
                last_was_ret = true;
            } else if m.starts_with('j')

                && let Some(target) = insn.target_addr {
                    result.branches.push(DissectBranch {
                        from_address: insn_addr,
                        to_address: target,
                        kind: BranchKind::ConditionalJump,
                    });
                    xrefs.entry(target).or_default().push(insn_addr);
                }

            offset += len;
        }

        let mut sorted_starts: Vec<usize> = function_starts.into_iter().collect();
        sorted_starts.sort_unstable();

        result.function_starts = sorted_starts;
        result.xrefs = xrefs;
        result
    }

    pub fn dissect_range(
        proc: &Process,
        start: usize,
        stop: usize,
    ) -> Result<DissectCodeResult, String> {
        let regions = proc.regions(false)?;
        let mut final_result = DissectCodeResult::default();
        let mut all_starts = HashSet::new();

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
                let partial = Self::dissect_buffer(&data, region_start);
                final_result.branches.extend(partial.branches);
                for (callee, callers) in partial.xrefs {
                    final_result.xrefs.entry(callee).or_default().extend(callers);
                }
                all_starts.extend(partial.function_starts);
            }
        }

        let mut sorted_starts: Vec<usize> = all_starts.into_iter().collect();
        sorted_starts.sort_unstable();
        final_result.function_starts = sorted_starts;

        Ok(final_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dissect_buffer_call_and_ret() {

        let mut code = vec![0xE8, 0x10, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC];
        while code.len() < 0x15 {
            code.push(0xCC);
        }
        code.push(0x90);
        code.push(0xC3);

        let result = DissectCodeEngine::dissect_buffer(&code, 0x1000);

        assert!(result.function_starts.contains(&0x1000));
        assert!(result.function_starts.contains(&0x1015));

        let callers = result.xrefs.get(&0x1015).expect("XRef should exist");
        assert!(callers.contains(&0x1000));

        let calls: Vec<_> = result.branches.iter().filter(|b| b.kind == BranchKind::Call).collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].from_address, 0x1000);
        assert_eq!(calls[0].to_address, 0x1015);
    }
}
