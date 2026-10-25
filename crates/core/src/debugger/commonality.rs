
use crate::process::Process;

pub const REGISTER_NAMES: [&str; 16] = [
    "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
];

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RegisterSnapshot {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

impl RegisterSnapshot {
    pub fn get_reg_by_index(&self, idx: usize) -> Option<u64> {
        match idx {
            0 => Some(self.rax),
            1 => Some(self.rbx),
            2 => Some(self.rcx),
            3 => Some(self.rdx),
            4 => Some(self.rsi),
            5 => Some(self.rdi),
            6 => Some(self.rbp),
            7 => Some(self.rsp),
            8 => Some(self.r8),
            9 => Some(self.r9),
            10 => Some(self.r10),
            11 => Some(self.r11),
            12 => Some(self.r12),
            13 => Some(self.r13),
            14 => Some(self.r14),
            15 => Some(self.r15),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterComparison {
    pub reg_name: &'static str,
    pub reg_index: usize,
    pub g1_constant: bool,
    pub g1_sample: u64,
    pub g2_constant: bool,
    pub g2_sample: u64,
    pub distinguishes_groups: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructureDifference {
    pub offset: usize,
    pub g1_constant: bool,
    pub g1_value: u64,
    pub g2_constant: bool,
    pub g2_value: u64,
    pub differentiates: bool,
    pub value_size: usize,
}

pub struct CommonalityAnalyzer;

impl CommonalityAnalyzer {

    pub fn analyze_registers(
        group1: &[RegisterSnapshot],
        group2: &[RegisterSnapshot],
    ) -> Vec<RegisterComparison> {
        let mut results = Vec::new();

        for (idx, &name) in REGISTER_NAMES.iter().enumerate() {
            let g1_vals: Vec<u64> = group1.iter().filter_map(|s| s.get_reg_by_index(idx)).collect();
            let g2_vals: Vec<u64> = group2.iter().filter_map(|s| s.get_reg_by_index(idx)).collect();

            let g1_constant = !g1_vals.is_empty() && g1_vals.iter().all(|&v| v == g1_vals[0]);
            let g2_constant = !g2_vals.is_empty() && g2_vals.iter().all(|&v| v == g2_vals[0]);

            let g1_sample = g1_vals.first().copied().unwrap_or(0);
            let g2_sample = g2_vals.first().copied().unwrap_or(0);

            let distinguishes = if !g1_vals.is_empty() && !g2_vals.is_empty() {
                if g1_constant && g2_constant {
                    g1_sample != g2_sample
                } else {

                    !g1_vals.iter().any(|v1| g2_vals.contains(v1))
                }
            } else {
                false
            };

            results.push(RegisterComparison {
                reg_name: name,
                reg_index: idx,
                g1_constant,
                g1_sample,
                g2_constant,
                g2_sample,
                distinguishes_groups: distinguishes,
            });
        }

        results
    }

    pub fn analyze_structures(
        proc: &Process,
        group1_ptrs: &[usize],
        group2_ptrs: &[usize],
        struct_size: usize,
    ) -> Result<Vec<StructureDifference>, String> {
        if group1_ptrs.is_empty() || group2_ptrs.is_empty() {
            return Ok(Vec::new());
        }

        let mut g1_data = Vec::new();
        for &ptr in group1_ptrs {
            if let Ok(bytes) = proc.read_bytes(ptr, struct_size) {
                g1_data.push(bytes);
            }
        }

        let mut g2_data = Vec::new();
        for &ptr in group2_ptrs {
            if let Ok(bytes) = proc.read_bytes(ptr, struct_size) {
                g2_data.push(bytes);
            }
        }

        if g1_data.is_empty() || g2_data.is_empty() {
            return Err("Failed to read structure memory for provided pointers".to_string());
        }

        let mut differences = Vec::new();
        let step = 4;

        let mut offset = 0;
        while offset + 4 <= struct_size {
            let mut g1_vals = Vec::new();
            for buf in &g1_data {
                if offset + 4 <= buf.len() {
                    let val = u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]) as u64;
                    g1_vals.push(val);
                }
            }

            let mut g2_vals = Vec::new();
            for buf in &g2_data {
                if offset + 4 <= buf.len() {
                    let val = u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]) as u64;
                    g2_vals.push(val);
                }
            }

            if !g1_vals.is_empty() && !g2_vals.is_empty() {
                let g1_const = g1_vals.iter().all(|&v| v == g1_vals[0]);
                let g2_const = g2_vals.iter().all(|&v| v == g2_vals[0]);
                let g1_samp = g1_vals[0];
                let g2_samp = g2_vals[0];

                let distinguishes = if g1_const && g2_const {
                    g1_samp != g2_samp
                } else {
                    !g1_vals.iter().any(|v1| g2_vals.contains(v1))
                };

                if distinguishes {
                    differences.push(StructureDifference {
                        offset,
                        g1_constant: g1_const,
                        g1_value: g1_samp,
                        g2_constant: g2_const,
                        g2_value: g2_samp,
                        differentiates: true,
                        value_size: 4,
                    });
                }
            }

            offset += step;
        }

        Ok(differences)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_registers() {
        let snap_p1 = RegisterSnapshot { rax: 0x100, rsi: 0x7FFE0000, ..Default::default() };
        let snap_p2 = RegisterSnapshot { rax: 0x100, rsi: 0x7FFE0000, ..Default::default() };

        let snap_e1 = RegisterSnapshot { rax: 0x200, rsi: 0x7FFE5000, ..Default::default() };
        let snap_e2 = RegisterSnapshot { rax: 0x200, rsi: 0x7FFE6000, ..Default::default() };

        let comps = CommonalityAnalyzer::analyze_registers(&[snap_p1, snap_p2], &[snap_e1, snap_e2]);

        let rax_comp = comps.iter().find(|c| c.reg_name == "RAX").unwrap();
        assert!(rax_comp.g1_constant);
        assert_eq!(rax_comp.g1_sample, 0x100);
        assert!(rax_comp.g2_constant);
        assert_eq!(rax_comp.g2_sample, 0x200);
        assert!(rax_comp.distinguishes_groups);

        let rsi_comp = comps.iter().find(|c| c.reg_name == "RSI").unwrap();
        assert!(rsi_comp.g1_constant);
        assert!(!rsi_comp.g2_constant);
        assert!(rsi_comp.distinguishes_groups);
    }
}

