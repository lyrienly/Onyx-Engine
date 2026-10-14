// language: Rust, file: pointer_scanner.rs, target: Windows 11, MSVC
// Multilevel pointer scanner and pointer map resolver

use std::collections::HashMap;
use std::mem::size_of;
use crate::process::{ModuleEntry, Process};

#[derive(Debug, Clone)]
pub struct PointerNode {
    pub from_address: usize,
    pub to_address: usize,
}

#[derive(Debug, Clone)]
pub struct PointerPath {
    pub module_name: String,
    pub base_offset: usize,
    pub offsets: Vec<usize>,
    pub final_address: usize,
}

impl PointerPath {
    pub fn to_display_string(&self) -> String {
        let mut s = format!("[\"{}\"+0x{:X}]", self.module_name, self.base_offset);
        for off in &self.offsets {
            s.push_str(&format!(" -> +0x{:X}", off));
        }
        s.push_str(&format!(" = 0x{:X}", self.final_address));
        s
    }
}

pub struct PointerScanner {
    // Reverse map: bucketed by destination range or direct index
    // destination_page -> list of (from_addr, to_addr)
    pub pointer_map: HashMap<usize, Vec<PointerNode>>,
}

impl PointerScanner {
    pub fn new() -> Self {
        PointerScanner {
            pointer_map: HashMap::new(),
        }
    }

    pub fn generate_map(&mut self, proc: &Process) -> Result<usize, String> {
        let regions = proc.regions(true)?;
        let ptr_size = size_of::<usize>();
        let mut total_pointers = 0;
        self.pointer_map.clear();

        // 4KB page indexing for fast reverse lookup
        const PAGE_SHIFT: usize = 12; // 4096 bytes per bucket

        let mut buf = vec![0u8; 512 * 1024];

        for region in &regions {
            let mut offset = 0;
            while offset < region.size {
                let cur_size = (region.size - offset).min(buf.len());
                let cur_addr = region.base + offset;

                if let Ok(read) = proc.read_raw(cur_addr, &mut buf[..cur_size]) {
                    if read >= ptr_size {
                        let max_i = read - ptr_size;
                        let mut i = 0;
                        while i <= max_i {
                            let ptr_val = if ptr_size == 8 {
                                u64::from_ne_bytes([
                                    buf[i], buf[i + 1], buf[i + 2], buf[i + 3],
                                    buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7],
                                ]) as usize
                            } else {
                                u32::from_ne_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize
                            };

                            // Check if pointer is non-null and reasonably aligned/sized
                            if ptr_val >= 0x10000 && ptr_val <= 0x7FFF_FFFF_FFFF {
                                let from_addr = cur_addr + i;
                                let bucket = ptr_val >> PAGE_SHIFT;

                                self.pointer_map
                                    .entry(bucket)
                                    .or_default()
                                    .push(PointerNode {
                                        from_address: from_addr,
                                        to_address: ptr_val,
                                    });
                                total_pointers += 1;
                            }
                            i += ptr_size;
                        }
                    }
                }
                offset += cur_size;
            }
        }

        Ok(total_pointers)
    }

    pub fn scan_paths(
        &self,
        proc: &Process,
        target_addr: usize,
        max_depth: usize,
        max_offset: usize,
    ) -> Result<Vec<PointerPath>, String> {
        let modules = proc.modules()?;
        let mut results = Vec::new();
        let mut current_offsets = Vec::new();

        self.find_recursive(
            target_addr,
            target_addr,
            max_depth,
            max_offset,
            &modules,
            &mut current_offsets,
            &mut results,
        );

        Ok(results)
    }

    fn find_recursive(
        &self,
        current_target: usize,
        final_target: usize,
        depth_left: usize,
        max_offset: usize,
        modules: &[ModuleEntry],
        offsets: &mut Vec<usize>,
        results: &mut Vec<PointerPath>,
    ) {
        if depth_left == 0 || results.len() >= 1000 {
            return;
        }

        const PAGE_SHIFT: usize = 12;
        let start_page = (current_target.saturating_sub(max_offset)) >> PAGE_SHIFT;
        let end_page = current_target >> PAGE_SHIFT;

        for page in start_page..=end_page {
            if let Some(nodes) = self.pointer_map.get(&page) {
                for node in nodes {
                    if node.to_address <= current_target && current_target - node.to_address <= max_offset {
                        let offset = current_target - node.to_address;
                        offsets.push(offset);

                        // Check if from_address is inside any module (static base!)
                        if let Some(m) = modules.iter().find(|m| node.from_address >= m.base && node.from_address < m.base + m.size) {
                            let base_offset = node.from_address - m.base;
                            let mut path_offsets = offsets.clone();
                            path_offsets.reverse();

                            results.push(PointerPath {
                                module_name: m.name.clone(),
                                base_offset,
                                offsets: path_offsets,
                                final_address: final_target,
                            });
                        } else if depth_left > 1 {
                            // Recurse deeper
                            self.find_recursive(
                                node.from_address,
                                final_target,
                                depth_left - 1,
                                max_offset,
                                modules,
                                offsets,
                                results,
                            );
                        }

                        offsets.pop();
                    }
                }
            }
        }
    }

    pub fn evaluate_path(proc: &Process, path: &PointerPath) -> Result<usize, String> {
        let m = proc.find_module(&path.module_name)
            .ok_or_else(|| format!("Module '{}' not found", path.module_name))?;
        let mut cur_addr = m.base + path.base_offset;

        for &off in &path.offsets {
            let next_ptr: usize = proc.read(cur_addr)?;
            if next_ptr == 0 {
                return Err(format!("Null pointer encountered at 0x{:X}", cur_addr));
            }
            cur_addr = next_ptr + off;
        }

        Ok(cur_addr)
    }

    pub fn rescan_paths(
        proc: &Process,
        paths: &[PointerPath],
        new_target_addr: usize,
    ) -> Vec<PointerPath> {
        paths
            .iter()
            .filter(|p| {
                if let Ok(resolved) = Self::evaluate_path(proc, p) {
                    resolved == new_target_addr
                } else {
                    false
                }
            })
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pointer_path_display() {
        let path = PointerPath {
            module_name: "game.exe".to_string(),
            base_offset: 0x1A00,
            offsets: vec![0x10, 0x48],
            final_address: 0x7FF7001048,
        };
        let s = path.to_display_string();
        assert!(s.contains("[\"game.exe\"+0x1A00]"));
        assert!(s.contains("-> +0x10"));
        assert!(s.contains("-> +0x48"));
    }
}


