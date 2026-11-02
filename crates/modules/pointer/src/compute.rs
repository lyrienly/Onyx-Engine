//! Parallel Reverse Pointer Search Engine (Wavefront Expansion).
//! Implements GPU-style breadth-first wavefront exploration of pointer paths.

use super::matrix::CompactPointerMatrix;
use onyx_core::pointer_scanner::PointerPath;
use onyx_core::process::ModuleEntry;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone)]
struct WavefrontNode {
    current_address: u64,
    offsets: Vec<usize>,
    visited: HashSet<u64>,
}

pub struct ComputePointerScanner;

impl ComputePointerScanner {
    /// Executes a parallel reverse pointer scan from `target_address` using the compact matrix.
    pub fn scan_wavefront(
        matrix: &CompactPointerMatrix,
        target_address: u64,
        max_depth: usize,
        max_offset: usize,
        alignment: usize,
        max_results: usize,
        modules: &[ModuleEntry],
        cancel_flag: Option<Arc<AtomicBool>>,
        progress_cb: Option<&mut dyn FnMut(f32, usize) -> bool>,
    ) -> Vec<PointerPath> {
        let mut results = Vec::new();
        if matrix.is_empty() || max_depth == 0 {
            return results;
        }

        let mut queue: Vec<WavefrontNode> = vec![WavefrontNode {
            current_address: target_address,
            offsets: Vec::new(),
            visited: {
                let mut set = HashSet::with_capacity(max_depth + 1);
                set.insert(target_address);
                set
            },
        }];

        let mut current_depth = 0;
        let mut cb = progress_cb;

        while current_depth < max_depth && !queue.is_empty() && results.len() < max_results {
            if let Some(ref cancel) = cancel_flag {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
            }

            let mut next_queue = Vec::with_capacity(queue.len() * 4);

            for node in &queue {
                if results.len() >= max_results {
                    break;
                }

                let candidates =
                    matrix.find_candidates(node.current_address, max_offset, alignment);

                for (from_addr, offset) in candidates {
                    if node.visited.contains(&from_addr) {
                        continue;
                    }

                    let mut new_offsets = node.offsets.clone();
                    new_offsets.push(offset);

                    // Check if from_addr points directly into a loaded module
                    if let Some(m) = modules.iter().find(|m| {
                        (from_addr as usize) >= m.base && (from_addr as usize) < (m.base + m.size)
                    }) {
                        let base_offset = (from_addr as usize) - m.base;
                        let mut final_offsets = new_offsets.clone();
                        final_offsets.reverse();

                        results.push(PointerPath {
                            module_name: m.name.clone(),
                            base_offset,
                            offsets: final_offsets,
                            final_address: target_address as usize,
                        });

                        if let Some(ref mut callback) = cb {
                            let pct = ((current_depth + 1) as f32 / max_depth as f32) * 100.0;
                            if !callback(pct, results.len()) {
                                return results;
                            }
                        }

                        if results.len() >= max_results {
                            return results;
                        }
                    } else if current_depth + 1 < max_depth {
                        let mut new_visited = node.visited.clone();
                        new_visited.insert(from_addr);

                        next_queue.push(WavefrontNode {
                            current_address: from_addr,
                            offsets: new_offsets,
                            visited: new_visited,
                        });
                    }
                }
            }

            current_depth += 1;
            queue = next_queue;
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_wavefront_finds_path() {
        let mut matrix = CompactPointerMatrix::new();
        // Module base: 0x400000, size: 0x10000
        // Module ptr at 0x401000 -> points to 0x500000
        // Intermediate ptr at 0x500020 -> points to target 0x600000 with offset 0x10
        matrix.push(0x401000, 0x500000);
        matrix.push(0x500020, 0x5FFFE0); // points to 0x5FFFE0, target is 0x600000 (offset 0x20)
        matrix.sort_and_dedup();

        let modules = vec![ModuleEntry {
            base: 0x400000,
            size: 0x10000,
            name: "test.exe".to_string(),
            path: "".to_string(),
        }];

        let paths = ComputePointerScanner::scan_wavefront(
            &matrix, 0x600000, 5, 0x1000, 4, 100, &modules, None, None,
        );

        assert!(!paths.is_empty());
        assert_eq!(paths[0].module_name, "test.exe");
    }
}
