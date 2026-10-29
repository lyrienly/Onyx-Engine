use crate::process::{ModuleEntry, Process};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::mem::size_of;

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

#[derive(Debug, Clone)]
pub struct PointerScanConfig {
    pub max_depth: usize,
    pub max_offset: usize,
    pub alignment: usize,
    pub max_results: usize,
    pub static_only: bool,
    pub min_address: usize,
    pub max_address: usize,
}

impl Default for PointerScanConfig {
    fn default() -> Self {
        Self {
            max_depth: 5,
            max_offset: 0x1000,
            alignment: 4,
            max_results: 20000,
            static_only: true,
            min_address: 0x10000,
            max_address: 0x7FFF_FFFF_FFFF,
        }
    }
}

pub struct PointerScanner {
    pub pointer_map: HashMap<usize, Vec<PointerNode>>,
    pub total_pointers: usize,
}

impl PointerScanner {
    pub fn new() -> Self {
        PointerScanner {
            pointer_map: HashMap::new(),
            total_pointers: 0,
        }
    }

    pub fn clear(&mut self) {
        self.pointer_map.clear();
        self.total_pointers = 0;
    }

    pub fn generate_map(&mut self, proc: &Process) -> Result<usize, String> {
        let config = PointerScanConfig::default();
        self.generate_map_with_progress(proc, &config, &mut |_, _| true)
    }

    pub fn generate_map_with_progress(
        &mut self,
        proc: &Process,
        config: &PointerScanConfig,
        progress_cb: &mut dyn FnMut(f32, usize) -> bool,
    ) -> Result<usize, String> {
        let regions = proc.regions(true)?;
        let ptr_size = size_of::<usize>();
        let align = if config.alignment == 0 {
            ptr_size
        } else {
            config.alignment
        };
        self.clear();

        const PAGE_SHIFT: usize = 12;
        let mut buf = vec![0u8; 1024 * 1024];

        let total_bytes: usize = regions.iter().map(|r| r.size).sum();
        let mut processed_bytes: usize = 0;

        for region in &regions {
            if region.base + region.size < config.min_address || region.base > config.max_address {
                processed_bytes += region.size;
                continue;
            }

            let mut offset = 0;
            while offset < region.size {
                let cur_size = (region.size - offset).min(buf.len());
                let cur_addr = region.base + offset;

                if let Ok(read) = proc.read_raw(cur_addr, &mut buf[..cur_size])
                    && read >= ptr_size
                {
                    let max_i = read - ptr_size;
                    let mut i = 0;
                    while i <= max_i {
                        let ptr_val = if ptr_size == 8 {
                            u64::from_ne_bytes([
                                buf[i],
                                buf[i + 1],
                                buf[i + 2],
                                buf[i + 3],
                                buf[i + 4],
                                buf[i + 5],
                                buf[i + 6],
                                buf[i + 7],
                            ]) as usize
                        } else {
                            u32::from_ne_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]])
                                as usize
                        };

                        if ptr_val >= config.min_address && ptr_val <= config.max_address {
                            let from_addr = cur_addr + i;
                            let bucket = ptr_val >> PAGE_SHIFT;

                            self.pointer_map
                                .entry(bucket)
                                .or_default()
                                .push(PointerNode {
                                    from_address: from_addr,
                                    to_address: ptr_val,
                                });
                            self.total_pointers += 1;
                        }
                        i += align;
                    }
                }

                offset += cur_size;
                processed_bytes += cur_size;

                let pct = if total_bytes > 0 {
                    (processed_bytes as f32 / total_bytes as f32) * 100.0
                } else {
                    100.0
                };

                if !progress_cb(pct.min(99.9), self.total_pointers) {
                    return Err("Pointer map generation cancelled".to_string());
                }
            }
        }

        let _ = progress_cb(100.0, self.total_pointers);
        Ok(self.total_pointers)
    }

    pub fn scan_paths(
        &self,
        proc: &Process,
        target_addr: usize,
        max_depth: usize,
        max_offset: usize,
    ) -> Result<Vec<PointerPath>, String> {
        let mut config = PointerScanConfig::default();
        config.max_depth = max_depth;
        config.max_offset = max_offset;
        self.scan_paths_with_progress(proc, target_addr, &config, &mut |_, _| true)
    }

    pub fn scan_paths_with_progress(
        &self,
        proc: &Process,
        target_addr: usize,
        config: &PointerScanConfig,
        progress_cb: &mut dyn FnMut(f32, usize) -> bool,
    ) -> Result<Vec<PointerPath>, String> {
        let modules = proc.modules()?;
        let mut results = Vec::new();
        let mut current_offsets = Vec::new();
        let mut visited = HashSet::new();

        self.find_recursive_safe(
            target_addr,
            target_addr,
            config.max_depth,
            config.max_offset,
            config.max_results,
            &modules,
            &mut current_offsets,
            &mut visited,
            &mut results,
            progress_cb,
        );

        let _ = progress_cb(100.0, results.len());
        Ok(results)
    }

    #[allow(clippy::too_many_arguments)]
    fn find_recursive_safe(
        &self,
        current_target: usize,
        final_target: usize,
        depth_left: usize,
        max_offset: usize,
        max_results: usize,
        modules: &[ModuleEntry],
        offsets: &mut Vec<usize>,
        visited: &mut HashSet<usize>,
        results: &mut Vec<PointerPath>,
        progress_cb: &mut dyn FnMut(f32, usize) -> bool,
    ) {
        if depth_left == 0 || results.len() >= max_results {
            return;
        }

        const PAGE_SHIFT: usize = 12;
        let start_page = (current_target.saturating_sub(max_offset)) >> PAGE_SHIFT;
        let end_page = current_target >> PAGE_SHIFT;

        for page in start_page..=end_page {
            if let Some(nodes) = self.pointer_map.get(&page) {
                for node in nodes {
                    if node.to_address <= current_target
                        && current_target - node.to_address <= max_offset
                    {
                        if visited.contains(&node.from_address) {
                            continue;
                        }

                        let offset = current_target - node.to_address;
                        offsets.push(offset);
                        visited.insert(node.from_address);

                        if let Some(m) = modules.iter().find(|m| {
                            node.from_address >= m.base && node.from_address < m.base + m.size
                        }) {
                            let base_offset = node.from_address - m.base;
                            let mut path_offsets = offsets.clone();
                            path_offsets.reverse();

                            results.push(PointerPath {
                                module_name: m.name.clone(),
                                base_offset,
                                offsets: path_offsets,
                                final_address: final_target,
                            });

                            if results.len().is_multiple_of(50) {
                                let _ = progress_cb(50.0, results.len());
                            }
                        } else if depth_left > 1 && results.len() < max_results {
                            self.find_recursive_safe(
                                node.from_address,
                                final_target,
                                depth_left - 1,
                                max_offset,
                                max_results,
                                modules,
                                offsets,
                                visited,
                                results,
                                progress_cb,
                            );
                        }

                        visited.remove(&node.from_address);
                        offsets.pop();

                        if results.len() >= max_results {
                            return;
                        }
                    }
                }
            }
        }
    }

    pub fn evaluate_path(proc: &Process, path: &PointerPath) -> Result<usize, String> {
        let m = proc
            .find_module(&path.module_name)
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
        let mut dummy_cb = |_: f32, _: usize| true;
        Self::rescan_paths_with_progress(proc, paths, new_target_addr, &mut dummy_cb)
    }

    pub fn rescan_paths_with_progress(
        proc: &Process,
        paths: &[PointerPath],
        new_target_addr: usize,
        progress_cb: &mut dyn FnMut(f32, usize) -> bool,
    ) -> Vec<PointerPath> {
        let mut valid_paths = Vec::new();
        let total = paths.len();

        for (idx, p) in paths.iter().enumerate() {
            if let Ok(resolved) = Self::evaluate_path(proc, p)
                && resolved == new_target_addr
            {
                let mut updated = p.clone();
                updated.final_address = resolved;
                valid_paths.push(updated);
            }

            if idx % 100 == 0 && total > 0 {
                let pct = (idx as f32 / total as f32) * 100.0;
                if !progress_cb(pct, valid_paths.len()) {
                    break;
                }
            }
        }

        let _ = progress_cb(100.0, valid_paths.len());
        valid_paths
    }

    pub fn rescan_paths_by_value_with_progress(
        proc: &Process,
        paths: &[PointerPath],
        expected_bytes: &[u8],
        progress_cb: &mut dyn FnMut(f32, usize) -> bool,
    ) -> Vec<PointerPath> {
        let mut valid_paths = Vec::new();
        let total = paths.len();
        let val_len = expected_bytes.len();
        if val_len == 0 {
            return valid_paths;
        }

        let mut read_buf = vec![0u8; val_len];

        for (idx, p) in paths.iter().enumerate() {
            if let Ok(resolved) = Self::evaluate_path(proc, p)
                && resolved != 0
                && let Ok(n) = proc.read_raw(resolved, &mut read_buf)
                && n == val_len
                && read_buf == expected_bytes
            {
                let mut updated = p.clone();
                updated.final_address = resolved;
                valid_paths.push(updated);
            }

            if idx % 100 == 0 && total > 0 {
                let pct = (idx as f32 / total as f32) * 100.0;
                if !progress_cb(pct, valid_paths.len()) {
                    break;
                }
            }
        }

        let _ = progress_cb(100.0, valid_paths.len());
        valid_paths
    }

    pub fn save_to_file(paths: &[PointerPath], path: &str) -> Result<(), String> {
        let file = File::create(path).map_err(|e| format!("Failed to create file: {}", e))?;
        let mut writer = BufWriter::new(file);

        writer.write_all(b"ONYXPTR1").map_err(|e| e.to_string())?;

        let count = paths.len() as u32;
        writer
            .write_all(&count.to_le_bytes())
            .map_err(|e| e.to_string())?;

        for p in paths {
            let mod_bytes = p.module_name.as_bytes();
            let mod_len = mod_bytes.len().min(255) as u8;
            writer.write_all(&[mod_len]).map_err(|e| e.to_string())?;
            writer
                .write_all(&mod_bytes[..mod_len as usize])
                .map_err(|e| e.to_string())?;

            writer
                .write_all(&(p.base_offset as u64).to_le_bytes())
                .map_err(|e| e.to_string())?;

            let off_count = p.offsets.len().min(16) as u16;
            writer
                .write_all(&off_count.to_le_bytes())
                .map_err(|e| e.to_string())?;
            for &off in &p.offsets[..off_count as usize] {
                writer
                    .write_all(&(off as u64).to_le_bytes())
                    .map_err(|e| e.to_string())?;
            }

            writer
                .write_all(&(p.final_address as u64).to_le_bytes())
                .map_err(|e| e.to_string())?;
        }

        writer.flush().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn load_from_file(path: &str) -> Result<Vec<PointerPath>, String> {
        let file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
        let mut reader = BufReader::new(file);

        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic).map_err(|e| e.to_string())?;
        if &magic != b"ONYXPTR1" {
            return Err("Invalid Onyx pointer file signature".to_string());
        }

        let mut count_buf = [0u8; 4];
        reader
            .read_exact(&mut count_buf)
            .map_err(|e| e.to_string())?;
        let count = u32::from_le_bytes(count_buf) as usize;

        let mut paths = Vec::with_capacity(count.min(100_000));

        for _ in 0..count {
            let mut mod_len_buf = [0u8; 1];
            reader
                .read_exact(&mut mod_len_buf)
                .map_err(|e| e.to_string())?;
            let mod_len = mod_len_buf[0] as usize;

            let mut mod_bytes = vec![0u8; mod_len];
            reader
                .read_exact(&mut mod_bytes)
                .map_err(|e| e.to_string())?;
            let module_name = String::from_utf8_lossy(&mod_bytes).to_string();

            let mut base_off_buf = [0u8; 8];
            reader
                .read_exact(&mut base_off_buf)
                .map_err(|e| e.to_string())?;
            let base_offset = u64::from_le_bytes(base_off_buf) as usize;

            let mut off_count_buf = [0u8; 2];
            reader
                .read_exact(&mut off_count_buf)
                .map_err(|e| e.to_string())?;
            let off_count = u16::from_le_bytes(off_count_buf) as usize;

            let mut offsets = Vec::with_capacity(off_count);
            for _ in 0..off_count {
                let mut off_buf = [0u8; 8];
                reader.read_exact(&mut off_buf).map_err(|e| e.to_string())?;
                offsets.push(u64::from_le_bytes(off_buf) as usize);
            }

            let mut final_addr_buf = [0u8; 8];
            reader
                .read_exact(&mut final_addr_buf)
                .map_err(|e| e.to_string())?;
            let final_address = u64::from_le_bytes(final_addr_buf) as usize;

            paths.push(PointerPath {
                module_name,
                base_offset,
                offsets,
                final_address,
            });
        }

        Ok(paths)
    }

    pub fn save_map_to_file(&self, path: &str, modules: &[ModuleEntry]) -> Result<(), String> {
        let file = File::create(path).map_err(|e| format!("Failed to create map file: {}", e))?;
        let mut writer = BufWriter::with_capacity(1024 * 1024, file);

        writer.write_all(b"ONYXMAP1").map_err(|e| e.to_string())?;

        let mod_count = modules.len() as u32;
        writer
            .write_all(&mod_count.to_le_bytes())
            .map_err(|e| e.to_string())?;
        for m in modules {
            let name_bytes = m.name.as_bytes();
            let name_len = name_bytes.len().min(255) as u8;
            writer.write_all(&[name_len]).map_err(|e| e.to_string())?;
            writer
                .write_all(&name_bytes[..name_len as usize])
                .map_err(|e| e.to_string())?;
            writer
                .write_all(&(m.base as u64).to_le_bytes())
                .map_err(|e| e.to_string())?;
            writer
                .write_all(&(m.size as u64).to_le_bytes())
                .map_err(|e| e.to_string())?;
        }

        let ptr_count = self.total_pointers as u64;
        writer
            .write_all(&ptr_count.to_le_bytes())
            .map_err(|e| e.to_string())?;
        for nodes in self.pointer_map.values() {
            for node in nodes {
                writer
                    .write_all(&(node.from_address as u64).to_le_bytes())
                    .map_err(|e| e.to_string())?;
                writer
                    .write_all(&(node.to_address as u64).to_le_bytes())
                    .map_err(|e| e.to_string())?;
            }
        }

        writer.flush().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn load_map_from_file(path: &str) -> Result<(Self, Vec<ModuleEntry>), String> {
        let file = File::open(path).map_err(|e| format!("Failed to open map file: {}", e))?;
        let mut reader = BufReader::with_capacity(1024 * 1024, file);

        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic).map_err(|e| e.to_string())?;
        if &magic != b"ONYXMAP1" {
            return Err("Invalid Onyx pointer map signature".to_string());
        }

        let mut mod_count_buf = [0u8; 4];
        reader
            .read_exact(&mut mod_count_buf)
            .map_err(|e| e.to_string())?;
        let mod_count = u32::from_le_bytes(mod_count_buf) as usize;
        let mut modules = Vec::with_capacity(mod_count);

        for _ in 0..mod_count {
            let mut len_buf = [0u8; 1];
            reader.read_exact(&mut len_buf).map_err(|e| e.to_string())?;
            let mut name_buf = vec![0u8; len_buf[0] as usize];
            reader
                .read_exact(&mut name_buf)
                .map_err(|e| e.to_string())?;
            let name = String::from_utf8_lossy(&name_buf).to_string();

            let mut base_buf = [0u8; 8];
            reader
                .read_exact(&mut base_buf)
                .map_err(|e| e.to_string())?;
            let base = u64::from_le_bytes(base_buf) as usize;

            let mut size_buf = [0u8; 8];
            reader
                .read_exact(&mut size_buf)
                .map_err(|e| e.to_string())?;
            let size = u64::from_le_bytes(size_buf) as usize;

            modules.push(ModuleEntry {
                name,
                path: String::new(),
                base,
                size,
            });
        }

        let mut ptr_count_buf = [0u8; 8];
        reader
            .read_exact(&mut ptr_count_buf)
            .map_err(|e| e.to_string())?;
        let ptr_count = u64::from_le_bytes(ptr_count_buf) as usize;

        let mut scanner = PointerScanner::new();
        const PAGE_SHIFT: usize = 12;

        for _ in 0..ptr_count {
            let mut from_buf = [0u8; 8];
            reader
                .read_exact(&mut from_buf)
                .map_err(|e| e.to_string())?;
            let from_address = u64::from_le_bytes(from_buf) as usize;

            let mut to_buf = [0u8; 8];
            reader.read_exact(&mut to_buf).map_err(|e| e.to_string())?;
            let to_address = u64::from_le_bytes(to_buf) as usize;

            let bucket = to_address >> PAGE_SHIFT;
            scanner
                .pointer_map
                .entry(bucket)
                .or_default()
                .push(PointerNode {
                    from_address,
                    to_address,
                });
            scanner.total_pointers += 1;
        }

        Ok((scanner, modules))
    }

    pub fn scan_paths_offline(
        &self,
        modules: &[ModuleEntry],
        target_addr: usize,
        config: &PointerScanConfig,
        progress_cb: &mut dyn FnMut(f32, usize) -> bool,
    ) -> Result<Vec<PointerPath>, String> {
        let mut results = Vec::new();
        let mut current_offsets = Vec::new();
        let mut visited = HashSet::new();

        self.find_recursive_safe(
            target_addr,
            target_addr,
            config.max_depth,
            config.max_offset,
            config.max_results,
            modules,
            &mut current_offsets,
            &mut visited,
            &mut results,
            progress_cb,
        );

        let _ = progress_cb(100.0, results.len());
        Ok(results)
    }

    pub fn evaluate_path_in_map(
        &self,
        modules: &[ModuleEntry],
        path: &PointerPath,
    ) -> Option<usize> {
        let m = modules
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(&path.module_name))?;
        let mut cur_addr = m.base + path.base_offset;

        for &off in &path.offsets {
            let mut found_dest = None;
            for nodes in self.pointer_map.values() {
                if let Some(node) = nodes.iter().find(|n| n.from_address == cur_addr) {
                    found_dest = Some(node.to_address);
                    break;
                }
            }

            let next_ptr = found_dest?;
            if next_ptr == 0 {
                return None;
            }
            cur_addr = next_ptr + off;
        }

        Some(cur_addr)
    }

    pub fn intersect_paths(paths_a: &[PointerPath], paths_b: &[PointerPath]) -> Vec<PointerPath> {
        let mut b_set: HashSet<(String, usize, Vec<usize>)> = HashSet::new();
        for p in paths_b {
            b_set.insert((
                p.module_name.to_lowercase(),
                p.base_offset,
                p.offsets.clone(),
            ));
        }

        paths_a
            .iter()
            .filter(|p| {
                b_set.contains(&(
                    p.module_name.to_lowercase(),
                    p.base_offset,
                    p.offsets.clone(),
                ))
            })
            .cloned()
            .collect()
    }
}

impl Default for PointerScanner {
    fn default() -> Self {
        Self::new()
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

    #[test]
    fn test_save_load_file() {
        let path = PointerPath {
            module_name: "test.dll".to_string(),
            base_offset: 0x240,
            offsets: vec![0x8, 0x14],
            final_address: 0x12345678,
        };
        let file_path = std::env::temp_dir().join("test_save_load.onyxptr");
        let file_str = file_path.to_str().unwrap();

        assert!(PointerScanner::save_to_file(std::slice::from_ref(&path), file_str).is_ok());
        let loaded = PointerScanner::load_from_file(file_str).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].module_name, "test.dll");
        assert_eq!(loaded[0].base_offset, 0x240);
        assert_eq!(loaded[0].offsets, vec![0x8, 0x14]);
        assert_eq!(loaded[0].final_address, 0x12345678);

        let _ = std::fs::remove_file(file_path);
    }

    #[test]
    fn test_save_load_map_and_offline_scan() {
        let mut scanner = PointerScanner::new();
        let modules = vec![ModuleEntry {
            name: "testapp.exe".to_string(),
            path: String::new(),
            base: 0x140000000,
            size: 0x50000,
        }];

        const PAGE_SHIFT: usize = 12;

        scanner
            .pointer_map
            .entry(0x200000 >> PAGE_SHIFT)
            .or_default()
            .push(PointerNode {
                from_address: 0x140001000,
                to_address: 0x200000,
            });
        scanner.total_pointers += 1;

        scanner
            .pointer_map
            .entry(0x300000 >> PAGE_SHIFT)
            .or_default()
            .push(PointerNode {
                from_address: 0x200020,
                to_address: 0x300000,
            });
        scanner.total_pointers += 1;

        let file_path = std::env::temp_dir().join("test_map.ptrmap");
        let file_str = file_path.to_str().unwrap();

        assert!(scanner.save_map_to_file(file_str, &modules).is_ok());

        let (loaded_scanner, loaded_mods) =
            PointerScanner::load_map_from_file(file_str).expect("load ptrmap");
        assert_eq!(loaded_mods.len(), 1);
        assert_eq!(loaded_mods[0].name, "testapp.exe");
        assert_eq!(loaded_scanner.total_pointers, 2);

        let mut config = PointerScanConfig::default();
        config.max_depth = 3;
        config.max_offset = 0x100;
        let paths = loaded_scanner
            .scan_paths_offline(&loaded_mods, 0x300040, &config, &mut |_, _| true)
            .unwrap();

        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].module_name, "testapp.exe");
        assert_eq!(paths[0].base_offset, 0x1000);
        assert_eq!(paths[0].offsets, vec![0x20, 0x40]);
        assert_eq!(paths[0].final_address, 0x300040);

        let eval_addr = loaded_scanner.evaluate_path_in_map(&loaded_mods, &paths[0]);
        assert_eq!(eval_addr, Some(0x300040));

        let other_paths = vec![paths[0].clone()];
        let intersected = PointerScanner::intersect_paths(&paths, &other_paths);
        assert_eq!(intersected.len(), 1);

        let _ = std::fs::remove_file(file_path);
    }
}
