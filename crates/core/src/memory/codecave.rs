use crate::process::Process;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaveByteType {
    Int3,
    Nop,
    Zero,
    AnyPadding,
}

impl CaveByteType {
    pub fn matches(&self, byte: u8) -> bool {
        match self {
            Self::Int3 => byte == 0xCC,
            Self::Nop => byte == 0x90,
            Self::Zero => byte == 0x00,
            Self::AnyPadding => byte == 0xCC || byte == 0x90 || byte == 0x00,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecaveEntry {
    pub address: usize,
    pub size: usize,
    pub byte_value: u8,
}

pub struct CodecaveScanner;

impl CodecaveScanner {
    pub fn scan_buffer(
        buffer: &[u8],
        base_address: usize,
        min_size: usize,
        byte_type: CaveByteType,
    ) -> Vec<CodecaveEntry> {
        let mut caves = Vec::new();
        if buffer.is_empty() || min_size == 0 {
            return caves;
        }

        let mut run_start = 0;
        let mut current_byte = buffer[0];
        let mut in_run = byte_type.matches(current_byte);

        for (i, &b) in buffer.iter().enumerate().skip(1) {
            if in_run {
                let same_byte = match byte_type {
                    CaveByteType::AnyPadding => b == current_byte,
                    _ => byte_type.matches(b),
                };

                if same_byte {
                    continue;
                } else {
                    let run_len = i - run_start;
                    if run_len >= min_size {
                        caves.push(CodecaveEntry {
                            address: base_address + run_start,
                            size: run_len,
                            byte_value: current_byte,
                        });
                    }
                    current_byte = b;
                    in_run = byte_type.matches(b);
                    run_start = i;
                }
            } else {
                if byte_type.matches(b) {
                    current_byte = b;
                    in_run = true;
                    run_start = i;
                }
            }
        }

        if in_run {
            let run_len = buffer.len() - run_start;
            if run_len >= min_size {
                caves.push(CodecaveEntry {
                    address: base_address + run_start,
                    size: run_len,
                    byte_value: current_byte,
                });
            }
        }

        caves
    }

    pub fn scan_process(
        proc: &Process,
        start: usize,
        stop: usize,
        min_size: usize,
        byte_type: CaveByteType,
        executable_only: bool,
    ) -> Result<Vec<CodecaveEntry>, String> {
        let regions = proc.regions(false)?;
        let mut results = Vec::new();

        for r in regions {
            if r.base >= stop || (r.base + r.size) <= start {
                continue;
            }
            if !r.is_readable() {
                continue;
            }
            if executable_only && !r.is_executable() {
                continue;
            }

            let region_start = r.base.max(start);
            let region_end = (r.base + r.size).min(stop);
            let read_len = region_end.saturating_sub(region_start);
            if read_len < min_size {
                continue;
            }

            if let Ok(data) = proc.read_bytes(region_start, read_len) {
                let caves = Self::scan_buffer(&data, region_start, min_size, byte_type);
                results.extend(caves);
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_buffer_int3() {
        let mut buf = vec![0x90; 10];
        buf.extend(vec![0xCC; 32]);
        buf.extend(vec![0x48, 0x89, 0x5C, 0x24]);
        buf.extend(vec![0xCC; 16]);

        let caves = CodecaveScanner::scan_buffer(&buf, 0x140000000, 20, CaveByteType::Int3);
        assert_eq!(caves.len(), 1);
        assert_eq!(caves[0].address, 0x140000000 + 10);
        assert_eq!(caves[0].size, 32);
        assert_eq!(caves[0].byte_value, 0xCC);
    }

    #[test]
    fn test_scan_buffer_any_padding() {
        let mut buf = vec![0x00; 64];
        buf.extend(vec![0x90; 40]);
        buf.extend(vec![0x55, 0x48, 0x89, 0xE5]);

        let caves = CodecaveScanner::scan_buffer(&buf, 0x1000, 32, CaveByteType::AnyPadding);
        assert_eq!(caves.len(), 2);
        assert_eq!(caves[0].address, 0x1000);
        assert_eq!(caves[0].size, 64);
        assert_eq!(caves[0].byte_value, 0x00);
        assert_eq!(caves[1].address, 0x1000 + 64);
        assert_eq!(caves[1].size, 40);
        assert_eq!(caves[1].byte_value, 0x90);
    }
}
