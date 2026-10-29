use crate::memory::entropy::{EntropyClass, EntropyScanner};
use crate::process::{MemoryRegion, Process};
use crate::security::hook_detection::find_embedded_pe;
use crate::win32::{MEM_PRIVATE, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyKind {
    Rwx,
    PrivateExecutable,
    EmbeddedPe,
    HighEntropy,
}

impl AnomalyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalyKind::Rwx => "rwx",
            AnomalyKind::PrivateExecutable => "private_executable",
            AnomalyKind::EmbeddedPe => "embedded_pe",
            AnomalyKind::HighEntropy => "high_entropy",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionAnomaly {
    pub base: usize,
    pub size: usize,
    pub kind: AnomalyKind,
}

pub struct MemoryAnomalyScanner;

impl MemoryAnomalyScanner {
    pub fn classify(region: &MemoryRegion) -> Vec<AnomalyKind> {
        let mut kinds = Vec::new();
        if !region.is_committed() {
            return kinds;
        }

        if region.protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0 {
            kinds.push(AnomalyKind::Rwx);
        }

        if region.mem_type == MEM_PRIVATE && region.is_executable() {
            kinds.push(AnomalyKind::PrivateExecutable);
        }

        kinds
    }

    pub fn inspect(
        region: &MemoryRegion,
        bytes: &[u8],
        min_entropy_size: usize,
    ) -> Vec<RegionAnomaly> {
        let mut found: Vec<RegionAnomaly> = Self::classify(region)
            .into_iter()
            .map(|kind| RegionAnomaly {
                base: region.base,
                size: region.size,
                kind,
            })
            .collect();

        if !bytes.is_empty() {
            if let Some(offset) = find_embedded_pe(bytes).first().copied() {
                found.push(RegionAnomaly {
                    base: region.base.wrapping_add(offset),
                    size: region.size.saturating_sub(offset),
                    kind: AnomalyKind::EmbeddedPe,
                });
            }

            if bytes.len() >= min_entropy_size
                && EntropyScanner::classify(bytes) == EntropyClass::Encrypted
            {
                found.push(RegionAnomaly {
                    base: region.base,
                    size: bytes.len(),
                    kind: AnomalyKind::HighEntropy,
                });
            }
        }

        found
    }

    pub fn scan(
        proc: &Process,
        sample_cap: usize,
        min_entropy_size: usize,
    ) -> Result<Vec<RegionAnomaly>, String> {
        let regions = proc.regions(false)?;
        let mut found = Vec::new();

        for region in regions {
            if !region.is_readable() {
                continue;
            }

            let read_len = region.size.min(sample_cap.max(1));
            if read_len == 0 {
                continue;
            }

            let bytes = proc.read_bytes(region.base, read_len).unwrap_or_default();
            found.extend(Self::inspect(&region, &bytes, min_entropy_size));
        }

        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win32::{MEM_COMMIT, MEM_IMAGE, PAGE_EXECUTE_READ, PAGE_READWRITE};

    fn region(protect: u32, mem_type: u32) -> MemoryRegion {
        MemoryRegion {
            base: 0x1000,
            size: 0x1000,
            state: MEM_COMMIT,
            protect,
            mem_type,
        }
    }

    #[test]
    fn test_classify_rwx_private() {
        let kinds = MemoryAnomalyScanner::classify(&region(PAGE_EXECUTE_READWRITE, MEM_PRIVATE));
        assert!(kinds.contains(&AnomalyKind::Rwx));
        assert!(kinds.contains(&AnomalyKind::PrivateExecutable));
    }

    #[test]
    fn test_classify_private_executable_without_rwx() {
        let kinds = MemoryAnomalyScanner::classify(&region(PAGE_EXECUTE_READ, MEM_PRIVATE));
        assert_eq!(kinds, vec![AnomalyKind::PrivateExecutable]);
    }

    #[test]
    fn test_classify_image_executable_is_normal() {
        assert!(MemoryAnomalyScanner::classify(&region(PAGE_EXECUTE_READ, MEM_IMAGE)).is_empty());
    }

    #[test]
    fn test_classify_private_data_is_normal() {
        assert!(MemoryAnomalyScanner::classify(&region(PAGE_READWRITE, MEM_PRIVATE)).is_empty());
    }

    #[test]
    fn test_inspect_finds_embedded_pe() {
        let mut bytes = vec![0u8; 0x200];
        let mz = 0x20usize;
        bytes[mz] = 0x4D;
        bytes[mz + 1] = 0x5A;
        bytes[mz + 0x3C..mz + 0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[mz + 0x80..mz + 0x84].copy_from_slice(b"PE\0\0");

        let found =
            MemoryAnomalyScanner::inspect(&region(PAGE_EXECUTE_READ, MEM_PRIVATE), &bytes, 0);

        assert!(
            found
                .iter()
                .any(|a| a.kind == AnomalyKind::EmbeddedPe && a.base == 0x1000 + mz)
        );
    }

    #[test]
    fn test_inspect_flags_high_entropy() {
        let mut bytes = Vec::with_capacity(512);
        for _ in 0..2 {
            for b in 0u8..=255u8 {
                bytes.push(b);
            }
        }

        let found =
            MemoryAnomalyScanner::inspect(&region(PAGE_READWRITE, MEM_PRIVATE), &bytes, 256);

        assert!(found.iter().any(|a| a.kind == AnomalyKind::HighEntropy));
    }

    #[test]
    fn test_inspect_ignores_low_entropy() {
        let bytes = vec![0u8; 1024];
        let found =
            MemoryAnomalyScanner::inspect(&region(PAGE_READWRITE, MEM_PRIVATE), &bytes, 256);
        assert!(!found.iter().any(|a| a.kind == AnomalyKind::HighEntropy));
    }
}
