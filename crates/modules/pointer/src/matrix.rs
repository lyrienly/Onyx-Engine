//! Compact 64-bit Pointer Matrix representation for high-throughput GPU/Compute traversal.
//! Pointers are represented as contiguous 128-bit records ([u64; 2]: from_address, to_address)
//! sorted by to_address for O(log N) binary search candidate slicing.

#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PointerPair {
    pub from_address: u64,
    pub to_address: u64,
}

#[derive(Debug, Clone, Default)]
pub struct CompactPointerMatrix {
    pub pairs: Vec<PointerPair>,
}

impl CompactPointerMatrix {
    pub fn new() -> Self {
        Self { pairs: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            pairs: Vec::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    pub fn push(&mut self, from: u64, to: u64) {
        self.pairs.push(PointerPair {
            from_address: from,
            to_address: to,
        });
    }

    /// Sorts pairs by `to_address` (primary) and `from_address` (secondary)
    /// to enable fast binary search slicing.
    pub fn sort_and_dedup(&mut self) {
        self.pairs.sort_unstable_by(|a, b| {
            a.to_address
                .cmp(&b.to_address)
                .then_with(|| a.from_address.cmp(&b.from_address))
        });
        self.pairs.dedup();
    }

    /// Finds candidate slice where `to_address` falls in [min_target, max_target]
    pub fn find_range(&self, min_target: u64, max_target: u64) -> &[PointerPair] {
        if self.pairs.is_empty() || min_target > max_target {
            return &[];
        }
        let start = self.pairs.partition_point(|p| p.to_address < min_target);
        let end = self.pairs.partition_point(|p| p.to_address <= max_target);
        if start >= end {
            &[]
        } else {
            &self.pairs[start..end]
        }
    }

    /// High-speed candidate search with offset and alignment filters
    pub fn find_candidates(
        &self,
        target_address: u64,
        max_offset: usize,
        alignment: usize,
    ) -> Vec<(u64, usize)> {
        let min_target = target_address.saturating_sub(max_offset as u64);
        let max_target = target_address;
        let slice = self.find_range(min_target, max_target);

        let align_val = alignment.max(1) as u64;
        let mut results = Vec::with_capacity(slice.len().min(1024));

        for p in slice {
            if p.to_address <= target_address {
                let offset = target_address - p.to_address;
                if offset % align_val == 0 {
                    results.push((p.from_address, offset as usize));
                }
            }
        }
        results
    }

    /// Raw buffer pointer for GPU VRAM / DirectCompute transfer
    pub fn as_raw_ptr(&self) -> *const u64 {
        self.pairs.as_ptr() as *const u64
    }

    /// Size of raw matrix buffer in bytes
    pub fn byte_size(&self) -> usize {
        self.pairs.len() * std::mem::size_of::<PointerPair>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matrix_range_search_and_alignment() {
        let mut matrix = CompactPointerMatrix::new();
        matrix.push(0x1000, 0x5000);
        matrix.push(0x1020, 0x5004);
        matrix.push(0x1040, 0x5007); // unaligned for 4-byte
        matrix.push(0x1060, 0x5008);
        matrix.push(0x1080, 0x6000);

        matrix.sort_and_dedup();

        // Target: 0x5010, max_offset: 0x20
        // Expected: 0x5000 (off 16), 0x5004 (off 12), 0x5008 (off 8)
        let candidates = matrix.find_candidates(0x5010, 0x20, 4);
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0], (0x1000, 16));
        assert_eq!(candidates[1], (0x1020, 12));
        assert_eq!(candidates[2], (0x1060, 8));
    }
}
