
use crate::process::Process;

pub const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
pub const FNV_PRIME: u64 = 0x100000001b3;

pub fn fnv1a64(buf: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for &b in buf {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotChunk {
    pub address: usize,
    pub size: usize,
    pub hash: u64,
}

#[derive(Debug, Clone)]
pub struct MemorySnapshot {
    pub chunks: Vec<SnapshotChunk>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangedRegion {
    pub start: usize,
    pub end: usize,
}

impl ChangedRegion {
    pub fn len(&self) -> usize {
        self.end - self.start
    }
}

impl MemorySnapshot {
    pub fn capture(
        proc: &Process,
        start: usize,
        stop: usize,
        chunk_size: usize,
    ) -> Result<Self, String> {
        let chunk = chunk_size.max(1);
        let regions = proc.regions(false)?;
        let mut chunks = Vec::new();

        for r in regions {
            if r.base >= stop || (r.base + r.size) <= start {
                continue;
            }
            if !r.is_readable() {
                continue;
            }

            let region_start = r.base.max(start);
            let region_end = (r.base + r.size).min(stop);

            let mut cur = region_start;
            while cur < region_end {
                let len = (region_end - cur).min(chunk);
                let data = proc.read_bytes(cur, len)?;
                chunks.push(SnapshotChunk {
                    address: cur,
                    size: len,
                    hash: fnv1a64(&data),
                });
                cur += len;
            }
        }

        Ok(MemorySnapshot { chunks })
    }

    pub fn diff(&self, other: &Self) -> Vec<ChangedRegion> {
        let mut raw: Vec<(usize, usize)> = Vec::new();
        let mut i = 0;
        let mut j = 0;

        loop {
            let a = self.chunks.get(i);
            let b = other.chunks.get(j);
            match (a, b) {
                (Some(a), Some(b)) => {
                    if a.address == b.address {
                        if a.hash != b.hash {
                            raw.push((a.address, a.address + a.size));
                        }
                        i += 1;
                        j += 1;
                    } else if a.address < b.address {
                        raw.push((a.address, a.address + a.size));
                        i += 1;
                    } else {
                        raw.push((b.address, b.address + b.size));
                        j += 1;
                    }
                }
                (Some(a), None) => {
                    raw.push((a.address, a.address + a.size));
                    i += 1;
                }
                (None, Some(b)) => {
                    raw.push((b.address, b.address + b.size));
                    j += 1;
                }
                (None, None) => break,
            }
        }

        merge_changed(raw)
    }

    pub fn changed_byte_count(&self, other: &Self) -> usize {
        self.diff(other).iter().map(|r| r.len()).sum()
    }
}

fn merge_changed(mut raw: Vec<(usize, usize)>) -> Vec<ChangedRegion> {
    raw.sort_by_key(|&(s, _)| s);
    let mut out: Vec<ChangedRegion> = Vec::new();

    for (s, e) in raw {
        if let Some(last) = out.last_mut() {
            if s <= last.end {
                if e > last.end {
                    last.end = e;
                }
                continue;
            }
        }
        out.push(ChangedRegion { start: s, end: e });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(address: usize, size: usize, hash: u64) -> SnapshotChunk {
        SnapshotChunk { address, size, hash }
    }

    #[test]
    fn test_fnv1a64_empty() {
        assert_eq!(fnv1a64(&[]), FNV_OFFSET_BASIS);
    }

    #[test]
    fn test_fnv1a64_deterministic_and_distinct() {
        assert_eq!(fnv1a64(b"hello"), fnv1a64(b"hello"));
        assert_ne!(fnv1a64(b"hello"), fnv1a64(b"world"));
        assert_ne!(fnv1a64(&[0x00]), fnv1a64(&[0x01]));
    }

    #[test]
    fn test_diff_identical() {
        let a = MemorySnapshot { chunks: vec![chunk(0x1000, 16, 1), chunk(0x1010, 16, 2)] };
        let b = MemorySnapshot { chunks: vec![chunk(0x1000, 16, 1), chunk(0x1010, 16, 2)] };
        assert!(a.diff(&b).is_empty());
        assert_eq!(a.changed_byte_count(&b), 0);
    }

    #[test]
    fn test_diff_single_changed_chunk() {
        let a = MemorySnapshot { chunks: vec![chunk(0x1000, 16, 1), chunk(0x1010, 16, 2)] };
        let b = MemorySnapshot { chunks: vec![chunk(0x1000, 16, 1), chunk(0x1010, 16, 99)] };
        let diff = a.diff(&b);
        assert_eq!(diff, vec![ChangedRegion { start: 0x1010, end: 0x1020 }]);
        assert_eq!(a.changed_byte_count(&b), 16);
    }

    #[test]
    fn test_diff_merges_adjacent_changed_chunks() {
        let a = MemorySnapshot {
            chunks: vec![chunk(0x1000, 16, 1), chunk(0x1010, 16, 2), chunk(0x1020, 16, 3)],
        };
        let b = MemorySnapshot {
            chunks: vec![chunk(0x1000, 16, 1), chunk(0x1010, 16, 20), chunk(0x1020, 16, 30)],
        };
        let diff = a.diff(&b);
        assert_eq!(diff, vec![ChangedRegion { start: 0x1010, end: 0x1030 }]);
        assert_eq!(a.changed_byte_count(&b), 32);
    }

    #[test]
    fn test_diff_detects_removed_chunk() {
        let a = MemorySnapshot { chunks: vec![chunk(0x1000, 16, 1), chunk(0x1010, 16, 2)] };
        let b = MemorySnapshot { chunks: vec![chunk(0x1000, 16, 1)] };
        let diff = a.diff(&b);
        assert_eq!(diff, vec![ChangedRegion { start: 0x1010, end: 0x1020 }]);
    }

    #[test]
    fn test_diff_detects_added_chunk() {
        let a = MemorySnapshot { chunks: vec![chunk(0x1000, 16, 1)] };
        let b = MemorySnapshot { chunks: vec![chunk(0x1000, 16, 1), chunk(0x1010, 16, 2)] };
        let diff = a.diff(&b);
        assert_eq!(diff, vec![ChangedRegion { start: 0x1010, end: 0x1020 }]);
    }
}
