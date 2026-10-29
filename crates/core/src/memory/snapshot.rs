use crate::process::Process;
use xxhash_rust::xxh3::xxh3_64;

pub const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
pub const FNV_PRIME: u64 = 0x100000001b3;

pub const DEFAULT_CHUNK_SIZE: usize = 4096;

pub fn fnv1a64(buf: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for &b in buf {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

pub fn xxh3(buf: &[u8]) -> u64 {
    xxh3_64(buf)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    Fnv1a64,
    Xxh3,
}

impl HashAlgo {
    pub fn hash(self, buf: &[u8]) -> u64 {
        match self {
            HashAlgo::Fnv1a64 => fnv1a64(buf),
            HashAlgo::Xxh3 => xxh3(buf),
        }
    }
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
    pub algo: HashAlgo,
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

    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

#[derive(Debug, Clone)]
pub struct ChangedChunkDiff {
    pub address: usize,
    pub old_hash: u64,
    pub new_hash: u64,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct ChangedBytes {
    pub address: usize,
    pub old_hash: u64,
    pub new_hash: u64,
    pub bytes: Vec<u8>,
}

impl MemorySnapshot {
    pub fn capture(
        proc: &Process,
        start: usize,
        stop: usize,
        chunk_size: usize,
    ) -> Result<Self, String> {
        Self::capture_with(proc, start, stop, chunk_size, HashAlgo::Xxh3)
    }

    pub fn capture_with(
        proc: &Process,
        start: usize,
        stop: usize,
        chunk_size: usize,
        algo: HashAlgo,
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
                let data = match proc.read_bytes(cur, len) {
                    Ok(d) => d,
                    Err(_) => {
                        cur += len;
                        continue;
                    }
                };
                chunks.push(SnapshotChunk {
                    address: cur,
                    size: len,
                    hash: algo.hash(&data),
                });
                cur += len;
            }
        }

        Ok(MemorySnapshot { chunks, algo })
    }

    pub fn capture_range(proc: &Process, base: usize, size: usize) -> Result<Self, String> {
        Self::capture_with(proc, base, base + size, DEFAULT_CHUNK_SIZE, HashAlgo::Xxh3)
    }

    pub fn diff(&self, other: &Self) -> Vec<ChangedRegion> {
        let raw = self.collect_changed_pairs(other);
        let mut flat: Vec<(usize, usize)> = raw
            .iter()
            .map(|c| (c.address, c.address + c.size))
            .collect();
        merge_changed(std::mem::take(&mut flat))
    }

    pub fn diff_detailed(&self, other: &Self) -> Vec<ChangedChunkDiff> {
        self.collect_changed_pairs(other)
    }

    fn collect_changed_pairs(&self, other: &Self) -> Vec<ChangedChunkDiff> {
        let mut out: Vec<ChangedChunkDiff> = Vec::new();
        let mut i = 0;
        let mut j = 0;

        loop {
            let a = self.chunks.get(i);
            let b = other.chunks.get(j);
            match (a, b) {
                (Some(a), Some(b)) => {
                    if a.address == b.address {
                        if a.hash != b.hash {
                            out.push(ChangedChunkDiff {
                                address: a.address,
                                old_hash: a.hash,
                                new_hash: b.hash,
                                size: a.size,
                            });
                        }
                        i += 1;
                        j += 1;
                    } else if a.address < b.address {
                        out.push(ChangedChunkDiff {
                            address: a.address,
                            old_hash: a.hash,
                            new_hash: 0,
                            size: a.size,
                        });
                        i += 1;
                    } else {
                        out.push(ChangedChunkDiff {
                            address: b.address,
                            old_hash: 0,
                            new_hash: b.hash,
                            size: b.size,
                        });
                        j += 1;
                    }
                }
                (Some(a), None) => {
                    out.push(ChangedChunkDiff {
                        address: a.address,
                        old_hash: a.hash,
                        new_hash: 0,
                        size: a.size,
                    });
                    i += 1;
                }
                (None, Some(b)) => {
                    out.push(ChangedChunkDiff {
                        address: b.address,
                        old_hash: 0,
                        new_hash: b.hash,
                        size: b.size,
                    });
                    j += 1;
                }
                (None, None) => break,
            }
        }

        out
    }

    pub fn diff_with_bytes(&self, proc: &Process) -> Result<Vec<ChangedBytes>, String> {
        let mut out = Vec::new();
        for chunk in &self.chunks {
            let data = match proc.read_bytes(chunk.address, chunk.size) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let new_hash = self.algo.hash(&data);
            if new_hash != chunk.hash {
                out.push(ChangedBytes {
                    address: chunk.address,
                    old_hash: chunk.hash,
                    new_hash,
                    bytes: data,
                });
            }
        }
        Ok(out)
    }

    pub fn changed_byte_count(&self, other: &Self) -> usize {
        self.diff(other).iter().map(|r| r.len()).sum()
    }

    pub fn heatmap(&self, other: &Self, bucket_size: usize) -> Vec<(usize, usize)> {
        let bucket = bucket_size.max(1);
        let diffs = self.diff(other);
        let mut buckets: std::collections::BTreeMap<usize, usize> =
            std::collections::BTreeMap::new();
        for r in diffs {
            let key = (r.start / bucket) * bucket;
            *buckets.entry(key).or_insert(0) += r.len();
        }
        buckets.into_iter().collect()
    }
}

fn merge_changed(mut raw: Vec<(usize, usize)>) -> Vec<ChangedRegion> {
    raw.sort_by_key(|&(s, _)| s);
    let mut out: Vec<ChangedRegion> = Vec::new();

    for (s, e) in raw {
        if let Some(last) = out.last_mut()
            && s <= last.end
        {
            if e > last.end {
                last.end = e;
            }
            continue;
        }
        out.push(ChangedRegion { start: s, end: e });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(address: usize, size: usize, hash: u64) -> SnapshotChunk {
        SnapshotChunk {
            address,
            size,
            hash,
        }
    }

    fn snap(chunks: Vec<SnapshotChunk>) -> MemorySnapshot {
        MemorySnapshot {
            chunks,
            algo: HashAlgo::Xxh3,
        }
    }

    #[test]
    fn test_fnv1a64_empty() {
        assert_eq!(fnv1a64(&[]), FNV_OFFSET_BASIS);
    }

    #[test]
    fn test_fnv1a64_deterministic_and_distinct() {
        assert_eq!(fnv1a64(b"hello"), fnv1a64(b"hello"));
        assert_ne!(fnv1a64(b"hello"), fnv1a64(b"world"));
    }

    #[test]
    fn test_xxh3_deterministic_and_distinct() {
        assert_eq!(xxh3(b"hello"), xxh3(b"hello"));
        assert_ne!(xxh3(b"hello"), xxh3(b"world"));
        assert_ne!(xxh3(&[0u8; 4096]), xxh3(&[1u8; 4096]));
    }

    #[test]
    fn test_diff_identical() {
        let a = snap(vec![chunk(0x1000, 16, 1), chunk(0x1010, 16, 2)]);
        let b = snap(vec![chunk(0x1000, 16, 1), chunk(0x1010, 16, 2)]);
        assert!(a.diff(&b).is_empty());
    }

    #[test]
    fn test_diff_single_changed_chunk() {
        let a = snap(vec![chunk(0x1000, 16, 1), chunk(0x1010, 16, 2)]);
        let b = snap(vec![chunk(0x1000, 16, 1), chunk(0x1010, 16, 99)]);
        let diff = a.diff(&b);
        assert_eq!(
            diff,
            vec![ChangedRegion {
                start: 0x1010,
                end: 0x1020
            }]
        );
        assert_eq!(a.changed_byte_count(&b), 16);
    }

    #[test]
    fn test_diff_merges_adjacent() {
        let a = snap(vec![
            chunk(0x1000, 16, 1),
            chunk(0x1010, 16, 2),
            chunk(0x1020, 16, 3),
        ]);
        let b = snap(vec![
            chunk(0x1000, 16, 1),
            chunk(0x1010, 16, 20),
            chunk(0x1020, 16, 30),
        ]);
        assert_eq!(
            a.diff(&b),
            vec![ChangedRegion {
                start: 0x1010,
                end: 0x1030
            }]
        );
    }

    #[test]
    fn test_diff_detailed_reports_hashes() {
        let a = snap(vec![chunk(0x1000, 16, 1), chunk(0x1010, 16, 2)]);
        let b = snap(vec![chunk(0x1000, 16, 1), chunk(0x1010, 16, 99)]);
        let d = a.diff_detailed(&b);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].address, 0x1010);
        assert_eq!(d[0].old_hash, 2);
        assert_eq!(d[0].new_hash, 99);
    }

    #[test]
    fn test_heatmap_groups_by_bucket() {
        let a = snap(vec![chunk(0x1000, 16, 1), chunk(0x1010, 16, 2)]);
        let b = snap(vec![chunk(0x1000, 16, 10), chunk(0x1010, 16, 20)]);
        let hm = a.heatmap(&b, 0x1000);
        assert_eq!(hm, vec![(0x1000, 32)]);
    }
}
