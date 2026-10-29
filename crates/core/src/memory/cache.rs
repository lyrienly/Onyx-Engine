use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crossbeam_queue::ArrayQueue;
use dashmap::DashMap;

use crate::process::Process;

pub const DEFAULT_CACHE_CHUNK_SIZE: usize = 512 * 1024;
pub const DEFAULT_CHUNK_SIZE: usize = DEFAULT_CACHE_CHUNK_SIZE;
pub const MIN_CHUNK_SIZE: usize = 4 * 1024;
pub const MAX_CHUNK_SIZE: usize = 2 * 1024 * 1024;

#[derive(Debug)]
pub struct CachedChunk {
    pub address: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub inserts: u64,
}

pub struct MemoryCache {
    chunks: DashMap<u64, Arc<CachedChunk>>,
    ring: ArrayQueue<u64>,
    chunk_size: usize,
    capacity: usize,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    inserts: AtomicU64,
}

impl MemoryCache {
    pub fn new(capacity: usize, chunk_size: usize) -> Self {
        let cap = capacity.max(1);
        let size = chunk_size.clamp(MIN_CHUNK_SIZE, MAX_CHUNK_SIZE);
        Self {
            chunks: DashMap::with_capacity(cap),
            ring: ArrayQueue::new(cap),
            chunk_size: size,
            capacity: cap,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            inserts: AtomicU64::new(0),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(256, DEFAULT_CHUNK_SIZE)
    }

    #[inline]
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    #[inline]
    fn align_down(&self, addr: u64) -> u64 {
        addr - (addr % self.chunk_size as u64)
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            inserts: self.inserts.load(Ordering::Relaxed),
        }
    }

    pub fn reset_stats(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.evictions.store(0, Ordering::Relaxed);
        self.inserts.store(0, Ordering::Relaxed);
    }

    pub fn clear(&self) {
        self.chunks.clear();
        while self.ring.pop().is_some() {}
    }

    pub fn get_chunk(&self, aligned_addr: u64) -> Option<Arc<CachedChunk>> {
        if let Some(entry) = self.chunks.get(&aligned_addr) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.clone())
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    fn insert_chunk(&self, aligned_addr: u64, data: Vec<u8>) -> Arc<CachedChunk> {
        let chunk = Arc::new(CachedChunk {
            address: aligned_addr,
            data,
        });
        self.chunks.insert(aligned_addr, chunk.clone());
        self.inserts.fetch_add(1, Ordering::Relaxed);

        while self.ring.push(aligned_addr).is_err() {
            if let Some(victim) = self.ring.pop() {
                if victim != aligned_addr {
                    self.chunks.remove(&victim);
                    self.evictions.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                break;
            }
        }
        chunk
    }

    pub fn get_or_load<F, E>(&self, addr: u64, size: usize, loader: F) -> Result<Vec<u8>, E>
    where
        F: Fn(u64, usize) -> Result<Vec<u8>, E>,
    {
        if size == 0 {
            return Ok(Vec::new());
        }

        let cs = self.chunk_size as u64;
        let end = addr.saturating_add(size as u64);
        let first = self.align_down(addr);
        let last = self.align_down(end.saturating_sub(1));
        let n_chunks = ((last - first) / cs + 1) as usize;

        let mut out: Vec<u8> = Vec::with_capacity(size);

        for i in 0..n_chunks {
            let aligned = first + (i as u64) * cs;
            let chunk = match self.get_chunk(aligned) {
                Some(c) => c,
                None => {
                    let data = loader(aligned, self.chunk_size)?;
                    self.insert_chunk(aligned, data)
                }
            };

            let chunk_start = aligned;
            let chunk_end = aligned + chunk.data.len() as u64;

            let want_start = addr.max(chunk_start);
            let want_end = end.min(chunk_end);
            if want_end <= want_start {
                continue;
            }
            let off = (want_start - chunk_start) as usize;
            let len = (want_end - want_start) as usize;
            out.extend_from_slice(&chunk.data[off..off + len]);
        }

        Ok(out)
    }

    pub fn read_process(&self, proc: &Process, addr: u64, size: usize) -> Result<Vec<u8>, String> {
        self.get_or_load(addr, size, |a, n| proc.read_bytes(a as usize, n))
    }

    pub fn invalidate(&self, start: u64, end: u64) {
        if end <= start {
            return;
        }
        let cs = self.chunk_size as u64;
        let first = self.align_down(start);
        let last = self.align_down(end - 1);
        let mut a = first;
        while a <= last {
            if self.chunks.remove(&a).is_some() {
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
            a += cs;
        }
    }

    pub fn invalidate_all(&self) {
        let n = self.chunks.len() as u64;
        self.clear();
        self.evictions.fetch_add(n, Ordering::Relaxed);
    }
}

impl std::fmt::Debug for MemoryCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.stats();
        f.debug_struct("MemoryCache")
            .field("chunk_size", &self.chunk_size)
            .field("capacity", &self.capacity)
            .field("len", &self.len())
            .field("stats", &s)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_backing(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i & 0xff) as u8).collect()
    }

    #[test]
    fn basic_hit_miss() {
        let cache = MemoryCache::new(8, MIN_CHUNK_SIZE);
        let backing = fake_backing(64 * 1024);
        let loader = |a: u64, n: usize| -> Result<Vec<u8>, String> {
            let s = a as usize;
            Ok(backing[s..s + n].to_vec())
        };
        let a = cache.get_or_load(0, 32, loader).unwrap();
        let b = cache.get_or_load(0, 32, loader).unwrap();
        assert_eq!(a, b);
        let s = cache.stats();
        assert_eq!(s.misses, 1);
        assert_eq!(s.hits, 1);
    }

    #[test]
    fn spanning_two_chunks() {
        let cache = MemoryCache::new(8, MIN_CHUNK_SIZE);
        let backing = fake_backing(64 * 1024);
        let loader = |a: u64, n: usize| -> Result<Vec<u8>, String> {
            Ok(backing[a as usize..a as usize + n].to_vec())
        };
        let cs = MIN_CHUNK_SIZE as u64;
        let out = cache.get_or_load(cs - 16, 64, loader).unwrap();
        assert_eq!(out.len(), 64);
        assert_eq!(&out[..], &backing[cs as usize - 16..cs as usize - 16 + 64]);
        let s = cache.stats();
        assert_eq!(s.misses, 2);
    }

    #[test]
    fn eviction_when_full() {
        let cache = MemoryCache::new(2, MIN_CHUNK_SIZE);
        let backing = fake_backing(1024 * 1024);
        let loader = |a: u64, n: usize| -> Result<Vec<u8>, String> {
            Ok(backing[a as usize..a as usize + n].to_vec())
        };
        let cs = MIN_CHUNK_SIZE as u64;
        cache.get_or_load(0, 16, loader).unwrap();
        cache.get_or_load(cs, 16, loader).unwrap();
        cache.get_or_load(cs * 2, 16, loader).unwrap();
        assert!(cache.len() <= 2);
        let s = cache.stats();
        assert!(s.evictions >= 1, "stats={:?}", s);
    }

    #[test]
    fn invalidate_range() {
        let cache = MemoryCache::new(8, MIN_CHUNK_SIZE);
        let backing = fake_backing(64 * 1024);
        let loader = |a: u64, n: usize| -> Result<Vec<u8>, String> {
            Ok(backing[a as usize..a as usize + n].to_vec())
        };
        let cs = MIN_CHUNK_SIZE as u64;
        cache.get_or_load(0, 16, loader).unwrap();
        cache.get_or_load(cs, 16, loader).unwrap();
        cache.invalidate(0, cs + 1);
        let _ = cache.get_or_load(0, 16, loader).unwrap();
        let s = cache.stats();
        assert!(s.misses >= 3);
    }
}
