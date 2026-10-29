#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkData {
    pub address: usize,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TimelineFrame {
    pub timestamp: u64,
    pub changed_chunks: usize,
    pub deltas: Vec<ChunkData>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeEvent {
    pub frame: usize,
    pub timestamp: u64,
    pub old: u8,
    pub new: u8,
}

#[derive(Debug, Clone)]
pub struct MemoryTimeline {
    chunk_size: usize,
    origin: usize,
    span: usize,
    frames: Vec<TimelineFrame>,
    current: Vec<ChunkData>,
}

impl MemoryTimeline {
    pub fn new(chunk_size: usize) -> Self {
        Self {
            chunk_size: chunk_size.max(1),
            origin: 0,
            span: 0,
            frames: Vec::new(),
            current: Vec::new(),
        }
    }

    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    pub fn origin(&self) -> usize {
        self.origin
    }

    pub fn span(&self) -> usize {
        self.span
    }

    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    pub fn timestamps(&self) -> Vec<u64> {
        self.frames.iter().map(|f| f.timestamp).collect()
    }

    pub fn memory_footprint(&self) -> usize {
        self.frames
            .iter()
            .flat_map(|f| f.deltas.iter())
            .map(|c| c.bytes.len())
            .sum()
    }

    fn split_chunks(&self, base: usize, bytes: &[u8]) -> Vec<ChunkData> {
        let mut chunks = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let end = (offset + self.chunk_size).min(bytes.len());
            chunks.push(ChunkData {
                address: base.wrapping_add(offset),
                bytes: bytes[offset..end].to_vec(),
            });
            offset = end;
        }
        chunks
    }

    pub fn record(&mut self, timestamp: u64, base: usize, bytes: &[u8]) -> Result<usize, String> {
        if bytes.is_empty() {
            return Err("cannot record an empty memory block".to_string());
        }

        if self.frames.is_empty() {
            self.origin = base;
            self.span = bytes.len();
            let chunks = self.split_chunks(base, bytes);
            let changed = chunks.len();
            self.current = chunks.clone();
            self.frames.push(TimelineFrame {
                timestamp,
                changed_chunks: changed,
                deltas: chunks,
            });
            return Ok(changed);
        }

        if base != self.origin || bytes.len() != self.span {
            return Err(format!(
                "recorded block must match first frame (base 0x{:X}, span {})",
                self.origin, self.span
            ));
        }

        let chunks = self.split_chunks(base, bytes);
        let mut deltas = Vec::new();

        for (index, chunk) in chunks.into_iter().enumerate() {
            if self.current[index].bytes != chunk.bytes {
                self.current[index] = chunk.clone();
                deltas.push(chunk);
            }
        }

        let changed = deltas.len();
        self.frames.push(TimelineFrame {
            timestamp,
            changed_chunks: changed,
            deltas,
        });
        Ok(changed)
    }

    fn chunk_address(&self, address: usize) -> Option<usize> {
        if address < self.origin || address >= self.origin.wrapping_add(self.span) {
            return None;
        }
        let index = (address - self.origin) / self.chunk_size;
        Some(self.origin.wrapping_add(index * self.chunk_size))
    }

    fn chunk_bytes(&self, chunk_address: usize, frame: usize) -> Option<&[u8]> {
        if frame >= self.frames.len() {
            return None;
        }
        for f in (0..=frame).rev() {
            if let Some(chunk) = self.frames[f]
                .deltas
                .iter()
                .find(|c| c.address == chunk_address)
            {
                return Some(&chunk.bytes);
            }
        }
        None
    }

    pub fn read_byte(&self, address: usize, frame: usize) -> Option<u8> {
        let chunk_address = self.chunk_address(address)?;
        let bytes = self.chunk_bytes(chunk_address, frame)?;
        let offset = address - chunk_address;
        bytes.get(offset).copied()
    }

    pub fn read_bytes(&self, address: usize, len: usize, frame: usize) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            out.push(self.read_byte(address.wrapping_add(i), frame)?);
        }
        Some(out)
    }

    pub fn changes_for_byte(&self, address: usize) -> Vec<ChangeEvent> {
        if self.frames.is_empty() {
            return Vec::new();
        }
        let mut events = Vec::new();
        let mut previous = match self.read_byte(address, 0) {
            Some(value) => value,
            None => return events,
        };

        for frame in 1..self.frames.len() {
            if let Some(current) = self.read_byte(address, frame) {
                if current != previous {
                    events.push(ChangeEvent {
                        frame,
                        timestamp: self.frames[frame].timestamp,
                        old: previous,
                        new: current,
                    });
                    previous = current;
                }
            }
        }

        events
    }

    pub fn changed_ranges(&self, from_frame: usize, to_frame: usize) -> Vec<(usize, usize)> {
        if from_frame >= self.frames.len() || to_frame >= self.frames.len() {
            return Vec::new();
        }

        let mut ranges: Vec<(usize, usize)> = Vec::new();
        for chunk in &self.current {
            let start = chunk.address;
            let end = chunk.address + chunk.bytes.len();
            let a = self.chunk_bytes(start, from_frame);
            let b = self.chunk_bytes(start, to_frame);
            if a != b {
                ranges.push((start, end));
            }
        }

        ranges.sort_by_key(|&(start, _)| start);
        let mut merged: Vec<(usize, usize)> = Vec::new();
        for (start, end) in ranges {
            if let Some(last) = merged.last_mut() {
                if start <= last.1 {
                    if end > last.1 {
                        last.1 = end;
                    }
                    continue;
                }
            }
            merged.push((start, end));
        }
        merged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timeline() -> MemoryTimeline {
        MemoryTimeline::new(8)
    }

    #[test]
    fn test_baseline_reads() {
        let mut tl = timeline();
        tl.record(100, 0x1000, &[0x11; 16]).unwrap();

        assert_eq!(tl.frame_count(), 1);
        assert_eq!(tl.origin(), 0x1000);
        assert_eq!(tl.span(), 16);
        assert_eq!(tl.read_byte(0x1000, 0), Some(0x11));
        assert_eq!(tl.read_byte(0x100F, 0), Some(0x11));
        assert_eq!(tl.read_byte(0x1010, 0), None);
        assert_eq!(tl.read_byte(0x0FFF, 0), None);
    }

    #[test]
    fn test_changed_chunk_is_stored_as_delta() {
        let mut tl = timeline();
        let mut base = [0u8; 32];
        tl.record(100, 0x2000, &base).unwrap();
        assert_eq!(tl.frames[0].changed_chunks, 4);

        base[10] = 0xAB;
        let changed = tl.record(200, 0x2000, &base).unwrap();
        assert_eq!(changed, 1);
        assert_eq!(tl.frames[1].deltas.len(), 1);
        assert_eq!(tl.frames[1].deltas[0].address, 0x2008);
        assert!(tl.memory_footprint() < 32 * 2);
    }

    #[test]
    fn test_read_historical_values() {
        let mut tl = timeline();
        let mut buf = [0u8; 16];
        tl.record(100, 0x3000, &buf).unwrap();

        buf[3] = 0x10;
        tl.record(200, 0x3000, &buf).unwrap();

        buf[3] = 0x20;
        tl.record(300, 0x3000, &buf).unwrap();

        assert_eq!(tl.read_byte(0x3003, 0), Some(0x00));
        assert_eq!(tl.read_byte(0x3003, 1), Some(0x10));
        assert_eq!(tl.read_byte(0x3003, 2), Some(0x20));
        assert_eq!(tl.read_bytes(0x3002, 2, 2), Some(vec![0x00, 0x20]));
    }

    #[test]
    fn test_changes_for_byte() {
        let mut tl = timeline();
        let mut buf = [0u8; 16];
        tl.record(100, 0x4000, &buf).unwrap();

        buf[1] = 0xAA;
        tl.record(200, 0x4000, &buf).unwrap();
        tl.record(250, 0x4000, &buf).unwrap();

        buf[1] = 0xBB;
        tl.record(300, 0x4000, &buf).unwrap();

        let events = tl.changes_for_byte(0x4001);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], ChangeEvent { frame: 1, timestamp: 200, old: 0x00, new: 0xAA });
        assert_eq!(events[1], ChangeEvent { frame: 3, timestamp: 300, old: 0xAA, new: 0xBB });
        assert!(tl.changes_for_byte(0x4002).is_empty());
    }

    #[test]
    fn test_changed_ranges_merges_adjacent_chunks() {
        let mut tl = timeline();
        let mut buf = [0u8; 32];
        tl.record(100, 0x5000, &buf).unwrap();

        buf[0] = 1;
        buf[8] = 2;
        tl.record(200, 0x5000, &buf).unwrap();

        assert_eq!(tl.changed_ranges(0, 1), vec![(0x5000, 0x5010)]);

        buf[16] = 3;
        tl.record(300, 0x5000, &buf).unwrap();

        assert_eq!(tl.changed_ranges(1, 2), vec![(0x5010, 0x5018)]);
        assert_eq!(tl.changed_ranges(0, 2), vec![(0x5000, 0x5018)]);
    }

    #[test]
    fn test_record_rejects_block_mismatch() {
        let mut tl = timeline();
        tl.record(100, 0x6000, &[0u8; 16]).unwrap();
        assert!(tl.record(200, 0x6000, &[0u8; 8]).is_err());
        assert!(tl.record(200, 0x7000, &[0u8; 16]).is_err());
        assert!(tl.record(200, 0x6000, &[]).is_err());
    }

    #[test]
    fn test_chunk_size_is_clamped() {
        let tl = MemoryTimeline::new(0);
        assert_eq!(tl.chunk_size(), 1);
    }

    #[test]
    fn test_timestamps_and_frame_count() {
        let mut tl = timeline();
        tl.record(10, 0x8000, &[0u8; 8]).unwrap();
        tl.record(20, 0x8000, &[1u8; 8]).unwrap();
        assert_eq!(tl.timestamps(), vec![10, 20]);
        assert_eq!(tl.frame_count(), 2);
        assert!(!tl.is_empty());
    }
}
