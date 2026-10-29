
use std::collections::{HashMap, HashSet, VecDeque};

use crate::process::Process;

#[derive(Debug, Clone)]
pub struct ReferenceGraph {
    base: usize,
    len: usize,
    pointer_size: usize,
    alignment: usize,
    slots: usize,
    reverse: HashMap<usize, Vec<usize>>,
}

impl ReferenceGraph {
    pub fn build(buffer: &[u8], base: usize, pointer_size: usize, alignment: usize) -> Self {
        let pointer_size = if pointer_size == 4 { 4 } else { 8 };
        let alignment = alignment.max(1);
        let end = base.wrapping_add(buffer.len());

        let mut reverse: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut slots = 0usize;
        let mut offset = 0usize;

        while offset + pointer_size <= buffer.len() {
            let address = base.wrapping_add(offset);
            let value = if pointer_size == 8 {
                let mut raw = [0u8; 8];
                raw.copy_from_slice(&buffer[offset..offset + 8]);
                u64::from_le_bytes(raw) as usize
            } else {
                let mut raw = [0u8; 4];
                raw.copy_from_slice(&buffer[offset..offset + 4]);
                u32::from_le_bytes(raw) as usize
            };

            slots += 1;
            if value >= base && value < end {
                reverse.entry(value).or_default().push(address);
            }

            offset += alignment;
        }

        Self {
            base,
            len: buffer.len(),
            pointer_size,
            alignment,
            slots,
            reverse,
        }
    }

    pub fn build_from_process(
        proc: &Process,
        base: usize,
        size: usize,
        pointer_size: usize,
    ) -> Result<Self, String> {
        let buffer = proc.read_bytes(base, size)?;
        Ok(Self::build(&buffer, base, pointer_size, pointer_size))
    }

    pub fn base(&self) -> usize {
        self.base
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn pointer_size(&self) -> usize {
        self.pointer_size
    }

    pub fn alignment(&self) -> usize {
        self.alignment
    }

    pub fn slot_count(&self) -> usize {
        self.slots
    }

    pub fn referenced_count(&self) -> usize {
        self.reverse.values().map(|v| v.len()).sum()
    }

    pub fn referrers(&self, address: usize) -> &[usize] {
        self.reverse
            .get(&address)
            .map(|values| values.as_slice())
            .unwrap_or(&[])
    }

    pub fn referrer_count(&self, address: usize) -> usize {
        self.reverse.get(&address).map_or(0, |values| values.len())
    }

    pub fn contains(&self, address: usize) -> bool {
        address >= self.base && address < self.base.wrapping_add(self.len)
    }

    pub fn find_path(&self, roots: &[usize], target: usize, max_depth: usize) -> Option<Vec<usize>> {
        if roots.is_empty() || max_depth == 0 || !self.contains(target) {
            return None;
        }

        let root_set: HashSet<usize> = roots.iter().copied().collect();
        if root_set.contains(&target) {
            return Some(vec![target]);
        }

        let mut visited: HashSet<usize> = HashSet::new();
        let mut child: HashMap<usize, usize> = HashMap::new();
        let mut queue: VecDeque<(usize, usize)> = VecDeque::new();

        visited.insert(target);
        queue.push_back((target, 0));

        while let Some((node, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            for &slot in self.referrers(node) {
                if slot == target || visited.contains(&slot) {
                    continue;
                }

                visited.insert(slot);
                child.insert(slot, node);

                if root_set.contains(&slot) {
                    let mut path = vec![slot];
                    let mut current = slot;
                    while let Some(&next) = child.get(&current) {
                        path.push(next);
                        current = next;
                    }
                    return Some(path);
                }

                queue.push_back((slot, depth + 1));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: usize = 0x1000;

    fn write_ptr(buffer: &mut [u8], offset: usize, value: usize) {
        buffer[offset..offset + 8].copy_from_slice(&(value as u64).to_le_bytes());
    }

    fn chain_buffer() -> Vec<u8> {
        let mut buffer = vec![0u8; 0x100];
        write_ptr(&mut buffer, 0x10, BASE + 0x20);
        write_ptr(&mut buffer, 0x20, BASE + 0x40);
        buffer
    }

    #[test]
    fn test_referrers() {
        let graph = ReferenceGraph::build(&chain_buffer(), BASE, 8, 8);
        assert_eq!(graph.referrers(BASE + 0x20), &[BASE + 0x10]);
        assert_eq!(graph.referrers(BASE + 0x40), &[BASE + 0x20]);
        assert!(graph.referrers(BASE + 0x80).is_empty());
        assert_eq!(graph.referrer_count(BASE + 0x40), 1);
        assert_eq!(graph.slot_count(), 0x100 / 8);
    }

    #[test]
    fn test_find_path() {
        let graph = ReferenceGraph::build(&chain_buffer(), BASE, 8, 8);
        let path = graph.find_path(&[BASE + 0x10], BASE + 0x40, 4).expect("path");
        assert_eq!(path, vec![BASE + 0x10, BASE + 0x20, BASE + 0x40]);
    }

    #[test]
    fn test_no_path() {
        let graph = ReferenceGraph::build(&chain_buffer(), BASE, 8, 8);
        assert!(graph.find_path(&[BASE + 0x30], BASE + 0x40, 4).is_none());
        assert!(graph.find_path(&[], BASE + 0x40, 4).is_none());
    }

    #[test]
    fn test_depth_limit() {
        let graph = ReferenceGraph::build(&chain_buffer(), BASE, 8, 8);
        assert!(graph.find_path(&[BASE + 0x10], BASE + 0x40, 1).is_none());
        assert!(graph.find_path(&[BASE + 0x10], BASE + 0x40, 2).is_some());
    }

    #[test]
    fn test_cycle_does_not_hang() {
        let mut buffer = vec![0u8; 0x40];
        write_ptr(&mut buffer, 0x00, BASE + 0x08);
        write_ptr(&mut buffer, 0x08, BASE + 0x00);
        let graph = ReferenceGraph::build(&buffer, BASE, 8, 8);
        assert!(graph.find_path(&[BASE + 0x30], BASE + 0x00, 8).is_none());
        assert_eq!(graph.referrers(BASE), &[BASE + 0x08]);
    }

    #[test]
    fn test_four_byte_pointers() {
        let mut buffer = vec![0u8; 0x40];
        buffer[0x04..0x08].copy_from_slice(&((BASE + 0x10) as u32).to_le_bytes());
        buffer[0x10..0x14].copy_from_slice(&((BASE + 0x20) as u32).to_le_bytes());
        let graph = ReferenceGraph::build(&buffer, BASE, 4, 4);
        assert_eq!(graph.pointer_size(), 4);
        assert_eq!(graph.referrers(BASE + 0x10), &[BASE + 0x04]);
        let path = graph.find_path(&[BASE + 0x04], BASE + 0x20, 4).expect("path");
        assert_eq!(path, vec![BASE + 0x04, BASE + 0x10, BASE + 0x20]);
    }

    #[test]
    fn test_out_of_range_pointers_ignored() {
        let mut buffer = vec![0u8; 0x40];
        write_ptr(&mut buffer, 0x00, 0xDEAD_BEEF);
        write_ptr(&mut buffer, 0x08, BASE - 1);
        let graph = ReferenceGraph::build(&buffer, BASE, 8, 8);
        assert_eq!(graph.referenced_count(), 0);
    }

    #[test]
    fn test_alignment_is_respected() {
        let mut buffer = vec![0u8; 0x40];
        write_ptr(&mut buffer, 0x04, BASE + 0x20);

        let aligned = ReferenceGraph::build(&buffer, BASE, 8, 8);
        assert!(aligned.referrers(BASE + 0x20).is_empty());
        assert_eq!(aligned.slot_count(), 8);

        let unaligned = ReferenceGraph::build(&buffer, BASE, 8, 4);
        assert_eq!(unaligned.referrers(BASE + 0x20), &[BASE + 0x04]);
        assert_eq!(unaligned.slot_count(), 15);
    }

    #[test]
    fn test_root_equals_target() {
        let buffer = vec![0u8; 0x40];
        let graph = ReferenceGraph::build(&buffer, BASE, 8, 8);
        assert_eq!(
            graph.find_path(&[BASE + 0x10], BASE + 0x10, 2),
            Some(vec![BASE + 0x10])
        );
    }
}
