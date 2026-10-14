// language: Rust, file: allochook.rs, target: Windows 11, MSVC
// Memory allocation tracker and heap monitor (Cheat Engine allochook equivalent)

use crate::process::{MemoryRegion, Process};

#[derive(Debug, Clone)]
pub struct AllocationRecord {
    pub base_address: usize,
    pub size: usize,
    pub allocation_type: u32,
    pub protection: u32,
    pub is_executable: bool,
}

pub struct AllocHookMonitor {
    initial_regions: Vec<MemoryRegion>,
}

impl AllocHookMonitor {
    pub fn new() -> Self {
        AllocHookMonitor {
            initial_regions: Vec::new(),
        }
    }

    /// Snapshots current memory regions to compare against future allocations
    pub fn snapshot(&mut self, proc: &Process) -> Result<usize, String> {
        self.initial_regions = proc.regions(false)?;
        Ok(self.initial_regions.len())
    }

    /// Detects all newly allocated memory regions since the last snapshot
    pub fn detect_new_allocations(&self, proc: &Process) -> Result<Vec<AllocationRecord>, String> {
        let current = proc.regions(false)?;
        let mut new_allocs = Vec::new();

        for cur in &current {
            // Check if this region was absent in initial snapshot
            let was_present = self.initial_regions.iter().any(|r| r.base == cur.base);
            if !was_present && cur.is_committed() {
                new_allocs.push(AllocationRecord {
                    base_address: cur.base,
                    size: cur.size,
                    allocation_type: cur.state,
                    protection: cur.protect,
                    is_executable: cur.is_executable(),
                });
            }
        }

        Ok(new_allocs)
    }
}
