// OnyxEngine Backend C-ABI Types
// Data structures designed for zero-copy FFI interaction with Pascal / Lazarus frontend

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OnyxProcessEntry {
    pub pid: u32,
    pub name: [u8; 260],
}

impl OnyxProcessEntry {
    pub fn new(pid: u32, name_str: &str) -> Self {
        let mut entry = Self {
            pid,
            name: [0u8; 260],
        };
        let bytes = name_str.as_bytes();
        let len = bytes.len().min(259);
        entry.name[..len].copy_from_slice(&bytes[..len]);
        entry.name[len] = 0;
        entry
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OnyxModuleEntry {
    pub base: usize,
    pub size: usize,
    pub name: [u8; 260],
}

impl OnyxModuleEntry {
    pub fn new(base: usize, size: usize, name_str: &str) -> Self {
        let mut entry = Self {
            base,
            size,
            name: [0u8; 260],
        };
        let bytes = name_str.as_bytes();
        let len = bytes.len().min(259);
        entry.name[..len].copy_from_slice(&bytes[..len]);
        entry.name[len] = 0;
        entry
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OnyxMemoryRegion {
    pub base: usize,
    pub size: usize,
    pub state: u32,
    pub protect: u32,
    pub region_type: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OnyxScanCandidate {
    pub address: usize,
    pub current_val: [u8; 64],
    pub previous_val: [u8; 64],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OnyxDisasmInsn {
    pub address: usize,
    pub length: u32,
    pub bytes: [u8; 16],
    pub mnemonic: [u8; 32],
    pub operands: [u8; 96],
}
