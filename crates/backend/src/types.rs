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

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OnyxVehHit {
    pub instruction_address: usize,
    pub count: usize,
    pub last_rax: u64,
    pub last_rbx: u64,
    pub last_rcx: u64,
    pub last_rdx: u64,
    pub last_rsi: u64,
    pub last_rdi: u64,
    pub last_rsp: u64,
    pub last_rbp: u64,
    pub instruction_text: [u8; 64],
}

impl OnyxVehHit {
    pub fn empty() -> Self {
        Self {
            instruction_address: 0,
            count: 0,
            last_rax: 0,
            last_rbx: 0,
            last_rcx: 0,
            last_rdx: 0,
            last_rsi: 0,
            last_rdi: 0,
            last_rsp: 0,
            last_rbp: 0,
            instruction_text: [0u8; 64],
        }
    }
}
