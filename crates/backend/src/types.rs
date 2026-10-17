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

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OnyxCodecaveEntry {
    pub address: usize,
    pub size: usize,
    pub byte_value: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OnyxRipRelativeMatch {
    pub instruction_address: usize,
    pub target_address: usize,
    pub mnemonic: [u8; 32],
    pub operands: [u8; 96],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OnyxRegisterSnapshot {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OnyxRegisterComparison {
    pub reg_name: [u8; 16],
    pub reg_index: u32,
    pub g1_constant: i32,
    pub g1_sample: u64,
    pub g2_constant: i32,
    pub g2_sample: u64,
    pub distinguishes_groups: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OnyxStructureDifference {
    pub offset: usize,
    pub g1_constant: i32,
    pub g1_value: u64,
    pub g2_constant: i32,
    pub g2_value: u64,
    pub differentiates: i32,
    pub value_size: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OnyxDissectBranch {
    pub from_address: usize,
    pub to_address: usize,
    pub kind: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OnyxXRefEntry {
    pub target_address: usize,
    pub caller_address: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OnyxStringReference {
    pub instruction_address: usize,
    pub string_address: usize,
    pub text: [u8; 128],
    pub is_unicode: i32,
    pub mnemonic: [u8; 32],
    pub operands: [u8; 96],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OnyxPeSection {
    pub name: [u8; 16],
    pub virtual_address: usize,
    pub virtual_size: usize,
    pub raw_size: usize,
    pub characteristics: u32,
    pub is_executable: i32,
    pub is_writable: i32,
    pub is_readable: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OnyxPeImport {
    pub module_name: [u8; 128],
    pub function_name: [u8; 128],
    pub ordinal: u16,
    pub iat_address: usize,
    pub resolved_address: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OnyxSignatureResult {
    pub pattern: [u8; 256],
    pub length: usize,
    pub match_count: usize,
    pub is_unique: i32,
}
