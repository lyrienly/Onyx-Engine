use crate::win32::*;

pub const IOCTL_CE_READMEMORY: DWORD = 0x22E000;
pub const IOCTL_CE_WRITEMEMORY: DWORD = 0x22E004;
pub const IOCTL_CE_OPENPROCESS: DWORD = 0x22E008;
pub const IOCTL_CE_QUERY_VIRTUAL_MEMORY: DWORD = 0x22E00C;
pub const IOCTL_CE_TEST: DWORD = 0x22E010;
pub const IOCTL_CE_GETPEPROCESS: DWORD = 0x22E014;
pub const IOCTL_CE_READPHYSICALMEMORY: DWORD = 0x22E018;
pub const IOCTL_CE_WRITEPHYSICALMEMORY: DWORD = 0x22E01C;
pub const IOCTL_CE_GETPHYSICALADDRESS: DWORD = 0x22E020;
pub const IOCTL_CE_GETCR3: DWORD = 0x22E028;
pub const IOCTL_CE_SETCR3: DWORD = 0x22E02C;
pub const IOCTL_CE_GETVERSION: DWORD = 0x22E058;

pub const IOCTL_CE_GET_BASE: DWORD = 0x22E18C;
pub const IOCTL_CE_HIDEDRIVER: DWORD = 0x22E190;
pub const IOCTL_CE_ENUM_VAD_MODULES: DWORD = 0x22E194;
pub const IOCTL_CE_TRANSLATE_CR3: DWORD = 0x22E198;
pub const IOCTL_CE_CLOAK_PAGE: DWORD = 0x22E19C;
pub const IOCTL_CE_UNCLOAK_PAGE: DWORD = 0x22E1A0;
pub const IOCTL_CE_WRITE_CLOAKED: DWORD = 0x22E1A4;
pub const IOCTL_CE_BULK_DUMP_CR3: DWORD = 0x22E1A8;
pub const IOCTL_CE_STEALTH_READ_PTE: DWORD = 0x22E1AC;
pub const IOCTL_CE_STRIP_CALLBACKS: DWORD = 0x22E1B4;
pub const IOCTL_CE_PATTERN_SCAN: DWORD = 0x22E1B8;
pub const IOCTL_CE_FREEZE_PROCESS: DWORD = 0x22E1BC;
pub const IOCTL_CE_SET_PROCESS_PROTECTION: DWORD = 0x22E1C0;
pub const IOCTL_CE_CLEAN_KERNEL_TRACES: DWORD = 0x22E1C4;
pub const IOCTL_CE_CLOAK_DEVICE_SYMLINK: DWORD = 0x22E1C8;
pub const IOCTL_CE_GET_DBVM_STATUS: DWORD = 0x22E1D0;
pub const IOCTL_CE_CLOAK_REGION: DWORD = 0x22E1D4;
pub const IOCTL_CE_START_DBVM_WATCH: DWORD = 0x22E1D8;
pub const IOCTL_CE_STOP_DBVM_WATCH: DWORD = 0x22E1DC;
pub const IOCTL_CE_POLL_DBVM_WATCH: DWORD = 0x22E1E0;
pub const IOCTL_CE_PHYSICAL_RAM_SCAVENGE: DWORD = 0x22E1CC;
pub const IOCTL_CE_HIDE_PROCESS: DWORD = 0x22E1EC;
pub const IOCTL_CE_ALLOCATE_PROCESS_MEMORY: DWORD = 0x22E1F0;
pub const IOCTL_CE_FREE_PROCESS_MEMORY: DWORD = 0x22E1F4;
pub const IOCTL_CE_PROTECT_PROCESS_MEMORY: DWORD = 0x22E1F8;
pub const IOCTL_CE_HIDE_THREAD: DWORD = 0x22E1FC;
pub const IOCTL_CE_SETUP_SHARED_RING: DWORD = 0x22E200;
pub const IOCTL_CE_PROCESS_SHARED_RING: DWORD = 0x22E204;
pub const IOCTL_CE_RESTORE_PROCESS: DWORD = 0x22E208;
pub const IOCTL_CE_INSPECT_PROCESS: DWORD = 0x22E20C;
pub const IOCTL_CE_INSPECT_DRIVER: DWORD = 0x22E210;
pub const IOCTL_CE_ENUM_CALLBACKS: DWORD = 0x22E214;
pub const IOCTL_CE_GET_HVCI_STATUS: DWORD = 0x22E218;

pub const IOCTL_CE_ULTIMAP2: DWORD = 0x22E13C;
pub const IOCTL_CE_DISABLEULTIMAP2: DWORD = 0x22E140;
pub const IOCTL_CE_ULTIMAP2_WAITFORDATA: DWORD = 0x22E144;
pub const IOCTL_CE_ULTIMAP2_CONTINUE: DWORD = 0x22E148;
pub const IOCTL_CE_ULTIMAP2_FLUSH: DWORD = 0x22E14C;
pub const IOCTL_CE_ULTIMAP2_PAUSE: DWORD = 0x22E150;
pub const IOCTL_CE_ULTIMAP2_RESUME: DWORD = 0x22E154;
pub const IOCTL_CE_ULTIMAP2_LOCKFILE: DWORD = 0x22E158;
pub const IOCTL_CE_ULTIMAP2_RELEASEFILE: DWORD = 0x22E15C;
pub const IOCTL_CE_ULTIMAP2_GETTRACESIZE: DWORD = 0x22E168;
pub const IOCTL_CE_ULTIMAP2_RESETTRACESIZE: DWORD = 0x22E16C;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CeUltimapRange {
    pub start_address: u64,
    pub end_address: u64,
    pub is_stop_address: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct CeUltimap2Config {
    pub pid: u32,
    pub buffer_size: u32,
    pub range_count: u32,
    pub no_pmi: u32,
    pub user_mode: u32,
    pub kernel_mode: u32,
    pub ranges: [CeUltimapRange; 8],
    pub file_name: [u16; 200],
}

impl Default for CeUltimap2Config {
    fn default() -> Self {
        Self {
            pid: 0,
            buffer_size: 4096 * 1024,
            range_count: 0,
            no_pmi: 0,
            user_mode: 1,
            kernel_mode: 0,
            ranges: [CeUltimapRange::default(); 8],
            file_name: [0u16; 200],
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CeUltimap2DataEvent {
    pub address: u64,
    pub size: u64,
    pub cpu_id: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CeHvciStatusOutput {
    pub vbs_enabled: u32,
    pub hvci_enabled: u32,
    pub strict_mode: u32,
    pub code_integrity_opts: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KernelObCallbackInfo {
    pub entry_address: u64,
    pub object_type: u64, // 1 = Process, 2 = Thread
    pub pre_operation: u64,
    pub post_operation: u64,
    pub operations: u32,
    pub enabled: u32,
    pub owner_module: [u8; 64],
}

impl Default for KernelObCallbackInfo {
    fn default() -> Self {
        Self {
            entry_address: 0,
            object_type: 0,
            pre_operation: 0,
            post_operation: 0,
            operations: 0,
            enabled: 0,
            owner_module: [0u8; 64],
        }
    }
}

impl KernelObCallbackInfo {
    pub fn owner_name(&self) -> String {
        let len = self
            .owner_module
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.owner_module.len());
        String::from_utf8_lossy(&self.owner_module[..len]).to_string()
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EnumCallbacksOutput {
    pub count: u32,
    pub _pad: u32,
    pub callbacks: [KernelObCallbackInfo; 32],
}

impl Default for EnumCallbacksOutput {
    fn default() -> Self {
        Self {
            count: 0,
            _pad: 0,
            callbacks: [KernelObCallbackInfo {
                entry_address: 0,
                object_type: 0,
                pre_operation: 0,
                post_operation: 0,
                operations: 0,
                enabled: 0,
                owner_module: [0u8; 64],
            }; 32],
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessMemoryProof {
    pub process_id: u32,
    pub _pad: u32,
    pub eprocess_address: u64,
    pub active_process_links_address: u64,
    pub flink: u64,
    pub blink: u64,
    pub flink_blink: u64,
    pub is_self_linked: u8,
    pub circular_integrity: u8,
    pub _reserved: [u8; 6],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct DriverMemoryProof {
    pub driver_object_address: u64,
    pub driver_section_address: u64,
    pub in_load_order_flink: u64,
    pub in_load_order_blink: u64,
    pub is_driver_module_unlinked: u8,
    pub _pad: [u8; 3],
    pub unloaded_drivers_estimated_count: u32,
}

pub const ONYX_RING_MAGIC: u32 = 0x58594E4F; // 'ONYX'
pub const ONYX_CMD_READ: u32 = 1;
pub const ONYX_CMD_WRITE: u32 = 2;
pub const ONYX_CMD_CR3_READ: u32 = 3;

pub const ONYX_STATUS_IDLE: u32 = 0;
pub const ONYX_STATUS_PENDING: u32 = 1;
pub const ONYX_STATUS_COMPLETED: u32 = 2;
pub const ONYX_STATUS_ERROR: u32 = 3;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct OnyxRingSlot {
    pub command: u32,
    pub status: u32,
    pub process_id: u64,
    pub address: u64,
    pub size: u32,
    pub transferred: u32,
    pub data: [u8; 4096],
}

#[repr(C, packed)]
pub struct OnyxSharedRing {
    pub magic: u32,
    pub head: u32,
    pub tail: u32,
    pub slot_count: u32,
    pub slots: [OnyxRingSlot; 8],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct SetupSharedRingOutput {
    pub user_address: u64,
    pub size: u32,
    pub status: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CeCloakInput {
    pub process_id: u32,
    pub virtual_address: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CeWriteCloakedHeader {
    pub process_id: u32,
    pub virtual_address: u64,
    pub size: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CeDbvmStatusOutput {
    pub is_active: u32,
    pub version: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CeCloakRegionHeader {
    pub process_id: u64,
    pub virtual_address: u64,
    pub size: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CeStealthReadInput {
    pub process_id: u64,
    pub virtual_address: u64,
    pub size: u32,
}

#[repr(C, packed)]
pub struct CeAllocMemoryInput {
    pub process_id: u64,
    pub base_address: u64,
    pub size: u64,
    pub allocation_type: u32,
    pub protect: u32,
}

#[repr(C, packed)]
pub struct CeAllocMemoryOutput {
    pub base_address: u64,
    pub status: u32,
}

#[repr(C, packed)]
pub struct CeFreeMemoryInput {
    pub process_id: u64,
    pub base_address: u64,
    pub size: u64,
    pub free_type: u32,
}

#[repr(C, packed)]
pub struct CeProtectMemoryInput {
    pub process_id: u64,
    pub base_address: u64,
    pub size: u64,
    pub new_protect: u32,
}

#[repr(C, packed)]
pub struct CeProtectMemoryOutput {
    pub base_address: u64,
    pub size: u64,
    pub old_protect: u32,
    pub status: u32,
}

#[repr(C, packed)]
pub struct CeReadMemoryInput {
    pub process_id: u64,
    pub start_address: u64,
    pub bytes_to_read: u16,
}

#[repr(C, packed)]
pub struct CeWriteMemoryHeader {
    pub process_id: u64,
    pub start_address: u64,
    pub bytes_to_write: u16,
}

#[repr(C)]
#[allow(dead_code)]
pub struct CeOpenProcessOutput {
    pub handle: u64,
    pub special: u8,
}

#[repr(C, packed)]
pub struct CeTranslateCr3Input {
    pub process_id: u32,
    pub virtual_address: u64,
}

#[repr(C, packed)]
pub struct CeBulkDumpInput {
    pub process_id: u64,
    pub base_address: u64,
    pub size: u32,
}

#[repr(C, packed)]
pub struct CeStripCallbacksInput {
    pub restore: u32,
}

#[repr(C, packed)]
pub struct CeFreezeProcessInput {
    pub process_id: u64,
    pub freeze: u32,
}

#[repr(C, packed)]
pub struct CeSetProtectionInput {
    pub process_id: u64,
    pub enable: u32,
}

#[repr(C, packed)]
pub struct CePatternScanInput {
    pub process_id: u64,
    pub start_address: u64,
    pub scan_size: u64,
    pub pattern_length: u32,
    pub pattern: [u8; 64],
    pub mask: [u8; 64],
}

#[repr(C)]
pub struct CePatternScanOutput {
    pub match_count: u32,
    pub matches: [u64; 32],
}

#[repr(C)]
pub struct VadModuleEntryRaw {
    pub base_address: u64,
    pub module_size: u64,
    pub module_name: [u16; 64],
    pub full_path: [u16; 260],
}

#[repr(C)]
pub struct VadEnumOutputHeader {
    pub count: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KernelSecurityProfile {
    pub secure_boot_active: bool,
    pub test_signing_active: bool,
    pub vbs_active: bool,
    pub hvci_active: bool,
    pub cr3_interception_risk: bool,
}
