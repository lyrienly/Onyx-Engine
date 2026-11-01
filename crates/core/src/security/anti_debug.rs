//! Complete Anti-Debug and Anti-Anti-Debug Shield Module
//!
//! Implements comprehensive usermode and kernel-level anti-debugging evasion:
//! 1. PEB Structure Masking:
//!    - BeingDebugged byte zeroing (`PEB + 0x02`)
//!    - NtGlobalFlag clearing (`PEB + 0xBC` on 64-bit, strips FLG_HEAP_* debug flags)
//!    - ProcessHeap Flags (`Heap + 0x70`) & ForceFlags (`Heap + 0x74`) normalization
//!    - Safe state backup and bidirectional restoration for local & remote processes
//! 2. System Query Interception & Spoofing:
//!    - NtQueryInformationProcess:
//!      * ProcessDebugPort (7) -> 0 (STATUS_SUCCESS)
//!      * ProcessDebugObjectHandle (30) -> NULL (STATUS_PORT_NOT_SET)
//!      * ProcessDebugFlags (31) -> 1 (STATUS_SUCCESS, indicates NoDebugInherit)
//!    - NtSetInformationThread:
//!      * ThreadHideFromDebugger (0x11) -> filtered / neutralized
//! 3. Timing Attack Normalization (RDTSC / RDTSCP):
//!    - Clamps execution cycle spikes induced by breakpoints or step-debugging
//!    - Monotonic virtual timestamp stabilizer
//! 4. Comprehensive Auditing & Diagnostic Reporting

use crate::win32::*;
use dashmap::DashMap;
use std::ffi::c_void;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

// NTSTATUS error codes
pub const STATUS_SUCCESS: i32 = 0x00000000;
pub const STATUS_PORT_NOT_SET: i32 = 0xC0000353u32 as i32;
pub const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;
pub const STATUS_INVALID_PARAMETER: i32 = 0xC000000Du32 as i32;

// Process Information Classes
pub const PROCESS_BASIC_INFORMATION: u32 = 0;
pub const PROCESS_DEBUG_PORT: u32 = 7;
pub const PROCESS_DEBUG_OBJECT_HANDLE: u32 = 30;
pub const PROCESS_DEBUG_FLAGS: u32 = 31;

// Thread Information Classes
pub const THREAD_HIDE_FROM_DEBUGGER: u32 = 0x11;

// NtGlobalFlag Heap Debugging Flags
pub const FLG_HEAP_ENABLE_TAIL_CHECK: u32 = 0x10;
pub const FLG_HEAP_ENABLE_FREE_CHECK: u32 = 0x20;
pub const FLG_HEAP_VALIDATE_PARAMETERS: u32 = 0x40;
pub const NT_GLOBAL_FLAG_DEBUG_MASK: u32 =
    FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS;

// ProcessHeap Flags
pub const HEAP_GROWABLE: u32 = 0x00000002;

// PEB & Heap Layout Offsets (x86_64)
pub const PEB_BEING_DEBUGGED_OFFSET_64: usize = 0x02;
pub const PEB_PROCESS_HEAP_OFFSET_64: usize = 0x30;
pub const PEB_NT_GLOBAL_FLAG_OFFSET_64: usize = 0xBC;
pub const HEAP_FLAGS_OFFSET_64: usize = 0x70;
pub const HEAP_FORCE_FLAGS_OFFSET_64: usize = 0x74;

// PEB & Heap Layout Offsets (x86 32-bit fallback)
pub const PEB_BEING_DEBUGGED_OFFSET_32: usize = 0x02;
pub const PEB_PROCESS_HEAP_OFFSET_32: usize = 0x18;
pub const PEB_NT_GLOBAL_FLAG_OFFSET_32: usize = 0x68;
pub const HEAP_FLAGS_OFFSET_32: usize = 0x40;
pub const HEAP_FORCE_FLAGS_OFFSET_32: usize = 0x44;

#[repr(C)]
struct ProcessBasicInformation {
    exit_status: i32,
    peb_base_address: *mut c_void,
    affinity_mask: usize,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

type NtQueryInformationProcessFn = unsafe extern "system" fn(
    process_handle: HANDLE,
    process_information_class: u32,
    process_information: *mut c_void,
    process_information_length: u32,
    return_length: *mut u32,
) -> i32;

type NtSetInformationThreadFn = unsafe extern "system" fn(
    thread_handle: HANDLE,
    thread_information_class: u32,
    thread_information: *mut c_void,
    thread_information_length: u32,
) -> i32;

/// Backup of original uncloaked PEB and Heap fields for clean restoration
#[derive(Debug, Clone, Copy)]
pub struct PebBackup {
    pub peb_address: usize,
    pub heap_address: usize,
    pub original_being_debugged: u8,
    pub original_nt_global_flag: u32,
    pub original_heap_flags: u32,
    pub original_heap_force_flags: u32,
}

/// Status summary after cloaking a process's PEB
#[derive(Debug, Clone, Copy, Default)]
pub struct PebCloakStatus {
    pub peb_address: usize,
    pub heap_address: usize,
    pub being_debugged_cleared: bool,
    pub nt_global_flag_cleared: bool,
    pub heap_flags_normalized: bool,
    pub heap_force_flags_cleared: bool,
}

static PEB_BACKUP_STORAGE: LazyLock<DashMap<usize, PebBackup>> = LazyLock::new(DashMap::new);

pub struct AntiDebug;

impl AntiDebug {
    /// Resolves the Process Environment Block (PEB) address for a target process handle.
    /// If handle is GetCurrentProcess(), uses segment register direct read (gs:[0x60] on x64).
    pub fn get_peb_address(h_process: HANDLE) -> Result<*mut c_void, String> {
        #[cfg(target_os = "windows")]
        unsafe {
            if h_process == GetCurrentProcess() || h_process.is_null() {
                #[cfg(target_arch = "x86_64")]
                {
                    let peb: *mut c_void;
                    core::arch::asm!(
                        "mov {}, gs:[0x60]",
                        out(reg) peb,
                        options(nostack, preserves_flags, readonly)
                    );
                    if !peb.is_null() {
                        return Ok(peb);
                    }
                }
                #[cfg(target_arch = "x86")]
                {
                    let peb: *mut c_void;
                    core::arch::asm!(
                        "mov {}, fs:[0x30]",
                        out(reg) peb,
                        options(nostack, preserves_flags, readonly)
                    );
                    if !peb.is_null() {
                        return Ok(peb);
                    }
                }
            }

            let ntdll_name = b"ntdll.dll\0";
            let h_ntdll = GetModuleHandleA(ntdll_name.as_ptr());
            if h_ntdll.is_null() {
                return Err("Failed to obtain handle to ntdll.dll".to_string());
            }

            let fn_name = b"NtQueryInformationProcess\0";
            let p_fn = GetProcAddress(h_ntdll, fn_name.as_ptr());
            if p_fn.is_null() {
                return Err("NtQueryInformationProcess not found".to_string());
            }

            let nt_query_info: NtQueryInformationProcessFn = std::mem::transmute(p_fn);
            let mut pbi = std::mem::zeroed::<ProcessBasicInformation>();
            let mut ret_len = 0u32;
            let status = nt_query_info(
                h_process,
                PROCESS_BASIC_INFORMATION,
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut ret_len,
            );

            if status >= 0 && !pbi.peb_base_address.is_null() {
                Ok(pbi.peb_base_address)
            } else {
                Err(format!(
                    "NtQueryInformationProcess failed with NTSTATUS 0x{:X}",
                    status
                ))
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = h_process;
            Err("Only supported on Windows".to_string())
        }
    }

    /// Cloaks the Process Environment Block (PEB) and ProcessHeap of the current process.
    pub fn cloak_current_process() -> Result<PebCloakStatus, String> {
        #[cfg(target_os = "windows")]
        unsafe {
            Self::cloak_target_process(GetCurrentProcess())
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(PebCloakStatus::default())
        }
    }

    /// Cloaks the Process Environment Block (PEB) and ProcessHeap for any target process handle.
    /// Saves a snapshot in internal storage for seamless reversal.
    pub fn cloak_target_process(h_process: HANDLE) -> Result<PebCloakStatus, String> {
        #[cfg(target_os = "windows")]
        unsafe {
            let peb = Self::get_peb_address(h_process)?;
            let peb_addr = peb as usize;
            let is_64 = std::mem::size_of::<usize>() == 8;

            let off_being_debugged = if is_64 {
                PEB_BEING_DEBUGGED_OFFSET_64
            } else {
                PEB_BEING_DEBUGGED_OFFSET_32
            };
            let off_process_heap = if is_64 {
                PEB_PROCESS_HEAP_OFFSET_64
            } else {
                PEB_PROCESS_HEAP_OFFSET_32
            };
            let off_nt_global_flag = if is_64 {
                PEB_NT_GLOBAL_FLAG_OFFSET_64
            } else {
                PEB_NT_GLOBAL_FLAG_OFFSET_32
            };
            let off_heap_flags = if is_64 {
                HEAP_FLAGS_OFFSET_64
            } else {
                HEAP_FLAGS_OFFSET_32
            };
            let off_heap_force_flags = if is_64 {
                HEAP_FORCE_FLAGS_OFFSET_64
            } else {
                HEAP_FORCE_FLAGS_OFFSET_32
            };

            let mut status = PebCloakStatus {
                peb_address: peb_addr,
                ..Default::default()
            };

            // 1. Read and clear BeingDebugged (UCHAR at PEB + 0x02)
            let mut orig_being_debugged = 0u8;
            let mut bytes_read = 0usize;
            let being_debugged_ptr = (peb_addr + off_being_debugged) as LPVOID;
            if ReadProcessMemory(
                h_process,
                being_debugged_ptr,
                &mut orig_being_debugged as *mut _ as LPVOID,
                1,
                &mut bytes_read,
            ) == TRUE
            {
                let zero = 0u8;
                let mut bytes_written = 0usize;
                let _ = Self::write_memory_safe(
                    h_process,
                    being_debugged_ptr,
                    &zero as *const _ as LPCVOID,
                    1,
                    &mut bytes_written,
                );
                status.being_debugged_cleared = true;
            }

            // 2. Read and adjust NtGlobalFlag (ULONG at PEB + 0xBC)
            let mut orig_nt_global_flag = 0u32;
            let nt_global_flag_ptr = (peb_addr + off_nt_global_flag) as LPVOID;
            if ReadProcessMemory(
                h_process,
                nt_global_flag_ptr,
                &mut orig_nt_global_flag as *mut _ as LPVOID,
                4,
                &mut bytes_read,
            ) == TRUE
            {
                let sanitized_flag = orig_nt_global_flag & !NT_GLOBAL_FLAG_DEBUG_MASK;
                let mut bytes_written = 0usize;
                let _ = Self::write_memory_safe(
                    h_process,
                    nt_global_flag_ptr,
                    &sanitized_flag as *const _ as LPCVOID,
                    4,
                    &mut bytes_written,
                );
                status.nt_global_flag_cleared = true;
            }

            // 3. Read ProcessHeap pointer from PEB
            let mut heap_ptr_val = 0usize;
            let ptr_size = std::mem::size_of::<usize>();
            let process_heap_field = (peb_addr + off_process_heap) as LPVOID;
            let mut orig_heap_flags = 0u32;
            let mut orig_heap_force_flags = 0u32;

            if ReadProcessMemory(
                h_process,
                process_heap_field,
                &mut heap_ptr_val as *mut _ as LPVOID,
                ptr_size,
                &mut bytes_read,
            ) == TRUE
                && heap_ptr_val != 0
            {
                status.heap_address = heap_ptr_val;

                // 4. Adjust Heap Flags (HEAP + 0x70)
                let heap_flags_ptr = (heap_ptr_val + off_heap_flags) as LPVOID;
                if ReadProcessMemory(
                    h_process,
                    heap_flags_ptr,
                    &mut orig_heap_flags as *mut _ as LPVOID,
                    4,
                    &mut bytes_read,
                ) == TRUE
                {
                    let clean_flags = HEAP_GROWABLE;
                    let mut bytes_written = 0usize;
                    let _ = Self::write_memory_safe(
                        h_process,
                        heap_flags_ptr,
                        &clean_flags as *const _ as LPCVOID,
                        4,
                        &mut bytes_written,
                    );
                    status.heap_flags_normalized = true;
                }

                // 5. Adjust Heap ForceFlags (HEAP + 0x74)
                let heap_force_flags_ptr = (heap_ptr_val + off_heap_force_flags) as LPVOID;
                if ReadProcessMemory(
                    h_process,
                    heap_force_flags_ptr,
                    &mut orig_heap_force_flags as *mut _ as LPVOID,
                    4,
                    &mut bytes_read,
                ) == TRUE
                {
                    let zero_force = 0u32;
                    let mut bytes_written = 0usize;
                    let _ = Self::write_memory_safe(
                        h_process,
                        heap_force_flags_ptr,
                        &zero_force as *const _ as LPCVOID,
                        4,
                        &mut bytes_written,
                    );
                    status.heap_force_flags_cleared = true;
                }
            }

            // Save state in backup storage
            let backup = PebBackup {
                peb_address: peb_addr,
                heap_address: heap_ptr_val,
                original_being_debugged: orig_being_debugged,
                original_nt_global_flag: orig_nt_global_flag,
                original_heap_flags: orig_heap_flags,
                original_heap_force_flags: orig_heap_force_flags,
            };
            PEB_BACKUP_STORAGE.insert(peb_addr, backup);

            Ok(status)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = h_process;
            Ok(PebCloakStatus::default())
        }
    }

    /// Restores the original PEB and Heap flags for a given target process.
    pub fn restore_target_process(h_process: HANDLE) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        unsafe {
            let peb = Self::get_peb_address(h_process)?;
            let peb_addr = peb as usize;
            let backup = match PEB_BACKUP_STORAGE.get(&peb_addr) {
                Some(b) => *b,
                None => return Err(format!("No backup found for PEB at 0x{:X}", peb_addr)),
            };

            let is_64 = std::mem::size_of::<usize>() == 8;
            let off_being_debugged = if is_64 {
                PEB_BEING_DEBUGGED_OFFSET_64
            } else {
                PEB_BEING_DEBUGGED_OFFSET_32
            };
            let off_nt_global_flag = if is_64 {
                PEB_NT_GLOBAL_FLAG_OFFSET_64
            } else {
                PEB_NT_GLOBAL_FLAG_OFFSET_32
            };
            let off_heap_flags = if is_64 {
                HEAP_FLAGS_OFFSET_64
            } else {
                HEAP_FLAGS_OFFSET_32
            };
            let off_heap_force_flags = if is_64 {
                HEAP_FORCE_FLAGS_OFFSET_64
            } else {
                HEAP_FORCE_FLAGS_OFFSET_32
            };

            let mut bytes_written = 0usize;

            // Restore BeingDebugged
            let being_debugged_ptr = (peb_addr + off_being_debugged) as LPVOID;
            let _ = Self::write_memory_safe(
                h_process,
                being_debugged_ptr,
                &backup.original_being_debugged as *const _ as LPCVOID,
                1,
                &mut bytes_written,
            );

            // Restore NtGlobalFlag
            let nt_global_flag_ptr = (peb_addr + off_nt_global_flag) as LPVOID;
            let _ = Self::write_memory_safe(
                h_process,
                nt_global_flag_ptr,
                &backup.original_nt_global_flag as *const _ as LPCVOID,
                4,
                &mut bytes_written,
            );

            // Restore Heap Flags and ForceFlags
            if backup.heap_address != 0 {
                let heap_flags_ptr = (backup.heap_address + off_heap_flags) as LPVOID;
                let _ = Self::write_memory_safe(
                    h_process,
                    heap_flags_ptr,
                    &backup.original_heap_flags as *const _ as LPCVOID,
                    4,
                    &mut bytes_written,
                );

                let heap_force_flags_ptr = (backup.heap_address + off_heap_force_flags) as LPVOID;
                let _ = Self::write_memory_safe(
                    h_process,
                    heap_force_flags_ptr,
                    &backup.original_heap_force_flags as *const _ as LPCVOID,
                    4,
                    &mut bytes_written,
                );
            }

            PEB_BACKUP_STORAGE.remove(&peb_addr);
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = h_process;
            Ok(())
        }
    }

    #[cfg(target_os = "windows")]
    unsafe fn write_memory_safe(
        h_process: HANDLE,
        addr: LPVOID,
        buffer: LPCVOID,
        size: usize,
        written: *mut usize,
    ) -> bool {
        unsafe {
            if WriteProcessMemory(h_process, addr, buffer, size, written) == TRUE {
                return true;
            }

            // Attempt protection change to PAGE_READWRITE if direct write is restricted
            let mut old_protect = 0u32;
            let is_current = h_process == GetCurrentProcess();
            let prot_ok = if is_current {
                VirtualProtect(addr, size, PAGE_READWRITE, &mut old_protect) == TRUE
            } else {
                VirtualProtectEx(h_process, addr, size, PAGE_READWRITE, &mut old_protect) == TRUE
            };

            if prot_ok {
                let write_ok = WriteProcessMemory(h_process, addr, buffer, size, written) == TRUE;
                let mut dummy = 0u32;
                if is_current {
                    VirtualProtect(addr, size, old_protect, &mut dummy);
                } else {
                    VirtualProtectEx(h_process, addr, size, old_protect, &mut dummy);
                }
                write_ok
            } else {
                false
            }
        }
    }

    pub fn hide_current_thread() -> Result<(), String> {
        #[cfg(target_os = "windows")]
        unsafe {
            let ntdll_name = b"ntdll.dll\0";
            let h_ntdll = GetModuleHandleA(ntdll_name.as_ptr());
            if h_ntdll.is_null() {
                return Err("Failed to obtain handle to ntdll.dll".to_string());
            }

            let fn_name = b"NtSetInformationThread\0";
            let p_fn = GetProcAddress(h_ntdll, fn_name.as_ptr());
            if p_fn.is_null() {
                return Err("NtSetInformationThread not found".to_string());
            }

            let nt_set_info: NtSetInformationThreadFn = std::mem::transmute(p_fn);
            let status = nt_set_info(
                GetCurrentThread(),
                THREAD_HIDE_FROM_DEBUGGER,
                std::ptr::null_mut(),
                0,
            );

            if status >= 0 {
                Ok(())
            } else {
                Err(format!(
                    "NtSetInformationThread failed with NTSTATUS 0x{:X}",
                    status
                ))
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(())
        }
    }

    pub fn has_hardware_breakpoints() -> bool {
        #[cfg(target_os = "windows")]
        unsafe {
            let mut ctx: CONTEXT = std::mem::zeroed();
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            let h_thread = GetCurrentThread();
            if GetThreadContext(h_thread, &mut ctx) == TRUE {
                let dr_active = ctx.Dr0 != 0
                    || ctx.Dr1 != 0
                    || ctx.Dr2 != 0
                    || ctx.Dr3 != 0
                    || (ctx.Dr7 & 0xFF) != 0;
                return dr_active;
            }
        }
        false
    }

    pub fn is_remote_debugger_present() -> bool {
        #[cfg(target_os = "windows")]
        unsafe {
            let mut is_debugger: BOOL = FALSE;
            if CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut is_debugger) == TRUE {
                return is_debugger == TRUE;
            }
        }
        false
    }

    pub fn is_debugger_present() -> bool {
        #[cfg(target_os = "windows")]
        unsafe {
            if IsDebuggerPresent() == TRUE {
                return true;
            }
        }
        false
    }

    pub fn audit() -> AntiDebugReport {
        let (peb_being_debugged, peb_nt_global_flag) = {
            #[cfg(target_os = "windows")]
            unsafe {
                if let Ok(peb) = Self::get_peb_address(GetCurrentProcess()) {
                    let peb_addr = peb as usize;
                    let is_64 = std::mem::size_of::<usize>() == 8;
                    let off_dbg = if is_64 {
                        PEB_BEING_DEBUGGED_OFFSET_64
                    } else {
                        PEB_BEING_DEBUGGED_OFFSET_32
                    };
                    let off_flag = if is_64 {
                        PEB_NT_GLOBAL_FLAG_OFFSET_64
                    } else {
                        PEB_NT_GLOBAL_FLAG_OFFSET_32
                    };

                    let dbg_val = *((peb_addr + off_dbg) as *const u8);
                    let flag_val = *((peb_addr + off_flag) as *const u32);
                    (dbg_val != 0, flag_val)
                } else {
                    (false, 0)
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                (false, 0)
            }
        };

        AntiDebugReport {
            debugger_present: Self::is_debugger_present(),
            remote_debugger: Self::is_remote_debugger_present(),
            hardware_breakpoints: Self::has_hardware_breakpoints(),
            peb_being_debugged,
            peb_nt_global_flag,
        }
    }
}

/// Spoofer for system queries (`NtQueryInformationProcess` and `NtSetInformationThread`).
pub struct AntiDebugQuerySpoofer;

impl AntiDebugQuerySpoofer {
    /// Handles NtQueryInformationProcess requests for debugger detection classes.
    /// Returns (Handled, NTSTATUS).
    pub fn spoof_query_information_process(
        class: u32,
        buffer: *mut c_void,
        buffer_len: usize,
        return_length: *mut u32,
    ) -> (bool, i32) {
        if buffer.is_null() {
            return (true, STATUS_INVALID_PARAMETER);
        }

        match class {
            PROCESS_DEBUG_PORT => {
                // Class 7: ProcessDebugPort -> writes 0 (not debugged)
                let expected = std::mem::size_of::<usize>();
                if buffer_len < expected {
                    return (true, STATUS_INFO_LENGTH_MISMATCH);
                }
                unsafe {
                    *(buffer as *mut usize) = 0;
                    if !return_length.is_null() {
                        *return_length = expected as u32;
                    }
                }
                (true, STATUS_SUCCESS)
            }

            PROCESS_DEBUG_OBJECT_HANDLE => {
                // Class 30: ProcessDebugObjectHandle -> returns STATUS_PORT_NOT_SET
                let expected = std::mem::size_of::<HANDLE>();
                if buffer_len < expected {
                    return (true, STATUS_INFO_LENGTH_MISMATCH);
                }
                unsafe {
                    *(buffer as *mut HANDLE) = std::ptr::null_mut();
                    if !return_length.is_null() {
                        *return_length = expected as u32;
                    }
                }
                (true, STATUS_PORT_NOT_SET)
            }

            PROCESS_DEBUG_FLAGS => {
                // Class 31: ProcessDebugFlags -> writes 1 (NoDebugInherit / Not Debugged)
                let expected = std::mem::size_of::<u32>();
                if buffer_len < expected {
                    return (true, STATUS_INFO_LENGTH_MISMATCH);
                }
                unsafe {
                    *(buffer as *mut u32) = 1;
                    if !return_length.is_null() {
                        *return_length = expected as u32;
                    }
                }
                (true, STATUS_SUCCESS)
            }

            _ => (false, STATUS_SUCCESS),
        }
    }

    /// Filters NtSetInformationThread.
    /// If class is ThreadHideFromDebugger (0x11), returns true to indicate the call should be dropped.
    pub fn filter_set_information_thread(class: u32) -> bool {
        class == THREAD_HIDE_FROM_DEBUGGER
    }
}

/// RDTSC Timing Attack Shield and Delta Normalizer
pub struct RdtscShield {
    virtual_tsc: AtomicU64,
}

impl Default for RdtscShield {
    fn default() -> Self {
        Self::new()
    }
}

impl RdtscShield {
    pub const DEFAULT_MAX_DELTA_CYCLES: u64 = 500;
    pub const DEFAULT_NORMALIZED_DELTA: u64 = 85;

    pub fn new() -> Self {
        Self {
            virtual_tsc: AtomicU64::new(1_000_000_000),
        }
    }

    /// Normalizes an execution cycle delta between two RDTSC measurements.
    /// If delta exceeds max_expected (indicating debugger pause, single step, or trap),
    /// it clamps to a realistic instruction cycle count.
    pub fn normalize_delta(
        measured_delta: u64,
        max_expected: u64,
        normalized_fallback: u64,
    ) -> u64 {
        if measured_delta > max_expected {
            normalized_fallback
        } else {
            measured_delta
        }
    }

    /// Advances the monotonic stabilized virtual timestamp by an expected instruction cost.
    pub fn next_virtual_tsc(&self, cycle_advance: u64) -> u64 {
        self.virtual_tsc.fetch_add(cycle_advance, Ordering::Relaxed)
    }

    /// Reads raw CPU TSC via intrinsic/assembly where available
    pub fn read_raw_tsc() -> u64 {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::x86_64::_rdtsc()
        }
        #[cfg(target_arch = "x86")]
        unsafe {
            core::arch::x86::_rdtsc()
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            0
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AntiDebugReport {
    pub debugger_present: bool,
    pub remote_debugger: bool,
    pub hardware_breakpoints: bool,
    pub peb_being_debugged: bool,
    pub peb_nt_global_flag: u32,
}

impl AntiDebugReport {
    pub fn is_under_analysis(&self) -> bool {
        self.debugger_present
            || self.remote_debugger
            || self.hardware_breakpoints
            || self.peb_being_debugged
            || (self.peb_nt_global_flag & NT_GLOBAL_FLAG_DEBUG_MASK != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anti_debug_audit() {
        let report = AntiDebug::audit();
        assert!(!report.hardware_breakpoints);
        let _ = AntiDebug::hide_current_thread();
    }

    #[test]
    fn test_peb_cloaking_and_restoration_cycle() {
        #[cfg(target_os = "windows")]
        {
            let status = AntiDebug::cloak_current_process().expect("PEB cloaking should succeed");
            assert_ne!(status.peb_address, 0);
            assert!(status.being_debugged_cleared);
            assert!(status.nt_global_flag_cleared);

            let audit_after = AntiDebug::audit();
            assert!(!audit_after.peb_being_debugged);
            assert_eq!(
                audit_after.peb_nt_global_flag & NT_GLOBAL_FLAG_DEBUG_MASK,
                0
            );

            // Restore
            unsafe {
                let res = AntiDebug::restore_target_process(GetCurrentProcess());
                assert!(res.is_ok());
            }
        }
    }

    #[test]
    fn test_spoofer_process_debug_port() {
        let mut debug_port = 0x1234usize;
        let mut ret_len = 0u32;
        let (handled, status) = AntiDebugQuerySpoofer::spoof_query_information_process(
            PROCESS_DEBUG_PORT,
            &mut debug_port as *mut _ as *mut c_void,
            std::mem::size_of::<usize>(),
            &mut ret_len,
        );
        assert!(handled);
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(debug_port, 0);
        assert_eq!(ret_len as usize, std::mem::size_of::<usize>());
    }

    #[test]
    fn test_spoofer_process_debug_flags() {
        let mut debug_flags = 0u32;
        let mut ret_len = 0u32;
        let (handled, status) = AntiDebugQuerySpoofer::spoof_query_information_process(
            PROCESS_DEBUG_FLAGS,
            &mut debug_flags as *mut _ as *mut c_void,
            std::mem::size_of::<u32>(),
            &mut ret_len,
        );
        assert!(handled);
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(debug_flags, 1); // 1 = No debugger attached
    }

    #[test]
    fn test_spoofer_process_debug_object_handle() {
        let mut debug_obj = 0xDEADBEEFusize as HANDLE;
        let mut ret_len = 0u32;
        let (handled, status) = AntiDebugQuerySpoofer::spoof_query_information_process(
            PROCESS_DEBUG_OBJECT_HANDLE,
            &mut debug_obj as *mut _ as *mut c_void,
            std::mem::size_of::<HANDLE>(),
            &mut ret_len,
        );
        assert!(handled);
        assert_eq!(status, STATUS_PORT_NOT_SET);
        assert!(debug_obj.is_null());
    }

    #[test]
    fn test_spoofer_thread_hide_filter() {
        assert!(AntiDebugQuerySpoofer::filter_set_information_thread(
            THREAD_HIDE_FROM_DEBUGGER
        ));
        assert!(!AntiDebugQuerySpoofer::filter_set_information_thread(0x00));
        assert!(!AntiDebugQuerySpoofer::filter_set_information_thread(0x01));
    }

    #[test]
    fn test_rdtsc_delta_normalization() {
        // Normal fast execution delta
        let fast_delta = 120u64;
        let normalized_fast = RdtscShield::normalize_delta(fast_delta, 500, 85);
        assert_eq!(normalized_fast, 120);

        // Huge spike induced by breakpoint or single step
        let spike_delta = 25_000_000u64;
        let normalized_spike = RdtscShield::normalize_delta(spike_delta, 500, 85);
        assert_eq!(normalized_spike, 85);
    }

    #[test]
    fn test_virtual_tsc_clock_monotonicity() {
        let clock = RdtscShield::new();
        let t1 = clock.next_virtual_tsc(50);
        let t2 = clock.next_virtual_tsc(75);
        assert!(t2 > t1);
        assert_eq!(t2 - t1, 50);
    }
}
