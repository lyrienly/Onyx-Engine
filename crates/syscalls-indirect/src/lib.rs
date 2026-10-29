#![cfg(all(windows, target_arch = "x86_64"))]

use core::ffi::c_void;
use core::mem::size_of;
use core::ptr;
use core::slice;
use std::collections::HashMap;
use std::sync::OnceLock;

use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
};

pub mod stub;

pub type NtStatus = i32;

#[derive(Debug)]
pub struct NtdllInfo {
    pub base: *const u8,
    pub ssn: HashMap<String, u32>,
    pub gadget: *const u8,
}

unsafe impl Send for NtdllInfo {}
unsafe impl Sync for NtdllInfo {}

static NTDLL: OnceLock<NtdllInfo> = OnceLock::new();

pub fn ntdll() -> &'static NtdllInfo {
    NTDLL.get_or_init(|| unsafe { load_ntdll().expect("failed to parse ntdll") })
}

pub fn get_ssn(name: &str) -> Option<u32> {
    ntdll().ssn.get(name).copied()
}

unsafe fn load_ntdll() -> Option<NtdllInfo> {
    let h = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    if h == 0 {
        return None;
    }
    let base = h as *const u8;

    let dos = &*(base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }
    let nt = &*(base.add(dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    if nt.Signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    let exp_dir_rva = nt.OptionalHeader.DataDirectory[0].VirtualAddress;
    let exp_dir_size = nt.OptionalHeader.DataDirectory[0].Size as usize;
    if exp_dir_rva == 0 || exp_dir_size == 0 {
        return None;
    }
    let exp = &*(base.add(exp_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY);

    let names = slice::from_raw_parts(
        base.add(exp.AddressOfNames as usize) as *const u32,
        exp.NumberOfNames as usize,
    );
    let ordinals = slice::from_raw_parts(
        base.add(exp.AddressOfNameOrdinals as usize) as *const u16,
        exp.NumberOfNames as usize,
    );
    let functions = slice::from_raw_parts(
        base.add(exp.AddressOfFunctions as usize) as *const u32,
        exp.NumberOfFunctions as usize,
    );

    let mut map: HashMap<String, u32> = HashMap::new();
    for i in 0..names.len() {
        let name_ptr = base.add(names[i] as usize) as *const u8;
        let name = read_cstr(name_ptr);
        if !(name.starts_with("Nt") || name.starts_with("Zw")) {
            continue;
        }
        let ord = ordinals[i] as usize;
        if ord >= functions.len() {
            continue;
        }
        let stub_rva = functions[ord] as usize;
        if stub_rva == 0 {
            continue;
        }
        let stub = base.add(stub_rva);
        if let Some(ssn) = extract_ssn(stub) {
            map.insert(name, ssn);
        }
    }

    let gadget = find_syscall_gadget(base, nt)?;

    Some(NtdllInfo {
        base,
        ssn: map,
        gadget,
    })
}

unsafe fn read_cstr(mut p: *const u8) -> String {
    let mut out = Vec::new();
    while *p != 0 {
        out.push(*p);
        p = p.add(1);
    }
    String::from_utf8_lossy(&out).into_owned()
}

unsafe fn extract_ssn(stub: *const u8) -> Option<u32> {
    // Canonical Nt stub on x64:
    //   4C 8B D1          mov r10, rcx
    //   B8 ?? ?? ?? ??    mov eax, imm32   <- SSN
    //   ...
    //   0F 05             syscall
    //   C3                ret
    // Scan first 32 bytes for `B8 xx xx xx xx` and ensure a `0F 05` within next 24 bytes.
    let bytes = slice::from_raw_parts(stub, 48);
    for i in 0..24 {
        if bytes[i] == 0xB8 {
            let imm = u32::from_le_bytes([
                bytes[i + 1],
                bytes[i + 2],
                bytes[i + 3],
                bytes[i + 4],
            ]);
            // sanity: SSN typically < 0x1000
            if imm > 0x2000 {
                continue;
            }
            for j in (i + 5)..(bytes.len() - 1) {
                if bytes[j] == 0x0F && bytes[j + 1] == 0x05 {
                    return Some(imm);
                }
            }
        }
    }
    None
}

unsafe fn find_syscall_gadget(
    base: *const u8,
    nt: &IMAGE_NT_HEADERS64,
) -> Option<*const u8> {
    let sections = slice::from_raw_parts(
        (nt as *const IMAGE_NT_HEADERS64 as *const u8)
            .add(size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER,
        nt.FileHeader.NumberOfSections as usize,
    );
    for s in sections {
        let name = &s.Name;
        if &name[..5] == b".text" {
            let va = base.add(s.VirtualAddress as usize);
            let size = s.Misc.VirtualSize as usize;
            let bytes = slice::from_raw_parts(va, size);
            for i in 0..bytes.len().saturating_sub(3) {
                if bytes[i] == 0x0F && bytes[i + 1] == 0x05 && bytes[i + 2] == 0xC3 {
                    return Some(va.add(i));
                }
            }
        }
    }
    None
}

/// Executes an indirect syscall. `args` must contain the exact number of
/// arguments the target Nt routine expects (max 11 supported).
pub unsafe fn do_syscall(ssn: u32, args: &[usize]) -> NtStatus {
    assert!(args.len() <= 11, "do_syscall supports up to 11 args");
    let gadget = ntdll().gadget;
    let mut a = [0usize; 11];
    for (i, v) in args.iter().enumerate() {
        a[i] = *v;
    }
    stub::onyx_syscall_gate(
        ssn, gadget, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10],
    )
}

// --------------------------- High level wrappers ---------------------------

pub unsafe fn nt_query_system_information(
    class: u32,
    buffer: *mut c_void,
    length: u32,
    return_length: *mut u32,
) -> NtStatus {
    let ssn = get_ssn("NtQuerySystemInformation").expect("NtQuerySystemInformation SSN");
    do_syscall(
        ssn,
        &[
            class as usize,
            buffer as usize,
            length as usize,
            return_length as usize,
        ],
    )
}

#[repr(C)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: *mut c_void,
    pub object_name: *mut c_void,
    pub attributes: u32,
    pub security_descriptor: *mut c_void,
    pub security_quality_of_service: *mut c_void,
}

#[repr(C)]
pub struct ClientId {
    pub unique_process: usize,
    pub unique_thread: usize,
}

pub unsafe fn nt_open_process(
    process_handle: *mut isize,
    desired_access: u32,
    object_attributes: *mut ObjectAttributes,
    client_id: *mut ClientId,
) -> NtStatus {
    let ssn = get_ssn("NtOpenProcess").expect("NtOpenProcess SSN");
    do_syscall(
        ssn,
        &[
            process_handle as usize,
            desired_access as usize,
            object_attributes as usize,
            client_id as usize,
        ],
    )
}

pub unsafe fn nt_read_virtual_memory(
    process_handle: isize,
    base_address: *const c_void,
    buffer: *mut c_void,
    size: usize,
    bytes_read: *mut usize,
) -> NtStatus {
    let ssn = get_ssn("NtReadVirtualMemory").expect("NtReadVirtualMemory SSN");
    do_syscall(
        ssn,
        &[
            process_handle as usize,
            base_address as usize,
            buffer as usize,
            size,
            bytes_read as usize,
        ],
    )
}

// --------------------------- NT structs for queries ---------------------------

pub const SYSTEM_BASIC_INFORMATION: u32 = 0;
pub const SYSTEM_PROCESS_INFORMATION: u32 = 5;

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct SystemBasicInformation {
    pub reserved: u32,
    pub timer_resolution: u32,
    pub page_size: u32,
    pub number_of_physical_pages: u32,
    pub lowest_physical_page_number: u32,
    pub highest_physical_page_number: u32,
    pub allocation_granularity: u32,
    pub minimum_user_mode_address: usize,
    pub maximum_user_mode_address: usize,
    pub active_processors_affinity_mask: usize,
    pub number_of_processors: i8,
    pub _pad: [u8; 7],
}

#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

#[repr(C)]
pub struct SystemProcessInformation {
    pub next_entry_offset: u32,
    pub number_of_threads: u32,
    pub _reserved1: [u8; 48],
    pub image_name: UnicodeString,
    pub base_priority: i32,
    pub unique_process_id: usize,
    pub inherited_from_unique_process_id: usize,
    // ... (truncated — enough to walk the list and print PID + name)
}

/// Iterates process-information buffer previously filled via
/// `nt_query_system_information(SYSTEM_PROCESS_INFORMATION, ...)`.
pub struct ProcessIter {
    cur: *const u8,
}

impl ProcessIter {
    pub unsafe fn new(buf: *const u8) -> Self {
        Self { cur: buf }
    }
}

impl Iterator for ProcessIter {
    type Item = (usize, String);

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            if self.cur.is_null() {
                return None;
            }
            let info = &*(self.cur as *const SystemProcessInformation);
            let name = if info.image_name.length > 0 && !info.image_name.buffer.is_null() {
                let s = slice::from_raw_parts(
                    info.image_name.buffer,
                    (info.image_name.length / 2) as usize,
                );
                String::from_utf16_lossy(s)
            } else {
                String::from("<System>")
            };
            let pid = info.unique_process_id;
            if info.next_entry_offset == 0 {
                self.cur = ptr::null();
            } else {
                self.cur = self.cur.add(info.next_entry_offset as usize);
            }
            Some((pid, name))
        }
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssn_resolves_core_nts() {
        for name in ["NtQuerySystemInformation", "NtOpenProcess", "NtReadVirtualMemory"] {
            let v = get_ssn(name);
            assert!(v.is_some(), "SSN not found for {name}");
            let ssn = v.unwrap();
            assert!(ssn > 0 && ssn < 0x1000, "implausible SSN {ssn} for {name}");
        }
    }

    #[test]
    fn gadget_discovered() {
        let g = ntdll().gadget;
        assert!(!g.is_null());
        unsafe {
            let b = slice::from_raw_parts(g, 3);
            assert_eq!(b, &[0x0F, 0x05, 0xC3]);
        }
    }

    #[test]
    fn indirect_query_system_basic_info() {
        let mut info = SystemBasicInformation::default();
        let mut ret = 0u32;
        let status = unsafe {
            nt_query_system_information(
                SYSTEM_BASIC_INFORMATION,
                &mut info as *mut _ as *mut c_void,
                size_of::<SystemBasicInformation>() as u32,
                &mut ret,
            )
        };
        assert_eq!(status, 0, "NTSTATUS = 0x{:X}", status);
        assert!(info.number_of_processors > 0);
        assert_eq!(info.page_size, 4096);
    }
}
