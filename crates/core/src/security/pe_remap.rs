use crate::win32::*;
use std::ffi::c_void;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SectionBounds {
    pub name: [u8; 8],
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub characteristics: u32,
}

pub struct PeRemap;

impl PeRemap {
    pub fn is_valid_pe(base_address: usize) -> bool {
        if base_address == 0 {
            return false;
        }

        unsafe {
            let dos_header = base_address as *const u8;
            if *dos_header != b'M' || *dos_header.add(1) != b'Z' {
                return false;
            }

            let e_lfanew = *(dos_header.add(0x3C) as *const i32);
            if e_lfanew <= 0 || e_lfanew > 0x10000000 {
                return false;
            }

            let nt_headers = dos_header.offset(e_lfanew as isize);
            let sig = *(nt_headers as *const u32);
            sig == 0x00004550
        }
    }

    pub fn get_size_of_image(base_address: usize) -> u32 {
        if !Self::is_valid_pe(base_address) {
            return 0;
        }

        unsafe {
            let dos_header = base_address as *const u8;
            let e_lfanew = *(dos_header.add(0x3C) as *const i32);
            let nt_headers = dos_header.offset(e_lfanew as isize);
            *(nt_headers.add(0x18 + 0x38) as *const u32)
        }
    }

    pub fn get_sections(base_address: usize) -> Vec<SectionBounds> {
        let mut sections = Vec::new();
        if !Self::is_valid_pe(base_address) {
            return sections;
        }

        unsafe {
            let dos_header = base_address as *const u8;
            let e_lfanew = *(dos_header.add(0x3C) as *const i32);
            let nt_headers = dos_header.offset(e_lfanew as isize);
            let num_sections = *(nt_headers.add(0x4 + 0x2) as *const u16) as usize;
            let size_of_opt_header = *(nt_headers.add(0x4 + 0x10) as *const u16) as usize;

            let section_header_start = nt_headers.add(0x18 + size_of_opt_header);
            for i in 0..num_sections {
                let sec_ptr = section_header_start.add(i * 40);
                let mut name = [0u8; 8];
                std::ptr::copy_nonoverlapping(sec_ptr, name.as_mut_ptr(), 8);

                let virtual_size = *(sec_ptr.add(8) as *const u32);
                let virtual_address = *(sec_ptr.add(12) as *const u32);
                let characteristics = *(sec_ptr.add(36) as *const u32);

                sections.push(SectionBounds {
                    name,
                    virtual_address,
                    virtual_size,
                    characteristics,
                });
            }
        }

        sections
    }

    pub fn find_section<'a>(
        sections: &'a [SectionBounds],
        name: &[u8],
    ) -> Option<&'a SectionBounds> {
        sections.iter().find(|s| {
            let s_name = s.name.split(|&b| b == 0).next().unwrap_or(&s.name);
            s_name == name
        })
    }

    pub fn apply_strict_section_protections(base_address: usize) -> Result<(), String> {
        if !Self::is_valid_pe(base_address) {
            return Err("Invalid PE base address".to_string());
        }

        let sections = Self::get_sections(base_address);
        for sec in &sections {
            let sec_name = sec.name.split(|&b| b == 0).next().unwrap_or(&sec.name);
            let target_addr = base_address + sec.virtual_address as usize;
            let size = sec.virtual_size as usize;

            if size == 0 {
                continue;
            }

            let new_prot = if sec_name == b".text" {
                PAGE_EXECUTE_READ
            } else if sec_name == b".rdata" {
                PAGE_READONLY
            } else {
                continue;
            };

            let mut old_prot: DWORD = 0;
            unsafe {
                let ok = VirtualProtect(target_addr as *mut c_void, size, new_prot, &mut old_prot);
                if ok != TRUE {
                    return Err(format!(
                        "Failed to protect section {:?}",
                        String::from_utf8_lossy(sec_name)
                    ));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_remap_validity_check() {
        assert!(!PeRemap::is_valid_pe(0));
    }
}
