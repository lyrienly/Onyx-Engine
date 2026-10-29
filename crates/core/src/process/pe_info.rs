use crate::process::Process;

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550;

pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeSectionEntry {
    pub name: String,
    pub virtual_address: usize,
    pub virtual_size: usize,
    pub raw_size: usize,
    pub characteristics: u32,
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_readable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeImportFunction {
    pub name: String,
    pub ordinal: u16,
    pub iat_address: usize,
    pub resolved_address: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeImportModule {
    pub module_name: String,
    pub functions: Vec<PeImportFunction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeInfo {
    pub image_base: usize,
    pub entry_point: usize,
    pub size_of_image: usize,
    pub is_64bit: bool,
    pub sections: Vec<PeSectionEntry>,
    pub imports: Vec<PeImportModule>,
}

pub struct PeInfoParser;

impl PeInfoParser {
    pub fn parse_process_module(proc: &Process, module_base: usize) -> Result<PeInfo, String> {

        let dos_magic = proc.read::<u16>(module_base)?;
        if dos_magic != IMAGE_DOS_SIGNATURE {
            return Err("Invalid DOS signature (expected MZ)".to_string());
        }

        let e_lfanew = proc.read::<i32>(module_base + 0x3C)? as usize;
        let nt_headers_addr = module_base + e_lfanew;

        let pe_sig = proc.read::<u32>(nt_headers_addr)?;
        if pe_sig != IMAGE_NT_SIGNATURE {
            return Err("Invalid NT signature (expected PE\\0\\0)".to_string());
        }

        let file_header_addr = nt_headers_addr + 4;
        let machine = proc.read::<u16>(file_header_addr)?;
        let num_sections = proc.read::<u16>(file_header_addr + 2)? as usize;
        let size_of_optional_header = proc.read::<u16>(file_header_addr + 16)? as usize;

        let optional_header_addr = file_header_addr + 20;
        let opt_magic = proc.read::<u16>(optional_header_addr)?;
        let is_64bit = opt_magic == 0x020B || machine == IMAGE_FILE_MACHINE_AMD64;

        let (entry_point_rva, image_base_addr, size_of_image, import_dir_rva) = if is_64bit {
            let ep = proc.read::<u32>(optional_header_addr + 16)? as usize;
            let ib = proc.read::<u64>(optional_header_addr + 24)? as usize;
            let si = proc.read::<u32>(optional_header_addr + 56)? as usize;
            let id_rva = proc.read::<u32>(optional_header_addr + 112 + 8)? as usize;
            (ep, ib, si, id_rva)
        } else {
            let ep = proc.read::<u32>(optional_header_addr + 16)? as usize;
            let ib = proc.read::<u32>(optional_header_addr + 28)? as usize;
            let si = proc.read::<u32>(optional_header_addr + 56)? as usize;
            let id_rva = proc.read::<u32>(optional_header_addr + 96 + 8)? as usize;
            (ep, ib, si, id_rva)
        };

        let section_table_addr = optional_header_addr + size_of_optional_header;
        let mut sections = Vec::with_capacity(num_sections);

        for i in 0..num_sections {
            let sec_addr = section_table_addr + (i * 40);
            let name_bytes = proc.read_bytes(sec_addr, 8)?;
            let null_idx = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_bytes[..null_idx]).to_string();

            let virtual_size = proc.read::<u32>(sec_addr + 8)? as usize;
            let virtual_address = proc.read::<u32>(sec_addr + 12)? as usize;
            let raw_size = proc.read::<u32>(sec_addr + 16)? as usize;
            let characteristics = proc.read::<u32>(sec_addr + 36)?;

            let is_executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            let is_writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            let is_readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;

            sections.push(PeSectionEntry {
                name,
                virtual_address: module_base + virtual_address,
                virtual_size,
                raw_size,
                characteristics,
                is_executable,
                is_writable,
                is_readable,
            });
        }

        let mut imports = Vec::new();
        if import_dir_rva != 0 {
            let mut desc_addr = module_base + import_dir_rva;
            loop {

                let original_first_thunk = proc.read::<u32>(desc_addr)? as usize;
                let name_rva = proc.read::<u32>(desc_addr + 12)? as usize;
                let first_thunk = proc.read::<u32>(desc_addr + 16)? as usize;

                if name_rva == 0 && first_thunk == 0 {
                    break;
                }

                let dll_name = proc.read_string(module_base + name_rva, 256, false)
                    .unwrap_or_else(|_| "Unknown.dll".to_string());

                let thunk_table_rva = if original_first_thunk != 0 {
                    original_first_thunk
                } else {
                    first_thunk
                };

                let mut thunk_ptr = module_base + thunk_table_rva;
                let mut iat_ptr = module_base + first_thunk;
                let mut funcs = Vec::new();

                loop {
                    if is_64bit {
                        let thunk_val = match proc.read::<u64>(thunk_ptr) {
                            Ok(v) => v,
                            Err(_) => break,
                        };
                        if thunk_val == 0 {
                            break;
                        }

                        let resolved_addr = proc.read::<u64>(iat_ptr).unwrap_or(0) as usize;

                        let (fn_name, ord) = if (thunk_val & 0x8000_0000_0000_0000) != 0 {
                            let ordinal = (thunk_val & 0xFFFF) as u16;
                            (format!("Ordinal_{}", ordinal), ordinal)
                        } else {
                            let name_entry_addr = module_base + (thunk_val as usize & 0x7FFF_FFFF);
                            let name = proc.read_string(name_entry_addr + 2, 256, false)
                                .unwrap_or_else(|_| format!("Sub_{:X}", thunk_val));
                            (name, 0)
                        };

                        funcs.push(PeImportFunction {
                            name: fn_name,
                            ordinal: ord,
                            iat_address: iat_ptr,
                            resolved_address: resolved_addr,
                        });

                        thunk_ptr += 8;
                        iat_ptr += 8;
                    } else {
                        let thunk_val = match proc.read::<u32>(thunk_ptr) {
                            Ok(v) => v,
                            Err(_) => break,
                        };
                        if thunk_val == 0 {
                            break;
                        }

                        let resolved_addr = proc.read::<u32>(iat_ptr).unwrap_or(0) as usize;

                        let (fn_name, ord) = if (thunk_val & 0x8000_0000) != 0 {
                            let ordinal = (thunk_val & 0xFFFF) as u16;
                            (format!("Ordinal_{}", ordinal), ordinal)
                        } else {
                            let name_entry_addr = module_base + (thunk_val as usize & 0x7FFF_FFFF);
                            let name = proc.read_string(name_entry_addr + 2, 256, false)
                                .unwrap_or_else(|_| format!("Sub_{:X}", thunk_val));
                            (name, 0)
                        };

                        funcs.push(PeImportFunction {
                            name: fn_name,
                            ordinal: ord,
                            iat_address: iat_ptr,
                            resolved_address: resolved_addr,
                        });

                        thunk_ptr += 4;
                        iat_ptr += 4;
                    }
                }

                imports.push(PeImportModule {
                    module_name: dll_name,
                    functions: funcs,
                });

                desc_addr += 20;
            }
        }

        Ok(PeInfo {
            image_base: if image_base_addr != 0 { image_base_addr } else { module_base },
            entry_point: module_base + entry_point_rva,
            size_of_image,
            is_64bit,
            sections,
            imports,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_constants() {
        assert_eq!(IMAGE_DOS_SIGNATURE, 0x5A4D);
        assert_eq!(IMAGE_NT_SIGNATURE, 0x00004550);
    }
}
