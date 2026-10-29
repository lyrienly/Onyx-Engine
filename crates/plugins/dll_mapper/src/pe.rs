use std::fs;

pub const IMAGE_FILE_DLL: u16 = 0x2000;

#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

impl SectionHeader {
    pub fn name_string(&self) -> String {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..end]).to_string()
    }
}

#[derive(Debug, Clone)]
pub struct PeImage {
    pub data: Vec<u8>,
    pub is_pe32_plus: bool,
    pub characteristics: u16,
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub reloc_rva: u32,
    pub reloc_size: u32,
    pub import_rva: u32,
    pub import_size: u32,
    pub tls_rva: u32,
    pub tls_size: u32,
    pub sections: Vec<SectionHeader>,
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16, String> {
    data.get(offset..offset + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| format!("truncated read of u16 at 0x{:X}", offset))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32, String> {
    data.get(offset..offset + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| format!("truncated read of u32 at 0x{:X}", offset))
}

fn u64_at(data: &[u8], offset: usize) -> Result<u64, String> {
    data.get(offset..offset + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        .ok_or_else(|| format!("truncated read of u64 at 0x{:X}", offset))
}

impl PeImage {
    pub fn parse_file(path: &str) -> Result<Self, String> {
        let data = fs::read(path).map_err(|e| format!("failed to read {}: {}", path, e))?;
        Self::parse(&data)
    }

    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 0x40 {
            return Err("file is too small to be a PE".to_string());
        }
        if u16_at(data, 0)? != 0x5A4D {
            return Err("invalid MZ signature".to_string());
        }

        let pe_offset = u32_at(data, 0x3C)? as usize;
        if data.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0".as_slice()) {
            return Err("invalid PE signature".to_string());
        }

        let coff = pe_offset + 4;
        let num_sections = u16_at(data, coff + 2)? as usize;
        let characteristics = u16_at(data, coff + 18)?;
        let size_of_optional = u16_at(data, coff + 16)? as usize;

        if num_sections == 0 || num_sections > 96 {
            return Err(format!("invalid section count: {}", num_sections));
        }

        let opt = coff + 20;
        if data.len() < opt + size_of_optional {
            return Err("truncated optional header".to_string());
        }

        let magic = u16_at(data, opt)?;
        let is_pe32_plus = match magic {
            0x20B => true,
            0x10B => false,
            other => return Err(format!("unsupported optional header magic 0x{:X}", other)),
        };

        let entry_point_rva = u32_at(data, opt + 16)?;
        let (image_base, data_dir_offset, num_dirs_offset) = if is_pe32_plus {
            (u64_at(data, opt + 24)?, opt + 112, opt + 108)
        } else {
            (u32_at(data, opt + 28)? as u64, opt + 96, opt + 92)
        };

        let section_alignment = u32_at(data, opt + 32)?;
        let file_alignment = u32_at(data, opt + 36)?;
        let size_of_image = u32_at(data, opt + 56)?;
        let size_of_headers = u32_at(data, opt + 60)?;
        let num_dirs = u32_at(data, num_dirs_offset)? as usize;

        let dir = |index: usize| -> (u32, u32) {
            if index < num_dirs {
                let off = data_dir_offset + index * 8;
                match (u32_at(data, off), u32_at(data, off + 4)) {
                    (Ok(rva), Ok(size)) => (rva, size),
                    _ => (0, 0),
                }
            } else {
                (0, 0)
            }
        };

        let (import_rva, import_size) = dir(1);
        let (reloc_rva, reloc_size) = dir(5);
        let (tls_rva, tls_size) = dir(9);

        let sections_offset = opt + size_of_optional;
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let off = sections_offset + i * 40;
            if data.len() < off + 40 {
                return Err("truncated section table".to_string());
            }
            let mut name = [0u8; 8];
            name.copy_from_slice(&data[off..off + 8]);
            sections.push(SectionHeader {
                name,
                virtual_size: u32_at(data, off + 8)?,
                virtual_address: u32_at(data, off + 12)?,
                size_of_raw_data: u32_at(data, off + 16)?,
                pointer_to_raw_data: u32_at(data, off + 20)?,
                characteristics: u32_at(data, off + 36)?,
            });
        }

        if size_of_image == 0 {
            return Err("SizeOfImage is zero".to_string());
        }
        if section_alignment == 0 || file_alignment == 0 {
            return Err("invalid section/file alignment".to_string());
        }
        if size_of_headers as usize > data.len() {
            return Err("SizeOfHeaders exceeds file size".to_string());
        }

        Ok(Self {
            data: data.to_vec(),
            is_pe32_plus,
            characteristics,
            image_base,
            entry_point_rva,
            size_of_image,
            size_of_headers,
            section_alignment,
            file_alignment,
            reloc_rva,
            reloc_size,
            import_rva,
            import_size,
            tls_rva,
            tls_size,
            sections,
        })
    }

    pub fn is_dll(&self) -> bool {
        self.characteristics & IMAGE_FILE_DLL != 0
    }

    #[allow(dead_code)]
    pub fn section_for_rva(&self, rva: u32) -> Option<&SectionHeader> {
        self.sections.iter().find(|s| {
            let start = s.virtual_address;
            let size = s.virtual_size.max(s.size_of_raw_data);
            rva >= start && rva < start.saturating_add(size)
        })
    }

    pub fn build_image(&self) -> Result<Vec<u8>, String> {
        let image_size = self.size_of_image as usize;
        if image_size == 0 {
            return Err("cannot build an empty image".to_string());
        }

        let mut image = vec![0u8; image_size];
        let header_len = (self.size_of_headers as usize).min(self.data.len());
        image[..header_len].copy_from_slice(&self.data[..header_len]);

        for section in &self.sections {
            let dst = section.virtual_address as usize;
            let src = section.pointer_to_raw_data as usize;
            let raw_size = section.size_of_raw_data as usize;
            if raw_size == 0 || dst >= image.len() {
                continue;
            }
            let available_src = self.data.len().saturating_sub(src);
            let available_dst = image.len().saturating_sub(dst);
            let copy_len = raw_size.min(available_src).min(available_dst);
            if copy_len > 0 {
                image[dst..dst + copy_len].copy_from_slice(&self.data[src..src + copy_len]);
            }
        }

        Ok(image)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn minimal_pe32_plus() -> Vec<u8> {
        let mut data = vec![0u8; 0x600];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        data[0x40..0x44].copy_from_slice(b"PE\0\0");

        let coff = 0x44;
        data[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        data[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        data[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes());
        data[coff + 18..coff + 20].copy_from_slice(&0x2022u16.to_le_bytes());

        let opt = coff + 20;
        data[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        data[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        data[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        data[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        data[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        data[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        data[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
        data[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

        data[opt + 112 + 8..opt + 112 + 12].copy_from_slice(&0x1900u32.to_le_bytes());
        data[opt + 112 + 12..opt + 112 + 16].copy_from_slice(&20u32.to_le_bytes());

        data[opt + 112 + 40..opt + 112 + 44].copy_from_slice(&0x1800u32.to_le_bytes());
        data[opt + 112 + 44..opt + 112 + 48].copy_from_slice(&28u32.to_le_bytes());

        let sec = opt + 0xF0;
        data[sec..sec + 8].copy_from_slice(b".text\0\0\0");
        data[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes());
        data[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        data[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes());
        data[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes());
        data[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

        data[0x400..0x404].copy_from_slice(&[0x48, 0x31, 0xC0, 0xC3]);
        data
    }

    #[test]
    fn test_parse_minimal_pe() {
        let pe = PeImage::parse(&minimal_pe32_plus()).expect("parse");
        assert!(pe.is_pe32_plus);
        assert!(pe.is_dll());
        assert_eq!(pe.image_base, 0x1_4000_0000);
        assert_eq!(pe.entry_point_rva, 0x1000);
        assert_eq!(pe.size_of_image, 0x2000);
        assert_eq!(pe.reloc_rva, 0x1800);
        assert_eq!(pe.reloc_size, 28);
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.sections[0].name_string(), ".text");
    }

    #[test]
    fn test_build_image_copies_headers_and_section() {
        let pe = PeImage::parse(&minimal_pe32_plus()).expect("parse");
        let image = pe.build_image().expect("image");
        assert_eq!(image.len(), 0x2000);
        assert_eq!(&image[0..2], b"MZ");
        assert_eq!(&image[0x1000..0x1004], &[0x48, 0x31, 0xC0, 0xC3]);
    }

    #[test]
    fn test_section_for_rva() {
        let pe = PeImage::parse(&minimal_pe32_plus()).expect("parse");
        assert_eq!(pe.section_for_rva(0x1000).map(|s| s.name_string()), Some(".text".to_string()));
        assert!(pe.section_for_rva(0x9000).is_none());
    }

    #[test]
    fn test_rejects_bad_input() {
        assert!(PeImage::parse(&[]).is_err());
        assert!(PeImage::parse(&[0u8; 0x40]).is_err());
        let mut bad = minimal_pe32_plus();
        bad[0x40] = b'X';
        assert!(PeImage::parse(&bad).is_err());
    }
}
