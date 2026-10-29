#[derive(Debug, Clone, Copy)]
pub struct SectionMeta {
    pub header_offset: usize,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone)]
pub struct PeHeaders {
    pub e_lfanew: usize,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub file_alignment: u32,
    pub section_alignment: u32,
    pub size_of_headers_field: usize,
    pub section_table_end: usize,
    pub sections: Vec<SectionMeta>,
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16, String> {
    data.get(offset..offset + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| format!("truncated u16 at 0x{:X}", offset))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32, String> {
    data.get(offset..offset + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| format!("truncated u32 at 0x{:X}", offset))
}

fn align_up(value: usize, alignment: usize) -> usize {
    if alignment == 0 {
        return value;
    }
    value.div_ceil(alignment) * alignment
}

pub fn parse_headers(data: &[u8]) -> Result<PeHeaders, String> {
    if data.len() < 0x40 {
        return Err("buffer too small for DOS header".to_string());
    }
    if u16_at(data, 0)? != 0x5A4D {
        return Err("invalid MZ signature".to_string());
    }

    let e_lfanew = u32_at(data, 0x3C)? as usize;
    if data.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0".as_slice()) {
        return Err("invalid PE signature".to_string());
    }

    let coff = e_lfanew + 4;
    let num_sections = u16_at(data, coff + 2)? as usize;
    let size_of_optional = u16_at(data, coff + 16)? as usize;
    if num_sections == 0 || num_sections > 96 {
        return Err(format!("invalid section count: {}", num_sections));
    }

    let opt = coff + 20;
    let magic = u16_at(data, opt)?;
    if magic != 0x20B && magic != 0x10B {
        return Err(format!("unsupported optional header magic 0x{:X}", magic));
    }

    let section_alignment = u32_at(data, opt + 32)?;
    let file_alignment = u32_at(data, opt + 36)?;
    let size_of_image = u32_at(data, opt + 56)?;
    let size_of_headers = u32_at(data, opt + 60)?;

    let sections_offset = opt + size_of_optional;
    let section_table_end = sections_offset + num_sections * 40;
    if data.len() < section_table_end {
        return Err("truncated section table".to_string());
    }

    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let off = sections_offset + i * 40;
        sections.push(SectionMeta {
            header_offset: off,
            virtual_address: u32_at(data, off + 12)?,
            virtual_size: u32_at(data, off + 8)?,
            raw_size: u32_at(data, off + 16)?,
            characteristics: u32_at(data, off + 36)?,
        });
    }

    Ok(PeHeaders {
        e_lfanew,
        size_of_image,
        size_of_headers,
        file_alignment,
        section_alignment,
        size_of_headers_field: opt + 60,
        section_table_end,
        sections,
    })
}

pub fn rebuild(image: &[u8]) -> Result<Vec<u8>, String> {
    let headers = parse_headers(image)?;
    if headers.size_of_image == 0 {
        return Err("SizeOfImage is zero".to_string());
    }
    if headers.file_alignment == 0 || headers.section_alignment == 0 {
        return Err("invalid alignment in headers".to_string());
    }

    let header_len = align_up(
        (headers.size_of_headers as usize).max(headers.section_table_end),
        headers.file_alignment as usize,
    );
    if header_len == 0 || header_len > 0x10_0000 {
        return Err(format!("invalid header size: {}", header_len));
    }

    let mut out = vec![0u8; header_len];
    let copy_len = header_len.min(image.len());
    out[..copy_len].copy_from_slice(&image[..copy_len]);

    let mut cursor = header_len;
    for section in &headers.sections {
        let virtual_size = section.virtual_size.max(section.raw_size) as usize;
        if virtual_size == 0 || section.virtual_address == 0 {
            let off = section.header_offset;
            out[off + 16..off + 20].copy_from_slice(&0u32.to_le_bytes());
            out[off + 20..off + 24].copy_from_slice(&0u32.to_le_bytes());
            continue;
        }
        if virtual_size > 64 * 1024 * 1024 {
            return Err(format!("section too large: {} bytes", virtual_size));
        }

        let raw_len = align_up(virtual_size, headers.file_alignment as usize);
        if cursor + raw_len > u32::MAX as usize {
            return Err("output too large".to_string());
        }
        out.resize(cursor + raw_len, 0);

        let src = section.virtual_address as usize;
        let available = image.len().saturating_sub(src).min(virtual_size);
        if available > 0 {
            out[cursor..cursor + available].copy_from_slice(&image[src..src + available]);
        }

        let off = section.header_offset;
        out[off + 16..off + 20].copy_from_slice(&(raw_len as u32).to_le_bytes());
        out[off + 20..off + 24].copy_from_slice(&(cursor as u32).to_le_bytes());

        cursor += raw_len;
    }

    let field = headers.size_of_headers_field;
    out[field..field + 4].copy_from_slice(&(header_len as u32).to_le_bytes());

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE_ALIGN: u32 = 0x200;
    const SECTION_ALIGN: u32 = 0x1000;
    const IMAGE_SIZE: u32 = 0x3000;
    const HEADERS_SIZE: u32 = 0x400;

    fn build_memory_image() -> Vec<u8> {
        let mut image = vec![0u8; IMAGE_SIZE as usize];

        image[0] = b'M';
        image[1] = b'Z';
        image[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        image[0x40..0x44].copy_from_slice(b"PE\0\0");

        let coff = 0x44;
        image[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        image[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
        image[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes());

        let opt = coff + 20;
        image[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        image[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        image[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        image[opt + 32..opt + 36].copy_from_slice(&SECTION_ALIGN.to_le_bytes());
        image[opt + 36..opt + 40].copy_from_slice(&FILE_ALIGN.to_le_bytes());
        image[opt + 56..opt + 60].copy_from_slice(&IMAGE_SIZE.to_le_bytes());
        image[opt + 60..opt + 64].copy_from_slice(&HEADERS_SIZE.to_le_bytes());
        image[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

        let sec = opt + 0xF0;
        image[sec..sec + 8].copy_from_slice(b".text\0\0\0");
        image[sec + 8..sec + 12].copy_from_slice(&0x300u32.to_le_bytes());
        image[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        image[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

        let sec2 = sec + 40;
        image[sec2..sec2 + 8].copy_from_slice(b".data\0\0\0");
        image[sec2 + 8..sec2 + 12].copy_from_slice(&0x500u32.to_le_bytes());
        image[sec2 + 12..sec2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        image[sec2 + 36..sec2 + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes());

        image[0x1000..0x1300].fill(0x90);
        image[0x2000..0x2500].fill(0xAB);

        image
    }

    #[test]
    fn test_parse_headers() {
        let image = build_memory_image();
        let headers = parse_headers(&image).expect("headers");
        assert_eq!(headers.size_of_image, IMAGE_SIZE);
        assert_eq!(headers.size_of_headers, HEADERS_SIZE);
        assert_eq!(headers.file_alignment, FILE_ALIGN);
        assert_eq!(headers.sections.len(), 2);
        assert_eq!(headers.sections[0].virtual_address, 0x1000);
        assert_eq!(headers.sections[1].virtual_size, 0x500);
    }

    #[test]
    fn test_rebuild_lays_out_sections() {
        let image = build_memory_image();
        let file = rebuild(&image).expect("rebuild");

        assert_eq!(file.len(), HEADERS_SIZE as usize + 0x400 + 0x600);
        assert_eq!(&file[0..2], b"MZ");

        let parsed = parse_headers(&file).expect("parse rebuilt");
        assert_eq!(parsed.size_of_headers, HEADERS_SIZE);
        assert_eq!(parsed.sections[0].raw_size, 0x400);
        assert_eq!(parsed.sections[0].virtual_address, 0x1000);
        assert_eq!(parsed.sections[1].raw_size, 0x600);

        let text_ptr = parsed.sections[0].header_offset;
        let text_off = u32_at(&file, text_ptr + 20).unwrap() as usize;
        let data_off = u32_at(&file, parsed.sections[1].header_offset + 20).unwrap() as usize;

        assert_eq!(&file[text_off..text_off + 0x300], &vec![0x90u8; 0x300][..]);
        assert_eq!(&file[data_off..data_off + 0x500], &vec![0xABu8; 0x500][..]);
    }

    #[test]
    fn test_rebuild_roundtrip_is_stable() {
        let image = build_memory_image();
        let first = rebuild(&image).expect("first");
        let second = rebuild(&first).expect("second");
        assert_eq!(first.len(), second.len());
    }

    #[test]
    fn test_rejects_bad_headers() {
        assert!(parse_headers(&[]).is_err());
        assert!(parse_headers(&[0u8; 0x400]).is_err());
    }
}
