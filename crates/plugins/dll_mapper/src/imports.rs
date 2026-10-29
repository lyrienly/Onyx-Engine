#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportSymbol {
    Name(String),
    Ordinal(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportEntry {
    pub module: String,
    pub iat_rva: u32,
    pub symbol: ImportSymbol,
}

fn read_u32(image: &[u8], offset: usize) -> Result<u32, String> {
    image
        .get(offset..offset + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| format!("truncated u32 at 0x{:X}", offset))
}

fn read_u64(image: &[u8], offset: usize) -> Result<u64, String> {
    image
        .get(offset..offset + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        .ok_or_else(|| format!("truncated u64 at 0x{:X}", offset))
}

fn read_cstr(image: &[u8], offset: usize) -> Result<String, String> {
    let tail = image
        .get(offset..)
        .ok_or_else(|| format!("string offset 0x{:X} out of bounds", offset))?;
    let end = tail
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| format!("unterminated string at 0x{:X}", offset))?;
    Ok(String::from_utf8_lossy(&tail[..end]).to_string())
}

pub fn parse_imports(
    image: &[u8],
    import_rva: u32,
    import_size: u32,
) -> Result<Vec<ImportEntry>, String> {
    if import_rva == 0 {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    let mut descriptor = import_rva as usize;
    let limit = if import_size == 0 {
        image.len()
    } else {
        (import_rva as usize).saturating_add(import_size as usize)
    };

    loop {
        if descriptor + 20 > image.len() || descriptor + 20 > limit {
            break;
        }

        let original_first_thunk = read_u32(image, descriptor)?;
        let name_rva = read_u32(image, descriptor + 12)?;
        let first_thunk = read_u32(image, descriptor + 16)?;

        if name_rva == 0 && first_thunk == 0 {
            break;
        }

        let module = read_cstr(image, name_rva as usize)?;
        let thunk = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };

        let mut index: u32 = 0;
        loop {
            let thunk_offset = thunk as usize + index as usize * 8;
            if thunk_offset + 8 > image.len() {
                return Err(format!("import thunk overflow for {}", module));
            }
            let value = read_u64(image, thunk_offset)?;
            if value == 0 {
                break;
            }

            let iat_rva = first_thunk.wrapping_add(index.wrapping_mul(8));
            let symbol = if value & 0x8000_0000_0000_0000 != 0 {
                ImportSymbol::Ordinal((value & 0xFFFF) as u16)
            } else {
                let name_offset = value as u32 as usize;
                ImportSymbol::Name(read_cstr(image, name_offset + 2)?)
            };

            entries.push(ImportEntry {
                module: module.clone(),
                iat_rva,
                symbol,
            });

            index += 1;
            if index > 100_000 {
                return Err("import thunk limit exceeded".to_string());
            }
        }

        descriptor += 20;
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMPORT_RVA: usize = 0x2000;

    fn import_image() -> Vec<u8> {
        let mut image = vec![0u8; 0x3000];

        image[IMPORT_RVA..IMPORT_RVA + 4].copy_from_slice(&0x2200u32.to_le_bytes());
        image[IMPORT_RVA + 12..IMPORT_RVA + 16].copy_from_slice(&0x2100u32.to_le_bytes());
        image[IMPORT_RVA + 16..IMPORT_RVA + 20].copy_from_slice(&0x2300u32.to_le_bytes());

        image[0x2100..0x210D].copy_from_slice(b"KERNEL32.dll\0");

        image[0x2200..0x2208].copy_from_slice(&0x2400u64.to_le_bytes());
        image[0x2208..0x2210].copy_from_slice(&0x8000_0000_0000_0005u64.to_le_bytes());
        image[0x2210..0x2218].copy_from_slice(&0u64.to_le_bytes());

        image[0x2400..0x2402].copy_from_slice(&0u16.to_le_bytes());
        image[0x2402..0x240A].copy_from_slice(b"GetProc\0");

        image
    }

    #[test]
    fn test_parses_named_and_ordinal_imports() {
        let image = import_image();
        let entries = parse_imports(&image, IMPORT_RVA as u32, 40).expect("imports");
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].module, "KERNEL32.dll");
        assert_eq!(entries[0].iat_rva, 0x2300);
        assert_eq!(entries[0].symbol, ImportSymbol::Name("GetProc".to_string()));

        assert_eq!(entries[1].iat_rva, 0x2308);
        assert_eq!(entries[1].symbol, ImportSymbol::Ordinal(5));
    }

    #[test]
    fn test_empty_directory() {
        assert!(parse_imports(&[0u8; 16], 0, 0).unwrap().is_empty());
    }

    #[test]
    fn test_unterminated_name_is_rejected() {
        let mut image = import_image();
        for byte in image[0x2100..].iter_mut() {
            *byte = b'A';
        }
        assert!(parse_imports(&image, IMPORT_RVA as u32, 40).is_err());
    }
}
