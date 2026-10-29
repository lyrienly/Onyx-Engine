pub const REL_BASED_ABSOLUTE: u16 = 0;
pub const REL_BASED_HIGHLOW: u16 = 3;
pub const REL_BASED_DIR64: u16 = 10;

pub fn apply_relocations(
    image: &mut [u8],
    reloc_rva: u32,
    reloc_size: u32,
    delta: i64,
) -> Result<u32, String> {
    if reloc_rva == 0 || reloc_size == 0 || delta == 0 {
        return Ok(0);
    }

    let start = reloc_rva as usize;
    let end = start
        .checked_add(reloc_size as usize)
        .ok_or_else(|| "relocation directory overflow".to_string())?;
    if end > image.len() {
        return Err("relocation directory exceeds image".to_string());
    }

    let mut cursor = start;
    let mut applied = 0u32;

    while cursor + 8 <= end {
        let page_rva =
            u32::from_le_bytes([image[cursor], image[cursor + 1], image[cursor + 2], image[cursor + 3]])
                as usize;
        let block_size = u32::from_le_bytes([
            image[cursor + 4],
            image[cursor + 5],
            image[cursor + 6],
            image[cursor + 7],
        ]) as usize;

        if block_size < 8 || block_size % 2 != 0 {
            return Err(format!("invalid relocation block size {}", block_size));
        }
        if cursor + block_size > end {
            return Err("relocation block exceeds directory".to_string());
        }

        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let offset = cursor + 8 + i * 2;
            let entry = u16::from_le_bytes([image[offset], image[offset + 1]]);
            let kind = entry >> 12;
            let target = page_rva + (entry & 0x0FFF) as usize;

            match kind {
                REL_BASED_ABSOLUTE => {}
                REL_BASED_HIGHLOW => {
                    if target + 4 > image.len() {
                        return Err(format!("HIGHLOW relocation out of bounds at 0x{:X}", target));
                    }
                    let value = u32::from_le_bytes([
                        image[target],
                        image[target + 1],
                        image[target + 2],
                        image[target + 3],
                    ]);
                    let updated = (value as i64 + delta) as u32;
                    image[target..target + 4].copy_from_slice(&updated.to_le_bytes());
                    applied += 1;
                }
                REL_BASED_DIR64 => {
                    if target + 8 > image.len() {
                        return Err(format!("DIR64 relocation out of bounds at 0x{:X}", target));
                    }
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&image[target..target + 8]);
                    let value = u64::from_le_bytes(bytes);
                    let updated = (value as i64).wrapping_add(delta) as u64;
                    image[target..target + 8].copy_from_slice(&updated.to_le_bytes());
                    applied += 1;
                }
                other => return Err(format!("unsupported relocation type {}", other)),
            }
        }

        cursor += block_size;
    }

    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir64_image() -> Vec<u8> {
        let mut image = vec![0u8; 0x2000];
        image[0x1000..0x1008].copy_from_slice(&0x1_4000_1000u64.to_le_bytes());
        image[0x1800..0x1804].copy_from_slice(&0x1000u32.to_le_bytes());
        image[0x1804..0x1808].copy_from_slice(&12u32.to_le_bytes());
        image[0x1808..0x180A].copy_from_slice(&0xA000u16.to_le_bytes());
        image[0x180A..0x180C].copy_from_slice(&0u16.to_le_bytes());
        image
    }

    #[test]
    fn test_dir64_applied() {
        let mut image = dir64_image();
        let applied = apply_relocations(&mut image, 0x1800, 12, -0x1000).expect("reloc");
        assert_eq!(applied, 1);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&image[0x1000..0x1008]);
        assert_eq!(u64::from_le_bytes(bytes), 0x1_4000_0000);
    }

    #[test]
    fn test_absolute_entry_is_skipped() {
        let mut image = dir64_image();
        image[0x180A..0x180C].copy_from_slice(&0x0000u16.to_le_bytes());
        image[0x1808..0x180A].copy_from_slice(&0x0000u16.to_le_bytes());
        let applied = apply_relocations(&mut image, 0x1800, 12, -0x1000).expect("reloc");
        assert_eq!(applied, 0);
    }

    #[test]
    fn test_zero_delta_is_noop() {
        let mut image = dir64_image();
        let applied = apply_relocations(&mut image, 0x1800, 12, 0).expect("reloc");
        assert_eq!(applied, 0);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&image[0x1000..0x1008]);
        assert_eq!(u64::from_le_bytes(bytes), 0x1_4000_1000);
    }

    #[test]
    fn test_highlow_applied() {
        let mut image = vec![0u8; 0x2000];
        image[0x1000..0x1004].copy_from_slice(&0x0040_1000u32.to_le_bytes());
        image[0x1800..0x1804].copy_from_slice(&0x1000u32.to_le_bytes());
        image[0x1804..0x1808].copy_from_slice(&12u32.to_le_bytes());
        image[0x1808..0x180A].copy_from_slice(&0x3000u16.to_le_bytes());
        image[0x180A..0x180C].copy_from_slice(&0u16.to_le_bytes());

        apply_relocations(&mut image, 0x1800, 12, 0x1000).expect("reloc");
        let v = u32::from_le_bytes([image[0x1000], image[0x1001], image[0x1002], image[0x1003]]);
        assert_eq!(v, 0x0040_2000);
    }

    #[test]
    fn test_invalid_block_is_rejected() {
        let mut image = vec![0u8; 0x2000];
        image[0x1800..0x1804].copy_from_slice(&0x1000u32.to_le_bytes());
        image[0x1804..0x1808].copy_from_slice(&4u32.to_le_bytes());
        assert!(apply_relocations(&mut image, 0x1800, 12, 1).is_err());
    }
}
