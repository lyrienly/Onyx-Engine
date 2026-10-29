use crate::debugger::disasm::{DecodedInsn, Disassembler};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixupKind {
    Relative,
    RipRelative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fixup {
    pub offset: usize,
    pub size: usize,
    pub kind: FixupKind,
}

#[derive(Debug, Clone)]
pub struct RelocatedInstruction {
    pub bytes: Vec<u8>,
    pub original_address: usize,
    pub new_address: usize,
    pub length: usize,
    pub relocated: bool,
}

#[derive(Debug, Clone)]
pub struct RelocatedBlock {
    pub instructions: Vec<RelocatedInstruction>,
    pub original_size: usize,
}

pub struct RelocationEngine;

impl RelocationEngine {
    fn is_legacy_prefix(b: u8) -> bool {
        matches!(
            b,
            0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65
        )
    }

    fn is_rex(b: u8) -> bool {
        b & 0xF0 == 0x40
    }

    fn rip_disp_offset(bytes: &[u8]) -> Option<usize> {
        if bytes.len() < 3 {
            return None;
        }
        let mut i = 0;
        while i < bytes.len() && Self::is_legacy_prefix(bytes[i]) {
            i += 1;
        }
        while i < bytes.len() && Self::is_rex(bytes[i]) {
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }
        let op = bytes[i];
        i += 1;
        if op == 0x0F {
            if i >= bytes.len() {
                return None;
            }
            let op2 = bytes[i];
            i += 1;
            if op2 == 0x38 || op2 == 0x3A {
                i += 1;
            }
        }
        if i >= bytes.len() {
            return None;
        }
        let modrm = bytes[i];
        let md = modrm >> 6;
        let rm = modrm & 0x07;
        if md == 0 && rm == 5 {
            Some(i + 1)
        } else {
            None
        }
    }

    pub fn classify_fixup(insn: &DecodedInsn) -> Option<Fixup> {
        if insn.target_addr.is_none() || insn.bytes.is_empty() {
            return None;
        }
        let mut i = 0;
        while i < insn.bytes.len() && Self::is_legacy_prefix(insn.bytes[i]) {
            i += 1;
        }
        while i < insn.bytes.len() && Self::is_rex(insn.bytes[i]) {
            i += 1;
        }
        if i >= insn.bytes.len() {
            return None;
        }
        let op = insn.bytes[i];

        if op == 0xEB || (0x70..=0x7F).contains(&op) {
            return Some(Fixup {
                offset: insn.bytes.len() - 1,
                size: 1,
                kind: FixupKind::Relative,
            });
        }
        if op == 0xE8 || op == 0xE9 {
            return Some(Fixup {
                offset: insn.bytes.len() - 4,
                size: 4,
                kind: FixupKind::Relative,
            });
        }
        if op == 0x0F {
            let op2 = *insn.bytes.get(i + 1)?;
            if (0x80..=0x8F).contains(&op2) {
                return Some(Fixup {
                    offset: insn.bytes.len() - 4,
                    size: 4,
                    kind: FixupKind::Relative,
                });
            }
        }

        Self::rip_disp_offset(&insn.bytes).map(|offset| Fixup {
            offset,
            size: 4,
            kind: FixupKind::RipRelative,
        })
    }

    pub fn relocate_instruction(insn: &DecodedInsn, new_address: usize) -> RelocatedInstruction {
        if let (Some(target), Some(fixup)) = (insn.target_addr, Self::classify_fixup(insn)) {
            let mut bytes = insn.bytes.clone();
            let mut length = insn.length;

            match fixup.kind {
                FixupKind::RipRelative => {
                    let next_ip = new_address.wrapping_add(insn.length);
                    let new_disp = target as i64 - next_ip as i64;
                    bytes[fixup.offset..fixup.offset + 4]
                        .copy_from_slice(&(new_disp as i32).to_le_bytes());
                }
                FixupKind::Relative if fixup.size == 4 => {
                    let next_ip = new_address.wrapping_add(insn.length);
                    let new_disp = target as i64 - next_ip as i64;
                    bytes[fixup.offset..fixup.offset + 4]
                        .copy_from_slice(&(new_disp as i32).to_le_bytes());
                }
                FixupKind::Relative => {
                    let op = insn.bytes[fixup.offset - 1];
                    let widened_len = if op == 0xEB { 5usize } else { 6usize };
                    let next_ip = new_address.wrapping_add(insn.length);
                    let new_disp = target as i64 - next_ip as i64;

                    if (-128..=127).contains(&new_disp) {
                        bytes[fixup.offset] = new_disp as i8 as u8;
                    } else {
                        let far_next_ip = new_address.wrapping_add(widened_len);
                        let far_disp = target as i64 - far_next_ip as i64;
                        let mut widened = Vec::with_capacity(6);
                        if op == 0xEB {
                            widened.push(0xE9);
                            widened.extend_from_slice(&(far_disp as i32).to_le_bytes());
                        } else {
                            let cc = op & 0x0F;
                            widened.push(0x0F);
                            widened.push(0x80 | cc);
                            widened.extend_from_slice(&(far_disp as i32).to_le_bytes());
                        }
                        bytes = widened;
                        length = widened_len;
                    }
                }
            }

            return RelocatedInstruction {
                bytes,
                original_address: insn.address,
                new_address,
                length,
                relocated: true,
            };
        }

        RelocatedInstruction {
            bytes: insn.bytes.clone(),
            original_address: insn.address,
            new_address,
            length: insn.length,
            relocated: false,
        }
    }

    pub fn relocate_block(
        code: &[u8],
        from_address: usize,
        to_address: usize,
        min_bytes: usize,
    ) -> Result<RelocatedBlock, String> {
        let mut offset = 0usize;
        let mut instructions = Vec::new();

        while offset < code.len() {
            let insn = Disassembler::decode_one(from_address.wrapping_add(offset), &code[offset..]);
            let len = insn.length.max(1);
            let new_address = to_address
                .wrapping_add(instructions.iter().map(|r: &RelocatedInstruction| r.length).sum::<usize>());
            instructions.push(Self::relocate_instruction(&insn, new_address));
            offset = offset.wrapping_add(len);

            if offset >= min_bytes {
                break;
            }
        }

        if offset < min_bytes {
            return Err(format!(
                "Not enough bytes to relocate (need {}, have {})",
                min_bytes, offset
            ));
        }

        Ok(RelocatedBlock {
            instructions,
            original_size: offset,
        })
    }

    pub fn emit_relative_jump(from_address: usize, to_address: usize) -> [u8; 5] {
        let rel = to_address as i64 - (from_address as i64 + 5);
        let mut bytes = [0xE9, 0, 0, 0, 0];
        bytes[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
        bytes
    }

    pub fn build_trampoline(
        code: &[u8],
        from_address: usize,
        to_address: usize,
        min_bytes: usize,
    ) -> Result<Vec<u8>, String> {
        let block = Self::relocate_block(code, from_address, to_address, min_bytes)?;
        let mut buffer = Vec::new();
        let mut cursor = to_address;

        for insn in &block.instructions {
            buffer.extend_from_slice(&insn.bytes);
            cursor = cursor.wrapping_add(insn.length);
        }

        let jump_back = Self::emit_relative_jump(cursor, from_address.wrapping_add(block.original_size));
        buffer.extend_from_slice(&jump_back);
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_rip_relative() {
        let code = [0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00];
        let insn = Disassembler::decode_one(0x1000, &code);
        assert_eq!(insn.target_addr, Some(0x1017));

        let fx = RelocationEngine::classify_fixup(&insn).expect("rip-relative fixup");
        assert_eq!(fx.kind, FixupKind::RipRelative);
        assert_eq!(fx.offset, 3);
        assert_eq!(fx.size, 4);
    }

    #[test]
    fn test_relocate_rip_relative() {
        let code = [0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00];
        let insn = Disassembler::decode_one(0x1000, &code);
        let rel = RelocationEngine::relocate_instruction(&insn, 0x2000);
        assert!(rel.relocated);

        let check = Disassembler::decode_one(0x2000, &rel.bytes);
        assert_eq!(check.target_addr, Some(0x1017));
    }

    #[test]
    fn test_relocate_relative_jmp_rel32() {
        let code = [0xE9, 0x00, 0x00, 0x00, 0x00];
        let insn = Disassembler::decode_one(0x1000, &code);
        assert_eq!(insn.target_addr, Some(0x1005));

        let rel = RelocationEngine::relocate_instruction(&insn, 0x2000);
        assert!(rel.relocated);
        let check = Disassembler::decode_one(0x2000, &rel.bytes);
        assert_eq!(check.target_addr, Some(0x1005));
    }

    #[test]
    fn test_relocate_relative_jmp_rel8_widens() {
        let code = [0xEB, 0x05];
        let insn = Disassembler::decode_one(0x1000, &code);
        assert_eq!(insn.target_addr, Some(0x1007));

        let rel = RelocationEngine::relocate_instruction(&insn, 0x2000);
        assert!(rel.relocated);
        assert_eq!(rel.bytes.len(), 5);
        assert_eq!(rel.bytes[0], 0xE9);
        let check = Disassembler::decode_one(0x2000, &rel.bytes);
        assert_eq!(check.target_addr, Some(0x1007));
    }

    #[test]
    fn test_relocate_jcc_rel8_widens() {
        let code = [0x74, 0x02];
        let insn = Disassembler::decode_one(0x1000, &code);
        assert_eq!(insn.target_addr, Some(0x1004));

        let rel = RelocationEngine::relocate_instruction(&insn, 0x5000);
        assert!(rel.relocated);
        assert_eq!(rel.bytes.len(), 6);
        assert_eq!(rel.bytes[0], 0x0F);
        assert_eq!(rel.bytes[1], 0x84);
        let check = Disassembler::decode_one(0x5000, &rel.bytes);
        assert_eq!(check.target_addr, Some(0x1004));
    }

    #[test]
    fn test_relocate_call_rel32() {
        let code = [0xE8, 0x00, 0x00, 0x00, 0x00];
        let insn = Disassembler::decode_one(0x1000, &code);
        assert_eq!(insn.target_addr, Some(0x1005));

        let rel = RelocationEngine::relocate_instruction(&insn, 0x4000);
        let check = Disassembler::decode_one(0x4000, &rel.bytes);
        assert_eq!(check.target_addr, Some(0x1005));
    }

    #[test]
    fn test_plain_instruction_not_relocated() {
        let code = [0x90];
        let insn = Disassembler::decode_one(0x1000, &code);
        let rel = RelocationEngine::relocate_instruction(&insn, 0x2000);
        assert!(!rel.relocated);
        assert_eq!(rel.bytes, vec![0x90]);
    }

    #[test]
    fn test_build_trampoline() {
        let code = [0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00, 0x90];
        let trampoline = RelocationEngine::build_trampoline(&code, 0x1000, 0x3000, 5).unwrap();

        assert_eq!(trampoline.len(), 7 + 5);
        assert_eq!(trampoline[trampoline.len() - 5], 0xE9);

        let relocated_lea = Disassembler::decode_one(0x3000, &trampoline[..7]);
        assert_eq!(relocated_lea.target_addr, Some(0x1017));

        let jump_back = Disassembler::decode_one(0x3007, &trampoline[7..]);
        assert_eq!(jump_back.target_addr, Some(0x1007));
    }

    #[test]
    fn test_relocate_block_not_enough_bytes() {
        let code = [0x90, 0x90, 0x90];
        assert!(RelocationEngine::relocate_block(&code, 0x1000, 0x3000, 5).is_err());
    }
}
