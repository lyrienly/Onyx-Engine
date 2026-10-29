#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GadgetKind {
    Ret,
    RetFar,
    RetImm(u16),
    JmpReg,
    CallReg,
    JmpMem,
    CallMem,
    Syscall,
    Int80,
    PopRet,
    LeaveRet,
}

impl GadgetKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            GadgetKind::Ret => "ret",
            GadgetKind::RetFar => "retf",
            GadgetKind::RetImm(_) => "ret imm",
            GadgetKind::JmpReg => "jmp reg",
            GadgetKind::CallReg => "call reg",
            GadgetKind::JmpMem => "jmp [mem]",
            GadgetKind::CallMem => "call [mem]",
            GadgetKind::Syscall => "syscall",
            GadgetKind::Int80 => "int 0x80",
            GadgetKind::PopRet => "pop; ret",
            GadgetKind::LeaveRet => "leave; ret",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gadget {
    pub address: usize,
    pub bytes: Vec<u8>,
    pub kind: GadgetKind,
}

pub struct RopFinder;

impl RopFinder {
    fn match_at(buffer: &[u8], i: usize) -> Option<(GadgetKind, usize)> {
        let remaining = buffer.len() - i;
        let b0 = buffer[i];

        if b0 == 0x0F && remaining >= 2 && buffer[i + 1] == 0x05 {
            return Some((GadgetKind::Syscall, 2));
        }
        if b0 == 0xCD && remaining >= 2 && buffer[i + 1] == 0x80 {
            return Some((GadgetKind::Int80, 2));
        }
        if b0 == 0xC9 && remaining >= 2 && buffer[i + 1] == 0xC3 {
            return Some((GadgetKind::LeaveRet, 2));
        }

        if b0 == 0xFF && remaining >= 2 {
            let modrm = buffer[i + 1];
            if (0xE0..=0xE7).contains(&modrm) {
                return Some((GadgetKind::JmpReg, 2));
            }
            if (0xD0..=0xD7).contains(&modrm) {
                return Some((GadgetKind::CallReg, 2));
            }
            if modrm == 0x25 && remaining >= 6 {
                return Some((GadgetKind::JmpMem, 6));
            }
            if modrm == 0x15 && remaining >= 6 {
                return Some((GadgetKind::CallMem, 6));
            }
        }

        if (0x58..=0x5F).contains(&b0) {
            if remaining >= 2 && buffer[i + 1] == 0xC3 {
                return Some((GadgetKind::PopRet, 2));
            }
            if remaining >= 4 && buffer[i + 1] == 0xC2 {
                return Some((GadgetKind::PopRet, 4));
            }
        }
        if b0 == 0x41 && remaining >= 3 {
            let pop = buffer[i + 1];
            if (0x58..=0x5F).contains(&pop) && buffer[i + 2] == 0xC3 {
                return Some((GadgetKind::PopRet, 3));
            }
            if (0x58..=0x5F).contains(&pop) && remaining >= 5 && buffer[i + 2] == 0xC2 {
                return Some((GadgetKind::PopRet, 5));
            }
        }

        if b0 == 0xC3 {
            return Some((GadgetKind::Ret, 1));
        }
        if b0 == 0xCB {
            return Some((GadgetKind::RetFar, 1));
        }
        if b0 == 0xC2 && remaining >= 3 {
            let imm = u16::from_le_bytes([buffer[i + 1], buffer[i + 2]]);
            return Some((GadgetKind::RetImm(imm), 3));
        }

        None
    }

    pub fn find(buffer: &[u8], base_address: usize, max_gadgets: usize) -> Vec<Gadget> {
        let mut gadgets = Vec::new();
        if buffer.is_empty() || max_gadgets == 0 {
            return gadgets;
        }

        for i in 0..buffer.len() {
            if gadgets.len() >= max_gadgets {
                break;
            }
            if let Some((kind, len)) = Self::match_at(buffer, i) {
                gadgets.push(Gadget {
                    address: base_address.wrapping_add(i),
                    bytes: buffer[i..i + len].to_vec(),
                    kind,
                });
            }
        }

        gadgets
    }

    pub fn find_by_kind(
        buffer: &[u8],
        base_address: usize,
        max_gadgets: usize,
        kind: GadgetKind,
    ) -> Vec<Gadget> {
        Self::find(buffer, base_address, usize::MAX)
            .into_iter()
            .filter(|g| g.kind == kind)
            .take(max_gadgets)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_basic_terminators() {
        let buf = [0xC3, 0xCB, 0xC2, 0x10, 0x00];
        let gadgets = RopFinder::find(&buf, 0x1000, 10);
        assert_eq!(gadgets.len(), 3);
        assert_eq!(gadgets[0].kind, GadgetKind::Ret);
        assert_eq!(gadgets[0].address, 0x1000);
        assert_eq!(gadgets[1].kind, GadgetKind::RetFar);
        assert_eq!(gadgets[2].kind, GadgetKind::RetImm(0x10));
        assert_eq!(gadgets[2].bytes, vec![0xC2, 0x10, 0x00]);
    }

    #[test]
    fn test_detects_register_transfers() {
        let buf = [0xFF, 0xE0, 0xFF, 0xD7, 0xFF, 0x25, 0, 0, 0, 0];
        let gadgets = RopFinder::find(&buf, 0, 10);
        let kinds: Vec<_> = gadgets.iter().map(|g| g.kind).collect();
        assert!(kinds.contains(&GadgetKind::JmpReg));
        assert!(kinds.contains(&GadgetKind::CallReg));
        assert!(kinds.contains(&GadgetKind::JmpMem));
    }

    #[test]
    fn test_detects_syscall_and_int80() {
        let buf = [0x0F, 0x05, 0xCD, 0x80];
        let gadgets = RopFinder::find(&buf, 0, 10);
        assert_eq!(gadgets[0].kind, GadgetKind::Syscall);
        assert_eq!(gadgets[1].kind, GadgetKind::Int80);
    }

    #[test]
    fn test_detects_pop_ret_variants() {
        let buf = [0x5F, 0xC3, 0x41, 0x58, 0xC3, 0x5E, 0xC2, 0x08, 0x00];
        let gadgets = RopFinder::find(&buf, 0, 20);
        let pop_rets: Vec<_> = gadgets
            .iter()
            .filter(|g| g.kind == GadgetKind::PopRet)
            .collect();
        let bytes: Vec<&[u8]> = pop_rets.iter().map(|g| g.bytes.as_slice()).collect();
        assert!(bytes.contains(&[0x5F, 0xC3].as_slice()));
        assert!(bytes.contains(&[0x41, 0x58, 0xC3].as_slice()));
        assert!(bytes.contains(&[0x5E, 0xC2, 0x08, 0x00].as_slice()));
    }

    #[test]
    fn test_detects_leave_ret() {
        let buf = [0xC9, 0xC3];
        let gadgets = RopFinder::find(&buf, 0, 10);
        assert_eq!(gadgets.len(), 2);
        assert_eq!(gadgets[0].kind, GadgetKind::LeaveRet);
        assert_eq!(gadgets[1].kind, GadgetKind::Ret);
    }

    #[test]
    fn test_respects_max_gadgets() {
        let buf = [0xC3; 32];
        let gadgets = RopFinder::find(&buf, 0, 5);
        assert_eq!(gadgets.len(), 5);
    }

    #[test]
    fn test_filter_by_kind() {
        let buf = [0xC3, 0x0F, 0x05, 0xC3];
        let syscalls = RopFinder::find_by_kind(&buf, 0, 10, GadgetKind::Syscall);
        assert_eq!(syscalls.len(), 1);
        assert_eq!(syscalls[0].address, 1);
    }

    #[test]
    fn test_little_endian_ret_imm() {
        let buf = [0xC2, 0x34, 0x12];
        let gadgets = RopFinder::find(&buf, 0, 10);
        assert_eq!(gadgets[0].kind, GadgetKind::RetImm(0x1234));
    }
}
