use zydis::ffi::DecodedOperandKind;
use zydis::{Decoder, Register, VisibleOperands};

pub const PATCH_SIZE: usize = 14;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrampolineError {
    PrologueTooShort,

    DecodeFailed,

    UnsupportedRelativeBranch,

    DisplacementOutOfRange,
}

impl core::fmt::Display for TrampolineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TrampolineError::PrologueTooShort => {
                write!(f, "prologue muito curto para patch de {} bytes", PATCH_SIZE)
            }
            TrampolineError::DecodeFailed => {
                write!(f, "falha ao decodificar instrucao do prologue")
            }
            TrampolineError::UnsupportedRelativeBranch => {
                write!(f, "branch relativo no prologue nao suportado")
            }
            TrampolineError::DisplacementOutOfRange => {
                write!(f, "deslocamento RIP-relative fora de i32 apos relocacao")
            }
        }
    }
}

impl std::error::Error for TrampolineError {}

#[derive(Debug, Clone)]
pub struct RelocationInfo {
    pub trampoline_offset: usize,

    pub source_offset: usize,

    pub length: usize,

    pub kind: RelocationKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelocationKind {
    None,

    RipRelative { old_disp: i32, new_disp: i32 },
}

pub struct Trampoline {
    pub bytes: Vec<u8>,

    pub consumed: usize,

    pub relocations: Vec<RelocationInfo>,
}

pub fn build_trampoline(
    prologue: &[u8],
    target_addr: u64,
    trampoline_addr: u64,
) -> Result<Trampoline, TrampolineError> {
    let decoder = Decoder::new64();
    let mut out: Vec<u8> = Vec::with_capacity(PATCH_SIZE + 16);
    let mut relocations = Vec::new();
    let mut consumed: usize = 0;

    for item in decoder.decode_all::<VisibleOperands>(prologue, target_addr) {
        let (ip, raw_bytes, insn) = match item {
            Ok(v) => v,
            Err(_) => return Err(TrampolineError::DecodeFailed),
        };

        let src_offset = (ip - target_addr) as usize;
        let dst_offset = out.len();
        let length = raw_bytes.len();

        for raw_imm in insn.raw.imm.iter() {
            if raw_imm.size != 0 && raw_imm.is_relative {
                return Err(TrampolineError::UnsupportedRelativeBranch);
            }
        }

        let mut insn_bytes = raw_bytes.to_vec();
        let mut rel_kind = RelocationKind::None;

        let mut rip_relative = false;
        for op in insn.visible_operands() {
            if let DecodedOperandKind::Mem(mem) = &op.kind {
                if mem.base == Register::RIP {
                    rip_relative = true;
                    break;
                }
            }
        }

        if rip_relative {
            let disp_offset = insn.raw.disp.offset as usize;
            let disp_size_bits = insn.raw.disp.size;
            if disp_size_bits != 32 || disp_offset == 0 || disp_offset + 4 > length {
                return Err(TrampolineError::DecodeFailed);
            }

            let old_disp = insn.raw.disp.value as i32;

            let absolute_target = (ip as i128)
                .wrapping_add(length as i128)
                .wrapping_add(old_disp as i128);

            let new_ip_after = (trampoline_addr as i128)
                .wrapping_add(dst_offset as i128)
                .wrapping_add(length as i128);

            let new_disp_i128 = absolute_target.wrapping_sub(new_ip_after);
            if new_disp_i128 > i32::MAX as i128 || new_disp_i128 < i32::MIN as i128 {
                return Err(TrampolineError::DisplacementOutOfRange);
            }
            let new_disp = new_disp_i128 as i32;
            let bytes = new_disp.to_le_bytes();
            insn_bytes[disp_offset..disp_offset + 4].copy_from_slice(&bytes);
            rel_kind = RelocationKind::RipRelative { old_disp, new_disp };
        }

        out.extend_from_slice(&insn_bytes);
        relocations.push(RelocationInfo {
            trampoline_offset: dst_offset,
            source_offset: src_offset,
            length,
            kind: rel_kind,
        });

        consumed += length;
        if consumed >= PATCH_SIZE {
            break;
        }
    }

    if consumed < PATCH_SIZE {
        return Err(TrampolineError::PrologueTooShort);
    }

    let continuation = target_addr.wrapping_add(consumed as u64);
    out.extend_from_slice(&absolute_jmp(continuation));

    Ok(Trampoline {
        bytes: out,
        consumed,
        relocations,
    })
}

pub fn absolute_jmp(addr: u64) -> [u8; PATCH_SIZE] {
    let mut buf = [0u8; PATCH_SIZE];
    buf[0] = 0xFF;
    buf[1] = 0x25;

    buf[6..14].copy_from_slice(&addr.to_le_bytes());
    buf
}
