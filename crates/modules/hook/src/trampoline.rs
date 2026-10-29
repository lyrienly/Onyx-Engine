//! Decodifica o prologue do alvo e constroi um trampolim relocado.
//!
//! Estrategia:
//! 1. Decodifica instrucoes com zydis ate acumular >= `PATCH_SIZE` bytes.
//! 2. Para cada instrucao copiada verifica operandos de memoria com base
//!    `RIP`: recalcula o `disp32` para apontar para o endereco original.
//! 3. Rejeita branches relativos (JMP/CALL/Jcc rel) dentro da regiao do
//!    patch, pois reajustar esses targets exige expansao de instrucao.
//! 4. Finaliza com `FF 25 00 00 00 00 <qword>` saltando para
//!    `target + bytes_copiados`.

use zydis::ffi::DecodedOperandKind;
use zydis::{Decoder, Register, VisibleOperands};

/// Tamanho do patch absoluto `JMP [RIP+0]; qword` em bytes.
pub const PATCH_SIZE: usize = 14;

/// Erros possiveis durante a construcao do trampolim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrampolineError {
    /// Nao foi possivel decodificar instrucoes suficientes para cobrir o patch.
    PrologueTooShort,
    /// Falha de decodificacao em alguma instrucao do prologue.
    DecodeFailed,
    /// Instrucao de controle de fluxo relativa dentro do prologue: nao e
    /// possivel copiar sem reconstruir a instrucao (fora do escopo).
    UnsupportedRelativeBranch,
    /// Novo deslocamento RIP-relative nao cabe em `i32` apos a relocacao.
    DisplacementOutOfRange,
}

impl core::fmt::Display for TrampolineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TrampolineError::PrologueTooShort => write!(f, "prologue muito curto para patch de {} bytes", PATCH_SIZE),
            TrampolineError::DecodeFailed => write!(f, "falha ao decodificar instrucao do prologue"),
            TrampolineError::UnsupportedRelativeBranch => write!(f, "branch relativo no prologue nao suportado"),
            TrampolineError::DisplacementOutOfRange => write!(f, "deslocamento RIP-relative fora de i32 apos relocacao"),
        }
    }
}

impl std::error::Error for TrampolineError {}

/// Metadados de uma relocacao aplicada em uma instrucao copiada.
#[derive(Debug, Clone)]
pub struct RelocationInfo {
    /// Offset da instrucao dentro do trampolim.
    pub trampoline_offset: usize,
    /// Offset da instrucao original dentro do alvo.
    pub source_offset: usize,
    /// Tamanho em bytes.
    pub length: usize,
    /// Tipo de relocacao aplicada.
    pub kind: RelocationKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelocationKind {
    /// Nao exigiu reajuste.
    None,
    /// Reajuste de displacement RIP-relative (disp32).
    RipRelative { old_disp: i32, new_disp: i32 },
}

/// Resultado da construcao do trampolim.
pub struct Trampoline {
    /// Bytes finais que devem ser escritos na code cave.
    pub bytes: Vec<u8>,
    /// Quantidade de bytes do prologue consumidos no alvo.
    pub consumed: usize,
    /// Relocacoes aplicadas (para debug / testes).
    pub relocations: Vec<RelocationInfo>,
}

/// Constroi o trampolim para um prologue cujos bytes estao em `prologue`,
/// originalmente mapeado em `target_addr`, sabendo que o trampolim sera
/// escrito em `trampoline_addr`.
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

        // Rejeita branches relativos (JMP rel, Jcc rel, CALL rel) no
        // prologue: a reconstrucao exigiria expansao da instrucao (ex:
        // transformar Jcc rel8 em sequencia de instrucoes com target
        // absoluto). Fora do escopo desta primeira versao.
        for raw_imm in insn.raw.imm.iter() {
            if raw_imm.size != 0 && raw_imm.is_relative {
                return Err(TrampolineError::UnsupportedRelativeBranch);
            }
        }

        let mut insn_bytes = raw_bytes.to_vec();
        let mut rel_kind = RelocationKind::None;

        // Procura operando de memoria com base = RIP.
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
                // RIP-relative sempre usa disp32 em modo 64 bits; qualquer
                // outra configuracao e inesperada.
                return Err(TrampolineError::DecodeFailed);
            }

            let old_disp = insn.raw.disp.value as i32;
            // Alvo absoluto em memoria referenciado pela instrucao original.
            let absolute_target = (ip as i128)
                .wrapping_add(length as i128)
                .wrapping_add(old_disp as i128);

            // Novo IP (apos a instrucao) quando ela estiver no trampolim.
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
            rel_kind = RelocationKind::RipRelative {
                old_disp,
                new_disp,
            };
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

    // Emite JMP absoluto de volta para o alvo + consumed.
    let continuation = target_addr.wrapping_add(consumed as u64);
    out.extend_from_slice(&absolute_jmp(continuation));

    Ok(Trampoline {
        bytes: out,
        consumed,
        relocations,
    })
}

/// Gera `FF 25 00 00 00 00 <qword addr>` — JMP absoluto de 14 bytes.
pub fn absolute_jmp(addr: u64) -> [u8; PATCH_SIZE] {
    let mut buf = [0u8; PATCH_SIZE];
    buf[0] = 0xFF;
    buf[1] = 0x25;
    // disp32 = 0
    buf[6..14].copy_from_slice(&addr.to_le_bytes());
    buf
}
