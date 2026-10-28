use zydis::{Decoder, Formatter, InstructionCategory, VisibleOperands};
use zydis::ffi::{DecodedOperand, DecodedOperandKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowType {
    Sequential,
    ConditionalJump,
    UnconditionalJump,
    Call,
    Return,
    Int,
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub address: u64,
    pub mnemonic: String,
    pub operands: String,
    pub bytes: Vec<u8>,
    pub length: u8,
    pub flow_type: FlowType,
    pub branch_target: Option<u64>,
}

fn classify(category: InstructionCategory) -> FlowType {
    match category {
        InstructionCategory::COND_BR => FlowType::ConditionalJump,
        InstructionCategory::UNCOND_BR => FlowType::UnconditionalJump,
        InstructionCategory::CALL => FlowType::Call,
        InstructionCategory::RET => FlowType::Return,
        InstructionCategory::INTERRUPT => FlowType::Int,
        _ => FlowType::Sequential,
    }
}

fn operand_target(ip: u64, insn: &zydis::Instruction<VisibleOperands>, ops: &[DecodedOperand]) -> Option<u64> {
    for op in ops {
        if matches!(op.kind, DecodedOperandKind::Imm(_)) {
            if let Ok(addr) = insn.calc_absolute_address(ip, op) {
                return Some(addr);
            }
        }
    }
    None
}

/// Disassembles `bytes` starting at virtual address `base_addr`.
pub fn disassemble(bytes: &[u8], base_addr: u64) -> Vec<Instruction> {
    let decoder = Decoder::new64();
    let formatter = Formatter::intel();
    let mut out = Vec::new();

    for item in decoder.decode_all::<VisibleOperands>(bytes, base_addr) {
        let (ip, raw_bytes, insn) = match item {
            Ok(v) => v,
            Err(_) => break,
        };

        let full = formatter.format(Some(ip), &insn).unwrap_or_default();
        let mnemonic = insn.mnemonic.static_string().unwrap_or("").to_string();
        let operands = if full.len() > mnemonic.len() {
            full[mnemonic.len()..].trim_start().to_string()
        } else {
            String::new()
        };

        let flow_type = classify(insn.meta.category);
        let branch_target = match flow_type {
            FlowType::ConditionalJump | FlowType::UnconditionalJump | FlowType::Call => {
                operand_target(ip, &insn, insn.visible_operands())
            }
            _ => None,
        };

        out.push(Instruction {
            address: ip,
            mnemonic,
            operands,
            bytes: raw_bytes.to_vec(),
            length: insn.length,
            flow_type,
            branch_target,
        });
    }

    out
}

/// Formats a single instruction into a human-readable line.
pub fn format_instruction(insn: &Instruction) -> String {
    let hex = insn.bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
    format!("0x{:016X}: {:<24} {} {}", insn.address, hex, insn.mnemonic, insn.operands)
}
