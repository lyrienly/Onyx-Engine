use crate::process::ModuleEntry;

#[derive(Debug, Clone)]
pub struct DecodedInsn {
    pub address: usize,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub length: usize,
    pub target_addr: Option<usize>,
}

impl DecodedInsn {
    pub fn to_display_string(&self) -> String {
        let hex_bytes = self.bytes.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "0x{:016X}: {:<20} {} {}",
            self.address, hex_bytes, self.mnemonic, self.operands
        )
    }

    pub fn to_symbolic_string(&self, modules: &[ModuleEntry]) -> String {
        let hex_bytes = self.bytes.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let addr_sym = format_symbol(self.address, modules);
        format!(
            "{:<24} - {:<16} - {} {}",
            addr_sym, hex_bytes, self.mnemonic, self.operands
        )
    }
}

pub fn format_symbol(addr: usize, modules: &[ModuleEntry]) -> String {
    for m in modules {
        if addr >= m.base && addr < m.base + m.size {
            let offset = addr - m.base;
            return format!("{}+0x{:X}", m.name, offset);
        }
    }
    format!("0x{:016X}", addr)
}

pub struct Disassembler;

impl Disassembler {
    pub fn disassemble_block(address: usize, code: &[u8], count: usize) -> Vec<DecodedInsn> {
        let mut insns = Vec::new();
        let mut offset = 0;

        while offset < code.len() && insns.len() < count {
            let insn_addr = address + offset;
            let insn = Self::decode_one(insn_addr, &code[offset..]);
            let len = insn.length.max(1);
            offset += len;
            insns.push(insn);
        }

        insns
    }

    pub fn decode_one(addr: usize, code: &[u8]) -> DecodedInsn {
        if code.is_empty() {
            return DecodedInsn {
                address: addr,
                bytes: vec![],
                mnemonic: "???".to_string(),
                operands: String::new(),
                length: 0,
                target_addr: None,
            };
        }

        let mut idx = 0;
        let mut rex = 0u8;
        let mut operand_size_override = false;
        let mut repeat_prefix = 0u8;
        let mut segment_override = "";

        while idx < code.len() {
            let b = code[idx];
            match b {
                0x66 => { operand_size_override = true; idx += 1; }
                0x67 => { idx += 1; }
                0xF0 => { idx += 1; }
                0xF2 | 0xF3 => { repeat_prefix = b; idx += 1; }
                0x2E => { segment_override = "cs:"; idx += 1; }
                0x36 => { segment_override = "ss:"; idx += 1; }
                0x3E => { segment_override = "ds:"; idx += 1; }
                0x26 => { segment_override = "es:"; idx += 1; }
                0x64 => { segment_override = "fs:"; idx += 1; }
                0x65 => { segment_override = "gs:"; idx += 1; }
                0x40..=0x4F => { rex = b; idx += 1; }
                _ => break,
            }
        }

        if idx >= code.len() {
            return fallback(addr, code);
        }

        let opcode = code[idx];
        idx += 1;

        let rex_w = (rex & 0x08) != 0;
        let rex_r = (rex & 0x04) != 0;
        let rex_x = (rex & 0x02) != 0;
        let rex_b = (rex & 0x01) != 0;

        match opcode {

            0x90 => DecodedInsn {
                address: addr,
                bytes: code[..idx].to_vec(),
                mnemonic: "nop".to_string(),
                operands: String::new(),
                length: idx,
                target_addr: None,
            },

            0xCC => DecodedInsn {
                address: addr,
                bytes: code[..idx].to_vec(),
                mnemonic: "int3".to_string(),
                operands: String::new(),
                length: idx,
                target_addr: None,
            },

            0xCD => {
                let imm = if idx < code.len() { let b = code[idx]; idx += 1; b } else { 0 };
                DecodedInsn {
                    address: addr,
                    bytes: code[..idx].to_vec(),
                    mnemonic: "int".to_string(),
                    operands: format!("0x{:02X}", imm),
                    length: idx,
                    target_addr: None,
                }
            }

            0xC3 => DecodedInsn {
                address: addr,
                bytes: code[..idx].to_vec(),
                mnemonic: "ret".to_string(),
                operands: String::new(),
                length: idx,
                target_addr: None,
            },

            0xC2 => {
                let imm = if idx + 2 <= code.len() {
                    let v = u16::from_le_bytes([code[idx], code[idx + 1]]);
                    idx += 2;
                    v
                } else { 0 };
                DecodedInsn {
                    address: addr,
                    bytes: code[..idx].to_vec(),
                    mnemonic: "ret".to_string(),
                    operands: format!("0x{:04X}", imm),
                    length: idx,
                    target_addr: None,
                }
            }

            0xC9 => DecodedInsn {
                address: addr,
                bytes: code[..idx].to_vec(),
                mnemonic: "leave".to_string(),
                operands: String::new(),
                length: idx,
                target_addr: None,
            },

            0x50..=0x57 => {
                let reg_id = (opcode - 0x50) + if rex_b { 8 } else { 0 };
                DecodedInsn {
                    address: addr,
                    bytes: code[..idx].to_vec(),
                    mnemonic: "push".to_string(),
                    operands: reg64_name(reg_id).to_string(),
                    length: idx,
                    target_addr: None,
                }
            }

            0x58..=0x5F => {
                let reg_id = (opcode - 0x58) + if rex_b { 8 } else { 0 };
                DecodedInsn {
                    address: addr,
                    bytes: code[..idx].to_vec(),
                    mnemonic: "pop".to_string(),
                    operands: reg64_name(reg_id).to_string(),
                    length: idx,
                    target_addr: None,
                }
            }

            0x6A => {
                let imm = if idx < code.len() { let b = code[idx] as i8; idx += 1; b } else { 0 };
                DecodedInsn {
                    address: addr,
                    bytes: code[..idx].to_vec(),
                    mnemonic: "push".to_string(),
                    operands: format!("0x{:02X}", imm as u8),
                    length: idx,
                    target_addr: None,
                }
            }

            0x68 => {
                let imm = if idx + 4 <= code.len() {
                    let v = u32::from_le_bytes([code[idx], code[idx + 1], code[idx + 2], code[idx + 3]]);
                    idx += 4;
                    v
                } else { 0 };
                DecodedInsn {
                    address: addr,
                    bytes: code[..idx].to_vec(),
                    mnemonic: "push".to_string(),
                    operands: format!("0x{:08X}", imm),
                    length: idx,
                    target_addr: None,
                }
            }

            0xEB => {
                if idx < code.len() {
                    let rel = code[idx] as i8;
                    idx += 1;
                    let target = addr.wrapping_add(idx).wrapping_add(rel as isize as usize);
                    DecodedInsn {
                        address: addr,
                        bytes: code[..idx].to_vec(),
                        mnemonic: "jmp".to_string(),
                        operands: format!("0x{:X}", target),
                        length: idx,
                        target_addr: Some(target),
                    }
                } else {
                    fallback(addr, code)
                }
            }

            0xE9 => {
                if idx + 4 <= code.len() {
                    let rel = i32::from_le_bytes([code[idx], code[idx + 1], code[idx + 2], code[idx + 3]]);
                    idx += 4;
                    let target = addr.wrapping_add(idx).wrapping_add(rel as isize as usize);
                    DecodedInsn {
                        address: addr,
                        bytes: code[..idx].to_vec(),
                        mnemonic: "jmp".to_string(),
                        operands: format!("0x{:X}", target),
                        length: idx,
                        target_addr: Some(target),
                    }
                } else {
                    fallback(addr, code)
                }
            }

            0xE8 => {
                if idx + 4 <= code.len() {
                    let rel = i32::from_le_bytes([code[idx], code[idx + 1], code[idx + 2], code[idx + 3]]);
                    idx += 4;
                    let target = addr.wrapping_add(idx).wrapping_add(rel as isize as usize);
                    DecodedInsn {
                        address: addr,
                        bytes: code[..idx].to_vec(),
                        mnemonic: "call".to_string(),
                        operands: format!("0x{:X}", target),
                        length: idx,
                        target_addr: Some(target),
                    }
                } else {
                    fallback(addr, code)
                }
            }

            0x70..=0x7F => {
                if idx < code.len() {
                    let rel = code[idx] as i8;
                    idx += 1;
                    let target = addr.wrapping_add(idx).wrapping_add(rel as isize as usize);
                    let cond = jcc_name(opcode & 0x0F);
                    DecodedInsn {
                        address: addr,
                        bytes: code[..idx].to_vec(),
                        mnemonic: cond.to_string(),
                        operands: format!("0x{:X}", target),
                        length: idx,
                        target_addr: Some(target),
                    }
                } else {
                    fallback(addr, code)
                }
            }

            0xB0..=0xB7 => {
                let reg_id = (opcode - 0xB0) + if rex_b { 8 } else { 0 };
                let imm = if idx < code.len() { let b = code[idx]; idx += 1; b } else { 0 };
                DecodedInsn {
                    address: addr,
                    bytes: code[..idx].to_vec(),
                    mnemonic: "mov".to_string(),
                    operands: format!("{}, 0x{:02X}", reg8_name(reg_id, rex != 0), imm),
                    length: idx,
                    target_addr: None,
                }
            }

            0xB8..=0xBF => {
                let reg_id = (opcode - 0xB8) + if rex_b { 8 } else { 0 };
                if rex_w {
                    if idx + 8 <= code.len() {
                        let imm = u64::from_le_bytes([
                            code[idx], code[idx+1], code[idx+2], code[idx+3],
                            code[idx+4], code[idx+5], code[idx+6], code[idx+7],
                        ]);
                        idx += 8;
                        DecodedInsn {
                            address: addr,
                            bytes: code[..idx].to_vec(),
                            mnemonic: "mov".to_string(),
                            operands: format!("{}, 0x{:016X}", reg64_name(reg_id), imm),
                            length: idx,
                            target_addr: None,
                        }
                    } else {
                        fallback(addr, code)
                    }
                } else {
                    if idx + 4 <= code.len() {
                        let imm = u32::from_le_bytes([code[idx], code[idx+1], code[idx+2], code[idx+3]]);
                        idx += 4;
                        let reg_name = if operand_size_override { reg16_name(reg_id) } else { reg32_name(reg_id) };
                        DecodedInsn {
                            address: addr,
                            bytes: code[..idx].to_vec(),
                            mnemonic: "mov".to_string(),
                            operands: format!("{}, 0x{:08X}", reg_name, imm),
                            length: idx,
                            target_addr: None,
                        }
                    } else {
                        fallback(addr, code)
                    }
                }
            }

            0x91..=0x97 => {
                let reg_id = (opcode - 0x90) + if rex_b { 8 } else { 0 };
                let r1 = if rex_w { "rax" } else { "eax" };
                let r2 = if rex_w { reg64_name(reg_id) } else { reg32_name(reg_id) };
                DecodedInsn {
                    address: addr,
                    bytes: code[..idx].to_vec(),
                    mnemonic: "xchg".to_string(),
                    operands: format!("{}, {}", r1, r2),
                    length: idx,
                    target_addr: None,
                }
            }

            0x0F => {
                decode_two_byte_op(addr, code, idx, rex_w, rex_r, rex_x, rex_b, operand_size_override, repeat_prefix, segment_override)
            }

            _ => {
                decode_one_byte_modrm(addr, code, idx, opcode, rex_w, rex_r, rex_x, rex_b, operand_size_override, segment_override)
            }
        }
    }
}

fn decode_one_byte_modrm(
    addr: usize,
    code: &[u8],
    mut idx: usize,
    op: u8,
    rex_w: bool,
    rex_r: bool,
    rex_x: bool,
    rex_b: bool,
    op_override: bool,
    seg: &str,
) -> DecodedInsn {
    if idx >= code.len() {
        return fallback(addr, code);
    }

    let modrm = code[idx];
    idx += 1;

    let (rm_desc, reg_idx, disp_target) = parse_modrm_operands(addr, code, &mut idx, modrm, rex_w, rex_r, rex_x, rex_b, op_override, seg);

    let is_byte = (op & 0x01) == 0 && op != 0x8D && op != 0xC7 && op != 0x83;
    let is_reg_dest = (op & 0x02) != 0;

    let reg_name = if is_byte {
        reg8_name(reg_idx, rex_w || rex_r || rex_b)
    } else if rex_w {
        reg64_name(reg_idx)
    } else if op_override {
        reg16_name(reg_idx)
    } else {
        reg32_name(reg_idx)
    };

    let alu_ops = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"];
    let alu_idx = (op >> 3) & 0x07;

    let (mnemonic, operands) = match op {

        0x00..=0x3B => {
            let mnem = alu_ops[alu_idx as usize];
            if is_reg_dest {
                (mnem, format!("{}, {}", reg_name, rm_desc))
            } else {
                (mnem, format!("{}, {}", rm_desc, reg_name))
            }
        }

        0x3C..=0x3D => ("cmp", format!("{}, {}", reg_name, rm_desc)),

        0x63 => ("movsxd", format!("{}, {}", reg64_name(reg_idx), rm_desc)),

        0x69 => {
            let imm = if idx + 4 <= code.len() {
                let v = u32::from_le_bytes([code[idx], code[idx+1], code[idx+2], code[idx+3]]);
                idx += 4; v
            } else { 0 };
            ("imul", format!("{}, {}, 0x{:X}", reg_name, rm_desc, imm))
        }
        0x6B => {
            let imm = if idx < code.len() { let b = code[idx] as i8; idx += 1; b } else { 0 };
            ("imul", format!("{}, {}, 0x{:02X}", reg_name, rm_desc, imm as u8))
        }

        0x80..=0x83 => {
            let subop = (modrm >> 3) & 0x07;
            let mnem = alu_ops[subop as usize];
            if op == 0x83 {

                let imm = if idx < code.len() { let b = code[idx] as i8; idx += 1; b } else { 0 };
                (mnem, format!("{}, 0x{:02X}", rm_desc, imm as u8))
            } else if op == 0x80 || op == 0x82 {
                let imm = if idx < code.len() { let b = code[idx]; idx += 1; b } else { 0 };
                (mnem, format!("{}, 0x{:02X}", rm_desc, imm))
            } else {
                let imm = if idx + 4 <= code.len() {
                    let v = u32::from_le_bytes([code[idx], code[idx+1], code[idx+2], code[idx+3]]);
                    idx += 4; v
                } else { 0 };
                (mnem, format!("{}, 0x{:08X}", rm_desc, imm))
            }
        }

        0x84 | 0x85 => ("test", format!("{}, {}", rm_desc, reg_name)),

        0x86 | 0x87 => ("xchg", format!("{}, {}", rm_desc, reg_name)),

        0x88 | 0x89 => ("mov", format!("{}, {}", rm_desc, reg_name)),

        0x8A | 0x8B => ("mov", format!("{}, {}", reg_name, rm_desc)),

        0x8D => ("lea", format!("{}, {}", reg_name, rm_desc)),

        0xC0 | 0xC1 => {
            let subop = (modrm >> 3) & 0x07;
            let shift_ops = ["rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"];
            let mnem = shift_ops[subop as usize];
            let imm = if idx < code.len() { let b = code[idx]; idx += 1; b } else { 0 };
            (mnem, format!("{}, 0x{:02X}", rm_desc, imm))
        }

        0xC6 => {
            let imm = if idx < code.len() { let b = code[idx]; idx += 1; b } else { 0 };
            ("mov", format!("byte ptr {}, 0x{:02X}", rm_desc, imm))
        }
        0xC7 => {
            let imm = if idx + 4 <= code.len() {
                let v = u32::from_le_bytes([code[idx], code[idx+1], code[idx+2], code[idx+3]]);
                idx += 4; v
            } else { 0 };
            ("mov", format!("{}, 0x{:08X}", rm_desc, imm))
        }

        0xD0..=0xD3 => {
            let subop = (modrm >> 3) & 0x07;
            let shift_ops = ["rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"];
            let mnem = shift_ops[subop as usize];
            let count = if (op & 0x02) != 0 { "cl" } else { "1" };
            (mnem, format!("{}, {}", rm_desc, count))
        }

        0xF6 | 0xF7 => {
            let subop = (modrm >> 3) & 0x07;
            match subop {
                0 => {
                    let imm = if op == 0xF6 {
                        if idx < code.len() { let b = code[idx]; idx += 1; b as u32 } else { 0 }
                    } else {
                        if idx + 4 <= code.len() {
                            let v = u32::from_le_bytes([code[idx], code[idx+1], code[idx+2], code[idx+3]]);
                            idx += 4; v
                        } else { 0 }
                    };
                    ("test", format!("{}, 0x{:X}", rm_desc, imm))
                }
                2 => ("not", rm_desc),
                3 => ("neg", rm_desc),
                4 => ("mul", rm_desc),
                5 => ("imul", rm_desc),
                6 => ("div", rm_desc),
                7 => ("idiv", rm_desc),
                _ => ("grp3", rm_desc),
            }
        }

        0xFE => {
            let subop = (modrm >> 3) & 0x07;
            match subop {
                0 => ("inc", format!("byte ptr {}", rm_desc)),
                1 => ("dec", format!("byte ptr {}", rm_desc)),
                _ => ("grp4", rm_desc),
            }
        }

        0xFF => {
            let subop = (modrm >> 3) & 0x07;
            match subop {
                0 => ("inc", rm_desc),
                1 => ("dec", rm_desc),
                2 => ("call", format!("qword ptr {}", rm_desc)),
                4 => ("jmp", format!("qword ptr {}", rm_desc)),
                6 => ("push", rm_desc),
                _ => ("grp5", rm_desc),
            }
        }
        _ => {

            ("db", format!("0x{:02X}", op))
        }
    };

    DecodedInsn {
        address: addr,
        bytes: code[..idx.min(code.len())].to_vec(),
        mnemonic: mnemonic.to_string(),
        operands,
        length: idx.min(code.len()),
        target_addr: disp_target,
    }
}

fn decode_two_byte_op(
    addr: usize,
    code: &[u8],
    mut idx: usize,
    rex_w: bool,
    rex_r: bool,
    rex_x: bool,
    rex_b: bool,
    op_override: bool,
    repeat_prefix: u8,
    seg: &str,
) -> DecodedInsn {
    if idx >= code.len() {
        return fallback(addr, code);
    }

    let op2 = code[idx];
    idx += 1;

    match op2 {

        0x05 => DecodedInsn {
            address: addr,
            bytes: code[..idx].to_vec(),
            mnemonic: "syscall".to_string(),
            operands: String::new(),
            length: idx,
            target_addr: None,
        },

        0xA2 => DecodedInsn {
            address: addr,
            bytes: code[..idx].to_vec(),
            mnemonic: "cpuid".to_string(),
            operands: String::new(),
            length: idx,
            target_addr: None,
        },

        0x80..=0x8F => {
            if idx + 4 <= code.len() {
                let rel = i32::from_le_bytes([code[idx], code[idx + 1], code[idx + 2], code[idx + 3]]);
                idx += 4;
                let target = addr.wrapping_add(idx).wrapping_add(rel as isize as usize);
                let cond = jcc_name(op2 & 0x0F);
                DecodedInsn {
                    address: addr,
                    bytes: code[..idx].to_vec(),
                    mnemonic: cond.to_string(),
                    operands: format!("0x{:X}", target),
                    length: idx,
                    target_addr: Some(target),
                }
            } else {
                fallback(addr, code)
            }
        }

        _ => {
            if idx >= code.len() {
                return fallback(addr, code);
            }
            let modrm = code[idx];
            idx += 1;

            let (rm_desc, reg_idx, disp_target) = parse_modrm_operands(addr, code, &mut idx, modrm, rex_w, rex_r, rex_x, rex_b, op_override, seg);
            let reg_name = if rex_w { reg64_name(reg_idx) } else { reg32_name(reg_idx) };
            let xmm_name = format!("xmm{}", reg_idx);

            let (mnemonic, operands) = match op2 {

                0x1F => ("nop", format!("dword ptr {}", rm_desc)),

                0x10 => {
                    let mnem = if repeat_prefix == 0xF3 { "movss" } else if repeat_prefix == 0xF2 { "movsd" } else { "movups" };
                    (mnem, format!("{}, {}", xmm_name, rm_desc))
                }
                0x11 => {
                    let mnem = if repeat_prefix == 0xF3 { "movss" } else if repeat_prefix == 0xF2 { "movsd" } else { "movups" };
                    (mnem, format!("{}, {}", rm_desc, xmm_name))
                }

                0x28 => ("movaps", format!("{}, {}", xmm_name, rm_desc)),
                0x29 => ("movaps", format!("{}, {}", rm_desc, xmm_name)),

                0x2E => ("ucomiss", format!("{}, {}", xmm_name, rm_desc)),
                0x2F => ("comiss", format!("{}, {}", xmm_name, rm_desc)),

                0x57 => ("xorps", format!("{}, {}", xmm_name, rm_desc)),

                0x58 => {
                    let mnem = if repeat_prefix == 0xF3 { "addss" } else if repeat_prefix == 0xF2 { "addsd" } else { "addps" };
                    (mnem, format!("{}, {}", xmm_name, rm_desc))
                }

                0x59 => {
                    let mnem = if repeat_prefix == 0xF3 { "mulss" } else if repeat_prefix == 0xF2 { "mulsd" } else { "mulps" };
                    (mnem, format!("{}, {}", xmm_name, rm_desc))
                }

                0x5C => {
                    let mnem = if repeat_prefix == 0xF3 { "subss" } else if repeat_prefix == 0xF2 { "subsd" } else { "subps" };
                    (mnem, format!("{}, {}", xmm_name, rm_desc))
                }

                0x5E => {
                    let mnem = if repeat_prefix == 0xF3 { "divss" } else if repeat_prefix == 0xF2 { "divsd" } else { "divps" };
                    (mnem, format!("{}, {}", xmm_name, rm_desc))
                }

                0x90..=0x9F => {
                    let cond = jcc_name(op2 & 0x0F);
                    let mnem = match cond {
                        "jo" => "seto", "jno" => "setno", "jb" => "setb", "jnb" => "setnb",
                        "jz" => "setz", "jnz" => "setnz", "jbe" => "setbe", "ja" => "seta",
                        "js" => "sets", "jns" => "setns", "jp" => "setp", "jnp" => "setnp",
                        "jl" => "setl", "jge" => "setge", "jle" => "setle", "jg" => "setg",
                        _ => "setcc",
                    };
                    (mnem, format!("byte ptr {}", rm_desc))
                }

                0xAF => ("imul", format!("{}, {}", reg_name, rm_desc)),

                0xB6 => ("movzx", format!("{}, byte ptr {}", reg_name, rm_desc)),

                0xB7 => ("movzx", format!("{}, word ptr {}", reg_name, rm_desc)),

                0xBE => ("movsx", format!("{}, byte ptr {}", reg_name, rm_desc)),

                0xBF => ("movsx", format!("{}, word ptr {}", reg_name, rm_desc)),
                _ => ("0x0F", format!("0x{:02X} {}", op2, rm_desc)),
            };

            DecodedInsn {
                address: addr,
                bytes: code[..idx.min(code.len())].to_vec(),
                mnemonic: mnemonic.to_string(),
                operands,
                length: idx.min(code.len()),
                target_addr: disp_target,
            }
        }
    }
}

fn parse_modrm_operands(
    addr: usize,
    code: &[u8],
    idx: &mut usize,
    modrm: u8,
    rex_w: bool,
    rex_r: bool,
    rex_x: bool,
    rex_b: bool,
    op_override: bool,
    seg: &str,
) -> (String, u8, Option<usize>) {
    let md = (modrm >> 6) & 0x03;
    let reg = ((modrm >> 3) & 0x07) | if rex_r { 8 } else { 0 };
    let rm = (modrm & 0x07) | if rex_b { 8 } else { 0 };

    if md == 3 {

        let name = if rex_w {
            reg64_name(rm).to_string()
        } else if op_override {
            reg16_name(rm).to_string()
        } else {
            reg32_name(rm).to_string()
        };
        return (name, reg, None);
    }

    let mut disp: i64 = 0;
    let mut has_disp = false;
    let mut is_rip_relative = false;
    let mut sib_str = String::new();

    if (rm & 0x07) == 4 {
        if *idx < code.len() {
            let sib = code[*idx];
            *idx += 1;
            let scale = 1 << ((sib >> 6) & 0x03);
            let index = ((sib >> 3) & 0x07) | if rex_x { 8 } else { 0 };
            let base = (sib & 0x07) | if rex_b { 8 } else { 0 };

            if index != 4 {
                if base == 5 && md == 0 {

                    sib_str = format!("{}{}*{}", seg, reg64_name(index), scale);
                } else {
                    sib_str = format!("{}{}+{ }*{}", seg, reg64_name(base), reg64_name(index), scale);
                }
            } else {
                sib_str = format!("{}{}", seg, reg64_name(base));
            }
        }
    }

    if md == 0 && (rm & 0x07) == 5 {

        if *idx + 4 <= code.len() {
            let d = i32::from_le_bytes([code[*idx], code[*idx+1], code[*idx+2], code[*idx+3]]);
            *idx += 4;
            disp = d as i64;
            has_disp = true;
            is_rip_relative = true;
        }
    } else if md == 1 {
        if *idx < code.len() {
            disp = (code[*idx] as i8) as i64;
            *idx += 1;
            has_disp = true;
        }
    } else if md == 2 {
        if *idx + 4 <= code.len() {
            let d = i32::from_le_bytes([code[*idx], code[*idx+1], code[*idx+2], code[*idx+3]]);
            *idx += 4;
            disp = d as i64;
            has_disp = true;
        }
    }

    let mut target_addr = None;
    let desc = if is_rip_relative {
        let target = (addr as isize + *idx as isize + disp as isize) as usize;
        target_addr = Some(target);
        if disp >= 0 {
            format!("{}[rip+0x{:X}] (0x{:X})", seg, disp, target)
        } else {
            format!("{}[rip-0x{:X}] (0x{:X})", seg, -disp, target)
        }
    } else if !sib_str.is_empty() {
        if has_disp && disp != 0 {
            if disp > 0 {
                format!("[{}+0x{:X}]", sib_str, disp)
            } else {
                format!("[{}-0x{:X}]", sib_str, -disp)
            }
        } else {
            format!("[{}]", sib_str)
        }
    } else if has_disp && disp != 0 {
        let base_name = reg64_name(rm);
        if disp > 0 {
            format!("{}[{}+0x{:X}]", seg, base_name, disp)
        } else {
            format!("{}[{}-0x{:X}]", seg, base_name, -disp)
        }
    } else {
        format!("{}[{}]", seg, reg64_name(rm))
    };

    (desc, reg, target_addr)
}

fn fallback(addr: usize, code: &[u8]) -> DecodedInsn {
    DecodedInsn {
        address: addr,
        bytes: if !code.is_empty() { vec![code[0]] } else { vec![] },
        mnemonic: "db".to_string(),
        operands: if !code.is_empty() { format!("0x{:02X}", code[0]) } else { String::new() },
        length: 1.min(code.len()),
        target_addr: None,
    }
}

pub fn reg64_name(id: u8) -> &'static str {
    match id {
        0 => "rax", 1 => "rcx", 2 => "rdx", 3 => "rbx",
        4 => "rsp", 5 => "rbp", 6 => "rsi", 7 => "rdi",
        8 => "r8",  9 => "r9",  10 => "r10", 11 => "r11",
        12 => "r12", 13 => "r13", 14 => "r14", 15 => "r15",
        _ => "r??",
    }
}

pub fn reg32_name(id: u8) -> &'static str {
    match id {
        0 => "eax", 1 => "ecx", 2 => "edx", 3 => "ebx",
        4 => "esp", 5 => "ebp", 6 => "esi", 7 => "edi",
        8 => "r8d", 9 => "r9d", 10 => "r10d", 11 => "r11d",
        12 => "r12d", 13 => "r13d", 14 => "r14d", 15 => "r15d",
        _ => "e??",
    }
}

pub fn reg16_name(id: u8) -> &'static str {
    match id {
        0 => "ax", 1 => "cx", 2 => "dx", 3 => "bx",
        4 => "sp", 5 => "bp", 6 => "si", 7 => "di",
        8 => "r8w", 9 => "r9w", 10 => "r10w", 11 => "r11w",
        12 => "r12w", 13 => "r13w", 14 => "r14w", 15 => "r15w",
        _ => "??",
    }
}

pub fn reg8_name(id: u8, has_rex: bool) -> &'static str {
    if has_rex {
        match id {
            0 => "al", 1 => "cl", 2 => "dl", 3 => "bl",
            4 => "spl", 5 => "bpl", 6 => "sil", 7 => "dil",
            8 => "r8b", 9 => "r9b", 10 => "r10b", 11 => "r11b",
            12 => "r12b", 13 => "r13b", 14 => "r14b", 15 => "r15b",
            _ => "??",
        }
    } else {
        match id {
            0 => "al", 1 => "cl", 2 => "dl", 3 => "bl",
            4 => "ah", 5 => "ch", 6 => "dh", 7 => "bh",
            _ => "??",
        }
    }
}

pub fn jcc_name(code: u8) -> &'static str {
    match code {
        0x0 => "jo", 0x1 => "jno", 0x2 => "jb", 0x3 => "jae",
        0x4 => "je", 0x5 => "jne", 0x6 => "jbe", 0x7 => "ja",
        0x8 => "js", 0x9 => "jns", 0xA => "jp", 0xB => "jnp",
        0xC => "jl", 0xD => "jge", 0xE => "jle", 0xF => "jg",
        _ => "jcc",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disasm_mov_and_nop() {
        let code = [0x90, 0x48, 0x89, 0xC3, 0xC3];
        let insns = Disassembler::disassemble_block(0x1000, &code, 10);
        assert_eq!(insns.len(), 3);
        assert_eq!(insns[0].mnemonic, "nop");
        assert_eq!(insns[1].mnemonic, "mov");
        assert_eq!(insns[1].operands, "rbx, rax");
        assert_eq!(insns[2].mnemonic, "ret");
    }

    #[test]
    fn test_disasm_add_zero_memory() {
        let code = [0x00, 0x00];
        let insns = Disassembler::disassemble_block(0x2000, &code, 1);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].mnemonic, "add");
        assert_eq!(insns[0].operands, "[rax], al");
    }

    #[test]
    fn test_disasm_call_rel32() {
        let code = [0xE8, 0x10, 0x00, 0x00, 0x00];
        let insns = Disassembler::disassemble_block(0x1000, &code, 1);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].mnemonic, "call");
        assert_eq!(insns[0].target_addr, Some(0x1015));
    }
}
