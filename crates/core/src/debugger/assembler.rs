#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegSize {
    Byte,
    Word,
    Dword,
    Qword,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegInfo {
    pub id: u8,
    pub size: RegSize,
    pub is_high_byte: bool,
}

pub fn parse_reg(s: &str) -> Option<RegInfo> {
    let lower = s.trim().to_lowercase();
    match lower.as_str() {

        "rax" => Some(RegInfo { id: 0, size: RegSize::Qword, is_high_byte: false }),
        "rcx" => Some(RegInfo { id: 1, size: RegSize::Qword, is_high_byte: false }),
        "rdx" => Some(RegInfo { id: 2, size: RegSize::Qword, is_high_byte: false }),
        "rbx" => Some(RegInfo { id: 3, size: RegSize::Qword, is_high_byte: false }),
        "rsp" => Some(RegInfo { id: 4, size: RegSize::Qword, is_high_byte: false }),
        "rbp" => Some(RegInfo { id: 5, size: RegSize::Qword, is_high_byte: false }),
        "rsi" => Some(RegInfo { id: 6, size: RegSize::Qword, is_high_byte: false }),
        "rdi" => Some(RegInfo { id: 7, size: RegSize::Qword, is_high_byte: false }),
        "r8"  => Some(RegInfo { id: 8, size: RegSize::Qword, is_high_byte: false }),
        "r9"  => Some(RegInfo { id: 9, size: RegSize::Qword, is_high_byte: false }),
        "r10" => Some(RegInfo { id: 10, size: RegSize::Qword, is_high_byte: false }),
        "r11" => Some(RegInfo { id: 11, size: RegSize::Qword, is_high_byte: false }),
        "r12" => Some(RegInfo { id: 12, size: RegSize::Qword, is_high_byte: false }),
        "r13" => Some(RegInfo { id: 13, size: RegSize::Qword, is_high_byte: false }),
        "r14" => Some(RegInfo { id: 14, size: RegSize::Qword, is_high_byte: false }),
        "r15" => Some(RegInfo { id: 15, size: RegSize::Qword, is_high_byte: false }),

        "eax" => Some(RegInfo { id: 0, size: RegSize::Dword, is_high_byte: false }),
        "ecx" => Some(RegInfo { id: 1, size: RegSize::Dword, is_high_byte: false }),
        "edx" => Some(RegInfo { id: 2, size: RegSize::Dword, is_high_byte: false }),
        "ebx" => Some(RegInfo { id: 3, size: RegSize::Dword, is_high_byte: false }),
        "esp" => Some(RegInfo { id: 4, size: RegSize::Dword, is_high_byte: false }),
        "ebp" => Some(RegInfo { id: 5, size: RegSize::Dword, is_high_byte: false }),
        "esi" => Some(RegInfo { id: 6, size: RegSize::Dword, is_high_byte: false }),
        "edi" => Some(RegInfo { id: 7, size: RegSize::Dword, is_high_byte: false }),
        "r8d" => Some(RegInfo { id: 8, size: RegSize::Dword, is_high_byte: false }),
        "r9d" => Some(RegInfo { id: 9, size: RegSize::Dword, is_high_byte: false }),
        "r10d" => Some(RegInfo { id: 10, size: RegSize::Dword, is_high_byte: false }),
        "r11d" => Some(RegInfo { id: 11, size: RegSize::Dword, is_high_byte: false }),
        "r12d" => Some(RegInfo { id: 12, size: RegSize::Dword, is_high_byte: false }),
        "r13d" => Some(RegInfo { id: 13, size: RegSize::Dword, is_high_byte: false }),
        "r14d" => Some(RegInfo { id: 14, size: RegSize::Dword, is_high_byte: false }),
        "r15d" => Some(RegInfo { id: 15, size: RegSize::Dword, is_high_byte: false }),

        "ax"  => Some(RegInfo { id: 0, size: RegSize::Word, is_high_byte: false }),
        "cx"  => Some(RegInfo { id: 1, size: RegSize::Word, is_high_byte: false }),
        "dx"  => Some(RegInfo { id: 2, size: RegSize::Word, is_high_byte: false }),
        "bx"  => Some(RegInfo { id: 3, size: RegSize::Word, is_high_byte: false }),
        "sp"  => Some(RegInfo { id: 4, size: RegSize::Word, is_high_byte: false }),
        "bp"  => Some(RegInfo { id: 5, size: RegSize::Word, is_high_byte: false }),
        "si"  => Some(RegInfo { id: 6, size: RegSize::Word, is_high_byte: false }),
        "di"  => Some(RegInfo { id: 7, size: RegSize::Word, is_high_byte: false }),
        "r8w" => Some(RegInfo { id: 8, size: RegSize::Word, is_high_byte: false }),
        "r9w" => Some(RegInfo { id: 9, size: RegSize::Word, is_high_byte: false }),
        "r10w" => Some(RegInfo { id: 10, size: RegSize::Word, is_high_byte: false }),
        "r11w" => Some(RegInfo { id: 11, size: RegSize::Word, is_high_byte: false }),
        "r12w" => Some(RegInfo { id: 12, size: RegSize::Word, is_high_byte: false }),
        "r13w" => Some(RegInfo { id: 13, size: RegSize::Word, is_high_byte: false }),
        "r14w" => Some(RegInfo { id: 14, size: RegSize::Word, is_high_byte: false }),
        "r15w" => Some(RegInfo { id: 15, size: RegSize::Word, is_high_byte: false }),

        "al"  => Some(RegInfo { id: 0, size: RegSize::Byte, is_high_byte: false }),
        "cl"  => Some(RegInfo { id: 1, size: RegSize::Byte, is_high_byte: false }),
        "dl"  => Some(RegInfo { id: 2, size: RegSize::Byte, is_high_byte: false }),
        "bl"  => Some(RegInfo { id: 3, size: RegSize::Byte, is_high_byte: false }),
        "spl" => Some(RegInfo { id: 4, size: RegSize::Byte, is_high_byte: false }),
        "bpl" => Some(RegInfo { id: 5, size: RegSize::Byte, is_high_byte: false }),
        "sil" => Some(RegInfo { id: 6, size: RegSize::Byte, is_high_byte: false }),
        "dil" => Some(RegInfo { id: 7, size: RegSize::Byte, is_high_byte: false }),
        "r8b" => Some(RegInfo { id: 8, size: RegSize::Byte, is_high_byte: false }),
        "r9b" => Some(RegInfo { id: 9, size: RegSize::Byte, is_high_byte: false }),
        "r10b" => Some(RegInfo { id: 10, size: RegSize::Byte, is_high_byte: false }),
        "r11b" => Some(RegInfo { id: 11, size: RegSize::Byte, is_high_byte: false }),
        "r12b" => Some(RegInfo { id: 12, size: RegSize::Byte, is_high_byte: false }),
        "r13b" => Some(RegInfo { id: 13, size: RegSize::Byte, is_high_byte: false }),
        "r14b" => Some(RegInfo { id: 14, size: RegSize::Byte, is_high_byte: false }),
        "r15b" => Some(RegInfo { id: 15, size: RegSize::Byte, is_high_byte: false }),

        "ah"  => Some(RegInfo { id: 4, size: RegSize::Byte, is_high_byte: true }),
        "ch"  => Some(RegInfo { id: 5, size: RegSize::Byte, is_high_byte: true }),
        "dh"  => Some(RegInfo { id: 6, size: RegSize::Byte, is_high_byte: true }),
        "bh"  => Some(RegInfo { id: 7, size: RegSize::Byte, is_high_byte: true }),

        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MemOperand {
    pub base: Option<RegInfo>,
    pub index: Option<RegInfo>,
    pub scale: u8,
    pub disp: i64,
    pub is_rip_relative: bool,
    pub explicit_size: Option<RegSize>,
}

pub fn parse_mem_operand(s: &str, resolver: &dyn Fn(&str) -> Option<usize>) -> Option<MemOperand> {
    let mut text = s.trim();
    let mut explicit_size = None;

    let lower = text.to_lowercase();
    if lower.starts_with("byte ptr ") {
        explicit_size = Some(RegSize::Byte);
        text = text[9..].trim();
    } else if lower.starts_with("word ptr ") {
        explicit_size = Some(RegSize::Word);
        text = text[9..].trim();
    } else if lower.starts_with("dword ptr ") {
        explicit_size = Some(RegSize::Dword);
        text = text[10..].trim();
    } else if lower.starts_with("qword ptr ") {
        explicit_size = Some(RegSize::Qword);
        text = text[10..].trim();
    }

    if !text.starts_with('[') || !text.ends_with(']') {
        return None;
    }

    let inner = text[1..text.len() - 1].trim();
    if inner.is_empty() {
        return None;
    }

    if inner.eq_ignore_ascii_case("rip") {
        return Some(MemOperand {
            base: None,
            index: None,
            scale: 1,
            disp: 0,
            is_rip_relative: true,
            explicit_size,
        });
    }

    let mut base = None;
    let mut index = None;
    let mut scale = 1;
    let mut disp: i64 = 0;
    let mut is_rip = false;

    let mut tokens: Vec<(bool, String)> = Vec::new();
    let mut cur = String::new();
    let mut positive = true;

    for ch in inner.chars() {
        if ch == '+' {
            if !cur.trim().is_empty() {
                tokens.push((positive, cur.trim().to_string()));
                cur.clear();
            }
            positive = true;
        } else if ch == '-' {
            if !cur.trim().is_empty() {
                tokens.push((positive, cur.trim().to_string()));
                cur.clear();
            }
            positive = false;
        } else {
            cur.push(ch);
        }
    }
    if !cur.trim().is_empty() {
        tokens.push((positive, cur.trim().to_string()));
    }

    for (is_pos, tok) in tokens {
        let t = tok.trim();
        if t.eq_ignore_ascii_case("rip") {
            is_rip = true;
            continue;
        }

        if let Some(star_pos) = t.find('*') {
            let p1 = t[..star_pos].trim();
            let p2 = t[star_pos + 1..].trim();
            let (reg_str, scale_str) = if parse_reg(p1).is_some() {
                (p1, p2)
            } else {
                (p2, p1)
            };
            if let Some(r) = parse_reg(reg_str) {
                index = Some(r);
                scale = scale_str.parse::<u8>().unwrap_or(1).max(1);
                continue;
            }
        }

        if let Some(r) = parse_reg(t) {
            if base.is_none() {
                base = Some(r);
            } else if index.is_none() {
                index = Some(r);
                scale = 1;
            }
            continue;
        }

        let num_val = if let Some(n) = parse_int_or_hex(t) {
            Some(n)
        } else if let Some(sym_addr) = resolver(t) {
            Some(sym_addr as i64)
        } else {
            None
        };

        if let Some(val) = num_val {
            if is_pos {
                disp += val;
            } else {
                disp -= val;
            }
        }
    }

    Some(MemOperand {
        base,
        index,
        scale,
        disp,
        is_rip_relative: is_rip,
        explicit_size,
    })
}

pub fn parse_int_or_hex(s: &str) -> Option<i64> {
    let t = s.trim();
    if t.starts_with("0x") || t.starts_with("0X") {
        i64::from_str_radix(&t[2..], 16).ok()
    } else if t.starts_with('$') {
        i64::from_str_radix(&t[1..], 16).ok()
    } else if t.starts_with('#') {
        t[1..].trim().parse::<i64>().ok()
    } else if t.starts_with('-') {
        let rest = &t[1..].trim();
        if rest.starts_with("0x") || rest.starts_with("0X") {
            i64::from_str_radix(&rest[2..], 16).ok().map(|n| -n)
        } else if rest.starts_with('$') {
            i64::from_str_radix(&rest[1..], 16).ok().map(|n| -n)
        } else if rest.starts_with('#') {
            rest[1..].trim().parse::<i64>().ok().map(|n| -n)
        } else {
            rest.parse::<i64>().ok().map(|n| -n)
        }
    } else {
        t.parse::<i64>().ok().or_else(|| i64::from_str_radix(t, 16).ok())
    }
}

pub struct Assembler;

impl Assembler {

    pub fn assemble_line(
        line: &str,
        current_ip: usize,
        resolver: &dyn Fn(&str) -> Option<usize>,
    ) -> Result<Vec<u8>, String> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(Vec::new());
        }

        let lower = trimmed.to_lowercase();

        if lower.starts_with("db ") {
            return parse_db_directive(&trimmed[3..], resolver);
        } else if lower.starts_with("dw ") {
            return parse_dw_directive(&trimmed[3..], resolver);
        } else if lower.starts_with("dd ") {
            return parse_dd_directive(&trimmed[3..], resolver);
        } else if lower.starts_with("dq ") {
            return parse_dq_directive(&trimmed[3..], resolver);
        } else if lower.starts_with("float ") {
            let f = trimmed[6..].trim().parse::<f32>().map_err(|e| e.to_string())?;
            return Ok(f.to_ne_bytes().to_vec());
        } else if lower.starts_with("double ") {
            let d = trimmed[7..].trim().parse::<f64>().map_err(|e| e.to_string())?;
            return Ok(d.to_ne_bytes().to_vec());
        }

        match lower.as_str() {
            "nop" => return Ok(vec![0x90]),
            "ret" => return Ok(vec![0xC3]),
            "int 3" | "int3" => return Ok(vec![0xCC]),
            "syscall" => return Ok(vec![0x0F, 0x05]),
            "leave" => return Ok(vec![0xC9]),
            "cdq" => return Ok(vec![0x99]),
            "cqo" => return Ok(vec![0x48, 0x99]),
            _ => {}
        }

        let (mnemonic, ops_str) = match trimmed.find(|c: char| c.is_whitespace()) {
            Some(idx) => (trimmed[..idx].trim().to_lowercase(), trimmed[idx..].trim()),
            None => (lower.clone(), ""),
        };

        match mnemonic.as_str() {
            "ret" => {
                if !ops_str.is_empty() {
                    let imm = parse_int_or_hex(ops_str).ok_or("Invalid ret immediate")? as u16;
                    let mut b = vec![0xC2];
                    b.extend_from_slice(&imm.to_le_bytes());
                    return Ok(b);
                }
                return Ok(vec![0xC3]);
            }

            "push" => {
                if let Some(reg) = parse_reg(ops_str) {
                    if reg.size == RegSize::Qword {
                        if reg.id >= 8 {
                            return Ok(vec![0x41, 0x50 + (reg.id - 8)]);
                        } else {
                            return Ok(vec![0x50 + reg.id]);
                        }
                    } else if reg.size == RegSize::Dword {
                        return Ok(vec![0x50 + reg.id]);
                    }
                } else if let Some(imm) = parse_int_or_hex(ops_str).or_else(|| resolver(ops_str).map(|a| a as i64)) {
                    if imm >= -128 && imm <= 127 {
                        return Ok(vec![0x6A, imm as u8]);
                    } else {
                        let mut b = vec![0x68];
                        b.extend_from_slice(&(imm as u32).to_le_bytes());
                        return Ok(b);
                    }
                }
            }

            "pop" => {
                if let Some(reg) = parse_reg(ops_str) {
                    if reg.size == RegSize::Qword {
                        if reg.id >= 8 {
                            return Ok(vec![0x41, 0x58 + (reg.id - 8)]);
                        } else {
                            return Ok(vec![0x58 + reg.id]);
                        }
                    } else if reg.size == RegSize::Dword {
                        return Ok(vec![0x58 + reg.id]);
                    }
                }
            }

            "jmp" => {
                return assemble_branch(0xE9, 0xEB, ops_str, current_ip, resolver);
            }

            "call" => {
                if let Some(reg) = parse_reg(ops_str) {
                    if reg.id >= 8 {
                        return Ok(vec![0x41, 0xFF, 0xD0 + (reg.id - 8)]);
                    } else {
                        return Ok(vec![0xFF, 0xD0 + reg.id]);
                    }
                }

                if let Some(mem) = parse_mem_operand(ops_str, resolver) {
                    return encode_modrm_insn(0xFF, 0xFF, RegInfo { id: 2, size: RegSize::Qword, is_high_byte: false }, &mem, false);
                }

                let target = resolver(ops_str)
                    .or_else(|| parse_int_or_hex(ops_str).map(|n| n as usize))
                    .ok_or_else(|| format!("Could not resolve call target '{}'", ops_str))?;

                let rel = (target as i64) - ((current_ip + 5) as i64);
                if rel >= i32::MIN as i64 && rel <= i32::MAX as i64 {
                    let mut b = vec![0xE8];
                    b.extend_from_slice(&(rel as i32).to_le_bytes());
                    return Ok(b);
                } else {

                    let mut b = vec![0x48, 0xB8];
                    b.extend_from_slice(&(target as u64).to_le_bytes());
                    b.extend_from_slice(&[0xFF, 0xD0]);
                    return Ok(b);
                }
            }

            "je" | "jz"   => return assemble_cond_jump(0x84, 0x74, ops_str, current_ip, resolver),
            "jne" | "jnz" => return assemble_cond_jump(0x85, 0x75, ops_str, current_ip, resolver),
            "jb" | "jc"   => return assemble_cond_jump(0x82, 0x72, ops_str, current_ip, resolver),
            "jae" | "jnc" => return assemble_cond_jump(0x83, 0x73, ops_str, current_ip, resolver),
            "jbe"         => return assemble_cond_jump(0x86, 0x76, ops_str, current_ip, resolver),
            "ja"          => return assemble_cond_jump(0x87, 0x77, ops_str, current_ip, resolver),
            "jl"          => return assemble_cond_jump(0x8C, 0x7C, ops_str, current_ip, resolver),
            "jge"         => return assemble_cond_jump(0x8D, 0x7D, ops_str, current_ip, resolver),
            "jle"         => return assemble_cond_jump(0x8E, 0x7E, ops_str, current_ip, resolver),
            "jg"          => return assemble_cond_jump(0x8F, 0x7F, ops_str, current_ip, resolver),
            "js"          => return assemble_cond_jump(0x88, 0x78, ops_str, current_ip, resolver),
            "jns"         => return assemble_cond_jump(0x89, 0x79, ops_str, current_ip, resolver),

            "mov" => {
                return assemble_mov(ops_str, resolver);
            }

            "lea" => {
                return assemble_lea(ops_str, resolver);
            }

            "add" => return assemble_alu(0x00, 0, ops_str, resolver),
            "or"  => return assemble_alu(0x08, 1, ops_str, resolver),
            "adc" => return assemble_alu(0x10, 2, ops_str, resolver),
            "sbb" => return assemble_alu(0x18, 3, ops_str, resolver),
            "and" => return assemble_alu(0x20, 4, ops_str, resolver),
            "sub" => return assemble_alu(0x28, 5, ops_str, resolver),
            "xor" => return assemble_alu(0x30, 6, ops_str, resolver),
            "cmp" => return assemble_alu(0x38, 7, ops_str, resolver),

            "test" => return assemble_test(ops_str, resolver),

            "inc" => return assemble_inc_dec(0, ops_str, resolver),
            "dec" => return assemble_inc_dec(1, ops_str, resolver),

            _ => {}
        }

        Err(format!("Unsupported or unrecognized assembly instruction: '{}'", line))
    }
}

fn assemble_branch(
    near_op: u8,
    short_op: u8,
    target_str: &str,
    current_ip: usize,
    resolver: &dyn Fn(&str) -> Option<usize>,
) -> Result<Vec<u8>, String> {
    let trimmed = target_str.trim();

    if let Some(reg) = parse_reg(trimmed) {
        if reg.id >= 8 {
            return Ok(vec![0x41, 0xFF, 0xE0 + (reg.id - 8)]);
        } else {
            return Ok(vec![0xFF, 0xE0 + reg.id]);
        }
    }

    if let Some(mem) = parse_mem_operand(trimmed, resolver) {
        return encode_modrm_insn(0xFF, 0xFF, RegInfo { id: 4, size: RegSize::Qword, is_high_byte: false }, &mem, false);
    }

    let (is_explicit_short, clean_target) = if let Some(stripped) = trimmed.strip_prefix("short ") {
        (true, stripped.trim())
    } else {
        (false, trimmed)
    };

    let target = resolver(clean_target)
        .or_else(|| parse_int_or_hex(clean_target).map(|n| n as usize))
        .ok_or_else(|| format!("Could not resolve branch destination '{}'", clean_target))?;

    let rel2 = (target as i64) - ((current_ip + 2) as i64);
    if is_explicit_short {
        if rel2 >= -128 && rel2 <= 127 {
            return Ok(vec![short_op, rel2 as u8]);
        } else {
            return Err(format!("Short jump out of range: rel={}", rel2));
        }
    }

    let rel5 = (target as i64) - ((current_ip + 5) as i64);
    if rel5 >= i32::MIN as i64 && rel5 <= i32::MAX as i64 {
        let mut b = vec![near_op];
        b.extend_from_slice(&(rel5 as i32).to_le_bytes());
        return Ok(b);
    }

    let mut b = vec![0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
    b.extend_from_slice(&(target as u64).to_le_bytes());
    Ok(b)
}

fn assemble_cond_jump(
    near_op2: u8,
    short_op: u8,
    target_str: &str,
    current_ip: usize,
    resolver: &dyn Fn(&str) -> Option<usize>,
) -> Result<Vec<u8>, String> {
    let trimmed = target_str.trim();
    let (is_explicit_short, clean_target) = if let Some(stripped) = trimmed.strip_prefix("short ") {
        (true, stripped.trim())
    } else {
        (false, trimmed)
    };

    let target = resolver(clean_target)
        .or_else(|| parse_int_or_hex(clean_target).map(|n| n as usize))
        .ok_or_else(|| format!("Could not resolve conditional jump target '{}'", clean_target))?;

    let rel2 = (target as i64) - ((current_ip + 2) as i64);
    if is_explicit_short {
        if rel2 >= -128 && rel2 <= 127 {
            return Ok(vec![short_op, rel2 as u8]);
        } else {
            return Err(format!("Short conditional jump out of range: rel={}", rel2));
        }
    }

    let rel6 = (target as i64) - ((current_ip + 6) as i64);
    if rel6 >= i32::MIN as i64 && rel6 <= i32::MAX as i64 {
        let mut b = vec![0x0F, near_op2];
        b.extend_from_slice(&(rel6 as i32).to_le_bytes());
        return Ok(b);
    }

    Err(format!("Conditional jump target 0x{:X} out of range from 0x{:X}", target, current_ip))
}

fn assemble_mov(ops_str: &str, resolver: &dyn Fn(&str) -> Option<usize>) -> Result<Vec<u8>, String> {
    let parts: Vec<&str> = ops_str.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() < 2 {
        return Err("mov requires two operands".to_string());
    }
    let dst_str = parts[0];
    let src_str = parts[1];

    let dst_reg = parse_reg(dst_str);
    let src_reg = parse_reg(src_str);

    if let (Some(dst), Some(src)) = (dst_reg, src_reg) {
        let mut bytes = Vec::new();
        let rex = make_rex(dst.size == RegSize::Qword, src.id >= 8, false, dst.id >= 8);
        if dst.size == RegSize::Word {
            bytes.push(0x66);
        }
        if let Some(r) = rex {
            bytes.push(r);
        }
        let opcode = if dst.size == RegSize::Byte { 0x88 } else { 0x89 };
        bytes.push(opcode);
        let modrm = 0xC0 | ((src.id & 7) << 3) | (dst.id & 7);
        bytes.push(modrm);
        return Ok(bytes);
    }

    if let (Some(dst), None) = (dst_reg, src_reg) {
        if let Some(imm) = parse_int_or_hex(src_str).or_else(|| resolver(src_str).map(|a| a as i64)) {
            let mut bytes = Vec::new();
            match dst.size {
                RegSize::Qword => {
                    let rex = make_rex(true, false, false, dst.id >= 8).unwrap_or(0x48);
                    bytes.push(rex);
                    bytes.push(0xB8 + (dst.id & 7));
                    bytes.extend_from_slice(&(imm as u64).to_le_bytes());
                }
                RegSize::Dword => {
                    if dst.id >= 8 {
                        bytes.push(0x41);
                    }
                    bytes.push(0xB8 + (dst.id & 7));
                    bytes.extend_from_slice(&(imm as u32).to_le_bytes());
                }
                RegSize::Word => {
                    bytes.push(0x66);
                    if dst.id >= 8 {
                        bytes.push(0x41);
                    }
                    bytes.push(0xB8 + (dst.id & 7));
                    bytes.extend_from_slice(&(imm as u16).to_le_bytes());
                }
                RegSize::Byte => {
                    if dst.id >= 4 && !dst.is_high_byte {
                        bytes.push(if dst.id >= 8 { 0x41 } else { 0x40 });
                    }
                    bytes.push(0xB0 + (dst.id & 7));
                    bytes.push(imm as u8);
                }
            }
            return Ok(bytes);
        }
    }

    if let (Some(dst), None) = (dst_reg, src_reg) {
        if let Some(mem) = parse_mem_operand(src_str, resolver) {
            return encode_modrm_insn(0x8B, 0x8A, dst, &mem, false);
        }
    }

    if let (None, Some(src)) = (dst_reg, src_reg) {
        if let Some(mem) = parse_mem_operand(dst_str, resolver) {
            return encode_modrm_insn(0x89, 0x88, src, &mem, true);
        }
    }

    if dst_reg.is_none() && src_reg.is_none() {
        if let Some(mem) = parse_mem_operand(dst_str, resolver) {
            if let Some(imm) = parse_int_or_hex(src_str).or_else(|| resolver(src_str).map(|a| a as i64)) {
                return encode_mem_imm(0xC7, 0xC6, 0, &mem, imm);
            }
        }
    }

    Err(format!("Cannot assemble mov instruction: '{}'", ops_str))
}

fn assemble_lea(ops_str: &str, resolver: &dyn Fn(&str) -> Option<usize>) -> Result<Vec<u8>, String> {
    let parts: Vec<&str> = ops_str.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() < 2 {
        return Err("lea requires two operands".to_string());
    }
    let dst = parse_reg(parts[0]).ok_or("lea destination must be a register")?;
    let mem = parse_mem_operand(parts[1], resolver).ok_or("lea source must be a memory operand")?;
    encode_modrm_insn(0x8D, 0x8D, dst, &mem, false)
}

fn assemble_alu(base_opcode: u8, reg_op: u8, ops_str: &str, resolver: &dyn Fn(&str) -> Option<usize>) -> Result<Vec<u8>, String> {
    let parts: Vec<&str> = ops_str.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() < 2 {
        return Err("ALU instruction requires two operands".to_string());
    }
    let dst_str = parts[0];
    let src_str = parts[1];

    let dst_reg = parse_reg(dst_str);
    let src_reg = parse_reg(src_str);

    if let (Some(dst), Some(src)) = (dst_reg, src_reg) {
        let mut bytes = Vec::new();
        let rex = make_rex(dst.size == RegSize::Qword, src.id >= 8, false, dst.id >= 8);
        if dst.size == RegSize::Word {
            bytes.push(0x66);
        }
        if let Some(r) = rex {
            bytes.push(r);
        }
        let opcode = if dst.size == RegSize::Byte { base_opcode } else { base_opcode + 1 };
        bytes.push(opcode);
        let modrm = 0xC0 | ((src.id & 7) << 3) | (dst.id & 7);
        bytes.push(modrm);
        return Ok(bytes);
    }

    if let (Some(dst), None) = (dst_reg, src_reg) {
        if let Some(mem) = parse_mem_operand(src_str, resolver) {
            return encode_modrm_insn(base_opcode + 3, base_opcode + 2, dst, &mem, false);
        }
    }

    if let (None, Some(src)) = (dst_reg, src_reg) {
        if let Some(mem) = parse_mem_operand(dst_str, resolver) {
            return encode_modrm_insn(base_opcode + 1, base_opcode, src, &mem, true);
        }
    }

    if let (Some(dst), None) = (dst_reg, src_reg) {
        if let Some(imm) = parse_int_or_hex(src_str).or_else(|| resolver(src_str).map(|a| a as i64)) {
            let mut bytes = Vec::new();
            let is_qword = dst.size == RegSize::Qword;
            let rex = make_rex(is_qword, false, false, dst.id >= 8);
            if dst.size == RegSize::Word {
                bytes.push(0x66);
            }
            if let Some(r) = rex {
                bytes.push(r);
            }
            if dst.size == RegSize::Byte {
                bytes.push(0x80);
                bytes.push(0xC0 | (reg_op << 3) | (dst.id & 7));
                bytes.push(imm as u8);
            } else if imm >= -128 && imm <= 127 {
                bytes.push(0x83);
                bytes.push(0xC0 | (reg_op << 3) | (dst.id & 7));
                bytes.push(imm as u8);
            } else {
                bytes.push(0x81);
                bytes.push(0xC0 | (reg_op << 3) | (dst.id & 7));
                bytes.extend_from_slice(&(imm as u32).to_le_bytes());
            }
            return Ok(bytes);
        }
    }

    if dst_reg.is_none() && src_reg.is_none() {
        if let Some(mem) = parse_mem_operand(dst_str, resolver) {
            if let Some(imm) = parse_int_or_hex(src_str).or_else(|| resolver(src_str).map(|a| a as i64)) {
                return encode_mem_imm(0x81, 0x80, reg_op, &mem, imm);
            }
        }
    }

    Err(format!("Cannot assemble ALU instruction: '{}'", ops_str))
}

fn assemble_test(ops_str: &str, resolver: &dyn Fn(&str) -> Option<usize>) -> Result<Vec<u8>, String> {
    let parts: Vec<&str> = ops_str.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() < 2 {
        return Err("test requires two operands".to_string());
    }
    let dst = parse_reg(parts[0]).ok_or("test destination must be register")?;
    let src = parse_reg(parts[1]);

    if let Some(src_r) = src {
        let mut bytes = Vec::new();
        let rex = make_rex(dst.size == RegSize::Qword, src_r.id >= 8, false, dst.id >= 8);
        if dst.size == RegSize::Word {
            bytes.push(0x66);
        }
        if let Some(r) = rex {
            bytes.push(r);
        }
        bytes.push(if dst.size == RegSize::Byte { 0x84 } else { 0x85 });
        bytes.push(0xC0 | ((src_r.id & 7) << 3) | (dst.id & 7));
        return Ok(bytes);
    } else if let Some(imm) = parse_int_or_hex(parts[1]).or_else(|| resolver(parts[1]).map(|a| a as i64)) {
        let mut bytes = Vec::new();
        let rex = make_rex(dst.size == RegSize::Qword, false, false, dst.id >= 8);
        if dst.size == RegSize::Word {
            bytes.push(0x66);
        }
        if let Some(r) = rex {
            bytes.push(r);
        }
        if dst.size == RegSize::Byte {
            bytes.push(0xF6);
            bytes.push(0xC0 | (dst.id & 7));
            bytes.push(imm as u8);
        } else {
            bytes.push(0xF7);
            bytes.push(0xC0 | (dst.id & 7));
            bytes.extend_from_slice(&(imm as u32).to_le_bytes());
        }
        return Ok(bytes);
    }

    Err(format!("Unsupported test operands: '{}'", ops_str))
}

fn assemble_inc_dec(reg_op: u8, ops_str: &str, resolver: &dyn Fn(&str) -> Option<usize>) -> Result<Vec<u8>, String> {
    if let Some(reg) = parse_reg(ops_str) {
        let mut bytes = Vec::new();
        let rex = make_rex(reg.size == RegSize::Qword, false, false, reg.id >= 8);
        if reg.size == RegSize::Word {
            bytes.push(0x66);
        }
        if let Some(r) = rex {
            bytes.push(r);
        }
        if reg.size == RegSize::Byte {
            bytes.push(0xFE);
        } else {
            bytes.push(0xFF);
        }
        bytes.push(0xC0 | (reg_op << 3) | (reg.id & 7));
        return Ok(bytes);
    } else if let Some(mem) = parse_mem_operand(ops_str, resolver) {
        let op = if mem.explicit_size == Some(RegSize::Byte) { 0xFE } else { 0xFF };
        return encode_mem_imm(op, 0xFE, reg_op, &mem, 0);
    }

    Err(format!("Unsupported inc/dec operand: '{}'", ops_str))
}

fn encode_modrm_insn(
    opcode_std: u8,
    opcode_byte: u8,
    reg: RegInfo,
    mem: &MemOperand,
    _mem_is_dst: bool,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();

    let is_qword = reg.size == RegSize::Qword || mem.explicit_size == Some(RegSize::Qword);
    let is_byte = reg.size == RegSize::Byte || mem.explicit_size == Some(RegSize::Byte);
    let is_word = reg.size == RegSize::Word || mem.explicit_size == Some(RegSize::Word);

    if is_word {
        bytes.push(0x66);
    }

    let b_bit = mem.base.as_ref().map(|b| b.id >= 8).unwrap_or(false);
    let x_bit = mem.index.as_ref().map(|x| x.id >= 8).unwrap_or(false);
    let r_bit = reg.id >= 8;

    let rex = make_rex(is_qword, r_bit, x_bit, b_bit);
    if let Some(r) = rex {
        bytes.push(r);
    }

    bytes.push(if is_byte { opcode_byte } else { opcode_std });

    let reg_bits = reg.id & 7;

    if mem.is_rip_relative {
        bytes.push(0x05 | (reg_bits << 3));
        bytes.extend_from_slice(&(mem.disp as i32).to_le_bytes());
        return Ok(bytes);
    }

    let base_reg = match &mem.base {
        Some(b) => b,
        None => {

            bytes.push(0x04 | (reg_bits << 3));
            bytes.push(0x25);
            bytes.extend_from_slice(&(mem.disp as i32).to_le_bytes());
            return Ok(bytes);
        }
    };

    let base_id = base_reg.id & 7;

    let needs_sib = base_id == 4 || mem.index.is_some();

    let (mod_bits, disp_size) = if mem.disp == 0 && base_id != 5 {
        (0x00, 0)
    } else if mem.disp >= -128 && mem.disp <= 127 {
        (0x40, 1)
    } else {
        (0x80, 4)
    };

    let rm_bits = if needs_sib { 4 } else { base_id };
    bytes.push(mod_bits | (reg_bits << 3) | rm_bits);

    if needs_sib {
        let scale_bits = match mem.scale {
            2 => 1,
            4 => 2,
            8 => 3,
            _ => 0,
        };
        let index_bits = mem.index.as_ref().map(|i| i.id & 7).unwrap_or(4);
        bytes.push((scale_bits << 6) | (index_bits << 3) | base_id);
    }

    if disp_size == 1 {
        bytes.push(mem.disp as u8);
    } else if disp_size == 4 {
        bytes.extend_from_slice(&(mem.disp as i32).to_le_bytes());
    }

    Ok(bytes)
}

fn encode_mem_imm(
    opcode_std: u8,
    opcode_byte: u8,
    reg_op: u8,
    mem: &MemOperand,
    imm: i64,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let is_byte = mem.explicit_size == Some(RegSize::Byte);
    let is_qword = mem.explicit_size == Some(RegSize::Qword);
    let is_word = mem.explicit_size == Some(RegSize::Word);

    if is_word {
        bytes.push(0x66);
    }

    let b_bit = mem.base.as_ref().map(|b| b.id >= 8).unwrap_or(false);
    let x_bit = mem.index.as_ref().map(|x| x.id >= 8).unwrap_or(false);

    let rex = make_rex(is_qword, false, x_bit, b_bit);
    if let Some(r) = rex {
        bytes.push(r);
    }

    let use_imm8 = !is_byte && opcode_std == 0x81 && imm >= -128 && imm <= 127;
    let actual_opcode = if is_byte {
        opcode_byte
    } else if use_imm8 {
        0x83
    } else {
        opcode_std
    };
    bytes.push(actual_opcode);

    let reg_bits = reg_op & 7;

    if mem.is_rip_relative {
        bytes.push(0x05 | (reg_bits << 3));
        bytes.extend_from_slice(&(mem.disp as i32).to_le_bytes());
    } else if let Some(base_reg) = &mem.base {
        let base_id = base_reg.id & 7;
        let needs_sib = base_id == 4 || mem.index.is_some();
        let (mod_bits, disp_size) = if mem.disp == 0 && base_id != 5 {
            (0x00, 0)
        } else if mem.disp >= -128 && mem.disp <= 127 {
            (0x40, 1)
        } else {
            (0x80, 4)
        };
        let rm_bits = if needs_sib { 4 } else { base_id };
        bytes.push(mod_bits | (reg_bits << 3) | rm_bits);

        if needs_sib {
            let scale_bits = match mem.scale { 2 => 1, 4 => 2, 8 => 3, _ => 0 };
            let index_bits = mem.index.as_ref().map(|i| i.id & 7).unwrap_or(4);
            bytes.push((scale_bits << 6) | (index_bits << 3) | base_id);
        }

        if disp_size == 1 {
            bytes.push(mem.disp as u8);
        } else if disp_size == 4 {
            bytes.extend_from_slice(&(mem.disp as i32).to_le_bytes());
        }
    } else {
        bytes.push(0x04 | (reg_bits << 3));
        bytes.push(0x25);
        bytes.extend_from_slice(&(mem.disp as i32).to_le_bytes());
    }

    if is_byte || use_imm8 {
        bytes.push(imm as u8);
    } else if is_word {
        bytes.extend_from_slice(&(imm as u16).to_le_bytes());
    } else {
        bytes.extend_from_slice(&(imm as u32).to_le_bytes());
    }

    Ok(bytes)
}

fn make_rex(w: bool, r: bool, x: bool, b: bool) -> Option<u8> {
    if w || r || x || b {
        let mut rex = 0x40;
        if w { rex |= 0x08; }
        if r { rex |= 0x04; }
        if x { rex |= 0x02; }
        if b { rex |= 0x01; }
        Some(rex)
    } else {
        None
    }
}

fn parse_db_directive(s: &str, _resolver: &dyn Fn(&str) -> Option<usize>) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut in_quote = false;
    let mut quote_char = '\'';
    let mut cur = String::new();

    for ch in s.chars() {
        if in_quote {
            if ch == quote_char {
                in_quote = false;
                out.extend(cur.as_bytes());
                cur.clear();
            } else {
                cur.push(ch);
            }
        } else if ch == '\'' || ch == '"' {
            in_quote = true;
            quote_char = ch;
        } else if ch == ',' || ch.is_whitespace() {
            let t = cur.trim();
            if !t.is_empty() {
                if let Some(val) = parse_int_or_hex(t) {
                    out.push(val as u8);
                }
                cur.clear();
            }
        } else {
            cur.push(ch);
        }
    }
    let t = cur.trim();
    if !t.is_empty() {
        if in_quote {
            out.extend(t.as_bytes());
        } else if let Some(val) = parse_int_or_hex(t) {
            out.push(val as u8);
        }
    }

    Ok(out)
}

fn parse_dw_directive(s: &str, _resolver: &dyn Fn(&str) -> Option<usize>) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for part in s.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
        let val = parse_int_or_hex(part).ok_or_else(|| format!("Invalid dw: '{}'", part))? as u16;
        out.extend_from_slice(&val.to_le_bytes());
    }
    Ok(out)
}

fn parse_dd_directive(s: &str, resolver: &dyn Fn(&str) -> Option<usize>) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for part in s.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
        let val = parse_int_or_hex(part)
            .or_else(|| resolver(part).map(|a| a as i64))
            .ok_or_else(|| format!("Invalid dd: '{}'", part))? as u32;
        out.extend_from_slice(&val.to_le_bytes());
    }
    Ok(out)
}

fn parse_dq_directive(s: &str, resolver: &dyn Fn(&str) -> Option<usize>) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for part in s.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
        let val = parse_int_or_hex(part)
            .or_else(|| resolver(part).map(|a| a as i64))
            .ok_or_else(|| format!("Invalid dq: '{}'", part))? as u64;
        out.extend_from_slice(&val.to_le_bytes());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assemble_simple_instructions() {
        let resolver = |_s: &str| None;

        assert_eq!(Assembler::assemble_line("nop", 0x1000, &resolver).unwrap(), vec![0x90]);

        assert_eq!(Assembler::assemble_line("ret", 0x1000, &resolver).unwrap(), vec![0xC3]);

        assert_eq!(Assembler::assemble_line("push rax", 0x1000, &resolver).unwrap(), vec![0x50]);

        assert_eq!(Assembler::assemble_line("push r8", 0x1000, &resolver).unwrap(), vec![0x41, 0x50]);

        assert_eq!(Assembler::assemble_line("pop rbx", 0x1000, &resolver).unwrap(), vec![0x5B]);

        let mov_imm64 = Assembler::assemble_line("mov rax, 0x1234567890ABCDEF", 0x1000, &resolver).unwrap();
        assert_eq!(mov_imm64[0..2], [0x48, 0xB8]);
        assert_eq!(mov_imm64[2..], 0x1234567890ABCDEFu64.to_le_bytes());

        let mov_mem_imm = Assembler::assemble_line("mov [rax+0x10], 0", 0x1000, &resolver).unwrap();
        assert_eq!(mov_mem_imm, vec![0xC7, 0x40, 0x10, 0x00, 0x00, 0x00, 0x00]);

        let add_mem_imm = Assembler::assemble_line("add [rbx], 5", 0x1000, &resolver).unwrap();
        assert_eq!(add_mem_imm, vec![0x83, 0x03, 0x05]);
    }

    #[test]
    fn test_assemble_branches_and_labels() {
        let sym_table = |s: &str| {
            if s == "target_label" {
                Some(0x2000)
            } else {
                None
            }
        };

        let short_jmp = Assembler::assemble_line("jmp short target_label", 0x1FFD, &sym_table).unwrap();
        assert_eq!(short_jmp, vec![0xEB, 0x01]);

        let near_jmp = Assembler::assemble_line("jmp target_label", 0x1000, &sym_table).unwrap();
        assert_eq!(near_jmp[0], 0xE9);
        assert_eq!(near_jmp.len(), 5);

        let jmp_rax = Assembler::assemble_line("jmp rax", 0x1000, &sym_table).unwrap();
        assert_eq!(jmp_rax, vec![0xFF, 0xE0]);

        let call_r8 = Assembler::assemble_line("call r8", 0x1000, &sym_table).unwrap();
        assert_eq!(call_r8, vec![0x41, 0xFF, 0xD0]);

        let db = Assembler::assemble_line("db 0x90, 0x90, 'OK', 0", 0x1000, &sym_table).unwrap();
        assert_eq!(db, vec![0x90, 0x90, b'O', b'K', 0]);
    }
}
