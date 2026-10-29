use std::collections::HashSet;
use std::fmt;

use crate::lexer::Span;
use crate::parser::{Script, Statement};

#[derive(Debug, Clone)]
pub struct AaError {
    pub msg: String,
    pub span: Span,
}

impl fmt::Display for AaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "erro AA em {}: {}", self.span, self.msg)
    }
}

impl std::error::Error for AaError {}

const REGISTERS: &[&str] = &[
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "rip", "r8", "r9", "r10", "r11", "r12",
    "r13", "r14", "r15", "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "r8d", "r9d",
    "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", "ax", "bx", "cx", "dx", "si", "di", "sp", "bp",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w", "al", "bl", "cl", "dl", "ah",
    "bh", "ch", "dh", "sil", "dil", "spl", "bpl", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b",
    "r14b", "r15b", "cs", "ds", "es", "fs", "gs", "ss", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4",
    "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
    "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
];

const DIRECTIVES: &[&str] = &[
    "byte",
    "word",
    "dword",
    "qword",
    "ptr",
    "db",
    "dw",
    "dd",
    "dq",
    "newmem",
    "originalcode",
    "exit",
    "code",
    "injectionpoint",
    "readmem",
    "reassemble",
];

const MNEMONICS: &[&str] = &[
    "mov",
    "lea",
    "add",
    "sub",
    "mul",
    "imul",
    "div",
    "idiv",
    "and",
    "or",
    "xor",
    "not",
    "neg",
    "shl",
    "shr",
    "sar",
    "sal",
    "rol",
    "ror",
    "cmp",
    "test",
    "jmp",
    "je",
    "jne",
    "jz",
    "jnz",
    "jl",
    "jg",
    "jle",
    "jge",
    "ja",
    "jae",
    "jb",
    "jbe",
    "jc",
    "jnc",
    "jo",
    "jno",
    "js",
    "jns",
    "call",
    "ret",
    "push",
    "pop",
    "nop",
    "int",
    "int3",
    "iret",
    "movsb",
    "movsw",
    "movsd",
    "movsq",
    "rep",
    "repne",
    "repe",
    "cld",
    "std",
    "movss",
    "movsd",
    "movaps",
    "movups",
    "addss",
    "subss",
    "mulss",
    "divss",
    "cvtsi2ss",
    "cvttss2si",
    "ucomiss",
    "pushfq",
    "popfq",
    "cmc",
    "clc",
    "stc",
    "cpuid",
    "rdtsc",
    "cli",
    "sti",
    "hlt",
    "xchg",
    "cmpxchg",
    "bswap",
    "lock",
];

fn is_known(word_lc: &str) -> bool {
    REGISTERS.contains(&word_lc) || DIRECTIVES.contains(&word_lc) || MNEMONICS.contains(&word_lc)
}

pub fn analyze(script: &Script) -> Result<(), AaError> {
    let mut symbols: HashSet<String> = HashSet::new();

    for stmt in &script.preamble {
        collect_symbol(stmt, &mut symbols);
    }

    for section in &script.sections {
        for stmt in &section.statements {
            collect_symbol(stmt, &mut symbols);
        }

        for stmt in &section.statements {
            if let Statement::LabelTarget { name, .. } = stmt {
                symbols.insert(name.clone());
            }
        }

        for stmt in &section.statements {
            match stmt {
                Statement::Assembly { line, span } => {
                    validate_assembly(line, *span, &symbols)?;
                }
                Statement::RegisterSymbol { name, span }
                | Statement::UnregisterSymbol { name, span }
                | Statement::Dealloc { name, span }
                    if !symbols.contains(name) =>
                {
                    return Err(AaError {
                        msg: format!(
                            "simbolo '{}' nao foi declarado antes de ser referenciado",
                            name
                        ),
                        span: *span,
                    });
                }
                _ => {}
            }
        }
    }

    Ok(())
}

fn collect_symbol(stmt: &Statement, out: &mut HashSet<String>) {
    match stmt {
        Statement::Alloc { symbol, .. } => {
            out.insert(symbol.clone());
        }
        Statement::Label { name, .. }
        | Statement::LabelTarget { name, .. }
        | Statement::RegisterSymbol { name, .. } => {
            out.insert(name.clone());
        }
        Statement::AobScanModule { symbol, .. } | Statement::AobScan { symbol, .. } => {
            out.insert(symbol.clone());
        }
        Statement::Define { name, .. } => {
            out.insert(name.clone());
        }
        _ => {}
    }
}

fn validate_assembly(line: &str, span: Span, symbols: &HashSet<String>) -> Result<(), AaError> {
    let mut words = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];

        if c == b'0' && matches!(bytes.get(i + 1).copied(), Some(b'x') | Some(b'X')) {
            i += 2;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            continue;
        }
        if c == b'$' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            continue;
        }

        if c == b'"' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }
        if c.is_ascii_digit() {
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            continue;
        }
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < bytes.len() {
                let cc = bytes[i];
                if cc.is_ascii_alphanumeric() || cc == b'_' {
                    i += 1;
                } else {
                    break;
                }
            }
            words.push(line[start..i].to_string());
        } else {
            i += 1;
        }
    }
    if words.is_empty() {
        return Ok(());
    }

    for w in &words[1..] {
        let lc = w.to_ascii_lowercase();
        if is_known(&lc) {
            continue;
        }

        if w.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        if symbols.contains(w) {
            continue;
        }
        return Err(AaError {
            msg: format!("simbolo '{}' usado em assembly nao foi declarado", w),
            span,
        });
    }
    Ok(())
}
