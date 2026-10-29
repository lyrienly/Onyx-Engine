//! Parser de scripts Auto Assembler (AA).
//!
//! Entrada: fonte do script como string.
//! Saida: AST `Script` com secoes `[ENABLE]`/`[DISABLE]` e lista de
//! `Statement` em cada uma. Em caso de erro, retorna um `AaError` com
//! linha+coluna originais.

use crate::analyzer::AaError;
use crate::lexer::{strip_comments, tokenize_line, Span};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SectionKind {
    Enable,
    Disable,
    Other(String),
}

#[derive(Debug, Clone)]
pub struct Section {
    pub kind: SectionKind,
    pub statements: Vec<Statement>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct Script {
    pub sections: Vec<Section>,
    /// Statements fora de qualquer secao (preamble). O Cheat Engine aceita
    /// algumas diretivas globais, como `define` e `include`, antes de
    /// `[ENABLE]`.
    pub preamble: Vec<Statement>,
}

#[derive(Debug, Clone)]
pub enum Statement {
    /// `alloc(symbol, size)` ou `alloc(symbol, size, nearAddress)`.
    Alloc {
        symbol: String,
        size: u64,
        near_addr: Option<String>,
        span: Span,
    },
    /// `label(name)` — reserva um simbolo que sera endereco de uma linha.
    Label { name: String, span: Span },
    /// `aobscanmodule(symbol, module, pattern)` — nome mantido como ident/string.
    AobScanModule {
        symbol: String,
        module: String,
        pattern: String,
        span: Span,
    },
    /// `aobscan(symbol, pattern)`.
    AobScan {
        symbol: String,
        pattern: String,
        span: Span,
    },
    /// `assert(address, bytes)` — valida bytes antes de injetar.
    Assert {
        address: String,
        bytes: String,
        span: Span,
    },
    /// `registersymbol(symbol)`.
    RegisterSymbol { name: String, span: Span },
    /// `unregistersymbol(symbol)`.
    UnregisterSymbol { name: String, span: Span },
    /// `dealloc(symbol)`.
    Dealloc { name: String, span: Span },
    /// `define(name, value)` — macro de substituicao textual.
    Define {
        name: String,
        value: String,
        span: Span,
    },
    /// `include "arquivo.aa"` ou `include(arquivo.aa)`.
    Include { path: String, span: Span },
    /// Definicao de label de destino: `symbol:` em uma linha propria.
    LabelTarget { name: String, span: Span },
    /// Linha de assembly bruta (mov, jmp, nop, db ...). Pos-expansao de macros.
    Assembly { line: String, span: Span },
    /// Bloco literal entre `{...}` que o parser nao decompos (reservado).
    RawBlock { text: String, span: Span },
}

impl Statement {
    pub fn span(&self) -> Span {
        match self {
            Statement::Alloc { span, .. }
            | Statement::Label { span, .. }
            | Statement::AobScanModule { span, .. }
            | Statement::AobScan { span, .. }
            | Statement::Assert { span, .. }
            | Statement::RegisterSymbol { span, .. }
            | Statement::UnregisterSymbol { span, .. }
            | Statement::Dealloc { span, .. }
            | Statement::Define { span, .. }
            | Statement::Include { span, .. }
            | Statement::LabelTarget { span, .. }
            | Statement::Assembly { span, .. }
            | Statement::RawBlock { span, .. } => *span,
        }
    }
}

/// Ponto de entrada principal.
pub fn parse_script(source: &str) -> Result<Script, AaError> {
    let lines = strip_comments(source);

    // Pass 1: coleta `define` para substituicao textual simples.
    let mut defines: Vec<(String, String)> = Vec::new();
    for l in &lines {
        if let Some(d) = try_capture_define(l.line_no, &l.text)? {
            defines.push(d);
        }
    }

    // Pass 2: parse em secoes, aplicando defines no corpo de assembly.
    let mut script = Script {
        sections: Vec::new(),
        preamble: Vec::new(),
    };
    let mut current: Option<Section> = None;

    for l in &lines {
        let text = l.text.trim();
        if text.is_empty() {
            continue;
        }

        // Cabecalho de secao `[ENABLE]`/`[DISABLE]`/`[OTHER]`.
        if text.starts_with('[') && text.ends_with(']') {
            if let Some(section) = current.take() {
                script.sections.push(section);
            }
            let inner = text[1..text.len() - 1].trim();
            let kind = match inner.to_ascii_uppercase().as_str() {
                "ENABLE" => SectionKind::Enable,
                "DISABLE" => SectionKind::Disable,
                other => SectionKind::Other(other.to_string()),
            };
            current = Some(Section {
                kind,
                statements: Vec::new(),
                span: Span {
                    line: l.line_no,
                    col: 1,
                },
            });
            continue;
        }

        let stmt = parse_statement(l.line_no, text, &defines)?;

        match &mut current {
            Some(section) => section.statements.push(stmt),
            None => script.preamble.push(stmt),
        }
    }

    if let Some(section) = current.take() {
        script.sections.push(section);
    }

    Ok(script)
}

fn try_capture_define(line_no: usize, text: &str) -> Result<Option<(String, String)>, AaError> {
    let trimmed = text.trim();
    if !trimmed.to_ascii_lowercase().starts_with("define") {
        return Ok(None);
    }
    // Duas sintaxes aceitas no CE:
    //   define(name, value)
    //   define name value
    let rest = &trimmed[6..];
    let rest_trim = rest.trim_start();

    if let Some(stripped) = rest_trim.strip_prefix('(') {
        let end = stripped.rfind(')').ok_or_else(|| AaError {
            msg: "define(..) sem parentese de fechamento".into(),
            span: Span { line: line_no, col: 1 },
        })?;
        let inside = &stripped[..end];
        let (name, value) = split_pair(inside).ok_or_else(|| AaError {
            msg: "define(..) espera 'nome, valor'".into(),
            span: Span { line: line_no, col: 1 },
        })?;
        return Ok(Some((name.trim().to_string(), value.trim().to_string())));
    }

    // forma `define NAME VALOR`
    let mut parts = rest_trim.splitn(2, char::is_whitespace);
    let name = parts.next().unwrap_or("").trim();
    let value = parts.next().unwrap_or("").trim();
    if name.is_empty() || value.is_empty() {
        return Ok(None);
    }
    Ok(Some((name.to_string(), value.to_string())))
}

fn split_pair(s: &str) -> Option<(&str, &str)> {
    // Divide no primeiro `,` em nivel 0 (sem respeitar aninhamento, suficiente aqui).
    let mut depth = 0i32;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => return Some((&s[..i], &s[i + 1..])),
            _ => {}
        }
    }
    None
}

fn parse_statement(
    line_no: usize,
    text: &str,
    defines: &[(String, String)],
) -> Result<Statement, AaError> {
    let span = Span { line: line_no, col: 1 };

    // Label target: "symbol:" sozinho na linha.
    if let Some(name) = text.strip_suffix(':') {
        let n = name.trim();
        if is_identifier(n) {
            return Ok(Statement::LabelTarget {
                name: n.to_string(),
                span,
            });
        }
    }

    let first_word_end = text
        .find(|c: char| c.is_whitespace() || c == '(')
        .unwrap_or(text.len());
    let head_lc = text[..first_word_end].to_ascii_lowercase();

    // `include "arquivo"` ou `include(arquivo)`.
    if head_lc == "include" {
        let rest = text[first_word_end..].trim();
        let path = if let Some(stripped) = rest.strip_prefix('(') {
            let end = stripped.rfind(')').ok_or_else(|| AaError {
                msg: "include(..) sem parentese de fechamento".into(),
                span,
            })?;
            stripped[..end].trim().trim_matches('"').to_string()
        } else {
            rest.trim_matches('"').to_string()
        };
        return Ok(Statement::Include { path, span });
    }

    // Diretivas no formato `nome(args)`.
    if text.ends_with(')') {
        if let Some(open) = text.find('(') {
            let head = text[..open].trim().to_ascii_lowercase();
            let inside = &text[open + 1..text.len() - 1];
            match head.as_str() {
                "alloc" => return parse_alloc(inside, span),
                "label" => {
                    let name = inside.trim();
                    if !is_identifier(name) {
                        return Err(AaError {
                            msg: format!("label() espera identificador, recebeu '{}'", name),
                            span,
                        });
                    }
                    return Ok(Statement::Label {
                        name: name.to_string(),
                        span,
                    });
                }
                "aobscanmodule" => return parse_aobscan_module(inside, span),
                "aobscan" => return parse_aobscan(inside, span),
                "aobscanregion" => return parse_aobscan(inside, span),
                "assert" => return parse_assert(inside, span),
                "registersymbol" => {
                    let name = inside.trim();
                    if !is_identifier(name) {
                        return Err(AaError {
                            msg: "registersymbol() espera um identificador".into(),
                            span,
                        });
                    }
                    return Ok(Statement::RegisterSymbol {
                        name: name.to_string(),
                        span,
                    });
                }
                "unregistersymbol" => {
                    let name = inside.trim();
                    if !is_identifier(name) {
                        return Err(AaError {
                            msg: "unregistersymbol() espera um identificador".into(),
                            span,
                        });
                    }
                    return Ok(Statement::UnregisterSymbol {
                        name: name.to_string(),
                        span,
                    });
                }
                "dealloc" => {
                    let name = inside.trim();
                    if !is_identifier(name) {
                        return Err(AaError {
                            msg: "dealloc() espera um identificador".into(),
                            span,
                        });
                    }
                    return Ok(Statement::Dealloc {
                        name: name.to_string(),
                        span,
                    });
                }
                "define" => {
                    let (name, value) = split_pair(inside).ok_or_else(|| AaError {
                        msg: "define(..) espera 'nome, valor'".into(),
                        span,
                    })?;
                    return Ok(Statement::Define {
                        name: name.trim().to_string(),
                        value: value.trim().to_string(),
                        span,
                    });
                }
                _ => { /* cai para assembly com validacao de tokens */ }
            }
        }
    }

    // Caso contrario, trata como linha de assembly apos expansao de defines.
    let expanded = expand_defines(text, defines);
    // Valida sintaxe lexica para capturar numeros/strings mal formados cedo.
    let _ = tokenize_line(line_no, &expanded).map_err(|e| AaError {
        msg: e.msg,
        span: e.span,
    })?;
    Ok(Statement::Assembly {
        line: expanded,
        span,
    })
}

fn parse_alloc(inside: &str, span: Span) -> Result<Statement, AaError> {
    let parts = split_args(inside);
    if parts.len() < 2 || parts.len() > 3 {
        return Err(AaError {
            msg: "alloc espera 2 ou 3 argumentos: (symbol, size[, near])".into(),
            span,
        });
    }
    let symbol = parts[0].trim().to_string();
    if !is_identifier(&symbol) {
        return Err(AaError {
            msg: format!("alloc: '{}' nao e um identificador valido", symbol),
            span,
        });
    }
    let size_tok = parts[1].trim();
    let size = parse_number(size_tok).ok_or_else(|| AaError {
        msg: format!("alloc: tamanho invalido '{}'", size_tok),
        span,
    })?;
    let near_addr = parts.get(2).map(|s| s.trim().to_string());
    Ok(Statement::Alloc {
        symbol,
        size,
        near_addr,
        span,
    })
}

fn parse_aobscan_module(inside: &str, span: Span) -> Result<Statement, AaError> {
    let parts = split_args(inside);
    if parts.len() != 3 {
        return Err(AaError {
            msg: "aobscanmodule espera 3 argumentos: (symbol, module, pattern)".into(),
            span,
        });
    }
    Ok(Statement::AobScanModule {
        symbol: parts[0].trim().to_string(),
        module: parts[1].trim().trim_matches('"').to_string(),
        pattern: parts[2].trim().to_string(),
        span,
    })
}

fn parse_aobscan(inside: &str, span: Span) -> Result<Statement, AaError> {
    let parts = split_args(inside);
    if parts.len() < 2 {
        return Err(AaError {
            msg: "aobscan espera (symbol, pattern)".into(),
            span,
        });
    }
    Ok(Statement::AobScan {
        symbol: parts[0].trim().to_string(),
        pattern: parts.last().unwrap().trim().to_string(),
        span,
    })
}

fn parse_assert(inside: &str, span: Span) -> Result<Statement, AaError> {
    let parts = split_args(inside);
    if parts.len() != 2 {
        return Err(AaError {
            msg: "assert espera (endereco, bytes)".into(),
            span,
        });
    }
    Ok(Statement::Assert {
        address: parts[0].trim().to_string(),
        bytes: parts[1].trim().to_string(),
        span,
    })
}

fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut depth = 0i32;
    let mut in_str = false;
    for c in s.chars() {
        match c {
            '"' => {
                in_str = !in_str;
                buf.push(c);
            }
            '(' if !in_str => {
                depth += 1;
                buf.push(c);
            }
            ')' if !in_str => {
                depth -= 1;
                buf.push(c);
            }
            ',' if depth == 0 && !in_str => {
                out.push(std::mem::take(&mut buf));
            }
            _ => buf.push(c),
        }
    }
    if !buf.trim().is_empty() {
        out.push(buf);
    }
    out
}

fn parse_number(text: &str) -> Option<u64> {
    let t = text.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if let Some(hex) = t.strip_prefix('$') {
        u64::from_str_radix(hex, 16).ok()
    } else if t.chars().all(|c| c.is_ascii_digit()) {
        t.parse().ok()
    } else if t.chars().all(|c| c.is_ascii_hexdigit()) {
        // AA aceita hex "nu" sem prefixo. Usamos a convencao de so aceitar
        // dessa forma quando ha pelo menos um caractere nao-decimal, para
        // nao ambiguar `1024`.
        u64::from_str_radix(t, 16).ok()
    } else {
        None
    }
}

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Expansao textual de `define`. Case-sensitive, substituicao de palavra
/// inteira (nao substitui dentro de identificadores maiores).
pub fn expand_defines(line: &str, defines: &[(String, String)]) -> String {
    if defines.is_empty() {
        return line.to_string();
    }
    let mut out = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0usize;

    'outer: while i < bytes.len() {
        let c = bytes[i];
        let is_word_start = c.is_ascii_alphabetic() || c == b'_';
        if is_word_start {
            let start = i;
            while i < bytes.len() {
                let cc = bytes[i];
                if cc.is_ascii_alphanumeric() || cc == b'_' {
                    i += 1;
                } else {
                    break;
                }
            }
            let word = &line[start..i];
            for (name, value) in defines {
                if word == name {
                    out.push_str(value);
                    continue 'outer;
                }
            }
            out.push_str(word);
        } else {
            out.push(c as char);
            i += 1;
        }
    }
    out
}
