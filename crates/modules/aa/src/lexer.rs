//! Pre-processador e tokenizador leve para scripts Auto Assembler.
//!
//! O AA do Cheat Engine e orientado a linhas: cada linha e um comentario,
//! um cabecalho de secao `[ENABLE]`/`[DISABLE]`, uma diretiva (ex.
//! `alloc(mem, 1024)`), um `label`, uma linha de assembly ou um label de
//! destino `symbol:`. Este modulo:
//!
//! * remove comentarios `//linha` e `{bloco}`,
//! * preserva numero de linha original para mensagens de erro,
//! * expoe uma tokenizacao fina (`Token`) que o parser usa quando precisa
//!   decompor uma diretiva.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub line: usize,
    pub col: usize,
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "linha {}, col {}", self.line, self.col)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    Ident(String),
    /// Numero ja parseado. `wide` sinaliza immediate que nao cabe em 32 bits —
    /// requisito importante para instrucoes como `mov rax, 0xDEADBEEFCAFEBABE`.
    Number { value: u64, wide: bool },
    Str(String),
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Colon,
    Plus,
    Minus,
    Star,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

/// Linha logica apos stripping de comentarios.
#[derive(Debug, Clone)]
pub struct Line {
    pub line_no: usize,
    pub text: String,
}

/// Tira comentarios `//...` e `{...}` preservando numeracao de linha.
/// Blocos `{...}` podem ser multilinha. Linhas em branco sao mantidas (com
/// texto vazio) para que o parser possa referenciar o numero original.
pub fn strip_comments(src: &str) -> Vec<Line> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut line_no = 1usize;
    let mut in_block = false;
    let bytes = src.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];

        if in_block {
            if b == b'}' {
                in_block = false;
            } else if b == b'\n' {
                out.push(Line {
                    line_no,
                    text: std::mem::take(&mut buf),
                });
                line_no += 1;
            }
            i += 1;
            continue;
        }

        match b {
            b'\n' => {
                out.push(Line {
                    line_no,
                    text: std::mem::take(&mut buf),
                });
                line_no += 1;
                i += 1;
            }
            b'/' if bytes.get(i + 1).copied() == Some(b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'{' => {
                in_block = true;
                i += 1;
            }
            b'"' => {
                // mantem string literal intacta
                buf.push('"');
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' && bytes[i] != b'\n' {
                    buf.push(bytes[i] as char);
                    i += 1;
                }
                if i < bytes.len() && bytes[i] == b'"' {
                    buf.push('"');
                    i += 1;
                }
            }
            _ => {
                buf.push(b as char);
                i += 1;
            }
        }
    }

    if !buf.is_empty() || out.is_empty() {
        out.push(Line {
            line_no,
            text: buf,
        });
    }
    out
}

/// Tokeniza uma unica linha (ja sem comentarios) para o parser decompor
/// uma diretiva como `alloc(mem, 2048, "game.exe"+0x1234)`.
pub fn tokenize_line(line_no: usize, text: &str) -> Result<Vec<Token>, LexError> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut col = 1usize;

    let bump = |i: &mut usize, col: &mut usize| {
        *i += 1;
        *col += 1;
    };

    while i < bytes.len() {
        let span = Span { line: line_no, col };
        let b = bytes[i];
        match b {
            b' ' | b'\t' | b'\r' => bump(&mut i, &mut col),
            b'(' => {
                out.push(Token {
                    kind: TokenKind::LParen,
                    span,
                });
                bump(&mut i, &mut col);
            }
            b')' => {
                out.push(Token {
                    kind: TokenKind::RParen,
                    span,
                });
                bump(&mut i, &mut col);
            }
            b',' => {
                out.push(Token {
                    kind: TokenKind::Comma,
                    span,
                });
                bump(&mut i, &mut col);
            }
            b':' => {
                out.push(Token {
                    kind: TokenKind::Colon,
                    span,
                });
                bump(&mut i, &mut col);
            }
            b'+' => {
                out.push(Token {
                    kind: TokenKind::Plus,
                    span,
                });
                bump(&mut i, &mut col);
            }
            b'-' => {
                out.push(Token {
                    kind: TokenKind::Minus,
                    span,
                });
                bump(&mut i, &mut col);
            }
            b'[' => {
                out.push(Token {
                    kind: TokenKind::LBracket,
                    span,
                });
                bump(&mut i, &mut col);
            }
            b']' => {
                out.push(Token {
                    kind: TokenKind::RBracket,
                    span,
                });
                bump(&mut i, &mut col);
            }
            b'*' => {
                out.push(Token {
                    kind: TokenKind::Star,
                    span,
                });
                bump(&mut i, &mut col);
            }
            b'"' => {
                i += 1;
                col += 1;
                let start = i;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += 1;
                    col += 1;
                }
                if i >= bytes.len() {
                    return Err(LexError {
                        msg: "string nao terminada".into(),
                        span,
                    });
                }
                let s = String::from_utf8_lossy(&bytes[start..i]).to_string();
                out.push(Token {
                    kind: TokenKind::Str(s),
                    span,
                });
                i += 1;
                col += 1;
            }
            b'$' => {
                // $DEADBEEF — hex ao estilo Pascal
                i += 1;
                col += 1;
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                    i += 1;
                    col += 1;
                }
                let txt = &text[start..i];
                if txt.is_empty() {
                    return Err(LexError {
                        msg: "literal hex vazio apos $".into(),
                        span,
                    });
                }
                let value = u64::from_str_radix(txt, 16).map_err(|_| LexError {
                    msg: format!("hex invalido '{}'", txt),
                    span,
                })?;
                out.push(Token {
                    kind: TokenKind::Number {
                        value,
                        wide: txt.len() > 8,
                    },
                    span,
                });
            }
            b'0' if matches!(bytes.get(i + 1).copied(), Some(b'x') | Some(b'X')) => {
                i += 2;
                col += 2;
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                    i += 1;
                    col += 1;
                }
                let txt = &text[start..i];
                let value = u64::from_str_radix(txt, 16).map_err(|_| LexError {
                    msg: format!("hex invalido '0x{}'", txt),
                    span,
                })?;
                out.push(Token {
                    kind: TokenKind::Number {
                        value,
                        wide: txt.len() > 8,
                    },
                    span,
                });
            }
            d if d.is_ascii_digit() => {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                    i += 1;
                    col += 1;
                }
                let txt = &text[start..i];
                // Se so tem digitos decimais, trata como decimal; se contem
                // caracteres hex, assume hex "nu" (padrao AA/CE).
                let is_decimal = txt.chars().all(|c| c.is_ascii_digit());
                let (value, wide) = if is_decimal {
                    let v: u64 = txt.parse().map_err(|_| LexError {
                        msg: format!("decimal invalido '{}'", txt),
                        span,
                    })?;
                    (v, v > u32::MAX as u64)
                } else {
                    let v = u64::from_str_radix(txt, 16).map_err(|_| LexError {
                        msg: format!("hex invalido '{}'", txt),
                        span,
                    })?;
                    (v, txt.len() > 8)
                };
                out.push(Token {
                    kind: TokenKind::Number { value, wide },
                    span,
                });
            }
            c if c.is_ascii_alphabetic() || c == b'_' || c == b'.' || c == b'@' => {
                let start = i;
                while i < bytes.len() {
                    let cc = bytes[i];
                    if cc.is_ascii_alphanumeric()
                        || cc == b'_'
                        || cc == b'.'
                        || cc == b'@'
                    {
                        i += 1;
                        col += 1;
                    } else {
                        break;
                    }
                }
                let name = text[start..i].to_string();
                out.push(Token {
                    kind: TokenKind::Ident(name),
                    span,
                });
            }
            _ => {
                return Err(LexError {
                    msg: format!("caractere inesperado '{}'", b as char),
                    span,
                });
            }
        }
    }

    Ok(out)
}

#[derive(Debug, Clone)]
pub struct LexError {
    pub msg: String,
    pub span: Span,
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "erro lexico em {}: {}", self.span, self.msg)
    }
}

impl std::error::Error for LexError {}

/// Compatibilidade com testes legados que ainda referenciam `Lexer::new(..).tokenize()`.
pub struct Lexer<'a> {
    src: &'a str,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a str) -> Self {
        Self { src }
    }

    pub fn tokenize(self) -> Result<Vec<Token>, LexError> {
        let mut all = Vec::new();
        for line in strip_comments(self.src) {
            all.extend(tokenize_line(line.line_no, &line.text)?);
        }
        Ok(all)
    }
}
