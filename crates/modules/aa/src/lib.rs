//! Parser e analisador de scripts Auto Assembler (AA) do Onyx.
//!
//! Esse modulo processa a sintaxe de scripts AA ja consolidada no Cheat Engine
//! (https://wiki.cheatengine.org/index.php?title=Auto_Assembler) com foco em
//! x86-64: suporta blocos `[ENABLE]`/`[DISABLE]`, diretivas `alloc`, `label`,
//! `aobscanmodule`, `assert`, `registersymbol`, `dealloc`, `unregistersymbol`,
//! macros `define`, inclusao via `include`, alem de instrucoes assembly livres
//! com registradores de 64 bits (rax..r15) e immediates de 64 bits.
//!
//! A geracao final de bytecode nao faz parte deste modulo — o pipeline aqui
//! termina em uma `Script` ja validada, pronta para ser consumida pelo
//! assembler nativo.

pub mod lexer;
pub mod parser;
pub mod analyzer;

pub use lexer::{Token, TokenKind, Lexer, Span};
pub use parser::{Script, Section, SectionKind, Statement, parse_script};
pub use analyzer::{analyze, AaError};
