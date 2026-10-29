pub mod lexer;
pub mod parser;
pub mod analyzer;

pub use lexer::{Token, TokenKind, Lexer, Span};
pub use parser::{Script, Section, SectionKind, Statement, parse_script};
pub use analyzer::{analyze, AaError};
