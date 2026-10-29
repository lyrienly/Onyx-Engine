pub mod analyzer;
pub mod lexer;
pub mod parser;

pub use analyzer::{analyze, AaError};
pub use lexer::{Lexer, Span, Token, TokenKind};
pub use parser::{parse_script, Script, Section, SectionKind, Statement};
