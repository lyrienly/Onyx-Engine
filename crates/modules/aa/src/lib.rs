pub mod analyzer;
pub mod lexer;
pub mod parser;

pub use analyzer::{analyze, AaError};
pub use lexer::{Lexer, Span, Token, TokenKind};
pub use parser::{parse_script, Script, Section, SectionKind, Statement};

#[no_mangle]
pub unsafe extern "C" fn onyx_aa_version() -> u32 {
    0x010000
}

#[no_mangle]
pub unsafe extern "C" fn onyx_aa_validate_script(script_ptr: *const u8, len: usize) -> i32 {
    if script_ptr.is_null() || len == 0 {
        return 0;
    }
    let slice = std::slice::from_raw_parts(script_ptr, len);
    if let Ok(text) = std::str::from_utf8(slice) {
        match parse_script(text) {
            Ok(script) => match analyze(&script) {
                Ok(_) => 1,
                Err(_) => 0,
            },
            Err(_) => 0,
        }
    } else {
        0
    }
}
