use std::os::raw::c_char;

use onyx_aa::{analyze, parse_script, Script, Section, SectionKind, Statement};
use serde_json::{json, Value};

use crate::api::abi_util::{
    cstr_to_str, guard, string_to_c, ERR_INTERNAL, ERR_INVALID_UTF8, ERR_NULL, OK,
};

fn section_kind_to_str(k: &SectionKind) -> Value {
    match k {
        SectionKind::Enable => json!("Enable"),
        SectionKind::Disable => json!("Disable"),
        SectionKind::Other(s) => json!({ "Other": s }),
    }
}

fn stmt_to_json(s: &Statement) -> Value {
    match s {
        Statement::Alloc {
            symbol,
            size,
            near_addr,
            span,
        } => json!({
            "kind": "Alloc", "symbol": symbol, "size": size, "near": near_addr,
            "line": span.line, "col": span.col,
        }),
        Statement::Label { name, span } => json!({
            "kind": "Label", "name": name, "line": span.line, "col": span.col,
        }),
        Statement::AobScanModule {
            symbol,
            module,
            pattern,
            span,
        } => json!({
            "kind": "AobScanModule", "symbol": symbol, "module": module,
            "pattern": pattern, "line": span.line, "col": span.col,
        }),
        Statement::AobScan {
            symbol,
            pattern,
            span,
        } => json!({
            "kind": "AobScan", "symbol": symbol, "pattern": pattern,
            "line": span.line, "col": span.col,
        }),
        Statement::Assert {
            address,
            bytes,
            span,
        } => json!({
            "kind": "Assert", "address": address, "bytes": bytes,
            "line": span.line, "col": span.col,
        }),
        Statement::RegisterSymbol { name, span } => json!({
            "kind": "RegisterSymbol", "name": name, "line": span.line, "col": span.col,
        }),
        Statement::UnregisterSymbol { name, span } => json!({
            "kind": "UnregisterSymbol", "name": name, "line": span.line, "col": span.col,
        }),
        Statement::Dealloc { name, span } => json!({
            "kind": "Dealloc", "name": name, "line": span.line, "col": span.col,
        }),
        Statement::Define { name, value, span } => json!({
            "kind": "Define", "name": name, "value": value, "line": span.line, "col": span.col,
        }),
        Statement::Include { path, span } => json!({
            "kind": "Include", "path": path, "line": span.line, "col": span.col,
        }),
        Statement::LabelTarget { name, span } => json!({
            "kind": "LabelTarget", "name": name, "line": span.line, "col": span.col,
        }),
        Statement::Assembly { line, span } => json!({
            "kind": "Assembly", "line": line, "src_line": span.line, "col": span.col,
        }),
        Statement::RawBlock { text, span } => json!({
            "kind": "RawBlock", "text": text, "line": span.line, "col": span.col,
        }),
    }
}

fn section_to_json(s: &Section) -> Value {
    json!({
        "kind": section_kind_to_str(&s.kind),
        "line": s.span.line,
        "col": s.span.col,
        "statements": s.statements.iter().map(stmt_to_json).collect::<Vec<_>>(),
    })
}

fn script_to_json(s: &Script) -> Value {
    json!({
        "preamble": s.preamble.iter().map(stmt_to_json).collect::<Vec<_>>(),
        "sections": s.sections.iter().map(section_to_json).collect::<Vec<_>>(),
    })
}

#[no_mangle]
pub unsafe extern "C" fn onyx_aa_parse(src: *const c_char, out_json: *mut *mut c_char) -> i32 {
    guard(|| {
        if src.is_null() || out_json.is_null() {
            return ERR_NULL;
        }
        let text = match cstr_to_str(src) {
            Some(s) => s,
            None => return ERR_INVALID_UTF8,
        };
        match parse_script(text) {
            Ok(script) => {
                let v = script_to_json(&script);
                let s = v.to_string();
                let ptr = string_to_c(s);
                if ptr.is_null() {
                    return ERR_INTERNAL;
                }
                *out_json = ptr;
                OK
            }
            Err(e) => {
                let v = json!({ "error": e.msg, "line": e.span.line, "col": e.span.col });
                let ptr = string_to_c(v.to_string());
                if !ptr.is_null() {
                    *out_json = ptr;
                }
                1
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn onyx_aa_analyze(src: *const c_char, out_err: *mut *mut c_char) -> i32 {
    guard(|| {
        if src.is_null() {
            return ERR_NULL;
        }
        let text = match cstr_to_str(src) {
            Some(s) => s,
            None => return ERR_INVALID_UTF8,
        };
        let script = match parse_script(text) {
            Ok(s) => s,
            Err(e) => {
                if !out_err.is_null() {
                    let msg = format!(
                        "parse: {} (linha {}, col {})",
                        e.msg, e.span.line, e.span.col
                    );
                    *out_err = string_to_c(msg);
                }
                return 1;
            }
        };
        match analyze(&script) {
            Ok(()) => OK,
            Err(e) => {
                if !out_err.is_null() {
                    let msg = format!(
                        "analyze: {} (linha {}, col {})",
                        e.msg, e.span.line, e.span.col
                    );
                    *out_err = string_to_c(msg);
                }
                2
            }
        }
    })
}
