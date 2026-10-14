// language: Rust, file: autoassembler.rs, target: Windows 11, MSVC
// Cheat Engine Auto Assembler (AA) script parser and execution engine

use std::collections::HashMap;
use crate::hook::make_absolute_jmp_64;
use crate::process::Process;
use crate::scanner::{ScanCondition, ScanValue, Scanner, ValType};
use crate::symbol::SymbolResolver;
use crate::win32::*;

#[derive(Debug, Clone)]
pub struct AaScriptResult {
    pub allocated_symbols: HashMap<String, (usize, usize)>, // name -> (address, size)
    pub registered_symbols: HashMap<String, usize>,
    pub patches: Vec<(usize, Vec<u8>)>, // (address, original_bytes)
}

pub struct AutoAssembler {
    symbols: HashMap<String, usize>,
    allocations: HashMap<String, (usize, usize)>,
    patches: Vec<(usize, Vec<u8>)>,
}

impl AutoAssembler {
    pub fn new() -> Self {
        AutoAssembler {
            symbols: HashMap::new(),
            allocations: HashMap::new(),
            patches: Vec::new(),
        }
    }

    pub fn execute(
        &mut self,
        proc: &Process,
        script: &str,
        enable_mode: bool,
    ) -> Result<AaScriptResult, String> {
        let lines: Vec<&str> = script.lines().collect();
        let mut in_target_section = false;
        let mut has_sections = false;

        // Check if script has [ENABLE] or [DISABLE] tags
        for line in &lines {
            let t = line.trim();
            if t.eq_ignore_ascii_case("[enable]") || t.eq_ignore_ascii_case("[disable]") {
                has_sections = true;
                break;
            }
        }

        if !has_sections {
            in_target_section = true;
        }

        let mut resolver = SymbolResolver::new();

        for line in &lines {
            let raw_trimmed = line.trim();
            // Ignore comments
            let trimmed = if let Some(pos) = raw_trimmed.find("//") {
                raw_trimmed[..pos].trim()
            } else if let Some(pos) = raw_trimmed.find('#') {
                raw_trimmed[..pos].trim()
            } else {
                raw_trimmed
            };

            if trimmed.is_empty() {
                continue;
            }

            if trimmed.eq_ignore_ascii_case("[enable]") {
                in_target_section = enable_mode;
                continue;
            } else if trimmed.eq_ignore_ascii_case("[disable]") {
                in_target_section = !enable_mode;
                continue;
            }

            if !in_target_section {
                continue;
            }

            self.parse_and_execute_line(proc, trimmed, &mut resolver)?;
        }

        Ok(AaScriptResult {
            allocated_symbols: self.allocations.clone(),
            registered_symbols: self.symbols.clone(),
            patches: self.patches.clone(),
        })
    }

    fn parse_and_execute_line(
        &mut self,
        proc: &Process,
        line: &str,
        resolver: &mut SymbolResolver,
    ) -> Result<(), String> {
        let lower = line.to_lowercase();

        // 1. alloc(symbol, size)
        if lower.starts_with("alloc(") && line.ends_with(')') {
            let inner = &line[6..line.len() - 1];
            let parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
            if parts.len() < 2 {
                return Err("alloc requires (name, size)".to_string());
            }
            let name = parts[0];
            let size = parse_number(parts[1])
                .ok_or_else(|| format!("Invalid alloc size '{}'", parts[1]))?;

            let addr = proc.alloc(size, PAGE_EXECUTE_READWRITE)?;
            self.allocations.insert(name.to_string(), (addr, size));
            self.symbols.insert(name.to_string(), addr);
            return Ok(());
        }

        // 2. dealloc(symbol)
        if lower.starts_with("dealloc(") && line.ends_with(')') {
            let name = line[8..line.len() - 1].trim();
            if let Some((addr, _)) = self.allocations.remove(name) {
                let _ = proc.free(addr);
                self.symbols.remove(name);
            }
            return Ok(());
        }

        // 3. registersymbol(name)
        if lower.starts_with("registersymbol(") && line.ends_with(')') {
            let _name = line[15..line.len() - 1].trim();
            // Symbol already tracked if allocated or resolved
            return Ok(());
        }

        // 4. unregistersymbol(name)
        if lower.starts_with("unregistersymbol(") && line.ends_with(')') {
            let name = line[17..line.len() - 1].trim();
            self.symbols.remove(name);
            return Ok(());
        }

        // 5. define(name, value)
        if lower.starts_with("define(") && line.ends_with(')') {
            let inner = &line[7..line.len() - 1];
            let parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
            if parts.len() >= 2 {
                let name = parts[0];
                if let Some(val) = self.resolve_address(proc, parts[1], resolver) {
                    self.symbols.insert(name.to_string(), val);
                }
            }
            return Ok(());
        }

        // 6. aobscan / aobscanmodule(name, [module], pattern)
        if lower.starts_with("aobscanmodule(") && line.ends_with(')') {
            let inner = &line[14..line.len() - 1];
            let parts: Vec<&str> = inner.splitn(3, ',').map(|s| s.trim()).collect();
            if parts.len() >= 3 {
                let name = parts[0];
                let _mod_name = parts[1];
                let pattern_str = parts[2];

                let mut scanner = Scanner::new(ValType::Aob);
                let val = ScanValue::parse(ValType::Aob, pattern_str)?;
                scanner.first_scan(proc, ScanCondition::Exact(val))?;

                if let Some(first_match) = scanner.results(1).first() {
                    self.symbols.insert(name.to_string(), first_match.address);
                    return Ok(());
                } else {
                    return Err(format!("aobscanmodule failed to find match for '{}'", name));
                }
            }
        }

        // 7. assert(addr, bytes)
        if lower.starts_with("assert(") && line.ends_with(')') {
            let inner = &line[7..line.len() - 1];
            let parts: Vec<&str> = inner.splitn(2, ',').map(|s| s.trim()).collect();
            if parts.len() >= 2 {
                let addr = self.resolve_address(proc, parts[0], resolver)
                    .ok_or_else(|| format!("Could not resolve assert address '{}'", parts[0]))?;
                let expected = parse_hex_bytes(parts[1])?;
                let current = proc.read_bytes(addr, expected.len())?;
                if current != expected {
                    return Err(format!("Assert failed at 0x{:X}", addr));
                }
                return Ok(());
            }
        }

        // 8. Memory patching / raw bytes:
        // Format: <address_or_symbol>: db 90 90 90
        // Or: jmp <target>
        if let Some(pos) = line.find(':') {
            let target_str = line[..pos].trim();
            let op_str = line[pos + 1..].trim();

            let target_addr = self.resolve_address(proc, target_str, resolver)
                .ok_or_else(|| format!("Could not resolve label/address '{}'", target_str))?;

            if op_str.to_lowercase().starts_with("db ") {
                let hex_part = &op_str[3..];
                let bytes = parse_hex_bytes(hex_part)?;

                let original = proc.read_bytes(target_addr, bytes.len())?;
                self.patches.push((target_addr, original));

                let old_protect = proc.protect(target_addr, bytes.len(), PAGE_EXECUTE_READWRITE)?;
                proc.write_raw(target_addr, &bytes)?;
                let _ = proc.protect(target_addr, bytes.len(), old_protect);
                return Ok(());
            } else if op_str.to_lowercase().starts_with("jmp ") {
                let dest_str = op_str[4..].trim();
                let dest_addr = self.resolve_address(proc, dest_str, resolver)
                    .ok_or_else(|| format!("Could not resolve jmp destination '{}'", dest_str))?;

                let jmp_bytes = make_absolute_jmp_64(dest_addr);
                let original = proc.read_bytes(target_addr, jmp_bytes.len())?;
                self.patches.push((target_addr, original));

                let old_protect = proc.protect(target_addr, jmp_bytes.len(), PAGE_EXECUTE_READWRITE)?;
                proc.write_raw(target_addr, &jmp_bytes)?;
                let _ = proc.protect(target_addr, jmp_bytes.len(), old_protect);
                return Ok(());
            }
        }

        Ok(())
    }

    fn resolve_address(
        &self,
        proc: &Process,
        s: &str,
        resolver: &mut SymbolResolver,
    ) -> Option<usize> {
        let trimmed = s.trim();

        // 1. Defined or allocated symbol
        if let Some(&addr) = self.symbols.get(trimmed) {
            return Some(addr);
        }

        // 2. Direct hex or decimal number
        if let Some(num) = parse_number(trimmed) {
            return Some(num);
        }

        // 3. Module + offset: "game.exe+0x1000" or "game.exe"+1000
        if let Some(pos) = trimmed.find('+') {
            let mod_part = trimmed[..pos].trim().trim_matches('"');
            let off_part = trimmed[pos + 1..].trim();

            let base = if let Some(m) = proc.find_module(mod_part) {
                m.base
            } else if let Some(&sym_addr) = self.symbols.get(mod_part) {
                sym_addr
            } else {
                return None;
            };

            let off = parse_number(off_part)?;
            return Some(base + off);
        }

        // 4. Dynamic export: "kernel32.dll!VirtualAlloc"
        if let Some(addr) = resolver.resolve(proc, trimmed) {
            return Some(addr);
        }

        None
    }

    /// Rollback all patches applied by this script
    pub fn rollback(&mut self, proc: &Process) {
        for (addr, orig_bytes) in self.patches.drain(..) {
            if let Ok(old_protect) = proc.protect(addr, orig_bytes.len(), PAGE_EXECUTE_READWRITE) {
                let _ = proc.write_raw(addr, &orig_bytes);
                let _ = proc.protect(addr, orig_bytes.len(), old_protect);
            }
        }
        for (_, (addr, _)) in self.allocations.drain() {
            let _ = proc.free(addr);
        }
        self.symbols.clear();
    }
}

fn parse_number(s: &str) -> Option<usize> {
    let t = s.trim();
    if t.starts_with("0x") || t.starts_with("0X") {
        usize::from_str_radix(&t[2..], 16).ok()
    } else {
        usize::from_str_radix(t, 16).or_else(|_| t.parse::<usize>()).ok()
    }
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    for part in s.split_whitespace() {
        let clean = part.trim_start_matches("0x").trim_start_matches("0X");
        let b = u8::from_str_radix(clean, 16)
            .map_err(|_| format!("Invalid hex byte: '{}'", part))?;
        bytes.push(b);
    }
    Ok(bytes)
}
