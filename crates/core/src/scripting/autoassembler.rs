use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use crate::debugger::assembler::Assembler;
use crate::disasm::Disassembler;
use crate::hook::make_absolute_jmp_64;
use crate::process::Process;
use crate::scanner::{ScanCondition, ScanValue, Scanner, ValType};
use crate::symbol::SymbolResolver;
use crate::win32::*;

#[derive(Debug, Clone)]
pub struct AaScriptResult {
    pub allocated_symbols: HashMap<String, (usize, usize)>,
    pub registered_symbols: HashMap<String, usize>,
    pub patches: Vec<(usize, Vec<u8>)>,
}

pub struct AutoAssembler {
    pub symbols: HashMap<String, usize>,
    pub allocations: HashMap<String, (usize, usize)>,
    pub patches: Vec<(usize, Vec<u8>)>,
    pub globalalloc_symbols: HashSet<String>,
    pub declared_labels: HashSet<String>,
}

impl AutoAssembler {
    pub fn new() -> Self {
        AutoAssembler {
            symbols: HashMap::new(),
            allocations: HashMap::new(),
            patches: Vec::new(),
            globalalloc_symbols: HashSet::new(),
            declared_labels: HashSet::new(),
        }
    }

    pub fn execute(
        &mut self,
        proc: &Process,
        script: &str,
        enable_mode: bool,
    ) -> Result<AaScriptResult, String> {
        let raw_lines: Vec<&str> = script.lines().collect();
        let mut in_target_section = false;
        let mut has_sections = false;

        for line in &raw_lines {
            let t = line.trim();
            if t.eq_ignore_ascii_case("[enable]") || t.eq_ignore_ascii_case("[disable]") {
                has_sections = true;
                break;
            }
        }

        if !has_sections {
            in_target_section = true;
        }

        let resolver = RefCell::new(SymbolResolver::new());
        let mut cond_stack: Vec<bool> = Vec::new();
        let mut active_lines: Vec<String> = Vec::new();

        for line in &raw_lines {
            let raw_trimmed = line.trim();
            let trimmed = strip_comments(raw_trimmed);

            if trimmed.is_empty() {
                continue;
            }

            let lower_t = trimmed.to_lowercase();
            if lower_t.starts_with("{$ifdef") && lower_t.ends_with('}') {
                let inner = trimmed[7..trimmed.len() - 1].trim();
                let is_def = self.symbols.contains_key(inner)
                    || self.allocations.contains_key(inner)
                    || resolver.borrow_mut().resolve(proc, inner).is_some();
                cond_stack.push(is_def);
                continue;
            } else if lower_t.starts_with("{$ifndef") && lower_t.ends_with('}') {
                let inner = trimmed[8..trimmed.len() - 1].trim();
                let is_def = self.symbols.contains_key(inner)
                    || self.allocations.contains_key(inner)
                    || resolver.borrow_mut().resolve(proc, inner).is_some();
                cond_stack.push(!is_def);
                continue;
            } else if lower_t == "{$else}" {
                if let Some(top) = cond_stack.pop() {
                    cond_stack.push(!top);
                }
                continue;
            } else if lower_t == "{$endif}" {
                cond_stack.pop();
                continue;
            }

            if cond_stack.iter().any(|&active| !active) {
                continue;
            }

            if trimmed.eq_ignore_ascii_case("[enable]") {
                in_target_section = enable_mode;
                continue;
            } else if trimmed.eq_ignore_ascii_case("[disable]") {
                in_target_section = !enable_mode;
                continue;
            }

            if in_target_section {
                active_lines.push(trimmed.to_string());
            }
        }

        let mut current_ip: Option<usize> = None;

        for line in &active_lines {
            let lower = line.to_lowercase();

            if lower.starts_with("label(") && line.ends_with(')') {
                let inner = line[6..line.len() - 1].trim();
                self.declared_labels.insert(inner.to_string());
                continue;
            }

            if lower.starts_with("alloc(") && line.ends_with(')') {
                let inner = &line[6..line.len() - 1];
                let parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
                if parts.len() < 2 {
                    return Err("alloc requires at least (name, size)".to_string());
                }
                let name = parts[0];
                let size = parse_number(parts[1])
                    .ok_or_else(|| format!("Invalid alloc size '{}'", parts[1]))?;

                let addr = if parts.len() >= 3 {
                    let near_target = self.resolve_address(proc, parts[2], &mut resolver.borrow_mut());
                    if let Some(preferred) = near_target {
                        proc.alloc_near(preferred, size, PAGE_EXECUTE_READWRITE)?
                    } else {
                        proc.alloc(size, PAGE_EXECUTE_READWRITE)?
                    }
                } else {
                    proc.alloc(size, PAGE_EXECUTE_READWRITE)?
                };

                self.allocations.insert(name.to_string(), (addr, size));
                self.symbols.insert(name.to_string(), addr);
                continue;
            }

            if lower.starts_with("globalalloc(") && line.ends_with(')') {
                let inner = &line[12..line.len() - 1];
                let parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
                if parts.len() < 2 {
                    return Err("globalalloc requires (name, size)".to_string());
                }
                let name = parts[0];
                let size = parse_number(parts[1])
                    .ok_or_else(|| format!("Invalid globalalloc size '{}'", parts[1]))?;

                let addr = proc.alloc(size, PAGE_EXECUTE_READWRITE)?;
                self.allocations.insert(name.to_string(), (addr, size));
                self.symbols.insert(name.to_string(), addr);
                self.globalalloc_symbols.insert(name.to_string());
                continue;
            }

            if lower.starts_with("dealloc(") && line.ends_with(')') {
                let name = line[8..line.len() - 1].trim();
                if let Some((addr, _)) = self.allocations.remove(name) {
                    let _ = proc.free(addr);
                    self.symbols.remove(name);
                }
                continue;
            }

            if lower.starts_with("define(") && line.ends_with(')') {
                let inner = &line[7..line.len() - 1];
                let parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    let name = parts[0];
                    if let Some(val) = self.resolve_address(proc, parts[1], &mut resolver.borrow_mut()) {
                        self.symbols.insert(name.to_string(), val);
                    }
                }
                continue;
            }

            if lower.starts_with("registersymbol(") && line.ends_with(')') {
                continue;
            }
            if lower.starts_with("unregistersymbol(") && line.ends_with(')') {
                let name = line[17..line.len() - 1].trim();
                self.symbols.remove(name);
                continue;
            }

            if lower.starts_with("aobscanmodule(") && line.ends_with(')') {
                let inner = &line[14..line.len() - 1];
                let parts: Vec<&str> = inner.splitn(3, ',').map(|s| s.trim()).collect();
                if parts.len() >= 3 {
                    let name = parts[0];
                    let pattern_str = parts[2];
                    let mut scanner = Scanner::new(ValType::Aob);
                    let val = ScanValue::parse(ValType::Aob, pattern_str)?;
                    scanner.first_scan(proc, ScanCondition::Exact(val))?;
                    if let Some(first_match) = scanner.results(1).first() {
                        self.symbols.insert(name.to_string(), first_match.address);
                        continue;
                    } else {
                        return Err(format!("aobscanmodule failed to find match for '{}'", name));
                    }
                }
            }
            if lower.starts_with("aobscan(") && line.ends_with(')') {
                let inner = &line[8..line.len() - 1];
                let parts: Vec<&str> = inner.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    let name = parts[0];
                    let pattern_str = parts[1];
                    let mut scanner = Scanner::new(ValType::Aob);
                    let val = ScanValue::parse(ValType::Aob, pattern_str)?;
                    scanner.first_scan(proc, ScanCondition::Exact(val))?;
                    if let Some(first_match) = scanner.results(1).first() {
                        self.symbols.insert(name.to_string(), first_match.address);
                        continue;
                    } else {
                        return Err(format!("aobscan failed to find match for '{}'", name));
                    }
                }
            }
            if lower.starts_with("aobscanfunction(") && line.ends_with(')') {
                let inner = &line[16..line.len() - 1];
                let parts: Vec<&str> = inner.splitn(3, ',').map(|s| s.trim()).collect();
                if parts.len() >= 3 {
                    self.execute_aobscanfunction_command(proc, parts[0], parts[1], parts[2], &mut resolver.borrow_mut())?;
                    continue;
                }
            }

            if lower.starts_with("assert(") && line.ends_with(')') {
                let inner = &line[7..line.len() - 1];
                let parts: Vec<&str> = inner.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    let addr = self.resolve_address(proc, parts[0], &mut resolver.borrow_mut())
                        .ok_or_else(|| format!("Could not resolve assert address '{}'", parts[0]))?;
                    let expected = parse_hex_bytes(parts[1])?;
                    let current = proc.read_bytes(addr, expected.len())?;
                    if current != expected {
                        return Err(format!("Assert failed at 0x{:X}", addr));
                    }
                    continue;
                }
            }

            if lower.starts_with("hook(") && line.ends_with(')') {
                let inner = &line[5..line.len() - 1];
                let parts: Vec<&str> = inner.splitn(3, ',').map(|s| s.trim()).collect();
                if parts.len() >= 3 {
                    self.execute_hook_command(proc, parts[0], parts[1], parts[2], &mut resolver.borrow_mut())?;
                    continue;
                }
            }
            if lower.starts_with("unhook(") && line.ends_with(')') {
                let addr_str = line[7..line.len() - 1].trim();
                self.execute_unhook_command(proc, addr_str, &mut resolver.borrow_mut())?;
                continue;
            }

            if lower.starts_with("loadlibrary(") && line.ends_with(')') {
                let path = line[12..line.len() - 1].trim().trim_matches('"');
                let _ = proc.inject_dll(path)?;
                continue;
            }

            if lower.starts_with("createthread(") && line.ends_with(')') {
                continue;
            }

            if lower.starts_with("readmem(") && line.ends_with(')') {
                let inner = &line[8..line.len() - 1];
                let parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    let size = parse_number(parts[1])
                        .ok_or_else(|| format!("Invalid readmem size '{}'", parts[1]))?;
                    if let Some(ip) = current_ip {
                        current_ip = Some(ip + size);
                    }
                }
                continue;
            }

            if let Some(pos) = line.find(':') {
                let target_part = line[..pos].trim();
                let rest = line[pos + 1..].trim();

                if let Some((addr, _)) = self.allocations.get(target_part) {
                    current_ip = Some(*addr);
                } else if self.declared_labels.contains(target_part) {
                    if let Some(ip) = current_ip {
                        self.symbols.insert(target_part.to_string(), ip);
                    }
                } else if let Some(addr) = self.resolve_address(proc, target_part, &mut resolver.borrow_mut()) {
                    current_ip = Some(addr);
                } else if let Some(ip) = current_ip {

                    self.symbols.insert(target_part.to_string(), ip);
                }

                if !rest.is_empty()
                    && let Some(ip) = current_ip {
                        let len = self.estimate_code_len(proc, rest, ip, &resolver)?;
                        current_ip = Some(ip + len);
                    }
                continue;
            }

            if let Some(ip) = current_ip {
                let len = self.estimate_code_len(proc, line, ip, &resolver)?;
                current_ip = Some(ip + len);
            }
        }

        current_ip = None;

        for line in &active_lines {
            let lower = line.to_lowercase();

            if lower.starts_with("label(")
                || lower.starts_with("alloc(")
                || lower.starts_with("globalalloc(")
                || lower.starts_with("dealloc(")
                || lower.starts_with("define(")
                || lower.starts_with("registersymbol(")
                || lower.starts_with("unregistersymbol(")
                || lower.starts_with("aobscan(")
                || lower.starts_with("aobscanmodule(")
                || lower.starts_with("aobscanfunction(")
                || lower.starts_with("assert(")
                || lower.starts_with("hook(")
                || lower.starts_with("unhook(")
                || lower.starts_with("loadlibrary(")
            {
                continue;
            }

            if lower.starts_with("createthread(") && line.ends_with(')') {
                let addr_str = line[12..line.len() - 1].trim();
                let target_addr = self.resolve_address(proc, addr_str, &mut resolver.borrow_mut())
                    .ok_or_else(|| format!("createthread: could not resolve address '{}'", addr_str))?;
                proc.create_thread(target_addr)?;
                continue;
            }

            if lower.starts_with("readmem(") && line.ends_with(')') {
                let inner = &line[8..line.len() - 1];
                let parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    let src_addr = self.resolve_address(proc, parts[0], &mut resolver.borrow_mut())
                        .ok_or_else(|| format!("readmem: could not resolve src address '{}'", parts[0]))?;
                    let size = parse_number(parts[1])
                        .ok_or_else(|| format!("Invalid readmem size '{}'", parts[1]))?;

                    let bytes = proc.read_bytes(src_addr, size)?;
                    let ip = current_ip.ok_or("readmem without active target address")?;
                    self.write_code_bytes(proc, ip, &bytes)?;
                    current_ip = Some(ip + bytes.len());
                }
                continue;
            }

            if let Some(pos) = line.find(':') {
                let target_part = line[..pos].trim();
                let rest = line[pos + 1..].trim();

                if let Some((addr, _)) = self.allocations.get(target_part) {
                    current_ip = Some(*addr);
                } else if let Some(&sym_addr) = self.symbols.get(target_part) {
                    current_ip = Some(sym_addr);
                } else if let Some(addr) = self.resolve_address(proc, target_part, &mut resolver.borrow_mut()) {
                    current_ip = Some(addr);
                }

                if !rest.is_empty() {
                    let ip = current_ip.ok_or_else(|| format!("No active address for instruction '{}'", rest))?;
                    let bytes = self.assemble_instruction(proc, rest, ip, &resolver)?;
                    self.write_code_bytes(proc, ip, &bytes)?;
                    current_ip = Some(ip + bytes.len());
                }
                continue;
            }

            if let Some(ip) = current_ip {
                let bytes = self.assemble_instruction(proc, line, ip, &resolver)?;
                self.write_code_bytes(proc, ip, &bytes)?;
                current_ip = Some(ip + bytes.len());
            }
        }

        Ok(AaScriptResult {
            allocated_symbols: self.allocations.clone(),
            registered_symbols: self.symbols.clone(),
            patches: self.patches.clone(),
        })
    }

    fn estimate_code_len(
        &self,
        proc: &Process,
        line: &str,
        ip: usize,
        resolver: &RefCell<SymbolResolver>,
    ) -> Result<usize, String> {
        let syms = &self.symbols;
        let dummy_resolver = |s: &str| -> Option<usize> {
            if let Some(&addr) = syms.get(s) {
                Some(addr)
            } else if let Some(addr) = self.resolve_address(proc, s, &mut resolver.borrow_mut()) {
                Some(addr)
            } else {

                Some(ip.wrapping_add(0x1000))
            }
        };

        let bytes = Assembler::assemble_line(line, ip, &dummy_resolver)?;
        Ok(bytes.len())
    }

    fn assemble_instruction(
        &self,
        proc: &Process,
        line: &str,
        ip: usize,
        resolver: &RefCell<SymbolResolver>,
    ) -> Result<Vec<u8>, String> {
        let syms = &self.symbols;
        let full_resolver = |s: &str| -> Option<usize> {
            if let Some(&addr) = syms.get(s) {
                Some(addr)
            } else {
                self.resolve_address(proc, s, &mut resolver.borrow_mut())
            }
        };

        Assembler::assemble_line(line, ip, &full_resolver)
    }

    fn write_code_bytes(&mut self, proc: &Process, address: usize, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() {
            return Ok(());
        }

        let is_allocated = self
            .allocations
            .values()
            .any(|&(addr, size)| address >= addr && address < addr + size);

        if is_allocated {
            proc.write_raw(address, bytes)?;
        } else {

            if let Ok(orig_bytes) = proc.read_bytes(address, bytes.len()) {
                self.patches.push((address, orig_bytes));
            }
            let old_protect = proc.protect(address, bytes.len(), PAGE_EXECUTE_READWRITE)?;
            proc.write_raw(address, bytes)?;
            let _ = proc.protect(address, bytes.len(), old_protect);
        }

        Ok(())
    }

    fn execute_hook_command(
        &mut self,
        proc: &Process,
        target_str: &str,
        dest_str: &str,
        orig_sym: &str,
        resolver: &mut SymbolResolver,
    ) -> Result<(), String> {
        let target_addr = self.resolve_address(proc, target_str, resolver)
            .ok_or_else(|| format!("hook: could not resolve target address '{}'", target_str))?;
        let dest_addr = self.resolve_address(proc, dest_str, resolver)
            .ok_or_else(|| format!("hook: could not resolve destination address '{}'", dest_str))?;

        const MIN_HOOK_SIZE: usize = 14;
        let preview = proc.read_bytes(target_addr, 32)?;
        let insns = Disassembler::disassemble_block(target_addr, &preview, 10);
        let mut stolen_len = 0;
        for insn in &insns {
            stolen_len += insn.length;
            if stolen_len >= MIN_HOOK_SIZE {
                break;
            }
        }
        if stolen_len < MIN_HOOK_SIZE {
            return Err(format!(
                "hook: not enough instruction bytes at 0x{:X} to place 14-byte hook (got {})",
                target_addr, stolen_len
            ));
        }

        let original_bytes = proc.read_bytes(target_addr, stolen_len)?;
        let return_addr = target_addr + stolen_len;
        let jmp_back = make_absolute_jmp_64(return_addr);
        let total_orig_size = stolen_len + jmp_back.len();

        let orig_alloc = proc.alloc(total_orig_size, PAGE_EXECUTE_READWRITE)?;
        let mut orig_code = Vec::with_capacity(total_orig_size);
        orig_code.extend_from_slice(&original_bytes);
        orig_code.extend_from_slice(&jmp_back);
        proc.write_raw(orig_alloc, &orig_code)?;

        let orig_name = orig_sym.trim();
        self.symbols.insert(orig_name.to_string(), orig_alloc);
        self.allocations.insert(orig_name.to_string(), (orig_alloc, total_orig_size));

        let mut detour = make_absolute_jmp_64(dest_addr);
        while detour.len() < stolen_len {
            detour.push(0x90);
        }

        self.patches.push((target_addr, original_bytes));

        let old_protect = proc.protect(target_addr, stolen_len, PAGE_EXECUTE_READWRITE)?;
        proc.write_raw(target_addr, &detour)?;
        let _ = proc.protect(target_addr, stolen_len, old_protect);

        Ok(())
    }

    fn execute_unhook_command(
        &mut self,
        proc: &Process,
        target_str: &str,
        resolver: &mut SymbolResolver,
    ) -> Result<(), String> {
        let target_addr = self.resolve_address(proc, target_str, resolver)
            .ok_or_else(|| format!("unhook: could not resolve address '{}'", target_str))?;

        if let Some(pos) = self.patches.iter().position(|(addr, _)| *addr == target_addr) {
            let (_, original_bytes) = self.patches.remove(pos);
            let old_protect = proc.protect(target_addr, original_bytes.len(), PAGE_EXECUTE_READWRITE)?;
            proc.write_raw(target_addr, &original_bytes)?;
            let _ = proc.protect(target_addr, original_bytes.len(), old_protect);
            Ok(())
        } else {
            Err(format!("unhook: no active hook found for address 0x{:X}", target_addr))
        }
    }

    fn execute_aobscanfunction_command(
        &mut self,
        proc: &Process,
        name: &str,
        fn_start_str: &str,
        aob_str: &str,
        resolver: &mut SymbolResolver,
    ) -> Result<(), String> {
        let fn_start = self.resolve_address(proc, fn_start_str, resolver)
            .ok_or_else(|| format!("aobscanfunction: could not resolve function start '{}'", fn_start_str))?;

        const MAX_FN_SCAN: usize = 4096;
        let read_buf = proc.read_bytes(fn_start, MAX_FN_SCAN)
            .unwrap_or_else(|_| proc.read_bytes(fn_start, 512).unwrap_or_default());

        if read_buf.is_empty() {
            return Err(format!("aobscanfunction: failed to read memory at 0x{:X}", fn_start));
        }

        let insns = Disassembler::disassemble_block(fn_start, &read_buf, 256);
        let mut fn_len = read_buf.len();
        for insn in &insns {
            if insn.mnemonic == "ret" {
                fn_len = (insn.address + insn.length - fn_start).min(read_buf.len());
                break;
            }
        }

        let pattern = ScanValue::parse(ValType::Aob, aob_str)?;
        if let ScanValue::Aob(pat) = pattern {
            let slice = &read_buf[..fn_len];
            if slice.len() >= pat.len() {
                let max_i = slice.len() - pat.len();
                for i in 0..=max_i {
                    let mut matched = true;
                    for (p_idx, pb) in pat.iter().enumerate() {
                        if !pb.matches(slice[i + p_idx]) {
                            matched = false;
                            break;
                        }
                    }
                    if matched {
                        let matched_addr = fn_start + i;
                        self.symbols.insert(name.trim().to_string(), matched_addr);
                        return Ok(());
                    }
                }
            }
        }

        Err(format!("aobscanfunction: pattern '{}' not found in function at 0x{:X}", aob_str, fn_start))
    }

    pub fn resolve_address(
        &self,
        proc: &Process,
        s: &str,
        resolver: &mut SymbolResolver,
    ) -> Option<usize> {
        let trimmed = s.trim();

        if let Some(&addr) = self.symbols.get(trimmed) {
            return Some(addr);
        }

        if let Some(num) = parse_number(trimmed) {
            return Some(num);
        }

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
            return Some(base.wrapping_add(off));
        } else if let Some(pos) = trimmed.rfind('-')
            && pos > 0 {
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
                return Some(base.wrapping_sub(off));
            }

        if let Some(addr) = resolver.resolve(proc, trimmed) {
            return Some(addr);
        }

        None
    }

    pub fn rollback(&mut self, proc: &Process) {
        for (addr, orig_bytes) in self.patches.drain(..).rev() {
            if let Ok(old_protect) = proc.protect(addr, orig_bytes.len(), PAGE_EXECUTE_READWRITE) {
                let _ = proc.write_raw(addr, &orig_bytes);
                let _ = proc.protect(addr, orig_bytes.len(), old_protect);
            }
        }
        for (_, (addr, _)) in self.allocations.drain() {
            let _ = proc.free(addr);
        }
        self.symbols.clear();
        self.globalalloc_symbols.clear();
        self.declared_labels.clear();
    }

    pub fn get_table_saveable_symbols(&self) -> HashMap<String, usize> {
        self.symbols
            .iter()
            .filter(|(k, _)| !self.globalalloc_symbols.contains(*k))
            .map(|(k, &v)| (k.clone(), v))
            .collect()
    }
}

impl Default for AutoAssembler {
    fn default() -> Self {
        Self::new()
    }
}

fn strip_comments(line: &str) -> &str {
    let mut s = line.trim();
    if let Some(pos) = s.find("//") {
        s = s[..pos].trim();
    }
    if let Some(pos) = s.find('#')
        && (pos == 0 || s[..pos].ends_with(|c: char| c.is_whitespace() || c == ',')) {
            let after = s[pos + 1..].trim();
            if after.starts_with(|c: char| c.is_ascii_alphabetic()) || after.is_empty() {
                s = s[..pos].trim();
            }
        }
    s
}

fn parse_number(s: &str) -> Option<usize> {
    let t = s.trim();
    if t.starts_with("0x") || t.starts_with("0X") {
        usize::from_str_radix(&t[2..], 16).ok()
    } else if t.starts_with('$') {
        usize::from_str_radix(&t[1..], 16).ok()
    } else if t.starts_with('#') {
        t[1..].trim().parse::<usize>().ok()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessAccessMode;

    #[test]
    fn test_conditional_compilation() {
        let mut aa = AutoAssembler::new();
        aa.symbols.insert("FEATURE_ACTIVE".to_string(), 0x140001000);

        let dummy_proc = Process {
            pid: 0,
            handle: std::ptr::null_mut(),
            name: String::new(),
            access_mode: ProcessAccessMode::NtApi,
            dbk: None,
        };

        let script = r#"
        [ENABLE]
        {$ifdef FEATURE_ACTIVE}
        define(TEST_A, 0x100)
        {$else}
        define(TEST_A, 0x200)
        {$endif}

        {$ifndef FEATURE_NONEXISTENT}
        define(TEST_B, 0x300)
        {$else}
        define(TEST_B, 0x400)
        {$endif}
        "#;

        let res = aa.execute(&dummy_proc, script, true).unwrap();
        assert_eq!(res.registered_symbols.get("TEST_A"), Some(&0x100));
        assert_eq!(res.registered_symbols.get("TEST_B"), Some(&0x300));
    }

    #[test]
    fn test_globalalloc_saveable_symbols() {
        let mut aa = AutoAssembler::new();
        aa.symbols.insert("normal_sym".to_string(), 0x140001000);
        aa.symbols.insert("global_sym".to_string(), 0x140002000);
        aa.globalalloc_symbols.insert("global_sym".to_string());

        let saveable = aa.get_table_saveable_symbols();
        assert!(saveable.contains_key("normal_sym"));
        assert!(!saveable.contains_key("global_sym"), "CE 7.7: globalalloc symbols must not save in tables");
    }

    #[test]
    fn test_relative_notation() {
        let mut aa = AutoAssembler::new();
        aa.symbols.insert("base_sym".to_string(), 0x1000);

        let dummy_proc = Process {
            pid: 0,
            handle: std::ptr::null_mut(),
            name: String::new(),
            access_mode: ProcessAccessMode::NtApi,
            dbk: None,
        };

        let mut resolver = SymbolResolver::new();
        let addr_plus = aa.resolve_address(&dummy_proc, "base_sym+0x20", &mut resolver).unwrap();
        let addr_minus = aa.resolve_address(&dummy_proc, "base_sym-0x10", &mut resolver).unwrap();

        assert_eq!(addr_plus, 0x1020);
        assert_eq!(addr_minus, 0x0FF0);
    }

    #[test]
    fn test_2pass_autoassembler_code_cave() {
        let proc = Process::attach_current().expect("attach to current process");
        let mut aa = AutoAssembler::new();

        let script = r#"
        [ENABLE]
        alloc(newmem, 2048)
        label(returnhere)
        label(exit)

        newmem:
        mov [rax+0x10], 0x3E8
        exit:
        jmp returnhere

        newmem+0x100:
        returnhere:
        nop
        "#;

        let res = aa.execute(&proc, script, true).expect("execute AA script");
        let newmem_addr = *res.registered_symbols.get("newmem").expect("newmem symbol");
        let returnhere_addr = *res.registered_symbols.get("returnhere").expect("returnhere symbol");
        let exit_addr = *res.registered_symbols.get("exit").expect("exit symbol");

        assert_eq!(returnhere_addr, newmem_addr + 0x100);
        assert!(exit_addr > newmem_addr);

        let bytes = proc.read_bytes(newmem_addr, 7).expect("read newmem");

        assert_eq!(bytes, vec![0xC7, 0x40, 0x10, 0xE8, 0x03, 0x00, 0x00]);

        let jmp_bytes = proc.read_bytes(exit_addr, 5).expect("read jmp");
        assert_eq!(jmp_bytes[0], 0xE9);

        aa.rollback(&proc);
        assert!(aa.symbols.is_empty());
        assert!(aa.allocations.is_empty());
    }
}
