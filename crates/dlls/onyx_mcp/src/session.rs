//! OnyxEngine - Central Active Session Manager for MCP
//! Maintains active process state, driver handle, scanning sessions, freezer,
//! pointer scanner, autoassembler, and mono dissector.

use onyx_core::debugger::assembler::Assembler;
use onyx_core::debugger::disasm::Disassembler;
use onyx_core::debugger::dissect_code::DissectCodeEngine;
use onyx_core::debugger::rop_finder::RopFinder;
use onyx_core::debugger::string_referencer::StringReferencer;
use onyx_core::error::get_locale;
use onyx_core::injection::speedhack::SpeedhackInjector;
use onyx_core::kernel::DbkDriver;
use onyx_core::memory::freeze::Freezer;
use onyx_core::memory::pointer_scanner::PointerScanner;
use onyx_core::memory::structure::StructureDissector;
use onyx_core::mono::mono::MonoDissector;
use onyx_core::process::{Process, ProcessAccessMode};
use onyx_core::scanner::{ScanValue, Scanner};
use onyx_core::scripting::autoassembler::AutoAssembler;
use std::sync::{Arc, Mutex};

pub struct McpSession {
    pub process: Mutex<Option<Arc<Process>>>,
    pub driver: Mutex<Option<Arc<DbkDriver>>>,
    pub scanner: Mutex<Option<Scanner>>,
    pub last_scan_results: Mutex<Vec<usize>>,
    pub freezer: Mutex<Freezer>,
    pub auto_assembler: Mutex<AutoAssembler>,
    pub mono_dissector: Mutex<MonoDissector>,
    pub pointer_scanner: Mutex<PointerScanner>,
    pub speedhack: Mutex<SpeedhackInjector>,
}

impl McpSession {
    pub fn new() -> Self {
        Self {
            process: Mutex::new(None),
            driver: Mutex::new(DbkDriver::connect().ok().map(Arc::new)),
            scanner: Mutex::new(None),
            last_scan_results: Mutex::new(Vec::new()),
            freezer: Mutex::new(Freezer::new()),
            auto_assembler: Mutex::new(AutoAssembler::new()),
            mono_dissector: Mutex::new(MonoDissector::new()),
            pointer_scanner: Mutex::new(PointerScanner::new()),
            speedhack: Mutex::new(SpeedhackInjector::new()),
        }
    }

    pub fn attach(&self, pid_or_name: &str) -> Result<serde_json::Value, String> {
        let trimmed = pid_or_name.trim();
        let pid = if let Ok(parsed_pid) = trimmed.parse::<u32>() {
            parsed_pid
        } else {
            let found = Process::find_by_name(trimmed)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("Processo '{}' não foi encontrado na tabela do sistema.", trimmed))?;
            found.pid
        };

        let dbk = self.driver.lock().unwrap().clone();
        let mode = if dbk.is_some() {
            ProcessAccessMode::KernelDbk
        } else {
            ProcessAccessMode::NtApi
        };

        let proc = Process::attach_with_mode(pid, mode, dbk)
            .map_err(|e| e.format(get_locale()))?;

        let arc_proc = Arc::new(proc);

        // Update freezer and pointer scanner target
        self.freezer.lock().unwrap().update_process(&arc_proc);

        let info = serde_json::json!({
            "status": "attached",
            "pid": arc_proc.pid,
            "name": arc_proc.name,
            "access_mode": arc_proc.access_mode.as_str(),
            "mode_badge": arc_proc.access_mode.badge()
        });

        *self.process.lock().unwrap() = Some(arc_proc);
        *self.scanner.lock().unwrap() = None;
        self.last_scan_results.lock().unwrap().clear();
        self.pointer_scanner.lock().unwrap().clear();

        Ok(info)
    }

    pub fn detach(&self) -> serde_json::Value {
        let mut proc_lock = self.process.lock().unwrap();
        if let Some(proc) = proc_lock.take() {
            self.freezer.lock().unwrap().stop();
            serde_json::json!({
                "status": "detached",
                "previous_pid": proc.pid,
                "name": proc.name
            })
        } else {
            serde_json::json!({
                "status": "idle",
                "message": "Nenhum processo estava anexado."
            })
        }
    }

    pub fn get_process(&self) -> Result<Arc<Process>, String> {
        self.process
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| "Nenhum processo está anexado no momento. Use 'attach_process' primeiro.".to_string())
    }

    pub fn read_memory(&self, address: usize, size: usize, data_type: &str) -> Result<serde_json::Value, String> {
        let proc = self.get_process()?;
        let mut buffer = vec![0u8; size];
        let bytes_read = proc
            .read_raw(address, &mut buffer)
            .map_err(|e| e.format(get_locale()))?;
        buffer.truncate(bytes_read);

        let hex_view = buffer
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");

        let interpreted = match data_type.to_lowercase().as_str() {
            "i8" if !buffer.is_empty() => serde_json::json!(buffer[0] as i8),
            "u8" | "byte" if !buffer.is_empty() => serde_json::json!(buffer[0]),
            "i16" if buffer.len() >= 2 => serde_json::json!(i16::from_le_bytes(buffer[0..2].try_into().unwrap())),
            "u16" if buffer.len() >= 2 => serde_json::json!(u16::from_le_bytes(buffer[0..2].try_into().unwrap())),
            "i32" | "int" if buffer.len() >= 4 => serde_json::json!(i32::from_le_bytes(buffer[0..4].try_into().unwrap())),
            "u32" | "dword" if buffer.len() >= 4 => serde_json::json!(u32::from_le_bytes(buffer[0..4].try_into().unwrap())),
            "i64" if buffer.len() >= 8 => serde_json::json!(i64::from_le_bytes(buffer[0..8].try_into().unwrap())),
            "u64" | "qword" | "pointer" if buffer.len() >= 8 => serde_json::json!(format!("0x{:X}", u64::from_le_bytes(buffer[0..8].try_into().unwrap()))),
            "float" if buffer.len() >= 4 => serde_json::json!(f32::from_le_bytes(buffer[0..4].try_into().unwrap())),
            "double" if buffer.len() >= 8 => serde_json::json!(f64::from_le_bytes(buffer[0..8].try_into().unwrap())),
            "string_utf8" => serde_json::json!(String::from_utf8_lossy(&buffer).to_string()),
            "string_utf16" => {
                let u16_words: Vec<u16> = buffer
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                serde_json::json!(String::from_utf16_lossy(&u16_words))
            }
            _ => serde_json::json!(null),
        };

        Ok(serde_json::json!({
            "address": format!("0x{:X}", address),
            "bytes_read": bytes_read,
            "hex": hex_view,
            "value": interpreted
        }))
    }

    pub fn write_memory(&self, address: usize, bytes: &[u8]) -> Result<serde_json::Value, String> {
        let proc = self.get_process()?;
        let written = proc
            .write_raw(address, bytes)
            .map_err(|e| e.format(get_locale()))?;

        Ok(serde_json::json!({
            "address": format!("0x{:X}", address),
            "bytes_written": written,
            "status": "success"
        }))
    }

    pub fn alloc_memory(&self, size: usize, protect: u32) -> Result<serde_json::Value, String> {
        let proc = self.get_process()?;
        let addr = proc
            .alloc(size, protect)
            .map_err(|e| e.format(get_locale()))?;

        Ok(serde_json::json!({
            "allocated_address": format!("0x{:X}", addr),
            "size": size,
            "protection": format!("0x{:X}", protect),
            "status": "success"
        }))
    }

    pub fn free_memory(&self, address: usize) -> Result<serde_json::Value, String> {
        let proc = self.get_process()?;
        proc.free(address).map_err(|e| e.format(get_locale()))?;

        Ok(serde_json::json!({
            "freed_address": format!("0x{:X}", address),
            "status": "success"
        }))
    }

    pub fn protect_memory(&self, address: usize, size: usize, new_protect: u32) -> Result<serde_json::Value, String> {
        let proc = self.get_process()?;
        let old = proc
            .protect(address, size, new_protect)
            .map_err(|e| e.format(get_locale()))?;

        Ok(serde_json::json!({
            "address": format!("0x{:X}", address),
            "size": size,
            "new_protection": format!("0x{:X}", new_protect),
            "old_protection": format!("0x{:X}", old),
            "status": "success"
        }))
    }

    pub fn query_regions(&self, writable_only: bool) -> Result<serde_json::Value, String> {
        let proc = self.get_process()?;
        let regions = proc
            .regions(writable_only)
            .map_err(|e| e.format(get_locale()))?;

        let mapped = regions.into_iter().take(100).map(|r| {
            serde_json::json!({
                "base": format!("0x{:X}", r.base),
                "size": r.size,
                "state": r.state,
                "protect": format!("0x{:X}", r.protect),
                "is_readable": r.is_readable(),
                "is_writable": r.is_writable(),
                "is_executable": r.is_executable()
            })
        }).collect::<Vec<_>>();

        Ok(serde_json::json!({
            "total_count": mapped.len(),
            "regions": mapped
        }))
    }

    pub fn disassemble(&self, address: usize, count: usize) -> Result<serde_json::Value, String> {
        let proc = self.get_process()?;
        let read_size = count * 15;
        let mut buffer = vec![0u8; read_size];
        let bytes_read = proc.read_raw(address, &mut buffer).map_err(|e| e.format(get_locale()))?;
        buffer.truncate(bytes_read);

        let decoded = Disassembler::disassemble_block(address, &buffer, count);
        let instructions = decoded
            .into_iter()
            .map(|insn| {
                let hex_bytes = insn
                    .bytes
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                serde_json::json!({
                    "address": format!("0x{:X}", insn.address),
                    "bytes": hex_bytes,
                    "mnemonic": insn.mnemonic,
                    "operands": insn.operands,
                    "target_address": insn.target_addr.map(|t| format!("0x{:X}", t))
                })
            })
            .collect::<Vec<_>>();

        Ok(serde_json::json!({
            "base_address": format!("0x{:X}", address),
            "instructions": instructions
        }))
    }

    pub fn assemble(&self, address: usize, instruction: &str) -> Result<serde_json::Value, String> {
        let assembled = Assembler::assemble_line(instruction, address, &|_| None)?;
        let hex = assembled.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");

        Ok(serde_json::json!({
            "instruction": instruction,
            "address": format!("0x{:X}", address),
            "bytes_length": assembled.len(),
            "opcodes": hex
        }))
    }

    pub fn dissect_structure(&self, address: usize, size: usize) -> Result<serde_json::Value, String> {
        let proc = self.get_process()?;
        let fields = StructureDissector::dissect(&proc, address, size)?;

        let serialized = fields.into_iter().map(|f| {
            serde_json::json!({
                "offset": format!("0x{:X}", f.offset),
                "type": f.guessed.type_name(),
                "preview": f.preview,
                "priority": f.priority
            })
        }).collect::<Vec<_>>();

        Ok(serde_json::json!({
            "structure_address": format!("0x{:X}", address),
            "total_size": size,
            "fields": serialized
        }))
    }

    pub fn find_rop_gadgets(&self, address: usize, size: usize, max_gadgets: usize) -> Result<serde_json::Value, String> {
        let proc = self.get_process()?;
        let buffer = proc.read_bytes(address, size).map_err(|e| e.format(get_locale()))?;
        let gadgets = RopFinder::find(&buffer, address, max_gadgets);

        let list = gadgets.into_iter().map(|g| {
            serde_json::json!({
                "address": format!("0x{:X}", g.address),
                "kind": g.kind.as_str(),
                "bytes": g.bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
            })
        }).collect::<Vec<_>>();

        Ok(serde_json::json!({
            "scanned_range": format!("0x{:X} - 0x{:X}", address, address + size),
            "count": list.len(),
            "gadgets": list
        }))
    }

    pub fn find_string_references(&self, start: usize, stop: usize, min_len: usize) -> Result<serde_json::Value, String> {
        let proc = self.get_process()?;
        let refs = StringReferencer::scan_process(&proc, start, stop, min_len)?;

        let list = refs.into_iter().take(100).map(|r| {
            serde_json::json!({
                "instruction_address": format!("0x{:X}", r.instruction_address),
                "string_address": format!("0x{:X}", r.string_address),
                "text": r.text,
                "is_unicode": r.is_unicode,
                "mnemonic": r.mnemonic,
                "operands": r.operands
            })
        }).collect::<Vec<_>>();

        Ok(serde_json::json!({
            "total_matches": list.len(),
            "references": list
        }))
    }

    pub fn dissect_code_branches(&self, address: usize, size: usize) -> Result<serde_json::Value, String> {
        let proc = self.get_process()?;
        let buffer = proc.read_bytes(address, size).map_err(|e| e.format(get_locale()))?;
        let result = DissectCodeEngine::dissect_buffer(&buffer, address);

        let branches = result.branches.into_iter().map(|b| {
            serde_json::json!({
                "from": format!("0x{:X}", b.from_address),
                "to": format!("0x{:X}", b.to_address),
                "kind": format!("{:?}", b.kind)
            })
        }).collect::<Vec<_>>();

        let starts = result.function_starts.into_iter().map(|s| format!("0x{:X}", s)).collect::<Vec<_>>();

        Ok(serde_json::json!({
            "base_address": format!("0x{:X}", address),
            "function_starts": starts,
            "branches": branches
        }))
    }

    pub fn pointer_resolve_chain(&self, base_addr: usize, offsets: &[usize]) -> Result<serde_json::Value, String> {
        let proc = self.get_process()?;
        let mut current = base_addr;

        let mut trace = vec![serde_json::json!({
            "step": 0,
            "address": format!("0x{:X}", current)
        })];

        for (i, &offset) in offsets.iter().enumerate() {
            let mut ptr_buf = [0u8; 8];
            proc.read_raw(current, &mut ptr_buf)
                .map_err(|e| format!("Falha ao ler ponteiro no passo {} (0x{:X}): {}", i, current, e.format(get_locale())))?;
            let deref = usize::from_le_bytes(ptr_buf);
            current = deref.wrapping_add(offset);

            trace.push(serde_json::json!({
                "step": i + 1,
                "dereferenced": format!("0x{:X}", deref),
                "offset": format!("0x{:X}", offset),
                "next_address": format!("0x{:X}", current)
            }));
        }

        Ok(serde_json::json!({
            "final_address": format!("0x{:X}", current),
            "offsets_count": offsets.len(),
            "trace": trace
        }))
    }

    pub fn pointer_scan_start(&self, target_address: usize, max_depth: usize, max_offset: usize) -> Result<serde_json::Value, String> {
        let proc = self.get_process()?;
        let mut scanner = self.pointer_scanner.lock().unwrap();
        
        let map_count = scanner.generate_map(&proc)?;
        let depth = max_depth.clamp(1, 5);
        let offset_limit = max_offset.clamp(0x10, 0x2000);

        let paths = scanner.scan_paths(&proc, target_address, depth, offset_limit)?;
        let serialized_paths = paths.into_iter().take(30).map(|p| {
            serde_json::json!({
                "display": p.to_display_string(),
                "base_module": p.module_name,
                "base_offset": format!("0x{:X}", p.base_offset),
                "offsets": p.offsets.iter().map(|o| format!("0x{:X}", o)).collect::<Vec<_>>()
            })
        }).collect::<Vec<_>>();

        Ok(serde_json::json!({
            "target_address": format!("0x{:X}", target_address),
            "pointers_in_map": map_count,
            "paths_found": serialized_paths.len(),
            "paths": serialized_paths
        }))
    }

    pub fn aa_validate_script(&self, script: &str) -> serde_json::Value {
        match onyx_aa::parse_script(script) {
            Ok(parsed) => match onyx_aa::analyze(&parsed) {
                Ok(_) => serde_json::json!({
                    "valid": true,
                    "sections": parsed.sections.len(),
                    "message": "Script AutoAssembler válido e verificado pelo analisador semântico."
                }),
                Err(err) => serde_json::json!({
                    "valid": false,
                    "error": format!("{:?}", err)
                }),
            },
            Err(e) => serde_json::json!({
                "valid": false,
                "error": format!("{:?}", e)
            }),
        }
    }

    pub fn aa_execute_script(&self, script: &str, enable_mode: bool) -> Result<serde_json::Value, String> {
        let proc = self.get_process()?;
        let mut aa = self.auto_assembler.lock().unwrap();
        let result = aa.execute(&proc, script, enable_mode)?;

        let allocated = result.allocated_symbols.into_iter().map(|(k, (addr, sz))| {
            serde_json::json!({ "symbol": k, "address": format!("0x{:X}", addr), "size": sz })
        }).collect::<Vec<_>>();

        let registered = result.registered_symbols.into_iter().map(|(k, addr)| {
            serde_json::json!({ "symbol": k, "address": format!("0x{:X}", addr) })
        }).collect::<Vec<_>>();

        Ok(serde_json::json!({
            "mode": if enable_mode { "ENABLE" } else { "DISABLE" },
            "allocated_symbols": allocated,
            "registered_symbols": registered,
            "patches_count": result.patches.len(),
            "status": "applied_successfully"
        }))
    }

    pub fn freeze_address(&self, address: usize, value_str: &str, data_type: &str, desc: &str) -> Result<serde_json::Value, String> {
        let proc = self.get_process()?;
        let scan_val = match data_type.to_lowercase().as_str() {
            "i8" => ScanValue::I8(value_str.parse().map_err(|e| format!("Valor inválido: {}", e))?),
            "i16" => ScanValue::I16(value_str.parse().map_err(|e| format!("Valor inválido: {}", e))?),
            "i32" | "int" => ScanValue::I32(value_str.parse().map_err(|e| format!("Valor inválido: {}", e))?),
            "i64" => ScanValue::I64(value_str.parse().map_err(|e| format!("Valor inválido: {}", e))?),
            "float" => ScanValue::Float(value_str.parse().map_err(|e| format!("Valor inválido: {}", e))?),
            "double" => ScanValue::Double(value_str.parse().map_err(|e| format!("Valor inválido: {}", e))?),
            _ => return Err(format!("Tipo de dado não suportado para congelamento: {}", data_type)),
        };

        let mut freezer = self.freezer.lock().unwrap();
        freezer.start(&proc, 50);
        let id = freezer.freeze(address, scan_val, desc);

        Ok(serde_json::json!({
            "freeze_id": id,
            "address": format!("0x{:X}", address),
            "locked_value": value_str,
            "type": data_type,
            "status": "frozen"
        }))
    }

    pub fn unfreeze_address(&self, address: usize) -> serde_json::Value {
        let freezer = self.freezer.lock().unwrap();
        let removed = freezer.unfreeze_by_address(address);
        serde_json::json!({
            "address": format!("0x{:X}", address),
            "unfrozen": removed
        })
    }

    pub fn freeze_list(&self) -> serde_json::Value {
        let freezer = self.freezer.lock().unwrap();
        let list = freezer.list().into_iter().map(|f| {
            serde_json::json!({
                "id": f.id,
                "address": format!("0x{:X}", f.address),
                "description": f.description
            })
        }).collect::<Vec<_>>();

        serde_json::json!({
            "total_frozen": list.len(),
            "entries": list
        })
    }

    pub fn speedhack_set_speed(&self, multiplier: f32) -> Result<serde_json::Value, String> {
        let proc = self.get_process()?;
        let mut sh = self.speedhack.lock().unwrap();
        sh.enable_speedhack(&proc, multiplier)?;

        Ok(serde_json::json!({
            "multiplier": multiplier,
            "status": "speedhack_active"
        }))
    }
}
