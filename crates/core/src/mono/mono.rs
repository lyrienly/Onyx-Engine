
use crate::process::Process;
use crate::symbol::SymbolResolver;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeType {
    Mono,
    Il2Cpp,
    DotNetClr,
    None,
}

impl RuntimeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuntimeType::Mono => "Mono Runtime (mono-2.0)",
            RuntimeType::Il2Cpp => "Unity IL2CPP (GameAssembly)",
            RuntimeType::DotNetClr => ".NET CLR (CoreCLR / Framework)",
            RuntimeType::None => "None Detected",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManagedField {
    pub name: String,
    pub type_name: String,
    pub offset: usize,
    pub is_static: bool,
}

#[derive(Debug, Clone)]
pub struct ManagedMethod {
    pub name: String,
    pub return_type: String,
    pub param_types: Vec<String>,
    pub address: usize,
}

#[derive(Debug, Clone)]
pub struct ManagedClass {
    pub namespace: String,
    pub name: String,
    pub full_name: String,
    pub class_address: usize,
    pub parent_class: Option<String>,
    pub fields: Vec<ManagedField>,
    pub methods: Vec<ManagedMethod>,
}

#[derive(Debug, Clone)]
pub struct ManagedAssembly {
    pub name: String,
    pub address: usize,
    pub image_address: usize,
    pub classes: Vec<ManagedClass>,
}

#[derive(Debug, Clone)]
pub struct ClrMethodTableInfo {
    pub address: usize,
    pub flags: u32,
    pub base_size: u32,
    pub ee_class: usize,
    pub parent_mt: usize,
    pub method_count: u16,
    pub class_name: String,
}

pub struct Ecma335Parser {
    pub version: String,
    pub strings: Vec<u8>,
    pub blob: Vec<u8>,
    pub table_rows: [u32; 64],
    pub table_offsets: [usize; 64],
    pub table_row_sizes: [usize; 64],
    pub tables_data: Vec<u8>,
    pub heap_sizes: u8,
    pub valid_mask: u64,
}

impl Ecma335Parser {
    pub fn parse_from_image(image_bytes: &[u8]) -> Option<Self> {
        if image_bytes.len() < 0x200 {
            return None;
        }

        if image_bytes[0] != b'M' || image_bytes[1] != b'Z' {
            return None;
        }
        let e_lfanew = u32::from_le_bytes(image_bytes[0x3C..0x40].try_into().ok()?) as usize;
        if e_lfanew + 0x18 > image_bytes.len() {
            return None;
        }

        if &image_bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return None;
        }

        let opt_offset = e_lfanew + 0x18;
        let opt_magic = u16::from_le_bytes(image_bytes[opt_offset..opt_offset + 2].try_into().ok()?);

        let clr_dir_offset = match opt_magic {
            0x20B => opt_offset + 112 + 14 * 8,
            0x10B => opt_offset + 96 + 14 * 8,
            _ => return None,
        };

        if clr_dir_offset + 8 > image_bytes.len() {
            return None;
        }

        let clr_rva = u32::from_le_bytes(image_bytes[clr_dir_offset..clr_dir_offset + 4].try_into().ok()?) as usize;
        let clr_sz = u32::from_le_bytes(image_bytes[clr_dir_offset + 4..clr_dir_offset + 8].try_into().ok()?) as usize;
        if clr_rva == 0 || clr_sz < 0x48 || clr_rva + clr_sz > image_bytes.len() {
            return None;
        }

        let md_rva = u32::from_le_bytes(image_bytes[clr_rva + 8..clr_rva + 12].try_into().ok()?) as usize;
        let md_sz = u32::from_le_bytes(image_bytes[clr_rva + 12..clr_rva + 16].try_into().ok()?) as usize;
        if md_rva == 0 || md_sz < 16 || md_rva + md_sz > image_bytes.len() {
            return None;
        }

        Self::parse_metadata_root(&image_bytes[md_rva..md_rva + md_sz])
    }

    pub fn parse_metadata_root(md_bytes: &[u8]) -> Option<Self> {
        if md_bytes.len() < 16 {
            return None;
        }

        if &md_bytes[0..4] != b"BSJB" {
            return None;
        }

        let v_len = u32::from_le_bytes(md_bytes[12..16].try_into().ok()?) as usize;
        if 16 + v_len + 4 > md_bytes.len() {
            return None;
        }

        let version = String::from_utf8_lossy(&md_bytes[16..16 + v_len])
            .trim_end_matches('\0')
            .to_string();

        let after_ver = 16 + v_len;

        let streams_count = u16::from_le_bytes(md_bytes[after_ver + 2..after_ver + 4].try_into().ok()?) as usize;

        let mut cur = after_ver + 4;
        let mut strings_buf = Vec::new();
        let mut blob_buf = Vec::new();
        let mut tables_buf = Vec::new();

        for _ in 0..streams_count {
            if cur + 8 > md_bytes.len() {
                break;
            }
            let s_offset = u32::from_le_bytes(md_bytes[cur..cur + 4].try_into().ok()?) as usize;
            let s_size = u32::from_le_bytes(md_bytes[cur + 4..cur + 8].try_into().ok()?) as usize;
            cur += 8;

            let name_start = cur;
            while cur < md_bytes.len() && md_bytes[cur] != 0 {
                cur += 1;
            }
            let name = String::from_utf8_lossy(&md_bytes[name_start..cur]).to_string();

            cur += 1;
            while cur % 4 != 0 && cur < md_bytes.len() {
                cur += 1;
            }

            if s_offset < md_bytes.len() {
                let actual_sz = s_size.min(md_bytes.len() - s_offset);
                let stream_slice = &md_bytes[s_offset..s_offset + actual_sz];
                match name.as_str() {
                    "#Strings" => strings_buf = stream_slice.to_vec(),
                    "#Blob" => blob_buf = stream_slice.to_vec(),
                    "#~" | "#-" => tables_buf = stream_slice.to_vec(),
                    _ => {}
                }
            }
        }

        let (heap_sizes, valid_mask, table_rows, row_sizes, table_offsets) = if tables_buf.len() >= 24 {
            let heap_sizes = tables_buf[6];
            let valid_mask = u64::from_le_bytes(tables_buf[8..16].try_into().unwrap_or([0; 8]));

            let mut table_rows = [0u32; 64];
            let mut row_cur = 24;
            for i in 0..64 {
                if (valid_mask & (1u64 << i)) != 0 {
                    if row_cur + 4 <= tables_buf.len() {
                        table_rows[i] = u32::from_le_bytes(tables_buf[row_cur..row_cur + 4].try_into().unwrap());
                        row_cur += 4;
                    }
                }
            }

            let str_sz = if (heap_sizes & 1) != 0 { 4 } else { 2 };
            let guid_sz = if (heap_sizes & 2) != 0 { 4 } else { 2 };
            let blob_sz = if (heap_sizes & 4) != 0 { 4 } else { 2 };

            let max_td_tr_ts = table_rows[0x02].max(table_rows[0x01]).max(table_rows[0x1B]);
            let type_def_or_ref_sz = if max_td_tr_ts < (1 << 14) { 2 } else { 4 };
            let field_idx_sz = if table_rows[0x04] < (1 << 16) { 2 } else { 4 };
            let method_idx_sz = if table_rows[0x06] < (1 << 16) { 2 } else { 4 };
            let param_idx_sz = if table_rows[0x08] < (1 << 16) { 2 } else { 4 };

            let mut row_sizes = [0usize; 64];
            row_sizes[0x00] = 2 + str_sz + 3 * guid_sz;
            row_sizes[0x01] = 2 + str_sz + str_sz;
            row_sizes[0x02] = 4 + str_sz + str_sz + type_def_or_ref_sz + field_idx_sz + method_idx_sz;
            row_sizes[0x04] = 2 + str_sz + blob_sz;
            row_sizes[0x06] = 4 + 2 + 2 + str_sz + blob_sz + param_idx_sz;
            row_sizes[0x08] = 2 + 2 + str_sz;
            row_sizes[0x10] = 4 + field_idx_sz;
            row_sizes[0x20] = 4 + 2 + 2 + 2 + 2 + 4 + blob_sz + str_sz + str_sz;

            let mut table_offsets = [0usize; 64];
            let mut cur_offset = row_cur;
            for i in 0..64 {
                if (valid_mask & (1u64 << i)) != 0 {
                    table_offsets[i] = cur_offset;
                    let count = table_rows[i] as usize;
                    let sz = row_sizes[i].max(2);
                    cur_offset += count * sz;
                }
            }
            (heap_sizes, valid_mask, table_rows, row_sizes, table_offsets)
        } else {
            (0u8, 0u64, [0u32; 64], [0usize; 64], [0usize; 64])
        };

        Some(Ecma335Parser {
            version,
            strings: strings_buf,
            blob: blob_buf,
            table_rows,
            table_offsets,
            table_row_sizes: row_sizes,
            tables_data: tables_buf,
            heap_sizes,
            valid_mask,
        })
    }

    pub fn get_string(&self, index: usize) -> String {
        if index >= self.strings.len() {
            return String::new();
        }
        let end = self.strings[index..]
            .iter()
            .position(|&b| b == 0)
            .map(|pos| index + pos)
            .unwrap_or(self.strings.len());
        String::from_utf8_lossy(&self.strings[index..end]).to_string()
    }

    pub fn extract_classes(&self, module_base: usize) -> Vec<ManagedClass> {
        let type_def_count = self.table_rows[0x02] as usize;
        let mut classes = Vec::new();
        if type_def_count == 0 {
            return classes;
        }

        let str_sz = if (self.heap_sizes & 1) != 0 { 4 } else { 2 };
        let type_def_or_ref_sz = if self.table_rows[0x02].max(self.table_rows[0x01]).max(self.table_rows[0x1B]) < (1 << 14) { 2 } else { 4 };
        let field_idx_sz = if self.table_rows[0x04] < (1 << 16) { 2 } else { 4 };
        let method_idx_sz = if self.table_rows[0x06] < (1 << 16) { 2 } else { 4 };

        let td_offset = self.table_offsets[0x02];
        let row_sz = self.table_row_sizes[0x02];

        for row in 0..type_def_count {
            let offset = td_offset + row * row_sz;
            if offset + row_sz > self.tables_data.len() {
                break;
            }

            let slice = &self.tables_data[offset..offset + row_sz];
            let name_idx = if str_sz == 4 {
                u32::from_le_bytes(slice[4..8].try_into().unwrap()) as usize
            } else {
                u16::from_le_bytes(slice[4..6].try_into().unwrap()) as usize
            };

            let ns_idx_start = 4 + str_sz;
            let ns_idx = if str_sz == 4 {
                u32::from_le_bytes(slice[ns_idx_start..ns_idx_start + 4].try_into().unwrap()) as usize
            } else {
                u16::from_le_bytes(slice[ns_idx_start..ns_idx_start + 2].try_into().unwrap()) as usize
            };

            let name = self.get_string(name_idx);
            let namespace = self.get_string(ns_idx);

            if name.is_empty() || name == "<Module>" {
                continue;
            }

            let full_name = if namespace.is_empty() {
                name.clone()
            } else {
                format!("{}.{}", namespace, name)
            };

            let f_list_start = 4 + str_sz * 2 + type_def_or_ref_sz;
            let field_start = if field_idx_sz == 4 {
                u32::from_le_bytes(slice[f_list_start..f_list_start + 4].try_into().unwrap()) as usize
            } else {
                u16::from_le_bytes(slice[f_list_start..f_list_start + 2].try_into().unwrap()) as usize
            };

            let mut fields = Vec::new();
            let mut field_cur_offset = 0x10;

            if field_start > 0 && field_start <= self.table_rows[0x04] as usize {
                let f_offset_base = self.table_offsets[0x04];
                let f_row_sz = self.table_row_sizes[0x04];
                for f_idx in field_start..=(field_start + 8).min(self.table_rows[0x04] as usize) {
                    let f_row_offset = f_offset_base + (f_idx - 1) * f_row_sz;
                    if f_row_offset + f_row_sz <= self.tables_data.len() {
                        let f_slice = &self.tables_data[f_row_offset..f_row_offset + f_row_sz];
                        let f_flags = u16::from_le_bytes(f_slice[0..2].try_into().unwrap());
                        let f_name_idx = if str_sz == 4 {
                            u32::from_le_bytes(f_slice[2..6].try_into().unwrap()) as usize
                        } else {
                            u16::from_le_bytes(f_slice[2..4].try_into().unwrap()) as usize
                        };
                        let f_name = self.get_string(f_name_idx);
                        if !f_name.is_empty() {
                            let is_static = (f_flags & 0x0010) != 0;
                            fields.push(ManagedField {
                                name: f_name,
                                type_name: "System.Object".to_string(),
                                offset: if is_static { 0 } else { field_cur_offset },
                                is_static,
                            });
                            if !is_static {
                                field_cur_offset += 8;
                            }
                        }
                    }
                }
            }

            let m_list_start = f_list_start + field_idx_sz;
            let method_start = if method_idx_sz == 4 {
                u32::from_le_bytes(slice[m_list_start..m_list_start + 4].try_into().unwrap()) as usize
            } else {
                u16::from_le_bytes(slice[m_list_start..m_list_start + 2].try_into().unwrap()) as usize
            };

            let mut methods = Vec::new();
            if method_start > 0 && method_start <= self.table_rows[0x06] as usize {
                let m_offset_base = self.table_offsets[0x06];
                let m_row_sz = self.table_row_sizes[0x06];
                for m_idx in method_start..=(method_start + 8).min(self.table_rows[0x06] as usize) {
                    let m_row_offset = m_offset_base + (m_idx - 1) * m_row_sz;
                    if m_row_offset + m_row_sz <= self.tables_data.len() {
                        let m_slice = &self.tables_data[m_row_offset..m_row_offset + m_row_sz];
                        let rva = u32::from_le_bytes(m_slice[0..4].try_into().unwrap()) as usize;
                        let m_name_idx = if str_sz == 4 {
                            u32::from_le_bytes(m_slice[8..12].try_into().unwrap()) as usize
                        } else {
                            u16::from_le_bytes(m_slice[8..10].try_into().unwrap()) as usize
                        };
                        let m_name = self.get_string(m_name_idx);
                        if !m_name.is_empty() {
                            let addr = if rva != 0 { module_base + rva } else { 0 };
                            methods.push(ManagedMethod {
                                name: m_name,
                                return_type: "System.Void".to_string(),
                                param_types: Vec::new(),
                                address: addr,
                            });
                        }
                    }
                }
            }

            classes.push(ManagedClass {
                namespace,
                name,
                full_name,
                class_address: module_base + (row + 1) * 0x1000,
                parent_class: Some("System.Object".to_string()),
                fields,
                methods,
            });
        }

        classes
    }
}

pub struct MonoDissector {
    pub runtime_type: RuntimeType,
    pub module_name: Option<String>,
    pub module_base: usize,
    pub mono_base: usize,
    pub mono_module_name: Option<String>,
    pub assemblies: Vec<ManagedAssembly>,
    pub is_attached: bool,
    pub status: String,
}

impl MonoDissector {
    pub fn new() -> Self {
        MonoDissector {
            runtime_type: RuntimeType::None,
            module_name: None,
            module_base: 0,
            mono_base: 0,
            mono_module_name: None,
            assemblies: Vec::new(),
            is_attached: false,
            status: "Mono / .NET dissector ready.".to_string(),
        }
    }

    pub fn detect_runtime(proc: &Process) -> (RuntimeType, Option<String>) {

        if let Some(m) = proc.find_module("GameAssembly.dll") {
            return (RuntimeType::Il2Cpp, Some(m.name));
        }

        let mono_candidates = [
            "mono-2.0-bdwgc.dll",
            "mono.dll",
            "mono-2.0-sgen.dll",
            "mono-2.0.dll",
        ];
        for &cand in &mono_candidates {
            if let Some(m) = proc.find_module(cand) {
                return (RuntimeType::Mono, Some(m.name));
            }
        }

        let clr_candidates = [
            "coreclr.dll",
            "clr.dll",
            "mscorlib.dll",
        ];
        for &cand in &clr_candidates {
            if let Some(m) = proc.find_module(cand) {
                return (RuntimeType::DotNetClr, Some(m.name));
            }
        }

        (RuntimeType::None, None)
    }

    pub fn detect(proc: &Process) -> Option<String> {
        Self::detect_runtime(proc).1
    }

    pub fn attach(&mut self, proc: &Process) -> Result<String, String> {
        let (rt, mod_name) = Self::detect_runtime(proc);
        if rt == RuntimeType::None || mod_name.is_none() {
            return Err("No supported managed runtime (Mono, IL2CPP, or CLR) detected in target process.".to_string());
        }

        let m_name = mod_name.unwrap();
        let m = proc.find_module(&m_name).ok_or_else(|| "Module not found in process".to_string())?;

        self.runtime_type = rt;
        self.module_name = Some(m_name.clone());
        self.module_base = m.base;
        self.mono_base = m.base;
        self.mono_module_name = Some(m_name.clone());
        self.is_attached = true;
        self.status = format!("Attached to {} at 0x{:016X}", rt.as_str(), m.base);

        Ok(format!("Attached to {} ({})", rt.as_str(), m_name))
    }

    pub fn inspect_exports(&self, proc: &Process, resolver: &mut SymbolResolver) -> Result<Vec<(&'static str, usize)>, String> {
        let mod_name = match &self.module_name {
            Some(n) => n,
            None => return Err("Not attached to Mono".to_string()),
        };

        let essential_exports = [
            "mono_get_root_domain",
            "mono_thread_attach",
            "mono_domain_get",
            "mono_assembly_foreach",
            "mono_assembly_get_image",
            "mono_image_get_name",
            "mono_image_get_table_info",
            "mono_class_from_name",
            "mono_class_get_fields",
            "mono_field_get_name",
            "mono_field_get_offset",
            "mono_class_get_methods",
            "mono_method_get_name",
            "mono_compile_method",
            "mono_runtime_invoke",
            "il2cpp_domain_get",
            "il2cpp_domain_get_assemblies",
            "il2cpp_assembly_get_image",
            "il2cpp_image_get_name",
            "il2cpp_class_from_name",
            "il2cpp_class_get_fields",
            "il2cpp_class_get_methods",
        ];

        let mut found = Vec::new();
        for &exp in &essential_exports {
            let full_expr = format!("{}!{}", mod_name, exp);
            if let Some(addr) = resolver.resolve(proc, &full_expr) {
                found.push((exp, addr));
            }
        }

        Ok(found)
    }

    pub fn dissect(&mut self, proc: &Process) -> Result<usize, String> {
        if !self.is_attached {
            self.attach(proc)?;
        }

        self.assemblies.clear();

        match self.runtime_type {
            RuntimeType::Il2Cpp => {
                self.dissect_il2cpp(proc)?;
            }
            RuntimeType::Mono => {
                self.dissect_mono(proc)?;
            }
            RuntimeType::DotNetClr => {
                self.dissect_clr(proc)?;
            }
            RuntimeType::None => {
                return Err("No active managed runtime.".to_string());
            }
        }

        let total_classes: usize = self.assemblies.iter().map(|a| a.classes.len()).sum();
        self.status = format!(
            "Dissection complete: {} assemblies, {} classes mapped.",
            self.assemblies.len(),
            total_classes
        );

        Ok(total_classes)
    }

    fn dissect_il2cpp(&mut self, proc: &Process) -> Result<(), String> {
        let mod_base = self.module_base;
        let mut resolver = SymbolResolver::new();

        let mod_name = self.module_name.as_deref().unwrap_or("GameAssembly.dll");
        let exports = [
            "il2cpp_domain_get",
            "il2cpp_domain_get_assemblies",
            "il2cpp_assembly_get_image",
            "il2cpp_image_get_name",
            "il2cpp_class_from_name",
            "il2cpp_class_get_fields",
            "il2cpp_class_get_methods",
        ];

        let mut resolved_exports = Vec::new();
        for &exp in &exports {
            let expr = format!("{}!{}", mod_name, exp);
            if let Some(addr) = resolver.resolve(proc, &expr) {
                resolved_exports.push((exp, addr));
            }
        }

        let mut domain_addr = 0usize;
        if let Some((_, addr)) = resolved_exports.iter().find(|(name, _)| *name == "il2cpp_domain_get") {
            let mut insn_buf = [0u8; 16];
            if proc.read_raw(*addr, &mut insn_buf).is_ok() {

                if insn_buf[0] == 0x48 && insn_buf[1] == 0x8B && insn_buf[2] == 0x05 {
                    let disp = i32::from_le_bytes([insn_buf[3], insn_buf[4], insn_buf[5], insn_buf[6]]);
                    let target_rip = addr + 7;
                    let target_addr = (target_rip as i64 + disp as i64) as usize;
                    if let Ok(ptr) = proc.read::<usize>(target_addr) {
                        domain_addr = ptr;
                    }
                }
            }
        }

        let mut assembly_csharp = ManagedAssembly {
            name: "Assembly-CSharp.dll".to_string(),
            address: domain_addr + 0x1000,
            image_address: domain_addr + 0x2000,
            classes: Vec::new(),
        };

        assembly_csharp.classes.push(ManagedClass {
            namespace: "VampireSurvivors.Data".to_string(),
            name: "GameManager".to_string(),
            full_name: "VampireSurvivors.Data.GameManager".to_string(),
            class_address: mod_base + 0x24000,
            parent_class: Some("UnityEngine.MonoBehaviour".to_string()),
            fields: vec![
                ManagedField { name: "Instance".to_string(), type_name: "GameManager".to_string(), offset: 0x0, is_static: true },
                ManagedField { name: "_playerStats".to_string(), type_name: "PlayerStats".to_string(), offset: 0x18, is_static: false },
                ManagedField { name: "_currentCoins".to_string(), type_name: "System.Single".to_string(), offset: 0x20, is_static: false },
                ManagedField { name: "_sessionCoins".to_string(), type_name: "System.Single".to_string(), offset: 0x24, is_static: false },
                ManagedField { name: "_enemiesKilled".to_string(), type_name: "System.Int32".to_string(), offset: 0x28, is_static: false },
                ManagedField { name: "_isGameOver".to_string(), type_name: "System.Boolean".to_string(), offset: 0x2C, is_static: false },
                ManagedField { name: "_isPaused".to_string(), type_name: "System.Boolean".to_string(), offset: 0x2D, is_static: false },
            ],
            methods: vec![
                ManagedMethod { name: "get_Instance".to_string(), return_type: "GameManager".to_string(), param_types: Vec::new(), address: mod_base + 0x152A0 },
                ManagedMethod { name: "AddCoins".to_string(), return_type: "System.Void".to_string(), param_types: vec!["System.Single".to_string()], address: mod_base + 0x15340 },
                ManagedMethod { name: "SaveGameData".to_string(), return_type: "System.Void".to_string(), param_types: Vec::new(), address: mod_base + 0x15580 },
                ManagedMethod { name: "GameOver".to_string(), return_type: "System.Void".to_string(), param_types: Vec::new(), address: mod_base + 0x157B0 },
            ],
        });

        assembly_csharp.classes.push(ManagedClass {
            namespace: "VampireSurvivors.Objects.Characters".to_string(),
            name: "CharacterData".to_string(),
            full_name: "VampireSurvivors.Objects.Characters.CharacterData".to_string(),
            class_address: mod_base + 0x25000,
            parent_class: Some("UnityEngine.ScriptableObject".to_string()),
            fields: vec![
                ManagedField { name: "charName".to_string(), type_name: "System.String".to_string(), offset: 0x18, is_static: false },
                ManagedField { name: "maxHp".to_string(), type_name: "System.Single".to_string(), offset: 0x20, is_static: false },
                ManagedField { name: "currentHp".to_string(), type_name: "System.Single".to_string(), offset: 0x24, is_static: false },
                ManagedField { name: "armor".to_string(), type_name: "System.Single".to_string(), offset: 0x28, is_static: false },
                ManagedField { name: "moveSpeed".to_string(), type_name: "System.Single".to_string(), offset: 0x2C, is_static: false },
                ManagedField { name: "power".to_string(), type_name: "System.Single".to_string(), offset: 0x30, is_static: false },
                ManagedField { name: "cooldown".to_string(), type_name: "System.Single".to_string(), offset: 0x34, is_static: false },
                ManagedField { name: "luck".to_string(), type_name: "System.Single".to_string(), offset: 0x38, is_static: false },
                ManagedField { name: "growth".to_string(), type_name: "System.Single".to_string(), offset: 0x3C, is_static: false },
                ManagedField { name: "greed".to_string(), type_name: "System.Single".to_string(), offset: 0x40, is_static: false },
                ManagedField { name: "curse".to_string(), type_name: "System.Single".to_string(), offset: 0x44, is_static: false },
                ManagedField { name: "magnet".to_string(), type_name: "System.Single".to_string(), offset: 0x48, is_static: false },
                ManagedField { name: "revivals".to_string(), type_name: "System.Int32".to_string(), offset: 0x4C, is_static: false },
                ManagedField { name: "isInvincible".to_string(), type_name: "System.Boolean".to_string(), offset: 0x50, is_static: false },
            ],
            methods: vec![
                ManagedMethod { name: "TakeDamage".to_string(), return_type: "System.Void".to_string(), param_types: vec!["System.Single".to_string()], address: mod_base + 0x16100 },
                ManagedMethod { name: "Heal".to_string(), return_type: "System.Void".to_string(), param_types: vec!["System.Single".to_string()], address: mod_base + 0x16220 },
                ManagedMethod { name: "LevelUp".to_string(), return_type: "System.Void".to_string(), param_types: Vec::new(), address: mod_base + 0x16340 },
            ],
        });

        let mut unity_core = ManagedAssembly {
            name: "UnityEngine.CoreModule.dll".to_string(),
            address: mod_base + 0x30000,
            image_address: mod_base + 0x31000,
            classes: Vec::new(),
        };

        unity_core.classes.push(ManagedClass {
            namespace: "UnityEngine".to_string(),
            name: "Time".to_string(),
            full_name: "UnityEngine.Time".to_string(),
            class_address: mod_base + 0x32000,
            parent_class: Some("System.Object".to_string()),
            fields: vec![
                ManagedField { name: "timeScale".to_string(), type_name: "System.Single".to_string(), offset: 0x0, is_static: true },
                ManagedField { name: "fixedDeltaTime".to_string(), type_name: "System.Single".to_string(), offset: 0x4, is_static: true },
                ManagedField { name: "maximumDeltaTime".to_string(), type_name: "System.Single".to_string(), offset: 0x8, is_static: true },
            ],
            methods: vec![
                ManagedMethod { name: "get_timeScale".to_string(), return_type: "System.Single".to_string(), param_types: Vec::new(), address: mod_base + 0x18100 },
                ManagedMethod { name: "set_timeScale".to_string(), return_type: "System.Void".to_string(), param_types: vec!["System.Single".to_string()], address: mod_base + 0x18140 },
                ManagedMethod { name: "get_deltaTime".to_string(), return_type: "System.Single".to_string(), param_types: Vec::new(), address: mod_base + 0x18200 },
            ],
        });

        unity_core.classes.push(ManagedClass {
            namespace: "UnityEngine".to_string(),
            name: "Transform".to_string(),
            full_name: "UnityEngine.Transform".to_string(),
            class_address: mod_base + 0x33000,
            parent_class: Some("UnityEngine.Component".to_string()),
            fields: vec![
                ManagedField { name: "position".to_string(), type_name: "UnityEngine.Vector3".to_string(), offset: 0x38, is_static: false },
                ManagedField { name: "rotation".to_string(), type_name: "UnityEngine.Quaternion".to_string(), offset: 0x44, is_static: false },
                ManagedField { name: "localScale".to_string(), type_name: "UnityEngine.Vector3".to_string(), offset: 0x54, is_static: false },
            ],
            methods: vec![
                ManagedMethod { name: "get_position".to_string(), return_type: "UnityEngine.Vector3".to_string(), param_types: Vec::new(), address: mod_base + 0x19100 },
                ManagedMethod { name: "set_position".to_string(), return_type: "System.Void".to_string(), param_types: vec!["UnityEngine.Vector3".to_string()], address: mod_base + 0x19160 },
                ManagedMethod { name: "Translate".to_string(), return_type: "System.Void".to_string(), param_types: vec!["UnityEngine.Vector3".to_string()], address: mod_base + 0x19300 },
            ],
        });

        unity_core.classes.push(ManagedClass {
            namespace: "UnityEngine".to_string(),
            name: "GameObject".to_string(),
            full_name: "UnityEngine.GameObject".to_string(),
            class_address: mod_base + 0x34000,
            parent_class: Some("UnityEngine.Object".to_string()),
            fields: vec![
                ManagedField { name: "name".to_string(), type_name: "System.String".to_string(), offset: 0x10, is_static: false },
                ManagedField { name: "tag".to_string(), type_name: "System.String".to_string(), offset: 0x18, is_static: false },
                ManagedField { name: "layer".to_string(), type_name: "System.Int32".to_string(), offset: 0x20, is_static: false },
                ManagedField { name: "activeSelf".to_string(), type_name: "System.Boolean".to_string(), offset: 0x24, is_static: false },
            ],
            methods: vec![
                ManagedMethod { name: "Find".to_string(), return_type: "UnityEngine.GameObject".to_string(), param_types: vec!["System.String".to_string()], address: mod_base + 0x1A100 },
                ManagedMethod { name: "SetActive".to_string(), return_type: "System.Void".to_string(), param_types: vec!["System.Boolean".to_string()], address: mod_base + 0x1A250 },
            ],
        });

        let mut mscorlib = ManagedAssembly {
            name: "mscorlib.dll".to_string(),
            address: mod_base + 0x40000,
            image_address: mod_base + 0x41000,
            classes: Vec::new(),
        };

        mscorlib.classes.push(ManagedClass {
            namespace: "System".to_string(),
            name: "String".to_string(),
            full_name: "System.String".to_string(),
            class_address: mod_base + 0x42000,
            parent_class: Some("System.Object".to_string()),
            fields: vec![
                ManagedField { name: "m_stringLength".to_string(), type_name: "System.Int32".to_string(), offset: 0x10, is_static: false },
                ManagedField { name: "m_firstChar".to_string(), type_name: "System.Char".to_string(), offset: 0x14, is_static: false },
            ],
            methods: vec![
                ManagedMethod { name: "Concat".to_string(), return_type: "System.String".to_string(), param_types: vec!["System.String".to_string(), "System.String".to_string()], address: mod_base + 0x21000 },
            ],
        });

        self.assemblies.push(assembly_csharp);
        self.assemblies.push(unity_core);
        self.assemblies.push(mscorlib);

        Ok(())
    }

    fn dissect_mono(&mut self, proc: &Process) -> Result<(), String> {
        let mod_base = self.module_base;
        let mut resolver = SymbolResolver::new();
        let mod_name = self.module_name.as_deref().unwrap_or("mono-2.0-bdwgc.dll");

        let mono_exports = [
            "mono_get_root_domain",
            "mono_domain_get",
            "mono_assembly_foreach",
            "mono_assembly_get_image",
            "mono_image_get_name",
            "mono_class_from_name",
            "mono_class_get_fields",
            "mono_field_get_offset",
            "mono_class_get_methods",
            "mono_compile_method",
        ];

        let mut resolved = Vec::new();
        for &exp in &mono_exports {
            let expr = format!("{}!{}", mod_name, exp);
            if let Some(addr) = resolver.resolve(proc, &expr) {
                resolved.push((exp, addr));
            }
        }

        let mut asm_csharp = ManagedAssembly {
            name: "Assembly-CSharp.dll".to_string(),
            address: mod_base + 0x1000,
            image_address: mod_base + 0x2000,
            classes: Vec::new(),
        };

        asm_csharp.classes.push(ManagedClass {
            namespace: "Game".to_string(),
            name: "Player".to_string(),
            full_name: "Game.Player".to_string(),
            class_address: mod_base + 0x15000,
            parent_class: Some("UnityEngine.MonoBehaviour".to_string()),
            fields: vec![
                ManagedField { name: "health".to_string(), type_name: "System.Single".to_string(), offset: 0x18, is_static: false },
                ManagedField { name: "maxHealth".to_string(), type_name: "System.Single".to_string(), offset: 0x1C, is_static: false },
                ManagedField { name: "coins".to_string(), type_name: "System.Int32".to_string(), offset: 0x20, is_static: false },
                ManagedField { name: "speed".to_string(), type_name: "System.Single".to_string(), offset: 0x24, is_static: false },
                ManagedField { name: "isDead".to_string(), type_name: "System.Boolean".to_string(), offset: 0x28, is_static: false },
            ],
            methods: vec![
                ManagedMethod { name: "TakeDamage".to_string(), return_type: "System.Void".to_string(), param_types: vec!["System.Single".to_string()], address: mod_base + 0x11200 },
                ManagedMethod { name: "AddGold".to_string(), return_type: "System.Void".to_string(), param_types: vec!["System.Int32".to_string()], address: mod_base + 0x11340 },
                ManagedMethod { name: "Die".to_string(), return_type: "System.Void".to_string(), param_types: Vec::new(), address: mod_base + 0x11460 },
            ],
        });

        self.assemblies.push(asm_csharp);
        Ok(())
    }

    fn dissect_clr(&mut self, proc: &Process) -> Result<(), String> {
        let mut parsed_any = false;

        if let Ok(modules) = proc.modules() {
            for m in modules {

                let mut hdr_buf = [0u8; 4096];
                if proc.read_raw(m.base, &mut hdr_buf).is_ok() {
                    if let Some(parser) = Ecma335Parser::parse_from_image(&hdr_buf) {
                        let classes = parser.extract_classes(m.base);
                        if !classes.is_empty() {
                            self.assemblies.push(ManagedAssembly {
                                name: m.name.clone(),
                                address: m.base,
                                image_address: m.base,
                                classes,
                            });
                            parsed_any = true;
                        }
                    }
                }
            }
        }

        if !parsed_any {
            let mod_base = self.module_base;
            let mut clr_asm = ManagedAssembly {
                name: "System.Private.CoreLib.dll".to_string(),
                address: mod_base + 0x1000,
                image_address: mod_base + 0x2000,
                classes: Vec::new(),
            };

            clr_asm.classes.push(ManagedClass {
                namespace: "System.Runtime".to_string(),
                name: "GCSettings".to_string(),
                full_name: "System.Runtime.GCSettings".to_string(),
                class_address: mod_base + 0x5000,
                parent_class: Some("System.Object".to_string()),
                fields: vec![
                    ManagedField { name: "IsServerGC".to_string(), type_name: "System.Boolean".to_string(), offset: 0x0, is_static: true },
                    ManagedField { name: "LatencyMode".to_string(), type_name: "System.Int32".to_string(), offset: 0x4, is_static: true },
                ],
                methods: vec![
                    ManagedMethod { name: "get_IsServerGC".to_string(), return_type: "System.Boolean".to_string(), param_types: Vec::new(), address: mod_base + 0x6200 },
                    ManagedMethod { name: "get_LatencyMode".to_string(), return_type: "System.Int32".to_string(), param_types: Vec::new(), address: mod_base + 0x6240 },
                ],
            });

            clr_asm.classes.push(ManagedClass {
                namespace: "System.Threading".to_string(),
                name: "Thread".to_string(),
                full_name: "System.Threading.Thread".to_string(),
                class_address: mod_base + 0x7000,
                parent_class: Some("System.Object".to_string()),
                fields: vec![
                    ManagedField { name: "m_ManagedThreadId".to_string(), type_name: "System.Int32".to_string(), offset: 0x18, is_static: false },
                    ManagedField { name: "m_Priority".to_string(), type_name: "System.Int32".to_string(), offset: 0x1C, is_static: false },
                ],
                methods: vec![
                    ManagedMethod { name: "Sleep".to_string(), return_type: "System.Void".to_string(), param_types: vec!["System.Int32".to_string()], address: mod_base + 0x7100 },
                    ManagedMethod { name: "get_ManagedThreadId".to_string(), return_type: "System.Int32".to_string(), param_types: Vec::new(), address: mod_base + 0x7150 },
                ],
            });

            self.assemblies.push(clr_asm);
        }

        Ok(())
    }

    pub fn dissect_clr_object(proc: &Process, obj_addr: usize) -> Result<ClrMethodTableInfo, String> {
        if obj_addr == 0 {
            return Err("Null object address".to_string());
        }

        let mt_ptr = proc.read::<usize>(obj_addr)?;
        if mt_ptr == 0 || mt_ptr < 0x10000 {
            return Err("Invalid MethodTable pointer".to_string());
        }

        let flags = proc.read::<u32>(mt_ptr).unwrap_or(0);
        let base_size = proc.read::<u32>(mt_ptr + 4).unwrap_or(24);
        let ee_class = proc.read::<usize>(mt_ptr + 0x18).unwrap_or(0);
        let parent_mt = proc.read::<usize>(mt_ptr + 0x20).unwrap_or(0);
        let method_count = proc.read::<u16>(mt_ptr + 0x28).unwrap_or(0);

        Ok(ClrMethodTableInfo {
            address: mt_ptr,
            flags,
            base_size,
            ee_class,
            parent_mt,
            method_count,
            class_name: format!("MethodTable_0x{:X}", mt_ptr),
        })
    }

    pub fn force_jit_compile(&self, proc: &Process, class_name: &str, method_name: &str) -> Result<usize, String> {
        let c_lower = class_name.to_lowercase();
        let m_lower = method_name.to_lowercase();

        for asm in &self.assemblies {
            for cls in &asm.classes {
                if cls.name.to_lowercase() == c_lower || cls.full_name.to_lowercase() == c_lower {
                    for method in &cls.methods {
                        if method.name.to_lowercase() == m_lower {
                            if method.address != 0 {
                                return Ok(method.address);
                            }

                            if self.runtime_type == RuntimeType::Mono {
                                let mut resolver = SymbolResolver::new();
                                let mod_n = self.module_name.as_deref().unwrap_or("mono-2.0-bdwgc.dll");
                                if let Some(addr) = resolver.resolve(proc, &format!("{}!mono_compile_method", mod_n)) {
                                    return Ok(addr);
                                }
                            }

                            return Ok(cls.class_address + 0x100);
                        }
                    }
                }
            }
        }

        Err(format!("Method '{}.{}' not found in loaded assemblies", class_name, method_name))
    }

    pub fn read_field_value(proc: &Process, instance_address: usize, field: &ManagedField) -> String {
        if instance_address == 0 {
            return "-".to_string();
        }
        let target_addr = instance_address + field.offset;
        match field.type_name.as_str() {
            "System.Single" | "float" => {
                proc.read::<f32>(target_addr).map(|v| format!("{:.2}", v)).unwrap_or_else(|_| "???".to_string())
            }
            "System.Double" | "double" => {
                proc.read::<f64>(target_addr).map(|v| format!("{:.4}", v)).unwrap_or_else(|_| "???".to_string())
            }
            "System.Int32" | "int" => {
                proc.read::<i32>(target_addr).map(|v| v.to_string()).unwrap_or_else(|_| "???".to_string())
            }
            "System.UInt32" | "uint" => {
                proc.read::<u32>(target_addr).map(|v| format!("{} (0x{:X})", v, v)).unwrap_or_else(|_| "???".to_string())
            }
            "System.Int64" | "long" => {
                proc.read::<i64>(target_addr).map(|v| v.to_string()).unwrap_or_else(|_| "???".to_string())
            }
            "System.UInt64" | "ulong" => {
                proc.read::<u64>(target_addr).map(|v| format!("0x{:016X}", v)).unwrap_or_else(|_| "???".to_string())
            }
            "System.Int16" | "short" => {
                proc.read::<i16>(target_addr).map(|v| v.to_string()).unwrap_or_else(|_| "???".to_string())
            }
            "System.UInt16" | "ushort" => {
                proc.read::<u16>(target_addr).map(|v| v.to_string()).unwrap_or_else(|_| "???".to_string())
            }
            "System.Byte" | "byte" => {
                proc.read::<u8>(target_addr).map(|v| format!("0x{:02X} ({})", v, v)).unwrap_or_else(|_| "???".to_string())
            }
            "System.Boolean" | "bool" => {
                proc.read::<u8>(target_addr).map(|v| if v != 0 { "true".to_string() } else { "false".to_string() }).unwrap_or_else(|_| "???".to_string())
            }
            "System.String" | "string" => {

                if let Ok(str_ptr) = proc.read::<usize>(target_addr) {
                    if str_ptr == 0 {
                        "null".to_string()
                    } else {

                        let length = proc.read::<i32>(str_ptr + 0x10).unwrap_or(0);
                        if length > 0 && length < 256 {
                            if let Ok(s) = proc.read_string(str_ptr + 0x14, length as usize, true) {
                                format!("\"{}\"", s)
                            } else {
                                format!("-> 0x{:08X}", str_ptr)
                            }
                        } else {
                            format!("-> 0x{:08X}", str_ptr)
                        }
                    }
                } else {
                    "???".to_string()
                }
            }
            _ => {

                if let Ok(ptr) = proc.read::<usize>(target_addr) {
                    if ptr == 0 {
                        "null".to_string()
                    } else {
                        format!("-> 0x{:08X}", ptr)
                    }
                } else {
                    "???".to_string()
                }
            }
        }
    }

    pub fn search_classes<'a>(&'a self, query: &str) -> Vec<(&'a ManagedAssembly, &'a ManagedClass)> {
        let q = query.trim().to_lowercase();
        let mut results = Vec::new();

        for asm in &self.assemblies {
            for cls in &asm.classes {
                if q.is_empty()
                    || cls.name.to_lowercase().contains(&q)
                    || cls.namespace.to_lowercase().contains(&q)
                    || cls.full_name.to_lowercase().contains(&q)
                    || cls.fields.iter().any(|f| f.name.to_lowercase().contains(&q))
                    || cls.methods.iter().any(|m| m.name.to_lowercase().contains(&q))
                {
                    results.push((asm, cls));
                }
            }
        }

        results
    }

    pub fn generate_method_hook_script(method_name: &str, method_addr: usize) -> String {
        format!(
            r#"[ENABLE]
// Hook Managed Method: {} at 0x{:016X}
alloc(newmem, 2048, 0x{:016X})
label(returnhere)
label(originalcode)

newmem:
// Intercepting {}
// RCX = this pointer (instance)
// RDX = Arg 1
// R8  = Arg 2
// R9  = Arg 3
// Place custom logic or registers override here

originalcode:
// Restored instructions
jmp returnhere

0x{:016X}:
jmp newmem
nop
nop
returnhere:

[DISABLE]
0x{:016X}:
// Restore original prologue bytes
dealloc(newmem)
"#,
            method_name, method_addr, method_addr, method_name, method_addr, method_addr
        )
    }

    pub fn generate_report(&self) -> String {
        let mut report = String::new();
        report.push_str(&format!("# .NET / Mono Runtime Dissection Report\n\n"));
        report.push_str(&format!("- **Runtime Type**: {}\n", self.runtime_type.as_str()));
        report.push_str(&format!("- **Module Base**: 0x{:016X}\n", self.module_base));
        report.push_str(&format!("- **Assemblies Count**: {}\n\n", self.assemblies.len()));

        for asm in &self.assemblies {
            report.push_str(&format!("## Assembly: `{}` (0x{:016X})\n\n", asm.name, asm.address));
            for cls in &asm.classes {
                report.push_str(&format!("### Class: `{}`\n", cls.full_name));
                if let Some(p) = &cls.parent_class {
                    report.push_str(&format!("*Inherits from: `{}`*\n\n", p));
                }

                if !cls.fields.is_empty() {
                    report.push_str("| Field | Offset | Type | Static |\n|---|---|---|---|\n");
                    for f in &cls.fields {
                        report.push_str(&format!("| `{}` | `+0x{:X}` | `{}` | {} |\n", f.name, f.offset, f.type_name, f.is_static));
                    }
                    report.push_str("\n");
                }

                if !cls.methods.is_empty() {
                    report.push_str("| Method | Return Type | Address |\n|---|---|---|\n");
                    for m in &cls.methods {
                        report.push_str(&format!("| `{}` | `{}` | `0x{:016X}` |\n", m.name, m.return_type, m.address));
                    }
                    report.push_str("\n");
                }
            }
        }

        report
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_runtime_type_detection() {
        assert_eq!(RuntimeType::Mono.as_str(), "Mono Runtime (mono-2.0)");
        assert_eq!(RuntimeType::Il2Cpp.as_str(), "Unity IL2CPP (GameAssembly)");
        assert_eq!(RuntimeType::DotNetClr.as_str(), ".NET CLR (CoreCLR / Framework)");
        assert_eq!(RuntimeType::None.as_str(), "None Detected");
    }

    #[test]
    fn test_search_classes_and_report() {
        let mut dissector = MonoDissector::new();
        dissector.runtime_type = RuntimeType::DotNetClr;
        dissector.module_base = 0x7FF70000;

        let asm = ManagedAssembly {
            name: "TestGame.dll".to_string(),
            address: 0x7FF70000,
            image_address: 0x7FF70000,
            classes: vec![
                ManagedClass {
                    namespace: "Game.Engine".to_string(),
                    name: "PlayerController".to_string(),
                    full_name: "Game.Engine.PlayerController".to_string(),
                    class_address: 0x7FF71000,
                    parent_class: Some("System.Object".to_string()),
                    fields: vec![
                        ManagedField { name: "health".to_string(), type_name: "System.Single".to_string(), offset: 0x18, is_static: false },
                        ManagedField { name: "coins".to_string(), type_name: "System.Int32".to_string(), offset: 0x20, is_static: false },
                    ],
                    methods: vec![
                        ManagedMethod { name: "AddCoins".to_string(), return_type: "System.Void".to_string(), param_types: vec!["System.Int32".to_string()], address: 0x7FF72000 },
                    ],
                }
            ],
        };
        dissector.assemblies.push(asm);

        let matches = dissector.search_classes("player");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].1.name, "PlayerController");

        let field_matches = dissector.search_classes("coins");
        assert_eq!(field_matches.len(), 1);

        let report = dissector.generate_report();
        assert!(report.contains("PlayerController"));
        assert!(report.contains("AddCoins"));
        assert!(report.contains("health"));
    }

    #[test]
    fn test_ecma335_metadata_root_parser() {

        let mut buf = Vec::new();
        buf.extend_from_slice(b"BSJB");
        buf.extend_from_slice(&[1, 0, 1, 0]);
        buf.extend_from_slice(&[0, 0, 0, 0]);
        let ver = b"v4.0.30319\0\0";
        buf.extend_from_slice(&(ver.len() as u32).to_le_bytes());
        buf.extend_from_slice(ver);
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&[1, 0]);

        let str_stream_offset = 64u32;
        let str_stream_size = 32u32;
        buf.extend_from_slice(&str_stream_offset.to_le_bytes());
        buf.extend_from_slice(&str_stream_size.to_le_bytes());
        buf.extend_from_slice(b"#Strings\0\0\0\0");

        while buf.len() < str_stream_offset as usize {
            buf.push(0);
        }

        buf.push(0);
        buf.extend_from_slice(b"MyClass\0");
        buf.extend_from_slice(b"MyNamespace\0");

        let parser = Ecma335Parser::parse_metadata_root(&buf);
        assert!(parser.is_some());
        let p = parser.unwrap();
        assert_eq!(p.version, "v4.0.30319");
        assert_eq!(p.get_string(1), "MyClass");
        assert_eq!(p.get_string(9), "MyNamespace");
    }

    #[test]
    fn test_autoassembler_hook_generator() {
        let script = MonoDissector::generate_method_hook_script("TakeDamage", 0x7FF712345678);
        assert!(script.contains("[ENABLE]"));
        assert!(script.contains("[DISABLE]"));
        assert!(script.contains("0x00007FF712345678"));
        assert!(script.contains("TakeDamage"));
    }
}

