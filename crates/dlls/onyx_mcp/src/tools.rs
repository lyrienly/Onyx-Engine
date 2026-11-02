//! Model Context Protocol - Complete Tool Declarations and Dispatcher
//! Covers all 25 modules, engine capabilities, plugins, kernel driver Ring-0, and AI diagnostics.

use crate::plugins::PluginManager;
use crate::protocol::{McpCallToolResult, McpTool};
use crate::session::McpSession;
use onyx_core::error::{get_last_error, get_locale, set_locale, OnyxLocale};
use onyx_core::kernel::DbkDriver;
use onyx_core::memory::scanner::AobByte;
use onyx_core::mono::mono::MonoDissector;
use onyx_core::process::Process;
use onyx_core::scanner::{ScanCondition, ScanValue, Scanner, ValType};
use serde_json::{json, Value};
use std::sync::Arc;

pub struct ToolRegistry {
    tools: Vec<McpTool>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        let tools = vec![
            // Process & System Inspection
            McpTool {
                name: "process_list".to_string(),
                description: "Lista todos os processos ativos no sistema operacional com PID, nome e contagem de threads.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "filter": { "type": "string", "description": "Filtro opcional por nome do executável (ex: 'notepad', 'game')" }
                    }
                }),
            },
            McpTool {
                name: "attach_process".to_string(),
                description: "Seleciona e anexa ao processo alvo para controle de memória, scans e plugins. Aceita PID numérico ou nome do executável.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "name_or_pid": { "type": "string", "description": "PID do processo (ex: '1234') ou nome do executável (ex: 'Tutorial-x86_64.exe')" }
                    },
                    "required": ["name_or_pid"]
                }),
            },
            McpTool {
                name: "detach_process".to_string(),
                description: "Desconecta e libera o descritor do processo atualmente anexado.".to_string(),
                input_schema: json!({ "type": "object", "properties": {} }),
            },
            McpTool {
                name: "process_info".to_string(),
                description: "Retorna detalhes técnicos do processo ativo (PID, modo de acesso NtApi/KernelDbk, arquitetura, base e CR3).".to_string(),
                input_schema: json!({ "type": "object", "properties": {} }),
            },
            McpTool {
                name: "process_modules".to_string(),
                description: "Enumera todas as DLLs e módulos carregados no processo alvo (nome, endereço base, tamanho e caminho).".to_string(),
                input_schema: json!({ "type": "object", "properties": {} }),
            },
            McpTool {
                name: "process_threads".to_string(),
                description: "Lista todas as threads do processo com seus Thread IDs (TID).".to_string(),
                input_schema: json!({ "type": "object", "properties": {} }),
            },
            McpTool {
                name: "process_suspend".to_string(),
                description: "Suspende a execução de todas as threads do processo alvo.".to_string(),
                input_schema: json!({ "type": "object", "properties": {} }),
            },
            McpTool {
                name: "process_resume".to_string(),
                description: "Resume a execução das threads suspensas do processo alvo.".to_string(),
                input_schema: json!({ "type": "object", "properties": {} }),
            },

            // Memory Operations
            McpTool {
                name: "memory_read".to_string(),
                description: "Lê bytes ou tipos interpretados da memória do processo (i8, u8, i16, u16, i32, u32, i64, u64, float, double, string_utf8, string_utf16, pointer).".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "address": { "type": "string", "description": "Endereço em hexadecimal (ex: '0x7FF712340000' ou '140700000000000')" },
                        "size": { "type": "integer", "description": "Quantidade de bytes a ler (ex: 4 para i32, 8 para pointer, 64 para buffer)" },
                        "data_type": { "type": "string", "description": "Interpretação: 'i32', 'u32', 'i64', 'u64', 'float', 'double', 'string_utf8', 'pointer', 'byte'" }
                    },
                    "required": ["address"]
                }),
            },
            McpTool {
                name: "memory_write".to_string(),
                description: "Grava bytes ou valores na memória do processo alvo com ajuste automático de proteção de página VirtualProtect.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "address": { "type": "string", "description": "Endereço em hexadecimal (ex: '0x7FF712340000')" },
                        "hex_bytes": { "type": "string", "description": "Sequência de bytes em hexadecimal (ex: '90 90 90 90' ou '48 89 5C 24 08')" }
                    },
                    "required": ["address", "hex_bytes"]
                }),
            },
            McpTool {
                name: "memory_alloc".to_string(),
                description: "Aloca uma nova região de memória virtual no processo (VirtualAllocEx) com proteção PAGE_EXECUTE_READWRITE.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "size": { "type": "integer", "description": "Tamanho da alocação em bytes (ex: 4096)" },
                        "protect": { "type": "string", "description": "Proteção opcional em hex (padrão: '0x40' para PAGE_EXECUTE_READWRITE)" }
                    },
                    "required": ["size"]
                }),
            },
            McpTool {
                name: "memory_free".to_string(),
                description: "Libera uma página de memória alocada via VirtualFreeEx.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "address": { "type": "string", "description": "Endereço base alocado a ser liberado" }
                    },
                    "required": ["address"]
                }),
            },
            McpTool {
                name: "memory_protect".to_string(),
                description: "Altera as permissões de proteção de uma região de memória virtual (VirtualProtectEx).".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "address": { "type": "string", "description": "Endereço inicial da página" },
                        "size": { "type": "integer", "description": "Tamanho da região" },
                        "protection": { "type": "string", "description": "Nova proteção em hex (ex: '0x40' para RWX, '0x04' para RW, '0x20' para RX)" }
                    },
                    "required": ["address", "size", "protection"]
                }),
            },
            McpTool {
                name: "memory_query_regions".to_string(),
                description: "Mapeia e lista as regiões de memória virtual (VAD / VirtualQueryEx) do processo alvo.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "writable_only": { "type": "boolean", "description": "Se verdadeiro, lista apenas páginas graváveis (RW / RWX)" }
                    }
                }),
            },

            // Cheat Engine Scanner
            McpTool {
                name: "scanner_first_scan".to_string(),
                description: "Executa a primeira varredura de memória (Cheat Engine Scanner) por valor exato ou AOB pattern.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "value": { "type": "string", "description": "Valor numérico (ex: '100') ou padrão de bytes AOB (ex: '48 8B 05 ?? ?? ?? ??')" },
                        "value_type": { "type": "string", "description": "Tipo do valor: 'i32', 'i64', 'float', 'double', 'aob', 'string'" }
                    },
                    "required": ["value"]
                }),
            },
            McpTool {
                name: "scanner_next_scan".to_string(),
                description: "Filtra os resultados da varredura anterior com nova condição (Exact, Increased, Decreased, Changed, Unchanged).".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "condition": { "type": "string", "description": "Condição: 'exact', 'increased', 'decreased', 'changed', 'unchanged'" },
                        "value": { "type": "string", "description": "Novo valor esperado (para condições que exigem valor, como 'exact')" }
                    },
                    "required": ["condition"]
                }),
            },
            McpTool {
                name: "scanner_get_results".to_string(),
                description: "Retorna a lista de endereços e valores encontrados na varredura ativa.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "limit": { "type": "integer", "description": "Limite máximo de resultados a retornar (padrão: 50)" }
                    }
                }),
            },
            McpTool {
                name: "scanner_reset".to_string(),
                description: "Reinicia o scanner e limpa a tabela de resultados.".to_string(),
                input_schema: json!({ "type": "object", "properties": {} }),
            },

            // Pointer Scanner
            McpTool {
                name: "pointer_resolve_chain".to_string(),
                description: "Percorre uma cadeia de ponteiros multi-nível (Base + Deslocamentos) e retorna o endereço resolvido final.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "base_address": { "type": "string", "description": "Endereço base em hex (ex: '0x7FF712340000')" },
                        "offsets": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Lista de offsets hexadecimais (ex: ['0x18', '0x30', '0x0'])"
                        }
                    },
                    "required": ["base_address", "offsets"]
                }),
            },
            McpTool {
                name: "pointer_scan".to_string(),
                description: "Varredura reversa de ponteiros multi-nível para encontrar caminhos estáveis até o endereço alvo.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "target_address": { "type": "string", "description": "Endereço alvo que se deseja apontar (ex: '0x1A2B3C4D0')" },
                        "max_depth": { "type": "integer", "description": "Profundidade máxima de níveis (1 a 5, padrão: 4)" },
                        "max_offset": { "type": "integer", "description": "Offset máximo de estrutura (padrão: 4096 / 0x1000)" }
                    },
                    "required": ["target_address"]
                }),
            },

            // AutoAssembler
            McpTool {
                name: "aa_validate_script".to_string(),
                description: "Valida sintaxe e semântica de script AutoAssembler do Cheat Engine ([ENABLE], [DISABLE], alloc, registersymbol).".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "script": { "type": "string", "description": "Conteúdo textual do script AutoAssembler" }
                    },
                    "required": ["script"]
                }),
            },
            McpTool {
                name: "aa_execute_script".to_string(),
                description: "Compila e executa script AutoAssembler aplicando hooks, alocações de memória e patches no processo.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "script": { "type": "string", "description": "Script Cheat Engine AutoAssembler" },
                        "enable_mode": { "type": "boolean", "description": "true para [ENABLE], false para [DISABLE] / rollback" }
                    },
                    "required": ["script"]
                }),
            },

            // Memory Freezer
            McpTool {
                name: "freeze_address".to_string(),
                description: "Congela um endereço de memória para que seu valor permaneça fixo em background (intervalo de 50ms).".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "address": { "type": "string", "description": "Endereço em hexadecimal (ex: '0x1A2B3C4D0')" },
                        "value": { "type": "string", "description": "Valor a congelar (ex: '999')" },
                        "data_type": { "type": "string", "description": "Tipo do valor: 'i32', 'i64', 'float', 'double'" },
                        "description": { "type": "string", "description": "Descrição opcional da entrada" }
                    },
                    "required": ["address", "value", "data_type"]
                }),
            },
            McpTool {
                name: "unfreeze_address".to_string(),
                description: "Descongela o endereço especificado, interrompendo a rotina de travamento de memória.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "address": { "type": "string", "description": "Endereço em hex a descongelar" }
                    },
                    "required": ["address"]
                }),
            },
            McpTool {
                name: "freeze_list".to_string(),
                description: "Lista todos os endereços atualmente congelados pelo mecanismo de memória.".to_string(),
                input_schema: json!({ "type": "object", "properties": {} }),
            },

            // Disassembly & Assembly
            McpTool {
                name: "disassemble".to_string(),
                description: "Desmonta instruções de máquina x86/x64 no endereço especificado usando o engine nativo Zydis.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "address": { "type": "string", "description": "Endereço em hexadecimal da instrução inicial" },
                        "count": { "type": "integer", "description": "Número de instruções sequenciais a desmontar (padrão: 10)" }
                    },
                    "required": ["address"]
                }),
            },
            McpTool {
                name: "assemble_instruction".to_string(),
                description: "Monta instrução x86/x64 em bytes de código de máquina opcodes (ex: 'mov eax, 100').".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "instruction": { "type": "string", "description": "Instrução textual em sintaxe Intel (ex: 'mov rax, rcx')" },
                        "address": { "type": "string", "description": "Endereço base para cálculo de saltos relativos RIP (padrão: '0x0')" }
                    },
                    "required": ["instruction"]
                }),
            },

            // Structure Dissector & RE Tools
            McpTool {
                name: "dissect_structure".to_string(),
                description: "Disseca estrutura de dados em memória, identificando ponteiros, vtables, inteiros, floats, strings e coleções Unreal.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "address": { "type": "string", "description": "Endereço base da estrutura em hexadecimal" },
                        "size": { "type": "integer", "description": "Tamanho em bytes a dissectar (ex: 256)" }
                    },
                    "required": ["address"]
                }),
            },
            McpTool {
                name: "find_rop_gadgets".to_string(),
                description: "Localiza gadgets ROP úteis em módulos executáveis (ret, pop reg; ret, syscall, jmp reg).".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "address": { "type": "string", "description": "Endereço inicial da região" },
                        "size": { "type": "integer", "description": "Tamanho da região a escanear" },
                        "max_gadgets": { "type": "integer", "description": "Máximo de gadgets a retornar (padrão: 50)" }
                    },
                    "required": ["address", "size"]
                }),
            },
            McpTool {
                name: "find_string_references".to_string(),
                description: "Localiza referências a strings literais ASCII e UTF-16 no código executável.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "start_address": { "type": "string", "description": "Endereço inicial de busca em hex" },
                        "stop_address": { "type": "string", "description": "Endereço final de busca em hex" },
                        "min_length": { "type": "integer", "description": "Comprimento mínimo de string (padrão: 4)" }
                    },
                    "required": ["start_address", "stop_address"]
                }),
            },
            McpTool {
                name: "dissect_code_branches".to_string(),
                description: "Mapeia grafo de saltos, chamadas de função, retornos e limites de funções em um bloco de código.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "address": { "type": "string", "description": "Endereço base do bloco de código" },
                        "size": { "type": "integer", "description": "Tamanho do bloco em bytes" }
                    },
                    "required": ["address", "size"]
                }),
            },

            // Mono & Unity IL2CPP
            McpTool {
                name: "mono_detect_runtime".to_string(),
                description: "Detecta a presença de runtime Mono Classic, Unity IL2CPP ou UnityPlayer no processo alvo.".to_string(),
                input_schema: json!({ "type": "object", "properties": {} }),
            },
            McpTool {
                name: "mono_enum_assemblies".to_string(),
                description: "Enumera assemblies gerenciados carregados pelo runtime Mono/Unity no processo.".to_string(),
                input_schema: json!({ "type": "object", "properties": {} }),
            },
            McpTool {
                name: "mono_method_hook_script".to_string(),
                description: "Gera script AutoAssembler pronto para interceptar e modificar um método do Mono/Unity.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "method_name": { "type": "string", "description": "Nome do método gerenciado" },
                        "method_address": { "type": "string", "description": "Endereço compilação JIT do método em hex" }
                    },
                    "required": ["method_name", "method_address"]
                }),
            },

            // .NET CLR
            McpTool {
                name: "dotnet_detect_runtime".to_string(),
                description: "Detecta versão do runtime .NET Framework (CLR 2.0-4.x) ou .NET Core (CoreCLR 5.0-9.0).".to_string(),
                input_schema: json!({ "type": "object", "properties": {} }),
            },
            McpTool {
                name: "dotnet_enum_modules".to_string(),
                description: "Enumera todos os módulos .NET gerenciados carregados no processo.".to_string(),
                input_schema: json!({ "type": "object", "properties": {} }),
            },

            // Plugins
            McpTool {
                name: "plugin_aob_validate".to_string(),
                description: "Executa plugin nativo SigMaker para validar padrão AOB em módulos carregados e checar unicidade.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "pattern": { "type": "string", "description": "Padrão de assinatura (ex: '48 89 5C 24 ?? 48 83 EC 20')" },
                        "module_filter": { "type": "string", "description": "Filtro opcional de módulo (ex: 'engine.dll')" }
                    },
                    "required": ["pattern"]
                }),
            },
            McpTool {
                name: "plugin_aob_generate".to_string(),
                description: "Executa plugin nativo SigMaker para gerar assinatura AOB única com wildcards a partir de um endereço de função.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "target_address": { "type": "string", "description": "Endereço da função em hex" },
                        "max_length": { "type": "integer", "description": "Comprimento máximo da assinatura (padrão: 64)" }
                    },
                    "required": ["target_address"]
                }),
            },
            McpTool {
                name: "plugin_dll_manual_map".to_string(),
                description: "Injeta DLL via manual mapping furtivo (sem LoadLibrary, limpando cabeçalhos PE, TLS callbacks e hijacking).".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "dll_path": { "type": "string", "description": "Caminho da DLL a ser mapeada manualmente" },
                        "erase_pe_headers": { "type": "boolean", "description": "Se verdadeiro, zera cabeçalhos MZ/PE após injeção" }
                    },
                    "required": ["dll_path"]
                }),
            },

            // Kernel Driver Ring-0
            McpTool {
                name: "kernel_connect".to_string(),
                description: "Estabelece conexão direta com o driver Ring-0 OnyxDriver / OwMemDriver.".to_string(),
                input_schema: json!({ "type": "object", "properties": {} }),
            },
            McpTool {
                name: "kernel_read_cr3".to_string(),
                description: "Lê memória física direta do processo através da tradução de tabela de páginas CR3 em Ring-0.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "address": { "type": "string", "description": "Endereço virtual em hex" },
                        "size": { "type": "integer", "description": "Quantidade de bytes a ler" }
                    },
                    "required": ["address", "size"]
                }),
            },
            McpTool {
                name: "kernel_write_cr3".to_string(),
                description: "Grava na memória física direta através de Ring-0 contornando proteções virtuais de página.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "address": { "type": "string", "description": "Endereço virtual em hex" },
                        "hex_bytes": { "type": "string", "description": "Bytes em hexadecimal a gravar" }
                    },
                    "required": ["address", "hex_bytes"]
                }),
            },
            McpTool {
                name: "kernel_strip_callbacks".to_string(),
                description: "Desvincula callbacks ObRegisterCallbacks de processo/thread no kernel para cegar anticheats e EDRs.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "restore": { "type": "boolean", "description": "Se verdadeiro, restaura os callbacks originais" }
                    }
                }),
            },
            McpTool {
                name: "kernel_hide_process".to_string(),
                description: "Oculta o processo alvo via Direct Kernel Object Manipulation (DKOM) desvinculando de ActiveProcessLinks.".to_string(),
                input_schema: json!({ "type": "object", "properties": {} }),
            },

            // Injection & Speedhack
            McpTool {
                name: "inject_dll".to_string(),
                description: "Injeta uma DLL no processo alvo via CreateRemoteThread + LoadLibraryW.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "dll_path": { "type": "string", "description": "Caminho absoluto ou relativo para a DLL a ser injetada" }
                    },
                    "required": ["dll_path"]
                }),
            },
            McpTool {
                name: "speedhack_set_speed".to_string(),
                description: "Ativa e ajusta a velocidade do jogo/processo alvo através do multiplicador de tempo do speedhack.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "multiplier": { "type": "number", "description": "Multiplicador de tempo (ex: 0.5 para câmera lenta, 2.0 para o dobro, 5.0 para 5x)" }
                    },
                    "required": ["multiplier"]
                }),
            },

            // System & Diagnostics
            McpTool {
                name: "system_get_last_error".to_string(),
                description: "Retorna o código do último erro diagnosticado pelo OnyxEngine acompanhado da mensagem explicativa no idioma ativo.".to_string(),
                input_schema: json!({ "type": "object", "properties": {} }),
            },
            McpTool {
                name: "system_set_locale".to_string(),
                description: "Configura o idioma de diagnóstico das mensagens de erro ('pt_BR', 'en_US', 'es_ES').".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "locale": { "type": "string", "description": "Código de idioma: 'pt_BR', 'en_US', 'es_ES'" }
                    },
                    "required": ["locale"]
                }),
            },
            McpTool {
                name: "system_capabilities".to_string(),
                description: "Relatório completo de todas as 25 bibliotecas modulares, plugins nativos e recursos ativos no OnyxEngine.".to_string(),
                input_schema: json!({ "type": "object", "properties": {} }),
            },
        ];

        Self { tools }
    }

    pub fn list(&self) -> Vec<McpTool> {
        self.tools.clone()
    }

    pub fn list_tools(&self) -> Vec<McpTool> {
        self.list()
    }

    pub fn call(&self, session: &Arc<McpSession>, name: &str, args: &Value) -> McpCallToolResult {
        self.call_tool(session, name, args)
    }

    pub fn call_tool(&self, session: &Arc<McpSession>, name: &str, args: &Value) -> McpCallToolResult {
        match name {
            // Process & System
            "process_list" => {
                let filter = args.get("filter").and_then(|v| v.as_str()).unwrap_or("");
                match Process::list_all() {
                    Ok(procs) => {
                        let filtered: Vec<_> = procs
                            .into_iter()
                            .filter(|p| filter.is_empty() || p.name.to_lowercase().contains(&filter.to_lowercase()))
                            .map(|p| json!({ "pid": p.pid, "name": p.name, "threads": p.threads }))
                            .collect();
                        McpCallToolResult::success(json!({ "total": filtered.len(), "processes": filtered }))
                    }
                    Err(e) => McpCallToolResult::error(format!("Erro ao listar processos: {}", e.format(get_locale()))),
                }
            }
            "attach_process" => {
                let name_or_pid = match args.get("name_or_pid").and_then(|v| v.as_str()) {
                    Some(val) => val,
                    None => return McpCallToolResult::error("Argumento 'name_or_pid' é obrigatório."),
                };
                match session.attach(name_or_pid) {
                    Ok(info) => McpCallToolResult::success(info),
                    Err(e) => McpCallToolResult::error(e),
                }
            }
            "detach_process" => McpCallToolResult::success(session.detach()),
            "process_info" => match session.get_process() {
                Ok(proc) => {
                    let main_mod = proc.modules().ok().and_then(|m| m.into_iter().next());
                    let base_addr = main_mod.as_ref().map(|m| format!("0x{:X}", m.base)).unwrap_or_else(|| "0x0".to_string());
                    McpCallToolResult::success(json!({
                        "pid": proc.pid,
                        "name": proc.name,
                        "access_mode": proc.access_mode.as_str(),
                        "mode_badge": proc.access_mode.badge(),
                        "main_module_base": base_addr
                    }))
                }
                Err(e) => McpCallToolResult::error(e),
            },
            "process_modules" => match session.get_process() {
                Ok(proc) => match proc.modules() {
                    Ok(mods) => {
                        let mapped: Vec<_> = mods.into_iter().map(|m| json!({
                            "name": m.name,
                            "base": format!("0x{:X}", m.base),
                            "size": m.size,
                            "path": m.path
                        })).collect();
                        McpCallToolResult::success(json!({ "total_modules": mapped.len(), "modules": mapped }))
                    }
                    Err(e) => McpCallToolResult::error(format!("Erro ao enumerar módulos: {}", e.format(get_locale()))),
                },
                Err(e) => McpCallToolResult::error(e),
            },
            "process_threads" => match session.get_process() {
                Ok(proc) => match proc.threads() {
                    Ok(tids) => McpCallToolResult::success(json!({ "total_threads": tids.len(), "threads": tids })),
                    Err(e) => McpCallToolResult::error(format!("Erro ao enumerar threads: {}", e.format(get_locale()))),
                },
                Err(e) => McpCallToolResult::error(e),
            },
            "process_suspend" => match session.get_process() {
                Ok(proc) => match proc.suspend() {
                    Ok(_) => McpCallToolResult::success(json!({ "status": "suspended", "pid": proc.pid })),
                    Err(e) => McpCallToolResult::error(format!("Falha ao suspender processo: {}", e.format(get_locale()))),
                },
                Err(e) => McpCallToolResult::error(e),
            },
            "process_resume" => match session.get_process() {
                Ok(proc) => match proc.resume() {
                    Ok(_) => McpCallToolResult::success(json!({ "status": "resumed", "pid": proc.pid })),
                    Err(e) => McpCallToolResult::error(format!("Falha ao resumir processo: {}", e.format(get_locale()))),
                },
                Err(e) => McpCallToolResult::error(e),
            },

            // Memory Operations
            "memory_read" => {
                let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Parâmetro 'address' é obrigatório."),
                };
                let addr = match parse_hex_or_dec(addr_str) {
                    Some(a) => a,
                    None => return McpCallToolResult::error(format!("Endereço inválido: '{}'", addr_str)),
                };
                let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(4) as usize;
                let data_type = args.get("data_type").and_then(|v| v.as_str()).unwrap_or("i32");

                match session.read_memory(addr, size, data_type) {
                    Ok(val) => McpCallToolResult::success(val),
                    Err(e) => McpCallToolResult::error(e),
                }
            }
            "memory_write" => {
                let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Parâmetro 'address' é obrigatório."),
                };
                let addr = match parse_hex_or_dec(addr_str) {
                    Some(a) => a,
                    None => return McpCallToolResult::error(format!("Endereço inválido: '{}'", addr_str)),
                };
                let hex_str = match args.get("hex_bytes").and_then(|v| v.as_str()) {
                    Some(h) => h,
                    None => return McpCallToolResult::error("Parâmetro 'hex_bytes' é obrigatório."),
                };
                let bytes = match parse_hex_bytes(hex_str) {
                    Ok(b) => b,
                    Err(e) => return McpCallToolResult::error(e),
                };

                match session.write_memory(addr, &bytes) {
                    Ok(res) => McpCallToolResult::success(res),
                    Err(e) => McpCallToolResult::error(e),
                }
            }
            "memory_alloc" => {
                let size = match args.get("size").and_then(|v| v.as_u64()) {
                    Some(s) => s as usize,
                    None => return McpCallToolResult::error("Parâmetro 'size' é obrigatório."),
                };
                let protect = args.get("protect").and_then(|v| v.as_str())
                    .and_then(parse_hex_or_dec)
                    .unwrap_or(0x40) as u32; // PAGE_EXECUTE_READWRITE

                match session.alloc_memory(size, protect) {
                    Ok(res) => McpCallToolResult::success(res),
                    Err(e) => McpCallToolResult::error(e),
                }
            }
            "memory_free" => {
                let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Parâmetro 'address' é obrigatório."),
                };
                let addr = match parse_hex_or_dec(addr_str) {
                    Some(a) => a,
                    None => return McpCallToolResult::error(format!("Endereço inválido: '{}'", addr_str)),
                };
                match session.free_memory(addr) {
                    Ok(res) => McpCallToolResult::success(res),
                    Err(e) => McpCallToolResult::error(e),
                }
            }
            "memory_protect" => {
                let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Parâmetro 'address' é obrigatório."),
                };
                let addr = match parse_hex_or_dec(addr_str) {
                    Some(a) => a,
                    None => return McpCallToolResult::error(format!("Endereço inválido: '{}'", addr_str)),
                };
                let size = match args.get("size").and_then(|v| v.as_u64()) {
                    Some(s) => s as usize,
                    None => return McpCallToolResult::error("Parâmetro 'size' é obrigatório."),
                };
                let prot_str = match args.get("protection").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => return McpCallToolResult::error("Parâmetro 'protection' é obrigatório."),
                };
                let new_prot = match parse_hex_or_dec(prot_str) {
                    Some(p) => p as u32,
                    None => return McpCallToolResult::error("Proteção inválida."),
                };

                match session.protect_memory(addr, size, new_prot) {
                    Ok(res) => McpCallToolResult::success(res),
                    Err(e) => McpCallToolResult::error(e),
                }
            }
            "memory_query_regions" => {
                let writable_only = args.get("writable_only").and_then(|v| v.as_bool()).unwrap_or(false);
                match session.query_regions(writable_only) {
                    Ok(res) => McpCallToolResult::success(res),
                    Err(e) => McpCallToolResult::error(e),
                }
            }

            // Scanner
            "scanner_first_scan" => {
                let val_str = match args.get("value").and_then(|v| v.as_str()) {
                    Some(v) => v,
                    None => return McpCallToolResult::error("Parâmetro 'value' é obrigatório."),
                };
                let val_type_str = args.get("value_type").and_then(|v| v.as_str()).unwrap_or("i32");
                let proc = match session.get_process() {
                    Ok(p) => p,
                    Err(e) => return McpCallToolResult::error(e),
                };

                let (val_type, scan_value) = match val_type_str.to_lowercase().as_str() {
                    "i32" => {
                        let parsed = match val_str.parse::<i32>() {
                            Ok(p) => p,
                            Err(_) => return McpCallToolResult::error("Valor inteiro i32 inválido."),
                        };
                        (ValType::I32, ScanValue::I32(parsed))
                    }
                    "i64" => {
                        let parsed = match val_str.parse::<i64>() {
                            Ok(p) => p,
                            Err(_) => return McpCallToolResult::error("Valor inteiro i64 inválido."),
                        };
                        (ValType::I64, ScanValue::I64(parsed))
                    }
                    "float" => {
                        let parsed = match val_str.parse::<f32>() {
                            Ok(p) => p,
                            Err(_) => return McpCallToolResult::error("Valor float inválido."),
                        };
                        (ValType::Float, ScanValue::Float(parsed))
                    }
                    "double" => {
                        let parsed = match val_str.parse::<f64>() {
                            Ok(p) => p,
                            Err(_) => return McpCallToolResult::error("Valor double inválido."),
                        };
                        (ValType::Double, ScanValue::Double(parsed))
                    }
                    "aob" => {
                        let mut aob_bytes = Vec::new();
                        for token in val_str.split_whitespace() {
                            if !token.is_empty() {
                                match AobByte::parse(token) {
                                    Ok(b) => aob_bytes.push(b),
                                    Err(e) => return McpCallToolResult::error(format!("Byte AOB inválido '{}': {}", token, e)),
                                }
                            }
                        }
                        if aob_bytes.is_empty() {
                            return McpCallToolResult::error("Padrão AOB não pode ser vazio.");
                        }
                        (ValType::Aob, ScanValue::Aob(aob_bytes))
                    }
                    "string" => (ValType::Str, ScanValue::Str(val_str.to_string())),
                    _ => return McpCallToolResult::error("Tipo de valor não suportado para escaneamento."),
                };

                let mut scanner = Scanner::new(val_type);
                let condition = ScanCondition::Exact(scan_value);
                match scanner.first_scan(&proc, condition) {
                    Ok(_) => {
                        let count = scanner.count();
                        let found_addrs: Vec<usize> = scanner.results(50).iter().map(|c| c.address).collect();
                        *session.scanner.lock().unwrap() = Some(scanner);
                        *session.last_scan_results.lock().unwrap() = found_addrs.clone();

                        McpCallToolResult::success(json!({
                            "status": "first_scan_complete",
                            "total_found": count,
                            "preview_addresses": found_addrs.into_iter().map(|a| format!("0x{:X}", a)).collect::<Vec<_>>()
                        }))
                    }
                    Err(e) => McpCallToolResult::error(format!("Erro durante o scan: {}", e)),
                }
            }
            "scanner_next_scan" => {
                let cond_str = match args.get("condition").and_then(|v| v.as_str()) {
                    Some(c) => c,
                    None => return McpCallToolResult::error("Parâmetro 'condition' é obrigatório."),
                };
                let proc = match session.get_process() {
                    Ok(p) => p,
                    Err(e) => return McpCallToolResult::error(e),
                };

                let mut lock = session.scanner.lock().unwrap();
                let scanner = match lock.as_mut() {
                    Some(s) => s,
                    None => return McpCallToolResult::error("Nenhum scan ativo. Execute 'scanner_first_scan' antes de 'scanner_next_scan'."),
                };

                let cond = match cond_str.to_lowercase().as_str() {
                    "increased" => ScanCondition::Increased,
                    "decreased" => ScanCondition::Decreased,
                    "changed" => ScanCondition::Changed,
                    "unchanged" => ScanCondition::Unchanged,
                    "exact" => {
                        let val_str = match args.get("value").and_then(|v| v.as_str()) {
                            Some(v) => v,
                            None => return McpCallToolResult::error("Condição 'exact' exige o parâmetro 'value'."),
                        };
                        let val = match scanner.val_type {
                            ValType::I32 => ScanValue::I32(val_str.parse().unwrap_or(0)),
                            ValType::I64 => ScanValue::I64(val_str.parse().unwrap_or(0)),
                            ValType::Float => ScanValue::Float(val_str.parse().unwrap_or(0.0)),
                            ValType::Double => ScanValue::Double(val_str.parse().unwrap_or(0.0)),
                            _ => ScanValue::Str(val_str.to_string()),
                        };
                        ScanCondition::Exact(val)
                    }
                    _ => return McpCallToolResult::error(format!("Condição de scan inválida: '{}'", cond_str)),
                };

                match scanner.next_scan(&proc, cond) {
                    Ok(_) => {
                        let count = scanner.count();
                        let found_addrs: Vec<usize> = scanner.results(50).iter().map(|c| c.address).collect();
                        *session.last_scan_results.lock().unwrap() = found_addrs.clone();

                        McpCallToolResult::success(json!({
                            "status": "next_scan_complete",
                            "remaining_matches": count,
                            "preview_addresses": found_addrs.into_iter().map(|a| format!("0x{:X}", a)).collect::<Vec<_>>()
                        }))
                    }
                    Err(e) => McpCallToolResult::error(format!("Erro durante o next scan: {}", e)),
                }
            }
            "scanner_get_results" => {
                let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
                let lock = session.scanner.lock().unwrap();
                match lock.as_ref() {
                    Some(s) => {
                        let items = s.results(limit).into_iter().map(|r| json!({
                            "address": format!("0x{:X}", r.address),
                            "value": format!("{:?}", r.current_value)
                        })).collect::<Vec<_>>();
                        McpCallToolResult::success(json!({ "total": s.count(), "results": items }))
                    }
                    None => McpCallToolResult::error("Nenhum scan ativo."),
                }
            }
            "scanner_reset" => {
                *session.scanner.lock().unwrap() = None;
                session.last_scan_results.lock().unwrap().clear();
                McpCallToolResult::success(json!({ "status": "scanner_reset" }))
            }

            // Pointer Scanner
            "pointer_resolve_chain" => {
                let base_str = match args.get("base_address").and_then(|v| v.as_str()) {
                    Some(b) => b,
                    None => return McpCallToolResult::error("Parâmetro 'base_address' é obrigatório."),
                };
                let base_addr = match parse_hex_or_dec(base_str) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Endereço base inválido."),
                };
                let offsets_arr = match args.get("offsets").and_then(|v| v.as_array()) {
                    Some(arr) => arr,
                    None => return McpCallToolResult::error("Parâmetro 'offsets' deve ser um array de strings hexadecimais."),
                };
                let mut offsets = Vec::new();
                for item in offsets_arr {
                    let s = item.as_str().unwrap_or("0");
                    match parse_hex_or_dec(s) {
                        Some(val) => offsets.push(val),
                        None => return McpCallToolResult::error(format!("Offset inválido: '{}'", s)),
                    }
                }

                match session.pointer_resolve_chain(base_addr, &offsets) {
                    Ok(res) => McpCallToolResult::success(res),
                    Err(e) => McpCallToolResult::error(e),
                }
            }
            "pointer_scan" => {
                let target_str = match args.get("target_address").and_then(|v| v.as_str()) {
                    Some(t) => t,
                    None => return McpCallToolResult::error("Parâmetro 'target_address' é obrigatório."),
                };
                let target_addr = match parse_hex_or_dec(target_str) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Endereço alvo inválido."),
                };
                let max_depth = args.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(4) as usize;
                let max_offset = args.get("max_offset").and_then(|v| v.as_u64()).unwrap_or(4096) as usize;

                match session.pointer_scan_start(target_addr, max_depth, max_offset) {
                    Ok(res) => McpCallToolResult::success(res),
                    Err(e) => McpCallToolResult::error(e),
                }
            }

            // AutoAssembler
            "aa_validate_script" => {
                let script = match args.get("script").and_then(|v| v.as_str()) {
                    Some(s) => s,
                    None => return McpCallToolResult::error("Parâmetro 'script' é obrigatório."),
                };
                McpCallToolResult::success(session.aa_validate_script(script))
            }
            "aa_execute_script" => {
                let script = match args.get("script").and_then(|v| v.as_str()) {
                    Some(s) => s,
                    None => return McpCallToolResult::error("Parâmetro 'script' é obrigatório."),
                };
                let enable = args.get("enable_mode").and_then(|v| v.as_bool()).unwrap_or(true);
                match session.aa_execute_script(script, enable) {
                    Ok(res) => McpCallToolResult::success(res),
                    Err(e) => McpCallToolResult::error(e),
                }
            }

            // Memory Freezer
            "freeze_address" => {
                let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Parâmetro 'address' é obrigatório."),
                };
                let addr = match parse_hex_or_dec(addr_str) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Endereço inválido."),
                };
                let val_str = match args.get("value").and_then(|v| v.as_str()) {
                    Some(v) => v,
                    None => return McpCallToolResult::error("Parâmetro 'value' é obrigatório."),
                };
                let data_type = args.get("data_type").and_then(|v| v.as_str()).unwrap_or("i32");
                let desc = args.get("description").and_then(|v| v.as_str()).unwrap_or("");

                match session.freeze_address(addr, val_str, data_type, desc) {
                    Ok(res) => McpCallToolResult::success(res),
                    Err(e) => McpCallToolResult::error(e),
                }
            }
            "unfreeze_address" => {
                let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Parâmetro 'address' é obrigatório."),
                };
                let addr = match parse_hex_or_dec(addr_str) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Endereço inválido."),
                };
                McpCallToolResult::success(session.unfreeze_address(addr))
            }
            "freeze_list" => McpCallToolResult::success(session.freeze_list()),

            // Disassembly & Assembly
            "disassemble" => {
                let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Parâmetro 'address' é obrigatório."),
                };
                let addr = match parse_hex_or_dec(addr_str) {
                    Some(a) => a,
                    None => return McpCallToolResult::error(format!("Endereço inválido: '{}'", addr_str)),
                };
                let count = args.get("count").and_then(|v| v.as_u64()).unwrap_or(10) as usize;

                match session.disassemble(addr, count) {
                    Ok(val) => McpCallToolResult::success(val),
                    Err(e) => McpCallToolResult::error(e),
                }
            }
            "assemble_instruction" => {
                let insn = match args.get("instruction").and_then(|v| v.as_str()) {
                    Some(i) => i,
                    None => return McpCallToolResult::error("Parâmetro 'instruction' é obrigatório."),
                };
                let addr = args.get("address").and_then(|v| v.as_str()).and_then(parse_hex_or_dec).unwrap_or(0);
                match session.assemble(addr, insn) {
                    Ok(res) => McpCallToolResult::success(res),
                    Err(e) => McpCallToolResult::error(e),
                }
            }

            // RE & Structures
            "dissect_structure" => {
                let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Parâmetro 'address' é obrigatório."),
                };
                let addr = match parse_hex_or_dec(addr_str) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Endereço inválido."),
                };
                let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(256) as usize;

                match session.dissect_structure(addr, size) {
                    Ok(res) => McpCallToolResult::success(res),
                    Err(e) => McpCallToolResult::error(e),
                }
            }
            "find_rop_gadgets" => {
                let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Parâmetro 'address' é obrigatório."),
                };
                let addr = match parse_hex_or_dec(addr_str) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Endereço inválido."),
                };
                let size = match args.get("size").and_then(|v| v.as_u64()) {
                    Some(s) => s as usize,
                    None => return McpCallToolResult::error("Parâmetro 'size' é obrigatório."),
                };
                let max_gadgets = args.get("max_gadgets").and_then(|v| v.as_u64()).unwrap_or(50) as usize;

                match session.find_rop_gadgets(addr, size, max_gadgets) {
                    Ok(res) => McpCallToolResult::success(res),
                    Err(e) => McpCallToolResult::error(e),
                }
            }
            "find_string_references" => {
                let start_str = match args.get("start_address").and_then(|v| v.as_str()) {
                    Some(s) => s,
                    None => return McpCallToolResult::error("Parâmetro 'start_address' é obrigatório."),
                };
                let start = match parse_hex_or_dec(start_str) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Endereço inicial inválido."),
                };
                let stop_str = match args.get("stop_address").and_then(|v| v.as_str()) {
                    Some(s) => s,
                    None => return McpCallToolResult::error("Parâmetro 'stop_address' é obrigatório."),
                };
                let stop = match parse_hex_or_dec(stop_str) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Endereço final inválido."),
                };
                let min_len = args.get("min_length").and_then(|v| v.as_u64()).unwrap_or(4) as usize;

                match session.find_string_references(start, stop, min_len) {
                    Ok(res) => McpCallToolResult::success(res),
                    Err(e) => McpCallToolResult::error(e),
                }
            }
            "dissect_code_branches" => {
                let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Parâmetro 'address' é obrigatório."),
                };
                let addr = match parse_hex_or_dec(addr_str) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Endereço inválido."),
                };
                let size = match args.get("size").and_then(|v| v.as_u64()) {
                    Some(s) => s as usize,
                    None => return McpCallToolResult::error("Parâmetro 'size' é obrigatório."),
                };

                match session.dissect_code_branches(addr, size) {
                    Ok(res) => McpCallToolResult::success(res),
                    Err(e) => McpCallToolResult::error(e),
                }
            }

            // Mono & Unity
            "mono_detect_runtime" => match session.get_process() {
                Ok(proc) => {
                    let runtime = onyx_mono::detect_mono_runtime(proc.pid);
                    McpCallToolResult::success(json!({
                        "pid": proc.pid,
                        "runtime": format!("{:?}", runtime)
                    }))
                }
                Err(e) => McpCallToolResult::error(e),
            },
            "mono_enum_assemblies" => match session.get_process() {
                Ok(proc) => {
                    let runtime = onyx_mono::detect_mono_runtime(proc.pid);
                    let result = onyx_mono::enumerate_assemblies(proc.pid, &runtime);
                    let assemblies = result.assemblies.into_iter().map(|a| json!({
                        "name": a.name,
                        "image_base": format!("0x{:X}", a.image_base),
                        "notes": a.notes
                    })).collect::<Vec<_>>();
                    McpCallToolResult::success(json!({
                        "count": assemblies.len(),
                        "partial": result.partial,
                        "assemblies": assemblies
                    }))
                }
                Err(e) => McpCallToolResult::error(e),
            },
            "mono_method_hook_script" => {
                let method_name = match args.get("method_name").and_then(|v| v.as_str()) {
                    Some(m) => m,
                    None => return McpCallToolResult::error("Parâmetro 'method_name' é obrigatório."),
                };
                let addr_str = match args.get("method_address").and_then(|v| v.as_str()) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Parâmetro 'method_address' é obrigatório."),
                };
                let addr = match parse_hex_or_dec(addr_str) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Endereço inválido."),
                };

                let script = MonoDissector::generate_method_hook_script(method_name, addr);
                McpCallToolResult::success(json!({ "method": method_name, "script": script }))
            }

            // .NET CLR
            "dotnet_detect_runtime" => match session.get_process() {
                Ok(proc) => match onyx_dotnet::detect_runtime(proc.pid) {
                    Some(clr) => McpCallToolResult::success(json!({
                        "kind": format!("{:?}", clr.kind),
                        "version": clr.version,
                        "module_path": clr.module_path.to_string_lossy(),
                        "module_base": format!("0x{:X}", clr.module_base)
                    })),
                    None => McpCallToolResult::success(json!({ "status": "none_detected", "message": "Nenhum runtime .NET identificado no processo." })),
                },
                Err(e) => McpCallToolResult::error(e),
            },
            "dotnet_enum_modules" => match session.get_process() {
                Ok(proc) => {
                    let modules = onyx_dotnet::enumerate_modules(proc.pid);
                    let mapped = modules.into_iter().map(|m| json!({
                        "name": m.name,
                        "base": format!("0x{:X}", m.base),
                        "size": m.size,
                        "path": m.path.to_string_lossy()
                    })).collect::<Vec<_>>();
                    McpCallToolResult::success(json!({ "count": mapped.len(), "modules": mapped }))
                }
                Err(e) => McpCallToolResult::error(e),
            },

            // Plugins
            "plugin_aob_validate" => {
                let pattern_str = match args.get("pattern").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => return McpCallToolResult::error("Parâmetro 'pattern' é obrigatório."),
                };
                let mod_filter = args.get("module_filter").and_then(|v| v.as_str()).unwrap_or("");
                let proc = match session.get_process() {
                    Ok(p) => p,
                    Err(e) => return McpCallToolResult::error(e),
                };

                match PluginManager::validate_aob(&proc, pattern_str, mod_filter) {
                    Ok(res) => McpCallToolResult::success(res),
                    Err(e) => McpCallToolResult::error(e),
                }
            }
            "plugin_aob_generate" => {
                let addr_str = match args.get("target_address").and_then(|v| v.as_str()) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Parâmetro 'target_address' é obrigatório."),
                };
                let addr = match parse_hex_or_dec(addr_str) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Endereço inválido."),
                };
                let max_len = args.get("max_length").and_then(|v| v.as_u64()).unwrap_or(64) as u32;
                let proc = match session.get_process() {
                    Ok(p) => p,
                    Err(e) => return McpCallToolResult::error(e),
                };

                match PluginManager::generate_aob(&proc, addr, max_len) {
                    Ok(res) => McpCallToolResult::success(res),
                    Err(e) => McpCallToolResult::error(e),
                }
            }
            "plugin_dll_manual_map" => {
                let dll_path = match args.get("dll_path").and_then(|v| v.as_str()) {
                    Some(d) => d,
                    None => return McpCallToolResult::error("Parâmetro 'dll_path' é obrigatório."),
                };
                let erase_headers = args.get("erase_pe_headers").and_then(|v| v.as_bool()).unwrap_or(true);
                let proc = match session.get_process() {
                    Ok(p) => p,
                    Err(e) => return McpCallToolResult::error(e),
                };

                match PluginManager::manual_map(&proc, dll_path, erase_headers) {
                    Ok(res) => McpCallToolResult::success(res),
                    Err(e) => McpCallToolResult::error(e),
                }
            }

            // Kernel Driver
            "kernel_connect" => {
                match DbkDriver::connect() {
                    Ok(driver) => {
                        let arc = Arc::new(driver);
                        *session.driver.lock().unwrap() = Some(arc.clone());
                        McpCallToolResult::success(json!({
                            "status": "connected",
                            "device": arc.device_name,
                            "capabilities": ["Ring-0", "CR3 Physical Translation", "DKOM Unlinking", "Callback Stripping"]
                        }))
                    }
                    Err(e) => McpCallToolResult::error(format!("Falha ao conectar ao driver de kernel: {}", e)),
                }
            }
            "kernel_read_cr3" => {
                let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Parâmetro 'address' é obrigatório."),
                };
                let addr = match parse_hex_or_dec(addr_str) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Endereço virtual inválido."),
                };
                let size = match args.get("size").and_then(|v| v.as_u64()) {
                    Some(s) => s as usize,
                    None => return McpCallToolResult::error("Parâmetro 'size' é obrigatório."),
                };

                let proc = match session.get_process() {
                    Ok(p) => p,
                    Err(e) => return McpCallToolResult::error(e),
                };

                let driver = match session.driver.lock().unwrap().clone() {
                    Some(d) => d,
                    None => return McpCallToolResult::error("Driver de kernel não está conectado. Use 'kernel_connect'."),
                };

                match driver.read_memory(proc.pid, addr, size) {
                    Ok(bytes) => {
                        let hex = bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                        McpCallToolResult::success(json!({
                            "address": format!("0x{:X}", addr),
                            "bytes_read": bytes.len(),
                            "hex": hex
                        }))
                    }
                    Err(e) => McpCallToolResult::error(e),
                }
            }
            "kernel_write_cr3" => {
                let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Parâmetro 'address' é obrigatório."),
                };
                let addr = match parse_hex_or_dec(addr_str) {
                    Some(a) => a,
                    None => return McpCallToolResult::error("Endereço virtual inválido."),
                };
                let hex_str = match args.get("hex_bytes").and_then(|v| v.as_str()) {
                    Some(h) => h,
                    None => return McpCallToolResult::error("Parâmetro 'hex_bytes' é obrigatório."),
                };
                let bytes = match parse_hex_bytes(hex_str) {
                    Ok(b) => b,
                    Err(e) => return McpCallToolResult::error(e),
                };

                let proc = match session.get_process() {
                    Ok(p) => p,
                    Err(e) => return McpCallToolResult::error(e),
                };

                let driver = match session.driver.lock().unwrap().clone() {
                    Some(d) => d,
                    None => return McpCallToolResult::error("Driver de kernel não está conectado."),
                };

                match driver.write_memory(proc.pid, addr, &bytes) {
                    Ok(written) => McpCallToolResult::success(json!({
                        "address": format!("0x{:X}", addr),
                        "bytes_written": written,
                        "status": "kernel_write_success"
                    })),
                    Err(e) => McpCallToolResult::error(e),
                }
            }
            "kernel_strip_callbacks" => {
                let restore = args.get("restore").and_then(|v| v.as_bool()).unwrap_or(false);
                let driver = match session.driver.lock().unwrap().clone() {
                    Some(d) => d,
                    None => return McpCallToolResult::error("Driver de kernel não está conectado."),
                };
                match driver.strip_callbacks(restore) {
                    Ok(count) => McpCallToolResult::success(json!({
                        "status": if restore { "callbacks_restored" } else { "callbacks_stripped" },
                        "affected_count": count
                    })),
                    Err(e) => McpCallToolResult::error(e),
                }
            }
            "kernel_hide_process" => {
                let proc = match session.get_process() {
                    Ok(p) => p,
                    Err(e) => return McpCallToolResult::error(e),
                };
                let driver = match session.driver.lock().unwrap().clone() {
                    Some(d) => d,
                    None => return McpCallToolResult::error("Driver de kernel não está conectado."),
                };
                match driver.hide_process(proc.pid) {
                    Ok(_) => McpCallToolResult::success(json!({
                        "status": "hidden_via_dkom",
                        "pid": proc.pid,
                        "details": "Desvinculado com sucesso de ActiveProcessLinks do EPROCESS."
                    })),
                    Err(e) => McpCallToolResult::error(e),
                }
            }

            // Injection & Speedhack
            "inject_dll" => {
                let dll_path = match args.get("dll_path").and_then(|v| v.as_str()) {
                    Some(d) => d,
                    None => return McpCallToolResult::error("Parâmetro 'dll_path' é obrigatório."),
                };
                let proc = match session.get_process() {
                    Ok(p) => p,
                    Err(e) => return McpCallToolResult::error(e),
                };
                match proc.inject_dll(dll_path) {
                    Ok(base) => McpCallToolResult::success(json!({
                        "status": "injected",
                        "remote_module_base": format!("0x{:X}", base),
                        "dll_path": dll_path
                    })),
                    Err(e) => McpCallToolResult::error(format!("Injeção falhou: {}", e.format(get_locale()))),
                }
            }
            "speedhack_set_speed" => {
                let mult = match args.get("multiplier").and_then(|v| v.as_f64()) {
                    Some(m) => m as f32,
                    None => return McpCallToolResult::error("Parâmetro 'multiplier' é obrigatório."),
                };
                match session.speedhack_set_speed(mult) {
                    Ok(res) => McpCallToolResult::success(res),
                    Err(e) => McpCallToolResult::error(e),
                }
            }

            // System & Diagnostics
            "system_get_last_error" => match get_last_error() {
                Some(err) => McpCallToolResult::success(json!({
                    "code": err.code.as_u32(),
                    "name": format!("{:?}", err.code),
                    "message": err.format(get_locale()),
                    "context": err.context
                })),
                None => McpCallToolResult::success(json!({
                    "code": 0,
                    "message": "Nenhum erro registrado no subsistema."
                })),
            },
            "system_set_locale" => {
                let loc_str = match args.get("locale").and_then(|v| v.as_str()) {
                    Some(l) => l,
                    None => return McpCallToolResult::error("Parâmetro 'locale' é obrigatório."),
                };
                let loc = match loc_str.to_lowercase().as_str() {
                    "pt_br" | "pt" => OnyxLocale::PtBr,
                    "en_us" | "en" => OnyxLocale::EnUs,
                    _ => return McpCallToolResult::error("Locale inválido. Use 'pt_BR' ou 'en_US'."),
                };
                set_locale(loc);
                McpCallToolResult::success(json!({ "status": "locale_updated", "locale": loc_str }))
            }
            "system_capabilities" => {
                McpCallToolResult::success(json!({
                    "engine": "OnyxEngine",
                    "version": "1.0.0",
                    "architecture": "x86_64",
                    "platform": "Windows 11 / 10",
                    "total_modular_dlls": 25,
                    "active_plugins": [
                        { "name": "onyx_aob_tool", "description": "SigMaker, AOB Validation and Generation" },
                        { "name": "onyx_dll_mapper", "description": "Stealth Manual Mapping with PE header erasing" }
                    ],
                    "core_modules": [
                        "onyx_backend", "onyx_scanner", "onyx_pointer", "onyx_disasm",
                        "onyx_aa", "onyx_freezer", "onyx_mono", "onyx_dotnet",
                        "onyx_hook", "onyx_overlay", "onyx_gdb_server", "onyx_shield",
                        "speedhack", "vehdebug", "taskmgr_cloak", "d3dhook", "allochook", "luaclient"
                    ],
                    "kernel_driver": "OnyxDriver.sys / OwMemDriver.sys (Ring-0, CR3 translation, DKOM, Callbacks)"
                }))
            }

            _ => McpCallToolResult::error(format!("Ferramenta desconhecida: '{}'", name)),
        }
    }
}

fn parse_hex_or_dec(s: &str) -> Option<usize> {
    let trimmed = s.trim();
    if let Some(stripped) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        usize::from_str_radix(stripped, 16).ok()
    } else {
        trimmed.parse::<usize>().ok()
    }
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let clean = s.replace(',', " ");
    let mut bytes = Vec::new();
    for token in clean.split_whitespace() {
        let token_clean = token.trim_start_matches("0x").trim_start_matches("0X");
        let byte = u8::from_str_radix(token_clean, 16)
            .map_err(|_| format!("Byte hexadecimal inválido: '{}'", token))?;
        bytes.push(byte);
    }
    if bytes.is_empty() {
        Err("Sequência hexadecimal vazia.".to_string())
    } else {
        Ok(bytes)
    }
}
