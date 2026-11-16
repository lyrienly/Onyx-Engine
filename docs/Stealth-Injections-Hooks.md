# Módulos de Stealth, Injeções e Hooks Avançados

## 1. Visão Geral

Os mecanismos tradicionais de injeção de DLLs (`CreateRemoteThread` + `LoadLibraryW`) e depuração usermode (`DebugActiveProcess`) são facilmente detectados por sistemas modernos de proteção (como Vanguard, EAC, BattlEye e EDRs corporativos) devido à presença de módulos na lista de DLLs carregadas (`InLoadOrderModuleList`), hooks inline em APIs de usermode (`ntdll.dll`) e verificações de integridade de pilha (*callstack walking*).

O OnyxEngine resolve esse desafio através de um conjunto dedicado de bibliotecas modulares de evasão e injeção em Rust e Assembly, operando de forma invisível no processo alvo.

---

## 2. Injeção por Manual Mapping (`crates/plugins/dll_mapper/src/`)

O **Manual Mapping** simula o comportamento do carregador nativo do sistema operacional (`LdrLoadDll` do Windows), carregando e linkando um executável PE (.dll) diretamente na memória virtual do processo alvo **sem registrar o módulo em nenhuma estrutura interna do Windows** (como o PEB ou o `Ldr` list).

```text
+---------------------------------------------------------------------------------+
|                       1. Leitura e Análise do Cabeçalho PE                      |
|   Verificação do DOS Header (MZ), NT Headers (PE00), OptionalHeader e Seções    |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                     2. Alocação de Memória Virtual Remota                       |
|   VirtualAllocEx(SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                     3. Cópia Segmentada das Seções PE                           |
|   Itera por IMAGE_SECTION_HEADER (.text, .rdata, .data, .pdata) e escreve dados  |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                4. Rebaseamento de Endereços (Base Relocations)                  |
|   Delta = EndereçoAlocado - ImageBasePreferencial                               |
|   Itera por IMAGE_BASE_RELOCATION e corrige ponteiros de 64 bits (DIR64)        |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                5. Resolução da Tabela de Importações (IAT)                      |
|   Lê IMAGE_IMPORT_DESCRIPTOR, carrega dependências e preenche os thunks         |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|             6. Execução de TLS Callbacks, DllMain e Wiping de Headers           |
|   Executa TLS (se presente), dispara DLL_PROCESS_ATTACH e apaga cabeçalhos      |
+---------------------------------------------------------------------------------+
```

### 2.1 Código de Produção: Correção de Relocations em Rust (`reloc.rs`)
Se o endereço alocado diferir da base preferencial, o módulo percorre blocos de realocação corrigindo entradas do tipo `IMAGE_REL_BASED_DIR64`:

```rust
// crates/plugins/dll_mapper/src/reloc.rs
pub const REL_BASED_DIR64: u16 = 10;

pub fn apply_relocations(
    image: &mut [u8],
    reloc_rva: u32,
    reloc_size: u32,
    delta: i64,
) -> Result<u32, String> {
    if reloc_rva == 0 || reloc_size == 0 || delta == 0 {
        return Ok(0);
    }

    let start = reloc_rva as usize;
    let end = start + reloc_size as usize;
    let mut cursor = start;
    let mut applied = 0u32;

    while cursor + 8 <= end {
        let page_rva = u32::from_le_bytes([
            image[cursor], image[cursor + 1], image[cursor + 2], image[cursor + 3]
        ]) as usize;
        let block_size = u32::from_le_bytes([
            image[cursor + 4], image[cursor + 5], image[cursor + 6], image[cursor + 7]
        ]) as usize;

        if block_size < 8 { break; }

        let entries_count = (block_size - 8) / 2;
        for i in 0..entries_count {
            let entry_offset = cursor + 8 + (i * 2);
            let entry = u16::from_le_bytes([image[entry_offset], image[entry_offset + 1]]);
            let reloc_type = entry >> 12;
            let offset = (entry & 0x0FFF) as usize;

            if reloc_type == REL_BASED_DIR64 {
                let target_offset = page_rva + offset;
                if target_offset + 8 <= image.len() {
                    let current_val = u64::from_le_bytes(
                        image[target_offset..target_offset + 8].try_into().unwrap()
                    );
                    let new_val = (current_val as i64 + delta) as u64;
                    image[target_offset..target_offset + 8].copy_from_slice(&new_val.to_le_bytes());
                    applied += 1;
                }
            }
        }
        cursor += block_size;
    }
    Ok(applied)
}
```

---

## 3. Expurgo e Destruição de Cabeçalhos PE (`pe_strip.dll`)

Após o carregamento da DLL na memória remota, scanners de assinatura de memória (como Moneta, PE-sieve ou módulos de auditoria de integridade) realizam varreduras buscando assinaturas de executáveis como a marca mágica `MZ` (`0x5A4D`) ou `PE\0\0` (`0x00004550`).

O `pe_strip.dll` sobrescreve todos os cabeçalhos da imagem injetada com zeros ou ruído criptográfico pseudo-aleatório:
- `IMAGE_DOS_HEADER` (64 bytes zerados)
- `IMAGE_NT_HEADERS` (Signature + FileHeader + OptionalHeader zerados)
- Tabela de seções (`IMAGE_SECTION_HEADER` zerada)

Isso transforma a DLL em um bloco anônimo de memória privada (`MEM_PRIVATE`), indistinguível de um buffer comum de dados da aplicação.

---

## 4. Falsificação de Pilha de Chamadas (`callstack_spoof.dll`)

Sistemas de detecção modernos interceptam APIs de alto privilégio (`NtReadVirtualMemory`, `NtAllocateVirtualMemory`) e inspecionam o endereço de retorno na pilha de execução (*Callstack Return Address*). Se o retorno apontar para uma região de memória anônima (fora dos módulos assinados da aplicação ou do sistema operacional), a injeção é denunciada imediatamente.

O `callstack_spoof.dll` utiliza trampolins em Assembly para **forjar frames legítimos na pilha**:

```text
Pilha Normal (Detectável):
[0x00] Endereço de Retorno -> 0x240A1234 (Memória Privada sem Módulo - DETECTADO)
[0x08] Parâmetros da chamada

Pilha Forjada pelo callstack_spoof:
[0x00] Endereço de Retorno -> ntdll.dll + 0x3A120 (Instrução legítima dentro da NTDLL)
[0x08] Endereço do Gadget de Restauração (jmp rbx / pop reg)
[0x10] Retorno real salvo em registrador preservado não volátil
```

---

## 5. Chamadas de Sistema Indiretas (`syscalls_indirect.dll`)

Muitos agentes de proteção instalam hooks inline (instruções `JMP <detour>`) nos primeiros 5 a 14 bytes das funções em `ntdll.dll` para monitorar chamadas de sistema.

O `syscalls_indirect.dll` contorna todos os hooks usermode através de **Syscalls Indiretas**:

```text
+---------------------------------------------------------------------------------+
|   1. Resolução Dinâmica do SSN (System Service Number) via Halo's Gate         |
|   Lê os bytes da NTDLL em memória. Se estiver hookada com JMP, examina os       |
|   vizinhos imediatos (+32 / -32 bytes) para calcular o índice exato do SSN.     |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|   2. Transição Limpa para o Kernel via Gadget                                   |
|   Não executa a instrução `syscall` em seu próprio código (o que geraria alerta |
|   de RIP fora da NTDLL). Em vez disso, salta para um opcode `syscall; ret`      |
|   original localizado no corpo legítimo da ntdll.dll:                           |
|                                                                                 |
|       mov r10, rcx                                                              |
|       mov eax, <SSN>                                                            |
|       jmp qword ptr [ntdll_clean_syscall_gadget]                                |
+---------------------------------------------------------------------------------+
```

---

## 6. Ocultação no Gerenciador de Tarefas (`taskmgr_cloak.dll`)

Para impedir que processos de instrumentação ou o próprio executável do OnyxEngine apareçam na listagem de processos do Windows:
- A DLL instala um hook de prólogo na função `NtQuerySystemInformation`.
- Quando a classe `SystemProcessInformation (5)` é requisitada, a função original do Windows é executada normalmente.
- Em seguida, o hook intercepta o buffer de saída retornado pelo kernel e percorre a lista encadeada de estruturas `SYSTEM_PROCESS_INFORMATION`.
- Ao localizar o PID ou o nome do processo alvo, a DLL desvincula a entrada ajustando o deslocamento `NextEntryOffset` da entrada anterior:

$$\text{EntradaAnterior}\rightarrow\text{NextEntryOffset} += \text{EntradaAlvo}\rightarrow\text{NextEntryOffset}$$

---

## 7. Depuração por Hardware via VEH (`crates/dlls/vehdebug/src/veh.rs`)

O módulo **`vehdebug_dll.dll`** captura eventos de memória por hardware sem abrir sessões formais de depuração com `DbgUiRemoteBreakin`:

```rust
// crates/dlls/vehdebug/src/veh.rs
pub trait VehHandler: Send + Sync {
    fn matches(&self, record: &EXCEPTION_RECORD, context: &CONTEXT) -> bool;
    fn handle(&self, record: &EXCEPTION_RECORD, context: &mut CONTEXT) -> VehDisposition;
}

// Manipulador global registrado via AddVectoredExceptionHandler(1, ...)
unsafe extern "system" fn global_veh_dispatcher(info: *mut EXCEPTION_POINTERS) -> LONG {
    let record = &*(*info).ExceptionRecord;
    let context = &mut *(*info).ContextRecord;

    // STATUS_SINGLE_STEP disparado por registradores de hardware DR0-DR3
    if record.ExceptionCode == STATUS_SINGLE_STEP {
        // Localiza e executa o handler registrado no OnyxEngine
        if let Some(handler) = find_matching_handler(record, context) {
            let disposition = handler.handle(record, context);
            // Limpa o bit de status de debug no DR6 para rearmar o breakpoint
            context.Dr6 &= !0x0F;
            return disposition.as_ntstatus(); // EXCEPTION_CONTINUE_EXECUTION
        }
    }
    EXCEPTION_CONTINUE_SEARCH
}
```

---

## 8. Modificação Temporal de Clock (`crates/dlls/speedhack/src/clock.rs`)

O **Speedhack** utiliza um relógio virtual com interpolação linear sem saltos discretos (*stuttering*):

```rust
// crates/dlls/speedhack/src/clock.rs
pub struct VirtualClock {
    pub base_real: i64,      // Ticks reais do hardware na última mudança de velocidade
    pub base_virtual: i64,   // Ticks acumulados calculados para a aplicação
    pub speed: f64,          // Multiplicador (ex: 0.5 para slow-motion, 2.0 para aceleração)
    pub freq: i64,           // Frequência do QueryPerformanceFrequency
}

impl VirtualClock {
    // Interpolação contínua: nenhuma descontinuidade temporal ao alterar velocidade
    pub fn get_virtual_time(&self, real_now: i64) -> i64 {
        let delta_real = real_now.wrapping_sub(self.base_real);
        let delta_virtual = (delta_real as f64 * self.speed) as i64;
        self.base_virtual.wrapping_add(delta_virtual)
    }

    // Reancora as bases na troca de velocidade
    pub fn set_speed(&mut self, real_now: i64, new_speed: f64) {
        self.base_virtual = self.get_virtual_time(real_now);
        self.base_real = real_now;
        self.speed = new_speed.max(0.0);
    }
}
```
