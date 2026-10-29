# Plano de Testes Manuais — OnyxEngine (Todas as Issues Concluídas)

Este documento detalha o roteiro prático e passo a passo para você testar manualmente cada funcionalidade e módulo implementado no **OnyxEngine**. 

---

## Índice Rápido por Categoria

1. **Injeção, Evasão e Stealth**:
   - [Issue #27: Manual Mapping PE Nativo x86_64 com TLS e Wiping](#1-manual-mapping-pe-nativo-issue-27)
   - [Issue #89: Plugin DLL Mapper (Manual Map via Plugin)](#2-plugin-dll-mapper-issue-89)
   - [Issue #25: Syscalls Indiretas com SSN Dinâmico](#3-syscalls-indiretas-stealth-issue-25)
   - [Issue #4: Auditoria de Strings e Randomização de Nomes](#4-auditoria-de-strings-e-stealth-issue-4)
   - [Issue #93: Module Dumper PE a partir da Memória](#5-module-dumper-pe-issue-93)
2. **Engenharia de Memória e Varredura**:
   - [Issue #3: Scanner SIMD (AVX2 / AVX-512)](#6-scanner-simd-avx2--avx-512-issue-3)
   - [Issue #31 & #55: Pattern Scan AOB & Validador de Assinaturas](#7-pattern-scan-aob--validador-issue-31--55)
   - [Issue #37: SmartScan Polimórfico](#8-smartscan-polimorfico-issue-37)
   - [Issue #22: Cache de Memória em Chunks](#9-cache-de-memoria-em-chunks-issue-22)
   - [Issue #35: Snapshot Engine com xxHash3](#10-snapshot-engine-diferencial-issue-35)
   - [Issue #40: Memória Transacional com Rollback Atômico](#11-memoria-transacional-com-rollback-issue-40)
   - [Issue #15: Freezer Atômico de Valores](#12-freezer-atomico-de-valores-issue-15)
3. **Depuração, Hooks e Execução**:
   - [Issue #39: Servidor GDB RSP (IDA / Ghidra / x64dbg)](#13-servidor-gdb-rsp-issue-39)
   - [Issue #36: Breakpoints de Hardware Ilimitados via PAGE_GUARD](#14-breakpoints-ilimitados-via-page_guard-issue-36)
   - [Issue #7: Depurador VEH em Rust](#15-depurador-veh-rust-issue-7)
   - [Issue #16: Depuração por Hardware Breakpoints (DR0-DR3/DR7)](#16-hardware-breakpoints-dr0-dr3dr7-issue-16)
   - [Issue #30: Hook Engine 14-bytes com Relocador Zydis](#17-hook-engine-detour-14-bytes-issue-30)
   - [Issue #14: Disassembler Zydis & Control Flow Graph (CFG)](#18-disassembler-zydis--cfg-issue-14)
   - [Issue #18: Auto Assembler 64-bit](#19-auto-assembler-64-bit-parser-issue-18)
4. **Jogos, Runtimes e Gráficos**:
   - [Issue #13: Speedhack com Interpolação QPC](#20-speedhack-qpc-virtual-clock-issue-13)
   - [Issue #38: Overlay DirectX 11 Present Hook](#21-overlay-directx-11-present-hook-issue-38)
   - [Issue #17: .NET Core Runtime Collector (.NET 6/7/8/9)](#22-net-core-runtime-collector-issue-17)
   - [Issue #10 & #34: Unity Mono & IL2CPP JIT Hooking com GC Guard](#23-unity-mono--il2cpp-jit-hooking-issues-10--34)
5. **Infraestrutura e Plugins**:
   - [Issue #53 & #73: C-ABI Bindings e Sistema de Plugins](#24-c-abi-bindings--sistema-de-plugins-issues-53--73)
   - [Issue #5: MCP Relay TCP com Auto-Reconexão](#25-mcp-relay-tcp-issue-5)
   - [Issue #74: Pipeline de CI/CD e Qualidade de Código](#26-pipeline-de-cicd-issue-74)

---

## 1. Manual Mapping PE Nativo (Issue #27)

*Objetivo*: Validar a injeção manual de PE x86_64 sem usar `LoadLibraryA/W`, processando relocations, importações, chamadas de TLS callbacks e apagamento do cabeçalho PE (header wiping) para evasão de escaneamento de memória.

### Pré-requisitos
- Executável cobaia: `notepad.exe` ou `cmd.exe`.

### Passo a Passo
1. Abra um terminal PowerShell e inicie o alvo:
   ```powershell
   Start-Process notepad.exe -PassThru
   ```
2. Execute o teste de integração e verificação de injeção manual:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_core --test manual_map_e2e -- --nocapture
   ```
3. Teste via API CLI / Harness:
   ```powershell
   cargo run -p onyx_core --example manual_map_harness -- notepad.exe
   ```
### Critérios de Sucesso
- A saída exibe: `[+] Manual map completed successfully`.
- Verificação de TLS: `TLS Callbacks executados na ordem correta antes do EntryPoint`.
- Verificação de Header Wipe: Leitura dos primeiros 0x1000 bytes do endereço base no processo alvo retorna zeros (`00 00 00 ...`), comprovando que o cabeçalho `IMAGE_DOS_HEADER` e `IMAGE_NT_HEADERS` foi destruído após o mapeamento.

---

## 2. Plugin DLL Mapper (Issue #89)

*Objetivo*: Validar a interface de plugin para injeção por Manual Mapping.

### Passo a Passo
1. Execute a suíte de testes do plugin:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_dll_mapper -- --nocapture
   ```
2. Inicie um processo de teste (ex: `notepad.exe`):
   ```powershell
   $p = Start-Process notepad.exe -PassThru
   $pid_notepad = $p.Id
   ```
3. Execute o mapper chamando a DLL compilada de exemplo:
   ```powershell
   cargo run -p onyx_dll_mapper -- --pid $pid_notepad --dll target\debug\allochook.dll
   ```
### Critérios de Sucesso
- `17 passed; 0 failed`.
- `OpenProcess`, alocação de seções (`PAGE_EXECUTE_READWRITE` convertida para `PAGE_EXECUTE_READ` ou `PAGE_READONLY`), resolução de IAT de `kernel32.dll` e execução de stub remoto retornam código `0`.
- Feche o processo: `Stop-Process -Id $pid_notepad`.

---

## 3. Syscalls Indiretas Stealth (Issue #25)

*Objetivo*: Chamar APIs nativas do NT (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`) resolvendo o System Service Number (SSN) dinamicamente a partir do `ntdll.dll` em disco/memória e saltando para o gadget `syscall; ret` dentro da própria `ntdll`, evitando hooks de usermode colocados por EDRs/anticheats.

### Passo a Passo
1. Execute a verificação das syscalls:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p syscalls-indirect -- --nocapture
   ```
### Critérios de Sucesso
- `gadget_discovered`: O motor localiza o gadget `syscall; ret` legítimo no espaço de código de `ntdll.dll`.
- `ssn_resolves_core_nts`: O SSN das funções `NtQuerySystemInformation`, `NtAllocateVirtualMemory`, `NtProtectVirtualMemory` é resolvido dinamicamente por ordenação de endereços de exportação.
- `indirect_query_system_basic_info`: A chamada indireta executa sem tocar no prólogo hookado da API e retorna `STATUS_SUCCESS (0)`.

---

## 4. Auditoria de Strings e Stealth (Issue #4)

*Objetivo*: Garantir que binários, nomes de mutex, pipes IPC e strings residuais não exponham identificadores óbvios como `Cheat Engine`, `DBVM` ou referências estáticas que anticheats monitoram.

### Passo a Passo
1. Execute a auditoria automática de strings:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_core --test stealth_audit -- --nocapture
   ```
2. Verifique os nomes gerados em tempo de execução:
   ```powershell
   cargo test -p onyx_core test_mutex_randomization -- --nocapture
   ```
### Critérios de Sucesso
- O pipe MCP e mutexes geram nomes variáveis usando hash FNV-1a (ex: `\\.\pipe\OnyxRelay_A1B2C3D4`).
- Nenhuma string `CheatEngine` ou `Cheat Engine` é detectada nas tabelas de recursos ou binários de saída do backend.

---

## 5. Module Dumper PE (Issue #93)

*Objetivo*: Reconstruir um PE completo a partir de um módulo carregado na memória de um processo externo, convertendo RVAs de seções de volta para File Offsets físicos e recalculando cabeçalhos para gerar um `.exe`/`.dll` válido para análise no IDA/Ghidra.

### Passo a Passo
1. Inicie um processo cobaia:
   ```powershell
   $proc = Start-Process cmd.exe -PassThru
   ```
2. Execute o teste do dumper:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_core module_dumper -- --nocapture
   ```
3. Teste manual do dump salvando em disco:
   ```powershell
   cargo run -p onyx_core --example dump_module -- $proc.Id "cmd.exe" "C:\Users\Administrator\Desktop\dumped_cmd.exe"
   ```
4. Inspecione o cabeçalho do arquivo gerado:
   ```powershell
   Get-Item C:\Users\Administrator\Desktop\dumped_cmd.exe
   ```
### Critérios de Sucesso
- O arquivo despejado possui assinatura `MZ` e `PE\0\0`.
- O alinhamento das seções (`SectionAlignment` vs `FileAlignment`) é corrigido.
- Remova o arquivo de teste: `Remove-Item C:\Users\Administrator\Desktop\dumped_cmd.exe -Force`; feche `Stop-Process -Id $proc.Id`.

---

## 6. Scanner SIMD (AVX2 / AVX-512) (Issue #3)

*Objetivo*: Varredura massiva de valores (inteiros de 8, 16, 32, 64 bits e floats/doubles) utilizando instruções vetoriais AVX2 (`_mm256_cmpeq_epi*`) e AVX-512 quando suportado pelo processador.

### Passo a Passo
1. Execute a suíte de benchmarks e equivalência escalar vs vetorial:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_scanner --test value_scan -- --nocapture
   ```
2. Verifique o scan em processo real:
   ```powershell
   cargo test -p onyx_scanner e2e_scan_process_cmd -- --nocapture
   ```
### Critérios de Sucesso
- `equivalence_scalar_simd_i32` e `equivalence_scalar_simd_i64` reportam 100% de correspondência de offsets encontrados entre os métodos escalar e SIMD.
- Benchmark exibe taxa de varredura superior a **2.5 GB/s** em AVX2 e até **9.8 GB/s** em AVX-512.
- O teste e2e injeta valores conhecidos na memória do `cmd.exe` e encontra todos os 3 offsets com exatidão.

---

## 7. Pattern Scan AOB & Validador (Issue #31 & #55)

*Objetivo*: Localização ultrarrápida de padrões de bytes com wildcards (ex: `48 8B 05 ?? ?? ?? ?? 48 85 C0`) via AVX2 e validação de padrões únicos em módulos de jogos.

### Passo a Passo
1. Execute os testes do scanner de padrão:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_scanner --test pattern -- --nocapture
   ```
2. Execute o validador de AOB:
   ```powershell
   cargo test -p onyx_aob_tool -- --nocapture
   ```
### Critérios de Sucesso
- Todos os testes de máscara com wildcards (`??` e `?`) passam com sucesso.
- O validador confirma unicidade (1 único match) em buffers de 100 MB em menos de 1 segundo.

---

## 8. SmartScan Polimórfico (Issue #37)

*Objetivo*: Identificar em uma única passagem de leitura de memória se cada endereço corresponde a um ponteiro válido, inteiro assinado/não-assinado ou string ASCII/Unicode.

### Passo a Passo
1. Execute os testes do SmartScan:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_scanner --test smart -- --nocapture
   ```
### Critérios de Sucesso
- `any_scan_enumerates_pointer_and_strings`: Identifica simultaneamente ponteiros, strings e inteiros em uma única passagem.
- `single_pass_vs_four_passes_benchmark`: Passagem única executa dentro da janela de eficiência sem duplicar overhead de leitura de memória.

---

## 9. Cache de Memória em Chunks (Issue #22)

*Objetivo*: Otimizar a leitura em lote de páginas virtuais através de buffers contíguos de 64 KB, reduzindo overhead de chamadas de sistema `ReadProcessMemory`.

### Passo a Passo
1. Execute os testes de cache concorrente e benchmarking:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_core --test memory_cache -- --nocapture
   ```
### Critérios de Sucesso
- `concurrent_readers_same_region`: Múltiplas threads leem o mesmo chunk simultaneamente sem corrupção ou contenção de lock.
- `e2e_cmd_cobaia_sequential_scan_hit_rate`: Taxa de cache hit atinge >95% durante varredura sequencial.

---

## 10. Snapshot Engine Diferencial (Issue #35)

*Objetivo*: Gerar snapshots diferenciais de memória compactados via `xxHash3`, comparando alterações de estado (valores alterados, aumentados, diminuídos).

### Passo a Passo
1. Execute os testes do Snapshot Engine:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_core --test snapshot_e2e -- --nocapture
   ```
### Critérios de Sucesso
- A comparação de dois snapshots com 10.000 páginas detecta exatamente as páginas modificadas via delta hash sem falso positivo.

---

## 11. Memória Transacional com Rollback (Issue #40)

*Objetivo*: Permitir escrita em lote na memória de um processo com capacidade de rollback atômico caso qualquer gravação falhe ou o usuário decida desfazer as alterações (útil para testes de patches de código e cheats).

### Passo a Passo
1. Execute o teste end-to-end com rollback no Notepad:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_core --test mem_tx_e2e -- --nocapture
   ```
### Critérios de Sucesso
- O teste grava bytes conhecidos na memória do notepad, confirma que a memória foi alterada, executa o `rollback()` e valida que os bytes originais foram 100% restaurados.

---

## 12. Freezer Atômico de Valores (Issue #15)

*Objetivo*: Manter valores de memória congelados com thread de alta prioridade e operações atômicas sem degradar o FPS da aplicação alvo.

### Passo a Passo
1. Execute os testes do módulo freezer:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_freezer -- --nocapture
   ```
### Critérios de Sucesso
- A thread congela 50 variáveis em paralelo; gravações externas concorrentes são imediatamente sobrescritas para o valor congelado dentro da janela de amostragem (<5 ms).

---

## 13. Servidor GDB RSP (Issue #39)

*Objetivo*: Iniciar um servidor GDB Remote Serial Protocol na porta `127.0.0.1:2159` permitindo que IDA Pro, Ghidra ou x64dbg conectem diretamente ao OnyxEngine para depurar processos alvos remotamente.

### Passo a Passo
1. Execute o teste do protocolo GDB:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_gdb_server -- --nocapture
   ```
2. Teste de conexão manual via terminal / GDB Client:
   - Abra um terminal e inicie o mock server do Onyx:
     ```powershell
     cargo run -p onyx_gdb_server --example gdb_listener
     ```
   - Em outro terminal, teste com curl/nc ou `gdb`:
     ```powershell
     powershell -Command "$client = New-Object System.Net.Sockets.TcpClient('127.0.0.1', 2159); $stream = $client.GetStream(); $writer = New-Object System.IO.StreamWriter($stream); $reader = New-Object System.IO.StreamReader($stream); $writer.Write('$qSupported#37'); $writer.Flush(); $reader.ReadLine(); $client.Close()"
     ```
### Critérios de Sucesso
- O servidor responde a pacotes padrão RSP: `+$PacketSize=1000;...#checksum`.
- Registradores x86_64 (`rax`, `rbx`, `rip`, etc.) e leituras de memória são respondidos com pacotes hexadecimais válidos.

---

## 14. Breakpoints Ilimitados via PAGE_GUARD (Issue #36)

*Objetivo*: Emular breakpoints de hardware sem limitação de 4 registradores (DR0-DR3), marcando páginas de memória com `PAGE_GUARD` e tratando `STATUS_GUARD_PAGE_VIOLATION` no VEH para pausar a execução e capturar contexto.

### Passo a Passo
1. Execute o teste de integração:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_core --test page_guard_e2e -- --nocapture
   ```
### Critérios de Sucesso
- Disparo do breakpoint é capturado no endereço exato da instrução.
- O tratador restaura a proteção com single-step e rearma a `PAGE_GUARD` sem causar loop infinito ou crash na aplicação.

---

## 15. Depurador VEH em Rust (Issue #7)

*Objetivo*: Depuração através de `VectoredExceptionHandler` registrado em usermode, capturando exceções de software (`INT3`), hardware (`STATUS_SINGLE_STEP`) e restaurando a execução sem travar a thread de destino.

### Passo a Passo
1. Execute os testes unitários e e2e da DLL VEH:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p vehdebug_dll -- --nocapture
   ```
### Critérios de Sucesso
- Breakpoint de software (`0xCC`) dispara o callback registrado.
- EFLAGS.RF (Resume Flag) é setado para prosseguir a execução após o breakpoint sem re-disparo imediato.

---

## 16. Hardware Breakpoints (DR0-DR3/DR7) (Issue #16)

*Objetivo*: Sincronizar registradores de depuração da CPU (`GetThreadContext`/`SetThreadContext`) em threads ativas sem congelamento perceptível de execução.

### Passo a Passo
1. Execute o harness de registradores de depuração:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo run -p onyx_core --example dr_dump
   ```
### Critérios de Sucesso
- Exibe o estado de DR0, DR1, DR2, DR3, DR6 e DR7 da thread atual e permite manipulação de bits de condição (execução, escrita, leitura/escrita).

---

## 17. Hook Engine Detour 14-bytes (Issue #30)

*Objetivo*: Criar ganchos inline (detours) de 14 bytes (`FF 25 00 00 00 00 [64-bit address]`) com desmontagem Zydis para copiar e realocar instruções originais do prólogo, preservando saltos RIP-relativos via trampolim.

### Passo a Passo
1. Execute os testes unitários e e2e do Hook Engine:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_hook -- --nocapture
   ```
### Critérios de Sucesso
- A função alvo tem sua execução redirecionada para a função gancho.
- A função gancho pode invocar o trampolim original e retornar o resultado esperado intacto.
- Desinstalação do gancho restaura os bytes originais da função perfeitamente.

---

## 18. Disassembler Zydis & CFG (Issue #14)

*Objetivo*: Desmontagem nativa de instruções x86_64 utilizando biblioteca Zydis, cálculo de saltos condicionais/incondicionais e construção do grafo de fluxo de controle (CFG).

### Passo a Passo
1. Execute os testes do desassemblador:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_disasm -- --nocapture
   ```
### Critérios de Sucesso
- Instruções complexas (AVX, VEX, RIP-relative) são decodificadas com mnemônicos, operandos e tamanhos corretos.
- Blocos básicos do grafo de controle (Basic Blocks) identificam nós de entrada, bifurcações e nós de saída sem ciclos corrompidos.

---

## 19. Auto Assembler 64-bit Parser (Issue #18)

*Objetivo*: Parser léxico e semântico de scripts Cheat Engine Auto Assembler (comandos `alloc`, `dealloc`, `define`, `registersymbol`, `assert`, `createthread`, `label`, `[ENABLE]`, `[DISABLE]`).

### Passo a Passo
1. Execute a suíte de testes do parser:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_aa -- --nocapture
   ```
### Critérios de Sucesso
- Comentários no estilo `//`, `/* */` e `{ }` são removidos.
- Labels e símbolos de 64 bits são resolvidos em 2 passagens.
- Blocos `[ENABLE]` e `[DISABLE]` são separados e analisados com precisão sintática.

---

## 20. Speedhack QPC Virtual Clock (Issue #13)

*Objetivo*: Alteração fluida da passagem de tempo em jogos interceptando `QueryPerformanceCounter`, `QueryPerformanceFrequency`, `GetTickCount` e `GetTickCount64` através de relógio virtual com interpolação Contínua para evitar saltos ou gaguejos (micro-stutters).

### Passo a Passo
1. Execute a suíte de testes do Speedhack:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p speedhack_dll -- --nocapture
   ```
### Critérios de Sucesso
- Aceleração para 2.0x dobra os ticks retornados em relação ao tempo real medido via `std::time::Instant`.
- Desaceleração para 0.5x divide os ticks pela metade.
- O rebase do relógio virtual é contínuo, sem saltos para trás (monotônico crescente garantido).

---

## 21. Overlay DirectX 11 Present Hook (Issue #38)

*Objetivo*: Injeção de gancho no método `Present` da `IDXGISwapChain` do DirectX 11 para renderização de interface gráfica e menus diretamente sobre a tela de jogos.

### Passo a Passo
1. Execute os testes unitários e de integração DirectX:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_overlay -- --nocapture
   ```
### Critérios de Sucesso
- Criação de dispositivo D3D11 headless em memória e SwapChain em janela oculta.
- Gancho na VTable no índice `8` (`Present`) intercepta o ciclo de renderização.
- Verificação do frame buffer detecta pixels com a cor dominante configurada no gancho (`green_dominant > 0`).

---

## 22. .NET Core Runtime Collector (Issue #17)

*Objetivo*: Detecção e inspeção de executáveis rodando sob runtimes modernos .NET Core (.NET 6, 7, 8 e 9 via `coreclr.dll` / `hostpolicy.dll`), extraindo versão do cabeçalho `VS_FIXEDFILEINFO`.

### Passo a Passo
1. Execute os testes do coletor .NET:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_dotnet -- --nocapture
   ```
### Critérios de Sucesso
- Parsing de estrutura `VS_VERSIONINFO` extrai números de versão sem falhas (ex: `7.0.11.0`).
- Processos que carregam `coreclr.dll` são identificados com seus caminhos de módulo e pontos de entrada gerenciados.

---

## 23. Unity Mono & IL2CPP JIT Hooking (Issues #10 & #34)

*Objetivo*: Suporte a jogos desenvolvidos na Unity: detecção de instâncias Mono 64-bit (`mono-2.0-bdwgc.dll`) e IL2CPP (`GameAssembly.dll`), além de gancho em métodos compilados via JIT protegendo threads contra o coletor de lixo (GC Guard).

### Passo a Passo
1. Execute os testes do módulo Mono:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_mono -- --nocapture
   ```
2. Execute os testes de hook JIT e GC Guard:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_mono_hook -- --nocapture
   ```
### Critérios de Sucesso
- Exportações de API Mono (`mono_domain_get`, `mono_assembly_open`, etc.) são mapeadas.
- GC Guard impede que o coletor de lixo mova ou desaloque o método hookado durante a execução do trampolim.

---

## 24. C-ABI Bindings & Sistema de Plugins (Issues #53 & #73)

*Objetivo*: Exportar funções nativas com convenção `extern "C"` (`#[no_mangle]`) na DLL de backend (`onyx_backend.dll`) para consumo pela interface Pascal/GUI e plugins externos em C/C++/Rust.

### Passo a Passo
1. Execute a verificação das exportações C-ABI:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_backend --test abi_smoke -- --nocapture
   ```
### Critérios de Sucesso
- Funções exportadas:
  - `onyx_gdb_start`, `onyx_gdb_stop`
  - `onyx_hook_install`, `onyx_hook_uninstall`
  - `onyx_aa_parse_and_analyze`
  - `onyx_manual_map_inject`
  - `onyx_speedhack_set_speed`
- Todas as chamadas retornam ponteiros e códigos de status válidos (`0 = OK`).

---

## 25. MCP Relay TCP (Issue #5)

*Objetivo*: Relay TCP e WebSocket para conexão do Engine com ferramentas de IA e agentes, incluindo reconexão automática e heartbeat.

### Passo a Passo
1. Execute a suíte de testes de resiliência:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo test -p onyx_core test_mcp_relay -- --nocapture
   ```
### Critérios de Sucesso
- Desconexão simulada do cliente restabelece conexão no próximo heartbeat sem travar a thread principal.

---

## 26. Pipeline de CI/CD (Issue #74)

*Objetivo*: Garantir que todo o repositório compile com zero warnings em Rust (`-D warnings`), formatação obrigatória (`cargo fmt`), verificação de vulnerabilidades em dependências (`cargo audit`) e compilação da interface gráfica em Pascal via `lazbuild`.

### Passo a Passo
1. Execute a verificação completa localmente:
   ```powershell
   cd C:\Users\Administrator\Desktop\OnyxEngine
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```
2. Verifique o status das Actions no GitHub:
   ```powershell
   gh pr checks 83
   # ou no commit da main:
   gh run list --limit 3
   ```
### Critérios de Sucesso
- `cargo fmt` não aponta diferenças de estilo.
- `cargo clippy` reporta 0 erros sob `-D warnings`.
- `lazbuild UI` compila `UI\onyxengine.lpi` com sucesso na nuvem.
- Todos os workflows de CI estão marcados com status verde (`pass / success`).

---

## Roteiro Rápido para Teste Geral do Workspace

Caso queira rodar uma validação total de uma só vez em sua máquina antes de abrir os jogos:

```powershell
cd C:\Users\Administrator\Desktop\OnyxEngine

Write-Host "1. Verificando formatacao..." -ForegroundColor Cyan
cargo fmt --all -- --check

Write-Host "2. Verificando clippy em modo estrito..." -ForegroundColor Cyan
cargo clippy --workspace --all-targets -- -D warnings

Write-Host "3. Rodando todos os 163+ testes do workspace..." -ForegroundColor Cyan
cargo test --workspace

Write-Host "Validacao concluida com sucesso!" -ForegroundColor Green
```
