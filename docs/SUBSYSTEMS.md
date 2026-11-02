# Subsistemas Técnicos e Engenharia de Módulos

## 1. Núcleo Central (onyx_core)

O `onyx_core` é o alicerce técnico de todo o ecossistema OnyxEngine. Ele encapsula a interação de baixo nível com as estruturas do sistema operacional Windows, depuração por hardware e algoritmos fundamentais de engenharia reversa.

### 1.1 Gerenciamento de Processos e Memória (src/process/)
- **`process.rs` (`Process`):** Representa uma sessão de controle sobre um processo alvo. Suporta três modos operacionais:
  - `NtApi`: Utiliza stubs nativos da `ntdll.dll` (`NtOpenProcess`, `NtReadVirtualMemory`, `NtWriteVirtualMemory`, `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtFreeVirtualMemory`).
  - `KernelDbk`: Despacha comandos de leitura e escrita diretamente para o driver `OwMemDriver.sys`, contornando permissões usermode e operando sob CR3 físico.
  - `Win32`: Modo clássico baseado nas APIs de alto nível da `kernel32.dll`.
- **`cache.rs` (`MemoryCache`):** Sistema de cache inteligente com estratégia de anel LRU (*Least Recently Used*). Agrupa leituras contíguas em blocos de 4 KB para acelerar varreduras com mais de 85% de taxa de acerto (*hit rate*).
- **`transaction.rs` (`MemoryTransaction`):** Suporte a transações de memória atômicas com reversão automática (*rollback*). Permite gravar patches temporários e restaurar o estado original caso uma operação subsequente falhe.
- **`watcher.rs` (`ProcessWatcher`):** Monitor em segundo plano baseado em WMI e polling de baixa sobrecarga que detecta a criação e encerramento de processos alvo em tempo real.
- **`symbol.rs` e `pdb.rs`:** Motor de símbolos integrado ao DbgHelp e resolvedor de PDBs remotos com suporte a servidores SymSrv da Microsoft.

### 1.2 Depuração e Análise Dinâmica (src/debugger/)
- **`veh.rs` (`VehDebugger`):** Depurador de hardware baseado em *Vectored Exception Handling*. Manipula os registradores de depuração de hardware do processador (`DR0`, `DR1`, `DR2`, `DR3`) e a máscara de controle `DR7`, interceptando acessos de execução, leitura e gravação sem injetar opcodes `INT3` (`0xCC`) na memória do alvo.
- **`page_guard.rs` (`PageGuardDebugger`):** Depurador de software baseado no atributo `PAGE_GUARD`. Monitora páginas inteiras e rastreia o ciclo de vida da exceção `STATUS_GUARD_PAGE_VIOLATION`, filtrando falsos positivos na mesma página e restaurando a guarda no passo seguinte.
- **`disasm.rs` (`Disassembler`):** Motor de desmontagem x86_64 de alta performance construído sobre a biblioteca Zydis. Decodifica prefixos REX, comprimentos de instrução, mnemônicos e operandos.
- **`relocator.rs` (`InstructionRelocator`):** Motor de relocação de código de máquina. Analisa prólogos de funções alvo e reconstrói instruções de salto relativo (`rel8`, `rel32`, `jcc`, `call`) para acomodar trampolins de desvio de tamanho arbitrário sem corromper ponteiros de execução.
- **`intel_pt.rs` (`IntelPtDecoder`):** Decodificador de telemetria por hardware Intel Processor Trace. Processa pacotes ToPA (*Table of Physical Addresses*), TIP, PGE, PGD e TNT gerados pelo processador em tempo real, permitindo reconstruir fluxos de controle de execução com impacto zero no ciclo de clock.

### 1.3 Segurança Operacional e Evasão (src/security/)
- **`anti_attach.rs`:** Monitor de threads que detecta chamadas remotas de `DbgBreakPoint` e `DbgUiRemoteBreakin`, desarmando tentativas de depuração externa.
- **`anti_debug.rs`:** Sanitizador de telemetria do processo. Mascara os campos `BeingDebugged`, `NtGlobalFlag` do PEB, normaliza contadores de ciclo de clock via `RDTSC` e mascara as chamadas a `NtQueryInformationProcess` para as classes `ProcessDebugPort`, `ProcessDebugObjectHandle` e `ProcessDebugFlags`.
- **`anti_dump.rs`:** Distorcedor e sanitizador de cabeçalhos PE em memória. Corrompe deliberadamente ponteiros da tabela de seções e IAT no momento em que ferramentas de dumping de processos tentam varrer o espaço virtual do executável.
- **`taskmgr_cloak.rs`:** Filtro interceptador de estruturas `SYSTEM_PROCESS_INFORMATION`, removendo o PID do OnyxEngine da listagem apresentada por utilitários de monitoramento como o Gerenciador de Tarefas do Windows e Process Hacker.

---

## 2. Orquestrador C-ABI (crates/backend)

O `crates/backend` expõe uma interface C-ABI estrita (`#[no_mangle] extern "C"`) compilada como `onyx_backend.dll`.

### 2.1 Subsistema Central de Erros (src/api/error.rs)
- Exporta as rotinas de consulta de diagnósticos em tempo de execução:
  - `onyx_error_get_last_code()`: Retorna o código numérico padronizado da última falha.
  - `onyx_error_get_last_message()`: Preenche um buffer de texto com a mensagem clara traduzida (em Português do Brasil por padrão).
  - `onyx_error_get_last_formatted()`: Retorna a string diagnóstica completa no formato `[ERRO XXXX] Mensagem (Endereço: 0x...) [Win32/NT: 0x...] -> Detalhe: ...`.
  - `onyx_error_set_locale()`: Permite comutar dinamicamente o idioma de diagnóstico entre `1` (PT-BR) e `0` (EN-US).
  - `onyx_error_clear()`: Limpa o estado de erro thread-local e global.

### 2.2 Controle de Processos e Memória (src/api/process.rs)
- Fornece pontos de entrada para enumeração de processos, leitura, gravação, alteração de proteção de página, alocação virtual e injeção de bibliotecas, garantindo que qualquer retorno nulo ou negativo seja precedido pelo registro exato do erro contextual.

### 2.3 Servidor de Depuração GDB (src/api/gdb.rs)
- Implementa um endpoint de rede compatível com o protocolo GDB RSP (*Remote Serial Protocol*). Permite conectar ferramentas como IDA Pro, Ghidra ou x64dbg diretamente ao backend do OnyxEngine através de um socket TCP local.

---

## 3. Módulos e Runtimes Especializados (crates/modules/)

1. **`onyx_scanner`:**
   - Motor de varredura multi-thread baseado em paralelismo de dados (Rayon). Divide o espaço de memória commitado em blocos independentes e executa comparações vetoriais com suporte a tipos escalares, ponto flutuante com tolerância e sequências binárias AOB.
2. **`onyx_pointer`:**
   - Motor minerador de ponteiros multinível. Constrói um grafo em memória das relações de endereçamento do processo alvo e descobre caminhos determinísticos a partir de módulos estáticos até uma variável volátil.
3. **`onyx_aa`:**
   - Compilador de Auto Assembler de 2 passos. Suporta alocação de code caves (`alloc`), criação de rótulos (`label`), desvios relativos e diretivas de montagem em tempo real.
4. **`onyx_mono` e `onyx_mono_hook`:**
   - Inspetor e manipulador de runtimes Mono e Unity Il2Cpp. Permite enumerar domínios gerenciados, inspecionar árvores de classes e interceptar a compilação JIT de métodos em tempo de execução.
5. **`onyx_dotnet`:**
   - Inspetor do runtime .NET CLR nativo da Microsoft, permitindo ler campos de objetos gerenciados e metadados de assemblies.
6. **`onyx_hook`:**
   - Mecanismo genérico de *Inline Hooking* e geração de trampolins com suporte completo a relocações de instruções x86_64.
7. **`onyx_overlay`:**
   - Renderizador de interface gráfica leve embutido diretamente na thread de apresentação visual de janelas Direct3D.

---

## 4. Bibliotecas de Injeção e Evasão (crates/dlls/)

1. **`speedhack_dll`:** Modifica a escala de tempo de jogos interceptando as chamadas de alta precisão `QueryPerformanceCounter`, `QueryPerformanceFrequency` e `GetTickCount64`.
2. **`vehdebug_dll`:** Biblioteca injetável no espaço de endereçamento do alvo para interceptação de eventos de depuração local através de manipuladores VEH internos.
3. **`d3dhook_dll`:** Intercepta as tabelas virtuais (`vtable`) de dispositivos Direct3D 9, 11 e 12, permitindo desenhar gráficos diretamente no backbuffer do jogo.
4. **`allochook_dll`:** Intercepta as APIs de alocação de memória da runtime C (`malloc`, `free`, `realloc`) para auditoria de vazamento de memória e identificação de buffers de dados.
5. **`luaclient_dll`:** Ponte de comunicação IPC com o interpretador Lua do Cheat Engine.
6. **`callstack_spoof`:** Evasor de heurísticas de análise de pilha (Callstack Walkers de antivírus e anticheats). Substitui o endereço de retorno no frame da thread por ponteiros pertencentes a bibliotecas legítimas do Windows.
7. **`pe_strip`:** Limpa e zera os cabeçalhos PE de bibliotecas injetadas na memória do alvo para evitar detecção por varreduras de assinaturas de dumps.
8. **`syscalls_indirect`:** Invocador de chamadas de sistema (syscalls) indiretas que salta diretamente para o opcode `syscall; ret` dentro da `ntdll.dll`, contornando ganchos usermode aplicados por soluções de EDR.
9. **`taskmgr_cloak`:** Injeta stubs que mascaram a existência do processo na listagem da tabela de tarefas do sistema operacional.
10. **`onyx_shield`:** Agrega proteções contra leitura indevida de memória, detecção de depuradores e auditoria de integridade.

---

## 5. Plugins de Extensão (crates/plugins/)

1. **`onyx_aob_tool`:**
   - Utilitário de criação e validação de assinaturas de bytes. Analisa blocos de código executável, identifica operandos que variam entre compilações e gera máscaras de busca curinga (`?`) garantindo que o padrão gerado seja exclusivo em todo o binário.
2. **`onyx_dll_mapper`:**
   - Injetor manual de bibliotecas (Manual Mapping). Lê um arquivo PE do disco, aloca espaço na memória do alvo, processa o diretório de relocações, resolve todas as dependências na IAT sem invocar a API `LoadLibraryW`, dispara os callbacks de TLS e executa o ponto de entrada `DllMain` via sequestro de thread ou criação remota.

---

## 6. Driver de Kernel Ring-0 (OwMemDriver.sys)

O driver de kernel oficial do OnyxEngine opera no nível mais privilegiado do processador (Ring-0) para viabilizar inspeções em cenários onde restrições do sistema operacional impedem o funcionamento normal em usermode.

### 6.1 Acesso Físico via CR3
- Cada processo no Windows possui seu próprio espaço de endereçamento virtual isolado gerenciado pelo registrador de controle CR3. O `OwMemDriver` obtém o endereço base do diretório de páginas do processo através do seu `EPROCESS` e navega pelos 4 níveis de paginação (PML4 -> PDPT -> PD -> PT). O driver mapeia as páginas físicas de memória diretamente na RAM, tornando irrelevante qualquer bloqueio de `OpenProcess` ou proteção de usermode.

### 6.2 Remoção de ObRegisterCallbacks
- Mecanismos modernos de segurança registram callbacks através da rotina do kernel `ObRegisterCallbacks` para interceptar a criação e duplicação de handles de processos e threads, removendo direitos como `PROCESS_VM_READ` ou `PROCESS_ALL_ACCESS`. O `OwMemDriver` localiza a lista encadeada interna de callbacks do `ntoskrnl.exe` e remove as entradas restritivas, restabelecendo o fluxo normal de criação de handles privilegiados.

### 6.3 Evasão DKOM e Limpeza de PiDDBCacheTable
- Para operar de maneira indetectável, o driver suporta manipulação direta de objetos do kernel (DKOM):
  - Remove o descritor do driver da lista duplamente encadeada `PsLoadedModuleList`.
  - Localiza a tabela `PiDDBCacheTable` e o hash listado no cache de integridade de drivers do Windows e expurga os registros associados ao nome do driver, impedindo que utilitários de auditoria identifiquem que o módulo foi carregado.

### 6.4 Rastreamento de Execução por Hardware (Intel PT / Ultimap 2)
- O driver configura os registradores MSR específicos do processador para ativar o Intel Processor Trace. O tráfego de execução gerado pelo núcleo da CPU é gravado diretamente em buffers ToPA físicos alocados em memória não paginável, fornecendo amostragem de fluxo de instruções em velocidade de hardware.
