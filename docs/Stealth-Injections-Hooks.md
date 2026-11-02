# Módulos de Stealth, Injeções e Hooks Avançados

## 1. Visão Geral

Os mecanismos tradicionais de injeção de DLLs (`CreateRemoteThread` + `LoadLibraryW`) e depuração usermode (`DebugActiveProcess`) são facilmente detectados por sistemas modernos de proteção (como Vanguard, EAC, BattlEye e EDRs corporativos) devido à presença de módulos na lista de DLLs carregadas (`InLoadOrderModuleList`), hooks inline em APIs de usermode (`ntdll.dll`) e verificações de integridade de pilha (*callstack walking*).

O OnyxEngine resolve esse desafio através de um conjunto dedicado de bibliotecas modulares de evasão e injeção em Rust e Assembly, operando de forma invisível no processo alvo.

---

## 2. Injeção por Manual Mapping (`onyx_dll_mapper.dll`)

O **Manual Mapping** é a técnica mais avançada de injeção em Ring-3. Ele simula o comportamento do carregador nativo do sistema operacional (`LdrLoadDll` do Windows), carregando e linkando um executável PE (.dll) diretamente na memória virtual do processo alvo **sem registrar o módulo em nenhuma estrutura interna do Windows** (como o PEB ou o `Ldr` list).

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

### 2.1 Matemática de Relocation (Base Relocations)
Se uma DLL foi compilada esperando ser carregada no endereço preferencial $B_{\text{orig}} = \text{0x180000000}$, mas o `VirtualAllocEx` alocou o bloco no endereço $B_{\text{real}} = \text{0x240A00000}$, o deslocamento $\Delta$ é calculado:

$$\Delta = B_{\text{real}} - B_{\text{orig}}$$

Para cada entrada do tipo `IMAGE_REL_BASED_DIR64` na tabela `.reloc`, o endereço de 64 bits é corrigido:

$$*(\text{uint64\_t}*)(B_{\text{real}} + \text{VirtualAddress} + \text{Offset}) += \Delta$$

---

## 3. Expurgo e Destruição de Cabeçalhos PE (`pe_strip.dll`)

Após o carregamento da DLL na memória remota, scanners de assinatura de memória (como Moneta, PE-sieve ou módulos anticheat) realizam varreduras buscando assinaturas de executáveis como a marca mágica `MZ` (`0x5A4D`) ou `PE\0\0` (`0x00004550`).

O `pe_strip.dll` sobrescreve todos os cabeçalhos da imagem injetada com zeros ou ruído criptográfico pseudo-aleatório:
- `IMAGE_DOS_HEADER` (64 bytes zerados)
- `IMAGE_NT_HEADERS` (Signature + FileHeader + OptionalHeader zerados)
- Tabela de seções (`IMAGE_SECTION_HEADER` zerada)

Isso transforma a DLL em um bloco anônimo de memória privada (`MEM_PRIVATE`), indistinguível de um buffer comum de dados do jogo.

---

## 4. Falsificação de Pilha de Chamadas (`callstack_spoof.dll`)

Sistemas de detecção modernos interceptam APIs de alto privilégio (`NtReadVirtualMemory`, `NtAllocateVirtualMemory`) e inspecionam o endereço de retorno na pilha de execução (*Callstack Return Address*). Se o retorno apontar para uma região de memória anônima (fora dos módulos assinados do jogo ou do sistema operacional), a injeção é denunciada imediatamente.

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

Muitos anticheats instalam hooks inline (instruções `JMP <detour>`) nos primeiros 5 a 14 bytes das funções em `ntdll.dll` para monitorar chamadas de sistema.

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

O processo continua em plena execução na CPU, mas é completamente invisível para o Gerenciador de Tarefas, Process Hacker e `tasklist`.

---

## 7. Depuração por Hardware via VEH (`vehdebug_dll.dll`)

A depuração convencional do Windows (`DbgUiRemoteBreakin`) cria threads adicionais detectáveis e exige privilégios de debug.

O módulo **`vehdebug_dll.dll`**:
1. Registra um manipulador de exceções vetorizadas de usermode chamando `AddVectoredExceptionHandler(1, VectoredHandler)`.
2. Habilita registradores de debug de hardware da CPU (**DR0, DR1, DR2, DR3**) e configura o registrador de controle **DR7** para disparar eventos de execução, leitura ou escrita em endereços específicos.
3. Ao atingir o endereço monitorado, a CPU emite uma exceção `STATUS_SINGLE_STEP (0x80000004)`.
4. O `VectoredHandler` intercepta a exceção antes de qualquer depurador do sistema, lê ou modifica os registradores na estrutura `PCONTEXT`, e retorna `EXCEPTION_CONTINUE_EXECUTION`, permitindo inspecionar variáveis sem pausar o processo nem registrar sessões de depuração.

---

## 8. Modificação Temporal de Clock (`speedhack_dll.dll`)

O **Speedhack** permite acelerar ou desacelerar jogos manipulando o fluxo de tempo percebido pelo motor gráfico ou pela física:
- Instala hooks transparentes nas APIs de cronometragem do Windows:
  - `QueryPerformanceCounter`
  - `QueryPerformanceFrequency`
  - `GetTickCount` / `GetTickCount64`
  - `timeGetTime`
- A fórmula de distorção temporal contínua garante que não ocorram saltos bruscos (*time warping glitches*):

$$T_{\text{falso}} = T_{\text{base\_falsa}} + (T_{\text{real\_atual}} - T_{\text{real\_anterior}}) \times \text{Multiplicador}$$

Dessa forma, o jogo opera a 0.5x (câmera lenta), 2.0x, 5.0x ou 10.0x de velocidade de forma perfeitamente suave e imperceptível para o loop de renderização.
