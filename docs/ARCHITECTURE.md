# Arquitetura Geral do OnyxEngine

## 1. Topologia do Sistema

O OnyxEngine adota um modelo em camadas desacoplado, projetado para garantir estabilidade, segurança operacional e performance determinística em operações de memória em grande escala.

```
+-------------------------------------------------------------------------+
|                       Interface Gráfica (GUI)                          |
|  - Lazarus / Free Pascal (UI/OnyxBackend.pas, MainUnit.pas, Form...)    |
|  - Cheat Engine 7.7 GUI modificada e desvinculada de rotinas legacy    |
+------------------------------------+------------------------------------+
                                     |
                                     | C-ABI Export (stdcall / cdecl)
                                     v
+-------------------------------------------------------------------------+
|                  Camada de Orquestração: onyx_backend.dll               |
|  - API de Processos, Varredura, Desmontagem, Congelamento e Erros       |
|  - Thread-Local LastError Store (PT-BR padrão / EN-US secundário)       |
|  - Despachante de Comandos MCP Bridge e Servidor GDB Remoto             |
+---------+--------------------+---------------------+--------------------+
          |                    |                     |
          v                    v                     v
+--------------------+ +-------------------+ +----------------------------+
|  Módulos Runtime   | | Injeções & Hooks  | |  Plugins de Extensão       |
|  - onyx_scanner    | | - speedhack_dll   | |  - onyx_aob_tool           |
|  - onyx_pointer    | | - vehdebug_dll    | |  - onyx_dll_mapper         |
|  - onyx_disasm     | | - d3dhook_dll     | +----------------------------+
|  - onyx_freezer    | | - allochook_dll   |
|  - onyx_aa         | | - luaclient_dll   |
|  - onyx_mono       | | - callstack_spoof |
|  - onyx_mono_hook  | | - pe_strip        |
|  - onyx_dotnet     | | - syscalls_ind    |
|  - onyx_overlay    | | - taskmgr_cloak   |
|  - onyx_hook       | | - onyx_shield     |
+---------+----------+ +---------+---------+
          |                      |
          +----------+-----------+
                     |
                     v
+-------------------------------------------------------------------------+
|                   Núcleo Central: onyx_core (Rust)                      |
|  - Gerenciador de Processos (NtOpenProcess / OpenProcess / Toolhelp)    |
|  - Manipulador de Memória Virtual (NtRead/WriteVirtualMemory)           |
|  - Sistema Central de Erros e Diagnósticos (OnyxError / i18n)           |
|  - Símbolos PDB (DbgHelp Symbol Engine / SymSrv)                        |
|  - Mecanismos de Proteção e Evasão PE/SEH/PPL                           |
+------------------------------------+------------------------------------+
                                     |
                                     | IOCTL (Fast I/O & Direct Buffer)
                                     v
+-------------------------------------------------------------------------+
|                  Camada de Kernel Ring-0: OwMemDriver.sys               |
|  - Mapeamento Físico de Memória Direta via CR3                          |
|  - Remoção Dinâmica de ObRegisterCallbacks (Process & Thread)           |
|  - Rastreamento por Hardware Intel PT / Ultimap 2 (ToPA buffer)         |
|  - Evasão de PiDDBCacheTable e Desvinculação DKOM de PsLoadedModuleList |
+-------------------------------------------------------------------------+
```

## 2. Estrutura de Diretórios do Repositório

```
OnyxEngine/
├── bin/                             # Binários compilados para distribuição
│   ├── OnyxEngine-CE.exe            # Executável principal (Frontend compilado)
│   ├── onyx_backend.dll             # Orquestrador nativo do backend
│   ├── onyx_scanner.dll             # Motor de varredura de memória
│   ├── onyx_pointer.dll             # Motor de resolução de ponteiros
│   ├── onyx_disasm.dll              # Desmontador de instruções x86_64
│   ├── onyx_freezer.dll             # Thread de congelamento de valores
│   ├── driver/                      # Pacote do driver de kernel
│   │   ├── OwMemDriver.sys          # Binário Ring-0 do driver
│   │   ├── OwMemDriver.inf          # Arquivo de instalação
│   │   └── OwMemDriver.cer          # Certificado de teste
│   ├── modules/                     # Módulos de análise e runtimes
│   │   ├── injections/              # DLLs carregáveis e injetáveis no alvo
│   └── plugins/                     # Extensões externas dinâmicas
├── crates/                          # Workspace de código Rust
│   ├── core/                        # Biblioteca central de lógica de baixo nível
│   │   └── src/error/               # Submódulo unificado de erros e diagnósticos
│   ├── backend/                     # Ponto de entrada C-ABI para a interface
│   ├── modules/                     # Sub-crates compilados como cdylib/rlib
│   ├── dlls/                        # DLLs de injeção e stealth
│   └── plugins/                     # Plugins exportáveis
├── driver/                          # Código-fonte oficial do driver Ring-0
│   ├── src/                         # Fontes C e ASM (.c, .asm)
│   ├── include/                     # Headers de controle e IOCTL (.h)
│   └── OnyxDriver.vcxproj           # Projeto do Visual Studio com WDK
├── UI/                              # Interface do Usuário em Free Pascal
│   ├── OnyxBackend.pas              # Bridge de ligação C-ABI e rotinas de erro
│   └── bin/                         # Cópia local de desenvolvimento das DLLs
└── docs/                            # Documentação técnica de engenharia
```

## 3. As 24 Bibliotecas Modulares (DLLs)

A engenharia do OnyxEngine opera sob modularidade estrita. Nenhuma rotina crítica reside monolithicamente no executável, permitindo substituição, atualização e patching independente de cada subsistema:

1. `onyx_backend.dll`: Ponto central de exportação C-ABI para a GUI.
2. `onyx_scanner.dll`: Mecanismo multi-thread de varredura com paginação de chunks.
3. `onyx_pointer.dll`: Resolvedor e minerador de ponteiros multinível com ordenação de profundidade.
4. `onyx_disasm.dll`: Desmontador de instruções x86_64 baseado em Zydis com extração de operandos RIP-relative.
5. `onyx_freezer.dll`: Sistema de controle temporal e sustentação de valores em memória.
6. `onyx_aa.dll`: Compilador JIT e analisador de scripts de Auto Assembler de 2 passos.
7. `onyx_mono.dll`: Inspetor de runtimes Mono Classic, Unity e Il2Cpp.
8. `onyx_mono_hook.dll`: Interceptador de compilação JIT de métodos gerenciados em tempo real.
9. `onyx_dotnet.dll`: Enumerador de runtimes e classes do CLR do .NET Framework e .NET Core.
10. `onyx_gdb_server.dll`: Servidor de depuração remota compatível com o protocolo GDB RSP.
11. `onyx_overlay.dll`: Renderizador de overlay gráfico baseado em egui e DirectX.
12. `onyx_hook.dll`: Gerenciador de detours, trampolins de código e hooks de prólogo.
13. `speedhack_dll.dll`: Modificador de temporização via intercepção de `QueryPerformanceCounter` e `GetTickCount64`.
14. `vehdebug_dll.dll`: Depurador de hardware baseado em Vectored Exception Handling (DR0-DR3).
15. `d3dhook_dll.dll`: Hook de swapchain Direct3D 9, 11 e 12 para desenho e inspeção visual.
16. `allochook_dll.dll`: Interceptador de alocações de memória para auditoria de heap.
17. `luaclient_dll.dll`: Cliente de automação e integração de scripts Lua.
18. `callstack_spoof.dll`: Evasor de análise de pilha através de sintetização de frames de retorno legítimos.
19. `pe_strip.dll`: Manipulador e expurgador de cabeçalhos PE para evitar detecção de dumps.
20. `syscalls_indirect.dll`: Invocador de syscalls nativas indiretas para contornar EDRs usermode.
21. `taskmgr_cloak.dll`: Ocultador de processos na tabela do Gerenciador de Tarefas do Windows.
22. `onyx_shield.dll`: Módulo consolidado de proteção contra dump, anexação indevida e depuração ativa.
23. `onyx_dll_mapper.dll`: Injetor manual de bibliotecas (Manual Mapping) com evasão de VAD e module stomping.
24. `onyx_aob_tool.dll`: Gerador e validador de assinaturas e máscaras de bytes (AOB).

## 4. Comunicação entre Camadas

### Frontend -> Backend (Usermode)
A interface em Pascal importa as funções C-ABI de `onyx_backend.dll` via convenção `stdcall` no Windows. Quando uma operação falha (retornando `0`, `-1` ou ponteiro nulo), o Pascal consulta imediatamente `onyx_error_get_last_code()` e `onyx_error_get_last_formatted()`. O diagnóstico traduzido em português é apresentado ao operador ou registrado em log, contendo o endereço virtual, código de erro e a causa técnica exata.

### Backend -> Driver (Ring-3 para Ring-0)
O acesso ao driver ocorre via `CreateFileW("\\\\.\\OwMemDriver", ...)` e despachos `DeviceIoControl`. Quando proteções de processo (PPL) impedem que `NtOpenProcess` obtenha handles válidos, o backend redireciona as operações para os códigos IOCTL do driver. O driver resolve os endereços físicos caminhando pela árvore de tabelas de paginação (PML4 -> PDPT -> PD -> PT) a partir do registrador CR3 do processo alvo, lendo páginas diretamente da memória física sem disparar eventos no subsistema de segurança usermode.
