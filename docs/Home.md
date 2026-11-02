# Bem-vindo à Wiki Oficial do OnyxEngine

O **OnyxEngine** é uma plataforma profissional de engenharia reversa, análise dinâmica de memória e instrumentação de processos x86_64 para sistemas Windows. O projeto moderniza a fundação clássica do Cheat Engine, substituindo implementações monolíticas e código legado por uma **arquitetura híbrida desacoplada em 25 bibliotecas nativas em Rust**, integradas a uma interface gráfica reformulada em Free Pascal / Lazarus, um driver de modo kernel Ring-0 (`OwMemDriver.sys`) e um servidor nativo compatível com o **Model Context Protocol (MCP)** para controle autônomo por agentes de Inteligência Artificial.

---

## 1. Topologia da Arquitetura

O OnyxEngine separa rigidamente **apresentação gráfica**, **lógica de escaneamento de alta performance**, **injeções/hooks de evasão** e **operações de privilégio em Ring-0**:

```text
+---------------------------------------------------------------------------------+
|                              Interface Gráfica (GUI)                            |
|             Lazarus / Free Pascal (UI/OnyxBackend.pas, MainUnit.pas)            |
+---------------------------------------------------------------------------------+
           |                                                      |
           | C-ABI FFI (stdcall / cdecl)                          | Named Pipe IPC
           v                                                      v
+---------------------------------------+      +----------------------------------+
|      Camada de Orquestração           |      |       Servidor MCP Nativo        |
|         onyx_backend.dll              |      |    onyx_mcp.dll / server.exe     |
|   Thread-Local Errors, Dispatcher     |      |    49 Ferramentas para IA        |
+---------------------------------------+      +----------------------------------+
           |
           +--------------------+---------------------+
           |                    |                     |
           v                    v                     v
+--------------------+ +-------------------+ +------------------------------------+
|  Motores Core      | | Injeções & Hooks  | |  Plugins Dinâmicos                 |
|  - onyx_scanner    | | - speedhack_dll   | |  - onyx_aob_tool (SigMaker)        |
|  - onyx_pointer    | | - vehdebug_dll    | |  - onyx_dll_mapper (Manual Map)    |
|  - onyx_disasm     | | - d3dhook_dll     | +------------------------------------+
|  - onyx_freezer    | | - allochook_dll   |
|  - onyx_aa         | | - luaclient_dll   |
|  - onyx_mono       | | - callstack_spoof |
|  - onyx_dotnet     | | - pe_strip        |
|  - onyx_overlay    | | - syscalls_ind    |
|  - onyx_hook       | | - taskmgr_cloak   |
|                    | | - onyx_shield     |
+--------------------+ +-------------------+
           |                      |
           +----------+-----------+
                      |
                      | DeviceIoControl (Fast I/O Buffering)
                      v
+---------------------------------------------------------------------------------+
|                        Driver de Kernel Ring-0: OwMemDriver.sys                 |
|      Acesso Físico Direto CR3 | Remoção Dinâmica de ObRegisterCallbacks         |
|      Ocultação DKOM de Processos | Rastreamento Hardware via Intel PT           |
+---------------------------------------------------------------------------------+
```

---

## 2. Mapa Modular da Documentação

A Wiki está estruturada em módulos detalhados para engenheiros reversos, pesquisadores de segurança e desenvolvedores de automação:

### 🎮 Tutoriais Práticos & Aplicação Real
* **[[Tutorial Prático: Criando seu Primeiro Trainer|Tutorial-Reversing-First-Game]]**: Guia completo do zero: anexação, varredura SIMD, detecção com breakpoints de hardware (DR0-DR3), resolução de ponteiros estáticos, criação de script AutoAssembler e automação remota por IA via MCP.
* **[[Engenharia Reversa de Unreal Engine 4 & 5|Unreal-Engine-Dissector]]**: Arquitetura interna da Unreal Engine (`GObjects`, `FNamePool`, `UWorld`, `APlayerController`), dissecação de classes C++, extração da matriz de ossos esqueléticos (`BoneMatrix`) para ESP/Aimbot e geração de SDK.

### 🛡️ Anticheats, Stealth & Kernel Ring-0
* **[[Evasão Avançada de Anticheats & Ring-0|Anticheat-Bypass-Deep-Dive]]**: Análise do modelo de ameaças de Vanguard, EAC, BattlEye e Ricochet. Implementação técnica de Callstack Spoofing, Syscalls Indiretas (Halo's Gate), Manual Mapping com expurgo de cabeçalhos PE e neutralização de `ObRegisterCallbacks`.
* **[[Módulos de Stealth & Injeções|Stealth-Injections-Hooks]]**: Especificação dos módulos `onyx_dll_mapper`, `pe_strip`, `callstack_spoof`, `syscalls_indirect`, `taskmgr_cloak`, `vehdebug_dll` e `speedhack_dll`.
* **[[Driver Ring-0 e Evasão Kernel|Kernel-Driver-Ring0]]**: Paginação física x86_64 a partir do registrador `CR3` ($\text{PML4} \rightarrow \text{PDPT} \rightarrow \text{PD} \rightarrow \text{PT}$), manipulação DKOM em `ActiveProcessLinks` e gravação de execução de CPU via Intel Processor Trace (Intel PT).

### ⚙️ Engenharia de Memória & Runtimes
* **[[Motor de Varredura SIMD|Memory-Scanner-Engine]]**: VAD walk, particionamento com Rayon, vetorização AVX2/SSE4.2 e comparação de valores exatos, desconhecidos e AOB com wildcards.
* **[[Resolução & Varredura de Ponteiros|Pointer-Scanner-Algorithms]]**: Algoritmo de Varredura Reversa com Mapa de Ponteiros Indexado, busca binária $O(\log N)$ e algoritmos de Rescan multi-sessão.
* **[[Desmontagem Zydis & AutoAssembler|Disassembly-Zydis-Engine]]**: Desmontador x86/x64 ultrarrápido Zydis com cálculo em tempo real de RIP-relative e compilador JIT AutoAssembler de 2 passos.
* **[[Runtimes Gerenciados Mono & .NET|Managed-Runtimes-Mono-DotNet]]**: Extração de metadados Unity/Mono, interceptação JIT de métodos em tempo real e auditoria de heap .NET CoreCLR via DAC.

### 🤖 Automação & Governança
* **[[Servidor Nativo MCP & Catálogo IA|MCP-Server-Guide]]**: Protocolo JSON-RPC 2.0 sobre Stdio e Named Pipes, ciclo de vida sob demanda e catálogo exaustivo com as 49 ferramentas para agentes de IA.
* **[[Referência C-ABI, FFI & Structs|C-ABI-FFI-Reference]]**: Definições exatas de tipos de dados em C e Pascal, alinhamento de memória e convenções de chamada.
* **[[Compilação, Pipeline & BUILD.bat|Build-and-Deploy]]**: Manual de compilação unificado com `BUILD.bat`.
* **[[Catálogo Unificado de Erros PT-BR|Error-Catalog]]**: Banco de dados completo de códigos de erro de 0 a 7099 com causas técnicas e diagnósticos em Português.
