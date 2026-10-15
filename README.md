# OnyxEngine

[![Rust](https://img.shields.io/badge/Rust-2024_Edition-orange?logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows_x86__64-blue?logo=windows)](https://www.microsoft.com/)
[![GUI](https://img.shields.io/badge/GUI-egui_%2F_eframe-green)](https://github.com/emilk/egui)
[![Status](https://img.shields.io/badge/Status-Active_Development-brightgreen)](#)

**OnyxEngine** é uma suíte de alta performance para engenharia reversa e manipulação de memória em processos Windows x86_64, combinando o frontend nativo do Cheat Engine em Free Pascal/Lazarus com um backend ultrarrápido modularizado em Rust (`onyx_backend.dll`).

---

## 🏛 Arquitetura Híbrida (Rust Backend + Pascal Frontend)

O projeto adota uma divisão estrita de responsabilidades:
1. **Frontend (Pascal / Lazarus):** Interface gráfica autêntica, robusta e completa do Cheat Engine (`cheat-engine/Cheat Engine`), compilada nativamente via `lazbuild`.
2. **Backend (Rust C-ABI DLL):** Motor de alta performance modularizado em pastas e subpastas (`crates/backend` e `crates/core`), compilado como biblioteca dinâmica nativa `onyx_backend.dll`.
3. **Bridge Unit (`OnyxBackend.pas`):** Camada de integração direta que intercepta chamadas de kernel (`NewKernelHandler.pas`), roteando operações de leitura, escrita, scanning e congelamento de memória para as rotinas em Rust.

```text
OnyxEngine/
├── Cargo.toml                      # Workspace Cargo raiz
├── BUILD.bat                       # Script unificado de compilação (Rust DLL + Pascal Frontend)
├── bin/                            # Diretório de distribuição e binários compilados
│   ├── OnyxEngine-CE.exe           # Frontend nativo (Cheat Engine em Lazarus)
│   ├── onyx_backend.dll            # Motor nativo em Rust (C-ABI)
│   └── lua53-64.dll                # Runtime Lua 5.3
│
├── cheat-engine/                   # [Frontend] Código-fonte original Cheat Engine em Pascal
│   └── Cheat Engine/
│       ├── cheatengine.lpi / .lpr  # Projeto principal do Lazarus
│       ├── OnyxBackend.pas         # Bridge FFI com a DLL do Rust
│       └── NewKernelHandler.pas    # Interceptador de operações de memória
│
└── crates/                         # [Backend em Rust]
    ├── backend/                    # [onyx_backend] DLL C-ABI para consumo pelo Pascal
    │   └── src/
    │       ├── lib.rs              # DllMain, versioning e ping
    │       ├── types.rs            # Structs compatíveis com C/Pascal
    │       └── api/                # Submódulos individuais de API
    │           ├── process.rs      # Attach, Read, Write, Protect, Alloc, Modules, Regions
    │           ├── scanner.rs      # FirstScan, NextScan, Undo, GetResults
    │           ├── disasm.rs       # DisassembleInstruction, DisassembleBlock (x86_64)
    │           ├── freezer.rs      # Background Freezer multi-threaded
    │           ├── pointer.rs      # PointerScan e PointerResolve
    │           ├── speedhack.rs    # Injeção e ajuste de frequência temporal
    │           └── mono.rs         # Dissecção de runtimes Mono / .NET / IL2CPP
    │
    ├── core/                       # [onyx_core] Motor algorítmico nativo de baixo nível
    │   └── src/
    │       ├── memory/             # Scanner, scanner de ponteiros, congelador, structs
    │       ├── process/            # Handles, APIs Win32 nativas, módulos, símbolos
    │       ├── debugger/           # Disassembler x86_64, VEH, hooks inline
    │       ├── scripting/          # Auto Assembler, Lua 5.3, tabelas .CT
    │       ├── mono/               # Dissector Mono / Unity IL2CPP
    │       └── injection/          # Speedhack e interceptadores
    │
    └── gui/                        # [onyx_gui] Frontend alternativo em Rust (egui/wgpu)

---

## 📊 Status do Projeto & Arquitetura Concluída

### ✅ O Que Já Foi Implementado e Roteado 100% para o Rust

- [x] **Backend Modular Nativo em Rust (`crates/backend` -> `onyx_backend.dll`):**
  - **Process Engine:** `onyx_process_attach`, `onyx_process_read`, `onyx_process_write`, `onyx_process_protect`, `onyx_process_alloc`, `onyx_process_free`, `onyx_process_modules`, `onyx_process_regions`.
  - **Memory Scanner Engine:** `onyx_scanner_first_scan`, `onyx_scanner_next_scan`, `onyx_scanner_undo`, `onyx_scanner_save_results_file` (formato binário direto `ADDRESSES.TMP` nativo do Cheat Engine).
  - **Disassembler Engine:** `onyx_disasm_instruction`, `onyx_disasm_block` decodificando instruções x86_64 completas com mnemônicos e operandos.
  - **Freezer & Pointer Engine:** `onyx_freezer_*` com thread dedicada em Rust e `onyx_pointer_resolve` para caminhos multinível.
  - **Mono / IL2CPP Dissector:** `onyx_mono_detect`, `onyx_mono_dissect` com contagem e mapeamento de classes.

- [x] **Frontend em Pascal / Lazarus Conectado ao Backend Rust (`cheat-engine/Cheat Engine`):**
  - **Hooking de Operações de Memória (`NewKernelHandler.pas`):** `ReadProcessMemoryActual`, `WriteProcessMemoryActual` e `OpenProcess` redirecionados para `onyx_process_*` na DLL do Rust.
  - **Scanner 100% via Rust (`memscan.pas`):** `TScanController.firstScan`, `TScanController.nextScan` e `TMemscan.undoLastScan` interceptados diretamente por `OnyxDoFirstScan`, `OnyxDoNextScan` e `OnyxDoUndoScan`, gravando os resultados em `ADDRESSES.TMP` e alimentando a interface gráfica sem intermediários.
  - **Disassembler 100% via Rust (`disassembler.pas`):** Registro de override global (`registerGlobalDisassembleOverride` com `TOnyxDisasmBridge`) de modo que cada instrução aberta no Memory View é decodificada diretamente pelo Rust.

- [x] **Build Unificado & Distribuição Automatizada (`BUILD.bat`):**
  - Compilação em um clique do backend em Rust com `cargo build --release -p onyx_backend`.
  - Compilação do frontend completo em Free Pascal via `lazbuild -B --build-mode=Release`.
  - Distribuição pronta em `bin/` contendo `OnyxEngine-CE.exe` e `onyx_backend.dll`.

---

## 🎯 O Que Falta para Atingir Paridade Completa com o Cheat Engine 7.5

Para que o OnyxEngine atinja equivalência absoluta funcional com o Cheat Engine original, os seguintes módulos estão no roadmap de desenvolvimento:

1. **"Find out what accesses / writes to this address" (Hardware Breakpoints):**
   - Configuração de registradores de depuração de hardware `DR0`-`DR3` e `DR7` para monitorar leitura e escrita em endereços específicos sem alterar o código do processo alvo.
   - Janela com lista de instruções interceptadoras, contagem de acessos (hits) e painel lateral com registradores (`RAX`, `RBX`, `RCX`, `RDX`, `RSI`, `RDI`, `RSP`, `RBP`, `R8-R15`, `EFLAGS`).
2. **Assembler Inline no Memory Viewer (Pressionar Espaço):**
   - Permitir que o usuário selecione uma linha no disassembler, pressione a tecla de espaço (ou duplo clique) e digite uma instrução assembly diretamente em texto (ex: `mov eax, 1` ou `jmp 0x140001000`), montando os opcodes em tempo real na memória.
3. **Structure Spider / Dissect Data Structures:**
   - Ferramenta gráfica para dissecar structs de memória em tempo real, detectando ponteiros aninhados, tipos prováveis (int, float, string) e gerando definições prontas em C/C++ ou Rust.
4. **Resolução de Símbolos PDB (Microsoft Symbol Server via DbgHelp):**
   - Download automático de símbolos de depuração da Microsoft para mapear funções de sistema (`ntdll.dll`, `kernel32.dll`, `user32.dll`) no disassembler em vez de apenas RVAs numéricos.
5. **Configuração de Hotkeys na Cheat Table:**
   - Possibilidade de associar atalhos de teclado (ex: `NUMPAD 1`, `Ctrl+F1`) a entradas da tabela para congelar, descongelar ou alterar valores com o jogo em foco.
6. **Integração com Driver Ring 0 (DBK64 Kernel Mode):**
   - Suporte opcional a driver assinado ou carregamento via vulnerabilidade conhecida para contornar proteções anticheat no nível de kernel (`ObRegisterCallbacks`, hooks em `NtReadVirtualMemory`).
7. **Ultimap & Code Coverage Tracing:**
   - Registro de fluxo de execução de threads com histórico de saltos e instruções executadas para análise de algoritmos complexos.

---

## 🛠 Como Compilar

### Pré-requisitos
- **Windows 10 / 11 (64-bit)**
- **Rust Toolchain:** Rust estável com target `x86_64-pc-windows-msvc`.
- **Lazarus IDE / Free Pascal:** Lazarus 2.2.x+ instalado com `lazbuild.exe` em `C:\lazarus` ou no PATH do sistema.

### Compilação Unificada em Um Clique
Execute o script na raiz do repositório:
```cmd
BUILD.bat
```

Isso irá:
1. Compilar o backend Rust (`onyx_backend.dll`) com otimizações máximas de release.
2. Compilar o frontend Lazarus (`cheatengine-x86_64.exe`) com todos os hooks do OnyxBackend.
3. Sincronizar e empacotar todos os binários e bibliotecas de suporte na pasta `bin/`.

Os executáveis finais prontos para uso estarão disponíveis em:
- `bin\OnyxEngine-CE.exe` (Frontend Pascal conectado ao backend Rust)
- `bin\onyx_backend.dll` (Motor Rust nativo de alta performance)
```

---

## ⚖ Licença & Aviso Legal

Este projeto foi desenvolvido com propósitos estritamente técnicos, voltado para engenharia reversa de software, pesquisa de segurança, depuração de executáveis e desenvolvimento de ferramentas para desenvolvedores de jogos e analistas de sistemas. O uso deste software em ambientes onde o monitoramento ou manipulação de memória infringe termos de serviço é de inteira responsabilidade do usuário.
