# OnyxEngine

[![Rust](https://img.shields.io/badge/Rust-2024_Edition-orange?logo=rust)](https://www.rust-lang.org/)
[![Pascal](https://img.shields.io/badge/Pascal-Free_Pascal_%2F_Lazarus-blue)](https://www.lazarus-ide.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows_x86__64-blue?logo=windows)](https://www.microsoft.com/)
[![Kernel](https://img.shields.io/badge/Kernel-OwMemDriver_Ring--0-red)](#)
[![Protocol](https://img.shields.io/badge/Protocol-Model_Context_Protocol_(MCP)-green)](#)
[![Status](https://img.shields.io/badge/Status-Active_Development-brightgreen)](#)

**OnyxEngine** é uma suíte de alta performance para engenharia reversa, análise e manipulação de memória no Windows x86_64. O projeto unifica o ecossistema comprovado do Cheat Engine (interface Pascal/Lazarus) com um motor nativo moderno em Rust (`onyx_backend.dll`), um driver de kernel ring-0 furtivo (`OwMemDriver.sys`) e suporte nativo ao **Model Context Protocol (MCP)** para automação por Inteligência Artificial.

---

## 🎯 Intuito e Objetivos do Projeto

1. **Memory Safety & Concorrência:** Migrar progressivamente algoritmos pesados de scanning, dissecção de ponteiros e congelamento de threads para Rust, eliminando falhas de concorrência, use-after-free e memory leaks.
2. **Operações Físicas Indetectáveis em Kernel (Ring-0):** Fornecer o driver unificado `OwMemDriver.sys` com tradução de memória física via paginação `CR3` multinível, contornando ganchos de `ObRegisterCallbacks` e eliminando a dependência de `KeStackAttachProcess`.
3. **Automação Nativa com IA (FastMCP):** Disponibilizar uma ponte completa MCP integrada à barra de menus do aplicativo, permitindo que agentes e LLMs analisem e controlem a memória de processos de forma programática.
4. **Desacoplamento e Furtividade:** Desvincular todas as assinaturas estáticas originais de identificação de processos, classes de janela e drivers legados.

---

## 🏛 Arquitetura da Stack Tecnológica

O sistema é construído sobre 4 pilares:

```text
┌─────────────────────────────────────────────────────────────┐
│              OnyxEngine Frontend (Lazarus / FPC)            │
│               OnyxEngine-CE.exe (bin/OnyxEngine-CE.exe)     │
│   - Interface gráfica LCL nativa                            │
│   - Menu MCP nativo em Português integrado ao lado do D3D   │
│   - Dialog de configurações com auto-carregamento de kernel │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
               ▼                              ▼
┌──────────────────────────────┐ ┌────────────────────────────┐
│   Backend em Rust (C-ABI)    │ │   Ponte MCP / Servidor     │
│       onyx_backend.dll       │ │   ce_mcp_bridge.lua + py   │
│  - Scanner multi-thread SIMD │ │  - FastMCP Server          │
│  - Pointer Resolver & Freezer│ │  - Relay TCP + Named Pipe  │
│  - Módulos em crates/        │ │  - Controle externo por IA │
└──────────────┬───────────────┘ └────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│               OwMemDriver.sys (Ring-0 Kernel)               │
│  - Tradução física direta PML4 -> PDPT -> PD -> PT          │
│  - Ocultação de módulo da PsLoadedModuleList (DKOM)         │
│  - Sanitização de registros da PiDDBCacheTable              │
│  - Remoção de Callbacks ObRegisterCallbacks                 │
└─────────────────────────────────────────────────────────────┘
```

---

## 📂 Estrutura de Diretórios e Binários

Todos os binários compilados residem centralizados no diretório **`bin/`**:

```text
OnyxEngine/
├── bin/                                # Diretório único de distribuição
│   ├── OnyxEngine-CE.exe               # Executável principal (Frontend Lazarus)
│   ├── onyx_backend.dll                # Motor nativo em Rust (C-ABI)
│   ├── OwMemDriver.sys                 # Driver ring-0 compilado e assinado
│   ├── OwMemDriver.cer                 # Certificado de teste instalado
│   ├── lua53-64.dll                    # Runtime oficial Lua 5.3 x64
│   ├── autorun/                        # Scripts Lua de inicialização (mcp_menu.lua, ce_mcp_bridge.lua)
│   └── mcp/                            # Servidor Python FastMCP e scripts de relay
│
├── cheat-engine/                       # Código-fonte do Frontend em Pascal e Driver em C
│   ├── Cheat Engine/                   # Projeto Lazarus (.lpi, .pas, .lfm)
│   └── DBKKernel/                      # Código-fonte do driver OwMemDriver
│
├── crates/                             # Código-fonte do Motor em Rust
│   ├── backend/                        # DLL C-ABI (onyx_backend)
│   ├── core/                           # Motor de scanning, memória, processos e scripts
│   ├── modules/                        # Scanner, desassembler, ponteiros e freezer
│   └── dlls/                           # Injeção e hooks (speedhack, vehdebug, d3dhook)
│
├── CONTRIBUTING.md                     # Guia de contribuição e fluxo de trabalho
└── Cargo.toml                          # Workspace raiz do Rust
```

---

## 🛠 Como Compilar o Projeto

### Pré-requisitos
* **Rust:** Ferramentas estáveis (`rustc`, `cargo`)
* **Free Pascal / Lazarus:** Lazarus 3.0+ com `lazbuild` no PATH (`C:\lazarus\lazbuild.exe`)
* **Python 3.10+:** Para execução do servidor MCP (`bin/mcp/requirements.txt`)
* **WDK / Visual Studio:** Windows Driver Kit instalado para o driver `OwMemDriver`

### Compilação do Backend (Rust)
```bash
cargo build --release -p onyx_backend
copy target\release\onyx_backend.dll bin\onyx_backend.dll
```

### Compilação do Frontend (Pascal)
```bash
lazbuild -B --build-mode=Release "cheat-engine\Cheat Engine\cheatengine.lpi"
copy "cheat-engine\Cheat Engine\bin\OnyxEngine-x86_64.exe" "bin\OnyxEngine-CE.exe"
```

---

## 🤝 Fluxo de Contribuição e Issues

Para manter a ordem e qualidade do repositório, **todos os colaboradores devem consultar o guia [CONTRIBUTING.md](file:///c:/Users/Administrator/Desktop/OnyxEngine/CONTRIBUTING.md)**:

1. **Sempre siga as Issues:** Não crie branches sem uma issue associada.
2. **Trabalhe em Branches:** Crie branches no padrão `feat/nome-da-tarefa` ou `fix/nome-do-bug`.
3. **Abra um Pull Request:** Todos os PRs são submetidos para a branch `main` e serão revisados e aprovados pelo mantenedor principal (**ErlonLy**).
