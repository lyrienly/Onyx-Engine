# OnyxEngine

OnyxEngine é uma plataforma avançada de análise de memória, inspeção de processos e engenharia reversa. O sistema integra uma arquitetura híbrida de alta performance composta por um frontend gráfico nativo em Free Pascal / Lazarus, um ecossistema modular de baixo nível desenvolvido em Rust (backend, scanner SIMD, desmontador Zydis, gerador de ponteiros e módulos de instrumentação e interceptação), um driver de modo kernel em C para operações privilegiadas em ring-0 (`OwMemDriver.sys`) e uma interface de automação nativa baseada no Model Context Protocol (MCP).

---

## Arquitetura do Sistema

O projeto é estruturado em quatro camadas operacionais totalmente desacopladas e 100% nativas (sem dependência de interpretadores externos):

```text
+-------------------------------------------------------------------+
|                        Frontend Visual (LCL)                      |
|                  OnyxEngine UI / Lazarus Free Pascal              |
+-------------------------------------------------------------------+
           |                                       |
           | C-ABI FFI (stdcall / cdecl)           | Named Pipe IPC / Stdio
           v                                       v
+-------------------------------+      +----------------------------+
|     Backend Nativo (Rust)     |      |    Servidor MCP Nativo     |
|   Varredura SIMD, Disasm,     |      |  onyx_mcp.dll / server.exe |
|    Injeção e Pointer Scanner  |      |   Controle Total para IA   |
+-------------------------------+      +----------------------------+
           |
           | DeviceIoControl (Fast I/O)
           v
+-------------------------------------------------------------------+
|                    Driver de Kernel (C / Ring-0)                  |
|          OwMemDriver.sys - Acesso Físico e Bypass de ObCallbacks  |
+-------------------------------------------------------------------+
```

### 1. Frontend em Free Pascal / Lazarus (`UI/`)
Responsável pela interface gráfica de alta responsividade, visualização de tabelas de endereços, desassemblagem e depuração visual. As rotinas pesadas de memória, congelamento e varredura são interceptadas e despachadas para o backend nativo em Rust via FFI de baixa latência.

### 2. Backend Nativo e Módulos em Rust (`crates/`)
Substitui os mecanismos legados por implementações seguras, com proteção de memória e paralelismo determinístico:
* `crates/core`: Primitivas de memória Win32, paginação virtual, manipulação de processos e tratamento unificado de erros com suporte a PT-BR.
* `crates/backend`: Orquestrador C-ABI principal (`onyx_backend.dll`).
* `crates/modules/`: Módulos modulares independentes (`scanner`, `pointer`, `disasm`, `freezer`, `aa`, `mono`, `mono_hook`, `dotnet`, `gdb_server`, `overlay`, `hook`).
* `crates/dlls/`: Módulos de instrumentação e monitoramento de sistema (`speedhack`, `vehdebug`, `d3dhook`, `allochook`, `luaclient`, `onyx_shield`, `taskmgr_cloak`, `onyx_mcp`).
* `crates/plugins/`: Extensões dinâmicas (`dll_mapper`, `aob_generator`).
* `crates/pe-strip`, `crates/syscalls-indirect`, `crates/callstack-spoof`: Primitivas de chamadas diretas de sistema e integridade operacional.

### 3. Hipervisor e Runtimes (`dbvm/` e `lua/`)
Componentes essenciais desacoplados na raiz:
* `dbvm/`: Hipervisor DBVM para virtualização por hardware (VT-x / AMD-V).
* `lua/`: Runtimes e bibliotecas auxiliares de script para automação de tabelas.

### 4. Servidor Nativo MCP (Model Context Protocol)
Interface de controle nativa em Rust (`onyx_mcp.dll` e `onyx_mcp_server.exe`), permitindo que agentes de inteligência artificial inspecionem processos, leiam/escrevam memória, executem scans, resolvam ponteiros e injetem código via JSON-RPC 2.0 padrão sobre standard I/O ou Named Pipes (`\\.\pipe\OnyxEngine_MCP_IPC`), operando sob demanda com zero consumo ocioso.

---

## Estrutura do Repositorio

O projeto organiza seus fontes e scripts de automação de forma modular na raiz:

```text
OnyxEngine/
|-- Cargo.toml                          # Manifesto do workspace Rust
|-- CONTRIBUTING.md                     # Diretrizes de contribuição e engenharia
|-- README.md                           # Documentação técnica do projeto
|-- BUILD.bat                           # Script mestre unificado de compilação
|-- docs/                               # Manuais técnicos, arquitetura e catálogo de erros
|-- UI/                                 # Frontend Pascal/Lazarus (.lpi, .pas, .lfm)
|   `-- bin/                            # Recursos de desenvolvimento e scripts autorun
|-- crates/                             # Código-fonte do motor em Rust
|   |-- core/                           # Subsistemas de processo, memória, IOCTL e diagnósticos
|   |-- backend/                        # DLL C-ABI principal (onyx_backend.dll)
|   |-- modules/                        # Módulos de análise, runtime e varredura
|   |-- dlls/                           # Módulos dinâmicos e servidor MCP nativo
|   `-- plugins/                        # Extensões dinâmicas de mapeamento e AOB
|-- dbvm/                               # Hipervisor DBVM desacoplado na raiz
`-- lua/                                # Runtimes e bibliotecas Lua na raiz
```

---

## Política de Distribuição de Binários

O repositório versiona estritamente código-fonte, scripts e recursos de compilação:

* **Diretório `bin/` local:** Gerado automaticamente pelo `BUILD.bat` para conter os artefatos compilados em tempo de desenvolvimento. É ignorado pelo Git para manter o repositório leve.
* **Releases Estáveis:** Pacotes binários oficiais homologados são publicados exclusivamente na aba de **Releases** do GitHub.

---

## Instruções de Compilação

### Pré-requisitos de Ambiente

* **Sistema Operacional:** Windows 10 ou Windows 11 (64-bit)
* **Rust Toolchain:** Versão estável (`1.85+`) com target `x86_64-pc-windows-msvc`
* **Lazarus IDE / Free Pascal:** FPC 3.2.2+ / Lazarus 2.2+ instalado com `lazbuild` no `PATH` ou em `C:\lazarus\lazbuild.exe`
* **Microsoft Visual C++ Build Tools:** MSVC v143 x64 instalado (Build Tools ou Visual Studio)
* **Windows Driver Kit (WDK):** Opcional, apenas se for recompilar o driver `OwMemDriver.sys` a partir dos fontes em C

### Pipeline Unificado (Recomendado)

Para compilar todo o ecossistema (Rust Workspace + Frontend Pascal) e desdobrar as DLLs e executáveis em `bin\`, execute na raiz:

```cmd
BUILD.bat
```

O script automatiza:
1. Validação de ferramentas (`cargo` e `lazbuild`).
2. Compilação de todos os 25 crates em modo Release otimizado (`cargo build --release --workspace`).
3. Implantação estruturada das DLLs de backend, extensões de sistema, plugins e MCP para `bin\` e `UI\bin\`.
4. Compilação do executável gráfico (`lazbuild -B --build-mode="Release 64-Bit" "UI\onyxengine.lpi"`).
5. Sincronização automática para `bin\OnyxEngine-CE.exe`.

### Compilação Manual dos Componentes

#### 1. Backend em Rust
```cmd
cargo build --release --workspace
```
Os artefatos compilados residem em `target\release\`.

#### 2. Frontend em Free Pascal
```cmd
lazbuild -B --build-mode="Release 64-Bit" "UI\onyxengine.lpi"
```
O executável principal é gerado em `UI\bin\OnyxEngine-x86_64.exe`.

---

## Fluxo de Contribuição e Engenharia

1. **Rastreamento por Issues:** Alterações substanciais devem referenciar uma Issue aberta previamente.
2. **Pipelines Verificados:** O workspace Rust e o frontend Pascal devem compilar sem erros através do `BUILD.bat`.
3. **Branches de Trabalho:** Desenvolvimento isolado em branches temáticas (`feat/`, `fix/`, `refactor/`).
4. **Revisão de Código:** Submissões via Pull Request direcionadas à branch `main`.

Consulte o arquivo [CONTRIBUTING.md](CONTRIBUTING.md) para detalhes completos sobre padrões de código e governança.

---

## Aviso Legal

Este software foi desenvolvido com a finalidade de fornecer uma plataforma para análise de memória, engenharia reversa de software, pesquisa de segurança da informação e instrumentação avançada de sistemas operacionais. Os desenvolvedores não se responsabilizam pelo uso indevido deste utilitário em violação a termos de serviço de terceiros ou legislações vigentes.
