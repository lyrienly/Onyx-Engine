# OnyxEngine

OnyxEngine e uma plataforma avancada de analise de memoria, inspecao de processos e engenharia reversa. O sistema integra uma arquitetura hibrida composta por um frontend em Free Pascal/Lazarus, um backend nativo de alta performance desenvolvido em Rust, um driver de modo kernel em C para operacoes privilegiadas em ring-0 e uma interface de automacao baseada no Model Context Protocol (MCP).

---

## Arquitetura do Sistema

O projeto e estruturado em quatro camadas operacionais:

```text
+-------------------------------------------------------------------+
|                        Frontend Visual (LCL)                      |
|                  Cheat Engine UI Base / Lazarus Pascal            |
+-------------------------------------------------------------------+
           |                                       |
           | C-ABI FFI                             | TCP RPC (52736)
           v                                       v
+-------------------------------+      +----------------------------+
|     Backend Nativo (Rust)     |      |    Servidor MCP (Python)   |
|   Varredura SIMD, Disasm,     |      |  Bridge de Automacao para  |
|    Injecao e Pointer Scanner  |      |   Agentes e Assistentes    |
+-------------------------------+      +----------------------------+
           |
           | DeviceIoControl
           v
+-------------------------------------------------------------------+
|                    Driver de Kernel (C / Ring-0)                  |
|          OwMemDriver.sys - Acesso Fisico e Bypass de ObCallbacks  |
+-------------------------------------------------------------------+
```

### 1. Frontend em Free Pascal / Lazarus (`UI/`)
Responsavel pela apresentacao grafica, gerenciamento de tabelas de enderecos, visualizacao de desassemblagem e depuracao visual. As chamadas criticas de memoria e varredura sao interceptadas por bridges que redirecionam o fluxo para a DLL nativa em Rust.

### 2. Backend Nativo em Rust (`crates/`)
Substitui os mecanismos legados de varredura e manipulacao de processos por implementacoes seguras e altamente paralelizadas em Rust:
* `crates/core`: Primitivas de memoria, manipulacao de processos Win32 e gerenciamento de memoria virtual.
* `crates/modules/scanner`: Motor de varredura multithread com particionamento paralelo (Rayon) e comparadores vetorizados.
* `crates/modules/debugger`: Bridge de desassemblagem integrando decodificadores modernos com a interface grafica.
* `crates/backend`: Camada de exportacao C-ABI (`onyx_backend.dll`) consumida dinamicamente pelo frontend.

### 3. Driver de Modo Kernel (`cheat-engine/DBKKernel`)
Modulo em nivel de ring-0 (`OwMemDriver.sys`) voltado para operacoes de memoria fisica (`\Device\PhysicalMemory`), leitura de registradores de controle (`CR3`, `CR0`, `CR4`) e contorno de filtros de protecao baseados em `ObRegisterCallbacks`.

### 4. Bridge de Automacao MCP (`UI/bin/mcp`)
Interface de integracao compativel com a especificacao Model Context Protocol (MCP), viabilizando o controle remoto de sessoes de depuracao, escaneamento e injecao de memoria por agentes de inteligencia artificial e ferramentas automatizadas.

---

## Estrutura do Repositorio

```text
OnyxEngine/
|-- Cargo.toml                          # Manifesto do workspace Rust
|-- CONTRIBUTING.md                     # Diretrizes de contribuicao e engenharia
|-- README.md                           # Documentacao tecnica do projeto
|-- BUILD.bat                           # Script de compilacao unificada
|-- UI/                                 # Frontend Pascal/Lazarus (.lpi, .pas, .lfm)
|   `-- bin/                            # Recursos, bibliotecas auxiliares e scripts autorun
|-- cheat-engine/                       # Fontes auxiliares e driver de kernel
|   |-- DBKKernel/                      # Codigo-fonte do driver de kernel C
|   `-- dbvm/                           # Codigo-fonte do DBVM
`-- crates/                             # Codigo-fonte do motor em Rust
    |-- backend/                        # DLL C-ABI (onyx_backend)
    |-- core/                           # Subsistemas de processo, memoria e scanners
    |-- modules/                        # Modulos de scanner, freezer e desassembler
    `-- dlls/                           # Modulos de injecao (speedhack, vehdebug, d3dhook)
```

---

## Politica de Distribuicao de Binarios

O repositorio de codigo-fonte versiona estritamente codigos-fonte, scripts e configuracoes necessarias para a geracao dos componentes. 

* **Diretorio `bin/` local:** Os artefatos compilados localmente residem em `bin/` apenas em tempo de desenvolvimento. Esta pasta e ignorada pelo Git e nao e enviada ao repositorio.
* **Releases Estaveis:** Pacotes compilados, testados e assinados sao disponibilizados exclusivamente atraves da aba de **Releases** do GitHub para versoes homologadas.

---

## Instrucoes de Compilacao

### Pre-requisitos de Ambiente

* **Sistema Operacional:** Windows 10 ou Windows 11 (64-bit)
* **Rust Toolchain:** Versao estavel (`1.75+`) com target `x86_64-pc-windows-msvc`
* **Lazarus IDE / Free Pascal:** Versao 2.2 ou superior instalada (com `lazbuild` configurado no PATH ou em `C:\lazarus\lazbuild.exe`)
* **Python:** Versao 3.10 ou superior para o servico de relay MCP (dependencias em `requirements.txt`)
* **Windows Driver Kit (WDK):** Necessario caso deseje recompilar o driver `OwMemDriver` a partir dos fontes

### 1. Compilacao do Backend em Rust
```cmd
cargo build --release -p onyx_backend
```
O artefato compilado sera gerado em `target\release\onyx_backend.dll`.

### 2. Compilacao do Frontend em Free Pascal
```cmd
lazbuild --build-mode="Release 64-Bit" "UI\cheatengine.lpi"
```
O executavel principal sera gerado em `UI\bin\OnyxEngine-x86_64.exe`.

### 3. Compilacao Unificada via Script
Para compilar simultaneamente o motor em Rust, sincronizar os artefatos e compilar a interface Pascal, execute na raiz do repositorio:
```cmd
BUILD.bat
```

---

## Fluxo de Contribuicao e Engenharia

O projeto adota regras estritas de governanca de codigo:

1. **Rastreamento Obrigatorio por Issues:** Nenhuma alteracao de codigo pode ser submetida sem uma Issue formal aberta previamente.
2. **Preservacao de Workflows:** E dever do colaborador manter os pipelines de build e testes unitarios passando sem falhas. Qualquer PR que quebre fluxos existentes sera reprovado.
3. **Branches por Funcionalidade:** Todo trabalho deve ser realizado em branches especificas (`feat/`, `fix/`, `refactor/`).
4. **Revisao de Codigo:** Todos os Pull Requests sao direcionados para a branch `main` e passam por analise e aprovacao do mantenedor principal (**ErlonLy**).

Consulte o arquivo [CONTRIBUTING.md](CONTRIBUTING.md) para detalhes completos sobre o fluxo operacional.

---

## Aviso Legal

Este software foi desenvolvido com a finalidade de fornecer uma plataforma para analise de memoria, engenharia reversa de software, pesquisa de seguranca da informacao e desenvolvimento de ferramentas de instrumentacao de sistemas operacionais. Os desenvolvedores nao se responsabilizam pelo uso indevido deste utilitario em violacao a termos de servico de terceiros ou legislacoes vigentes.
