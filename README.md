# OnyxEngine

[![Rust](https://img.shields.io/badge/Rust-2024_Edition-orange?logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows_x86__64-blue?logo=windows)](https://www.microsoft.com/)
[![GUI](https://img.shields.io/badge/GUI-egui_%2F_eframe-green)](https://github.com/emilk/egui)
[![Status](https://img.shields.io/badge/Status-Active_Development-brightgreen)](#)

**OnyxEngine** é uma estação de trabalho nativa em Rust para engenharia reversa, inspeção de memória em tempo real, depuração e análise de processos Windows x86_64. 

Projetada com foco em alta performance, segurança de tipos, arquitetura estritamente desacoplada e ausência de sobrecarga desnecessária, a suíte unifica em uma interface gráfica moderna e responsiva as capacidades essenciais de inspeção de baixo nível.

---

## 🏛 Arquitetura do Workspace

O projeto é estruturado como um workspace modular do Cargo, separando rigorosamente o motor nativo (`core`), a interface gráfica (`gui`) e as bibliotecas dinâmicas injetáveis (`dlls`):

```text
OnyxEngine/
├── Cargo.toml                      # Workspace raiz (resolver v2)
├── BUILD.bat                       # Script automatizado de compilação Release
├── bin/                            # Diretório de distribuição e binários compilados
│   ├── OnyxEngine.exe              # Executável principal (GUI nativa)
│   ├── lua53-64.dll                # Runtime embutido Lua 5.3
│   ├── allochook_dll.dll           # Interceptor de alocações (Heap / VirtualAlloc)
│   ├── d3dhook_dll.dll             # Overlay DirectX / Direct3D & HUD
│   ├── luaclient_dll.dll           # Cliente IPC Lua para automação remota
│   ├── speedhack_dll.dll           # Scaler de tempo de alta precisão (QPC/GetTickCount)
│   └── vehdebug_dll.dll            # Motor de depuração VEH (Vectored Exception Handler)
│
└── crates/
    ├── core/                       # [onyx_core] Biblioteca agnóstica de baixo nível
    │   └── src/
    │       ├── lib.rs
    │       ├── memory/             # Scanner, scanner de ponteiros, congelador, dissector de estruturas
    │       ├── process/            # Handles, APIs Win32 nativas, módulos, símbolos, driver de kernel
    │       ├── debugger/           # Disassembler x86_64, hardware breakpoints, VEH, hooks inline
    │       ├── scripting/          # Parser Auto Assembler, engine Lua 5.3, tabelas .CT
    │       ├── mono/               # Dissector avançado de runtime .NET / Mono / Unity IL2CPP
    │       └── injection/          # Injetores de DLLs, speedhack e alloc hooks
    │
    ├── gui/                        # [onyx_gui] Interface gráfica reativa (eframe / egui)
    │   └── src/
    │       ├── main.rs             # Configuração da janela nativa e tema escuro
    │       ├── app.rs              # OnyxEngineApp (ciclo de vida e throttling de polling)
    │       ├── state.rs            # Modelos de dados e estado compartilhado
    │       └── ui/
    │           ├── menu_bar.rs      # Menus superiores (File/Process/Tools) e barra de status
    │           ├── scanner_panel.rs # Parâmetros de scan, filtros, tipos e lista de candidatos
    │           ├── cheat_table.rs   # Lista de endereços ativos, congelamento e edição
    │           └── modals/          # Janelas secundárias e modais independentes
    │               ├── process_modal.rs    # Seletor de processos com busca em tempo real
    │               ├── memory_view.rs      # Disassembler x86_64, Hex Matrix e Data Inspector
    │               ├── pointer_scanner.rs  # Scanner de ponteiros multinível
    │               ├── mono_modal.rs       # Navegador de assemblies, classes, métodos e campos
    │               ├── auto_assembler.rs   # Editor de scripts AA ([ENABLE]/[DISABLE])
    │               ├── lua_console.rs      # Console interativo Lua 5.3
    │               ├── plugins_modal.rs    # Painel de injeção de DLLs auxiliares
    │               ├── address_modal.rs    # Inserção manual de endereços e cadeias de ponteiros
    │               └── edit_byte_modal.rs  # Edição pontual de bytes hexadecimais
    │
    └── dlls/                       # DLLs nativas injetáveis (cdylib)
        ├── allochook/              # Monitoramento e desvio de chamadas de alocação
        ├── d3dhook/                # Interceptação de buffers e renderização DirectX
        ├── luaclient/              # Ponte de comando IPC via Lua
        ├── speedhack/              # Modificação de frequência de clock e contadores temporais
        └── vehdebug/               # Tratamento de exceções e captura de registradores
```

---

## 📊 Status do Projeto & Paridade com o Cheat Engine

### ✅ O Que Já Foi Implementado (Concluído)

- [x] **Arquitetura 100% GUI Nativa (Zero CLI / Zero Bloat):**
  - Todo o código foi unificado no executável único `OnyxEngine.exe` acelerado por hardware via `egui + wgpu + winit`.
  - Remoção de dependências legadas, remoção de referências a ferramentas externas, IA ou MCP, tornando o projeto um utilitário de engenharia reversa sério e independente.
- [x] **Interface Gráfica Responsiva & Autêntica ao Cheat Engine:**
  - **Eliminação de Glifos Quebrados:** Purga total de caracteres não-ASCII que renderizavam caixas vazias (`[]`). O indicador de processo agora utiliza desenho vetorial direto na GPU (`ui.painter().circle_filled()`).
  - **Layout Adaptativo:** Redimensionamento inteligente de janela sem espaços vazios. A área superior do scanner e a lista de candidatos se adaptam dinamicamente, enquanto a Cheat Table inferior ocupa todo o espaço vertical restante.
  - **Barra Central Clássica do CE:** Inclui o botão `[ Memory View ]` à esquerda, o botão central com seta vermelha `[ \/ ]` para descer candidatos para a tabela, e o botão `[ Add Address Manually ]` à direita.
- [x] **Navegador de Memória (Memory Viewer) Fiel ao CE 7.5:**
  - **Disassembler x86_64:**
    - Cabeçalho padronizado: `Address | Bytes | Opcode | Comment`.
    - Seleção contínua em azul Cheat Engine (`rgb(0, 120, 215)`) e destaque de sintaxe para chamadas (`call`), saltos (`jmp`/`jxx`) e retornos (`ret`).
    - Menu de contexto rápido com suporte a **NOP instruction**, cópia de endereço e transição para o Hex View.
  - **Divisor Central Mnemônico:** Exibe a interpretação textual da instrução selecionada (ex: `subtract`, `call procedure`, `jump`, `logical compare`).
  - **Banner de Região de Memória:** Exibe informações detalhadas de proteção e alocação (`Protect: Execute/Read/Write   AllocationBase=...   Base=...   Size=...   Module=...`).
  - **Hex Dump em 16 Bytes:**
    - Colunas `00..07` em verde e frame amarelo destacado nas colunas `08..0F`.
    - Coluna de caracteres ASCII em tempo real.
    - Suporte a clique duplo ou menu de contexto em cada byte individual para edição pontual de memória.
- [x] **Scanner de Memória Nativo:**
  - Tipos suportados: Inteiros (i8, u8, i16, u16, i32, u32, i64, u64), Float (32-bit), Double (64-bit), Strings e Array of Bytes (AOB).
  - Modos de varredura: Exact Value, Bigger than, Smaller than, Value between, Unknown initial value, Changed/Unchanged value, Increased/Decreased by.
  - Fast Scan com alinhamento configurável (1, 2, 4, 8 bytes), filtros por tipo de proteção de página e histórico completo com **Undo Scan**.
- [x] **Multilevel Pointer Scanner:**
  - Varredura recursiva de nós e caminhos de ponteiros multinível com profundidade configurável e re-scan diferencial.
- [x] **Cheat Table & Freeze Engine:**
  - Suporte a entradas estáticas e ponteiros encadeados multinível (`P->[Module+Offset]->Offset`).
  - Thread independente em segundo plano com congelamento de valores em tempo real.
  - Suporte a salvar e carregar tabelas `.CT`.
- [x] **Mono / .NET CLR Runtime Dissector:**
  - Detecção automática de Mono, .NET Core e Unity IL2CPP com árvore de assemblies, classes, métodos e campos com offsets.
- [x] **Auto Assembler & Lua 5.3:**
  - Parser Auto Assembler com blocos `[ENABLE]` e `[DISABLE]`, `alloc`, `dealloc`, `registersymbol` e injeção de saltos.
  - Console interativo com runtime nativo Lua 5.3 (`lua53-64.dll`).
- [x] **Speedhack & Gerenciador de DLLs:**
  - Controle de velocidade em tempo real (0.1x a 20x) e injeção de bibliotecas auxiliares via `CreateRemoteThread`.

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
- **Rust Toolchain:** Rust estável (edição 2024 recomendada) com target `x86_64-pc-windows-msvc`.
- **Visual Studio Build Tools:** C++ MSVC Build Tools instalados.

### Compilação Rápida
Execute o script em lote na raiz do repositório:
```cmd
BUILD.bat
```

Ou execute diretamente via Cargo:
```cmd
# Compilação otimizada de todo o workspace
cargo build --release

# O binário final estará em:
target\release\OnyxEngine.exe
```

---

## ⚖ Licença & Aviso Legal

Este projeto foi desenvolvido com propósitos estritamente técnicos, voltado para engenharia reversa de software, pesquisa de segurança, depuração de executáveis e desenvolvimento de ferramentas para desenvolvedores de jogos e analistas de sistemas. O uso deste software em ambientes onde o monitoramento ou manipulação de memória infringe termos de serviço é de inteira responsabilidade do usuário.
