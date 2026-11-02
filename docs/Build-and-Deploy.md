# Manual de Compilação, Pipeline e Desdobramento (DevSecOps)

## 1. Requisitos de Ambiente

Para compilar e gerar a suite completa de binários do OnyxEngine, o ambiente Windows 11 deve atender aos seguintes pré-requisitos:

### 1.1 Ferramental Obrigatório
- **Rust Toolchain:** Rust 1.85+ (Edição 2024 / canal estável) com o target `x86_64-pc-windows-msvc`.
- **Microsoft Visual Studio / C++ Build Tools:** Cargas de trabalho para desenvolvimento C++ instaladas, incluindo o compilador MSVC v143 x64 e o Windows SDK (10.0.22621 ou superior).
- **Lazarus IDE / Free Pascal (FPC 3.2.2+):** Com `lazbuild.exe` acessível via `PATH` ou no local padrão `C:\lazarus\lazbuild.exe`.
- **Windows Driver Kit (WDK):** Necessário exclusivamente caso seja requerida a recompilação do driver de kernel `OwMemDriver.sys` a partir dos fontes em C.

---

## 2. Processo de Compilação do Workspace Rust

O ecossistema nativo do OnyxEngine utiliza o Cargo Workspace para orquestrar todas as bibliotecas e executáveis em paralelo:

```powershell
# Navegar até a raiz do repositório
cd OnyxEngine

# Limpeza opcional de cache de compilação
cargo clean

# Compilação completa em modo Release Otimizado (-O3)
cargo build --release --workspace
```

### 2.1 Artefatos Gerados
Após a execução do build, a pasta `target/release/` conterá todos os binários modulares:
- `onyx_backend.dll`
- `onyx_scanner.dll`
- `onyx_pointer.dll`
- `onyx_disasm.dll`
- `onyx_freezer.dll`
- `onyx_aa.dll`, `onyx_mono.dll`, `onyx_mono_hook.dll`, `onyx_dotnet.dll`, `onyx_gdb_server.dll`, `onyx_overlay.dll`, `onyx_hook.dll`
- `speedhack_dll.dll`, `vehdebug_dll.dll`, `d3dhook_dll.dll`, `allochook_dll.dll`, `luaclient_dll.dll`, `callstack_spoof.dll`, `pe_strip.dll`, `syscalls_indirect.dll`, `taskmgr_cloak.dll`, `onyx_shield.dll`
- `onyx_mcp.dll`, `onyx_mcp_server.exe`
- `onyx_dll_mapper.dll`, `onyx_aob_tool.dll`

---

## 3. Script Unificado de Automação (BUILD.bat)

O script `BUILD.bat` na raiz do repositório centraliza a rotina de compilação, implantação de bibliotecas e build do frontend:

1. Valida a presença de `cargo` e `lazbuild` no ambiente.
2. Executa `cargo build --release --workspace`.
3. Garante a criação e organização das pastas de distribuição:
   - `bin/`
   - `bin/modules/`
   - `bin/modules/injections/`
   - `bin/plugins/`
   - `UI/bin/` (espelho local de desenvolvimento)
4. Desdobra as bibliotecas compiladas nos seus respectivos diretórios de injeção e carregamento dinâmico.
5. Invoca o compilador Pascal com rebuild forçado:
   ```cmd
   lazbuild -B --build-mode="Release 64-Bit" "UI\onyxengine.lpi"
   ```
6. Sincroniza o executável final `UI\bin\OnyxEngine-x86_64.exe` para `bin\OnyxEngine-CE.exe`.

Para executar o pipeline completo:
```cmd
BUILD.bat
```

---

## 4. Estrutura de Distribuição Final

A pasta `bin/` representa o pacote pronto para distribuição:

```
bin/
├── OnyxEngine-CE.exe             # Executável do frontend compilado
├── onyx_backend.dll              # Orquestrador do backend Rust com C-ABI
├── onyx_scanner.dll              # Módulo de varredura SIMD
├── onyx_pointer.dll              # Módulo de resolução e varredura de ponteiros
├── onyx_disasm.dll               # Módulo desmontador Zydis
├── onyx_freezer.dll              # Módulo de congelamento de valores
├── onyx_mcp.dll                  # Servidor MCP modular
├── onyx_mcp_server.exe           # Servidor MCP stdio autônomo
├── taskmgr_cloak.dll             # Stealth de ocultação no gerenciador de tarefas
├── lua53-64.dll                  # Runtime oficial da linguagem Lua 5.3 x64
├── OwMemDriver.sys               # Driver de kernel compilado x86_64
├── autorun/                      # Scripts de inicialização e ponte LUA/MCP
├── modules/                      # Módulos de runtime e análise
│   ├── injections/               # DLLs injetáveis no processo alvo
└── plugins/                      # Extensões externas dinâmicas
```

---

## 5. Práticas de Validação

Antes de realizar commits ou tags de versão:
1. Execute `BUILD.bat` em um terminal limpo e garanta retorno de erro 0 em todas as etapas.
2. Verifique o status com `git status` para assegurar que nenhum arquivo temporário de depuração ou sessão local permaneça pendente.
