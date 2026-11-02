# Manual de Compilação, Pipeline e Desdobramento (DevSecOps)

## 1. Requisitos de Ambiente

Para compilar e gerar a suite completa de binários do OnyxEngine, o ambiente Windows 11 deve atender aos seguintes pré-requisitos:

### 1.1 Ferramental Obrigatório
- **Rust Toolchain:** Rust 1.85+ (Edição 2024 / canal estável) com o target `x86_64-pc-windows-msvc`.
- **Microsoft Visual Studio 2022:** Cargas de trabalho para "Desenvolvimento para desktop com C++" instaladas, incluindo o compilador MSVC v143 x64 e o SDK do Windows 11 (versão 10.0.22621 ou superior).
- **Windows Driver Kit (WDK):** Necessário exclusivamente caso seja requerida a recompilação do driver de kernel `OwMemDriver.sys` a partir dos fontes em C. Para uso normal, os artefatos compilados e certificados já acompanham o repositório em `bin/driver/`.
- **Lazarus IDE / Free Pascal (FPC 3.2.2+):** Necessário caso seja feita alteração na casca gráfica do Cheat Engine (`UI/`).

---

## 2. Processo de Compilação do Workspace Rust

O ecossistema nativo do OnyxEngine utiliza o Cargo Workspace para orquestrar todas as 24 bibliotecas e executáveis em paralelo:

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
- `onyx_dll_mapper.dll`, `onyx_aob_tool.dll`

---

## 3. Script Unificado de Automação (BUILD_ONYX.bat)

O script `BUILD_ONYX.bat` centraliza a rotina de compilação e desdobramento automatizado para as pastas de distribuição:

1. Valida a presença do Cargo no `PATH`.
2. Executa `cargo build --release --workspace`.
3. Garante a criação da estrutura de diretórios:
   - `bin/`
   - `bin/modules/`
   - `bin/modules/injections/`
   - `bin/plugins/`
   - `UI/bin/` (cópia local para desenvolvimento da interface)
4. Copia cada biblioteca para seu local de carregamento dinâmico correspondente.

Para executar o pipeline completo:
```cmd
BUILD_ONYX.bat
```

---

## 4. Estrutura de Distribuição Final

A pasta `bin/` representa o pacote pronto para distribuição em produção:

```
bin/
├── OnyxEngine-CE.exe             # Executável do Cheat Engine 7.7 customizado
├── onyx_backend.dll              # Orquestrador do backend Rust com C-ABI
├── onyx_scanner.dll              # Módulo de varredura
├── onyx_pointer.dll              # Módulo de ponteiros
├── onyx_disasm.dll               # Módulo desmontador
├── onyx_freezer.dll              # Módulo de congelamento
├── lua53-64.dll                  # Runtime oficial da linguagem Lua 5.3 x64
├── driver/                       # Pacote oficial do driver Ring-0
│   ├── OwMemDriver.sys           # Driver compilado x86_64
│   ├── OwMemDriver.inf           # Arquivo de instalação INF
│   └── OwMemDriver.cer           # Certificado público para teste de assinatura
├── modules/                      # Módulos de análise
│   ├── onyx_aa.dll
│   ├── onyx_dotnet.dll
│   ├── onyx_gdb_server.dll
│   ├── onyx_hook.dll
│   ├── onyx_mono.dll
│   ├── onyx_mono_hook.dll
│   ├── onyx_overlay.dll
│   └── injections/               # Bibliotecas de injeção remota
│       ├── allochook_dll.dll
│       ├── callstack_spoof.dll
│       ├── d3dhook_dll.dll
│       ├── luaclient_dll.dll
│       ├── onyx_shield.dll
│       ├── pe_strip.dll
│       ├── speedhack_dll.dll
│       ├── syscalls_indirect.dll
│       ├── taskmgr_cloak.dll
│       └── vehdebug_dll.dll
└── plugins/                      # Extensões externas
    ├── onyx_aob_tool.dll
    └── onyx_dll_mapper.dll
```

---

## 5. Práticas de Validação e Testes Automatizados (CI)

Antes de qualquer merge ou desdobramento em ambiente de homologação ou produção, execute a bateria completa de testes:

```powershell
# Execução da suite de testes de integração e testes unitários do workspace
cargo test --workspace

# Validação estrita de linter e ausência de warnings
cargo check --workspace
```

### 5.1 Garantias Operacionais
- Todos os testes unitários do subsistema de erros validam o ciclo completo de mapeamento de códigos, mensagens em português e formatação técnica.
- As chamadas de C-ABI em `abi_smoke.rs` asseguram compatibilidade binária entre a convenção de chamada da DLL Rust e os headers importados no Pascal em `UI/OnyxBackend.pas`.
- Nenhuma dependência não gerenciada ou arquivo de código-fonte reside nas pastas de distribuição `bin/`.
