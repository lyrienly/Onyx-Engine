# Onyx DLL Manual Mapper

Plugin de injecao mapeada de DLL (manual mapping) para o OnyxEngine.

Mapeia uma DLL PE32+ (x64) no processo alvo sem `LoadLibrary`:

- aloca memoria no alvo e escreve headers + secoes;
- aplica base relocations;
- resolve imports (por nome e por ordinal) via `LoadLibraryA`/`GetProcAddress` remotos;
- ajusta protecoes por secao;
- executa callbacks de TLS (quando presentes);
- chama `DllMain(DLL_PROCESS_ATTACH)`;
- opcionalmente apaga os headers do PE.

## Build

```bash
cargo build -p onyx_dll_mapper --release
```

Saida: `onyx_dll_mapper.dll` (cdylib).

## API

```c
typedef struct OnyxMapOptions {
    uint32_t struct_size;
    uint32_t flags;          // ONYX_MAP_* (0 = padrao: PROTECT_SECTIONS | CALL_TLS)
    uint64_t preferred_base; // reservado
} OnyxMapOptions;

int32_t OnyxPlugin_MapDll(const char* dll_path, const OnyxMapOptions* options, OnyxMapResult* out);
int32_t OnyxPlugin_IsMapped(uint64_t image_base);
```

Flags:

| Flag | Efeito |
| --- | --- |
| `ONYX_MAP_ERASE_HEADERS` | zera os headers do PE depois do `DllMain` |
| `ONYX_MAP_PROTECT_SECTIONS` | aplica `VirtualProtectEx` conforme `Characteristics` |
| `ONYX_MAP_CALL_TLS` | executa callbacks de TLS com `DLL_PROCESS_ATTACH` |

Codigos de retorno: `ONYX_PLUGIN_OK` (0) e os `ONYX_PLUGIN_ERR_*` do SDK.

## Limitacoes

- Somente PE32+ (x64) em alvo x64.
- DLLs gerenciadas (.NET) e mixed-mode nao sao suportadas.
- `LoadLibraryA`/`GetProcAddress` sao chamados pelo endereco local da `kernel32`
  (assume o mesmo base address no alvo, valido para DLLs de sistema na mesma sessao).
- `preferred_base` ainda nao e usado; a base preferida do PE e tentada primeiro.
- CFG/CET podem bloquear chamadas indiretas em alvos endurecidos.
- O modulo nao e registrado no PEB (nao usa o loader), entao nao aparece em
  `EnumProcessModules` por padrao.

## Testes

- `cargo test -p onyx_dll_mapper`: parser de PE, relocations (DIR64/HIGHLOW),
  resolucao de imports (nome/ordinal), layout do stub e mapeamento de protecoes.
- A injecao ao vivo nao roda em CI; requer um processo alvo e uma DLL de teste.

## Aviso

Uso restrito a pesquisa de seguranca e engenharia reversa autorizada.
