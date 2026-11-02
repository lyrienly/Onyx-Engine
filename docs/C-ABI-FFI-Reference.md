# Referência C-ABI, FFI & Estruturas de Memória

## 1. Visão Geral da Interoperabilidade C-ABI

A comunicação entre a casca gráfica em **Free Pascal / Lazarus** (`UI/OnyxBackend.pas`) e o ecossistema nativo em **Rust** (`crates/`) é realizada através de uma interface de binário de aplicativo (**C-ABI**) estrita.

### 1.1 Convenção de Chamada
- **Arquitetura x86_64:** Utiliza a convenção de chamada padrão da Microsoft x64 (`__fastcall`), onde os quatro primeiros argumentos inteiros/ponteiros são passados nos registradores `RCX`, `RDX`, `R8` e `R9`, com o restante empilhado na pilha de execução.
- **Arquitetura x86 (32-bit):** Utiliza a convenção `stdcall`, com parâmetros empilhados da direita para a esquerda e limpeza de pilha realizada pela função chamada (*callee cleanup*).
- **Tratamento de Strings:** Strings são passadas como ponteiros para sequências de caracteres terminadas em nulo (`const char*`) codificadas em UTF-8.

---

## 2. Estruturas de Dados Compartilhadas

### 2.1 Estrutura de Informações de Processo (`PROCESS_INFO_ENTRY`)
```c
#pragma pack(push, 8)
typedef struct _PROCESS_INFO_ENTRY {
    uint32_t process_id;            // PID numérico do processo
    char     process_name[260];     // Nome do executável (ex: "game.exe")
    uint64_t base_address;          // Endereço de carregamento do módulo principal
    uint64_t image_size;            // Tamanho em bytes da imagem PE na memória
    uint32_t is_64bit;              // 1 se x64, 0 se WoW64 / 32-bit
    uint32_t thread_count;          // Quantidade de threads ativas
} PROCESS_INFO_ENTRY, *PPROCESS_INFO_ENTRY;
#pragma pack(pop)
```

Em Free Pascal (`OnyxBackend.pas`):
```pascal
type
  TProcessInfoEntry = packed record
    ProcessId: UInt32;
    ProcessName: array[0..259] of AnsiChar;
    BaseAddress: UInt64;
    ImageSize: UInt64;
    Is64Bit: UInt32;
    ThreadCount: UInt32;
  end;
  PProcessInfoEntry = ^TProcessInfoEntry;
```

---

### 2.2 Estrutura de Entrada de Varredura (`SCAN_RESULT_ENTRY`)
```c
#pragma pack(push, 8)
typedef struct _SCAN_RESULT_ENTRY {
    uint64_t address;               // Endereço de memória encontrado
    uint8_t  current_value[16];     // Valor atual lido no último scan
    uint8_t  previous_value[16];    // Valor anterior arquivado no scan prévio
    uint32_t value_type;            // 0=Byte, 1=i16, 2=i32, 3=i64, 4=f32, 5=f64, 6=AOB
} SCAN_RESULT_ENTRY, *PSCAN_RESULT_ENTRY;
#pragma pack(pop)
```

---

### 2.3 Estrutura de Instrução Desmontada Zydis (`DISASM_INSTRUCTION_ENTRY`)
```c
#pragma pack(push, 8)
typedef struct _DISASM_INSTRUCTION_ENTRY {
    uint64_t address;               // Endereço virtual da instrução
    uint8_t  length;                // Tamanho da instrução em bytes (1 a 15 bytes)
    uint8_t  opcode_bytes[15];      // Bytes binários brutos da instrução
    char     mnemonic[32];          // Mnemônico formatado (ex: "mov", "sub", "jmp")
    char     operands[128];         // Operandos formatados (ex: "rax, [rbx+44h]")
    uint64_t referenced_address;    // Endereço efetivo resolvido (se houver RIP-relative)
    uint32_t is_branch;             // 1 se for salto/call, 0 caso contrário
} DISASM_INSTRUCTION_ENTRY, *PDISASM_INSTRUCTION_ENTRY;
#pragma pack(pop)
```

---

## 3. Catálogo de Funções Exportadas

### 3.1 Orquestrador Central (`onyx_backend.dll`)

```c
// Inicializa o subsistema backend e aloca buffers globais
ONYX_API int onyx_initialize(void);

// Encerra os subsistemas e libera descritores
ONYX_API void onyx_shutdown(void);

// Anexa a um processo por PID
ONYX_API int onyx_process_attach(uint32_t pid);

// Desconecta do processo ativo
ONYX_API int onyx_process_detach(void);

// Lê memória virtual do processo anexado
ONYX_API int onyx_memory_read(uint64_t address, void* buffer, size_t size, size_t* bytes_read);

// Grava na memória virtual do processo anexado
ONYX_API int onyx_memory_write(uint64_t address, const void* buffer, size_t size, size_t* bytes_written);

// Consulta o último código de erro thread-local
ONYX_API uint32_t onyx_error_get_last_code(void);

// Consulta a mensagem explicativa formatada em Português
ONYX_API int onyx_error_get_last_formatted(char* buffer, size_t buffer_size);
```

### 3.2 Motor de Congelamento de Valores (`onyx_freezer.dll`)

```c
// Congela um endereço na memória com valor específico
ONYX_API int freezer_freeze(uint64_t address, const void* value_buffer, size_t value_size, uint32_t interval_ms);

// Descongela um endereço previamente travado
ONYX_API int freezer_unfreeze(uint64_t address);

// Remove todos os congelamentos ativos
ONYX_API void freezer_clear_all(void);

// Retorna a contagem de endereços ativamente congelados
ONYX_API uint32_t freezer_get_count(void);
```
