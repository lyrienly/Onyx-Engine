# Guia Profundo de Evasão de Anticheats & Engenharia de Ring-0

## 1. O Modelo de Ameaça dos Anticheats Modernos

Sistemas de proteção contemporâneos (**Vanguard, Easy Anti-Cheat, BattlEye, Ricochet, ACE**) operam em modelo híbrido com agentes em **Ring-3 (Usermode)** e drivers de alta prioridade em **Ring-0 (Kernelmode)**. Para instrumentar a memória de um jogo protegido sem disparar banimentos imediatos ou integridade de cliente violada, é indispensável dissecar cada vetor de detecção e contra-atacar na camada exata de execução.

```text
+---------------------------------------------------------------------------------+
|                                 VETORES USERMODE                                |
|  - Hooks inline em NTDLL (NtReadVirtualMemory, NtOpenProcess)                   |
|  - Validação de Pilha (Callstack Walking: RtlCaptureStackBackTrace)              |
|  - Auditoria de Seções PE modificadas (Integrity Checks / .text checksums)      |
|  - Detecção de Memória Executável sem Módulo (Unbacked Executable Memory)       |
|  - Monitoramento de Threads Estranhas (DbgUiRemoteBreakin / CreateRemoteThread) |
+---------------------------------------------------------------------------------+
                                       ^
                                       | Contra-ataque OnyxEngine:
                                       | - Syscalls Indiretas via Halo's Gate
                                       | - Callstack Spoofing com Gadgets Sintéticos
                                       | - Manual Mapping com Expurgo PE (pe_strip)
                                       | - Depuração Hardware via VEH (DR0-DR3)
                                       |
+---------------------------------------------------------------------------------+
|                                 VETORES KERNELMODE                              |
|  - Intercepção de Handles de Processo via ObRegisterCallbacks                   |
|  - Proteção de Processos PPL (Protected Process Light)                          |
|  - Auditoria de Drivers Carregados (PiDDBCacheTable, MmUnloadedDrivers)         |
|  - Verificação de Assinatura de Código e Certificados Revogados                 |
|  - Varredura de ActiveProcessLinks e Threads de Sistema PsCreateSystemThread    |
+---------------------------------------------------------------------------------+
                                       ^
                                       | Contra-ataque OnyxEngine:
                                       | - Leitura/Escrita Física Direta via CR3 com Range Safety
                                       | - Desvinculação Dinâmica de ObRegisterCallbacks
                                       | - Remoção Dinâmica de PPL (DKOM PsIsProtectedProcess)
                                       | - Limpeza de PiDDBCacheTable e MmUnloadedDrivers
                                       | - Hardware Tracing via Intel PT (ToPA buffers)
```

---

## 2. Evasão Usermode com Código de Produção

### 2.1 Quebrando a Auditoria de Callstack (*Callstack Spoofing*)
Quando um cheat chama `NtWriteVirtualMemory`, o driver do anticheat inspeciona a pilha de execução com `RtlCaptureStackBackTrace`. Se o endereço de retorno apontar para uma região de memória anônima (`MEM_PRIVATE`), a injeção é denunciada.

O OnyxEngine implementa o sintetizador de pilha em Assembly x64 (`crates/callstack-spoof`):

```assembly
; callstack_spoof_stub.asm - Sintetizador de Frames Legítimos
.code
SpoofCall PROC
    ; Preserva registradores não voláteis
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15

    ; Aloca espaço de sombra e frame falso
    sub rsp, 28h

    ; Carrega o gadget dentro de um módulo legítimo do Windows (ex: jmp [rbx] na ntdll)
    mov r11, rcx              ; Função real a ser chamada
    mov r12, rdx              ; Gadget de retorno legítimo dentro da NTDLL

    ; Substitui o endereço de retorno real na pilha pelo endereço do gadget
    mov [rsp + 20h], r12

    ; Dispara a função alvo através de salto indireto
    call r11

    ; Restaura a pilha e registradores
    add rsp, 28h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
SpoofCall ENDP
END
```

### 2.2 Syscalls Indiretas via Halo's Gate (`crates/syscalls-indirect/src/lib.rs`)
Anticheats hookam APIs na `ntdll.dll` sobrescrevendo o prólogo com `JMP <anticheat>`. O módulo do OnyxEngine resolve o System Service Number (SSN) dinamicamente lendo os vizinhos não hookados e salta para um gadget limpo `syscall; ret`:

```rust
// crates/syscalls-indirect/src/lib.rs
pub struct NtdllInfo {
    pub base: *const u8,
    pub ssn: HashMap<String, u32>,
    pub gadget: *const u8, // Aponta para instrução 'syscall; ret' na NTDLL
}

// Resolução de SSN contornando hooks inline
pub fn resolve_ssn_halos_gate(func_ptr: *const u8) -> Option<u32> {
    unsafe {
        // Se a função começar com 0x4C, 0x8B, 0xD1, 0xB8 (mov r10, rcx; mov eax, ssn)
        if *func_ptr == 0x4C && *func_ptr.add(1) == 0x8B && *func_ptr.add(3) == 0xB8 {
            return Some(*(func_ptr.add(4) as *const u32));
        }

        // Se estiver hookada com JMP (0xE9): busca nos vizinhos (+32 / -32 bytes)
        if *func_ptr == 0xE9 {
            for idx in 1..32 {
                // Vizinho abaixo
                let down = func_ptr.add(idx * 32);
                if *down == 0x4C && *down.add(3) == 0xB8 {
                    let ssn = *(down.add(4) as *const u32);
                    return Some(ssn.wrapping_sub(idx as u32));
                }
                // Vizinho acima
                let up = func_ptr.sub(idx * 32);
                if *up == 0x4C && *up.add(3) == 0xB8 {
                    let ssn = *(up.add(4) as *const u32);
                    return Some(ssn.wrapping_add(idx as u32));
                }
            }
        }
        None
    }
}
```

---

## 3. Evasão Kernelmode com Código C do Driver (`OwMemDriver.sys`)

### 3.1 Tradução Física Direta sem Handles via CR3 (`driver/src/physmem.c`)
O driver do OnyxEngine valida intervalos físicos reais do hardware com `MmGetPhysicalMemoryRanges`, impedindo Blue Screens (BSOD) ao navegar por tabelas de página:

```c
// driver/src/physmem.c - Verificação de Segurança de Faixas Físicas
static SAFE_PHYSICAL_MEMORY_RANGE g_SafePhysicalRanges[128];
static ULONG g_SafePhysicalRangeCount = 0;

VOID InitializeSafePhysicalRanges(VOID)
{
    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (!ranges) return;

    ULONG count = 0;
    for (ULONG i = 0; count < 128; i++) {
        if (ranges[i].BaseAddress.QuadPart == 0 && ranges[i].NumberOfBytes.QuadPart == 0)
            break;

        ULONG64 base = (ULONG64)ranges[i].BaseAddress.QuadPart;
        ULONG64 size = (ULONG64)ranges[i].NumberOfBytes.QuadPart;
        if (size > 0) {
            g_SafePhysicalRanges[count].BaseAddress = base;
            g_SafePhysicalRanges[count].EndAddress = base + size;
            count++;
        }
    }
    ExFreePool(ranges);
    g_SafePhysicalRangeCount = count;
}
```

Com os limites de memória garantidos, o driver caminha pela hierarquia de 4 níveis x86_64:

```c
// driver/src/physmem.c - Resolução de Paginação de 4 Níveis
ULONG64 TranslateVirtualToPhysical(ULONG64 cr3, ULONG64 virtual_address) {
    ULONG64 pml4_idx = (virtual_address >> 39) & 0x1FF;
    ULONG64 pdpt_idx = (virtual_address >> 30) & 0x1FF;
    ULONG64 pd_idx   = (virtual_address >> 21) & 0x1FF;
    ULONG64 pt_idx   = (virtual_address >> 12) & 0x1FF;
    ULONG64 offset   = virtual_address & 0xFFF;

    ULONG64 pml4e = ReadPhysicalUlong64(cr3 + (pml4_idx * 8));
    if (!(pml4e & 1)) return 0;

    ULONG64 pdpte = ReadPhysicalUlong64((pml4e & 0x000FFFFFFFFFF000ULL) + (pdpt_idx * 8));
    if (!(pdpte & 1)) return 0;
    if (pdpte & 0x80) return (pdpte & 0x000FFFFFC0000000ULL) + (virtual_address & 0x3FFFFFFFULL); // 1 GB Page

    ULONG64 pde = ReadPhysicalUlong64((pdpte & 0x000FFFFFFFFFF000ULL) + (pd_idx * 8));
    if (!(pde & 1)) return 0;
    if (pde & 0x80) return (pde & 0x000FFFFFFFE00000ULL) + (virtual_address & 0x1FFFFFULL);       // 2 MB Page

    ULONG64 pte = ReadPhysicalUlong64((pde & 0x000FFFFFFFFFF000ULL) + (pt_idx * 8));
    if (!(pte & 1)) return 0;

    return (pte & 0x000FFFFFFFFFF000ULL) + offset; // 4 KB Page
}
```

---

### 3.2 Desvinculação Dinâmica de ObRegisterCallbacks (`driver/src/callbacks.c`)
O driver localiza e manipula as estruturas internas `_OB_CALLBACK_ENTRY`:

```c
// driver/src/callbacks.c
#pragma pack(push, 1)
typedef struct _OB_CALLBACK_ENTRY {
    LIST_ENTRY CallbackList;
    ULONG Operations;
    ULONG Enabled;
    PVOID Entry;
    POBJECT_TYPE ObjectType;
    PVOID PreOperation;
    PVOID PostOperation;
    KSPIN_LOCK Lock;
} OB_CALLBACK_ENTRY, *POB_CALLBACK_ENTRY;
#pragma pack(pop)

// Desconecta a rotina de interceptação do anticheat
NTSTATUS StripProcessCallbacks(PVOID TargetDriverBase, ULONG TargetDriverSize)
{
    PLIST_ENTRY list = GetObjectTypeCallbackList(*PsProcessType);
    if (!list) return STATUS_NOT_FOUND;

    PLIST_ENTRY current = list->Flink;
    while (current != list) {
        POB_CALLBACK_ENTRY entry = CONTAINING_RECORD(current, OB_CALLBACK_ENTRY, CallbackList);
        // Se a função PreOperation estiver dentro da faixa de memória do driver do anticheat:
        if ((ULONG64)entry->PreOperation >= (ULONG64)TargetDriverBase &&
            (ULONG64)entry->PreOperation < (ULONG64)TargetDriverBase + TargetDriverSize)
        {
            // Desativa a interceptação restaurando permissões
            InterlockedExchangePointer(&entry->PreOperation, NULL);
        }
        current = current->Flink;
    }
    return STATUS_SUCCESS;
}
```

---

### 3.3 Remoção Dinâmica de PPL via Desmontagem em Runtime (`driver/src/dkom.c`)
Para processos com proteção **PPL (Protected Process Light)**, o offset exato de `_PS_PROTECTION` varia conforme o build do Windows 10/11 (21H2, 22H2, 23H2, 24H2). O driver do OnyxEngine resolve o deslocamento desmontando `PsIsProtectedProcess` em tempo de execução:

```c
// driver/src/dkom.c - Resolução Dinâmica de Deslocamento de Proteção
ULONG ResolveProcessProtectionOffset(VOID)
{
    UNICODE_STRING uRoutine;
    RtlInitUnicodeString(&uRoutine, L"PsIsProtectedProcess");
    PUCHAR pfn = (PUCHAR)MmGetSystemRoutineAddress(&uRoutine);
    if (!pfn) return 0;

    // Varre as instruções buscando o opcode de teste do campo de proteção
    for (ULONG i = 0; i < 48; i++) {
        // Padrão: test byte ptr [rcx + offset], 7
        if (pfn[i] == 0xF6 && pfn[i + 1] == 0x81 && pfn[i + 6] == 0x07) {
            ULONG offset = *(PULONG)(pfn + i + 2);
            if (offset >= 0x400 && offset <= 0x1000) return offset;
        }
        // Padrão alternativo: mov al, byte ptr [rcx + offset]
        else if (pfn[i] == 0x8A && pfn[i + 1] == 0x81) {
            ULONG offset = *(PULONG)(pfn + i + 2);
            if (offset >= 0x400 && offset <= 0x1000) return offset;
        }
    }
    return 0x87A; // Fallback para builds Windows 11 modernos
}

// Zera a proteção PPL no EPROCESS permitindo OpenProcess com PROCESS_ALL_ACCESS
VOID StripPPL(PEPROCESS Process)
{
    ULONG offset = ResolveProcessProtectionOffset();
    if (offset != 0) {
        PUCHAR pProtection = (PUCHAR)Process + offset;
        *pProtection = 0; // Type = 0 (None), Signer = 0 (None)
    }
}
```
