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
|  - Auditoria de Drivers Carregados (PiDDBCacheTable, MmUnloadedDrivers)         |
|  - Verificação de Assinatura de Código e Certificados Revogados                 |
|  - Detecção de Hipervisores (Timing Attacks RDTSC / CPUID VM-Exit)              |
|  - Varredura de ActiveProcessLinks e Threads de Sistema PsCreateSystemThread    |
+---------------------------------------------------------------------------------+
                                       ^
                                       | Contra-ataque OnyxEngine:
                                       | - Leitura/Escrita Física Direta via CR3
                                       | - Desvinculação Dinâmica de ObRegisterCallbacks
                                       | - DKOM em ActiveProcessLinks
                                       | - Limpeza de PiDDBCacheTable e MmUnloadedDrivers
                                       | - Hardware Tracing via Intel PT (ToPA buffers)
```

---

## 2. Evasão Usermode: Passo a Passo Técnico

### 2.1 Quebrando a Auditoria de Callstack (*Callstack Spoofing*)
Quando um cheat chama `NtWriteVirtualMemory`, o driver do anticheat ou a hook usermode inspeciona a pilha de execução com `RtlCaptureStackBackTrace`. Se o endereço de retorno estiver dentro de uma região `MEM_PRIVATE` (código injetado avulso), o anticheat emite um alerta de telemetria.

O OnyxEngine implementa um trampolim de spoofing em Assembly puro x64 (`callstack_spoof.dll`):

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

### 2.2 Syscalls Indiretas via Halo's Gate (`syscalls_indirect.dll`)
Anticheats hookam funções como `NtProtectVirtualMemory` sobrescrevendo os primeiros 5 bytes com `JMP <anticheat_hook>`. Para contornar essa interceptação:
1. O OnyxEngine lê os bytes de `NtProtectVirtualMemory` na memória da `ntdll.dll`.
2. Se o padrão começar com `E9` (`JMP`), o algoritmo **Halo's Gate** examina os vizinhos adjacentes (+32 bytes para cima ou para baixo) que não estão hookados.
3. Como os System Service Numbers (SSN) são estritamente sequenciais no Windows x64, o SSN da função hookada é inferido com precisão matemática:
   $$\text{SSN}_{\text{alvo}} = \text{SSN}_{\text{vizinho}} \pm \text{Distância}$$
4. O registrador `EAX` é carregado com o SSN calculado e a execução salta para uma instrução `syscall; ret` localizada dentro do próprio corpo original da NTDLL, garantindo que o RIP de transição pertença a uma página executável legítima e assinada da Microsoft.

---

## 3. Evasão Kernelmode: Engenharia de Ring-0

### 3.1 Tradução Física Direta sem Handles via CR3
Mesmo que um anticheat retire todos os privilégios do handle usermode do OnyxEngine via `ObRegisterCallbacks` (concedendo apenas `0x1000` / `PROCESS_QUERY_LIMITED_INFORMATION`), o driver `OwMemDriver.sys` opera em nível de hardware, tornando a concessão de handles totalmente irrelevante:

```c
// physmem.c - Caminhada pelas tabelas de paginação x86_64
ULONG64 TranslateVirtualToPhysical(ULONG64 cr3, ULONG64 virtual_address) {
    // 1. Extração dos índices de 9 bits da hierarquia de páginas
    ULONG64 pml4_idx = (virtual_address >> 39) & 0x1FF;
    ULONG64 pdpt_idx = (virtual_address >> 30) & 0x1FF;
    ULONG64 pd_idx   = (virtual_address >> 21) & 0x1FF;
    ULONG64 pt_idx   = (virtual_address >> 12) & 0x1FF;
    ULONG64 offset   = virtual_address & 0xFFF;

    // 2. Leitura da tabela PML4 a partir do endereço físico no CR3
    ULONG64 pml4e = ReadPhysicalUlong64(cr3 + (pml4_idx * 8));
    if (!(pml4e & 1)) return 0; // Bit de presença ausente

    // 3. Leitura da tabela PDPT
    ULONG64 pdpte = ReadPhysicalUlong64((pml4e & 0x000FFFFFFFFFF000ULL) + (pdpt_idx * 8));
    if (!(pdpte & 1)) return 0;

    // 4. Verificação de página grande (1 GB)
    if (pdpte & 0x80) return (pdpte & 0x000FFFFFC0000000ULL) + (virtual_address & 0x3FFFFFFFULL);

    // 5. Leitura do Diretório de Páginas (PD)
    ULONG64 pde = ReadPhysicalUlong64((pdpte & 0x000FFFFFFFFFF000ULL) + (pd_idx * 8));
    if (!(pde & 1)) return 0;

    // 6. Verificação de página grande (2 MB)
    if (pde & 0x80) return (pde & 0x000FFFFFFFE00000ULL) + (virtual_address & 0x1FFFFFULL);

    // 7. Leitura da Tabela de Páginas (PT)
    ULONG64 pte = ReadPhysicalUlong64((pde & 0x000FFFFFFFFFF000ULL) + (pt_idx * 8));
    if (!(pte & 1)) return 0;

    // 8. Endereço físico final do quadro de 4 KB
    return (pte & 0x000FFFFFFFFFF000ULL) + offset;
}
```

A leitura é realizada mapeando o quadro físico diretamente com `MmMapIoSpaceEx(PhysicalAddress, Size, PAGE_READWRITE)`. Esse método contorna:
- Notificações de acesso a memória do kernel.
- Permissões de proteção de página de usermode (`PAGE_NOACCESS`, `PAGE_GUARD`).
- Hooks colocados por filtros de driver de anticheats.

### 3.2 Desvinculação Dinâmica de ObRegisterCallbacks
Para restaurar a capacidade de depuração usermode quando necessário, o driver localiza a lista não exportada de callbacks do subsistema de objetos:
1. Analisa a função exportada `ObUnRegisterCallbacks` para extrair o ponteiro da lista circular `ObpProcessCallbackList`.
2. Itera sobre os nós `CALLBACK_ENTRY_ITEM`.
3. Ao identificar a entrada pertencente ao anticheat (pelo endereço base do driver correspondente), o driver altera os ponteiros de função de `PreOperation` e `PostOperation` para ponteiros nulos ou retorna `OB_PREOP_SUCCESS` sem aplicar as máscaras restritivas de acesso.
