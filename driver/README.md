# OwMemDriver v2.0 - OnyxEngine Ring-0 Kernel Memory Engine

Driver de kernel dedicado para o **OnyxEngine**, projetado para alto desempenho, evasão e estabilidade em **Windows 10** e **Windows 11** (64-bit).

---

## Recursos e Técnicas Implementadas

### 1. Leitura e Escrita Física Direta via CR3 (Zero-Attach)
- Realiza o page-walking de 4 níveis de tabela de páginas (**PML4 -> PDPT -> PD -> PT**) para traduzir Endereços Virtuais (VA) em Endereços Físicos (PA).
- Lê e escreve diretamente na memória física através de `MmCopyMemory` mapeando blocos de páginas.
- **Zero Attach**: Não chama `KeAttachProcess` nem `KeStackAttachProcess`, impedindo que threads do OnyxEngine sejam registradas na fila APC do processo alvo.
- Suporte a páginas padrão de **4 KB**, Large Pages de **2 MB** e **1 GB**, e resolução de PTEs de transição (desvio de traps de VMProtect/Themida).
- Resolução dinâmica de KVA Shadowing (`UserDirectoryTableBase` vs `DirectoryTableBase`).

### 2. Blindagem Total contra Telas Azuis (Zero BSOD)
- **Pools NX**: Todas as alocações de memória usam `NonPagedPoolNx` (`DBK_POOL_NX = 512`), em conformidade total com Windows 10 e Windows 11.
- **Top-Level SEH**: Todo o despachante de IOCTLs (`DispatchIoctl`) é encapsulado por blocos `__try __except (EXCEPTION_EXECUTE_HANDLER)` retornando `STATUS_UNHANDLED_EXCEPTION` em vez de disparar BugCheck.
- **Validação Estrita de Limites**: Checagem de `InputBufferLength` e `OutputBufferLength` com respostas imediatas `STATUS_INFO_LENGTH_MISMATCH` e `STATUS_BUFFER_TOO_SMALL`.

### 3. Gestão Furtiva de ObRegisterCallbacks
- No momento em que `IOCTL_CE_OPENPROCESS` é executado, o driver desliga temporariamente os ponteiros `PreOperation` de callbacks registrados (`StripProcessCallbacks(FALSE)`).
- Logo após a chamada `ObOpenObjectByPointer` criar a handle com `PROCESS_ALL_ACCESS`, os callbacks são restaurados (`StripProcessCallbacks(TRUE)`).
- Impede que drivers de proteção e segurança (EDRs, agentes de monitoramento) façam downgrade de direitos da handle ou bloqueiem a abertura do processo.

### 4. Ocultação de Processo via Kernel (DKOM)
- Função `HideProcessByPid(pid)` que localiza o `EPROCESS` e desvincula a entrada do processo da lista duplamente encadeada `ActiveProcessLinks`.
- Resolução dinâmica do offset de `ActiveProcessLinks` compatível com Windows 10 (1903 a 22H2) e Windows 11 (21H2 a 24H2).
- Torna o processo invisível para Task Manager, Process Hacker e varreduras de processos em usermode/kernel.

### 5. Higienização de Rastros (PiDDBCacheTable e MmUnloadedDrivers)
- Remove vestígios de `OwMemDriver.sys`, `owmemdriver.sys`, `lydumen.sys` e `dbk64.sys` da tabela `PiDDBCacheTable` do `ntoskrnl.exe`.
- Zera entradas e nomes no array de drivers descarregados `MmUnloadedDrivers`.

---

## Estrutura de Arquivos

```text
driver/
├── include/
│   ├── DBKFunc.h          # Declarações do CR3 walker, PiDDB cleaner e DKOM
│   ├── IOPLDispatcher.h   # Definições de IOCTLs do OnyxEngine
│   ├── memscan.h          # Interfaces de varredura e cópia física
│   └── ...
├── src/
│   ├── DBKDrvr.c          # Entry point (DriverEntry) e registro de dispositivo
│   ├── IOPLDispatcher.c   # Despachante IOCTL blindado com SEH
│   ├── DBKFunc.c          # Algoritmos de CR3 walk, DKOM e PiDDB
│   ├── memscan.c          # Leitura/escrita física prioritária
│   └── ...
├── OwMemDriver.inf        # Arquivo de instalação para Windows 10/11 x64
└── README.md
```

## Compilação e Conformidade HVCI / VBS (Windows 11)

### 1. Requisitos de Compilação
O driver deve ser compilado com o **Visual Studio 2022 + WDK (Windows Driver Kit)** configurado para:
- **Configuração**: `Release | x64`
- **Target OS**: `Windows 10 and later`
- **Flag Obrigatória de Integridade**: `/INTEGRITYCHECK` (Linker -> Command Line -> `/INTEGRITYCHECK`).
  - Esta flag grava `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` (0x0080) no cabeçalho PE, exigência formal do subsistema CI.dll para execução compatível com **HVCI (Memory Integrity)**.

### 2. Políticas de Memória Ring-0 (W^X & Pool NX)
- **Zero NonPagedPool Executável**: Todas as alocações dinâmicas utilizam estritamente `DBK_POOL_NX` (`NonPagedPoolNx = 512`), garantindo o bit No-Execute (NX/XD) ativo em todas as páginas de kernel.
- **Conformidade W^X**: Nenhuma rotina executa instruções em pools de dados ou tenta modificar páginas de código somente-leitura.
- **Blindagem de CR0**: Operações de CR0 são protegidas contra traps de SLAT/EPT impostos por hipervisores Type-1 (Microsoft Hyper-V / VBS).

### 3. Modos de Carregamento
- **Ambiente de Testes Homologado**: Desativação temporária do Secure Boot no firmware UEFI com `bcdedit /set testsigning on` e assinatura de teste local.
- **Carregamento Furtivo**: Compatível com alocação em Ring-0 através de interfaces de kernel mapping (ex: RTCore64 / BYOVD).
