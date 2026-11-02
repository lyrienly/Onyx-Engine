# Driver Ring-0 e Evasão em Nível de Kernel (`OwMemDriver.sys`)

## 1. Visão Geral

O **OwMemDriver.sys** (também integrado como **OnyxDriver**) é o subsistema de kernel Ring-0 do OnyxEngine, desenvolvido em C nativo e x64 Assembly com o Windows Driver Kit (WDK). Ele é responsável por fornecer operações privilegiadas de memória física e hardware que não podem ser executadas a partir do usermode (Ring-3), permitindo ao OnyxEngine inspecionar e manipular processos protegidos por mecanismos modernos de segurança de sistemas operacionais e anti-cheats (como EAC, BattlEye, Vanguard e EDRs corporativos).

---

## 2. Capacidades de Kernel

```text
+--------------------------------------------------------------------------+
|                       OnyxEngine Usermode (Ring-3)                       |
|         onyx_backend.dll / OnyxEngine-CE.exe / onyx_mcp_server           |
+--------------------------------------------------------------------------+
                                     |
                                     | DeviceIoControl (Fast I/O Buffering)
                                     v
+--------------------------------------------------------------------------+
|                  OwMemDriver.sys / OnyxDriver (Ring-0)                   |
+--------------------------------------------------------------------------+
|  [physmem.c]        Leitura/Escrita Física Direta via Paginação CR3      |
|  [callbacks.c]      Desvinculação Dinâmica de ObRegisterCallbacks        |
|  [dkom.c]           Direct Kernel Object Manipulation (Process Unlink)   |
|  [stealth.c]        Limpeza de PiDDBCacheTable e MmUnloadedDrivers       |
|  [ultimap2.c]       Rastreamento Hardware Intel PT via ToPA Buffers      |
|  [debugger.c]       Depuração Kernel e Manipulação de DR0-DR7 / IDT      |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
|                       Hardware / Memória Física                          |
|             MMU x86_64 / Registradores de Controle / RAM                 |
+--------------------------------------------------------------------------+
```

---

## 3. Principais Subsistemas do Driver

### 3.1 Tradução Física Direta e Paginação CR3 (`physmem.c`)
- **Desvio de Hooks Usermode**: Não utiliza APIs como `NtReadVirtualMemory` ou `ReadProcessMemory`, que são monitoradas por EDRs e anti-cheats.
- **Caminhada de Tabelas de Páginas**: A partir do ponteiro `CR3` (Directory Table Base) do `EPROCESS` alvo, o driver resolve o endereço virtual em endereço físico através da hierarquia de paginação de 4 níveis do x86_64:
  $$\text{Virtual Address} \longrightarrow \text{PML4} \longrightarrow \text{PDPT} \longrightarrow \text{PD} \longrightarrow \text{PT} \longrightarrow \text{Physical Frame}$$
- **Mapeamento Seguro**: Utiliza `MmMapIoSpaceEx` ou o manipulador de seção física `\Device\PhysicalMemory` com verificações estritas de limites e tratamento de exceções estruturadas (SEH), prevenindo Blue Screen of Death (BSOD) em acessos a páginas inválidas.

### 3.2 Evasão e Desvinculação de ObRegisterCallbacks (`callbacks.c`)
- Sistemas anticheat usam `ObRegisterCallbacks` para interceptar tentativas de obtenção de handles para processos de jogos via `NtOpenProcess`, reduzindo privilégios para `PROCESS_QUERY_LIMITED_INFORMATION`.
- O driver localiza dinamicamente as listas internas não documentadas do kernel:
  - `ObpProcessCallbackList`
  - `ObpThreadCallbackList`
- O driver desconecta ou neutraliza as rotinas de pré-operação (`PreOperationCallback`) e pós-operação (`PostOperationCallback`), restaurando permissões totais de acesso (`PROCESS_ALL_ACCESS`) transparentemente.

### 3.3 Direct Kernel Object Manipulation - DKOM (`dkom.c`)
- **Ocultação de Processo**: Desvincula a estrutura `EPROCESS` do processo alvo da lista circular duplamente encadeada `ActiveProcessLinks`. O processo continua executando na CPU pelo escalonador de threads (`KTHREAD`), mas desaparece completamente de chamadas como `NtQuerySystemInformation` e do Gerenciador de Tarefas do Windows.
- **Elevação de Token**: Manipulação do ponteiro `Token` no `EPROCESS` para replicar o token de segurança do processo `SYSTEM` (PID 4), concedendo privilégios absolutos de depuração (`SeDebugPrivilege`).

### 3.4 Furtividade e Limpeza de Rastros (`stealth.c`)
Para evitar detecções de carregamento de drivers manuais ou sem assinatura:
- **Limpeza de PiDDBCacheTable**: Remove a entrada do driver do cache de executáveis incompatíveis verificado por anticheats.
- **Desvinculação de MmUnloadedDrivers**: Purga o registro de descarga de driver da lista do kernel para impedir auditoria retroativa.
- **Limpeza de KernelHashBucketList**: Remove hashes de certificados residuais gerados pelo carregador do Windows.

### 3.5 Rastreamento de Execução por Hardware via Intel PT (`ultimap2.c`)
- O subsistema **Ultimap 2** utiliza **Intel Processor Trace (Intel PT)** para registrar cada desvio, salto condicional e chamada de função executada pela CPU em tempo real com impacto inferior a 1% de performance.
- Configura a tabela física de buffers de saída **ToPA (Table of Physical Addresses)** diretamente nos registradores MSR de trace (`IA32_RTIT_CTL`, `IA32_RTIT_OUTPUT_BASE`), viabilizando a gravação contínua do fluxo de instruções de binários protegidos sem necessidade de breakpoints de software (`INT 3`).

---

## 4. Interface IOCTL e Comunicação Usermode

A comunicação entre a `onyx_backend.dll` e o `OwMemDriver.sys` opera através de descritores de dispositivo criados via Win32:

```c
HANDLE hDriver = CreateFileW(L"\\\\.\\OwMemDriver",
                             GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL,
                             OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL,
                             NULL);
```

### Principais Códigos de Controle (IOCTL)

| Código IOCTL | Finalidade |
|---|---|
| `IOCTL_CE_READ_MEMORY` | Leitura de memória virtual ou física via paginação CR3 |
| `IOCTL_CE_WRITE_MEMORY` | Escrita direta de memória física contornando permissões de página |
| `IOCTL_CE_GET_CR3` | Consulta do registrador CR3 base do diretório de tabelas do alvo |
| `IOCTL_CE_STRIP_CALLBACKS` | Desvinculação das estruturas ObRegisterCallbacks no kernel |
| `IOCTL_CE_HIDE_PROCESS` | Ocultação DKOM do processo alvo em ActiveProcessLinks |
| `IOCTL_CE_SETUP_ULTIMAP2` | Inicialização dos buffers ToPA e controle de MSRs do Intel PT |
| `IOCTL_CE_SET_DEBUGGER` | Configuração de breakpoints por hardware no kernel (DR0-DR3) |

---

## 5. Procedimentos de Instalação e Execução

### 5.1 Modo de Assinatura de Teste (Testsigning)
Para carregar o driver em ambientes de pesquisa e desenvolvimento:
```cmd
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
```
*(Reinicialização do sistema necessária)*

### 5.2 Instalação do Certificado de Teste
O certificado digital de teste do driver acompanha o pacote em `OwMemDriver.cer`:
```cmd
certutil -addstore "Root" OwMemDriver.cer
certutil -addstore "TrustedPublisher" OwMemDriver.cer
```

### 5.3 Criação do Serviço de Kernel
Para registrar e iniciar o driver sob demanda:
```cmd
sc create OwMemDriver binPath= "C:\Caminho\OwMemDriver.sys" type= kernel
sc start OwMemDriver
```

---

## 6. Diagnóstico e Tratamento de Erros

O subsistema de kernel reporta códigos de status NTSTATUS mapeados diretamente para o catálogo unificado de erros do OnyxEngine:
- `0xC0000005` (`STATUS_ACCESS_VIOLATION`) -> Tratado pelo SEH interno do driver sem causar falha no sistema.
- `0xC0000001` (`STATUS_UNSUCCESSFUL`) -> Falha de localização de tabelas de símbolos ou paginação.
- `0xC0000022` (`STATUS_ACCESS_DENIED`) -> Concorrência de integridade em modo HVCI/VBS; o driver sinaliza a necessidade de isolamento via CR3 estrito.
