# Catálogo Completo do Sistema de Erros do OnyxEngine

## 1. Fundamentos do Sistema de Erros

No contexto de engenharia reversa e segurança de sistemas, erros silenciosos ou genéricos geram falhas graves de diagnóstico e perda de tempo durante auditorias. O OnyxEngine adota um modelo tipado e unificado em que cada condição anômala possui:
1. Um código numérico padronizado (`OnyxErrorCode`).
2. Mensagem em Português do Brasil (`pt-BR`) como idioma primário do operador.
3. Mensagem técnica complementar em Inglês (`en-US`).
4. Contexto de hardware/sistema (Endereço Virtual, Endereço Físico CR3, PID, NTSTATUS ou Win32 Error Code).
5. Armazenamento thread-local seguro para ambientes concorrentes multi-thread.

---

## 2. Catálogo Exaustivo de Códigos de Erro (1 por 1)

### Faixa 0: Sucesso
- **Código 0: `Success`**
  - **Causa:** A operação foi executada e finalizada sem falhas ou anomalias.
  - **Diagnóstico PT-BR:** Operação concluída com sucesso.
  - **Resolução:** Nenhuma ação necessária.

---

### Faixa 100 - 199: Geral & Barramento ABI

- **Código 101: `NullPointer`**
  - **Causa:** Um ponteiro essencial para a operação (como buffer de saída, handle de processo ou string de caminho) foi passado como nulo (`0x0`).
  - **Diagnóstico PT-BR:** Ponteiro nulo inesperado passado para o parâmetro especificado.
  - **Resolução:** Validar a alocação de memória do chamador antes de despachar a chamada para a DLL.

- **Código 102: `InvalidArgument`**
  - **Causa:** Um ou mais parâmetros violaram os limites ou invariantes esperados pela função (ex: contadores negativos, máscaras inválidas).
  - **Diagnóstico PT-BR:** Argumento inválido fornecido para a rotina interna.
  - **Resolução:** Inspecionar os argumentos de entrada e certificar-se de que correspondem à especificação do C-ABI.

- **Código 103: `BufferTooSmall`**
  - **Causa:** O buffer alocado pelo cliente para receber resultados (como lista de módulos ou seções PE) é menor do que a quantidade mínima necessária.
  - **Diagnóstico PT-BR:** Buffer insuficiente fornecido pelo chamador.
  - **Resolução:** Utilizar o parâmetro de saída de contagem total (`out_total`) para redimensionar o buffer antes da gravação.

- **Código 104: `BufferOverflow`**
  - **Causa:** Tentativa de escrita ou leitura além da capacidade máxima alocada para uma estrutura ou canal de comunicação.
  - **Diagnóstico PT-BR:** Transbordamento de buffer detectado na operação.
  - **Resolução:** Ajustar o limitador de paginação ou truncar os dados conforme os limites do subsistema.

- **Código 105: `IndexOutOfBounds`**
  - **Causa:** Solicitação de acesso a um elemento inexistente em um array interno (ex: slot de breakpoint inexistente no registrador DRx).
  - **Diagnóstico PT-BR:** Índice fora dos limites do array ou coleção.
  - **Resolução:** Verificar a faixa de índices disponíveis antes de endereçar elementos indexados.

- **Código 106: `InvalidState`**
  - **Causa:** A rotina foi acionada fora do ciclo de vida esperado (ex: tentar continuar uma varredura sem que a primeira varredura tenha sido executada).
  - **Diagnóstico PT-BR:** Estado inválido ou inconsistente para a execução do comando.
  - **Resolução:** Seguir a máquina de estados requerida pelo subsistema antes da chamada.

- **Código 107: `OperationCancelled`**
  - **Causa:** O operador ou uma rotina assíncrona sinalizou interrupção forçada (ex: cancelamento de varredura profunda de ponteiros).
  - **Diagnóstico PT-BR:** A operação foi cancelada pelo usuário ou pelo sistema.
  - **Resolução:** Tratar o encerramento gracioso e liberar os descritores temporários.

- **Código 108: `OperationTimeout`**
  - **Causa:** O tempo máximo de espera para uma resposta de thread remota, pipe IPC ou sinalização de sincronismo foi esgotado.
  - **Diagnóstico PT-BR:** Tempo limite de espera esgotado na operação.
  - **Resolução:** Aumentar o timeout de sincronismo ou verificar se o processo alvo está bloqueado em deadlock.

- **Código 109: `NotImplemented`**
  - **Causa:** Chamada direcionada a um recurso experimental ou função reservada que ainda não possui implementação nativa.
  - **Diagnóstico PT-BR:** Recurso ou rotina técnica ainda não implementada.
  - **Resolução:** Consultar o roadmap do projeto e utilizar módulos alternativos disponíveis.

- **Código 110: `InternalError`**
  - **Causa:** Falha interna não categorizada em tempo de execução, captura de exceção não tratada ou corrupção de estado interno.
  - **Diagnóstico PT-BR:** Falha interna não tratada no núcleo do OnyxEngine.
  - **Resolução:** Coletar o log detalhado e submeter relatório de auditoria para o time de desenvolvimento.

---

### Faixa 1000 - 1099: Gestão de Processos

- **Código 1001: `ProcessNotFound`**
  - **Causa:** O PID ou nome do processo alvo especificado não existe na tabela ativa de tarefas do Windows.
  - **Diagnóstico PT-BR:** Processo com o identificador especificado não foi encontrado no sistema.
  - **Resolução:** Atualizar a lista de processos via `onyx_process_list` para confirmar a existência do alvo.

- **Código 1002: `ProcessAccessDenied`**
  - **Causa:** A chamada ao Win32 `OpenProcess` ou NT Native `NtOpenProcess` retornou código de acesso negado (`ERROR_ACCESS_DENIED` ou `STATUS_ACCESS_DENIED`). Ocorre frequentemente quando o alvo é um Processo Protegido (PPL), possui driver de proteção / EDR com ObRegisterCallbacks ou o processo executor não possui elevação administrativa.
  - **Diagnóstico PT-BR:** Acesso negado ao anexar ao processo. O alvo pode ser protegido por PPL, possuir filtros de kernel ou requerer privilégios administrativos.
  - **Resolução:** Executar o executável com permissões de Administrador e habilitar o modo Ring-0 através do driver `OwMemDriver`.

- **Código 1003: `ProcessAttachFailed`**
  - **Causa:** Falha genérica durante a anexação que não se enquadra em acesso negado (ex: processo em processo de terminação zumbi).
  - **Diagnóstico PT-BR:** Falha ao conectar ao processo alvo.
  - **Resolução:** Verificar o ciclo de vida do executável alvo.

- **Código 1004: `ProcessSnapshotFailed`**
  - **Causa:** Falha nas chamadas `CreateToolhelp32Snapshot` ou `NtQuerySystemInformation` ao listar processos ou módulos do sistema.
  - **Diagnóstico PT-BR:** Falha ao capturar snapshot de processos do sistema operacional.
  - **Resolução:** Verificar restrições de memória do sistema ou bloqueios de telemetria por antivírus.

- **Código 1005: `ProcessSuspensionFailed`**
  - **Causa:** A chamada nativa `NtSuspendProcess` falhou ao congelar a execução do processo alvo.
  - **Diagnóstico PT-BR:** Falha ao suspender as threads do processo alvo.
  - **Resolução:** Verificar se o handle possui os direitos `PROCESS_SUSPEND_RESUME`.

- **Código 1006: `ProcessResumeFailed`**
  - **Causa:** A chamada nativa `NtResumeProcess` falhou ao descongelar a execução das threads do processo.
  - **Diagnóstico PT-BR:** Falha ao retomar a execução do processo alvo.
  - **Resolução:** Confirmar a integridade do handle do processo e contadores de suspensão.

- **Código 1007: `ProcessInvalidHandle`**
  - **Causa:** O descritor de processo (`HANDLE`) passado para a rotina de leitura, gravação ou análise é nulo ou já foi encerrado.
  - **Diagnóstico PT-BR:** Handle do processo alvo é inválido ou já foi encerrado.
  - **Resolução:** Reanexar ao processo utilizando `onyx_process_attach`.

- **Código 1008: `ProcessThreadSnapshotFailed`**
  - **Causa:** Falha ao enumerar as threads ativas do processo alvo via Toolhelp32.
  - **Diagnóstico PT-BR:** Falha ao capturar a lista de threads ativas do processo.
  - **Resolução:** Validar se o processo não está travado em estado crítico de encerramento.

- **Código 1009: `ProcessArchitectureMismatch`**
  - **Causa:** Tentativa de manipular um processo com arquitetura incompatível (ex: processo de 32 bits sob depurador puramente de 64 bits sem thunks WOW64).
  - **Diagnóstico PT-BR:** Incompatibilidade de arquitetura entre o OnyxEngine e o processo alvo.
  - **Resolução:** Certificar-se de que o processo alvo é um binário x86_64 nativo.

- **Código 1010: `ProcessAlreadyAttached`**
  - **Causa:** Tentativa de abrir uma nova conexão com um processo que já está sob sessão ativa de controle.
  - **Diagnóstico PT-BR:** O processo alvo já está anexado na sessão atual.
  - **Resolução:** Reutilizar a instância aberta ou fechar a sessão anterior com `onyx_process_close`.

- **Código 1011: `ProcessNotAttached`**
  - **Causa:** Tentativa de executar uma ação de leitura/escrita antes de realizar a anexação ao processo.
  - **Diagnóstico PT-BR:** Nenhuma sessão de processo ativa encontrada para executar a operação.
  - **Resolução:** Invocar `onyx_process_attach` antes de qualquer manipulação de memória.

- **Código 1012: `ProcessModuleNotFound`**
  - **Causa:** O módulo dinâmico (DLL ou EXE principal) solicitado por nome não foi encontrado na memória do alvo.
  - **Diagnóstico PT-BR:** Módulo dinâmico não foi localizado no espaço de endereçamento do processo.
  - **Resolução:** Verificar a grafia exata do módulo ou aguardar o carregamento de bibliotecas dinâmicas tardias.

- **Código 1013: `ProcessPebQueryFailed`**
  - **Causa:** Falha ao resolver o endereço base do Process Environment Block (PEB) via `NtQueryInformationProcess`.
  - **Diagnóstico PT-BR:** Falha ao consultar os descritores do PEB no processo remoto.
  - **Resolução:** Requer direitos `PROCESS_QUERY_INFORMATION` ou uso de acesso a nível de kernel.

- **Código 1014: `ProcessCr3ResolveFailed`**
  - **Causa:** O driver de kernel não conseguiu localizar o endereço do registrador CR3 associado ao `EPROCESS` do processo.
  - **Diagnóstico PT-BR:** Falha ao resolver o diretório de paginação física (CR3) no kernel.
  - **Resolução:** Validar a compatibilidade da versão do kernel Windows (10/11) com os offsets da `KPROCESS`.

---

### Faixa 1100 - 1199: Operações de Memória Virtual

- **Código 1101: `MemoryReadFailed`**
  - **Causa:** Falha na leitura de memória remota via `ReadProcessMemory` ou `NtReadVirtualMemory`. Tipicamente provocada por leitura em páginas não alocadas (`MEM_FREE`), protegidas por `PAGE_NOACCESS`, ou páginas descarregadas para o arquivo de paginação.
  - **Diagnóstico PT-BR:** Falha na leitura de memória remota. Página inacessível, não alocada ou com proteção restrita.
  - **Resolução:** Consultar a proteção da página com `onyx_process_regions` antes de requisitar leitura de grandes blocos.

- **Código 1102: `MemoryWriteFailed`**
  - **Causa:** Tentativa de gravação em página de memória com atributos somente leitura (`PAGE_READONLY`, `PAGE_EXECUTE_READ`) sem que a proteção tenha sido relaxada, ou intercepção por proteção de integridade de memória.
  - **Diagnóstico PT-BR:** Falha na gravação de memória remota. Página protegida contra escrita.
  - **Resolução:** Aplicar alteração temporária de proteção via `onyx_process_protect` para `PAGE_EXECUTE_READWRITE` antes da escrita.

- **Código 1103: `MemoryAllocFailed`**
  - **Causa:** O sistema operacional ou o processo alvo recusou a solicitação de alocação virtual via `VirtualAllocEx` ou `NtAllocateVirtualMemory` (ex: fragmentação severa de memória ou falta de cota de commit).
  - **Diagnóstico PT-BR:** Falha na alocação de memória virtual no processo alvo.
  - **Resolução:** Reduzir o tamanho da alocação ou não especificar endereço base fixo.

- **Código 1104: `MemoryProtectFailed`**
  - **Causa:** Falha ao alterar as permissões de acesso de uma região de memória via `VirtualProtectEx`.
  - **Diagnóstico PT-BR:** Falha ao modificar os direitos de proteção da página de memória.
  - **Resolução:** Confirmar se o endereço e o tamanho estão alinhados a fronteiras de página (4 KB).

- **Código 1105: `MemoryFreeFailed`**
  - **Causa:** Tentativa de liberação de memória com `VirtualFreeEx` fornecendo endereço incorreto ou tipo de liberação inválido.
  - **Diagnóstico PT-BR:** Falha na liberação de memória virtual no processo alvo.
  - **Resolução:** Garantir que o endereço base passado para liberação seja o endereço exato retornado na alocação original.

- **Código 1106: `MemoryQueryFailed`**
  - **Causa:** Falha na consulta de atributos de bloco de memória via `VirtualQueryEx` ou `NtQueryVirtualMemory`.
  - **Diagnóstico PT-BR:** Falha na consulta dos descritores de memória virtual do alvo.
  - **Resolução:** Assegurar que o endereço consultado se encontra dentro do espaço canônico do usuário x86_64.

- **Código 1107: `MemoryInvalidAddress`**
  - **Causa:** O endereço fornecido encontra-se fora do intervalo de endereçamento virtual de 64 bits suportado ou no espaço protegido do kernel (acima de `0x7FFF_FFFF_FFFF`).
  - **Diagnóstico PT-BR:** Endereço de memória inválido ou fora dos limites do espaço de endereçamento usermode.
  - **Resolução:** Fornecer ponteiros canônicos pertencentes à faixa de usermode.

- **Código 1108: `MemoryPageGuardEncountered`**
  - **Causa:** Acessada uma página demarcada com o modificador `PAGE_GUARD`. No Windows, este acesso dispara uma exceção única de proteção.
  - **Diagnóstico PT-BR:** Exceção de proteção PAGE_GUARD interceptada no endereço de memória.
  - **Resolução:** Remover o modificador `PAGE_GUARD` antes da leitura, ou registrar um manipulador VEH para tratar o disparo.

- **Código 1109: `MemoryCopyOnWriteViolation`**
  - **Causa:** Violação de integridade ao tentar escrever em páginas marcadas com semântica Copy-on-Write sem replicação prévia.
  - **Diagnóstico PT-BR:** Violação de permissão Copy-on-Write na região de memória.
  - **Resolução:** Aplicar proteção explícita de escrita na página antes da operação.

- **Código 1110: `MemoryUnalignedAccess`**
  - **Causa:** Tentativa de execução de instrução ou leitura de tipo escalar obrigatório que requer alinhamento estrito (ex: operandos vetoriais SSE/AVX que exigem alinhamento de 16 ou 32 bytes).
  - **Diagnóstico PT-BR:** Violação de alinhamento em acesso a tipos estruturados ou vetoriais.
  - **Resolução:** Alinhar o endereço base aos limites exigidos pela arquitetura.

- **Código 1111: `MemoryZeroBytesTransferred`**
  - **Causa:** A chamada de I/O de memória completou formalmente, porém transferiu zero bytes do processo alvo.
  - **Diagnóstico PT-BR:** Nenhum byte foi transferido na operação de leitura ou escrita.
  - **Resolução:** Verificar se o tamanho solicitado era zero ou se a página foi descarregada no instante da chamada.

---

### Faixa 2000 - 2099: Driver Ring-0 (OwMemDriver)

- **Código 2001: `DriverNotConnected`**
  - **Causa:** O handle para o dispositivo de kernel `\\.\OwMemDriver` não está aberto na sessão atual. Ocorre quando o driver não foi instalado, não foi iniciado via `sc start` ou o executável não tem permissão para abrir o device object.
  - **Diagnóstico PT-BR:** Driver OwMemDriver não está conectado ou o dispositivo de kernel não pôde ser aberto.
  - **Resolução:** Verificar se o driver está instalado via `OwMemDriver.inf` e assinado em modo de teste, ou ativar o carregamento automático no menu de kernel.

- **Código 2002: `DriverConnectionFailed`**
  - **Causa:** Erro ao despachar a abertura do objeto de dispositivo com `CreateFileW`.
  - **Diagnóstico PT-BR:** Falha na conexão inicial com o dispositivo de driver Ring-0.
  - **Resolução:** Confirmar se o serviço do driver não foi travado por políticas de HVCI ou antivírus.

- **Código 2003: `DriverIoctlFailed`**
  - **Causa:** O despachante do driver (`DeviceIoControl`) retornou erro ou status de exceção não tratada ao processar o código de controle.
  - **Diagnóstico PT-BR:** Falha no despacho da requisição DeviceIoControl para o driver.
  - **Resolução:** Checar os códigos de retorno NTSTATUS gravados no log de depuração do kernel (DbgPrint).

- **Código 2004: `DriverPhysicalReadFailed`**
  - **Causa:** Falha do driver ao mapear ou ler endereços de memória física da RAM via `MmMapIoSpace` ou paginação direta.
  - **Diagnóstico PT-BR:** Falha na leitura de memória física pelo driver de kernel.
  - **Resolução:** Validar se o endereço físico fornecido existe na tabela de memória física do sistema operacional.

- **Código 2005: `DriverPhysicalWriteFailed`**
  - **Causa:** Falha do driver ao gravar diretamente em quadros físicos de memória RAM.
  - **Diagnóstico PT-BR:** Falha na gravação de memória física pelo driver de kernel.
  - **Resolução:** Checar se a página física não possui proteção a nível de hipervisor (SLAT/EPT).

- **Código 2006: `DriverCr3WalkFailed`**
  - **Causa:** O driver falhou ao caminhar pela estrutura hierárquica de tabelas de páginas x86_64 a partir do CR3 para traduzir um endereço virtual para físico.
  - **Diagnóstico PT-BR:** Falha ao traduzir endereço virtual para físico através da tabela CR3.
  - **Resolução:** O endereço virtual pode não estar mapeado no momento ou se encontrar em estado de swap.

- **Código 2007: `DriverObCallbackFailed`**
  - **Causa:** Erro ao tentar remover ou mascarar entradas na lista interna de `ObRegisterCallbacks` do `ntoskrnl.exe`.
  - **Diagnóstico PT-BR:** Falha ao expurgar callbacks de segurança de acesso a processos no kernel.
  - **Resolução:** Validar a compatibilidade dos offsets internos do kernel para a compilação atual do Windows 11.

- **Código 2008: `DriverPteManipulationFailed`**
  - **Causa:** Falha ao alterar diretamente bits de permissão de escrita em Page Table Entries (PTEs).
  - **Diagnóstico PT-BR:** Falha na manipulação direta de descritores de página (PTE) no kernel.
  - **Resolução:** Verificar se o recurso VBS/HVCI está ativo, impedindo gravação arbitrária em estruturas de paginação.

- **Código 2009: `DriverPpidbCacheCleanFailed`**
  - **Causa:** Falha ao localizar e expurgar vestígios do carregamento do driver na tabela `PiDDBCacheTable` do kernel.
  - **Diagnóstico PT-BR:** Falha na limpeza de vestígios de carregamento do driver na tabela PiDDBCacheTable.
  - **Resolução:** Atualizar a assinatura de varredura do padrão da tabela de drivers no binário do `ntoskrnl.exe`.

- **Código 2010: `DriverIntelPtUnsupported`**
  - **Causa:** O processador do sistema não oferece suporte às extensões de hardware do Intel Processor Trace (Intel PT) ou arquiteturas híbridas desabilitaram ToPA.
  - **Diagnóstico PT-BR:** Processador do computador não possui suporte a recursos de rastreamento por hardware Intel PT / Ultimap.
  - **Resolução:** Utilizar depuração por software (VEH ou PageGuard) em vez de Ultimap 2.

- **Código 2011: `DriverIntelPtInitFailed`**
  - **Causa:** Falha ao configurar registradores MSR específicos do Intel PT ou alocar os buffers ToPA no kernel.
  - **Diagnóstico PT-BR:** Falha na inicialização da sessão de hardware Intel PT no driver.
  - **Resolução:** Verificar se a virtualização VT-x/VT-d não está restringindo o uso de MSRs de telemetria.

- **Código 2012: `DriverIntelPtBufferOverflow`**
  - **Causa:** A taxa de geração de pacotes de execução pelo processador superou a velocidade de drenagem do buffer circular de telemetria.
  - **Diagnóstico PT-BR:** Transbordamento do buffer circular de rastreamento Intel PT.
  - **Resolução:** Aumentar o tamanho do buffer alocado ou aplicar filtros de intervalo de endereçamento (CR3 filtering).

- **Código 2013: `DriverVmxOffloadFailed`**
  - **Causa:** Falha ao despachar instruções de virtualização direta (VMX) a partir da camada de kernel.
  - **Diagnóstico PT-BR:** Falha no processamento de instruções VMX no driver.
  - **Resolução:** Confirmar suporte à virtualização aninhada na BIOS/UEFI.

- **Código 2014: `DriverHvciIncompatible`**
  - **Causa:** A Integridade de Código Protegida por Hipervisor (HVCI / Memory Integrity) do Windows 11 está ativa e bloqueou o driver ou suas operações de escrita direta.
  - **Diagnóstico PT-BR:** Incompatibilidade com as políticas de isolamento de memória HVCI ativas no Windows.
  - **Resolução:** Reconfigurar a política de isolamento do Windows Defender caso necessário para operações de teste.

- **Código 2015: `DriverDkomFailed`**
  - **Causa:** Falha na manipulação direta de objetos do kernel (Direct Kernel Object Manipulation) ao desvincular o módulo de drivers.
  - **Diagnóstico PT-BR:** Falha na desvinculação DKOM de estruturas internas do kernel.
  - **Resolução:** Atualizar os offsets de ponteiros da lista duplamente encadeada `PsLoadedModuleList`.

- **Código 2016: `DriverSeDebugGrantFailed`**
  - **Causa:** Falha ao injetar ou habilitar o privilégio `SeDebugPrivilege` no token primário do processo.
  - **Diagnóstico PT-BR:** Falha na concessão de privilégios de depuração SeDebugPrivilege ao processo.
  - **Resolução:** Iniciar a ferramenta através de uma conta com perfil de Administrador local.

---

### Faixa 3000 - 3099: Varredura de Memória & Ponteiros

- **Código 3001: `ScannerPatternParseFailed`**
  - **Causa:** A sequência de bytes (AOB) fornecida para busca possui sintaxe incorreta, caracteres inválidos ou tokens desconhecidos.
  - **Diagnóstico PT-BR:** Padrão AOB inválido fornecido para o motor de busca.
  - **Resolução:** Utilizar apenas pares hexadecimais (ex: `48 89 5C 24 ??`) e `?` ou `??` para curingas.

- **Código 3002: `ScannerInvalidDataType`**
  - **Causa:** Tentativa de varredura com tipo de dado numérico não suportado pelo motor.
  - **Diagnóstico PT-BR:** Tipo de dado numérico inválido ou incompatível na varredura.
  - **Resolução:** Selecionar um dos tipos padrão suportados: Int8, Int16, Int32, Int64, Float, Double, String ou AOB.

- **Código 3003: `ScannerBufferOverflow`**
  - **Causa:** A quantidade de resultados encontrados superou a capacidade configurada para a FoundList ou disco temporário.
  - **Diagnóstico PT-BR:** Limite de resultados de varredura excedido.
  - **Resolução:** Refinar as condições de busca na Primeira Varredura para reduzir a amostragem inicial.

- **Código 3004: `ScannerNoActiveScan`**
  - **Causa:** Acionamento de Próxima Varredura (`Next Scan`) sem que uma Primeira Varredura (`First Scan`) tenha sido concluída com sucesso.
  - **Diagnóstico PT-BR:** Nenhuma sessão de varredura ativa encontrada. Execute a Primeira Varredura antes da próxima.
  - **Resolução:** Executar uma Primeira Varredura com valores válidos antes de aplicar refinamentos.

- **Código 3005: `ScannerRegionQueryFailed`**
  - **Causa:** Falha ao consultar o mapa de memória do processo alvo durante a preparação dos intervalos de busca.
  - **Diagnóstico PT-BR:** Falha ao enumerar regiões de memória para a varredura.
  - **Resolução:** Validar se o handle do processo alvo permanece ativo e com permissões de consulta.

- **Código 3006: `ScannerFileSaveFailed`**
  - **Causa:** Falha ao gravar o arquivo temporário binário `ADDRESSES.TMP` no disco durante a finalização do lote de resultados.
  - **Diagnóstico PT-BR:** Falha na gravação do arquivo temporário de resultados no disco.
  - **Resolução:** Verificar espaço livre em disco e permissões de escrita na pasta temporária do executável.

- **Código 3007: `ScannerFileReadFailed`**
  - **Causa:** Falha ao abrir ou ler o arquivo `ADDRESSES.TMP` durante a recuperação de resultados pela FoundList da interface.
  - **Diagnóstico PT-BR:** Falha na leitura do arquivo de resultados temporários.
  - **Resolução:** Confirmar que nenhum outro processo bloqueou o arquivo temporário.

- **Código 3008: `PointerScannerAlreadyRunning`**
  - **Causa:** Tentativa de disparar uma nova rotina pesada de mineração de ponteiros enquanto uma busca já se encontra em execução ativa.
  - **Diagnóstico PT-BR:** O motor de varredura de ponteiros já está em execução nesta sessão.
  - **Resolução:** Aguardar a conclusão do processo atual ou cancelar a busca antes de iniciar outra.

- **Código 3009: `PointerScannerNotRunning`**
  - **Causa:** Tentativa de interromper ou ler status de busca de ponteiros sem que nenhuma rotina esteja ativa.
  - **Diagnóstico PT-BR:** Nenhuma sessão de busca de ponteiros está em execução no momento.
  - **Resolução:** Iniciar uma sessão de ponteiros antes de solicitar progresso.

- **Código 3010: `PointerChainBroken`**
  - **Causa:** Durante a resolução recursiva de uma cadeia multinível de ponteiros, um dos endereços intermediários apontou para memória descarregada, nula ou com valor ilegível.
  - **Diagnóstico PT-BR:** Cadeia de ponteiros interrompida no endereço especificado.
  - **Resolução:** Refazer a mineração de ponteiros com novas amostras ou atualizar os offsets para a versão atual do alvo.

- **Código 3011: `PointerMaxDepthExceeded`**
  - **Causa:** A busca atingiu o limite máximo estipulado de níveis de ponteiros (profundidade de saltos).
  - **Diagnóstico PT-BR:** Profundidade máxima de cadeia de ponteiros excedida na mineração.
  - **Resolução:** Aumentar a profundidade limite na configuração do Pointer Scanner.

- **Código 3012: `PointerInvalidTargetAddress`**
  - **Causa:** O endereço de destino fornecido para o cálculo da cadeia de ponteiros é nulo ou pertence a uma região não estática.
  - **Diagnóstico PT-BR:** Endereço alvo inválido para a resolução de cadeias de ponteiros.
  - **Resolução:** Informar o endereço exato da variável de interesse localizado na varredura de memória.

- **Código 3013: `PointerRescanDataMismatch`**
  - **Causa:** Durante a revarredura de ponteiros (`Pointer Rescan`), o mapa de memória gravado anteriormente divergiu de forma irreconciliável da instância atual do processo.
  - **Diagnóstico PT-BR:** Inconsistência de layout de memória detectada durante a revarredura de ponteiros.
  - **Resolução:** Realizar a revarredura apenas em instâncias com a mesma versão do binário e layout compatível.

- **Código 3014: `PointerMapEmpty`**
  - **Causa:** A estrutura de mapa de ponteiros não gerou nós durante o mapeamento inicial de páginas do alvo.
  - **Diagnóstico PT-BR:** O mapa de ponteiros gerado está vazio. Nenhuma relação de ponteiro encontrada nas regiões selecionadas.
  - **Resolução:** Expandir as regiões mapeadas para incluir seções de Heap e dados estáticos dos módulos.

---

### Faixa 4000 - 4099: Injeções, Detours & Engenharia PE

- **Código 4001: `InjectionDllNotFound`**
  - **Causa:** O arquivo binário da DLL fornecido para injeção não existe no caminho local nem nas pastas conhecidas (`bin/`, `modules/injections/`).
  - **Diagnóstico PT-BR:** Arquivo DLL para injeção não foi localizado no caminho indicado.
  - **Resolução:** Verificar se a compilação gerou o arquivo no diretório esperado e se o nome está correto.

- **Código 4002: `InjectionRemoteAllocFailed`**
  - **Causa:** Falha ao alocar o bloco de memória remota no processo alvo para abrigar a string de caminho da biblioteca.
  - **Diagnóstico PT-BR:** Falha na alocação de buffer remoto para receber os parâmetros da injeção.
  - **Resolução:** Validar se o processo alvo não possui limites rígidos de alocação de memória ou hooks anti-alocação.

- **Código 4003: `InjectionWritePathFailed`**
  - **Causa:** Falha na escrita dos bytes do caminho da DLL no buffer remoto recém-alocado.
  - **Diagnóstico PT-BR:** Falha ao gravar o caminho da DLL na memória do processo alvo.
  - **Resolução:** Checar se a proteção da página remota permite gravação (`PAGE_READWRITE`).

- **Código 4004: `InjectionThreadCreationFailed`**
  - **Causa:** A chamada ao Win32 `CreateRemoteThread` ou sequestro de thread remota foi interceptada ou recusada pelo sistema.
  - **Diagnóstico PT-BR:** Falha na criação da thread remota de inicialização no processo alvo.
  - **Resolução:** Utilizar métodos evasivos como Manual Mapping ou thread hijacking em vez de `CreateRemoteThread`.

- **Código 4005: `InjectionLoadLibraryFailed`**
  - **Causa:** O endereço do procedimento `LoadLibraryW` na `kernel32.dll` não pôde ser resolvido, ou o ponto de entrada da biblioteca injetada retornou código nulo.
  - **Diagnóstico PT-BR:** Falha na execução de LoadLibraryW no processo remoto. Verifique dependências ausentes da DLL.
  - **Resolução:** Inspecionar se a DLL possui dependências do Visual C++ Redistributable não instaladas no alvo.

- **Código 4006: `HookTrampolineFailed`**
  - **Causa:** O motor de detours falhou ao relocar instruções do prólogo da função alvo para o trampolim (ex: instrução RIP-relative que não pôde ser ampliada).
  - **Diagnóstico PT-BR:** Falha na geração do trampolim de desvio da função interceptada.
  - **Resolução:** Verificar o código da função alvo no desmontador para identificar instruções atípicas no prólogo.

- **Código 4007: `HookTargetTooSmall`**
  - **Causa:** O prólogo da função alvo contém menos de 5 bytes (ou 14 bytes para saltos absolutos de 64 bits) antes da primeira instrução de salto ou retorno, impossibilitando a inserção segura de um desvio JMP.
  - **Diagnóstico PT-BR:** Tamanho do prólogo da função é inferior ao espaço mínimo necessário para acomodar o desvio.
  - **Resolução:** Utilizar hooks por quebra de hardware (VEH Debugger) ou modificar o ponto de interceptação para uma instrução posterior.

- **Código 4008: `HookAlreadyInstalled`**
  - **Causa:** Tentativa de instalar um gancho em uma rotina que já possui um detour instalado no mesmo endereço.
  - **Diagnóstico PT-BR:** Já existe um hook ativo registrado no endereço especificado.
  - **Resolução:** Remover o hook existente antes de reinstalar uma nova versão.

- **Código 4009: `HookNotInstalled`**
  - **Causa:** Tentativa de desinstalar um hook em um endereço onde nenhuma interceptação estava registrada.
  - **Diagnóstico PT-BR:** Nenhum hook registrado foi localizado no endereço solicitado para remoção.
  - **Resolução:** Confirmar a tabela de hooks ativos antes de invocar a rotina de desinstalação.

- **Código 4010: `ManualMapInvalidPeHeader`**
  - **Causa:** O arquivo fornecido para injeção manual não é um executável portátil válido (assinatura `IMAGE_DOS_SIGNATURE` ou `IMAGE_NT_SIGNATURE` ausente ou corrompida).
  - **Diagnóstico PT-BR:** O arquivo não possui cabeçalhos PE válidos para execução de Manual Mapping.
  - **Resolução:** Recompilar o binário para gerar um arquivo PE x86_64 limpo.

- **Código 4011: `ManualMapRelocFailed`**
  - **Causa:** O motor de Manual Mapping falhou ao processar a tabela de relocação de base (`.reloc`) para o endereço remoto carregado.
  - **Diagnóstico PT-BR:** Falha na aplicação da tabela de relocações do binário mapeado.
  - **Resolução:** Assegurar que a biblioteca foi compilada com suporte a ASLR habilitado (`/DYNAMICBASE`).

- **Código 4012: `ManualMapImportResolveFailed`**
  - **Causa:** O motor de Manual Mapping não conseguiu resolver uma das funções dependentes listadas na Import Address Table (IAT) do binário.
  - **Diagnóstico PT-BR:** Falha ao resolver dependências de importação (IAT) da biblioteca mapeada.
  - **Resolução:** Checar se todas as DLLs exigidas pelo módulo estão carregadas no processo alvo.

- **Código 4013: `ManualMapTlsInitFailed`**
  - **Causa:** Falha na inicialização dos callbacks de Thread Local Storage (TLS) da biblioteca mapeada.
  - **Diagnóstico PT-BR:** Falha no processamento de callbacks TLS da biblioteca mapeada.
  - **Resolução:** Desabilitar a flag de chamada TLS ou revisar os inicializadores estáticos da DLL.

- **Código 4014: `ManualMapEntryExecutionFailed`**
  - **Causa:** A invocação remota do ponto de entrada `DllMain` (com `DLL_PROCESS_ATTACH`) retornou código falso (`0`) ou gerou uma exceção no alvo.
  - **Diagnóstico PT-BR:** O ponto de entrada DllMain do módulo mapeado retornou erro durante a inicialização.
  - **Resolução:** Depurar a rotina de inicialização da biblioteca mapeada para isolar eventuais falhas internas.

- **Código 4015: `PeStripSectionNotFound`**
  - **Causa:** O módulo de expurgo de PE não localizou a seção especificada para ser mascarada ou descartada.
  - **Diagnóstico PT-BR:** Seção PE indicada para remoção não foi encontrada na tabela de seções.
  - **Resolução:** Verificar a nomenclatura exata das seções PE no cabeçalho do arquivo.

- **Código 4016: `PeStripInvalidDosSignature`**
  - **Causa:** Falha ao expurgar o cabeçalho DOS devido a divergência no número mágico `MZ` (`0x5A4D`).
  - **Diagnóstico PT-BR:** Assinatura DOS (MZ) inválida ou corrompida no cabeçalho.
  - **Resolução:** Confirmar a integridade do arquivo antes de executar a sanitização de cabeçalhos.

- **Código 4017: `PeStripInvalidNtHeaders`**
  - **Causa:** Falha ao localizar os descritores NT (`PE\0\0`) durante o processo de expurgo de headers.
  - **Diagnóstico PT-BR:** Assinatura de cabeçalho NT (PE) inválida ou ausente.
  - **Resolução:** Validar se o binário não foi previamente comprimido ou corrompido por packers maliciosos.

- **Código 4018: `CallstackSpoofGadgetNotFound`**
  - **Causa:** O sintetizador de pilha de execução não encontrou gadgets válidos (`jmp rbx`, `call rsi`) nas bibliotecas legítimas do Windows (`kernel32.dll`, `ntdll.dll`).
  - **Diagnóstico PT-BR:** Gadgets necessários para o mascaramento de pilha (Callstack Spoofing) não foram encontrados.
  - **Resolução:** Atualizar a tabela de módulos confiáveis utilizados como fonte de gadgets de retorno.

- **Código 4019: `SyscallResolveFailed`**
  - **Causa:** O resolvedor dinâmico de syscalls não conseguiu extrair o número do System Service Call (SSN) dos stubs da `ntdll.dll` (provavelmente devido a hooks de terceiros).
  - **Diagnóstico PT-BR:** Falha ao resolver número da syscall (SSN) na memória do ntdll.
  - **Resolução:** Utilizar o resolvedor Halos Gate ou Tartarus Gate para deduzir o SSN por instruções vizinhas.

- **Código 4020: `SpeedhackInitFailed`**
  - **Causa:** Falha ao interceptar ou calibrar a frequência dos contadores de alta precisão do Windows.
  - **Diagnóstico PT-BR:** Falha na inicialização do modificador de velocidade temporal (Speedhack).
  - **Resolução:** Confirmar se o alvo suporta `QueryPerformanceCounter` sem proteções anti-tamper.

- **Código 4021: `AllochookFailed`**
  - **Causa:** Falha ao inicializar o hook interceptador de alocações de heap na biblioteca `allochook_dll.dll`.
  - **Diagnóstico PT-BR:** Falha na ativação da auditoria e intercepção de alocações de memória.
  - **Resolução:** Verificar permissões de escrita na seção de importação de heap da runtime C do processo.

---

### Faixa 5000 - 5099: Depurador de Hardware & VEH

- **Código 5001: `VehHandlerAlreadyRegistered`**
  - **Causa:** Tentativa de registrar um novo tratador de exceção vetorial quando o tratador global já está ativo.
  - **Diagnóstico PT-BR:** O tratador de exceção vetorial (VEH) já está registrado no processo.
  - **Resolução:** Desregistrar o tratador anterior antes de inicializar uma nova sessão.

- **Código 5002: `VehHandlerNotRegistered`**
  - **Causa:** Tentativa de remover o manipulador VEH sem que ele esteja ativo no sistema.
  - **Diagnóstico PT-BR:** Nenhum tratador de exceção vetorial (VEH) ativo para ser desregistrado.
  - **Resolução:** Garantir que o depurador VEH foi inicializado previamente.

- **Código 5003: `VehHwSlotUnavailable`**
  - **Causa:** Todos os 4 registradores de depuração de hardware da arquitetura x86_64 (`DR0`, `DR1`, `DR2`, `DR3`) já estão alocados com pontos de parada ativos.
  - **Diagnóstico PT-BR:** Todos os 4 registradores de hardware de depuração (DR0-DR3) estão ocupados.
  - **Resolução:** Remover um breakpoint de hardware inativo antes de solicitar um novo slot.

- **Código 5004: `VehHwSlotInvalid`**
  - **Causa:** Foi solicitado um índice de registrador de depuração fora do intervalo permitido de 0 a 3.
  - **Diagnóstico PT-BR:** Índice de registrador de depuração de hardware inválido.
  - **Resolução:** Utilizar apenas índices compreendidos entre 0 e 3.

- **Código 5005: `VehThreadContextFetchFailed`**
  - **Causa:** A chamada ao Win32 `GetThreadContext` falhou ao extrair o estado dos registradores de uma thread alvo.
  - **Diagnóstico PT-BR:** Falha ao obter o contexto dos registradores da thread remota.
  - **Resolução:** Assegurar que a thread alvo foi suspensa com `SuspendThread` antes de consultar o contexto.

- **Código 5006: `VehThreadContextSetFailed`**
  - **Causa:** A chamada ao Win32 `SetThreadContext` falhou ao gravar novos valores nos registradores de depuração da thread.
  - **Diagnóstico PT-BR:** Falha ao aplicar o novo contexto de registradores na thread remota.
  - **Resolução:** Requer permissões `THREAD_SET_CONTEXT` no handle da thread.

- **Código 5007: `PageGuardAllocationFailed`**
  - **Causa:** Falha na alocação da tabela interna de rastreamento de páginas vigiadas do depurador de software PageGuard.
  - **Diagnóstico PT-BR:** Falha ao alocar tabela de controle do depurador de proteção PageGuard.
  - **Resolução:** Checar recursos de memória livre no processo executor.

- **Código 5008: `PageGuardHandlerFailed`**
  - **Causa:** Erro no despachante de exceções de página do depurador de software PageGuard ao restaurar a proteção após um evento.
  - **Diagnóstico PT-BR:** Falha no tratamento de página vigiada do depurador PageGuard.
  - **Resolução:** Inspecionar o endereço da página na pilha de chamadas para verificar conflitos com o subsistema SEH.

- **Código 5009: `GdbServerBindFailed`**
  - **Causa:** O servidor embutido de depuração remota GDB não conseguiu vincular a porta TCP local (ex: porta já em uso por outro processo).
  - **Diagnóstico PT-BR:** Falha ao vincular a porta de escuta do servidor de depuração remota GDB.
  - **Resolução:** Escolher outra porta livre nas opções de rede ou encerrar a instância anterior do servidor GDB.

- **Código 5010: `GdbPacketParseError`**
  - **Causa:** O cliente GDB remoto enviou um pacote com formato malformado, checksum de integridade inválido ou comandos desconhecidos.
  - **Diagnóstico PT-BR:** Falha na análise de sintaxe ou integridade do pacote do protocolo GDB.
  - **Resolução:** Verificar a compatibilidade da versão do cliente GDB conectado ao OnyxEngine.

- **Código 5011: `DisasmInstructionFailed`**
  - **Causa:** O motor Zydis falhou ao decodificar os bytes na posição solicitada (bytes inválidos ou sequência de opcodes não pertencente à especificação x86_64).
  - **Diagnóstico PT-BR:** Falha ao desmontar instrução x86_64 no endereço indicado.
  - **Resolução:** Assegurar que o ponteiro desmontado aponta para o início exato de uma instrução executável.

---

### Faixa 6000 - 6099: Runtimes Gerenciados (Mono, .NET, Lua)

- **Código 6001: `MonoModuleNotFound`**
  - **Causa:** Nenhuma das bibliotecas conhecidas do runtime Mono (`mono-2.0-bdwgc.dll`, `mono.dll`, `UnityPlayer.dll`) foi encontrada na memória do alvo.
  - **Diagnóstico PT-BR:** Módulo de runtime Mono ou Unity não foi localizado no processo alvo.
  - **Resolução:** Certificar-se de que o aplicativo alvo é baseado em Unity/Mono e aguardar a inicialização do motor.

- **Código 6002: `MonoRootDomainFailed`**
  - **Causa:** A invocação da API exportada `mono_get_root_domain` retornou ponteiro nulo.
  - **Diagnóstico PT-BR:** Falha ao obter o domínio raiz (Root Domain) do runtime Mono.
  - **Resolução:** Aguardar a conclusão do carregamento do runtime Mono antes de iniciar a inspeção de classes.

- **Código 6003: `MonoThreadAttachFailed`**
  - **Causa:** Falha ao registrar a thread de inspeção no garbage collector do Mono com `mono_thread_attach`.
  - **Diagnóstico PT-BR:** Falha ao registrar thread de inspeção no runtime do Mono.
  - **Resolução:** Requer passagem de ponteiro de domínio válido para o anexador de thread.

- **Código 6004: `MonoAssemblyLoadFailed`**
  - **Causa:** Falha ao carregar um assembly gerenciado (`.dll`) no domínio do Mono.
  - **Diagnóstico PT-BR:** Falha ao carregar assembly gerenciado no domínio do Mono.
  - **Resolução:** Validar a compatibilidade da versão do assembly com o framework da aplicação alvo.

- **Código 6005: `MonoImageOpenFailed`**
  - **Causa:** A imagem executável interna do assembly gerenciado retornou ponteiro corrompido ao ser aberta.
  - **Diagnóstico PT-BR:** Falha ao abrir imagem de metadados do assembly Mono.
  - **Resolução:** Confirmar a integridade do arquivo gerenciado em disco.

- **Código 6006: `MonoClassLookupFailed`**
  - **Causa:** A classe gerenciada solicitada por namespace e nome não existe na imagem carregada.
  - **Diagnóstico PT-BR:** Classe gerenciada não encontrada no namespace informado do Mono.
  - **Resolução:** Verificar a grafia exata de maiúsculas e minúsculas no namespace e no nome da classe.

- **Código 6007: `MonoMethodLookupFailed`**
  - **Causa:** O método solicitado não foi localizado dentro da classe informada.
  - **Diagnóstico PT-BR:** Método gerenciado não foi localizado na classe do Mono.
  - **Resolução:** Confirmar o nome e a contagem de parâmetros do método pretendido.

- **Código 6008: `MonoCompileFailed`**
  - **Causa:** O compilador JIT do Mono (`mono_compile_method`) falhou ao compilar o método intermediário (CIL) para código de máquina nativo x86_64.
  - **Diagnóstico PT-BR:** Falha na compilação JIT do método gerenciado para código nativo.
  - **Resolução:** Confirmar se o método não possui restrições de genéricos abstratos não instanciados.

- **Código 6009: `DotNetRuntimeNotFound`**
  - **Causa:** O processo alvo não carrega os módulos centrais do CLR da Microsoft (`clr.dll` ou `coreclr.dll`).
  - **Diagnóstico PT-BR:** Runtime .NET CLR não foi detectado no processo alvo.
  - **Resolução:** Validar se o aplicativo alvo é verdadeiramente baseado em tecnologias .NET da Microsoft.

- **Código 6010: `DotNetClrtypeNotFound`**
  - **Causa:** Falha ao consultar tipos de dados e metadados no repositório de tipos do CLR.
  - **Diagnóstico PT-BR:** Tipo de dado ou classe .NET não localizada nos metadados do CLR.
  - **Resolução:** Atualizar a enumeração de módulos gerenciados do processo alvo.

- **Código 6011: `LuaScriptExecutionError`**
  - **Causa:** O motor de scripts Lua encontrou um erro em tempo de execução ao executar um comando no console ou na tabela de endereços do OnyxEngine.
  - **Diagnóstico PT-BR:** Erro na execução do script de automação Lua.
  - **Resolução:** Inspecionar o log de rastreamento do erro e corrigir a lógica do script.

- **Código 6012: `LuaSyntaxError`**
  - **Causa:** O script Lua fornecido para compilação possui erros gramaticais ou sintaxe inválida.
  - **Diagnóstico PT-BR:** Erro de sintaxe na compilação do script Lua.
  - **Resolução:** Validar os delimitadores de blocos e declarações de variáveis do script.

---

### Faixa 7000 - 7099: Plugins & Extensões

- **Código 7001: `PluginNotFound`**
  - **Causa:** A extensão de plugin solicitada não existe na pasta `bin/plugins/` ou não pôde ser carregada pelo Windows via `LoadLibraryW`.
  - **Diagnóstico PT-BR:** Biblioteca de plugin dinâmico não foi encontrada no disco.
  - **Resolução:** Certificar-se de que a DLL do plugin reside na pasta `plugins/` e possui todas as dependências requeridas.

- **Código 7002: `PluginInvalidExport`**
  - **Causa:** O plugin carregado não expõe os pontos de entrada obrigatórios da API de extensões do OnyxEngine (`OnyxPlugin_GetInfo`, `OnyxPlugin_Init`).
  - **Diagnóstico PT-BR:** O plugin carregado não expõe os pontos de exportação exigidos pela especificação.
  - **Resolução:** Recompilar o plugin garantindo a exportação correta das rotinas em conformidade com a convenção de chamada de plugins.

- **Código 7003: `PluginInitFailed`**
  - **Causa:** A rotina `OnyxPlugin_Init` da extensão retornou código de falha durante o estabelecimento da ponte com a API do host.
  - **Diagnóstico PT-BR:** Falha na inicialização interna do plugin dinâmico.
  - **Resolução:** Analisar as mensagens de log emitidas pela extensão durante o carregamento inicial.

- **Código 7004: `AobToolSignatureGenerationFailed`**
  - **Causa:** O plugin `onyx_aob_tool` não conseguiu gerar uma assinatura única a partir das instruções fornecidas (instruções curtas demais ou comuns a muitas funções do executável).
  - **Diagnóstico PT-BR:** Não foi possível gerar uma assinatura AOB exclusiva para o bloco de instruções selecionado.
  - **Resolução:** Aumentar o número de instruções analisadas para garantir exclusividade do padrão de bytes.

- **Código 7005: `AobToolMaskLengthMismatch`**
  - **Causa:** A máscara de bytes gerada pelo validador AOB possui comprimento divergente da sequência de bytes alvo.
  - **Diagnóstico PT-BR:** Divergência de comprimento entre a sequência de bytes e a máscara da assinatura.
  - **Resolução:** Recalcular a máscara para que coincida exatamente com o número de bytes do padrão.

- **Código 7006: `DllMapperInvalidImage`**
  - **Causa:** A imagem binária carregada pelo plugin `onyx_dll_mapper` está corrompida ou não é compatível com o alvo x86_64.
  - **Diagnóstico PT-BR:** Imagem da biblioteca fornecida para Manual Mapping é inválida.
  - **Resolução:** Verificar a integridade do arquivo compilado.

- **Código 7007: `DllMapperSectionMappingFailed`**
  - **Causa:** Falha ao mapear seções individuais da biblioteca no espaço de endereçamento remoto do processo alvo.
  - **Diagnóstico PT-BR:** Falha no mapeamento das seções PE da biblioteca no processo remoto.
  - **Resolução:** Validar se a proteção de memória do processo alvo permite a criação de seções executáveis.

- **Código 7008: `DllMapperTlsFailed`**
  - **Causa:** Falha na alocação ou inicialização dos diretórios de dados estáticos de TLS da biblioteca pelo injetor manual.
  - **Diagnóstico PT-BR:** Falha na inicialização de descritores TLS no Manual Mapper.
  - **Resolução:** Revisar o suporte do módulo mapeado a inicializadores estáticos em tempo de execução.
