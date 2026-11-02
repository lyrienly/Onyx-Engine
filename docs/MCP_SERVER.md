# Servidor Nativo MCP (Model Context Protocol) do OnyxEngine

## 1. Visão Geral

O OnyxEngine possui uma implementação nativa de alto desempenho do **Model Context Protocol (MCP)** desenvolvida em Rust. Diferente de pontes legadas baseadas em scripts Python ou interpretadores externos, o servidor MCP do OnyxEngine é compilado diretamente como uma biblioteca modular (`onyx_mcp.dll`) e como um executável de comunicação por standard I/O (`onyx_mcp_server.exe`).

O servidor permite que agentes autônomos de Inteligência Artificial (Antigravity, Claude Desktop, Cursor, OpenAI Agents ou ferramentas proprietárias) inspecionem, controlem e modifiquem a memória de qualquer processo do Windows em tempo de execução via protocolo JSON-RPC 2.0 padrão, cobrindo **100% das funções do engine**, inclusive os plugins nativos, o driver Ring-0, scanners, desmontadores e descompiladores gerenciados.

---

## 2. Métodos de Execução e Arquitetura

O subsistema MCP opera sob dois modos de inicialização:

1. **Modo Executável Stdio (`bin/onyx_mcp_server.exe`):**
   - Utilizado para integração com assistentes de IA que inicializam subprocessos locais.
   - Lê requisições JSON-RPC linha a linha de `stdin` e responde via `stdout` com garantia de terminação de linha em `\n` (evitando corrupção de fluxo no Windows).
   - Suporta flags de linha de comando: `--manifest` (exibe todas as 49 ferramentas em JSON) e `--version`.
   - Não requer Python, pip, ou bibliotecas de terceiros instaladas na máquina host.

2. **Modo Biblioteca Dinâmica (`bin/onyx_mcp.dll`):**
   - Pode ser carregada em tempo de execução pelo executável principal `OnyxEngine-CE.exe` ou injetada em processos.
   - Expõe funções C-ABI para despacho direto de payloads JSON na memória (`onyx_mcp_dispatch_json`) e execução em thread separada de I/O (`onyx_mcp_start_stdio_thread`).

---

## 3. Catálogo de Ferramentas Nativas para IA (49 Ferramentas)

### A. Controle e Diagnóstico de Processo
- `process_list`: Lista todos os processos ativos no sistema operacional com PID, nome e contagem de threads.
- `attach_process`: Seleciona e anexa ao processo alvo para controle de memória, scans e plugins. Aceita PID numérico ou nome do executável.
- `detach_process`: Desconecta e libera o descritor do processo atualmente anexado.
- `process_info`: Retorna detalhes técnicos do processo ativo (PID, modo de acesso NtApi/KernelDbk, base e badges).
- `process_modules`: Enumera todas as DLLs e módulos carregados no processo alvo (nome, base, tamanho e caminho).
- `process_threads`: Lista todas as threads do processo com seus Thread IDs (TID).
- `process_suspend`: Suspende a execução de todas as threads do processo alvo.
- `process_resume`: Resume a execução das threads suspensas do processo alvo.

### B. Leitura, Escrita e Alocação de Memória
- `memory_read`: Lê bytes ou tipos interpretados da memória do processo (`i8`, `u8`, `i16`, `u16`, `i32`, `u32`, `i64`, `u64`, `float`, `double`, `string_utf8`, `string_utf16`, `pointer`).
- `memory_write`: Grava bytes ou valores na memória do processo alvo com ajuste automático de proteção de página VirtualProtect.
- `memory_alloc`: Aloca uma nova região de memória virtual privada no processo (VirtualAllocEx) com proteção PAGE_EXECUTE_READWRITE.
- `memory_free`: Libera uma página de memória alocada via VirtualFreeEx.
- `memory_protect`: Altera as permissões de proteção de uma região de memória virtual (VirtualProtectEx).
- `memory_query_regions`: Mapeia e lista as regiões de memória virtual (VAD / VirtualQueryEx) do processo alvo.

### C. Varredura de Memória (Cheat Engine Scanner)
- `scanner_first_scan`: Executa a primeira varredura de memória (Exact, AOB, Float, String) em threads paralelas.
- `scanner_next_scan`: Filtra os resultados da varredura anterior com nova condição (Exact, Increased, Decreased, Changed, Unchanged).
- `scanner_get_results`: Retorna a lista de endereços e valores encontrados na varredura ativa.
- `scanner_reset`: Reinicia o scanner e limpa a tabela de resultados.

### D. Varredura e Resolução de Ponteiros
- `pointer_resolve_chain`: Percorre uma cadeia de ponteiros multi-nível (Base + Deslocamentos) e retorna o endereço resolvido final.
- `pointer_scan`: Varredura reversa de ponteiros multi-nível para encontrar caminhos estáveis até o endereço alvo.

### E. Scripting AutoAssembler
- `aa_validate_script`: Valida sintaxe e semântica de script AutoAssembler do Cheat Engine (`[ENABLE]`, `[DISABLE]`, `alloc`, `registersymbol`).
- `aa_execute_script`: Compila e executa script AutoAssembler aplicando hooks, alocações de memória e patches no processo.

### F. Congelamento de Valores (Memory Freezer)
- `freeze_address`: Congela um endereço de memória para que seu valor permaneça fixo em background (intervalo de 50ms).
- `unfreeze_address`: Descongela o endereço especificado, interrompendo a rotina de travamento de memória.
- `freeze_list`: Lista todos os endereços atualmente congelados pelo mecanismo de memória.

### G. Desmontagem e Montagem de Código
- `disassemble`: Desmonta instruções de máquina x86/x64 no endereço especificado usando o engine nativo Zydis.
- `assemble_instruction`: Monta instrução x86/x64 em bytes de código de máquina opcodes (ex: `mov eax, 100`).

### H. Engenharia Reversa e Análise de Estruturas
- `dissect_structure`: Disseca estrutura de dados em memória, identificando ponteiros, vtables, inteiros, floats, strings e coleções Unreal.
- `find_rop_gadgets`: Localiza gadgets ROP úteis em módulos executáveis (`ret`, `pop reg; ret`, `syscall`, `jmp reg`).
- `find_string_references`: Localiza referências a strings literais ASCII e UTF-16 no código executável.
- `dissect_code_branches`: Mapeia grafo de saltos, chamadas de função, retornos e limites de funções em um bloco de código.

### I. Runtimes Mono, Unity e .NET CLR
- `mono_detect_runtime`: Detecta a presença de runtime Mono Classic, Unity IL2CPP ou UnityPlayer no processo alvo.
- `mono_enum_assemblies`: Enumera assemblies gerenciados carregados pelo runtime Mono/Unity no processo.
- `mono_method_hook_script`: Gera script AutoAssembler pronto para interceptar e modificar um método do Mono/Unity.
- `dotnet_detect_runtime`: Detecta versão do runtime .NET Framework (CLR 2.0-4.x) ou .NET Core (CoreCLR 5.0-9.0).
- `dotnet_enum_modules`: Enumera todos os módulos .NET gerenciados carregados no processo.

### J. Plugins Nativos
- `plugin_aob_validate`: Executa plugin nativo SigMaker para validar padrão AOB em módulos carregados e checar unicidade.
- `plugin_aob_generate`: Executa plugin nativo SigMaker para gerar assinatura AOB única com wildcards a partir de um endereço de função.
- `plugin_dll_manual_map`: Injeta DLL via manual mapping furtivo (sem LoadLibrary, limpando cabeçalhos PE, TLS callbacks e hijacking).

### K. Driver Ring-0 de Kernel (OnyxDriver / OwMemDriver)
- `kernel_connect`: Estabelece conexão direta com o driver Ring-0 OnyxDriver / OwMemDriver.
- `kernel_read_cr3`: Lê memória física direta do processo através da tradução de tabela de páginas CR3 em Ring-0.
- `kernel_write_cr3`: Grava na memória física direta através de Ring-0 contornando proteções virtuais de página.
- `kernel_strip_callbacks`: Desvincula callbacks ObRegisterCallbacks de processo/thread no kernel para cegar anticheats e EDRs.
- `kernel_hide_process`: Oculta o processo alvo via Direct Kernel Object Manipulation (DKOM) desvinculando de ActiveProcessLinks.

### L. Injeção e Manipulação de Clock
- `inject_dll`: Injeta uma DLL no processo alvo via CreateRemoteThread + LoadLibraryW.
- `speedhack_set_speed`: Ativa e ajusta a velocidade do jogo/processo alvo através do multiplicador de tempo do speedhack.

### M. Diagnóstico e Sistema
- `system_get_last_error`: Retorna o código do último erro diagnosticado pelo OnyxEngine acompanhado da mensagem explicativa no idioma ativo (PT-BR).
- `system_set_locale`: Configura o idioma de diagnóstico das mensagens de erro (`pt_BR`, `en_US`).
- `system_capabilities`: Relatório completo de todas as 25 bibliotecas modulares, plugins nativos e recursos ativos no OnyxEngine.

---

## 4. Configuração para Ambientes de Inteligência Artificial

### 4.1 Integração com Claude Desktop
Adicione ao arquivo `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "onyx_engine": {
      "command": "C:\\Users\\Administrator\\Desktop\\OnyxEngine\\bin\\onyx_mcp_server.exe",
      "args": []
    }
  }
}
```

### 4.2 Integração com Antigravity / Cursor
No arquivo `onyx_mcp_config.json` ou nas configurações do Cursor MCP:

```json
{
  "mcpServers": {
    "onyx_engine": {
      "command": "C:\\Users\\Administrator\\Desktop\\OnyxEngine\\bin\\onyx_mcp_server.exe",
      "transport": "stdio"
    }
  }
}
```
