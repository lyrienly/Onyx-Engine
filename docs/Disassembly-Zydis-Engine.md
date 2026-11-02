# Motor de Desmontagem Zydis e Compilador AutoAssembler

## 1. Visão Geral

A engenharia reversa e a criação de patches em tempo real no OnyxEngine são sustentadas por dois módulos centrais escritos em Rust:
* **`onyx_disasm.dll`**: Motor de desmontagem de instruções de máquina x86 e x86_64 de ultra-alta velocidade baseado no decodificador **Zydis**.
* **`onyx_aa.dll`**: Compilador JIT de scripts de montagem de dois passos (**AutoAssembler**), compatível com a sintaxe clássica do Cheat Engine, capaz de alocar code caves, resolver símbolos e injetar trampolins em tempo de execução.

---

## 2. Decodificação e Análise com Zydis (`onyx_disasm.dll`)

Diferente de desmontadores legados mais lentos, o `onyx_disasm.dll` analisa opcodes de instruções em nanossegundos, extraindo metadados essenciais para criação automática de hooks:

### 2.1 Resolução de Endereçamento Relativo ao RIP
No conjunto de instruções x86_64, a maioria das referências a variáveis estáticas e tabelas de ponteiros utiliza o registrador de instrução relativa:
`mov rax, [rip + 0x123456]`

O `onyx_disasm` calcula automaticamente o endereço absoluto final em tempo de desmontagem:

$$\text{EndereçoEfetivo} = \text{EndereçoInstrução} + \text{TamanhoInstrução} + \text{DeslocamentoRIP}$$

Exemplo de saída formatada:
```text
0x00007FFA10203040: 48 8B 05 59 12 00 00   mov rax, [rip + 0x1259]   ; -> 0x00007FFA102042A0 (g_PlayerManager)
0x00007FFA10203047: 48 85 C0               test rax, rax
0x00007FFA1020304A: 74 15                  jz 0x00007FFA10203061
```

### 2.2 Análise de Blocos Básicos e Grafos de Fluxo (CFG)
O motor percorre instruções sequenciais identificando instruções de desvio incondicional (`jmp`), condicional (`je`, `jne`, `jg`, `jl`), chamadas de função (`call`) e retornos (`ret`), mapeando o início e fim de rotinas para prevenir que hooks quebrem o alinhamento de prólogos.

---

## 3. O Compilador AutoAssembler (`onyx_aa.dll`)

O **AutoAssembler** é o padrão da indústria para criação de trainers e modificações de código na memória de jogos. Um script é composto por seções de ativação (`[ENABLE]`) e desativação (`[DISABLE]`), garantindo que qualquer alteração possa ser desfeita de forma limpa.

### 3.1 Exemplo de Script de Hook (Detour Code Cave)

```assembly
[ENABLE]
// Aloca 1024 bytes de memória executável próxima ao módulo alvo
alloc(newmem, 1024, "game.exe"+0x45A120)
label(returnhere)
label(originalcode)

// Registra o símbolo globalmente para uso por outros scripts
registersymbol(newmem)

newmem:
  // Lógica customizada: vida infinita (fixa em 9999)
  mov dword ptr [rbx+0x44], #9999

originalcode:
  // Executa as instruções originais que foram sobrescritas pelo hook
  mov eax, [rbx+0x44]
  jmp returnhere

"game.exe"+0x45A120:
  // Salto para o code cave criado
  jmp newmem
returnhere:

[DISABLE]
// Restaura os bytes originais da função
"game.exe"+0x45A120:
  mov eax, [rbx+0x44]

// Libera a memória alocada e limpa símbolos
dealloc(newmem)
unregistersymbol(newmem)
```

### 3.2 O Processo de Compilação em 2 Passos
1. **Passo 1 (Cálculo de Símbolos e Tamanhos)**:
   - Lê todas as declarações `alloc`, `label`, `registersymbol` e calcula quantos bytes cada instrução assembly ocupará na memória.
   - Determina se o salto `jmp newmem` necessita de um salto curto relativo de 5 bytes (`jmp rel32`) ou um salto longo de 14 bytes (`jmp [rip+0] / 0xFF 0x25`).
2. **Passo 2 (Montagem Binária e Gravação)**:
   - Resolve todos os rótulos (*labels*) para seus endereços numéricos finais.
   - Gera os opcodes binários e grava os bytes atômicos na memória virtual do processo alvo via `WriteProcessMemory` ou `OwMemDriver.sys`.
