# Tutorial Prático: Engenharia Reversa e Instrumentação de Processos do Zero

## 1. Objetivo do Tutorial

Este tutorial prático guia o desenvolvedor passo a passo pelo ciclo completo de engenharia reversa de um processo em x86_64 utilizando o OnyxEngine:
1. **Anexação ao processo alvo**
2. **Localização do endereço dinâmico de recurso (`m_StateCounter`)**
3. **Identificação da instrução assembly que modifica a variável**
4. **Resolução de ponteiro estável via Pointer Scanner**
5. **Criação de um script AutoAssembler para Interceptação e Trava de Valor**
6. **Automação remota da instrumentação via Servidor Nativo MCP**

---

## 2. Passo 1: Anexação ao Processo Alvo

Abra o **OnyxEngine-CE.exe** como Administrador:
1. Clique no ícone do monitor no canto superior esquerdo (**Process Picker**).
2. Localize o processo alvo na lista (ex: `target_app.exe`) e confirme em **Open**.
3. O título da janela passará a exibir `OnyxEngine (Admin) - target_app.exe`.

Alternativamente, via servidor MCP:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "attach_process",
  "params": {
    "process": "target_app.exe"
  }
}
```

---

## 3. Passo 2: Localizando o Endereço de Recurso na Memória

1. Na aplicação, observe o valor atual do contador de estado (ex: **100**).
2. No painel de varredura do OnyxEngine:
   - **Value Type**: `4 Bytes`
   - **Scan Type**: `Exact Value`
   - **Value**: `100`
   - Clique em **First Scan**.
   - O motor SIMD paralelizado varrerá toda a memória em milissegundos, retornando milhares de endereços com valor 100.
3. Volte à aplicação e acione o evento que altera o valor (o contador cai para **75**).
4. No OnyxEngine:
   - Digite `75` no campo de valor.
   - Clique em **Next Scan**.
   - O motor descartará todos os endereços que não sofreram a mesma alteração.
5. Repita o processo mais uma vez (ex: o valor cai para **50** -> Next Scan com `50`).
6. Restará apenas **1 endereço**, por exemplo: `0x1B840A20`. Dê duplo clique para adicioná-lo à tabela de endereços.

---

## 4. Passo 3: Descobrindo o que Escreve no Endereço (*Find What Writes*)

O endereço `0x1B840A20` é dinâmico e deixará de existir quando a aplicação for encerrada. Precisamos encontrar a **instrução de código de máquina** que reduz a vida quando sofremos dano:

1. Clique com o botão direito no endereço salvo na tabela e selecione:
   **"Find out what writes to this address"** (ou pressione `F6`).
2. O OnyxEngine aciona o depurador por hardware via **VEH (`vehdebug_dll.dll`)**, configurando o registrador `DR0` da CPU para monitorar gravações de memória sem abrir sessões de debug detectáveis pelo processo alvo.
3. Volte à aplicação e acione a alteração de valor novamente.
4. A janela do depurador captura instantaneamente a instrução responsável:
   ```assembly
   0x7FFA2045A120 - 29 43 44 - sub [rbx+44], eax
   ```
5. **Análise da Instrução**:
   - `sub`: Instrução de subtração.
   - `eax`: Quantidade subtraída da variável.
   - `rbx`: Ponteiro base da estrutura principal de contexto (`MainContext`).
   - `+44`: Deslocamento (*offset*) em hexadecimal onde a variável de recurso reside dentro da classe.

---

## 5. Passo 4: Encontrando o Ponteiro Estático via Pointer Scanner

Sabendo que o offset da variável é `0x44`, precisamos descobrir qual ponteiro estático carrega o endereço da estrutura contido em `rbx`:

1. Clique com o botão direito no endereço da variável na tabela e selecione **"Generate pointermap"**.
2. Salve o arquivo como `map1.scandata`. O `onyx_pointer.dll` varre toda a memória e cataloga todos os ponteiros do processo.
3. Clique em **"Pointer scan for this address"** -> selecione `map1.scandata` -> Profundidade máxima: `5`, Offset máximo: `2048` (`0x800`).
4. O scanner encontra milhares de caminhos potenciais.
5. **O Passo Crucial do Rescan**:
   - Reinicie a aplicação alvo (o ASLR remapeará os endereços).
   - Repita o Passo 2 para achar o novo endereço do recurso na nova sessão (ex: agora é `0x24C09120`).
   - Na janela do Pointer Scanner, clique em **Pointer Scanner -> Rescan memory**.
   - Digite o novo endereço `0x24C09120`.
   - O algoritmo de poda do `onyx_pointer.dll` elimina todas as cadeias quebradas, restando a cadeia estável e verdadeira:
   ```text
   "target_app.exe" + 0x002F8400 -> Offset: 0x44
   ```

---

## 6. Passo 5: Criando o Script AutoAssembler para Fixação de Valor

Com a instrução de decremento localizada (`0x7FFA2045A120`), vamos criar um patch de injeção de código (*Code Cave*):

1. No menu principal, vá em **Tools -> Auto Assemble** (ou pressione `Ctrl + A`).
2. Vá em **Template -> AOB Injection**. O OnyxEngine gera a estrutura automática:

```assembly
[ENABLE]
aobscanmodule(INJECT_RESOURCE, target_app.exe, 29 43 44 48 8B 4B 50)
alloc(newmem, 1024, INJECT_RESOURCE)
label(code)
label(return)

newmem:
code:
  // Em vez de subtrair o valor (sub [rbx+44], eax), travamos a variável no valor estável 100:
  mov dword ptr [rbx+44], #100
  jmp return

INJECT_RESOURCE:
  jmp code
return:
registersymbol(INJECT_RESOURCE)

[DISABLE]
INJECT_RESOURCE:
  // Restaura os bytes originais de subtração
  db 29 43 44
unregistersymbol(INJECT_RESOURCE)
dealloc(newmem)
```

3. Clique em **File -> Assign to current address table**.
4. Agora basta marcar a caixa de seleção na tabela para ativar a trava do recurso instantaneamente.

---

## 7. Passo 6: Automação Total via Servidor MCP

Qualquer agente de Inteligência Artificial ou script externo pode replicar todo esse processo remotamente enviando requisições JSON-RPC ao `onyx_mcp_server.exe`:

```python
import json, subprocess

# Inicializa o processo do servidor MCP nativo
p = subprocess.Popen(
    [r"C:\Users\Administrator\Desktop\OnyxEngine\bin\onyx_mcp_server.exe"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    text=True
)

def send_rpc(method, params={}):
    req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}) + "\n"
    p.stdin.write(req)
    p.stdin.flush()
    return json.loads(p.stdout.readline())

# 1. Anexa à aplicação alvo
send_rpc("attach_process", {"process": "target_app.exe"})

# 2. Resolve a cadeia de ponteiros e descobre o endereço de memória atual
res = send_rpc("pointer_resolve_chain", {
    "base_module": "target_app.exe",
    "base_offset": 0x2F8400,
    "offsets": [0x44]
})
resource_addr = res["result"]["final_address"]

# 3. Congela o contador em 9999 permanentemente
send_rpc("freeze_address", {
    "address": resource_addr,
    "value_type": "i32",
    "value": 9999
})

print("Trava de valor ativada com sucesso via OnyxEngine MCP!")
```
