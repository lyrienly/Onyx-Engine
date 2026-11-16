# Runtimes Gerenciados Mono, Unity e .NET CLR

## 1. Visão Geral

Grande parte das aplicações contemporâneas é desenvolvida sobre motores como **Unity** ou frameworks **.NET (C# / F#)**. Em processos gerenciados, o código executável não reside estaticamente em arquivos binários compilados diretamente para código de máquina; em vez disso, ele é empacotado em bytecode intermediário (CIL - Common Intermediate Language) e compilado dinamicamente para código nativo em tempo de execução (**JIT - Just-In-Time Compilation**).

O OnyxEngine possui módulos nativos dedicados à instrumentação de runtimes gerenciados:
* **`onyx_mono.dll`**: Inspetor de runtimes Mono Classic e Unity Engine.
* **`onyx_mono_hook.dll`**: Interceptador de compilação JIT de métodos Unity em tempo real.
* **`onyx_dotnet.dll`**: Inspetor de runtimes .NET Framework (CLR 2.0 a 4.8) e .NET Core / .NET 5 a 9 (CoreCLR).

---

## 2. Inspeção de Runtimes Mono / Unity (`onyx_mono.dll`)

Em aplicações Unity que utilizam a backend Mono (`mono.dll` ou `mono-2.0-bdwgc.dll`), o `onyx_mono.dll` conecta-se às estruturas internas do runtime gerenciado exportadas pelo processo:

```text
+---------------------------------------------------------------------------------+
|                       1. Localização e Conexão ao Runtime                       |
|   Identifica mono.dll / mono-2.0-bdwgc.dll e resolve exports C-ABI              |
|   Invocação de mono_get_root_domain() e mono_thread_attach()                    |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                      2. Enumeração de Assemblies e Classes                      |
|   mono_assembly_foreach() -> Lista Assembly-CSharp.dll, UnityEngine.dll         |
|   mono_image_get_table_rows() -> Mapeia classes, namespaces e heranças          |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                        3. Mapeamento de Métodos e Campos                        |
|   mono_class_get_methods() -> Nomes de funções, parâmetros e tipos de retorno   |
|   mono_class_get_fields()  -> Deslocamentos de variáveis de membros de classe   |
+---------------------------------------------------------------------------------+
```

### 2.1 Identificação Automática de Campos de Classe
O módulo inspeciona classes como `PlayerController`, retornando a tabela exata de offsets sem que o operador precise abrir um descompilador externo:
```text
Classe: Assembly-CSharp.PlayerController
  [0x18] m_Health : System.Int32
  [0x1C] m_MaxHealth : System.Int32
  [0x20] m_MovementSpeed : System.Single
  [0x28] m_Inventory : InventoryManager
```

---

## 3. Hook de Métodos JIT em Tempo Real (`onyx_mono_hook.dll`)

Em runtimes JIT, o código de máquina de uma função só existe na memória após o método ser executado pela primeira vez. Se um hook tradicional for colocado antes da compilação JIT, o processo causará um *crash* porque o endereço aponta apenas para uma estrutura interna de metadados do Mono (`MonoMethod`).

O **`onyx_mono_hook.dll`** resolve essa questão:
1. Intercepta a própria função do compilador JIT do Mono (`mono_compile_method`).
2. Aguarda a finalização da compilação legítima do método.
3. No instante exato em que o ponteiro nativo de código de máquina é gerado, instala o detour sem interromper o pipeline de execução da engine Unity.

---

## 4. Instrumentação de .NET Moderno e CoreCLR (`onyx_dotnet.dll`)

Para aplicações e softwares que utilizam .NET Framework moderno ou .NET Core 6/7/8/9:
- O módulo localiza as bibliotecas de execução `clr.dll` ou `coreclr.dll`.
- Utiliza a biblioteca auxiliar de acesso a dados do compilador (**DAC - Data Access Component** / `mscordacwks.dll`).
- Percorre a tabela de métodos (**MethodTable**) e o objeto **EEClass** para mapear instâncias ativas no garbage collector (GC Heap), permitindo rastrear objetos vivos sem que os ponteiros fiquem obsoletos após coletas de lixo do .NET.
