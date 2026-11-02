# Engenharia Reversa de Unreal Engine 4 & 5 com OnyxEngine

## 1. Visão Geral do Modelo de Objetos da Unreal Engine

Jogos desenvolvidos sobre a **Unreal Engine (UE4 / UE5)** compartilham uma arquitetura padronizada de reflexão de objetos baseada na classe fundamental `UObject`. Compreendendo a disposição das estruturas mestras em memória, o OnyxEngine permite navegar por todo o grafo de entidades do jogo (jogadores, inimigos, armas, veículos, projéteis e coordenadas 3D) de forma totalmente genérica.

```text
                               +-------------------+
                               |     UWorld        |
                               +-------------------+
                                         |
                                         v
                         +-------------------------------+
                         |         UGameInstance         |
                         +-------------------------------+
                                         |
                                         v
                         +-------------------------------+
                         |          ULocalPlayer         |
                         +-------------------------------+
                                         |
                                         v
                         +-------------------------------+
                         |       APlayerController       |
                         +-------------------------------+
                                         |
                       +-----------------+-----------------+
                       |                                   |
                       v                                   v
        +-----------------------------+     +-----------------------------+
        |     APawn / ACharacter      |     |         APlayerCamera       |
        |   (Entidade do Jogador)     |     |   (Matriz ViewProjection)   |
        +-----------------------------+     +-----------------------------+
                       |
                       v
        +-----------------------------+
        |    USkeletalMeshComponent   |
        |  (Matriz de Ossos e Esqueleto)|
        +-----------------------------+
```

---

## 2. As Estruturas Globais Centrais

### 2.1 `GObjects` (`TUObjectArray`)
O `GObjects` é o array mestre que mantém ponteiros para todas as instâncias de classes alocadas no jogo.
- **Na UE 4.11 a 4.20:** Array bidimensional de chunks de 64 KB de objetos (`FUObjectItem`).
- **Na UE 4.21 a 5.x:** Tabela segmentada indexada por `ObjectIndex`:
  $$\text{Chunk} = \text{ObjectIndex} / 65536, \quad \text{IndexInChunk} = \text{ObjectIndex} \% 65536$$

### 2.2 `GNames` / `FNamePool`
Todos os identificadores de texto (nomes de classes, propriedades, funções e ossos) utilizam o tipo `FName`.
- **UE 4.23+ / UE 5:** Utiliza o **FNamePool** segmentado em blocos de 16 KB. Cada `FName` contém um `Index` de 32 bits e um `Number`.
- Para resolver uma string de osso (ex: `"Head"`, `"Pelvis"`):
  $$\text{BlockOffset} = \text{NameIndex} \gg 16, \quad \text{ByteOffset} = (\text{NameIndex} \ \& \ \text{0xFFFF}) \times 2$$

---

## 3. Dissecador Automático de Estruturas do OnyxEngine

O OnyxEngine inclui um dissecador de memória especializado em arquiteturas orientadas a objetos C++ e Unreal:
1. Anexe ao jogo e abra **Memory View** (`Ctrl + M`).
2. Vá em **Tools -> Dissect Data / Structures** (`Ctrl + D`).
3. Digite o endereço do ponteiro do seu jogador (`APawn`).
4. O OnyxEngine lê a memória adjacente, identifica a **Virtual Method Table (VTable)** no offset `0x00`, e classifica automaticamente cada campo:
   - Inteiros e Contadores (32 e 64 bits)
   - Pointers apontando para memória executável (VTable) ou Heap (Instâncias filhas)
   - Vetores 3D (`FVector: X, Y, Z float`)
   - Quatérnios de Rotação (`FQuat: X, Y, Z, W float`)
   - Matrizes de Transformação (`FTransform`)

---

## 4. Extração de Matriz de Ossos (*Bone Matrix*)

Para renderizar ESP (esqueleto na tela) ou implementar mira assistida (Aimbot direcionado à cabeça), precisamos das coordenadas 3D dos ossos da malha esquelética (`USkeletalMeshComponent`):

### 4.1 Estrutura `FTransform`
Cada osso possui sua própria transformação local composta por:
```cpp
struct FTransform {
    FQuat   Rotation;      // 16 bytes: X, Y, Z, W (Quatérnio de rotação)
    FVector Translation;   // 12 bytes: X, Y, Z (Coordenadas no espaço local)
    FVector Scale3D;       // 12 bytes: Escala do osso
};
```

### 4.2 Multiplicação Matricial para Espaço de Mundo
A coordenada real do osso no mundo 3D do jogo é obtida multiplicando a transformação do osso pela transformação do componente esquelético:

$$\mathbf{M}_{\text{World}} = \mathbf{M}_{\text{BoneLocal}} \times \mathbf{M}_{\text{ComponentToWorld}}$$

O endereço do array de ossos é lido diretamente do `USkeletalMeshComponent`:
```text
USkeletalMeshComponent + 0x4B0 -> TArray<FTransform> BoneArray
  BoneArray[0]  -> Root
  BoneArray[1]  -> Pelvis
  BoneArray[6]  -> Spine
  BoneArray[8]  -> Neck
  BoneArray[9]  -> Head (Cabeça do Jogador Alvo)
```

---

## 5. Automação via MCP para Extração de SDK

Através da ferramenta `dissect_structure` do servidor MCP, um agente de IA pode extrair a classe C++ completa em código compilável:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "dissect_structure",
  "params": {
    "address": "0x24C80000",
    "size": 1024,
    "detect_unreal_fields": true
  }
}
```

O servidor retorna o layout de memória completo com os tipos de dados identificados, gerando automaticamente os arquivos de cabeçalho (.h) da SDK do jogo sem necessidade de recompilar ferramentas externas.
