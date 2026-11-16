# Algoritmos de Resolução e Varredura de Ponteiros (`onyx_pointer.dll`)

## 1. O Problema do Endereçamento Dinâmico

Em aplicações modernas para x86_64, objetos críticos como estruturas de contexto principal, inventários e tabelas de entidades residem em memória de alocação dinâmica (**Heap / VirtualAlloc**) e têm seus endereços base aleatorizados pelo sistema operacional a cada inicialização (**ASLR - Address Space Layout Randomization**).

Como consequência, um endereço de memória estático obtido em uma sessão torna-se inválido na sessão seguinte. Para contornar essa limitação de forma permanente, o OnyxEngine utiliza o módulo **`onyx_pointer.dll`** para identificar **cadeias de ponteiros multinível** que conectam um endereço estático do módulo executável principal (ex: `target_app.exe + 0x1A2B3C`) até o endereço dinâmico da variável desejada.

---

## 2. Modelo Matemático da Cadeia de Ponteiros

Uma cadeia de ponteiros de profundidade $N$ é formalizada pela equação iterativa:

$$A_0 = \text{MóduloBase} + O_0$$
$$A_1 = [\![A_0]\!] + O_1$$
$$A_2 = [\![A_1]\!] + O_2$$
$$\vdots$$
$$A_N = [\![A_{N-1}]\!] + O_N = \text{EndereçoAlvo}$$

Onde:
* $\text{MóduloBase}$ é o endereço inicial de carregamento da DLL ou EXE na memória.
* $O_i$ é o deslocamento (*offset*) em bytes aplicado ao desreferenciar o ponteiro anterior.
* $[\![X]\!]$ denota a operação de leitura de 8 bytes (x64) presentes no endereço de memória $X$.

Exemplo prático de desreferenciamento em 3 níveis:
```text
[client.dll + 0x0182E400]           -> Ponteiro Base Estático: 0x7FFA8000
    + 0x10 -> [0x7FFA8010]          -> Aponta para C_BasePlayer: 0x24C80000
    + 0x320 -> [0x24C80320]         -> Aponta para C_PlayerPawn: 0x1A401000
    + 0x44 -> 0x1A401044            -> Endereço Final da Vida (m_iHealth = 100)
```

---

## 3. Algoritmo de Varredura Reversa (Reverse Pointer Map)

A busca ingênua direta (*Forward Search*) a partir de todos os ponteiros do módulo é computacionalmente inviável, com complexidade de tempo exponencial $O(M^D)$, onde $M$ é o número de ponteiros e $D$ é a profundidade.

O `onyx_pointer.dll` emprega o algoritmo de **Varredura Reversa com Mapa de Ponteiros Indexado**:

```text
+---------------------------------------------------------------------------------+
|                       1. Geração do PointerMap (.scandata)                      |
|   Varre toda a memória do alvo e extrai pares (Endereço, ValorApontado)         |
|   Filtra apenas valores que apontam para regiões válidas (MEM_COMMIT)           |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                          2. Indexação e Ordenação                               |
|   Ordena o array de nós pelo ValorApontado para permitir busca binária O(log N) |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                     3. Busca Reversa em Largura (BFS / DFS)                     |
|   A partir do TargetAddress, busca todos os endereços X onde:                   |
|                      TargetAddress - MaxOffset <= [X] <= TargetAddress          |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                    4. Verificação de Base Estática (Módulo)                     |
|   Se o endereço X pertencer a um módulo executável (.exe / .dll), a cadeia é    |
|   registrada como caminho válido. Caso contrário, X torna-se o novo alvo.       |
+---------------------------------------------------------------------------------+
```

---

## 4. Otimizações de Performance do `onyx_pointer.dll`

1. **Bucket Hash + Binary Search Híbrido**: O mapa de memória é segmentado em *buckets* indexados, reduzindo o espaço de busca da busca binária de $N$ para $K \ll N$.
2. **Poda de Ramos Cíclicos**: Caminhos que referenciam estruturas circulares de dados (listas encadeadas em que $A \rightarrow B \rightarrow A$) são abortados imediatamente para evitar loops infinitos.
3. **Rescan Multi-Sessão**:
   - Um scan inicial pode encontrar 500.000 caminhos possíveis.
   - Ao reiniciar o processo ou recarregar módulos, o endereço da variável muda para um novo valor.
   - O comando de **Rescan** testa cada uma das 500.000 cadeias salvas contra o novo endereço alvo, descartando ponteiros que apontam para lixo e filtrando até restar apenas **1 a 5 caminhos verdadeiros**.

### 4.1 Algoritmo de Expansão de Frente de Onda (`scan_wavefront`)

O núcleo do scanner de ponteiros implementa uma busca em largura (*Breadth-First Search*) paralela que expande nós candidatos a partir do endereço alvo em direção aos módulos estáticos carregados:

```rust
// crates/modules/pointer/src/compute.rs
#[derive(Clone)]
struct WavefrontNode {
    current_address: u64,
    offsets: Vec<usize>,
    visited: HashSet<u64>,
}

pub fn scan_wavefront(
    matrix: &CompactPointerMatrix,
    target_address: u64,
    max_depth: usize,
    max_offset: usize,
    alignment: usize,
    max_results: usize,
    modules: &[ModuleEntry],
    cancel_flag: Option<Arc<AtomicBool>>,
    progress_cb: Option<&mut dyn FnMut(f32, usize) -> bool>,
) -> Vec<PointerPath> {
    let mut results = Vec::new();
    if matrix.is_empty() || max_depth == 0 {
        return results;
    }

    let mut queue: Vec<WavefrontNode> = vec![WavefrontNode {
        current_address: target_address,
        offsets: Vec::new(),
        visited: {
            let mut set = HashSet::with_capacity(max_depth + 1);
            set.insert(target_address);
            set
        },
    }];

    let mut current_depth = 0;

    while current_depth < max_depth && !queue.is_empty() && results.len() < max_results {
        if let Some(ref cancel) = cancel_flag {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
        }

        let mut next_queue = Vec::with_capacity(queue.len() * 4);

        for node in &queue {
            if results.len() >= max_results {
                break;
            }

            // Localiza todos os ponteiros no mapa que apontam para [node.current_address - max_offset .. node.current_address]
            let candidates = matrix.find_candidates(node.current_address, max_offset, alignment);

            for (from_addr, offset) in candidates {
                if node.visited.contains(&from_addr) {
                    continue; // Poda de ciclo
                }

                let mut new_offsets = node.offsets.clone();
                new_offsets.push(offset);

                // Verifica se from_addr reside no intervalo de memória de algum módulo DLL/EXE carregado
                if let Some(m) = modules.iter().find(|m| {
                    (from_addr as usize) >= m.base && (from_addr as usize) < (m.base + m.size)
                }) {
                    let base_offset = (from_addr as usize) - m.base;
                    let mut path_offsets = new_offsets.clone();
                    path_offsets.reverse();

                    results.push(PointerPath {
                        module_name: m.name.clone(),
                        base_offset,
                        offsets: path_offsets,
                    });
                } else if current_depth + 1 < max_depth {
                    let mut next_visited = node.visited.clone();
                    next_visited.insert(from_addr);
                    next_queue.push(WavefrontNode {
                        current_address: from_addr,
                        offsets: new_offsets,
                        visited: next_visited,
                    });
                }
            }
        }

        queue = next_queue;
        current_depth += 1;
    }

    results
}
```

---

## 5. Interface C-ABI (`onyx_pointer.dll`)

```c
// Resolve uma cadeia de ponteiros e retorna o endereço de destino final
DWORD64 pointer_resolve_chain(DWORD process_id, DWORD64 base_address, const DWORD* offsets, DWORD offset_count);

// Inicia a geração de um mapa de ponteiros do processo
HANDLE pointer_map_create(DWORD process_id, const char* output_filename);

// Executa a varredura reversa a partir de um mapa de ponteiros
HANDLE pointer_scan_start(const char* map_filename, DWORD64 target_address, DWORD max_depth, DWORD max_offset);

// Filtra resultados anteriores com um novo endereço alvo após reinício
DWORD pointer_rescan(HANDLE hScanResults, DWORD process_id, DWORD64 new_target_address);
```
