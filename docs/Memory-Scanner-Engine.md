# Motor de Varredura de Memória SIMD (`onyx_scanner.dll`)

## 1. Visão Geral

O módulo **`onyx_scanner.dll`** é o motor nativo de alto desempenho responsável pela enumeração, filtragem e localização de padrões de valores na memória virtual de processos alvos. Desenvolvido em Rust com paralelismo determinístico (baseado no framework **Rayon**) e comparadores vetorizados em hardware (**AVX2 / SSE4.2 / NEON**), ele substitui o algoritmo de varredura monolítico legado do Cheat Engine original, alcançando velocidades de processamento de até **5 GB/s** em memória física mapeada.

---

## 2. Pipeline de Varredura de Memória

O ciclo de vida de uma varredura é dividido em quatro estágios encadeados:

```text
+---------------------------------------------------------------------------------+
|                       1. Enumeração de Páginas (VAD Walk)                       |
|   VirtualQueryEx -> Filtra MEM_COMMIT, tipo de página e permissões de proteção   |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                    2. Particionamento em Chunks Paralelos                       |
|   Divisão da memória em blocos alinhados de 64 KB distribuídos via Rayon pool   |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                      3. Comparador Vetorizado SIMD (AVX2)                       |
|   Carregamento de 256 bits (_mm256_loadu_si256) + Comparação (_mm256_cmpeq_epi32)|
|   Extração de máscara de bits via _mm256_movemask_epi8                          |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                     4. Agregação e Compactação de Resultados                    |
|   Array denso de pares (Endereço, ValorAnterior) armazenado sem alocação extra  |
+---------------------------------------------------------------------------------+
```

---

## 3. Tipos de Dados e Modos de Comparação

O motor suporta todos os tipos primitivos de dados com alinhamento configurável (1, 2, 4, 8 ou 16 bytes):

| Tipo de Dado | Tamanho | Algoritmo de Comparação |
|---|---|---|
| `Byte (i8/u8)` | 1 byte | Comparação direta de registradores |
| `2 Bytes (i16/u16)` | 2 bytes | Comparação com máscara de alinhamento de 16 bits |
| `4 Bytes (i32/u32)` | 4 bytes | Vetorizado AVX2 (`_mm256_cmpeq_epi32`) |
| `8 Bytes (i64/u64)` | 8 bytes | Vetorizado AVX2 (`_mm256_cmpeq_epi64`) |
| `Float (f32)` | 4 bytes | Tolerância de precisão (`|A - B| <= epsilon`) |
| `Double (f64)` | 8 bytes | Tolerância de precisão em ponto flutuante de 64 bits |
| `String (UTF-8 / UTF-16)` | Dinâmico | Busca rápida de substrings Boyer-Moore-Horspool vetorizada |
| `Array of Bytes (AOB)` | Variável | Comparação por máscara de bytes curingas (`??`) com `memchr` |

---

## 4. Algoritmos de First Scan e Next Scan

### 4.1 First Scan: Valor Exato (`Exact Value`)
Na primeira varredura, o scanner não possui dados prévios. Ele divide cada região elegível em blocos de memória e aplica a rotina SIMD para testar 8 inteiros de 32 bits simultaneamente por ciclo de clock:

```rust
#[target_feature(enable = "avx2")]
pub unsafe fn scan_chunk_exact_i32(buffer: &[u8], target_val: i32, results: &mut Vec<usize>) {
    let target_vec = _mm256_set1_epi32(target_val);
    let len = buffer.len();
    let mut offset = 0;

    while offset + 32 <= len {
        // Carrega 32 bytes não alinhados da memória do alvo
        let data_vec = _mm256_loadu_si256(buffer.as_ptr().add(offset) as *const __m256i);
        // Compara 8 valores de 32 bits em paralelo
        let cmp = _mm256_cmpeq_epi32(data_vec, target_vec);
        let mask = _mm256_movemask_epi8(cmp) as u32;

        if mask != 0 {
            // Decodifica quais das 8 posições deram match
            for i in 0..8 {
                if (mask & (0xF << (i * 4))) == (0xF << (i * 4)) {
                    results.push(offset + (i * 4));
                }
            }
        }
        offset += 32;
    }
}
```

### 4.2 First Scan: Valor Inicial Desconhecido (`Unknown Initial Value`)
Quando o valor procurado é desconhecido (ex: barra de vida sem numeração visível), o scanner armazena um snapshot compactado de toda a memória elegível do processo em buffers segmentados. Cada página recebe um array contíguo contendo o estado $V_0$.

### 4.3 Next Scan: Condições Relacionais
Nas varreduras subsequentes, o motor consulta apenas os endereços que sobreviveram aos scans anteriores, comparando o valor recém-lido $V_{\text{atual}}$ com o valor arquivado $V_{\text{anterior}}$:

* **Valor Aumentado (`Increased Value`)**: $V_{\text{atual}} > V_{\text{anterior}}$
* **Valor Diminuído (`Decreased Value`)**: $V_{\text{atual}} < V_{\text{anterior}}$
* **Valor Alterado (`Changed Value`)**: $V_{\text{atual}} \neq V_{\text{anterior}}$
* **Valor Inalterado (`Unchanged Value`)**: $V_{\text{atual}} == V_{\text{anterior}}$
* **Valor Aumentado por X (`Increased by X`)**: $V_{\text{atual}} == V_{\text{anterior}} + X$
* **Valor Diminuído por X (`Decreased by X`)**: $V_{\text{atual}} == V_{\text{anterior}} - X$

---

## 5. Varredura com Mascaramento AOB (Array of Bytes)

A varredura por assinatura de bytes aceita wildcards (`?` ou `??`), permitindo localizar funções em binários mesmo quando instruções contêm deslocamentos variáveis, registradores alternados ou endereços de saltos RIP-relative.

Exemplo de padrão de injeção:
```text
Padrão:  48 8B 05 ?? ?? ?? ?? 48 8B 48 18 48 85 C9 74
Máscara: xx xx xx ?? ?? ?? ?? xx xx xx xx xx xx xx xx
```

O comparador do `onyx_scanner` divide a assinatura em duas partes:
1. **Padrão de Bytes Fixos**: `[0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x48, 0x18, 0x48, 0x85, 0xC9, 0x74]`
2. **Máscara de Validação (Bitmask)**: `[0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]`

A validação em lote calcula:
$$(\text{Chunk\_Bytes} \ \& \ \text{Bitmask}) == (\text{Pattern\_Bytes} \ \& \ \text{Bitmask})$$

---

## 6. Exportações C-ABI (`onyx_scanner.dll`)

A biblioteca expõe funções com convenção `stdcall` para consumo direto pelo frontend e bridges de script:

```c
// Inicializa uma nova instância do motor de varredura
HANDLE scanner_new(DWORD process_id);

// Configura o tipo de dado e alinhamento
BOOL scanner_set_data_type(HANDLE hScanner, int data_type, int alignment);

// Executa a primeira varredura em paralelo
DWORD64 scanner_first_scan(HANDLE hScanner, int scan_type, const char* value_str);

// Filtra a lista ativa de resultados
DWORD64 scanner_next_scan(HANDLE hScanner, int scan_type, const char* value_str);

// Obtém os resultados paginados
DWORD scanner_get_results(HANDLE hScanner, DWORD offset, DWORD count, SCAN_RESULT_ENTRY* out_entries);

// Limpa e reseta a tabela de escaneamento
void scanner_reset(HANDLE hScanner);

// Destrói a instância e libera buffers
void scanner_free(HANDLE hScanner);
```
