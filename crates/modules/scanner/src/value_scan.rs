//! Scanner de valores exatos com aceleracao SIMD (AVX2 / AVX-512).
//!
//! Encontra todos os offsets dentro de um buffer onde um valor (`i32`, `i64`,
//! `f32`, `f64`) aparece exatamente. Para busca exata, floats sao comparados
//! bit-a-bit (equivalentes a cmpeq de inteiros do mesmo tamanho), o que
//! satisfaz as regras de IEEE-754 pra operacao `Exact Value` do engine.
//!
//! Dispatch em runtime: AVX-512F > AVX2 > escalar.

use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    I32,
    I64,
    F32,
    F64,
}

impl ValueKind {
    #[inline]
    pub fn size(self) -> usize {
        match self {
            ValueKind::I32 | ValueKind::F32 => 4,
            ValueKind::I64 | ValueKind::F64 => 8,
        }
    }

    #[inline]
    pub fn default_align(self) -> usize {
        self.size()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Needle {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
}

impl Needle {
    #[inline]
    pub fn kind(&self) -> ValueKind {
        match self {
            Needle::I32(_) => ValueKind::I32,
            Needle::I64(_) => ValueKind::I64,
            Needle::F32(_) => ValueKind::F32,
            Needle::F64(_) => ValueKind::F64,
        }
    }

    #[inline]
    fn as_i32_bits(&self) -> i32 {
        match self {
            Needle::I32(v) => *v,
            Needle::F32(v) => v.to_bits() as i32,
            _ => 0,
        }
    }

    #[inline]
    fn as_i64_bits(&self) -> i64 {
        match self {
            Needle::I64(v) => *v,
            Needle::F64(v) => v.to_bits() as i64,
            _ => 0,
        }
    }
}

/// Resolve alinhamento efetivo. `align == 0` usa o alinhamento natural do tipo.
#[inline]
fn effective_align(kind: ValueKind, align: usize) -> usize {
    if align == 0 {
        kind.default_align()
    } else {
        align.max(1)
    }
}

// ---------- escalar (referencia) ----------

pub fn scan_exact_scalar(buffer: &[u8], needle: Needle, align: usize) -> Vec<usize> {
    let kind = needle.kind();
    let step = effective_align(kind, align);
    let sz = kind.size();
    if buffer.len() < sz {
        return Vec::new();
    }
    let end = buffer.len() - sz;
    let mut out = Vec::new();

    match kind {
        ValueKind::I32 | ValueKind::F32 => {
            let target = needle.as_i32_bits();
            let mut i = 0usize;
            while i <= end {
                let v = i32::from_le_bytes([
                    buffer[i],
                    buffer[i + 1],
                    buffer[i + 2],
                    buffer[i + 3],
                ]);
                if v == target {
                    out.push(i);
                }
                i += step;
            }
        }
        ValueKind::I64 | ValueKind::F64 => {
            let target = needle.as_i64_bits();
            let mut i = 0usize;
            while i <= end {
                let v = i64::from_le_bytes([
                    buffer[i],
                    buffer[i + 1],
                    buffer[i + 2],
                    buffer[i + 3],
                    buffer[i + 4],
                    buffer[i + 5],
                    buffer[i + 6],
                    buffer[i + 7],
                ]);
                if v == target {
                    out.push(i);
                }
                i += step;
            }
        }
    }
    out
}

// ---------- AVX2 ----------
//
// Estrategia: janelas de 32 bytes. Comparamos como lane de 32 bits ou 64 bits
// e extraimos a mask de 256 bits via `_mm256_movemask_epi8`. Cada lane marca
// 4 ou 8 bytes contiguos iguais, entao basta ler os bits em passo 4 ou 8.
//
// Alinhamento diferente do tamanho do tipo (ex: align=1) requer varrer todos
// os bytes - rodamos a janela em offsets independentes (0..align) via loop
// externo.

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use super::effective_align;
    use super::{Needle, ValueKind};
    use std::arch::x86_64::*;

    #[target_feature(enable = "avx2")]
    pub unsafe fn scan_exact_i32(buffer: &[u8], target: i32, align: usize) -> Vec<usize> {
        let step = effective_align(ValueKind::I32, align);
        let sz = 4usize;
        if buffer.len() < sz {
            return Vec::new();
        }
        let end = buffer.len() - sz;

        let mut out = Vec::new();
        let needle = _mm256_set1_epi32(target);

        if step == sz {
            // caso rapido: alinhamento natural, janelas sucessivas de 32B,
            // 8 lanes de i32 por janela.
            let lanes = 8usize;
            let mut i = 0usize;
            while i + 32 <= buffer.len() {
                let chunk = _mm256_loadu_si256(buffer.as_ptr().add(i) as *const __m256i);
                let eq = _mm256_cmpeq_epi32(chunk, needle);
                let bits = _mm256_movemask_epi8(eq) as u32;
                // cada lane i32 ocupa 4 bits iguais; pegamos o bit 0 de cada
                // nibble (0, 4, 8, 12, ...)
                for lane in 0..lanes {
                    if (bits >> (lane * 4)) & 0xF != 0 {
                        let pos = i + lane * sz;
                        if pos <= end {
                            out.push(pos);
                        }
                    }
                }
                i += 32;
            }
            // tail escalar alinhado ao step
            while i <= end {
                let v = i32::from_le_bytes([
                    buffer[i],
                    buffer[i + 1],
                    buffer[i + 2],
                    buffer[i + 3],
                ]);
                if v == target {
                    out.push(i);
                }
                i += step;
            }
        } else {
            // alinhamento arbitrario: usa fallback escalar com step dado.
            // (comum em cases de align=1,2; nao vale a pena vetorizar.)
            let mut i = 0usize;
            while i <= end {
                let v = i32::from_le_bytes([
                    buffer[i],
                    buffer[i + 1],
                    buffer[i + 2],
                    buffer[i + 3],
                ]);
                if v == target {
                    out.push(i);
                }
                i += step;
            }
        }
        out
    }

    #[target_feature(enable = "avx2")]
    pub unsafe fn scan_exact_i64(buffer: &[u8], target: i64, align: usize) -> Vec<usize> {
        let step = effective_align(ValueKind::I64, align);
        let sz = 8usize;
        if buffer.len() < sz {
            return Vec::new();
        }
        let end = buffer.len() - sz;

        let mut out = Vec::new();
        let needle = _mm256_set1_epi64x(target);

        if step == sz {
            let lanes = 4usize;
            let mut i = 0usize;
            while i + 32 <= buffer.len() {
                let chunk = _mm256_loadu_si256(buffer.as_ptr().add(i) as *const __m256i);
                let eq = _mm256_cmpeq_epi64(chunk, needle);
                let bits = _mm256_movemask_epi8(eq) as u32;
                for lane in 0..lanes {
                    if (bits >> (lane * 8)) & 0xFF != 0 {
                        let pos = i + lane * sz;
                        if pos <= end {
                            out.push(pos);
                        }
                    }
                }
                i += 32;
            }
            while i <= end {
                let v = i64::from_le_bytes([
                    buffer[i],
                    buffer[i + 1],
                    buffer[i + 2],
                    buffer[i + 3],
                    buffer[i + 4],
                    buffer[i + 5],
                    buffer[i + 6],
                    buffer[i + 7],
                ]);
                if v == target {
                    out.push(i);
                }
                i += step;
            }
        } else {
            let mut i = 0usize;
            while i <= end {
                let v = i64::from_le_bytes([
                    buffer[i],
                    buffer[i + 1],
                    buffer[i + 2],
                    buffer[i + 3],
                    buffer[i + 4],
                    buffer[i + 5],
                    buffer[i + 6],
                    buffer[i + 7],
                ]);
                if v == target {
                    out.push(i);
                }
                i += step;
            }
        }
        out
    }

    pub unsafe fn scan_exact_dispatch(
        buffer: &[u8],
        needle: Needle,
        align: usize,
    ) -> Vec<usize> {
        match needle.kind() {
            ValueKind::I32 | ValueKind::F32 => {
                scan_exact_i32(buffer, needle.as_i32_bits(), align)
            }
            ValueKind::I64 | ValueKind::F64 => {
                scan_exact_i64(buffer, needle.as_i64_bits(), align)
            }
        }
    }
}

// ---------- AVX-512 ----------
#[cfg(target_arch = "x86_64")]
mod avx512 {
    use super::effective_align;
    use super::{Needle, ValueKind};
    use std::arch::x86_64::*;

    #[target_feature(enable = "avx512f")]
    pub unsafe fn scan_exact_i32(buffer: &[u8], target: i32, align: usize) -> Vec<usize> {
        let step = effective_align(ValueKind::I32, align);
        let sz = 4usize;
        if buffer.len() < sz {
            return Vec::new();
        }
        let end = buffer.len() - sz;

        let mut out = Vec::new();
        let needle = _mm512_set1_epi32(target);

        if step == sz {
            let mut i = 0usize;
            while i + 64 <= buffer.len() {
                let chunk = _mm512_loadu_si512(buffer.as_ptr().add(i) as *const _);
                let mask: u16 = _mm512_cmpeq_epi32_mask(chunk, needle);
                let mut m = mask;
                while m != 0 {
                    let lane = m.trailing_zeros() as usize;
                    let pos = i + lane * sz;
                    if pos <= end {
                        out.push(pos);
                    }
                    m &= m - 1;
                }
                i += 64;
            }
            while i <= end {
                let v = i32::from_le_bytes([
                    buffer[i],
                    buffer[i + 1],
                    buffer[i + 2],
                    buffer[i + 3],
                ]);
                if v == target {
                    out.push(i);
                }
                i += step;
            }
        } else {
            let mut i = 0usize;
            while i <= end {
                let v = i32::from_le_bytes([
                    buffer[i],
                    buffer[i + 1],
                    buffer[i + 2],
                    buffer[i + 3],
                ]);
                if v == target {
                    out.push(i);
                }
                i += step;
            }
        }
        out
    }

    #[target_feature(enable = "avx512f")]
    pub unsafe fn scan_exact_i64(buffer: &[u8], target: i64, align: usize) -> Vec<usize> {
        let step = effective_align(ValueKind::I64, align);
        let sz = 8usize;
        if buffer.len() < sz {
            return Vec::new();
        }
        let end = buffer.len() - sz;

        let mut out = Vec::new();
        let needle = _mm512_set1_epi64(target);

        if step == sz {
            let mut i = 0usize;
            while i + 64 <= buffer.len() {
                let chunk = _mm512_loadu_si512(buffer.as_ptr().add(i) as *const _);
                let mask: u8 = _mm512_cmpeq_epi64_mask(chunk, needle);
                let mut m = mask;
                while m != 0 {
                    let lane = m.trailing_zeros() as usize;
                    let pos = i + lane * sz;
                    if pos <= end {
                        out.push(pos);
                    }
                    m &= m - 1;
                }
                i += 64;
            }
            while i <= end {
                let v = i64::from_le_bytes([
                    buffer[i],
                    buffer[i + 1],
                    buffer[i + 2],
                    buffer[i + 3],
                    buffer[i + 4],
                    buffer[i + 5],
                    buffer[i + 6],
                    buffer[i + 7],
                ]);
                if v == target {
                    out.push(i);
                }
                i += step;
            }
        } else {
            let mut i = 0usize;
            while i <= end {
                let v = i64::from_le_bytes([
                    buffer[i],
                    buffer[i + 1],
                    buffer[i + 2],
                    buffer[i + 3],
                    buffer[i + 4],
                    buffer[i + 5],
                    buffer[i + 6],
                    buffer[i + 7],
                ]);
                if v == target {
                    out.push(i);
                }
                i += step;
            }
        }
        out
    }

    pub unsafe fn scan_exact_dispatch(
        buffer: &[u8],
        needle: Needle,
        align: usize,
    ) -> Vec<usize> {
        match needle.kind() {
            ValueKind::I32 | ValueKind::F32 => {
                scan_exact_i32(buffer, needle.as_i32_bits(), align)
            }
            ValueKind::I64 | ValueKind::F64 => {
                scan_exact_i64(buffer, needle.as_i64_bits(), align)
            }
        }
    }
}

// ---------- feature detect ----------

pub fn avx2_supported() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| {
        #[cfg(target_arch = "x86_64")]
        {
            is_x86_feature_detected!("avx2")
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    })
}

pub fn avx512_supported() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| {
        #[cfg(target_arch = "x86_64")]
        {
            is_x86_feature_detected!("avx512f")
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    })
}

// ---------- dispatch publico ----------

#[inline]
pub fn scan_exact_avx2(buffer: &[u8], needle: Needle, align: usize) -> Vec<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if avx2_supported() {
            unsafe {
                return avx2::scan_exact_dispatch(buffer, needle, align);
            }
        }
    }
    scan_exact_scalar(buffer, needle, align)
}

#[inline]
pub fn scan_exact_avx512(buffer: &[u8], needle: Needle, align: usize) -> Vec<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if avx512_supported() {
            unsafe {
                return avx512::scan_exact_dispatch(buffer, needle, align);
            }
        }
    }
    scan_exact_avx2(buffer, needle, align)
}

#[inline]
pub fn scan_exact(buffer: &[u8], needle: Needle, align: usize) -> Vec<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if avx512_supported() {
            unsafe {
                return avx512::scan_exact_dispatch(buffer, needle, align);
            }
        }
        if avx2_supported() {
            unsafe {
                return avx2::scan_exact_dispatch(buffer, needle, align);
            }
        }
    }
    scan_exact_scalar(buffer, needle, align)
}

// ---------- pipeline de I/O por processo (Windows) ----------

#[cfg(windows)]
pub mod process_pipeline {
    //! Varre todas as regioes commited e legiveis de um processo em paralelo
    //! via `std::thread::scope`, lendo com `ReadProcessMemory` e aplicando o
    //! `scan_exact` SIMD. Retorna enderecos absolutos.

    use super::{scan_exact, Needle};
    use onyx_core::process::win32::*;
    use std::sync::Mutex;

    const READ_CHUNK: usize = 1 << 20; // 1 MiB

    fn is_readable(mbi: &MEMORY_BASIC_INFORMATION) -> bool {
        if mbi.State != MEM_COMMIT {
            return false;
        }
        let prot = mbi.Protect;
        if prot & PAGE_GUARD != 0 || prot & PAGE_NOACCESS != 0 {
            return false;
        }
        let readable = PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY;
        prot & readable != 0
    }

    fn enumerate_regions(h: HANDLE) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut addr: usize = 0;
        unsafe {
            loop {
                let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                let n = VirtualQueryEx(
                    h,
                    addr as LPCVOID,
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );
                if n == 0 {
                    break;
                }
                let base = mbi.BaseAddress as usize;
                let size = mbi.RegionSize;
                if is_readable(&mbi) {
                    out.push((base, size));
                }
                let next = base.wrapping_add(size);
                if next <= addr {
                    break;
                }
                addr = next;
            }
        }
        out
    }

    pub fn scan_process(pid: u32, needle: Needle, align: usize) -> Vec<u64> {
        unsafe {
            let h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
            if h.is_null() {
                return Vec::new();
            }
            let regions = enumerate_regions(h);
            let results = Mutex::new(Vec::<u64>::new());
            let h_bits = h as usize;

            let n_threads = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
                .max(1);
            let chunks: Vec<&[(usize, usize)]> = regions.chunks(regions.len().div_ceil(n_threads).max(1)).collect();

            std::thread::scope(|s| {
                for chunk in chunks {
                    let results = &results;
                    s.spawn(move || {
                        let h = h_bits as HANDLE;
                        let mut buf = vec![0u8; READ_CHUNK];
                        let mut local = Vec::<u64>::new();
                        for &(base, size) in chunk {
                            let mut off = 0usize;
                            while off < size {
                                let want = (size - off).min(READ_CHUNK);
                                buf.resize(want, 0);
                                let mut read: SIZE_T = 0;
                                let ok = ReadProcessMemory(
                                    h,
                                    (base + off) as LPCVOID,
                                    buf.as_mut_ptr() as LPVOID,
                                    want,
                                    &mut read,
                                );
                                if ok == 0 || read == 0 {
                                    off += want;
                                    continue;
                                }
                                let slice = &buf[..read];
                                let hits = scan_exact(slice, needle, align);
                                for h in hits {
                                    local.push((base + off + h) as u64);
                                }
                                off += read;
                            }
                        }
                        if !local.is_empty() {
                            let mut g = results.lock().unwrap();
                            g.extend(local);
                        }
                    });
                }
            });

            CloseHandle(h);
            let mut v = results.into_inner().unwrap();
            v.sort_unstable();
            v
        }
    }
}

#[cfg(not(windows))]
pub mod process_pipeline {
    use super::Needle;
    pub fn scan_process(_pid: u32, _needle: Needle, _align: usize) -> Vec<u64> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_i32_known_offsets() {
        let mut buf = vec![0u8; 4096];
        let target: i32 = 0x1234_5678;
        for off in [0usize, 400, 1600, 3200] {
            buf[off..off + 4].copy_from_slice(&target.to_le_bytes());
        }
        let hits = scan_exact_scalar(&buf, Needle::I32(target), 4);
        assert_eq!(hits, vec![0, 400, 1600, 3200]);
    }

    #[test]
    fn scalar_i64_known_offsets() {
        let mut buf = vec![0u8; 4096];
        let target: i64 = 0x0BAD_C0DE_DEAD_BEEFi64;
        for off in [0usize, 400, 1600, 3200] {
            buf[off..off + 8].copy_from_slice(&target.to_le_bytes());
        }
        let hits = scan_exact_scalar(&buf, Needle::I64(target), 8);
        assert_eq!(hits, vec![0, 400, 1600, 3200]);
    }

    #[test]
    fn align_filters_hits() {
        let mut buf = vec![0u8; 128];
        let target: i32 = 42;
        // valor em offset nao alinhado deve ser ignorado por align=4
        buf[5..9].copy_from_slice(&target.to_le_bytes());
        let hits = scan_exact_scalar(&buf, Needle::I32(target), 4);
        assert!(hits.is_empty());
        let hits = scan_exact_scalar(&buf, Needle::I32(target), 1);
        assert_eq!(hits, vec![5]);
    }

    #[test]
    fn f32_bitwise_exact() {
        let mut buf = vec![0u8; 256];
        let v: f32 = 3.1415927;
        buf[16..20].copy_from_slice(&v.to_le_bytes());
        buf[64..68].copy_from_slice(&v.to_le_bytes());
        let hits = scan_exact(&buf, Needle::F32(v), 4);
        assert_eq!(hits, vec![16, 64]);
    }
}
