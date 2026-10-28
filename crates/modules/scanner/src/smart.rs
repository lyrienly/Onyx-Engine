//! SmartScan: varredura em passagem unica com inferencia polimorfica de tipos.
//!
//! Em vez de o operador decidir previamente se o valor procurado e `i32`, `f32`,
//! `i64`, etc, o `smart_scan` percorre o buffer uma unica vez e, em cada offset,
//! avalia simultaneamente todas as interpretacoes compativeis (respeitando
//! alinhamento e heuristicas de validade). O resultado e uma lista de
//! [`SmartHit`] com o tipo inferido para cada endereco candidato.

use std::fmt::Write;

/// Tipos de dados inferidos pelo SmartScan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScanType {
    I32,
    I64,
    F32,
    F64,
    Pointer,
    StringAscii,
    StringUtf16,
}

impl ScanType {
    pub fn width(self) -> usize {
        match self {
            ScanType::I32 | ScanType::F32 => 4,
            ScanType::I64 | ScanType::F64 | ScanType::Pointer => 8,
            // Strings tem tamanho variavel; width minimo:
            ScanType::StringAscii => 4,
            ScanType::StringUtf16 => 8,
        }
    }

    pub fn alignment(self) -> usize {
        match self {
            ScanType::I32 | ScanType::F32 => 4,
            ScanType::I64 | ScanType::F64 | ScanType::Pointer => 8,
            ScanType::StringAscii => 1,
            ScanType::StringUtf16 => 2,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ScanType::I32 => "i32",
            ScanType::I64 => "i64",
            ScanType::F32 => "f32",
            ScanType::F64 => "f64",
            ScanType::Pointer => "pointer",
            ScanType::StringAscii => "string_ascii",
            ScanType::StringUtf16 => "string_utf16",
        }
    }
}

/// Alvo de busca.
#[derive(Debug, Clone)]
pub enum SmartTarget {
    /// Bytes exatos; qualquer offset que inicie com `bytes` casa, com
    /// inferencia do tipo de acordo com o tamanho e alinhamento.
    Exact(Vec<u8>),
    /// Valor numerico; retorna hits em qualquer tipo numerico (i32/i64/f32/f64)
    /// cujos bytes no offset se decodifiquem para o valor com tolerancia.
    Numeric(f64),
    /// Enumera tudo que pareca ser dado "razoavel" em cada offset.
    Any,
}

/// Resultado de um candidato.
#[derive(Debug, Clone)]
pub struct SmartHit {
    pub address: u64,
    pub scan_type: ScanType,
    pub bytes: Vec<u8>,
    pub interpreted: String,
}

/// Tolerancia relativa para comparacao de floats em `Numeric`.
const F_EPSILON: f64 = 1e-6;

/// Range razoavel de ponteiros userland x86_64.
const PTR_MIN: u64 = 0x1_0000;
const PTR_MAX: u64 = 0x7FFF_FFFF_FFFF;

/// Range razoavel de inteiros (evita 0xFFFFFFFF e similares).
/// Qualquer coisa fora do intervalo [-2^31+1, 2^31-1] e marcada como "ruim"
/// para i32 (ou mantida mas filtrada pela heuristica de "palavras suspeitas").
fn is_reasonable_i32(v: i32) -> bool {
    // Rejeita valores que parecem padding/magic.
    const BAD: &[i32] = &[
        i32::MIN,
        -1,
        0x7FFF_FFFF,
        0x5555_5555,
        0x5555_5555u32 as i32,
        0xAAAA_AAAAu32 as i32,
        0xCCCC_CCCCu32 as i32,
        0xDEAD_BEEFu32 as i32,
        0xCDCD_CDCDu32 as i32,
        0xBAAD_F00Du32 as i32,
        0xFEEE_FEEEu32 as i32,
    ];
    !BAD.contains(&v)
}

fn is_reasonable_i64(v: i64) -> bool {
    const BAD: &[i64] = &[
        i64::MIN,
        -1,
        i64::MAX,
        0x5555_5555_5555_5555u64 as i64,
        0xAAAA_AAAA_AAAA_AAAAu64 as i64,
        0xCCCC_CCCC_CCCC_CCCCu64 as i64,
        0xDEAD_BEEF_DEAD_BEEFu64 as i64,
        0xCDCD_CDCD_CDCD_CDCDu64 as i64,
    ];
    !BAD.contains(&v)
}

fn is_reasonable_f32(v: f32) -> bool {
    if !v.is_finite() {
        return false;
    }
    if v == 0.0 {
        return true;
    }
    let a = v.abs();
    a > 1e-30 && a < 1e30
}

fn is_reasonable_f64(v: f64) -> bool {
    if !v.is_finite() {
        return false;
    }
    if v == 0.0 {
        return true;
    }
    let a = v.abs();
    a > 1e-300 && a < 1e300
}

fn is_reasonable_pointer(v: u64) -> bool {
    v >= PTR_MIN && v <= PTR_MAX && (v & 0x7) == 0
}

/// Verifica string ASCII imprimivel terminada em NUL, len minimo >= 4.
/// Retorna (string, len_total_incluindo_nul).
fn try_ascii_string(buf: &[u8]) -> Option<(String, usize)> {
    let mut end = None;
    for (i, &b) in buf.iter().enumerate() {
        if b == 0 {
            end = Some(i);
            break;
        }
        if !(0x20..=0x7E).contains(&b) && b != b'\t' {
            return None;
        }
        if i >= 1024 {
            return None;
        }
    }
    let e = end?;
    if e < 4 {
        return None;
    }
    let s = std::str::from_utf8(&buf[..e]).ok()?.to_string();
    Some((s, e + 1))
}

/// UTF-16LE imprimivel terminada em 0x0000, len minimo >= 4 chars.
fn try_utf16_string(buf: &[u8]) -> Option<(String, usize)> {
    if buf.len() < 10 {
        return None;
    }
    let mut units: Vec<u16> = Vec::new();
    let mut i = 0;
    while i + 1 < buf.len() {
        let u = u16::from_le_bytes([buf[i], buf[i + 1]]);
        if u == 0 {
            break;
        }
        if u < 0x20 || u > 0xFFFD {
            return None;
        }
        units.push(u);
        i += 2;
        if units.len() > 1024 {
            return None;
        }
    }
    if units.len() < 4 {
        return None;
    }
    let s = String::from_utf16(&units).ok()?;
    Some((s, (units.len() + 1) * 2))
}

fn fmt_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        let _ = write!(s, "{:02X}", b);
    }
    s
}

#[allow(dead_code)]
fn numeric_matches(v: f64, target: f64) -> bool {
    if !v.is_finite() || !target.is_finite() {
        return false;
    }
    // Comparacao exata para inteiros, tolerancia relativa para floats.
    if target == v {
        return true;
    }
    let scale = target.abs().max(1.0);
    (v - target).abs() <= F_EPSILON * scale
}

/// Scan unico. Percorre `buffer` uma vez e emite hits inferindo o tipo.
///
/// - `base_addr`: endereco virtual correspondente ao byte 0 do buffer.
/// - `target`: filtro de busca.
pub fn smart_scan(buffer: &[u8], base_addr: u64, target: SmartTarget) -> Vec<SmartHit> {
    match target {
        SmartTarget::Numeric(n) => scan_numeric(buffer, base_addr, n),
        SmartTarget::Exact(ref b) => scan_exact(buffer, base_addr, b),
        SmartTarget::Any => scan_any(buffer, base_addr),
    }
}

/// Hot path para busca numerica. Varredura unica alinhada em 4 bytes;
/// em cada offset alinhado em 4 testa i32/f32; em offsets alinhados em 8
/// testa adicionalmente i64/f64/pointer. Sem alocacoes por offset.
fn scan_numeric(buffer: &[u8], base_addr: u64, target: f64) -> Vec<SmartHit> {
    let len = buffer.len();
    let mut hits: Vec<SmartHit> = Vec::new();

    // Para inteiros comparamos sem conversao para f64 quando o target cabe em i64.
    let target_i64 = if target.fract() == 0.0 && target.abs() < 9.22e18 {
        Some(target as i64)
    } else {
        None
    };
    let target_f = target;
    let scale = target_f.abs().max(1.0);
    let eps = F_EPSILON * scale;

    // Precomputa bits para match exato rapido quando target cabe em i32/f32 exato.
    let target_i32_bits: Option<i32> = target_i64
        .and_then(|t| i32::try_from(t).ok());
    let target_f32_bits: Option<u32> = {
        let f = target as f32;
        if (f as f64 - target).abs() <= eps {
            Some(f.to_bits())
        } else {
            None
        }
    };
    let target_f64_bits: u64 = target.to_bits();
    let ptr_mode = target >= 0.0 && target.fract() == 0.0 && target >= PTR_MIN as f64 && target <= PTR_MAX as f64;
    let target_ptr: u64 = if ptr_mode { target as u64 } else { 0 };

    let p = buffer.as_ptr();
    let mut off = 0usize;
    // Loop desenrolado: processa chunks de 8 bytes (dois i32 + um i64/f64/ptr).
    while off + 8 <= len {
        unsafe {
            // Primeiro i32 (offset off, alinhado 8 ⇒ alinhado 4).
            let v32a = std::ptr::read_unaligned(p.add(off) as *const i32);
            let v32b = std::ptr::read_unaligned(p.add(off + 4) as *const i32);
            let v64 = std::ptr::read_unaligned(p.add(off) as *const i64);

            // ----- i32 match exato -----
            if let Some(t) = target_i32_bits {
                if v32a == t {
                    hits.push(SmartHit {
                        address: base_addr.wrapping_add(off as u64),
                        scan_type: ScanType::I32,
                        bytes: buffer[off..off + 4].to_vec(),
                        interpreted: v32a.to_string(),
                    });
                }
                if v32b == t {
                    hits.push(SmartHit {
                        address: base_addr.wrapping_add((off + 4) as u64),
                        scan_type: ScanType::I32,
                        bytes: buffer[off + 4..off + 8].to_vec(),
                        interpreted: v32b.to_string(),
                    });
                }
            }

            // ----- f32 match (bits exato ou tolerante) -----
            let bits_a = v32a as u32;
            let bits_b = v32b as u32;
            if let Some(tb) = target_f32_bits {
                if bits_a == tb {
                    let fv = f32::from_bits(bits_a);
                    hits.push(SmartHit {
                        address: base_addr.wrapping_add(off as u64),
                        scan_type: ScanType::F32,
                        bytes: buffer[off..off + 4].to_vec(),
                        interpreted: format!("{}", fv),
                    });
                }
                if bits_b == tb {
                    let fv = f32::from_bits(bits_b);
                    hits.push(SmartHit {
                        address: base_addr.wrapping_add((off + 4) as u64),
                        scan_type: ScanType::F32,
                        bytes: buffer[off + 4..off + 8].to_vec(),
                        interpreted: format!("{}", fv),
                    });
                }
            } else {
                // Fallback: tolerante (apenas quando target nao bate exato em f32).
                let fva = f32::from_bits(bits_a);
                if fva.is_finite() && (fva as f64 - target_f).abs() <= eps {
                    hits.push(SmartHit {
                        address: base_addr.wrapping_add(off as u64),
                        scan_type: ScanType::F32,
                        bytes: buffer[off..off + 4].to_vec(),
                        interpreted: format!("{}", fva),
                    });
                }
                let fvb = f32::from_bits(bits_b);
                if fvb.is_finite() && (fvb as f64 - target_f).abs() <= eps {
                    hits.push(SmartHit {
                        address: base_addr.wrapping_add((off + 4) as u64),
                        scan_type: ScanType::F32,
                        bytes: buffer[off + 4..off + 8].to_vec(),
                        interpreted: format!("{}", fvb),
                    });
                }
            }

            // ----- i64 match exato -----
            if let Some(t) = target_i64 {
                if v64 == t {
                    hits.push(SmartHit {
                        address: base_addr.wrapping_add(off as u64),
                        scan_type: ScanType::I64,
                        bytes: buffer[off..off + 8].to_vec(),
                        interpreted: v64.to_string(),
                    });
                }
            }

            // ----- f64 bits -----
            let u64v = v64 as u64;
            if u64v == target_f64_bits {
                let fv = f64::from_bits(u64v);
                hits.push(SmartHit {
                    address: base_addr.wrapping_add(off as u64),
                    scan_type: ScanType::F64,
                    bytes: buffer[off..off + 8].to_vec(),
                    interpreted: format!("{}", fv),
                });
            }

            // ----- pointer -----
            if ptr_mode && u64v == target_ptr {
                hits.push(SmartHit {
                    address: base_addr.wrapping_add(off as u64),
                    scan_type: ScanType::Pointer,
                    bytes: buffer[off..off + 8].to_vec(),
                    interpreted: format!("0x{:X}", u64v),
                });
            }
        }
        off += 8;
    }

    // Cauda: possivel i32 remanescente.
    while off + 4 <= len {
        let v32 = unsafe { std::ptr::read_unaligned(p.add(off) as *const i32) };
        if target_i64.is_some_and(|t| (v32 as i64) == t) {
            hits.push(SmartHit {
                address: base_addr.wrapping_add(off as u64),
                scan_type: ScanType::I32,
                bytes: buffer[off..off + 4].to_vec(),
                interpreted: v32.to_string(),
            });
        }
        off += 4;
    }

    hits
}

fn scan_exact(buffer: &[u8], base_addr: u64, needle: &[u8]) -> Vec<SmartHit> {
    let len = buffer.len();
    let mut hits: Vec<SmartHit> = Vec::new();
    if needle.is_empty() || needle.len() > len {
        return hits;
    }

    let mut off = 0usize;
    while off + needle.len() <= len {
        if &buffer[off..off + needle.len()] == needle {
            let addr = base_addr.wrapping_add(off as u64);
            let scan_type = match needle.len() {
                4 if off % 4 == 0 => ScanType::I32,
                8 if off % 8 == 0 => ScanType::I64,
                _ => ScanType::StringAscii,
            };
            let interpreted = match scan_type {
                ScanType::I32 => {
                    let v = i32::from_le_bytes([needle[0], needle[1], needle[2], needle[3]]);
                    v.to_string()
                }
                ScanType::I64 => {
                    let v = i64::from_le_bytes([
                        needle[0], needle[1], needle[2], needle[3], needle[4], needle[5],
                        needle[6], needle[7],
                    ]);
                    v.to_string()
                }
                _ => String::from_utf8_lossy(needle).to_string(),
            };
            hits.push(SmartHit {
                address: addr,
                scan_type,
                bytes: needle.to_vec(),
                interpreted,
            });
        }
        off += 1;
    }
    hits
}

fn scan_any(buffer: &[u8], base_addr: u64) -> Vec<SmartHit> {
    let len = buffer.len();
    let mut hits: Vec<SmartHit> = Vec::new();

    // Pass 1: numeric sweep stride 4.
    let mut off = 0usize;
    while off + 4 <= len {
        let p = buffer.as_ptr();
        let v32 = unsafe { std::ptr::read_unaligned(p.add(off) as *const i32) };
        if is_reasonable_i32(v32) && v32 != 0 {
            let b = &buffer[off..off + 4];
            hits.push(SmartHit {
                address: base_addr.wrapping_add(off as u64),
                scan_type: ScanType::I32,
                bytes: b.to_vec(),
                interpreted: v32.to_string(),
            });
        }
        let f32v = f32::from_bits(v32 as u32);
        if is_reasonable_f32(f32v) && f32v != 0.0 {
            let b = &buffer[off..off + 4];
            hits.push(SmartHit {
                address: base_addr.wrapping_add(off as u64),
                scan_type: ScanType::F32,
                bytes: b.to_vec(),
                interpreted: format!("{}", f32v),
            });
        }

        if off + 8 <= len && off % 8 == 0 {
            let v64 = unsafe { std::ptr::read_unaligned(p.add(off) as *const i64) };
            let u64v = v64 as u64;
            if is_reasonable_i64(v64) && v64 != 0 {
                let b = &buffer[off..off + 8];
                hits.push(SmartHit {
                    address: base_addr.wrapping_add(off as u64),
                    scan_type: ScanType::I64,
                    bytes: b.to_vec(),
                    interpreted: v64.to_string(),
                });
            }
            let f64v = f64::from_bits(u64v);
            if is_reasonable_f64(f64v) && f64v != 0.0 {
                let b = &buffer[off..off + 8];
                hits.push(SmartHit {
                    address: base_addr.wrapping_add(off as u64),
                    scan_type: ScanType::F64,
                    bytes: b.to_vec(),
                    interpreted: format!("{}", f64v),
                });
            }
            if is_reasonable_pointer(u64v) {
                let b = &buffer[off..off + 8];
                hits.push(SmartHit {
                    address: base_addr.wrapping_add(off as u64),
                    scan_type: ScanType::Pointer,
                    bytes: b.to_vec(),
                    interpreted: format!("0x{:X}", u64v),
                });
            }
        }
        off += 4;
    }

    // Pass 2: strings byte a byte. Fail-fast: 1o byte precisa ser printable.
    let mut i = 0usize;
    while i < len {
        let b = buffer[i];
        if (0x20..=0x7E).contains(&b) {
            if let Some((s, l)) = try_ascii_string(&buffer[i..]) {
                hits.push(SmartHit {
                    address: base_addr.wrapping_add(i as u64),
                    scan_type: ScanType::StringAscii,
                    bytes: s.as_bytes().to_vec(),
                    interpreted: s,
                });
                i += l;
                continue;
            }
        }
        i += 1;
    }

    // Pass 3: UTF-16 em offsets pares com primeiro byte printable + segundo byte 0.
    let mut i = 0usize;
    while i + 10 <= len {
        if buffer[i + 1] == 0 && (0x20..=0x7E).contains(&buffer[i]) {
            if let Some((s, l)) = try_utf16_string(&buffer[i..]) {
                hits.push(SmartHit {
                    address: base_addr.wrapping_add(i as u64),
                    scan_type: ScanType::StringUtf16,
                    bytes: buffer[i..i + l.min(len - i)].to_vec(),
                    interpreted: s,
                });
                i += l;
                continue;
            }
        }
        i += 2;
    }

    hits
}

/// Formatacao conveniente de hits para logs/debug.
pub fn format_hits(hits: &[SmartHit]) -> String {
    let mut out = String::new();
    for h in hits {
        let _ = writeln!(
            out,
            "{:#018x}  {:<13} {:<24} [{}]",
            h.address,
            h.scan_type.as_str(),
            h.interpreted,
            fmt_bytes(&h.bytes)
        );
    }
    out
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn ascii_detection() {
        let mut buf = vec![0u8; 32];
        buf[0..5].copy_from_slice(b"hello");
        buf[5] = 0;
        let (s, l) = try_ascii_string(&buf).unwrap();
        assert_eq!(s, "hello");
        assert_eq!(l, 6);
    }

    #[test]
    fn utf16_detection() {
        let text = "hello";
        let mut bytes: Vec<u8> = Vec::new();
        for c in text.encode_utf16() {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0]);
        let (s, _) = try_utf16_string(&bytes).unwrap();
        assert_eq!(s, "hello");
    }

    #[test]
    fn numeric_exact_i32() {
        let mut buf = vec![0u8; 32];
        buf[4..8].copy_from_slice(&42i32.to_le_bytes());
        let hits = smart_scan(&buf, 0x1000, SmartTarget::Numeric(42.0));
        assert!(hits.iter().any(|h| h.scan_type == ScanType::I32 && h.address == 0x1004));
    }
}
