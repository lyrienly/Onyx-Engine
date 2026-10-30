use onyx_core::process::{Process, ProcessAccessMode};
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    Empty,
    InvalidToken(String),
    AllWildcards,
}

#[derive(Debug, Clone)]
pub struct Pattern {
    pub bytes: Vec<u8>,
    pub mask: Vec<bool>,
}

impl Pattern {
    pub fn parse(pattern_str: &str) -> Result<Self, PatternError> {
        let mut bytes = Vec::new();
        let mut mask = Vec::new();

        for tok in pattern_str.split_ascii_whitespace() {
            if tok == "??" || tok == "?" {
                bytes.push(0);
                mask.push(false);
            } else if tok.len() == 2 || tok.len() == 1 {
                match u8::from_str_radix(tok, 16) {
                    Ok(b) => {
                        bytes.push(b);
                        mask.push(true);
                    }
                    Err(_) => return Err(PatternError::InvalidToken(tok.to_string())),
                }
            } else {
                return Err(PatternError::InvalidToken(tok.to_string()));
            }
        }

        if bytes.is_empty() {
            return Err(PatternError::Empty);
        }
        if mask.iter().all(|&m| !m) {
            return Err(PatternError::AllWildcards);
        }

        Ok(Pattern { bytes, mask })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[inline]
fn matches_at(haystack: &[u8], pos: usize, needle: &[u8], mask: &[bool]) -> bool {
    for i in 0..needle.len() {
        if mask[i] && haystack[pos + i] != needle[i] {
            return false;
        }
    }
    true
}

pub fn find_pattern_scalar(haystack: &[u8], needle: &[u8], mask: &[bool]) -> Option<usize> {
    let n = needle.len();
    if n == 0 || haystack.len() < n {
        return None;
    }

    let mut suffix_start = n;
    for i in (0..n).rev() {
        if mask[i] {
            suffix_start = i;
        } else {
            break;
        }
    }

    let suf_len = n - suffix_start;
    let effective = if suf_len == 0 { 1 } else { suf_len };

    let mut skip = [effective; 256];

    for i in 0..n - 1 {
        if mask[i] {
            let dist_from_end = n - 1 - i;
            if dist_from_end < effective {
                skip[needle[i] as usize] = dist_from_end;
            }
        }
    }

    let mut pos = 0;
    let last = n - 1;
    while pos + n <= haystack.len() {
        if matches_at(haystack, pos, needle, mask) {
            return Some(pos);
        }

        let shift = skip[haystack[pos + last] as usize];
        pos += shift.max(1);
    }

    None
}

pub fn find_all_scalar(haystack: &[u8], needle: &[u8], mask: &[bool]) -> Vec<usize> {
    let mut out = Vec::new();
    let n = needle.len();
    if n == 0 || haystack.len() < n {
        return out;
    }
    let mut pos = 0;
    while pos + n <= haystack.len() {
        if matches_at(haystack, pos, needle, mask) {
            out.push(pos);
            pos += 1;
        } else {
            pos += 1;
        }
    }
    out
}

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use super::matches_at;
    use std::arch::x86_64::*;

    #[target_feature(enable = "avx2")]
    pub unsafe fn find_pattern_avx2(
        haystack: &[u8],
        needle: &[u8],
        mask: &[bool],
    ) -> Option<usize> {
        let n = needle.len();
        if n == 0 || haystack.len() < n {
            return None;
        }

        let mut anchor_idx = 0usize;
        while anchor_idx < n && !mask[anchor_idx] {
            anchor_idx += 1;
        }
        if anchor_idx == n {
            return None;
        }

        let mut second_idx = anchor_idx + 1;
        while second_idx < n && !mask[second_idx] {
            second_idx += 1;
        }

        let anchor_byte = needle[anchor_idx];
        let anchor_v = _mm256_set1_epi8(anchor_byte as i8);

        let has_second = second_idx < n;
        let second_byte = if has_second { needle[second_idx] } else { 0u8 };
        let second_v = _mm256_set1_epi8(second_byte as i8);
        let second_off = second_idx.wrapping_sub(anchor_idx);

        let end = haystack.len().saturating_sub(n);

        let mut p: usize = 0;
        while p <= end {
            let anchor_pos = p + anchor_idx;
            if anchor_pos + 32 > haystack.len() {
                break;
            }
            let chunk = _mm256_loadu_si256(haystack.as_ptr().add(anchor_pos) as *const __m256i);
            let eq = _mm256_cmpeq_epi8(chunk, anchor_v);
            let mut mask_bits = _mm256_movemask_epi8(eq) as u32;

            if has_second {
                let sec_pos = anchor_pos + second_off;
                if sec_pos + 32 <= haystack.len() {
                    let chunk2 =
                        _mm256_loadu_si256(haystack.as_ptr().add(sec_pos) as *const __m256i);
                    let eq2 = _mm256_cmpeq_epi8(chunk2, second_v);
                    let mask2 = _mm256_movemask_epi8(eq2) as u32;
                    mask_bits &= mask2;
                }
            }

            while mask_bits != 0 {
                let bit = mask_bits.trailing_zeros() as usize;
                let candidate = p + bit;
                if candidate <= end && matches_at(haystack, candidate, needle, mask) {
                    return Some(candidate);
                }
                mask_bits &= mask_bits - 1;
            }

            p += 32;
        }

        let fallback_start = if p == 0 { 0 } else { p };
        (fallback_start..=end).find(|&q| matches_at(haystack, q, needle, mask))
    }

    #[target_feature(enable = "avx2")]
    pub unsafe fn find_all_avx2(haystack: &[u8], needle: &[u8], mask: &[bool]) -> Vec<usize> {
        let mut out = Vec::new();
        let n = needle.len();
        if n == 0 || haystack.len() < n {
            return out;
        }

        let mut anchor_idx = 0usize;
        while anchor_idx < n && !mask[anchor_idx] {
            anchor_idx += 1;
        }
        if anchor_idx == n {
            return out;
        }
        let mut second_idx = anchor_idx + 1;
        while second_idx < n && !mask[second_idx] {
            second_idx += 1;
        }

        let anchor_byte = needle[anchor_idx];
        let anchor_v = _mm256_set1_epi8(anchor_byte as i8);
        let has_second = second_idx < n;
        let second_byte = if has_second { needle[second_idx] } else { 0u8 };
        let second_v = _mm256_set1_epi8(second_byte as i8);
        let second_off = second_idx.wrapping_sub(anchor_idx);

        let end = haystack.len().saturating_sub(n);
        let mut p: usize = 0;
        while p <= end {
            let anchor_pos = p + anchor_idx;
            if anchor_pos + 32 > haystack.len() {
                break;
            }
            let chunk = _mm256_loadu_si256(haystack.as_ptr().add(anchor_pos) as *const __m256i);
            let eq = _mm256_cmpeq_epi8(chunk, anchor_v);
            let mut mask_bits = _mm256_movemask_epi8(eq) as u32;

            if has_second {
                let sec_pos = anchor_pos + second_off;
                if sec_pos + 32 <= haystack.len() {
                    let chunk2 =
                        _mm256_loadu_si256(haystack.as_ptr().add(sec_pos) as *const __m256i);
                    let eq2 = _mm256_cmpeq_epi8(chunk2, second_v);
                    let mask2 = _mm256_movemask_epi8(eq2) as u32;
                    mask_bits &= mask2;
                }
            }

            while mask_bits != 0 {
                let bit = mask_bits.trailing_zeros() as usize;
                let candidate = p + bit;
                if candidate <= end && matches_at(haystack, candidate, needle, mask) {
                    out.push(candidate);
                }
                mask_bits &= mask_bits - 1;
            }

            p += 32;
        }

        let fallback_start = if p == 0 { 0 } else { p };
        for q in fallback_start..=end {
            if matches_at(haystack, q, needle, mask) && !out.last().is_some_and(|&l| l == q) {
                out.push(q);
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }
}

fn avx2_supported() -> bool {
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

pub fn find_pattern(haystack: &[u8], pattern_str: &str) -> Option<usize> {
    let p = Pattern::parse(pattern_str).ok()?;
    find_pattern_with(haystack, &p)
}

pub fn find_pattern_with(haystack: &[u8], pattern: &Pattern) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if avx2_supported() {
            unsafe {
                return avx2::find_pattern_avx2(haystack, &pattern.bytes, &pattern.mask);
            }
        }
    }
    find_pattern_scalar(haystack, &pattern.bytes, &pattern.mask)
}

pub fn find_all(haystack: &[u8], pattern_str: &str) -> Vec<usize> {
    let p = match Pattern::parse(pattern_str) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    find_all_with(haystack, &p)
}

pub fn find_all_with(haystack: &[u8], pattern: &Pattern) -> Vec<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if avx2_supported() {
            unsafe {
                return avx2::find_all_avx2(haystack, &pattern.bytes, &pattern.mask);
            }
        }
    }
    find_all_scalar(haystack, &pattern.bytes, &pattern.mask)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanEngineStrategy {
    #[default]
    Auto,
    UserModeAvx2,
    KernelPhysical,
}

pub fn scan_pattern_process(
    proc: &Process,
    pattern: &Pattern,
    start_addr: usize,
    size: usize,
    strategy: ScanEngineStrategy,
) -> Result<Vec<usize>, String> {
    if pattern.is_empty() {
        return Err("Empty pattern".to_string());
    }

    if (strategy == ScanEngineStrategy::KernelPhysical || strategy == ScanEngineStrategy::Auto)
        && proc.access_mode == ProcessAccessMode::KernelDbk
        && pattern.len() <= 64
    {
        if let Some(ref dbk) = proc.dbk {
            let mask_bytes: Vec<u8> = pattern
                .mask
                .iter()
                .map(|&m| if m { 0xFF } else { 0x00 })
                .collect();
            if let Ok(matches) = dbk.pattern_scan_cr3(
                proc.pid,
                start_addr as u64,
                size as u64,
                &pattern.bytes,
                &mask_bytes,
            ) {
                if !matches.is_empty() {
                    return Ok(matches.into_iter().map(|m| m as usize).collect());
                }
            }
        }
    }

    let chunk_size = 512 * 1024;
    let mut buf = vec![0u8; chunk_size];
    let mut results = Vec::new();
    let mut offset = 0;
    let n = pattern.len();

    while offset < size {
        let cur_size = (size - offset).min(chunk_size);
        let cur_addr = start_addr + offset;

        if let Ok(bytes_read) = proc.read_raw(cur_addr, &mut buf[..cur_size]) {
            if bytes_read >= n {
                let matches = find_all_with(&buf[..bytes_read], pattern);
                for m in matches {
                    results.push(cur_addr + m);
                }
            }
        }

        if offset + cur_size < size {
            offset += cur_size.saturating_sub(n.saturating_sub(1));
        } else {
            break;
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let p = Pattern::parse("48 8B ?? ?? E8 ?? ?? ?? ??").unwrap();
        assert_eq!(p.bytes.len(), 9);
        assert_eq!(
            p.mask,
            vec![true, true, false, false, true, false, false, false, false]
        );
        assert_eq!(p.bytes[0], 0x48);
        assert_eq!(p.bytes[1], 0x8B);
        assert_eq!(p.bytes[4], 0xE8);
    }

    #[test]
    fn parse_single_q() {
        let p = Pattern::parse("48 ? 8B").unwrap();
        assert_eq!(p.mask, vec![true, false, true]);
    }

    #[test]
    fn parse_invalid() {
        assert!(Pattern::parse("ZZ").is_err());
        assert!(Pattern::parse("").is_err());
        assert!(Pattern::parse("?? ??").is_err());
    }

    #[test]
    fn scalar_simple() {
        let hay = b"\x00\x00\x48\x8B\x05\xDE\xAD\xBE\xEF\xE8\x11\x22\x33\x44\x00\x00";
        let p = Pattern::parse("48 8B ?? ?? ?? ?? ?? E8").unwrap();
        let r = find_pattern_scalar(hay, &p.bytes, &p.mask);
        assert_eq!(r, Some(2));
    }

    #[test]
    fn scalar_not_found() {
        let hay = b"\x00\x00\x00\x00";
        let p = Pattern::parse("DE AD BE EF").unwrap();
        assert_eq!(find_pattern_scalar(hay, &p.bytes, &p.mask), None);
    }

    #[test]
    fn find_all_scalar_multi() {
        let hay = b"\xAA\xBB\xCC\x00\xAA\xBB\xCC\x00\xAA\xBB\xCC";
        let p = Pattern::parse("AA BB CC").unwrap();
        assert_eq!(find_all_scalar(hay, &p.bytes, &p.mask), vec![0, 4, 8]);
    }

    #[test]
    fn api_find_pattern() {
        let mut hay = vec![0u8; 10_000];
        hay[5000] = 0x48;
        hay[5001] = 0x8B;
        hay[5002] = 0x15;
        hay[5003] = 0xAA;
        hay[5004] = 0xBB;
        hay[5005] = 0xCC;
        hay[5006] = 0xDD;
        hay[5007] = 0xE8;
        let r = find_pattern(&hay, "48 8B ?? ?? ?? ?? ?? E8");
        assert_eq!(r, Some(5000));
    }
}
