
use crate::process::Process;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyClass {
    Zero,
    Plain,
    Code,
    Compressed,
    Encrypted,
}

impl EntropyClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntropyClass::Zero => "zero",
            EntropyClass::Plain => "plaintext",
            EntropyClass::Code => "code",
            EntropyClass::Compressed => "compressed",
            EntropyClass::Encrypted => "encrypted",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EntropyReport {
    pub base: usize,
    pub size: usize,
    pub entropy: f64,
    pub class: EntropyClass,
}

pub struct EntropyScanner;

impl EntropyScanner {
    pub fn shannon_entropy(buf: &[u8]) -> f64 {
        if buf.is_empty() {
            return 0.0;
        }
        let mut counts = [0u64; 256];
        for &b in buf {
            counts[b as usize] += 1;
        }
        let len = buf.len() as f64;
        let mut entropy = 0.0;
        for &c in counts.iter() {
            if c == 0 {
                continue;
            }
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
        entropy
    }

    pub fn classify(buf: &[u8]) -> EntropyClass {
        Self::classify_entropy(Self::shannon_entropy(buf), buf)
    }

    pub fn classify_entropy(entropy: f64, buf: &[u8]) -> EntropyClass {
        if buf.iter().all(|&b| b == 0) {
            return EntropyClass::Zero;
        }
        if entropy < 3.5 {
            EntropyClass::Plain
        } else if entropy < 6.5 {
            EntropyClass::Code
        } else if entropy < 7.5 {
            EntropyClass::Compressed
        } else {
            EntropyClass::Encrypted
        }
    }

    pub fn analyze(
        proc: &Process,
        start: usize,
        stop: usize,
        sample_cap: usize,
    ) -> Result<Vec<EntropyReport>, String> {
        let regions = proc.regions(false)?;
        let mut reports = Vec::new();

        for r in regions {
            if r.base >= stop || (r.base + r.size) <= start {
                continue;
            }
            if !r.is_readable() {
                continue;
            }

            let region_start = r.base.max(start);
            let region_end = (r.base + r.size).min(stop);
            let total_len = region_end.saturating_sub(region_start);
            if total_len == 0 {
                continue;
            }

            let read_len = total_len.min(sample_cap);
            let data = proc.read_bytes(region_start, read_len)?;
            let entropy = Self::shannon_entropy(&data);
            let class = Self::classify_entropy(entropy, &data);

            reports.push(EntropyReport {
                base: region_start,
                size: read_len,
                entropy,
                class,
            });
        }

        Ok(reports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_bounds() {
        assert_eq!(EntropyScanner::shannon_entropy(&[]), 0.0);
        assert_eq!(EntropyScanner::shannon_entropy(&[0u8; 256]), 0.0);
        assert_eq!(EntropyScanner::shannon_entropy(&[0xFFu8; 256]), 0.0);
    }

    #[test]
    fn test_shannon_entropy_full_range() {
        let mut buf = Vec::with_capacity(256);
        for _ in 0..256 {
            for b in 0u8..=255u8 {
                buf.push(b);
            }
        }
        let e = EntropyScanner::shannon_entropy(&buf);
        assert!((e - 8.0).abs() < 1e-9, "uniform 256-symbol buffer must be 8.0, got {}", e);
    }

    #[test]
    fn test_classify() {
        assert_eq!(EntropyScanner::classify(&[0u8; 4096]), EntropyClass::Zero);

        let mut full = Vec::with_capacity(1024);
        for i in 0..1024 {
            full.push((i % 251) as u8);
        }
        assert_eq!(EntropyScanner::classify(&full), EntropyClass::Encrypted);

        let low = vec![0xAA, 0xBB].repeat(512);
        assert_eq!(EntropyScanner::classify(&low), EntropyClass::Plain);
    }

    #[test]
    fn test_classify_thresholds() {
        let nonzero = vec![1u8; 64];
        assert_eq!(EntropyScanner::classify_entropy(1.0, &nonzero), EntropyClass::Plain);
        assert_eq!(EntropyScanner::classify_entropy(5.0, &nonzero), EntropyClass::Code);
        assert_eq!(EntropyScanner::classify_entropy(7.0, &nonzero), EntropyClass::Compressed);
        assert_eq!(EntropyScanner::classify_entropy(7.9, &nonzero), EntropyClass::Encrypted);
    }
}
