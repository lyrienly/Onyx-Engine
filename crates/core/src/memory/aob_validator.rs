
use crate::memory::scanner::AobByte;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AobError {
    pub token_index: usize,
    pub token: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AobWarning {
    NoExactByte,
    ShortPattern,
    TooManyMatches,
    PatternLongerThanBuffer,
}

impl AobWarning {
    pub fn as_str(&self) -> &'static str {
        match self {
            AobWarning::NoExactByte => "pattern has no exact byte (slow and ambiguous)",
            AobWarning::ShortPattern => "pattern is shorter than 8 bytes",
            AobWarning::TooManyMatches => "pattern matches too many places",
            AobWarning::PatternLongerThanBuffer => "pattern is longer than the buffer",
        }
    }

    pub fn flag(&self) -> u32 {
        match self {
            AobWarning::NoExactByte => 1,
            AobWarning::ShortPattern => 2,
            AobWarning::TooManyMatches => 4,
            AobWarning::PatternLongerThanBuffer => 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AobValidation {
    pub valid: bool,
    pub error: Option<AobError>,
    pub byte_len: usize,
    pub wildcard_count: usize,
    pub match_count: u64,
    pub is_unique: bool,
    pub match_offsets: Vec<usize>,
    pub warnings: Vec<AobWarning>,
}

impl AobValidation {
    pub fn warning_flags(&self) -> u32 {
        self.warnings.iter().fold(0, |acc, w| acc | w.flag())
    }
}

pub struct AobValidator;

impl AobValidator {
    pub fn parse(pattern: &str) -> Result<Vec<AobByte>, AobError> {
        let tokens: Vec<&str> = pattern.split_whitespace().collect();
        if tokens.is_empty() {
            return Err(AobError {
                token_index: 0,
                token: String::new(),
                message: "empty AOB pattern".to_string(),
            });
        }

        let mut bytes = Vec::with_capacity(tokens.len());
        for (index, token) in tokens.iter().enumerate() {
            match AobByte::parse(token) {
                Ok(byte) => bytes.push(byte),
                Err(message) => {
                    return Err(AobError {
                        token_index: index,
                        token: token.to_string(),
                        message,
                    })
                }
            }
        }
        Ok(bytes)
    }

    pub fn normalize(pattern: &str) -> Result<String, AobError> {
        let bytes = Self::parse(pattern)?;
        Ok(bytes
            .iter()
            .map(|b| b.to_pattern_token())
            .collect::<Vec<_>>()
            .join(" "))
    }

    pub fn find_matches(
        buffer: &[u8],
        pattern: &[AobByte],
        max_offsets: usize,
    ) -> (u64, Vec<usize>) {
        if pattern.is_empty() || buffer.len() < pattern.len() {
            return (0, Vec::new());
        }

        let mut count = 0u64;
        let mut offsets = Vec::new();
        let max_idx = buffer.len() - pattern.len();

        for i in 0..=max_idx {
            let matched = pattern
                .iter()
                .enumerate()
                .all(|(p_idx, byte)| byte.matches(buffer[i + p_idx]));
            if matched {
                count += 1;
                if offsets.len() < max_offsets {
                    offsets.push(i);
                }
            }
        }

        (count, offsets)
    }

    pub fn validate(pattern: &str, buffer: &[u8]) -> AobValidation {
        match Self::parse(pattern) {
            Err(error) => AobValidation {
                valid: false,
                error: Some(error),
                byte_len: 0,
                wildcard_count: 0,
                match_count: 0,
                is_unique: false,
                match_offsets: Vec::new(),
                warnings: Vec::new(),
            },
            Ok(bytes) => Self::validate_bytes(&bytes, buffer),
        }
    }

    pub fn validate_bytes(bytes: &[AobByte], buffer: &[u8]) -> AobValidation {
        if bytes.is_empty() {
            return AobValidation {
                valid: false,
                error: Some(AobError {
                    token_index: 0,
                    token: String::new(),
                    message: "empty AOB pattern".to_string(),
                }),
                byte_len: 0,
                wildcard_count: 0,
                match_count: 0,
                is_unique: false,
                match_offsets: Vec::new(),
                warnings: Vec::new(),
            };
        }

        let wildcard_count = bytes.iter().filter(|b| !b.is_exact()).count();
        let exact_count = bytes.len() - wildcard_count;

        let mut warnings = Vec::new();
        if exact_count == 0 {
            warnings.push(AobWarning::NoExactByte);
        } else if bytes.len() < 8 {
            warnings.push(AobWarning::ShortPattern);
        }
        if buffer.len() < bytes.len() {
            warnings.push(AobWarning::PatternLongerThanBuffer);
        }

        let (match_count, match_offsets) = if buffer.is_empty() {
            (0, Vec::new())
        } else {
            Self::find_matches(buffer, bytes, 64)
        };

        if match_count > 1000 {
            warnings.push(AobWarning::TooManyMatches);
        }

        AobValidation {
            valid: true,
            error: None,
            byte_len: bytes.len(),
            wildcard_count,
            match_count,
            is_unique: match_count == 1,
            match_offsets,
            warnings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_and_normalize() {
        assert_eq!(
            AobValidator::normalize("e9 ?? a? ?3 0XFF").unwrap(),
            "E9 ?? A? ?3 FF"
        );
    }

    #[test]
    fn test_parse_error_reports_token_index() {
        let err = AobValidator::parse("E9 ZZ 90").unwrap_err();
        assert_eq!(err.token_index, 1);
        assert_eq!(err.token, "ZZ");
    }

    #[test]
    fn test_empty_pattern_is_invalid() {
        let v = AobValidator::validate("   ", &[0u8; 16]);
        assert!(!v.valid);
        assert!(v.error.is_some());
    }

    #[test]
    fn test_unique_match() {
        let mut buf = vec![0u8; 64];
        buf[10..13].copy_from_slice(&[0x48, 0x8B, 0xC1]);
        let v = AobValidator::validate("48 8B C1", &buf);
        assert!(v.valid);
        assert_eq!(v.match_count, 1);
        assert!(v.is_unique);
        assert_eq!(v.match_offsets, vec![10]);
    }

    #[test]
    fn test_multiple_matches_not_unique() {
        let mut buf = vec![0u8; 32];
        buf[4..6].copy_from_slice(&[0xDE, 0xAD]);
        buf[20..22].copy_from_slice(&[0xDE, 0xAD]);
        let v = AobValidator::validate("DE AD", &buf);
        assert_eq!(v.match_count, 2);
        assert!(!v.is_unique);
        assert_eq!(v.match_offsets, vec![4, 20]);
    }

    #[test]
    fn test_wildcards_counted() {
        let v = AobValidator::validate("48 ?? A? ?3 C1", &[0u8; 16]);
        assert_eq!(v.byte_len, 5);
        assert_eq!(v.wildcard_count, 3);
        assert!(v.warnings.contains(&AobWarning::ShortPattern));
    }

    #[test]
    fn test_no_exact_byte_warning() {
        let v = AobValidator::validate("?? ?? ?? ?? ?? ?? ?? ?? ??", &[0u8; 32]);
        assert!(v.warnings.contains(&AobWarning::NoExactByte));
        assert_eq!(v.match_count, 24);
    }

    #[test]
    fn test_pattern_longer_than_buffer() {
        let v = AobValidator::validate("48 8B C1 90 90 90", &[0u8; 4]);
        assert!(v.warnings.contains(&AobWarning::PatternLongerThanBuffer));
        assert_eq!(v.match_count, 0);
    }

    #[test]
    fn test_warning_flags() {
        let v = AobValidator::validate("?? ?? ??", &[0u8; 16]);
        assert_eq!(v.warning_flags() & AobWarning::NoExactByte.flag(), 1);
    }
}
