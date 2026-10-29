use crate::memory::aob_validator::{AobValidation, AobValidator};

const HEADER: &str = "# onyx-aob-library v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AobSignature {
    pub name: String,
    pub pattern: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureCheck {
    pub name: String,
    pub pattern: String,
    pub valid: bool,
    pub unique: bool,
    pub match_count: u64,
    pub first_match: Option<usize>,
    pub error: Option<String>,
    pub warning_flags: u32,
}

impl SignatureCheck {
    pub fn is_broken(&self) -> bool {
        !self.valid || self.match_count != 1
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignatureLibrary {
    signatures: Vec<AobSignature>,
}

impl SignatureLibrary {
    pub fn new() -> Self {
        Self {
            signatures: Vec::new(),
        }
    }

    pub fn add(&mut self, name: &str, pattern: &str) -> Result<(), String> {
        let name = name.trim();
        let pattern = pattern.trim();
        if name.is_empty() {
            return Err("signature name must not be empty".to_string());
        }
        if name.contains('\t') || name.contains('\n') {
            return Err("signature name must not contain tabs or newlines".to_string());
        }
        if pattern.is_empty() {
            return Err("signature pattern must not be empty".to_string());
        }
        AobValidator::parse(pattern).map_err(|e| {
            format!(
                "invalid pattern at token {} ({}): {}",
                e.token_index, e.token, e.message
            )
        })?;

        if let Some(existing) = self.signatures.iter_mut().find(|s| s.name == name) {
            existing.pattern = pattern.to_string();
        } else {
            self.signatures.push(AobSignature {
                name: name.to_string(),
                pattern: pattern.to_string(),
            });
        }
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.signatures.len();
        self.signatures.retain(|s| s.name != name);
        before != self.signatures.len()
    }

    pub fn get(&self, name: &str) -> Option<&AobSignature> {
        self.signatures.iter().find(|s| s.name == name)
    }

    pub fn names(&self) -> Vec<&str> {
        self.signatures.iter().map(|s| s.name.as_str()).collect()
    }

    pub fn signatures(&self) -> &[AobSignature] {
        &self.signatures
    }

    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    pub fn to_text(&self) -> String {
        let mut out = String::from(HEADER);
        out.push('\n');
        for sig in &self.signatures {
            out.push_str(&sig.name);
            out.push('\t');
            out.push_str(&sig.pattern);
            out.push('\n');
        }
        out
    }

    pub fn from_text(text: &str) -> Result<Self, String> {
        let mut library = Self::new();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, pattern) = line
                .split_once('\t')
                .ok_or_else(|| format!("line {}: expected \"name<TAB>pattern\"", index + 1))?;
            library
                .add(name, pattern)
                .map_err(|e| format!("line {}: {}", index + 1, e))?;
        }
        Ok(library)
    }

    pub fn load(path: &str) -> Result<Self, String> {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("failed to read {}: {}", path, e))?;
        Self::from_text(&text)
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        std::fs::write(path, self.to_text()).map_err(|e| format!("failed to write {}: {}", path, e))
    }

    pub fn validate_all(&self, buffer: &[u8], base: usize) -> Vec<SignatureCheck> {
        self.signatures
            .iter()
            .map(|sig| Self::check_signature(sig, buffer, base))
            .collect()
    }

    pub fn broken(&self, buffer: &[u8], base: usize) -> Vec<SignatureCheck> {
        self.validate_all(buffer, base)
            .into_iter()
            .filter(|check| check.is_broken())
            .collect()
    }

    fn check_signature(sig: &AobSignature, buffer: &[u8], base: usize) -> SignatureCheck {
        let validation: AobValidation = AobValidator::validate(&sig.pattern, buffer);
        SignatureCheck {
            name: sig.name.clone(),
            pattern: sig.pattern.clone(),
            valid: validation.valid,
            unique: validation.is_unique,
            match_count: validation.match_count,
            first_match: validation
                .match_offsets
                .first()
                .map(|offset| base.wrapping_add(*offset)),
            error: validation
                .error
                .as_ref()
                .map(|e| format!("token {} ({}): {}", e.token_index, e.token, e.message)),
            warning_flags: validation.warning_flags(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_buffer() -> Vec<u8> {
        let mut buf = vec![0u8; 64];
        buf[8..12].copy_from_slice(&[0x48, 0x8B, 0x05, 0x10]);
        buf[32..36].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        buf[40..44].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        buf
    }

    #[test]
    fn test_add_get_remove() {
        let mut lib = SignatureLibrary::new();
        lib.add("health", "48 8B 05 10").unwrap();
        assert_eq!(lib.len(), 1);
        assert_eq!(lib.get("health").unwrap().pattern, "48 8B 05 10");
        assert!(lib.remove("health"));
        assert!(!lib.remove("health"));
        assert!(lib.is_empty());
    }

    #[test]
    fn test_add_replaces_same_name() {
        let mut lib = SignatureLibrary::new();
        lib.add("sig", "48 8B").unwrap();
        lib.add("sig", "90 90").unwrap();
        assert_eq!(lib.len(), 1);
        assert_eq!(lib.get("sig").unwrap().pattern, "90 90");
    }

    #[test]
    fn test_add_rejects_bad_input() {
        let mut lib = SignatureLibrary::new();
        assert!(lib.add("", "90").is_err());
        assert!(lib.add("name", "").is_err());
        assert!(lib.add("na\tme", "90").is_err());
        assert!(lib.add("name", "ZZ").is_err());
        assert!(lib.is_empty());
    }

    #[test]
    fn test_text_roundtrip() {
        let mut lib = SignatureLibrary::new();
        lib.add("health", "48 8B 05 10").unwrap();
        lib.add("mana", "DE AD BE EF").unwrap();

        let text = lib.to_text();
        assert!(text.starts_with(HEADER));

        let parsed = SignatureLibrary::from_text(&text).unwrap();
        assert_eq!(parsed, lib);
        assert_eq!(parsed.names(), vec!["health", "mana"]);
    }

    #[test]
    fn test_from_text_ignores_comments_and_blank_lines() {
        let text = "# comment\n\n  \nsig\t90 90\n";
        let lib = SignatureLibrary::from_text(text).unwrap();
        assert_eq!(lib.len(), 1);
        assert_eq!(lib.get("sig").unwrap().pattern, "90 90");
    }

    #[test]
    fn test_from_text_reports_line_number() {
        let text = "# x\nsig\t90 90\nbadline\n";
        let err = SignatureLibrary::from_text(text).unwrap_err();
        assert!(err.contains("line 3"), "got: {}", err);
    }

    #[test]
    fn test_validate_all_detects_unique_ambiguous_and_invalid() {
        let mut lib = SignatureLibrary::new();
        lib.add("unique", "48 8B 05 10").unwrap();
        lib.add("ambiguous", "DE AD BE EF").unwrap();
        lib.add("missing", "11 22 33 44 55").unwrap();

        let buf = sample_buffer();
        let checks = lib.validate_all(&buf, 0x400000);

        let unique = checks.iter().find(|c| c.name == "unique").unwrap();
        assert!(unique.valid);
        assert!(unique.unique);
        assert_eq!(unique.match_count, 1);
        assert_eq!(unique.first_match, Some(0x400000 + 8));

        let ambiguous = checks.iter().find(|c| c.name == "ambiguous").unwrap();
        assert_eq!(ambiguous.match_count, 2);
        assert!(!ambiguous.unique);
        assert!(ambiguous.is_broken());

        let missing = checks.iter().find(|c| c.name == "missing").unwrap();
        assert_eq!(missing.match_count, 0);
        assert!(missing.is_broken());
    }

    #[test]
    fn test_invalid_pattern_is_reported() {
        let lib = SignatureLibrary {
            signatures: vec![AobSignature {
                name: "bad".to_string(),
                pattern: "ZZ".to_string(),
            }],
        };
        let checks = lib.validate_all(&[0u8; 16], 0);
        assert_eq!(checks.len(), 1);
        assert!(!checks[0].valid);
        assert!(checks[0].error.is_some());
        assert!(checks[0].is_broken());
    }

    #[test]
    fn test_broken_filters_only_problems() {
        let mut lib = SignatureLibrary::new();
        lib.add("unique", "48 8B 05 10").unwrap();
        lib.add("ambiguous", "DE AD BE EF").unwrap();

        let broken = lib.broken(&sample_buffer(), 0);
        assert_eq!(broken.len(), 1);
        assert_eq!(broken[0].name, "ambiguous");
    }

    #[test]
    fn test_save_and_load_file() {
        let mut lib = SignatureLibrary::new();
        lib.add("health", "48 8B 05 10").unwrap();

        let mut path = std::env::temp_dir();
        path.push(format!("onyx_siglib_{}.txt", std::process::id()));
        let path_str = path.to_string_lossy().to_string();

        lib.save(&path_str).unwrap();
        let loaded = SignatureLibrary::load(&path_str).unwrap();
        assert_eq!(loaded, lib);

        let _ = std::fs::remove_file(&path);
    }
}
