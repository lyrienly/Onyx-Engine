use crate::process::Process;
use crate::debugger::disasm::Disassembler;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringReferenceMatch {
    pub instruction_address: usize,
    pub string_address: usize,
    pub text: String,
    pub is_unicode: bool,
    pub mnemonic: String,
    pub operands: String,
}

pub struct StringReferencer;

impl StringReferencer {

    pub fn try_extract_ascii(bytes: &[u8], min_len: usize) -> Option<String> {
        if bytes.len() < min_len {
            return None;
        }

        let mut len = 0;
        for &b in bytes {
            if b == 0 {
                break;
            }
            if !(0x20..=0x7E).contains(&b) && b != b'\t' && b != b'\r' && b != b'\n' {
                return None;
            }
            len += 1;
        }

        if len >= min_len {
            Some(String::from_utf8_lossy(&bytes[..len]).to_string())
        } else {
            None
        }
    }

    pub fn try_extract_utf16(bytes: &[u8], min_len: usize) -> Option<String> {
        if bytes.len() < min_len * 2 {
            return None;
        }

        let mut u16_chars = Vec::new();
        for chunk in bytes.as_chunks::<2>().0 {
            let val = u16::from_le_bytes([chunk[0], chunk[1]]);
            if val == 0 {
                break;
            }
            if !(0x20..=0x7E).contains(&val) && val != 0x09 && val != 0x0A && val != 0x0D {
                return None;
            }
            u16_chars.push(val);
        }

        if u16_chars.len() >= min_len {
            Some(String::from_utf16_lossy(&u16_chars))
        } else {
            None
        }
    }

    pub fn scan_process(
        proc: &Process,
        start: usize,
        stop: usize,
        min_string_len: usize,
    ) -> Result<Vec<StringReferenceMatch>, String> {
        let regions = proc.regions(false)?;
        let mut results = Vec::new();

        for r in regions {
            if r.base >= stop || (r.base + r.size) <= start {
                continue;
            }
            if !r.is_readable() || !r.is_executable() {
                continue;
            }

            let region_start = r.base.max(start);
            let region_end = (r.base + r.size).min(stop);
            let read_len = region_end.saturating_sub(region_start);
            if read_len == 0 {
                continue;
            }

            let code = match proc.read_bytes(region_start, read_len) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let mut offset = 0;
            while offset < code.len() {
                let insn_addr = region_start + offset;
                let insn = Disassembler::decode_one(insn_addr, &code[offset..]);
                let len = insn.length.max(1);

                if let Some(target) = insn.target_addr

                    && let Ok(target_bytes) = proc.read_bytes(target, 128) {
                        if let Some(ascii_str) = Self::try_extract_ascii(&target_bytes, min_string_len) {
                            results.push(StringReferenceMatch {
                                instruction_address: insn_addr,
                                string_address: target,
                                text: ascii_str,
                                is_unicode: false,
                                mnemonic: insn.mnemonic.clone(),
                                operands: insn.operands.clone(),
                            });
                        } else if let Some(utf16_str) = Self::try_extract_utf16(&target_bytes, min_string_len) {
                            results.push(StringReferenceMatch {
                                instruction_address: insn_addr,
                                string_address: target,
                                text: utf16_str,
                                is_unicode: true,
                                mnemonic: insn.mnemonic.clone(),
                                operands: insn.operands.clone(),
                            });
                        }
                    }

                offset += len;
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ascii() {
        let text = b"PlayerHealth_Max\0junkdata";
        let res = StringReferencer::try_extract_ascii(text, 4);
        assert_eq!(res, Some("PlayerHealth_Max".to_string()));

        let short = b"abc\0";
        assert_eq!(StringReferencer::try_extract_ascii(short, 4), None);
    }

    #[test]
    fn test_extract_utf16() {
        let utf16_bytes = vec![
            b'G', 0, b'a', 0, b'm', 0, b'e', 0, b'O', 0, b'v', 0, b'e', 0, b'r', 0, 0, 0,
        ];
        let res = StringReferencer::try_extract_utf16(&utf16_bytes, 4);
        assert_eq!(res, Some("GameOver".to_string()));
    }
}
