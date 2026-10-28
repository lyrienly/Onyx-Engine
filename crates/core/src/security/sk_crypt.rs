pub struct SkCrypt;

impl SkCrypt {
    #[inline(always)]
    pub fn decrypt_xor(data: &[u8], key1: u8, key2: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for (i, &b) in data.iter().enumerate() {
            let k = key1.wrapping_add((i as u8) % (1 + key2));
            out.push(b ^ k);
        }
        out
    }

    #[inline(always)]
    pub fn decrypt_string(data: &[u8], key1: u8, key2: u8) -> String {
        let decrypted = Self::decrypt_xor(data, key1, key2);
        let end = decrypted.iter().position(|&c| c == 0).unwrap_or(decrypted.len());
        String::from_utf8_lossy(&decrypted[..end]).to_string()
    }

    #[inline(always)]
    pub fn encrypt_bytes(data: &[u8], key1: u8, key2: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for (i, &b) in data.iter().enumerate() {
            let k = key1.wrapping_add((i as u8) % (1 + key2));
            out.push(b ^ k);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skcrypt_roundtrip() {
        let original = b"OnyxEngine Stealth Test\0";
        let encrypted = SkCrypt::encrypt_bytes(original, 0x5A, 0x0F);
        let decrypted = SkCrypt::decrypt_string(&encrypted, 0x5A, 0x0F);
        assert_eq!(decrypted, "OnyxEngine Stealth Test");
    }
}
