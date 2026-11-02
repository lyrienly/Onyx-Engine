// High-grade compile-time string encryption and stack-zeroing RAII wrapper.
// Zero plaintext strings in .rdata / binary image.

use std::ops::Deref;
use std::sync::atomic::{Ordering, compiler_fence};

/// Compile-time pseudo-random key generator based on FNV-1a hash
pub const fn fnv1a_hash(s: &str, seed: u64) -> u64 {
    let bytes = s.as_bytes();
    let mut hash = 0xcbf29ce484222325 ^ seed;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(0x100000001b3);
        i += 1;
    }
    hash
}

/// Encrypts bytes at compile-time with dual-key sliding XOR
pub const fn const_encrypt<const N: usize>(input: &[u8; N], key1: u8, key2: u8) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        let k = key1.wrapping_add((i as u8) % (1 + key2));
        out[i] = input[i] ^ k;
        i += 1;
    }
    out
}

/// RAII wrapper holding decrypted string on stack; volatile zeroizes on drop.
pub struct ObfStr<const N: usize> {
    buffer: [u8; N],
    len: usize,
}

impl<const N: usize> ObfStr<N> {
    #[inline(always)]
    pub fn new(encrypted: &[u8; N], key1: u8, key2: u8) -> Self {
        let mut buffer = [0u8; N];
        let mut i = 0;
        while i < N {
            let k = key1.wrapping_add((i as u8) % (1 + key2));
            buffer[i] = encrypted[i] ^ k;
            i += 1;
        }
        compiler_fence(Ordering::SeqCst);

        let mut len = N;
        let mut j = 0;
        while j < N {
            if buffer[j] == 0 {
                len = j;
                break;
            }
            j += 1;
        }

        Self { buffer, len }
    }

    #[inline(always)]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buffer[..self.len]).unwrap_or("")
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..self.len]
    }
}

impl<const N: usize> Deref for ObfStr<N> {
    type Target = str;
    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl<const N: usize> Drop for ObfStr<N> {
    #[inline(always)]
    fn drop(&mut self) {
        for b in self.buffer.iter_mut() {
            unsafe {
                std::ptr::write_volatile(b, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Compile-time string encryption macro.
/// Output has zero plaintext in compiled binary.
#[macro_export]
macro_rules! sk_crypt {
    ($s:expr) => {{
        const STR_BYTES: &[u8] = $s.as_bytes();
        const N: usize = STR_BYTES.len();
        const KEY1: u8 =
            ($crate::security::sk_crypt::fnv1a_hash(concat!(file!(), ":", line!()), 0x9E3779B9)
                & 0xFF) as u8;
        const KEY2: u8 =
            (($crate::security::sk_crypt::fnv1a_hash(concat!(file!(), ":", line!()), 0x85EBCA6B)
                >> 8)
                & 0x0F) as u8;

        const ENCRYPTED: [u8; N] = {
            let mut arr = [0u8; N];
            let mut i = 0;
            while i < N {
                arr[i] = STR_BYTES[i];
                i += 1;
            }
            $crate::security::sk_crypt::const_encrypt(&arr, KEY1, KEY2)
        };

        $crate::security::sk_crypt::ObfStr::new(&ENCRYPTED, KEY1, KEY2)
    }};
}

/// Compile-time API name hashing (DJB2) for dynamic resolution without strings
pub const fn hash_api(name: &str) -> u32 {
    let bytes = name.as_bytes();
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < bytes.len() {
        hash = hash.wrapping_mul(33).wrapping_add(bytes[i] as u32);
        i += 1;
    }
    hash
}

#[macro_export]
macro_rules! api_hash {
    ($name:expr) => {
        $crate::security::sk_crypt::hash_api($name)
    };
}

// Backward compatibility with previous SkCrypt struct
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
        let end = decrypted
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(decrypted.len());
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

    #[test]
    fn test_skcrypt_macro_compile_time() {
        let s = sk_crypt!("Sensitive Anti-Cheat Vector String 0xDEADBEEF");
        assert_eq!(&*s, "Sensitive Anti-Cheat Vector String 0xDEADBEEF");
        assert_eq!(s.as_str(), "Sensitive Anti-Cheat Vector String 0xDEADBEEF");
    }

    #[test]
    fn test_api_hash() {
        const HASH_NT_QUERY: u32 = api_hash!("NtQuerySystemInformation");
        assert_ne!(HASH_NT_QUERY, 0);
        assert_eq!(HASH_NT_QUERY, hash_api("NtQuerySystemInformation"));
    }
}
