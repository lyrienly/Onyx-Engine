//! framing e parsing do gdb remote serial protocol
//!
//! formato: `$<data>#<xx>` onde xx eh checksum (mod 256) em hex ascii.
//! ack: `+` (ok) ou `-` (reenviar).

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub data: Vec<u8>,
}

impl Packet {
    pub fn new<T: Into<Vec<u8>>>(data: T) -> Self {
        Self { data: data.into() }
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.data).unwrap_or("")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Incomplete,
    MissingStart,
    BadChecksum { expected: u8, actual: u8 },
    BadHex,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Incomplete => write!(f, "pacote incompleto"),
            ParseError::MissingStart => write!(f, "sem delimitador $"),
            ParseError::BadChecksum { expected, actual } => {
                write!(f, "checksum invalido esperado={:02x} atual={:02x}", expected, actual)
            }
            ParseError::BadHex => write!(f, "hex invalido no checksum"),
        }
    }
}

impl std::error::Error for ParseError {}

pub fn checksum(data: &[u8]) -> u8 {
    let mut sum: u32 = 0;
    for &b in data {
        sum = sum.wrapping_add(b as u32);
    }
    (sum & 0xff) as u8
}

pub fn encode_packet(data: &[u8]) -> Vec<u8> {
    let cs = checksum(data);
    let mut out = Vec::with_capacity(data.len() + 4);
    out.push(b'$');
    out.extend_from_slice(data);
    out.push(b'#');
    out.extend_from_slice(format!("{:02x}", cs).as_bytes());
    out
}

/// faz parse de um pacote em `bytes`. retorna o pacote e quantos bytes consumidos.
/// pula bytes de ack/nack iniciais (`+`/`-`).
pub fn parse_packet(bytes: &[u8]) -> Result<(Packet, usize), ParseError> {
    let mut i = 0;
    while i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
        i += 1;
    }
    if i >= bytes.len() {
        return Err(ParseError::Incomplete);
    }
    if bytes[i] != b'$' {
        return Err(ParseError::MissingStart);
    }
    let start = i + 1;
    let mut end = start;
    while end < bytes.len() && bytes[end] != b'#' {
        end += 1;
    }
    if end >= bytes.len() || end + 2 >= bytes.len() {
        return Err(ParseError::Incomplete);
    }
    let data = &bytes[start..end];
    let cs_hi = hex_val(bytes[end + 1])?;
    let cs_lo = hex_val(bytes[end + 2])?;
    let expected = (cs_hi << 4) | cs_lo;
    let actual = checksum(data);
    if expected != actual {
        return Err(ParseError::BadChecksum { expected, actual });
    }
    Ok((Packet::new(data.to_vec()), end + 3))
}

fn hex_val(b: u8) -> Result<u8, ParseError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(ParseError::BadHex),
    }
}

/// bytes -> string hex little-endian irrelevante aqui (apenas hex ascii dos bytes).
pub fn bytes_to_hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, ParseError> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(ParseError::BadHex);
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// parse de inteiro hex em string (ex: "deadbeef")
pub fn parse_hex_u64(s: &str) -> Result<u64, ParseError> {
    if s.is_empty() {
        return Err(ParseError::BadHex);
    }
    let mut v: u64 = 0;
    for b in s.bytes() {
        v = v.checked_shl(4).ok_or(ParseError::BadHex)?;
        v |= hex_val(b)? as u64;
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_sanity() {
        // "OK" -> O=0x4f K=0x4b soma=0x9a
        assert_eq!(checksum(b"OK"), 0x9a);
    }

    #[test]
    fn encode_ok() {
        assert_eq!(encode_packet(b"OK"), b"$OK#9a".to_vec());
    }

    #[test]
    fn parse_ok() {
        let (p, n) = parse_packet(b"$OK#9a").unwrap();
        assert_eq!(p.data, b"OK");
        assert_eq!(n, 6);
    }

    #[test]
    fn parse_with_ack_prefix() {
        let (p, n) = parse_packet(b"+$OK#9a").unwrap();
        assert_eq!(p.data, b"OK");
        assert_eq!(n, 7);
    }

    #[test]
    fn parse_bad_checksum() {
        let r = parse_packet(b"$OK#00");
        assert!(matches!(r, Err(ParseError::BadChecksum { .. })));
    }

    #[test]
    fn parse_incomplete() {
        assert_eq!(parse_packet(b"$OK#9"), Err(ParseError::Incomplete));
        assert_eq!(parse_packet(b"$OK"), Err(ParseError::Incomplete));
    }

    #[test]
    fn roundtrip_qsupported() {
        let payload = b"qSupported:multiprocess+;xmlRegisters=i386;qRelocInsn+";
        let enc = encode_packet(payload);
        let (p, _) = parse_packet(&enc).unwrap();
        assert_eq!(p.data, payload);
    }

    #[test]
    fn hex_roundtrip() {
        let b = [0xde, 0xad, 0xbe, 0xef, 0x00, 0xff];
        let h = bytes_to_hex(&b);
        assert_eq!(h, "deadbeef00ff");
        assert_eq!(hex_to_bytes(&h).unwrap(), b);
    }

    #[test]
    fn parse_hex_u64_ok() {
        assert_eq!(parse_hex_u64("deadbeef").unwrap(), 0xdeadbeef);
        assert_eq!(parse_hex_u64("0").unwrap(), 0);
        assert_eq!(parse_hex_u64("ffffffffffffffff").unwrap(), u64::MAX);
    }
}
