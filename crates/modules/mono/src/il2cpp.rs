//! Parse do cabecalho `global-metadata.dat` do IL2CPP.
//!
//! IL2CPP (gerado pelo pipeline da Unity) nao expoe metadata via DLL exports
//! como o Mono classic. Em vez disso, cada build empacota um arquivo binario
//! `global-metadata.dat` dentro de `*_Data/il2cpp_data/Metadata/`. Esse arquivo
//! guarda strings, tipos, metodos, dominios, assemblies etc.
//!
//! Este modulo parseia o cabecalho e os indices mais uteis para o
//! `MonoDataCollector`:
//! - Validacao da magic `0xFAB11BAF`
//! - Versao do schema (24-29 cobre Unity 2018-2023)
//! - Enumeracao de strings do heap `StringLiteral`
//!
//! Enumeracao de tipos/metodos exige correlacao com `Il2CppClass` em
//! `GameAssembly.dll`; nao e feita aqui.

pub const GLOBAL_METADATA_MAGIC: u32 = 0xFAB11BAF;

/// Cabecalho binario do `global-metadata.dat` (schema estavel entre 24..=29,
/// com addicao de campos ao final em versoes mais novas).
///
/// Os deslocamentos sao referentes ao proprio cabecalho; cada tabela do heap
/// usa `offset`/`size` em bytes.
#[derive(Debug, Clone)]
pub struct Il2CppMetadataHeader {
    pub sanity: u32,
    pub version: i32,
    pub string_literal_offset: u32,
    pub string_literal_size: u32,
    pub string_literal_data_offset: u32,
    pub string_literal_data_size: u32,
    pub string_offset: u32,
    pub string_size: u32,
    pub events_offset: u32,
    pub events_size: u32,
    pub properties_offset: u32,
    pub properties_size: u32,
    pub methods_offset: u32,
    pub methods_size: u32,
    pub parameter_default_values_offset: u32,
    pub parameter_default_values_size: u32,
    pub field_default_values_offset: u32,
    pub field_default_values_size: u32,
}

/// Parseia os primeiros bytes de um `global-metadata.dat`. Retorna None se a
/// magic nao bater ou se o buffer for curto demais para conter o cabecalho
/// basico (72 bytes = 4 sanity + 4 version + 16 pares offset/size).
pub fn parse_global_metadata_header(bytes: &[u8]) -> Option<Il2CppMetadataHeader> {
    if bytes.len() < 0x50 {
        return None;
    }
    let sanity = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    if sanity != GLOBAL_METADATA_MAGIC {
        return None;
    }
    let version = i32::from_le_bytes(bytes[4..8].try_into().ok()?);
    // schemas suportados oficialmente pelos jogos atuais
    if !(16..=35).contains(&version) {
        return None;
    }

    let u32_at = |off: usize| -> Option<u32> {
        bytes
            .get(off..off + 4)?
            .try_into()
            .ok()
            .map(u32::from_le_bytes)
    };

    Some(Il2CppMetadataHeader {
        sanity,
        version,
        string_literal_offset: u32_at(0x08)?,
        string_literal_size: u32_at(0x0C)?,
        string_literal_data_offset: u32_at(0x10)?,
        string_literal_data_size: u32_at(0x14)?,
        string_offset: u32_at(0x18)?,
        string_size: u32_at(0x1C)?,
        events_offset: u32_at(0x20)?,
        events_size: u32_at(0x24)?,
        properties_offset: u32_at(0x28)?,
        properties_size: u32_at(0x2C)?,
        methods_offset: u32_at(0x30)?,
        methods_size: u32_at(0x34)?,
        parameter_default_values_offset: u32_at(0x38)?,
        parameter_default_values_size: u32_at(0x3C)?,
        field_default_values_offset: u32_at(0x40)?,
        field_default_values_size: u32_at(0x44)?,
    })
}

/// Enumera strings do heap `#Strings` do metadata (array de C-strings
/// terminadas em NUL).
pub fn enumerate_strings(bytes: &[u8], header: &Il2CppMetadataHeader) -> Vec<String> {
    let start = header.string_offset as usize;
    let end = start
        .saturating_add(header.string_size as usize)
        .min(bytes.len());
    if start >= end {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cur = start;
    while cur < end {
        let rest = &bytes[cur..end];
        let n = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        if n == 0 {
            cur += 1;
            continue;
        }
        if let Ok(s) = std::str::from_utf8(&rest[..n]) {
            out.push(s.to_string());
        }
        cur += n + 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_synth(version: i32, strings: &[&str]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&GLOBAL_METADATA_MAGIC.to_le_bytes());
        buf.extend_from_slice(&version.to_le_bytes());
        // 16 pares offset/size (zerados). O par #Strings vive em [0x18..0x20].
        for _ in 0..16 {
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
        }
        // Escreve o heap de strings logo apos o cabecalho (offset 0x88).
        let strings_offset = buf.len() as u32;
        let mut heap = Vec::new();
        for s in strings {
            heap.extend_from_slice(s.as_bytes());
            heap.push(0);
        }
        let strings_size = heap.len() as u32;
        buf.extend_from_slice(&heap);
        // Patch dos campos #Strings offset/size.
        buf[0x18..0x1C].copy_from_slice(&strings_offset.to_le_bytes());
        buf[0x1C..0x20].copy_from_slice(&strings_size.to_le_bytes());
        buf
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = vec![0u8; 0x80];
        bytes[0] = 0xDE;
        bytes[1] = 0xAD;
        assert!(parse_global_metadata_header(&bytes).is_none());
    }

    #[test]
    fn parses_header_v29() {
        let bytes = build_synth(29, &["System.Object", "UnityEngine.MonoBehaviour"]);
        let header = parse_global_metadata_header(&bytes).expect("header must parse");
        assert_eq!(header.sanity, GLOBAL_METADATA_MAGIC);
        assert_eq!(header.version, 29);
        assert_eq!(header.string_offset, 0x88);
        assert!(header.string_size > 0);
    }

    #[test]
    fn enumerates_strings_from_synth() {
        let bytes = build_synth(27, &["Il2CppObject", "GameManager", "AddCoins"]);
        let header = parse_global_metadata_header(&bytes).unwrap();
        let strings = enumerate_strings(&bytes, &header);
        assert_eq!(
            strings,
            vec![
                "Il2CppObject".to_string(),
                "GameManager".to_string(),
                "AddCoins".to_string()
            ]
        );
    }

    #[test]
    fn version_outside_supported_range_fails() {
        // v2 nao e um schema real do IL2CPP.
        let bytes = build_synth(2, &[]);
        assert!(parse_global_metadata_header(&bytes).is_none());
    }
}
