//! Unit tests para parse de versao VS_FIXEDFILEINFO.

use onyx_dotnet::runtime::parse_vs_versioninfo;

#[test]
fn parses_fixed_file_info_signature() {
    // Monta um blob minimo que contem a assinatura 0xFEEF04BD seguida de
    // VS_FIXEDFILEINFO com fileVersion 7.0.11.0.
    let mut buf = Vec::new();
    // VS_VERSIONINFO header: wLength, wValueLength (>=52), wType.
    buf.extend_from_slice(&[0x00, 0x02]); // wLength (ignorado pelo parser)
    buf.extend_from_slice(&52u16.to_le_bytes()); // wValueLength
    buf.extend_from_slice(&[0x00, 0x00]); // wType
                                          // padding ate o fixed-info
    buf.extend(std::iter::repeat_n(0u8, 16));
    // VS_FIXEDFILEINFO (52 bytes)
    buf.extend_from_slice(&0xFEEF04BDu32.to_le_bytes()); // dwSignature
    buf.extend_from_slice(&0x00010000u32.to_le_bytes()); // strucVersion
                                                         // fileVersionMS = major<<16 | minor
    let ms: u32 = 7u32 << 16;
    let ls: u32 = 11u32 << 16;
    buf.extend_from_slice(&ms.to_le_bytes());
    buf.extend_from_slice(&ls.to_le_bytes());
    // productVersionMS/LS
    buf.extend_from_slice(&ms.to_le_bytes());
    buf.extend_from_slice(&ls.to_le_bytes());
    // flagsMask, flags, OS, type, subtype, dateMS, dateLS
    for _ in 0..7 {
        buf.extend_from_slice(&0u32.to_le_bytes());
    }

    let v = parse_vs_versioninfo(&buf).expect("deve parsear VS_FIXEDFILEINFO");
    assert_eq!(v, "7.0.11.0");
}

#[test]
fn returns_none_on_empty() {
    assert!(parse_vs_versioninfo(&[]).is_none());
}

#[test]
fn returns_none_without_signature() {
    let buf = vec![0u8; 128];
    assert!(parse_vs_versioninfo(&buf).is_none());
}
