#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookKind {
    JmpRelative,
    CallRelative,
    JmpIndirect,
    CallIndirect,
    PushRet,
    MovRaxJmp,
    DataPatch,
}

impl HookKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            HookKind::JmpRelative => "relative_jmp",
            HookKind::CallRelative => "relative_call",
            HookKind::JmpIndirect => "indirect_jmp",
            HookKind::CallIndirect => "indirect_call",
            HookKind::PushRet => "push_ret",
            HookKind::MovRaxJmp => "mov_rax_jmp",
            HookKind::DataPatch => "data_patch",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatchRange {
    pub offset: usize,
    pub length: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookReport {
    pub offset: usize,
    pub kind: HookKind,
}

pub fn detect_patches(original: &[u8], patched: &[u8]) -> Vec<PatchRange> {
    let len = original.len().min(patched.len());
    let mut out = Vec::new();
    let mut i = 0;

    while i < len {
        if original[i] != patched[i] {
            let start = i;
            while i < len && original[i] != patched[i] {
                i += 1;
            }
            out.push(PatchRange {
                offset: start,
                length: i - start,
            });
        } else {
            i += 1;
        }
    }

    if original.len() != patched.len() {
        out.push(PatchRange {
            offset: len,
            length: original.len().max(patched.len()) - len,
        });
    }

    out
}

pub fn classify_hook(patched: &[u8]) -> HookKind {
    let p = patched;

    if p.len() >= 12 && p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0 {
        return HookKind::MovRaxJmp;
    }
    if p.len() >= 6 && p[0] == 0x68 && p[5] == 0xC3 {
        return HookKind::PushRet;
    }
    if p.len() >= 6 && p[0] == 0xFF && p[1] == 0x25 {
        return HookKind::JmpIndirect;
    }
    if p.len() >= 6 && p[0] == 0xFF && p[1] == 0x15 {
        return HookKind::CallIndirect;
    }
    if p.len() >= 5 && p[0] == 0xE9 {
        return HookKind::JmpRelative;
    }
    if p.len() >= 5 && p[0] == 0xE8 {
        return HookKind::CallRelative;
    }
    if p.len() >= 2 && p[0] == 0xEB {
        return HookKind::JmpRelative;
    }

    HookKind::DataPatch
}

pub fn scan_module_hooks(original: &[u8], patched: &[u8]) -> Vec<HookReport> {
    detect_patches(original, patched)
        .into_iter()
        .map(|range| {
            let end = (range.offset + range.length).min(patched.len());
            let stub = &patched[range.offset..end];
            HookReport {
                offset: range.offset,
                kind: classify_hook(stub),
            }
        })
        .collect()
}

pub fn find_embedded_pe(buf: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    if buf.len() < 0x40 {
        return out;
    }

    let mut i = 0;
    while i + 2 <= buf.len() {
        if buf[i] == 0x4D && buf[i + 1] == 0x5A
            && i + 0x40 <= buf.len() {
                let pe_off = u32::from_le_bytes([
                    buf[i + 0x3C],
                    buf[i + 0x3D],
                    buf[i + 0x3E],
                    buf[i + 0x3F],
                ]) as usize;
                if i + pe_off + 4 <= buf.len() && &buf[i + pe_off..i + pe_off + 4] == b"PE\0\0" {
                    out.push(i);
                }
            }
        i += 1;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jmp_stub() -> [u8; 5] {
        [0xE9, 0x11, 0x22, 0x33, 0x44]
    }

    #[test]
    fn test_detect_patches_empty() {
        let a = [1u8, 2, 3, 4, 5];
        let b = [1u8, 2, 3, 4, 5];
        assert!(detect_patches(&a, &b).is_empty());
    }

    #[test]
    fn test_detect_patches_merges_contiguous() {
        let a = [0u8; 16];
        let mut b = [0u8; 16];
        b[4] = 0xE9;
        b[5] = 0x11;
        b[6] = 0x22;
        let patches = detect_patches(&a, &b);
        assert_eq!(patches, vec![PatchRange { offset: 4, length: 3 }]);
    }

    #[test]
    fn test_detect_patches_length_mismatch() {
        let a = [1u8; 8];
        let b = [1u8; 12];
        let patches = detect_patches(&a, &b);
        assert_eq!(patches, vec![PatchRange { offset: 8, length: 4 }]);
    }

    #[test]
    fn test_classify_hook_kinds() {
        assert_eq!(classify_hook(&jmp_stub()), HookKind::JmpRelative);
        assert_eq!(classify_hook(&[0xE8, 0, 0, 0, 0]), HookKind::CallRelative);
        assert_eq!(classify_hook(&[0xEB, 0x10]), HookKind::JmpRelative);
        assert_eq!(classify_hook(&[0xFF, 0x25, 0, 0, 0, 0]), HookKind::JmpIndirect);
        assert_eq!(classify_hook(&[0xFF, 0x15, 0, 0, 0, 0]), HookKind::CallIndirect);
        assert_eq!(classify_hook(&[0x68, 0, 0, 0, 0, 0xC3]), HookKind::PushRet);

        let mut mov_rax = [0u8; 12];
        mov_rax[0] = 0x48;
        mov_rax[1] = 0xB8;
        mov_rax[10] = 0xFF;
        mov_rax[11] = 0xE0;
        assert_eq!(classify_hook(&mov_rax), HookKind::MovRaxJmp);

        assert_eq!(classify_hook(&[0x48, 0x89, 0x5C, 0x24]), HookKind::DataPatch);
    }

    #[test]
    fn test_scan_module_hooks() {
        let original = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x90, 0x90, 0x90, 0x90];
        let mut patched = original;
        patched[0..5].copy_from_slice(&jmp_stub());
        patched[8] = 0xCC;

        let reports = scan_module_hooks(&original, &patched);
        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].offset, 0);
        assert_eq!(reports[0].kind, HookKind::JmpRelative);
        assert_eq!(reports[1].offset, 8);
        assert_eq!(reports[1].kind, HookKind::DataPatch);
    }

    #[test]
    fn test_find_embedded_pe() {
        let mut buf = vec![0u8; 0x200];
        let mz = 0x40usize;
        buf[mz] = 0x4D;
        buf[mz + 1] = 0x5A;
        buf[mz + 0x3C..mz + 0x40].copy_from_slice(&0x80u32.to_le_bytes());
        buf[mz + 0x80..mz + 0x84].copy_from_slice(b"PE\0\0");

        assert_eq!(find_embedded_pe(&buf), vec![mz]);
        assert!(find_embedded_pe(&[0u8; 0x100]).is_empty());
    }
}
