use crate::process::Process;

#[derive(Debug, Clone, PartialEq)]
pub enum InferredKind {
    Padding,
    Bool(bool),
    U8(u8),
    I32(i32),
    F32(f32),
    I64(i64),
    F64(f64),
    Pointer(usize),
    VTablePointer(usize),
    CodePointer(usize),
    StringPointer(usize, String),
    InlineString(String),
    Unknown,
}

impl InferredKind {
    pub fn c_type(&self) -> &'static str {
        match self {
            InferredKind::Padding      => "uint8_t",
            InferredKind::Bool(_)      => "bool",
            InferredKind::U8(_)        => "uint8_t",
            InferredKind::I32(_)       => "int32_t",
            InferredKind::F32(_)       => "float",
            InferredKind::I64(_)       => "int64_t",
            InferredKind::F64(_)       => "double",
            InferredKind::Pointer(_)   => "void*",
            InferredKind::VTablePointer(_) => "void**",
            InferredKind::CodePointer(_)   => "void(*)()",
            InferredKind::StringPointer(_, _) => "char*",
            InferredKind::InlineString(_)     => "char",
            InferredKind::Unknown      => "uint8_t",
        }
    }

    pub fn rust_type(&self) -> &'static str {
        match self {
            InferredKind::Padding      => "u8",
            InferredKind::Bool(_)      => "bool",
            InferredKind::U8(_)        => "u8",
            InferredKind::I32(_)       => "i32",
            InferredKind::F32(_)       => "f32",
            InferredKind::I64(_)       => "i64",
            InferredKind::F64(_)       => "f64",
            InferredKind::Pointer(_)   => "*mut u8",
            InferredKind::VTablePointer(_) => "*mut *mut u8",
            InferredKind::CodePointer(_)   => "usize",
            InferredKind::StringPointer(_, _) => "*mut u8",
            InferredKind::InlineString(_)     => "u8",
            InferredKind::Unknown      => "u8",
        }
    }
}

#[derive(Debug, Clone)]
pub struct InferredField {
    pub offset: usize,
    pub size: usize,
    pub kind: InferredKind,
    pub value_hint: String,
}

#[derive(Debug, Clone)]
pub struct StructLayout {
    pub base: usize,
    pub total_size: usize,
    pub alignment: usize,
    pub fields: Vec<InferredField>,
}

pub struct StructSpider;

impl StructSpider {

    pub fn infer_bytes(base: usize, buf: &[u8]) -> StructLayout {
        Self::infer_from_slice(base, buf, &[], &[])
    }

    pub fn infer_from_slice(
        base: usize,
        buf: &[u8],
        readable: &[(usize, usize)],
        executable: &[(usize, usize)],
    ) -> StructLayout {
        let total_size = buf.len();
        let mut fields: Vec<InferredField> = Vec::new();
        let mut off = 0usize;

        let in_region = |addr: usize, regs: &[(usize, usize)]| -> bool {
            regs.iter().any(|(b, s)| addr >= *b && addr < b.saturating_add(*s))
        };

        while off < total_size {
            let remaining = total_size - off;

            if off.is_multiple_of(8) && remaining >= 8 {
                let bytes = &buf[off..off + 8];
                let u = u64::from_le_bytes(bytes.try_into().unwrap());
                let s = i64::from_le_bytes(bytes.try_into().unwrap());
                let f = f64::from_le_bytes(bytes.try_into().unwrap());

                if u == 0 {

                    let start = off;
                    let mut end = off + 8;
                    while end + 8 <= total_size && end.is_multiple_of(8) {
                        let next = &buf[end..end + 8];
                        if u64::from_le_bytes(next.try_into().unwrap()) == 0 {
                            end += 8;
                        } else {
                            break;
                        }
                    }
                    fields.push(InferredField {
                        offset: start,
                        size: end - start,
                        kind: InferredKind::Padding,
                        value_hint: "zeroed".into(),
                    });
                    off = end;
                    continue;
                }

                let ptr = u as usize;
                let looks_like_pointer = (0x10000..=0x7FFF_FFFF_FFFF).contains(&u);
                if looks_like_pointer {
                    if in_region(ptr, executable) {
                        fields.push(InferredField {
                            offset: off,
                            size: 8,
                            kind: InferredKind::CodePointer(ptr),
                            value_hint: format!("code @ 0x{:X}", ptr),
                        });
                        off += 8;
                        continue;
                    }
                    if in_region(ptr, readable) {

                        fields.push(InferredField {
                            offset: off,
                            size: 8,
                            kind: InferredKind::Pointer(ptr),
                            value_hint: format!("heap @ 0x{:X}", ptr),
                        });
                        off += 8;
                        continue;
                    }
                }

                if f.is_finite() && f.abs() >= 1e-3 && f.abs() <= 1e5

                    && !(s.abs() < 1_000_000 && (u & 0xFFFF_FFFF_0000_0000) == 0) {
                        fields.push(InferredField {
                            offset: off,
                            size: 8,
                            kind: InferredKind::F64(f),
                            value_hint: format!("{:.6}", f),
                        });
                        off += 8;
                        continue;
                    }

                let upper = &buf[off + 4..off + 8];
                if upper == [0, 0, 0, 0] {
                    let lower = &buf[off..off + 4];
                    let i = i32::from_le_bytes(lower.try_into().unwrap());
                    let fl = f32::from_le_bytes(lower.try_into().unwrap());
                    if fl.is_finite() && fl.abs() >= 1e-3 && fl.abs() <= 1e5
                        && (fl.fract() != 0.0 || (i.abs() > 1000 && fl.abs() > 1.0))
                    {
                        fields.push(InferredField {
                            offset: off,
                            size: 4,
                            kind: InferredKind::F32(fl),
                            value_hint: format!("{:.4}f", fl),
                        });
                    } else {
                        fields.push(InferredField {
                            offset: off,
                            size: 4,
                            kind: InferredKind::I32(i),
                            value_hint: format!("{} (0x{:X})", i, i),
                        });
                    }

                    fields.push(InferredField {
                        offset: off + 4,
                        size: 4,
                        kind: InferredKind::Padding,
                        value_hint: "align4".into(),
                    });
                    off += 8;
                    continue;
                }

                fields.push(InferredField {
                    offset: off,
                    size: 8,
                    kind: InferredKind::I64(s),
                    value_hint: format!("{} (0x{:X})", s, s),
                });
                off += 8;
                continue;
            }

            if off.is_multiple_of(4) && remaining >= 4 {
                let lower = &buf[off..off + 4];
                let i = i32::from_le_bytes(lower.try_into().unwrap());
                let fl = f32::from_le_bytes(lower.try_into().unwrap());
                let u = u32::from_le_bytes(lower.try_into().unwrap());

                if u == 0 {
                    fields.push(InferredField {
                        offset: off,
                        size: 4,
                        kind: InferredKind::Padding,
                        value_hint: "zeroed".into(),
                    });
                    off += 4;
                    continue;
                }

                if fl.is_finite() && fl.abs() >= 1e-3 && fl.abs() <= 1e5 && fl.fract() != 0.0 {
                    fields.push(InferredField {
                        offset: off,
                        size: 4,
                        kind: InferredKind::F32(fl),
                        value_hint: format!("{:.4}f", fl),
                    });
                } else {
                    fields.push(InferredField {
                        offset: off,
                        size: 4,
                        kind: InferredKind::I32(i),
                        value_hint: format!("{} (0x{:X})", i, i),
                    });
                }
                off += 4;
                continue;
            }

            let b = buf[off];
            let kind = match b {
                0 => InferredKind::Padding,
                1 => InferredKind::Bool(true),
                _ => InferredKind::U8(b),
            };
            fields.push(InferredField {
                offset: off,
                size: 1,
                kind,
                value_hint: format!("0x{:02X}", b),
            });
            off += 1;
        }

        let alignment = if fields.iter().any(|f| f.size == 8) {
            8
        } else if fields.iter().any(|f| f.size == 4) {
            4
        } else {
            1
        };

        StructLayout { base, total_size, alignment, fields }
    }

    pub fn infer_struct(
        proc: &Process,
        base: usize,
        max_size: usize,
    ) -> Result<StructLayout, String> {
        let buf = proc.read_bytes(base, max_size)?;
        let regions = proc.regions(false).unwrap_or_default();

        let readable: Vec<(usize, usize)> = regions
            .iter()
            .filter(|r| r.is_readable())
            .map(|r| (r.base, r.size))
            .collect();
        let executable: Vec<(usize, usize)> = regions
            .iter()
            .filter(|r| r.is_executable())
            .map(|r| (r.base, r.size))
            .collect();

        let mut layout = Self::infer_from_slice(base, &buf, &readable, &executable);

        for f in layout.fields.iter_mut() {
            if let InferredKind::Pointer(p) = f.kind {

                if let Ok(s) = proc.read_string(p, 64, false)
                    && is_printable_ascii(&s) && s.len() >= 2 {
                        f.kind = InferredKind::StringPointer(p, s.clone());
                        f.value_hint = format!("\"{}\"", s);
                        continue;
                    }

                if let Ok(first) = proc.read::<usize>(p) {
                    let is_code = executable.iter().any(|(b, s)| first >= *b && first < b.saturating_add(*s));
                    if is_code {
                        f.kind = InferredKind::VTablePointer(p);
                        f.value_hint = format!("vtable @ 0x{:X} (m0=0x{:X})", p, first);
                    }
                }
            }
        }

        Ok(layout)
    }

    pub fn to_cpp(name: &str, layout: &StructLayout) -> String {
        let mut out = format!(
            "// Inferred from 0x{:X} ({} bytes, align {})\nstruct {} {{\n",
            layout.base, layout.total_size, layout.alignment, name
        );
        for f in &layout.fields {
            let fname = if matches!(f.kind, InferredKind::Padding) {
                format!("_pad_0x{:X}", f.offset)
            } else {
                format!("field_0x{:X}", f.offset)
            };
            let array = if (matches!(f.kind, InferredKind::Padding) && f.size > 1)
                || matches!(f.kind, InferredKind::InlineString(_))
            {
                format!("[{}]", f.size)
            } else {
                String::new()
            };
            out.push_str(&format!(
                "    {:<10} {}{}; // +0x{:04X} ({} B) {}\n",
                f.kind.c_type(),
                fname,
                array,
                f.offset,
                f.size,
                f.value_hint
            ));
        }
        out.push_str("};\n");
        out
    }

    pub fn to_rust(name: &str, layout: &StructLayout) -> String {
        let mut out = format!(
            "// Inferred from 0x{:X} ({} bytes, align {})\n#[repr(C)]\npub struct {} {{\n",
            layout.base, layout.total_size, layout.alignment, name
        );
        for f in &layout.fields {
            let fname = if matches!(f.kind, InferredKind::Padding) {
                format!("_pad_0x{:X}", f.offset)
            } else {
                format!("field_0x{:X}", f.offset)
            };
            let ty = if (matches!(f.kind, InferredKind::Padding) && f.size > 1)
                || matches!(f.kind, InferredKind::InlineString(_))
            {
                format!("[u8; {}]", f.size)
            } else {
                f.kind.rust_type().to_string()
            };
            out.push_str(&format!(
                "    pub {}: {}, // +0x{:04X} ({} B) {}\n",
                fname, ty, f.offset, f.size, f.value_hint
            ));
        }
        out.push_str("}\n");
        out
    }
}

fn is_printable_ascii(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c == ' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_buf() -> ([u8; 48], usize, usize) {

        let mut b = [0u8; 48];
        b[0..8].copy_from_slice(&0x1122334455667788i64.to_le_bytes());
        b[8..12].copy_from_slice(&42i32.to_le_bytes());
        b[16..20].copy_from_slice(&2.5f32.to_le_bytes());
        b[24..32].copy_from_slice(&(-9999i64).to_le_bytes());
        b[32..36].copy_from_slice(&1337i32.to_le_bytes());
        b[40..44].copy_from_slice(&7i32.to_le_bytes());

        let fake_readable_base = 0x4000_0000usize;
        let fake_exec_base = 0x5000_0000usize;
        (b, fake_readable_base, fake_exec_base)
    }

    #[test]
    fn infers_mixed_fields_and_padding() {
        let (buf, _, _) = build_buf();
        let layout = StructSpider::infer_bytes(0, &buf);

        let f0 = &layout.fields[0];
        assert_eq!(f0.offset, 0);
        assert_eq!(f0.size, 8);
        assert!(matches!(f0.kind, InferredKind::I64(0x1122334455667788)));

        let f_i32_42 = layout.fields.iter().find(|f| f.offset == 8).expect("field @ 0x8");
        assert_eq!(f_i32_42.size, 4);
        assert!(matches!(f_i32_42.kind, InferredKind::I32(42)));

        let pad_c = layout.fields.iter().find(|f| f.offset == 0xC).expect("pad @ 0xC");
        assert_eq!(pad_c.size, 4);
        assert!(matches!(pad_c.kind, InferredKind::Padding));

        let f_f32 = layout.fields.iter().find(|f| f.offset == 0x10).expect("field @ 0x10");
        assert_eq!(f_f32.size, 4);
        if let InferredKind::F32(v) = f_f32.kind {
            assert!((v - 2.5f32).abs() < 1e-6);
        } else {
            panic!("expected F32 at +0x10, got {:?}", f_f32.kind);
        }

        let f_i64_neg = layout.fields.iter().find(|f| f.offset == 0x18).expect("i64 @ 0x18");
        assert_eq!(f_i64_neg.size, 8);
        assert!(matches!(f_i64_neg.kind, InferredKind::I64(-9999)));

        assert_eq!(layout.alignment, 8);
    }

    #[test]
    fn exports_cpp_and_rust() {
        let (buf, _, _) = build_buf();
        let layout = StructSpider::infer_bytes(0x7FFABCDEF000, &buf);

        let cpp = StructSpider::to_cpp("MyStruct", &layout);
        assert!(cpp.contains("struct MyStruct"));
        assert!(cpp.contains("_pad_0xC[4]") || cpp.contains("_pad_0xC [4]"));
        assert!(cpp.contains("int32_t"));
        assert!(cpp.contains("float"));

        let rs = StructSpider::to_rust("MyStruct", &layout);
        assert!(rs.contains("#[repr(C)]"));
        assert!(rs.contains("pub struct MyStruct"));
        assert!(rs.contains(": i32"));
        assert!(rs.contains(": f32"));
        assert!(rs.contains("[u8; 4]"));
    }

    #[test]
    fn detects_pointer_as_code_vs_heap() {

        let (mut buf, readable_base, exec_base) = build_buf();
        buf[0..8].copy_from_slice(&(exec_base + 0x400).to_le_bytes());
        buf[8..16].copy_from_slice(&(readable_base + 0x200).to_le_bytes());

        let readable = [(readable_base, 0x10000usize)];
        let executable = [(exec_base, 0x10000usize)];
        let layout = StructSpider::infer_from_slice(0, &buf, &readable, &executable);

        let f0 = &layout.fields[0];
        assert_eq!(f0.offset, 0);
        assert_eq!(f0.size, 8);
        assert!(matches!(f0.kind, InferredKind::CodePointer(_)), "got {:?}", f0.kind);

        let f1 = &layout.fields[1];
        assert_eq!(f1.offset, 8);
        assert_eq!(f1.size, 8);
        assert!(matches!(f1.kind, InferredKind::Pointer(_)), "got {:?}", f1.kind);
    }

    #[test]
    fn e2e_infer_struct_from_live_process() {
        let proc = Process::attach_current().expect("attach current");
        let addr = proc
            .alloc(64, crate::process::win32::PAGE_READWRITE)
            .expect("alloc");

        let other = proc
            .alloc(32, crate::process::win32::PAGE_READWRITE)
            .expect("alloc other");

        let mut bytes = [0u8; 64];
        bytes[0..8].copy_from_slice(&0x7F00000012345678i64.to_le_bytes());
        bytes[8..12].copy_from_slice(&42i32.to_le_bytes());
        bytes[16..20].copy_from_slice(&2.5f32.to_le_bytes());
        bytes[24..32].copy_from_slice(&(-1000i64).to_le_bytes());
        bytes[32..40].copy_from_slice(&(other as u64).to_le_bytes());
        proc.write_raw(addr, &bytes).expect("write");

        let layout = StructSpider::infer_struct(&proc, addr, 64).expect("infer");

        let f8 = layout.fields.iter().find(|f| f.offset == 8).expect("i32@8");
        assert!(matches!(f8.kind, InferredKind::I32(42)), "got {:?}", f8.kind);

        let fc = layout.fields.iter().find(|f| f.offset == 0xC).expect("pad@C");
        assert!(matches!(fc.kind, InferredKind::Padding));

        let f10 = layout.fields.iter().find(|f| f.offset == 0x10).expect("f32@10");
        if let InferredKind::F32(v) = f10.kind {
            assert!((v - 2.5f32).abs() < 1e-5);
        } else {
            panic!("expected F32@0x10, got {:?}", f10.kind);
        }

        let f18 = layout.fields.iter().find(|f| f.offset == 0x18).expect("i64@18");
        assert!(matches!(f18.kind, InferredKind::I64(-1000)));

        let f20 = layout.fields.iter().find(|f| f.offset == 0x20).expect("ptr@20");
        assert!(
            matches!(f20.kind, InferredKind::Pointer(_) | InferredKind::VTablePointer(_)),
            "expected pointer-like at +0x20, got {:?}",
            f20.kind
        );

        let cpp = StructSpider::to_cpp("E2E", &layout);
        assert!(cpp.contains("int32_t"));
        assert!(cpp.contains("float"));
        let rs = StructSpider::to_rust("E2E", &layout);
        assert!(rs.contains(": i32"));
        assert!(rs.contains(": f32"));

        println!("--- Inferred layout ---\n{}\n{}", cpp, rs);

        let _ = proc.free(addr);
        let _ = proc.free(other);
    }
}
