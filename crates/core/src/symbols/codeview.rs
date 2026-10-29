use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeViewInfo {
    pub pdb_name: String,
    pub guid: [u8; 16],
    pub age: u32,
}

impl CodeViewInfo {
    pub fn guid_age_key(&self) -> String {
        let g = &self.guid;
        format!(
            "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:X}",
            g[3],
            g[2],
            g[1],
            g[0],
            g[5],
            g[4],
            g[7],
            g[6],
            g[8],
            g[9],
            g[10],
            g[11],
            g[12],
            g[13],
            g[14],
            g[15],
            self.age
        )
    }

    pub fn pdb_basename(&self) -> &str {
        let p = self.pdb_name.as_str();
        if let Some(idx) = p.rfind(['\\', '/']) {
            &p[idx + 1..]
        } else {
            p
        }
    }
}

fn ioerr<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

fn read_u16_le(buf: &[u8], off: usize) -> io::Result<u16> {
    if off + 2 > buf.len() {
        return Err(ioerr("short read u16"));
    }
    Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
}

fn read_u32_le(buf: &[u8], off: usize) -> io::Result<u32> {
    if off + 4 > buf.len() {
        return Err(ioerr("short read u32"));
    }
    Ok(u32::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
    ]))
}

pub fn read_codeview_from_file(path: &Path) -> io::Result<CodeViewInfo> {
    let mut f = File::open(path)?;

    let mut hdr = [0u8; 0x1000];
    let n = f.read(&mut hdr)?;
    if n < 0x40 {
        return Err(ioerr("file too small"));
    }
    let hdr = &hdr[..n];

    if hdr[0] != b'M' || hdr[1] != b'Z' {
        return Err(ioerr("not a PE: missing MZ"));
    }

    let e_lfanew = read_u32_le(hdr, 0x3C)? as usize;
    if e_lfanew + 0x18 > hdr.len() {
        return Err(ioerr("e_lfanew out of range"));
    }

    if &hdr[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(ioerr("not a PE: missing PE sig"));
    }

    let file_header_off = e_lfanew + 4;
    let num_sections = read_u16_le(hdr, file_header_off + 2)? as usize;
    let size_of_optional_header = read_u16_le(hdr, file_header_off + 16)? as usize;

    let opt_header_off = file_header_off + 20;
    let opt_magic = read_u16_le(hdr, opt_header_off)?;

    let (debug_dir_rva, debug_dir_size) = if opt_magic == 0x020B {
        let data_dirs_off = opt_header_off + 112;
        let debug_entry_off = data_dirs_off + 6 * 8;
        (
            read_u32_le(hdr, debug_entry_off)? as usize,
            read_u32_le(hdr, debug_entry_off + 4)? as usize,
        )
    } else if opt_magic == 0x010B {
        let data_dirs_off = opt_header_off + 96;
        let debug_entry_off = data_dirs_off + 6 * 8;
        (
            read_u32_le(hdr, debug_entry_off)? as usize,
            read_u32_le(hdr, debug_entry_off + 4)? as usize,
        )
    } else {
        return Err(ioerr("unknown PE optional header magic"));
    };

    if debug_dir_rva == 0 || debug_dir_size == 0 {
        return Err(ioerr("no debug directory in PE"));
    }

    let sections_off = opt_header_off + size_of_optional_header;
    let mut sections: Vec<(u32, u32, u32, u32)> = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let off = sections_off + i * 40;
        if off + 40 > hdr.len() {
            return Err(ioerr("section header out of range"));
        }
        let v_size = read_u32_le(hdr, off + 8)?;
        let v_addr = read_u32_le(hdr, off + 12)?;
        let r_size = read_u32_le(hdr, off + 16)?;
        let r_ptr = read_u32_le(hdr, off + 20)?;
        sections.push((v_addr, v_size, r_ptr, r_size));
    }

    let rva_to_offset = |rva: u32| -> Option<u64> {
        for &(v_addr, v_size, r_ptr, _r_size) in &sections {
            if rva >= v_addr && rva < v_addr + v_size.max(1) {
                return Some((rva - v_addr + r_ptr) as u64);
            }
        }
        None
    };

    let debug_dir_off = rva_to_offset(debug_dir_rva as u32)
        .ok_or_else(|| ioerr("debug dir RVA not in any section"))?;

    let entry_count = debug_dir_size / 28;
    let mut debug_buf = vec![0u8; entry_count * 28];
    f.seek(SeekFrom::Start(debug_dir_off))?;
    f.read_exact(&mut debug_buf)?;

    for i in 0..entry_count {
        let base = i * 28;
        let typ = read_u32_le(&debug_buf, base + 12)?;
        if typ != 2 {
            continue;
        }
        let size_of_data = read_u32_le(&debug_buf, base + 16)? as usize;
        let pointer_to_raw = read_u32_le(&debug_buf, base + 24)? as u64;

        let mut cv_buf = vec![0u8; size_of_data];
        f.seek(SeekFrom::Start(pointer_to_raw))?;
        f.read_exact(&mut cv_buf)?;

        if cv_buf.len() < 24 || &cv_buf[0..4] != b"RSDS" {
            continue;
        }

        let mut guid = [0u8; 16];
        guid.copy_from_slice(&cv_buf[4..20]);
        let age = read_u32_le(&cv_buf, 20)?;

        let name_bytes = &cv_buf[24..];
        let nul = name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_bytes.len());
        let pdb_name = String::from_utf8_lossy(&name_bytes[..nul]).into_owned();

        return Ok(CodeViewInfo {
            pdb_name,
            guid,
            age,
        });
    }

    Err(ioerr("no RSDS CodeView entry found in debug directory"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_age_key_formats_rsds_correctly() {
        let info = CodeViewInfo {
            pdb_name: "ntdll.pdb".to_string(),
            guid: [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
                0xFF, 0x00,
            ],
            age: 1,
        };
        let key = info.guid_age_key();
        assert_eq!(key, "443322116655887799AABBCCDDEEFF001");
    }

    #[test]
    fn pdb_basename_strips_dirs() {
        let info = CodeViewInfo {
            pdb_name: "d:\\build\\x64\\ntdll.pdb".to_string(),
            guid: [0; 16],
            age: 1,
        };
        assert_eq!(info.pdb_basename(), "ntdll.pdb");
    }
}
