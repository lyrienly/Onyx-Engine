use crate::memory::pe_rebuild::{parse_headers, rebuild};
use crate::process::Process;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpReport {
    pub path: String,
    pub size: usize,
    pub image_base: usize,
}

fn rebuild_and_write(
    proc: &Process,
    image_base: usize,
    out_path: &str,
) -> Result<DumpReport, String> {
    let header_sample = proc.read_bytes(image_base, 0x1000)?;
    let headers = parse_headers(&header_sample)?;

    let image_size = headers.size_of_image as usize;
    if image_size == 0 || image_size > 512 * 1024 * 1024 {
        return Err(format!("invalid SizeOfImage: {}", image_size));
    }

    let image = proc.read_bytes(image_base, image_size)?;
    let file = rebuild(&image)?;
    std::fs::write(out_path, &file).map_err(|e| format!("failed to write {}: {}", out_path, e))?;

    Ok(DumpReport {
        path: out_path.to_string(),
        size: file.len(),
        image_base,
    })
}

pub fn dump_module(
    proc: &Process,
    module_base: usize,
    out_path: &str,
) -> Result<DumpReport, String> {
    rebuild_and_write(proc, module_base, out_path)
}

pub fn dump_embedded_pe(
    proc: &Process,
    address: usize,
    out_path: &str,
) -> Result<DumpReport, String> {
    rebuild_and_write(proc, address, out_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dump_report_is_comparable() {
        let report = DumpReport {
            path: "dump.dll".to_string(),
            size: 0x400,
            image_base: 0x1_4000_0000,
        };
        assert_eq!(report.clone(), report);
    }
}
