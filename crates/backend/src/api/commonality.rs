// language: Rust, file: commonality.rs, target: Windows 11, MSVC
// Commonality and Structure Difference Analysis C-ABI Bridge

use onyx_core::process::Process;
use onyx_core::debugger::commonality::{CommonalityAnalyzer, RegisterSnapshot};
use crate::types::{OnyxRegisterSnapshot, OnyxRegisterComparison, OnyxStructureDifference};

#[no_mangle]
pub unsafe extern "C" fn onyx_commonality_analyze_registers(
    g1: *const OnyxRegisterSnapshot,
    g1_count: u32,
    g2: *const OnyxRegisterSnapshot,
    g2_count: u32,
    out_comparisons: *mut OnyxRegisterComparison,
    max_out: u32,
    out_count: *mut u32,
) -> i32 {
    if g1.is_null() || g2.is_null() || out_comparisons.is_null() || max_out == 0 {
        return -1;
    }

    let g1_slice = std::slice::from_raw_parts(g1, g1_count as usize);
    let g2_slice = std::slice::from_raw_parts(g2, g2_count as usize);

    let g1_snaps: Vec<RegisterSnapshot> = g1_slice.iter().map(|s| RegisterSnapshot {
        rax: s.rax, rbx: s.rbx, rcx: s.rcx, rdx: s.rdx,
        rsi: s.rsi, rdi: s.rdi, rbp: s.rbp, rsp: s.rsp,
        r8: s.r8, r9: s.r9, r10: s.r10, r11: s.r11,
        r12: s.r12, r13: s.r13, r14: s.r14, r15: s.r15,
        rip: s.rip, rflags: s.rflags,
    }).collect();

    let g2_snaps: Vec<RegisterSnapshot> = g2_slice.iter().map(|s| RegisterSnapshot {
        rax: s.rax, rbx: s.rbx, rcx: s.rcx, rdx: s.rdx,
        rsi: s.rsi, rdi: s.rdi, rbp: s.rbp, rsp: s.rsp,
        r8: s.r8, r9: s.r9, r10: s.r10, r11: s.r11,
        r12: s.r12, r13: s.r13, r14: s.r14, r15: s.r15,
        rip: s.rip, rflags: s.rflags,
    }).collect();

    let comps = CommonalityAnalyzer::analyze_registers(&g1_snaps, &g2_snaps);

    if !out_count.is_null() {
        *out_count = comps.len() as u32;
    }

    let write_len = comps.len().min(max_out as usize);
    for i in 0..write_len {
        let mut entry = OnyxRegisterComparison {
            reg_name: [0u8; 16],
            reg_index: comps[i].reg_index as u32,
            g1_constant: if comps[i].g1_constant { 1 } else { 0 },
            g1_sample: comps[i].g1_sample,
            g2_constant: if comps[i].g2_constant { 1 } else { 0 },
            g2_sample: comps[i].g2_sample,
            distinguishes_groups: if comps[i].distinguishes_groups { 1 } else { 0 },
        };
        let b = comps[i].reg_name.as_bytes();
        let blen = b.len().min(15);
        entry.reg_name[..blen].copy_from_slice(&b[..blen]);

        *out_comparisons.add(i) = entry;
    }

    write_len as i32
}

#[no_mangle]
pub unsafe extern "C" fn onyx_commonality_analyze_structures(
    handle: *mut Process,
    g1_ptrs: *const usize,
    g1_count: u32,
    g2_ptrs: *const usize,
    g2_count: u32,
    struct_size: usize,
    out_diffs: *mut OnyxStructureDifference,
    max_diffs: u32,
    out_count: *mut u32,
) -> i32 {
    if handle.is_null() || g1_ptrs.is_null() || g2_ptrs.is_null() || out_diffs.is_null() || max_diffs == 0 {
        return -1;
    }

    let g1_slice = std::slice::from_raw_parts(g1_ptrs, g1_count as usize);
    let g2_slice = std::slice::from_raw_parts(g2_ptrs, g2_count as usize);

    match CommonalityAnalyzer::analyze_structures(&*handle, g1_slice, g2_slice, struct_size) {
        Ok(diffs) => {
            if !out_count.is_null() {
                *out_count = diffs.len() as u32;
            }
            let write_len = diffs.len().min(max_diffs as usize);
            for i in 0..write_len {
                *out_diffs.add(i) = OnyxStructureDifference {
                    offset: diffs[i].offset,
                    g1_constant: if diffs[i].g1_constant { 1 } else { 0 },
                    g1_value: diffs[i].g1_value,
                    g2_constant: if diffs[i].g2_constant { 1 } else { 0 },
                    g2_value: diffs[i].g2_value,
                    differentiates: if diffs[i].differentiates { 1 } else { 0 },
                    value_size: diffs[i].value_size as u32,
                };
            }
            write_len as i32
        }
        Err(_) => -1,
    }
}
