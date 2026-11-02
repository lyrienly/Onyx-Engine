//! Telemetria do processo alvo: memória, uptime, e qualquer outra métrica
//! que o overlay quiser mostrar.

use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::GetCurrentProcess;

/// Retorna `(working_set_atual_MB, peak_working_set_MB)` do processo onde
/// a DLL está injetada. Em caso de falha retorna `(0, 0)`.
pub fn process_memory_mb() -> (u64, u64) {
    unsafe {
        let mut pmc = PROCESS_MEMORY_COUNTERS {
            cb: size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            ..Default::default()
        };
        let proc = GetCurrentProcess();
        if GetProcessMemoryInfo(proc, &mut pmc, pmc.cb).is_ok() {
            (
                (pmc.WorkingSetSize / (1024 * 1024)) as u64,
                (pmc.PeakWorkingSetSize / (1024 * 1024)) as u64,
            )
        } else {
            (0, 0)
        }
    }
}
