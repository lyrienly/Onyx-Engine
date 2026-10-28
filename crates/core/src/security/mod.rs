//! Módulo de Segurança e Evasão Avançada do OnyxEngine
//! 
//! Contém as 4 técnicas de proteção e camuflagem:
//! 1. `taskmgr_cloak`: Ocultação dinâmica de processos no Gerenciador de Tarefas e Process Hacker
//! 2. `anti_attach`: Neutralização de rotinas de attach remoto (DbgUiRemoteBreakin, DbgBreakPoint)
//! 3. `anti_debug`: Detecção de hardware breakpoints (DR0-DR7), ThreadHideFromDebugger e auditoria PEB
//! 4. `anti_dump`: Prevenção contra dumpers de memória (Scylla, PETools) via distorção de PEB e cabeçalhos

pub mod taskmgr_cloak;
pub mod anti_attach;
pub mod anti_debug;
pub mod anti_dump;

pub use taskmgr_cloak::{TaskmgrCloakManager, filter_system_process_information};
pub use anti_attach::AntiAttach;
pub use anti_debug::{AntiDebug, AntiDebugReport};
pub use anti_dump::AntiDump;

/// Ativa a proteção global do OnyxEngine em uma única chamada
pub fn activate_process_shield() -> Result<(), String> {
    AntiAttach::enable()?;
    let _ = AntiDebug::hide_current_thread();
    let _ = AntiDump::distort_peb_size_of_image(0x100000);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_activate_process_shield() {
        let res = activate_process_shield();
        assert!(res.is_ok());
    }
}
