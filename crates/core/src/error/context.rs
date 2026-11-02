//! OnyxEngine - Rich Contextual Error Type
//! Encapsulates machine error code, localized human messages (PT-BR & EN), and technical context.

use super::codes::OnyxErrorCode;
use super::locale::OnyxLocale;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnyxError {
    pub code: OnyxErrorCode,
    pub message_en: String,
    pub message_pt: String,
    pub context: Option<String>,
    pub win32_code: Option<u32>,
    pub address: Option<usize>,
}

impl fmt::Display for OnyxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[OnyxError {}] {} / {}",
            self.code.as_u32(),
            self.message_pt,
            self.message_en
        )
    }
}

impl std::error::Error for OnyxError {}

impl From<OnyxError> for String {
    fn from(err: OnyxError) -> Self {
        err.format(super::storage::get_locale())
    }
}

impl From<&str> for OnyxError {
    fn from(s: &str) -> Self {
        OnyxError::new(OnyxErrorCode::InternalError, s, s)
    }
}

impl From<String> for OnyxError {
    fn from(s: String) -> Self {
        OnyxError::new(OnyxErrorCode::InternalError, s.clone(), s)
    }
}

impl OnyxError {
    pub fn new(
        code: OnyxErrorCode,
        message_en: impl Into<String>,
        message_pt: impl Into<String>,
    ) -> Self {
        Self {
            code,
            message_en: message_en.into(),
            message_pt: message_pt.into(),
            context: None,
            win32_code: None,
            address: None,
        }
    }

    pub fn with_context(mut self, ctx: impl Into<String>) -> Self {
        self.context = Some(ctx.into());
        self
    }

    pub fn with_win32(mut self, code: u32) -> Self {
        self.win32_code = Some(code);
        self
    }

    pub fn with_address(mut self, addr: usize) -> Self {
        self.address = Some(addr);
        self
    }

    pub fn message(&self, locale: OnyxLocale) -> &str {
        match locale {
            OnyxLocale::EnUs => &self.message_en,
            OnyxLocale::PtBr => &self.message_pt,
        }
    }

    pub fn format(&self, locale: OnyxLocale) -> String {
        let msg = self.message(locale);
        let mut out = format!("[ERRO {:04}] {}", self.code.as_u32(), msg);
        if let Some(addr) = self.address {
            out.push_str(&format!(" (Endereço: 0x{:X})", addr));
        }
        if let Some(w32) = self.win32_code {
            out.push_str(&format!(" [Win32/NT: 0x{:X}]", w32));
        }
        if let Some(ctx) = &self.context {
            out.push_str(&format!(" -> Detalhe: {}", ctx));
        }
        out
    }

    // ==========================================
    // Specific Process Error Constructors
    // ==========================================
    pub fn process_not_found(pid: u32) -> Self {
        Self::new(
            OnyxErrorCode::ProcessNotFound,
            format!("Process with PID {} was not found", pid),
            format!("Processo com PID {} não foi encontrado", pid),
        )
    }

    pub fn process_access_denied(pid: u32, win32_code: u32) -> Self {
        Self::new(
            OnyxErrorCode::ProcessAccessDenied,
            format!(
                "Access denied attaching to process PID {}. Process might be protected (PPL) or kernel driver is required",
                pid
            ),
            format!(
                "Acesso negado ao anexar ao processo PID {}. O alvo pode ser protegido (PPL) ou requer driver de kernel",
                pid
            ),
        )
        .with_win32(win32_code)
    }

    pub fn process_attach_failed(pid: u32, reason: &str) -> Self {
        Self::new(
            OnyxErrorCode::ProcessAttachFailed,
            format!("Failed to attach to process PID {}: {}", pid, reason),
            format!("Falha ao conectar ao processo PID {}: {}", pid, reason),
        )
        .with_context(reason)
    }

    pub fn process_snapshot_failed(win32_code: u32) -> Self {
        Self::new(
            OnyxErrorCode::ProcessSnapshotFailed,
            "Failed to take toolhelp32 process snapshot",
            "Falha ao capturar snapshot de processos do sistema",
        )
        .with_win32(win32_code)
    }

    pub fn process_suspension_failed(pid: u32, nt_status: u32) -> Self {
        Self::new(
            OnyxErrorCode::ProcessSuspensionFailed,
            format!("NtSuspendProcess failed on PID {}", pid),
            format!("Falha ao suspender o processo PID {}", pid),
        )
        .with_win32(nt_status)
    }

    pub fn process_resume_failed(pid: u32, nt_status: u32) -> Self {
        Self::new(
            OnyxErrorCode::ProcessResumeFailed,
            format!("NtResumeProcess failed on PID {}", pid),
            format!("Falha ao retomar a execução do processo PID {}", pid),
        )
        .with_win32(nt_status)
    }

    pub fn process_invalid_handle() -> Self {
        Self::new(
            OnyxErrorCode::ProcessInvalidHandle,
            "Target process handle is null or closed",
            "Handle do processo alvo é inválido ou já foi encerrado",
        )
    }

    pub fn process_module_not_found(name: &str) -> Self {
        Self::new(
            OnyxErrorCode::ProcessModuleNotFound,
            format!("Module '{}' was not found in target process memory", name),
            format!("Módulo '{}' não foi encontrado na memória do processo", name),
        )
        .with_context(name)
    }

    // ==========================================
    // Specific Memory Error Constructors
    // ==========================================
    pub fn memory_read_failed(address: usize, size: usize, win32_code: u32) -> Self {
        Self::new(
            OnyxErrorCode::MemoryReadFailed,
            format!(
                "Failed to read {} bytes at 0x{:X}. Page might be unmapped or guarded",
                size, address
            ),
            format!(
                "Falha ao ler {} bytes no endereço 0x{:X}. Página inacessível, não mapeada ou protegida",
                size, address
            ),
        )
        .with_address(address)
        .with_win32(win32_code)
    }

    pub fn memory_write_failed(address: usize, size: usize, win32_code: u32) -> Self {
        Self::new(
            OnyxErrorCode::MemoryWriteFailed,
            format!(
                "Failed to write {} bytes at 0x{:X}. Page might be read-only or copy-on-write",
                size, address
            ),
            format!(
                "Falha ao gravar {} bytes no endereço 0x{:X}. Página protegida contra escrita",
                size, address
            ),
        )
        .with_address(address)
        .with_win32(win32_code)
    }

    pub fn memory_alloc_failed(size: usize, protect: u32, win32_code: u32) -> Self {
        Self::new(
            OnyxErrorCode::MemoryAllocFailed,
            format!(
                "Virtual allocation of {} bytes with protect 0x{:X} failed",
                size, protect
            ),
            format!(
                "Falha na alocação virtual de {} bytes com proteção 0x{:X}",
                size, protect
            ),
        )
        .with_win32(win32_code)
    }

    pub fn memory_protect_failed(address: usize, new_protect: u32, win32_code: u32) -> Self {
        Self::new(
            OnyxErrorCode::MemoryProtectFailed,
            format!(
                "VirtualProtect failed at 0x{:X} with new protect 0x{:X}",
                address, new_protect
            ),
            format!(
                "Falha ao alterar proteção de memória em 0x{:X} para 0x{:X}",
                address, new_protect
            ),
        )
        .with_address(address)
        .with_win32(win32_code)
    }

    pub fn memory_free_failed(address: usize, win32_code: u32) -> Self {
        Self::new(
            OnyxErrorCode::MemoryFreeFailed,
            format!("VirtualFree failed at address 0x{:X}", address),
            format!("Falha ao liberar memória virtual no endereço 0x{:X}", address),
        )
        .with_address(address)
        .with_win32(win32_code)
    }

    pub fn memory_page_guard(address: usize) -> Self {
        Self::new(
            OnyxErrorCode::MemoryPageGuardEncountered,
            format!("PAGE_GUARD violation triggered at 0x{:X}", address),
            format!("Exceção de proteção PAGE_GUARD interceptada no endereço 0x{:X}", address),
        )
        .with_address(address)
    }

    // ==========================================
    // Specific Driver & Ring-0 Error Constructors
    // ==========================================
    pub fn driver_not_connected() -> Self {
        Self::new(
            OnyxErrorCode::DriverNotConnected,
            "OwMemDriver is not connected or Ring-0 kernel device '\\\\.\\OwMemDriver' was not opened",
            "Driver OwMemDriver não está conectado ou o dispositivo '\\\\.\\OwMemDriver' não pôde ser aberto",
        )
    }

    pub fn driver_ioctl_failed(ioctl: u32, win32_code: u32) -> Self {
        Self::new(
            OnyxErrorCode::DriverIoctlFailed,
            format!("DeviceIoControl failed for IOCTL code 0x{:X}", ioctl),
            format!("Falha no despacho do DeviceIoControl para o código IOCTL 0x{:X}", ioctl),
        )
        .with_win32(win32_code)
    }

    pub fn driver_physical_read_failed(phys_addr: u64) -> Self {
        Self::new(
            OnyxErrorCode::DriverPhysicalReadFailed,
            format!("Kernel physical memory read failed at 0x{:X}", phys_addr),
            format!("Falha na leitura de memória física pelo kernel no endereço 0x{:X}", phys_addr),
        )
    }

    pub fn driver_physical_write_failed(phys_addr: u64) -> Self {
        Self::new(
            OnyxErrorCode::DriverPhysicalWriteFailed,
            format!("Kernel physical memory write failed at 0x{:X}", phys_addr),
            format!("Falha na gravação de memória física pelo kernel no endereço 0x{:X}", phys_addr),
        )
    }

    pub fn driver_cr3_walk_failed(virt_addr: usize) -> Self {
        Self::new(
            OnyxErrorCode::DriverCr3WalkFailed,
            format!("Failed to walk page table directory (CR3) for virtual address 0x{:X}", virt_addr),
            format!("Falha ao resolver tabela de páginas (CR3) para o endereço virtual 0x{:X}", virt_addr),
        )
        .with_address(virt_addr)
    }

    pub fn driver_intel_pt_unsupported(feature: &str) -> Self {
        Self::new(
            OnyxErrorCode::DriverIntelPtUnsupported,
            format!("Hardware does not support Intel PT / Ultimap feature: {}", feature),
            format!("Processador não suporta o recurso Intel PT / Ultimap: {}", feature),
        )
        .with_context(feature)
    }

    // ==========================================
    // Specific Scanner & Pointer Constructors
    // ==========================================
    pub fn scanner_invalid_pattern(pattern: &str, reason: &str) -> Self {
        Self::new(
            OnyxErrorCode::ScannerPatternParseFailed,
            format!("Invalid AOB pattern '{}': {}", pattern, reason),
            format!("Padrão AOB inválido '{}': {}", pattern, reason),
        )
        .with_context(reason)
    }

    pub fn scanner_no_active_scan() -> Self {
        Self::new(
            OnyxErrorCode::ScannerNoActiveScan,
            "No active memory scan session found. Please run a First Scan first",
            "Nenhuma sessão de varredura ativa. Execute uma Primeira Varredura primeiro",
        )
    }

    pub fn pointer_chain_broken(depth: usize, address: usize) -> Self {
        Self::new(
            OnyxErrorCode::PointerChainBroken,
            format!("Pointer chain resolution broken at depth {} at address 0x{:X}", depth, address),
            format!("Cadeia de ponteiros interrompida no nível {} no endereço 0x{:X}", depth, address),
        )
        .with_address(address)
    }

    // ==========================================
    // Specific Injections & Hooks Constructors
    // ==========================================
    pub fn injection_dll_not_found(path: &str) -> Self {
        Self::new(
            OnyxErrorCode::InjectionDllNotFound,
            format!("DLL binary for injection was not found at '{}'", path),
            format!("Arquivo DLL para injeção não foi encontrado no caminho '{}'", path),
        )
        .with_context(path)
    }

    pub fn injection_remote_alloc_failed(win32_code: u32) -> Self {
        Self::new(
            OnyxErrorCode::InjectionRemoteAllocFailed,
            "Failed to allocate memory buffer in remote target process for DLL path",
            "Falha ao alocar buffer de memória no processo alvo para o caminho da DLL",
        )
        .with_win32(win32_code)
    }

    pub fn injection_thread_failed(win32_code: u32) -> Self {
        Self::new(
            OnyxErrorCode::InjectionThreadCreationFailed,
            "CreateRemoteThread or thread hijacking failed in target process",
            "Falha ao criar thread remota (CreateRemoteThread) no processo alvo",
        )
        .with_win32(win32_code)
    }

    pub fn hook_target_too_small(size: usize, required: usize) -> Self {
        Self::new(
            OnyxErrorCode::HookTargetTooSmall,
            format!("Target prologue size ({} bytes) is smaller than required detour size ({} bytes)", size, required),
            format!("Tamanho do prólogo alvo ({} bytes) é menor que o desvio mínimo necessário ({} bytes)", size, required),
        )
    }

    pub fn manual_map_invalid_pe(reason: &str) -> Self {
        Self::new(
            OnyxErrorCode::ManualMapInvalidPeHeader,
            format!("Manual map failed: invalid PE format ({})", reason),
            format!("Manual map falhou: formato de cabeçalho PE inválido ({})", reason),
        )
        .with_context(reason)
    }

    // ==========================================
    // General / ABI Constructors
    // ==========================================
    pub fn null_pointer(param_name: &str) -> Self {
        Self::new(
            OnyxErrorCode::NullPointer,
            format!("Unexpected null pointer passed for parameter '{}'", param_name),
            format!("Ponteiro nulo inesperado passado para o parâmetro '{}'", param_name),
        )
        .with_context(param_name)
    }

    pub fn invalid_argument(reason: &str) -> Self {
        Self::new(
            OnyxErrorCode::InvalidArgument,
            format!("Invalid argument: {}", reason),
            format!("Argumento inválido: {}", reason),
        )
        .with_context(reason)
    }

    pub fn buffer_too_small(required: usize, provided: usize) -> Self {
        Self::new(
            OnyxErrorCode::BufferTooSmall,
            format!("Buffer too small: required {} bytes, but provided only {}", required, provided),
            format!("Buffer insuficiente: necessário {} bytes, mas fornecido apenas {}", required, provided),
        )
    }

    pub fn not_implemented(feature: &str) -> Self {
        Self::new(
            OnyxErrorCode::NotImplemented,
            format!("Feature '{}' is not yet implemented", feature),
            format!("Recurso '{}' ainda não está implementado", feature),
        )
        .with_context(feature)
    }
}
