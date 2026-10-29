//! Instalacao e remocao de hooks inline.

use crate::trampoline::{absolute_jmp, build_trampoline, TrampolineError, PATCH_SIZE};

#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
#[cfg(windows)]
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::GetCurrentProcess;

#[derive(Debug)]
pub enum HookError {
    Trampoline(TrampolineError),
    Alloc,
    Protect,
    #[cfg(not(windows))]
    Unsupported,
}

impl core::fmt::Display for HookError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HookError::Trampoline(e) => write!(f, "trampolim: {}", e),
            HookError::Alloc => write!(f, "falha ao alocar code cave"),
            HookError::Protect => write!(f, "falha ao alterar protecao de memoria"),
            #[cfg(not(windows))]
            HookError::Unsupported => write!(f, "plataforma nao suportada"),
        }
    }
}

impl std::error::Error for HookError {}

impl From<TrampolineError> for HookError {
    fn from(value: TrampolineError) -> Self {
        HookError::Trampoline(value)
    }
}

/// Representa um hook ativo. Enquanto este objeto estiver vivo o alvo
/// permanece patchado; chame [`Hook::remove`] para restaurar.
pub struct Hook {
    target: *mut u8,
    original_bytes: [u8; PATCH_SIZE],
    patched_len: usize,
    trampoline_ptr: *mut u8,
    trampoline_len: usize,
    trampoline_alloc_size: usize,
    active: bool,
}

// SAFETY: todos os acessos escrevem via APIs do SO em enderecos ja validados;
// nao ha estado interior compartilhado alem dos ponteiros brutos.
unsafe impl Send for Hook {}
unsafe impl Sync for Hook {}

impl Hook {
    /// Instala um hook inline substituindo o prologue de `target_fn` por um
    /// JMP para `hook_fn`. O trampolim retornado pode ser invocado via
    /// [`Hook::original`] para executar o comportamento original.
    #[cfg(windows)]
    pub fn new(target_fn: *const u8, hook_fn: *const u8) -> Result<Self, HookError> {
        if target_fn.is_null() || hook_fn.is_null() {
            return Err(HookError::Alloc);
        }

        // Le o maximo que pode precisar para decodificar: 15 bytes maximos
        // por instrucao x86-64, ate acumular PATCH_SIZE bytes.
        let probe_len = PATCH_SIZE + 15;
        let prologue = unsafe { core::slice::from_raw_parts(target_fn, probe_len) }.to_vec();

        // Aloca code cave RWX. Tamanho generoso: ate 15 bytes por instrucao
        // relocada mais o JMP de 14 bytes.
        let alloc_size: usize = 128;
        let cave = unsafe {
            VirtualAlloc(
                core::ptr::null(),
                alloc_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if cave.is_null() {
            return Err(HookError::Alloc);
        }

        let tramp = match build_trampoline(&prologue, target_fn as u64, cave as u64) {
            Ok(t) => t,
            Err(e) => {
                unsafe { VirtualFree(cave, 0, MEM_RELEASE) };
                return Err(e.into());
            }
        };

        if tramp.bytes.len() > alloc_size {
            unsafe { VirtualFree(cave, 0, MEM_RELEASE) };
            return Err(HookError::Alloc);
        }

        // Escreve trampolim.
        unsafe {
            core::ptr::copy_nonoverlapping(tramp.bytes.as_ptr(), cave as *mut u8, tramp.bytes.len());
        }

        // Backup dos bytes originais que serao sobrescritos.
        let mut original_bytes = [0u8; PATCH_SIZE];
        unsafe {
            core::ptr::copy_nonoverlapping(target_fn, original_bytes.as_mut_ptr(), PATCH_SIZE);
        }

        // Patch do alvo com JMP absoluto para hook.
        let patch = absolute_jmp(hook_fn as u64);
        let mut old_protect: u32 = 0;
        let ok = unsafe {
            VirtualProtect(
                target_fn as *mut _,
                PATCH_SIZE,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
        };
        if ok == 0 {
            unsafe { VirtualFree(cave, 0, MEM_RELEASE) };
            return Err(HookError::Protect);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(patch.as_ptr(), target_fn as *mut u8, PATCH_SIZE);
        }
        let mut dummy: u32 = 0;
        unsafe {
            VirtualProtect(
                target_fn as *mut _,
                PATCH_SIZE,
                old_protect,
                &mut dummy,
            );
            FlushInstructionCache(GetCurrentProcess(), target_fn as *const _, PATCH_SIZE);
            FlushInstructionCache(GetCurrentProcess(), cave as *const _, tramp.bytes.len());
        }

        Ok(Hook {
            target: target_fn as *mut u8,
            original_bytes,
            patched_len: PATCH_SIZE,
            trampoline_ptr: cave as *mut u8,
            trampoline_len: tramp.bytes.len(),
            trampoline_alloc_size: alloc_size,
            active: true,
        })
    }

    #[cfg(not(windows))]
    pub fn new(_target_fn: *const u8, _hook_fn: *const u8) -> Result<Self, HookError> {
        Err(HookError::Unsupported)
    }

    /// Retorna o ponteiro para o trampolim, que pode ser chamado como se
    /// fosse a funcao original.
    pub fn original(&self) -> *const u8 {
        self.trampoline_ptr as *const u8
    }

    /// Restaura os bytes originais do alvo e libera a code cave.
    #[cfg(windows)]
    pub fn remove(mut self) -> Result<(), HookError> {
        self.restore_in_place()
    }

    #[cfg(not(windows))]
    pub fn remove(self) -> Result<(), HookError> {
        Err(HookError::Unsupported)
    }

    #[cfg(windows)]
    fn restore_in_place(&mut self) -> Result<(), HookError> {
        if !self.active {
            return Ok(());
        }
        let mut old_protect: u32 = 0;
        let ok = unsafe {
            VirtualProtect(
                self.target as *mut _,
                self.patched_len,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
        };
        if ok == 0 {
            return Err(HookError::Protect);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.original_bytes.as_ptr(),
                self.target,
                self.patched_len,
            );
        }
        let mut dummy: u32 = 0;
        unsafe {
            VirtualProtect(
                self.target as *mut _,
                self.patched_len,
                old_protect,
                &mut dummy,
            );
            FlushInstructionCache(GetCurrentProcess(), self.target as *const _, self.patched_len);
            VirtualFree(self.trampoline_ptr as *mut _, 0, MEM_RELEASE);
        }
        self.active = false;
        // Silencia aviso de variavel nao usada.
        let _ = PAGE_EXECUTE_READ;
        let _ = self.trampoline_len;
        let _ = self.trampoline_alloc_size;
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for Hook {
    fn drop(&mut self) {
        if self.active {
            let _ = self.restore_in_place();
        }
    }
}
