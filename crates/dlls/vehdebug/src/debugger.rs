//! Breakpoint manager (software INT3 + hardware DR0-DR7) por cima do
//! dispatcher VEH. Design foca em estabilidade:
//!
//! * SW bp: escreve `0xCC`, VEH captura `EXCEPTION_BREAKPOINT`, decrementa RIP,
//!   restaura o byte original e liga a Trap Flag para re-armar o `0xCC`
//!   depois que a instrucao original executa (igual tecnica usada em #36).
//! * HW bp: configura DR0-DR3 + DR7 na thread corrente; no hit, limpa DR6 e
//!   seta a Resume Flag para evitar refire infinito.

use crate::ffi::*;
use crate::veh::{
    BreakpointId, VehDisposition, VehHandler, allocate_id, register_handler,
    unregister_handler,
};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Mutex;

/// Snapshot entregue ao callback de hit.
#[derive(Debug, Copy, Clone, Default)]
pub struct BpHit {
    pub id: u64,
    pub rip: u64,
    pub thread_id: u32,
    pub dr6: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
}

pub type HitSink = Box<dyn Fn(BpHit) + Send + Sync>;

/// Tamanhos validos para HW bp (bits LEN em DR7).
#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum HwBpSize {
    One = 0b00,
    Two = 0b01,
    Four = 0b11,
    Eight = 0b10,
}

/// Tipos de acesso (bits R/W em DR7).
#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum HwBpAccess {
    Execute = 0b00,
    Write = 0b01,
    ReadWrite = 0b11,
}

// -------------------- Software breakpoint --------------------

struct SwBreakpoint {
    id: BreakpointId,
    address: usize,
    original_byte: AtomicU8,
    armed: AtomicBool,
    expecting_single_step: AtomicBool,
    sink: Option<HitSink>,
}

impl SwBreakpoint {
    fn arm(&self) -> bool {
        unsafe { patch_byte(self.address, 0xCC, &self.original_byte, &self.armed) }
    }
    fn disarm(&self) -> bool {
        if !self.armed.load(Ordering::SeqCst) {
            return true;
        }
        unsafe {
            let orig = self.original_byte.load(Ordering::SeqCst);
            let ok = write_byte(self.address, orig);
            if ok {
                self.armed.store(false, Ordering::SeqCst);
            }
            ok
        }
    }
}

impl Drop for SwBreakpoint {
    fn drop(&mut self) {
        // Garante que o byte original volta ao lugar quando o breakpoint
        // sai do registry — essencial para evitar INT3 orfao no alvo.
        let _ = self.disarm();
    }
}

impl Drop for HwBreakpoint {
    fn drop(&mut self) {
        // Reprograma o DR correspondente para zero.
        let _ = program_debug_registers(
            0,
            self.dr_index,
            HwBpAccess::Execute,
            HwBpSize::One,
            false,
        );
    }
}

impl VehHandler for SwBreakpoint {
    fn id(&self) -> BreakpointId {
        self.id
    }

    fn matches(&self, record: &EXCEPTION_RECORD, context: &CONTEXT) -> bool {
        if record.ExceptionCode == EXCEPTION_BREAKPOINT {
            // RIP ja esta no byte do INT3 em x64 (o kernel aponta para a
            // instrucao faulting, nao para a proxima).
            return context.Rip as usize == self.address;
        }
        if record.ExceptionCode == EXCEPTION_SINGLE_STEP
            && self.expecting_single_step.load(Ordering::SeqCst)
        {
            // Um unico single-step pendente apos restauro para re-armar.
            return true;
        }
        false
    }

    fn handle(&self, record: &EXCEPTION_RECORD, context: &mut CONTEXT) -> VehDisposition {
        match record.ExceptionCode {
            EXCEPTION_BREAKPOINT => {
                // Reporta hit.
                if let Some(sink) = &self.sink {
                    sink(BpHit {
                        id: self.id.0,
                        rip: context.Rip,
                        thread_id: unsafe { GetCurrentThreadId() },
                        dr6: context.Dr6,
                        rax: context.Rax,
                        rbx: context.Rbx,
                        rcx: context.Rcx,
                        rdx: context.Rdx,
                        rsi: context.Rsi,
                        rdi: context.Rdi,
                        rsp: context.Rsp,
                        rbp: context.Rbp,
                    });
                }

                // Restaura byte original para a instrucao poder rodar.
                unsafe {
                    let orig = self.original_byte.load(Ordering::SeqCst);
                    write_byte(self.address, orig);
                }
                self.armed.store(false, Ordering::SeqCst);

                // Liga TF para pegar um single-step e re-armar o INT3.
                self.expecting_single_step.store(true, Ordering::SeqCst);
                context.EFlags |= EFLAGS_TF;
                VehDisposition::Continue
            }
            EXCEPTION_SINGLE_STEP => {
                // Instrucao original ja executou — re-arma.
                self.expecting_single_step.store(false, Ordering::SeqCst);
                let _ = self.arm();
                context.EFlags &= !EFLAGS_TF;
                VehDisposition::Continue
            }
            _ => VehDisposition::Search,
        }
    }
}

// -------------------- Hardware breakpoint --------------------

struct HwBreakpoint {
    id: BreakpointId,
    address: u64,
    dr_index: u8, // 0..=3
    sink: Option<HitSink>,
}

impl VehHandler for HwBreakpoint {
    fn id(&self) -> BreakpointId {
        self.id
    }

    fn matches(&self, record: &EXCEPTION_RECORD, context: &CONTEXT) -> bool {
        if record.ExceptionCode != EXCEPTION_SINGLE_STEP {
            return false;
        }
        // bit B0..B3 em DR6 sinaliza qual DR disparou.
        let mask = 1u64 << self.dr_index;
        (context.Dr6 & mask) != 0
    }

    fn handle(&self, _record: &EXCEPTION_RECORD, context: &mut CONTEXT) -> VehDisposition {
        if let Some(sink) = &self.sink {
            sink(BpHit {
                id: self.id.0,
                rip: context.Rip,
                thread_id: unsafe { GetCurrentThreadId() },
                dr6: context.Dr6,
                rax: context.Rax,
                rbx: context.Rbx,
                rcx: context.Rcx,
                rdx: context.Rdx,
                rsi: context.Rsi,
                rdi: context.Rdi,
                rsp: context.Rsp,
                rbp: context.Rbp,
            });
        }
        // Limpa o bit especifico de DR6 e seta RF em EFLAGS: assim a
        // instrucao faulting nao refira o mesmo DR imediatamente.
        context.Dr6 &= !(1u64 << self.dr_index);
        context.EFlags |= EFLAGS_RF;
        VehDisposition::Continue
    }
}

// -------------------- VehDebugger --------------------

/// Facade publica. Dona do `VehRegistration` enquanto estiver viva.
pub struct VehDebugger {
    _registration: crate::veh::VehRegistration,
}

impl VehDebugger {
    pub fn new() -> Option<Self> {
        crate::veh::arm_dispatcher();
        let reg = crate::veh::VehRegistration::install()?;
        Some(Self { _registration: reg })
    }

    pub fn set_sw_bp(&self, address: usize, sink: Option<HitSink>) -> Option<BreakpointId> {
        let id = allocate_id();
        let bp = SwBreakpoint {
            id,
            address,
            original_byte: AtomicU8::new(0),
            armed: AtomicBool::new(false),
            expecting_single_step: AtomicBool::new(false),
            sink,
        };
        if !bp.arm() {
            return None;
        }
        register_handler(Box::new(bp));
        Some(id)
    }

    pub fn set_hw_bp(
        &self,
        address: u64,
        dr_index: u8,
        access: HwBpAccess,
        size: HwBpSize,
        sink: Option<HitSink>,
    ) -> Option<BreakpointId> {
        if dr_index > 3 {
            return None;
        }
        if !program_debug_registers(address, dr_index, access, size, true) {
            return None;
        }
        let id = allocate_id();
        let bp = HwBreakpoint {
            id,
            address,
            dr_index,
            sink,
        };
        register_handler(Box::new(bp));
        Some(id)
    }

    pub fn remove(&self, id: BreakpointId) -> bool {
        if let Some(h) = unregister_handler(id) {
            // Downcast nao e trivial com dyn trait sem Any; usamos um
            // marcador via drop custom. Para simplicidade: tentamos
            // tratar como SwBreakpoint primeiro — se o drop desarmar o
            // byte, otimo; HwBreakpoint precisa limpar DR*.
            //
            // Como alternativa limpa, chamamos uma trait method opcional
            // via side-channel: um Box<dyn VehHandler> nao expoe `remove`,
            // entao executamos a limpeza aqui por heuristica — a
            // implementacao concreta fica a cargo de cada struct via Drop.
            drop(h);
            // Reprograma DRs — se o id correspondia a um hw bp, o DR fica
            // sem a entrada. Como nao sabemos qual DR era, iteramos: na
            // pratica, chamadores sabem o id e podem invocar
            // `clear_all_hw_bps` quando quiserem.
            true
        } else {
            false
        }
    }

    /// Desliga TODOS os DRs da thread corrente — util como kill-switch.
    pub fn clear_all_hw_bps(&self) {
        clear_debug_registers();
    }
}

impl Drop for VehDebugger {
    fn drop(&mut self) {
        clear_debug_registers();
        crate::veh::disarm_dispatcher();
    }
}

// -------------------- Byte patching helpers --------------------

unsafe fn write_byte(address: usize, value: u8) -> bool {
    let mut old_prot: DWORD = 0;
    let addr = address as LPVOID;
    if VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &mut old_prot) == 0 {
        return false;
    }
    std::ptr::write_volatile(address as *mut u8, value);
    let mut _ignored: DWORD = 0;
    let _ = VirtualProtect(addr, 1, old_prot, &mut _ignored);
    FlushInstructionCache(GetCurrentProcess(), addr as LPCVOID, 1);
    true
}

unsafe fn patch_byte(
    address: usize,
    new_byte: u8,
    out_original: &AtomicU8,
    out_armed: &AtomicBool,
) -> bool {
    let mut old_prot: DWORD = 0;
    let addr = address as LPVOID;
    if VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &mut old_prot) == 0 {
        return false;
    }
    let original = std::ptr::read_volatile(address as *const u8);
    std::ptr::write_volatile(address as *mut u8, new_byte);
    let mut _ignored: DWORD = 0;
    let _ = VirtualProtect(addr, 1, old_prot, &mut _ignored);
    FlushInstructionCache(GetCurrentProcess(), addr as LPCVOID, 1);
    out_original.store(original, Ordering::SeqCst);
    out_armed.store(true, Ordering::SeqCst);
    true
}

// -------------------- Debug register plumbing --------------------

static DR_LOCK: Mutex<()> = Mutex::new(());

/// Programa um DR especifico. Preserva outros DRs ja setados.
fn program_debug_registers(
    address: u64,
    dr_index: u8,
    access: HwBpAccess,
    size: HwBpSize,
    enable: bool,
) -> bool {
    let _guard = DR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        let h = GetCurrentThread();
        if GetThreadContext(h, &mut ctx) == 0 {
            return false;
        }
        match dr_index {
            0 => ctx.Dr0 = address,
            1 => ctx.Dr1 = address,
            2 => ctx.Dr2 = address,
            3 => ctx.Dr3 = address,
            _ => return false,
        }
        let mut dr7 = ctx.Dr7;
        // Limpa 4 bits de LEN/RW para este DR (bits 16+idx*4 .. 19+idx*4).
        let rw_shift = 16 + (dr_index as u64) * 4;
        let len_shift = 18 + (dr_index as u64) * 4;
        dr7 &= !(0b1111u64 << rw_shift);
        // Limpa bits L/G (local/global enable) do DR.
        let le_shift = (dr_index as u64) * 2;
        dr7 &= !(0b11u64 << le_shift);
        if enable {
            dr7 |= (access as u64) << rw_shift;
            dr7 |= (size as u64) << len_shift;
            dr7 |= 1u64 << le_shift; // Local Enable
        }
        ctx.Dr7 = dr7;
        ctx.Dr6 = 0;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        SetThreadContext(h, &ctx) != 0
    }
}

/// Zera todos os DRs da thread corrente.
pub fn clear_debug_registers() {
    let _guard = DR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        let h = GetCurrentThread();
        if GetThreadContext(h, &mut ctx) == 0 {
            return;
        }
        ctx.Dr0 = 0;
        ctx.Dr1 = 0;
        ctx.Dr2 = 0;
        ctx.Dr3 = 0;
        ctx.Dr6 = 0;
        ctx.Dr7 = 0;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        let _ = SetThreadContext(h, &ctx);
    }
}
