//! abstracao do alvo de depuracao: registradores + memoria.
//!
//! o servidor nao conhece a implementacao concreta — pode ser um processo
//! usuario (ReadProcessMemory), o driver ow_mem ou um mock pra teste.

use std::collections::BTreeMap;
use std::io;
use std::sync::Mutex;

/// 17 registradores gerais x86_64 na ordem que o gdb espera:
/// rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8..r15, rip.
#[derive(Debug, Clone, Default)]
pub struct Registers {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
}

impl Registers {
    pub const COUNT: usize = 17;
    pub const BYTES: usize = 17 * 8;

    pub fn get(&self, idx: usize) -> Option<u64> {
        Some(match idx {
            0 => self.rax,
            1 => self.rbx,
            2 => self.rcx,
            3 => self.rdx,
            4 => self.rsi,
            5 => self.rdi,
            6 => self.rbp,
            7 => self.rsp,
            8 => self.r8,
            9 => self.r9,
            10 => self.r10,
            11 => self.r11,
            12 => self.r12,
            13 => self.r13,
            14 => self.r14,
            15 => self.r15,
            16 => self.rip,
            _ => return None,
        })
    }

    pub fn set(&mut self, idx: usize, val: u64) -> bool {
        let slot = match idx {
            0 => &mut self.rax,
            1 => &mut self.rbx,
            2 => &mut self.rcx,
            3 => &mut self.rdx,
            4 => &mut self.rsi,
            5 => &mut self.rdi,
            6 => &mut self.rbp,
            7 => &mut self.rsp,
            8 => &mut self.r8,
            9 => &mut self.r9,
            10 => &mut self.r10,
            11 => &mut self.r11,
            12 => &mut self.r12,
            13 => &mut self.r13,
            14 => &mut self.r14,
            15 => &mut self.r15,
            16 => &mut self.rip,
            _ => return false,
        };
        *slot = val;
        true
    }

    /// serializa como g packet: 17 u64 little-endian em hex ascii.
    pub fn to_g_hex(&self) -> String {
        let mut buf = [0u8; Self::BYTES];
        for i in 0..Self::COUNT {
            let v = self.get(i).unwrap();
            buf[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
        }
        let mut s = String::with_capacity(Self::BYTES * 2);
        for b in buf.iter() {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    /// faz parse do payload de um G packet.
    pub fn from_g_hex(s: &str) -> Option<Self> {
        if s.len() < Self::BYTES * 2 {
            return None;
        }
        let bytes = crate::protocol::hex_to_bytes(&s[..Self::BYTES * 2]).ok()?;
        let mut r = Registers::default();
        for i in 0..Self::COUNT {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            r.set(i, u64::from_le_bytes(buf));
        }
        Some(r)
    }
}

/// razao do halt — reportada ao cliente via `?` e apos `c`/`s`.
#[derive(Debug, Clone, Copy)]
pub enum StopReason {
    Trap,       // S05 — breakpoint/single-step
    Interrupt,  // S02
    Exited,     // W00
}

impl StopReason {
    pub fn encode(&self) -> &'static str {
        match self {
            StopReason::Trap => "S05",
            StopReason::Interrupt => "S02",
            StopReason::Exited => "W00",
        }
    }
}

/// trait implementada pelos alvos reais (processo win32, driver, veh)
/// e pelo mock de teste.
pub trait GdbTarget: Send {
    fn read_registers(&self) -> io::Result<Registers>;
    fn write_registers(&mut self, regs: &Registers) -> io::Result<()>;
    fn read_memory(&self, addr: u64, len: usize) -> io::Result<Vec<u8>>;
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> io::Result<()>;
    fn cont(&mut self) -> io::Result<StopReason> {
        Ok(StopReason::Trap)
    }
    fn step(&mut self) -> io::Result<StopReason> {
        Ok(StopReason::Trap)
    }
    fn add_sw_breakpoint(&mut self, _addr: u64, _kind: u32) -> io::Result<()> {
        Ok(())
    }
    fn remove_sw_breakpoint(&mut self, _addr: u64, _kind: u32) -> io::Result<()> {
        Ok(())
    }
    fn add_hw_breakpoint(&mut self, _addr: u64, _kind: u32) -> io::Result<()> {
        Ok(())
    }
    fn remove_hw_breakpoint(&mut self, _addr: u64, _kind: u32) -> io::Result<()> {
        Ok(())
    }
}

/// alvo falso em memoria para testes e desenvolvimento.
pub struct MockTarget {
    pub regs: Registers,
    pub mem: BTreeMap<u64, u8>,
    pub breakpoints: Vec<(u64, u32, bool)>, // (addr, kind, is_hw)
}

impl MockTarget {
    pub fn new() -> Self {
        Self {
            regs: Registers::default(),
            mem: BTreeMap::new(),
            breakpoints: Vec::new(),
        }
    }

    pub fn with_memory(mut self, base: u64, data: &[u8]) -> Self {
        for (i, b) in data.iter().enumerate() {
            self.mem.insert(base + i as u64, *b);
        }
        self
    }
}

impl Default for MockTarget {
    fn default() -> Self {
        Self::new()
    }
}

impl GdbTarget for MockTarget {
    fn read_registers(&self) -> io::Result<Registers> {
        Ok(self.regs.clone())
    }
    fn write_registers(&mut self, regs: &Registers) -> io::Result<()> {
        self.regs = regs.clone();
        Ok(())
    }
    fn read_memory(&self, addr: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            out.push(*self.mem.get(&(addr + i as u64)).unwrap_or(&0));
        }
        Ok(out)
    }
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> io::Result<()> {
        for (i, b) in data.iter().enumerate() {
            self.mem.insert(addr + i as u64, *b);
        }
        Ok(())
    }
    fn add_sw_breakpoint(&mut self, addr: u64, kind: u32) -> io::Result<()> {
        self.breakpoints.push((addr, kind, false));
        Ok(())
    }
    fn remove_sw_breakpoint(&mut self, addr: u64, kind: u32) -> io::Result<()> {
        self.breakpoints
            .retain(|(a, k, hw)| !(*a == addr && *k == kind && !*hw));
        Ok(())
    }
    fn add_hw_breakpoint(&mut self, addr: u64, kind: u32) -> io::Result<()> {
        self.breakpoints.push((addr, kind, true));
        Ok(())
    }
    fn remove_hw_breakpoint(&mut self, addr: u64, kind: u32) -> io::Result<()> {
        self.breakpoints
            .retain(|(a, k, hw)| !(*a == addr && *k == kind && *hw));
        Ok(())
    }
}

/// wrapper que coloca um alvo atras de mutex para compartilhar entre threads.
pub struct SharedTarget<T: GdbTarget> {
    inner: Mutex<T>,
}

impl<T: GdbTarget> SharedTarget<T> {
    pub fn new(t: T) -> Self {
        Self {
            inner: Mutex::new(t),
        }
    }
    pub fn lock(&self) -> std::sync::MutexGuard<'_, T> {
        self.inner.lock().unwrap()
    }
}
