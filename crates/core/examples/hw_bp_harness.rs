use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use onyx_core::debugger::{
    read_thread_debug_registers, BreakpointSize, BreakpointType, HardwareBreakpointMonitor,
    HwBpError, VehDebugger,
};
use onyx_core::process::Process;

struct Target {
    child: Child,
    pid: u32,
    address: usize,
}

impl Target {
    fn spawn(exe: &PathBuf) -> Result<Self, String> {
        let mut child = Command::new(exe)
            .arg("8")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|error| format!("nao foi possivel iniciar {}: {error}", exe.display()))?;

        let stdout = child.stdout.take().ok_or("stdout do alvo indisponivel")?;
        let mut lines = BufReader::new(stdout).lines();

        let mut pid = None;
        let mut address = None;

        for _ in 0..3 {
            let line = lines
                .next()
                .ok_or("o alvo encerrou antes de informar PID/ADDR")?
                .map_err(|error| error.to_string())?;

            if let Some(value) = line.strip_prefix("PID=") {
                pid = value.trim().parse::<u32>().ok();
            } else if let Some(value) = line.strip_prefix("ADDR=") {
                address = usize::from_str_radix(value.trim().trim_start_matches("0x"), 16).ok();
            }
        }

        Ok(Target {
            child,
            pid: pid.ok_or("o alvo nao informou PID")?,
            address: address.ok_or("o alvo nao informou ADDR")?,
        })
    }

    fn send(&mut self, command: &str) -> Result<(), String> {
        let stdin = self.child.stdin.as_mut().ok_or("stdin do alvo indisponivel")?;
        stdin
            .write_all(format!("{command}\n").as_bytes())
            .map_err(|error| error.to_string())?;
        stdin.flush().map_err(|error| error.to_string())
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.send("QUIT");
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn main() {
    match run() {
        Ok(()) => println!("\nOK: todos os cenarios passaram"),
        Err(error) => {
            eprintln!("\nFALHOU: {error}");
            std::process::exit(1);
        }
    }
}

fn target_exe() -> Result<PathBuf, String> {
    let mut path = std::env::current_exe().map_err(|error| error.to_string())?;
    path.pop();

    let exe = path.join(format!("hw_bp_target{}", std::env::consts::EXE_SUFFIX));
    if !exe.exists() {
        return Err(format!(
            "{} nao encontrado. Rode antes: cargo build -p onyx_core --example hw_bp_target",
            exe.display()
        ));
    }

    Ok(exe)
}

fn run() -> Result<(), String> {
    let exe = target_exe()?;
    let mut target = Target::spawn(&exe)?;
    println!("alvo: pid={} addr={:#x}", target.pid, target.address);

    let proc = Process::attach(target.pid)?;
    let threads = proc.threads()?;
    println!("threads detectadas: {}", threads.len());
    if threads.len() < 2 {
        return Err("o alvo precisa ter pelo menos 2 threads".to_string());
    }

    let mut veh = VehDebugger::new(target.pid);

    let mut indices = Vec::new();
    for offset in 0..4 {
        let address = target.address + offset * 8;
        let index = veh
            .set_stealth_breakpoint(&proc, address, BreakpointType::Write, BreakpointSize::Byte8)
            .map_err(|error| format!("slot {offset}: {error}"))?;
        indices.push(index);
    }
    if indices != vec![0, 1, 2, 3] {
        return Err(format!("slots inesperados: {indices:?}"));
    }
    println!("1/6 quatro slots ocupados: {indices:?}");

    let dr = read_thread_debug_registers(threads[0])
        .map_err(|error| format!("leitura dos DRs falhou: {error}"))?;
    let expected = [
        target.address as u64,
        (target.address + 8) as u64,
        (target.address + 16) as u64,
        (target.address + 24) as u64,
    ];
    let actual = [dr.dr0, dr.dr1, dr.dr2, dr.dr3];
    for index in 0..4 {
        if actual[index] != expected[index] || !dr.slot_enabled(index) {
            return Err(format!(
                "DR{index} divergente: esperado {:#x}, obtido {:#x} (habilitado={})",
                expected[index],
                actual[index],
                dr.slot_enabled(index)
            ));
        }
    }
    println!(
        "1b/6 DRs fisicos conferem: {:#x} {:#x} {:#x} {:#x} dr7={:#x}",
        dr.dr0, dr.dr1, dr.dr2, dr.dr3, dr.dr7
    );

    match veh.set_stealth_breakpoint(
        &proc,
        target.address,
        BreakpointType::Write,
        BreakpointSize::Byte8,
    ) {
        Err(HwBpError::NoFreeSlot) => println!("2/6 quinto breakpoint recusado com NoFreeSlot (-2)"),
        other => return Err(format!("esperava NoFreeSlot, obteve {other:?}")),
    }

    veh.clear_stealth_breakpoint(&proc, 1)
        .map_err(|error| format!("clear do slot 1: {error}"))?;
    if veh.used_slots() != 3 {
        return Err(format!(
            "esperava 3 slots usados apos o clear, obteve {}",
            veh.used_slots()
        ));
    }

    let reused = veh
        .set_stealth_breakpoint(
            &proc,
            target.address + 0x40,
            BreakpointType::Execute,
            BreakpointSize::Byte1,
        )
        .map_err(|error| format!("reuso do slot 1: {error}"))?;
    if reused != 1 {
        return Err(format!("esperava reuso do slot 1, obteve {reused}"));
    }
    println!("3/6 slot 1 liberado e reutilizado");

    match veh.clear_stealth_breakpoint(&proc, 4) {
        Err(HwBpError::InvalidSlot) => println!("4/6 slot 4 recusado com InvalidSlot (-3)"),
        other => return Err(format!("esperava InvalidSlot, obteve {other:?}")),
    }

    veh.clear_all(&proc);
    if veh.used_slots() != 0 {
        return Err(format!(
            "esperava registro vazio, obteve {} slots",
            veh.used_slots()
        ));
    }
    println!("5/6 registro de slots limpo");

    target.send("GO")?;
    let stop = Arc::new(AtomicBool::new(false));
    let hits = HardwareBreakpointMonitor::monitor_address(
        &proc,
        0,
        target.address,
        BreakpointType::Write,
        BreakpointSize::Byte8,
        3,
        stop,
    )?;
    target.send("STOP")?;

    if hits.is_empty() {
        return Err("nenhum hit capturado pelo monitor".to_string());
    }
    println!(
        "6/6 hit capturado: {} ocorrencias em '{}'",
        hits[0].count, hits[0].instruction_text
    );

    Ok(())
}
