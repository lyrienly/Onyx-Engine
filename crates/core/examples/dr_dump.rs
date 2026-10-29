use onyx_core::debugger::read_thread_debug_registers;
use onyx_core::process::Process;

fn main() {
    let pid = match std::env::args().nth(1).and_then(|arg| arg.parse::<u32>().ok()) {
        Some(pid) => pid,
        None => {
            eprintln!("uso: dr_dump.exe <pid>");
            std::process::exit(2);
        }
    };

    let proc = match Process::attach(pid) {
        Ok(proc) => proc,
        Err(error) => {
            eprintln!("falha ao anexar no pid {pid}: {error}");
            std::process::exit(1);
        }
    };

    let threads = match proc.threads() {
        Ok(threads) => threads,
        Err(error) => {
            eprintln!("falha ao listar threads: {error}");
            std::process::exit(1);
        }
    };

    println!("pid={pid} threads={}", threads.len());

    for tid in threads {
        match read_thread_debug_registers(tid) {
            Ok(dr) => {
                println!(
                    "tid={tid} dr0={:#x} dr1={:#x} dr2={:#x} dr3={:#x} dr6={:#x} dr7={:#x}",
                    dr.dr0, dr.dr1, dr.dr2, dr.dr3, dr.dr6, dr.dr7
                );
                println!(
                    "  habilitados: dr0={} dr1={} dr2={} dr3={}",
                    dr.slot_enabled(0),
                    dr.slot_enabled(1),
                    dr.slot_enabled(2),
                    dr.slot_enabled(3)
                );
            }
            Err(error) => println!("tid={tid} erro: {error}"),
        }
    }
}
