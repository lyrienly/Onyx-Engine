//! e2e: sobe o GdbServer num socket local, abre um cliente rsp proprio
//! em rust e executa o handshake completo que ida/ghidra fazem.

use onyx_gdb_server::protocol::{bytes_to_hex, encode_packet, parse_packet};
use onyx_gdb_server::target::{MockTarget, Registers};
use onyx_gdb_server::GdbServer;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

/// manda `payload`, le ack, le reply.
fn exchange(stream: &mut TcpStream, payload: &[u8]) -> Vec<u8> {
    let enc = encode_packet(payload);
    stream.write_all(&enc).unwrap();
    stream.flush().unwrap();

    // le ate conseguir o `+` + um pacote inteiro
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        // tenta primeiro: pula acks e tenta parse
        let mut scan = buf.as_slice();
        while let Some(&b) = scan.first() {
            if b == b'+' || b == b'-' {
                scan = &scan[1..];
            } else {
                break;
            }
        }
        if let Ok((pkt, _)) = parse_packet(scan) {
            // manda ack pro servidor
            stream.write_all(b"+").unwrap();
            stream.flush().unwrap();
            return pkt.data;
        }
        let n = stream.read(&mut tmp).unwrap();
        assert!(n > 0, "conexao fechou antes do reply");
        buf.extend_from_slice(&tmp[..n]);
    }
}

#[test]
fn full_handshake_against_mock() {
    // alvo: registradores com valores conhecidos, mem com padrao
    let mut regs = Registers::default();
    regs.rax = 0x1122334455667788;
    regs.rbx = 0xaabbccddeeff0011;
    regs.rip = 0x0000_7ffe_0000_1234;

    let mut mock = MockTarget::new().with_memory(0x1000, &[0xde, 0xad, 0xbe, 0xef, 0x90, 0x90, 0xcc, 0xc3]);
    mock.regs = regs.clone();
    let target = Arc::new(Mutex::new(mock));

    let port = free_port();
    let addr = format!("127.0.0.1:{}", port);
    let server = GdbServer::listen(addr.clone(), target.clone()).unwrap();

    // da um instante pro listener aceitar
    std::thread::sleep(Duration::from_millis(50));
    let mut stream = TcpStream::connect(&addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // 1) qSupported
    let r = exchange(&mut stream, b"qSupported:multiprocess+;xmlRegisters=i386");
    let r_s = std::str::from_utf8(&r).unwrap();
    eprintln!("[e2e] qSupported -> {}", r_s);
    assert!(r_s.contains("PacketSize=4000"));

    // 2) vMustReplyEmpty
    let r = exchange(&mut stream, b"vMustReplyEmpty");
    eprintln!("[e2e] vMustReplyEmpty -> {:?}", std::str::from_utf8(&r));
    assert!(r.is_empty());

    // 3) ?
    let r = exchange(&mut stream, b"?");
    eprintln!("[e2e] ? -> {}", std::str::from_utf8(&r).unwrap());
    assert_eq!(&r, b"S05");

    // 4) qAttached
    let r = exchange(&mut stream, b"qAttached");
    eprintln!("[e2e] qAttached -> {}", std::str::from_utf8(&r).unwrap());
    assert_eq!(&r, b"1");

    // 5) g — regs
    let r = exchange(&mut stream, b"g");
    let hex = std::str::from_utf8(&r).unwrap();
    eprintln!("[e2e] g -> {} chars", hex.len());
    assert_eq!(hex.len(), Registers::BYTES * 2);
    // confere os 8 bytes do RAX
    let expected_rax = bytes_to_hex(&regs.rax.to_le_bytes());
    assert_eq!(&hex[..16], expected_rax.as_str());

    // 6) p0 — rax individual
    let r = exchange(&mut stream, b"p0");
    assert_eq!(std::str::from_utf8(&r).unwrap(), expected_rax);
    eprintln!("[e2e] p0 (rax) -> {}", expected_rax);

    // 7) P16=... — seta rip
    let new_rip: u64 = 0xcafef00d_12345678;
    let p_payload = format!("P10={}", bytes_to_hex(&new_rip.to_le_bytes())); // 0x10=16=rip
    let r = exchange(&mut stream, p_payload.as_bytes());
    assert_eq!(&r, b"OK");
    assert_eq!(target.lock().unwrap().regs.rip, new_rip);
    eprintln!("[e2e] P10 -> OK, rip agora = {:#x}", new_rip);

    // 8) m1000,8 — le a memoria
    let r = exchange(&mut stream, b"m1000,8");
    let r_s = std::str::from_utf8(&r).unwrap();
    eprintln!("[e2e] m1000,8 -> {}", r_s);
    assert_eq!(r_s, "deadbeef9090ccc3");

    // 9) M1008,4:aabbccdd — escreve e confere
    let r = exchange(&mut stream, b"M1008,4:aabbccdd");
    assert_eq!(&r, b"OK");
    let r = exchange(&mut stream, b"m1008,4");
    assert_eq!(std::str::from_utf8(&r).unwrap(), "aabbccdd");
    eprintln!("[e2e] M + m roundtrip ok");

    // 10) Z0 breakpoint em 0x1000
    let r = exchange(&mut stream, b"Z0,1000,1");
    assert_eq!(&r, b"OK");
    assert_eq!(target.lock().unwrap().breakpoints.len(), 1);
    eprintln!("[e2e] Z0 ok");

    // 11) c — continue (mock devolve trap)
    let r = exchange(&mut stream, b"c");
    assert_eq!(&r, b"S05");
    eprintln!("[e2e] c -> S05");

    // 12) s — step
    let r = exchange(&mut stream, b"s");
    assert_eq!(&r, b"S05");
    eprintln!("[e2e] s -> S05");

    // 13) k — kill, encerra sessao
    let r = exchange(&mut stream, b"k");
    assert_eq!(&r, b"OK");
    eprintln!("[e2e] k -> OK (sessao encerrada)");

    drop(stream);
    // o server retorna apos o k
    let _ = server.thread.join().unwrap();
    eprintln!("[e2e] servidor terminou limpo");
}

#[test]
fn unknown_command_returns_empty() {
    let target = Arc::new(Mutex::new(MockTarget::new()));
    let port = free_port();
    let addr = format!("127.0.0.1:{}", port);
    let server = GdbServer::listen(addr.clone(), target).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let mut stream = TcpStream::connect(&addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let r = exchange(&mut stream, b"XqualquerCoisa");
    assert!(r.is_empty(), "comando desconhecido deve retornar pacote vazio");

    let r = exchange(&mut stream, b"k");
    assert_eq!(&r, b"OK");
    let _ = server.thread.join();
}
