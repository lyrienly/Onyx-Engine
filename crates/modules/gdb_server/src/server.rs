use crate::protocol::{
    bytes_to_hex, encode_packet, hex_to_bytes, parse_hex_u64, parse_packet, Packet, ParseError,
};
use crate::target::{GdbTarget, Registers};

use std::io::{self, Read, Write};
use std::net::{TcpListener, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

enum Resp {
    Reply(Vec<u8>),
    Empty,
    Terminate,
}

pub struct GdbServer {
    pub thread: JoinHandle<io::Result<()>>,
}

impl GdbServer {
    pub fn listen<A, T>(addr: A, target: Arc<Mutex<T>>) -> io::Result<Self>
    where
        A: ToSocketAddrs,
        T: GdbTarget + 'static,
    {
        let listener = TcpListener::bind(addr)?;
        let thread = thread::spawn(move || -> io::Result<()> {
            let (stream, _peer) = listener.accept()?;
            let mut reader = stream.try_clone()?;
            let mut writer = stream;
            serve_connection(&mut reader, &mut writer, &target)
        });
        Ok(Self { thread })
    }
}

pub fn serve_connection<R, W, T>(
    reader: &mut R,
    writer: &mut W,
    target: &Arc<Mutex<T>>,
) -> io::Result<()>
where
    R: Read,
    W: Write,
    T: GdbTarget,
{
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];

    loop {
        loop {
            match parse_packet(&buf) {
                Ok((pkt, used)) => {
                    buf.drain(..used);
                    writer.write_all(b"+")?;
                    writer.flush()?;
                    let resp = handle_packet(&pkt, target);
                    match resp {
                        Resp::Reply(data) => {
                            let enc = encode_packet(&data);
                            writer.write_all(&enc)?;
                            writer.flush()?;
                        }
                        Resp::Empty => {
                            writer.write_all(&encode_packet(b""))?;
                            writer.flush()?;
                        }
                        Resp::Terminate => {
                            writer.write_all(&encode_packet(b"OK"))?;
                            writer.flush()?;
                            return Ok(());
                        }
                    }
                }
                Err(ParseError::Incomplete) => break,
                Err(ParseError::MissingStart) => {
                    if !buf.is_empty() {
                        buf.remove(0);
                    } else {
                        break;
                    }
                }
                Err(ParseError::BadChecksum { .. }) | Err(ParseError::BadHex) => {
                    writer.write_all(b"-")?;
                    writer.flush()?;
                    if let Some(pos) = buf.iter().position(|&b| b == b'#') {
                        let drop = (pos + 3).min(buf.len());
                        buf.drain(..drop);
                    } else {
                        buf.clear();
                    }
                }
            }
        }

        let n = reader.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn handle_packet<T: GdbTarget>(pkt: &Packet, target: &Arc<Mutex<T>>) -> Resp {
    let data = &pkt.data[..];
    let text = std::str::from_utf8(data).unwrap_or("");

    if data.is_empty() {
        return Resp::Empty;
    }

    match data[0] {
        b'?' => Resp::Reply(b"S05".to_vec()),
        b'g' => {
            let regs = match target.lock().unwrap().read_registers() {
                Ok(r) => r,
                Err(_) => return Resp::Reply(b"E01".to_vec()),
            };
            Resp::Reply(regs.to_g_hex().into_bytes())
        }
        b'G' => {
            let payload = &text[1..];
            match Registers::from_g_hex(payload) {
                Some(regs) => {
                    if target.lock().unwrap().write_registers(&regs).is_ok() {
                        Resp::Reply(b"OK".to_vec())
                    } else {
                        Resp::Reply(b"E01".to_vec())
                    }
                }
                None => Resp::Reply(b"E22".to_vec()),
            }
        }
        b'm' => {
            let rest = &text[1..];
            let (addr_s, len_s) = match rest.split_once(',') {
                Some(x) => x,
                None => return Resp::Reply(b"E22".to_vec()),
            };
            let addr = match parse_hex_u64(addr_s) {
                Ok(v) => v,
                Err(_) => return Resp::Reply(b"E22".to_vec()),
            };
            let len = match parse_hex_u64(len_s) {
                Ok(v) => v as usize,
                Err(_) => return Resp::Reply(b"E22".to_vec()),
            };
            match target.lock().unwrap().read_memory(addr, len) {
                Ok(bytes) => Resp::Reply(bytes_to_hex(&bytes).into_bytes()),
                Err(_) => Resp::Reply(b"E14".to_vec()),
            }
        }
        b'M' => {
            let rest = &text[1..];
            let (head, data_hex) = match rest.split_once(':') {
                Some(x) => x,
                None => return Resp::Reply(b"E22".to_vec()),
            };
            let (addr_s, _len_s) = match head.split_once(',') {
                Some(x) => x,
                None => return Resp::Reply(b"E22".to_vec()),
            };
            let addr = match parse_hex_u64(addr_s) {
                Ok(v) => v,
                Err(_) => return Resp::Reply(b"E22".to_vec()),
            };
            let bytes = match hex_to_bytes(data_hex) {
                Ok(b) => b,
                Err(_) => return Resp::Reply(b"E22".to_vec()),
            };
            match target.lock().unwrap().write_memory(addr, &bytes) {
                Ok(()) => Resp::Reply(b"OK".to_vec()),
                Err(_) => Resp::Reply(b"E14".to_vec()),
            }
        }
        b'p' => {
            let idx = match parse_hex_u64(&text[1..]) {
                Ok(v) => v as usize,
                Err(_) => return Resp::Reply(b"E22".to_vec()),
            };
            let regs = match target.lock().unwrap().read_registers() {
                Ok(r) => r,
                Err(_) => return Resp::Reply(b"E01".to_vec()),
            };
            match regs.get(idx) {
                Some(v) => Resp::Reply(bytes_to_hex(&v.to_le_bytes()).into_bytes()),
                None => Resp::Reply(b"E22".to_vec()),
            }
        }
        b'P' => {
            let rest = &text[1..];
            let (n_s, v_s) = match rest.split_once('=') {
                Some(x) => x,
                None => return Resp::Reply(b"E22".to_vec()),
            };
            let idx = match parse_hex_u64(n_s) {
                Ok(v) => v as usize,
                Err(_) => return Resp::Reply(b"E22".to_vec()),
            };
            let bytes = match hex_to_bytes(v_s) {
                Ok(b) => b,
                Err(_) => return Resp::Reply(b"E22".to_vec()),
            };
            if bytes.len() != 8 {
                return Resp::Reply(b"E22".to_vec());
            }
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes);
            let val = u64::from_le_bytes(arr);
            let mut t = target.lock().unwrap();
            let mut regs = match t.read_registers() {
                Ok(r) => r,
                Err(_) => return Resp::Reply(b"E01".to_vec()),
            };
            if !regs.set(idx, val) {
                return Resp::Reply(b"E22".to_vec());
            }
            match t.write_registers(&regs) {
                Ok(()) => Resp::Reply(b"OK".to_vec()),
                Err(_) => Resp::Reply(b"E01".to_vec()),
            }
        }
        b'c' => {
            let reason = target
                .lock()
                .unwrap()
                .cont()
                .unwrap_or(crate::target::StopReason::Trap);
            Resp::Reply(reason.encode().as_bytes().to_vec())
        }
        b's' => {
            let reason = target
                .lock()
                .unwrap()
                .step()
                .unwrap_or(crate::target::StopReason::Trap);
            Resp::Reply(reason.encode().as_bytes().to_vec())
        }
        b'k' => Resp::Terminate,
        b'D' => Resp::Reply(b"OK".to_vec()),
        b'H' => Resp::Reply(b"OK".to_vec()),
        b'Z' | b'z' => handle_breakpoint(text, target),
        b'q' => handle_query(text, target),
        b'v' => handle_v(text),
        _ => Resp::Empty,
    }
}

fn handle_breakpoint<T: GdbTarget>(text: &str, target: &Arc<Mutex<T>>) -> Resp {
    let add = text.starts_with('Z');
    let rest = &text[1..];
    let mut parts = rest.split(',');
    let type_s = match parts.next() {
        Some(s) => s,
        None => return Resp::Reply(b"E22".to_vec()),
    };
    let addr_s = match parts.next() {
        Some(s) => s,
        None => return Resp::Reply(b"E22".to_vec()),
    };
    let kind_s = match parts.next() {
        Some(s) => s,
        None => return Resp::Reply(b"E22".to_vec()),
    };
    let btype: u32 = match type_s.parse() {
        Ok(v) => v,
        Err(_) => return Resp::Reply(b"E22".to_vec()),
    };
    let addr = match parse_hex_u64(addr_s) {
        Ok(v) => v,
        Err(_) => return Resp::Reply(b"E22".to_vec()),
    };
    let kind = match parse_hex_u64(kind_s) {
        Ok(v) => v as u32,
        Err(_) => return Resp::Reply(b"E22".to_vec()),
    };

    let mut t = target.lock().unwrap();
    let r = match (btype, add) {
        (0, true) => t.add_sw_breakpoint(addr, kind),
        (0, false) => t.remove_sw_breakpoint(addr, kind),
        (1, true) => t.add_hw_breakpoint(addr, kind),
        (1, false) => t.remove_hw_breakpoint(addr, kind),
        _ => return Resp::Empty,
    };
    match r {
        Ok(()) => Resp::Reply(b"OK".to_vec()),
        Err(_) => Resp::Reply(b"E01".to_vec()),
    }
}

fn handle_query<T: GdbTarget>(text: &str, _target: &Arc<Mutex<T>>) -> Resp {
    if let Some(rest) = text.strip_prefix("qSupported") {
        let _ = rest;
        return Resp::Reply(b"PacketSize=4000;qXfer:features:read+".to_vec());
    }
    if text == "qAttached" || text.starts_with("qAttached:") {
        return Resp::Reply(b"1".to_vec());
    }
    if text == "qC" {
        return Resp::Reply(b"QC1".to_vec());
    }
    if text == "qfThreadInfo" {
        return Resp::Reply(b"m1".to_vec());
    }
    if text == "qsThreadInfo" {
        return Resp::Reply(b"l".to_vec());
    }
    if text == "qTStatus" {
        return Resp::Reply(b"T0".to_vec());
    }
    if text.starts_with("qXfer:features:read:target.xml") {
        return Resp::Reply(
            b"l<target version=\"1.0\"><architecture>i386:x86-64</architecture></target>".to_vec(),
        );
    }
    Resp::Empty
}

fn handle_v(text: &str) -> Resp {
    if text == "vMustReplyEmpty" {
        return Resp::Reply(Vec::new());
    }
    if text.starts_with("vCont?") {
        return Resp::Reply(b"vCont;c;s".to_vec());
    }
    Resp::Empty
}
