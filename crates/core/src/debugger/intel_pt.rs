//! Intel Processor Trace (Intel PT) Decoder and Trace Processing Engine.
//!
//! Provides parsing, stream synchronization, and execution flow reconstruction for
//! hardware-captured packet streams (TIP, TNT, FUP, PSB, MODE, PIP, TSC, MTC)
//! from Intel Core processors (including 12th, 13th, and 14th gen Alder Lake / Raptor Lake).

use std::collections::BTreeMap;

/// Intel PT packet representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntelPtPacket {
    Pad,
    Psb,
    PsbEnd,
    Ovf,
    ShortTnt { count: u8, bits: u8 },
    LongTnt { count: u8, bits: u64 },
    Tip { ip: u64 },
    TipPge { ip: u64 },
    TipPgd { ip: u64 },
    Fup { ip: u64 },
    ModeExec { is_64bit: bool },
    ModeTsx { in_tx: bool },
    Pip { cr3: u64 },
    Tsc { timestamp: u64 },
    Mtc { ctc: u8 },
    Cyc { count: u32 },
    Unknown(u8),
}

/// Reconstructed execution flow event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntelPtExecutionEvent {
    TraceStart { ip: u64 },
    TraceStop { ip: u64 },
    Branch { from: u64, to: u64, taken: bool },
    FlowUpdate { ip: u64 },
    ContextSwitch { cr3: u64 },
}

/// Address filtering range for Intel PT execution filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressFilterRange {
    pub start_ip: u64,
    pub end_ip: u64,
}

impl AddressFilterRange {
    #[inline]
    pub fn contains(&self, ip: u64) -> bool {
        ip >= self.start_ip && ip <= self.end_ip
    }
}

/// High-performance stream decoder for Intel PT packets.
#[derive(Debug, Default)]
pub struct IntelPtDecoder {
    last_ip: u64,
    current_cr3: u64,
    in_trace: bool,
    filter_ranges: Vec<AddressFilterRange>,
}

impl IntelPtDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an execution range filter (e.g. main module bounds).
    pub fn add_filter_range(&mut self, start_ip: u64, end_ip: u64) {
        self.filter_ranges
            .push(AddressFilterRange { start_ip, end_ip });
    }

    /// Check if an IP matches any configured filter ranges (or true if no filters configured).
    #[inline]
    pub fn is_ip_allowed(&self, ip: u64) -> bool {
        if self.filter_ranges.is_empty() {
            true
        } else {
            self.filter_ranges.iter().any(|r| r.contains(ip))
        }
    }

    /// Parse an Intel PT raw byte stream into structured packets.
    pub fn parse_packets(&mut self, stream: &[u8]) -> Vec<IntelPtPacket> {
        let mut packets = Vec::new();
        let mut idx = 0;

        while idx < stream.len() {
            let b0 = stream[idx];

            // 1. PAD (0x00)
            if b0 == 0x00 {
                packets.push(IntelPtPacket::Pad);
                idx += 1;
                continue;
            }

            // 2. Multi-byte prefix 0x02
            if b0 == 0x02 && idx + 1 < stream.len() {
                let b1 = stream[idx + 1];

                // PSB (16-byte fixed pattern: repeating 0x02 0x82 x 8)
                if b1 == 0x82 && idx + 16 <= stream.len() {
                    let mut is_psb = true;
                    for p in 0..8 {
                        if stream[idx + p * 2] != 0x02 || stream[idx + p * 2 + 1] != 0x82 {
                            is_psb = false;
                            break;
                        }
                    }
                    if is_psb {
                        packets.push(IntelPtPacket::Psb);
                        idx += 16;
                        continue;
                    }
                }

                // PSBEND (0x02 0x23)
                if b1 == 0x23 {
                    packets.push(IntelPtPacket::PsbEnd);
                    idx += 2;
                    continue;
                }

                // OVF (0x02 0xF3)
                if b1 == 0xF3 {
                    packets.push(IntelPtPacket::Ovf);
                    idx += 2;
                    continue;
                }

                // PIP (0x02 0x43 followed by 6 bytes CR3)
                if b1 == 0x43 && idx + 8 <= stream.len() {
                    let mut cr3_bytes = [0u8; 8];
                    cr3_bytes[..6].copy_from_slice(&stream[idx + 2..idx + 8]);
                    let raw_cr3 = u64::from_le_bytes(cr3_bytes);
                    let cr3 = raw_cr3 & !0x1F; // Clear lower 5 flag bits
                    packets.push(IntelPtPacket::Pip { cr3 });
                    idx += 8;
                    continue;
                }

                // Long TNT (0x02 0xA3 followed by 6 bytes payload)
                if b1 == 0xA3 && idx + 8 <= stream.len() {
                    let mut tnt_bytes = [0u8; 8];
                    tnt_bytes[..6].copy_from_slice(&stream[idx + 2..idx + 8]);
                    let raw = u64::from_le_bytes(tnt_bytes);
                    // Highest set bit is stop bit
                    let stop_bit_pos = 63 - raw.leading_zeros();
                    let count = stop_bit_pos as u8;
                    let bits = raw & !(1 << stop_bit_pos);
                    packets.push(IntelPtPacket::LongTnt { count, bits });
                    idx += 8;
                    continue;
                }
            }

            // 3. Short TNT (0b...b10)
            if (b0 & 0x01) == 0 && (b0 != 0x00) {
                // Short TNT: lowest 0 bit followed by stop bit 1
                let stop_bit = 7 - b0.leading_zeros();
                if stop_bit > 1 {
                    let count = (stop_bit - 1) as u8;
                    let bits = (b0 >> 1) & ((1 << count) - 1);
                    packets.push(IntelPtPacket::ShortTnt { count, bits });
                    idx += 1;
                    continue;
                }
            }

            // 4. IP Packet Family: TIP (0x0d), TIP.PGE (0x11), TIP.PGD (0x01), FUP (0x1d)
            let op = b0 & 0x1F;
            if op == 0x0D || op == 0x11 || op == 0x01 || op == 0x1D {
                let ipc = (b0 >> 5) & 0x07;
                let (_ip_bytes, payload_len) = match ipc {
                    0 => (0, 0),
                    1 => (2, 2),
                    2 => (4, 4),
                    3 => (8, 8),
                    4 => (6, 6),
                    _ => (0, 0),
                };

                if idx + 1 + payload_len <= stream.len() {
                    let ip = self.decompress_ip(&stream[idx + 1..idx + 1 + payload_len], ipc);
                    self.last_ip = ip;
                    match op {
                        0x0D => packets.push(IntelPtPacket::Tip { ip }),
                        0x11 => packets.push(IntelPtPacket::TipPge { ip }),
                        0x01 => packets.push(IntelPtPacket::TipPgd { ip }),
                        0x1D => packets.push(IntelPtPacket::Fup { ip }),
                        _ => {}
                    }
                    idx += 1 + payload_len;
                    continue;
                }
            }

            // 5. MODE Packet (0x99 followed by leaf byte)
            if b0 == 0x99 && idx + 1 < stream.len() {
                let leaf = stream[idx + 1];
                if (leaf & 0xE0) == 0x00 {
                    let is_64bit = (leaf & 0x01) != 0;
                    packets.push(IntelPtPacket::ModeExec { is_64bit });
                    idx += 2;
                    continue;
                } else if (leaf & 0xE0) == 0x20 {
                    let in_tx = (leaf & 0x01) != 0;
                    packets.push(IntelPtPacket::ModeTsx { in_tx });
                    idx += 2;
                    continue;
                }
            }

            // 6. Timing Packets: TSC (0x19 + 7 bytes) and MTC (0x59 + 1 byte)
            if b0 == 0x19 && idx + 8 <= stream.len() {
                let mut tsc_bytes = [0u8; 8];
                tsc_bytes[..7].copy_from_slice(&stream[idx + 1..idx + 8]);
                let timestamp = u64::from_le_bytes(tsc_bytes);
                packets.push(IntelPtPacket::Tsc { timestamp });
                idx += 8;
                continue;
            }
            if b0 == 0x59 && idx + 2 <= stream.len() {
                let ctc = stream[idx + 1];
                packets.push(IntelPtPacket::Mtc { ctc });
                idx += 2;
                continue;
            }

            // Unrecognized byte
            packets.push(IntelPtPacket::Unknown(b0));
            idx += 1;
        }

        packets
    }

    /// Decompress IP based on Intel PT IPC field.
    #[inline]
    fn decompress_ip(&self, payload: &[u8], ipc: u8) -> u64 {
        match ipc {
            0 => self.last_ip,
            1 => {
                let mut bytes = [0u8; 8];
                bytes[..2].copy_from_slice(&payload[..2]);
                let val = u16::from_le_bytes([bytes[0], bytes[1]]) as u64;
                (self.last_ip & !0xFFFF) | val
            }
            2 => {
                let mut bytes = [0u8; 8];
                bytes[..4].copy_from_slice(&payload[..4]);
                let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
                (self.last_ip & !0xFFFF_FFFF) | val
            }
            3 => {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(payload);
                u64::from_le_bytes(bytes)
            }
            4 => {
                let mut bytes = [0u8; 8];
                bytes[..6].copy_from_slice(&payload[..6]);
                let raw = u64::from_le_bytes(bytes);
                // Sign extend bit 47
                if (raw & (1 << 47)) != 0 {
                    raw | 0xFFFF_0000_0000_0000
                } else {
                    raw
                }
            }
            _ => self.last_ip,
        }
    }

    /// Reconstruct execution flow events with module filtering.
    pub fn reconstruct_execution_flow(&mut self, stream: &[u8]) -> Vec<IntelPtExecutionEvent> {
        let packets = self.parse_packets(stream);
        let mut events = Vec::new();
        let mut current_ip = 0u64;

        for pkt in packets {
            match pkt {
                IntelPtPacket::Psb => {
                    self.in_trace = true;
                }
                IntelPtPacket::TipPge { ip } => {
                    self.in_trace = true;
                    current_ip = ip;
                    if self.is_ip_allowed(ip) {
                        events.push(IntelPtExecutionEvent::TraceStart { ip });
                    }
                }
                IntelPtPacket::TipPgd { ip } => {
                    self.in_trace = false;
                    if self.is_ip_allowed(ip) {
                        events.push(IntelPtExecutionEvent::TraceStop { ip });
                    }
                }
                IntelPtPacket::Tip { ip } => {
                    if self.in_trace && self.is_ip_allowed(ip) {
                        events.push(IntelPtExecutionEvent::Branch {
                            from: current_ip,
                            to: ip,
                            taken: true,
                        });
                    }
                    current_ip = ip;
                }
                IntelPtPacket::Fup { ip } => {
                    if self.is_ip_allowed(ip) {
                        events.push(IntelPtExecutionEvent::FlowUpdate { ip });
                    }
                    current_ip = ip;
                }
                IntelPtPacket::Pip { cr3 } => {
                    self.current_cr3 = cr3;
                    events.push(IntelPtExecutionEvent::ContextSwitch { cr3 });
                }
                IntelPtPacket::ShortTnt { count, bits } => {
                    for i in 0..count {
                        let taken = ((bits >> (count - 1 - i)) & 1) != 0;
                        if self.in_trace && self.is_ip_allowed(current_ip) {
                            events.push(IntelPtExecutionEvent::Branch {
                                from: current_ip,
                                to: 0, // Inferred by disassembler in full trace walk
                                taken,
                            });
                        }
                    }
                }
                IntelPtPacket::LongTnt { count, bits } => {
                    for i in 0..count {
                        let taken = ((bits >> (count - 1 - i)) & 1) != 0;
                        if self.in_trace && self.is_ip_allowed(current_ip) {
                            events.push(IntelPtExecutionEvent::Branch {
                                from: current_ip,
                                to: 0,
                                taken,
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        events
    }
}

/// Multithreaded session trace processor collecting Intel PT events across CPU cores.
#[derive(Debug, Default)]
pub struct IntelPtMultiCoreSession {
    core_decoders: BTreeMap<u32, IntelPtDecoder>,
    aggregated_events: Vec<IntelPtExecutionEvent>,
    filter_ranges: Vec<AddressFilterRange>,
}

impl IntelPtMultiCoreSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_module_filter(&mut self, start_ip: u64, end_ip: u64) {
        self.filter_ranges = vec![AddressFilterRange { start_ip, end_ip }];
        for decoder in self.core_decoders.values_mut() {
            decoder.filter_ranges = self.filter_ranges.clone();
        }
    }

    /// Process raw packet buffer received from a specific CPU core.
    pub fn process_core_buffer(&mut self, cpu_id: u32, raw_buffer: &[u8]) -> usize {
        let ranges = self.filter_ranges.clone();
        let decoder = self.core_decoders.entry(cpu_id).or_insert_with(|| {
            let mut d = IntelPtDecoder::new();
            d.filter_ranges = ranges;
            d
        });

        let mut events = decoder.reconstruct_execution_flow(raw_buffer);
        let count = events.len();
        self.aggregated_events.append(&mut events);
        count
    }

    pub fn total_events(&self) -> usize {
        self.aggregated_events.len()
    }

    pub fn clear(&mut self) {
        self.core_decoders.clear();
        self.aggregated_events.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psb_detection() {
        let psb = [0x02, 0x82].repeat(8);
        let mut decoder = IntelPtDecoder::new();
        let pkts = decoder.parse_packets(&psb);
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0], IntelPtPacket::Psb);
    }

    #[test]
    fn test_tip_pge_and_tip_pgd_decompression() {
        // TIP.PGE with 48-bit IP (IPC = 4 -> opcode = (4 << 5) | 0x11 = 0x91)
        let mut stream = vec![0x91];
        let target_ip: u64 = 0x7FF6_1234_5678;
        stream.extend_from_slice(&target_ip.to_le_bytes()[..6]);

        // TIP.PGD with suppressed IP (IPC = 0 -> opcode = 0x01)
        stream.push(0x01);

        let mut decoder = IntelPtDecoder::new();
        let pkts = decoder.parse_packets(&stream);
        assert_eq!(pkts.len(), 2);
        assert_eq!(pkts[0], IntelPtPacket::TipPge { ip: target_ip });
        assert_eq!(pkts[1], IntelPtPacket::TipPgd { ip: target_ip });
    }

    #[test]
    fn test_short_tnt_parsing() {
        // Short TNT: 0b00101110 -> stop bit at 5, branches: Taken(1), NotTaken(0), Taken(1), Taken(1)
        // bit 0 is 0. bits [4:1] = 0b0111, bit 5 = 1 (stop bit).
        let tnt_byte = 0b0011_1110;
        let mut decoder = IntelPtDecoder::new();
        let pkts = decoder.parse_packets(&[tnt_byte]);
        assert_eq!(pkts.len(), 1);
        if let IntelPtPacket::ShortTnt { count, bits: _ } = pkts[0] {
            assert_eq!(count, 4);
        } else {
            panic!("Expected ShortTnt");
        }
    }

    #[test]
    fn test_pip_cr3_parsing() {
        // PIP: 0x02 0x43 followed by 6 bytes CR3
        let cr3_val: u64 = 0x1A2B_3000;
        let mut stream = vec![0x02, 0x43];
        stream.extend_from_slice(&cr3_val.to_le_bytes()[..6]);

        let mut decoder = IntelPtDecoder::new();
        let pkts = decoder.parse_packets(&stream);
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0], IntelPtPacket::Pip { cr3: cr3_val });
    }

    #[test]
    fn test_filter_by_range() {
        let mut decoder = IntelPtDecoder::new();
        decoder.add_filter_range(0x1000, 0x2000);

        // Packet 1: inside range
        let mut stream = vec![0x91];
        let ip_inside: u64 = 0x1500;
        stream.extend_from_slice(&ip_inside.to_le_bytes()[..6]);

        // Packet 2: outside range
        stream.push(0x91);
        let ip_outside: u64 = 0x3000;
        stream.extend_from_slice(&ip_outside.to_le_bytes()[..6]);

        let events = decoder.reconstruct_execution_flow(&stream);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], IntelPtExecutionEvent::TraceStart { ip: 0x1500 });
    }

    #[test]
    fn test_multicore_session_aggregation() {
        let mut session = IntelPtMultiCoreSession::new();
        session.set_module_filter(0x1000, 0x5000);

        let mut stream_cpu0 = vec![0x91];
        let ip_cpu0: u64 = 0x2000;
        stream_cpu0.extend_from_slice(&ip_cpu0.to_le_bytes()[..6]);

        let mut stream_cpu1 = vec![0x91];
        let ip_cpu1: u64 = 0x3000;
        stream_cpu1.extend_from_slice(&ip_cpu1.to_le_bytes()[..6]);

        let c0 = session.process_core_buffer(0, &stream_cpu0);
        let c1 = session.process_core_buffer(1, &stream_cpu1);

        assert_eq!(c0, 1);
        assert_eq!(c1, 1);
        assert_eq!(session.total_events(), 2);
    }
}
