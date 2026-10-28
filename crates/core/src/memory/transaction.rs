use crate::process::{Process, ProcessAccessMode};

#[derive(Debug, Clone)]
pub struct WriteOp {
    pub address: usize,
    pub old_bytes: Vec<u8>,
    pub new_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ProtectOp {
    pub address: usize,
    pub size: usize,
    pub old_protect: u32,
    pub new_protect: u32,
}

#[derive(Debug, Clone)]
pub enum UndoEntry {
    Write(WriteOp),
    Protect(ProtectOp),
}

pub struct MemoryTransaction {
    pub pid: u32,
    process: Process,
    log: Vec<UndoEntry>,
    committed: bool,
    rolled_back: bool,
}

impl MemoryTransaction {
    pub fn begin(pid: u32) -> Result<Self, String> {
        let process = Process::attach_with_mode(pid, ProcessAccessMode::NtApi, None)
            .or_else(|_| Process::attach(pid))?;
        Ok(Self {
            pid,
            process,
            log: Vec::new(),
            committed: false,
            rolled_back: false,
        })
    }

    pub fn begin_with_process(process: Process) -> Self {
        let pid = process.pid;
        Self {
            pid,
            process,
            log: Vec::new(),
            committed: false,
            rolled_back: false,
        }
    }

    pub fn log(&self) -> &[UndoEntry] {
        &self.log
    }

    pub fn len(&self) -> usize {
        self.log.len()
    }

    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }

    pub fn write(&mut self, address: usize, bytes: &[u8]) -> Result<(), String> {
        if self.committed || self.rolled_back {
            return Err("transaction already finalized".to_string());
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let mut old = vec![0u8; bytes.len()];
        self.process
            .read_raw(address, &mut old)
            .map_err(|e| format!("read old bytes at 0x{:X}: {}", address, e))?;

        self.process
            .write_raw(address, bytes)
            .map_err(|e| format!("write at 0x{:X}: {}", address, e))?;

        self.log.push(UndoEntry::Write(WriteOp {
            address,
            old_bytes: old,
            new_bytes: bytes.to_vec(),
        }));
        Ok(())
    }

    pub fn protect(&mut self, address: usize, size: usize, new_protect: u32) -> Result<u32, String> {
        if self.committed || self.rolled_back {
            return Err("transaction already finalized".to_string());
        }
        let old_protect = self
            .process
            .protect(address, size, new_protect)
            .map_err(|e| format!("protect 0x{:X}: {}", address, e))?;
        self.log.push(UndoEntry::Protect(ProtectOp {
            address,
            size,
            old_protect,
            new_protect,
        }));
        Ok(old_protect)
    }

    pub fn commit(mut self) {
        self.committed = true;
        self.log.clear();
    }

    pub fn rollback(mut self) -> Result<(), String> {
        self.rollback_in_place()
    }

    fn rollback_in_place(&mut self) -> Result<(), String> {
        if self.rolled_back {
            return Ok(());
        }
        let mut first_err: Option<String> = None;
        while let Some(entry) = self.log.pop() {
            match entry {
                UndoEntry::Write(op) => {
                    if let Err(e) = self.process.write_raw(op.address, &op.old_bytes) {
                        if first_err.is_none() {
                            first_err = Some(format!(
                                "rollback write at 0x{:X}: {}",
                                op.address, e
                            ));
                        }
                    }
                }
                UndoEntry::Protect(op) => {
                    if let Err(e) = self.process.protect(op.address, op.size, op.old_protect) {
                        if first_err.is_none() {
                            first_err = Some(format!(
                                "rollback protect at 0x{:X}: {}",
                                op.address, e
                            ));
                        }
                    }
                }
            }
        }
        self.rolled_back = true;
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl Drop for MemoryTransaction {
    fn drop(&mut self) {
        if !self.committed && !self.rolled_back && !self.log.is_empty() {
            let _ = self.rollback_in_place();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_local_buffer<F: FnOnce(usize)>(size: usize, f: F) {
        let buf = vec![0u8; size].into_boxed_slice();
        let ptr = Box::into_raw(buf) as *mut u8;
        f(ptr as usize);
        unsafe {
            drop(Box::from_raw(std::slice::from_raw_parts_mut(ptr, size)));
        }
    }

    #[test]
    fn begin_commit_write_persists() {
        with_local_buffer(16, |addr| {
            let pid = std::process::id();
            let mut tx = MemoryTransaction::begin(pid).expect("begin");
            tx.write(addr, &[0xAA, 0xBB, 0xCC, 0xDD]).expect("write");
            tx.commit();
            let slice = unsafe { std::slice::from_raw_parts(addr as *const u8, 4) };
            assert_eq!(slice, &[0xAA, 0xBB, 0xCC, 0xDD]);
        });
    }

    #[test]
    fn rollback_restores_original_bytes() {
        with_local_buffer(16, |addr| {
            let original = [0x11u8, 0x22, 0x33, 0x44];
            unsafe {
                std::ptr::copy_nonoverlapping(original.as_ptr(), addr as *mut u8, 4);
            }
            let pid = std::process::id();
            let mut tx = MemoryTransaction::begin(pid).expect("begin");
            tx.write(addr, &[0xDE, 0xAD, 0xBE, 0xEF]).expect("w1");
            tx.write(addr + 4, &[0xCA, 0xFE]).expect("w2");
            assert_eq!(tx.len(), 2);
            tx.rollback().expect("rollback");
            let slice = unsafe { std::slice::from_raw_parts(addr as *const u8, 4) };
            assert_eq!(slice, &original);
        });
    }

    #[test]
    fn drop_without_commit_rolls_back() {
        with_local_buffer(8, |addr| {
            let original = [0x01u8, 0x02, 0x03, 0x04];
            unsafe {
                std::ptr::copy_nonoverlapping(original.as_ptr(), addr as *mut u8, 4);
            }
            let pid = std::process::id();
            {
                let mut tx = MemoryTransaction::begin(pid).expect("begin");
                tx.write(addr, &[0xFF, 0xFF, 0xFF, 0xFF]).expect("w");
            }
            let slice = unsafe { std::slice::from_raw_parts(addr as *const u8, 4) };
            assert_eq!(slice, &original);
        });
    }

    #[test]
    fn rollback_order_is_reverse() {
        with_local_buffer(4, |addr| {
            unsafe { *(addr as *mut u32) = 0 };
            let pid = std::process::id();
            let mut tx = MemoryTransaction::begin(pid).expect("begin");
            tx.write(addr, &[1u8, 0, 0, 0]).expect("w1");
            tx.write(addr, &[2u8, 0, 0, 0]).expect("w2");
            tx.write(addr, &[3u8, 0, 0, 0]).expect("w3");
            tx.rollback().expect("rb");
            let v = unsafe { *(addr as *const u32) };
            assert_eq!(v, 0);
        });
    }

    #[test]
    fn write_after_finalize_fails() {
        with_local_buffer(4, |addr| {
            let pid = std::process::id();
            let mut tx = MemoryTransaction::begin(pid).expect("begin");
            tx.write(addr, &[1, 2, 3, 4]).expect("w");
            tx.rollback_in_place().unwrap();
            assert!(tx.write(addr, &[5, 6, 7, 8]).is_err());
        });
    }
}
