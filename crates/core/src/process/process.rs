use crate::error::{set_last_error, OnyxError, OnyxErrorCode, OnyxResult};
use crate::kernel::DbkDriver;
use crate::win32::*;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessAccessMode {
    NtApi,
    KernelDbk,
    Win32,
}

impl ProcessAccessMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NtApi => "NT Native API",
            Self::KernelDbk => "Kernel OnyxDriver",
            Self::Win32 => "Win32 API",
        }
    }

    pub fn badge(&self) -> &'static str {
        match self {
            Self::NtApi => "[NT API]",
            Self::KernelDbk => "[OnyxDriver]",
            Self::Win32 => "[WIN32]",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProcessEntry {
    pub pid: u32,
    pub name: String,
    pub parent_pid: u32,
    pub threads: u32,
}

#[derive(Debug, Clone)]
pub struct ModuleEntry {
    pub name: String,
    pub path: String,
    pub base: usize,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base: usize,
    pub size: usize,
    pub state: u32,
    pub protect: u32,
    pub mem_type: u32,
}

impl MemoryRegion {
    #[inline]
    pub fn is_committed(&self) -> bool {
        (self.state & MEM_COMMIT) != 0
    }

    #[inline]
    pub fn is_readable(&self) -> bool {
        if !self.is_committed() {
            return false;
        }
        if (self.protect & PAGE_GUARD) != 0 || (self.protect & PAGE_NOACCESS) != 0 {
            return false;
        }
        (self.protect
            & (PAGE_READONLY
                | PAGE_READWRITE
                | PAGE_WRITECOPY
                | PAGE_EXECUTE
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY))
            != 0
    }

    #[inline]
    pub fn is_writable(&self) -> bool {
        if !self.is_committed() {
            return false;
        }
        if (self.protect & PAGE_GUARD) != 0 || (self.protect & PAGE_NOACCESS) != 0 {
            return false;
        }
        (self.protect
            & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
            != 0
    }

    #[inline]
    pub fn is_executable(&self) -> bool {
        if !self.is_committed() {
            return false;
        }
        (self.protect
            & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
            != 0
    }
}

pub struct Process {
    pub pid: u32,
    pub handle: HANDLE,
    pub name: String,
    pub access_mode: ProcessAccessMode,
    pub dbk: Option<Arc<DbkDriver>>,
}

unsafe impl Send for Process {}
unsafe impl Sync for Process {}

impl Process {
    pub fn list_all_nt() -> OnyxResult<Vec<ProcessEntry>> {
        let mut buffer_size: u32 = 256 * 1024;
        let mut buffer: Vec<u8> = vec![0u8; buffer_size as usize];
        let mut return_len: u32 = 0;

        unsafe {
            loop {
                let status = NtQuerySystemInformation(
                    SystemProcessInformation,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer_size,
                    &mut return_len,
                );

                if status == STATUS_INFO_LENGTH_MISMATCH {
                    buffer_size = return_len.max(buffer_size * 2) + 64 * 1024;
                    buffer.resize(buffer_size as usize, 0);
                } else if status < 0 {
                    let err = OnyxError::process_snapshot_failed(status as u32); set_last_error(err.clone()); return Err(err);
                } else {
                    break;
                }
            }

            let mut entries = Vec::new();
            let mut offset = 0;

            loop {
                let p_info = buffer.as_ptr().add(offset) as *const SYSTEM_PROCESS_INFORMATION;
                let info = &*p_info;

                let pid = info.UniqueProcessId as usize as u32;
                let parent_pid = info.InheritedFromUniqueProcessId as usize as u32;
                let threads = info.NumberOfThreads;

                let name = if info.ImageName.Length > 0 && !info.ImageName.Buffer.is_null() {
                    let len = (info.ImageName.Length / 2) as usize;
                    let slice = std::slice::from_raw_parts(info.ImageName.Buffer, len);
                    String::from_utf16_lossy(slice)
                } else if pid == 0 {
                    "System Idle Process".to_string()
                } else if pid == 4 {
                    "System".to_string()
                } else {
                    format!("PID_{}", pid)
                };

                entries.push(ProcessEntry {
                    pid,
                    name,
                    parent_pid,
                    threads,
                });

                if info.NextEntryOffset == 0 {
                    break;
                }
                offset += info.NextEntryOffset as usize;
                if offset >= buffer.len() {
                    break;
                }
            }

            Ok(entries)
        }
    }

    pub fn list_all() -> OnyxResult<Vec<ProcessEntry>> {
        if let Ok(entries) = Self::list_all_nt()
            && !entries.is_empty()
        {
            return Ok(entries);
        }

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            let err = OnyxError::process_snapshot_failed(unsafe { GetLastError() }); set_last_error(err.clone()); return Err(err);
        }

        let mut entries = Vec::new();
        let mut pe: PROCESSENTRY32W = unsafe { zeroed() };
        pe.dwSize = size_of::<PROCESSENTRY32W>() as DWORD;

        unsafe {
            if Process32FirstW(snapshot, &mut pe) == TRUE {
                loop {
                    let name_len = pe
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(pe.szExeFile.len());
                    let name = String::from_utf16_lossy(&pe.szExeFile[..name_len]);

                    entries.push(ProcessEntry {
                        pid: pe.th32ProcessID,
                        name,
                        parent_pid: pe.th32ParentProcessID,
                        threads: pe.cntThreads,
                    });

                    if Process32NextW(snapshot, &mut pe) != TRUE {
                        break;
                    }
                }
            }
            CloseHandle(snapshot);
        }

        Ok(entries)
    }

    pub fn find_by_name(name: &str) -> OnyxResult<Option<ProcessEntry>> {
        let list = Self::list_all()?;
        let lower = name.to_lowercase();
        for p in list {
            if p.name.to_lowercase() == lower || p.name.to_lowercase() == format!("{}.exe", lower) {
                return Ok(Some(p));
            }
        }
        Ok(None)
    }

    pub fn attach_current() -> OnyxResult<Self> {
        let pid = unsafe { GetCurrentProcessId() };
        Self::attach(pid)
    }

    pub fn attach(pid: u32) -> OnyxResult<Self> {
        Self::attach_with_mode(pid, ProcessAccessMode::NtApi, None)
    }

    pub fn attach_with_mode(
        pid: u32,
        mode: ProcessAccessMode,
        dbk: Option<Arc<DbkDriver>>,
    ) -> OnyxResult<Self> {
        let _ = enable_debug_privilege();

        let mut handle: HANDLE = null_mut();

        if mode == ProcessAccessMode::KernelDbk
            && let Some(ref driver) = dbk
            && let Ok(h) = driver.open_process(pid)
        {
            handle = h;
        }

        if handle.is_null()
            && (mode == ProcessAccessMode::NtApi || mode == ProcessAccessMode::KernelDbk)
        {
            let mut client_id = CLIENT_ID {
                UniqueProcess: pid as usize as HANDLE,
                UniqueThread: null_mut(),
            };
            let mut obj_attr: OBJECT_ATTRIBUTES = unsafe { zeroed() };
            obj_attr.Length = size_of::<OBJECT_ATTRIBUTES>() as ULONG;

            let mut proc_handle: HANDLE = null_mut();
            let status = unsafe {
                NtOpenProcess(
                    &mut proc_handle,
                    PROCESS_ALL_ACCESS,
                    &mut obj_attr,
                    &mut client_id,
                )
            };

            if status == STATUS_SUCCESS && !proc_handle.is_null() {
                handle = proc_handle;
            } else {
                let fallback_access = PROCESS_VM_READ
                    | PROCESS_VM_WRITE
                    | PROCESS_VM_OPERATION
                    | PROCESS_QUERY_INFORMATION;
                let status_fb = unsafe {
                    NtOpenProcess(
                        &mut proc_handle,
                        fallback_access,
                        &mut obj_attr,
                        &mut client_id,
                    )
                };
                if status_fb == STATUS_SUCCESS && !proc_handle.is_null() {
                    handle = proc_handle;
                }
            }
        }

        if handle.is_null() {
            let h = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) };
            if h.is_null() {
                let fallback_access = PROCESS_VM_READ
                    | PROCESS_VM_WRITE
                    | PROCESS_VM_OPERATION
                    | PROCESS_QUERY_INFORMATION;
                let fallback_h = unsafe { OpenProcess(fallback_access, FALSE, pid) };
                if fallback_h.is_null() {
                    let err = unsafe { GetLastError() };
                    let err_obj = if err == 5 { OnyxError::process_access_denied(pid, err) } else { OnyxError::process_attach_failed(pid, &format!("OpenProcess error 0x{:X}", err)) }; set_last_error(err_obj.clone()); return Err(err_obj);
                }
                handle = fallback_h;
            } else {
                handle = h;
            }
        }

        let name = Self::list_all()
            .ok()
            .and_then(|list| list.into_iter().find(|p| p.pid == pid).map(|p| p.name))
            .unwrap_or_else(|| format!("PID:{}", pid));

        Ok(Process {
            pid,
            handle,
            name,
            access_mode: mode,
            dbk,
        })
    }

    pub fn set_access_mode(&mut self, mode: ProcessAccessMode) {
        self.access_mode = mode;
    }

    pub fn set_dbk(&mut self, dbk: Option<Arc<DbkDriver>>) {
        self.dbk = dbk;
    }

    pub fn get_cr3(&self) -> OnyxResult<u64> {
        if let Some(ref dbk) = self.dbk {
            dbk.get_cr3(self.pid).map_err(|s| OnyxError::new(OnyxErrorCode::DriverCr3WalkFailed, s.clone(), s))
        } else {
            { let err = OnyxError::driver_not_connected(); set_last_error(err.clone()); Err(err) }
        }
    }

    pub fn attach_by_name(name: &str) -> OnyxResult<Self> {
        let found =
            Self::find_by_name(name)?.ok_or_else(|| { let e = OnyxError::process_not_found(0).with_context(name); set_last_error(e.clone()); e })?;
        Self::attach(found.pid)
    }

    pub fn suspend(&self) -> OnyxResult<()> {
        let status = unsafe { NtSuspendProcess(self.handle) };
        if status == 0 {
            Ok(())
        } else {
            { let err = OnyxError::process_suspension_failed(self.pid, status as u32); set_last_error(err.clone()); Err(err) }
        }
    }

    pub fn resume(&self) -> OnyxResult<()> {
        let status = unsafe { NtResumeProcess(self.handle) };
        if status == 0 {
            Ok(())
        } else {
            { let err = OnyxError::process_resume_failed(self.pid, status as u32); set_last_error(err.clone()); Err(err) }
        }
    }

    pub fn modules(&self) -> OnyxResult<Vec<ModuleEntry>> {
        if self.access_mode == ProcessAccessMode::KernelDbk
            && let Some(ref dbk) = self.dbk
            && let Ok(vad_mods) = dbk.enum_vad_modules(self.pid)
            && !vad_mods.is_empty()
        {
            return Ok(vad_mods);
        }

        let snapshot =
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid) };
        if snapshot == INVALID_HANDLE_VALUE {
            if let Some(ref dbk) = self.dbk
                && let Ok(vad_mods) = dbk.enum_vad_modules(self.pid)
            {
                return Ok(vad_mods);
            }
            let err = OnyxError::process_snapshot_failed(unsafe { GetLastError() }).with_context(format!("PID {}", self.pid)); set_last_error(err.clone()); return Err(err);
        }

        let mut mods = Vec::new();
        let mut me: MODULEENTRY32W = unsafe { zeroed() };
        me.dwSize = size_of::<MODULEENTRY32W>() as DWORD;

        unsafe {
            if Module32FirstW(snapshot, &mut me) == TRUE {
                loop {
                    let name_len = me
                        .szModule
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(me.szModule.len());
                    let name = String::from_utf16_lossy(&me.szModule[..name_len]);

                    let path_len = me
                        .szExePath
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(me.szExePath.len());
                    let path = String::from_utf16_lossy(&me.szExePath[..path_len]);

                    mods.push(ModuleEntry {
                        name,
                        path,
                        base: me.modBaseAddr as usize,
                        size: me.modBaseSize as usize,
                    });

                    if Module32NextW(snapshot, &mut me) != TRUE {
                        break;
                    }
                }
            }
            CloseHandle(snapshot);
        }

        Ok(mods)
    }

    pub fn find_module(&self, mod_name: &str) -> Option<ModuleEntry> {
        let lower = mod_name.to_lowercase();
        self.modules().ok()?.into_iter().find(|m| {
            m.name.to_lowercase() == lower
                || m.name.to_lowercase() == format!("{}.dll", lower)
                || m.name.to_lowercase() == format!("{}.exe", lower)
        })
    }

    pub fn regions(&self, writable_only: bool) -> OnyxResult<Vec<MemoryRegion>> {
        let use_kernel_query = self.access_mode == ProcessAccessMode::KernelDbk
            && self.dbk.is_some();

        let mut regions = Vec::new();
        let mut addr: usize = 0x10000;
        let max_addr: usize = crate::memory::MAX_USER_ADDRESS;

        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };

        while addr < max_addr {
            let success = if use_kernel_query {
                let dbk = self.dbk.as_ref().unwrap();
                if let Ok(info) = dbk.query_virtual_memory(self.pid, addr as u64) {
                    mbi.BaseAddress = info.base_address as PVOID;
                    mbi.AllocationBase = info.allocation_base as PVOID;
                    mbi.AllocationProtect = info.allocation_protect;
                    mbi.RegionSize = info.region_size as SIZE_T;
                    mbi.State = info.state;
                    mbi.Protect = info.protect;
                    mbi.Type = info.mem_type;
                    true
                } else {
                    false
                }
            } else if self.access_mode == ProcessAccessMode::NtApi {
                let mut return_len: SIZE_T = 0;
                let status = unsafe {
                    NtQueryVirtualMemory(
                        self.handle,
                        addr as PVOID,
                        0,
                        &mut mbi as *mut _ as PVOID,
                        size_of::<MEMORY_BASIC_INFORMATION>(),
                        &mut return_len,
                    )
                };
                status == STATUS_SUCCESS && return_len > 0
            } else {
                let res = unsafe {
                    VirtualQueryEx(
                        self.handle,
                        addr as LPCVOID,
                        &mut mbi,
                        size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                };
                res > 0
            };

            if !success {
                addr += 0x1000;
                continue;
            }

            let reg = MemoryRegion {
                base: mbi.BaseAddress as usize,
                size: mbi.RegionSize,
                state: mbi.State,
                protect: mbi.Protect,
                mem_type: mbi.Type,
            };

            if reg.is_readable() && (!writable_only || reg.is_writable()) {
                regions.push(reg);
            }

            let next_addr = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
            if next_addr <= addr {
                break;
            }
            addr = next_addr;
        }

        Ok(regions)
    }

    pub fn read_raw(&self, address: usize, buf: &mut [u8]) -> OnyxResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if self.access_mode == ProcessAccessMode::KernelDbk
            && let Some(ref dbk) = self.dbk
        {
            if let Ok(bytes) = dbk.bulk_dump_cr3(self.pid, address as u64, buf.len())
                && !bytes.is_empty()
            {
                let to_copy = bytes.len().min(buf.len());
                buf[..to_copy].copy_from_slice(&bytes[..to_copy]);
                return Ok(to_copy);
            }

            if let Ok(bytes) = dbk.read_memory(self.pid, address, buf.len()) {
                let to_copy = bytes.len().min(buf.len());
                buf[..to_copy].copy_from_slice(&bytes[..to_copy]);
                return Ok(to_copy);
            }
        }

        if self.access_mode == ProcessAccessMode::NtApi
            || self.access_mode == ProcessAccessMode::KernelDbk
        {
            let mut bytes_read: SIZE_T = 0;
            let status = unsafe {
                NtReadVirtualMemory(
                    self.handle,
                    address as PVOID,
                    buf.as_mut_ptr() as PVOID,
                    buf.len(),
                    &mut bytes_read,
                )
            };

            if status == STATUS_SUCCESS && bytes_read > 0 {
                return Ok(bytes_read);
            }
        }

        let mut bytes_read: SIZE_T = 0;
        let ok = unsafe {
            ReadProcessMemory(
                self.handle,
                address as LPCVOID,
                buf.as_mut_ptr() as LPVOID,
                buf.len(),
                &mut bytes_read,
            )
        };

        if ok == TRUE && bytes_read > 0 {
            Ok(bytes_read)
        } else {
            { let err = OnyxError::memory_read_failed(address, buf.len(), unsafe { GetLastError() }); set_last_error(err.clone()); Err(err) }
        }
    }

    pub fn read_bytes(&self, address: usize, len: usize) -> OnyxResult<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let read = self.read_raw(address, &mut buf)?;
        buf.truncate(read);
        Ok(buf)
    }

    pub fn read<T: Copy>(&self, address: usize) -> OnyxResult<T> {
        let mut val: T = unsafe { zeroed() };
        let buf = unsafe {
            std::slice::from_raw_parts_mut(&mut val as *mut T as *mut u8, size_of::<T>())
        };
        self.read_raw(address, buf)?;
        Ok(val)
    }

    pub fn read_string(
        &self,
        address: usize,
        max_len: usize,
        utf16: bool,
    ) -> OnyxResult<String> {
        if utf16 {
            let mut words = vec![0u16; max_len];
            let buf = unsafe {
                std::slice::from_raw_parts_mut(words.as_mut_ptr() as *mut u8, max_len * 2)
            };
            self.read_raw(address, buf)?;
            let len = words.iter().position(|&c| c == 0).unwrap_or(words.len());
            Ok(String::from_utf16_lossy(&words[..len]))
        } else {
            let mut bytes = vec![0u8; max_len];
            self.read_raw(address, &mut bytes)?;
            let len = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
            Ok(String::from_utf8_lossy(&bytes[..len]).to_string())
        }
    }

    pub fn write_raw(&self, address: usize, data: &[u8]) -> OnyxResult<usize> {
        if data.is_empty() {
            return Ok(0);
        }

        if self.access_mode == ProcessAccessMode::KernelDbk
            && let Some(ref dbk) = self.dbk
            && let Ok(written) = dbk.write_memory(self.pid, address, data)
        {
            return Ok(written);
        }

        if self.access_mode == ProcessAccessMode::NtApi
            || self.access_mode == ProcessAccessMode::KernelDbk
        {
            let mut base_addr = address as PVOID;
            let mut region_size: SIZE_T = data.len();
            let mut old_protect: ULONG = 0;

            unsafe {
                NtProtectVirtualMemory(
                    self.handle,
                    &mut base_addr,
                    &mut region_size,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                );
            }

            let mut bytes_written: SIZE_T = 0;
            let status = unsafe {
                NtWriteVirtualMemory(
                    self.handle,
                    address as PVOID,
                    data.as_ptr() as LPCVOID,
                    data.len(),
                    &mut bytes_written,
                )
            };

            if old_protect != 0 {
                let mut restore_addr = address as PVOID;
                let mut restore_size: SIZE_T = data.len();
                let mut dummy: ULONG = 0;
                unsafe {
                    NtProtectVirtualMemory(
                        self.handle,
                        &mut restore_addr,
                        &mut restore_size,
                        old_protect,
                        &mut dummy,
                    );
                }
            }

            if status == STATUS_SUCCESS && bytes_written > 0 {
                return Ok(bytes_written);
            }
        }

        let mut bytes_written: SIZE_T = 0;
        let mut old_protect: DWORD = 0;

        unsafe {
            VirtualProtectEx(
                self.handle,
                address as LPVOID,
                data.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );
        }

        let ok = unsafe {
            WriteProcessMemory(
                self.handle,
                address as LPVOID,
                data.as_ptr() as LPCVOID,
                data.len(),
                &mut bytes_written,
            )
        };

        if old_protect != 0 {
            unsafe {
                let mut dummy = 0;
                VirtualProtectEx(
                    self.handle,
                    address as LPVOID,
                    data.len(),
                    old_protect,
                    &mut dummy,
                );
            }
        }

        if ok == TRUE && bytes_written > 0 {
            Ok(bytes_written)
        } else {
            { let err = OnyxError::memory_write_failed(address, data.len(), unsafe { GetLastError() }); set_last_error(err.clone()); Err(err) }
        }
    }

    pub fn write<T: Copy>(&self, address: usize, val: &T) -> OnyxResult<()> {
        let slice =
            unsafe { std::slice::from_raw_parts(val as *const T as *const u8, size_of::<T>()) };
        self.write_raw(address, slice)?;
        Ok(())
    }

    pub fn alloc(&self, size: usize, protect: u32) -> OnyxResult<usize> {
        if self.access_mode == ProcessAccessMode::NtApi
            || self.access_mode == ProcessAccessMode::KernelDbk
        {
            let mut base_addr: PVOID = null_mut();
            let mut region_size: SIZE_T = size;
            let status = unsafe {
                NtAllocateVirtualMemory(
                    self.handle,
                    &mut base_addr,
                    0,
                    &mut region_size,
                    MEM_COMMIT | MEM_RESERVE,
                    protect,
                )
            };
            if status == STATUS_SUCCESS && !base_addr.is_null() {
                return Ok(base_addr as usize);
            }
        }

        let addr = unsafe {
            VirtualAllocEx(
                self.handle,
                null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                protect,
            )
        };
        if addr.is_null() {
            { let err = OnyxError::memory_alloc_failed(size, protect, unsafe { GetLastError() }); set_last_error(err.clone()); Err(err) }
        } else {
            Ok(addr as usize)
        }
    }

    pub fn alloc_near(
        &self,
        preferred_addr: usize,
        size: usize,
        protect: u32,
    ) -> OnyxResult<usize> {
        if preferred_addr == 0 {
            return self.alloc(size, protect);
        }

        let min_addr = preferred_addr.saturating_sub(0x7000_0000).max(0x10000);
        let max_addr = preferred_addr.saturating_add(0x7000_0000);

        let mut delta: usize = 0x10000;
        while delta < 0x7000_0000 {
            if preferred_addr + delta < max_addr {
                let target = preferred_addr + delta;
                let addr = unsafe {
                    VirtualAllocEx(
                        self.handle,
                        target as LPVOID,
                        size,
                        MEM_COMMIT | MEM_RESERVE,
                        protect,
                    )
                };
                if !addr.is_null() {
                    return Ok(addr as usize);
                }
            }
            if preferred_addr > min_addr + delta {
                let target = preferred_addr - delta;
                let addr = unsafe {
                    VirtualAllocEx(
                        self.handle,
                        target as LPVOID,
                        size,
                        MEM_COMMIT | MEM_RESERVE,
                        protect,
                    )
                };
                if !addr.is_null() {
                    return Ok(addr as usize);
                }
            }
            delta += 0x10000;
        }

        self.alloc(size, protect)
    }

    pub fn free(&self, address: usize) -> OnyxResult<()> {
        if self.access_mode == ProcessAccessMode::NtApi
            || self.access_mode == ProcessAccessMode::KernelDbk
        {
            let mut base_addr = address as PVOID;
            let mut region_size: SIZE_T = 0;
            let status = unsafe {
                NtFreeVirtualMemory(self.handle, &mut base_addr, &mut region_size, MEM_RELEASE)
            };
            if status == STATUS_SUCCESS {
                return Ok(());
            }
        }

        let ok = unsafe { VirtualFreeEx(self.handle, address as LPVOID, 0, MEM_RELEASE) };
        if ok == TRUE {
            Ok(())
        } else {
            { let err = OnyxError::memory_free_failed(address, unsafe { GetLastError() }); set_last_error(err.clone()); Err(err) }
        }
    }

    pub fn protect(&self, address: usize, size: usize, new_protect: u32) -> OnyxResult<u32> {
        if self.access_mode == ProcessAccessMode::NtApi
            || self.access_mode == ProcessAccessMode::KernelDbk
        {
            let mut base_addr = address as PVOID;
            let mut region_size: SIZE_T = size;
            let mut old_protect: ULONG = 0;
            let status = unsafe {
                NtProtectVirtualMemory(
                    self.handle,
                    &mut base_addr,
                    &mut region_size,
                    new_protect,
                    &mut old_protect,
                )
            };
            if status == STATUS_SUCCESS {
                return Ok(old_protect);
            }
        }

        let mut old_protect: DWORD = 0;
        let ok = unsafe {
            VirtualProtectEx(
                self.handle,
                address as LPVOID,
                size,
                new_protect,
                &mut old_protect,
            )
        };
        if ok == TRUE {
            Ok(old_protect)
        } else {
            { let err = OnyxError::memory_protect_failed(address, new_protect, unsafe { GetLastError() }); set_last_error(err.clone()); Err(err) }
        }
    }

    pub fn threads(&self) -> OnyxResult<Vec<u32>> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            let err = OnyxError::new(OnyxErrorCode::ProcessThreadSnapshotFailed, "Failed to create thread snapshot", "Falha ao capturar threads do processo").with_win32(unsafe { GetLastError() }); set_last_error(err.clone()); return Err(err);
        }

        let mut thread_ids = Vec::new();
        let mut te: THREADENTRY32 = unsafe { zeroed() };
        te.dwSize = size_of::<THREADENTRY32>() as DWORD;

        unsafe {
            if Thread32First(snapshot, &mut te) == TRUE {
                loop {
                    if te.th32OwnerProcessID == self.pid {
                        thread_ids.push(te.th32ThreadID);
                    }
                    if Thread32Next(snapshot, &mut te) != TRUE {
                        break;
                    }
                }
            }
            CloseHandle(snapshot);
        }

        Ok(thread_ids)
    }

    pub fn resolve_dll_path(path_str: &str) -> OnyxResult<PathBuf> {
        let p = Path::new(path_str);
        if p.is_absolute() && p.exists() {
            return std::fs::canonicalize(p).map_err(|e| OnyxError::injection_dll_not_found(path_str).with_context(e.to_string()));
        }

        if let Ok(exe_path) = std::env::current_exe()
            && let Some(exe_dir) = exe_path.parent()
        {
            let candidate = exe_dir.join(p);
            if candidate.exists() {
                return std::fs::canonicalize(&candidate).map_err(|e| OnyxError::injection_dll_not_found(path_str).with_context(e.to_string()));
            }
            if let Some(filename) = p.file_name() {
                let candidate2 = exe_dir.join(filename);
                if candidate2.exists() {
                    return std::fs::canonicalize(&candidate2).map_err(|e| OnyxError::injection_dll_not_found(path_str).with_context(e.to_string()));
                }
            }
        }

        if p.exists() {
            return std::fs::canonicalize(p).map_err(|e| OnyxError::injection_dll_not_found(path_str).with_context(e.to_string()));
        }

        if let Some(filename) = p.file_name() {
            let candidates = [
                PathBuf::from(filename),
                PathBuf::from("modules/injections").join(filename),
                PathBuf::from("bin/modules/injections").join(filename),
                PathBuf::from("UI/bin/modules/injections").join(filename),
                PathBuf::from("../UI/bin/modules/injections").join(filename),
                PathBuf::from("../../UI/bin/modules/injections").join(filename),
                PathBuf::from("target/release").join(filename),
                PathBuf::from("../target/release").join(filename),
                PathBuf::from("../../target/release").join(filename),
                PathBuf::from("target/debug").join(filename),
                PathBuf::from("../target/debug").join(filename),
                PathBuf::from("../../target/debug").join(filename),
                PathBuf::from("CE_rust_gui/target/release").join(filename),
                PathBuf::from("CE_rust/target/release").join(filename),
            ];
            for c in &candidates {
                if c.exists() {
                    return std::fs::canonicalize(c).map_err(|e| OnyxError::injection_dll_not_found(path_str).with_context(e.to_string()));
                }
            }
        }

        { let e = OnyxError::injection_dll_not_found(path_str); set_last_error(e.clone()); Err(e) }
    }

    pub fn inject_dll(&self, dll_path: &str) -> OnyxResult<usize> {
        let full_path = Self::resolve_dll_path(dll_path)?;
        let full_path_str = full_path.to_str().ok_or("Invalid UTF-8 DLL path")?;
        let clean_path = full_path_str.strip_prefix(r"\\?\").unwrap_or(full_path_str);

        let wide_path: Vec<u16> = clean_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let path_bytes = wide_path.len() * 2;

        let remote_buf = self.alloc(path_bytes, PAGE_READWRITE)?;
        let slice: &[u8] =
            unsafe { std::slice::from_raw_parts(wide_path.as_ptr() as *const u8, path_bytes) };

        if let Err(e) = self.write_raw(remote_buf, slice) {
            let _ = self.free(remote_buf);
            let err = OnyxError::new(OnyxErrorCode::InjectionWritePathFailed, format!("Failed to write DLL path to remote process: {}", e), format!("Falha ao gravar caminho da DLL na memória do processo: {}", e)); set_last_error(err.clone()); return Err(err);
        }

        let k32_name: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
        let h_k32 = unsafe { crate::win32::GetModuleHandleW(k32_name.as_ptr()) };
        if h_k32.is_null() {
            let _ = self.free(remote_buf);
            let err = OnyxError::new(OnyxErrorCode::InjectionLoadLibraryFailed, "Failed to get kernel32.dll handle", "Falha ao obter handle de kernel32.dll"); set_last_error(err.clone()); return Err(err);
        }

        let loadlib_proc =
            unsafe { crate::win32::GetProcAddress(h_k32, b"LoadLibraryW\0".as_ptr()) };
        if loadlib_proc.is_null() {
            let _ = self.free(remote_buf);
            let err = OnyxError::new(OnyxErrorCode::InjectionLoadLibraryFailed, "Failed to resolve LoadLibraryW address", "Falha ao resolver endereço de LoadLibraryW"); set_last_error(err.clone()); return Err(err);
        }

        let thread_start = unsafe {
            std::mem::transmute::<LPVOID, unsafe extern "system" fn(LPVOID) -> DWORD>(loadlib_proc)
        };

        let h_thread = unsafe {
            CreateRemoteThread(
                self.handle,
                null_mut(),
                0,
                thread_start,
                remote_buf as LPVOID,
                0,
                null_mut(),
            )
        };

        if h_thread.is_null() || h_thread == INVALID_HANDLE_VALUE {
            let _ = self.free(remote_buf);
            let err = OnyxError::injection_thread_failed(unsafe { GetLastError() }); set_last_error(err.clone()); return Err(err);
        }

        unsafe {
            WaitForSingleObject(h_thread, 10000);
            let mut exit_code: DWORD = 0;
            GetExitCodeThread(h_thread, &mut exit_code);
            CloseHandle(h_thread);
            let _ = self.free(remote_buf);

            if exit_code == 0 {
                { let err = OnyxError::new(OnyxErrorCode::InjectionLoadLibraryFailed, "LoadLibraryW returned NULL in target process", "LoadLibraryW retornou NULL no processo alvo. Verifique se a DLL possui dependências não resolvidas"); set_last_error(err.clone()); Err(err) }
            } else {
                Ok(exit_code as usize)
            }
        }
    }

    pub fn create_thread(&self, start_address: usize) -> OnyxResult<usize> {
        let thread_start = unsafe {
            std::mem::transmute::<LPVOID, unsafe extern "system" fn(LPVOID) -> DWORD>(
                start_address as LPVOID,
            )
        };
        let mut thread_id: DWORD = 0;
        let h_thread = unsafe {
            CreateRemoteThread(
                self.handle,
                null_mut(),
                0,
                thread_start,
                null_mut(),
                0,
                &mut thread_id,
            )
        };
        if h_thread.is_null() || h_thread == INVALID_HANDLE_VALUE {
            { let err = OnyxError::injection_thread_failed(unsafe { GetLastError() }); set_last_error(err.clone()); Err(err) }
        } else {
            unsafe { CloseHandle(h_thread) };
            Ok(thread_id as usize)
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

pub fn enable_debug_privilege() -> OnyxResult<()> {
    let mut token: HANDLE = null_mut();
    unsafe {
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) != TRUE
        {
            let err = OnyxError::new(OnyxErrorCode::DriverSeDebugGrantFailed, "OpenProcessToken failed", "Falha ao abrir token do processo atual").with_win32(GetLastError()); set_last_error(err.clone()); return Err(err);
        }

        let priv_name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
        let mut luid: LUID = zeroed();

        if LookupPrivilegeValueW(null(), priv_name.as_ptr(), &mut luid) != TRUE {
            CloseHandle(token);
            let err = OnyxError::new(OnyxErrorCode::DriverSeDebugGrantFailed, "LookupPrivilegeValueW failed", "Falha ao consultar SeDebugPrivilege").with_win32(GetLastError()); set_last_error(err.clone()); return Err(err);
        }

        let mut tp: TOKEN_PRIVILEGES = zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        let ok = AdjustTokenPrivileges(
            token,
            FALSE,
            &tp,
            size_of::<TOKEN_PRIVILEGES>() as DWORD,
            null_mut(),
            null_mut(),
        );
        CloseHandle(token);

        if ok == TRUE {
            Ok(())
        } else {
            { let err = OnyxError::new(OnyxErrorCode::DriverSeDebugGrantFailed, "AdjustTokenPrivileges failed", "Falha ao ajustar privilégios do token").with_win32(GetLastError()); set_last_error(err.clone()); Err(err) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_dll_path() {
        let res = Process::resolve_dll_path("d3dhook_dll.dll");
        if let Ok(path) = res {
            assert!(path.exists(), "Resolved path does not exist: {:?}", path);
        } else {
            let temp_dir = std::env::temp_dir();
            let test_dll = temp_dir.join("test_mock_hook.dll");
            let _ = std::fs::write(&test_dll, b"MZ");
            let resolved = Process::resolve_dll_path(test_dll.to_str().unwrap());
            assert!(resolved.is_ok(), "Expected to resolve path: {:?}", resolved);
            let _ = std::fs::remove_file(test_dll);
        }
    }

    #[test]
    fn test_process_access_mode_badges() {
        assert_eq!(ProcessAccessMode::NtApi.badge(), "[NT API]");
        assert_eq!(ProcessAccessMode::KernelDbk.badge(), "[OnyxDriver]");
        assert_eq!(ProcessAccessMode::Win32.badge(), "[WIN32]");
    }

    #[test]
    fn test_nt_api_attach_and_read_current_process() {
        let current_pid = std::process::id();
        let proc = Process::attach_with_mode(current_pid, ProcessAccessMode::NtApi, None);
        assert!(
            proc.is_ok(),
            "Failed to attach via NtOpenProcess: {:?}",
            proc.err()
        );

        let p = proc.unwrap();
        assert_eq!(p.access_mode, ProcessAccessMode::NtApi);

        let magic: u64 = 0xDEADBEEFCAFE1337;
        let addr = &magic as *const u64 as usize;
        let val: OnyxResult<u64> = p.read(addr);
        assert!(
            val.is_ok(),
            "Failed to read via NtReadVirtualMemory: {:?}",
            val.err()
        );
        assert_eq!(val.unwrap(), 0xDEADBEEFCAFE1337);
    }
}
