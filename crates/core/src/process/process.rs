// language: Rust, file: process.rs, target: Windows 11, MSVC
// Target process management, memory R/W, module enumeration, and privilege escalation

use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use crate::win32::*;
use crate::kernel::DbkDriver;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessAccessMode {
    NtApi,      // Native NT syscalls via ntdll (NtOpenProcess, NtReadVirtualMemory, NtWriteVirtualMemory)
    KernelDbk,  // Official Cheat Engine DBK64/DBK32 driver
    Win32,      // Standard Win32 fallback
}

impl ProcessAccessMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NtApi => "NT Native API",
            Self::KernelDbk => "Kernel DBK64",
            Self::Win32 => "Win32 API",
        }
    }

    pub fn badge(&self) -> &'static str {
        match self {
            Self::NtApi => "[NT API]",
            Self::KernelDbk => "[DBK64]",
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
        (self.protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0
    }

    #[inline]
    pub fn is_writable(&self) -> bool {
        if !self.is_committed() {
            return false;
        }
        if (self.protect & PAGE_GUARD) != 0 || (self.protect & PAGE_NOACCESS) != 0 {
            return false;
        }
        (self.protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0
    }

    #[inline]
    pub fn is_executable(&self) -> bool {
        if !self.is_committed() {
            return false;
        }
        (self.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0
    }
}

pub struct Process {
    pub pid: u32,
    pub handle: HANDLE,
    pub name: String,
    pub access_mode: ProcessAccessMode,
    pub dbk: Option<Arc<DbkDriver>>,
}

impl Process {
    pub fn list_all() -> Result<Vec<ProcessEntry>, String> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err("Failed to create process snapshot".to_string());
        }

        let mut entries = Vec::new();
        let mut pe: PROCESSENTRY32W = unsafe { zeroed() };
        pe.dwSize = size_of::<PROCESSENTRY32W>() as DWORD;

        unsafe {
            if Process32FirstW(snapshot, &mut pe) == TRUE {
                loop {
                    let name_len = pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(pe.szExeFile.len());
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

    pub fn find_by_name(name: &str) -> Result<Option<ProcessEntry>, String> {
        let list = Self::list_all()?;
        let lower = name.to_lowercase();
        for p in list {
            if p.name.to_lowercase() == lower || p.name.to_lowercase() == format!("{}.exe", lower) {
                return Ok(Some(p));
            }
        }
        Ok(None)
    }

    /// Attaches to target process using Native NT API (NtOpenProcess) by default
    pub fn attach(pid: u32) -> Result<Self, String> {
        Self::attach_with_mode(pid, ProcessAccessMode::NtApi, None)
    }

    /// Attaches to target process with specified access mode (NtApi, KernelDbk, Win32)
    pub fn attach_with_mode(
        pid: u32,
        mode: ProcessAccessMode,
        dbk: Option<Arc<DbkDriver>>,
    ) -> Result<Self, String> {
        let _ = enable_debug_privilege();

        let mut handle: HANDLE = null_mut();

        // 1. If KernelDbk mode and driver available, attempt kernel open
        if mode == ProcessAccessMode::KernelDbk {
            if let Some(ref driver) = dbk {
                if let Ok(h) = driver.open_process(pid) {
                    handle = h;
                }
            }
        }

        // 2. Native NT API: NtOpenProcess (bypasses usermode hooks on OpenProcess)
        if handle.is_null() && (mode == ProcessAccessMode::NtApi || mode == ProcessAccessMode::KernelDbk) {
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
                // Secondary attempt with VM_READ | VM_WRITE | VM_OPERATION | QUERY_INFORMATION
                let fallback_access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
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

        // 3. Fallback to standard Win32 OpenProcess
        if handle.is_null() {
            let h = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) };
            if h.is_null() {
                let fallback_access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
                let fallback_h = unsafe { OpenProcess(fallback_access, FALSE, pid) };
                if fallback_h.is_null() {
                    let err = unsafe { GetLastError() };
                    return Err(format!("Failed to open process PID {} via NtOpenProcess/OpenProcess (Error: 0x{:X})", pid, err));
                }
                handle = fallback_h;
            } else {
                handle = h;
            }
        }

        // Resolve process name
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

    pub fn get_cr3(&self) -> Result<u64, String> {
        if let Some(ref dbk) = self.dbk {
            dbk.get_cr3(self.pid)
        } else {
            Err("DBK driver not attached".to_string())
        }
    }

    pub fn attach_by_name(name: &str) -> Result<Self, String> {
        let found = Self::find_by_name(name)?
            .ok_or_else(|| format!("Process '{}' not found", name))?;
        Self::attach(found.pid)
    }

    pub fn modules(&self) -> Result<Vec<ModuleEntry>, String> {
        let snapshot = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid)
        };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!("Failed to create module snapshot for PID {}", self.pid));
        }

        let mut mods = Vec::new();
        let mut me: MODULEENTRY32W = unsafe { zeroed() };
        me.dwSize = size_of::<MODULEENTRY32W>() as DWORD;

        unsafe {
            if Module32FirstW(snapshot, &mut me) == TRUE {
                loop {
                    let name_len = me.szModule.iter().position(|&c| c == 0).unwrap_or(me.szModule.len());
                    let name = String::from_utf16_lossy(&me.szModule[..name_len]);

                    let path_len = me.szExePath.iter().position(|&c| c == 0).unwrap_or(me.szExePath.len());
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
            m.name.to_lowercase() == lower || m.name.to_lowercase() == format!("{}.dll", lower) || m.name.to_lowercase() == format!("{}.exe", lower)
        })
    }

    pub fn regions(&self, readable_only: bool) -> Result<Vec<MemoryRegion>, String> {
        let mut regions = Vec::new();
        let mut addr: usize = 0x10000; // Skip first 64KB null-page boundary
        let max_addr: usize = if size_of::<usize>() == 8 { 0x7FFF_FFFF_FFFF } else { 0x7FFF_FFFF };

        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };

        while addr < max_addr {
            let mut return_len: SIZE_T = 0;
            let success = if self.access_mode == ProcessAccessMode::NtApi || self.access_mode == ProcessAccessMode::KernelDbk {
                let status = unsafe {
                    NtQueryVirtualMemory(
                        self.handle,
                        addr as PVOID,
                        0, // MemoryBasicInformation
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
                // Advance 4KB on error to avoid stalling
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

            if !readable_only || reg.is_readable() {
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

    /// Reads raw memory bytes via DBK kernel, NtReadVirtualMemory, or fallback RPM
    pub fn read_raw(&self, address: usize, buf: &mut [u8]) -> Result<usize, String> {
        if buf.is_empty() {
            return Ok(0);
        }

        // 1. Kernel DBK Mode
        if self.access_mode == ProcessAccessMode::KernelDbk {
            if let Some(ref dbk) = self.dbk {
                if let Ok(bytes) = dbk.read_memory(self.pid, address, buf.len()) {
                    let to_copy = bytes.len().min(buf.len());
                    buf[..to_copy].copy_from_slice(&bytes[..to_copy]);
                    return Ok(to_copy);
                }
            }
        }

        // 2. Native NT API: NtReadVirtualMemory (bypasses usermode hooks on ReadProcessMemory)
        if self.access_mode == ProcessAccessMode::NtApi || self.access_mode == ProcessAccessMode::KernelDbk {
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

        // 3. Fallback: Win32 ReadProcessMemory
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
            Err(format!("Memory read failed at 0x{:X}", address))
        }
    }

    pub fn read_bytes(&self, address: usize, len: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; len];
        let read = self.read_raw(address, &mut buf)?;
        buf.truncate(read);
        Ok(buf)
    }

    pub fn read<T: Copy>(&self, address: usize) -> Result<T, String> {
        let mut val: T = unsafe { zeroed() };
        let buf = unsafe {
            std::slice::from_raw_parts_mut(&mut val as *mut T as *mut u8, size_of::<T>())
        };
        self.read_raw(address, buf)?;
        Ok(val)
    }

    pub fn read_string(&self, address: usize, max_len: usize, utf16: bool) -> Result<String, String> {
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

    /// Writes raw memory bytes via DBK kernel, NtWriteVirtualMemory, or fallback WPM
    pub fn write_raw(&self, address: usize, data: &[u8]) -> Result<usize, String> {
        if data.is_empty() {
            return Ok(0);
        }

        // 1. Kernel DBK Mode
        if self.access_mode == ProcessAccessMode::KernelDbk {
            if let Some(ref dbk) = self.dbk {
                if let Ok(written) = dbk.write_memory(self.pid, address, data) {
                    return Ok(written);
                }
            }
        }

        // 2. Native NT API: NtProtectVirtualMemory + NtWriteVirtualMemory
        if self.access_mode == ProcessAccessMode::NtApi || self.access_mode == ProcessAccessMode::KernelDbk {
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

        // 3. Fallback: Win32 VirtualProtectEx + WriteProcessMemory
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
            Err(format!("Memory write failed at 0x{:X}", address))
        }
    }

    pub fn write<T: Copy>(&self, address: usize, val: &T) -> Result<(), String> {
        let slice = unsafe {
            std::slice::from_raw_parts(val as *const T as *const u8, size_of::<T>())
        };
        self.write_raw(address, slice)?;
        Ok(())
    }

    /// Allocates memory via NtAllocateVirtualMemory or VirtualAllocEx
    pub fn alloc(&self, size: usize, protect: u32) -> Result<usize, String> {
        if self.access_mode == ProcessAccessMode::NtApi || self.access_mode == ProcessAccessMode::KernelDbk {
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

        // Fallback
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
            Err("Memory allocation failed (NtAllocateVirtualMemory / VirtualAllocEx)".to_string())
        } else {
            Ok(addr as usize)
        }
    }

    /// Frees memory via NtFreeVirtualMemory or VirtualFreeEx
    pub fn free(&self, address: usize) -> Result<(), String> {
        if self.access_mode == ProcessAccessMode::NtApi || self.access_mode == ProcessAccessMode::KernelDbk {
            let mut base_addr = address as PVOID;
            let mut region_size: SIZE_T = 0;
            let status = unsafe {
                NtFreeVirtualMemory(
                    self.handle,
                    &mut base_addr,
                    &mut region_size,
                    MEM_RELEASE,
                )
            };
            if status == STATUS_SUCCESS {
                return Ok(());
            }
        }

        // Fallback
        let ok = unsafe { VirtualFreeEx(self.handle, address as LPVOID, 0, MEM_RELEASE) };
        if ok == TRUE {
            Ok(())
        } else {
            Err(format!("Memory free failed at 0x{:X}", address))
        }
    }

    /// Modifies memory protection via NtProtectVirtualMemory or VirtualProtectEx
    pub fn protect(&self, address: usize, size: usize, new_protect: u32) -> Result<u32, String> {
        if self.access_mode == ProcessAccessMode::NtApi || self.access_mode == ProcessAccessMode::KernelDbk {
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

        // Fallback
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
            Err(format!("VirtualProtect failed at 0x{:X}", address))
        }
    }

    pub fn threads(&self) -> Result<Vec<u32>, String> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err("Failed to create thread snapshot".to_string());
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

    pub fn resolve_dll_path(path_str: &str) -> Result<PathBuf, String> {
        let p = Path::new(path_str);
        if p.is_absolute() && p.exists() {
            return std::fs::canonicalize(p).map_err(|e| e.to_string());
        }

        // 1. Next to current executable (ce_rust_gui.exe / CE_rust.exe)
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let candidate = exe_dir.join(p);
                if candidate.exists() {
                    return std::fs::canonicalize(&candidate).map_err(|e| e.to_string());
                }
                if let Some(filename) = p.file_name() {
                    let candidate2 = exe_dir.join(filename);
                    if candidate2.exists() {
                        return std::fs::canonicalize(&candidate2).map_err(|e| e.to_string());
                    }
                }
            }
        }

        // 2. Relative to working directory
        if p.exists() {
            return std::fs::canonicalize(p).map_err(|e| e.to_string());
        }

        // 3. Known project paths
        if let Some(filename) = p.file_name() {
            let candidates = [
                PathBuf::from(filename),
                PathBuf::from("modules/injections").join(filename),
                PathBuf::from("bin/modules/injections").join(filename),
                PathBuf::from("cheat-engine/Cheat Engine/bin/modules/injections").join(filename),
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
                    return std::fs::canonicalize(c).map_err(|e| e.to_string());
                }
            }
        }

        Err(format!("Could not locate DLL '{}' in executable directory, CWD, or build folders", path_str))
    }

    pub fn inject_dll(&self, dll_path: &str) -> Result<usize, String> {
        let full_path = Self::resolve_dll_path(dll_path)?;
        let full_path_str = full_path.to_str().ok_or("Invalid UTF-8 DLL path")?;
        let clean_path = if full_path_str.starts_with(r"\\?\") {
            &full_path_str[4..]
        } else {
            full_path_str
        };

        let wide_path: Vec<u16> = clean_path.encode_utf16().chain(std::iter::once(0)).collect();
        let path_bytes = wide_path.len() * 2;

        let remote_buf = self.alloc(path_bytes, PAGE_READWRITE)?;
        let slice: &[u8] = unsafe {
            std::slice::from_raw_parts(wide_path.as_ptr() as *const u8, path_bytes)
        };

        if let Err(e) = self.write_raw(remote_buf, slice) {
            let _ = self.free(remote_buf);
            return Err(format!("Failed to write DLL path to remote process: {}", e));
        }

        let k32_name: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
        let h_k32 = unsafe { crate::win32::GetModuleHandleW(k32_name.as_ptr()) };
        if h_k32.is_null() {
            let _ = self.free(remote_buf);
            return Err("Failed to get kernel32.dll handle".to_string());
        }

        let loadlib_proc = unsafe {
            crate::win32::GetProcAddress(h_k32, b"LoadLibraryW\0".as_ptr())
        };
        if loadlib_proc.is_null() {
            let _ = self.free(remote_buf);
            return Err("Failed to resolve LoadLibraryW".to_string());
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
            return Err(format!("CreateRemoteThread failed (Error: {})", unsafe { GetLastError() }));
        }

        unsafe {
            WaitForSingleObject(h_thread, 10000);
            let mut exit_code: DWORD = 0;
            GetExitCodeThread(h_thread, &mut exit_code);
            CloseHandle(h_thread);
            let _ = self.free(remote_buf);

            if exit_code == 0 {
                Err("LoadLibraryW returned NULL in target process".to_string())
            } else {
                Ok(exit_code as usize)
            }
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

pub fn enable_debug_privilege() -> Result<(), String> {
    let mut token: HANDLE = null_mut();
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) != TRUE {
            return Err("OpenProcessToken failed".to_string());
        }

        let priv_name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
        let mut luid: LUID = zeroed();

        if LookupPrivilegeValueW(null(), priv_name.as_ptr(), &mut luid) != TRUE {
            CloseHandle(token);
            return Err("LookupPrivilegeValueW failed".to_string());
        }

        let mut tp: TOKEN_PRIVILEGES = zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        let ok = AdjustTokenPrivileges(token, FALSE, &tp, size_of::<TOKEN_PRIVILEGES>() as DWORD, null_mut(), null_mut());
        CloseHandle(token);

        if ok == TRUE {
            Ok(())
        } else {
            Err("AdjustTokenPrivileges failed".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_dll_path() {
        let res = Process::resolve_dll_path("d3dhook_dll.dll");
        assert!(res.is_ok(), "Expected to resolve d3dhook_dll.dll, got: {:?}", res);
        let path = res.unwrap();
        assert!(path.exists(), "Resolved path does not exist: {:?}", path);
    }

    #[test]
    fn test_process_access_mode_badges() {
        assert_eq!(ProcessAccessMode::NtApi.badge(), "[NT API]");
        assert_eq!(ProcessAccessMode::KernelDbk.badge(), "[DBK64]");
        assert_eq!(ProcessAccessMode::Win32.badge(), "[WIN32]");
    }

    #[test]
    fn test_nt_api_attach_and_read_current_process() {
        let current_pid = std::process::id();
        let proc = Process::attach_with_mode(current_pid, ProcessAccessMode::NtApi, None);
        assert!(proc.is_ok(), "Failed to attach via NtOpenProcess: {:?}", proc.err());

        let p = proc.unwrap();
        assert_eq!(p.access_mode, ProcessAccessMode::NtApi);

        // Read a known local variable via NtReadVirtualMemory
        let magic: u64 = 0xDEADBEEFCAFE1337;
        let addr = &magic as *const u64 as usize;
        let val: Result<u64, String> = p.read(addr);
        assert!(val.is_ok(), "Failed to read via NtReadVirtualMemory: {:?}", val.err());
        assert_eq!(val.unwrap(), 0xDEADBEEFCAFE1337);
    }
}

