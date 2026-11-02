use super::types::*;
use crate::sk_crypt;
use crate::win32::*;
use std::mem::size_of;
use std::ptr::null_mut;

pub struct OnyxDriver {
    pub device_handle: HANDLE,
    pub device_name: String,
}

pub type DbkDriver = OnyxDriver;

unsafe impl Send for OnyxDriver {}
unsafe impl Sync for OnyxDriver {}

impl OnyxDriver {
    pub fn connect_device(device_path: &str) -> Result<Self, String> {
        let wide_name: Vec<u16> = device_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };

        if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
            let driver = OnyxDriver {
                device_handle: handle,
                device_name: device_path.to_string(),
            };

            let _ = driver.hide_driver();
            let _ = driver.clean_traces();
            Ok(driver)
        } else {
            Err(format!("Failed to open device {}", device_path))
        }
    }

    pub fn connect() -> Result<Self, String> {
        let target = sk_crypt!(r"\\.\OnyxDriver");

        if let Ok(driver) = Self::connect_device(&target) {
            return Ok(driver);
        }

        Err(
            "Failed to connect to OnyxDriver (\\\\.\\OnyxDriver). Is OnyxDriver.sys loaded?"
                .to_string(),
        )
    }

    pub fn test(&self) -> bool {
        let mut returned: DWORD = 0;
        let mut test_val: u32 = 0xAA55AA55;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_TEST,
                &mut test_val as *mut _ as LPVOID,
                size_of::<u32>() as DWORD,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        ok == TRUE
    }

    pub fn get_version(&self) -> Result<u32, String> {
        let mut version: u32 = 0;
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_GETVERSION,
                null_mut(),
                0,
                &mut version as *mut _ as LPVOID,
                size_of::<u32>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok(version)
        } else {
            Err("Failed to query DBK version".to_string())
        }
    }

    pub fn get_process_base(&self, pid: u32) -> Result<u64, String> {
        let mut input_pid = pid;
        let mut base_addr: u64 = 0;
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_GET_BASE,
                &mut input_pid as *mut _ as LPVOID,
                size_of::<u32>() as DWORD,
                &mut base_addr as *mut _ as LPVOID,
                size_of::<u64>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE && base_addr != 0 {
            Ok(base_addr)
        } else {
            Err(format!(
                "Failed to resolve process base via kernel for PID {}",
                pid
            ))
        }
    }

    #[inline]

    pub fn open_process(&self, pid: u32) -> Result<HANDLE, String> {
        let mut input_pid: u64 = pid as u64;
        let mut output: CeOpenProcessOutput = unsafe { std::mem::zeroed() };
        let mut returned: DWORD = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_OPENPROCESS,
                &mut input_pid as *mut _ as LPVOID,
                size_of::<u64>() as DWORD,
                &mut output as *mut _ as LPVOID,
                size_of::<CeOpenProcessOutput>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };

        if ok == TRUE && output.handle != 0 {
            Ok(output.handle as HANDLE)
        } else {
            Err(format!(
                "OnyxDriver IOCTL_CE_OPENPROCESS failed for PID {}",
                pid
            ))
        }
    }

    pub fn setup_shared_ring(&self) -> Result<*mut OnyxSharedRing, String> {
        let mut output = SetupSharedRingOutput {
            user_address: 0,
            size: 0,
            status: 0,
        };
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_SETUP_SHARED_RING,
                null_mut(),
                0,
                &mut output as *mut _ as LPVOID,
                size_of::<SetupSharedRingOutput>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };
        let user_addr = output.user_address;
        let status = output.status;
        if ok == TRUE && user_addr != 0 && status == 0 {
            Ok(user_addr as *mut OnyxSharedRing)
        } else {
            Err(format!(
                "IOCTL_CE_SETUP_SHARED_RING failed (addr={:#X}, status={:#X})",
                user_addr, status
            ))
        }
    }

    pub fn process_shared_ring(&self) -> Result<(), String> {
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_PROCESS_SHARED_RING,
                null_mut(),
                0,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok(())
        } else {
            Err("IOCTL_CE_PROCESS_SHARED_RING failed".to_string())
        }
    }
}

impl Drop for OnyxDriver {
    fn drop(&mut self) {
        if !self.device_handle.is_null() && self.device_handle != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.device_handle);
            }
        }
    }
}
