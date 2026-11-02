use super::OnyxDriver;
use super::types::*;
use crate::win32::*;
use std::mem::size_of;
use std::ptr::null_mut;

impl OnyxDriver {
    pub fn setup_ultimap2(&self, config: &CeUltimap2Config) -> Result<(), String> {
        let mut returned: DWORD = 0;
        let mut cfg = *config;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_ULTIMAP2,
                &mut cfg as *mut _ as LPVOID,
                size_of::<CeUltimap2Config>() as DWORD,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok(())
        } else {
            Err(format!(
                "Failed to setup Ultimap2 (os error: {})",
                std::io::Error::last_os_error()
            ))
        }
    }

    pub fn disable_ultimap2(&self) -> Result<(), String> {
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_DISABLEULTIMAP2,
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
            Err(format!(
                "Failed to disable Ultimap2 (os error: {})",
                std::io::Error::last_os_error()
            ))
        }
    }

    pub fn wait_for_ultimap2_data(&self, timeout_ms: u32) -> Result<CeUltimap2DataEvent, String> {
        let mut input_timeout = timeout_ms;
        let mut event = CeUltimap2DataEvent::default();
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_ULTIMAP2_WAITFORDATA,
                &mut input_timeout as *mut _ as LPVOID,
                size_of::<u32>() as DWORD,
                &mut event as *mut _ as LPVOID,
                size_of::<CeUltimap2DataEvent>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok(event)
        } else {
            Err(format!(
                "Failed to wait for Ultimap2 data (os error: {})",
                std::io::Error::last_os_error()
            ))
        }
    }

    pub fn continue_ultimap2(&self, cpu_nr: u32) -> Result<(), String> {
        let mut input_cpu = cpu_nr;
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_ULTIMAP2_CONTINUE,
                &mut input_cpu as *mut _ as LPVOID,
                size_of::<u32>() as DWORD,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok(())
        } else {
            Err(format!(
                "Failed to continue Ultimap2 for CPU {} (os error: {})",
                cpu_nr,
                std::io::Error::last_os_error()
            ))
        }
    }

    pub fn flush_ultimap2(&self) -> Result<(), String> {
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_ULTIMAP2_FLUSH,
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
            Err("Failed to flush Ultimap2 buffers".to_string())
        }
    }

    pub fn pause_ultimap2(&self) -> Result<(), String> {
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_ULTIMAP2_PAUSE,
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
            Err("Failed to pause Ultimap2".to_string())
        }
    }

    pub fn resume_ultimap2(&self) -> Result<(), String> {
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_ULTIMAP2_RESUME,
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
            Err("Failed to resume Ultimap2".to_string())
        }
    }

    pub fn get_ultimap2_trace_size(&self) -> Result<u64, String> {
        let mut size: u64 = 0;
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_ULTIMAP2_GETTRACESIZE,
                null_mut(),
                0,
                &mut size as *mut _ as LPVOID,
                size_of::<u64>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok(size)
        } else {
            Err("Failed to get Ultimap2 trace size".to_string())
        }
    }

    pub fn reset_ultimap2_trace_size(&self) -> Result<(), String> {
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_ULTIMAP2_RESETTRACESIZE,
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
            Err("Failed to reset Ultimap2 trace size".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ultimap2_config_size_matches_driver() {
        assert_eq!(size_of::<CeUltimapRange>(), 24);
        assert_eq!(size_of::<CeUltimap2Config>(), 616);
        assert_eq!(size_of::<CeUltimap2DataEvent>(), 24);
    }
}
