use super::OnyxDriver;
use super::types::*;
use crate::win32::*;
use std::mem::size_of;
use std::ptr::null_mut;

impl OnyxDriver {
    pub fn hide_driver(&self) -> Result<(), String> {
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_HIDEDRIVER,
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
            Err("Failed to hide driver from PsLoadedModuleList".to_string())
        }
    }

    pub fn inspect_process(&self, pid: u32) -> Result<ProcessMemoryProof, String> {
        let mut input_pid = pid;
        let mut proof = ProcessMemoryProof::default();
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_INSPECT_PROCESS,
                &mut input_pid as *mut _ as LPVOID,
                size_of::<u32>() as DWORD,
                &mut proof as *mut _ as LPVOID,
                size_of::<ProcessMemoryProof>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok(proof)
        } else {
            Err(format!(
                "Failed to inspect process PID {} (os error: {})",
                pid,
                std::io::Error::last_os_error()
            ))
        }
    }

    pub fn inspect_driver(&self) -> Result<DriverMemoryProof, String> {
        let mut proof = DriverMemoryProof::default();
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_INSPECT_DRIVER,
                null_mut(),
                0,
                &mut proof as *mut _ as LPVOID,
                size_of::<DriverMemoryProof>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok(proof)
        } else {
            Err(format!(
                "Failed to inspect driver memory (os error: {})",
                std::io::Error::last_os_error()
            ))
        }
    }

    pub fn clean_traces(&self) -> Result<(), String> {
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_CLEAN_KERNEL_TRACES,
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
            Err("Failed to clean kernel driver traces".to_string())
        }
    }

    pub fn cloak_symlink(&self, new_symlink: &str) -> Result<(), String> {
        let wide: Vec<u16> = new_symlink
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_CLOAK_DEVICE_SYMLINK,
                wide.as_ptr() as LPVOID,
                (wide.len() * 2) as DWORD,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok(())
        } else {
            Err("Failed to cloak device symlink".to_string())
        }
    }

    pub fn is_secure_boot_active() -> bool {
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("powershell")
                .args(["-NoProfile", "-Command", "Confirm-SecureBootUEFI 2>$null"])
                .output()
            {
                let text = String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .to_lowercase();
                if text == "true" {
                    return true;
                }
            }
        }
        false
    }

    pub fn is_test_signing_enabled() -> bool {
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("bcdedit")
                .args(["/enum", "{current}"])
                .output()
            {
                let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
                if text.contains("testsigning") && text.contains("yes") {
                    return true;
                }
            }
        }
        false
    }

    pub fn is_vbs_active() -> bool {
        #[cfg(target_os = "windows")]
        {
            let subkey: Vec<u16> = "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\0"
                .encode_utf16()
                .collect();
            let val_vbs: Vec<u16> = "EnableVirtualizationBasedSecurity\0"
                .encode_utf16()
                .collect();
            let mut data: u32 = 0;
            let mut size: DWORD = std::mem::size_of::<u32>() as DWORD;

            let res = unsafe {
                RegGetValueW(
                    HKEY_LOCAL_MACHINE,
                    subkey.as_ptr(),
                    val_vbs.as_ptr(),
                    RRF_RT_REG_DWORD,
                    std::ptr::null_mut(),
                    &mut data as *mut _ as LPVOID,
                    &mut size,
                )
            };

            if res == 0 && data == 1 {
                return true;
            }

            use std::process::Command;
            if let Ok(output) = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    "(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard 2>$null).VirtualizationBasedSecurityStatus",
                ])
                .output()
            {
                let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if text == "2" || text == "1" {
                    return true;
                }
            }
        }
        false
    }

    pub fn is_hvci_active() -> bool {
        #[cfg(target_os = "windows")]
        {
            let subkey_scenario: Vec<u16> =
                "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\0"
                    .encode_utf16()
                    .collect();
            let val_enabled: Vec<u16> = "Enabled\0".encode_utf16().collect();
            let mut data: u32 = 0;
            let mut size: DWORD = std::mem::size_of::<u32>() as DWORD;

            let res = unsafe {
                RegGetValueW(
                    HKEY_LOCAL_MACHINE,
                    subkey_scenario.as_ptr(),
                    val_enabled.as_ptr(),
                    RRF_RT_REG_DWORD,
                    std::ptr::null_mut(),
                    &mut data as *mut _ as LPVOID,
                    &mut size,
                )
            };

            if res == 0 && data == 1 {
                return true;
            }

            let subkey_dg: Vec<u16> = "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\0"
                .encode_utf16()
                .collect();
            let val_hvci: Vec<u16> = "HypervisorEnforcedCodeIntegrity\0".encode_utf16().collect();
            size = std::mem::size_of::<u32>() as DWORD;

            let res2 = unsafe {
                RegGetValueW(
                    HKEY_LOCAL_MACHINE,
                    subkey_dg.as_ptr(),
                    val_hvci.as_ptr(),
                    RRF_RT_REG_DWORD,
                    std::ptr::null_mut(),
                    &mut data as *mut _ as LPVOID,
                    &mut size,
                )
            };

            if res2 == 0 && data == 1 {
                return true;
            }

            use std::process::Command;
            if let Ok(output) = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    "((Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard 2>$null).SecurityServicesRunning -contains 2)",
                ])
                .output()
            {
                let text = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
                if text == "true" {
                    return true;
                }
            }
        }
        false
    }

    pub fn is_cr3_interception_risk() -> bool {
        Self::is_vbs_active()
    }

    pub fn evaluate_security_profile() -> KernelSecurityProfile {
        let secure_boot = Self::is_secure_boot_active();
        let test_signing = Self::is_test_signing_enabled();
        let vbs = Self::is_vbs_active();
        let hvci = Self::is_hvci_active();
        let cr3_risk = vbs;

        KernelSecurityProfile {
            secure_boot_active: secure_boot,
            test_signing_active: test_signing,
            vbs_active: vbs,
            hvci_active: hvci,
            cr3_interception_risk: cr3_risk,
        }
    }

    pub fn check_cr3_intercept_advisory(pid: u32) -> Option<String> {
        if Self::is_cr3_interception_risk() {
            Some(format!(
                "Aviso: VBS (Seguranca Baseada em Virtualizacao) esta ativo. Traducoes fisicas de CR3 para o PID {} operam sob SLAT/EPT do hipervisor; paginas protegidas do Secure Kernel (VTL 1) nao podem ser acessadas diretamente.",
                pid
            ))
        } else {
            None
        }
    }
}
