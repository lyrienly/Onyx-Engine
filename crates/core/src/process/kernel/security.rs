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

    pub fn get_hvci_status(&self) -> Result<CeHvciStatusOutput, String> {
        let mut status = CeHvciStatusOutput::default();
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_GET_HVCI_STATUS,
                null_mut(),
                0,
                &mut status as *mut _ as LPVOID,
                size_of::<CeHvciStatusOutput>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok(status)
        } else {
            Err(format!(
                "Failed to query HVCI status from driver (os error: {})",
                std::io::Error::last_os_error()
            ))
        }
    }

    pub fn is_hypervisor_present() -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            let res = std::arch::x86_64::__cpuid(1);
            (res.ecx & (1 << 31)) != 0
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    }

    pub fn query_system_code_integrity() -> Option<(bool, bool, u32)> {
        #[cfg(target_os = "windows")]
        {
            #[repr(C)]
            struct SystemCodeIntegrityInformation {
                length: u32,
                code_integrity_options: u32,
            }

            type PfnNtQuerySystemInformation = unsafe extern "system" fn(
                system_information_class: u32,
                system_information: *mut std::ffi::c_void,
                system_information_length: u32,
                return_length: *mut u32,
            ) -> i32;

            let ntdll = unsafe { GetModuleHandleA(b"ntdll.dll\0".as_ptr()) };
            if !ntdll.is_null() {
                let proc = unsafe { GetProcAddress(ntdll, b"NtQuerySystemInformation\0".as_ptr()) };
                if !proc.is_null() {
                    let nt_query: PfnNtQuerySystemInformation =
                        unsafe { std::mem::transmute(proc) };
                    let mut sci = SystemCodeIntegrityInformation {
                        length: std::mem::size_of::<SystemCodeIntegrityInformation>() as u32,
                        code_integrity_options: 0,
                    };
                    let mut ret_len = 0u32;
                    let status = unsafe {
                        nt_query(
                            103, // SystemCodeIntegrityInformation
                            &mut sci as *mut _ as *mut std::ffi::c_void,
                            std::mem::size_of::<SystemCodeIntegrityInformation>() as u32,
                            &mut ret_len,
                        )
                    };
                    if status >= 0 {
                        let hvci_enabled = (sci.code_integrity_options & 0x00000400) != 0; // CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED
                        let strict_mode = (sci.code_integrity_options & 0x00001000) != 0; // CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED
                        return Some((hvci_enabled, strict_mode, sci.code_integrity_options));
                    }
                }
            }
        }
        None
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
            // HVCI strictly requires VBS
            if Self::is_hvci_active() {
                return true;
            }

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
            if let Some((hvci, _, _)) = Self::query_system_code_integrity() {
                if hvci {
                    return true;
                }
            }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hvci_status_struct_size_and_alignment() {
        assert_eq!(std::mem::size_of::<CeHvciStatusOutput>(), 16);
    }

    #[test]
    fn test_hypervisor_detection_does_not_panic() {
        let _ = OnyxDriver::is_hypervisor_present();
    }

    #[test]
    fn test_code_integrity_query_does_not_panic() {
        let _ = OnyxDriver::query_system_code_integrity();
    }

    #[test]
    fn test_security_profile_evaluation() {
        let profile = OnyxDriver::evaluate_security_profile();
        if profile.hvci_active {
            assert!(profile.vbs_active, "HVCI cannot be active without VBS");
            assert!(
                profile.cr3_interception_risk,
                "CR3 risk must be set when VBS/HVCI is active"
            );
        }
    }
}
