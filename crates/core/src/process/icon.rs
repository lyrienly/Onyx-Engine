use std::path::Path;
use std::ptr::null_mut;
use crate::process::win32::*;

pub struct ProcessIconExtractor;

impl ProcessIconExtractor {
    pub fn get_process_path(pid: u32, name: &str) -> Option<String> {
        if pid == 0 || pid == 4 {
            return None;
        }

        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) };
        if !handle.is_null() {
            let mut buf = [0u16; 1024];
            let mut size = buf.len() as DWORD;
            let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size) };
            unsafe { CloseHandle(handle) };

            if ok == TRUE && size > 0 {
                let path_str = String::from_utf16_lossy(&buf[..size as usize]);
                if Path::new(&path_str).exists() {
                    return Some(path_str);
                }
            }
        }

        let sys32 = format!(r"C:\Windows\System32\{}", name);
        if Path::new(&sys32).exists() {
            return Some(sys32);
        }

        let win = format!(r"C:\Windows\{}", name);
        if Path::new(&win).exists() {
            return Some(win);
        }

        None
    }

    fn extract_rgba_from_hicon(h_icon: HICON, owns_handle: bool) -> Option<(u32, u32, Vec<u8>)> {
        if h_icon.is_null() {
            return None;
        }

        let mut icon_info: ICONINFO = unsafe { std::mem::zeroed() };
        if unsafe { GetIconInfo(h_icon, &mut icon_info) } == FALSE {
            if owns_handle {
                unsafe { DestroyIcon(h_icon) };
            }
            return None;
        }

        let hdc = unsafe { GetDC(null_mut()) };
        if hdc.is_null() {
            if !icon_info.hbmColor.is_null() {
                unsafe { DeleteObject(icon_info.hbmColor) };
            }
            if !icon_info.hbmMask.is_null() {
                unsafe { DeleteObject(icon_info.hbmMask) };
            }
            if owns_handle {
                unsafe { DestroyIcon(h_icon) };
            }
            return None;
        }

        let mut bmp: BITMAP = unsafe { std::mem::zeroed() };
        let has_color = !icon_info.hbmColor.is_null();
        let target_bitmap = if has_color { icon_info.hbmColor } else { icon_info.hbmMask };

        let obj_ok = unsafe {
            GetObjectW(
                target_bitmap,
                std::mem::size_of::<BITMAP>() as i32,
                &mut bmp as *mut _ as LPVOID,
            )
        };

        if obj_ok == 0 || bmp.bmWidth <= 0 || bmp.bmHeight <= 0 {
            unsafe {
                ReleaseDC(null_mut(), hdc);
                if !icon_info.hbmColor.is_null() { DeleteObject(icon_info.hbmColor); }
                if !icon_info.hbmMask.is_null() { DeleteObject(icon_info.hbmMask); }
                if owns_handle { DestroyIcon(h_icon); }
            }
            return None;
        }

        let width = bmp.bmWidth as u32;
        let height = if has_color { bmp.bmHeight as u32 } else { (bmp.bmHeight / 2) as u32 };

        let mut bmi: BITMAPINFO = unsafe { std::mem::zeroed() };
        bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as DWORD;
        bmi.bmiHeader.biWidth = width as i32;
        bmi.bmiHeader.biHeight = -(height as i32);
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;

        let pixel_count = (width * height) as usize;
        let mut pixels = vec![0u8; pixel_count * 4];

        if has_color {
            unsafe {
                GetDIBits(
                    hdc,
                    icon_info.hbmColor,
                    0,
                    height,
                    pixels.as_mut_ptr() as LPVOID,
                    &mut bmi,
                    DIB_RGB_COLORS,
                );
            }

            let mut has_alpha = false;
            for chunk in pixels.as_chunks::<4>().0 {
                if chunk[3] > 0 {
                    has_alpha = true;
                    break;
                }
            }

            if !has_alpha && !icon_info.hbmMask.is_null() {

                let mut mask_pixels = vec![0u8; pixel_count * 4];
                unsafe {
                    GetDIBits(
                        hdc,
                        icon_info.hbmMask,
                        0,
                        height,
                        mask_pixels.as_mut_ptr() as LPVOID,
                        &mut bmi,
                        DIB_RGB_COLORS,
                    );
                }

                for i in 0..pixel_count {

                    let is_transparent = mask_pixels[i * 4] != 0 || mask_pixels[i * 4 + 1] != 0 || mask_pixels[i * 4 + 2] != 0;
                    pixels[i * 4 + 3] = if is_transparent { 0 } else { 255 };
                }
            } else if !has_alpha {

                for chunk in pixels.as_chunks_mut::<4>().0 {
                    chunk[3] = if chunk[0] == 0 && chunk[1] == 0 && chunk[2] == 0 { 0 } else { 255 };
                }
            }

            for chunk in pixels.as_chunks_mut::<4>().0 {
                chunk.swap(0, 2);
            }
        } else {

            let mut mask_pixels = vec![0u8; pixel_count * 4];
            unsafe {
                GetDIBits(
                    hdc,
                    icon_info.hbmMask,
                    0,
                    height,
                    mask_pixels.as_mut_ptr() as LPVOID,
                    &mut bmi,
                    DIB_RGB_COLORS,
                );
            }

            for i in 0..pixel_count {
                let val = if mask_pixels[i * 4] == 0 { 255 } else { 0 };
                pixels[i * 4] = val;
                pixels[i * 4 + 1] = val;
                pixels[i * 4 + 2] = val;
                pixels[i * 4 + 3] = val;
            }
        }

        unsafe {
            ReleaseDC(null_mut(), hdc);
            if !icon_info.hbmColor.is_null() { DeleteObject(icon_info.hbmColor); }
            if !icon_info.hbmMask.is_null() { DeleteObject(icon_info.hbmMask); }
            if owns_handle { DestroyIcon(h_icon); }
        }

        Some((width, height, pixels))
    }

    pub fn extract_icon_for_path(path: &str) -> Option<(u32, u32, Vec<u8>)> {
        unsafe {
            let _ = CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        }
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

        let mut h_small: HICON = null_mut();
        let count = unsafe { ExtractIconExW(wide.as_ptr(), 0, null_mut(), &mut h_small, 1) };
        if count > 0 && count != u32::MAX && !h_small.is_null()
            && let Some(rgba) = Self::extract_rgba_from_hicon(h_small, true) {
                return Some(rgba);
            }

        let mut shfi: SHFILEINFOW = unsafe { std::mem::zeroed() };
        let res = unsafe {
            SHGetFileInfoW(
                wide.as_ptr(),
                0,
                &mut shfi,
                std::mem::size_of::<SHFILEINFOW>() as u32,
                SHGFI_ICON | SHGFI_SMALLICON,
            )
        };

        if res != 0 && !shfi.hIcon.is_null() {
            return Self::extract_rgba_from_hicon(shfi.hIcon, true);
        }

        None
    }

    pub fn extract_default_exe_icon() -> Option<(u32, u32, Vec<u8>)> {
        unsafe {
            let _ = CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        }
        let wide: Vec<u16> = ".exe".encode_utf16().chain(std::iter::once(0)).collect();
        let mut shfi: SHFILEINFOW = unsafe { std::mem::zeroed() };
        let res = unsafe {
            SHGetFileInfoW(
                wide.as_ptr(),
                FILE_ATTRIBUTE_NORMAL,
                &mut shfi,
                std::mem::size_of::<SHFILEINFOW>() as u32,
                SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES,
            )
        };

        if res != 0 && !shfi.hIcon.is_null()
            && let Some(icon) = Self::extract_rgba_from_hicon(shfi.hIcon, true) {
                return Some(icon);
            }

        let sys_icon = unsafe { LoadIconW(null_mut(), IDI_APPLICATION) };
        if !sys_icon.is_null() {
            return Self::extract_rgba_from_hicon(sys_icon, false);
        }

        None
    }

    pub fn get_process_icon(pid: u32, name: &str) -> Option<(u32, u32, Vec<u8>)> {
        if let Some(path) = Self::get_process_path(pid, name)
            && let Some(icon) = Self::extract_icon_for_path(&path) {
                return Some(icon);
            }

        if let Some(icon) = Self::extract_icon_for_path(name) {
            return Some(icon);
        }

        Self::extract_default_exe_icon()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_default_exe_icon() {
        let icon = ProcessIconExtractor::extract_default_exe_icon();
        assert!(icon.is_some(), "Default .exe icon extraction failed");
        let (w, h, pixels) = icon.unwrap();
        assert!(w > 0 && h > 0, "Icon dimension should be non-zero");
        assert_eq!(pixels.len(), (w * h * 4) as usize, "RGBA pixel buffer length mismatch");
    }

    #[test]
    fn test_extract_current_process_icon() {
        let icon = ProcessIconExtractor::get_process_icon(std::process::id(), "cargo.exe");
        assert!(icon.is_some(), "Failed to extract current process or fallback icon");
    }

    #[test]
    fn test_default_exe_icon_is_repeatable() {
        let first = ProcessIconExtractor::extract_default_exe_icon();
        let second = ProcessIconExtractor::extract_default_exe_icon();
        assert!(first.is_some(), "First default icon extraction failed");
        assert!(second.is_some(), "Second default icon extraction failed");
        assert_eq!(first.unwrap().2, second.unwrap().2, "Default icon pixels must be stable");
    }

    #[test]
    fn test_get_process_path_ignores_system_pids() {
        assert!(ProcessIconExtractor::get_process_path(0, "System").is_none());
        assert!(ProcessIconExtractor::get_process_path(4, "System").is_none());
    }
}
