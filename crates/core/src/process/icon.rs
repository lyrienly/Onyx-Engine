// language: Rust, file: icon.rs, target: Windows 11, MSVC
// Windows Shell Executable Icon Extractor
// Extracts high-fidelity 16x16 / 32x32 RGBA icons for running processes and executables

use std::path::Path;
use std::ptr::null_mut;
use crate::process::win32::*;

pub struct ProcessIconExtractor;

impl ProcessIconExtractor {
    pub fn get_process_path(pid: u32, name: &str) -> Option<String> {
        if pid == 0 || pid == 4 {
            return None;
        }

        // 1. Try querying via OpenProcess + QueryFullProcessImageNameW
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

        // 2. Fallback: check Windows System32 / Windows folders
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

    pub fn extract_rgba_from_hicon(h_icon: HICON) -> Option<(u32, u32, Vec<u8>)> {
        if h_icon.is_null() {
            return None;
        }

        let mut icon_info: ICONINFO = unsafe { std::mem::zeroed() };
        if unsafe { GetIconInfo(h_icon, &mut icon_info) } == FALSE {
            unsafe { DestroyIcon(h_icon) };
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
            unsafe { DestroyIcon(h_icon) };
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
                DestroyIcon(h_icon);
            }
            return None;
        }

        let width = bmp.bmWidth as u32;
        let height = if has_color { bmp.bmHeight as u32 } else { (bmp.bmHeight / 2) as u32 };

        let mut bmi: BITMAPINFO = unsafe { std::mem::zeroed() };
        bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as DWORD;
        bmi.bmiHeader.biWidth = width as i32;
        bmi.bmiHeader.biHeight = -(height as i32); // Top-down
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

            // Check if alpha channel exists or is all zero
            let mut has_alpha = false;
            for chunk in pixels.chunks_exact(4) {
                if chunk[3] > 0 {
                    has_alpha = true;
                    break;
                }
            }

            if !has_alpha && !icon_info.hbmMask.is_null() {
                // Extract 1-bit transparency mask
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
                    // Mask bit 0 = opaque, 1 = transparent
                    let is_transparent = mask_pixels[i * 4] != 0 || mask_pixels[i * 4 + 1] != 0 || mask_pixels[i * 4 + 2] != 0;
                    pixels[i * 4 + 3] = if is_transparent { 0 } else { 255 };
                }
            } else if !has_alpha {
                // Fallback: opaque if any color is present
                for chunk in pixels.chunks_exact_mut(4) {
                    chunk[3] = if chunk[0] == 0 && chunk[1] == 0 && chunk[2] == 0 { 0 } else { 255 };
                }
            }

            // Convert BGRA -> RGBA
            for chunk in pixels.chunks_exact_mut(4) {
                chunk.swap(0, 2);
            }
        } else {
            // Monochrome icon: extract from mask
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
            DestroyIcon(h_icon);
        }

        Some((width, height, pixels))
    }

    pub fn extract_icon_for_path(path: &str) -> Option<(u32, u32, Vec<u8>)> {
        unsafe {
            let _ = CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        }
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

        // 1. Try ExtractIconExW for small 16x16 icon
        let mut h_small: HICON = null_mut();
        let count = unsafe { ExtractIconExW(wide.as_ptr(), 0, null_mut(), &mut h_small, 1) };
        if count > 0 && count != u32::MAX && !h_small.is_null() {
            if let Some(rgba) = Self::extract_rgba_from_hicon(h_small) {
                return Some(rgba);
            }
        }

        // 2. Try SHGetFileInfoW
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
            return Self::extract_rgba_from_hicon(shfi.hIcon);
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

        if res != 0 && !shfi.hIcon.is_null() {
            if let Some(icon) = Self::extract_rgba_from_hicon(shfi.hIcon) {
                return Some(icon);
            }
        }

        // User32 fallback: standard application icon
        let sys_icon = unsafe { LoadIconW(null_mut(), IDI_APPLICATION) };
        if !sys_icon.is_null() {
            return Self::extract_rgba_from_hicon(sys_icon);
        }

        None
    }

    pub fn get_process_icon(pid: u32, name: &str) -> Option<(u32, u32, Vec<u8>)> {
        if let Some(path) = Self::get_process_path(pid, name) {
            if let Some(icon) = Self::extract_icon_for_path(&path) {
                return Some(icon);
            }
        }

        // Fallback: try by name if it's a known filename
        if let Some(icon) = Self::extract_icon_for_path(name) {
            return Some(icon);
        }

        // Fallback: standard Windows executable icon
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
}

