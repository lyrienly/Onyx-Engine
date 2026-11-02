use crate::hooks::{dxgi, d3d12, vulkan};
use parking_lot::Mutex;

pub struct HookManager {
    pub dxgi_installed: bool,
    pub d3d12_installed: bool,
    pub vulkan_installed: bool,
}

impl HookManager {
    const fn new() -> Self {
        Self {
            dxgi_installed: false,
            d3d12_installed: false,
            vulkan_installed: false,
        }
    }
}

pub static MANAGER: Mutex<HookManager> = Mutex::new(HookManager::new());

pub unsafe fn install_all() {
    let mut mgr = MANAGER.lock();
    mgr.dxgi_installed = dxgi::install().is_ok();
    mgr.d3d12_installed = d3d12::install().is_ok();
    mgr.vulkan_installed = vulkan::install().is_ok();
}

pub unsafe fn uninstall_all() {
    let mut mgr = MANAGER.lock();
    if mgr.vulkan_installed {
        vulkan::uninstall();
        mgr.vulkan_installed = false;
    }
    if mgr.d3d12_installed {
        d3d12::uninstall();
        mgr.d3d12_installed = false;
    }
    if mgr.dxgi_installed {
        dxgi::uninstall();
        mgr.dxgi_installed = false;
    }
}
