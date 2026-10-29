//! Declaracoes extern e tipos minimos de D3D11/DXGI usados pelo overlay.
//! Mantemos independencia das features gigantes do `windows-sys` para evitar
//! inchar o workspace: so precisamos de `D3D11CreateDeviceAndSwapChain` +
//! algumas estruturas e constantes.

#![allow(non_snake_case, non_camel_case_types, dead_code)]

use core::ffi::c_void;

pub type HRESULT = i32;
pub type HWND = *mut c_void;
pub type DXGI_FORMAT = u32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

pub const DXGI_FORMAT_R8G8B8A8_UNORM: DXGI_FORMAT = 28;
pub const DXGI_USAGE_RENDER_TARGET_OUTPUT: u32 = 0x00000020;
pub const DXGI_SWAP_EFFECT_DISCARD: u32 = 0;
pub const D3D11_SDK_VERSION: u32 = 7;
pub const D3D_DRIVER_TYPE_HARDWARE: u32 = 1;
pub const D3D_DRIVER_TYPE_WARP: u32 = 5;
pub const D3D_FEATURE_LEVEL_11_0: u32 = 0xB000;
pub const D3D_FEATURE_LEVEL_10_0: u32 = 0xA000;

pub const D3D11_USAGE_DEFAULT: u32 = 0;
pub const D3D11_USAGE_STAGING: u32 = 3;
pub const D3D11_CPU_ACCESS_READ: u32 = 0x20000;
pub const D3D11_MAP_READ: u32 = 1;
pub const D3D11_RTV_DIMENSION_TEXTURE2D: u32 = 4;

pub const IID_ID3D11_TEXTURE2D: GUID = GUID {
    data1: 0x6f15aaf2,
    data2: 0xd208,
    data3: 0x4e89,
    data4: [0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c],
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DXGI_RATIONAL {
    pub Numerator: u32,
    pub Denominator: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DXGI_MODE_DESC {
    pub Width: u32,
    pub Height: u32,
    pub RefreshRate: DXGI_RATIONAL,
    pub Format: DXGI_FORMAT,
    pub ScanlineOrdering: u32,
    pub Scaling: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DXGI_SAMPLE_DESC {
    pub Count: u32,
    pub Quality: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DXGI_SWAP_CHAIN_DESC {
    pub BufferDesc: DXGI_MODE_DESC,
    pub SampleDesc: DXGI_SAMPLE_DESC,
    pub BufferUsage: u32,
    pub BufferCount: u32,
    pub OutputWindow: HWND,
    pub Windowed: i32,
    pub SwapEffect: u32,
    pub Flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct D3D11_TEXTURE2D_DESC {
    pub Width: u32,
    pub Height: u32,
    pub MipLevels: u32,
    pub ArraySize: u32,
    pub Format: DXGI_FORMAT,
    pub SampleDesc: DXGI_SAMPLE_DESC,
    pub Usage: u32,
    pub BindFlags: u32,
    pub CPUAccessFlags: u32,
    pub MiscFlags: u32,
}

#[repr(C)]
pub struct D3D11_MAPPED_SUBRESOURCE {
    pub pData: *mut c_void,
    pub RowPitch: u32,
    pub DepthPitch: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct D3D11_TEX2D_RTV {
    pub MipSlice: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct D3D11_RENDER_TARGET_VIEW_DESC {
    pub Format: DXGI_FORMAT,
    pub ViewDimension: u32,
    pub Texture2D: D3D11_TEX2D_RTV, // valido para ViewDimension=TEXTURE2D
}

// Interfaces opacas
pub type ID3D11Device = c_void;
pub type ID3D11DeviceContext = c_void;
pub type ID3D11RenderTargetView = c_void;
pub type ID3D11Texture2D = c_void;
pub type ID3D11Resource = c_void;
pub type IDXGISwapChain = c_void;

#[link(name = "d3d11")]
unsafe extern "system" {
    pub fn D3D11CreateDeviceAndSwapChain(
        pAdapter: *mut c_void,
        DriverType: u32,
        Software: *mut c_void,
        Flags: u32,
        pFeatureLevels: *const u32,
        FeatureLevels: u32,
        SDKVersion: u32,
        pSwapChainDesc: *const DXGI_SWAP_CHAIN_DESC,
        ppSwapChain: *mut *mut IDXGISwapChain,
        ppDevice: *mut *mut ID3D11Device,
        pFeatureLevel: *mut u32,
        ppImmediateContext: *mut *mut ID3D11DeviceContext,
    ) -> HRESULT;
}

// --- vtables (layouts estaveis conforme especificacao COM da MS) ---

#[repr(C)]
pub struct IUnknownVtbl {
    pub query_interface: unsafe extern "system" fn(
        this: *mut c_void,
        iid: *const GUID,
        ppv: *mut *mut c_void,
    ) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(this: *mut c_void) -> u32,
    pub release: unsafe extern "system" fn(this: *mut c_void) -> u32,
}

#[repr(C)]
pub struct IDXGISwapChainVtbl {
    pub base: IUnknownVtbl,
    pub _set_private_data: *const c_void,
    pub _set_private_data_interface: *const c_void,
    pub _get_private_data: *const c_void,
    pub _get_parent: *const c_void,
    pub _get_device: *const c_void,
    pub present:
        unsafe extern "system" fn(this: *mut c_void, sync_interval: u32, flags: u32) -> HRESULT,
    pub get_buffer: unsafe extern "system" fn(
        this: *mut c_void,
        buffer: u32,
        riid: *const GUID,
        pp_surface: *mut *mut c_void,
    ) -> HRESULT,
}

#[repr(C)]
pub struct ID3D11DeviceVtbl {
    pub base: IUnknownVtbl,
    pub _create_buffer: *const c_void,
    pub _create_texture_1d: *const c_void,
    pub create_texture_2d: unsafe extern "system" fn(
        this: *mut c_void,
        desc: *const D3D11_TEXTURE2D_DESC,
        initial: *const c_void,
        tex: *mut *mut ID3D11Texture2D,
    ) -> HRESULT,
    pub _create_texture_3d: *const c_void,
    pub _create_shader_resource_view: *const c_void,
    pub _create_unordered_access_view: *const c_void,
    pub create_render_target_view: unsafe extern "system" fn(
        this: *mut c_void,
        resource: *mut ID3D11Resource,
        desc: *const D3D11_RENDER_TARGET_VIEW_DESC,
        rtv: *mut *mut ID3D11RenderTargetView,
    ) -> HRESULT,
}

#[repr(C)]
pub struct ID3D11DeviceContextVtbl {
    pub base: IUnknownVtbl,
    // ID3D11DeviceChild
    pub _get_device: *const c_void,
    pub _get_private_data: *const c_void,
    pub _set_private_data: *const c_void,
    pub _set_private_data_interface: *const c_void,
    // ID3D11DeviceContext (slots 7..)
    pub _vs_set_cb: *const c_void,
    pub _ps_set_sr: *const c_void,
    pub _ps_set_shader: *const c_void,
    pub _ps_set_samp: *const c_void,
    pub _vs_set_shader: *const c_void,
    pub _draw_indexed: *const c_void,
    pub _draw: *const c_void,
    pub map: unsafe extern "system" fn(
        this: *mut c_void,
        resource: *mut ID3D11Resource,
        subresource: u32,
        map_type: u32,
        map_flags: u32,
        mapped: *mut D3D11_MAPPED_SUBRESOURCE,
    ) -> HRESULT, // slot 14
    pub unmap: unsafe extern "system" fn(
        this: *mut c_void,
        resource: *mut ID3D11Resource,
        subresource: u32,
    ), // slot 15
    pub _ps_set_cb: *const c_void,
    pub _ia_set_il: *const c_void,
    pub _ia_set_vb: *const c_void,
    pub _ia_set_ib: *const c_void,
    pub _draw_indexed_inst: *const c_void,
    pub _draw_inst: *const c_void,
    pub _gs_set_cb: *const c_void,
    pub _gs_set_shader: *const c_void,
    pub _ia_set_pt: *const c_void,
    pub _vs_set_sr: *const c_void,
    pub _vs_set_samp: *const c_void,
    pub _begin: *const c_void,
    pub _end: *const c_void,
    pub _get_data: *const c_void,
    pub _set_predication: *const c_void,
    pub _gs_set_sr: *const c_void,
    pub _gs_set_samp: *const c_void,
    pub _om_set_rt: *const c_void,
    pub _om_set_rt_uav: *const c_void,
    pub _om_set_blend: *const c_void,
    pub _om_set_ds: *const c_void,
    pub _so_set_targets: *const c_void,
    pub _draw_auto: *const c_void,
    pub _draw_indexed_inst_indirect: *const c_void,
    pub _draw_inst_indirect: *const c_void,
    pub _dispatch: *const c_void,
    pub _dispatch_indirect: *const c_void,
    pub _rs_set_state: *const c_void,
    pub _rs_set_viewports: *const c_void,
    pub _rs_set_scissors: *const c_void,
    pub _copy_subresource_region: *const c_void,
    pub copy_resource: unsafe extern "system" fn(
        this: *mut c_void,
        dst: *mut ID3D11Resource,
        src: *mut ID3D11Resource,
    ), // slot 47
    pub _update_subresource: *const c_void,
    pub _copy_structure_count: *const c_void,
    pub clear_render_target_view: unsafe extern "system" fn(
        this: *mut c_void,
        rtv: *mut ID3D11RenderTargetView,
        rgba: *const [f32; 4],
    ), // slot 50
}

pub const PRESENT_VTABLE_INDEX: usize = 8;

/// Release COM via vtable.
pub unsafe fn release_com(obj: *mut c_void) {
    if obj.is_null() {
        return;
    }
    let vtbl = *(obj as *const *const IUnknownVtbl);
    ((*vtbl).release)(obj);
}
