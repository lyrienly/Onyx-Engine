//! Estado capturado em runtime pelos hooks das APIs gráficas.
//!
//! Depois que o primeiro frame é apresentado, os trampolins preenchem este
//! módulo com o Device/Context/Queue reais do jogo — são estes objetos que
//! o backend ImGui vai usar para desenhar o overlay no mesmo pipeline.

use parking_lot::Mutex;
use windows::Win32::Graphics::Direct3D11::ID3D11Device;
use windows::Win32::Graphics::Direct3D12::{ID3D12CommandQueue, ID3D12Device};
use windows::Win32::Graphics::Dxgi::IDXGISwapChain;
use windows::core::Interface;

pub enum CapturedApi {
    None,
    D3D11 {
        device: ID3D11Device,
    },
    D3D12 {
        device: ID3D12Device,
        queue: Option<ID3D12CommandQueue>,
    },
    Vulkan,
}

pub static CAPTURED: Mutex<CapturedApi> = Mutex::new(CapturedApi::None);

pub fn is_captured() -> bool {
    !matches!(*CAPTURED.lock(), CapturedApi::None)
}

pub unsafe fn try_capture_from_swap_chain(swap_chain: &IDXGISwapChain) {
    if is_captured() {
        return;
    }
    if let Ok(dev) = swap_chain.GetDevice::<ID3D12Device>() {
        *CAPTURED.lock() = CapturedApi::D3D12 {
            device: dev,
            queue: None,
        };
        return;
    }
    if let Ok(dev) = swap_chain.GetDevice::<ID3D11Device>() {
        *CAPTURED.lock() = CapturedApi::D3D11 { device: dev };
    }
}

pub fn set_d3d12_queue(queue: ID3D12CommandQueue) {
    let mut cur = CAPTURED.lock();
    match &mut *cur {
        CapturedApi::D3D12 { queue: slot, .. } if slot.is_none() => {
            *slot = Some(queue);
        }
        CapturedApi::None => {
            // Queue capturada antes de qualquer Present — guardamos o device
            // depois quando o Present finalmente rodar.
        }
        _ => {}
    }
}

pub fn mark_vulkan() {
    let mut cur = CAPTURED.lock();
    if matches!(*cur, CapturedApi::None) {
        *cur = CapturedApi::Vulkan;
    }
}

pub fn clear() {
    *CAPTURED.lock() = CapturedApi::None;
}
