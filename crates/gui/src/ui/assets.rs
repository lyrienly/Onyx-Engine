use eframe::egui::{self, ColorImage, TextureHandle, TextureOptions};

pub const ICON_OPENPROCESS: &[u8] = include_bytes!("../../assets/openprocess.png");
pub const ICON_OPEN: &[u8] = include_bytes!("../../assets/open.png");
pub const ICON_SAVE: &[u8] = include_bytes!("../../assets/save.png");
pub const ICON_ARROW: &[u8] = include_bytes!("../../assets/arrow.png");
pub const ICON_SETTINGS: &[u8] = include_bytes!("../../assets/settings.png");
pub const ICON_MEMORYVIEW: &[u8] = include_bytes!("../../assets/memoryview.png");
pub const ICON_CELOGO: &[u8] = include_bytes!("../../assets/celogo.png");

pub struct CeIcons {
    pub open_process: TextureHandle,
    pub open: TextureHandle,
    pub save: TextureHandle,
    pub arrow_down: TextureHandle,
    pub settings: TextureHandle,
    pub memory_view: TextureHandle,
    pub ce_logo: TextureHandle,
}

impl CeIcons {
    fn load_tex(ctx: &egui::Context, name: &str, bytes: &[u8]) -> TextureHandle {
        let img = image::load_from_memory(bytes).expect("Failed to decode embedded CE icon");
        let rgba = img.to_rgba8();
        let size = [rgba.width() as usize, rgba.height() as usize];
        let color_image = ColorImage::from_rgba_unmultiplied(size, rgba.as_raw());
        ctx.load_texture(name, color_image, TextureOptions::LINEAR)
    }

    pub fn load(ctx: &egui::Context) -> Self {
        Self {
            open_process: Self::load_tex(ctx, "ce_icon_openprocess", ICON_OPENPROCESS),
            open: Self::load_tex(ctx, "ce_icon_open", ICON_OPEN),
            save: Self::load_tex(ctx, "ce_icon_save", ICON_SAVE),
            arrow_down: Self::load_tex(ctx, "ce_icon_arrow", ICON_ARROW),
            settings: Self::load_tex(ctx, "ce_icon_settings", ICON_SETTINGS),
            memory_view: Self::load_tex(ctx, "ce_icon_memoryview", ICON_MEMORYVIEW),
            ce_logo: Self::load_tex(ctx, "ce_icon_celogo", ICON_CELOGO),
        }
    }
}
