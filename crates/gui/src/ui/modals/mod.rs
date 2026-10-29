pub mod address_modal;
pub mod auto_assembler;
pub mod edit_byte_modal;
pub mod lua_console;
pub mod memory_view;
pub mod mono_modal;
pub mod plugins_modal;
pub mod pointer_scanner;
pub mod process_modal;
pub mod settings_modal;

use crate::app::OnyxEngineApp;
use eframe::egui;

pub fn render_all_modals(app: &mut OnyxEngineApp, ctx: &egui::Context) {
    process_modal::render(app, ctx);
    memory_view::render(app, ctx);
    pointer_scanner::render(app, ctx);
    mono_modal::render(app, ctx);
    auto_assembler::render(app, ctx);
    lua_console::render(app, ctx);
    plugins_modal::render(app, ctx);
    address_modal::render(app, ctx);
    edit_byte_modal::render(app, ctx);
    settings_modal::render(app, ctx);
}
