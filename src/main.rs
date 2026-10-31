#![windows_subsystem = "windows"]

mod app;
mod checksums;
mod export;
mod gpg;
mod hash;
mod shell;
mod signature;
mod store;
mod virustotal;
mod worker;

use eframe::egui;
use std::path::PathBuf;

fn main() -> eframe::Result {
    let paths: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    let icon = egui::IconData {
        rgba: include_bytes!("../assets/icon64.rgba").to_vec(),
        width: 64,
        height: 64,
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Empreinte")
            .with_inner_size([1000.0, 720.0])
            .with_min_inner_size([760.0, 520.0])
            .with_drag_and_drop(true)
            .with_icon(icon),
        ..Default::default()
    };
    eframe::run_native(
        "Empreinte",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, paths)))),
    )
}
