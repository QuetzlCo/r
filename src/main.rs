// Release: no console window. Debug: console stays for RUST_LOG output.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

extern crate native_windows_derive as nwd;
extern crate native_windows_gui as nwg;

mod app;
mod config;
mod encoding;
mod error;
mod parser;
mod postprocessor;
mod preprocessor;
mod processing;
mod validator;
mod writer;

use nwg::NativeUi;

fn main() {
    // Logger active only when RUST_LOG env var is set
    env_logger::init();

    nwg::init().expect("NWG init failed");
    nwg::Font::set_global_family("Tahoma").expect("Font set failed");

    let _ui = app::UlpApp::build_ui(Default::default())
        .expect("Failed to build UI");

    // Blocks here until window closes
    nwg::dispatch_thread_events();
}
