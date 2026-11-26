#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#[cfg(feature = "macos-installed-desktop-image")]
compile_error!("the ordinary image must be built from its separate cdylib adapter, never this bin");
#[cfg(not(feature = "macos-installed-desktop-image"))]
fn main() -> std::process::ExitCode {
    match mobile_release_desktop::shell::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => std::process::ExitCode::FAILURE,
    }
}
