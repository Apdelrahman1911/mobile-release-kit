//! Fixed source build selection shared by app, one-shot Installer and observers.
#[path = "macos_install_fixed_paths.rs"]
mod fixed;
pub use fixed::*;
include!(concat!(env!("OUT_DIR"), "/mrk-macos-build-release.rs"));
#[cfg(test)]
#[path = "macos_build_release.rs"]
mod build_release;
pub const PROTOCOL_SHA: &str = "083e6afae3e329c4e0d81bad00dd0c9920f77491b38ce0d23aa602996f4c4bf5";
pub fn runtime_root() -> std::path::PathBuf { std::path::Path::new(INSTALL_ROOT).join("versions").join(RELEASE).join("runtime") }
