//! Fixed release selection DATA shared by the app and one-shot Installer.
pub const INSTALL_ROOT: &str = "/Library/Application Support/MobileReleaseKit";
pub const RELEASE: &str = "macos26-arm64-project-draft-01";
pub const APP_NAME: &str = "Mobile Release Kit.app";
pub const APP: &str = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app";
pub const PROTOCOL_SHA: &str = "860d1cee0072730a487ac8e632206c69e3ba676cab849b144a61755c4b84e41e";
pub fn runtime_root() -> std::path::PathBuf { std::path::Path::new(INSTALL_ROOT).join("versions").join(RELEASE).join("runtime") }
