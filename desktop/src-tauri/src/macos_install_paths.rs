//! Fixed release selection DATA shared by the app and one-shot Installer.
pub const INSTALL_ROOT: &str = "/Library/Application Support/MobileReleaseKit";
pub const PACKAGE_ID: &str = "dev.mobile-release-kit.desktop.installed";
pub const FIXTURE_PACKAGE_ID: &str = "dev.mobile-release-kit.desktop.installed-fixture";
pub const PACKAGE_VERSION: &str = "0.1.0";
pub const BUNDLE_ID: &str = "dev.mobile-release-kit.desktop";
pub const RELEASE: &str = "macos26-arm64-project-draft-01";
pub const APP_NAME: &str = "Mobile Release Kit.app";
pub const APP: &str = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app";
pub const PROTOCOL_SHA: &str = "083e6afae3e329c4e0d81bad00dd0c9920f77491b38ce0d23aa602996f4c4bf5";
pub fn runtime_root() -> std::path::PathBuf { std::path::Path::new(INSTALL_ROOT).join("versions").join(RELEASE).join("runtime") }
