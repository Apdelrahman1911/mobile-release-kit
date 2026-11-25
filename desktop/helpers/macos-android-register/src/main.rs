#![forbid(unsafe_code)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() { std::process::exit(mobile_release_desktop::android_registration_helper::run()); }
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() { std::process::exit(2); }
