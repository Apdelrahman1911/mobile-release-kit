//! Fixed cdylib install identity, never a renamed executable.
#[allow(dead_code)]
#[path = "../../src-tauri/src/macos_install_fixed_paths.rs"]
mod installed_paths;
fn main() {
    let target = std::env::var("TARGET").expect("Cargo target required");
    assert!(matches!(target.as_str(), "aarch64-apple-darwin" | "x86_64-apple-darwin"));
    assert_eq!(std::env::var("CARGO_CFG_TARGET_OS").as_deref(), Ok("macos"));
    assert_eq!(std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH").as_deref(), Ok("64"));
    println!("cargo:rerun-if-changed=../../src-tauri/src/macos_install_fixed_paths.rs");
    println!("cargo:rustc-link-arg-cdylib=-Wl,-install_name,{}", installed_paths::DESKTOP_IMAGE);
    println!("cargo:rustc-link-arg-cdylib=-mmacosx-version-min=26.0");
}
