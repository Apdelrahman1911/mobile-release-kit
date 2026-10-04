//! Fixed cdylib install identity, never a renamed executable.
#[allow(dead_code)]
#[path = "../../src-tauri/src/macos_install_fixed_paths.rs"]
mod installed_paths;
fn main() {
    assert_eq!(std::env::var("TARGET").as_deref(), Ok("aarch64-apple-darwin"));
    println!("cargo:rerun-if-changed=../../src-tauri/src/macos_install_fixed_paths.rs");
    println!("cargo:rustc-link-arg-cdylib=-Wl,-install_name,{}", installed_paths::DESKTOP_IMAGE);
    println!("cargo:rustc-link-arg-cdylib=-mmacosx-version-min=26.0");
}
