//! Fixed Installer entry; source and lifecycle admission stay in the native
//! boundary. This desktop crate continues to forbid unsafe FFI.
#[cfg(any(
    feature = "desktop-shell",
    feature = "macos-installed-installer",
    feature = "macos-installed-remover",
    feature = "macos-android-registration-helper",
    feature = "macos-package-producer",
    feature = "macos-remove-producer",
    feature = "macos-installed-observation",
    feature = "macos-installed-app-absence-fixture"
))]
compile_error!("setup executable requires its exclusive graph");
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
fn main() {
    std::process::exit(mrk_macos_installed_native::xcode_setup_entry());
}
#[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
fn main() {
    std::process::exit(78);
}
