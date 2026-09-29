//! Fixed synthetic lookup-only peer; never an installed application or CLI.
#[cfg(not(all(target_os = "macos", target_arch = "aarch64", debug_assertions,
    feature = "installed-observation", mrk_wrapping_keychain_qualification,
    mrk_wrapping_keychain_qualification_native)))]
compile_error!("private peer requires the exact nonshipping native qualification handshake");
fn main() {
    mrk_macos_installed_native::wrapping_keychain::private_pair::reader_entry();
}
