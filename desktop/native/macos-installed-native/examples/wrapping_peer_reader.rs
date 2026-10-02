//! Fixed synthetic lookup-only peer; never an installed application or CLI.
#[cfg(not(all(target_os = "macos", target_arch = "aarch64", debug_assertions,
    feature = "installed-observation", mrk_wrapping_keychain_qualification,
    mrk_wrapping_keychain_qualification_native)))]
compile_error!("private helper requires the exact nonshipping native qualification handshake");
use std::sync::atomic::{AtomicBool, Ordering};
static ACTIVE: AtomicBool = AtomicBool::new(false);
// The library/observer/libtest has no definition and cannot activate this role.
// This exported function reads only the one-shot state privately held by main.
#[unsafe(no_mangle)]
pub extern "C" fn mrk_wrapping_private_process_role() -> u32 {
    if ACTIVE.load(Ordering::Acquire) { 2 } else { 0 }
}
fn main() {
    let entry = std::time::Instant::now(); // Original10s child clock starts here.
    assert_eq!(std::env::args_os().len(), 1, "private reader accepts no arguments");
    assert!(!ACTIVE.swap(true, Ordering::AcqRel), "private reader is single-use");
    mrk_macos_installed_native::wrapping_keychain::private_pair::reader_entry(entry);
}
