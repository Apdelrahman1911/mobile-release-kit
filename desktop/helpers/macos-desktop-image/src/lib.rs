//! The one fixed ordinary C image entry. No release engine or alternate UI.
#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
compile_error!("the ordinary installed image requires macOS ARM64");
#[cfg(not(panic = "unwind"))]
compile_error!("the image ABI requires unwind containment, never panic=abort");

/// Called only by the fixed libSystem facade AFTER its actual original SH.
/// Symbol export is confined to this tiny crate; the application remains
/// unsafe_code=forbid and exposes a safe SAME-builder seam only.
#[no_mangle]
pub extern "C" fn mrk_desktop_image_entry_v1() -> i32 {
    match std::panic::catch_unwind(mobile_release_desktop::shell::run_installed_image) {
        Ok(Ok(())) => 0,
        Ok(Err(_)) => 1,
        Err(payload) => {
            // Dropping an arbitrary panic payload can panic a second time.
            // Preserve unknown custody; never unwind through C or force exit.
            let _retained = std::mem::ManuallyDrop::new(payload);
            loop { std::thread::park_timeout(std::time::Duration::from_secs(1)); }
        }
    }
}
