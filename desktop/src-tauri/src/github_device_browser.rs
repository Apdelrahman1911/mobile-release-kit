//! Fixed public device-page handoff only; never an authorization operation.
//! The shell owns the exact current session/revision/expiry admission and calls
//! outside document/registry locks. On macOS it uses the existing main-thread
//! route. No URL, code, token, browser handle, retry or session mutation enters
//! this adapter. A returned Ok means only that the OS accepted the handoff.

use crate::error::BridgeError;

pub(crate) fn open_fixed_device_page() -> Result<(), BridgeError> {
    if platform_handoff() {
        Ok(())
    } else {
        Err(BridgeError::unavailable(
            "The browser handoff was not confirmed. Open https://github.com/login/device manually.",
        ))
    }
}

#[cfg(all(feature = "desktop-shell", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn platform_handoff() -> bool {
    // Existing GTK/GIO dependency, synchronous documented OS handoff. Do not
    // expose the native error or use the async variant/another task-owned helper.
    gtk::gio::AppInfo::launch_default_for_uri(
        "https://github.com/login/device",
        None::<&gtk::gio::AppLaunchContext>,
    ).is_ok()
}

#[cfg(all(feature = "desktop-shell", target_os = "macos", target_arch = "aarch64"))]
fn platform_handoff() -> bool {
    mrk_macos_installed_native::open_fixed_github_device_page()
}

#[cfg(all(feature = "desktop-shell", target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
fn platform_handoff() -> bool {
    mrk_windows_installed_native::open_fixed_github_device_page()
}

#[cfg(not(any(
    all(feature = "desktop-shell", target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(feature = "desktop-shell", target_os = "macos", target_arch = "aarch64"),
    all(feature = "desktop-shell", target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
)))]
fn platform_handoff() -> bool { false }
