//! Transport-only disposable fixture; no ordinary application or SM authority.
#[unsafe(no_mangle)]
pub extern "C" fn mrk_desktop_image_entry_v1()->i32 {
    mrk_macos_installed_native::e2_transport_diagnostic::enter()
}
