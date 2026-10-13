//! Fixed, nonshipping native E2 fixture image. The existing installed facade
//! supplies the original main entry; there is no CLI/runtime selector.
#[unsafe(no_mangle)]
pub extern "C" fn mrk_desktop_image_entry_v1()->i32 {
    mrk_macos_installed_native::e2_native_fixture::enter()
}
