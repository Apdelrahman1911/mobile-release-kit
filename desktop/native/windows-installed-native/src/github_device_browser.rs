//! Fixed public device-page handoff on the caller's current thread.
//! Session/revision/expiry admission and main-thread routing belong to the
//! existing shell, outside document/registry locks. No process handle, worker,
//! completion callback or browser lifetime is imported into the task owner.

use std::mem::size_of;
use std::ptr::null;
use windows_sys::Win32::System::Com::{
    CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
};
use windows_sys::Win32::UI::Shell::{
    ShellExecuteExW, SHELLEXECUTEINFOW, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

// Exactly "https://github.com/login/device" plus NUL; never a caller argument.
const DEVICE_PAGE: [u16; 32] = [
    104, 116, 116, 112, 115, 58, 47, 47, 103, 105, 116, 104, 117, 98, 46, 99,
    111, 109, 47, 108, 111, 103, 105, 110, 47, 100, 101, 118, 105, 99, 101, 0,
];
const OPEN: [u16; 5] = [111, 112, 101, 110, 0];

/// True is only the actual synchronous OS handoff acceptance. False is not
/// proof that no browser action occurred. Never retry or authenticate here.
pub fn open_fixed_github_device_page() -> bool {
    let mut request = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        // Finish the Shell/DDE handoff before returning this stack frame. No
        // process-handle request, input-idle wait, user-data argument or error UI.
        fMask: SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: OPEN.as_ptr(),
        lpFile: DEVICE_PAGE.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };
    // SAFETY: null reserved input, documented flags on THIS caller thread.
    // A conflicting apartment refuses; it does not create an STA worker.
    let initialized = unsafe {
        CoInitializeEx(null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32)
    };
    if initialized < 0 { return false; }
    // S_OK and S_FALSE both require one matching CoUninitialize. Any other
    // nonnegative return is conservatively refused after balancing that success.
    let accepted = if initialized == 0 || initialized == 1 {
        // SAFETY: exact locked Windows binding/size, zeroed unused fields, static
        // NUL-terminated fixed strings; NOASYNC retains no task stack callback.
        unsafe { ShellExecuteExW(&mut request) != 0 }
    } else { false };
    // SAFETY: exactly this successful initialization, same thread, after the
    // synchronous handoff returned. It does not close/stop the user's browser.
    unsafe { CoUninitialize() };
    accepted
}
