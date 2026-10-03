//! One ordinary main-thread inherited-gate admission. The original descriptor
//! stays in the native process-lifetime cell; this API cannot unlock or close it.
//! It is not a maintenance, credential, worker-finality or test-coverage permit.
use std::{io, path::Path};
#[path = "../../../src-tauri/src/macos_install_fixed_paths.rs"]
mod paths;
unsafe extern "C" {
    fn mrk_installed_entry_admit(descriptor: i32, entry_pid: i32) -> i32;
    fn mrk_installed_entry_retained() -> i32;
}
fn canonical(value: &std::ffi::OsStr, minimum: i32) -> Option<i32> {
    let text = value.to_str()?;
    if text.is_empty() || text.len() > 10 || text.starts_with('0') || !text.bytes().all(|c| c.is_ascii_digit()) { return None; }
    text.parse::<i32>().ok().filter(|n| *n >= minimum)
}
pub fn admit_once() -> io::Result<()> {
    let invalid = || io::Error::from(io::ErrorKind::PermissionDenied);
    // A missing/untrusted argument is never turned into descriptor ownership.
    // In particular no close, dup, gate reacquisition or fallback occurs here.
    let mut args = std::env::args_os();
    args.next().ok_or_else(invalid)?;
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--mrk-installed-entry-v1")) { return Err(invalid()); }
    let fd = canonical(&args.next().ok_or_else(invalid)?, 3).ok_or_else(invalid)?;
    let pid = canonical(&args.next().ok_or_else(invalid)?, 2).ok_or_else(invalid)?;
    if args.next().is_some() || std::env::current_exe()? != Path::new(paths::PAYLOAD_EXECUTABLE) { return Err(invalid()); }
    // SAFETY: bounded scalar arguments only. C admits real main/account/PID and
    // the exact inherited descriptor against protected named originals before
    // retaining it. It does not consume or close an unadmitted argument's FD.
    let result = unsafe { mrk_installed_entry_admit(fd, pid) };
    if result != 0 { return Err(io::Error::from_raw_os_error(result)); }
    // SAFETY: inert current-process/main-thread state; no handle or permit.
    if unsafe { mrk_installed_entry_retained() } != 1 { return Err(invalid()); }
    Ok(())
}
