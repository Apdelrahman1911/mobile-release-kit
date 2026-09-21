//! Small Darwin ABI boundary, not an operation owner or an execution permit.
//! The application retains its original slots/tasks and supplies every deadline.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::{ffi::{c_char, c_int, c_void, CString}, io, marker::PhantomData,
    os::fd::{AsRawFd, BorrowedFd}, path::PathBuf, ptr::NonNull, rc::Rc};

unsafe extern "C" {
    fn mrk_platform() -> c_int;
    fn mrk_user(uid: *mut u32) -> c_int;
    fn mrk_acl_empty(fd: c_int) -> c_int;
    fn mrk_no_xattrs(fd: c_int) -> c_int;
    fn mrk_entries(fd: c_int, bytes: *mut u8, capacity: usize, used: *mut usize) -> c_int;
    fn mrk_sync(fd: c_int, file: c_int) -> c_int;
    fn mrk_publish(from: c_int, source: *const c_char, to: c_int, destination: *const c_char) -> c_int;
    fn mrk_panel_reserve() -> *mut c_void;
    fn mrk_panel_start(panel: *mut c_void, kind: c_int) -> c_int;
    fn mrk_panel_poll(panel: *mut c_void, result: *mut c_int, path: *mut u8, capacity: usize) -> c_int;
    fn mrk_panel_close(panel: *mut c_void) -> c_int;
    fn mrk_panel_release(panel: *mut c_void) -> c_int;
    fn mrk_main_thread() -> c_int;
    #[cfg(test)]
    fn mrk_panel_response(kind: c_int, code: i64, programmatic: c_int) -> c_int;
}
fn result(code: c_int) -> io::Result<()> { if code == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(code)) } }
pub fn platform() -> io::Result<()> {
    // SAFETY: fixed uname/sysctl observation with no input pointers or handles.
    result(unsafe { mrk_platform() })
}
pub fn real_user() -> io::Result<u32> {
    let mut uid = 0;
    // SAFETY: fixed writable result cell; the shim validates the actual kernel/user.
    result(unsafe { mrk_user(&mut uid) })?; Ok(uid)
}
pub fn empty_acl(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: borrowed live descriptor; no ownership transfer or new descriptor.
    result(unsafe { mrk_acl_empty(fd.as_raw_fd()) })
}
pub fn no_xattrs(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: borrowed live descriptor, metadata only.
    result(unsafe { mrk_no_xattrs(fd.as_raw_fd()) })
}
pub fn directory_block(fd: BorrowedFd<'_>, buffer: &mut [u8]) -> io::Result<usize> {
    if buffer.len() != 65536 { return Err(io::ErrorKind::InvalidInput.into()); }
    let mut used = 0;
    // SAFETY: exact bounded writable buffer, live directory descriptor; shim
    // checks every native record before serializing. No dup/fdopendir custody.
    result(unsafe { mrk_entries(fd.as_raw_fd(), buffer.as_mut_ptr(), buffer.len(), &mut used) })?;
    if used > buffer.len() { return Err(io::ErrorKind::InvalidData.into()); } Ok(used)
}
pub fn sync(fd: BorrowedFd<'_>, file: bool) -> io::Result<()> {
    // SAFETY: borrowed original; no descriptor consumption.
    result(unsafe { mrk_sync(fd.as_raw_fd(), i32::from(file)) })
}
pub fn publish_directory(from: BorrowedFd<'_>, source: &str, to: BorrowedFd<'_>, destination: &str) -> io::Result<()> {
    fn component(value: &str) -> io::Result<CString> {
        if value.is_empty() || value.len() > 255 || value == "." || value == ".." || value.contains('/') {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        CString::new(value).map_err(|_| io::ErrorKind::InvalidInput.into())
    }
    let source = component(source)?; let destination = component(destination)?;
    // SAFETY: original directory descriptors and NUL-terminated single names.
    // The C call always uses RENAME_EXCL; never an overwrite-capable fallback.
    result(unsafe { mrk_publish(from.as_raw_fd(), source.as_ptr(), to.as_raw_fd(), destination.as_ptr()) })
}

#[derive(Clone, Copy)]
pub enum PanelKind { Project, Quit }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PanelResponse { Accept, Decline, Other }
fn panel_response(code: c_int) -> io::Result<PanelResponse> {
    match code { 1 => Ok(PanelResponse::Accept), 2 => Ok(PanelResponse::Decline), 0 => Ok(PanelResponse::Other),
        _ => Err(io::ErrorKind::InvalidData.into()) }
}
pub enum PanelState { Showing, Responded { response: PanelResponse, path: Option<PathBuf> }, Closed }
/// Main-thread-only original. Drop deliberately does not stand in for native
/// close/release finality: an unresolved object is retained, never retried.
pub struct Panel { original: NonNull<c_void>, unknown: bool, _main: PhantomData<Rc<()>> }
pub fn main_thread() -> bool { unsafe { mrk_main_thread() == 1 } }
impl Panel {
    pub fn reserve() -> io::Result<Self> {
        // SAFETY: native code enforces the main thread before allocating.
        let original = NonNull::new(unsafe { mrk_panel_reserve() }).ok_or(io::ErrorKind::Other)?;
        Ok(Self { original, unknown: false, _main: PhantomData })
    }
    fn usable(&self) -> io::Result<()> {
        if self.unknown || !main_thread() { Err(io::ErrorKind::Other.into()) } else { Ok(()) }
    }
    pub fn start(&mut self, kind: PanelKind) -> io::Result<()> {
        self.usable()?;
        // SAFETY: retained opaque original, main-thread-only type. EPERM means
        // the native function observed no available parent before construction.
        let result = result(unsafe { mrk_panel_start(self.original.as_ptr(), match kind { PanelKind::Project => 1, PanelKind::Quit => 2 }) });
        if result.as_ref().is_err_and(|error| error.kind() != io::ErrorKind::PermissionDenied) { self.unknown = true; }
        result
    }
    pub fn poll(&mut self) -> io::Result<PanelState> {
        self.usable()?;
        let mut result_code = 0; let mut path = [0u8; 4097];
        // SAFETY: retained object and bounded writable result buffers.
        let state = unsafe { mrk_panel_poll(self.original.as_ptr(), &mut result_code, path.as_mut_ptr(), path.len()) };
        match state {
            0 => Ok(PanelState::Showing),
            1 => {
                let Some(end) = path.iter().position(|b| *b == 0) else {
                    self.unknown = true; return Err(io::ErrorKind::InvalidData.into());
                };
                // A non-UTF-8 choice is not a source-path capability. Returning
                // no path lets Rust refuse it while closing the known panel;
                // it is not a fabricated native Cancel or cleanup Unknown.
                let path = if end == 0 { None } else { std::str::from_utf8(&path[..end]).ok().map(PathBuf::from) };
                let response = match panel_response(result_code) {
                    Ok(response) => response,
                    Err(error) => { self.unknown = true; return Err(error); }
                };
                Ok(PanelState::Responded { response, path })
            }
            2 => Ok(PanelState::Closed),
            _ => { self.unknown = true; Err(io::ErrorKind::Other.into()) },
        }
    }
    pub fn close_once(&mut self) -> io::Result<()> {
        self.usable()?;
        // SAFETY: original retained main-thread object; native call is one-use.
        let result = result(unsafe { mrk_panel_close(self.original.as_ptr()) });
        if result.is_err() { self.unknown = true; } result
    }
    pub fn release(mut self) -> Result<(), Self> {
        if self.usable().is_err() { return Err(self); }
        // SAFETY: the shim refuses before freeing unless original completion
        // returned, dismissal is observed and our exact references can retire.
        if unsafe { mrk_panel_release(self.original.as_ptr()) } == 0 { Ok(()) }
        else { self.unknown = true; Err(self) } // Never dereference a failed-release original again.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_explicit_user_appkit_responses_can_be_accept_or_decline() {
        // Calls the SAME pure C classifier used by the real completion. These
        // definitions construct no NSWindow, fake callback or native permit.
        for (kind, code, expected) in [
            (1, 1, PanelResponse::Accept), (1, 0, PanelResponse::Decline),
            (2, 1001, PanelResponse::Accept), (2, 1000, PanelResponse::Decline),
            (1, -1000, PanelResponse::Other), (1, -1001, PanelResponse::Other),
            (1, 1000, PanelResponse::Other), (2, 0, PanelResponse::Other),
            (2, -1000, PanelResponse::Other), (2, -1001, PanelResponse::Other),
            (2, 1002, PanelResponse::Other), (2, i64::MAX, PanelResponse::Other),
            (1, i64::MIN, PanelResponse::Other), (0, 0, PanelResponse::Other),
        ] {
            // SAFETY: fixed primitive DATA into a pure classifier, no handles
            // or AppKit construction and no ownership transfer.
            let actual = unsafe { mrk_panel_response(kind, code, 0) };
            assert_eq!(panel_response(actual).ok(), Some(expected));
            let programmatic = unsafe { mrk_panel_response(kind, code, 1) };
            assert_eq!(panel_response(programmatic).ok(), Some(PanelResponse::Other));
        }
        assert!(panel_response(-1).is_err());
        assert!(panel_response(3).is_err());
    }
}
