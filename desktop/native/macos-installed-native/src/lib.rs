//! Small Darwin ABI boundary, not an operation owner or an execution permit.
//! The application retains its original slots/tasks and supplies every deadline.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(all(feature = "installed-observation", not(debug_assertions)))]
compile_error!("installed observation controls require debug assertions in an explicit instrumented build");
use std::{ffi::{c_char, c_int, c_void, CString}, io, marker::PhantomData,
    os::fd::{AsRawFd, BorrowedFd}, path::PathBuf, ptr::NonNull, rc::Rc};

unsafe extern "C" {
    fn mrk_platform() -> c_int;
    fn mrk_user(uid: *mut u32) -> c_int;
    fn mrk_acl_empty(fd: c_int, phase: *mut c_int, call_result: *mut c_int, native_errno: *mut c_int,
        free_result: *mut c_int, free_errno: *mut c_int) -> c_int;
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
    fn mrk_decode_directory_entries(block: *const u8, bytes: usize, count: c_int, out: *mut u8, capacity: usize, used: *mut usize) -> c_int;
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
/// Finite diagnostics from the same original ACL observation, not another query.
/// The actual errno (including0) stays separate from the returned fallback code.
pub struct AclFailure {
    pub phase: &'static str,
    pub call_result: i32,
    pub native_errno: i32,
    pub free_result: i32,
    pub free_errno: i32,
    pub refusal_code: Option<i32>,
    error: io::Error,
}
impl AclFailure { pub fn into_io_error(self) -> io::Error { self.error } }
pub fn empty_acl_observed(fd: BorrowedFd<'_>) -> Result<(), AclFailure> {
    let (mut phase, mut returned, mut observed_errno, mut freed, mut free_errno) = (0, 0, 0, 0, 0);
    // SAFETY: borrowed live FD and five distinct writable scalar cells. No
    // descriptor acquisition/consumption; native temporaries retire in that call.
    let code = unsafe { mrk_acl_empty(fd.as_raw_fd(), &mut phase, &mut returned, &mut observed_errno, &mut freed, &mut free_errno) };
    let name = match phase {
        1 => "filesec-allocation", 2 => "fstatx-snapshot", 3 => "snapshot-owner", 4 => "snapshot-group", 5 => "snapshot-mode",
        6 => "acl-presence", 7 => "acl-conversion", 8 => "acl-object", 9 => "acl-validation", 10 => "acl-first-entry",
        11 => "acl-entry-present", 12 => "acl-free", _ => "ffi-output",
    };
    if code == 0 && (phase, returned, observed_errno, freed, free_errno) == (0, 0, 0, 0, 0) { return Ok(()); }
    let consistent = code > 0 && phase >= 1 && phase <= 12 && observed_errno >= 0 && free_errno >= 0
        && (freed != 0 || free_errno == 0) && (phase != 12 || freed != 0)
        && (phase != 11 || (returned == 0 && observed_errno == 0));
    if consistent {
        Err(AclFailure { phase: name, call_result: returned, native_errno: observed_errno, free_result: freed, free_errno,
            refusal_code: Some(code), error: io::Error::from_raw_os_error(code) })
    } else {
        // Inconsistent FFI output is never accepted or described as a real errno.
        Err(AclFailure { phase: "ffi-output", call_result: 0, native_errno: 0, free_result: 0, free_errno: 0,
            refusal_code: None, error: io::ErrorKind::InvalidData.into() })
    }
}
pub fn empty_acl(fd: BorrowedFd<'_>) -> io::Result<()> {
    empty_acl_observed(fd).map_err(AclFailure::into_io_error)
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
pub struct Panel {
    original: NonNull<c_void>, unknown: bool, _main: PhantomData<Rc<()>>,
    #[cfg(feature = "installed-observation")]
    observation_identity_armed: bool,
    #[cfg(feature = "installed-observation")]
    observation_start: Option<observation::IdentityStartReturn>,
}
pub fn main_thread() -> bool { unsafe { mrk_main_thread() == 1 } }
impl Panel {
    pub fn reserve() -> io::Result<Self> {
        // SAFETY: native code enforces the main thread before allocating.
        let original = NonNull::new(unsafe { mrk_panel_reserve() }).ok_or(io::ErrorKind::Other)?;
        Ok(Self { original, unknown: false, _main: PhantomData,
            #[cfg(feature = "installed-observation")]
            observation_identity_armed: false,
            #[cfg(feature = "installed-observation")]
            observation_start: None,
        })
    }
    fn usable(&self) -> io::Result<()> {
        if self.unknown || !main_thread() { Err(io::ErrorKind::Other.into()) } else { Ok(()) }
    }
    pub fn start(&mut self, kind: PanelKind) -> io::Result<()> {
        #[cfg(feature = "installed-observation")]
        { self.observation_start = None; }
        self.usable()?;
        // SAFETY: retained opaque original, main-thread-only type. EPERM means
        // the native function observed no available parent before construction.
        let status = unsafe { mrk_panel_start(self.original.as_ptr(), match kind { PanelKind::Project => 1, PanelKind::Quit => 2 }) };
        #[cfg(feature = "installed-observation")]
        if self.observation_identity_armed {
            // This C call ACTUALLY returned. Copy saved scalars now, before the
            // unchanged unknown rule; never query AppKit to explain an error.
            self.observation_start = Some(observation::identity_start_return(self.original, status));
        }
        let result = result(status);
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

// The integration target's cfg(test) does not reach this dependency. Explicit
// nondefault feature forwarding selects BOTH this Rust seam and the C controls.
#[cfg(feature = "installed-observation")]
pub use observation::{PanelAction, PanelActionDiagnostic, PanelObservation, OpenIdentity, OpenDiagnostic, OpenReport,
    OpenInputReturn, IdentityConfiguration, IdentityStartReturn, IdentityBinding, IdentityBindingReturn, PanelConfirmProof,
    installed_accessibility_trusted, installed_observation_flags_data_check};
#[cfg(feature = "installed-observation")]
mod observation {
    use super::*;
    use std::{path::Path, panic::{catch_unwind, AssertUnwindSafe}, time::Instant};

    pub enum PanelAction<'a> {
        ProjectCancel,
        /// A caller-prebound synthetic directory, once per original panel.
        /// Navigation returning is NOT evidence that Open selected this path.
        ProjectDirectory(&'a Path),
        QuitCancel,
        QuitConfirm,
    }
    /// Closed labels copied from one original return, never a native query or
    /// action/finality permit. Missing/invalid DATA does not change that return.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PanelActionDiagnostic {
        pub action: &'static str, pub domain: &'static str,
        pub site: &'static str, pub error: &'static str,
    }
    fn action_name(action: c_int) -> Option<&'static str> {
        match action { 1 => Some("project-cancel"), 2 => Some("project-directory"), 3 => Some("project-open"),
            4 => Some("quit-cancel"), 5 => Some("quit-confirm"), _ => None }
    }
    // Same numbered sites and Darwin errno values as the feature-gated shim.
    // Code 3 remains historical diagnostic DATA only, never a callable action.
    // label, original native-return status (-1 = exception-only), action mask,
    // whether an EXISTING Objective-C query/action at this site can throw.
    const ACTION_SITES: [(&str, c_int, u8, bool); 35] = [
        ("main-thread", 22, 31, false), ("state-pointer", 22, 31, false),
        ("action-code", 22, 31, false), ("directory-argument", 22, 31, false),
        ("original-unknown", 5, 31, false), ("not-started", 1, 31, false),
        ("window-absent", 1, 31, false), ("parent-absent", 1, 31, false),
        ("completion-absent", 1, 31, false), ("responded", 1, 31, false),
        ("callback-active", 1, 31, false), ("close-attempted", 1, 31, false),
        ("closed", 1, 31, false), ("action-attempted", 1, 31, false),
        ("panel-kind", 1, 31, false), ("attachment", 35, 31, true),
        ("directory-already-bound", 1, 2, false), ("directory-path", 22, 2, false),
        ("directory-text", 22, 2, true), ("directory-url", 22, 2, true),
        ("directory-set", 0, 2, true), ("directory-unbound", 1, 4, false),
        ("directory-not-returned", 1, 4, false), ("directory-ready", 35, 4, true),
        ("alert-buttons", -1, 24, true), ("alert-absent", 1, 24, false),
        ("button-count", 1, 24, true), ("button-index", -1, 24, true),
        ("button-window", 1, 24, true), ("button-enabled", 35, 24, true),
        ("button-hidden", 35, 24, true), ("project-cancel", 0, 1, true),
        ("project-open", 0, 4, true), ("quit-cancel", 0, 8, true), ("quit-confirm", 0, 16, true),
    ];
    fn action_return_diagnostic(action: c_int, status: c_int, wire: u32) -> Option<PanelActionDiagnostic> {
        let action_label = action_name(action)?;
        let (site, expected, actions, exception) = *ACTION_SITES.get((wire & 0xffff).checked_sub(1)? as usize)?;
        if actions & (1u8 << (action - 1)) == 0 { return None; }
        let domain = match wire >> 16 {
            1 if expected >= 0 && status == expected => "native-return",
            2 if exception && status == 5 => "objc-exception",
            _ => return None,
        };
        let error = match status { 0 => "none", 1 => "permission-denied", 5 => "io",
            22 => "invalid-input", 35 => "would-block", _ => return None };
        Some(PanelActionDiagnostic { action: action_label, domain, site, error })
    }
    fn action_diagnostics_data_check() -> bool {
        // Inert decoder checks only. No Panel, exception, or native call exists.
        for action in 1..=5 {
            for (index, &(site, status, actions, exception)) in ACTION_SITES.iter().enumerate() {
                let applies = actions & (1u8 << (action - 1)) != 0;
                let wire = (index + 1) as u32;
                let native = action_return_diagnostic(action, status, 0x10000 | wire);
                let caught = action_return_diagnostic(action, 5, 0x20000 | wire);
                if native.is_some() != (applies && status >= 0) || caught.is_some() != (applies && exception)
                    || native.is_some_and(|d| d.site != site || d.action != action_name(action).unwrap() || d.domain != "native-return")
                    || caught.is_some_and(|d| d.error != "io" || d.domain != "objc-exception") { return false; }
                for bad in [wire, 0x30000 | wire, 0x80010000 | wire] {
                    if action_return_diagnostic(action, status, bad).is_some() { return false; }
                }
                if action_return_diagnostic(action, 999, 0x10000 | wire).is_some() { return false; }
            }
        }
        action_return_diagnostic(3, 5, 0x20021).is_some_and(|d| d.site == "project-open" && d.error == "io")
            && action_return_diagnostic(3, 0, 0x10021).is_some_and(|d| d.error == "none")
            && action_return_diagnostic(3, 35, 0x10018).is_some_and(|d| d.error == "would-block")
            && [0, 6, -1].into_iter().all(|action| action_return_diagnostic(action, 5, 0x20021).is_none())
            && [0, 0x10000, 0x10024, u32::MAX].into_iter().all(|wire| action_return_diagnostic(3, 5, wire).is_none())
    }
    pub struct PanelObservation {
        pub kind: PanelKind,
        pub started: bool,
        pub attached: bool,
        pub parent_present: bool,
        pub panel_present: bool,
        pub parent_references_panel: Option<bool>,
        pub panel_references_parent: Option<bool>,
        pub panel_visible: Option<bool>,
        pub directory_bound: bool,
        pub directory_returned: bool,
        pub directory_ready: bool,
        pub action_attempted: bool,
        pub action_returned: bool,
        pub callback_returned: bool,
        pub response: Option<PanelResponse>,
        /// Only the original native completion writes this selected path.
        pub selected: Option<PathBuf>,
        pub close_attempted: bool,
        pub dismissed: bool,
        pub closed: bool,
    }
    unsafe extern "C" {
        fn mrk_panel_observe(panel: *mut c_void, kind: *mut c_int, flags: *mut u32,
            response: *mut c_int, path: *mut u8, capacity: usize) -> c_int;
        fn mrk_panel_observe_action(panel: *mut c_void, action: c_int, directory: *const c_char,
            diagnostic: *mut u32) -> c_int;
        fn mrk_observation_ax_trusted() -> c_int;
        fn mrk_panel_observe_arm_open_identity(panel: *mut c_void) -> c_int;
        fn mrk_panel_observe_identity_data(panel: *mut c_void, data: *mut IdentityWire);
        fn mrk_panel_observe_open_identity(panel: *mut c_void, parent: *mut u8, sheet: *mut u8, capacity: usize) -> c_int;
        fn mrk_panel_observe_confirm(panel: *mut c_void, parent: *const u8, sheet: *const u8, capacity: usize,
            admission: unsafe extern "C" fn(*mut c_void, c_int) -> c_int,
            context: *mut c_void, result: *mut OpenWire);
    }
    /// Original copied identity only; no native object leaves its main owner.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct OpenIdentity { parent: [u8; 64], panel: [u8; 64] }
    fn identity_tag(bytes: &[u8; 64], prefix: &[u8]) -> bool {
        let end = prefix.len() + 36;
        bytes.starts_with(prefix) && bytes[end..].iter().all(|byte| *byte == 0)
            && bytes[prefix.len()..end].iter().enumerate().all(|(i, byte)|
                if [8, 13, 18, 23].contains(&i) { *byte == b'-' } else { byte.is_ascii_hexdigit() })
    }
    fn identity_actual(bytes: &[u8; 64]) -> bool {
        let Some(end) = bytes.iter().position(|b| *b == 0).filter(|end| *end > 0) else { return false; };
        bytes[end..].iter().all(|b| *b == 0) && std::str::from_utf8(&bytes[..end]).is_ok()
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OpenDiagnostic { pub site: &'static str, pub error: &'static str }
    const OPEN_ERRORS: [&str; 16] = ["none", "wrong-thread", "invalid-input", "ineligible", "unsupported", "ambiguous",
        "malformed", "limit", "deadline", "custody", "not-triggered", "reserved", "reserved", "changed",
        "objc-exception", "cleanup-unknown"];
    #[repr(C)]
    #[derive(Clone, Copy, Default, PartialEq, Eq)]
    struct IdentityProofWire {
        flags: u32, checked: u32, matched: u32, parent: u32, panel: u32, children: u32,
        originals: u32, site: u32, error: u32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default, PartialEq, Eq)]
    struct ConfirmProofWire { flags: u32, checked: u32, matched: u32, site: u32, error: u32 }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct IdentityWire {
        flags: u32, parent: u32, site: u32, error: u32,
        binding: IdentityProofWire,
    }
    const IDENTITY_CLASSES: [Option<&str>; 5] = [None, Some("nil"), Some("match"), Some("different"), Some("type-invalid")];
    const IDENTITY_SITES: [Option<&str>; 6] = [None, Some("objects"), Some("parent-tag"), Some("parent-set"),
        Some("parent-get"), Some("complete")];
    const PANEL_ID_CLASSES: [Option<&str>; 10] = [None, Some("nil"), Some("type-invalid"), Some("empty"),
        Some("byte-limit"), Some("nul"), Some("encoding-invalid"), Some("valid"), Some("match"), Some("different")];
    const PROOF_SITES: [&str; 14] = ["objects", "attachment", "directory", "parent-identifier", "panel-identifier",
        "parent-sheets", "panel-sheets", "panel-attached-sheet", "native-children", "native-parent", "native-role",
        "stable-identifier", "final-eligibility", "complete"];
    const CONFIRM_SITES: [&str; 6] = ["objects", "open-panel", "capability", "confirm-allowed", "stable-original", "complete"];
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PanelConfirmProof {
        pub attempted: bool,
        pub checks: [Option<bool>; 5], pub site: &'static str, pub error: &'static str,
    }
    impl PanelConfirmProof {
        pub fn matched(self) -> bool {
            self.attempted && self.checks == [Some(true); 5]
                && self.site == "complete" && self.error == "none"
        }
    }
    fn confirm_proof(w: ConfirmProofWire) -> Option<PanelConfirmProof> {
        if w.flags != 1 || w.checked & !31 != 0 || w.matched & !w.checked != 0
            || w.checked & 1 == 0 || w.checked & (w.checked + 1) != 0 || matches!(w.error, 11 | 12 | 15) { return None; }
        let d = PanelConfirmProof { attempted: true,
            checks: std::array::from_fn(|i| (w.checked & (1 << i) != 0).then_some(w.matched & (1 << i) != 0)),
            site: *CONFIRM_SITES.get(w.site.checked_sub(1)? as usize)?, error: *OPEN_ERRORS.get(w.error as usize)?,
        };
        if (d.site == "complete") != (d.error == "none")
            || d.error == "none" && !d.matched() { return None; }
        for bit in 1..5 {
            if w.checked & (1 << bit) != 0 && w.matched & ((1 << bit) - 1) != (1 << bit) - 1 { return None; }
        }
        Some(d)
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct IdentityConfiguration {
        pub attempted: bool, pub parent_setter_entered: bool, pub parent_setter_returned: bool,
        pub parent: Option<&'static str>,
        pub site: Option<&'static str>, pub error: Option<&'static str>,
    }
    impl IdentityConfiguration {
        pub fn complete(self) -> bool {
            self.attempted && self.parent_setter_entered && self.parent_setter_returned
                && self.parent.is_some() && self.site == Some("complete") && self.error == Some("none")
        }
    }
    /// Exists only after the original C start returns; an invalid scalar frame
    /// is missing DATA, never permission to change that original return.
    #[derive(Clone, Copy)]
    pub struct IdentityStartReturn { pub result: &'static str, pub configuration: Option<IdentityConfiguration> }
    impl IdentityStartReturn {
        pub fn succeeded(self) -> bool { self.result == "ok" && self.configuration.is_some_and(IdentityConfiguration::complete) }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct IdentityBinding {
        pub attempted: bool, pub parent: Option<&'static str>, pub panel: Option<&'static str>,
        pub checks: [Option<bool>; 12], pub children: Option<u32>, pub originals: Option<&'static str>,
        pub site: &'static str, pub error: &'static str,
    }
    impl IdentityBinding {
        pub fn matched(self) -> bool {
            self.attempted && self.parent == Some("match") && self.panel == Some("match")
                && self.checks == [Some(true); 12] && self.children.is_some_and(|n| (1..=16).contains(&n))
                && self.originals == Some("one") && self.site == "complete" && self.error == "none"
        }
    }
    #[derive(Clone, Copy)]
    pub struct IdentityBindingReturn { pub configuration: IdentityConfiguration, pub binding: IdentityBinding }
    fn identity_configuration(w: IdentityWire) -> Option<IdentityConfiguration> {
        if w.flags & !31 != 0 || w.flags & 1 == 0 { return None; }
        let parent = *IDENTITY_CLASSES.get(w.parent as usize)?;
        let c = IdentityConfiguration {
            attempted: w.flags & 2 != 0, parent_setter_entered: w.flags & 4 != 0, parent_setter_returned: w.flags & 8 != 0,
            parent, site: *IDENTITY_SITES.get(w.site as usize)?,
            error: (w.flags & 2 != 0).then_some(*OPEN_ERRORS.get(w.error as usize)?),
        };
        if !c.attempted {
            return (w.flags == 1 && w.site == 0 && w.error == 0 && parent.is_none()).then_some(c);
        }
        let valid = match (w.site, w.error) {
            (1, 3) | (2, 2 | 14) => w.flags == 3 && parent.is_none(),
            (3, 14) => w.flags == 7 && parent.is_none(),
            (4, 14) => w.flags == 15 && parent.is_none(),
            (5, 0) => w.flags == 31 && c.complete(),
            _ => false,
        };
        valid.then_some(c)
    }
    pub(super) fn identity_start_return(original: NonNull<c_void>, status: c_int) -> IdentityStartReturn {
        let mut wire = IdentityWire::default();
        // SAFETY: immediate original-return copy; this opaque cell is retained
        // on EVERY start return. No Objective-C query or ownership operation.
        unsafe { mrk_panel_observe_identity_data(original.as_ptr(), &mut wire); }
        let result = match status { 0 => "ok", 1 => "permission-denied", 5 => "io", 22 => "invalid-input", 37 => "already", _ => "other" };
        let configuration = identity_configuration(wire).filter(|c|
            wire.binding == IdentityProofWire::default() && (status != 0 || c.complete()));
        IdentityStartReturn { result, configuration }
    }
    fn identity_proof(status: c_int, w: IdentityProofWire) -> Option<IdentityBinding> {
        if c_int::try_from(w.error).ok() != Some(status) || w.flags & !1 != 0 || w.checked & !0xfff != 0
            || w.matched & !w.checked != 0 || w.children > 18 { return None; }
        let b = IdentityBinding {
            attempted: w.flags == 1, parent: *IDENTITY_CLASSES.get(w.parent as usize)?,
            panel: *PANEL_ID_CLASSES.get(w.panel as usize)?,
            checks: std::array::from_fn(|i| (w.checked & (1 << i) != 0).then_some(w.matched & (1 << i) != 0)),
            children: w.children.checked_sub(1),
            originals: *[None, Some("zero"), Some("one"), Some("multiple")].get(w.originals as usize)?,
            site: *PROOF_SITES.get(w.site.checked_sub(1)? as usize)?, error: *OPEN_ERRORS.get(w.error as usize)?,
        };
        if !b.attempted {
            return (w.checked == 0 && w.matched == 0 && w.parent == 0 && w.panel == 0
                && w.children == 0 && w.originals == 0 && b.site == "objects" && b.error == "custody").then_some(b);
        }
        // First-value validity remains true on this exact later stability
        // failure. The final class is diagnostic, never a new binding.
        let stable_change = w.checked == 0x7ff && w.matched == 0x3ff
            && b.site == "stable-identifier" && b.error == "changed"
            && matches!(b.panel, Some("nil" | "type-invalid" | "empty" | "byte-limit" | "nul" | "encoding-invalid" | "different"));
        if w.checked & 1 == 0 || b.checks[3] == Some(true) && b.parent != Some("match")
            || b.checks[4] == Some(true) && !matches!(b.panel, Some("valid" | "match")) && !stable_change
            || b.checks[7] == Some(true) && !(b.children.is_some_and(|n| (1..=16).contains(&n)) && b.originals == Some("one"))
            || b.checks[10] == Some(true) && b.panel != Some("match")
            || (b.site == "complete") != (b.error == "none") || b.error == "none" && !b.matched() { return None; }
        Some(b)
    }
    fn identity_binding_return(status: c_int, w: IdentityWire) -> Option<IdentityBindingReturn> {
        let configuration = identity_configuration(w)?;
        if !configuration.complete() { return None; }
        Some(IdentityBindingReturn { configuration, binding: identity_proof(status, w.binding)? })
    }
    fn identity_data_check() -> bool {
        // Inert scalar DATA only: no panel/owner/native call or return is made.
        let empty = IdentityWire { flags: 1, ..IdentityWire::default() };
        if !identity_configuration(empty).is_some_and(|c| !c.attempted && !c.complete() && c.parent.is_none())
            || identity_configuration(IdentityWire::default()).is_some() { return false; }
        for parent in 1..=4 {
            let configured = IdentityWire { flags: 31, parent, site: 5, ..IdentityWire::default() };
            if !identity_configuration(configured).is_some_and(IdentityConfiguration::complete) { return false; }
        }
        for (flags, site) in [(3, 2), (7, 3), (15, 4)] {
            let partial = IdentityWire { flags, site, error: 14, ..IdentityWire::default() };
            if !identity_configuration(partial).is_some_and(|c| !c.complete())
                || identity_configuration(IdentityWire { parent: 2, ..partial }).is_some() { return false; }
        }
        let proof = IdentityProofWire { flags: 1, checked: 0xfff, matched: 0xfff, parent: 2, panel: 8,
            children: 2, originals: 2, site: 14, error: 0 };
        if !identity_proof(0, proof).is_some_and(IdentityBinding::matched) { return false; }
        // Every exact native edge, singleton and no-nested check is mandatory.
        for bit in 0..12 {
            let missing = IdentityProofWire { checked: proof.checked & !(1 << bit), matched: proof.matched & !(1 << bit), ..proof };
            if identity_proof(0, missing).is_some() { return false; }
            let changed = IdentityProofWire { matched: proof.matched & !(1 << bit), site: 13, error: 13, ..proof };
            if identity_proof(13, changed).is_some_and(IdentityBinding::matched) { return false; }
        }
        for bad in [IdentityProofWire { panel: 7, ..proof }, IdentityProofWire { parent: 3, ..proof },
            IdentityProofWire { children: 18, ..proof }, IdentityProofWire { originals: 3, ..proof },
            IdentityProofWire { flags: 3, ..proof }, IdentityProofWire { checked: 0x1fff, ..proof }] {
            if identity_proof(0, bad).is_some() { return false; }
        }
        for panel in [1, 2, 3, 4, 5, 6, 9] {
            let changed = IdentityProofWire { checked: 0x7ff, matched: 0x3ff, panel, site: 12, error: 13, ..proof };
            if !identity_proof(13, changed).is_some_and(|b|
                b.checks[4] == Some(true) && b.checks[10] == Some(false) && !b.matched())
                || identity_proof(13, IdentityProofWire { site: 5, ..changed }).is_some()
                || identity_proof(4, IdentityProofWire { error: 4, ..changed }).is_some()
                || identity_proof(13, IdentityProofWire { checked: 0xfff, ..changed }).is_some() { return false; }
        }
        let configured = IdentityWire { flags: 31, parent: 2, site: 5, binding: proof, ..IdentityWire::default() };
        let early = IdentityProofWire { flags: 1, checked: 1, matched: 0, site: 1, error: 3, ..IdentityProofWire::default() };
        identity_binding_return(0, configured).is_some_and(|r| r.binding.matched())
            && identity_binding_return(14, configured).is_none()
            && identity_binding_return(0, IdentityWire { binding: IdentityProofWire::default(), ..configured }).is_none()
            && identity_binding_return(3, IdentityWire { binding: early, ..configured }).is_some_and(|r| !r.binding.matched())
            && identity_configuration(IdentityWire { flags: 63, ..configured }).is_none()
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct OpenWire { flags: u32, site: u32, error: u32, initial_proof: IdentityProofWire, proof: IdentityProofWire,
        eligibility: ConfirmProofWire, recheck: ConfirmProofWire }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OpenReport {
        pub diagnostic: OpenDiagnostic, pub attempted: bool, pub confirm_returned: bool,
        pub triggered: Option<bool>, pub custody_known: bool,
        pub initial_proof: Option<IdentityBinding>, pub proof: Option<IdentityBinding>,
        pub eligibility: Option<PanelConfirmProof>, pub recheck: Option<PanelConfirmProof>,
    }
    impl OpenReport {
        pub fn succeeded(self) -> bool {
            self.attempted && self.confirm_returned && self.triggered == Some(true) && self.custody_known
                && self.initial_proof.is_some_and(IdentityBinding::matched) && self.proof.is_some_and(IdentityBinding::matched)
                && self.eligibility.is_some_and(PanelConfirmProof::matched) && self.recheck.is_some_and(PanelConfirmProof::matched)
                && self.diagnostic == OpenDiagnostic { site: "confirm", error: "none" }
        }
    }
    fn open_return(w: OpenWire) -> Option<OpenReport> {
        if w.flags & !15 != 0 || matches!(w.error, 11 | 12 | 15) { return None; }
        let initial_proof = if w.initial_proof == IdentityProofWire::default() { None }
            else { Some(identity_proof(c_int::try_from(w.initial_proof.error).ok()?, w.initial_proof)?) };
        let eligibility = if w.eligibility == ConfirmProofWire::default() { None } else { Some(confirm_proof(w.eligibility)?) };
        let proof = if w.proof == IdentityProofWire::default() { None }
            else { Some(identity_proof(c_int::try_from(w.proof.error).ok()?, w.proof)?) };
        let recheck = if w.recheck == ConfirmProofWire::default() { None } else { Some(confirm_proof(w.recheck)?) };
        let r = OpenReport { diagnostic: OpenDiagnostic {
            site: *["entry", "confirm-eligibility", "original-proof", "confirm-recheck", "admission", "confirm", "initial-original-proof"]
                .get(w.site.checked_sub(1)? as usize)?,
            error: *OPEN_ERRORS.get(w.error as usize)?, },
            attempted: w.flags & 1 != 0, confirm_returned: w.flags & 2 != 0,
            triggered: (w.flags & 2 != 0).then_some(w.flags & 4 != 0), custody_known: w.flags & 8 != 0,
            initial_proof, proof, eligibility, recheck };
        if w.flags & 4 != 0 && !r.confirm_returned || r.confirm_returned && !r.attempted
            || r.attempted && (!recheck.is_some_and(PanelConfirmProof::matched) || r.diagnostic.site != "confirm")
            || recheck.is_some() && !proof.is_some_and(IdentityBinding::matched)
            || proof.is_some() && !eligibility.is_some_and(PanelConfirmProof::matched)
            || eligibility.is_some() && !initial_proof.is_some_and(IdentityBinding::matched)
            || matches!(w.error, 9 | 14) && r.custody_known
            || w.error == 10 && r.triggered != Some(false)
            || r.confirm_returned && r.triggered == Some(false) && !matches!(w.error, 9 | 10)
            || w.error == 0 && !r.succeeded() { return None; }
        for (site, error) in [("initial-original-proof", initial_proof.map(|p| p.error)),
            ("confirm-eligibility", eligibility.map(|p| p.error)), ("original-proof", proof.map(|p| p.error)),
            ("confirm-recheck", recheck.map(|p| p.error))] {
            if r.diagnostic.site == site && error != Some(r.diagnostic.error) { return None; }
        }
        Some(r)
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OpenInputReturn { pub entered: bool, pub report: Option<OpenReport>, pub custody_known: bool }
    struct OpenAdmission<'a, F> { end: Instant, admit: &'a mut F, custody_known: bool }
    unsafe extern "C" fn open_admission<F: FnMut(bool) -> Option<bool>>(context: *mut c_void, after: c_int) -> c_int {
        // The callback is synchronous and borrowed only for the original FFI.
        let context = unsafe { &mut *context.cast::<OpenAdmission<'_, F>>() };
        let checked = catch_unwind(AssertUnwindSafe(|| {
            if !matches!(after, 0 | 1) { context.custody_known = false; return 9; }
            let Some(allowed) = (context.admit)(after == 1) else { context.custody_known = false; return 9; };
            if Instant::now() >= context.end { return 8; }
            if !allowed { return 3; } 0
        }));
        match checked { Ok(code) => code, Err(payload) => { context.custody_known = false; std::mem::forget(payload); 9 } }
    }
    pub fn installed_accessibility_trusted() -> Result<bool, ()> {
        match unsafe { mrk_observation_ax_trusted() } { 1 => Some(true), -1 => None, 0 => Some(false), _ => None }.ok_or(())
    }
    fn semantic_data_check() -> bool {
        // Inert decoders only: these values never manufacture native evidence.
        if std::mem::size_of::<IdentityWire>() != 52 || std::mem::size_of::<OpenWire>() != 124
            || std::mem::size_of::<ConfirmProofWire>() != 20 { return false; }
        let d = ConfirmProofWire { flags: 1, checked: 31, matched: 31, site: 6, error: 0 };
        let p = IdentityProofWire { flags: 1, checked: 0xfff, matched: 0xfff, parent: 2, panel: 8,
            children: 2, originals: 2, site: 14, error: 0 };
        let full = OpenWire { flags: 15, site: 6, error: 0, initial_proof: p, proof: p, eligibility: d, recheck: d };
        if !open_return(full).is_some_and(OpenReport::succeeded) { return false; }
        for flags in 0..32 {
            if open_return(OpenWire { flags, ..full }).is_some_and(OpenReport::succeeded) != (flags == 15) { return false; }
        }
        for bit in 0..5 {
            if confirm_proof(ConfirmProofWire { checked: d.checked & !(1 << bit), matched: d.matched & !(1 << bit), ..d }).is_some()
                || open_return(OpenWire { recheck: ConfirmProofWire { matched: d.matched & !(1 << bit), ..d }, ..full }).is_some() { return false; }
        }
        let unsupported = ConfirmProofWire { flags: 1, checked: 7, matched: 3, site: 3, error: 4 };
        let disallowed = ConfirmProofWire { flags: 1, checked: 15, matched: 7, site: 4, error: 3 };
        let changed = ConfirmProofWire { flags: 1, checked: 31, matched: 15, site: 5, error: 9 };
        let late = OpenWire { error: 8, ..full };
        open_return(OpenWire { flags: 8, site: 2, error: 4, initial_proof: p, eligibility: unsupported, ..OpenWire::default() })
                .is_some_and(|r| !r.attempted && r.custody_known && r.eligibility.is_some_and(|d| d.checks[2] == Some(false)))
            && open_return(OpenWire { flags: 8, site: 2, error: 3, initial_proof: p, eligibility: disallowed, ..OpenWire::default() })
                .is_some_and(|r| !r.attempted && r.custody_known)
            && open_return(OpenWire { flags: 8, site: 4, error: 3, recheck: disallowed, ..full })
                .is_some_and(|r| !r.attempted && r.custody_known && !r.succeeded())
            && open_return(OpenWire { flags: 0, site: 4, error: 9, recheck: changed, ..full })
                .is_some_and(|r| !r.attempted && !r.custody_known)
            && open_return(OpenWire { flags: 11, error: 10, ..full }).is_some_and(|r| r.triggered == Some(false) && !r.succeeded())
            && open_return(OpenWire { flags: 1, error: 14, ..full }).is_some_and(|r| r.attempted && !r.confirm_returned && !r.custody_known)
            && open_return(late).is_some_and(|r| r.confirm_returned && r.triggered == Some(true) && !r.succeeded())
            && open_return(OpenWire { flags: 15, error: 14, ..full }).is_none()
            && open_return(OpenWire { proof: IdentityProofWire::default(), ..full }).is_none()
            && open_return(OpenWire { initial_proof: IdentityProofWire::default(), ..full }).is_none()
            && open_return(OpenWire { flags: 7, error: 9, ..full }).is_some_and(|r| r.confirm_returned && !r.custody_known && !r.succeeded())
            && open_return(OpenWire { flags: 8, site: 2, error: 4, eligibility: unsupported, ..OpenWire::default() }).is_none()
            && open_return(OpenWire { eligibility: unsupported, ..full }).is_none()
            && confirm_proof(ConfirmProofWire { flags: 3, ..d }).is_none()
            && confirm_proof(ConfirmProofWire { checked: 63, matched: 63, ..d }).is_none()
            && open_return(OpenWire { site: 0, ..full }).is_none()
    }
    fn observation_flags_valid(flags: u32) -> bool {
        let both_present = flags & 0x3000 == 0x3000;
        flags & !0x1ffff == 0 && (flags & 2 != 0) == (flags & 0x1f000 == 0x1f000)
            && (both_present || flags & 0xc000 == 0)
            && (flags & 0x2000 != 0 || flags & 0x10000 == 0)
    }
    /// Pure checks called by the existing instrumented observer entry, not a
    /// native query or a separate test executable/qualification route.
    pub fn installed_observation_flags_data_check() -> bool {
        action_diagnostics_data_check() && identity_data_check() && semantic_data_check()
            && [0, 0x1000, 0x2000, 0x12000, 0x3000, 0xf000, 0x1f002, 0x1ffff]
            .into_iter().all(observation_flags_valid)
            && [2, 0x4000, 0x8000, 0x10000, 0x14000, 0x1f000, 0x20000, u32::MAX]
                .into_iter().all(|flags| !observation_flags_valid(flags))
    }
    impl Panel {
        pub fn installed_arm_open_identity(&mut self) -> io::Result<()> {
            self.usable()?;
            if self.observation_identity_armed { return Err(io::ErrorKind::Other.into()); }
            // SAFETY: fresh retained original. The C arm writes a scalar only.
            let returned = result(unsafe { mrk_panel_observe_arm_open_identity(self.original.as_ptr()) });
            if returned.is_ok() { self.observation_identity_armed = true; } else { self.unknown = true; }
            returned
        }
        pub fn take_installed_identity_start_return(&mut self) -> Option<IdentityStartReturn> {
            self.observation_start.take() // Rust DATA only, including an original failed start.
        }
        pub fn installed_open_identity(&mut self, returned: &mut Option<IdentityBindingReturn>) -> Result<OpenIdentity, OpenDiagnostic> {
            *returned = None;
            self.usable().map_err(|_| OpenDiagnostic { site: "binding", error: "ineligible" })?;
            let mut identity = OpenIdentity { parent: [0; 64], panel: [0; 64] };
            // SAFETY: exact retained main-thread original; copied identity DATA.
            let status = unsafe { mrk_panel_observe_open_identity(self.original.as_ptr(), identity.parent.as_mut_ptr(),
                identity.panel.as_mut_ptr(), identity.parent.len()) };
            let mut wire = IdentityWire::default();
            unsafe { mrk_panel_observe_identity_data(self.original.as_ptr(), &mut wire); }
            *returned = identity_binding_return(status, wire);
            if status == 0 && returned.is_some_and(|r| r.binding.matched()) && identity_tag(&identity.parent, b"mrk-parent-")
                && identity_actual(&identity.panel) && identity.parent != identity.panel { return Ok(identity); }
            if returned.is_none() || status == 0 || matches!(status, 9 | 14 | 15) || !(1..16).contains(&status) { self.unknown = true; }
            Err(OpenDiagnostic { site: "binding", error: usize::try_from(status).ok().filter(|s| *s != 0)
                .and_then(|s| OPEN_ERRORS.get(s)).copied().unwrap_or("malformed") })
        }
        pub fn installed_panel_confirm<F: FnMut(bool) -> Option<bool>>(&mut self, identity: &OpenIdentity,
            end: Instant, mut admit: F) -> OpenInputReturn {
            let mut returned = OpenInputReturn { entered: false, report: None, custody_known: false };
            if self.usable().is_err() || !identity_tag(&identity.parent, b"mrk-parent-")
                || !identity_actual(&identity.panel) || identity.parent == identity.panel { return returned; }
            let mut context = OpenAdmission { end, admit: &mut admit, custody_known: true };
            let mut wire = OpenWire::default(); returned.entered = true;
            // SAFETY: main-only original Panel; synchronous scoped callback;
            // all original-panel/Objective-C custody stays in that same Panel.
            unsafe { mrk_panel_observe_confirm(self.original.as_ptr(), identity.parent.as_ptr(), identity.panel.as_ptr(),
                identity.parent.len(), open_admission::<F>, (&mut context as *mut OpenAdmission<'_, F>).cast(), &mut wire); }
            returned.report = open_return(wire);
            returned.custody_known = context.custody_known && returned.report.is_some_and(|r| r.custody_known);
            if !returned.custody_known { self.unknown = true; }
            returned
        }
        pub fn installed_observation(&mut self) -> io::Result<PanelObservation> {
            self.usable()?;
            let mut kind = 0; let mut flags = 0; let mut response = 0; let mut path = [0u8; 4097];
            // SAFETY: same retained main-thread original and exact writable
            // DATA cells. Unlike poll, this neither consumes nor adds a fact.
            let status = unsafe { mrk_panel_observe(self.original.as_ptr(), &mut kind, &mut flags,
                &mut response, path.as_mut_ptr(), path.len()) };
            if let Err(error) = result(status) { self.unknown = true; return Err(error); }
            let parsed = (|| {
                let kind = match kind { 1 => PanelKind::Project, 2 => PanelKind::Quit,
                    _ => return Err(io::Error::from(io::ErrorKind::InvalidData)) };
                if !observation_flags_valid(flags) { return Err(io::ErrorKind::InvalidData.into()); }
                let parent_present = flags & 0x1000 != 0; let panel_present = flags & 0x2000 != 0;
                let end = path.iter().position(|byte| *byte == 0).ok_or(io::ErrorKind::InvalidData)?;
                let selected = if end == 0 { None } else { std::str::from_utf8(&path[..end]).ok().map(PathBuf::from) };
                let response = if flags & 128 != 0 { Some(panel_response(response)?) } else { None };
                Ok(PanelObservation { kind, started: flags & 1 != 0, attached: flags & 2 != 0,
                    parent_present, panel_present,
                    parent_references_panel: (parent_present && panel_present).then_some(flags & 0x4000 != 0),
                    panel_references_parent: (parent_present && panel_present).then_some(flags & 0x8000 != 0),
                    panel_visible: panel_present.then_some(flags & 0x10000 != 0),
                    directory_bound: flags & 4 != 0, directory_returned: flags & 8 != 0,
                    directory_ready: flags & 16 != 0, action_attempted: flags & 32 != 0,
                    action_returned: flags & 64 != 0, callback_returned: flags & 256 != 0,
                    response, selected, close_attempted: flags & 512 != 0,
                    dismissed: flags & 1024 != 0, closed: flags & 2048 != 0 })
            })();
            if parsed.is_err() { self.unknown = true; } parsed
        }
        /// false means a not-yet-ready sheet/directory/button was observed
        /// BEFORE any action. true means only the actual action call returned;
        /// the real callback and original coordinator still own all outcomes.
        pub fn installed_action(&mut self, action: PanelAction<'_>, diagnostic: &mut Option<PanelActionDiagnostic>) -> io::Result<bool> {
            *diagnostic = None; // Never expose a previous action's diagnostic.
            let name = match &action { PanelAction::ProjectCancel => "project-cancel",
                PanelAction::ProjectDirectory(_) => "project-directory",
                PanelAction::QuitCancel => "quit-cancel", PanelAction::QuitConfirm => "quit-confirm" };
            if let Err(error) = self.usable() {
                *diagnostic = Some(PanelActionDiagnostic { action: name, domain: "rust-precondition",
                    site: "original-usability", error: "other" });
                return Err(error);
            }
            let (code, directory) = match action {
                PanelAction::ProjectCancel => (1, None),
                PanelAction::ProjectDirectory(path) => {
                    let text = path.to_str().ok_or(io::ErrorKind::InvalidInput).map_err(|error| {
                        *diagnostic = Some(PanelActionDiagnostic { action: name, domain: "rust-precondition",
                            site: "directory-utf8", error: "invalid-input" }); error
                    })?;
                    if !path.is_absolute() || text.len() > 4096 || text.split('/').skip(1)
                        .any(|part| part.is_empty() || part == "." || part == "..") {
                        *diagnostic = Some(PanelActionDiagnostic { action: name, domain: "rust-precondition",
                            site: "directory-path", error: "invalid-input" });
                        return Err(io::ErrorKind::InvalidInput.into());
                    }
                    (2, Some(CString::new(text).map_err(|_| {
                        *diagnostic = Some(PanelActionDiagnostic { action: name, domain: "rust-precondition",
                            site: "directory-cstring", error: "invalid-input" }); io::ErrorKind::InvalidInput
                    })?))
                }
                PanelAction::QuitCancel => (4, None),
                PanelAction::QuitConfirm => (5, None),
            };
            // SAFETY: same retained main-thread original; optional bounded
            // CString lives through the call and is copied once by the shim.
            // The initialized writable diagnostic belongs to THIS call only.
            let mut wire = 0u32;
            let status = unsafe { mrk_panel_observe_action(self.original.as_ptr(), code,
                directory.as_ref().map_or(std::ptr::null(), |path| path.as_ptr()), &mut wire) };
            *diagnostic = action_return_diagnostic(code, status, wire);
            match result(status) {
                Ok(()) => Ok(true),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
                // These native refusals promise no action was attempted.
                Err(error) if matches!(error.kind(), io::ErrorKind::InvalidInput | io::ErrorKind::PermissionDenied) => Err(error),
                Err(error) => { self.unknown = true; Err(error) }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bulk_directory_records_preserve_full_ids_and_refuse_malformed_batches() {
        // Literal public Darwin packed DATA: length, returned attributes,
        // name reference, object type, full64-bit FILEID, name and padding.
        // In particular FILEID starts at offset36, not a C-struct offset40.
        fn record(kind: u32, inode: u64, name: &[u8]) -> Vec<u8> {
            let length = (44 + name.len() + 1 + 3) & !3;
            let mut bytes = vec![0; length];
            bytes[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
            bytes[4..8].copy_from_slice(&0x8200_0009u32.to_ne_bytes());
            bytes[24..28].copy_from_slice(&20i32.to_ne_bytes());
            bytes[28..32].copy_from_slice(&((name.len() + 1) as u32).to_ne_bytes());
            bytes[32..36].copy_from_slice(&kind.to_ne_bytes());
            bytes[36..44].copy_from_slice(&inode.to_ne_bytes());
            bytes[44..44 + name.len()].copy_from_slice(name);
            bytes
        }
        fn decode(bytes: &[u8], count: i32, capacity: usize) -> (i32, usize, Vec<u8>) {
            let mut output = vec![0u8; 65536];
            let mut used = usize::MAX;
            // SAFETY: live input/output allocations, capacities no larger
            // than their actual allocations. This pure parser opens nothing.
            let code = unsafe { mrk_decode_directory_entries(bytes.as_ptr(), bytes.len(), count,
                output.as_mut_ptr(), capacity, &mut used) };
            assert!(used <= output.len());
            output.truncate(used);
            (code, used, output)
        }
        let directory = record(2, 0x1_0000_0001, b"dir");
        let file = record(1, 0x2_0000_0002, b"file");
        assert_eq!(file.len(), 52); // Legal4-byte final short-fit, not mandatory8.
        let mut block = [directory.clone(), file.clone()].concat();
        let mut expected = Vec::new();
        for (inode, kind, name) in [(0x1_0000_0001u64, 4u8, b"dir".as_slice()),
                                    (0x2_0000_0002u64, 8u8, b"file".as_slice())] {
            expected.extend_from_slice(&inode.to_ne_bytes()); expected.push(kind);
            expected.extend_from_slice(&(name.len() as u16).to_ne_bytes()); expected.extend_from_slice(name);
        }
        assert_eq!(decode(&block, 2, 65536), (0, expected.len(), expected.clone()));
        block.resize(65536, 0); // Native API returns count, not filled byte length.
        assert_eq!(decode(&block, 2, 65536), (0, expected.len(), expected));
        assert_eq!(decode(&block, 0, 65536), (0, 0, Vec::new()));
        // Extra legal alignment padding after the name remains outside attr_length.
        let mut padded = file.clone(); padded.resize(56, 0); padded[..4].copy_from_slice(&56u32.to_ne_bytes());
        assert_eq!(decode(&padded, 1, 65536).0, 0);
        for (bytes, count, capacity) in [(&directory[..directory.len()-1], 1, 65536),
            (&directory[..], -1, 65536), (&directory[..], 2, 65536),
            (&directory[..], i32::MAX, 65536), (&directory[..], 1, 13)] {
            let (code, used, _) = decode(bytes, count, capacity);
            assert_ne!(code, 0); assert_eq!(used, 0);
        }
        let mutations: &[(usize, &[u8])] = &[
            (0, &0u32.to_ne_bytes()), (0, &47u32.to_ne_bytes()), (0, &65536u32.to_ne_bytes()),
            (4, &0x8000_0001u32.to_ne_bytes()), (4, &0x8200_000bu32.to_ne_bytes()),
            (8, &1u32.to_ne_bytes()), (12, &1u32.to_ne_bytes()),
            (16, &1u32.to_ne_bytes()), (20, &1u32.to_ne_bytes()),
            (24, &(-1i32).to_ne_bytes()), (24, &4i32.to_ne_bytes()), (24, &i32::MAX.to_ne_bytes()),
            (28, &1u32.to_ne_bytes()), (28, &257u32.to_ne_bytes()), (28, &256u32.to_ne_bytes()),
            (32, &5u32.to_ne_bytes()), (36, &0u64.to_ne_bytes()),
            (44, b"/"), (45, b"\0"), (47, b"x"),
        ];
        for &(offset, replacement) in mutations {
            let mut invalid = directory.clone();
            invalid[offset..offset + replacement.len()].copy_from_slice(replacement);
            // One good prefix cannot turn a malformed second record into a
            // partial successful inventory (used must remain zero).
            let batch = [file.clone(), invalid].concat();
            let (code, used, _) = decode(&batch, 2, 65536);
            assert_ne!(code, 0, "offset={offset}"); assert_eq!(used, 0);
        }
    }
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
