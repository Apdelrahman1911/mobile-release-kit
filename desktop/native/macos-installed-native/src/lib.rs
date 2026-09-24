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
    OpenInputReturn, OpenRecheckReturn, ControlContainerButtonProof, RowSelectionProof, RowSelectionLimit, installed_prompt_button,
    IdentityConfiguration, IdentityStartReturn, IdentityBinding, IdentityBindingReturn,
    OriginalWindowState, OriginalWindowReturn, installed_original_window,
    installed_accessibility_trusted, installed_observation_flags_data_check};
#[cfg(feature = "installed-observation")]
mod observation {
    use super::*;
    use std::{path::Path, os::unix::ffi::OsStrExt, panic::{catch_unwind, AssertUnwindSafe}, time::{Duration, Instant}};

    pub enum PanelAction<'a> {
        ProjectCancel,
        /// Immutable fixture-root target, once per original panel. Native
        /// preparation browses its parent; navigation is NOT selection proof.
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
        fn mrk_observation_original_window(original: usize, flags: *mut u32) -> c_int;
        fn mrk_panel_observe(panel: *mut c_void, kind: *mut c_int, flags: *mut u32,
            response: *mut c_int, path: *mut u8, capacity: usize) -> c_int;
        fn mrk_panel_observe_action(panel: *mut c_void, action: c_int, directory: *const c_char,
            diagnostic: *mut u32) -> c_int;
        fn mrk_observation_ax_trusted() -> c_int;
        fn mrk_panel_observe_arm_open_identity(panel: *mut c_void) -> c_int;
        fn mrk_panel_observe_identity_data(panel: *mut c_void, data: *mut IdentityWire);
        fn mrk_panel_observe_open_identity(panel: *mut c_void, parent: *mut u8, sheet: *mut u8,
            prompt: *mut u8, capacity: usize, target: *mut u8, target_capacity: usize) -> c_int;
        fn mrk_panel_observe_open_recheck(panel: *mut c_void, parent: *const u8, sheet: *const u8,
            prompt: *const u8, target: *const u8, target_capacity: usize, stage: u32, result: *mut RecheckWire);
        fn mrk_observation_prompt_press(parent: *const u8, sheet: *const u8, prompt: *const u8, capacity: usize,
            target: *const u8, target_capacity: usize,
            admission: unsafe extern "C" fn(*mut c_void, u64, c_int, *mut OpenTimeout) -> c_int,
            recheck: unsafe extern "C" fn(*mut c_void, c_int) -> c_int,
            context: *mut c_void, result: *mut OpenWire);
    }
    /// Original copied identity only; no native object leaves its main owner.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct OpenIdentity { parent: [u8; 64], panel: [u8; 64], prompt: [u8; 8], target: [u8; 4097] }
    impl OpenIdentity {
        fn valid(self) -> bool {
            identity_tag(&self.parent, b"mrk-parent-") && identity_actual(&self.panel) && self.parent != self.panel
                && self.prompt.starts_with(b"MRK") && self.prompt[7] == 0
                && self.prompt[3..7].iter().zip(&self.parent[11..15]).all(|(p, b)| *p == b.to_ascii_uppercase())
                && selection_target(&self.target)
        }
        pub fn targets(&self, path: &Path) -> bool { selection_target(&self.target) && path.as_os_str().as_bytes() == self.target.split(|b| *b == 0).next().unwrap_or(&[]) }
    }
    fn selection_target(bytes: &[u8; 4097]) -> bool {
        let Some(end) = bytes.iter().position(|b| *b == 0).filter(|end| *end > 1) else { return false; };
        bytes[0] == b'/' && bytes[end..].iter().all(|b| *b == 0) && std::str::from_utf8(&bytes[..end]).is_ok()
            && bytes[1..end].split(|b| *b == b'/').all(|part| !part.is_empty() && part.len() <= 255 && part != b"." && part != b"..")
    }
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
        "malformed", "limit", "deadline", "custody", "invalid-element", "cannot-complete", "ax-other", "changed",
        "objc-exception", "cleanup-unknown"];
    #[repr(C)]
    #[derive(Clone, Copy, Default, PartialEq, Eq)]
    struct IdentityProofWire {
        flags: u32, checked: u32, matched: u32, parent: u32, panel: u32, children: u32,
        originals: u32, site: u32, error: u32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct IdentityWire {
        flags: u32, parent: u32, prompt: u32, site: u32, error: u32,
        binding: IdentityProofWire,
    }
    const IDENTITY_CLASSES: [Option<&str>; 5] = [None, Some("nil"), Some("match"), Some("different"), Some("type-invalid")];
    const IDENTITY_SITES: [Option<&str>; 8] = [None, Some("objects"), Some("parent-tag"), Some("parent-set"),
        Some("parent-get"), Some("complete"), Some("prompt-set"), Some("prompt-get")];
    const PANEL_ID_CLASSES: [Option<&str>; 10] = [None, Some("nil"), Some("type-invalid"), Some("empty"),
        Some("byte-limit"), Some("nul"), Some("encoding-invalid"), Some("valid"), Some("match"), Some("different")];
    const PROOF_SITES: [&str; 14] = ["objects", "attachment", "directory", "parent-identifier", "panel-identifier",
        "parent-sheets", "panel-sheets", "panel-attached-sheet", "native-children", "native-parent", "native-role",
        "stable-identifier", "final-eligibility", "complete"];
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct IdentityConfiguration {
        pub attempted: bool, pub parent_setter_entered: bool, pub parent_setter_returned: bool,
        pub prompt_setter_entered: bool, pub prompt_setter_returned: bool,
        pub parent: Option<&'static str>, pub prompt: Option<&'static str>,
        pub site: Option<&'static str>, pub error: Option<&'static str>,
    }
    impl IdentityConfiguration {
        pub fn complete(self) -> bool {
            self.attempted && self.parent_setter_entered && self.parent_setter_returned
                && self.prompt_setter_entered && self.prompt_setter_returned && self.prompt == Some("match")
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
        if w.flags & !127 != 0 || w.flags & 1 == 0 { return None; }
        let parent = *IDENTITY_CLASSES.get(w.parent as usize)?;
        let prompt = *IDENTITY_CLASSES.get(w.prompt as usize)?;
        let c = IdentityConfiguration {
            attempted: w.flags & 2 != 0, parent_setter_entered: w.flags & 4 != 0, parent_setter_returned: w.flags & 8 != 0,
            prompt_setter_entered: w.flags & 32 != 0, prompt_setter_returned: w.flags & 64 != 0,
            parent, prompt, site: *IDENTITY_SITES.get(w.site as usize)?,
            error: (w.flags & 2 != 0).then_some(*OPEN_ERRORS.get(w.error as usize)?),
        };
        if !c.attempted {
            return (w.flags == 1 && w.site == 0 && w.error == 0 && parent.is_none() && prompt.is_none()).then_some(c);
        }
        let valid = match (w.site, w.error) {
            (1, 3) | (2, 2 | 14) => w.flags == 3 && parent.is_none() && prompt.is_none(),
            (3, 14) => w.flags == 7 && parent.is_none() && prompt.is_none(),
            (4, 14) => w.flags == 15 && parent.is_none() && prompt.is_none(),
            (6, 14) => w.flags == 47 && parent.is_some() && prompt.is_none(),
            (7, 14) => w.flags == 111 && parent.is_some() && prompt.is_none(),
            (7, 13) => w.flags == 111 && parent.is_some() && matches!(prompt, Some("nil" | "different" | "type-invalid")),
            (5, 0) => w.flags == 127 && c.complete(),
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
            let configured = IdentityWire { flags: 127, parent, prompt: 2, site: 5, ..IdentityWire::default() };
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
        let configured = IdentityWire { flags: 127, parent: 2, prompt: 2, site: 5, binding: proof, ..IdentityWire::default() };
        let early = IdentityProofWire { flags: 1, checked: 1, matched: 0, site: 1, error: 3, ..IdentityProofWire::default() };
        identity_binding_return(0, configured).is_some_and(|r| r.binding.matched())
            && identity_binding_return(14, configured).is_none()
            && identity_binding_return(0, IdentityWire { binding: IdentityProofWire::default(), ..configured }).is_none()
            && identity_binding_return(3, IdentityWire { binding: early, ..configured }).is_some_and(|r| !r.binding.matched())
            && identity_configuration(IdentityWire { flags: 255, ..configured }).is_none()
            && identity_configuration(IdentityWire { prompt: 3, ..configured }).is_none()
            && identity_configuration(IdentityWire { flags: 31, ..configured }).is_none()
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct OpenWire { flags: u32, site: u32, error: u32, checks: u32, calls: u32,
        initial_nodes_examined: u32, recheck_nodes_examined: u32, owned: u32, released: u32, ax_error: i32,
        last_role: u32, last_depth: u32, selection_checks: u32, selection_flags: u32, selection_nodes_examined: u32,
        selection_limit_queued: u32, selection_limit_count: i64 }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct RecheckWire { known: u32, error: u32, prompt: u32, proof: IdentityProofWire, selected_target: u32 }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OpenRecheckReturn {
        pub stage: u32, pub custody_known: bool, pub error: &'static str, pub selected_target: Option<&'static str>,
        pub prompt: Option<bool>, pub proof: Option<IdentityBinding>,
    }
    impl OpenRecheckReturn {
        pub fn matched(self) -> bool {
            self.custody_known && self.error == "none" && self.prompt == Some(true)
                && self.proof.is_some_and(IdentityBinding::matched)
                && matches!((self.stage, self.selected_target), (1, None) | (2, Some("match")))
        }
    }
    fn recheck_return(w: RecheckWire, stage: u32) -> Option<OpenRecheckReturn> {
        if !(1..=2).contains(&stage) || w.known > 1 || w.prompt > 2 || matches!(w.error, 10..=12 | 15)
            || stage == 1 && w.selected_target != 0 { return None; }
        let proof = if w.proof == IdentityProofWire::default() { None }
            else { Some(identity_proof(c_int::try_from(w.proof.error).ok()?, w.proof)?) };
        let selected_target = *[None, Some("entered-not-returned"), Some("not-ready"), Some("match"),
            Some("different"), Some("malformed"), Some("multiple")].get(w.selected_target as usize)?;
        let r = OpenRecheckReturn { stage, custody_known: w.known == 1, error: *OPEN_ERRORS.get(w.error as usize)?, selected_target,
            prompt: match w.prompt { 1 => Some(true), 2 => Some(false), _ => None }, proof };
        if r.prompt.is_some() && !proof.is_some_and(IdentityBinding::matched)
            || selected_target.is_some() && r.prompt != Some(true)
            || w.error == 0 && !r.matched() || w.error == 13 && r.prompt == Some(true) && selected_target != Some("different")
            || matches!(w.error, 9 | 14) && r.custody_known
            || !matches!(w.error, 9 | 14) && !r.custody_known
            || proof.is_none() && !matches!(w.error, 9 | 14)
            || proof.is_some_and(|p| p.error != "none") && proof.map(|p| p.error) != Some(r.error) { return None; }
        if let Some(selected) = selected_target {
            let allowed = match selected {
                "entered-not-returned" => w.error == 14,
                "not-ready" => matches!(w.error, 3 | 9 | 14),
                "match" => matches!(w.error, 0 | 3 | 9 | 14),
                "different" => matches!(w.error, 13 | 9 | 14),
                "malformed" => matches!(w.error, 6 | 9 | 14),
                "multiple" => matches!(w.error, 5 | 9 | 14),
                _ => false,
            };
            if !allowed { return None; }
        }
        Some(r)
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RowSelectionLimit {
        pub role: &'static str, pub depth: u32, pub count: i64, pub queued_nodes: u32,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RowSelectionProof {
        pub checks: [bool; 3], pub nodes_examined: u32,
        pub attempted: bool, pub returned: bool, pub setter_succeeded: Option<bool>,
        pub limit: Option<RowSelectionLimit>,
    }
    impl RowSelectionProof {
        pub fn matched(self) -> bool {
            self.checks == [true; 3] && (2..=48).contains(&self.nodes_examined)
                && self.attempted && self.returned && self.setter_succeeded == Some(true)
                && self.limit.is_none()
        }
    }
    /// Finite actual AX/CF DATA from the one original worker. A retired slot is
    /// either a definite empty out-slot or its CFRelease actually returned;
    /// these counters deliberately do not claim that many non-null objects.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ControlContainerButtonProof {
        pub checks: [bool; 7], pub calls: u32, pub initial_nodes_examined: u32, pub recheck_nodes_examined: u32,
        pub last_role: &'static str, pub last_depth: u32,
        pub cf_slots: u32, pub cf_slots_retired: u32, pub cleanup_returned: bool, pub ax_error: i32,
    }
    impl ControlContainerButtonProof {
        pub fn matched(self) -> bool {
            self.checks == [true; 7] && (1..=512).contains(&self.calls)
                && (1..=16).contains(&self.initial_nodes_examined) && (1..=16).contains(&self.recheck_nodes_examined)
                && self.last_role == "Button" && (1..=8).contains(&self.last_depth)
                && self.last_depth <= self.initial_nodes_examined.min(self.recheck_nodes_examined)
                && (1..=256).contains(&self.cf_slots) && self.cf_slots_retired == self.cf_slots
                && self.cleanup_returned && self.ax_error == 0
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OpenReport {
        pub diagnostic: OpenDiagnostic, pub attempted: bool, pub press_returned: bool,
        pub triggered: Option<bool>, pub custody_known: bool,
        pub initial_proof: Option<IdentityBinding>, pub proof: Option<IdentityBinding>,
        pub prompt: [Option<bool>; 2], pub button: ControlContainerButtonProof,
        pub selection: RowSelectionProof, pub selected_target: Option<&'static str>,
    }
    impl OpenReport {
        pub fn succeeded(self) -> bool {
            self.attempted && self.press_returned && self.triggered == Some(true) && self.custody_known
                && self.initial_proof.is_some_and(IdentityBinding::matched) && self.proof.is_some_and(IdentityBinding::matched)
                && self.prompt == [Some(true); 2] && self.button.matched()
                && self.selection.matched() && self.selected_target == Some("match")
                && self.diagnostic == OpenDiagnostic { site: "press", error: "none" }
        }
    }
    fn open_return(w: OpenWire, rechecks: [Option<OpenRecheckReturn>; 2], known: bool) -> Option<OpenReport> {
        // Control completion bits form a prefix over the eligible projection,
        // not all AX descendants. Second-pass progress cannot erase the first.
        if w.flags & !15 != 0 || w.checks > 127 || w.checks & (w.checks + 1) != 0
            || w.calls > 512 || w.initial_nodes_examined > 16 || w.recheck_nodes_examined > 16
            || w.last_depth > 8 || w.owned > 256 || w.released > w.owned
            || !(w.ax_error == 0 || (-25214..=-25200).contains(&w.ax_error))
            || !matches!(w.selection_checks, 0 | 1 | 3 | 7) || !matches!(w.selection_flags, 0 | 1 | 3 | 7)
            || w.selection_nodes_examined > 48 { return None; }
        let limit = if matches!(w.site, 22..=25) {
            // Only these first local refusals may reuse the raw role/depth.
            // Validate them before excluding that geometry from button DATA.
            if w.error != 7 || w.ax_error != 0 || w.checks != 3 || w.flags & 7 != 0
                || w.initial_nodes_examined != 0 || w.recheck_nodes_examined != 0
                || w.selection_checks != 0 || w.selection_flags != 0 || w.calls == 0 || w.owned == 0
                || !rechecks[0].is_some_and(OpenRecheckReturn::matched) || rechecks[1].is_some()
                || !(1..=49).contains(&w.selection_limit_queued)
                || w.selection_limit_queued < w.selection_nodes_examined + 1 { return None; }
            let root = w.last_role == 1 && w.last_depth == 0 && w.selection_nodes_examined == 0
                && w.selection_limit_queued == 1;
            let container = matches!(w.last_role, 2 | 3 | 6 | 7 | 8)
                && (1..=8).contains(&w.last_depth) && w.last_depth <= w.selection_nodes_examined;
            let count = w.selection_limit_count;
            let array_limit = if matches!(w.last_role, 6 | 7) { 32 } else { 16 };
            let local_site = match w.site {
                22 => count > array_limit && (root || container),
                23 => (count < 0 || count > array_limit) && (root || container),
                24 => (1..=array_limit).contains(&count) && count > i64::from(49 - w.selection_limit_queued)
                    && container && w.last_depth < 8,
                25 => (1..=array_limit).contains(&count) && container && w.last_depth == 8,
                _ => false,
            };
            if !local_site { return None; }
            let role = match w.last_role { 1 => "Sheet", 2 => "Group", 3 => "SplitGroup", 6 => "Table",
                7 => "Outline", 8 => "ScrollArea", _ => return None };
            Some(RowSelectionLimit { role, depth: w.last_depth, count, queued_nodes: w.selection_limit_queued })
        } else {
            if w.selection_limit_queued != 0 || w.selection_limit_count != 0 { return None; }
            None
        };
        let selection = RowSelectionProof { checks: std::array::from_fn(|i| w.selection_checks & (1 << i) != 0),
            nodes_examined: w.selection_nodes_examined, attempted: w.selection_flags & 1 != 0,
            returned: w.selection_flags & 2 != 0, setter_succeeded: (w.selection_flags & 2 != 0).then_some(w.selection_flags & 4 != 0), limit };
        let button = ControlContainerButtonProof { checks: std::array::from_fn(|i| w.checks & (1 << i) != 0), calls: w.calls,
            initial_nodes_examined: w.initial_nodes_examined, recheck_nodes_examined: w.recheck_nodes_examined,
            last_role: *["not-read", "Sheet", "Group", "SplitGroup", "Button", "Browser", "Table", "Outline", "ScrollArea", "opaque"]
                .get(if limit.is_some() { 0 } else { w.last_role as usize })?,
            last_depth: if limit.is_some() { 0 } else { w.last_depth }, cf_slots: w.owned, cf_slots_retired: w.released,
            cleanup_returned: w.flags & 8 != 0, ax_error: w.ax_error };
        let r = OpenReport { diagnostic: OpenDiagnostic {
            site: *["entry", "application", "windows", "parent-identifier", "sheet", "topology", "control-projection", "button",
                "control-recheck", "initial-original-proof", "original-proof", "admission", "press", "cleanup",
                "control-title-limit", "control-child-count-limit", "control-child-copy-limit", "control-node-limit", "control-depth-limit",
                "selection", "selection-write", "selection-count-limit", "selection-copy-limit", "selection-node-limit", "selection-depth-limit"]
                .get(w.site.checked_sub(1)? as usize)?, error: *OPEN_ERRORS.get(w.error as usize)?, },
            attempted: w.flags & 1 != 0, press_returned: w.flags & 2 != 0,
            triggered: (w.flags & 2 != 0).then_some(w.flags & 4 != 0),
            custody_known: known && button.cleanup_returned && rechecks.iter().flatten().all(|r| r.custody_known),
            initial_proof: rechecks[0].and_then(|r| r.proof), proof: rechecks[1].and_then(|r| r.proof),
            prompt: rechecks.map(|r| r.and_then(|r| r.prompt)), button, selection,
            selected_target: rechecks[1].and_then(|r| r.selected_target) };
        if w.flags & 4 != 0 && !r.press_returned || r.press_returned && !r.attempted
            || r.attempted && (w.checks != 127 || !rechecks.into_iter().all(|r| r.is_some_and(OpenRecheckReturn::matched))
                || !matches!(r.diagnostic.site, "press" | "cleanup") || !selection.matched() || r.selected_target != Some("match"))
            || button.cleanup_returned && w.released != w.owned
            || matches!(w.error, 9 | 14 | 15) && r.custody_known
            || w.calls != 0 && !rechecks[0].is_some_and(OpenRecheckReturn::matched)
            || rechecks.iter().enumerate().any(|(i, r)| r.is_some_and(|r| r.stage != i as u32 + 1))
            || w.selection_nodes_examined != 0 && (w.checks & 3 != 3 || w.calls == 0 || w.owned == 0)
            || w.selection_checks != 0 && w.selection_nodes_examined < 2
            || selection.attempted && (w.selection_checks != 7 || w.calls == 0 || w.owned == 0)
            || selection.setter_succeeded == Some(false) && w.ax_error == 0
            || selection.attempted && !selection.returned && (w.site != 21 || w.error != 14 || w.ax_error != 0
                || button.cleanup_returned || w.released != 0)
            || (w.initial_nodes_examined != 0 || w.checks > 3) && !selection.matched()
            || matches!(w.site, 7..=9 | 11..=13 | 15..=19) && !selection.matched()
            || w.selection_flags != 0 && !selection.matched() && !matches!(w.site, 21 | 14)
            || (w.checks != 0 || w.last_role != 0) && (w.calls == 0 || w.owned == 0)
            || w.initial_nodes_examined != 0 && w.checks & 3 != 3
            || w.checks & 4 != 0 && w.initial_nodes_examined == 0
            || w.checks < 63 && w.recheck_nodes_examined != 0
            || limit.is_none() && w.last_depth > w.initial_nodes_examined.max(w.recheck_nodes_examined)
            || w.checks == 127 && (w.recheck_nodes_examined == 0 || w.last_role != 4 || w.last_depth == 0
                || w.last_depth > w.initial_nodes_examined.min(w.recheck_nodes_examined))
            || rechecks[1].is_some() && w.checks != 127
            || r.triggered == Some(false) && w.ax_error == 0
            || r.triggered == Some(true) && w.ax_error != 0
            || w.ax_error != 0 && w.error == 0
            || w.error == 0 && !r.succeeded() { return None; }
        if matches!(w.site, 20 | 21) && (w.checks != 3 || w.initial_nodes_examined != 0 || w.recheck_nodes_examined != 0
            || w.flags & 7 != 0 || rechecks[1].is_some() || w.last_depth != 0
            || w.site == 20 && w.selection_flags != 0 || w.site == 21 && !selection.attempted) { return None; }
        if w.site == 7 && (!matches!(w.checks, 3 | 7) || w.recheck_nodes_examined != 0)
            || w.site == 8 && (!matches!(w.checks, 15 | 31 | 63) || w.recheck_nodes_examined != 0)
            || w.site == 9 && (w.checks != 63 || w.last_depth > w.recheck_nodes_examined) { return None; }
        // Count/Copy may fail on the root OR a deeper admitted container. A
        // deeper failure preserves its already-begun node count, including
        // late/Unknown outcomes; not-read can never stand in for an actual role.
        if matches!(w.site, 15..=19) {
            let examined = match w.checks {
                3 if w.recheck_nodes_examined == 0 => w.initial_nodes_examined,
                63 if w.initial_nodes_examined >= 1 => w.recheck_nodes_examined,
                _ => return None,
            };
            let node = (1..=8).contains(&w.last_depth) && examined >= w.last_depth;
            let container = matches!(w.last_role, 2 | 3) && node;
            let local_site = match w.site {
                15 => w.last_role == 4 && node,
                16 | 17 => container || w.last_role == 1 && w.last_depth == 0 && examined == 0,
                18 => container && w.last_depth < 8,
                19 => container && w.last_depth == 8,
                _ => false,
            };
            if w.error != 7 || !local_site || w.calls == 0 || w.owned == 0 || w.ax_error != 0 || w.flags & 7 != 0
                || !rechecks[0].is_some_and(OpenRecheckReturn::matched) || rechecks[1].is_some() { return None; }
        }
        Some(r)
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OpenInputReturn { pub entered: bool, pub report: Option<OpenReport>, pub custody_known: bool }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct OpenTimeout { seconds: f32, required_ns: u64 }
    struct OpenAdmission<'a, F, G> {
        end: Instant, admit: &'a mut F, recheck: &'a mut G,
        rechecks: [Option<OpenRecheckReturn>; 2], next_recheck: usize, custody_known: bool,
    }
    fn timeout_for(remaining: Duration) -> Option<OpenTimeout> {
        let allowance = remaining.as_nanos().min(100_000_000);
        if allowance == 0 { return None; }
        let mut seconds = (allowance as f64 / 1_000_000_000.0) as f32;
        // Round DOWN, including the nonexact f32 representation of0.1s. C
        // independently checks ceil(seconds*1e9) against this exact allowance.
        if (f64::from(seconds) * 1_000_000_000.0).ceil() > allowance as f64 {
            seconds = f32::from_bits(seconds.to_bits().checked_sub(1)?);
        }
        let required_ns = (f64::from(seconds) * 1_000_000_000.0).ceil() as u64;
        (seconds.is_finite() && seconds > 0.0 && required_ns > 0 && u128::from(required_ns) <= allowance)
            .then_some(OpenTimeout { seconds, required_ns })
    }
    unsafe extern "C" fn open_admission<F, G>(opaque: *mut c_void, required_ns: u64, after: c_int,
        timeout: *mut OpenTimeout) -> c_int
    where F: FnMut(bool) -> Option<bool>, G: FnMut(u32) -> Result<(OpenRecheckReturn, bool), u32> {
        let context = unsafe { &mut *opaque.cast::<OpenAdmission<'_, F, G>>() };
        let checked = catch_unwind(AssertUnwindSafe(|| {
            if !matches!(after, 0 | 1) || required_ns > 100_000_000 || !timeout.is_null() && required_ns != 0 {
                context.custody_known = false; return 9;
            }
            let Some(allowed) = (context.admit)(after == 1) else { context.custody_known = false; return 9; };
            let remaining = context.end.saturating_duration_since(Instant::now());
            if remaining.is_zero() || remaining.as_nanos() < u128::from(required_ns) { return 8; }
            if !allowed { return 3; }
            if !timeout.is_null() {
                let Some(value) = timeout_for(remaining) else { return 8; };
                unsafe { *timeout = value; }
            }
            0
        }));
        match checked { Ok(code) => code, Err(payload) => { context.custody_known = false; std::mem::forget(payload); 9 } }
    }
    unsafe extern "C" fn open_recheck<F, G>(opaque: *mut c_void, stage: c_int) -> c_int
    where F: FnMut(bool) -> Option<bool>, G: FnMut(u32) -> Result<(OpenRecheckReturn, bool), u32> {
        let context = unsafe { &mut *opaque.cast::<OpenAdmission<'_, F, G>>() };
        let checked = catch_unwind(AssertUnwindSafe(|| {
            if !(1..=2).contains(&stage) || stage as usize != context.next_recheck + 1 {
                context.custody_known = false; return 9;
            }
            context.next_recheck += 1; // Never redispatch a stage, including errors.
            let (returned, admitted) = match (context.recheck)(stage as u32) {
                Ok(returned) => returned,
                Err(code) if matches!(code, 3 | 8) => return code as c_int,
                Err(_) => { context.custody_known = false; return 9; },
            };
            context.rechecks[stage as usize - 1] = Some(returned);
            if returned.stage != stage as u32 || !returned.custody_known { context.custody_known = false; return 9; }
            let code = OPEN_ERRORS.iter().position(|e| *e == returned.error).unwrap_or(9) as c_int;
            if code != 0 { return code; }
            if !returned.matched() { context.custody_known = false; return 9; }
            if Instant::now() >= context.end { return 8; }
            if !admitted { return 3; }
            0
        }));
        match checked { Ok(code) => code, Err(payload) => { context.custody_known = false; std::mem::forget(payload); 9 } }
    }
    /// One off-main public AX operation. Only scalar identity and synchronous
    /// callbacks cross this boundary; Panel/NSWindow/CF owners are never Send.
    pub fn installed_prompt_button<F, G>(identity: OpenIdentity, end: Instant, mut admit: F, mut recheck: G) -> OpenInputReturn
    where F: FnMut(bool) -> Option<bool>, G: FnMut(u32) -> Result<(OpenRecheckReturn, bool), u32> {
        let mut returned = OpenInputReturn { entered: false, report: None, custody_known: false };
        if main_thread() || !identity.valid() { return returned; }
        let mut context = OpenAdmission { end, admit: &mut admit, recheck: &mut recheck,
            rechecks: [None; 2], next_recheck: 0, custody_known: true };
        let mut wire = OpenWire::default(); returned.entered = true;
        // SAFETY: bounded copied input lives through the single synchronous
        // call; callbacks borrow this worker stack only while C is active.
        unsafe { mrk_observation_prompt_press(identity.parent.as_ptr(), identity.panel.as_ptr(), identity.prompt.as_ptr(),
            identity.parent.len(), identity.target.as_ptr(), identity.target.len(), open_admission::<F, G>, open_recheck::<F, G>,
            (&mut context as *mut OpenAdmission<'_, F, G>).cast(), &mut wire); }
        returned.report = open_return(wire, context.rechecks, context.custody_known);
        returned.custody_known = context.custody_known && returned.report.is_some_and(|r| r.custody_known);
        returned
    }
    pub fn installed_accessibility_trusted() -> Result<bool, ()> {
        match unsafe { mrk_observation_ax_trusted() } { 1 => Some(true), -1 => None, 0 => Some(false), _ => None }.ok_or(())
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OriginalWindowState {
        pub application_present: bool, pub active: bool, pub main_present: bool,
        pub original_main: bool, pub ordinary_window: bool, pub no_attached_sheet: bool,
    }
    impl OriginalWindowState {
        pub fn ready(self) -> bool {
            self.application_present && self.active && self.main_present && self.original_main
                && self.ordinary_window && self.no_attached_sheet
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OriginalWindowReturn { pub result: &'static str, pub state: Option<OriginalWindowState> }
    fn original_window_state(flags: u32) -> Option<OriginalWindowState> {
        if flags & !63 != 0 || flags & 1 == 0 && flags != 0
            || flags & 4 == 0 && flags & 56 != 0 { return None; }
        Some(OriginalWindowState { application_present: flags & 1 != 0, active: flags & 2 != 0,
            main_present: flags & 4 != 0, original_main: flags & 8 != 0,
            ordinary_window: flags & 16 != 0, no_attached_sheet: flags & 32 != 0 })
    }
    fn original_window_return(code: c_int, flags: u32) -> OriginalWindowReturn {
        if code == 0 {
            if let Some(state) = original_window_state(flags) {
                return OriginalWindowReturn { result: "ok", state: Some(state) };
            }
        } else if flags == 0 && matches!(code, 1 | 2) {
            return OriginalWindowReturn { result: if code == 1 { "entry-refused" } else { "native-error" }, state: None };
        }
        OriginalWindowReturn { result: "invalid-return", state: None }
    }
    /// A synchronous read only: no supplied-address dereference, saved pointer,
    /// new native retain, activation request or ownership/finality authority.
    pub fn installed_original_window(original: usize) -> OriginalWindowReturn {
        let mut flags = 0;
        // SAFETY: fixed writable scalar output; the integer is only compared to
        // NSApp's own mainWindow address. Native code checks main before AppKit.
        let code = unsafe { mrk_observation_original_window(original, &mut flags) };
        original_window_return(code, flags)
    }
    fn original_window_data_check() -> bool {
        // Inert scalar decoding only, never an AppKit call or evidence sample.
        for flags in 0..128 {
            let valid = flags < 64 && (flags == 0 || flags & 1 != 0)
                && (flags & 4 != 0 || flags & 56 == 0);
            let sample = original_window_return(0, flags);
            if sample.state.is_some() != valid || (sample.result == "ok") != valid
                || sample.state.is_some_and(OriginalWindowState::ready) != (flags == 63) { return false; }
        }
        for code in [-1, 1, 2, 3, c_int::MAX] {
            let sample = original_window_return(code, 0);
            let expected = match code {
                1 => "entry-refused", 2 => "native-error", _ => "invalid-return",
            };
            if sample.state.is_some() || sample.result != expected
                || original_window_return(code, 63).result != "invalid-return" { return false; }
        }
        original_window_return(0, u32::MAX).result == "invalid-return"
    }
    fn semantic_data_check() -> bool {
        // Inert decoder/timeout DATA only: never manufacture a native return.
        if std::mem::size_of::<IdentityWire>() != 56 || std::mem::size_of::<OpenWire>() != 72
            || std::mem::offset_of!(OpenWire, selection_limit_queued) != 60
            || std::mem::offset_of!(OpenWire, selection_limit_count) != 64
            || std::mem::size_of::<RecheckWire>() != 52 || std::mem::size_of::<OpenTimeout>() != 16 { return false; }
        let p = IdentityProofWire { flags: 1, checked: 0xfff, matched: 0xfff, parent: 2, panel: 8,
            children: 2, originals: 2, site: 14, error: 0 };
        let rw = RecheckWire { known: 1, error: 0, prompt: 1, proof: p, selected_target: 0 };
        let Some(recheck) = recheck_return(rw, 1) else { return false; };
        let Some(final_recheck) = recheck_return(RecheckWire { selected_target: 3, ..rw }, 2) else { return false; };
        let rechecks = [Some(recheck), Some(final_recheck)];
        let full = OpenWire { flags: 15, site: 13, error: 0, checks: 127, calls: 101,
            initial_nodes_examined: 4, recheck_nodes_examined: 4, owned: 60, released: 60, ax_error: 0,
            last_role: 4, last_depth: 2, selection_checks: 7, selection_flags: 7, selection_nodes_examined: 4,
            selection_limit_queued: 0, selection_limit_count: 0 };
        let Some(success) = open_return(full, rechecks, true) else { return false; };
        if !success.succeeded() { return false; }
        // Neither incomplete eligible projection, missing unique button, nor
        // unperformed same-original control-path recheck may pass the proof.
        for bit in 0..7 {
            if open_return(OpenWire { checks: full.checks & !(1 << bit), ..full }, rechecks, true).is_some() { return false; }
        }
        for bad in [OpenWire { calls: 513, ..full }, OpenWire { initial_nodes_examined: 17, ..full },
            OpenWire { initial_nodes_examined: 0, ..full }, OpenWire { recheck_nodes_examined: 0, ..full },
            OpenWire { recheck_nodes_examined: 17, ..full }, OpenWire { last_role: 10, ..full },
            OpenWire { last_role: 2, ..full }, OpenWire { last_depth: 0, ..full }, OpenWire { last_depth: 9, ..full },
            OpenWire { owned: 257, released: 257, ..full }, OpenWire { released: 59, ..full },
            OpenWire { ax_error: 1, ..full }, OpenWire { checks: 255, ..full }, OpenWire { flags: 31, ..full }] {
            if open_return(bad, rechecks, true).is_some() { return false; }
        }
        for bad in [RecheckWire { prompt: 0, ..rw }, RecheckWire { prompt: 2, ..rw },
            RecheckWire { known: 0, ..rw }, RecheckWire { proof: IdentityProofWire::default(), ..rw }] {
            if recheck_return(bad, 1).is_some() { return false; }
        }
        // Pure selection DATA: parent browsing, setter return and selected URL
        // are separate facts. Missing/malformed/foreign proof never permits Press.
        let mut target = [0u8; 4097]; target[..23].copy_from_slice(b"/synthetic/project-root");
        if !selection_target(&target) { return false; }
        for bad in [b"/".as_slice(), b"/synthetic/../root", b"/synthetic//root", b"relative/root", b"/synthetic/root/"] {
            let mut bytes = [0u8; 4097]; bytes[..bad.len()].copy_from_slice(bad);
            if selection_target(&bytes) { return false; }
        }
        target[100] = 1; if selection_target(&target) { return false; }
        for bad in [OpenWire { selection_checks: 3, ..full }, OpenWire { selection_flags: 3, ..full },
            OpenWire { selection_flags: 0, ..full }, OpenWire { selection_nodes_examined: 1, ..full },
            OpenWire { selection_nodes_examined: 49, ..full }] {
            if open_return(bad, rechecks, true).is_some() { return false; }
        }
        // Widened selection DATA survives unchanged; control/global bounds do not widen.
        for nodes in [17, 36, 48] {
            if !open_return(OpenWire { selection_nodes_examined: nodes, ..full }, rechecks, true)
                .is_some_and(|r| r.selection.nodes_examined == nodes && r.succeeded()) { return false; }
        }
        if recheck_return(rw, 2).is_some() || recheck_return(RecheckWire { selected_target: 3, ..rw }, 1).is_some()
            || open_return(full, [Some(recheck); 2], true).is_some() { return false; }
        for (selected_target, error, known) in [(1, 14, 0), (2, 3, 1), (4, 13, 1), (5, 6, 1), (6, 5, 1)] {
            let Some(refused) = recheck_return(RecheckWire { selected_target, error, known, ..rw }, 2) else { return false; };
            let wire = OpenWire { flags: if known == 1 { 8 } else { 0 }, error, site: 11,
                released: if known == 1 { full.owned } else { 0 }, ..full };
            if !open_return(wire, [Some(recheck), Some(refused)], known == 1).is_some_and(|r|
                !r.attempted && r.selection.matched() && r.selected_target == refused.selected_target && !r.succeeded())
                || open_return(full, [Some(recheck), Some(refused)], true).is_some() { return false; }
        }
        for (selection_checks, selection_nodes_examined, error) in [(0, 2, 4), (0, 36, 5), (0, 2, 6),
            (1, 2, 13), (3, 2, 4), (0, 48, 7)] {
            let wire = OpenWire { flags: 8, checks: 3, site: 20, error, selection_checks, selection_flags: 0,
                selection_nodes_examined, initial_nodes_examined: 0, recheck_nodes_examined: 0,
                last_role: 0, last_depth: 0, ..full };
            if !open_return(wire, [Some(recheck), None], true).is_some_and(|r| !r.attempted && !r.selection.attempted
                && r.selected_target.is_none() && !r.succeeded()) { return false; }
        }
        for (selection_flags, error, ax_error, known) in [(1, 14, 0, false), (3, 11, -25204, true), (7, 8, 0, true)] {
            let wire = OpenWire { flags: if known { 8 } else { 0 }, checks: 3, site: 21, error, ax_error, selection_flags,
                initial_nodes_examined: 0, recheck_nodes_examined: 0, last_role: 1, last_depth: 0,
                released: if known { full.owned } else { 0 }, ..full };
            if !open_return(wire, [Some(recheck), None], known).is_some_and(|r| !r.attempted && r.selection.attempted
                && r.selection.returned == (selection_flags != 1) && r.selected_target.is_none() && !r.succeeded()) { return false; }
            if selection_flags == 1 {
                // A caught selector exception keeps the original callback
                // context intact, but cannot invent CF/action retirement.
                if !open_return(wire, [Some(recheck), None], true).is_some_and(|r| !r.custody_known) { return false; }
                for bad in [OpenWire { flags: 8, error: 4, released: full.owned, ..wire },
                    OpenWire { error: 4, ..wire }, OpenWire { site: 14, ..wire }, OpenWire { ax_error: -25204, ..wire },
                    OpenWire { flags: 8, released: full.owned, ..wire }, OpenWire { released: 1, ..wire }] {
                    for context_known in [false, true] {
                        if open_return(bad, [Some(recheck), None], context_known).is_some() { return false; }
                    }
                }
            }
        }
        // SelectedRows precedes the control passes. A later common-budget refusal
        // preserves its completed effect, never inventing Press or finality.
        let budget_limited = OpenWire { flags: 8, site: 7, error: 7, checks: 3, calls: 512,
            initial_nodes_examined: 3, recheck_nodes_examined: 0, owned: 256, released: 256,
            last_role: 2, last_depth: 2, selection_nodes_examined: 36, ..full };
        for (flags, released, known) in [(8, 256, true), (8, 256, false), (0, 16, false), (0, 16, true)] {
            let Some(r) = open_return(OpenWire { flags, released, ..budget_limited }, [Some(recheck), None], known)
                else { return false; };
            if r.selection != (RowSelectionProof { nodes_examined: 36, ..success.selection })
                || r.diagnostic != (OpenDiagnostic { site: "control-projection", error: "limit" })
                || r.attempted || r.press_returned || r.triggered.is_some() || r.selected_target.is_some()
                || r.proof.is_some() || r.succeeded() || r.custody_known != (known && flags & 8 != 0)
                || r.button.calls != 512 || r.button.cf_slots != 256 || r.button.cf_slots_retired != released
                || r.button.cleanup_returned != (flags & 8 != 0) { return false; }
        }
        for bad in [OpenWire { selection_flags: 0, ..budget_limited }, OpenWire { selection_checks: 0, ..budget_limited },
            OpenWire { flags: 9, ..budget_limited }, OpenWire { error: 0, ..budget_limited },
            OpenWire { calls: 513, ..budget_limited }, OpenWire { owned: 257, released: 257, ..budget_limited },
            OpenWire { initial_nodes_examined: 17, ..budget_limited }, OpenWire { released: 16, ..budget_limited }] {
            if open_return(bad, [Some(recheck), None], true).is_some() { return false; }
        }
        for (initial, recheck, depth) in [(1, 1, 1), (4, 6, 3), (16, 16, 8)] {
            if !open_return(OpenWire { initial_nodes_examined: initial, recheck_nodes_examined: recheck, last_depth: depth, ..full }, rechecks, true)
                .is_some_and(OpenReport::succeeded) { return false; }
        }
        // Complete first projection: zero/two matches, including a disabled
        // duplicate in another admitted branch. Recheck ambiguity, replacement,
        // changed role/title or reparenting never authorizes Press.
        for (checks, error) in [(7, 4), (7, 5), (3, 7), (63, 4), (63, 5), (63, 13)] {
            let failed = OpenWire { flags: 8, site: if checks == 63 { 9 } else { 7 }, error, checks,
                recheck_nodes_examined: if checks == 63 { 4 } else { 0 }, ..full };
            if !open_return(failed, [Some(recheck), None], true).is_some_and(|r| !r.attempted && !r.succeeded()) { return false; }
        }
        // A node can fail its type/parent/role before a role was read. Keeping
        // not-read + this positive depth is essential to honest diagnostics.
        for checks in [3, 63] {
            let failed = OpenWire { flags: 8, site: if checks == 3 { 7 } else { 9 }, error: 6, checks,
                initial_nodes_examined: 4, recheck_nodes_examined: if checks == 3 { 0 } else { 2 },
                last_role: 0, last_depth: 2, ..full };
            if !open_return(failed, [Some(recheck), None], true).is_some_and(|r|
                r.button.last_role == "not-read" && r.button.last_depth == 2 && !r.succeeded()) { return false; }
        }
        for (checks, initial, again) in [(1, 1, 0), (3, 17, 0), (7, 0, 0), (15, 4, 1), (31, 4, 1), (127, 4, 0)] {
            let failed = OpenWire { flags: 8, site: 7, error: 7, checks,
                initial_nodes_examined: initial, recheck_nodes_examined: again, ..full };
            if open_return(failed, [Some(recheck), None], true).is_some() { return false; }
        }
        if open_return(OpenWire { flags: 8, site: 9, error: 6, checks: 63, initial_nodes_examined: 8,
            recheck_nodes_examined: 1, last_role: 0, last_depth: 2, ..full }, [Some(recheck), None], true).is_some() { return false; }
        for (site, label, role, depth, minimum) in [
            (15, "control-title-limit", 4, 1, 1),
            (16, "control-child-count-limit", 1, 0, 0), (16, "control-child-count-limit", 2, 2, 2),
            (17, "control-child-copy-limit", 1, 0, 0), (17, "control-child-copy-limit", 3, 2, 2),
            (18, "control-node-limit", 2, 1, 1), (19, "control-depth-limit", 3, 8, 8)] {
            for checks in [3, 63] {
                let limits = if depth == 0 { (0, 0) } else { (minimum, 16) };
                let frame = |examined| OpenWire { flags: 8, site, error: 7, checks,
                    initial_nodes_examined: if checks == 3 { examined } else { 16 },
                    recheck_nodes_examined: if checks == 63 { examined } else { 0 }, last_role: role, last_depth: depth, ..full };
                for examined in [0, 1, 2, 8, 16, 17] {
                    let failed = frame(examined);
                    let valid = (limits.0..=limits.1).contains(&examined);
                    for (flags, released, known) in [(8, full.owned, true), (8, full.owned, false), (0, 16, false)] {
                        let returned = open_return(OpenWire { flags, released, ..failed }, [Some(recheck), None], known);
                        if returned.is_some() != valid { return false; }
                        if valid && !returned.is_some_and(|r| r.diagnostic == OpenDiagnostic { site: label, error: "limit" }
                            && !r.attempted && !r.press_returned && r.triggered.is_none() && !r.succeeded()
                            && r.custody_known == known && r.button.cleanup_returned == (flags & 8 != 0)
                            && r.button.cf_slots_retired == released && r.button.last_depth == depth
                            && r.button.initial_nodes_examined == failed.initial_nodes_examined
                            && r.button.recheck_nodes_examined == failed.recheck_nodes_examined)
                            { return false; }
                    }
                }
                let failed = frame(limits.0);
                for bad in [OpenWire { error: 0, ..failed }, OpenWire { error: 5, ..failed },
                    OpenWire { calls: 0, ..failed }, OpenWire { owned: 0, released: 0, ..failed },
                    OpenWire { checks: 7, ..failed }, OpenWire { ax_error: -25204, ..failed },
                    OpenWire { flags: 9, ..failed }, OpenWire { site: 20, ..failed }, OpenWire { last_role: 0, ..failed },
                    OpenWire { last_role: 9, ..failed }, OpenWire { last_depth: 9, ..failed }] {
                    if open_return(bad, [Some(recheck), None], true).is_some() { return false; }
                }
                if open_return(failed, [None; 2], true).is_some() || open_return(failed, rechecks, true).is_some()
                    || open_return(OpenWire { site, ..full }, rechecks, true).is_some() { return false; }
            }
        }
        // Synthetic successor-policy DATA, not observed layouts. The historical
        // Outline20 refusal remains bound to its original16/17 source policy.
        for (site, label, role, name, depth, nodes, queued, count) in [
            (22, "selection-count-limit", 1, "Sheet", 0, 0, 1, 17),
            (22, "selection-count-limit", 1, "Sheet", 0, 0, 1, i64::MAX),
            (22, "selection-count-limit", 2, "Group", 1, 1, 2, 17),
            (22, "selection-count-limit", 3, "SplitGroup", 8, 8, 9, i64::MAX),
            (22, "selection-count-limit", 8, "ScrollArea", 3, 12, 17, 17),
            (22, "selection-count-limit", 6, "Table", 1, 1, 2, i64::MAX),
            (22, "selection-count-limit", 7, "Outline", 8, 48, 49, 33),
            (23, "selection-copy-limit", 1, "Sheet", 0, 0, 1, i64::MIN),
            (23, "selection-copy-limit", 1, "Sheet", 0, 0, 1, -1),
            (23, "selection-copy-limit", 1, "Sheet", 0, 0, 1, 17),
            (23, "selection-copy-limit", 1, "Sheet", 0, 0, 1, i64::MAX),
            (23, "selection-copy-limit", 2, "Group", 1, 1, 2, -1),
            (23, "selection-copy-limit", 3, "SplitGroup", 8, 8, 9, i64::MIN),
            (23, "selection-copy-limit", 8, "ScrollArea", 3, 12, 17, i64::MAX),
            (23, "selection-copy-limit", 6, "Table", 1, 1, 2, 33),
            (23, "selection-copy-limit", 7, "Outline", 8, 48, 49, i64::MIN),
            (24, "selection-node-limit", 2, "Group", 3, 12, 34, 16),
            (24, "selection-node-limit", 3, "SplitGroup", 7, 20, 40, 10),
            (24, "selection-node-limit", 8, "ScrollArea", 3, 12, 49, 1),
            (24, "selection-node-limit", 6, "Table", 3, 12, 18, 32),
            (24, "selection-node-limit", 7, "Outline", 7, 48, 49, 1),
            (25, "selection-depth-limit", 2, "Group", 8, 8, 9, 1),
            (25, "selection-depth-limit", 3, "SplitGroup", 8, 8, 9, 8),
            (25, "selection-depth-limit", 8, "ScrollArea", 8, 12, 17, 16),
            (25, "selection-depth-limit", 6, "Table", 8, 8, 49, 32),
            (25, "selection-depth-limit", 7, "Outline", 8, 48, 49, 32)] {
            let failed = OpenWire { flags: 8, site, error: 7, checks: 3, calls: 100, owned: 45, released: 45,
                initial_nodes_examined: 0, recheck_nodes_examined: 0, last_role: role, last_depth: depth,
                selection_checks: 0, selection_flags: 0, selection_nodes_examined: nodes,
                selection_limit_queued: queued, selection_limit_count: count, ..full };
            let diagnostic = RowSelectionLimit { role: name, depth, count, queued_nodes: queued };
            // Context and CF cleanup histories stay independent of the tuple;
            // a known callback context cannot repair unreturned CF cleanup.
            for (flags, released, known) in [(8, 45, true), (8, 45, false), (0, 16, false), (0, 16, true), (0, 0, true)] {
                let Some(r) = open_return(OpenWire { flags, released, ..failed }, [Some(recheck), None], known)
                    else { return false; };
                if r.diagnostic != (OpenDiagnostic { site: label, error: "limit" }) || r.succeeded()
                    || r.attempted || r.press_returned || r.triggered.is_some() || r.proof.is_some() || r.selected_target.is_some()
                    || r.prompt != [Some(true), None] || r.initial_proof != success.initial_proof
                    || r.selection.limit != Some(diagnostic) || r.selection.nodes_examined != nodes
                    || r.selection.checks != [false; 3] || r.selection.attempted || r.selection.returned
                    || r.selection.setter_succeeded.is_some() || r.selection.matched()
                    || r.button.checks != [true, true, false, false, false, false, false]
                    || r.button.initial_nodes_examined != 0 || r.button.recheck_nodes_examined != 0
                    || r.button.last_role != "not-read" || r.button.last_depth != 0
                    || r.button.calls != 100 || r.button.cf_slots != 45 || r.button.cf_slots_retired != released
                    || r.button.cleanup_returned != (flags & 8 != 0) || r.custody_known != (known && flags & 8 != 0) { return false; }
            }
            let complete = RowSelectionProof { limit: Some(diagnostic), ..success.selection };
            if complete.matched() || (OpenReport { selection: complete, ..success }).succeeded() { return false; }
            for bad in [OpenWire { error: 0, ..failed }, OpenWire { error: 8, ..failed }, OpenWire { error: 14, ..failed },
                OpenWire { ax_error: -25204, ..failed }, OpenWire { calls: 0, ..failed }, OpenWire { calls: 513, ..failed },
                OpenWire { owned: 0, released: 0, ..failed }, OpenWire { owned: 257, released: 257, ..failed },
                OpenWire { released: 44, ..failed }, OpenWire { checks: 1, ..failed }, OpenWire { checks: 7, ..failed },
                OpenWire { flags: 9, ..failed }, OpenWire { flags: 10, ..failed }, OpenWire { flags: 12, ..failed },
                OpenWire { initial_nodes_examined: 1, ..failed }, OpenWire { recheck_nodes_examined: 1, ..failed },
                OpenWire { selection_checks: 1, ..failed }, OpenWire { selection_checks: 3, ..failed },
                OpenWire { selection_checks: 7, ..failed }, OpenWire { selection_flags: 1, ..failed },
                OpenWire { selection_flags: 3, ..failed }, OpenWire { selection_flags: 7, ..failed },
                OpenWire { selection_nodes_examined: 49, ..failed }, OpenWire { selection_limit_queued: 0, ..failed },
                OpenWire { selection_limit_queued: 50, ..failed }, OpenWire { selection_limit_queued: nodes, ..failed },
                OpenWire { last_role: 0, ..failed }, OpenWire { last_role: 4, ..failed }, OpenWire { last_role: 5, ..failed },
                OpenWire { last_role: 9, ..failed }, OpenWire { last_role: 10, ..failed }, OpenWire { last_role: u32::MAX, ..failed },
                OpenWire { last_depth: 9, ..failed }, OpenWire { last_role: 1, last_depth: 1, ..failed },
                OpenWire { last_role: 2, last_depth: 0, ..failed },
                OpenWire { last_role: 2, last_depth: 2, selection_nodes_examined: 1, selection_limit_queued: 2, ..failed },
                OpenWire { last_role: 1, last_depth: 0, selection_nodes_examined: 0, selection_limit_queued: 2, ..failed },
                OpenWire { last_role: 1, last_depth: 0, selection_nodes_examined: 1, selection_limit_queued: 2, ..failed }] {
                if open_return(bad, [Some(recheck), None], true).is_some() { return false; }
            }
            let array_limit = if matches!(role, 6 | 7) { 32 } else { 16 };
            let invalid_counts: &[i64] = match site {
                22 => &[i64::MIN, -1, 0, 1, array_limit], 23 => &[0, 1, array_limit],
                _ => &[i64::MIN, -1, 0, array_limit + 1, i64::MAX],
            };
            for &selection_limit_count in invalid_counts {
                if open_return(OpenWire { selection_limit_count, ..failed }, [Some(recheck), None], true).is_some() { return false; }
            }
            let incompatible_sites: &[u32] = match site { 22 | 23 => &[24, 25], 24 => &[22, 23, 25], _ => &[22, 23, 24] };
            for &site in incompatible_sites {
                if open_return(OpenWire { site, ..failed }, [Some(recheck), None], true).is_some() { return false; }
            }
            if site == 23 && count < 0 && open_return(OpenWire { site: 22, ..failed }, [Some(recheck), None], true).is_some()
                || open_return(failed, [None; 2], true).is_some() || open_return(failed, rechecks, true).is_some()
                || open_return(failed, [Some(final_recheck), None], true).is_some() { return false; }
            // None of the old sites acquires an appended-field exception.
            for site in 1..=21 {
                if open_return(OpenWire { site, ..failed }, [Some(recheck), None], true).is_some() { return false; }
            }
            let generic = OpenWire { site: 20, last_role: 0, last_depth: 0,
                selection_limit_queued: 0, selection_limit_count: 0, ..failed };
            if !open_return(generic, [Some(recheck), None], true).is_some_and(|r| r.selection.limit.is_none() && !r.succeeded()) { return false; }
        }
        let geometry = OpenWire { flags: 8, site: 24, error: 7, checks: 3, last_role: 2, last_depth: 3,
            initial_nodes_examined: 0, recheck_nodes_examined: 0, selection_checks: 0, selection_flags: 0,
            selection_nodes_examined: 12, selection_limit_queued: 34, selection_limit_count: 16, ..full };
        for bad in [OpenWire { selection_limit_count: 15, ..geometry }, // Exactly the remaining15 slots.
            OpenWire { last_role: 1, last_depth: 0, selection_nodes_examined: 0, selection_limit_queued: 1, ..geometry },
            OpenWire { last_depth: 8, selection_nodes_examined: 8, selection_limit_queued: 49, selection_limit_count: 1, ..geometry },
            OpenWire { site: 25, last_depth: 7, selection_nodes_examined: 7, selection_limit_queued: 49, selection_limit_count: 1, ..geometry },
            OpenWire { selection_limit_queued: 1, ..full }, OpenWire { selection_limit_count: 17, ..full }] {
            if open_return(bad, [Some(recheck), None], true).is_some() || open_return(bad, rechecks, true).is_some() { return false; }
        }
        // At queue17, both observed20 and the32-row bound fit; neither is a
        // count/copy/node refusal under the successor policy. No native claim.
        for role in [6, 7] {
            for count in [20, 32] {
                for site in [22, 23, 24] {
                    let fits = OpenWire { site, last_role: role, selection_limit_queued: 17,
                        selection_limit_count: count, ..geometry };
                    if open_return(fits, [Some(recheck), None], true).is_some() { return false; }
                }
            }
        }
        let changed = recheck_return(RecheckWire { prompt: 2, error: 13, ..rw }, 2);
        if !changed.is_some_and(|r| r.custody_known && !r.matched()) { return false; }
        for ns in [1, 99, 10_000_001, 99_999_999, 100_000_000, 2_000_000_000] {
            let Some(t) = timeout_for(Duration::from_nanos(ns)) else { return false; };
            if t.required_ns > ns.min(100_000_000) || t.required_ns == 0
                || t.required_ns != (f64::from(t.seconds) * 1_000_000_000.0).ceil() as u64 { return false; }
        }
        timeout_for(Duration::ZERO).is_none()
            && open_return(OpenWire { flags: 11, error: 11, ax_error: -25204, ..full }, rechecks, true)
                .is_some_and(|r| r.press_returned && r.triggered == Some(false) && !r.succeeded())
            && open_return(OpenWire { error: 8, ..full }, rechecks, true)
                .is_some_and(|r| r.press_returned && r.triggered == Some(true) && !r.succeeded())
            && open_return(OpenWire { flags: 7, error: 9, ..full }, rechecks, false)
                .is_some_and(|r| r.press_returned && !r.custody_known && !r.succeeded())
            && open_return(OpenWire { flags: 1, error: 14, released: 0, ..full }, rechecks, false)
                .is_some_and(|r| r.attempted && !r.press_returned && !r.custody_known)
            && open_return(OpenWire { error: 8, flags: 8, site: 12, ..full }, rechecks, true)
                .is_some_and(|r| !r.attempted && r.custody_known && !r.succeeded())
            && open_return(full, [Some(recheck), None], true).is_none()
            && open_return(full, rechecks, false).is_none()
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
        action_diagnostics_data_check() && identity_data_check() && semantic_data_check() && original_window_data_check()
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
            self.usable().map_err(|_| OpenDiagnostic { site: "entry", error: "ineligible" })?;
            let mut identity = OpenIdentity { parent: [0; 64], panel: [0; 64], prompt: [0; 8], target: [0; 4097] };
            // SAFETY: exact retained main-thread original; copied identity DATA.
            let status = unsafe { mrk_panel_observe_open_identity(self.original.as_ptr(), identity.parent.as_mut_ptr(),
                identity.panel.as_mut_ptr(), identity.prompt.as_mut_ptr(), identity.parent.len(), identity.target.as_mut_ptr(), identity.target.len()) };
            let mut wire = IdentityWire::default();
            unsafe { mrk_panel_observe_identity_data(self.original.as_ptr(), &mut wire); }
            *returned = identity_binding_return(status, wire);
            if status == 0 && returned.is_some_and(|r| r.binding.matched()) && identity.valid() { return Ok(identity); }
            if returned.is_none() || status == 0 || matches!(status, 9 | 14 | 15) || !(1..16).contains(&status) { self.unknown = true; }
            Err(OpenDiagnostic { site: "entry", error: usize::try_from(status).ok().filter(|s| *s != 0)
                .and_then(|s| OPEN_ERRORS.get(s)).copied().unwrap_or("malformed") })
        }
        /// Same original read-only main-thread proof. No input action occurs
        /// here; the enclosing main handler must return its guards before receipt.
        pub fn installed_open_recheck(&mut self, identity: &OpenIdentity, stage: u32) -> Option<OpenRecheckReturn> {
            if self.usable().is_err() || !identity.valid() || !(1..=2).contains(&stage) { return None; }
            let mut wire = RecheckWire::default();
            // SAFETY: exact main-thread original plus bounded copied DATA, no
            // native object or borrowed Panel pointer goes to the AX worker.
            unsafe { mrk_panel_observe_open_recheck(self.original.as_ptr(), identity.parent.as_ptr(), identity.panel.as_ptr(),
                identity.prompt.as_ptr(), identity.target.as_ptr(), identity.target.len(), stage, &mut wire); }
            let returned = recheck_return(wire, stage);
            if !returned.is_some_and(|r| r.custody_known) { self.unknown = true; }
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
