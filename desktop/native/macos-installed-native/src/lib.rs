//! Small Darwin ABI boundary, not an operation owner or an execution permit.
//! The application retains its original slots/tasks and supplies every deadline.
#![cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
#[cfg(all(feature = "installed-observation", not(debug_assertions)))]
compile_error!("installed observation controls require debug assertions in an explicit instrumented build");
// The fixture requires its paired native build and one isolated image graph.
// A Cargo feature or synthetic receipt alone never qualifies fixture identity.
#[cfg(any(
    all(feature = "e2-native-fixture", not(mrk_e2_native_fixture_native)),
    all(mrk_e2_native_fixture_native, not(feature = "e2-native-fixture")),
    all(feature = "e2-native-fixture", any(
        not(any(feature = "desktop-image", feature = "resident-image")),
        all(feature = "desktop-image", feature = "resident-image"),
        feature = "vault-helper", feature = "installed-observation", mrk_wrapping_keychain_qualification
    ))
))]
compile_error!("E2 fixture requires its isolated matching native desktop or resident image role");
#[cfg(all(feature = "e2-native-fixture", feature = "desktop-image", mrk_e2_native_fixture_native))]
pub mod e2_native_fixture;
// Unwired wrapping-key primitive; no availability or execution authority.
pub mod wrapping_keychain;
pub mod vault_filesystem;
pub mod vault_helper_wire;
pub mod vault_helper_filesystem;
#[cfg(not(any(feature = "vault-helper", feature = "android-registration-helper")))]
pub mod vault_helper_launch;
#[cfg(not(any(feature = "installed-observation", feature = "vault-helper", feature = "android-registration-helper",
    feature = "desktop-image")))]
pub mod installed_entry;
pub mod android_lease;
pub mod android_registration;
pub mod android_maintenance_wire;
#[cfg(not(any(feature = "android-registration-helper", feature = "vault-helper")))]
pub mod android_maintenance_client;
#[cfg(feature = "android-registration-helper")]
pub mod installed_image;
pub mod android_catalog_query;
pub mod android_catalog_query_wire;
pub mod android_service_prepare;
#[cfg(feature = "android-registration-helper")]
pub mod android_service_control;
#[cfg(feature = "android-registration-helper")]
pub mod android_service_resident;
pub mod android_service_budget;
#[cfg(not(any(feature = "android-registration-helper", feature = "vault-helper")))]
pub mod android_service_management;
#[cfg(not(any(feature = "android-registration-helper", feature = "vault-helper")))]
pub mod install_producer;
mod android_service_lease;
mod android_service_client_data;
pub const DESKTOP_IMAGE_BUILD: bool = cfg!(feature = "desktop-image");
pub const RESIDENT_IMAGE_BUILD: bool = cfg!(feature = "resident-image");
pub const PACKAGE_PRODUCER_SIGNING_BUILD: bool = cfg!(feature = "package-producer-signing");
#[cfg(all(feature = "package-producer-signing", any(
    feature = "installed-observation", feature = "vault-helper", feature = "android-registration-helper",
    feature = "desktop-image", feature = "resident-image", feature = "e2-native-fixture",
    mrk_wrapping_keychain_qualification
)))]
compile_error!("package producer signing requires its isolated nonshipping native graph");
#[cfg(all(feature = "resident-image", any(not(feature = "android-registration-helper"),
    feature = "desktop-image", feature = "vault-helper", feature = "installed-observation",
    mrk_wrapping_keychain_qualification)))]
compile_error!("resident image requires its isolated native helper graph");
#[cfg(all(feature = "desktop-image", any(feature = "installed-observation", feature = "vault-helper",
    feature = "android-registration-helper", mrk_wrapping_keychain_qualification)))]
compile_error!("ordinary product image requires its isolated native role");
pub const ANDROID_REGISTRATION_HELPER_BUILD: bool = cfg!(feature = "android-registration-helper");
#[cfg(any(
    all(feature = "android-registration-helper", not(mrk_android_registration_helper_native)),
    all(mrk_android_registration_helper_native, not(feature = "android-registration-helper")),
    all(feature = "android-registration-helper", any(feature = "vault-helper", feature = "installed-observation", mrk_wrapping_keychain_qualification))
))]
compile_error!("Android helper requires its isolated matching native Cargo role");
pub const VAULT_HELPER_BUILD: bool = cfg!(feature = "vault-helper");
#[cfg(any(
    all(feature = "vault-helper", not(mrk_wrapping_vault_helper_native)),
    all(mrk_wrapping_vault_helper_native, not(feature = "vault-helper")),
    all(feature = "vault-helper", any(feature = "installed-observation", mrk_wrapping_keychain_qualification))
))]
compile_error!("vault helper requires its isolated matching native Cargo role");
#[cfg(feature = "vault-helper")]
pub mod vault_helper;
use std::{ffi::{c_char, c_int, c_void, CString}, io, marker::PhantomData,
    os::{fd::{AsRawFd, BorrowedFd}, unix::ffi::OsStrExt}, path::{Path, PathBuf}, ptr::NonNull, rc::Rc};

unsafe extern "C" {
    fn mrk_platform() -> c_int;
    #[cfg(test)]
    fn mrk_platform_native_data(sysname: *const c_char, machine: *const c_char, returned: c_int,
        observed_errno: c_int, length: usize, translated: c_int) -> c_int;
    fn mrk_user(uid: *mut u32) -> c_int;
    fn mrk_reveal_installation() -> c_int;
    fn mrk_acl_empty(fd: c_int, phase: *mut c_int, call_result: *mut c_int, native_errno: *mut c_int,
        free_result: *mut c_int, free_errno: *mut c_int) -> c_int;
    fn mrk_no_xattrs(fd: c_int) -> c_int;
    fn mrk_entries(fd: c_int, bytes: *mut u8, capacity: usize, used: *mut usize) -> c_int;
    fn mrk_sync(fd: c_int, file: c_int) -> c_int;
    fn mrk_publish(from: c_int, source: *const c_char, to: c_int, destination: *const c_char) -> c_int;
    fn mrk_swap_installation_state(root: c_int, archived: *const c_char) -> c_int;
    fn mrk_panel_reserve() -> *mut c_void;
    fn mrk_panel_reserve_images() -> *mut c_void;
    fn mrk_panel_start(panel: *mut c_void, kind: c_int) -> c_int;
    fn mrk_panel_start_project_field(panel: *mut c_void, kind: c_int, initial: *const u8, bytes: usize) -> c_int;
    fn mrk_panel_poll(panel: *mut c_void, result: *mut c_int, path: *mut u8, capacity: usize) -> c_int;
    fn mrk_panel_poll_images(panel: *mut c_void, result: *mut c_int, selection: *mut c_int,
        count: *mut usize, paths: *mut u8, capacity: usize) -> c_int;
    fn mrk_panel_close(panel: *mut c_void) -> c_int;
    fn mrk_panel_release(panel: *mut c_void) -> c_int;
    fn mrk_main_thread() -> c_int;
    #[cfg(test)]
    fn mrk_decode_directory_entries(block: *const u8, bytes: usize, count: c_int, out: *mut u8, capacity: usize, used: *mut usize) -> c_int;
    #[cfg(any(test, feature = "installed-observation"))]
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
/// Issue one fixed-location Finder request. The caller retains its original
/// document gate through this synchronous call; there is no callback or worker.
/// Success does not establish Finder visibility or installation integrity.
pub fn reveal_installation() -> io::Result<()> {
    // SAFETY: no pointers or caller-selected path; native checks ordinary user.
    result(unsafe { mrk_reveal_installation() })
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
fn state_archive_component(value: &str) -> io::Result<CString> {
    let invocation = value.strip_prefix(".maintenance-").and_then(|s| s.strip_suffix(".state.json"))
        .ok_or(io::ErrorKind::InvalidInput)?;
    if invocation.len() != 32 || !invocation.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !invocation.bytes().any(|b| b != b'0') { return Err(io::ErrorKind::InvalidInput.into()); }
    CString::new(value).map_err(|_| io::ErrorKind::InvalidInput.into())
}
/// One fixed metadata swap, not an overwrite-capable payload publisher. Caller
/// must hold the original EX gate and BOTH authenticated files, account the
/// actual return, recheck names/content and persist the original parent. No
/// absence fallback, path discovery, file deletion or durability claim here.
pub fn swap_installation_state(root: BorrowedFd<'_>, archived: &str) -> io::Result<()> {
    let archived = state_archive_component(archived)?;
    // SAFETY: borrowed directory and a checked fixed-format NUL-terminated leaf.
    // Native admits two distinct protected metadata files on this filesystem;
    // the canonical name and RENAME_SWAP flags are fixed in the shim.
    result(unsafe { mrk_swap_installation_state(root.as_raw_fd(), archived.as_ptr()) })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PanelKind { Project, Quit, File, VersionSource, IosProject, IosWorkspace, MetadataRoot, EvidenceFolder, PublicImages, AndroidJdk, AndroidSdk, AndroidGradle }
impl PanelKind {
    fn code(self) -> c_int { match self {
        Self::Project => 1, Self::Quit => 2, Self::File => 3, Self::VersionSource => 4,
        Self::IosProject => 5, Self::IosWorkspace => 6, Self::MetadataRoot => 7, Self::EvidenceFolder => 8,
        Self::PublicImages => 9, Self::AndroidJdk => 10, Self::AndroidSdk => 11, Self::AndroidGradle => 12,
    } }
    fn project_field(self) -> bool { matches!(self, Self::VersionSource | Self::IosProject | Self::IosWorkspace | Self::MetadataRoot) }
}
fn project_field_initial(kind: PanelKind, initial: &Path) -> io::Result<&[u8]> {
    let bytes = initial.as_os_str().as_bytes();
    if !kind.project_field() || bytes.is_empty() || bytes.len() > 4096 || bytes[0] != b'/'
        || bytes.contains(&0) || initial.to_str().is_none()
        || bytes != b"/" && bytes[1..].split(|byte| *byte == b'/').any(|part|
            part.is_empty() || part == b"." || part == b".." || part.len() > 255) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(bytes)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PanelResponse { Accept, Decline, Other }
fn panel_response(code: c_int) -> io::Result<PanelResponse> {
    match code { 1 => Ok(PanelResponse::Accept), 2 => Ok(PanelResponse::Decline), 0 => Ok(PanelResponse::Other),
        _ => Err(io::ErrorKind::InvalidData.into()) }
}
pub enum PanelState { Showing, Responded { response: PanelResponse, path: Option<PathBuf> }, Closed }

pub const PUBLIC_IMAGE_COUNT: usize = 10;
pub const PUBLIC_IMAGE_PATH_BYTES: usize = 4097; // includes the native NUL sentinel
const PUBLIC_IMAGE_RESULT_BYTES: usize = PUBLIC_IMAGE_COUNT * PUBLIC_IMAGE_PATH_BYTES;
// Same-time first-party holdings: native batch, Rust poll batch, original
// single-result cell, ten bounded PathBuf allocations and their Vec headers.
// The scalar margin is not permission for a second batch or a pathname clone.
pub const PUBLIC_IMAGE_CONTROL_BYTES: usize = 2 * PUBLIC_IMAGE_RESULT_BYTES + PUBLIC_IMAGE_PATH_BYTES
    + PUBLIC_IMAGE_COUNT * (PUBLIC_IMAGE_PATH_BYTES - 1 + std::mem::size_of::<PathBuf>())
    + std::mem::size_of::<Vec<PathBuf>>() + 512;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicImageRefusal { Count, Path, Capacity }
pub enum PublicImageSelection { Unselected, Paths(Vec<PathBuf>), Refused(PublicImageRefusal) }
pub enum ImagesPanelState { Showing, Responded { response: PanelResponse, selection: PublicImageSelection }, Closed }

fn public_image_selection(response: PanelResponse, selection: c_int, count: usize,
    bytes: &[u8; PUBLIC_IMAGE_RESULT_BYTES]) -> io::Result<PublicImageSelection> {
    // Native refuses the WHOLE batch and clears it, rather than exporting a
    // good prefix. Closed scalar combinations catch ABI corruption separately
    // from a known bad user choice; only the latter permits ordinary cleanup.
    if selection != 1 {
        if count != 0 || bytes.iter().any(|byte| *byte != 0) { return Err(io::ErrorKind::InvalidData.into()); }
        return match (response, selection) {
            (PanelResponse::Decline | PanelResponse::Other, 0) => Ok(PublicImageSelection::Unselected),
            (PanelResponse::Accept, 2) => Ok(PublicImageSelection::Refused(PublicImageRefusal::Count)),
            (PanelResponse::Accept, 3) => Ok(PublicImageSelection::Refused(PublicImageRefusal::Path)),
            _ => Err(io::ErrorKind::InvalidData.into()),
        };
    }
    if response != PanelResponse::Accept || !(1..=PUBLIC_IMAGE_COUNT).contains(&count)
        || bytes[count * PUBLIC_IMAGE_PATH_BYTES..].iter().any(|byte| *byte != 0) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut lengths = [0usize; PUBLIC_IMAGE_COUNT];
    let mut invalid_encoding = false;
    // Validate every member BEFORE allocating/copying any PathBuf. Non-UTF-8
    // selected files are a known input refusal, not a fabricated native Cancel.
    for (index, chunk) in bytes.chunks_exact(PUBLIC_IMAGE_PATH_BYTES).take(count).enumerate() {
        let Some(end) = chunk.iter().position(|byte| *byte == 0) else { return Err(io::ErrorKind::InvalidData.into()); };
        if end == 0 || chunk[0] != b'/' || chunk[end..].iter().any(|byte| *byte != 0) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        invalid_encoding |= std::str::from_utf8(&chunk[..end]).is_err();
        lengths[index] = end;
    }
    if invalid_encoding { return Ok(PublicImageSelection::Refused(PublicImageRefusal::Path)); }
    let mut paths = Vec::new();
    if paths.try_reserve_exact(count).is_err() || paths.capacity() > PUBLIC_IMAGE_COUNT {
        return Ok(PublicImageSelection::Refused(PublicImageRefusal::Capacity));
    }
    for (index, &length) in lengths[..count].iter().enumerate() {
        let start = index * PUBLIC_IMAGE_PATH_BYTES;
        let text = std::str::from_utf8(&bytes[start..start + length]).map_err(|_| io::ErrorKind::InvalidData)?;
        let mut path = PathBuf::new();
        if path.try_reserve_exact(length).is_err() || path.capacity() > PUBLIC_IMAGE_PATH_BYTES - 1 {
            return Ok(PublicImageSelection::Refused(PublicImageRefusal::Capacity));
        }
        path.push(text);
        if path.capacity() > PUBLIC_IMAGE_PATH_BYTES - 1 {
            return Ok(PublicImageSelection::Refused(PublicImageRefusal::Capacity));
        }
        paths.push(path);
    }
    Ok(PublicImageSelection::Paths(paths))
}
/// Main-thread-only original. Drop deliberately does not stand in for native
/// close/release finality: an unresolved object is retained, never retried.
pub struct Panel {
    original: NonNull<c_void>, unknown: bool, _main: PhantomData<Rc<()>>,
    #[cfg(feature = "installed-observation")]
    observation_identity_armed: bool,
    #[cfg(feature = "installed-observation")]
    observation_start: Option<observation::IdentityStartReturn>,
    #[cfg(feature = "installed-observation")]
    observation_completion: Option<observation::CompletionReturn>,
    #[cfg(feature = "installed-observation")]
    observation_completion_captured: bool,
}
pub fn main_thread() -> bool { unsafe { mrk_main_thread() == 1 } }
impl Panel {
    pub fn reserve() -> io::Result<Self> { Self::reserve_original(false) }
    /// Purpose9-only storage on the same retained native original. Singleton
    /// reservations cannot start or poll it, including before presentation.
    pub fn reserve_public_images() -> io::Result<Self> { Self::reserve_original(true) }
    fn reserve_original(images: bool) -> io::Result<Self> {
        // SAFETY: both native constructors enforce the main thread; each
        // returns one original with the SAME existing close/release lifecycle.
        let original = NonNull::new(unsafe {
            if images { mrk_panel_reserve_images() } else { mrk_panel_reserve() }
        }).ok_or(io::ErrorKind::Other)?;
        Ok(Self { original, unknown: false, _main: PhantomData,
            #[cfg(feature = "installed-observation")]
            observation_identity_armed: false,
            #[cfg(feature = "installed-observation")]
            observation_start: None,
            #[cfg(feature = "installed-observation")]
            observation_completion: None,
            #[cfg(feature = "installed-observation")]
            observation_completion_captured: false,
        })
    }
    fn usable(&self) -> io::Result<()> {
        if self.unknown || !main_thread() { Err(io::ErrorKind::Other.into()) } else { Ok(()) }
    }
    pub fn start(&mut self, kind: PanelKind) -> io::Result<()> {
        if kind.project_field() { return Err(io::ErrorKind::InvalidInput.into()); }
        self.start_inner(kind, None)
    }
    /// Only the original native project-field binding supplies this root.
    /// It is an initial location, not selection containment or write authority.
    pub fn start_project_field(&mut self, kind: PanelKind, initial: &Path) -> io::Result<()> {
        let bytes = project_field_initial(kind, initial)?;
        self.start_inner(kind, Some(bytes))
    }
    fn start_inner(&mut self, kind: PanelKind, initial: Option<&[u8]>) -> io::Result<()> {
        #[cfg(feature = "installed-observation")]
        { self.observation_start = None; }
        self.usable()?;
        // SAFETY: retained opaque original, main-thread-only type. EPERM means
        // the native function observed no available parent before construction.
        let status = unsafe { match initial {
            // SAFETY: the complete borrowed UTF-8 slice was checked above and
            // remains live through this synchronous native start/temporary close.
            Some(bytes) => mrk_panel_start_project_field(self.original.as_ptr(), kind.code(), bytes.as_ptr(), bytes.len()),
            None => mrk_panel_start(self.original.as_ptr(), kind.code()),
        } };
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
        #[cfg(feature = "installed-observation")]
        if self.observation_identity_armed && !self.observation_completion_captured {
            // This original poll ACTUALLY returned. Save fixed completion DATA
            // before ANY state/path/error conversion, including the -1 path.
            // A normal early Showing/no-completion poll does not spend the slot.
            if let Some(returned) = observation::completion_return(self.original, state) {
                self.observation_completion = Some(returned);
                self.observation_completion_captured = true;
            }
        }
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
    pub fn poll_public_images(&mut self) -> io::Result<ImagesPanelState> {
        self.usable()?;
        let mut response = 0; let mut selection = 0; let mut count = 0;
        let mut paths = [0u8; PUBLIC_IMAGE_RESULT_BYTES];
        // SAFETY: exact bounded batch and scalar cells on this same main-thread
        // original. C rejects singleton reservations even before start; no
        // singleton cell is consumed. An unstarted IMAGE reservation can only
        // show/close, never select.
        let state = unsafe { mrk_panel_poll_images(self.original.as_ptr(), &mut response, &mut selection,
            &mut count, paths.as_mut_ptr(), paths.len()) };
        let returned = match state {
            0 => Ok(ImagesPanelState::Showing),
            1 => panel_response(response).and_then(|response| {
                public_image_selection(response, selection, count, &paths)
                    .map(|selection| ImagesPanelState::Responded { response, selection })
            }),
            2 => Ok(ImagesPanelState::Closed),
            _ => Err(io::ErrorKind::Other.into()),
        };
        if returned.is_err() { self.unknown = true; }
        returned
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
    OpenInputReturn, OpenPressTiming, OpenRecheckReturn, ControlContainerButtonProof, AxFailure, CompletionSelection, CompletionReturn, installed_prompt_button,
    IdentityConfiguration, IdentityStartReturn, IdentityBinding, IdentityBindingReturn,
    OriginalWindowState, OriginalWindowReturn, ProjectFieldPreparation, VersionSourceNamePreparation, VersionSourceParentReady, VersionSourceSelectionReady, VersionSourceSelection, SelectionLimit, SelectionProjectionSummary, ContentReadiness, installed_original_window,
    installed_accessibility_trusted, installed_observation_flags_data_check};
#[cfg(feature = "installed-observation")]
mod observation {
    use super::*;
    use std::{path::Path, os::unix::ffi::OsStrExt, panic::{catch_unwind, AssertUnwindSafe}, time::{Duration, Instant}};

    pub enum PanelAction { ProjectCancel, QuitCancel, QuitConfirm, FileCancel }
    /// Closed labels copied from one original return, never a native query or
    /// action/finality permit. Missing/invalid DATA does not change that return.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PanelActionDiagnostic {
        pub action: &'static str, pub domain: &'static str,
        pub site: &'static str, pub error: &'static str,
    }
    fn action_name(action: c_int) -> Option<&'static str> {
        match action { 1 => Some("project-cancel"), 2 => Some("project-directory"), 3 => Some("project-open"),
            4 => Some("quit-cancel"), 5 => Some("quit-confirm"), 6 => Some("file-cancel"), _ => None }
    }
    // Same numbered sites and Darwin errno values as the feature-gated shim.
    // Codes 2/3 remain historical diagnostic DATA only, never callable actions.
    // label, original native-return status (-1 = exception-only), action mask,
    // whether an EXISTING Objective-C query/action at this site can throw.
    const ACTION_SITES: [(&str, c_int, u8, bool); 36] = [
        ("main-thread", 22, 63, false), ("state-pointer", 22, 63, false),
        ("action-code", 22, 63, false), ("directory-argument", 22, 63, false),
        ("original-unknown", 5, 63, false), ("not-started", 1, 63, false),
        ("window-absent", 1, 63, false), ("parent-absent", 1, 63, false),
        ("completion-absent", 1, 63, false), ("responded", 1, 63, false),
        ("callback-active", 1, 63, false), ("close-attempted", 1, 63, false),
        ("closed", 1, 63, false), ("action-attempted", 1, 63, false),
        ("panel-kind", 1, 63, false), ("attachment", 35, 63, true),
        ("directory-already-bound", 1, 2, false), ("directory-path", 22, 2, false),
        ("directory-text", 22, 2, true), ("directory-url", 22, 2, true),
        ("directory-set", 0, 2, true), ("directory-unbound", 1, 4, false),
        ("directory-not-returned", 1, 4, false), ("directory-ready", 35, 4, true),
        ("alert-buttons", -1, 24, true), ("alert-absent", 1, 24, false),
        ("button-count", 1, 24, true), ("button-index", -1, 24, true),
        ("button-window", 1, 24, true), ("button-enabled", 35, 24, true),
        ("button-hidden", 35, 24, true), ("project-cancel", 0, 1, true),
        ("project-open", 0, 4, true), ("quit-cancel", 0, 8, true), ("quit-confirm", 0, 16, true), ("file-cancel", 0, 32, true),
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
        for action in 1..=6 {
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
            && [0, 7, -1].into_iter().all(|action| action_return_diagnostic(action, 5, 0x20021).is_none())
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
        /// Closed diagnostic from the same query; never an action or completion receipt.
        pub directory_readiness: &'static str,
        /// Same returned sample's intermediate parent DATA, never full readiness.
        pub version_source_parent_ready: Option<VersionSourceParentReady>,
        /// A different one-use sample: permits selection preparation, not Open.
        pub version_source_selection_ready: Option<VersionSourceSelectionReady>,
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
    /// Opaque main-thread DATA from one returned native sample. Moving it does
    /// not grant an action: the same original, owner, pending slot and native
    /// sample generation must still admit the one-use name preparation.
    pub struct VersionSourceParentReady { original: NonNull<c_void>, sample: u32 }
    pub struct VersionSourceSelectionReady { original: NonNull<c_void>, sample: u32 }
    impl PanelObservation {
        pub fn version_source_name_ready(&self) -> bool {
            self.kind == PanelKind::VersionSource && self.started && self.attached
                && self.parent_present && self.panel_present && self.parent_references_panel == Some(true)
                && self.panel_references_parent == Some(true) && self.panel_visible == Some(true)
                && self.directory_bound && self.directory_returned && !self.directory_ready
                && self.directory_readiness == "not-ready"
                && self.version_source_parent_ready.as_ref().is_some_and(|sample| sample.sample != 0)
                && self.version_source_selection_ready.is_none()
                && !self.action_attempted && !self.action_returned && !self.callback_returned
                && self.response.is_none() && self.selected.is_none()
                && !self.close_attempted && !self.dismissed && !self.closed
        }
        pub fn version_source_selection_ready(&self) -> bool {
            self.kind == PanelKind::VersionSource && self.started && self.attached
                && self.parent_present && self.panel_present && self.parent_references_panel == Some(true)
                && self.panel_references_parent == Some(true) && self.panel_visible == Some(true)
                && self.directory_bound && self.directory_returned
                && matches!((self.directory_ready, self.directory_readiness),
                    (false, "selection-not-matched") | (true, "ready"))
                && self.version_source_parent_ready.is_none()
                && self.version_source_selection_ready.as_ref().is_some_and(|sample| sample.sample != 0)
                && !self.action_attempted && !self.action_returned && !self.callback_returned
                && self.response.is_none() && self.selected.is_none()
                && !self.close_attempted && !self.dismissed && !self.closed
        }
    }
    /// Saved scalar DATA from a returned original initial-root/navigation
    /// preparation. It does not include VersionSource's later name phase.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ProjectFieldPreparation { pub result: &'static str, pub facts: Option<u32>, pub file_filter: Option<u32> }
    impl ProjectFieldPreparation {
        pub fn succeeded(self, kind: PanelKind, navigate: bool) -> bool {
            kind.project_field() && self.result == "ok"
                && self.facts == Some(511 | 4096 | if navigate { 512 | 1024 } else { 0 })
                && if kind == PanelKind::VersionSource { matches!(self.file_filter, Some(23 | 27 | 55 | 59)) }
                    else { self.file_filter == Some(0) }
        }
    }
    /// Separate closed five-bit original name receipt: phase entry, saved
    /// parent/current topology admission, setter entry, setter return, cleanup.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct VersionSourceNamePreparation { pub result: &'static str, pub facts: Option<u32> }
    impl VersionSourceNamePreparation {
        pub fn succeeded(self) -> bool { self.result == "ok" && self.facts == Some(31) }
    }
    fn project_field_result(status: c_int) -> &'static str {
        match status { 0 => "ok", 1 => "permission-denied", 5 => "io", 22 => "invalid-input",
            35 => "would-block", 37 => "already", _ => "invalid-return" }
    }
    fn project_field_preparation(status: c_int, flags: u32, filter: u32) -> ProjectFieldPreparation {
        // Bit2048 is no longer a navigation fact. Historical failure DATA is
        // parsed separately; no old8191 mask can stand in for the new name call.
        let valid = flags & !6143 == 0 && (flags == 0 || flags & 257 == 257)
            && (flags & 512 == 0 || flags & 511 == 511) && (flags & 1024 == 0 || flags & 512 != 0)
            && (status != 35 || flags == 0);
        // Closed one-call getter prefix; zero means not sampled for this kind.
        // Nil/empty content types and nonempty restriction are distinct, but
        // neither permits selection. No UTI strings or borrowed objects cross.
        let filter_valid = matches!(filter, 0 | 1 | 3 | 7 | 11 | 23 | 27 | 55 | 59)
            && (filter == 0 || flags & 511 == 511);
        ProjectFieldPreparation { result: project_field_result(status), facts: valid.then_some(flags),
            file_filter: filter_valid.then_some(filter) }
    }
    fn version_source_name_preparation(status: c_int, flags: u32) -> VersionSourceNamePreparation {
        let valid = flags & !31 == 0 && (flags == 0 || flags & 1 != 0)
            && (flags & 4 == 0 || flags & 3 == 3) && (flags & 8 == 0 || flags & 4 != 0)
            && status != 35;
        VersionSourceNamePreparation { result: project_field_result(status), facts: valid.then_some(flags) }
    }
    fn version_source_parent_matches(sample: &VersionSourceParentReady, original: NonNull<c_void>) -> bool {
        sample.original == original && sample.sample != 0
    }
    fn version_source_name_data_check() -> bool {
        // Inert addresses and scalar DATA only; no native Panel is constructed.
        let original = NonNull::<c_void>::dangling();
        let fresh = || PanelObservation { kind: PanelKind::VersionSource, started: true, attached: true,
            parent_present: true, panel_present: true, parent_references_panel: Some(true),
            panel_references_parent: Some(true), panel_visible: Some(true),
            directory_bound: true, directory_returned: true, directory_ready: false, directory_readiness: "not-ready",
            version_source_parent_ready: Some(VersionSourceParentReady { original, sample: 1 }),
            version_source_selection_ready: None,
            action_attempted: false, action_returned: false, callback_returned: false, response: None, selected: None,
            close_attempted: false, dismissed: false, closed: false };
        if !fresh().version_source_name_ready() || fresh().directory_ready { return false; }
        let invalid: &[fn(&mut PanelObservation)] = &[
            |p| p.started = false, |p| p.attached = false, |p| p.parent_present = false, |p| p.panel_present = false,
            |p| p.parent_references_panel = Some(false), |p| p.panel_references_parent = None,
            |p| p.panel_visible = Some(false), |p| p.directory_bound = false, |p| p.directory_returned = false,
            |p| p.directory_ready = true, |p| p.directory_readiness = "directory-not-matched",
            |p| p.version_source_parent_ready = None,
            |p| p.version_source_parent_ready.as_mut().unwrap().sample = 0,
            |p| p.action_attempted = true, |p| p.action_returned = true, |p| p.callback_returned = true,
            |p| p.response = Some(PanelResponse::Accept), |p| p.selected = Some(PathBuf::from("/inert-data-not-opened")),
            |p| p.close_attempted = true, |p| p.dismissed = true, |p| p.closed = true,
        ];
        for change in invalid { let mut sample = fresh(); change(&mut sample); if sample.version_source_name_ready() { return false; } }
        for kind in [PanelKind::Project, PanelKind::Quit, PanelKind::File, PanelKind::IosProject, PanelKind::IosWorkspace, PanelKind::MetadataRoot, PanelKind::EvidenceFolder, PanelKind::PublicImages] {
            let mut sample = fresh(); sample.kind = kind; if sample.version_source_name_ready() { return false; }
        }
        let sample = fresh().version_source_parent_ready.unwrap();
        let mut other_byte = 0u8; let other = NonNull::from(&mut other_byte).cast::<c_void>();
        if !version_source_parent_matches(&sample, original) || version_source_parent_matches(&sample, other)
            || version_source_parent_matches(&VersionSourceParentReady { original, sample: 0 }, original) { return false; }
        for flags in 0..64 {
            let expected = [0, 1, 3, 7, 15, 17, 19, 23, 31].contains(&flags);
            if version_source_name_preparation(5, flags).facts.is_some() != expected
                || version_source_name_preparation(0, flags).succeeded() != (flags == 31) { return false; }
        }
        for status in [1, 5, 22, 35, 37, -1] {
            if version_source_name_preparation(status, 31).succeeded() { return false; }
        }
        let selecting = || {
            let mut panel = fresh();
            panel.version_source_parent_ready = None;
            panel.version_source_selection_ready = Some(VersionSourceSelectionReady { original, sample: 2 });
            panel.directory_readiness = "selection-not-matched"; panel
        };
        if !selecting().version_source_selection_ready() || selecting().version_source_name_ready()
            || selecting().directory_ready || fresh().version_source_selection_ready() { return false; }
        let changes: &[fn(&mut PanelObservation)] = &[
            |p| p.version_source_selection_ready = None,
            |p| p.version_source_selection_ready.as_mut().unwrap().sample = 0,
            |p| p.kind = PanelKind::File, |p| p.started = false, |p| p.attached = false,
            |p| p.directory_bound = false, |p| p.directory_returned = false,
            |p| p.directory_readiness = "directory-not-matched", |p| p.directory_ready = true,
            |p| p.parent_references_panel = Some(false), |p| p.panel_references_parent = None,
            |p| p.action_attempted = true, |p| p.callback_returned = true,
            |p| p.close_attempted = true, |p| p.dismissed = true,
        ];
        for change in changes { let mut sample = selecting(); change(&mut sample); if sample.version_source_selection_ready() { return false; } }
        let mut ready = selecting(); ready.directory_ready = true; ready.directory_readiness = "ready";
        if !ready.version_source_selection_ready() || ready.version_source_name_ready() { return false; }
        // An exception after setter entry/return may retain known cleanup, but
        // neither partial flags nor a nonzero native result becomes success.
        version_source_name_preparation(5, 23).facts == Some(23)
            && !version_source_name_preparation(5, 31).succeeded()
            && version_source_name_preparation(35, 0).facts.is_none()
    }
    fn project_field_data_check() -> bool {
        // Pure spelling/ABI DATA in the existing observer entry. No Panel,
        // AppKit call, filesystem operation or additional test runner exists.
        for kind in [PanelKind::VersionSource, PanelKind::IosProject, PanelKind::IosWorkspace, PanelKind::MetadataRoot] {
            if project_field_initial(kind, Path::new("/Users/owner/project")).ok() != Some(b"/Users/owner/project".as_slice()) {
                return false;
            }
            for invalid in ["", "relative", "//Users", "/Users/../project", "/Users/./project", "/Users/project/", "/Users/a\0b"] {
                if project_field_initial(kind, Path::new(invalid)).is_ok() { return false; }
            }
            let filter = if kind == PanelKind::VersionSource { 55 } else { 0 };
            for navigate in [false, true] {
                let mask = 511 | 4096 | if navigate { 512 | 1024 } else { 0 };
                if !project_field_preparation(0, mask, filter).succeeded(kind, navigate) { return false; }
                for bit in 0..13 {
                    if project_field_preparation(0, mask ^ (1 << bit), filter).succeeded(kind, navigate) { return false; }
                }
                for status in [1, 5, 22, 35, 37, -1] {
                    if project_field_preparation(status, mask, filter).succeeded(kind, navigate) { return false; }
                }
            }
        }
        for kind in [PanelKind::Project, PanelKind::File, PanelKind::Quit, PanelKind::EvidenceFolder, PanelKind::PublicImages] {
            if project_field_initial(kind, Path::new("/Users/owner/project")).is_ok()
                || project_field_preparation(0, 511 | 4096, 0).succeeded(kind, false) { return false; }
        }
        for flags in [2048, 8191, 8192, 1, 256, 512, 257 | 1024, 257 | 2048, 4096, u32::MAX] {
            if project_field_preparation(5, flags, 0).facts.is_some() { return false; }
        }
        for filter in 0..=64 {
            let sample = project_field_preparation(0, 6143, filter);
            if sample.succeeded(PanelKind::VersionSource, true) != matches!(filter, 23 | 27 | 55 | 59)
                || sample.succeeded(PanelKind::IosProject, true) != (filter == 0) { return false; }
        }
        project_field_preparation(35, 0, 0) == (ProjectFieldPreparation { result: "would-block", facts: Some(0), file_filter: Some(0) })
            && project_field_preparation(35, 257, 0).facts.is_none()
            && project_field_initial(PanelKind::VersionSource, Path::new(&format!("/{}", "a".repeat(4096)))).is_err()
            && version_source_name_data_check()
    }
    unsafe extern "C" {
        fn mrk_observation_original_window(original: usize, flags: *mut u32) -> c_int;
        fn mrk_panel_observe(panel: *mut c_void, kind: *mut c_int, flags: *mut u32,
            response: *mut c_int, path: *mut u8, capacity: usize, name_sample: *mut u32) -> c_int;
        fn mrk_panel_observe_action(panel: *mut c_void, action: c_int, directory: *const c_char,
            diagnostic: *mut u32) -> c_int;
        fn mrk_panel_observe_project_field(panel: *mut c_void, navigate: c_int, facts: *mut u32, filter: *mut u32) -> c_int;
        fn mrk_panel_observe_version_source_name(panel: *mut c_void, sample: u32, facts: *mut u32) -> c_int;
        fn mrk_observation_ax_trusted() -> c_int;
        fn mrk_panel_observe_arm_open_identity(panel: *mut c_void, target: *const u8, capacity: usize) -> c_int;
        fn mrk_panel_observe_identity_data(panel: *mut c_void, data: *mut IdentityWire);
        fn mrk_panel_observe_completion_data(panel: *mut c_void, data: *mut CompletionWire);
        fn mrk_panel_observe_open_identity(panel: *mut c_void, parent: *mut u8, sheet: *mut u8,
            prompt: *mut u8, capacity: usize, target: *mut u8, target_capacity: usize, selection_sample: u32) -> c_int;
        fn mrk_panel_observe_open_recheck(panel: *mut c_void, parent: *const u8, sheet: *const u8,
            prompt: *const u8, target: *const u8, target_capacity: usize, selection: u32, stage: u32, result: *mut RecheckWire);
        fn mrk_observation_prompt_press(parent: *const u8, sheet: *const u8, prompt: *const u8, capacity: usize,
            target: *const u8, target_capacity: usize, selection: u32,
            admission: unsafe extern "C" fn(*mut c_void, u64, c_int, *mut OpenTimeout) -> c_int,
            recheck: unsafe extern "C" fn(*mut c_void, c_int) -> c_int,
            context: *mut c_void, result: *mut OpenWire);
    }
    /// Original copied identity only; no native object leaves its main owner.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct OpenIdentity { parent: [u8; 64], panel: [u8; 64], prompt: [u8; 8], target: [u8; 4097], selection: bool }
    impl OpenIdentity {
        pub fn selects_version_source(&self) -> bool { self.selection }
        fn valid(self) -> bool {
            identity_tag(&self.parent, b"mrk-parent-") && identity_actual(&self.panel) && self.parent != self.panel
                && self.prompt.starts_with(b"MRK") && self.prompt[7] == 0
                && self.prompt[3..7].iter().zip(&self.parent[11..15]).all(|(p, b)| *p == b.to_ascii_uppercase())
                && project_target(&self.target)
        }
        pub fn targets(&self, path: &Path) -> bool { project_target(&self.target) && path.as_os_str().as_bytes() == self.target.split(|b| *b == 0).next().unwrap_or(&[]) }
    }
    fn project_target(bytes: &[u8; 4097]) -> bool {
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
    const IDENTITY_SITES: [Option<&str>; 13] = [None, Some("objects"), Some("parent-tag"), Some("parent-set"),
        Some("parent-get"), Some("complete"), Some("prompt-set"), Some("prompt-get"),
        Some("initial-directory-url"), Some("initial-directory-set"), Some("file-name-set"), Some("file-name-get"), Some("initial-temporary-close")];
    const PANEL_ID_CLASSES: [Option<&str>; 10] = [None, Some("nil"), Some("type-invalid"), Some("empty"),
        Some("byte-limit"), Some("nul"), Some("encoding-invalid"), Some("valid"), Some("match"), Some("different")];
    const PROOF_SITES: [&str; 14] = ["objects", "attachment", "directory", "parent-identifier", "panel-identifier",
        "parent-sheets", "panel-sheets", "panel-attached-sheet", "native-children", "native-parent", "native-role",
        "stable-identifier", "final-eligibility", "complete"];
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct IdentityConfiguration {
        pub attempted: bool, pub parent_setter_entered: bool, pub parent_setter_returned: bool,
        pub prompt_setter_entered: bool, pub prompt_setter_returned: bool,
        pub initial_directory_setter_entered: bool, pub initial_directory_setter_returned: bool,
        pub file_panel: bool, pub file_name_setter_entered: bool, pub file_name_setter_returned: bool,
        pub parent: Option<&'static str>, pub prompt: Option<&'static str>,
        pub site: Option<&'static str>, pub error: Option<&'static str>,
    }
    impl IdentityConfiguration {
        pub fn complete(self) -> bool {
            self.attempted && self.parent_setter_entered && self.parent_setter_returned
                && self.prompt_setter_entered && self.prompt_setter_returned && self.prompt == Some("match")
                && self.initial_directory_setter_entered && self.initial_directory_setter_returned
                && self.file_name_setter_entered == self.file_panel && self.file_name_setter_returned == self.file_panel
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
        pub purpose: &'static str,
        pub attempted: bool, pub parent: Option<&'static str>, pub panel: Option<&'static str>,
        pub checks: [Option<bool>; 12], pub children: Option<u32>, pub originals: Option<&'static str>,
        pub site: &'static str, pub error: &'static str,
    }
    impl IdentityBinding {
        pub fn matched(self) -> bool { self.purpose == "full-open" && self.complete() }
        pub fn selection_parent_matched(self) -> bool { self.purpose == "selection-parent" && self.complete() }
        fn complete(self) -> bool {
            self.attempted && self.parent == Some("match") && self.panel == Some("match")
                && self.checks == [Some(true); 12] && self.children.is_some_and(|n| (1..=16).contains(&n))
                && self.originals == Some("one") && self.site == "complete" && self.error == "none"
        }
    }
    #[derive(Clone, Copy)]
    pub struct IdentityBindingReturn { pub configuration: IdentityConfiguration, pub binding: IdentityBinding }
    fn identity_configuration(w: IdentityWire) -> Option<IdentityConfiguration> {
        if w.flags & !4095 != 0 || w.flags & 1 == 0 { return None; }
        let parent = *IDENTITY_CLASSES.get(w.parent as usize)?;
        let prompt = *IDENTITY_CLASSES.get(w.prompt as usize)?;
        let c = IdentityConfiguration {
            attempted: w.flags & 2 != 0, parent_setter_entered: w.flags & 4 != 0, parent_setter_returned: w.flags & 8 != 0,
            prompt_setter_entered: w.flags & 32 != 0, prompt_setter_returned: w.flags & 64 != 0,
            initial_directory_setter_entered: w.flags & 128 != 0, initial_directory_setter_returned: w.flags & 256 != 0,
            file_panel: w.flags & 512 != 0, file_name_setter_entered: w.flags & 1024 != 0, file_name_setter_returned: w.flags & 2048 != 0,
            parent, prompt, site: *IDENTITY_SITES.get(w.site as usize)?,
            error: (w.flags & 2 != 0).then_some(*OPEN_ERRORS.get(w.error as usize)?),
        };
        if !c.attempted {
            return (w.flags == 1 && w.site == 0 && w.error == 0 && parent.is_none() && prompt.is_none()).then_some(c);
        }
        // File-only setter states do not change the original project ABI.
        // The kind bit is set by the original native constructor, not callers.
        let file_flags = w.flags & (512 | 1024 | 2048);
        let base_flags = w.flags & 511;
        let file_valid = match w.site {
            10 => file_flags == (512 | 1024) && base_flags == 495 && w.error == 14,
            11 => file_flags == (512 | 1024 | 2048) && base_flags == 495 && matches!(w.error, 13 | 14),
            5 if c.file_panel => file_flags == (512 | 1024 | 2048),
            _ => file_flags == if c.file_panel { 512 } else { 0 },
        };
        if !file_valid { return None; }
        let valid = match (w.site, w.error) {
            (10 | 11, 13 | 14) if c.file_panel => parent.is_some() && prompt == Some("match"),
            (1, 3) | (2, 2 | 14) => base_flags == 3 && parent.is_none() && prompt.is_none(),
            (3, 14) => base_flags == 7 && parent.is_none() && prompt.is_none(),
            (4, 14) => base_flags == 15 && parent.is_none() && prompt.is_none(),
            (6, 14) => base_flags == 47 && parent.is_some() && prompt.is_none(),
            (7, 14) => base_flags == 111 && parent.is_some() && prompt.is_none(),
            (7, 13) => base_flags == 111 && parent.is_some() && matches!(prompt, Some("nil" | "different" | "type-invalid")),
            (8, 2 | 14) => base_flags == 111 && parent.is_some() && prompt == Some("match"),
            (9, 14) => base_flags == 239 && parent.is_some() && prompt == Some("match"),
            (12, 15) => !c.file_panel && matches!(base_flags, 111 | 239 | 495) && parent.is_some() && prompt == Some("match"),
            (5, 0) => base_flags == 511 && c.complete(),
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
        if c_int::try_from(w.error).ok() != Some(status) || !matches!(w.flags, 0 | 1 | 3) || w.checked & !0xfff != 0
            || w.matched & !w.checked != 0 || w.children > 18 { return None; }
        let b = IdentityBinding {
            purpose: if w.flags & 2 != 0 { "selection-parent" } else { "full-open" },
            attempted: w.flags & 1 != 0, parent: *IDENTITY_CLASSES.get(w.parent as usize)?,
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
            || (b.site == "complete") != (b.error == "none") || b.error == "none" && !b.complete() { return None; }
        Some(b)
    }
    fn identity_binding_return(status: c_int, w: IdentityWire) -> Option<IdentityBindingReturn> {
        let configuration = identity_configuration(w)?;
        if !configuration.complete() { return None; }
        Some(IdentityBindingReturn { configuration, binding: identity_proof(status, w.binding)? })
    }
    fn identity_data_check() -> bool {
        // Inert scalar DATA only: no panel/owner/native call or return is made.
        if std::mem::size_of::<IdentityWire>() != 56 || std::mem::size_of::<IdentityProofWire>() != 36 { return false; }
        let empty = IdentityWire { flags: 1, ..IdentityWire::default() };
        if !identity_configuration(empty).is_some_and(|c| !c.attempted && !c.complete() && c.parent.is_none())
            || identity_configuration(IdentityWire::default()).is_some() { return false; }
        for parent in 1..=4 {
            let configured = IdentityWire { flags: 511, parent, prompt: 2, site: 5, ..IdentityWire::default() };
            if !identity_configuration(configured).is_some_and(|c| c.complete() && !c.file_panel)
                || !identity_configuration(IdentityWire { flags: 4095, ..configured }).is_some_and(|c|
                    c.complete() && c.file_panel && c.file_name_setter_entered && c.file_name_setter_returned) { return false; }
        }
        for (flags, site) in [(3, 2), (7, 3), (15, 4)] {
            let partial = IdentityWire { flags, site, error: 14, ..IdentityWire::default() };
            if !identity_configuration(partial).is_some_and(|c| !c.complete())
                || !identity_configuration(IdentityWire { flags: flags | 512, ..partial }).is_some_and(|c|
                    c.file_panel && !c.complete() && !c.file_name_setter_entered && !c.file_name_setter_returned)
                || identity_configuration(IdentityWire { parent: 2, ..partial }).is_some() { return false; }
        }
        for (flags, site, error) in [(111, 8, 2), (111, 8, 14), (239, 9, 14)] {
            let partial = IdentityWire { flags, site, error, parent: 2, prompt: 2, ..IdentityWire::default() };
            if !identity_configuration(partial).is_some_and(|c| !c.complete()
                && c.initial_directory_setter_entered == (site == 9) && !c.initial_directory_setter_returned)
                || identity_configuration(IdentityWire { flags: flags | 256, ..partial }).is_some() { return false; }
        }
        // P2 initial-location temporary retirement may fail before/after the
        // setter returned. Preserve the actual partial chronology, not success.
        for flags in [111, 239, 495] {
            let partial = IdentityWire { flags, site: 12, error: 15, parent: 2, prompt: 2, ..IdentityWire::default() };
            if !identity_configuration(partial).is_some_and(|c| !c.complete() && !c.file_panel
                && c.error == Some("cleanup-unknown") && c.initial_directory_setter_returned == (flags == 495))
                || identity_configuration(IdentityWire { flags: flags | 16, ..partial }).is_some()
                || identity_configuration(IdentityWire { flags: flags | 512, ..partial }).is_some() { return false; }
        }
        // Exact entered/returned distinction for the actual File-only setter
        // and getter. Neither a partial nor a wrong kind may become complete.
        for (flags, site, error) in [(2031, 10, 14), (4079, 11, 14), (4079, 11, 13)] {
            let partial = IdentityWire { flags, site, error, parent: 2, prompt: 2, ..IdentityWire::default() };
            if !identity_configuration(partial).is_some_and(|c| c.file_panel && !c.complete()
                && c.initial_directory_setter_returned && c.file_name_setter_entered
                && c.file_name_setter_returned == (site == 11)) { return false; }
            for changed in [IdentityWire { flags: flags & !512, ..partial }, IdentityWire { flags: flags | 16, ..partial },
                IdentityWire { flags: flags ^ 2048, ..partial }, IdentityWire { prompt: 3, ..partial },
                IdentityWire { error: 0, ..partial }, IdentityWire { site: 5, ..partial }] {
                if identity_configuration(changed).is_some() { return false; }
            }
        }
        let proof = IdentityProofWire { flags: 1, checked: 0xfff, matched: 0xfff, parent: 2, panel: 8,
            children: 2, originals: 2, site: 14, error: 0 };
        if !identity_proof(0, proof).is_some_and(IdentityBinding::matched)
            || identity_proof(0, proof).is_some_and(IdentityBinding::selection_parent_matched)
            || !identity_proof(0, IdentityProofWire { flags: 3, ..proof }).is_some_and(|p|
                p.selection_parent_matched() && !p.matched()) { return false; }
        // Every exact native edge, singleton and no-nested check is mandatory.
        for bit in 0..12 {
            let missing = IdentityProofWire { checked: proof.checked & !(1 << bit), matched: proof.matched & !(1 << bit), ..proof };
            if identity_proof(0, missing).is_some() { return false; }
            let changed = IdentityProofWire { matched: proof.matched & !(1 << bit), site: 13, error: 13, ..proof };
            if identity_proof(13, changed).is_some_and(IdentityBinding::matched) { return false; }
        }
        for bad in [IdentityProofWire { panel: 7, ..proof }, IdentityProofWire { parent: 3, ..proof },
            IdentityProofWire { children: 18, ..proof }, IdentityProofWire { originals: 3, ..proof },
            IdentityProofWire { flags: 2, ..proof }, IdentityProofWire { flags: 5, ..proof }, IdentityProofWire { checked: 0x1fff, ..proof }] {
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
        let configured = IdentityWire { flags: 511, parent: 2, prompt: 2, site: 5, binding: proof, ..IdentityWire::default() };
        let early = IdentityProofWire { flags: 1, checked: 1, matched: 0, site: 1, error: 3, ..IdentityProofWire::default() };
        identity_binding_return(0, configured).is_some_and(|r| r.binding.matched())
            && identity_binding_return(0, IdentityWire { flags: 4095, ..configured })
                .is_some_and(|r| r.configuration.file_panel && r.binding.matched())
            && identity_binding_return(14, configured).is_none()
            && identity_binding_return(0, IdentityWire { binding: IdentityProofWire::default(), ..configured }).is_none()
            && identity_binding_return(3, IdentityWire { binding: early, ..configured }).is_some_and(|r| !r.binding.matched())
            && identity_configuration(IdentityWire { flags: 127, ..configured }).is_none()
            && identity_configuration(IdentityWire { flags: 255, ..configured }).is_none()
            && identity_configuration(IdentityWire { flags: 1023, ..configured }).is_none()
            && identity_configuration(IdentityWire { prompt: 3, ..configured }).is_none()
            && identity_configuration(IdentityWire { flags: 31, ..configured }).is_none()
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default, PartialEq, Eq)]
    struct CompletionWire { flags: u32, response: u32, selection: u32 }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CompletionSelection {
        pub callback_entered: bool, pub urls_read_entered: bool, pub urls_read_returned: bool,
        pub callback_returned: bool, pub duplicate: bool, pub native_unknown: bool,
        pub response: Option<&'static str>, pub selection: Option<&'static str>,
    }
    impl CompletionSelection {
        pub fn matched(self) -> bool {
            self.callback_entered && self.urls_read_entered && self.urls_read_returned && self.callback_returned
                && !self.duplicate && !self.native_unknown && self.response == Some("accept") && self.selection == Some("match")
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CompletionReturn { pub poll_result: &'static str, pub facts: Option<CompletionSelection> }
    impl CompletionReturn {
        pub fn succeeded(self) -> bool { self.poll_result == "responded" && self.facts.is_some_and(CompletionSelection::matched) }
    }
    fn completion_selection(w: CompletionWire) -> Option<CompletionSelection> {
        if w.flags & !63 != 0 { return None; }
        let r = CompletionSelection {
            callback_entered: w.flags & 1 != 0, urls_read_entered: w.flags & 2 != 0, urls_read_returned: w.flags & 4 != 0,
            callback_returned: w.flags & 8 != 0, duplicate: w.flags & 16 != 0, native_unknown: w.flags & 32 != 0,
            response: *[None, Some("accept"), Some("decline"), Some("other")].get(w.response as usize)?,
            selection: *[None, Some("empty"), Some("malformed"), Some("multiple"), Some("different"),
                Some("ordinary-path-disagreement"), Some("match")].get(w.selection as usize)?,
        };
        if !r.callback_entered && (w.flags & !32 != 0 || r.response.is_some() || r.selection.is_some())
            || r.urls_read_entered && r.response != Some("accept")
            || r.urls_read_returned && !r.urls_read_entered
            || r.selection.is_some() && !r.urls_read_returned
            || r.duplicate && !r.native_unknown { return None; }
        let incomplete = if r.response == Some("accept") { !r.urls_read_returned || r.selection.is_none() }
            else { r.urls_read_entered || r.selection.is_some() };
        if !r.native_unknown && (!r.callback_entered || !r.callback_returned || r.response.is_none() || incomplete) { return None; }
        Some(r)
    }
    fn completion_poll_return(w: CompletionWire, status: c_int) -> Option<CompletionReturn> {
        if status == 0 && w == CompletionWire::default() { return None; }
        // No completion on an earlier Showing poll is absence, not publication.
        // All other actual returns keep their history (or invalid DATA) once.
        let poll_result = match status { 0 => "showing", 1 => "responded", 2 => "closed", -1 => "error", _ => "invalid-return" };
        Some(CompletionReturn { poll_result, facts: completion_selection(w) })
    }
    pub(super) fn completion_return(original: NonNull<c_void>, status: c_int) -> Option<CompletionReturn> {
        let mut wire = CompletionWire::default();
        // SAFETY: immediate post-poll scalar copy from the same retained original,
        // BEFORE usable/error conversion or release. No AppKit call/recovery poll.
        unsafe { mrk_panel_observe_completion_data(original.as_ptr(), &mut wire); }
        completion_poll_return(wire, status)
    }
    fn completion_data_check() -> bool {
        if std::mem::size_of::<CompletionWire>() != 12 { return false; }
        let matched = CompletionWire { flags: 15, response: 1, selection: 6 };
        if !completion_poll_return(matched, 1).is_some_and(CompletionReturn::succeeded)
            || completion_poll_return(CompletionWire::default(), 0).is_some() { return false; }
        for status in [-1, 0, 2, 3] {
            if completion_poll_return(matched, status).is_none_or(CompletionReturn::succeeded) { return false; }
        }
        for selection in 1..=5 {
            let Some(r) = completion_poll_return(CompletionWire { selection, ..matched }, 1) else { return false; };
            if r.succeeded() || !r.facts.is_some_and(|f| !f.native_unknown && f.callback_returned) { return false; }
        }
        // Getter entry without return, returned getter whose classification
        // threw, known mismatch plus preexisting Unknown, and duplicate/reentry.
        for wire in [CompletionWire { flags: 43, selection: 0, ..matched },
            CompletionWire { flags: 47, selection: 0, ..matched },
            CompletionWire { flags: 47, selection: 4, ..matched },
            CompletionWire { flags: 63, ..matched }, CompletionWire { flags: 32, ..CompletionWire::default() }] {
            if !completion_poll_return(wire, -1).is_some_and(|r| r.poll_result == "error" && !r.succeeded()
                && r.facts.is_some_and(|f| f.native_unknown)) { return false; }
        }
        for response in [2, 3] {
            if !completion_poll_return(CompletionWire { flags: 9, response, selection: 0 }, 1).is_some_and(|r|
                !r.succeeded() && r.facts.is_some_and(|f| !f.native_unknown && !f.urls_read_entered)) { return false; }
        }
        for wire in [CompletionWire { flags: 79, ..matched }, CompletionWire { flags: 31, ..matched },
            CompletionWire { flags: 13, ..matched }, CompletionWire { flags: 7, ..matched },
            CompletionWire { flags: 3, ..matched }, CompletionWire { response: 0, ..matched },
            CompletionWire { response: 4, ..matched }, CompletionWire { response: 2, ..matched },
            CompletionWire { selection: 0, ..matched }, CompletionWire { selection: 7, ..matched }] {
            if completion_selection(wire).is_some() { return false; }
        }
        // Unusable/missing DATA never upgrades an actual error/absent callback.
        completion_poll_return(CompletionWire::default(), -1).is_some_and(|r| r.facts.is_none() && !r.succeeded())
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct OpenWire { flags: u32, site: u32, error: u32, checks: u32, calls: u32,
        initial_nodes_examined: u32, recheck_nodes_examined: u32, owned: u32, released: u32, ax_error: i32,
        last_role: u32, last_depth: u32,
        selection_mode: u32, selection_checks: u32, selection_flags: u32, selection_nodes: u32,
        selection_matches: u32, selection_attribute: u32, selection_last_role: u32, selection_depth: u32,
        selection_limit: u32, selection_limit_cap: u32, selection_limit_queued: u32, selection_limit_children: u32,
        selection_limit_observed: i64, ax_failure_operation: u32, ax_failure_attribute: u32,
        selection_summary_version: u32, selection_table_roles: u32, selection_outline_roles: u32, selection_list_roles: u32,
        selection_entry_roots: u32, selection_title_present: u32, selection_title_absent: u32, selection_value_present: u32,
        selection_outside_entry_role_mask: u32, selection_fixture_label_mask: u32,
        selection_expected_label_relations: u32, selection_expected_label_role_mask: u32,
        selection_sample: u32, selection_calls_before: u32, selection_cf_before: u32, selection_wait: u32,
        selection_pending: [[u32; 16]; 7], selection_projection_diagnostic: [u32; 20] }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct RecheckWire { known: u32, error: u32, prompt: u32, proof: IdentityProofWire }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OpenRecheckReturn {
        pub stage: u32, pub custody_known: bool, pub error: &'static str,
        pub prompt: Option<bool>, pub proof: Option<IdentityBinding>,
    }
    impl OpenRecheckReturn {
        pub fn matched(self) -> bool {
            self.custody_known && self.error == "none" && self.prompt == Some(true)
                && self.proof.is_some_and(IdentityBinding::matched) && (1..=2).contains(&self.stage)
        }
        pub fn selection_parent_matched(self) -> bool {
            self.stage == 0 && self.custody_known && self.error == "none" && self.prompt == Some(true)
                && self.proof.is_some_and(IdentityBinding::selection_parent_matched)
        }
        fn stage_matched(self) -> bool { if self.stage == 0 { self.selection_parent_matched() } else { self.matched() } }
    }
    fn recheck_return(w: RecheckWire, stage: u32) -> Option<OpenRecheckReturn> {
        if stage > 2 || w.known > 1 || w.prompt > 2 || matches!(w.error, 10..=12 | 15) { return None; }
        let proof = if w.proof == IdentityProofWire::default() { None }
            else { Some(identity_proof(c_int::try_from(w.proof.error).ok()?, w.proof)?) };
        let r = OpenRecheckReturn { stage, custody_known: w.known == 1,
            error: *OPEN_ERRORS.get(w.error as usize)?,
            prompt: match w.prompt { 1 => Some(true), 2 => Some(false), _ => None }, proof };
        if proof.is_some_and(|p| p.attempted && (p.purpose == "selection-parent") != (stage == 0))
            || r.prompt.is_some() && !proof.is_some_and(|p|
                if stage == 0 { p.selection_parent_matched() } else { p.matched() })
            || w.error == 0 && !r.stage_matched() || w.error == 13 && r.prompt == Some(true)
            || matches!(w.error, 9 | 14) && r.custody_known
            || !matches!(w.error, 9 | 14) && !r.custody_known
            || proof.is_none() && !matches!(w.error, 9 | 14)
            || proof.is_some_and(|p| p.error != "none") && proof.map(|p| p.error) != Some(r.error) { return None; }
        Some(r)
    }
    /// Closed tags for the first actual nonzero AX return, never an action permit.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AxFailure {
        pub operation: &'static str,
        pub attribute: Option<&'static str>,
    }
    const AX_FAILURE_OPERATIONS: [&str; 9] = [
        "set-messaging-timeout", "copy-attribute-value", "get-attribute-value-count", "copy-attribute-values",
        "copy-action-names", "is-attribute-settable", "set-attribute-value", "perform-action",
        "copy-multiple-attribute-values",
    ];
    const AX_FAILURE_ATTRIBUTES: [Option<&str>; 12] = [
        None, Some("Parent"), Some("Role"), Some("Identifier"), Some("Title"), Some("Value"), Some("Enabled"),
        Some("Windows"), Some("Children"), Some("Rows"), Some("SelectedChildren"), Some("SelectedRows"),
    ];
    fn ax_failure_return(w: OpenWire) -> Option<Option<AxFailure>> {
        if w.ax_error == 0 {
            return (w.ax_failure_operation == 0 && w.ax_failure_attribute == 0).then_some(None);
        }
        if !(-25214..=-25200).contains(&w.ax_error)
            || !matches!((w.ax_failure_operation, w.ax_failure_attribute),
                (1 | 5 | 8 | 9, 0) | (2, 1..=6) | (3 | 4, 7..=11) | (6 | 7, 10 | 11)) { return None; }
        Some(Some(AxFailure {
            operation: *AX_FAILURE_OPERATIONS.get(w.ax_failure_operation.checked_sub(1)? as usize)?,
            attribute: *AX_FAILURE_ATTRIBUTES.get(w.ax_failure_attribute as usize)?,
        }))
    }
    const SELECT_NODES: u32 = 256;
    const SELECT_CALLS: u32 = 3072;
    const SELECT_CF: u32 = 1024;
    const SELECT_SAMPLES: u32 = 8;
    fn prompt_limits(selecting: bool) -> (u32, u32) {
        if selecting { (SELECT_SAMPLES * SELECT_CALLS, SELECT_SAMPLES * SELECT_CF) } else { (512, 256) }
    }
    /// Compact fixed DATA for complete zero-match samples only. Rows are:
    /// ordinal, calls-before/after, CF-before/after, nodes, depth, role, entries,
    /// fixture-mask, expected-relations, checks, matches, flags, error, wait.
    /// No pending row or wait result is permission for a selection or Open.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ContentReadiness {
        pub sample: u32, pub calls_before: u32, pub cf_before: u32, pub wait: u32,
        pub pending: [[u32; 16]; 7],
    }
    fn content_readiness_return(w: OpenWire) -> Option<Option<ContentReadiness>> {
        if w.selection_sample == 0 {
            if w.selection_calls_before != 0 || w.selection_cf_before != 0 || w.selection_wait != 0
                || w.selection_pending != [[0; 16]; 7] || w.calls != 0 || w.owned != 0 { return None; }
            return Some(None);
        }
        if w.selection_mode != 1 || w.selection_sample > SELECT_SAMPLES || w.selection_wait > 3 { return None; }
        let mut calls = 0; let mut slots = 0;
        for (i, row) in w.selection_pending.into_iter().enumerate() {
            if i >= (w.selection_sample - 1) as usize {
                if row != [0; 16] { return None; }
                continue;
            }
            let [ordinal, before, after, cf_before, cf_after, nodes, depth, role, entries, mask,
                relations, checks, matches, flags, error, wait] = row;
            if ordinal != i as u32 + 1 || before != calls || cf_before != slots
                || after <= before || after - before > SELECT_CALLS || cf_after <= cf_before || cf_after - cf_before > SELECT_CF
                || !(1..SELECT_NODES).contains(&nodes) || !(1..=8).contains(&depth) || depth > nodes
                || !(1..=16).contains(&role) || entries > nodes || mask > 31 || mask.count_ones() > nodes
                || relations > 6 || relations & 1 != 0 || entries == 0 && (mask != 0 || relations != 0)
                || checks != 1 || matches != 0 || flags != 0 || error != 0 || wait != 2 { return None; }
            calls = after; slots = cf_after;
        }
        if w.selection_calls_before != calls || w.selection_cf_before != slots || w.calls < calls || w.owned < slots
            || w.calls - calls > SELECT_CALLS || w.owned - slots > SELECT_CF
            || w.calls > SELECT_SAMPLES * SELECT_CALLS || w.owned > SELECT_SAMPLES * SELECT_CF { return None; }
        if w.selection_wait != 0 && (w.selection_sample == SELECT_SAMPLES || w.selection_checks != 1
            || w.selection_matches != 0 || w.selection_flags != 0 || w.flags & 7 != 0 || w.site != 21 || w.error == 0
            || w.ax_error != 0 || w.selection_wait == 3 && w.error != 12) { return None; }
        Some(Some(ContentReadiness { sample: w.selection_sample, calls_before: calls, cf_before: slots,
            wait: w.selection_wait, pending: w.selection_pending }))
    }
    /// Finite actual AX/CF DATA from the one original worker. A retired slot is
    /// either a definite empty out-slot or its CFRelease actually returned;
    /// these counters deliberately do not claim that many non-null objects.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ControlContainerButtonProof {
        pub checks: [bool; 7], pub calls: u32, pub initial_nodes_examined: u32, pub recheck_nodes_examined: u32,
        pub last_role: &'static str, pub last_depth: u32,
        pub cf_slots: u32, pub cf_slots_retired: u32, pub cleanup_returned: bool, pub ax_error: i32,
        pub ax_failure: Option<AxFailure>,
    }
    impl ControlContainerButtonProof {
        /// Ordinary preconfigured panels retain their original resource limits.
        pub fn matched(self) -> bool { self.matched_for_mode(false) }
        fn matched_for_mode(self, selecting: bool) -> bool {
            let (calls, slots) = prompt_limits(selecting);
            self.checks == [true; 7] && (1..=calls).contains(&self.calls)
                && (1..=16).contains(&self.initial_nodes_examined) && (1..=16).contains(&self.recheck_nodes_examined)
                && self.last_role == "Button" && (1..=8).contains(&self.last_depth)
                && self.last_depth <= self.initial_nodes_examined.min(self.recheck_nodes_examined)
                && (1..=slots).contains(&self.cf_slots) && self.cf_slots_retired == self.cf_slots
                && self.cleanup_returned && self.ax_error == 0 && self.ax_failure.is_none()
        }
    }
    /// The first original selection refusal only. No additional AX observation.
    /// Queue/children zero on the C wire is UNOBSERVED, not an observed zero.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SelectionLimit {
        pub predicate: &'static str, pub observed: i64, pub cap: u32,
        pub queued: Option<u32>, pub children: Option<u32>,
    }
    fn selection_limit_return(w: OpenWire) -> Option<Option<SelectionLimit>> {
        if w.selection_limit == 0 {
            if w.selection_limit_cap != 0 || w.selection_limit_queued != 0 || w.selection_limit_children != 0
                || w.selection_limit_observed != 0 || (21..=25).contains(&w.site) && w.error == 7 { return None; }
            return Some(None);
        }
        if w.selection_mode != 1 || w.error != 7 || w.ax_error != 0 || w.flags & 7 != 0
            || !matches!(w.site, 21 | 22 | 23 | 25) { return None; }
        let projection = w.site == 21;
        if projection {
            if w.selection_checks != 0 || !(1..=SELECT_NODES).contains(&w.selection_limit_queued)
                || w.selection_limit_queued <= w.selection_nodes { return None; }
        } else if w.selection_limit_queued != 0 { return None; }
        let count = w.selection_limit_observed; let cap = w.selection_limit_cap;
        let children = w.selection_limit_children;
        let child_cap = match w.selection_last_role { 6 | 7 | 11 => 32, 1 | 2 | 3 | 5 | 8 | 10 | 12 | 13 => 16, _ => 0 };
        let valid = match w.selection_limit {
            1 => projection && cap == 512 && count > 512 && children == 0
                && w.selection_nodes > 0 && w.selection_depth > 0 && matches!(w.selection_last_role, 2 | 12..=16),
            2 | 3 => (projection && child_cap != 0 && cap == child_cap || w.site == 25 && cap == 32)
                && children == 0 && (count > i64::from(cap) || w.selection_limit == 3 && count < 0),
            4 => projection && cap == SELECT_NODES && count == i64::from(w.selection_limit_queued)
                && child_cap != 0 && (1..=child_cap).contains(&children) && children > SELECT_NODES - w.selection_limit_queued
                && w.selection_depth < 8,
            5 => projection && cap == 8 && count == 8 && w.selection_depth == 8
                && child_cap != 0 && (1..=child_cap).contains(&children),
            // Each AX admission reserves the same original two-call batch;
            // Selection CF allocation refuses BEFORE reserving the 1025th original slot.
            6 => cap == SELECT_CALLS && count == i64::from(w.calls.checked_sub(w.selection_calls_before)?)
                && (SELECT_CALLS - 1..=SELECT_CALLS).contains(&(count as u32)) && children == 0,
            7 => cap == SELECT_CF && count == i64::from(w.owned.checked_sub(w.selection_cf_before)?)
                && count == i64::from(SELECT_CF) && children == 0,
            _ => false,
        };
        if !valid { return None; }
        Some(Some(SelectionLimit {
            predicate: *["label-length", "child-count", "child-copy-count", "queue-capacity", "depth",
                "ax-call-budget", "cf-slot-budget"].get(w.selection_limit.checked_sub(1)? as usize)?,
            observed: count, cap, queued: (w.selection_limit_queued != 0).then_some(w.selection_limit_queued),
            children: (children != 0).then_some(children),
        }))
    }
    /// Bounded observations from the one existing roster, never raw labels or selection authority.
    /// Role counts mean typed observed roles, not successfully traversed containers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SelectionProjectionSummary {
        pub table_roles: u32, pub outline_roles: u32, pub list_roles: u32, pub entry_roots: u32,
        pub title_present: u32, pub title_absent: u32, pub value_present: u32, pub outside_entry_role_mask: u32,
        /// Fixed labels: VERSION, link-input, kind-input, inputs, version.properties.
        pub fixture_label_mask: u32,
        /// Exact, case-only, literal-decoration bits; typed entry-label roles only.
        pub expected_label_relations: u32, pub expected_label_role_mask: u32,
    }
    fn selection_projection_summary_return(w: OpenWire) -> Option<Option<SelectionProjectionSummary>> {
        let counts = [w.selection_table_roles, w.selection_outline_roles, w.selection_list_roles, w.selection_entry_roots,
            w.selection_title_present, w.selection_title_absent, w.selection_value_present];
        if w.selection_summary_version == 0 {
            if counts.iter().any(|&n| n != 0) || w.selection_outside_entry_role_mask != 0
                || w.selection_fixture_label_mask != 0 || w.selection_expected_label_relations != 0
                || w.selection_expected_label_role_mask != 0
                || w.selection_checks != 0 || w.selection_flags != 0 || w.selection_nodes != 0 || w.selection_matches != 0
                || w.selection_attribute != 0 || w.selection_last_role != 0 || w.selection_depth != 0
                || w.selection_limit != 0 || (21..=25).contains(&w.site) { return None; }
            return Some(None);
        }
        if w.selection_summary_version != 2 || w.selection_mode != 1 || w.selection_nodes >= SELECT_NODES
            || counts.iter().any(|&n| n > w.selection_nodes) { return None; }
        // These additions cannot overflow: every summand is already below256.
        let roles = w.selection_table_roles + w.selection_outline_roles + w.selection_list_roles;
        let labels = w.selection_title_present + w.selection_title_absent + w.selection_value_present;
        let present = w.selection_title_present + w.selection_value_present;
        if roles > w.selection_nodes || labels > w.selection_nodes
            || w.selection_entry_roots != 0 && roles == 0 || labels != 0 && w.selection_entry_roots == 0
            || w.selection_matches > w.selection_entry_roots
            || w.selection_matches > w.selection_title_present + w.selection_value_present
            || w.selection_outside_entry_role_mask & !0x1c210 != 0
            || w.selection_outside_entry_role_mask != 0 && w.selection_nodes == 0
            || w.selection_fixture_label_mask & !31 != 0 || w.selection_fixture_label_mask.count_ones() > present
            || w.selection_expected_label_relations & !7 != 0
            || w.selection_expected_label_role_mask & !0x1f004 != 0
            || w.selection_expected_label_role_mask.count_ones() > present
            || (w.selection_expected_label_relations == 0) != (w.selection_expected_label_role_mask == 0)
            || (w.selection_expected_label_relations & 1 != 0) != (w.selection_matches != 0) { return None; }
        Some(Some(SelectionProjectionSummary {
            table_roles: w.selection_table_roles, outline_roles: w.selection_outline_roles, list_roles: w.selection_list_roles,
            entry_roots: w.selection_entry_roots, title_present: w.selection_title_present,
            title_absent: w.selection_title_absent, value_present: w.selection_value_present,
            outside_entry_role_mask: w.selection_outside_entry_role_mask,
            fixture_label_mask: w.selection_fixture_label_mask,
            expected_label_relations: w.selection_expected_label_relations,
            expected_label_role_mask: w.selection_expected_label_role_mask,
        }))
    }
    /// One bounded read-only extension of the first completed zero-match census.
    /// Fixed masks only; VERSION in outside_field_mask may be the name field.
    /// Complete describes only this finite probe, not an atomic directory view.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SelectionProjectionDiagnostic {
        pub version: u32, pub state: &'static str, pub normal_fixture_mask: u32,
        pub calls_before: u32, pub calls_after: u32, pub cf_before: u32, pub cf_after: u32,
        pub eligible_frontiers: u32, pub attempted_frontiers: u32, pub added_nodes: u32, pub max_depth: u32,
        pub alternate_value_mask: u32, pub frontier_label_mask: u32, pub outside_field_mask: u32,
        pub alternate_role_mask: u32, pub frontier_role_mask: u32, pub unavailable: u32,
        pub omissions: u32, pub duplicates: u32, pub non_string_values: u32,
    }
    fn selection_projection_diagnostic_return(w: OpenWire) -> Option<Option<SelectionProjectionDiagnostic>> {
        let row = w.selection_projection_diagnostic;
        if row == [0; 20] { return Some(None); } // Unentered is indeterminate, never a negative observation.
        let [version, state, normal_fixture_mask, calls_before, calls_after, cf_before, cf_after,
            eligible_frontiers, attempted_frontiers, added_nodes, max_depth, alternate_value_mask,
            frontier_label_mask, outside_field_mask, alternate_role_mask, frontier_role_mask,
            unavailable, omissions, duplicates, non_string_values] = row;
        if version != 1 || !(1..=3).contains(&state) || w.selection_mode != 1
            || !(1..=SELECT_SAMPLES).contains(&w.selection_sample)
            || calls_before == 0 || calls_before > calls_after || calls_after > SELECT_CALLS
            || cf_before == 0 || cf_before > cf_after || cf_after > SELECT_CF
            || calls_after - calls_before > 1024 || cf_after - cf_before > 512
            || eligible_frontiers >= SELECT_NODES || attempted_frontiers > eligible_frontiers || attempted_frontiers > 64
            || added_nodes > 64 || max_depth > 8 || (added_nodes == 0) != (max_depth == 0)
            || normal_fixture_mask > 31 || alternate_value_mask > 31 || frontier_label_mask > 31 || outside_field_mask > 31
            || alternate_role_mask & !0x7004 != 0 || frontier_role_mask & !0x1f014 != 0
            || (alternate_value_mask == 0) != (alternate_role_mask == 0)
            || (frontier_label_mask == 0) != (frontier_role_mask == 0)
            || unavailable & !63 != 0 || omissions & !1023 != 0
            || duplicates > 32 * (attempted_frontiers + added_nodes)
            || non_string_values > cf_after - cf_before
            || 2 * added_nodes > cf_after - cf_before
            || alternate_value_mask.count_ones() > cf_after - cf_before
            || outside_field_mask.count_ones() > cf_after - cf_before
            || alternate_role_mask.count_ones() > cf_after - cf_before
            || frontier_label_mask.count_ones() > 2 * added_nodes || frontier_role_mask.count_ones() > added_nodes
            || added_nodes != 0 && attempted_frontiers == 0 { return None; }
        let (first_nodes, first_mask, first_calls, first_cf) = if w.selection_sample == 1 {
            if w.selection_checks != 1 || w.selection_matches != 0 || w.selection_flags != 0
                || w.selection_summary_version != 2 { return None; }
            (w.selection_nodes, w.selection_fixture_label_mask, w.calls, w.owned)
        } else {
            let first = w.selection_pending[0];
            if first[0] != 1 || first[1] != 0 || first[3] != 0 || first[11..16] != [1, 0, 0, 0, 2]
                || state == 1 { return None; }
            (first[5], first[9], first[2], first[4])
        };
        if !(1..SELECT_NODES).contains(&first_nodes) || first_mask != normal_fixture_mask
            || calls_after != first_calls || cf_after != first_cf || eligible_frontiers > first_nodes
            || first_nodes + 1 + added_nodes > SELECT_NODES
            || state == 1 && w.error == 0
            || state == 2 && (unavailable != 0 || omissions != 0 || non_string_values != 0
                || attempted_frontiers != eligible_frontiers)
            || state == 3 && unavailable == 0 && omissions == 0 && non_string_values == 0
                && attempted_frontiers == eligible_frontiers && w.error == 0 { return None; }
        Some(Some(SelectionProjectionDiagnostic { version,
            state: *["unentered", "entered", "returned-complete", "returned-incomplete"].get(state as usize)?,
            normal_fixture_mask, calls_before, calls_after, cf_before, cf_after,
            eligible_frontiers, attempted_frontiers, added_nodes, max_depth, alternate_value_mask,
            frontier_label_mask, outside_field_mask, alternate_role_mask, frontier_role_mask,
            unavailable, omissions, duplicates, non_string_values }))
    }
    fn projection_diagnostic_data_check() -> bool {
        // Inert wire DATA only. This does not simulate AX timing, return or readiness.
        if selection_projection_diagnostic_return(OpenWire::default()) != Some(None) { return false; }
        let row = [1, 2, 24, 205, 221, 110, 120, 1, 1, 1, 4, 0, 2, 1, 0, 1 << 15, 0, 0, 0, 0];
        let wire = OpenWire { selection_mode: 1, selection_sample: 1, selection_checks: 1,
            selection_summary_version: 2, selection_nodes: 12, selection_fixture_label_mask: 24,
            calls: 221, owned: 120, selection_projection_diagnostic: row, ..OpenWire::default() };
        let Some(Some(data)) = selection_projection_diagnostic_return(wire) else { return false; };
        if data.state != "returned-complete" || data.frontier_label_mask != 2 || data.outside_field_mask != 1 { return false; }
        // Button is diagnostic frontier DATA only; alternate-role admission stays unchanged.
        for (index, role, valid) in [(15, 4, true), (15, 3, false), (14, 2, true), (14, 4, false)] {
            let mut current = wire;
            current.selection_projection_diagnostic[index] = 1 << role;
            if index == 14 { current.selection_projection_diagnostic[11] = 1; }
            if selection_projection_diagnostic_return(current).is_some() != valid { return false; }
        }
        for index in 0..20 {
            let mut bad = wire; bad.selection_projection_diagnostic[index] = u32::MAX;
            if selection_projection_diagnostic_return(bad).is_some() { return false; }
        }
        for (state, unavailable, error, valid) in [(1, 0, 14, true), (1, 0, 0, false),
            (2, 32, 0, false), (3, 32, 0, true), (3, 0, 0, false), (3, 0, 8, true)] {
            let mut current = wire; current.error = error;
            current.selection_projection_diagnostic[1] = state;
            current.selection_projection_diagnostic[16] = unavailable;
            if selection_projection_diagnostic_return(current).is_some() != valid { return false; }
        }
        let mut later = wire; later.selection_sample = 2; later.selection_checks = 0; later.selection_nodes = 1;
        later.calls = 240; later.owned = 132;
        later.selection_pending[0] = [1, 0, 221, 0, 120, 12, 4, 16, 2, 24, 0, 1, 0, 0, 0, 2];
        if selection_projection_diagnostic_return(later) != Some(Some(data)) { return false; }
        later.selection_pending[0][9] = 1;
        if selection_projection_diagnostic_return(later).is_some() { return false; }
        let mut outside_only = wire;
        for index in [9, 10, 12, 15] { outside_only.selection_projection_diagnostic[index] = 0; }
        selection_projection_diagnostic_return(outside_only)
            .is_some_and(|r| r.is_some_and(|r| r.frontier_label_mask == 0 && r.outside_field_mask == 1))
    }
    /// The actual selecting operation's closed DATA; neither labels nor file identity.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct VersionSourceSelection {
        pub checks: [bool; 5], pub attempted: bool, pub returned: bool, pub selected: Option<bool>,
        pub nodes: u32, pub matches: u32, pub attribute: &'static str, pub last_role: &'static str, pub depth: u32,
        pub limit: Option<SelectionLimit>, pub projection_summary: Option<SelectionProjectionSummary>,
        pub content_readiness: Option<ContentReadiness>, pub projection_diagnostic: Option<SelectionProjectionDiagnostic>,
    }
    impl VersionSourceSelection {
        pub fn matched(self) -> bool {
            self.content_readiness.is_some_and(|r| (1..=SELECT_SAMPLES).contains(&r.sample) && r.wait == 0)
                && self.limit.is_none() && self.checks == [true; 5] && self.attempted && self.returned && self.selected == Some(true)
                && (1..SELECT_NODES).contains(&self.nodes) && self.matches == 1
                && matches!(self.attribute, "SelectedRows" | "SelectedChildren") && self.last_role != "not-read"
                && (1..=8).contains(&self.depth) && self.depth <= self.nodes
        }
    }
    fn content_readiness_data_check(full: OpenWire, rechecks: [Option<OpenRecheckReturn>; 3]) -> bool {
        let mut pending = [[0u32; 16]; 7];
        for count in 0..=7usize {
            if count > 0 { let i = count - 1; pending[i] = [i as u32 + 1, i as u32 * 707, (i as u32 + 1) * 707,
                i as u32 * 434, (i as u32 + 1) * 434, 182, 8, 16, 43, 24, 0, 1, 0, 0, 0, 2]; }
            let before = count as u32 * 707; let cf_before = count as u32 * 434;
            let current = OpenWire { selection_sample: count as u32 + 1, selection_calls_before: before,
                selection_cf_before: cf_before, selection_pending: pending, calls: before + full.calls,
                owned: cf_before + full.owned, released: cf_before + full.owned, ..full };
            if !open_return(current, rechecks, true, true).is_some_and(OpenReport::succeeded) { return false; }
            for bad in [OpenWire { calls: before + SELECT_CALLS + 1, ..current },
                OpenWire { owned: cf_before + SELECT_CF + 1, released: cf_before + SELECT_CF + 1, ..current },
                OpenWire { selection_calls_before: before + 1, ..current },
                OpenWire { released: current.owned - 1, ..current },
                OpenWire { selection_wait: 2, ..current }, OpenWire { selection_sample: 9, ..current }] {
                if open_return(bad, rechecks, true, true).is_some() { return false; }
            }
            if count > 0 {
                for index in 0..16 {
                    let mut bad = current;
                    bad.selection_pending[count - 1][index] = u32::MAX;
                    if open_return(bad, rechecks, true, true).is_some() { return false; }
                }
            }
            if count < 7 {
                let mut trailing = current; trailing.selection_pending[count][0] = count as u32 + 1;
                if open_return(trailing, rechecks, true, true).is_some() { return false; }
            }
        }
        // A complete pending sample can stop for deadline, wait error or the
        // eighth-sample bound, never manufacture a selected or successful input.
        for (count, wait, error) in [(0usize, 0, 8), (2, 1, 14), (2, 2, 8), (2, 3, 12), (7, 0, 4)] {
            let mut history = pending;
            for row in &mut history[count..] { *row = [0; 16]; }
            let calls_before = count as u32 * 707; let cf_before = count as u32 * 434;
            let stopped = OpenWire { flags: 8, site: 21, error, checks: 3, selection_checks: 1,
                selection_flags: 0, selection_matches: 0, selection_attribute: 0, selection_wait: wait,
                selection_expected_label_relations: 0, selection_expected_label_role_mask: 0,
                initial_nodes_examined: 0, recheck_nodes_examined: 0, last_role: 0, last_depth: 0,
                selection_sample: count as u32 + 1, selection_pending: history,
                selection_calls_before: calls_before, selection_cf_before: cf_before,
                calls: calls_before + full.calls, owned: cf_before + full.owned, ..full };
            let known = error != 14;
            let stopped = OpenWire { flags: if known { 8 } else { 0 },
                released: if known { stopped.owned } else { 0 }, ..stopped };
            if !open_return(stopped, [rechecks[0], None, None], known, true)
                .is_some_and(|r| !r.succeeded() && !r.attempted && r.custody_known == known) { return false; }
        }
        true
    }
    fn selection_return(w: OpenWire) -> Option<VersionSourceSelection> {
        if w.selection_checks > 31 || w.selection_checks & (w.selection_checks + 1) != 0
            || !matches!(w.selection_flags, 0 | 1 | 3 | 7) || w.selection_nodes >= SELECT_NODES || w.selection_matches > 2
            || w.selection_depth > 8 || w.selection_depth > w.selection_nodes || w.selection_matches > w.selection_nodes
            || w.selection_checks != 0 && (w.selection_nodes == 0 || w.selection_last_role == 0 || w.selection_depth == 0)
            || (w.selection_attribute != 0) != (w.selection_checks & 4 != 0)
            || w.selection_checks >= 3 && (w.selection_matches != 1 || w.selection_nodes == 0)
            || w.selection_flags != 0 && w.selection_checks < 15
            || w.selection_flags == 3 && w.ax_error == 0
            || w.selection_checks == 31 && w.selection_flags != 7 { return None; }
        Some(VersionSourceSelection {
            checks: std::array::from_fn(|i| w.selection_checks & (1 << i) != 0),
            attempted: w.selection_flags & 1 != 0, returned: w.selection_flags & 2 != 0,
            selected: (w.selection_flags & 2 != 0).then_some(w.selection_flags & 4 != 0),
            nodes: w.selection_nodes, matches: w.selection_matches,
            attribute: *["not-read", "SelectedRows", "SelectedChildren"].get(w.selection_attribute as usize)?,
            last_role: *["not-read", "Sheet", "Group", "SplitGroup", "Button", "Browser", "Table", "Outline", "ScrollArea", "opaque",
                "Column", "List", "Row", "Cell", "Image", "StaticText", "TextField"].get(w.selection_last_role as usize)?,
            depth: w.selection_depth, limit: selection_limit_return(w)?, projection_summary: selection_projection_summary_return(w)?,
            content_readiness: content_readiness_return(w)?, projection_diagnostic: selection_projection_diagnostic_return(w)?,
        })
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OpenReport {
        pub diagnostic: OpenDiagnostic, pub attempted: bool, pub press_returned: bool,
        pub triggered: Option<bool>, pub custody_known: bool,
        pub initial_proof: Option<IdentityBinding>, pub proof: Option<IdentityBinding>,
        pub prompt: [Option<bool>; 2], pub button: ControlContainerButtonProof,
        pub selection_mode: bool, pub selection: Option<VersionSourceSelection>,
        pub selection_parent: Option<IdentityBinding>, pub selection_prompt: Option<bool>,
    }
    impl OpenReport {
        pub fn succeeded(self) -> bool {
            self.attempted && self.press_returned && self.triggered == Some(true) && self.custody_known
                && self.initial_proof.is_some_and(IdentityBinding::matched) && self.proof.is_some_and(IdentityBinding::matched)
                && self.prompt == [Some(true); 2] && self.button.matched_for_mode(self.selection_mode)
                && (if self.selection_mode {
                    self.selection.is_some_and(VersionSourceSelection::matched)
                        && self.selection_parent.is_some_and(IdentityBinding::selection_parent_matched)
                        && self.selection_prompt == Some(true)
                } else { self.selection.is_none() && self.selection_parent.is_none() && self.selection_prompt.is_none() })
                && self.diagnostic == OpenDiagnostic { site: "press", error: "none" }
        }
    }
    fn open_return(w: OpenWire, rechecks: [Option<OpenRecheckReturn>; 3], known: bool, selecting: bool) -> Option<OpenReport> {
        // Mode belongs to the opaque frozen identity, not the returned wire.
        if w.selection_mode != u32::from(selecting) || !selecting && (rechecks[0].is_some()
            || w.selection_checks != 0 || w.selection_flags != 0 || w.selection_nodes != 0 || w.selection_matches != 0
            || w.selection_attribute != 0 || w.selection_last_role != 0 || w.selection_depth != 0 || w.site > 19
            || w.selection_limit != 0 || w.selection_limit_cap != 0 || w.selection_limit_queued != 0
            || w.selection_limit_children != 0 || w.selection_limit_observed != 0
            || w.selection_summary_version != 0 || w.selection_table_roles != 0 || w.selection_outline_roles != 0
            || w.selection_list_roles != 0 || w.selection_entry_roots != 0 || w.selection_title_present != 0
            || w.selection_title_absent != 0 || w.selection_value_present != 0
            || w.selection_outside_entry_role_mask != 0 || w.selection_fixture_label_mask != 0
            || w.selection_expected_label_relations != 0 || w.selection_expected_label_role_mask != 0
            || w.selection_sample != 0 || w.selection_calls_before != 0 || w.selection_cf_before != 0 || w.selection_wait != 0
            || w.selection_pending != [[0; 16]; 7] || w.selection_projection_diagnostic != [0; 20]) { return None; }
        // Only the already-bound original mode chooses the whole-call envelope.
        let (calls, slots) = prompt_limits(selecting);
        // Control completion bits form a prefix over the eligible projection,
        // not all AX descendants. Second-pass progress cannot erase the first.
        if w.flags & !15 != 0 || w.checks > 127 || w.checks & (w.checks + 1) != 0
            || w.calls > calls || w.initial_nodes_examined > 16 || w.recheck_nodes_examined > 16
            || w.last_depth > 8 || w.owned > slots || w.released > w.owned
            || !(w.ax_error == 0 || (-25214..=-25200).contains(&w.ax_error)) { return None; }
        let selection = if selecting { Some(selection_return(w)?) } else { None };
        let selector_complete = selection.is_some_and(VersionSourceSelection::matched);
        let button = ControlContainerButtonProof { checks: std::array::from_fn(|i| w.checks & (1 << i) != 0), calls: w.calls,
            initial_nodes_examined: w.initial_nodes_examined, recheck_nodes_examined: w.recheck_nodes_examined,
            last_role: *["not-read", "Sheet", "Group", "SplitGroup", "Button", "Browser", "Table", "Outline", "ScrollArea", "opaque"]
                .get(w.last_role as usize)?,
            last_depth: w.last_depth, cf_slots: w.owned, cf_slots_retired: w.released,
            cleanup_returned: w.flags & 8 != 0, ax_error: w.ax_error, ax_failure: ax_failure_return(w)? };
        let r = OpenReport { diagnostic: OpenDiagnostic {
            site: *["entry", "application", "windows", "parent-identifier", "sheet", "topology", "control-projection", "button",
                "control-recheck", "initial-original-proof", "original-proof", "admission", "press", "cleanup",
                "control-title-limit", "control-child-count-limit", "control-child-copy-limit", "control-node-limit", "control-depth-limit",
                "selection-parent-proof", "selection-projection", "selection-recheck", "selection-settable", "selection-write", "selection-readback"]
                .get(w.site.checked_sub(1)? as usize)?, error: *OPEN_ERRORS.get(w.error as usize)?, },
            attempted: w.flags & 1 != 0, press_returned: w.flags & 2 != 0,
            triggered: (w.flags & 2 != 0).then_some(w.flags & 4 != 0),
            custody_known: known && button.cleanup_returned && rechecks.iter().flatten().all(|r| r.custody_known),
            initial_proof: rechecks[1].and_then(|r| r.proof), proof: rechecks[2].and_then(|r| r.proof),
            prompt: [rechecks[1].and_then(|r| r.prompt), rechecks[2].and_then(|r| r.prompt)], button,
            selection_mode: selecting, selection, selection_parent: rechecks[0].and_then(|r| r.proof),
            selection_prompt: rechecks[0].and_then(|r| r.prompt) };
        let first_admission = if selecting { rechecks[0].is_some_and(OpenRecheckReturn::selection_parent_matched) }
            else { rechecks[1].is_some_and(OpenRecheckReturn::matched) };
        if w.flags & 4 != 0 && !r.press_returned || r.press_returned && !r.attempted
            || r.attempted && (w.checks != 127 || !rechecks[1..].iter().all(|r| r.is_some_and(OpenRecheckReturn::matched))
                || selecting && !selector_complete || !matches!(r.diagnostic.site, "press" | "cleanup"))
            || button.cleanup_returned && w.released != w.owned
            || matches!(w.error, 9 | 14 | 15) && r.custody_known
            || w.calls != 0 && !first_admission
            || rechecks.iter().enumerate().any(|(i, r)| r.is_some_and(|r| r.stage != i as u32))
            || (w.checks != 0 || w.last_role != 0) && (w.calls == 0 || w.owned == 0)
            || w.initial_nodes_examined != 0 && w.checks & 3 != 3
            || (w.initial_nodes_examined != 0 || w.checks > 3) && !rechecks[1].is_some_and(OpenRecheckReturn::matched)
            || w.checks & 4 != 0 && w.initial_nodes_examined == 0
            || w.checks < 63 && w.recheck_nodes_examined != 0
            || w.last_depth > w.initial_nodes_examined.max(w.recheck_nodes_examined)
            || w.checks == 127 && (w.recheck_nodes_examined == 0 || w.last_role != 4 || w.last_depth == 0
                || w.last_depth > w.initial_nodes_examined.min(w.recheck_nodes_examined))
            || rechecks[2].is_some() && w.checks != 127
            || r.triggered == Some(false) && w.ax_error == 0
            || r.triggered == Some(true) && w.ax_error != 0
            || w.ax_error != 0 && w.error == 0
            || w.error == 0 && !r.succeeded() { return None; }
        if selecting {
            let selection_started = w.selection_checks != 0 || w.selection_flags != 0 || w.selection_nodes != 0
                || w.selection_matches != 0 || w.selection_attribute != 0 || w.selection_last_role != 0 || w.selection_depth != 0
                || w.selection_limit != 0 || w.selection_summary_version != 0;
            if selection_started && (w.checks & 3 != 3 || w.calls == 0 || w.owned == 0)
                || rechecks[1].is_some() && !selector_complete
                || w.checks > 3 && !selector_complete { return None; }
            if w.site == 20 && rechecks[0].is_some_and(|proof| proof.error != "none" && proof.error != r.diagnostic.error) { return None; }
            if w.site == 20 && (w.calls != 0 || w.owned != 0 || w.checks != 0 || selection_started || rechecks[1..].iter().any(Option::is_some))
                || w.site >= 21 && (w.checks != 3 || rechecks[1..].iter().any(Option::is_some))
                || w.site == 21 && (!matches!(w.selection_checks, 0 | 1 | 3) || w.selection_flags != 0)
                || w.site == 22 && (w.selection_checks != 3 || w.selection_flags != 0)
                || w.site == 23 && (!matches!(w.selection_checks, 7 | 15) || w.selection_flags != 0)
                || w.site == 24 && (w.selection_checks != 15 || w.selection_flags == 0)
                || w.site == 25 && (!matches!(w.selection_checks, 15 | 31) || w.selection_flags != 7) { return None; }
        }
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
                || !rechecks[1].is_some_and(OpenRecheckReturn::matched) || rechecks[2].is_some() { return None; }
        }
        Some(r)
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OpenPressTiming {
        pub installed_allowance_ns: u64,
        pub last_permit_to_return_admission_ns: Option<u64>,
    }
    #[derive(Default)]
    struct OpenPressCapture {
        permit: Option<(u64, Instant)>, after_attempted: bool, returned_at: Option<Instant>,
    }
    impl OpenPressCapture {
        fn first_return_attempt(&mut self, after: c_int) -> bool {
            let first = after == 1 && !self.after_attempted;
            if after == 1 { self.after_attempted = true; }
            first
        }
        fn duration_ns(duration: Duration) -> Option<u64> { u64::try_from(duration.as_nanos()).ok() }
        fn timing(&self, report: Option<OpenReport>) -> Option<OpenPressTiming> {
            let report = report?;
            if !report.attempted || !report.press_returned || report.triggered != Some(false)
                || report.button.ax_error != -25204
                || report.button.ax_failure != Some(AxFailure { operation: "perform-action", attribute: None }) { return None; }
            let (installed_allowance_ns, permitted_at) = self.permit?;
            // The valid attempted/returned report binds the last positive permit
            // to the final Press. A missing first return clock stays unknown.
            let elapsed = self.returned_at.and_then(|at| at.checked_duration_since(permitted_at))
                .and_then(Self::duration_ns);
            Some(OpenPressTiming { installed_allowance_ns, last_permit_to_return_admission_ns: elapsed })
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OpenInputReturn {
        pub entered: bool, pub report: Option<OpenReport>, pub custody_known: bool, pub press_timing: Option<OpenPressTiming>,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct OpenTimeout { seconds: f32, required_ns: u64 }
    struct OpenAdmission<'a, F, G> {
        end: Instant, admit: &'a mut F, recheck: &'a mut G,
        rechecks: [Option<OpenRecheckReturn>; 3], next_recheck: usize, custody_known: bool, press: OpenPressCapture,
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
            // Spend even a refused/unwound first return admission. A later
            // CF-cleanup callback must never substitute its clock for Press.
            let first_after = context.press.first_return_attempt(after);
            if !matches!(after, 0 | 1) || required_ns > 100_000_000 || !timeout.is_null() && required_ns != 0 {
                context.custody_known = false; return 9;
            }
            let Some(allowed) = (context.admit)(after == 1) else { context.custody_known = false; return 9; };
            let now = Instant::now();
            if first_after { context.press.returned_at = Some(now); }
            let remaining = context.end.saturating_duration_since(now);
            if remaining.is_zero() || remaining.as_nanos() < u128::from(required_ns) { return 8; }
            if !allowed { return 3; }
            if !timeout.is_null() {
                let Some(value) = timeout_for(remaining) else { return 8; };
                unsafe { *timeout = value; }
            }
            if after == 0 && required_ns > 0 && !context.press.after_attempted {
                context.press.permit = Some((required_ns, now));
            }
            0
        }));
        match checked { Ok(code) => code, Err(payload) => { context.custody_known = false; std::mem::forget(payload); 9 } }
    }
    unsafe extern "C" fn open_recheck<F, G>(opaque: *mut c_void, stage: c_int) -> c_int
    where F: FnMut(bool) -> Option<bool>, G: FnMut(u32) -> Result<(OpenRecheckReturn, bool), u32> {
        let context = unsafe { &mut *opaque.cast::<OpenAdmission<'_, F, G>>() };
        let checked = catch_unwind(AssertUnwindSafe(|| {
            if !(0..=2).contains(&stage) || stage as usize != context.next_recheck {
                context.custody_known = false; return 9;
            }
            context.next_recheck += 1; // Never redispatch a stage, including errors.
            let (returned, admitted) = match (context.recheck)(stage as u32) {
                Ok(returned) => returned,
                Err(code) if matches!(code, 3 | 8) => return code as c_int,
                Err(_) => { context.custody_known = false; return 9; },
            };
            context.rechecks[stage as usize] = Some(returned);
            if returned.stage != stage as u32 || !returned.custody_known { context.custody_known = false; return 9; }
            let code = OPEN_ERRORS.iter().position(|e| *e == returned.error).unwrap_or(9) as c_int;
            if code != 0 { return code; }
            if !returned.stage_matched() { context.custody_known = false; return 9; }
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
        let mut returned = OpenInputReturn { entered: false, report: None, custody_known: false, press_timing: None };
        if main_thread() || !identity.valid() { return returned; }
        let mut context = OpenAdmission { end, admit: &mut admit, recheck: &mut recheck,
            rechecks: [None; 3], next_recheck: if identity.selection { 0 } else { 1 }, custody_known: true, press: OpenPressCapture::default() };
        let mut wire = OpenWire::default(); returned.entered = true;
        // SAFETY: bounded copied input lives through the single synchronous
        // call; callbacks borrow this worker stack only while C is active.
        unsafe { mrk_observation_prompt_press(identity.parent.as_ptr(), identity.panel.as_ptr(), identity.prompt.as_ptr(),
            identity.parent.len(), identity.target.as_ptr(), identity.target.len(), u32::from(identity.selection), open_admission::<F, G>, open_recheck::<F, G>,
            (&mut context as *mut OpenAdmission<'_, F, G>).cast(), &mut wire); }
        returned.report = open_return(wire, context.rechecks, context.custody_known, identity.selection);
        returned.press_timing = context.press.timing(returned.report);
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
    fn selection_data_check() -> bool {
        // Inert decoder vectors only. These are not an AX/AppKit emulator or
        // evidence that an actual row, setter, URL or worker has returned.
        let proof = IdentityProofWire { flags: 1, checked: 0xfff, matched: 0xfff, parent: 2, panel: 8,
            children: 2, originals: 2, site: 14, error: 0 };
        let parent_proof = IdentityProofWire { flags: 3, ..proof };
        let full_recheck = RecheckWire { known: 1, error: 0, prompt: 1, proof };
        let parent_recheck = RecheckWire { proof: parent_proof, ..full_recheck };
        let Some(parent) = recheck_return(parent_recheck, 0) else { return false; };
        let Some(first) = recheck_return(full_recheck, 1) else { return false; };
        let Some(last) = recheck_return(full_recheck, 2) else { return false; };
        if parent.matched() || !parent.selection_parent_matched() || first.selection_parent_matched()
            || recheck_return(full_recheck, 0).is_some() || recheck_return(parent_recheck, 1).is_some()
            || recheck_return(parent_recheck, 2).is_some() { return false; }
        let refused_parent_proof = IdentityProofWire { flags: 3, checked: 7, matched: 3, site: 3, error: 3,
            ..IdentityProofWire::default() };
        let Some(refused_parent) = recheck_return(RecheckWire { known: 1, error: 3, prompt: 0, proof: refused_parent_proof }, 0)
            else { return false; };
        let refused_parent_wire = OpenWire { flags: 8, site: 20, error: 3, selection_mode: 1, ..OpenWire::default() };
        if !open_return(refused_parent_wire, [Some(refused_parent), None, None], true, true).is_some_and(|r|
            r.custody_known && !r.attempted && !r.succeeded() && !r.selection.unwrap().attempted
                && r.selection.unwrap().projection_summary.is_none())
            || open_return(OpenWire { error: 4, ..refused_parent_wire }, [Some(refused_parent), None, None], true, true).is_some()
            || open_return(OpenWire { calls: 1, ..refused_parent_wire }, [Some(refused_parent), None, None], true, true).is_some()
            { return false; }
        let rechecks = [Some(parent), Some(first), Some(last)];
        let full = OpenWire { flags: 15, site: 13, error: 0, checks: 127, calls: 221,
            initial_nodes_examined: 4, recheck_nodes_examined: 4, owned: 120, released: 120, ax_error: 0,
            last_role: 4, last_depth: 2, selection_mode: 1, selection_sample: 1, selection_checks: 31, selection_flags: 7,
            selection_nodes: 12, selection_matches: 1, selection_attribute: 1, selection_last_role: 15, selection_depth: 4,
            selection_summary_version: 2, selection_table_roles: 1, selection_entry_roots: 2,
            selection_title_absent: 2, selection_value_present: 2, selection_fixture_label_mask: 1,
            selection_expected_label_relations: 1, selection_expected_label_role_mask: 1 << 15, ..OpenWire::default() };
        if !content_readiness_data_check(full, rechecks) { return false; }
        if !open_return(full, rechecks, true, true).is_some_and(OpenReport::succeeded)
            || !open_return(OpenWire { selection_attribute: 2, ..full }, rechecks, true, true).is_some_and(OpenReport::succeeded)
            || open_return(full, rechecks, true, false).is_some() { return false; }
        // Synthetic widened-arena DATA only, not a native observation or promised pass.
        for nodes in [49, 50, 64, 127, 128, 255] {
            if !open_return(OpenWire { selection_nodes: nodes, ..full }, rechecks, true, true)
                .is_some_and(OpenReport::succeeded) { return false; }
        }
        // Aggregate counters remain selecting through both control passes and
        // Press. These closed DATA bounds are not native execution receipts.
        for (nodes, calls, slots) in [(12, 513, 257), (255, 2616, 1016), (255, 3072, 1024)] {
            let sample = OpenWire { selection_nodes: nodes, calls, owned: slots, released: slots, ..full };
            let Some(report) = open_return(sample, rechecks, true, true) else { return false; };
            if !report.succeeded() || report.button.matched()
                || open_return(sample, rechecks, true, false).is_some()
                || open_return(OpenWire { released: slots - 1, ..sample }, rechecks, true, true).is_some()
                { return false; }
        }
        for bit in 0..5 {
            if open_return(OpenWire { selection_checks: full.selection_checks & !(1 << bit), ..full }, rechecks, true, true).is_some() { return false; }
        }
        for bad in [OpenWire { selection_mode: 0, ..full }, OpenWire { selection_mode: 2, ..full },
            OpenWire { selection_flags: 0, ..full }, OpenWire { selection_flags: 1, ..full }, OpenWire { selection_flags: 3, ..full },
            OpenWire { selection_nodes: 0, ..full }, OpenWire { selection_nodes: 256, ..full },
            OpenWire { selection_matches: 0, ..full }, OpenWire { selection_matches: 2, ..full },
            OpenWire { selection_attribute: 0, ..full }, OpenWire { selection_attribute: 3, ..full },
            OpenWire { selection_last_role: 0, ..full }, OpenWire { selection_last_role: 17, ..full },
            OpenWire { selection_depth: 0, ..full }, OpenWire { selection_depth: 9, ..full },
            OpenWire { calls: 3073, ..full }, OpenWire { owned: 1025, released: 1025, ..full },
            OpenWire { released: 119, ..full }] {
            if open_return(bad, rechecks, true, true).is_some() { return false; }
        }
        for missing in 0..3 {
            let mut incomplete = rechecks; incomplete[missing] = None;
            if open_return(full, incomplete, true, true).is_some() { return false; }
        }
        for changed in [[Some(first), Some(first), Some(last)], [Some(parent), Some(parent), Some(last)],
            [Some(parent), Some(last), Some(first)]] {
            if open_return(full, changed, true, true).is_some() { return false; }
        }
        // Missing/ambiguous complete rosters are real failed DATA, not fabricated
        // success or permission to select a first match.
        let missing = OpenWire { flags: 8, site: 21, error: 4, checks: 3, calls: 100,
            initial_nodes_examined: 0, recheck_nodes_examined: 0, owned: 40, released: 40,
            last_role: 1, last_depth: 0, selection_checks: 1, selection_flags: 0,
            selection_nodes: 8, selection_matches: 0, selection_attribute: 0, selection_last_role: 11, selection_depth: 2,
            selection_fixture_label_mask: 0, selection_expected_label_relations: 0, selection_expected_label_role_mask: 0, ..full };
        let admitted = [Some(parent), None, None];
        // Inert summary DATA only. Null is unentered; an entered all-zero roster
        // is distinct and cannot supply a successful match, URL, setter or Press.
        let zero = OpenWire { error: 8, selection_checks: 0, selection_nodes: 0, selection_last_role: 0, selection_depth: 0,
            selection_table_roles: 0, selection_entry_roots: 0, selection_title_absent: 0, selection_value_present: 0, ..missing };
        let empty = SelectionProjectionSummary { table_roles: 0, outline_roles: 0, list_roles: 0, entry_roots: 0,
            title_present: 0, title_absent: 0, value_present: 0, outside_entry_role_mask: 0,
            fixture_label_mask: 0, expected_label_relations: 0, expected_label_role_mask: 0 };
        if !open_return(zero, admitted, true, true).is_some_and(|r|
            !r.succeeded() && !r.attempted && r.selection.is_some_and(|s| s.projection_summary == Some(empty) && !s.matched()))
            || open_return(OpenWire { selection_summary_version: 2, ..refused_parent_wire },
                [Some(refused_parent), None, None], true, true).is_some() { return false; }
        let no_entries = OpenWire { error: 4, selection_checks: 1, selection_nodes: 8, selection_last_role: 16,
            selection_depth: 2, selection_outside_entry_role_mask: 1 << 16, ..zero };
        for sample in [no_entries, OpenWire { selection_outside_entry_role_mask: 0x1c210, ..no_entries },
            OpenWire { selection_table_roles: 1, selection_last_role: 6, selection_outside_entry_role_mask: 0, ..no_entries },
            OpenWire { selection_table_roles: 1, selection_entry_roots: 1, selection_title_absent: 1,
                selection_last_role: 12, selection_outside_entry_role_mask: 0, ..no_entries },
            OpenWire { selection_table_roles: 1, selection_entry_roots: 1, selection_title_present: 1,
                selection_last_role: 12, selection_outside_entry_role_mask: 0, ..no_entries },
            OpenWire { selection_table_roles: 1, selection_entry_roots: 1, selection_title_absent: 1, selection_value_present: 1,
                selection_last_role: 15, selection_depth: 3, selection_outside_entry_role_mask: 0, ..no_entries }] {
            if !open_return(sample, admitted, true, true).is_some_and(|r| !r.succeeded() && !r.attempted
                && r.selection.is_some_and(|s| s.projection_summary.is_some() && s.matches == 0 && !s.matched())) { return false; }
        }
        // A present bounded label plus zero matches still does not prove that
        // the target was represented anywhere in this fixed grammar.
        for bad in [OpenWire { selection_summary_version: 0, ..zero }, OpenWire { selection_summary_version: 1, ..zero },
            OpenWire { selection_summary_version: 3, ..zero },
            OpenWire { selection_summary_version: 0, selection_table_roles: 1, site: 20, ..zero },
            OpenWire { selection_summary_version: 0, selection_outside_entry_role_mask: 16, site: 20, ..zero },
            OpenWire { selection_table_roles: 1, ..zero }, OpenWire { selection_outline_roles: 1, ..zero },
            OpenWire { selection_list_roles: 1, ..zero }, OpenWire { selection_entry_roots: 1, ..zero },
            OpenWire { selection_title_present: 1, ..zero }, OpenWire { selection_title_absent: 1, ..zero },
            OpenWire { selection_value_present: 1, ..zero }, OpenWire { selection_outside_entry_role_mask: 16, ..zero },
            OpenWire { selection_fixture_label_mask: 1, ..zero }, OpenWire { selection_expected_label_relations: 2, ..zero },
            OpenWire { selection_expected_label_role_mask: 1 << 15, ..zero },
            OpenWire { selection_summary_version: 0, ..full }, OpenWire { selection_table_roles: 256, ..full },
            OpenWire { selection_outline_roles: u32::MAX, ..full }, OpenWire { selection_list_roles: 13, ..full },
            OpenWire { selection_entry_roots: 13, ..full }, OpenWire { selection_title_present: 13, ..full },
            OpenWire { selection_title_absent: 13, ..full }, OpenWire { selection_value_present: 13, ..full },
            OpenWire { selection_table_roles: 12, selection_outline_roles: 1, ..full },
            OpenWire { selection_title_present: 9, selection_title_absent: 2, selection_value_present: 2, ..full },
            OpenWire { selection_table_roles: 0, ..full }, OpenWire { selection_entry_roots: 0, ..full },
            OpenWire { selection_entry_roots: 1, selection_matches: 2, selection_checks: 1, selection_flags: 0,
                selection_attribute: 0, ..full },
            OpenWire { selection_value_present: 0, ..full },
            OpenWire { selection_outside_entry_role_mask: 1 << 12, ..full },
            OpenWire { selection_outside_entry_role_mask: 1 << 13, ..full },
            OpenWire { selection_outside_entry_role_mask: u32::MAX, ..full },
            OpenWire { selection_fixture_label_mask: 32, ..full }, OpenWire { selection_fixture_label_mask: 7, ..full },
            OpenWire { selection_expected_label_relations: 8, ..full }, OpenWire { selection_expected_label_relations: 2, ..full },
            OpenWire { selection_expected_label_role_mask: 0, ..full }, OpenWire { selection_expected_label_role_mask: 1 << 4, ..full },
            OpenWire { selection_expected_label_role_mask: (1 << 12) | (1 << 13) | (1 << 14), ..full },
            OpenWire { selection_expected_label_relations: 1, selection_expected_label_role_mask: 1 << 15, ..missing }] {
            if selection_return(bad).is_some() { return false; }
        }
        // Closed relations describe actual scalar observations, not permission
        // to accept a case-insensitive/decorated label or choose a first match.
        for sample in [OpenWire { selection_fixture_label_mask: 8, ..missing },
            OpenWire { selection_expected_label_relations: 2, selection_expected_label_role_mask: 1 << 16, ..missing },
            OpenWire { selection_expected_label_relations: 4, selection_expected_label_role_mask: 1 << 15, ..missing },
            OpenWire { selection_expected_label_relations: 6, selection_expected_label_role_mask: (1 << 15) | (1 << 16), ..missing }] {
            if !open_return(sample, admitted, true, true).is_some_and(|r| !r.succeeded() && !r.attempted
                && r.selection.is_some_and(|s| !s.matched() && s.matches == 0)) { return false; }
        }
        if !open_return(OpenWire { selection_fixture_label_mask: 31, selection_value_present: 5,
            selection_expected_label_relations: 7, selection_expected_label_role_mask: (1 << 15) | (1 << 16), ..full },
            rechecks, true, true).is_some_and(OpenReport::succeeded) { return false; }
        let ordinary = OpenWire { selection_mode: 0, selection_sample: 0, selection_checks: 0, selection_flags: 0, selection_nodes: 0,
            selection_matches: 0, selection_attribute: 0, selection_last_role: 0, selection_depth: 0,
            selection_summary_version: 0, selection_table_roles: 0, selection_entry_roots: 0,
            selection_title_absent: 0, selection_value_present: 0, selection_fixture_label_mask: 0,
            selection_expected_label_relations: 0, selection_expected_label_role_mask: 0, ..full };
        let ordinary_rechecks = [None, Some(first), Some(last)];
        if !open_return(ordinary, ordinary_rechecks, true, false).is_some_and(OpenReport::succeeded) { return false; }
        for bad in [OpenWire { selection_summary_version: 2, ..ordinary }, OpenWire { selection_table_roles: 1, ..ordinary },
            OpenWire { selection_outline_roles: 1, ..ordinary }, OpenWire { selection_list_roles: 1, ..ordinary },
            OpenWire { selection_entry_roots: 1, ..ordinary }, OpenWire { selection_title_present: 1, ..ordinary },
            OpenWire { selection_title_absent: 1, ..ordinary }, OpenWire { selection_value_present: 1, ..ordinary },
            OpenWire { selection_outside_entry_role_mask: 16, ..ordinary },
            OpenWire { selection_fixture_label_mask: 1, ..ordinary },
            OpenWire { selection_expected_label_relations: 2, ..ordinary },
            OpenWire { selection_expected_label_role_mask: 1 << 15, ..ordinary }] {
            if open_return(bad, ordinary_rechecks, true, false).is_some() { return false; }
        }
        // Synthetic bounded refusal DATA, never an AX result or Open authority.
        let limit = OpenWire { error: 7, calls: 202, owned: 88, released: 88, selection_checks: 0,
            selection_nodes: 24, selection_matches: 0, selection_last_role: 12, selection_depth: 4,
            selection_limit: 1, selection_limit_cap: 512, selection_limit_observed: 513, selection_limit_queued: 25, ..missing };
        for malformed in [OpenWire { selection_limit: 1, ..full }, OpenWire { selection_limit_cap: 1, ..full },
            OpenWire { selection_limit_queued: 1, ..full }, OpenWire { selection_limit_children: 1, ..full },
            OpenWire { selection_limit_observed: 1, ..full }] {
            if open_return(malformed, rechecks, true, true).is_some() { return false; }
        }
        if !open_return(OpenWire { flags: 0, released: 0, ..limit }, admitted, false, true).is_some_and(|r|
            !r.custody_known && !r.succeeded() && r.selection.is_some_and(|s| s.limit.is_some())) { return false; }
        let queue = OpenWire { selection_limit: 4, selection_limit_cap: 256, selection_limit_observed: 256,
            selection_limit_queued: 256, selection_limit_children: 1, ..limit };
        for refused in [limit, OpenWire { selection_limit_observed: i64::MAX, ..limit },
            OpenWire { selection_limit: 2, selection_limit_cap: 16, selection_limit_observed: 17, ..limit },
            OpenWire { selection_limit: 2, selection_limit_cap: 32, selection_limit_observed: 33, selection_last_role: 6, ..limit },
            OpenWire { selection_limit: 3, selection_limit_cap: 16, selection_limit_observed: 17, ..limit },
            OpenWire { selection_limit: 3, selection_limit_cap: 32, selection_limit_observed: i64::MIN, selection_last_role: 11, ..limit },
            queue, OpenWire { selection_limit_observed: 247, selection_limit_queued: 247, selection_limit_children: 10, ..queue },
            OpenWire { selection_limit: 5, selection_limit_cap: 8, selection_limit_observed: 8,
                selection_depth: 8, selection_limit_children: 16, ..queue },
            OpenWire { selection_limit: 6, selection_limit_cap: 3072, selection_limit_observed: 3072, calls: 3072, ..limit },
            OpenWire { selection_limit: 7, selection_limit_cap: 1024, selection_limit_observed: 1024,
                owned: 1024, released: 1024, ..limit },
            OpenWire { site: 22, selection_checks: 3, selection_matches: 1, selection_limit_queued: 0,
                selection_expected_label_relations: 1, selection_expected_label_role_mask: 1 << 15,
                selection_limit: 6, selection_limit_cap: 3072, selection_limit_observed: 3071, calls: 3071, ..limit },
            OpenWire { site: 25, selection_checks: 15, selection_flags: 7, selection_attribute: 1, selection_matches: 1,
                selection_expected_label_relations: 1, selection_expected_label_role_mask: 1 << 15,
                selection_limit: 2, selection_limit_cap: 32, selection_limit_observed: 33, selection_limit_queued: 0, ..limit }] {
            if !open_return(refused, admitted, true, true).is_some_and(|r| !r.succeeded() && !r.attempted
                && r.selection.is_some_and(|s| !s.matched() && s.limit.is_some())) { return false; }
        }
        for bad in [OpenWire { selection_limit: 0, ..limit }, OpenWire { selection_limit: 8, ..limit },
            OpenWire { selection_limit_cap: 513, ..limit }, OpenWire { selection_limit_observed: 512, ..limit },
            OpenWire { selection_limit_queued: 0, ..limit }, OpenWire { selection_limit_queued: 24, ..limit },
            OpenWire { selection_limit_queued: 257, ..limit }, OpenWire { selection_limit_children: 1, ..limit },
            OpenWire { error: 8, ..limit }, OpenWire { ax_error: -25204, ax_failure_operation: 2, ax_failure_attribute: 1, ..limit }, OpenWire { site: 24, ..limit },
            OpenWire { selection_limit: 2, selection_limit_cap: 32, selection_limit_observed: 33, ..limit },
            OpenWire { selection_limit: 3, selection_limit_cap: 16, selection_limit_observed: 0, ..limit },
            OpenWire { selection_limit_observed: 255, selection_limit_queued: 255, selection_limit_children: 1, ..queue },
            // Historical caps are not current-source refusal predicates.
            OpenWire { selection_limit_cap: 49, selection_limit_observed: 49,
                selection_limit_queued: 49, selection_limit_children: 1, ..queue },
            OpenWire { selection_limit_cap: 128, selection_limit_observed: 128,
                selection_limit_queued: 128, selection_limit_children: 1, ..queue },
            OpenWire { selection_limit: 6, selection_limit_cap: 512, selection_limit_observed: 512, calls: 512, ..limit },
            OpenWire { selection_limit: 7, selection_limit_cap: 256, selection_limit_observed: 256,
                owned: 256, released: 256, ..limit },
            OpenWire { selection_limit_children: 0, ..queue }, OpenWire { selection_limit_children: 17, ..queue },
            OpenWire { selection_depth: 8, ..queue },
            OpenWire { selection_limit: 5, selection_limit_cap: 8, selection_limit_observed: 8, ..queue },
            OpenWire { selection_limit: 6, selection_limit_cap: 3072, selection_limit_observed: 3070, calls: 3070, ..limit },
            OpenWire { selection_limit: 7, selection_limit_cap: 1024, selection_limit_observed: 1023, owned: 1023, released: 1023, ..limit },
            OpenWire { selection_limit: 0, selection_limit_observed: 1, ..full },
            OpenWire { selection_limit: 1, selection_limit_cap: 512, selection_limit_observed: 513, ..full }] {
            if open_return(bad, admitted, true, true).is_some() { return false; }
        }
        for failed in [missing, OpenWire { error: 5, selection_matches: 2,
            selection_expected_label_relations: 1, selection_expected_label_role_mask: 1 << 15, ..missing },
            OpenWire { error: 7, selection_checks: 0, selection_matches: 1, selection_limit: 2,
                selection_expected_label_relations: 1, selection_expected_label_role_mask: 1 << 15,
                selection_limit_cap: 32, selection_limit_observed: 33, selection_limit_queued: 9, ..missing }] {
            if !open_return(failed, admitted, true, true).is_some_and(|r| r.custody_known
                && !r.attempted && !r.selection.unwrap().attempted && !r.succeeded()) { return false; }
        }
        for bad in [OpenWire { selection_nodes: 1, selection_matches: 2, selection_depth: 1, ..missing },
            OpenWire { selection_depth: 0, ..missing }, OpenWire { selection_last_role: 0, ..missing }] {
            if open_return(bad, admitted, true, true).is_some() { return false; }
        }
        let write = OpenWire { site: 24, error: 11, ax_error: -25204, selection_checks: 15, selection_flags: 3,
            ax_failure_operation: 7, ax_failure_attribute: 11,
            selection_matches: 1, selection_attribute: 1, selection_expected_label_relations: 1,
            selection_expected_label_role_mask: 1 << 15, ..missing };
        if !open_return(write, admitted, true, true).is_some_and(|r| !r.attempted && !r.succeeded()
            && r.selection.is_some_and(|s| s.attempted && s.returned && s.selected == Some(false))) { return false; }
        let readback = OpenWire { site: 25, error: 13, ax_error: 0, ax_failure_operation: 0, ax_failure_attribute: 0,
            selection_flags: 7, ..write };
        if !open_return(readback, admitted, true, true).is_some_and(|r| !r.attempted && !r.succeeded()
            && r.selection.is_some_and(|s| s.selected == Some(true) && !s.matched())) { return false; }
        // A real selection/readback still cannot replace actual singleton-URL
        // readiness. Keep this refused full proof and never progress to Open.
        let url_proof = IdentityProofWire { flags: 1, checked: 7, matched: 3, site: 3, error: 3, ..IdentityProofWire::default() };
        let Some(refused) = recheck_return(RecheckWire { known: 1, error: 3, prompt: 0, proof: url_proof }, 1) else { return false; };
        let no_url = OpenWire { site: 10, error: 3, selection_checks: 31, ..readback };
        if !open_return(no_url, [Some(parent), Some(refused), None], true, true).is_some_and(|r|
            !r.attempted && !r.succeeded() && r.selection.is_some_and(VersionSourceSelection::matched)
                && !r.initial_proof.unwrap().matched()) { return false; }
        open_return(OpenWire { error: 8, ..full }, rechecks, true, true).is_some_and(|r| !r.succeeded())
            && open_return(OpenWire { flags: 7, error: 9, ..full }, rechecks, false, true)
                .is_some_and(|r| !r.custody_known && !r.succeeded())
            && open_return(full, rechecks, false, true).is_none()
    }
    fn ax_failure_data_check() -> bool {
        // Inert closed-decoder DATA, never a native AX return or action receipt.
        let pairs: [(u32, u32, &str, Option<&str>); 24] = [
            (1, 0, "set-messaging-timeout", None),
            (2, 1, "copy-attribute-value", Some("Parent")),
            (2, 2, "copy-attribute-value", Some("Role")),
            (2, 3, "copy-attribute-value", Some("Identifier")),
            (2, 4, "copy-attribute-value", Some("Title")),
            (2, 5, "copy-attribute-value", Some("Value")),
            (2, 6, "copy-attribute-value", Some("Enabled")),
            (3, 7, "get-attribute-value-count", Some("Windows")),
            (3, 8, "get-attribute-value-count", Some("Children")),
            (3, 9, "get-attribute-value-count", Some("Rows")),
            (3, 10, "get-attribute-value-count", Some("SelectedChildren")),
            (3, 11, "get-attribute-value-count", Some("SelectedRows")),
            (4, 7, "copy-attribute-values", Some("Windows")),
            (4, 8, "copy-attribute-values", Some("Children")),
            (4, 9, "copy-attribute-values", Some("Rows")),
            (4, 10, "copy-attribute-values", Some("SelectedChildren")),
            (4, 11, "copy-attribute-values", Some("SelectedRows")),
            (5, 0, "copy-action-names", None),
            (6, 10, "is-attribute-settable", Some("SelectedChildren")),
            (6, 11, "is-attribute-settable", Some("SelectedRows")),
            (7, 10, "set-attribute-value", Some("SelectedChildren")),
            (7, 11, "set-attribute-value", Some("SelectedRows")),
            (8, 0, "perform-action", None),
            (9, 0, "copy-multiple-attribute-values", None),
        ];
        let mut admitted_pairs = 0;
        for operation in (0u32..=10).chain([u32::MAX]) {
            for attribute in (0u32..=12).chain([u32::MAX]) {
                let pair = pairs.iter().find(|p| p.0 == operation && p.1 == attribute);
                if pair.is_some() { admitted_pairs += 1; }
                for ax_error in (-25214..=-25200).chain([0, 1, -1, -25215, -25199, i32::MIN, i32::MAX]) {
                    let expected = if ax_error == 0 {
                        (operation == 0 && attribute == 0).then_some(None)
                    } else if (-25214..=-25200).contains(&ax_error) {
                        pair.map(|p| Some(AxFailure { operation: p.2, attribute: p.3 }))
                    } else { None };
                    let wire = OpenWire { ax_error, ax_failure_operation: operation, ax_failure_attribute: attribute,
                        ..OpenWire::default() };
                    if ax_failure_return(wire) != expected { return false; }
                }
            }
        }
        admitted_pairs == 24 && ax_failure_return(OpenWire::default()) == Some(None)
    }
    fn press_timing_data_check(failed: OpenReport) -> bool {
        // Inert callback/clock DATA only. No C, AX, native receipt or sleep.
        // The unwind regression must refuse rather than abort on an abort profile.
        if !cfg!(panic = "unwind") { return false; }
        fn invoke<F, G>(context: &mut OpenAdmission<'_, F, G>, required: u64, after: c_int) -> c_int
        where F: FnMut(bool) -> Option<bool>, G: FnMut(u32) -> Result<(OpenRecheckReturn, bool), u32> {
            unsafe { open_admission::<F, G>((context as *mut OpenAdmission<'_, F, G>).cast(),
                required, after, std::ptr::null_mut()) }
        }
        let mode = std::cell::Cell::new(0);
        let mut admit = |_: bool| match mode.get() {
            0 => Some(true), 1 => Some(false), 2 => None,
            // Exercise the existing unwind catcher without invoking a panic hook.
            _ => std::panic::resume_unwind(Box::new(())),
        };
        let mut recheck = |_: u32| -> Result<(OpenRecheckReturn, bool), u32> { Err(9) };
        let now = Instant::now(); let Some(end) = now.checked_add(Duration::from_secs(60)) else { return false; };
        let mut context = OpenAdmission { end, admit: &mut admit, recheck: &mut recheck,
            rechecks: [None; 3], next_recheck: 1, custody_known: true, press: OpenPressCapture::default() };
        if std::mem::size_of::<OpenPressCapture>() > 96 || std::mem::size_of::<OpenPressTiming>() > 32
            || invoke(&mut context, 10, 0) != 0 || invoke(&mut context, 20, 0) != 0 { return false; }
        let permit = context.press.permit;
        if permit.map(|p| p.0) != Some(20) { return false; }
        mode.set(1);
        if invoke(&mut context, 30, 0) != 3 || context.press.permit != permit { return false; }
        mode.set(0);
        if invoke(&mut context, 0, 0) != 0 || context.press.permit != permit
            || invoke(&mut context, 0, 1) != 0 { return false; }
        let first = context.press.returned_at;
        if first.is_none() || invoke(&mut context, 0, 1) != 0 || context.press.returned_at != first
            || invoke(&mut context, 40, 0) != 0 || context.press.permit != permit
            || !context.press.timing(Some(failed)).is_some_and(|t| t.installed_allowance_ns == 20
                && t.last_permit_to_return_admission_ns.is_some()) { return false; }
        for refusal in [2, 3, 4] {
            context.press = OpenPressCapture::default(); context.custody_known = true; mode.set(0);
            if invoke(&mut context, 50, 0) != 0 { return false; }
            let permit = context.press.permit;
            mode.set(if refusal == 4 { 0 } else { refusal });
            if invoke(&mut context, if refusal == 4 { 100_000_001 } else { 0 }, 1) != 9
                || !context.press.after_attempted || context.press.returned_at.is_some() || context.custody_known { return false; }
            mode.set(0);
            if invoke(&mut context, 0, 1) != 0 || context.press.returned_at.is_some() || context.press.permit != permit
                || context.press.timing(Some(failed)) != Some(OpenPressTiming {
                    installed_allowance_ns: 50, last_permit_to_return_admission_ns: None }) { return false; }
        }
        // Reaching the existing return clock records DATA even on ineligibility
        // or deadline. Neither return code nor any owner permission is changed.
        for late in [false, true] {
            context.press = OpenPressCapture::default(); context.custody_known = true; context.end = end; mode.set(0);
            if invoke(&mut context, 60, 0) != 0 { return false; }
            if late { context.end = now; } else { mode.set(1); }
            if invoke(&mut context, 0, 1) != (if late { 8 } else { 3 })
                || !context.press.timing(Some(failed)).is_some_and(|t| t.last_permit_to_return_admission_ns.is_some()) { return false; }
        }
        let mut exact = OpenPressCapture { permit: Some((1, now)), after_attempted: true, returned_at: Some(now) };
        if exact.timing(Some(failed)) != Some(OpenPressTiming {
            installed_allowance_ns: 1, last_permit_to_return_admission_ns: Some(0) }) { return false; }
        let Some(later) = now.checked_add(Duration::from_nanos(1)) else { return false; };
        exact.permit = Some((1, later));
        if exact.timing(Some(failed)).and_then(|t| t.last_permit_to_return_admission_ns).is_some()
            || OpenPressCapture::duration_ns(Duration::from_nanos(u64::MAX)) != Some(u64::MAX)
            || OpenPressCapture::duration_ns(Duration::from_nanos(u64::MAX) + Duration::from_nanos(1)).is_some()
            || OpenPressCapture::default().timing(Some(failed)).is_some() || exact.timing(None).is_some() { return false; }
        for invalid in [OpenReport { attempted: false, ..failed }, OpenReport { press_returned: false, ..failed },
            OpenReport { triggered: Some(true), ..failed },
            OpenReport { button: ControlContainerButtonProof { ax_error: -25202, ..failed.button }, ..failed },
            OpenReport { button: ControlContainerButtonProof { ax_failure: None, ..failed.button }, ..failed },
            OpenReport { button: ControlContainerButtonProof {
                ax_failure: Some(AxFailure { operation: "set-messaging-timeout", attribute: None }), ..failed.button }, ..failed }] {
            if exact.timing(Some(invalid)).is_some() { return false; }
        }
        true
    }
    fn semantic_data_check() -> bool {
        // Inert decoder/timeout DATA only: never manufacture a native return.
        let ordinary_return = |w, r: [Option<OpenRecheckReturn>; 2], known|
            open_return(w, [None, r[0], r[1]], known, false);
        if std::mem::size_of::<IdentityWire>() != 56 || std::mem::size_of::<OpenWire>() != 704
            || std::mem::offset_of!(OpenWire, selection_sample) != 160
            || std::mem::offset_of!(OpenWire, selection_pending) != 176
            || std::mem::offset_of!(OpenWire, selection_projection_diagnostic) != 624
            || std::mem::offset_of!(OpenWire, selection_limit_observed) != 96
            || std::mem::offset_of!(OpenWire, ax_failure_operation) != 104
            || std::mem::offset_of!(OpenWire, ax_failure_attribute) != 108
            || std::mem::offset_of!(OpenWire, selection_summary_version) != 112
            || std::mem::offset_of!(OpenWire, selection_table_roles) != 116
            || std::mem::offset_of!(OpenWire, selection_outline_roles) != 120
            || std::mem::offset_of!(OpenWire, selection_list_roles) != 124
            || std::mem::offset_of!(OpenWire, selection_entry_roots) != 128
            || std::mem::offset_of!(OpenWire, selection_title_present) != 132
            || std::mem::offset_of!(OpenWire, selection_title_absent) != 136
            || std::mem::offset_of!(OpenWire, selection_value_present) != 140
            || std::mem::offset_of!(OpenWire, selection_outside_entry_role_mask) != 144
            || std::mem::offset_of!(OpenWire, selection_fixture_label_mask) != 148
            || std::mem::offset_of!(OpenWire, selection_expected_label_relations) != 152
            || std::mem::offset_of!(OpenWire, selection_expected_label_role_mask) != 156
            || std::mem::size_of::<RecheckWire>() != 48 || std::mem::size_of::<OpenTimeout>() != 16
            || !completion_data_check() || !selection_data_check() || !ax_failure_data_check()
            || !projection_diagnostic_data_check() { return false; }
        let p = IdentityProofWire { flags: 1, checked: 0xfff, matched: 0xfff, parent: 2, panel: 8,
            children: 2, originals: 2, site: 14, error: 0 };
        let rw = RecheckWire { known: 1, error: 0, prompt: 1, proof: p };
        let Some(recheck) = recheck_return(rw, 1) else { return false; };
        let Some(final_recheck) = recheck_return(rw, 2) else { return false; };
        let rechecks = [Some(recheck), Some(final_recheck)];
        let full = OpenWire { flags: 15, site: 13, error: 0, checks: 127, calls: 101,
            initial_nodes_examined: 4, recheck_nodes_examined: 4, owned: 60, released: 60, ax_error: 0,
            last_role: 4, last_depth: 2, ..OpenWire::default() };
        let Some(success) = ordinary_return(full, rechecks, true) else { return false; };
        if !success.succeeded() || success.button.ax_failure.is_some() { return false; }
        let contradictory = ControlContainerButtonProof {
            ax_failure: Some(AxFailure { operation: "perform-action", attribute: None }), ..success.button };
        if contradictory.matched() { return false; }
        for malformed in [OpenWire { ax_failure_operation: 8, ..full }, OpenWire { ax_failure_attribute: 1, ..full }] {
            if ordinary_return(malformed, rechecks, true).is_some() { return false; }
        }
        // Neither incomplete eligible projection, missing unique button, nor
        // unperformed same-original control-path recheck may pass the proof.
        for bit in 0..7 {
            if ordinary_return(OpenWire { checks: full.checks & !(1 << bit), ..full }, rechecks, true).is_some() { return false; }
        }
        for bad in [OpenWire { selection_limit: 1, ..full }, OpenWire { selection_limit_cap: 1, ..full },
            OpenWire { selection_limit_queued: 1, ..full }, OpenWire { selection_limit_children: 1, ..full },
            OpenWire { selection_limit_observed: 1, ..full },
            OpenWire { calls: 513, ..full }, OpenWire { initial_nodes_examined: 17, ..full },
            OpenWire { initial_nodes_examined: 0, ..full }, OpenWire { recheck_nodes_examined: 0, ..full },
            OpenWire { recheck_nodes_examined: 17, ..full }, OpenWire { last_role: 10, ..full },
            OpenWire { last_role: 2, ..full }, OpenWire { last_depth: 0, ..full }, OpenWire { last_depth: 9, ..full },
            OpenWire { owned: 257, released: 257, ..full }, OpenWire { released: 59, ..full },
            OpenWire { ax_error: 1, ax_failure_operation: 8, ax_failure_attribute: 0, ..full }, OpenWire { checks: 255, ..full }, OpenWire { flags: 31, ..full }] {
            if ordinary_return(bad, rechecks, true).is_some() { return false; }
        }
        for bad in [RecheckWire { prompt: 0, ..rw }, RecheckWire { prompt: 2, ..rw },
            RecheckWire { known: 0, ..rw }, RecheckWire { proof: IdentityProofWire::default(), ..rw }] {
            if recheck_return(bad, 1).is_some() { return false; }
        }
        // Immutable target DATA is bound before native start, never a selected-path substitute.
        let mut target = [0u8; 4097]; target[..23].copy_from_slice(b"/synthetic/project-root");
        if !project_target(&target) { return false; }
        for bad in [b"/".as_slice(), b"/synthetic/../root", b"/synthetic//root", b"relative/root", b"/synthetic/root/"] {
            let mut bytes = [0u8; 4097]; bytes[..bad.len()].copy_from_slice(bad);
            if project_target(&bytes) { return false; }
        }
        target[100] = 1; if project_target(&target) { return false; }
        if ordinary_return(full, [Some(recheck); 2], true).is_some() { return false; }
        // A common-budget refusal still cannot invent Press or native finality.
        let budget_limited = OpenWire { flags: 8, site: 7, error: 7, checks: 3, calls: 512,
            initial_nodes_examined: 3, recheck_nodes_examined: 0, owned: 256, released: 256,
            last_role: 2, last_depth: 2, ..full };
        for (flags, released, known) in [(8, 256, true), (8, 256, false), (0, 16, false), (0, 16, true)] {
            let Some(r) = ordinary_return(OpenWire { flags, released, ..budget_limited }, [Some(recheck), None], known)
                else { return false; };
            if r.diagnostic != (OpenDiagnostic { site: "control-projection", error: "limit" })
                || r.attempted || r.press_returned || r.triggered.is_some()
                || r.proof.is_some() || r.succeeded() || r.custody_known != (known && flags & 8 != 0)
                || r.button.calls != 512 || r.button.cf_slots != 256 || r.button.cf_slots_retired != released
                || r.button.cleanup_returned != (flags & 8 != 0) { return false; }
        }
        for bad in [OpenWire { flags: 9, ..budget_limited }, OpenWire { error: 0, ..budget_limited },
            OpenWire { calls: 513, ..budget_limited }, OpenWire { owned: 257, released: 257, ..budget_limited },
            OpenWire { initial_nodes_examined: 17, ..budget_limited }, OpenWire { released: 16, ..budget_limited }] {
            if ordinary_return(bad, [Some(recheck), None], true).is_some() { return false; }
        }
        for (initial, recheck, depth) in [(1, 1, 1), (4, 6, 3), (16, 16, 8)] {
            if !ordinary_return(OpenWire { initial_nodes_examined: initial, recheck_nodes_examined: recheck, last_depth: depth, ..full }, rechecks, true)
                .is_some_and(OpenReport::succeeded) { return false; }
        }
        // Complete first projection: zero/two matches, including a disabled
        // duplicate in another admitted branch. Recheck ambiguity, replacement,
        // changed role/title or reparenting never authorizes Press.
        for (checks, error) in [(7, 4), (7, 5), (3, 7), (63, 4), (63, 5), (63, 13)] {
            let failed = OpenWire { flags: 8, site: if checks == 63 { 9 } else { 7 }, error, checks,
                recheck_nodes_examined: if checks == 63 { 4 } else { 0 }, ..full };
            if !ordinary_return(failed, [Some(recheck), None], true).is_some_and(|r| !r.attempted && !r.succeeded()) { return false; }
        }
        // A node can fail its type/parent/role before a role was read. Keeping
        // not-read + this positive depth is essential to honest diagnostics.
        for checks in [3, 63] {
            let failed = OpenWire { flags: 8, site: if checks == 3 { 7 } else { 9 }, error: 6, checks,
                initial_nodes_examined: 4, recheck_nodes_examined: if checks == 3 { 0 } else { 2 },
                last_role: 0, last_depth: 2, ..full };
            if !ordinary_return(failed, [Some(recheck), None], true).is_some_and(|r|
                r.button.last_role == "not-read" && r.button.last_depth == 2 && !r.succeeded()) { return false; }
        }
        for (checks, initial, again) in [(1, 1, 0), (3, 17, 0), (7, 0, 0), (15, 4, 1), (31, 4, 1), (127, 4, 0)] {
            let failed = OpenWire { flags: 8, site: 7, error: 7, checks,
                initial_nodes_examined: initial, recheck_nodes_examined: again, ..full };
            if ordinary_return(failed, [Some(recheck), None], true).is_some() { return false; }
        }
        if ordinary_return(OpenWire { flags: 8, site: 9, error: 6, checks: 63, initial_nodes_examined: 8,
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
                        let returned = ordinary_return(OpenWire { flags, released, ..failed }, [Some(recheck), None], known);
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
                    OpenWire { checks: 7, ..failed }, OpenWire { ax_error: -25204, ax_failure_operation: 2, ax_failure_attribute: 1, ..failed },
                    OpenWire { flags: 9, ..failed }, OpenWire { site: 20, ..failed }, OpenWire { last_role: 0, ..failed },
                    OpenWire { last_role: 9, ..failed }, OpenWire { last_depth: 9, ..failed }] {
                    if ordinary_return(bad, [Some(recheck), None], true).is_some() { return false; }
                }
                if ordinary_return(failed, [None; 2], true).is_some() || ordinary_return(failed, rechecks, true).is_some()
                    || ordinary_return(OpenWire { site, ..full }, rechecks, true).is_some() { return false; }
            }
        }
        let changed = recheck_return(RecheckWire { prompt: 2, error: 13, ..rw }, 2);
        if !changed.is_some_and(|r| r.custody_known && !r.matched()) { return false; }
        for ns in [1, 99, 10_000_001, 99_999_999, 100_000_000, 2_000_000_000] {
            let Some(t) = timeout_for(Duration::from_nanos(ns)) else { return false; };
            if t.required_ns > ns.min(100_000_000) || t.required_ns == 0
                || t.required_ns != (f64::from(t.seconds) * 1_000_000_000.0).ceil() as u64 { return false; }
        }
        let Some(failed_press) = ordinary_return(OpenWire { flags: 11, error: 11, ax_error: -25204,
            ax_failure_operation: 8, ax_failure_attribute: 0, ..full }, rechecks, true) else { return false; };
        if !press_timing_data_check(failed_press) { return false; }
        timeout_for(Duration::ZERO).is_none()
            && ordinary_return(OpenWire { flags: 11, error: 11, ax_error: -25204,
                ax_failure_operation: 8, ax_failure_attribute: 0, ..full }, rechecks, true)
                .is_some_and(|r| r.press_returned && r.triggered == Some(false) && !r.succeeded()
                    && r.button.ax_failure == Some(AxFailure { operation: "perform-action", attribute: None }))
            // Earlier overall deadline and first actual AX fault are independent.
            && ordinary_return(OpenWire { flags: 11, error: 8, ax_error: -25204,
                ax_failure_operation: 8, ax_failure_attribute: 0, ..full }, rechecks, true)
                .is_some_and(|r| r.diagnostic.error == "deadline" && r.button.ax_error == -25204
                    && r.button.ax_failure == Some(AxFailure { operation: "perform-action", attribute: None })
                    && r.press_returned && r.triggered == Some(false) && !r.succeeded())
            && ordinary_return(OpenWire { error: 8, ..full }, rechecks, true)
                .is_some_and(|r| r.press_returned && r.triggered == Some(true) && !r.succeeded())
            && ordinary_return(OpenWire { flags: 7, error: 9, ..full }, rechecks, false)
                .is_some_and(|r| r.press_returned && !r.custody_known && !r.succeeded())
            && ordinary_return(OpenWire { flags: 1, error: 14, released: 0, ..full }, rechecks, false)
                .is_some_and(|r| r.attempted && !r.press_returned && !r.custody_known)
            && ordinary_return(OpenWire { error: 8, flags: 8, site: 12, ..full }, rechecks, true)
                .is_some_and(|r| !r.attempted && r.custody_known && !r.succeeded())
            && ordinary_return(full, [Some(recheck), None], true).is_none()
            && ordinary_return(full, rechecks, false).is_none()
    }
    fn observation_flags_valid(flags: u32) -> bool {
        let both_present = flags & 0x3000 == 0x3000;
        let readiness = (flags >> 17) & 3;
        flags & !0x1fffff == 0 && (flags & 2 != 0) == (flags & 0x1f000 == 0x1f000)
            && (both_present || flags & 0xc000 == 0)
            && (flags & 0x2000 != 0 || flags & 0x10000 == 0)
            && (flags & 16 != 0) == (readiness == 3)
            && (readiness == 0 || flags & 0x200c == 0x200c)
            && (flags & 0x80000 == 0 || flags == 0x9f00f)
            && (flags & 0x100000 == 0 || matches!(flags, 0x15f00f | 0x17f01f))
    }
    fn observation_directory_readiness(kind: PanelKind, flags: u32) -> Option<&'static str> {
        if !observation_flags_valid(flags) || flags & 0x180000 != 0 && kind != PanelKind::VersionSource { return None; }
        match (flags >> 17) & 3 {
            0 => Some("not-ready"),
            1 if !matches!(kind, PanelKind::Quit) => Some("directory-not-matched"),
            2 if kind == PanelKind::File => Some("filename-not-matched"),
            2 if kind == PanelKind::VersionSource => Some("selection-not-matched"),
            3 if !matches!(kind, PanelKind::Quit) => Some("ready"),
            _ => None,
        }
    }
    fn observation_name_sample_valid(kind: PanelKind, flags: u32, sample: u32) -> bool {
        observation_directory_readiness(kind, flags).is_some() && (sample != 0) == (flags & 0x180000 != 0)
    }
    /// Pure checks called by the existing instrumented observer entry, not a
    /// native query or a separate test executable/qualification route.
    pub fn installed_observation_flags_data_check() -> bool {
        action_diagnostics_data_check() && identity_data_check() && semantic_data_check() && original_window_data_check()
            && project_field_data_check() && evidence_folder_abi_data_check() && public_images_abi_data_check()
            && [0, 0x1000, 0x2000, 0x12000, 0x3000, 0xf000, 0x1f002, 0x2200c, 0x4200c, 0x6201c, 0x7ffff, 0x9f00f, 0x15f00f, 0x17f01f]
                .into_iter().all(observation_flags_valid)
            && [2, 0x4000, 0x8000, 0x10000, 0x14000, 0x1f000, 0x1ffff, 0x20000,
                0x22008, 0x22004, 0x6001c, 0x6200c, 0x2201c, 0x4201c, 0x80000, 0x100000, 0x1df00f, 0x15f01f, u32::MAX]
                .into_iter().all(|flags| !observation_flags_valid(flags))
            && [PanelKind::Project, PanelKind::Quit, PanelKind::File, PanelKind::VersionSource,
                PanelKind::IosProject, PanelKind::IosWorkspace, PanelKind::MetadataRoot, PanelKind::EvidenceFolder, PanelKind::PublicImages].into_iter().all(|kind| {
                observation_directory_readiness(kind, 0) == Some("not-ready")
                    && observation_directory_readiness(kind, 0x2200c)
                        == (!matches!(kind, PanelKind::Quit)).then_some("directory-not-matched")
                    && observation_directory_readiness(kind, 0x4200c)
                        == match kind {
                            PanelKind::File => Some("filename-not-matched"),
                            PanelKind::VersionSource => Some("selection-not-matched"),
                            _ => None,
                        }
                    && observation_directory_readiness(kind, 0x6201c)
                        == (!matches!(kind, PanelKind::Quit)).then_some("ready")
                    && observation_directory_readiness(kind, 0x1ffff).is_none()
                    && observation_name_sample_valid(kind, 0x9f00f, 1) == (kind == PanelKind::VersionSource)
                    && !observation_name_sample_valid(kind, 0x9f00f, 0)
                    && !observation_name_sample_valid(kind, 0x6201c, 1)
                    && !observation_name_sample_valid(kind, 0x9f01f, 1)
                    && !observation_name_sample_valid(kind, 0xbf00f, 1)
                    && observation_name_sample_valid(kind, 0x15f00f, 2) == (kind == PanelKind::VersionSource)
                    && observation_name_sample_valid(kind, 0x17f01f, 2) == (kind == PanelKind::VersionSource)
                    && !observation_name_sample_valid(kind, 0x15f00f, 0)
                    && !observation_name_sample_valid(kind, 0x1df00f, 2)
            })
    }
    impl Panel {
        pub fn installed_version_source_name(&mut self, sample: VersionSourceParentReady,
            returned: &mut Option<VersionSourceNamePreparation>) -> io::Result<()> {
            *returned = None;
            self.usable()?;
            if !version_source_parent_matches(&sample, self.original) { return Err(io::ErrorKind::PermissionDenied.into()); }
            let mut facts = 0;
            // SAFETY: the same retained main-thread original and a consumed,
            // opaque returned sample. C rejects a stale generation without a
            // new directory query and retains entry/return/cleanup separately.
            let status = unsafe { mrk_panel_observe_version_source_name(self.original.as_ptr(), sample.sample, &mut facts) };
            let data = version_source_name_preparation(status, facts); *returned = Some(data);
            match result(status) {
                Ok(()) if data.succeeded() => Ok(()),
                Err(error) => { self.unknown = true; Err(error) },
                Ok(()) => { self.unknown = true; Err(io::ErrorKind::InvalidData.into()) },
            }
        }
        pub fn installed_project_field(&mut self, kind: PanelKind, navigate: bool,
            returned: &mut Option<ProjectFieldPreparation>) -> io::Result<bool> {
            *returned = None;
            self.usable()?;
            if !kind.project_field() { return Err(io::ErrorKind::InvalidInput.into()); }
            let mut facts = 0; let mut filter = 0;
            // SAFETY: retained main-thread original, fixed scalar arguments and
            // writable cells; every conversion is owned/retired by that call.
            let status = unsafe { mrk_panel_observe_project_field(self.original.as_ptr(), i32::from(navigate), &mut facts, &mut filter) };
            let data = project_field_preparation(status, facts, filter); *returned = Some(data);
            match result(status) {
                Ok(()) if data.succeeded(kind, navigate) => Ok(true),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock && data.facts == Some(0) => Ok(false),
                Err(error) if matches!(error.kind(), io::ErrorKind::InvalidInput | io::ErrorKind::PermissionDenied) => Err(error),
                Err(error) => { self.unknown = true; Err(error) },
                Ok(()) => { self.unknown = true; Err(io::ErrorKind::InvalidData.into()) },
            }
        }
        pub fn installed_arm_open_identity(&mut self, path: &Path) -> io::Result<()> {
            self.usable()?;
            if self.observation_identity_armed { return Err(io::ErrorKind::Other.into()); }
            let bytes = path.as_os_str().as_bytes();
            if bytes.len() > 4096 { return Err(io::ErrorKind::InvalidInput.into()); }
            let mut target = [0u8; 4097]; target[..bytes.len()].copy_from_slice(bytes);
            if !project_target(&target) { return Err(io::ErrorKind::InvalidInput.into()); }
            // SAFETY: fresh retained original and validated fixed target DATA.
            // The passive arm copies it before start; no AppKit call or action.
            let returned = result(unsafe { mrk_panel_observe_arm_open_identity(self.original.as_ptr(), target.as_ptr(), target.len()) });
            if returned.is_ok() { self.observation_identity_armed = true; } else { self.unknown = true; }
            returned
        }
        pub fn take_installed_identity_start_return(&mut self) -> Option<IdentityStartReturn> {
            self.observation_start.take() // Rust DATA only, including an original failed start.
        }
        pub fn take_installed_completion_return(&mut self) -> Option<CompletionReturn> {
            // Saved Rust DATA even when the returned poll made this Panel unknown.
            // No usable(), native call, new poll, release, or publication retry.
            self.observation_completion.take()
        }
        pub fn installed_open_identity(&mut self, selection: Option<VersionSourceSelectionReady>,
            returned: &mut Option<IdentityBindingReturn>) -> Result<OpenIdentity, OpenDiagnostic> {
            *returned = None;
            self.usable().map_err(|_| OpenDiagnostic { site: "entry", error: "ineligible" })?;
            let selecting = selection.is_some();
            let selection_sample = match selection {
                Some(ticket) if ticket.original == self.original && ticket.sample != 0 => ticket.sample,
                Some(_) => { self.unknown = true; return Err(OpenDiagnostic { site: "entry", error: "custody" }); },
                None => 0,
            };
            let mut identity = OpenIdentity { parent: [0; 64], panel: [0; 64], prompt: [0; 8], target: [0; 4097], selection: selecting };
            // SAFETY: exact retained main-thread original; copied identity DATA.
            let status = unsafe { mrk_panel_observe_open_identity(self.original.as_ptr(), identity.parent.as_mut_ptr(),
                identity.panel.as_mut_ptr(), identity.prompt.as_mut_ptr(), identity.parent.len(), identity.target.as_mut_ptr(), identity.target.len(), selection_sample) };
            let mut wire = IdentityWire::default();
            unsafe { mrk_panel_observe_identity_data(self.original.as_ptr(), &mut wire); }
            *returned = identity_binding_return(status, wire);
            if status == 0 && returned.is_some_and(|r|
                if selecting { r.binding.selection_parent_matched() } else { r.binding.matched() }) && identity.valid() { return Ok(identity); }
            if returned.is_none() || status == 0 || matches!(status, 9 | 14 | 15) || !(1..16).contains(&status) { self.unknown = true; }
            Err(OpenDiagnostic { site: "entry", error: usize::try_from(status).ok().filter(|s| *s != 0)
                .and_then(|s| OPEN_ERRORS.get(s)).copied().unwrap_or("malformed") })
        }
        /// Same original read-only main-thread proof. No input action occurs
        /// here; the enclosing main handler must return its guards before receipt.
        pub fn installed_open_recheck(&mut self, identity: &OpenIdentity, stage: u32) -> Option<OpenRecheckReturn> {
            if self.usable().is_err() || !identity.valid() || stage > 2 || stage == 0 && !identity.selection { return None; }
            let mut wire = RecheckWire::default();
            // SAFETY: exact main-thread original plus bounded copied DATA, no
            // native object or borrowed Panel pointer goes to the AX worker.
            unsafe { mrk_panel_observe_open_recheck(self.original.as_ptr(), identity.parent.as_ptr(), identity.panel.as_ptr(),
                identity.prompt.as_ptr(), identity.target.as_ptr(), identity.target.len(), u32::from(identity.selection), stage, &mut wire); }
            let returned = recheck_return(wire, stage);
            if !returned.is_some_and(|r| r.custody_known) { self.unknown = true; }
            returned
        }
        pub fn installed_observation(&mut self) -> io::Result<PanelObservation> {
            self.usable()?;
            let mut kind = 0; let mut flags = 0; let mut response = 0; let mut path = [0u8; 4097]; let mut name_sample = 0;
            // SAFETY: same retained main-thread original and exact writable
            // DATA cells. A bounded sample number only rejects stale name
            // preparation; it never grants completion or original finality.
            let status = unsafe { mrk_panel_observe(self.original.as_ptr(), &mut kind, &mut flags,
                &mut response, path.as_mut_ptr(), path.len(), &mut name_sample) };
            if let Err(error) = result(status) { self.unknown = true; return Err(error); }
            let parsed = (|| {
                let kind = match kind { 1 => PanelKind::Project, 2 => PanelKind::Quit, 3 => PanelKind::File,
                    4 => PanelKind::VersionSource, 5 => PanelKind::IosProject, 6 => PanelKind::IosWorkspace, 7 => PanelKind::MetadataRoot,
                    8 => PanelKind::EvidenceFolder, 9 => PanelKind::PublicImages,
                    10 => PanelKind::AndroidJdk, 11 => PanelKind::AndroidSdk, 12 => PanelKind::AndroidGradle,
                    _ => return Err(io::Error::from(io::ErrorKind::InvalidData)) };
                let directory_readiness = observation_directory_readiness(kind, flags).ok_or(io::ErrorKind::InvalidData)?;
                if !observation_name_sample_valid(kind, flags, name_sample) { return Err(io::ErrorKind::InvalidData.into()); }
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
                    directory_ready: flags & 16 != 0, directory_readiness,
                    version_source_parent_ready: (flags & 0x80000 != 0).then_some(VersionSourceParentReady { original: self.original, sample: name_sample }),
                    version_source_selection_ready: (flags & 0x100000 != 0).then_some(VersionSourceSelectionReady { original: self.original, sample: name_sample }),
                    action_attempted: flags & 32 != 0,
                    action_returned: flags & 64 != 0, callback_returned: flags & 256 != 0,
                    response, selected, close_attempted: flags & 512 != 0,
                    dismissed: flags & 1024 != 0, closed: flags & 2048 != 0 })
            })();
            if parsed.is_err() { self.unknown = true; } parsed
        }
        /// false means a not-yet-ready sheet/directory/button was observed
        /// BEFORE any action. true means only the actual action call returned;
        /// the real callback and original coordinator still own all outcomes.
        pub fn installed_action(&mut self, action: PanelAction, diagnostic: &mut Option<PanelActionDiagnostic>) -> io::Result<bool> {
            *diagnostic = None; // Never expose a previous action's diagnostic.
            let name = match &action { PanelAction::ProjectCancel => "project-cancel",
                PanelAction::QuitCancel => "quit-cancel", PanelAction::QuitConfirm => "quit-confirm", PanelAction::FileCancel => "file-cancel" };
            if let Err(error) = self.usable() {
                *diagnostic = Some(PanelActionDiagnostic { action: name, domain: "rust-precondition",
                    site: "original-usability", error: "other" });
                return Err(error);
            }
            let code = match action {
                PanelAction::ProjectCancel => 1, PanelAction::QuitCancel => 4, PanelAction::QuitConfirm => 5, PanelAction::FileCancel => 6,
            };
            // SAFETY: same retained main-thread original; no late directory or
            // direct Open route. Diagnostic belongs to THIS original call only.
            let mut wire = 0u32;
            let status = unsafe { mrk_panel_observe_action(self.original.as_ptr(), code, std::ptr::null(), &mut wire) };
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

#[cfg(any(test, feature = "installed-observation"))]
fn public_images_abi_data_check() -> bool {
    // Pure fixed DATA; the only FFI below is the same handle-free response
    // classifier used by completion. No Panel, NSApp, URL or callback exists.
    if PanelKind::PublicImages.code() != 9 || PanelKind::PublicImages.project_field()
        || PUBLIC_IMAGE_CONTROL_BYTES > 128 * 1024
        || project_field_initial(PanelKind::PublicImages, Path::new("/inert/project")).is_ok() { return false; }
    for (code, expected) in [(1, PanelResponse::Accept), (0, PanelResponse::Decline),
        (-1000, PanelResponse::Other), (1000, PanelResponse::Other), (i64::MAX, PanelResponse::Other)] {
        // SAFETY: primitive values only, no native object or action.
        if panel_response(unsafe { mrk_panel_response(9, code, 0) }).ok() != Some(expected)
            || panel_response(unsafe { mrk_panel_response(9, code, 1) }).ok() != Some(PanelResponse::Other) { return false; }
    }
    let mut bytes = [0u8; PUBLIC_IMAGE_RESULT_BYTES];
    for response in [PanelResponse::Decline, PanelResponse::Other] {
        if !matches!(public_image_selection(response, 0, 0, &bytes), Ok(PublicImageSelection::Unselected)) { return false; }
    }
    for (status, reason) in [(2, PublicImageRefusal::Count), (3, PublicImageRefusal::Path)] {
        if !matches!(public_image_selection(PanelResponse::Accept, status, 0, &bytes),
            Ok(PublicImageSelection::Refused(actual)) if actual == reason) { return false; }
    }
    for (response, status, count) in [(PanelResponse::Accept, 0, 0), (PanelResponse::Accept, 4, 0),
        (PanelResponse::Accept, 1, 0), (PanelResponse::Accept, 1, 11),
        (PanelResponse::Accept, 2, 1), (PanelResponse::Decline, 1, 1)] {
        if public_image_selection(response, status, count, &bytes).is_ok() { return false; }
    }
    for count in [1, 2, PUBLIC_IMAGE_COUNT] {
        bytes.fill(0);
        for index in 0..count {
            let path = b"/inert/image.png";
            let start = index * PUBLIC_IMAGE_PATH_BYTES;
            bytes[start..start + path.len()].copy_from_slice(path);
        }
        match public_image_selection(PanelResponse::Accept, 1, count, &bytes) {
            Ok(PublicImageSelection::Paths(paths)) if paths.len() == count && paths.capacity() <= PUBLIC_IMAGE_COUNT
                && paths.iter().all(|path| path == Path::new("/inert/image.png") && path.capacity() <= 4096) => {},
            _ => return false,
        }
        // A bad final member must refuse the complete batch, not publish the
        // previous good members. UTF-8 input refusal does not poison native custody.
        bytes[(count - 1) * PUBLIC_IMAGE_PATH_BYTES + 1] = 0xff;
        if !matches!(public_image_selection(PanelResponse::Accept, 1, count, &bytes),
            Ok(PublicImageSelection::Refused(PublicImageRefusal::Path))) { return false; }
    }
    bytes.fill(0); bytes[..4096].fill(b'a'); bytes[0] = b'/';
    if !matches!(public_image_selection(PanelResponse::Accept, 1, 1, &bytes),
        Ok(PublicImageSelection::Paths(paths)) if paths[0].as_os_str().as_bytes().len() == 4096) { return false; }
    bytes[4096] = b'a'; // no sentinel, not a truncated successful path
    if public_image_selection(PanelResponse::Accept, 1, 1, &bytes).is_ok() { return false; }
    bytes.fill(0); bytes[0] = b'/'; bytes[PUBLIC_IMAGE_PATH_BYTES] = b'x';
    if public_image_selection(PanelResponse::Accept, 1, 1, &bytes).is_ok() { return false; }
    bytes[PUBLIC_IMAGE_PATH_BYTES] = 0; bytes[0] = b'r';
    if public_image_selection(PanelResponse::Accept, 1, 1, &bytes).is_ok() { return false; }
    // Refusal cells cannot smuggle a successful prefix or claim another shape.
    !public_image_selection(PanelResponse::Accept, 3, 0, &bytes).is_ok()
}

#[cfg(any(test, feature = "installed-observation"))]
fn evidence_folder_abi_data_check() -> bool {
    // Shared by libtest and the existing observer DATA entry; no FFI call.
    [(PanelKind::Project, 1), (PanelKind::Quit, 2), (PanelKind::File, 3),
        (PanelKind::VersionSource, 4), (PanelKind::IosProject, 5), (PanelKind::IosWorkspace, 6),
        (PanelKind::MetadataRoot, 7), (PanelKind::EvidenceFolder, 8)]
        .into_iter().all(|(kind, code)| kind.code() == code)
        && !PanelKind::EvidenceFolder.project_field()
        && ["/inert/project", "/", "relative"].into_iter()
            .all(|root| project_field_initial(PanelKind::EvidenceFolder, Path::new(root)).is_err())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compiled_machine_and_translation_data_refuse_foreign_or_unknown_hosts() {
        use nix::errno::Errno;
        #[cfg(target_arch = "aarch64")]
        let (native, opposite) = (c"arm64", c"x86_64");
        #[cfg(target_arch = "x86_64")]
        let (native, opposite) = (c"x86_64", c"arm64");
        let check = |sysname: *const c_char, machine: *const c_char, returned: c_int,
            observed_errno: c_int, length: usize, translated: c_int| {
            // SAFETY: only static terminated strings or null; the private C
            // predicate consumes DATA, with no native queries or acquisitions.
            unsafe { mrk_platform_native_data(sysname, machine, returned, observed_errno, length, translated) }
        };
        let width = std::mem::size_of::<c_int>();
        let missing = Errno::ENOENT as c_int;
        let error = Errno::EIO as c_int;
        let refused = Errno::ENOTSUP as c_int;
        assert_eq!(check(c"Darwin".as_ptr(), native.as_ptr(), 0, 0, width, 0), 0);
        assert_eq!(check(c"Darwin".as_ptr(), native.as_ptr(), 0, error, width, 0), 0);
        // Neither output scalar is a fact after the documented missing key.
        assert_eq!(check(c"Darwin".as_ptr(), native.as_ptr(), -1, missing, usize::MAX, c_int::MIN), 0);
        for translated in [-1, 1, 2] {
            assert_eq!(check(c"Darwin".as_ptr(), native.as_ptr(), 0, missing, width, translated), refused);
        }
        for length in [0, width - 1, width + 1, usize::MAX] {
            assert_eq!(check(c"Darwin".as_ptr(), native.as_ptr(), 0, 0, length, 0), refused);
        }
        for (returned, observed_errno) in [(-1, 0), (-1, error), (1, missing), (-2, missing)] {
            assert_eq!(check(c"Darwin".as_ptr(), native.as_ptr(), returned, observed_errno, width, 0), refused);
        }
        // Native/absent-key paths both require the independent compiled-machine
        // literal and Darwin. Null/empty values cannot authorize either path.
        for (sysname, machine) in [
            (c"Linux".as_ptr(), native.as_ptr()), (c"".as_ptr(), native.as_ptr()),
            (std::ptr::null(), native.as_ptr()), (c"Darwin".as_ptr(), opposite.as_ptr()),
            (c"Darwin".as_ptr(), c"".as_ptr()), (c"Darwin".as_ptr(), std::ptr::null()),
        ] {
            for (returned, observed_errno) in [(0, 0), (-1, missing)] {
                assert_eq!(check(sysname, machine, returned, observed_errno, width, 0), refused);
            }
        }
    }
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
        let link = record(5, 0xf_0000_0003, b"linked.p12");
        assert_eq!(file.len(), 52); // Legal4-byte final short-fit, not mandatory8.
        let mut block = [directory.clone(), file.clone(), link.clone()].concat();
        let mut expected = Vec::new();
        for (inode, kind, name) in [(0x1_0000_0001u64, 4u8, b"dir".as_slice()),
                                    (0x2_0000_0002u64, 8u8, b"file".as_slice()),
                                    (0xf_0000_0003u64, 10u8, b"linked.p12".as_slice())] {
            expected.extend_from_slice(&inode.to_ne_bytes()); expected.push(kind);
            expected.extend_from_slice(&(name.len() as u16).to_ne_bytes()); expected.extend_from_slice(name);
        }
        assert_eq!(decode(&block, 3, 65536), (0, expected.len(), expected.clone()));
        // Exhaustion in the final link record cannot publish the good prefix.
        let (code, used, _) = decode(&block, 3, expected.len() - 1);
        assert_ne!(code, 0); assert_eq!(used, 0);
        block.resize(65536, 0); // Native API returns count, not filled byte length.
        assert_eq!(decode(&block, 3, 65536), (0, expected.len(), expected));
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
            (32, &0u32.to_ne_bytes()), (32, &3u32.to_ne_bytes()), (32, &4u32.to_ne_bytes()),
            (32, &6u32.to_ne_bytes()), (32, &7u32.to_ne_bytes()), (32, &8u32.to_ne_bytes()),
            (32, &u32::MAX.to_ne_bytes()), (36, &0u64.to_ne_bytes()),
            (44, b"/"), (45, b"\0"), (47, b"x"),
        ];
        for &(offset, replacement) in mutations {
            let mut invalid = directory.clone();
            invalid[offset..offset + replacement.len()].copy_from_slice(replacement);
            // One good prefix cannot turn a malformed second record into a
            // partial successful inventory (used must remain zero).
            let batch = [link.clone(), invalid].concat();
            let (code, used, _) = decode(&batch, 2, 65536);
            assert_ne!(code, 0, "offset={offset}"); assert_eq!(used, 0);
        }
    }
    #[test]
    fn evidence_folder_is_a_distinct_non_project_field_abi_purpose() {
        assert!(evidence_folder_abi_data_check());
    }
    #[test]
    fn public_image_result_is_bounded_complete_and_distinct_from_cancel() {
        assert!(public_images_abi_data_check());
    }
    #[test]
    fn only_explicit_user_appkit_responses_can_be_accept_or_decline() {
        // Calls the SAME pure C classifier used by the real completion. These
        // definitions construct no NSWindow, fake callback or native permit.
        for (kind, code, expected) in [
            (1, 1, PanelResponse::Accept), (1, 0, PanelResponse::Decline),
            (3, 1, PanelResponse::Accept), (3, 0, PanelResponse::Decline),
            (4, 1, PanelResponse::Accept), (4, 0, PanelResponse::Decline),
            (5, 1, PanelResponse::Accept), (5, 0, PanelResponse::Decline),
            (6, 1, PanelResponse::Accept), (6, 0, PanelResponse::Decline),
            (7, 1, PanelResponse::Accept), (7, 0, PanelResponse::Decline),
            (8, 1, PanelResponse::Accept), (8, 0, PanelResponse::Decline),
            (8, -1000, PanelResponse::Other), (8, -1001, PanelResponse::Other),
            (8, 1000, PanelResponse::Other), (8, 1001, PanelResponse::Other),
            (8, i64::MIN, PanelResponse::Other), (i32::MAX, 1, PanelResponse::Other),
            (9, 1, PanelResponse::Accept), (9, 0, PanelResponse::Decline),
            (4, -1000, PanelResponse::Other), (7, 1001, PanelResponse::Other),
            (3, -1000, PanelResponse::Other), (3, 1001, PanelResponse::Other),
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
            assert_eq!(panel_response(actual).ok(), Some(expected), "kind={kind} code={code}");
            let programmatic = unsafe { mrk_panel_response(kind, code, 1) };
            assert_eq!(panel_response(programmatic).ok(), Some(PanelResponse::Other), "programmatic kind={kind} code={code}");
        }
        // Android purposes are actual open panels, not unknown-kind sentinels.
        // Use the public purpose mapping while testing the same native classifier.
        for purpose in [PanelKind::AndroidJdk, PanelKind::AndroidSdk, PanelKind::AndroidGradle] {
            let kind = purpose.code();
            for (code, expected) in [(1, PanelResponse::Accept), (0, PanelResponse::Decline),
                (-1000, PanelResponse::Other), (-1001, PanelResponse::Other),
                (1000, PanelResponse::Other), (1001, PanelResponse::Other),
                (i64::MIN, PanelResponse::Other), (i64::MAX, PanelResponse::Other)] {
                // SAFETY: fixed scalar DATA, no AppKit object or native permit.
                let actual = unsafe { mrk_panel_response(kind, code, 0) };
                assert_eq!(panel_response(actual).ok(), Some(expected), "kind={kind} code={code}");
                let programmatic = unsafe { mrk_panel_response(kind, code, 1) };
                assert_eq!(panel_response(programmatic).ok(), Some(PanelResponse::Other), "programmatic kind={kind} code={code}");
            }
        }
        assert!(panel_response(-1).is_err());
        assert!(panel_response(3).is_err());
    }
}
