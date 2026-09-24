//! Narrow Windows shell boundary: ordinary interactive admission, one fresh
//! WebView2 data scope, the original document watch, and Project/Quit dialogs.
//!
//! This is not a runtime selector/executor or a general filesystem/COM service.
//! Callers register each inert book before entry and retain it on its original
//! STA until explicit settlement. Drop never claims cleanup of an original.
use super::*;
use std::{cell::OnceCell, collections::BTreeSet, mem::size_of_val, path::{Path, PathBuf}, rc::Rc};
use windows::{core::{Interface, PCWSTR, PWSTR}, Win32::{Foundation::HWND,
    System::Com::{CoGetApartmentType, APTTYPE, APTTYPEQUALIFIER, APTTYPE_MAINSTA, APTTYPE_STA}}};
use windows_sys::Win32::{System::{Registry as R, StationsAndDesktops as D}, UI::WindowsAndMessaging as W};
use webview2_com::Microsoft::Web::WebView2::Win32 as WV;

#[path = "ui_profile.rs"]
mod profile;
#[cfg(feature = "desktop-ui-dialogs")]
#[path = "ui_dialog.rs"]
mod dialog;
#[cfg(feature = "desktop-ui-dialogs")]
pub use dialog::{Dialog, DialogControl, DialogEvent, DialogResult, DialogResponse};
#[cfg(feature = "windows-installed-observation")]
pub use dialog::{DialogAction, DialogObservation};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialogKind { Project, Quit }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiError {
    OrdinaryContext, InteractiveDesktop, ManagedRuntimeUnavailable,
    RuntimeOverrides, UserDataParent, NativeFailure, CleanupUnknown, State,
}
impl UiError {
    pub fn label(self) -> &'static str { match self {
        Self::OrdinaryContext => "ordinary-context", Self::InteractiveDesktop => "interactive-desktop",
        Self::ManagedRuntimeUnavailable => "managed-webview2", Self::RuntimeOverrides => "webview2-overrides",
        Self::UserDataParent => "private-user-data-parent", Self::NativeFailure => "native-failure",
        Self::CleanupUnknown => "cleanup-unknown", Self::State => "original-state",
    } }
}
impl std::fmt::Display for UiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.label()) }
}
impl std::error::Error for UiError {}
type UiResult<T> = std::result::Result<T, UiError>;
fn mapped<T>(value: Result<T>, refusal: UiError) -> UiResult<T> {
    value.map_err(|error| if error == Error::Unknown { UiError::CleanupUnknown } else { refusal })
}
fn hresult<T>(value: windows::core::Result<T>) -> UiResult<T> {
    value.map_err(|error| if error.code().0 == HRESULT_PENDING { UiError::CleanupUnknown } else { UiError::NativeFailure })
}
fn cleanup_checkpoint(end: std::time::Instant) -> UiResult<()> {
    if std::time::Instant::now() < end { Ok(()) } else { Err(UiError::CleanupUnknown) }
}
fn exact_text(units: &[u16]) -> UiResult<String> {
    let end = units.iter().position(|unit| *unit == 0).ok_or(UiError::NativeFailure)?;
    if end == 0 { return Err(UiError::NativeFailure); }
    String::from_utf16(&units[..end]).map_err(|_| UiError::NativeFailure)
}
fn sta() -> UiResult<()> {
    let mut kind = APTTYPE::default(); let mut qualifier = APTTYPEQUALIFIER::default();
    // No COM initialization/reinitialization and no apartment transfer.
    hresult(unsafe { CoGetApartmentType(&mut kind, &mut qualifier) })?;
    if kind == APTTYPE_STA || kind == APTTYPE_MAINSTA { Ok(()) } else { Err(UiError::OrdinaryContext) }
}

/// Finite public DATA only. Actual token/SID/station/path/handles stay private.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrerequisiteFacts {
    pub ordinary_context: bool,
    pub interactive_desktop: bool,
    pub managed_runtime: bool,
    pub override_free: bool,
    pub private_parent: bool,
    pub runtime_version: String,
}
struct PathOriginal { original: Original, metadata: Metadata, runtime_scope: Option<AuthorityScope> }
fn managed_runtime_scope(depth: usize, root_depth: usize) -> AuthorityScope {
    if depth >= root_depth { AuthorityScope::ImmutableVersion } else { AuthorityScope::AncestorOutsideVersion }
}
struct NativeTextState { value: PWSTR, entered: bool, returned: bool, released: bool, unknown: bool }
struct NativeText { original: Held<NativeTextState> }
impl std::ops::Deref for NativeText {
    type Target = NativeTextState;
    fn deref(&self) -> &Self::Target { self.original.as_ref().get_ref() }
}
impl std::ops::DerefMut for NativeText {
    fn deref_mut(&mut self) -> &mut Self::Target { unsafe { self.original.as_mut().get_unchecked_mut() } }
}
impl NativeText {
    fn new() -> Self { Self { original: ManuallyDrop::new(Box::pin(NativeTextState {
        value: PWSTR::null(), entered: false, returned: false, released: false, unknown: false })) } }
    fn complete(&mut self, result: windows::core::Result<()>) -> UiResult<()> {
        if !self.entered || self.returned || self.unknown
            || result.as_ref().is_err_and(|error| error.code().0 == HRESULT_PENDING) {
            self.unknown = true; return Err(UiError::CleanupUnknown);
        }
        self.returned = true;
        if result.is_err() && !self.value.is_null() { self.unknown = true; return Err(UiError::CleanupUnknown); }
        hresult(result)
    }
    fn read(&self, limit: usize) -> UiResult<String> {
        if self.unknown { return Err(UiError::CleanupUnknown); }
        if !self.entered || !self.returned || self.released || self.value.is_null() { return Err(UiError::NativeFailure); }
        let mut units = Vec::with_capacity(limit.min(512));
        // A successful documented getter owns a NUL-terminated CoTaskMem UTF16
        // allocation. Bound copying; never lstrlenW/lossy path conversion.
        for index in 0..limit {
            let unit = unsafe { *self.value.0.add(index) };
            if unit == 0 { return if units.is_empty() { Err(UiError::NativeFailure) }
                else { String::from_utf16(&units).map_err(|_| UiError::NativeFailure) }; }
            units.push(unit);
        }
        Err(UiError::NativeFailure)
    }
    fn release(&mut self) -> UiResult<()> {
        if self.released { return Ok(()); }
        if self.unknown || self.entered && !self.returned { return Err(UiError::CleanupUnknown); }
        if !self.value.is_null() {
            unsafe { windows::Win32::System::Com::CoTaskMemFree(Some(self.value.0.cast())); }
            self.value = PWSTR::null();
        }
        self.released = true; Ok(())
    }
}
impl Drop for NativeText {
    fn drop(&mut self) {
        // A pending getter retains its ORIGINAL output destination as well as
        // any allocation it may yet write. No implicit CoTaskMemFree.
        if self.released { unsafe { ManuallyDrop::drop(&mut self.original); } }
    }
}

// Event-token outputs, including their still-entered destinations, belong to
// the original watch before each COM registration. No stack token on failure.
struct HookState { value: i64, entered: bool, returned: bool, registered: bool, remove_entered: bool, removed: bool, unknown: bool }
struct HookToken { original: Held<HookState> }
impl std::ops::Deref for HookToken {
    type Target = HookState;
    fn deref(&self) -> &Self::Target { self.original.as_ref().get_ref() }
}
impl std::ops::DerefMut for HookToken {
    fn deref_mut(&mut self) -> &mut Self::Target { unsafe { self.original.as_mut().get_unchecked_mut() } }
}
impl HookToken {
    fn new() -> Self { Self { original: ManuallyDrop::new(Box::pin(HookState {
        value: 0, entered: false, returned: false, registered: false, remove_entered: false, removed: false, unknown: false })) } }
    fn complete(&mut self, result: windows::core::Result<()>) -> UiResult<()> {
        if !self.entered || self.returned || self.unknown
            || result.as_ref().is_err_and(|error| error.code().0 == HRESULT_PENDING) {
            self.unknown = true; return Err(UiError::CleanupUnknown);
        }
        self.returned = true;
        if result.is_err() && self.value != 0 { self.unknown = true; return Err(UiError::CleanupUnknown); }
        hresult(result)?; self.registered = true; Ok(())
    }
    fn token(&self) -> UiResult<Option<i64>> {
        if self.unknown || self.entered && !self.returned { return Err(UiError::CleanupUnknown); }
        Ok((self.registered && !self.removed).then_some(self.value))
    }
    fn settled(&self) -> bool { !self.unknown && (!self.entered || self.returned && (!self.registered || self.removed)) }
}
impl Drop for HookToken {
    fn drop(&mut self) { if self.settled() { unsafe { ManuallyDrop::drop(&mut self.original); } } }
}

/// Mutating, caller-retained admission. Failure cannot discard partial originals.
/// The standalone prerequisite probe uses this same inspector but never creates
/// a user-data directory or a WebView. Its receipt is not a transferable permit.
pub struct Prerequisites {
    native: NativeBook,
    paths: Vec<PathOriginal>,
    input_desktop: D::HDESK,
    station: D::HWINSTA, // borrowed, NEVER CloseWindowStation
    desktop: D::HDESK, // borrowed, NEVER CloseDesktop
    thread: u32,
    session: u32,
    logon: Option<Sid>,
    runtime_text: NativeText,
    overrides: RegistryAudit,
    program_files: String,
    local_data: String,
    parent: Option<usize>,
    image: Option<usize>,
    image_dos: String,
    facts: Option<PrerequisiteFacts>,
    begun: bool,
    final_attempted: bool,
    unknown: bool,
}
impl Default for Prerequisites { fn default() -> Self { Self::new() } }
impl Prerequisites {
    pub fn new() -> Self {
        Self { native: NativeBook::new(), paths: Vec::new(), input_desktop: null_mut(),
            station: null_mut(), desktop: null_mut(), thread: 0, session: 0, logon: None,
            runtime_text: NativeText::new(), overrides: RegistryAudit::new(), program_files: String::new(), local_data: String::new(),
            parent: None, image: None, image_dos: String::new(), facts: None,
            begun: false, final_attempted: false, unknown: false }
    }
    pub fn facts(&self) -> Option<&PrerequisiteFacts> { self.facts.as_ref() }
    #[cfg(test)]
    pub(crate) fn observed_user_sid(&self) -> Option<&[u8]> {
        self.native.user.as_ref().map(|facts| facts.user.bytes())
    }
    pub fn inspect(&mut self) -> UiResult<PrerequisiteFacts> {
        if self.begun || self.final_attempted || self.unknown { return Err(UiError::State); }
        self.begun = true;
        let result = self.inspect_inner();
        if result == Err(UiError::CleanupUnknown) { self.unknown = true; }
        result
    }
    fn inspect_inner(&mut self) -> UiResult<PrerequisiteFacts> {
        let token = mapped(self.native.observe_user_once(), UiError::OrdinaryContext)?.clone();
        let logons: Vec<_> = token.groups.iter().filter(|group|
            group.attributes & windows_sys::Win32::System::SystemServices::SE_GROUP_LOGON_ID as u32
                == windows_sys::Win32::System::SystemServices::SE_GROUP_LOGON_ID as u32).collect();
        if logons.len() != 1 || logons[0].attributes & windows_sys::Win32::System::SystemServices::SE_GROUP_ENABLED as u32 == 0 {
            return Err(UiError::OrdinaryContext);
        }
        self.logon = Some(logons[0].sid.clone());
        self.thread = unsafe { T::GetCurrentThreadId() };
        self.station = unsafe { D::GetProcessWindowStation() };
        self.desktop = unsafe { D::GetThreadDesktop(self.thread) };
        if self.station.is_null() || self.desktop.is_null()
            || unsafe { T::ProcessIdToSessionId(T::GetCurrentProcessId(), &mut self.session) } == 0
            || self.session == 0 { return Err(UiError::InteractiveDesktop); }
        // These are the intended account's actual originals, not the CI runner's
        // station. Do not change a DACL, switch a desktop, or assume lpDesktop.
        self.input_desktop = unsafe { D::OpenInputDesktop(0, 0,
            D::DESKTOP_READOBJECTS | D::DESKTOP_CREATEWINDOW | D::DESKTOP_WRITEOBJECTS) };
        if self.input_desktop.is_null() { return Err(UiError::InteractiveDesktop); }
        self.session_check()?;
        overrides_absent(&mut self.overrides)?;
        self.runtime_text.entered = true;
        let result = unsafe { WV::GetAvailableCoreWebView2BrowserVersionString(PCWSTR::null(), &mut self.runtime_text.value) };
        self.runtime_text.complete(result).map_err(|error|
            if error == UiError::CleanupUnknown { error } else { UiError::ManagedRuntimeUnavailable })?;
        let version = self.runtime_text.read(96).map_err(|_| UiError::ManagedRuntimeUnavailable)?;
        if !stable_version(&version) { return Err(UiError::ManagedRuntimeUnavailable); }
        self.program_files = known_folder(SH::CSIDL_PROGRAM_FILESX86 as i32)?;
        self.local_data = known_folder(SH::CSIDL_LOCAL_APPDATA as i32).map_err(|_| UiError::UserDataParent)?;
        self.image_dos = format!("{}\\Microsoft\\EdgeWebView\\Application\\{}\\msedgewebview2.exe", self.program_files, version);
        let image_path = self.image_dos.clone();
        self.image = Some(self.path(&image_path, FileKind::File, true)?);
        let local_data = self.local_data.clone();
        self.parent = Some(self.path(&local_data, FileKind::Directory, false)?);
        self.recheck_inner()?;
        let facts = PrerequisiteFacts { ordinary_context: true, interactive_desktop: true,
            managed_runtime: true, override_free: true, private_parent: true, runtime_version: version };
        self.facts = Some(facts.clone()); Ok(facts)
    }
    fn session_check(&self) -> UiResult<()> {
        if unsafe { T::GetCurrentThreadId() } != self.thread
            || unsafe { D::GetProcessWindowStation() } != self.station
            || unsafe { D::GetThreadDesktop(self.thread) } != self.desktop {
            return Err(UiError::InteractiveDesktop);
        }
        let mut session = 0;
        if unsafe { T::ProcessIdToSessionId(T::GetCurrentProcessId(), &mut session) } == 0 || session != self.session {
            return Err(UiError::InteractiveDesktop);
        }
        let flags: D::USEROBJECTFLAGS = user_object(self.station, D::UOI_FLAGS)?;
        let current: i32 = user_object(self.desktop, D::UOI_IO)?;
        let input: i32 = user_object(self.input_desktop, D::UOI_IO)?;
        if flags.fInherit != 0 || flags.fReserved != 0 || flags.dwFlags & W::WSF_VISIBLE as u32 == 0
            || current != 1 || input != 1 || object_name(self.station)? != "WinSta0"
            || object_name(self.desktop)? != "Default" || object_name(self.input_desktop)? != "Default" {
            return Err(UiError::InteractiveDesktop);
        }
        Ok(())
    }
    fn path(&mut self, path: &str, kind: FileKind, protected: bool) -> UiResult<usize> {
        let refusal = if protected { UiError::ManagedRuntimeUnavailable } else { UiError::UserDataParent };
        let (drive, components) = mapped(decode::dos_location(path), refusal)?;
        if components.len() > 20 { return Err(refusal); }
        let runtime_depth = if protected {
            let root = format!("{}\\Microsoft\\EdgeWebView", self.program_files);
            let (root_drive, root_components) = mapped(decode::dos_location(&root), refusal)?;
            // Exact decoded ancestry, never a string-prefix/suffix alias.
            if drive != root_drive || components.len() <= root_components.len()
                || !components.starts_with(&root_components) { return Err(refusal); }
            Some(root_components.len())
        } else { None };
        let device = mapped(self.native.mapping(&drive), refusal)?;
        let root_name = format!("{device}\\");
        let mut index = if let Some(index) = self.paths.iter().position(|entry|
            self.native.slot(entry.original.index).is_ok_and(|slot| slot.canonical == root_name)) { index } else {
            let original = mapped(self.native.reserve(Kind::Directory, None, &root_name, root_name.clone()), refusal)?;
            // The book registers the root's result destination before native entry.
            mapped(self.native.call(Call::Open(original.index), null_mut(), Vec::new()), refusal)?;
            let metadata = mapped(self.native.metadata(&original), refusal)?;
            self.paths.push(PathOriginal { original, metadata, runtime_scope: None }); self.paths.len() - 1
        };
        self.admit_path(index, runtime_depth.map(|root| managed_runtime_scope(0, root)))?;
        for (position, name) in components.iter().enumerate() {
            let parent = index; let parent_slot = self.paths[parent].original.index;
            let child_kind = if position + 1 == components.len() { kind } else { FileKind::Directory };
            index = if let Some(index) = self.paths.iter().position(|entry| self.native.slot(entry.original.index)
                .is_ok_and(|slot| slot.parent == Some(parent_slot) && slot.name == wide(name))) { index } else {
                let original = mapped(self.native.open_child(&self.paths[parent].original, name, child_kind), refusal)?;
                let metadata = mapped(self.native.metadata(&original), refusal)?;
                if self.paths.iter().any(|entry| entry.metadata.identity == metadata.identity) { return Err(refusal); }
                self.paths.push(PathOriginal { original, metadata, runtime_scope: None }); self.paths.len() - 1
            };
            self.admit_path(index, runtime_depth.map(|root| managed_runtime_scope(position + 1, root)))?;
        }
        if mapped(self.native.mapping(&drive), refusal)? != device { return Err(refusal); }
        Ok(index)
    }
    fn admit_path(&mut self, index: usize, scope: Option<AuthorityScope>) -> UiResult<()> {
        let entry = self.paths.get_mut(index).ok_or(UiError::State)?;
        let refusal = if scope.is_some() { UiError::ManagedRuntimeUnavailable } else { UiError::UserDataParent };
        mapped(self.native.local_ntfs(&entry.original), refusal)?;
        mapped(self.native.no_alternate_streams(&entry.original), refusal)?;
        if let Some(scope) = scope {
            // Internal runtime directories must reject untrusted child creation,
            // not only writes to the final executable. Cached originals retain
            // their strongest admitted scope through all later rechecks.
            let scope = if entry.runtime_scope == Some(AuthorityScope::ImmutableVersion) {
                AuthorityScope::ImmutableVersion } else { scope };
            mapped(self.native.security(&entry.original, scope), UiError::ManagedRuntimeUnavailable)?;
            entry.runtime_scope = Some(scope);
        } else {
            let user = self.native.user.as_ref().ok_or(UiError::State)?.user.clone();
            let result = mapped(self.native.original_call(entry.original.index, Call::Security), UiError::UserDataParent)?;
            let count = mapped(result.count(), UiError::UserDataParent)?;
            private_parent_descriptor(mapped(result.bytes(count), UiError::UserDataParent)?, &user)?;
        }
        Ok(())
    }
    fn recheck_inner(&mut self) -> UiResult<()> {
        mapped(self.native.recheck_user(), UiError::OrdinaryContext)?;
        self.session_check()?; overrides_absent(&mut self.overrides)?;
        if known_folder(SH::CSIDL_PROGRAM_FILESX86 as i32)? != self.program_files
            || known_folder(SH::CSIDL_LOCAL_APPDATA as i32)? != self.local_data { return Err(UiError::UserDataParent); }
        for entry in &self.paths {
            let refusal = if entry.runtime_scope.is_some() { UiError::ManagedRuntimeUnavailable } else { UiError::UserDataParent };
            let metadata = mapped(self.native.metadata(&entry.original), refusal)?;
            // Directory timestamps may change for unrelated siblings. Original
            // full identity/kind/attributes/canonical-name cannot change.
            if metadata.identity != entry.metadata.identity || metadata.kind != entry.metadata.kind
                || metadata.attributes != entry.metadata.attributes || metadata.creation != entry.metadata.creation
                || metadata.kind == FileKind::File && metadata != entry.metadata { return Err(refusal); }
            if let Some(scope) = entry.runtime_scope {
                mapped(self.native.security(&entry.original, scope), UiError::ManagedRuntimeUnavailable)?;
            }
        }
        Ok(())
    }
    pub fn recheck(&mut self) -> UiResult<()> {
        if self.facts.is_none() || self.final_attempted || self.unknown { return Err(UiError::State); }
        let result = self.recheck_inner();
        if result == Err(UiError::CleanupUnknown) { self.unknown = true; }
        result
    }
    pub fn settle_once(&mut self) -> CloseOutcome {
        if self.final_attempted { return if self.settled() { CloseOutcome::Settled } else { CloseOutcome::Unknown }; }
        self.final_attempted = true;
        if !self.overrides.settled() { self.unknown = true; }
        if self.runtime_text.release().is_err() { self.unknown = true; }
        if !self.input_desktop.is_null() {
            if unsafe { D::CloseDesktop(self.input_desktop) } == 0 { self.unknown = true; }
            else { self.input_desktop = null_mut(); }
        }
        if self.native.settle_once() != CloseOutcome::Settled { self.unknown = true; }
        if self.settled() { CloseOutcome::Settled } else { CloseOutcome::Unknown }
    }
    pub fn settled(&self) -> bool {
        self.final_attempted && !self.unknown && self.input_desktop.is_null()
            && self.runtime_text.released && self.overrides.settled() && self.native.settled()
    }
}

fn stable_version(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 4 && parts.iter().all(|part| !part.is_empty() && part.len() <= 5
        && (part.len() == 1 || !part.starts_with('0')) && part.bytes().all(|byte| byte.is_ascii_digit())
        && part.parse::<u16>().is_ok()) && parts[0].parse::<u16>().is_ok_and(|major| major >= 120)
}
fn known_folder(folder: i32) -> UiResult<String> {
    let mut path = [0u16; F::MAX_PATH as usize];
    if unsafe { SH::SHGetFolderPathW(null_mut(), folder, null_mut(), SH::SHGFP_TYPE_CURRENT as u32, path.as_mut_ptr()) } != 0 {
        return Err(UiError::UserDataParent);
    }
    let path = exact_text(&path)?; mapped(decode::dos_location(&path), UiError::UserDataParent)?; Ok(path)
}
fn user_object<T: Copy + Default>(handle: F::HANDLE, class: i32) -> UiResult<T> {
    let mut value = T::default(); let mut length = 0;
    if unsafe { D::GetUserObjectInformationW(handle, class, (&mut value as *mut T).cast(), size_of::<T>() as u32, &mut length) } == 0
        || length as usize != size_of::<T>() { return Err(UiError::InteractiveDesktop); }
    Ok(value)
}
fn object_name(handle: F::HANDLE) -> UiResult<String> {
    let mut value = [0u16; 128]; let mut length = 0;
    if unsafe { D::GetUserObjectInformationW(handle, D::UOI_NAME, value.as_mut_ptr().cast(), size_of_val(&value) as u32, &mut length) } == 0
        || length < 2 || length as usize > size_of_val(&value) || length % 2 != 0 { return Err(UiError::InteractiveDesktop); }
    exact_text(&value[..length as usize / 2]).map_err(|_| UiError::InteractiveDesktop)
}

// The default/null-folder loader has documented environment and policy lookup
// surfaces. Refuse the complete WebView2 namespaces rather than guessing app-ID
// precedence or accepting unknown per-app values. An ordinary per-user EdgeUpdate
// registration is also unsupported; this slice admits system Evergreen only.
const OVERRIDE_KEYS: &[(&str, bool)] = &[
    ("SOFTWARE\\Policies\\Microsoft\\Edge\\WebView2", false),
    ("SOFTWARE\\Microsoft\\Edge\\WebView2", false),
    ("SOFTWARE\\Microsoft\\EdgeUpdate", true),
    ("SOFTWARE\\Microsoft\\EdgeWebView", true),
];
struct RegistryOriginal {
    name: Vec<u16>, value: UnsafeCell<R::HKEY>, entered: bool, returned: bool, close_entered: bool, settled: bool,
}
struct RegistryAudit { originals: Vec<Held<RegistryOriginal>>, unknown: bool }
impl RegistryAudit {
    fn new() -> Self { Self { originals: Vec::new(), unknown: false } }
    fn absent(&mut self, root: R::HKEY, name: &[u16], view: u32) -> UiResult<()> {
        if self.unknown || self.originals.len() >= 96 { return Err(UiError::CleanupUnknown); }
        self.originals.push(ManuallyDrop::new(Box::pin(RegistryOriginal {
            name: name.to_vec(), value: UnsafeCell::new(null_mut()), entered: false, returned: false, close_entered: false, settled: false })));
        let original = self.originals.last_mut().ok_or(UiError::State)?;
        let original = unsafe { original.as_mut().get_unchecked_mut() };
        original.entered = true;
        let result = unsafe { R::RegOpenKeyExW(root, original.name.as_ptr(), 0, R::KEY_QUERY_VALUE | view, original.value.get()) };
        if result == F::ERROR_IO_PENDING { self.unknown = true; return Err(UiError::CleanupUnknown); }
        original.returned = true;
        let handle = unsafe { *original.value.get() };
        if result == F::ERROR_FILE_NOT_FOUND || result == F::ERROR_PATH_NOT_FOUND {
            if !handle.is_null() { self.unknown = true; return Err(UiError::CleanupUnknown); }
            original.settled = true; return Ok(());
        }
        if result == F::ERROR_SUCCESS && !handle.is_null() {
            original.close_entered = true;
            if unsafe { R::RegCloseKey(handle) } != F::ERROR_SUCCESS { self.unknown = true; return Err(UiError::CleanupUnknown); }
            original.settled = true; return Err(UiError::RuntimeOverrides);
        }
        if !handle.is_null() { self.unknown = true; return Err(UiError::CleanupUnknown); }
        original.settled = true; Err(UiError::RuntimeOverrides)
    }
    fn settled(&self) -> bool { !self.unknown && self.originals.iter().all(|original| original.settled) }
}
impl Drop for RegistryAudit {
    fn drop(&mut self) {
        for original in &mut self.originals {
            if original.settled { unsafe { ManuallyDrop::drop(original); } }
        }
    }
}
fn overrides_absent(audit: &mut RegistryAudit) -> UiResult<()> {
    use std::os::windows::ffi::OsStrExt;
    for (name, _) in std::env::vars_os() {
        let units: Vec<u16> = name.encode_wide().collect();
        let prefix: Vec<u16> = "WEBVIEW2_".encode_utf16().collect();
        if units.len() >= prefix.len() && units[..prefix.len()].iter().zip(&prefix)
            .all(|(left, right)| *left == *right || *left >= b'a' as u16 && *left <= b'z' as u16 && *left - 32 == *right) {
            return Err(UiError::RuntimeOverrides);
        }
    }
    for (key, user_only) in OVERRIDE_KEYS {
        for root in [R::HKEY_CURRENT_USER, R::HKEY_LOCAL_MACHINE] {
            if *user_only && root != R::HKEY_CURRENT_USER { continue; }
            for view in [R::KEY_WOW64_32KEY, R::KEY_WOW64_64KEY] {
                audit.absent(root, &wide(key), view)?;
            }
        }
    }
    Ok(())
}

// Mutable-user-parent policy is intentionally separate from runtime authority.
// Unknown ACE types/flags/rights refuse; only this user and protected system
// trustees may mutate the selected ancestry. Everyone may retain ordinary read
// rights. The newly created leaf gets an exact protected user+SYSTEM DACL.
fn private_parent_descriptor(raw: &[u8], user: &Sid) -> UiResult<SecurityFacts> {
    let parse = || -> Result<SecurityFacts> {
        let header = size_of::<S::SECURITY_DESCRIPTOR_RELATIVE>();
        if raw.len() < header || raw.len() > BUFFER || raw[0] != 1 || raw[1] != 0 { return Err(Error::Unsafe); }
        let control = decode::u16_at(raw, 2)?;
        let known = S::SE_OWNER_DEFAULTED | S::SE_GROUP_DEFAULTED | S::SE_DACL_PRESENT | S::SE_DACL_DEFAULTED
            | S::SE_SACL_PRESENT | S::SE_SACL_DEFAULTED | S::SE_DACL_AUTO_INHERIT_REQ | S::SE_SACL_AUTO_INHERIT_REQ
            | S::SE_DACL_AUTO_INHERITED | S::SE_SACL_AUTO_INHERITED | S::SE_DACL_PROTECTED | S::SE_SACL_PROTECTED | S::SE_SELF_RELATIVE;
        if control & !known != 0 || control & (S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT) != (S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT)
            || decode::u32_at(raw, 12)? != 0 { return Err(Error::Unsafe); }
        let owner_offset = decode::u32_at(raw, 4)? as usize;
        let acl_offset = decode::u32_at(raw, 16)? as usize;
        if owner_offset < header || owner_offset % 4 != 0 || acl_offset < header || acl_offset % 4 != 0 { return Err(Error::Unsafe); }
        let owner = security::sid_at(raw, owner_offset, raw.len())?;
        if owner != *user && !system_trustee(&owner) { return Err(Error::Unsafe); }
        let acl = decode::span(raw, acl_offset, size_of::<S::ACL>())?;
        if !matches!(acl[0], 2 | 4) || acl[1] != 0 || decode::u16_at(acl, 6)? != 0 { return Err(Error::Unsafe); }
        let length = decode::u16_at(acl, 2)? as usize;
        let count = decode::u16_at(acl, 4)? as usize;
        if length < 8 || length % 4 != 0 || count > 128 { return Err(Error::Unsafe); }
        let acl = decode::span(raw, acl_offset, length)?; let mut offset = 8;
        let overlaps = |a: (usize, usize), b: (usize, usize)| a.0 < b.1 && b.0 < a.1;
        let acl_range = (acl_offset, acl_offset + length);
        let owner_range = (owner_offset, owner_offset + owner.bytes().len());
        if overlaps(owner_range, acl_range) { return Err(Error::Unsafe); }
        let group_offset = decode::u32_at(raw, 8)? as usize;
        if group_offset != 0 {
            if group_offset < header || group_offset % 4 != 0 { return Err(Error::Unsafe); }
            let group = security::sid_at(raw, group_offset, raw.len())?;
            let range = (group_offset, group_offset + group.bytes().len());
            if overlaps(range, acl_range) || range != owner_range && overlaps(range, owner_range) { return Err(Error::Unsafe); }
        }
        let mut aces = Vec::with_capacity(count);
        let mutation = FS::FILE_WRITE_EA | FS::FILE_WRITE_ATTRIBUTES
            | FS::DELETE | FS::FILE_DELETE_CHILD | FS::WRITE_DAC | FS::WRITE_OWNER
            | F::GENERIC_ALL | F::GENERIC_WRITE;
        for _ in 0..count {
            let head = decode::span(acl, offset, 8)?;
            let extent = decode::u16_at(head, 2)? as usize;
            if extent < 16 || extent % 4 != 0 || !matches!(head[0], 0 | 1)
                || head[1] as u32 & !(S::OBJECT_INHERIT_ACE | S::CONTAINER_INHERIT_ACE | S::NO_PROPAGATE_INHERIT_ACE | S::INHERIT_ONLY_ACE | S::INHERITED_ACE) != 0 {
                return Err(Error::Unsafe);
            }
            let ace = decode::span(acl, offset, extent)?;
            let sid = security::sid_at(ace, 8, extent)?;
            if 8 + sid.bytes().len() != extent { return Err(Error::Unsafe); }
            let flags = head[1] as u32;
            if flags & (S::NO_PROPAGATE_INHERIT_ACE | S::INHERIT_ONLY_ACE) != 0
                && flags & (S::OBJECT_INHERIT_ACE | S::CONTAINER_INHERIT_ACE) == 0 { return Err(Error::Unsafe); }
            let rights = decode::u32_at(ace, 4)?;
            if rights & !(FS::FILE_ALL_ACCESS | F::GENERIC_READ | F::GENERIC_WRITE | F::GENERIC_EXECUTE | F::GENERIC_ALL) != 0
                || head[0] == 0 && flags & S::INHERIT_ONLY_ACE == 0
                && sid != *user && !system_trustee(&sid) && rights & mutation != 0 { return Err(Error::Unsafe); }
            aces.push(AceFact { allow: head[0] == 0, flags: head[1], mask: rights, sid });
            offset += extent;
        }
        if acl[offset..].iter().any(|byte| *byte != 0) { return Err(Error::Unsafe); }
        Ok(SecurityFacts { owner, control, revision: acl[0], aces })
    };
    mapped(parse(), UiError::UserDataParent)
}
fn system_trustee(sid: &Sid) -> bool {
    // Exact S-1-5-18, BUILTIN Administrators, TrustedInstaller.
    let b = sid.bytes();
    b == [1,1,0,0,0,0,0,5,18,0,0,0]
        || b == [1,2,0,0,0,0,0,5,32,0,0,0,32,2,0,0]
        || b.len() == 32 && b[..8] == [1,6,0,0,0,0,0,5]
            && [80,956008885,3418522649,1831038044,1853292631,2271478464].iter().enumerate()
                .all(|(index, sub)| decode::u32_at(b, 8 + index * 4) == Ok(*sub))
}

struct ComOriginal<T> { value: UnsafeCell<ManuallyDrop<T>>, released: Cell<bool> }
impl<T> ComOriginal<T> {
    fn new(value: T) -> Self { Self { value: UnsafeCell::new(ManuallyDrop::new(value)), released: Cell::new(false) } }
    fn get(&self) -> UiResult<&T> {
        if self.released.get() { Err(UiError::State) } else { Ok(unsafe { &*self.value.get() }) }
    }
    fn release(&self) {
        // Private STA-only holders call this only after callback depth is zero,
        // registration removal returned, and no borrowed COM call is entered.
        if !self.released.replace(true) { unsafe { ManuallyDrop::drop(&mut *self.value.get()); } }
    }
    fn release_before(&self, end: std::time::Instant) -> UiResult<()> {
        cleanup_checkpoint(end)?; self.release(); cleanup_checkpoint(end)
    }
}
// Synchronous COM creation/query APIs still receive an ORIGINAL output cell.
// An unexpected pending/partial result must not leave a stack destination or
// silently discard a returned reference. Successful custody transfers once to
// the caller's already registered ComOriginal; there is no implicit Release.
struct ComOutputState {
    value: UnsafeCell<*mut std::ffi::c_void>, entered: Cell<bool>, returned: Cell<bool>,
    transferred: Cell<bool>, unknown: Cell<bool>,
}
struct ComOutput { state: Held<ComOutputState> }
impl ComOutput {
    fn new() -> Self { Self { state: ManuallyDrop::new(Box::pin(ComOutputState {
        value: UnsafeCell::new(null_mut()), entered: Cell::new(false), returned: Cell::new(false),
        transferred: Cell::new(false), unknown: Cell::new(false),
    })) } }
    fn begin(&self) -> UiResult<*mut *mut std::ffi::c_void> {
        if self.state.entered.replace(true) || self.state.unknown.get() {
            self.state.unknown.set(true); return Err(UiError::CleanupUnknown);
        }
        Ok(self.state.value.get())
    }
    fn complete<I: Interface>(&self, result: windows::core::HRESULT) -> UiResult<I> {
        if !self.state.entered.get() || self.state.returned.get() || self.state.unknown.get()
            || result.0 == HRESULT_PENDING {
            self.state.unknown.set(true); return Err(UiError::CleanupUnknown);
        }
        self.state.returned.set(true);
        let value = unsafe { *self.state.value.get() };
        if result.0 != 0 {
            if result.is_ok() || !value.is_null() {
                self.state.unknown.set(true); return Err(UiError::CleanupUnknown);
            }
            return Err(UiError::NativeFailure);
        }
        if value.is_null() { self.state.unknown.set(true); return Err(UiError::CleanupUnknown); }
        self.state.transferred.set(true);
        Ok(unsafe { I::from_raw(value) })
    }
    fn settled(&self) -> bool {
        !self.state.unknown.get() && (!self.state.entered.get()
            || self.state.returned.get() && (self.state.transferred.get() || unsafe { (*self.state.value.get()).is_null() }))
    }
}
impl Drop for ComOutput {
    fn drop(&mut self) { if self.settled() { unsafe { ManuallyDrop::drop(&mut self.state); } } }
}
struct ComValueState<T> { value: UnsafeCell<T>, entered: Cell<bool>, returned: Cell<bool>, unknown: Cell<bool> }
/// One scalar getter on the original COM object; the output is not a new
/// capability. Pending results retain their destination just like COM outputs.
struct ComValue<T: Copy + Default> { state: Held<ComValueState<T>> }
impl<T: Copy + Default> ComValue<T> {
    fn new() -> Self { Self { state: ManuallyDrop::new(Box::pin(ComValueState {
        value: UnsafeCell::new(T::default()), entered: Cell::new(false), returned: Cell::new(false), unknown: Cell::new(false),
    })) } }
    fn begin(&self) -> UiResult<*mut T> {
        if self.state.entered.replace(true) || self.state.unknown.get() {
            self.state.unknown.set(true); return Err(UiError::CleanupUnknown);
        }
        Ok(self.state.value.get())
    }
    fn complete(&self, result: windows::core::Result<()>) -> UiResult<T> {
        if !self.state.entered.get() || self.state.returned.get() || self.state.unknown.get()
            || result.as_ref().is_err_and(|error| error.code().0 == HRESULT_PENDING) {
            self.state.unknown.set(true); return Err(UiError::CleanupUnknown);
        }
        self.state.returned.set(true); hresult(result)?;
        Ok(unsafe { *self.state.value.get() })
    }
    fn settled(&self) -> bool { !self.state.unknown.get() && (!self.state.entered.get() || self.state.returned.get()) }
}
impl<T: Copy + Default> Drop for ComValue<T> {
    fn drop(&mut self) { if self.settled() { unsafe { ManuallyDrop::drop(&mut self.state); } } }
}
struct WatchCallbacks {
    thread: u32, depth: Cell<usize>, lost: Cell<bool>, unknown: Cell<bool>,
    browser: Cell<u32>, exited: Cell<bool>, on_loss: Box<dyn Fn()>,
    exit_args: OnceCell<ComOriginal<WV::ICoreWebView2BrowserProcessExitedEventArgs>>, exit_pid: ComValue<u32>,
}
impl WatchCallbacks {
    fn lost(&self) {
        if !self.lost.replace(true)
            && std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.on_loss)())).is_err() { self.unknown.set(true); }
    }
    fn enter(&self) -> CallbackReturn<'_> {
        if unsafe { T::GetCurrentThreadId() } != self.thread { self.unknown.set(true); }
        self.depth.set(self.depth.get().saturating_add(1)); CallbackReturn(self)
    }
    fn browser_exited(&self, args: Option<WV::ICoreWebView2BrowserProcessExitedEventArgs>) {
        if self.exit_args.get().is_some() { self.unknown.set(true); self.lost(); return; }
        let observed = (|| {
            let args = args.ok_or(UiError::NativeFailure)?;
            // Retain this callback's actual args before its getter, including
            // pending/partial return. A second exit never replaces the original.
            self.exit_args.set(ComOriginal::new(args)).map_err(|_| UiError::CleanupUnknown)?;
            let args = self.exit_args.get().ok_or(UiError::State)?.get()?;
            let output = self.exit_pid.begin()?;
            self.exit_pid.complete(unsafe { args.BrowserProcessId(output) })
        })();
        match observed {
            Ok(id) if id != 0 && id == self.browser.get() && !self.exited.replace(true) => {},
            _ => self.unknown.set(true),
        }
        self.lost();
    }
}
struct CallbackReturn<'a>(&'a WatchCallbacks);
impl Drop for CallbackReturn<'_> { fn drop(&mut self) { self.0.depth.set(self.0.depth.get().saturating_sub(1)); } }

/// Actual WebView2 controller/environment and event-registration originals.
/// Construct inert, retain, then install on the framework's same original STA.
struct DocumentWatch {
    controller: Option<ComOriginal<WV::ICoreWebView2Controller>>,
    environment: Option<ComOriginal<WV::ICoreWebView2Environment>>,
    environment5: Option<ComOriginal<WV::ICoreWebView2Environment5>>,
    environment7: Option<ComOriginal<WV::ICoreWebView2Environment7>>,
    core: Option<ComOriginal<WV::ICoreWebView2>>,
    core_output: ComOutput, environment5_output: ComOutput, environment7_output: ComOutput,
    failed_handler: Option<ComOriginal<WV::ICoreWebView2ProcessFailedEventHandler>>,
    exited_handler: Option<ComOriginal<WV::ICoreWebView2BrowserProcessExitedEventHandler>>,
    failed_token: HookToken, exited_token: HookToken,
    callbacks: Option<Rc<WatchCallbacks>>,
    version: NativeText, user_data: NativeText,
    parent_output: ComValue<HWND>, browser_output: ComValue<u32>,
    process: F::HANDLE,
    parent: HWND,
    begun: bool, installed: bool, close_entered: bool, controller_closed: bool,
    process_close_entered: bool, released: bool, unknown: bool,
}
impl DocumentWatch {
    fn new() -> Self { Self {
        controller: None, environment: None, environment5: None, environment7: None, core: None,
        core_output: ComOutput::new(), environment5_output: ComOutput::new(), environment7_output: ComOutput::new(),
        failed_handler: None, exited_handler: None, failed_token: HookToken::new(), exited_token: HookToken::new(), callbacks: None,
        version: NativeText::new(), user_data: NativeText::new(), parent_output: ComValue::new(), browser_output: ComValue::new(),
        process: null_mut(), parent: HWND::default(),
        begun: false, installed: false, close_entered: false, controller_closed: false,
        process_close_entered: false, released: false, unknown: false,
    } }
    fn callbacks(&self) -> UiResult<&WatchCallbacks> { self.callbacks.as_deref().ok_or(UiError::State) }
    fn fail<T>(&mut self, error: UiError) -> UiResult<T> {
        if error == UiError::CleanupUnknown { self.unknown = true; }
        if let Some(callbacks) = &self.callbacks { callbacks.lost(); }
        Err(error)
    }
    fn install(&mut self, controller: WV::ICoreWebView2Controller, environment: WV::ICoreWebView2Environment,
        prerequisites: &mut Prerequisites, data: &Path, on_loss: Box<dyn Fn()>) -> UiResult<()> {
        if self.begun { return Err(UiError::State); }
        self.begun = true;
        // Adoption precedes every post-dispatch/STOP/admission observation.
        self.controller = Some(ComOriginal::new(controller));
        self.environment = Some(ComOriginal::new(environment));
        self.callbacks = Some(Rc::new(WatchCallbacks { thread: unsafe { T::GetCurrentThreadId() },
            depth: Cell::new(0), lost: Cell::new(false), unknown: Cell::new(false), browser: Cell::new(0),
            exited: Cell::new(false), on_loss, exit_args: OnceCell::new(), exit_pid: ComValue::new() }));
        let result = self.install_inner(prerequisites, data);
        match result { Ok(()) => { self.installed = true; Ok(()) }, Err(error) => self.fail(error) }
    }
    fn install_inner(&mut self, prerequisites: &mut Prerequisites, data: &Path) -> UiResult<()> {
        sta()?; prerequisites.recheck()?;
        let controller = self.controller.as_ref().ok_or(UiError::State)?.get()?;
        let core_output = self.core_output.begin()?;
        let core = unsafe { (controller.vtable().CoreWebView2)(controller.as_raw(), core_output) };
        self.core = Some(ComOriginal::new(self.core_output.complete(core)?));
        let parent_output = self.parent_output.begin()?;
        self.parent = self.parent_output.complete(unsafe { controller.ParentWindow(parent_output) })?;
        let mut process_id = 0;
        if self.parent.0.is_null() || unsafe { W::GetWindowThreadProcessId(self.parent.0, &mut process_id) } != prerequisites.thread
            || process_id != unsafe { T::GetCurrentProcessId() } { return Err(UiError::OrdinaryContext); }
        let environment = self.environment.as_ref().ok_or(UiError::State)?.get()?;
        let environment5_output = self.environment5_output.begin()?;
        let environment5 = unsafe { (environment.vtable().base__.QueryInterface)(environment.as_raw(),
            &WV::ICoreWebView2Environment5::IID, environment5_output) };
        self.environment5 = Some(ComOriginal::new(self.environment5_output.complete(environment5)?));
        let environment7_output = self.environment7_output.begin()?;
        let environment7 = unsafe { (environment.vtable().base__.QueryInterface)(environment.as_raw(),
            &WV::ICoreWebView2Environment7::IID, environment7_output) };
        self.environment7 = Some(ComOriginal::new(self.environment7_output.complete(environment7)?));
        self.version.entered = true;
        let version = unsafe { environment.BrowserVersionString(&mut self.version.value) };
        self.version.complete(version)?;
        if self.version.read(96)? != prerequisites.facts.as_ref().ok_or(UiError::State)?.runtime_version { return Err(UiError::ManagedRuntimeUnavailable); }
        self.user_data.entered = true;
        let folder = unsafe { self.environment7.as_ref().ok_or(UiError::State)?.get()?.UserDataFolder(&mut self.user_data.value) };
        self.user_data.complete(folder)?;
        if Path::new(&self.user_data.read(NAME_UNITS)?) != data { return Err(UiError::UserDataParent); }
        let callbacks = self.callbacks.as_ref().ok_or(UiError::State)?.clone();
        self.failed_handler = Some(ComOriginal::new(webview2_com::ProcessFailedEventHandler::create(Box::new(move |_, _| {
            let _return = callbacks.enter(); callbacks.lost(); Ok(())
        }))));
        let callbacks = self.callbacks.as_ref().ok_or(UiError::State)?.clone();
        self.exited_handler = Some(ComOriginal::new(webview2_com::BrowserProcessExitedEventHandler::create(Box::new(move |_, args| {
            let _return = callbacks.enter();
            callbacks.browser_exited(args); Ok(())
        }))));
        let browser_output = self.browser_output.begin()?;
        let pid = self.browser_output.complete(unsafe {
            self.core.as_ref().ok_or(UiError::State)?.get()?.BrowserProcessId(browser_output)
        })?;
        if pid == 0 || self.callbacks()?.lost.get() { return Err(UiError::NativeFailure); }
        self.callbacks()?.browser.set(pid);
        self.process = unsafe { T::OpenProcess(T::PROCESS_QUERY_LIMITED_INFORMATION | FS::SYNCHRONIZE, 0, pid) };
        if !valid_handle(self.process) { return Err(UiError::NativeFailure); }
        if unsafe { T::GetProcessId(self.process) } != pid
            || unsafe { T::WaitForSingleObject(self.process, 0) } != F::WAIT_TIMEOUT { return Err(UiError::NativeFailure); }
        let mut image = [0u16; NAME_UNITS]; let mut count = image.len() as u32;
        if unsafe { T::QueryFullProcessImageNameW(self.process, 0, image.as_mut_ptr(), &mut count) } == 0
            || count == 0 || count as usize >= image.len() { return Err(UiError::ManagedRuntimeUnavailable); }
        let path = String::from_utf16(&image[..count as usize]).map_err(|_| UiError::ManagedRuntimeUnavailable)?;
        if !path.eq_ignore_ascii_case(&prerequisites.image_dos) { return Err(UiError::ManagedRuntimeUnavailable); }
        // Correspondence with the SAME protected executable original, not just
        // a version string, a numeric PID, or a new pathname open after launch.
        let image = prerequisites.image.ok_or(UiError::State)?;
        if mapped(prerequisites.native.metadata(&prerequisites.paths[image].original), UiError::ManagedRuntimeUnavailable)?
            != prerequisites.paths[image].metadata { return Err(UiError::ManagedRuntimeUnavailable); }
        // Expected browser identity is installed before either callback can run.
        self.failed_token.entered = true;
        let registered = unsafe { self.core.as_ref().ok_or(UiError::State)?.get()?.add_ProcessFailed(
            self.failed_handler.as_ref().ok_or(UiError::State)?.get()?, &mut self.failed_token.value) };
        self.failed_token.complete(registered)?;
        self.exited_token.entered = true;
        let registered = unsafe { self.environment5.as_ref().ok_or(UiError::State)?.get()?.add_BrowserProcessExited(
            self.exited_handler.as_ref().ok_or(UiError::State)?.get()?, &mut self.exited_token.value) };
        self.exited_token.complete(registered)?;
        if unsafe { T::WaitForSingleObject(self.process, 0) } != F::WAIT_TIMEOUT { return Err(UiError::NativeFailure); }
        if self.callbacks()?.lost.get() || self.callbacks()?.unknown.get() { return Err(UiError::NativeFailure); }
        Ok(())
    }
    fn parent(&self, kind: DialogKind) -> UiResult<DialogParent> {
        sta()?;
        if !self.installed || self.released || self.unknown
            || kind == DialogKind::Project && (self.close_entered || self.callbacks()?.lost.get()) { return Err(UiError::State); }
        let mut process = 0;
        if unsafe { W::GetWindowThreadProcessId(self.parent.0, &mut process) } != self.callbacks()?.thread
            || process != unsafe { T::GetCurrentProcessId() } { return Err(UiError::State); }
        Ok(DialogParent { window: self.parent, thread: self.callbacks()?.thread })
    }
    fn close_once(&mut self, end: std::time::Instant) -> UiResult<()> {
        cleanup_checkpoint(end)?; sta()?;
        if self.unknown || self.callbacks()?.unknown.get() || self.callbacks()?.depth.get() != 0 { return Err(UiError::CleanupUnknown); }
        if self.close_entered { return if self.controller_closed { Ok(()) } else { Err(UiError::CleanupUnknown) }; }
        self.close_entered = true; self.callbacks()?.lost();
        // Remove the core hook while the core is still open. Calling core event
        // methods after Controller.Close can fail with object-disconnected.
        if let Some(token) = self.failed_token.token()? {
            if self.failed_token.remove_entered { return self.fail(UiError::CleanupUnknown); }
            self.failed_token.remove_entered = true;
            if unsafe { self.core.as_ref().ok_or(UiError::State)?.get()?.remove_ProcessFailed(token) }.is_err() {
                return self.fail(UiError::CleanupUnknown);
            }
            self.failed_token.removed = true;
        }
        cleanup_checkpoint(end)?;
        if unsafe { self.controller.as_ref().ok_or(UiError::State)?.get()?.Close() }.is_err() { return self.fail(UiError::CleanupUnknown); }
        self.controller_closed = true; cleanup_checkpoint(end)
    }
    fn settle(&mut self, end: std::time::Instant) -> UiResult<bool> {
        cleanup_checkpoint(end)?; sta()?;
        if self.released { return Ok(true); }
        if self.unknown || self.callbacks()?.unknown.get() || self.callbacks()?.depth.get() != 0 {
            return self.fail(UiError::CleanupUnknown);
        }
        if !self.controller_closed || !valid_handle(self.process) { return self.fail(UiError::CleanupUnknown); }
        match unsafe { T::WaitForSingleObject(self.process, 0) } {
            F::WAIT_TIMEOUT => return Ok(false),
            F::WAIT_OBJECT_0 => {},
            _ => return self.fail(UiError::CleanupUnknown),
        }
        // A genuine exit callback AND the original process handle's signaled
        // state are both required; absence/reuse of a PID is never finality.
        if !self.callbacks()?.exited.get() { return Ok(false); }
        cleanup_checkpoint(end)?;
        if let Some(token) = self.exited_token.token()? {
            if self.exited_token.remove_entered { return self.fail(UiError::CleanupUnknown); }
            self.exited_token.remove_entered = true;
            if unsafe { self.environment5.as_ref().ok_or(UiError::State)?.get()?.remove_BrowserProcessExited(token) }.is_err() {
                return self.fail(UiError::CleanupUnknown);
            }
            self.exited_token.removed = true;
        }
        cleanup_checkpoint(end)?;
        if self.callbacks()?.depth.get() != 0 { return self.fail(UiError::CleanupUnknown); }
        if !self.core_output.settled() || !self.environment5_output.settled() || !self.environment7_output.settled()
            || !self.parent_output.settled() || !self.browser_output.settled() || !self.callbacks()?.exit_pid.settled() {
            return self.fail(UiError::CleanupUnknown);
        }
        self.version.release()?; cleanup_checkpoint(end)?;
        self.user_data.release()?; cleanup_checkpoint(end)?;
        if self.process_close_entered { return self.fail(UiError::CleanupUnknown); }
        self.process_close_entered = true;
        if unsafe { F::CloseHandle(self.process) } == 0 { return self.fail(UiError::CleanupUnknown); }
        self.process = null_mut(); cleanup_checkpoint(end)?;
        if let Some(original) = &self.failed_handler { original.release_before(end)?; }
        if let Some(original) = &self.exited_handler { original.release_before(end)?; }
        if let Some(original) = &self.core { original.release_before(end)?; }
        if let Some(original) = &self.controller { original.release_before(end)?; }
        if let Some(original) = &self.environment7 { original.release_before(end)?; }
        if let Some(original) = &self.environment5 { original.release_before(end)?; }
        if let Some(original) = &self.environment { original.release_before(end)?; }
        if let Some(original) = self.callbacks()?.exit_args.get() { original.release_before(end)?; }
        self.released = true; Ok(true)
    }
}

/// One original application lifetime. Registered before prepare; retained by the
/// same STA through WebView/controller/browser/callback and data-scope settlement.
pub struct ShellSession {
    prerequisites: Prerequisites,
    profile: profile::Profile,
    watch: DocumentWatch,
    construction_started: bool,
    cleanup_end: Option<std::time::Instant>,
    finality: bool,
    unknown: bool,
}
/// Borrowed main-window identity minted only by the retained actual watch. It
/// owns no HWND and must never be closed/destroyed by a dialog.
pub struct DialogParent { window: HWND, thread: u32 }
impl Default for ShellSession { fn default() -> Self { Self::new() } }
impl ShellSession {
    pub fn new() -> Self { Self { prerequisites: Prerequisites::new(), profile: profile::Profile::new(),
        watch: DocumentWatch::new(), construction_started: false, cleanup_end: None, finality: false, unknown: false } }
    pub fn prepare(&mut self) -> UiResult<PathBuf> {
        self.prerequisites.inspect()?; self.profile.create(&mut self.prerequisites)?;
        Ok(self.profile.path()?.to_path_buf())
    }
    pub fn before_webview(&mut self) -> UiResult<()> {
        if self.construction_started || self.unknown { return Err(UiError::State); }
        self.prerequisites.recheck()?; self.profile.path()?;
        self.construction_started = true; Ok(())
    }
    pub fn install(&mut self, controller: WV::ICoreWebView2Controller, environment: WV::ICoreWebView2Environment,
        on_loss: Box<dyn Fn()>) -> UiResult<()> {
        if !self.construction_started || self.unknown { return Err(UiError::State); }
        let path = self.profile.path()?.to_path_buf();
        self.watch.install(controller, environment, &mut self.prerequisites, &path, on_loss)
    }
    pub fn dialog_parent(&self, kind: DialogKind) -> UiResult<DialogParent> { self.watch.parent(kind) }
    pub fn finish_failed_setup(&mut self, end: std::time::Instant) -> UiResult<bool> {
        if self.construction_started {
            // Wry has not provided custody of every partial creation to the
            // caller on build failure. Do not infer no browser or delete UDF.
            self.mark_unknown(); return Err(UiError::CleanupUnknown);
        }
        self.begin_close(end)?; self.settle()
    }
    pub fn begin_close(&mut self, end: std::time::Instant) -> UiResult<()> {
        if self.unknown { return Err(UiError::CleanupUnknown); }
        if self.cleanup_end.is_some_and(|original| original != end) { self.mark_unknown(); return Err(UiError::CleanupUnknown); }
        self.cleanup_end = Some(end); // Original endpoint, before first native Close.
        if cleanup_checkpoint(end).is_err() { self.mark_unknown(); return Err(UiError::CleanupUnknown); }
        let result = if self.construction_started { self.watch.close_once(end) } else { Ok(()) };
        if result == Err(UiError::CleanupUnknown) || cleanup_checkpoint(end).is_err() {
            self.mark_unknown(); return Err(UiError::CleanupUnknown);
        }
        result
    }
    pub fn settle(&mut self) -> UiResult<bool> {
        if self.unknown { return Err(UiError::CleanupUnknown); }
        if self.finality { return Ok(true); }
        let end = self.cleanup_end.ok_or(UiError::State)?;
        if cleanup_checkpoint(end).is_err() { self.mark_unknown(); return Err(UiError::CleanupUnknown); }
        if self.construction_started {
            match self.watch.settle(end) {
                Ok(true) => {},
                Ok(false) => return Ok(false),
                Err(error) => { self.mark_unknown(); return Err(error); },
            }
        }
        if self.profile.settle_once(&mut self.prerequisites, true, end).is_err() {
            self.unknown = true; return Err(UiError::CleanupUnknown);
        }
        if cleanup_checkpoint(end).is_err() || self.prerequisites.settle_once() != CloseOutcome::Settled
            || cleanup_checkpoint(end).is_err() {
            self.unknown = true; return Err(UiError::CleanupUnknown);
        }
        self.finality = true; Ok(true)
    }
    pub fn mark_unknown(&mut self) { self.unknown = true; if let Some(callbacks) = &self.watch.callbacks { callbacks.lost(); } }
    #[cfg(feature = "windows-installed-observation")]
    pub fn observed_finality(&self) -> UiResult<bool> {
        sta()?;
        Ok(self.finality && !self.unknown && self.profile.settled() && self.prerequisites.settled()
            && self.watch.released && self.watch.failed_token.settled() && self.watch.exited_token.settled()
            && self.watch.process.is_null() && self.watch.callbacks.as_ref().is_some_and(|callbacks|
                callbacks.depth.get() == 0 && callbacks.exited.get() && !callbacks.unknown.get()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn managed_runtime_root_and_every_descendant_use_immutable_policy() {
        // C:\Program Files (x86)\Microsoft\EdgeWebView: depth three is the
        // managed root; Application, version and the executable are inside it.
        for depth in 0..3 { assert_eq!(managed_runtime_scope(depth, 3), AuthorityScope::AncestorOutsideVersion); }
        for depth in 3..7 { assert_eq!(managed_runtime_scope(depth, 3), AuthorityScope::ImmutableVersion); }
    }
    #[test]
    fn system_evergreen_version_never_admits_preview_channel_or_path() {
        assert!(stable_version("142.0.3595.65"));
        for value in ["", "142.0.3595.65 beta", "142.0.3595.65 dev", "0142.0.0.1", "142.0.0", "142.0.0.65536", "..\\runtime", "119.0.0.1"] {
            assert!(!stable_version(value));
        }
    }
    #[test]
    fn callbacks_remain_absorbingly_lost_and_track_original_return() {
        let calls = Rc::new(Cell::new(0)); let observed = calls.clone();
        let state = WatchCallbacks { thread: 0, depth: Cell::new(0), lost: Cell::new(false), unknown: Cell::new(false),
            browser: Cell::new(0), exited: Cell::new(false), on_loss: Box::new(move || observed.set(observed.get() + 1)),
            exit_args: OnceCell::new(), exit_pid: ComValue::new() };
        // Pure state branch: no Windows process/window/COM call in this test.
        state.depth.set(1); let returned = CallbackReturn(&state);
        state.lost(); state.lost(); assert_eq!(calls.get(), 1); assert_eq!(state.depth.get(), 1);
        drop(returned); assert_eq!(state.depth.get(), 0); assert!(state.lost.get());
    }
    #[test]
    fn registration_requires_actual_removal_and_partial_failure_is_not_settled() -> UiResult<()> {
        let mut token = HookToken::new(); token.entered = true;
        token.complete(Ok(()))?; // Zero is not reserved by EventRegistrationToken.
        assert_eq!(token.token()?, Some(0)); assert!(!token.settled());
        token.remove_entered = true; token.removed = true;
        assert_eq!(token.token()?, None); assert!(token.settled());

        let mut partial = HookToken::new(); partial.entered = true; partial.value = 12;
        let failed = windows::core::HRESULT(0x80004005u32 as i32).ok();
        assert_eq!(partial.complete(failed), Err(UiError::CleanupUnknown));
        assert_eq!(partial.token(), Err(UiError::CleanupUnknown)); assert!(!partial.settled());
        assert_eq!(partial.complete(Ok(())), Err(UiError::CleanupUnknown));
        Ok(())
    }
    #[test]
    fn pending_outputs_never_become_releasable_from_a_late_success() -> UiResult<()> {
        let output = ComOutput::new(); let _destination = output.begin()?;
        assert!(matches!(output.complete::<windows::core::IUnknown>(windows::core::HRESULT(HRESULT_PENDING)),
            Err(UiError::CleanupUnknown)));
        assert!(!output.settled());
        assert!(matches!(output.complete::<windows::core::IUnknown>(windows::core::HRESULT(0)),
            Err(UiError::CleanupUnknown)));
        let scalar = ComValue::<u32>::new(); let _destination = scalar.begin()?;
        assert_eq!(scalar.complete(windows::core::HRESULT(HRESULT_PENDING).ok()), Err(UiError::CleanupUnknown));
        assert_eq!(scalar.complete(Ok(())), Err(UiError::CleanupUnknown)); assert!(!scalar.settled());
        let mut text = NativeText::new(); text.entered = true;
        assert_eq!(text.complete(windows::core::HRESULT(HRESULT_PENDING).ok()), Err(UiError::CleanupUnknown));
        assert_eq!(text.release(), Err(UiError::CleanupUnknown));
        assert_eq!(text.complete(Ok(())), Err(UiError::CleanupUnknown));
        Ok(())
    }
    #[test]
    fn shell_cleanup_endpoint_cannot_expire_or_be_replaced_into_success() -> UiResult<()> {
        let first = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut original = ShellSession::new(); original.begin_close(first)?;
        assert_eq!(original.begin_close(first + std::time::Duration::from_secs(1)), Err(UiError::CleanupUnknown));
        assert_eq!(original.settle(), Err(UiError::CleanupUnknown));
        let mut expired = ShellSession::new();
        assert_eq!(expired.begin_close(std::time::Instant::now()), Err(UiError::CleanupUnknown));
        assert_eq!(expired.begin_close(first), Err(UiError::CleanupUnknown));
        assert!(!expired.finality); assert!(!original.finality);
        Ok(())
    }
}
