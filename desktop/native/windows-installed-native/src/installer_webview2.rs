//! Fixed acquired Evergreen prerequisite. No path, command, service or account RPC.
//! The caller retains this original before native entry and lends the SAME installer
//! boundary. Shared Microsoft update services and their outputs are never task-owned.
use super::*;
use super::installer_acquisition::{InputAcquisition, PrerequisiteBinding};
use super::installer_primitives::*;
use super::{AdmissionRole as R, AdmissionOp as O};
use sha2::{Digest, Sha256};
use windows_sys::Win32::System::{JobObjects as J, Registry as REG};

const INSTALLER: &str = "MicrosoftEdgeWebView2RuntimeInstallerX64.exe";
const CLIENT: &str = "SOFTWARE\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
const SUPPORT_ENTRIES: u32 = 2048;
const SUPPORT_DEPTH: usize = 16;
const SUPPORT_BYTES: u64 = 1024 * 1024 * 1024;
const FREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const OWNED_PROCESSES: u32 = 32;
const WAIT_MS: u32 = 100;
// A finite call bound, not another clock/lease. The original 570/600 guard is
// still decisive, including settlement. No loop is allowed to run indefinitely.
const WAIT_SLICES: usize = 6000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfflineWebView2Mode { AlreadyPresent, Installed }
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum WebView2SupportDisposition {
    /// No owned creation was recorded; this is NOT a pathname-absence proof.
    #[default]
    NoOwnedOutputRecorded,
    RetainedBeforeVendor,
    RetainedVendorMayHaveRun,
    CreationUncertain,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WebView2SupportOutput {
    pub disposition: WebView2SupportDisposition,
    pub created: bool, pub retained: bool, pub census_complete: bool,
    pub entries: u32, pub bytes: u64, pub over_budget: bool,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OfflineWebView2Report {
    pub mode: Option<OfflineWebView2Mode>, pub vendor_may_have_run: bool,
    pub process_signalled: bool, pub owned_job_empty: bool,
    /// Actual returned process exit code, never a PID or a vendor log.
    pub vendor_exit_code: Option<u32>,
    /// Settlement was withheld for the launch-dependent original books because
    /// this same retained process owner has not established finality.
    pub process_dependencies_pending: bool,
    pub support: WebView2SupportOutput,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebView2Original { Input, MachineBefore, MachineAfter, Support, System, RegistryBefore, RegistryAfter, Job, Process, Thread }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebView2CleanupError {
    pub original: WebView2Original,
    /// Retained record ordinal, NEVER an OS HANDLE or PID.
    pub record: usize,
    pub error: Error,
}

// Only the two fixed entry methods select this policy. It is not a runtime
// presence receipt, caller-selected command, or authority to skip any admission.
#[derive(Clone, Copy)]
enum PreparationRoute {
    InstallIfNeeded,
    #[cfg(feature = "qualification-result")]
    ExistingOnly,
}
impl PreparationRoute {
    fn permit_install(self) -> Result<()> {
        match self {
            Self::InstallIfNeeded => Ok(()),
            #[cfg(feature = "qualification-result")]
            Self::ExistingOnly => Err(Error::Unavailable),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Version { text: String, parts: [u16; 4] }
impl Version {
    fn parse(value: &str) -> Result<Option<Self>> {
        if value.is_empty() || value == "0.0.0.0" { return Ok(None); }
        let mut parts = [0u16; 4];
        let mut split = value.split('.');
        for part in &mut parts {
            let text = split.next().ok_or(Error::Unsafe)?;
            need(!text.is_empty() && text.len() <= 5 && (text.len() == 1 || !text.starts_with('0'))
                && text.bytes().all(|c| c.is_ascii_digit()))?;
            *part = text.parse().map_err(|_| Error::Unsafe)?;
        }
        need(split.next().is_none() && parts[0] > 0)?;
        Ok(Some(Self { text: value.to_owned(), parts }))
    }
    fn supported(&self) -> bool { self.parts[0] >= 120 }
}

// The production registry observation and focused DATA tests share this exact
// decoder. Passing DATA here cannot open a registry key or create runtime proof.
fn registry_version(kind: u32, length: usize, bytes: &[u8]) -> Result<Option<Version>> {
    need(kind == REG::REG_SZ && length <= 128 && length <= bytes.len() && length % 2 == 0)?;
    if length == 0 { return Ok(None); }
    let mut text: Vec<u16> = bytes[..length].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    need(text.pop() == Some(0) && !text.contains(&0))?;
    let value = String::from_utf16(&text).map_err(|_| Error::Unsafe)?;
    Version::parse(&value)
}

fn completed_exit(signalled: bool, code: u32) -> Result<()> {
    need(signalled && code != F::STILL_ACTIVE as u32 && code == 0)
}

fn owned_job_empty(count_bytes: u32, total: u32, active: u32, assigned: bool) -> Result<bool> {
    need(count_bytes == size_of::<J::JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32
        && active <= OWNED_PROCESSES && total >= active && (!assigned || total > 0))?;
    Ok(active == 0)
}

fn clean_environment(system: &str, windows: &str, support: &str) -> Result<Vec<u16>> {
    let mut environment = Vec::new();
    for (key, value) in [("PATH", system), ("SystemRoot", windows), ("TEMP", support), ("TMP", support), ("windir", windows)] {
        environment.extend(wide(&format!("{key}={value}")));
    }
    environment.push(0); need(environment.len() < 4 * NAME_UNITS)?;
    Ok(environment)
}

// Private syntax, not an arbitrary executor/callback. An actual returned error
// is classified and retained before sampling a later STOP or deadline.
macro_rules! path_call {
    ($owner:ident, $boundary:ident, $expression:expr) => {{
        $owner.before($boundary)?;
        let returned = $expression;
        $owner.after($boundary, returned)?
    }};
}

struct Node {
    slot: usize, parent: Option<usize>, path: String, facts: Facts,
    scope: AuthorityScope, managed_image: bool, os_ancestor: bool,
    entries: Option<Vec<DirectoryEntry>>,
}
struct PathBook {
    native: NativeBook, mutation: MutationSlot, nodes: Vec<Node>,
    location: Option<KnownLocation>, first: Option<Error>, unknown: bool, settled: bool,
}
impl PathBook {
    fn new() -> Self {
        Self { native: NativeBook::new(), mutation: None, nodes: Vec::new(),
            location: None, first: None, unknown: false, settled: false }
    }
    fn key(&self, slot: usize) -> Original { Original { book: Arc::clone(&self.native.identity), index: slot } }
    fn latch(&mut self, error: Error) {
        if self.first.is_none() { self.first = Some(error); }
        self.unknown |= error == Error::Unknown || self.native.is_unknown() || self.mutation.is_some();
    }
    fn before(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        let returned = if self.unknown || self.native.is_unknown() || self.mutation.is_some() { Err(Error::Unknown) }
            else if self.first.is_some() || self.settled { Err(Error::State) }
            else { boundary.producing_boundary() };
        if let Err(error) = returned { self.latch(error); } returned
    }
    fn after<T>(&mut self, boundary: &dyn InstallerBoundary, returned: Result<T>) -> Result<T> {
        let returned = match returned { Err(first) => Err(first), Ok(value) => boundary.producing_boundary().map(|()| value) };
        if let Err(error) = returned.as_ref() { self.latch(*error); } returned
    }
    fn checked(&mut self, boundary: &dyn InstallerBoundary, slot: usize,
        scope: AuthorityScope, managed: bool) -> Result<Facts> {
        let key = self.key(slot);
        path_call!(self, boundary, self.native.noninherited(slot));
        let metadata = if managed { path_call!(self, boundary, self.native.managed_webview_image_metadata(&key)) }
            else { path_call!(self, boundary, self.native.metadata(&key)) };
        need(metadata.identity.volume_serial != 0 && metadata.creation > 0 && metadata.write > 0 && metadata.change > 0
            && if managed { metadata.links > 0 } else { metadata.links == 1 })?;
        path_call!(self, boundary, self.native.no_alternate_streams(&key));
        let security = path_call!(self, boundary, self.native.security(&key, scope));
        let after = if managed { path_call!(self, boundary, self.native.managed_webview_image_metadata(&key)) }
            else { path_call!(self, boundary, self.native.metadata(&key)) };
        need(after == metadata)?; Ok(Facts { metadata, security })
    }
    fn recheck(&mut self, boundary: &dyn InstallerBoundary, index: usize) -> Result<()> {
        let node = self.nodes.get(index).ok_or(Error::State)?;
        let (slot, scope, managed, facts) = (node.slot, node.scope, node.managed_image, node.facts.clone());
        need(self.checked(boundary, slot, scope, managed)? == facts)
    }
    fn recheck_after_vendor(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        self.recheck_location(boundary)?;
        for index in 0..self.nodes.len() {
            let node = &self.nodes[index];
            let (slot, scope, managed, os, facts) =
                (node.slot, node.scope, node.managed_image, node.os_ancestor, node.facts.clone());
            let current = self.checked(boundary, slot, scope, managed)?;
            if os {
                // ONLY the freshly OS-discovered volume/Program Files/Windows
                // ancestry. The recorded support creation/vendor-created siblings
                // may change directory times.
                // MRK inputs and every managed-runtime node NEVER take this arm.
                need(same_object(&facts.metadata, &current.metadata) && facts.security == current.security)?;
            } else { need(current == facts)?; }
        }
        Ok(())
    }
    fn recheck_location(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        self.before(boundary)?;
        let returned = self.native.recheck_location(self.location.as_ref().ok_or(Error::State)?);
        self.after(boundary, returned)
    }
    fn entries(&mut self, boundary: &dyn InstallerBoundary, index: usize, selected: Option<&str>) -> Result<Vec<DirectoryEntry>> {
        if let Some(entries) = &self.nodes.get(index).ok_or(Error::State)?.entries { return Ok(entries.clone()); }
        self.recheck(boundary, index)?;
        let key = self.key(self.nodes[index].slot);
        let mut entries = Vec::new();
        loop {
            let next = match selected {
                Some(name) => path_call!(self, boundary, self.native.next_ancestor_entries(&key, name)),
                None => path_call!(self, boundary, self.native.next_entries(&key)),
            };
            match next { Some(rows) => { need(entries.len().saturating_add(rows.len()) <= MAX_ENTRIES)?; entries.extend(rows); }, None => break }
        }
        let node = &self.nodes[index];
        check_entry_frame(&entries, &node.facts.metadata, node.parent.map(|p| &self.nodes[p].facts.metadata))?;
        self.recheck(boundary, index)?;
        self.nodes[index].entries = Some(entries.clone()); Ok(entries)
    }
    fn child(&mut self, boundary: &dyn InstallerBoundary, parent: usize, name: &str,
        kind: FileKind, scope: AuthorityScope, managed: bool, os: bool) -> Result<usize> {
        let entries = self.entries(boundary, parent, Some(name))?;
        let row = selected_entry(&entries, name)?.ok_or(Error::Unsafe)?;
        need(row.kind == kind)?;
        self.recheck(boundary, parent)?;
        let key = self.key(self.nodes[parent].slot);
        let original = if managed { path_call!(self, boundary, self.native.open_metadata_child(&key, name)) }
            else { path_call!(self, boundary, self.native.open_child(&key, name, kind)) };
        let facts = self.checked(boundary, original.index, scope, managed)?;
        match_entry(&row, &facts.metadata)?;
        need(!self.nodes.iter().any(|n| n.facts.metadata.identity == facts.metadata.identity))?;
        let prefix = &self.nodes[parent].path;
        let path = format!("{}{}{}", prefix, if prefix.ends_with('\\') { "" } else { "\\" }, name);
        need(path.encode_utf16().count() < NAME_UNITS)?;
        let index = self.nodes.len();
        self.nodes.push(Node { slot: original.index, parent: Some(parent), path, facts, scope,
            managed_image: managed, os_ancestor: os, entries: None });
        self.recheck(boundary, parent)?; Ok(index)
    }
    fn root(&mut self, boundary: &dyn InstallerBoundary, kind: LocationKind) -> Result<usize> {
        need(self.nodes.is_empty() && self.location.is_none())?;
        let location = path_call!(self, boundary, self.native.location(kind));
        need(Arc::ptr_eq(&location.book, &self.native.identity))?;
        need(location.components.len() <= super::installer_input_data::SOURCE_COMPONENTS)?;
        need(path_call!(self, boundary, self.native.mapping(&location.drive)) == location.device)?;
        let dos = format!("{}\\", location.drive);
        let native = format!("{}\\", location.device);
        let original = path_call!(self, boundary, self.native.reserve(Kind::Directory, None, &native, native.clone()));
        path_call!(self, boundary, self.native.call(Call::Open(original.index), null_mut(), Vec::new()));
        path_call!(self, boundary, self.native.local_ntfs(&original));
        let facts = self.checked(boundary, original.index, AuthorityScope::AncestorOutsideVersion, false)?;
        self.nodes.push(Node { slot: original.index, parent: None, path: dos, facts,
            scope: AuthorityScope::AncestorOutsideVersion, managed_image: false, os_ancestor: true, entries: None });
        let components = location.components.clone(); self.location = Some(location);
        let mut parent = 0;
        for component in components {
            parent = self.child(boundary, parent, &component, FileKind::Directory,
                AuthorityScope::AncestorOutsideVersion, false, true)?;
        }
        self.recheck_location(boundary)?; Ok(parent)
    }
    fn close_producing(&mut self, boundary: &dyn InstallerBoundary, slot: usize) -> Result<()> {
        self.before(boundary)?; let returned = self.native.close_index(slot); self.after(boundary, returned)
    }
    fn settle_process_dependency(&mut self, boundary: &dyn InstallerBoundary, process: &VendorProcess,
        role: WebView2Original, errors: &mut Vec<WebView2CleanupError>) -> CloseOutcome {
        // These originals protect the executable, working directory and clean
        // environment locations of THIS launch. Unknown process admission cannot
        // release them. Do not mark attempted, consume, reopen or retry anything.
        if !process.finality() { return CloseOutcome::Unknown; }
        self.settle(boundary, role, errors)
    }
    fn settle(&mut self, boundary: &dyn InstallerBoundary, role: WebView2Original, errors: &mut Vec<WebView2CleanupError>) -> CloseOutcome {
        if self.settled { return if self.native.settled() && !self.unknown { CloseOutcome::Settled } else { CloseOutcome::Unknown }; }
        self.settled = true;
        if self.mutation.is_some() || self.native.active.is_some() {
            self.unknown = true; return CloseOutcome::Unknown;
        }
        // Do not call NativeBook::settle_once's native loop without boundaries.
        // Close only known originals once; preserve a failed consuming attempt.
        self.native.retiring = true;
        for index in (0..self.native.slots.len()).rev() {
            if matches!(self.native.slots[index].state, SlotState::NoHandle | SlotState::Closed) { continue; }
            boundary.settlement_boundary();
            let returned = self.native.close_index(index);
            if let Err(error) = returned { self.unknown = true; errors.push(WebView2CleanupError { original: role, record: index, error }); }
            boundary.settlement_boundary();
        }
        if self.unknown { self.native.unknown = true; }
        if self.native.settled() { CloseOutcome::Settled } else { CloseOutcome::Unknown }
    }
}

// Native registry pointers remain pinned in the actual retained observation.
// This is the machine32 registration only; ordinary UI admission remains intact.
struct RegistryFrame {
    key: UnsafeCell<REG::HKEY>, name: Vec<u16>, value_name: Vec<u16>,
    bytes: UnsafeCell<[u8; 128]>, length: UnsafeCell<u32>, kind: UnsafeCell<u32>,
    entered: Cell<bool>, returned: Cell<Option<u32>>, key_state: Cell<SlotState>,
    _pin: PhantomPinned,
}
struct MachineObservation {
    paths: PathBook, registry: Held<RegistryFrame>, version: Option<Version>,
    first: Option<Error>, unknown: bool, inspected: bool, settled: bool,
}
impl MachineObservation {
    fn new() -> Self {
        Self { paths: PathBook::new(), registry: ManuallyDrop::new(Box::pin(RegistryFrame {
            key: UnsafeCell::new(null_mut()), name: wide(CLIENT), value_name: wide("pv"),
            bytes: UnsafeCell::new([0; 128]), length: UnsafeCell::new(128), kind: UnsafeCell::new(u32::MAX),
            entered: Cell::new(false), returned: Cell::new(None), key_state: Cell::new(SlotState::Reserved), _pin: PhantomPinned,
        })), version: None, first: None, unknown: false, inspected: false, settled: false }
    }
    fn latch(&mut self, error: Error) {
        if self.first.is_none() { self.first = Some(error); }
        self.unknown |= error == Error::Unknown || self.paths.unknown;
    }
    fn before(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        let returned = if self.unknown { Err(Error::Unknown) } else if self.first.is_some() || self.settled { Err(Error::State) }
            else { boundary.producing_boundary() };
        if let Err(error) = returned { self.latch(error); } returned
    }
    fn after<T>(&mut self, boundary: &dyn InstallerBoundary, returned: Result<T>) -> Result<T> {
        let returned = match returned { Err(first) => Err(first), Ok(value) => boundary.producing_boundary().map(|()| value) };
        if let Err(error) = returned.as_ref() { self.latch(*error); } returned
    }
    fn open_registry(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        self.before(boundary)?;
        let frame = self.registry.as_ref().get_ref();
        need(frame.key_state.get() == SlotState::Reserved)?;
        frame.key_state.set(SlotState::Acquiring); frame.entered.set(true); frame.returned.set(None);
        let status = unsafe { REG::RegOpenKeyExW(REG::HKEY_LOCAL_MACHINE, frame.name.as_ptr(), 0,
            REG::KEY_QUERY_VALUE | REG::KEY_WOW64_32KEY, frame.key.get()) };
        frame.returned.set(Some(status));
        if status == F::ERROR_IO_PENDING { return self.after(boundary, Err(Error::Unknown)); }
        let handle = unsafe { *frame.key.get() };
        let returned = if (status == F::ERROR_SUCCESS) == handle.is_null() {
            frame.key_state.set(SlotState::Unknown); Err(Error::Unknown)
        } else if status == F::ERROR_SUCCESS { frame.key_state.set(SlotState::Owned); Ok(()) }
        else if handle.is_null() {
            frame.key_state.set(SlotState::NoHandle);
            if matches!(status, F::ERROR_FILE_NOT_FOUND | F::ERROR_PATH_NOT_FOUND) { Ok(()) } else { Err(Error::Unavailable) }
        } else { frame.key_state.set(SlotState::Unknown); Err(Error::Unknown) };
        self.after(boundary, returned)
    }
    fn query(&mut self, boundary: &dyn InstallerBoundary) -> Result<Option<Version>> {
        self.before(boundary)?;
        let frame = self.registry.as_ref().get_ref();
        if frame.key_state.get() == SlotState::NoHandle { return Ok(None); }
        need(frame.key_state.get() == SlotState::Owned && frame.returned.get().is_some())?;
        unsafe { *frame.length.get() = 128; *frame.kind.get() = u32::MAX; *frame.bytes.get() = [0; 128]; }
        frame.returned.set(None);
        let status = unsafe { REG::RegQueryValueExW(*frame.key.get(), frame.value_name.as_ptr(), null(),
            frame.kind.get(), frame.bytes.get().cast(), frame.length.get()) };
        frame.returned.set(Some(status));
        let returned = if status == F::ERROR_IO_PENDING { Err(Error::Unknown) }
        else if status == F::ERROR_FILE_NOT_FOUND { Ok(None) }
        else if status == F::ERROR_MORE_DATA { Err(Error::Bounds) }
        else if status != F::ERROR_SUCCESS { Err(Error::Unavailable) }
        else { self.decode_registry() };
        self.after(boundary, returned)
    }
    fn decode_registry(&self) -> Result<Option<Version>> {
        let frame = self.registry.as_ref().get_ref();
        let (length, kind) = unsafe { (*frame.length.get() as usize, *frame.kind.get()) };
        let bytes = unsafe { &*frame.bytes.get() };
        registry_version(kind, length, bytes)
    }
    fn inspect(&mut self, boundary: &dyn InstallerBoundary) -> Result<bool> {
        need(!self.inspected)?; self.inspected = true;
        self.open_registry(boundary)?;
        self.version = self.query(boundary)?;
        let mut parent = self.paths.root(boundary, LocationKind::ProgramFilesX86)?;
        let Some(version) = self.version.clone() else { return Ok(false); };
        // Old registration is not permission to repair an arbitrary old pathname.
        // It must satisfy exactly the same protected image proof before upgrade.
        for component in ["Microsoft", "EdgeWebView", "Application", version.text.as_str()] {
            parent = self.paths.child(boundary, parent, component, FileKind::Directory,
                AuthorityScope::ImmutableVersion, false, false)?;
        }
        self.paths.child(boundary, parent, "msedgewebview2.exe", FileKind::File,
            AuthorityScope::ImmutableVersion, true, false)?;
        self.paths.recheck_location(boundary)?;
        for index in 0..self.paths.nodes.len() { self.paths.recheck(boundary, index)?; }
        need(self.query(boundary)? == self.version)?;
        Ok(version.supported())
    }
    fn settle(&mut self, boundary: &dyn InstallerBoundary, after: bool, errors: &mut Vec<WebView2CleanupError>) -> CloseOutcome {
        if self.settled { return if !self.unknown && self.paths.native.settled() { CloseOutcome::Settled } else { CloseOutcome::Unknown }; }
        self.settled = true;
        let frame = self.registry.as_ref().get_ref();
        if frame.key_state.get() == SlotState::Owned && frame.returned.get().is_some_and(|v| v != F::ERROR_IO_PENDING) {
            boundary.settlement_boundary(); frame.key_state.set(SlotState::Closing); frame.returned.set(None);
            let status = unsafe { REG::RegCloseKey(*frame.key.get()) };
            frame.returned.set(Some(status));
            if status == F::ERROR_SUCCESS { frame.key_state.set(SlotState::Closed); }
            else {
                frame.key_state.set(SlotState::Unknown); self.unknown = true;
                errors.push(WebView2CleanupError { original: if after { WebView2Original::RegistryAfter } else { WebView2Original::RegistryBefore }, record: 0, error: Error::Unknown });
            }
            boundary.settlement_boundary();
        } else if frame.key_state.get() == SlotState::Reserved && !frame.entered.get() {
            frame.key_state.set(SlotState::NoHandle);
        }
        if !matches!(frame.key_state.get(), SlotState::NoHandle | SlotState::Closed) { self.unknown = true; }
        let role = if after { WebView2Original::MachineAfter } else { WebView2Original::MachineBefore };
        if self.paths.settle(boundary, role, errors) == CloseOutcome::Unknown { self.unknown = true; }
        if self.unknown { CloseOutcome::Unknown } else { CloseOutcome::Settled }
    }
}

#[derive(Clone, Copy)]
enum VendorOp { Job, Limits, Create, Noninherit(WebView2Original), Assign, Resume, Wait, Exit,
    Count, Pause, FreeSpace, TerminateJob, TerminateChild, Close(WebView2Original) }
struct Launch {
    application: Vec<u16>, command: UnsafeCell<Vec<u16>>, environment: Vec<u16>, directory: Vec<u16>,
    startup: UnsafeCell<T::STARTUPINFOW>, process: UnsafeCell<T::PROCESS_INFORMATION>,
    job: UnsafeCell<F::HANDLE>, job_state: Cell<SlotState>, process_state: Cell<SlotState>, thread_state: Cell<SlotState>,
    _pin: PhantomPinned,
}
struct VendorFrame {
    operation: VendorOp, handle: F::HANDLE, peer: F::HANDLE, path: Vec<u16>,
    limits: UnsafeCell<J::JOBOBJECT_EXTENDED_LIMIT_INFORMATION>,
    accounting: UnsafeCell<J::JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>,
    count: UnsafeCell<u32>, scalar: UnsafeCell<u32>, available: UnsafeCell<u64>, total: UnsafeCell<u64>, free: UnsafeCell<u64>,
    entered: Cell<bool>, returned: Cell<Option<Returned>>, _pin: PhantomPinned,
}
#[derive(Default)]
struct VendorValue { scalar: u32, available: u64 }
struct VendorProcess {
    launch: Option<Held<Launch>>, active: Option<Held<VendorFrame>>, uncertain_closes: Vec<Held<VendorFrame>>,
    first: Option<Error>, unknown: bool,
    create_entered: bool, assigned: bool, resume_entered: bool, signalled: bool, exit_zero: bool, empty: bool,
    exit_code: Option<u32>,
    terminate_entered: bool, settled: bool,
}
impl VendorProcess {
    fn new() -> Self {
        Self { launch: None, active: None, uncertain_closes: Vec::with_capacity(3), first: None, unknown: false, create_entered: false,
            assigned: false, resume_entered: false, signalled: false, exit_zero: false, empty: false,
            exit_code: None,
            terminate_entered: false, settled: false }
    }
    fn configure(&mut self, application: &str, support: &str, windows: &str, system: &str) -> Result<()> {
        need(self.launch.is_none() && !self.create_entered && !self.settled)?;
        for path in [application, support, windows, system] {
            let (_, components) = decode::dos_location(path)?;
            need(!components.is_empty() && !path.contains('"') && path.encode_utf16().count() < NAME_UNITS)?;
        }
        // All input vectors belong to the original pinned launch BEFORE any call.
        // This is a fixed clean environment, not an ambient-environment filter.
        let environment = clean_environment(system, windows, support)?;
        let mut startup = T::STARTUPINFOW::default(); startup.cb = size_of::<T::STARTUPINFOW>() as u32;
        self.launch = Some(ManuallyDrop::new(Box::pin(Launch {
            application: wide(application), command: UnsafeCell::new(wide(&format!("\"{application}\" /silent /install"))),
            environment, directory: wide(support), startup: UnsafeCell::new(startup),
            process: UnsafeCell::new(T::PROCESS_INFORMATION::default()), job: UnsafeCell::new(null_mut()),
            job_state: Cell::new(SlotState::Reserved), process_state: Cell::new(SlotState::Reserved), thread_state: Cell::new(SlotState::Reserved),
            _pin: PhantomPinned,
        }))); Ok(())
    }
    fn latch(&mut self, error: Error) {
        if self.first.is_none() { self.first = Some(error); }
        self.unknown |= error == Error::Unknown || self.active.is_some();
    }
    fn original(&self, role: WebView2Original) -> Result<(&Cell<SlotState>, F::HANDLE)> {
        let launch = self.launch.as_ref().ok_or(Error::State)?.as_ref().get_ref();
        // The pointer values are DATA here; only an Owned state permits use.
        let (state, handle) = unsafe { match role {
            WebView2Original::Job => (&launch.job_state, *launch.job.get()),
            WebView2Original::Process => (&launch.process_state, (*launch.process.get()).hProcess),
            WebView2Original::Thread => (&launch.thread_state, (*launch.process.get()).hThread),
            _ => return Err(Error::State),
        }};
        Ok((state, handle))
    }
    fn handle(&self, role: WebView2Original) -> Result<F::HANDLE> {
        let (state, handle) = self.original(role)?;
        need(state.get() == SlotState::Owned && valid_handle(handle))?; Ok(handle)
    }
    fn native(&mut self, operation: VendorOp, path: &str) -> Result<VendorValue> {
        if self.active.is_some() || self.unknown && !matches!(operation, VendorOp::Close(_)) { return Err(Error::Unknown); }
        let (handle, peer) = match operation {
            VendorOp::Limits | VendorOp::Count | VendorOp::TerminateJob => (self.handle(WebView2Original::Job)?, null_mut()),
            VendorOp::Assign => (self.handle(WebView2Original::Job)?, self.handle(WebView2Original::Process)?),
            VendorOp::Resume => (self.handle(WebView2Original::Thread)?, null_mut()),
            VendorOp::Wait | VendorOp::Exit | VendorOp::TerminateChild => (self.handle(WebView2Original::Process)?, null_mut()),
            VendorOp::Noninherit(role) | VendorOp::Close(role) => (self.handle(role)?, null_mut()),
            _ => (null_mut(), null_mut()),
        };
        match operation {
            VendorOp::Job => need(self.original(WebView2Original::Job)?.0.get() == SlotState::Reserved)?,
            VendorOp::Create => need(!self.create_entered && !self.assigned && !self.resume_entered)?,
            VendorOp::Assign => need(self.create_entered && !self.assigned && !self.resume_entered)?,
            VendorOp::Resume => need(self.assigned && !self.resume_entered)?,
            VendorOp::Exit => need(self.signalled)?,
            VendorOp::TerminateJob | VendorOp::TerminateChild => need(!self.terminate_entered)?,
            _ => (),
        }
        let mut limits = J::JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = J::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | J::JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = OWNED_PROCESSES;
        self.active = Some(ManuallyDrop::new(Box::pin(VendorFrame {
            operation, handle, peer, path: if path.is_empty() { Vec::new() } else { wide(path) },
            limits: UnsafeCell::new(limits), accounting: UnsafeCell::new(J::JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default()),
            count: UnsafeCell::new(u32::MAX), scalar: UnsafeCell::new(u32::MAX),
            available: UnsafeCell::new(u64::MAX), total: UnsafeCell::new(u64::MAX), free: UnsafeCell::new(u64::MAX),
            entered: Cell::new(false), returned: Cell::new(None), _pin: PhantomPinned,
        })));
        let frame = self.active.as_ref().ok_or(Error::Unknown)?.as_ref().get_ref();
        let launch = self.launch.as_ref().ok_or(Error::State)?.as_ref().get_ref();
        match operation {
            VendorOp::Job => launch.job_state.set(SlotState::Acquiring),
            VendorOp::Create => {
                self.create_entered = true;
                launch.process_state.set(SlotState::Acquiring); launch.thread_state.set(SlotState::Acquiring);
            },
            VendorOp::Resume => self.resume_entered = true,
            VendorOp::TerminateJob | VendorOp::TerminateChild => self.terminate_entered = true,
            VendorOp::Close(role) => self.original(role)?.0.set(SlotState::Closing),
            _ => (),
        }
        frame.entered.set(true);
        // SAFETY: original owner registered pinned frames/output cells first;
        // no borrowed buffers, asynchronous flags, inherited handles or callback.
        let returned = unsafe { match frame.operation {
            VendorOp::Job => {
                *launch.job.get() = J::CreateJobObjectW(null(), null());
                let handle = *launch.job.get();
                if valid_handle(handle) { Returned::Boolean(1, 0) } else { Returned::Boolean(0, F::GetLastError()) }
            },
            VendorOp::Limits => boolean(J::SetInformationJobObject(frame.handle, J::JobObjectExtendedLimitInformation,
                frame.limits.get().cast(), size_of::<J::JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32)),
            VendorOp::Create => boolean(T::CreateProcessW(launch.application.as_ptr(), (*launch.command.get()).as_mut_ptr(),
                null(), null(), 0, T::CREATE_SUSPENDED | T::CREATE_UNICODE_ENVIRONMENT | T::CREATE_NO_WINDOW,
                launch.environment.as_ptr().cast(), launch.directory.as_ptr(), launch.startup.get(), launch.process.get())),
            VendorOp::Noninherit(_) => boolean(F::GetHandleInformation(frame.handle, frame.scalar.get())),
            VendorOp::Assign => boolean(J::AssignProcessToJobObject(frame.handle, frame.peer)),
            VendorOp::Resume => {
                let count = T::ResumeThread(frame.handle);
                if count == u32::MAX { Returned::Boolean(0, F::GetLastError()) } else { Returned::Scalar(count) }
            },
            VendorOp::Wait => {
                let value = T::WaitForSingleObject(frame.handle, WAIT_MS);
                if value == F::WAIT_FAILED { Returned::Boolean(0, F::GetLastError()) } else { Returned::Scalar(value) }
            },
            VendorOp::Exit => boolean(T::GetExitCodeProcess(frame.handle, frame.scalar.get())),
            VendorOp::Count => boolean(J::QueryInformationJobObject(frame.handle, J::JobObjectBasicAccountingInformation,
                frame.accounting.get().cast(), size_of::<J::JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32, frame.count.get())),
            VendorOp::Pause => { T::Sleep(WAIT_MS); Returned::Boolean(1, 0) },
            VendorOp::FreeSpace => boolean(FS::GetDiskFreeSpaceExW(frame.path.as_ptr(), frame.available.get(), frame.total.get(), frame.free.get())),
            VendorOp::TerminateJob => boolean(J::TerminateJobObject(frame.handle, 0xc0000120)),
            VendorOp::TerminateChild => boolean(T::TerminateProcess(frame.handle, 0xc0000120)),
            VendorOp::Close(_) => boolean(F::CloseHandle(frame.handle)),
        }};
        frame.returned.set(Some(returned)); // FIRST work after native return.
        let observed = self.classify(operation, returned);
        if matches!(observed, Err(Error::Unknown)) && matches!(operation, VendorOp::Close(_))
            && matches!(returned, Returned::Boolean(0, code) if code != F::ERROR_IO_PENDING) {
            // A synchronous failed consuming close is not an active native writer.
            // Keep its actual original/frame and absorbing Unknown, but permit
            // once-close of other already-proved-independent originals. Never
            // retry the failed HANDLE, or turn this into a producing exception.
            if self.uncertain_closes.len() < 3 {
                self.uncertain_closes.push(self.active.take().ok_or(Error::Unknown)?);
            }
        } else if !matches!(observed, Err(Error::Unknown)) {
            // Every native call is definitely returned and output has been copied
            // to the same owner before consuming its temporary buffer allocation.
            let held = self.active.take().ok_or(Error::Unknown)?;
            drop(ManuallyDrop::into_inner(held));
        }
        if let Err(error) = observed.as_ref() { self.latch(*error); }
        observed
    }
    fn classify(&mut self, operation: VendorOp, returned: Returned) -> Result<VendorValue> {
        let frame = self.active.as_ref().ok_or(Error::Unknown)?.as_ref().get_ref();
        let launch = self.launch.as_ref().ok_or(Error::Unknown)?.as_ref().get_ref();
        let ok = match returned {
            Returned::Boolean(0, F::ERROR_IO_PENDING) => return Err(Error::Unknown),
            Returned::Boolean(value, _) => value != 0,
            Returned::Scalar(_) => true,
            _ => return Err(Error::Unknown),
        };
        match operation {
            VendorOp::Job => {
                let handle = unsafe { *launch.job.get() };
                if ok && valid_handle(handle) { launch.job_state.set(SlotState::Owned); }
                else if !ok && handle.is_null() { launch.job_state.set(SlotState::NoHandle); }
                else { launch.job_state.set(SlotState::Unknown); return Err(Error::Unknown); }
            },
            VendorOp::Create => {
                let p = unsafe { &*launch.process.get() };
                if ok && valid_handle(p.hProcess) && valid_handle(p.hThread) && p.hProcess != p.hThread
                    && p.hProcess != unsafe { *launch.job.get() } && p.hThread != unsafe { *launch.job.get() }
                    && p.dwProcessId != 0 && p.dwThreadId != 0 {
                    launch.process_state.set(SlotState::Owned); launch.thread_state.set(SlotState::Owned);
                } else if !ok && p.hProcess.is_null() && p.hThread.is_null() && p.dwProcessId == 0 && p.dwThreadId == 0 {
                    launch.process_state.set(SlotState::NoHandle); launch.thread_state.set(SlotState::NoHandle);
                } else {
                    launch.process_state.set(SlotState::Unknown); launch.thread_state.set(SlotState::Unknown);
                    return Err(Error::Unknown);
                }
            },
            VendorOp::Close(role) => {
                self.original(role)?.0.set(if ok { SlotState::Closed } else { SlotState::Unknown });
                if !ok { return Err(Error::Unknown); }
            },
            _ => (),
        }
        if !ok { return Err(Error::Unavailable); }
        let mut value = VendorValue::default();
        match operation {
            VendorOp::Noninherit(_) => need(unsafe { *frame.scalar.get() } == 0)?,
            VendorOp::Assign => self.assigned = true,
            VendorOp::Resume => need(matches!(returned, Returned::Scalar(1)))?,
            VendorOp::Wait => match returned {
                Returned::Scalar(F::WAIT_OBJECT_0) => { self.signalled = true; value.scalar = 1; },
                Returned::Scalar(F::WAIT_TIMEOUT) => (),
                _ => return Err(Error::Unknown),
            },
            VendorOp::Exit => {
                let code = unsafe { *frame.scalar.get() };
                self.exit_code = Some(code);
                self.exit_zero = self.signalled && code == 0;
                // This actual observed nonzero result wins before a later STOP.
                completed_exit(self.signalled, code)?;
            },
            VendorOp::Count => {
                let accounting = unsafe { &*frame.accounting.get() };
                let empty = owned_job_empty(unsafe { *frame.count.get() }, accounting.TotalProcesses,
                    accounting.ActiveProcesses, self.assigned)?;
                value.scalar = accounting.ActiveProcesses;
                self.empty = empty;
            },
            VendorOp::FreeSpace => {
                let (available, free, total) = unsafe { (*frame.available.get(), *frame.free.get(), *frame.total.get()) };
                // Total is caller-quota-aware, while Free is volume-wide. A
                // legitimate quota can make Free > Total; only Available must
                // fit both. Neither a quota nor global free space grants headroom.
                need(available <= free && available <= total && free != u64::MAX && total != u64::MAX)?;
                value.available = available;
            },
            _ => (),
        }
        Ok(value)
    }
    fn produce(&mut self, boundary: &dyn InstallerBoundary, operation: VendorOp, path: &str) -> Result<VendorValue> {
        if self.first.is_some() || self.settled { return Err(Error::State); }
        if let Err(error) = boundary.producing_boundary() { self.latch(error); return Err(error); }
        let returned = self.native(operation, path);
        let returned = match returned { Err(first) => Err(first), Ok(value) => boundary.producing_boundary().map(|()| value) };
        if let Err(error) = returned.as_ref() { self.latch(*error); } returned
    }
    fn settlement(&mut self, boundary: &dyn InstallerBoundary, operation: VendorOp,
        role: WebView2Original, errors: &mut Vec<WebView2CleanupError>) -> Result<VendorValue> {
        boundary.settlement_boundary();
        let returned = self.native(operation, "");
        if let Err(error) = returned.as_ref() { errors.push(WebView2CleanupError { original: role, record: 0, error: *error }); }
        boundary.settlement_boundary(); returned
    }
    fn launch_and_wait(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        self.produce(boundary, VendorOp::Job, "")?;
        self.produce(boundary, VendorOp::Noninherit(WebView2Original::Job), "")?;
        self.produce(boundary, VendorOp::Limits, "")?;
        self.produce(boundary, VendorOp::Create, "")?;
        self.produce(boundary, VendorOp::Noninherit(WebView2Original::Process), "")?;
        self.produce(boundary, VendorOp::Noninherit(WebView2Original::Thread), "")?;
        self.produce(boundary, VendorOp::Assign, "")?;
        self.produce(boundary, VendorOp::Resume, "")?;
        for _ in 0..WAIT_SLICES {
            if !self.signalled { self.produce(boundary, VendorOp::Wait, "")?; }
            if self.signalled { break; }
        }
        need(self.signalled)?;
        self.produce(boundary, VendorOp::Exit, "")?;
        for _ in 0..WAIT_SLICES {
            self.produce(boundary, VendorOp::Count, "")?;
            if self.empty { return Ok(()); }
            self.produce(boundary, VendorOp::Pause, "")?;
        }
        Err(Error::Bounds)
    }
    fn settle(&mut self, boundary: &dyn InstallerBoundary, errors: &mut Vec<WebView2CleanupError>) -> CloseOutcome {
        if self.settled { return if self.finality() { CloseOutcome::Settled } else { CloseOutcome::Unknown }; }
        self.settled = true;
        if self.launch.is_none() { return if self.finality() { CloseOutcome::Settled } else { CloseOutcome::Unknown }; }
        if self.active.is_some() || self.unknown { return CloseOutcome::Unknown; }
        let child_owned = self.original(WebView2Original::Process).is_ok_and(|(s, _)| s.get() == SlotState::Owned);
        let job_owned = self.original(WebView2Original::Job).is_ok_and(|(s, _)| s.get() == SlotState::Owned);
        if child_owned && (!self.signalled || self.assigned && !self.empty) {
            let operation = if self.assigned { VendorOp::TerminateJob } else { VendorOp::TerminateChild };
            let role = if self.assigned { WebView2Original::Job } else { WebView2Original::Process };
            // Exactly one termination attempt. A success is NOT completion.
            if self.settlement(boundary, operation, role, errors).is_err() { self.unknown = true; }
            if !self.unknown {
                for _ in 0..WAIT_SLICES {
                    if !self.signalled && self.settlement(boundary, VendorOp::Wait, WebView2Original::Process, errors).is_err() { self.unknown = true; break; }
                    if self.signalled { break; }
                }
                if !self.signalled { self.unknown = true; }
            }
        }
        if job_owned && !self.unknown {
            for _ in 0..WAIT_SLICES {
                if self.settlement(boundary, VendorOp::Count, WebView2Original::Job, errors).is_err() { self.unknown = true; break; }
                if self.empty { break; }
                if self.settlement(boundary, VendorOp::Pause, WebView2Original::Job, errors).is_err() { self.unknown = true; break; }
            }
            if !self.empty { self.unknown = true; }
        }
        if self.unknown || child_owned && !self.signalled || job_owned && !self.empty { return CloseOutcome::Unknown; }
        for role in [WebView2Original::Thread, WebView2Original::Process, WebView2Original::Job] {
            let state = match self.original(role) { Ok((state, _)) => state.get(), Err(_) => { self.unknown = true; continue; } };
            if state == SlotState::Reserved {
                if let Ok((state, _)) = self.original(role) { state.set(SlotState::NoHandle); }
            } else if state == SlotState::Owned && self.settlement(boundary, VendorOp::Close(role), role, errors).is_err() {
                self.unknown = true;
            } else if !matches!(state, SlotState::NoHandle | SlotState::Closed | SlotState::Owned) { self.unknown = true; }
        }
        if self.finality() { CloseOutcome::Settled } else { CloseOutcome::Unknown }
    }
    fn finality(&self) -> bool {
        self.settled && self.active.is_none() && self.uncertain_closes.is_empty() && !self.unknown && (self.launch.is_none()
            || [WebView2Original::Job, WebView2Original::Process, WebView2Original::Thread].iter()
                .all(|role| self.original(*role).is_ok_and(|(s, _)| matches!(s.get(), SlotState::Closed | SlotState::NoHandle))))
    }
}

impl PathBook {
    fn token_scalar(&mut self, boundary: &dyn InstallerBoundary, index: usize,
        class: S::TOKEN_INFORMATION_CLASS) -> Result<u32> {
        let value = path_call!(self, boundary, self.native.token(index, class));
        let trace = self.native.admission.at(O::TokenData);
        trace.need(value.count_in(trace)? == 4, C::ScalarWidth)?;
        decode::Observed::new(trace).u32_at(value.bytes_in(4, trace)?, 0)
    }
    fn policy_scalar(&mut self, boundary: &dyn InstallerBoundary, index: usize,
        class: S::TOKEN_INFORMATION_CLASS) -> Result<u32> {
        self.before(boundary)?;
        let mut no_creations = [];
        let entered = enter_registered_mutation(&mut self.native, &mut self.mutation, &mut no_creations,
            Effect::Scalar(class), Some(index), "", &[], Vec::new());
        if let Err(error) = entered { self.latch(error); return Err(error); }
        let returned = finish_registered_mutation(&mut self.native, &mut self.mutation, &mut no_creations, None)
            .and_then(|value| scalar_value(value.scalar()?));
        self.after(boundary, returned)
    }
    fn collect_installer(&mut self, boundary: &dyn InstallerBoundary, index: usize) -> Result<Installer> {
        path_call!(self, boundary, self.native.absent_thread_token());
        let before = path_call!(self, boundary, self.native.token(index, S::TokenStatistics));
        let trace = self.native.admission.at(O::TokenData);
        let initial = security::Observed::new(trace).statistics(before.bytes_in(before.count_in(trace)?, trace)?)?;
        let token_type = self.token_scalar(boundary, index, S::TokenType)?;
        let elevated = self.token_scalar(boundary, index, S::TokenElevation)?;
        let elevation_type = self.token_scalar(boundary, index, S::TokenElevationType)?;
        let ui_access = self.token_scalar(boundary, index, S::TokenUIAccess)?;
        let virtualization = self.token_scalar(boundary, index, S::TokenVirtualizationEnabled)?;
        let restricted = self.policy_scalar(boundary, index, S::TokenHasRestrictions)?;
        let app_container = self.policy_scalar(boundary, index, S::TokenIsAppContainer)?;
        let user = path_call!(self, boundary, self.native.token(index, S::TokenUser));
        let integrity = path_call!(self, boundary, self.native.token(index, S::TokenIntegrityLevel));
        let groups = path_call!(self, boundary, self.native.token(index, S::TokenGroups));
        let privileges = path_call!(self, boundary, self.native.token(index, S::TokenPrivileges));
        let trace = self.native.admission.at(O::InstallerPolicy).role(R::Installer);
        let data = self.native.admission.at(O::TokenData);
        let u = data.role(R::User); let i = data.role(R::Integrity); let g = data.role(R::Groups); let p = data.role(R::Privileges);
        let result = InstallerData(trace).installer_facts(initial, token_type, elevated, elevation_type,
            ui_access, virtualization, restricted, app_container,
            user.bytes_in(user.count_in(u)?, u)?, integrity.bytes_in(integrity.count_in(i)?, i)?,
            groups.bytes_in(groups.count_in(g)?, g)?, privileges.bytes_in(privileges.count_in(p)?, p)?)?;
        let after = path_call!(self, boundary, self.native.token(index, S::TokenStatistics));
        let trace = self.native.admission.at(O::TokenData);
        need(security::Observed::new(trace).statistics(after.bytes_in(after.count_in(trace)?, trace)?)? == initial)?;
        path_call!(self, boundary, self.native.absent_thread_token()); Ok(result)
    }
    fn open_token(&mut self, boundary: &dyn InstallerBoundary) -> Result<usize> {
        let key = path_call!(self, boundary, self.native.reserve(Kind::ProcessToken, None, "", String::new()));
        let returned = path_call!(self, boundary, self.native.call(Call::ProcessToken(key.index), null_mut(), Vec::new()));
        need(matches!(returned.arena.returned()?, Returned::Boolean(v, 0) if v != 0))?;
        path_call!(self, boundary, self.native.noninherited(key.index)); Ok(key.index)
    }
    fn admit_installer(&mut self, boundary: &dyn InstallerBoundary, expected: &Installer) -> Result<()> {
        need(self.native.process_token.is_none())?;
        let arch = path_call!(self, boundary, self.native.call(Call::Architecture, null_mut(), Vec::new()));
        let trace = self.native.admission.at(O::Architecture); let d = decode::Observed::new(trace);
        need(d.u16_at(arch.bytes_in(4, trace)?, 0)? == SI::IMAGE_FILE_MACHINE_UNKNOWN
            && d.u16_at(arch.bytes_in(4, trace)?, 2)? == SI::IMAGE_FILE_MACHINE_AMD64)?;
        let token = self.open_token(boundary)?; self.native.process_token = Some(token);
        need(self.collect_installer(boundary, token)? == *expected)
    }
    fn recheck_installer(&mut self, boundary: &dyn InstallerBoundary, expected: &Installer) -> Result<()> {
        let token = self.native.process_token.ok_or(Error::State)?;
        need(self.collect_installer(boundary, token)? == *expected)?;
        let current = self.open_token(boundary)?;
        need(self.collect_installer(boundary, current)? == *expected)?;
        self.close_producing(boundary, current)?;
        path_call!(self, boundary, self.native.absent_thread_token()); Ok(())
    }
}

struct RetainedAncestor { path: String, facts: Facts, scope: AuthorityScope }
struct Expected {
    source: Arc<()>, output: Arc<()>, installer: Installer,
    location: (String, String, Vec<String>), digest: String, image: String, helper: String,
    relative: String, size: u64, file: Facts, ancestors: Vec<RetainedAncestor>, hash: [u8; 32],
}
impl Expected {
    fn from_original(binding: PrerequisiteBinding<'_>, hash: [u8; 32]) -> Result<Self> {
        need(binding.row49_relative == format!("installer-input/{}/{}/prerequisites/{INSTALLER}",
            super::installer_input_data::TARGET, binding.image)
            && binding.row49_size > 0 && binding.row49_size <= MAX_FILE_BYTES
            && binding.row49_facts.metadata.size == binding.row49_size
            && binding.row49_facts.metadata.kind == FileKind::File)?;
        exact_security(&binding.row49_facts.security, FileKind::File, true, false)?;
        Ok(Self { source: Arc::clone(binding.source_identity), output: Arc::clone(binding.output_identity),
            installer: binding.installer.clone(), location: (binding.location.drive.clone(), binding.location.device.clone(), binding.location.components.clone()),
            digest: binding.digest.to_owned(), image: binding.image.to_owned(), helper: binding.helper.to_owned(),
            relative: binding.row49_relative.to_owned(), size: binding.row49_size, file: binding.row49_facts.clone(),
            ancestors: binding.ancestors.iter().map(|a| RetainedAncestor { path: a.path.to_owned(), facts: a.facts.clone(), scope: a.scope }).collect(), hash })
    }
    fn matches(&self, binding: &PrerequisiteBinding<'_>) -> Result<()> {
        need(Arc::ptr_eq(&self.source, binding.source_identity) && Arc::ptr_eq(&self.output, binding.output_identity)
            && self.installer == *binding.installer && self.digest == binding.digest && self.image == binding.image
            && self.helper == binding.helper && self.relative == binding.row49_relative && self.size == binding.row49_size
            && self.file == *binding.row49_facts && self.ancestors.len() == binding.ancestors.len()
            && self.location == (binding.location.drive.clone(), binding.location.device.clone(), binding.location.components.clone()))?;
        for (actual, retained) in binding.ancestors.iter().zip(&self.ancestors) {
            need(retained.path == actual.path && retained.facts == *actual.facts && retained.scope == actual.scope)?;
        }
        Ok(())
    }
}

/// Actual non-cloneable owner. Native construction is inert; the fixed application
/// takes expected row49 SHA256 only from its retained compiled ExpectedInputData.
/// No renderer/CLI path, executable, argument, registry or account selector exists.
pub struct OfflineWebView2Owner {
    expected: Expected, input: PathBook, system: PathBook, support: PathBook,
    before_machine: MachineObservation, after_machine: MachineObservation, process: VendorProcess,
    input_hash: Option<Sha256>, input_index: Option<usize>, input_hashed: bool,
    support_index: Option<usize>, creation: Vec<Creation>, first: Option<Error>, unknown: bool,
    started: bool, settlement_attempted: bool, complete: Option<OfflineWebView2Mode>,
    cleanup: Vec<WebView2CleanupError>, output: WebView2SupportOutput,
}
// SAFETY: serialized move before native entry, then the actual process-lifetime
// owner/Mutex retains all pinned originals. No raw reference/HANDLE escapes and
// no thread token or privilege loan is transferred. This object is not Sync.
unsafe impl Send for OfflineWebView2Owner {}
impl OfflineWebView2Owner {
    pub fn for_acquisition(acquisition: &InputAcquisition, expected_row49_sha256: [u8; 32]) -> Result<Self> {
        let binding = acquisition.prerequisite_binding()?;
        Ok(Self { expected: Expected::from_original(binding, expected_row49_sha256)?,
            input: PathBook::new(), system: PathBook::new(), support: PathBook::new(),
            before_machine: MachineObservation::new(), after_machine: MachineObservation::new(), process: VendorProcess::new(),
            input_hash: Some(Sha256::new()), input_index: None, input_hashed: false,
            support_index: None, creation: Vec::new(), first: None, unknown: false, started: false,
            settlement_attempted: false, complete: None, cleanup: Vec::with_capacity(256), output: WebView2SupportOutput::default() })
    }
    fn latch(&mut self, error: Error) {
        if self.first.is_none() { self.first = Some(error); }
        self.unknown |= error == Error::Unknown || self.input.unknown || self.system.unknown || self.support.unknown
            || self.before_machine.unknown || self.after_machine.unknown || self.process.unknown;
    }
    fn before(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        let returned = if self.unknown { Err(Error::Unknown) } else if self.first.is_some() || self.settlement_attempted { Err(Error::State) }
            else { boundary.producing_boundary() };
        if let Err(error) = returned { self.latch(error); } returned
    }
    fn admit_input(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        self.input.admit_installer(boundary, &self.expected.installer)?;
        let mut parent = self.input.root(boundary, LocationKind::ProgramFiles)?;
        let location = self.input.location.as_ref().ok_or(Error::State)?;
        need((location.drive.clone(), location.device.clone(), location.components.clone()) == self.expected.location)?;
        for ancestor in &self.expected.ancestors {
            let name = ancestor.path.rsplit('\\').next().ok_or(Error::State)?;
            parent = self.input.child(boundary, parent, name, FileKind::Directory, ancestor.scope, false, false)?;
            need(self.input.nodes[parent].path == ancestor.path && self.input.nodes[parent].facts == ancestor.facts)?;
        }
        let file = self.input.child(boundary, parent, INSTALLER, FileKind::File, AuthorityScope::ImmutableVersion, false, false)?;
        need(self.input.nodes[file].facts == self.expected.file)?;
        self.input_index = Some(file);
        let key = self.input.key(self.input.nodes[file].slot);
        let mut read = 0u64;
        loop {
            self.before(boundary)?;
            let returned = self.input.native.read_next(&key, BUFFER);
            let bytes = match returned { Err(first) => return Err(first), Ok(bytes) => bytes };
            // Retain actual hash/byte progress before a later STOP observation.
            if bytes.is_empty() { need(read == self.expected.size)?; break; }
            read = read.checked_add(bytes.len() as u64).ok_or(Error::Bounds)?;
            need(read <= self.expected.size)?;
            self.input_hash.as_mut().ok_or(Error::State)?.update(&bytes);
            self.before(boundary)?;
        }
        let digest: [u8; 32] = self.input_hash.take().ok_or(Error::State)?.finalize().into();
        need(digest == self.expected.hash)?; self.input_hashed = true;
        self.input.recheck(boundary, file)?;
        self.input.recheck_installer(boundary, &self.expected.installer)
    }
    fn prepare_support(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        let windows = self.support.root(boundary, LocationKind::Windows)?;
        let system = self.system.root(boundary, LocationKind::System)?;
        let support_drive = {
            let windows_location = self.support.location.as_ref().ok_or(Error::State)?;
            let system_location = self.system.location.as_ref().ok_or(Error::State)?;
            need(windows_location.drive == system_location.drive && windows_location.device == system_location.device
                && system_location.components.len() == windows_location.components.len() + 1
                && system_location.components.starts_with(&windows_location.components)
                && system_location.components.last().is_some_and(|part| part.eq_ignore_ascii_case("System32")))?;
            format!("{}\\", windows_location.drive)
        };
        self.before(boundary)?;
        let pid = unsafe { T::GetCurrentProcessId() }; // locator only, never process ownership
        need(pid != 0)?;
        self.before(boundary)?;
        let name = format!("MRK-WebView2-{}-{pid}", self.expected.image);
        let path = format!("{}\\{name}", self.support.nodes[windows].path);
        let rows = self.support.entries(boundary, windows, Some(&name))?;
        need(selected_entry(&rows, &name)?.is_none())?; // collision never adopted
        let application = self.input.nodes[self.input_index.ok_or(Error::State)?].path.clone();
        self.process.configure(&application, &path, &self.support.nodes[windows].path, &self.system.nodes[system].path)?;
        // Both the support and installation volumes get their own available-to-
        // this-caller observation. This is headroom, not a quota on vendor services.
        self.system.before(boundary)?;
        let returned = self.system.native.location(LocationKind::ProgramFilesX86);
        let machine_location = self.system.after(boundary, returned)?;
        let previous = self.before_machine.paths.location.as_ref().ok_or(Error::State)?;
        need(machine_location.drive == previous.drive && machine_location.device == previous.device
            && machine_location.components == previous.components)?;
        let machine_drive = format!("{}\\", machine_location.drive);
        need(self.process.produce(boundary, VendorOp::FreeSpace, &support_drive)?.available >= FREE_BYTES)?;
        if machine_drive != support_drive {
            need(self.process.produce(boundary, VendorOp::FreeSpace, &machine_drive)?.available >= FREE_BYTES)?;
        }
        self.input.recheck_installer(boundary, &self.expected.installer)?;
        self.support.recheck_location(boundary)?; self.support.recheck(boundary, windows)?;
        let descriptor = descriptor(FileKind::Directory, false, false)?;
        self.creation.push(Creation { path: path.clone(), parent: windows, entered: false, returned: None });
        self.before(boundary)?;
        let entered = enter_registered_mutation(&mut self.support.native, &mut self.support.mutation, &mut self.creation,
            Effect::Directory(0), None, &path, &descriptor, Vec::new());
        if let Err(error) = entered { self.latch(error); return Err(error); }
        let returned = finish_registered_mutation(&mut self.support.native, &mut self.support.mutation, &mut self.creation, None);
        // Record possible/known persisted output before any later boundary.
        self.output.created = self.creation[0].returned.is_some_and(|(value, _)| value != 0);
        self.output.retained = self.output.created || self.creation[0].returned.is_none()
            || matches!(returned, Err(Error::Unknown));
        // Only genuine synchronous creation success grants the known retained
        // disposition. A possible/contradictory result stays explicitly uncertain.
        // Zero census counts never certify that this directory is empty/absent.
        self.output.disposition = if self.output.created && returned.is_ok() {
            WebView2SupportDisposition::RetainedBeforeVendor
        } else if self.output.retained { WebView2SupportDisposition::CreationUncertain }
        else { WebView2SupportDisposition::NoOwnedOutputRecorded };
        match returned { Ok(_) => (), Err(first) => return Err(first) }
        self.before(boundary)?;
        let parent_facts = self.support.nodes[windows].facts.clone();
        let current = self.support.checked(boundary, self.support.nodes[windows].slot, AuthorityScope::AncestorOutsideVersion, false)?;
        need(child_transition(&parent_facts.metadata, &current.metadata) && parent_facts.security == current.security)?;
        self.support.nodes[windows].facts = current;
        // The actual exclusive creation authorizes this one open; an absent
        // pre-create cursor is never reinterpreted as an existing namespace row.
        let key = self.support.key(self.support.nodes[windows].slot);
        self.support.before(boundary)?;
        let returned = self.support.native.open_child(&key, &name, FileKind::Directory);
        let original = self.support.after(boundary, returned)?;
        let facts = self.support.checked(boundary, original.index, AuthorityScope::ImmutableVersion, false)?;
        exact_security(&facts.security, FileKind::Directory, false, false)?;
        let index = self.support.nodes.len();
        self.support.nodes.push(Node { slot: original.index, parent: Some(windows), path, facts,
            scope: AuthorityScope::ImmutableVersion, managed_image: false, os_ancestor: false, entries: None });
        self.support_index = Some(index); self.support.recheck(boundary, windows)?;
        self.input.recheck_installer(boundary, &self.expected.installer)
    }
    fn census(&mut self, boundary: &dyn InstallerBoundary, parent: usize, depth: usize) -> Result<()> {
        need(depth <= SUPPORT_DEPTH)?;
        let rows = self.support.entries(boundary, parent, None)?;
        for row in rows.iter().filter(|row| row.name != "." && row.name != "..") {
            self.output.entries = self.output.entries.checked_add(1).ok_or(Error::Bounds)?;
            if self.output.entries > SUPPORT_ENTRIES { self.output.over_budget = true; return Err(Error::Bounds); }
            let child = self.support.child(boundary, parent, &row.name, row.kind, AuthorityScope::ImmutableVersion, false, false)?;
            if row.kind == FileKind::Directory { self.census(boundary, child, depth + 1)?; }
            else {
                self.output.bytes = self.output.bytes.checked_add(self.support.nodes[child].facts.metadata.size).ok_or(Error::Bounds)?;
                if self.output.bytes > SUPPORT_BYTES { self.output.over_budget = true; return Err(Error::Bounds); }
            }
            self.support.recheck(boundary, child)?;
            self.support.close_producing(boundary, self.support.nodes[child].slot)?;
        }
        self.support.recheck(boundary, parent)
    }
    fn account_support(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        let index = self.support_index.ok_or(Error::State)?;
        let original = self.support.nodes[index].facts.clone();
        let current = self.support.checked(boundary, self.support.nodes[index].slot, AuthorityScope::ImmutableVersion, false)?;
        // This ONE actual exclusively-created vendor support root is permitted
        // to gain vendor children. It is not a general metadata-drift exception.
        need(same_object(&original.metadata, &current.metadata) && original.security == current.security)?;
        exact_security(&current.security, FileKind::Directory, false, false)?;
        self.support.nodes[index].facts = current;
        self.census(boundary, index, 0)?;
        self.support.recheck_location(boundary)?;
        // Complete means this bounded observation returned, NOT future updater
        // quiescence, a hard disk quota, or permission to recursively delete it.
        self.output.census_complete = true; Ok(())
    }
    fn run(&mut self, acquisition: &InputAcquisition, boundary: &dyn InstallerBoundary,
        route: PreparationRoute) -> Result<OfflineWebView2Mode> {
        self.before(boundary)?;
        self.expected.matches(&acquisition.prerequisite_binding()?)?;
        self.admit_input(boundary)?;
        let present = self.before_machine.inspect(boundary)?;
        if self.before_machine.settle(boundary, false, &mut self.cleanup) != CloseOutcome::Settled { return Err(Error::Unknown); }
        if present {
            self.input.recheck_installer(boundary, &self.expected.installer)?;
            for index in 0..self.input.nodes.len() { self.input.recheck(boundary, index)?; }
            return Ok(OfflineWebView2Mode::AlreadyPresent);
        }
        // Actual acquired input/hash/HKLM32/image observations above are shared
        // with installation. Existing-only refuses absent/old state HERE, before
        // even creating support output. Unsafe observations already returned Err.
        route.permit_install()?;
        self.prepare_support(boundary)?;
        self.input.recheck_after_vendor(boundary)?;
        self.system.recheck_after_vendor(boundary)?;
        self.input.recheck_installer(boundary, &self.expected.installer)?;
        self.process.launch_and_wait(boundary)?;
        need(self.process.signalled && self.process.exit_zero && self.process.empty)?;
        self.input.recheck_installer(boundary, &self.expected.installer)?;
        need(self.after_machine.inspect(boundary)?)?;
        self.input.recheck_after_vendor(boundary)?;
        self.system.recheck_after_vendor(boundary)?;
        self.account_support(boundary)?;
        self.expected.matches(&acquisition.prerequisite_binding()?)?;
        Ok(OfflineWebView2Mode::Installed)
    }
    pub fn prepare_once(&mut self, acquisition: &InputAcquisition, boundary: &dyn InstallerBoundary) -> Result<()> {
        self.prepare_with_route(acquisition, boundary, PreparationRoute::InstallIfNeeded)
    }
    /// Fixed nonshipping qualification route. Still needs this ACTUAL retained
    /// acquisition, full row49 hash and genuine protected machine-runtime proof.
    /// It never invokes the bundled file, including when that file is fixture DATA.
    #[cfg(feature = "qualification-result")]
    pub fn prepare_existing_once(&mut self, acquisition: &InputAcquisition, boundary: &dyn InstallerBoundary) -> Result<()> {
        self.prepare_with_route(acquisition, boundary, PreparationRoute::ExistingOnly)
    }
    fn prepare_with_route(&mut self, acquisition: &InputAcquisition, boundary: &dyn InstallerBoundary,
        route: PreparationRoute) -> Result<()> {
        // Shared once latch: neither entry can retry/fall back after the other
        // starts, even after a definite read-only Unavailable refusal.
        if self.started || self.settlement_attempted { return Err(Error::State); }
        self.started = true;
        let returned = self.run(acquisition, boundary, route);
        let mode = match returned { Ok(mode) => mode, Err(first) => { self.latch(first); return Err(first); } };
        if self.settle_originals(boundary) != CloseOutcome::Settled {
            self.latch(Error::Unknown); return Err(self.first.unwrap_or(Error::Unknown));
        }
        // Success is committed only after real original finality AND the same
        // producing guard's final after-check. STOP cleanup cannot grant success.
        if let Err(error) = boundary.producing_boundary() { self.latch(error); return Err(error); }
        let final_binding = acquisition.prerequisite_binding().and_then(|binding| self.expected.matches(&binding))
            .and_then(|()| need(self.input_hashed && self.cleanup.is_empty() && self.first.is_none()));
        if let Err(error) = final_binding { self.latch(error); return Err(error); }
        self.complete = Some(mode); Ok(())
    }
    fn settle_originals(&mut self, boundary: &dyn InstallerBoundary) -> CloseOutcome {
        if self.settlement_attempted { return if self.finality() { CloseOutcome::Settled } else { CloseOutcome::Unknown }; }
        self.settlement_attempted = true;
        if self.process.settle(boundary, &mut self.cleanup) != CloseOutcome::Settled { self.unknown = true; }
        if self.after_machine.settle(boundary, true, &mut self.cleanup) != CloseOutcome::Settled { self.unknown = true; }
        if self.before_machine.settle(boundary, false, &mut self.cleanup) != CloseOutcome::Settled { self.unknown = true; }
        if self.support.settle_process_dependency(boundary, &self.process, WebView2Original::Support, &mut self.cleanup) != CloseOutcome::Settled { self.unknown = true; }
        if self.system.settle_process_dependency(boundary, &self.process, WebView2Original::System, &mut self.cleanup) != CloseOutcome::Settled { self.unknown = true; }
        if self.input.settle_process_dependency(boundary, &self.process, WebView2Original::Input, &mut self.cleanup) != CloseOutcome::Settled { self.unknown = true; }
        if self.finality() { CloseOutcome::Settled } else { CloseOutcome::Unknown }
    }
    pub fn fail_and_settle_once(&mut self, boundary: &dyn InstallerBoundary) -> CloseOutcome {
        if self.first.is_none() { self.latch(Error::State); }
        self.settle_originals(boundary)
    }
    fn finality(&self) -> bool {
        self.settlement_attempted && !self.unknown && self.process.finality()
            && self.before_machine.settled && !self.before_machine.unknown
            && self.after_machine.settled && !self.after_machine.unknown
            && self.input.native.settled() && self.system.native.settled() && self.support.native.settled()
    }
    pub(super) fn require_complete_for(&self, acquisition: &InputAcquisition) -> Result<()> {
        self.expected.matches(&acquisition.prerequisite_binding()?)?;
        need(self.complete.is_some() && self.input_hashed && self.first.is_none() && self.cleanup.is_empty() && self.finality())
    }
    pub fn first_failure(&self) -> Option<Error> { self.first }
    pub fn cleanup_errors(&self) -> &[WebView2CleanupError] { &self.cleanup }
    pub fn report(&self) -> OfflineWebView2Report {
        let mut support = self.output;
        if support.disposition == WebView2SupportDisposition::RetainedBeforeVendor && self.process.create_entered {
            support.disposition = WebView2SupportDisposition::RetainedVendorMayHaveRun;
        }
        OfflineWebView2Report { mode: self.complete, vendor_may_have_run: self.process.create_entered,
            process_signalled: self.process.signalled, owned_job_empty: self.process.empty,
            vendor_exit_code: self.process.exit_code,
            process_dependencies_pending: self.settlement_attempted && !self.process.finality(), support }
    }
}

#[cfg(test)]
#[path = "installer_webview2_tests.rs"]
mod tests;
