//! Private native facts, not a qualified runtime or a process-creation adapter.
//!
//! The caller must register this book inside its ORIGINAL retained Resources before
//! releasing blocking work. Serialize it under that owner's Mutex; keep it and the
//! actual workers reachable through STOP, document loss, timeout and settlement.
//! The facts/publication adapters create no worker, broker or consumer process;
//! their blocking calls belong off the UI/deadline thread. The separately gated
//! `desktop-ui` module owns only the original STA shell/document/dialog resources.
//!
//! Native output destinations already belong to the pinned book before entry.
//! Drop never closes a HANDLE; unresolved storage is deliberately not deallocated.
//! Leaking storage is memory-safety fallback, NOT proof of owner reachability or
//! settlement. A future Windows owner integration must supply that proof.
#![cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
#![allow(unsafe_code)] // Small audited boundary; the application still forbids unsafe.
#![deny(unsafe_op_in_unsafe_fn)]

use std::cell::{Cell, UnsafeCell};
use std::marker::PhantomPinned;
use std::mem::{offset_of, size_of, ManuallyDrop};
use std::pin::Pin;
use std::ptr::{null, null_mut};
use std::sync::Arc;
use windows_sys::Wdk::{Foundation::OBJECT_ATTRIBUTES, Storage::FileSystem as N};
use windows_sys::Wdk::System::SystemServices as NS;
use windows_sys::Win32::{Foundation as F, Security as S, Storage::FileSystem as FS};
use windows_sys::Win32::System::{IO, SystemInformation as SI, Threading as T, WindowsProgramming as WP};
use windows_sys::Win32::UI::Shell as SH;

mod decode;
mod security;
mod loader;
pub use loader::SystemImage;
// Pure closed DATA is also used by the headless Windows startup scalar route.
pub mod ui_startup_data;
mod project;
pub use project::{ProjectBook, project_path_hint};
#[cfg(feature = "desktop-ui")]
pub mod ui;
#[cfg(all(test, feature = "desktop-ui"))]
mod hosted_ui_tests;
#[cfg(any(test, feature = "qualification-result"))]
mod qualification_result;
#[cfg(feature = "qualification-result")]
pub use qualification_result::{write_fullwalk_result_once, write_passive_result_once, require_passive_qualification, FullwalkFacts, PassiveFacts};
#[cfg(all(feature = "qualification-result", feature = "windows-installed-observation"))]
pub use qualification_result::{UiRole, UiCaseFacts, normal_ui_deadline, require_normal_ui_qualification, write_normal_ui_result_once};
#[cfg(all(feature = "qualification-result", feature = "windows-installed-observation"))]
pub use qualification_result::{normal_ui_project, mutate_normal_ui_fixture, verify_normal_ui_fixture,
    UI_FIXTURE_CONFIG, UI_FIXTURE_CONFIG_AFTER, UI_FIXTURE_SOURCE, UI_FIXTURE_VERSION, UI_FIXTURE_KEEP};
#[cfg(feature = "runtime-publication")]
mod publication;
#[cfg(feature = "runtime-publication")]
pub use publication::{Publication, PublicationFrameObservation, PublicationCopyObservation, PUBLICATION_PAYLOADS};
pub use decode::{DirectoryEntry, FileIdentity, Metadata};
pub use security::{AceFact, GroupFact, SecurityFacts, Sid, TokenFacts, TokenIdentity};

// E_PENDING is the exact scalar value in locked windows-sys 0.61.2
// Win32/System/Com/Urlmon. No Urlmon/COM function or loader dependency is used.
const HRESULT_PENDING: i32 = 0x8000000a_u32 as i32;
const BUFFER: usize = 64 * 1024;
pub const MAX_ORIGINALS: usize = 48; // Token originals count, too; one aggregate book.
const MAX_LIVE: usize = MAX_ORIGINALS;
const MAX_RECORDS: usize = 8256;
const MAX_FILES: usize = 2048;
const MAX_ENTRIES: usize = 8192;
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
const NAME_UNITS: usize = 8192;
const MAP_UNITS: usize = 4096;
type Held<T> = ManuallyDrop<Pin<Box<T>>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error { Unavailable, Unsafe, Bounds, State, Unknown }
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileKind { Directory, File }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityScope { AncestorOutsideVersion, ImmutableVersion }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotState { Reserved, Acquiring, Owned, NoHandle, Closing, Closed, Unknown }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseOutcome { Settled, Unknown }

// Closed, allocation-free DATA from the first returning admission refusal.
// The recorder lives in the original book, never TLS/a logger/a replacement owner.
use AdmissionCheck as C;

macro_rules! admission_labels {
    ($name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(crate) enum $name { $($variant),+ }
        impl $name {
            fn label(self) -> &'static str { match self { $(Self::$variant => $label),+ } }
            #[allow(dead_code)]
            pub(crate) fn from_label(value: &str) -> Option<Self> {
                match value { $($label => Some(Self::$variant),)+ _ => None }
            }
            #[cfg(test)]
            const ALL: &'static [Self] = &[$(Self::$variant),+];
        }
    };
}
pub(crate) use admission_labels;
admission_labels!(AdmissionRole {
    Owner => "owner", Installer => "installer", Primary => "primary-token",
    ThreadBefore => "thread-before", ThreadAfter => "thread-after",
    StatisticsBefore => "statistics-before", StatisticsAfter => "statistics-after",
    TokenType => "token-type", Elevation => "elevation", ElevationType => "elevation-type",
    UiAccess => "ui-access", Virtualization => "virtualization", Restrictions => "has-restrictions",
    AppContainer => "app-container", User => "user", Integrity => "integrity",
    Groups => "groups", Privileges => "privileges", Volume => "volume",
    ProgramFiles => "program-files", Mrk => "mrk", RuntimeInput => "runtime-input",
    Target => "target", Version => "version", Python => "python", Manifest => "manifest"
});
admission_labels!(AdmissionOp {
    Owner => "owner", Architecture => "architecture", TokenOpen => "token-open",
    HandleInfo => "handle-info", ThreadToken => "thread-token", TokenData => "token-data",
    Scalar => "scalar", InstallerPolicy => "installer-policy", Location => "location",
    Mapping => "mapping", Volume => "volume", Metadata => "metadata", Streams => "streams",
    SecurityAncestor => "security-ancestor", SecurityVersion => "security-version",
    Directory => "directory", Identity => "identity",
    Inventory => "inventory", Read => "read", FinalManifest => "final-manifest",
    MutationInput => "mutation-input"
});
admission_labels!(AdmissionCheck {
    OutputBytes => "output-bytes", OutputCount => "output-count", TextCount => "text-count",
    Span => "span", Utf16Width => "utf16-width", Utf16Encoding => "utf16-encoding",
    Terminator => "terminator", TextLength => "text-length", LocationDrive => "location-drive",
    LocationComponents => "location-components", MappingSize => "mapping-size",
    MappingFrame => "mapping-frame", MappingDevice => "mapping-device", MappingDigits => "mapping-digits",
    Attributes => "attributes", MetadataSize => "metadata-size", AttributeAgreement => "attribute-agreement",
    DirectoryBoolean => "directory-boolean", DeletePending => "delete-pending", ObjectKind => "object-kind",
    DirectoryAttribute => "directory-attribute", FileSize => "file-size", AllocationSize => "allocation-size",
    FileLinks => "file-links", FileId => "file-id", DirectoryOffset => "directory-offset",
    DirectoryNameLength => "directory-name-length", DirectoryNext => "directory-next",
    DirectoryName => "directory-name", DirectoryDot => "directory-dot",
    StreamMissing => "stream-missing", StreamFrame => "stream-frame", StreamName => "stream-name",
    StreamSize => "stream-size", StreamAllocation => "stream-allocation", StreamPadding => "stream-padding",
    SidRevision => "sid-revision", SidCount => "sid-count", SidExtent => "sid-extent",
    DescriptorSize => "descriptor-size", DescriptorRevision => "descriptor-revision",
    DescriptorReserved => "descriptor-reserved", DescriptorControl => "descriptor-control",
    DescriptorRequired => "descriptor-required", DescriptorSacl => "descriptor-sacl",
    OwnerOffset => "owner-offset", AclOffset => "acl-offset", OwnerTrust => "owner-trust",
    AclRevision => "acl-revision", AclReserved => "acl-reserved", AclSize => "acl-size",
    AclCount => "acl-count", OwnerAclOverlap => "owner-acl-overlap", GroupOffset => "group-offset",
    GroupOverlap => "group-overlap", AceType => "ace-type", AceSize => "ace-size",
    AceSidSize => "ace-sid-size", AceFlags => "ace-flags", AceInheritance => "ace-inheritance",
    AceMask => "ace-mask", AceDangerousRights => "ace-dangerous-rights",
    StatisticsSize => "statistics-size", StatisticsType => "statistics-type",
    StatisticsGroups => "statistics-groups", StatisticsPrivileges => "statistics-privileges",
    Inherited => "inherited", DriveShape => "drive-shape", DriveType => "drive-type",
    MappingCount => "mapping-count", LocationChanged => "location-changed",
    ChildParent => "child-parent", ChildName => "child-name", VolumeName => "volume-name",
    VolumeDeviceSize => "volume-device-size", VolumeDeviceType => "volume-device-type",
    VolumeRemote => "volume-remote", FileType => "file-type", CaseSensitive => "case-sensitive",
    CanonicalName => "canonical-name", AncestorName => "ancestor-name", ReadCount => "read-count",
    ThreadAbsent => "thread-absent", OrderFresh => "order-fresh", InstallerFresh => "installer-fresh",
    ArchitectureProcess => "architecture-process", ArchitectureNative => "architecture-native",
    PrimaryOpen => "primary-open", ScalarWidth => "scalar-width", ScalarCompletion => "scalar-completion",
    ScalarCanonical => "scalar-canonical", TokenPrimary => "token-primary", Elevated => "elevated",
    UiAccess => "ui-access", Virtualization => "virtualization", Restricted => "restricted",
    AppContainer => "app-container", UserBuffer => "user-buffer", IntegrityBuffer => "integrity-buffer",
    PointerValue => "pointer-value", PointerOffset => "pointer-offset", PointerMinimum => "pointer-minimum",
    PointerAlignment => "pointer-alignment", UserAttributes => "user-attributes",
    IntegrityAttributes => "integrity-attributes", SystemIntegrity => "system-integrity",
    SystemElevation => "system-elevation", AccountShape => "account-shape",
    AccountIntegrity => "account-integrity", AccountElevation => "account-elevation",
    GroupCount => "group-count", GroupSize => "group-size", GroupCountMatch => "group-count-match",
    GroupFlags => "group-flags", GroupDenyEnabled => "group-deny-enabled", GroupDuplicate => "group-duplicate",
    AdminOwner => "admin-owner", PrivilegesCount => "privileges-count", PrivilegesSize => "privileges-size",
    PrivilegesCountMatch => "privileges-count-match", PrivilegeLuid => "privilege-luid",
    PrivilegeDuplicate => "privilege-duplicate", PrivilegeFlags => "privilege-flags",
    StatisticsChanged => "statistics-changed", LocationOwner => "location-owner",
    LocationOrdinaryUser => "location-ordinary-user", LocationStarted => "location-started",
    MappingChanged => "mapping-changed", VolumeSerial => "volume-serial", Links => "links",
    CreationTime => "creation-time", WriteTime => "write-time", ChangeTime => "change-time",
    MetadataChanged => "metadata-changed", DirectoryChanged => "directory-changed",
    VolumeChanged => "volume-changed", IdentityAlias => "identity-alias", Component => "component",
    DirectoryKind => "directory-kind", SelectedCase => "selected-case", SelectedDuplicate => "selected-duplicate",
    DotKind => "dot-kind", DotIdentity => "dot-identity", EntryDuplicate => "entry-duplicate",
    EntryKind => "entry-kind", EntryIdentity => "entry-identity", EntryAttributes => "entry-attributes",
    SourceEntry => "source-entry", SourceKind => "source-kind", RosterName => "roster-name",
    RosterKind => "roster-kind", RosterMissing => "roster-missing", ManifestSize => "manifest-size",
    ManifestLimit => "manifest-limit", ManifestReportedSize => "manifest-reported-size",
    ManifestFinalSize => "manifest-final-size", ManifestFinalFacts => "manifest-final-facts",
    MutationData => "mutation-data", MutationDescriptor => "mutation-descriptor"
});

#[derive(Clone, Copy)]
pub(crate) enum AdmissionIndex { Directory, Ace, Group, Privilege }
impl AdmissionIndex {
    fn limit(self) -> usize { match self { Self::Directory => 8192, Self::Ace => 2048, Self::Group => 256, Self::Privilege => 64 } }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationAdmissionObservation {
    role: AdmissionRole, operation: AdmissionOp, check: AdmissionCheck, index: Option<u16>,
}
impl PublicationAdmissionObservation {
    /// Already normalized DATA only; no owner, native output, path or clock read.
    pub fn diagnostic_line(self) -> Option<String> {
        let mut line = String::with_capacity(256);
        line.push_str("MRK_WINDOWS_RUNTIME_PUBLISH_ADMISSION_V1=role="); line.push_str(self.role.label());
        line.push_str(";op="); line.push_str(self.operation.label());
        line.push_str(";check="); line.push_str(self.check.label()); line.push_str(";index=");
        if let Some(index) = self.index { line.push_str(&index.to_string()); } else { line.push_str("none"); }
        line.push('\n'); if line.len() <= 256 { Some(line) } else { None }
    }
}
struct AdmissionTrace {
    active: Cell<bool>, role: Cell<AdmissionRole>, first: Cell<Option<PublicationAdmissionObservation>>,
}
impl AdmissionTrace {
    fn new() -> Self { Self { active: Cell::new(false), role: Cell::new(AdmissionRole::Owner), first: Cell::new(None) } }
    fn at(&self, operation: AdmissionOp) -> Refusal<'_> {
        Refusal { owner: if self.active.get() { Some(self) } else { None }, role: self.role.get(), operation, index: None }
    }
}
#[derive(Clone, Copy)]
pub(crate) struct Refusal<'a> {
    owner: Option<&'a AdmissionTrace>, role: AdmissionRole, operation: AdmissionOp, index: Option<u16>,
}
impl<'a> Refusal<'a> {
    pub(crate) fn none() -> Self { Self { owner: None, role: AdmissionRole::Owner, operation: AdmissionOp::Owner, index: None } }
    pub(crate) fn role(self, role: AdmissionRole) -> Self { Self { role, ..self } }
    pub(crate) fn index(self, kind: AdmissionIndex, index: usize) -> Self {
        // Literal zero-based bounds; invalid indices become absent DATA, never a clamp/authority.
        Self { index: if index < kind.limit() { Some(index as u16) } else { None }, ..self }
    }
    pub(crate) fn error(self, error: Error, check: AdmissionCheck) -> Error {
        if error == Error::Unsafe {
            if let Some(owner) = self.owner {
                if owner.first.get().is_none() {
                    owner.first.set(Some(PublicationAdmissionObservation { role: self.role, operation: self.operation, check, index: self.index }));
                }
            }
        }
        error
    }
    pub(crate) fn unsafe_at(self, check: AdmissionCheck) -> Error { self.error(Error::Unsafe, check) }
    pub(crate) fn need(self, value: bool, check: AdmissionCheck) -> Result<()> {
        if value { Ok(()) } else { Err(self.unsafe_at(check)) }
    }
    pub(crate) fn result<T>(self, result: Result<T>, check: AdmissionCheck) -> Result<T> {
        result.map_err(|error| self.error(error, check))
    }
}

// The key cannot be constructed or cloned outside the crate. Keeping its Arc
// prevents an old key from matching a different book after allocator address reuse.
// It owns NO native handle; dropping it never retires its book's slot.
pub struct Original { book: Arc<()>, index: usize }
#[derive(Clone, Copy, Eq, PartialEq)]
enum Kind { Directory, File, ProcessToken, ThreadToken }
// Metadata policy only, never an admission capability or SystemImage tag.
// Ordinary payloads retain their existing single-link observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MetadataObservationProfile { Ordinary, ManagedWebViewImage }
const MANAGED_WEBVIEW_IMAGE: &str = "msedgewebview2.exe";
impl MetadataObservationProfile {
    fn admits(self, kind: Kind, name: &[u16], system_image: bool) -> bool {
        match self {
            Self::Ordinary => true,
            Self::ManagedWebViewImage => kind == Kind::File && !system_image
                && name == wide(MANAGED_WEBVIEW_IMAGE).as_slice(),
        }
    }
}
impl From<FileKind> for Kind {
    fn from(value: FileKind) -> Self {
        match value { FileKind::Directory => Self::Directory, FileKind::File => Self::File }
    }
}
// The ORIGINAL directory cursor gets one purpose and one owned selected name.
// Another mode/name cannot reinterpret earlier batches or restart enumeration.
#[derive(Debug, Eq, PartialEq)]
enum DirectoryMode { Unstarted, Strict, Ancestor(String), Selected(Vec<String>) }
impl DirectoryMode {
    fn bind(&mut self, requested: Self) -> Result<()> {
        if requested == Self::Unstarted { return Err(Error::State); }
        if *self == Self::Unstarted { *self = requested; Ok(()) }
        else if *self == requested { Ok(()) } else { Err(Error::State) }
    }
}
struct Slot {
    output: UnsafeCell<F::HANDLE>,
    state: SlotState,
    kind: Kind,
    parent: Option<usize>,
    name: Vec<u16>,
    canonical: String,
    read_bytes: u64,
    read_ended: bool,
    directory_ended: bool,
    directory_mode: DirectoryMode,
    // Only open_system_image can attach this role, before the original open.
    system_image: Option<SystemImage>,
    _pin: PhantomPinned,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase { Prepared, Entered, Returned, Complete }
#[derive(Clone, Copy)]
enum PrivilegeName { ChangeNotify, Shutdown, Undock, IncreaseWorkingSet, TimeZone }
#[derive(Clone, Copy)]
enum Call {
    Architecture, Folder, WindowsDirectory, SystemDirectory, Mapping, DriveType,
    Open(usize), ProcessToken(usize), ThreadToken(usize), Close(usize),
    #[cfg(test)]
    QualificationSourceToken(usize),
    #[cfg(test)]
    QualificationRestrictedToken(usize),
    Info(FS::FILE_INFO_BY_HANDLE_CLASS, usize), HandleInfo, FinalName, FileType,
    VolumeName, VolumeDevice, Streams, Security,
    Token(S::TOKEN_INFORMATION_CLASS), Privilege(PrivilegeName), Read(usize), Entries,
}
impl Call {
    // Pure slot classification, shared by native and inert registration. The
    // qualification variants never exist in a production native unit.
    fn token_output(self) -> Option<usize> {
        match self {
            Self::ProcessToken(index) | Self::ThreadToken(index) => Some(index),
            #[cfg(test)]
            Self::QualificationSourceToken(index) | Self::QualificationRestrictedToken(index) => Some(index),
            _ => None,
        }
    }
    fn acquisition_output(self) -> Option<usize> {
        match self { Self::Open(index) => Some(index), _ => self.token_output() }
    }
}
// A fixed output uses its complete SDK type, not the arena's spare capacity.
// Variable outputs retain the one bounded buffer; no size-discovery query/retry.
fn token_information_length(class: S::TOKEN_INFORMATION_CLASS) -> Result<u32> {
    let length = match class {
        S::TokenStatistics => size_of::<S::TOKEN_STATISTICS>(),
        S::TokenType => size_of::<S::TOKEN_TYPE>(),
        S::TokenElevation => size_of::<S::TOKEN_ELEVATION>(),
        S::TokenElevationType => size_of::<S::TOKEN_ELEVATION_TYPE>(),
        S::TokenUIAccess | S::TokenVirtualizationEnabled => size_of::<u32>(),
        S::TokenUser | S::TokenIntegrityLevel | S::TokenGroups | S::TokenPrivileges => BUFFER,
        _ => return Err(Error::State),
    };
    if length == 0 || length > BUFFER { return Err(Error::Bounds); }
    u32::try_from(length).map_err(|_| Error::Bounds)
}
#[derive(Clone, Copy, Debug)]
enum Returned { Boolean(i32, u32), Count(u32, u32), Hresult(i32), Nt(i32), Scalar(u32) }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompletionRefusal {
    OpenInvalidHandle, OpenIoStatus, OpenNotOpened, OpenDuplicate,
    TokenInvalidHandle, TokenDuplicate,
}
#[repr(C, align(8))]
struct Aligned([u8; BUFFER]);
struct Arena {
    call: Call,
    token_length: u32,
    phase: Cell<Phase>,
    returned: Cell<Option<Returned>>,
    completion_refusal: Cell<Option<CompletionRefusal>>,
    input: Vec<u16>,
    handle: F::HANDLE,
    output_handle: *mut F::HANDLE,
    unicode: F::UNICODE_STRING,
    attributes: OBJECT_ATTRIBUTES,
    directory: bool,
    bytes: UnsafeCell<Aligned>,
    count: UnsafeCell<u32>,
    iosb: UnsafeCell<IO::IO_STATUS_BLOCK>,
    _pin: PhantomPinned,
}
impl Arena {
    fn buffer(&self) -> *mut u8 { self.bytes.get().cast::<u8>() }
    fn returned(&self) -> Result<Returned> { self.returned.get().ok_or(Error::Unknown) }
}
struct Complete { arena: Pin<Box<Arena>> }
impl Complete {
    fn bytes(&self, length: usize) -> Result<&[u8]> {
        if self.arena.phase.get() != Phase::Complete { return Err(Error::Unknown); }
        if length > BUFFER { return Err(Error::Unsafe); }
        // SAFETY: only definite synchronous completion constructs Complete; the
        // pinned allocation is still owned, aligned and has BUFFER initialized bytes.
        Ok(unsafe { std::slice::from_raw_parts(self.arena.buffer(), length) })
    }
    fn count(&self) -> Result<usize> {
        // SAFETY: Complete excludes outstanding writes to this retained output.
        let value = unsafe { *self.arena.count.get() } as usize;
        if value > BUFFER { return Err(Error::Unsafe); }
        Ok(value)
    }
    fn nt_bytes(&self) -> Result<&[u8]> {
        // SAFETY: STATUS_PENDING/contradictory IOSB never becomes Complete.
        let count = unsafe { (*self.arena.iosb.get()).Information };
        self.bytes(count)
    }
    fn scalar(&self) -> Result<u32> {
        match self.arena.returned()? {
            Returned::Scalar(value) | Returned::Count(value, _) => Ok(value), _ => Err(Error::State),
        }
    }
    fn bytes_in(&self, length: usize, trace: Refusal<'_>) -> Result<&[u8]> { trace.result(self.bytes(length), C::OutputBytes) }
    fn count_in(&self, trace: Refusal<'_>) -> Result<usize> { trace.result(self.count(), C::OutputCount) }
    fn nt_bytes_in(&self, trace: Refusal<'_>) -> Result<&[u8]> { trace.result(self.nt_bytes(), C::OutputBytes) }
    fn text(&self, capacity: usize, counted: bool) -> Result<String> { self.text_in(capacity, counted, Refusal::none()) }
    fn text_in(&self, capacity: usize, counted: bool, trace: Refusal<'_>) -> Result<String> {
        let count = if counted { self.scalar()? as usize } else { capacity };
        if counted && (count == 0 || count >= capacity) { return Err(trace.unsafe_at(C::TextCount)); }
        decode::Observed::new(trace).terminated(self.bytes_in(capacity.checked_mul(2).ok_or(Error::Bounds)?, trace)?,
            if counted { Some(count) } else { None })
    }
}

/// Non-cloneable storage book, not runtime authority. Calls are synchronous and
/// must remain in original retained blocking work; no cancel-by-drop is supported.
pub struct NativeBook {
    admission: AdmissionTrace,
    identity: Arc<()>,
    slots: Vec<Held<Slot>>,
    active: Option<Held<Arena>>,
    unknown: bool,
    started: bool,
    retiring: bool,
    entries: usize,
    bytes_read: u64,
    process_token: Option<usize>,
    user: Option<TokenFacts>,
    roots_started: bool,
    #[cfg(test)]
    first_unavailable: Option<(Call, Returned)>,
}
// SAFETY: actual Windows file/token handles are process-wide. Only ownership of
// the serialized book moves; no reference to its UnsafeCell outputs escapes.
// Its pin allocations do not move, and an entered call exclusively borrows the
// book under the existing owner's Mutex. It is deliberately NOT Sync. Token
// observations are current-context facts, not a transferable impersonation lease.
unsafe impl Send for NativeBook {}
impl Default for NativeBook { fn default() -> Self { Self::new() } }
impl NativeBook {
    pub fn new() -> Self {
        Self { admission: AdmissionTrace::new(), identity: Arc::new(()), slots: Vec::new(), active: None, unknown: false, started: false,
            retiring: false, entries: 0, bytes_read: 0, process_token: None,
            user: None, roots_started: false,
            #[cfg(test)]
            first_unavailable: None }
    }
    #[cfg(test)]
    fn remember_unavailable(&mut self, call: Call, returned: Returned) {
        // Live callers are only the existing terminal Unavailable edges. Copy
        // captured scalars; never inspect native output or format before settlement.
        if self.first_unavailable.is_none() { self.first_unavailable = Some((call, returned)); }
    }
    fn clear(&self) -> Result<()> {
        if self.unknown || self.active.is_some() { Err(Error::Unknown) }
        else if self.retiring { Err(Error::State) } else { Ok(()) }
    }
    fn slot(&self, index: usize) -> Result<&Slot> {
        self.slots.get(index).map(|s| s.as_ref().get_ref()).ok_or(Error::State)
    }
    fn slot_mut(&mut self, index: usize) -> Result<&mut Slot> {
        let slot = self.slots.get_mut(index).ok_or(Error::State)?;
        // SAFETY: private access changes fields only, never moves a pinned Slot.
        Ok(unsafe { slot.as_mut().get_unchecked_mut() })
    }
    fn index(&self, original: &Original) -> Result<usize> {
        if !Arc::ptr_eq(&self.identity, &original.book) { return Err(Error::State); }
        self.slot(original.index)?; Ok(original.index)
    }
    fn handle(&self, index: usize) -> Result<F::HANDLE> {
        let slot = self.slot(index)?;
        if slot.state != SlotState::Owned || self.active.is_some() { return Err(Error::State); }
        // SAFETY: Owned is published only after definite output completion; all
        // borrowers are serialized and no entered operation can be present here.
        let handle = unsafe { *slot.output.get() };
        if !valid_handle(handle) { return Err(Error::Unknown); }
        Ok(handle)
    }
    fn reserve(&mut self, kind: Kind, parent: Option<usize>, name: &str, canonical: String) -> Result<Original> {
        self.clear()?;
        // A selected path gets one original attempt for this book, including
        // definite failures and retired originals. Token probes have no path.
        if matches!(kind, Kind::Directory | Kind::File) && self.slots.iter().any(|s|
            matches!(s.kind, Kind::Directory | Kind::File) && s.canonical == canonical) {
            return Err(Error::State);
        }
        let live = self.slots.iter().filter(|s| !matches!(s.state, SlotState::NoHandle | SlotState::Closed)).count();
        if self.slots.len() >= MAX_RECORDS || live >= MAX_LIVE { return Err(Error::Bounds); }
        if kind == Kind::File && self.slots.iter().filter(|s| s.kind == Kind::File).count() >= MAX_FILES {
            return Err(Error::Bounds);
        }
        if let Some(parent) = parent { self.handle(parent)?; }
        let mut encoded: Vec<u16> = name.encode_utf16().collect();
        if encoded.len() > 32766 { return Err(Error::Bounds); }
        encoded.push(0);
        self.slots.try_reserve(1).map_err(|_| Error::Bounds)?;
        let index = self.slots.len();
        self.slots.push(ManuallyDrop::new(Box::pin(Slot { output: UnsafeCell::new(null_mut()),
            state: SlotState::Reserved, kind, parent, name: encoded, canonical,
            read_bytes: 0, read_ended: false, directory_ended: false, directory_mode: DirectoryMode::Unstarted,
            system_image: None, _pin: PhantomPinned })));
        Ok(Original { book: Arc::clone(&self.identity), index })
    }
    fn arena(&self) -> Result<&Arena> {
        self.active.as_ref().map(|a| a.as_ref().get_ref()).ok_or(Error::Unknown)
    }
    fn unknown<T>(&mut self) -> Result<T> { self.unknown = true; Err(Error::Unknown) }
    fn completion_unknown<T>(&mut self, refusal: CompletionRefusal) -> Result<T> {
        // Only the six original successful-acquisition refusal branches call
        // this. Save their first rejecting predicate in the SAME retained arena;
        // no native output, handle or clock is read by this diagnostic recorder.
        if let Some(frame) = self.active.as_ref() {
            let saved = &frame.as_ref().get_ref().completion_refusal;
            if saved.get().is_none() { saved.set(Some(refusal)); }
        }
        self.unknown()
    }
    fn take_complete(&mut self) -> Result<Complete> {
        self.arena()?.phase.set(Phase::Complete);
        let frame = self.active.take().ok_or(Error::Unknown)?;
        Ok(Complete { arena: ManuallyDrop::into_inner(frame) })
    }
    fn call(&mut self, call: Call, handle: F::HANDLE, input: Vec<u16>) -> Result<Complete> {
        // Close may continue other independent known originals after a returned
        // close failure; no other call may follow Unknown or retirement.
        if matches!(call, Call::Close(_)) {
            if self.active.is_some() { return self.unknown(); }
        } else { self.clear()?; }
        // Select the input extent before publishing storage or entering the OS.
        let token_length = match call {
            Call::Token(class) => token_information_length(class)?,
            _ => 0, // never consumed by a non-token dispatch
        };
        let mut frame = Box::pin(Arena { call, token_length, phase: Cell::new(Phase::Prepared), returned: Cell::new(None),
            completion_refusal: Cell::new(None),
            input, handle, output_handle: null_mut(), unicode: F::UNICODE_STRING::default(),
            attributes: OBJECT_ATTRIBUTES::default(), directory: false,
            bytes: UnsafeCell::new(Aligned([0; BUFFER])), count: UnsafeCell::new(u32::MAX),
            iosb: UnsafeCell::new(IO::IO_STATUS_BLOCK { Anonymous: IO::IO_STATUS_BLOCK_0 { Status: F::STATUS_PENDING }, Information: usize::MAX }),
            _pin: PhantomPinned });
        // SAFETY: frame is pinned but not entered; initialize its self-referential
        // input pointers before publishing the arena and before native effects.
        let setup = unsafe { frame.as_mut().get_unchecked_mut() };
        if let Some(index) = call.acquisition_output() {
            let slot = self.slot(index)?;
            if slot.state != SlotState::Reserved { return Err(Error::State); }
            setup.output_handle = slot.output.get();
            if matches!(call, Call::Open(_)) {
                setup.input = slot.name.clone();
                setup.directory = slot.kind == Kind::Directory;
                setup.unicode.Length = u16::try_from((setup.input.len() - 1) * 2).map_err(|_| Error::Bounds)?;
                setup.unicode.MaximumLength = u16::try_from(setup.input.len() * 2).map_err(|_| Error::Bounds)?;
                setup.unicode.Buffer = setup.input.as_mut_ptr();
                setup.attributes.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
                setup.attributes.RootDirectory = match slot.parent { Some(parent) => self.handle(parent)?, None => null_mut() };
                setup.attributes.ObjectName = &setup.unicode;
                setup.attributes.Attributes = F::OBJ_DONT_REPARSE;
            }
        }
        self.active = Some(ManuallyDrop::new(frame));
        self.mark_entered(call)?;
        let frame = self.arena()?;
        // SAFETY: all arguments/destinations and parents are already registered,
        // pinned, initialized, bounded and exclusively borrowed. No allocation,
        // callback or deadline check divides return from scalar capture.
        let returned = unsafe { invoke(frame) };
        frame.returned.set(Some(returned));
        frame.phase.set(Phase::Returned);
        self.finish(call, returned)
    }
    // Inert state transition shared with narrow contract tests; it performs no
    // native call. The active arena and every output cell already belong to us.
    fn mark_entered(&mut self, call: Call) -> Result<()> {
        if self.arena()?.phase.get() != Phase::Prepared { return self.unknown(); }
        if let Some(i) = call.acquisition_output() {
            if self.slot(i)?.state != SlotState::Reserved { return self.unknown(); }
            self.slot_mut(i)?.state = SlotState::Acquiring;
        } else if let Call::Close(i) = call {
            let attempted = self.arena()?.handle;
            let slot = self.slot_mut(i)?;
            if slot.state != SlotState::Owned { return self.unknown(); }
            // SAFETY: no earlier call is outstanding. Retire BEFORE entry;
            // the arena holds the one attempted value, never an RAII owner.
            if unsafe { *slot.output.get() } != attempted { return self.unknown(); }
            slot.state = SlotState::Closing;
            unsafe { *slot.output.get() = null_mut(); }
        }
        self.started = true;
        self.arena()?.phase.set(Phase::Entered);
        Ok(())
    }
    fn finish(&mut self, call: Call, returned: Returned) -> Result<Complete> {
        if self.arena()?.phase.get() != Phase::Returned { return self.unknown(); }
        if self.unknown && !matches!(call, Call::Close(_)) { return self.unknown(); }
        if let Call::Close(index) = call {
            if self.slot(index)?.state != SlotState::Closing { return self.unknown(); }
            let success = matches!(returned, Returned::Boolean(value, _) if value != 0);
            self.slot_mut(index)?.state = if success { SlotState::Closed } else { SlotState::Unknown };
            if !success { self.unknown = true; }
            let result = self.take_complete()?;
            return if success { Ok(result) } else { Err(Error::Unknown) };
        }
        // NEVER evaluate native output cells before rejecting pending/ambiguous
        // return classes. In particular FALSE/ERROR_IO_PENDING is not a completed
        // ReadFile failure, and stale IOSB is not an acquisition failure receipt.
        if matches!(returned, Returned::Nt(F::STATUS_PENDING)
            | Returned::Boolean(0, F::ERROR_IO_PENDING)
            | Returned::Count(0, F::ERROR_IO_PENDING)
            | Returned::Hresult(HRESULT_PENDING)) { return self.unknown(); }
        if let Returned::Nt(status) = returned {
            if status != F::STATUS_SUCCESS && (status as u32 >> 30) != 3 { return self.unknown(); }
        }
        if let Call::Open(index) = call {
            if self.slot(index)?.state != SlotState::Acquiring { return self.unknown(); }
            let status = match returned { Returned::Nt(value) => value, _ => return self.unknown() };
            // SAFETY: only a definite non-PENDING NT status reaches these reads.
            let handle = unsafe { *self.slot(index)?.output.get() };
            if status != F::STATUS_SUCCESS {
                if !handle.is_null() { return self.unknown(); }
                self.slot_mut(index)?.state = SlotState::NoHandle;
                let _complete = self.take_complete()?;
                #[cfg(test)]
                self.remember_unavailable(call, returned);
                return Err(Error::Unavailable);
            }
            let frame = self.arena()?;
            // SAFETY: STATUS_SUCCESS completes the create; contradictory IOSB is
            // nevertheless retained as Unknown, never offered for ordinary close.
            let (io, info) = unsafe { ((*frame.iosb.get()).Anonymous.Status, (*frame.iosb.get()).Information) };
            // Preserve the original short-circuit order, including the lazy
            // duplicate check. Tags describe the already-executed predicate.
            if !valid_handle(handle) { return self.completion_unknown(CompletionRefusal::OpenInvalidHandle); }
            if io != F::STATUS_SUCCESS { return self.completion_unknown(CompletionRefusal::OpenIoStatus); }
            if info != WP::FILE_OPENED as usize { return self.completion_unknown(CompletionRefusal::OpenNotOpened); }
            if self.duplicate_live(index, handle) { return self.completion_unknown(CompletionRefusal::OpenDuplicate); }
            self.slot_mut(index)?.state = SlotState::Owned;
        } else if let Some(index) = call.token_output() {
            if self.slot(index)?.state != SlotState::Acquiring { return self.unknown(); }
            let (value, _) = match returned { Returned::Boolean(v, e) => (v, e), _ => return self.unknown() };
            #[cfg(test)]
            if matches!(call, Call::QualificationSourceToken(_) | Call::QualificationRestrictedToken(_))
                && !matches!(returned, Returned::Boolean(v, 0) if v != 0)
                && !matches!(returned, Returned::Boolean(0, e) if e != 0) {
                // Inconsistent qualification acquisition never authorizes its
                // output cell. Pending was already refused above.
                return self.unknown();
            }
            // SAFETY: synchronous completed BOOL token call, excluding IO_PENDING.
            let handle = unsafe { *self.slot(index)?.output.get() };
            if value != 0 {
                if !valid_handle(handle) { return self.completion_unknown(CompletionRefusal::TokenInvalidHandle); }
                if self.duplicate_live(index, handle) { return self.completion_unknown(CompletionRefusal::TokenDuplicate); }
                self.slot_mut(index)?.state = SlotState::Owned;
            } else {
                if !handle.is_null() { return self.unknown(); }
                self.slot_mut(index)?.state = SlotState::NoHandle;
            }
            // The caller must distinguish precise ERROR_NO_TOKEN from every
            // other returned FALSE; successful thread tokens remain owned too.
            return self.take_complete();
        } else if let Returned::Nt(status) = returned {
            if status != F::STATUS_SUCCESS {
                let _complete = self.take_complete()?;
                #[cfg(test)]
                self.remember_unavailable(call, returned);
                return Err(Error::Unavailable);
            }
            let frame = self.arena()?;
            // SAFETY: query returned SUCCESS; IOSB must corroborate completion.
            if unsafe { (*frame.iosb.get()).Anonymous.Status } != F::STATUS_SUCCESS { return self.unknown(); }
        }
        let failed = match returned {
            Returned::Boolean(0, error) => !(matches!(call, Call::Entries) && error == F::ERROR_NO_MORE_FILES),
            Returned::Count(0, _) => true,
            Returned::Hresult(value) => value != F::S_OK,
            _ => false,
        };
        let result = self.take_complete()?;
        if failed {
            #[cfg(test)]
            self.remember_unavailable(call, returned);
            Err(Error::Unavailable)
        } else { Ok(result) }
    }
    fn duplicate_live(&self, index: usize, handle: F::HANDLE) -> bool {
        self.slots.iter().enumerate().any(|(i, s)| i != index && s.state == SlotState::Owned
            // SAFETY: no other output destination can be entered simultaneously;
            // these Owned originals have definite acquisition completion.
            && unsafe { *s.output.get() == handle })
    }
    fn original_call(&mut self, index: usize, call: Call) -> Result<Complete> {
        let handle = self.handle(index)?; self.call(call, handle, Vec::new())
    }
    fn noninherited(&mut self, index: usize) -> Result<()> {
        let result = self.original_call(index, Call::HandleInfo)?;
        let trace = self.admission.at(AdmissionOp::HandleInfo);
        if decode::Observed::new(trace).u32_at(result.bytes_in(4, trace)?, 0)? & F::HANDLE_FLAG_INHERIT != 0 { return Err(trace.unsafe_at(C::Inherited)); }
        Ok(())
    }
    /// Call only after the actual worker has returned, never because a clock
    /// expired while a borrower might still run. It cannot manufacture NoHandle.
    pub fn mark_interrupted(&mut self) { self.unknown = true; }
    pub fn state(&self, original: &Original) -> Result<SlotState> { Ok(self.slot(self.index(original)?)?.state) }
    pub fn is_unknown(&self) -> bool { self.unknown || self.active.is_some() }
    pub fn never_started(&self) -> bool { !self.started && self.slots.is_empty() && self.active.is_none() && !self.unknown && !self.retiring && !self.roots_started && self.user.is_none() }
    pub fn close_once(&mut self, original: &Original) -> Result<()> {
        let index = self.index(original)?; self.close_index(index)
    }
    fn close_index(&mut self, index: usize) -> Result<()> {
        if self.active.is_some() { return self.unknown(); }
        let state = self.slot(index)?.state;
        if state == SlotState::Reserved { self.slot_mut(index)?.state = SlotState::NoHandle; return Ok(()); }
        if state != SlotState::Owned { return Err(Error::State); }
        if self.slots.iter().any(|s| s.parent == Some(index) && !matches!(s.state, SlotState::NoHandle | SlotState::Closed)) {
            return Err(Error::State); // no native close attempted; dependency is live
        }
        let handle = self.handle(index)?;
        self.call(Call::Close(index), handle, Vec::new()).map(|_| ())
    }
    pub fn settle_once(&mut self) -> CloseOutcome {
        if self.retiring { self.unknown = true; return CloseOutcome::Unknown; }
        self.retiring = true;
        if self.active.is_some() { self.unknown = true; return CloseOutcome::Unknown; }
        for index in (0..self.slots.len()).rev() {
            let state = match self.slot(index) { Ok(s) => s.state, Err(_) => { self.unknown = true; continue; } };
            if matches!(state, SlotState::NoHandle | SlotState::Closed) { continue; }
            if self.close_index(index).is_err() { self.unknown = true; }
        }
        if self.settled() { CloseOutcome::Settled } else { CloseOutcome::Unknown }
    }
    pub fn settled(&self) -> bool {
        self.retiring && !self.unknown && self.active.is_none()
            && self.slots.iter().all(|s| matches!(s.state, SlotState::NoHandle | SlotState::Closed))
    }
}
impl Drop for NativeBook {
    fn drop(&mut self) {
        // No CloseHandle in Drop, ever. Unknown entered arena may reference any
        // parent/output cell. ManuallyDrop preserves those exact heap allocations.
        if self.active.is_some() { return; }
        for slot in &mut self.slots {
            if matches!(slot.state, SlotState::NoHandle | SlotState::Closed) {
                // SAFETY: this slot cannot be referenced by outstanding native IO,
                // owns no live/uncertain handle and is destroyed exactly once.
                unsafe { ManuallyDrop::drop(slot); }
            }
        }
    }
}
fn valid_handle(value: F::HANDLE) -> bool { !value.is_null() && value != F::INVALID_HANDLE_VALUE }
fn wide(value: &str) -> Vec<u16> { value.encode_utf16().chain(std::iter::once(0)).collect() }
fn boolean(value: i32) -> Returned {
    // SAFETY: GetLastError is captured immediately on the same invoking thread;
    // no allocation/native operation/callback intervenes after a failed call.
    Returned::Boolean(value, if value == 0 { unsafe { F::GetLastError() } } else { 0 })
}
fn counted(value: u32) -> Returned {
    // SAFETY: same immediate, thread-local error-capture rule as boolean().
    Returned::Count(value, if value == 0 { unsafe { F::GetLastError() } } else { 0 })
}
unsafe fn invoke(a: &Arena) -> Returned {
    // SAFETY: call() owns/pins and exclusively retains every input/output before
    // entry. These are locked SDK declarations. No callback or asynchronous mode
    // is requested; unexpected pending results still retain every allocation.
    unsafe {
        match a.call {
            Call::Architecture => boolean(T::IsWow64Process2(T::GetCurrentProcess(), a.buffer().cast(), a.buffer().add(2).cast())),
            Call::Folder => Returned::Hresult(SH::SHGetFolderPathW(null_mut(), SH::CSIDL_PROGRAM_FILES as i32, null_mut(), SH::SHGFP_TYPE_CURRENT as u32, a.buffer().cast())),
            Call::WindowsDirectory => counted(SI::GetSystemWindowsDirectoryW(a.buffer().cast(), NAME_UNITS as u32)),
            Call::SystemDirectory => counted(SI::GetSystemDirectoryW(a.buffer().cast(), NAME_UNITS as u32)),
            Call::Mapping => counted(FS::QueryDosDeviceW(a.input.as_ptr(), a.buffer().cast(), MAP_UNITS as u32)),
            Call::DriveType => Returned::Scalar(FS::GetDriveTypeW(a.input.as_ptr())),
            Call::Open(_) => Returned::Nt(N::NtCreateFile(a.output_handle,
                FS::SYNCHRONIZE | FS::READ_CONTROL | FS::FILE_READ_ATTRIBUTES |
                    if a.directory { FS::FILE_LIST_DIRECTORY | FS::FILE_TRAVERSE } else { FS::FILE_READ_DATA },
                &a.attributes, a.iosb.get(), null(), 0, FS::FILE_SHARE_READ, N::FILE_OPEN,
                N::FILE_SYNCHRONOUS_IO_NONALERT | if a.directory { N::FILE_DIRECTORY_FILE } else { N::FILE_NON_DIRECTORY_FILE }, null(), 0)),
            Call::ProcessToken(_) => boolean(T::OpenProcessToken(T::GetCurrentProcess(), S::TOKEN_QUERY, a.output_handle)),
            #[cfg(test)]
            Call::QualificationSourceToken(_) => boolean(T::OpenProcessToken(T::GetCurrentProcess(),
                S::TOKEN_QUERY | S::TOKEN_DUPLICATE, a.output_handle)),
            #[cfg(test)]
            Call::QualificationRestrictedToken(_) => boolean(S::CreateRestrictedToken(a.handle,
                S::DISABLE_MAX_PRIVILEGE, 0, null(), 0, null(), 0, null(), a.output_handle)),
            Call::ThreadToken(_) => boolean(T::OpenThreadToken(T::GetCurrentThread(), S::TOKEN_QUERY, 1, a.output_handle)),
            Call::Close(_) => boolean(F::CloseHandle(a.handle)),
            Call::HandleInfo => boolean(F::GetHandleInformation(a.handle, a.buffer().cast())),
            Call::Info(class, size) => boolean(FS::GetFileInformationByHandleEx(a.handle, class, a.buffer().cast(), size as u32)),
            Call::FinalName => counted(FS::GetFinalPathNameByHandleW(a.handle, a.buffer().cast(), NAME_UNITS as u32, FS::FILE_NAME_NORMALIZED | FS::VOLUME_NAME_NT)),
            Call::FileType => Returned::Scalar(FS::GetFileType(a.handle)),
            Call::VolumeName => boolean(FS::GetVolumeInformationByHandleW(a.handle, null_mut(), 0, null_mut(), null_mut(), null_mut(), a.buffer().cast(), 261)),
            Call::VolumeDevice => Returned::Nt(N::NtQueryVolumeInformationFile(a.handle, a.iosb.get(), a.buffer().cast(), size_of::<NS::FILE_FS_DEVICE_INFORMATION>() as u32, N::FileFsDeviceInformation)),
            Call::Streams => Returned::Nt(N::NtQueryInformationFile(a.handle, a.iosb.get(), a.buffer().cast(), BUFFER as u32, N::FileStreamInformation)),
            Call::Security => boolean(S::GetKernelObjectSecurity(a.handle, S::OWNER_SECURITY_INFORMATION | S::DACL_SECURITY_INFORMATION, a.buffer().cast(), BUFFER as u32, a.count.get())),
            Call::Token(class) => boolean(S::GetTokenInformation(a.handle, class, a.buffer().cast(), a.token_length, a.count.get())),
            Call::Privilege(name) => boolean(S::LookupPrivilegeValueW(null(), match name {
                PrivilegeName::ChangeNotify => S::SE_CHANGE_NOTIFY_NAME,
                PrivilegeName::Shutdown => S::SE_SHUTDOWN_NAME,
                PrivilegeName::Undock => S::SE_UNDOCK_NAME,
                PrivilegeName::IncreaseWorkingSet => S::SE_INC_WORKING_SET_NAME,
                PrivilegeName::TimeZone => S::SE_TIME_ZONE_NAME,
            }, a.buffer().cast())),
            Call::Read(count) => boolean(FS::ReadFile(a.handle, a.buffer(), count as u32, a.count.get(), null_mut())),
            Call::Entries => boolean(FS::GetFileInformationByHandleEx(a.handle, FS::FileIdExtdDirectoryInfo, a.buffer().cast(), BUFFER as u32)),
        }
    }
}

#[derive(Clone, Copy)]
enum LocationKind { ProgramFiles, Windows, System }
pub struct KnownLocation { book: Arc<()>, kind: LocationKind, path: String, drive: String, device: String, components: Vec<String> }
impl KnownLocation {
    pub fn path(&self) -> &str { &self.path }
    pub fn components(&self) -> &[String] { &self.components }
    /// DATA comparison of two discoveries in this SAME original book. This is
    /// not a new mapping observation or permission to reopen a consumed cursor.
    pub fn same_volume(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.book, &other.book) && self.drive == other.drive && self.device == other.device
    }
}
pub struct KnownLocations { pub program_files: KnownLocation, pub windows: KnownLocation, pub system: KnownLocation }
impl NativeBook {
    fn location(&mut self, kind: LocationKind) -> Result<KnownLocation> {
        let (call, capacity, counted) = match kind {
            LocationKind::ProgramFiles => (Call::Folder, F::MAX_PATH as usize, false),
            LocationKind::Windows => (Call::WindowsDirectory, NAME_UNITS, true),
            LocationKind::System => (Call::SystemDirectory, NAME_UNITS, true),
        };
        let (path, trace) = {
            let complete = self.call(call, null_mut(), Vec::new())?;
            let trace = self.admission.at(AdmissionOp::Location);
            (complete.text_in(capacity, counted, trace)?, trace)
        };
        let (drive, components) = decode::Observed::new(trace).dos_location(&path)?;
        let device = self.mapping(&drive)?;
        Ok(KnownLocation { book: Arc::clone(&self.identity), kind, path, drive, device, components })
    }
    fn mapping(&mut self, drive: &str) -> Result<String> {
        if drive.len() != 2 || !drive.as_bytes()[0].is_ascii_alphabetic() || drive.as_bytes()[1] != b':' { return Err(self.admission.at(AdmissionOp::Mapping).unsafe_at(C::DriveShape)); }
        let root = format!("{drive}\\");
        if self.call(Call::DriveType, null_mut(), wide(&root))?.scalar()? != WP::DRIVE_FIXED { return Err(self.admission.at(AdmissionOp::Mapping).unsafe_at(C::DriveType)); }
        let result = self.call(Call::Mapping, null_mut(), wide(drive))?;
        let count = result.scalar()? as usize;
        let trace = self.admission.at(AdmissionOp::Mapping);
        if count < 2 || count > MAP_UNITS { return Err(trace.unsafe_at(C::MappingCount)); }
        decode::Observed::new(trace).mapping(result.bytes_in(count * 2, trace)?)
    }
    pub fn known_locations_once(&mut self) -> Result<KnownLocations> {
        self.clear()?;
        if self.user.is_none() || self.roots_started { return Err(Error::State); }
        self.roots_started = true;
        Ok(KnownLocations { program_files: self.location(LocationKind::ProgramFiles)?,
            windows: self.location(LocationKind::Windows)?, system: self.location(LocationKind::System)? })
    }
    pub fn recheck_location(&mut self, location: &KnownLocation) -> Result<()> {
        self.clear()?;
        if !Arc::ptr_eq(&self.identity, &location.book) { return Err(Error::State); }
        let now = self.location(location.kind)?;
        if now.path != location.path || now.drive != location.drive || now.device != location.device { return Err(self.admission.at(AdmissionOp::Location).unsafe_at(C::LocationChanged)); }
        Ok(())
    }
    /// Opens only the volume from this book's actual OS discovery. This creates
    /// an original, not a protected-root capability; inspect its ACL/identity too.
    pub fn open_volume(&mut self, location: &KnownLocation) -> Result<Original> {
        self.clear()?;
        if !Arc::ptr_eq(&self.identity, &location.book) || self.user.is_none() { return Err(Error::State); }
        if self.mapping(&location.drive)? != location.device { return Err(Error::Unsafe); }
        let name = format!("{}\\", location.device);
        let original = self.reserve(Kind::Directory, None, &name, name.clone())?;
        self.call(Call::Open(original.index), null_mut(), Vec::new())?;
        self.noninherited(original.index)?;
        self.local_ntfs(&original)?;
        self.recheck_location(location)?;
        Ok(original)
    }
    pub fn open_child(&mut self, parent: &Original, name: &str, kind: FileKind) -> Result<Original> {
        self.clear()?;
        let index = self.index(parent)?;
        let parent = self.slot(index)?;
        if parent.kind != Kind::Directory { return Err(self.admission.at(AdmissionOp::Directory).unsafe_at(C::ChildParent)); }
        if !decode::component(name) { return Err(self.admission.at(AdmissionOp::Directory).unsafe_at(C::ChildName)); }
        let canonical = format!("{}{}{}", parent.canonical, if parent.canonical.ends_with('\\') { "" } else { "\\" }, name);
        if canonical.encode_utf16().count() >= NAME_UNITS { return Err(Error::Bounds); }
        let original = self.reserve(kind.into(), Some(index), name, canonical)?;
        self.call(Call::Open(original.index), null_mut(), Vec::new())?;
        self.noninherited(original.index)?; Ok(original)
    }
    pub fn local_ntfs(&mut self, original: &Original) -> Result<()> {
        self.clear()?; let index = self.index(original)?;
        let (name, trace) = {
            let complete = self.original_call(index, Call::VolumeName)?;
            let trace = self.admission.at(AdmissionOp::Volume);
            (complete.text_in(261, false, trace)?, trace)
        };
        if name != "NTFS" { return Err(trace.unsafe_at(C::VolumeName)); }
        let result = self.original_call(index, Call::VolumeDevice)?;
        let trace = self.admission.at(AdmissionOp::Volume);
        let d = decode::Observed::new(trace);
        let bytes = result.nt_bytes_in(trace)?;
        if bytes.len() != size_of::<NS::FILE_FS_DEVICE_INFORMATION>() { return Err(trace.unsafe_at(C::VolumeDeviceSize)); }
        if d.u32_at(bytes, offset_of!(NS::FILE_FS_DEVICE_INFORMATION, DeviceType))? != FS::FILE_DEVICE_DISK { return Err(trace.unsafe_at(C::VolumeDeviceType)); }
        if d.u32_at(bytes, offset_of!(NS::FILE_FS_DEVICE_INFORMATION, Characteristics))? & NS::FILE_REMOTE_DEVICE != 0 { return Err(trace.unsafe_at(C::VolumeRemote)); }
        Ok(())
    }
    pub fn metadata(&mut self, original: &Original) -> Result<Metadata> {
        self.metadata_with_profile(original, MetadataObservationProfile::Ordinary)
    }
    pub(crate) fn managed_webview_image_metadata(&mut self, original: &Original) -> Result<Metadata> {
        self.metadata_with_profile(original, MetadataObservationProfile::ManagedWebViewImage)
    }
    fn metadata_with_profile(&mut self, original: &Original, profile: MetadataObservationProfile) -> Result<Metadata> {
        self.clear()?; let index = self.index(original)?;
        let slot = self.slot(index)?;
        // Reject role mixing BEFORE FileType or any native metadata call.
        if !profile.admits(slot.kind, &slot.name, slot.system_image.is_some()) {
            return Err(self.admission.at(AdmissionOp::Metadata).unsafe_at(C::ObjectKind));
        }
        let kind = match slot.kind { Kind::Directory => FileKind::Directory, Kind::File => FileKind::File, _ => return Err(Error::State) };
        if self.original_call(index, Call::FileType)?.scalar()? != FS::FILE_TYPE_DISK { return Err(self.admission.at(AdmissionOp::Metadata).unsafe_at(C::FileType)); }
        let basic = self.original_call(index, Call::Info(FS::FileBasicInfo, size_of::<FS::FILE_BASIC_INFO>()))?;
        let standard = self.original_call(index, Call::Info(FS::FileStandardInfo, size_of::<FS::FILE_STANDARD_INFO>()))?;
        let tag = self.original_call(index, Call::Info(FS::FileAttributeTagInfo, size_of::<FS::FILE_ATTRIBUTE_TAG_INFO>()))?;
        let id = self.original_call(index, Call::Info(FS::FileIdInfo, size_of::<FS::FILE_ID_INFO>()))?;
        let trace = self.admission.at(AdmissionOp::Metadata);
        let basic = basic.bytes_in(size_of::<FS::FILE_BASIC_INFO>(), trace)?;
        let standard = standard.bytes_in(size_of::<FS::FILE_STANDARD_INFO>(), trace)?;
        let tag = tag.bytes_in(size_of::<FS::FILE_ATTRIBUTE_TAG_INFO>(), trace)?;
        let id = id.bytes_in(size_of::<FS::FILE_ID_INFO>(), trace)?;
        let facts = if profile == MetadataObservationProfile::ManagedWebViewImage {
            decode::Observed::new(trace).managed_webview_image_metadata(kind, basic, standard, tag, id)?
        } else if self.slot(index)?.system_image.is_some() {
            decode::Observed::new(trace).system_image_metadata(kind, basic, standard, tag, id)?
        } else { decode::Observed::new(trace).metadata(kind, basic, standard, tag, id)? };
        if kind == FileKind::Directory {
            let case = self.original_call(index, Call::Info(FS::FileCaseSensitiveInfo, size_of::<FS::FILE_CASE_SENSITIVE_INFO>()))?;
            let trace = self.admission.at(AdmissionOp::Metadata);
            if decode::Observed::new(trace).u32_at(case.bytes_in(4, trace)?, 0)? != 0 { return Err(trace.unsafe_at(C::CaseSensitive)); }
        }
        let (name, trace) = {
            let complete = self.original_call(index, Call::FinalName)?;
            let trace = self.admission.at(AdmissionOp::Metadata);
            (complete.text_in(NAME_UNITS, true, trace)?, trace)
        };
        if name != self.slot(index)?.canonical { return Err(trace.unsafe_at(C::CanonicalName)); }
        Ok(facts)
    }
    pub fn security(&mut self, original: &Original, scope: AuthorityScope) -> Result<SecurityFacts> {
        self.clear()?; let index = self.index(original)?;
        let kind = match self.slot(index)?.kind { Kind::Directory => FileKind::Directory, Kind::File => FileKind::File, _ => return Err(Error::State) };
        let result = self.original_call(index, Call::Security)?;
        { let trace = self.admission.at(match scope {
                AuthorityScope::AncestorOutsideVersion => AdmissionOp::SecurityAncestor,
                AuthorityScope::ImmutableVersion => AdmissionOp::SecurityVersion,
            });
            security::Observed::new(trace).descriptor(result.bytes_in(result.count_in(trace)?, trace)?, kind, scope) }
    }
    pub fn no_alternate_streams(&mut self, original: &Original) -> Result<()> {
        self.clear()?; let index = self.index(original)?;
        let kind = match self.slot(index)?.kind { Kind::Directory => FileKind::Directory, Kind::File => FileKind::File, _ => return Err(Error::State) };
        let result = self.original_call(index, Call::Streams)?;
        { let trace = self.admission.at(AdmissionOp::Streams);
            decode::Observed::new(trace).streams(result.nt_bytes_in(trace)?, kind) }
    }
    /// One sequential bounded batch on the ORIGINAL directory. Never restart.
    /// None means actual ERROR_NO_MORE_FILES, not an empty/malformed batch.
    pub fn next_entries(&mut self, original: &Original) -> Result<Option<Vec<DirectoryEntry>>> {
        self.directory_entries(original, DirectoryMode::Strict)
    }
    /// Parent-prefix DATA only. Never use for the version's strict inventory.
    /// Unrelated sibling attributes do not grant any open/follow permission. The
    /// exact selected name (and ASCII aliases) still needs ordinary attributes;
    /// the caller owes exact-name EOF matching and original canonical/full-ID checks.
    pub fn next_ancestor_entries(&mut self, original: &Original, selected_name: &str) -> Result<Option<Vec<DirectoryEntry>>> {
        self.clear()?; // absorbing native Unknown precedes even argument refusal
        if !decode::component(selected_name) { return Err(self.admission.at(AdmissionOp::Directory).unsafe_at(C::AncestorName)); }
        self.directory_entries(original, DirectoryMode::Ancestor(selected_name.to_owned()))
    }
    /// One finite selection fixed on the ORIGINAL cursor's first call. Shared
    /// native location branches and the fixed OS-image roster are its only
    /// installed caller. Unrelated siblings remain DATA, never open authority.
    pub fn next_selected_entries(&mut self, original: &Original, names: &[String]) -> Result<Option<Vec<DirectoryEntry>>> {
        self.clear()?;
        loader::selected_names(names)?;
        self.directory_entries(original, DirectoryMode::Selected(names.to_vec()))
    }
    fn directory_entries(&mut self, original: &Original, mode: DirectoryMode) -> Result<Option<Vec<DirectoryEntry>>> {
        self.clear()?; let index = self.index(original)?;
        if self.slot(index)?.kind != Kind::Directory || self.slot(index)?.directory_ended { return Err(Error::State); }
        self.slot_mut(index)?.directory_mode.bind(mode)?;
        // At the exact limit allow an EOF observation, but a single over-limit
        // batch exhausts this entire book, not just the current directory.
        if self.entries > MAX_ENTRIES { return Err(Error::Bounds); }
        // A failed/ambiguous query or decoder refusal cannot be retried on an
        // unknown cursor. Only a fully accepted nonterminal batch permits next.
        self.slot_mut(index)?.directory_ended = true;
        let result = self.original_call(index, Call::Entries)?;
        if matches!(result.arena.returned()?, Returned::Boolean(0, F::ERROR_NO_MORE_FILES)) {
            self.slot_mut(index)?.directory_ended = true; return Ok(None);
        }
        let trace = self.admission.at(AdmissionOp::Directory);
        let d = decode::Observed::new(trace);
        let entries = match &self.slot(index)?.directory_mode {
            DirectoryMode::Strict => d.directory(result.bytes_in(BUFFER, trace)?)?,
            DirectoryMode::Ancestor(name) => d.ancestor_directory(result.bytes_in(BUFFER, trace)?, name)?,
            DirectoryMode::Selected(names) => d.selected_directory(result.bytes_in(BUFFER, trace)?, names)?,
            DirectoryMode::Unstarted => return Err(Error::State),
        };
        self.entries = self.entries.checked_add(entries.len()).ok_or(Error::Bounds)?;
        if self.entries > MAX_ENTRIES { return Err(Error::Bounds); }
        self.slot_mut(index)?.directory_ended = false;
        Ok(Some(entries))
    }
    /// No seek/reopen/retry. Empty bytes are definite successful ReadFile EOF.
    /// Hashing/full inventory and expected size remain the caller's retained work.
    pub fn read_next(&mut self, original: &Original, count: usize) -> Result<Vec<u8>> {
        self.clear()?; let index = self.index(original)?;
        if count == 0 || count > BUFFER { return Err(Error::Bounds); }
        if self.slot(index)?.kind != Kind::File || self.slot(index)?.read_ended { return Err(Error::State); }
        let prior = self.slot(index)?.read_bytes;
        if self.bytes_read > MAX_TOTAL_BYTES || prior > MAX_FILE_BYTES { return Err(Error::Bounds); }
        // One extra byte can distinguish exact-limit EOF from excess content;
        // it is never returned as accepted data. After excess, no other original
        // can continue past the global budget. No seek or second source is used.
        let remaining = (MAX_TOTAL_BYTES - self.bytes_read).min(MAX_FILE_BYTES - prior);
        let request = count.min(remaining.min(BUFFER as u64 - 1) as usize + 1);
        self.slot_mut(index)?.read_ended = true; // an error never authorizes retry
        let result = self.original_call(index, Call::Read(request))?;
        let trace = self.admission.at(AdmissionOp::Read);
        let consumed = result.count_in(trace)?;
        if consumed > request { return Err(trace.unsafe_at(C::ReadCount)); }
        self.bytes_read = self.bytes_read.checked_add(consumed as u64).ok_or(Error::Bounds)?;
        if self.bytes_read > MAX_TOTAL_BYTES { return Err(Error::Bounds); }
        let slot = self.slot_mut(index)?;
        slot.read_bytes = slot.read_bytes.checked_add(consumed as u64).ok_or(Error::Bounds)?;
        if slot.read_bytes > MAX_FILE_BYTES { return Err(Error::Bounds); }
        slot.read_ended = consumed == 0;
        Ok(result.bytes_in(consumed, self.admission.at(AdmissionOp::Read))?.to_vec())
    }
    fn absent_thread_token(&mut self) -> Result<()> {
        let key = self.reserve(Kind::ThreadToken, None, "", String::new())?;
        let result = self.call(Call::ThreadToken(key.index), null_mut(), Vec::new())?;
        match result.arena.returned()? {
            Returned::Boolean(0, F::ERROR_NO_TOKEN) if self.slot(key.index)?.state == SlotState::NoHandle => Ok(()),
            _ => Err(self.admission.at(AdmissionOp::ThreadToken).unsafe_at(C::ThreadAbsent)), // any acquired impersonation token stays owned
        }
    }
    fn token(&mut self, index: usize, class: S::TOKEN_INFORMATION_CLASS) -> Result<Complete> {
        self.original_call(index, Call::Token(class))
    }
    fn collect_user(&mut self, index: usize) -> Result<TokenFacts> {
        self.absent_thread_token()?;
        let before = self.token(index, S::TokenStatistics)?;
        let initial = security::statistics(before.bytes(before.count()?)?)?;
        let mut allowed = [0u64; 5];
        for (i, name) in [PrivilegeName::ChangeNotify, PrivilegeName::Shutdown, PrivilegeName::Undock,
            PrivilegeName::IncreaseWorkingSet, PrivilegeName::TimeZone].into_iter().enumerate() {
            let result = self.call(Call::Privilege(name), null_mut(), Vec::new())?;
            let luid = decode::u64_at(result.bytes(size_of::<F::LUID>())?, 0)?;
            if luid == 0 || allowed[..i].contains(&luid) { return Err(Error::Unsafe); }
            allowed[i] = luid;
        }
        let mut scalar = |class| -> Result<u32> {
            let result = self.token(index, class)?;
            let count = result.count()?;
            if count != 4 { return Err(Error::Unsafe); }
            decode::u32_at(result.bytes(count)?, 0)
        };
        let token_type = scalar(S::TokenType)?;
        let elevated = scalar(S::TokenElevation)?;
        let elevation_type = scalar(S::TokenElevationType)?;
        let ui_access = scalar(S::TokenUIAccess)?;
        let virtualization = scalar(S::TokenVirtualizationEnabled)?;
        let user = self.token(index, S::TokenUser)?;
        let integrity = self.token(index, S::TokenIntegrityLevel)?;
        let groups = self.token(index, S::TokenGroups)?;
        let privileges = self.token(index, S::TokenPrivileges)?;
        let facts = security::token_facts(initial, token_type, elevated, elevation_type, ui_access, virtualization,
            user.bytes(user.count()?)?, integrity.bytes(integrity.count()?)?,
            groups.bytes(groups.count()?)?, privileges.bytes(privileges.count()?)?, &allowed)?;
        let after = self.token(index, S::TokenStatistics)?;
        if security::statistics(after.bytes(after.count()?)?)? != initial { return Err(Error::Unsafe); }
        self.absent_thread_token()?;
        Ok(facts)
    }
    pub fn observe_user_once(&mut self) -> Result<&TokenFacts> {
        self.clear()?;
        if self.process_token.is_some() || self.user.is_some() { return Err(Error::State); }
        let arch = self.call(Call::Architecture, null_mut(), Vec::new())?;
        if decode::u16_at(arch.bytes(4)?, 0)? != SI::IMAGE_FILE_MACHINE_UNKNOWN
            || decode::u16_at(arch.bytes(4)?, 2)? != SI::IMAGE_FILE_MACHINE_AMD64 { return Err(Error::Unsafe); }
        let original = self.reserve(Kind::ProcessToken, None, "", String::new())?;
        self.process_token = Some(original.index); // no second primary-token open
        let opened = self.call(Call::ProcessToken(original.index), null_mut(), Vec::new())?;
        if !matches!(opened.arena.returned()?, Returned::Boolean(v, _) if v != 0) {
            #[cfg(test)]
            if let Some(returned) = opened.arena.returned.get() {
                self.remember_unavailable(opened.arena.call, returned);
            }
            return Err(Error::Unavailable);
        }
        self.noninherited(original.index)?;
        self.user = Some(self.collect_user(original.index)?);
        self.user.as_ref().ok_or(Error::State)
    }
    /// Reobserve the calling context and SAME original token before the future
    /// owner prepares a launch. No cached boolean or borrowed pseudo-handle proves
    /// non-impersonation on another executor. No IO may follow the final owner claim.
    pub fn recheck_user(&mut self) -> Result<()> {
        self.clear()?;
        let index = self.process_token.ok_or(Error::State)?;
        let facts = self.collect_user(index)?;
        if self.user.as_ref() != Some(&facts) { return Err(Error::Unsafe); }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod hosted_tests;

#[cfg(test)]
mod ordinary_owner;

#[cfg(test)]
mod qualification_fixture;
