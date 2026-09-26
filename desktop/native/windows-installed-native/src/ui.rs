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
use windows_sys::Win32::{System::{Registry as R, RemoteDesktop as RD, StationsAndDesktops as D}, UI::WindowsAndMessaging as W};
use webview2_com::Microsoft::Web::WebView2::Win32 as WV;
use crate::ui_startup_data::{Loss, NativeError, NativeMark, OverrideObservation, OverrideOpen, OverrideProbe, OverrideRefusal, PublicationOrder, Stage, Word};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering};

#[path = "ui_profile.rs"]
mod profile;
#[cfg(feature = "desktop-ui-dialogs")]
#[path = "ui_dialog.rs"]
mod dialog;
#[cfg(feature = "desktop-ui-dialogs")]
pub use dialog::{Dialog, DialogControl, DialogEvent, DialogResult, DialogResponse};
#[cfg(feature = "windows-installed-observation")]
pub use dialog::{DialogAction, DialogObservation};

// Qualification-only supporting HWND containment, not native button selection.
// HWND 0 and shared containers are valid logical-control representations. The
// native-only owner must not acquire Common Controls/dialog dependencies here.
#[cfg(any(test, feature = "windows-installed-observation"))]
pub(crate) mod quit_native {
    use windows_sys::Win32::{Foundation as F, UI::WindowsAndMessaging as W};
    use std::ptr::null_mut;

    const PARENTS: usize = 32;
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum Failure { State, Bounds, Process, Thread, Descendant, Lineage, Style, Changed }
    type Result<T> = std::result::Result<T, Failure>;
    fn require(ok: bool, error: Failure) -> Result<()> { if ok { Ok(()) } else { Err(error) } }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Link { handle: F::HWND, process: u32, thread: u32, child: bool, style: isize, parent: Option<F::HWND> }
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct Container { handle: F::HWND, links: Vec<Link> }
    impl Container {
        pub(crate) fn windowless() -> Self { Self { handle: null_mut(), links: Vec::new() } }
        fn new(handle: F::HWND) -> Self { Self { handle, links: Vec::with_capacity(PARENTS + 1) } }
        fn push(&mut self, link: Link, dialog: F::HWND, process: u32, thread: u32) -> Result<bool> {
            require(!dialog.is_null() && process != 0 && thread != 0 && !self.handle.is_null(), Failure::State)?;
            require(self.links.len() <= PARENTS, Failure::Bounds)?;
            require(!link.handle.is_null() && !self.links.iter().any(|old| old.handle == link.handle), Failure::Lineage)?;
            let expected = self.links.last().map_or(Some(self.handle), |old| old.parent);
            require(expected == Some(link.handle), Failure::Lineage)?;
            require(link.process == process, Failure::Process)?; require(link.thread == thread, Failure::Thread)?;
            let root = link.handle == dialog;
            if root { require(link.parent.is_none(), Failure::Lineage)?; }
            else {
                require(self.links.len() < PARENTS, Failure::Bounds)?;
                // GetParent alone may return a top-level owner. Both independent
                // descendant evidence and WS_CHILD are mandatory at every link.
                require(link.child && link.style & W::WS_CHILD as isize != 0, Failure::Descendant)?;
                require(link.parent.is_some_and(|parent| !parent.is_null() && parent != link.handle), Failure::Lineage)?;
            }
            self.links.push(link); Ok(root)
        }
        fn complete(&self, dialog: F::HWND, process: u32, thread: u32) -> Result<()> {
            require(!dialog.is_null() && process != 0 && thread != 0, Failure::State)?;
            if self.handle.is_null() { return require(self.links.is_empty(), Failure::Lineage); }
            require(!self.links.is_empty() && self.links.len() <= PARENTS + 1, Failure::Bounds)?;
            let mut checked = Self::new(self.handle);
            for (index, link) in self.links.iter().copied().enumerate() {
                let ended = checked.push(link, dialog, process, thread)?;
                require(ended == (index + 1 == self.links.len()), Failure::Lineage)?;
            }
            Ok(())
        }
        pub(crate) fn same(&self, current: &Self) -> Result<()> { require(self == current, Failure::Changed) }
    }
    fn style(window: F::HWND) -> Result<isize> {
        unsafe { F::SetLastError(F::ERROR_SUCCESS) };
        let value = unsafe { W::GetWindowLongPtrW(window, W::GWL_STYLE) };
        let error = if value == 0 { unsafe { F::GetLastError() } } else { 0 };
        require(error == 0, Failure::Style)?; Ok(value)
    }
    pub(crate) fn observe(handle: F::HWND, dialog: F::HWND, process: u32, thread: u32) -> Result<Container> {
        require(!dialog.is_null() && process != 0 && thread != 0, Failure::State)?;
        if handle.is_null() { return Ok(Container::windowless()); }
        let mut container = Container::new(handle); let mut current = handle;
        loop {
            require(container.links.len() <= PARENTS, Failure::Bounds)?;
            require(!current.is_null() && !container.links.iter().any(|link| link.handle == current), Failure::Lineage)?;
            let mut actual_process = 0;
            let actual_thread = unsafe { W::GetWindowThreadProcessId(current, &mut actual_process) };
            let child = unsafe { W::IsChild(dialog, current) } != 0;
            let style = style(current)?;
            let parent = if current == dialog { None } else { Some(unsafe { W::GetParent(current) }) };
            if container.push(Link { handle: current, process: actual_process, thread: actual_thread, child, style, parent },
                dialog, process, thread)? { break; }
            current = parent.ok_or(Failure::Lineage)?;
        }
        container.complete(dialog, process, thread)?; Ok(container)
    }

    #[cfg(test)]
    pub(crate) fn contract() -> [Container; 4] {
        // The actual bounded predicates, inert borrowed handles only. No native
        // query, release, message, provider or synthetic response is entered.
        let dialog = 1usize as F::HWND; let child = 2usize as F::HWND; let middle = 3usize as F::HWND;
        let process = 17; let thread = 19;
        let root = Link { handle: dialog, process, thread, child: false, style: 0, parent: None };
        let leaf = Link { handle: child, process, thread, child: true, style: W::WS_CHILD as isize, parent: Some(dialog) };
        let mut direct = Container::new(child); assert_eq!(direct.push(leaf, dialog, process, thread), Ok(false));
        assert_eq!(direct.push(root, dialog, process, thread), Ok(true)); assert_eq!(direct.complete(dialog, process, thread), Ok(()));
        let mut nested = Container::new(child);
        assert_eq!(nested.push(Link { parent: Some(middle), ..leaf }, dialog, process, thread), Ok(false));
        assert_eq!(nested.push(Link { handle: middle, ..leaf }, dialog, process, thread), Ok(false));
        assert_eq!(nested.push(root, dialog, process, thread), Ok(true)); assert_eq!(nested.complete(dialog, process, thread), Ok(()));
        let mut shared = Container::new(dialog); assert_eq!(shared.push(root, dialog, process, thread), Ok(true));
        let windowless = Container::windowless(); assert_eq!(windowless.complete(dialog, process, thread), Ok(()));
        for original in [&direct, &nested, &shared, &windowless] { assert_eq!(original.same(original), Ok(())); }
        assert_eq!(direct.same(&nested), Err(Failure::Changed)); assert_eq!(windowless.same(&shared), Err(Failure::Changed));
        for (link, error) in [
            (Link { process: process + 1, ..leaf }, Failure::Process),
            (Link { thread: thread + 1, ..leaf }, Failure::Thread),
            (Link { child: false, ..leaf }, Failure::Descendant),
            (Link { style: 0, ..leaf }, Failure::Descendant),
            (Link { parent: Some(child), ..leaf }, Failure::Lineage),
            (Link { parent: Some(null_mut()), ..leaf }, Failure::Lineage),
            (Link { handle: middle, ..leaf }, Failure::Lineage),
        ] {
            let mut candidate = Container::new(child); let mut effects = 0;
            let result = (|| { candidate.push(link, dialog, process, thread)?; effects += 1; Ok(()) })();
            assert_eq!(result, Err(error)); assert_eq!(effects, 0);
        }
        let mut incomplete = Container::new(child); incomplete.links.push(leaf);
        assert_eq!(incomplete.complete(dialog, process, thread), Err(Failure::Lineage));
        let mut cycle = Container::new(child);
        assert_eq!(cycle.push(Link { parent: Some(middle), ..leaf }, dialog, process, thread), Ok(false));
        assert_eq!(cycle.push(Link { handle: middle, parent: Some(child), ..leaf }, dialog, process, thread), Ok(false));
        assert_eq!(cycle.push(leaf, dialog, process, thread), Err(Failure::Lineage));
        let mut bounded = Container::new(100usize as F::HWND);
        for offset in 0..PARENTS {
            let handle = (100 + offset) as F::HWND; let parent = (101 + offset) as F::HWND;
            assert_eq!(bounded.push(Link { handle, parent: Some(parent), ..leaf }, dialog, process, thread), Ok(false));
        }
        assert_eq!(bounded.push(Link { handle: (100 + PARENTS) as F::HWND, ..leaf }, dialog, process, thread), Err(Failure::Bounds));
        [windowless, shared, direct, nested]
    }
}

// Separate from STOP/close ownership. A qualification action may become
// not-ready only before this latch; entry consumes it even when the postcheck
// fails. This helper neither invents a dialog response nor grants finality.
#[cfg(any(test, feature = "windows-installed-observation"))]
pub(crate) struct QuitAction { entered: Cell<bool> }
#[cfg(any(test, feature = "windows-installed-observation"))]
impl QuitAction {
    pub(crate) fn new() -> Self { Self { entered: Cell::new(false) } }
    pub(crate) fn check(&self) -> UiResult<()> { if self.entered.get() { Err(UiError::State) } else { Ok(()) } }
    pub(crate) fn request(&self, effect: impl FnOnce() -> UiResult<()>) -> UiResult<bool> {
        self.check()?; self.entered.set(true); effect()?; Ok(true)
    }
    #[cfg(test)]
    pub(crate) fn contract() {
        for result in [Ok(()), Err(UiError::State), Err(UiError::CleanupUnknown)] {
            let action = Self::new(); let effects = Cell::new(0);
            assert_eq!(action.check(), Ok(())); assert!(!action.entered.get());
            assert_eq!(action.request(|| {
                assert!(action.entered.get()); effects.set(effects.get() + 1);
                assert_eq!(action.request(|| { effects.set(effects.get() + 1); Ok(()) }), Err(UiError::State));
                result
            }), result.map(|_| true)); // Never false after effect entry.
            assert_eq!(action.check(), Err(UiError::State));
            assert_eq!(action.request(|| { effects.set(effects.get() + 1); Ok(()) }), Err(UiError::State));
            assert_eq!(effects.get(), 1);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialogKind { Project, Quit }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiError {
    OrdinaryContext, InteractiveDesktop, ManagedRuntimeUnavailable,
    RuntimeOverrides, UserDataParent, NativeFailure, CleanupUnknown, State,
}
impl UiError {
    fn diagnostic(self) -> NativeError { match self {
        Self::OrdinaryContext => NativeError::Ordinary, Self::InteractiveDesktop => NativeError::Interactive,
        Self::ManagedRuntimeUnavailable => NativeError::Runtime, Self::RuntimeOverrides => NativeError::Overrides,
        Self::UserDataParent => NativeError::Data, Self::NativeFailure => NativeError::Native,
        Self::CleanupUnknown => NativeError::Unknown, Self::State => NativeError::State,
    } }
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

// One ordinary diagnostic name; no caller-selected name or handle payload.
const STARTUP_PROPERTY: &[u16] = &[77,82,75,46,87,105,110,100,111,119,115,46,78,111,114,109,97,108,83,116,97,114,116,117,112,46,68,105,97,103,110,111,115,116,105,99,46,118,49,0];
#[derive(Default)]
pub struct StartupPublication {
    order: PublicationOrder, hwnd: AtomicUsize, thread: AtomicU32, process: AtomicU32,
    sealed: AtomicBool, removal: AtomicU8,
}
impl StartupPublication {
    pub fn seal(&self) { self.sealed.store(true, Ordering::SeqCst); self.order.seal(); }
    // Borrowed, synchronous checkpoint only; never stored/boxed. The caller
    // rereads the SAME original document's current accepted-Quit endpoint on
    // every boundary, including when Quit began after this publication entered.
    // A once-captured None must not authorize later effects past a new STOP.
    fn admitted(&self, permitted: &dyn Fn() -> bool) -> bool {
        if self.sealed.load(Ordering::SeqCst) { return false; }
        if !permitted() { self.seal(); return false; }
        true
    }
    fn identity(&self, permitted: &dyn Fn() -> bool) -> bool {
        if !self.admitted(permitted) { return false; }
        if unsafe { T::GetCurrentThreadId() } != self.thread.load(Ordering::SeqCst) { return false; }
        if !self.admitted(permitted) { return false; }
        let mut process = 0;
        let thread = unsafe { W::GetWindowThreadProcessId(self.hwnd.load(Ordering::SeqCst) as F::HWND, &mut process) };
        thread == self.thread.load(Ordering::SeqCst) && process == self.process.load(Ordering::SeqCst) && self.admitted(permitted)
    }
    fn get(&self, permitted: &dyn Fn() -> bool) -> Option<u64> {
        if !self.admitted(permitted) { return None; }
        let raw = (unsafe { W::GetPropW(self.hwnd.load(Ordering::SeqCst) as F::HWND, STARTUP_PROPERTY.as_ptr()) }) as usize as u64;
        self.admitted(permitted).then_some(raw)
    }
    fn set(&self, word: u64, permitted: &dyn Fn() -> bool) -> bool {
        if !self.admitted(permitted) || !self.order.entered() { return false; }
        let returned = unsafe { W::SetPropW(self.hwnd.load(Ordering::SeqCst) as F::HWND,
            STARTUP_PROPERTY.as_ptr(), word as usize as F::HANDLE) } != 0;
        returned && self.admitted(permitted) && self.get(permitted) == Some(word)
    }
    pub fn bind(&self, hwnd: usize, word: u64, permitted: &dyn Fn() -> bool) {
        if !self.admitted(permitted) || !self.order.bind() { return; }
        let success = (|| {
            if hwnd == 0 || Word::decode(word).is_none() || !self.admitted(permitted) { return false; }
            self.hwnd.store(hwnd, Ordering::SeqCst);
            self.thread.store(unsafe { T::GetCurrentThreadId() }, Ordering::SeqCst);
            if !self.admitted(permitted) { return false; }
            self.process.store(unsafe { T::GetCurrentProcessId() }, Ordering::SeqCst);
            self.identity(permitted) && self.get(permitted) == Some(0) && self.set(word, permitted)
        })();
        self.order.returned(word, success);
    }
    pub fn publish(&self, word: u64, permitted: &dyn Fn() -> bool) {
        if !self.admitted(permitted) { return; }
        let Some(previous) = self.order.begin(word) else { return; };
        // Non-atomic hygiene only: no ownership/authentication claim against a
        // concurrent writer. Any conflict/error disables all later attempts.
        let success = self.identity(permitted) && self.get(permitted) == Some(previous) && self.set(word, permitted);
        self.order.returned(word, success);
    }
    pub fn retire(&self, permitted: &dyn Fn() -> bool) {
        let Some(previous) = self.order.retire() else { self.seal(); return; };
        // Retire the lifecycle before entry. The caller's checkpoint additionally
        // requires the exact supplied original endpoint at EVERY effect; a
        // concurrent/recursive Destroyed seal stops all later native effects.
        self.removal.store(1, Ordering::SeqCst);
        if self.identity(permitted) && self.get(permitted) == Some(previous) && self.admitted(permitted) {
            let returned = (unsafe { W::RemovePropW(self.hwnd.load(Ordering::SeqCst) as F::HWND, STARTUP_PROPERTY.as_ptr()) }) as usize as u64;
            self.removal.store(if returned == previous && self.admitted(permitted) { 2 } else { 3 }, Ordering::SeqCst);
        } else { self.removal.store(3, Ordering::SeqCst); }
        // The integer is never freed/CloseHandle'd. No removal bit gates native
        // finality and no missing property is claimed as cleanup success.
        self.seal();
    }
}
pub(crate) fn startup_property(hwnd: F::HWND) -> u64 {
    // Caller is the existing exact-root owner, with its original Clock checks.
    // NULL has no invented GetLastError/no-window meaning.
    (unsafe { W::GetPropW(hwnd, STARTUP_PROPERTY.as_ptr()) }) as usize as u64
}

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

// Finite first-refusal DATA on the SAME inspector. None of these tags decides
// admission, invokes an API, reads a native destination, or grants settlement.
super::admission_labels!(ProbeStage {
    Getter => "version-getter", Text => "version-text", Version => "stable-version",
    Decode => "path-decode", Depth => "path-depth", RootDecode => "runtime-root-decode",
    Ancestry => "runtime-ancestry", MappingBefore => "mapping-before", Reserve => "root-reserve",
    RootOpen => "root-open", RootMetadata => "root-metadata", ChildOpen => "child-open",
    ChildMetadata => "child-metadata", Alias => "identity-alias", Ntfs => "local-ntfs",
    Streams => "alternate-streams", Security => "runtime-security", MappingAfter => "mapping-after",
    RecheckMetadata => "recheck-metadata", RecheckIdentity => "recheck-identity", RecheckSecurity => "recheck-security"
});
super::admission_labels!(ProbeCause {
    Unavailable => "unavailable", Unsafe => "unsafe", Bounds => "bounds", State => "state",
    Native => "native-failure", Policy => "ui-policy"
});
super::admission_labels!(ProbeDetail {
    TextState => "text-state", TextNull => "text-null", TextEmpty => "text-empty",
    TextUtf16 => "text-utf16", TextBound => "text-bound",
    VersionCount => "version-count", VersionEmpty => "version-empty", VersionWidth => "version-width",
    VersionZero => "version-leading-zero", VersionDigits => "version-digits", VersionRange => "version-range",
    VersionMajor => "version-major", MappingChanged => "mapping-changed",
    Identity => "identity", Kind => "kind", Attributes => "attributes", Creation => "creation", File => "file-metadata"
});
super::admission_labels!(ProbeOperation {
    Getter => "webview-version", Mapping => "dos-mapping", Open => "open", Handle => "handle-info",
    Basic => "metadata-basic", Standard => "metadata-standard", Tag => "metadata-tag", Id => "metadata-id",
    Case => "metadata-case", Name => "final-name", VolumeName => "volume-name",
    VolumeDevice => "volume-device", Streams => "streams", Security => "security"
});
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeStatus { Win32(u32), Nt(i32), Hresult(i32) }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProbeNative { operation: ProbeOperation, status: ProbeStatus }
impl ProbeNative {
    fn valid(self, stage: ProbeStage) -> bool {
        use ProbeOperation as O;
        use ProbeStage as P;
        let operation = match stage {
            P::Getter => self.operation == O::Getter,
            P::MappingBefore | P::MappingAfter => self.operation == O::Mapping,
            P::RootOpen => self.operation == O::Open,
            P::ChildOpen => matches!(self.operation, O::Open | O::Handle),
            P::RootMetadata | P::ChildMetadata | P::RecheckMetadata => matches!(self.operation,
                O::Basic | O::Standard | O::Tag | O::Id | O::Case | O::Name),
            P::Ntfs => matches!(self.operation, O::VolumeName | O::VolumeDevice),
            P::Streams => self.operation == O::Streams,
            P::Security | P::RecheckSecurity => self.operation == O::Security,
            _ => false,
        };
        operation && match (self.operation, self.status) {
            (O::Getter, ProbeStatus::Hresult(code)) => code < 0 && code != HRESULT_PENDING,
            (O::Open | O::VolumeDevice | O::Streams, ProbeStatus::Nt(code)) => (code as u32 >> 30) == 3,
            (O::Mapping | O::Handle | O::Basic | O::Standard | O::Tag | O::Id | O::Case | O::Name
                | O::VolumeName | O::Security, ProbeStatus::Win32(code)) => code != F::ERROR_IO_PENDING,
            _ => false,
        }
    }
    #[cfg(test)]
    fn original(call: Call, returned: Returned) -> Option<Self> {
        use ProbeOperation as O;
        let operation = match call {
            Call::Mapping => O::Mapping, Call::Open(_) => O::Open, Call::HandleInfo => O::Handle,
            Call::Info(class, size) => match class {
                FS::FileBasicInfo if size == size_of::<FS::FILE_BASIC_INFO>() => O::Basic,
                FS::FileStandardInfo if size == size_of::<FS::FILE_STANDARD_INFO>() => O::Standard,
                FS::FileAttributeTagInfo if size == size_of::<FS::FILE_ATTRIBUTE_TAG_INFO>() => O::Tag,
                FS::FileIdInfo if size == size_of::<FS::FILE_ID_INFO>() => O::Id,
                FS::FileCaseSensitiveInfo if size == size_of::<FS::FILE_CASE_SENSITIVE_INFO>() => O::Case,
                _ => return None,
            },
            Call::FinalName => O::Name, Call::VolumeName => O::VolumeName,
            Call::VolumeDevice => O::VolumeDevice, Call::Streams => O::Streams, Call::Security => O::Security,
            _ => return None,
        };
        let status = match (operation, returned) {
            (O::Mapping | O::Name, Returned::Count(0, code)) if code != F::ERROR_IO_PENDING => ProbeStatus::Win32(code),
            (O::Handle | O::Basic | O::Standard | O::Tag | O::Id | O::Case | O::VolumeName | O::Security,
                Returned::Boolean(0, code)) if code != F::ERROR_IO_PENDING => ProbeStatus::Win32(code),
            (O::Open | O::VolumeDevice | O::Streams, Returned::Nt(code)) if (code as u32 >> 30) == 3 => ProbeStatus::Nt(code),
            _ => return None,
        };
        Some(Self { operation, status })
    }
}

fn probe_admission_valid(stage: ProbeStage, value: PublicationAdmissionObservation) -> bool {
    use AdmissionOp as O;
    use ProbeStage as P;
    let operation = match stage {
        P::MappingBefore | P::MappingAfter => value.operation == O::Mapping,
        P::ChildOpen => matches!(value.operation, O::Directory | O::HandleInfo),
        P::RootMetadata | P::ChildMetadata | P::RecheckMetadata => value.operation == O::Metadata,
        P::Ntfs => value.operation == O::Volume, P::Streams => value.operation == O::Streams,
        P::Security | P::RecheckSecurity => matches!(value.operation, O::SecurityAncestor | O::SecurityVersion),
        _ => false,
    };
    if !operation || value.role != AdmissionRole::RuntimeInput { return false; }
    let security = matches!(value.operation, O::SecurityAncestor | O::SecurityVersion);
    if value.index.is_some_and(|index| !security || index >= 2048) { return false; }
    match value.operation {
        O::Mapping => matches!(value.check, C::OutputBytes | C::Utf16Width | C::Utf16Encoding
            | C::DriveShape | C::DriveType | C::MappingCount | C::MappingSize | C::MappingFrame | C::MappingDevice | C::MappingDigits),
        O::Directory => matches!(value.check, C::ChildParent | C::ChildName),
        O::HandleInfo => matches!(value.check, C::OutputBytes | C::Span | C::Inherited),
        O::Metadata => matches!(value.check, C::OutputBytes | C::Span | C::TextCount | C::Utf16Width | C::Utf16Encoding
            | C::Terminator | C::TextLength | C::Attributes | C::MetadataSize | C::AttributeAgreement
            | C::DirectoryBoolean | C::DeletePending | C::ObjectKind | C::DirectoryAttribute | C::FileSize
            | C::AllocationSize | C::FileLinks | C::FileId | C::FileType | C::CaseSensitive | C::CanonicalName),
        O::Volume => matches!(value.check, C::OutputBytes | C::Span | C::Utf16Width | C::Utf16Encoding | C::Terminator
            | C::TextLength | C::VolumeName | C::VolumeDeviceSize | C::VolumeDeviceType | C::VolumeRemote),
        O::Streams => matches!(value.check, C::OutputBytes | C::Span | C::Utf16Width | C::Utf16Encoding | C::StreamMissing
            | C::StreamFrame | C::StreamName | C::StreamSize | C::StreamAllocation | C::StreamPadding),
        O::SecurityAncestor | O::SecurityVersion => matches!(value.check, C::OutputBytes | C::OutputCount | C::Span
            | C::SidRevision | C::SidCount | C::SidExtent | C::DescriptorSize | C::DescriptorRevision | C::DescriptorReserved
            | C::DescriptorControl | C::DescriptorRequired | C::DescriptorSacl | C::OwnerOffset | C::AclOffset | C::OwnerTrust
            | C::AclRevision | C::AclReserved | C::AclSize | C::AclCount | C::OwnerAclOverlap | C::GroupOffset | C::GroupOverlap
            | C::AceType | C::AceSize | C::AceSidSize | C::AceFlags | C::AceInheritance | C::AceMask | C::AceDangerousRights),
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ManagedRuntimeRefusal {
    stage: ProbeStage, path: Option<u8>, cause: ProbeCause, detail: Option<ProbeDetail>,
    native: Option<ProbeNative>, admission: Option<PublicationAdmissionObservation>,
}
impl ManagedRuntimeRefusal {
    fn valid(self) -> bool {
        use ProbeCause as E;
        use ProbeDetail as D;
        use ProbeStage as P;
        let bound = matches!(self.stage, P::Ntfs | P::Streams | P::Security | P::RecheckMetadata | P::RecheckIdentity | P::RecheckSecurity);
        if self.path.is_some_and(|index| usize::from(index) >= MAX_ORIGINALS) || self.path.is_some() != bound { return false; }
        let kind = match self.stage {
            P::Getter => self.cause == E::Native && self.detail.is_none() && self.native.is_some(),
            P::Text => self.cause == E::Native && matches!(self.detail,
                Some(D::TextState | D::TextNull | D::TextEmpty | D::TextUtf16 | D::TextBound)),
            P::Version => self.cause == E::Policy && matches!(self.detail, Some(D::VersionCount | D::VersionEmpty
                | D::VersionWidth | D::VersionZero | D::VersionDigits | D::VersionRange | D::VersionMajor)),
            P::Depth | P::Ancestry | P::Alias => self.cause == E::Policy && self.detail.is_none(),
            P::RecheckIdentity => self.cause == E::Policy && matches!(self.detail,
                Some(D::Identity | D::Kind | D::Attributes | D::Creation | D::File)),
            P::MappingAfter if self.cause == E::Policy => self.detail == Some(D::MappingChanged),
            P::Decode | P::RootDecode => matches!(self.cause, E::Unsafe | E::Bounds | E::State) && self.detail.is_none(),
            P::Reserve => matches!(self.cause, E::Bounds | E::State) && self.detail.is_none(),
            _ => matches!(self.cause, E::Unavailable | E::Unsafe | E::Bounds | E::State) && self.detail.is_none(),
        };
        kind && self.native.is_none_or(|value| (self.cause == E::Unavailable || self.stage == P::Getter) && value.valid(self.stage))
            && self.admission.is_none_or(|value| self.cause == E::Unsafe && probe_admission_valid(self.stage, value))
    }
    pub(super) fn json(self) -> Result<String> {
        if !self.valid() { return Err(Error::Unsafe); }
        let optional = |value: Option<&str>| value.map_or_else(|| "null".to_owned(), |value| format!("\"{value}\""));
        let native = self.native.map_or_else(|| "null".to_owned(), |value| {
            let (domain, code) = match value.status {
                ProbeStatus::Win32(code) => ("win32", i64::from(code)), ProbeStatus::Nt(code) => ("ntstatus", i64::from(code)),
                ProbeStatus::Hresult(code) => ("hresult", i64::from(code)),
            };
            format!("{{\"operation\":\"{}\",\"domain\":\"{domain}\",\"code\":{code}}}", value.operation.label())
        });
        let admission = self.admission.map_or_else(|| "null".to_owned(), |value| format!(
            "{{\"operation\":\"{}\",\"check\":\"{}\",\"index\":{}}}", value.operation.label(), value.check.label(),
            value.index.map_or_else(|| "null".to_owned(), |index| index.to_string())));
        let raw = format!("{{\"schemaVersion\":1,\"stage\":\"{}\",\"pathIndex\":{},\"cause\":\"{}\",\"detail\":{},\"native\":{native},\"admission\":{admission}}}",
            self.stage.label(), self.path.map_or_else(|| "null".to_owned(), |index| index.to_string()),
            self.cause.label(), optional(self.detail.map(ProbeDetail::label)));
        if raw.len() > 768 { Err(Error::Bounds) } else { Ok(raw) }
    }
    pub(super) fn parse(raw: &str) -> Option<Self> {
        // Only the closed canonical fragment is decoded; its entire envelope is
        // still reconstructed and byte-compared by UiRequest::accept_child.
        if raw.len() > 768 || !raw.is_ascii() { return None; }
        let (stage, tail) = raw.strip_prefix("{\"schemaVersion\":1,\"stage\":\"")?.split_once("\",\"pathIndex\":")?;
        let (path, tail) = tail.split_once(",\"cause\":\"")?;
        let (cause, tail) = tail.split_once("\",\"detail\":")?;
        let (detail, tail) = tail.split_once(",\"native\":")?;
        let (native, admission) = tail.split_once(",\"admission\":")?;
        let admission = admission.strip_suffix('}')?;
        let value = Self {
            stage: ProbeStage::from_label(stage)?, path: if path == "null" { None } else { Some(path.parse().ok()?) },
            cause: ProbeCause::from_label(cause)?, detail: if detail == "null" { None }
                else { Some(ProbeDetail::from_label(detail.strip_prefix('"')?.strip_suffix('"')?)?) },
            native: if native == "null" { None } else {
                let (operation, tail) = native.strip_prefix("{\"operation\":\"")?.split_once("\",\"domain\":\"")?;
                let (domain, code) = tail.split_once("\",\"code\":")?;
                let code = code.strip_suffix('}')?;
                Some(ProbeNative { operation: ProbeOperation::from_label(operation)?, status: match domain {
                    "win32" => ProbeStatus::Win32(code.parse().ok()?), "ntstatus" => ProbeStatus::Nt(code.parse().ok()?),
                    "hresult" => ProbeStatus::Hresult(code.parse().ok()?), _ => return None,
                } })
            },
            admission: if admission == "null" { None } else {
                let (operation, tail) = admission.strip_prefix("{\"operation\":\"")?.split_once("\",\"check\":\"")?;
                let (check, index) = tail.split_once("\",\"index\":")?;
                let index = index.strip_suffix('}')?;
                Some(PublicationAdmissionObservation { role: AdmissionRole::RuntimeInput,
                    operation: AdmissionOp::from_label(operation)?, check: C::from_label(check)?,
                    index: if index == "null" { None } else { Some(index.parse().ok()?) } })
            },
        };
        (value.json().ok()?.as_str() == raw).then_some(value)
    }
}

#[derive(Default)]
struct ProbeTrace {
    selected: Option<(ProbeStage, Option<u8>)>, before_admission: Option<PublicationAdmissionObservation>,
    #[cfg(test)]
    before_unavailable: bool,
    first: Option<ManagedRuntimeRefusal>,
}
impl ProbeTrace {
    fn at(&mut self, stage: ProbeStage, path: Option<usize>, managed: bool, native: &NativeBook) {
        self.selected = managed.then_some((stage, path.and_then(|index| u8::try_from(index).ok())));
        self.before_admission = native.admission.first.get();
        #[cfg(test)] { self.before_unavailable = native.first_unavailable.is_some(); }
    }
    fn record(&mut self, cause: ProbeCause, detail: Option<ProbeDetail>, native: Option<ProbeNative>,
        admission: Option<PublicationAdmissionObservation>) {
        if self.first.is_none() {
            if let Some((stage, path)) = self.selected {
                self.first = Some(ManagedRuntimeRefusal { stage, path, cause, detail, native, admission });
            }
        }
    }
    fn policy(&mut self, detail: Option<ProbeDetail>) { self.record(ProbeCause::Policy, detail, None, None); }
    fn mapped<T>(&mut self, value: Result<T>, native: &NativeBook, refusal: UiError) -> UiResult<T> {
        if refusal == UiError::ManagedRuntimeUnavailable {
            if let Err(error) = &value {
                let cause = match error { Error::Unavailable => Some(ProbeCause::Unavailable), Error::Unsafe => Some(ProbeCause::Unsafe),
                    Error::Bounds => Some(ProbeCause::Bounds), Error::State => Some(ProbeCause::State), Error::Unknown => None };
                if let Some(cause) = cause {
                    #[allow(unused_mut)]
                    let mut observed = None;
                    #[cfg(test)]
                    if *error == Error::Unavailable && !self.before_unavailable {
                        observed = native.first_unavailable.and_then(|(call, returned)| ProbeNative::original(call, returned));
                    }
                    let admission = if *error == Error::Unsafe && self.before_admission.is_none() {
                        native.admission.first.get() } else { None };
                    self.record(cause, None, observed, admission);
                }
            }
        }
        mapped(value, refusal)
    }
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
struct PathOriginal {
    original: Original, metadata: Metadata, runtime_scope: Option<AuthorityScope>,
    metadata_profile: MetadataObservationProfile,
}
impl PathOriginal {
    fn matches_profile(&self, kind: FileKind, profile: MetadataObservationProfile) -> Result<()> {
        if self.metadata.kind == kind && self.metadata_profile == profile { Ok(()) } else { Err(Error::State) }
    }
    fn observe(&self, native: &mut NativeBook) -> Result<Metadata> {
        observe_path_metadata(native, &self.original, self.metadata_profile)
    }
}
fn path_metadata_profile(path: &str, kind: FileKind, protected_image: Option<&str>) -> UiResult<MetadataObservationProfile> {
    match protected_image {
        None => Ok(MetadataObservationProfile::Ordinary),
        Some(expected) if kind == FileKind::File && path == expected => Ok(MetadataObservationProfile::ManagedWebViewImage),
        Some(_) => Err(UiError::ManagedRuntimeUnavailable),
    }
}
fn observe_path_metadata(native: &mut NativeBook, original: &Original, profile: MetadataObservationProfile) -> Result<Metadata> {
    match profile {
        MetadataObservationProfile::Ordinary => native.metadata(original),
        MetadataObservationProfile::ManagedWebViewImage => native.managed_webview_image_metadata(original),
    }
}
fn path_metadata_mismatch(metadata: &Metadata, original: &Metadata) -> Option<ProbeDetail> {
    if metadata.identity != original.identity { Some(ProbeDetail::Identity) }
    else if metadata.kind != original.kind { Some(ProbeDetail::Kind) }
    else if metadata.attributes != original.attributes { Some(ProbeDetail::Attributes) }
    else if metadata.creation != original.creation { Some(ProbeDetail::Creation) }
    else if metadata.kind == FileKind::File && metadata != original { Some(ProbeDetail::File) }
    else { None }
}
fn managed_runtime_scope(depth: usize, root_depth: usize) -> AuthorityScope {
    if depth >= root_depth { AuthorityScope::ImmutableVersion } else { AuthorityScope::AncestorOutsideVersion }
}
struct NativeTextState {
    value: PWSTR, entered: bool, returned: bool, released: bool, unknown: bool,
    error_hresult: Option<i32>, read_refusal: Cell<Option<ProbeDetail>>,
}
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
        value: PWSTR::null(), entered: false, returned: false, released: false, unknown: false,
        error_hresult: None, read_refusal: Cell::new(None) })) } }
    fn complete(&mut self, result: windows::core::Result<()>) -> UiResult<()> {
        // Copy only an actual first returning Err; Ok does not expose the
        // original HRESULT through this documented wrapper. No output read.
        if self.entered && !self.returned && !self.unknown && self.error_hresult.is_none() {
            self.error_hresult = result.as_ref().err().map(|error| error.code().0);
        }
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
        if !self.entered || !self.returned || self.released { return Err(self.read_failed(ProbeDetail::TextState)); }
        if self.value.is_null() { return Err(self.read_failed(ProbeDetail::TextNull)); }
        let mut units = Vec::with_capacity(limit.min(512));
        // A successful documented getter owns a NUL-terminated CoTaskMem UTF16
        // allocation. Bound copying; never lstrlenW/lossy path conversion.
        for index in 0..limit {
            let unit = unsafe { *self.value.0.add(index) };
            if unit == 0 { return if units.is_empty() { Err(self.read_failed(ProbeDetail::TextEmpty)) }
                else { String::from_utf16(&units).map_err(|_| self.read_failed(ProbeDetail::TextUtf16)) }; }
            units.push(unit);
        }
        Err(self.read_failed(ProbeDetail::TextBound))
    }
    fn read_failed(&self, detail: ProbeDetail) -> UiError {
        if self.read_refusal.get().is_none() { self.read_refusal.set(Some(detail)); }
        UiError::NativeFailure
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
    probe: ProbeTrace,
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
        Self { native: NativeBook::new(), probe: ProbeTrace::default(), paths: Vec::new(), input_desktop: null_mut(),
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
    #[cfg(test)]
    pub(super) fn managed_refusal(&self, observed: &UiResult<PrerequisiteFacts>) -> Option<ManagedRuntimeRefusal> {
        if !self.settled() || !matches!(observed, Err(UiError::ManagedRuntimeUnavailable)) { return None; }
        self.probe.first.filter(|value| value.valid())
    }
    pub fn inspect(&mut self) -> UiResult<PrerequisiteFacts> {
        self.overrides.refusal.reset();
        if self.begun || self.final_attempted || self.unknown { return Err(UiError::State); }
        self.begun = true;
        self.native.admission.active.set(true);
        self.native.admission.role.set(AdmissionRole::RuntimeInput);
        let result = self.inspect_inner();
        self.native.admission.active.set(false); // Cleanup cannot overwrite the original first refusal.
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
            || unsafe { RD::ProcessIdToSessionId(T::GetCurrentProcessId(), &mut self.session) } == 0
            || self.session == 0 { return Err(UiError::InteractiveDesktop); }
        // These are the intended account's actual originals, not the CI runner's
        // station. Do not change a DACL, switch a desktop, or assume lpDesktop.
        self.input_desktop = unsafe { D::OpenInputDesktop(0, 0,
            D::DESKTOP_READOBJECTS | D::DESKTOP_CREATEWINDOW | D::DESKTOP_WRITEOBJECTS) };
        if self.input_desktop.is_null() { return Err(UiError::InteractiveDesktop); }
        self.session_check()?;
        overrides_absent(&mut self.overrides)?;
        self.probe.at(ProbeStage::Getter, None, true, &self.native);
        self.runtime_text.entered = true;
        let result = unsafe { WV::GetAvailableCoreWebView2BrowserVersionString(PCWSTR::null(), &mut self.runtime_text.value) };
        self.runtime_text.complete(result).map_err(|error| {
            if error == UiError::CleanupUnknown { error } else {
                self.probe.record(ProbeCause::Native, None, self.runtime_text.error_hresult.map(|code|
                    ProbeNative { operation: ProbeOperation::Getter, status: ProbeStatus::Hresult(code) }), None);
                UiError::ManagedRuntimeUnavailable
            }
        })?;
        self.probe.at(ProbeStage::Text, None, true, &self.native);
        let version = self.runtime_text.read(96).map_err(|_| {
            self.probe.record(ProbeCause::Native, self.runtime_text.read_refusal.get(), None, None);
            UiError::ManagedRuntimeUnavailable
        })?;
        self.probe.at(ProbeStage::Version, None, true, &self.native);
        if let Some(detail) = version_refusal(&version) {
            self.probe.policy(Some(detail)); return Err(UiError::ManagedRuntimeUnavailable);
        }
        self.program_files = known_folder(SH::CSIDL_PROGRAM_FILESX86 as i32)?;
        self.local_data = known_folder(SH::CSIDL_LOCAL_APPDATA as i32).map_err(|_| UiError::UserDataParent)?;
        self.image_dos = format!("{}\\Microsoft\\EdgeWebView\\Application\\{}\\{}", self.program_files, version, MANAGED_WEBVIEW_IMAGE);
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
        if unsafe { RD::ProcessIdToSessionId(T::GetCurrentProcessId(), &mut session) } == 0 || session != self.session {
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
        self.probe.at(ProbeStage::Decode, None, protected, &self.native);
        let result = decode::dos_location(path);
        let (drive, components) = self.probe.mapped(result, &self.native, refusal)?;
        self.probe.at(ProbeStage::Depth, None, protected, &self.native);
        if components.len() > 20 { self.probe.policy(None); return Err(refusal); }
        // Only the exact getter-version-selected final image takes the provider
        // profile. Every ancestor and all local-data paths remain ordinary.
        let final_profile = path_metadata_profile(path, kind, if protected { Some(&self.image_dos) } else { None })?;
        let runtime_depth = if protected {
            let root = format!("{}\\Microsoft\\EdgeWebView", self.program_files);
            self.probe.at(ProbeStage::RootDecode, None, true, &self.native);
            let result = decode::dos_location(&root);
            let (root_drive, root_components) = self.probe.mapped(result, &self.native, refusal)?;
            // Exact decoded ancestry, never a string-prefix/suffix alias.
            self.probe.at(ProbeStage::Ancestry, None, true, &self.native);
            if drive != root_drive || components.len() <= root_components.len()
                || !components.starts_with(&root_components) {
                self.probe.policy(None); return Err(refusal);
            }
            Some(root_components.len())
        } else { None };
        self.probe.at(ProbeStage::MappingBefore, None, protected, &self.native);
        let result = self.native.mapping(&drive);
        let device = self.probe.mapped(result, &self.native, refusal)?;
        let root_name = format!("{device}\\");
        let mut index = if let Some(index) = self.paths.iter().position(|entry|
            self.native.slot(entry.original.index).is_ok_and(|slot| slot.canonical == root_name)) {
            self.probe.at(ProbeStage::RootMetadata, None, protected, &self.native);
            self.probe.mapped(self.paths[index].matches_profile(FileKind::Directory, MetadataObservationProfile::Ordinary), &self.native, refusal)?;
            index
        } else {
            // No pathIndex exists until its actual PathOriginal is bound below.
            self.probe.at(ProbeStage::Reserve, None, protected, &self.native);
            let result = self.native.reserve(Kind::Directory, None, &root_name, root_name.clone());
            let original = self.probe.mapped(result, &self.native, refusal)?;
            self.probe.at(ProbeStage::RootOpen, None, protected, &self.native);
            let result = self.native.call(Call::Open(original.index), null_mut(), Vec::new());
            self.probe.mapped(result, &self.native, refusal)?;
            self.probe.at(ProbeStage::RootMetadata, None, protected, &self.native);
            let result = self.native.metadata(&original);
            let metadata = self.probe.mapped(result, &self.native, refusal)?;
            self.paths.push(PathOriginal { original, metadata, runtime_scope: None,
                metadata_profile: MetadataObservationProfile::Ordinary }); self.paths.len() - 1
        };
        self.admit_path(index, runtime_depth.map(|root| managed_runtime_scope(0, root)))?;
        for (position, name) in components.iter().enumerate() {
            let parent = index; let parent_slot = self.paths[parent].original.index;
            let child_kind = if position + 1 == components.len() { kind } else { FileKind::Directory };
            let metadata_profile = if position + 1 == components.len() { final_profile } else { MetadataObservationProfile::Ordinary };
            index = if let Some(index) = self.paths.iter().position(|entry| self.native.slot(entry.original.index)
                .is_ok_and(|slot| slot.parent == Some(parent_slot) && slot.name == wide(name))) {
                self.probe.at(ProbeStage::ChildMetadata, None, protected, &self.native);
                self.probe.mapped(self.paths[index].matches_profile(child_kind, metadata_profile), &self.native, refusal)?;
                index
            } else {
                self.probe.at(ProbeStage::ChildOpen, None, protected, &self.native);
                let result = self.native.open_child(&self.paths[parent].original, name, child_kind);
                let original = self.probe.mapped(result, &self.native, refusal)?;
                self.probe.at(ProbeStage::ChildMetadata, None, protected, &self.native);
                let result = observe_path_metadata(&mut self.native, &original, metadata_profile);
                let metadata = self.probe.mapped(result, &self.native, refusal)?;
                self.probe.at(ProbeStage::Alias, None, protected, &self.native);
                if self.paths.iter().any(|entry| entry.metadata.identity == metadata.identity) {
                    self.probe.policy(None); return Err(refusal);
                }
                self.paths.push(PathOriginal { original, metadata, runtime_scope: None, metadata_profile }); self.paths.len() - 1
            };
            self.admit_path(index, runtime_depth.map(|root| managed_runtime_scope(position + 1, root)))?;
        }
        self.probe.at(ProbeStage::MappingAfter, None, protected, &self.native);
        let result = self.native.mapping(&drive);
        if self.probe.mapped(result, &self.native, refusal)? != device {
            self.probe.policy(Some(ProbeDetail::MappingChanged)); return Err(refusal);
        }
        Ok(index)
    }
    fn admit_path(&mut self, index: usize, scope: Option<AuthorityScope>) -> UiResult<()> {
        let entry = self.paths.get_mut(index).ok_or(UiError::State)?;
        let refusal = if scope.is_some() { UiError::ManagedRuntimeUnavailable } else { UiError::UserDataParent };
        self.probe.at(ProbeStage::Ntfs, Some(index), scope.is_some(), &self.native);
        let result = self.native.local_ntfs(&entry.original);
        self.probe.mapped(result, &self.native, refusal)?;
        self.probe.at(ProbeStage::Streams, Some(index), scope.is_some(), &self.native);
        let result = self.native.no_alternate_streams(&entry.original);
        self.probe.mapped(result, &self.native, refusal)?;
        if let Some(scope) = scope {
            // Internal runtime directories must reject untrusted child creation,
            // not only writes to the final executable. Cached originals retain
            // their strongest admitted scope through all later rechecks.
            let scope = if entry.runtime_scope == Some(AuthorityScope::ImmutableVersion) {
                AuthorityScope::ImmutableVersion } else { scope };
            self.probe.at(ProbeStage::Security, Some(index), true, &self.native);
            let result = self.native.security(&entry.original, scope);
            self.probe.mapped(result, &self.native, UiError::ManagedRuntimeUnavailable)?;
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
        for (index, entry) in self.paths.iter().enumerate() {
            let managed = entry.runtime_scope.is_some();
            let refusal = if managed { UiError::ManagedRuntimeUnavailable } else { UiError::UserDataParent };
            self.probe.at(ProbeStage::RecheckMetadata, Some(index), managed, &self.native);
            let result = entry.observe(&mut self.native);
            let metadata = self.probe.mapped(result, &self.native, refusal)?;
            // Same short-circuit equality order; retain only the rejecting tag.
            self.probe.at(ProbeStage::RecheckIdentity, Some(index), managed, &self.native);
            let detail = path_metadata_mismatch(&metadata, &entry.metadata);
            if let Some(detail) = detail { self.probe.policy(Some(detail)); return Err(refusal); }
            if let Some(scope) = entry.runtime_scope {
                self.probe.at(ProbeStage::RecheckSecurity, Some(index), true, &self.native);
                let result = self.native.security(&entry.original, scope);
                self.probe.mapped(result, &self.native, UiError::ManagedRuntimeUnavailable)?;
            }
        }
        Ok(())
    }
    pub fn recheck(&mut self) -> UiResult<()> {
        self.overrides.refusal.reset();
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

fn version_refusal(value: &str) -> Option<ProbeDetail> {
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 4 { return Some(ProbeDetail::VersionCount); }
    for part in &parts {
        if part.is_empty() { return Some(ProbeDetail::VersionEmpty); }
        if part.len() > 5 { return Some(ProbeDetail::VersionWidth); }
        if part.len() != 1 && part.starts_with('0') { return Some(ProbeDetail::VersionZero); }
        if !part.bytes().all(|byte| byte.is_ascii_digit()) { return Some(ProbeDetail::VersionDigits); }
        if part.parse::<u16>().is_err() { return Some(ProbeDetail::VersionRange); }
    }
    if !parts[0].parse::<u16>().is_ok_and(|major| major >= 120) { return Some(ProbeDetail::VersionMajor); }
    None
}
fn stable_version(value: &str) -> bool { version_refusal(value).is_none() }
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
// precedence, plus the full per-user EdgeUpdate Clients registration container.
// Generic EdgeWebView registry-root presence alone does not establish a documented
// override or installation. Admission still requires the actual protected system
// image, matching runtime version/user-data folder and original browser binding.
const OVERRIDE_KEYS: &[(&str, bool)] = &[
    ("SOFTWARE\\Policies\\Microsoft\\Edge\\WebView2", false),
    ("SOFTWARE\\Microsoft\\Edge\\WebView2", false),
    ("SOFTWARE\\Microsoft\\EdgeUpdate\\Clients", true),
];
struct RegistryOriginal {
    name: Vec<u16>, value: UnsafeCell<R::HKEY>, entered: bool, returned: bool, close_entered: bool, settled: bool,
}
struct RegistryAudit { originals: Vec<Held<RegistryOriginal>>, unknown: bool, refusal: OverrideObservation }
impl RegistryAudit {
    fn new() -> Self { Self { originals: Vec::new(), unknown: false, refusal: OverrideObservation::default() } }
    fn absent(&mut self, root: R::HKEY, name: &[u16], view: u32, probe: Option<OverrideProbe>) -> UiResult<()> {
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
            original.settled = true;
            self.refusal.note(OverrideRefusal::registry(probe, OverrideOpen::Present));
            return Err(UiError::RuntimeOverrides);
        }
        if !handle.is_null() { self.unknown = true; return Err(UiError::CleanupUnknown); }
        original.settled = true;
        self.refusal.note(OverrideRefusal::registry(probe, if result == F::ERROR_SUCCESS {
            OverrideOpen::SuccessNull
        } else { OverrideOpen::OtherStatusNull }));
        Err(UiError::RuntimeOverrides)
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
    audit.refusal.reset();
    use std::os::windows::ffi::OsStrExt;
    for (name, _) in std::env::vars_os() {
        let units: Vec<u16> = name.encode_wide().collect();
        let prefix: Vec<u16> = "WEBVIEW2_".encode_utf16().collect();
        if units.len() >= prefix.len() && units[..prefix.len()].iter().zip(&prefix)
            .all(|(left, right)| *left == *right || *left >= b'a' as u16 && *left <= b'z' as u16 && *left - 32 == *right) {
            audit.refusal.note(Some(OverrideRefusal::ENVIRONMENT));
            return Err(UiError::RuntimeOverrides);
        }
    }
    for (key_index, (key, user_only)) in OVERRIDE_KEYS.iter().enumerate() {
        for (hive_index, root) in [R::HKEY_CURRENT_USER, R::HKEY_LOCAL_MACHINE].iter().copied().enumerate() {
            if *user_only && root != R::HKEY_CURRENT_USER { continue; }
            for (view_index, view) in [R::KEY_WOW64_32KEY, R::KEY_WOW64_64KEY].iter().copied().enumerate() {
                let probe = OverrideProbe::from_parts(key_index, hive_index, view_index);
                audit.absent(root, &wide(key), view, probe)?;
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
    browser: Cell<u32>, exited: Cell<bool>, on_loss: Box<dyn Fn(Loss)>,
    exit_args: OnceCell<ComOriginal<WV::ICoreWebView2BrowserProcessExitedEventArgs>>, exit_pid: ComValue<u32>,
}
impl WatchCallbacks {
    fn lost(&self, reason: Loss) {
        let reason = if self.unknown.get() { Loss::CallbackUnknown } else { reason };
        if !self.lost.replace(true)
            && std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.on_loss)(reason))).is_err() { self.unknown.set(true); }
    }
    fn enter(&self) -> CallbackReturn<'_> {
        if unsafe { T::GetCurrentThreadId() } != self.thread { self.unknown.set(true); }
        self.depth.set(self.depth.get().saturating_add(1)); CallbackReturn(self)
    }
    fn browser_exited(&self, args: Option<WV::ICoreWebView2BrowserProcessExitedEventArgs>) {
        if self.exit_args.get().is_some() { self.unknown.set(true); self.lost(Loss::BrowserExited); return; }
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
        self.lost(Loss::BrowserExited);
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
    install_stage: Cell<(Stage, u8)>,
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
        install_stage: Cell::new((Stage::None, 0)),
        begun: false, installed: false, close_entered: false, controller_closed: false,
        process_close_entered: false, released: false, unknown: false,
    } }
    fn stage(&self, stage: Stage, record: &dyn Fn(NativeMark)) {
        self.install_stage.set((stage, 0)); record(NativeMark { stage, part: 0, error: None });
    }
    fn substage(&self, part: u8, record: &dyn Fn(NativeMark)) {
        let (stage, _) = self.install_stage.get();
        self.install_stage.set((stage, part)); record(NativeMark { stage, part, error: None });
    }
    fn callbacks(&self) -> UiResult<&WatchCallbacks> { self.callbacks.as_deref().ok_or(UiError::State) }
    fn fail<T>(&mut self, error: UiError) -> UiResult<T> {
        if error == UiError::CleanupUnknown { self.unknown = true; }
        if let Some(callbacks) = &self.callbacks { callbacks.lost(Loss::Operation); }
        Err(error)
    }
    fn install(&mut self, controller: WV::ICoreWebView2Controller, environment: WV::ICoreWebView2Environment,
        prerequisites: &mut Prerequisites, data: &Path, on_loss: Box<dyn Fn(Loss)>, record: &dyn Fn(NativeMark)) -> UiResult<()> {
        // Before adoption these taps are record-only, never USER32 publication.
        self.stage(Stage::Watch, record);
        if self.begun { record(NativeMark { stage: Stage::Watch, part: 0, error: Some(NativeError::State) }); return Err(UiError::State); }
        self.begun = true;
        // Adoption precedes every post-dispatch/STOP/admission observation.
        self.controller = Some(ComOriginal::new(controller));
        self.environment = Some(ComOriginal::new(environment));
        self.callbacks = Some(Rc::new(WatchCallbacks { thread: unsafe { T::GetCurrentThreadId() },
            depth: Cell::new(0), lost: Cell::new(false), unknown: Cell::new(false), browser: Cell::new(0),
            exited: Cell::new(false), on_loss, exit_args: OnceCell::new(), exit_pid: ComValue::new() }));
        self.stage(Stage::Adopted, record);
        let result = self.install_inner(prerequisites, data, record);
        match result {
            Ok(()) => { self.installed = true; self.stage(Stage::Complete, record); Ok(()) },
            Err(error) => {
                // Record the actual returned error BEFORE fail/on_loss. The
                // borrowed error tap is record-only until that original loss.
                let (stage, part) = self.install_stage.get();
                record(NativeMark { stage, part, error: Some(error.diagnostic()) });
                self.fail(error)
            }
        }
    }
    fn install_inner(&mut self, prerequisites: &mut Prerequisites, data: &Path, record: &dyn Fn(NativeMark)) -> UiResult<()> {
        self.stage(Stage::Sta, record); sta()?;
        self.stage(Stage::Prerequisites, record);
        let recheck = prerequisites.recheck();
        let refusal = prerequisites.overrides.refusal.returned(recheck.as_ref().err().map(|error| error.diagnostic()));
        if recheck == Err(UiError::RuntimeOverrides) {
            if let Some(refusal) = refusal { self.install_stage.set((Stage::WatchOverrideAudit, refusal.code())); }
        }
        recheck?;
        self.stage(Stage::Controller, record);
        let controller = self.controller.as_ref().ok_or(UiError::State)?;
        self.substage(1, record); let controller = controller.get()?;
        self.stage(Stage::CoreOutput, record);
        let core_output = self.core_output.begin()?;
        self.stage(Stage::Core, record);
        let core = unsafe { (controller.vtable().CoreWebView2)(controller.as_raw(), core_output) };
        self.core = Some(ComOriginal::new(self.core_output.complete(core)?));
        self.stage(Stage::ParentOutput, record);
        let parent_output = self.parent_output.begin()?;
        self.stage(Stage::Parent, record);
        self.parent = self.parent_output.complete(unsafe { controller.ParentWindow(parent_output) })?;
        self.stage(Stage::ParentPresent, record);
        let mut process_id = 0;
        if self.parent.0.is_null() { return Err(UiError::OrdinaryContext); }
        self.stage(Stage::ParentIdentity, record);
        if unsafe { W::GetWindowThreadProcessId(self.parent.0, &mut process_id) } != prerequisites.thread { return Err(UiError::OrdinaryContext); }
        self.stage(Stage::ParentProcess, record);
        if process_id != unsafe { T::GetCurrentProcessId() } { return Err(UiError::OrdinaryContext); }
        self.stage(Stage::Environment, record);
        let environment = self.environment.as_ref().ok_or(UiError::State)?;
        self.substage(1, record); let environment = environment.get()?;
        self.stage(Stage::Environment5Output, record);
        let environment5_output = self.environment5_output.begin()?;
        self.stage(Stage::Environment5, record);
        let environment5 = unsafe { (environment.vtable().base__.QueryInterface)(environment.as_raw(),
            &WV::ICoreWebView2Environment5::IID, environment5_output) };
        self.environment5 = Some(ComOriginal::new(self.environment5_output.complete(environment5)?));
        self.stage(Stage::Environment7Output, record);
        let environment7_output = self.environment7_output.begin()?;
        self.stage(Stage::Environment7, record);
        let environment7 = unsafe { (environment.vtable().base__.QueryInterface)(environment.as_raw(),
            &WV::ICoreWebView2Environment7::IID, environment7_output) };
        self.environment7 = Some(ComOriginal::new(self.environment7_output.complete(environment7)?));
        self.stage(Stage::Version, record);
        self.version.entered = true;
        let version = unsafe { environment.BrowserVersionString(&mut self.version.value) };
        self.version.complete(version)?;
        {
            self.stage(Stage::VersionText, record); let version = self.version.read(96)?;
            self.stage(Stage::VersionMatch, record);
            if version != prerequisites.facts.as_ref().ok_or(UiError::State)?.runtime_version { return Err(UiError::ManagedRuntimeUnavailable); }
        }
        self.stage(Stage::FolderEnvironment, record);
        self.user_data.entered = true;
        let environment7 = self.environment7.as_ref().ok_or(UiError::State)?;
        self.substage(1, record); let environment7 = environment7.get()?;
        self.stage(Stage::Folder, record);
        let folder = unsafe { environment7.UserDataFolder(&mut self.user_data.value) };
        self.user_data.complete(folder)?;
        {
            self.stage(Stage::FolderText, record); let folder = self.user_data.read(NAME_UNITS)?;
            self.stage(Stage::FolderMatch, record);
            if Path::new(&folder) != data { return Err(UiError::UserDataParent); }
        }
        self.stage(Stage::FailedHandler, record);
        let callbacks = self.callbacks.as_ref().ok_or(UiError::State)?.clone();
        self.failed_handler = Some(ComOriginal::new(webview2_com::ProcessFailedEventHandler::create(Box::new(move |_, _| {
            let _return = callbacks.enter(); callbacks.lost(Loss::ProcessFailed); Ok(())
        }))));
        self.stage(Stage::ExitedHandler, record);
        let callbacks = self.callbacks.as_ref().ok_or(UiError::State)?.clone();
        self.exited_handler = Some(ComOriginal::new(webview2_com::BrowserProcessExitedEventHandler::create(Box::new(move |_, args| {
            let _return = callbacks.enter(); callbacks.browser_exited(args); Ok(())
        }))));
        self.stage(Stage::BrowserOutput, record);
        let browser_output = self.browser_output.begin()?;
        self.stage(Stage::BrowserCore, record);
        let core = self.core.as_ref().ok_or(UiError::State)?;
        self.substage(1, record); let core = core.get()?;
        self.stage(Stage::BrowserPid, record);
        let pid = self.browser_output.complete(unsafe { core.BrowserProcessId(browser_output) })?;
        self.stage(Stage::BrowserPidCheck, record);
        if pid == 0 { return Err(UiError::NativeFailure); }
        self.stage(Stage::BrowserLost, record);
        if self.callbacks()?.lost.get() { return Err(UiError::NativeFailure); }
        self.stage(Stage::BrowserBind, record);
        self.callbacks()?.browser.set(pid);
        self.stage(Stage::ProcessOpen, record);
        self.process = unsafe { T::OpenProcess(T::PROCESS_QUERY_LIMITED_INFORMATION | FS::SYNCHRONIZE, 0, pid) };
        self.stage(Stage::ProcessHandle, record);
        if !valid_handle(self.process) { return Err(UiError::NativeFailure); }
        self.stage(Stage::ProcessIdentity, record);
        if unsafe { T::GetProcessId(self.process) } != pid { return Err(UiError::NativeFailure); }
        self.stage(Stage::InitialWait, record);
        if unsafe { T::WaitForSingleObject(self.process, 0) } != F::WAIT_TIMEOUT { return Err(UiError::NativeFailure); }
        self.stage(Stage::ImageQuery, record);
        let mut image = [0u16; NAME_UNITS]; let mut count = image.len() as u32;
        if unsafe { T::QueryFullProcessImageNameW(self.process, 0, image.as_mut_ptr(), &mut count) } == 0 { return Err(UiError::ManagedRuntimeUnavailable); }
        self.stage(Stage::ImageLength, record);
        if count == 0 { return Err(UiError::ManagedRuntimeUnavailable); }
        self.stage(Stage::ImageFit, record);
        if count as usize >= image.len() { return Err(UiError::ManagedRuntimeUnavailable); }
        self.stage(Stage::ImageText, record);
        let path = String::from_utf16(&image[..count as usize]).map_err(|_| UiError::ManagedRuntimeUnavailable)?;
        self.stage(Stage::ImageMatch, record);
        if !path.eq_ignore_ascii_case(&prerequisites.image_dos) { return Err(UiError::ManagedRuntimeUnavailable); }
        // Correspondence with the SAME protected executable original, not just
        // a version string, a numeric PID, or a new pathname open after launch.
        self.stage(Stage::ProtectedImage, record);
        let image = prerequisites.image.ok_or(UiError::State)?;
        let observed = mapped(prerequisites.paths[image].observe(&mut prerequisites.native), UiError::ManagedRuntimeUnavailable)?;
        self.stage(Stage::ProtectedMatch, record);
        if observed != prerequisites.paths[image].metadata { return Err(UiError::ManagedRuntimeUnavailable); }
        // Expected browser identity is installed before either callback can run.
        self.stage(Stage::FailedCore, record);
        self.failed_token.entered = true;
        let core = self.core.as_ref().ok_or(UiError::State)?;
        self.substage(1, record); let core = core.get()?;
        self.stage(Stage::FailedHandlerSlot, record);
        let handler = self.failed_handler.as_ref().ok_or(UiError::State)?;
        self.substage(1, record); let handler = handler.get()?;
        self.stage(Stage::FailedRegistration, record);
        let registered = unsafe { core.add_ProcessFailed(handler, &mut self.failed_token.value) };
        self.failed_token.complete(registered)?;
        self.stage(Stage::ExitedEnvironment, record);
        self.exited_token.entered = true;
        let environment5 = self.environment5.as_ref().ok_or(UiError::State)?;
        self.substage(1, record); let environment5 = environment5.get()?;
        self.stage(Stage::ExitedHandlerSlot, record);
        let handler = self.exited_handler.as_ref().ok_or(UiError::State)?;
        self.substage(1, record); let handler = handler.get()?;
        self.stage(Stage::ExitedRegistration, record);
        let registered = unsafe { environment5.add_BrowserProcessExited(handler, &mut self.exited_token.value) };
        self.exited_token.complete(registered)?;
        self.stage(Stage::FinalWait, record);
        if unsafe { T::WaitForSingleObject(self.process, 0) } != F::WAIT_TIMEOUT { return Err(UiError::NativeFailure); }
        self.stage(Stage::CallbackState, record);
        if self.callbacks()?.lost.get() { return Err(UiError::NativeFailure); }
        self.stage(Stage::CallbackUnknown, record);
        if self.callbacks()?.unknown.get() { return Err(UiError::NativeFailure); }
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
        self.close_entered = true; self.callbacks()?.lost(Loss::Stop);
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
        on_loss: Box<dyn Fn(Loss)>, record: &dyn Fn(NativeMark)) -> UiResult<()> {
        record(NativeMark { stage: Stage::Session, part: 0, error: None });
        if !self.construction_started {
            record(NativeMark { stage: Stage::Session, part: 0, error: Some(NativeError::State) }); return Err(UiError::State);
        }
        record(NativeMark { stage: Stage::SessionState, part: 0, error: None });
        if self.unknown {
            record(NativeMark { stage: Stage::SessionState, part: 0, error: Some(NativeError::State) }); return Err(UiError::State);
        }
        record(NativeMark { stage: Stage::Profile, part: 0, error: None });
        let path = match self.profile.path() {
            Ok(path) => path.to_path_buf(),
            Err(error) => { record(NativeMark { stage: Stage::Profile, part: 0, error: Some(error.diagnostic()) }); return Err(error); }
        };
        self.watch.install(controller, environment, &mut self.prerequisites, &path, on_loss, record)
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
    pub fn mark_unknown(&mut self) { self.unknown = true; if let Some(callbacks) = &self.watch.callbacks { callbacks.lost(Loss::Operation); } }
    #[cfg(feature = "windows-installed-observation")]
    pub fn observed_finality(&self) -> UiResult<bool> {
        sta()?;
        Ok(self.finality && !self.unknown && self.profile.settled() && self.prerequisites.settled()
            && self.watch.released && self.watch.failed_token.settled() && self.watch.exited_token.settled()
            && self.watch.process.is_null() && self.watch.callbacks.as_ref().is_some_and(|callbacks|
                callbacks.depth.get() == 0 && callbacks.exited.get() && !callbacks.unknown.get()))
    }
}

// Called by the existing selected unavailable-probe wrapper; no additional
// native selector or harness. These are inert allocations/scalars only.
#[cfg(test)]
pub(super) fn prerequisite_refusal_contract(request: &super::qualification_result::UiRequest) {
    use ProbeCause as E;
    use ProbeDetail as D;
    use ProbeStage as P;
    let digest = "a".repeat(64); let account = "b".repeat(64);
    let sample = |stage| {
        let mut value = ManagedRuntimeRefusal { stage, path: None, cause: E::Unsafe, detail: None, native: None, admission: None };
        match stage {
            P::Getter => { value.cause = E::Native; value.native = Some(ProbeNative {
                operation: ProbeOperation::Getter, status: ProbeStatus::Hresult(0x80070002u32 as i32) }); },
            P::Text => { value.cause = E::Native; value.detail = Some(D::TextNull); },
            P::Version => { value.cause = E::Policy; value.detail = Some(D::VersionMajor); },
            P::Depth | P::Ancestry | P::Alias => value.cause = E::Policy,
            P::Reserve => value.cause = E::State,
            P::Ntfs | P::Streams | P::Security | P::RecheckMetadata | P::RecheckSecurity => value.path = Some(0),
            P::RecheckIdentity => { value.path = Some(0); value.cause = E::Policy; value.detail = Some(D::Identity); },
            _ => {},
        }
        value
    };
    for &stage in P::ALL {
        let value = sample(stage); assert!(value.valid());
        let raw = value.json().expect("closed diagnostic"); assert!(raw.len() <= 768);
        assert_eq!(ManagedRuntimeRefusal::parse(&raw), Some(value));
        let result = request.probe_result(&digest, &account, Some("managed-webview2"), None, Some(&value)).expect("closed child");
        assert!(result.len() <= 4096);
        assert_eq!(request.accept_child(result.as_bytes(), &digest, &account), Ok(false));
        assert!(request.probe_result(&digest, &account, None, Some("130.0.1.2"), Some(&value)).is_err());
        assert!(request.probe_result(&digest, &account, Some("interactive-desktop"), None, Some(&value)).is_err());
        for altered in [raw.replace("\"schemaVersion\":1", "\"schemaVersion\":true"),
            raw.replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"extra\":0"),
            raw.replace("\"stage\":", "\"stage\":\"version-getter\",\"stage\":"),
            raw.replace(stage.label(), "unknown-stage")] {
            assert!(ManagedRuntimeRefusal::parse(&altered).is_none());
        }
        // A pre-bind stage must not claim an index; bound stages cannot omit it.
        let mut bad = value; bad.path = if value.path.is_none() { Some(0) } else { None }; assert!(!bad.valid());
        bad.path = Some(48); assert!(!bad.valid());
    }
    assert!(request.probe_result(&digest, &account, Some("managed-webview2"), None, None).is_err());
    let rich = ManagedRuntimeRefusal { path: Some(47), admission: Some(PublicationAdmissionObservation {
        role: AdmissionRole::RuntimeInput, operation: AdmissionOp::SecurityAncestor, check: C::AceDangerousRights, index: Some(2047),
    }), ..sample(P::RecheckSecurity) };
    let raw = rich.json().expect("bounded rich original");
    assert_eq!(ManagedRuntimeRefusal::parse(&raw), Some(rich));
    for (from, to) in [("2047", "2048"), ("2047", "true"), ("2047", "02047"), ("47", "48"),
        ("security-ancestor", "metadata"), ("ace-dangerous-rights", "token-primary"), ("unsafe", "unavailable")] {
        assert!(ManagedRuntimeRefusal::parse(&raw.replace(from, to)).is_none());
    }
    let getter = sample(P::Getter); let raw = getter.json().expect("getter");
    for code in ["0", "1", "-2147483638", "-2147483649", "4294967295", "true", "-02147483648"] {
        assert!(ManagedRuntimeRefusal::parse(&raw.replace("-2147024894", code)).is_none());
    }
    for domain in ["win32", "ntstatus", "unknown"] {
        assert!(ManagedRuntimeRefusal::parse(&raw.replace("hresult", domain)).is_none());
    }
    assert!(ManagedRuntimeRefusal::parse(&"x".repeat(769)).is_none());
    let result = request.probe_result(&digest, &account, Some("managed-webview2"), None, Some(&rich)).expect("rich child");
    for (from, to) in [("\"available\":false", "\"available\":true"), ("\"originalsSettled\":true", "\"originalsSettled\":false"),
        ("managedRuntimeRefusal", "unrecognized"), ("\"noWebviewCreated\":true", "\"noWebviewCreated\":false")] {
        assert!(request.accept_child(result.replace(from, to).as_bytes(), &digest, &account).is_err());
    }
    assert!(request.accept_child(result.as_bytes(), &"c".repeat(64), &account).is_err());
    assert!(request.accept_child(result.as_bytes(), &digest, &"c".repeat(64)).is_err());

    for (version, detail) in [("", D::VersionCount), ("130..1.2", D::VersionEmpty), ("130.123456.1.2", D::VersionWidth),
        ("0130.0.1.2", D::VersionZero), ("130.0.1.a", D::VersionDigits), ("130.65536.1.2", D::VersionRange),
        ("119.0.1.2", D::VersionMajor), ("130.0.1.2 beta", D::VersionWidth)] {
        assert_eq!(version_refusal(version), Some(detail)); assert!(!stable_version(version));
    }
    for version in ["120.0.0.0", "130.0.1.2", "65535.65535.65535.65535"] { assert!(stable_version(version)); }
    let mut text = NativeText::new();
    assert_eq!(text.read(96), Err(UiError::NativeFailure)); assert_eq!(text.read_refusal.get(), Some(D::TextState));
    text.entered = true; assert_eq!(text.complete(Ok(())), Ok(()));
    assert_eq!(text.read(96), Err(UiError::NativeFailure)); assert_eq!(text.read_refusal.get(), Some(D::TextState));
    text.released = true; // No native allocation exists; do not call CoTaskMemFree.
    for (units, detail) in [(vec![0], D::TextEmpty), (vec![0xd800, 0], D::TextUtf16), (vec![65, 66], D::TextBound)] {
        let mut text = NativeText::new(); let mut units = units;
        text.entered = true; text.value = PWSTR(units.as_mut_ptr()); assert_eq!(text.complete(Ok(())), Ok(()));
        assert_eq!(text.read(units.len()), Err(UiError::NativeFailure)); assert_eq!(text.read_refusal.get(), Some(detail));
        text.value = PWSTR::null(); text.released = true; // Rust DATA buffer, never native allocated.
    }
    let mut contradictory = NativeText::new(); contradictory.entered = true; contradictory.value = PWSTR(1usize as *mut u16);
    assert_eq!(contradictory.complete(windows::core::HRESULT(0x80004005u32 as i32).ok()), Err(UiError::CleanupUnknown));
    assert_eq!(contradictory.read(96), Err(UiError::CleanupUnknown));
    contradictory.value = PWSTR::null(); contradictory.released = true; // Inert sentinel, no native free.

    struct InertProbe(Prerequisites);
    impl Drop for InertProbe {
        fn drop(&mut self) {
            if let Some(frame) = self.0.native.active.take() { drop(ManuallyDrop::into_inner(frame)); }
            for slot in self.0.native.slots.drain(..) { drop(ManuallyDrop::into_inner(slot)); }
            self.0.runtime_text.released = true; // This fixture never entered the getter.
        }
    }
    let refusal = UiError::ManagedRuntimeUnavailable;
    let mut fixture = InertProbe(Prerequisites::new()); let p = &mut fixture.0;
    p.probe.at(P::RootOpen, None, true, &p.native);
    let original = p.native.reserve(Kind::Directory, None, "inert", "inert".to_owned()).expect("inert reserve");
    super::tests::enter_inert(&mut p.native, Call::Open(original.index), null_mut()).expect("inert entry");
    let returned = Returned::Nt(0xc0000022u32 as i32);
    let frame = p.native.arena().expect("inert arena"); frame.returned.set(Some(returned)); frame.phase.set(Phase::Returned);
    let value = p.native.finish(Call::Open(original.index), returned);
    assert!(matches!(value, Err(Error::Unavailable)));
    assert!(matches!(p.probe.mapped(value, &p.native, refusal), Err(UiError::ManagedRuntimeUnavailable)));
    let first = p.probe.first.expect("original returning refusal"); assert!(first.valid());
    assert_eq!(first.native, ProbeNative::original(Call::Open(original.index), returned));
    assert!(p.managed_refusal(&Err(refusal)).is_none()); // No finality from a returning error.
    p.probe.at(P::Version, None, true, &p.native); p.probe.policy(Some(D::VersionMajor));
    assert_eq!(p.probe.first, Some(first));
    // Model settled inert storage, not a native-close observation or receipt.
    p.final_attempted = true; p.runtime_text.released = true; p.native.retiring = true;
    assert_eq!(p.managed_refusal(&Err(refusal)), Some(first));
    p.unknown = true; assert!(p.managed_refusal(&Err(refusal)).is_none());
    assert!(p.managed_refusal(&Err(UiError::CleanupUnknown)).is_none());
    let mut stale = ProbeTrace::default(); stale.at(P::MappingBefore, None, true, &p.native);
    assert_eq!(stale.mapped::<()>(Err(Error::Unavailable), &p.native, refusal), Err(refusal));
    assert!(stale.first.expect("stage without stale status").native.is_none());

    let mut fixture = InertProbe(Prerequisites::new()); let p = &mut fixture.0;
    p.native.admission.active.set(true); p.native.admission.role.set(AdmissionRole::RuntimeInput);
    p.probe.at(P::RecheckSecurity, Some(0), true, &p.native);
    let error = p.native.admission.at(AdmissionOp::SecurityVersion).unsafe_at(C::AceDangerousRights);
    assert_eq!(p.probe.mapped::<()>(Err(error), &p.native, refusal), Err(refusal));
    assert!(p.probe.first.expect("original predicate").valid());
    let mut later = ProbeTrace::default(); later.at(P::MappingBefore, None, true, &p.native);
    assert_eq!(later.mapped::<()>(Err(Error::Unsafe), &p.native, refusal), Err(refusal));
    assert!(later.first.expect("stage without stale admission").admission.is_none());
    for (call, returned) in [(Call::Open(0), Returned::Nt(F::STATUS_PENDING)), (Call::Open(0), Returned::Nt(0)),
        (Call::Open(0), Returned::Nt(0x80000005u32 as i32)), (Call::Open(0), Returned::Boolean(0, 5)),
        (Call::Security, Returned::Boolean(0, F::ERROR_IO_PENDING)), (Call::Security, Returned::Boolean(1, 5)),
        (Call::Entries, Returned::Boolean(0, F::ERROR_NO_MORE_FILES))] {
        assert!(ProbeNative::original(call, returned).is_none());
    }
    let mut unknown = ProbeTrace::default(); unknown.at(P::RootOpen, None, true, &p.native);
    assert_eq!(unknown.mapped::<()>(Err(Error::Unknown), &p.native, refusal), Err(UiError::CleanupUnknown));
    assert!(unknown.first.is_none());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn managed_runtime_root_and_every_descendant_use_immutable_policy() -> Result<()> {
        // C:\Program Files (x86)\Microsoft\EdgeWebView: depth three is the
        // managed root; Application, version and the executable are inside it.
        for depth in 0..3 { assert_eq!(managed_runtime_scope(depth, 3), AuthorityScope::AncestorOutsideVersion); }
        for depth in 3..7 { assert_eq!(managed_runtime_scope(depth, 3), AuthorityScope::ImmutableVersion); }
        use MetadataObservationProfile as P;
        let image = r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\142.0.3595.65\msedgewebview2.exe";
        assert_eq!(path_metadata_profile(image, FileKind::File, Some(image)), Ok(P::ManagedWebViewImage));
        assert_eq!(path_metadata_profile(image, FileKind::File, None), Ok(P::Ordinary));
        assert_eq!(path_metadata_profile(image, FileKind::Directory, Some(image)), Err(UiError::ManagedRuntimeUnavailable));
        assert_eq!(path_metadata_profile(r"C:\other\msedgewebview2.exe", FileKind::File, Some(image)), Err(UiError::ManagedRuntimeUnavailable));
        assert!(P::ManagedWebViewImage.admits(Kind::File, &wide(MANAGED_WEBVIEW_IMAGE), false));
        for (kind, name, os_image) in [(Kind::Directory, MANAGED_WEBVIEW_IMAGE, false),
            (Kind::File, "other.exe", false), (Kind::File, MANAGED_WEBVIEW_IMAGE, true)] {
            assert!(!P::ManagedWebViewImage.admits(kind, &wide(name), os_image));
            let mut native = NativeBook::new();
            let original = native.reserve(kind, None, name, name.to_owned())?;
            if os_image { native.slot_mut(original.index)?.system_image = Some(SystemImage::Kernel32); }
            // Real entry point must reject the role before any native call;
            // all records in this fixture are inert, unentered allocations.
            assert_eq!(native.managed_webview_image_metadata(&original), Err(Error::Unsafe));
            assert!(!native.started && native.active.is_none());
            for slot in native.slots.drain(..) { drop(ManuallyDrop::into_inner(slot)); }
        }
        let mut basic = vec![0; size_of::<FS::FILE_BASIC_INFO>()];
        let mut standard = vec![0; size_of::<FS::FILE_STANDARD_INFO>()];
        let mut tag = vec![0; size_of::<FS::FILE_ATTRIBUTE_TAG_INFO>()];
        let mut id = vec![0; size_of::<FS::FILE_ID_INFO>()];
        basic[offset_of!(FS::FILE_BASIC_INFO, FileAttributes)..][..4].copy_from_slice(&FS::FILE_ATTRIBUTE_NORMAL.to_le_bytes());
        tag[offset_of!(FS::FILE_ATTRIBUTE_TAG_INFO, FileAttributes)..][..4].copy_from_slice(&FS::FILE_ATTRIBUTE_NORMAL.to_le_bytes());
        standard[offset_of!(FS::FILE_STANDARD_INFO, EndOfFile)..][..8].copy_from_slice(&37u64.to_le_bytes());
        standard[offset_of!(FS::FILE_STANDARD_INFO, AllocationSize)..][..8].copy_from_slice(&4096u64.to_le_bytes());
        id[offset_of!(FS::FILE_ID_INFO, FileId)] = 1;
        let observe = decode::Observed::new(Refusal::none());
        for links in [0u32, 1, 2, u32::MAX] {
            standard[offset_of!(FS::FILE_STANDARD_INFO, NumberOfLinks)..][..4].copy_from_slice(&links.to_le_bytes());
            assert_eq!(observe.managed_webview_image_metadata(FileKind::File, &basic, &standard, &tag, &id).is_ok(), links > 0);
            assert_eq!(observe.metadata(FileKind::File, &basic, &standard, &tag, &id).is_ok(), links == 1);
            assert_eq!(observe.system_image_metadata(FileKind::File, &basic, &standard, &tag, &id).is_ok(), links > 0);
            assert!(observe.managed_webview_image_metadata(FileKind::Directory, &basic, &standard, &tag, &id).is_err());
        }
        standard[offset_of!(FS::FILE_STANDARD_INFO, NumberOfLinks)..][..4].copy_from_slice(&2u32.to_le_bytes());
        let original_metadata = observe.managed_webview_image_metadata(FileKind::File, &basic, &standard, &tag, &id)?;
        let entry = PathOriginal { original: Original { book: Arc::new(()), index: 0 }, metadata: original_metadata.clone(),
            metadata_profile: P::ManagedWebViewImage, runtime_scope: Some(AuthorityScope::ImmutableVersion) };
        assert_eq!(entry.matches_profile(FileKind::File, P::ManagedWebViewImage), Ok(()));
        assert_eq!(entry.matches_profile(FileKind::File, P::Ordinary), Err(Error::State));
        assert_eq!(entry.matches_profile(FileKind::Directory, P::ManagedWebViewImage), Err(Error::State));
        let ordinary = PathOriginal { original: Original { book: Arc::new(()), index: 0 }, metadata: original_metadata.clone(),
            metadata_profile: P::Ordinary, runtime_scope: None };
        assert_eq!(ordinary.matches_profile(FileKind::File, P::ManagedWebViewImage), Err(Error::State));
        // Exercise the actual captured-profile dispatch used for rechecks AND
        // the browser's same-original image correspondence. Reserved, wrong-
        // role storage makes both routes refuse before any native entry.
        let mut native = NativeBook::new();
        let original = native.reserve(Kind::File, None, "other.exe", "other.exe".to_owned())?;
        let managed = PathOriginal { original, metadata: original_metadata.clone(),
            metadata_profile: P::ManagedWebViewImage, runtime_scope: Some(AuthorityScope::ImmutableVersion) };
        assert_eq!(managed.observe(&mut native), Err(Error::Unsafe));
        let ordinary = PathOriginal { metadata_profile: P::Ordinary, ..managed };
        assert_eq!(ordinary.observe(&mut native), Err(Error::State));
        assert!(!native.started && native.active.is_none());
        for slot in native.slots.drain(..) { drop(ManuallyDrop::into_inner(slot)); }
        assert_eq!(path_metadata_mismatch(&original_metadata, &original_metadata), None);
        for changed in [0, 1, 3] {
            let mut metadata = original_metadata.clone(); metadata.links = changed;
            assert_eq!(path_metadata_mismatch(&metadata, &original_metadata), Some(ProbeDetail::File));
        }
        assert!(observe.managed_webview_image_metadata(FileKind::File, &basic[..basic.len() - 1], &standard, &tag, &id).is_err());
        for size in [MAX_FILE_BYTES + 1, u64::MAX] {
            standard[offset_of!(FS::FILE_STANDARD_INFO, EndOfFile)..][..8].copy_from_slice(&size.to_le_bytes());
            assert!(observe.managed_webview_image_metadata(FileKind::File, &basic, &standard, &tag, &id).is_err());
        }
        standard[offset_of!(FS::FILE_STANDARD_INFO, EndOfFile)..][..8].copy_from_slice(&37u64.to_le_bytes());
        standard[offset_of!(FS::FILE_STANDARD_INFO, DeletePending)] = 1;
        assert!(observe.managed_webview_image_metadata(FileKind::File, &basic, &standard, &tag, &id).is_err());
        standard[offset_of!(FS::FILE_STANDARD_INFO, DeletePending)] = 0;
        basic[offset_of!(FS::FILE_BASIC_INFO, FileAttributes)..][..4].copy_from_slice(&FS::FILE_ATTRIBUTE_REPARSE_POINT.to_le_bytes());
        tag[offset_of!(FS::FILE_ATTRIBUTE_TAG_INFO, FileAttributes)..][..4].copy_from_slice(&FS::FILE_ATTRIBUTE_REPARSE_POINT.to_le_bytes());
        assert!(observe.managed_webview_image_metadata(FileKind::File, &basic, &standard, &tag, &id).is_err());
        Ok(())
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
            browser: Cell::new(0), exited: Cell::new(false), on_loss: Box::new(move |_| observed.set(observed.get() + 1)),
            exit_args: OnceCell::new(), exit_pid: ComValue::new() };
        // Pure state branch: no Windows process/window/COM call in this test.
        state.depth.set(1); let returned = CallbackReturn(&state);
        state.lost(Loss::Operation); state.lost(Loss::Operation); assert_eq!(calls.get(), 1); assert_eq!(state.depth.get(), 1);
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
