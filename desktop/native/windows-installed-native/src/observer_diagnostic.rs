//! The one qualification-only append leaf. Ordinary OriginalFile sharing and
//! success result writers are deliberately unchanged. No Drop closes a handle.
use super::*;
use crate::ui_observer_diagnostic_data as data;
#[cfg(all(feature = "qualification-result", feature = "windows-installed-observation"))]
use data::{Event, Frame, JournalOrder, Latch, Refusal, Snapshot};
#[cfg(all(feature = "qualification-result", feature = "windows-installed-observation"))]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Both authorities are allocated from the original UI admission, never from
/// timeout/finality. Shared latches cannot be reset by a new cursor or helper.
#[cfg(test)]
pub(crate) struct ObserverDiagnosticClock {
    entry: u64, execution_tick: u64, execution_end: Instant,
    diagnostic: Option<(u64, Instant)>,
    execution_latched: std::sync::atomic::AtomicBool,
    diagnostic_latched: std::sync::atomic::AtomicBool,
}
#[cfg(test)]
impl ObserverDiagnosticClock {
    pub(crate) fn new(entry: u64, execution_end: Instant) -> Result<Self> {
        let execution_tick = entry.checked_add(data::EXECUTION_MS).ok_or(Error::Bounds)?;
        let diagnostic = entry.checked_add(data::DIAGNOSTIC_MS).zip(
            execution_end.checked_add(std::time::Duration::from_millis(data::DIAGNOSTIC_MS - data::EXECUTION_MS)));
        Ok(Self { entry, execution_tick, execution_end, diagnostic,
            execution_latched: std::sync::atomic::AtomicBool::new(false),
            diagnostic_latched: std::sync::atomic::AtomicBool::new(false) })
    }
    pub(crate) fn permitted(&self, failure: bool) -> bool {
        let (tick, end, latched) = if failure {
            let Some((tick, end)) = self.diagnostic else { return false; };
            (tick, end, &self.diagnostic_latched)
        } else { (self.execution_tick, self.execution_end, &self.execution_latched) };
        data::window_sample(self.entry, tick, unsafe { SI::GetTickCount64() }, Instant::now() < end, latched)
    }
    fn ceiling(&self) -> Instant { self.diagnostic.map_or(self.execution_end, |(_, end)| end) }
}

// First-only parent-reader DATA. Optional references are absent on every child
// append/create path. No record owns a handle, changes a Result, or samples time.
macro_rules! capture_labels {
    ($name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(crate) enum $name { $($variant),+ }
        impl $name {
            pub(crate) fn label(self) -> &'static str { match self { $(Self::$variant => $label),+ } }
            #[cfg(test)]
            pub(crate) const ALL: &'static [Self] = &[$(Self::$variant),+];
        }
    };
}
capture_labels!(ObserverCaptureOperation {
    Eligibility => "eligibility",
    CaptureOutput => "capture-output",
    InventorySelect => "inventory-select",
    OutputOriginal => "output-original",
    OutputLocation => "output-location",
    DriveBefore => "drive-before",
    RootReserve => "root-reserve",
    RootOpen => "root-open",
    RootNoninherited => "root-noninherited",
    RootFilesystem => "root-filesystem",
    RootMetadata => "root-metadata",
    AncestorOpen => "ancestor-open",
    AncestorMetadata => "ancestor-metadata",
    OutputBinding => "output-binding",
    JournalOpen => "journal-open",
    JournalCursorMetadataBefore => "journal-cursor-metadata-before",
    JournalReadOnce => "journal-read-once",
    JournalCreated => "journal-created",
    JournalOriginalName => "journal-original-name",
    JournalOriginalMetadataBefore => "journal-original-metadata-before",
    JournalOriginalIdentity => "journal-original-identity",
    JournalAclBefore => "journal-acl-before",
    JournalStreamsBefore => "journal-streams-before",
    JournalRead => "journal-read",
    JournalAclAfter => "journal-acl-after",
    JournalStreamsAfter => "journal-streams-after",
    JournalOriginalMetadataAfter => "journal-original-metadata-after",
    JournalOriginalStability => "journal-original-stability",
    JournalCursorBinding => "journal-cursor-binding",
    JournalCursorStreams => "journal-cursor-streams",
    JournalCursorMetadataAfter => "journal-cursor-metadata-after",
    CursorMetadataAfter => "cursor-metadata-after",
    DriveAfter => "drive-after",
    OutputPoststate => "output-poststate",
    ResultOriginal => "result-original",
    FixtureDirectoryOriginal => "fixture-directory-original",
    FixtureDirectoryOpen => "fixture-directory-open",
    FixtureDirectoryMetadata => "fixture-directory-metadata",
    FixtureDirectoryBinding => "fixture-directory-binding",
    FixtureFileOriginal => "fixture-file-original",
    FixtureFileOpen => "fixture-file-open",
    FixtureFileMetadata => "fixture-file-metadata",
    FixtureFileStreams => "fixture-file-streams",
    FixtureFileRead => "fixture-file-read",
    FixtureFileEof => "fixture-file-eof",
    FixtureDirectoryMetadataAfter => "fixture-directory-metadata-after",
    FixtureFileMetadataAfter => "fixture-file-metadata-after",
    ConfigurationInput => "configuration-input",
    ConfigurationRead => "configuration-read",
    DirectoryBatch => "directory-batch",
    DirectoryEntry => "directory-entry",
    DirectoryRoster => "directory-roster",
});
capture_labels!(ObserverCaptureCheck {
    ParentSettled => "parent-settled",
    ChildOriginal => "child-original",
    ChildReturned => "child-returned",
    ChildCreated => "child-created",
    ChildSignaled => "child-signaled",
    ChildExitObserved => "child-exit-observed",
    ChildProcessClosed => "child-process-closed",
    ChildThreadClosed => "child-thread-closed",
    ChildKnown => "child-known",
    ObservationKnown => "observation-known",
    InventoryKnown => "inventory-known",
    JournalPresent => "journal-present",
    JournalKnown => "journal-known",
    InventoryFresh => "inventory-fresh",
    CachedOutput => "cached-output",
    CachedFile => "cached-file",
    Directory => "directory",
    OriginalOwned => "original-owned",
    OriginalInactive => "original-inactive",
    OriginalHandle => "original-handle",
    PathText => "path-text",
    DosLocation => "dos-location",
    PathDepth => "path-depth",
    ParentOriginal => "parent-original",
    InventoryBound => "inventory-bound",
    InventoryOnce => "inventory-once",
    InventoryClock => "inventory-clock",
    NativePurpose => "native-purpose",
    NativeClockBefore => "native-clock-before",
    NativeClockAfter => "native-clock-after",
    NativeReturn => "native-return",
    HelperReturn => "helper-return",
    VolumeSerial => "volume-serial",
    FileId => "file-id",
    CreationTime => "creation-time",
    Attributes => "attributes",
    Links => "links",
    WriteTime => "write-time",
    ChangeTime => "change-time",
    FileSize => "file-size",
    AllocationSize => "allocation-size",
    RawLimit => "raw-limit",
    ReadOnce => "read-once",
    Created => "created",
    ClockPermitted => "clock-permitted",
    FileCeiling => "file-ceiling",
    StampDirectory => "stamp-directory",
    StampDeletePending => "stamp-delete-pending",
    StampSize => "stamp-size",
    StampAllocation => "stamp-allocation",
    StampLinks => "stamp-links",
    StampAttributes => "stamp-attributes",
    StampKind => "stamp-kind",
    StampFileId => "stamp-file-id",
    DescriptorSize => "descriptor-size",
    DescriptorHeader => "descriptor-header",
    DescriptorControl => "descriptor-control",
    DescriptorRequired => "descriptor-required",
    DescriptorSacl => "descriptor-sacl",
    DescriptorDaclOffset => "descriptor-dacl-offset",
    DescriptorDaclSpan => "descriptor-dacl-span",
    DescriptorDaclBytes => "descriptor-dacl-bytes",
    DescriptorOwnerOffset => "descriptor-owner-offset",
    DescriptorGroupOffset => "descriptor-group-offset",
    DescriptorSid => "descriptor-sid",
    DescriptorPrincipalExtent => "descriptor-principal-extent",
    DescriptorPrincipalOverlap => "descriptor-principal-overlap",
    DescriptorOwnerTrust => "descriptor-owner-trust",
    DescriptorAccount => "descriptor-account",
    StreamsReturned => "streams-returned",
    StreamsData => "streams-data",
    ReadState => "read-state",
    ReadReturned => "read-returned",
    ReadCount => "read-count",
    StampStable => "stamp-stable",
    MappingStable => "mapping-stable",
    Input => "input",
    Admission => "admission",
    OriginalClock => "original-clock",
    OriginalStamp => "original-stamp",
    Role => "role",
    BytesEqual => "bytes-equal",
    EndOfFile => "end-of-file",
    EntryUnique => "entry-unique",
    EntryLimit => "entry-limit",
    ExpectedChild => "expected-child",
    EntryKind => "entry-kind",
    DotIdentity => "dot-identity",
    ParentIdentity => "parent-identity",
    ExactRoster => "exact-roster",
});

// New poststate positions are fixed synthetic roles, never native slot IDs.
// Preserve the old <=16 grammar for every pre-existing operation.
fn capture_position_valid(operation: ObserverCaptureOperation, index: Option<u8>) -> bool {
    use ObserverCaptureOperation as O;
    if index.is_some_and(|index| index > 16) { return false; }
    match operation {
        O::FixtureDirectoryOriginal | O::FixtureDirectoryOpen | O::FixtureDirectoryMetadata
        | O::FixtureDirectoryBinding | O::FixtureDirectoryMetadataAfter => index.is_some_and(|index| index <= 2),
        O::FixtureFileOriginal | O::FixtureFileOpen | O::FixtureFileMetadata | O::FixtureFileStreams
        | O::FixtureFileRead | O::FixtureFileEof | O::FixtureFileMetadataAfter
        | O::DirectoryBatch | O::DirectoryEntry | O::DirectoryRoster => index.is_some_and(|index| index <= 3),
        O::OutputPoststate | O::ResultOriginal | O::ConfigurationInput | O::ConfigurationRead => index.is_none(),
        _ => true,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObserverCaptureNative {
    Original(PrerequisiteNative), NtStreams(i32), Win32Streams(u32),
}
impl ObserverCaptureNative {
    fn valid(self) -> bool {
        use PrerequisiteApi as A;
        match self {
            Self::Original(value) => value.valid() && matches!(value.api,
                A::QueryDosDeviceW | A::NtCreateFile | A::GetHandleInformation | A::GetVolumeInformationByHandleW
                | A::NtQueryVolumeInformationFile | A::GetFileInformationByHandleEx | A::GetFinalPathNameByHandleW
                | A::GetKernelObjectSecurity | A::ReadFile)
                && !(value.api == A::GetFileInformationByHandleEx
                    && value.selector == PrerequisiteSelector::FileIdExtdDirectoryInfo)
                && !(value.api == A::NtCreateFile && value.selector != PrerequisiteSelector::None),
            Self::NtStreams(value) => value != 0,
            Self::Win32Streams(_) => true,
        }
    }
    #[cfg(test)]
    pub(crate) fn returned(call: Call, returned: Returned) -> Option<Self> {
        let value = match (call, returned) {
            (Call::Streams, Returned::Nt(value)) if value != 0 => Some(Self::NtStreams(value)),
            _ => prerequisite_native_pair(call, returned).map(Self::Original),
        };
        value.filter(|value| value.valid())
    }
    fn write_json(self, output: &mut impl std::io::Write) -> std::io::Result<()> {
        let (api, selector, kind, value, status, code) = match self {
            Self::Original(value) => (value.api.label(), match value.selector {
                PrerequisiteSelector::None => "none", PrerequisiteSelector::FileBasicInfo => "file-basic-info",
                PrerequisiteSelector::FileStandardInfo => "file-standard-info", PrerequisiteSelector::FileAttributeTagInfo => "file-attribute-tag-info",
                PrerequisiteSelector::FileIdInfo => "file-id-info", PrerequisiteSelector::FileCaseSensitiveInfo => "file-case-sensitive-info",
                PrerequisiteSelector::FileFsDeviceInformation => "file-fs-device-information", _ => "invalid",
            }, value.kind.label(), value.value.unwrap_or(0), value.status.label(), value.code.unwrap_or(0)),
            Self::NtStreams(value) => ("NtQueryInformationFile", "file-stream-information", "ntstatus", i64::from(value), "ntstatus", i64::from(value)),
            Self::Win32Streams(code) => ("GetFileInformationByHandleEx", "file-stream-info", "bool", 0, "win32", i64::from(code)),
        };
        write!(output, "{{\"api\":\"{api}\",\"selector\":\"{selector}\",\"kind\":\"{kind}\",\"value\":{value},\"status\":\"{status}\",\"code\":{code}}}")
    }
}
capture_labels!(ObserverEntryClass {
    ExpectedNameCaseAlias => "expected-name-case-alias",
    KnownCwdLog => "known-cwd-log",
    OtherRegular => "other-regular",
    OtherDirectory => "other-directory",
    Other => "other",
});
capture_labels!(ObserverExpectedName {
    Result => "result", Journal => "journal", Project => "project", App => "app", Release => "release",
    Gradle => "gradle", Version => "version", Keep => "keep", Config => "config",
});
impl ObserverExpectedName {
    fn of(role: UiRole, name: &str) -> Option<Self> {
        if name == role.name("result.private.json") { return Some(Self::Result); }
        if name == role.name(data::SUFFIX) { return Some(Self::Journal); }
        match name {
            "project" => Some(Self::Project), "app" => Some(Self::App), "release" => Some(Self::Release),
            "build.gradle.kts" => Some(Self::Gradle), "version.properties" => Some(Self::Version),
            "keep.txt" => Some(Self::Keep), "mobile-release.json" => Some(Self::Config), _ => None,
        }
    }
    fn position(self) -> u8 { match self {
        Self::Result | Self::Journal | Self::Project => 0,
        Self::App | Self::Release | Self::Version | Self::Keep => 1,
        Self::Gradle => 2, Self::Config => 3,
    } }
}
capture_labels!(ObserverKnownLog {
    Debug => "debug-log", ChromeDebug => "chrome-debug-log", MsedgeDebug => "msedge-debug-log",
});
impl ObserverKnownLog {
    fn of(name: &str) -> Option<Self> {
        [("debug.log", Self::Debug), ("chrome_debug.log", Self::ChromeDebug), ("msedge_debug.log", Self::MsedgeDebug)]
            .into_iter().find(|(fixed, _)| name.eq_ignore_ascii_case(fixed)).map(|(_, label)| label)
    }
}
capture_labels!(ObserverDirectoryFamily {
    AppIdentifier => "app-identifier",
    FixtureProject => "fixture-project", FixtureApp => "fixture-app", FixtureRelease => "fixture-release",
    EbWebView => "ebwebview", WebView2 => "webview2",
    AppData => "app-data", Local => "local", Roaming => "roaming", Microsoft => "microsoft", Temp => "temp",
    Default => "default", Crashpad => "crashpad", CrashDumps => "crash-dumps", BrowserMetrics => "browser-metrics",
    Cache => "cache", CodeCache => "code-cache", GpuCache => "gpu-cache", DawnCache => "dawn-cache", ShaderCache => "shader-cache",
    SessionStorage => "session-storage", LocalStorage => "local-storage",
    Desktop => "desktop", Documents => "documents", Downloads => "downloads", Favorites => "favorites", Links => "links", Recent => "recent",
    LiteralUserProfile => "literal-userprofile", LiteralLocalAppData => "literal-localappdata", LiteralAppData => "literal-appdata",
    LiteralTemp => "literal-temp", LiteralTmp => "literal-tmp",
    MrkWebView2Shape => "mrk-webview2-shape", WebView2Suffix => "webview2-suffix",
});
impl ObserverDirectoryFamily {
    // Lexical names only: neither a producing process nor this run's profile.
    // No original basename, prefix, nonce or executable authority is retained.
    fn of(name: &str) -> Option<Self> {
        let fixed = [
            ("dev.mobile-release-kit.desktop", Self::AppIdentifier),
            ("project", Self::FixtureProject), ("app", Self::FixtureApp), ("release", Self::FixtureRelease),
            ("EBWebView", Self::EbWebView), ("WebView2", Self::WebView2),
            ("AppData", Self::AppData), ("Local", Self::Local), ("Roaming", Self::Roaming), ("Microsoft", Self::Microsoft), ("Temp", Self::Temp),
            ("Default", Self::Default), ("Crashpad", Self::Crashpad), ("CrashDumps", Self::CrashDumps), ("BrowserMetrics", Self::BrowserMetrics),
            ("Cache", Self::Cache), ("Code Cache", Self::CodeCache), ("GPUCache", Self::GpuCache), ("DawnCache", Self::DawnCache), ("ShaderCache", Self::ShaderCache),
            ("Session Storage", Self::SessionStorage), ("Local Storage", Self::LocalStorage),
            ("Desktop", Self::Desktop), ("Documents", Self::Documents), ("Downloads", Self::Downloads), ("Favorites", Self::Favorites), ("Links", Self::Links), ("Recent", Self::Recent),
            ("%USERPROFILE%", Self::LiteralUserProfile), ("%LOCALAPPDATA%", Self::LiteralLocalAppData), ("%APPDATA%", Self::LiteralAppData),
            ("%TEMP%", Self::LiteralTemp), ("%TMP%", Self::LiteralTmp),
        ];
        if let Some((_, family)) = fixed.into_iter().find(|(fixed, _)| name.eq_ignore_ascii_case(fixed)) { return Some(family); }
        if name.strip_prefix("mrk-webview2-").is_some_and(|tail|
            tail.len() == 32 && tail.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))) {
            return Some(Self::MrkWebView2Shape);
        }
        // rsplit_once is boundary-safe even when the original prefix is UTF-8.
        name.rsplit_once('.').filter(|(prefix, suffix)| !prefix.is_empty() && suffix.eq_ignore_ascii_case("WebView2"))
            .map(|_| Self::WebView2Suffix)
    }
}
// Same decoded entry only. No arbitrary name, path, file ID or content survives
// classification. A known log NAME does not identify its producer or make it safe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ObserverCaptureEntry {
    class: ObserverEntryClass, expected: Option<ObserverExpectedName>, log: Option<ObserverKnownLog>,
    kind: FileKind, attributes: u32, directory_family: Option<ObserverDirectoryFamily>,
    source_relation: Option<data::OutputDirectoryRelation>,
}
impl ObserverCaptureEntry {
    fn of<'a>(role: UiRole, entry: &DirectoryEntry, mut expected: impl Iterator<Item = &'a str>) -> Self {
        let mut value = Self { class: ObserverEntryClass::Other, expected: None, log: None,
            kind: entry.kind, attributes: entry.attributes, directory_family: None, source_relation: None };
        if !value.consistent() { return value; } // DATA fallback, never a new decoder admission.
        value.expected = expected.find(|name| *name != entry.name.as_str() && name.eq_ignore_ascii_case(&entry.name))
            .and_then(|name| ObserverExpectedName::of(role, name));
        if value.expected.is_some() { value.class = ObserverEntryClass::ExpectedNameCaseAlias; }
        else if let Some(log) = ObserverKnownLog::of(&entry.name) {
            value.class = ObserverEntryClass::KnownCwdLog; value.log = Some(log);
        } else { value.class = match entry.kind { FileKind::File => ObserverEntryClass::OtherRegular,
            FileKind::Directory => ObserverEntryClass::OtherDirectory }; }
        if value.class == ObserverEntryClass::OtherDirectory {
            value.directory_family = ObserverDirectoryFamily::of(&entry.name);
        }
        value
    }
    fn consistent(self) -> bool { (self.attributes & FS::FILE_ATTRIBUTE_DIRECTORY != 0) == (self.kind == FileKind::Directory) }
    fn valid(self, position: Option<u8>) -> bool {
        if self.source_relation.is_some_and(|relation| position != Some(0)
            || self.class != ObserverEntryClass::OtherDirectory || !self.consistent() || !relation.valid()) { return false; }
        if self.directory_family.is_some() && (self.class != ObserverEntryClass::OtherDirectory || !self.consistent()) { return false; }
        if !self.consistent() { return self.class == ObserverEntryClass::Other && self.expected.is_none() && self.log.is_none(); }
        match self.class {
            ObserverEntryClass::ExpectedNameCaseAlias => self.expected.is_some_and(|name| Some(name.position()) == position) && self.log.is_none(),
            ObserverEntryClass::KnownCwdLog => self.expected.is_none() && self.log.is_some(),
            ObserverEntryClass::OtherRegular => self.kind == FileKind::File && self.expected.is_none() && self.log.is_none(),
            ObserverEntryClass::OtherDirectory => self.kind == FileKind::Directory && self.expected.is_none() && self.log.is_none(),
            ObserverEntryClass::Other => false,
        }
    }
    fn write_json(self, output: &mut impl std::io::Write) -> std::io::Result<()> {
        write!(output, "{{\"class\":\"{}\",\"expected\":", self.class.label())?;
        match self.expected { Some(name) => write!(output, "\"{}\"", name.label())?, None => output.write_all(b"null")? }
        output.write_all(b",\"log\":")?;
        match self.log { Some(log) => write!(output, "\"{}\"", log.label())?, None => output.write_all(b"null")? }
        write!(output, ",\"kind\":\"{}\",\"attributes\":{}",
            match self.kind { FileKind::File => "file", FileKind::Directory => "directory" }, self.attributes)?;
        if let Some(family) = self.directory_family { write!(output, ",\"directoryFamily\":\"{}\"", family.label())?; }
        if let Some(relation) = self.source_relation { output.write_all(b",\"sourceRelation\":")?; relation.write_json(output)?; }
        output.write_all(b"}")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ObserverCaptureFailure {
    pub(crate) operation: ObserverCaptureOperation, pub(crate) check: ObserverCaptureCheck,
    pub(crate) index: Option<u8>, pub(crate) error: Option<Error>,
    pub(crate) native: Option<ObserverCaptureNative>, pub(crate) detail: Option<PrerequisiteDetail>,
    pub(crate) entry: Option<ObserverCaptureEntry>,
}
impl ObserverCaptureFailure {
    fn valid(self) -> bool {
        use ObserverCaptureCheck as C;
        if !capture_position_valid(self.operation, self.index) || self.error == Some(Error::Unknown) { return false; }
        if let Some(entry) = self.entry {
            return self.operation == ObserverCaptureOperation::DirectoryEntry && self.check == C::ExpectedChild
                && self.error == Some(Error::Unsafe) && self.native.is_none() && self.detail.is_none() && entry.valid(self.index);
        }
        if self.error.is_none() {
            return self.operation == ObserverCaptureOperation::Eligibility && self.index.is_none()
                && self.native.is_none() && self.detail.is_none()
                && matches!(self.check, C::ParentSettled | C::ChildOriginal | C::ChildReturned | C::ChildCreated
                    | C::ChildSignaled | C::ChildExitObserved | C::ChildProcessClosed | C::ChildThreadClosed | C::ChildKnown
                    | C::ObservationKnown | C::InventoryKnown | C::JournalPresent | C::JournalKnown | C::InventoryFresh);
        }
        if self.operation == ObserverCaptureOperation::Eligibility { return false; }
        match (self.check, self.native, self.detail) {
            (C::NativeReturn, Some(native), None) => matches!(self.error, Some(Error::Unsafe | Error::Unavailable)) && native.valid(),
            (C::Input, None, Some(PrerequisiteDetail::Input(_))) => true,
            (C::Admission, None, Some(PrerequisiteDetail::Admission(_))) => self.error == Some(Error::Unsafe),
            (C::NativeReturn | C::Input | C::Admission, _, _) => false,
            (_, None, None) => true,
            _ => false,
        }
    }
    fn write_json(self, output: &mut impl std::io::Write) -> std::io::Result<()> {
        let kind = if self.error.is_some() { "returned-error" } else { "not-attempted" };
        write!(output, "{{\"kind\":\"{kind}\",\"operation\":\"{}\",\"check\":\"{}\",\"index\":", self.operation.label(), self.check.label())?;
        match self.index { Some(index) => write!(output, "{index}")?, None => output.write_all(b"null")? }
        output.write_all(b",\"error\":")?;
        match self.error { Some(error) => write!(output, "\"{error:?}\"")?, None => output.write_all(b"null")? }
        output.write_all(b",\"native\":")?;
        match self.native { Some(native) => native.write_json(output)?, None => output.write_all(b"null")? }
        output.write_all(b",\"detail\":")?;
        match self.detail { Some(detail) => { let (prefix, label) = detail.labels(); write!(output, "\"{prefix}{label}\"")?; }, None => output.write_all(b"null")? }
        if let Some(entry) = self.entry { output.write_all(b",\"entry\":")?; entry.write_json(output)?; }
        output.write_all(b"}")
    }
}
pub(crate) struct ObserverCaptureTrace {
    first: Cell<Option<ObserverCaptureFailure>>, operation: Cell<ObserverCaptureOperation>, index: Cell<Option<u8>>,
}
impl Default for ObserverCaptureTrace {
    fn default() -> Self { Self { first: Cell::new(None), operation: Cell::new(ObserverCaptureOperation::Eligibility), index: Cell::new(None) } }
}
impl ObserverCaptureTrace {
    pub(crate) fn first(&self) -> Option<ObserverCaptureFailure> { self.first.get() }
    pub(crate) fn write_json(&self, output: &mut impl std::io::Write) -> std::io::Result<()> {
        match self.first() { Some(first) => {
            if !first.valid() { return Err(std::io::ErrorKind::InvalidData.into()); }
            first.write_json(output)
        }, None => output.write_all(b"null") }
    }
    fn remember(&self, check: ObserverCaptureCheck, error: Option<Error>, native: Option<ObserverCaptureNative>, detail: Option<PrerequisiteDetail>) {
        if self.first.get().is_none() { self.first.set(Some(ObserverCaptureFailure {
            operation: self.operation.get(), check, index: self.index.get(), error, native, detail, entry: None })); }
    }
    pub(crate) fn unexpected_entry<'a>(&self, role: UiRole, entry: &DirectoryEntry, expected: impl Iterator<Item = &'a str>) {
        self.unexpected_entry_with_relation(role, entry, expected, None);
    }
    pub(crate) fn unexpected_entry_with_relation<'a>(&self, role: UiRole, entry: &DirectoryEntry,
        expected: impl Iterator<Item = &'a str>, relation: Option<data::OutputDirectoryRelation>) {
        if self.first.get().is_none() {
            let mut classified = ObserverCaptureEntry::of(role, entry, expected);
            if self.operation.get() == ObserverCaptureOperation::DirectoryEntry && self.index.get() == Some(0)
                && classified.class == ObserverEntryClass::OtherDirectory && classified.consistent() {
                // Invalid added DATA is omitted; it cannot replace the original failure.
                classified.source_relation = relation.filter(|value| value.valid());
            }
            self.first.set(Some(ObserverCaptureFailure {
                operation: self.operation.get(), check: ObserverCaptureCheck::ExpectedChild, index: self.index.get(),
                error: Some(Error::Unsafe), native: None, detail: None, entry: Some(classified),
            }));
        }
    }
    pub(crate) fn gate(&self, check: ObserverCaptureCheck, admitted: bool) -> bool {
        if !admitted { self.remember(check, None, None, None); } admitted
    }
    pub(crate) fn result<T>(&self, check: ObserverCaptureCheck, original: Result<T>) -> Result<T> {
        if let Err(error) = &original { self.remember(check, Some(*error), None, None); } original
    }
    pub(crate) fn native_result<T>(&self, original: Result<T>, native: Option<ObserverCaptureNative>, detail: Option<PrerequisiteDetail>) -> Result<T> {
        if let Err(error) = &original {
            let (check, native, detail) = match (native, detail) {
                (Some(native), _) => (ObserverCaptureCheck::NativeReturn, Some(native), None),
                (None, Some(PrerequisiteDetail::Input(check))) => (ObserverCaptureCheck::Input, None, Some(PrerequisiteDetail::Input(check))),
                (None, Some(PrerequisiteDetail::Admission(check))) => (ObserverCaptureCheck::Admission, None, Some(PrerequisiteDetail::Admission(check))),
                _ => (ObserverCaptureCheck::HelperReturn, None, None),
            };
            self.remember(check, Some(*error), native, detail);
        }
        original
    }
    pub(crate) fn scope<T>(&self, operation: ObserverCaptureOperation, index: Option<u8>, observe: impl FnOnce() -> Result<T>) -> Result<T> {
        let previous = (self.operation.replace(operation), self.index.replace(index));
        let original = self.result(ObserverCaptureCheck::HelperReturn, observe());
        self.operation.set(previous.0); self.index.set(previous.1); original
    }
}
fn read_result<T>(trace: Option<&ObserverCaptureTrace>, check: ObserverCaptureCheck, original: Result<T>) -> Result<T> {
    match trace { Some(trace) => trace.result(check, original), None => original }
}
fn read_input_result<T>(trace: Option<&ObserverCaptureTrace>, input: &InputTrace, original: Result<T>) -> Result<T> {
    match trace { Some(trace) => {
        let fault = input.prerequisite.and_then(|record| record.first);
        // These three unchanged OriginalFile helpers label their own timely
        // refusal F04 without an Input/native detail. Preserve that existing
        // returned clock decision; do not query the clock/body a second time.
        if matches!(&original, Err(Error::Unsafe)) && fault.is_some_and(|value| value.check == PrerequisiteCheck::F04
            && value.error == Error::Unsafe && value.native.is_none() && value.detail.is_none()) {
            return trace.result(ObserverCaptureCheck::FileCeiling, original);
        }
        trace.native_result(original, fault.and_then(|value| value.native).map(ObserverCaptureNative::Original), fault.and_then(|value| value.detail))
    }, None => original }
}
fn read_scope<T>(trace: Option<&ObserverCaptureTrace>, operation: ObserverCaptureOperation, observe: impl FnOnce() -> Result<T>) -> Result<T> {
    match trace { Some(trace) => trace.scope(operation, Some(16), observe), None => observe() }
}
fn read_streams(trace: Option<&ObserverCaptureTrace>, raw: &[u8]) -> Result<()> {
    let admission = AdmissionTrace::new(); admission.active.set(trace.is_some());
    let original = decode::Observed::new(admission.at(AdmissionOp::Streams)).streams(raw, FileKind::File);
    match trace { Some(trace) => trace.native_result(original, None,
        admission.first.get().map(|value| PrerequisiteDetail::Admission(value.check))), None => original }
}

#[cfg(test)]
impl ObserverCaptureTrace {
    pub(crate) fn unexpected_entry_contract() -> Result<()> {
        Self::output_directory_relation_contract()?;
        use ObserverCaptureCheck as C; use ObserverCaptureOperation as O; use ObserverEntryClass as Class;
        use ObserverDirectoryFamily as D;
        fn entry(name: &str, kind: FileKind, attributes: u32) -> DirectoryEntry {
            DirectoryEntry { name: name.to_owned(), file_id: [0x37; 16], kind, attributes }
        }
        fn observe(role: UiRole, position: u8, entry: &DirectoryEntry, names: &[(u8, String)]) -> (Result<()>, ObserverCaptureTrace) {
            let trace = ObserverCaptureTrace::default(); let calls = Cell::new(0);
            let original = trace.scope(O::DirectoryEntry, Some(position), || {
                calls.set(calls.get() + 1);
                let original = names.iter().find(|(p, name)| *p == position && *name == entry.name).map(|_| ()).ok_or(Error::Unsafe)
                    .map_err(|error| { trace.unexpected_entry(role, entry,
                        names.iter().filter(|(p, _)| *p == position).map(|(_, name)| name.as_str())); error });
                trace.result(C::ExpectedChild, original)
            });
            assert_eq!(calls.get(), 1); (original, trace)
        }
        for role in [UiRole::ProjectDraft, UiRole::QuitPassive, UiRole::DocumentLoss] {
            use ObserverExpectedName as N;
            let names = [(N::Result, role.name("result.private.json")), (N::Journal, role.name(data::SUFFIX)),
                (N::Project, "project".to_owned()), (N::App, "app".to_owned()), (N::Release, "release".to_owned()),
                (N::Gradle, "build.gradle.kts".to_owned()), (N::Version, "version.properties".to_owned()),
                (N::Keep, "keep.txt".to_owned()), (N::Config, "mobile-release.json".to_owned())];
            let expected: Vec<_> = names.iter().map(|(label, name)| (label.position(), name.clone())).collect();
            for (label, name) in &names {
                let exact = entry(name, FileKind::File, FS::FILE_ATTRIBUTE_ARCHIVE);
                let (original, trace) = observe(role, label.position(), &exact, &expected);
                assert_eq!(original, Ok(())); assert!(trace.first().is_none());
                let alias = entry(&name.to_ascii_uppercase(), FileKind::File, FS::FILE_ATTRIBUTE_ARCHIVE);
                let (original, trace) = observe(role, label.position(), &alias, &expected);
                assert_eq!(original, Err(Error::Unsafe)); let first = trace.first().unwrap();
                let captured = first.entry.unwrap();
                assert!(first.valid()); assert_eq!(captured.class, Class::ExpectedNameCaseAlias);
                assert_eq!(captured.expected, Some(*label)); assert_eq!(captured.log, None);
                assert_eq!(captured.directory_family, None);
                assert_eq!((captured.kind, captured.attributes), (alias.kind, alias.attributes));
            }
            // A case alias in a different parent, or an absent optional result,
            // remains other DATA. A fixture-family label is not an expected-name witness.
            let absent: Vec<_> = expected.iter().filter(|(_, name)| *name != role.name("result.private.json")).cloned().collect();
            for (position, value, names) in [
                (1, entry("PROJECT", FileKind::Directory, FS::FILE_ATTRIBUTE_DIRECTORY), &expected),
                (0, entry(&role.name("result.private.json").to_ascii_uppercase(), FileKind::File, 0), &absent),
            ] {
                let (original, trace) = observe(role, position, &value, names);
                assert_eq!(original, Err(Error::Unsafe)); let first = trace.first().unwrap(); assert!(first.valid());
                assert!(first.entry.unwrap().expected.is_none());
                if value.name == "PROJECT" { assert_eq!(first.entry.unwrap().directory_family, Some(D::FixtureProject)); }
            }
        }
        let role = UiRole::ProjectDraft; let expected = [(0, "project".to_owned())];
        for (name, log) in [("debug.log", ObserverKnownLog::Debug), ("chrome_debug.log", ObserverKnownLog::ChromeDebug),
            ("msedge_debug.log", ObserverKnownLog::MsedgeDebug)] {
            for name in [name.to_owned(), name.to_ascii_uppercase()] {
                for (kind, attributes) in [(FileKind::File, FS::FILE_ATTRIBUTE_ARCHIVE | FS::FILE_ATTRIBUTE_HIDDEN),
                    (FileKind::Directory, u32::MAX)] {
                    let value = entry(&name, kind, attributes); let (original, trace) = observe(role, 0, &value, &expected);
                    assert_eq!(original, Err(Error::Unsafe)); let first = trace.first().unwrap(); assert!(first.valid());
                    let captured = first.entry.unwrap(); assert_eq!((captured.class, captured.log), (Class::KnownCwdLog, Some(log)));
                    assert_eq!(captured.directory_family, None);
                    assert_eq!((captured.kind, captured.attributes), (kind, attributes));
                    let mut raw = Vec::new(); trace.write_json(&mut raw).map_err(|_| Error::State)?;
                    assert!(!String::from_utf8(raw).unwrap().contains(name.as_str()));
                    trace.unexpected_entry(role, &entry("later-private-name", FileKind::File, 0), std::iter::empty());
                    let _ = trace.scope(O::JournalOpen, Some(16), || trace.result::<()>(C::HelperReturn, Err(Error::Unavailable)));
                    assert_eq!(trace.first(), Some(first));
                }
            }
        }
        fn family_case(name: &str, expected_family: D) -> Result<()> {
            let role = UiRole::ProjectDraft;
            let value = entry(name, FileKind::Directory, FS::FILE_ATTRIBUTE_DIRECTORY);
            let (original, trace) = observe(role, 0, &value, &[]);
            assert_eq!(original, Err(Error::Unsafe)); let first = trace.first().unwrap(); assert!(first.valid());
            let captured = first.entry.unwrap();
            assert_eq!((captured.class, captured.expected, captured.log), (Class::OtherDirectory, None, None));
            assert_eq!(captured.directory_family, Some(expected_family));
            assert_eq!((captured.kind, captured.attributes), (value.kind, value.attributes));
            let mut bytes = [0u8; 4096]; let mut cursor = std::io::Cursor::new(&mut bytes[..]);
            trace.write_json(&mut cursor).map_err(|_| Error::State)?;
            let count = cursor.position() as usize; assert!(count < bytes.len());
            let text = std::str::from_utf8(&bytes[..count]).unwrap();
            assert!(text.contains(&format!("\"directoryFamily\":\"{}\"", expected_family.label())));
            assert!(text.contains("\"check\":\"expected-child\",\"index\":0,\"error\":\"Unsafe\""));
            if matches!(expected_family, D::MrkWebView2Shape | D::WebView2Suffix) {
                assert!(!text.contains(name));
                assert!(!text.contains("0123456789abcdef0123456789abcdef"));
                assert!(!text.contains("private-prefix"));
            }
            trace.unexpected_entry(role, &entry("later-private-name", FileKind::Directory, FS::FILE_ATTRIBUTE_DIRECTORY), std::iter::empty());
            let _ = trace.scope(O::JournalOpen, Some(16), || trace.result::<()>(C::HelperReturn, Err(Error::Unavailable)));
            assert_eq!(trace.first(), Some(first));
            // A family never grants the old file/alias/log/fallback categories.
            for invalid in 0..7 {
                let mut changed = first; let entry = changed.entry.as_mut().unwrap();
                match invalid {
                    0 => { entry.class = Class::OtherRegular; entry.kind = FileKind::File; entry.attributes = 0; },
                    1 => { entry.class = Class::ExpectedNameCaseAlias; entry.expected = Some(ObserverExpectedName::Project); },
                    2 => { entry.class = Class::KnownCwdLog; entry.log = Some(ObserverKnownLog::Debug); },
                    3 => { entry.class = Class::Other; entry.kind = FileKind::File; },
                    4 => entry.attributes = 0,
                    5 => entry.expected = Some(ObserverExpectedName::Project),
                    _ => entry.log = Some(ObserverKnownLog::Debug),
                }
                assert!(!changed.valid());
            }
            Ok(())
        }
        let fixed_families = [
            ("dev.mobile-release-kit.desktop", D::AppIdentifier),
            ("project", D::FixtureProject), ("app", D::FixtureApp), ("release", D::FixtureRelease),
            ("EBWebView", D::EbWebView), ("WebView2", D::WebView2),
            ("AppData", D::AppData), ("Local", D::Local), ("Roaming", D::Roaming), ("Microsoft", D::Microsoft), ("Temp", D::Temp),
            ("Default", D::Default), ("Crashpad", D::Crashpad), ("CrashDumps", D::CrashDumps), ("BrowserMetrics", D::BrowserMetrics),
            ("Cache", D::Cache), ("Code Cache", D::CodeCache), ("GPUCache", D::GpuCache), ("DawnCache", D::DawnCache), ("ShaderCache", D::ShaderCache),
            ("Session Storage", D::SessionStorage), ("Local Storage", D::LocalStorage),
            ("Desktop", D::Desktop), ("Documents", D::Documents), ("Downloads", D::Downloads), ("Favorites", D::Favorites), ("Links", D::Links), ("Recent", D::Recent),
            ("%USERPROFILE%", D::LiteralUserProfile), ("%LOCALAPPDATA%", D::LiteralLocalAppData), ("%APPDATA%", D::LiteralAppData),
            ("%TEMP%", D::LiteralTemp), ("%TMP%", D::LiteralTmp),
        ];
        assert_eq!(fixed_families.len(), 33);
        let mut seen = Vec::new();
        for (name, family) in fixed_families {
            assert!(!seen.contains(&family)); seen.push(family);
            family_case(name, family)?; family_case(&name.to_ascii_uppercase(), family)?;
        }
        for (name, family) in [
            ("mrk-webview2-0123456789abcdef0123456789abcdef", D::MrkWebView2Shape),
            ("private-prefix.exe.WebView2", D::WebView2Suffix), ("é.wEbViEw2", D::WebView2Suffix),
            ("日本語.WebView2", D::WebView2Suffix),
        ] { family_case(name, family)?; if !seen.contains(&family) { seen.push(family); } }
        assert_eq!(seen.len(), D::ALL.len()); assert_eq!(seen.len(), 35);
        for name in ["", "é", "日本語", ".WebView2", "private-prefix.WebView2.more", "private-prefix.WebView",
            "private-prefix.WebView۲", "EBWebView-extra", "project-extra", "%TEMP", "USERPROFILE",
            "mrk-webview2-0123456789abcdef0123456789abcde", "mrk-webview2-0123456789abcdef0123456789abcdef0",
            "mrk-webview2-0123456789abcdef0123456789abcdeg", "mrk-webview2-0123456789abcdef0123456789abcdeF",
            "MRK-webview2-0123456789abcdef0123456789abcdef"] {
            let (original, trace) = observe(role, 0, &entry(name, FileKind::Directory, FS::FILE_ATTRIBUTE_DIRECTORY), &expected);
            assert_eq!(original, Err(Error::Unsafe)); assert!(trace.first().unwrap().valid());
            assert_eq!(trace.first().unwrap().entry.unwrap().directory_family, None);
        }
        for (kind, attributes) in [(FileKind::File, 0), (FileKind::File, FS::FILE_ATTRIBUTE_DIRECTORY), (FileKind::Directory, 0)] {
            let (original, trace) = observe(role, 0, &entry("EBWebView", kind, attributes), &expected);
            assert_eq!(original, Err(Error::Unsafe)); assert!(trace.first().unwrap().valid());
            assert_eq!(trace.first().unwrap().entry.unwrap().directory_family, None);
        }
        for (name, legacy) in [
            ("private-unlisted-name", "{\"class\":\"other-directory\",\"expected\":null,\"log\":null,\"kind\":\"directory\",\"attributes\":16}"),
            ("debug.log", "{\"class\":\"known-cwd-log\",\"expected\":null,\"log\":\"debug-log\",\"kind\":\"directory\",\"attributes\":16}"),
        ] {
            let captured = ObserverCaptureEntry::of(role, &entry(name, FileKind::Directory, FS::FILE_ATTRIBUTE_DIRECTORY), std::iter::empty());
            let mut raw = Vec::new(); captured.write_json(&mut raw).map_err(|_| Error::State)?;
            assert_eq!(raw, legacy.as_bytes());
        }
        for (kind, attributes, class) in [(FileKind::File, 0, Class::OtherRegular),
            (FileKind::Directory, FS::FILE_ATTRIBUTE_DIRECTORY, Class::OtherDirectory),
            (FileKind::File, FS::FILE_ATTRIBUTE_DIRECTORY, Class::Other), (FileKind::Directory, 0, Class::Other)] {
            let value = entry("private-unlisted-name", kind, attributes); let (original, trace) = observe(role, 0, &value, &expected);
            assert_eq!(original, Err(Error::Unsafe)); let first = trace.first().unwrap(); assert!(first.valid());
            let captured = first.entry.unwrap(); assert_eq!(captured.class, class);
            assert_eq!((captured.expected, captured.log), (None, None));
            assert_eq!(captured.directory_family, None);
            let mut raw = Vec::new(); trace.write_json(&mut raw).map_err(|_| Error::State)?;
            assert!(!String::from_utf8(raw).unwrap().contains(value.name.as_str()));
            for invalid in 0..8 {
                let mut changed = first;
                match invalid {
                    0 => changed.operation = O::JournalRead, 1 => changed.check = C::EntryKind,
                    2 => changed.index = Some(4), 3 => changed.error = Some(Error::Bounds), 4 => changed.error = None,
                    5 => changed.detail = Some(PrerequisiteDetail::Input(InputCheck::PathText)),
                    6 => changed.native = Some(ObserverCaptureNative::NtStreams(-1)),
                    _ => changed.entry.as_mut().unwrap().expected = Some(ObserverExpectedName::Config),
                }
                assert!(!changed.valid());
            }
        }
        let trace = Self::default();
        let _ = trace.scope(O::DirectoryEntry, Some(0), || trace.result::<()>(C::EntryUnique, Err(Error::Unsafe)));
        let first = trace.first();
        trace.unexpected_entry(role, &entry("EBWebView", FileKind::Directory, FS::FILE_ATTRIBUTE_DIRECTORY), std::iter::empty());
        assert_eq!(trace.first(), first); assert!(trace.first().unwrap().entry.is_none());
        assert_eq!((ObserverEntryClass::ALL.len(), ObserverExpectedName::ALL.len(), ObserverKnownLog::ALL.len()), (5, 9, 3));
        Ok(())
    }
    fn output_directory_relation_contract() -> Result<()> {
        use ObserverCaptureCheck as C; use ObserverCaptureOperation as O;
        let relation = data::OutputDirectoryRelation { available_mask: 31, roster_mask: 4, exact_name_mask: 0, identity_mask: 8 };
        let entry = DirectoryEntry { name: "private-unlisted-directory".to_owned(), file_id: [0x37; 16],
            kind: FileKind::Directory, attributes: FS::FILE_ATTRIBUTE_DIRECTORY };
        for role in [UiRole::ProjectDraft, UiRole::QuitPassive, UiRole::DocumentLoss] {
            let trace = Self::default();
            let original = trace.scope(O::DirectoryEntry, Some(0), || {
                trace.unexpected_entry_with_relation(role, &entry, std::iter::empty(), Some(relation));
                trace.result::<()>(C::ExpectedChild, Err(Error::Unsafe))
            });
            let first = trace.first().unwrap(); assert!(first.valid());
            assert_eq!(first.entry.unwrap().source_relation, Some(relation)); assert_eq!(original, Err(Error::Unsafe));
            let mut bytes = Vec::new(); trace.write_json(&mut bytes).map_err(|_| Error::State)?;
            let text = std::str::from_utf8(&bytes).unwrap();
            assert!(text.contains("\"sourceRelation\":{\"availableMask\":31,\"rosterMask\":4,\"exactNameMask\":0,\"identityMask\":8}"));
            for private in [entry.name.as_str(), "file_id", "volume", "path"] { assert!(!text.contains(private)); }
            trace.unexpected_entry_with_relation(role, &entry, std::iter::empty(), Some(Default::default()));
            let _ = trace.scope(O::JournalOpen, Some(16), || trace.result::<()>(C::HelperReturn, Err(Error::Unavailable)));
            assert_eq!(trace.first(), Some(first));
            let mut short = [0u8; 8]; assert!(trace.write_json(&mut std::io::Cursor::new(&mut short[..])).is_err());
            assert_eq!(trace.first(), Some(first));
            for position in 1..=3 {
                let trace = Self::default();
                trace.scope(O::DirectoryEntry, Some(position), || {
                    trace.unexpected_entry_with_relation(role, &entry, std::iter::empty(), Some(relation)); Ok(())
                })?;
                assert!(trace.first().unwrap().entry.unwrap().source_relation.is_none());
                let mut invalid = first; invalid.index = Some(position); assert!(!invalid.valid());
            }
            for value in [DirectoryEntry { name: "debug.log".to_owned(), ..entry.clone() },
                DirectoryEntry { kind: FileKind::File, attributes: 0, ..entry.clone() },
                DirectoryEntry { attributes: 0, ..entry.clone() }] {
                let trace = Self::default();
                trace.scope(O::DirectoryEntry, Some(0), || {
                    trace.unexpected_entry_with_relation(role, &value, std::iter::empty(), Some(relation)); Ok(())
                })?;
                assert!(trace.first().unwrap().entry.unwrap().source_relation.is_none());
            }
            for invalid in [data::OutputDirectoryRelation { available_mask: 32, ..relation },
                data::OutputDirectoryRelation { exact_name_mask: 4, ..relation },
                data::OutputDirectoryRelation { available_mask: 0, ..relation }] {
                let trace = Self::default();
                trace.scope(O::DirectoryEntry, Some(0), || {
                    trace.unexpected_entry_with_relation(role, &entry, std::iter::empty(), Some(invalid)); Ok(())
                })?;
                let first = trace.first().unwrap(); assert_eq!(first.error, Some(Error::Unsafe));
                assert!(first.entry.unwrap().source_relation.is_none()); assert!(first.valid());
            }
            let trace = Self::default();
            let _ = trace.scope(O::JournalOpen, Some(16), || trace.result::<()>(C::HelperReturn, Err(Error::Unavailable)));
            let before = trace.first();
            trace.scope(O::DirectoryEntry, Some(0), || {
                trace.unexpected_entry_with_relation(role, &entry, std::iter::empty(), Some(relation)); Ok(())
            })?;
            assert_eq!(trace.first(), before);
        }
        Ok(())
    }
    pub(crate) fn reader_contract() -> Result<()> {
        use ObserverCaptureCheck as C; use ObserverCaptureOperation as O;
        // DATA predicates only: no JournalFile/native owner, clock or I/O.
        let mut input = InputTrace::prerequisite_only(true);
        input.prerequisite_fault(PrerequisiteCheck::F04, Error::Unsafe, None, None);
        let trace = Self::default();
        assert_eq!(trace.scope(O::JournalOriginalMetadataBefore, Some(16), ||
            read_input_result::<()>(Some(&trace), &input, Err(Error::Unsafe))), Err(Error::Unsafe));
        assert_eq!(trace.first().map(|value| (value.check, value.native, value.detail)), Some((C::FileCeiling, None, None)));
        // A saved failed scalar whose semantic check did not run is not copied
        // into the first ceiling refusal, even if reused after that decision.
        input.prerequisite_fault(PrerequisiteCheck::F04, Error::Unsafe,
            PrerequisiteNative::boolean(PrerequisiteApi::GetFileInformationByHandleEx, PrerequisiteSelector::FileIdInfo, 0, Some(5)),
            Some(PrerequisiteDetail::Input(InputCheck::IdInfoReturned)));
        let first = trace.first();
        assert_eq!(read_input_result::<()>(Some(&trace), &input, Err(Error::Unsafe)), Err(Error::Unsafe));
        assert_eq!(trace.first(), first);
        let stamp = Stamp { volume: 7, id: [3; 16], creation: 11, write: 12, change: 13,
            size: 0, allocation: 0, links: 1, attributes: FS::FILE_ATTRIBUTE_ARCHIVE };
        let identity = Identity::of(&stamp);
        let mut cases = vec![(stamp.clone(), None)];
        for check in [C::VolumeSerial, C::FileId, C::CreationTime, C::Attributes, C::Links, C::FileSize] {
            let mut changed = stamp.clone();
            match check {
                C::VolumeSerial => changed.volume += 1, C::FileId => changed.id[0] += 1,
                C::CreationTime => changed.creation += 1, C::Attributes => changed.attributes = 0,
                C::Links => changed.links = 2, C::FileSize => changed.size = data::BYTE_LIMIT as i64 + 1,
                _ => unreachable!(),
            }
            cases.push((changed, Some(check)));
        }
        for (value, check) in cases {
            let trace = Self::default();
            let original = trace.scope(O::JournalOriginalIdentity, Some(16), || identity.matches_observed(&value, Some(&trace)));
            assert_eq!(original, need(identity.matches(&value)));
            assert_eq!(trace.first().map(|value| value.check), check);
        }
        let parent = builtin(545); let account = builtin(546);
        let (acl, length) = append_acl(&parent, &account)?; let owner = system_sid();
        let dacl = 20 + owner.len(); let mut raw = vec![0u8; dacl + length]; raw[0] = 1;
        raw[2..4].copy_from_slice(&(S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT | S::SE_DACL_PROTECTED).to_le_bytes());
        raw[4..8].copy_from_slice(&20u32.to_le_bytes()); raw[8..12].copy_from_slice(&20u32.to_le_bytes());
        raw[16..20].copy_from_slice(&(dacl as u32).to_le_bytes());
        raw[20..dacl].copy_from_slice(&owner); raw[dacl..].copy_from_slice(&acl.0[..length]);
        assert_eq!(descriptor_matches(&raw, &acl.0[..length], &parent, &account, None), Ok(()));
        let mut cases = vec![(raw.clone(), None), (Vec::new(), Some(C::DescriptorSize))];
        for check in [C::DescriptorHeader, C::DescriptorRequired, C::DescriptorSacl, C::DescriptorDaclOffset,
            C::DescriptorDaclBytes, C::DescriptorOwnerOffset, C::DescriptorGroupOffset, C::DescriptorSid] {
            let mut changed = raw.clone();
            match check {
                C::DescriptorHeader => changed[0] = 0, C::DescriptorRequired => changed[3] = 0,
                C::DescriptorSacl => changed[12] = 20, C::DescriptorDaclOffset => changed[16] = 1,
                C::DescriptorDaclBytes => changed[dacl] ^= 1, C::DescriptorOwnerOffset => changed[4] = 21,
                C::DescriptorGroupOffset => changed[8] = 21, C::DescriptorSid => changed[20] = 0,
                _ => unreachable!(),
            }
            cases.push((changed, Some(check)));
        }
        for (value, check) in cases {
            let trace = Self::default();
            let original = trace.scope(O::JournalAclBefore, Some(16), || descriptor_matches(&value, &acl.0[..length], &parent, &account, Some(&trace)));
            assert_eq!(original, descriptor_matches(&value, &acl.0[..length], &parent, &account, None));
            assert_eq!(trace.first().map(|value| value.check), check);
        }
        let mut stream = vec![0u8; 40]; stream[4..8].copy_from_slice(&14u32.to_le_bytes());
        for (index, unit) in "::$DATA".encode_utf16().enumerate() { stream[24 + index * 2..26 + index * 2].copy_from_slice(&unit.to_le_bytes()); }
        assert_eq!(read_streams(None, &stream), Ok(()));
        let mut cases = vec![(Vec::new(), AdmissionCheck::StreamMissing)];
        let mut changed = stream.clone(); changed[4] = 0; cases.push((changed, AdmissionCheck::StreamFrame));
        let mut changed = stream.clone(); changed[24] = b'X'; cases.push((changed, AdmissionCheck::StreamName));
        let mut changed = stream.clone(); changed.push(0); cases.push((changed, AdmissionCheck::StreamPadding));
        for (value, check) in cases {
            let trace = Self::default();
            assert_eq!(trace.scope(O::JournalStreamsBefore, Some(16), || read_streams(Some(&trace), &value)), read_streams(None, &value));
            assert_eq!(trace.first().map(|value| (value.check, value.detail, value.native)),
                Some((C::Admission, Some(PrerequisiteDetail::Admission(check)), None)));
        }
        Ok(())
    }
}

const APPEND_ACCESS: u32 = FS::FILE_APPEND_DATA | FS::FILE_READ_ATTRIBUTES | FS::READ_CONTROL | FS::SYNCHRONIZE;
#[repr(C, align(8))]
struct StreamBuffer([u8; 40]);

fn observer_role(role: UiRole) -> bool { matches!(role, UiRole::ProjectDraft | UiRole::QuitPassive | UiRole::DocumentLoss) }
fn fixed_leaf(role: UiRole, output: &Path) -> Result<PathBuf> {
    need(observer_role(role) && output.file_name().and_then(|name| name.to_str()) == Some(role.name("output").as_str()))?;
    fixed_path(output.to_str().ok_or(Error::Unsafe)?)?;
    Ok(output.join(role.name(data::SUFFIX)))
}

fn append_acl(parent: &[u8], account: &[u8]) -> Result<(Box<Aligned>, usize)> {
    let principals = [(system_sid(), FS::FILE_ALL_ACCESS), (builtin(544), FS::FILE_ALL_ACCESS),
        (parent.to_vec(), FS::FILE_ALL_ACCESS), (account.to_vec(), APPEND_ACCESS)];
    need(principals.iter().enumerate().all(|(i, (sid, _))| principals[..i].iter().all(|(prior, _)| prior != sid)))?;
    let size = 8 + principals.iter().map(|(sid, _)| 8 + sid.len()).sum::<usize>();
    need(size < BUFFER && size <= u16::MAX as usize)?;
    let mut acl = Box::new(Aligned([0; BUFFER]));
    acl.0[0] = 2; acl.0[2..4].copy_from_slice(&(size as u16).to_le_bytes()); acl.0[4..6].copy_from_slice(&4u16.to_le_bytes());
    let mut at = 8;
    for (sid, rights) in principals {
        need(security::sid_at(&sid, 0, sid.len())?.bytes() == sid)?;
        let length = 8 + sid.len();
        acl.0[at + 2..at + 4].copy_from_slice(&(length as u16).to_le_bytes());
        acl.0[at + 4..at + 8].copy_from_slice(&rights.to_le_bytes());
        acl.0[at + 8..at + length].copy_from_slice(&sid); at += length;
    }
    Ok((acl, size))
}
fn descriptor_matches(raw: &[u8], acl: &[u8], parent: &[u8], account: &[u8], trace: Option<&ObserverCaptureTrace>) -> Result<()> {
    use ObserverCaptureCheck as C;
    read_result(trace, C::DescriptorSize, need(raw.len() >= 20 && raw.len() <= BUFFER))?;
    read_result(trace, C::DescriptorHeader, need(raw[0] == 1 && raw[1] == 0))?;
    let control = read_result(trace, C::DescriptorControl, decode::u16_at(raw, 2))?;
    let required = S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT | S::SE_DACL_PROTECTED;
    let known = S::SE_OWNER_DEFAULTED | S::SE_GROUP_DEFAULTED | S::SE_DACL_PRESENT | S::SE_DACL_DEFAULTED
        | S::SE_SACL_PRESENT | S::SE_SACL_DEFAULTED | S::SE_DACL_AUTO_INHERIT_REQ | S::SE_SACL_AUTO_INHERIT_REQ
        | S::SE_DACL_AUTO_INHERITED | S::SE_SACL_AUTO_INHERITED | S::SE_DACL_PROTECTED | S::SE_SACL_PROTECTED | S::SE_SELF_RELATIVE;
    read_result(trace, C::DescriptorRequired, need(control & required == required))?;
    read_result(trace, C::DescriptorControl, need(control & !known == 0 && control & S::SE_DACL_AUTO_INHERITED == 0))?;
    read_result(trace, C::DescriptorSacl, need(read_result(trace, C::DescriptorSacl, decode::u32_at(raw, 12))? == 0))?;
    let dacl = read_result(trace, C::DescriptorDaclOffset, decode::u32_at(raw, 16))? as usize;
    read_result(trace, C::DescriptorDaclOffset, need(dacl >= 20 && dacl % 4 == 0))?;
    read_result(trace, C::DescriptorDaclBytes, need(read_result(trace, C::DescriptorDaclSpan, decode::span(raw, dacl, acl.len()))? == acl))?;
    let principal = |offset, check| -> Result<(Vec<u8>, (usize, usize))> {
        let start = read_result(trace, check, decode::u32_at(raw, offset))? as usize;
        read_result(trace, check, need(start >= 20 && start % 4 == 0))?;
        let sid = read_result(trace, C::DescriptorSid, security::sid_at(raw, start, raw.len()))?.bytes().to_vec();
        read_result(trace, C::DescriptorPrincipalExtent, need(start + sid.len() <= dacl || start >= dacl + acl.len()))?;
        let end = start + sid.len(); Ok((sid, (start, end)))
    };
    let (owner, owner_range) = principal(4, C::DescriptorOwnerOffset)?; let (group, group_range) = principal(8, C::DescriptorGroupOffset)?;
    read_result(trace, C::DescriptorPrincipalOverlap, need(group_range == owner_range || group_range.1 <= owner_range.0 || group_range.0 >= owner_range.1))?;
    read_result(trace, C::DescriptorOwnerTrust, need([system_sid(), builtin(544), parent.to_vec()].contains(&owner)))?;
    read_result(trace, C::DescriptorAccount, need(owner != account && group != account))
}

#[derive(Clone)]
struct Identity { volume: u64, id: [u8; 16], creation: i64, attributes: u32 }
impl Identity {
    fn of(stamp: &Stamp) -> Self { Self { volume: stamp.volume, id: stamp.id, creation: stamp.creation, attributes: stamp.attributes } }
    fn parse(value: &str) -> Result<Self> {
        artifact_identity(value)?; let fields: Vec<_> = value.split(':').collect();
        let mut id = [0; 16]; id.copy_from_slice(&unhex(fields[1])?);
        Ok(Self { volume: fields[0].parse().map_err(|_| Error::Unsafe)?, id,
            creation: fields[2].parse().map_err(|_| Error::Unsafe)?, attributes: fields[5].parse().map_err(|_| Error::Unsafe)? })
    }
    fn matches(&self, stamp: &Stamp) -> bool {
        self.volume == stamp.volume && self.id == stamp.id && self.creation == stamp.creation
            && self.attributes == stamp.attributes && stamp.links == 1 && stamp.size >= 0 && stamp.size as usize <= data::BYTE_LIMIT
    }
    #[cfg(test)]
    fn matches_observed(&self, stamp: &Stamp, trace: Option<&ObserverCaptureTrace>) -> Result<()> {
        use ObserverCaptureCheck as C;
        read_result(trace, C::VolumeSerial, need(self.volume == stamp.volume))?;
        read_result(trace, C::FileId, need(self.id == stamp.id))?;
        read_result(trace, C::CreationTime, need(self.creation == stamp.creation))?;
        read_result(trace, C::Attributes, need(self.attributes == stamp.attributes))?;
        read_result(trace, C::Links, need(stamp.links == 1))?;
        read_result(trace, C::FileSize, need(stamp.size >= 0 && stamp.size as usize <= data::BYTE_LIMIT))
    }
}

// This type alone can open the append journal with write sharing. It is never
// used for ordinary inputs/results, and never shares DELETE. The parent creates
// the EMPTY file read-only and retains that SAME original through child finality;
// there is no transient writer close/reopen or identity gap.
struct JournalFile { original: OriginalFile, streams: Box<StreamBuffer>, stream_return: i32 }
impl JournalFile {
    fn new(path: &Path, end: Instant) -> Result<Self> {
        Ok(Self { original: OriginalFile::new_until(path, false, end)?, streams: Box::new(StreamBuffer([0; 40])), stream_return: 0 })
    }
    fn check(&mut self, permitted: &dyn Fn() -> bool) -> Result<()> { self.check_observed(permitted, None) }
    fn check_observed(&mut self, permitted: &dyn Fn() -> bool, trace: Option<&ObserverCaptureTrace>) -> Result<()> {
        read_result(trace, ObserverCaptureCheck::ClockPermitted, need(permitted()))?;
        read_result(trace, ObserverCaptureCheck::FileCeiling, self.original.body().timely())
    }
    fn open(&mut self, parent_create: bool, security: *const S::SECURITY_ATTRIBUTES, permitted: &dyn Fn() -> bool) -> Result<()> {
        self.check(permitted)?;
        let b = self.original.body(); need(b.state == SlotState::Reserved && !b.active)?;
        b.state = SlotState::Acquiring; b.active = true;
        b.handle = unsafe { FS::CreateFileW(b.path.as_ptr(), if parent_create { FS::FILE_GENERIC_READ } else { APPEND_ACCESS },
            FS::FILE_SHARE_READ | if parent_create { FS::FILE_SHARE_WRITE } else { 0 }, security,
            if parent_create { FS::CREATE_NEW } else { FS::OPEN_EXISTING },
            FS::FILE_FLAG_OPEN_REPARSE_POINT | FS::FILE_ATTRIBUTE_ARCHIVE, null_mut()) };
        b.error = if valid_handle(b.handle) { 0 } else { unsafe { F::GetLastError() } };
        if valid_handle(b.handle) { b.active = false; b.state = SlotState::Owned; }
        else if b.error != 0 && b.error != F::ERROR_IO_PENDING && b.handle == F::INVALID_HANDLE_VALUE {
            b.active = false; b.state = SlotState::NoHandle; self.check(permitted)?; return Err(Error::Unavailable);
        } else { b.state = SlotState::Unknown; return Err(Error::Unknown); }
        self.check(permitted)
    }
    fn named(&mut self, path: &Path, permitted: &dyn Fn() -> bool) -> Result<()> {
        self.named_observed(path, permitted, None)
    }
    fn named_observed(&mut self, path: &Path, permitted: &dyn Fn() -> bool, trace: Option<&ObserverCaptureTrace>) -> Result<()> {
        self.check_observed(permitted, trace)?;
        let mut input = InputTrace::prerequisite_only(trace.is_some());
        let original = self.original.named_traced(path, &mut input);
        read_input_result(trace, &input, original)?; self.check_observed(permitted, trace)
    }
    fn stamp(&mut self, permitted: &dyn Fn() -> bool) -> Result<Stamp> {
        self.stamp_observed(permitted, None)
    }
    fn stamp_observed(&mut self, permitted: &dyn Fn() -> bool, trace: Option<&ObserverCaptureTrace>) -> Result<Stamp> {
        use ObserverCaptureCheck as C;
        // Refresh the borrowed original document checkpoint before AND after
        // every native effect, including each member of the metadata group.
        for which in 0..4 {
            self.check_observed(permitted, trace)?;
            let mut input = InputTrace::prerequisite_only(trace.is_some());
            let original = self.original.info(which, &mut input);
            read_input_result(trace, &input, original)?; self.check_observed(permitted, trace)?;
        }
        let b = self.original.body();
        read_result(trace, C::StampDirectory, need(!b.standard.Directory))?;
        read_result(trace, C::StampDeletePending, need(!b.standard.DeletePending))?;
        read_result(trace, C::StampSize, need(b.standard.EndOfFile >= 0 && b.standard.EndOfFile as usize <= data::BYTE_LIMIT))?;
        read_result(trace, C::StampAllocation, need(b.standard.AllocationSize >= 0))?;
        read_result(trace, C::StampLinks, need(b.standard.NumberOfLinks == 1))?;
        read_result(trace, C::StampAttributes, need(b.tag.FileAttributes == b.basic.FileAttributes))?;
        read_result(trace, C::StampKind, need(b.basic.FileAttributes & (FS::FILE_ATTRIBUTE_REPARSE_POINT | FS::FILE_ATTRIBUTE_DIRECTORY) == 0))?;
        read_result(trace, C::StampFileId, need(b.id.FileId.Identifier != [0; 16]))?;
        Ok(Stamp { volume: b.id.VolumeSerialNumber, id: b.id.FileId.Identifier, creation: b.basic.CreationTime,
            write: b.basic.LastWriteTime, change: b.basic.ChangeTime, size: b.standard.EndOfFile,
            allocation: b.standard.AllocationSize, links: b.standard.NumberOfLinks, attributes: b.basic.FileAttributes })
    }
    fn descriptor(&mut self, acl: &[u8], parent: &[u8], account: &[u8], permitted: &dyn Fn() -> bool) -> Result<()> {
        self.descriptor_observed(acl, parent, account, permitted, None)
    }
    fn descriptor_observed(&mut self, acl: &[u8], parent: &[u8], account: &[u8], permitted: &dyn Fn() -> bool,
        trace: Option<&ObserverCaptureTrace>) -> Result<()> {
        self.check_observed(permitted, trace)?;
        let mut input = InputTrace::prerequisite_only(trace.is_some());
        let original = self.original.descriptor_traced(&mut input);
        let raw = read_input_result(trace, &input, original)?; self.check_observed(permitted, trace)?;
        descriptor_matches(&raw, acl, parent, account, trace)
    }
    fn streams(&mut self, permitted: &dyn Fn() -> bool) -> Result<()> {
        self.streams_observed(permitted, None)
    }
    fn streams_observed(&mut self, permitted: &dyn Fn() -> bool, trace: Option<&ObserverCaptureTrace>) -> Result<()> {
        use ObserverCaptureCheck as C;
        self.check_observed(permitted, trace)?; self.streams.0.fill(0);
        let b = self.original.body(); read_result(trace, C::OriginalOwned, need(b.state == SlotState::Owned))?;
        read_result(trace, C::OriginalInactive, need(!b.active))?; b.active = true;
        self.stream_return = unsafe { FS::GetFileInformationByHandleEx(b.handle, FS::FileStreamInfo,
            self.streams.0.as_mut_ptr().cast(), self.streams.0.len() as u32) };
        b.error = if self.stream_return != 0 { 0 } else { unsafe { F::GetLastError() } };
        b.active = self.stream_return == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
        if b.active { b.state = SlotState::Unknown; return read_result(trace, C::StreamsReturned, Err(Error::Unknown)); }
        let native = (self.stream_return == 0).then_some(ObserverCaptureNative::Win32Streams(b.error));
        self.check_observed(permitted, trace)?;
        let original = need(self.stream_return != 0);
        match trace { Some(trace) => trace.native_result(original, native, None), None => original }?;
        read_streams(trace, &self.streams.0)
    }
    fn append(&mut self, raw: &[u8], permitted: &dyn Fn() -> bool) -> Result<()> {
        self.check(permitted)?; self.original.write(raw, data::RECORD_LIMIT)?; self.check(permitted)
    }
    #[cfg(test)]
    fn read(&mut self, permitted: &dyn Fn() -> bool, trace: Option<&ObserverCaptureTrace>) -> Result<Vec<u8>> {
        use ObserverCaptureCheck as C;
        // SAME pinned parent original and bounded full EOF. The selected90/110
        // gate surrounds EVERY metadata member and the one ReadFile, not just
        // a compound OriginalFile::read call whose ceiling may be110s.
        let before = self.stamp_observed(permitted, trace)?;
        let b = self.original.body(); b.raw = vec![0; before.size as usize + 1]; b.count = 0;
        self.check_observed(permitted, trace)?;
        let b = self.original.body(); read_result(trace, C::ReadState, need(b.state == SlotState::Owned && !b.active))?; b.active = true;
        let returned = unsafe { FS::ReadFile(b.handle, b.raw.as_mut_ptr(), b.raw.len() as u32, &mut b.count, null_mut()) };
        b.error = if returned != 0 { 0 } else { unsafe { F::GetLastError() } };
        b.active = returned == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
        if b.active { b.state = SlotState::Unknown; return read_result(trace, C::ReadReturned, Err(Error::Unknown)); }
        let native = PrerequisiteNative::boolean(PrerequisiteApi::ReadFile, PrerequisiteSelector::None, returned, Some(b.error))
            .map(ObserverCaptureNative::Original);
        self.check_observed(permitted, trace)?;
        let b = self.original.body();
        let original = need(returned != 0);
        match trace { Some(trace) => trace.native_result(original, native, None), None => original }?;
        read_result(trace, C::ReadCount, need(b.count as i64 == before.size))?;
        let raw = b.raw[..b.count as usize].to_vec();
        read_result(trace, C::StampStable, need(self.stamp_observed(permitted, trace)? == before))?; Ok(raw)
    }
    fn close(&mut self) -> Result<()> { self.original.close() } // Original close is allowed late, never retried.
}

/// Existing native owner retains this object BEFORE create enters. No new
/// process/thread/timer, no caller-selected path and no inherited handle.
#[cfg(test)]
pub(crate) struct ObserverDiagnosticOriginal {
    file: JournalFile, path: PathBuf, role: UiRole, parent: Vec<u8>, account: Vec<u8>,
    acl: Box<Aligned>, acl_size: usize, descriptor: Box<S::SECURITY_DESCRIPTOR>, attributes: Box<S::SECURITY_ATTRIBUTES>,
    initialized: i32, dacl_return: i32, control_return: i32, created: Option<Stamp>, binding: Option<String>,
    clock: Arc<ObserverDiagnosticClock>, read_started: bool,
}
#[cfg(test)]
impl ObserverDiagnosticOriginal {
    pub(crate) fn new(role: UiRole, output: &Path, parent: &[u8], account: &[u8], clock: Arc<ObserverDiagnosticClock>) -> Result<Self> {
        let path = fixed_leaf(role, output)?; let (acl, acl_size) = append_acl(parent, account)?;
        Ok(Self { file: JournalFile::new(&path, clock.ceiling())?, path, role, parent: parent.to_vec(), account: account.to_vec(),
            acl, acl_size, descriptor: Box::new(S::SECURITY_DESCRIPTOR::default()), attributes: Box::new(S::SECURITY_ATTRIBUTES::default()),
            initialized: 0, dacl_return: 0, control_return: 0, created: None, binding: None, clock, read_started: false })
    }
    pub(crate) fn create(&mut self, request_sha: &str) -> Result<()> {
        need(self.created.is_none() && self.binding.is_none() && is_hex(request_sha, 64))?;
        let clock = Arc::clone(&self.clock); let permitted = || clock.permitted(false);
        self.file.check(&permitted)?;
        self.initialized = unsafe { S::InitializeSecurityDescriptor((&mut *self.descriptor as *mut S::SECURITY_DESCRIPTOR).cast(), 1) };
        self.file.check(&permitted)?; need(self.initialized != 0)?;
        self.file.check(&permitted)?;
        self.dacl_return = unsafe { S::SetSecurityDescriptorDacl((&mut *self.descriptor as *mut S::SECURITY_DESCRIPTOR).cast(),
            1, self.acl.0.as_ptr().cast(), 0) };
        self.file.check(&permitted)?; need(self.dacl_return != 0)?;
        self.file.check(&permitted)?;
        self.control_return = unsafe { S::SetSecurityDescriptorControl((&mut *self.descriptor as *mut S::SECURITY_DESCRIPTOR).cast(),
            S::SE_DACL_PROTECTED, S::SE_DACL_PROTECTED) };
        self.file.check(&permitted)?; need(self.control_return != 0)?;
        self.attributes.nLength = size_of::<S::SECURITY_ATTRIBUTES>() as u32;
        self.attributes.lpSecurityDescriptor = (&mut *self.descriptor as *mut S::SECURITY_DESCRIPTOR).cast();
        self.attributes.bInheritHandle = 0;
        self.file.open(true, &*self.attributes, &permitted)?;
        self.file.named(&self.path, &permitted)?;
        let stamp = self.file.stamp(&permitted)?; need(stamp.size == 0)?;
        self.file.descriptor(&self.acl.0[..self.acl_size], &self.parent, &self.account, &permitted)?;
        self.file.streams(&permitted)?; need(self.file.stamp(&permitted)? == stamp)?;
        self.binding = Some(format!("1|{request_sha}|{}", stamp.wire())); self.created = Some(stamp); Ok(())
    }
    pub(crate) fn binding(&self, role: UiRole, output: &Path) -> Result<&str> {
        need(self.role == role && self.path == fixed_leaf(role, output)?)?;
        self.binding.as_deref().ok_or(Error::State)
    }
    pub(crate) fn name(&self) -> String { self.role.name(data::SUFFIX) }
    // Caller first opens a retained share-read-only NativeBook cursor under the
    // SAME output original. It excludes writers before this original full EOF.
    pub(crate) fn poststate(&mut self, failure: bool, trace: Option<&ObserverCaptureTrace>) -> Result<(Stamp, Vec<u8>)> {
        use ObserverCaptureCheck as C; use ObserverCaptureOperation as O;
        read_scope(trace, O::JournalReadOnce, || read_result(trace, C::ReadOnce, need(!self.read_started)))?; self.read_started = true;
        let clock = Arc::clone(&self.clock); let permitted = || clock.permitted(failure);
        let expected = Identity::of(read_scope(trace, O::JournalCreated, ||
            read_result(trace, C::Created, self.created.as_ref().ok_or(Error::State)))?);
        read_scope(trace, O::JournalOriginalName, || self.file.named_observed(&self.path, &permitted, trace))?;
        let before = read_scope(trace, O::JournalOriginalMetadataBefore, || self.file.stamp_observed(&permitted, trace))?;
        read_scope(trace, O::JournalOriginalIdentity, || expected.matches_observed(&before, trace))?;
        read_scope(trace, O::JournalAclBefore, || self.file.descriptor_observed(&self.acl.0[..self.acl_size], &self.parent, &self.account, &permitted, trace))?;
        read_scope(trace, O::JournalStreamsBefore, || self.file.streams_observed(&permitted, trace))?;
        let raw = read_scope(trace, O::JournalRead, || self.file.read(&permitted, trace))?;
        read_scope(trace, O::JournalAclAfter, || self.file.descriptor_observed(&self.acl.0[..self.acl_size], &self.parent, &self.account, &permitted, trace))?;
        read_scope(trace, O::JournalStreamsAfter, || self.file.streams_observed(&permitted, trace))?;
        let after = read_scope(trace, O::JournalOriginalMetadataAfter, || self.file.stamp_observed(&permitted, trace))?;
        read_scope(trace, O::JournalOriginalStability, || {
            read_result(trace, C::StampStable, need(after == before))?;
            read_result(trace, C::ReadCount, need(raw.len() == before.size as usize))
        })?;
        Ok((before, raw)) // Raw partial tail is DATA; parsing cannot decide readiness.
    }
    pub(crate) fn close(&mut self) -> Result<()> { self.file.close() }
    pub(crate) fn is_closed(&self) -> bool { self.file.original.is_closed() }
    pub(crate) fn unresolved(&self) -> bool {
        self.file.original.body.active || matches!(self.file.original.body.state,
            SlotState::Acquiring | SlotState::Closing | SlotState::Unknown)
    }
}

/// Fixed observer context contains only Rust DATA/atomics, not a transported
/// HANDLE. Every append cursor and all native buffers stay on its actual caller.
#[cfg(all(feature = "qualification-result", feature = "windows-installed-observation"))]
pub struct ObserverDiagnostic {
    path: PathBuf, identity: Identity, parent: Vec<u8>, account: Vec<u8>, acl: Box<Aligned>, acl_size: usize,
    end: Instant, order: JournalOrder, latch: Latch, startup: AtomicU64, bytes: AtomicUsize,
}
#[cfg(all(feature = "qualification-result", feature = "windows-installed-observation"))]
impl ObserverDiagnostic {
    pub fn admit(end: Instant) -> Result<Self> {
        deadline(Some(end))?; let role = require_normal_ui_qualification()?;
        let request_raw = std::env::var("MRK_WINDOWS_NORMAL_UI_REQUEST").map_err(|_| Error::State)?;
        let request = UiRequest::parse(request_raw.as_bytes())?;
        let output = fixed_path(&std::env::var("MRK_WINDOWS_NORMAL_UI_OUTPUT").map_err(|_| Error::State)?)?;
        request.at_root(output.parent().ok_or(Error::Unsafe)?)?;
        need(std::env::current_dir().map_err(|_| Error::Unavailable)? == output)?;
        let path = fixed_leaf(role, &output)?;
        let raw = std::env::var(data::IDENTITY_ENV).map_err(|_| Error::State)?;
        need(raw.len() <= 228 && raw.is_ascii())?;
        let values: Vec<_> = raw.split('|').collect();
        need(values.len() == 3 && values[0] == "1" && is_hex(values[1], 64)
            && fullwalk_digest(request_raw.as_bytes(), end, false)? == values[1])?;
        let identity = Identity::parse(values[2])?;
        let parent = unhex(&std::env::var("MRK_WINDOWS_PARENT_SID").map_err(|_| Error::State)?)?;
        let account = unhex(&std::env::var("MRK_WINDOWS_ORDINARY_SID").map_err(|_| Error::State)?)?;
        let (acl, acl_size) = append_acl(&parent, &account)?;
        deadline(Some(end))?;
        Ok(Self { path, identity, parent, account, acl, acl_size, end, order: JournalOrder::default(),
            latch: Latch::default(), startup: AtomicU64::new(0), bytes: AtomicUsize::new(0) })
    }
    pub fn refuse(&self, reason: Refusal) { self.latch.refuse(reason); }
    pub fn observe(&self, snapshot: Snapshot) { self.latch.observe(snapshot); }
    pub fn unavailable(&self) { self.order.unavailable(); }
    fn startup_word(&self) -> Option<u64> { match self.startup.load(Ordering::SeqCst) { 0 => None, word => Some(word) } }
    pub fn admitted(&self) { self.emit(Event::MainAdmitted, self.latch.snapshot(), self.startup_word(), &|| true); }
    pub fn progress(&self, permitted: &dyn Fn() -> bool) {
        let snapshot = self.latch.snapshot();
        self.emit(Event::Step(snapshot.step), snapshot, self.startup_word(), permitted);
        if self.latch.first().is_some() { self.emit(Event::ObserverRefusal, snapshot, self.startup_word(), permitted); }
    }
    pub fn builder_returned(&self, permitted: &dyn Fn() -> bool) {
        self.emit(Event::BuilderReturned, self.latch.snapshot(), self.startup_word(), permitted); self.progress(permitted);
    }
    pub fn startup(&self, raw: u64, permitted: &dyn Fn() -> bool) {
        let Some(word) = crate::ui_startup_data::Word::decode(raw) else { self.order.unavailable(); return; };
        // Caller already performed original adoption/invalidation. Do not read
        // the HWND, invent a startup sample, or call a production drive method.
        self.startup.store(raw, Ordering::SeqCst);
        self.emit(if word.first_refusal { Event::StartupRefusal } else { Event::Startup(word.event) },
            self.latch.snapshot(), Some(raw), permitted);
    }
    fn emit(&self, event: Event, snapshot: Snapshot, startup: Option<u64>, permitted: &dyn Fn() -> bool) {
        let Some(permit) = self.order.begin(event) else { return; };
        let mut raw = Frame::default();
        if permit.record(&mut raw, snapshot, startup, self.latch.first()).is_err()
            || self.append_original(raw.bytes(), permitted).is_err() { self.order.disable(); }
        // Permit drops only an atomic gate. No mutex spans any native operation.
    }
    fn append_original(&self, raw: &[u8], permitted: &dyn Fn() -> bool) -> Result<()> {
        use data::{AppendPhase as P, AppendReturn as R};
        let previous = self.bytes.load(Ordering::SeqCst);
        let next = data::next_bytes(previous, raw.len()).ok_or(Error::Bounds)?;
        let mut file = JournalFile::new(&self.path, self.end)?;
        let observed = data::append_once(|phase| {
            let returned = (|| -> Result<()> { match phase {
                P::Inspect => {
                    file.open(false, null(), permitted)?; file.named(&self.path, permitted)?;
                    let before = file.stamp(permitted)?; need(self.identity.matches(&before) && before.size as usize == previous)?;
                    file.descriptor(&self.acl.0[..self.acl_size], &self.parent, &self.account, permitted)?;
                    file.streams(permitted)
                },
                P::Write => file.append(raw, permitted),
                P::InspectWritten => {
                    let after = file.stamp(permitted)?;
                    need(self.identity.matches(&after) && after.size as usize == next)?;
                    file.streams(permitted)
                },
                P::Close => file.close(), // Late original close is permitted, never retried.
            } })();
            match returned { Ok(()) => R::Complete, Err(Error::Unknown) => R::Unresolved, Err(_) => R::Refused }
        });
        if observed == R::Unresolved {
            loop { std::thread::park(); std::hint::black_box((&mut file, self, permitted)); }
        }
        need(observed == R::Complete)?; file.check(permitted)?; self.bytes.store(next, Ordering::SeqCst); Ok(())
    }
}
