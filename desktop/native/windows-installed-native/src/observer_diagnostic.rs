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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ObserverCaptureFailure {
    pub(crate) operation: ObserverCaptureOperation, pub(crate) check: ObserverCaptureCheck,
    pub(crate) index: Option<u8>, pub(crate) error: Option<Error>,
    pub(crate) native: Option<ObserverCaptureNative>, pub(crate) detail: Option<PrerequisiteDetail>,
}
impl ObserverCaptureFailure {
    fn valid(self) -> bool {
        use ObserverCaptureCheck as C;
        if !capture_position_valid(self.operation, self.index) || self.error == Some(Error::Unknown) { return false; }
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
            operation: self.operation.get(), check, index: self.index.get(), error, native, detail })); }
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
