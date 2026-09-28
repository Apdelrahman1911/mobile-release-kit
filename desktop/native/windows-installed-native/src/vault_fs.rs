//! One ordinary-account, original-directory NTFS fence feasibility observation.
//!
//! This is NOT a vault, a durability guarantee, an execution owner or a shipping
//! capability. The existing ordinary native epoch registers the fixture and its
//! actual full identity, retains THIS probe outside its original blocking worker,
//! and supplies its existing absolute operation/cleanup endpoints. Never call
//! this from resource-free DATA tests, the UI thread, or renderer-selected paths.
//! No directory/file creation, data write, rename, delete, key or Store call occurs.
use super::{Aligned, Arena, Call, CloseOutcome, DirectoryEntry, Error, FileIdentity,
    FileKind, FileReadPurpose, Held, Kind, Metadata, NativeBook, Original, Phase,
    Result, Returned, SlotState, BUFFER, F, FS, IO, N, NAME_UNITS, OBJECT_ATTRIBUTES};
use std::{cell::{Cell, UnsafeCell}, collections::BTreeSet, marker::PhantomPinned,
    mem::{size_of, ManuallyDrop}, ptr::{null, null_mut}};

const INSPECT_ACCESS: u32 = FS::SYNCHRONIZE | FS::READ_CONTROL | FS::FILE_READ_ATTRIBUTES
    | FS::FILE_LIST_DIRECTORY | FS::FILE_TRAVERSE;
// Expand the SDK's GENERIC_WRITE mapping explicitly, rather than first opening
// read-only and reopening after a flush refusal. FILE_OPEN and SHARE_READ remain
// unchanged. Access denial here is NOT an executed or unsupported fence.
const FENCE_ACCESS: u32 = INSPECT_ACCESS | FS::FILE_GENERIC_WRITE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryFenceStage {
    NotStarted, Token, Mapping, AncestorOpen, TargetOpen, Inheritance, Ntfs,
    Metadata, Streams, DirectoryIdentity, TargetIdentity, AncestorEdge, ContextBeforeFence, Fence,
    Postcheck, MappingAfterFence, ContextAfterFence, Complete, Cleanup,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryFenceClass { NotRun, Supported, Unavailable, RefusedBeforeFence, Stopped, Unknown }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryFenceFailure {
    pub stage: DirectoryFenceStage,
    pub error: Error,
    pub stopped: bool,
}
/// Captured scalar DATA only. On pending/informational/warning results we NEVER
/// read the IOSB. An immediate native error need not initialize it either; only
/// STATUS_SUCCESS authorizes the corroborating IOSB reads recorded here.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectoryFenceIo {
    pub entered: bool,
    pub ntstatus: Option<i32>,
    pub iosb_status: Option<i32>,
    pub iosb_information: Option<u64>,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectoryFenceCleanup {
    pub attempted: bool,
    pub expired: bool,
    pub outcome: Option<CloseOutcome>,
    pub close_attempts: u16,
    pub closed: u16,
    pub no_handle: u16,
    pub unresolved: u16,
    pub first_error: Option<Error>,
}
/// No path, name, SID, handle or file bytes can enter this observation. A None
/// classification means the original run/cleanup has not reached a conclusion.
/// Even Supported is ONLY exact-profile API feasibility, never crash durability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryFenceObservation {
    pub stage: DirectoryFenceStage,
    pub classification: Option<DirectoryFenceClass>,
    pub first_failure: Option<DirectoryFenceFailure>,
    pub target_requested_access: u32,
    pub last_open_directory: Option<u16>,
    pub last_open_requested_access: u32,
    pub last_open: DirectoryFenceIo,
    pub fence: DirectoryFenceIo,
    pub stop_observed: bool,
    pub cleanup: DirectoryFenceCleanup,
}

struct Directory { original: Original, name: String, metadata: Option<Metadata> }
struct FlushFrame {
    handle: F::HANDLE,
    phase: Cell<Phase>,
    returned: Cell<Option<i32>>,
    iosb: UnsafeCell<IO::IO_STATUS_BLOCK>,
    _pin: PhantomPinned,
}

pub struct DirectoryFenceProbe {
    native: NativeBook,
    drive: String,
    components: Vec<String>,
    expected: FileIdentity,
    directories: Vec<Directory>,
    flush: Option<Held<FlushFrame>>,
    begun: bool,
    run_result: Option<Result<()>>,
    observation: DirectoryFenceObservation,
}
// SAFETY: the existing owner moves only exclusive, serialized custody. Windows
// file/token handles are process-wide and pinned output allocations do not move.
// No reference/raw handle escapes; the original worker must return before any
// other thread can borrow this probe. It intentionally is not Sync.
unsafe impl Send for DirectoryFenceProbe {}

impl DirectoryFenceProbe {
    /// DATA only. The caller owes original owner/fixture authorization; path and
    /// identity are not a renderer/environment permission to operate elsewhere.
    pub fn new(path: &str, expected: FileIdentity) -> Result<Self> {
        let (drive, components) = super::project::spelling(path)?;
        if expected.file_id == [0; 16] { return Err(Error::Unsafe); }
        let mut directories = Vec::new();
        directories.try_reserve_exact(components.len() + 1).map_err(|_| Error::Bounds)?;
        Ok(Self { native: NativeBook::new(), drive, components, expected, directories,
            flush: None, begun: false, run_result: None, observation: DirectoryFenceObservation {
                stage: DirectoryFenceStage::NotStarted, classification: Some(DirectoryFenceClass::NotRun),
                first_failure: None, target_requested_access: FENCE_ACCESS,
                last_open_directory: None, last_open_requested_access: 0, last_open: Default::default(),
                fence: Default::default(), stop_observed: false, cleanup: Default::default(),
            } })
    }
    pub fn never_started(&self) -> bool {
        !self.begun && !self.observation.cleanup.attempted && self.native.never_started() && self.flush.is_none()
    }
    pub fn settled(&self) -> bool {
        self.observation.cleanup.outcome == Some(CloseOutcome::Settled)
            && !self.flush_outstanding() && self.native.settled()
    }
    pub fn observation(&self) -> DirectoryFenceObservation {
        let mut value = self.observation;
        value.classification = self.classification();
        value
    }

    /// One original attempt. Always call settle_once on THIS same retained probe
    /// after the actual worker returns, including ordinary failure/unwind paths.
    /// A returning success here is not publication authority or a cleanup receipt.
    pub fn run_once(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        if !self.never_started() {
            return Err(if self.native.is_unknown() || self.flush_outstanding() { Error::Unknown } else { Error::State });
        }
        self.begun = true;
        let result = self.run(stop);
        if let Err(error) = result { self.failure(error, false); }
        self.run_result = Some(result);
        result
    }

    fn checkpoint(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        if stop() {
            self.observation.stop_observed = true;
            self.failure(Error::Unavailable, true);
            Err(Error::Unavailable)
        } else { Ok(()) }
    }
    fn failure(&mut self, error: Error, stopped: bool) {
        if self.observation.first_failure.is_none() {
            self.observation.first_failure = Some(DirectoryFenceFailure { stage: self.observation.stage, error, stopped });
        }
    }
    fn stage(&mut self, value: DirectoryFenceStage, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        self.observation.stage = value;
        self.checkpoint(stop)
    }
    fn run(&mut self, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        self.stage(DirectoryFenceStage::Token, stop)?;
        self.native.observe_user_once()?;
        self.checkpoint(stop)?;
        self.stage(DirectoryFenceStage::Mapping, stop)?;
        let device = self.native.mapping(&self.drive)?;
        self.checkpoint(stop)?;
        let root_name = format!("{device}\\");
        self.stage(DirectoryFenceStage::AncestorOpen, stop)?;
        let original = self.native.reserve(Kind::Directory, None, &root_name, root_name.clone())?;
        self.directories.push(Directory { original, name: String::new(), metadata: None });
        self.open_directory(0, INSPECT_ACCESS)?;
        self.checkpoint(stop)?;
        self.admit(0, stop)?;
        for component in 0..self.components.len() {
            let target = component + 1 == self.components.len();
            self.stage(if target { DirectoryFenceStage::TargetOpen } else { DirectoryFenceStage::AncestorOpen }, stop)?;
            let parent = self.directories.len() - 1;
            let name = self.components[component].clone();
            let slot = self.native.slot(self.directories[parent].original.index)?;
            let canonical = format!("{}{}{}", slot.canonical, if slot.canonical.ends_with('\\') { "" } else { "\\" }, name);
            if canonical.encode_utf16().count() >= NAME_UNITS { return Err(Error::Bounds); }
            let original = self.native.reserve(Kind::Directory, Some(self.directories[parent].original.index), &name, canonical)?;
            // Constructor reserved complete path capacity. Register the actual
            // original BEFORE its one native attempt, never after a STOP check.
            self.directories.push(Directory { original, name, metadata: None });
            let index = self.directories.len() - 1;
            self.open_directory(index, if target { FENCE_ACCESS } else { INSPECT_ACCESS })?;
            self.checkpoint(stop)?;
            self.admit(index, stop)?;
        }
        self.stage(DirectoryFenceStage::TargetIdentity, stop)?;
        if self.metadata(self.directories.len() - 1)?.identity != self.expected { return Err(Error::Unsafe); }
        for parent in 0..self.directories.len() - 1 { self.same_parent(parent, stop)?; }
        for index in (0..self.directories.len()).rev() { self.postcheck(index, stop)?; }
        self.stage(DirectoryFenceStage::Mapping, stop)?;
        if self.native.mapping(&self.drive)? != device { return Err(Error::Unsafe); }
        self.checkpoint(stop)?;
        self.stage(DirectoryFenceStage::ContextBeforeFence, stop)?;
        self.native.recheck_user()?;
        self.checkpoint(stop)?;
        self.stage(DirectoryFenceStage::Fence, stop)?;
        let fence = self.flush_once();
        if let Err(error) = fence { self.failure(error, false); }
        // Preserve the actual native failure before a late STOP/postcheck. A
        // definite native negative still gets original identity/context checks;
        // pending/unknown NEVER permits more IO against dependent originals.
        if self.native.is_unknown() || self.flush_outstanding() { return Err(Error::Unknown); }
        let postcheck = self.after_fence(&device, stop);
        if let Err(error) = postcheck { self.failure(error, false); }
        fence.and(postcheck)
    }

    fn metadata(&self, index: usize) -> Result<&Metadata> {
        self.directories.get(index).and_then(|value| value.metadata.as_ref()).ok_or(Error::State)
    }
    fn sample(&mut self, index: usize, stop: &mut dyn FnMut() -> bool) -> Result<Metadata> {
        self.stage(DirectoryFenceStage::Ntfs, stop)?;
        self.native.local_ntfs(&self.directories.get(index).ok_or(Error::State)?.original)?;
        self.checkpoint(stop)?;
        self.stage(DirectoryFenceStage::Metadata, stop)?;
        let metadata = self.native.metadata(&self.directories[index].original)?;
        self.checkpoint(stop)?;
        self.stage(DirectoryFenceStage::Streams, stop)?;
        self.native.no_alternate_streams(&self.directories[index].original)?;
        self.checkpoint(stop)?;
        Ok(metadata)
    }
    fn admit(&mut self, index: usize, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        self.stage(DirectoryFenceStage::Inheritance, stop)?;
        self.native.noninherited(self.directories.get(index).ok_or(Error::State)?.original.index)?;
        self.checkpoint(stop)?;
        let metadata = self.sample(index, stop)?;
        self.stage(DirectoryFenceStage::DirectoryIdentity, stop)?;
        if metadata.kind != FileKind::Directory
            || index > 0 && metadata.identity.volume_serial != self.metadata(index - 1)?.identity.volume_serial
            || self.directories.iter().filter_map(|value| value.metadata.as_ref()).any(|prior| prior.identity == metadata.identity) {
            return Err(Error::Unsafe);
        }
        self.directories[index].metadata = Some(metadata);
        Ok(())
    }
    fn postcheck(&mut self, index: usize, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        let actual = self.sample(index, stop)?;
        self.stage(DirectoryFenceStage::Postcheck, stop)?;
        if !same_directory(self.metadata(index)?, &actual) { return Err(Error::Unsafe); }
        Ok(())
    }
    fn same_parent(&mut self, parent: usize, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        let selected = self.directories[parent + 1].name.clone();
        let mut names = BTreeSet::new();
        let mut found = false;
        loop {
            self.stage(DirectoryFenceStage::AncestorEdge, stop)?;
            let batch = self.native.next_ancestor_entries(&self.directories[parent].original, &selected)?;
            self.checkpoint(stop)?;
            let Some(batch) = batch else { break };
            for entry in batch {
                if !names.insert(entry.name.to_ascii_lowercase()) { return Err(Error::Unsafe); }
                if entry.name == "." || entry.name == ".." {
                    let expected = if entry.name == "." { parent } else { parent.saturating_sub(1) };
                    if entry.kind != FileKind::Directory || entry.file_id != self.metadata(expected)?.identity.file_id { return Err(Error::Unsafe); }
                } else if entry.name.eq_ignore_ascii_case(&selected) {
                    if found || !selected_edge(&entry, &selected, self.metadata(parent + 1)?) { return Err(Error::Unsafe); }
                    found = true;
                }
            }
        }
        if !found { return Err(Error::Unsafe); }
        self.postcheck(parent, stop)
    }
    fn after_fence(&mut self, device: &str, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        self.checkpoint(stop)?;
        for index in (0..self.directories.len()).rev() { self.postcheck(index, stop)?; }
        self.stage(DirectoryFenceStage::MappingAfterFence, stop)?;
        if self.native.mapping(&self.drive)? != device { return Err(Error::Unsafe); }
        self.checkpoint(stop)?;
        self.stage(DirectoryFenceStage::ContextAfterFence, stop)?;
        self.native.recheck_user()?;
        self.checkpoint(stop)?;
        self.observation.stage = DirectoryFenceStage::Complete;
        Ok(())
    }

    fn open_directory(&mut self, directory: usize, access: u32) -> Result<()> {
        self.native.clear()?;
        let index = self.directories.get(directory).ok_or(Error::State)?.original.index;
        let slot = self.native.slot(index)?;
        let required = if directory == self.components.len() { FENCE_ACCESS } else { INSPECT_ACCESS };
        if slot.kind != Kind::Directory || slot.state != SlotState::Reserved
            || access != required { return Err(Error::State); }
        self.observation.last_open_directory = Some(u16::try_from(directory).map_err(|_| Error::Bounds)?);
        self.observation.last_open_requested_access = access;
        self.observation.last_open = Default::default();
        // Same pinned Slot/Arena, OBJ_DONT_REPARSE, synchronous FILE_OPEN and
        // completion adoption as NativeBook. Only the predeclared desired access
        // differs. Do not broaden NativeBook::open_child or its read-only policy.
        let call = Call::Open(index);
        let mut frame = Box::pin(Arena { call, token_length: 0, phase: Cell::new(Phase::Prepared), returned: Cell::new(None),
            completion_refusal: Cell::new(None), input: slot.name.clone(), handle: null_mut(), output_handle: slot.output.get(),
            unicode: F::UNICODE_STRING::default(), attributes: OBJECT_ATTRIBUTES::default(),
            directory: true, file_purpose: FileReadPurpose::Content, bytes: UnsafeCell::new(Aligned([0; BUFFER])),
            count: UnsafeCell::new(u32::MAX), iosb: UnsafeCell::new(pending_iosb()), _pin: PhantomPinned });
        // SAFETY: initialize only fields of the fresh pinned frame, before any
        // OS entry. Input allocation and original output cell remain retained.
        let setup = unsafe { frame.as_mut().get_unchecked_mut() };
        setup.unicode.Length = u16::try_from((setup.input.len() - 1) * 2).map_err(|_| Error::Bounds)?;
        setup.unicode.MaximumLength = u16::try_from(setup.input.len() * 2).map_err(|_| Error::Bounds)?;
        setup.unicode.Buffer = setup.input.as_mut_ptr();
        setup.attributes.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
        setup.attributes.RootDirectory = match slot.parent { Some(parent) => self.native.handle(parent)?, None => null_mut() };
        setup.attributes.ObjectName = &setup.unicode;
        setup.attributes.Attributes = F::OBJ_DONT_REPARSE;
        self.native.active = Some(ManuallyDrop::new(frame));
        self.native.mark_entered(call)?;
        self.observation.last_open.entered = true;
        let frame = self.native.arena()?;
        // SAFETY: all inputs/output cells and parents are pinned/registered in
        // this original book before entry. No callback divides return/capture.
        let status = unsafe { N::NtCreateFile(frame.output_handle, access, &frame.attributes, frame.iosb.get(),
            null(), 0, FS::FILE_SHARE_READ, N::FILE_OPEN,
            N::FILE_SYNCHRONOUS_IO_NONALERT | N::FILE_DIRECTORY_FILE, null(), 0) };
        frame.returned.set(Some(Returned::Nt(status)));
        frame.phase.set(Phase::Returned);
        self.observation.last_open.ntstatus = Some(status);
        if status == F::STATUS_SUCCESS {
            // SAFETY: only completed SUCCESS authorizes corroborating IOSB;
            // finish below retains contradictions/invalid/duplicate handles.
            let io = unsafe { &*frame.iosb.get() };
            self.observation.last_open.iosb_status = Some(unsafe { io.Anonymous.Status });
            self.observation.last_open.iosb_information = Some(io.Information as u64);
        }
        self.native.finish(call, Returned::Nt(status)).map(|_| ())
    }

    fn flush_once(&mut self) -> Result<()> {
        self.native.clear()?;
        if self.flush.is_some() { return Err(Error::State); }
        let target = self.directories.last().ok_or(Error::State)?;
        if target.metadata.as_ref().ok_or(Error::State)?.identity != self.expected { return Err(Error::Unsafe); }
        let handle = self.native.handle(target.original.index)?;
        self.flush = Some(ManuallyDrop::new(Box::pin(FlushFrame { handle, phase: Cell::new(Phase::Prepared),
            returned: Cell::new(None), iosb: UnsafeCell::new(pending_iosb()), _pin: PhantomPinned })));
        let frame = self.flush.as_ref().ok_or(Error::State)?.as_ref().get_ref();
        frame.phase.set(Phase::Entered);
        self.observation.fence.entered = true;
        // SAFETY: one registered original directory, explicit flush access,
        // synchronous mode, no callback/worker/APC, and pinned ORIGINAL IOSB.
        // Flags0 requests the full API fence, never DATA_ONLY/NO_SYNC fallback.
        let status = unsafe { N::NtFlushBuffersFileEx(frame.handle, 0, null(), 0, frame.iosb.get()) };
        frame.returned.set(Some(status)); // immediate scalar custody before STOP
        frame.phase.set(Phase::Returned);
        self.observation.fence.ntstatus = Some(status);
        if !definite_nt(status) {
            self.native.mark_interrupted();
            return Err(Error::Unknown); // NEVER read pending/ambiguous IOSB
        }
        let io_status = if status == F::STATUS_SUCCESS {
            // SAFETY: STATUS_SUCCESS completed the original synchronous call.
            let io = unsafe { &*frame.iosb.get() };
            let io_status = unsafe { io.Anonymous.Status };
            self.observation.fence.iosb_status = Some(io_status);
            self.observation.fence.iosb_information = Some(io.Information as u64);
            Some(io_status)
        } else { None }; // native immediate failure need not write IOSB
        if flush_result(status, io_status) == Err(Error::Unknown) {
            self.native.mark_interrupted();
            return Err(Error::Unknown);
        }
        frame.phase.set(Phase::Complete);
        flush_result(status, io_status)
    }
    fn flush_outstanding(&self) -> bool {
        self.flush.as_ref().is_some_and(|frame| frame.as_ref().get_ref().phase.get() != Phase::Complete)
    }

    /// One original bounded cleanup attempt; repeated calls only observe. Do
    /// not pass a renewed deadline. Unknown/pending retains the same originals,
    /// and the caller MUST retain this probe in its existing non-final wait path.
    pub fn settle_once(&mut self, cleanup_expired: &mut dyn FnMut() -> bool) -> CloseOutcome {
        if self.observation.cleanup.attempted {
            return if self.settled() { CloseOutcome::Settled } else { CloseOutcome::Unknown };
        }
        self.observation.cleanup.attempted = true;
        self.observation.stage = DirectoryFenceStage::Cleanup;
        self.native.retiring = true;
        if self.flush_outstanding() || self.native.active.is_some() {
            self.native.mark_interrupted();
            self.observation.cleanup.first_error = Some(Error::Unknown);
        } else {
            for index in (0..self.native.slots.len()).rev() {
                let state = self.native.slots[index].state;
                if matches!(state, SlotState::NoHandle | SlotState::Closed) { continue; }
                if self.cleanup_cutoff(cleanup_expired) { break; }
                let result = self.native.close_index(index);
                let after = self.native.slots[index].state;
                // A dependency refusal is not a CloseHandle attempt. These
                // states are published only by the actual original close path.
                if state == SlotState::Owned && matches!(after, SlotState::Closing | SlotState::Closed | SlotState::Unknown) {
                    self.observation.cleanup.close_attempts += 1;
                }
                if let Err(error) = result {
                    if self.observation.cleanup.first_error.is_none() { self.observation.cleanup.first_error = Some(error); }
                    self.native.mark_interrupted();
                }
                if self.cleanup_cutoff(cleanup_expired) { break; }
            }
            // Also check an empty/already-settled roster; clock lateness is not
            // erased by having no CloseHandle call to perform.
            if !self.observation.cleanup.expired { self.cleanup_cutoff(cleanup_expired); }
        }
        for slot in &self.native.slots {
            match slot.state {
                SlotState::NoHandle => self.observation.cleanup.no_handle += 1,
                SlotState::Closed => self.observation.cleanup.closed += 1,
                _ => self.observation.cleanup.unresolved += 1,
            }
        }
        if self.observation.cleanup.unresolved != 0 { self.native.mark_interrupted(); }
        let outcome = if !self.flush_outstanding() && self.native.settled() { CloseOutcome::Settled } else { CloseOutcome::Unknown };
        self.observation.cleanup.outcome = Some(outcome);
        outcome
    }
    fn cleanup_cutoff(&mut self, expired: &mut dyn FnMut() -> bool) -> bool {
        if expired() {
            self.observation.cleanup.expired = true;
            self.observation.stop_observed = true;
            self.failure(Error::Unavailable, true);
            true
        } else { false }
    }
    fn classification(&self) -> Option<DirectoryFenceClass> {
        use DirectoryFenceClass as Class;
        if self.native.is_unknown() || self.flush_outstanding() { return Some(Class::Unknown); }
        if !self.begun { return Some(Class::NotRun); }
        if !self.observation.cleanup.attempted { return None; }
        if !self.settled() || self.run_result.is_none() { return Some(Class::Unknown); }
        if let Some(failure) = self.observation.first_failure {
            return Some(if failure.error == Error::Unknown { Class::Unknown }
                else if failure.stopped { Class::Stopped }
                else if !self.observation.fence.entered { Class::RefusedBeforeFence }
                else { Class::Unavailable });
        }
        if self.run_result == Some(Ok(())) && self.observation.fence.entered
            && flush_result(self.observation.fence.ntstatus.unwrap_or(F::STATUS_PENDING), self.observation.fence.iosb_status).is_ok()
            && !self.observation.stop_observed && !self.observation.cleanup.expired {
            Some(Class::Supported)
        } else { Some(Class::Unknown) }
    }
}
impl Drop for DirectoryFenceProbe {
    fn drop(&mut self) {
        // No native cleanup/retry/receipt in Drop. An incomplete ORIGINAL IOSB
        // may still be written; keep its allocation. NativeBook likewise retains
        // its uncertain originals. This fallback is NOT owner reachability.
        if let Some(frame) = self.flush.as_mut() {
            if frame.as_ref().get_ref().phase.get() == Phase::Complete {
                // SAFETY: no outstanding writer or earlier manual drop exists.
                unsafe { ManuallyDrop::drop(frame); }
            }
        }
    }
}

fn pending_iosb() -> IO::IO_STATUS_BLOCK {
    IO::IO_STATUS_BLOCK { Anonymous: IO::IO_STATUS_BLOCK_0 { Status: F::STATUS_PENDING }, Information: usize::MAX }
}
fn definite_nt(status: i32) -> bool { status == F::STATUS_SUCCESS || (status as u32 >> 30) == 3 }
fn flush_result(status: i32, io_status: Option<i32>) -> Result<()> {
    if !definite_nt(status) { Err(Error::Unknown) }
    else if status != F::STATUS_SUCCESS { Err(Error::Unavailable) }
    else if io_status != Some(F::STATUS_SUCCESS) { Err(Error::Unknown) }
    else { Ok(()) }
}
fn same_directory(expected: &Metadata, actual: &Metadata) -> bool {
    // Sibling timestamp/link churn is not an identity change in an ordinary
    // fixture. Native metadata independently refuses reparse/delete/case states.
    expected.kind == FileKind::Directory && actual.kind == FileKind::Directory
        && expected.identity == actual.identity && expected.attributes == actual.attributes
}
fn selected_edge(entry: &DirectoryEntry, selected: &str, target: &Metadata) -> bool {
    entry.name == selected && entry.kind == FileKind::Directory && target.kind == FileKind::Directory
        && entry.file_id == target.identity.file_id && entry.attributes == target.attributes
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> FileIdentity { FileIdentity { volume_serial: 9, file_id: [0x83; 16] } }
    fn metadata() -> Metadata { Metadata { identity: identity(), kind: FileKind::Directory,
        attributes: FS::FILE_ATTRIBUTE_DIRECTORY, size: 0, allocation_size: 0, links: 1,
        creation: 1, write: 2, change: 3 } }
    #[test]
    fn construction_and_early_stop_are_data_only_and_one_shot() -> Result<()> {
        for path in [r"C:\fixtures\..\elsewhere", r"\\server\fixture", r"C:\fixture:stream", r"C:\"] {
            assert!(DirectoryFenceProbe::new(path, identity()).is_err());
        }
        assert!(DirectoryFenceProbe::new(r"C:\fixture", FileIdentity { volume_serial: 9, file_id: [0; 16] }).is_err());
        let mut probe = DirectoryFenceProbe::new(r"C:\fixture", identity())?;
        assert!(probe.never_started());
        assert_eq!(probe.observation().classification, Some(DirectoryFenceClass::NotRun));
        assert_eq!(probe.run_once(&mut || true), Err(Error::Unavailable));
        assert!(probe.native.never_started()); assert!(probe.native.slots.is_empty());
        assert!(!probe.observation().fence.entered); assert!(probe.flush.is_none());
        assert_eq!(probe.observation().classification, None);
        assert_eq!(probe.settle_once(&mut || false), CloseOutcome::Settled);
        assert_eq!(probe.observation().classification, Some(DirectoryFenceClass::Stopped));
        assert_eq!(probe.observation().cleanup.close_attempts, 0);
        assert_eq!(probe.run_once(&mut || false), Err(Error::State));
        assert_eq!(probe.settle_once(&mut || panic!("repeat must not renew cleanup")), CloseOutcome::Settled);
        Ok(())
    }
    #[test]
    fn native_completion_data_distinguishes_refusal_pending_and_corroboration() {
        assert_eq!(flush_result(F::STATUS_SUCCESS, Some(F::STATUS_SUCCESS)), Ok(()));
        for status in [F::STATUS_PENDING, 1, 0x40000001_u32 as i32, 0x80000005_u32 as i32] {
            assert!(!definite_nt(status));
            assert_eq!(flush_result(status, Some(F::STATUS_SUCCESS)), Err(Error::Unknown));
        }
        for io in [None, Some(F::STATUS_PENDING), Some(F::STATUS_INVALID_DEVICE_REQUEST)] {
            assert_eq!(flush_result(F::STATUS_SUCCESS, io), Err(Error::Unknown));
        }
        assert_eq!(flush_result(F::STATUS_INVALID_DEVICE_REQUEST, None), Err(Error::Unavailable));
        assert_eq!(FENCE_ACCESS & FS::FILE_GENERIC_WRITE, FS::FILE_GENERIC_WRITE);
        assert_eq!(INSPECT_ACCESS & (FS::FILE_WRITE_DATA | FS::FILE_APPEND_DATA), 0);
        assert_eq!(FENCE_ACCESS & (FS::DELETE | FS::WRITE_DAC | FS::WRITE_OWNER), 0);
    }
    #[test]
    fn first_native_failure_survives_later_stop_and_cleanup_data() -> Result<()> {
        let mut probe = DirectoryFenceProbe::new(r"C:\fixture", identity())?;
        // Populate scalar bookkeeping only; this is NOT a synthetic native pass.
        probe.begun = true; probe.run_result = Some(Err(Error::Unavailable));
        probe.observation.stage = DirectoryFenceStage::TargetOpen;
        probe.observation.last_open.entered = true;
        probe.observation.last_open.ntstatus = Some(F::STATUS_ACCESS_DENIED);
        probe.failure(Error::Unavailable, false);
        assert_eq!(probe.checkpoint(&mut || true), Err(Error::Unavailable));
        assert_eq!(probe.settle_once(&mut || false), CloseOutcome::Settled);
        let facts = probe.observation();
        assert_eq!(facts.classification, Some(DirectoryFenceClass::RefusedBeforeFence));
        assert_eq!(facts.first_failure, Some(DirectoryFenceFailure { stage: DirectoryFenceStage::TargetOpen,
            error: Error::Unavailable, stopped: false }));
        assert_eq!(facts.last_open.ntstatus, Some(F::STATUS_ACCESS_DENIED));
        assert!(!facts.fence.entered); assert_eq!(facts.cleanup.close_attempts, 0);
        Ok(())
    }
    #[test]
    fn cleanup_expiry_retains_original_reservation_without_retry() -> Result<()> {
        let mut probe = DirectoryFenceProbe::new(r"C:\fixture", identity())?;
        // reserve() is inert. No native handle value is constructed or closed.
        let original = probe.native.reserve(Kind::Directory, None, "fixture", "fixture".into())?;
        probe.begun = true; probe.run_result = Some(Err(Error::Unavailable));
        assert_eq!(probe.settle_once(&mut || true), CloseOutcome::Unknown);
        assert_eq!(probe.native.state(&original)?, SlotState::Reserved);
        assert_eq!(probe.observation().cleanup.unresolved, 1);
        assert_eq!(probe.observation().cleanup.close_attempts, 0);
        assert_eq!(probe.observation().classification, Some(DirectoryFenceClass::Unknown));
        assert_eq!(probe.settle_once(&mut || panic!("unknown must not retry")), CloseOutcome::Unknown);
        assert!(!probe.settled());
        Ok(())
    }
    #[test]
    fn outstanding_frame_blocks_cleanup_and_reentry_without_native_calls() -> Result<()> {
        let mut probe = DirectoryFenceProbe::new(r"C:\fixture", identity())?;
        // Inert original output storage, NOT an entered Windows call. No valid
        // native handle is manufactured and no receipt claims native execution.
        probe.begun = true;
        probe.flush = Some(ManuallyDrop::new(Box::pin(FlushFrame { handle: null_mut(),
            phase: Cell::new(Phase::Prepared), returned: Cell::new(None),
            iosb: UnsafeCell::new(pending_iosb()), _pin: PhantomPinned })));
        assert!(probe.flush_outstanding());
        assert_eq!(probe.settle_once(&mut || panic!("outstanding cannot enter cleanup")), CloseOutcome::Unknown);
        assert_eq!(probe.observation().classification, Some(DirectoryFenceClass::Unknown));
        assert_eq!(probe.observation().cleanup.close_attempts, 0);
        assert_eq!(probe.run_once(&mut || panic!("unknown cannot reenter")), Err(Error::Unknown));
        assert_eq!(probe.settle_once(&mut || panic!("unknown cannot retry")), CloseOutcome::Unknown);
        assert!(!probe.settled());
        // Only test-local, never-entered heap storage is reclaimed. Production
        // never removes an unresolved frame, manufactures completion or retries.
        drop(ManuallyDrop::into_inner(probe.flush.take().ok_or(Error::State)?));
        Ok(())
    }
    #[test]
    fn cleanup_callback_unwind_cannot_publish_finality_or_renew_the_attempt() -> Result<()> {
        let mut probe = DirectoryFenceProbe::new(r"C:\fixture", identity())?;
        assert_eq!(probe.run_once(&mut || true), Err(Error::Unavailable));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            probe.settle_once(&mut || panic!("inert cleanup clock failure"))
        }));
        assert!(result.is_err()); assert!(probe.native.slots.is_empty());
        assert!(probe.native.settled()); // Underlying empty roster is not probe finality.
        assert!(!probe.settled()); assert_eq!(probe.observation().cleanup.outcome, None);
        assert_eq!(probe.observation().classification, Some(DirectoryFenceClass::Unknown));
        assert_eq!(probe.settle_once(&mut || panic!("incomplete cleanup cannot retry")), CloseOutcome::Unknown);
        Ok(())
    }
    #[test]
    fn directory_identity_and_edge_use_all_bits_and_exact_spelling() {
        let original = metadata();
        let mut later = original.clone(); later.change += 1; later.write += 1; later.links += 1;
        assert!(same_directory(&original, &later));
        for byte in 0..16 {
            let mut other = original.clone(); other.identity.file_id[byte] ^= 0x80;
            assert!(!same_directory(&original, &other));
        }
        let mut other = original.clone(); other.identity.volume_serial ^= 1 << 63;
        assert!(!same_directory(&original, &other));
        let mut entry = DirectoryEntry { name: "fixture".into(), file_id: original.identity.file_id,
            kind: FileKind::Directory, attributes: original.attributes };
        assert!(selected_edge(&entry, "fixture", &original));
        entry.name = "Fixture".into(); assert!(!selected_edge(&entry, "fixture", &original));
        entry.name = "fixture".into(); entry.file_id[15] ^= 1; assert!(!selected_edge(&entry, "fixture", &original));
    }
}
