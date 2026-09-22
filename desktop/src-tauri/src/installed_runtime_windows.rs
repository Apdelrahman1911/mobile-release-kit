//! Retained NTFS sealed-version inspection DATA and original settlement only.
//!
//! Register this entire book in the caller's original retained resources before
//! releasing blocking work. It creates no worker, clock, process or capability.
//! A method may remain blocked after STOP/deadline; that original borrower/book
//! must remain reachable. Do not call interruption/settlement concurrently.
//! Closed ordinary payload handles cannot authorize future pathname consumption.
//! Publication, loaded-image admission and the producing owner join remain closed.
#![forbid(unsafe_code)]

use std::{collections::BTreeSet, time::Instant};
use mrk_windows_installed_native as native;
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use crate::runtime::windows_version::{self, Inventory, InventoryKind, InventoryProgress, VersionSpec, BLOCK_SIZE, MANIFEST_BYTES, SELECTED};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionFailure {
    Binding, Stopped, Deadline, NativeUnavailable, Unsafe, Bounds,
    AlreadyUsed, Manifest, Inventory, Identity, Unknown,
}
type Result<T> = std::result::Result<T, InspectionFailure>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase { New, Inspecting, Inspected, Refused, Settling, Settled, Unknown }

struct Record {
    original: native::Original,
    parent: Option<usize>,
    scope: native::AuthorityScope,
    protected_boundary: bool,
    keep: bool,
    closed: bool,
    metadata: Option<native::Metadata>,
    security: Option<native::SecurityFacts>,
}
impl Record {
    fn new(original: native::Original, parent: Option<usize>, scope: native::AuthorityScope,
        protected_boundary: bool, keep: bool) -> Self {
        Self { original, parent, scope, protected_boundary, keep, closed: false, metadata: None, security: None }
    }
}

/// Bounded facts, not executable paths, transferable handles or an owner receipt.
#[derive(Debug)]
pub(crate) struct VersionObservation {
    pub(crate) target: &'static str,
    pub(crate) manifest_sha256: String,
    pub(crate) inventory_sha256: String,
    pub(crate) core_sha256: String,
    pub(crate) files: usize,
    pub(crate) entries: usize,
    pub(crate) payload_bytes: u64,
    pub(crate) version_identity: native::FileIdentity,
    pub(crate) selected_identities: [native::FileIdentity; 3],
}

pub(crate) struct WindowsVersionBook {
    native: native::NativeBook,
    phase: Phase,
    call_pending: bool,
    settlement_attempted: bool,
    records: Vec<Record>,
    identities: BTreeSet<(u64, [u8; 16])>,
    locations: Option<native::KnownLocations>,
    selected: [Option<usize>; 3],
    entries: usize,
    observation: Option<VersionObservation>,
}

fn checkpoint(end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
    if *stop.borrow() || stop.has_changed().is_err() { return Err(InspectionFailure::Stopped); }
    if Instant::now() >= end { return Err(InspectionFailure::Deadline); }
    Ok(())
}
fn native_failure(error: native::Error) -> InspectionFailure {
    match error {
        native::Error::Unavailable => InspectionFailure::NativeUnavailable,
        native::Error::Unsafe => InspectionFailure::Unsafe,
        native::Error::Bounds => InspectionFailure::Bounds,
        native::Error::State => InspectionFailure::AlreadyUsed,
        native::Error::Unknown => InspectionFailure::Unknown,
    }
}
// This is one existing NativeBook METHOD boundary, not per-FFI cancellation.
// Completion and newly acquired original keys are recorded before post-call STOP.
fn finish_method<T>(book: &mut native::NativeBook, phase: &mut Phase, pending: &mut bool,
    returned: native::Result<T>, end: Instant, stop: &watch::Receiver<bool>) -> Result<T> {
    *pending = false; // the actual synchronous method invocation has returned
    if book.is_unknown() || matches!(&returned, Err(native::Error::Unknown)) {
        book.mark_interrupted(); *phase = Phase::Unknown;
        return Err(InspectionFailure::Unknown);
    }
    let after = checkpoint(end, stop);
    match returned {
        Err(error) => Err(native_failure(error)),
        Ok(value) => { after?; Ok(value) },
    }
}
fn method<T>(book: &mut native::NativeBook, phase: &mut Phase, pending: &mut bool,
    end: Instant, stop: &watch::Receiver<bool>, invoke: impl FnOnce(&mut native::NativeBook) -> native::Result<T>) -> Result<T> {
    if book.is_unknown() || *pending || *phase == Phase::Unknown {
        *phase = Phase::Unknown; return Err(InspectionFailure::Unknown);
    }
    if *phase != Phase::Inspecting { return Err(InspectionFailure::AlreadyUsed); }
    checkpoint(end, stop)?;
    *pending = true;
    let returned = invoke(book);
    finish_method(book, phase, pending, returned, end, stop)
}
fn retained_path(path: &str) -> bool {
    SELECTED.iter().any(|selected| *selected == path || selected.strip_prefix(path).is_some_and(|tail| tail.starts_with('/')))
}

impl WindowsVersionBook {
    pub(crate) fn new() -> Self {
        Self { native: native::NativeBook::new(), phase: Phase::New, call_pending: false,
            settlement_attempted: false, records: Vec::new(), identities: BTreeSet::new(), locations: None,
            selected: [None; 3], entries: 0, observation: None }
    }
    pub(crate) fn never_started(&self) -> bool {
        self.phase == Phase::New && !self.call_pending && !self.settlement_attempted
            && self.native.never_started() && self.records.is_empty() && self.observation.is_none()
    }
    pub(crate) fn inspect_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<&VersionObservation> {
        if self.phase == Phase::Unknown || self.native.is_unknown() { return Err(InspectionFailure::Unknown); }
        if self.phase != Phase::New { return Err(InspectionFailure::AlreadyUsed); }
        self.phase = Phase::Inspecting;
        match self.inspect(end, stop) {
            Ok(observation) => {
                self.observation = Some(observation); self.phase = Phase::Inspected;
                self.observation.as_ref().ok_or(InspectionFailure::Unknown)
            },
            Err(error) => {
                if self.native.is_unknown() || self.call_pending || error == InspectionFailure::Unknown {
                    self.phase = Phase::Unknown; Err(InspectionFailure::Unknown)
                } else { self.phase = Phase::Refused; Err(error) }
            },
        }
    }
    fn inspect(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<VersionObservation> {
        checkpoint(end, stop)?;
        let spec = VersionSpec::compiled().map_err(|_| InspectionFailure::Binding)?;
        method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop,
            |book| book.observe_user_once().map(|_| ()))?;
        let locations = &mut self.locations;
        method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop, |book| {
            *locations = Some(book.known_locations_once()?); Ok(())
        })?;
        let mut components = self.locations.as_ref().ok_or(InspectionFailure::Unknown)?.program_files.components().to_vec();
        components.extend(spec.components().into_iter().map(str::to_owned));
        let mut current = self.open_volume(end, stop)?;
        for (index, name) in components.iter().enumerate() {
            // Outside the version, unrelated sibling attributes are DATA only.
            // No sibling is opened. Every selected component remains ordinary.
            let entries = self.enumerate(current, Some(name), end, stop)?;
            let entry = entries.iter().find(|entry| entry.name == *name).ok_or(InspectionFailure::Inventory)?;
            if entry.kind != native::FileKind::Directory { return Err(InspectionFailure::Inventory); }
            let boundary = index + 1 == components.len();
            let scope = if boundary { native::AuthorityScope::ImmutableVersion } else { native::AuthorityScope::AncestorOutsideVersion };
            current = self.open_child(current, entry, scope, boundary, true, end, stop)?;
        }
        let version = current;
        // The version's original cursor is consumed once and cached as bounded
        // DATA. Reading manifest first never restarts/reopens that directory.
        let entries = self.enumerate(version, None, end, stop)?;
        let entry = entries.iter().find(|entry| entry.name == "manifest.json").ok_or(InspectionFailure::Manifest)?;
        if entry.kind != native::FileKind::File { return Err(InspectionFailure::Manifest); }
        let manifest = self.open_child(version, entry, native::AuthorityScope::ImmutableVersion, false, false, end, stop)?;
        let size = self.metadata(manifest)?.size;
        if size == 0 || size > MANIFEST_BYTES { return Err(InspectionFailure::Manifest); }
        let mut bytes = Vec::new();
        bytes.try_reserve(usize::try_from(size).map_err(|_| InspectionFailure::Bounds)?).map_err(|_| InspectionFailure::Bounds)?;
        self.read(manifest, size, Some(&mut bytes), end, stop)?;
        // Includes exact byte hash before strict JSON, supplier pins and the
        // manifest's own share of NativeBook's file/read budgets.
        let inventory = spec.decode(&bytes).map_err(|_| InspectionFailure::Manifest)?;
        checkpoint(end, stop)?;
        self.close_record(manifest, end, stop)?;
        let mut progress = inventory.progress();
        self.walk(version, "", entries, manifest, &inventory, &mut progress, end, stop)?;
        if !progress.complete() { return Err(InspectionFailure::Inventory); }
        // Retained prefix, version, selected images and selected ancestors all
        // get final canonical-name/identity/ACL/stream/filesystem observations.
        for index in 0..self.records.len() {
            if !self.records[index].closed { self.postcheck(index, end, stop)?; }
        }
        method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop, |book| book.recheck_user())?;
        let locations = self.locations.as_ref().ok_or(InspectionFailure::Unknown)?;
        for location in [&locations.program_files, &locations.windows, &locations.system] {
            method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop, |book| book.recheck_location(location))?;
        }
        let selected = self.selected.map(|index| index.ok_or(InspectionFailure::Inventory));
        let selected_identities = [self.metadata(selected[0]?)?.identity,
            self.metadata(selected[1]?)?.identity, self.metadata(selected[2]?)?.identity];
        checkpoint(end, stop)?;
        Ok(VersionObservation { target: windows_version::TARGET, manifest_sha256: spec.manifest_sha256().to_owned(),
            inventory_sha256: inventory.manifest.inventory_sha256.clone(), core_sha256: inventory.manifest.core_sha256.clone(),
            files: inventory.manifest.files.len(), entries: self.entries, payload_bytes: inventory.payload_bytes,
            version_identity: self.metadata(version)?.identity, selected_identities })
    }
    fn metadata(&self, index: usize) -> Result<&native::Metadata> {
        self.records.get(index).and_then(|record| record.metadata.as_ref()).ok_or(InspectionFailure::Unknown)
    }
    fn open_volume(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<usize> {
        self.records.try_reserve(1).map_err(|_| InspectionFailure::Bounds)?;
        let locations = self.locations.as_ref().ok_or(InspectionFailure::Unknown)?;
        let records = &mut self.records;
        let index = records.len();
        method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop, |book| {
            let original = book.open_volume(&locations.program_files)?;
            records.push(Record::new(original, None, native::AuthorityScope::AncestorOutsideVersion, false, true));
            Ok(()) // original key is retained before any post-call interruption
        })?;
        self.admit(index, None, end, stop)?; Ok(index)
    }
    fn open_child(&mut self, parent: usize, entry: &native::DirectoryEntry, scope: native::AuthorityScope,
        protected: bool, keep: bool, end: Instant, stop: &watch::Receiver<bool>) -> Result<usize> {
        self.records.try_reserve(1).map_err(|_| InspectionFailure::Bounds)?;
        let records = &mut self.records;
        let index = records.len();
        method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop, |book| {
            let parent_original = &records.get(parent).ok_or(native::Error::State)?.original;
            let original = book.open_child(parent_original, &entry.name, entry.kind)?;
            records.push(Record::new(original, Some(parent), scope, protected, keep)); Ok(())
        })?;
        self.admit(index, Some(entry), end, stop)?; Ok(index)
    }
    fn sample(&mut self, index: usize, end: Instant, stop: &watch::Receiver<bool>) -> Result<(native::Metadata, native::SecurityFacts)> {
        let record = self.records.get(index).ok_or(InspectionFailure::Unknown)?;
        if record.closed { return Err(InspectionFailure::AlreadyUsed); }
        method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop, |book| book.local_ntfs(&record.original))?;
        // metadata() also requires the retained canonical name, not a path reopen.
        let metadata = method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop,
            |book| book.metadata(&record.original))?;
        let security = method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop,
            |book| book.security(&record.original, record.scope))?;
        method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop,
            |book| book.no_alternate_streams(&record.original))?;
        // SECURITY_DESCRIPTOR_CONTROL's SE_DACL_PROTECTED DATA bit. The native
        // decoder has already checked owner, ACE structure/rights and control.
        if record.protected_boundary && security.control & 0x1000 == 0 { return Err(InspectionFailure::Unsafe); }
        Ok((metadata, security))
    }
    fn admit(&mut self, index: usize, entry: Option<&native::DirectoryEntry>, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        let (metadata, security) = self.sample(index, end, stop)?;
        if let Some(entry) = entry {
            let parent = self.records[index].parent.ok_or(InspectionFailure::Unknown)?;
            if metadata.identity.volume_serial != self.metadata(parent)?.identity.volume_serial
                || metadata.identity.file_id != entry.file_id || metadata.kind != entry.kind || metadata.attributes != entry.attributes {
                return Err(InspectionFailure::Identity);
            }
        }
        if !self.identities.insert((metadata.identity.volume_serial, metadata.identity.file_id)) {
            return Err(InspectionFailure::Identity);
        }
        self.records[index].metadata = Some(metadata); self.records[index].security = Some(security); Ok(())
    }
    fn postcheck(&mut self, index: usize, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        let (metadata, security) = self.sample(index, end, stop)?;
        let record = self.records.get(index).ok_or(InspectionFailure::Unknown)?;
        if record.metadata.as_ref() != Some(&metadata) || record.security.as_ref() != Some(&security) {
            return Err(InspectionFailure::Identity);
        }
        Ok(())
    }
    fn enumerate(&mut self, index: usize, ancestor_name: Option<&str>, end: Instant,
        stop: &watch::Receiver<bool>) -> Result<Vec<native::DirectoryEntry>> {
        let mut entries = Vec::new();
        let mut names = BTreeSet::new();
        loop {
            let record = self.records.get(index).ok_or(InspectionFailure::Unknown)?;
            let batch = method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop, |book| {
                match ancestor_name {
                    Some(name) => book.next_ancestor_entries(&record.original, name),
                    None => book.next_entries(&record.original),
                }
            })?;
            let Some(batch) = batch else { break }; // actual native EOF only
            self.entries = self.entries.checked_add(batch.len()).ok_or(InspectionFailure::Bounds)?;
            // NativeBook enforces its one aggregate8192 count, including all
            // prefixes and dot entries. Do not give this directory a fresh budget.
            entries.try_reserve(batch.len()).map_err(|_| InspectionFailure::Bounds)?;
            for entry in batch {
                if !names.insert(entry.name.to_ascii_lowercase()) { return Err(InspectionFailure::Inventory); }
                if entry.name == "." || entry.name == ".." {
                    let expected = if entry.name == "." { index } else { record.parent.unwrap_or(index) };
                    if entry.kind != native::FileKind::Directory || entry.file_id != self.metadata(expected)?.identity.file_id {
                        return Err(InspectionFailure::Identity);
                    }
                    continue;
                }
                entries.push(entry);
            }
        }
        self.postcheck(index, end, stop)?;
        Ok(entries)
    }
    fn read(&mut self, index: usize, expected: u64, mut capture: Option<&mut Vec<u8>>,
        end: Instant, stop: &watch::Receiver<bool>) -> Result<String> {
        if self.metadata(index)?.kind != native::FileKind::File || self.metadata(index)?.size != expected {
            return Err(InspectionFailure::Identity);
        }
        let mut count = 0u64;
        let mut hash = Sha256::new();
        loop {
            let record = self.records.get(index).ok_or(InspectionFailure::Unknown)?;
            let bytes = method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop,
                |book| book.read_next(&record.original, BLOCK_SIZE))?;
            if bytes.is_empty() { break; } // genuine ReadFile EOF, not expected count
            count = count.checked_add(bytes.len() as u64).ok_or(InspectionFailure::Bounds)?;
            if count > expected { return Err(InspectionFailure::Inventory); }
            hash.update(&bytes);
            if let Some(output) = capture.as_mut() { output.extend_from_slice(&bytes); }
        }
        if count != expected { return Err(InspectionFailure::Inventory); }
        Ok(hash.finalize().iter().map(|byte| format!("{byte:02x}")).collect())
    }
    #[allow(clippy::too_many_arguments)]
    fn walk(&mut self, directory: usize, relative: &str, entries: Vec<native::DirectoryEntry>, manifest: usize,
        inventory: &Inventory, progress: &mut InventoryProgress, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        for entry in entries {
            checkpoint(end, stop)?;
            let path = if relative.is_empty() { entry.name.clone() } else { format!("{relative}/{}", entry.name) };
            let kind = match entry.kind { native::FileKind::File => InventoryKind::File, native::FileKind::Directory => InventoryKind::Directory };
            progress.observe(&path, kind).map_err(|_| InspectionFailure::Inventory)?;
            if path == "manifest.json" {
                // The same cached entry was used for the original manifest read.
                if self.metadata(manifest)?.identity.file_id != entry.file_id { return Err(InspectionFailure::Identity); }
                continue;
            }
            let keep = retained_path(&path);
            let index = self.open_child(directory, &entry, native::AuthorityScope::ImmutableVersion, false, keep, end, stop)?;
            match entry.kind {
                native::FileKind::Directory => {
                    let children = self.enumerate(index, None, end, stop)?;
                    self.walk(index, &path, children, manifest, inventory, progress, end, stop)?;
                },
                native::FileKind::File => {
                    let expected = inventory.file(&path).ok_or(InspectionFailure::Inventory)?;
                    if self.read(index, expected.size, None, end, stop)? != expected.sha256 { return Err(InspectionFailure::Inventory); }
                    if let Some(selected) = SELECTED.iter().position(|selected| *selected == path) {
                        if self.selected[selected].replace(index).is_some() { return Err(InspectionFailure::Inventory); }
                    }
                    if keep { self.postcheck(index, end, stop)?; } else { self.close_record(index, end, stop)?; }
                },
            }
        }
        // Bottom-up postcheck before an ordinary directory's original close.
        // Selected ancestors remain live, avoiding close of a live dependency.
        if self.records[directory].keep { self.postcheck(directory, end, stop)?; }
        else { self.close_record(directory, end, stop)?; }
        Ok(())
    }
    fn close_record(&mut self, index: usize, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        self.postcheck(index, end, stop)?;
        let records = &mut self.records;
        method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop, |book| {
            let record = records.get_mut(index).ok_or(native::Error::State)?;
            book.close_once(&record.original)?;
            record.closed = true;
            // Completed ACL DATA can be released; the original key/full metadata
            // and positive close stay retained. This is not native output memory.
            record.security = None;
            Ok(()) // record actual close before post-call STOP
        })
    }
    /// Only after actual borrower return (including unwind), never on timeout
    /// while another thread may still operate. Unknown cannot be reset/replaced.
    pub(crate) fn mark_interrupted(&mut self) {
        self.native.mark_interrupted(); self.phase = Phase::Unknown;
    }
    /// Original settlement only. It proves no worker/child/consumer joins and
    /// cannot authorize caller finality by itself. No Drop path calls this.
    pub(crate) fn settle_originals(&mut self) -> native::CloseOutcome {
        if self.settlement_attempted {
            self.mark_interrupted(); return native::CloseOutcome::Unknown;
        }
        self.settlement_attempted = true;
        if self.call_pending || self.phase == Phase::Inspecting { self.mark_interrupted(); }
        let unknown = self.phase == Phase::Unknown || self.native.is_unknown();
        self.phase = Phase::Settling;
        let result = self.native.settle_once();
        if !unknown && result == native::CloseOutcome::Settled && self.native.settled() {
            self.phase = Phase::Settled; result
        } else { self.phase = Phase::Unknown; native::CloseOutcome::Unknown }
    }
    pub(crate) fn settled(&self) -> bool {
        self.settlement_attempted && !self.call_pending && self.phase == Phase::Settled && self.native.settled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn stopped_expired_and_lost_channel_inspection_never_enters_native_work() {
        for kind in 0..3 {
            let mut book = WindowsVersionBook::new();
            assert!(book.never_started());
            let (sender, stop) = watch::channel(kind == 0);
            let end = if kind == 1 { Instant::now() } else { Instant::now() + Duration::from_secs(1) };
            if kind == 2 { drop(sender); }
            let expected = if kind == 1 { InspectionFailure::Deadline } else { InspectionFailure::Stopped };
            assert_eq!(book.inspect_once(end, &stop).unwrap_err(), expected);
            assert!(!book.never_started());
            assert!(book.native.never_started());
            assert!(book.records.is_empty() && book.observation.is_none());
            assert_eq!(book.inspect_once(end, &stop).unwrap_err(), InspectionFailure::AlreadyUsed);
            // Empty-book settlement does not call any Windows API. It proves
            // only this real no-start case, never success of a native walk.
            assert_eq!(book.settle_originals(), native::CloseOutcome::Settled);
            assert!(book.settled());
        }
    }
    #[test]
    fn unknown_completion_precedes_post_call_stop_and_deadline() {
        let mut native = native::NativeBook::new();
        let mut phase = Phase::Inspecting;
        let mut pending = true;
        let (_sender, stop) = watch::channel(true);
        let result = finish_method::<()>(&mut native, &mut phase, &mut pending,
            Err(native::Error::Unknown), Instant::now(), &stop);
        assert_eq!(result, Err(InspectionFailure::Unknown));
        assert_eq!(phase, Phase::Unknown);
        assert!(!pending && native.is_unknown());
        assert_eq!(native.settle_once(), native::CloseOutcome::Unknown);
    }
    #[test]
    fn ordinary_returned_refusal_is_not_unknown_and_pending_is_not_a_join() {
        let mut native = native::NativeBook::new();
        let mut phase = Phase::Inspecting;
        let mut pending = true;
        let (_sender, stop) = watch::channel(true);
        assert_eq!(finish_method::<()>(&mut native, &mut phase, &mut pending,
            Err(native::Error::Unsafe), Instant::now(), &stop), Err(InspectionFailure::Unsafe));
        assert!(!native.is_unknown() && !pending);
        assert_eq!(native.settle_once(), native::CloseOutcome::Settled);
        let mut interrupted = WindowsVersionBook::new();
        interrupted.call_pending = true;
        interrupted.mark_interrupted(); // no actual borrower is running in this DATA test
        assert_eq!(interrupted.settle_originals(), native::CloseOutcome::Unknown);
        assert!(!interrupted.settled());
    }
    #[test]
    fn settlement_and_interruption_are_one_shot_not_close_by_drop() {
        let mut book = WindowsVersionBook::new();
        assert_eq!(book.settle_originals(), native::CloseOutcome::Settled);
        assert!(book.settled());
        assert_eq!(book.settle_originals(), native::CloseOutcome::Unknown);
        assert!(!book.settled());
        let mut book = WindowsVersionBook::new();
        book.mark_interrupted();
        let (_sender, stop) = watch::channel(false);
        assert_eq!(book.inspect_once(Instant::now() + Duration::from_secs(1), &stop).unwrap_err(), InspectionFailure::Unknown);
        assert_eq!(book.settle_originals(), native::CloseOutcome::Unknown);
        assert!(!book.settled());
    }
    // Intentionally not part of the inert selection. Root must provide the
    // reviewed protected fixed version and ordinary-account/process owner first.
    // This is a real walk+settlement check, NOT producing-owner/loader approval.
    #[test]
    #[ignore = "requires reviewed ordinary Windows account and compile-bound protected version fixture"]
    fn native_protected_version_walk_and_original_settlement() {
        let mut book = WindowsVersionBook::new();
        let (_sender, stop) = watch::channel(false);
        let original_end = Instant::now() + Duration::from_secs(10);
        let inspected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
            book.inspect_once(original_end, &stop).is_ok()));
        let good = match inspected {
            Ok(good) => good,
            Err(_) => { book.mark_interrupted(); false },
        };
        let closed = book.settle_originals(); // always before any assertion/report
        assert!(good, "the actual protected version was not completely inspected");
        assert!(closed == native::CloseOutcome::Settled && book.settled(), "original settlement is unconfirmed");
        assert!(Instant::now() <= original_end + Duration::from_secs(2), "original observation/settlement window exceeded");
    }

    #[test]
    fn selected_ancestors_remain_live_but_unrelated_subtrees_do_not() {
        for path in ["python", "python/python.exe", "core.zip", "engine_bootstrap.py"] { assert!(retained_path(path)); }
        for path in ["py", "python/python", "python/python.exe/child", "python/pythonw.exe", "other"] {
            assert!(!retained_path(path));
        }
    }
}
