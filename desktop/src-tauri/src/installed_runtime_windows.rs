//! Retained NTFS version/loader custody for the existing passive query owner.
//!
//! Register this entire book in the caller's original retained resources before
//! releasing blocking work. It creates no worker, clock or process; only the
//! private passive slots can move its originals into a one-use capability.
//! A method may remain blocked after STOP/deadline; that original borrower/book
//! must remain reachable. Do not call interruption/settlement concurrently.
//! Closed ordinary payload handles cannot authorize future pathname consumption.
//! Normal Windows Desktop, project snapshot, edits and MSI/session remain closed.
#![forbid(unsafe_code)]

use std::{collections::{BTreeMap, BTreeSet}, path::PathBuf, time::Instant};
pub(crate) use mrk_windows_installed_native::CloseOutcome;
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
enum Phase { New, Inspecting, Inspected, Transferred, Preparing, Prepared, Refused, Settling, Settled, Unknown }

struct Record {
    original: native::Original,
    parent: Option<usize>,
    scope: native::AuthorityScope,
    protected_boundary: bool,
    keep: bool,
    closed: bool,
    metadata: Option<native::Metadata>,
    security: Option<native::SecurityFacts>,
    volume: u8,
    path: Vec<String>,
    entries: Option<Vec<native::DirectoryEntry>>,
    enumeration_strict: bool,
}
impl Record {
    fn new(original: native::Original, parent: Option<usize>, scope: native::AuthorityScope,
        protected_boundary: bool, keep: bool) -> Self {
        Self { original, parent, scope, protected_boundary, keep, closed: false, metadata: None, security: None,
            volume: 0, path: Vec::new(), entries: None, enumeration_strict: false }
    }
}

/// Bounded facts, not executable paths, transferable handles or an owner receipt.
#[derive(Debug)]
pub(crate) struct VersionObservation {
    pub(crate) target: &'static str,
    pub(crate) manifest_sha256: String,
    #[cfg(test)]
    protocol_sha256: String,
    #[cfg(test)]
    account_sid_sha256: String,
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
    loader: Option<LoaderPlan>,
    volumes: [Option<usize>; 3],
    loader_ready: bool,
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
    if !matches!(*phase, Phase::Inspecting | Phase::Preparing) { return Err(InspectionFailure::AlreadyUsed); }
    checkpoint(end, stop)?;
    *pending = true;
    let returned = invoke(book);
    finish_method(book, phase, pending, returned, end, stop)
}
fn retained_path(path: &str) -> bool {
    SELECTED.iter().any(|selected| *selected == path || selected.strip_prefix(path).is_some_and(|tail| tail.starts_with('/')))
}

fn location_at(locations: &native::KnownLocations, index: usize) -> Result<&native::KnownLocation> {
    match index { 0 => Ok(&locations.program_files), 1 => Ok(&locations.windows),
        2 => Ok(&locations.system), _ => Err(InspectionFailure::Binding) }
}

// Bounded path/selector DATA prepared before namespace effects. It cannot mint
// a capability; that requires the same book's actual native admission below.
struct LoaderPlan {
    roots: [u8; 3],
    selectors: BTreeMap<(u8, Vec<String>), Vec<String>>,
    selection: crate::runtime::VerifiedRuntime,
    system_root: String,
}
impl LoaderPlan {
    fn new(locations: &native::KnownLocations, spec: &VersionSpec) -> Result<Self> {
        let locations_array = [&locations.program_files, &locations.windows, &locations.system];
        let mut roots = [0, 1, 2];
        for index in 0..3 { for prior in 0..index {
            if locations_array[index].same_volume(locations_array[prior]) { roots[index] = roots[prior]; break; }
        } }
        let windows = locations.windows.components().to_vec();
        let system = locations.system.components().to_vec();
        if !locations.windows.same_volume(&locations.system) || system.len() != windows.len().checked_add(1).ok_or(InspectionFailure::Bounds)?
            || !system.iter().zip(&windows).all(|(a, b)| a.eq_ignore_ascii_case(b))
            || !system.last().is_some_and(|n| n.eq_ignore_ascii_case("System32")) {
            return Err(InspectionFailure::Binding);
        }
        let layout = windows_version::launch_layout(locations.program_files.path(), spec).map_err(|_| InspectionFailure::Bounds)?;
        let mut version = locations.program_files.components().to_vec();
        version.extend(spec.components().into_iter().map(str::to_owned));
        let mut python = version.clone(); python.push("python".to_owned());
        let mut legacy = windows.to_vec(); legacy.push("System".to_owned());
        let mut selectors = BTreeMap::new();
        let mut directories = BTreeSet::new();
        for (root, branch) in [(roots[0], &python), (roots[1], &windows),
            (roots[2], &system), (roots[1], &legacy)] {
            directories.insert(Self::key(root, &[]));
            let mut path = Vec::new();
            for component in branch {
                Self::select(&mut selectors, (root, path.clone()), component)?;
                path.push(component.clone()); directories.insert(Self::key(root, &path));
                if directories.len() > native::MAX_ORIGINALS { return Err(InspectionFailure::Bounds); }
            }
        }
        // Every future OS image open and the acquisition-thread token check
        // already has space. NativeBook also enforces the real peak per reserve.
        Self::peak(directories.len())?;
        for image in native::SystemImage::ALL {
            Self::select(&mut selectors, (roots[2], system.to_vec()), image.name())?;
        }
        let root = PathBuf::from(&layout.root);
        let selection = crate::runtime::VerifiedRuntime { python: PathBuf::from(layout.python),
            bootstrap: root.join("engine_bootstrap.py"), core: root.join("core.zip"), cwd: root };
        Ok(Self { roots, selectors, selection, system_root: locations.windows.path().to_owned() })
    }
    fn select(selectors: &mut BTreeMap<(u8, Vec<String>), Vec<String>>, key: (u8, Vec<String>), name: &str) -> Result<()> {
        let names = selectors.entry(Self::key(key.0, &key.1)).or_default();
        // Known-location APIs can disagree about case in a shared prefix. That
        // is one selector, not two actual directory entries. Actual aliases are
        // rejected by the single native cursor's case-folded seen-name set.
        if names.iter().any(|prior| prior.eq_ignore_ascii_case(name)) { return Ok(()); }
        if names.len() >= 35 { return Err(InspectionFailure::Bounds); }
        names.push(name.to_owned()); names.sort(); Ok(())
    }
    fn key(volume: u8, path: &[String]) -> (u8, Vec<String>) {
        (volume, path.iter().map(|part| part.to_ascii_lowercase()).collect())
    }
    fn peak(directories: usize) -> Result<usize> {
        let peak = directories.checked_add(SELECTED.len())
            .and_then(|n| n.checked_add(native::SystemImage::ALL.len()))
            .and_then(|n| n.checked_add(2)).ok_or(InspectionFailure::Bounds)?;
        if peak > native::MAX_ORIGINALS { Err(InspectionFailure::Bounds) } else { Ok(peak) }
    }
}

impl WindowsVersionBook {
    pub(crate) fn new() -> Self {
        Self { native: native::NativeBook::new(), phase: Phase::New, call_pending: false,
            settlement_attempted: false, records: Vec::new(), identities: BTreeSet::new(), locations: None,
            selected: [None; 3], entries: 0, observation: None, loader: None, volumes: [None; 3], loader_ready: false }
    }
    pub(crate) fn never_started(&self) -> bool {
        self.phase == Phase::New && !self.call_pending && !self.settlement_attempted
            && self.native.never_started() && self.records.is_empty() && self.observation.is_none()
            && self.loader.is_none() && !self.loader_ready && self.volumes == [None; 3]
    }
    pub(crate) fn inspect_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<&VersionObservation> {
        self.inspect_kind(false, end, stop)
    }
    fn inspect_kind(&mut self, passive: bool, end: Instant, stop: &watch::Receiver<bool>) -> Result<&VersionObservation> {
        if self.phase == Phase::Unknown || self.native.is_unknown() { return Err(InspectionFailure::Unknown); }
        if self.phase != Phase::New { return Err(InspectionFailure::AlreadyUsed); }
        self.phase = Phase::Inspecting;
        match self.inspect(passive, end, stop) {
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
    fn inspect(&mut self, passive: bool, end: Instant, stop: &watch::Receiver<bool>) -> Result<VersionObservation> {
        checkpoint(end, stop)?;
        let spec = VersionSpec::compiled().map_err(|_| InspectionFailure::Binding)?;
        #[cfg(test)]
        let mut account_sid_sha256 = None;
        method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop, |book| {
            let actual = book.observe_user_once()?;
            // Copy DATA from this existing borrower, never a second token query.
            #[cfg(test)]
            { account_sid_sha256 = Some(Sha256::digest(actual.user.bytes()).iter().map(|b| format!("{b:02x}")).collect()); }
            #[cfg(not(test))]
            let _ = actual;
            Ok(())
        })?;
        let locations = &mut self.locations;
        method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop, |book| {
            *locations = Some(book.known_locations_once()?); Ok(())
        })?;
        if passive {
            self.loader = Some(LoaderPlan::new(self.locations.as_ref().ok_or(InspectionFailure::Unknown)?, &spec)?);
        }
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
        if passive { inventory.passive_loader_inventory().map_err(|_| InspectionFailure::Inventory)?; }
        checkpoint(end, stop)?;
        self.close_record(manifest, end, stop)?;
        let mut progress = inventory.progress();
        self.walk(version, "", entries, manifest, &inventory, &mut progress, end, stop)?;
        if !progress.complete() { return Err(InspectionFailure::Inventory); }
        if passive { self.inspect_loader(end, stop)?; }
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
        self.loader_ready = passive;
        Ok(VersionObservation { target: windows_version::TARGET, manifest_sha256: spec.manifest_sha256().to_owned(),
            #[cfg(test)]
            protocol_sha256: inventory.manifest.protocol_sha256.clone(),
            #[cfg(test)]
            account_sid_sha256: account_sid_sha256.ok_or(InspectionFailure::Unknown)?,
            inventory_sha256: inventory.manifest.inventory_sha256.clone(), core_sha256: inventory.manifest.core_sha256.clone(),
            files: inventory.manifest.files.len(), entries: self.entries, payload_bytes: inventory.payload_bytes,
            version_identity: self.metadata(version)?.identity, selected_identities })
    }
    fn metadata(&self, index: usize) -> Result<&native::Metadata> {
        self.records.get(index).and_then(|record| record.metadata.as_ref()).ok_or(InspectionFailure::Unknown)
    }
    fn open_location_chain(&mut self, location: usize, end: Instant, stop: &watch::Receiver<bool>) -> Result<usize> {
        let components = location_at(self.locations.as_ref().ok_or(InspectionFailure::Unknown)?, location)?.components().to_vec();
        let mut parent = self.open_volume_for(location, end, stop)?;
        for (ordinal, name) in components.iter().enumerate() {
            let entries = self.enumerate(parent, Some(name), end, stop)?;
            let entry = entries.iter().find(|entry| entry.name.eq_ignore_ascii_case(name)).ok_or(InspectionFailure::Inventory)?;
            if entry.kind != native::FileKind::Directory { return Err(InspectionFailure::Inventory); }
            let existing = self.records.iter().position(|record| record.parent == Some(parent)
                && record.path.last().is_some_and(|p| p.eq_ignore_ascii_case(&entry.name)));
            let scope = if ordinal + 1 == components.len() { native::AuthorityScope::ImmutableVersion }
                else { native::AuthorityScope::AncestorOutsideVersion };
            parent = if let Some(index) = existing {
                if self.records[index].closed || self.metadata(index)?.identity.file_id != entry.file_id {
                    return Err(InspectionFailure::Identity);
                }
                // A shared Windows root may have been an ancestor of another
                // branch. Strengthen it to a loader-search root, never weaken it.
                if scope == native::AuthorityScope::ImmutableVersion { self.records[index].scope = scope; }
                self.postcheck(index, end, stop)?; index
            } else { self.open_child(parent, entry, scope, false, true, end, stop)? };
        }
        Ok(parent)
    }
    fn inspect_loader(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        if self.loader.is_none() || self.loader_ready { return Err(InspectionFailure::AlreadyUsed); }
        let windows = self.open_location_chain(1, end, stop)?;
        let entries = self.enumerate(windows, Some("System"), end, stop)?;
        // The Windows root's immutable ACL + actual original EOF establishes
        // absence too; never probe a second name by pathname after this scan.
        if let Some(entry) = entries.iter().find(|entry| entry.name.eq_ignore_ascii_case("System")) {
            if entry.kind != native::FileKind::Directory { return Err(InspectionFailure::Inventory); }
            if self.records.iter().any(|record| record.parent == Some(windows)
                && record.path.last().is_some_and(|name| name.eq_ignore_ascii_case(&entry.name))) {
                // Unsupported overlap is a refusal, never a second original
                // or a restarted directory cursor.
                return Err(InspectionFailure::Identity);
            }
            self.open_child(windows, entry, native::AuthorityScope::ImmutableVersion, false, true, end, stop)?;
        }
        let system = self.open_location_chain(2, end, stop)?;
        let entries = self.enumerate(system, Some("kernel32.dll"), end, stop)?;
        for image in native::SystemImage::ALL {
            checkpoint(end, stop)?;
            let entry = entries.iter().find(|entry| entry.name.eq_ignore_ascii_case(image.name()))
                .ok_or(InspectionFailure::Inventory)?;
            if entry.kind != native::FileKind::File { return Err(InspectionFailure::Inventory); }
            self.records.try_reserve(1).map_err(|_| InspectionFailure::Bounds)?;
            let volume = self.records[system].volume;
            let mut path = self.records[system].path.clone(); path.push(entry.name.clone());
            let locations = self.locations.as_ref().ok_or(InspectionFailure::Unknown)?;
            let records = &mut self.records;
            let index = records.len();
            method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop, |book| {
                let original = book.open_system_image(&locations.system, &records[system].original, *image, &entry.name)?;
                let mut record = Record::new(original, Some(system), native::AuthorityScope::ImmutableVersion, false, true);
                record.volume = volume; record.path = path; records.push(record); Ok(())
            })?;
            self.admit(index, Some(entry), end, stop)?;
        }
        Ok(())
    }
    fn prepare_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        if self.phase != Phase::Transferred || !self.loader_ready || self.loader.is_none()
            || self.settlement_attempted || self.call_pending || self.native.is_unknown() {
            return Err(InspectionFailure::AlreadyUsed);
        }
        self.phase = Phase::Preparing;
        let returned = (|| {
            method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop, |book| book.recheck_user())?;
            for index in 0..self.records.len() { if !self.records[index].closed { self.postcheck(index, end, stop)?; } }
            let locations = self.locations.as_ref().ok_or(InspectionFailure::Unknown)?;
            for location in [&locations.program_files, &locations.windows, &locations.system] {
                method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop, |book| book.recheck_location(location))?;
            }
            let loader = self.loader.as_ref().ok_or(InspectionFailure::Unknown)?;
            // Same fixed strings; this is not a new selection or pathname reopen.
            if !windows_version::python_path_fits(loader.selection.python.to_str().ok_or(InspectionFailure::Binding)?) {
                return Err(InspectionFailure::Bounds);
            }
            checkpoint(end, stop)
        })();
        match returned {
            Ok(()) => { self.phase = Phase::Prepared; Ok(()) },
            Err(error) => {
                if self.phase == Phase::Unknown || self.native.is_unknown() || self.call_pending || error == InspectionFailure::Unknown {
                    self.mark_interrupted(); Err(InspectionFailure::Unknown)
                } else { self.phase = Phase::Refused; Err(error) }
            },
        }
    }
    fn open_volume(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<usize> {
        self.open_volume_for(0, end, stop)
    }
    fn open_volume_for(&mut self, location: usize, end: Instant, stop: &watch::Receiver<bool>) -> Result<usize> {
        let root = self.loader.as_ref().map_or(location as u8, |p| p.roots[location]);
        if let Some(index) = self.volumes[root as usize] {
            self.postcheck(index, end, stop)?; return Ok(index);
        }
        self.records.try_reserve(1).map_err(|_| InspectionFailure::Bounds)?;
        let selected = location_at(self.locations.as_ref().ok_or(InspectionFailure::Unknown)?, location)?;
        let records = &mut self.records;
        let volumes = &mut self.volumes;
        let index = records.len();
        method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop, |book| {
            let original = book.open_volume(selected)?;
            let mut record = Record::new(original, None, native::AuthorityScope::AncestorOutsideVersion, false, true);
            record.volume = root;
            records.push(record); volumes[root as usize] = Some(index);
            Ok(()) // original key is retained before any post-call interruption
        })?;
        self.admit(index, None, end, stop)?; Ok(index)
    }
    fn open_child(&mut self, parent: usize, entry: &native::DirectoryEntry, scope: native::AuthorityScope,
        protected: bool, keep: bool, end: Instant, stop: &watch::Receiver<bool>) -> Result<usize> {
        self.records.try_reserve(1).map_err(|_| InspectionFailure::Bounds)?;
        let parent_record = self.records.get(parent).ok_or(InspectionFailure::Unknown)?;
        let volume = parent_record.volume;
        let mut path = parent_record.path.clone(); path.push(entry.name.clone());
        let records = &mut self.records;
        let index = records.len();
        method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop, |book| {
            let parent_original = &records.get(parent).ok_or(native::Error::State)?.original;
            let original = book.open_child(parent_original, &entry.name, entry.kind)?;
            let mut record = Record::new(original, Some(parent), scope, protected, keep);
            record.volume = volume; record.path = path; records.push(record); Ok(())
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
        let original = self.records.get(index).ok_or(InspectionFailure::Unknown)?;
        if let Some(entries) = &original.entries {
            if original.enumeration_strict != ancestor_name.is_none() { return Err(InspectionFailure::AlreadyUsed); }
            let entries = entries.clone();
            self.postcheck(index, end, stop)?; return Ok(entries);
        }
        let selected = if ancestor_name.is_some() {
            self.loader.as_ref().map(|p| p.selectors.get(&LoaderPlan::key(original.volume, &original.path))
                .cloned().ok_or(InspectionFailure::Inventory)).transpose()?
        } else { None };
        let mut entries = Vec::new();
        let mut names = BTreeSet::new();
        loop {
            let record = self.records.get(index).ok_or(InspectionFailure::Unknown)?;
            let batch = method(&mut self.native, &mut self.phase, &mut self.call_pending, end, stop, |book| {
                match (&selected, ancestor_name) {
                    (Some(names), Some(_)) => book.next_selected_entries(&record.original, names),
                    (None, Some(name)) => book.next_ancestor_entries(&record.original, name),
                    (_, None) => book.next_entries(&record.original),
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
        self.records[index].entries = Some(entries.clone());
        self.records[index].enumeration_strict = ancestor_name.is_none();
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
        if self.call_pending || matches!(self.phase, Phase::Inspecting | Phase::Preparing) { self.mark_interrupted(); }
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

/// Storage in the existing query Owner, registered before inspection starts.
/// A selection, manifest hash or completed inspection DATA cannot construct the
/// private capability; the complete still-live book must move here exactly once.
pub(crate) struct PassiveRuntimeSlots {
    inspection: Option<WindowsVersionBook>,
    profile: Option<crate::runtime::PassiveInstalledProfile>,
    acquisition: Option<PassiveInstalledRuntime>,
    inspection_started: bool,
    settlement_started: bool,
}
pub(crate) struct PassiveInstalledRuntime {
    original: WindowsVersionBook,
    _profile: crate::runtime::PassiveInstalledProfile,
    claimed: bool,
    refused_before_effect: bool,
}
impl WindowsVersionBook {
    fn transfer_ready(&self) -> bool {
        self.phase == Phase::Inspected && self.loader_ready && self.loader.is_some()
            && self.observation.is_some() && self.selected.iter().all(Option::is_some)
            && !self.call_pending && !self.settlement_attempted && !self.native.is_unknown()
            && self.records.iter().filter(|r| r.keep).all(|r| !r.closed && r.metadata.is_some() && r.security.is_some())
    }
}
impl PassiveInstalledRuntime {
    pub(crate) fn prepare_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<&crate::runtime::VerifiedRuntime> {
        if self.claimed || self.refused_before_effect { return Err(InspectionFailure::AlreadyUsed); }
        self.original.prepare_once(end, stop)?;
        self.original.loader.as_ref().map(|loader| &loader.selection).ok_or(InspectionFailure::Unknown)
    }
    /// This is native-known Windows DATA from THIS retained book, not ambient
    /// SystemRoot. It is borrowed only while preparing the fixed command.
    pub(crate) fn system_root(&self) -> Result<&str> {
        if !self.ready() { return Err(InspectionFailure::AlreadyUsed); }
        self.original.loader.as_ref().map(|loader| loader.system_root.as_str()).ok_or(InspectionFailure::Unknown)
    }
    fn ready(&self) -> bool {
        self.original.phase == Phase::Prepared && self.original.loader_ready
            && self.original.loader.is_some() && !self.original.native.is_unknown()
            && !self.original.call_pending && !self.original.settlement_attempted
            && !self.claimed && !self.refused_before_effect
    }
    pub(crate) fn claim_once(&mut self) -> Result<()> {
        if !self.ready() { return Err(InspectionFailure::AlreadyUsed); }
        self.claimed = true; Ok(())
    }
    // Only the unconditional closed-profile no-effect stub may call this.
    // A real Command::spawn error is opaque and NEVER sets this receipt.
    #[cfg(not(all(not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(test, feature = "desktop-shell"))))]
    pub(crate) fn record_closed_spawn_gate(&mut self) { self.refused_before_effect = true; }
}
impl PassiveRuntimeSlots {
    pub(crate) fn new() -> Self {
        Self { inspection: Some(WindowsVersionBook::new()), profile: None, acquisition: None,
            inspection_started: false, settlement_started: false }
    }
    pub(crate) fn never_started(&self) -> bool {
        !self.inspection_started && !self.settlement_started && self.profile.is_none() && self.acquisition.is_none()
            && self.inspection.as_ref().is_some_and(WindowsVersionBook::never_started)
    }
    pub(crate) fn inspect_once(&mut self, profile: crate::runtime::PassiveInstalledProfile,
        end: Instant, stop: &watch::Receiver<bool>) -> std::result::Result<crate::runtime::VerifiedRuntime, crate::error::BridgeError> {
        use crate::error::BridgeError;
        if !self.never_started() { return Err(BridgeError::cleanup_unknown()); }
        profile.compiled()?; // Compile-bound DATA, before any native operation.
        self.profile = Some(profile); self.inspection_started = true;
        let original = self.inspection.as_mut().ok_or_else(BridgeError::cleanup_unknown)?;
        match original.inspect_kind(true, end, stop) {
            Ok(_) => {
                let loader = original.loader.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
                let data = &loader.selection;
                Ok(crate::runtime::VerifiedRuntime { python: data.python.clone(), bootstrap: data.bootstrap.clone(),
                    core: data.core.clone(), cwd: data.cwd.clone() }) // DATA only.
            },
            Err(InspectionFailure::Unknown) => Err(BridgeError::cleanup_unknown()),
            Err(InspectionFailure::Deadline) => Err(BridgeError::timeout()),
            Err(_) => Err(BridgeError::unavailable("The Windows payload/loader originals failed admission.")),
        }
    }
    pub(crate) fn transfer_once(&mut self) -> Result<()> {
        if self.acquisition.is_some() || !self.inspection_started || self.settlement_started || self.profile.is_none()
            || !self.inspection.as_ref().is_some_and(WindowsVersionBook::transfer_ready) {
            return Err(InspectionFailure::AlreadyUsed);
        }
        let profile = self.profile.take().ok_or(InspectionFailure::AlreadyUsed)?;
        let Some(mut original) = self.inspection.take() else {
            self.profile = Some(profile); return Err(InspectionFailure::AlreadyUsed);
        };
        original.phase = Phase::Transferred;
        self.acquisition = Some(PassiveInstalledRuntime { original, _profile: profile,
            claimed: false, refused_before_effect: false });
        Ok(()) // No native call, allocation, await or fallible work after take.
    }
    pub(crate) fn capability(&mut self) -> Result<&mut PassiveInstalledRuntime> {
        if self.settlement_started { return Err(InspectionFailure::AlreadyUsed); }
        self.acquisition.as_mut().ok_or(InspectionFailure::AlreadyUsed)
    }
    pub(crate) fn no_child_effect(&self) -> bool {
        match (&self.inspection, &self.acquisition) {
            (Some(_), None) => true,
            (None, Some(runtime)) => !runtime.claimed || runtime.refused_before_effect,
            _ => false,
        }
    }
    pub(crate) fn mark_interrupted(&mut self) {
        if let Some(original) = &mut self.inspection { original.mark_interrupted(); }
        if let Some(runtime) = &mut self.acquisition { runtime.original.mark_interrupted(); }
    }
    pub(crate) fn settle_originals(&mut self) -> CloseOutcome {
        if self.settlement_started { self.mark_interrupted(); return CloseOutcome::Unknown; }
        self.settlement_started = true;
        let mut count = 0; let mut positive = true;
        if let Some(original) = &mut self.inspection { count += 1; positive &= original.settle_originals() == CloseOutcome::Settled; }
        if let Some(runtime) = &mut self.acquisition { count += 1; positive &= runtime.original.settle_originals() == CloseOutcome::Settled; }
        if count == 1 && positive && self.settled() { CloseOutcome::Settled } else { CloseOutcome::Unknown }
    }
    pub(crate) fn settled(&self) -> bool {
        self.settlement_started && match (&self.inspection, &self.acquisition) {
            (Some(original), None) => original.settled(),
            (None, Some(runtime)) => runtime.original.settled(),
            _ => false,
        }
    }
    #[cfg(test)]
    pub(crate) fn settled_observation(&self) -> Option<(native::FullwalkFacts, crate::runtime::VerifiedRuntime, String, bool)> {
        if !self.settled() { return None; }
        let (original, claimed) = match (&self.inspection, &self.acquisition) {
            (Some(original), None) => (original, false),
            (None, Some(runtime)) => (&runtime.original, runtime.claimed),
            _ => return None,
        };
        if !original.loader_ready { return None; }
        let actual = original.observation.as_ref()?;
        let loader = original.loader.as_ref()?;
        let data = &loader.selection;
        Some((native::FullwalkFacts {
            target: actual.target.to_owned(), manifest_sha256: actual.manifest_sha256.clone(),
            protocol_sha256: actual.protocol_sha256.clone(), account_sid_sha256: actual.account_sid_sha256.clone(),
            inventory_sha256: actual.inventory_sha256.clone(), core_sha256: actual.core_sha256.clone(),
            files: actual.files, entries: actual.entries, payload_bytes: actual.payload_bytes,
            version_identity: actual.version_identity, selected_identities: actual.selected_identities,
        }, crate::runtime::VerifiedRuntime { python: data.python.clone(), bootstrap: data.bootstrap.clone(),
            core: data.core.clone(), cwd: data.cwd.clone() }, loader.system_root.clone(), claimed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn passive_slots_cannot_transfer_partial_inspection_or_settled_books() {
        let mut slots = PassiveRuntimeSlots::new();
        assert!(slots.never_started() && slots.no_child_effect());
        assert!(slots.transfer_once().is_err() && slots.capability().is_err());
        slots.inspection_started = true;
        for phase in [Phase::New, Phase::Inspecting, Phase::Inspected, Phase::Refused, Phase::Preparing, Phase::Prepared, Phase::Unknown] {
            slots.inspection.as_mut().unwrap().phase = phase;
            assert!(!slots.inspection.as_ref().unwrap().transfer_ready());
            assert!(slots.transfer_once().is_err() && slots.acquisition.is_none());
        }
        let mut slots = PassiveRuntimeSlots::new();
        assert_eq!(slots.settle_originals(), CloseOutcome::Settled);
        assert!(slots.settled() && slots.transfer_once().is_err() && slots.capability().is_err());
        assert_eq!(slots.settle_originals(), CloseOutcome::Unknown);
        assert!(!slots.settled());
        let mut book = WindowsVersionBook::new();
        book.phase = Phase::Preparing; // No actual native borrower in this DATA test.
        assert_eq!(book.settle_originals(), CloseOutcome::Unknown);
        assert!(!book.settled());
        let mut selectors = BTreeMap::new();
        let key = (0, Vec::new());
        assert!(LoaderPlan::select(&mut selectors, key.clone(), "Windows").is_ok());
        assert!(LoaderPlan::select(&mut selectors, key.clone(), "Windows").is_ok());
        assert_eq!(LoaderPlan::select(&mut selectors, key.clone(), "WINDOWS"), Ok(()));
        assert_eq!(selectors.get(&key).unwrap().as_slice(), &["Windows".to_owned()]);
        assert_eq!(LoaderPlan::peak(12), Ok(native::MAX_ORIGINALS));
        assert_eq!(LoaderPlan::peak(13), Err(InspectionFailure::Bounds));
        assert_eq!(LoaderPlan::peak(usize::MAX), Err(InspectionFailure::Bounds));
    }

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
        let reporting_end = original_end + Duration::from_secs(2); // no restarted reporting clock
        let inspected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            book.inspect_once(original_end, &stop).map(|actual| native::FullwalkFacts {
                target: actual.target.to_owned(), manifest_sha256: actual.manifest_sha256.clone(),
                protocol_sha256: actual.protocol_sha256.clone(), inventory_sha256: actual.inventory_sha256.clone(),
                core_sha256: actual.core_sha256.clone(), account_sid_sha256: actual.account_sid_sha256.clone(),
                files: actual.files, entries: actual.entries, payload_bytes: actual.payload_bytes,
                version_identity: actual.version_identity, selected_identities: actual.selected_identities,
            }) // owned bounded DATA copied before this actual borrow ends
        }));
        let actual = match inspected {
            Ok(Ok(actual)) => Some(actual),
            Ok(Err(_)) => None,
            Err(_) => { book.mark_interrupted(); None },
        };
        let closed = book.settle_originals(); // always after borrower return/unwind, before assertion/report
        assert!(actual.is_some(), "the actual protected version was not completely inspected");
        assert!(closed == native::CloseOutcome::Settled && book.settled(), "original settlement is unconfirmed");
        assert!(Instant::now() <= reporting_end, "original observation/settlement window exceeded");
        let Some(actual) = actual else { unreachable!() };
        assert!(native::write_fullwalk_result_once(&actual, reporting_end).is_ok(),
            "the fixed original result write/close did not complete within the original boundary");
    }

    #[test]
    fn selected_ancestors_remain_live_but_unrelated_subtrees_do_not() {
        for path in ["python", "python/python.exe", "core.zip", "engine_bootstrap.py"] { assert!(retained_path(path)); }
        for path in ["py", "python/python", "python/python.exe/child", "python/pythonw.exe", "other"] {
            assert!(!retained_path(path));
        }
    }
}
