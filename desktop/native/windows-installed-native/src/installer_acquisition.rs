//! Fixed54 protected input acquisition. Not a bootstrap, publisher or launcher.
//!
//! The safe caller must retain this actual non-cloneable object in its original
//! process owner before any native step. The same serialized blocking worker and
//! real enclosing watchdog own both books. No worker, close-on-Drop, process
//! discovery, deletion, destination argument or ambient extraction fallback exists.
use super::*;
use super::{AdmissionRole as R, AdmissionOp as O, AdmissionCheck as C};
use super::installer_input_data::*;
use super::installer_primitives::*;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

const OPERATION: Duration = Duration::from_secs(600);

fn selected_mode(name: &str) -> EntryMode { EntryMode::Selected(vec![name.to_owned()]) }
fn relative_parent(path: &str) -> (&str, &str) { path.rsplit_once('/').unwrap_or(("", path)) }
fn source_children(layout: &InputLayout, parent: &str) -> BTreeMap<String, FileKind> {
    let mut expected = BTreeMap::new();
    for directory in layout.source_directories.iter().filter(|p| !p.is_empty()) {
        let (at, name) = relative_parent(directory);
        if at == parent { expected.insert(name.to_owned(), FileKind::Directory); }
    }
    for path in &layout.paths {
        let (at, name) = relative_parent(&path.source);
        if at == parent { expected.insert(name.to_owned(), FileKind::File); }
    }
    expected
}
fn exact_kinds(rows: &[DirectoryEntry], mut expected: BTreeMap<String, FileKind>) -> Result<()> {
    for entry in rows.iter().filter(|r| r.name != "." && r.name != "..") {
        need(expected.remove(&entry.name) == Some(entry.kind))?;
    }
    need(expected.is_empty())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcquisitionBook { Source, Output }

/// Closed cleanup DATA. An index is a retained record, not an OS handle or PID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcquisitionCleanupError {
    pub book: AcquisitionBook,
    pub original_record: usize,
    pub error: Error,
}

/// Actual observed counts, including source/readback excess-detection bytes.
/// Unreturned native outputs are not counted or observed; this DATA is not finality.
/// Confirmed writes exclude unobservable failed/pending counts. If that field
/// is uncertain the retained output may contain additional partial bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcquisitionByteCounts {
    pub source_read: u64,
    pub confirmed_written: u64,
    pub readback_read: u64,
    pub write_count_unknown: bool,
}

// Unlike KnownLocation, this is candidate DATA and never destination authority.
struct SourceLocation {
    book: Arc<()>, path: String, drive: String, device: Option<String>, components: Vec<String>,
}
#[derive(Clone)]
enum EntryMode { Strict, Selected(Vec<String>) }
struct InputDirectory {
    slot: usize, parent: Option<usize>, dos: String, components: Vec<String>, scope: AuthorityScope,
    facts: Facts, mode: EntryMode, entries: Option<Vec<DirectoryEntry>>,
    // These are separately recorded actual exclusive creations, NOT cursor rows.
    additions: Vec<DirectoryEntry>, created: bool, strict_source: bool, write_subtree: bool,
}
fn readonly_common_ancestor(a: &InputDirectory, b: &InputDirectory,
    canonical_a: &str, canonical_b: &str, same_mapping: bool) -> bool {
    same_mapping && !a.strict_source && !b.strict_source && !a.write_subtree && !b.write_subtree
        && !a.created && !b.created && a.facts.metadata.kind == FileKind::Directory
        && b.facts.metadata.kind == FileKind::Directory && a.components == b.components
        && a.dos == b.dos && canonical_a == canonical_b && a.facts == b.facts
}
#[derive(Clone, Copy)]
struct AncestorPair { source: usize, output: usize }
#[derive(Clone)]
struct SourceFile { slot: usize, facts: Facts }
#[derive(Clone)]
struct OutputFile { writer: usize, facts: Facts, readback: Option<usize> }
struct ControlCache { source: SourceFile, bytes: Vec<u8> }
#[derive(Clone)]
struct BranchAbsence { parent: usize, name: String }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage { Fresh, Controls, Copying, Complete }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransferStage { Copy, SourceEof, Readback, ReadbackEof }
struct Transfer {
    index: usize, stage: TransferStage, source: SourceFile, writer: usize,
    created: Facts, readback: Option<usize>, readback_facts: Option<Facts>,
    copied: u64, reread: u64, proof: CopyProof, source_hash: bool, readback_hash: bool,
}

/// One original owner; neither book is a worker or replaceable custody layer.
pub struct InputAcquisition {
    source: NativeBook, output: NativeBook, mutation: MutationSlot,
    end: Instant, expired: bool, first_failure: Option<Error>, unknown: bool, stage: Stage,
    installer: Option<Installer>, source_location: SourceLocation, output_location: Option<KnownLocation>,
    digest: String, image: String, layout: InputLayout, sizes: [u64; INPUTS], expected_total: u64,
    source_dirs: Vec<InputDirectory>, output_dirs: Vec<InputDirectory>, pairs: Vec<AncestorPair>,
    source_paths: BTreeMap<String, usize>, output_paths: BTreeMap<String, usize>,
    source_files: Vec<Option<SourceFile>>, output_files: Vec<Option<OutputFile>>,
    controls: [Option<ControlCache>; 2], absences: [Option<BranchAbsence>; 2], program_files: Option<usize>,
    creations: Vec<Creation>, transfer: Option<Transfer>, proofs: Vec<CopyProof>,
    writes: WriteAccounting, settlement_attempted: bool, cleanup_errors: Vec<AcquisitionCleanupError>,
    #[cfg(feature = "runtime-publication")]
    activation: Option<Result<ShellActivation>>,
}
// SAFETY: serialized move of the original owner only. Every native output is
// pinned in these actual books/mutation; no borrowed HANDLE or UnsafeCell escapes.
// This object is deliberately not Sync. Calling-thread token checks are real,
// not a privilege lease transferred by Send.
unsafe impl Send for InputAcquisition {}

impl InputAcquisition {
    /// No native effect. Bind authenticated expected lengths in acquisition order
    /// (runtime47, publisher, shell, prerequisite, notices2, controls2), not the
    /// differently sorted DATA3 inventory array. D/H/I are not trust by themselves.
    pub fn new(source_candidate: &str, digest: &str, helper: &str, image: &str, sizes: [u64; INPUTS]) -> Result<Self> {
        let (drive, components) = decode::dos_location(source_candidate)?;
        need(components.len() <= SOURCE_COMPONENTS && source_candidate.encode_utf16().count() < NAME_UNITS)?;
        let layout = InputLayout::new(digest, helper, image).ok_or(Error::Unsafe)?;
        let expected_total = expected_sizes(&sizes).ok_or(Error::Bounds)?;
        let source = NativeBook::installer_source();
        let source_location = SourceLocation { book: Arc::clone(&source.identity), path: source_candidate.to_owned(),
            drive, device: None, components };
        Ok(Self { source, output: NativeBook::installer_output(), mutation: None,
            end: Instant::now().checked_add(OPERATION).ok_or(Error::Bounds)?, expired: false,
            first_failure: None, unknown: false, stage: Stage::Fresh, installer: None, source_location, output_location: None,
            digest: digest.to_owned(), image: image.to_owned(), layout, sizes, expected_total,
            source_dirs: Vec::new(), output_dirs: Vec::new(), pairs: Vec::new(), source_paths: BTreeMap::new(), output_paths: BTreeMap::new(),
            source_files: vec![None; INPUTS], output_files: vec![None; INPUTS], controls: [None, None],
            absences: [None, None], program_files: None, creations: Vec::new(), transfer: None, proofs: Vec::new(),
            writes: WriteAccounting::default(), settlement_attempted: false, cleanup_errors: Vec::new(),
            #[cfg(feature = "runtime-publication")]
            activation: None,
        })
    }
    fn book(&self, side: AcquisitionBook) -> &NativeBook {
        match side { AcquisitionBook::Source => &self.source, AcquisitionBook::Output => &self.output }
    }
    fn book_mut(&mut self, side: AcquisitionBook) -> &mut NativeBook {
        match side { AcquisitionBook::Source => &mut self.source, AcquisitionBook::Output => &mut self.output }
    }
    fn dirs(&self, side: AcquisitionBook) -> &Vec<InputDirectory> {
        match side { AcquisitionBook::Source => &self.source_dirs, AcquisitionBook::Output => &self.output_dirs }
    }
    fn dirs_mut(&mut self, side: AcquisitionBook) -> &mut Vec<InputDirectory> {
        match side { AcquisitionBook::Source => &mut self.source_dirs, AcquisitionBook::Output => &mut self.output_dirs }
    }
    fn key(&self, side: AcquisitionBook, slot: usize) -> Original {
        Original { book: Arc::clone(&self.book(side).identity), index: slot }
    }
    fn active_frame(&self) -> bool { self.mutation.is_some() || self.source.active.is_some() || self.output.active.is_some() }
    fn latch(&mut self, error: Error) {
        if self.first_failure.is_none() { self.first_failure = Some(error); }
        self.unknown |= error == Error::Unknown || self.active_frame() || self.source.is_unknown() || self.output.is_unknown();
    }
    fn tick(&mut self) -> Result<()> {
        self.expired |= Instant::now() >= self.end;
        if self.expired { Err(Error::Bounds) } else { Ok(()) }
    }
    fn ready(&mut self) -> Result<()> {
        if self.unknown || self.active_frame() || self.source.is_unknown() || self.output.is_unknown() { return Err(Error::Unknown); }
        if self.first_failure.is_some() || self.settlement_attempted { return Err(Error::State); }
        self.source.clear()?; self.output.clear()?; self.tick()
    }
    fn step<T>(&mut self, body: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let result = self.ready().and_then(|_| body(self)).and_then(|v| { self.tick()?; Ok(v) });
        if let Err(error) = result.as_ref() { self.latch(*error); }
        result
    }
    fn checked(&mut self, side: AcquisitionBook, slot: usize, scope: AuthorityScope) -> Result<Facts> {
        self.ready()?; let key = self.key(side, slot);
        let book = self.book_mut(side);
        book.noninherited(slot)?;
        let metadata = book.metadata(&key)?;
        need(metadata.identity.volume_serial != 0 && metadata.links == 1
            && metadata.creation > 0 && metadata.write > 0 && metadata.change > 0)?;
        book.no_alternate_streams(&key)?;
        let security = book.security(&key, scope)?;
        need(book.metadata(&key)? == metadata)?; self.tick()?;
        Ok(Facts { metadata, security })
    }
    fn recheck_dir(&mut self, side: AcquisitionBook, index: usize) -> Result<()> {
        let dir = self.dirs(side).get(index).ok_or(Error::State)?;
        let (slot, scope, facts) = (dir.slot, dir.scope, dir.facts.clone());
        need(self.checked(side, slot, scope)? == facts)
    }
    fn child_path(&self, side: AcquisitionBook, parent: usize, name: &str) -> Result<String> {
        need(decode::component(name))?;
        let dos = &self.dirs(side).get(parent).ok_or(Error::State)?.dos;
        let path = format!("{}{}{}", dos, if dos.ends_with('\\') { "" } else { "\\" }, name);
        need(path.encode_utf16().count() < NAME_UNITS)?; Ok(path)
    }
    fn same_mapping(&self) -> bool {
        self.output_location.as_ref().is_some_and(|output| {
            self.source_location.drive == output.drive && self.source_location.device.as_ref() == Some(&output.device)
                && Arc::ptr_eq(&self.source_location.book, &self.source.identity)
                && Arc::ptr_eq(&output.book, &self.output.identity)
        })
    }
    fn distinct_file_identity(&self, metadata: &Metadata) -> Result<()> {
        let identity = metadata.identity;
        need(!self.source_dirs.iter().chain(&self.output_dirs).any(|d| d.facts.metadata.identity == identity)
            && !self.source_files.iter().flatten().any(|f| f.facts.metadata.identity == identity)
            && !self.output_files.iter().flatten().any(|f| f.facts.metadata.identity == identity))
    }
    #[allow(clippy::too_many_arguments)]
    fn add_dir(&mut self, side: AcquisitionBook, slot: usize, parent: Option<usize>, dos: String,
        components: Vec<String>, scope: AuthorityScope, mode: EntryMode, created: bool,
        strict_source: bool, write_subtree: bool) -> Result<usize> {
        let facts = self.checked(side, slot, scope)?;
        need(facts.metadata.kind == FileKind::Directory)?;
        if let Some(volume) = self.dirs(side).first() {
            need(volume.facts.metadata.identity.volume_serial == facts.metadata.identity.volume_serial)?;
        }
        need(!self.dirs(side).iter().any(|d| d.facts.metadata.identity == facts.metadata.identity))?;
        need(!self.source_files.iter().flatten().any(|f| f.facts.metadata.identity == facts.metadata.identity)
            && !self.output_files.iter().flatten().any(|f| f.facts.metadata.identity == facts.metadata.identity))?;
        if created { exact_security(&facts.security, FileKind::Directory, false, false)?; }
        let candidate = InputDirectory { slot, parent, dos, components, scope, facts, mode,
            entries: None, additions: Vec::new(), created, strict_source, write_subtree };
        let other = match side { AcquisitionBook::Source => AcquisitionBook::Output, AcquisitionBook::Output => AcquisitionBook::Source };
        let peer = self.dirs(other).iter().position(|d| d.facts.metadata.identity == candidate.facts.metadata.identity);
        if let Some(peer) = peer {
            let original = &self.dirs(other)[peer];
            need(readonly_common_ancestor(&candidate, original, &self.book(side).slot(slot)?.canonical,
                &self.book(other).slot(original.slot)?.canonical, self.same_mapping()))?;
            self.recheck_dir(other, peer)?;
        }
        let index = self.dirs(side).len();
        self.dirs_mut(side).push(candidate);
        if let Some(peer) = peer {
            let pair = match side { AcquisitionBook::Source => AncestorPair { source: index, output: peer },
                AcquisitionBook::Output => AncestorPair { source: peer, output: index } };
            need(!self.pairs.iter().any(|p| p.source == pair.source || p.output == pair.output))?;
            self.pairs.push(pair);
        }
        Ok(index)
    }
    fn entries(&mut self, side: AcquisitionBook, index: usize) -> Result<Vec<DirectoryEntry>> {
        if let Some(rows) = &self.dirs(side).get(index).ok_or(Error::State)?.entries { return Ok(rows.clone()); }
        self.recheck_dir(side, index)?;
        let dir = &self.dirs(side)[index]; let (slot, mode) = (dir.slot, dir.mode.clone());
        let key = self.key(side, slot); let mut rows = Vec::new();
        loop {
            self.ready()?;
            let next = match &mode {
                EntryMode::Strict => self.book_mut(side).next_entries(&key)?,
                EntryMode::Selected(names) => self.book_mut(side).next_selected_entries(&key, names)?,
            };
            self.tick()?;
            match next { Some(batch) => rows.extend(batch), None => break }
        }
        let dir = &self.dirs(side)[index];
        let parent = dir.parent.map(|p| &self.dirs(side)[p].facts.metadata);
        check_entry_frame(&rows, &dir.facts.metadata, parent)?;
        self.recheck_dir(side, index)?; self.dirs_mut(side)[index].entries = Some(rows.clone()); Ok(rows)
    }
    fn selected(&mut self, side: AcquisitionBook, parent: usize, name: &str) -> Result<Option<DirectoryEntry>> {
        // Refuse a second unrelated selection before consulting cached cursor DATA.
        match &self.dirs(side).get(parent).ok_or(Error::State)?.mode {
            EntryMode::Selected(names) => need(names.iter().any(|n| n == name))?, EntryMode::Strict => {},
        }
        let rows = self.entries(side, parent)?;
        let initial = selected_entry(&rows, name)?;
        let added = selected_entry(&self.dirs(side)[parent].additions, name)?;
        need(initial.is_none() || added.is_none())?; Ok(initial.or(added))
    }
    #[allow(clippy::too_many_arguments)]
    fn existing_dir(&mut self, side: AcquisitionBook, parent: usize, name: &str, scope: AuthorityScope,
        mode: EntryMode, strict_source: bool, write_subtree: bool) -> Result<usize> {
        let entry = self.selected(side, parent, name)?.ok_or(Error::Unsafe)?;
        need(entry.kind == FileKind::Directory)?; self.recheck_dir(side, parent)?;
        let parent_key = self.key(side, self.dirs(side)[parent].slot);
        let key = self.book_mut(side).open_child(&parent_key, name, FileKind::Directory)?;
        let dos = self.child_path(side, parent, name)?;
        let mut components = self.dirs(side)[parent].components.clone(); components.push(name.to_owned());
        let index = self.add_dir(side, key.index, Some(parent), dos, components, scope, mode, false, strict_source, write_subtree)?;
        match_entry(&entry, &self.dirs(side)[index].facts.metadata)?; self.recheck_dir(side, parent)?; Ok(index)
    }
    fn before_child(&mut self, parent: usize, name: &str) -> Result<()> {
        self.recheck_installer()?; self.recheck_locations()?; self.recheck_dir(AcquisitionBook::Output, parent)?;
        if let Some(pair) = self.pairs.iter().find(|p| p.output == parent).copied() {
            self.recheck_dir(AcquisitionBook::Source, pair.source)?;
            need(self.source_dirs[pair.source].facts == self.output_dirs[parent].facts)?;
        }
        need(self.selected(AcquisitionBook::Output, parent, name)?.is_none())
    }
    fn after_child(&mut self, parent: usize, name: &str, child: &Metadata) -> Result<()> {
        // Only a definite exclusive-create path invokes this. No other drift is
        // licensed and neither original is replaced, reopened or cursor-replayed.
        let dir = self.output_dirs.get(parent).ok_or(Error::State)?;
        let (slot, scope, before) = (dir.slot, dir.scope, dir.facts.clone());
        let output = self.checked(AcquisitionBook::Output, slot, scope)?;
        need(child_transition(&before.metadata, &output.metadata) && before.security == output.security)?;
        let pair = self.pairs.iter().find(|p| p.output == parent).copied();
        let paired_after = if let Some(pair) = pair {
            let source = &self.source_dirs[pair.source];
            let (slot, scope, before) = (source.slot, source.scope, source.facts.clone());
            let after = self.checked(AcquisitionBook::Source, slot, scope)?;
            need(child_transition(&before.metadata, &after.metadata) && before.security == after.security && after == output)?;
            Some((pair.source, after))
        } else { None };
        let initial = self.output_dirs[parent].entries.as_ref().ok_or(Error::State)?;
        need(selected_entry(initial, name)?.is_none() && selected_entry(&self.output_dirs[parent].additions, name)?.is_none())?;
        if let Some((index, facts)) = paired_after { self.source_dirs[index].facts = facts; }
        self.output_dirs[parent].facts = output;
        self.output_dirs[parent].additions.push(DirectoryEntry { name: name.to_owned(), file_id: child.identity.file_id,
            kind: child.kind, attributes: child.attributes });
        Ok(())
    }
    fn mutate(&mut self, effect: Effect, slot: Option<usize>, dos: &str, raw: &[u8], data: Vec<u8>) -> Result<MutationComplete> {
        self.ready()?;
        enter_registered_mutation(&mut self.output, &mut self.mutation, &mut self.creations, effect, slot, dos, raw, data)?;
        let result = finish_registered_mutation(&mut self.output, &mut self.mutation, &mut self.creations, Some(&mut self.writes));
        if let Err(error) = result.as_ref() { self.latch(*error); }
        let complete = result?; self.tick()?; Ok(complete)
    }
    fn scalar(&mut self, index: usize, class: S::TOKEN_INFORMATION_CLASS) -> Result<u32> {
        self.output.admission.at(O::Scalar).need([S::TokenHasRestrictions, S::TokenIsAppContainer].contains(&class), C::ScalarCompletion)?;
        let complete = self.mutate(Effect::Scalar(class), Some(index), "", &[], Vec::new())?;
        let trace = self.output.admission.at(O::Scalar);
        trace.result(scalar_value(trace.result(complete.scalar(), C::ScalarCompletion)?), C::ScalarCanonical)
    }
    fn close_one(&mut self, side: AcquisitionBook, slot: usize) -> Result<()> {
        // A globally active frame forbids even independent cross-book closes.
        // A returned failed close is different: independent originals may close.
        if self.active_frame() { return Err(Error::Unknown); }
        let result = self.book_mut(side).close_index(slot);
        if let Err(error) = result.as_ref() {
            if !self.cleanup_errors.iter().any(|e| e.book == side && e.original_record == slot) {
                self.cleanup_errors.push(AcquisitionCleanupError { book: side, original_record: slot, error: *error });
            }
        }
        result
    }
    fn closed(&self, side: AcquisitionBook, slot: usize) -> bool {
        self.book(side).slot(slot).is_ok_and(|s| s.state == SlotState::Closed)
    }
    fn recheck_locations(&mut self) -> Result<()> {
        self.ready()?;
        need(Arc::ptr_eq(&self.source_location.book, &self.source.identity))?;
        let mapped = self.source.mapping(&self.source_location.drive)?;
        need(self.source_location.device.as_ref() == Some(&mapped))?;
        let location = self.output_location.as_ref().ok_or(Error::State)?;
        self.output.recheck_location(location)?; self.tick()
    }
}

impl InputAcquisition {
    fn collect_installer(&mut self, index: usize) -> Result<Installer> {
        self.ready()?;
        self.output.admission.role.set(R::ThreadBefore); self.output.absent_thread_token()?;
        self.output.admission.role.set(R::StatisticsBefore);
        let before = self.output.token(index, S::TokenStatistics)?;
        let trace = self.output.admission.at(O::TokenData);
        let initial = security::Observed::new(trace).statistics(before.bytes_in(before.count_in(trace)?, trace)?)?;
        let mut scalar = |class, role| -> Result<u32> {
            self.output.admission.role.set(role);
            let value = self.output.token(index, class)?;
            let trace = self.output.admission.at(O::TokenData);
            trace.need(value.count_in(trace)? == 4, C::ScalarWidth)?;
            decode::Observed::new(trace).u32_at(value.bytes_in(4, trace)?, 0)
        };
        let token_type = scalar(S::TokenType, R::TokenType)?;
        let elevated = scalar(S::TokenElevation, R::Elevation)?;
        let elevation_type = scalar(S::TokenElevationType, R::ElevationType)?;
        let ui_access = scalar(S::TokenUIAccess, R::UiAccess)?;
        let virtualization = scalar(S::TokenVirtualizationEnabled, R::Virtualization)?;
        self.output.admission.role.set(R::Restrictions);
        let restricted = self.scalar(index, S::TokenHasRestrictions)?;
        self.output.admission.role.set(R::AppContainer);
        let app_container = self.scalar(index, S::TokenIsAppContainer)?;
        self.output.admission.role.set(R::User);
        let user = self.output.token(index, S::TokenUser)?;
        self.output.admission.role.set(R::Integrity);
        let integrity = self.output.token(index, S::TokenIntegrityLevel)?;
        self.output.admission.role.set(R::Groups);
        let groups = self.output.token(index, S::TokenGroups)?;
        self.output.admission.role.set(R::Privileges);
        let privileges = self.output.token(index, S::TokenPrivileges)?;
        let trace = self.output.admission.at(O::InstallerPolicy).role(R::Installer);
        let token_data = self.output.admission.at(O::TokenData);
        let u = token_data.role(R::User); let i = token_data.role(R::Integrity);
        let g = token_data.role(R::Groups); let p = token_data.role(R::Privileges);
        let facts = InstallerData(trace).installer_facts(initial, token_type, elevated, elevation_type, ui_access, virtualization,
            restricted, app_container, user.bytes_in(user.count_in(u)?, u)?, integrity.bytes_in(integrity.count_in(i)?, i)?,
            groups.bytes_in(groups.count_in(g)?, g)?, privileges.bytes_in(privileges.count_in(p)?, p)?)?;
        self.output.admission.role.set(R::StatisticsAfter);
        let after = self.output.token(index, S::TokenStatistics)?;
        let trace = self.output.admission.at(O::TokenData);
        trace.need(security::Observed::new(trace).statistics(after.bytes_in(after.count_in(trace)?, trace)?)? == initial, C::StatisticsChanged)?;
        self.output.admission.role.set(R::ThreadAfter); self.output.absent_thread_token()?;
        self.tick()?; Ok(facts)
    }
    fn open_process_token(&mut self) -> Result<usize> {
        self.output.admission.role.set(R::Primary);
        let key = self.output.reserve(Kind::ProcessToken, None, "", String::new())?;
        let result = self.output.call(Call::ProcessToken(key.index), null_mut(), Vec::new())?;
        self.output.admission.at(O::TokenOpen).need(matches!(result.arena.returned()?, Returned::Boolean(v, 0) if v != 0), C::PrimaryOpen)?;
        self.output.noninherited(key.index)?; Ok(key.index)
    }
    fn admit_installer(&mut self) -> Result<()> {
        self.output.admission.role.set(R::Installer);
        self.output.admission.at(O::Owner).need(self.installer.is_none() && self.output.user.is_none() && self.output.process_token.is_none(), C::InstallerFresh)?;
        let arch = self.output.call(Call::Architecture, null_mut(), Vec::new())?;
        let trace = self.output.admission.at(O::Architecture);
        let d = decode::Observed::new(trace);
        trace.need(d.u16_at(arch.bytes_in(4, trace)?, 0)? == SI::IMAGE_FILE_MACHINE_UNKNOWN, C::ArchitectureProcess)?;
        trace.need(d.u16_at(arch.bytes_in(4, trace)?, 2)? == SI::IMAGE_FILE_MACHINE_AMD64, C::ArchitectureNative)?;
        let index = self.open_process_token()?;
        self.output.process_token = Some(index);
        self.installer = Some(self.collect_installer(index)?); Ok(())
    }
    fn recheck_installer(&mut self) -> Result<()> {
        self.ready()?;
        let initial = self.installer.clone().ok_or(Error::State)?;
        let original = self.output.process_token.ok_or(Error::State)?;
        need(self.collect_installer(original)? == initial)?;
        // A new bounded *observation* of the CURRENT primary token detects token
        // replacement. It is not a replacement for the retained original token.
        let current = self.open_process_token()?;
        need(self.collect_installer(current)? == initial)?;
        self.close_one(AcquisitionBook::Output, current)?; self.output.absent_thread_token()?; self.tick()
    }
}

impl InputAcquisition {
    fn discover_locations(&mut self) -> Result<()> {
        self.ready()?;
        need(self.output_location.is_none() && self.source_location.device.is_none()
            && self.source.user.is_none() && self.source.process_token.is_none()
            && !self.source.roots_started && !self.output.roots_started)?;
        let output = self.output.location(LocationKind::ProgramFiles)?;
        need(Arc::ptr_eq(&output.book, &self.output.identity))?;
        let device = self.source.mapping(&self.source_location.drive)?;
        // Component-aware overlap is forbidden in either direction. A source
        // root above MRK could change through our own writes; a source below MRK
        // could be confused with output authority. Neither is supported.
        if device == output.device {
            let mut destination = output.components.clone(); destination.push("Mobile Release Kit".to_owned());
            need(!prefix_components(&self.source_location.components, &destination)
                && !prefix_components(&destination, &self.source_location.components))?;
        }
        self.source_location.device = Some(device); self.output_location = Some(output); self.tick()
    }
    fn open_original_volume(&mut self, side: AcquisitionBook, drive: &str, device: &str, mode: EntryMode) -> Result<usize> {
        self.ready()?; need(!self.book(side).roots_started)?;
        need(self.book_mut(side).mapping(drive)? == device)?;
        let name = format!("{device}\\");
        let key = self.book_mut(side).reserve(Kind::Directory, None, &name, name.clone())?;
        self.book_mut(side).call(Call::Open(key.index), null_mut(), Vec::new())?;
        self.book_mut(side).noninherited(key.index)?; self.book_mut(side).local_ntfs(&key)?;
        self.book_mut(side).roots_started = true;
        self.add_dir(side, key.index, None, format!("{drive}\\"), Vec::new(), AuthorityScope::AncestorOutsideVersion,
            mode, false, false, false)
    }
    fn admit_source_tree(&mut self) -> Result<()> {
        let side = AcquisitionBook::Source;
        let (drive, components, device) = (self.source_location.drive.clone(), self.source_location.components.clone(),
            self.source_location.device.clone().ok_or(Error::State)?);
        let first = components.first().ok_or(Error::State)?;
        let mut parent = self.open_original_volume(side, &drive, &device, selected_mode(first))?;
        for (i, name) in components.iter().enumerate() {
            let strict = i + 1 == components.len();
            let mode = if strict { EntryMode::Strict } else { selected_mode(&components[i + 1]) };
            parent = self.existing_dir(side, parent, name,
                if strict { AuthorityScope::ImmutableVersion } else { AuthorityScope::AncestorOutsideVersion }, mode, strict, false)?;
        }
        need(self.source_dirs[parent].dos == self.source_location.path)?;
        self.source_paths.insert(String::new(), parent);
        let directories = self.layout.source_directories.clone();
        for relative in directories.iter().filter(|p| !p.is_empty()) {
            let (parent_path, name) = relative_parent(relative);
            let parent = *self.source_paths.get(parent_path).ok_or(Error::State)?;
            let index = self.existing_dir(side, parent, name, AuthorityScope::ImmutableVersion, EntryMode::Strict, true, false)?;
            need(self.source_paths.insert(relative.clone(), index).is_none())?;
        }
        for relative in &directories {
            let index = *self.source_paths.get(relative).ok_or(Error::State)?;
            let rows = self.entries(side, index)?; exact_kinds(&rows, source_children(&self.layout, relative))?;
        }
        // Full fixed roster and entry IDs are known before mutation. Actual
        // lengths are NOT part of DirectoryEntry: controls are read now and each
        // other original proves its own expected size before its writer.
        let mut identities = BTreeSet::new();
        for dir in &self.source_dirs { need(identities.insert(dir.facts.metadata.identity.file_id))?; }
        for path in &self.layout.paths {
            let (parent, name) = relative_parent(&path.source);
            let parent = *self.source_paths.get(parent).ok_or(Error::State)?;
            let row = selected_entry(self.source_dirs[parent].entries.as_ref().ok_or(Error::State)?, name)?.ok_or(Error::Unsafe)?;
            need(row.kind == FileKind::File && row.file_id != [0; 16] && identities.insert(row.file_id))?;
        }
        Ok(())
    }
    fn admit_destination(&mut self) -> Result<()> {
        let side = AcquisitionBook::Output;
        let location = self.output_location.as_ref().ok_or(Error::State)?;
        let (drive, device, components) = (location.drive.clone(), location.device.clone(), location.components.clone());
        let first = components.first().ok_or(Error::State)?;
        let mut parent = self.open_original_volume(side, &drive, &device, selected_mode(first))?;
        for (i, name) in components.iter().enumerate() {
            let next = components.get(i + 1).map(String::as_str).unwrap_or("Mobile Release Kit");
            parent = self.existing_dir(side, parent, name, AuthorityScope::AncestorOutsideVersion, selected_mode(next), false, false)?;
        }
        self.program_files = Some(parent);
        if self.selected(side, parent, "Mobile Release Kit")?.is_none() {
            self.absences = [Some(BranchAbsence { parent, name: "Mobile Release Kit".to_owned() }),
                Some(BranchAbsence { parent, name: "Mobile Release Kit".to_owned() })];
            return Ok(());
        }
        let root = self.existing_dir(side, parent, "Mobile Release Kit", AuthorityScope::AncestorOutsideVersion,
            EntryMode::Selected(vec!["runtime-input".to_owned(), "installer-input".to_owned()]), false, true)?;
        self.output_paths.insert(String::new(), root);
        for (index, branch) in ["runtime-input", "installer-input"].iter().enumerate() {
            let absence = self.probe_branch(root, branch)?; self.absences[index] = Some(absence);
        }
        Ok(())
    }
    fn probe_branch(&mut self, root: usize, branch: &str) -> Result<BranchAbsence> {
        let mut parent = root; let mut relative = String::new();
        let image = self.image.clone();
        for (name, next) in [(branch, TARGET), (TARGET, image.as_str())] {
            if self.selected(AcquisitionBook::Output, parent, name)?.is_none() {
                return Ok(BranchAbsence { parent, name: name.to_owned() });
            }
            parent = self.existing_dir(AcquisitionBook::Output, parent, name,
                AuthorityScope::AncestorOutsideVersion, selected_mode(next), false, true)?;
            if !relative.is_empty() { relative.push('/'); } relative.push_str(name);
            need(self.output_paths.insert(relative.clone(), parent).is_none())?;
        }
        need(self.selected(AcquisitionBook::Output, parent, &image)?.is_none())?;
        Ok(BranchAbsence { parent, name: image })
    }
    fn payload_parent(&self, index: usize, source: bool) -> Result<(usize, String)> {
        let row = self.layout.paths.get(index).ok_or(Error::State)?;
        let (parent, name) = relative_parent(if source { &row.source } else { &row.output });
        let paths = if source { &self.source_paths } else { &self.output_paths };
        Ok((*paths.get(parent).ok_or(Error::State)?, name.to_owned()))
    }
    fn open_source(&mut self, index: usize) -> Result<SourceFile> {
        need(index < INPUTS && self.source_files[index].is_none())?;
        let side = AcquisitionBook::Source;
        let (parent, name) = self.payload_parent(index, true)?;
        let row = self.selected(side, parent, &name)?.ok_or(Error::Unsafe)?;
        need(row.kind == FileKind::File)?; self.recheck_dir(side, parent)?;
        let key = self.key(side, self.source_dirs[parent].slot);
        let original = self.source.open_child(&key, &name, FileKind::File)?;
        let facts = self.checked(side, original.index, AuthorityScope::ImmutableVersion)?;
        match_entry(&row, &facts.metadata)?; self.distinct_file_identity(&facts.metadata)?;
        need(facts.metadata.identity.volume_serial == self.source_dirs[parent].facts.metadata.identity.volume_serial
            && facts.metadata.size == self.sizes[index])?;
        self.recheck_dir(side, parent)?;
        let file = SourceFile { slot: original.index, facts };
        self.source_files[index] = Some(file.clone()); Ok(file)
    }
    fn read_controls(&mut self) -> Result<()> {
        for (control, index) in CONTROLS.into_iter().enumerate() {
            need(self.controls[control].is_none())?;
            let source = self.open_source(index)?;
            // Register both actual original and cache in the owner before reading.
            self.controls[control] = Some(ControlCache { source: source.clone(), bytes: Vec::new() });
            loop {
                self.ready()?; let key = self.key(AcquisitionBook::Source, source.slot);
                let chunk = self.source.read_next(&key, BUFFER)?; self.tick()?;
                if chunk.is_empty() { break; }
                let cache = self.controls[control].as_mut().ok_or(Error::State)?;
                let length = cache.bytes.len().checked_add(chunk.len()).ok_or(Error::Bounds)?;
                need(length <= CONTROL_LIMITS[control] && length as u64 <= self.sizes[index])?;
                cache.bytes.extend(chunk);
            }
            let cache = self.controls[control].as_ref().ok_or(Error::State)?;
            let original = self.source.slot(cache.source.slot)?;
            need(cache.bytes.len() as u64 == self.sizes[index] && original.read_ended && original.read_bytes == self.sizes[index])?;
            need(self.checked(AcquisitionBook::Source, source.slot, AuthorityScope::ImmutableVersion)? == source.facts)?;
        }
        Ok(())
    }
    /// Admit actual ancestry, exact source54 roster, both absent per-I branches,
    /// and original bounded control bytes/EOF. No output mutation occurs here.
    /// The safe caller must authenticate these exact bytes before create_once.
    pub fn admit_once(&mut self) -> Result<[Vec<u8>; 2]> {
        self.source.admission.active.set(true); self.output.admission.active.set(true);
        let result = self.step(|this| {
            need(this.stage == Stage::Fresh)?;
            this.admit_installer()?; this.discover_locations()?; this.recheck_installer()?;
            this.admit_source_tree()?; this.admit_destination()?; this.read_controls()?;
            need(this.absences.iter().all(Option::is_some))?; this.recheck_locations()?;
            this.stage = Stage::Controls;
            Ok([this.controls[0].as_ref().ok_or(Error::State)?.bytes.clone(),
                this.controls[1].as_ref().ok_or(Error::State)?.bytes.clone()])
        });
        self.source.admission.active.set(false); self.output.admission.active.set(false); result
    }
    fn new_dir(&mut self, parent: usize, name: &str) -> Result<usize> {
        self.before_child(parent, name)?;
        let path = self.child_path(AcquisitionBook::Output, parent, name)?;
        let intent = self.creations.len();
        need(intent < DIRECTORY_INTENTS && !self.creations.iter().any(|c| c.path == path))?;
        self.creations.push(Creation { path: path.clone(), parent, entered: false, returned: None });
        let raw = descriptor(FileKind::Directory, false, false)?;
        self.mutate(Effect::Directory(intent), None, &path, &raw, Vec::new())?;
        need(self.creations[intent].parent == parent && self.creations[intent].entered
            && self.creations[intent].returned.is_some_and(|(ok, error)| ok != 0 && error == 0))?;
        let key = self.key(AcquisitionBook::Output, self.output_dirs[parent].slot);
        let original = self.output.open_child(&key, name, FileKind::Directory)?;
        let mut components = self.output_dirs[parent].components.clone(); components.push(name.to_owned());
        let index = self.add_dir(AcquisitionBook::Output, original.index, Some(parent), path, components,
            AuthorityScope::ImmutableVersion, EntryMode::Strict, true, false, true)?;
        let child = self.output_dirs[index].facts.metadata.clone(); self.after_child(parent, name, &child)?;
        let rows = self.entries(AcquisitionBook::Output, index)?;
        need(rows.iter().all(|r| r.name == "." || r.name == ".."))?; Ok(index)
    }
    /// The caller's true value means strict authenticated DATA3/supplier/profile
    /// validation of the returned originals succeeded, not merely JSON parsing.
    /// False latches failure before the first mutation. No implicit acceptance.
    pub fn create_once(&mut self, controls_accepted: bool) -> Result<()> {
        self.step(|this| {
            need(this.stage == Stage::Controls && controls_accepted && this.creations.is_empty())?;
            need(this.absences.iter().all(Option::is_some))?;
            need(expected_sizes(&this.sizes) == Some(this.expected_total))?;
            for (control, index) in CONTROLS.into_iter().enumerate() {
                let cache = this.controls[control].as_ref().ok_or(Error::State)?;
                let source = cache.source.clone();
                let original = this.source.slot(source.slot)?;
                need(control_window(this.sizes[index], original.read_bytes, original.read_ended, cache.bytes.len(), 0).is_some())?;
                need(this.checked(AcquisitionBook::Source, source.slot, AuthorityScope::ImmutableVersion)? == source.facts)?;
            }
            // Prove BOTH recorded absences again through the same held original
            // parents/cursors before any effect. Never adopt a new existing path.
            for absence in this.absences.clone() {
                let absence = absence.ok_or(Error::State)?;
                this.recheck_dir(AcquisitionBook::Output, absence.parent)?;
                need(this.selected(AcquisitionBook::Output, absence.parent, &absence.name)?.is_none())?;
            }
            this.recheck_installer()?; this.recheck_locations()?;
            for relative in this.layout.output_directories.clone() {
                if this.output_paths.contains_key(&relative) { continue; }
                let (parent, name) = if relative.is_empty() {
                    (this.program_files.ok_or(Error::State)?, "Mobile Release Kit".to_owned())
                } else {
                    let (parent, name) = relative_parent(&relative);
                    (*this.output_paths.get(parent).ok_or(Error::State)?, name.to_owned())
                };
                let index = this.new_dir(parent, &name)?;
                need(this.output_paths.insert(relative, index).is_none())?;
            }
            this.stage = Stage::Copying; Ok(())
        })
    }
}

impl InputAcquisition {
    pub fn start_copy(&mut self, index: usize) -> Result<()> {
        self.step(|this| {
            need(this.stage == Stage::Copying && this.transfer.is_none() && index == this.proofs.len() && index < INPUTS)?;
            let source = if let Some(control) = CONTROLS.iter().position(|i| *i == index) {
                this.controls[control].as_ref().ok_or(Error::State)?.source.clone()
            } else { this.open_source(index)? };
            need(source.facts.metadata.size == this.sizes[index]
                && this.checked(AcquisitionBook::Source, source.slot, AuthorityScope::ImmutableVersion)? == source.facts)?;
            let (parent, name) = this.payload_parent(index, false)?;
            this.before_child(parent, &name)?;
            let parent_slot = this.output_dirs[parent].slot;
            let parent_name = &this.output.slot(parent_slot)?.canonical;
            let canonical = format!("{}{}{}", parent_name, if parent_name.ends_with('\\') { "" } else { "\\" }, name);
            let writer = this.output.reserve(Kind::File, Some(parent_slot), &name, canonical)?.index;
            let path = this.child_path(AcquisitionBook::Output, parent, &name)?;
            let raw = descriptor(FileKind::File, this.layout.paths[index].image(), false)?;
            this.mutate(Effect::Writer, Some(writer), &path, &raw, Vec::new())?;
            let created = this.checked(AcquisitionBook::Output, writer, AuthorityScope::ImmutableVersion)?;
            this.distinct_file_identity(&created.metadata)?;
            need(created.metadata.size == 0 && created.metadata.identity.volume_serial == this.output_dirs[parent].facts.metadata.identity.volume_serial)?;
            exact_security(&created.security, FileKind::File, this.layout.paths[index].image(), false)?;
            this.output_files[index] = Some(OutputFile { writer, facts: created.clone(), readback: None });
            this.after_child(parent, &name, &created.metadata)?;
            this.transfer = Some(Transfer { index, stage: TransferStage::Copy, source, writer, created,
                readback: None, readback_facts: None, copied: 0, reread: 0, proof: CopyProof::default(),
                source_hash: false, readback_hash: false });
            Ok(())
        })
    }
    /// Only exact successful original writes return bytes to the safe hasher.
    /// Positive short reads remain valid; a short write never gets a repair loop.
    pub fn copy_next(&mut self) -> Result<Vec<u8>> {
        self.step(|this| {
            need(this.stage == Stage::Copying)?;
            let transfer = this.transfer.as_ref().ok_or(Error::State)?;
            need(transfer.stage == TransferStage::Copy)?;
            let (index, source, writer, copied) = (transfer.index, transfer.source.slot, transfer.writer, transfer.copied);
            let size = this.sizes[index];
            let chunk = if let Some(control) = CONTROLS.iter().position(|i| *i == index) {
                let cache = this.controls[control].as_ref().ok_or(Error::State)?;
                need(cache.source.slot == source)?;
                let original = this.source.slot(source)?;
                let range = control_window(size, original.read_bytes, original.read_ended, cache.bytes.len(), copied).ok_or(Error::Unsafe)?;
                cache.bytes.get(range).ok_or(Error::State)?.to_vec()
            } else {
                let key = this.key(AcquisitionBook::Source, source); this.source.read_next(&key, BUFFER)?
            };
            this.tick()?;
            if chunk.is_empty() {
                let original = this.source.slot(source)?;
                need(copied == size && original.read_ended && original.read_bytes == size)?;
                let transfer = this.transfer.as_mut().ok_or(Error::State)?;
                transfer.proof.source_eof = true; transfer.stage = TransferStage::SourceEof; return Ok(chunk);
            }
            let after = copied.checked_add(chunk.len() as u64).ok_or(Error::Bounds)?;
            need(after <= size)?; this.recheck_installer()?;
            let complete = this.mutate(Effect::Write, Some(writer), "", &[], chunk)?;
            need(!this.writes.unknown_count && this.writes.confirmed_bytes <= this.expected_total)?;
            this.transfer.as_mut().ok_or(Error::State)?.copied = after;
            Ok(complete.frame.data.clone())
        })
    }
    // Only the closed actual writer's SAME fixed path can receive its distinct
    // readback original. This never changes ordinary one-path-ever reservation.
    fn reserve_readback(&mut self, parent: usize, name: &str, writer: usize) -> Result<usize> {
        self.ready()?; need(decode::component(name))?;
        let parent_slot = self.output_dirs.get(parent).ok_or(Error::State)?.slot;
        self.output.handle(parent_slot)?;
        let parent_name = &self.output.slot(parent_slot)?.canonical;
        let canonical = format!("{}{}{}", parent_name, if parent_name.ends_with('\\') { "" } else { "\\" }, name);
        need(self.output.slot(writer)?.canonical == canonical && self.output.slot(writer)?.kind == Kind::File
            && self.closed(AcquisitionBook::Output, writer) && later_originals_closed(self.output.slots.iter()
                .filter(|s| s.canonical == canonical).map(|s| s.state)))?;
        let live = self.output.slots.iter().filter(|s| !matches!(s.state, SlotState::NoHandle | SlotState::Closed)).count();
        if self.output.slots.len() >= self.output.records_limit || live >= MAX_LIVE
            || self.output.slots.iter().filter(|s| s.kind == Kind::File).count() >= MAX_FILES
            || canonical.encode_utf16().count() >= NAME_UNITS { return Err(Error::Bounds); }
        self.output.slots.try_reserve(1).map_err(|_| Error::Bounds)?;
        let index = self.output.slots.len();
        self.output.slots.push(ManuallyDrop::new(Box::pin(Slot { output: UnsafeCell::new(null_mut()),
            state: SlotState::Reserved, kind: Kind::File, file_purpose: FileReadPurpose::Content,
            parent: Some(parent_slot), name: wide(name), canonical, read_bytes: 0, read_ended: false,
            directory_ended: false, directory_mode: DirectoryMode::Unstarted, system_image: None, _pin: PhantomPinned })));
        Ok(index)
    }
    /// A false source hash decision fails before flush/close/readback. A true
    /// value is supplied only after the caller hashes these actual returned
    /// chunks against the immutable authenticated profile and accepts real EOF.
    pub fn finish_copy(&mut self, source_hash_accepted: bool) -> Result<()> {
        self.step(|this| {
            need(this.stage == Stage::Copying && source_hash_accepted)?;
            let transfer = this.transfer.as_ref().ok_or(Error::State)?;
            need(transfer.stage == TransferStage::SourceEof && transfer.proof.source_eof
                && transfer.copied == this.sizes[transfer.index])?;
            let (index, source, writer, created) = (transfer.index, transfer.source.clone(), transfer.writer, transfer.created.clone());
            need(this.source.slot(source.slot)?.read_ended && this.source.slot(source.slot)?.read_bytes == this.sizes[index])?;
            this.transfer.as_mut().ok_or(Error::State)?.source_hash = true;
            this.recheck_installer()?;
            this.mutate(Effect::Flush, Some(writer), "", &[], Vec::new())?;
            this.transfer.as_mut().ok_or(Error::State)?.proof.flushed = true;
            let written = this.checked(AcquisitionBook::Output, writer, AuthorityScope::ImmutableVersion)?;
            need(write_transition(&created.metadata, &written.metadata, this.sizes[index]) && created.security == written.security)?;
            exact_security(&written.security, FileKind::File, this.layout.paths[index].image(), false)?;
            this.close_one(AcquisitionBook::Output, writer)?;
            this.transfer.as_mut().ok_or(Error::State)?.proof.writer_closed = true;
            need(this.checked(AcquisitionBook::Source, source.slot, AuthorityScope::ImmutableVersion)? == source.facts)?;
            this.close_one(AcquisitionBook::Source, source.slot)?;
            this.transfer.as_mut().ok_or(Error::State)?.proof.source_closed = true;
            this.ready()?;
            let (parent, name) = this.payload_parent(index, false)?; this.recheck_dir(AcquisitionBook::Output, parent)?;
            let readback = this.reserve_readback(parent, &name, writer)?;
            this.transfer.as_mut().ok_or(Error::State)?.readback = Some(readback);
            this.output_files[index].as_mut().ok_or(Error::State)?.readback = Some(readback);
            this.output.call(Call::Open(readback), null_mut(), Vec::new())?;
            this.output.noninherited(readback)?;
            let observed = this.checked(AcquisitionBook::Output, readback, AuthorityScope::ImmutableVersion)?;
            need(writer_close_transition(&written.metadata, &observed.metadata) && written.security == observed.security)?;
            this.output_files[index].as_mut().ok_or(Error::State)?.facts = observed.clone();
            let transfer = this.transfer.as_mut().ok_or(Error::State)?;
            transfer.readback_facts = Some(observed); transfer.stage = TransferStage::Readback; Ok(())
        })
    }
    pub fn readback_next(&mut self) -> Result<Vec<u8>> {
        self.step(|this| {
            need(this.stage == Stage::Copying)?;
            let transfer = this.transfer.as_ref().ok_or(Error::State)?;
            need(transfer.stage == TransferStage::Readback && transfer.proof.writer_closed && transfer.proof.source_closed && transfer.source_hash)?;
            let (index, readback, before) = (transfer.index, transfer.readback.ok_or(Error::State)?, transfer.reread);
            let key = this.key(AcquisitionBook::Output, readback); let chunk = this.output.read_next(&key, BUFFER)?; this.tick()?;
            let count = before.checked_add(chunk.len() as u64).ok_or(Error::Bounds)?; need(count <= this.sizes[index])?;
            if chunk.is_empty() {
                need(count == this.sizes[index] && this.output.slot(readback)?.read_ended
                    && this.output.slot(readback)?.read_bytes == count)?;
            }
            let transfer = this.transfer.as_mut().ok_or(Error::State)?; transfer.reread = count;
            if chunk.is_empty() { transfer.proof.readback_eof = true; transfer.stage = TransferStage::ReadbackEof; }
            Ok(chunk)
        })
    }
    pub fn finish_readback(&mut self, readback_hash_accepted: bool) -> Result<()> {
        self.step(|this| {
            need(this.stage == Stage::Copying && readback_hash_accepted)?;
            let transfer = this.transfer.as_ref().ok_or(Error::State)?;
            need(transfer.stage == TransferStage::ReadbackEof && transfer.source_hash && transfer.proof.readback_eof
                && transfer.index == this.proofs.len() && transfer.reread == this.sizes[transfer.index])?;
            let (readback, before) = (transfer.readback.ok_or(Error::State)?, transfer.readback_facts.clone().ok_or(Error::State)?);
            need(this.output.slot(readback)?.read_ended
                && this.checked(AcquisitionBook::Output, readback, AuthorityScope::ImmutableVersion)? == before)?;
            this.close_one(AcquisitionBook::Output, readback)?;
            let transfer = this.transfer.as_mut().ok_or(Error::State)?;
            transfer.proof.readback_closed = true; transfer.readback_hash = true;
            need(transfer.proof.complete() && transfer.source_hash && transfer.readback_hash)?;
            let transfer = this.transfer.take().ok_or(Error::State)?; this.proofs.push(transfer.proof); Ok(())
        })
    }
    fn inventories(&mut self) -> Result<()> {
        need(self.transfer.is_none() && self.proofs.len() == INPUTS && self.proofs.iter().all(|p| p.complete()))?;
        for index in 0..INPUTS {
            let source = self.source_files[index].as_ref().ok_or(Error::State)?;
            let output = self.output_files[index].as_ref().ok_or(Error::State)?;
            need(self.closed(AcquisitionBook::Source, source.slot) && self.closed(AcquisitionBook::Output, output.writer)
                && self.closed(AcquisitionBook::Output, output.readback.ok_or(Error::State)?))?;
        }
        need(self.source.bytes_read == self.expected_total && self.output.bytes_read == self.expected_total
            && self.writes.confirmed_bytes == self.expected_total && !self.writes.unknown_count)?;
        for relative in self.layout.source_directories.clone() {
            let parent = *self.source_paths.get(&relative).ok_or(Error::State)?;
            let rows = self.entries(AcquisitionBook::Source, parent)?;
            let mut expected = BTreeMap::new();
            for directory in self.source_dirs.iter().filter(|d| d.parent == Some(parent)) {
                let name = directory.dos.rsplit('\\').next().ok_or(Error::State)?;
                expected.insert(name.to_owned(), directory.facts.metadata.clone());
            }
            for (index, path) in self.layout.paths.iter().enumerate() {
                let (at, name) = relative_parent(&path.source);
                if at == relative {
                    expected.insert(name.to_owned(), self.source_files[index].as_ref().ok_or(Error::State)?.facts.metadata.clone());
                }
            }
            exact_entries(&rows, &expected)?;
        }
        // New directories use their original empty cursor plus actual recorded
        // child creates. Shared ancestors keep their original selected cursor.
        // No reopened enumeration, assumed empty receipt, or silent drift refresh.
        for parent in 0..self.output_dirs.len() {
            let mut rows = self.entries(AcquisitionBook::Output, parent)?;
            rows.extend(self.output_dirs[parent].additions.iter().cloned());
            if let EntryMode::Selected(names) = &self.output_dirs[parent].mode {
                rows.retain(|r| r.name == "." || r.name == ".." || names.iter().any(|n| n.eq_ignore_ascii_case(&r.name)));
            }
            let directory = &self.output_dirs[parent];
            check_entry_frame(&rows, &directory.facts.metadata, directory.parent.map(|i| &self.output_dirs[i].facts.metadata))?;
            let mut expected = BTreeMap::new();
            for child in self.output_dirs.iter().filter(|d| d.parent == Some(parent)) {
                let name = child.dos.rsplit('\\').next().ok_or(Error::State)?;
                expected.insert(name.to_owned(), child.facts.metadata.clone());
            }
            for index in 0..INPUTS {
                let (at, name) = self.payload_parent(index, false)?;
                if at == parent {
                    expected.insert(name, self.output_files[index].as_ref().ok_or(Error::State)?.facts.metadata.clone());
                }
            }
            exact_entries(&rows, &expected)?;
        }
        for i in 0..self.source_dirs.len() { self.recheck_dir(AcquisitionBook::Source, i)?; }
        for i in 0..self.output_dirs.len() { self.recheck_dir(AcquisitionBook::Output, i)?; }
        Ok(())
    }
    fn settle_books_once(&mut self) -> CloseOutcome {
        if self.settlement_attempted {
            return if self.source.settled() && self.output.settled() && !self.active_frame() {
                CloseOutcome::Settled
            } else { CloseOutcome::Unknown };
        }
        self.settlement_attempted = true;
        self.source.retiring = true; self.output.retiring = true;
        // One unresolved frame stops native entry across BOTH books, even if
        // the other book happens to have no active query arena of its own.
        if self.active_frame() {
            self.source.mark_interrupted(); self.output.mark_interrupted(); self.latch(Error::Unknown);
            return CloseOutcome::Unknown;
        }
        for side in [AcquisitionBook::Source, AcquisitionBook::Output] {
            for slot in (0..self.book(side).slots.len()).rev() {
                if self.active_frame() {
                    self.source.mark_interrupted(); self.output.mark_interrupted(); self.latch(Error::Unknown);
                    return CloseOutcome::Unknown;
                }
                let state = match self.book(side).slot(slot) {
                    Ok(s) => s.state,
                    Err(error) => { self.latch(error); self.book_mut(side).mark_interrupted(); continue; },
                };
                match state {
                    SlotState::NoHandle | SlotState::Closed => continue,
                    SlotState::Unknown | SlotState::Closing | SlotState::Acquiring => {
                        // Never retry an attempted/uncertain original close.
                        self.book_mut(side).mark_interrupted(); self.latch(Error::Unknown); continue;
                    },
                    SlotState::Reserved | SlotState::Owned => {},
                }
                if let Err(error) = self.close_one(side, slot) {
                    self.book_mut(side).mark_interrupted(); self.latch(error);
                }
            }
        }
        if self.source.settled() && self.output.settled() && !self.active_frame() { CloseOutcome::Settled }
        else { self.latch(Error::Unknown); CloseOutcome::Unknown }
    }
    /// Final same-original postconditions, then once-closes in dependency order.
    /// This does not expose any files to ordinary users or start an executable.
    pub fn finish_once(&mut self) -> Result<()> {
        self.step(|this| {
            need(this.stage == Stage::Copying && this.proofs.len() == INPUTS && this.transfer.is_none())?;
            this.recheck_installer()?; this.recheck_locations()?; this.inventories()?;
            this.recheck_installer()?; this.recheck_locations()?; this.tick()?;
            if this.settle_books_once() != CloseOutcome::Settled {
                return Err(this.first_failure.unwrap_or(Error::Unknown));
            }
            need(this.source.settled() && this.output.settled() && this.first_failure.is_none()
                && !this.unknown && this.cleanup_errors.is_empty())?;
            this.tick()?; this.stage = Stage::Complete; Ok(())
        })
    }
    /// Cleanup finality is not acquisition success. Failure/STOP/timeout is
    /// latched before any permitted once-close, and no partial path is deleted.
    pub fn fail_and_settle_once(&mut self) -> CloseOutcome {
        if self.first_failure.is_none() { self.latch(Error::State); }
        self.settle_books_once()
    }
    pub fn inputs_retained_and_settled(&self) -> bool {
        self.stage == Stage::Complete && self.first_failure.is_none() && !self.unknown && !self.expired
            && Instant::now() < self.end && self.proofs.len() == INPUTS && self.transfer.is_none()
            && self.settlement_attempted && self.cleanup_errors.is_empty() && !self.active_frame()
            && self.source.settled() && self.output.settled()
    }
    #[cfg(feature = "runtime-publication")]
    pub(super) fn runtime_source_binding(&self) -> Result<(String, String, Arc<()>, Facts)> {
        // Historical successful closure, not a new deadline-sensitive receipt.
        // The safe caller additionally owes its actual retained return and live
        // original aggregate guard. No original book is reset or reopened here.
        need(self.stage == Stage::Complete && self.first_failure.is_none() && !self.unknown
            && !self.expired && self.proofs.len() == INPUTS && self.proofs.iter().all(|p| p.complete())
            && self.transfer.is_none() && self.settlement_attempted && self.cleanup_errors.is_empty()
            && !self.active_frame() && self.source.settled() && self.output.settled())?;
        for index in 0..INPUTS {
            let source = self.source_files[index].as_ref().ok_or(Error::State)?;
            let output = self.output_files[index].as_ref().ok_or(Error::State)?;
            need(self.closed(AcquisitionBook::Source, source.slot)
                && self.closed(AcquisitionBook::Output, output.writer)
                && self.closed(AcquisitionBook::Output, output.readback.ok_or(Error::State)?))?;
        }
        let root = *self.output_paths.get("").ok_or(Error::State)?;
        let mrk = self.output_dirs.get(root).ok_or(Error::State)?;
        need(self.closed(AcquisitionBook::Output, mrk.slot))?;
        Ok((self.digest.clone(), self.image.clone(), Arc::clone(&self.output.identity), mrk.facts.clone()))
    }
    /// Read-only original-storage DATA for the explicit nonshipping fixture.
    /// In particular this does not resample or prolong the old acquisition clock.
    #[cfg(feature = "installer-protected-fixture")]
    pub fn retained_fixture_observation(&self) -> super::installer_fixture_data::InstallerFixtureAcquisitionObservation {
        use super::installer_fixture_data::InstallerFixtureAcquisitionObservation;
        let mut result = InstallerFixtureAcquisitionObservation {
            original_books_settled: self.settlement_attempted && self.source.settled()
                && self.output.settled() && !self.active_frame() && !self.unknown,
            complete_rows: self.proofs.iter().filter(|p| p.complete()).count(),
            controls_read_bytes: self.controls.iter().flatten().map(|c| c.bytes.len() as u64).sum(),
            byte_counts: self.byte_counts(),
            partial_ordinal: self.transfer.as_ref().map(|t| t.index),
            partial_writer_closed: self.transfer.as_ref()
                .is_some_and(|t| self.closed(AcquisitionBook::Output, t.writer)),
            activation_started: self.activation.is_some(),
            activation_settled: self.shell_activation_settled(),
            activation_completed: self.shell_activation_completed(),
            activation_cleanup_errors: self.shell_activation_cleanup_errors().len(),
            roles_mask: 0, transition_mask: 0, controls_mask: 0,
            public_roles_mask: 0, unexpected_control: false,
        };
        if let Some(Ok(activation)) = &self.activation {
            for (i, role) in activation.roles.iter().enumerate() {
                if i >= 6 { result.unexpected_control = true; continue; }
                result.roles_mask |= 1 << i;
                if role.transition { result.transition_mask |= 1 << i; }
            }
            for node in &activation.nodes {
                if let Some(i) = node.role {
                    if i >= 6 { result.unexpected_control = true; continue; }
                    if node.control.is_some() { result.controls_mask |= 1 << i; }
                    if exact_security(&node.facts.security, node.facts.metadata.kind, i == 5, true).is_ok() {
                        result.public_roles_mask |= 1 << i;
                    }
                } else if node.control.is_some() { result.unexpected_control = true; }
            }
        }
        result
    }
    pub fn first_failure(&self) -> Option<Error> { self.first_failure }
    pub fn cleanup_errors(&self) -> &[AcquisitionCleanupError] { &self.cleanup_errors }
    pub fn byte_counts(&self) -> AcquisitionByteCounts {
        AcquisitionByteCounts { source_read: self.source.bytes_read, confirmed_written: self.writes.confirmed_bytes,
            readback_read: self.output.bytes_read, write_count_unknown: self.writes.unknown_count
                || self.mutation.as_ref().is_some_and(|f| matches!(f.as_ref().get_ref().effect, Effect::Write)) }
    }
}


/// Borrowed original acquisition facts for the fixed offline prerequisite owner.
/// This is neither a new path authority nor a current-filesystem success receipt.
#[cfg(feature = "runtime-publication")]
pub(super) struct PrerequisiteAncestor<'a> {
    pub(super) path: &'a str,
    pub(super) facts: &'a Facts,
    pub(super) scope: AuthorityScope,
}

#[cfg(feature = "runtime-publication")]
pub(super) struct PrerequisiteBinding<'a> {
    pub(super) source_identity: &'a Arc<()>,
    pub(super) output_identity: &'a Arc<()>,
    pub(super) installer: &'a Installer,
    pub(super) location: &'a KnownLocation,
    pub(super) digest: &'a str,
    pub(super) image: &'a str,
    pub(super) helper: &'a str,
    pub(super) row49_relative: &'a str,
    pub(super) row49_size: u64,
    pub(super) row49_facts: &'a Facts,
    pub(super) ancestors: [PrerequisiteAncestor<'a>; 5],
}

#[cfg(feature = "runtime-publication")]
impl InputAcquisition {
    /// Historical original54 closure only. The real prerequisite owner must
    /// freshly admit current originals and compare these exact facts before work.
    /// The safe caller still owes its actual retained acquisition Result/guard.
    pub(super) fn prerequisite_binding(&self) -> Result<PrerequisiteBinding<'_>> {
        self.runtime_source_binding()?;
        let location = self.output_location.as_ref().ok_or(Error::State)?;
        need(Arc::ptr_eq(&location.book, &self.output.identity)
            && !Arc::ptr_eq(&self.source.identity, &self.output.identity))?;
        let installer = self.installer.as_ref().ok_or(Error::State)?;
        let prefix = format!("installer-input/{TARGET}/{}/", self.image);
        let publisher = self.layout.paths.get(47).ok_or(Error::State)?;
        need(publisher.source == "publisher/mrk-windows-runtime-publish.exe")?;
        let helper = publisher.output.strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix("/mrk-windows-runtime-publish.exe"))
            .ok_or(Error::State)?;
        need(digest_name(helper))?;

        let row = self.layout.paths.get(49).ok_or(Error::State)?;
        need(row.source == "prerequisites/MicrosoftEdgeWebView2RuntimeInstallerX64.exe"
            && row.output == format!("{prefix}prerequisites/MicrosoftEdgeWebView2RuntimeInstallerX64.exe"))?;
        let output = self.output_files.get(49).and_then(Option::as_ref).ok_or(Error::State)?;
        need(self.proofs.get(49).is_some_and(|proof| proof.complete())
            && self.closed(AcquisitionBook::Output, output.writer)
            && self.closed(AcquisitionBook::Output, output.readback.ok_or(Error::State)?)
            && output.facts.metadata.kind == FileKind::File
            && output.facts.metadata.size == self.sizes[49])?;
        exact_security(&output.facts.security, FileKind::File, true, false)?;

        let paths = [String::new(), "installer-input".to_owned(),
            format!("installer-input/{TARGET}"),
            format!("installer-input/{TARGET}/{}", self.image),
            format!("installer-input/{TARGET}/{}/prerequisites", self.image)];
        let mut indices = [0usize; 5];
        for (ordinal, path) in paths.iter().enumerate() {
            let index = *self.output_paths.get(path).ok_or(Error::State)?;
            let directory = self.output_dirs.get(index).ok_or(Error::State)?;
            need(directory.facts.metadata.kind == FileKind::Directory
                && self.closed(AcquisitionBook::Output, directory.slot)
                && directory.parent == if ordinal == 0 { self.program_files }
                    else { Some(indices[ordinal - 1]) })?;
            indices[ordinal] = index;
        }
        let parent = &self.output_dirs[indices[4]];
        let (row_parent, row_name) = relative_parent(&row.output);
        need(row_parent == paths[4]
            && row_name == "MicrosoftEdgeWebView2RuntimeInstallerX64.exe"
            && output.facts.metadata.identity.volume_serial
                == parent.facts.metadata.identity.volume_serial)?;
        // The checked indices stay valid under this immutable borrow. No copy
        // of a receipt, factory, reopened owner or mutable original can escape.
        let ancestors = std::array::from_fn(|ordinal| {
            let directory = &self.output_dirs[indices[ordinal]];
            PrerequisiteAncestor { path: &directory.dos,
                facts: &directory.facts, scope: directory.scope }
        });
        Ok(PrerequisiteBinding {
            source_identity: &self.source.identity, output_identity: &self.output.identity,
            installer, location, digest: &self.digest, image: &self.image, helper,
            row49_relative: &row.output, row49_size: self.sizes[49],
            row49_facts: &output.facts, ancestors,
        })
    }
}

#[cfg(feature = "runtime-publication")]
#[derive(Clone, Debug)]
pub struct ShellActivationCleanupError { pub original: usize, pub error: Error }

#[cfg(feature = "runtime-publication")]
struct RetainedShellRole {
    // Derived from the actual acquisition, never passed by an external caller.
    name: String, path: String, facts: Facts, transition: bool,
    expected_entries: Option<Vec<DirectoryEntry>>,
}
#[cfg(feature = "runtime-publication")]
struct ShellNode {
    slot: usize, parent: Option<usize>, path: String, facts: Facts,
    scope: AuthorityScope, control: Option<usize>, role: Option<usize>,
    entries: Option<Vec<DirectoryEntry>>,
}
#[cfg(feature = "runtime-publication")]
impl ShellNode { fn current(&self) -> usize { self.control.unwrap_or(self.slot) } }

/// New control originals live inside the same acquisition owner. Its previously
/// settled source/output books stay untouched; no replacement owner or timer.
#[cfg(feature = "runtime-publication")]
struct ShellActivation {
    book: NativeBook, mutation: MutationSlot, roles: Vec<RetainedShellRole>,
    nodes: Vec<ShellNode>, location: Option<KnownLocation>, expected_location: (String, String, Vec<String>),
    installer: Installer, first: Option<Error>, unknown: bool, exposed: bool,
    settling: bool, complete: bool, cleanup: Vec<ShellActivationCleanupError>,
}

// Macro syntax, not an operation callback/factory: the concrete expression is
// evaluated only after this SAME actual borrowed producing boundary.
#[cfg(feature = "runtime-publication")]
macro_rules! shell_call {
    ($owner:ident, $boundary:ident, $expression:expr) => {{
        $owner.before($boundary)?;
        let returned = $expression;
        $owner.after($boundary, returned)?
    }};
}

#[cfg(feature = "runtime-publication")]
fn shell_directory_transition(dir: &InputDirectory, facts: &Facts, creations: &[Creation]) -> Result<bool> {
    need(facts.metadata.kind == FileKind::Directory)?;
    if exact_security(&facts.security, FileKind::Directory, false, true).is_ok() { return Ok(false); }
    exact_security(&facts.security, FileKind::Directory, false, false)?;
    need(dir.created)?;
    let mut own = creations.iter().filter(|c| c.path == dir.dos);
    let created = own.next().ok_or(Error::State)?;
    need(own.next().is_none() && Some(created.parent) == dir.parent && created.entered
        && created.returned.is_some_and(|(ok, error)| ok != 0 && error == 0))?;
    Ok(true)
}

#[cfg(feature = "runtime-publication")]
impl InputAcquisition {
    fn retained_shell_roles(&self, runtime: &super::publication::Publication) -> Result<Vec<RetainedShellRole>> {
        let mrk = runtime.activation_mrk(self)?;
        let paths = [
            String::new(), "installer-input".to_owned(),
            format!("installer-input/{TARGET}"), format!("installer-input/{TARGET}/{}", self.image),
            format!("installer-input/{TARGET}/{}/shell", self.image),
        ];
        let mut roles = Vec::new();
        let mut previous = None;
        for (ordinal, path) in paths.iter().enumerate() {
            let index = *self.output_paths.get(path).ok_or(Error::State)?;
            let dir = self.output_dirs.get(index).ok_or(Error::State)?;
            if ordinal != 0 { need(dir.parent == previous)?; }
            previous = Some(index);
            let facts = if ordinal == 0 { mrk.clone() } else { dir.facts.clone() };
            let transition = shell_directory_transition(dir, &facts, &self.creations)?;
            let expected_entries = if ordinal >= 3 {
                let mut entries = dir.entries.clone().ok_or(Error::State)?;
                entries.extend(dir.additions.clone()); Some(entries)
            } else { None };
            let name = dir.dos.rsplit('\\').next().ok_or(Error::State)?.to_owned();
            roles.push(RetainedShellRole { name, path: dir.dos.clone(), facts, transition, expected_entries });
        }
        let row = self.layout.paths.get(48).ok_or(Error::State)?;
        need(row.output == format!("installer-input/{TARGET}/{}/shell/mobile-release-kit-desktop.exe", self.image))?;
        let shell = self.output_files.get(48).and_then(Option::as_ref).ok_or(Error::State)?;
        need(self.proofs.get(48).is_some_and(|p| p.complete())
            && self.closed(AcquisitionBook::Output, shell.writer)
            && self.closed(AcquisitionBook::Output, shell.readback.ok_or(Error::State)?)
            && shell.facts.metadata.kind == FileKind::File && shell.facts.metadata.size == self.sizes[48])?;
        exact_security(&shell.facts.security, FileKind::File, true, false)?;
        let parent = roles.last().ok_or(Error::State)?;
        roles.push(RetainedShellRole { name: "mobile-release-kit-desktop.exe".to_owned(),
            path: format!("{}\\mobile-release-kit-desktop.exe", parent.path),
            facts: shell.facts.clone(), transition: true, expected_entries: None });
        need(roles.len() == 6)?;
        Ok(roles)
    }
    fn prepare_shell_activation(&self, runtime: &super::publication::Publication) -> Result<ShellActivation> {
        let roles = self.retained_shell_roles(runtime)?;
        let location = self.output_location.as_ref().ok_or(Error::State)?;
        let installer = self.installer.clone().ok_or(Error::State)?;
        Ok(ShellActivation {
            book: NativeBook::new(), mutation: None, roles, nodes: Vec::new(), location: None,
            expected_location: (location.drive.clone(), location.device.clone(), location.components.clone()),
            installer, first: None, unknown: false, exposed: false, settling: false, complete: false, cleanup: Vec::new(),
        })
    }
    /// Native permission phase only. The fixed application sequencer must also
    /// require its actual acquisition, offline prerequisite and runtime results.
    /// There is no public installer/selection entry in this source slice.
    pub fn activate_retained_shell_once(&mut self, runtime: &super::publication::Publication,
        prerequisite: &super::installer_webview2::OfflineWebView2Owner,
        boundary: &dyn InstallerBoundary) -> Result<()> {
        need(self.activation.is_none())?;
        // Even an admission failure is retained once. Preparing this DATA has
        // no native effects; the actual owner is registered BEFORE run enters.
        // The actual same-acquisition prerequisite original is mandatory. A DTO,
        // copied mode or native owner from another acquisition cannot expose roles.
        self.activation = Some(prerequisite.require_complete_for(self)
            .and_then(|()| self.prepare_shell_activation(runtime)));
        let original = match self.activation.as_mut().ok_or(Error::State)? {
            Ok(original) => original,
            Err(first) => return Err(*first),
        };
        let returned = original.run(boundary);
        match returned {
            Ok(()) => Ok(()),
            Err(first) => {
                original.latch(first);
                // Error already retained. STOP never prevents once settlement.
                original.settle_once(boundary);
                Err(first)
            },
        }
    }
    pub fn shell_activation_settled(&self) -> bool {
        match self.activation.as_ref() {
            Some(Err(_)) => true, // preparation refused BEFORE any native effect
            Some(Ok(a)) => a.settling && a.book.settled() && a.mutation.is_none() && !a.unknown,
            None => false,
        }
    }
    pub fn shell_activation_completed(&self) -> bool {
        self.activation.as_ref().is_some_and(|a| a.as_ref().is_ok_and(|a|
            a.complete && a.first.is_none() && a.exposed && a.cleanup.is_empty())) && self.shell_activation_settled()
    }
    pub fn shell_activation_possibly_exposed(&self) -> bool {
        self.activation.as_ref().is_some_and(|a| a.as_ref().is_ok_and(|a| a.exposed))
    }
    pub fn shell_activation_first_failure(&self) -> Option<Error> {
        match self.activation.as_ref() { Some(Err(first)) => Some(*first), Some(Ok(a)) => a.first, None => None }
    }
    pub fn shell_activation_cleanup_errors(&self) -> &[ShellActivationCleanupError] {
        match self.activation.as_ref() { Some(Ok(a)) => a.cleanup.as_slice(), _ => &[] }
    }
}

#[cfg(feature = "runtime-publication")]
impl ShellActivation {
    fn key(&self, slot: usize) -> Original { Original { book: Arc::clone(&self.book.identity), index: slot } }
    fn active(&self) -> bool { self.mutation.is_some() || self.book.active.is_some() }
    fn latch(&mut self, error: Error) {
        if self.first.is_none() { self.first = Some(error); }
        self.unknown |= error == Error::Unknown || self.active() || self.book.is_unknown();
    }
    fn before(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        let result = if self.active() || self.unknown || self.book.is_unknown() { Err(Error::Unknown) }
            else if self.first.is_some() || self.settling { Err(Error::State) }
            else { boundary.producing_boundary() };
        if let Err(error) = result { self.latch(error); } result
    }
    fn after<T>(&mut self, boundary: &dyn InstallerBoundary, returned: Result<T>) -> Result<T> {
        // A returned native error wins before a later STOP/clock sample.
        let result = match returned {
            Err(first) => Err(first),
            Ok(value) => boundary.producing_boundary().map(|()| value),
        };
        if let Err(error) = result.as_ref() { self.latch(*error); } result
    }
    fn mutate(&mut self, boundary: &dyn InstallerBoundary, effect: Effect, slot: usize,
        path: &str, descriptor: &[u8]) -> Result<MutationComplete> {
        self.before(boundary)?;
        // No directory/data creation is supported in this owner.
        need(matches!(effect, Effect::Control(_) | Effect::Seal | Effect::Scalar(_)))?;
        let mut no_creations = [];
        let entered = enter_registered_mutation(&mut self.book, &mut self.mutation,
            &mut no_creations, effect, Some(slot), path, descriptor, Vec::new());
        if let Err(error) = entered { self.latch(error); return Err(error); }
        // Classify/retire the real returned frame before the after-boundary.
        let returned = finish_registered_mutation(&mut self.book, &mut self.mutation, &mut no_creations, None);
        self.after(boundary, returned)
    }
    fn checked(&mut self, boundary: &dyn InstallerBoundary, slot: usize, scope: AuthorityScope) -> Result<Facts> {
        let key = self.key(slot);
        shell_call!(self, boundary, self.book.noninherited(slot));
        let metadata = shell_call!(self, boundary, self.book.metadata(&key));
        need(metadata.identity.volume_serial != 0 && metadata.links == 1
            && metadata.creation > 0 && metadata.write > 0 && metadata.change > 0)?;
        shell_call!(self, boundary, self.book.no_alternate_streams(&key));
        let security = shell_call!(self, boundary, self.book.security(&key, scope));
        need(shell_call!(self, boundary, self.book.metadata(&key)) == metadata)?;
        Ok(Facts { metadata, security })
    }
    fn recheck(&mut self, boundary: &dyn InstallerBoundary, index: usize) -> Result<()> {
        let node = self.nodes.get(index).ok_or(Error::State)?;
        let (slot, scope, facts) = (node.current(), node.scope, node.facts.clone());
        need(self.checked(boundary, slot, scope)? == facts)
    }
    fn token_scalar(&mut self, boundary: &dyn InstallerBoundary, index: usize,
        class: S::TOKEN_INFORMATION_CLASS) -> Result<u32> {
        let value = shell_call!(self, boundary, self.book.token(index, class));
        let trace = self.book.admission.at(O::TokenData);
        trace.need(value.count_in(trace)? == 4, C::ScalarWidth)?;
        decode::Observed::new(trace).u32_at(value.bytes_in(4, trace)?, 0)
    }
    fn collect_installer(&mut self, boundary: &dyn InstallerBoundary, index: usize) -> Result<Installer> {
        shell_call!(self, boundary, self.book.absent_thread_token());
        let before = shell_call!(self, boundary, self.book.token(index, S::TokenStatistics));
        let trace = self.book.admission.at(O::TokenData);
        let initial = security::Observed::new(trace).statistics(before.bytes_in(before.count_in(trace)?, trace)?)?;
        let token_type = self.token_scalar(boundary, index, S::TokenType)?;
        let elevated = self.token_scalar(boundary, index, S::TokenElevation)?;
        let elevation_type = self.token_scalar(boundary, index, S::TokenElevationType)?;
        let ui_access = self.token_scalar(boundary, index, S::TokenUIAccess)?;
        let virtualization = self.token_scalar(boundary, index, S::TokenVirtualizationEnabled)?;
        let restricted = self.mutate(boundary, Effect::Scalar(S::TokenHasRestrictions), index, "", &[])?.scalar()?;
        let restricted = scalar_value(restricted)?;
        let app_container = self.mutate(boundary, Effect::Scalar(S::TokenIsAppContainer), index, "", &[])?.scalar()?;
        let app_container = scalar_value(app_container)?;
        let user = shell_call!(self, boundary, self.book.token(index, S::TokenUser));
        let integrity = shell_call!(self, boundary, self.book.token(index, S::TokenIntegrityLevel));
        let groups = shell_call!(self, boundary, self.book.token(index, S::TokenGroups));
        let privileges = shell_call!(self, boundary, self.book.token(index, S::TokenPrivileges));
        let trace = self.book.admission.at(O::InstallerPolicy).role(R::Installer);
        let data = self.book.admission.at(O::TokenData);
        let u = data.role(R::User); let i = data.role(R::Integrity);
        let g = data.role(R::Groups); let p = data.role(R::Privileges);
        let result = InstallerData(trace).installer_facts(initial, token_type, elevated, elevation_type,
            ui_access, virtualization, restricted, app_container,
            user.bytes_in(user.count_in(u)?, u)?, integrity.bytes_in(integrity.count_in(i)?, i)?,
            groups.bytes_in(groups.count_in(g)?, g)?, privileges.bytes_in(privileges.count_in(p)?, p)?)?;
        let after = shell_call!(self, boundary, self.book.token(index, S::TokenStatistics));
        let trace = self.book.admission.at(O::TokenData);
        need(security::Observed::new(trace).statistics(after.bytes_in(after.count_in(trace)?, trace)?)? == initial)?;
        shell_call!(self, boundary, self.book.absent_thread_token());
        Ok(result)
    }
    fn open_token(&mut self, boundary: &dyn InstallerBoundary) -> Result<usize> {
        let key = shell_call!(self, boundary, self.book.reserve(Kind::ProcessToken, None, "", String::new()));
        let returned = shell_call!(self, boundary, self.book.call(Call::ProcessToken(key.index), null_mut(), Vec::new()));
        need(matches!(returned.arena.returned()?, Returned::Boolean(v, 0) if v != 0))?;
        shell_call!(self, boundary, self.book.noninherited(key.index)); Ok(key.index)
    }
    fn close_producing(&mut self, boundary: &dyn InstallerBoundary, slot: usize) -> Result<()> {
        self.before(boundary)?;
        let returned = self.book.close_index(slot);
        if let Err(error) = returned {
            self.cleanup.push(ShellActivationCleanupError { original: slot, error });
        }
        self.after(boundary, returned)
    }
    fn recheck_installer(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        let original = self.book.process_token.ok_or(Error::State)?;
        need(self.collect_installer(boundary, original)? == self.installer)?;
        let current = self.open_token(boundary)?;
        need(self.collect_installer(boundary, current)? == self.installer)?;
        self.close_producing(boundary, current)?;
        shell_call!(self, boundary, self.book.absent_thread_token()); Ok(())
    }
    fn recheck_location(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        self.before(boundary)?;
        let returned = self.book.recheck_location(self.location.as_ref().ok_or(Error::State)?);
        self.after(boundary, returned)
    }
    fn entries(&mut self, boundary: &dyn InstallerBoundary, index: usize, name: &str) -> Result<Vec<DirectoryEntry>> {
        if let Some(rows) = &self.nodes.get(index).ok_or(Error::State)?.entries { return Ok(rows.clone()); }
        self.recheck(boundary, index)?;
        let node = &self.nodes[index];
        let strict = node.role.is_some_and(|r| self.roles[r].expected_entries.is_some());
        let key = self.key(node.current());
        let mut entries = Vec::new();
        loop {
            let batch = if strict { shell_call!(self, boundary, self.book.next_entries(&key)) }
                else { shell_call!(self, boundary, self.book.next_ancestor_entries(&key, name)) };
            match batch { Some(rows) => entries.extend(rows), None => break }
        }
        let node = &self.nodes[index];
        check_entry_frame(&entries, &node.facts.metadata, node.parent.map(|p| &self.nodes[p].facts.metadata))?;
        if let Some(expected) = node.role.and_then(|r| self.roles[r].expected_entries.as_ref()) {
            let map = |rows: &[DirectoryEntry]| -> Result<BTreeMap<String, ([u8; 16], FileKind, u32)>> {
                let mut found = BTreeMap::new();
                for row in rows {
                    if row.name == "." || row.name == ".." { continue; }
                    need(found.insert(row.name.clone(), (row.file_id, row.kind, row.attributes)).is_none())?;
                }
                Ok(found)
            };
            need(map(expected)? == map(&entries)?)?;
        }
        self.recheck(boundary, index)?;
        self.nodes[index].entries = Some(entries.clone()); Ok(entries)
    }
    fn open_child(&mut self, boundary: &dyn InstallerBoundary, parent: usize,
        name: &str, role: Option<usize>) -> Result<usize> {
        let entries = self.entries(boundary, parent, name)?;
        let row = selected_entry(&entries, name)?.ok_or(Error::Unsafe)?;
        let kind = role.map_or(FileKind::Directory, |i| self.roles[i].facts.metadata.kind);
        need(row.kind == kind)?;
        self.recheck(boundary, parent)?;
        let key = self.key(self.nodes[parent].current());
        let original = shell_call!(self, boundary, self.book.open_child(&key, name, kind));
        let scope = if role.is_some() { AuthorityScope::ImmutableVersion } else { AuthorityScope::AncestorOutsideVersion };
        let facts = self.checked(boundary, original.index, scope)?;
        match_entry(&row, &facts.metadata)?;
        need(!self.nodes.iter().any(|n| n.facts.metadata.identity == facts.metadata.identity))?;
        let parent_path = &self.nodes[parent].path;
        let path = format!("{}{}{}", parent_path, if parent_path.ends_with('\\') { "" } else { "\\" }, name);
        if let Some(i) = role {
            need(self.roles[i].facts == facts && self.roles[i].path == path)?;
        }
        let index = self.nodes.len();
        self.nodes.push(ShellNode { slot: original.index, parent: Some(parent), path, facts, scope,
            control: None, role, entries: None });
        self.recheck(boundary, parent)?; Ok(index)
    }
    fn admit(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        let arch = shell_call!(self, boundary, self.book.call(Call::Architecture, null_mut(), Vec::new()));
        let trace = self.book.admission.at(O::Architecture);
        let d = decode::Observed::new(trace);
        need(d.u16_at(arch.bytes_in(4, trace)?, 0)? == SI::IMAGE_FILE_MACHINE_UNKNOWN
            && d.u16_at(arch.bytes_in(4, trace)?, 2)? == SI::IMAGE_FILE_MACHINE_AMD64)?;
        let token = self.open_token(boundary)?;
        self.book.process_token = Some(token);
        need(self.collect_installer(boundary, token)? == self.installer)?;
        let location = shell_call!(self, boundary, self.book.location(LocationKind::ProgramFiles));
        need(Arc::ptr_eq(&location.book, &self.book.identity)
            && (location.drive.clone(), location.device.clone(), location.components.clone()) == self.expected_location)?;
        need(shell_call!(self, boundary, self.book.mapping(&location.drive)) == location.device)?;
        let path = format!("{}\\", location.drive);
        let native = format!("{}\\", location.device);
        let root = shell_call!(self, boundary, self.book.reserve(Kind::Directory, None, &native, native.clone()));
        shell_call!(self, boundary, self.book.call(Call::Open(root.index), null_mut(), Vec::new()));
        shell_call!(self, boundary, self.book.noninherited(root.index));
        shell_call!(self, boundary, self.book.local_ntfs(&root));
        let facts = self.checked(boundary, root.index, AuthorityScope::AncestorOutsideVersion)?;
        self.nodes.push(ShellNode { slot: root.index, parent: None, path, facts,
            scope: AuthorityScope::AncestorOutsideVersion, control: None, role: None, entries: None });
        let components = location.components.clone();
        self.location = Some(location); self.book.roots_started = true;
        let mut parent = 0;
        for component in components { parent = self.open_child(boundary, parent, &component, None)?; }
        for role in 0..self.roles.len() {
            let name = self.roles[role].name.clone();
            parent = self.open_child(boundary, parent, &name, Some(role))?;
        }
        self.recheck_installer(boundary)?; self.recheck_location(boundary)
    }
    fn reserve_control(&mut self, boundary: &dyn InstallerBoundary, index: usize) -> Result<usize> {
        self.before(boundary)?;
        let node = self.nodes.get(index).ok_or(Error::State)?;
        let role = node.role.ok_or(Error::State)?;
        need(self.roles[role].transition && node.control.is_none() && self.book.slot(node.slot)?.state == SlotState::Closed)?;
        let parent = node.parent.ok_or(Error::State)?;
        let previous = node.slot; let path = node.path.clone();
        let kind = node.facts.metadata.kind; let before = node.facts.clone();
        let name = path.rsplit('\\').next().ok_or(Error::State)?;
        self.recheck(boundary, parent)?; self.recheck_installer(boundary)?; self.recheck_location(boundary)?;
        let parent_slot = self.nodes[parent].current();
        let canonical_parent = &self.book.slot(parent_slot)?.canonical;
        let canonical = format!("{}{}{}", canonical_parent, if canonical_parent.ends_with('\\') { "" } else { "\\" }, name);
        need(self.book.slot(previous)?.canonical == canonical
            && later_originals_closed(self.book.slots.iter().filter(|s| s.canonical == canonical).map(|s| s.state)))?;
        let live = self.book.slots.iter().filter(|s| !matches!(s.state, SlotState::NoHandle | SlotState::Closed)).count();
        need(self.book.slots.len() < MAX_RECORDS && live < MAX_LIVE
            && (kind != FileKind::File || self.book.slots.iter().filter(|s| s.kind == Kind::File).count() < MAX_FILES)
            && canonical.encode_utf16().count() < NAME_UNITS)?;
        self.book.slots.try_reserve(1).map_err(|_| Error::Bounds)?;
        let slot = self.book.slots.len();
        self.book.slots.push(ManuallyDrop::new(Box::pin(Slot { output: UnsafeCell::new(null_mut()),
            state: SlotState::Reserved, kind: kind.into(), file_purpose: FileReadPurpose::Content, parent: Some(parent_slot),
            name: wide(name), canonical, read_bytes: 0, read_ended: false, directory_ended: false,
            directory_mode: DirectoryMode::Unstarted, system_image: None, _pin: PhantomPinned })));
        self.nodes[index].control = Some(slot);
        self.mutate(boundary, Effect::Control(kind == FileKind::Directory), slot, &path, &[])?;
        need(self.checked(boundary, slot, AuthorityScope::ImmutableVersion)? == before)?;
        Ok(slot)
    }
    fn seal(&mut self, boundary: &dyn InstallerBoundary, index: usize) -> Result<()> {
        let node = self.nodes.get(index).ok_or(Error::State)?;
        let role = node.role.ok_or(Error::State)?;
        need(self.roles[role].transition)?;
        let slot = node.control.ok_or(Error::State)?;
        let before = node.facts.clone();
        self.recheck_installer(boundary)?; self.recheck_location(boundary)?;
        need(self.checked(boundary, slot, AuthorityScope::ImmutableVersion)? == before)?;
        let image = role == 5;
        let raw = descriptor(before.metadata.kind, image, true)?;
        self.before(boundary)?;
        // Windows traverse bypass: even the first descendant's failed grant
        // may expose bytes. Record before the actual original native entry.
        self.exposed = true;
        self.mutate(boundary, Effect::Seal, slot, "", &raw)?;
        let after = self.checked(boundary, slot, AuthorityScope::ImmutableVersion)?;
        need(acl_transition(&before.metadata, &after.metadata))?;
        exact_security(&after.security, before.metadata.kind, image, true)?;
        self.nodes[index].facts = after;
        Ok(())
    }
    fn settle_once(&mut self, boundary: &dyn InstallerBoundary) -> CloseOutcome {
        if self.settling { return if self.book.settled() && !self.active() { CloseOutcome::Settled } else { CloseOutcome::Unknown }; }
        self.settling = true; self.book.retiring = true;
        if self.active() { self.book.mark_interrupted(); self.latch(Error::Unknown); return CloseOutcome::Unknown; }
        for slot in (0..self.book.slots.len()).rev() {
            if self.active() { self.book.mark_interrupted(); self.latch(Error::Unknown); return CloseOutcome::Unknown; }
            let state = match self.book.slot(slot) {
                Ok(s) => s.state,
                Err(error) => { self.latch(error); self.book.mark_interrupted(); continue; },
            };
            match state {
                SlotState::NoHandle | SlotState::Closed => continue,
                SlotState::Unknown | SlotState::Closing | SlotState::Acquiring => {
                    self.book.mark_interrupted(); self.latch(Error::Unknown); continue;
                },
                SlotState::Reserved | SlotState::Owned => {},
            }
            boundary.settlement_boundary();
            let returned = self.book.close_index(slot);
            if let Err(error) = returned {
                // Retain the actual failure BEFORE the after-custody check.
                self.cleanup.push(ShellActivationCleanupError { original: slot, error });
                self.latch(error); self.book.mark_interrupted();
            }
            boundary.settlement_boundary();
        }
        if self.book.settled() && !self.active() && !self.unknown { CloseOutcome::Settled }
        else { self.latch(Error::Unknown); CloseOutcome::Unknown }
    }
    fn run(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        self.admit(boundary)?;
        // All six actual identities/security/creation bindings are admitted
        // before ANY permission-control open or grant.
        let mutable: Vec<usize> = self.nodes.iter().enumerate().filter_map(|(i, n)|
            n.role.filter(|r| self.roles[*r].transition).map(|_| i)).collect();
        for index in mutable.iter().copied().rev() {
            self.recheck(boundary, index)?;
            self.close_producing(boundary, self.nodes[index].slot)?;
        }
        for index in mutable.iter().copied() { self.reserve_control(boundary, index)?; }
        for index in mutable.iter().copied().rev() { self.seal(boundary, index)?; }
        for index in 0..self.nodes.len() { self.recheck(boundary, index)?; }
        self.recheck_installer(boundary)?; self.recheck_location(boundary)?;
        need(self.settle_once(boundary) == CloseOutcome::Settled)?;
        self.after(boundary, Ok(()))?;
        self.complete = true; Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owner() -> Result<InputAcquisition> {
        InputAcquisition::new("C:\\fixed-input", &"a".repeat(64), &"b".repeat(64), &"c".repeat(64), [1; INPUTS])
    }
    fn proof() -> CopyProof {
        CopyProof { source_eof: true, flushed: true, writer_closed: true, source_closed: true,
            readback_eof: true, readback_closed: true }
    }
    // Pure frame DATA, never passed to an OS function. Tests which keep a frame
    // unresolved explicitly retire this never-entered fixture after assertions.
    fn mutation_fixture(phase: Phase, returned: Option<Returned>, count: u32) -> Held<Mutation> {
        ManuallyDrop::new(Box::pin(Mutation { effect: Effect::Write, phase: Cell::new(phase), returned: Cell::new(returned), slot: None,
            length_observation: Cell::new(ObservedScalarLength::Unobserved), path: Vec::new(),
            descriptor: UnsafeCell::new(Aligned([0; BUFFER])), attributes: S::SECURITY_ATTRIBUTES::default(),
            handle: null_mut(), output: null_mut(), data: vec![1, 2, 3], count: UnsafeCell::new(count),
            scalar: UnsafeCell::new(0), _pin: PhantomPinned }))
    }
    fn query_fixture() -> Held<Arena> {
        ManuallyDrop::new(Box::pin(Arena { call: Call::Mapping, token_length: 0,
            phase: Cell::new(Phase::Entered), returned: Cell::new(None), completion_refusal: Cell::new(None),
            input: Vec::new(), handle: null_mut(), output_handle: null_mut(), unicode: F::UNICODE_STRING::default(),
            attributes: OBJECT_ATTRIBUTES::default(), directory: false, file_purpose: FileReadPurpose::Content,
            bytes: UnsafeCell::new(Aligned([0; BUFFER])), count: UnsafeCell::new(0),
            iosb: UnsafeCell::new(IO::IO_STATUS_BLOCK { Anonymous: IO::IO_STATUS_BLOCK_0 { Status: F::STATUS_PENDING }, Information: 0 }),
            _pin: PhantomPinned }))
    }
    fn directory_fixture() -> Result<InputDirectory> {
        let raw = descriptor(FileKind::Directory, false, false)?;
        Ok(InputDirectory { slot: 0, parent: None, dos: "C:\\Program Files".to_owned(), components: vec!["Program Files".to_owned()],
            scope: AuthorityScope::AncestorOutsideVersion, facts: Facts {
                metadata: Metadata { identity: FileIdentity { volume_serial: 1, file_id: [1; 16] }, kind: FileKind::Directory,
                    attributes: FS::FILE_ATTRIBUTE_DIRECTORY, size: 0, allocation_size: 0, links: 1, creation: 1, write: 1, change: 1 },
                security: security::descriptor(&raw, FileKind::Directory, AuthorityScope::ImmutableVersion)?,
            }, mode: selected_mode("Mobile Release Kit"), entries: None, additions: Vec::new(),
            created: false, strict_source: false, write_subtree: false })
    }
    #[cfg(feature = "runtime-publication")]
    #[test]
    fn activation_private_roles_require_actual_exclusive_creation_data() -> Result<()> {
        let mut dir = directory_fixture()?;
        let mut creation = Creation { path: dir.dos.clone(), parent: 7, entered: true, returned: Some((1, 0)) };
        dir.parent = Some(7);
        assert!(shell_directory_transition(&dir, &dir.facts, std::slice::from_ref(&creation)).is_err());
        dir.created = true;
        assert_eq!(shell_directory_transition(&dir, &dir.facts, std::slice::from_ref(&creation)), Ok(true));
        creation.parent = 6;
        assert!(shell_directory_transition(&dir, &dir.facts, std::slice::from_ref(&creation)).is_err());
        creation.parent = 7; creation.returned = Some((0, F::ERROR_ALREADY_EXISTS));
        assert!(shell_directory_transition(&dir, &dir.facts, std::slice::from_ref(&creation)).is_err());
        creation.returned = Some((1, 0)); creation.entered = false;
        assert!(shell_directory_transition(&dir, &dir.facts, std::slice::from_ref(&creation)).is_err());
        dir.created = false;
        dir.facts.security = security::descriptor(&descriptor(FileKind::Directory, false, true)?,
            FileKind::Directory, AuthorityScope::ImmutableVersion)?;
        assert_eq!(shell_directory_transition(&dir, &dir.facts, &[]), Ok(false));
        Ok(())
    }
    #[cfg(feature = "runtime-publication")]
    struct BoundaryData { stop: Cell<bool>, work: Cell<usize>, cleanup: Cell<usize> }
    #[cfg(feature = "runtime-publication")]
    impl InstallerBoundary for BoundaryData {
        fn producing_boundary(&self) -> Result<()> {
            self.work.set(self.work.get() + 1);
            if self.stop.get() { Err(Error::State) } else { Ok(()) }
        }
        fn settlement_boundary(&self) { self.cleanup.set(self.cleanup.get() + 1); }
    }
    #[cfg(feature = "runtime-publication")]
    fn shell_state_data() -> Result<ShellActivation> {
        // Intentionally UNADMITTED state: never passed through a native call.
        // These copied token fields cannot authenticate any process/permission.
        let principal = directory_fixture()?.facts.security.owner;
        Ok(ShellActivation {
            book: NativeBook::new(), mutation: None, roles: Vec::new(), nodes: Vec::new(), location: None,
            expected_location: (String::new(), String::new(), Vec::new()),
            installer: Installer { identity: TokenIdentity { token_id: 0, authentication_id: 0, modified_id: 0, groups: 0, privileges: 0 },
                user: principal.clone(), integrity: principal, elevation_type: 0, groups: Vec::new(), privileges: Vec::new() },
            first: None, unknown: false, exposed: false, settling: false, complete: false, cleanup: Vec::new(),
        })
    }
    #[cfg(feature = "runtime-publication")]
    #[test]
    fn activation_gate_retains_errors_before_stop_and_still_settles_known_originals() -> Result<()> {
        let gate = BoundaryData { stop: Cell::new(true), work: Cell::new(0), cleanup: Cell::new(0) };
        let mut state = shell_state_data()?;
        assert_eq!(state.mutate(&gate, Effect::Seal, usize::MAX, "", &[]).err(), Some(Error::State));
        assert!(state.book.never_started() && state.mutation.is_none() && !state.exposed);

        let mut state = shell_state_data()?;
        let before = gate.work.get();
        assert_eq!(state.after::<()>(&gate, Err(Error::Unavailable)), Err(Error::Unavailable));
        assert_eq!(gate.work.get(), before); // returned Err precedes later STOP sample
        assert_eq!(state.first, Some(Error::Unavailable));
        let original = state.book.reserve(Kind::ThreadToken, None, "", String::new())?;
        // Reserved -> NoHandle: only this existing no-native path is exercised.
        assert_eq!(state.settle_once(&gate), CloseOutcome::Settled);
        assert_eq!(state.book.slot(original.index)?.state, SlotState::NoHandle);
        assert_eq!(gate.cleanup.get(), 2);
        assert_eq!(state.first, Some(Error::Unavailable));
        assert_eq!(state.settle_once(&gate), CloseOutcome::Settled);
        assert_eq!(gate.cleanup.get(), 2); // no retry of the original close
        assert!(!state.complete && !state.exposed);

        let mut state = shell_state_data()?;
        let reserved = state.book.reserve(Kind::ThreadToken, None, "", String::new())?;
        state.book.active = Some(query_fixture()); // never-entered fixture DATA
        state.latch(Error::Unknown);
        let calls = gate.cleanup.get();
        assert_eq!(state.settle_once(&gate), CloseOutcome::Unknown);
        assert_eq!(gate.cleanup.get(), calls);
        assert_eq!(state.book.slot(reserved.index)?.state, SlotState::Reserved);
        drop(ManuallyDrop::into_inner(state.book.active.take().ok_or(Error::State)?));
        assert_eq!(state.settle_once(&gate), CloseOutcome::Unknown);
        Ok(())
    }
    #[cfg(feature = "runtime-publication")]
    #[test]
    fn activation_rejects_incomplete_actual_owners_before_any_native_call() -> Result<()> {
        let acquisition = owner()?;
        let runtime = super::super::publication::Publication::new(&"a".repeat(64))?;
        assert!(super::super::publication::Publication::for_installer(&acquisition).is_err());
        assert!(acquisition.prerequisite_binding().is_err());
        assert!(super::super::installer_webview2::OfflineWebView2Owner::for_acquisition(&acquisition, [0; 32]).is_err());
        // The public activation call now REQUIRES an actual prerequisite owner.
        // Do not invent one to get past that type boundary in a DATA-only test.
        assert!(acquisition.prepare_shell_activation(&runtime).is_err());
        assert!(acquisition.activation.is_none());
        assert!(!acquisition.shell_activation_completed() && !acquisition.shell_activation_possibly_exposed());
        assert!(acquisition.source.never_started() && acquisition.output.never_started());
        // Existing activation state tests separately retain once-failure, STOP,
        // no-native Reserved settlement and absorbing Unknown coverage.
        Ok(())
    }

    #[test]
    fn acquisition_bounds_do_not_broaden_ordinary_or_publication() -> Result<()> {
        let ordinary = NativeBook::new(); let acquisition = owner()?;
        assert_eq!((MAX_ORIGINALS, MAX_LIVE, MAX_RECORDS, MAX_FILES), (48, 48, 8256, 2048));
        assert_eq!(MAX_FILE_BYTES, 512 * 1024 * 1024);
        assert_eq!((ordinary.records_limit, ordinary.total_bytes_limit), (8256, 1024 * 1024 * 1024));
        assert_eq!((acquisition.source.records_limit, acquisition.source.total_bytes_limit), (8256, ACQUISITION_TOTAL_BYTES));
        assert_eq!((acquisition.output.records_limit, acquisition.output.total_bytes_limit), (OUTPUT_RECORDS, ACQUISITION_TOTAL_BYTES));
        #[cfg(feature = "runtime-publication")]
        assert_eq!(super::super::publication::PUBLICATION_PAYLOADS, PUBLICATION_PAYLOADS);
        // Small test-only ceiling exercises actual reservation/retirement/latching
        // without thousands of allocations. Real fixed profiles are asserted above.
        let mut bounded = owner()?; bounded.output.records_limit = 2;
        for _ in 0..2 {
            let original = bounded.output.reserve(Kind::ThreadToken, None, "", String::new())?;
            bounded.output.close_index(original.index)?; // Reserved -> NoHandle; no native call.
        }
        assert_eq!(bounded.output.slots.len(), 2); // Retirement never resets record capacity.
        assert_eq!(bounded.step(|this| this.output.reserve(Kind::ThreadToken, None, "", String::new()).map(|_| ())), Err(Error::Bounds));
        assert_eq!(bounded.first_failure(), Some(Error::Bounds));
        assert_eq!(bounded.fail_and_settle_once(), CloseOutcome::Settled);
        assert!(!bounded.inputs_retained_and_settled());
        Ok(())
    }
    #[test]
    fn wrong_order_rejected_hashes_and_expiry_fail_before_any_native_entry() -> Result<()> {
        let mut rejected = owner()?;
        assert_eq!(rejected.create_once(false), Err(Error::Unsafe));
        assert_eq!(rejected.first_failure(), Some(Error::Unsafe));
        assert!(rejected.source.never_started() && rejected.output.never_started() && rejected.creations.is_empty());
        assert_eq!(rejected.admit_once().err(), Some(Error::State));
        assert_eq!(rejected.first_failure(), Some(Error::Unsafe));
        assert_eq!(rejected.fail_and_settle_once(), CloseOutcome::Settled);
        assert!(!rejected.inputs_retained_and_settled());
        for readback in [false, true] {
            let mut rejected = owner()?; rejected.stage = Stage::Copying;
            let result = if readback { rejected.finish_readback(false) } else { rejected.finish_copy(false) };
            assert_eq!(result, Err(Error::Unsafe));
            assert!(rejected.source.never_started() && rejected.output.never_started() && rejected.mutation.is_none());
        }
        let mut expired = owner()?; expired.end = Instant::now();
        assert_eq!(expired.admit_once().err(), Some(Error::Bounds));
        assert!(expired.expired && expired.source.never_started() && expired.output.never_started());
        assert_eq!(expired.fail_and_settle_once(), CloseOutcome::Settled);
        assert!(!expired.inputs_retained_and_settled());
        Ok(())
    }
    #[test]
    fn both_branch_absences_precede_the_first_mutation() -> Result<()> {
        for missing in 0..2 {
            let mut acquisition = owner()?; acquisition.stage = Stage::Controls;
            acquisition.absences[1 - missing] = Some(BranchAbsence { parent: usize::MAX, name: "not-an-open-authority".to_owned() });
            assert_eq!(acquisition.create_once(true), Err(Error::Unsafe));
            assert!(acquisition.creations.is_empty() && acquisition.mutation.is_none()
                && acquisition.source.never_started() && acquisition.output.never_started());
        }
        Ok(())
    }
    #[test]
    fn common_ancestors_require_both_real_book_bindings_and_same_closed_facts() -> Result<()> {
        let mut acquisition = owner()?;
        acquisition.source_location.device = Some("\\Device\\HarddiskVolume1".to_owned());
        acquisition.output_location = Some(KnownLocation { book: Arc::clone(&acquisition.output.identity),
            kind: LocationKind::ProgramFiles, path: "C:\\Program Files".to_owned(), drive: "C:".to_owned(),
            device: "\\Device\\HarddiskVolume1".to_owned(), components: vec!["Program Files".to_owned()] });
        assert!(acquisition.same_mapping());
        acquisition.source_location.book = Arc::new(());
        assert!(!acquisition.same_mapping()); // same strings do not route a wrong book
        acquisition.source_location.book = Arc::clone(&acquisition.source.identity);
        acquisition.output_location.as_mut().ok_or(Error::State)?.book = Arc::new(());
        assert!(!acquisition.same_mapping());
        let canonical = "\\Device\\HarddiskVolume1\\Program Files";
        let a = directory_fixture()?; let b = directory_fixture()?;
        assert!(readonly_common_ancestor(&a, &b, canonical, canonical, true));
        assert!(!readonly_common_ancestor(&a, &b, canonical, canonical, false));
        assert!(!readonly_common_ancestor(&a, &b, canonical, "different", true));
        for change in 0..6 {
            let mut b = directory_fixture()?;
            match change {
                0 => b.strict_source = true, 1 => b.write_subtree = true, 2 => b.created = true,
                3 => b.facts.metadata.identity.volume_serial += 1,
                4 => b.facts.metadata.change += 1,
                _ => b.facts.security = security::descriptor(&descriptor(FileKind::Directory, false, true)?,
                    FileKind::Directory, AuthorityScope::ImmutableVersion)?,
            }
            assert!(!readonly_common_ancestor(&a, &b, canonical, canonical, true));
        }
        Ok(())
    }
    #[test]
    fn either_original_query_or_mutation_blocks_all_cross_book_cleanup() -> Result<()> {
        for active in 0..3 {
            let mut acquisition = owner()?;
            let source = acquisition.source.reserve(Kind::ThreadToken, None, "", String::new())?.index;
            let output = acquisition.output.reserve(Kind::ThreadToken, None, "", String::new())?.index;
            match active {
                0 => acquisition.source.active = Some(query_fixture()),
                1 => acquisition.output.active = Some(query_fixture()),
                _ => acquisition.mutation = Some(mutation_fixture(Phase::Entered, None, u32::MAX)),
            }
            assert_eq!(acquisition.fail_and_settle_once(), CloseOutcome::Unknown);
            assert_eq!(acquisition.source.slot(source)?.state, SlotState::Reserved);
            assert_eq!(acquisition.output.slot(output)?.state, SlotState::Reserved);
            assert!(acquisition.cleanup_errors().is_empty());
            assert_eq!(acquisition.fail_and_settle_once(), CloseOutcome::Unknown);
            assert!(!acquisition.inputs_retained_and_settled());
            // No real native entry occurred; these are fixture-only allocations.
            if let Some(frame) = acquisition.source.active.take() { drop(ManuallyDrop::into_inner(frame)); }
            if let Some(frame) = acquisition.output.active.take() { drop(ManuallyDrop::into_inner(frame)); }
            if let Some(frame) = acquisition.mutation.take() { drop(ManuallyDrop::into_inner(frame)); }
            assert_eq!(acquisition.fail_and_settle_once(), CloseOutcome::Unknown); // never resumes retirement
        }
        Ok(())
    }
    #[test]
    fn definite_short_write_retires_before_error_and_counts_only_actual_return() -> Result<()> {
        let mut acquisition = owner()?;
        acquisition.mutation = Some(mutation_fixture(Phase::Returned, Some(Returned::Boolean(1, 0)), 2));
        let result = finish_registered_mutation(&mut acquisition.output, &mut acquisition.mutation,
            &mut acquisition.creations, Some(&mut acquisition.writes));
        assert_eq!(result.err(), Some(Error::Unsafe));
        assert!(acquisition.mutation.is_none() && !acquisition.output.is_unknown());
        assert_eq!(acquisition.byte_counts().confirmed_written, 2);
        assert!(!acquisition.byte_counts().write_count_unknown);
        acquisition.latch(Error::Unsafe);
        assert_eq!(acquisition.fail_and_settle_once(), CloseOutcome::Settled);
        assert_eq!(acquisition.first_failure(), Some(Error::Unsafe));
        assert!(!acquisition.inputs_retained_and_settled());

        let mut failed = owner()?;
        failed.mutation = Some(mutation_fixture(Phase::Returned, Some(Returned::Boolean(0, F::ERROR_ACCESS_DENIED)), u32::MAX));
        assert_eq!(finish_registered_mutation(&mut failed.output, &mut failed.mutation,
            &mut failed.creations, Some(&mut failed.writes)).err(), Some(Error::Unavailable));
        assert!(failed.mutation.is_none() && !failed.output.is_unknown());
        assert_eq!(failed.byte_counts().confirmed_written, 0); // Failed count is never observable.
        assert!(failed.byte_counts().write_count_unknown);
        failed.latch(Error::Unavailable);
        assert_eq!(failed.fail_and_settle_once(), CloseOutcome::Settled);
        assert!(!failed.inputs_retained_and_settled());

        let mut unknown = owner()?;
        unknown.mutation = Some(mutation_fixture(Phase::Returned, Some(Returned::Boolean(0, F::ERROR_IO_PENDING)), 2));
        assert_eq!(finish_registered_mutation(&mut unknown.output, &mut unknown.mutation,
            &mut unknown.creations, Some(&mut unknown.writes)).err(), Some(Error::Unknown));
        assert_eq!(unknown.byte_counts().confirmed_written, 0); // never read a pending output count
        assert!(unknown.byte_counts().write_count_unknown && unknown.mutation.is_some());
        assert_eq!(unknown.fail_and_settle_once(), CloseOutcome::Unknown);
        drop(ManuallyDrop::into_inner(unknown.mutation.take().ok_or(Error::State)?));
        Ok(())
    }
    #[test]
    fn returned_failed_close_does_not_block_independent_once_retirement() -> Result<()> {
        let mut acquisition = owner()?;
        let failed = acquisition.source.reserve(Kind::ThreadToken, None, "", String::new())?.index;
        let independent = acquisition.output.reserve(Kind::ThreadToken, None, "", String::new())?.index;
        // Existing NativeBook tests cover the native-return classifier. This
        // test starts from its closed DATA outcome, not an invented HANDLE.
        acquisition.source.slot_mut(failed)?.state = SlotState::Unknown;
        acquisition.source.mark_interrupted(); acquisition.latch(Error::Unavailable);
        assert_eq!(acquisition.fail_and_settle_once(), CloseOutcome::Unknown);
        assert_eq!(acquisition.source.slot(failed)?.state, SlotState::Unknown);
        assert_eq!(acquisition.output.slot(independent)?.state, SlotState::NoHandle);
        assert!(acquisition.output.settled() && !acquisition.source.settled());
        assert_eq!(acquisition.first_failure(), Some(Error::Unavailable));
        assert_eq!(acquisition.fail_and_settle_once(), CloseOutcome::Unknown);
        Ok(())
    }
    #[test]
    fn every_copy_edge_and_both_books_are_required_for_finality() -> Result<()> {
        for missing in 0..6 {
            let mut p = proof();
            match missing { 0 => p.source_eof = false, 1 => p.flushed = false,
                2 => p.writer_closed = false, 3 => p.source_closed = false,
                4 => p.readback_eof = false, _ => p.readback_closed = false }
            assert!(!p.complete());
        }
        let mut acquisition = owner()?;
        // Pure finality predicate only: no fixture is claimed to be native input.
        acquisition.stage = Stage::Complete; acquisition.proofs = vec![proof(); INPUTS]; acquisition.settlement_attempted = true;
        acquisition.source.retiring = true;
        assert!(!acquisition.inputs_retained_and_settled());
        acquisition.output.retiring = true;
        assert!(acquisition.inputs_retained_and_settled());
        acquisition.output.mark_interrupted();
        assert!(!acquisition.inputs_retained_and_settled());
        Ok(())
    }
}


#[cfg(feature = "installer-selection")]
impl InputAcquisition {
    pub(super) fn selection_binding(&self,
        prerequisite: &super::installer_webview2::OfflineWebView2Owner,
        runtime: &super::publication::Publication) -> Result<super::installer_selection::SelectionBinding> {
        // These are ACTUAL same-acquisition original owners. No caller-supplied
        // boolean, copied result, serialized identity or stale clock qualifies.
        prerequisite.require_complete_for(self)?;
        runtime.activation_mrk(self)?;
        need(self.shell_activation_completed())?;
        let activation = self.activation.as_ref().and_then(|a| a.as_ref().ok()).ok_or(Error::State)?;
        let mut activated = Vec::new();
        for role in 0..6 {
            let mut nodes = activation.nodes.iter().filter(|n| n.role == Some(role));
            let node = nodes.next().ok_or(Error::State)?;
            need(nodes.next().is_none() && activation.book.slot(node.current())?.state == SlotState::Closed)?;
            exact_security(&node.facts.security, node.facts.metadata.kind, role == 5, true)?;
            activated.push((node.path.clone(), node.facts.clone()));
        }
        let location = self.output_location.as_ref().ok_or(Error::State)?;
        Ok(super::installer_selection::SelectionBinding {
            image: self.image.clone(), runtime: self.digest.clone(), sizes: self.sizes,
            installer: self.installer.clone().ok_or(Error::State)?, program_files: location.path.clone(),
            acquisition: Arc::clone(&self.output.identity), activated,
        })
    }
}
