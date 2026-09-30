//! Private Windows launch-selection owner. No command/path executor or installer entry.
//! Each instance must live in the process-lifetime application owner before native
//! entry. The SAME original 570/600 controller boundary protects work and settlement.
//! A preview is DATA, not authority; apply re-admits its complete observation.
//! Neither Drop nor a saved recovery record proves native or controller finality.
use super::*;
use super::installer_primitives::*;
use super::installer_selection_data as data;
use super::installer_input_data::{InputLayout, PUBLICATION_PAYLOADS};
use super::{AdmissionRole as R, AdmissionOp as O};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::c_void;
use std::thread::{self, ThreadId};
use sha2::{Digest, Sha256};
use windows_sys::Win32::System::{Com as COM, Registry as REG};
use windows_sys::Win32::System::Com::StructuredStorage as STG;
use windows_sys::Wdk::System::Registry as NK;

pub use data::{Disposition as SelectionDisposition, ImageData as SelectionImageData,
    Mode as SelectionMode, Preview as SelectionPreview, Report as SelectionReport};

fn hash(raw: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(raw) {
        out.push(HEX[(byte >> 4) as usize] as char); out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}
fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char); out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}
fn bounded_field(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    need(value.len() <= data::RECORD_LIMIT
        && out.len().checked_add(value.len() + 4).is_some_and(|n| n <= data::RECORD_LIMIT))?;
    out.extend((value.len() as u32).to_le_bytes()); out.extend(value); Ok(())
}
fn facts_bytes(path: &str, facts: &Facts) -> Result<Vec<u8>> {
    // Exact typed observation, never parsed back into an Original or authority.
    let mut out = b"MRK_SELECTION_FILE_FACTS_V1\0".to_vec();
    bounded_field(&mut out, path.as_bytes())?;
    let m = &facts.metadata;
    bounded_field(&mut out, &m.identity.volume_serial.to_le_bytes())?;
    bounded_field(&mut out, &m.identity.file_id)?;
    out.push(if m.kind == FileKind::Directory { 1 } else { 2 });
    out.extend(m.attributes.to_le_bytes()); out.extend(m.links.to_le_bytes());
    out.extend(m.size.to_le_bytes()); out.extend(m.allocation_size.to_le_bytes());
    out.extend(m.creation.to_le_bytes()); out.extend(m.write.to_le_bytes()); out.extend(m.change.to_le_bytes());
    bounded_field(&mut out, facts.security.owner.bytes())?;
    out.extend(facts.security.control.to_le_bytes()); out.push(facts.security.revision);
    out.extend((facts.security.aces.len() as u32).to_le_bytes());
    for ace in &facts.security.aces {
        out.push(u8::from(ace.allow)); out.push(ace.flags); out.extend(ace.mask.to_le_bytes());
        bounded_field(&mut out, ace.sid.bytes())?;
    }
    Ok(out)
}


fn same_recorded_file(recorded: &[u8], original_path: &str, current: &Facts, renamed: bool) -> Result<()> {
    // Compare the SAME original file identity and every encoded attribute/
    // security fact. Only a recorded move may advance ChangeTime and change
    // location. Matching bytes or a familiar target alone is not ownership.
    let mut observed = facts_bytes(original_path, current)?;
    let change_at = b"MRK_SELECTION_FILE_FACTS_V1\0".len() + 4 + original_path.len()
        + (4 + 8) + (4 + 16) + 1 + 4 + 4 + 8 + 8 + 8 + 8;
    let prior = recorded.get(change_at..change_at + 8).ok_or(Error::Unsafe)?;
    let before = i64::from_le_bytes(prior.try_into().map_err(|_| Error::Unsafe)?);
    need(before > 0 && if renamed { current.metadata.change >= before } else { current.metadata.change == before })?;
    observed.get_mut(change_at..change_at + 8).ok_or(Error::State)?.copy_from_slice(prior);
    need(observed == recorded)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionOriginal { Files, ImageInputs, RuntimeImage, Registry, Transaction, ComReference, Apartment, Reservation,
    #[cfg(feature = "installer-selection-fixture")]
    FixtureRegistry,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectionCleanupError { pub original: SelectionOriginal, pub record: usize, pub error: Error }

macro_rules! checked_call {
    ($owner:ident, $boundary:ident, $expression:expr) => {{
        $owner.before($boundary)?;
        let returned = $expression;
        $owner.after($boundary, returned)?
    }};
}

struct FileNode {
    slot: usize, parent: Option<usize>, path: String, facts: Facts, scope: AuthorityScope,
    entries: Option<Vec<DirectoryEntry>>, created: bool, read_bytes: Option<Vec<u8>>, flushed: bool,
}
#[derive(Clone, Copy)]
enum FileEffect { Open { create: bool }, Directory, Write, Flush, Rewind, Rename }
impl FileEffect {
    fn tag(self) -> u8 { match self { Self::Open { create: false } => 1,
        Self::Open { create: true } => 2, Self::Directory => 3, Self::Write => 4,
        Self::Flush => 5, Self::Rewind => 6, Self::Rename => 7 } }
}
#[derive(Clone, Debug)]
struct FileReturn {
    operation: u8, slot: Option<usize>, value: i32, error: u32, count: Option<u32>,
    /// The logical fixed path is retained even when creation returned before
    /// admission, or a later STOP prevents constructing a FileNode.
    logical_path: String, destination: Option<String>,
}
#[derive(Clone)]
struct RenameTarget { node: usize, parent: usize, name: String, path: String, canonical: String }

struct FileFrame {
    effect: FileEffect, phase: Cell<Phase>, returned: Cell<Option<Returned>>, slot: Option<usize>,
    handle: F::HANDLE, output: *mut F::HANDLE, path: Vec<u16>, logical_path: String,
    descriptor: UnsafeCell<Aligned>, attributes: S::SECURITY_ATTRIBUTES,
    data: Vec<u8>, count: UnsafeCell<u32>, position: UnsafeCell<i64>,
    rename: UnsafeCell<Aligned>, rename_length: u32, rename_target: Option<RenameTarget>, _pin: PhantomPinned,
}
struct FileOwner {
    book: NativeBook, scalar: MutationSlot, effect: Option<Held<FileFrame>>,
    nodes: Vec<FileNode>, by_path: BTreeMap<String, usize>, locations: Vec<KnownLocation>,
    installer: Option<Installer>, first: Option<Error>, unknown: bool, settling: bool,
    writes: WriteAccounting, effects: Vec<FileReturn>, cleanup: Vec<SelectionCleanupError>, role: SelectionOriginal,
}
impl FileOwner {
    fn new(role: SelectionOriginal) -> Self {
        let profile = match role {
            SelectionOriginal::Files => RetainedSelectionBook::SelectionEntries,
            SelectionOriginal::ImageInputs => RetainedSelectionBook::Inputs54,
            SelectionOriginal::RuntimeImage => RetainedSelectionBook::Runtime47,
            _ => unreachable!("closed FileOwner role"),
        };
        Self { book: NativeBook::selection_retained(profile), scalar: None, effect: None,
            nodes: Vec::new(), by_path: BTreeMap::new(), locations: Vec::new(), installer: None,
            first: None, unknown: false, settling: false, writes: WriteAccounting::default(), effects: Vec::new(),
            cleanup: Vec::new(), role }
    }
    fn key(&self, slot: usize) -> Original { Original { book: Arc::clone(&self.book.identity), index: slot } }
    fn active(&self) -> bool { self.effect.is_some() || self.scalar.is_some() || self.book.active.is_some() }
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
        // Error-first: a later cooperative STOP never replaces a returned cause.
        let result = match returned { Err(first) => Err(first), Ok(value) => boundary.producing_boundary().map(|()| value) };
        if let Err(error) = result.as_ref() { self.latch(*error); } result
    }
    fn checked(&mut self, boundary: &dyn InstallerBoundary, slot: usize, scope: AuthorityScope) -> Result<Facts> {
        let key = self.key(slot);
        checked_call!(self, boundary, self.book.noninherited(slot));
        let metadata = checked_call!(self, boundary, self.book.metadata(&key));
        need(metadata.identity.volume_serial != 0 && metadata.links == 1
            && metadata.creation > 0 && metadata.write > 0 && metadata.change > 0)?;
        checked_call!(self, boundary, self.book.no_alternate_streams(&key));
        let security = checked_call!(self, boundary, self.book.security(&key, scope));
        need(checked_call!(self, boundary, self.book.metadata(&key)) == metadata)?;
        Ok(Facts { metadata, security })
    }
    fn recheck(&mut self, boundary: &dyn InstallerBoundary, index: usize) -> Result<()> {
        let n = self.nodes.get(index).ok_or(Error::State)?;
        let (slot, scope, old) = (n.slot, n.scope, n.facts.clone());
        need(self.checked(boundary, slot, scope)? == old)
    }
    fn entries(&mut self, boundary: &dyn InstallerBoundary, index: usize, selected: Option<&[String]>) -> Result<Vec<DirectoryEntry>> {
        self.recheck(boundary, index)?;
        if let Some(entries) = &self.nodes.get(index).ok_or(Error::State)?.entries { return Ok(entries.clone()); }
        let key = self.key(self.nodes[index].slot); let mut entries = Vec::new();
        loop {
            let batch = match selected {
                Some(names) => checked_call!(self, boundary, self.book.next_selected_entries(&key, names)),
                None => checked_call!(self, boundary, self.book.next_entries(&key)),
            };
            match batch {
                Some(rows) => { need(entries.len().saturating_add(rows.len()) <= MAX_ENTRIES)?; entries.extend(rows); },
                None => break,
            }
        }
        let n = &self.nodes[index];
        check_entry_frame(&entries, &n.facts.metadata, n.parent.map(|p| &self.nodes[p].facts.metadata))?;
        self.recheck(boundary, index)?;
        self.nodes[index].entries = Some(entries.clone()); Ok(entries)
    }
    fn add_node(&mut self, slot: usize, parent: Option<usize>, path: String, facts: Facts,
        scope: AuthorityScope, created: bool) -> Result<usize> {
        need(self.nodes.len() < 256 && !self.by_path.contains_key(&path)
            && !self.nodes.iter().any(|n| n.facts.metadata.identity == facts.metadata.identity))?;
        let index = self.nodes.len(); self.by_path.insert(path.clone(), index);
        self.nodes.push(FileNode { slot, parent, path, facts, scope, entries: None, created, read_bytes: None, flushed: false });
        Ok(index)
    }
    fn child_path(&self, parent: usize, name: &str) -> Result<String> {
        need(!name.is_empty() && !name.contains(['/', '\\', '\0', ':']) && name != "." && name != "..")?;
        let prefix = &self.nodes.get(parent).ok_or(Error::State)?.path;
        let path = format!("{}{}{}", prefix, if prefix.ends_with('\\') { "" } else { "\\" }, name);
        need(path.encode_utf16().count() < NAME_UNITS)?; Ok(path)
    }
    fn child(&mut self, boundary: &dyn InstallerBoundary, parent: usize, name: &str,
        kind: FileKind, scope: AuthorityScope, rename_original: bool) -> Result<Option<usize>> {
        let path = self.child_path(parent, name)?;
        if let Some(index) = self.by_path.get(&path).copied() {
            self.recheck(boundary, index)?; return Ok(Some(index));
        }
        let entries = self.entries(boundary, parent, None)?;
        let Some(row) = selected_entry(&entries, name)? else { return Ok(None); };
        need(row.kind == kind)?; self.recheck(boundary, parent)?;
        let parent_key = self.key(self.nodes[parent].slot);
        let original = if rename_original {
            need(kind == FileKind::File)?;
            let canonical = format!("{}\\{}", self.book.slot(parent_key.index)?.canonical.trim_end_matches('\\'), name);
            let key = checked_call!(self, boundary, self.book.reserve(Kind::File, Some(parent_key.index), name, canonical));
            self.file_effect(boundary, FileEffect::Open { create: false }, Some(key.index), &path, &[], Vec::new(), None)?;
            key
        } else { checked_call!(self, boundary, self.book.open_child(&parent_key, name, kind)) };
        let facts = self.checked(boundary, original.index, scope)?;
        match_entry(&row, &facts.metadata)?;
        let index = self.add_node(original.index, Some(parent), path, facts, scope, false)?;
        self.recheck(boundary, parent)?; Ok(Some(index))
    }
    fn discover(&mut self, boundary: &dyn InstallerBoundary, kinds: &[LocationKind]) -> Result<()> {
        need(self.locations.is_empty() && self.nodes.is_empty())?;
        for kind in kinds {
            let location = checked_call!(self, boundary, self.book.location(*kind));
            need(location.components.len() <= super::installer_input_data::SOURCE_COMPONENTS)?; self.locations.push(location);
        }
        Ok(())
    }
    fn root(&mut self, boundary: &dyn InstallerBoundary, location_index: usize) -> Result<usize> {
        let location = self.locations.get(location_index).ok_or(Error::State)?;
        let drive = location.drive.clone(); let device = location.device.clone();
        let components = location.components.clone();
        let root_path = format!("{}\\", drive);
        let root = if let Some(index) = self.by_path.get(&root_path).copied() {
            need(self.nodes[index].facts.metadata.kind == FileKind::Directory)?;
            self.recheck(boundary, index)?; index
        } else {
            let native = format!("{}\\", device);
            let original = checked_call!(self, boundary, self.book.reserve(Kind::Directory, None, &native, native.clone()));
            checked_call!(self, boundary, self.book.call(Call::Open(original.index), null_mut(), Vec::new()));
            checked_call!(self, boundary, self.book.local_ntfs(&original));
            let facts = self.checked(boundary, original.index, AuthorityScope::AncestorOutsideVersion)?;
            self.add_node(original.index, None, root_path, facts, AuthorityScope::AncestorOutsideVersion, false)?
        };
        let mut parent = root;
        for name in components {
            // OS ancestors use a selected-name census, not a strict census of
            // unrelated software. All desired root chains are discovered first.
            let names = self.known_os_children(&self.nodes[parent].path);
            self.entries(boundary, parent, Some(&names))?;
            parent = self.child(boundary, parent, &name, FileKind::Directory,
                AuthorityScope::AncestorOutsideVersion, false)?.ok_or(Error::Unsafe)?;
        }
        Ok(parent)
    }
    fn known_os_children(&self, parent: &str) -> Vec<String> {
        let mut result = BTreeSet::new();
        for location in &self.locations {
            let prefix = format!("{}\\", location.drive); let mut path = prefix;
            for component in &location.components {
                if path == parent { result.insert(component.clone()); }
                if !path.ends_with('\\') { path.push('\\'); } path.push_str(component);
            }
        }
        result.into_iter().collect()
    }
    fn recheck_locations(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        for index in 0..self.locations.len() {
            self.before(boundary)?;
            let result = self.book.recheck_location(&self.locations[index]);
            self.after(boundary, result)?;
        }
        Ok(())
    }
    fn close_producing(&mut self, boundary: &dyn InstallerBoundary, slot: usize) -> Result<()> {
        self.before(boundary)?; let returned = self.book.close_index(slot);
        if let Err(error) = returned { self.cleanup.push(SelectionCleanupError { original: self.role, record: slot, error }); }
        self.after(boundary, returned)
    }
    fn read_file(&mut self, boundary: &dyn InstallerBoundary, index: usize, size: u64,
        expected: Option<&str>, keep_bytes: bool) -> Result<Vec<u8>> {
        need(size > 0 && size <= MAX_FILE_BYTES && (!keep_bytes || size <= 1024 * 1024))?;
        self.recheck(boundary, index)?;
        let n = &self.nodes[index]; need(n.facts.metadata.kind == FileKind::File && n.facts.metadata.size == size)?;
        let key = self.key(n.slot); let mut bytes = Vec::new(); let mut hasher = Sha256::new(); let mut count = 0u64;
        loop {
            let part = checked_call!(self, boundary, self.book.read_next(&key, BUFFER));
            if part.is_empty() { break; }
            count = count.checked_add(part.len() as u64).ok_or(Error::Bounds)?; need(count <= size)?;
            hasher.update(&part); if keep_bytes { bytes.extend(part); }
        }
        need(count == size)?;
        let observed = hex_digest(&hasher.finalize());
        if let Some(expected) = expected { need(observed == expected)?; }
        self.recheck(boundary, index)?;
        if keep_bytes { self.nodes[index].read_bytes = Some(bytes.clone()); }
        Ok(bytes)
    }
    fn descriptor_of(&self, index: usize) -> Result<Vec<u8>> {
        let n = self.nodes.get(index).ok_or(Error::State)?; facts_bytes(&n.path, &n.facts)
    }
    fn known_closed(&self) -> bool {
        self.settling && !self.unknown && !self.active() && self.book.settled() && self.cleanup.is_empty()
    }
    fn settle_once(&mut self, boundary: &dyn InstallerBoundary) {
        if self.settling { return; } self.settling = true;
        if self.active() || self.unknown || self.book.is_unknown() { self.unknown = true; return; }
        self.book.retiring = true;
        for index in (0..self.book.slots.len()).rev() {
            if matches!(self.book.slots[index].state, SlotState::NoHandle | SlotState::Closed) { continue; }
            boundary.settlement_boundary();
            let returned = self.book.close_index(index);
            if let Err(error) = returned {
                self.unknown = true; self.cleanup.push(SelectionCleanupError { original: self.role, record: index, error });
            }
            boundary.settlement_boundary();
        }
        if self.unknown { self.book.unknown = true; }
    }
}

impl FileOwner {
    fn token_scalar(&mut self, boundary: &dyn InstallerBoundary, index: usize, class: S::TOKEN_INFORMATION_CLASS) -> Result<u32> {
        let value = checked_call!(self, boundary, self.book.token(index, class));
        let trace = self.book.admission.at(O::TokenData);
        trace.need(value.count_in(trace)? == 4, C::ScalarWidth)?;
        decode::Observed::new(trace).u32_at(value.bytes_in(4, trace)?, 0)
    }
    fn scalar_boolean(&mut self, boundary: &dyn InstallerBoundary, index: usize, class: S::TOKEN_INFORMATION_CLASS) -> Result<u32> {
        self.before(boundary)?;
        let mut creations = [];
        let entered = enter_registered_mutation(&mut self.book, &mut self.scalar, &mut creations,
            Effect::Scalar(class), Some(index), "", &[], Vec::new());
        if let Err(error) = entered { self.latch(error); return Err(error); }
        let returned = finish_registered_mutation(&mut self.book, &mut self.scalar, &mut creations, None)
            .and_then(|c| c.scalar()).and_then(scalar_value);
        self.after(boundary, returned)
    }
    fn collect_installer(&mut self, boundary: &dyn InstallerBoundary, index: usize) -> Result<Installer> {
        checked_call!(self, boundary, self.book.absent_thread_token());
        let before = checked_call!(self, boundary, self.book.token(index, S::TokenStatistics));
        let trace = self.book.admission.at(O::TokenData);
        let initial = security::Observed::new(trace).statistics(before.bytes_in(before.count_in(trace)?, trace)?)?;
        let token_type = self.token_scalar(boundary, index, S::TokenType)?;
        let elevated = self.token_scalar(boundary, index, S::TokenElevation)?;
        let elevation_type = self.token_scalar(boundary, index, S::TokenElevationType)?;
        let ui_access = self.token_scalar(boundary, index, S::TokenUIAccess)?;
        let virtualization = self.token_scalar(boundary, index, S::TokenVirtualizationEnabled)?;
        let restricted = self.scalar_boolean(boundary, index, S::TokenHasRestrictions)?;
        let app_container = self.scalar_boolean(boundary, index, S::TokenIsAppContainer)?;
        let user = checked_call!(self, boundary, self.book.token(index, S::TokenUser));
        let integrity = checked_call!(self, boundary, self.book.token(index, S::TokenIntegrityLevel));
        let groups = checked_call!(self, boundary, self.book.token(index, S::TokenGroups));
        let privileges = checked_call!(self, boundary, self.book.token(index, S::TokenPrivileges));
        let trace = self.book.admission.at(O::InstallerPolicy).role(R::Installer);
        let d = self.book.admission.at(O::TokenData);
        let u = d.role(R::User); let i = d.role(R::Integrity); let g = d.role(R::Groups); let p = d.role(R::Privileges);
        let result = InstallerData(trace).installer_facts(initial, token_type, elevated, elevation_type,
            ui_access, virtualization, restricted, app_container,
            user.bytes_in(user.count_in(u)?, u)?, integrity.bytes_in(integrity.count_in(i)?, i)?,
            groups.bytes_in(groups.count_in(g)?, g)?, privileges.bytes_in(privileges.count_in(p)?, p)?)?;
        let after = checked_call!(self, boundary, self.book.token(index, S::TokenStatistics));
        let trace = self.book.admission.at(O::TokenData);
        need(security::Observed::new(trace).statistics(after.bytes_in(after.count_in(trace)?, trace)?)? == initial)?;
        checked_call!(self, boundary, self.book.absent_thread_token()); Ok(result)
    }
    fn token(&mut self, boundary: &dyn InstallerBoundary) -> Result<usize> {
        let original = checked_call!(self, boundary, self.book.reserve(Kind::ProcessToken, None, "", String::new()));
        let returned = checked_call!(self, boundary, self.book.call(Call::ProcessToken(original.index), null_mut(), Vec::new()));
        need(matches!(returned.arena.returned()?, Returned::Boolean(v, 0) if v != 0))?;
        checked_call!(self, boundary, self.book.noninherited(original.index)); Ok(original.index)
    }
    fn admit_installer(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        need(self.installer.is_none())?;
        let arch = checked_call!(self, boundary, self.book.call(Call::Architecture, null_mut(), Vec::new()));
        let trace = self.book.admission.at(O::Architecture);
        let d = decode::Observed::new(trace);
        need(d.u16_at(arch.bytes_in(4, trace)?, 0)? == SI::IMAGE_FILE_MACHINE_UNKNOWN
            && d.u16_at(arch.bytes_in(4, trace)?, 2)? == SI::IMAGE_FILE_MACHINE_AMD64)?;
        let original = self.token(boundary)?;
        self.book.process_token = Some(original);
        self.installer = Some(self.collect_installer(boundary, original)?);
        self.recheck_installer(boundary)
    }
    fn recheck_installer(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        let expected = self.installer.clone().ok_or(Error::State)?;
        let original = self.book.process_token.ok_or(Error::State)?;
        need(self.collect_installer(boundary, original)? == expected)?;
        let current = self.token(boundary)?;
        need(self.collect_installer(boundary, current)? == expected)?;
        self.close_producing(boundary, current)?;
        checked_call!(self, boundary, self.book.absent_thread_token()); Ok(())
    }

    fn file_effect(&mut self, boundary: &dyn InstallerBoundary, effect: FileEffect, slot: Option<usize>,
        path: &str, raw_descriptor: &[u8], bytes: Vec<u8>, rename_to: Option<(usize, &str)>) -> Result<()> {
        self.before(boundary)?;
        need(bytes.len() <= BUFFER && raw_descriptor.len() <= BUFFER && self.effects.len() < 1024)?;
        let opens = matches!(effect, FileEffect::Open { .. });
        let handle = if opens || matches!(effect, FileEffect::Directory) { null_mut() }
            else { self.book.handle(slot.ok_or(Error::State)?)? };
        let logical_path = if opens || matches!(effect, FileEffect::Directory) { path.to_owned() }
            else { self.nodes.iter().find(|n| Some(n.slot) == slot).map(|n| n.path.clone()).ok_or(Error::State)? };
        let path = if opens || matches!(effect, FileEffect::Directory) {
            need(data::native_dos_path(path))?; wide(&format!("\\\\?\\{path}"))
        } else { Vec::new() };
        let mut frame = Box::pin(FileFrame { effect, phase: Cell::new(Phase::Prepared), returned: Cell::new(None),
            slot, handle, output: null_mut(), path, logical_path, descriptor: UnsafeCell::new(Aligned([0; BUFFER])),
            attributes: S::SECURITY_ATTRIBUTES::default(), data: bytes, count: UnsafeCell::new(u32::MAX),
            position: UnsafeCell::new(-1), rename: UnsafeCell::new(Aligned([0; BUFFER])), rename_length: 0, rename_target: None, _pin: PhantomPinned });
        // SAFETY: exclusive pinned setup, before any native pointer escapes.
        let setup = unsafe { frame.as_mut().get_unchecked_mut() };
        if !raw_descriptor.is_empty() {
            unsafe { (&mut *setup.descriptor.get()).0[..raw_descriptor.len()].copy_from_slice(raw_descriptor); }
            setup.attributes.lpSecurityDescriptor = setup.descriptor.get().cast();
        }
        setup.attributes.nLength = size_of::<S::SECURITY_ATTRIBUTES>() as u32;
        setup.attributes.bInheritHandle = 0;
        if opens {
            let original = self.book.slot(slot.ok_or(Error::State)?)?;
            need(original.state == SlotState::Reserved)?; setup.output = original.output.get();
        }
        if matches!(effect, FileEffect::Rename) {
            let (parent, leaf) = rename_to.ok_or(Error::State)?;
            need(!leaf.is_empty() && !leaf.contains(['\\', '/', '\0', ':']) && leaf != "." && leaf != "..")?;
            let name: Vec<u16> = leaf.encode_utf16().collect();
            let offset = offset_of!(FS::FILE_RENAME_INFO, FileName);
            let extent = offset.checked_add(name.len() * 2).ok_or(Error::Bounds)?;
            need(extent <= BUFFER)?;
            let parent_handle = self.book.handle(self.nodes.get(parent).ok_or(Error::State)?.slot)?;
            let name_length = u32::try_from(name.len() * 2).map_err(|_| Error::Bounds)?;
            // The arena is zeroed, including ReplaceIfExists=false and all SDK
            // padding. Never copy possibly uninitialized Rust struct padding.
            unsafe {
                let destination = (*setup.rename.get()).0.as_mut_ptr();
                std::ptr::write_unaligned(destination.add(offset_of!(FS::FILE_RENAME_INFO, RootDirectory)).cast::<F::HANDLE>(), parent_handle);
                std::ptr::write_unaligned(destination.add(offset_of!(FS::FILE_RENAME_INFO, FileNameLength)).cast::<u32>(), name_length);
                std::ptr::copy_nonoverlapping(name.as_ptr().cast::<u8>(), destination.add(offset), name.len() * 2);
            }
            setup.rename_length = extent as u32;
            let node = self.nodes.iter().position(|n| Some(n.slot) == slot).ok_or(Error::State)?;
            let path = self.child_path(parent, leaf)?;
            need(!self.by_path.contains_key(&path))?;
            let canonical = format!("{}\\{}", self.book.slot(self.nodes[parent].slot)?.canonical.trim_end_matches('\\'), leaf);
            setup.rename_target = Some(RenameTarget { node, parent, name: leaf.to_owned(), path, canonical });
        } else { need(rename_to.is_none())?; }
        self.effect = Some(ManuallyDrop::new(frame));
        if opens { self.book.slot_mut(slot.ok_or(Error::State)?)?.state = SlotState::Acquiring; }
        self.book.started = true;
        let frame = self.effect.as_ref().ok_or(Error::Unknown)?.as_ref().get_ref();
        frame.phase.set(Phase::Entered);
        // Every argument/output is in the registered pinned original. Only
        // synchronous documented calls; record actual return immediately.
        let returned = unsafe {
            match effect {
                FileEffect::Open { create } => {
                    *frame.output = FS::CreateFileW(frame.path.as_ptr(),
                        F::GENERIC_READ | FS::READ_CONTROL | FS::FILE_READ_ATTRIBUTES | FS::DELETE
                            | if create { F::GENERIC_WRITE } else { 0 },
                        FS::FILE_SHARE_READ, &frame.attributes,
                        if create { FS::CREATE_NEW } else { FS::OPEN_EXISTING },
                        FS::FILE_ATTRIBUTE_NORMAL | FS::FILE_FLAG_OPEN_REPARSE_POINT, null_mut());
                    if valid_handle(*frame.output) { Returned::Boolean(1, 0) }
                    else { Returned::Boolean(0, F::GetLastError()) }
                },
                FileEffect::Directory => boolean(FS::CreateDirectoryW(frame.path.as_ptr(), &frame.attributes)),
                FileEffect::Write => boolean(FS::WriteFile(frame.handle, frame.data.as_ptr(), frame.data.len() as u32, frame.count.get(), null_mut())),
                FileEffect::Flush => boolean(FS::FlushFileBuffers(frame.handle)),
                FileEffect::Rewind => boolean(FS::SetFilePointerEx(frame.handle, 0, frame.position.get(), FS::FILE_BEGIN)),
                FileEffect::Rename => boolean(FS::SetFileInformationByHandle(frame.handle, FS::FileRenameInfo,
                    frame.rename.get().cast(), frame.rename_length)),
            }
        };
        frame.returned.set(Some(returned)); frame.phase.set(Phase::Returned);
        let completed = self.finish_file_effect();
        #[cfg(feature = "installer-selection-fixture")]
        if completed.is_ok() && matches!(effect, FileEffect::Rename) {
            // Only observe a real successful native return, after custody and
            // output accounting were updated, before the next producing check.
            use super::installer_selection_fixture_data::SelectionFixturePoint as Point;
            let destination = self.effects.last().and_then(|r| r.destination.as_deref());
            if destination.is_some_and(|p| p.ends_with(r"\previous.lnk")) {
                boundary.selection_fixture_return_boundary(Point::OldMoveReturned);
            } else if destination.is_some_and(|p| p.ends_with(r"\Mobile Release Kit.lnk")) {
                boundary.selection_fixture_return_boundary(Point::NewMoveReturned);
            }
        }
        self.after(boundary, completed)
    }
    fn finish_file_effect(&mut self) -> Result<()> {
        let frame = self.effect.as_ref().ok_or(Error::Unknown)?.as_ref().get_ref();
        if frame.phase.get() != Phase::Returned { self.unknown = true; return Err(Error::Unknown); }
        let (ok, error) = match frame.returned.get() { Some(Returned::Boolean(ok, error)) => (ok, error), _ => { self.unknown = true; return Err(Error::Unknown); } };
        let effect = frame.effect; let slot = frame.slot;
        let rename = frame.rename_target.clone();
        // Retain actual native outcome BEFORE later classification or STOP.
        self.effects.push(FileReturn { operation: effect.tag(), slot, value: ok, error,
            count: matches!(effect, FileEffect::Write).then(|| unsafe { *frame.count.get() }),
            logical_path: frame.logical_path.clone(), destination: rename.as_ref().map(|r| r.path.clone()) });
        let mut result = mutation_return(ok, error);
        if result == Err(Error::Unknown) { self.unknown = true; return result; }
        if matches!(effect, FileEffect::Open { .. }) {
            let index = slot.ok_or(Error::Unknown)?;
            let original = self.book.slot(index)?;
            let handle = unsafe { *original.output.get() };
            if original.state != SlotState::Acquiring
                || (ok != 0 && (!valid_handle(handle) || self.book.duplicate_live(index, handle)))
                || (ok == 0 && handle != F::INVALID_HANDLE_VALUE) {
                self.unknown = true; return Err(Error::Unknown);
            }
            self.book.slot_mut(index)?.state = if ok != 0 { SlotState::Owned } else { SlotState::NoHandle };
        }
        let frame = self.effect.as_ref().ok_or(Error::Unknown)?.as_ref().get_ref();
        if matches!(effect, FileEffect::Write) {
            if result.is_ok() {
                let count = unsafe { *frame.count.get() }; self.writes.observe(count, frame.data.len());
                result = write_return(ok, error, count, frame.data.len());
            } else { self.writes.unknown_count = true; }
        } else if matches!(effect, FileEffect::Rewind) && result.is_ok() {
            // This is the ORIGINAL new writer's first readback, never a reset of
            // an already-read EOF/failed read or a second reader capability.
            let original = self.book.slot(slot.ok_or(Error::State)?)?;
            need(original.read_bytes == 0 && !original.read_ended)?;
            result = need(unsafe { *frame.position.get() } == 0);
        }
        if result == Err(Error::Unknown) { self.unknown = true; return result; }
        frame.phase.set(Phase::Complete);
        let held = self.effect.take().ok_or(Error::Unknown)?;
        drop(ManuallyDrop::into_inner(held));
        if result.is_ok() {
            if matches!(effect, FileEffect::Flush) {
                let node = self.nodes.iter_mut().find(|n| Some(n.slot) == slot).ok_or(Error::State)?;
                node.flushed = true;
            }
            if let Some(target) = rename {
                // Actual successful rename transfers expected custody BEFORE a
                // post-return STOP can short-circuit metadata/readback checks.
                let node = target.node; let parent = self.nodes[node].parent.ok_or(Error::State)?;
                let old_path = self.nodes[node].path.clone();
                let destination_slot = self.nodes[target.parent].slot;
                let original = self.book.slot_mut(slot.ok_or(Error::State)?)?;
                original.canonical = target.canonical; original.parent = Some(destination_slot);
                original.name = wide(&target.name);
                self.by_path.remove(&old_path); self.by_path.insert(target.path.clone(), node);
                self.nodes[node].path = target.path; self.nodes[node].parent = Some(target.parent);
                if let Some(rows) = self.nodes[parent].entries.as_mut() {
                    let leaf = old_path.rsplit('\\').next().ok_or(Error::State)?;
                    rows.retain(|row| row.name != leaf);
                }
                self.add_created_entry(target.parent, node, &target.name)?;
            }
        }
        result
    }
    fn rename_observation(&self, slot: usize) -> (bool, Option<(i32, u32)>) {
        if let Some(returned) = self.effects.iter().rev().find(|r|
            r.operation == FileEffect::Rename.tag() && r.slot == Some(slot)) {
            return (true, Some((returned.value, returned.error)));
        }
        let entered = self.effect.as_ref().is_some_and(|held| {
            let original = held.as_ref().get_ref();
            matches!(original.effect, FileEffect::Rename) && original.slot == Some(slot)
                && matches!(original.phase.get(), Phase::Entered | Phase::Returned)
        });
        (entered, None)
    }
    fn refresh_after_child(&mut self, boundary: &dyn InstallerBoundary, parent: usize) -> Result<()> {
        let n = &self.nodes[parent]; let (slot, scope, previous) = (n.slot, n.scope, n.facts.clone());
        let current = self.checked(boundary, slot, scope)?;
        need(child_transition(&previous.metadata, &current.metadata) && current.security == previous.security)?;
        self.nodes[parent].facts = current; Ok(())
    }
    fn create_directory(&mut self, boundary: &dyn InstallerBoundary, parent: usize, name: &str) -> Result<usize> {
        let path = self.child_path(parent, name)?;
        need(selected_entry(&self.entries(boundary, parent, None)?, name)?.is_none())?;
        self.recheck(boundary, parent)?;
        let descriptor = descriptor(FileKind::Directory, false, false)?;
        self.file_effect(boundary, FileEffect::Directory, None, &path, &descriptor, Vec::new(), None)?;
        self.refresh_after_child(boundary, parent)?;
        let p = self.key(self.nodes[parent].slot);
        let original = checked_call!(self, boundary, self.book.open_child(&p, name, FileKind::Directory));
        let facts = self.checked(boundary, original.index, AuthorityScope::ImmutableVersion)?;
        exact_security(&facts.security, FileKind::Directory, false, false)?;
        let index = self.add_node(original.index, Some(parent), path, facts, AuthorityScope::ImmutableVersion, true)?;
        self.add_created_entry(parent, index, name)?; Ok(index)
    }
    fn add_created_entry(&mut self, parent: usize, index: usize, name: &str) -> Result<()> {
        let m = &self.nodes[index].facts.metadata;
        let row = DirectoryEntry { name: name.to_owned(), file_id: m.identity.file_id, kind: m.kind, attributes: m.attributes };
        let entries = self.nodes[parent].entries.as_mut().ok_or(Error::State)?;
        need(selected_entry(entries, name)?.is_none())?; entries.push(row); Ok(())
    }
    fn write_new_file(&mut self, boundary: &dyn InstallerBoundary, parent: usize, name: &str,
        bytes: &[u8], public: bool, report: &mut SelectionReport, close: bool) -> Result<usize> {
        need(!bytes.is_empty() && bytes.len() <= data::RECORD_LIMIT)?;
        need(selected_entry(&self.entries(boundary, parent, None)?, name)?.is_none())?;
        self.recheck(boundary, parent)?;
        let path = self.child_path(parent, name)?;
        let canonical = format!("{}\\{}", self.book.slot(self.nodes[parent].slot)?.canonical.trim_end_matches('\\'), name);
        let original = checked_call!(self, boundary, self.book.reserve(Kind::File, Some(self.nodes[parent].slot), name, canonical));
        let descriptor = descriptor(FileKind::File, false, public)?;
        self.file_effect(boundary, FileEffect::Open { create: true }, Some(original.index), &path, &descriptor, Vec::new(), None)?;
        self.refresh_after_child(boundary, parent)?;
        let before = self.checked(boundary, original.index, AuthorityScope::ImmutableVersion)?;
        exact_security(&before.security, FileKind::File, false, public)?; need(before.metadata.size == 0)?;
        let index = self.add_node(original.index, Some(parent), path, before.clone(), AuthorityScope::ImmutableVersion, true)?;
        self.add_created_entry(parent, index, name)?;
        // Charge every possibly persisted byte BEFORE entering its native write.
        // A short/failed write never recovers that budget or restarts the write.
        for part in bytes.chunks(BUFFER) {
            need(report.charge(part.len()))?;
            let previous = self.writes.confirmed_bytes;
            let result = self.file_effect(boundary, FileEffect::Write, Some(original.index), "", &[], part.to_vec(), None);
            report.output_bytes_confirmed = report.output_bytes_confirmed.checked_add(self.writes.confirmed_bytes.saturating_sub(previous)).ok_or(Error::Bounds)?;
            result?;
        }
        self.file_effect(boundary, FileEffect::Flush, Some(original.index), "", &[], Vec::new(), None)?;
        let written = self.checked(boundary, original.index, AuthorityScope::ImmutableVersion)?;
        need(write_transition(&before.metadata, &written.metadata, bytes.len() as u64) && written.security == before.security)?;
        self.nodes[index].facts = written;
        self.file_effect(boundary, FileEffect::Rewind, Some(original.index), "", &[], Vec::new(), None)?;
        let actual = self.read_file(boundary, index, bytes.len() as u64, Some(&hash(bytes)), true)?;
        need(actual == bytes)?;
        if close { self.close_producing(boundary, original.index)?; }
        Ok(index)
    }
    fn rename_original(&mut self, boundary: &dyn InstallerBoundary, index: usize, destination: usize, name: &str) -> Result<()> {
        let n = &self.nodes[index]; let parent = n.parent.ok_or(Error::State)?;
        let slot = n.slot; let previous = n.facts.clone();
        need(n.facts.metadata.kind == FileKind::File && self.nodes[destination].facts.metadata.kind == FileKind::Directory)?;
        need(previous.metadata.identity.volume_serial == self.nodes[destination].facts.metadata.identity.volume_serial)?;
        let new_path = self.child_path(destination, name)?;
        need(selected_entry(&self.entries(boundary, destination, None)?, name)?.is_none()
            && !self.by_path.contains_key(&new_path))?;
        self.recheck(boundary, parent)?; self.recheck(boundary, destination)?; self.recheck(boundary, index)?;
        self.file_effect(boundary, FileEffect::Rename, Some(slot), "", &[], Vec::new(), Some((destination, name)))?;
        // The successful native return already transferred expected name/custody.
        // These further observations can fail honestly without losing that fact.
        need(self.nodes[index].path == new_path && self.nodes[index].parent == Some(destination))?;
        self.refresh_after_child(boundary, parent)?;
        if parent != destination { self.refresh_after_child(boundary, destination)?; }
        let current = self.checked(boundary, slot, AuthorityScope::ImmutableVersion)?;
        need(same_object(&previous.metadata, &current.metadata)
            && previous.metadata.size == current.metadata.size
            && previous.metadata.allocation_size == current.metadata.allocation_size
            && previous.metadata.write == current.metadata.write
            && current.metadata.change >= previous.metadata.change
            && current.security == previous.security)?;
        self.nodes[index].facts = current;
        self.recheck(boundary, index)
    }
}

// The registry and kernel reservation use exact, different rights. Reuse the
// existing structural SD parser; never reinterpret KEY_READ as FILE rights.
fn selection_descriptor(purpose: security::SelectionDescriptor) -> Result<Vec<u8>> {
    let owner = admins();
    let entries = match purpose {
        security::SelectionDescriptor::Registration => vec![(system(), REG::KEY_ALL_ACCESS), (owner.clone(), REG::KEY_ALL_ACCESS), (users(), REG::KEY_READ)],
        security::SelectionDescriptor::Reservation => vec![(system(), T::MUTEX_ALL_ACCESS), (owner.clone(), T::MUTEX_ALL_ACCESS)],
        security::SelectionDescriptor::RegistrationParent => return Err(Error::State), // never author the OS parent
    };
    let mut acl = vec![0u8; size_of::<S::ACL>()]; acl[0] = 2;
    for (principal, mask) in &entries {
        acl.extend([0, 0]); acl.extend(((8 + principal.len()) as u16).to_le_bytes());
        acl.extend(mask.to_le_bytes()); acl.extend(principal);
    }
    let length = acl.len() as u16; acl[2..4].copy_from_slice(&length.to_le_bytes());
    acl[4..6].copy_from_slice(&(entries.len() as u16).to_le_bytes());
    let mut raw = vec![0u8; 20]; raw[0] = 1;
    raw[2..4].copy_from_slice(&(S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT | S::SE_DACL_PROTECTED).to_le_bytes());
    raw[4..8].copy_from_slice(&20u32.to_le_bytes()); raw[8..12].copy_from_slice(&20u32.to_le_bytes());
    raw[16..20].copy_from_slice(&((20 + owner.len()) as u32).to_le_bytes());
    raw.extend(owner); raw.extend(acl);
    security::Observed::new(Refusal::none()).selection_descriptor(&raw, purpose)?; Ok(raw)
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct RegistrySnapshot { present: bool, values: data::Registration, security: Vec<u8>, write: u64 }
impl RegistrySnapshot {
    fn absent() -> Self { Self { present: false, values: data::Registration::new(), security: Vec::new(), write: 0 } }
    fn encoded(&self) -> Result<Vec<u8>> {
        let mut out = vec![u8::from(self.present)]; out.extend(self.write.to_le_bytes());
        bounded_field(&mut out, &self.security)?;
        for (name, value) in &self.values {
            bounded_field(&mut out, name.as_bytes())?; out.extend(value.kind.to_le_bytes());
            bounded_field(&mut out, &value.bytes)?;
        }
        Ok(out)
    }
}
#[derive(Clone, Copy)]
enum KeyRole { Before = 0, Staged = 1, After = 2, Parent = 3, ParentStaged = 4, ParentAfter = 5 }
const REGISTRATION_PARENT: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
const REGISTRATION_LEAF: &str = "MobileReleaseKit";
struct RegistryOriginal {
    transaction: UnsafeCell<F::HANDLE>, tx_state: Cell<SlotState>,
    keys: [UnsafeCell<REG::HKEY>; 6], key_states: [Cell<SlotState>; 6],
    reservation: UnsafeCell<F::HANDLE>, reservation_state: Cell<SlotState>,
    owns_reservation: Cell<bool>, _pin: PhantomPinned,
}
#[derive(Clone, Copy)]
enum RegistryEffect {
    Reserve, ReservationSecurity, ReservationHandleInfo, NewTransaction, TransactionHandleInfo, Open(KeyRole), CreateStaged,
    Info(KeyRole), Value(KeyRole, u32), Security(KeyRole), ParentLink(KeyRole), Name(KeyRole), SetValue, Remove,
    Commit, Rollback, CloseKey(KeyRole), CloseTransaction, ReleaseReservation, CloseReservation, Random,
}
impl RegistryEffect {
    fn tag(self) -> u8 {
        match self { Self::Reserve => 1, Self::ReservationSecurity => 2, Self::NewTransaction => 3,
            Self::Open(KeyRole::Before) => 4, Self::Open(KeyRole::Staged) => 5, Self::Open(KeyRole::After) => 6,
            Self::Open(KeyRole::Parent) => 30, Self::Open(KeyRole::ParentStaged) => 31, Self::Open(KeyRole::ParentAfter) => 32,
            Self::CreateStaged => 7, Self::Info(role) => 40 + role as u8,
            Self::Value(role, _) => 50 + role as u8, Self::Security(role) => 60 + role as u8,
            Self::ParentLink(role) => 80 + role as u8, Self::Name(role) => 90 + role as u8,
            Self::SetValue => 17, Self::Remove => 18, Self::Commit => 19, Self::Rollback => 20,
            Self::CloseKey(role) => 70 + role as u8, Self::CloseTransaction => 24,
            Self::ReleaseReservation => 25, Self::CloseReservation => 26, Self::Random => 27,
            Self::ReservationHandleInfo => 28, Self::TransactionHandleInfo => 29 }
    }
}
struct RegistryCall {
    effect: RegistryEffect, phase: Cell<Phase>, returned: Cell<Option<Returned>>,
    transaction: F::HANDLE, key: REG::HKEY, reservation: F::HANDLE, output: *mut F::HANDLE,
    path: Vec<u16>, value: Vec<u16>, input: Vec<u8>, kind: u32,
    descriptor: UnsafeCell<Aligned>, attributes: S::SECURITY_ATTRIBUTES,
    bytes: UnsafeCell<Aligned>, name: UnsafeCell<[u16; 128]>,
    length: UnsafeCell<u32>, name_length: UnsafeCell<u32>, value_kind: UnsafeCell<u32>,
    disposition: UnsafeCell<u32>, subkeys: UnsafeCell<u32>, values: UnsafeCell<u32>,
    time: UnsafeCell<F::FILETIME>, _pin: PhantomPinned,
}
struct RegistryOwner {
    originals: Held<RegistryOriginal>, call: Option<Held<RegistryCall>>, caller: ThreadId,
    first: Option<Error>, unknown: bool, committed: bool, commit_entered: bool,
    rollback_attempted: bool, settling: bool, reservation_closed: bool, staged: Option<RegistrySnapshot>,
    parent_security: Option<Vec<u8>>,
    effects: Vec<(u8, u8, i64, u32)>, cleanup: Vec<SelectionCleanupError>,
}
impl RegistryOwner {
    fn new() -> Self {
        Self { originals: ManuallyDrop::new(Box::pin(RegistryOriginal {
            transaction: UnsafeCell::new(null_mut()), tx_state: Cell::new(SlotState::Reserved),
            keys: std::array::from_fn(|_| UnsafeCell::new(null_mut())),
            key_states: std::array::from_fn(|_| Cell::new(SlotState::Reserved)),
            reservation: UnsafeCell::new(null_mut()), reservation_state: Cell::new(SlotState::Reserved),
            owns_reservation: Cell::new(false), _pin: PhantomPinned })),
            call: None, caller: thread::current().id(), first: None, unknown: false, committed: false,
            commit_entered: false, rollback_attempted: false, settling: false, reservation_closed: false, staged: None,
            parent_security: None,
            effects: Vec::new(), cleanup: Vec::new() }
    }
    fn latch(&mut self, error: Error) {
        if self.first.is_none() { self.first = Some(error); }
        self.unknown |= error == Error::Unknown || self.call.is_some();
    }
    fn before(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        let result = if self.unknown || self.call.is_some() { Err(Error::Unknown) }
            else if self.first.is_some() || self.settling || self.caller != thread::current().id() { Err(Error::State) }
            else { boundary.producing_boundary() };
        if let Err(error) = result { self.latch(error); } result
    }
    fn after<T>(&mut self, boundary: &dyn InstallerBoundary, returned: Result<T>) -> Result<T> {
        let result = match returned { Err(first) => Err(first), Ok(value) => boundary.producing_boundary().map(|()| value) };
        if let Err(error) = result.as_ref() { self.latch(*error); } result
    }
    fn original(&self) -> &RegistryOriginal { self.originals.as_ref().get_ref() }
    fn tx(&self) -> Result<F::HANDLE> {
        need(self.original().tx_state.get() == SlotState::Owned)?;
        Ok(unsafe { *self.original().transaction.get() })
    }
    fn key(&self, role: KeyRole) -> Result<REG::HKEY> {
        need(self.original().key_states[role as usize].get() == SlotState::Owned)?;
        Ok(unsafe { *self.original().keys[role as usize].get() })
    }
    fn invoke(&mut self, boundary: &dyn InstallerBoundary, effect: RegistryEffect,
        name: &str, value: Option<&data::RegistryValue>, cleanup: bool) -> Result<Pin<Box<RegistryCall>>> {
        if cleanup {
            boundary.settlement_boundary();
            need(self.caller == thread::current().id() && self.call.is_none() && !self.unknown)?;
        } else { self.before(boundary)?; }
        need(self.effects.len() < 512)?;
        let key = match effect {
            RegistryEffect::Info(role) | RegistryEffect::Value(role, _) | RegistryEffect::Security(role)
                | RegistryEffect::ParentLink(role) | RegistryEffect::Name(role) | RegistryEffect::CloseKey(role) => self.key(role)?,
            RegistryEffect::SetValue => self.key(KeyRole::Staged)?,
            RegistryEffect::Open(KeyRole::Before) => self.key(KeyRole::Parent)?,
            RegistryEffect::Open(KeyRole::After) => self.key(KeyRole::ParentAfter)?,
            RegistryEffect::Open(KeyRole::Staged) | RegistryEffect::CreateStaged | RegistryEffect::Remove =>
                self.key(KeyRole::ParentStaged)?,
            _ => null_mut(),
        };
        let transaction = if matches!(effect, RegistryEffect::CreateStaged | RegistryEffect::Open(KeyRole::Staged | KeyRole::ParentStaged)
            | RegistryEffect::Remove | RegistryEffect::Commit | RegistryEffect::Rollback | RegistryEffect::CloseTransaction | RegistryEffect::TransactionHandleInfo) { self.tx()? } else { null_mut() };
        let reservation = if matches!(effect, RegistryEffect::ReleaseReservation | RegistryEffect::CloseReservation | RegistryEffect::ReservationSecurity | RegistryEffect::ReservationHandleInfo) {
            need(self.original().reservation_state.get() == SlotState::Owned)?;
            unsafe { *self.original().reservation.get() }
        } else { null_mut() };
        let raw = match effect {
            RegistryEffect::Reserve => selection_descriptor(security::SelectionDescriptor::Reservation)?,
            RegistryEffect::CreateStaged => selection_descriptor(security::SelectionDescriptor::Registration)?,
            _ => Vec::new(),
        };
        need(value.is_none_or(|v| v.bytes.len() <= data::REGISTRY_LIMIT))?;
        let mut frame = Box::pin(RegistryCall { effect, phase: Cell::new(Phase::Prepared), returned: Cell::new(None),
            transaction, key, reservation, output: null_mut(),
            path: wide(match effect {
                RegistryEffect::Reserve => r"Global\MobileReleaseKit.Selection.Maintenance.v1",
                RegistryEffect::Open(KeyRole::Parent | KeyRole::ParentStaged | KeyRole::ParentAfter) => REGISTRATION_PARENT,
                _ => REGISTRATION_LEAF,
            }),
            value: wide(if matches!(effect, RegistryEffect::ParentLink(_)) { "SymbolicLinkValue" } else { name }),
            input: value.map_or_else(Vec::new, |v| v.bytes.clone()), kind: value.map_or(0, |v| v.kind),
            descriptor: UnsafeCell::new(Aligned([0; BUFFER])), attributes: S::SECURITY_ATTRIBUTES::default(),
            bytes: UnsafeCell::new(Aligned([0; BUFFER])), name: UnsafeCell::new([0; 128]),
            length: UnsafeCell::new(BUFFER as u32), name_length: UnsafeCell::new(128), value_kind: UnsafeCell::new(u32::MAX),
            disposition: UnsafeCell::new(u32::MAX), subkeys: UnsafeCell::new(u32::MAX), values: UnsafeCell::new(u32::MAX),
            time: UnsafeCell::new(F::FILETIME::default()), _pin: PhantomPinned });
        let setup = unsafe { frame.as_mut().get_unchecked_mut() };
        if !raw.is_empty() {
            unsafe { (&mut *setup.descriptor.get()).0[..raw.len()].copy_from_slice(&raw); }
            setup.attributes.lpSecurityDescriptor = setup.descriptor.get().cast();
        }
        setup.attributes.nLength = size_of::<S::SECURITY_ATTRIBUTES>() as u32; setup.attributes.bInheritHandle = 0;
        match effect {
            RegistryEffect::Reserve => {
                need(self.original().reservation_state.get() == SlotState::Reserved)?;
                setup.output = self.original().reservation.get(); self.original().reservation_state.set(SlotState::Acquiring);
            },
            RegistryEffect::NewTransaction => {
                need(self.original().tx_state.get() == SlotState::Reserved)?;
                setup.output = self.original().transaction.get(); self.original().tx_state.set(SlotState::Acquiring);
            },
            RegistryEffect::Open(role) => {
                need(self.original().key_states[role as usize].get() == SlotState::Reserved)?;
                setup.output = self.original().keys[role as usize].get(); self.original().key_states[role as usize].set(SlotState::Acquiring);
            },
            RegistryEffect::CreateStaged => {
                need(self.original().key_states[1].get() == SlotState::Reserved)?;
                setup.output = self.original().keys[1].get(); self.original().key_states[1].set(SlotState::Acquiring);
            },
            RegistryEffect::CloseKey(role) => self.original().key_states[role as usize].set(SlotState::Closing),
            RegistryEffect::CloseTransaction => self.original().tx_state.set(SlotState::Closing),
            RegistryEffect::CloseReservation => self.original().reservation_state.set(SlotState::Closing),
            RegistryEffect::ReleaseReservation => need(self.original().owns_reservation.get())?,
            RegistryEffect::Commit => need(!self.commit_entered && !self.rollback_attempted)?,
            RegistryEffect::Rollback => need(!self.rollback_attempted && !self.committed)?,
            _ => (),
        }
        self.call = Some(ManuallyDrop::new(frame));
        let frame = self.call.as_ref().ok_or(Error::Unknown)?.as_ref().get_ref();
        // Entry is observed only at the registered native-entry boundary, not
        // when a wrapper or its policy checks began.
        if matches!(effect, RegistryEffect::Commit) { self.commit_entered = true; }
        if matches!(effect, RegistryEffect::Rollback) { self.rollback_attempted = true; }
        frame.phase.set(Phase::Entered);
        let status = unsafe {
            match effect {
                RegistryEffect::Reserve => {
                    F::SetLastError(0);
                    *frame.output = T::CreateMutexExW(&frame.attributes, frame.path.as_ptr(), T::CREATE_MUTEX_INITIAL_OWNER, T::MUTEX_ALL_ACCESS);
                    let error = F::GetLastError();
                    Returned::Boolean(if valid_handle(*frame.output) { 1 } else { 0 }, error)
                },
                RegistryEffect::ReservationSecurity => boolean(S::GetKernelObjectSecurity(frame.reservation,
                    S::OWNER_SECURITY_INFORMATION | S::DACL_SECURITY_INFORMATION, frame.bytes.get().cast(), BUFFER as u32, frame.length.get())),
                RegistryEffect::ReservationHandleInfo => boolean(F::GetHandleInformation(frame.reservation, frame.length.get())),
                RegistryEffect::TransactionHandleInfo => boolean(F::GetHandleInformation(frame.transaction, frame.length.get())),
                RegistryEffect::NewTransaction => {
                    *frame.output = FS::CreateTransaction(null_mut(), null_mut(), 0, 0, 0, 600_000, null());
                    if valid_handle(*frame.output) { Returned::Boolean(1, 0) } else { Returned::Boolean(0, F::GetLastError()) }
                },
                RegistryEffect::Open(role) => Returned::Scalar(match role {
                    KeyRole::Parent | KeyRole::ParentAfter => REG::RegOpenKeyExW(REG::HKEY_LOCAL_MACHINE, frame.path.as_ptr(),
                        REG::REG_OPTION_OPEN_LINK, REG::KEY_READ | REG::KEY_WOW64_64KEY, frame.output),
                    KeyRole::ParentStaged => REG::RegOpenKeyTransactedW(REG::HKEY_LOCAL_MACHINE, frame.path.as_ptr(),
                        REG::REG_OPTION_OPEN_LINK, REG::KEY_READ | REG::KEY_CREATE_SUB_KEY | REG::KEY_WOW64_64KEY,
                        frame.output, frame.transaction, null()),
                    KeyRole::Staged => REG::RegOpenKeyTransactedW(frame.key, frame.path.as_ptr(), REG::REG_OPTION_OPEN_LINK,
                        REG::KEY_READ | REG::KEY_SET_VALUE | FS::DELETE | REG::KEY_WOW64_64KEY,
                        frame.output, frame.transaction, null()),
                    KeyRole::Before | KeyRole::After => REG::RegOpenKeyExW(frame.key, frame.path.as_ptr(), REG::REG_OPTION_OPEN_LINK,
                        REG::KEY_READ | REG::KEY_WOW64_64KEY, frame.output),
                }),
                // Parent is an already opened, protected existing original.
                // The create/delete name is ONE literal component, never the
                // multi-component HKLM path; missing ancestors cannot be made.
                RegistryEffect::CreateStaged => Returned::Scalar(REG::RegCreateKeyTransactedW(frame.key,
                    frame.path.as_ptr(), 0, null(), REG::REG_OPTION_NON_VOLATILE,
                    REG::KEY_READ | REG::KEY_SET_VALUE | FS::DELETE | REG::KEY_WOW64_64KEY, &frame.attributes,
                    frame.output, frame.disposition.get(), frame.transaction, null())),
                RegistryEffect::Info(_) => Returned::Scalar(REG::RegQueryInfoKeyW(frame.key, null_mut(), null_mut(), null(),
                    frame.subkeys.get(), null_mut(), null_mut(), frame.values.get(), null_mut(), null_mut(), null_mut(), frame.time.get())),
                RegistryEffect::Value(_, ordinal) => Returned::Scalar(REG::RegEnumValueW(frame.key, ordinal,
                    frame.name.get().cast(), frame.name_length.get(), null(), frame.value_kind.get(), frame.bytes.get().cast(), frame.length.get())),
                RegistryEffect::Security(_) => Returned::Scalar(REG::RegGetKeySecurity(frame.key,
                    S::OWNER_SECURITY_INFORMATION | S::DACL_SECURITY_INFORMATION, frame.bytes.get().cast(), frame.length.get())),
                RegistryEffect::Name(_) => Returned::Nt(NK::NtQueryKey(frame.key, NK::KeyNameInformation,
                    frame.bytes.get().cast(), BUFFER as u32, frame.length.get())),
                RegistryEffect::ParentLink(_) => Returned::Scalar(REG::RegQueryValueExW(frame.key,
                    frame.value.as_ptr(), null(), frame.value_kind.get(), frame.bytes.get().cast(), frame.length.get())),
                RegistryEffect::SetValue => Returned::Scalar(REG::RegSetValueExW(frame.key, frame.value.as_ptr(), 0,
                    frame.kind, frame.input.as_ptr(), frame.input.len() as u32)),
                RegistryEffect::Remove => Returned::Scalar(REG::RegDeleteKeyTransactedW(frame.key,
                    frame.path.as_ptr(), REG::KEY_WOW64_64KEY, 0, frame.transaction, null())),
                RegistryEffect::Commit => boolean(FS::CommitTransaction(frame.transaction)),
                RegistryEffect::Rollback => boolean(FS::RollbackTransaction(frame.transaction)),
                RegistryEffect::CloseKey(_) => Returned::Scalar(REG::RegCloseKey(frame.key)),
                RegistryEffect::CloseTransaction => boolean(F::CloseHandle(frame.transaction)),
                RegistryEffect::ReleaseReservation => boolean(T::ReleaseMutex(frame.reservation)),
                RegistryEffect::CloseReservation => boolean(F::CloseHandle(frame.reservation)),
                RegistryEffect::Random => Returned::Nt(windows_sys::Win32::Security::Cryptography::BCryptGenRandom(
                    null_mut(), frame.bytes.get().cast(), 16, windows_sys::Win32::Security::Cryptography::BCRYPT_USE_SYSTEM_PREFERRED_RNG)),
            }
        };
        frame.returned.set(Some(status)); frame.phase.set(Phase::Returned);
        let result = self.finish_call();
        #[cfg(feature = "installer-selection-fixture")]
        if result.is_ok() && matches!(effect, RegistryEffect::Commit) {
            boundary.selection_fixture_return_boundary(
                super::installer_selection_fixture_data::SelectionFixturePoint::RegistryCommitReturned);
        }
        // Original return and state have been retained before any later STOP.
        if cleanup {
            if let Err(error) = result.as_ref() { self.latch(*error); }
            boundary.settlement_boundary(); result
        } else { self.after(boundary, result) }
    }
    fn finish_call(&mut self) -> Result<Pin<Box<RegistryCall>>> {
        let f = self.call.as_ref().ok_or(Error::Unknown)?.as_ref().get_ref();
        need(f.phase.get() == Phase::Returned)?;
        let returned = f.returned.get().ok_or(Error::Unknown)?; let effect = f.effect;
        let mut result = match returned {
            Returned::Boolean(ok, error) => mutation_return(ok, error),
            Returned::Scalar(status) if status == F::ERROR_SUCCESS => Ok(()),
            Returned::Scalar(F::ERROR_IO_PENDING) => Err(Error::Unknown),
            Returned::Scalar(F::ERROR_MORE_DATA) => Err(Error::Bounds),
            Returned::Scalar(_) => Err(Error::Unavailable),
            Returned::Nt(0) => Ok(()), Returned::Nt(F::STATUS_PENDING) => Err(Error::Unknown),
            Returned::Nt(_) => Err(Error::Unavailable), _ => Err(Error::Unknown),
        };
        let (tag, scalar, error) = match returned {
            Returned::Boolean(v, e) => (1, i64::from(v), e),
            Returned::Scalar(v) => (2, i64::from(v), 0),
            Returned::Nt(v) => (3, i64::from(v), 0), _ => (0, 0, 0),
        };
        self.effects.push((effect.tag(), tag, scalar, error));
        if matches!(effect, RegistryEffect::ParentLink(_)) {
            // A REG_LINK parent is not followed. Any SymbolicLinkValue is an
            // incompatible occupant, not permission to target another key.
            result = match returned {
                Returned::Scalar(F::ERROR_FILE_NOT_FOUND) => Ok(()),
                Returned::Scalar(F::ERROR_SUCCESS) => Err(Error::Unsafe),
                _ => result,
            };
        }
        if matches!(effect, RegistryEffect::Reserve) {
            let handle = unsafe { *self.original().reservation.get() };
            match returned {
                Returned::Boolean(1, 0) if valid_handle(handle) => {
                    self.original().reservation_state.set(SlotState::Owned);
                    self.original().owns_reservation.set(true); result = Ok(());
                },
                Returned::Boolean(1, F::ERROR_ALREADY_EXISTS) if valid_handle(handle) => {
                    // We received a reference but NOT the existing mutex's
                    // ownership. Refuse; settlement closes only this reference.
                    self.original().reservation_state.set(SlotState::Owned); result = Err(Error::Unsafe);
                },
                Returned::Boolean(0, e) if !valid_handle(handle) && e != 0 && e != F::ERROR_IO_PENDING => {
                    self.original().reservation_state.set(SlotState::NoHandle); result = Err(Error::Unavailable);
                },
                _ => { self.original().reservation_state.set(SlotState::Unknown); result = Err(Error::Unknown); },
            }
        } else if matches!(effect, RegistryEffect::NewTransaction) {
            let handle = unsafe { *self.original().transaction.get() };
            if result.is_ok() && valid_handle(handle) { self.original().tx_state.set(SlotState::Owned); }
            else if result == Err(Error::Unavailable) && handle == F::INVALID_HANDLE_VALUE { self.original().tx_state.set(SlotState::NoHandle); }
            else { self.original().tx_state.set(SlotState::Unknown); result = Err(Error::Unknown); }
        } else if let RegistryEffect::Open(role) = effect {
            result = self.adopt_key(role, returned)?;
        } else if matches!(effect, RegistryEffect::CreateStaged) {
            result = self.adopt_key(KeyRole::Staged, returned)?;
            if result.is_ok() && unsafe { *f.disposition.get() } != REG::REG_CREATED_NEW_KEY { result = Err(Error::Unsafe); }
        } else {
            match effect {
                RegistryEffect::CloseKey(role) => self.original().key_states[role as usize].set(if result.is_ok() { SlotState::Closed } else { SlotState::Unknown }),
                RegistryEffect::CloseTransaction => self.original().tx_state.set(if result.is_ok() { SlotState::Closed } else { SlotState::Unknown }),
                RegistryEffect::CloseReservation => self.original().reservation_state.set(if result.is_ok() { SlotState::Closed } else { SlotState::Unknown }),
                RegistryEffect::ReleaseReservation if result.is_ok() => self.original().owns_reservation.set(false),
                RegistryEffect::Commit if result.is_ok() => self.committed = true,
                _ => (),
            }
        }
        if result == Err(Error::Unknown) { self.unknown = true; return Err(Error::Unknown); }
        f.phase.set(Phase::Complete);
        let original = self.call.take().ok_or(Error::Unknown)?;
        let completed = ManuallyDrop::into_inner(original);
        result?; Ok(completed)
    }
    fn adopt_key(&self, role: KeyRole, returned: Returned) -> Result<Result<()>> {
        let handle = unsafe { *self.original().keys[role as usize].get() };
        let status = match returned { Returned::Scalar(s) => s, _ => return Err(Error::Unknown) };
        let state = &self.original().key_states[role as usize];
        if status == F::ERROR_SUCCESS && !handle.is_null() {
            if self.original().keys.iter().enumerate().any(|(index, other)|
                index != role as usize && self.original().key_states[index].get() == SlotState::Owned
                    && unsafe { *other.get() } == handle) {
                state.set(SlotState::Unknown); Ok(Err(Error::Unknown))
            } else { state.set(SlotState::Owned); Ok(Ok(())) }
        }
        else if handle.is_null() && matches!(status, F::ERROR_FILE_NOT_FOUND | F::ERROR_PATH_NOT_FOUND) {
            state.set(SlotState::NoHandle); Ok(Ok(()))
        } else if status != 0 && status != F::ERROR_IO_PENDING && handle.is_null() {
            state.set(SlotState::NoHandle); Ok(Err(Error::Unavailable))
        } else { state.set(SlotState::Unknown); Ok(Err(Error::Unknown)) }
    }
    fn reserve_once(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        self.invoke(boundary, RegistryEffect::Reserve, "", None, false)?;
        let flags = self.invoke(boundary, RegistryEffect::ReservationHandleInfo, "", None, false)?;
        need(unsafe { *flags.length.get() } & F::HANDLE_FLAG_INHERIT == 0)?;
        let f = self.invoke(boundary, RegistryEffect::ReservationSecurity, "", None, false)?;
        let length = unsafe { *f.length.get() } as usize; need(length <= BUFFER)?;
        security::Observed::new(Refusal::none()).selection_descriptor(unsafe { &(*f.bytes.get()).0[..length] },
            security::SelectionDescriptor::Reservation)?;
        Ok(())
    }
    fn random_run(&mut self, boundary: &dyn InstallerBoundary) -> Result<String> {
        let f = self.invoke(boundary, RegistryEffect::Random, "", None, false)?;
        let id = hex_digest(unsafe { &(*f.bytes.get()).0[..16] });
        need(data::recovery_id(&id))?; Ok(id)
    }
    fn open_before(&mut self, boundary: &dyn InstallerBoundary) -> Result<RegistrySnapshot> {
        self.invoke(boundary, RegistryEffect::Open(KeyRole::Parent), "", None, false)?;
        let security = self.admit_parent(boundary, KeyRole::Parent)?;
        self.parent_security = Some(security);
        self.invoke(boundary, RegistryEffect::Open(KeyRole::Before), "", None, false)?;
        self.snapshot(boundary, KeyRole::Before)
    }
    fn fixed_name(&mut self, boundary: &dyn InstallerBoundary, role: KeyRole) -> Result<()> {
        let original = self.invoke(boundary, RegistryEffect::Name(role), "", None, false)?;
        let returned_bytes = unsafe { *original.length.get() } as usize;
        need(returned_bytes <= BUFFER && returned_bytes >= 4)?;
        let raw = unsafe { &(*original.bytes.get()).0[..returned_bytes] };
        let d = decode::Observed::new(Refusal::none());
        let bytes = d.u32_at(raw, offset_of!(NS::KEY_NAME_INFORMATION, NameLength))? as usize;
        let begin = offset_of!(NS::KEY_NAME_INFORMATION, Name);
        need(bytes > 0 && bytes % 2 == 0 && bytes <= NAME_UNITS * 2
            && begin.checked_add(bytes) == Some(returned_bytes))?;
        let words: Vec<u16> = raw[begin..].chunks_exact(2).map(|p| u16::from_le_bytes([p[0],p[1]])).collect();
        need(!words.contains(&0))?;
        let actual = String::from_utf16(&words).map_err(|_| Error::Unsafe)?;
        let relative = if matches!(role, KeyRole::Parent | KeyRole::ParentStaged | KeyRole::ParentAfter) {
            REGISTRATION_PARENT
        } else { data::REGISTRATION };
        need(actual.eq_ignore_ascii_case(&format!(r"\REGISTRY\MACHINE\{relative}")))
    }
    fn admit_parent(&mut self, boundary: &dyn InstallerBoundary, role: KeyRole) -> Result<Vec<u8>> {
        need(matches!(role, KeyRole::Parent | KeyRole::ParentStaged | KeyRole::ParentAfter)
            && self.original().key_states[role as usize].get() == SlotState::Owned)?;
        self.fixed_name(boundary, role)?;
        let returned = self.invoke(boundary, RegistryEffect::Security(role), "", None, false)?;
        let length = unsafe { *returned.length.get() } as usize; need(length <= BUFFER)?;
        let raw = unsafe { (*returned.bytes.get()).0[..length].to_vec() };
        security::Observed::new(Refusal::none()).selection_descriptor(&raw,
            security::SelectionDescriptor::RegistrationParent)?;
        self.invoke(boundary, RegistryEffect::ParentLink(role), "", None, false)?;
        self.fixed_name(boundary, role)?;
        Ok(raw)
    }
    fn info(&mut self, boundary: &dyn InstallerBoundary, role: KeyRole) -> Result<(u32, u64)> {
        let f = self.invoke(boundary, RegistryEffect::Info(role), "", None, false)?;
        let (subkeys, values, time) = unsafe { (*f.subkeys.get(), *f.values.get(), *f.time.get()) };
        need(subkeys == 0 && values <= data::MAX_VALUES as u32)?;
        let write = u64::from(time.dwLowDateTime) | (u64::from(time.dwHighDateTime) << 32);
        need(write > 0)?; Ok((values, write))
    }
    fn snapshot(&mut self, boundary: &dyn InstallerBoundary, role: KeyRole) -> Result<RegistrySnapshot> {
        need(matches!(role, KeyRole::Before | KeyRole::Staged | KeyRole::After))?;
        if self.original().key_states[role as usize].get() == SlotState::NoHandle { return Ok(RegistrySnapshot::absent()); }
        self.fixed_name(boundary, role)?;
        let before = self.info(boundary, role)?;
        let f = self.invoke(boundary, RegistryEffect::Security(role), "", None, false)?;
        let length = unsafe { *f.length.get() } as usize; need(length <= BUFFER)?;
        let security = unsafe { (*f.bytes.get()).0[..length].to_vec() };
        security::Observed::new(Refusal::none()).selection_descriptor(&security, security::SelectionDescriptor::Registration)?;
        let mut values = data::Registration::new();
        for index in 0..before.0 {
            let f = self.invoke(boundary, RegistryEffect::Value(role, index), "", None, false)?;
            let (count, length, kind) = unsafe { (*f.name_length.get() as usize, *f.length.get() as usize, *f.value_kind.get()) };
            need(count > 0 && count < 128 && length <= BUFFER)?;
            let words = unsafe { &*f.name.get() }; need(words[count] == 0 && !words[..count].contains(&0))?;
            let name = String::from_utf16(&words[..count]).map_err(|_| Error::Unsafe)?;
            let bytes = unsafe { (*f.bytes.get()).0[..length].to_vec() };
            need(values.insert(name, data::RegistryValue { kind, bytes }).is_none())?;
        }
        need(self.info(boundary, role)? == before)?;
        self.fixed_name(boundary, role)?;
        if !values.is_empty() { need(data::registration_shape(&values))?; }
        Ok(RegistrySnapshot { present: true, values, security, write: before.1 })
    }
    fn stage(&mut self, boundary: &dyn InstallerBoundary, before: &RegistrySnapshot,
        proposed: &data::Registration, remove: bool, report: &mut SelectionReport) -> Result<()> {
        // Establish genuine TxR support, exact access/security and staging BEFORE
        // the first authoritative shortcut rename. No nontransactional fallback.
        need(remove || data::registration_shape(proposed))?;
        self.invoke(boundary, RegistryEffect::NewTransaction, "", None, false)?;
        let flags = self.invoke(boundary, RegistryEffect::TransactionHandleInfo, "", None, false)?;
        need(unsafe { *flags.length.get() } & F::HANDLE_FLAG_INHERIT == 0)?;
        self.invoke(boundary, RegistryEffect::Open(KeyRole::ParentStaged), "", None, false)?;
        let current = self.admit_parent(boundary, KeyRole::ParentStaged)?;
        need(self.parent_security.as_ref() == Some(&current))?;
        if before.present {
            self.invoke(boundary, RegistryEffect::Open(KeyRole::Staged), "", None, false)?;
            need(self.snapshot(boundary, KeyRole::Staged)? == *before)?;
        } else if !remove {
            self.invoke(boundary, RegistryEffect::CreateStaged, "", None, false)?;
            let created = self.snapshot(boundary, KeyRole::Staged)?;
            need(created.present && created.values.is_empty())?;
        } else {
            // Remove+missing is not permission to reuse a cached NoHandle.
            // The actual transacted lookup must positively observe absence.
            self.invoke(boundary, RegistryEffect::Open(KeyRole::Staged), "", None, false)?;
            need(self.snapshot(boundary, KeyRole::Staged)? == *before)?;
        }
        if remove {
            if before.present {
                self.invoke(boundary, RegistryEffect::Remove, "", None, false)?;
                self.invoke(boundary, RegistryEffect::CloseKey(KeyRole::Staged), "", None, false)?;
            }
        } else {
            for (name, value) in proposed {
                need(report.charge(value.bytes.len()))?;
                let prior = self.effects.len();
                let returned = self.invoke(boundary, RegistryEffect::SetValue, name, Some(value), false);
                // STOP after a successful RegSetValue does not erase its known
                // staged byte count. A staged value is NOT a committed value.
                if self.effects.len() == prior + 1
                    && self.effects.last() == Some(&(RegistryEffect::SetValue.tag(), 2, 0, 0)) {
                    report.output_bytes_confirmed = report.output_bytes_confirmed.checked_add(value.bytes.len() as u64).ok_or(Error::Bounds)?;
                }
                returned?;
            }
            let staged = self.snapshot(boundary, KeyRole::Staged)?;
            need(staged.present && staged.values == *proposed)?;
            self.staged = Some(staged);
        }
        if remove { self.staged = Some(RegistrySnapshot::absent()); }
        Ok(())
    }
    fn recheck_namespace_before_effect(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        // Bounded observations on the actual original transaction/keys.
        // A held HKEY whose native name changed cannot authorize a move.
        self.fixed_name(boundary, KeyRole::Parent)?;
        self.fixed_name(boundary, KeyRole::ParentStaged)?;
        for role in [KeyRole::Before, KeyRole::Staged] {
            if self.original().key_states[role as usize].get() == SlotState::Owned {
                self.fixed_name(boundary, role)?;
            }
        }
        Ok(())
    }
    fn commit_once(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        self.recheck_namespace_before_effect(boundary)?;
        let current = self.admit_parent(boundary, KeyRole::ParentStaged)?;
        need(self.parent_security.as_ref() == Some(&current))?;
        if self.original().key_states[KeyRole::Staged as usize].get() == SlotState::Owned {
            self.fixed_name(boundary, KeyRole::Staged)?;
        }
        self.invoke(boundary, RegistryEffect::Commit, "", None, false).map(|_| ())
    }
    fn verify_after(&mut self, boundary: &dyn InstallerBoundary, expected: &data::Registration, remove: bool) -> Result<()> {
        // A retained HKEY alone is not named namespace proof. Recheck the
        // ordinary original parent, then freshly open the fixed native64 parent
        // from the hive. Completed-transaction keys are closed only: no query
        // depends on a transacted HKEY remaining usable after CommitTransaction.
        // A renamed/rebound ordinary parent cannot be silently adopted.
        self.fixed_name(boundary, KeyRole::Parent)?;
        self.invoke(boundary, RegistryEffect::Open(KeyRole::ParentAfter), "", None, false)?;
        let current = self.admit_parent(boundary, KeyRole::ParentAfter)?;
        need(self.parent_security.as_ref() == Some(&current))?;
        if self.original().key_states[1].get() == SlotState::Owned {
            self.invoke(boundary, RegistryEffect::CloseKey(KeyRole::Staged), "", None, false)?;
        }
        if self.original().key_states[0].get() == SlotState::Owned {
            // RegDeleteKey marks a key deleted until its last original closes.
            // Do not misclassify our own open Before key as a foreign occupant.
            self.invoke(boundary, RegistryEffect::CloseKey(KeyRole::Before), "", None, false)?;
        }
        self.invoke(boundary, RegistryEffect::Open(KeyRole::After), "", None, false)?;
        let actual = self.snapshot(boundary, KeyRole::After)?;
        // A missing leaf has no key name to query. Its ordinary parent must
        // still name the fixed namespace AFTER the actual absence observation.
        self.fixed_name(boundary, KeyRole::ParentAfter)?;
        self.fixed_name(boundary, KeyRole::Parent)?;
        need(if remove { !actual.present } else { actual.present && actual.values == *expected })
    }
    fn settle_registry_once(&mut self, boundary: &dyn InstallerBoundary) {
        if self.settling { return; } self.settling = true;
        if self.call.is_some() || self.unknown { self.unknown = true; return; }
        if self.original().tx_state.get() == SlotState::Owned && !self.committed && !self.rollback_attempted {
            if let Err(error) = self.invoke(boundary, RegistryEffect::Rollback, "", None, true) {
                self.cleanup.push(SelectionCleanupError { original: SelectionOriginal::Transaction, record: 0, error });
            }
        }
        for role in [KeyRole::After, KeyRole::Staged, KeyRole::Before, KeyRole::ParentAfter, KeyRole::ParentStaged, KeyRole::Parent] {
            if self.original().key_states[role as usize].get() == SlotState::Owned {
                if let Err(error) = self.invoke(boundary, RegistryEffect::CloseKey(role), "", None, true) {
                    self.cleanup.push(SelectionCleanupError { original: SelectionOriginal::Registry, record: role as usize, error });
                }
            } else if self.original().key_states[role as usize].get() == SlotState::Reserved {
                self.original().key_states[role as usize].set(SlotState::NoHandle);
            }
        }
        if self.original().key_states.iter().all(|s| matches!(s.get(), SlotState::NoHandle | SlotState::Closed)) {
            if self.original().tx_state.get() == SlotState::Owned {
                if let Err(error) = self.invoke(boundary, RegistryEffect::CloseTransaction, "", None, true) {
                    self.cleanup.push(SelectionCleanupError { original: SelectionOriginal::Transaction, record: 0, error });
                }
            } else if self.original().tx_state.get() == SlotState::Reserved { self.original().tx_state.set(SlotState::NoHandle); }
        }
    }
    fn registry_closed(&self) -> bool {
        self.settling && !self.unknown && self.call.is_none()
            && self.original().key_states.iter().all(|s| matches!(s.get(), SlotState::NoHandle | SlotState::Closed))
            && matches!(self.original().tx_state.get(), SlotState::NoHandle | SlotState::Closed)
    }
    fn close_reservation_once(&mut self, boundary: &dyn InstallerBoundary) {
        if self.reservation_closed { return; }
        // The caller proves all other dependent originals settled BEFORE this.
        self.reservation_closed = true;
        if self.call.is_some() || self.unknown { self.unknown = true; return; }
        if self.original().owns_reservation.get() {
            if let Err(error) = self.invoke(boundary, RegistryEffect::ReleaseReservation, "", None, true) {
                self.cleanup.push(SelectionCleanupError { original: SelectionOriginal::Reservation, record: 0, error }); return;
            }
        }
        if self.original().reservation_state.get() == SlotState::Owned {
            if let Err(error) = self.invoke(boundary, RegistryEffect::CloseReservation, "", None, true) {
                self.cleanup.push(SelectionCleanupError { original: SelectionOriginal::Reservation, record: 0, error });
            }
        } else if self.original().reservation_state.get() == SlotState::Reserved {
            self.original().reservation_state.set(SlotState::NoHandle);
        }
    }
    fn closed(&self) -> bool {
        self.registry_closed() && self.reservation_closed && !self.original().owns_reservation.get()
            && matches!(self.original().reservation_state.get(), SlotState::NoHandle | SlotState::Closed) && self.cleanup.is_empty()
    }
}

// Stable COM ABI declarations are limited to the four SDK interfaces below.
// Source reference: Microsoft win32metadata WinSDK ShObjIdl_core.h / ObjIdl.h.
// Uncalled vtable entries occupy pointer-sized slots; they are never invoked.
type QueryInterfaceFn = unsafe extern "system" fn(*mut c_void, *const windows_sys::core::GUID, *mut *mut c_void) -> i32;
type RefFn = unsafe extern "system" fn(*mut c_void) -> u32;
type FactoryFn = unsafe extern "system" fn(*const windows_sys::core::GUID, *const windows_sys::core::GUID, *mut *mut c_void) -> i32;
#[repr(C)]
struct UnknownTable { query: QueryInterfaceFn, add_ref: RefFn, release: RefFn }
#[repr(C)]
struct FactoryTable {
    base: UnknownTable,
    create: unsafe extern "system" fn(*mut c_void, *mut c_void, *const windows_sys::core::GUID, *mut *mut c_void) -> i32,
    lock_server: usize,
}
#[repr(C)]
struct LinkTable {
    base: UnknownTable,
    get_path: unsafe extern "system" fn(*mut c_void, *mut u16, i32, *mut FS::WIN32_FIND_DATAW, u32) -> i32,
    get_id_list: usize, set_id_list: usize,
    get_description: unsafe extern "system" fn(*mut c_void, *mut u16, i32) -> i32,
    set_description: unsafe extern "system" fn(*mut c_void, *const u16) -> i32,
    get_working: unsafe extern "system" fn(*mut c_void, *mut u16, i32) -> i32,
    set_working: unsafe extern "system" fn(*mut c_void, *const u16) -> i32,
    get_arguments: unsafe extern "system" fn(*mut c_void, *mut u16, i32) -> i32,
    set_arguments: unsafe extern "system" fn(*mut c_void, *const u16) -> i32,
    get_hotkey: unsafe extern "system" fn(*mut c_void, *mut u16) -> i32,
    set_hotkey: unsafe extern "system" fn(*mut c_void, u16) -> i32,
    get_show: unsafe extern "system" fn(*mut c_void, *mut i32) -> i32,
    set_show: unsafe extern "system" fn(*mut c_void, i32) -> i32,
    get_icon: unsafe extern "system" fn(*mut c_void, *mut u16, i32, *mut i32) -> i32,
    set_icon: unsafe extern "system" fn(*mut c_void, *const u16, i32) -> i32,
    set_relative: usize, resolve: usize,
    set_path: unsafe extern "system" fn(*mut c_void, *const u16) -> i32,
}
#[repr(C)]
struct PersistTable {
    base: UnknownTable, get_class: usize, is_dirty: usize,
    load: unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32,
    save: unsafe extern "system" fn(*mut c_void, *mut c_void, i32) -> i32,
    size: unsafe extern "system" fn(*mut c_void, *mut u64) -> i32,
}
#[repr(C)]
struct StreamTable {
    base: UnknownTable,
    read: unsafe extern "system" fn(*mut c_void, *mut c_void, u32, *mut u32) -> i32,
    write: unsafe extern "system" fn(*mut c_void, *const c_void, u32, *mut u32) -> i32,
    seek: unsafe extern "system" fn(*mut c_void, i64, u32, *mut u64) -> i32,
    set_size: usize, copy_to: usize, commit: usize, revert: usize,
    lock_region: usize, unlock_region: usize, stat: usize, clone_stream: usize,
}
#[repr(C)]
struct LinkDataTable {
    base: UnknownTable, add_block: usize, copy_block: usize, remove_block: usize,
    get_flags: unsafe extern "system" fn(*mut c_void, *mut u32) -> i32,
    set_flags: unsafe extern "system" fn(*mut c_void, u32) -> i32,
}
const fn guid(a: u32, b: u16, c: u16, d: [u8; 8]) -> windows_sys::core::GUID {
    windows_sys::core::GUID { data1: a, data2: b, data3: c, data4: d }
}
const COM_TAIL: [u8; 8] = [0xc0, 0, 0, 0, 0, 0, 0, 0x46];
const SHELL_LINK: windows_sys::core::GUID = guid(0x00021401, 0, 0, COM_TAIL);
const LINK_IID: windows_sys::core::GUID = guid(0x000214f9, 0, 0, COM_TAIL);
const FACTORY_IID: windows_sys::core::GUID = guid(1, 0, 0, COM_TAIL);
const PERSIST_IID: windows_sys::core::GUID = guid(0x00000109, 0, 0, COM_TAIL);
const DATA_IID: windows_sys::core::GUID = guid(0x45e2b4ae, 0xb1c3, 0x11d0, [0xb9,0x2f,0,0xa0,0xc9,3,0x12,0xe1]);
#[derive(Clone, Copy, Eq, PartialEq)]
enum ComRole { Module, Factory, Link, Persist, LinkData, Stream }
struct ComOriginal { pointer: UnsafeCell<*mut c_void>, state: Cell<SlotState>, role: ComRole, _pin: PhantomPinned }
#[derive(Clone, Copy)]
enum ComEffect {
    Initialize, LoadModule, ModuleName, Export, Factory, NewLink, NewStream, Query(ComRole),
    SetPath, SetDescription, SetWorking, SetArguments, SetShow, SetHotkey, SetIcon,
    GetPath, GetDescription, GetWorking, GetArguments, GetShow, GetHotkey, GetIcon, GetFlags,
    PersistLoad, PersistSave, PersistSize, StreamRead(usize), StreamWrite, StreamSeek(u32),
    Release, FreeModule, Uninitialize,
}
struct ComCall {
    effect: ComEffect, phase: Cell<Phase>, returned: Cell<Option<Returned>>, slot: Option<usize>,
    object: *mut c_void, other: *mut c_void, output: *mut *mut c_void,
    factory: Option<FactoryFn>, export: UnsafeCell<Option<unsafe extern "system" fn() -> isize>>,
    text: Vec<u16>, bytes: Vec<u8>, output_bytes: UnsafeCell<[u8; data::LINK_LIMIT + 1]>,
    output_text: UnsafeCell<[u16; NAME_UNITS]>, count: UnsafeCell<u32>, number: UnsafeCell<i32>,
    large: UnsafeCell<u64>, word: UnsafeCell<u16>, _pin: PhantomPinned,
}
struct LinkCodec {
    caller: ThreadId, originals: Vec<Held<ComOriginal>>, call: Option<Held<ComCall>>,
    factory_entry: Option<FactoryFn>, module: Option<usize>, factory: Option<usize>,
    initialized: bool, apartment_entered: bool, uninitialized: bool,
    first: Option<Error>, unknown: bool, settling: bool, cleanup: Vec<SelectionCleanupError>,
}
impl LinkCodec {
    fn new() -> Self {
        Self { caller: thread::current().id(), originals: Vec::new(), call: None,
            factory_entry: None, module: None, factory: None, initialized: false, apartment_entered: false,
            uninitialized: false, first: None, unknown: false, settling: false, cleanup: Vec::new() }
    }
    fn latch(&mut self, error: Error) {
        if self.first.is_none() { self.first = Some(error); }
        self.unknown |= error == Error::Unknown || self.call.is_some();
    }
    fn before(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        let returned = if self.call.is_some() || self.unknown { Err(Error::Unknown) }
            else if self.caller != thread::current().id() || self.settling || self.first.is_some() { Err(Error::State) }
            else { boundary.producing_boundary() };
        if let Err(error) = returned { self.latch(error); } returned
    }
    fn after<T>(&mut self, boundary: &dyn InstallerBoundary, returned: Result<T>) -> Result<T> {
        let result = match returned { Err(first) => Err(first), Ok(value) => boundary.producing_boundary().map(|()| value) };
        if let Err(error) = result.as_ref() { self.latch(*error); } result
    }
    fn reserve(&mut self, role: ComRole) -> Result<usize> {
        need(self.originals.len() < 32)?;
        let index = self.originals.len();
        self.originals.push(ManuallyDrop::new(Box::pin(ComOriginal {
            pointer: UnsafeCell::new(null_mut()), state: Cell::new(SlotState::Reserved), role, _pin: PhantomPinned })));
        Ok(index)
    }
    fn pointer(&self, index: usize, role: ComRole) -> Result<*mut c_void> {
        let original = self.originals.get(index).ok_or(Error::State)?.as_ref().get_ref();
        need(original.role == role && original.state.get() == SlotState::Owned)?;
        let pointer = unsafe { *original.pointer.get() }; need(!pointer.is_null())?; Ok(pointer)
    }
    fn invoke(&mut self, boundary: &dyn InstallerBoundary, effect: ComEffect, object: Option<usize>,
        other: Option<usize>, slot: Option<usize>, text: &str, bytes: &[u8], cleanup: bool) -> Result<Pin<Box<ComCall>>> {
        if cleanup {
            boundary.settlement_boundary();
            need(self.caller == thread::current().id() && self.call.is_none() && !self.unknown)?;
        } else { self.before(boundary)?; }
        need(text.encode_utf16().count() < NAME_UNITS && !text.contains('\0') && bytes.len() <= data::LINK_LIMIT)?;
        let role = match effect {
            ComEffect::ModuleName | ComEffect::Export | ComEffect::FreeModule => Some(ComRole::Module),
            ComEffect::NewLink => Some(ComRole::Factory),
            ComEffect::GetFlags => Some(ComRole::LinkData),
            ComEffect::PersistLoad | ComEffect::PersistSave | ComEffect::PersistSize => Some(ComRole::Persist),
            ComEffect::StreamRead(_) | ComEffect::StreamWrite | ComEffect::StreamSeek(_) => Some(ComRole::Stream),
            ComEffect::SetPath | ComEffect::SetDescription | ComEffect::SetWorking | ComEffect::SetArguments
                | ComEffect::SetShow | ComEffect::SetHotkey | ComEffect::SetIcon
                | ComEffect::GetPath | ComEffect::GetDescription | ComEffect::GetWorking | ComEffect::GetArguments
                | ComEffect::GetShow | ComEffect::GetHotkey | ComEffect::GetIcon | ComEffect::Query(_) => Some(ComRole::Link),
            ComEffect::Release => Some(self.originals.get(object.ok_or(Error::State)?).ok_or(Error::State)?.role),
            _ => None,
        };
        let pointer = match (object, role) { (Some(i), Some(r)) => self.pointer(i, r)?, (None, None) => null_mut(), _ => return Err(Error::State) };
        let uses_stream = matches!(effect, ComEffect::PersistLoad | ComEffect::PersistSave);
        need(uses_stream == other.is_some())?;
        let stream = if let Some(i) = other { self.pointer(i, ComRole::Stream)? } else { null_mut() };
        let output_role = match effect {
            ComEffect::LoadModule => Some(ComRole::Module), ComEffect::Factory => Some(ComRole::Factory),
            ComEffect::NewLink => Some(ComRole::Link), ComEffect::NewStream => Some(ComRole::Stream),
            ComEffect::Query(ComRole::Persist) => Some(ComRole::Persist),
            ComEffect::Query(ComRole::LinkData) => Some(ComRole::LinkData),
            ComEffect::Query(_) => return Err(Error::State), _ => None,
        };
        need(slot.is_some() == output_role.is_some())?;
        if let (Some(index), Some(role)) = (slot, output_role) {
            need(self.originals.get(index).ok_or(Error::State)?.role == role)?;
        }
        if matches!(effect, ComEffect::Factory) { need(self.factory_entry.is_some())?; }
        if let ComEffect::StreamRead(count) = effect { need(count > 0 && count <= data::LINK_LIMIT + 1)?; }
        if let ComEffect::StreamSeek(origin) = effect { need(origin <= 2)?; }
        if matches!(effect, ComEffect::Release) { need(role != Some(ComRole::Module))?; }
        let mut frame = Box::pin(ComCall { effect, phase: Cell::new(Phase::Prepared), returned: Cell::new(None), slot,
            object: pointer, other: stream, output: null_mut(), factory: self.factory_entry,
            export: UnsafeCell::new(None), text: wide(text), bytes: bytes.to_vec(),
            output_bytes: UnsafeCell::new([0; data::LINK_LIMIT + 1]), output_text: UnsafeCell::new([0; NAME_UNITS]),
            count: UnsafeCell::new(u32::MAX), number: UnsafeCell::new(i32::MIN),
            large: UnsafeCell::new(u64::MAX), word: UnsafeCell::new(u16::MAX), _pin: PhantomPinned });
        let setup = unsafe { frame.as_mut().get_unchecked_mut() };
        if let Some(index) = slot {
            let original = self.originals.get(index).ok_or(Error::State)?.as_ref().get_ref();
            need(original.state.get() == SlotState::Reserved)?;
            setup.output = original.pointer.get(); original.state.set(SlotState::Acquiring);
        }
        if matches!(effect, ComEffect::Initialize) {
            need(!self.apartment_entered)?; self.apartment_entered = true;
        } else if matches!(effect, ComEffect::Uninitialize) {
            need(self.initialized && !self.uninitialized)?; self.uninitialized = true;
        } else if matches!(effect, ComEffect::Release | ComEffect::FreeModule) {
            self.originals[object.ok_or(Error::State)?].state.set(SlotState::Closing);
        }
        self.call = Some(ManuallyDrop::new(frame));
        let f = self.call.as_ref().ok_or(Error::Unknown)?.as_ref().get_ref(); f.phase.set(Phase::Entered);
        // SAFETY: objects come only from the fixed OS class factory/interfaces;
        // each has a retained original reference, role and pinned output storage.
        let returned = unsafe {
            let link = || &**(f.object as *const *const LinkTable);
            let stream = || &**(f.object as *const *const StreamTable);
            let persist = || &**(f.object as *const *const PersistTable);
            let hr = match effect {
                ComEffect::Initialize => COM::CoInitializeEx(null(), COM::COINIT_APARTMENTTHREADED as u32 | COM::COINIT_DISABLE_OLE1DDE as u32),
                ComEffect::LoadModule => {
                    *f.output = windows_sys::Win32::System::LibraryLoader::LoadLibraryExW(f.text.as_ptr(), null_mut(),
                        windows_sys::Win32::System::LibraryLoader::LOAD_LIBRARY_SEARCH_SYSTEM32);
                    if (*f.output).is_null() { f.returned.set(Some(Returned::Boolean(0, F::GetLastError()))); } else { f.returned.set(Some(Returned::Boolean(1, 0))); }
                    0
                },
                ComEffect::ModuleName => {
                    let count = windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW(f.object,
                        f.output_text.get().cast(), NAME_UNITS as u32);
                    f.returned.set(Some(Returned::Count(count, if count == 0 { F::GetLastError() } else { 0 }))); 0
                },
                ComEffect::Export => {
                    *f.export.get() = windows_sys::Win32::System::LibraryLoader::GetProcAddress(f.object, c"DllGetClassObject".as_ptr().cast());
                    f.returned.set(Some(Returned::Boolean(i32::from((*f.export.get()).is_some()),
                        if (*f.export.get()).is_none() { F::GetLastError() } else { 0 }))); 0
                },
                ComEffect::Factory => (f.factory.ok_or(Error::State)?)(&SHELL_LINK, &FACTORY_IID, f.output),
                ComEffect::NewLink => ((&**(f.object as *const *const FactoryTable)).create)(f.object, null_mut(), &LINK_IID, f.output),
                ComEffect::NewStream => STG::CreateStreamOnHGlobal(null_mut(), 1, f.output),
                ComEffect::Query(role) => {
                    let iid = match role { ComRole::Persist => &PERSIST_IID, ComRole::LinkData => &DATA_IID, _ => return Err(Error::State) };
                    (link().base.query)(f.object, iid, f.output)
                },
                ComEffect::SetPath => (link().set_path)(f.object, f.text.as_ptr()),
                ComEffect::SetDescription => (link().set_description)(f.object, f.text.as_ptr()),
                ComEffect::SetWorking => (link().set_working)(f.object, f.text.as_ptr()),
                ComEffect::SetArguments => (link().set_arguments)(f.object, f.text.as_ptr()),
                ComEffect::SetShow => (link().set_show)(f.object, 1),
                ComEffect::SetHotkey => (link().set_hotkey)(f.object, 0),
                ComEffect::SetIcon => (link().set_icon)(f.object, f.text.as_ptr(), 0),
                ComEffect::GetPath => (link().get_path)(f.object, f.output_text.get().cast(), NAME_UNITS as i32, null_mut(), SH::SLGP_RAWPATH as u32),
                ComEffect::GetDescription => (link().get_description)(f.object, f.output_text.get().cast(), NAME_UNITS as i32),
                ComEffect::GetWorking => (link().get_working)(f.object, f.output_text.get().cast(), NAME_UNITS as i32),
                ComEffect::GetArguments => (link().get_arguments)(f.object, f.output_text.get().cast(), NAME_UNITS as i32),
                ComEffect::GetShow => (link().get_show)(f.object, f.number.get()),
                ComEffect::GetHotkey => (link().get_hotkey)(f.object, f.word.get()),
                ComEffect::GetIcon => (link().get_icon)(f.object, f.output_text.get().cast(), NAME_UNITS as i32, f.number.get()),
                ComEffect::GetFlags => ((&**(f.object as *const *const LinkDataTable)).get_flags)(f.object, f.count.get()),
                ComEffect::PersistLoad => (persist().load)(f.object, f.other),
                ComEffect::PersistSave => (persist().save)(f.object, f.other, 1),
                ComEffect::PersistSize => (persist().size)(f.object, f.large.get()),
                ComEffect::StreamRead(count) => {
                    if count == 0 || count > data::LINK_LIMIT + 1 { return Err(Error::Bounds); }
                    (stream().read)(f.object, f.output_bytes.get().cast(), count as u32, f.count.get())
                },
                ComEffect::StreamWrite => (stream().write)(f.object, f.bytes.as_ptr().cast(), f.bytes.len() as u32, f.count.get()),
                ComEffect::StreamSeek(origin) => (stream().seek)(f.object, 0, origin, f.large.get()),
                ComEffect::Release => {
                    let count = ((&**(f.object as *const *const UnknownTable)).release)(f.object);
                    f.returned.set(Some(Returned::Scalar(count))); 0
                },
                ComEffect::FreeModule => {
                    f.returned.set(Some(boolean(windows_sys::Win32::Foundation::FreeLibrary(f.object)))); 0
                },
                ComEffect::Uninitialize => { COM::CoUninitialize(); f.returned.set(Some(Returned::Scalar(0))); 0 },
            };
            f.returned.get().unwrap_or(Returned::Hresult(hr))
        };
        f.returned.set(Some(returned)); f.phase.set(Phase::Returned);
        let result = self.finish_call(object);
        if cleanup {
            if let Err(error) = result.as_ref() { self.latch(*error); }
            boundary.settlement_boundary(); result
        } else { self.after(boundary, result) }
    }
    fn finish_call(&mut self, released: Option<usize>) -> Result<Pin<Box<ComCall>>> {
        let f = self.call.as_ref().ok_or(Error::Unknown)?.as_ref().get_ref();
        need(f.phase.get() == Phase::Returned)?;
        let returned = f.returned.get().ok_or(Error::Unknown)?; let effect = f.effect;
        let mut result = match returned {
            Returned::Hresult(0) => Ok(()),
            Returned::Hresult(1) if matches!(effect, ComEffect::Initialize | ComEffect::StreamRead(_)) => Ok(()),
            Returned::Hresult(HRESULT_PENDING) => Err(Error::Unknown),
            Returned::Hresult(_) => Err(Error::Unavailable),
            Returned::Boolean(ok, error) => mutation_return(ok, error),
            Returned::Count(count, 0) if count > 0 && count < NAME_UNITS as u32 => Ok(()),
            Returned::Scalar(_) if matches!(effect, ComEffect::Release | ComEffect::Uninitialize) => Ok(()),
            _ => Err(Error::Unknown),
        };
        if matches!(effect, ComEffect::Initialize) && result.is_ok() { self.initialized = true; }
        if let Some(index) = f.slot {
            let original = self.originals.get(index).ok_or(Error::Unknown)?.as_ref().get_ref();
            let pointer = unsafe { *original.pointer.get() };
            if result.is_ok() && !pointer.is_null() { original.state.set(SlotState::Owned); }
            else if result == Err(Error::Unavailable) && pointer.is_null() { original.state.set(SlotState::NoHandle); }
            else { original.state.set(SlotState::Unknown); result = Err(Error::Unknown); }
        }
        if matches!(effect, ComEffect::Release | ComEffect::FreeModule) {
            self.originals[released.ok_or(Error::Unknown)?].state.set(if result.is_ok() { SlotState::Closed } else { SlotState::Unknown });
        }
        if result == Err(Error::Unknown) { self.unknown = true; return Err(Error::Unknown); }
        f.phase.set(Phase::Complete);
        let held = self.call.take().ok_or(Error::Unknown)?;
        let completed = ManuallyDrop::into_inner(held);
        result?; Ok(completed)
    }
    fn initialize_once(&mut self, boundary: &dyn InstallerBoundary, system: &str) -> Result<()> {
        need(data::native_dos_path(system))?;
        self.invoke(boundary, ComEffect::Initialize, None, None, None, "", &[], false)?;
        // Fixed OS-derived local DLL, fixed export/class/IID. Never consult a
        // user-supplied COM registration, path, class, expansion or search path.
        let path = format!(r"{system}\shell32.dll");
        let module = self.reserve(ComRole::Module)?;
        self.module = Some(module);
        self.invoke(boundary, ComEffect::LoadModule, None, None, Some(module), &path, &[], false)?;
        let observed = self.invoke(boundary, ComEffect::ModuleName, Some(module), None, None, "", &[], false)?;
        need(Self::text(&observed)?.eq_ignore_ascii_case(&path))?;
        let export = self.invoke(boundary, ComEffect::Export, Some(module), None, None, "", &[], false)?;
        let pointer = unsafe { *export.export.get() }.ok_or(Error::Unavailable)?;
        // SDK DllGetClassObject exact ABI, for this one fixed system export.
        self.factory_entry = Some(unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, FactoryFn>(pointer) });
        let factory = self.reserve(ComRole::Factory)?; self.factory = Some(factory);
        self.invoke(boundary, ComEffect::Factory, None, None, Some(factory), "", &[], false)?;
        Ok(())
    }
    fn text(call: &ComCall) -> Result<String> {
        let words = unsafe { &*call.output_text.get() };
        let end = words.iter().position(|w| *w == 0).ok_or(Error::Bounds)?;
        String::from_utf16(&words[..end]).map_err(|_| Error::Unsafe)
    }
    fn new_link(&mut self, boundary: &dyn InstallerBoundary) -> Result<(usize, usize, usize)> {
        let link = self.reserve(ComRole::Link)?;
        self.invoke(boundary, ComEffect::NewLink, self.factory, None, Some(link), "", &[], false)?;
        let persist = self.reserve(ComRole::Persist)?;
        self.invoke(boundary, ComEffect::Query(ComRole::Persist), Some(link), None, Some(persist), "", &[], false)?;
        let list = self.reserve(ComRole::LinkData)?;
        self.invoke(boundary, ComEffect::Query(ComRole::LinkData), Some(link), None, Some(list), "", &[], false)?;
        Ok((link, persist, list))
    }
    fn new_stream(&mut self, boundary: &dyn InstallerBoundary) -> Result<usize> {
        let stream = self.reserve(ComRole::Stream)?;
        self.invoke(boundary, ComEffect::NewStream, None, None, Some(stream), "", &[], false)?; Ok(stream)
    }
    fn validate_link(&mut self, boundary: &dyn InstallerBoundary, link: usize, list: usize) -> Result<String> {
        let flags = self.invoke(boundary, ComEffect::GetFlags, Some(list), None, None, "", &[], false)?;
        let flags = unsafe { *flags.count.get() };
        // Only fields authored below; no advertised/Darwin, expansion, elevation,
        // relative/cwd, tracking-target metadata or other special execution data.
        let allowed = (SH::SLDF_HAS_ID_LIST | SH::SLDF_HAS_LINK_INFO | SH::SLDF_HAS_NAME
            | SH::SLDF_HAS_ICONLOCATION | SH::SLDF_UNICODE) as u32;
        need(flags & !allowed == 0)?;
        let path = self.invoke(boundary, ComEffect::GetPath, Some(link), None, None, "", &[], false)?;
        let path = Self::text(&path)?; need(data::native_dos_path(&path))?;
        for (effect, expected) in [(ComEffect::GetWorking, ""), (ComEffect::GetArguments, ""), (ComEffect::GetDescription, "Mobile Release Kit")] {
            let current = self.invoke(boundary, effect, Some(link), None, None, "", &[], false)?;
            need(Self::text(&current)? == expected)?;
        }
        let show = self.invoke(boundary, ComEffect::GetShow, Some(link), None, None, "", &[], false)?;
        need(unsafe { *show.number.get() } == 1)?;
        let key = self.invoke(boundary, ComEffect::GetHotkey, Some(link), None, None, "", &[], false)?;
        need(unsafe { *key.word.get() } == 0)?;
        let icon = self.invoke(boundary, ComEffect::GetIcon, Some(link), None, None, "", &[], false)?;
        need(Self::text(&icon)? == path && unsafe { *icon.number.get() } == 0)?; Ok(path)
    }
    fn encode(&mut self, boundary: &dyn InstallerBoundary, target: &str) -> Result<Vec<u8>> {
        need(data::native_dos_path(target))?;
        let (link, persist, list) = self.new_link(boundary)?;
        for (effect, text) in [(ComEffect::SetPath, target), (ComEffect::SetDescription, "Mobile Release Kit"),
            (ComEffect::SetWorking, ""), (ComEffect::SetArguments, ""), (ComEffect::SetShow, ""),
            (ComEffect::SetHotkey, ""), (ComEffect::SetIcon, target)] {
            self.invoke(boundary, effect, Some(link), None, None, text, &[], false)?;
        }
        need(self.validate_link(boundary, link, list)? == target)?;
        let size = self.invoke(boundary, ComEffect::PersistSize, Some(persist), None, None, "", &[], false)?;
        need(unsafe { *size.large.get() } <= data::LINK_LIMIT as u64)?;
        let stream = self.new_stream(boundary)?;
        self.invoke(boundary, ComEffect::PersistSave, Some(persist), Some(stream), None, "", &[], false)?;
        let size = self.invoke(boundary, ComEffect::StreamSeek(1), Some(stream), None, None, "", &[], false)?;
        let length = unsafe { *size.large.get() } as usize; need(length > 0 && length <= data::LINK_LIMIT)?;
        let start = self.invoke(boundary, ComEffect::StreamSeek(0), Some(stream), None, None, "", &[], false)?;
        need(unsafe { *start.large.get() } == 0)?;
        let content = self.invoke(boundary, ComEffect::StreamRead(length), Some(stream), None, None, "", &[], false)?;
        need(unsafe { *content.count.get() } as usize == length)?;
        let bytes = unsafe { (*content.output_bytes.get())[..length].to_vec() };
        let end = self.invoke(boundary, ComEffect::StreamRead(1), Some(stream), None, None, "", &[], false)?;
        need(unsafe { *end.count.get() } == 0)?; Ok(bytes)
    }
    fn decode(&mut self, boundary: &dyn InstallerBoundary, bytes: &[u8]) -> Result<String> {
        need(!bytes.is_empty() && bytes.len() <= data::LINK_LIMIT)?;
        let (link, persist, list) = self.new_link(boundary)?;
        let stream = self.new_stream(boundary)?;
        let write = self.invoke(boundary, ComEffect::StreamWrite, Some(stream), None, None, "", bytes, false)?;
        need(unsafe { *write.count.get() } as usize == bytes.len())?;
        let start = self.invoke(boundary, ComEffect::StreamSeek(0), Some(stream), None, None, "", &[], false)?;
        need(unsafe { *start.large.get() } == 0)?;
        self.invoke(boundary, ComEffect::PersistLoad, Some(persist), Some(stream), None, "", &[], false)?;
        let cursor = self.invoke(boundary, ComEffect::StreamSeek(1), Some(stream), None, None, "", &[], false)?;
        need(unsafe { *cursor.large.get() } == bytes.len() as u64)?;
        self.validate_link(boundary, link, list)
    }
    fn settle_once(&mut self, boundary: &dyn InstallerBoundary) {
        if self.settling { return; } self.settling = true;
        if self.call.is_some() || self.unknown { self.unknown = true; return; }
        for index in (0..self.originals.len()).rev() {
            let state = self.originals[index].state.get(); let role = self.originals[index].role;
            if state == SlotState::Reserved { self.originals[index].state.set(SlotState::NoHandle); continue; }
            if state != SlotState::Owned { continue; }
            if role == ComRole::Module && self.originals.iter().any(|o| o.role != ComRole::Module
                && !matches!(o.state.get(), SlotState::Closed | SlotState::NoHandle)) { continue; }
            let effect = if role == ComRole::Module { ComEffect::FreeModule } else { ComEffect::Release };
            if let Err(error) = self.invoke(boundary, effect, Some(index), None, None, "", &[], true) {
                self.cleanup.push(SelectionCleanupError { original: SelectionOriginal::ComReference, record: index, error });
            }
        }
        if self.originals.iter().all(|o| matches!(o.state.get(), SlotState::Closed | SlotState::NoHandle)) && self.initialized && !self.uninitialized {
            if let Err(error) = self.invoke(boundary, ComEffect::Uninitialize, None, None, None, "", &[], true) {
                self.cleanup.push(SelectionCleanupError { original: SelectionOriginal::Apartment, record: 0, error });
            }
        }
    }
    fn closed(&self) -> bool {
        self.settling && !self.unknown && self.call.is_none() && (!self.initialized || self.uninitialized)
            && self.originals.iter().all(|o| matches!(o.state.get(), SlotState::Closed | SlotState::NoHandle)) && self.cleanup.is_empty()
    }
}


/// A protected PROFILE observed by this original owner. Bytes are DATA; the safe
/// adapter decodes the EXISTING profile schema, then returns only expected rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionProfileInput { pub image: String, pub bytes: Vec<u8> }

pub(super) struct SelectionBinding {
    pub(super) image: String, pub(super) runtime: String, pub(super) sizes: [u64; 54],
    pub(super) installer: Installer, pub(super) program_files: String,
    pub(super) acquisition: Arc<()>, pub(super) activated: Vec<(String, Facts)>,
}

struct Provenance {
    image: String, directory: usize, profile: usize, launch: usize, bytes: Vec<u8>,
    expected: Option<SelectionImageData>,
}
struct RecoveryOriginals {
    run: String, directory: usize, records: Vec<usize>, record: data::RecoveryRecord,
    backup: Option<usize>, incoming: Option<usize>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Use { Preview, Apply }

/// Actual readonly54/runtime47 storage, not acquisition copy proofs. The selected
/// shell and directory originals remain held until selection settlement. Leaves
/// remain held through selection; closed selection-only capacities cover the exact rosters.
struct ReadonlyImage {
    inputs: FileOwner, runtime: FileOwner, image: SelectionImageData,
    shell: Option<usize>, complete: bool, observation: Option<String>, bytes: u64,
}
impl ReadonlyImage {
    fn new(image: SelectionImageData) -> Self {
        Self { inputs: FileOwner::new(SelectionOriginal::ImageInputs),
            runtime: FileOwner::new(SelectionOriginal::RuntimeImage), image,
            shell: None, complete: false, observation: None, bytes: 0 }
    }
    fn run(&mut self, boundary: &dyn InstallerBoundary, installer: &Installer) -> Result<()> {
        need(!self.complete && self.image.shape_valid())?;
        let layout = InputLayout::new(&self.image.runtime, &self.image.helper, &self.image.image).ok_or(Error::Unsafe)?;
        let retained: Vec<(String, u64, String, bool)> = layout.paths.iter().enumerate().map(|(i, p)|
            (p.output.clone(), self.image.input_sizes[i], self.image.input_hashes[i].clone(), p.image())).collect();
        let public_prefix = format!("installer-input/{}/{}", data::TARGET, self.image.image);
        let private_prefix = format!("runtime-input/{}/{}", data::TARGET, self.image.image);
        let (shell, input_bytes) = Self::walk(&mut self.inputs, boundary, installer, &retained,
            &[private_prefix, public_prefix.clone()], Some(&public_prefix))?;
        self.shell = shell; self.bytes = input_bytes;
        let runtime_prefix = format!("versions/{}/{}", data::TARGET, self.image.runtime);
        let published: Vec<(String, u64, String, bool)> = PUBLICATION_PAYLOADS.iter().enumerate().map(|(i, leaf)|
            (format!("{runtime_prefix}/{leaf}"), self.image.input_sizes[i], self.image.input_hashes[i].clone(),
                leaf.ends_with(".exe") || leaf.ends_with(".dll") || leaf.ends_with(".pyd"))).collect();
        let (_, runtime_bytes) = Self::walk(&mut self.runtime, boundary, installer, &published, &[runtime_prefix], None)?;
        self.bytes = self.bytes.checked_add(runtime_bytes).ok_or(Error::Bounds)?;
        need(self.shell.is_some())?;
        let mut snapshot = Vec::new();
        // Immutable payload facts and their complete expected hashes. Parent
        // namespace timestamps not changed by these readonly walks are included.
        for owner in [&self.inputs, &self.runtime] {
            for node in &owner.nodes {
                bounded_field(&mut snapshot, &facts_bytes(&node.path, &node.facts)?)?;
            }
        }
        self.observation = Some(hash(&snapshot)); self.complete = true; Ok(())
    }
    fn walk(owner: &mut FileOwner, boundary: &dyn InstallerBoundary, installer: &Installer,
        rows: &[(String, u64, String, bool)], immutable_roots: &[String],
        retained_public: Option<&str>) -> Result<(Option<usize>, u64)> {
        owner.admit_installer(boundary)?;
        need(owner.installer.as_ref() == Some(installer))?;
        owner.discover(boundary, &[LocationKind::ProgramFiles])?;
        let pf = owner.root(boundary, 0)?;
        owner.entries(boundary, pf, Some(&["Mobile Release Kit".to_owned()]))?;
        let mrk = owner.child(boundary, pf, "Mobile Release Kit", FileKind::Directory,
            AuthorityScope::ImmutableVersion, false)?.ok_or(Error::Unsafe)?;
        exact_security(&owner.nodes[mrk].facts.security, FileKind::Directory, false, true)?;
        let mut paths = BTreeMap::from([(String::new(), mrk)]);
        let mut directories = BTreeSet::new();
        for (path, _, _, _) in rows {
            let mut current = path.as_str();
            while let Some((parent, _)) = current.rsplit_once('/') {
                directories.insert(parent.to_owned()); current = parent;
            }
        }
        let mut directories: Vec<_> = directories.into_iter().collect();
        directories.sort_by_key(|p| (p.split('/').count(), p.clone()));
        let mut all = vec![String::new()]; all.extend(directories.iter().cloned());
        for path in &all {
            let index = *paths.get(path).ok_or(Error::State)?;
            let strict = immutable_roots.iter().any(|root| path == root || path.starts_with(&format!("{root}/")));
            let mut names = BTreeSet::new();
            for candidate in directories.iter().chain(rows.iter().map(|r| &r.0)) {
                let (parent, name) = candidate.rsplit_once('/').unwrap_or(("", candidate.as_str()));
                if parent == path.as_str() { names.insert(name.to_owned()); }
            }
            let selected: Vec<_> = names.into_iter().collect();
            owner.entries(boundary, index, if strict { None } else { Some(&selected) })?;
            for child in directories.iter().filter(|p| p.rsplit_once('/').map_or("", |(d, _)| d) == path.as_str()) {
                let name = child.rsplit('/').next().ok_or(Error::State)?;
                let node = owner.child(boundary, index, name, FileKind::Directory,
                    AuthorityScope::ImmutableVersion, false)?.ok_or(Error::Unsafe)?;
                let public = match retained_public {
                    None => true,
                    Some(prefix) => child.as_str() == "installer-input"
                        || child == &format!("installer-input/{}", data::TARGET)
                        || child.as_str() == prefix || child == &format!("{prefix}/shell"),
                };
                exact_security(&owner.nodes[node].facts.security, FileKind::Directory, false, public)?;
                paths.insert(child.clone(), node);
            }
        }
        let mut shell = None; let mut bytes = 0u64;
        for (path, size, digest, image) in rows {
            let (parent, name) = path.rsplit_once('/').ok_or(Error::State)?;
            let parent = *paths.get(parent).ok_or(Error::State)?;
            owner.recheck_installer(boundary)?;
            let index = owner.child(boundary, parent, name, FileKind::File,
                AuthorityScope::ImmutableVersion, false)?.ok_or(Error::Unsafe)?;
            let public = retained_public.is_none() || path.ends_with("/shell/mobile-release-kit-desktop.exe");
            exact_security(&owner.nodes[index].facts.security, FileKind::File, *image, public)?;
            owner.read_file(boundary, index, *size, Some(digest), false)?;
            bytes = bytes.checked_add(*size).ok_or(Error::Bounds)?;
            if retained_public.is_some() && path.ends_with("/shell/mobile-release-kit-desktop.exe") {
                need(shell.replace(index).is_none())?;
            }
            // Retain every original until selection settles. Closing a verified
            // payload here would permit a later writer before launch selection.
        }
        for (path, index) in &paths {
            let mut expected = BTreeMap::new();
            for (child_path, child) in &paths {
                if !child_path.is_empty()
                    && child_path.rsplit_once('/').map_or("", |(p, _)| p) == path.as_str() {
                    expected.insert(child_path.rsplit('/').next().ok_or(Error::State)?.to_owned(), owner.nodes[*child].facts.metadata.clone());
                }
            }
            for (row, _, _, _) in rows {
                let (parent, name) = row.rsplit_once('/').ok_or(Error::State)?;
                if parent == path.as_str() {
                    let absolute = owner.child_path(*index, name)?;
                    let file = *owner.by_path.get(&absolute).ok_or(Error::State)?;
                    expected.insert(name.to_owned(), owner.nodes[file].facts.metadata.clone());
                }
            }
            exact_entries(owner.nodes[*index].entries.as_ref().ok_or(Error::State)?, &expected)?;
            owner.recheck(boundary, *index)?;
        }
        owner.recheck_locations(boundary)?; owner.recheck_installer(boundary)?; Ok((shell, bytes))
    }
    fn recheck_target(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        need(self.complete && self.observation.is_some())?;
        let shell = self.shell.ok_or(Error::State)?;
        self.inputs.recheck(boundary, shell)?;
        // Parent/I/runtime namespaces remain unchanged. Only the MRK ancestor
        // can gain this owner's separately recorded selection directory.
        for owner in [&mut self.inputs, &mut self.runtime] {
            for index in 0..owner.nodes.len() {
                let node = &owner.nodes[index];
                if node.path.contains(r"\Mobile Release Kit\") {
                    owner.recheck(boundary, index)?;
                }
            }
            owner.recheck_locations(boundary)?; owner.recheck_installer(boundary)?;
        }
        Ok(())
    }
    fn settle_once(&mut self, boundary: &dyn InstallerBoundary) {
        self.inputs.settle_once(boundary); self.runtime.settle_once(boundary);
    }
    fn closed(&self) -> bool { self.inputs.known_closed() && self.runtime.known_closed() }
}

/// This original is retained by the safe application's process-lifetime OWNER
/// before observe/apply. No public bridge, generic command or installer is added.
pub struct SelectionOwner {
    caller: ThreadId, use_: Use, mode: SelectionMode, proposed: SelectionImageData,
    confirmed: Option<SelectionPreview>, binding: Option<SelectionBinding>,
    recovery_id: Option<String>, files: FileOwner, registry: RegistryOwner, codec: LinkCodec,
    program_files: Option<usize>, programs: Option<usize>, mrk: Option<usize>,
    selection: Option<usize>, selection_target: Option<usize>, selector: Option<usize>,
    selector_bytes: Vec<u8>, selector_image: Option<String>, before_registry: Option<RegistrySnapshot>,
    provenances: Vec<Provenance>, recovery: Option<RecoveryOriginals>, verification: Option<ReadonlyImage>,
    before_image: Option<String>, chosen_image: Option<String>, proposed_registry: data::Registration,
    observed: bool, bound: bool, preview: Option<SelectionPreview>, applying: bool,
    run: Option<String>, recovery_output: Option<usize>, incoming: Option<usize>,
    old_descriptor: Vec<u8>, new_descriptor: Vec<u8>, new_link: Vec<u8>,
    first: Option<Error>, settling: bool, report: SelectionReport,
    #[cfg(feature = "installer-selection-fixture")]
    fixture_case: Option<super::installer_selection_fixture_data::SelectionFixtureCase>,
    #[cfg(feature = "installer-selection-fixture")]
    fixture_competitor: Option<RegistryOwner>,
    #[cfg(feature = "installer-selection-fixture")]
    fixture_conflict_staged: bool,
    #[cfg(feature = "installer-selection-fixture")]
    fixture_competitor_report: Option<SelectionReport>,
}
// SAFETY: all pointers refer to owned pinned originals. Moving storage does not
// move a native allocation. Every operation/cleanup rejects another thread; Drop
// calls no native finalizer. The safe adapter additionally serializes OWNER.
unsafe impl Send for SelectionOwner {}

impl SelectionOwner {
    fn new(use_: Use, mode: SelectionMode, proposed: SelectionImageData,
        confirmed: Option<SelectionPreview>, recovery: Option<String>, binding: Option<SelectionBinding>) -> Result<Self> {
        need(proposed.shape_valid() && hash(&proposed.profile) == proposed.image
            && recovery.as_ref().is_none_or(|r| data::recovery_id(r))
            && mode.recovery() == recovery.is_some()
            && (use_ == Use::Preview) == confirmed.is_none()
            && (binding.is_some() == (use_ == Use::Apply && mode == SelectionMode::InstallActivated)))?;
        if let Some(value) = &confirmed { need(value.mode == mode)?; }
        Ok(Self { caller: thread::current().id(), use_, mode, proposed, confirmed, binding, recovery_id: recovery,
            files: FileOwner::new(SelectionOriginal::Files), registry: RegistryOwner::new(), codec: LinkCodec::new(),
            program_files: None, programs: None, mrk: None, selection: None, selection_target: None,
            selector: None, selector_bytes: Vec::new(), selector_image: None, before_registry: None,
            provenances: Vec::new(), recovery: None, verification: None,
            before_image: None, chosen_image: None, proposed_registry: data::Registration::new(),
            observed: false, bound: false, preview: None, applying: false, run: None,
            recovery_output: None, incoming: None, old_descriptor: Vec::new(), new_descriptor: Vec::new(),
            new_link: Vec::new(), first: None, settling: false, report: SelectionReport::new(mode),
            #[cfg(feature = "installer-selection-fixture")]
            fixture_case: None,
            #[cfg(feature = "installer-selection-fixture")]
            fixture_competitor: None,
            #[cfg(feature = "installer-selection-fixture")]
            fixture_conflict_staged: false,
            #[cfg(feature = "installer-selection-fixture")]
            fixture_competitor_report: None,
        })
    }
    pub fn for_preview(mode: SelectionMode, proposed: SelectionImageData, recovery: Option<String>) -> Result<Self> {
        Self::new(Use::Preview, mode, proposed, None, recovery, None)
    }
    pub fn for_maintenance(confirmed: SelectionPreview, proposed: SelectionImageData, recovery: Option<String>) -> Result<Self> {
        need(confirmed.mode != SelectionMode::InstallActivated)?;
        Self::new(Use::Apply, confirmed.mode, proposed, Some(confirmed), recovery, None)
    }
    pub fn for_activated(confirmed: SelectionPreview, proposed: SelectionImageData,
        acquisition: &super::installer_acquisition::InputAcquisition,
        prerequisite: &super::installer_webview2::OfflineWebView2Owner,
        runtime: &super::publication::Publication) -> Result<Self> {
        need(confirmed.mode == SelectionMode::InstallActivated)?;
        let binding = acquisition.selection_binding(prerequisite, runtime)?;
        need(binding.image == proposed.image && binding.runtime == proposed.runtime && binding.sizes == proposed.input_sizes)?;
        Self::new(Use::Apply, SelectionMode::InstallActivated, proposed, Some(confirmed), None, Some(binding))
    }
    fn before(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        need(self.caller == thread::current().id() && !self.settling && self.first.is_none())?;
        boundary.producing_boundary()
    }
    fn retain<T>(&mut self, phase: &'static str, returned: Result<T>) -> Result<T> {
        if let Err(error) = returned.as_ref() {
            if self.first.is_none() { self.first = Some(*error); }
            self.report.fail(phase, *error == Error::Unknown || self.unknown());
        }
        returned
    }
    fn unknown(&self) -> bool {
        #[cfg(feature = "installer-selection-fixture")]
        if self.fixture_competitor.as_ref().is_some_and(|r| r.unknown || r.call.is_some()) { return true; }
        self.files.unknown || self.files.active() || self.files.book.is_unknown()
            || self.registry.unknown || self.registry.call.is_some() || self.codec.unknown || self.codec.call.is_some()
            || self.verification.as_ref().is_some_and(|v| v.inputs.unknown || v.runtime.unknown
                || v.inputs.active() || v.runtime.active() || v.inputs.book.is_unknown() || v.runtime.book.is_unknown())
    }
    fn product_root(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        self.files.admit_installer(boundary)?;
        self.files.discover(boundary, &[LocationKind::ProgramFiles, LocationKind::CommonPrograms, LocationKind::System])?;
        let pf = self.files.root(boundary, 0)?;
        let programs = self.files.root(boundary, 1)?;
        let system = self.files.root(boundary, 2)?;
        self.program_files = Some(pf); self.programs = Some(programs);
        need(self.files.locations[0].same_volume(&self.files.locations[1])
            && self.files.nodes[pf].facts.metadata.identity.volume_serial == self.files.nodes[programs].facts.metadata.identity.volume_serial)?;
        self.files.entries(boundary, pf, Some(&["Mobile Release Kit".to_owned()]))?;
        self.files.entries(boundary, programs, Some(&[data::SHORTCUT.to_owned()]))?;
        self.mrk = self.files.child(boundary, pf, "Mobile Release Kit", FileKind::Directory,
            AuthorityScope::ImmutableVersion, false)?;
        if let Some(mrk) = self.mrk {
            exact_security(&self.files.nodes[mrk].facts.security, FileKind::Directory, false, true)?;
            self.files.entries(boundary, mrk, Some(&["selection".to_owned()]))?;
            self.selection = self.files.child(boundary, mrk, "selection", FileKind::Directory,
                AuthorityScope::ImmutableVersion, false)?;
        }
        if let Some(selection) = self.selection {
            exact_security(&self.files.nodes[selection].facts.security, FileKind::Directory, false, false)?;
            self.files.entries(boundary, selection, Some(&[data::TARGET.to_owned(), "recovery".to_owned()]))?;
            self.selection_target = self.files.child(boundary, selection, data::TARGET, FileKind::Directory,
                AuthorityScope::ImmutableVersion, false)?;
            if let Some(target) = self.selection_target {
                exact_security(&self.files.nodes[target].facts.security, FileKind::Directory, false, false)?;
            }
        }
        let system_path = self.files.nodes[system].path.clone();
        self.codec.initialize_once(boundary, &system_path)?;
        if let Some(binding) = &self.binding {
            need(self.files.nodes[pf].path == binding.program_files
                && self.files.installer.as_ref() == Some(&binding.installer))?;
        }
        Ok(())
    }
    fn read_provenance(&mut self, boundary: &dyn InstallerBoundary, image: &str) -> Result<()> {
        if self.provenances.iter().any(|p| p.image == image) { return Ok(()); }
        need(data::digest(image) && self.provenances.len() < 3)?;
        let target = self.selection_target.ok_or(Error::Unsafe)?;
        let directory = self.files.child(boundary, target, image, FileKind::Directory,
            AuthorityScope::ImmutableVersion, false)?.ok_or(Error::Unsafe)?;
        exact_security(&self.files.nodes[directory].facts.security, FileKind::Directory, false, false)?;
        let profile = self.files.child(boundary, directory, "profile.json", FileKind::File,
            AuthorityScope::ImmutableVersion, false)?.ok_or(Error::Unsafe)?;
        let launch = self.files.child(boundary, directory, "launch.lnk", FileKind::File,
            AuthorityScope::ImmutableVersion, false)?.ok_or(Error::Unsafe)?;
        for node in [profile, launch] { exact_security(&self.files.nodes[node].facts.security, FileKind::File, false, false)?; }
        let size = self.files.nodes[profile].facts.metadata.size; need(size <= data::PROFILE_LIMIT as u64)?;
        self.files.read_file(boundary, profile, size, Some(image), true)?;
        let size = self.files.nodes[launch].facts.metadata.size; need(size <= data::LINK_LIMIT as u64)?;
        let bytes = self.files.read_file(boundary, launch, size, None, true)?;
        let pf = &self.files.nodes[self.program_files.ok_or(Error::State)?].path;
        let target_path = data::shell_target(pf, image).ok_or(Error::Unsafe)?;
        need(self.codec.decode(boundary, &bytes)? == target_path)?;
        let expected = BTreeMap::from([("profile.json".to_owned(), self.files.nodes[profile].facts.metadata.clone()),
            ("launch.lnk".to_owned(), self.files.nodes[launch].facts.metadata.clone())]);
        exact_entries(self.files.nodes[directory].entries.as_ref().ok_or(Error::State)?, &expected)?;
        self.provenances.push(Provenance { image: image.to_owned(), directory, profile, launch, bytes, expected: None });
        Ok(())
    }
    pub fn observe_once(&mut self, boundary: &dyn InstallerBoundary) -> Result<Vec<SelectionProfileInput>> {
        let returned = self.observe(boundary); self.retain("observe-owned-launch-entries", returned)
    }
    fn observe(&mut self, boundary: &dyn InstallerBoundary) -> Result<Vec<SelectionProfileInput>> {
        self.before(boundary)?; need(!self.observed)?; self.observed = true;
        if self.use_ == Use::Apply { self.registry.reserve_once(boundary)?; }
        self.product_root(boundary)?;
        let programs = self.programs.ok_or(Error::State)?;
        self.selector = self.files.child(boundary, programs, data::SHORTCUT, FileKind::File,
            AuthorityScope::ImmutableVersion, self.use_ == Use::Apply)?;
        if let Some(link) = self.selector {
            exact_security(&self.files.nodes[link].facts.security, FileKind::File, false, true)?;
            let size = self.files.nodes[link].facts.metadata.size; need(size <= data::LINK_LIMIT as u64)?;
            self.selector_bytes = self.files.read_file(boundary, link, size, None, true)?;
            self.old_descriptor = self.files.descriptor_of(link)?;
            let target = self.codec.decode(boundary, &self.selector_bytes)?;
            let pf = &self.files.nodes[self.program_files.ok_or(Error::State)?].path;
            self.selector_image = Some(data::image_hint_from_target(pf, &target).ok_or(Error::Unsafe)?);
        }
        let registration = self.registry.open_before(boundary)?;
        let registered_image = if registration.present {
            need(data::registration_shape(&registration.values))?;
            Some(data::image_hint_from_registration(&registration.values).ok_or(Error::Unsafe)?)
        } else { None };
        self.before_registry = Some(registration);
        if self.mode.recovery() { self.read_recovery(boundary)?; }
        let mut images = BTreeSet::new();
        if let Some(image) = &self.selector_image { images.insert(image.clone()); }
        if let Some(image) = &registered_image { images.insert(image.clone()); }
        let chosen = match self.mode {
            SelectionMode::InstallActivated => self.proposed.image.clone(),
            SelectionMode::RepairSameImage | SelectionMode::RemoveSelection => {
                if self.mode == SelectionMode::RepairSameImage {
                    need(self.selector_image.as_ref().is_none_or(|i| i == &self.proposed.image)
                        && registered_image.as_ref().is_none_or(|i| i == &self.proposed.image))?;
                }
                self.selector_image.as_ref().or(registered_image.as_ref()).cloned().unwrap_or_else(|| self.proposed.image.clone())
            },
            SelectionMode::RecoverPrevious => self.recovery.as_ref().ok_or(Error::State)?.record.before_image.clone().ok_or(Error::Unsafe)?,
            SelectionMode::RecoverCurrent => {
                let record = &self.recovery.as_ref().ok_or(Error::State)?.record;
                need(!record.new_link.is_empty() && !record.new_registry.is_empty())?;
                record.image.clone()
            },
        };
        if self.mode != SelectionMode::InstallActivated
            && (self.mode != SelectionMode::RemoveSelection || self.selector_image.is_some() || registered_image.is_some()) {
            images.insert(chosen.clone());
        }
        if let Some(recovery) = &self.recovery {
            images.insert(recovery.record.image.clone());
            if let Some(old) = &recovery.record.before_image { images.insert(old.clone()); }
        }
        if !self.mode.recovery() {
            need(self.selector_image.is_none() || registered_image.is_none() || self.selector_image == registered_image)?;
        }
        self.before_image = self.selector_image.clone().or(registered_image);
        self.chosen_image = self.mode.selects_image().then_some(chosen);
        for image in images { self.read_provenance(boundary, &image)?; }
        // Fresh Install preview describes intended bytes before acquisition; it
        // must not invent acquired originals or serialize target-dependent link bytes.
        if self.mode == SelectionMode::InstallActivated {
            if let Some(target) = self.selection_target {
                need(self.files.child(boundary, target, &self.proposed.image.clone(), FileKind::Directory,
                    AuthorityScope::ImmutableVersion, false)?.is_none())?;
            }
        }
        Ok(self.provenances.iter().map(|p| SelectionProfileInput {
            image: p.image.clone(), bytes: self.files.nodes[p.profile].read_bytes.clone().unwrap_or_default(),
        }).collect())
    }
}


impl SelectionOwner {
    fn read_recovery(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        let run = self.recovery_id.clone().ok_or(Error::State)?;
        let selection = self.selection.ok_or(Error::Unsafe)?;
        let root = self.files.child(boundary, selection, "recovery", FileKind::Directory,
            AuthorityScope::ImmutableVersion, false)?.ok_or(Error::Unsafe)?;
        exact_security(&self.files.nodes[root].facts.security, FileKind::Directory, false, false)?;
        self.files.entries(boundary, root, Some(&[run.clone()]))?;
        let directory = self.files.child(boundary, root, &run, FileKind::Directory,
            AuthorityScope::ImmutableVersion, false)?.ok_or(Error::Unsafe)?;
        exact_security(&self.files.nodes[directory].facts.security, FileKind::Directory, false, false)?;
        let rows = self.files.entries(boundary, directory, None)?;
        let names: BTreeSet<_> = (0..data::PHASES.len()).map(|n| format!("record-{n:02}.bin"))
            .chain(["incoming.lnk".to_owned(), "previous.lnk".to_owned()]).collect();
        need(rows.iter().all(|row| row.name == "." || row.name == ".."
            || (row.kind == FileKind::File && names.contains(&row.name))))?;
        let mut records = Vec::new(); let mut latest: Option<data::RecoveryRecord> = None;
        for (ordinal, phase) in data::PHASES.iter().enumerate() {
            let name = format!("record-{ordinal:02}.bin");
            let Some(index) = self.files.child(boundary, directory, &name, FileKind::File,
                AuthorityScope::ImmutableVersion, false)? else { continue; };
            exact_security(&self.files.nodes[index].facts.security, FileKind::File, false, false)?;
            let size = self.files.nodes[index].facts.metadata.size; need(size <= data::RECORD_LIMIT as u64)?;
            let raw = self.files.read_file(boundary, index, size, None, true)?;
            let current = data::RecoveryRecord::decode(&raw).ok_or(Error::Unsafe)?;
            need(current.run == run && current.phase == *phase)?;
            if let Some(previous) = latest.as_ref() {
                // Every immutable phase agrees on the original proposal. A later
                // record adds actual returns; it cannot rewrite original intent.
                let mut earlier = previous.clone();
                earlier.phase = current.phase; earlier.prior_returns = current.prior_returns.clone();
                need(earlier == current && current.prior_returns.starts_with(&previous.prior_returns))?;
            } else { need(ordinal == 0)?; }
            latest = Some(current); records.push(index);
        }
        let record = latest.ok_or(Error::Unsafe)?;
        let mut leaves = [None, None];
        for (ordinal, name, expected) in [(0, "previous.lnk", &record.old_link), (1, "incoming.lnk", &record.new_link)] {
            let Some(index) = self.files.child(boundary, directory, name, FileKind::File,
                AuthorityScope::ImmutableVersion, false)? else { continue; };
            need(!expected.is_empty())?;
            exact_security(&self.files.nodes[index].facts.security, FileKind::File, false, true)?;
            let bytes = self.files.read_file(boundary, index, expected.len() as u64, Some(&hash(expected)), true)?;
            need(bytes == *expected)?;
            let original_path = if ordinal == 0 {
                self.files.child_path(self.programs.ok_or(Error::State)?, data::SHORTCUT)?
            } else { self.files.child_path(directory, "incoming.lnk")? };
            let descriptor = if ordinal == 0 { &record.old_file_descriptor } else { &record.new_file_descriptor };
            same_recorded_file(descriptor, &original_path, &self.files.nodes[index].facts, ordinal == 0)?;
            leaves[ordinal] = Some(index);
        }
        self.recovery = Some(RecoveryOriginals { run, directory, records, record, backup: leaves[0], incoming: leaves[1] });
        Ok(())
    }
    fn expected(&self, image: &str) -> Result<&SelectionImageData> {
        if image == self.proposed.image && self.mode == SelectionMode::InstallActivated { return Ok(&self.proposed); }
        self.provenances.iter().find(|p| p.image == image).and_then(|p| p.expected.as_ref()).ok_or(Error::State)
    }
    fn canonical_link(&self, image: &str) -> Result<&[u8]> {
        self.provenances.iter().find(|p| p.image == image).map(|p| p.bytes.as_slice()).ok_or(Error::State)
    }
    pub fn bind_profiles_once(&mut self, boundary: &dyn InstallerBoundary,
        decoded: &[SelectionImageData]) -> Result<SelectionPreview> {
        let returned = self.bind_profiles(boundary, decoded); self.retain("validate-profile-and-selection", returned)
    }
    fn bind_profiles(&mut self, boundary: &dyn InstallerBoundary,
        decoded: &[SelectionImageData]) -> Result<SelectionPreview> {
        self.before(boundary)?; need(self.observed && !self.bound && decoded.len() == self.provenances.len())?;
        self.bound = true;
        for (original, expected) in self.provenances.iter_mut().zip(decoded) {
            need(expected.shape_valid() && expected.image == original.image
                && hash(&expected.profile) == original.image
                && self.files.nodes[original.profile].read_bytes.as_deref() == Some(expected.profile.as_slice()))?;
            original.expected = Some(expected.clone());
        }
        if let Some(image) = &self.selector_image {
            need(self.canonical_link(image)? == self.selector_bytes)?;
        }
        let pf = self.files.nodes[self.program_files.ok_or(Error::State)?].path.clone();
        let before = self.before_registry.as_ref().ok_or(Error::State)?;
        if before.present {
            let image = data::image_hint_from_registration(&before.values).ok_or(Error::Unsafe)?;
            need(data::registration(&pf, self.expected(&image)?).as_ref() == Some(&before.values))?;
        }
        if let Some(recovery) = &self.recovery {
            let record = &recovery.record;
            if let Some(old) = &record.before_image {
                if !record.old_link.is_empty() { need(self.canonical_link(old)? == record.old_link)?; }
                if !record.old_registry.is_empty() {
                    need(data::registration(&pf, self.expected(old)?).as_ref() == Some(&record.old_registry))?;
                    security::Observed::new(Refusal::none()).selection_descriptor(
                        &record.old_registry_security, security::SelectionDescriptor::Registration)?;
                }
            } else { need(record.old_link.is_empty() && record.old_registry.is_empty())?; }
            if !record.new_link.is_empty() {
                need(self.canonical_link(&record.image)? == record.new_link
                    && data::registration(&pf, self.expected(&record.image)?).as_ref() == Some(&record.new_registry))?;
                security::Observed::new(Refusal::none()).selection_descriptor(
                    &record.new_registry_security, security::SelectionDescriptor::Registration)?;
            } else { need(record.new_registry.is_empty())?; }
            if let Some(index) = self.selector {
                let old_path = self.files.child_path(self.programs.ok_or(Error::State)?, data::SHORTCUT)?;
                let incoming_path = self.files.child_path(recovery.directory, "incoming.lnk")?;
                let current = &self.files.nodes[index].facts;
                let same_old = !record.old_file_descriptor.is_empty()
                    && same_recorded_file(&record.old_file_descriptor, &old_path, current, false).is_ok();
                let same_new = !record.new_file_descriptor.is_empty()
                    && same_recorded_file(&record.new_file_descriptor, &incoming_path, current, true).is_ok();
                need(same_old || same_new)?;
            }
            for image in [self.selector_image.as_ref(), data::image_hint_from_registration(&before.values).as_ref()].into_iter().flatten() {
                need(image == &record.image || record.before_image.as_ref() == Some(image))?;
            }
        }
        if let Some(image) = &self.chosen_image {
            self.proposed_registry = data::registration(&pf, self.expected(image)?).ok_or(Error::Unsafe)?;
        }
        if data::payload_verification_required(self.mode, self.use_ == Use::Apply) {
            let image = self.chosen_image.clone().ok_or(Error::State)?;
            let expected = self.expected(&image)?.clone();
            self.verification = Some(ReadonlyImage::new(expected));
            let installer = self.files.installer.as_ref().ok_or(Error::State)?.clone();
            let verification = self.verification.as_mut().ok_or(Error::State)?;
            verification.run(boundary, &installer)?;
            self.report.retained_image_bytes_observed = Some(verification.bytes);
            if let Some(binding) = &self.binding {
                // Actual completed/settled acquisition+prerequisite+publication+
                // activation originals supplied these roles, not a success DTO.
                need(binding.activated.len() == 6 && !Arc::ptr_eq(&binding.acquisition, &self.files.book.identity))?;
                for (path, expected) in &binding.activated {
                    let index = *verification.inputs.by_path.get(path).ok_or(Error::Unsafe)?;
                    need(verification.inputs.nodes[index].facts == *expected)?;
                }
            }
        }
        self.recheck_observation(boundary)?;
        let observation = self.snapshot_hash()?;
        let owned = self.chosen_image.as_ref().or(self.before_image.as_ref());
        let selected = owned.map(|i| self.expected(i)).transpose()?;
        let preview = SelectionPreview {
            mode: self.mode, before_image: self.before_image.clone(), after_image: self.chosen_image.clone(),
            runtime: selected.map(|i| i.runtime.clone()), core_version: selected.map(|i| i.core_version.clone()),
            shortcut_path: self.files.child_path(self.programs.ok_or(Error::State)?, data::SHORTCUT)?,
            registration_path: data::REGISTRATION, observation_sha256: observation,
            preserved_paths: ["installer-input", "runtime-input", "versions", "selection"].iter()
                .map(|part| format!(r"{pf}\Mobile Release Kit\{part}")).collect(),
            retained_image_bytes_observed: if self.mode == SelectionMode::InstallActivated { None }
                else { self.report.retained_image_bytes_observed },
            warning: data::RECOVERY_WARNING,
        };
        if let Some(confirmed) = &self.confirmed { need(preview == *confirmed)?; }
        self.preview = Some(preview.clone()); self.report.stage = data::Stage::Observed;
        Ok(preview)
    }
    fn recheck_observation(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        self.files.recheck_locations(boundary)?; self.files.recheck_installer(boundary)?;
        for index in 0..self.files.nodes.len() {
            let slot = self.files.nodes[index].slot;
            if self.files.book.slot(slot)?.state == SlotState::Owned { self.files.recheck(boundary, index)?; }
        }
        let before = self.before_registry.clone().ok_or(Error::State)?;
        need(self.registry.snapshot(boundary, KeyRole::Before)? == before)?;
        if let Some(verification) = self.verification.as_mut() { verification.recheck_target(boundary)?; }
        Ok(())
    }
    fn snapshot_hash(&self) -> Result<String> {
        let mut out = b"MRK_SELECTION_PREVIEW_V1\0".to_vec();
        bounded_field(&mut out, self.mode.name().as_bytes())?;
        // Complete proposed DATA, not merely a copied ready bit.
        bounded_field(&mut out, &self.proposed.profile)?;
        for value in [&self.proposed.image, &self.proposed.runtime, &self.proposed.helper, &self.proposed.core_version] {
            bounded_field(&mut out, value.as_bytes())?;
        }
        for (size, digest) in self.proposed.input_sizes.iter().zip(&self.proposed.input_hashes) {
            out.extend(size.to_le_bytes()); bounded_field(&mut out, digest.as_bytes())?;
        }
        bounded_field(&mut out, self.recovery_id.as_deref().unwrap_or("").as_bytes())?;
        bounded_field(&mut out, self.before_image.as_deref().unwrap_or("").as_bytes())?;
        bounded_field(&mut out, self.chosen_image.as_deref().unwrap_or("").as_bytes())?;
        for location in &self.files.locations {
            bounded_field(&mut out, location.path.as_bytes())?;
            bounded_field(&mut out, location.drive.as_bytes())?;
            bounded_field(&mut out, location.device.as_bytes())?;
        }
        // Initial acquisition may create the product/retained-I parents between
        // new-install preview and Apply. Those unrelated timestamps are not the
        // proposal/selector snapshot. Every actual old selector/provenance and
        // CommonPrograms original below uses its complete unchanged facts.
        let programs = self.programs.ok_or(Error::State)?;
        bounded_field(&mut out, &self.files.descriptor_of(programs)?)?;
        bounded_field(&mut out, &self.old_descriptor)?;
        bounded_field(&mut out, &self.selector_bytes)?;
        bounded_field(&mut out, &self.before_registry.as_ref().ok_or(Error::State)?.encoded()?)?;
        bounded_field(&mut out, self.registry.parent_security.as_deref().ok_or(Error::State)?)?;
        for original in &self.provenances {
            for index in [original.directory, original.profile, original.launch] {
                bounded_field(&mut out, &self.files.descriptor_of(index)?)?;
            }
        }
        if let Some(recovery) = &self.recovery {
            bounded_field(&mut out, recovery.run.as_bytes())?;
            bounded_field(&mut out, &self.files.descriptor_of(recovery.directory)?)?;
            for index in recovery.records.iter().copied().chain(recovery.backup).chain(recovery.incoming) {
                bounded_field(&mut out, &self.files.descriptor_of(index)?)?;
                bounded_field(&mut out, self.files.nodes[index].read_bytes.as_deref().ok_or(Error::State)?)?;
            }
        }
        // Existing-image previews verify the same whole readonly closure again
        // on Apply. A newly acquired image cannot have a pre-acquisition proof.
        if self.mode != SelectionMode::InstallActivated {
            bounded_field(&mut out, self.verification.as_ref().and_then(|v| v.observation.as_deref()).unwrap_or("").as_bytes())?;
        }
        Ok(hash(&out))
    }
    pub fn finish_preview_once(&mut self, boundary: &dyn InstallerBoundary) -> Result<SelectionPreview> {
        need(self.use_ == Use::Preview && self.bound && !self.applying)?;
        let preview = self.preview.clone().ok_or(Error::State);
        self.settle_once(boundary);
        let returned = preview.and_then(|preview| { need(self.report.native_closed && self.first.is_none())?; Ok(preview) });
        self.retain("preview-finality", returned)
    }
    fn ensure_private_directory(&mut self, boundary: &dyn InstallerBoundary, parent: usize, name: &str) -> Result<usize> {
        if let Some(index) = self.files.child(boundary, parent, name, FileKind::Directory,
            AuthorityScope::ImmutableVersion, false)? {
            exact_security(&self.files.nodes[index].facts.security, FileKind::Directory, false, false)?;
            Ok(index)
        } else { self.files.create_directory(boundary, parent, name) }
    }
    fn prepare_outputs(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        let mrk = self.mrk.ok_or(Error::Unsafe)?;
        let selection = match self.selection { Some(index) => index,
            None => self.files.create_directory(boundary, mrk, "selection")? };
        self.selection = Some(selection);
        if self.files.nodes[selection].entries.is_none() {
            self.files.entries(boundary, selection, None)?;
        }
        let target = match self.selection_target { Some(index) => index,
            None => self.ensure_private_directory(boundary, selection, data::TARGET)? };
        self.selection_target = Some(target);
        if self.mode == SelectionMode::InstallActivated {
            let image = self.proposed.image.clone();
            need(self.files.child(boundary, target, &image, FileKind::Directory, AuthorityScope::ImmutableVersion, false)?.is_none())?;
            let directory = self.files.create_directory(boundary, target, &image)?;
            self.files.write_new_file(boundary, directory, "profile.json", &self.proposed.profile, false, &mut self.report, true)?;
            let pf = &self.files.nodes[self.program_files.ok_or(Error::State)?].path;
            let path = data::shell_target(pf, &image).ok_or(Error::Unsafe)?;
            self.new_link = self.codec.encode(boundary, &path)?;
            need(self.codec.decode(boundary, &self.new_link)? == path)?;
            self.files.write_new_file(boundary, directory, "launch.lnk", &self.new_link, false, &mut self.report, true)?;
        } else if let Some(image) = &self.chosen_image {
            self.new_link = self.canonical_link(image)?.to_vec();
        }
        let recovery = self.ensure_private_directory(boundary, selection, "recovery")?;
        // The volume check is not inferred from DOS spelling. Both actual roots
        // were admitted local NTFS, mapped to one native device and serial.
        need(self.files.nodes[recovery].facts.metadata.identity.volume_serial
            == self.files.nodes[self.programs.ok_or(Error::State)?].facts.metadata.identity.volume_serial)?;
        let run = self.registry.random_run(boundary)?;
        self.run = Some(run.clone());
        let directory = self.files.create_directory(boundary, recovery, &run)?;
        self.recovery_output = Some(directory);
        if !self.new_link.is_empty() {
            let index = self.files.write_new_file(boundary, directory, "incoming.lnk",
                &self.new_link, true, &mut self.report, false)?;
            self.new_descriptor = self.files.descriptor_of(index)?;
            self.incoming = Some(index);
        }
        Ok(())
    }
    fn prior_returns(&self) -> Result<Vec<u8>> {
        // Closed actual native observations only; no HANDLE/pointer values and
        // no interpreted success token. Preserve each critical effect's real code.
        let mut out = Vec::new();
        for returned in &self.files.effects {
            if returned.operation == FileEffect::Rename.tag() {
                out.extend([1, returned.operation]); out.extend(returned.value.to_le_bytes());
                out.extend(returned.error.to_le_bytes());
            }
        }
        for (operation, kind, value, error) in &self.registry.effects {
            if [RegistryEffect::Commit.tag(), RegistryEffect::Rollback.tag()].contains(operation) {
                out.extend([2, *operation, *kind]); out.extend(value.to_le_bytes()); out.extend(error.to_le_bytes());
            }
        }
        need(out.len() <= 4096)?; Ok(out)
    }
    fn write_record(&mut self, boundary: &dyn InstallerBoundary, phase: &'static str) -> Result<()> {
        let ordinal = data::PHASES.iter().position(|p| *p == phase).ok_or(Error::State)?;
        need(self.report.completely_closed_records < data::MAX_RECORDS)?;
        let before = self.before_registry.as_ref().ok_or(Error::State)?;
        let staged = self.registry.staged.as_ref().ok_or(Error::State)?;
        let image = self.chosen_image.as_ref().or(self.before_image.as_ref()).unwrap_or(&self.proposed.image);
        let record = data::RecoveryRecord { mode: self.mode, phase, run: self.run.clone().ok_or(Error::State)?,
            image: image.clone(), before_image: self.before_image.clone(),
            observation: self.preview.as_ref().ok_or(Error::State)?.observation_sha256.clone(),
            old_file_descriptor: self.old_descriptor.clone(), new_file_descriptor: self.new_descriptor.clone(),
            old_link: self.selector_bytes.clone(), new_link: self.new_link.clone(),
            old_registry: before.values.clone(), new_registry: self.proposed_registry.clone(),
            old_registry_security: before.security.clone(), new_registry_security: staged.security.clone(),
            prior_returns: self.prior_returns()? };
        let raw = record.encode().ok_or(Error::Bounds)?;
        let parent = self.recovery_output.ok_or(Error::State)?;
        let name = format!("record-{ordinal:02}.bin");
        let path = self.files.child_path(parent, &name)?;
        let returned = self.files.write_new_file(boundary, parent, &name, &raw, false, &mut self.report, true);
        // Flush acknowledgement, full readback/EOF and consuming close are
        // distinct observations. A STOP after a real flush is not "never written".
        if let Some(index) = self.files.by_path.get(&path).copied() {
            let node = &self.files.nodes[index];
            if node.flushed { self.report.os_flush_acknowledged_records += 1; }
            let slot = self.files.book.slot(node.slot)?;
            if node.flushed && node.read_bytes.as_deref() == Some(raw.as_slice())
                && slot.read_ended && slot.read_bytes == raw.len() as u64 && slot.state == SlotState::Closed {
                self.report.completely_closed_records += 1;
                self.report.completely_closed_phase_mask |= 1u8 << ordinal;
            }
        }
        returned.map(|_| ())
    }
    pub fn apply_once(&mut self, boundary: &dyn InstallerBoundary) -> Result<SelectionReport> {
        let returned = self.apply(boundary);
        let retained = self.retain("apply-launch-selection", returned);
        self.report.registry_commit_entered |= self.registry.commit_entered;
        self.report.registry_committed |= self.registry.committed;
        self.settle_once(boundary);
        match retained {
            Err(first) => Err(first),
            Ok(()) if self.report.native_closed && self.first.is_none() => {
                self.report.disposition = if self.mode == SelectionMode::RemoveSelection {
                    SelectionDisposition::LaunchEntriesRemoved
                } else { SelectionDisposition::Selected };
                self.report.stage = data::Stage::Closed; Ok(self.report())
            },
            Ok(()) => self.retain("selection-finality", Err(Error::Unknown)),
        }
    }
    fn apply(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
        self.before(boundary)?;
        need(self.use_ == Use::Apply && self.bound && !self.applying
            && self.preview.as_ref() == self.confirmed.as_ref())?;
        self.applying = true;
        need(self.registry.original().owns_reservation.get())?;
        self.recheck_observation(boundary)?;
        if self.mode == SelectionMode::RepairSameImage && self.selector.is_some()
            && self.before_registry.as_ref().is_some_and(|r| r.present) {
            // Genuine whole54/runtime47 readonly verification already ran. This
            // no-op cannot be reported as byte/ACL repair or a fresh acquisition.
            return Ok(());
        }
        if self.mode == SelectionMode::RemoveSelection && self.selector.is_none()
            && self.before_registry.as_ref().is_some_and(|r| !r.present) { return Ok(()); }
        self.prepare_outputs(boundary)?;
        let before = self.before_registry.clone().ok_or(Error::State)?;
        #[cfg(feature = "installer-selection-fixture")]
        if let Some(competitor) = self.fixture_competitor.as_mut() {
            // A genuine second transaction on the exact existing fixture key;
            // it never commits or moves a selector. Same-value staging obtains
            // the real registry write conflict; no simulated error code.
            let observed = competitor.open_before(boundary)?;
            need(before.present && observed == before)?;
            let charged = self.fixture_competitor_report.as_mut().ok_or(Error::State)?;
            competitor.stage(boundary, &observed, &observed.values, false, charged)?;
            self.fixture_conflict_staged = true;
        }
        self.registry.stage(boundary, &before, &self.proposed_registry,
            self.mode == SelectionMode::RemoveSelection, &mut self.report)?;
        self.report.stage = data::Stage::RegistryStaged;
        self.write_record(boundary, "prepared")?;
        self.recheck_observation(boundary)?;
        if let Some(index) = self.selector {
            self.write_record(boundary, "before-old-move")?;
            self.report.stage = data::Stage::BackupIntentFlushed;
            self.registry.recheck_namespace_before_effect(boundary)?;
            self.before(boundary)?;
            let slot = self.files.nodes[index].slot;
            let returned = self.files.rename_original(boundary, index, self.recovery_output.ok_or(Error::State)?, "previous.lnk");
            let (entered, native) = self.files.rename_observation(slot);
            self.report.old_move_entered = entered; self.report.old_move_native = native;
            if native.is_some() { self.report.stage = data::Stage::BackupReturned; }
            // Intent is persisted; actual returned DATA is already retained.
            // A native error/STOP must NOT authorize another producing write.
            returned?;
            self.write_record(boundary, "old-move-returned")?;
        }
        if let Some(index) = self.incoming {
            self.write_record(boundary, "before-new-move")?;
            self.report.stage = data::Stage::SelectIntentFlushed;
            self.registry.recheck_namespace_before_effect(boundary)?;
            self.before(boundary)?;
            let slot = self.files.nodes[index].slot;
            let returned = self.files.rename_original(boundary, index, self.programs.ok_or(Error::State)?, data::SHORTCUT);
            let (entered, native) = self.files.rename_observation(slot);
            self.report.new_move_entered = entered; self.report.new_move_native = native;
            if native.is_some() { self.report.stage = data::Stage::SelectReturned; }
            returned?;
            self.write_record(boundary, "new-move-returned")?;
            let actual = &self.files.nodes[index];
            need(actual.read_bytes.as_deref() == Some(self.new_link.as_slice())
                && actual.facts.metadata.size == self.new_link.len() as u64
                && self.files.book.slot(actual.slot)?.read_ended)?;
            self.files.recheck(boundary, index)?;
        }
        if let Some(verification) = self.verification.as_mut() { verification.recheck_target(boundary)?; }
        self.write_record(boundary, "before-registry-commit")?;
        self.report.stage = data::Stage::RegistryIntentFlushed;
        self.before(boundary)?;
        let returned = self.registry.commit_once(boundary);
        self.report.registry_commit_entered = self.registry.commit_entered;
        self.report.registry_committed = self.registry.committed;
        if let Some((operation, kind, value, error)) = self.registry.effects.last() {
            if *operation == RegistryEffect::Commit.tag() && *kind == 1 {
                self.report.registry_native = Some((*value as i32, *error));
                self.report.stage = data::Stage::RegistryReturned;
            }
        }
        returned?;
        self.write_record(boundary, "registry-returned")?;
        self.registry.verify_after(boundary, &self.proposed_registry, self.mode == SelectionMode::RemoveSelection)?;
        if let Some(index) = self.incoming { self.files.recheck(boundary, index)?; }
        self.files.recheck_locations(boundary)?; self.files.recheck_installer(boundary)?;
        Ok(())
    }
    pub fn settle_once(&mut self, boundary: &dyn InstallerBoundary) {
        if self.settling { return; } self.settling = true;
        if self.caller != thread::current().id() {
            self.report.fail("wrong-settlement-thread", true); return;
        }
        boundary.settlement_boundary();
        // Known once closes proceed through cooperative STOP. Never retry an
        // uncertain original; every independent cleanup error remains retained.
        self.codec.settle_once(boundary);
        if let Some(verification) = self.verification.as_mut() { verification.settle_once(boundary); }
        self.files.settle_once(boundary);
        self.registry.settle_registry_once(boundary);
        #[cfg(feature = "installer-selection-fixture")]
        if let Some(competitor) = self.fixture_competitor.as_mut() {
            competitor.settle_registry_once(boundary);
            if competitor.registry_closed() { competitor.close_reservation_once(boundary); }
        }
        #[cfg(feature = "installer-selection-fixture")]
        let fixture_closed = self.fixture_competitor.as_ref().is_none_or(|r| r.closed());
        #[cfg(not(feature = "installer-selection-fixture"))]
        let fixture_closed = true;
        if fixture_closed && self.codec.closed() && self.files.known_closed()
            && self.verification.as_ref().is_none_or(|v| v.closed()) && self.registry.registry_closed() {
            self.registry.close_reservation_once(boundary);
        }
        self.report.native_closed = fixture_closed && self.codec.closed() && self.files.known_closed()
            && self.verification.as_ref().is_none_or(|v| v.closed()) && self.registry.closed();
        if !self.report.native_closed { self.report.fail("native-finality", true); }
        if !self.cleanup_errors().is_empty() {
            if self.first.is_none() { self.first = Some(Error::Unknown); }
            self.report.fail("cleanup-error", true);
        }
        boundary.settlement_boundary();
    }
    pub fn report(&self) -> SelectionReport {
        let mut report = self.report.clone();
        report.write_count_unknown = self.files.writes.unknown_count;
        let kind = |effect: u8| {
            if effect == FileEffect::Directory.tag() { Some(data::OutputKind::CreatedDirectory) }
            else if effect == (FileEffect::Open { create: true }).tag() { Some(data::OutputKind::CreatedFile) }
            else if effect == FileEffect::Rename.tag() { Some(data::OutputKind::Rename) } else { None }
        };
        report.outputs = self.files.effects.iter().filter_map(|effect| kind(effect.operation).map(|kind|
            data::OutputObservation { kind, path: effect.logical_path.clone(), destination: effect.destination.clone(),
                native_return: Some((effect.value, effect.error)) })).collect();
        if let Some(held) = &self.files.effect {
            let frame = held.as_ref().get_ref();
            if frame.phase.get() == Phase::Entered {
                if let Some(kind) = kind(frame.effect.tag()) {
                    report.outputs.push(data::OutputObservation { kind, path: frame.logical_path.clone(),
                        destination: frame.rename_target.as_ref().map(|r| r.path.clone()), native_return: None });
                }
            }
        }
        report
    }
    pub fn first_failure(&self) -> Option<Error> { self.first }
    pub fn native_closed(&self) -> bool { self.report.native_closed }
    pub fn cleanup_errors(&self) -> Vec<SelectionCleanupError> {
        let mut errors = self.files.cleanup.clone(); errors.extend_from_slice(&self.registry.cleanup);
        errors.extend_from_slice(&self.codec.cleanup);
        if let Some(v) = &self.verification { errors.extend_from_slice(&v.inputs.cleanup); errors.extend_from_slice(&v.runtime.cleanup); }
        #[cfg(feature = "installer-selection-fixture")]
        if let Some(r) = &self.fixture_competitor {
            errors.extend(r.cleanup.iter().map(|e| SelectionCleanupError {
                original: SelectionOriginal::FixtureRegistry, record: e.record, error: e.error }));
        }
        errors
    }
}


#[cfg(test)]
mod original_descriptor_tests {
    use super::*;
    #[test]
    fn recovery_compares_original_identity_and_only_allows_recorded_rename_change_time() {
        let raw = descriptor(FileKind::File, false, true).expect("inert descriptor");
        let facts = Facts {
            metadata: Metadata {
                identity: FileIdentity { volume_serial: 9, file_id: [7; 16] },
                kind: FileKind::File, attributes: FS::FILE_ATTRIBUTE_ARCHIVE,
                size: 101, allocation_size: 4096, links: 1, creation: 10, write: 20, change: 30,
            },
            security: security::descriptor(&raw, FileKind::File, AuthorityScope::ImmutableVersion)
                .expect("inert security DATA"),
        };
        let path = r"C:\fixed\Mobile Release Kit.lnk";
        let recorded = facts_bytes(path, &facts).expect("bounded inert record");
        assert!(same_recorded_file(&recorded, path, &facts, false).is_ok());
        let mut moved = facts.clone(); moved.metadata.change += 1;
        assert!(same_recorded_file(&recorded, path, &moved, false).is_err());
        assert!(same_recorded_file(&recorded, path, &moved, true).is_ok());
        moved.metadata.identity.file_id[0] ^= 1;
        assert!(same_recorded_file(&recorded, path, &moved, true).is_err());
        let mut changed = facts.clone(); changed.metadata.write += 1;
        assert!(same_recorded_file(&recorded, path, &changed, true).is_err());
        assert!(same_recorded_file(&recorded[..recorded.len()-1], path, &facts, true).is_err());
    }
}


#[cfg(feature = "installer-selection-fixture")]
impl SelectionOwner {
    /// DATA-only before any native call. The safe owner registers this entire
    /// original (including the optional actual competitor) before observe_once.
    pub fn fixture_arm_once(&mut self, case: super::installer_selection_fixture_data::SelectionFixtureCase) -> Result<()> {
        need(!self.observed && !self.bound && !self.applying && self.fixture_case.is_none()
            && case.mode() == self.mode && case.preview() == (self.use_ == Use::Preview))?;
        self.fixture_case = Some(case);
        if case == super::installer_selection_fixture_data::SelectionFixtureCase::RegistryConflict {
            self.fixture_competitor = Some(RegistryOwner::new());
            self.fixture_competitor_report = Some(SelectionReport::new(self.mode));
        }
        Ok(())
    }
    pub fn fixture_observation(&self) -> super::installer_selection_fixture_data::SelectionFixtureObservation {
        use super::installer_selection_fixture_data::SelectionFixtureObservation;
        let verification = self.verification.as_ref();
        SelectionFixtureObservation {
            report: self.report(),
            recovery_run: self.run.clone(),
            input_rows_verified: verification.filter(|v| v.complete).map_or(0, |v|
                v.inputs.nodes.iter().filter(|n| n.facts.metadata.kind == FileKind::File).count()),
            runtime_rows_verified: verification.filter(|v| v.complete).map_or(0, |v|
                v.runtime.nodes.iter().filter(|n| n.facts.metadata.kind == FileKind::File).count()),
            readonly_originals_closed: verification.is_none_or(|v| v.closed()),
            registry_conflict_staged: self.fixture_conflict_staged,
            registry_conflict_returned: self.registry.effects.iter().any(|(_, kind, value, _)|
                *kind == 2 && *value == i64::from(F::ERROR_TRANSACTIONAL_CONFLICT)),
            registry_competitor_closed: self.fixture_competitor.as_ref().is_none_or(|r| r.closed()),
            registry_competitor_output: self.fixture_competitor_report.clone(),
        }
    }
}

// Deliberately nonshipping access to the SAME registered primitive owners.
// This interface cannot transact a key, select a registry name, resolve/launch
// a shortcut, or mutate a filesystem path.
#[cfg(all(test, feature = "installer-selection-fixture"))]
pub(crate) mod fixture_observation {
    use super::*;
    use super::super::installer_fixture_data::{installer_fixture_inputs, InstallerFixtureCase};
    use super::super::qualification_result::Stamp;

    pub(crate) const FOREIGN_IMAGE: &str =
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct RegistrationObservation {
        pub present: bool,
        pub values: data::Registration,
        pub security: Vec<u8>,
        pub parent_security: Vec<u8>,
        pub write: u64,
        pub complete_sha256: String,
    }
    /// This object is retained by the actual native fixture before its first
    /// call, including on unknown return/close. It has no Drop settlement.
    pub(crate) struct Observer {
        registry: RegistryOwner,
        codec: LinkCodec,
        before: Option<RegistrySnapshot>,
        initialized: bool,
        rechecked: bool,
        decodes: usize,
        foreign_encoded: bool,
    }
    impl Observer {
        pub fn new() -> Self {
            Self { registry: RegistryOwner::new(), codec: LinkCodec::new(), before: None,
                initialized: false, rechecked: false, decodes: 0, foreign_encoded: false }
        }
        pub fn initialize(&mut self, boundary: &dyn InstallerBoundary, system: &str) -> Result<()> {
            need(!self.initialized)?; self.initialized = true;
            self.codec.initialize_once(boundary, system)
        }
        pub fn registration(&mut self, boundary: &dyn InstallerBoundary) -> Result<RegistrationObservation> {
            need(self.before.is_none())?;
            let actual = self.registry.open_before(boundary)?;
            let result = RegistrationObservation { present: actual.present, values: actual.values.clone(),
                security: actual.security.clone(), write: actual.write,
                parent_security: self.registry.parent_security.clone().ok_or(Error::State)?,
                complete_sha256: hash(&actual.encoded()?) };
            self.before = Some(actual); Ok(result)
        }
        pub fn decode_profile(&mut self, boundary: &dyn InstallerBoundary, bytes: &[u8],
            program_files: &str, image: &str) -> Result<()> {
            // Four canonical provenances and one actual selector. No repeated
            // decoding of the historical recovery links is necessary: their
            // complete bytes/ACL/native identities are checked against these
            // canonical originals by the caller.
            need(self.initialized && self.decodes < 5
                && (image == FOREIGN_IMAGE || InstallerFixtureCase::ALL.iter().copied()
                    .map(installer_fixture_inputs).collect::<Result<Vec<_>>>()?
                    .iter().any(|input| input.image == image)))?;
            self.decodes += 1;
            let target = data::shell_target(program_files, image).ok_or(Error::Unsafe)?;
            need(self.codec.decode(boundary, bytes)? == target)
        }
        pub fn encode_foreign_once(&mut self, boundary: &dyn InstallerBoundary, program_files: &str) -> Result<Vec<u8>> {
            need(self.initialized && !self.foreign_encoded)?;
            for case in InstallerFixtureCase::ALL {
                need(installer_fixture_inputs(case)?.image != FOREIGN_IMAGE)?;
            }
            self.foreign_encoded = true;
            let target = data::shell_target(program_files, FOREIGN_IMAGE).ok_or(Error::Unsafe)?;
            self.codec.encode(boundary, &target)
        }
        pub fn recheck_registration(&mut self, boundary: &dyn InstallerBoundary) -> Result<()> {
            need(!self.rechecked)?; self.rechecked = true;
            let before = self.before.clone().ok_or(Error::State)?;
            // The production primitive freshly opens the fixed native64 parent
            // and leaf; cached NoHandle never becomes a later absence proof.
            self.registry.verify_after(boundary, &before.values, !before.present)?;
            let after = self.registry.snapshot(boundary, KeyRole::After)?;
            need(after == before)
        }
        pub fn unknown(&self) -> bool {
            self.registry.unknown || self.registry.call.is_some()
                || self.codec.unknown || self.codec.call.is_some()
        }
        pub fn settle_once(&mut self, boundary: &dyn InstallerBoundary) {
            self.codec.settle_once(boundary);
            self.registry.settle_registry_once(boundary);
            if self.codec.closed() && self.registry.registry_closed() {
                self.registry.close_reservation_once(boundary);
            }
        }
        pub fn closed(&self) -> bool { self.codec.closed() && self.registry.closed() }
    }
    pub fn original_matches(recorded: &[u8], original_path: &str, stamp: &Stamp,
        descriptor: &[u8], renamed: bool) -> Result<()> {
        need(stamp.attributes & FS::FILE_ATTRIBUTE_DIRECTORY == 0
            && stamp.size >= 0 && stamp.allocation >= stamp.size)?;
        let facts = Facts { metadata: Metadata {
            identity: FileIdentity { volume_serial: stamp.volume, file_id: stamp.id },
            kind: FileKind::File, attributes: stamp.attributes, links: stamp.links,
            size: stamp.size as u64, allocation_size: stamp.allocation as u64,
            creation: stamp.creation, write: stamp.write, change: stamp.change,
        }, security: security::descriptor(descriptor, FileKind::File, AuthorityScope::ImmutableVersion)? };
        same_recorded_file(recorded, original_path, &facts, renamed)
    }
}
