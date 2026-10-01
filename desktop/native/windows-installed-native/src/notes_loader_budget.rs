//! Closed Required Notes installed-loader DATA, not a transaction capability.
//!
//! This selection has its own immutable NotesProfile and COMPILED_NOTES binding.
//! Sharing the catalog and resource-report DATA never shares an Image selection.
//! There is deliberately no production Notes closure yet: compiled() refuses.
//! The immutable-runtime loader security policy below is not the project Notes
//! transaction security decoder (which must preserve complete OWNER+GROUP/DACL).
use super::{AceFact, Arena, Error, Result, SecurityFacts, Sid, SlotState, SystemImage, MAX_ORIGINALS, BUFFER, counts_live};
use std::mem::size_of;

pub const CATALOG_COUNT: usize = 40;
pub const SECURITY_BYTES: usize = 16 * 1024 * 1024;
pub const DIRECTORY_ENVELOPE: usize = 12;
const LEGACY_SELECTED: usize = 3;
const OS_ORIGINALS: usize = 31;
const TOKEN_ORIGINALS: usize = 2;
const MAX_CLOSURE_EDGES: usize = 2048;
const MAX_ACES: usize = 2048;
const MAX_SID_BYTES: usize = 68;

pub use super::image_loader_budget::{Payload, CompileResourceFacts, SecurityResourceFacts, NativeResourceFacts};
use super::image_loader_budget::SUPPLIER;

pub const REQUIRED: [Payload; 9] = [
    Payload::Bootstrap, Payload::Core, Payload::Python, Payload::Python314,
    Payload::PythonPath, Payload::PythonZip, Payload::Ctypes, Payload::LibFfi, Payload::Bridge,
];
const CATALOG_MASK: u64 = (1u64 << CATALOG_COUNT) - 1;
fn required_mask() -> u64 { REQUIRED.iter().fold(0, |bits, item| bits | item.bit()) }

// The shared supplier table is immutable DATA. Bootstrap/core/bridge pins are
// supplied ONLY by this separate Notes profile; no Image profile is consulted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Architecture { Data, X64Pe }
fn architecture(payload: Payload) -> Architecture {
    match payload {
        Payload::License | Payload::PythonCatalog | Payload::PythonPath
        | Payload::PythonZip | Payload::Bootstrap | Payload::Core => Architecture::Data,
        _ => Architecture::X64Pe,
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Artifact<'a> { name: &'a str, bytes: u64, sha256: &'a str, architecture: Architecture }
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum EdgeKind { StaticImport, DelayImport, DynamicInput }
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ClosureEdge<'a> { source: &'a str, kind: EdgeKind, target: &'a str }
#[derive(Clone, Copy)]
struct Closure<'a> {
    // Separate exact proof bindings: a source import expectation is not a PE
    // import table, and direct imports alone do not prove delay/dynamic inputs.
    fingerprint: &'a str, pe_imports: &'a str, delay_imports: &'a str, dynamic_inputs: &'a str,
    rows: &'a [Artifact<'a>], edges: &'a [ClosureEdge<'a>],
}
struct NotesProfile<'a> {
    target: &'a str, manifest: &'a str, protocol: &'a str,
    extras: [Artifact<'a>; 3], // bootstrap, core, separately pinned actual bridge
    closure: Closure<'a>,
}
const TARGET: &str = "x86_64-pc-windows-msvc";
static COMPILED_NOTES: Option<NotesProfile<'static>> = None;

fn sha(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}
fn artifact_pin<'a>(profile: &'a NotesProfile<'a>, payload: Payload) -> Result<Artifact<'a>> {
    if payload.ordinal() < SUPPLIER.len() {
        let (name, bytes, sha256) = SUPPLIER[payload.ordinal()];
        if name != payload.name() { return Err(Error::State); }
        Ok(Artifact { name, bytes, sha256, architecture: architecture(payload) })
    } else {
        let item = *profile.extras.get(payload.ordinal() - SUPPLIER.len()).ok_or(Error::State)?;
        if item.name != payload.name() || item.architecture != architecture(payload)
            || item.bytes == 0 || item.bytes > super::MAX_FILE_BYTES || !sha(item.sha256) {
            return Err(Error::Unsafe);
        }
        Ok(item)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrozenCount { mask: u64, selected: usize, limit: usize }
impl FrozenCount {
    fn from_mask(mask: u64) -> Result<Self> {
        if mask & !CATALOG_MASK != 0 || mask & required_mask() != required_mask() {
            return Err(Error::Unsafe);
        }
        let selected = usize::try_from(mask.count_ones()).map_err(|_| Error::Bounds)?;
        let envelope = MAX_ORIGINALS.checked_sub(LEGACY_SELECTED)
            .and_then(|n| n.checked_sub(OS_ORIGINALS))
            .and_then(|n| n.checked_sub(TOKEN_ORIGINALS)).ok_or(Error::Bounds)?;
        if envelope != DIRECTORY_ENVELOPE || SystemImage::ALL.len() != OS_ORIGINALS
            || !(REQUIRED.len()..=CATALOG_COUNT).contains(&selected) { return Err(Error::Bounds); }
        let limit = MAX_ORIGINALS.checked_sub(LEGACY_SELECTED)
            .and_then(|n| n.checked_add(selected)).ok_or(Error::Bounds)?;
        Ok(Self { mask, selected, limit })
    }
    fn peak(self, directories: usize) -> Result<usize> {
        let peak = directories.checked_add(self.selected)
            .and_then(|n| n.checked_add(OS_ORIGINALS))
            .and_then(|n| n.checked_add(TOKEN_ORIGINALS)).ok_or(Error::Bounds)?;
        if directories > DIRECTORY_ENVELOPE || peak > self.limit { Err(Error::Bounds) } else { Ok(peak) }
    }
}
fn validate_closure(profile: &NotesProfile<'_>, closure: &Closure<'_>) -> Result<FrozenCount> {
    if profile.target != TARGET || !sha(profile.manifest) || !sha(profile.protocol)
        || [closure.fingerprint, closure.pe_imports, closure.delay_imports, closure.dynamic_inputs]
            .iter().any(|value| !sha(value))
        || closure.rows.len() > CATALOG_COUNT || closure.edges.len() > MAX_CLOSURE_EDGES {
        return Err(Error::Unsafe);
    }
    for payload in [Payload::Bootstrap, Payload::Core, Payload::Bridge] { artifact_pin(profile, payload)?; }
    let mut mask = 0u64;
    for row in closure.rows {
        let payload = Payload::from_name(row.name).ok_or(Error::Unsafe)?;
        if mask & payload.bit() != 0 || *row != artifact_pin(profile, payload)? { return Err(Error::Unsafe); }
        mask |= payload.bit();
    }
    let counted = FrozenCount::from_mask(mask)?;
    let mut previous = None;
    for edge in closure.edges {
        if previous.is_some_and(|prior| prior >= *edge) { return Err(Error::Unsafe); }
        previous = Some(*edge);
        let source = Payload::from_name(edge.source).ok_or(Error::Unsafe)?;
        if mask & source.bit() == 0 { return Err(Error::Unsafe); }
        if let Some(target) = Payload::from_name(edge.target) {
            if mask & target.bit() == 0 { return Err(Error::Unsafe); }
        } else if !SystemImage::ALL.iter().any(|image| image.name() == edge.target) {
            // API-set resolution, if needed, must be represented by the actual
            // proved physical OS input and bound by the PE proof fingerprint.
            return Err(Error::Unsafe);
        }
    }
    // A larger cap cannot admit an arbitrary catalog superset: every extra
    // selected input must be reachable from the required startup/import roots.
    let mut reachable = required_mask();
    for _ in 0..CATALOG_COUNT {
        let before = reachable;
        for edge in closure.edges {
            let source = Payload::from_name(edge.source).ok_or(Error::Unsafe)?;
            if reachable & source.bit() != 0 {
                if let Some(target) = Payload::from_name(edge.target) { reachable |= target.bit(); }
            }
        }
        if reachable == before { break; }
    }
    if reachable != mask { return Err(Error::Unsafe); }
    Ok(counted)
}
fn admit_profile(profile: &NotesProfile<'_>, actual: &Closure<'_>) -> Result<FrozenCount> {
    let expected = validate_closure(profile, &profile.closure)?;
    let observed = validate_closure(profile, actual)?;
    if expected != observed || actual.fingerprint != profile.closure.fingerprint
        || actual.pe_imports != profile.closure.pe_imports || actual.delay_imports != profile.closure.delay_imports
        || actual.dynamic_inputs != profile.closure.dynamic_inputs
        || actual.rows != profile.closure.rows || actual.edges != profile.closure.edges {
        return Err(Error::Unsafe);
    }
    Ok(observed)
}

/// Closed compile-bound DATA, not a launch/profile qualification. No integer,
/// caller row list, environment variable or public test constructor produces it.
pub struct NotesLoaderSelection {
    profile: Option<&'static NotesProfile<'static>>,
    count: FrozenCount,
}
impl NotesLoaderSelection {
    pub fn compiled() -> Result<Self> {
        let profile = COMPILED_NOTES.as_ref().ok_or(Error::Unavailable)?;
        let count = admit_profile(profile, &profile.closure)?;
        Ok(Self { profile: Some(profile), count })
    }
    pub(super) fn production_bound(&self) -> bool {
        match (self.profile, COMPILED_NOTES.as_ref()) {
            (Some(actual), Some(compiled)) => std::ptr::eq(actual, compiled),
            _ => false,
        }
    }
    pub fn selected_count(&self) -> usize { self.count.selected }
    pub fn selected_mask(&self) -> u64 { self.count.mask }
    pub fn live_limit(&self) -> usize { self.count.limit }
    pub fn peak(&self, directories: usize) -> Result<usize> { self.count.peak(directories) }
    pub fn selected(&self) -> impl Iterator<Item = Payload> + '_ {
        Payload::ALL.into_iter().filter(|item| self.count.mask & item.bit() != 0)
    }
    pub fn contains(&self, item: Payload) -> bool { self.count.mask & item.bit() != 0 }
    pub fn retained_path(&self, path: &str) -> bool {
        self.selected().any(|item| item.name() == path
            || item.name().strip_prefix(path).is_some_and(|tail| tail.starts_with('/')))
    }
    pub fn matches_version(&self, target: &str, manifest: &str, protocol: &str) -> bool {
        self.production_bound() && self.profile.is_some_and(|profile|
            profile.target == target && profile.manifest == manifest && profile.protocol == protocol)
    }
    pub fn closure_fingerprint(&self) -> Result<&'static str> {
        Ok(self.profile.ok_or(Error::Unavailable)?.closure.fingerprint)
    }
    pub fn verify_inventory_file(&self, path: &str, bytes: u64, hash: &str) -> Result<()> {
        let payload = Payload::from_name(path).ok_or(Error::Unsafe)?;
        let pin = artifact_pin(self.profile.ok_or(Error::Unavailable)?, payload)?;
        if bytes == pin.bytes && hash == pin.sha256 { Ok(()) } else { Err(Error::Unsafe) }
    }
    pub fn compile_resource_facts(&self) -> Result<CompileResourceFacts> {
        let profile = self.profile.ok_or(Error::Unavailable)?;
        Ok(CompileResourceFacts {
            selected: self.count.selected, live_limit: self.count.limit,
            catalog_members: CATALOG_COUNT, closure_rows: profile.closure.rows.len(),
            closure_edges: profile.closure.edges.len(), closure_edge_bound: MAX_CLOSURE_EDGES,
            // Static text/tables have no per-book Vec allocation. Report their
            // actual in-object layouts separately from referenced static bytes.
            selection_inline_bytes: size_of::<Self>(), row_layout_bytes: size_of::<Artifact<'static>>(),
            edge_layout_bytes: size_of::<ClosureEdge<'static>>(),
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WalkPhase { Inventory, Loader, Ready, Refused }
/// Notes-loader-only phase DATA retained in the same WindowsVersionBook. Its callers
/// supply facts from original records/EOF, not public success receipts.
pub struct NotesWalk {
    selected_mask: u64, attempted: u64, os_attempted: u32,
    transient: bool, phase: WalkPhase, first: Option<Error>,
}
impl NotesWalk {
    pub fn new(selection: &NotesLoaderSelection) -> Self {
        Self { selected_mask: selection.count.mask, attempted: 0, os_attempted: 0,
            transient: false, phase: WalkPhase::Inventory, first: None }
    }
    fn healthy(&self) -> Result<()> { self.first.map_or(Ok(()), Err) }
    fn refusal<T>(&mut self, error: Error) -> Result<T> {
        if self.first.is_none() { self.first = Some(error); }
        self.phase = WalkPhase::Refused;
        Err(self.first.unwrap_or(error))
    }
    pub fn before_directory(&mut self) -> Result<()> {
        self.healthy()?;
        if self.transient || !matches!(self.phase, WalkPhase::Inventory | WalkPhase::Loader) {
            return self.refusal(Error::State);
        }
        // No new directory after the OS-image phase begins. All original
        // known-location/legacy parents are acquired before its first file.
        if self.os_attempted != 0 { return self.refusal(Error::State); }
        Ok(())
    }
    pub fn before_payload(&mut self, selected: Option<Payload>) -> Result<()> {
        self.healthy()?;
        if self.phase != WalkPhase::Inventory || self.transient { return self.refusal(Error::State); }
        match selected {
            Some(payload) if self.selected_mask & payload.bit() != 0 && self.attempted & payload.bit() == 0 => {
                self.attempted |= payload.bit();
            },
            Some(_) => return self.refusal(Error::State),
            None => self.transient = true,
        }
        Ok(()) // attempt frozen BEFORE the original acquisition; never retried
    }
    pub fn transient_closed(&mut self, actual: SlotState) -> Result<()> {
        self.healthy()?;
        if self.phase != WalkPhase::Inventory || !self.transient || actual != SlotState::Closed {
            return self.refusal(Error::State);
        }
        self.transient = false; Ok(())
    }
    pub fn enter_loader(&mut self, inventory_eof: bool, observed_selected_mask: u64,
        nonselected_still_live: bool) -> Result<()> {
        self.healthy()?;
        if self.phase != WalkPhase::Inventory || self.transient || !inventory_eof
            || nonselected_still_live || observed_selected_mask != self.selected_mask
            || self.attempted != self.selected_mask {
            return self.refusal(Error::State);
        }
        self.phase = WalkPhase::Loader; Ok(())
    }
    pub fn before_os(&mut self, image: SystemImage) -> Result<()> {
        self.healthy()?;
        if self.phase != WalkPhase::Loader || self.transient { return self.refusal(Error::State); }
        let ordinal = SystemImage::ALL.iter().position(|prior| *prior == image).ok_or(Error::State)?;
        let bit = 1u32.checked_shl(u32::try_from(ordinal).map_err(|_| Error::Bounds)?).ok_or(Error::Bounds)?;
        if self.os_attempted & bit != 0 { return self.refusal(Error::State); }
        self.os_attempted |= bit; Ok(())
    }
    pub fn ready(&mut self, all_originals_admitted: bool) -> Result<()> {
        self.healthy()?;
        if self.phase != WalkPhase::Loader || self.os_attempted != (1u32 << OS_ORIGINALS) - 1
            || !all_originals_admitted { return self.refusal(Error::State); }
        self.phase = WalkPhase::Ready; Ok(())
    }
    pub fn is_ready(&self) -> bool { self.first.is_none() && self.phase == WalkPhase::Ready }
}

/// Not a whole-process heap measurement. This independent Notes-loader-only16MiB
/// ceiling counts ALL retained security facts plus a simultaneous new decoding
/// and its query/transient reservation. The child's16MiB is not pooled here.
#[derive(Clone, Copy)]
pub(super) struct SecurityReservation { pub facts: SecurityResourceFacts }
fn security_storage(facts: &SecurityFacts) -> Result<usize> {
    size_of::<SecurityFacts>().checked_add(facts.retained_heap_bytes().ok_or(Error::Bounds)?)
        .ok_or(Error::Bounds)
}
fn security_total(retained: usize, observation: usize, working: usize) -> Result<usize> {
    let total = retained.checked_add(observation).and_then(|n| n.checked_add(working)).ok_or(Error::Bounds)?;
    if total > SECURITY_BYTES { Err(Error::Bounds) } else { Ok(total) }
}
impl SecurityReservation {
    pub(super) fn reserve<'a>(retained: impl Iterator<Item = &'a SecurityFacts>) -> Result<Self> {
        let mut retained_bytes = 0usize;
        for item in retained {
            retained_bytes = retained_bytes.checked_add(security_storage(item)?).ok_or(Error::Bounds)?;
        }
        // Maximum accepted decoder allocation capacities, NOT lengths or a host
        // layout guess. Each actual allocation is checked inside the shared
        // security decoder before it adopts it; a larger allocator capacity
        // refuses before any next native entry. Owner+temporary group coexist.
        let decoded_reservation = MAX_ACES.checked_mul(size_of::<AceFact>().checked_add(MAX_SID_BYTES).ok_or(Error::Bounds)?)
            .and_then(|n| n.checked_add(2 * MAX_SID_BYTES))
            .and_then(|n| n.checked_add(size_of::<SecurityFacts>()))
            .and_then(|n| n.checked_add(size_of::<Sid>())).ok_or(Error::Bounds)?;
        // Arena contains the original64KiB raw query; it is not copied out.
        // Count the complete target SDK arena layout, not just transferred bytes.
        let query_reservation = size_of::<Arena>();
        if query_reservation < BUFFER { return Err(Error::State); }
        let simultaneous_peak = security_total(retained_bytes, decoded_reservation, query_reservation)?;
        Ok(Self { facts: SecurityResourceFacts {
            retained_bytes, decoded_reservation, query_reservation, simultaneous_peak,
            ceiling: SECURITY_BYTES, ace_layout_bytes: size_of::<AceFact>(),
            security_layout_bytes: size_of::<SecurityFacts>(),
        } })
    }
    pub(super) fn admit_observed(&self, observed: &SecurityFacts) -> Result<()> {
        let actual = security_storage(observed)?;
        if actual > self.facts.decoded_reservation { return Err(Error::Bounds); }
        security_total(self.facts.retained_bytes, actual, self.facts.query_reservation).map(|_| ())
    }
}

impl super::NativeBook {
    /// The original book's measured slot/name/token/frame capacities. This is
    /// DATA only; it neither samples native state nor admits a new operation.
    pub fn required_notes_loader_resource_facts(&self) -> Result<NativeResourceFacts> {
        let selection = self.required_notes_loader_selection().ok_or(Error::State)?;
        Ok(NativeResourceFacts {
            selected: selection.selected_count(), live_limit: selection.live_limit(),
            live_originals: self.slots.iter().filter(|slot| counts_live(slot.state)).count(),
            lifetime_records: self.slots.len(), file_attempts: self.slots.iter().filter(|slot| slot.kind == super::Kind::File).count(),
            entries: self.entries, read_bytes: self.bytes_read,
            retained_native_heap_bytes: self.public_image_retained_heap_bytes().ok_or(Error::Bounds)?,
            // Same existing bounded helper: nine worst-case simultaneous native
            // observation arenas/token scratch, separately from ACL accounting.
            native_working_reservation: self.public_image_transient_bytes(true).ok_or(Error::Bounds)?,
            native_book_inline_bytes: size_of::<Self>(),
            maximum_records: super::MAX_RECORDS, maximum_files: super::MAX_FILES,
            maximum_entries: super::MAX_ENTRIES, maximum_file_bytes: super::MAX_FILE_BYTES,
            maximum_read_bytes: super::MAX_TOTAL_BYTES,
        })
    }
    pub fn required_notes_loader_location_storage(&self, locations: &super::KnownLocations) -> Result<usize> {
        if self.required_notes_loader_selection().is_none() { return Err(Error::State); }
        let mut bytes = size_of::<super::KnownLocations>();
        for location in [&locations.program_files, &locations.windows, &locations.system] {
            if !std::sync::Arc::ptr_eq(&self.identity, &location.book) { return Err(Error::State); }
            for value in [&location.path, &location.drive, &location.device] {
                bytes = bytes.checked_add(value.capacity()).ok_or(Error::Bounds)?;
            }
            bytes = bytes.checked_add(location.components.capacity().checked_mul(size_of::<String>()).ok_or(Error::Bounds)?)
                .ok_or(Error::Bounds)?;
            for component in &location.components { bytes = bytes.checked_add(component.capacity()).ok_or(Error::Bounds)?; }
        }
        Ok(bytes)
    }
    pub fn required_notes_loader_security_facts<'a>(&self, retained: impl Iterator<Item = &'a SecurityFacts>)
        -> Result<SecurityResourceFacts> {
        if self.required_notes_loader_selection().is_none() { return Err(Error::State); }
        Ok(SecurityReservation::reserve(retained)?.facts)
    }
    /// ONLY this method may query security on a Notes-loader-purpose book. Its one
    /// caller passes every still-present Record.security from that original
    /// WindowsVersionBook; the returned new facts coexist with all old facts.
    pub fn required_notes_loader_security<'a>(&mut self, original: &super::Original, scope: super::AuthorityScope,
        retained: impl Iterator<Item = &'a SecurityFacts>) -> Result<SecurityFacts> {
        self.clear()?;
        if self.required_notes_loader_selection().is_none() { return Err(Error::State); }
        let reservation = self.capacity_result(SecurityReservation::reserve(retained))?;
        let index = self.index(original)?;
        let kind = match self.slot(index)?.kind {
            super::Kind::Directory => super::FileKind::Directory,
            super::Kind::File => super::FileKind::File, _ => return Err(Error::State),
        };
        // Reservation precedes allocation/registration/entry. Unknown keeps the
        // entered native Arena in this SAME book; no budget code takes it away.
        let returned = self.original_call(index, super::Call::Security)?;
        let trace = self.admission.at(match scope {
            super::AuthorityScope::AncestorOutsideVersion => super::AdmissionOp::SecurityAncestor,
            super::AuthorityScope::ImmutableVersion => super::AdmissionOp::SecurityVersion,
        });
        let decoded = super::security::Observed::new(trace).image_descriptor(
            returned.bytes_in(returned.count_in(trace)?, trace)?, kind, scope, reservation.facts.decoded_reservation);
        let observed = self.capacity_result(decoded)?;
        self.capacity_result(reservation.admit_observed(&observed))?;
        Ok(observed) // actual capacities checked before the caller's next method
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_notes_profile_cannot_borrow_an_image_selection() {
        assert!(matches!(NotesLoaderSelection::compiled(), Err(Error::Unavailable)));
        let inert = NotesLoaderSelection { profile: None, count: FrozenCount::from_mask(required_mask()).unwrap() };
        assert!(!inert.production_bound());
        assert!(!inert.matches_version(TARGET, &"a".repeat(64), &"b".repeat(64)));
        assert!(matches!(super::super::NativeBook::new_required_notes_loader(inert), Err(Error::Unavailable)));
        let ordinary = super::super::NativeBook::new();
        assert!(ordinary.required_notes_loader_selection().is_none());
        assert!(ordinary.metadata_images_selection().is_none());
        assert_eq!(ordinary.live_limit, super::super::MAX_LIVE);
    }
    #[test]
    fn count_is_closed_catalog_data_not_an_integer_limit() {
        let minimum = FrozenCount::from_mask(required_mask()).unwrap();
        assert_eq!(minimum.selected, REQUIRED.len());
        assert_eq!(minimum.peak(DIRECTORY_ENVELOPE).unwrap(), minimum.limit);
        assert!(minimum.peak(DIRECTORY_ENVELOPE + 1).is_err());
        assert!(FrozenCount::from_mask(required_mask() & !(1u64 << Payload::Bridge.ordinal())).is_err());
        assert!(FrozenCount::from_mask(required_mask() | (1u64 << CATALOG_COUNT)).is_err());
    }
    #[test]
    fn failed_walk_does_not_restart_after_known_close() {
        let selection = NotesLoaderSelection { profile: None, count: FrozenCount::from_mask(required_mask()).unwrap() };
        let mut walk = NotesWalk::new(&selection);
        walk.before_payload(None).unwrap();
        assert_eq!(walk.before_directory(), Err(Error::State));
        assert_eq!(walk.transient_closed(SlotState::Closed), Err(Error::State));
        assert!(!walk.is_ready());
        let mut fresh = NotesWalk::new(&selection);
        fresh.before_payload(Some(Payload::Bridge)).unwrap();
        assert_eq!(fresh.before_payload(Some(Payload::Bridge)), Err(Error::State));
        assert_eq!(fresh.enter_loader(true, selection.selected_mask(), false), Err(Error::State));
    }
}
