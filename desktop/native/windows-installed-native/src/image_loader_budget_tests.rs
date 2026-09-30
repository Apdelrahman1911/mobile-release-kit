//! Inert DATA/registration contracts only. No Windows API or subject is invoked.
//! Private synthetic tables never populate COMPILED or a production selection.
#![allow(clippy::unwrap_used)]
use super::*;
use super::super::{NativeBook, LivePurpose, Kind, Original, CloseOutcome, MAX_RECORDS,
    MAX_FILES, MAX_ENTRIES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, charge_entries, charge_read};
use std::cell::{Cell, UnsafeCell};
use std::marker::PhantomPinned;
use std::mem::{offset_of, ManuallyDrop};
use std::ptr::null_mut;
use windows_sys::Win32::{Foundation as F, Security as S, Storage::FileSystem as FS, System::IO};

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const E: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const EXTRAS: [Artifact<'static>; 3] = [
    Artifact { name: "config_edit_bootstrap.py", bytes: 1, sha256: A, architecture: Architecture::Data },
    Artifact { name: "core.zip", bytes: 1, sha256: B, architecture: Architecture::Data },
    Artifact { name: "python/mrk_image_writer_native.dll", bytes: 1, sha256: C, architecture: Architecture::X64Pe },
];
struct Fixture { rows: Vec<Artifact<'static>>, edges: Vec<ClosureEdge<'static>> }
impl Fixture {
    fn new(mask: u64) -> Self {
        let mut rows = Vec::new();
        for payload in Payload::ALL {
            if mask & payload.bit() == 0 { continue; }
            rows.push(if payload.ordinal() < SUPPLIER.len() {
                let (name, bytes, sha256) = SUPPLIER[payload.ordinal()];
                Artifact { name, bytes, sha256, architecture: architecture(payload) }
            } else { EXTRAS[payload.ordinal() - SUPPLIER.len()] });
        }
        let mut edges = vec![
            ClosureEdge { source: Payload::Python.name(), kind: EdgeKind::StaticImport, target: Payload::Python314.name() },
            ClosureEdge { source: Payload::Ctypes.name(), kind: EdgeKind::StaticImport, target: Payload::LibFfi.name() },
            ClosureEdge { source: Payload::Bridge.name(), kind: EdgeKind::DelayImport, target: "kernel32.dll" },
            ClosureEdge { source: Payload::Bootstrap.name(), kind: EdgeKind::DynamicInput, target: Payload::Core.name() },
        ];
        for payload in Payload::ALL {
            if mask & payload.bit() != 0 && required_mask() & payload.bit() == 0 {
                edges.push(ClosureEdge { source: Payload::Bridge.name(), kind: EdgeKind::DynamicInput, target: payload.name() });
            }
        }
        edges.sort();
        Self { rows, edges }
    }
    fn profile(&self) -> Profile<'_> {
        Profile { target: TARGET, manifest: D, protocol: E, extras: EXTRAS,
            closure: Closure { fingerprint: A, pe_imports: B, delay_imports: C, dynamic_inputs: D,
                rows: &self.rows, edges: &self.edges } }
    }
}
fn mask11() -> u64 { required_mask() | Payload::VcRuntime.bit() | Payload::VcRuntime1.bit() }
fn synthetic(mask: u64) -> ImageLoaderSelection {
    let fixture = Fixture::new(mask); let profile = fixture.profile();
    let count = admit_profile(&profile, &profile.closure).unwrap();
    ImageLoaderSelection { profile: None, count } // NO compiled pin/production seal
}
fn image_book(mask: u64) -> NativeBook {
    // Private inert constructor only; the PUBLIC constructor refuses synthetic().
    NativeBook::with_purpose(LivePurpose::MetadataImages(synthetic(mask)))
}
fn reserve_token(book: &mut NativeBook) -> Result<Original> {
    book.reserve(Kind::ThreadToken, None, "", String::new())
}
fn fill(book: &mut NativeBook, count: usize) {
    for _ in 0..count { reserve_token(book).unwrap(); }
}
fn sid(subauthorities: usize) -> Sid {
    let mut bytes = vec![1, subauthorities as u8, 0, 0, 0, 0, 0, 5];
    for i in 0..subauthorities { bytes.extend_from_slice(&(i as u32 + 1).to_le_bytes()); }
    super::super::security::sid_at(&bytes, 0, bytes.len()).unwrap()
}
fn facts(count: usize, sid_subauthorities: usize) -> SecurityFacts {
    let sid = sid(sid_subauthorities);
    SecurityFacts { owner: sid.clone(), control: 0x8004, revision: 2,
        aces: (0..count).map(|_| AceFact { allow: false, flags: 0, mask: 0, sid: sid.clone() }).collect() }
}
fn compact_descriptor(count: usize) -> Vec<u8> {
    // Valid conservative relative descriptor DATA: SYSTEM owner and Everyone
    // read-only ACEs. Compact SIDs allow2048 ACEs inside the existing64KiB buffer.
    let system = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let everyone = [1u8, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    let header = size_of::<S::SECURITY_DESCRIPTOR_RELATIVE>();
    let acl_at = header + system.len();
    let width = offset_of!(S::ACCESS_ALLOWED_ACE, SidStart) + everyone.len();
    let acl_size = size_of::<S::ACL>() + count * width;
    let mut bytes = vec![0u8; acl_at + acl_size];
    bytes[offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Revision)] = 1;
    let control = S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT;
    let control_at = offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Control);
    bytes[control_at..control_at + 2].copy_from_slice(&control.to_le_bytes());
    let owner_at = offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Owner);
    bytes[owner_at..owner_at + 4].copy_from_slice(&(header as u32).to_le_bytes());
    let dacl_at = offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Dacl);
    bytes[dacl_at..dacl_at + 4].copy_from_slice(&(acl_at as u32).to_le_bytes());
    bytes[header..acl_at].copy_from_slice(&system);
    bytes[acl_at + offset_of!(S::ACL, AclRevision)] = 2;
    let size_at = acl_at + offset_of!(S::ACL, AclSize);
    bytes[size_at..size_at + 2].copy_from_slice(&(acl_size as u16).to_le_bytes());
    let count_at = acl_at + offset_of!(S::ACL, AceCount);
    bytes[count_at..count_at + 2].copy_from_slice(&(count as u16).to_le_bytes());
    for index in 0..count {
        let at = acl_at + size_of::<S::ACL>() + index * width;
        bytes[at + offset_of!(S::ACE_HEADER, AceType)] = 0; // ACCESS_ALLOWED_ACE_TYPE
        let size_at = at + offset_of!(S::ACE_HEADER, AceSize);
        bytes[size_at..size_at + 2].copy_from_slice(&(width as u16).to_le_bytes());
        let mask_at = at + offset_of!(S::ACCESS_ALLOWED_ACE, Mask);
        bytes[mask_at..mask_at + 4].copy_from_slice(&FS::FILE_GENERIC_READ.to_le_bytes());
        let sid_at = at + offset_of!(S::ACCESS_ALLOWED_ACE, SidStart);
        bytes[sid_at..sid_at + everyone.len()].copy_from_slice(&everyone);
    }
    bytes
}

#[test]
fn c01_default_is_still_48_and_synthetic_data_cannot_construct_production_book() {
    assert_eq!(MAX_ORIGINALS, 48);
    for mut standard in [NativeBook::new(), NativeBook::default()] {
        assert!(matches!(standard.purpose, LivePurpose::Standard48));
        assert_eq!(standard.purpose.limit(), 48);
        fill(&mut standard, 48);
        assert!(matches!(reserve_token(&mut standard), Err(Error::Bounds)));
        assert!(standard.capacity_refusal.is_none()); // legacy policy unchanged
        assert_eq!(standard.settle_once(), CloseOutcome::Settled); // only Reserved -> NoHandle, NO OS call
    }
    assert!(ImageLoaderSelection::compiled().is_err());
    assert!(matches!(NativeBook::new_metadata_images_loader(synthetic(required_mask())), Err(Error::Unavailable)));
    // Project44, credential45 and destination38+reservations are unchanged
    // donor leaves/constructors in the sealed diff, not new synthetic profiles.
}

#[test]
fn c02_closed_catalog_required_nine_aliases_duplicates_and_unmapped_inputs() {
    for payload in REQUIRED {
        assert!(FrozenCount::from_mask(required_mask() & !payload.bit()).is_err());
    }
    assert!(FrozenCount::from_mask(required_mask() & !Payload::PythonPath.bit() & !Payload::PythonZip.bit()).is_err());
    assert!(FrozenCount::from_mask(required_mask() | (1u64 << CATALOG_COUNT)).is_err());
    for name in ["python/PYTHON.exe", "python/../python.exe", "python/unknown.dll", "python/python.exe/"] {
        assert!(Payload::from_name(name).is_none());
    }
    let fixture = Fixture::new(required_mask()); let profile = fixture.profile();
    let mut rows = fixture.rows.clone(); rows.push(rows[0]);
    let mut actual = profile.closure; actual.rows = &rows;
    assert!(admit_profile(&profile, &actual).is_err());
    let mut edges = fixture.edges.clone();
    edges.push(ClosureEdge { source: Payload::Bridge.name(), kind: EdgeKind::StaticImport, target: "outside.dll" });
    edges.sort(); actual = profile.closure; actual.edges = &edges;
    assert!(admit_profile(&profile, &actual).is_err());
    let full = Fixture::new(CATALOG_MASK); let full_profile = full.profile();
    let mut rows = full.rows.clone();
    rows.push(Artifact { name: "python/forty_first.dll", bytes: 1, sha256: E, architecture: Architecture::X64Pe });
    let mut actual = full_profile.closure; actual.rows = &rows;
    assert!(admit_profile(&full_profile, &actual).is_err());
}

#[test]
fn c03_count_derived_54_56_85_preserves_exact_directory_envelope_and_overflow() {
    for (mask, count, limit, peak10) in [(required_mask(), 9, 54, 52), (mask11(), 11, 56, 54), (CATALOG_MASK, 40, 85, 83)] {
        let selected = synthetic(mask);
        assert_eq!(selected.selected_count(), count);
        assert_eq!(selected.live_limit(), limit);
        assert_eq!(selected.peak(10), Ok(peak10));
        assert_eq!(selected.peak(12), Ok(limit));
        assert_eq!(selected.peak(13), Err(Error::Bounds));
        assert_eq!(selected.peak(usize::MAX), Err(Error::Bounds));
    }
    let overflowing = FrozenCount { mask: required_mask(), selected: usize::MAX, limit: usize::MAX };
    assert_eq!(overflowing.peak(1), Err(Error::Bounds));
}

#[test]
fn c05_pinned_architecture_hash_transitive_delay_dynamic_and_fingerprint_are_exact() {
    let fixture = Fixture::new(mask11()); let profile = fixture.profile();
    assert!(admit_profile(&profile, &profile.closure).is_ok());
    for changed in 0..2 {
        let mut rows = fixture.rows.clone();
        if changed == 0 { rows[0].sha256 = E; } else { rows[0].architecture = Architecture::Data; }
        // Use a known PE row, not one of the catalog's DATA-only inputs.
        let index = rows.iter().position(|row| row.name == Payload::Python.name()).unwrap();
        if changed == 0 { rows[index].sha256 = E; } else { rows[index].architecture = Architecture::Data; }
        let mut actual = profile.closure; actual.rows = &rows;
        assert!(admit_profile(&profile, &actual).is_err());
    }
    for kind in [EdgeKind::StaticImport, EdgeKind::DelayImport, EdgeKind::DynamicInput] {
        let mut edges = fixture.edges.clone();
        let index = edges.iter().position(|edge| edge.kind == kind).unwrap(); edges.remove(index);
        let mut actual = profile.closure; actual.edges = &edges;
        assert!(admit_profile(&profile, &actual).is_err());
    }
    let mut actual = profile.closure; actual.fingerprint = E;
    assert!(admit_profile(&profile, &actual).is_err());
    actual = profile.closure; actual.dynamic_inputs = E;
    assert!(admit_profile(&profile, &actual).is_err());
    let mut wrong = fixture.profile(); wrong.target = "aarch64-pc-windows-msvc";
    assert!(admit_profile(&wrong, &wrong.closure).is_err());
    assert!(!synthetic(mask11()).production_bound());
    assert!(ImageLoaderSelection::compiled().is_err()); // A valid fixture never writes COMPILED.
}

#[test]
fn c06_purpose_is_frozen_before_original_registration_through_refusal_and_retirement() {
    let mut standard = NativeBook::new();
    assert!(standard.never_started() && !standard.purpose.is_images());
    assert_eq!(standard.purpose.limit(), 48);
    let mut image = image_book(required_mask());
    let identity = std::sync::Arc::as_ptr(&image.identity);
    assert!(image.never_started());
    assert_eq!(image.purpose.limit(), 54);
    let key = reserve_token(&mut image).unwrap();
    assert!(!image.never_started());
    image.close_once(&key).unwrap(); // unentered Reserved only, no native HANDLE
    assert_eq!(image.purpose.limit(), 54);
    assert_eq!(image.capacity_result::<()>(Err(Error::Bounds)), Err(Error::Bounds));
    image.mark_interrupted();
    assert_eq!(image.settle_once(), CloseOutcome::Unknown);
    assert_eq!(std::sync::Arc::as_ptr(&image.identity), identity);
    assert_eq!(image.purpose.limit(), 54);
    assert_eq!(image.capacity_refusal, Some(Error::Bounds));
    assert_eq!(standard.purpose.limit(), 48);
    assert_eq!(standard.settle_once(), CloseOutcome::Settled);
}

#[test]
fn c07_real_native_reserve_counts_every_non_absent_state_and_never_recycles_rows() {
    for state in [SlotState::Reserved, SlotState::Acquiring, SlotState::Owned, SlotState::Closing, SlotState::Unknown] {
        let mut book = image_book(required_mask()); fill(&mut book, 54);
        // Pure state fixture; NO native handle/output is fabricated as usable.
        book.slot_mut(0).unwrap().state = state;
        assert!(counts_live(state));
        assert!(matches!(reserve_token(&mut book), Err(Error::Bounds)));
        assert_eq!(book.slots.len(), 54);
    }
    for state in [SlotState::NoHandle, SlotState::Closed] {
        let mut book = image_book(required_mask()); fill(&mut book, 54);
        book.slot_mut(0).unwrap().state = state;
        assert!(!counts_live(state));
        assert!(reserve_token(&mut book).is_ok());
        assert_eq!(book.slots.len(), 55); // previous lifetime row remains
    }
    let mut book = image_book(required_mask());
    let key = book.reserve(Kind::File, None, "x", "one-original".to_owned()).unwrap();
    book.close_once(&key).unwrap();
    assert!(matches!(book.reserve(Kind::File, None, "x", "one-original".to_owned()), Err(Error::State)));
    assert_eq!(book.slots.len(), 1);
}

#[test]
fn c08_inventory_transient_positive_close_then_exact_31_os_phase_is_mandatory() {
    let selection = synthetic(mask11());
    let mut walk = ImageWalk::new(&selection);
    walk.before_directory().unwrap();
    walk.before_payload(None).unwrap();
    assert!(walk.transient);
    walk.transient_closed(SlotState::Closed).unwrap();
    for payload in selection.selected() { walk.before_payload(Some(payload)).unwrap(); }
    walk.enter_loader(true, selection.selected_mask(), false).unwrap();
    walk.before_directory().unwrap(); // known-location parents, before first OS
    for image in SystemImage::ALL { walk.before_os(*image).unwrap(); }
    walk.ready(true).unwrap(); assert!(walk.is_ready());
    assert!(walk.before_payload(None).is_err()); // no spare leaf after OS retention
    let mut wrong = ImageWalk::new(&selection);
    assert!(wrong.enter_loader(true, selection.selected_mask(), false).is_err());
    let mut wrong = ImageWalk::new(&selection);
    wrong.before_payload(None).unwrap();
    assert!(wrong.transient_closed(SlotState::NoHandle).is_err());
    let mut wrong = ImageWalk::new(&selection);
    for payload in selection.selected() { wrong.before_payload(Some(payload)).unwrap(); }
    assert!(wrong.enter_loader(true, selection.selected_mask(), true).is_err());
    let mut wrong = ImageWalk::new(&selection);
    for payload in selection.selected() { wrong.before_payload(Some(payload)).unwrap(); }
    wrong.enter_loader(true, selection.selected_mask(), false).unwrap();
    wrong.before_os(SystemImage::ALL[0]).unwrap();
    assert!(wrong.before_os(SystemImage::ALL[0]).is_err());
    assert_eq!(selection.peak(12), Ok(selection.live_limit()));
}

#[test]
fn c09_security_actual_capacity_old_new_and_reserved_query_are_one_image_ceiling() {
    let mut old = facts(1, 15);
    assert_eq!(old.aces[0].sid.bytes().len(), 68);
    let before = security_storage(&old).unwrap();
    let capacity = old.aces.capacity(); old.aces.reserve(31);
    assert!(old.aces.capacity() > old.aces.len());
    assert_eq!(security_storage(&old).unwrap() - before,
        (old.aces.capacity() - capacity) * size_of::<AceFact>());
    let reservation = SecurityReservation::reserve(std::iter::once(&old)).unwrap();
    assert_eq!(reservation.facts.retained_bytes, security_storage(&old).unwrap());
    let fresh = facts(2048, 15); // worst-size decoded DATA, not a native descriptor
    assert_eq!(fresh.aces.len(), 2048);
    assert!(reservation.admit_observed(&fresh).is_ok());
    let working = reservation.facts.query_reservation;
    assert_eq!(security_total(SECURITY_BYTES - working, 0, working), Ok(SECURITY_BYTES));
    assert_eq!(security_total(SECURITY_BYTES - working, 1, working), Err(Error::Bounds));
    assert_eq!(security_total(usize::MAX, 1, working), Err(Error::Bounds));
    assert!(security_total(SECURITY_BYTES / 2, SECURITY_BYTES / 2, working).is_err()); // BOTH old/new plus work
    let mut excessive = facts(1, 1);
    excessive.aces.reserve(SECURITY_BYTES / size_of::<AceFact>());
    assert!(reservation.admit_observed(&excessive).is_err());
    let observation = super::super::security::Observed::new(super::super::Refusal::none());
    let raw = compact_descriptor(2048);
    assert!(raw.len() < BUFFER);
    assert!(observation.image_descriptor(&raw, super::super::FileKind::File,
        super::super::AuthorityScope::ImmutableVersion, reservation.facts.decoded_reservation).is_ok());
    assert!(observation.image_descriptor(&raw, super::super::FileKind::File,
        super::super::AuthorityScope::ImmutableVersion, 1).is_err()); // allocation cannot outrun reservation
    assert!(observation.image_descriptor(&compact_descriptor(2049), super::super::FileKind::File,
        super::super::AuthorityScope::ImmutableVersion, reservation.facts.decoded_reservation).is_err());
}

#[test]
fn c10_image_allowance_does_not_enlarge_lifetime_file_entry_or_read_quotas() {
    assert_eq!((MAX_RECORDS, MAX_FILES, MAX_ENTRIES), (8256, 2048, 8192));
    assert_eq!((MAX_FILE_BYTES, MAX_TOTAL_BYTES), (512 * 1024 * 1024, 1024 * 1024 * 1024));
    let mut records = image_book(required_mask());
    for _ in 0..MAX_RECORDS {
        let key = reserve_token(&mut records).unwrap(); records.close_once(&key).unwrap();
    }
    assert!(matches!(reserve_token(&mut records), Err(Error::Bounds)));
    assert_eq!(records.slots.len(), MAX_RECORDS);
    let mut files = image_book(required_mask());
    for index in 0..MAX_FILES {
        let key = files.reserve(Kind::File, None, "x", format!("original-{index}")).unwrap();
        files.close_once(&key).unwrap();
    }
    assert!(matches!(files.reserve(Kind::File, None, "x", "extra-original".to_owned()), Err(Error::Bounds)));
    let mut entries = MAX_ENTRIES - 1;
    assert_eq!(charge_entries(&mut entries, 1), Ok(()));
    assert_eq!(charge_entries(&mut entries, 1), Err(Error::Bounds));
    assert_eq!(entries, MAX_ENTRIES + 1); // exhausted original aggregate, not reset
    let mut overflow = usize::MAX;
    assert_eq!(charge_entries(&mut overflow, 1), Err(Error::Bounds));
    for limit in [MAX_FILE_BYTES, MAX_TOTAL_BYTES] {
        let mut total = limit - 1;
        assert_eq!(charge_read(&mut total, 1, limit), Ok(()));
        assert_eq!(charge_read(&mut total, 1, limit), Err(Error::Bounds));
        assert_eq!(total, limit + 1);
    }
}

#[test]
fn c12_capacity_refusal_never_drops_pending_frame_original_or_first_error() {
    let mut book = image_book(required_mask());
    let key = reserve_token(&mut book).unwrap();
    let identity = std::sync::Arc::as_ptr(&book.identity);
    let original_slot = book.slots[0].as_ref().get_ref() as *const super::super::Slot;
    // An inert retention fixture, never entered into Windows. The real guard is
    // shared with every native active frame and does not need a fabricated join.
    book.active = Some(ManuallyDrop::new(Box::pin(Arena {
        call: super::super::Call::ThreadToken(key.index), token_length: 0,
        phase: Cell::new(super::super::Phase::Entered), returned: Cell::new(None),
        completion_refusal: Cell::new(None), input: Vec::new(), handle: null_mut(), output_handle: null_mut(),
        unicode: F::UNICODE_STRING::default(),
        attributes: windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES::default(),
        directory: false, file_purpose: super::super::FileReadPurpose::Content,
        bytes: UnsafeCell::new(super::super::Aligned([0; BUFFER])), count: UnsafeCell::new(u32::MAX),
        iosb: UnsafeCell::new(IO::IO_STATUS_BLOCK {
            Anonymous: IO::IO_STATUS_BLOCK_0 { Status: F::STATUS_PENDING }, Information: usize::MAX,
        }), _pin: PhantomPinned,
    })));
    let frame = book.active.as_ref().unwrap().as_ref().get_ref() as *const Arena;
    assert_eq!(book.capacity_result::<()>(Err(Error::Bounds)), Err(Error::Bounds));
    assert_eq!(book.capacity_result::<()>(Err(Error::State)), Err(Error::State));
    assert!(matches!(reserve_token(&mut book), Err(Error::Unknown)));
    assert_eq!(book.close_once(&key), Err(Error::Unknown));
    assert_eq!(book.settle_once(), CloseOutcome::Unknown);
    assert_eq!(book.capacity_refusal, Some(Error::Bounds));
    assert_eq!(book.active.as_ref().unwrap().as_ref().get_ref() as *const Arena, frame);
    assert_eq!(book.slots[0].as_ref().get_ref() as *const super::super::Slot, original_slot);
    assert_eq!(std::sync::Arc::as_ptr(&book.identity), identity);
    assert_eq!(book.slots.len(), 1);
    assert_eq!(book.state(&key), Ok(SlotState::Reserved));
}
