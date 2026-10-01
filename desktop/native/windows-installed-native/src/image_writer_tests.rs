//! Inert contract-test SOURCE only. No hosted Windows primitive is qualified by
//! these tests. They contain no call to a native acquisition/write/close method.
use super::*;

fn plan(role: ImageRole) -> Vec<PlannedChild> {
    vec![PlannedChild { parent: 0, name: "new-a".to_owned(), role }]
}
fn fixture_descriptor() -> Vec<u8> {
    let mut raw = vec![0u8; 72];
    raw[0] = 1;
    raw[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    raw[4..8].copy_from_slice(&20u32.to_le_bytes());
    raw[8..12].copy_from_slice(&32u32.to_le_bytes());
    raw[16..20].copy_from_slice(&44u32.to_le_bytes());
    for (at, sub) in [(20, 21u32), (32, 22), (60, 21)] {
        raw[at] = 1;
        raw[at + 1] = 1;
        raw[at + 7] = 5;
        raw[at + 8..at + 12].copy_from_slice(&sub.to_le_bytes());
    }
    raw[44] = 2;
    raw[46..48].copy_from_slice(&28u16.to_le_bytes());
    raw[48..50].copy_from_slice(&1u16.to_le_bytes());
    raw[54..56].copy_from_slice(&20u16.to_le_bytes());
    raw[56..60].copy_from_slice(&FS::FILE_GENERIC_READ.to_le_bytes());
    raw
}

#[test]
fn roles_request_exact_first_acquisition_rights() {
    for role in [ImageRole::ExistingDirectory, ImageRole::MutationParent,
        ImageRole::Config, ImageRole::IgnoreFile, ImageRole::UnchangedImage,
        ImageRole::ReplaceTarget, ImageRole::PrivateDirectory, ImageRole::ControlFile,
        ImageRole::StagedImage, ImageRole::StagedDirectory] {
        let access = role.access();
        assert_eq!(access & R, R);
        if !role.create() { assert_eq!(access & (FS::WRITE_DAC | FS::WRITE_OWNER), 0); }
        assert_eq!(role.content_writer(), matches!(role, ImageRole::ControlFile | ImageRole::StagedImage));
    }
    assert_eq!(ImageRole::ExistingDirectory.access(), DI);
    assert_eq!(ImageRole::MutationParent.access(), DW);
    assert_eq!(ImageRole::ReplaceTarget.access(), FW);
    assert_eq!(ImageRole::PrivateDirectory.access(), DW | FS::DELETE);
    assert_eq!(ImageRole::StagedImage.access(), FW | FS::WRITE_DAC | FS::WRITE_OWNER);
    assert_eq!(ImageRole::StagedDirectory.access(), DW | FS::DELETE | FS::WRITE_DAC | FS::WRITE_OWNER);
    assert!(!ImageRole::ReplaceTarget.content_writer());
}
#[test]
fn exclusive_create_never_uses_existing_open_adoption() {
    assert_eq!(acquisition_information(false), WP::FILE_OPENED as usize);
    assert_eq!(acquisition_information(true), WP::FILE_CREATED as usize);
    assert_ne!(acquisition_information(false), acquisition_information(true));
}
#[test]
fn preparation_is_bounded_frozen_and_book_bound_without_native_entry() {
    let first = ImagePrimitives::prepare(r"C:\work\app", &plan(ImageRole::ControlFile)).unwrap();
    let second = ImagePrimitives::prepare(r"C:\work\app", &plan(ImageRole::ControlFile)).unwrap();
    assert!(first.native.never_started());
    assert!(first.effects().is_empty());
    assert_eq!(first.rows[first.root].role, ImageRole::MutationParent);
    assert_eq!(first.rows[first.root + 1].parent, Some(first.root));
    assert!(matches!(second.row(&first.key(1).unwrap()), Err(Error::State)));
    assert!(matches!(first.key(2), Err(Error::State)));
    assert!(first.costs().unwrap().retained_heap_bytes < HEAP_BYTES);
}
#[test]
fn unsupported_names_aliases_parents_and_peak_fail_before_native_entry() {
    for path in [r"\\server\share\app", r"C:\work\..\app", r"C:\prøject"] {
        assert!(ImagePrimitives::prepare(path, &[]).is_err());
    }
    let mut children = plan(ImageRole::ControlFile);
    children.push(PlannedChild { parent: 0, name: "NEW-A".to_owned(), role: ImageRole::Config });
    assert!(matches!(ImagePrimitives::prepare(r"C:\work\app", &children), Err(Error::Unsafe)));
    children[1].name = "child".to_owned();
    children[1].parent = 1;
    assert!(matches!(ImagePrimitives::prepare(r"C:\work\app", &children), Err(Error::State)));
    children[0].parent = 1;
    assert!(matches!(ImagePrimitives::prepare(r"C:\work\app", &children), Err(Error::State)));
    let many: Vec<_> = (0..MAX_PLAN_ROWS).map(|i| PlannedChild {
        parent: 0, name: format!("leaf-{i}"), role: ImageRole::Config,
    }).collect();
    assert!(matches!(ImagePrimitives::prepare(r"C:\work\app", &many), Err(Error::Bounds)));
}
#[test]
fn pass_and_context_bounds_cannot_reset_the_shared_ledger() {
    let mut owner = ImagePrimitives::prepare(r"C:\work\app", &plan(ImageRole::Config)).unwrap();
    owner.passes = MAX_PASSES;
    let key = owner.key(1).unwrap();
    assert!(matches!(owner.begin_read_pass(&key), Err(Error::Bounds)));
    assert_eq!(owner.passes, MAX_PASSES);
    assert_eq!(owner.first_failure(), Some(Error::Bounds));
    assert!(matches!(owner.begin_once(), Err(Error::State)));
    assert_eq!(owner.native.bytes_read, 0);
    assert_eq!(owner.native.entries, 0);
    assert!(owner.native.never_started());
}
#[test]
fn descriptor_retains_owner_group_layout_mask_flags_order_and_control() {
    let raw = fixture_descriptor();
    let observed = descriptor(&raw).unwrap();
    assert_eq!(observed.raw, raw);
    let mut changed = raw.clone();
    changed[40..44].copy_from_slice(&23u32.to_le_bytes()); // group, not discarded
    assert_ne!(descriptor(&changed).unwrap(), observed);
    changed = raw.clone();
    changed[2..4].copy_from_slice(&0x9004u16.to_le_bytes()); // protected DACL
    assert_ne!(descriptor(&changed).unwrap(), observed);
    changed = raw.clone();
    changed[52] = 1; // ordered deny ACE retained, never simplified to an allow
    assert_ne!(descriptor(&changed).unwrap(), observed);
}
#[test]
fn descriptor_refuses_unknown_control_ace_layout_and_null_group_or_dacl() {
    let raw = fixture_descriptor();
    for offset in [8usize, 16] {
        let mut changed = raw.clone();
        changed[offset..offset + 4].fill(0);
        assert!(descriptor(&changed).is_err());
    }
    for (offset, value) in [(0, 2u8), (1, 1), (44, 4), (52, 2), (53, 0x80)] {
        let mut changed = raw.clone();
        changed[offset] = value;
        assert!(descriptor(&changed).is_err());
    }
    let mut overlap = raw.clone();
    overlap[8..12].copy_from_slice(&24u32.to_le_bytes());
    assert!(descriptor(&overlap).is_err());
    let mut unknown = raw.clone();
    unknown[2..4].copy_from_slice(&0x8014u16.to_le_bytes()); // SACL_PRESENT
    assert!(descriptor(&unknown).is_err());
    let mut count = raw;
    count[48..50].copy_from_slice(&(MAX_ACES as u16 + 1).to_le_bytes());
    assert!(descriptor(&count).is_err());
}
#[test]
fn numerical_reservations_do_not_enlarge_native_limits() {
    assert_eq!(MAX_PLAN_ROWS + 10, MAX_LIVE);
    assert!(MAX_PLAN_ROWS + 1 + 2 * USER_CHECKS as usize + 24 <= MAX_RECORDS);
    assert!(IMAGE_ENTRIES <= MAX_ENTRIES);
    assert!(IMAGE_BYTES <= MAX_TOTAL_BYTES);
    assert!(PASS_BYTES <= MAX_FILE_BYTES);
    assert_eq!(IMAGE_BYTES, 256 * 1024 * 1024);
}


// The following are also inert DATA regressions. Synthetic returned frames below
// never dispatch a Windows call and are NOT evidence of actual OS completion.
fn lifecycle_children() -> Vec<PlannedChild> {
    vec![
        PlannedChild { parent: 0, name: "journal".to_owned(), role: ImageRole::PrivateDirectory },
        PlannedChild { parent: 1, name: "stage".to_owned(), role: ImageRole::StagedDirectory },
        PlannedChild { parent: 2, name: "leaf".to_owned(), role: ImageRole::StagedImage },
        PlannedChild { parent: 0, name: "destination".to_owned(), role: ImageRole::MutationParent },
        PlannedChild { parent: 0, name: "target".to_owned(), role: ImageRole::ReplaceTarget },
    ]
}
fn planned_edge(parent: u16, name: &str) -> PlannedEdge { PlannedEdge { parent, name: name.to_owned() } }
fn lifecycle_moves() -> Vec<PlannedMove> {
    vec![
        PlannedMove { source: 2, from: planned_edge(1, "stage"), to: planned_edge(4, "published") },
        PlannedMove { source: 2, from: planned_edge(4, "published"), to: planned_edge(1, "stage") },
        PlannedMove { source: 5, from: planned_edge(0, "target"), to: planned_edge(1, "old-0") },
    ]
}
fn lifecycle_owner() -> ImagePrimitives {
    ImagePrimitives::prepare_lifecycle(r"C:\work\app", &lifecycle_children(), &lifecycle_moves(),
        &[PlannedDelete { source: 5, at: planned_edge(1, "old-0") }]).unwrap()
}
fn data_snapshot(kind: FileKind, id: u8) -> Snapshot {
    Snapshot { metadata: Metadata { identity: FileIdentity { volume_serial: 7, file_id: [id; 16] },
        kind, attributes: if kind == FileKind::Directory { FS::FILE_ATTRIBUTE_DIRECTORY } else { FS::FILE_ATTRIBUTE_ARCHIVE },
        size: 12, allocation_size: 4096, links: 1, creation: 1, write: 2, change: 3 },
        security: descriptor(&fixture_descriptor()).unwrap() }
}
fn data_entry(name: &str, facts: &Snapshot) -> DirectoryEntry {
    DirectoryEntry { name: name.to_owned(), file_id: facts.metadata.identity.file_id,
        kind: facts.metadata.kind, attributes: facts.metadata.attributes }
}
fn data_proof(parent: usize, entries: Vec<DirectoryEntry>) -> RosterEvidence {
    RosterEvidence { row: parent, generation: 1, epoch: 0,
        after: data_snapshot(FileKind::Directory, 99), entries }
}
fn install_returned_frame(owner: &mut ImagePrimitives, call: ImageCall, status: i32, io: i32, information: usize) {
    owner.effects.push(EffectObservation { kind: call.kind(), row: call.row() as u16,
        entered: true, returned: Some(NativeReturn::Nt(status)), iosb_status: None,
        information: None, adopted: false, latched: false, complete: false });
    owner.active = Some(ManuallyDrop::new(Box::pin(Frame {
        call, effect: owner.effects.len() - 1, phase: Cell::new(Phase::Returned),
        returned: Cell::new(Some(Returned::Nt(status))), handle: null_mut(), output_handle: null_mut(),
        input: Vec::new(), unicode: F::UNICODE_STRING::default(), attributes: OBJECT_ATTRIBUTES::default(),
        access: 0, directory: false, offset: 0, information_length: 0,
        bytes: UnsafeCell::new(Aligned([0; BUFFER])), count: UnsafeCell::new(u32::MAX),
        iosb: UnsafeCell::new(IO::IO_STATUS_BLOCK { Anonymous: IO::IO_STATUS_BLOCK_0 { Status: io }, Information: information }),
        _pin: PhantomPinned,
    })));
}
fn entered_move_data() -> (ImagePrimitives, ImageCall, String) {
    let mut owner = lifecycle_owner();
    owner.namespace.bind_volume(r"\Device\HarddiskVolume1").unwrap();
    let row = owner.root + 2;
    let before_name = owner.namespace.claim_acquisition(row).unwrap();
    owner.namespace.bind_original(row, 17).unwrap();
    let mut prepared = owner.namespace.prepare_move(0).unwrap();
    owner.namespace.enter_move(&mut prepared).unwrap();
    owner.pending_move = Some(PendingMove { step: 0, before: data_snapshot(FileKind::Directory, 8), prepared: Some(prepared) });
    owner.move_observations[0].entered = true;
    owner.move_observations[0].change_before = Some(3);
    (owner, ImageCall::Rename { row, step: 0 }, before_name)
}

#[test]
fn lifecycle_keys_edges_and_backup_roles_are_frozen_before_native_entry() {
    let first = lifecycle_owner();
    let other = lifecycle_owner();
    assert!(first.native.never_started());
    assert_eq!(first.namespace.move_count(), 3);
    assert_eq!(first.namespace.delete_count(), 1);
    assert!(other.move_step(&first.move_key(0).unwrap()).is_err());
    assert!(other.delete_step(&first.delete_key(0).unwrap()).is_err());
    assert!(first.move_key(3).is_err() && first.delete_key(1).is_err());
    let root_move = [PlannedMove { source: 0, from: planned_edge(0, "app"), to: planned_edge(1, "app") }];
    assert!(ImagePrimitives::prepare_lifecycle(r"C:\work\app", &lifecycle_children(), &root_move, &[]).is_err());
    let live_target_delete = [PlannedDelete { source: 5, at: planned_edge(0, "target") }];
    assert!(ImagePrimitives::prepare_lifecycle(r"C:\work\app", &lifecycle_children(), &lifecycle_moves(), &live_target_delete).is_err());
    let unsafe_backup = [PlannedMove { source: 5, from: planned_edge(0, "target"), to: planned_edge(4, "old-0") }];
    assert!(ImagePrimitives::prepare_lifecycle(r"C:\work\app", &lifecycle_children(), &unsafe_backup, &[]).is_err());
    let mut invalid_name = lifecycle_moves();
    invalid_name[0].to.name = "con".to_owned();
    assert!(ImagePrimitives::prepare_lifecycle(r"C:\work\app", &lifecycle_children(), &invalid_name, &[]).is_err());
}
#[test]
fn private_current_name_binds_book_original_slot_row_and_epoch() {
    let mut owner = lifecycle_owner();
    owner.namespace.bind_volume(r"\Device\HarddiskVolume1").unwrap();
    let row = owner.root + 2;
    owner.namespace.claim_acquisition(row).unwrap();
    owner.namespace.bind_original(row, 17).unwrap();
    let other_book = Arc::new(());
    {
        let name = CurrentName { book: &owner.native.identity, slot: 17, row, epoch: 0, namespace: &owner.namespace };
        assert!(name.canonical_for(&owner.native.identity, 17).unwrap().ends_with(r"\journal\stage"));
        assert!(name.canonical_for(&other_book, 17).is_err());
        assert!(name.canonical_for(&owner.native.identity, 18).is_err());
        let wrong_row = CurrentName { row: row + 1, ..name };
        assert!(wrong_row.canonical_for(&owner.native.identity, 17).is_err());
    }
    let epoch = owner.namespace.next_epoch().unwrap();
    owner.namespace.latch_epoch(epoch);
    let stale = CurrentName { book: &owner.native.identity, slot: 17, row, epoch: 0, namespace: &owner.namespace };
    assert!(stale.canonical_for(&owner.native.identity, 17).is_err());
}
#[test]
fn accepted_rename_latches_before_later_refusal_without_rewriting_acquisition() {
    let (mut owner, call, old) = entered_move_data();
    let row = call.row();
    let acquisition_parent = owner.rows[row].parent;
    let acquisition_leaf = owner.rows[row].name.clone();
    install_returned_frame(&mut owner, call, F::STATUS_SUCCESS, F::STATUS_SUCCESS, 0);
    owner.finish(call, Returned::Nt(F::STATUS_SUCCESS)).unwrap();
    assert_eq!(owner.namespace.epoch(), 1);
    assert_ne!(owner.namespace.name(row, 1).unwrap(), old);
    assert!(owner.namespace.name(row + 1, 1).unwrap().ends_with(r"\destination\published\leaf"));
    assert_eq!(owner.rows[row].parent, acquisition_parent);
    assert_eq!(owner.rows[row].name, acquisition_leaf);
    assert!(owner.effects[0].latched && owner.move_observations[0].accepted);
    assert!(!owner.move_observations[0].finalized && !owner.accepted_effects_finalized());
    assert!(owner.namespace.prepare_move(0).is_err());
    let _ = owner.record::<()>(Err(Error::Unsafe)); // a fallible postcheck, NOT rollback
    assert_eq!(owner.namespace.epoch(), 1);
    assert_eq!(owner.first_failure(), Some(Error::Unsafe));
    assert!(owner.mutation_idle().is_err());
    let _ = owner.record::<()>(Err(Error::State));
    assert_eq!(owner.first_failure(), Some(Error::Unsafe));
}
#[test]
fn uncertain_rename_keeps_exact_frame_plan_claims_and_both_parents() {
    for status in [F::STATUS_PENDING, 0x40000000, 0x80000000u32 as i32] {
        let (mut owner, call, old) = entered_move_data();
        install_returned_frame(&mut owner, call, status, F::STATUS_SUCCESS, 0);
        assert!(matches!(owner.finish(call, Returned::Nt(status)), Err(Error::Unknown)));
        assert!(owner.active.is_some() && owner.pending_move.as_ref().unwrap().prepared.is_some());
        assert_eq!(owner.namespace.epoch(), 0);
        assert_eq!(owner.namespace.name(call.row(), 0).unwrap(), old);
        assert!(owner.namespace.prepare_move(0).is_err());
        let plan = owner.namespace.move_plan(0).unwrap();
        let needed = owner.protected_rows();
        assert_ne!(needed & (1u64 << plan.from.parent), 0);
        assert_ne!(needed & (1u64 << plan.to.parent), 0);
        let frame = owner.frame().unwrap() as *const Frame;
        assert_eq!(owner.retire_handles_once(), CloseOutcome::Unknown);
        assert_eq!(owner.frame().unwrap() as *const Frame, frame);
        assert_eq!(owner.retire_handles_once(), CloseOutcome::Unknown);
        assert_eq!(owner.effects.len(), 1); // no close or redispatch through frame
    }
}
#[test]
fn contradictory_rename_success_does_not_latch_or_drop_storage() {
    for (io, information) in [(F::STATUS_PENDING, 0), (F::STATUS_SUCCESS, 1)] {
        let (mut owner, call, _) = entered_move_data();
        install_returned_frame(&mut owner, call, F::STATUS_SUCCESS, io, information);
        assert!(matches!(owner.finish(call, Returned::Nt(F::STATUS_SUCCESS)), Err(Error::Unknown)));
        assert!(owner.active.is_some() && !owner.effects[0].latched);
        assert!(!owner.move_observations[0].accepted);
        assert_eq!(owner.namespace.epoch(), 0);
    }
}
#[test]
fn rename_changes_only_change_time_and_records_no_content_security_exemption() {
    let before = data_snapshot(FileKind::File, 5);
    let mut after = before.clone();
    after.metadata.change += 10;
    assert!(same_after_rename(&before, &after));
    after.metadata.write += 1;
    assert!(!same_after_rename(&before, &after));
    after = before.clone(); after.metadata.size += 1;
    assert!(!same_after_rename(&before, &after));
    after = before.clone(); after.metadata.allocation_size += 4096;
    assert!(!same_after_rename(&before, &after));
    after = before.clone(); after.metadata.identity.file_id[15] ^= 1;
    assert!(!same_after_rename(&before, &after));
    after = before.clone(); after.security.raw[40] ^= 1;
    assert!(!same_after_rename(&before, &after));
}
#[test]
fn completed_roster_authority_is_same_book_parent_generation_and_epoch() {
    let mut owner = lifecycle_owner();
    owner.namespace.bind_volume(r"\Device\HarddiskVolume1").unwrap();
    let row = owner.root;
    owner.roster_evidence.push(data_proof(row, Vec::new()));
    owner.latest_roster[row] = 1;
    let key = PassKey { book: Arc::clone(&owner.native.identity), row, generation: 1 };
    assert_eq!(owner.roster_index(&key, row).unwrap(), 0);
    assert!(owner.roster_index(&key, row + 1).is_err());
    let wrong = PassKey { book: Arc::new(()), row, generation: 1 };
    assert!(owner.roster_index(&wrong, row).is_err());
    owner.latest_roster[row] = 2;
    assert!(owner.roster_index(&key, row).is_err());
    owner.latest_roster[row] = 1;
    let epoch = owner.namespace.next_epoch().unwrap(); owner.namespace.latch_epoch(epoch);
    assert!(owner.roster_index(&key, row).is_err());
}
#[test]
fn endpoint_absence_uses_full_id_and_only_the_declared_same_parent_exception() {
    let source = data_snapshot(FileKind::File, 6);
    let old = namespace::Edge { parent: 3, name: "old".to_owned() };
    let new = namespace::Edge { parent: 3, name: "new".to_owned() };
    let proof = data_proof(3, vec![data_entry("new", &source)]);
    assert!(endpoint_absent(&proof, &old, source.metadata.identity, Some(&new)).is_ok());
    assert!(endpoint_present(&proof, &new, &source).is_ok());
    assert!(endpoint_absent(&proof, &old, source.metadata.identity, None).is_err()); // deletion has no exception
    assert!(endpoint_absent(&proof, &new, source.metadata.identity, None).is_err());
    let alias = data_proof(3, vec![data_entry("alias", &source)]);
    assert!(endpoint_absent(&alias, &old, source.metadata.identity, Some(&new)).is_err());
    assert!(endpoint_present(&alias, &new, &source).is_err());
    let wrong_parent = data_proof(4, Vec::new());
    assert!(endpoint_absent(&wrong_parent, &old, source.metadata.identity, None).is_err());
    let mut other_id = source.clone(); other_id.metadata.identity.file_id[15] ^= 1;
    let unrelated = data_proof(3, vec![data_entry("unrelated", &other_id)]);
    assert!(endpoint_absent(&unrelated, &old, source.metadata.identity, None).is_ok());
}
#[test]
fn disposition_acceptance_is_not_positive_close_absence_fence_or_deletion() {
    let children = plan(ImageRole::ControlFile);
    let mut owner = ImagePrimitives::prepare_lifecycle(r"C:\work\app", &children, &[],
        &[PlannedDelete { source: 1, at: planned_edge(0, "new-a") }]).unwrap();
    owner.namespace.bind_volume(r"\Device\HarddiskVolume1").unwrap();
    let row = owner.root + 1;
    owner.namespace.claim_acquisition(row).unwrap();
    let epoch = owner.namespace.enter_delete(0).unwrap();
    owner.pending_deletion = Some(0);
    owner.deletion_observations[0].entered = true;
    let call = ImageCall::Disposition { row, step: 0, epoch };
    install_returned_frame(&mut owner, call, F::STATUS_SUCCESS, F::STATUS_SUCCESS, 0);
    owner.finish(call, Returned::Nt(F::STATUS_SUCCESS)).unwrap();
    let fact = owner.deletion_observations[0];
    assert!(fact.disposition_accepted && !fact.close_attempted && !fact.handle_retired && !fact.deleted);
    assert_eq!(fact.disposition_epoch, Some(1));
    assert!(owner.delete_pending(row) && !owner.accepted_effects_finalized());
    assert!(owner.mutation_idle().is_err());
    // No original was fabricated. A missing close receipt cannot become deleted.
    assert!(matches!(owner.close_disposed_once(&owner.delete_key(0).unwrap()), Err(Error::State)));
    assert!(!owner.deletion_observations[0].handle_retired && !owner.deletion_observations[0].deleted);
}
#[test]
fn current_deletion_parent_stays_protected_after_positive_handle_retirement() {
    let mut owner = lifecycle_owner();
    let step = 0;
    let plan = owner.namespace.delete_plan(step).unwrap().clone();
    assert_ne!(Some(plan.edge.parent), owner.rows[plan.row].parent);
    owner.pending_deletion = Some(step);
    owner.deletion_observations[step].disposition_accepted = true;
    owner.deletion_observations[step].close_attempted = true;
    owner.deletion_observations[step].handle_retired = true; // synthetic DATA, not a native receipt
    let protected = owner.protected_rows();
    assert_ne!(protected & (1u64 << plan.edge.parent), 0);
    assert_eq!(protected & (1u64 << plan.row), 0);
    assert!(!owner.deletion_observations[step].deleted);
}
#[test]
fn unknown_children_block_union_parents_not_independent_known_originals() {
    let owner = lifecycle_owner();
    let plan = owner.namespace.move_plan(0).unwrap();
    let source = plan.row;
    let child = source + 1;
    let unknown_live = 1u64 << child;
    assert!(owner.namespace.has_live_dependency(source, unknown_live));
    let parents = owner.namespace.dependency_closure(unknown_live);
    assert_ne!(parents & (1u64 << plan.from.parent), 0);
    assert_ne!(parents & (1u64 << plan.to.parent), 0);
    assert!(!owner.namespace.has_live_dependency(owner.root + 5, unknown_live));
    for state in [SlotState::Acquiring, SlotState::Closing, SlotState::Unknown, SlotState::Closed, SlotState::NoHandle] {
        assert!(!known_close_candidate(state, false));
    }
    for state in [SlotState::Reserved, SlotState::Owned] {
        assert!(known_close_candidate(state, false));
        assert!(!known_close_candidate(state, true)); // never retry any consuming request
    }
}
#[test]
fn locked_sdk_information_layouts_and_pending_storage_keep_original_caps() {
    assert_eq!(offset_of!(N::FILE_RENAME_INFORMATION, RootDirectory), 8);
    assert_eq!(offset_of!(N::FILE_RENAME_INFORMATION, FileNameLength), 16);
    assert_eq!(offset_of!(N::FILE_RENAME_INFORMATION, FileName), 20);
    assert_eq!(offset_of!(N::FILE_DISPOSITION_INFORMATION, DeleteFile), 0);
    assert_eq!(size_of::<N::FILE_DISPOSITION_INFORMATION>(), 1);
    let (owner, _, _) = entered_move_data();
    assert!(owner.pending_move.as_ref().unwrap().prepared.as_ref().unwrap().heap_bytes().unwrap() > 0);
    assert!(owner.costs().unwrap().retained_heap_bytes < HEAP_BYTES);
    assert_eq!(namespace::MAX_ROWS, MAX_PLAN_ROWS);
    assert_eq!(namespace::MAX_MOVES, 16);
    assert_eq!(MAX_LIVE, 48);
}

#[test]
fn exact_fence_binding_rejects_stale_parent_roster_and_moved_directory_timestamps() {
    let mut owner = lifecycle_owner();
    let row = owner.root;
    owner.roster_evidence.push(data_proof(row, Vec::new()));
    owner.latest_roster[row] = 1;
    let parent_after = owner.roster_evidence[0].after.clone();
    let source_after = data_snapshot(FileKind::Directory, 7);
    // The actual shared binding/comparison seam, called on BOTH sides of each
    // original fence. These are inert snapshots, not native fence receipts.
    for (row, expected, proved) in [
        (row, FenceExpected::Roster(0), &parent_after),
        (row + 2, FenceExpected::SourceAfter(&source_after), &source_after),
    ] {
        assert_eq!(owner.check_fence_snapshot(row, expected, proved), Ok(()));
        for change_time in [false, true] {
            let mut changed = (*proved).clone();
            if change_time { changed.metadata.change += 1; } else { changed.metadata.write += 1; }
            assert!(same_identity_security(proved, &changed)); // loose directory check allows it
            assert_eq!(owner.check_fence_snapshot(row, expected, &changed), Err(Error::Unsafe));
            // A later stable before/after pair cannot replace the earlier proof.
            let stable_later = changed.clone();
            assert_eq!(changed, stable_later);
            assert_eq!(owner.check_fence_snapshot(row, expected, &stable_later), Err(Error::Unsafe));
        }
    }
    assert!(owner.native.never_started() && owner.effects().is_empty());
}
