use super::*;
use crate::{application_state_store::Fixture, service_protocol::Id};
use data::tests::{armed, intent, reseal_fixture, unknown as unknown_attempt};

fn opened(enabled: bool) -> (Fixture, Arc<PrivateStateDirectory>, Arc<NativeUse>) {
    let fixture = Fixture::new();
    let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
    let original = Arc::new(store.begin_native_use().unwrap());
    if enabled {
        store.enable_apple_provisioning(&original).unwrap();
    }
    (fixture, store, original)
}
fn close(store: &PrivateStateDirectory, original: &NativeUse) {
    // Only synchronous, actually returned Store calls run in these tests; no
    // native worker/provider/join witness is created or qualified by cleanup.
    store.retire_native_use(original).unwrap();
    store.close().unwrap();
}
fn variant(operation: u8, account: u8) -> BundleRegistrationIntent {
    let mut value = intent();
    value.context.operation_id = format!("{operation:032x}");
    value.provenance.operation_id = Id::parse(&value.context.operation_id).unwrap();
    value.context.account_ref = AccountRef::from_selected_issuer([account; 16]);
    reseal_fixture(&mut value);
    value
}

#[test]
fn v1_inspection_is_unavailable_not_empty_or_an_implicit_upgrade() {
    let (_fixture, store, native) = opened(false);
    let mut port = AppleProvisioningJournal::new(store.clone(), native.clone());
    let error = port
        .inspect_account(&intent().context.account_ref)
        .err()
        .unwrap();
    assert_eq!(error.code, Error::Unavailable);
    assert_eq!(
        store.read(Namespace::Projects).unwrap().revision,
        Revision(0)
    );
    assert_eq!(
        store.read(Namespace::AppleProvisioning).err().unwrap().code,
        Error::Unavailable
    );
    assert!(port.retained_reservation().is_none());
    close(&store, &native);
}

#[test]
fn durable_reserve_and_original_updates_do_not_turn_terminal_child_into_finality() {
    let (_fixture, store, native) = opened(true);
    let mut port = AppleProvisioningJournal::new(store.clone(), native.clone());
    let value = intent();
    let initial = port.inspect_account(&value.context.account_ref).unwrap();
    assert_eq!(initial.revision, Revision(0));
    assert!(initial.rows.is_empty() && initial.account == value.context.account_ref);
    let ack = port
        .reserve(initial.revision, value.clone(), armed(&value))
        .unwrap();
    assert_eq!(ack.revision, Revision(1));
    assert!(Arc::ptr_eq(
        port.retained_reservation().unwrap(),
        &ack.original
    ));
    assert!(ack.row.send_armed && ack.row.unresolved());
    assert_eq!(store.close().err().unwrap().code, Error::Busy);
    let mut no_send = armed(&value);
    no_send.sequence = 2;
    no_send.record.status = AttemptStatus::Failed;
    no_send.record.reason = AttemptReason::AuthorizationChanged;
    no_send.record.possible_send = false;
    let updated = port
        .record_attempt(ack.revision, &ack.original, no_send)
        .unwrap();
    assert_eq!(updated.revision, Revision(2));
    assert!(updated.row.send_armed && updated.row.unresolved());
    assert!(updated.row.native_settlement == NativeSettlement::Pending);
    // Only the actual parent may supply NativeJoined to finish_native; this
    // test intentionally cannot manufacture that fact from the failed status.
    let mut next = AppleProvisioningJournal::new(store.clone(), native.clone());
    let another = variant(2, 1);
    assert_eq!(
        next.reserve(Revision(2), another.clone(), armed(&another))
            .err()
            .unwrap()
            .code,
        Error::RecoveryRequired
    );
    close(&store, &native);
}

#[test]
fn account_gate_covers_other_projects_and_rotated_record_contexts() {
    let (_fixture, store, native) = opened(true);
    let mut first = AppleProvisioningJournal::new(store.clone(), native.clone());
    let value = intent();
    first
        .reserve(Revision(0), value.clone(), armed(&value))
        .unwrap();
    let mut changed = variant(2, 1);
    changed.context.project_id = "project-2".into();
    changed.context.credential_record_id = "rotated-record".into();
    changed.context.credential_revision = 2;
    changed.provenance.project_binding.project_id = Id::parse(&"7".repeat(32)).unwrap();
    changed.provenance.project_binding.canonical_root = "/synthetic/other-project".into();
    changed.provenance.project_binding.inode = 303;
    changed.provenance.registered_root.path =
        changed.provenance.project_binding.canonical_root.clone();
    changed.provenance.registered_root.inode = 303;
    reseal_fixture(&mut changed);
    let mut second = AppleProvisioningJournal::new(store.clone(), native.clone());
    assert_eq!(
        second
            .reserve(Revision(1), changed.clone(), armed(&changed))
            .err()
            .unwrap()
            .code,
        Error::RecoveryRequired
    );
    assert!(second.retained_reservation().is_none());
    assert_eq!(
        store.read(Namespace::AppleProvisioning).unwrap().revision,
        Revision(1)
    );
    close(&store, &native);
}

#[test]
fn stale_expected_revision_is_not_a_reserve_ack_or_an_automatic_retry() {
    let (_fixture, store, native) = opened(true);
    let mut first = AppleProvisioningJournal::new(store.clone(), native.clone());
    let mut second = AppleProvisioningJournal::new(store.clone(), native.clone());
    let value = intent();
    let other = variant(2, 2);
    let observed = second
        .inspect_account(&other.context.account_ref)
        .unwrap()
        .revision;
    first
        .reserve(Revision(0), value.clone(), armed(&value))
        .unwrap();
    assert_eq!(
        second
            .reserve(observed, other.clone(), armed(&other))
            .err()
            .unwrap()
            .code,
        Error::Conflict
    );
    assert!(second.retained_reservation().is_none());
    assert_eq!(
        store.read(Namespace::AppleProvisioning).unwrap().revision,
        Revision(1)
    );
    // There is no hidden retry with a new revision or new intent.
    assert!(second
        .inspect_account(&other.context.account_ref)
        .unwrap()
        .rows
        .is_empty());
    close(&store, &native);
}

#[test]
fn lost_reserve_ack_keeps_original_and_armed_row_across_restart_without_replay() {
    let (fixture, store, native) = opened(true);
    let value = intent();
    let mut port = AppleProvisioningJournal::new(store.clone(), native.clone());
    port.lose_next_ack = true;
    let error = port
        .reserve(Revision(0), value.clone(), armed(&value))
        .err()
        .unwrap();
    assert_eq!(error.code, Error::StateUnknown);
    assert!(port.retained_reservation().is_some());
    assert_eq!(
        port.reserve(Revision(0), value.clone(), armed(&value))
            .err()
            .unwrap(),
        error
    );
    assert_eq!(
        port.inspect_account(&value.context.account_ref)
            .err()
            .unwrap(),
        error
    );
    let original = port.retained_reservation().unwrap().clone();
    close(&store, &native);

    let reopened = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
    let later_use = Arc::new(reopened.begin_native_use().unwrap());
    let mut later = AppleProvisioningJournal::new(reopened.clone(), later_use.clone());
    let found = later.inspect_account(&value.context.account_ref).unwrap();
    assert_eq!(found.revision, Revision(1));
    assert_eq!(found.rows.len(), 1);
    assert!(found.rows[0].send_armed && found.rows[0].unresolved());
    assert!(later.retained_reservation().is_none());
    assert_eq!(
        later
            .record_attempt(found.revision, &original, unknown_attempt(&value))
            .err()
            .unwrap()
            .code,
        Error::Conflict
    );
    let other = variant(2, 1);
    assert_eq!(
        later
            .reserve(found.revision, other.clone(), armed(&other))
            .err()
            .unwrap()
            .code,
        Error::RecoveryRequired
    );
    close(&reopened, &later_use);
}

#[test]
fn lost_update_ack_and_identical_readback_never_restore_a_writable_original() {
    let (_fixture, store, native) = opened(true);
    let mut port = AppleProvisioningJournal::new(store.clone(), native.clone());
    let value = intent();
    let ack = port
        .reserve(Revision(0), value.clone(), armed(&value))
        .unwrap();
    port.lose_next_ack = true;
    let error = port
        .record_attempt(ack.revision, &ack.original, unknown_attempt(&value))
        .err()
        .unwrap();
    assert_eq!(error.code, Error::StateUnknown);
    assert!(Arc::ptr_eq(
        port.retained_reservation().unwrap(),
        &ack.original
    ));
    let mut observer = AppleProvisioningJournal::new(store.clone(), native.clone());
    let current = observer
        .inspect_account(&value.context.account_ref)
        .unwrap();
    assert_eq!(current.revision, Revision(2));
    assert!(current.rows[0].attempt.record.status == AttemptStatus::Unknown);
    assert!(current.rows[0].unresolved());
    assert_eq!(
        observer
            .record_attempt(current.revision, &ack.original, unknown_attempt(&value))
            .err()
            .unwrap()
            .code,
        Error::Conflict
    );
    assert_eq!(
        port.record_attempt(current.revision, &ack.original, unknown_attempt(&value))
            .err()
            .unwrap(),
        error
    );
    close(&store, &native);
}

#[test]
fn historical_selection_after_real_store_reopen_preserves_unknown_and_native_fence() {
    let (fixture, store, native) = opened(true);
    let value = intent();
    let mut first = AppleProvisioningJournal::new(store.clone(), native.clone());
    let ack = first.reserve(Revision(0), value.clone(), armed(&value)).unwrap();
    first.record_attempt(ack.revision, &ack.original, unknown_attempt(&value)).unwrap();
    // Only the actual synchronous Store calls above ran. No worker, native
    // joined receipt or provider authority is constructed by this fixture.
    close(&store, &native);

    let reopened = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
    let later_use = Arc::new(reopened.begin_native_use().unwrap());
    let mut later = AppleProvisioningJournal::new(reopened.clone(), later_use.clone());
    let before = reopened.read(Namespace::AppleProvisioning).unwrap();
    let found = later.inspect_account(&value.context.account_ref).unwrap();
    let mut current = crate::apple_provisioning_protocol::ScopeData {
        provisioning: value.context.clone(), provenance: value.provenance.clone(),
        target: value.target.clone(), reviewed_at: None,
    };
    // Runtime aliases, current key revision and the explicit display name may
    // differ. The stable original project/root/issuer and target must match.
    current.provisioning.project_id = "new-runtime-alias".into();
    current.provisioning.credential_revision += 1;
    current.target.display_name = "New review label".into();
    let history = crate::apple_provisioning_protocol::recovery_history(&found, &current).unwrap();
    assert!(history.attempts.len() == 1 && history.hidden_unresolved == 0);
    assert!(history.attempts[0].reference.operation_id == value.context.operation_id);
    assert!(history.attempts[0].status == AttemptStatus::Unknown);
    assert!(history.attempts[0].native_settlement == NativeSettlement::Pending);
    assert!(later.retained_reservation().is_none());
    let after = reopened.read(Namespace::AppleProvisioning).unwrap();
    assert_eq!(before.revision, after.revision);
    assert_eq!(before.bytes, after.bytes);
    let another = variant(2, 1);
    assert_eq!(later.reserve(found.revision, another.clone(), armed(&another)).err().unwrap().code, Error::RecoveryRequired);
    close(&reopened, &later_use);
}

#[test]
fn wrong_store_or_retired_use_cannot_read_or_update_the_namespace() {
    let (_a, first, native_a) = opened(true);
    let (_b, second, native_b) = opened(true);
    let account = intent().context.account_ref;
    let mut wrong = AppleProvisioningJournal::new(first.clone(), native_b.clone());
    assert_eq!(
        wrong.inspect_account(&account).err().unwrap().code,
        Error::Conflict
    );
    let mut old = AppleProvisioningJournal::new(first.clone(), native_a.clone());
    first.retire_native_use(&native_a).unwrap();
    let next = Arc::new(first.begin_native_use().unwrap());
    assert_eq!(
        old.inspect_account(&account).err().unwrap().code,
        Error::Conflict
    );
    let mut current = AppleProvisioningJournal::new(first.clone(), next.clone());
    assert!(current.inspect_account(&account).unwrap().rows.is_empty());
    close(&first, &next);
    close(&second, &native_b);
}

#[test]
fn invalid_or_nonzero_empty_state_never_becomes_an_empty_account() {
    for raw in [Vec::new(), b"{\"schemaVersion\":1,\"schemaVersion\":1,\"protocol\":\"mrk-apple-provisioning-journal/1\",\"rows\":[]}\n".to_vec(),
        b"{\"schemaVersion\":2,\"protocol\":\"mrk-apple-provisioning-journal/1\",\"rows\":[]}\n".to_vec()]
    {
        let (_fixture, store, native) = opened(true);
        store.replace(Namespace::AppleProvisioning, Revision(0), &raw).unwrap();
        let mut port = AppleProvisioningJournal::new(store.clone(), native.clone());
        assert_eq!(port.inspect_account(&intent().context.account_ref).err().unwrap().code, Error::RecoveryRequired);
        assert!(port.failure().is_some() && port.retained_reservation().is_none());
        // Semantically invalid Apple references do not reset or modify the
        // independent original namespace files.
        assert_eq!(store.read(Namespace::Projects).unwrap().revision, Revision(0));
        close(&store, &native);
    }
}

#[test]
fn full_journal_refuses_new_rows_without_eviction_or_revision_change() {
    let (_fixture, store, native) = opened(true);
    let mut state = State::empty();
    for number in 1..=ROWS as u8 {
        let value = variant(number, number);
        let mut attempt = armed(&value);
        attempt.sequence = 2;
        attempt.record.status = AttemptStatus::Failed;
        attempt.record.reason = AttemptReason::AuthorizationChanged;
        attempt.record.possible_send = false;
        // Restored HISTORY DATA fixture only, not constructed native witnesses.
        state.rows.push(JournalRow {
            intent: value,
            send_armed: true,
            attempt,
            native_settlement: NativeSettlement::Known,
        });
    }
    state.rows.sort_by(|a, b| row_key(a).cmp(&row_key(b)));
    let bytes = state.bytes().unwrap();
    assert!(bytes.len() <= ROWS * ROW_LIMIT);
    store
        .replace(Namespace::AppleProvisioning, Revision(0), &bytes)
        .unwrap();
    let mut port = AppleProvisioningJournal::new(store.clone(), native.clone());
    let next = variant(33, 33);
    assert_eq!(
        port.reserve(Revision(1), next.clone(), armed(&next))
            .err()
            .unwrap()
            .code,
        Error::Busy
    );
    let snapshot = store.read(Namespace::AppleProvisioning).unwrap();
    assert_eq!(snapshot.revision, Revision(1));
    assert_eq!(snapshot.bytes, bytes);
    close(&store, &native);
}
