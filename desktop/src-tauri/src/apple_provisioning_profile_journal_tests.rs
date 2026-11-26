//! Real tiny private-directory/CAS fixtures, not vault/provider/native joins.
use super::*;
use crate::application_state_store::Fixture;
use crate::service_protocol::Id;
use data::profile::tests::{initial, intent, reseal, reused};

fn opened() -> (Fixture, Arc<PrivateStateDirectory>, Arc<NativeUse>) {
    let fixture = Fixture::new();
    let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
    let native = Arc::new(store.begin_native_use().unwrap());
    store.enable_apple_provisioning(&native).unwrap();
    (fixture, store, native)
}
fn close(store: &PrivateStateDirectory, native: &NativeUse) {
    // These fixtures execute only synchronous returned Store calls. No joined
    // provider/save/AssetWork receipt or production parent token is fabricated.
    store.retire_native_use(native).unwrap();
    store.close().unwrap();
}
fn variant(operation: u8, account: u8, reuse: bool) -> ProfileSetupIntent {
    let mut value = intent(reuse);
    value.context.operation_id = format!("{operation:032x}");
    value.context.account_ref = AccountRef::from_selected_issuer([account; 16]);
    value.provenance.operation_id = Id::parse(&value.context.operation_id).unwrap();
    reseal(&mut value);
    value
}
fn reserve_reuse(
    port: &mut AppleProvisioningJournal,
    value: &ProfileSetupIntent,
) -> ProfileJournalAck {
    port.reserve_profile(Revision(0), value.clone(), initial(value))
        .unwrap()
}

#[test]
fn profile_inspection_never_upgrades_and_first_explicit_reserve_is_atomic_v2() {
    let (_fixture, store, native) = opened();
    let value = intent(true);
    let before = store.read(Namespace::AppleProvisioning).unwrap();
    assert!(before.bytes.is_empty() && before.revision == Revision(0));
    let mut port = AppleProvisioningJournal::new(store.clone(), native.clone());
    let account = port.inspect_account(&value.context.account_ref).unwrap();
    assert!(account.rows.is_empty() && account.profile_rows.is_empty());
    assert_eq!(
        store.read(Namespace::AppleProvisioning).unwrap().bytes,
        before.bytes
    );
    let ack = reserve_reuse(&mut port, &value);
    assert!(ack.revision == Revision(1) && !ack.row.send_armed && ack.row.unresolved());
    assert!(Arc::ptr_eq(
        port.retained_profile_reservation().unwrap(),
        &ack.original
    ));
    let current = store.read(Namespace::AppleProvisioning).unwrap();
    let decoded = State::decode(&current).unwrap();
    assert!(decoded.schema_version == 2 && decoded.profile_rows.as_ref().unwrap().len() == 1);
    assert_eq!(store.close().err().unwrap().code, Error::Busy);
    close(&store, &native);
}
#[test]
fn schema2_preserves_existing_bundle_row_and_other_namespaces_exactly() {
    let (_fixture, store, native) = opened();
    let mut original = AppleProvisioningJournal::new(store.clone(), native.clone());
    let bundle = data::tests::intent();
    let ack = original
        .reserve(Revision(0), bundle.clone(), data::tests::armed(&bundle))
        .unwrap();
    let row_bytes = canonical(&ack.row, ROW_LIMIT).unwrap();
    let untouched = [
        Namespace::Projects,
        Namespace::CredentialReferences,
        Namespace::VersionAllocations,
    ]
    .map(|namespace| store.read(namespace).unwrap());
    let value = variant(2, 2, true);
    let mut profile = AppleProvisioningJournal::new(store.clone(), native.clone());
    profile
        .reserve_profile(ack.revision, value.clone(), initial(&value))
        .unwrap();
    let state = State::decode(&store.read(Namespace::AppleProvisioning).unwrap()).unwrap();
    assert!(state.rows.len() == 1 && state.profile_rows.as_ref().unwrap().len() == 1);
    assert_eq!(canonical(&state.rows[0], ROW_LIMIT).unwrap(), row_bytes);
    for (namespace, old) in [
        Namespace::Projects,
        Namespace::CredentialReferences,
        Namespace::VersionAllocations,
    ]
    .into_iter()
    .zip(untouched)
    {
        let new = store.read(namespace).unwrap();
        assert_eq!(new.revision, old.revision);
        assert_eq!(new.bytes, old.bytes);
    }
    close(&store, &native);
}
#[test]
fn both_action_families_obey_same_issuer_unknown_and_saved_pending_fence() {
    let (_fixture, store, native) = opened();
    let value = intent(true);
    let mut first = AppleProvisioningJournal::new(store.clone(), native.clone());
    let ack = reserve_reuse(&mut first, &value);
    let returned = first
        .record_profile(ack.revision, &ack.original, reused(&value))
        .unwrap();
    let mut armed = returned.row.update.clone();
    armed.sequence += 1;
    armed.save = ProfileSaveState::Armed;
    let armed = first
        .record_profile(returned.revision, &ack.original, armed)
        .unwrap();
    let mut unknown = armed.row.update.clone();
    unknown.sequence += 1;
    unknown.save = ProfileSaveState::Unknown;
    let unknown = first
        .record_profile(armed.revision, &ack.original, unknown)
        .unwrap();
    for other in [variant(2, 1, false), variant(3, 1, true)] {
        let mut later = AppleProvisioningJournal::new(store.clone(), native.clone());
        assert_eq!(
            later
                .reserve_profile(unknown.revision, other.clone(), initial(&other))
                .err()
                .unwrap()
                .code,
            Error::RecoveryRequired
        );
        assert!(later.retained_profile_reservation().is_none());
    }
    let mut bundle = data::tests::intent();
    bundle.context.operation_id = "9".repeat(32);
    bundle.provenance.operation_id = Id::parse(&bundle.context.operation_id).unwrap();
    data::tests::reseal_fixture(&mut bundle);
    let mut other = AppleProvisioningJournal::new(store.clone(), native.clone());
    assert_eq!(
        other
            .reserve(
                unknown.revision,
                bundle.clone(),
                data::tests::armed(&bundle)
            )
            .err()
            .unwrap()
            .code,
        Error::RecoveryRequired
    );
    assert!(other.retained_reservation().is_none());
    close(&store, &native);
}
#[test]
fn existing_bundle_pending_blocks_profile_without_migration_or_destination_adoption() {
    let (_fixture, store, native) = opened();
    let bundle = data::tests::intent();
    let mut first = AppleProvisioningJournal::new(store.clone(), native.clone());
    first
        .reserve(Revision(0), bundle.clone(), data::tests::armed(&bundle))
        .unwrap();
    let before = store.read(Namespace::AppleProvisioning).unwrap();
    let mut later = AppleProvisioningJournal::new(store.clone(), native.clone());
    let value = variant(2, 1, false);
    assert_eq!(
        later
            .reserve_profile(before.revision, value.clone(), initial(&value))
            .err()
            .unwrap()
            .code,
        Error::RecoveryRequired
    );
    assert!(later.retained_profile_reservation().is_none());
    let after = store.read(Namespace::AppleProvisioning).unwrap();
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.bytes, before.bytes);
    assert!(State::decode(&after).unwrap().profile_rows.is_none());
    close(&store, &native);
}
#[test]
fn lost_profile_reserve_ack_persists_full_destination_without_restore_or_replay() {
    let (fixture, store, native) = opened();
    let value = intent(false);
    let mut first = AppleProvisioningJournal::new(store.clone(), native.clone());
    first.lose_next_ack = true;
    let error = first
        .reserve_profile(Revision(0), value.clone(), initial(&value))
        .err()
        .unwrap();
    assert_eq!(error.code, Error::StateUnknown);
    let held = first.retained_profile_reservation().unwrap().clone();
    assert!(held.intent().destination == value.destination);
    assert_eq!(
        first
            .reserve_profile(Revision(0), value.clone(), initial(&value))
            .err()
            .unwrap(),
        error
    );
    close(&store, &native);
    let reopened = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
    let later_use = Arc::new(reopened.begin_native_use().unwrap());
    let mut later = AppleProvisioningJournal::new(reopened.clone(), later_use.clone());
    let account = later.inspect_account(&value.context.account_ref).unwrap();
    assert!(
        account.profile_rows.len() == 1
            && account.profile_rows[0].send_armed
            && account.profile_rows[0].unresolved()
    );
    assert!(
        account.profile_rows[0].intent.destination == value.destination
            && later.retained_profile_reservation().is_none()
    );
    let mut next = initial(&value);
    next.sequence = 2;
    assert_eq!(
        later
            .record_profile(account.revision, &held, next)
            .err()
            .unwrap()
            .code,
        Error::Conflict
    );
    let other = variant(2, 1, false);
    assert_eq!(
        later
            .reserve_profile(account.revision, other.clone(), initial(&other))
            .err()
            .unwrap()
            .code,
        Error::RecoveryRequired
    );
    close(&reopened, &later_use);
}
#[test]
fn lost_save_ack_is_sticky_even_with_identical_current_state_readback() {
    let (_fixture, store, native) = opened();
    let value = intent(true);
    let mut first = AppleProvisioningJournal::new(store.clone(), native.clone());
    let ack = reserve_reuse(&mut first, &value);
    let returned = first
        .record_profile(ack.revision, &ack.original, reused(&value))
        .unwrap();
    let mut armed = returned.row.update.clone();
    armed.sequence += 1;
    armed.save = ProfileSaveState::Armed;
    first.lose_next_ack = true;
    let error = first
        .record_profile(returned.revision, &ack.original, armed)
        .err()
        .unwrap();
    assert_eq!(error.code, Error::StateUnknown);
    let mut observer = AppleProvisioningJournal::new(store.clone(), native.clone());
    let account = observer
        .inspect_account(&value.context.account_ref)
        .unwrap();
    assert!(
        account.profile_rows[0].update.save == ProfileSaveState::Armed
            && account.profile_rows[0].unresolved()
    );
    assert_eq!(
        first
            .inspect_account(&value.context.account_ref)
            .err()
            .unwrap(),
        error
    );
    assert!(observer.retained_profile_reservation().is_none());
    close(&store, &native);
}
#[test]
fn corrupt_schema_mixed_duplicate_and_combined_capacity_fail_closed() {
    let value = intent(true);
    let row = ProfileSetupRow {
        intent: value.clone(),
        send_armed: false,
        update: initial(&value),
        native_settlement: NativeSettlement::Pending,
    };
    let mut state = State::empty();
    state.profile_rows = Some(vec![row.clone()]);
    assert!(state.bytes().is_err());
    state.schema_version = 2;
    state.protocol = PROFILE_PROTOCOL.into();
    state.bytes().unwrap();
    let bundle = data::tests::intent();
    state.rows.push(JournalRow {
        intent: bundle.clone(),
        send_armed: true,
        attempt: data::tests::armed(&bundle),
        native_settlement: NativeSettlement::Pending,
    });
    assert!(state.bytes().is_err()); // Duplicate operation/account across BOTH families.
    state.rows.clear();
    state.profile_rows = Some(Vec::new());
    for index in 1..=32u8 {
        let intent = variant(index, index, true);
        state.profile_rows.as_mut().unwrap().push(ProfileSetupRow {
            update: initial(&intent),
            intent,
            send_armed: false,
            native_settlement: NativeSettlement::Pending,
        });
    }
    state
        .profile_rows
        .as_mut()
        .unwrap()
        .sort_by(|a, b| profile_key(a).cmp(&profile_key(b)));
    state.bytes().unwrap();
    state.profile_rows.as_mut().unwrap().push(row);
    assert!(state.bytes().is_err());
    let mut encoded = serde_json::to_value(State::empty()).unwrap();
    encoded["schemaVersion"] = 2.into();
    assert!(serde_json::from_value::<State>(encoded)
        .unwrap()
        .validate()
        .is_err());
}
