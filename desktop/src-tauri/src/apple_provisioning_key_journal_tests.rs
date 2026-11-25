//! Real private Store/CAS fixtures. No generator, key, native join witness or
//! successful vault write is invented by these tests.
use super::*;
use crate::{application_state_store::Fixture, service_protocol::Id};
use data::key::tests::{certificate, certificate_armed, initial, intent, reseal, returned};

fn opened() -> (Fixture, Arc<PrivateStateDirectory>, Arc<NativeUse>) {
    let fixture = Fixture::new();
    let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
    let native = Arc::new(store.begin_native_use().unwrap());
    store.enable_apple_provisioning(&native).unwrap();
    (fixture, store, native)
}
fn close(store: &PrivateStateDirectory, native: &NativeUse) {
    // Only synchronous, actually returned Store calls occur in these tests.
    store.retire_native_use(native).unwrap();
    store.close().unwrap();
}
fn variant(operation: u8, account: u8) -> KeyPrepareIntent {
    let mut value = intent();
    value.context.operation_id = format!("{operation:032x}");
    value.context.account_ref = AccountRef::from_selected_issuer([account; 16]);
    value.provenance.operation_id = Id::parse(&value.context.operation_id).unwrap();
    reseal(&mut value);
    value
}
fn other_certificate(operation: u8, account: u8) -> CertificateIssuanceIntent {
    let mut value = certificate();
    let key = variant(operation, account);
    value.context = key.context;
    value.provenance = key.provenance;
    value.before_sha256 = key.before_sha256;
    value.plan_sha256 = value.plan_hash().unwrap();
    value
}

#[test]
fn read_does_not_upgrade_and_explicit_key_reserve_preserves_v1_v2_rows() {
    let (_fixture, store, native) = opened();
    let mut bundle = AppleProvisioningJournal::new(store.clone(), native.clone());
    let old = data::tests::intent();
    let bundle_ack = bundle
        .reserve(Revision(0), old.clone(), data::tests::armed(&old))
        .unwrap();
    let mut old_profile = data::profile::tests::intent(true);
    old_profile.context.operation_id = "8".repeat(32);
    old_profile.provenance.operation_id = Id::parse(&old_profile.context.operation_id).unwrap();
    old_profile.context.account_ref = AccountRef::from_selected_issuer([2; 16]);
    data::profile::tests::reseal(&mut old_profile);
    let mut profile = AppleProvisioningJournal::new(store.clone(), native.clone());
    let profile_ack = profile
        .reserve_profile(
            bundle_ack.revision,
            old_profile.clone(),
            data::profile::tests::initial(&old_profile),
        )
        .unwrap();
    let before = store.read(Namespace::AppleProvisioning).unwrap();
    let original_bundle = canonical(&bundle_ack.row, ROW_LIMIT).unwrap();
    let original_profile = canonical(&profile_ack.row, ROW_LIMIT).unwrap();
    let namespaces = [
        Namespace::Projects,
        Namespace::CredentialReferences,
        Namespace::VersionAllocations,
    ];
    let untouched = namespaces.map(|namespace| store.read(namespace).unwrap());
    let value = variant(3, 3);
    let mut key = AppleProvisioningJournal::new(store.clone(), native.clone());
    let account = key.inspect_account(&value.context.account_ref).unwrap();
    assert!(account.key_rows.is_empty() && account.certificate_rows.is_empty());
    let after_read = store.read(Namespace::AppleProvisioning).unwrap();
    assert_eq!(after_read.revision, before.revision);
    assert_eq!(after_read.bytes, before.bytes);
    assert_eq!(State::decode(&after_read).unwrap().schema_version, 2);
    let ack = key.reserve_key(account.revision, value, initial()).unwrap();
    assert!(Arc::ptr_eq(
        key.retained_key_reservation().unwrap(),
        &ack.original
    ));
    assert!(ack.row.generator_armed && ack.row.unresolved());
    let state = State::decode(&store.read(Namespace::AppleProvisioning).unwrap()).unwrap();
    assert_eq!(state.schema_version, 3);
    assert_eq!(state.row_count(), 3);
    assert_eq!(
        canonical(&state.rows[0], ROW_LIMIT).unwrap(),
        original_bundle
    );
    assert_eq!(
        canonical(&state.profile_rows.as_ref().unwrap()[0], ROW_LIMIT).unwrap(),
        original_profile
    );
    for (namespace, old) in namespaces.into_iter().zip(untouched) {
        let current = store.read(namespace).unwrap();
        assert_eq!(current.revision, old.revision);
        assert_eq!(current.bytes, old.bytes);
    }
    close(&store, &native);
}

#[test]
fn pending_key_fences_all_other_actions_and_saved_data_is_not_native_finality() {
    let (_fixture, store, native) = opened();
    let value = intent();
    let mut key = AppleProvisioningJournal::new(store.clone(), native.clone());
    let ack = key
        .reserve_key(Revision(0), value.clone(), initial())
        .unwrap();
    let output = key
        .record_key(ack.revision, &ack.original, returned())
        .unwrap();
    let mut saved = output.row.update.clone();
    saved.sequence += 1;
    saved.save = ProfileSaveState::ReadBack;
    saved.saved_reference = Some(value.destination.clone());
    saved.disposition = KeyDisposition::Prepared;
    let saved = key
        .record_key(output.revision, &ack.original, saved)
        .unwrap();
    assert!(saved.row.unresolved() && saved.row.native_settlement == NativeSettlement::Pending);
    let before = store.read(Namespace::AppleProvisioning).unwrap();
    let mut bundle = data::tests::intent();
    bundle.context.operation_id = "8".repeat(32);
    bundle.provenance.operation_id = Id::parse(&bundle.context.operation_id).unwrap();
    data::tests::reseal_fixture(&mut bundle);
    let mut profile = data::profile::tests::intent(true);
    profile.context.operation_id = "9".repeat(32);
    profile.provenance.operation_id = Id::parse(&profile.context.operation_id).unwrap();
    data::profile::tests::reseal(&mut profile);
    let mut other = AppleProvisioningJournal::new(store.clone(), native.clone());
    assert_eq!(
        other
            .reserve(before.revision, bundle.clone(), data::tests::armed(&bundle))
            .err()
            .unwrap()
            .code,
        Error::RecoveryRequired
    );
    assert_eq!(
        other
            .reserve_profile(
                before.revision,
                profile.clone(),
                data::profile::tests::initial(&profile)
            )
            .err()
            .unwrap()
            .code,
        Error::RecoveryRequired
    );
    assert_eq!(
        other
            .reserve_key(before.revision, variant(2, 1), initial())
            .err()
            .unwrap()
            .code,
        Error::RecoveryRequired
    );
    let cert = other_certificate(3, 1);
    assert_eq!(
        other
            .reserve_certificate(before.revision, cert.clone(), certificate_armed(&cert))
            .err()
            .unwrap()
            .code,
        Error::RecoveryRequired
    );
    assert!(
        other.retained_reservation().is_none()
            && other.retained_profile_reservation().is_none()
            && other.retained_key_reservation().is_none()
            && other.retained_certificate_reservation().is_none()
    );
    assert_eq!(
        store.read(Namespace::AppleProvisioning).unwrap().bytes,
        before.bytes
    );
    assert_eq!(store.close().err().unwrap().code, Error::Busy);
    close(&store, &native);
}

#[test]
fn existing_profile_or_certificate_pending_blocks_new_key_without_migration_or_replay() {
    for certificate_first in [false, true] {
        let (_fixture, store, native) = opened();
        let mut original = AppleProvisioningJournal::new(store.clone(), native.clone());
        if certificate_first {
            let value = certificate();
            original
                .reserve_certificate(Revision(0), value.clone(), certificate_armed(&value))
                .unwrap();
        } else {
            let value = data::profile::tests::intent(false);
            original
                .reserve_profile(
                    Revision(0),
                    value.clone(),
                    data::profile::tests::initial(&value),
                )
                .unwrap();
        }
        let before = store.read(Namespace::AppleProvisioning).unwrap();
        let mut later = AppleProvisioningJournal::new(store.clone(), native.clone());
        assert_eq!(
            later
                .reserve_key(before.revision, variant(2, 1), initial())
                .err()
                .unwrap()
                .code,
            Error::RecoveryRequired
        );
        assert!(later.retained_key_reservation().is_none());
        let after = store.read(Namespace::AppleProvisioning).unwrap();
        assert_eq!(after.revision, before.revision);
        assert_eq!(after.bytes, before.bytes);
        close(&store, &native);
    }
}

#[test]
fn lost_reserve_ack_survives_restart_without_recreating_original_or_regenerating() {
    let (fixture, store, native) = opened();
    let value = intent();
    let mut first = AppleProvisioningJournal::new(store.clone(), native.clone());
    first.lose_next_ack = true;
    let failure = first
        .reserve_key(Revision(0), value.clone(), initial())
        .err()
        .unwrap();
    assert_eq!(failure.code, Error::StateUnknown);
    let held = first.retained_key_reservation().unwrap().clone();
    assert!(held.intent().destination == value.destination);
    assert_eq!(
        first
            .inspect_account(&value.context.account_ref)
            .err()
            .unwrap(),
        failure
    );
    assert_eq!(
        first
            .reserve_key(Revision(0), value.clone(), initial())
            .err()
            .unwrap(),
        failure
    );
    close(&store, &native);
    let reopened = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
    let later_use = Arc::new(reopened.begin_native_use().unwrap());
    let mut later = AppleProvisioningJournal::new(reopened.clone(), later_use.clone());
    let account = later.inspect_account(&value.context.account_ref).unwrap();
    assert_eq!(account.key_rows.len(), 1);
    assert!(
        account.key_rows[0].unresolved()
            && account.key_rows[0].intent.destination == value.destination
    );
    assert!(later.retained_key_reservation().is_none());
    assert_eq!(
        later
            .record_key(account.revision, &held, returned())
            .err()
            .unwrap()
            .code,
        Error::Conflict
    );
    assert_eq!(
        later
            .reserve_key(account.revision, variant(2, 1), initial())
            .err()
            .unwrap()
            .code,
        Error::RecoveryRequired
    );
    close(&reopened, &later_use);
}

#[test]
fn lost_output_ack_and_unknown_save_never_adopt_a_readback_or_claim_no_generation() {
    for lost in [false, true] {
        let (_fixture, store, native) = opened();
        let value = intent();
        let mut first = AppleProvisioningJournal::new(store.clone(), native.clone());
        let ack = first
            .reserve_key(Revision(0), value.clone(), initial())
            .unwrap();
        first.lose_next_ack = lost;
        let output = first.record_key(ack.revision, &ack.original, returned());
        if lost {
            assert_eq!(output.err().unwrap().code, Error::StateUnknown);
        } else {
            let output = output.unwrap();
            let mut unknown = output.row.update.clone();
            unknown.sequence += 1;
            unknown.save = ProfileSaveState::Unknown;
            unknown.disposition = KeyDisposition::Unknown;
            let unknown = first
                .record_key(output.revision, &ack.original, unknown)
                .unwrap();
            let mut no_generation = initial();
            no_generation.sequence = unknown.row.update.sequence + 1;
            no_generation.generation = KeyGeneration::NotEntered;
            no_generation.disposition = KeyDisposition::Failed;
            assert!(first
                .record_key(unknown.revision, &ack.original, no_generation)
                .is_err());
        }
        let mut observer = AppleProvisioningJournal::new(store.clone(), native.clone());
        let account = observer
            .inspect_account(&value.context.account_ref)
            .unwrap();
        assert!(account.key_rows[0].unresolved() && account.key_rows[0].update.output.is_some());
        assert!(observer.retained_key_reservation().is_none());
        assert_eq!(
            observer
                .record_key(account.revision, &ack.original, returned())
                .err()
                .unwrap()
                .code,
            Error::Conflict
        );
        close(&store, &native);
    }
}

#[test]
fn same_namespace_joint_capacity_counts_all_families_and_refuses_without_new_original() {
    let (_fixture, store, native) = opened();
    let mut revision = Revision(0);
    for index in 1..=ROWS as u8 {
        let mut port = AppleProvisioningJournal::new(store.clone(), native.clone());
        if index % 2 == 0 {
            let value = variant(index, index);
            revision = port
                .reserve_key(revision, value, initial())
                .unwrap()
                .revision;
        } else {
            let value = other_certificate(index, index);
            revision = port
                .reserve_certificate(revision, value.clone(), certificate_armed(&value))
                .unwrap()
                .revision;
        }
    }
    let before = store.read(Namespace::AppleProvisioning).unwrap();
    let state = State::decode(&before).unwrap();
    assert_eq!(state.key_rows.as_ref().unwrap().len(), 16);
    assert_eq!(state.certificate_rows.as_ref().unwrap().len(), 16);
    let mut later = AppleProvisioningJournal::new(store.clone(), native.clone());
    assert_eq!(
        later
            .reserve_key(revision, variant(33, 33), initial())
            .err()
            .unwrap()
            .code,
        Error::Busy
    );
    assert!(later.retained_key_reservation().is_none());
    assert_eq!(
        store.read(Namespace::AppleProvisioning).unwrap().bytes,
        before.bytes
    );
    close(&store, &native);
}

#[test]
fn stale_revision_and_other_native_use_cannot_turn_an_equal_intent_into_original() {
    let (_fixture, store, native) = opened();
    let value = intent();
    let mut first = AppleProvisioningJournal::new(store.clone(), native.clone());
    let ack = first
        .reserve_key(Revision(0), value.clone(), initial())
        .unwrap();
    let mut later = AppleProvisioningJournal::new(store.clone(), native.clone());
    assert_eq!(
        later
            .reserve_key(Revision(0), variant(2, 2), initial())
            .err()
            .unwrap()
            .code,
        Error::Conflict
    );
    assert!(later.retained_key_reservation().is_none());
    assert_eq!(
        later
            .record_key(ack.revision, &ack.original, returned())
            .err()
            .unwrap()
            .code,
        Error::Conflict
    );
    store.retire_native_use(&native).unwrap();
    let next_use = Arc::new(store.begin_native_use().unwrap());
    let mut next = AppleProvisioningJournal::new(store.clone(), next_use.clone());
    assert_eq!(
        next.record_key(ack.revision, &ack.original, returned())
            .err()
            .unwrap()
            .code,
        Error::Conflict
    );
    assert!(first
        .record_key(ack.revision, &ack.original, returned())
        .is_err());
    close(&store, &next_use);
}
