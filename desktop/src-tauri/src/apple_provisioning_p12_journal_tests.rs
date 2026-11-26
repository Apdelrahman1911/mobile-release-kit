//! Fixed local-save DATA and real Store-call tests. No native Joined/Binding
//! token is constructed and no key, certificate, assembler or provider runs.
use super::*;
use data::p12::*;

fn intent() -> P12SaveIntent {
    let old = data::profile::tests::intent(true);
    let key = data::key::tests::intent();
    let mut value = P12SaveIntent {
        action: P12LocalAction::AssemblePkcs12,
        context: key.context,
        provenance: key.provenance,
        target: old.target,
        source_p8: key.source_p8,
        source_key: key.destination,
        destination: crate::credential_setup::KeyReference {
            vault_id: "1".repeat(32),
            generation_id: "2".repeat(32),
            record_id: "9".repeat(32),
            revision_id: "a".repeat(32),
            revision_counter: 1,
        },
        bundle: old.bundle,
        certificate: old.certificate,
        csr_sha256: "b".repeat(64),
        before_sha256: old.before_sha256,
        request_binding_sha256: "c".repeat(64),
        observed_at: old.observed_at,
        valid_until: old.valid_until,
        review_sha256: String::new(),
    };
    value.review_sha256 = value.review_hash().unwrap();
    value.validate().unwrap();
    value
}
fn initial() -> P12SaveUpdate {
    P12SaveUpdate {
        sequence: 1,
        assembly: P12Assembly::Armed,
        output: None,
        save: ProfileSaveState::NotEntered,
        saved_reference: None,
        disposition: P12Disposition::Running,
        cancel_requested: false,
    }
}
fn returned(intent: &P12SaveIntent) -> P12SaveUpdate {
    P12SaveUpdate {
        sequence: 2,
        assembly: P12Assembly::Returned,
        output: Some(P12OutputMetadata {
            frame_bytes: (b"MRK-APPLE-P12/1\n".len() + 4 + 64 + 4) as u32,
            frame_sha256: "d".repeat(64),
            p12_bytes: 4,
            p12_sha256: "e".repeat(64),
            certificate_sha256: intent.certificate.certificate_sha256.clone(),
            public_key_sha256: intent.certificate.public_key_sha256.clone(),
        }),
        save: ProfileSaveState::NotEntered,
        saved_reference: None,
        disposition: P12Disposition::Running,
        cancel_requested: false,
    }
}

#[test]
fn p12_local_intent_never_encodes_a_provider_post_or_private_package() {
    let value = intent();
    let bytes = data::canonical(&value, ROW_LIMIT).unwrap();
    for word in [
        b"possibleSend".as_slice(),
        b"POST",
        b"password",
        b"pkcs8",
        b"BEGIN",
    ] {
        assert!(!bytes.windows(word.len()).any(|item| item == word));
    }
    for mutate in [0, 1, 2, 3] {
        let mut bad = value.clone();
        match mutate {
            0 => bad.destination = bad.source_key.clone(),
            1 => bad.destination.revision_counter = 2,
            2 => bad.certificate.certificate_type = "IOS_DISTRIBUTION".into(),
            _ => bad.valid_until = bad.observed_at.clone(),
        }
        bad.review_sha256 = bad.review_hash().unwrap();
        assert!(bad.validate().is_err());
    }
    let mut foreign = value.clone();
    foreign.source_key.revision_id = "f".repeat(32);
    // Same cert/key package DATA is recovery-first even if a key ref changed;
    // neither row becomes the current cryptographic proof for reuse.
    assert!(value.same_package(&foreign));
}
#[test]
fn known_no_save_is_distinct_from_save_attempt_unknown_and_readback() {
    let value = intent();
    let armed = initial();
    let out = returned(&value);
    out.follows(&armed, &value).unwrap();
    let mut refused = out.clone();
    refused.sequence += 1;
    refused.disposition = P12Disposition::Refused;
    refused.cancel_requested = true;
    refused.follows(&out, &value).unwrap();
    let mut attempted = out.clone();
    attempted.sequence += 1;
    attempted.save = ProfileSaveState::Armed;
    attempted.follows(&out, &value).unwrap();
    let mut false_refusal = refused.clone();
    false_refusal.sequence = attempted.sequence + 1;
    assert!(false_refusal.follows(&attempted, &value).is_err());
    let mut unknown = attempted.clone();
    unknown.sequence += 1;
    unknown.save = ProfileSaveState::Unknown;
    unknown.disposition = P12Disposition::Unknown;
    unknown.follows(&attempted, &value).unwrap();
    let mut saved = unknown.clone();
    saved.sequence += 1;
    saved.save = ProfileSaveState::ReadBack;
    saved.saved_reference = Some(value.destination.clone());
    saved.disposition = P12Disposition::SavedUnassigned;
    assert!(saved.follows(&unknown, &value).is_err());
    saved.sequence = attempted.sequence + 1;
    saved.follows(&attempted, &value).unwrap();
    let row = P12SaveRow {
        intent: value,
        assembly_armed: true,
        update: saved,
        native_settlement: NativeSettlement::Pending,
    };
    assert!(row.unresolved()); // Readback DATA is not NativeJoined or Bind.
}
#[test]
fn p12_no_save_data_cannot_clear_unknown_or_rearm_a_refused_original() {
    let value = intent();
    let armed = initial();
    let mut no_run = armed.clone();
    no_run.sequence += 1;
    no_run.assembly = P12Assembly::NoOutputRetained;
    no_run.disposition = P12Disposition::Refused;
    no_run.follows(&armed, &value).unwrap();
    let mut another = returned(&value);
    another.sequence = no_run.sequence + 1;
    assert!(another.follows(&no_run, &value).is_err());
    let mut unknown = armed.clone();
    unknown.sequence += 1;
    unknown.assembly = P12Assembly::Unknown;
    unknown.disposition = P12Disposition::Unknown;
    unknown.follows(&armed, &value).unwrap();
    no_run.sequence = unknown.sequence + 1;
    assert!(no_run.follows(&unknown, &value).is_err());
}
#[test]
fn p12_v4_preserves_prior_canonical_rows_and_default_version() {
    let mut old = State::empty();
    assert_eq!(old.schema_version, 1);
    let prior = data::key::tests::intent();
    old.key_rows = Some(vec![KeyPrepareRow {
        intent: prior,
        generator_armed: true,
        update: data::key::tests::initial(),
        native_settlement: NativeSettlement::Pending,
    }]);
    old.profile_rows = Some(Vec::new());
    old.certificate_rows = Some(Vec::new());
    old.protocol = KEY_PROTOCOL.into();
    old.schema_version = 3;
    let before = data::canonical(old.key_rows.as_ref().unwrap(), STATE_LIMIT).unwrap();
    old.p12_v4().unwrap();
    assert_eq!(old.schema_version, 4);
    assert_eq!(
        before,
        data::canonical(old.key_rows.as_ref().unwrap(), STATE_LIMIT).unwrap()
    );
    assert!(old.p12_rows.as_ref().unwrap().is_empty());
    let mut mixed = State::empty();
    mixed.p12_rows = Some(Vec::new());
    assert!(mixed.validate().is_err());
}
#[test]
fn p12_actual_cas_lost_ack_stays_original_and_cannot_reserve_again() {
    use crate::application_state_store::Fixture;
    let fixture = Fixture::new();
    let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
    let native = Arc::new(store.begin_native_use().unwrap());
    store.enable_apple_provisioning(&native).unwrap();
    let mut port = AppleProvisioningJournal::new(store.clone(), native.clone());
    let value = intent();
    assert!(port
        .inspect_account(&value.context.account_ref)
        .unwrap()
        .p12_rows
        .is_empty());
    assert_eq!(
        store.read(Namespace::AppleProvisioning).unwrap().revision,
        Revision(0)
    );
    port.lose_next_ack = true;
    assert!(port
        .reserve_p12(Revision(0), value.clone(), initial())
        .is_err());
    let original = port.retained_p12_reservation().unwrap().clone();
    assert!(original.intent() == &value && port.failure().is_some());
    let before = store.read(Namespace::AppleProvisioning).unwrap();
    let state = State::decode(&before).unwrap();
    assert_eq!(state.schema_version, 4);
    assert!(state.p12_rows.as_ref().unwrap()[0].unresolved());
    assert!(port
        .reserve_p12(before.revision, value.clone(), initial())
        .is_err());
    let mut other = AppleProvisioningJournal::new(store.clone(), native.clone());
    assert!(other
        .reserve_p12(before.revision, value, initial())
        .is_err());
    assert_eq!(
        store.read(Namespace::AppleProvisioning).unwrap().bytes,
        before.bytes
    );
    // Only these synchronous real Store calls ran. This does NOT construct
    // the future async parent/native Joined token or settle the journal row.
    store.retire_native_use(&native).unwrap();
    store.close().unwrap();
}
