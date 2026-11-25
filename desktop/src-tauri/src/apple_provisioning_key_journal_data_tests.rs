//! Synthetic reference/transition DATA. No test constructs a native key loan,
//! generator, custody ACK, save permission or original joined witness.
use super::*;

pub(in crate::apple_provisioning_journal) fn intent() -> KeyPrepareIntent {
    let mut old = profile::tests::intent(true);
    old.context.credential_record_id = old.source_key.record_id.clone();
    old.context.credential_revision = old.source_key.revision_counter;
    KeyPrepareIntent {
        context: old.context,
        provenance: old.provenance,
        target: old.target,
        source_p8: old.source_key,
        destination: old.destination,
        algorithm: KeyAlgorithm::Rsa2048Sha256,
        bundle: old.bundle,
        observed_at: old.observed_at,
        valid_until: old.valid_until,
        before_sha256: "5e277d1a091aa7d07ee10e51f51cbf8840bc52c8b67d5afc885e73d2a9f0d334".into(),
        review_plan_sha256: "e288a5fea793d75cfb8b0f3745b5f6469ef08e938b9a629852e938b6d360152e"
            .into(),
    }
}
pub(in crate::apple_provisioning_journal) fn reseal(value: &mut KeyPrepareIntent) {
    value.before_sha256 = hash(&json!({"context":value.context.core_value(),"bundleId":value.target.bundle_id,
        "scope":"signing-resources","available":true,"reason":"observed",
        "bundles":[[value.bundle.resource_id,value.bundle.identifier,value.bundle.platform,value.bundle.seed_id]],
        "certificates":[],"profiles":[]})).unwrap();
    value.review_plan_sha256 = value.review_hash().unwrap();
}
pub(in crate::apple_provisioning_journal) fn initial() -> KeyPrepareUpdate {
    KeyPrepareUpdate {
        sequence: 1,
        generation: KeyGeneration::Armed,
        output: None,
        save: ProfileSaveState::NotEntered,
        saved_reference: None,
        disposition: KeyDisposition::Running,
        cancel_requested: false,
    }
}
pub(in crate::apple_provisioning_journal) fn returned() -> KeyPrepareUpdate {
    KeyPrepareUpdate {
        sequence: 2,
        generation: KeyGeneration::Returned,
        output: Some(KeyOutputMetadata {
            frame_bytes: 4000,
            frame_sha256: "a".repeat(64),
            csr_sha256: "b".repeat(64),
            public_key_sha256: "c".repeat(64),
        }),
        save: ProfileSaveState::Armed,
        saved_reference: None,
        disposition: KeyDisposition::Running,
        cancel_requested: false,
    }
}
pub(in crate::apple_provisioning_journal) fn certificate() -> CertificateIssuanceIntent {
    let old = intent();
    CertificateIssuanceIntent {
        context: old.context,
        provenance: old.provenance,
        target: old.target,
        source_key: old.destination,
        source_p8: old.source_p8,
        bundle: old.bundle,
        csr_sha256: "7491895b9cc83c79b670da4cc534f6471fa02a4c732d9b8ffa641824f6c08311".into(),
        public_key_sha256: "7".repeat(64),
        observed_at: old.observed_at,
        valid_until: old.valid_until,
        before_sha256: old.before_sha256,
        plan_sha256: "e7631ca4847238a803fd8f553c53a33ed4f5a70ea62c6fddc4d2dcf20cf22868".into(),
        request_body_sha256: "ecb53bbed3b00846867c0b35592d70d44fe020b1c62a39c7e559e5fd3e966698"
            .into(),
    }
}
pub(in crate::apple_provisioning_journal) fn certificate_armed(
    intent: &CertificateIssuanceIntent,
) -> CertificateUpdate {
    CertificateUpdate {
        sequence: 1,
        record: CertificateAttemptRecord {
            context: intent.context.clone(),
            plan_sha256: intent.plan_sha256.clone(),
            action: CertificateCreateAction::CreateCertificate,
            status: AttemptStatus::Running,
            reason: AttemptReason::ReadbackRequired,
            possible_send: true,
            response_resource_id: None,
            response_resource_sha256: None,
            observed_resource_id: None,
            cancel_requested: false,
        },
        receipt: None,
    }
}

#[test]
fn actual_python_key_review_and_certificate_plan_vectors_match_without_private_bodies() {
    let key = intent();
    key.validate().unwrap();
    let cert = certificate();
    cert.validate().unwrap();
    let bytes = canonical(&key, ROW_LIMIT).unwrap();
    assert!(bytes.is_ascii() && String::from_utf8(bytes).unwrap().contains("\\ud83d\\ude80"));
    let cert = canonical(&cert, ROW_LIMIT).unwrap();
    assert!(!cert
        .windows(b"BEGIN CERTIFICATE".len())
        .any(|w| w == b"BEGIN CERTIFICATE"));
    assert!(!cert
        .windows(b"privateKey".len())
        .any(|w| w == b"privateKey"));
}
#[test]
fn full_random_reference_target_age_and_closed_algorithm_are_not_replaceable() {
    let key = intent();
    let mut bad = key.clone();
    bad.destination.revision_id = bad.destination.record_id.clone();
    assert!(bad.validate().is_err());
    let mut bad = key.clone();
    bad.destination.revision_counter = 2;
    assert!(bad.validate().is_err());
    let mut bad = key.clone();
    bad.destination.generation_id = "8".repeat(32);
    assert!(bad.validate().is_err());
    let mut bad = key.clone();
    bad.bundle.seed_id = "WRONGTEAM1".into();
    assert!(bad.validate().is_err());
    let mut bad = key.clone();
    bad.context.credential_record_id = "9".repeat(32);
    reseal(&mut bad);
    assert!(bad.validate().is_err());
    let mut bad = key.clone();
    bad.context.credential_revision += 1;
    reseal(&mut bad);
    assert!(bad.validate().is_err());
    let cert = certificate();
    let mut bad = cert.clone();
    bad.context.credential_record_id = "9".repeat(32);
    bad.plan_sha256 = bad.plan_hash().unwrap();
    assert!(bad.validate().is_err());
    let mut bad = cert;
    bad.context.credential_revision += 1;
    bad.plan_sha256 = bad.plan_hash().unwrap();
    assert!(bad.validate().is_err());
    let mut bad = key.clone();
    bad.valid_until = "2026-10-19T10:25:31.123456+00:00".into();
    assert!(bad.validate().is_err());
    let mut value = serde_json::to_value(&key).unwrap();
    value["algorithm"] = json!("rsa-4096-sha1");
    assert!(serde_json::from_value::<KeyPrepareIntent>(value).is_err());
}
#[test]
fn partial_or_missing_output_never_becomes_not_entered_after_return() {
    let key = intent();
    let first = initial();
    first.initial(&key).unwrap();
    let second = returned();
    second.follows(&first, &key).unwrap();
    let mut empty = second.clone();
    empty.output = None;
    assert!(empty.validate(&key).is_err());
    let mut no_go = first.clone();
    no_go.sequence = 3;
    no_go.generation = KeyGeneration::NotEntered;
    no_go.disposition = KeyDisposition::Failed;
    assert!(no_go.follows(&second, &key).is_err());
    let mut unknown = first.clone();
    unknown.sequence = 2;
    unknown.generation = KeyGeneration::Unknown;
    unknown.disposition = KeyDisposition::Unknown;
    unknown.follows(&first, &key).unwrap();
    no_go.sequence = 3;
    assert!(no_go.follows(&unknown, &key).is_err());
    let row = KeyPrepareRow {
        intent: key,
        generator_armed: true,
        update: unknown,
        native_settlement: NativeSettlement::Known,
    };
    assert!(row.unresolved());
}
#[test]
fn cancellation_preserves_completed_key_save_but_does_not_finish_original_jobs() {
    let key = intent();
    let mut got = returned();
    got.cancel_requested = true;
    got.follows(&initial(), &key).unwrap();
    let mut written = got.clone();
    written.sequence = 3;
    written.save = ProfileSaveState::Written;
    written.follows(&got, &key).unwrap();
    let mut saved = written.clone();
    saved.sequence = 4;
    saved.save = ProfileSaveState::ReadBack;
    saved.saved_reference = Some(key.destination.clone());
    saved.disposition = KeyDisposition::Cancelled;
    saved.follows(&written, &key).unwrap();
    let mut row = KeyPrepareRow {
        intent: key,
        generator_armed: true,
        update: saved,
        native_settlement: NativeSettlement::Pending,
    };
    assert!(row.unresolved());
    row.native_settlement = NativeSettlement::Known;
    assert!(!row.unresolved());
    let mut forgery = row.update.clone();
    forgery.sequence += 1;
    forgery.disposition = KeyDisposition::Prepared;
    forgery.cancel_requested = false;
    assert!(forgery.follows(&row.update, &row.intent).is_err());
}
#[test]
fn unknown_save_is_absorbing_and_has_no_csr_or_saved_ref_recovery_shortcut() {
    let key = intent();
    let got = returned();
    let mut unknown = got.clone();
    unknown.sequence = 3;
    unknown.save = ProfileSaveState::Unknown;
    unknown.disposition = KeyDisposition::Unknown;
    unknown.follows(&got, &key).unwrap();
    for state in [
        ProfileSaveState::NotEntered,
        ProfileSaveState::Armed,
        ProfileSaveState::Written,
        ProfileSaveState::ReadBack,
    ] {
        let mut bad = unknown.clone();
        bad.sequence = 4;
        bad.save = state;
        bad.disposition = KeyDisposition::Prepared;
        if state == ProfileSaveState::ReadBack {
            bad.saved_reference = Some(key.destination.clone());
        }
        assert!(bad.follows(&unknown, &key).is_err());
    }
    let mut bad = unknown.clone();
    bad.sequence = 4;
    bad.output.as_mut().unwrap().csr_sha256 = "d".repeat(64);
    assert!(bad.follows(&unknown, &key).is_err());
}
#[test]
fn certificate_sparse_receipt_and_sent_unknown_cannot_be_rewritten_or_rearmed() {
    let intent = certificate();
    let first = certificate_armed(&intent);
    first.initial(&intent).unwrap();
    let mut next = first.clone();
    next.sequence = 2;
    next.record.status = AttemptStatus::RecoveryRequired;
    next.record.reason = AttemptReason::ReadbackRequired;
    let receipt = CertificateCreationReceipt {
        schema_version: 1,
        resource_id: "new-certificate".into(),
        certificate_type: None,
        expires_at: None,
        certificate_sha256: None,
    };
    next.record.response_resource_id = Some(receipt.resource_id.clone());
    next.record.response_resource_sha256 = Some(receipt.sha256().unwrap());
    next.receipt = Some(receipt);
    next.follows(&first, &intent).unwrap();
    let mut bad = next.clone();
    bad.sequence = 3;
    bad.receipt.as_mut().unwrap().certificate_type = Some("DISTRIBUTION".into());
    bad.record.response_resource_sha256 = Some(bad.receipt.as_ref().unwrap().sha256().unwrap());
    assert!(bad.follows(&next, &intent).is_err());
    let mut unknown = first.clone();
    unknown.sequence = 2;
    unknown.record.status = AttemptStatus::Unknown;
    unknown.record.reason = AttemptReason::ProviderOutcomeUnknown;
    unknown.follows(&first, &intent).unwrap();
    let mut retry = first;
    retry.sequence = 3;
    assert!(retry.follows(&unknown, &intent).is_err());
    let mut no_send = unknown.clone();
    no_send.sequence = 3;
    no_send.record.possible_send = false;
    no_send.record.status = AttemptStatus::Cancelled;
    no_send.record.reason = AttemptReason::CancelledBeforeSend;
    no_send.record.cancel_requested = true;
    assert!(no_send.follows(&unknown, &intent).is_err());
}
#[test]
fn restored_key_reference_requires_a_new_explicit_plan_not_old_attempt_adoption() {
    let old = certificate();
    let update = certificate_armed(&old);
    let mut restored = old.clone();
    restored.source_key.record_id = "9".repeat(32);
    restored.source_key.revision_id = "a".repeat(32);
    assert!(restored.validate().is_err());
    restored.plan_sha256 = restored.plan_hash().unwrap();
    restored.validate().unwrap();
    assert!(update.validate(&restored).is_err());
}
