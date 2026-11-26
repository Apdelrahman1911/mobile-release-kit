//! Closed profile DATA through the actual shared decoder. Inert invalid DER
//! deliberately cannot yield an identity comparison, native ACK or save permit.
//! No file, native framework, process, key or Apple request is used.
use super::*;
use crate::credential_setup::KeyReference;
use std::time::{Duration, UNIX_EPOCH};

fn profile_value(mode: Mode) -> Value {
    let mut value = prepare_value(mode);
    value["p12RecordId"] = json!("d".repeat(32));
    value["p12RecordRevision"] = json!(1);
    if mode == Mode::ProfileReview {
        value["reference"] = Value::Null;
    }
    value
}
fn selected() -> KeyReference {
    serde_json::from_value(
        json!({"vaultId":"a".repeat(32),"generationId":"b".repeat(32),
        "recordId":"d".repeat(32),"revisionId":"e".repeat(32),"revisionCounter":1}),
    )
    .unwrap()
}
fn profile_binding() -> Arc<RequestBinding> {
    let mut binding = Arc::try_unwrap(binding(Mode::Review)).ok().unwrap();
    binding.context = prepare(&profile_value(Mode::ProfileReview))
        .unwrap()
        .context;
    binding.scope.signing = Some(ProfileScopeData {
        source_key: selected(),
        destination: None,
        expected_certificate_sha256: hex(&Sha256::digest(b"not a certificate")),
        p12_sha256: "a".repeat(64),
        entitlements: json!({}),
        review: None,
        prior: None,
    });
    assert!(binding.scope.signing.as_ref().unwrap().valid(
        &binding.context,
        &binding.scope.target,
        None
    ));
    Arc::new(binding)
}
fn identity_payload() -> Value {
    json!({"certificateDer":"bm90IGEgY2VydGlmaWNhdGU=","publicKeySpkiDer":"bm90IGEga2V5",
        "chainSha256":["a".repeat(64)],"chainCheckedAt":"2026-10-20T00:00:00+00:00",
        "sourceKey":selected(),"p12Sha256":"a".repeat(64)})
}
fn receive_identity(binding: &Arc<RequestBinding>, value: Value) -> Result<Frame, BridgeError> {
    let mut decoder = Decoder::new(binding.clone());
    decoder.push(&accepted(binding))?;
    decoder.push(&line(&envelope(binding, 1, "identity", value)))
}
fn inert_identity(binding: &Arc<RequestBinding>) -> IdentityInput {
    match receive_identity(binding, identity_payload()).unwrap() {
        Frame::Event(EventDataFrame {
            data: EventData::Profile(ProfileEvent::Identity(input)),
            ..
        }) => input,
        _ => panic!("expected only public identity DATA"),
    }
}

#[test]
fn separate_modes_require_p12_and_their_exact_one_use_consent() {
    for mode in [
        Mode::ProfileReview,
        Mode::ProfileReuse,
        Mode::ProfileCreate,
        Mode::ProfileReconcile,
    ] {
        let value = profile_value(mode);
        let context = prepare(&value).unwrap().context;
        assert!(context.mode.profile());
        for removed in ["p12RecordId", "p12RecordRevision"] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(removed);
            assert!(prepare(&missing).is_err());
        }
        for selected in [
            Mode::Review,
            Mode::Register,
            Mode::Reconcile,
            Mode::ProfileReview,
            Mode::ProfileReuse,
            Mode::ProfileCreate,
            Mode::ProfileReconcile,
        ] {
            let request = start(
                &json!({"operationId":"1".repeat(32),"ownerGeneration":"5".repeat(32),
                "consentVersion":selected.consent()}),
            )
            .unwrap();
            assert_eq!(request.matches_context(&context), selected == mode);
        }
    }
    for mode in [Mode::Review, Mode::Register, Mode::Reconcile] {
        assert!(prepare(&profile_value(mode)).is_err());
        assert_eq!(mode.frame_limit(), FRAME_LIMIT);
        assert_eq!(mode.response_limit(), RESPONSE_LIMIT);
    }
}

#[test]
fn only_profile_mode_accepts_one_original_identity_phase() {
    let original = profile_binding();
    assert!(matches!(
        receive_identity(&original, identity_payload()).unwrap(),
        Frame::Event(_)
    ));
    let mut decoder = Decoder::new(original.clone());
    decoder.push(&accepted(&original)).unwrap();
    let raw = line(&envelope(&original, 1, "identity", identity_payload()));
    decoder.push(&raw).unwrap();
    assert!(decoder.push(&raw).is_err()); // Duplicate/old sequence never renews an ACK.
    assert!(!decoder.settled());
    let old = binding(Mode::Review);
    assert!(receive_identity(&old, identity_payload()).is_err());
}

#[test]
fn identity_comparison_requires_every_original_scope_and_whole_public_source_digest() {
    let binding = profile_binding();
    for changed in [
        "sourceKey",
        "p12Sha256",
        "certificateDer",
        "chainSha256",
        "extra",
    ] {
        let mut value = identity_payload();
        match changed {
            "sourceKey" => value[changed]["revisionId"] = json!("f".repeat(32)),
            "p12Sha256" => value[changed] = json!("b".repeat(64)),
            "certificateDer" => value[changed] = json!("bm90"),
            "chainSha256" => value[changed] = json!(["a".repeat(64), "a".repeat(64)]),
            _ => value["profileContent"] = json!("no content is permitted in this phase"),
        }
        assert!(receive_identity(&binding, value).is_err(), "{changed}");
    }
    for changed in ["operationId", "ownerGeneration", "nonce", "requestSha256"] {
        let mut decoder = Decoder::new(binding.clone());
        decoder.push(&accepted(&binding)).unwrap();
        let mut value = envelope(&binding, 1, "identity", identity_payload());
        value[changed] = json!(if changed == "requestSha256" {
            "a".repeat(64)
        } else {
            "a".repeat(32)
        });
        assert!(decoder.push(&line(&value)).is_err());
        assert!(decoder
            .push(&line(&envelope(
                &binding,
                1,
                "identity",
                identity_payload()
            )))
            .is_err());
    }
}

#[test]
fn public_identity_syntax_is_never_a_certificate_or_join_proof() {
    let binding = profile_binding();
    let input = inert_identity(&binding);
    let at = UNIX_EPOCH + Duration::from_micros(input.chain_checked_at);
    assert!(IdentityComparison::inspect(&binding, &input, at, &mut || false).is_err());
    assert!(IdentityComparison::inspect(
        &binding,
        &input,
        at + Duration::from_secs(301),
        &mut || false
    )
    .is_err());
    assert!(IdentityComparison::inspect(
        &binding,
        &input,
        at - Duration::from_secs(1),
        &mut || false
    )
    .is_err());
    assert!(IdentityComparison::inspect(&binding, &input, at, &mut || true).is_err());
    // No native comparison is constructible here, hence no positive ACK or
    // CertificateBinding. The maintained parser rejects the obvious fake DER.
}

#[test]
fn identity_phase_bound_and_unsupported_base64_are_not_silently_truncated() {
    let binding = profile_binding();
    for value in [
        "AA=A".to_string(),
        "Zh==".to_string(),
        "AAAA".repeat(PROFILE_IDENTITY_LIMIT),
    ] {
        let mut payload = identity_payload();
        payload["publicKeySpkiDer"] = json!(value);
        assert!(receive_identity(&binding, payload).is_err());
    }
    assert_eq!(Mode::ProfileReview.frame_limit(), PROFILE_IDENTITY_LIMIT);
    assert_eq!(Mode::ProfileReview.response_limit(), PROFILE_JSON_LIMIT);
    assert_eq!(Mode::ProfileCreate.events(), 4);
}

#[test]
fn wrong_order_or_a_parent_ack_echo_cannot_become_an_observation() {
    let binding = profile_binding();
    for kind in [
        "profile-observed",
        "profile-pending",
        "identity-ack",
        "journal-ack",
    ] {
        let mut decoder = Decoder::new(binding.clone());
        decoder.push(&accepted(&binding)).unwrap();
        assert!(decoder
            .push(&line(&envelope(&binding, 1, kind, json!({}))))
            .is_err());
        assert!(!decoder.settled());
    }
}
