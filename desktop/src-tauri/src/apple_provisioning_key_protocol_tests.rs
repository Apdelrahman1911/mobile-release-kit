//! Closed DATA through the actual shared parser; no selected loan, generated
//! key, private receiver, journal ACK or native permission is constructed.
use super::*;
use crate::apple_provisioning_journal::{
    KeyAlgorithm, KeyDisposition, KeyGeneration, KeyPrepareIntent, KeyPrepareUpdate, ProfileBundle,
    ProfileSaveState,
};
use crate::credential_setup::KeyReference;

fn key_value(mode: Mode) -> Value {
    let mut value = prepare_value(mode);
    value["reference"] = if mode == Mode::KeyReview {
        Value::Null
    } else {
        json!({"operationId":"8".repeat(32),"ownerGeneration":"9".repeat(32)})
    };
    value["newApplication"] = json!(false);
    value
}
fn key_binding(mode: Mode) -> Arc<RequestBinding> {
    let mut b = Arc::try_unwrap(binding(Mode::Review)).ok().unwrap();
    b.context = prepare(&key_value(mode)).unwrap().context;
    b.scope.target.existing_application = true;
    let mut scope = KeyScopeData {
        source_p8: KeyReference {
            vault_id: "a".repeat(32),
            generation_id: "b".repeat(32),
            record_id: b.context.record_id.clone(),
            revision_id: "d".repeat(32),
            revision_counter: 1,
        },
        source_key: None,
        destination: None,
        entitlements: json!({}),
        review: None,
        vault_inventory: KeyVaultInventory {
            records: 1,
            keys: 0,
        },
    };
    if mode == Mode::KeyPrepare {
        scope.destination = Some(KeyReference {
            vault_id: "a".repeat(32),
            generation_id: "b".repeat(32),
            record_id: "e".repeat(32),
            revision_id: "f".repeat(32),
            revision_counter: 1,
        });
        scope.review = Some(KeyReviewData {
            reference: b.context.reference.clone().unwrap(),
            observed_at: "2026-10-19T10:20:30.123456+00:00".into(),
            valid_until: "2026-10-19T10:25:30.123456+00:00".into(),
            selection: KeyReviewChoice {
                bundle: ProfileBundle {
                    resource_id: "bundle-one".into(),
                    identifier: b.scope.target.bundle_id.clone(),
                    platform: "IOS".into(),
                    seed_id: "TESTTEAM01".into(),
                },
                before_sha256: "a".repeat(64),
                plan_sha256: "b".repeat(64),
            },
        });
        b.scope.reviewed_at = scope.review.as_ref().map(|r| r.observed_at.clone());
    }
    b.scope.key = Some(scope);
    Arc::new(b)
}
fn key_pending(binding: &RequestBinding) -> Value {
    let scope = binding.scope.key.as_ref().unwrap();
    let review = scope.review.as_ref().unwrap();
    let mut intent = KeyPrepareIntent {
        context: binding.scope.provisioning.clone(),
        provenance: binding.scope.provenance.clone(),
        target: scope.target(&binding.scope.target).unwrap(),
        source_p8: scope.source_p8.clone(),
        destination: scope.destination.clone().unwrap(),
        algorithm: KeyAlgorithm::Rsa2048Sha256,
        bundle: review.selection.bundle.clone(),
        observed_at: review.observed_at.clone(),
        valid_until: review.valid_until.clone(),
        before_sha256: review.selection.before_sha256.clone(),
        review_plan_sha256: String::new(),
    };
    intent.review_plan_sha256 = intent.review_hash().unwrap();
    intent.validate().unwrap();
    let update = KeyPrepareUpdate {
        sequence: 1,
        generation: KeyGeneration::Armed,
        output: None,
        save: ProfileSaveState::NotEntered,
        saved_reference: None,
        disposition: KeyDisposition::Running,
        cancel_requested: false,
    };
    json!({"observedAt":intent.observed_at,"validUntil":intent.valid_until,"beforeSha256":intent.before_sha256,
        "planSha256":intent.review_plan_sha256,"update":update})
}
fn with_pending(binding: &Arc<RequestBinding>) -> Decoder {
    let mut decoder = Decoder::new(binding.clone());
    decoder.push(&accepted(binding)).unwrap();
    assert!(matches!(
        decoder
            .push(&line(&envelope(
                binding,
                1,
                "key-pending",
                key_pending(binding)
            )))
            .unwrap(),
        Frame::Event(_)
    ));
    decoder
}
fn key_output() -> Value {
    json!({"frameBytes":4000,"frameSha256":"a".repeat(64),"csrSha256":"b".repeat(64),"publicKeySha256":"c".repeat(64)})
}
fn key_terminal(binding: &RequestBinding) -> Value {
    let mut value = complete(binding);
    value["result"] = json!({"schemaVersion":1,"scope":"local-ios-distribution-key","mode":binding.context.mode,
        "decision":"produced","reason":"producer-returned","saved":false,"certificateRequested":false,"credentialReady":false});
    value
}

#[test]
fn local_key_modes_keep_old_grammar_and_consent_closed_and_future_modes_unavailable() {
    for mode in [Mode::KeyReview, Mode::KeyPrepare] {
        let input = key_value(mode);
        let context = prepare(&input).unwrap().context;
        for other in [
            Mode::Review,
            Mode::Register,
            Mode::Reconcile,
            Mode::ProfileReview,
            Mode::ProfileReuse,
            Mode::ProfileCreate,
            Mode::ProfileReconcile,
            Mode::KeyReview,
            Mode::KeyPrepare,
        ] {
            let start = start(
                &json!({"operationId":"1".repeat(32),"ownerGeneration":"5".repeat(32),
                "consentVersion":other.consent()}),
            )
            .unwrap();
            assert_eq!(start.matches_context(&context), mode == other);
        }
        for (field, value) in [
            ("p12RecordId", json!("d".repeat(32))),
            ("privateKey", json!("not admitted")),
            ("newApplication", json!(true)),
            ("platform", json!("android")),
            ("executionMode", json!("remote")),
        ] {
            let mut changed = input.clone();
            changed[field] = value;
            assert!(prepare(&changed).is_err(), "{field}");
        }
    }
    for mode in [
        Mode::KeyRecover,
        Mode::CertificateReview,
        Mode::CertificateCreate,
        Mode::CertificateReconcile,
    ] {
        assert!(prepare(&key_value(mode)).is_err());
    }
    for mode in [Mode::Review, Mode::Register, Mode::Reconcile] {
        assert_eq!(mode.response_limit(), RESPONSE_LIMIT);
        assert_eq!(mode.frame_limit(), FRAME_LIMIT);
    }
    let mut original = Arc::try_unwrap(binding(Mode::Review)).ok().unwrap();
    let observed = Observed {
        observed_at: "2026-10-19T10:20:30.123456+00:00".into(),
        observation: Observation::NotReturned,
        bundle: None,
        before_sha256: Some("a".repeat(64)),
        decision: Decision::ReviewRequired,
    };
    assert!(observed.valid(&original));
    // Exercise the actual old-Observed dispatcher, not a second mode parser.
    for mode in [
        Mode::KeyReview,
        Mode::KeyPrepare,
        Mode::KeyRecover,
        Mode::CertificateReview,
        Mode::CertificateCreate,
        Mode::CertificateReconcile,
    ] {
        original.context.mode = mode;
        assert!(!observed.valid(&original));
    }
}

#[test]
fn key_events_require_same_context_sequence_and_cannot_enter_old_modes() {
    let b = key_binding(Mode::KeyPrepare);
    for field in ["operationId", "ownerGeneration", "nonce", "requestSha256"] {
        let mut decoder = Decoder::new(b.clone());
        decoder.push(&accepted(&b)).unwrap();
        let mut value = envelope(&b, 1, "key-pending", key_pending(&b));
        value[field] = json!("9".repeat(32));
        assert!(decoder.push(&line(&value)).is_err());
        assert!(decoder
            .push(&line(&envelope(&b, 1, "key-pending", key_pending(&b))))
            .is_err());
    }
    let mut decoder = with_pending(&b);
    assert!(decoder
        .push(&line(&envelope(&b, 1, "key-pending", key_pending(&b))))
        .is_err());
    let old = binding(Mode::Review);
    let mut decoder = Decoder::new(old.clone());
    decoder.push(&accepted(&old)).unwrap();
    assert!(decoder
        .push(&line(&envelope(&old, 1, "key-pending", key_pending(&b))))
        .is_err());
    for kind in ["key-retained", "key-pending-ack"] {
        let mut decoder = with_pending(&b);
        assert!(decoder
            .push(&line(&envelope(&b, 2, kind, json!({}))))
            .is_err());
    }
}

#[test]
fn output_metadata_is_not_saved_key_or_csr_authority_and_missing_output_refuses() {
    let b = key_binding(Mode::KeyPrepare);
    let mut decoder = with_pending(&b);
    assert!(decoder
        .push(&line(&envelope(&b, 2, "terminal", key_terminal(&b))))
        .is_err());
    for changed in ["saved", "certificateRequested", "credentialReady", "extra"] {
        let mut decoder = with_pending(&b);
        decoder
            .push(&line(&envelope(&b, 2, "key-output", key_output())))
            .unwrap();
        let mut terminal = key_terminal(&b);
        terminal["result"][changed] = json!(true);
        assert!(decoder
            .push(&line(&envelope(&b, 3, "terminal", terminal)))
            .is_err());
    }
    let mut decoder = with_pending(&b);
    let mut oversized = key_output();
    oversized["frameBytes"] = json!(u32::MAX);
    assert!(decoder
        .push(&line(&envelope(&b, 2, "key-output", oversized)))
        .is_err());
    let mut decoder = with_pending(&b);
    decoder
        .push(&line(&envelope(&b, 2, "key-output", key_output())))
        .unwrap();
    assert!(matches!(
        decoder
            .push(&line(&envelope(&b, 3, "terminal", key_terminal(&b))))
            .unwrap(),
        Frame::Terminal(_)
    ));
    // The last positive is decoder DATA only: no private body/ACK/native joins exist.
}

#[test]
fn no_generation_receipt_must_match_original_command_count_and_not_follow_output() {
    let b = key_binding(Mode::KeyPrepare);
    for (commands, before_command) in [(5, false), (8, false), (7, true)] {
        let mut decoder = with_pending(&b);
        assert!(decoder
            .push(&line(&envelope(
                &b,
                2,
                "key-not-generated",
                json!({"commands":commands,"beforeCommand":before_command})
            )))
            .is_err());
    }
    for count in [6, 7] {
        let mut decoder = with_pending(&b);
        decoder
            .push(&line(&envelope(
                &b,
                2,
                "key-not-generated",
                json!({"commands":6,"beforeCommand":true}),
            )))
            .unwrap();
        let mut terminal = key_terminal(&b);
        terminal["result"] = Value::Null;
        terminal["outcome"] = json!("cancelled");
        terminal["reason"] = json!("cancelled");
        terminal["lifetime"]["stopObserved"] = json!("cancelled");
        terminal["lifetime"]["commands"] = json!(count);
        assert_eq!(
            decoder
                .push(&line(&envelope(&b, 3, "terminal", terminal)))
                .is_ok(),
            count == 6
        );
    }
    let mut decoder = with_pending(&b);
    decoder
        .push(&line(&envelope(&b, 2, "key-output", key_output())))
        .unwrap();
    assert!(decoder
        .push(&line(&envelope(
            &b,
            3,
            "key-not-generated",
            json!({"commands":6,"beforeCommand":true})
        )))
        .is_err());
}

#[test]
fn review_without_complete_inventory_cannot_mint_local_preparation_selection() {
    let b = key_binding(Mode::KeyReview);
    let mut decoder = Decoder::new(b.clone());
    decoder.push(&accepted(&b)).unwrap();
    let observed = json!({"observedAt":"2026-10-19T10:20:30.123456+00:00",
        "validUntil":"2026-10-19T10:25:30.123456+00:00","decision":"blocked",
        "reason":"inventory-unavailable","selection":null});
    decoder
        .push(&line(&envelope(&b, 1, "key-observed", observed.clone())))
        .unwrap();
    let mut result = key_terminal(&b);
    result["result"]["decision"] = json!("prepare-review");
    result["result"]["reason"] = json!("local-key-required");
    assert!(decoder
        .push(&line(&envelope(&b, 2, "terminal", result)))
        .is_err());
    let mut decoder = Decoder::new(b.clone());
    decoder.push(&accepted(&b)).unwrap();
    let mut missing = observed;
    missing["decision"] = json!("prepare-review");
    missing["reason"] = json!("local-key-required");
    assert!(decoder
        .push(&line(&envelope(&b, 1, "key-observed", missing)))
        .is_err());
}
