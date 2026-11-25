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
        vault_inventory: Some(KeyVaultInventory {
            records: 1,
            keys: 0,
        }),
        recovery: None,
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

fn recovery_binding() -> (Arc<RequestBinding>, Value) {
    let mut b = Arc::try_unwrap(key_binding(Mode::KeyReview)).ok().unwrap();
    b.context.mode = Mode::KeyRecover;
    b.context.key_record_id = Some("e".repeat(32));
    b.context.key_record_revision = Some(1);
    assert!(b.context.valid());
    let scope = b.scope.key.as_mut().unwrap();
    let source = KeyReference {
        vault_id: scope.source_p8.vault_id.clone(), generation_id: scope.source_p8.generation_id.clone(),
        record_id: "e".repeat(32), revision_id: "f".repeat(32), revision_counter: 1,
    };
    let csr = "-----BEGIN CERTIFICATE REQUEST-----\nMAA=\n-----END CERTIFICATE REQUEST-----\n";
    // Deliberately inert framing DATA, not a private key or signed CSR.
    let output = crate::apple_provisioning_journal::KeyOutputMetadata {
        frame_bytes: 4000, frame_sha256: "a".repeat(64),
        csr_sha256: hex(&Sha256::digest(csr.as_bytes())),
        public_key_sha256: hex(&Sha256::digest([0x30, 0])),
    };
    scope.source_key = Some(source.clone());
    scope.vault_inventory = None;
    scope.recovery = Some(KeyRecoverySelection {
        reference: Reference { operation_id: "6".repeat(32), owner_generation: "7".repeat(32) },
        row_sha256: "b".repeat(64), native_settlement: crate::apple_provisioning_journal::NativeSettlement::Pending,
        output: output.clone(), recovery: None,
    });
    assert!(scope.valid(&b.context, &b.scope.target, None));
    (Arc::new(b), json!({"sourceKey":source,"csrPem":csr,"publicKeySpkiDer":"MAA=","output":output}))
}

#[test]
fn recovery_actual_decoder_requires_exact_original_comparison_before_terminal() {
    let (b, compared) = recovery_binding();
    let mut terminal = complete(&b);
    terminal["result"] = json!({"schemaVersion":1,"scope":"local-ios-distribution-key","mode":"key-recover",
        "decision":"compared","reason":"stored-key-checked","saved":false,"certificateRequested":false,"credentialReady":false});
    let fresh = || { let mut d = Decoder::new(b.clone()); d.push(&accepted(&b)).unwrap(); d };
    assert!(fresh().push(&line(&envelope(&b,1,"terminal",terminal.clone()))).is_err());
    let mut decoder = fresh();
    let Frame::Event(event) = decoder.push(&line(&envelope(&b,1,"key-compared",compared.clone()))).unwrap() else { panic!("comparison event") };
    let EventData::Key(KeyEvent::Compared(input)) = event.data else { panic!("typed comparison") };
    let ack: Value = serde_json::from_slice(&key_recovery_ack(&b,&input.payload_sha256).unwrap()).unwrap();
    assert_eq!(ack["kind"], "key-compared-ack");
    assert_eq!(ack["step"], 1);
    assert_eq!(ack["requestSha256"], b.sha256);
    assert_eq!(ack["payload"]["originalRowSha256"], "b".repeat(64));
    assert!(matches!(decoder.push(&line(&envelope(&b,2,"terminal",terminal.clone()))).unwrap(),Frame::Terminal(_)));
    for flag in ["saved","certificateRequested","credentialReady"] {
        let mut decoder = fresh(); decoder.push(&line(&envelope(&b,1,"key-compared",compared.clone()))).unwrap();
        let mut bad = terminal.clone(); bad["result"][flag] = json!(true);
        assert!(decoder.push(&line(&envelope(&b,2,"terminal",bad))).is_err());
    }
    // A complete private reply/Terminal is still only parser DATA: no native
    // loan, original writer return, Asset join or journal proof was created.
}

#[test]
fn recovery_decoder_rejects_crossref_both_hash_mismatches_foreign_mode_and_partial_frame() {
    let (b, compared) = recovery_binding();
    let fresh = || { let mut d = Decoder::new(b.clone()); d.push(&accepted(&b)).unwrap(); d };
    for case in 0..6 {
        let mut bad = compared.clone();
        match case {
            0 => bad["sourceKey"]["revisionId"] = json!("9".repeat(32)),
            1 => bad["csrPem"] = json!("-----BEGIN CERTIFICATE REQUEST-----\nMAE=\n-----END CERTIFICATE REQUEST-----\n"),
            2 => bad["publicKeySpkiDer"] = json!("MAE="),
            3 => bad["output"]["frameSha256"] = json!("d".repeat(64)),
            4 => bad["output"]["frameBytes"] = json!(4001),
            _ => bad["keySavedAckSha256"] = json!("c".repeat(64)),
        }
        assert!(fresh().push(&line(&envelope(&b,1,"key-compared",bad))).is_err());
    }
    for mode in [Mode::KeyReview,Mode::KeyPrepare,Mode::Review] {
        let other = if mode == Mode::Review { binding(mode) } else { key_binding(mode) };
        let mut decoder = Decoder::new(other.clone()); decoder.push(&accepted(&other)).unwrap();
        assert!(decoder.push(&line(&envelope(&other,1,"key-compared",compared.clone()))).is_err());
    }
    let mut decoder = fresh(); decoder.push(&line(&envelope(&b,1,"key-compared",compared.clone()))).unwrap();
    assert!(decoder.push(&line(&envelope(&b,2,"key-compared",compared.clone()))).is_err());
    for field in ["operationId","ownerGeneration","nonce","requestSha256"] {
        let mut foreign = envelope(&b,1,"key-compared",compared.clone()); foreign[field] = json!("8".repeat(32));
        assert!(fresh().push(&line(&foreign)).is_err());
    }
    let bytes = line(&envelope(&b,1,"key-compared",compared));
    assert!(fresh().push(&bytes[..bytes.len()-1]).is_err());
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
