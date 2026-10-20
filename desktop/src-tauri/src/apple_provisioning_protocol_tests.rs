//! Synthetic protocol DATA only. No RegisteredRoot, material/Store lease,
//! OriginalReservation, job receipt or native join witness is constructed.
use super::*;
use crate::{
    apple_provisioning_journal::{AccountRef, AttemptRecord, RegisteredRootData},
    application_service::ProjectBinding,
    application_state_store::Revision,
};

fn prepare_value(mode: Mode) -> Value {
    json!({"projectId":"project-1","draftRevision":1,"baselineGeneration":1,
        "savedConfig":{"bytes":123,"sha256":"3".repeat(64)},
        "savedVersion":{"source":"version.properties","bytes":45,"sha256":"4".repeat(64),"name":"1.2.3","build":7},
        "credentialContextRevision":1,"recordId":"c".repeat(32),"recordRevision":1,
        "executionMode":"local","platform":"ios","mode":mode,
        "reference":if mode == Mode::Review { Value::Null }
            else { json!({"operationId":"8".repeat(32),"ownerGeneration":"9".repeat(32)}) },
        "newApplication":mode == Mode::Register,"displayName":"Synthetic 🚀"})
}
fn binding(mode: Mode) -> Arc<RequestBinding> {
    let context = prepare(&prepare_value(mode)).unwrap().context;
    let provisioning = ProvisioningContext {
        project_id: context.project_id.clone(),
        client_id: "native-test-client".into(),
        operation_id: "1".repeat(32),
        observation_revision: 1,
        account_ref: AccountRef::from_selected_issuer([1; 16]),
        credential_record_id: context.record_id.clone(),
        credential_revision: 1,
        credential_context_revision: 1,
    };
    let provenance = NativeProvenance {
        project_binding: ProjectBinding {
            project_id: Id::parse(&"2".repeat(32)).unwrap(),
            canonical_root: "/synthetic/reference-only".into(),
            device: 202,
            inode: 101,
        },
        operation_id: Id::parse(&"1".repeat(32)).unwrap(),
        owner_generation: Id::parse(&"5".repeat(32)).unwrap(),
        registration_generation: 1,
        registered_root: RegisteredRootData {
            path: "/synthetic/reference-only".into(),
            device: 202,
            inode: 101,
            mode: 0o40755,
            uid: 501,
            gid: 20,
        },
        draft_revision: 1,
        baseline_generation: 1,
        saved_config: context.saved_config.clone(),
        saved_version: context.saved_version.clone(),
    };
    Arc::new(RequestBinding {
        operation: "1".repeat(32),
        generation: "5".repeat(32),
        context,
        scope: ScopeData {
            signing: None, key: None,
            provisioning,
            provenance,
            target: BundleTarget {
                bundle_id: "com.example.inert".into(),
                team_id: "TESTTEAM01".into(),
                app_id_prefix: "TESTTEAM01".into(),
                display_name: "Synthetic 🚀".into(),
                existing_application: false,
            },
            reviewed_at: if mode == Mode::Register {
                Some("2026-10-19T10:20:30.123456+00:00".into())
            } else {
                None
            },
        },
        nonce: "6".repeat(32),
        sha256: "7".repeat(64),
        revision: Revision(0),
    })
}
fn armed(binding: &RequestBinding) -> AttemptUpdate {
    AttemptUpdate {
        sequence: 1,
        record: AttemptRecord {
            context: binding.scope.provisioning.clone(),
            plan_sha256: "b75a1a063fb23ba3c80124960eb54c6ca9e0e9a458372881552b61a5ef861107".into(),
            action: Action::RegisterBundleId,
            status: AttemptStatus::Running,
            reason: AttemptReason::ReadbackRequired,
            possible_send: true,
            response_resource_id: None,
            response_resource_sha256: None,
            observed_resource_id: None,
            cancel_requested: false,
        },
    }
}
fn pending(binding: &RequestBinding) -> Value {
    // Generated once with the actual pure Python core, Unicode target and the
    // same closed context. Neither vector creation nor this test uses Apple.
    json!({"observedAt":"2026-10-19T10:20:30.123456+00:00","validUntil":"2026-10-19T10:25:30.123456+00:00",
        "beforeSha256":"89d05520a846a3f00d5ab55df921c2293c9b737a51447a6b4a9f8fa29bec92d7",
        "planSha256":"b75a1a063fb23ba3c80124960eb54c6ca9e0e9a458372881552b61a5ef861107",
        "requestBodySha256":"459a26665c038c87bd279e000e2b70de31976942ce1b496726b0b632904c3aed",
        "update":armed(binding)})
}
fn envelope(binding: &RequestBinding, sequence: u32, kind: &str, payload: Value) -> Value {
    json!({"protocol":PROTOCOL,"operationId":binding.operation,"ownerGeneration":binding.generation,
        "nonce":binding.nonce,"requestSha256":binding.sha256,"sequence":sequence,"kind":kind,"payload":payload})
}
fn line(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}
fn accepted(binding: &RequestBinding) -> Vec<u8> {
    line(&envelope(
        binding,
        0,
        "accepted",
        json!({"schemaVersion":1,"context":binding.context}),
    ))
}
fn observed(binding: &RequestBinding) -> Value {
    json!({"observedAt":"2026-10-19T10:20:30.123456+00:00","observation":"not-returned","bundle":null,
        "beforeSha256":"89d05520a846a3f00d5ab55df921c2293c9b737a51447a6b4a9f8fa29bec92d7",
        "decision":if binding.context.mode == Mode::Reconcile { "comparison-only" } else { "review-required" }})
}
fn complete(binding: &RequestBinding) -> Value {
    json!({"schemaVersion":1,"context":binding.context,"outcome":"complete","reason":"none",
        "result":{"schemaVersion":1,"scope":"local-ios-bundle-provisioning","mode":binding.context.mode,
            "observation":"not-returned","decision":if binding.context.mode == Mode::Reconcile { "comparison-only" } else { "review-required" },
            "attempt":null,"comparison":if binding.context.mode == Mode::Reconcile { json!("not-returned") } else { Value::Null },"limitations":LIMITATIONS},
        "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":true,
            "commands":binding.context.mode.commands(),"profileCalls":0,"inputClosed":true,"handlersRestored":true,
            "invocationClosed":true,"stopObserved":"none"}})
}

#[test]
fn closed_prepare_never_accepts_account_path_query_or_old_consent() {
    for mode in [Mode::Review, Mode::Register, Mode::Reconcile] {
        let value = prepare_value(mode);
        let context = prepare(&value).unwrap().context;
        for (name, replacement) in [
            ("query", json!("bundle-id-registration")),
            ("target", json!({})),
            ("accountRef", json!("e".repeat(64))),
            ("projectRoot", json!("/tmp")),
            ("token", json!("redacted")),
            ("executionMode", json!("github")),
            ("platform", json!("android")),
            ("newApplication", json!(mode != Mode::Register)),
        ] {
            let mut bad = value.clone();
            bad[name] = replacement;
            assert!(prepare(&bad).is_err(), "{name}");
        }
        for selected in [Mode::Review, Mode::Register, Mode::Reconcile] {
            let input = start(&json!({"operationId":"1".repeat(32),"ownerGeneration":"5".repeat(32),"consentVersion":selected.consent()})).unwrap();
            assert_eq!(input.matches_context(&context), selected == mode);
        }
        for consent in [
            "local-ios-store-access-v1",
            "local-ios-bundle-id-registration-v1",
            "local-ios-store-prepare-v1",
        ] {
            assert!(start(&json!({"operationId":"1".repeat(32),"ownerGeneration":"5".repeat(32),"consentVersion":consent})).is_err());
        }
    }
}

#[test]
fn required_reference_and_immutable_display_label_are_closed() {
    let mut value = prepare_value(Mode::Review);
    value.as_object_mut().unwrap().remove("reference");
    assert!(prepare(&value).is_err());
    for bad in [
        json!(""),
        json!("line\nbreak"),
        json!("x".repeat(129)),
        Value::Null,
    ] {
        let mut value = prepare_value(Mode::Register);
        value["displayName"] = bad;
        assert!(prepare(&value).is_err());
    }
    assert!(!timestamp_shape("2026-10-19T10:20:30.000000+00:00"));
    assert!(!timestamp_shape("2026-10-19T10:20:30Z"));
    assert!(timestamp_shape("2026-10-19T10:20:30+00:00"));
    assert!(timestamp_shape("2026-10-19T10:20:30.123456+00:00"));
}

#[test]
fn each_foreign_original_nonce_or_raw_request_digest_latches_decoder_failure() {
    let binding = binding(Mode::Review);
    for name in ["operationId", "ownerGeneration", "nonce", "requestSha256"] {
        let mut value = envelope(
            &binding,
            0,
            "accepted",
            json!({"schemaVersion":1,"context":binding.context}),
        );
        value[name] = json!(if name == "requestSha256" {
            "a".repeat(64)
        } else {
            "a".repeat(32)
        });
        let mut decoder = Decoder::new(binding.clone());
        assert!(decoder.push(&line(&value)).is_err());
        assert!(decoder.push(&accepted(&binding)).is_err());
        assert!(!decoder.settled());
    }
}

#[test]
fn raw_duplicate_member_and_extra_profile_content_refuse_before_projection() {
    let binding = binding(Mode::Review);
    let mut duplicate = accepted(&binding);
    duplicate.splice(1..1, b"\"sequence\":99,".iter().copied());
    assert!(Decoder::new(binding.clone()).push(&duplicate).is_err());
    let mut decoder = Decoder::new(binding.clone());
    decoder.push(&accepted(&binding)).unwrap();
    let mut payload = observed(&binding);
    payload["profileContent"] = json!("not-decoded");
    assert!(decoder
        .push(&line(&envelope(&binding, 1, "observed", payload)))
        .is_err());
    assert!(raw_request(br#"{"projectId":"a","projectId":"b"}"#).is_err());
}

#[test]
fn observed_metadata_is_scoped_and_does_not_turn_seed_id_into_team_proof() {
    let binding = binding(Mode::Review);
    let mut payload = observed(&binding);
    payload["observation"] = json!("found");
    payload["decision"] = json!("reuse");
    payload["bundle"] = json!({"resourceId":"resource-1","identifier":"com.example.inert","platform":"IOS","seedId":"OTHERTEAM1"});
    let parsed = Observed::deserialize(&payload).unwrap();
    assert!(parsed.valid(&binding));
    for (name, bad) in [
        ("identifier", json!("com.other.app")),
        ("platform", json!("MAC_OS")),
        ("resourceId", json!("x".repeat(129))),
    ] {
        let mut changed = payload.clone();
        changed["bundle"][name] = bad;
        assert!(!Observed::deserialize(changed).unwrap().valid(&binding));
    }
    payload["bundle"].as_object_mut().unwrap().remove("seedId");
    assert!(Observed::deserialize(payload).is_err());
    let mut absent = observed(&binding);
    absent["decision"] = json!("registration-confirmed");
    assert!(!Observed::deserialize(absent).unwrap().valid(&binding));
}

#[test]
fn pending_reconstructs_service_intent_and_exact_python_hashes_without_receipt() {
    let binding = binding(Mode::Register);
    let mut decoder = Decoder::new(binding.clone());
    decoder.push(&accepted(&binding)).unwrap();
    let Frame::Event(event) = decoder
        .push(&line(&envelope(&binding, 1, "pending", pending(&binding))))
        .unwrap()
    else {
        panic!("expected DATA")
    };
    let EventData::Pending { intent, update } = event.data else {
        panic!("expected DATA")
    };
    intent.validate().unwrap();
    assert_eq!(
        intent.provenance.project_binding.canonical_root,
        "/synthetic/reference-only"
    );
    assert_eq!(
        update.sha256().unwrap(),
        "3c293145e9c6cd4985694e0cddbc5722fa8740c247d521dbb32ccdaad272b355"
    );
    // There is deliberately no test constructor for JournalAck, native use,
    // OriginalReservation or either native join witness.
    assert!(!decoder.settled());
}

#[test]
fn pending_changed_plan_time_scope_and_false_no_send_do_not_reach_ack() {
    let binding = binding(Mode::Register);
    for name in ["beforeSha256", "planSha256", "requestBodySha256"] {
        let mut payload = pending(&binding);
        payload[name] = json!("e".repeat(64));
        let mut decoder = Decoder::new(binding.clone());
        decoder.push(&accepted(&binding)).unwrap();
        assert!(decoder
            .push(&line(&envelope(&binding, 1, "pending", payload)))
            .is_err());
    }
    for pointer in [
        "/update/record/context/operationId",
        "/update/record/context/accountRef",
        "/observedAt",
        "/validUntil",
        "/update/record/possibleSend",
    ] {
        let mut payload = pending(&binding);
        *payload.pointer_mut(pointer).unwrap() = match pointer {
            "/update/record/possibleSend" => json!(false),
            "/observedAt" | "/validUntil" => json!("2026-10-19T10:26:30.123456+00:00"),
            "/update/record/context/accountRef" => json!("e".repeat(64)),
            _ => json!("e".repeat(32)),
        };
        let mut decoder = Decoder::new(binding.clone());
        decoder.push(&accepted(&binding)).unwrap();
        assert!(
            decoder
                .push(&line(&envelope(&binding, 1, "pending", payload)))
                .is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn missing_sequence_out_of_order_or_extra_native_fact_never_settles() {
    let binding = binding(Mode::Register);
    let mut update = armed(&binding);
    update.sequence = 2;
    let mut decoder = Decoder::new(binding.clone());
    decoder.push(&accepted(&binding)).unwrap();
    assert!(decoder
        .push(&line(&envelope(
            &binding,
            2,
            "attempt",
            json!({"update":update})
        )))
        .is_err());
    let mut decoder = Decoder::new(binding.clone());
    decoder.push(&accepted(&binding)).unwrap();
    let mut payload = pending(&binding);
    payload["nativeJoined"] = json!(true);
    assert!(decoder
        .push(&line(&envelope(&binding, 1, "pending", payload)))
        .is_err());
}

#[test]
fn complete_core_lifetime_is_still_only_data_and_wrong_command_or_signing_claim_fails() {
    let binding = binding(Mode::Review);
    let mut decoder = Decoder::new(binding.clone());
    decoder.push(&accepted(&binding)).unwrap();
    decoder
        .push(&line(&envelope(
            &binding,
            1,
            "observed",
            observed(&binding),
        )))
        .unwrap();
    assert!(matches!(
        decoder
            .push(&line(&envelope(
                &binding,
                2,
                "terminal",
                complete(&binding)
            )))
            .unwrap(),
        Frame::Terminal(_)
    ));
    assert!(decoder.settled());
    assert!(decoder.push(&accepted(&binding)).is_err());
    for pointer in [
        "/lifetime/commands",
        "/lifetime/commandDispatched",
        "fewer-commands",
        "/lifetime/profileCalls",
        "/lifetime/inputClosed",
        "/result/credentialReady",
    ] {
        let mut value = complete(&binding);
        match pointer {
            "/lifetime/commands" => value["lifetime"]["commands"] = json!(8),
            "/lifetime/commandDispatched" => value["lifetime"]["commandDispatched"] = json!(false),
            "fewer-commands" => value["lifetime"]["commands"] = json!(6),
            "/lifetime/profileCalls" => value["lifetime"]["profileCalls"] = json!(1),
            "/lifetime/inputClosed" => value["lifetime"]["inputClosed"] = json!(false),
            _ => value["result"]["credentialReady"] = json!(true),
        }
        let mut decoder = Decoder::new(binding.clone());
        decoder.push(&accepted(&binding)).unwrap();
        decoder
            .push(&line(&envelope(
                &binding,
                1,
                "observed",
                observed(&binding),
            )))
            .unwrap();
        assert!(
            decoder
                .push(&line(&envelope(&binding, 2, "terminal", value)))
                .is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn reconciliation_has_no_attempt_or_registration_success_and_unknown_has_no_result() {
    let binding = binding(Mode::Reconcile);
    let mut decoder = Decoder::new(binding.clone());
    decoder.push(&accepted(&binding)).unwrap();
    decoder
        .push(&line(&envelope(
            &binding,
            1,
            "observed",
            observed(&binding),
        )))
        .unwrap();
    let mut value = complete(&binding);
    value["result"]["decision"] = json!("registration-confirmed");
    assert!(decoder
        .push(&line(&envelope(&binding, 2, "terminal", value)))
        .is_err());
    let binding = self::binding(Mode::Register);
    let mut decoder = Decoder::new(binding.clone());
    decoder.push(&accepted(&binding)).unwrap();
    let mut unknown = complete(&binding);
    unknown["outcome"] = json!("unknown");
    unknown["reason"] = json!("cleanup-unknown");
    unknown["result"] = Value::Null;
    unknown["lifetime"]["fatal"] = json!(true);
    let Frame::Terminal(terminal) = decoder
        .push(&line(&envelope(&binding, 1, "terminal", unknown)))
        .unwrap()
    else {
        panic!("expected DATA")
    };
    assert!(!terminal.lifetime.settled());
    assert!(terminal.result.is_none());
}

#[path = "apple_provisioning_profile_protocol_tests.rs"]
mod profile_contract;

#[path = "apple_provisioning_key_protocol_tests.rs"]
mod key_contract;
