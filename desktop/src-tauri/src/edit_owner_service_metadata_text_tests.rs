//! Fixed original-chain and DATA negatives. No Session, publisher, source or
//! native receipt is constructed and no native success is qualified here.
use super::*;

#[test]
fn exact_metadata_publications_cannot_skip_repeat_or_rebase() {
    let mut stage = Stage::Bound;
    for step in [
        Step::Open,
        Step::Opened,
        Step::Prepare,
        Step::Prepared,
        Step::Apply,
        Step::Terminal,
        Step::Retired,
    ] {
        let next = successor(stage, step).unwrap();
        assert!(successor(next, step).is_none());
        stage = next;
    }
    assert_eq!(stage, Stage::Returned);
    assert!(successor(Stage::Opening, Step::Apply).is_none());
    assert!(successor(Stage::Reviewing, Step::Retired).is_none());
    assert!(successor(Stage::Reviewing, Step::Terminal).is_none());
}

#[test]
fn metadata_agent_commands_accept_only_original_ids_and_separate_consent() {
    use crate::metadata_text_commands as cmd;
    let origin = json!({"serviceInstance":"1".repeat(32),"projectId":"2".repeat(32),"requestId":"3".repeat(32)});
    let request = json!({"intent":"agent-metadata-text","origin":origin});
    assert!(cmd::agent(&request).is_ok());
    assert!(cmd::agent_status(&json!({})).unwrap().is_none());
    assert_eq!(
        cmd::agent_status(&origin).unwrap().unwrap(),
        cmd::agent_query(&origin).unwrap()
    );
    for key in [
        "root",
        "window",
        "fields",
        "expectedBaseline",
        "planToken",
        "force",
    ] {
        let mut bad = request.clone();
        bad[key] = json!("not authority");
        assert!(cmd::agent(&bad).is_err());
    }
    for intent in ["agent-configuration", "agent-version-edit", "recover"] {
        let mut bad = request.clone();
        bad["intent"] = json!(intent);
        assert!(cmd::agent(&bad).is_err());
    }
    for key in ["serviceInstance", "projectId", "requestId"] {
        let mut bad = origin.clone();
        bad.as_object_mut().unwrap().remove(key);
        assert!(cmd::agent_status(&bad).is_err());
    }
    let allow = json!({"origin":origin,"original":{"sessionId":"4".repeat(32),"ownerGeneration":"5".repeat(32),"revision":"6".repeat(32)},"planToken":"7".repeat(32),"expectedNativeStatusRevision":8,"consentVersion":p::CONSENT});
    assert!(cmd::agent_allow(&allow).is_ok());
    let mut bad = allow;
    bad["consentVersion"] = json!(crate::service_configuration_protocol::CONSENT);
    assert!(cmd::agent_allow(&bad).is_err());
    // Ordinary manual Open and explicit recovery keep their own unchanged DTOs.
    assert!(
        cmd::open(&json!({"projectId":"project-a","platform":"android","locale":"en-US"})).is_ok()
    );
    assert!(matches!(
        cmd::open_request(&json!({"projectId":"project-a","intent":"recover"})),
        Ok(cmd::OpenRequest::Recover(_))
    ));
}

#[test]
fn fresh_open_comparison_retains_all_config_field_and_root_witnesses() {
    let fields = p::Platform::Android
        .ids()
        .iter()
        .map(|id| json!({"id":id,"state":"absent"}))
        .collect::<Vec<_>>();
    let original: p::Observation = serde_json::from_value(json!({
        "schemaVersion":1,"platform":"android","locale":"en-US","metadataRoot":"release/store","observationScope":"single-request-non-atomic",
        "baseline":{"config":{"byteLength":2,"sha256":"a".repeat(64)},"fields":fields},
        "fields":p::Platform::Android.ids().iter().map(|id|json!({"id":id,"state":"absent","path":format!("release/store/android/en-US/{id}")})).collect::<Vec<_>>(),
        "assurance":{"basis":"static-text","projectCodeExecuted":false,"toolsProbed":false,"credentialsRead":false,"gitObserved":false,"storeContacted":false,"writesPerformed":false,"releaseReadiness":"unknown"}
    })).unwrap();
    original.validate().unwrap();
    let native: metadata_wire::Baseline =
        serde_json::from_value(serde_json::to_value(&original.baseline).unwrap()).unwrap();
    assert!(baseline_matches(&original, "release/store", &native).unwrap());
    assert!(!baseline_matches(&original, "release/other", &native).unwrap());
    let mut changed = native.clone();
    changed.config.sha256 = "b".repeat(64);
    assert!(!baseline_matches(&original, "release/store", &changed).unwrap());
    let mut changed = native.clone();
    changed.fields.swap(0, 1);
    assert!(!baseline_matches(&original, "release/store", &changed).unwrap());
    let mut changed = native;
    changed.fields[0] = metadata_wire::BaselineField::Present {
        id: metadata_wire::FieldId::Title,
        byte_length: 0,
        sha256: p::sha(b""),
    };
    assert!(!baseline_matches(&original, "release/store", &changed).unwrap());
    assert!(matches!(
        &original.baseline.fields[0],
        p::BaselineField::Absent { .. }
    ));
}

#[test]
fn missing_metadata_retirement_chain_never_changes_resource_facts_into_saved() {
    let mut projection = EditProjection {
        domain: EditDomain::MetadataText,
        workflow: None,
        metadata_text: None,
        release_version: None,
        metadata_images: None,
        initialization: None,
        identity: None,
        project_id: "inert".into(),
        session_id: "a".repeat(32),
        owner_generation: "b".repeat(32),
        phase: Phase::Finalizing,
        review_remaining_ms: 0,
        checkout: None,
        prepared: None,
        recovery: None,
        apply_submitted: true,
        core_outcome: Some(wire::CoreEditOutcome {
            effect: Effect::Committed,
            journal: Journal::Clean,
            resources: ResourceState::Settled,
            reason: wire::CoreReason::None,
        }),
        native_reason: Reason::None,
        native_finality: NativeFinality::Pending,
        late_settled: false,
    };
    let original = projection.core_outcome.clone();
    let mut unknown = false;
    fence_retirement(&mut projection, &mut unknown, false);
    assert!(unknown);
    assert_eq!(projection.native_reason, Reason::CallerLost);
    assert_eq!(projection.core_outcome, original);
    assert_eq!(projection.phase, Phase::Finalizing);
    assert_eq!(projection.native_finality, NativeFinality::Pending);
    assert!(final_data(&projection, unknown).is_none());
    fence_retirement(&mut projection, &mut unknown, true);
    assert!(unknown);
    projection.native_reason = Reason::Cancelled;
    assert!(!known_outcome(&projection).unwrap().saved());
}
