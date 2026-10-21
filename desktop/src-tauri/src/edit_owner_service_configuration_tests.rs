//! Pure chain/outcome negatives. Never construct a Session, receipt or fake
//! all-jobs-joined value to exercise an alleged native success.
use super::*;
#[test]
fn exact_seven_publications_have_no_repeat_skip_or_rebase() {
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
    assert!(successor(Stage::Reviewing, Step::Terminal).is_none());
    assert!(successor(Stage::Opening, Step::Apply).is_none());
}
#[test]
fn no_preview_or_watchdog_cancellation_can_be_replaced_by_status_data() {
    let mut chain = Chain {
        epoch: 9,
        stage: Stage::Reviewing,
        pending: None,
        failed: false,
    };
    chain.failed = true;
    assert!(chain.failed);
    assert!(successor(chain.stage, Step::Retired).is_none());
    let read = crate::service_version_reserve_requests::ReadPermission::new(
        Instant::now() + Duration::from_secs(60),
    );
    let early = Instant::now();
    read.revoke(early);
    read.revoke(early + Duration::from_secs(2));
    assert_eq!(
        read.stop(early + Duration::from_secs(3))
            .unwrap()
            .map(|(_, at)| at),
        Some(early)
    );
}
#[test]
fn actual_main_window_decoders_accept_only_the_closed_origin_variant() {
    use crate::edit_commands as command;
    use serde_json::json;
    let good = json!({"intent":"agent-configuration","origin":{
        "serviceInstance":"1".repeat(32),"projectId":"2".repeat(32),"requestId":"3".repeat(32)}});
    assert!(matches!(
        command::configuration_open(&good),
        Ok(command::ConfigurationOpen::Agent(_))
    ));
    assert!(matches!(
        command::configuration_prepare(&good),
        Ok(command::ConfigurationPrepare::Agent(_))
    ));
    assert!(matches!(
        command::configuration_apply(&good),
        Ok(command::ConfigurationApply::Agent(_))
    ));
    for field in [
        "window",
        "root",
        "draft",
        "expectedBase",
        "planToken",
        "force",
    ] {
        let mut bad = good.clone();
        bad[field] = json!("not authority");
        assert!(command::configuration_open(&bad).is_err());
        assert!(command::configuration_prepare(&bad).is_err());
        assert!(command::configuration_apply(&bad).is_err());
    }
    assert!(matches!(
        command::configuration_open(&json!({"projectId":"original-project"})),
        Ok(command::ConfigurationOpen::Edit(_))
    ));
    assert!(matches!(
        command::configuration_open(&json!({"projectId":"original-project","intent":"recover"})),
        Ok(command::ConfigurationOpen::Recover(_))
    ));
    assert!(command::agent_configuration_status(&json!({}))
        .unwrap()
        .is_none());
    let query = good["origin"].clone();
    assert_eq!(
        command::agent_configuration_status(&query)
            .unwrap()
            .unwrap(),
        command::agent_configuration_query(&query).unwrap()
    );
    for field in ["serviceInstance", "projectId", "requestId"] {
        let mut missing = query.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(command::agent_configuration_status(&missing).is_err());
        let mut invalid = query.clone();
        invalid[field] = json!(null);
        assert!(command::agent_configuration_status(&invalid).is_err());
    }
    for bad in [
        json!(null),
        json!([]),
        good,
        json!({"origin":query}),
        json!({"latest":true}),
        json!({"requestId":"3".repeat(32)}),
    ] {
        assert!(command::agent_configuration_status(&bad).is_err());
    }
    let mut extra = query;
    extra["window"] = json!("not authority");
    assert!(command::agent_configuration_status(&extra).is_err());
}

#[test]
fn new_cli_frame_limits_precede_clone_while_ordinary_configuration_stays_supported() {
    use serde_json::json;
    fn opened(base: Value) -> Vec<u8> {
        let value = json!({"protocol":wire::PROTOCOL,"session":"a".repeat(32),"seq":0,"kind":"opened",
            "result":{"revision":"b".repeat(32),"base":base,"scopeResources":"settled"}});
        let mut raw = serde_json::to_vec(&value).unwrap();
        raw.push(b'\n');
        raw
    }
    let id = "a".repeat(32);
    let small = opened(json!({"value":"unchanged"}));
    assert!(wire::decode(&small, &id).is_ok());
    assert!(wire::decode_agent_configuration(&small, &id).is_ok());
    let oversized = opened(json!({"value":"x".repeat(273*1024)}));
    assert!(wire::decode(&oversized, &id).is_ok());
    assert!(wire::decode_agent_configuration(&oversized, &id).is_err());
    let tiny = opened(json!({"many":(0..2000).map(|_|json!({"x":{}})).collect::<Vec<_>>()}));
    assert!(tiny.len() < 256 * 1024);
    assert!(wire::decode(&tiny, &id).is_ok());
    assert!(wire::decode_agent_configuration(&tiny, &id).is_err());
    let duplicate = b"{\"protocol\":1,\"protocol\":1}";
    assert!(crate::protocol::strict_configuration_agent_frame_json(duplicate).is_err());
}

#[test]
fn failed_retirement_chain_cannot_publish_saved_attribution_or_change_physical_facts() {
    // Projection DATA only: no Session, publisher, runtime or joined receipt.
    fn projection(effect: Effect, journal: Journal) -> EditProjection {
        EditProjection {
            domain: EditDomain::Configuration,
            workflow: None,
            metadata_text: None,
            release_version: None,
            metadata_images: None,
            initialization: None,
            identity: None,
            project_id: "inert-project".into(),
            session_id: "a".repeat(32),
            owner_generation: "b".repeat(32),
            phase: Phase::Finalizing,
            review_remaining_ms: 0,
            checkout: None,
            prepared: None,
            recovery: None,
            apply_submitted: true,
            core_outcome: Some(wire::CoreEditOutcome {
                effect,
                journal,
                resources: ResourceState::Settled,
                reason: wire::CoreReason::None,
            }),
            native_reason: Reason::None,
            native_finality: NativeFinality::Pending,
            late_settled: false,
        }
    }
    for (effect, journal) in [
        (Effect::Committed, Journal::Clean),
        (Effect::Unchanged, Journal::NotCreated),
    ] {
        let mut p = projection(effect, journal);
        let core = p.core_outcome.clone();
        let mut unknown = false;
        fence_retirement(&mut p, &mut unknown, false);
        assert!(unknown);
        assert_eq!(p.native_reason, Reason::CallerLost);
        assert_eq!(p.core_outcome, core);
        assert!(p.apply_submitted);
        assert_eq!(p.phase, Phase::Finalizing);
        assert_eq!(p.native_finality, NativeFinality::Pending);
        assert!(!p.late_settled);
        assert!(final_data(&p, unknown).is_none());
        fence_retirement(&mut p, &mut unknown, true);
        assert!(unknown); // A later chain status never clears earlier failure.
        assert_eq!(p.native_reason, Reason::CallerLost);
    }
    let mut cancelled = projection(Effect::NotStarted, Journal::NotCreated);
    cancelled.apply_submitted = false;
    cancelled.native_reason = Reason::ReviewExpired;
    cancelled.core_outcome.as_mut().unwrap().reason = wire::CoreReason::Cancelled;
    let core = cancelled.core_outcome.clone();
    let mut unknown = false;
    fence_retirement(&mut cancelled, &mut unknown, false);
    assert!(!unknown);
    assert_eq!(cancelled.native_reason, Reason::ReviewExpired);
    assert_eq!(cancelled.core_outcome, core);
    assert_eq!(cancelled.native_finality, NativeFinality::Pending);
    assert!(final_data(&cancelled, false).is_none());
}
