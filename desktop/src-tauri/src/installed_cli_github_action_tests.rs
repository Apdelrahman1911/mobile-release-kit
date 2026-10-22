//! Original argument/output methods only; never starts the CLI, IPC or a provider.
use super::*;
fn id(c: &str) -> Id {
    Id::parse(&c.repeat(32)).unwrap()
}
fn args(text: &str) -> Vec<OsString> {
    text.split_whitespace().map(OsString::from).collect()
}
#[test]
fn three_fixed_verbs_use_only_ids_and_submit_requires_reviewed_confirmation() {
    let ids = format!(
        "{} {} {}",
        id("a").as_str(),
        id("b").as_str(),
        id("c").as_str()
    );
    let valid = format!("github-submit {ids} --reviewed --json");
    let words = super::super::collect_arguments(args(&valid).into_iter());
    assert!(recognizes(&words));
    assert!(matches!(
        parse(&words).unwrap().command,
        Command::Submit { .. }
    ));
    for suffix in [
        "",
        " --json",
        " --reviewed --force",
        " --reviewed --json extra",
    ] {
        assert!(parse(&args(&format!("github-submit {ids}{suffix}"))).is_err());
    }
    for command in ["github-status", "github-cancel"] {
        assert!(parse(&args(&format!("{command} {ids} --json"))).is_ok());
        assert!(parse(&args(&format!("{command} {ids} --reviewed"))).is_err());
    }
    assert!(!recognizes(&args("github-prepare")));
}
#[test]
fn returned_status_and_lost_reply_keep_exact_original_ids_and_no_replay() {
    let q = github::Query {
        project_id: id("a"),
        service_instance: id("b"),
        request_id: id("c"),
    };
    let bytes = unconfirmed(&q, Error::StateUnknown, true);
    let data: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(data["request"], serde_json::to_value(&q).unwrap());
    assert_eq!(data["doNotReplay"], true);
    let status = github::Status {
        origin: q.clone(),
        grant_id: id("d"),
        review: github::Review::FailedJobsRetry(github::PreparedReference {
            session_id: "github-connection-1".into(),
            consent_id: "a".repeat(32),
            expected_revision: 2,
            prepared_sha256: "b".repeat(64),
        }),
        revision: 4,
        state: github::State::Complete,
        settlement: p::Settlement::Settled,
        operation_id: Some("github-actions-retry-1".into()),
        reason: github::Reason::None,
        effect: github::Effect::AcceptedUnconfirmed,
        never_admitted: false,
        do_not_replay: true, snapshot: None, result:None,
    };
    let mut response = p::Response {
        version: 1,
        request_id: id("e"),
        service_instance: id("b"),
        client_id: id("f"),
        session_id: id("a"),
        response: p::ResponseBody::GitHubActionRequest(status),
    };
    let (code, bytes) = output(&response, &q, Some(&id("d")), false).unwrap();
    assert_eq!(code, 0);
    assert!(String::from_utf8(bytes)
        .unwrap()
        .contains("does not mean CI passed"));
    assert!(output(&response, &q, Some(&id("e")), true).is_err());
    response.service_instance = id("e");
    assert!(output(&response, &q, None, true).is_err());
}
#[test]
fn real_local_catalogue_keeps_one_closed_mutation_family_and_finite_output() {
    let bytes = super::super::capabilities(true).unwrap();
    assert!(bytes.len() <= crate::installed_cli::CAPABILITIES_BYTES);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let v = &value["githubActions"];
    assert_eq!(v["commands"], serde_json::json!(COMMANDS));
    assert_eq!(v["kinds"], serde_json::json!([
        "repository-create", "draft-pr-create", "pr-create", "failed-jobs-retry", "setup-publish", "setup-reconcile", "activity-overview",
        "preflight-prepare", "preflight-dispatch", "preflight-pending", "preflight-observe",
        "release-prepare", "release-dispatch", "release-pending", "release-observe",
        "setup-prepare", "counter-prepare", "counter-create", "publication-pending", "counter-reconcile",
        "counter-enrollment-review", "counter-enrollment-connect"
    ]));
    assert_eq!(v["readOnlyKinds"], serde_json::json!([
        "setup-reconcile", "activity-overview", "preflight-pending", "preflight-observe",
        "release-pending", "release-observe", "publication-pending", "counter-reconcile", "counter-enrollment-review"
    ]));
    let enrollment = &v["counterEnrollment"];
    for key in ["reviewRequiresSeparateConsent", "connectRequiresNewConsent", "explicitCheckAfterSubmit",
        "reviewGrantWithdrawalBeforeConnect", "localMappingOnly"] {
        assert_eq!(enrollment[key], true, "{key}");
    }
    for key in ["counterCreation", "reservation", "automaticConnect"] {
        assert_eq!(enrollment[key], false, "{key}");
    }
    let help = super::super::capabilities(false).unwrap();
    assert!(help.len() <= crate::installed_cli::CAPABILITIES_BYTES);
    assert!(std::str::from_utf8(&help).unwrap().contains("After each github-submit, Check"));
    assert_eq!(v["prepareKinds"], serde_json::json!(["preflight-prepare", "release-prepare", "counter-prepare", "setup-prepare"]));
    for key in ["oneUse", "mutating", "requiresExactDesktopConsent", "requiresRunningDesktop", "requiresProjectReadGrant",
        "normalPrCreation", "counterSetup", "firstCounterOnly", "counterPrepareMayCreateLocalState", "cliPendingLoad",
        "cliPrepare", "workflowDispatch", "dispatchMayRunProjectCode"] {
        assert_eq!(v[key], true, "{key}");
    }
    for key in ["defaultEnabled", "privateArguments", "readGrantAuthorizesWrites", "prepareAuthorizesDispatch",
        "merge", "automaticRetry", "nativeAvailabilityChecked"] {
        assert_eq!(v[key], false, "{key}");
    }
}

#[test]
fn publication_cli_output_preserves_read_effect_original_ids_and_counter_exclusion() {
    let q = github::Query { project_id:id("a"), service_instance:id("b"), request_id:id("c") };
    for kind in [github::Kind::SetupPublish, github::Kind::SetupReconcile] {
        let review=if kind==github::Kind::SetupPublish { github::Review::SetupPublish(github::PreparedReference {
            session_id:"github-connection-1".into(), consent_id:"a".repeat(32), expected_revision:2, prepared_sha256:"b".repeat(64),
        }) } else { github::Review::SetupReconcile(github::PendingReference {
            session_id:"github-connection-1".into(), expected_revision:2, marker:"a".repeat(32), record_sha256:"b".repeat(64),
        }) };
        let response=p::Response { version:1, request_id:id("e"),service_instance:id("b"),client_id:id("f"),session_id:id("a"),
            response:p::ResponseBody::GitHubActionRequest(github::Status {
                origin:q.clone(),grant_id:id("d"),review,revision:4,state:github::State::Complete,settlement:p::Settlement::Settled,
                operation_id:Some("github-publication-7".into()),reason:github::Reason::None,
                effect:if kind==github::Kind::SetupReconcile {github::Effect::None}else{github::Effect::DraftPrObserved},
                never_admitted:false,do_not_replay:true, snapshot:None, result:None,
            }),
        };
        let (code,bytes)=output(&response,&q,Some(&id("d")),false).unwrap();assert_eq!(code,0);
        let text=String::from_utf8(bytes).unwrap();
        assert!(text.contains(if kind==github::Kind::SetupReconcile {"GET-only"}else{"Counter setup is not included"}));
        assert!(text.contains(q.request_id.as_str()));assert!(text.contains("never resubmit automatically"));
        let (_,json)=output(&response,&q,None,true).unwrap();
        let parsed: serde_json::Value=serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed,serde_json::to_value(&response).unwrap());
        let mut wrong=q.clone();wrong.request_id=id("e");assert!(output(&response,&wrong,None,true).is_err());
    }
}

#[test]
fn activity_cli_output_is_historical_compact_data_not_a_new_read_permission() {
    use github::activity::{Reference, Snapshot, Section, SectionState, SectionReason, Coverage};
    let q = github::Query { project_id: id("a"), service_instance: id("b"), request_id: id("c") };
    let response = p::Response {
        version: 1, request_id: id("e"), service_instance: id("b"), client_id: id("f"), session_id: id("a"),
        response: p::ResponseBody::GitHubActionRequest(github::Status {
            origin: q.clone(), grant_id: id("d"), revision: 4,
            review: github::Review::ActivityOverview(Reference {
                session_id: "session-a".into(), expected_revision: 7, expected_connection_revision: 9,
                account_id: "11".into(), repository_id: "22".into(),
            }),
            state: github::State::Complete, settlement: p::Settlement::Settled,
            operation_id: Some("github-activity-7".into()), reason: github::Reason::None,
            effect: github::Effect::None, never_admitted: false, do_not_replay: true,
            result:None, snapshot: Some(Snapshot {
                account_id: 11, repository_id: 22, observed_at: "2026-10-21T12:00:00Z".into(),
                pull_requests: Section { state: SectionState::Unavailable, reason: SectionReason::Forbidden,
                    coverage: Coverage::Unknown, total: None, rows: vec![] },
                workflow_runs: Section { state: SectionState::Read, reason: SectionReason::None,
                    coverage: Coverage::Complete, total: Some(0), rows: vec![] },
            }),
        }),
    };
    let (code, bytes) = output(&response, &q, Some(&id("d")), false).unwrap();
    assert_eq!(code, 0);
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("historical Activity") && text.contains("no write"));
    assert!(text.contains("account 11") && text.contains("repository 22"));
    assert!(text.contains(q.request_id.as_str()) && text.contains("never resubmit automatically"));
    let (_, bytes) = output(&response, &q, None, true).unwrap();
    assert!(bytes.len() <= github::activity::RESPONSE_LIMIT + 1);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value, serde_json::to_value(&response).unwrap());
    if let p::ResponseBody::GitHubActionRequest(row) = &response.response {
        let snapshot = row.snapshot.as_ref().unwrap();
        assert_eq!(snapshot.pull_requests.total, None);
        assert_eq!(snapshot.pull_requests.reason, SectionReason::Forbidden);
        assert_eq!(snapshot.workflow_runs.total, Some(0));
    }
    let mut wrong = q.clone(); wrong.request_id = id("e");
    assert!(output(&response, &wrong, None, true).is_err());
    assert!(output(&response, &q, Some(&id("f")), true).is_err());
}

#[test]
fn enrollment_cli_output_keeps_exact_review_or_connected_data_without_new_authority() {
    use github::enrollment as e;
    let q = github::Query { project_id:id("a"), service_instance:id("b"), request_id:id("c") };
    for connect in [false, true] {
        let review = if connect { github::Review::CounterEnrollmentConnect(e::ConnectReference {
            session_id:"session-a".into(), expected_revision:7, expected_connection_revision:9,
            review_id:"a".repeat(32), review_sha256:"b".repeat(64),
        }) } else { github::Review::CounterEnrollmentReview(e::ReviewReference {
            session_id:"session-a".into(), expected_revision:7, expected_connection_revision:9,
            request_sha256:"b".repeat(64),
        }) };
        let result = e::Snapshot {
            operation:if connect {e::Operation::Connect}else{e::Operation::Review},
            phase:if connect {e::Phase::Connected}else{e::Phase::Reviewed},
            reason:if connect {e::OutcomeReason::Connected}else{e::OutcomeReason::None},
            review:if connect {None}else{Some(e::ReviewView { id:"a".repeat(32), repository:"fixture/app".into(),
                version:e::Version{name:"1.2.3".into(),build:7}, reservations:2 })},
        };
        let mut response=p::Response { version:1,request_id:id("e"),service_instance:id("b"),client_id:id("f"),session_id:id("a"),
            response:p::ResponseBody::GitHubActionRequest(github::Status {
                origin:q.clone(),grant_id:id("d"),review,revision:4,state:github::State::Complete,settlement:p::Settlement::Settled,
                operation_id:Some("a".repeat(32)),reason:github::Reason::None,
                effect:if connect {github::Effect::LocalMappingObserved}else{github::Effect::None},
                never_admitted:false,do_not_replay:true,snapshot:None,result:Some(github::dispatch::Snapshot::Enrollment(result)),
            }),
        };
        let (code, bytes)=output(&response,&q,Some(&id("d")),true).unwrap();assert_eq!(code,0);
        assert!(bytes.len()<=github::activity::RESPONSE_LIMIT+1);
        let value:serde_json::Value=serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value,serde_json::to_value(&response).unwrap());
        let (_, bytes)=output(&response,&q,None,false).unwrap();
        let text=String::from_utf8(bytes).unwrap();
        assert!(text.contains(q.request_id.as_str())&&text.contains("never resubmit automatically"));
        assert!(output(&response,&q,Some(&id("f")),true).is_err());
        let p::ResponseBody::GitHubActionRequest(row)=&mut response.response else {unreachable!()};
        row.state=github::State::Finishing;row.settlement=p::Settlement::Pending;
        assert!(output(&response,&q,None,true).is_err()); // result/observed mapping requires all returns
    }
}
