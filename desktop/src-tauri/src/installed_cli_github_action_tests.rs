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
        do_not_replay: true,
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
    assert_eq!(
        v["kinds"],
        serde_json::json!(["repository-create", "draft-pr-create", "failed-jobs-retry", "setup-publish", "setup-reconcile"])
    );
    assert_eq!(v["readOnlyKinds"], serde_json::json!(["setup-reconcile"]));
    assert_eq!(v["counterSetup"], false);
    assert_eq!(v["cliPendingLoad"], false);
    for key in ["oneUse", "mutating", "requiresExactDesktopConsent"] {
        assert_eq!(v[key], true);
    }
    for key in [
        "cliPrepare",
        "privateArguments",
        "readGrantAuthorizesWrites",
        "normalPrCreation",
        "merge",
        "workflowDispatch",
        "automaticRetry",
        "nativeAvailabilityChecked",
    ] {
        assert_eq!(v[key], false);
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
                never_admitted:false,do_not_replay:true,
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
