//! Strict DATA and existing encoders only: no Consent, ticket, files or provider.
use super::super::*;
use crate::service_github_action_protocol as agent;

fn draft(ready: bool) -> Draft {
    let mut value = serde_json::json!({"base":"main","head":"feature/login","title":"Review login","body":"Reviewed text"});
    if ready {
        value["creationMode"] = serde_json::json!("ready-for-review");
    }
    serde_json::from_value(value).unwrap()
}
fn prepared(ready: bool) -> Prepared {
    let t = Target {
        scope: Scope {
            project_binding: "a".repeat(64),
            repository: "owner/app".into(),
            account_id: "11".into(),
            repository_id: "22".into(),
        },
        intent: Some(draft(ready).intent("b".repeat(32))),
    };
    serde_json::from_value(serde_json::json!({"target":t,"baseSha":"c".repeat(40),"headSha":"d".repeat(40),
        "comparison":{"aheadBy":1,"behindBy":0,"totalCommits":1,"reportedFiles":0,"coverage":"windowed","files":[]},
        "draft":!ready,"creationPermission":"not-proven","confirmation":t.confirmation()})).unwrap()
}
fn request(ready: bool) -> Request {
    let p = prepared(ready);
    Request {
        kind: Kind::Create,
        target: p.target.clone(),
        home: Some("/inert-task-home".into()),
        prepared: Some(p),
        draft: Some(draft(ready)),
    }
}

#[test]
fn legacy_draft_omits_mode_and_preserves_old_canonical_confirmation_and_digest() {
    let d = draft(false);
    let p = prepared(false);
    assert!(d.valid() && p.valid());
    assert_eq!(
        serde_json::to_value(&d).unwrap(),
        serde_json::json!({"base":"main","head":"feature/login","title":"Review login","body":"Reviewed text"})
    );
    let value = serde_json::to_value(&p).unwrap();
    assert!(value["target"]["intent"].get("creationMode").is_none());
    assert_eq!(value["draft"], true);
    assert_eq!(p.confirmation, "Create a draft pull request in owner/app from feature/login into main with the text you reviewed? Existing GitHub workflows may run. No code is pushed or merged. This does not authorize a release. Stopping cannot undo a sent request.");
    let parsed: Prepared = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(
        canonical(&parsed).unwrap(),
        serde_json::to_vec(&value).unwrap()
    );
    assert_eq!(
        p.digest().unwrap(),
        format!("{:x}", Sha256::digest(serde_json::to_vec(&value).unwrap()))
    );
    assert_ne!(p.digest().unwrap(), prepared(true).digest().unwrap());
}

#[test]
fn ready_requires_explicit_retained_mode_and_correlated_boolean_not_false_alone() {
    for ready in [false, true] {
        let p = prepared(ready);
        assert!(p.valid());
        let mut raw = serde_json::to_value(&p).unwrap();
        raw["draft"] = serde_json::json!(ready);
        assert!(!serde_json::from_value::<Prepared>(raw).unwrap().valid());
    }
    let mut raw = serde_json::to_value(prepared(true)).unwrap();
    raw["target"]["intent"]
        .as_object_mut()
        .unwrap()
        .remove("creationMode");
    assert!(!serde_json::from_value::<Prepared>(raw).unwrap().valid());
    assert!(prepared(true)
        .confirmation
        .contains("Reviewers may be notified"));
}

#[test]
fn absent_only_defaults_to_draft_while_null_bool_object_unknown_and_duplicate_refuse() {
    for v in [
        Value::Null,
        serde_json::json!(false),
        serde_json::json!(true),
        serde_json::json!("draft"),
        serde_json::json!("ready"),
        serde_json::json!({"ready-for-review":null}),
        serde_json::json!([]),
    ] {
        let mut d = serde_json::to_value(draft(false)).unwrap();
        d["creationMode"] = v.clone();
        assert!(serde_json::from_value::<Draft>(d).is_err());
        let mut t = serde_json::to_value(prepared(false).target).unwrap();
        t["intent"]["creationMode"] = v;
        assert!(serde_json::from_value::<Target>(t).is_err());
    }
    let value = serde_json::json!({"sessionId":"session-a","expectedRevision":1,"expectedConnectionRevision":2,"draft":draft(true)});
    let bytes = serde_json::to_vec(&value).unwrap();
    let decoded = raw_input("github_pull_request_prepare", &bytes).unwrap();
    assert!(decode_command("github_pull_request_prepare", &decoded).is_ok());
    let duplicate = String::from_utf8(bytes).unwrap().replace(
        "\"creationMode\":\"ready-for-review\"",
        "\"creationMode\":\"ready-for-review\",\"creationMode\":\"ready-for-review\"",
    );
    assert!(raw_input("github_pull_request_prepare", duplicate.as_bytes()).is_err());
}

#[test]
fn original_private_go_and_prepare_input_require_the_same_mode() {
    for ready in [false, true] {
        let mut r = request(ready);
        assert!(r.valid());
        let initial = encode_initial("inert", &r).unwrap();
        let digest = format!("{:x}", Sha256::digest(&initial));
        let raw = encode_go("inert", &digest, Some("inert-not-a-token"), &r).unwrap();
        assert!(raw.len() <= GO_LIMIT);
        let go: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            go["go"]["draft"],
            serde_json::to_value(draft(ready)).unwrap()
        );
        assert_eq!(go["go"]["prepared"]["draft"], !ready);
        r.draft = Some(draft(!ready));
        assert!(!r.valid());
        assert!(encode_initial("inert", &r).is_err());
        assert!(encode_go("inert", &digest, Some("inert-not-a-token"), &r).is_err());
    }
}

#[test]
fn ready_and_draft_cli_consents_match_the_native_prepared_not_the_shared_prefix() {
    let old = agent::Kind::DraftPrCreate;
    let ready = agent::Kind::PrCreate;
    assert_eq!(old.consent(), "agent-draft-pr-create-once-v1");
    assert_eq!(ready.consent(), "agent-pr-create-once-v1");
    assert_eq!(old.prefix(), ready.prefix()); // Same original native PR owner.
    assert_ne!(old.action(), ready.action());
    for (p, expected) in [(prepared(false), old), (prepared(true), ready)] {
        for kind in [
            old,
            ready,
            agent::Kind::RepositoryCreate,
            agent::Kind::FailedJobsRetry,
            agent::Kind::SetupPublish,
            agent::Kind::SetupReconcile,
        ] {
            assert_eq!(p.agent_kind_matches(kind), kind == expected);
        }
    }
    let mut mismatch = prepared(true);
    mismatch.draft = true;
    assert!(!mismatch.agent_kind_matches(ready));
    let selected: agent::Selection = serde_json::from_value(serde_json::json!({"kind":"pr-create","sessionId":"session-a","consentId":"b".repeat(32),"expectedRevision":4})).unwrap();
    assert!(selected.valid());
    assert_eq!(selected.kind(), ready);
    assert!(agent::Effect::AcknowledgedUnconfirmed.valid_for(ready));
    assert!(!agent::Effect::DraftPrObserved.valid_for(ready));
    assert_eq!(agent::REQUEST_LIMIT, 32);
}

#[test]
fn both_modes_share_existing_record_response_and_heap_bounds_without_an_extra_pool() {
    let p = prepared(true);
    let row = Pending {
        prepared: p,
        claimed: true,
        acknowledged: None,
        closed: None,
    };
    assert!(row.valid());
    let s = Status {
        schema_version: 1,
        revision: 1,
        session_id: Some("session-a".into()),
        available: true,
        reason: Reason::None,
        operation: None,
        consent: None,
        pending: vec![row; 32],
        observed: None,
        acknowledged: None,
    };
    assert!(s.fits());
    assert!(s.heap().unwrap() < RETAINED_LIMIT);
    let mut raw = serde_json::to_value(prepared(true)).unwrap();
    raw["confirmation"] = serde_json::json!("x".repeat(4096));
    assert!(!serde_json::from_value::<Prepared>(raw).unwrap().valid());
}
