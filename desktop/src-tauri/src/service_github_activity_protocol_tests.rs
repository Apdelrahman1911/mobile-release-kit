//! Closed DATA and allocation arithmetic only. No account, source or native IO.
use super::*;
use crate::{service_github_action_protocol as p, service_protocol as service};
use serde_json::json;

fn id() -> service::Id {
    service::Id::parse(&"a".repeat(32)).unwrap()
}
fn reference() -> Reference {
    Reference {
        session_id: "s".repeat(64),
        expected_revision: u32::MAX - 9,
        expected_connection_revision: u32::MAX - 2,
        account_id: u64::MAX.to_string(),
        repository_id: u64::MAX.to_string(),
    }
}
fn snapshot() -> Snapshot {
    let mut pulls = Vec::with_capacity(ROWS);
    let mut runs = Vec::with_capacity(ROWS);
    for i in 0..ROWS {
        pulls.push(Pull {
            number: u64::MAX - i as u64,
            state: PullState::Closed,
            draft: false,
        });
        runs.push(Run {
            id: u64::MAX - i as u64,
            attempt: 1000,
            status: RunState::Completed,
            conclusion: Some(Conclusion::StartupFailure),
        });
    }
    Snapshot {
        account_id: u64::MAX,
        repository_id: u64::MAX,
        observed_at: "9999-12-31T23:59:59Z".into(),
        pull_requests: Section {
            state: SectionState::Read,
            reason: SectionReason::None,
            coverage: Coverage::Windowed,
            total: None,
            rows: pulls,
        },
        workflow_runs: Section {
            state: SectionState::Read,
            reason: SectionReason::None,
            coverage: Coverage::Windowed,
            total: Some(i32::MAX as u32),
            rows: runs,
        },
    }
}
fn status() -> p::Status {
    p::Status {
        origin: p::Query {
            project_id: id(),
            service_instance: id(),
            request_id: id(),
        },
        grant_id: id(),
        review: p::Review::ActivityOverview(reference()),
        revision: u32::MAX - 1,
        state: p::State::Complete,
        settlement: service::Settlement::Settled,
        operation_id: Some(format!("github-activity-{}", u64::MAX)),
        reason: p::Reason::None,
        effect: p::Effect::None,
        never_admitted: false,
        do_not_replay: true,
        snapshot: Some(snapshot()), result:None,
    }
}

#[test]
fn permission_revision_is_exact_full_u64_and_consumes_only_the_supplied_generation() {
    for n in [0, 1, (1u64 << 53) + 1, u64::MAX - 1, u64::MAX] {
        let value = json!(n.to_string());
        let r: PermissionRevision = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(r.0, n);
        assert_eq!(serde_json::to_value(r).unwrap(), value);
        assert_eq!(r.successor(n), n.checked_add(1));
        assert_eq!(r.successor(n.wrapping_add(1)), None);
    }
    for v in [
        json!(0),
        json!(1.0),
        json!(null),
        json!(""),
        json!("00"),
        json!("01"),
        json!("-0"),
        json!("+1"),
        json!(" 1"),
        json!("18446744073709551616"),
        json!([]),
    ] {
        assert!(serde_json::from_value::<PermissionRevision>(v).is_err());
    }
    // These are the exact comparison/overflow methods used at BOTH Doc cuts,
    // not an authorization fixture or a new counter implementation.
    let observed = PermissionRevision(8);
    let after_empty_revoke = 9;
    assert_eq!(observed.successor(after_empty_revoke), None);
    let commit = observed.successor(8).unwrap();
    assert_eq!(observed.successor(commit), None); // second delayed Allow loses
    assert_eq!(PermissionRevision(u64::MAX).successor(u64::MAX), None);
}

#[test]
fn activity_reference_has_no_prepared_or_mutating_consent_upgrade() {
    let r = p::Review::ActivityOverview(reference());
    assert!(r.valid() && r.retained_fits());
    assert!(r.prepared().is_none());
    let selection = p::Selection::ActivityOverview(reference().selection());
    assert!(selection.valid());
    let reference = reference();
    let mut value = json!({
        "kind": "activity-overview",
        "sessionId": reference.session_id,
        "expectedRevision": reference.expected_revision,
        "expectedConnectionRevision": reference.expected_connection_revision,
    });
    assert_eq!(serde_json::from_value::<p::Selection>(value.clone()).unwrap(), selection);
    for name in [
        "consentId",
        "preparedSha256",
        "marker",
        "token",
        "repository",
        "branch",
    ] {
        value[name] = json!("forbidden");
        assert!(serde_json::from_value::<p::Selection>(value.clone()).is_err());
        value.as_object_mut().unwrap().remove(name);
    }
    for kind in [
        p::Kind::RepositoryCreate,
        p::Kind::DraftPrCreate,
        p::Kind::PrCreate,
        p::Kind::FailedJobsRetry,
        p::Kind::SetupPublish,
        p::Kind::SetupReconcile,
    ] {
        assert_ne!(kind.consent(), p::Kind::ActivityOverview.consent());
        assert_ne!(kind.action(), p::Kind::ActivityOverview.action());
        value["kind"] = json!(kind);
        assert!(serde_json::from_value::<p::Selection>(value.clone()).is_err());
    }
    for effect in [
        p::Effect::NotSent,
        p::Effect::PotentiallyApplied,
        p::Effect::Accepted,
        p::Effect::CreatedObserved,
    ] {
        assert!(!effect.valid_for(p::Kind::ActivityOverview));
    }
}

#[test]
fn all_thirty_rows_have_checked_physical_backing_and_complete_cli_and_main_envelopes() {
    let row = status();
    row.validate().unwrap();
    let s = row.snapshot.as_ref().unwrap();
    assert!(s.allocated().unwrap() <= SNAPSHOT_BACKING);
    let reply = service::Response {
        version: 1,
        request_id: id(),
        service_instance: id(),
        client_id: id(),
        session_id: id(),
        response: service::ResponseBody::GitHubActionRequest(row.clone()),
    };
    let encoded = service::encode_response(&reply).unwrap();
    assert!(encoded.len() <= RESPONSE_LIMIT);
    assert_eq!(encoded, serde_json::to_vec(&reply).unwrap());
    assert_eq!(encoded.capacity(), encoded.len());
    let main = MainAccess {
        access: p::Access {
            service_instance: Some(id()),
            project_id: Some(id()),
            grant_id: Some(id()),
            review: Some(row.review.clone()),
            enabled: false,
            remaining_ms: 0,
            consumed: true,
            pending: false,
            unknown: false,
            status: Some(row),
        },
        permission_revision: PermissionRevision(u64::MAX),
    };
    main.access.validate().unwrap();
    // Same standard typed serialization as the four Tauri command results.
    let text = serde_json::to_string(&main).unwrap();
    assert!(text.len() <= RESPONSE_LIMIT);
    assert!(text.capacity() <= 2 * RESPONSE_LIMIT);
    let typed: p::Status =
        serde_json::from_value(serde_json::to_value(&main).unwrap()["status"].clone()).unwrap();
    assert_eq!(typed.snapshot.unwrap(), snapshot());
    // SAME server worker: one owned compact projection, conservative two
    // fixed validation/output scratches, request/ID copies and bounded scratch.
    // All Request/Response inline enum/return cells remain in original H.
    let worker = p::RAW_LIMIT + SNAPSHOT_BACKING + 1024 + 2 * RESPONSE_LIMIT + 4096;
    assert!(worker <= p::IPC_WORKER_BACKING);
    assert_eq!(p::DOCUMENT_BACKING, 786_432);
}

#[test]
fn compact_row_refuses_hidden_fields_overallocation_and_unavailable_as_empty() {
    let original = snapshot();
    let mut v = serde_json::to_value(&original).unwrap();
    v["workflowRuns"]["rows"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"1","attempt":1,"status":"queued","conclusion":null}));
    assert!(serde_json::from_value::<Snapshot>(v).is_err());
    for edit in 0..6 {
        let mut v = serde_json::to_value(&original).unwrap();
        match edit {
            0 => v["workflowRuns"]["rows"][0]["token"] = json!("INERT"),
            1 => v["workflowRuns"]["rows"][0]["conclusion"] = json!("new-arbitrary-state"),
            2 => v["workflowRuns"]["rows"][0]["status"] = json!("queued"),
            3 => v["pullRequests"]["reason"] = json!("forbidden"),
            4 => v["pullRequests"]["coverage"] = json!("complete"),
            _ => v["observedAt"] = json!("2025-02-29T00:00:00Z"),
        }
        assert!(serde_json::from_value::<Snapshot>(v).map_or(true, |s| !s.valid()));
    }
    // The service-only predicate has exactly the already-admitted native UTC
    // grammar, but needs no native module in the standalone installed CLI.
    for value in [
        "0000-01-01T00:00:00Z",
        "1900-02-29T00:00:00Z",
        "2000-02-29T23:59:59Z",
        "2100-02-29T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026-10-21T24:00:00Z",
        "2026-10-21T23:59:60Z",
        "9999-12-31T23:59:59Z",
        "2026-10-21T12:00:00+00:00",
        "2026-10-21T12:00:00Z",
    ] {
        assert_eq!(utc(value), crate::github_connection_protocol::utc(value));
    }
    let mut over = original.clone();
    over.workflow_runs.rows.reserve(SNAPSHOT_BACKING);
    assert!(!over.valid()); // valid short DATA cannot smuggle large capacity
    let mut gap = original;
    gap.pull_requests = Section {
        state: SectionState::Unavailable,
        reason: SectionReason::Forbidden,
        coverage: Coverage::Unknown,
        total: None,
        rows: vec![],
    };
    assert!(gap.valid());
    gap.pull_requests.total = Some(0);
    assert!(!gap.valid());
}

#[test]
fn old_six_status_bytes_have_no_optional_snapshot_or_permission_revision() {
    for kind in [
        p::Kind::RepositoryCreate,
        p::Kind::DraftPrCreate,
        p::Kind::PrCreate,
        p::Kind::FailedJobsRetry,
        p::Kind::SetupPublish,
        p::Kind::SetupReconcile,
    ] {
        let mut row = status();
        row.review = if kind == p::Kind::SetupReconcile {
            p::Review::SetupReconcile(p::PendingReference {
                session_id: "session-a".into(),
                expected_revision: 1,
                marker: "b".repeat(32),
                record_sha256: "c".repeat(64),
            })
        } else {
            p::Review::from_prepared(
                kind,
                p::PreparedReference {
                    session_id: "session-a".into(),
                    expected_revision: 1,
                    consent_id: "b".repeat(32),
                    prepared_sha256: "c".repeat(64),
                },
            )
            .unwrap()
        };
        row.snapshot = None;
        row.state = p::State::Queued;
        row.settlement = service::Settlement::Pending;
        row.operation_id = None;
        row.effect = kind.initial_effect();
        row.validate().unwrap();
        let bytes = serde_json::to_vec(&row).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v.as_object().unwrap().len(), 11);
        assert!(v.get("snapshot").is_none() && v.get("permissionRevision").is_none());
        assert_eq!(
            serde_json::to_vec(&serde_json::from_slice::<p::Status>(&bytes).unwrap()).unwrap(),
            bytes
        );
        v["snapshot"] = json!(null);
        assert!(serde_json::from_value::<p::Status>(v).is_err());
    }
}
