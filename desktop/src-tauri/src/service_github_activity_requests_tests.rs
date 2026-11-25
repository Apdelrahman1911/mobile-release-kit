//! Real Entry/Inbox/READ methods with inert DATA. No Supervisor receipt, IO or
//! native qualification is manufactured by these caller/history permutations.
use super::*;
use serde_json::json;
use std::time::Duration;

fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
struct Fixture {
    inbox: Inbox,
    scope: Arc<NativeScope>,
    _doc: Arc<()>,
}
impl Fixture {
    fn new() -> Self {
        let at = Instant::now();
        let doc = Arc::new(());
        let scope = NativeScope::new(
            id('1'),
            "project-1".into(),
            "/never-opened-activity-entry".into(),
            1,
            2,
            1,
            p::Review::ActivityOverview(p::activity::Reference {
                session_id: "session-a".into(),
                expected_revision: 3,
                expected_connection_revision: 9,
                account_id: "11".into(),
                repository_id: "22".into(),
            }),
            Arc::new(()),
            at + Duration::from_secs(100),
            Arc::new(
                crate::service_version_reserve_requests::ReadPermission::new(
                    at + Duration::from_secs(110),
                ),
            ),
            Arc::downgrade(&doc),
            tokio::sync::watch::channel(0).0,
        );
        let inbox = Inbox::new(id('2'));
        inbox.allow(scope.clone(), id('3')).unwrap();
        Self {
            inbox,
            scope,
            _doc: doc,
        }
    }
    fn input(&self) -> p::Submit {
        p::Submit {
            origin: p::Query {
                project_id: id('1'),
                service_instance: id('2'),
                request_id: id('4'),
            },
            grant_id: id('3'),
        }
    }
    fn claim(&self) -> Claim {
        self.inbox.submit(self.input()).unwrap();
        self.inbox.claim().unwrap().unwrap()
    }
    fn enter(e: &Entry, go: bool) {
        e.entering().unwrap();
        e.arm("github-activity-1").unwrap();
        if go {
            e.go("github-activity-1").unwrap();
        }
    }
}
fn observation() -> crate::github_activity_protocol::Observation {
    use crate::github_activity_protocol as a;
    a::Observation {
        target: a::Target {
            project_binding: "f".repeat(64),
            repository: "owner/app".into(),
            account_id: "11".into(),
            repository_id: "22".into(),
        },
        selection: a::Selection::Overview { branch: None },
        observed_at: "2026-10-21T12:00:00Z".into(),
        data: json!({"kind":"overview","branchHead":null,
            "pullRequests":{"state":"unavailable","reason":"forbidden","coverage":"unknown","total":null,"rows":[]},
            "workflowRuns":{"state":"read","reason":"none","coverage":"complete","total":0,"rows":[]}}),
    }
}

#[test]
fn activity_submit_clock_is_not_restarted_by_queue_grant_or_credential_renewal() {
    let f = Fixture::new();
    let call = f.claim();
    let e = call.entry();
    let end = e.submitted + Duration::from_secs(60);
    assert_eq!(
        e.activity_end(end + Duration::from_secs(500), e.submitted)
            .unwrap(),
        end
    );
    assert_eq!(
        e.activity_end(end + Duration::from_secs(900), end - Duration::from_secs(1))
            .unwrap(),
        end
    );
    assert!(e.activity_end(end + Duration::from_secs(900), end).is_err());
    assert_eq!(
        e.activity_end(e.submitted + Duration::from_secs(10), e.submitted)
            .unwrap(),
        e.submitted + Duration::from_secs(10)
    );
    // The actual READ end remains authoritative even before any owner arms.
    assert!(end <= f.scope.read.end());
    f.scope.read.revoke(e.submitted);
    assert!(e.activity_end(end, e.submitted).is_err());
    call.returned(Err(p::Reason::PermissionRevoked));
}

#[test]
fn compact_native_data_requires_same_caller_and_matching_final_history_ack() {
    for native_first in [false, true] {
        let f = Fixture::new();
        let call = f.claim();
        let e = call.entry().clone();
        Fixture::enter(&e, true);
        assert_eq!(e.status().unwrap().effect, p::Effect::None);
        if native_first {
            e.activity_returned(
                "github-activity-1",
                p::Reason::None,
                p::activity::Snapshot::from_observation(&observation()).ok(),
            );
            assert!(e.claim_history().unwrap().is_none());
        }
        call.returned(Ok(()));
        if !native_first {
            assert!(e.pending());
            e.activity_returned(
                "github-activity-1",
                p::Reason::None,
                p::activity::Snapshot::from_observation(&observation()).ok(),
            );
        }
        let before = e.status().unwrap();
        assert_eq!(before.state, p::State::Finishing);
        assert!(before.snapshot.is_none());
        let ack = e.claim_history().unwrap().unwrap();
        assert!(e.pending());
        ack.returned(Ok(())).unwrap();
        let final_row = e.status().unwrap();
        assert!(!e.pending());
        assert_eq!(final_row.state, p::State::Complete);
        assert_eq!(final_row.effect, p::Effect::None);
        let snapshot = final_row.snapshot.unwrap();
        assert_eq!(
            snapshot.pull_requests.reason,
            p::activity::SectionReason::Forbidden
        );
        assert_eq!(snapshot.workflow_runs.total, Some(0));
        // Reconnect reads the SAME immutable row, not a later Activity view.
        assert_eq!(
            f.inbox.query(&f.input().origin, false).unwrap().snapshot,
            Some(snapshot)
        );
        assert!(f.inbox.claim().unwrap().is_none());
    }
}

#[test]
fn activity_partial_or_foreign_result_never_supplies_success_or_mutation_effect() {
    for variant in 0..4 {
        let f = Fixture::new();
        let call = f.claim();
        let e = call.entry().clone();
        Fixture::enter(&e, variant != 0);
        let mut data = observation();
        if variant == 1 {
            data.target.repository_id = "23".into();
        }
        if variant == 2 {
            data.selection = crate::github_activity_protocol::Selection::Overview {
                branch: Some("main".into()),
            };
        }
        if variant == 3 {
            data.data["workflowRuns"]["rows"] = json!([{"token":"INERT"}]);
        }
        e.activity_returned(
            "github-activity-1",
            p::Reason::None,
            p::activity::Snapshot::from_observation(&data).ok(),
        );
        call.returned(Ok(()));
        if let Some(h) = e.claim_history().unwrap() {
            h.returned(Ok(())).unwrap();
        }
        let row = e.status().unwrap();
        assert_ne!(row.state, p::State::Complete);
        assert_eq!(row.effect, p::Effect::None);
        assert!(row.snapshot.is_none());
    }
}

#[test]
fn early_read_revoke_after_stop_and_history_loss_keep_original_read_unknown() {
    let f = Fixture::new();
    let call = f.claim();
    let e = call.entry().clone();
    Fixture::enter(&e, true);
    let stop = Instant::now();
    e.cancel(p::Reason::UserCancelled, stop);
    let earlier = stop - Duration::from_millis(1);
    f.scope.read.revoke(earlier);
    assert_eq!(e.first_stop(), Some((false, earlier)));
    e.activity_returned(
        "github-activity-1",
        p::Reason::None,
        p::activity::Snapshot::from_observation(&observation()).ok(),
    );
    call.returned(Ok(()));
    let h = e.claim_history().unwrap().unwrap();
    assert_eq!(h.fact.reason, p::Reason::PermissionRevoked);
    assert_eq!(h.fact.effect, p::Effect::None);
    assert!(h.returned(Err(Error::Unavailable)).is_err());
    let row = e.status().unwrap();
    assert_eq!(row.state, p::State::Unknown);
    assert!(row.snapshot.is_none());
    e.activity_returned(
        "github-activity-1",
        p::Reason::None,
        p::activity::Snapshot::from_observation(&observation()).ok(),
    );
    assert_eq!(e.status().unwrap(), row);
    // Repeated late notifications cannot change the first Unknown reason or
    // consume revisions until exhaustion without a new original fact.
    e.unknown(p::Reason::CleanupUnknown);
    e.unknown(p::Reason::HistoryUnavailable);
    assert_eq!(e.status().unwrap(), row);
    assert!(e.pending());
    assert!(e.claim_history().unwrap().is_none());
    assert!(f.inbox.claim().unwrap().is_none());
}

#[test]
fn activity_known_pre_arm_refusal_has_no_fabricated_native_receipt() {
    let f = Fixture::new();
    let call = f.claim();
    let e = call.entry().clone();
    call.returned(Err(p::Reason::Busy));
    let row = e.status().unwrap();
    assert!(row.never_admitted && row.operation_id.is_none() && row.snapshot.is_none());
    assert_eq!(row.effect, p::Effect::None);
    assert!(e.pending());
    e.claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    assert_eq!(e.status().unwrap().state, p::State::Refused);
    assert!(!e.pending());
}
