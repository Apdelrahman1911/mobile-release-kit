//! DATA injections exercise the original finite inbox. None mint native
//! currentness, join receipts, a Git process or a qualified execution.
use super::*;
use std::time::Duration;
fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn scope(doc: &Arc<()>, family: Family) -> Arc<NativeScope> {
    Arc::new(NativeScope {
        project_id: id('a'),
        runtime_id: "project-1".into(),
        root: "/inert/git-commit".into(),
        device: 1,
        inode: 2,
        registration: 1,
        document_revision: 1,
        input_revision: 1,
        read_operation_id: "git-read-1".into(),
        document: Arc::downgrade(doc),
        selection: p::Selection::new_shared(
            if family == Family::Commit {
                p::Action::Commit
            } else {
                p::Action::Stage
            },
            "d".repeat(64),
            vec!["app/a".into()],
        )
        .unwrap(),
        commit: if family == Family::Commit {
            Some(
                Draft::new(
                    "approved private draft".into(),
                    "Example".into(),
                    "a@example.invalid".into(),
                )
                .unwrap(),
            )
        } else {
            None
        },
        changes: tokio::sync::watch::channel(0).0,
    })
}
fn input(inbox: &Inbox, grant: Id, request: Id) -> p::Prepare {
    p::Prepare {
        origin: p::Query {
            project_id: id('a'),
            service_instance: inbox.instance.clone(),
            request_id: request,
        },
        grant_id: grant,
    }
}
fn setup() -> (Arc<()>, Inbox, p::Prepare) {
    let doc = Arc::new(());
    let inbox = Inbox::new(id('b'));
    let grant = inbox
        .allow_commit(scope(&doc, Family::Commit))
        .unwrap()
        .0
        .grant_id
        .unwrap();
    let request = input(&inbox, grant, id('c'));
    (doc, inbox, request)
}
fn prepared(inbox: &Inbox, request: &p::Prepare) -> Arc<NativeLink> {
    inbox.prepare_commit(request.clone()).unwrap();
    let mut claim = inbox.claim().unwrap().unwrap();
    let link = claim.link().unwrap();
    link.arm("git-local-1").unwrap();
    claim.returned(Ok(()));
    link.retired(OperationState::Succeeded);
    assert!(link
        .ready(
            p::Review {
                review_id: "git-local-1-review".into(),
                expected_index: "e".repeat(64),
                review_digest: "f".repeat(64),
                document_revision: 1,
                registration_generation: 1
            },
            Instant::now() + Duration::from_secs(60)
        )
        .unwrap());
    link
}
fn start(request: &p::Prepare) -> p::Start {
    p::Start {
        origin: request.origin.clone(),
        prepare_operation_id: "git-local-1".into(),
        review_id: "git-local-1-review".into(),
    }
}

#[test]
fn index_grant_and_queries_cannot_consume_or_cancel_commit_and_the_reverse() {
    let (doc, inbox, request) = setup();
    assert!(!inbox.access().unwrap().enabled);
    assert!(inbox.prepare(request.clone()).is_err());
    assert!(inbox.entries().unwrap().is_empty());
    inbox.prepare_commit(request.clone()).unwrap();
    assert!(inbox.query(&request.origin, true).is_err());
    assert_eq!(
        inbox.query_commit(&request.origin, false).unwrap().0.state,
        p::State::Queued
    );
    assert!(inbox.start(&start(&request)).is_err());
    inbox.query_commit(&request.origin, true).unwrap();
    let access = inbox.allow(scope(&doc, Family::Index)).unwrap();
    assert!(!inbox.commit_access().unwrap().0.enabled);
    let next = input(&inbox, access.grant_id.unwrap(), id('d'));
    assert!(inbox.prepare_commit(next.clone()).is_err());
    inbox.prepare(next.clone()).unwrap();
    assert!(inbox.query_commit(&next.origin, true).is_err());
    assert_eq!(
        inbox.query(&next.origin, false).unwrap().state,
        p::State::Queued
    );
}
#[test]
fn only_explicit_allow_replaces_an_unused_family_and_wrong_scope_has_no_effect() {
    let (doc, inbox, request) = setup();
    assert!(inbox.allow(scope(&doc, Family::Commit)).is_err());
    assert_eq!(
        inbox.commit_access().unwrap().0.grant_id,
        Some(request.grant_id.clone())
    );
    assert!(inbox.scope(&id('a')).unwrap().access.grant_id.is_none());
    let replacement = inbox.allow(scope(&doc, Family::Index)).unwrap();
    assert!(inbox.prepare_commit(request).is_err());
    assert_eq!(inbox.access().unwrap().grant_id, replacement.grant_id);
}
#[test]
fn exact_retry_returns_same_row_and_cross_family_request_id_never_replays() {
    let (doc, inbox, request) = setup();
    let first = inbox.prepare_commit(request.clone()).unwrap();
    assert_eq!(inbox.prepare_commit(request.clone()).unwrap(), first);
    assert_eq!(inbox.entries().unwrap().len(), 1);
    inbox.query_commit(&request.origin, true).unwrap();
    let next = inbox.allow(scope(&doc, Family::Index)).unwrap();
    let repeated = input(
        &inbox,
        next.grant_id.unwrap(),
        request.origin.request_id.clone(),
    );
    assert!(inbox.prepare(repeated).is_err());
    assert_eq!(inbox.entries().unwrap().len(), 1);
}
#[test]
fn shared_cap_is_total_metadata_only_not_thirty_two_private_drafts() {
    let doc = Arc::new(());
    let inbox = Inbox::new(id('b'));
    for n in 1..=p::REQUEST_LIMIT {
        let family = if n % 2 == 0 {
            Family::Index
        } else {
            Family::Commit
        };
        let held = scope(&doc, family);
        let weak = Arc::downgrade(&held);
        let grant = inbox.allow_for(held, family).unwrap().grant_id.unwrap();
        let request = input(&inbox, grant, Id::parse(&format!("{n:032x}")).unwrap());
        inbox.prepare_for(request.clone(), family).unwrap();
        if family == Family::Commit {
            inbox.query_commit(&request.origin, true).unwrap();
        } else {
            inbox.query(&request.origin, true).unwrap();
        }
        assert!(inbox.entries().unwrap().last().unwrap().scope().is_err());
        // Only the single current lease retains that scope, not the tombstone.
        assert_eq!(weak.strong_count(), 1);
    }
    assert_eq!(inbox.entries().unwrap().len(), p::REQUEST_LIMIT);
    assert!(inbox.allow_commit(scope(&doc, Family::Commit)).is_err());
    assert!(inbox.allow(scope(&doc, Family::Index)).is_err());
}
#[test]
fn same_claim_links_prepare_and_apply_then_unknown_blocks_both_families() {
    let (doc, inbox, request) = setup();
    let link = prepared(&inbox, &request);
    assert!(link.scope().commit.as_ref().is_some_and(Draft::valid));
    inbox.start_commit(&start(&request)).unwrap();
    let mut claim = inbox.claim().unwrap().unwrap();
    let apply = claim.link().unwrap();
    assert!(Arc::ptr_eq(apply.scope(), link.scope()));
    assert!(apply.arm("git-local-1").is_err());
    apply.arm("git-local-2").unwrap();
    claim.returned(Ok(()));
    apply.retired(OperationState::Unknown);
    let unknown = inbox.query_commit(&request.origin, true).unwrap();
    assert_eq!(unknown.0.state, p::State::Unknown);
    assert_eq!(unknown.0.settlement, Settlement::Unknown);
    let first_stop = apply.entry().stop_at().unwrap();
    // Exact repeated Start is an idempotent observation of this retained row,
    // not a second native admission or permission to clear its uncertainty.
    assert_eq!(inbox.start_commit(&start(&request)).unwrap(), unknown);
    assert!(inbox.claim().unwrap().is_none());
    let entries = inbox.entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert!(Arc::ptr_eq(&entries[0], apply.entry()));
    assert_eq!(apply.entry().stop_at().unwrap(), first_stop);
    let mut changed = start(&request);
    changed.review_id = "git-local-other-review".into();
    assert!(inbox.start_commit(&changed).is_err());
    assert_eq!(inbox.query_commit(&request.origin, false).unwrap(), unknown);
    for family in [Family::Index, Family::Commit] {
        assert!(inbox.allow_for(scope(&doc, family), family).is_err());
    }
}
#[test]
fn expired_start_consent_keeps_original_status_stop_and_first_failure() {
    let (_doc, inbox, request) = setup();
    let link = prepared(&inbox, &request);
    {
        let mut row = link.entry.lock().unwrap();
        row.review.as_mut().unwrap().1 = Instant::now() - Duration::from_millis(1);
    }
    assert!(inbox.start_commit(&start(&request)).is_err());
    let first = inbox.query_commit(&request.origin, true).unwrap();
    inbox.revoke_commit().unwrap();
    let last = inbox.query_commit(&request.origin, false).unwrap();
    assert_eq!(last.0.reason, first.0.reason);
    assert!(inbox.claim().unwrap().is_none());
}
#[test]
fn either_native_gui_stop_revokes_the_shared_grant_without_retiming_first_stop() {
    for family in [Family::Index, Family::Commit] {
        for stopped_before_revoke in [false, true] {
            let doc = Arc::new(());
            let inbox = Inbox::new(id('b'));
            let grant = inbox
                .allow_for(scope(&doc, family), family)
                .unwrap()
                .grant_id
                .unwrap();
            let request = input(&inbox, grant, id('c'));
            inbox.prepare_for(request.clone(), family).unwrap();
            let mut claim = inbox.claim().unwrap().unwrap();
            let link = claim.link().unwrap();
            link.arm("git-local-1").unwrap();
            claim.returned(Ok(()));
            let first = Instant::now() - Duration::from_millis(1);
            if stopped_before_revoke {
                link.entry().cancel(p::Reason::UserCancelled, first);
            }

            // Native main-window Stop is global to the one grant. This is
            // deliberately NOT the family-bound CLI request cancellation.
            if family == Family::Commit {
                inbox.revoke().unwrap();
            } else {
                inbox.revoke_commit().unwrap();
            }
            let stop = link.entry().stop_at().unwrap().unwrap();
            if stopped_before_revoke {
                assert_eq!(stop, (p::Reason::UserCancelled, first));
            } else {
                assert_eq!(stop.0, p::Reason::PermissionRevoked);
            }
            assert!(link.stopped());
            assert!(!inbox.access().unwrap().enabled);
            assert!(!inbox.commit_access().unwrap().0.enabled);
            inbox.revoke().unwrap();
            inbox.revoke_commit().unwrap();
            assert_eq!(link.entry().stop_at().unwrap(), Some(stop));
            let status = link.entry().status().unwrap();
            assert_eq!(status.state, p::State::Stopping);
            assert_eq!(status.settlement, Settlement::Pending);
            assert_eq!(status.prepare_operation_id.as_deref(), Some("git-local-1"));
            assert!(inbox.allow(scope(&doc, Family::Index)).is_err());
            assert!(inbox.allow_commit(scope(&doc, Family::Commit)).is_err());
        }
    }
}
#[test]
fn dropped_postclaim_observer_never_credits_nonentry_or_releases_unknown() {
    let (doc, inbox, request) = setup();
    inbox.prepare_commit(request.clone()).unwrap();
    let claim = inbox.claim().unwrap().unwrap();
    drop(claim);
    assert_eq!(
        inbox.query_commit(&request.origin, false).unwrap().0.state,
        p::State::Unknown
    );
    assert!(inbox.allow(scope(&doc, Family::Index)).is_err());
    assert!(inbox.allow_commit(scope(&doc, Family::Commit)).is_err());
}
