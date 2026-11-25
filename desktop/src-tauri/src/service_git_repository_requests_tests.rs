//! Exercises the SAME finite inbox using inert phase observations. These
//! injections do not create native source/receipt/permission or run Git.
use super::*;
use std::time::Duration;

fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn action() -> repository::Action {
    repository::Action::BranchCreate {
        expected_revision: "a".repeat(64),
        expected_reference_revision: "b".repeat(64),
        name: "next".into(),
    }
}
fn scope(doc: &Arc<()>, family: Family, init: bool) -> Arc<NativeScope> {
    Arc::new(NativeScope {
        project_id: id('a'),
        runtime_id: "project-1".into(),
        root: "/inert/git-repository".into(),
        device: 1,
        inode: 2,
        registration: 1,
        document_revision: 1,
        input_revision: 1,
        read_operation_id: if init {
            None
        } else {
            Some("git-read-1".into())
        },
        document: Arc::downgrade(doc),
        selection: match family {
            Family::Repository => repository::Selection::new(if init {
                repository::Action::Initialize {}
            } else {
                action()
            })
            .unwrap()
            .into(),
            _ => p::Selection::new_shared(
                if family == Family::Commit {
                    p::Action::Commit
                } else {
                    p::Action::Stage
                },
                "a".repeat(64),
                vec!["app/a".into()],
            )
            .unwrap()
            .into(),
        },
        commit: if family == Family::Commit {
            Some(
                Draft::new(
                    "private draft".into(),
                    "Fixture".into(),
                    "fixture@example.invalid".into(),
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
fn review(init: bool) -> repository::Review {
    repository::Review {
        review_id: "git-local-1-review".into(),
        source_revision: "a".repeat(64),
        reference_revision: if init { None } else { Some("b".repeat(64)) },
        expected_index: if init { None } else { Some("e".repeat(64)) },
        review_digest: "f".repeat(64),
        document_revision: 1,
        registration_generation: 1,
        preview: if init {
            repository::Preview::Initialize {
                initial_branch: "main".into(),
                object_format: "sha1".into(),
            }
        } else {
            repository::Preview::BranchCreate {
                head: "c".repeat(40),
                branch: Some("refs/heads/main".into()),
                target_ref: "refs/heads/next".into(),
            }
        },
    }
}
fn setup(init: bool) -> (Arc<()>, Inbox, p::Prepare) {
    let doc = Arc::new(());
    let inbox = Inbox::new(id('b'));
    let grant = inbox
        .allow_repository(scope(&doc, Family::Repository, init))
        .unwrap()
        .grant_id
        .unwrap();
    let request = input(&inbox, grant, id('c'));
    (doc, inbox, request)
}
fn start(request: &p::Prepare) -> p::Start {
    p::Start {
        origin: request.origin.clone(),
        prepare_operation_id: "git-local-1".into(),
        review_id: "git-local-1-review".into(),
    }
}

#[test]
fn only_init_has_null_basis_and_no_file_family_can_borrow_that_exception() {
    let doc = Arc::new(());
    let inbox = Inbox::new(id('b'));
    for family in [Family::Index, Family::Commit, Family::Repository] {
        let mut ordinary = scope(&doc, family, false);
        Arc::get_mut(&mut ordinary).unwrap().read_operation_id = None;
        assert!(inbox.allow_for(ordinary, family).is_err());
    }
    let mut init = scope(&doc, Family::Repository, true);
    Arc::get_mut(&mut init).unwrap().read_operation_id = Some("invented-observe".into());
    assert!(inbox.allow_repository(init).is_err());
    let good = scope(&doc, Family::Repository, true);
    assert!(inbox.allow(good.clone()).is_err());
    assert!(inbox.allow_commit(good.clone()).is_err());
    let allowed = inbox.allow_repository(good).unwrap();
    assert!(allowed.enabled);
    assert!(inbox.entries().unwrap().is_empty());
    assert!(inbox.access().unwrap().selection.is_none());
    assert!(inbox.commit_access().unwrap().0.selection.is_none());
}

#[test]
fn shared_grant_replacement_contention_and_family_queries_stay_exact() {
    let doc = Arc::new(());
    let inbox = Inbox::new(id('b'));
    for old in [Family::Index, Family::Commit] {
        let old_grant = inbox
            .allow_for(scope(&doc, old, false), old)
            .unwrap()
            .grant_id
            .unwrap();
        let grant = inbox
            .allow_repository(scope(&doc, Family::Repository, false))
            .unwrap()
            .grant_id
            .unwrap();
        assert!(!inbox.access().unwrap().enabled);
        assert!(!inbox.commit_access().unwrap().0.enabled);
        assert!(inbox
            .prepare_for(input(&inbox, old_grant, id('d')), old)
            .is_err());
        let request = input(&inbox, grant, Id::random().unwrap());
        assert!(inbox.prepare(request.clone()).is_err());
        assert!(inbox.prepare_commit(request.clone()).is_err());
        let first = inbox.prepare_repository(request.clone()).unwrap();
        assert!(inbox.query(&request.origin, true).is_err());
        assert!(inbox.query_commit(&request.origin, true).is_err());
        assert!(inbox.start(&start(&request)).is_err());
        assert!(inbox.start_commit(&start(&request)).is_err());
        assert_eq!(
            inbox.query_repository(&request.origin, false).unwrap(),
            first
        );
        for family in [Family::Index, Family::Commit, Family::Repository] {
            assert!(inbox.allow_for(scope(&doc, family, false), family).is_err());
        }
        inbox.query_repository(&request.origin, true).unwrap();
    }
}

#[test]
fn exact_lost_ack_retry_and_discovery_keep_one_row_and_never_rearm_unknown() {
    let (doc, inbox, request) = setup(false);
    let first = inbox.prepare_repository(request.clone()).unwrap();
    assert_eq!(inbox.prepare_repository(request.clone()).unwrap(), first);
    let mut other = request.clone();
    other.grant_id = id('e');
    assert!(inbox.prepare_repository(other).is_err());
    let rows = inbox.catalogue_requests(&id('b'), &id('a')).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].request_id, request.origin.request_id);
    assert_eq!(
        rows[0].family,
        crate::service_request_catalogue::AdditionalFamily::GitRepository
    );
    assert_eq!(
        serde_json::to_value(&rows).unwrap()[0]
            .as_object()
            .unwrap()
            .len(),
        2
    );
    drop(inbox.claim().unwrap().unwrap()); // Deliberate missing caller, not a native receipt.
    let unknown = inbox.query_repository(&request.origin, false).unwrap();
    assert_eq!(unknown.settlement, Settlement::Unknown);
    assert_eq!(inbox.prepare_repository(request.clone()).unwrap(), unknown);
    assert_eq!(
        inbox.query_repository(&request.origin, true).unwrap(),
        unknown
    );
    assert_eq!(inbox.catalogue_requests(&id('b'), &id('a')).unwrap(), rows);
    for family in [Family::Index, Family::Commit, Family::Repository] {
        assert!(inbox.allow_for(scope(&doc, family, false), family).is_err());
    }
    assert!(inbox.claim().unwrap().is_none());
}

#[test]
fn same_claim_needs_joined_typed_review_then_one_apply_before_final_observation() {
    for init in [false, true] {
        let (_doc, inbox, request) = setup(init);
        inbox.prepare_repository(request.clone()).unwrap();
        let mut claim = inbox.claim().unwrap().unwrap();
        let link = claim.link().unwrap();
        assert!(link
            .ready(review(init), Instant::now() + Duration::from_secs(60))
            .is_err());
        link.arm("git-local-1").unwrap();
        claim.returned(Ok(()));
        link.retired(OperationState::Succeeded);
        assert!(inbox.start_repository(&start(&request)).is_err());
        assert!(link
            .ready(review(!init), Instant::now() + Duration::from_secs(60))
            .is_err());
        let mut stale = review(init);
        stale.source_revision = "9".repeat(64);
        if !init {
            assert!(link
                .ready(stale, Instant::now() + Duration::from_secs(60))
                .is_err());
        }
        assert!(link
            .ready(review(init), Instant::now() + Duration::from_secs(60))
            .unwrap());
        let ready = inbox.query_repository(&request.origin, false).unwrap();
        assert_eq!(
            ready.review.as_ref().unwrap().expected_index.is_none(),
            init
        );
        assert_eq!(ready.settlement, Settlement::Pending);
        let started = inbox.start_repository(&start(&request)).unwrap();
        assert_eq!(inbox.start_repository(&start(&request)).unwrap(), started);
        let mut apply = inbox.claim().unwrap().unwrap();
        let next = apply.link().unwrap();
        assert!(next.same_request(&link));
        assert!(Arc::ptr_eq(next.scope(), link.scope()));
        next.arm("git-local-2").unwrap();
        apply.returned(Ok(()));
        link.review_removed();
        assert_eq!(
            inbox
                .query_repository(&request.origin, false)
                .unwrap()
                .state,
            p::State::Applying
        );
        next.retired(OperationState::Succeeded);
        let ended = inbox.query_repository(&request.origin, false).unwrap();
        assert_eq!(ended.state, p::State::Finished);
        assert_eq!(ended.settlement, Settlement::Settled);
        assert_eq!(inbox.start_repository(&start(&request)).unwrap(), ended);
        assert!(inbox.claim().unwrap().is_none());
    }
}

#[test]
fn any_desktop_family_revoke_stops_same_original_without_retiming_or_early_cleanup_credit() {
    for revoked_from in [Family::Index, Family::Commit, Family::Repository] {
        let (_doc, inbox, request) = setup(false);
        inbox.prepare_repository(request.clone()).unwrap();
        let mut claim = inbox.claim().unwrap().unwrap();
        let link = claim.link().unwrap();
        link.arm("git-local-1").unwrap();
        claim.returned(Ok(()));
        let first = Instant::now() - Duration::from_millis(1);
        link.entry().cancel(p::Reason::UserCancelled, first);
        inbox.revoke_for(revoked_from).unwrap();
        assert_eq!(
            link.entry().stop_at().unwrap(),
            Some((p::Reason::UserCancelled, first))
        );
        assert!(link.current("git-local-1").is_err());
        let status = inbox.query_repository(&request.origin, false).unwrap();
        assert_eq!(status.state, p::State::Stopping);
        assert_eq!(status.settlement, Settlement::Pending);
        assert!(!inbox.repository_access().unwrap().enabled);
        link.retired(OperationState::Cancelled);
        assert_eq!(
            inbox
                .query_repository(&request.origin, false)
                .unwrap()
                .settlement,
            Settlement::Settled
        );
    }
}

#[test]
fn thirty_two_tombstones_are_shared_across_all_families_without_scopes_or_extra_allowance() {
    let doc = Arc::new(());
    let inbox = Inbox::new(id('b'));
    let families = [Family::Index, Family::Commit, Family::Repository];
    for n in 0..p::REQUEST_LIMIT {
        let family = families[n % 3];
        let held = scope(&doc, family, family == Family::Repository);
        let weak = Arc::downgrade(&held);
        let grant = inbox.allow_for(held, family).unwrap().grant_id.unwrap();
        let request = input(
            &inbox,
            grant,
            Id::parse(&format!("{:032x}", n + 1)).unwrap(),
        );
        inbox.prepare_for(request.clone(), family).unwrap();
        let entry = inbox.entries().unwrap().last().unwrap().clone();
        entry.cancel(p::Reason::UserCancelled, Instant::now());
        assert!(entry.scope().is_err());
        assert_eq!(weak.strong_count(), 1);
        assert!(entry.row.lock().unwrap().review.is_none());
    }
    assert_eq!(
        inbox.catalogue_requests(&id('b'), &id('a')).unwrap().len(),
        p::REQUEST_LIMIT
    );
    for family in families {
        assert!(inbox.allow_for(scope(&doc, family, false), family).is_err());
    }
    assert!(DOCUMENT_BACKING < 3 * 1024 * 1024);
}
