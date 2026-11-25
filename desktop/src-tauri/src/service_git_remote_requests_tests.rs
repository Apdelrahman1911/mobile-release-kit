//! The genuine finite Inbox/Entry/Claim/NativeLink state machine with inert
//! callback DATA. No native receipt, Connection hold, IO, source or GO proof is
//! constructed; real callback placement is separately enforced in GitLocal.
use super::*;
use std::time::Duration;
fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn scope(doc: &Arc<()>, push: bool) -> Arc<NativeScope> {
    selected_scope(doc, remote::tests::selection(push))
}
fn selected_scope(doc: &Arc<()>, selection: remote::Selection) -> Arc<NativeScope> {
    Arc::new(NativeScope {
        project_id: id('a'),
        runtime_id: "project-1".into(),
        root: "/inert/remote".into(),
        device: 1,
        inode: 2,
        registration: 1,
        document_revision: 1,
        input_revision: 1,
        read_operation_id: Some("git-read-1".into()),
        document: Arc::downgrade(doc),
        selection: selection.into(),
        commit: None,
        changes: tokio::sync::watch::channel(0).0,
    })
}
fn setup(push: bool) -> (Arc<()>, Inbox, p::Prepare) {
    selected_setup(remote::tests::selection(push))
}
fn selected_setup(selection: remote::Selection) -> (Arc<()>, Inbox, p::Prepare) {
    let doc = Arc::new(());
    let inbox = Inbox::new(id('b'));
    let grant = inbox
        .allow_remote(selected_scope(&doc, selection))
        .unwrap()
        .grant_id
        .unwrap();
    let input = p::Prepare {
        origin: p::Query {
            project_id: id('a'),
            service_instance: id('b'),
            request_id: id('c'),
        },
        grant_id: grant,
    };
    (doc, inbox, input)
}
fn claim(inbox: &Inbox, input: &p::Prepare) -> (Claim, Arc<NativeLink>) {
    inbox.prepare_remote(input.clone()).unwrap();
    let mut claim = inbox.claim().unwrap().unwrap();
    let link = claim.link().unwrap();
    link.arm("git-local-1").unwrap();
    (claim, link)
}
fn candidate(push: bool) -> Option<(remote::Review, Instant)> {
    Some((
        remote::tests::review(push),
        Instant::now() + Duration::from_secs(299),
    ))
}
fn start(input: &p::Prepare) -> p::Start {
    p::Start {
        origin: input.origin.clone(),
        prepare_operation_id: "git-local-1".into(),
        review_id: "git-local-1-review".into(),
    }
}
fn status(inbox: &Inbox, input: &p::Prepare) -> remote::Status {
    inbox.query_remote(&input.origin, false).unwrap()
}
fn pending(inbox: &Inbox, input: &p::Prepare) {
    let s = status(inbox, input);
    assert_eq!(s.progress.settlement, Settlement::Pending);
    assert!(s.progress.review.is_none() && s.progress.outcome.is_none() && s.result.is_none());
}
#[test]
fn new_branch_prepare_and_apply_keep_same_three_returns_and_single_consumed_kind() {
    for prepare_caller_first in [false, true] {
        for apply_caller_first in [false, true] {
            let (doc, inbox, input) = selected_setup(remote::tests::new_branch_selection());
            let (prepare, link) = claim(&inbox, &input);
            let review = Some((
                remote::tests::new_branch_review(),
                Instant::now() + Duration::from_secs(299),
            ));
            if prepare_caller_first {
                prepare.returned(Ok(()));
                link.retired(OperationState::Succeeded);
                pending(&inbox, &input);
                assert!(inbox.start_remote(&start(&input)).is_err());
                assert!(link.remote_connection_returned(review, None).unwrap());
            } else {
                link.retired(OperationState::Succeeded);
                assert!(link.remote_connection_returned(review, None).unwrap());
                pending(&inbox, &input);
                assert!(inbox.start_remote(&start(&input)).is_err());
                prepare.returned(Ok(()));
            }
            let ready = status(&inbox, &input);
            assert!(matches!(
                ready.progress.review.as_ref().unwrap().preview,
                remote::Preview::PushNewBranch { .. }
            ));
            assert_eq!(
                ready.progress.selection.action.kind(),
                remote::Kind::PushNewBranch
            );
            let args = start(&input);
            inbox.start_remote(&args).unwrap();
            let mut apply = inbox.claim().unwrap().unwrap();
            let next = apply.link().unwrap();
            assert!(next.same_request(&link));
            next.arm("git-local-2").unwrap();
            link.review_removed();
            let result = remote::Outcome {
                operation_id: "git-local-2".into(),
                action: remote::Kind::PushNewBranch,
                state: remote::EffectState::RecoveryRequired,
                effect_phase: remote::Effect::SendConsumed,
                retained_paths: vec!["mrk-git-test/mrk-git-push-test".into()],
            };
            if apply_caller_first {
                apply.returned(Ok(()));
                next.retired(OperationState::RecoveryRequired);
                pending(&inbox, &input);
                next.remote_connection_returned(None, Some(result.clone()))
                    .unwrap();
            } else {
                next.retired(OperationState::RecoveryRequired);
                next.remote_connection_returned(None, Some(result.clone()))
                    .unwrap();
                pending(&inbox, &input);
                apply.returned(Ok(()));
            }
            let final_status = status(&inbox, &input);
            assert_eq!(final_status.result, Some(result));
            assert_eq!(final_status.progress.settlement, Settlement::Settled);
            assert_eq!(inbox.start_remote(&args).unwrap(), final_status);
            assert_eq!(inbox.prepare_remote(input.clone()).unwrap(), final_status);
            assert!(inbox.claim().unwrap().is_none());
            assert!(inbox.allow_remote(scope(&doc, true)).is_err());
        }
    }
}
#[test]
fn new_branch_lost_finish_caller_or_expired_review_never_rearms_from_status() {
    for which in 0..4 {
        let (doc, inbox, input) = selected_setup(remote::tests::new_branch_selection());
        let (caller, link) = claim(&inbox, &input);
        link.retired(OperationState::Succeeded);
        let review = Some((
            remote::tests::new_branch_review(),
            Instant::now() + Duration::from_secs(299),
        ));
        match which {
            0 => {
                caller.returned(Ok(()));
                pending(&inbox, &input);
                // No Connection finish arrived. A terminal native event is
                // not that missing original, even for an absence-only push.
                link.entry.unknown();
            }
            1 => {
                drop(caller);
                assert!(!link.remote_connection_returned(review, None).unwrap());
            }
            2 => {
                assert!(!link
                    .remote_connection_returned(
                        Some((remote::tests::new_branch_review(), Instant::now())),
                        None
                    )
                    .unwrap());
                pending(&inbox, &input);
                caller.returned(Ok(()));
            }
            _ => {
                assert!(link.remote_connection_returned(review, None).unwrap());
                link.review_removed();
                pending(&inbox, &input);
                caller.returned(Ok(()));
            }
        }
        let current = status(&inbox, &input);
        assert!(current.progress.review.is_none());
        assert_eq!(inbox.prepare_remote(input.clone()).unwrap(), current);
        assert!(inbox.start_remote(&start(&input)).is_err());
        assert!(inbox.claim().unwrap().is_none());
        if which < 2 {
            assert_eq!(current.progress.settlement, Settlement::Unknown);
            assert!(inbox
                .allow_remote(selected_scope(&doc, remote::tests::new_branch_selection()))
                .is_err());
        } else {
            assert_eq!(current.progress.settlement, Settlement::Settled);
        }
    }
}
#[test]
fn an_existing_fetch_or_push_grant_cannot_be_upgraded_to_new_branch_review() {
    for old in [false, true] {
        let (doc, inbox, input) = setup(old);
        let (caller, link) = claim(&inbox, &input);
        assert!(inbox
            .allow_remote(selected_scope(&doc, remote::tests::new_branch_selection()))
            .is_err());
        caller.returned(Ok(()));
        link.retired(OperationState::Succeeded);
        assert!(link
            .remote_connection_returned(
                Some((
                    remote::tests::new_branch_review(),
                    Instant::now() + Duration::from_secs(299)
                )),
                None,
            )
            .is_err());
        // The real caller marks any failed native-review comparison Unknown.
        link.entry.unknown();
        let original = status(&inbox, &input);
        assert_eq!(
            original.progress.selection.action.kind(),
            if old {
                remote::Kind::Push
            } else {
                remote::Kind::Fetch
            }
        );
        assert_eq!(original.progress.settlement, Settlement::Unknown);
        assert!(original.progress.review.is_none());
        assert_eq!(inbox.prepare_remote(input.clone()).unwrap(), original);
        assert!(inbox.start_remote(&start(&input)).is_err());
    }
}
#[test]
fn both_return_orders_withhold_ready_history_and_start_until_all_three_originals() {
    for caller_first in [false, true] {
        let (_doc, inbox, input) = setup(false);
        let (claim, link) = claim(&inbox, &input);
        if caller_first {
            claim.returned(Ok(()));
            link.retired(OperationState::Succeeded);
            pending(&inbox, &input);
            assert!(inbox.start_remote(&start(&input)).is_err());
            assert!(link
                .remote_connection_returned(candidate(false), None)
                .unwrap());
        } else {
            link.retired(OperationState::Succeeded);
            pending(&inbox, &input);
            assert!(link
                .remote_connection_returned(candidate(false), None)
                .unwrap());
            pending(&inbox, &input);
            let h = link.entry.claim_history().unwrap().unwrap();
            assert_eq!(h.2, OperationState::Running);
            assert_eq!(h.3, Settlement::Pending);
            link.entry.history_returned(h.1, Ok(())).unwrap();
            assert!(inbox.start_remote(&start(&input)).is_err());
            claim.returned(Ok(()));
        }
        let ready = status(&inbox, &input);
        assert_eq!(ready.progress.state, p::State::Prepared);
        assert!(ready.progress.review.is_some());
        assert!(ready.result.is_none());
        inbox.start_remote(&start(&input)).unwrap();
        let apply = inbox.claim().unwrap().unwrap();
        apply.returned(Err(Error::Busy));
        assert_eq!(
            status(&inbox, &input).progress.settlement,
            Settlement::Settled
        );
    }
}
#[test]
fn cancelled_failed_and_no_review_still_wait_for_connection_and_caller_return() {
    for native in [
        OperationState::Cancelled,
        OperationState::Failed,
        OperationState::Succeeded,
    ] {
        let (_doc, inbox, input) = setup(false);
        let (claim, link) = claim(&inbox, &input);
        link.entry.cancel(p::Reason::UserCancelled, Instant::now());
        link.retired(native);
        link.no_review();
        link.review_removed();
        pending(&inbox, &input);
        assert!(!link.remote_connection_returned(None, None).unwrap());
        pending(&inbox, &input);
        claim.returned(Ok(()));
        let s = status(&inbox, &input);
        assert_eq!(s.progress.settlement, Settlement::Settled);
        assert!(s.progress.review.is_none());
        assert_ne!(s.progress.outcome, Some(OperationState::Succeeded));
    }
}
#[test]
fn expiry_and_removed_candidate_do_not_close_before_original_return_or_renew_review() {
    for kind in 0..3 {
        let (_doc, inbox, input) = setup(false);
        let (claim, link) = claim(&inbox, &input);
        link.retired(OperationState::Succeeded);
        let mut c = candidate(false);
        if kind == 0 {
            c.as_mut().unwrap().1 = Instant::now() - Duration::from_millis(1);
        }
        if kind == 1 {
            link.lease.revoked.store(true, Ordering::Release);
        }
        let keep = link.remote_connection_returned(c, None).unwrap();
        if kind == 2 {
            assert!(keep);
            link.review_removed();
        }
        pending(&inbox, &input);
        claim.returned(Ok(()));
        let s = status(&inbox, &input);
        assert_eq!(s.progress.settlement, Settlement::Settled);
        assert!(s.progress.review.is_none());
        assert!(inbox.start_remote(&start(&input)).is_err());
        assert_eq!(inbox.prepare_remote(input.clone()).unwrap(), s);
    }
}
#[test]
fn armed_apply_keeps_own_return_and_effect_after_consumed_prepare_review_drops() {
    for caller_first in [false, true] {
        let (_doc, inbox, input) = setup(true);
        let (prepare, link) = claim(&inbox, &input);
        prepare.returned(Ok(()));
        link.retired(OperationState::Succeeded);
        link.remote_connection_returned(candidate(true), None)
            .unwrap();
        let args = start(&input);
        inbox.start_remote(&args).unwrap();
        let mut apply = inbox.claim().unwrap().unwrap();
        let next = apply.link().unwrap();
        assert!(next.same_request(&link));
        next.arm("git-local-2").unwrap();
        link.review_removed();
        let original = remote::Outcome {
            operation_id: "git-local-2".into(),
            action: remote::Kind::Push,
            state: remote::EffectState::RecoveryRequired,
            effect_phase: remote::Effect::SendEntered,
            retained_paths: vec!["mrk-git-test/mrk-git-push-test".into()],
        };
        if caller_first {
            apply.returned(Ok(()));
            next.retired(OperationState::RecoveryRequired);
            pending(&inbox, &input);
            next.remote_connection_returned(None, Some(original.clone()))
                .unwrap();
        } else {
            next.retired(OperationState::RecoveryRequired);
            next.remote_connection_returned(None, Some(original.clone()))
                .unwrap();
            pending(&inbox, &input);
            apply.returned(Ok(()));
        }
        let s = status(&inbox, &input);
        assert_eq!(s.result, Some(original));
        assert_eq!(s.progress.outcome, Some(OperationState::RecoveryRequired));
        assert_eq!(inbox.start_remote(&args).unwrap(), s);
        assert!(inbox.claim().unwrap().is_none());
        assert!(inbox.allow_remote(scope(&_doc, false)).is_err());
    }
}
#[test]
fn lost_caller_missing_finish_and_unknown_never_rearm_or_accept_status_as_settlement() {
    for which in 0..3 {
        let (_doc, inbox, input) = setup(false);
        let (claim, link) = claim(&inbox, &input);
        link.retired(OperationState::Succeeded);
        match which {
            0 => {
                drop(claim);
                assert!(!link
                    .remote_connection_returned(candidate(false), None)
                    .unwrap());
            }
            1 => {
                claim.returned(Ok(()));
                pending(&inbox, &input);
                link.entry.unknown();
            }
            _ => {
                link.remote_connection_returned(candidate(false), None)
                    .unwrap();
                claim.returned(Err(Error::StateUnknown));
            }
        }
        let s = status(&inbox, &input);
        assert_eq!(s.progress.settlement, Settlement::Unknown);
        assert!(s.progress.review.is_none());
        assert_eq!(inbox.prepare_remote(input.clone()).unwrap(), s);
        assert!(inbox.start_remote(&start(&input)).is_err());
        assert!(inbox.allow_remote(scope(&_doc, false)).is_err());
    }
}

#[test]
fn connection_return_refuses_foreign_review_identity_and_contradictory_terminal_effect() {
    for changed in 0..3 {
        let (_doc, inbox, input) = setup(false);
        let (claim, link) = claim(&inbox, &input);
        claim.returned(Ok(()));
        link.retired(OperationState::Succeeded);
        let mut c = candidate(false).unwrap();
        match changed {
            0 => c.0.review_id = "git-local-other-review".into(),
            1 => c.0.document_revision += 1,
            _ => c.0.registration_generation += 1,
        }
        assert!(link.remote_connection_returned(Some(c), None).is_err());
        // Same behavior as the sole production caller on a failed comparison;
        // no opaque native receipt or Connection proof is fabricated here.
        link.entry.unknown();
        assert_eq!(status(&inbox, &input).progress.state, p::State::Unknown);
        assert!(inbox.start_remote(&start(&input)).is_err());
    }
    let (_doc, inbox, input) = setup(true);
    let (claim, link) = claim(&inbox, &input);
    claim.returned(Ok(()));
    link.retired(OperationState::Succeeded);
    link.remote_connection_returned(candidate(true), None)
        .unwrap();
    inbox.start_remote(&start(&input)).unwrap();
    let mut claim = inbox.claim().unwrap().unwrap();
    let apply = claim.link().unwrap();
    apply.arm("git-local-2").unwrap();
    claim.returned(Ok(()));
    apply.retired(OperationState::Failed);
    let contradictory = remote::Outcome {
        operation_id: "git-local-2".into(),
        action: remote::Kind::Push,
        state: remote::EffectState::Succeeded,
        effect_phase: remote::Effect::RemoteReturned,
        retained_paths: vec![],
    };
    assert!(apply
        .remote_connection_returned(None, Some(contradictory))
        .is_err());
    assert!(
        apply
            .entry
            .lock()
            .unwrap()
            .remote
            .as_ref()
            .unwrap()
            .connection_returned
    );
    apply.entry.unknown();
    assert!(status(&inbox, &input).result.is_none());
    assert_eq!(status(&inbox, &input).progress.state, p::State::Unknown);
}
#[test]
fn cross_family_foreign_ids_and_duplicate_body_cannot_select_a_remote_or_another_apply() {
    let (_doc, inbox, input) = setup(false);
    inbox.prepare_remote(input.clone()).unwrap();
    assert!(inbox.prepare(input.clone()).is_err());
    assert!(inbox.prepare_commit(input.clone()).is_err());
    assert!(inbox.prepare_repository(input.clone()).is_err());
    let first = status(&inbox, &input);
    assert_eq!(inbox.prepare_remote(input.clone()).unwrap(), first);
    let mut other = input.clone();
    other.grant_id = id('e');
    assert!(inbox.prepare_remote(other).is_err());
    let rows = inbox.catalogue_requests(&id('b'), &id('a')).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].family,
        crate::service_request_catalogue::AdditionalFamily::GitRemote
    );
    assert!(inbox
        .catalogue_requests(&id('b'), &id('e'))
        .unwrap()
        .is_empty());
    let mut claim = inbox.claim().unwrap().unwrap();
    let link = claim.link().unwrap();
    link.arm("git-local-1").unwrap();
    claim.returned(Ok(()));
    link.retired(OperationState::Succeeded);
    let mut c = candidate(false).unwrap();
    if let remote::Preview::Fetch {
        expected_target,
        candidate_ref_oid,
        ..
    } = &mut c.0.preview
    {
        *expected_target = Some(candidate_ref_oid.clone());
    }
    link.remote_connection_returned(Some(c), None).unwrap();
    assert!(status(&inbox, &input).progress.review.is_some());
    assert!(inbox.start_remote(&start(&input)).is_err());
    link.review_removed();
    assert_eq!(
        status(&inbox, &input).progress.settlement,
        Settlement::Settled
    );
}
#[test]
fn ordinary_local_family_keeps_its_original_finality_and_has_no_remote_finish_capability() {
    let doc = Arc::new(());
    let inbox = Inbox::new(id('b'));
    let mut s = scope(&doc, false);
    let s = Arc::get_mut(&mut s).unwrap();
    s.selection = p::Selection::new(p::Action::Stage, "a".repeat(64), vec!["app/file".into()])
        .unwrap()
        .into();
    let local = Arc::new(NativeScope {
        project_id: s.project_id.clone(),
        runtime_id: s.runtime_id.clone(),
        root: s.root.clone(),
        device: s.device,
        inode: s.inode,
        registration: s.registration,
        document_revision: s.document_revision,
        input_revision: s.input_revision,
        read_operation_id: s.read_operation_id.clone(),
        document: s.document.clone(),
        selection: s.selection.clone(),
        commit: None,
        changes: s.changes.clone(),
    });
    let grant = inbox.allow(local).unwrap().grant_id.unwrap();
    let input = p::Prepare {
        origin: p::Query {
            project_id: id('a'),
            service_instance: id('b'),
            request_id: id('c'),
        },
        grant_id: grant,
    };
    inbox.prepare(input.clone()).unwrap();
    let mut claim = inbox.claim().unwrap().unwrap();
    let link = claim.link().unwrap();
    link.arm("git-local-1").unwrap();
    claim.returned(Ok(()));
    assert!(!link.is_remote());
    assert!(link
        .remote_connection_returned(candidate(false), None)
        .is_err());
    link.retired(OperationState::Failed);
    assert_eq!(
        inbox.query(&input.origin, false).unwrap().settlement,
        Settlement::Settled
    );
}
