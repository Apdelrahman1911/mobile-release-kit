//! Actual shared Inbox/READ/history methods using the existing Store DATA fixture.
//! Deliberately no Saved invocation, Keychain, local journal, or native receipt proof.
use super::*;
use crate::{service_local_history_protocol as h, service_store_requests::history as queue};
fn selected() -> h::Review {
    h::Review {
        kind: h::Kind::Verify,
        operation_id: id('a'),
        owner_generation: id('b'),
        status_revision: 3,
        platform: None,
        candidate_operation_id: None,
    }
}
fn scope(f: &Fixture) -> Arc<queue::Scope> {
    Arc::new(queue::Scope {
        project_id: id('1'),
        runtime_id: "p1".into(),
        review_id: id('4'),
        review: selected(),
        root: "/inert/never-opened".into(),
        device: 1,
        inode: 2,
        observation_revision: 0,
        expires: f.scope.expires,
        read: f.scope.read.clone(),
        document: Arc::downgrade(&f.doc),
        witness: Arc::downgrade(&f.witness),
        control: Control::new(),
        retired: AtomicBool::new(false),
        changes: tokio::sync::watch::channel(0).0,
    })
}
fn report() -> h::Report {
    h::Report {
        enrolled: true,
        head_sequence: 1,
        history: vec![],
        candidate_inputs: None,
        limitations: h::LIMITATIONS,
    }
}
fn final_data() -> queue::NativeData {
    queue::NativeData {
        operation: h::Operation {
            operation_id: id('a'),
            owner_generation: id('b'),
            status_revision: 5,
        },
        state: OperationState::Succeeded,
        reason: h::Reason::None,
        outcome: Some(h::Outcome::Complete),
        result: Some(report()),
        retired: true,
    }
}
fn enter(f: &Fixture) -> (Arc<queue::Entry>, queue::Claim) {
    f.inbox.allow_history(scope(f), id('3')).unwrap();
    f.inbox.submit_history(f.input(), Instant::now()).unwrap();
    (
        f.inbox.history_entries().unwrap()[0].clone(),
        f.inbox.claim_local_history().unwrap().unwrap(),
    )
}
#[test]
fn local_history_triple_returns_and_progress_ack_never_settle_early() {
    for native_first in [false, true] {
        let f = Fixture::new();
        let (e, c) = enter(&f);
        let mut n = final_data();
        n.operation.status_revision = 4;
        n.state = OperationState::Running;
        n.result = None;
        n.retired = false;
        n.outcome = None;
        e.native(n);
        let progress = e.claim_history().unwrap().unwrap();
        if native_first {
            e.native(final_data());
            assert!(e.pending());
        }
        c.returned();
        if !native_first {
            e.native(final_data());
        }
        progress.returned(Ok(())).unwrap();
        assert!(e.pending());
        assert_eq!(e.status().unwrap().state, h::State::Finishing);
        assert!(e.status().unwrap().result.is_none());
        let final_history = e.claim_history().unwrap().unwrap();
        assert!(e.pending());
        final_history.returned(Ok(())).unwrap();
        assert!(!e.pending());
        let a = f.inbox.history_access().unwrap();
        a.validate().unwrap();
        assert!(a.consumed && !a.pending && !a.enabled);
        assert_eq!(a.status.unwrap().result, Some(report()));
    }
}
#[test]
fn local_history_lost_caller_writer_or_invalid_native_retains_unknown() {
    for cut in 0..4 {
        let f = Fixture::new();
        let (e, c) = enter(&f);
        e.native(final_data());
        if cut == 0 {
            drop(c);
        } else {
            c.returned();
            let history = e.claim_history().unwrap().unwrap();
            if cut == 1 {
                drop(history);
            } else if cut == 2 {
                assert!(history.returned(Err(Error::Unavailable)).is_err());
            } else {
                history.returned(Ok(())).unwrap();
                let mut changed = final_data();
                changed.operation.owner_generation = id('c');
                e.native(changed);
            }
        }
        e.native(final_data());
        assert!(e.pending());
        assert_eq!(e.status().unwrap().state, h::State::Unknown);
        assert!(f.inbox.can_allow_history().is_err());
        assert!(f.inbox.can_allow().is_err());
        assert!(e.claim_history().unwrap().is_none());
    }
}
#[test]
fn local_history_same_request_reconnect_is_not_replay_and_exact_query_is_retained() {
    let f = Fixture::new();
    let (e, c) = enter(&f);
    assert_eq!(
        f.inbox
            .submit_history(f.input(), Instant::now())
            .unwrap()
            .origin,
        *e.origin()
    );
    assert!(f.inbox.claim_local_history().unwrap().is_none());
    for field in 0..3 {
        let mut i = f.input();
        match field {
            0 => i.origin.project_id = id('6'),
            1 => i.origin.service_instance = id('6'),
            _ => i.review_id = id('6'),
        };
        assert!(f.inbox.submit_history(i, Instant::now()).is_err());
    }
    assert!(f.inbox.submit(f.input(), Instant::now()).is_err());
    assert!(f.inbox.query(&f.input().origin, false).is_err());
    let mut wrong = f.input().origin;
    wrong.project_id = id('6');
    assert!(f.inbox.query_history(&wrong, false).is_err());
    f.inbox.query_history(e.origin(), true).unwrap();
    assert!(e.stop_at(Instant::now()).is_some());
    c.returned();
    let mut n = final_data();
    n.state = OperationState::Cancelled;
    n.reason = h::Reason::UserCancelled;
    n.outcome = Some(h::Outcome::Cancelled);
    n.result = None;
    e.native(n);
    e.claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    assert_eq!(
        f.inbox.query_history(e.origin(), false).unwrap().state,
        h::State::Cancelled
    );
    assert!(f.inbox.claim_local_history().unwrap().is_none());
    f.inbox.close(Instant::now());
    assert!(f.inbox.query_history(e.origin(), false).is_err());
}
#[test]
fn local_history_read_stop_and_weak_context_keep_earliest_cut_no_saved_config() {
    let f = Fixture::new();
    let s = scope(&f);
    let at = Instant::now();
    let point = crate::agent_identity_requests::SavedPoint {
        project_id: id('1'),
        runtime_id: "p1".into(),
        root: s.root.clone(),
        device: 1,
        inode: 2,
        revision: 0,
        fresh: false,
    };
    assert!(s.matches(&point));
    f.scope.read.revoke(at);
    assert!(s.current(false, at + Duration::from_secs(3)).is_err());
    s.control
        .stop(h::Reason::UserCancelled, at + Duration::from_secs(2));
    assert_eq!(
        s.control.first().unwrap(),
        Some((h::Reason::PermissionRevoked, at))
    );
    let f = Fixture::new();
    let s = scope(&f);
    drop(f.witness);
    assert!(s.current(false, Instant::now()).is_err());
    assert_eq!(
        s.control.first().unwrap().unwrap().0,
        h::Reason::ContextChanged
    );
    let f = Fixture::new();
    let s = scope(&f);
    assert!(s.current(false, s.expires).is_err());
    assert_eq!(
        s.control.first().unwrap(),
        Some((h::Reason::Expired, s.expires))
    );
    assert!(!s.retired.load(Ordering::Acquire));
}
#[test]
fn local_history_shared32_and_discovery_use_one_namespace_without_reading_or_expiring_rows() {
    use crate::service_request_catalogue as cat;
    let f = Fixture::new();
    for index in 1..=32 {
        let mut input = f.input();
        input.origin.request_id = Id::parse(&format!("{index:032x}")).unwrap();
        if index % 2 == 0 {
            f.inbox.allow_history(scope(&f), id('3')).unwrap();
            f.inbox.submit_history(input, Instant::now()).unwrap();
            let c = f.inbox.claim_local_history().unwrap().unwrap();
            let e = c.entry().clone();
            c.returned();
            e.native(final_data());
            e.claim_history()
                .unwrap()
                .unwrap()
                .returned(Ok(()))
                .unwrap();
        } else {
            f.inbox
                .allow(Fixture::scope(&f.doc, &f.witness), id('3'))
                .unwrap();
            f.inbox.submit(input, Instant::now()).unwrap();
            let c = f.inbox.claim().unwrap().unwrap();
            let e = c.entry().clone();
            c.returned();
            e.native(f.finished());
            e.claim_history()
                .unwrap()
                .unwrap()
                .returned(Ok(()))
                .unwrap();
        }
    }
    assert!(f.inbox.can_allow_history().is_err());
    assert!(f.inbox.can_allow().is_err());
    let rows = f.inbox.catalogue_requests(&id('2'), &id('1')).unwrap();
    assert_eq!(rows.len(), 32);
    assert_eq!(
        rows.iter()
            .filter(|r| r.family == cat::AdditionalFamily::LocalHistory)
            .count(),
        16
    );
    assert!(f
        .inbox
        .catalogue_requests(&id('2'), &id('9'))
        .unwrap()
        .is_empty());
    assert!(f.inbox.catalogue_requests(&id('9'), &id('1')).is_err());
    let mut view = cat::Catalogue {
        schema_version: 2,
        scope: cat::Scope::CurrentHostRetainedRequests,
        sampling: cat::Sampling::PerRequestNotAtomic,
        service_instance: id('2'),
        project_id: id('1'),
        do_not_replay: true,
        requests: vec![],
        additional_requests: Some(rows),
    };
    view.validate().unwrap();
    let human = cat::human(&view);
    assert!(human.contains("mrk local-history-status"));
    assert!(human.contains("mrk store-status"));
    view.additional_requests
        .as_mut()
        .unwrap()
        .push(cat::AdditionalRequest {
            family: cat::AdditionalFamily::LocalHistory,
            request_id: id('9'),
        });
    assert!(view.validate().is_err());
    view.additional_requests.as_mut().unwrap().pop();
    let duplicate = view.additional_requests.as_ref().unwrap()[0]
        .request_id
        .clone();
    view.additional_requests.as_mut().unwrap()[1].request_id = duplicate;
    assert!(view.validate().is_err());
    // Enumeration is immutable input DATA even for an unclaimed/revoked original.
    let f = Fixture::new();
    f.inbox.allow_history(scope(&f), id('3')).unwrap();
    f.inbox.submit_history(f.input(), Instant::now()).unwrap();
    let e = f.inbox.history_entries().unwrap().remove(0);
    f.scope.read.revoke(Instant::now());
    let before = e.scope().control.first().unwrap();
    assert!(before.is_none());
    f.inbox.catalogue_requests(&id('2'), &id('1')).unwrap();
    assert_eq!(e.scope().control.first().unwrap(), before);
    assert!(e.pending());
}
#[test]
fn local_history_and_existing_store_preparation_exclude_only_live_originals() {
    let f = Fixture::new();
    let (e, c) = enter(&f);
    assert!(f.inbox.allow(f.scope.clone(), id('6')).is_err());
    let selected = crate::service_store_prepare_protocol::Selection {
        kind: crate::service_store_prepare_protocol::Kind::AndroidAccess,
        saved_config: review().saved_config,
        saved_version: review().saved_version,
        candidate: None,
        later: None,
        execute: None,
    };
    let ps = crate::service_store_requests::preparation::Scope::new(
        id('1'),
        "p1".into(),
        id('4'),
        selected,
        f.scope.root.clone(),
        1,
        2,
        1,
        f.scope.expires,
        f.scope.read.clone(),
        Arc::downgrade(&f.doc),
        Arc::downgrade(&f.witness),
        tokio::sync::watch::channel(0).0,
    );
    assert!(f.inbox.allow_preparation(ps.clone(), id('6')).is_err());
    c.returned();
    e.native(final_data());
    e.claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    assert!(f.inbox.allow_preparation(ps, id('6')).is_ok());
    assert!(f.inbox.can_allow_history().is_err());
}
#[test]
fn local_history_quote_keeps_entire_old_store_debit_and_shared_eight_peak() {
    assert_eq!(
        queue::retained_document_backing(),
        Some(p::DOCUMENT_BACKING)
    );
    assert_eq!(p::DOCUMENT_BACKING, 2 * 1024 * 1024);
    assert!(
        queue::IPC_WORKER_BACKING
            >= h::STATUS_LIMIT
                + 2 * (std::mem::size_of::<h::Access>() + std::mem::size_of::<h::Status>() + 8192)
    );
    let f = Fixture::new();
    let (e, c) = enter(&f);
    c.returned();
    e.native(final_data());
    e.claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    let access = f.inbox.history_access().unwrap();
    let response = crate::service_protocol::Response {
        version: 1,
        request_id: id('8'),
        service_instance: id('2'),
        client_id: id('6'),
        session_id: id('7'),
        response: crate::service_protocol::ResponseBody::LocalHistoryAccess(Box::new(access)),
    };
    assert!(
        crate::service_protocol::encode_response(&response)
            .unwrap()
            .len()
            <= h::STATUS_LIMIT
    );
}
