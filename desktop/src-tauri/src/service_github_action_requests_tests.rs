//! Pure metadata/real mutex tests. No native receipts, timers, filesystem or IO.
use super::*;
use std::time::Duration;
fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
struct F {
    inbox: Inbox,
    scope: Arc<NativeScope>,
    _doc: Arc<()>,
}
impl F {
    fn new(kind: p::Kind) -> Self {
        let now = Instant::now();
        let doc = Arc::new(());
        let scope = NativeScope::new(
            id('1'),
            "project-1".into(),
            "/fixed-inert-project".into(),
            1,
            2,
            3,
            if kind == p::Kind::SetupReconcile { p::Review::SetupReconcile(p::PendingReference {
                session_id: "github-connection-1".into(), expected_revision: 4,
                marker: "a".repeat(32), record_sha256: "b".repeat(64),
            }) } else {
            p::Review::from_prepared(kind, p::PreparedReference {
                session_id: "github-connection-1".into(),
                consent_id: "a".repeat(32),
                expected_revision: 4,
                prepared_sha256: "b".repeat(64),
            }).unwrap()
            },
            Arc::new(()),
            now + Duration::from_secs(100),
            Arc::new(
                crate::service_version_reserve_requests::ReadPermission::new(
                    now + Duration::from_secs(110),
                ),
            ),
            Arc::downgrade(&doc),
            tokio::sync::watch::channel(1).0,
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
    fn arm(&self, e: &Entry) -> String {
        let op = format!("{}1", self.scope.review.kind().prefix());
        e.entering().unwrap();
        e.arm(&op).unwrap();
        op
    }
}
#[test]
fn three_kinds_require_caller_native_and_same_history_in_either_order() {
    for kind in [
        p::Kind::RepositoryCreate,
        p::Kind::DraftPrCreate,
        p::Kind::PrCreate,
        p::Kind::FailedJobsRetry,
    ] {
        for native_first in [false, true] {
            let f = F::new(kind);
            let c = f.claim();
            let e = c.entry().clone();
            let op = f.arm(&e);
            let effect = if kind == p::Kind::FailedJobsRetry {
                p::Effect::Accepted
            } else {
                p::Effect::CreatedObserved
            };
            if native_first {
                e.returned_native(&op, p::Reason::None, effect);
                assert!(e.claim_history().unwrap().is_none());
            }
            c.returned(Ok(()));
            if !native_first {
                assert!(e.pending());
                e.returned_native(&op, p::Reason::None, effect)
            }
            assert_eq!(e.status().unwrap().state, p::State::Finishing);
            let h = e.claim_history().unwrap().unwrap();
            assert!(e.pending());
            h.returned(Ok(())).unwrap();
            assert_eq!(e.status().unwrap().state, p::State::Complete);
            assert!(!e.pending());
        }
    }
}
#[test]
fn known_pre_registration_refusal_has_no_native_receipt() {
    let f = F::new(p::Kind::RepositoryCreate);
    let c = f.claim();
    let e = c.entry().clone();
    c.returned(Err(p::Reason::ContextChanged));
    assert!(e.status().unwrap().operation_id.is_none());
    assert!(e.status().unwrap().never_admitted);
    assert!(e.pending());
    e.claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    assert_eq!(e.status().unwrap().settlement, Settlement::Settled);
}
#[test]
fn entered_failure_or_lost_caller_is_unknown_not_never_admitted() {
    for entered in [true, false] {
        let f = F::new(p::Kind::RepositoryCreate);
        let c = f.claim();
        let e = c.entry().clone();
        if entered {
            e.entering().unwrap();
            c.returned(Err(p::Reason::NativeRefused))
        } else {
            drop(c)
        }
        assert_eq!(e.status().unwrap().state, p::State::Unknown);
        assert!(!e.status().unwrap().never_admitted);
        assert!(e.pending());
    }
}
#[test]
fn progress_history_ack_cannot_settle_later_final() {
    let f = F::new(p::Kind::DraftPrCreate);
    let c = f.claim();
    let e = c.entry().clone();
    let op = f.arm(&e);
    let progress = e.claim_history().unwrap().unwrap();
    e.returned_native(&op, p::Reason::None, p::Effect::CreatedObserved);
    c.returned(Ok(()));
    progress.returned(Ok(())).unwrap();
    assert!(e.pending());
    e.claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    assert!(!e.pending());
}
#[test]
fn history_failure_and_drop_are_absorbing_even_after_native_return() {
    for dropped in [false, true] {
        let f = F::new(p::Kind::FailedJobsRetry);
        let c = f.claim();
        let e = c.entry().clone();
        let op = f.arm(&e);
        e.returned_native(&op, p::Reason::None, p::Effect::Accepted);
        c.returned(Ok(()));
        let h = e.claim_history().unwrap().unwrap();
        if dropped {
            drop(h)
        } else {
            assert_eq!(h.returned(Err(Error::Unavailable)), Err(Error::Unavailable));
        }
        assert_eq!(e.status().unwrap().state, p::State::Unknown);
        e.returned_native(&op, p::Reason::None, p::Effect::Accepted);
        assert_eq!(e.status().unwrap().state, p::State::Unknown);
        assert!(e.claim_history().unwrap().is_none());
    }
}
#[test]
fn same_id_reconnect_is_not_a_second_submit_or_claim() {
    let f = F::new(p::Kind::RepositoryCreate);
    let input = f.input();
    f.inbox.submit(input.clone()).unwrap();
    let c = f.inbox.claim().unwrap().unwrap();
    assert!(f.inbox.submit(input.clone()).is_ok());
    assert!(f.inbox.claim().unwrap().is_none());
    let mut changed = input;
    changed.grant_id = id('5');
    assert_eq!(f.inbox.submit(changed).err(), Some(Error::Conflict));
    drop(c);
}
#[test]
fn exact_scope_and_service_ids_are_required() {
    let f = F::new(p::Kind::RepositoryCreate);
    for field in 0..3 {
        let mut v = f.input();
        match field {
            0 => v.origin.project_id = id('5'),
            1 => v.origin.service_instance = id('5'),
            _ => v.grant_id = id('5'),
        };
        assert!(f.inbox.submit(v).is_err());
    }
    assert!(f.inbox.submit(f.input()).is_ok());
}
#[test]
fn old_read_revoke_keeps_earlier_failure_after_later_stop() {
    let f = F::new(p::Kind::DraftPrCreate);
    let c = f.claim();
    let e = c.entry();
    f.arm(e);
    let at = Instant::now();
    e.cancel(p::Reason::UserCancelled, at);
    let earlier = at - Duration::from_secs(1);
    f.scope.read.revoke(earlier);
    assert_eq!(e.first_stop(), Some((false, earlier)));
    let replacement =
        crate::service_version_reserve_requests::ReadPermission::new(at + Duration::from_secs(100));
    assert!(replacement.stop(at).unwrap().is_none());
    assert_eq!(e.first_stop(), Some((false, earlier)));
    drop(c);
}
#[test]
fn wrong_kind_id_and_foreign_effect_do_not_supply_completion() {
    let f = F::new(p::Kind::RepositoryCreate);
    let c = f.claim();
    let e = c.entry();
    e.entering().unwrap();
    assert!(e.arm("github-actions-retry-1").is_err());
    e.arm("repository-create-1").unwrap();
    e.returned_native("repository-create-1", p::Reason::None, p::Effect::Accepted);
    assert_eq!(e.status().unwrap().state, p::State::Unknown);
    drop(c);
}
#[test]
fn go_fact_is_monotone_and_does_not_imply_http_success() {
    let f = F::new(p::Kind::RepositoryCreate);
    let c = f.claim();
    let e = c.entry().clone();
    let op = f.arm(&e);
    e.go(&op).unwrap();
    assert!(e.go(&op).is_err());
    assert_eq!(e.status().unwrap().effect, p::Effect::PotentiallyApplied);
    e.returned_native(&op, p::Reason::NativeRefused, p::Effect::NotSent);
    c.returned(Ok(()));
    e.claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    assert_eq!(e.status().unwrap().effect, p::Effect::PotentiallyApplied);
    assert_eq!(e.status().unwrap().state, p::State::Refused);
}
#[test]
fn metadata_census_includes_rows_and_all_eight_worker_copies() {
    use std::mem::size_of;
    assert_eq!(p::REQUEST_LIMIT, 32);
    // Exact fixed payload maxima below are enforced at scope admission. This
    // includes even the old scopes' physical capacity, all ID allocations,
    // two redacted output copies, row/claim/history structs, arc/mutex/allocator
    // headroom and separately the original read-facet cell. No retired credit.
    let scope_payload = 64 + 128 + 8192 + 128 + 64 + 128;
    let output_payload = 4 * 64 + 128 + 64 + 128 + 84;
    let row = scope_payload
        + 4 * 64
        + 2 * output_payload
        + size_of::<Entry>()
        + size_of::<NativeScope>()
        + size_of::<Claim>()
        + size_of::<History>()
        + 2 * size_of::<Fact>()
        + size_of::<crate::service_version_reserve_requests::ReadPermission>()
        + 2 * size_of::<p::Status>()
        + 2048;
    assert!(row <= 16 * 1024, "whole retained row quote: {row}");
    // Input and each of three possible typed/encoded output copies are charged
    // together, including Vec growth and the actual service envelope structs.
    // Fixed MAIN decode is typed and cannot construct arbitrary Value trees.
    let worker = crate::service_protocol::REQUEST_BYTES
        + p::RAW_LIMIT
        + size_of::<crate::service_protocol::Request>()
        + size_of::<crate::service_protocol::Response>()
        + 3 * (size_of::<p::Status>() + output_payload + 2 * p::STATUS_LIMIT)
        + 4096;
    assert!(worker <= 32 * 1024, "whole worker quote: {worker}");
    assert_eq!(retained_document_backing(), Some(p::DOCUMENT_BACKING));
    assert_eq!(p::DOCUMENT_BACKING, 786_432);
    assert_eq!(p::IPC_WORKER_BACKING, 32 * 1024);
    // SAME original worker pool, not8 additional callers per family.
    assert_eq!(p::DOCUMENT_BACKING + 8 * p::IPC_WORKER_BACKING, 1024 * 1024);
}

fn retained_scope(f: &F, kind: p::Kind) -> Arc<NativeScope> {
    let mut runtime = String::with_capacity(128);
    runtime.push_str(&"x".repeat(64));
    let mut root = std::path::PathBuf::with_capacity(8192);
    root.push(format!("/{}", "x".repeat(4095)));
    let mut review = f.scope.review.clone();
    review = p::Review::from_prepared(kind, review.prepared().unwrap().clone()).unwrap();
    review.prepared_mut().unwrap().session_id = String::with_capacity(128);
    review.prepared_mut().unwrap().session_id.push_str(&"s".repeat(64));
    review.prepared_mut().unwrap().consent_id = String::with_capacity(64);
    review.prepared_mut().unwrap().consent_id.push_str(&"a".repeat(32));
    review.prepared_mut().unwrap().prepared_sha256 = String::with_capacity(128);
    review.prepared_mut().unwrap().prepared_sha256.push_str(&"b".repeat(64));
    NativeScope::new(
        id('1'),
        runtime,
        root,
        1,
        2,
        3,
        review,
        Arc::new(()),
        Instant::now() + Duration::from_secs(100),
        f.scope.read.clone(),
        Arc::downgrade(&f._doc),
        f.scope.changes.clone(),
    )
}

#[test]
fn short_metadata_with_overbound_physical_capacity_is_not_admitted() {
    let f = F::new(p::Kind::RepositoryCreate);
    let scope = retained_scope(&f, p::Kind::RepositoryCreate);
    assert!(scope.valid());
    for field in 0..5 {
        let mut scope = retained_scope(&f, p::Kind::RepositoryCreate);
        let s = Arc::get_mut(&mut scope).unwrap();
        match field {
            0 => {
                s.root = std::path::PathBuf::with_capacity(8193);
                s.root.push("/short");
            }
            1 => {
                s.runtime_id = String::with_capacity(129);
                s.runtime_id.push('p');
            }
            2 => {
                s.review.prepared_mut().unwrap().session_id = String::with_capacity(129);
                s.review.prepared_mut().unwrap().session_id.push('s');
            }
            3 => {
                s.review.prepared_mut().unwrap().consent_id = String::with_capacity(65);
                s.review.prepared_mut().unwrap().consent_id.push_str(&"a".repeat(32));
            }
            _ => {
                s.review.prepared_mut().unwrap().prepared_sha256 = String::with_capacity(129);
                s.review.prepared_mut().unwrap().prepared_sha256.push_str(&"b".repeat(64));
            }
        }
        assert!(s.review.valid());
        let inbox = Inbox::new(id('2'));
        assert_eq!(inbox.allow(scope, id('3')).err(), Some(Error::Conflict));
        assert!(inbox.entries().unwrap().is_empty());
    }
}

#[test]
fn one_32_row_pool_retains_old_three_kind_tombstones_and_refuses_the_33rd() {
    let f = F::new(p::Kind::RepositoryCreate);
    for n in 0..p::REQUEST_LIMIT {
        let grant = if n == 0 {
            id('3')
        } else {
            Id::parse(&format!("{:032x}", 100 + n)).unwrap()
        };
        if n != 0 {
            let kind = [
                p::Kind::RepositoryCreate,
                p::Kind::DraftPrCreate,
                p::Kind::PrCreate,
                p::Kind::FailedJobsRetry,
             ][n % 4];
            f.inbox
                .allow(retained_scope(&f, kind), grant.clone())
                .unwrap();
        }
        let mut request = f.input();
        request.origin.request_id = Id::parse(&format!("{:032x}", 1000 + n)).unwrap();
        request.grant_id = grant;
        f.inbox.submit(request).unwrap();
        let caller = f.inbox.claim().unwrap().unwrap();
        let entry = caller.entry().clone();
        caller.returned(Err(p::Reason::NativeRefused));
        entry
            .claim_history()
            .unwrap()
            .unwrap()
            .returned(Ok(()))
            .unwrap();
        assert!(!entry.pending());
    }
    let old = f.inbox.entries().unwrap();
    assert_eq!(old.len(), p::REQUEST_LIMIT);
    assert!(old.iter().all(|e| e.status().unwrap().never_admitted));
    assert_eq!(
        f.inbox
            .allow(retained_scope(&f, p::Kind::PrCreate), id('5'))
            .err(),
        Some(Error::Busy)
    );
    assert_eq!(f.inbox.entries().unwrap().len(), old.len());
    assert!(old
        .iter()
        .zip(f.inbox.entries().unwrap())
        .all(|(a, b)| Arc::ptr_eq(a, &b)));
}
#[test]
fn same_original_stop_advances_once_and_earlier_read_refines_without_finality() {
    let f = F::new(p::Kind::FailedJobsRetry);
    let c = f.claim();
    let e = c.entry();
    f.arm(e);
    let before = e.status().unwrap();
    let now = Instant::now();
    e.cancel(p::Reason::UserCancelled, now);
    let stopped = e.status().unwrap();
    assert!(stopped.revision > before.revision);
    assert_eq!(stopped.reason, p::Reason::UserCancelled);
    assert_eq!(e.status().unwrap(), stopped);
    f.scope.read.revoke(now - Duration::from_millis(1));
    let earlier = e.status().unwrap();
    assert!(earlier.revision > stopped.revision);
    assert_eq!(earlier.reason, p::Reason::PermissionRevoked);
    assert_eq!(earlier.settlement, Settlement::Pending);
    assert!(e.pending());
    drop(c);
}
#[test]
fn exact_document_query_survives_new_lease_without_adopting_another_doc() {
    let f = F::new(p::Kind::RepositoryCreate);
    let c = f.claim();
    let e = c.entry().clone();
    c.returned(Err(p::Reason::NativeRefused));
    e.claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    let new = F::new(p::Kind::DraftPrCreate);
    f.inbox.allow(new.scope.clone(), id('6')).unwrap();
    let q = &f.input().origin;
    assert_eq!(f.inbox.query_for_document(q, &f._doc).unwrap().origin, *q);
    assert_eq!(
        f.inbox.query_for_document(q, &new._doc),
        Err(Error::AccessDenied)
    );
    assert_eq!(
        f.inbox.access().unwrap().review.unwrap().kind(),
        p::Kind::DraftPrCreate
    );
}

#[test]
fn publication_read_go_and_return_stay_read_only_until_original_caller_and_history_return() {
    let f = F::new(p::Kind::SetupReconcile);
    let call = f.claim(); let e = call.entry().clone(); let op = f.arm(&e);
    assert_eq!(e.status().unwrap().effect, p::Effect::None);
    e.go(&op).unwrap();
    assert_eq!(e.status().unwrap().effect, p::Effect::None);
    // This tests the memory transition, not an actual native receipt.
    e.returned_native(&op, p::Reason::None, p::Effect::None);
    assert_eq!(e.status().unwrap().effect, p::Effect::None);
    assert!(e.pending()); assert!(e.claim_history().unwrap().is_none());
    call.returned(Ok(()));
    assert!(e.pending());
    e.claim_history().unwrap().unwrap().returned(Ok(())).unwrap();
    let s = e.status().unwrap();
    assert_eq!(s.state, p::State::Complete); assert_eq!(s.effect, p::Effect::None);
    assert!(!e.pending()); assert!(s.validate().is_ok());
    assert_eq!(f.inbox.submit(f.input()).unwrap(), s); // same original, not replay
}
#[test]
fn publication_impossible_write_effect_and_lost_history_cannot_release_a_read_or_a_write() {
    for kind in [p::Kind::SetupPublish, p::Kind::SetupReconcile] {
        let f = F::new(kind); let call = f.claim(); let e = call.entry().clone(); let op = f.arm(&e);
        e.go(&op).unwrap();
        e.returned_native(&op, p::Reason::None, p::Effect::CreatedObserved);
        call.returned(Ok(()));
        assert_eq!(e.status().unwrap().state, p::State::Unknown); assert!(e.pending());
    }
    let f = F::new(p::Kind::SetupReconcile); let call = f.claim(); let e = call.entry().clone(); let op = f.arm(&e);
    e.returned_native(&op, p::Reason::None, p::Effect::DraftPrObserved); call.returned(Ok(()));
    e.claim_history().unwrap().unwrap().returned(Err(Error::StateUnknown)).unwrap_err();
    assert_eq!(e.status().unwrap().state, p::State::Unknown); assert!(e.pending());
}
#[test]
fn publication_never_admitted_is_not_a_native_return_and_shares_the_same_permission_pool() {
    for kind in [p::Kind::SetupPublish, p::Kind::SetupReconcile] {
        let f=F::new(kind); let call=f.claim(); let e=call.entry().clone();
        assert!(f.inbox.allow(f.scope.clone(), id('5')).is_err());
        call.returned(Err(p::Reason::NativeRefused));
        assert_eq!(e.status().unwrap().effect, kind.initial_effect());
        assert!(e.status().unwrap().never_admitted); assert!(e.pending());
        e.claim_history().unwrap().unwrap().returned(Ok(())).unwrap();
        let s=e.status().unwrap(); assert!(s.never_admitted); assert_eq!(s.operation_id,None);
        assert_eq!(s.effect,kind.initial_effect()); assert!(!e.pending()); assert!(s.validate().is_ok());
    }
}
