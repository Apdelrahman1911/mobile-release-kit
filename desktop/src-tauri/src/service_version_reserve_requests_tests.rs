//! Inert metadata/consent tests. No native Review, Source, Store or finality
//! receipts are manufactured; final snapshots below are explicitly DATA.
use super::*;
pub(crate) fn id(n: u32) -> Id {
    Id::parse(&format!("{n:032x}")).unwrap()
}
pub(crate) struct Rig {
    pub(crate) inbox: Arc<Inbox>,
    pub(crate) scope: Arc<NativeScope>,
    pub(crate) doc: Arc<()>,
    pub(crate) review: Arc<()>,
    pub(crate) input: p::Submit,
}
impl Rig {
    pub(crate) fn new() -> Self {
        let (doc, review) = (Arc::new(()), Arc::new(()));
        let now = Instant::now();
        let scope = Arc::new(NativeScope {
            project_id: id(2),
            runtime_id: "project-1".into(),
            review_id: id(3),
            review_revision: 1,
            review_end: now + Duration::from_secs(110),
            read: Arc::new(ReadPermission::new(now + Duration::from_secs(120))),
            document: Arc::downgrade(&doc),
            review: Arc::downgrade(&review),
            changes: tokio::sync::watch::channel(0).0,
        });
        let inbox = Arc::new(Inbox::new(id(1)));
        let input = p::Submit {
            origin: p::Query {
                project_id: id(2),
                service_instance: id(1),
                request_id: id(5),
            },
            grant_id: id(4),
            review_id: id(3),
        };
        Self {
            inbox,
            scope,
            doc,
            review,
            input,
        }
    }
    pub(crate) fn allowed(&self) {
        self.inbox
            .allow(self.scope.clone(), self.input.grant_id.clone())
            .unwrap();
    }
    pub(crate) fn claim(&self) -> Claim {
        self.allowed();
        self.inbox.submit(self.input.clone()).unwrap();
        self.inbox.claim().unwrap().unwrap()
    }
}
fn data() -> Final {
    Final::Reserved(p::Reservation {
        candidate_id: "12345678-1234-4234-9234-123456789abc".into(),
        name: "1.2.3".into(),
        build: 7,
        ci: None,
    })
}
#[test]
fn no_grant_no_claim_and_allow_refusals_do_not_insert_a_new_grant() {
    let r = Rig::new();
    assert_eq!(
        r.inbox.submit(r.input.clone()).unwrap_err(),
        Error::AccessDenied
    );
    assert!(r.inbox.claim().unwrap().is_none());
    assert_eq!(r.inbox.access().unwrap(), p::Access::empty());
    r.allowed();
    let before = r.inbox.access().unwrap();
    let mut invalid = Rig::new();
    Arc::get_mut(&mut invalid.scope).unwrap().review_revision = 0;
    assert_eq!(
        r.inbox.allow(invalid.scope, id(99)).unwrap_err(),
        Error::Conflict
    );
    assert_eq!(r.inbox.access().unwrap().grant_id, before.grant_id);
    r.inbox.submit(r.input.clone()).unwrap();
    assert_eq!(
        r.inbox.allow(r.scope.clone(), id(99)).unwrap_err(),
        Error::Busy
    );
    assert_eq!(r.inbox.access().unwrap().grant_id, before.grant_id);
}
#[test]
fn equal_retry_observes_original_and_changed_body_cannot_replay() {
    let r = Rig::new();
    let mut claim = r.claim();
    let first = r.inbox.query(&r.input.origin, false).unwrap();
    assert_eq!(r.inbox.submit(r.input.clone()).unwrap(), first);
    let mut changed = r.input.clone();
    changed.review_id = id(88);
    assert_eq!(r.inbox.submit(changed).unwrap_err(), Error::Conflict);
    assert!(r.inbox.claim().unwrap().is_none());
    claim.not_admitted(Error::Busy).unwrap();
    claim.entry().continuation_joined(true);
    let final_row = claim.entry().status().unwrap();
    assert_eq!(final_row.state, p::State::Refused);
    r.inbox.close(Instant::now());
    assert_eq!(r.inbox.submit(r.input.clone()).unwrap(), final_row);
    assert_eq!(r.inbox.book.lock().unwrap().entries.len(), 1);
}
#[test]
fn original_id_is_installed_once_and_data_waits_for_actual_continuation_join() {
    let r = Rig::new();
    let mut claim = r.claim();
    assert!(claim.link().arm(id(6).as_str()).unwrap());
    assert_eq!(claim.entry().status().unwrap().operation_id, Some(id(6)));
    assert!(claim.link().arm(id(7).as_str()).is_err());
    claim.native_returned(id(6).as_str(), data()).unwrap();
    let pending = claim.entry().status().unwrap();
    assert_eq!(pending.state, p::State::Finishing);
    assert_eq!(pending.settlement, Settlement::Pending);
    assert!(claim.entry().completed_operation().unwrap().is_none());
    claim.entry().continuation_joined(true);
    let final_row = claim.entry().status().unwrap();
    assert_eq!(final_row.state, p::State::Reserved);
    assert_eq!(claim.entry().completed_operation().unwrap(), Some(id(6)));
    r.inbox
        .revoke(p::Reason::PermissionRevoked, Instant::now())
        .unwrap();
    assert_eq!(claim.entry().status().unwrap(), final_row); // Later status/STOP never rewrites this row.
    assert!(claim.entry().row.lock().unwrap().lease.is_none());
}
#[test]
fn loss_unknown_and_join_error_are_absorbing_without_rearm() {
    for armed in [false, true] {
        let r = Rig::new();
        let claim = r.claim();
        let entry = claim.entry().clone();
        if armed {
            claim.link().arm(id(6).as_str()).unwrap();
        }
        drop(claim);
        let unknown = entry.status().unwrap();
        assert_eq!(unknown.state, p::State::Unknown);
        entry.continuation_joined(true);
        entry.cancel(p::Reason::UserCancelled, Instant::now());
        assert_eq!(entry.status().unwrap(), unknown);
        assert!(entry.pending());
        assert_eq!(r.inbox.submit(r.input.clone()).unwrap(), unknown);
        assert_eq!(
            r.inbox.allow(r.scope.clone(), id(99)).unwrap_err(),
            Error::Busy
        );
    }
}
#[test]
fn revoke_before_claim_never_registers_a_continuation_and_keeps_original_request() {
    let r = Rig::new();
    r.allowed();
    r.inbox.submit(r.input.clone()).unwrap();
    r.inbox
        .revoke(p::Reason::PermissionRevoked, Instant::now())
        .unwrap();
    assert!(r.inbox.claim().unwrap().is_none());
    let row = r.inbox.query(&r.input.origin, false).unwrap();
    assert_eq!(row.state, p::State::Cancelled);
    assert_eq!(row.operation_id, None);
    assert_eq!(row.settlement, Settlement::Settled);
    assert!(r.inbox.access().unwrap().consumed);
}
#[test]
fn cancelled_claim_keeps_pending_until_returned_and_joined() {
    let r = Rig::new();
    let mut claim = r.claim();
    r.inbox.query(&r.input.origin, true).unwrap();
    assert!(claim.entry().pending());
    claim.not_admitted(Error::Conflict).unwrap();
    assert!(claim.entry().pending());
    claim.entry().continuation_joined(true);
    let row = claim.entry().status().unwrap();
    assert_eq!(row.state, p::State::Cancelled);
    assert_eq!(row.reason, Some(p::Reason::UserCancelled));
    assert!(row.operation_id.is_none());
    assert!(claim.entry().completed_operation().unwrap().is_none());
}
#[test]
fn prearm_earliest_review_or_read_stop_wins_delayed_observation() {
    for review_earlier in [true, false] {
        let mut r = Rig::new();
        let now = Instant::now();
        let scope = Arc::get_mut(&mut r.scope).unwrap();
        scope.review_end = now + Duration::from_secs(if review_earlier { 20 } else { 100 });
        let mut claim = r.claim();
        r.scope.read.revoke(now + Duration::from_secs(50));
        claim.entry().expire(now + Duration::from_secs(101));
        let (reason, at) = claim.entry().first_stop().unwrap().unwrap();
        assert_eq!(
            at,
            now + Duration::from_secs(if review_earlier { 20 } else { 50 })
        );
        assert_eq!(
            reason,
            if review_earlier {
                p::Reason::Expired
            } else {
                p::Reason::PermissionRevoked
            }
        );
        claim
            .entry()
            .cancel(p::Reason::UserCancelled, now + Duration::from_secs(110));
        assert_eq!(claim.entry().first_stop().unwrap().unwrap().1, at);
        claim.not_admitted(Error::Expired).unwrap();
        claim.entry().continuation_joined(true);
    }
}
#[test]
fn admitted_native_does_not_reuse_review_expiry_but_read_revocation_still_stops() {
    let r = Rig::new();
    let claim = r.claim();
    claim.link().arm(id(6).as_str()).unwrap();
    claim
        .entry()
        .expire(r.scope.review_end + Duration::from_millis(1));
    assert!(claim.entry().first_stop().unwrap().is_none());
    let revoke = Instant::now();
    r.scope.read.revoke(revoke);
    claim.entry().expire(revoke);
    assert_eq!(
        claim.entry().first_stop().unwrap(),
        Some((p::Reason::PermissionRevoked, revoke))
    );
}
#[test]
fn revoke_after_native_result_before_join_never_advertises_completion() {
    let r = Rig::new();
    let mut claim = r.claim();
    claim.link().arm(id(6).as_str()).unwrap();
    claim.native_returned(id(6).as_str(), data()).unwrap();
    r.scope.read.revoke(Instant::now());
    claim.entry().continuation_joined(true);
    assert_eq!(claim.entry().status().unwrap().state, p::State::Cancelled);
    assert!(claim.entry().completed_operation().unwrap().is_none());
}
#[test]
fn read_facets_are_shared_not_renewed_or_revoked_by_arc_drop() {
    let end = Instant::now() + Duration::from_secs(10);
    let read = Arc::new(ReadPermission::new(end));
    drop(read.clone());
    assert!(read.stop(Instant::now()).unwrap().is_none());
    let at = Instant::now();
    read.revoke(at);
    read.revoke(at + Duration::from_secs(1));
    assert_eq!(
        read.stop(at).unwrap(),
        Some((p::Reason::PermissionRevoked, at))
    );
    let only_expiry = ReadPermission::new(end);
    assert_eq!(
        only_expiry.stop(end).unwrap(),
        Some((p::Reason::Expired, end))
    );
}
#[test]
fn foreign_origin_replaced_grant_and_dead_review_are_not_permission() {
    let r = Rig::new();
    r.allowed();
    r.inbox
        .revoke(p::Reason::PermissionRevoked, Instant::now())
        .unwrap();
    r.inbox.allow(r.scope.clone(), id(99)).unwrap();
    assert_eq!(
        r.inbox.submit(r.input.clone()).unwrap_err(),
        Error::AccessDenied
    );
    let mut right = r.input.clone();
    right.grant_id = id(99);
    for change in [0, 1, 2] {
        let mut wrong = right.clone();
        match change {
            0 => wrong.origin.project_id = id(88),
            1 => wrong.origin.service_instance = id(88),
            _ => wrong.review_id = id(88),
        };
        assert!(r.inbox.submit(wrong).is_err());
    }
    drop(r.review);
    assert_eq!(r.inbox.submit(right).unwrap_err(), Error::AccessDenied);
}
#[test]
fn thirty_two_tombstones_keep_metadata_without_thirty_two_originals() {
    let r = Rig::new();
    for n in 0..p::REQUEST_LIMIT {
        let grant = id(100 + n as u32);
        r.inbox.allow(r.scope.clone(), grant.clone()).unwrap();
        let mut input = r.input.clone();
        input.grant_id = grant;
        input.origin.request_id = id(200 + n as u32);
        r.inbox.submit(input.clone()).unwrap();
        let mut claim = r.inbox.claim().unwrap().unwrap();
        claim.not_admitted(Error::Busy).unwrap();
        claim.entry().continuation_joined(true);
    }
    assert_eq!(
        r.inbox.allow(r.scope.clone(), id(999)).unwrap_err(),
        Error::Busy
    );
    let book = r.inbox.book.lock().unwrap();
    assert_eq!(book.entries.len(), p::REQUEST_LIMIT);
    assert!(book
        .entries
        .iter()
        .all(|e| e.row.lock().unwrap().lease.is_none()));
    assert!(Arc::strong_count(&r.scope) <= 3); // Rig + one current lease; no per-row Source/Lane.
}

#[test]
fn read_publication_rejects_changed_closed_failed_or_overflowed_epoch_without_rebinding() {
    // This tests only the weak comparison slot. The actual Service constructs
    // and drops its original Grant, covered by the real-Service test child.
    for mode in ["revoked", "closed", "failed", "overflow"] {
        let inbox = Inbox::new(id(1));
        let end = Instant::now() + Duration::from_secs(120);
        let original = Arc::new(ReadPermission::new(end));
        let epoch = inbox.read_permission_epoch().unwrap();
        inbox.publish_read_permission(&original, epoch).unwrap();
        assert_eq!(Arc::strong_count(&original), 1); // Only Weak, not a second Grant.
        let before = Instant::now();
        let expected = match mode {
            "revoked" => {
                inbox.read_revoked(before); // No Reserve lease exists yet.
                assert!(inbox.read_permission_epoch().unwrap() > epoch);
                assert_eq!(
                    original.stop(before).unwrap(),
                    Some((p::Reason::PermissionRevoked, before))
                );
                Error::Conflict
            }
            "closed" => {
                inbox.close(before);
                Error::Unavailable
            }
            "failed" => {
                inbox.fence();
                Error::StateUnknown
            }
            "overflow" => {
                inbox.book.lock().unwrap().read_epoch = u64::MAX - 1;
                inbox.read_revoked(before);
                assert_eq!(
                    original.stop(before).unwrap(),
                    Some((p::Reason::PermissionRevoked, before))
                );
                Error::StateUnknown
            }
            _ => unreachable!(),
        };
        let uninstalled = Arc::new(ReadPermission::new(end));
        let weak = Arc::downgrade(&uninstalled);
        assert_eq!(
            inbox.publish_read_permission(&uninstalled, epoch),
            Err(expected)
        );
        let held = inbox
            .book
            .lock()
            .unwrap()
            .current_read
            .as_ref()
            .unwrap()
            .upgrade()
            .unwrap();
        assert!(Arc::ptr_eq(&held, &original));
        assert_eq!(Arc::strong_count(&uninstalled), 1);
        drop(uninstalled);
        assert!(weak.upgrade().is_none());
        if mode != "revoked" {
            assert!(inbox.read_permission_epoch().is_err());
        }
    }
}
