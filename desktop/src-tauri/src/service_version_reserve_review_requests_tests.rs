//! Memory rows only; these tests cannot produce a native Review, Source,
//! retirement or grant. Symbolic Weak identities exercise only comparisons.
use super::*;
use crate::service_version_reserve_requests::{
    tests::{id, Rig},
    Inbox,
};
fn input(n: u32) -> p::Request {
    p::Request {
        origin: p::Query {
            project_id: id(2),
            service_instance: id(1),
            request_id: id(n),
        },
        options: p::Options {
            reference: "refs/heads/main".into(),
            increment: p::Increment::Build,
            new_candidate: false,
            acknowledge_limitations: true,
            future_tag: None,
        },
    }
}
fn scope(read: Arc<ReadPermission>) -> Scope {
    Scope {
        saved: SavedPoint {
            project_id: id(2),
            runtime_id: "project-1".into(),
            root: "/inert/no-open".into(),
            device: 1,
            inode: 2,
            revision: 1,
            fresh: true,
        },
        read,
    }
}
fn entry() -> Arc<Entry> {
    Entry::new(
        input(30),
        scope(Arc::new(ReadPermission::new(
            Instant::now() + Duration::from_secs(300),
        ))),
        Instant::now(),
    )
    .unwrap()
}
#[test]
fn source_review_and_reserve_share_the_exact_thirty_two_original_rows() {
    let r = Rig::new();
    r.allowed();
    r.inbox.submit(r.input.clone()).unwrap();
    r.inbox.query(&r.input.origin, true).unwrap();
    for n in 0..31 {
        let q = input(100 + n);
        r.inbox
            .enqueue_review(q.clone(), scope(r.scope.read.clone()), Instant::now())
            .unwrap();
        assert!(r.inbox.review_kind(&q.origin).unwrap());
        r.inbox.review_status(Some(&q.origin), true).unwrap();
    }
    assert_eq!(
        r.inbox
            .enqueue_review(input(300), scope(r.scope.read.clone()), Instant::now())
            .unwrap_err(),
        Error::Busy
    );
    assert_eq!(
        r.inbox.catalogue_requests(&id(1), &id(2)).unwrap().len(),
        32
    );
    assert_eq!(
        r.inbox
            .enqueue_review(input(100), scope(r.scope.read.clone()), Instant::now())
            .unwrap()
            .phase,
        p::Phase::Refused
    );
    let mut changed = input(100);
    changed.options.increment = p::Increment::Major;
    assert_eq!(
        r.inbox
            .enqueue_review(changed, scope(r.scope.read.clone()), Instant::now())
            .unwrap_err(),
        Error::Conflict
    );
    let mut cross = r.input.clone();
    cross.origin = input(100).origin;
    assert_eq!(r.inbox.submit(cross).unwrap_err(), Error::Conflict);
    assert!(!r.inbox.review_kind(&r.input.origin).unwrap());
    assert!(r.inbox.query(&input(100).origin, false).is_err());
}
#[test]
fn review_exception_is_exact_and_a_different_live_lease_never_becomes_read_permission() {
    let r = Rig::new();
    r.allowed();
    assert_eq!(
        r.inbox
            .enqueue_review(input(30), scope(r.scope.read.clone()), Instant::now())
            .unwrap_err(),
        Error::Busy
    );
    let inbox = Inbox::new(id(1));
    inbox
        .enqueue_review(input(30), scope(r.scope.read.clone()), Instant::now())
        .unwrap();
    let original = inbox.review_entry(&input(30).origin).unwrap();
    assert!(inbox.blocks_review().unwrap());
    assert!(!inbox.blocks_review_except(Some(&original)).unwrap());
    assert!(inbox.blocks_review_except(Some(&entry())).unwrap());
    assert!(inbox.claim().unwrap().is_none());
    assert_eq!(inbox.access().unwrap(), reserve::Access::empty());
}
#[test]
fn native_comparison_alone_waits_for_the_original_caller_and_loss_is_absorbing() {
    let e = entry();
    let caller = e.begin().unwrap();
    e.bind(id(7).as_str()).unwrap();
    let identity = Arc::new(());
    e.native_ready(
        id(7).as_str(),
        2,
        &identity,
        Instant::now() + Duration::from_secs(110),
    )
    .unwrap();
    assert_eq!(e.status().unwrap().phase, p::Phase::Finishing);
    assert!(!e.ready_current(&identity, Instant::now()));
    caller.returned().unwrap();
    assert_eq!(e.status().unwrap().phase, p::Phase::ReviewReady);
    assert!(e.ready_current(&identity, Instant::now()));
    e.consume_review(&identity).unwrap();
    e.scope.read.revoke(Instant::now());
    assert_eq!(e.stop_at(Instant::now()).unwrap(), None);
    assert_eq!(e.status().unwrap().remaining_ms, 0);
    let lost = entry();
    let caller = lost.begin().unwrap();
    drop(caller);
    assert!(lost.pending());
    assert_eq!(lost.status().unwrap().phase, p::Phase::Unknown);
    assert!(lost.begin().is_err());
    lost.cancel(reserve::Reason::UserCancelled, Instant::now());
    assert!(lost.pending());
}
#[test]
fn old_read_end_and_earlier_revoke_are_sampled_after_stop_without_renewal() {
    let e = entry();
    let caller = e.begin().unwrap();
    let now = Instant::now();
    e.cancel(reserve::Reason::UserCancelled, now);
    let earlier = now - Duration::from_secs(2);
    e.scope.read.revoke(earlier);
    assert_eq!(e.stop_at(now).unwrap().unwrap().1, earlier);
    assert!(e.pending());
    let new = ReadPermission::new(now + Duration::from_secs(3600));
    assert!(new.stop(now).unwrap().is_none());
    assert_eq!(e.stop_at(now).unwrap().unwrap().1, earlier);
    assert_eq!(
        poll_end(now, now + Duration::from_secs(8), false),
        now + Duration::from_millis(100)
    );
    assert_eq!(
        poll_end(now, now - Duration::from_secs(1), false),
        now - Duration::from_secs(1)
    );
    assert_eq!(
        poll_end(now, now + Duration::from_secs(8), true),
        now + Duration::from_secs(8)
    );
    e.native_refused(reserve::Reason::PermissionRevoked)
        .unwrap();
    caller.returned().unwrap();
    assert!(!e.pending());
}

#[test]
fn original_read_poison_after_earlier_stop_stays_unknown_after_both_returns() {
    let e = entry();
    let caller = e.begin().unwrap();
    let at = Instant::now();
    e.cancel(reserve::Reason::UserCancelled, at);
    assert_eq!(
        e.stop_at(at).unwrap(),
        Some((reserve::Reason::UserCancelled, at))
    );
    crate::service_version_reserve_requests::tests::poison_original_read(&e.scope.read);
    // This is the actual watchdog/control method, not a public status poll.
    assert_eq!(e.stop_at(at), Err(Error::StateUnknown));
    assert_eq!(
        e.row.lock().unwrap().stop,
        Some((reserve::Reason::UserCancelled, at))
    );
    e.native_refused(reserve::Reason::UserCancelled).unwrap();
    // The same outer caller really returns, but it cannot commit a clean
    // bookkeeping receipt after READ uncertainty. No status poll is needed.
    assert_eq!(caller.returned(), Err(Error::StateUnknown));
    assert!(e.row.lock().unwrap().native_returned);
    assert!(!e.row.lock().unwrap().caller_returned);
    assert!(e.pending());
    assert!(e.holds_review());
    assert_eq!(e.stop_at(at), Err(Error::StateUnknown));
    assert_eq!(e.status().unwrap().phase, p::Phase::Unknown);
    assert!(e.begin().is_err());
}
#[test]
fn separate_allow_and_submit_require_the_same_private_ready_comparison() {
    let r = Rig::new();
    let q = input(30);
    r.inbox
        .enqueue_review(q.clone(), scope(r.scope.read.clone()), Instant::now())
        .unwrap();
    let e = r.inbox.review_entry(&q.origin).unwrap();
    let caller = e.begin().unwrap();
    e.bind(r.scope.review_id.as_str()).unwrap();
    e.native_ready(
        r.scope.review_id.as_str(),
        r.scope.review_revision,
        &r.review,
        r.scope.review_end,
    )
    .unwrap();
    assert_eq!(
        r.inbox
            .allow(r.scope.clone(), r.input.grant_id.clone())
            .unwrap_err(),
        Error::Busy
    );
    caller.returned().unwrap();
    r.allowed();
    r.inbox.submit(r.input.clone()).unwrap();
    assert!(r.inbox.claim().unwrap().is_some());
    let foreign = Arc::new(());
    assert!(!e.ready_current(&foreign, Instant::now()));
    assert!(e.consume_review(&foreign).is_err());
    assert!(r
        .inbox
        .enqueue_review(input(31), scope(r.scope.read.clone()), Instant::now())
        .is_err());
}
#[test]
fn queued_cancel_or_expired_source_never_binds_or_upgrades_a_review() {
    let e = entry();
    e.cancel(reserve::Reason::UserCancelled, Instant::now());
    assert!(e.begin().is_err());
    assert_eq!(e.status().unwrap().phase, p::Phase::Refused);
    let read = Arc::new(ReadPermission::new(Instant::now() - Duration::from_secs(1)));
    assert!(Entry::new(input(42), scope(read), Instant::now()).is_err());
    let mut stale = scope(Arc::new(ReadPermission::new(
        Instant::now() + Duration::from_secs(300),
    )));
    stale.saved.fresh = false;
    assert!(Entry::new(input(42), stale, Instant::now()).is_err());
}
