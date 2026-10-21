//! DATA and original permission clocks only. These tests do not mint a native
//! Prepared/Session, IO join or all-jobs witness; actual native use remains separate.
use super::*;
use std::{path::PathBuf, time::Duration};
fn id(n: u8) -> Id {
    Id::parse(&format!("{n:032x}")).unwrap()
}
fn review() -> p::Review {
    p::Review {
        original: p::Original {
            session_id: id(4),
            owner_generation: id(5),
            revision: id(6),
            plan_token: id(7),
        },
        native_status_revision: 9,
        name: "1.2".into(),
        build: "8".into(),
        source: "public/version.properties".into(),
        before_bytes: 20,
        before_sha256: "a".repeat(64),
        after_bytes: 21,
        after_sha256: "b".repeat(64),
        candidate_id: None,
    }
}
struct Fixture {
    inbox: Inbox,
    lease: Arc<Lease>,
    wake: Arc<Notify>,
}
impl Fixture {
    fn new() -> Self {
        let wake = Arc::new(Notify::new());
        let end = Instant::now() + Duration::from_secs(300);
        let lease = Lease::new(
            id(3),
            id(9),
            Scope {
                saved: SavedPoint {
                    project_id: id(2),
                    runtime_id: "native-project".into(),
                    root: PathBuf::from("/never-opened-version-data"),
                    device: 1,
                    inode: 2,
                    revision: 3,
                    fresh: false,
                },
                read: Arc::new(ReadPermission::new(end)),
            },
            review(),
            end,
            Arc::downgrade(&wake),
        )
        .unwrap();
        Self {
            inbox: Inbox::new(id(1)),
            lease,
            wake,
        }
    }
    fn install(&self) {
        self.inbox.install(self.lease.clone(), || Ok(())).unwrap();
    }
    fn input(&self) -> p::Submit {
        p::Submit {
            origin: p::Query {
                project_id: id(2),
                service_instance: id(1),
                request_id: id(8),
            },
            grant_id: id(3),
            session_id: id(4),
            plan_token: id(7),
            reviewed: true,
        }
    }
    fn submit(&self) -> Arc<Entry> {
        self.inbox.submit(self.input()).unwrap();
        self.inbox.entry(&self.input().origin).unwrap()
    }
}
#[test]
fn install_precedes_public_allow_and_revoke_before_allow_is_not_rearmed() {
    let f = Fixture::new();
    let before = f.inbox.receiver();
    assert!(!f.inbox.access().unwrap().live);
    let called = AtomicBool::new(false);
    f.inbox
        .install(f.lease.clone(), || {
            called.store(true, Ordering::Release);
            assert!(!before.has_changed().unwrap());
            Ok(())
        })
        .unwrap();
    assert!(called.load(Ordering::Acquire));
    assert!(f.inbox.access().unwrap().live);
    assert!(before.has_changed().unwrap());
    let other = Fixture::new();
    other
        .inbox
        .revoke(&other.lease.nonce, Instant::now())
        .unwrap();
    assert!(other
        .inbox
        .install(other.lease.clone(), || panic!(
            "must refuse before native install"
        ))
        .is_err());
    assert!(other.inbox.submit(other.input()).is_err());
    assert!(Arc::strong_count(&f.wake) > 0);
}
#[test]
fn permanent_submit_binds_same_lease_and_duplicate_never_enters_twice() {
    let f = Fixture::new();
    f.install();
    let e = f.submit();
    assert!(Arc::ptr_eq(&e.lease, &f.lease));
    assert!(Arc::ptr_eq(&f.lease.entry().unwrap().unwrap(), &e));
    assert!(f.inbox.submit(f.input()).is_ok());
    let mut changed = f.input();
    changed.plan_token = id(10);
    assert!(f.inbox.submit(changed).is_err());
    assert!(f.lease.gui_claim().is_err());
    assert!(e.preclaim().unwrap());
    assert!(!e.preclaim().unwrap());
    assert!(e.enqueue().is_ok());
    assert!(e.enqueue().is_err());
    let mut next = f.input();
    next.origin.request_id = id(11);
    assert!(f.inbox.submit(next).is_err());
    assert_eq!(f.inbox.catalogue(&id(2)).unwrap(), vec![id(8)]);
}
#[test]
fn gui_winner_spends_unused_lease_without_borrowing_its_later_stop() {
    let f = Fixture::new();
    f.install();
    f.lease.gui_claim().unwrap();
    assert!(f.lease.gui_claim().is_err());
    assert!(f.inbox.submit(f.input()).is_err());
    f.lease.scope.read.revoke(Instant::now());
    f.lease.revoke(Instant::now()).unwrap();
    assert_eq!(
        f.lease
            .stop_at(f.lease.end + Duration::from_secs(1))
            .unwrap(),
        None
    );
}
#[test]
fn final_seal_serializes_submit_without_a_dropped_unobserved_entry() {
    let f = Fixture::new();
    f.install();
    assert!(f.lease.seal().unwrap().is_none());
    assert!(f.inbox.submit(f.input()).is_err());
    let g = Fixture::new();
    g.install();
    let e = g.submit();
    assert!(Arc::ptr_eq(&g.lease.seal().unwrap().unwrap(), &e));
    assert_eq!(e.status().unwrap().settlement, Settlement::Pending); // Seal is NOT finality.
    e.unknown();
    assert_eq!(e.status().unwrap().settlement, Settlement::Unknown);
}
#[test]
fn original_read_clock_and_earliest_stop_survive_unavailable_renderer_or_renewal() {
    let f = Fixture::new();
    f.install();
    let e = f.submit();
    let first = Instant::now();
    e.cancel(first + Duration::from_secs(2)).unwrap();
    f.lease.scope.read.revoke(first);
    let renewed = ReadPermission::new(first + Duration::from_secs(1000));
    assert!(renewed.stop(first).unwrap().is_none());
    assert_eq!(
        f.lease.stop_at(first + Duration::from_secs(3)).unwrap(),
        Some(first)
    );
    assert!(!e.pending().unwrap());
    assert!(e.preclaim().is_err());
    let status = e.status().unwrap();
    assert!(status.cancel_requested);
    assert_eq!(status.settlement, Settlement::Pending); // No native return invented.
    let g = Fixture::new();
    g.install();
    let ge = g.submit();
    assert_eq!(
        g.lease
            .stop_at(g.lease.end + Duration::from_secs(1))
            .unwrap(),
        Some(g.lease.end)
    );
    assert_eq!(ge.status().unwrap().settlement, Settlement::Pending);
}
#[test]
fn known_cleanup_poll_keeps_original_cutoff_and_resamples_earlier_read_revocation() {
    let f = Fixture::new();
    f.install();
    let e = f.submit();
    let first = Instant::now();
    let later = first + Duration::from_secs(2);
    e.cancel(later).unwrap();
    let now = first + Duration::from_secs(3);
    assert_eq!(f.lease.stop_at(now).unwrap(), Some(later));
    let original_end = later + Duration::from_secs(8);
    let poll = f.lease.cleanup_poll_end(original_end, now);
    assert_eq!(poll, now + Duration::from_millis(100));
    // A real old facet replacement can publish its previously captured instant
    // AFTER STOP. No relay wake or worker frame is needed for the next poll.
    f.lease.scope.read.revoke(first);
    let renewed = ReadPermission::new(first + Duration::from_secs(1000));
    assert!(renewed.stop(poll).unwrap().is_none());
    let observed = f.lease.stop_at(poll).unwrap().unwrap();
    assert_eq!(observed, first);
    let contracted = observed + Duration::from_secs(8);
    assert!(contracted < original_end);
    assert_eq!(
        f.lease
            .cleanup_poll_end(contracted, contracted - Duration::from_millis(1)),
        contracted
    );
    assert_eq!(
        f.lease
            .cleanup_poll_end(contracted, contracted + Duration::from_secs(1)),
        contracted
    );
    assert_eq!(e.status().unwrap().settlement, Settlement::Pending); // Polling is not a native return.
    let gui = Fixture::new();
    gui.install();
    gui.lease.gui_claim().unwrap();
    gui.lease.scope.read.revoke(first);
    assert_eq!(gui.lease.cleanup_poll_end(original_end, now), original_end);
    assert_eq!(gui.lease.stop_at(now).unwrap(), None);
}
#[test]
fn missing_original_or_unknown_is_absorbing_and_counter_overflow_never_rearms() {
    let f = Fixture::new();
    f.install();
    let e = f.submit();
    let input = f.input();
    drop(f.wake);
    assert!(f.lease.stop_at(Instant::now()).is_err());
    assert_eq!(e.status().unwrap().settlement, Settlement::Unknown);
    assert!(f.inbox.submit(input).is_ok());
    assert!(e.preclaim().is_err());
    let g = Fixture::new();
    g.install();
    let ge = g.submit();
    ge.row.lock().unwrap().revision = u32::MAX - 1;
    assert!(ge.cancel(Instant::now()).is_err());
    assert!(ge.failed.load(Ordering::Acquire));
    assert!(!ge.pending().unwrap());
}
#[test]
fn failed_native_retirement_and_exact_old_query_cannot_be_relabelled_current() {
    let f = Fixture::new();
    f.install();
    let e = f.submit();
    e.retired(None).unwrap();
    let old = f.inbox.access_for(&f.input().origin).unwrap();
    assert_eq!(old.request.unwrap().settlement, Settlement::Unknown);
    assert!(!f.inbox.access().unwrap().live);
    assert!(e.retired(None).is_err());
    let mut foreign = f.input().origin;
    foreign.request_id = id(17);
    assert!(f.inbox.access_for(&foreign).is_err());
}
#[test]
fn revoke_nonce_capacity_preserves_other_live_original_and_never_evicts() {
    let f = Fixture::new();
    f.install();
    for n in 30..61 {
        f.inbox.revoke(&id(n), Instant::now()).unwrap();
    }
    assert!(f.inbox.access().unwrap().live);
    assert!(f.inbox.revoke(&id(99), Instant::now()).is_err());
    f.inbox.revoke(&f.lease.nonce, Instant::now()).unwrap();
    assert!(!f.inbox.access().unwrap().live);
    assert_eq!(f.inbox.lock().unwrap().revoked.len(), 32);
}
