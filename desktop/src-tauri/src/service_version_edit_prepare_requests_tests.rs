//! Original metadata/READ/Call tests only. Notify and compact DTOs are DATA,
//! not a fabricated Session, NativeUse, source proof or successful retirement.
use super::*;
use crate::{
    agent_identity_requests::SavedPoint, service_version_edit_requests::Inbox,
    service_version_reserve_requests::ReadPermission,
};
use std::{path::PathBuf, time::Duration};
fn id(n: u16) -> Id {
    Id::parse(&format!("{n:032x}")).unwrap()
}
struct Fixture {
    inbox: Inbox,
    read: Arc<ReadPermission>,
    wake: Arc<Notify>,
}
impl Fixture {
    fn new() -> Self {
        Self {
            inbox: Inbox::new(id(1)),
            read: Arc::new(ReadPermission::new(
                Instant::now() + Duration::from_secs(300),
            )),
            wake: Arc::new(Notify::new()),
        }
    }
    fn scope(&self) -> Scope {
        Scope {
            saved: SavedPoint {
                project_id: id(2),
                runtime_id: "native-project".into(),
                root: PathBuf::from("/never-opened-version-prepare-data"),
                device: 1,
                inode: 2,
                revision: 3,
                fresh: true,
            },
            read: self.read.clone(),
        }
    }
    fn input(&self, n: u16) -> p::Prepare {
        p::Prepare {
            origin: p::Query {
                project_id: id(2),
                service_instance: id(1),
                request_id: id(n),
            },
            selection: p::Selection::Manual {
                values: p::Values {
                    name: "1.2".into(),
                    build: "8".into(),
                },
            },
        }
    }
    fn entry(&self, n: u16) -> Arc<Entry> {
        let input = self.input(n);
        self.inbox.prepare(input.clone(), self.scope()).unwrap();
        self.inbox.preparation(&input.origin).unwrap()
    }
    fn opened(&self, e: &Arc<Entry>) -> Call {
        let call = e.begin(Kind::Open, None).unwrap().unwrap();
        e.claim_open().unwrap();
        e.bind(
            p::Original {
                session_id: id(4),
                owner_generation: id(5),
            },
            Arc::downgrade(&self.wake),
        )
        .unwrap();
        e.opened(
            p::Checkout {
                revision: id(6),
                source: "public/version.properties".into(),
                ios_enabled: false,
                values: p::Values {
                    name: "1.2".into(),
                    build: "7".into(),
                },
                config_bytes: 100,
                config_sha256: "a".repeat(64),
                version_bytes: 20,
                version_sha256: "b".repeat(64),
            },
            p::Values {
                name: "1.2".into(),
                build: "8".into(),
            },
        )
        .unwrap();
        call
    }
    fn review(&self) -> edit::Review {
        edit::Review {
            original: edit::Original {
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
            before_sha256: "b".repeat(64),
            after_bytes: 21,
            after_sha256: "c".repeat(64),
            candidate_id: None,
        }
    }
    fn ready(&self, e: &Arc<Entry>) {
        self.opened(e).finish(true).unwrap();
        let call = e.begin(Kind::Prepare, Some((1, 1))).unwrap().unwrap();
        e.prepared(self.review()).unwrap();
        call.finish(true).unwrap();
        assert!(e.ready(&self.review()).unwrap());
    }
    fn lease(&self) -> Arc<Lease> {
        Lease::new(
            id(8),
            id(9),
            self.scope(),
            self.review(),
            self.read.end(),
            Arc::downgrade(&self.wake),
        )
        .unwrap()
    }
    fn submit(&self, n: u16) -> edit::Submit {
        edit::Submit {
            origin: self.input(n).origin,
            grant_id: id(8),
            session_id: id(4),
            plan_token: id(7),
            reviewed: true,
        }
    }
}

#[test]
fn actual_call_returns_not_opened_or_prepared_events_enable_next_phase() {
    let f = Fixture::new();
    let e = f.entry(20);
    let open = f.opened(&e);
    assert_eq!(e.status().unwrap().phase, p::Phase::Opened);
    assert!(e.begin(Kind::Prepare, Some((1, 1))).is_err());
    assert!(e.begin(Kind::Open, None).unwrap().is_none());
    open.finish(true).unwrap();
    let prepare = e.begin(Kind::Prepare, Some((1, 1))).unwrap().unwrap();
    assert_eq!(e.prepare_data().unwrap().3, (1, 1));
    e.prepared(f.review()).unwrap();
    assert!(!e.ready(&f.review()).unwrap());
    assert!(f.lease().associate(&e).is_err());
    prepare.finish(true).unwrap();
    assert!(e.ready(&f.review()).unwrap());
    assert!(e.begin(Kind::Prepare, Some((9, 9))).unwrap().is_none()); // duplicate observes only
    assert_eq!(e.status().unwrap().review, Some(f.review()));
}

#[test]
fn same_preparation_exemption_is_required_at_both_install_and_normal_submit() {
    let f = Fixture::new();
    let e = f.entry(20);
    f.ready(&e);
    let unassociated = f.lease();
    assert_eq!(
        f.inbox
            .install(unassociated, || panic!("must refuse before install"))
            .err(),
        Some(Error::Busy)
    );
    let mut wrong = f.review();
    wrong.original.plan_token = id(17);
    assert!(!e.ready(&wrong).unwrap());
    let lease = f.lease();
    lease.associate(&e).unwrap();
    f.inbox.install(lease.clone(), || Ok(())).unwrap(); // DATA installer only, no native claim
    let input = f.submit(21);
    let status = f.inbox.submit(input.clone()).unwrap();
    assert_eq!(status.origin, input.origin);
    assert_eq!(
        e.status().unwrap().apply_request,
        Some(input.origin.clone())
    );
    assert_eq!(f.inbox.catalogue(&id(2)).unwrap(), vec![id(20), id(21)]);
    assert!(Arc::ptr_eq(
        &f.inbox.entry(&input.origin).unwrap().lease,
        &lease
    ));
    assert!(f.inbox.submit(input.clone()).is_ok());
    let mut changed = input;
    changed.plan_token = id(18);
    assert!(f.inbox.submit(changed).is_err());
    assert!(f.inbox.submit(f.submit(20)).is_err()); // stored preparation cannot become Apply
    assert!(f.inbox.prepare(f.input(21), f.scope()).is_err()); // or conversely
    assert!(f
        .inbox
        .preparation_status(Some(&f.input(20).origin))
        .unwrap()
        .is_some());
    assert!(f
        .inbox
        .preparation_status(Some(&f.input(21).origin))
        .is_err());
}

#[test]
fn cancelled_unknown_foreign_or_unreturned_preparation_cannot_exempt_another_lease() {
    for cut in 0..4 {
        let f = Fixture::new();
        let e = f.entry(20);
        let pending = if cut == 3 {
            f.opened(&e).finish(true).unwrap();
            let call = e.begin(Kind::Prepare, Some((1, 1))).unwrap().unwrap();
            e.prepared(f.review()).unwrap();
            Some(call)
        } else {
            f.ready(&e);
            None
        };
        let lease = f.lease();
        if cut == 0 {
            e.cancel(Instant::now()).unwrap();
        }
        if cut == 1 {
            e.unknown();
        }
        if cut == 2 {
            let other = Fixture::new();
            let foreign = other.lease();
            assert!(foreign.associate(&e).is_err()); // exact old READ, not same-looking IDs
            continue;
        }
        assert!(lease.associate(&e).is_err());
        assert!(f
            .inbox
            .install(lease, || panic!("no native install"))
            .is_err());
        assert!(f.inbox.prepare(f.input(22), f.scope()).is_err());
        if let Some(call) = pending {
            call.finish(true).unwrap();
        }
    }
}

#[test]
fn shared_thirty_two_rows_include_preparation_and_apply_without_eviction() {
    let f = Fixture::new();
    for n in 100..130 {
        let e = f.entry(n);
        e.cancel(Instant::now()).unwrap();
        assert_eq!(
            e.status().unwrap().result.unwrap().effect,
            edit::Effect::NotStarted
        );
    }
    let e = f.entry(20);
    f.ready(&e);
    let lease = f.lease();
    lease.associate(&e).unwrap();
    f.inbox.install(lease, || Ok(())).unwrap();
    f.inbox.submit(f.submit(21)).unwrap();
    assert_eq!(f.inbox.catalogue(&id(2)).unwrap().len(), 32);
    assert!(f.inbox.prepare(f.input(22), f.scope()).is_err());
    assert!(f.inbox.submit(f.submit(23)).is_err());
    assert!(f.inbox.submit(f.submit(21)).is_ok()); // original metadata remains observable
    assert_eq!(
        f.inbox
            .preparation_status(Some(&f.input(100).origin))
            .unwrap()
            .unwrap()
            .phase,
        p::Phase::Final
    );
}

#[test]
fn gui_winner_stops_only_delegation_and_keeps_later_original_read_revoke_out() {
    let f = Fixture::new();
    let e = f.entry(20);
    f.ready(&e);
    let lease = f.lease();
    lease.associate(&e).unwrap();
    f.inbox.install(lease.clone(), || Ok(())).unwrap();
    lease.gui_claim().unwrap();
    assert!(e.gui_owned());
    assert!(f.inbox.submit(f.submit(21)).is_err());
    let at = Instant::now();
    f.read.revoke(at);
    e.cancel(at).unwrap();
    assert_eq!(
        e.stop_at(f.read.end() + Duration::from_secs(1)).unwrap(),
        None
    );
    assert!(!e.status().unwrap().cancel_requested);
    assert_eq!(e.status().unwrap().phase, p::Phase::Applying);
    assert!(e.occupied().unwrap()); // GUI owns an original; no native return invented
    assert!(f.inbox.prepare(f.input(22), f.scope()).is_err());
}

#[test]
fn original_read_first_failure_and_lost_caller_never_rearm_or_become_final() {
    let f = Fixture::new();
    let e = f.entry(20);
    let open = f.opened(&e);
    open.finish(true).unwrap();
    let call = e.begin(Kind::Prepare, Some((1, 1))).unwrap().unwrap();
    let first = Instant::now();
    let later = first + Duration::from_secs(2);
    e.cancel(later).unwrap();
    assert_eq!(e.stop_at(later).unwrap(), Some(later));
    f.read.revoke(first);
    let other = ReadPermission::new(first + Duration::from_secs(1000));
    assert!(other.stop(later).unwrap().is_none());
    assert_eq!(e.stop_at(later).unwrap(), Some(first));
    assert_eq!(e.status().unwrap().settlement, Settlement::Pending);
    drop(call); // missing original continuation return, not a receipt
    assert_eq!(e.status().unwrap().settlement, Settlement::Unknown);
    assert!(e.occupied().unwrap());
    assert!(f.inbox.prepare(f.input(20), f.scope()).is_ok()); // same original Unknown
    assert!(f.inbox.prepare(f.input(22), f.scope()).is_err());
    assert!(e.begin(Kind::Prepare, Some((1, 1))).unwrap().is_none());
}

#[test]
fn unentered_return_claim_failure_and_late_final_data_have_distinct_custody() {
    let f = Fixture::new();
    let e = f.entry(20);
    e.begin(Kind::Open, None)
        .unwrap()
        .unwrap()
        .finish(false)
        .unwrap();
    assert!(!e.occupied().unwrap());
    assert_eq!(
        e.status().unwrap().result.unwrap().effect,
        edit::Effect::NotStarted
    );
    let claimed = f.entry(21);
    let call = claimed.begin(Kind::Open, None).unwrap().unwrap();
    claimed.claim_open().unwrap();
    call.finish(false).unwrap(); // claimed but no same-original link/return proof
    assert_eq!(claimed.status().unwrap().settlement, Settlement::Unknown);
    assert!(claimed.occupied().unwrap());
    let g = Fixture::new();
    let pending = g.entry(22);
    let original = g.opened(&pending);
    // Model only the metadata retirement callback, never a NativeUse. Even
    // terminal metadata cannot free the retained real caller.
    pending
        .retired(Some(edit::Final {
            effect: edit::Effect::NotStarted,
            journal: edit::Journal::NotCreated,
            cancelled: true,
            apply_submitted: false,
        }))
        .unwrap();
    assert!(pending.occupied().unwrap());
    original.finish(true).unwrap();
    assert!(!pending.occupied().unwrap());
}

#[test]
fn revision_overflow_and_exact_old_discovery_do_not_adopt_latest_preparation() {
    let f = Fixture::new();
    let old = f.entry(20);
    old.cancel(Instant::now()).unwrap();
    let current = f.entry(21);
    assert_eq!(
        f.inbox.preparation_status(None).unwrap().unwrap().origin,
        current.input.origin
    );
    assert_eq!(
        f.inbox
            .preparation_status(Some(&old.input.origin))
            .unwrap()
            .unwrap()
            .phase,
        p::Phase::Final
    );
    let mut unknown = old.input.origin.clone();
    unknown.request_id = id(30);
    assert!(f.inbox.preparation_status(Some(&unknown)).is_err());
    current.row.lock().unwrap().status.revision = u32::MAX - 1;
    assert!(current.cancel(Instant::now()).is_err());
    assert!(current.failed.load(Ordering::Acquire));
    assert!(current.occupied().unwrap());
}
