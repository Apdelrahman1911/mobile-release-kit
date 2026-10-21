//! Actual finite Inbox/Entry/Claim with inert callback DATA. No native source,
//! private material, joins receipt, saved key or Bind proof is manufactured.
use super::*;
fn id(n: u32) -> Id {
    Id::parse(&format!("{n:032x}")).unwrap()
}
struct Rig {
    inbox: Inbox,
    scope: Arc<NativeScope>,
    _identity: Arc<()>,
    input: p::Submit,
}
impl Rig {
    fn new(kind: p::Kind) -> Self {
        let identity = Arc::new(());
        let now = Instant::now();
        let scope = Arc::new(NativeScope {
            project_id: id(2),
            runtime_id: "project-1".into(),
            kind,
            end: now + Duration::from_secs(100),
            read: Arc::new(ReadPermission::new(now + Duration::from_secs(200))),
            identity: Arc::downgrade(&identity),
            changes: tokio::sync::watch::channel(0).0,
        });
        Self {
            inbox: Inbox::new(id(1)),
            scope,
            _identity: identity,
            input: p::Submit {
                origin: p::Query {
                    project_id: id(2),
                    service_instance: id(1),
                    request_id: id(3),
                },
                grant_id: id(4),
            },
        }
    }
    fn allow(&self) {
        let epoch = self.inbox.read_epoch().unwrap();
        self.inbox.publish_read(&self.scope.read, epoch).unwrap();
        self.inbox
            .allow(self.scope.clone(), self.input.grant_id.clone())
            .unwrap();
    }
    fn claim(&self) -> (Claim, Arc<NativeLink>) {
        self.allow();
        self.inbox.submit(self.input.clone()).unwrap();
        let c = self.inbox.claim().unwrap().unwrap();
        let l = c.link().clone();
        (c, l)
    }
    fn status(&self) -> p::Status {
        self.inbox.query(&self.input.origin, false).unwrap()
    }
}
fn key() -> p::KeyReference {
    p::KeyReference {
        vault_id: id(10),
        generation_id: id(11),
        record_id: id(12),
        revision_id: id(13),
        revision_counter: 1,
    }
}
fn arm(link: &NativeLink) {
    link.attempted().unwrap();
    link.arm(7).unwrap();
    link.installed(7).unwrap();
}

#[test]
fn one_exact_read_facet_and_desktop_scope_are_required_before_any_claim() {
    let r = Rig::new(p::Kind::GenerateNew);
    assert_eq!(
        r.inbox.submit(r.input.clone()).unwrap_err(),
        Error::AccessDenied
    );
    assert!(r.inbox.claim().unwrap().is_none());
    assert!(r.inbox.allow(r.scope.clone(), id(4)).is_err()); // Read alone is not published implicitly.
    let foreign = Arc::new(ReadPermission::new(r.scope.read.end()));
    r.inbox.publish_read(&foreign, 0).unwrap();
    assert!(r.inbox.allow(r.scope.clone(), id(4)).is_err());
    r.allow();
    let a = r.inbox.access(Some(&id(2))).unwrap();
    assert!(a.enabled && !a.consumed);
    assert_eq!(a.kind, Some(p::Kind::GenerateNew));
    assert_eq!(r.inbox.access(Some(&id(9))).unwrap(), p::Access::empty());
    assert!(r.inbox.allow(r.scope.clone(), id(5)).is_err());
    r.inbox.read_revoked(Instant::now());
    assert!(!r.inbox.access(None).unwrap().enabled);
    assert!(r.inbox.publish_read(&r.scope.read, 0).is_err());
}
#[test]
fn exact_duplicates_observe_only_and_never_alias_another_project_instance_or_grant() {
    let r = Rig::new(p::Kind::BindReviewed);
    r.allow();
    let first = r.inbox.submit(r.input.clone()).unwrap();
    assert_eq!(r.inbox.submit(r.input.clone()).unwrap(), first);
    for i in 0..3 {
        let mut wrong = r.input.clone();
        match i {
            0 => wrong.grant_id = id(40),
            1 => wrong.origin.project_id = id(41),
            _ => wrong.origin.service_instance = id(42),
        };
        assert!(r.inbox.submit(wrong).is_err());
    }
    let c = r.inbox.claim().unwrap().unwrap();
    assert!(r.inbox.claim().unwrap().is_none());
    assert_eq!(
        r.inbox.submit(r.input.clone()).unwrap().kind,
        p::Kind::BindReviewed
    );
    c.returned(Err(Error::Conflict));
    let e = r.inbox.book.lock().unwrap().entries[0].clone();
    assert_eq!(r.status().settlement, Settlement::Pending);
    e.continuation_joined(true);
    assert_eq!(r.status().state, p::State::Refused);
    assert_eq!(r.inbox.submit(r.input.clone()).unwrap(), r.status());
}
#[test]
fn every_order_requires_actual_caller_native_and_continuation_returns() {
    for kind in [p::Kind::GenerateNew, p::Kind::BindReviewed] {
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let r = Rig::new(kind);
            let (claim, link) = r.claim();
            arm(&link);
            let mut claim = Some(claim);
            let outcome = if kind == p::Kind::GenerateNew {
                p::State::SavedUnassigned
            } else {
                p::State::Assigned
            };
            for (position, part) in order.into_iter().enumerate() {
                match part {
                    0 => claim.take().unwrap().returned(Ok(())),
                    1 => link
                        .entry()
                        .native_retired(7, outcome, p::Reason::None, Some(key())),
                    _ => link.entry().continuation_joined(true),
                }
                let s = r.status();
                if position < 2 {
                    assert_eq!(s.settlement, Settlement::Pending);
                    assert!(s.key.is_none());
                } else {
                    assert_eq!(s.state, outcome);
                    assert_eq!(s.key, Some(key()));
                    assert!(!link.entry().pending());
                }
            }
            assert!(!link.entry().needs_native_retirement(7).unwrap());
            r.inbox.revoke(&id(4), Instant::now()).unwrap();
            assert_eq!(r.status().state, outcome); // A later permission withdrawal cannot rewrite history.
        }
    }
}
#[test]
fn attempted_preparation_without_install_and_lost_original_return_are_absorbing_unknown() {
    for prepared in [false, true] {
        let r = Rig::new(p::Kind::GenerateNew);
        let (c, l) = r.claim();
        l.attempted().unwrap();
        assert!(l.attempted().is_err());
        if prepared {
            l.preparation(id(20).as_str(), id(21).as_str()).unwrap();
            assert!(l.preparation(id(20).as_str(), id(21).as_str()).is_err());
        }
        c.returned(Err(Error::Unavailable));
        l.entry().continuation_joined(true);
        assert_eq!(r.status().state, p::State::Unknown);
        assert!(l.entry().pending());
        assert_eq!(
            r.inbox.submit(r.input.clone()).unwrap().state,
            p::State::Unknown
        );
        assert!(r.inbox.allow(r.scope.clone(), id(33)).is_err());
    }
    let r = Rig::new(p::Kind::BindReviewed);
    let (c, l) = r.claim();
    arm(&l);
    drop(c);
    l.entry()
        .native_retired(7, p::State::Assigned, p::Reason::None, Some(key()));
    l.entry().continuation_joined(true);
    assert_eq!(r.status().state, p::State::Unknown);
}
#[test]
fn queued_cancel_is_not_native_nogo_and_stale_revoke_cannot_withdraw_a_new_consent() {
    let mut r = Rig::new(p::Kind::GenerateNew);
    r.allow();
    r.inbox.submit(r.input.clone()).unwrap();
    assert_eq!(
        r.inbox.query(&r.input.origin, true).unwrap().state,
        p::State::Cancelled
    );
    assert!(r.inbox.claim().unwrap().is_none());
    assert!(r.status().asset_operation_id.is_none());
    r.inbox.revoke(&id(4), Instant::now()).unwrap();
    r.input.grant_id = id(5);
    r.input.origin.request_id = id(6);
    r.inbox.allow(r.scope.clone(), id(5)).unwrap();
    let a = r.inbox.revoke(&id(4), Instant::now()).unwrap();
    assert!(a.enabled);
    assert_eq!(a.grant_id, Some(id(5)));
    assert_eq!(
        r.inbox.submit(r.input.clone()).unwrap().state,
        p::State::Queued
    );
}
#[test]
fn read_revoke_and_original_end_never_renew_or_infer_success_on_stop() {
    let r = Rig::new(p::Kind::GenerateNew);
    let (c, l) = r.claim();
    arm(&l);
    let lease = r.inbox.book.lock().unwrap().lease.clone().unwrap();
    let after = r.scope.end + Duration::from_secs(1);
    assert_eq!(
        lease.stop(after, false).unwrap(),
        Some((p::Reason::Expired, r.scope.end))
    );
    assert_eq!(lease.stop(after, true).unwrap(), None); // Native work clock, not a new five-minute timer.
    let first = Instant::now();
    r.scope.read.revoke(first);
    assert_eq!(r.status().state, p::State::StopRequested);
    l.entry()
        .cancel(p::Reason::ContextChanged, first + Duration::from_secs(1));
    assert_eq!(r.status().reason, p::Reason::PermissionRevoked);
    c.returned(Ok(()));
    l.entry()
        .native_retired(7, p::State::SavedUnassigned, p::Reason::None, Some(key()));
    l.entry().continuation_joined(true);
    let s = r.status();
    assert_eq!(s.state, p::State::Cancelled);
    assert!(s.key.is_none());
}
#[test]
fn catalogue_copies_only_original_ids_without_expiring_or_polling_requests() {
    let r = Rig::new(p::Kind::BindReviewed);
    let (c, l) = r.claim();
    let before = l.entry().row.lock().unwrap().status.clone();
    r.scope.read.revoke(Instant::now());
    assert_eq!(r.inbox.retained_ids(&id(2)).unwrap(), vec![id(3)]);
    assert!(r.inbox.retained_ids(&id(9)).unwrap().is_empty());
    assert_eq!(l.entry().row.lock().unwrap().status, before);
    assert!(l.entry().row.lock().unwrap().stop.is_none());
    drop(c);
    r.inbox.close(Instant::now());
    assert!(r.inbox.retained_ids(&id(2)).is_err());
}
#[test]
fn capacity_keeps_all_original_tombstones_and_never_resets_a_used_consent() {
    let r = Rig::new(p::Kind::GenerateNew);
    r.inbox.publish_read(&r.scope.read, 0).unwrap();
    for n in 0..p::REQUEST_LIMIT {
        let consent = id(100 + n as u32);
        r.inbox.allow(r.scope.clone(), consent.clone()).unwrap();
        let mut input = r.input.clone();
        input.grant_id = consent.clone();
        input.origin.request_id = id(200 + n as u32);
        r.inbox.submit(input.clone()).unwrap();
        r.inbox.query(&input.origin, true).unwrap();
        r.inbox.revoke(&consent, Instant::now()).unwrap();
    }
    assert_eq!(r.inbox.retained_ids(&id(2)).unwrap().len(), 32);
    assert_eq!(
        r.inbox.allow(r.scope.clone(), id(999)).unwrap_err(),
        Error::Busy
    );
    assert!(DOCUMENT_BACKING > p::REQUEST_LIMIT * std::mem::size_of::<Entry>());
    assert!(DOCUMENT_BACKING < 4 * 1024 * 1024); // Bound checked, not a new reservation or RSS claim.
}
#[test]
fn unknown_join_wrong_original_and_poison_cannot_become_finished_or_a_new_grant() {
    let r = Rig::new(p::Kind::BindReviewed);
    let (c, l) = r.claim();
    arm(&l);
    c.returned(Ok(()));
    l.entry()
        .native_retired(8, p::State::Assigned, p::Reason::None, Some(key()));
    l.entry().continuation_joined(true);
    assert_eq!(r.status().state, p::State::Unknown);
    let r = Rig::new(p::Kind::GenerateNew);
    let (c, l) = r.claim();
    arm(&l);
    c.returned(Ok(()));
    l.entry()
        .native_retired(7, p::State::SavedUnassigned, p::Reason::None, Some(key()));
    l.entry().continuation_joined(false);
    assert_eq!(r.status().state, p::State::Unknown);
    let r = Rig::new(p::Kind::GenerateNew);
    r.allow();
    r.inbox.revoke(&id(4), Instant::now()).unwrap();
    let lease = r.inbox.book.lock().unwrap().lease.clone().unwrap();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = lease.stopped.lock().unwrap();
        panic!("inert poisoned permission");
    }));
    assert_eq!(
        r.inbox.allow(r.scope.clone(), id(5)).unwrap_err(),
        Error::StateUnknown
    );
}
