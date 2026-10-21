//! Actual finite inbox/Read/Claim synchronization; NO native authority fixture.
use super::*;
fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
struct Fixture {
    inbox: Inbox,
    doc: Arc<()>,
    scope: Arc<NativeScope>,
    link: Arc<NativeLink>,
}
impl Fixture {
    fn new() -> Self {
        let now = Instant::now();
        let doc = Arc::new(());
        let scope = Arc::new(NativeScope {
            project_id: id('1'),
            runtime_id: "p1".into(),
            review_id: id('4'),
            review: p::Review {
                kind: p::Kind::Doctor,
                platform: p::Platform::Android,
                draft_revision: 1,
                baseline_generation: 1,
                prepared: None,
                sources: None,
            },
            root: "/inert-never-opened".into(),
            device: 1,
            inode: 2,
            observation_revision: 1,
            saved_config: None,
            expires: now + Duration::from_secs(120),
            read: Arc::new(
                crate::service_version_reserve_requests::ReadPermission::new(
                    now + Duration::from_secs(200),
                ),
            ),
            document: Arc::downgrade(&doc),
            control: Control::new(),
            retired: AtomicBool::new(false),
            changes: tokio::sync::watch::channel(0).0,
        });
        let link = NativeLink::new(scope.clone());
        Self {
            inbox: Inbox::new(id('2')),
            doc,
            scope,
            link,
        }
    }
    fn input(&self) -> p::Submit {
        p::Submit {
            origin: p::Query {
                project_id: id('1'),
                service_instance: id('2'),
                request_id: id('5'),
            },
            grant_id: id('3'),
            review_id: id('4'),
        }
    }
    fn queued(&self) -> Arc<Entry> {
        self.inbox.allow(self.scope.clone(), id('3')).unwrap();
        self.inbox.submit(self.input(), Instant::now()).unwrap();
        let e = self.inbox.entries().unwrap()[0].clone();
        self.link.attach(&e).unwrap();
        e
    }
    fn result(&self) -> NativeData {
        NativeData {
            sequence: 2,
            operation: Some(p::Operation {
                operation_id: id('a'),
                owner_generation: Some(id('b')),
                registration_generation: None,
            }),
            state: OperationState::Succeeded,
            reason: p::Reason::None,
            outcome: Some(p::Outcome::Complete),
            result: Some(p::Report::Doctor {
                checks: vec![p::Finding {
                    check: p::Check::Git,
                    status: p::CheckStatus::Failed,
                }],
            }),
            retired: true,
        }
    }
}
#[test]
fn three_real_return_slots_required_in_both_callback_orders() {
    for native_first in [true, false] {
        let f = Fixture::new();
        let e = f.queued();
        let claim = f.inbox.claim().unwrap().unwrap();
        assert!(f.inbox.claim().unwrap().is_none());
        if native_first {
            e.native(f.result());
            assert!(e.claim_history().unwrap().is_none());
            assert_eq!(e.status().unwrap().state, p::State::Finishing);
            claim.returned();
        } else {
            claim.returned();
            assert!(e.pending());
            e.native(f.result());
        }
        assert!(e.pending());
        let h = e.claim_history().unwrap().unwrap();
        assert!(h.first);
        assert!(e.pending());
        h.returned(Ok(())).unwrap();
        assert!(!e.pending());
        assert_eq!(e.status().unwrap().state, p::State::Complete);
        assert!(e.status().unwrap().result.is_some());
        e.cancel(p::Reason::UserCancelled, Instant::now());
        assert_eq!(e.status().unwrap().state, p::State::Complete);
    }
}
#[test]
fn exact_duplicate_nonce_and_foreign_cancel_do_not_replay_or_stop() {
    let f = Fixture::new();
    let e = f.queued();
    assert_eq!(
        f.inbox.submit(f.input(), Instant::now()).unwrap(),
        e.status().unwrap()
    );
    let mut changed = f.input();
    changed.review_id = id('6');
    assert!(f.inbox.submit(changed, Instant::now()).is_err());
    assert_eq!(f.inbox.entries().unwrap().len(), 1);
    let mut q = f.input().origin;
    q.project_id = id('7');
    assert!(f.inbox.query(&q, true).is_err());
    assert!(f.scope.control.first().unwrap().is_none());
    assert!(matches!(f.inbox.can_allow(&id('8')), Err(Error::Busy)));
    let claim = f.inbox.claim().unwrap().unwrap();
    assert!(f.link.consume(&e).is_ok());
    assert!(f.link.consume(&e).is_err());
    claim.returned();
    let before = Fixture::new();
    before.inbox.revoke(&id('3'), Instant::now()).unwrap();
    assert!(matches!(
        before.inbox.allow(before.scope.clone(), id('3')),
        Err(Error::AccessDenied)
    ));
}
#[test]
fn lost_caller_history_and_contradictory_callback_stay_unknown() {
    for case in 0..3 {
        let f = Fixture::new();
        let e = f.queued();
        let c = f.inbox.claim().unwrap().unwrap();
        e.native(f.result());
        if case == 0 {
            drop(c);
        } else {
            c.returned();
            let h = e.claim_history().unwrap().unwrap();
            if case == 1 {
                drop(h);
            } else {
                h.returned(Ok(())).unwrap();
                let mut other = f.result();
                other.sequence += 1;
                e.native(other);
            }
        }
        assert_eq!(e.status().unwrap().settlement, Settlement::Unknown);
        assert!(e.pending());
        assert!(e.status().unwrap().result.is_none());
        assert!(f.inbox.can_allow(&id('8')).is_err());
    }
}
#[test]
fn quiet_read_facet_preserves_earliest_failure_and_absolute_permission() {
    let f = Fixture::new();
    let e = f.queued();
    let c = f.inbox.claim().unwrap().unwrap();
    f.link.consume(&e).unwrap();
    let now = Instant::now();
    let early = now - Duration::from_millis(5);
    f.scope.control.stop(p::Reason::UserCancelled, now);
    f.scope.read.revoke(early);
    assert_eq!(
        f.link.stop_at(now),
        Some((p::Reason::PermissionRevoked, early))
    );
    assert_eq!(f.scope.control.first().unwrap().unwrap().1, early);
    c.returned();
    assert!(e.pending());
    let f = Fixture::new();
    f.inbox.allow(f.scope.clone(), id('3')).unwrap();
    assert!(f.inbox.submit(f.input(), f.scope.expires).is_err());
    assert!(f.inbox.entries().unwrap().is_empty());
    f.scope.read.revoke(Instant::now());
    assert!(f.inbox.submit(f.input(), Instant::now()).is_err());
}
#[test]
fn cancelled_unentered_still_needs_actual_caller_and_history() {
    let f = Fixture::new();
    let e = f.queued();
    let c = f.inbox.claim().unwrap().unwrap();
    f.link.cancel(p::Reason::UserCancelled, Instant::now());
    assert!(!f.link.unentered_caller_returned());
    assert!(e.pending());
    c.returned();
    assert!(f.link.unentered_caller_returned());
    // This tests the DATA relay only, not a fabricated native retirement proof.
    f.link.refused_unentered(p::Reason::UserCancelled);
    assert!(e.pending());
    e.claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    assert_eq!(e.status().unwrap().state, p::State::Cancelled);
    assert!(f.scope.retired.load(Ordering::Acquire));
    assert!(f.link.caller_returned());
    // Same DATA relay with a callback cached before attachment. The original
    // caller and history still have to return; a cached value alone is not final.
    let f = Fixture::new();
    f.inbox.allow(f.scope.clone(), id('3')).unwrap();
    f.inbox.submit(f.input(), Instant::now()).unwrap();
    let e = f.inbox.entries().unwrap()[0].clone();
    let c = f.inbox.claim().unwrap().unwrap();
    c.returned();
    f.link.refused_unentered(p::Reason::UserCancelled);
    assert!(e.pending());
    assert!(e.claim_history().unwrap().is_none());
    f.link.attach(&e).unwrap();
    assert!(e.pending());
    e.claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    assert_eq!(e.status().unwrap().state, p::State::Cancelled);
}
#[test]
fn bounded_consent_exhaustion_and_document_loss_do_not_reset() {
    let f = Fixture::new();
    for i in 1..=p::CONSENT_LIMIT {
        f.inbox
            .revoke(&Id::parse(&format!("{i:032x}")).unwrap(), Instant::now())
            .unwrap();
    }
    assert!(matches!(
        f.inbox.revoke(&id('e'), Instant::now()),
        Err(Error::Busy)
    ));
    let f = Fixture::new();
    f.inbox.allow(f.scope.clone(), id('3')).unwrap();
    let input = f.input();
    drop(f.doc);
    assert!(f.inbox.submit(input, Instant::now()).is_err());
    assert!(DOCUMENT_BACKING > p::REQUEST_LIMIT * ROW);
}
