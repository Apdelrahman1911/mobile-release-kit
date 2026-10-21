//! Real memory inbox/claim methods, inert weak comparison originals only.
//! These tests do not manufacture Supervisor/Connection/HTTP join authority.
use super::*;
fn id(n: usize) -> Id {
    Id::parse(&format!("{n:032x}")).unwrap()
}
struct Fixture {
    inbox: Inbox,
    doc: Arc<()>,
    review: Arc<()>,
    read: Arc<ReadPermission>,
    scope: Arc<NativeScope>,
}
impl Fixture {
    fn new() -> Self {
        let inbox = Inbox::new(id(1));
        let doc = Arc::new(());
        let review = Arc::new(());
        let now = Instant::now();
        let read = Arc::new(ReadPermission::new(now + Duration::from_secs(110)));
        let scope = inbox.scope(
            id(2),
            "project-1".into(),
            id(3),
            now + Duration::from_secs(100),
            read.clone(),
            Arc::downgrade(&doc),
            Arc::downgrade(&review),
            tokio::sync::watch::channel(0).0,
            1,
        );
        Self {
            inbox,
            doc,
            review,
            read,
            scope,
        }
    }
    fn submit(&self, n: usize) -> p::Submit {
        p::Submit {
            origin: p::Query {
                project_id: id(2),
                service_instance: id(1),
                request_id: id(n),
            },
            consent_id: self.scope.consent_id.clone(),
        }
    }
}
#[test]
fn consumed_access_is_not_revoked_scope_and_exact_retry_never_remints_claim() {
    let f = Fixture::new();
    let input = f.submit(4);
    assert!(f.inbox.submit(input.clone()).is_err());
    f.inbox.allow(f.scope.clone()).unwrap();
    let queued = f.inbox.submit(input.clone()).unwrap();
    assert!(!f.inbox.access().unwrap().unwrap().enabled);
    assert!(f.inbox.scope_live(&f.scope).unwrap());
    assert_eq!(f.inbox.submit(input.clone()).unwrap(), queued);
    let claim = f.inbox.claim().unwrap().unwrap();
    assert!(f.inbox.claim().unwrap().is_none());
    let link = claim.link().clone();
    link.arm("github-play-cleanup-1").unwrap();
    assert!(link.arm("github-play-cleanup-2").is_err());
    claim.handoff("github-play-cleanup-1").unwrap();
    link.entry().unknown();
    let unknown = f.inbox.query(&input.origin, false).unwrap();
    assert_eq!(unknown.state, p::State::Unknown);
    assert_eq!(f.inbox.submit(input.clone()).unwrap(), unknown);
    assert!(f.inbox.claim().unwrap().is_none());
    assert!(f.inbox.submit(f.submit(5)).is_err());
    assert!(f.inbox.allow(f.scope.clone()).is_err());
    let mut other = input;
    other.origin.project_id = id(5);
    assert!(f.inbox.submit(other).is_err());
    assert!(link
        .settled("github-play-cleanup-1", p::Effect::NotSent, None)
        .is_err());
}
#[test]
fn original_earliest_stop_and_later_unknown_do_not_renew_watchdog_or_revisions() {
    let f = Fixture::new();
    f.inbox.allow(f.scope.clone()).unwrap();
    let input = f.submit(4);
    f.inbox.submit(input.clone()).unwrap();
    let claim = f.inbox.claim().unwrap().unwrap();
    let link = claim.link().clone();
    link.arm("github-play-cleanup-1").unwrap();
    claim.handoff("github-play-cleanup-1").unwrap();
    let at = Instant::now();
    f.read.revoke(at);
    let first = link.entry().watchdog_stop().unwrap().unwrap();
    assert_eq!(first, (false, at));
    let revision = link.entry().status().unwrap().revision;
    for _ in 0..4 {
        assert_eq!(link.entry().watchdog_stop().unwrap(), Some(first));
    }
    assert_eq!(link.entry().status().unwrap().revision, revision);
    link.entry().unknown();
    let unknown = link.entry().status().unwrap();
    assert_eq!(link.entry().watchdog_stop().unwrap(), Some((true, at)));
    link.entry().unknown();
    assert_eq!(link.entry().status().unwrap(), unknown);
    assert!(link.current(true).is_err());
    assert!(f.inbox.claim().unwrap().is_none());
}
#[test]
fn original_native_go_and_unknown_are_immediate_monotone_facts_not_join_or_retry_authority() {
    let f = Fixture::new();
    f.inbox.allow(f.scope.clone()).unwrap();
    let input = f.submit(4);
    f.inbox.submit(input.clone()).unwrap();
    let claim = f.inbox.claim().unwrap().unwrap();
    let link = claim.link().clone();
    let operation = "github-play-cleanup-1";
    link.arm(operation).unwrap();
    claim.handoff(operation).unwrap();
    let armed = link.entry().status().unwrap();
    assert_eq!(armed.effect, p::Effect::NotSent);
    assert!(link.native_go("github-play-cleanup-2").is_err());
    assert_eq!(link.entry().status().unwrap(), armed);
    // Exercise the very same observation methods called after the original
    // GO claim and at native Unknown publication. No owner/receipt is forged.
    link.native_go(operation).unwrap();
    let go = link.entry().status().unwrap();
    assert_eq!(go.effect, p::Effect::PotentiallyApplied);
    assert_eq!(go.settlement, Settlement::Pending);
    let original_failure = Instant::now();
    link.entry().cancel(
        p::Reason::UserCancelled,
        original_failure + Duration::from_secs(1),
    );
    let stopping = link.entry().status().unwrap();
    assert_eq!(stopping.state, p::State::Stopping);
    assert_eq!(stopping.effect, p::Effect::PotentiallyApplied);
    link.native_unknown(operation, true, original_failure)
        .unwrap();
    let unknown = f.inbox.query(&input.origin, false).unwrap();
    assert_eq!(unknown.state, p::State::Unknown);
    assert_eq!(unknown.settlement, Settlement::Unknown);
    assert_eq!(unknown.effect, p::Effect::PotentiallyApplied);
    assert_eq!(unknown.origin, input.origin);
    assert_eq!(unknown.operation_id.as_deref(), Some(operation));
    assert_eq!(
        link.entry().watchdog_stop().unwrap(),
        Some((true, original_failure))
    );
    link.native_unknown(operation, false, original_failure + Duration::from_secs(5))
        .unwrap();
    link.native_go(operation).unwrap();
    assert_eq!(link.entry().status().unwrap(), unknown);
    assert_eq!(f.inbox.submit(input).unwrap(), unknown);
    assert!(link.current(true).is_err());
    assert!(link
        .settled(operation, p::Effect::AcknowledgedUnconfirmed, None)
        .is_err());
    assert!(f.inbox.claim().unwrap().is_none());
    assert!(f.inbox.submit(f.submit(5)).is_err());
    assert!(f.inbox.allow(f.scope.clone()).is_err());
    assert_eq!(link.entry().status().unwrap(), unknown);
}
#[test]
fn known_refusal_without_go_is_not_sent_and_a_later_reply_cannot_erase_original_go() {
    for go in [false, true] {
        let f = Fixture::new();
        f.inbox.allow(f.scope.clone()).unwrap();
        let input = f.submit(4);
        f.inbox.submit(input.clone()).unwrap();
        let claim = f.inbox.claim().unwrap().unwrap();
        let link = claim.link().clone();
        let operation = "github-play-cleanup-1";
        link.arm(operation).unwrap();
        claim.handoff(operation).unwrap();
        if go {
            link.native_go(operation).unwrap();
        }
        // Inert DATA exercises the existing final metadata reducer; this is
        // not an assertion that any native job or receipt has actually joined.
        link.settled(
            operation,
            p::Effect::NotSent,
            Some(p::Reason::NativeRefused),
        )
        .unwrap();
        let status = f.inbox.query(&input.origin, false).unwrap();
        assert_eq!(
            status.effect,
            if go {
                p::Effect::PotentiallyApplied
            } else {
                p::Effect::NotSent
            }
        );
        assert_eq!(status.reason, Some(p::Reason::NativeRefused));
        assert_eq!(status.settlement, Settlement::Settled);
        assert!(link.native_go(operation).is_err());
        assert_eq!(f.inbox.query(&input.origin, false).unwrap(), status);
    }
}
#[test]
fn prearm_review_expiry_uses_original_end_and_postarm_does_not_renew_read_permission() {
    let f = Fixture::new();
    assert_eq!(
        f.scope
            .stop(f.scope.end + Duration::from_secs(11), false)
            .unwrap(),
        Some((p::Reason::Expired, f.scope.end))
    );
    assert_eq!(
        f.scope
            .stop(f.scope.end + Duration::from_secs(1), true)
            .unwrap(),
        None
    );
    assert_eq!(
        f.scope
            .stop(f.read.end() + Duration::from_secs(1), true)
            .unwrap(),
        Some((p::Reason::Expired, f.read.end()))
    );
}
#[test]
fn dropped_claim_close_and_context_loss_are_not_native_settlement() {
    let f = Fixture::new();
    f.inbox.allow(f.scope.clone()).unwrap();
    let input = f.submit(4);
    f.inbox.submit(input.clone()).unwrap();
    drop(f.inbox.claim().unwrap().unwrap());
    assert_eq!(
        f.inbox.query(&input.origin, false).unwrap().state,
        p::State::Unknown
    );
    f.inbox.close(Instant::now());
    assert_eq!(
        f.inbox.query(&input.origin, false).unwrap().state,
        p::State::Unknown
    );
    assert!(f.inbox.claim().unwrap().is_none());
    let g = Fixture::new();
    g.inbox.allow(g.scope.clone()).unwrap();
    let input = g.submit(4);
    g.inbox.submit(input.clone()).unwrap();
    drop(g.review);
    drop(g.doc);
    let cancelled = g.inbox.query(&input.origin, false).unwrap();
    assert_eq!(cancelled.state, p::State::Cancelled);
    assert_eq!(cancelled.operation_id, None);
}
#[test]
fn known_preinsertion_refusal_keeps_tombstone_and_capacity_does_not_evict_it() {
    let f = Fixture::new();
    for n in 0..p::REQUEST_LIMIT {
        let scope = f.inbox.scope(
            id(2),
            "project-1".into(),
            id(n + 20),
            Instant::now() + Duration::from_secs(60),
            f.read.clone(),
            Arc::downgrade(&f.doc),
            Arc::downgrade(&f.review),
            tokio::sync::watch::channel(0).0,
            1,
        );
        f.inbox.allow(scope.clone()).unwrap();
        let mut input = f.submit(n + 100);
        input.consent_id = scope.consent_id.clone();
        f.inbox.submit(input.clone()).unwrap();
        let claim = f.inbox.claim().unwrap().unwrap();
        claim.not_admitted(Error::Busy).unwrap();
        let refused = f.inbox.query(&input.origin, false).unwrap();
        assert_eq!(refused.state, p::State::Refused);
        assert_eq!(refused.effect, p::Effect::NotSent);
        assert_eq!(refused.operation_id, None);
    }
    assert!(f.inbox.allow(f.scope.clone()).is_err());
    assert_eq!(f.inbox.book.lock().unwrap().entries.len(), p::REQUEST_LIMIT);
    assert!(
        DOCUMENT_BACKING
            >= p::REQUEST_LIMIT * 4096
                + 8 * (crate::service_protocol::REQUEST_BYTES + 2 * p::STATUS_LIMIT)
    );
}
#[test]
fn poisoned_or_fenced_original_inbox_invalidates_already_claimed_link() {
    let f = Fixture::new();
    f.inbox.allow(f.scope.clone()).unwrap();
    f.inbox.submit(f.submit(4)).unwrap();
    let claim = f.inbox.claim().unwrap().unwrap();
    let link = claim.link().clone();
    f.inbox.fence();
    assert_eq!(link.current(false), Err(Error::StateUnknown));
    assert_eq!(link.entry().watchdog_stop().unwrap().unwrap().0, true);
    drop(claim);
    assert!(f.inbox.access().is_err());
}
