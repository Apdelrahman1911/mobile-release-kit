//! Inert state/clock tests. No executor, child, project IO or qualification.
//! The existing test-only identity is predicate DATA, never sent to a runtime.
use super::*;
use std::path::PathBuf;
use serde_json::json;

fn owner() -> OfflinePreflightOwner { OfflinePreflightOwner::new(RuntimeConfig::packaged(PathBuf::from("/unopened-runtime"))) }
fn project() -> RegisteredRoot { RegisteredRoot { path: PathBuf::from("/unopened-preflight-project"),
    identity: crate::asset_source::DirectoryIdentity::synthetic_evidence_identity() } }
fn projection() -> wire::Projection { wire::Projection { operation_id: "a".repeat(32), owner_generation: "b".repeat(32),
    context: wire::tests::context(), phase: Phase::AwaitingConsent, intent_usable: true,
    outcome: None, reason: Reason::None, result: None } }
fn prepared(owner: &OfflinePreflightOwner, expires: Instant) {
    owner.inner.lock().prepared = Some(Prepared { projection: projection(), expires, registration: 1, project: project() });
}
fn start_input(id: &str) -> Start { wire::start(&json!({"operationId":id,"ownerGeneration":"b".repeat(32),"consentVersion":wire::CONSENT})).unwrap() }
fn active() -> (OfflinePreflightOwner, Arc<Session>) {
    let owner = owner(); let p = projection();
    let (stop, _) = watch::channel(false); let (pipes, _) = watch::channel(Pipes::Pending); let (frames, receiver) = mpsc::channel(2);
    let session = Arc::new(Session { id: p.operation_id.clone(), generation: p.owner_generation.clone(), context: p.context.clone(),
        profile: Profile::LinuxX64, clocks: Clocks::new(Instant::now()), registration: 1, project: project(), request: AsyncMutex::new(None),
        stop, pipes, frames, wake: Notify::new(), output_bytes: AtomicUsize::new(0), resource_unknown: AtomicBool::new(false),
        driver_done: AtomicBool::new(false), driver_joined: AtomicBool::new(false), driver_failed: AtomicBool::new(false),
        watchdog_joined: AtomicBool::new(false), watchdog_failed: AtomicBool::new(false), manager_failed: AtomicBool::new(false),
        startup: Mutex::new(Startup::default()), resources: AsyncMutex::new(Resources { frames: Some(receiver), ..Resources::default() }),
        input: Arc::new(AsyncMutex::new(Pipe::default())), output: Arc::new(AsyncMutex::new(Pipe::default())), error: Arc::new(AsyncMutex::new(Pipe::default())),
        driver: AsyncMutex::new(None), watchdog: Mutex::new(None), manager: AsyncMutex::new(None), observer: AsyncMutex::new(None),
        driver_return: Mutex::new(None), manager_return: Mutex::new(None), observer_return: Mutex::new(None), watchdog_return: Mutex::new(None) });
    let p = RunProjection { operation_id: p.operation_id, owner_generation: p.owner_generation, context: p.context,
        phase: Phase::Starting, outcome: None, reason: Reason::None, result: None };
    owner.inner.lock().active = Some(Active { owner: session.clone(), projection: p, first_stop: None, work_expired: false,
        accepted: false, terminal: false, unknown: false, final_join_seen: false });
    (owner, session)
}

#[test]
fn qualification_is_closed_without_a_runtime_or_another_owners_permit() {
    let owner = owner(); assert!(!owner.inner.qualified());
    let status = owner.status(Availability::Available).unwrap();
    assert!(matches!(status.availability, Availability::RuntimeUnqualified | Availability::UnsupportedPlatform));
    assert!(status.operation.is_none()); assert!(owner.can_exit());
    let input = wire::prepare(&json!({"projectId":"inert-project","draftRevision":2,"baselineGeneration":3,
        "savedConfig":{"bytes":123,"sha256":"c".repeat(64)}})).unwrap();
    assert!(owner.prepare(input, 1, project(), Availability::Available).is_err());
    assert!(owner.inner.lock().prepared.is_none()); assert!(owner.inner.lock().active.is_none());
}

#[test]
fn no_owner_startup_and_unsupported_status_do_not_claim_document_loss() {
    let owner = owner();
    let initial = owner.status(Availability::Busy).unwrap();
    assert!(initial.operation.is_none());
    assert_eq!(initial.availability, if Profile::current().is_some() { Availability::Busy } else { Availability::UnsupportedPlatform });
    let bound = owner.status(Availability::Available).unwrap();
    assert_eq!(bound.availability, if Profile::current().is_some() { Availability::RuntimeUnqualified } else { Availability::UnsupportedPlatform });
    assert!(bound.operation.is_none());
    if initial.availability != bound.availability { assert!(bound.status_revision > initial.status_revision); }
    owner.document_lost();
    let lost = owner.status(Availability::DocumentLost).unwrap();
    assert_eq!(lost.availability, if Profile::current().is_some() { Availability::DocumentLost } else { Availability::UnsupportedPlatform });
    assert!(lost.operation.is_none());
    // Supplied unsupported capability DATA only, never a host or runtime permit.
    let unsupported = owner.status(Availability::UnsupportedPlatform).unwrap();
    assert_eq!(unsupported.availability, Availability::UnsupportedPlatform);
    assert!(unsupported.operation.is_none()); assert!(owner.can_exit());
    if lost.availability != unsupported.availability { assert!(unsupported.status_revision > lost.status_revision); }
}

#[test]
fn intent_expires_with_a_new_revision_and_cancel_never_creates_an_owner() {
    let owner = owner(); prepared(&owner, Instant::now() + INTENT);
    let before = owner.status(Availability::Available).unwrap();
    assert!(before.operation.as_ref().unwrap().intent_usable);
    let expiry = Instant::now(); owner.inner.lock().prepared.as_mut().unwrap().expires = expiry;
    owner.inner.expire_prepared(&mut owner.inner.lock(), expiry);
    let after = owner.status(Availability::Available).unwrap();
    assert!(after.status_revision > before.status_revision);
    let operation = after.operation.unwrap(); assert!(!operation.intent_usable);
    assert_eq!((operation.phase, operation.outcome, operation.reason), (Phase::Terminal, Some(Outcome::Refused), Reason::IntentExpired));
    assert!(owner.inner.lock().active.is_none());
    prepared(&owner, Instant::now() + INTENT);
    let status = owner.cancel(&"a".repeat(32), &"b".repeat(32), Availability::Available).unwrap();
    assert_eq!(status.operation.unwrap().outcome, Some(Outcome::Cancelled));
    assert!(owner.inner.lock().prepared.is_none()); assert!(owner.inner.lock().active.is_none());
}

#[test]
fn start_burns_before_unavailability_and_foreign_start_grants_nothing() {
    let owner = owner(); prepared(&owner, Instant::now() + INTENT);
    assert!(owner.start(start_input(&"f".repeat(32)), Instant::now(), Some((1, project())), Availability::Available).is_err());
    assert!(owner.inner.lock().prepared.is_some());
    let status = owner.start(start_input(&"a".repeat(32)), Instant::now(), Some((1, project())), Availability::Available).unwrap().release();
    assert!(owner.inner.lock().prepared.is_none()); assert!(owner.inner.lock().active.is_none());
    assert_eq!(status.operation.unwrap().outcome, Some(Outcome::Refused));
    assert!(owner.start(start_input(&"a".repeat(32)), Instant::now(), Some((1, project())), Availability::Available).is_err());
}

#[test]
fn whole_run_endpoints_and_first_stop_never_renew() {
    let (owner, session) = active(); let t = session.clocks.admitted;
    assert_eq!(session.clocks.work, t + WORK); assert_eq!(session.clocks.finality, t + HARD);
    let first = t + Duration::from_secs(5);
    let mut r = owner.inner.lock();
    owner.inner.stop_locked(&mut r, &session, Reason::Cancelled, first);
    owner.inner.stop_locked(&mut r, &session, Reason::ProtocolError, first + Duration::from_secs(9));
    let a = r.active.as_ref().unwrap(); assert_eq!(a.first_stop, Some(first));
    assert_eq!(session.clocks.settlement(a.first_stop), first + SETTLEMENT);
    owner.inner.advance_locked(&mut r, &session, first + SETTLEMENT);
    let a = r.active.as_ref().unwrap(); assert!(a.unknown && r.disabled); assert_eq!(a.first_stop, Some(first));
    let p = a.projection.public(); assert_eq!((p.phase, p.outcome, p.reason), (Phase::Unknown, Some(Outcome::Unknown), Reason::CleanupUnknown));
    assert!(p.result.is_none());
}

#[test]
fn complete_negative_is_provisional_and_not_first_failure() {
    let (owner, session) = active(); let t = session.clocks.admitted;
    owner.inner.accept_at(&session, Frame::Accepted, t);
    owner.inner.accept_at(&session, wire::tests::terminal_frame(&session.context), t + Duration::from_secs(1));
    let mut r = owner.inner.lock();
    let a = r.active.as_ref().unwrap(); assert!(a.first_stop.is_none() && a.projection.result.is_some());
    let p = a.projection.public(); assert_eq!(p.phase, Phase::Stopping); assert!(p.outcome.is_none() && p.result.is_none());
    // An unjoined native result cannot win over a later original Cancel.
    owner.inner.stop_locked(&mut r, &session, Reason::Cancelled, t + Duration::from_secs(2));
    assert_eq!(r.active.as_ref().unwrap().projection.outcome, Some(Outcome::Cancelled));
}

#[test]
fn late_terminal_never_reverses_timeout_or_unknown_in_either_delivery_order() {
    for due in [WORK, HARD] { for clock_first in [false, true] {
        let (owner, session) = active(); let now = session.clocks.admitted + due;
        owner.inner.accept_at(&session, Frame::Accepted, session.clocks.admitted);
        if clock_first { owner.inner.advance_locked(&mut owner.inner.lock(), &session, now); }
        owner.inner.accept_at(&session, wire::tests::terminal_frame(&session.context), now);
        owner.inner.advance_locked(&mut owner.inner.lock(), &session, now);
        let r = owner.inner.lock(); let a = r.active.as_ref().unwrap();
        assert_eq!(a.projection.reason, Reason::TimedOut); assert_eq!(a.projection.outcome, Some(Outcome::TimedOut));
        assert_eq!(a.unknown, due == HARD); assert!(a.projection.public().result.is_none()); assert!(r.last.is_none());
    } }
}

#[test]
fn repeated_unknown_polling_does_not_publish_new_results_or_extend_clocks() {
    let (owner, session) = active();
    owner.inner.advance_locked(&mut owner.inner.lock(), &session, session.clocks.finality);
    let before = { let r = owner.inner.lock(); (r.revision, r.active.as_ref().unwrap().first_stop) };
    for _ in 0..8 {
        assert!(owner.inner.endpoint(&session).is_none());
        let r = owner.inner.lock(); let a = r.active.as_ref().unwrap();
        assert_eq!((r.revision, a.first_stop), before); assert!(a.unknown && r.disabled && r.last.is_none());
    }
}
