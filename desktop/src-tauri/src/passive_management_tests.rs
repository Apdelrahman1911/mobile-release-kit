//! Inert state and native-free current-thread Tokio management tests ONLY.
//! Every driver below returns synthetic data; none calls drive/resolve or starts
//! an OS child. The sole query poll checks executor refusal before registration.
//! Nothing here acquires files or establishes native resource finality.
use super::*;
use std::{future::Future, path::PathBuf, task::{Context, Poll, Waker}};

struct Rig {
    supervisor: Supervisor,
    owner: Arc<Owner>,
    receiver: Option<oneshot::Receiver<Result<Value, BridgeError>>>,
}
fn rig() -> Rig {
    rig_profile(Profile::Passive(Method::Capabilities), None)
}
fn rig_profile(profile: Profile, github_receipt: Option<Arc<Mutex<GitHubReadReceipt>>>) -> Rig {
    let supervisor = Supervisor::new(RuntimeConfig::packaged(PathBuf::from("/inert-never-resolved")));
    let permit = supervisor.inner.permits.clone().try_acquire_owned().unwrap();
    let (reply, receiver) = oneshot::channel();
    let (reply, receiver) = if matches!(profile, Profile::Passive(_)) { (Some(reply), Some(receiver)) }
        else { (None, None) };
    let (stop, _) = watch::channel(false);
    let owner = Arc::new(Owner {
        key: 1, id: "inert-only-1".into(), profile, github_receipt,
        state: Mutex::new(OwnerState::new(Instant::now() + OPERATION_TIME, reply)),
        resources: AsyncMutex::new(Resources::default()), stop, changed: Notify::new(), permit: Mutex::new(Some(permit)),
        driver: AsyncMutex::new(None), watchdog: AsyncMutex::new(None), observer: AsyncMutex::new(None),
        #[cfg(all(feature = "development-runtime"))]
        observation: Arc::new(Mutex::new(hosted_tests::Observation::default())),
    });
    lock(&supervisor.inner.owners).insert(owner.key, owner.clone());
    Rig { supervisor, owner, receiver }
}
fn github_rig() -> (Rig, GitHubReadTicket) {
    let receipt = Arc::new(Mutex::new(GitHubReadReceipt::Pending));
    let rig = rig_profile(Profile::GitHubReadOnly, Some(receipt.clone()));
    let ticket = GitHubReadTicket { owner: rig.owner.clone(), receipt };
    (rig, ticket)
}
fn inert_github_outcome() -> GitHubReadOutcome {
    use crate::github_connection_protocol::{Fact, FactState, GitHubReadControl, GitHubReadFacts, Reason};
    GitHubReadOutcome {
        facts: GitHubReadFacts { schema_version: 1,
            account: Fact { state: FactState::Unavailable, value: None, observed_at: None, reason: Reason::Cancelled },
            repository: Fact { state: FactState::Unavailable, value: None, observed_at: None, reason: Reason::Cancelled },
            automation: Fact { state: FactState::Unavailable, value: None, observed_at: None, reason: Reason::Cancelled } },
        control: GitHubReadControl { reason: Reason::Cancelled, credential_expires_at: None, cooldown_seconds: None, cooldown_blocked: false },
    }
}
fn start_observer(rig: &Rig) {
    let owner = rig.owner.clone();
    let inner = rig.supervisor.inner.clone();
    let guard = FinalObserverGuard { owner: owner.clone(), inner: inner.clone(), retired: false };
    *rig.owner.observer.try_lock().unwrap() = Some(tokio::spawn(async move {
        observe_management(inner, owner).await;
        guard.retired();
    }));
}
fn staged_tasks(rig: &Rig) -> (oneshot::Sender<()>, oneshot::Sender<()>) {
    let (release_driver, driver) = oneshot::channel();
    let (release_watchdog, watchdog_return) = oneshot::channel();
    let outcome = match rig.owner.profile {
        Profile::Passive(_) => ReadOutcome::Passive(Value::String("inert-result".into())),
        Profile::GitHubReadOnly => ReadOutcome::GitHub(inert_github_outcome()),
    };
    *rig.owner.driver.try_lock().unwrap() = Some(tokio::spawn(async move {
        driver.await.unwrap();
        DriverEnd::Ready(Ok(outcome))
    }));
    let owner = rig.owner.clone();
    let inner = rig.supervisor.inner.clone();
    *rig.owner.watchdog.try_lock().unwrap() = Some(tokio::spawn(async move {
        let original = watchdog(inner, owner).await;
        watchdog_return.await.unwrap();
        original
    }));
    start_observer(rig);
    (release_driver, release_watchdog)
}
async fn turns_until(mut condition: impl FnMut() -> bool) {
    // Finite scheduler turns, not an operation clock or native-time claim.
    for _ in 0..1024 {
        if condition() { return; }
        tokio::task::yield_now().await;
    }
    assert!(condition(), "inert original tasks did not reach the expected state");
}
fn assert_retained(rig: &mut Rig) {
    assert!(!rig.supervisor.can_exit());
    assert!(!rig.supervisor.disabled(), "a live observer must not drop its custody guard");
    assert_eq!(rig.supervisor.inner.permits.available_permits(), ACTIVE_LIMIT - 1);
    {
        let state = lock(&rig.owner.state);
        assert!(!state.terminal && !state.unknown && state.error.is_none());
    }
    if let Some(receiver) = &mut rig.receiver {
        assert!(matches!(receiver.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
    }
}
async fn join_settled_observer(rig: &Rig) {
    let mut slot = rig.owner.observer.lock().await;
    tokio::time::timeout(Duration::from_secs(2), slot.as_mut().unwrap()).await
        .expect("inert final observer exceeded the test-only wait bound").unwrap();
    slot.take();
    assert!(rig.supervisor.can_exit());
    assert_eq!(rig.supervisor.inner.permits.available_permits(), ACTIVE_LIMIT);
    let state = lock(&rig.owner.state);
    assert!(state.terminal);
    assert_eq!(state.driver_join, ManagementJoin::Returned);
    assert_eq!(state.watchdog_join, ManagementJoin::Returned);
}
async fn result(rig: &mut Rig) -> Result<Value, BridgeError> {
    tokio::time::timeout(Duration::from_secs(2), rig.receiver.take().unwrap()).await
        .expect("inert response exceeded the test-only wait bound").unwrap()
}
async fn end_inert_retained_observer(rig: &Rig) {
    // Test-only teardown: both inert tasks already produced their actual joins;
    // the remaining observer holds no native resource. This is NEVER authority
    // to abort a production/native owner or to clean an Unknown native fixture.
    {
        let state = lock(&rig.owner.state);
        assert_ne!(state.driver_join, ManagementJoin::Pending);
        assert_ne!(state.watchdog_join, ManagementJoin::Pending);
        let resources = rig.owner.resources.try_lock().unwrap();
        assert!(resources.inspection.is_none() && resources.acquisition.is_none() && resources.child.is_none()
            && resources.writer.is_none() && resources.stdout.is_none() && resources.stderr.is_none());
    }
    let mut slot = rig.owner.observer.lock().await;
    let original = slot.as_mut().unwrap();
    original.abort();
    assert!(original.await.unwrap_err().is_cancelled());
    slot.take();
}

#[tokio::test(flavor = "current_thread")]
async fn original_returns_precede_reply_permit_and_registry_retirement() {
    let mut rig = rig();
    let (driver, watchdog) = staged_tasks(&rig);
    tokio::task::yield_now().await;
    assert_retained(&mut rig);
    driver.send(()).unwrap();
    turns_until(|| lock(&rig.owner.state).driver_join == ManagementJoin::Returned).await;
    assert_retained(&mut rig); // Native-ready synthetic data still is not manager finality.
    assert_eq!(lock(&rig.owner.state).watchdog_join, ManagementJoin::Pending);
    watchdog.send(()).unwrap();
    assert_eq!(result(&mut rig).await.unwrap(), Value::String("inert-result".into()));
    assert!(rig.supervisor.can_exit()); // Reply cannot precede slot/registry return.
    join_settled_observer(&rig).await;
    assert!(!rig.supervisor.disabled());
}

#[tokio::test(flavor = "current_thread")]
async fn abandoned_reply_and_shutdown_observer_do_not_own_management() {
    let mut rig = rig();
    let (driver, watchdog) = staged_tasks(&rig);
    drop(rig.receiver.take());
    let mut shutdown = Box::pin(rig.supervisor.shutdown());
    let first_poll = std::future::poll_fn(|cx| Poll::Ready(shutdown.as_mut().poll(cx))).await;
    assert!(first_poll.is_pending());
    drop(shutdown);
    let first_deadline = lock(&rig.owner.state).cleanup_endpoint;
    assert!(first_deadline.is_some());
    assert!(*rig.owner.stop.subscribe().borrow());
    driver.send(()).unwrap();
    watchdog.send(()).unwrap();
    join_settled_observer(&rig).await;
    assert_eq!(lock(&rig.owner.state).cleanup_endpoint, first_deadline);
    assert_eq!(lock(&rig.owner.state).error.as_ref().unwrap().code, "shutting_down");
}

#[tokio::test(flavor = "current_thread")]
async fn actual_driver_and_watchdog_panics_are_observed_without_repoll_or_retirement() {
    for driver_fails in [true, false] {
        let mut rig = rig();
        if driver_fails {
            *rig.owner.driver.try_lock().unwrap() = Some(tokio::spawn(async { panic!("inert driver failure") }));
            let owner = rig.owner.clone(); let inner = rig.supervisor.inner.clone();
            *rig.owner.watchdog.try_lock().unwrap() = Some(tokio::spawn(watchdog(inner, owner)));
        } else {
            // The original driver is held behind its empty resource book, to
            // prove watchdog failure observation never needs that book lock.
            let owner = rig.owner.clone();
            *rig.owner.driver.try_lock().unwrap() = Some(tokio::spawn(async move {
                let _book = owner.resources.lock().await;
                DriverEnd::Ready(Ok(ReadOutcome::Passive(Value::Null)))
            }));
            *rig.owner.watchdog.try_lock().unwrap() = Some(tokio::spawn(async { panic!("inert watchdog failure") }));
        }
        let retained_owner = rig.owner.clone();
        let held = retained_owner.resources.lock().await;
        start_observer(&rig);
        turns_until(|| rig.supervisor.disabled()).await;
        assert!(!rig.supervisor.can_exit());
        assert_eq!(rig.supervisor.inner.permits.available_permits(), ACTIVE_LIMIT - 1);
        assert_eq!(result(&mut rig).await.unwrap_err().code, "cleanup_unknown");
        drop(held);
        turns_until(|| {
            let state = lock(&rig.owner.state);
            state.driver_join != ManagementJoin::Pending && state.watchdog_join != ManagementJoin::Pending
        }).await;
        {
            let state = lock(&rig.owner.state);
            assert_eq!(state.driver_join, if driver_fails { ManagementJoin::Panicked } else { ManagementJoin::Returned });
            assert_eq!(state.watchdog_join, if driver_fails { ManagementJoin::Returned } else { ManagementJoin::Panicked });
            assert!(state.unknown && !state.terminal);
        }
        // Failed original slots are inspected only after the sole observer is
        // joined; neither the fixture nor another observer consumes them again.
        end_inert_retained_observer(&rig).await;
        assert_eq!(rig.owner.driver.try_lock().unwrap().is_some(), driver_fails);
        assert_eq!(rig.owner.watchdog.try_lock().unwrap().is_some(), !driver_fails);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn guard_covers_observer_loss_before_its_first_poll() {
    let mut rig = rig();
    let guard = FinalObserverGuard { inner: rig.supervisor.inner.clone(), owner: rig.owner.clone(), retired: false };
    let original = tokio::spawn(async move { let _guard = guard; pending::<()>().await; });
    // Current-thread executor: this original has not been polled yet.
    original.abort();
    assert!(original.await.unwrap_err().is_cancelled());
    assert!(rig.supervisor.disabled());
    assert!(!rig.supervisor.can_exit());
    assert_eq!(rig.supervisor.inner.permits.available_permits(), ACTIVE_LIMIT - 1);
    assert!(*rig.owner.stop.subscribe().borrow());
    assert_eq!(result(&mut rig).await.unwrap_err().code, "cleanup_unknown");
    assert_eq!(lock(&rig.owner.state).driver_join, ManagementJoin::Pending);
}

#[tokio::test(flavor = "current_thread")]
async fn missing_roster_and_unexplained_early_watchdog_return_fail_closed() {
    let mut rig = rig();
    // Missing is not no-attempt/returned proof; an early typed observation of
    // Pending cannot later become a legal watchdog stop reason.
    *rig.owner.watchdog.try_lock().unwrap() = Some(tokio::spawn(async { WatchdogEnd::DriverObserved(ManagementJoin::Pending) }));
    start_observer(&rig);
    turns_until(|| lock(&rig.owner.state).watchdog_join != ManagementJoin::Pending).await;
    assert_eq!(result(&mut rig).await.unwrap_err().code, "cleanup_unknown");
    assert_eq!(lock(&rig.owner.state).driver_join, ManagementJoin::Missing);
    assert_eq!(lock(&rig.owner.state).watchdog_join, ManagementJoin::InvalidReturn);
    assert!(!rig.supervisor.can_exit());
    end_inert_retained_observer(&rig).await;
    assert!(rig.owner.watchdog.try_lock().unwrap().is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn incomplete_roster_locks_prevent_even_fast_originals_from_retiring() {
    let mut rig = rig();
    let mut driver = rig.owner.driver.try_lock().unwrap();
    let mut watch_slot = rig.owner.watchdog.try_lock().unwrap();
    *driver = Some(tokio::spawn(async { DriverEnd::Ready(Ok(ReadOutcome::Passive(Value::Null))) }));
    let owner = rig.owner.clone(); let inner = rig.supervisor.inner.clone();
    *watch_slot = Some(tokio::spawn(watchdog(inner, owner)));
    start_observer(&rig);
    tokio::task::yield_now().await;
    assert!(!rig.supervisor.can_exit());
    assert!(!rig.supervisor.disabled(), "roster contention must not drop the observer's guard");
    assert_eq!(lock(&rig.owner.state).driver_join, ManagementJoin::Pending);
    assert!(matches!(rig.receiver.as_mut().unwrap().try_recv(), Err(oneshot::error::TryRecvError::Empty)));
    drop(watch_slot); drop(driver);
    join_settled_observer(&rig).await;
    assert_eq!(result(&mut rig).await.unwrap(), Value::Null);
}

#[test]
fn same_clock_latches_once_and_does_not_self_notify_after_expiry() {
    let rig = rig();
    let endpoint = lock(&rig.owner.state).endpoint;
    assert_eq!(rig.owner.advance_clock(&rig.supervisor.inner, endpoint), Some(endpoint + CLEANUP_TIME));
    rig.owner.fail(BridgeError::shutdown());
    let first = lock(&rig.owner.state).cleanup_endpoint;
    assert_eq!(first, Some(endpoint + CLEANUP_TIME));
    assert_eq!(rig.owner.advance_clock(&rig.supervisor.inner, endpoint + CLEANUP_TIME), None);
    let mut changed = Box::pin(rig.owner.changed.notified());
    assert_eq!(rig.owner.advance_clock(&rig.supervisor.inner, endpoint + CLEANUP_TIME + Duration::from_secs(3)), None);
    assert!(changed.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    assert_eq!(lock(&rig.owner.state).cleanup_endpoint, first);
    assert_eq!(lock(&rig.owner.state).error.as_ref().unwrap().code, "query_timeout");
    assert!(lock(&rig.owner.state).unknown);
    assert!(rig.supervisor.disabled());
}

#[tokio::test(flavor = "current_thread")]
async fn late_actual_joins_allow_exit_but_never_restore_success_or_capability() {
    let mut rig = rig();
    let (driver, watchdog) = staged_tasks(&rig);
    driver.send(()).unwrap();
    turns_until(|| lock(&rig.owner.state).driver_join == ManagementJoin::Returned).await;
    let endpoint = lock(&rig.owner.state).endpoint;
    // Inert same-clock decision only: no elapsed native deadline is claimed.
    rig.owner.advance_clock(&rig.supervisor.inner, endpoint + CLEANUP_TIME);
    assert_eq!(result(&mut rig).await.unwrap_err().code, "cleanup_unknown");
    let first = lock(&rig.owner.state).cleanup_endpoint;
    assert!(!rig.supervisor.can_exit());
    watchdog.send(()).unwrap();
    join_settled_observer(&rig).await;
    assert!(rig.supervisor.disabled());
    assert!(lock(&rig.owner.state).unknown);
    assert_eq!(lock(&rig.owner.state).cleanup_endpoint, first);
}

#[test]
fn executor_refusal_precedes_registration_or_native_work() {
    let supervisor = Supervisor::new(RuntimeConfig::packaged(PathBuf::from("/inert-never-resolved")));
    let mut query = Box::pin(supervisor.query(Method::Capabilities, serde_json::json!({})));
    let result = query.as_mut().poll(&mut Context::from_waker(Waker::noop()));
    assert!(matches!(result, Poll::Ready(Err(_))));
    assert!(supervisor.can_exit());
    assert_eq!(supervisor.inner.permits.available_permits(), ACTIVE_LIMIT);
    assert!(supervisor.start_github_readonly("owner/app", None, None, "INERT_ONLY").is_err());
    assert!(supervisor.can_exit());
    assert_eq!(supervisor.inner.permits.available_permits(), ACTIVE_LIMIT);
}

#[test]
fn serialized_retirement_rechecks_same_clock_and_shutdown_with_ready_joins() {
    fn ready(endpoint: Instant) -> OwnerState {
        let mut state = OwnerState::new(endpoint, None);
        state.driver_join = ManagementJoin::Returned;
        state.watchdog_join = ManagementJoin::Returned;
        state.driver_end = Some(DriverEnd::Ready(Ok(ReadOutcome::Passive(Value::Null))));
        state.watchdog_end = Some(WatchdogEnd::DriverObserved(ManagementJoin::Returned));
        state
    }
    let start = Instant::now();
    let endpoint = start + OPERATION_TIME;
    // These synthetic management receipts test only the actual final locked
    // decision. No child, native lifetime, elapsed timeout or exit is claimed.
    let mut before = ready(endpoint);
    assert_eq!(before.retirement_result(endpoint - Duration::from_nanos(1), false).unwrap().unwrap(), ReadOutcome::Passive(Value::Null));
    assert!(before.cleanup_endpoint.is_none());

    let mut at = ready(endpoint);
    assert_eq!(at.retirement_result(endpoint, false).unwrap().unwrap_err().code, "query_timeout");
    assert_eq!(at.cleanup_endpoint, Some(endpoint + CLEANUP_TIME));
    assert!(!at.unknown);

    let first_failure = start + Duration::from_secs(1);
    let cleanup_endpoint = first_failure + CLEANUP_TIME;
    let mut cleanup = ready(endpoint);
    cleanup.fail_at(BridgeError::shutdown(), first_failure);
    assert_eq!(cleanup.retirement_result(cleanup_endpoint, false).unwrap().unwrap_err().code, "cleanup_unknown");
    assert!(cleanup.unknown);
    assert_eq!(cleanup.cleanup_endpoint, Some(cleanup_endpoint));
    assert_eq!(cleanup.error.as_ref().unwrap().code, "shutting_down");

    let mut stopped = ready(endpoint);
    assert_eq!(stopped.retirement_result(start, true).unwrap().unwrap_err().code, "shutting_down");
    assert_eq!(stopped.cleanup_endpoint, Some(start + CLEANUP_TIME));

    let mut both_ready = ready(endpoint);
    assert_eq!(both_ready.retirement_result(endpoint, true).unwrap().unwrap_err().code, "shutting_down");
    assert_eq!(both_ready.cleanup_endpoint, Some(endpoint + CLEANUP_TIME));

    let mut unknown = ready(endpoint);
    unknown.unknown = true;
    assert_eq!(unknown.retirement_result(start, false).unwrap().unwrap_err().code, "cleanup_unknown");
    assert!(unknown.unknown);
}

#[tokio::test(flavor = "current_thread")]
async fn github_receipt_waits_for_original_management_and_keeps_original_settlement_time() {
    let (mut rig, ticket) = github_rig();
    let (driver, watchdog) = staged_tasks(&rig);
    assert_eq!(ticket.operation_id(), "inert-only-1");
    driver.send(()).unwrap();
    turns_until(|| lock(&rig.owner.state).driver_join == ManagementJoin::Returned).await;
    assert_retained(&mut rig);
    assert!(matches!(ticket.receipt(), GitHubReadReceipt::Pending));
    watchdog.send(()).unwrap();
    join_settled_observer(&rig).await;
    let GitHubReadReceipt::Settled { outcome, settled_at, was_unknown } = ticket.receipt() else {
        panic!("original retirement did not seal its safe-data mailbox");
    };
    assert_eq!(outcome.unwrap(), inert_github_outcome());
    assert!(!was_unknown);
    let GitHubReadReceipt::Settled { settled_at: repeated, .. } = ticket.receipt() else { panic!("receipt regressed"); };
    assert_eq!(settled_at, repeated); // Observation never renews time authority.
}

#[tokio::test(flavor = "current_thread")]
async fn github_stop_and_ticket_drop_are_not_original_settlement() {
    let (rig, ticket) = github_rig();
    let (driver, watchdog) = staged_tasks(&rig);
    let receipt = ticket.receipt.clone();
    ticket.stop();
    let original_cleanup = lock(&rig.owner.state).cleanup_endpoint;
    assert!(original_cleanup.is_some());
    assert!(matches!(ticket.receipt(), GitHubReadReceipt::Pending));
    ticket.stop();
    assert_eq!(lock(&rig.owner.state).cleanup_endpoint, original_cleanup);
    assert!(!rig.supervisor.can_exit());
    drop(ticket);
    assert!(!rig.supervisor.can_exit());
    assert_eq!(rig.supervisor.inner.permits.available_permits(), ACTIVE_LIMIT - 1);
    driver.send(()).unwrap(); watchdog.send(()).unwrap();
    join_settled_observer(&rig).await;
    let retained = lock(&receipt).clone();
    let GitHubReadReceipt::Settled { outcome, was_unknown, .. } = retained else { panic!("no original retirement"); };
    assert_eq!(outcome.unwrap_err().code, "cancelled");
    assert!(!was_unknown);
}

#[tokio::test(flavor = "current_thread")]
async fn github_unknown_mailbox_can_finish_but_never_regains_success() {
    let (rig, ticket) = github_rig();
    let (driver, watchdog) = staged_tasks(&rig);
    driver.send(()).unwrap();
    turns_until(|| lock(&rig.owner.state).driver_join == ManagementJoin::Returned).await;
    rig.owner.unknown(&rig.supervisor.inner);
    assert!(matches!(ticket.receipt(), GitHubReadReceipt::RetainedUnknown));
    assert!(!rig.supervisor.can_exit());
    watchdog.send(()).unwrap();
    join_settled_observer(&rig).await;
    let GitHubReadReceipt::Settled { outcome, settled_at, was_unknown } = ticket.receipt() else { panic!("no late original receipt"); };
    assert!(was_unknown);
    assert_eq!(outcome.unwrap_err().code, "cleanup_unknown");
    rig.owner.unknown(&rig.supervisor.inner);
    let GitHubReadReceipt::Settled { settled_at: repeated, was_unknown: repeated_unknown, .. } = ticket.receipt() else { panic!("late unknown regressed finality"); };
    assert_eq!(settled_at, repeated);
    assert!(repeated_unknown && rig.supervisor.disabled());
}

#[tokio::test(flavor = "current_thread")]
async fn github_guard_loss_only_reports_retained_unknown_and_never_fabricates_a_receipt() {
    let (rig, ticket) = github_rig();
    let guard = FinalObserverGuard { inner: rig.supervisor.inner.clone(), owner: rig.owner.clone(), retired: false };
    let original = tokio::spawn(async move { let _guard = guard; pending::<()>().await; });
    // As in the passive guard fixture: an unpolled synthetic future with no
    // runtime inspection/native resources. Never a production cleanup strategy.
    original.abort();
    assert!(original.await.unwrap_err().is_cancelled());
    assert!(matches!(ticket.receipt(), GitHubReadReceipt::RetainedUnknown));
    assert!(rig.supervisor.disabled() && !rig.supervisor.can_exit());
    assert_eq!(rig.supervisor.inner.permits.available_permits(), ACTIVE_LIMIT - 1);
}
