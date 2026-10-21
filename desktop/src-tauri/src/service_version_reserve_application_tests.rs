//! Actual Service/Grant/private-Store fixtures, with inert Review comparison
//! DATA only. No native Review, Lane, credential, provider, GO or join receipt
//! is manufactured. Dropping an unreturned memory claim remains Unknown.
use super::*;
use crate::application_service::tests::{
    passive, poison_fixture, register_fixture, with_state_locked,
};
use crate::application_state_store::Fixture;
use std::{sync::mpsc, thread};

#[path = "service_version_reserve_review_application_tests.rs"]
mod source_review;

const OBSERVER_BOUND: Duration = Duration::from_secs(5);

fn setup() -> (
    Fixture,
    Arc<PrivateStateDirectory>,
    Arc<ApplicationService>,
    Id,
) {
    let fixture = Fixture::new();
    let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
    let service = Arc::new(ApplicationService::open(store.clone()).unwrap());
    let (project, root) = register_fixture(&service, &fixture.app, "project", "project-1");
    service
        .publish_passive_snapshot("project-1", &passive(&root, &"a".repeat(64)))
        .unwrap();
    (fixture, store, service, project)
}

fn read_client(service: &ApplicationService, project: &Id, lifetime: Duration) -> ClientSession {
    service
        .allow_agent_read(vec![project.clone()], lifetime)
        .unwrap();
    service.admit_client().unwrap()
}

fn comparison_scope(
    service: &ApplicationService,
) -> (Arc<requests::NativeScope>, Arc<()>, Arc<()>) {
    let point = service.version_reserve_point("project-1").unwrap();
    let document = Arc::new(());
    let review = Arc::new(());
    let scope = Arc::new(requests::NativeScope {
        project_id: point.saved.project_id,
        runtime_id: point.saved.runtime_id,
        review_id: Id::random().unwrap(),
        review_revision: 1,
        review_end: Instant::now() + Duration::from_secs(110),
        read: point.read, // The genuine original Grant facet, not a fresh clock.
        document: Arc::downgrade(&document),
        review: Arc::downgrade(&review),
        changes: tokio::sync::watch::channel(0).0,
    });
    (scope, document, review)
}

fn submit_data(service: &ApplicationService, scope: &requests::NativeScope) -> wire::Submit {
    wire::Submit {
        origin: wire::Query {
            project_id: scope.project_id.clone(),
            service_instance: service.instance().clone(),
            request_id: Id::random().unwrap(),
        },
        grant_id: Id::random().unwrap(),
        review_id: scope.review_id.clone(),
    }
}

fn reply(result: Result<p::ResponseBody, Error>) -> wire::Status {
    match result.unwrap() {
        p::ResponseBody::VersionReserveRequest(value) => value,
        _ => panic!("expected the closed Reserve response"),
    }
}

#[test]
fn actual_read_and_review_grants_are_both_required_and_reconnect_keeps_original() {
    let (_fixture, store, service, project) = setup();
    assert_eq!(service.admit_client().err(), Some(Error::AccessDenied));
    assert_eq!(
        service.version_reserve_point("project-1").err(),
        Some(Error::AccessDenied)
    );
    let first = read_client(&service, &project, Duration::from_secs(300));
    let (scope, _document, _review) = comparison_scope(&service);
    let input = submit_data(&service, &scope);
    let before = store.read(Namespace::Projects).unwrap();

    assert_eq!(
        service
            .service_version_reserve_submit(&first, input.clone())
            .err(),
        Some(Error::AccessDenied)
    );
    assert!(service
        .version_reserve_requests()
        .claim()
        .unwrap()
        .is_none());
    service
        .version_reserve_requests()
        .allow(scope.clone(), input.grant_id.clone())
        .unwrap();
    let queued = reply(service.service_version_reserve_submit(&first, input.clone()));
    assert_eq!(queued.state, wire::State::Queued);
    assert_eq!(queued.settlement, p::Settlement::Pending);
    assert!(queued.operation_id.is_none());
    let claim = service.version_reserve_requests().claim().unwrap().unwrap();

    let reconnected = service.admit_client().unwrap();
    assert_ne!(first.client_id, reconnected.client_id);
    assert_ne!(first.session_id, reconnected.session_id);
    assert_eq!(
        reply(service.service_version_reserve_submit(&reconnected, input.clone())),
        queued
    );
    assert_eq!(
        reply(service.service_version_reserve_query(&reconnected, &input.origin, false)),
        queued
    );
    let mut changed = input.clone();
    changed.review_id = Id::random().unwrap();
    assert_eq!(
        service
            .service_version_reserve_submit(&reconnected, changed)
            .err(),
        Some(Error::Conflict)
    );
    assert!(service
        .version_reserve_requests()
        .claim()
        .unwrap()
        .is_none());
    assert!(claim.entry().first_stop().unwrap().is_none());

    // These are the exact current-project guards used for this response at
    // the existing IPC pre-send seam; no socket/native execution is claimed.
    assert_eq!(
        service.android_tools_client_current(&reconnected, &project),
        Ok(())
    );
    service.revoke_agent_read().unwrap();
    assert_eq!(
        service
            .service_version_reserve_query(&reconnected, &input.origin, true)
            .err(),
        Some(Error::AccessDenied)
    );
    assert_eq!(
        service.android_tools_client_current(&reconnected, &project),
        Err(Error::AccessDenied)
    );
    let stopped = claim.entry().status().unwrap();
    assert_eq!(stopped.state, wire::State::Stopping);
    assert_eq!(stopped.reason, Some(wire::Reason::PermissionRevoked));
    assert_eq!(stopped.settlement, p::Settlement::Pending);
    assert!(stopped.reservation.is_none());
    let after = store.read(Namespace::Projects).unwrap();
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.bytes, before.bytes);

    drop(claim);
    service.stop().unwrap();
    store.close().unwrap();
}

#[test]
fn actual_grant_renewal_revokes_old_facet_but_clones_cannot_revoke_or_renew() {
    let (_fixture, store, service, project) = setup();
    let first = read_client(&service, &project, Duration::from_secs(300));
    let (scope, _document, _review) = comparison_scope(&service);
    let input = submit_data(&service, &scope);
    service
        .version_reserve_requests()
        .allow(scope.clone(), input.grant_id.clone())
        .unwrap();
    reply(service.service_version_reserve_submit(&first, input.clone()));
    let claim = service.version_reserve_requests().claim().unwrap().unwrap();
    let copied = scope.read.clone();
    let point = service.version_reserve_point("project-1").unwrap();
    assert!(Arc::ptr_eq(&copied, &point.read));
    drop(point);
    drop(copied);
    assert_eq!(claim.link().current(false), Ok(()));
    assert_eq!(service.version_reserve_original_current(&scope), Ok(()));

    let renewal_begin = Instant::now();
    let current = read_client(&service, &project, Duration::from_secs(300));
    let renewal_end = Instant::now();
    let next = service.version_reserve_point("project-1").unwrap();
    assert!(!Arc::ptr_eq(&scope.read, &next.read));
    assert_eq!(service.client_current(&first), Err(Error::AccessDenied));
    assert_eq!(service.client_current(&current), Ok(()));
    assert_eq!(
        service.version_reserve_original_current(&scope),
        Err(Error::Conflict)
    );
    assert!(claim.link().current(false).is_err());
    let first_stop = claim.entry().first_stop().unwrap().unwrap();
    assert_eq!(first_stop.0, wire::Reason::PermissionRevoked);
    assert!(renewal_begin <= first_stop.1 && first_stop.1 <= renewal_end);
    let stopped = claim.entry().status().unwrap();
    let retried = reply(service.service_version_reserve_submit(&current, input.clone()));
    assert_eq!(retried.origin, stopped.origin);
    assert_eq!(retried.grant_id, stopped.grant_id);
    assert_eq!(retried.review_id, stopped.review_id);
    assert_eq!(retried.operation_id, stopped.operation_id);
    assert_eq!(retried.state, wire::State::Stopping);
    assert_eq!(retried.reason, stopped.reason);
    assert_eq!(retried.settlement, p::Settlement::Pending);
    assert!(retried.revision >= stopped.revision);
    assert!(retried.reservation.is_none());
    let (new_scope, _new_document, _new_review) = comparison_scope(&service);
    assert_eq!(
        service
            .version_reserve_requests()
            .allow(new_scope, Id::random().unwrap())
            .err(),
        Some(Error::Busy)
    );
    assert!(service
        .version_reserve_requests()
        .claim()
        .unwrap()
        .is_none());
    service.revoke_agent_read().unwrap();
    assert_eq!(claim.entry().first_stop().unwrap(), Some(first_stop));
    assert_eq!(
        claim.entry().status().unwrap().settlement,
        p::Settlement::Pending
    );

    drop(claim);
    service.stop().unwrap();
    store.close().unwrap();
}

#[test]
fn original_service_grant_drop_revokes_the_surviving_comparison_link() {
    let (_fixture, store, service, project) = setup();
    let client = read_client(&service, &project, Duration::from_secs(300));
    let (scope, _document, _review) = comparison_scope(&service);
    let input = submit_data(&service, &scope);
    service
        .version_reserve_requests()
        .allow(scope.clone(), input.grant_id.clone())
        .unwrap();
    reply(service.service_version_reserve_submit(&client, input));
    let claim = service.version_reserve_requests().claim().unwrap().unwrap();
    let retained_facet = scope.read.clone();
    assert_eq!(claim.link().current(false), Ok(()));
    assert_eq!(Arc::strong_count(&service), 1);
    let before_drop = Instant::now();
    drop(service); // No explicit revoke masks the original Grant::drop path.
    let after_drop = Instant::now();
    assert!(Arc::ptr_eq(&scope.read, &retained_facet));
    assert!(claim.link().current(false).is_err());
    let (reason, at) = claim.entry().first_stop().unwrap().unwrap();
    assert_eq!(reason, wire::Reason::PermissionRevoked);
    assert!(before_drop <= at && at <= after_drop);
    assert_eq!(
        claim.entry().status().unwrap().settlement,
        p::Settlement::Pending
    );

    drop(claim); // No native task was entered; do not invent a joined receipt.
    store.close().unwrap();
}

#[test]
fn retained_native_read_checks_do_not_wait_for_the_service_state_mutex() {
    let (_fixture, store, service, project) = setup();
    let client = read_client(&service, &project, Duration::from_secs(300));
    let (scope, _document, _review) = comparison_scope(&service);
    let input = submit_data(&service, &scope);
    service
        .version_reserve_requests()
        .allow(scope.clone(), input.grant_id.clone())
        .unwrap();
    reply(service.service_version_reserve_submit(&client, input));
    let claim = service.version_reserve_requests().claim().unwrap().unwrap();
    let link = claim.link().clone();
    let original_service = service.clone();
    let (send, receive) = mpsc::channel();
    let (worker, observed) = with_state_locked(&service, || {
        let worker = thread::spawn(move || {
            let history = original_service.native_history_current();
            let current = link.current(false);
            let _ = send.send((history, current));
        });
        // Deliberately hold the real IO-capable Service mutex, not a stand-in.
        // Release it and join even on timeout BEFORE making any assertion.
        (worker, receive.recv_timeout(OBSERVER_BOUND))
    });
    let joined = worker.join();
    assert!(joined.is_ok());
    assert_eq!(observed.unwrap(), (Ok(()), Ok(())));
    assert!(claim.entry().first_stop().unwrap().is_none());

    drop(claim);
    service.stop().unwrap();
    store.close().unwrap();
}

#[test]
fn captured_read_facet_revokes_before_inbox_allow_and_service_mutex_release() {
    let (_fixture, store, service, project) = setup();
    let client = read_client(&service, &project, Duration::from_secs(300));
    let (scope, _document, _review) = comparison_scope(&service);
    let inbox = service.version_reserve_requests();
    // ReservePoint already holds the genuine Grant facet, but neither an
    // Inbox lease nor an Entry exists to make it reachable through a request.
    assert_eq!(inbox.access().unwrap(), wire::Access::empty());
    assert!(inbox.claim().unwrap().is_none());
    let epoch = inbox.read_permission_epoch().unwrap();
    let grant = Id::random().unwrap();
    let original_service = service.clone();
    let (worker, observed) = with_state_locked(&service, || {
        let worker = thread::spawn(move || original_service.revoke_agent_read());
        let until = Instant::now() + OBSERVER_BOUND;
        // No Entry notification exists yet. Synchronize on the SAME Inbox's
        // actual revoke epoch, not a signal sent before revoke enters. This
        // finite wait never holds the Inbox guard across sleep or Service IO.
        let changed = loop {
            let current = inbox.read_permission_epoch();
            if current != Ok(epoch) {
                break Some((current, Instant::now()));
            }
            if Instant::now() >= until {
                break None;
            }
            thread::sleep(Duration::from_millis(1));
        };
        let observed = changed.map(|(current, at)| {
            // Exercise real Allow while the original revoke caller still
            // cannot acquire Service.state. Grant::drop cannot mask a missing
            // pre-Allow weak-facet revocation at this cut.
            (
                current,
                at,
                inbox.allow(scope.clone(), grant).err(),
                inbox.access(),
            )
        });
        (worker, observed)
    });
    let released = Instant::now();
    let joined = worker.join(); // Always release the actual guard and join first.
    assert_eq!(joined.unwrap(), Ok(()));
    let (current, at, refusal, access) =
        observed.expect("original revoke must reach the captured facet before Service IO");
    assert_eq!(current, Ok(epoch.checked_add(1).unwrap()));
    assert!(at <= released);
    assert_eq!(refusal, Some(Error::Conflict));
    assert_eq!(access.unwrap(), wire::Access::empty());
    assert!(inbox.claim().unwrap().is_none());
    assert_eq!(service.client_current(&client), Err(Error::AccessDenied));

    service.stop().unwrap();
    store.close().unwrap();
}

#[test]
fn read_revoke_reaches_original_link_before_waiting_for_service_state() {
    let (_fixture, store, service, project) = setup();
    let client = read_client(&service, &project, Duration::from_secs(300));
    let (scope, _document, _review) = comparison_scope(&service);
    let input = submit_data(&service, &scope);
    service
        .version_reserve_requests()
        .allow(scope.clone(), input.grant_id.clone())
        .unwrap();
    reply(service.service_version_reserve_submit(&client, input));
    let claim = service.version_reserve_requests().claim().unwrap().unwrap();
    let mut changes = scope.changes.subscribe();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let original_service = service.clone();
    let began = Instant::now();
    let (worker, notification) = with_state_locked(&service, || {
        let worker = thread::spawn(move || original_service.revoke_agent_read());
        // Wait for the SAME Entry's ordinary change notification. There is
        // no polling, extra callback, detached task or fake revoke signal.
        let observed = runtime.block_on(async {
            match tokio::time::timeout(OBSERVER_BOUND, changes.changed()).await {
                Ok(Ok(())) => Some(Instant::now()),
                _ => None,
            }
        });
        (worker, observed)
    });
    let released = Instant::now();
    let joined = worker.join(); // The original blocked caller has now returned.
    assert_eq!(joined.unwrap(), Ok(()));
    let notified = notification.expect("revoke must reach the Entry before the IO mutex releases");
    assert!(notified <= released);
    assert!(claim.link().current(false).is_err());
    let first_stop = claim.entry().first_stop().unwrap().unwrap();
    assert_eq!(first_stop.0, wire::Reason::PermissionRevoked);
    assert!(began <= first_stop.1 && first_stop.1 <= notified);
    assert_eq!(
        claim.entry().status().unwrap().settlement,
        p::Settlement::Pending
    );
    service.revoke_agent_read().unwrap();
    assert_eq!(claim.entry().first_stop().unwrap(), Some(first_stop));
    assert_eq!(service.client_current(&client), Err(Error::AccessDenied));

    drop(claim);
    service.stop().unwrap();
    store.close().unwrap();
}

#[test]
fn unobserved_service_poison_fences_retained_link_without_another_state_lock() {
    let (_fixture, store, service, project) = setup();
    let client = read_client(&service, &project, Duration::from_secs(300));
    let (scope, _document, _review) = comparison_scope(&service);
    let input = submit_data(&service, &scope);
    service
        .version_reserve_requests()
        .allow(scope.clone(), input.grant_id.clone())
        .unwrap();
    reply(service.service_version_reserve_submit(&client, input));
    let claim = service.version_reserve_requests().claim().unwrap().unwrap();
    assert_eq!(claim.link().current(false), Ok(()));
    poison_fixture(&service);
    assert!(service.state.is_poisoned());
    assert!(!service.native_history_fenced.load(Ordering::Acquire));
    // First observer is the actual atomic-only native gate, NOT Service::lock.
    assert_eq!(service.native_history_current(), Err(Error::StateUnknown));
    assert!(claim.link().current(false).is_err());
    let unknown = claim.entry().status().unwrap();
    assert_eq!(unknown.state, wire::State::Unknown);
    assert_eq!(unknown.settlement, p::Settlement::Unknown);
    assert_eq!(unknown.reason, Some(wire::Reason::CleanupUnknown));
    assert!(unknown.reservation.is_none());
    assert!(service.version_reserve_requests().claim().is_err());
    assert_eq!(
        service
            .allow_agent_read(vec![project], Duration::from_secs(300))
            .err(),
        Some(Error::StateUnknown)
    );
    drop(claim);
    assert_eq!(service.stop(), Err(Error::StateUnknown));
    store.close().unwrap();
}

#[test]
fn facet_expiry_is_the_actual_original_grant_deadline_not_the_poll_time() {
    let (_fixture, store, service, project) = setup();
    let client = read_client(&service, &project, Duration::from_secs(30));
    let original_end = service
        .state
        .lock()
        .unwrap()
        .grant
        .as_ref()
        .unwrap()
        .expires;
    let (scope, _document, _review) = comparison_scope(&service);
    assert!(original_end < scope.review_end);
    let input = submit_data(&service, &scope);
    service
        .version_reserve_requests()
        .allow(scope.clone(), input.grant_id.clone())
        .unwrap();
    reply(service.service_version_reserve_submit(&client, input));
    let claim = service.version_reserve_requests().claim().unwrap().unwrap();
    // Supply a delayed observation to the actual Entry method; do not mutate
    // either original deadline or construct another ReadPermission for it.
    claim.entry().expire(original_end + Duration::from_secs(1));
    assert_eq!(
        claim.entry().first_stop().unwrap(),
        Some((wire::Reason::Expired, original_end))
    );
    assert!(claim.link().current(false).is_err());
    assert_eq!(
        claim.entry().status().unwrap().settlement,
        p::Settlement::Pending
    );

    drop(claim);
    service.stop().unwrap();
    store.close().unwrap();
}

#[test]
fn reserve_response_project_and_alias_guards_survive_reconnect_and_pre_send_revoke() {
    let (fixture, store, service, project) = setup();
    let (other, _) = register_fixture(&service, &fixture.app, "other", "project-2");
    service
        .allow_agent_read(
            vec![project.clone(), other.clone()],
            Duration::from_secs(300),
        )
        .unwrap();
    let client = service.admit_client().unwrap();
    let (scope, _document, _review) = comparison_scope(&service);
    let input = submit_data(&service, &scope);
    service
        .version_reserve_requests()
        .allow(scope.clone(), input.grant_id.clone())
        .unwrap();
    let queued = reply(service.service_version_reserve_submit(&client, input.clone()));
    let mut other_query = input.origin.clone();
    other_query.project_id = other.clone();
    assert_eq!(
        service
            .service_version_reserve_query(&client, &other_query, true)
            .err(),
        Some(Error::Conflict)
    );
    assert_eq!(
        reply(service.service_version_reserve_query(&client, &input.origin, false)),
        queued
    );
    service
        .state
        .lock()
        .unwrap()
        .runtime_aliases
        .remove("project-1");
    assert_eq!(
        service
            .service_version_reserve_query(&client, &input.origin, false)
            .err(),
        Some(Error::Conflict)
    );
    assert_eq!(
        service.android_tools_client_current(&client, &queued.origin.project_id),
        Err(Error::Conflict)
    );
    service
        .state
        .lock()
        .unwrap()
        .runtime_aliases
        .insert("project-1".into(), project.clone());
    let narrowed = read_client(&service, &other, Duration::from_secs(300));
    assert_eq!(
        service
            .service_version_reserve_query(&narrowed, &input.origin, true)
            .err(),
        Some(Error::AccessDenied)
    );
    assert_eq!(
        service.android_tools_client_current(&narrowed, &queued.origin.project_id),
        Err(Error::AccessDenied)
    );
    assert_eq!(service.client_current(&client), Err(Error::AccessDenied));

    service.stop().unwrap();
    store.close().unwrap();
}
