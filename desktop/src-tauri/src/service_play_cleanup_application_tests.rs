//! Original private Store/Service/Grant tests. Weak document/review objects are
//! inert comparison DATA, never native Connection, consent or join proof.
use super::*;
use crate::application_service::tests::{
    passive, poison_fixture, register_fixture, with_state_locked,
};
use crate::application_state_store::Fixture;
use std::{sync::mpsc, thread};
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
fn scope(s: &ApplicationService) -> (Arc<requests::NativeScope>, Arc<()>, Arc<()>) {
    let p = s.play_cleanup_point("project-1").unwrap();
    let doc = Arc::new(());
    let review = Arc::new(());
    let value = s.play_cleanup_requests().scope(
        p.saved.project_id,
        p.saved.runtime_id,
        Id::random().unwrap(),
        Instant::now() + Duration::from_secs(100),
        p.read,
        Arc::downgrade(&doc),
        Arc::downgrade(&review),
        tokio::sync::watch::channel(0).0,
        1,
    );
    (value, doc, review)
}
fn input(s: &ApplicationService, scope: &requests::NativeScope) -> wire::Submit {
    wire::Submit {
        origin: wire::Query {
            project_id: scope.project_id.clone(),
            service_instance: s.instance().clone(),
            request_id: Id::random().unwrap(),
        },
        consent_id: scope.consent_id.clone(),
    }
}
fn reply(r: Result<p::ResponseBody, Error>) -> wire::Status {
    match r.unwrap() {
        p::ResponseBody::PlayCleanupRequest(v) => v,
        _ => panic!("wrong closed cleanup response"),
    }
}
#[test]
fn actual_read_and_cleanup_scopes_both_required_reconnect_and_presend_rematch() {
    let (_f, store, s, project) = setup();
    assert_eq!(
        s.play_cleanup_point("project-1").err(),
        Some(Error::AccessDenied)
    );
    s.allow_agent_read(vec![project.clone()], Duration::from_secs(300))
        .unwrap();
    let client = s.admit_client().unwrap();
    let (scope, _doc, _review) = scope(&s);
    let request = input(&s, &scope);
    let before = store.read(Namespace::Projects).unwrap();
    assert_eq!(
        s.service_play_cleanup_submit(&client, request.clone())
            .err(),
        Some(Error::AccessDenied)
    );
    s.play_cleanup_requests().allow(scope.clone()).unwrap();
    let original = reply(s.service_play_cleanup_submit(&client, request.clone()));
    let claim = s.play_cleanup_requests().claim().unwrap().unwrap();
    let next = s.admit_client().unwrap();
    assert_ne!(client.client_id, next.client_id);
    assert_eq!(
        reply(s.service_play_cleanup_submit(&next, request.clone())),
        original
    );
    assert!(s.play_cleanup_requests().claim().unwrap().is_none());
    let mut changed = request.clone();
    changed.consent_id = Id::random().unwrap();
    assert!(s.service_play_cleanup_submit(&next, changed).is_err());
    assert_eq!(s.android_tools_client_current(&next, &project), Ok(()));
    s.state.lock().unwrap().runtime_aliases.remove("project-1");
    assert_eq!(
        s.android_tools_client_current(&next, &project),
        Err(Error::Conflict)
    );
    assert!(s
        .service_play_cleanup_query(&next, &request.origin, false)
        .is_err());
    s.state
        .lock()
        .unwrap()
        .runtime_aliases
        .insert("project-1".into(), project.clone());
    s.revoke_agent_read().unwrap();
    assert_eq!(
        s.service_play_cleanup_query(&next, &request.origin, true)
            .err(),
        Some(Error::AccessDenied)
    );
    assert_eq!(
        s.android_tools_client_current(&next, &project),
        Err(Error::AccessDenied)
    );
    assert_eq!(
        claim.link().entry().status().unwrap().state,
        wire::State::Stopping
    );
    let after = store.read(Namespace::Projects).unwrap();
    assert_eq!(before.revision, after.revision);
    assert_eq!(before.bytes, after.bytes);
    drop(claim);
    s.stop().unwrap();
    store.close().unwrap();
}
#[test]
fn original_grant_clone_drop_and_renewal_do_not_rebind_old_cleanup_scope() {
    let (_f, store, s, project) = setup();
    s.allow_agent_read(vec![project.clone()], Duration::from_secs(300))
        .unwrap();
    let client = s.admit_client().unwrap();
    let (scope, _doc, _review) = scope(&s);
    let request = input(&s, &scope);
    s.play_cleanup_requests().allow(scope.clone()).unwrap();
    reply(s.service_play_cleanup_submit(&client, request));
    let claim = s.play_cleanup_requests().claim().unwrap().unwrap();
    let copied = scope.read.clone();
    drop(copied);
    assert_eq!(claim.link().current(false), Ok(()));
    let before = Instant::now();
    s.allow_agent_read(vec![project], Duration::from_secs(300))
        .unwrap();
    let after = Instant::now();
    let new = s.play_cleanup_point("project-1").unwrap();
    assert!(!Arc::ptr_eq(&scope.read, &new.read));
    assert!(claim.link().current(false).is_err());
    let (r, at) = claim.link().entry().first_stop().unwrap().unwrap();
    assert_eq!(r, wire::Reason::PermissionRevoked);
    assert!(before <= at && at <= after);
    assert_eq!(s.client_current(&client), Err(Error::AccessDenied));
    drop(claim);
    s.stop().unwrap();
    store.close().unwrap();
}
#[test]
fn before_allow_revocation_and_claim_watchdog_do_not_wait_for_service_io_mutex() {
    let (_f, store, s, project) = setup();
    s.allow_agent_read(vec![project], Duration::from_secs(300))
        .unwrap();
    let (scope, _doc, _review) = scope(&s);
    let original = s.clone();
    let (worker, observed, allowed) = with_state_locked(&s, || {
        let worker = thread::spawn(move || original.revoke_agent_read());
        let end = Instant::now() + Duration::from_secs(5);
        let mut observed = None;
        while Instant::now() < end {
            if let Ok(Some(v)) = scope.read.stop(Instant::now()) {
                observed = Some(v);
                break;
            }
            thread::yield_now();
        }
        let allowed = s.play_cleanup_requests().allow(scope.clone());
        (worker, observed, allowed)
    });
    let returned = worker.join();
    assert!(returned.unwrap().is_ok());
    assert!(observed.is_some());
    assert!(allowed.is_err());
    // Obtain a new actual Grant and claimed comparison link for the watchdog cut.
    s.allow_agent_read(vec![scope.project_id.clone()], Duration::from_secs(300))
        .unwrap();
    let (new, _d, _r) = self::scope(&s);
    let client = s.admit_client().unwrap();
    s.play_cleanup_requests().allow(new.clone()).unwrap();
    reply(s.service_play_cleanup_submit(&client, input(&s, &new)));
    let claim = s.play_cleanup_requests().claim().unwrap().unwrap();
    let link = claim.link().clone();
    let original = s.clone();
    let (send, recv) = mpsc::channel();
    let (worker, result) = with_state_locked(&s, || {
        let worker = thread::spawn(move || {
            let result = (
                original.native_history_current(),
                link.current(false),
                link.entry().watchdog_stop(),
            );
            let _ = send.send(result);
        });
        let result = recv.recv_timeout(Duration::from_secs(5));
        (worker, result)
    });
    worker.join().unwrap();
    let result = result.unwrap();
    assert_eq!(result.0, Ok(()));
    assert_eq!(result.1, Ok(()));
    assert_eq!(result.2, Ok(None));
    drop(claim);
    s.stop().unwrap();
    store.close().unwrap();
}
#[test]
fn unobserved_service_poison_fences_claim_without_second_service_lock() {
    let (_f, store, s, project) = setup();
    s.allow_agent_read(vec![project], Duration::from_secs(300))
        .unwrap();
    let (scope, _doc, _review) = scope(&s);
    let client = s.admit_client().unwrap();
    s.play_cleanup_requests().allow(scope.clone()).unwrap();
    reply(s.service_play_cleanup_submit(&client, input(&s, &scope)));
    let claim = s.play_cleanup_requests().claim().unwrap().unwrap();
    poison_fixture(&s);
    assert_eq!(s.native_history_current(), Err(Error::StateUnknown));
    assert_eq!(claim.link().current(false), Err(Error::StateUnknown));
    assert_eq!(
        claim.link().entry().status().unwrap().state,
        wire::State::Unknown
    );
    assert!(s.play_cleanup_requests().claim().is_err());
    drop(claim);
    drop(s);
    store.close().unwrap();
}
