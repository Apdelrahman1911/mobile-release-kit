//! Actual private Service/Store and READ, with no native source, socket,
//! runtime, Store provider, Review identity or permission manufactured.
use super::*;
use crate::service_version_reserve_review_protocol as review;

fn input(service: &ApplicationService, project: &Id) -> review::Request {
    review::Request {
        origin: wire::Query {
            project_id: project.clone(),
            service_instance: service.instance().clone(),
            request_id: Id::random().unwrap(),
        },
        options: review::Options {
            reference: "refs/heads/main".into(),
            increment: review::Increment::Build,
            new_candidate: false,
            acknowledge_limitations: true,
            future_tag: None,
        },
    }
}
fn review_reply(result: Result<p::ResponseBody, Error>) -> review::Status {
    match result.unwrap() {
        p::ResponseBody::VersionReserveReview(value) => value,
        _ => panic!("the stored read kind must not become a Reserve status"),
    }
}

#[test]
fn original_read_reconnect_observes_review_without_reserve_permission_or_replay() {
    let (_fixture, store, service, project) = setup();
    let client = read_client(&service, &project, Duration::from_secs(300));
    let request = input(&service, &project);
    let before = store.read(Namespace::Projects).unwrap();
    let queued = review_reply(service.service_version_reserve_review(&client, request.clone()));
    assert_eq!(queued.phase, review::Phase::Queued);
    assert!(queued.operation_id.is_none() && queued.review.is_none());
    let original = service
        .version_reserve_requests()
        .review_entry(&request.origin)
        .unwrap();
    assert_eq!(
        service.version_reserve_requests().access().unwrap(),
        wire::Access::empty()
    );
    assert!(service
        .version_reserve_requests()
        .claim()
        .unwrap()
        .is_none());

    let reconnected = service.admit_client().unwrap();
    assert_ne!(client.client_id, reconnected.client_id);
    assert_eq!(
        review_reply(service.service_version_reserve_review(&reconnected, request.clone())),
        queued
    );
    assert_eq!(
        review_reply(service.service_version_reserve_query(&reconnected, &request.origin, false)),
        queued
    );
    assert!(Arc::ptr_eq(
        &original,
        &service
            .version_reserve_requests()
            .review_entry(&request.origin)
            .unwrap()
    ));
    let mut changed = request.clone();
    changed.options.increment = review::Increment::Major;
    assert_eq!(
        service
            .service_version_reserve_review(&reconnected, changed)
            .err(),
        Some(Error::Conflict)
    );
    assert_eq!(
        service.android_tools_client_current(&reconnected, &project),
        Ok(())
    );

    let cancelled =
        review_reply(service.service_version_reserve_query(&reconnected, &request.origin, true));
    assert_eq!(cancelled.phase, review::Phase::Refused); // No native caller was admitted.
    assert_eq!(cancelled.settlement, p::Settlement::Settled);
    assert!(cancelled.review.is_none());
    let rows = service
        .version_reserve_requests()
        .catalogue_requests(service.instance(), &project)
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].request_id, request.origin.request_id);
    let after = store.read(Namespace::Projects).unwrap();
    assert_eq!(
        (after.revision, after.bytes),
        (before.revision, before.bytes)
    );
    service.stop().unwrap();
    store.close().unwrap();
}

#[test]
fn actual_saved_config_alias_and_old_read_fence_a_new_review_without_native_work() {
    let (_fixture, store, service, project) = setup();
    let client = read_client(&service, &project, Duration::from_secs(300));
    let first = input(&service, &project);
    // The real saved point must be fresh BEFORE a new row can be accepted.
    {
        let mut state = service.lock().unwrap();
        state
            .saved
            .projects
            .iter_mut()
            .find(|p| p.binding.project_id == project)
            .unwrap()
            .observation
            .as_mut()
            .unwrap()
            .stale = true;
    }
    assert_eq!(
        service
            .service_version_reserve_review(&client, first.clone())
            .err(),
        Some(Error::Conflict)
    );
    {
        let mut state = service.lock().unwrap();
        state
            .saved
            .projects
            .iter_mut()
            .find(|p| p.binding.project_id == project)
            .unwrap()
            .observation
            .as_mut()
            .unwrap()
            .stale = false;
    }
    review_reply(service.service_version_reserve_review(&client, first.clone()));
    let original = service
        .version_reserve_requests()
        .review_entry(&first.origin)
        .unwrap();
    let old_read = original.scope.read.clone();
    service.lock().unwrap().runtime_aliases.remove("project-1");
    assert_eq!(
        service.android_tools_client_current(&client, &project),
        Err(Error::Conflict)
    );
    assert_eq!(
        service
            .service_version_reserve_query(&client, &first.origin, false)
            .err(),
        Some(Error::Conflict)
    );
    service
        .lock()
        .unwrap()
        .runtime_aliases
        .insert("project-1".into(), project.clone());

    // A genuinely renewed Grant cannot renew the old row's READ or T.
    let renewed = read_client(&service, &project, Duration::from_secs(300));
    assert!(old_read.stop(Instant::now()).unwrap().is_some());
    assert!(!Arc::ptr_eq(
        &old_read,
        &service.version_reserve_point("project-1").unwrap().read
    ));
    let stopped =
        review_reply(service.service_version_reserve_query(&renewed, &first.origin, false));
    assert_eq!(stopped.phase, review::Phase::Refused);
    assert_eq!(stopped.reason, Some(wire::Reason::PermissionRevoked));
    assert!(original.begin().is_err());
    assert_eq!(
        service
            .version_reserve_requests()
            .catalogue_requests(service.instance(), &project)
            .unwrap()
            .len(),
        1
    );
    service.stop().unwrap();
    store.close().unwrap();
}
