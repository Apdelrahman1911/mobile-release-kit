//! Real private Store + original Service policy tests. These do not fabricate
//! ProjectProbe/Document authority and do not qualify native startup or signals.
use super::*;
use crate::application_service::tests::{passive, register_fixture};
use crate::application_state_store::{Fixture, Namespace, PrivateStateDirectory};
use std::{mem::ManuallyDrop, os::unix::fs::MetadataExt};

fn request(request: p::RequestBody) -> p::Request {
    p::Request {
        version: p::VERSION,
        request_id: Id::random().unwrap(),
        request,
    }
}
fn lease() -> Arc<HistoryLease> {
    HistoryLease::new(Instant::now(), Duration::from_secs(30)).unwrap()
}
#[test]
fn history_allowlist_precedes_every_dispatch_family_and_service_lock() {
    let fixture = ManuallyDrop::new(Fixture::new());
    let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
    let original = lease();
    let service = ApplicationService::open_history(store.clone(), original.clone()).unwrap();
    let (project, root) = register_fixture(&service, &fixture.app, "project", "history");
    assert_eq!(
        service
            .allow_agent_read(vec![project.clone()], Duration::from_secs(30))
            .err(),
        Some(Error::AccessDenied)
    );
    assert_eq!(
        service.allow_history_read(project.clone(), &lease()).err(),
        Some(Error::AccessDenied)
    );
    service
        .allow_history_read(project.clone(), &original)
        .unwrap();
    let client = service.admit_client().unwrap();
    let id = Id::random().unwrap();
    let query = p::ProjectQuery {
        project_id: project.clone(),
    };
    let version_query = crate::service_version_reserve_protocol::Query {
        service_instance: service.instance().clone(),
        project_id: project.clone(),
        request_id: id.clone(),
    };
    let cleanup_query = crate::service_play_cleanup_protocol::Query {
        service_instance: service.instance().clone(),
        project_id: project.clone(),
        request_id: id.clone(),
        purpose: crate::service_play_cleanup_protocol::Purpose::PlayCleanup,
    };
    let identity_query = crate::agent_identity_requests::Query {
        service_instance: service.instance().clone(),
        project_id: project.clone(),
        intent_id: id.clone(),
    };
    let checks = crate::agent_local_checks::Submit {
        service_instance: service.instance().clone(),
        project_id: project.clone(),
        request_id: id.clone(),
        expected_observation_revision: 1,
    };
    let build = crate::agent_build_requests::Prepare {
        service_instance: service.instance().clone(),
        project_id: project.clone(),
        request_id: id.clone(),
        expected_observation_revision: 1,
    };
    let build_start = crate::agent_build_requests::Start {
        origin: build.query(),
        operation_id: Id::random().unwrap(),
        owner_generation: Id::random().unwrap(),
    };
    let git_query = crate::service_git_protocol::Query {
        service_instance: service.instance().clone(),
        project_id: project.clone(),
        request_id: id.clone(),
    };
    let git_prepare = crate::service_git_protocol::Prepare {
        origin: git_query.clone(),
        grant_id: Id::random().unwrap(),
    };
    let git_start = crate::service_git_protocol::Start {
        origin: git_query.clone(),
        prepare_operation_id: "original-prepare".into(),
        review_id: "original-review".into(),
    };
    let identity_submit = crate::agent_identity_requests::Submit {
        service_instance: service.instance().clone(),
        project_id: project.clone(),
        intent_id: id.clone(),
        expected_observation_revision: 1,
        change: crate::agent_identity_requests::Change {
            selection: crate::agent_identity_requests::Selection {
                platform: crate::agent_identity_requests::Platform::Android,
                target: ":app".into(),
                project: None,
            },
            desired_identity: "com.example.app".into(),
            identity_intent: crate::agent_identity_requests::IdentityIntent::Preserve,
        },
    };
    let identity_start = crate::agent_identity_requests::actions::Start {
        origin: identity_query.clone(),
        original: crate::agent_identity_requests::actions::Original {
            operation_id: Id::random().unwrap(),
            owner_generation: Id::random().unwrap(),
            revision: Id::random().unwrap(),
        },
        plan_token: Id::random().unwrap(),
        reviewed: true,
    };
    // Actual typed, decode-valid requests reaching ALL the families which
    // dispatch can handle before taking the ordinary service lock. Also refuse
    // otherwise read-only runtime cells: history does not pretend they exist.
    let denied = vec![
        p::RequestBody::AndroidTools(query.clone()),
        p::RequestBody::Requests(query.clone()),
        p::RequestBody::Repository(query.clone()),
        p::RequestBody::GitIndexScope(query.clone()),
        p::RequestBody::GitCommitScope(query.clone()),
        p::RequestBody::GitRepositoryScope(query.clone()),
        p::RequestBody::GitRemoteScope(query.clone()),
        p::RequestBody::GitIndexPrepare(git_prepare.clone()),
        p::RequestBody::GitCommitPrepare(git_prepare.clone()),
        p::RequestBody::GitRepositoryPrepare(git_prepare.clone()),
        p::RequestBody::GitRemotePrepare(git_prepare),
        p::RequestBody::GitIndexStart(git_start.clone()),
        p::RequestBody::GitCommitStart(git_start.clone()),
        p::RequestBody::GitRepositoryStart(git_start.clone()),
        p::RequestBody::GitRemoteStart(git_start),
        p::RequestBody::GitIndexStatus(git_query.clone()),
        p::RequestBody::GitCommitStatus(git_query.clone()),
        p::RequestBody::GitRepositoryStatus(git_query.clone()),
        p::RequestBody::GitRemoteStatus(git_query.clone()),
        p::RequestBody::GitIndexCancel(git_query.clone()),
        p::RequestBody::GitCommitCancel(git_query.clone()),
        p::RequestBody::GitRepositoryCancel(git_query.clone()),
        p::RequestBody::GitRemoteCancel(git_query),
        p::RequestBody::VersionReserveSubmit(crate::service_version_reserve_protocol::Submit {
            origin: version_query.clone(),
            grant_id: id.clone(),
            review_id: Id::random().unwrap(),
        }),
        p::RequestBody::VersionReserveStatus(version_query.clone()),
        p::RequestBody::VersionReserveCancel(version_query),
        p::RequestBody::PlayCleanupSubmit(crate::service_play_cleanup_protocol::Submit {
            origin: cleanup_query.clone(),
            consent_id: id.clone(),
        }),
        p::RequestBody::PlayCleanupStatus(cleanup_query.clone()),
        p::RequestBody::PlayCleanupCancel(cleanup_query),
        p::RequestBody::IdentitySubmit(identity_submit),
        p::RequestBody::IdentityStart(identity_start),
        p::RequestBody::IdentityPrepare(identity_query.clone()),
        p::RequestBody::IdentityIntent(identity_query.clone()),
        p::RequestBody::IdentityActionStatus(identity_query.clone()),
        p::RequestBody::IdentityCancel(identity_query),
        p::RequestBody::LocalCheckSubmit(checks.clone()),
        p::RequestBody::LocalCheckStatus(checks.query()),
        p::RequestBody::LocalCheckCancel(checks.query()),
        p::RequestBody::AndroidBuildPrepare(build.clone()),
        p::RequestBody::AndroidBuildStart(build_start.clone()),
        p::RequestBody::AndroidBuildStatus(build.query()),
        p::RequestBody::AndroidBuildCancel(build.query()),
        p::RequestBody::IosArchivePrepare(build.clone()),
        p::RequestBody::IosArchiveStart(build_start),
        p::RequestBody::IosArchiveStatus(build.query()),
        p::RequestBody::IosArchiveCancel(build.query()),
    ];
    let before = store.read(Namespace::Projects).unwrap();
    {
        let _same_state = service.state.lock().unwrap();
        for body in denied {
            let input = request(body);
            let encoded = p::encode_request(&input).unwrap();
            let decoded = p::decode_request(&encoded).unwrap();
            assert!(!history_request(&decoded.request));
            // This would deadlock if an old special route or generic dispatch
            // reached state instead of the history-only front gate.
            assert_eq!(
                service.dispatch(&client, decoded).response,
                p::ResponseBody::Error(Error::AccessDenied)
            );
        }
    }
    assert_eq!(
        service
            .publish_passive_snapshot("history", &passive(&root, &"1".repeat(64)))
            .err(),
        Some(Error::AccessDenied)
    );
    let after = store.read(Namespace::Projects).unwrap();
    assert_eq!(before.revision, after.revision);
    assert_eq!(before.bytes, after.bytes);
    let info = service.dispatch(&client, request(p::RequestBody::Info(p::Empty {})));
    let p::ResponseBody::Info(view) = &info.response else {
        panic!("not Info")
    };
    assert!(
        view.read_only && !view.requires_running_desktop && !view.read_grant_authorizes_execution
    );
    let encoded = p::encode_response(&info).unwrap();
    assert_eq!(
        p::decode_response(&encoded, &info.request_id, service.instance()).unwrap(),
        info
    );
    service.stop().unwrap();
    store.close().unwrap();
    drop((service, store));
    drop(ManuallyDrop::into_inner(fixture));
}

#[test]
fn history_reload_is_stale_and_never_restores_alias_grant_or_execution() {
    let fixture = ManuallyDrop::new(Fixture::new());
    let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
    let service = ApplicationService::open(store.clone()).unwrap();
    let (project, root) = register_fixture(&service, &fixture.app, "project", "desktop");
    service
        .publish_passive_snapshot("desktop", &passive(&root, &"2".repeat(64)))
        .unwrap();
    let operation = Id::random().unwrap();
    service
        .begin_operation(
            "desktop",
            operation.clone(),
            p::Action::Build,
            p::OperationState::Unknown,
            p::Settlement::Unknown,
        )
        .unwrap();
    service
        .allow_agent_read(vec![project.clone()], Duration::from_secs(30))
        .unwrap();
    let previous_client = service.admit_client().unwrap();
    service.stop().unwrap();
    store.close().unwrap();
    drop((service, store));
    let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
    let original = lease();
    let service = ApplicationService::open_history(store.clone(), original.clone()).unwrap();
    let before = store.read(Namespace::Projects).unwrap();
    assert_eq!(service.admit_client().err(), Some(Error::AccessDenied));
    assert_eq!(
        service.allow_history_read(project.clone(), &original).err(),
        Some(Error::Conflict)
    );
    // Real directory metadata for Service DATA registration only. The native
    // History Host separately requires actual PRE/exclusion/POST SourceBooks.
    let held = std::fs::File::open(&root).unwrap();
    let metadata = held.metadata().unwrap();
    let rebound = service
        .register_native("history", &root, metadata.dev(), metadata.ino())
        .unwrap();
    nix::unistd::close(held).unwrap();
    assert_eq!(rebound.project_id, project);
    service
        .allow_history_read(project.clone(), &original)
        .unwrap();
    assert_eq!(
        service
            .dispatch(
                &previous_client,
                request(p::RequestBody::Projects(p::Empty {}))
            )
            .response,
        p::ResponseBody::Error(Error::AccessDenied)
    );
    let client = service.admit_client().unwrap();
    let query = p::ProjectQuery {
        project_id: project.clone(),
    };
    for body in [
        p::RequestBody::Info(p::Empty {}),
        p::RequestBody::Projects(p::Empty {}),
        p::RequestBody::Observe(query.clone()),
        p::RequestBody::Operations(query.clone()),
        p::RequestBody::Operation(p::OperationQuery {
            project_id: project.clone(),
            operation_id: operation.clone(),
        }),
    ] {
        assert!(history_request(&body));
        let response = service.dispatch(&client, request(body));
        assert!(!matches!(response.response, p::ResponseBody::Error(_)));
        p::encode_response(&response).unwrap();
    }
    let p::ResponseBody::Observation(observation) = service
        .dispatch(&client, request(p::RequestBody::Observe(query.clone())))
        .response
    else {
        panic!("not observation")
    };
    assert!(observation.observation.unwrap().stale);
    let p::ResponseBody::Operations(operations) = service
        .dispatch(&client, request(p::RequestBody::Operations(query)))
        .response
    else {
        panic!("not operations")
    };
    assert_eq!(operations.len(), 1);
    assert!(operations[0].stale);
    assert_eq!(operations[0].state, p::OperationState::Unknown);
    assert_eq!(operations[0].settlement, p::Settlement::Unknown);
    let after = store.read(Namespace::Projects).unwrap();
    assert_eq!(before.revision, after.revision);
    assert_eq!(before.bytes, after.bytes);
    service.fence_native_history();
    assert_eq!(
        service.allow_history_read(project, &original).err(),
        Some(Error::StateUnknown)
    );
    assert_eq!(
        service
            .dispatch(&client, request(p::RequestBody::Info(p::Empty {})))
            .response,
        p::ResponseBody::Error(Error::StateUnknown)
    );
    service.stop().unwrap();
    store.close().unwrap();
    drop((service, store));
    drop(ManuallyDrop::into_inner(fixture));
}

#[test]
fn history_stop_overtakes_blocked_grant_publication_without_timer_renewal() {
    let fixture = ManuallyDrop::new(Fixture::new());
    let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
    let start = Instant::now() - Duration::from_secs(1);
    let original = HistoryLease::new(start, Duration::from_secs(30)).unwrap();
    let service =
        Arc::new(ApplicationService::open_history(store.clone(), original.clone()).unwrap());
    let (project, _) = register_fixture(&service, &fixture.app, "project", "history");
    service
        .allow_history_read(project.clone(), &original)
        .unwrap();
    assert_eq!(
        service
            .state
            .lock()
            .unwrap()
            .grant
            .as_ref()
            .unwrap()
            .expires,
        start + Duration::from_secs(30)
    );
    service.revoke_agent_read().unwrap();
    let held = service.state.lock().unwrap();
    let same_service = service.clone();
    let same_lease = original.clone();
    let (entered, observed) = std::sync::mpsc::sync_channel(0);
    let publisher = std::thread::spawn(move || {
        entered.send(()).unwrap();
        same_service.allow_history_read(project, &same_lease)
    });
    observed.recv().unwrap();
    original.stop(); // Atomic while the actual state mutex is still held.
    assert_eq!(service.native_history_current(), Err(Error::AccessDenied));
    drop(held);
    assert_eq!(publisher.join().unwrap().err(), Some(Error::AccessDenied));
    assert!(service.state.lock().unwrap().grant.is_none());
    assert_eq!(original.expires(), start + Duration::from_secs(30));
    service.stop().unwrap();
    store.close().unwrap();
    drop((service, store));
    drop(ManuallyDrop::into_inner(fixture));
}
