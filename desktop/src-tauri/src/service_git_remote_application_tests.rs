//! Real Service/Grant/Store fixtures, inert native scope only. No native
//! admission, Git subprocess, source proof or settlement receipt is created.
use super::*;
use crate::{application_service::tests::register_fixture, application_state_store::Fixture};

fn request(body: p::RequestBody) -> p::Request {
    p::Request {
        version: p::VERSION,
        request_id: Id::random().unwrap(),
        request: body,
    }
}

#[test]
fn actual_service_dispatch_requires_read_plus_remote_grant_and_preserves_original_on_reconnect() {
    let fixture = Fixture::new();
    let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
    let service = ApplicationService::open(store.clone()).unwrap();
    let (project, root) = register_fixture(&service, &fixture.app, "project", "project-1");
    service
        .allow_agent_read(vec![project.clone()], Duration::from_secs(60))
        .unwrap();
    let client = service.admit_client().unwrap();
    let point = service.git_index_point("project-1").unwrap();
    let doc = Arc::new(());
    let scope = Arc::new(requests::NativeScope {
        project_id: project.clone(),
        runtime_id: "project-1".into(),
        root,
        device: point.device,
        inode: point.inode,
        registration: 1,
        document_revision: 1,
        input_revision: 1,
        read_operation_id: Some("git-read-1".into()),
        document: Arc::downgrade(&doc),
        selection: remote::tests::selection(false).into(),
        commit: None,
        changes: tokio::sync::watch::channel(0).0,
    });
    let mut input = remote::Prepare {
        origin: remote::Query {
            project_id: project.clone(),
            service_instance: service.instance().clone(),
            request_id: Id::random().unwrap(),
        },
        grant_id: Id::random().unwrap(),
    };
    let denied = service.dispatch(
        &client,
        request(p::RequestBody::GitRemotePrepare(input.clone())),
    );
    assert_eq!(denied.response, p::ResponseBody::Error(Error::AccessDenied));
    assert!(service.git_index_requests().entries().unwrap().is_empty());
    input.grant_id = service
        .git_index_requests()
        .allow_remote(scope)
        .unwrap()
        .grant_id
        .unwrap();
    let scope = service.dispatch(
        &client,
        request(p::RequestBody::GitRemoteScope(p::ProjectQuery {
            project_id: project.clone(),
        })),
    );
    assert!(matches!(&scope.response, p::ResponseBody::GitRemoteScope(v) if v.access.enabled));
    p::encode_response(&scope).unwrap();
    for body in [
        p::RequestBody::GitIndexPrepare(input.clone()),
        p::RequestBody::GitCommitPrepare(input.clone()),
    ] {
        assert_eq!(
            service.dispatch(&client, request(body)).response,
            p::ResponseBody::Error(Error::AccessDenied)
        );
    }
    let first = service.dispatch(
        &client,
        request(p::RequestBody::GitRemotePrepare(input.clone())),
    );
    assert!(
        matches!(&first.response,p::ResponseBody::GitRemoteRequest(v) if v.progress.state==git::State::Queued && v.progress.review.is_none() && v.result.is_none())
    );
    p::encode_response(&first).unwrap();
    let newer = service.admit_client().unwrap();
    assert_ne!(client.client_id, newer.client_id);
    let repeated = service.dispatch(
        &newer,
        request(p::RequestBody::GitRemotePrepare(input.clone())),
    );
    assert_eq!(first.response, repeated.response);
    assert_eq!(service.git_index_requests().entries().unwrap().len(), 1);
    let start = remote::Start {
        origin: input.origin.clone(),
        prepare_operation_id: "invented-operation".into(),
        review_id: "invented-review".into(),
    };
    assert_eq!(
        service
            .dispatch(&newer, request(p::RequestBody::GitRemoteStart(start)))
            .response,
        p::ResponseBody::Error(Error::Conflict)
    );
    for body in [
        p::RequestBody::GitIndexCancel(input.origin.clone()),
        p::RequestBody::GitCommitCancel(input.origin.clone()),
    ] {
        assert!(matches!(
            service.dispatch(&newer, request(body)).response,
            p::ResponseBody::Error(_)
        ));
    }
    assert_eq!(
        service
            .dispatch(
                &newer,
                request(p::RequestBody::GitRemoteStatus(input.origin.clone()))
            )
            .response,
        first.response
    );
    let stopped = service.dispatch(
        &newer,
        request(p::RequestBody::GitRemoteCancel(input.origin.clone())),
    );
    assert!(
        matches!(stopped.response,p::ResponseBody::GitRemoteRequest(v) if v.progress.state==git::State::Cancelled)
    );
    service.revoke_agent_read().unwrap();
    assert_eq!(
        service
            .dispatch(
                &newer,
                request(p::RequestBody::GitRemoteStatus(input.origin))
            )
            .response,
        p::ResponseBody::Error(Error::AccessDenied)
    );
    assert_eq!(
        service.android_tools_client_current(&newer, &project),
        Err(Error::AccessDenied)
    );
    service.stop().unwrap();
    drop(service);
    store.close().unwrap();
}

#[test]
fn remote_scope_and_presend_reject_changed_project_alias_and_old_read_session() {
    let fixture = Fixture::new();
    let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
    let service = ApplicationService::open(store.clone()).unwrap();
    let (project, _) = register_fixture(&service, &fixture.app, "project", "project-1");
    service
        .allow_agent_read(vec![project.clone()], Duration::from_secs(60))
        .unwrap();
    let client = service.admit_client().unwrap();
    service.git_remote_scope(&client, &project).unwrap();
    let foreign = Id::random().unwrap();
    assert_eq!(
        service.git_remote_scope(&client, &foreign).unwrap_err(),
        Error::AccessDenied
    );
    assert_eq!(
        service.android_tools_client_current(&client, &foreign),
        Err(Error::AccessDenied)
    );
    service
        .allow_agent_read(vec![project.clone()], Duration::from_secs(60))
        .unwrap();
    assert_eq!(
        service.git_remote_scope(&client, &project).unwrap_err(),
        Error::AccessDenied
    );
    let current = service.admit_client().unwrap();
    service.git_remote_scope(&current, &project).unwrap();
    service.lock().unwrap().runtime_aliases.clear();
    assert_eq!(
        service.git_remote_scope(&current, &project).unwrap_err(),
        Error::Conflict
    );
    assert_eq!(
        service.android_tools_client_current(&current, &project),
        Err(Error::Conflict)
    );
    service.stop().unwrap();
    drop(service);
    store.close().unwrap();
}
