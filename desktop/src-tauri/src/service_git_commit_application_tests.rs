use super::*;
use crate::{
    application_service::tests::register_fixture, application_state_store::Fixture,
    service_git_commit_protocol::Draft,
};

#[test]
fn same_service_requires_read_and_commit_grants_and_reconnect_cannot_replay() {
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
        selection: git::Selection::new_shared(
            git::Action::Commit,
            "a".repeat(64),
            vec!["app/a".into()],
        )
        .unwrap().into(),
        commit: Some(
            Draft::new(
                "Desktop-only private message".into(),
                "Example Author".into(),
                "a@example.invalid".into(),
            )
            .unwrap(),
        ),
        changes: tokio::sync::watch::channel(0).0,
    });
    let mut input = commit::Prepare {
        origin: commit::Query {
            project_id: project.clone(),
            service_instance: service.instance().clone(),
            request_id: Id::random().unwrap(),
        },
        grant_id: Id::random().unwrap(),
    };
    assert_eq!(
        service
            .git_commit_prepare(&client, input.clone())
            .unwrap_err(),
        Error::AccessDenied
    );
    input.grant_id = service
        .git_index_requests()
        .allow_commit(scope)
        .unwrap()
        .0
        .grant_id
        .unwrap();
    assert_eq!(
        service
            .git_index_prepare(&client, input.clone())
            .unwrap_err(),
        Error::AccessDenied
    );
    let first = service.git_commit_prepare(&client, input.clone()).unwrap();
    let newer = service.admit_client().unwrap();
    assert_eq!(
        service.git_commit_prepare(&newer, input.clone()).unwrap(),
        first
    );
    assert_eq!(service.git_index_requests().entries().unwrap().len(), 1);
    assert!(service
        .git_index_query(&newer, &input.origin, true)
        .is_err());
    let row = service
        .git_commit_query(&newer, &input.origin, false)
        .unwrap();
    assert!(
        matches!(row, p::ResponseBody::GitCommitRequest(row) if row.0.state == git::State::Queued)
    );
    service.revoke_agent_read().unwrap();
    assert_eq!(
        service
            .git_commit_query(&newer, &input.origin, true)
            .unwrap_err(),
        Error::AccessDenied
    );
    assert_eq!(
        service
            .android_tools_client_current(&newer, &project)
            .unwrap_err(),
        Error::AccessDenied
    );
    service.stop().unwrap();
    drop(service);
    store.close().unwrap();
}
#[test]
fn commit_scope_and_presend_require_same_current_alias() {
    let fixture = Fixture::new();
    let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
    let service = ApplicationService::open(store.clone()).unwrap();
    let (project, _) = register_fixture(&service, &fixture.app, "project", "project-1");
    service
        .allow_agent_read(vec![project.clone()], Duration::from_secs(60))
        .unwrap();
    let client = service.admit_client().unwrap();
    service.git_commit_scope(&client, &project).unwrap();
    service.lock().unwrap().runtime_aliases.clear();
    assert_eq!(
        service.git_commit_scope(&client, &project).unwrap_err(),
        Error::Conflict
    );
    assert_eq!(
        service
            .android_tools_client_current(&client, &project)
            .unwrap_err(),
        Error::Conflict
    );
    service.stop().unwrap();
    drop(service);
    store.close().unwrap();
}
