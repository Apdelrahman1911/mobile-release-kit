use super::*;
use crate::application_service::tests::register_fixture;
use crate::application_state_store::Fixture;
#[test]
fn original_service_requires_both_grants_and_preserves_request_across_client_reconnect() {
    let f = Fixture::new();
    let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
    let service = ApplicationService::open(store.clone()).unwrap();
    let (project, root) = register_fixture(&service, &f.app, "project", "project-1");
    service
        .allow_agent_read(vec![project.clone()], Duration::from_secs(60))
        .unwrap();
    let client = service.admit_client().unwrap();
    let point = service.git_index_point("project-1").unwrap();
    let doc = Arc::new(());
    let (changes, _) = tokio::sync::watch::channel(0);
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
        selection: git::Selection::new(git::Action::Stage, "a".repeat(64), vec!["app/a".into()])
            .unwrap().into(),
        commit: None,
        changes,
    });
    let mut input = git::Prepare {
        origin: git::Query {
            project_id: project.clone(),
            service_instance: service.instance().clone(),
            request_id: Id::random().unwrap(),
        },
        grant_id: Id::random().unwrap(),
    };
    assert_eq!(
        service
            .git_index_prepare(&client, input.clone())
            .unwrap_err(),
        Error::AccessDenied
    );
    input.grant_id = service
        .git_index_requests()
        .allow(scope)
        .unwrap()
        .grant_id
        .unwrap();
    service.git_index_prepare(&client, input.clone()).unwrap();
    let newer = service.admit_client().unwrap();
    assert_ne!(client.client_id, newer.client_id);
    service.git_index_prepare(&newer, input.clone()).unwrap();
    assert_eq!(service.git_index_requests().entries().unwrap().len(), 1);
    service
        .git_index_query(&newer, &input.origin, true)
        .unwrap();
    service.revoke_agent_read().unwrap();
    assert_eq!(
        service
            .git_index_query(&newer, &input.origin, false)
            .unwrap_err(),
        Error::AccessDenied
    );
    service.stop().unwrap();
    drop(service);
    store.close().unwrap();
}
#[test]
fn current_runtime_alias_and_presend_project_guard_do_not_leak_a_previous_registration() {
    let f = Fixture::new();
    let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
    let service = ApplicationService::open(store.clone()).unwrap();
    let (project, _) = register_fixture(&service, &f.app, "project", "project-1");
    service
        .allow_agent_read(vec![project.clone()], Duration::from_secs(60))
        .unwrap();
    let client = service.admit_client().unwrap();
    service.git_index_scope(&client, &project).unwrap();
    service.lock().unwrap().runtime_aliases.clear();
    assert_eq!(
        service.git_index_scope(&client, &project).unwrap_err(),
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
