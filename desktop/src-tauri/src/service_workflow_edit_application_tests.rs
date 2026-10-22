//! Real existing private Service/Store fixture, without a Workflow Session, child,
//! writer or synthetic retirement. Missing configuration is not WRITE authority.
use super::*;
use crate::{
    application_service::tests::{passive, poison_fixture, register_fixture},
    application_state_store::Fixture,
};

fn setup(
    config_state: &str,
) -> (
    Fixture,
    Arc<PrivateStateDirectory>,
    Arc<ApplicationService>,
    Id,
    ClientSession,
    wire::Prepare,
) {
    let fixture = Fixture::new();
    let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
    let service = Arc::new(ApplicationService::open(store.clone()).unwrap());
    let (id, root) = register_fixture(&service, &fixture.app, "project", "workflow_edit-project");
    let mut observation = passive(&root, &"a".repeat(64));
    observation["config"] = serde_json::json!({"state":config_state,"content":null});
    service
        .publish_passive_snapshot("workflow_edit-project", &observation)
        .unwrap();
    service
        .allow_agent_read(vec![id.clone()], Duration::from_secs(300))
        .unwrap();
    let client = service.admit_client().unwrap();
    let point = ApplicationService::identity_point(&service.state.lock().unwrap(), &id).unwrap();
    let input = wire::Prepare {
        origin: wire::Query {
            service_instance: service.instance().clone(),
            project_id: id.clone(),
            request_id: Id::random().unwrap(),
        },
        expected_observation_revision: point.revision,
    };
    (fixture, store, service, id, client, input)
}
fn view(result: Result<p::ResponseBody, Error>) -> wire::Status {
    match result.unwrap() {
        p::ResponseBody::WorkflowEditRequest(v) => v,
        _ => panic!("wrong closed response"),
    }
}

#[cfg(target_os="macos")]
#[test]
fn missing_or_invalid_configuration_queues_only_original_preparation_and_history_requires_real_ack()
{
    for config_state in ["missing", "invalid"] {
        let (_fixture, store, service, _id, client, input) = setup(config_state);
        let before = store.read(Namespace::Projects).unwrap();
        let first = view(service.workflow_edit_prepare(&client, input.clone()));
        assert_eq!(first.phase, wire::Phase::QueuedOpen);
        assert!(first.original.is_none() && first.review.is_none() && !first.permission_available);
        let mut repeated = view(service.workflow_edit_prepare(&client, input.clone()));
        // Idempotency preserves the request, not an obsolete countdown sample.
        assert!(repeated.remaining_ms > 0 && repeated.remaining_ms <= first.remaining_ms);
        repeated.remaining_ms = first.remaining_ms;
        assert_eq!(repeated, first);
        let unreviewed = wire::Apply {
            origin: input.origin.clone(),
            original: wire::Original {
                session_id: Id::random().unwrap(),
                owner_generation: Id::random().unwrap(),
                revision: Id::random().unwrap(),
            },
            plan_token: Id::random().unwrap(),
            reviewed: true,
        };
        assert_eq!(
            service
                .workflow_edit_apply(&client, unreviewed)
                .unwrap_err(),
            Error::AccessDenied
        );
        let after = store.read(Namespace::Projects).unwrap();
        assert_eq!(
            (before.revision, before.bytes),
            (after.revision, after.bytes)
        );
        let refused = view(service.workflow_edit_query(&client, &input.origin, true));
        assert_eq!(refused.phase, wire::Phase::Refused);
        assert_eq!(refused.settlement, p::Settlement::Pending);
        let entry = service
            .configuration_requests
            .workflow_edit_entry(&input.origin)
            .unwrap();
        assert!(entry.occupied().unwrap());
        // Actual durable Service publication, not status-as-native retirement.
        // This was never claimed by a native Workflow owner, hence no join is forged.
        service.publish_workflow_edit_history().unwrap();
        let final_view = view(service.workflow_edit_query(&client, &input.origin, false));
        assert_eq!(final_view.phase, wire::Phase::Final);
        assert!(final_view.original.is_none() && !final_view.result.unwrap().saved());
        let final_snapshot = store.read(Namespace::Projects).unwrap();
        assert!(final_snapshot.revision.0 > after.revision.0);
        service.publish_workflow_edit_history().unwrap();
        assert_eq!(
            store.read(Namespace::Projects).unwrap().revision,
            final_snapshot.revision
        );
        let rows = service.state.lock().unwrap().saved.operations.clone();
        assert!(rows
            .iter()
            .any(|row| row.action == p::Action::EditGitHubWorkflows));
        service.stop().unwrap();
        store.close().unwrap();
    }
}

#[cfg(target_os="macos")]
#[test]
fn workflow_edit_keeps_actual_read_scope_alias_and_unobserved_poison_not_saved_preferences() {
    let (_fixture, store, service, id, client, input) = setup("missing");
    let mut stale = input.clone();
    stale.expected_observation_revision += 1;
    assert!(service.workflow_edit_prepare(&client, stale).is_err());
    let mut foreign = input.clone();
    foreign.origin.project_id = Id::random().unwrap();
    assert!(service.workflow_edit_prepare(&client, foreign).is_err());
    view(service.workflow_edit_prepare(&client, input.clone()));
    let entry = service
        .configuration_requests
        .workflow_edit_entry(&input.origin)
        .unwrap();
    service
        .allow_agent_read(vec![id], Duration::from_secs(300))
        .unwrap();
    let next = service.admit_client().unwrap();
    assert!(service
        .workflow_edit_query(&client, &input.origin, false)
        .is_err());
    assert!(!entry.live(Instant::now()));
    assert!(service.workflow_edit_current(&entry, true).is_err());
    assert_eq!(
        view(service.workflow_edit_query(&next, &input.origin, false)).phase,
        wire::Phase::Refused
    );
    service.publish_workflow_edit_history().unwrap();
    service
        .state
        .lock()
        .unwrap()
        .runtime_aliases
        .remove("workflow_edit-project");
    assert!(service.workflow_edit_current(&entry, false).is_err());
    poison_fixture(&service);
    assert!(service.native_history_current().is_err());
    assert!(service.workflow_edit_current(&entry, false).is_err());
    store.close().unwrap();
}

#[cfg(not(target_os="macos"))]
#[test]
fn unsupported_workflow_platform_refuses_before_book_or_history_even_with_real_read() {
    let (_fixture,store,service,_id,client,input)=setup("missing");
    let before=store.read(Namespace::Projects).unwrap();
    assert!(!wire::platform_supported());
    assert!(matches!(service.workflow_edit_prepare(&client,input.clone()),Err(Error::Unavailable)));
    let apply=wire::Apply{origin:input.origin.clone(),original:wire::Original{
        session_id:Id::random().unwrap(),owner_generation:Id::random().unwrap(),revision:Id::random().unwrap()},
        plan_token:Id::random().unwrap(),reviewed:true};
    assert!(matches!(service.workflow_edit_apply(&client,apply),Err(Error::Unavailable)));
    assert!(service.configuration_requests.workflow_edit_entry(&input.origin).is_err());
    let after=store.read(Namespace::Projects).unwrap();
    assert_eq!((before.revision,before.bytes),(after.revision,after.bytes));
    service.stop().unwrap();store.close().unwrap();
}
