//! Real private Service/Store fixture. No Config native Session or writer is
//! constructed; these tests prove only READ scope and enqueue authority.
use super::*;
use crate::{
    application_service::tests::{passive, poison_fixture, register_fixture},
    application_state_store::Fixture,
};
fn setup() -> (
    Fixture,
    Arc<PrivateStateDirectory>,
    Arc<ApplicationService>,
    Id,
    ClientSession,
    wire::Read,
) {
    let f = Fixture::new();
    let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
    let service = Arc::new(ApplicationService::open(store.clone()).unwrap());
    let (id, root) = register_fixture(&service, &f.app, "project", "config-project");
    service
        .publish_passive_snapshot("config-project", &passive(&root, &"a".repeat(64)))
        .unwrap();
    service
        .allow_agent_read(vec![id.clone()], Duration::from_secs(300))
        .unwrap();
    let client = service.admit_client().unwrap();
    let point = ApplicationService::identity_point(&service.state.lock().unwrap(), &id).unwrap();
    let input = wire::Read {
        origin: wire::Query {
            service_instance: service.instance().clone(),
            project_id: id.clone(),
            request_id: Id::random().unwrap(),
        },
        expected_observation_revision: point.revision,
    };
    (f, store, service, id, client, input)
}
fn view(result: Result<p::ResponseBody, Error>) -> wire::Status {
    match result.unwrap() {
        p::ResponseBody::ConfigurationRequest(v) => v,
        _ => panic!("wrong closed response"),
    }
}
#[test]
fn current_read_enqueues_without_store_mutation_and_does_not_authorize_apply() {
    let (_f, store, service, _, client, input) = setup();
    let before = store.read(Namespace::Projects).unwrap();
    let first = view(service.configuration_read(&client, input.clone()));
    assert_eq!(first.phase, wire::Phase::QueuedRead);
    assert!(
        first.original.is_none()
            && first.review.is_none()
            && !first.permission_live
            && !first.apply_consumed
    );
    assert_eq!(
        view(service.configuration_read(&client, input.clone())),
        first
    );
    let bytes = serde_json::to_string(&first).unwrap();
    assert!(!bytes.contains("mustNotEscape") && !bytes.contains("sentinel"));
    assert_eq!(
        service
            .configuration_apply(
                &client,
                wire::Apply {
                    origin: input.origin.clone(),
                    original: wire::Original {
                        session_id: Id::random().unwrap(),
                        owner_generation: Id::random().unwrap(),
                        revision: Id::random().unwrap()
                    },
                    plan_token: Id::random().unwrap(),
                    reviewed: true
                }
            )
            .unwrap_err(),
        Error::AccessDenied
    );
    let after = store.read(Namespace::Projects).unwrap();
    assert_eq!(before.revision, after.revision);
    assert_eq!(before.bytes, after.bytes);
    view(service.configuration_query(&client, &input.origin, true));
    service.stop().unwrap();
    store.close().unwrap();
}
#[test]
fn renewal_observes_and_stops_old_request_but_never_revives_original_facet() {
    let (_f, store, service, id, client, input) = setup();
    view(service.configuration_read(&client, input.clone()));
    let entry = service
        .configuration_requests()
        .entry(&input.origin)
        .unwrap();
    service
        .allow_agent_read(vec![id], Duration::from_secs(300))
        .unwrap();
    let next = service.admit_client().unwrap();
    assert!(service
        .configuration_query(&client, &input.origin, false)
        .is_err());
    assert!(!entry.live(Instant::now()));
    assert!(service.configuration_current(&entry, true).is_err());
    assert_eq!(
        view(service.configuration_query(&next, &input.origin, false)).phase,
        wire::Phase::Refused
    );
    view(service.configuration_query(&next, &input.origin, true));
    service.stop().unwrap();
    store.close().unwrap();
}
#[test]
fn wrong_project_stale_alias_and_unobserved_poison_are_not_read_or_native_authority() {
    let (_f, store, service, _, client, input) = setup();
    let mut bad = input.clone();
    bad.origin.project_id = Id::random().unwrap();
    assert!(service.configuration_read(&client, bad).is_err());
    bad = input.clone();
    bad.expected_observation_revision += 1;
    assert!(service.configuration_read(&client, bad).is_err());
    view(service.configuration_read(&client, input.clone()));
    let entry = service
        .configuration_requests()
        .entry(&input.origin)
        .unwrap();
    service
        .state
        .lock()
        .unwrap()
        .runtime_aliases
        .remove("config-project");
    assert!(service.configuration_current(&entry, true).is_err());
    poison_fixture(&service);
    assert!(service.native_history_current().is_err());
    assert!(service.configuration_current(&entry, false).is_err());
    // Original poison is retained; this is not a recovered Store/Service claim.
    store.close().unwrap();
}
