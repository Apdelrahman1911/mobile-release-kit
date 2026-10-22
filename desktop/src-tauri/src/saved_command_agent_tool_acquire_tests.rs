//! Private comparison/actual dormant Session DATA, never a native join fixture.
//! No runtime, source census, file, picker, permit or child is entered here.
use super::*;
use serde_json::json;
fn inspection(mask: u8) -> (SavedCommandOwner, Arc<Inspection>) {
    let context = wire::prepare(&json!({"projectId":"p1","draftRevision":1,"baselineGeneration":2,
        "savedConfig":{"bytes":120,"sha256":"a".repeat(64)},"action":"inspect","review":null})).unwrap();
    let owner = SavedCommandOwner::new(RuntimeConfig::packaged("/never-opened-tool-runtime".into()), SavedCommandDomain::ToolAcquisition);
    let (owner, original) = crate::saved_command_owner::tests::active_with_context(owner, Context::ToolAcquisition(context.clone()));
    // A terminal's comparison setters do not make its Session joined. Keep all
    // original driver/watchdog/observer slots untouched and assert refusal below.
    let mut terminal: wire::Terminal = serde_json::from_value(json!({"schemaVersion":1,"context":context,
        "outcome":"complete","reason":"none","result":{"requirements":{"sourcesSha256":"b".repeat(64)}},
        "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":false,"commands":0,"profileCalls":0,
            "inputClosed":true,"handlersRestored":true,"resourcesClosed":true,"stopObserved":"none"}})).unwrap();
    terminal.observe_protected_tools(wire::ProtectedTools::NoneInSupportedCatalogue);
    terminal.observe_components(wire::components::Partition::observed(std::array::from_fn(|i| Some(mask & (1 << i) == 0))).unwrap());
    (owner, Arc::new(Inspection { original, terminal }))
}
#[test]
fn sixteen_original_partitions_project_only_missing_components_without_granting_a_join() {
    let all = [p::Component::Jdk, p::Component::AndroidPlatform, p::Component::AndroidBuildTools, p::Component::Gradle];
    for mask in 0..16 {
        let (_owner, original) = inspection(mask);
        let selected = Original::selected(&original);
        if mask == 0 { assert!(selected.is_none()); continue; }
        let selected = selected.unwrap();
        assert!(selected.missing.capacity() <= 4 && selected.compatible.capacity() <= 4);
        assert!(selected.retained_bytes().unwrap() <= p::ACQUISITION_HEAP_BYTES);
        assert_eq!(selected.missing, all.into_iter().enumerate().filter_map(|(i,c)| (mask & (1 << i) != 0).then_some(c)).collect::<Vec<_>>());
        assert_eq!(selected.compatible, all.into_iter().enumerate().filter_map(|(i,c)| (mask & (1 << i) == 0).then_some(c)).collect::<Vec<_>>());
        let mut acquire = original.terminal.context.clone();
        acquire.action = wire::Action::Acquire;
        acquire.review = Some(wire::Review { operation_id: original.original.id.clone(), owner_generation: original.original.generation.clone(),
            requirements_sha256: selected.requirements_sha256 });
        assert!(!original_joined(&original.original));
        assert!(!original.matches(&acquire, original.original.registration, &original.original.project));
    }
}
#[test]
fn equal_inspection_data_in_a_replaced_slot_cannot_satisfy_the_original_weak_identity() {
    let (owner, original) = inspection(4);
    let selection = Original::selected(&original).unwrap();
    let bound = Original { inspection: Arc::downgrade(&original) };
    let replacement = Arc::new(Inspection { original: original.original.clone(), terminal: original.terminal.clone() });
    assert_eq!(Original::selected(&replacement).as_ref(), Some(&selection));
    let mut r = owner.inner.lock();
    r.tool_acquisition.review = Some(original.clone());
    assert!(bound.current_inspection(&r).is_some()); // Pointer comparison only, not matches_source/Prepare.
    r.tool_acquisition.review = Some(replacement);
    assert!(bound.current_inspection(&r).is_none());
    r.tool_acquisition.review = None;
    drop(original);
    assert!(bound.inspection.upgrade().is_none());
    assert!(bound.current_inspection(&r).is_none());
}
