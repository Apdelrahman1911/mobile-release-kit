//! Actual default owner census and fixed representation arithmetic only.
//! No project/source admission, native grant, process, file or runtime IO.
use super::*;

#[test]
fn document_limit_is_checked_not_inferred_from_a_successful_census() {
    assert_eq!(document_fits(SESSION_BYTES).unwrap(), SESSION_BYTES);
    assert!(document_fits(SESSION_BYTES + 1).is_err());
    assert!(document_fits(usize::MAX).is_err());
    assert!(grant_cells_bytes(usize::MAX, 1).is_none());
}

#[test]
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )
))]
fn actual_default_document_and_near_limit_copied_doctor_input_fit() {
    // Same inert default constructors as the existing configuration census
    // regression. Their path is DATA; no native registration/Host is called.
    let root = std::path::PathBuf::from("/never-opened-tool-setup-census");
    let bridge = Arc::new(DesktopBridge::new(root.clone()));
    let document = DocumentBinding::new(bridge.clone());
    bridge.edits.initial_document("main").unwrap();
    let state = document.lock();
    let d = document.tool_setup_document_bytes(&state).unwrap();

    let mut map = serde_json::Map::new();
    // Keep room for the real Start/Allow envelopes inside NODE_LIMIT. Wide
    // objects exercise the BTreeMap/node debit, not just a large flat string.
    for i in 0..(crate::protocol::NODE_LIMIT / 2 - 32) {
        map.insert(format!("k{i:05}"), Value::Bool(true));
    }
    map.insert("padding".into(), Value::String(String::new()));
    let mut draft = Value::Object(map);
    let initial = serde_json::to_vec(&draft).unwrap().len();
    draft["padding"] = Value::String("x".repeat(512 * 1024 - initial));
    assert_eq!(serde_json::to_vec(&draft).unwrap().len(), 512 * 1024);
    let raw = serde_json::json!({"projectId":"p1","draftRevision":1,"baselineGeneration":1,
        "platform":"android","operation":"build","draft":draft});
    let input = crate::environment_diagnostics_protocol::start(&raw).unwrap();
    let held = crate::environment_diagnostics_owner::EnvironmentDiagnosticsOwner::tool_setup_doctor_allocation_data(&input, &root).unwrap();
    assert!(
        held > 512 * 1024 * 3,
        "real Value/node copies remain charged"
    );
    let total = d
        .checked_add(held)
        .and_then(|n| {
            n.checked_add(grant_cells_bytes(
                input.project_id.capacity(),
                root.capacity(),
            )?)
        })
        .unwrap();
    assert!(
        document_fits(total).is_ok(),
        "actual default D={d}, fixed copied-input grant={held}, total={total}"
    );
    // Retained capacity cannot be 'freed' by a report or counted as zero. This
    // checks the production gate without allocating another huge fixture.
    assert!(document_fits(total.checked_add(SESSION_BYTES).unwrap()).is_err());
    assert!(state.agent_tool_setup.pending.is_none() && state.agent_tool_setup.grant.is_none());
    drop(state);
    document.lock().agent_tool_setup.lost = true;
    // The actual RAW entry checks its original slot before parsing another
    // draft. A fenced owner cannot be made to retain a second decoded Value.
    assert_eq!(
        document
            .allow_agent_tool_setup(MAIN, b"not JSON")
            .unwrap_err(),
        public(Error::StateUnknown)
    );
}
