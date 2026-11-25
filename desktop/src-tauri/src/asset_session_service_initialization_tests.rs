//! Original RAW decoders and borrowed default-Document gates, not an installed
//! native Init Session, picker, provider operation or fabricated success receipt.
use super::*;
use serde::Deserialize;
use serde_json::json;

fn origin() -> Value {
    json!({"serviceInstance":"1".repeat(32),"projectId":"2".repeat(32),"requestId":"3".repeat(32)})
}
fn open() -> Value {
    json!({"agentInitialization":true,"origin":origin(),"input":{"intent":"initialize","projectId":"init-project","draft":{},"toolingRepository":"example/toolkit","toolingSha":"b".repeat(40),"draftRevision":7,"baselineGeneration":3}})
}

#[test]
fn initialization_raw_is_closed_current_main_input_and_never_recovery_or_ipc_draft() {
    let body = open();
    let bytes = serde_json::to_vec(&body).unwrap();
    let (q, input) = raw_request(&bytes, Kind::Open).unwrap();
    assert_eq!(q.request_id.as_str(), "3".repeat(32));
    assert!(matches!(
        input,
        Input::Open(n::Open::Initialize {
            draft_revision: 7,
            baseline_generation: 3,
            ..
        })
    ));
    for (kind, input) in [
        (
            Kind::Prepare,
            json!({"intent":"initialize","sessionId":"4".repeat(32),"revision":"5".repeat(32)}),
        ),
        (
            Kind::Apply,
            json!({"intent":"initialize","sessionId":"4".repeat(32),"planToken":"6".repeat(32)}),
        ),
    ] {
        let value = json!({"agentInitialization":true,"origin":origin(),"input":input});
        assert!(raw_request(&serde_json::to_vec(&value).unwrap(), kind).is_ok());
        let mut recovery = value.clone();
        recovery["input"]["intent"] = json!("recover");
        assert!(raw_request(&serde_json::to_vec(&recovery).unwrap(), kind).is_err());
        let mut foreign = value;
        foreign["input"]["window"] = json!("other");
        assert!(raw_request(&serde_json::to_vec(&foreign).unwrap(), kind).is_err());
    }
    for field in ["window", "root", "force", "allowOverwrite"] {
        let mut bad = body.clone();
        bad[field] = json!(true);
        assert!(initialization_agent_raw(&bad, Kind::Open).is_err());
    }
    let mut recover = body.clone();
    recover["input"] = json!({"intent":"recover","projectId":"init-project"});
    assert!(initialization_agent_raw(&recover, Kind::Open).is_err());
    let mut excessive = body.clone();
    excessive["input"]["draft"] = json!({"x":"a".repeat(512*1024)});
    assert!(initialization_agent_raw(&excessive, Kind::Open).is_err());
    let mut nodes = body.clone();
    nodes["input"]["draft"] = json!({"x":vec![0;8001]});
    assert!(initialization_agent_raw(&nodes, Kind::Open).is_err());
    let duplicate = String::from_utf8(bytes).unwrap().replacen(
        "\"agentInitialization\":true",
        "\"agentInitialization\":true,\"agentInitialization\":true",
        1,
    );
    assert!(raw_request(duplicate.as_bytes(), Kind::Open).is_err());
    assert!(raw_request(
        &vec![b' '; crate::edit_protocol::REQUEST_LIMIT + 1],
        Kind::Open
    )
    .is_err());
    // Ordinary original Open is still decoded by its unchanged JSON frontdoor.
    assert!(initialization_agent_raw(&body["input"], Kind::Open)
        .unwrap()
        .is_none());
    assert!(crate::edit_commands::initialization_open(&body["input"]).is_ok());
    assert!(crate::service_initialization_protocol::Prepare::deserialize(body).is_err());
}

#[test]
fn initialization_default_document_includes_complete_edit_future_and_retained_capacity() {
    let bridge = Arc::new(DesktopBridge::new(std::path::PathBuf::from(
        "/never-opened-initialization-census",
    )));
    let document = DocumentBinding::new(bridge.clone());
    bridge.edits.initial_document("main").unwrap();
    let mut state = document.lock();
    let base = lookup_memory::retained_document_bytes(&document.inner, &state).unwrap();
    let additional = installation_memory::additional_document_bytes(&document, &state).unwrap();
    let edit = bridge.edits.initialization_agent_edit_backing().unwrap();
    let total = document.initialization_agent_storage(&state).unwrap();
    let code = crate::macos_history_inventory::CODE_CONTROL_RESERVE;
    let data = total.checked_sub(code).unwrap();
    eprintln!("Initialization D={base} additional={additional} code={code} fullEditFuture={edit} data={data} dataCap={SESSION_BYTES} total={total} combinedCap={}",code+SESSION_BYTES);
    assert_eq!(total, base + additional + edit);
    assert_eq!(
        crate::macos_history_inventory::SHARED_DATA_LIMIT,
        SESSION_BYTES
    );
    assert!(data <= SESSION_BYTES);
    assert!(total <= code + SESSION_BYTES);
    assert!(
        edit > code
            + crate::edit_protocol::REQUEST_LIMIT
            + crate::project_initialization_edit_protocol::RESPONSE_LIMIT
    );
    // Minimum additional real Vec capacity which crosses this actual target's
    // cap. Count the retained storage even though it has no live records.
    let needed = (SESSION_BYTES - data) / std::mem::size_of::<Record>() + 2;
    state.records.reserve_exact(needed);
    let capacity = state.records.capacity();
    let over = lookup_memory::retained_document_bytes(&document.inner, &state).unwrap();
    assert!(over + additional + edit - code > SESSION_BYTES);
    assert!(document.initialization_agent_storage(&state).is_err());
    assert_eq!(state.records.capacity(), capacity);
    assert!(state.records.is_empty());
}

#[test]
fn initialization_first_peer_cut_has_no_publisher_or_saved_input_side_effect() {
    let bridge = Arc::new(DesktopBridge::new(std::path::PathBuf::from(
        "/never-opened-initialization-peer-gate",
    )));
    let document = DocumentBinding::new(bridge.clone());
    bridge.edits.initial_document("main").unwrap();
    let epoch = document.inner.android_registration_control.epoch().unwrap();
    let mut state = document.lock();
    state.stopping = true;
    assert!(document.initialization_agent_peers(&state, true).is_err());
    assert!(document.initialization_agent_peers(&state, false).is_err());
    assert_eq!(
        document.inner.android_registration_control.epoch().unwrap(),
        epoch
    );
    assert!(state.stopping);
    assert!(bridge.edits.can_exit());
}
