//! Original InvokeBody variant/size tests only. No webview or native owner.
use super::preflight_request_body;
use tauri::ipc::InvokeBody;

#[test]
fn offline_commands_require_original_raw_body_not_a_json_value() {
    assert!(preflight_request_body(&InvokeBody::Json(serde_json::json!({}))).is_err());
    assert!(preflight_request_body(&InvokeBody::Raw(b"{}".to_vec())).is_ok());
    assert!(preflight_request_body(&InvokeBody::Raw(b"{\"a\":1,\"a\":2}".to_vec())).is_err());
    assert!(preflight_request_body(&InvokeBody::Raw(Vec::new())).is_err());
    let mut boundary = vec![b' '; 8190]; boundary.extend_from_slice(b"{}");
    assert!(preflight_request_body(&InvokeBody::Raw(boundary.clone())).is_ok());
    boundary.push(b' ');
    assert!(preflight_request_body(&InvokeBody::Raw(boundary)).is_err());
}
