//! Inert original InvokeBody DATA tests; no webview, native dispatch or owner.
use super::android_build_request_body;
use tauri::ipc::InvokeBody;

#[test]
fn android_commands_require_original_raw_body_and_preserve_duplicate_detection() {
    assert!(android_build_request_body(&InvokeBody::Json(serde_json::json!({}))).is_err());
    assert!(android_build_request_body(&InvokeBody::Raw(b"{}".to_vec())).is_ok());
    for bytes in [b"".as_slice(), b"{\"a\":1,\"a\":2}", b"{\"a\":{\"b\":1,\"b\":2}}", b"{}{}", b"{\"a\":1e0}"] {
        assert!(android_build_request_body(&InvokeBody::Raw(bytes.to_vec())).is_err());
    }
    let mut boundary = vec![b' '; crate::android_build_protocol::IPC_LIMIT - 2];
    boundary.extend_from_slice(b"{}");
    assert!(android_build_request_body(&InvokeBody::Raw(boundary.clone())).is_ok());
    boundary.push(b' ');
    assert!(android_build_request_body(&InvokeBody::Raw(boundary)).is_err());
}
