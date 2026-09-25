//! Inert closed-DATA tests only; no runtime, project, IO or native permission.
use super::*;

pub(crate) fn context() -> Context {
    Context { project_id: "inert-project".into(), draft_revision: 2, baseline_generation: 3,
        saved_config: Content { bytes: 123, sha256: "c".repeat(64) }, platform: Platform::Android,
        operation: Operation::OfflinePreflight }
}
fn result(context: &Context) -> Value {
    json!({"schemaVersion":1,"scope":"saved-offline-android-no-core-build","usedConfig":context.saved_config,
        "findings":[{"ordinal":0,"check":"configured-project-check","message":"configured-project-check",
            "status":"FAIL","projectCheckIndex":0}],
        "summary":{"total":1,"shown":1,"omitted":0,"counts":{"PASS":0,"FAIL":1,"MISSING":0,"BLOCKED":0,
            "INVALID":0,"SKIP":0,"MANUAL":0,"CONFIGURED":0,"NOT_APPLICABLE":0}},
        "limitations":LIMITATIONS})
}
fn terminal_value(context: &Context) -> Value {
    json!({"schemaVersion":1,"context":context,"outcome":"complete","reason":"none","result":result(context),
        "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":true,"commands":1,
            "profileCalls":0,"inputClosed":true,"handlersRestored":true,"invocationClosed":true,"stopObserved":"none"}})
}
fn encode(payload: Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({"protocol":PROTOCOL,"operationId":"a".repeat(32),
        "ownerGeneration":"b".repeat(32),"sequence":1,"kind":"terminal","payload":payload})).unwrap();
    bytes.push(b'\n'); bytes
}
fn decoded(payload: Value, context: &Context) -> Result<Frame, BridgeError> {
    decode(&encode(payload), &"a".repeat(32), &"b".repeat(32), context)
}
pub(crate) fn terminal_frame(context: &Context) -> Frame { decoded(terminal_value(context), context).unwrap() }

#[test]
fn native_preflight_request_refuses_windows_identity_before_posix_dto() {
    use crate::asset_source::{DirectoryIdentity, ProjectIdentity};
    // Absolute POSIX-shaped DATA isolates the identity check from path refusal.
    // Neither fixture opens a project, observes a token or invokes a process.
    let mut root = RegisteredRoot { path: "/inert-project".into(),
        identity: ProjectIdentity::Posix(DirectoryIdentity::synthetic_evidence_identity()) };
    assert!(request(&"a".repeat(32), &"b".repeat(32), &context(), Profile::LinuxX64,
        &root, Path::new("/inert-cwd")).is_ok());
    root.identity = ProjectIdentity::Windows { volume: u64::MAX, file_id: [0xff; 16] };
    assert!(request(&"a".repeat(32), &"b".repeat(32), &context(), Profile::LinuxX64,
        &root, Path::new("/inert-cwd")).is_err());
}

#[test]
fn tauri_command_allowlist_keeps_saved_preflight_local_and_explicit() {
    // Compile-time source DATA only; no filesystem access or shell launch.
    let build = include_str!("../build.rs");
    let commands = build.split("const COMMANDS: &[&str] = &[").nth(1).unwrap().split("];").next().unwrap();
    let capability: Value = serde_json::from_str(include_str!("../capabilities/main.json")).unwrap();
    assert_eq!(capability["identifier"], "main");
    assert_eq!(capability["windows"], json!(["main"]));
    assert_eq!(capability["local"], true);
    assert!(capability.get("remote").is_none());
    let permissions = capability["permissions"].as_array().unwrap();
    for command in ["prepare_offline_preflight", "start_offline_preflight", "offline_preflight_status", "cancel_offline_preflight"] {
        let declared = format!("\"{command}\"");
        assert_eq!(commands.matches(declared.as_str()).count(), 1);
        let permission = format!("allow-{}", command.replace('_', "-"));
        assert_eq!(permissions.iter().filter(|value| value.as_str() == Some(permission.as_str())).count(), 1);
    }
}

#[test]
fn original_raw_length_duplicate_keys_and_closed_renderer_selection() {
    let mut boundary = vec![b' '; IPC_LIMIT - 2]; boundary.extend_from_slice(b"{}");
    assert!(status_request(&raw_request(&boundary).unwrap()).is_ok());
    boundary.push(b' '); assert!(raw_request(&boundary).is_err());
    for bytes in [b"".as_slice(), b"{\"a\":1,\"a\":2}", b"{\"number\":NaN}", b"{} trailing"] {
        assert!(raw_request(bytes).is_err());
    }
    let valid = json!({"projectId":"inert-project","draftRevision":2,"baselineGeneration":3,
        "savedConfig":{"bytes":123,"sha256":"c".repeat(64)}});
    assert!(prepare(&valid).is_ok());
    for key in ["draft", "argv", "environment", "root", "runtime"] {
        let mut value = valid.clone(); value[key] = json!("PRIVATE"); assert!(prepare(&value).is_err());
    }
    for value in [json!(true), json!(u32::MAX), json!(-1)] {
        let mut input = valid.clone(); input["draftRevision"] = value; assert!(prepare(&input).is_err());
    }
    let mut run = json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":CONSENT});
    assert!(start(&run).is_ok()); run["consentVersion"] = json!("other"); assert!(start(&run).is_err());
    assert!(cancel(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32)})).is_ok());
    assert!(status_request(&json!({"projectId":"inert-project"})).is_err());
}

#[test]
fn complete_negative_is_valid_but_closed_lifetime_and_used_config_are_required() {
    let context = context();
    assert!(matches!(terminal_frame(&context), Frame::Terminal(t) if t.outcome == Outcome::Complete));
    for field in ["complete", "contained", "inputClosed", "handlersRestored", "invocationClosed"] {
        let mut payload = terminal_value(&context); payload["lifetime"][field] = json!(false);
        assert!(decoded(payload.clone(), &context).is_err());
        payload["outcome"] = json!("unknown"); payload["reason"] = json!("cleanup-unknown"); payload["result"] = Value::Null;
        assert!(decoded(payload, &context).is_ok());
    }
    let mut payload = terminal_value(&context); payload["result"]["usedConfig"]["sha256"] = json!("d".repeat(64));
    assert!(decoded(payload, &context).is_err());
    let mut payload = terminal_value(&context); payload["context"]["baselineGeneration"] = json!(4);
    assert!(decoded(payload, &context).is_err());
    let mut payload = terminal_value(&context); payload["lifetime"]["profileCalls"] = json!(1);
    assert!(decoded(payload, &context).is_err());
}

#[test]
fn required_nullables_rows_and_exact_summary_cannot_be_omitted_or_extended() {
    let context = context();
    for path in ["result", "context"] {
        let mut payload = terminal_value(&context); payload.as_object_mut().unwrap().remove(path);
        assert!(decoded(payload, &context).is_err());
    }
    let mut payload = terminal_value(&context);
    payload["lifetime"].as_object_mut().unwrap().remove("commandDispatched"); assert!(decoded(payload, &context).is_err());
    let mut payload = terminal_value(&context);
    payload["result"]["findings"][0].as_object_mut().unwrap().remove("projectCheckIndex"); assert!(decoded(payload, &context).is_err());
    for (field, value) in [("ordinal", json!(1)), ("projectCheckIndex", json!(32)), ("message", json!("PRIVATE")), ("path", json!("PRIVATE"))] {
        let mut payload = terminal_value(&context); payload["result"]["findings"][0][field] = value;
        assert!(decoded(payload, &context).is_err());
    }
    for field in ["shown", "total", "omitted"] {
        let mut payload = terminal_value(&context); payload["result"]["summary"][field] = json!(4097);
        assert!(decoded(payload, &context).is_err());
    }
    let mut payload = terminal_value(&context); payload["result"]["limitations"].as_array_mut().unwrap().reverse();
    assert!(decoded(payload, &context).is_err());
    let mut payload = terminal_value(&context); payload["result"]["summary"]["counts"]["FAIL"] = json!(0);
    assert!(decoded(payload, &context).is_err());
}

#[test]
fn unknown_is_not_a_successful_receipt_and_framing_is_not_a_loose_json_document() {
    let context = context();
    let mut payload = terminal_value(&context); payload["outcome"] = json!("unknown");
    payload["reason"] = json!("cleanup-unknown"); payload["result"] = Value::Null;
    assert!(decoded(payload.clone(), &context).is_err());
    payload["lifetime"]["fatal"] = json!(true); assert!(decoded(payload, &context).is_ok());
    let original = encode(terminal_value(&context));
    let mut extra = original.clone(); extra.extend_from_slice(b"{}\n");
    assert!(decode(&extra, &"a".repeat(32), &"b".repeat(32), &context).is_err());
    assert!(decode(&original[..original.len()-1], &"a".repeat(32), &"b".repeat(32), &context).is_err());
    assert!(decode(&original, &"f".repeat(32), &"b".repeat(32), &context).is_err());
}
