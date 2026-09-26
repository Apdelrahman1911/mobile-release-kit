//! Inert DTO/decoder tests. No project is opened, no original join is invented,
//! and no model value qualifies the native ProjectRecovery runtime.
use super::*;

pub(crate) fn context() -> Context {
    Context { project_id: "inert-project".into(), draft_revision: 2, baseline_generation: 3,
        action: Action::Inspect, review: None }
}
pub(crate) fn eligible_observation() -> Observation {
    Observation { status: InspectionStatus::Pending, session: Some("c".repeat(32)),
        roles: vec![Role::AndroidServices], quiescence: Quiescence::Original }
}
pub(crate) fn terminal_value(context: &Context) -> Value {
    json!({"schemaVersion":1,"context":context,"outcome":"complete","reason":"none",
        "effect":if context.action == Action::Inspect { "inspection" } else { "recovery-attempted" },
        "reviewStamp":if context.action == Action::Inspect { Some("d".repeat(64)) } else { None },
        "result":{"schemaVersion":1,"scope":"project-build-inputs-only","action":context.action,
            "observation":if context.action == Action::Inspect { Some(eligible_observation()) } else { None },
            "recoveredSession":context.review.as_ref().and_then(|review| review.session.clone()),"limitations":LIMITATIONS},
        "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":false,
            "commands":0,"profileCalls":0,"inputClosed":true,"handlersRestored":true,
            "resourcesClosed":true,"stopObserved":"none"}})
}
fn encode(payload: Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({"protocol":PROTOCOL,"operationId":"a".repeat(32),
        "ownerGeneration":"b".repeat(32),"sequence":1,"kind":"terminal","payload":payload})).unwrap();
    bytes.push(b'\n'); bytes
}
pub(crate) fn terminal_frame(context: &Context) -> Frame {
    decode(&encode(terminal_value(context)), &"a".repeat(32), &"b".repeat(32), context).unwrap()
}
fn accepted(value: Value, context: &Context) -> bool {
    decode(&encode(value), &"a".repeat(32), &"b".repeat(32), context).is_ok()
}

#[test]
fn recovery_request_is_closed_and_renderer_cannot_supply_a_session_or_stamp() {
    let input = json!({"projectId":"inert-project","draftRevision":2,"baselineGeneration":3,"action":"recover"});
    let parsed = prepare(&input).unwrap();
    assert!(parsed.context().review.is_none());
    assert!(!parsed.context().valid()); // Native must fill its original review.
    for name in ["review", "session", "reviewStamp", "root", "manual", "confirm", "command", "environment"] {
        let mut extra = input.clone(); extra[name] = json!("UNTRUSTED"); assert!(prepare(&extra).is_err());
    }
    for bytes in [b"{\"action\":\"inspect\",\"action\":\"recover\"}".as_slice(), b"{} trailing", b""] {
        assert!(raw_request(bytes).is_err());
    }
    assert!(status_request(&json!({})).is_ok());
    assert!(status_request(&json!({"projectId":"inert-project"})).is_err());
    let start_input = json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":CONSENT});
    assert!(start(&start_input).is_ok());
    let mut wrong = start_input; wrong["consentVersion"] = json!(crate::offline_preflight_protocol::CONSENT);
    assert!(start(&wrong).is_err());
}

#[test]
fn recorded_none_never_supplies_recovery_and_cleanup_only_is_not_file_restore() {
    let mut observed = eligible_observation(); assert!(observed.eligible());
    observed.quiescence = Quiescence::Operator; assert!(observed.eligible());
    observed.quiescence = Quiescence::None; assert!(observed.valid() && !observed.eligible());
    let mut selected = context(); selected.action = Action::Recover; selected.review = Some(observed.clone());
    assert!(!selected.valid());
    observed.status = InspectionStatus::CleanupOnly; observed.quiescence = Quiescence::Original;
    assert!(!observed.valid()); observed.roles.clear(); assert!(observed.eligible());
    for state in [InspectionStatus::Idle, InspectionStatus::Busy, InspectionStatus::Conflict] {
        observed.status = state; assert!(!observed.valid());
        let empty = Observation { status: state, session: None, roles: vec![], quiescence: Quiescence::None };
        assert!(empty.valid() && !empty.eligible());
    }
}

#[test]
fn native_request_needs_exact_domain_identity_and_private_review() {
    let mut root = RegisteredRoot { path: "/inert-project".into(),
        identity: crate::asset_source::ProjectIdentity::Posix(crate::asset_source::DirectoryIdentity::synthetic_evidence_identity()) };
    let selected = context();
    assert!(request(&"a".repeat(32), &"b".repeat(32), &selected, Profile::LinuxX64, &root, Path::new("/inert-work"), None).is_ok());
    assert!(request(&"a".repeat(32), &"b".repeat(32), &selected, Profile::LinuxX64, &root, Path::new("/inert-work"), Some(&"d".repeat(64))).is_err());
    let selected = Context { action: Action::Recover, review: Some(eligible_observation()), ..selected };
    assert!(request(&"a".repeat(32), &"b".repeat(32), &selected, Profile::LinuxX64, &root, Path::new("/inert-work"), None).is_err());
    assert!(request(&"a".repeat(32), &"b".repeat(32), &selected, Profile::LinuxX64, &root, Path::new("/inert-work"), Some(&"d".repeat(64))).is_ok());
    root.identity = crate::asset_source::ProjectIdentity::Windows { volume: 1, file_id: [1; 16] };
    assert!(request(&"a".repeat(32), &"b".repeat(32), &selected, Profile::LinuxX64, &root, Path::new("/inert-work"), Some(&"d".repeat(64))).is_err());
}

#[test]
fn complete_requires_all_original_core_custody_and_no_command_activity() {
    let selected = context(); let good = terminal_value(&selected); assert!(accepted(good.clone(), &selected));
    for (key, value) in [("resourcesClosed", json!(false)), ("inputClosed", json!(false)),
        ("handlersRestored", json!(false)), ("commandDispatched", json!(true)), ("commands", json!(1)),
        ("profileCalls", json!(1)), ("fatal", json!(true)), ("complete", json!(false))] {
        let mut bad = good.clone(); bad["lifetime"][key] = value; assert!(!accepted(bad, &selected));
    }
    for value in [json!(null), json!("incorrect")] {
        let mut bad = good.clone(); bad["reviewStamp"] = value; assert!(!accepted(bad, &selected));
    }
    let mut absent = good.clone(); absent["result"]["observation"]["quiescence"] = json!("none");
    absent["reviewStamp"] = Value::Null; assert!(accepted(absent.clone(), &selected));
    absent["reviewStamp"] = json!("d".repeat(64)); assert!(!accepted(absent, &selected));
    let mut rejected = good.clone(); rejected["effect"] = json!("recovery-attempted"); assert!(!accepted(rejected, &selected));
}

#[test]
fn recovery_failure_and_unknown_never_claim_a_recovered_session() {
    let selected = Context { action: Action::Recover, review: Some(eligible_observation()), ..context() };
    let good = terminal_value(&selected); assert!(accepted(good.clone(), &selected));
    let mut changed = good.clone(); changed["result"]["recoveredSession"] = json!("e".repeat(32)); assert!(!accepted(changed, &selected));
    let mut failure = good; failure["outcome"] = json!("failed"); failure["reason"] = json!("project-conflict");
    assert!(!accepted(failure.clone(), &selected)); failure["result"] = Value::Null;
    assert!(accepted(failure.clone(), &selected));
    failure["outcome"] = json!("cancelled"); failure["reason"] = json!("cancelled");
    assert!(!accepted(failure.clone(), &selected)); failure["lifetime"]["stopObserved"] = json!("cancelled");
    assert!(accepted(failure.clone(), &selected));
    failure["outcome"] = json!("unknown"); failure["reason"] = json!("cleanup-unknown");
    assert!(!accepted(failure.clone(), &selected)); failure["lifetime"]["resourcesClosed"] = json!(false);
    assert!(accepted(failure, &selected));
}

#[test]
fn recovery_ipc_is_local_and_the_packaged_entry_is_separately_qualified() {
    let commands = include_str!("../build.rs").split("const COMMANDS: &[&str] = &[").nth(1).unwrap().split("];").next().unwrap();
    let capability: Value = serde_json::from_str(include_str!("../capabilities/main.json")).unwrap();
    assert_eq!(capability["local"], true); assert!(capability.get("remote").is_none());
    let permissions = capability["permissions"].as_array().unwrap();
    for command in ["prepare_project_recovery", "start_project_recovery", "project_recovery_status", "cancel_project_recovery"] {
        assert_eq!(commands.matches(format!("\"{command}\"").as_str()).count(), 1);
        let permission = format!("allow-{}", command.replace('_', "-"));
        assert_eq!(permissions.iter().filter(|value| value.as_str() == Some(permission.as_str())).count(), 1);
    }
}
