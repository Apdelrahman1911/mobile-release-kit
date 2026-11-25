use super::*;
fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn words(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}
const I: &str = "11111111111111111111111111111111";
#[test]
fn initialization_cli_has_only_id_prepare_and_explicit_exact_apply() {
    let args = super::super::collect_arguments(words(&[
        "initialization-apply",
        I,
        I,
        I,
        I,
        I,
        I,
        I,
        "--reviewed",
        "--json",
    ]));
    assert!(matches!(parse(&args).unwrap().command, Command::Apply(_)));
    for args in [
        words(&["initialization-prepare", I, "01"]),
        words(&["initialization-prepare", I, "0"]),
        words(&["initialization-prepare", I, "7", "--stdin"]),
        words(&["initialization-apply", I, I, I, I, I, I, I]),
        words(&["initialization-recover", I]),
        words(&["initialization-prepare", I, "7", "/private/path"]),
    ] {
        assert!(parse(&args).is_err());
    }
    assert!(matches!(
        parse(&words(&["initialization-prepare", I, "7", "--json"]))
            .unwrap()
            .command,
        Command::Prepare(_, 7)
    ));
    let q = query(I, I, I).unwrap();
    let request = framed(p::RequestBody::InitializationPrepare(c::Prepare {
        origin: q.clone(),
        expected_observation_revision: 7,
    }))
    .unwrap();
    assert!(matches!(
        p::decode_request(&p::encode_request(&request).unwrap())
            .unwrap()
            .request,
        p::RequestBody::InitializationPrepare(_)
    ));
    let not_reviewed = p::RequestBody::InitializationApply(c::Apply {
        origin: q,
        original: original(I, I, I).unwrap(),
        plan_token: id('2'),
        reviewed: false,
    });
    assert!(framed(not_reviewed).is_err());
}
#[test]
fn initialization_output_keeps_original_ids_unknown_and_missing_ack_no_replay() {
    let q = query(I, I, I).unwrap();
    let row = c::Status {
        schema_version: 1,
        origin: q.clone(),
        runtime_project_id: "init-project".into(),
        revision: 2,
        phase: c::Phase::Unknown,
        settlement: p::Settlement::Unknown,
        original: None,
        review: None,
        permission_available: false,
        permission_consumed: false,
        remaining_ms: 0,
        cancel_requested: false,
        result: None,
        do_not_replay: true,
    };
    let response = p::Response {
        version: p::VERSION,
        request_id: id('2'),
        service_instance: q.service_instance.clone(),
        client_id: id('3'),
        session_id: id('4'),
        response: p::ResponseBody::InitializationRequest(row),
    };
    let (code, bytes) = output(&response, &q, true).unwrap();
    assert_eq!(code, 6);
    assert!(bytes.ends_with(b"\n"));
    assert!(p::decode_response(&bytes, &response.request_id, &response.service_instance).is_ok());
    let mut foreign = q.clone();
    foreign.request_id = id('f');
    assert!(output(&response, &foreign, true).is_err());
    let (code, bytes) = unconfirmed(&q, true);
    assert_eq!(code, 6);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["doNotReplay"], true);
    assert_eq!(value["admission"], "unconfirmed");
    assert_eq!(value["origin"], serde_json::to_value(&q).unwrap());
    let human = String::from_utf8(output(&response, &q, false).unwrap().1).unwrap();
    assert!(human.contains("Unknown") && human.contains("initialization-status"));
    assert!(!human.contains("settled."));
}
#[test]
fn complete_capabilities_and_help_disclose_real_desktop_input_and_recovery_boundary() {
    let bytes = super::super::capabilities(true).unwrap();
    assert!(bytes.len() <= crate::installed_cli::CAPABILITIES_BYTES);
    let all: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let init = &all["initialization"];
    assert_eq!(init["commands"].as_array().unwrap().len(), 4);
    assert_eq!(init["readAuthorizesPrepareOnly"], true);
    assert_eq!(init["requiresSelectedDesktopDraftAndToolkit"], true);
    assert_eq!(init["applyRequiresSeparateNativePreviewConsent"], true);
    for flag in [
        "existingTargetOverwrite",
        "recovery",
        "headless",
        "nativeAvailabilityChecked",
    ] {
        assert_eq!(init[flag], false);
    }
    let human = String::from_utf8(super::super::capabilities(false).unwrap()).unwrap();
    assert!(human.contains("initialization-prepare") && human.contains("Desktop"));
    assert!(super::super::HELP.contains("recovery stays in Desktop"));
}
