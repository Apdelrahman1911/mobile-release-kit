use super::*;
fn words(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}
const ID: &str = "11111111111111111111111111111111";
#[test]
fn actual_bounded_cli_collector_keeps_apply_and_explicit_review_argument() {
    let input = words(&[
        "configuration-apply",
        ID,
        ID,
        ID,
        ID,
        ID,
        ID,
        ID,
        "--reviewed",
        "--json",
    ]);
    let original = super::super::collect_arguments(input);
    let parsed = parse(&original).unwrap();
    assert!(parsed.json);
    assert!(matches!(parsed.command, Command::Apply(_)));
    let mut extra = original.clone();
    extra.push("trailing".into());
    assert!(parse(&super::super::collect_arguments(extra)).is_err());
    assert!(parse(&words(&["configuration-apply", ID, ID, ID, ID, ID, ID, ID])).is_err());
}
#[test]
fn strict_stdin_and_typed_requests_never_accept_full_config_or_implicit_enable() {
    let good = br#"{"kind":"source","candidateBranch":"main","productionBranch":"production"}"#;
    let change = read_change(&good[..]).unwrap();
    let q = query(ID, ID, ID).unwrap();
    let request = framed(p::RequestBody::ConfigurationPrepare(c::Prepare {
        origin: q,
        original: original(ID, ID, ID).unwrap(),
        change,
    }))
    .unwrap();
    let encoded = p::encode_request(&request).unwrap();
    assert!(encoded.len() <= p::REQUEST_BYTES);
    assert!(p::decode_request(&encoded).is_ok());
    for bad in [
        br#"{"schemaVersion":1,"commands":{}}"#.as_slice(),
        br#"{"kind":"android","module":":app","variant":"release","enabled":true}"#.as_slice(),
    ] {
        assert!(read_change(bad).is_err());
    }
    assert!(read_change(vec![b' '; c::CHANGE_BYTES + 1].as_slice()).is_err());
    assert!(parse(&words(&["configuration-read", ID, "01"])).is_err());
}
#[test]
fn actual_capability_output_keeps_limit_scope_and_all_compiled_repository_actions() {
    let bytes = super::super::capabilities(true).unwrap();
    assert!(bytes.len() <= crate::installed_cli::CAPABILITIES_BYTES);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let config = &value["configuration"];
    assert_eq!(config["readAuthorizesPrepareOnly"], true);
    assert_eq!(config["applyRequiresDesktopPreview"], true);
    assert_eq!(config["nativeAvailabilityChecked"], false);
    assert_eq!(config["commands"].as_array().unwrap().len(), 5);
    assert_eq!(value["operationsRequire"]["runningDesktop"], true);
    assert!(value["gitRepository"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a == "set-upstream"));
    assert_eq!(value["gitRepository"]["nativeAvailabilityChecked"], false);
    let help = String::from_utf8(super::super::capabilities(false).unwrap()).unwrap();
    assert!(help.contains("configuration-apply") && help.contains("Desktop"));
}
