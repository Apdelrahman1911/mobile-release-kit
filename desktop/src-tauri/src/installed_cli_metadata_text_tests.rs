use super::*;
fn words(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}
const ID: &str = "11111111111111111111111111111111";
#[test]
fn actual_collector_keeps_five_fixed_verbs_and_explicit_apply_review() {
    let args = super::super::collect_arguments(words(&[
        "metadata-text-apply",
        ID,
        ID,
        ID,
        ID,
        ID,
        ID,
        ID,
        "--reviewed",
        "--json",
    ]));
    let v = parse(&args).unwrap();
    assert!(v.json && matches!(v.command, Command::Apply(_)));
    assert!(parse(&words(&["metadata-text-apply", ID, ID, ID, ID, ID, ID, ID])).is_err());
    assert!(parse(&words(&["metadata-text-read", ID, "01", "ios", "en-US"])).is_err());
    assert!(parse(&words(&["metadata-text-read", ID, "1", "both", "en-US"])).is_err());
    assert!(parse(&words(&["metadata-text-read", ID, "1", "ios", "../en-US"])).is_err());
    assert!(parse(&words(&[
        "metadata-text-prepare",
        ID,
        ID,
        ID,
        "/caller/path"
    ]))
    .is_err());
}
#[test]
fn stdin_accepts_complete_long_public_fields_but_not_sparse_or_oversize_inputs() {
    let fields = c::Fields {
        platform: c::Platform::Ios,
        fields: c::Platform::Ios
            .ids()
            .iter()
            .map(|id| c::Field {
                id: (*id).into(),
                text: "Public ".repeat(570),
            })
            .collect(),
    };
    let bytes = c::encoded(&fields, c::STDIN_BYTES).unwrap();
    assert!(bytes.len() > 4096);
    assert_eq!(read_fields(bytes.as_slice()).unwrap(), fields);
    assert!(
        read_fields(br#"{"platform":"android","fields":[],"root":"/other"}"#.as_slice()).is_err()
    );
    assert!(read_fields(vec![b' '; c::STDIN_BYTES + 1].as_slice()).is_err());
}
#[test]
fn capability_output_preserves_old_request_bound_and_names_new_only_limits() {
    let value: serde_json::Value =
        serde_json::from_slice(&super::super::capabilities(true).unwrap()).unwrap();
    assert_eq!(
        value["metadataText"]["commands"].as_array().unwrap().len(),
        5
    );
    assert_eq!(
        value["metadataText"]["prepareRequestBytes"],
        c::REQUEST_BYTES
    );
    assert_eq!(value["metadataText"]["nativeAvailabilityChecked"], false);
    assert_eq!(value["operationsRequire"]["runningDesktop"], true);
    assert!(
        String::from_utf8(super::super::capabilities(false).unwrap())
            .unwrap()
            .contains("metadata-text-prepare")
    );
    assert_eq!(p::REQUEST_BYTES, 4096);
}
#[test]
fn missing_ack_output_retains_only_original_ids_and_never_invites_replay() {
    let q = query(ID, ID, ID).unwrap();
    let (code, bytes) = unconfirmed(&q, true);
    assert_eq!(code, 6);
    let data: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(data["admission"], "unconfirmed");
    assert_eq!(data["doNotReplay"], true);
    let text = String::from_utf8(receipt(&q).into_bytes()).unwrap();
    assert!(text.contains("metadata-text-status") && text.contains("metadata-text-cancel"));
    assert!(!text.contains("metadata-text-apply") && !text.contains("metadata-text-read"));
}
