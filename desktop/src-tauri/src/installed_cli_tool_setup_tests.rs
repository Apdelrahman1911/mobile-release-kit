//! Parsing and public correlation only; no socket, process or native calls.
use super::*;
fn args(v: &[&str]) -> Vec<OsString> {
    v.iter().map(OsString::from).collect()
}
#[test]
fn three_tools_cli_verbs_admit_only_reviewed_ids() {
    let a = "a".repeat(32);
    let b = "b".repeat(32);
    let c = "c".repeat(32);
    let d = "d".repeat(32);
    assert!(parse(&args(&[
        COMMANDS[0],
        &a,
        &b,
        &c,
        &d,
        "--reviewed",
        "--json"
    ]))
    .is_ok());
    for v in [
        vec![COMMANDS[0], &a, &b, &c, &d],
        vec![COMMANDS[0], &a, &b, &c, &d, "--reviewed", "--reviewed"],
        vec![COMMANDS[1], &a, &b, "/tmp/source"],
        vec!["tool-setup-prepare", &a, &b, &c],
        vec![COMMANDS[2], &a, &b, &c, "--url", "https://example.invalid"],
    ] {
        assert!(parse(&args(&v)).is_err());
    }
    for kind in &COMMANDS[1..] {
        assert!(parse(&args(&[kind, &a, &b, &c])).is_ok());
    }
}
#[test]
fn lost_tools_request_receipt_is_id_only_no_replay() {
    let q = tools::Query {
        project_id: Id::parse(&"1".repeat(32)).unwrap(),
        service_instance: Id::parse(&"2".repeat(32)).unwrap(),
        request_id: Id::parse(&"3".repeat(32)).unwrap(),
    };
    let text = receipt(&q);
    assert!(text.contains("tool-setup-status"));
    assert!(text.contains("tool-setup-cancel"));
    assert!(!text.contains("tool-setup-submit"));
    let v: serde_json::Value =
        serde_json::from_slice(&unconfirmed(&q, Error::Unavailable, true)).unwrap();
    assert_eq!(v["doNotReplay"], true);
    assert_eq!(v["request"]["requestId"], q.request_id.as_str());
}
