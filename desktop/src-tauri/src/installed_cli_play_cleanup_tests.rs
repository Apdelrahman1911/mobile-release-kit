use super::*;
fn id(c: &str) -> Id {
    Id::parse(&c.repeat(32)).unwrap()
}
fn args(command: &str) -> Vec<OsString> {
    command.split_whitespace().map(OsString::from).collect()
}
#[test]
fn original_argument_collector_accepts_exact_reviewed_submit_and_rejects_extras() {
    let text = format!(
        "play-cleanup-submit {} {} {} --reviewed --json",
        id("a").as_str(),
        id("b").as_str(),
        id("c").as_str()
    );
    let words = super::super::collect_arguments(args(&text).into_iter());
    assert!(recognizes(&words));
    assert!(matches!(
        parse(&words).unwrap().command,
        Command::Submit { .. }
    ));
    assert!(parse(&args(&text.replace(" --reviewed", ""))).is_err());
    assert!(parse(&args(&(text.clone() + " extra"))).is_err());
    for cmd in ["play-cleanup-status", "play-cleanup-cancel"] {
        let text = format!(
            "{cmd} {} {} {} --json",
            id("a").as_str(),
            id("b").as_str(),
            id("c").as_str()
        );
        assert!(parse(&args(&text)).is_ok());
    }
}
#[test]
fn lost_reply_preserves_original_ids_and_ack_is_not_cleanup_in_human_or_json() {
    let q = cleanup::Query {
        project_id: id("a"),
        service_instance: id("b"),
        request_id: id("c"),
    };
    let uncertain = unconfirmed(&q, Error::StateUnknown, true);
    let v: serde_json::Value = serde_json::from_slice(&uncertain).unwrap();
    assert_eq!(v["request"], serde_json::to_value(&q).unwrap());
    assert_eq!(v["doNotReplay"], true);
    let status = cleanup::Status {
        origin: q.clone(),
        consent_id: id("d"),
        revision: 3,
        state: cleanup::State::Settled,
        settlement: p::Settlement::Settled,
        operation_id: Some("github-play-cleanup-1".into()),
        reason: None,
        effect: cleanup::Effect::AcknowledgedUnconfirmed,
        do_not_replay: true,
    };
    let mut r = p::Response {
        version: 1,
        request_id: id("e"),
        service_instance: q.service_instance.clone(),
        client_id: id("f"),
        session_id: id("a"),
        response: p::ResponseBody::PlayCleanupRequest(status),
    };
    let (_, human) = output(&r, &q, Some(&id("d")), false).unwrap();
    let human = String::from_utf8(human).unwrap();
    assert!(human.contains("ACK is not cleanup confirmation"));
    assert!(human.contains(q.request_id.as_str()));
    assert!(output(&r, &q, Some(&id("f")), true).is_err());
    r.service_instance = id("f");
    assert!(output(&r, &q, None, true).is_err());
}
#[test]
fn actual_capability_catalogue_keeps_fixed_limit_and_separate_mutating_consent() {
    let bytes = super::super::capabilities(true).unwrap();
    assert!(bytes.len() <= 12 * 1024 + 1);
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let cleanup = &v["playCleanup"];
    assert_eq!(cleanup["oneUse"], true);
    assert_eq!(cleanup["readGrantAuthorizesDispatch"], false);
    assert_eq!(cleanup["dispatchAcknowledgementIsCleanup"], false);
    assert_eq!(cleanup["publishing"], false);
    assert_eq!(cleanup["mutating"], true);
    assert_eq!(cleanup["commands"], serde_json::json!(COMMANDS));
}
