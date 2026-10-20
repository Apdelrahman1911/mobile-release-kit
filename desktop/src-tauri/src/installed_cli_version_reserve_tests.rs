use super::*;
fn id(n: u8) -> Id {
    Id::parse(&format!("{n:032x}")).unwrap()
}
fn words(command: &str) -> Vec<OsString> {
    command.split_whitespace().map(OsString::from).collect()
}
#[test]
fn actual_original_collector_preserves_fixed_submit_with_reviewed_and_json() {
    let text = format!(
        "version-reserve-submit {} {} {} {} --reviewed",
        id(1).as_str(),
        id(2).as_str(),
        id(3).as_str(),
        id(4).as_str()
    );
    for suffix in ["", " --json"] {
        let args = collect_arguments(words(&(text.clone() + suffix)));
        assert!(recognizes(&args));
        let parsed = parse(&args).unwrap();
        assert_eq!(parsed.json, !suffix.is_empty());
        assert!(matches!(parsed.command, Command::Submit { .. }));
    }
    for suffix in [" --force", " extra --json", " --reviewed"] {
        assert!(parse(&collect_arguments(words(&(text.clone() + suffix)))).is_err());
    }
    assert!(parse(&words(&text.replace(" --reviewed", ""))).is_err());
    let many = collect_arguments(words(&(text + &" extra".repeat(30))));
    assert_eq!(many.len(), 11);
    assert!(parse(&many).is_err());
}
#[test]
fn status_cancel_and_bound_response_cannot_alias_a_different_original() {
    let query = reserve::Query {
        project_id: id(1),
        service_instance: id(2),
        request_id: id(3),
    };
    for name in [COMMANDS[1], COMMANDS[2]] {
        let parsed = parse(&words(&format!(
            "{} {} {} {} --json",
            name,
            id(1).as_str(),
            id(2).as_str(),
            id(3).as_str()
        )))
        .unwrap();
        assert!(parsed.json);
    }
    let status = reserve::Status {
        origin: query.clone(),
        grant_id: id(4),
        review_id: id(5),
        revision: 1,
        state: reserve::State::Queued,
        operation_id: None,
        settlement: p::Settlement::Pending,
        reason: None,
        reservation: None,
        do_not_replay: true,
    };
    let mut response = p::Response {
        version: 1,
        request_id: id(6),
        service_instance: id(2),
        client_id: id(10),
        session_id: id(11),
        response: p::ResponseBody::VersionReserveRequest(status.clone()),
    };
    let (code, bytes) = output(&response, &query, Some((&id(4), &id(5))), true).unwrap();
    assert_eq!(code, 0);
    assert_eq!(bytes.iter().filter(|b| **b == b'\n').count(), 1);
    assert!(bytes.len() < reserve::STATUS_LIMIT);
    assert!(output(&response, &query, Some((&id(7), &id(5))), true).is_err());
    response.service_instance = id(8);
    assert!(output(&response, &query, None, true).is_err());
}
#[test]
fn lost_ack_keeps_exact_public_request_and_catalogue_stays_bounded_without_readiness() {
    let q = reserve::Query {
        project_id: id(1),
        service_instance: id(2),
        request_id: id(3),
    };
    let value: serde_json::Value =
        serde_json::from_slice(&unconfirmed(&q, Error::Unavailable, true)).unwrap();
    assert_eq!(value["request"]["requestId"], q.request_id.as_str());
    assert_eq!(value["doNotReplay"], true);
    assert!(receipt(&q).contains("version-reserve-status"));
    assert!(!receipt(&q).contains("version-reserve-submit"));
    let bytes = capabilities(true).unwrap();
    assert!(bytes.len() <= 12 * 1024);
    let catalog: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let cap = &catalog["versionReservation"];
    assert_eq!(cap["commands"].as_array().unwrap().len(), 3);
    for field in [
        "defaultEnabled",
        "readGrantAuthorizesReserve",
        "appliesSourceEdits",
        "nativeAvailabilityChecked",
    ] {
        assert_eq!(cap[field], false);
    }
    assert_eq!(cap["maxReviewMs"], 120000);
    assert_eq!(cap["maxRetainedRequests"], 32);
}
