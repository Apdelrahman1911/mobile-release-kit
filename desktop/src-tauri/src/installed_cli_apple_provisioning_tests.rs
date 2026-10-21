use super::*;
fn id(n: u8) -> Id {
    Id::parse(&format!("{n:032x}")).unwrap()
}
fn words(v: &str) -> Vec<OsString> {
    v.split_whitespace().map(OsString::from).collect()
}
fn review() -> apple::Review {
    apple::Review {
        mode: apple::Mode::Review,
        operation_id: id(10),
        owner_generation: id(11),
        status_revision: 3,
        saved_config: apple::Content {
            bytes: 100,
            sha256: "a".repeat(64),
        },
        saved_version: apple::Version {
            bytes: 40,
            sha256: "b".repeat(64),
            name: "1.2.3".into(),
            build: 42,
        },
    }
}
#[test]
fn apple_cli_cli_requires_fixed_id_only_consent_and_closed_commands() {
    let text = format!(
        "apple-provisioning-submit {} {} {} {} --reviewed",
        id(1).as_str(),
        id(2).as_str(),
        id(3).as_str(),
        id(4).as_str()
    );
    for suffix in ["", " --json"] {
        let args = collect_arguments(words(&(text.clone() + suffix)));
        assert!(recognizes(&args));
        assert!(matches!(
            parse(&args).unwrap().command,
            Command::Submit { .. }
        ));
    }
    for suffix in [" --force", " --upload", " --reviewed"] {
        assert!(parse(&words(&(text.clone() + suffix))).is_err());
    }
    assert!(parse(&words(&text.replace(" --reviewed", ""))).is_err());
    for name in [COMMANDS[1], COMMANDS[2]] {
        assert!(parse(&words(&format!(
            "{name} {} {} {} --json",
            id(1).as_str(),
            id(2).as_str(),
            id(5).as_str()
        )))
        .is_ok());
    }
}
#[test]
fn apple_cli_cli_output_correlates_actual_response_and_pending_is_not_completion() {
    let q = apple::Query {
        project_id: id(1),
        service_instance: id(2),
        request_id: id(5),
    };
    let status = apple::Status {
        origin: q.clone(),
        grant_id: id(3),
        review_id: id(10),
        revision: 1,
        review: review(),
        state: apple::State::Queued,
        settlement: p::Settlement::Pending,
        reason: apple::Reason::None,
        operation: None,
        outcome: None,
        result: None,
        record_at_completion: None,
    };
    let mut response = p::Response {
        version: 1,
        request_id: id(6),
        service_instance: id(2),
        client_id: id(7),
        session_id: id(8),
        response: p::ResponseBody::AppleProvisioningRequest(status),
    };
    let (code, bytes) = output(&response, &q, Some((&id(3), &id(10))), true).unwrap();
    assert_eq!(code, 0);
    assert!(bytes.len() < apple::STATUS_LIMIT);
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(String::from_utf8(serde_json::to_vec(&v).unwrap())
        .unwrap()
        .contains("pending"));
    assert!(output(&response, &q, Some((&id(9), &id(10))), true).is_err());
    response.service_instance = id(9);
    assert!(output(&response, &q, None, true).is_err());
}
#[test]
fn apple_cli_cli_lost_ack_has_only_original_status_cancel_and_no_replay() {
    let q = apple::Query {
        project_id: id(1),
        service_instance: id(2),
        request_id: id(5),
    };
    let v: serde_json::Value =
        serde_json::from_slice(&unconfirmed(&q, Error::StateUnknown, true)).unwrap();
    assert_eq!(v["request"]["requestId"], id(5).as_str());
    assert_eq!(v["doNotReplay"], true);
    assert!(!receipt(&q).contains("apple-provisioning-submit"));
    let catalogue: serde_json::Value =
        serde_json::from_slice(&capabilities(true).unwrap()).unwrap();
    let c = &catalogue["appleProvisioning"];
    assert_eq!(c["commands"].as_array().unwrap().len(), 3);
    assert_eq!(c["modeCount"], 15);
    for key in [
        "cliPrepare",
        "headless",
        "privateArguments",
        "savedIsAssigned",
        "statusGrantsNextStep",
        "keyRecover",
        "p12Reconcile",
    ] {
        assert_eq!(c[key], false);
    }
    assert_eq!(c["requiresExactOneUseDesktopConsent"], true);
}
