use super::*;
fn id(n: u8) -> Id {
    Id::parse(&format!("{n:032x}")).unwrap()
}
fn words(v: &str) -> Vec<OsString> {
    v.split_whitespace().map(OsString::from).collect()
}
fn review() -> store::Review {
    store::Review {
        kind: store::Kind::AccessCheck,
        platform: store::Platform::Android,
        operation_id: id(10),
        owner_generation: id(11),
        status_revision: 3,
        saved_config: store::Content {
            bytes: 100,
            sha256: "a".repeat(64),
        },
        saved_version: store::Version {
            bytes: 40,
            sha256: "b".repeat(64),
            name: "1.2.3".into(),
            build: 42,
        },
        candidate: None,
        release: None,
    }
}
#[test]
fn store_cli_requires_fixed_id_only_consent_and_closed_commands() {
    let text = format!(
        "store-submit {} {} {} {} --reviewed",
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
fn store_cli_output_correlates_actual_response_and_pending_is_not_completion() {
    let q = store::Query {
        project_id: id(1),
        service_instance: id(2),
        request_id: id(5),
    };
    let status = store::Status {
        origin: q.clone(),
        grant_id: id(3),
        review_id: id(4),
        revision: 1,
        review: review(),
        state: store::State::Queued,
        settlement: p::Settlement::Pending,
        reason: store::Reason::None,
        operation: None,
        outcome: None,
        result: None,
    };
    let mut response = p::Response {
        version: 1,
        request_id: id(6),
        service_instance: id(2),
        client_id: id(7),
        session_id: id(8),
        response: p::ResponseBody::StoreRequest(status),
    };
    let (code, bytes) = output(&response, &q, Some((&id(3), &id(4))), true).unwrap();
    assert_eq!(code, 0);
    assert!(bytes.len() < store::STATUS_LIMIT);
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(String::from_utf8(serde_json::to_vec(&v).unwrap())
        .unwrap()
        .contains("pending"));
    assert!(output(&response, &q, Some((&id(9), &id(4))), true).is_err());
    response.service_instance = id(9);
    assert!(output(&response, &q, None, true).is_err());
}
#[test]
fn store_cli_lost_ack_has_only_original_status_cancel_and_no_replay() {
    let q = store::Query {
        project_id: id(1),
        service_instance: id(2),
        request_id: id(5),
    };
    let v: serde_json::Value =
        serde_json::from_slice(&unconfirmed(&q, Error::StateUnknown, true)).unwrap();
    assert_eq!(v["request"]["requestId"], id(5).as_str());
    assert_eq!(v["doNotReplay"], true);
    assert!(!receipt(&q).contains("store-submit"));
    let catalogue: serde_json::Value =
        serde_json::from_slice(&capabilities(true).unwrap()).unwrap();
    let c = &catalogue["store"];
    assert_eq!(c["commands"].as_array().unwrap().len(), 3);
    for key in [
        "defaultEnabled",
        "queryVariants",
        "nativeAvailabilityChecked",
    ] {
        assert_eq!(c[key], false);
    }
    assert_eq!(c["readGrantAuthorizesExecution"], false);
    for key in ["execute", "reconcile", "upload", "promotion", "requiresSeparateExactModeConsent"] { assert_eq!(c[key], true); }
    for key in ["oldAccessPrepareGrantsAuthorizeRelease", "automaticRetry", "publicRelease"] { assert_eq!(c[key], false); }
}

#[path = "installed_cli_store_release_tests.rs"]
mod release_tests;
