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
    let (code, bytes) = output(&response, &q, Some((&id(3), &id(10),false)), true).unwrap();
    assert_eq!(code, 0);
    assert!(bytes.len() < apple::STATUS_LIMIT);
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(String::from_utf8(serde_json::to_vec(&v).unwrap())
        .unwrap()
        .contains("pending"));
    assert!(output(&response, &q, Some((&id(9), &id(10),false)), true).is_err());
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
    assert_eq!(c["commands"].as_array().unwrap().len(), 4);
    assert_eq!(c["cliPrepare"],true);
    assert_eq!(c["prepareRequiresDesktopSelection"],true);
    assert_eq!(c["prepareIsStart"],false);
    assert_eq!(c["modeCount"], 16);
    assert_eq!(c["keyRecover"], true);
    assert_eq!(c["keyRecoverScope"], "known-durable-original-reference");
    for key in [
        "headless",
        "privateArguments",
        "savedIsAssigned",
        "statusGrantsNextStep",
        "p12Reconcile",
    ] {
        assert_eq!(c[key], false);
    }
    assert_eq!(c["requiresExactOneUseDesktopConsent"], true);
}

#[test]
fn apple_prepare_cli_only_addresses_and_separate_consent_no_context_or_material(){
    let text=format!("apple-provisioning-prepare {} {} {} {} --reviewed",id(1).as_str(),id(2).as_str(),id(3).as_str(),id(4).as_str());
    for suffix in [""," --json"]{
        let args=collect_arguments(words(&(text.clone()+suffix)));assert!(recognizes(&args));
        assert!(matches!(parse(&args).unwrap().command,Command::Prepare{..}));
    }
    assert!(parse(&words(&text.replace(" --reviewed",""))).is_err());
    for suffix in [" --mode key-prepare"," --path /tmp/key"," --password secret"," --reviewed"," --force"]{
        assert!(parse(&words(&(text.clone()+suffix))).is_err());
    }
    assert!(parse(&words(&text.replace(id(4).as_str(),"/not-an-address"))).is_err());
}

#[test]
fn apple_prepare_cli_reply_must_match_exact_kind_scope_and_original_query(){
    let q=apple::Query{project_id:id(1),service_instance:id(2),request_id:id(5)};
    let status=prepare::Status{origin:q.clone(),grant_id:id(3),scope_id:id(4),mode:apple::Mode::Review,revision:1,
        phase:prepare::Phase::Queued,settlement:p::Settlement::Pending,reason:apple::Reason::None,prepared:None,usable:false,handed_off:false};
    let mut response=p::Response{version:1,request_id:id(6),service_instance:id(2),client_id:id(7),session_id:id(8),response:p::ResponseBody::AppleProvisioningPreparation(status)};
    let (_,bytes)=output(&response,&q,Some((&id(3),&id(4),true)),true).unwrap();
    assert!(bytes.len()<apple::STATUS_LIMIT);assert!(output(&response,&q,Some((&id(3),&id(4),false)),true).is_err());
    assert!(output(&response,&q,Some((&id(3),&id(9),true)),true).is_err());
    assert!(output(&response,&q,None,true).is_ok()); // existing Status by exact old request
    response.service_instance=id(9);assert!(output(&response,&q,None,true).is_err());
    assert!(!receipt(&q).contains("apple-provisioning-prepare"));
}
