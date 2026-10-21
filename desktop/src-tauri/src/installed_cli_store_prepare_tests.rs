//! The real installed CLI parser/codec only. No IPC/server/native call.
use super::*;
use crate::service_store_prepare_protocol as flow;
fn status() -> flow::Status {
    let r = review();
    flow::Status {
        schema_version: 1,
        origin: store::Query {
            project_id: id(1),
            service_instance: id(2),
            request_id: id(5),
        },
        prepare_grant_id: id(3),
        selection_id: id(4),
        revision: 1,
        selection: flow::Selection {
            kind: flow::Kind::AndroidAccess,
            saved_config: r.saved_config,
            saved_version: r.saved_version,
            candidate: None,
        },
        phase: flow::Phase::Queued,
        settlement: p::Settlement::Pending,
        reason: store::Reason::None,
        prepared: None,
        operation: None,
        start_grant_id: None,
        prepare_returned: false,
        start_submitted: false,
        outcome: None,
        result: None,
        do_not_replay: true,
    }
}
fn response(s: flow::Status) -> p::Response {
    p::Response {
        version: p::VERSION,
        request_id: id(6),
        service_instance: id(2),
        client_id: id(7),
        session_id: id(8),
        response: p::ResponseBody::StorePreparation(Box::new(s)),
    }
}
#[test]
fn store_prepare_cli_has_two_fixed_separately_reviewed_id_only_commands() {
    for name in ["store-prepare", "store-start"] {
        let args = format!(
            "{name} {} {} {} {}{} --reviewed",
            id(1).as_str(),
            id(2).as_str(),
            id(3).as_str(),
            id(4).as_str(),
            if name == "store-start" {
                format!(" {}", id(5).as_str())
            } else {
                String::new()
            }
        );
        for suffix in ["", " --json"] {
            let p = parse(&words(&(args.clone() + suffix))).unwrap();
            assert!(matches!(p.command, Command::Preparation(_)));
        }
        for suffix in [" --force", " --query", " --path=/tmp", " --reviewed"] {
            assert!(parse(&words(&(args.clone() + suffix))).is_err());
        }
        assert!(parse(&words(&args.replace(" --reviewed", ""))).is_err());
    }
    assert!(parse(&words(&format!(
        "store-start {} {} {} {} --reviewed",
        id(1).as_str(),
        id(2).as_str(),
        id(3).as_str(),
        id(4).as_str()
    )))
    .is_err());
    assert!(parse(&words(&format!(
        "store-prepare {} {} {} {} {} --reviewed",
        id(1).as_str(),
        id(2).as_str(),
        id(3).as_str(),
        id(4).as_str(),
        id(5).as_str()
    )))
    .is_err());
}
#[test]
fn store_prepare_cli_original_response_and_start_grants_cannot_cross_use() {
    let s = status();
    let q = s.origin.clone();
    let mut response = response(s);
    let (code, bytes) =
        preparation::output(&response, &q, Some((false, &id(3), &id(4))), true).unwrap();
    assert_eq!(code, 0);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(value.to_string().contains("doNotReplay"));
    assert!(preparation::output(&response, &q, Some((true, &id(3), &id(4))), true).is_err());
    // Existing status/cancel route accepts this exact new kind, old Submit does not.
    assert!(output(&response, &q, None, true).is_ok());
    assert!(output(&response, &q, Some((&id(3), &id(4))), true).is_err());
    let p::ResponseBody::StorePreparation(s) = &mut response.response else {
        unreachable!()
    };
    s.phase = flow::Phase::Starting;
    s.prepare_returned = true;
    s.start_submitted = true;
    s.start_grant_id = Some(id(9));
    s.prepared = Some(flow::Review {
        review_id: id(10),
        operation: store::Operation {
            operation_id: id(10),
            owner_generation: id(11),
            status_revision: 3,
        },
    });
    assert!(preparation::output(&response, &q, Some((true, &id(9), &id(10))), true).is_ok());
    assert!(preparation::output(&response, &q, Some((true, &id(3), &id(10))), true).is_err());
    response.service_instance = id(12);
    assert!(preparation::output(&response, &q, None, true).is_err());
}
#[test]
fn store_prepare_cli_unknown_keeps_ids_and_catalogue_discloses_query_effects() {
    let mut s = status();
    s.phase = flow::Phase::Unknown;
    s.settlement = p::Settlement::Unknown;
    s.reason = store::Reason::CleanupUnknown;
    s.outcome = Some(store::Outcome::Unknown);
    let q = s.origin.clone();
    let r = response(s);
    let (code, text) = preparation::output(&r, &q, None, false).unwrap();
    assert_eq!(code, 6);
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains(q.request_id.as_str()));
    assert!(text.contains("Prepare does not start"));
    let catalogue: serde_json::Value =
        serde_json::from_slice(&capabilities(true).unwrap()).unwrap();
    let c = &catalogue["store"];
    assert_eq!(c["commands"].as_array().unwrap().len(), 5);
    assert_eq!(c["oldSubmitQueryVariants"], false);
    assert_eq!(c["queryVariants"], true);
    assert_eq!(c["prepareAuthorizesStart"], false);
    assert_eq!(c["inventoryIsAllocationAuthority"], false);
    assert_eq!(c["nativeAvailabilityChecked"], false);
    assert_eq!(c["automaticRetry"], false);
    assert_eq!(c["oldAccessPrepareGrantsAuthorizeRelease"], false);
    let unknown: serde_json::Value =
        serde_json::from_slice(&unconfirmed(&q, Error::StateUnknown, true)).unwrap();
    assert_eq!(unknown["request"]["requestId"], q.request_id.as_str());
    assert_eq!(unknown["doNotReplay"], true);
}
