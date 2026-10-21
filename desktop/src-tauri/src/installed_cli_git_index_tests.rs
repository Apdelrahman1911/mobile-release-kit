use super::*;
fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn q() -> git::Query {
    git::Query {
        project_id: id('a'),
        service_instance: id('b'),
        request_id: id('c'),
    }
}
#[test]
fn actual_outer_collector_preserves_complete_start_and_rejects_extra_arguments() {
    let q = q();
    let words = [
        "git-index-start",
        q.project_id.as_str(),
        q.service_instance.as_str(),
        q.request_id.as_str(),
        "git-local-1",
        "git-local-1-review",
        "--json",
    ];
    let args = super::super::collect_arguments(words.into_iter().map(OsString::from));
    assert!(recognizes(&args));
    assert!(parse(&args).is_ok());
    let extra = super::super::collect_arguments(
        args.into_iter()
            .chain(std::iter::repeat(OsString::from("extra"))),
    );
    assert_eq!(extra.len(), 11);
    assert!(parse(&extra).is_err());
}
#[test]
fn uncertain_send_exposes_same_client_request_ids_and_never_a_replacement_action() {
    let q = q();
    let bytes = unconfirmed(&q, Error::Unavailable, true);
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["request"]["requestId"], q.request_id.as_str());
    assert_eq!(v["doNotReplay"], true);
    let human = String::from_utf8(unconfirmed(&q, Error::StateUnknown, false)).unwrap();
    assert!(human.contains("git-index-status"));
    assert!(human.contains("git-index-cancel"));
    assert!(!human.contains("git-index-prepare"));
}
#[test]
fn reply_must_bind_same_instance_request_project_and_fixed_framing() {
    let q = q();
    let request = framed(p::RequestBody::GitIndexStart(git::Start {
        origin: q.clone(),
        prepare_operation_id: "git-local-1".into(),
        review_id: "git-local-1-review".into(),
    }))
    .unwrap();
    assert!(p::encode_request(&request).unwrap().len() <= 4096);
    let response = p::Response {
        version: 1,
        request_id: id('e'),
        service_instance: id('f'),
        client_id: id('1'),
        session_id: id('2'),
        response: p::ResponseBody::GitIndexScope(git::Scope {
            service_instance: id('f'),
            project_id: q.project_id.clone(),
            access: git::Access::empty(),
        }),
    };
    assert!(output(&response, &q.project_id, Some(&q), true).is_err());
    assert!(output(&response, &id('d'), None, true).is_err());
}

#[test]
fn compiled_catalogue_names_only_separately_allowed_index_changes_and_stays_bounded() {
    let bytes = super::super::capabilities(true).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(bytes.len() <= crate::installed_cli::CAPABILITIES_BYTES);
    let git = &value["gitIndex"];
    assert_eq!(git["scope"], "desktop-selected-stage-or-unstage");
    assert_eq!(git["readGrantAuthorizesWrites"], false);
    assert_eq!(git["nativeAvailabilityChecked"], false);
    assert_eq!(git["commands"].as_array().unwrap().len(), 5);
    for flag in ["commit", "branchChanges", "push", "credentials"] {
        assert_eq!(git[flag], false);
    }
    assert!(!super::super::capabilities(false).unwrap().is_empty());
}
