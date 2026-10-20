use super::*;
fn id(v: char) -> Id {
    Id::parse(&v.to_string().repeat(32)).unwrap()
}
fn status() -> Status {
    Status {
        origin: Query {
            project_id: id('a'),
            service_instance: id('b'),
            request_id: id('c'),
        },
        grant_id: id('d'),
        selection: Selection::new(Action::Stage, "e".repeat(64), vec!["app/a.txt".into()])
            .unwrap()
            .summary,
        revision: 1,
        state: State::Queued,
        prepare_operation_id: None,
        apply_operation_id: None,
        review: None,
        outcome: None,
        settlement: Settlement::Pending,
        reason: None,
        history_available: false,
        do_not_replay: true,
    }
}
#[test]
fn selection_hash_binds_exact_action_revision_and_sorted_safe_paths() {
    let a = Selection::new(
        Action::Stage,
        "a".repeat(64),
        vec!["app/a.txt".into(), "app/b.txt".into()],
    )
    .unwrap();
    let b = Selection::new(Action::Unstage, "a".repeat(64), a.paths.clone()).unwrap();
    assert_ne!(a.summary.selection_sha256, b.summary.selection_sha256);
    let mut changed = a.clone();
    changed.paths[0] = "app/c.txt".into();
    assert!(changed.validate().is_err());
    for paths in [
        vec!["b".into(), "a".into()],
        vec!["a".into(), "a".into()],
        vec!["../x".into()],
        vec!["a/.git/index".into()],
        vec!["a\\b".into()],
        vec!["a\nb".into()],
        vec![],
    ] {
        assert!(Selection::new(Action::Stage, "a".repeat(64), paths).is_err());
    }
}
#[test]
fn capacity_and_escaped_reply_bounds_apply_before_output_allocation() {
    let mut path = String::with_capacity(1024 * 1024);
    path.push_str("a");
    let mut paths = Vec::with_capacity(8192);
    paths.push(path);
    let value = Selection::new(Action::Stage, "a".repeat(64), paths).unwrap();
    assert_eq!(value.paths.capacity(), 1);
    assert_eq!(value.paths[0].capacity(), 1);
    let heavy = (0..PATH_LIMIT)
        .map(|i| format!("p{i:02}/{0}/{0}/{0}/{0}", "\"".repeat(250)))
        .collect();
    assert!(Selection::new(Action::Stage, "a".repeat(64), heavy).is_err());
    let scope = Scope {
        service_instance: id('b'),
        project_id: id('a'),
        access: Access {
            enabled: true,
            remaining_ms: 1,
            consumed: false,
            project_id: Some(id('a')),
            grant_id: Some(id('d')),
            selection: Some(value),
        },
    };
    let response = crate::service_protocol::Response {
        version: 1,
        request_id: id('f'),
        service_instance: id('b'),
        client_id: id('1'),
        session_id: id('2'),
        response: crate::service_protocol::ResponseBody::GitIndexScope(scope),
    };
    response_bound(&response, true).unwrap();
    assert!(encoded_bound(&response, 8).is_err());
}
#[test]
fn status_refuses_forged_phase_pair_and_ready_or_unknown_shortcuts() {
    let mut s = status();
    s.validate().unwrap();
    s.state = State::Prepared;
    assert!(s.validate().is_err());
    s.state = State::Applying;
    assert!(s.validate().is_err());
    s.state = State::Queued;
    s.prepare_operation_id = Some("git-local-1".into());
    assert!(s.validate().is_err());
    s.state = State::Unknown;
    s.settlement = Settlement::Unknown;
    s.outcome = Some(OperationState::Unknown);
    s.validate().unwrap();
    s.history_available = true;
    s.validate().unwrap();
    s.settlement = Settlement::Settled;
    assert!(s.validate().is_err());
    s = status();
    let mut v = serde_json::to_value(s).unwrap();
    v["executable"] = serde_json::json!("ignored?");
    assert!(serde_json::from_value::<Status>(v).is_err());
}
#[test]
fn service_frame_correlation_and_fixed_scope_do_not_accept_raw_git_actions() {
    let q = Query {
        project_id: id('a'),
        service_instance: id('b'),
        request_id: id('c'),
    };
    let r = crate::service_protocol::Request {
        version: 1,
        request_id: id('f'),
        request: crate::service_protocol::RequestBody::GitIndexPrepare(Prepare {
            origin: q,
            grant_id: id('d'),
        }),
    };
    let bytes = crate::service_protocol::encode_request(&r).unwrap();
    assert!(bytes.len() < 4096);
    let mut v = serde_json::to_value(r).unwrap();
    v["request"]["params"]["paths"] = serde_json::json!(["arbitrary"]);
    assert!(crate::service_protocol::decode_request(&serde_json::to_vec(&v).unwrap()).is_err());
    let mut access = Access::empty();
    access.enabled = true;
    assert!(access.validate().is_err());
}
