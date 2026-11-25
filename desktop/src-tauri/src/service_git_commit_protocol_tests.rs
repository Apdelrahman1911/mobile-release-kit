use super::*;
use crate::service_protocol::{self as service, Id, Settlement};
fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn selection() -> p::Selection {
    p::Selection::new_shared(
        p::Action::Commit,
        "a".repeat(64),
        vec!["app/a".into(), "other/b".into()],
    )
    .unwrap()
}
fn access() -> p::Access {
    p::Access {
        enabled: true,
        remaining_ms: 60000,
        consumed: false,
        project_id: Some(id('b')),
        grant_id: Some(id('c')),
        selection: Some(selection()),
    }
}

#[test]
fn draft_bounds_match_native_utf8_and_never_admit_header_or_control_injection() {
    assert!(Draft::new(
        "line\n\tcontinued".into(),
        "Author".into(),
        "a@example.invalid".into()
    )
    .is_ok());
    for (message, name, email) in [
        (" ".into(), "A".into(), "a@b".into()),
        ("a\rb".into(), "A".into(), "a@b".into()),
        ("é".repeat(2049), "A".into(), "a@b".into()),
        ("valid".into(), "é".repeat(65), "a@b".into()),
        ("valid".into(), "A <B>".into(), "a@b".into()),
        ("valid".into(), "A".into(), "a@b@c".into()),
        ("valid".into(), "A".into(), "a\nb@c".into()),
    ] {
        assert!(Draft::new(message, name, email).is_err());
    }
}
#[test]
fn commit_selection_has_distinct_digest_and_index_public_validators_refuse_it() {
    let value = selection();
    assert!(value.validate().is_err());
    assert!(p::Selection::new(p::Action::Commit, "a".repeat(64), value.paths.clone()).is_err());
    let index = p::Selection::new(p::Action::Stage, "a".repeat(64), value.paths.clone()).unwrap();
    assert_ne!(
        index.summary.selection_sha256,
        value.summary.selection_sha256
    );
    assert!(Access(access()).validate().is_ok());
    assert!(access().validate().is_err());
    let mut wrong = access();
    wrong.selection = Some(index);
    assert!(Access(wrong).validate().is_err());
    assert!(Access::empty().validate().is_ok());
}
#[test]
fn commit_scope_is_bounded_redacted_and_matches_real_envelope_instance() {
    let scope = Scope(p::Scope {
        service_instance: id('d'),
        project_id: id('b'),
        access: access(),
    });
    let mut response = service::Response {
        version: service::VERSION,
        request_id: id('e'),
        service_instance: id('d'),
        client_id: id('f'),
        session_id: id('1'),
        response: service::ResponseBody::GitCommitScope(scope),
    };
    let bytes = service::encode_response(&response).unwrap();
    assert!(bytes.len() <= p::SCOPE_BYTES);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["response"]["kind"], "git-commit-scope");
    let text = std::str::from_utf8(&bytes).unwrap();
    for forbidden in [
        "message",
        "authorName",
        "authorEmail",
        "identity",
        "command",
        "privateDraft",
    ] {
        assert!(!text.contains(forbidden));
    }
    response.service_instance = id('2');
    assert!(service::encode_response(&response).is_err());
}
#[test]
fn commit_status_cannot_be_cast_to_index_or_gain_private_fields() {
    let row = p::Status {
        origin: p::Query {
            project_id: id('b'),
            service_instance: id('d'),
            request_id: id('e'),
        },
        grant_id: id('c'),
        selection: selection().summary,
        revision: 1,
        state: p::State::Queued,
        prepare_operation_id: None,
        apply_operation_id: None,
        review: None,
        outcome: None,
        settlement: Settlement::Pending,
        reason: None,
        history_available: false,
        do_not_replay: true,
    };
    assert!(row.validate().is_err());
    assert!(Status(row.clone()).validate().is_ok());
    let mut value = serde_json::to_value(&Status(row)).unwrap();
    value["message"] = serde_json::json!("not public");
    assert!(serde_json::from_value::<Status>(value).is_err());
}
