//! Portable comparison DATA only. No test constructs a native Gate, receipt,
//! source reader, Git process, or Desktop permission from decoded data.
use super::*;
use crate::service_protocol::{self as service, Id, OperationState, Settlement};
use serde_json::{json, Value};

fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn actions() -> Vec<Action> {
    vec![
        Action::Initialize {},
        Action::BranchCreate {
            expected_revision: "a".repeat(64),
            expected_reference_revision: "b".repeat(64),
            name: "next".into(),
        },
        Action::BranchSwitch {
            expected_revision: "a".repeat(64),
            expected_reference_revision: "b".repeat(64),
            name: "next".into(),
        },
        Action::BranchRename {
            expected_revision: "a".repeat(64),
            expected_reference_revision: "b".repeat(64),
            name: "next".into(),
        },
        Action::FastForward {
            expected_revision: "a".repeat(64),
            expected_reference_revision: "b".repeat(64),
            target_ref: "refs/remotes/origin/main".into(),
            target_oid: "d".repeat(40),
        },
    ]
}
fn review(action: &Action) -> Review {
    let head = "c".repeat(40);
    let branch = "refs/heads/main".to_owned();
    Review {
        review_id: "git-local-1-review".into(),
        source_revision: "a".repeat(64),
        reference_revision: action.revisions().map(|_| "b".repeat(64)),
        expected_index: action.revisions().map(|_| "e".repeat(64)),
        review_digest: "f".repeat(64),
        document_revision: 1,
        registration_generation: 1,
        preview: match action {
            Action::SetUpstream { head, branch, remote, repository, .. } => Preview::SetUpstream {
                head: head.clone(), branch: branch.clone(), remote: remote.clone(), repository: repository.clone(),
                config_changed: true, missing_directory_count: 2, unchanged: false,
            },
            Action::Initialize {} => Preview::Initialize {
                initial_branch: "main".into(),
                object_format: "sha1".into(),
            },
            Action::BranchCreate { name, .. } => Preview::BranchCreate {
                head,
                branch: Some(branch),
                target_ref: format!("refs/heads/{name}"),
            },
            Action::BranchSwitch { name, .. } => Preview::BranchSwitch {
                head,
                branch,
                target_ref: format!("refs/heads/{name}"),
                target_oid: "d".repeat(40),
                changed_path_count: 2,
            },
            Action::BranchRename { name, .. } => Preview::BranchRename {
                head,
                branch,
                target_ref: format!("refs/heads/{name}"),
                config_moved: true,
                logging: true,
            },
            Action::FastForward {
                target_ref,
                target_oid,
                ..
            } => Preview::FastForward {
                head,
                branch,
                target_ref: target_ref.clone(),
                target_oid: target_oid.clone(),
                changed_path_count: 2,
            },
        },
    }
}
fn prepared(action: Action) -> Status {
    let review = review(&action);
    Status {
        origin: Query {
            project_id: id('a'),
            service_instance: id('b'),
            request_id: id('c'),
        },
        grant_id: id('d'),
        selection: Selection::new(action).unwrap(),
        revision: 4,
        state: p::State::Prepared,
        prepare_operation_id: Some("git-local-1".into()),
        apply_operation_id: None,
        review: Some(review),
        outcome: None,
        settlement: Settlement::Pending,
        reason: None,
        history_available: false,
        do_not_replay: true,
    }
}

#[test]
fn closed_five_actions_bind_digest_and_reject_commands_network_and_extra_authority() {
    // Keep the old wire bytes (and therefore the selection digest), while
    // refusing unknown fields even for the otherwise empty Initialize action.
    assert_eq!(serde_json::to_vec(&Action::Initialize {}).unwrap(), br#"{"kind":"initialize"}"#);
    assert!(serde_json::from_value::<Action>(json!({})).is_err());
    for action in actions() {
        let selected = Selection::new(action.clone()).unwrap();
        assert_eq!(
            serde_json::from_value::<Selection>(serde_json::to_value(&selected).unwrap()).unwrap(),
            selected
        );
        selected.validate().unwrap();
        let mut changed = selected.clone();
        changed.selection_sha256 = "0".repeat(64);
        assert!(changed.validate().is_err());
        for key in [
            "command",
            "path",
            "url",
            "token",
            "nativeReceipt",
            "expectedIndex",
        ] {
            let mut value = serde_json::to_value(&action).unwrap();
            value[key] = json!("forged");
            assert!(serde_json::from_value::<Action>(value).is_err(),
                "{} accepted unexpected field {key}", action.label());
        }
    }
    for kind in ["fetch", "push", "stage", "commit", "reset", "clean"] {
        assert!(serde_json::from_value::<Action>(json!({"kind":kind})).is_err());
    }
    for bad in [
        "../outside",
        "-m",
        "next.lock",
        "a//b",
        "a\n",
        "a@{b",
        "a\\b",
    ] {
        let value = Action::BranchCreate {
            expected_revision: "a".repeat(64),
            expected_reference_revision: "b".repeat(64),
            name: bad.into(),
        };
        assert!(Selection::new(value).is_err());
    }
    let mut bad = actions().pop().unwrap();
    if let Action::FastForward { target_ref, .. } = &mut bad {
        *target_ref = "refs/heads/main".into();
    }
    assert!(bad.validate().is_err());
}

#[test]
fn new_access_requires_all_nulls_and_does_not_change_old_family_wire_shape() {
    let empty = serde_json::to_value(Access::empty()).unwrap();
    assert_eq!(empty.as_object().unwrap().len(), 6);
    assert!(serde_json::from_value::<Access>(empty.clone())
        .unwrap()
        .validate()
        .is_ok());
    for key in ["projectId", "grantId", "selection"] {
        let mut missing = empty.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(serde_json::from_value::<Access>(missing).is_err());
        let mut wrong = empty.clone();
        wrong[key] = json!(false);
        assert!(serde_json::from_value::<Access>(wrong).is_err());
    }
    let access = Access {
        enabled: true,
        remaining_ms: 1,
        consumed: false,
        project_id: Some(id('a')),
        grant_id: Some(id('b')),
        selection: Some(Selection::new(Action::Initialize {}).unwrap()),
    };
    access.validate().unwrap();
    let mut bad = access.clone();
    bad.remaining_ms = 0;
    assert!(bad.validate().is_err());
    bad.remaining_ms = 1;
    bad.consumed = true;
    assert!(bad.validate().is_err());
    bad.enabled = false;
    assert!(bad.validate().is_err());
    let files = p::Access {
        enabled: true,
        remaining_ms: 1,
        consumed: false,
        project_id: Some(id('a')),
        grant_id: Some(id('b')),
        selection: Some(
            p::Selection::new(p::Action::Stage, "a".repeat(64), vec!["app/a".into()]).unwrap(),
        ),
    };
    let old = serde_json::to_value(&files).unwrap();
    assert!(old["selection"]["summary"].is_object());
    assert!(old["selection"].get("action").is_none());
    assert!(serde_json::from_value::<Access>(old.clone()).is_err());
    assert_eq!(serde_json::from_value::<p::Access>(old).unwrap(), files);
    assert!(serde_json::from_value::<p::Access>(serde_json::to_value(access).unwrap()).is_err());
}

#[test]
fn typed_previews_require_exact_source_reference_target_and_no_fake_init_index() {
    for action in actions() {
        let selected = Selection::new(action.clone()).unwrap();
        let good = review(&action);
        assert!(good.matches(&selected));
        for key in ["referenceRevision", "expectedIndex"] {
            let mut value = serde_json::to_value(&good).unwrap();
            value.as_object_mut().unwrap().remove(key);
            assert!(serde_json::from_value::<Review>(value).is_err());
        }
        let mut bad = good.clone();
        bad.registration_generation = 0;
        assert!(!bad.matches(&selected));
        if matches!(action, Action::Initialize {}) {
            let mut bad = good.clone();
            bad.expected_index = Some("e".repeat(64));
            assert!(!bad.matches(&selected));
            let mut bad = good.clone();
            bad.reference_revision = Some("b".repeat(64));
            assert!(!bad.matches(&selected));
        } else {
            let mut bad = good.clone();
            bad.source_revision = "9".repeat(64);
            assert!(!bad.matches(&selected));
            let mut bad = good.clone();
            bad.reference_revision = Some("9".repeat(64));
            assert!(!bad.matches(&selected));
            let mut value = serde_json::to_value(&good).unwrap();
            value["preview"]["targetRef"] = json!("refs/heads/foreign");
            let bad: Review = serde_json::from_value(value).unwrap();
            assert!(!bad.matches(&selected));
        }
    }
    let mut data = serde_json::to_value(review(&actions()[1])).unwrap();
    data["preview"]["branch"] = Value::Null;
    assert!(serde_json::from_value::<Review>(data.clone())
        .unwrap()
        .validate()
        .is_ok());
    data["preview"].as_object_mut().unwrap().remove("branch");
    assert!(serde_json::from_value::<Review>(data).is_err());
}

#[test]
fn repository_progress_and_service_envelope_never_turn_pending_or_unknown_into_success() {
    for action in actions() {
        let status = prepared(action);
        status.validate().unwrap();
        let mut response = service::Response {
            version: service::VERSION,
            request_id: id('e'),
            service_instance: id('b'),
            client_id: id('f'),
            session_id: id('1'),
            response: service::ResponseBody::GitRepositoryRequest(status.clone()),
        };
        assert!(service::encode_response(&response).unwrap().len() <= p::STATUS_BYTES);
        response.service_instance = id('2');
        assert!(service::encode_response(&response).is_err());
        let mut bad = status.clone();
        bad.settlement = Settlement::Settled;
        assert!(bad.validate().is_err());
        let mut bad = status.clone();
        bad.outcome = Some(OperationState::Succeeded);
        assert!(bad.validate().is_err());
        let mut unknown = status;
        unknown.review = None;
        unknown.state = p::State::Unknown;
        unknown.outcome = Some(OperationState::Unknown);
        unknown.settlement = Settlement::Unknown;
        unknown.validate().unwrap();
        unknown.settlement = Settlement::Settled;
        assert!(unknown.validate().is_err());
    }
}

#[test]
fn longest_bounded_preview_fits_existing_status_cap_without_retaining_contents() {
    let long = |suffix: &str| format!("refs/heads/{}/{suffix}", "a".repeat(980));
    let action = Action::FastForward {
        expected_revision: "a".repeat(64),
        expected_reference_revision: "b".repeat(64),
        target_ref: format!("refs/remotes/origin/{}", "z".repeat(980)),
        target_oid: "d".repeat(64),
    };
    let mut status = prepared(action);
    if let Preview::FastForward { head, branch, .. } = &mut status.review.as_mut().unwrap().preview
    {
        *head = "c".repeat(64);
        *branch = long("main");
    }
    status.validate().unwrap();
    assert!(serde_json::to_vec(&status).unwrap().len() < p::STATUS_BYTES - 512);
    let value = serde_json::to_value(status).unwrap();
    for field in [
        "paths",
        "contents",
        "diff",
        "command",
        "candidate",
        "token",
        "message",
        "identity",
    ] {
        assert!(value.get(field).is_none());
        assert!(value["review"].get(field).is_none());
        assert!(value["review"]["preview"].get(field).is_none());
    }
}
