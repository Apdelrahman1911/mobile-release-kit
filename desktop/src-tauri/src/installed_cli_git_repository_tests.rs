//! The real outer collector/shared parser, framing and formatter only. No IPC,
//! credentials, native grant, Git subprocess or filesystem owner is entered.
use super::*;
use crate::service_git_repository_protocol as repository;
use serde_json::json;

fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn origin() -> git::Query {
    git::Query {
        project_id: id('a'),
        service_instance: id('b'),
        request_id: id('c'),
    }
}
fn response(body: p::ResponseBody) -> p::Response {
    p::Response {
        version: p::VERSION,
        request_id: id('d'),
        service_instance: id('b'),
        client_id: id('e'),
        session_id: id('f'),
        response: body,
    }
}

#[test]
fn repository_actual_outer_collector_preserves_all_five_commands_and_no_cli_action_parameters() {
    let q = origin();
    let commands: Vec<Vec<&str>> = vec![
        vec!["git-repository-scope", q.project_id.as_str()],
        vec![
            "git-repository-prepare",
            q.project_id.as_str(),
            q.service_instance.as_str(),
            id_str(),
        ],
        vec![
            "git-repository-start",
            q.project_id.as_str(),
            q.service_instance.as_str(),
            q.request_id.as_str(),
            "git-local-1",
            "git-local-1-review",
        ],
        vec![
            "git-repository-status",
            q.project_id.as_str(),
            q.service_instance.as_str(),
            q.request_id.as_str(),
        ],
        vec![
            "git-repository-cancel",
            q.project_id.as_str(),
            q.service_instance.as_str(),
            q.request_id.as_str(),
        ],
    ];
    for words in commands {
        for json in [false, true] {
            let words = words.iter().copied().chain(json.then_some("--json"));
            let args = super::super::collect_arguments(words.map(OsString::from));
            assert!(recognizes_for(&args, Family::Repository));
            let parsed = parse_for(&args, Family::Repository).unwrap();
            assert_eq!(parsed.json, json);
            assert!(parse(&args).is_err());
            assert!(parse_for(&args, Family::Commit).is_err());
            if let Command::Start(start) = parsed.command {
                assert_eq!(start.origin, q);
                assert_eq!(start.review_id, "git-local-1-review");
            }
            let extra = super::super::collect_arguments(
                args.into_iter()
                    .chain(std::iter::repeat(OsString::from("--force"))),
            );
            assert_eq!(extra.len(), 11);
            assert!(parse_for(&extra, Family::Repository).is_err());
        }
    }
    fn id_str() -> &'static str {
        "dddddddddddddddddddddddddddddddd"
    }
}

#[test]
fn repository_framing_is_ids_only_and_unknown_reply_keeps_original_status_stop() {
    let q = origin();
    let body = p::RequestBody::GitRepositoryPrepare(git::Prepare {
        origin: q.clone(),
        grant_id: id('d'),
    });
    let bytes = p::encode_request(&framed(body).unwrap()).unwrap();
    assert!(bytes.len() <= 4096);
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["request"]["method"], "git-repository.prepare");
    assert_eq!(value["request"]["params"].as_object().unwrap().len(), 2);
    for field in [
        "action",
        "name",
        "targetRef",
        "path",
        "command",
        "environment",
        "url",
    ] {
        value["request"]["params"][field] = json!("forged");
        assert!(p::decode_request(&serde_json::to_vec(&value).unwrap()).is_err());
        value["request"]["params"]
            .as_object_mut()
            .unwrap()
            .remove(field);
    }
    let json = unconfirmed_for(&q, Error::Unavailable, true, Family::Repository);
    let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(value["request"]["requestId"], q.request_id.as_str());
    assert_eq!(value["doNotReplay"], true);
    let human = String::from_utf8(unconfirmed_for(
        &q,
        Error::StateUnknown,
        false,
        Family::Repository,
    ))
    .unwrap();
    assert!(human.contains("git-repository-status") && human.contains("git-repository-cancel"));
    assert!(!human.contains("git-repository-prepare") && !human.contains("git-index-status"));
}

#[test]
fn repository_output_is_family_bound_and_init_preview_never_fabricates_an_index_or_ref() {
    let q = origin();
    let scope = repository::Scope {
        service_instance: q.service_instance.clone(),
        project_id: q.project_id.clone(),
        access: repository::Access::empty(),
    };
    let good = response(p::ResponseBody::GitRepositoryScope(scope));
    assert!(output_for(&good, &q.project_id, None, true, Family::Repository).is_ok());
    assert!(output(&good, &q.project_id, None, true).is_err());
    assert!(output_for(&good, &id('9'), None, false, Family::Repository).is_err());
    let old = response(p::ResponseBody::GitIndexScope(git::Scope {
        service_instance: q.service_instance.clone(),
        project_id: q.project_id.clone(),
        access: git::Access::empty(),
    }));
    assert!(output_for(&old, &q.project_id, None, false, Family::Repository).is_err());
    let status = repository::Status {
        origin: q.clone(),
        grant_id: id('d'),
        selection: repository::Selection::new(repository::Action::Initialize {}).unwrap(),
        revision: 3,
        state: git::State::Prepared,
        prepare_operation_id: Some("git-local-1".into()),
        apply_operation_id: None,
        review: Some(repository::Review {
            review_id: "git-local-1-review".into(),
            source_revision: "a".repeat(64),
            reference_revision: None,
            expected_index: None,
            review_digest: "b".repeat(64),
            document_revision: 1,
            registration_generation: 1,
            preview: repository::Preview::Initialize {
                initial_branch: "main".into(),
                object_format: "sha1".into(),
            },
        }),
        outcome: None,
        settlement: p::Settlement::Pending,
        reason: None,
        history_available: false,
        do_not_replay: true,
    };
    let mut ready = response(p::ResponseBody::GitRepositoryRequest(status));
    let (_, bytes) =
        output_for(&ready, &q.project_id, Some(&q), false, Family::Repository).unwrap();
    let human = String::from_utf8(bytes).unwrap();
    assert!(human.contains("git-repository-start"));
    assert!(human.contains("no synthetic index") && human.contains("settlement Pending"));
    let (_, json) = output_for(&ready, &q.project_id, Some(&q), true, Family::Repository).unwrap();
    assert!(json.len() <= git::STATUS_BYTES + 1 && json.ends_with(b"\n"));
    ready.service_instance = id('9');
    assert!(output_for(&ready, &q.project_id, Some(&q), false, Family::Repository).is_err());
}

#[test]
fn compiled_repository_catalogue_preserves_old_families_and_local_output_bound() {
    let bytes = super::super::capabilities(true).unwrap();
    assert!(bytes.len() <= crate::installed_cli::CAPABILITIES_BYTES);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let own = &value["gitRepository"];
    assert_eq!(
        own["actions"],
        json!([
            "initialize",
            "branch-create",
            "branch-switch",
            "branch-rename",
            "fast-forward"
        ])
    );
    assert_eq!(own["commands"].as_array().unwrap().len(), 5);
    for field in [
        "defaultEnabled",
        "readGrantAuthorizesWrites",
        "prepareApplies",
        "fetch",
        "push",
        "nativeAvailabilityChecked",
    ] {
        assert_eq!(own[field], false);
    }
    assert_eq!(own["oneUse"], true);
    assert_eq!(own["sharesGitGrantAnd32Requests"], true);
    assert_eq!(value["gitIndex"]["branchChanges"], false);
    assert_eq!(value["gitIndex"]["commit"], false);
    assert_eq!(value["gitCommits"]["branchChanges"], false);
    assert_eq!(value["gitCommits"]["includesPrivateDraft"], false);
    assert!(!super::super::capabilities(false).unwrap().is_empty());
}
