//! Actual shared CLI collector/codec/formatter; inert bytes only. No socket,
//! Git process, credential, Connection or native settlement is constructed.
use super::*;
use crate::service_git_remote_protocol as remote;
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
fn actual_collector_admits_only_the_five_id_only_remote_commands() {
    let q = origin();
    let d = id('d');
    let words = vec![
        vec!["git-remote-scope", q.project_id.as_str()],
        vec![
            "git-remote-prepare",
            q.project_id.as_str(),
            q.service_instance.as_str(),
            d.as_str(),
        ],
        vec![
            "git-remote-start",
            q.project_id.as_str(),
            q.service_instance.as_str(),
            q.request_id.as_str(),
            "git-local-1",
            "git-local-1-review",
        ],
        vec![
            "git-remote-status",
            q.project_id.as_str(),
            q.service_instance.as_str(),
            q.request_id.as_str(),
        ],
        vec![
            "git-remote-cancel",
            q.project_id.as_str(),
            q.service_instance.as_str(),
            q.request_id.as_str(),
        ],
    ];
    for words in words {
        for json in [false, true] {
            let args = super::super::collect_arguments(
                words
                    .iter()
                    .copied()
                    .chain(json.then_some("--json"))
                    .map(OsString::from),
            );
            assert!(recognizes_for(&args, Family::Remote));
            assert_eq!(parse_for(&args, Family::Remote).unwrap().json, json);
            for old in [Family::Index, Family::Commit, Family::Repository] {
                assert!(parse_for(&args, old).is_err());
            }
            for extra in ["--force", "https://github.com/other/repo", "--token"] {
                let mut v = args.clone();
                v.push(extra.into());
                assert!(parse_for(&v, Family::Remote).is_err());
            }
        }
    }
}
#[test]
fn wire_and_lost_reply_preserve_exact_ids_without_an_action_or_replay() {
    let q = origin();
    let request = framed(p::RequestBody::GitRemotePrepare(git::Prepare {
        origin: q.clone(),
        grant_id: id('d'),
    }))
    .unwrap();
    let bytes = p::encode_request(&request).unwrap();
    assert!(bytes.len() < 4096);
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["request"]["method"], "git-remote.prepare");
    for field in [
        "action",
        "url",
        "token",
        "window",
        "remoteRef",
        "accountId",
        "repositoryId",
    ] {
        value["request"]["params"][field] = "forged".into();
        assert!(p::decode_request(&serde_json::to_vec(&value).unwrap()).is_err());
        value["request"]["params"]
            .as_object_mut()
            .unwrap()
            .remove(field);
    }
    let lost = String::from_utf8(unconfirmed_for(
        &q,
        Error::StateUnknown,
        false,
        Family::Remote,
    ))
    .unwrap();
    assert!(lost.contains("git-remote-status") && lost.contains("git-remote-cancel"));
    assert!(!lost.contains("git-remote-start") && !lost.contains("git-remote-prepare"));
}
#[test]
fn exact_ready_effect_unknown_and_family_mismatch_remain_distinct() {
    let q = origin();
    let mut status = remote::Status {
        progress: git::Status {
            origin: q.clone(),
            grant_id: id('d'),
            selection: remote::tests::selection(true),
            revision: 3,
            state: git::State::Prepared,
            prepare_operation_id: Some("git-local-1".into()),
            apply_operation_id: None,
            review: Some(remote::tests::review(true)),
            outcome: None,
            settlement: p::Settlement::Pending,
            reason: None,
            history_available: false,
            do_not_replay: true,
        },
        result: None,
    };
    let view = response(p::ResponseBody::GitRemoteRequest(status.clone()));
    let (_, bytes) = output_for(&view, &q.project_id, Some(&q), false, Family::Remote).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("git-remote-start") && text.contains("64 outgoing commits"));
    assert!(output_for(&view, &q.project_id, Some(&q), false, Family::Repository).is_err());
    assert!(output_for(&view, &id('9'), Some(&q), false, Family::Remote).is_err());
    status.progress.state = git::State::Unknown;
    status.progress.settlement = p::Settlement::Unknown;
    status.progress.outcome = Some(p::OperationState::Unknown);
    status.progress.reason = Some(git::Reason::CleanupUnknown);
    status.progress.review = None;
    let view = response(p::ResponseBody::GitRemoteRequest(status.clone()));
    let (code, bytes) = output_for(&view, &q.project_id, Some(&q), false, Family::Remote).unwrap();
    assert_eq!(code, 6);
    assert!(!String::from_utf8(bytes)
        .unwrap()
        .contains("git-remote-start"));
    status.progress.state = git::State::Finished;
    status.progress.settlement = p::Settlement::Settled;
    status.progress.outcome = Some(p::OperationState::RecoveryRequired);
    status.progress.reason = Some(git::Reason::RecoveryRequired);
    status.progress.apply_operation_id = Some("git-local-2".into());
    status.result = Some(remote::Outcome {
        operation_id: "git-local-2".into(),
        action: remote::Kind::Push,
        state: remote::EffectState::RecoveryRequired,
        effect_phase: remote::Effect::SendConsumed,
        retained_paths: vec!["mrk-git-original/mrk-git-push-original".into()],
    });
    let view = response(p::ResponseBody::GitRemoteRequest(status.clone()));
    assert_eq!(
        output_for(&view, &q.project_id, Some(&q), true, Family::Remote)
            .unwrap()
            .0,
        6
    );
    status.progress.outcome = Some(p::OperationState::Succeeded);
    assert!(p::encode_response(&response(p::ResponseBody::GitRemoteRequest(status))).is_err());
}
#[test]
fn complete_capabilities_remain_bounded_and_discovery_includes_remote() {
    for json in [false, true] {
        let b = super::super::capabilities(json).unwrap();
        assert!(b.len() <= crate::installed_cli::CAPABILITIES_BYTES);
        let s = String::from_utf8(b).unwrap();
        for name in super::super::git_remote::NAMES {
            assert!(s.contains(name));
        }
        if json {
            let v: serde_json::Value = serde_json::from_str(&s).unwrap();
            assert_eq!(v["gitRemote"]["nativeAvailabilityChecked"], false);
            assert_eq!(
                v["gitRemote"]["actions"],
                serde_json::json!(["fetch", "push", "push-new-branch"])
            );
            assert!(v["requestDiscovery"]["families"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "git-remote"));
        }
    }
}
#[test]
fn new_branch_scope_uses_existing_id_only_commands_and_explains_no_upstream() {
    let q = origin();
    let scope = response(p::ResponseBody::GitRemoteScope(remote::Scope {
        service_instance: q.service_instance.clone(),
        project_id: q.project_id.clone(),
        access: remote::Access {
            enabled: true,
            remaining_ms: 900000,
            consumed: false,
            project_id: Some(q.project_id.clone()),
            grant_id: Some(id('d')),
            selection: Some(remote::tests::new_branch_selection()),
        },
    }));
    let (_, text) = output_for(&scope, &q.project_id, None, false, Family::Remote).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("push-new-branch") && text.contains("git-remote-prepare"));
    assert!(
        text.contains("target not advertised")
            && text.contains("server create-only update must reject any existing target")
            && text.contains("does not configure a remote or upstream")
    );
    assert!(!text.contains("prove the target absent"));
    let (_, bytes) = output_for(&scope, &q.project_id, None, true, Family::Remote).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        value["response"]["value"]["access"]["selection"]["action"]["kind"],
        "push-new-branch"
    );
    assert!(value["response"]["value"]["access"]["selection"]["action"]["remote"].is_null());
    let grant = id('d');
    let args = super::super::collect_arguments(
        [
            "git-remote-prepare",
            q.project_id.as_str(),
            q.service_instance.as_str(),
            grant.as_str(),
            "push-new-branch",
        ]
        .into_iter()
        .map(OsString::from),
    );
    assert!(parse_for(&args, Family::Remote).is_err());
}
#[test]
fn new_branch_ready_and_returned_failure_keep_exact_kind_without_retry_command() {
    let q = origin();
    let mut status = remote::Status {
        progress: git::Status {
            origin: q.clone(),
            grant_id: id('d'),
            selection: remote::tests::new_branch_selection(),
            revision: 3,
            state: git::State::Prepared,
            prepare_operation_id: Some("git-local-1".into()),
            apply_operation_id: None,
            review: Some(remote::tests::new_branch_review()),
            outcome: None,
            settlement: p::Settlement::Pending,
            reason: None,
            history_available: false,
            do_not_replay: true,
        },
        result: None,
    };
    let view = response(p::ResponseBody::GitRemoteRequest(status.clone()));
    let (_, bytes) = output_for(&view, &q.project_id, Some(&q), false, Family::Remote).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert!(
        text.contains("Create-only Push")
            && text.contains("64 reachable commits")
            && text.contains("git-remote-start")
    );
    assert!(!text.contains("Normal Push"));
    status.progress.state = git::State::Finished;
    status.progress.review = None;
    status.progress.apply_operation_id = Some("git-local-2".into());
    status.progress.outcome = Some(p::OperationState::RecoveryRequired);
    status.progress.settlement = p::Settlement::Settled;
    status.progress.reason = Some(git::Reason::RecoveryRequired);
    status.result = Some(remote::Outcome {
        operation_id: "git-local-2".into(),
        action: remote::Kind::PushNewBranch,
        state: remote::EffectState::RecoveryRequired,
        effect_phase: remote::Effect::SendConsumed,
        retained_paths: vec!["mrk-git-original/mrk-git-push-original".into()],
    });
    let view = response(p::ResponseBody::GitRemoteRequest(status.clone()));
    let (code, bytes) = output_for(&view, &q.project_id, Some(&q), false, Family::Remote).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert_eq!(code, 6);
    assert!(
        text.contains("push-new-branch")
            && text.contains("git-remote-status")
            && text.contains("git-remote-cancel")
    );
    assert!(!text.contains("git-remote-start") && !text.contains("git-remote-prepare"));
    assert!(
        text.contains("separate explicit Desktop Activity")
            && text.contains("cannot settle or replay")
    );
    status.result.as_mut().unwrap().action = remote::Kind::Push;
    assert!(p::encode_response(&response(p::ResponseBody::GitRemoteRequest(status))).is_err());
}
