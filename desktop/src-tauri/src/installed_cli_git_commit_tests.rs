//! Exercises the actual shared argument collection/parser and typed output.
//! No transport, native permission, filesystem or Git process is invoked.
use super::*;
use crate::service_git_commit_protocol as commit;
fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn query_fixture() -> git::Query {
    git::Query {
        project_id: id('a'),
        service_instance: id('b'),
        request_id: id('c'),
    }
}

#[test]
fn commit_outer_collector_and_closed_parser_preserve_ids_and_reject_index_or_extra_words() {
    let q = query_fixture();
    let words = [
        "git-commit-start",
        q.project_id.as_str(),
        q.service_instance.as_str(),
        q.request_id.as_str(),
        "git-local-1",
        "git-local-1-review",
        "--json",
    ];
    let args = super::super::collect_arguments(words.into_iter().map(OsString::from));
    assert!(recognizes_for(&args, Family::Commit));
    assert!(!recognizes(&args));
    let parsed = parse_for(&args, Family::Commit).unwrap();
    assert!(parsed.json);
    let Command::Start(start) = parsed.command else {
        panic!("closed Start")
    };
    assert_eq!(start.origin, q);
    assert_eq!(start.prepare_operation_id, "git-local-1");
    assert!(parse(&args).is_err());
    let extra = super::super::collect_arguments(
        args.into_iter()
            .chain(std::iter::repeat(OsString::from("extra"))),
    );
    assert_eq!(extra.len(), 11);
    assert!(parse_for(&extra, Family::Commit).is_err());
}
#[test]
fn commit_uncertain_receipt_keeps_exact_ids_and_never_prints_replacement_or_private_draft() {
    let q = query_fixture();
    let bytes = unconfirmed_for(&q, Error::Unavailable, true, Family::Commit);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["request"]["requestId"], q.request_id.as_str());
    assert_eq!(value["doNotReplay"], true);
    let human = String::from_utf8(unconfirmed_for(
        &q,
        Error::StateUnknown,
        false,
        Family::Commit,
    ))
    .unwrap();
    assert!(human.contains("git-commit-status") && human.contains("git-commit-cancel"));
    assert!(!human.contains("git-commit-prepare") && !human.contains("git-index-status"));
}
#[test]
fn commit_output_requires_correct_typed_family_and_instance_even_for_empty_scope() {
    let q = query_fixture();
    let scope = git::Scope {
        service_instance: q.service_instance.clone(),
        project_id: q.project_id.clone(),
        access: git::Access::empty(),
    };
    let mut response = p::Response {
        version: p::VERSION,
        request_id: id('d'),
        service_instance: q.service_instance.clone(),
        client_id: id('e'),
        session_id: id('f'),
        response: p::ResponseBody::GitCommitScope(commit::Scope(scope.clone())),
    };
    assert!(output_for(&response, &q.project_id, None, true, Family::Commit).is_ok());
    assert!(output(&response, &q.project_id, None, true).is_err());
    response.response = p::ResponseBody::GitIndexScope(scope);
    assert!(output_for(&response, &q.project_id, None, true, Family::Commit).is_err());
}
#[test]
fn commit_request_framing_and_catalogue_preserve_no_draft_and_existing_output_cap() {
    let q = query_fixture();
    let request = framed(p::RequestBody::GitCommitPrepare(git::Prepare {
        origin: q,
        grant_id: id('d'),
    }))
    .unwrap();
    let bytes = p::encode_request(&request).unwrap();
    assert!(bytes.len() <= 4096);
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["request"]["method"], "git-commit.prepare");
    for field in ["message", "identity", "paths", "command"] {
        assert!(!std::str::from_utf8(&bytes).unwrap().contains(field));
    }
    let catalogue = super::super::capabilities(true).unwrap();
    assert!(catalogue.len() <= crate::installed_cli::CAPABILITIES_BYTES);
    let v: serde_json::Value = serde_json::from_slice(&catalogue).unwrap();
    assert_eq!(v["gitIndex"]["commit"], false);
    assert_eq!(
        v["gitCommits"]["sharesGrantAndRequestLimitWithGitIndex"],
        true
    );
    assert_eq!(v["gitCommits"]["commands"].as_array().unwrap().len(), 5);
    for field in [
        "nativeAvailabilityChecked",
        "includesPrivateDraft",
        "hooks",
        "signing",
        "branchChanges",
        "push",
        "credentials",
    ] {
        assert_eq!(v["gitCommits"][field], false);
    }
}
