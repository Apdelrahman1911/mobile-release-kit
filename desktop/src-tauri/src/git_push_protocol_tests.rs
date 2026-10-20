use super::*;
use serde_json::{json, Value};

pub(crate) fn action() -> Action {
    Action {
        kind: Kind::Push,
        expected_revision: "a".repeat(64),
        expected_reference_revision: "b".repeat(64),
        remote: "origin".into(),
        local_ref: "refs/heads/main".into(),
        remote_ref: "refs/heads/main".into(),
        old_oid: "1".repeat(40),
        new_oid: "2".repeat(40),
        connection_session_id: "connection-1".into(),
        expected_connection_revision: 3,
    }
}
pub(crate) fn review() -> Review {
    let a = action();
    Review {
        action: Kind::Push,
        remote: a.remote,
        repository: "owner/repository".into(),
        account_id: "12".into(),
        repository_id: "34".into(),
        login: "owner".into(),
        branch: a.local_ref,
        head: a.new_oid.clone(),
        upstream_ref: a.remote_ref,
        expected_remote_oid: a.old_oid,
        tracking_ref: "refs/remotes/origin/main".into(),
        commits: vec![a.new_oid],
        expected_revision: a.expected_revision,
        expected_reference_revision: a.expected_reference_revision,
        expected_index: "c".repeat(64),
        basis: "existing-configured-upstream".into(),
        withheld: ["messages", "authors", "emails", "signatures", "objects"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        review_digest: "d".repeat(64),
    }
}
pub(crate) fn intent() -> Intent {
    let r = review();
    let commits = r.commits_sha256();
    Intent {
        action: Kind::Push,
        review_digest: r.review_digest,
        expected_revision: r.expected_revision,
        expected_reference_revision: r.expected_reference_revision,
        expected_index: r.expected_index,
        remote: r.remote,
        repository: r.repository,
        account_id: r.account_id,
        repository_id: r.repository_id,
        local_ref: r.branch,
        remote_ref: r.upstream_ref,
        old_oid: r.expected_remote_oid,
        new_oid: r.head,
        commits_sha256: commits,
    }
}
#[test]
fn only_existing_branch_nonforce_action_and_exact_connection_data_decode() {
    let a = action();
    assert!(a.valid());
    let value = serde_json::to_value(&a).unwrap();
    assert!(serde_json::from_value::<Action>(value.clone()).unwrap() == a);
    for (key, bad) in [
        ("force", json!(true)),
        ("kind", json!("fetch")),
        ("oldOid", json!("0".repeat(40))),
        ("remoteRef", json!("refs/tags/v1")),
        ("expectedConnectionRevision", json!(0)),
        ("privateToken", json!("not-a-token")),
    ] {
        let mut v = value.clone();
        v[key] = bad;
        assert!(
            serde_json::from_value::<Action>(v)
                .map(|a| a.valid())
                .unwrap_or(false)
                == false
        );
    }
    let mut same = a.clone();
    same.new_oid = same.old_oid.clone();
    assert!(!same.valid());
}
#[test]
fn review_binds_exact_upstream_oids_commit_set_and_no_message_author_payload() {
    let a = action();
    let r = review();
    assert!(r.valid() && r.matches(&a));
    let mut bad = r.clone();
    bad.commits.push(bad.head.clone());
    assert!(!bad.valid());
    let mut bad = r.clone();
    bad.expected_remote_oid = bad.head.clone();
    assert!(!bad.valid());
    let mut bad = r.clone();
    bad.tracking_ref = "refs/remotes/other/main".into();
    assert!(!bad.valid());
    let mut bad = r.clone();
    bad.account_id = "99".into();
    assert!(bad.valid());
    assert!(!intent().matches(&bad));
    let mut v = serde_json::to_value(&r).unwrap();
    v["messages"] = json!(["private"]);
    assert!(serde_json::from_value::<Review>(v).is_err());
    let mut too_many = r.clone();
    too_many.commits = (1..=COMMIT_LIMIT + 1)
        .map(|v| format!("{v:040x}"))
        .collect();
    too_many.head = too_many.commits.last().unwrap().clone();
    assert!(!too_many.valid());
}
#[test]
fn candidate_binds_complete_review_not_only_new_oid_and_does_not_mean_sent() {
    let r = review();
    let i = intent();
    assert!(i.matches(&r) && i.matches_action(&action()));
    let mut other = i.clone();
    other.commits_sha256 = "e".repeat(64);
    assert!(!other.matches(&r));
    let mut other = i.clone();
    other.old_oid = "3".repeat(40);
    assert!(!other.matches_action(&action()));
    let value = json!({"operationId":"git-7","action":"push","state":"recovery-required","settlement":"settled",
        "reason":"cancelled","observation":null,"intent":i,"effectPhase":"candidate-acknowledged","retainedPaths":[]});
    let pending: Mutation = serde_json::from_value(value.clone()).unwrap();
    assert!(pending.valid(&action(), "git-7"));
    let mut claimed = value;
    claimed["state"] = json!("succeeded");
    claimed["reason"] = Value::Null;
    assert!(!serde_json::from_value::<Mutation>(claimed)
        .unwrap()
        .valid(&action(), "git-7"));
}
#[test]
fn journal_keeps_same_review_and_refuses_candidate_replacement_or_unbound_finality() {
    let r = review();
    let mut j = crate::git_push_state::Journal::preparing(&r);
    let valid = |j: &crate::git_push_state::Journal| {
        j.valid(
            &r.expected_revision,
            Some(&r.head),
            Some(&r.branch),
            &r.expected_index,
            &r.review_digest,
        )
    };
    assert!(valid(&j) && j.accepts(&intent()));
    j.candidate = Some(intent());
    assert!(valid(&j) && !j.accepts(&intent()));
    let original = j.clone();
    let mut changed = j.clone();
    changed.reviewed.expected_remote_oid = "3".repeat(40);
    assert!(!changed.same_original(&original) && !valid(&changed));
    let bytes = serde_json::to_vec(&j).unwrap();
    let reopened: crate::git_push_state::Journal = serde_json::from_slice(&bytes).unwrap();
    assert!(reopened == j && !reopened.accepts(&intent()) && reopened.final_state.is_none());
}
