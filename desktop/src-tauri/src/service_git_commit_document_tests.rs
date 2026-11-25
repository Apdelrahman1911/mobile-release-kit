use super::*;
use crate::service_protocol::Id;
fn observed() -> read::Projection {
    super::super::tests::observed()
}
fn draft(message: &str) -> Draft {
    Draft::new(
        message.into(),
        "Example Author".into(),
        "a@example.invalid".into(),
    )
    .unwrap()
}
fn scope(doc: &Arc<()>) -> requests::NativeScope {
    requests::NativeScope {
        project_id: Id::parse(&"a".repeat(32)).unwrap(),
        runtime_id: "project-1".into(),
        root: "/inert/no-native".into(),
        device: 1,
        inode: 2,
        registration: 1,
        document_revision: 1,
        input_revision: 1,
        read_operation_id: Some("git-read-1".into()),
        document: Arc::downgrade(doc),
        selection: whole_selection(&observed()).unwrap().into(),
        commit: Some(draft("approved")),
        changes: tokio::sync::watch::channel(0).0,
    }
}
#[test]
fn whole_commit_selection_includes_every_staged_row_not_renderer_selected_subset() {
    let mut value = observed();
    value.result["observation"]["changes"] = serde_json::json!([
        {"path":"app/a","index":"M","worktree":"M","kind":"file","conflict":false},
        {"path":"other/b","index":"A","worktree":" ","kind":"file","conflict":false},
        {"path":"unstaged/c","index":" ","worktree":"M","kind":"file","conflict":false},
        {"path":"untracked/d","index":"?","worktree":"?","kind":"file","conflict":false}
    ]);
    let selected = whole_selection(&value).unwrap();
    assert_eq!(selected.paths, vec!["app/a", "other/b"]);
    assert_eq!(selected.summary.action, wire::Action::Commit);
    value.result["observation"]["changes"][0]["index"] = serde_json::json!(" ");
    assert_ne!(
        whole_selection(&value).unwrap().summary.selection_sha256,
        selected.summary.selection_sha256
    );
}
#[test]
fn failed_nonobserve_incomplete_or_conflicted_data_is_never_commit_eligibility() {
    for cut in 0..7 {
        let mut value = observed();
        match cut {
            0 => value.action.kind = read::Kind::Diff,
            1 => value.phase = read::Phase::Running,
            2 => value.outcome = Some(read::Outcome::Refused),
            3 => value.phase = read::Phase::CleanupUnknown,
            4 => value.result["observation"]["restrictions"] = serde_json::json!(["unsupported"]),
            5 => value.result["observation"]["changes"][0]["conflict"] = serde_json::json!(true),
            _ => value.result["observation"]["changes"][0]["index"] = serde_json::json!(" "),
        }
        assert!(whole_selection(&value).is_err());
    }
}
#[test]
fn only_exact_private_draft_and_real_whole_index_review_match_common_native_scope() {
    let doc = Arc::new(());
    let mut scope = scope(&doc);
    let original = action(&scope).unwrap();
    assert!(original.valid() && original.kind() == local::Kind::Commit);
    assert!(!same_action(&original, scope.selection.files().unwrap())); // Index matcher stays index-only.
    let mut review = local::FileReview {
        action: local::Kind::Commit,
        expected_revision: scope.selection.files().unwrap().summary.repository_revision.clone(),
        paths: scope.selection.files().unwrap().paths.clone(),
        whole_index: true,
        head: Some("b".repeat(40)),
        branch: Some("refs/heads/main".into()),
        expected_index: "c".repeat(64),
        review_digest: "d".repeat(64),
    };
    assert!(review_matches(&scope, &review));
    review.whole_index = false;
    assert!(!review_matches(&scope, &review));
    review.whole_index = true;
    review.paths = vec!["not-approved".into()];
    assert!(!review_matches(&scope, &review));
    scope.commit = Some(draft("changed message"));
    assert!(action(&scope).unwrap() != original);
    scope.commit = Some(
        Draft::new(
            "approved".into(),
            "Different Author".into(),
            "other@example.invalid".into(),
        )
        .unwrap(),
    );
    assert!(action(&scope).unwrap() != original);
    scope.commit = None;
    assert!(action(&scope).is_err());
}
#[test]
fn commit_gui_codec_accepts_only_private_draft_and_original_ids_not_a_native_plan() {
    let value = serde_json::json!({"projectId":"project-1","expectedDocumentRevision":1,"expectedPermissionRevision":"0","readOperationId":"git-read-1",
        "message":"approved", "authorName":"Example", "authorEmail":"a@example.invalid", "consentVersion":commit::CONSENT});
    assert!(decode_commit_allow(&serde_json::to_vec(&value).unwrap()).is_ok());
    for field in [
        "paths",
        "action",
        "root",
        "nativeReceipt",
        "reviewId",
        "command",
    ] {
        let mut changed = value.clone();
        changed[field] = serde_json::json!("injected");
        assert!(decode_commit_allow(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
    let mut changed = value;
    changed["consentVersion"] = serde_json::json!(wire::CONSENT);
    assert!(decode_commit_allow(&serde_json::to_vec(&changed).unwrap()).is_err());
}
