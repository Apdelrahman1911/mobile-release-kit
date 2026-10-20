use super::*;
fn observed() -> read::Projection {
    read::Projection {
        operation_id: "git-read-1".into(),
        context: read::Context {
            project_id: "project-1".into(),
            generation: 1,
            revision: "document-1".into(),
        },
        action: read::Action {
            kind: read::Kind::Observe,
            expected_revision: None,
            paths: vec![],
            staged: false,
        },
        phase: read::Phase::Settled,
        outcome: Some(read::Outcome::Ok),
        reason: None,
        result: serde_json::json!({"observation":{"revision":"a".repeat(64),"head":"b".repeat(40),"branch":"refs/heads/main","unborn":false,"detached":false,
 "changes":[{"path":"app/a","index":"M","worktree":"M","kind":"file","conflict":false}],"remotes":[],"restrictions":[]},
 "referenceRevision":"c".repeat(64),"tracking":{"state":"not-configured","remote":null,"mergeRef":null,"localRef":null,"head":null,"ahead":null,"behind":null},"basis":"local-refs-no-fetch"}),
    }
}
#[test]
fn only_current_successful_observe_data_is_even_eligible_for_native_consent() {
    let v = observed();
    assert!(successful_observe(&v));
    assert!(selection(&v, wire::Action::Stage, vec!["app/a".into()]).is_ok());
    for field in 0..4 {
        let mut bad = v.clone();
        match field {
            0 => bad.action.kind = read::Kind::Diff,
            1 => bad.outcome = Some(read::Outcome::Refused),
            2 => bad.phase = read::Phase::CleanupUnknown,
            _ => bad.phase = read::Phase::Running,
        };
        assert!(selection(&bad, wire::Action::Stage, vec!["app/a".into()]).is_err());
    }
    let mut bad = v.clone();
    bad.result["observation"]["changes"][0]["worktree"] = serde_json::json!(" ");
    assert!(selection(&bad, wire::Action::Stage, vec!["app/a".into()]).is_err());
    assert!(selection(&v, wire::Action::Stage, vec!["not-observed".into()]).is_err());
    // This test is only DATA eligibility. It does not create the original
    // Observe stamp/receipt, NativeLink, native permission or a Git process.
}
#[test]
fn native_consent_codec_rejects_paths_outside_exact_selected_roster() {
    let value = serde_json::json!({"projectId":"project-1","expectedDocumentRevision":1,"readOperationId":"git-read-1","action":"stage","paths":["app/a"],"consentVersion":wire::CONSENT});
    assert!(decode_allow(&serde_json::to_vec(&value).unwrap()).is_ok());
    for key in ["window", "root", "nativeReceipt", "command", "reviewId"] {
        let mut bad = value.clone();
        bad[key] = serde_json::json!("forged");
        assert!(decode_allow(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    let mut bad = value.clone();
    bad["paths"] = serde_json::json!(["app/z", "app/a"]);
    assert!(decode_allow(&serde_json::to_vec(&bad).unwrap()).is_err());
    let duplicate = b"{\"projectId\":\"project-1\",\"projectId\":\"project-2\"}";
    assert!(decode_allow(duplicate).is_err());
}
#[test]
fn dormant_document_or_nonmain_caller_never_starts_a_host_or_native_reader() {
    let bridge = Arc::new(DesktopBridge::new(std::path::PathBuf::from(
        "/inert/git-index-never-opened",
    )));
    let doc = DocumentBinding::new(bridge.clone());
    assert!(!doc.agent_git_index_access(MAIN).unwrap().enabled);
    assert!(doc.agent_git_index_access("foreign").is_err());
    assert!(!doc.revoke_agent_git_index(MAIN).unwrap().enabled);
    doc.service_git_index_tick(Path::new("/inert/no-io"));
    doc.drain_git_index_for_exit();
    assert!(!bridge.application_service.status().unwrap().enabled);
}
