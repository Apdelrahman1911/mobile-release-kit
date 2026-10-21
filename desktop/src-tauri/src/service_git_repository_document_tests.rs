//! Actual codecs and DATA predicates, not native admission or join receipts.
use super::*;
use crate::service_protocol::Id;
use serde_json::json;

fn observed() -> read::Projection {
    super::super::tests::observed()
}
fn branch_action(kind: &str) -> repository::Action {
    serde_json::from_value(json!({"kind":kind,"expectedRevision":"a".repeat(64),
        "expectedReferenceRevision":"c".repeat(64),"name":"next"}))
    .unwrap()
}
fn branches() -> read::Projection {
    let mut value = observed();
    value.operation_id = "git-read-branches".into();
    value.action.kind = read::Kind::Branches;
    value.action.expected_revision = Some("a".repeat(64));
    value.result = json!({"revision":"a".repeat(64),"referenceRevision":"c".repeat(64),
        "head":"b".repeat(40),"branch":"refs/heads/main","basis":"local-refs-no-fetch",
        "branches":[{"ref":"refs/heads/main","oid":"b".repeat(40)},{"ref":"refs/heads/next","oid":"d".repeat(40)}]});
    value
}
fn scope(doc: &Arc<()>, action: repository::Action) -> requests::NativeScope {
    let init = matches!(action, repository::Action::Initialize {});
    requests::NativeScope {
        project_id: Id::parse(&"a".repeat(32)).unwrap(),
        runtime_id: "project-1".into(),
        root: "/inert/no-native-repository".into(),
        device: 1,
        inode: 2,
        registration: 1,
        document_revision: 1,
        input_revision: 1,
        read_operation_id: if init {
            None
        } else {
            Some("git-read-1".into())
        },
        document: Arc::downgrade(doc),
        selection: repository::Selection::new(action).unwrap().into(),
        commit: None,
        changes: tokio::sync::watch::channel(0).0,
    }
}

#[test]
fn allow_codec_requires_exact_local_action_consent_and_null_only_for_init() {
    assert!(decode_repository_empty(b"{}").is_ok());
    assert!(decode_repository_empty(b"{\"root\":\"forged\"}").is_err());
    assert!(decode_repository_empty(&vec![b' '; 1024]).is_err());
    assert!(decode_repository_empty(b"").is_err());
    let value = json!({"projectId":"project-1","expectedDocumentRevision":1,"readOperationId":null,
        "action":{"kind":"initialize"},"consentVersion":repository::CONSENT});
    assert!(decode_repository_allow(&serde_json::to_vec(&value).unwrap()).is_ok());
    for field in ["readOperationId", "action", "consentVersion"] {
        let mut bad = value.clone();
        bad.as_object_mut().unwrap().remove(field);
        assert!(decode_repository_allow(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    for field in [
        "window",
        "root",
        "command",
        "paths",
        "nativeReceipt",
        "expectedIndex",
    ] {
        let mut bad = value.clone();
        bad[field] = json!("forged");
        assert!(decode_repository_allow(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    let mut bad = value.clone();
    bad["readOperationId"] = json!("invented");
    assert!(decode_repository_allow(&serde_json::to_vec(&bad).unwrap()).is_err());
    let mut branch = value.clone();
    branch["action"] = serde_json::to_value(branch_action("branch-create")).unwrap();
    assert!(decode_repository_allow(&serde_json::to_vec(&branch).unwrap()).is_err());
    branch["readOperationId"] = json!("git-read-branches");
    assert!(decode_repository_allow(&serde_json::to_vec(&branch).unwrap()).is_ok());
    branch["consentVersion"] = json!(wire::CONSENT);
    assert!(decode_repository_allow(&serde_json::to_vec(&branch).unwrap()).is_err());
    assert!(decode_repository_allow(b"{\"projectId\":\"a\",\"projectId\":\"b\"}").is_err());
    assert!(decode_repository_allow(&vec![b' '; repository::RAW_LIMIT]).is_err());
}

#[test]
fn current_positive_observe_or_branches_is_distinct_from_failed_read_and_cached_ff_basis() {
    let observed = observed();
    let branches = branches();
    assert!(successful_read(&branches));
    assert!(!successful_observe(&branches));
    for kind in ["branch-create", "branch-switch", "branch-rename"] {
        let action = branch_action(kind);
        assert!(selected(&observed, &action));
        assert!(selected(&branches, &action));
        for cut in 0..5 {
            let mut bad = branches.clone();
            match cut {
                0 => bad.phase = read::Phase::Running,
                1 => bad.phase = read::Phase::CleanupUnknown,
                2 => bad.outcome = Some(read::Outcome::Refused),
                3 => bad.result["referenceRevision"] = json!("9".repeat(64)),
                _ => bad.result["revision"] = json!("9".repeat(64)),
            }
            assert!(!selected(&bad, &action));
        }
    }
    assert!(!selected(&observed, &repository::Action::Initialize {}));
    assert!(!selected(&branches, &repository::Action::Initialize {}));
    let ff = repository::Action::FastForward {
        expected_revision: "a".repeat(64),
        expected_reference_revision: "c".repeat(64),
        target_ref: "refs/remotes/origin/main".into(),
        target_oid: "d".repeat(40),
    };
    let mut cached = observed.clone();
    cached.result["observation"]["changes"] = json!([]);
    cached.result["tracking"] = json!({"state":"complete","remote":"origin","mergeRef":"refs/heads/main", "localRef":"refs/remotes/origin/main",
        "head":"d".repeat(40),"ahead":0,"behind":1});
    assert!(selected(&cached, &ff));
    assert!(!selected(&branches, &ff));
    assert!(!selected(&observed, &ff));
    for (key, value) in [
        ("head", json!("e".repeat(40))),
        ("localRef", json!("refs/remotes/other/main")),
        ("ahead", json!(1)),
        ("behind", json!(0)),
        ("state", json!("shallow")),
    ] {
        let mut bad = cached.clone();
        bad.result["tracking"][key] = value;
        assert!(!selected(&bad, &ff));
    }
}

#[test]
fn fixed_native_action_and_original_review_summary_keep_source_identity_and_init_absence_distinct()
{
    let doc = Arc::new(());
    let mut actions = vec![
        repository::Action::Initialize {},
        branch_action("branch-create"),
        branch_action("branch-switch"),
        branch_action("branch-rename"),
    ];
    actions.push(repository::Action::FastForward {
        expected_revision: "a".repeat(64),
        expected_reference_revision: "c".repeat(64),
        target_ref: "refs/remotes/origin/main".into(),
        target_oid: "d".repeat(40),
    });
    for selected in actions {
        let native = native::action(&selected).unwrap();
        assert!(native.valid());
        assert_eq!(
            serde_json::to_value(native).unwrap(),
            serde_json::to_value(selected).unwrap()
        );
    }
    for init in [false, true] {
        let selected = if init {
            repository::Action::Initialize {}
        } else {
            branch_action("branch-create")
        };
        let scope = scope(&doc, selected);
        // Native public review DATA is decoded only for testing this mapper.
        // No original Gate, ReadyReview or SourceBook is made by this test.
        let review: local::Review = if init {
            serde_json::from_value(
                json!({"action":"initialize","expectedRevision":"a".repeat(64),
                "initialBranch":"main","objectFormat":"sha1","reviewDigest":"f".repeat(64)}),
            )
            .unwrap()
        } else {
            serde_json::from_value(json!({"action":"branch-create","name":"next","targetRef":"refs/heads/next",
                "expectedRevision":"a".repeat(64),"expectedReferenceRevision":"c".repeat(64),"head":"b".repeat(40),
                "branch":"refs/heads/main","expectedIndex":"e".repeat(64),"reviewDigest":"f".repeat(64)})).unwrap()
        };
        let summary = native::review(&scope, &review, "git-local-1-review".into(), 1, 1).unwrap();
        let shared::Reviewed::Repository(summary) = summary else {
            panic!("wrong review family")
        };
        assert_eq!(summary.expected_index.is_none(), init);
        assert_eq!(summary.reference_revision.is_none(), init);
        assert!(native::review(&scope, &review, "git-local-1-review".into(), 2, 1).is_none());
        assert!(native::review(&scope, &review, "git-local-1-review".into(), 1, 2).is_none());
        let mut bad = serde_json::to_value(&review).unwrap();
        bad["reviewDigest"] = json!("not-a-digest");
        let bad: local::Review = serde_json::from_value(bad).unwrap();
        assert!(native::review(&scope, &bad, "git-local-1-review".into(), 1, 1).is_none());
    }
}

#[test]
fn dormant_status_or_foreign_window_cannot_initialize_host_read_or_git() {
    let bridge = Arc::new(DesktopBridge::new(std::path::PathBuf::from(
        "/inert/git-repository-never-opened",
    )));
    let doc = DocumentBinding::new(bridge.clone());
    assert!(!doc.agent_git_repository_access(MAIN).unwrap().enabled);
    assert!(doc.agent_git_repository_access("foreign").is_err());
    assert!(!doc.revoke_agent_git_repository(MAIN).unwrap().enabled);
    let args = decode_repository_allow(&serde_json::to_vec(&json!({"projectId":"project-1", "expectedDocumentRevision":1,
        "readOperationId":null,"action":{"kind":"initialize"},"consentVersion":repository::CONSENT})).unwrap()).unwrap();
    assert!(doc.allow_agent_git_repository("foreign", args).is_err());
    doc.service_git_index_tick(Path::new("/inert/no-io"));
    doc.drain_git_index_for_exit();
    assert!(!bridge.application_service.status().unwrap().enabled);
}
