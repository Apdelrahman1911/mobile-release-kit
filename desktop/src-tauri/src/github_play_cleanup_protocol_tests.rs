//! Closed DATA codec tests; not enrollment, protected-key or dispatch proof.
use super::*;
fn prepared() -> Prepared {
    let target = Target {
        scope: Scope {
            project_binding: "f".repeat(64),
            repository: "fixture/app".into(),
            account_id: "11".into(),
            repository_id: "22".into(),
        },
        tooling_repository: crate::github_release_protocol::TOOLING_REPOSITORY.into(),
        tooling_sha: "f".repeat(40),
        marker: "a".repeat(32),
    };
    let mut p = Prepared {
        target,
        account_login: "fixture".into(),
        branch: "main".into(),
        source_sha: "b".repeat(40),
        source_tree: "e".repeat(40),
        saved_config_sha256: "f".repeat(64),
        workflow_id: "33".into(),
        caller_sha256: "a".repeat(64),
        authority: Authority {
            project_id: "00000000-0000-4000-8000-000000000001".into(),
            repository: "fixture/app".into(),
            repository_id: "22".into(),
            ledger_id: "00000000-0000-4000-8000-000000000002".into(),
            genesis_sha256: "c".repeat(64),
            protected_branch: true,
        },
        checkpoint: Checkpoint {
            sequence: 0,
            head_sha256: "c".repeat(64),
            commit: "c".repeat(40),
        },
        ledger_blob: "d".repeat(40),
        journal_blob: "e".repeat(40),
        journal_sha256: "f".repeat(64),
        journal_revision: 1,
        candidate: Candidate {
            candidate_id: "00000000-0000-4000-8000-000000000003".into(),
            attempt_id: "00000000-0000-4000-8000-000000000004".into(),
            request_sha256: "a".repeat(64),
            local_project_id: "e".repeat(32),
            platform: Platform::Android,
            source: OriginalSource {
                commit: "a".repeat(40),
                tree: "d".repeat(40),
                source_ref: "refs/heads/main".into(),
                configuration_sha256: "b".repeat(64),
                version_sha256: "c".repeat(64),
            },
            identity_revision: "d".repeat(64),
            base_version: Version {
                name: "1.0.0".into(),
                build: 1,
            },
            capsule_sha256: "e".repeat(64),
        },
        confirmation: String::new(),
    };
    p.confirmation = p.confirmation();
    assert!(p.valid());
    p
}
fn request() -> Request {
    let p = prepared();
    Request {
        kind: Kind::Observe,
        target: p.target.clone(),
        source: None,
        home: Some("/inert-home".into()),
        prepared: Some(p),
    }
}
#[test]
fn advanced_dispatch_head_is_separate_from_original_source_and_alias_safe_once_key() {
    let p = prepared();
    assert_ne!(p.source_sha, p.candidate.source.commit);
    let mut alias = p.clone();
    alias.target.marker = "b".repeat(32);
    alias.target.scope.account_id = "12".into();
    alias.target.scope.project_binding = "1".repeat(64);
    alias.target.scope.repository = "FIXTURE/APP".into();
    alias.account_login = "another".into();
    alias.confirmation = alias.confirmation();
    assert!(alias.valid());
    assert_eq!(alias.once_key(), p.once_key());
    assert_ne!(alias.digest().unwrap(), p.digest().unwrap());
    let mut wrong = p.clone();
    wrong.candidate.source.source_ref = "refs/heads/other".into();
    assert!(!wrong.valid());
    let mut wrong = p.clone();
    wrong.authority.repository_id = "23".into();
    assert!(!wrong.valid());
    let raw = canonical(&p).unwrap();
    for v in ["editId", "ciphertextBase64", "keyVersion", "token", "runId"] {
        assert!(!std::str::from_utf8(&raw).unwrap().contains(v));
    }
    assert!(raw.len() <= PREPARED_LIMIT);
}
#[test]
fn acknowledgement_and_absent_later_journal_are_never_cleanup_success() {
    let r = request();
    assert!(r.valid());
    let control = serde_json::json!({"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false});
    let v = serde_json::json!({"effect":"observed-unconfirmed","reason":"none","claimed":true,"acknowledged":true,"observed":{"counterCommit":"c".repeat(40),"journalSha256":"d".repeat(64),"journalRevision":2,"pendingTuple":"not-present","assurance":"later-journal-read-not-cleanup-proof"},"control":control});
    let seen: Cleanup = serde_json::from_value(v.clone()).unwrap();
    assert!(seen.valid(&r));
    let mut bad = v;
    bad["effect"] = serde_json::json!("succeeded");
    assert!(serde_json::from_value::<Cleanup>(bad).is_err());
    let mut dispatch = r.clone();
    dispatch.kind = Kind::Dispatch;
    let ack:Cleanup=serde_json::from_value(serde_json::json!({"effect":"acknowledged-unconfirmed","reason":"source-changed","claimed":true,"acknowledged":true,"observed":null,"control":control})).unwrap();
    assert!(ack.valid(&dispatch));
    assert!(!ack.valid(&r));
}
#[test]
fn worker_refusal_has_exact_correlation_and_no_public_consent_or_private_field() {
    let r = request();
    let control = serde_json::json!({"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false});
    let value = serde_json::json!({"protocol":PROTOCOL,"id":"github-play-cleanup-1","result":{"schemaVersion":1,"kind":"observe","reason":"source-changed","prepared":null,"cleanup":{"effect":"unresolved","reason":"source-changed","claimed":true,"acknowledged":true,"observed":null,"control":control},"pending":null,"control":control}});
    let encode = |v: &Value| {
        let mut raw = serde_json::to_vec(v).unwrap();
        raw.push(b'\n');
        raw
    };
    let raw = encode(&value);
    assert!(decode_reply("github-play-cleanup-1", &raw, &r).is_ok());
    assert!(decode_reply("github-play-cleanup-2", &raw, &r).is_err());
    for key in ["token", "editId", "consentId"] {
        let mut bad = value.clone();
        bad["result"][key] = serde_json::json!("never-public");
        assert!(decode_reply("github-play-cleanup-1", &encode(&bad), &r).is_err());
    }
    let mut missing = value;
    missing["result"].as_object_mut().unwrap().remove("pending");
    assert!(decode_reply("github-play-cleanup-1", &encode(&missing), &r).is_err());
}
#[test]
fn explicit_closed_command_does_not_accept_desktop_release_markers_or_auto_confirm() {
    let args = serde_json::json!({"sessionId":"github-session-1","expectedRevision":2,"consentId":"a".repeat(32),"confirm":true});
    assert!(decode_command("github_play_cleanup_start", &args).is_ok());
    assert!(decode_command("github_play_cleanup_allow_agent", &args).is_ok());
    let mut bad = args.clone();
    bad["confirm"] = serde_json::json!(false);
    assert!(decode_command("github_play_cleanup_start", &bad).is_err());
    for key in ["platform", "attemptId", "ref", "desktopAttempt"] {
        let mut bad = args.clone();
        bad[key] = serde_json::json!("injected");
        assert!(decode_command("github_play_cleanup_start", &bad).is_err());
    }
    assert!(raw_input("github_play_cleanup_status", b"{\"x\":1,\"x\":2}").is_err());
}
#[test]
fn exact_fixed_allowances_preserve_separate_document_and_cleanup_bounds() {
    assert_eq!(
        crate::github_setup_protocol::SECRET_CONFIGURATION_WORK_BYTES,
        16 * 1024 * 1024
    );
    assert_eq!(REMOTE_WORK_BYTES, 16 * 1024 * 1024);
    assert_eq!(RETAINED_LIMIT, 8 * 1024 * 1024);
    assert_eq!(DOCUMENT_LIMIT, 64 * 1024 * 1024);
    assert_eq!(SESSION_LIMIT, 104 * 1024 * 1024);
    assert_eq!(admission_bytes(0), Some(40 * 1024 * 1024));
    assert_eq!(admission_bytes(DOCUMENT_LIMIT), Some(SESSION_LIMIT));
    assert!(admission_bytes(DOCUMENT_LIMIT + 1).is_none());
    assert!(admission_bytes(usize::MAX).is_none());
}
