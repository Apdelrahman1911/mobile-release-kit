//! Closed decoder DATA only. No Document, grant, native operation or IPC.
use super::*;

#[test]
fn fixed_main_decoder_accepts_only_the_original_closed_three_selections() {
    for kind in [
        p::Kind::RepositoryCreate,
        p::Kind::DraftPrCreate,
        p::Kind::PrCreate,
        p::Kind::FailedJobsRetry,
    ] {
        let value = serde_json::json!({"selection": {
            "kind":kind, "sessionId":"github-connection-1", "consentId":"a".repeat(32),
            "expectedRevision":7}, "consentVersion":kind.consent(), "expectedPermissionRevision":"0"});
        let bytes = serde_json::to_vec(&value).unwrap();
        let decoded: Allow = decode(&bytes).unwrap();
        assert_eq!(decoded.selection.kind(), kind);
        assert_eq!(decoded.selection.prepared().unwrap().expected_revision, 7);
        assert_eq!(decoded.consent_version, kind.consent());
        for suffix in [" {}", " null"] {
            let mut trailing = bytes.clone();
            trailing.extend_from_slice(suffix.as_bytes());
            assert!(decode::<Allow>(&trailing).is_err());
        }
        let mut extra = value;
        extra["selection"]["url"] = serde_json::json!("https://example.invalid/private");
        assert!(decode::<Allow>(&serde_json::to_vec(&extra).unwrap()).is_err());
    }
    assert!(decode::<Allow>(br#"{"selection":{"kind":"repository-create","kind":"draft-pr-create"},"consentVersion":"x"}"#).is_err());
    assert!(decode::<Allow>(br#"{"selection":[],"consentVersion":"x"}"#).is_err());
    assert!(decode::<super::super::agent_identity::Empty>(b"{}").is_ok());
    assert!(
        decode::<super::super::agent_identity::Empty>(br#"{"unexpected":[{},{},{}]}"#).is_err()
    );
    let query = serde_json::json!({"projectId":"a".repeat(32),"serviceInstance":"b".repeat(32),"requestId":"c".repeat(32)});
    assert!(decode::<p::Query>(&serde_json::to_vec(&query).unwrap()).is_ok());
}

#[test]
fn request_byte_bound_precedes_typed_parse_without_a_generic_value_tree() {
    struct Never;
    impl<'de> serde::Deserialize<'de> for Never {
        fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
            panic!("overbound input must not invoke even the typed decoder")
        }
    }
    assert!(decode::<Never>(&[]).is_err());
    assert!(decode::<Never>(&vec![b' '; p::RAW_LIMIT + 1]).is_err());
    let mut boundary = b"{}".to_vec();
    boundary.resize(p::RAW_LIMIT, b' ');
    assert!(decode::<super::super::agent_identity::Empty>(&boundary).is_ok());
    boundary.push(b' ');
    assert!(decode::<super::super::agent_identity::Empty>(&boundary).is_err());
}

fn original_document() -> DocumentBinding {
    // Standard constructors, no runtime/source/Store is entered by these
    // counter-only methods; this is not an admitted permission fixture.
    DocumentBinding::new(Arc::new(DesktopBridge::new("/never-opened-gh-main-revision".into())))
}
fn activity_allow(revision: &str) -> Allow {
    decode(&serde_json::to_vec(&serde_json::json!({"selection":{"kind":"activity-overview",
        "sessionId":"session-a","expectedRevision":3,"expectedConnectionRevision":9},
        "consentVersion":"agent-activity-overview-once-v1","expectedPermissionRevision":revision})).unwrap()).unwrap()
}
#[test]
fn empty_main_revoke_invalidates_delayed_allow_before_first_off_document_cut() {
    let d = original_document();
    let first = d.agent_github_action_access(MAIN).unwrap();
    assert_eq!(first.permission_revision.0, 0);
    assert!(first.access.grant_id.is_none());
    let after = d.revoke_agent_github_action(MAIN).unwrap();
    assert_eq!(after.permission_revision.0, 1);
    assert_eq!(d.allow_agent_github_action(MAIN, activity_allow("0")).err().unwrap().code, "cli_access_changed");
    assert!(d.github_action_service().unwrap().is_none());
    assert!(!d.inner.agent_github_action_allow_pending.load(Ordering::Acquire));
    assert_eq!(d.agent_github_action_access(MAIN).unwrap().permission_revision.0, 1);
    // Ordinary Access neither consumes nor refreshes the observed generation.
    assert_eq!(d.agent_github_action_access(MAIN).unwrap().permission_revision.0, 1);
}
#[test]
fn main_revoke_and_relay_close_share_doc_epoch_and_exhaustion_never_wraps() {
    let d = original_document();
    let expected = p::activity::PermissionRevision(0);
    {
        let _s = d.lock();
        assert_eq!(expected.successor(d.inner.agent_github_action_revoke_epoch.load(Ordering::Acquire)), Some(1));
    }
    d.github_action_agent_relay_closed();
    {
        let _s = d.lock();
        assert_eq!(expected.successor(d.inner.agent_github_action_revoke_epoch.load(Ordering::Acquire)), None);
        d.inner.agent_github_action_revoke_epoch.store(u64::MAX, Ordering::Release);
    }
    assert_eq!(d.revoke_agent_github_action(MAIN).err().unwrap().code, "cli_access_unknown");
    d.github_action_agent_relay_closed();
    assert_eq!(d.agent_github_action_access(MAIN).unwrap().permission_revision.0, u64::MAX);
    assert_eq!(d.allow_agent_github_action(MAIN, activity_allow(&u64::MAX.to_string())).err().unwrap().code, "cli_access_changed");
    assert!(d.github_action_service().unwrap().is_none());
}
#[test]
fn main_expected_revision_is_mandatory_and_cannot_come_from_cli_status() {
    let valid = serde_json::to_value(serde_json::json!({"selection":{"kind":"activity-overview",
        "sessionId":"session-a","expectedRevision":3,"expectedConnectionRevision":9},
        "consentVersion":"agent-activity-overview-once-v1","expectedPermissionRevision":"0"})).unwrap();
    assert!(decode::<Allow>(&serde_json::to_vec(&valid).unwrap()).is_ok());
    for v in [serde_json::json!(0), serde_json::json!(null), serde_json::json!("01"), serde_json::json!("18446744073709551616")] {
        let mut bad = valid.clone(); bad["expectedPermissionRevision"] = v;
        assert!(decode::<Allow>(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    let mut absent = valid; absent.as_object_mut().unwrap().remove("expectedPermissionRevision");
    assert!(decode::<Allow>(&serde_json::to_vec(&absent).unwrap()).is_err());
}

#[test]
fn only_new_prepare_main_input_gets_four_kib_and_physical_capacity_is_bounded() {
    let value=serde_json::json!({"selection":{"kind":"release-prepare","sessionId":"session-a",
        "expectedRevision":1,"expectedConnectionRevision":2,"branch":"main","platform":"ios",
        "selection":{"stage":"candidate","candidateRunId":null,"externalRunId":null,
            "recoveryRunId":null,"originalSourceSha":null,"originalVersion":null}},
        "consentVersion":"agent-release-prepare-once-v1","expectedPermissionRevision":"0"});
    let mut bytes=serde_json::to_vec(&value).unwrap();bytes.resize(4096,b' ');
    assert!(decode_allow(&bytes).is_ok());assert!(decode::<Allow>(&bytes).is_err());
    bytes.push(b' ');assert!(decode_allow(&bytes).is_err());
    let old=serde_json::json!({"selection":{"kind":"repository-create","sessionId":"session-a",
        "expectedRevision":1,"consentId":"a".repeat(32)},"consentVersion":"agent-repository-create-once-v1",
        "expectedPermissionRevision":"0"});
    let mut bytes=serde_json::to_vec(&old).unwrap();bytes.resize(1024,b' ');assert!(decode_allow(&bytes).is_ok());
    bytes.push(b' ');assert!(decode_allow(&bytes).is_err());
    let mut args=decode_allow(&serde_json::to_vec(&value).unwrap()).unwrap();
    if let native::dispatch::Selection::ReleasePrepare(v)=&mut args.selection {v.branch.reserve_exact(4096);}
    assert!(!args.selection.retained_fits());
    assert!(decode_allow(br#"{"selection":{"kind":"release-prepare","kind":"preflight-prepare"}}"#).is_err());
}

#[test]
fn same_doc_permission_is_spent_before_actual_inbox_error_or_later_install_failure() {
    for after_install in [false,true] {
        let d=original_document();let at=Instant::now();let original=p::activity::PermissionRevision(0);
        let inbox=r::Inbox::new(Id::parse(&"2".repeat(32)).unwrap());
        let data=p::Review::PreflightPending(p::dispatch::RequestReference{session_id:"session-a".into(),expected_revision:3,request_sha256:"a".repeat(64)});
        let scope=r::NativeScope::new(Id::parse(&"1".repeat(32)).unwrap(),"project-1".into(),"/never-opened-install-order".into(),1,2,3,
            data,Arc::new(()),at+std::time::Duration::from_secs(60),
            Arc::new(crate::service_version_reserve_requests::ReadPermission::new(at+std::time::Duration::from_secs(70))),
            Arc::downgrade(&d.inner.session_identity),d.inner.changes.clone());
        if !after_install {inbox.close(at);}
        let state=d.lock();
        d.consume_github_action_permission_locked(&state,original,1).unwrap();
        let result=inbox.allow(scope.clone(),Id::parse(&"3".repeat(32)).unwrap());
        if after_install {assert!(result.is_ok());}else{assert!(result.is_err());}
        // Model the immediate next native-install/response error after the real
        // in-memory Inbox insertion. No native permission/finality is fabricated.
        scope.unused_closed();
        assert!(d.consume_github_action_permission_locked(&state,original,1).is_err());
        assert_eq!(d.inner.agent_github_action_revoke_epoch.load(Ordering::Acquire),1);
        drop(state);
        assert_eq!(d.agent_github_action_access(MAIN).unwrap().permission_revision.0,1);
        d.revoke_agent_github_action(MAIN).unwrap();
        assert_eq!(d.agent_github_action_access(MAIN).unwrap().permission_revision.0,2);
    }
}

#[test]
fn native_main_capture_abi_fits_same_named_phase_not_a_new_document_or_ipc_quote() {
    let actual=dispatch::main_call_bytes().unwrap();
    println!("GitHub dispatch native MAIN phase={actual} originalLimit={}",p::MAIN_CALL_BACKING);
    assert!(dispatch::main_call_fits(),"actual native MAIN={actual}");
    assert_eq!(p::MAIN_CALL_BACKING,48*1024);
    assert_eq!(r::retained_document_backing(),Some(p::DOCUMENT_BACKING));
    assert_eq!(p::DOCUMENT_BACKING,786432);
    assert_eq!(p::REQUEST_LIMIT,32);
    assert_eq!(p::IPC_WORKER_BACKING,32*1024);
}
