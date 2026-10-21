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
