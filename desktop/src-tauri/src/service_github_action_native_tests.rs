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
            "expectedRevision":7}, "consentVersion":kind.consent()});
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
