//! Actual nonce/Doc census guards only. No Host, chooser, native or key access.
use super::*;
fn id(n: u8) -> Id {
    Id::parse(&format!("{n:032x}")).unwrap()
}
#[test]
fn apple_cli_revoke_before_first_allow_tombstones_only_that_nonce() {
    let mut state = State::default();
    state.withdraw(&id(1)).unwrap();
    assert!(state.reserve(&id(1)).is_err());
    assert!(!state.current(&id(1)));
    state.reserve(&id(2)).unwrap();
    assert!(state.current(&id(2)));
    state.withdraw(&id(1)).unwrap();
    assert!(state.current(&id(2)));
    assert!(state.reserve(&id(2)).is_err());
    state.withdraw(&id(2)).unwrap();
    assert!(!state.current(&id(2)));
}
#[test]
fn apple_cli_consent_book_never_reclaims_withdrawn_or_failed_ids() {
    let mut state = State::default();
    for n in 1..=32 {
        state.withdraw(&id(n)).unwrap();
    }
    assert!(state.reserve(&id(33)).is_err());
    assert!(state.withdraw(&id(33)).is_err());
    state.withdraw(&id(1)).unwrap();
    assert_eq!(state.nonces.len(), 32);
}
#[test]
fn apple_cli_uses_actual_default_document_plus_two_profile_payload_quotes() {
    let bridge = Arc::new(DesktopBridge::new("/never-opened-apple-cli-data".into()));
    let document = DocumentBinding::new(bridge.clone());
    bridge.edits.initial_document("main").unwrap();
    let mut state = document.lock();
    let base = lookup_memory::retained_document_bytes(&document.inner, &state).unwrap();
    for (id, kind, file_kind) in [
        ("inert-p8", Kind::AscP8, credential_format::FileKind::AscP8),
        (
            "inert-p12",
            Kind::AppleP12,
            credential_format::FileKind::AppleP12,
        ),
    ] {
        let observation = credential_format::inspect(file_kind, &[], &mut || false)
            .ok()
            .unwrap();
        state.records.push(Record {
            key: RecordKey {
                id: Token(id.into()),
                revision: 1,
            },
            payload: Arc::new(Payload {
                kind,
                fields: None,
                material: Some(Arc::new(Material {
                    origin: MaterialOrigin::Selected(asset_source::CapturedSource::memory_data(
                        Vec::new(),
                    )),
                    observation,
                })),
            }),
            mutation_pending: false,
        });
    }
    let retained = lookup_memory::retained_document_bytes(&document.inner, &state).unwrap();
    assert!(base >= p::DOCUMENT_BACKING);
    assert!(retained >= base + 2 * RECORD_METADATA_BYTES);
    for mode in [
        crate::apple_provisioning_protocol::Mode::ProfileReview,
        crate::apple_provisioning_protocol::Mode::KeyPrepare,
        crate::apple_provisioning_protocol::Mode::CertificateCreate,
        crate::apple_provisioning_protocol::Mode::P12Save,
    ] {
        let future =
            crate::saved_command_owner::apple_provisioning_document_backing_bytes(mode).unwrap();
        assert!(
            retained.checked_add(future).unwrap() < SESSION_BYTES,
            "{mode:?}"
        );
    }
    assert!(retained.checked_add(usize::MAX).is_none());
}
