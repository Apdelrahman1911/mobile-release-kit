//! Closed MAIN DATA and actual Document census only; no Source/Store/loan,
//! registered project, consent, ticket or native completion is fabricated.
use super::*;
#[test]
fn main_review_decoder_requires_exact_origin_and_nullable_status_selection() {
    let q = serde_json::json!({"projectId":"1".repeat(32),"serviceInstance":"2".repeat(32),"requestId":"3".repeat(32)});
    let v = serde_json::json!({"intent":"agent-version-reserve-review","origin":q});
    assert!(start_request(v.clone()).is_ok());
    for key in ["source", "projectId", "options", "permission", "nativeId"] {
        let mut bad = v.clone();
        bad[key] = serde_json::json!({});
        assert!(start_request(bad).is_err())
    }
    assert!(status_request(br#"{"origin":null}"#).unwrap().is_none());
    assert!(status_request(b"{}").is_err());
    assert!(
        status_request(&serde_json::to_vec(&serde_json::json!({"origin":q})).unwrap())
            .unwrap()
            .is_some()
    );
    assert!(status_request(br#"{"origin":null,"other":true}"#).is_err());
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[test]
fn actual_review_document_source_future_and_retained_payload_obey_original_cap() {
    let bridge = Arc::new(DesktopBridge::new("/never-opened-review-memory".into()));
    let document = DocumentBinding::new(bridge.clone());
    bridge.edits.initial_document("main").unwrap();
    let mut state = document.lock();
    let base = lookup_memory::retained_document_bytes(&document.inner, &state).unwrap();
    // Real separate P8 + service-account backing for the paired inventory
    // context. Empty observations are NOT usable material, loans or receipts.
    for (id, kind, file_kind) in [
        (
            "inert-review-p8",
            Kind::AscP8,
            credential_format::FileKind::AscP8,
        ),
        (
            "inert-review-sa",
            Kind::GoogleServiceAccount,
            credential_format::FileKind::GoogleServiceAccount,
        ),
    ] {
        let observation = credential_format::inspect(file_kind, &[], &mut || false)
            .unwrap_or_else(|_| panic!("inert credential observation interrupted"));
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
                        Vec::with_capacity(16 * 1024),
                    )),
                    observation,
                })),
            }),
            mutation_pending: false,
        });
    }
    assert!(!Arc::ptr_eq(
        &state.records[0].payload,
        &state.records[1].payload
    ));
    let retained = lookup_memory::retained_document_bytes(&document.inner, &state).unwrap();
    assert!(retained >= base + 2 * RECORD_METADATA_BYTES + 32 * 1024);
    let debit = lookup_memory::retained_document_bytes(&document.inner, &state)
        .unwrap()
        .checked_add(installation_memory::additional_document_bytes(&document, &state).unwrap())
        .unwrap();
    // Max supported comparison strings plus the actual SOURCE/Lane/Completion
    // quote. No fake RegisteredRoot is needed to check retained allocation.
    let input = std::mem::size_of::<crate::supervisor::VersionAllocationSourceInput>()
        + 64
        + 4096
        + 2 * 64
        + 512
        + 211;
    let future = version_allocation::source_quote(input).unwrap();
    eprintln!("Review DATA: Document={debit}; SOURCE={future}; original64MiB cap, separate code unchanged");
    assert!(crate::macos_history_inventory::admission_bytes(debit, future).is_some());
    assert!(version_allocation::source_quote(usize::MAX).is_none());
    let observation =
        credential_format::inspect(credential_format::FileKind::AscP8, &[], &mut || false)
            .unwrap_or_else(|_| panic!("inert credential observation interrupted"));
    state.records.push(Record {
        key: RecordKey {
            id: Token("overbound-review".into()),
            revision: 1,
        },
        payload: Arc::new(Payload {
            kind: Kind::AscP8,
            fields: None,
            material: Some(Arc::new(Material {
                origin: MaterialOrigin::Selected(asset_source::CapturedSource::memory_data(
                    Vec::with_capacity(SESSION_BYTES),
                )),
                observation,
            })),
        }),
        mutation_pending: false,
    });
    let over = lookup_memory::retained_document_bytes(&document.inner, &state).unwrap();
    assert!(crate::macos_history_inventory::admission_bytes(over, future).is_none());
    state.retiring = true;
    assert!(lookup_memory::retained_document_bytes(&document.inner, &state).is_err());
}
