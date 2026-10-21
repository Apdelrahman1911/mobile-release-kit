//! SAME actual empty Document census. Extra selected buffers are DATA only,
//! with no current source witness, vault/key/credential or operation admission.
use super::*;
#[test]
fn default_document_fits_cleanup_but_real_retained_buffers_refuse_without_quota_change() {
    let bridge = Arc::new(DesktopBridge::new(std::path::PathBuf::from(
        "/never-opened-cleanup-data",
    )));
    let document = DocumentBinding::new(bridge.clone());
    bridge.edits.initial_document("main").unwrap();
    let mut state = document.lock();
    let base = lookup_memory::retained_document_bytes(&document.inner, &state).unwrap();
    let admitted = p::admission_bytes(base);
    eprintln!("cleanup DATA census: emptyDoc={base}; admitted={admitted:?}; cap={SESSION_BYTES}");
    assert_eq!(p::SESSION_LIMIT, SESSION_BYTES);
    assert!(
        admitted.is_some(),
        "unchanged default Document must fit the closed cleanup quote"
    );
    for n in 0..2 {
        let observation = crate::credential_format::inspect(
            crate::credential_format::FileKind::AndroidKeystore,
            &[],
            &mut || false,
        )
        .ok()
        .expect("inert empty observation");
        let material = Material {
            origin: MaterialOrigin::Selected(asset_source::CapturedSource::memory_data(
                Vec::with_capacity(8 * 1024 * 1024),
            )),
            observation,
        };
        state.records.push(Record {
            key: RecordKey {
                id: Token(format!("inert-cleanup-record-{n}")),
                revision: 1,
            },
            payload: Arc::new(Payload {
                kind: Kind::AndroidKeystore,
                material: Some(Arc::new(material)),
                fields: None,
            }),
            mutation_pending: false,
        });
    }
    let larger = lookup_memory::retained_document_bytes(&document.inner, &state).unwrap();
    assert!(larger >= base + 18 * 1024 * 1024);
    assert!(p::admission_bytes(larger).is_none());
    // Unknown retirement is not an opportunity to subtract any original bytes.
    state.retiring = true;
    assert!(lookup_memory::retained_document_bytes(&document.inner, &state).is_err());
}
