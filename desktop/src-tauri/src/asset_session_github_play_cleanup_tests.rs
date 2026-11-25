//! SAME actual empty Document census. Extra selected buffers are DATA only,
//! with no current source witness, vault/key/credential or operation admission.
use super::*;
#[test]
fn actual_document_growth_preserves_separate_cleanup_and_document_limits() {
    let bridge = Arc::new(DesktopBridge::new(std::path::PathBuf::from(
        "/never-opened-cleanup-data",
    )));
    let document = DocumentBinding::new(bridge.clone());
    bridge.edits.initial_document("main").unwrap();
    let mut state = document.lock();
    let base = lookup_memory::retained_document_bytes(&document.inner, &state).unwrap();
    let admitted = p::admission_bytes(base);
    let work = 40 * 1024 * 1024;
    eprintln!("cleanup DATA census: emptyDoc={base}; admitted={admitted:?}; documentCap={SESSION_BYTES}; combinedCap={}", p::SESSION_LIMIT);
    assert_eq!(p::DOCUMENT_LIMIT, SESSION_BYTES);
    assert_eq!(p::SESSION_LIMIT, SESSION_BYTES + work);
    assert_eq!(admitted, Some(base + work));
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
    assert!(larger < SESSION_BYTES);
    assert_eq!(p::admission_bytes(larger), Some(larger + work));
    // Actual retained capacity beyond the shared Document's own ceiling is
    // refused even though the cleanup partition has its separate reservation.
    let growth = SESSION_BYTES.checked_sub(larger).unwrap() + 1;
    let payload = Arc::get_mut(&mut state.records[1].payload).unwrap();
    let material = Arc::get_mut(payload.material.as_mut().unwrap()).unwrap();
    let MaterialOrigin::Selected(source) = &mut material.origin else {
        panic!("inert selected source")
    };
    assert!(source.bytes.is_empty());
    source.bytes.reserve_exact(source.bytes.capacity().checked_add(growth).unwrap());
    let too_large = lookup_memory::retained_document_bytes(&document.inner, &state).unwrap();
    assert!(too_large >= larger + growth);
    assert!(too_large > SESSION_BYTES);
    assert!(p::admission_bytes(too_large).is_none());
    // Unknown retirement is not an opportunity to subtract any original bytes.
    state.retiring = true;
    assert!(lookup_memory::retained_document_bytes(&document.inner, &state).is_err());
}
