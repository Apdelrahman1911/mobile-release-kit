//! Actual retained objects and the SAME live census. No source handle, native
//! admission/NEW, credential, returned task or successful state use is made.
use super::*;
use crate::apple_provisioning_protocol::Mode;
use crate::application_service_host::NativeStateReady;
use crate::asset_session::AppleProvisioningDocumentInput as Input;

fn document() -> (Arc<DesktopBridge>, DocumentBinding) {
    let bridge = Arc::new(DesktopBridge::new(
        "/never-opened-apple-retained-memory".into(),
    ));
    let document = DocumentBinding::new(bridge.clone());
    bridge.edits.initial_document("main").unwrap();
    (bridge, document)
}

fn input(
    mode: Mode,
    ready: Arc<NativeStateReady>,
    original: Option<Arc<OriginalWork>>,
) -> Arc<Input> {
    let context = Input::census_context(mode);
    let material =
        SelectedStoreMaterial::apple_census_data(&context, 524_288, 16 * 1024, 4 * 1024 * 1024);
    Input::census_data(context, material, ready, original)
}

#[test]
fn retained_review_material_is_counted_after_current_document_replacement() {
    let (bridge, document) = document();
    let mut state = document.lock();
    let empty = retained_document_bytes(&document.inner, &state).unwrap();
    let old = input(
        Mode::Review,
        NativeStateReady::closed_apple_census_data(),
        None,
    );
    bridge
        .apple_provisioning
        .retain_apple_census_review_data(&old);
    let retained = retained_document_bytes(&document.inner, &state).unwrap();
    assert!(retained >= empty + 524_288 + 16 * 1024 + 4 * 1024 * 1024 + 2 * RECORD_METADATA_BYTES);

    // The old material is now reachable only through the actual saved review;
    // replacing/clearing current selection cannot turn it into free capacity.
    let context = Input::census_context(Mode::Review);
    let replacement = SelectedStoreMaterial::apple_census_data(&context, 32, 32, 0);
    let (native, payload) = replacement.census_parts();
    state.context = Some(native.clone());
    state.records.push(Record {
        key: RecordKey {
            id: Token("current-only".into()),
            revision: 1,
        },
        payload: payload.clone(),
        mutation_pending: false,
    });
    let with_current = retained_document_bytes(&document.inner, &state).unwrap();
    assert!(with_current > retained);
    state.context = None;
    state.records = Vec::new();
    assert_eq!(
        retained_document_bytes(&document.inner, &state).unwrap(),
        retained
    );

    // Lossless overbound test: actual extra retained allocation, not a forged
    // census number, and no discarded old review to fit the shared limit.
    // Use the ordinary in-memory Payload shape for a distinct overbound source.
    let observation =
        credential_format::inspect(credential_format::FileKind::AscP8, &[], &mut || false)
            .ok()
            .expect("inert empty observation");
    let payload = Arc::new(Payload {
        kind: Kind::AscP8,
        fields: None,
        material: Some(Arc::new(Material {
            origin: MaterialOrigin::Selected(asset_source::CapturedSource::memory_data(
                Vec::with_capacity(SESSION_BYTES),
            )),
            observation,
        })),
    });
    state.records.push(Record {
        key: RecordKey {
            id: Token("overbound-only".into()),
            revision: 1,
        },
        payload,
        mutation_pending: false,
    });
    let overbound = retained_document_bytes(&document.inner, &state).unwrap();
    assert!(overbound >= retained + SESSION_BYTES);
    assert!(matches!(
        store_admission_bytes(&document.inner, &state, old.material(), 0),
        Err(Problem::Capacity)
    ));
    assert!(old.current().is_err() && old.ready().begin_use().is_err());
}

#[test]
fn same_ready_context_payloads_and_distinct_material_wrapper_are_deduplicated() {
    let (bridge, document) = document();
    let mut state = document.lock();
    let ready = NativeStateReady::closed_apple_census_data();
    let original = input(Mode::Review, ready.clone(), None);
    bridge
        .apple_provisioning
        .retain_apple_census_review_data(&original);
    let once = retained_document_bytes(&document.inner, &state).unwrap();
    state.apple_provisioning_ready = Some(ready.clone());
    assert_eq!(
        retained_document_bytes(&document.inner, &state).unwrap(),
        once
    );
    let other = NativeStateReady::closed_apple_census_data();
    state.apple_provisioning_ready = Some(other.clone());
    assert_eq!(
        retained_document_bytes(&document.inner, &state).unwrap(),
        once + native_state_ready_bytes(&other).unwrap()
    );

    let current = OriginalWork::new(1, false, Weak::new());
    let source = SourceBook::new();
    let retirement = Retirement::default();
    let mut census = Census::new(&current, &source, &retirement);
    census.current = None;
    let material = original.material();
    census.selected_store_material(material).unwrap();
    let bytes = census.bytes;
    census.selected_store_material(material).unwrap();
    let (context, payload) = material.census_parts();
    census.context(context).unwrap();
    census.payload(payload).unwrap();
    for (_, payload) in material.supplemental_census() {
        census.payload(payload).unwrap();
    }
    assert_eq!(census.bytes, bytes);
    let alias = material.apple_census_alias();
    census.selected_store_material(&alias).unwrap();
    assert_eq!(
        census.bytes,
        bytes
            + std::mem::size_of::<SelectedStoreMaterial>()
            + ARC_CELLS
            + alias.own_retained_heap_bytes().unwrap()
    );
    assert!(
        original.current().is_err() && ready.begin_use().is_err() && other.begin_use().is_err()
    );
}

#[test]
fn active_same_original_live_and_pending_census_keep_borrowed_source_and_retirement() {
    for mode in [
        Mode::ProfileReview,
        Mode::KeyReview,
        Mode::KeyRecover,
        Mode::CertificateReview,
        Mode::P12Review,
    ] {
        let (bridge, document) = document();
        let mut state = document.lock();
        let original = OriginalWork::new(1, false, Arc::downgrade(&document.inner));
        *original.source.lock().unwrap() = SourceBook::unstarted_backing_data();
        let selected = input(
            mode,
            NativeStateReady::closed_apple_census_data(),
            Some(original.clone()),
        );
        bridge
            .apple_provisioning
            .install_apple_census_active_data(selected.clone(), &original);
        state.slot = Some(Slot::new(
            original.clone(),
            Operation::Prepare,
            None,
            None,
            None,
        ));

        // These are the original guards supplied at real live NEW/allowance
        // callbacks. Re-locking either inside traversal would refuse here.
        let source = original.source.lock().unwrap();
        let retirement = original.retirement.lock().unwrap();
        let live = live_bytes(&state, &original, &source, &retirement).unwrap();
        assert!(source.not_started());
        assert!(live >= 524_288 + 16 * 1024 + 4 * 1024 * 1024 + source.retained_bytes().unwrap());
        let mut census = Census::new(&original, &source, &retirement);
        census.artifact_document(&document.inner).unwrap();
        census.document(&state).unwrap();
        assert_eq!(census.bytes, live);
        let once = census.bytes;
        census.owner(&original).unwrap();
        census.selected_store_material(selected.material()).unwrap();
        census.apple_state_ready(selected.ready()).unwrap();
        assert_eq!(census.bytes, once);
        census.slot(state.slot.as_ref().unwrap()).unwrap();
        let pending = census.bytes; // Preserve the old pending slot's extra quote.
        assert!(pending > live);
        let vault = original.vault.lock().unwrap();
        assert!(live_bytes(&state, &original, &source, &retirement).is_err());
        drop(vault);
        assert_eq!(
            live_bytes(&state, &original, &source, &retirement).unwrap(),
            live
        );
        drop((retirement, source));
        assert_eq!(
            pending_slot_bytes(&state, state.slot.as_ref().unwrap()).unwrap(),
            pending
        );

        // This refusal applies only to another NEW admission. It does not
        // withdraw/expire/poison this original or synthesize its finality.
        assert!(matches!(
            retained_document_bytes(&document.inner, &state),
            Err(Problem::Unavailable)
        ));
        let foreign = OriginalWork::new(1, false, Arc::downgrade(&document.inner));
        let source = foreign.source.lock().unwrap();
        let retirement = foreign.retirement.lock().unwrap();
        assert!(live_bytes(&state, &foreign, &source, &retirement).is_err());
        assert!(!state.unknown && !state.stopping && !original.stop.load(Ordering::SeqCst));
        assert!(matches!(
            original.coordinator.lock().unwrap().receipt,
            JoinReceipt::New
        ));
        assert!(selected.current().is_err() && selected.ready().begin_use().is_err());
    }
}

#[test]
fn old_review_original_without_return_is_refused_not_credited() {
    let (bridge, document) = document();
    let state = document.lock();
    let original = OriginalWork::new(1, false, Arc::downgrade(&document.inner));
    let selected = input(
        Mode::KeyRecover,
        NativeStateReady::closed_apple_census_data(),
        Some(original.clone()),
    );
    bridge
        .apple_provisioning
        .retain_apple_census_review_data(&selected);
    assert!(matches!(
        retained_document_bytes(&document.inner, &state),
        Err(Problem::CleanupUnknown)
    ));
    assert!(matches!(
        original.coordinator.lock().unwrap().receipt,
        JoinReceipt::New
    ));
    assert!(!state.unknown && !original.stop.load(Ordering::SeqCst));
    assert!(selected.current().is_err() && selected.ready().begin_use().is_err());
}
