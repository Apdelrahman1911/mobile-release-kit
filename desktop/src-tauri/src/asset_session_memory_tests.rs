//! Real in-memory Document census; no runtime, filesystem, credential or
//! provider operation. Native quote checks below are DATA, not native execution.
use super::*;
use crate::macos_history_inventory as history;

#[test]
fn actual_document_and_retained_capacity_obey_shared_admission() {
    let bridge=Arc::new(DesktopBridge::new("/never-opened-shared-memory-data".into()));
    let document=DocumentBinding::new(bridge.clone());
    bridge.edits.initial_document("main").unwrap();
    let mut state=document.lock();
    let base=lookup_memory::retained_document_bytes(&document.inner,&state).unwrap();
    let code=history::CODE_CONTROL_RESERVE;
    eprintln!("shared DATA census: document={base}; shared={SESSION_BYTES}; code={code}");
    assert_eq!(history::SHARED_DATA_LIMIT,SESSION_BYTES);
    assert!(base>0 && base<SESSION_BYTES);
    // Test the complete permitted writer, not a fabricated zero-byte owner.
    let writer=16*1024*1024;
    assert_eq!(history::admission_bytes(base,code+writer),Some(base+code+writer));
    assert_eq!(crate::git_local_protocol::admission_bytes(base,code+writer),Some(base+code+writer));
    for (name,remote,admit) in [
        ("fetch",crate::git_local_protocol::fetch_worker::REMOTE_BACKING,
            crate::git_local_protocol::fetch_worker::admission_bytes as fn(usize,usize)->Option<usize>),
        ("push",crate::git_local_protocol::push_worker::REMOTE_BACKING,
            crate::git_local_protocol::push_worker::admission_bytes as fn(usize,usize)->Option<usize>),
    ] {
        assert_eq!(admit(base,code+writer+remote),Some(base+code+writer+remote),"{name}");
    }
    let execute=crate::saved_command_owner::store_execute_document_backing_bytes().unwrap();
    let noncode=base.checked_add(execute).unwrap();
    assert!(noncode<=SESSION_BYTES);
    assert_eq!(lookup_memory::execute_remaining_from_admitted_total(code+noncode,64),
        Some(96*1024*1024-noncode-64));

    // Charge a genuinely retained selected buffer, not a made-up census total.
    let observation=credential_format::inspect(credential_format::FileKind::AndroidKeystore,
        &[],&mut||false).ok().expect("inert empty observation");
    state.records.push(Record{key:RecordKey{id:Token("inert-shared-memory".into()),revision:1},
        payload:Arc::new(Payload{kind:Kind::AndroidKeystore,fields:None,
            material:Some(Arc::new(Material{origin:MaterialOrigin::Selected(
                asset_source::CapturedSource::memory_data(Vec::with_capacity(SESSION_BYTES))),observation}))}),
        mutation_pending:false});
    let larger=lookup_memory::retained_document_bytes(&document.inner,&state).unwrap();
    assert!(larger>=base+SESSION_BYTES);
    assert!(history::admission_bytes(larger,code).is_none());
    assert!(crate::git_local_protocol::admission_bytes(larger,code+writer).is_none());
    state.retiring=true;
    assert!(lookup_memory::retained_document_bytes(&document.inner,&state).is_err());
}

#[test]
fn actual_document_plus_apple_future_fits_original_session_limit() {
    use crate::apple_provisioning_protocol::Mode;
    use crate::saved_command_owner::apple_provisioning_document_backing_bytes as future_for;
    let bridge=Arc::new(DesktopBridge::new("/never-opened-apple-memory-data".into()));
    let document=DocumentBinding::new(bridge.clone());
    bridge.edits.initial_document("main").unwrap();
    let mut state=document.lock();
    let base=lookup_memory::retained_document_bytes(&document.inner,&state).unwrap();
    assert!(state.records.is_empty());
    for (id,kind,file_kind) in [
        ("inert-apple-p8",Kind::AscP8,credential_format::FileKind::AscP8),
        ("inert-apple-p12",Kind::AppleP12,credential_format::FileKind::AppleP12),
    ] {
        // Real, distinct retained payloads and format observations; empty
        // census DATA is not a usable credential, BoundLoan or native receipt.
        let observation=credential_format::inspect(file_kind,&[],&mut||false)
            .ok().expect("inert empty observation");
        state.records.push(Record{key:RecordKey{id:Token(id.into()),revision:1},
            payload:Arc::new(Payload{kind,fields:None,material:Some(Arc::new(Material{
                origin:MaterialOrigin::Selected(asset_source::CapturedSource::memory_data(Vec::new())),
                observation}))}),mutation_pending:false});
    }
    assert!(!Arc::ptr_eq(&state.records[0].payload,&state.records[1].payload));
    let retained=lookup_memory::retained_document_bytes(&document.inner,&state).unwrap();
    assert!(retained>=base+2*RECORD_METADATA_BYTES);
    let future=future_for(Mode::ProfileReview).unwrap();
    let minimum=retained.checked_add(future).unwrap();
    eprintln!("Apple DATA census: empty={base}; with P8/P12={retained}; profile future={future}; minimum={minimum}; cap={SESSION_BYTES}");
    for mode in [Mode::ProfileReview,Mode::ProfileReuse,Mode::ProfileCreate,Mode::ProfileReconcile] {
        assert_eq!(future_for(mode),Some(future));
        assert!(retained.checked_add(future_for(mode).unwrap()).unwrap()<SESSION_BYTES,"{mode:?}");
    }
    // Reconstruct the old exclusive-parent double charge using actual helper
    // quotes. This exact two-payload Document could not admit that old quote.
    let common=future_for(Mode::Review).unwrap();
    let extra_key=[Mode::KeyPrepare,Mode::CertificateCreate,Mode::P12Save].into_iter()
        .map(|mode|future_for(mode).unwrap().checked_sub(common).unwrap()).max().unwrap();
    let old_minimum=minimum.checked_add(extra_key).unwrap();
    eprintln!("Apple DATA old exclusive-parent double charge: minimum={old_minimum}; cap={SESSION_BYTES}");
    assert!(old_minimum>SESSION_BYTES);
    assert!(retained.checked_add(usize::MAX).is_none());
    // Necessary, not sufficient: actual material/Ready/loan charges still run
    // at the production gate. Retained capacity is never free credit.
    let grow_by=SESSION_BYTES.checked_sub(minimum).unwrap()+1;
    let payload=Arc::get_mut(&mut state.records[1].payload).unwrap();
    let material=Arc::get_mut(payload.material.as_mut().unwrap()).unwrap();
    let MaterialOrigin::Selected(source)=&mut material.origin else { panic!("inert selected source") };
    source.bytes.reserve_exact(grow_by);
    let larger=lookup_memory::retained_document_bytes(&document.inner,&state).unwrap();
    assert!(larger>=retained+grow_by);
    assert!(larger.checked_add(future).unwrap()>SESSION_BYTES);
    state.retiring=true;
    assert!(matches!(lookup_memory::retained_document_bytes(&document.inner,&state),
        Err(lookup_memory::Problem::CleanupUnknown)));
}

#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
#[test]
fn actual_mac_native_quotes_fit_current_document_before_any_runtime_is_opened() {
    let bridge=Arc::new(DesktopBridge::new("/never-opened-mac-quotes".into()));
    let document=DocumentBinding::new(bridge.clone());
    bridge.edits.initial_document("main").unwrap();
    let state=document.lock();
    let base=lookup_memory::retained_document_bytes(&document.inner,&state).unwrap();
    for (name,future) in [
        ("history",crate::installed_runtime::GitHubHistoryRuntimeSlots::working_reservation_bytes()),
        ("auth",crate::installed_runtime::GitHubAuthRuntimeSlots::working_reservation_bytes()),
        ("read",crate::installed_runtime::GitReadRuntimeSlots::working_reservation_bytes()),
    ] {
        let future=future.expect("native quote");
        eprintln!("Mac DATA quote: kind={name}; document={base}; future={future}");
        assert!(lookup_memory::history_admission_bytes(&document.inner,&state,future).is_ok(),"{name}");
    }
    let writer=crate::installed_runtime::GitLocalRuntimeSlots::working_reservation_bytes().unwrap();
    eprintln!("Mac DATA quote: kind=writer; document={base}; future={writer}");
    assert!(lookup_memory::git_local_admission_bytes(&document.inner,&state,writer).is_ok());
    for (kind,remote) in [
        (crate::git_local_protocol::Kind::Fetch,crate::git_local_protocol::fetch_worker::REMOTE_BACKING),
        (crate::git_local_protocol::Kind::Push,crate::git_local_protocol::push_worker::REMOTE_BACKING),
    ] {
        assert!(lookup_memory::git_local_admission_bytes_for(&document.inner,&state,writer+remote,kind).is_ok());
    }
}
