use super::*;
use sha2::Digest;
fn projection() -> EditProjection {
    EditProjection {
        domain: EditDomain::ProjectInitialization,
        project_id: "init-project".into(),
        session_id: "1".repeat(32),
        owner_generation: "2".repeat(32),
        phase: Phase::Reviewing,
        review_remaining_ms: 0,
        checkout: None,
        prepared: None,
        recovery: None,
        workflow: None,
        metadata_text: None,
        release_version: None,
        metadata_images: None,
        identity: None,
        initialization: Some(n::Details::new(n::Intent::Initialize, (7, 3))),
        apply_submitted: false,
        core_outcome: None,
        native_reason: Reason::None,
        native_finality: NativeFinality::Pending,
        late_settled: false,
    }
}
fn prepared_view() -> n::InitializationView {
    let mut v = n::tests::view();
    for index in 6..256 {
        v.files.push(n::FileView {
            index,
            kind: n::Kind::Metadata,
            path: format!("metadata/{index:03}.txt"),
            action: n::Action::Create,
            before_bytes: None,
            after_bytes: 0,
        });
    }
    v.directory_count = 4;
    v.create_directories = vec![
        ".github".into(),
        "metadata".into(),
        "release".into(),
        ".github/workflows".into(),
    ];
    for (index, w) in v.workflows.iter_mut().enumerate() {
        w.content = "x".repeat(16 * 1024);
        w.byte_length = w.content.len() as u32;
        w.sha256 = format!("{:x}", sha2::Sha256::digest(w.content.as_bytes()));
        v.files[index + 2].after_bytes = w.byte_length;
    }
    assert!(v.valid());
    v
}
#[test]
fn initialization_quote_keeps_global_malformed_decode_and_three_frame_status_coexistence() {
    assert_eq!(PREVIEW_MAP_ENTRIES, 1444);
    assert_eq!(PREVIEW_ARRAY_ELEMENTS, 4288);
    assert!(DECODE >= crate::protocol::NODE_LIMIT * 512 + 7 * n::RESPONSE_LIMIT);
    assert!(DECODE >= crate::protocol::NODE_LIMIT * (512 + 128) + 4 * n::RESPONSE_LIMIT);
    assert!(FUTURE >= 3 * REPRESENTATION + DECODE + 6 * ACTIVE_STATUS_WIRE + CONTROL);
    assert!(
        FUTURE
            >= 4 * REPRESENTATION
                + 3 * n::VIEW_LIMIT
                + 3 * n::RESPONSE_LIMIT
                + 6 * ACTIVE_STATUS_WIRE
                + CONTROL
    );
    assert!(FUTURE >= OPEN_INPUT + CONTROL);
    let mut p = projection();
    let d = p.initialization.as_mut().unwrap();
    assert!(d.accept_opened(n::Opened::Initialize {
        revision: "3".repeat(32),
        observed: n::Observed {
            schema_version: 1,
            file_count: 256,
            directory_count: 4
        },
        scope_resources: ResourceState::Settled
    }));
    let frame = ChildFrame::InitializationPrepared(n::PreparedReply::Initialize {
        revision: "3".repeat(32),
        plan_token: "4".repeat(32),
        view: prepared_view(),
        scope_resources: ResourceState::Settled,
    });
    prospective(&p, &frame).unwrap();
    if let ChildFrame::InitializationPrepared(v) = frame {
        assert!(p.initialization.as_mut().unwrap().accept_prepared(v));
    }
    let actual = super::projection(&p).unwrap();
    assert!(actual < REPRESENTATION);
    eprintln!("Init typed representation={REPRESENTATION} maximum inventory fixture={actual} decoder={DECODE} future={FUTURE}");
}
#[test]
fn original_last_recovery_and_failed_capacity_are_not_erased_to_admit_initialization() {
    let owner = EditOwner::new(RuntimeConfig::packaged(PathBuf::from(
        "/never-opened-init-retained",
    )));
    let empty = owner.initialization_agent_edit_backing().unwrap();
    let mut old = projection();
    old.phase = Phase::Unknown;
    old.native_finality = NativeFinality::Unknown;
    old.initialization = Some(n::tests::detail(n::RecoveryAction::CommittedCleanup));
    let wire = last_status_wire(&old).unwrap();
    assert_eq!(wire, 2 * n::VIEW_LIMIT + 16 * 1024);
    let actual = super::projection(&old).unwrap();
    owner.inner.lock().last = Some(old);
    assert!(owner.initialization_agent_edit_backing().unwrap() >= empty + 3 * actual + 6 * wire);
    let mut registry = owner.inner.lock();
    let saved = registry.last.as_mut().unwrap();
    saved.project_id = String::with_capacity(SESSION_MEMORY_LIMIT);
    saved.project_id.push_str("init-project");
    let pointer = saved.project_id.as_ptr();
    let capacity = saved.project_id.capacity();
    drop(registry);
    assert!(owner.initialization_agent_edit_backing().is_err());
    let registry = owner.inner.lock();
    assert_eq!(registry.last.as_ref().unwrap().project_id.as_ptr(), pointer);
    assert_eq!(
        registry.last.as_ref().unwrap().project_id.capacity(),
        capacity
    );
}
// Real capacity is used above, not a fake byte total or assumed target layout.
const SESSION_MEMORY_LIMIT: usize = 64 * 1024 * 1024;
