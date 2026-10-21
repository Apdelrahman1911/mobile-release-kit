//! Inert borrowed capacity checks. No source/native owner is opened.
use super::*;
fn data() -> EditProjection {
    EditProjection {
        domain: EditDomain::MetadataText,
        workflow: None,
        metadata_text: None,
        release_version: None,
        metadata_images: None,
        initialization: None,
        identity: None,
        project_id: "p".into(),
        session_id: "s".into(),
        owner_generation: "g".into(),
        phase: Phase::Unknown,
        review_remaining_ms: 0,
        checkout: None,
        prepared: None,
        recovery: None,
        apply_submitted: false,
        core_outcome: None,
        native_reason: Reason::None,
        native_finality: NativeFinality::Pending,
        late_settled: false,
    }
}
fn submission(capacity: usize) -> t::Submission {
    t::Submission {
        expected_baseline: t::Baseline {
            config: t::ContentDigest {
                byte_length: 2,
                sha256: "a".repeat(64),
            },
            fields: Vec::new(),
        },
        fields: vec![t::TextField {
            id: t::FieldId::Title,
            text: String::with_capacity(capacity),
        }],
    }
}
#[test]
fn metadata_borrowed_census_keeps_original_other_domain_last_and_actual_capacity() {
    let owner = EditOwner::new(RuntimeConfig::packaged(PathBuf::from(
        "/never-opened-metadata-memory",
    )));
    let initial = owner.metadata_text_agent_edit_backing().unwrap();
    let mut old = data();
    old.domain = EditDomain::Configuration;
    let mut text = String::with_capacity(1024 * 1024);
    text.push('x');
    let pointer = text.as_ptr();
    let capacity = text.capacity();
    old.checkout = Some(c::Checkout {
        revision: "a".repeat(32),
        base: Value::String(text),
    });
    owner.inner.lock().last = Some(old);
    assert!(owner.metadata_text_agent_edit_backing().unwrap() >= initial + capacity);
    assert_eq!(
        owner
            .inner
            .lock()
            .last
            .as_ref()
            .unwrap()
            .checkout
            .as_ref()
            .unwrap()
            .base
            .as_str()
            .unwrap()
            .as_ptr(),
        pointer
    );
    assert!(METADATA_FUTURE > 6 * METADATA_REPRESENTATION + 2 * c::STATUS_LIMIT);
}
#[test]
fn complete_metadata_submission_and_frame_are_bounded_before_adopting_or_cloning() {
    let mut original = data();
    let original_bytes = projection(&original).unwrap();
    let small = submission(4096);
    assert!(metadata_submission(&original, &small).is_ok());
    let excessive = submission(METADATA_REPRESENTATION);
    assert!(metadata_submission(&original, &excessive).is_err());
    assert_eq!(projection(&original).unwrap(), original_bytes);
    original.metadata_text = Some(t::Details {
        platform: None,
        locale: None,
        checkout: None,
        prepared: None,
        recovery: None,
        submission: Some(submission(METADATA_REPRESENTATION / 2)),
    });
    let before = projection(&original).unwrap();
    let frame = ChildFrame::MetadataTextOpened(t::Opened {
        revision: "a".repeat(32),
        metadata_root: String::with_capacity(METADATA_REPRESENTATION - before + 1),
        baseline: small.expected_baseline,
        scope_resources: ResourceState::Settled,
    });
    assert!(metadata_prospective(&data(), &frame).is_ok());
    assert!(metadata_prospective(&original, &frame).is_err());
    assert_eq!(projection(&original).unwrap(), before);
    assert!(original.metadata_text.as_ref().unwrap().checkout.is_none());
}
