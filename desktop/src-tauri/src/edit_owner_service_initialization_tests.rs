//! Pure private projection/chain DATA. No Session or native return is invented.
use super::*;
use crate::edit_protocol::CoreEditOutcome;

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
        initialization: Some(initialization_wire::Details::new(
            initialization_wire::Intent::Initialize,
            (7, 3),
        )),
        apply_submitted: false,
        core_outcome: None,
        native_reason: Reason::None,
        native_finality: NativeFinality::Pending,
        late_settled: false,
    }
}
fn prepared() -> EditProjection {
    let mut p = projection();
    let d = p.initialization.as_mut().unwrap();
    assert!(d.accept_opened(initialization_wire::Opened::Initialize {
        revision: "3".repeat(32),
        observed: initialization_wire::Observed {
            schema_version: 1,
            file_count: 6,
            directory_count: 3
        },
        scope_resources: ResourceState::Settled
    }));
    assert!(
        d.accept_prepared(initialization_wire::PreparedReply::Initialize {
            revision: "3".repeat(32),
            plan_token: "4".repeat(32),
            view: initialization_wire::tests::view(),
            scope_resources: ResourceState::Settled
        })
    );
    p
}
#[test]
fn initialization_seven_original_publications_do_not_skip_repeat_or_rebase() {
    let mut stage = Stage::Bound;
    for step in [
        Step::Open,
        Step::Opened,
        Step::Prepare,
        Step::Prepared,
        Step::Apply,
        Step::Terminal,
        Step::Retired,
    ] {
        let next = successor(stage, step).unwrap();
        assert!(successor(next, step).is_none());
        stage = next;
    }
    assert_eq!(stage, Stage::Returned);
    assert!(successor(Stage::Opening, Step::Apply).is_none());
    assert!(successor(Stage::Reviewing, Step::Terminal).is_none());
    assert!(successor(Stage::Finalizing, Step::Prepare).is_none());
}
#[test]
fn private_inventory_summary_is_from_actual_initialization_preview_not_recovery_or_public_ids() {
    assert!(review(&projection(), 12).is_err());
    let mut p = prepared();
    let summary = review(&p, 12).unwrap();
    assert_eq!(
        (
            summary.draft_revision,
            summary.baseline_generation,
            summary.file_count
        ),
        (7, 3, 6)
    );
    assert_eq!(
        summary.created_files + summary.preserved_files + summary.appended_files,
        6
    );
    assert_eq!(summary.tooling_repository, "example/toolkit");
    assert_eq!(summary.tooling_sha, "b".repeat(40));
    assert_eq!(summary.native_status_revision, 12);
    assert_eq!(summary.plan_token.as_str(), "4".repeat(32));
    p.initialization = Some(initialization_wire::tests::detail(
        initialization_wire::RecoveryAction::CommittedCleanup,
    ));
    assert!(review(&p, 12).is_err());
}
#[test]
fn initialization_positive_attribution_requires_original_chain_and_real_native_finality() {
    let mut p = prepared();
    p.apply_submitted = true;
    p.core_outcome = Some(CoreEditOutcome {
        effect: Effect::Committed,
        journal: Journal::Clean,
        resources: ResourceState::Settled,
        reason: CoreReason::None,
    });
    assert!(final_data(&p, false).is_none()); // A core frame is not native retirement.
    let mut unknown = false;
    fence_retirement(&mut p, &mut unknown, false);
    assert!(unknown);
    assert_eq!(p.native_reason, Reason::CallerLost);
    assert_eq!(p.native_finality, NativeFinality::Pending); // No fake joined value.
    let mut failed = prepared();
    failed.core_outcome = Some(CoreEditOutcome {
        effect: Effect::NotStarted,
        journal: Journal::NotCreated,
        resources: ResourceState::Settled,
        reason: CoreReason::Cancelled,
    });
    let mut unknown = false;
    fence_retirement(&mut failed, &mut unknown, false);
    assert!(!unknown);
    assert!(final_data(&failed, false).is_none());
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[test]
fn initialization_code_census_borrows_only_the_same_live_slot_and_refuses_busy_or_lost() {
    let original = Arc::new(Mutex::new(InstalledEditSlots::ProjectInitialization(
        ProjectInitializationRuntimeSlots::new(),
    )));
    let weak = Arc::downgrade(&original);
    assert!(native_code_bytes(&weak).is_err()); // Ordinary slot is not opted in.
    {
        let mut held = original.lock().unwrap();
        let InstalledEditSlots::ProjectInitialization(slots) = &mut *held else {
            unreachable!()
        };
        slots.bind_initialization_agent_inspection().unwrap();
        assert!(slots.never_started());
        assert!(native_code_bytes(&weak).is_err()); // No wait or zero fallback.
    }
    let count = native_code_bytes(&weak).unwrap();
    assert_eq!(
        count,
        std::mem::size_of::<ProjectInitializationRuntimeSlots>()
    );
    assert_eq!(Arc::strong_count(&original), 1); // No additional retained owner.
    let poisoned = original.clone();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = poisoned.lock().unwrap();
        panic!("inert original slot poison");
    }));
    drop(poisoned);
    assert!(native_code_bytes(&weak).is_err());
    drop(original);
    assert!(native_code_bytes(&weak).is_err());
    let foreign = Arc::new(Mutex::new(InstalledEditSlots::Configuration(
        ConfigurationRuntimeSlots::new(),
    )));
    assert!(native_code_bytes(&Arc::downgrade(&foreign)).is_err());
}
