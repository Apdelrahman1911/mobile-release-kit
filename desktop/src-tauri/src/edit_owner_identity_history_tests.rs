//! Pure projections from the existing synthetic identity protocol fixtures.
//! These are mapping tests, not native admission or process/join qualification.
use super::*;

fn projection() -> EditProjection {
    EditProjection {
        domain: EditDomain::ProjectIdentity,
        identity: Some(identity_wire::tests::edit_details(true, false)),
        workflow: None,
        metadata_text: None,
        release_version: None,
        metadata_images: None,
        initialization: None,
        project_id: "project-1".into(),
        session_id: "1".repeat(32),
        owner_generation: "2".repeat(32),
        phase: Phase::Reviewing,
        review_remaining_ms: 1,
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
fn core(effect: Effect, journal: Journal, reason: CoreReason) -> wire::CoreEditOutcome {
    wire::CoreEditOutcome {
        effect,
        journal,
        resources: ResourceState::Settled,
        reason,
    }
}
fn applied() -> EditProjection {
    let mut p = projection();
    p.apply_submitted = true;
    p.phase = Phase::Final;
    p.native_finality = NativeFinality::Settled;
    p.core_outcome = Some(core(Effect::Committed, Journal::Clean, CoreReason::None));
    p
}

#[test]
fn actual_core_terminal_is_pending_until_original_native_retirement() {
    let mut p = applied();
    p.phase = Phase::Finalizing;
    p.native_finality = NativeFinality::Pending;
    assert_eq!(
        observation(&p, false, false),
        Ok(IdentityObservation::Running)
    );
    assert!(observation(&p, false, true).is_err());
    p.phase = Phase::Final;
    p.native_finality = NativeFinality::Settled;
    assert!(observation(&p, false, false).is_err());
    assert_eq!(
        observation(&p, false, true),
        Ok(IdentityObservation::Succeeded)
    );
}

#[test]
fn only_actual_review_is_prepared_and_close_does_not_claim_applied_success() {
    let mut p = projection();
    assert_eq!(
        observation(&p, false, false),
        Ok(IdentityObservation::Prepared)
    );
    p.phase = Phase::Editing;
    assert_eq!(
        observation(&p, false, false),
        Ok(IdentityObservation::Running)
    );
    p.phase = Phase::Finalizing;
    p.native_reason = Reason::Discarded;
    p.core_outcome = Some(core(
        Effect::NotStarted,
        Journal::NotCreated,
        CoreReason::None,
    ));
    assert_eq!(
        observation(&p, false, false),
        Ok(IdentityObservation::CancellationRequested)
    );
    p.phase = Phase::Final;
    p.native_finality = NativeFinality::Settled;
    assert_eq!(
        observation(&p, false, true),
        Ok(IdentityObservation::Cancelled)
    );
}

#[test]
fn unchanged_requires_real_applied_noop_and_valid_identity_details() {
    let mut p = applied();
    p.identity = Some(identity_wire::tests::edit_details(true, true));
    p.core_outcome = Some(core(
        Effect::Unchanged,
        Journal::NotCreated,
        CoreReason::None,
    ));
    assert_eq!(
        observation(&p, false, true),
        Ok(IdentityObservation::Succeeded)
    );
    p.apply_submitted = false;
    assert!(observation(&p, false, true).is_err());
    p = applied();
    p.identity = Some(identity_wire::tests::edit_details(false, false));
    assert!(observation(&p, false, true).is_err());
    p = applied();
    p.domain = EditDomain::ReleaseVersion;
    assert!(observation(&p, false, true).is_err());
}

#[test]
fn rollback_and_stale_no_start_remain_failed_settled_records() {
    let mut p = applied();
    for outcome in [
        core(
            Effect::RolledBack,
            Journal::Clean,
            CoreReason::FilesystemError,
        ),
        core(
            Effect::NotStarted,
            Journal::NotCreated,
            CoreReason::StaleRevision,
        ),
    ] {
        p.core_outcome = Some(outcome);
        assert_eq!(
            observation(&p, false, true),
            Ok(IdentityObservation::Failed)
        );
    }
}

#[test]
fn committed_after_apply_cancellation_is_not_cancelled_and_unknown_wins() {
    let mut p = applied();
    p.native_reason = Reason::Cancelled;
    assert_eq!(
        observation(&p, false, true),
        Ok(IdentityObservation::Failed)
    );
    p.core_outcome = Some(core(
        Effect::RolledBack,
        Journal::Clean,
        CoreReason::Cancelled,
    ));
    assert_eq!(
        observation(&p, false, true),
        Ok(IdentityObservation::Cancelled)
    );
    p.core_outcome = Some(core(
        Effect::RolledBack,
        Journal::Clean,
        CoreReason::FilesystemError,
    ));
    assert_eq!(
        observation(&p, false, true),
        Ok(IdentityObservation::Failed)
    );
    assert_eq!(
        observation(&p, true, true),
        Ok(IdentityObservation::Unknown)
    );
}

#[test]
fn native_core_and_late_unknown_precede_success_or_recovery_labels() {
    for n in 0..6 {
        let mut p = applied();
        match n {
            0 => p.native_finality = NativeFinality::Unknown,
            1 => p.late_settled = true,
            2 => p.phase = Phase::Unknown,
            3 => {
                p.core_outcome = Some(core(
                    Effect::Unknown,
                    Journal::Unknown,
                    CoreReason::CustodyUnknown,
                ))
            }
            4 => p.core_outcome.as_mut().unwrap().resources = ResourceState::Unknown,
            _ => p.core_outcome.as_mut().unwrap().journal = Journal::Unknown,
        }
        assert_eq!(
            observation(&p, false, true),
            Ok(IdentityObservation::Unknown)
        );
    }
    let mut p = applied();
    p.core_outcome = Some(core(
        Effect::Committed,
        Journal::RecoveryRequired,
        CoreReason::FilesystemError,
    ));
    assert_eq!(
        observation(&p, false, true),
        Ok(IdentityObservation::RecoveryRequired)
    );
    p.native_finality = NativeFinality::Unknown;
    assert_eq!(
        observation(&p, false, true),
        Ok(IdentityObservation::Unknown)
    );
}

#[test]
fn recovery_success_uses_existing_original_identity_recovery_predicate() {
    for (action, effect) in [
        ("committed_cleanup", Effect::Committed),
        ("rolled_back_cleanup", Effect::RolledBack),
        ("preparing_cleanup", Effect::NotStarted),
        ("rollback", Effect::RolledBack),
    ] {
        let mut p = applied();
        p.identity = Some(identity_wire::tests::recovery_details(action, true));
        p.core_outcome = Some(core(effect, Journal::Clean, CoreReason::None));
        assert!(identity_recovery_complete(&p));
        assert_eq!(
            observation(&p, false, true),
            Ok(IdentityObservation::Succeeded)
        );
        p.native_reason = Reason::IoError;
        assert_eq!(
            observation(&p, false, true),
            Ok(IdentityObservation::Failed)
        );
    }
}

#[test]
fn failed_open_without_core_is_visible_but_missing_post_apply_effect_is_unknown() {
    let mut p = projection();
    p.phase = Phase::Final;
    p.native_finality = NativeFinality::Settled;
    p.native_reason = Reason::SpawnFailed;
    assert_eq!(
        observation(&p, false, true),
        Ok(IdentityObservation::Failed)
    );
    p.native_reason = Reason::IoError;
    p.apply_submitted = true;
    assert_eq!(
        observation(&p, false, true),
        Ok(IdentityObservation::Unknown)
    );
}

#[test]
fn timeout_is_not_relabelled_cancelled_by_core_cleanup() {
    let mut p = applied();
    p.native_reason = Reason::ActiveTimeout;
    p.core_outcome = Some(core(
        Effect::RolledBack,
        Journal::Clean,
        CoreReason::Cancelled,
    ));
    assert_eq!(
        observation(&p, false, true),
        Ok(IdentityObservation::Failed)
    );
    p.phase = Phase::Finalizing;
    p.native_finality = NativeFinality::Pending;
    assert_eq!(
        observation(&p, false, false),
        Ok(IdentityObservation::Running)
    );
}
