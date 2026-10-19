//! Original EditOwner predicate DATA only. No native task or finality receipt.
use super::*;
use identity_wire::tests::{edit_details, recovery_details, PLAN, REVISION};

fn projection(detail: identity_wire::Details) -> EditProjection {
    EditProjection {
        domain: EditDomain::ProjectIdentity,
        identity: Some(detail),
        initialization: None,
        workflow: None,
        metadata_text: None,
        release_version: None,
        metadata_images: None,
        project_id: "a".repeat(32),
        session_id: "b".repeat(32),
        owner_generation: "c".repeat(32),
        phase: Phase::Reviewing,
        review_remaining_ms: 1000,
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
#[test]
fn identity_uses_original_closed_domain_and_never_general_or_other_profile_fallback() {
    assert!(!qualified(EditDomain::ProjectIdentity, false));
    assert!(!qualified(EditDomain::ProjectIdentity, true));
    assert!(!installed_registration_matches(
        EditDomain::ProjectIdentity,
        false
    ));
    assert!(installed_registration_matches(
        EditDomain::ProjectIdentity,
        true
    ));
    assert_eq!(
        installed_bootstrap_argument(EditDomain::ProjectIdentity),
        Some("project_identity")
    );
    assert_eq!(
        capability_reason(
            EditDomain::ProjectIdentity,
            Some(EditDomain::Configuration),
            false,
            false,
            true,
            true
        ),
        EditAvailability::OtherEditActive
    );
    let p = projection(edit_details(true, false));
    assert!(p.identity_projection().is_ok());
    assert!(!p.configuration_valid());
    assert!(p.workflow_projection().is_err());
    assert!(p.metadata_text_projection().is_err());
    assert!(p.release_version_projection().is_err());
    assert!(p.metadata_images_projection().is_err());
    assert!(p.initialization_projection().is_err());
    let mut bad = p.clone();
    bad.checkout = Some(Checkout {
        revision: REVISION.into(),
        base: json!({}),
    });
    assert!(bad.identity_projection().is_err());
    assert!(!terminal_projection_admissible(
        &bad,
        Some(PLAN),
        &core(Effect::NotStarted, Journal::NotCreated, CoreReason::None)
    ));
}
#[test]
fn identity_invalid_request_retires_only_original_generation_preapply_review() {
    let p = projection(edit_details(true, false));
    let generation = p.owner_generation.clone();
    for phase in [
        Phase::Opening,
        Phase::Editing,
        Phase::Preparing,
        Phase::Reviewing,
    ] {
        let mut before = p.clone();
        before.phase = phase;
        assert!(identity_request_retirable(
            EditDomain::ProjectIdentity,
            &before,
            &generation
        ));
        before.apply_submitted = true;
        assert!(!identity_request_retirable(
            EditDomain::ProjectIdentity,
            &before,
            &generation
        ));
    }
    for phase in [Phase::Applying, Phase::Final, Phase::Unknown] {
        let mut after = p.clone();
        after.phase = phase;
        assert!(!identity_request_retirable(
            EditDomain::ProjectIdentity,
            &after,
            &generation
        ));
    }
    assert!(!identity_request_retirable(
        EditDomain::Configuration,
        &p,
        &generation
    ));
    assert!(!identity_request_retirable(
        EditDomain::ProjectIdentity,
        &p,
        &"d".repeat(32)
    ));
}
#[test]
fn exact_original_token_and_apply_receipt_are_required_even_for_identity_noop() {
    for noop in [false, true] {
        let mut p = projection(edit_details(true, noop));
        let outcome = core(
            if noop {
                Effect::Unchanged
            } else {
                Effect::Committed
            },
            if noop {
                Journal::NotCreated
            } else {
                Journal::Clean
            },
            CoreReason::None,
        );
        assert!(!terminal_projection_admissible(&p, Some(PLAN), &outcome));
        p.apply_submitted = true;
        p.phase = Phase::Applying;
        assert!(terminal_projection_admissible(&p, Some(PLAN), &outcome));
        assert!(!terminal_projection_admissible(
            &p,
            Some(REVISION),
            &outcome
        ));
        assert!(!terminal_projection_admissible(&p, None, &outcome));
    }
}
#[test]
fn only_settled_matching_identity_recovery_may_clear_its_own_pending_domain() {
    let mut p = projection(recovery_details("committed_cleanup", true));
    p.apply_submitted = true;
    p.phase = Phase::Final;
    p.native_finality = NativeFinality::Settled;
    p.core_outcome = Some(core(Effect::Committed, Journal::Clean, CoreReason::None));
    assert!(identity_recovery_complete(&p));
    let mut domains = DomainBlocks::default();
    assert!(domains.record(&p.project_id, EditDomain::ProjectIdentity, false, true));
    assert!(domains.record(&p.project_id, EditDomain::ReleaseVersion, true, true));
    assert!(!domains.clear_domain(&p.project_id, EditDomain::ProjectIdentity));
    assert!(domains.may_recover(&p.project_id, EditDomain::ReleaseVersion));
    for change in 0..7 {
        let mut bad = p.clone();
        match change {
            0 => bad.late_settled = true,
            1 => bad.native_finality = NativeFinality::Unknown,
            2 => bad.phase = Phase::Unknown,
            3 => bad.native_reason = Reason::IoError,
            4 => bad.apply_submitted = false,
            5 => {
                bad.core_outcome = Some(core(
                    Effect::Committed,
                    Journal::RecoveryRequired,
                    CoreReason::FilesystemError,
                ))
            }
            _ => {
                bad.core_outcome = Some(core(Effect::RolledBack, Journal::Clean, CoreReason::None))
            }
        }
        assert!(!identity_recovery_complete(&bad));
    }
    p.identity = Some(edit_details(true, false));
    assert!(!identity_recovery_complete(&p));
}
