//! Detached historical profile DATA, issued only in the existing positive
//! original retirement branch. Never a private Review or saved-record grant.
use super::*;

pub(super) struct Publication {
    reference: apple_wire::Reference,
    context: apple_wire::Context,
    history: apple_wire::ProfileRecoveryHistory,
}
pub(super) fn backing_bytes() -> Option<usize> {
    // Bounded original history + construction scratch. Parent status charges
    // already cover both projected/serialized reply and event copies.
    apple_wire::PROFILE_RECOVERY_LIMIT
        .checked_mul(2)?
        .checked_add(apple_wire::IPC_LIMIT)?
        .checked_add(std::mem::size_of::<Publication>())
}
pub(super) fn publish(registry: &mut Registry, owner: &Session) {
    let Context::AppleProvisioning(context) = &owner.context else {
        return;
    };
    if context.mode != apple_wire::Mode::ProfileReview {
        return;
    }
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    if let Some(history) = super::native::profile_history(owner) {
        registry.profile_recovery = Some(Publication {
            reference: apple_wire::Reference {
                operation_id: owner.id.clone(),
                owner_generation: owner.generation.clone(),
            },
            context: context.clone(),
            history,
        });
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    let _ = registry; // No unsupported-platform list or native finality fiction.
}
pub(super) fn project(registry: &Registry, projection: &mut apple_wire::Projection) {
    projection.profile_recovery = None;
    let Some(stored) = &registry.profile_recovery else {
        return;
    };
    if projection.operation_id == stored.reference.operation_id
        && projection.owner_generation == stored.reference.owner_generation
        && projection.context == stored.context
        && projection.context.mode == apple_wire::Mode::ProfileReview
        && projection.phase == apple_wire::Phase::Terminal
        && projection.outcome == Some(apple_wire::Outcome::Complete)
        && projection.reason == apple_wire::Reason::None
        && projection
            .result
            .as_ref()
            .and_then(apple_wire::ResultData::profile)
            .is_some()
    {
        projection.profile_recovery = Some(stored.history.clone());
    }
}
