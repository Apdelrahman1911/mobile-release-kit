//! A read-only observation tap INSIDE the original EditOwner. Never uses the
//! public IdentityStatus, renderer state or a result-shaped terminal as finality.
use super::*;
use crate::application_service_host::{
    ApplicationHost, IdentityCapture, IdentityObservation, IdentitySource,
};
use std::sync::Weak;

pub(super) struct Binding {
    document: Weak<()>,
    host: Weak<ApplicationHost>,
}
pub(super) enum Link {
    Uncaptured,
    Skipped,
    Captured {
        original: Weak<Session>,
        generation: [u8; 32],
        capture: IdentityCapture,
    },
}
impl Default for Link {
    fn default() -> Self {
        Self::Uncaptured
    }
}

impl EditOwner {
    /// Called once from the genuine Document constructor AFTER the original
    /// saved-registration binding. Optional history cannot admit/disable edits.
    pub(crate) fn bind_identity_history(&self, document: &Arc<()>, host: &Arc<ApplicationHost>) {
        let Some(original) = self.inner.android_registration.get() else {
            return;
        };
        if original.document.as_ptr() != Arc::as_ptr(document) {
            return;
        }
        if let Some(bound) = self.inner.identity_history.get() {
            // Never retarget an existing session/capture to a new host.
            if bound.document.as_ptr() != Arc::as_ptr(document)
                || bound.host.as_ptr() != Arc::as_ptr(host)
            {
                return;
            }
            return;
        }
        let _ = self.inner.identity_history.set(Binding {
            document: Arc::downgrade(document),
            host: Arc::downgrade(host),
        });
    }
}

fn identity_shape(projection: &EditProjection) -> bool {
    projection.domain == EditDomain::ProjectIdentity
        && projection.identity.is_some()
        && projection.workflow.is_none()
        && projection.metadata_text.is_none()
        && projection.release_version.is_none()
        && projection.metadata_images.is_none()
        && projection.initialization.is_none()
        && projection.recovery.is_none()
        && projection.checkout.is_none()
        && projection.prepared.is_none()
}
fn cancellation(reason: Reason) -> bool {
    matches!(
        reason,
        Reason::Discarded
            | Reason::Cancelled
            | Reason::CallerLost
            | Reason::WindowLost
            | Reason::Shutdown
    )
}

/// `retired` is supplied ONLY by the original observe_final hook after its
/// already-existing join/ledger checks. There is no exported DTO/finality API.
pub(super) fn observation(
    projection: &EditProjection,
    unknown: bool,
    retired: bool,
) -> Result<IdentityObservation, ()> {
    use IdentityObservation as O;
    if !identity_shape(projection) {
        return Err(());
    }
    let core = projection.core_outcome.as_ref();
    if unknown
        || projection.phase == Phase::Unknown
        || projection.native_finality == NativeFinality::Unknown
        || projection.late_settled
        || core.is_some_and(|core| {
            core.effect == Effect::Unknown
                || core.journal == Journal::Unknown
                || core.resources == ResourceState::Unknown
        })
    {
        return Ok(O::Unknown);
    }
    let detail = projection.identity.as_ref().ok_or(())?;
    if !detail.valid()
        || core.is_some_and(|core| {
            !core.valid() || !detail.terminal_admissible(projection.apply_submitted, core)
        })
    {
        return Err(());
    }
    if !retired {
        if projection.native_finality != NativeFinality::Pending || projection.phase == Phase::Final
        {
            return Err(());
        }
        return Ok(
            if projection.phase == Phase::Reviewing
                && projection.native_reason == Reason::None
                && !projection.apply_submitted
                && detail.prepared.is_some()
            {
                O::Prepared
            } else if projection.phase == Phase::Finalizing
                && cancellation(projection.native_reason)
            {
                O::CancellationRequested
            } else {
                O::Running
            },
        );
    }
    if projection.phase != Phase::Final || projection.native_finality != NativeFinality::Settled {
        return Err(());
    }
    let Some(core) = core else {
        // Missing post-Apply effect/journal evidence cannot become a settled
        // failure merely because native processes/resources actually joined.
        if projection.apply_submitted {
            return Ok(O::Unknown);
        }
        return if cancellation(projection.native_reason) {
            Ok(O::Cancelled)
        } else if projection.native_reason != Reason::None {
            Ok(O::Failed)
        } else {
            Err(())
        };
    };
    if core.journal == Journal::RecoveryRequired {
        return Ok(O::RecoveryRequired);
    }
    if detail.intent == identity_wire::Intent::Recover && identity_recovery_complete(projection)
        || detail.intent == identity_wire::Intent::Edit
            && projection.apply_submitted
            && projection.native_reason == Reason::None
            && core.reason == CoreReason::None
            && matches!(core.effect, Effect::Committed | Effect::Unchanged)
            && detail.terminal_admissible(true, core)
    {
        return Ok(O::Succeeded);
    }
    // A late cancellation cannot relabel an installed committed identity as
    // "cancelled". Likewise a filesystem/protocol/timeout failure remains a
    // failure even if a later stop request also caused cleanup.
    if core.effect != Effect::Committed
        && matches!(core.reason, CoreReason::None | CoreReason::Cancelled)
        && (cancellation(projection.native_reason)
            || projection.native_reason == Reason::None && core.reason == CoreReason::Cancelled)
    {
        return Ok(O::Cancelled);
    }
    Ok(O::Failed)
}

/// Called after the native revision increment, before its existing watch send.
/// First admission is the ONLY capture opportunity; enabling the Host later
/// does not adopt old active sessions or the replaceable r.last projection.
pub(super) fn changed(inner: &Inner, registry: &mut Registry) {
    let Some(active) = registry.active.as_mut() else {
        return;
    };
    if matches!(active.history, Link::Uncaptured) {
        active.history = Link::Skipped;
        let capture = (|| {
            if active.session.domain != EditDomain::ProjectIdentity
                || !identity_shape(&active.projection)
                || active.projection.phase != Phase::Opening
                || active.claimed_seq != 0
                || active.opened
                || active.prepared
                || active.terminal
                || active.unknown
                || !registry.document_bound
                || registry.document_lost
                || registry.disabled
                || registry.exhausted
                || inner.poisoned.load(Ordering::SeqCst)
                || active.projection.owner_generation != registry.generation
                || active.projection.session_id != active.session.id
            {
                return None;
            }
            let binding = inner.identity_history.get()?;
            let registration = inner.android_registration.get()?;
            if !Weak::ptr_eq(&binding.document, &registration.document) {
                return None;
            }
            let document = binding.document.upgrade()?;
            let host = binding.host.upgrade()?;
            let registered = active.session.registration.as_ref()?;
            let generation: [u8; 32] = active
                .projection
                .owner_generation
                .as_bytes()
                .try_into()
                .ok()?;
            let capture = host.capture_identity(
                IdentitySource {
                    runtime_id: &active.projection.project_id,
                    root: &registered.root,
                    registration: registered.generation,
                    document: &document,
                    session_id: &active.session.id,
                },
                registry.revision,
            )?;
            Some(Link::Captured {
                original: Arc::downgrade(&active.session),
                generation,
                capture,
            })
        })();
        if let Some(capture) = capture {
            active.history = capture;
        }
    }
    publish(
        &active.session,
        &active.projection,
        &active.history,
        active.unknown,
        registry.revision,
        registry.disabled || registry.exhausted || inner.poisoned.load(Ordering::SeqCst),
        false,
    );
}

fn publish(
    session: &Arc<Session>,
    projection: &EditProjection,
    link: &Link,
    unknown: bool,
    revision: u32,
    invalid: bool,
    retired: bool,
) {
    let Link::Captured {
        original,
        generation,
        capture,
    } = link
    else {
        return;
    };
    if original.as_ptr() != Arc::as_ptr(session)
        || generation.as_slice() != projection.owner_generation.as_bytes()
        || projection.session_id != session.id
        || revision == 0
    {
        capture.unavailable();
        return;
    }
    // Original UNKNOWN is observable even after its native registry disables
    // new work. A mere invalid/mismatched registry never invents such a fact.
    let result = observation(projection, unknown, retired);
    match result {
        Ok(IdentityObservation::Unknown) => capture.record(revision, IdentityObservation::Unknown),
        Ok(value) if !invalid => capture.record(revision, value),
        _ => capture.unavailable(),
    }
}

/// Exact hook inside observe_final, after original resource settlement and
/// Phase/NativeFinality assignment and atomic active -> r.last publication.
/// The SAME original registry lock still excludes replacement by another edit;
/// its actual revision and original weak Session are used, not public Status.
pub(super) fn retired(
    inner: &Inner,
    registry: &Registry,
    session: &Arc<Session>,
    link: &Link,
    unknown: bool,
) {
    let Some(projection) = registry.last.as_ref() else {
        if let Link::Captured { capture, .. } = link {
            capture.unavailable();
        }
        return;
    };
    publish(
        session,
        projection,
        link,
        unknown,
        registry.revision,
        registry.disabled || registry.exhausted || inner.poisoned.load(Ordering::SeqCst),
        true,
    );
}

#[cfg(test)]
#[path = "edit_owner_identity_history_tests.rs"]
mod tests;
