//! Metadata facet of the SAME three original Supervisor owners, never a runner.
use super::*;
use crate::{service_github_action_protocol::Reason, service_github_action_requests::Entry};
fn entry(owner: &Owner) -> Option<&Arc<Entry>> {
    owner
        .repository_create_gate
        .as_ref()
        .and_then(|g| g.agent())
        .or_else(|| owner.pull_request_gate.as_ref().and_then(|g| g.agent()))
        .or_else(|| owner.actions_retry_gate.as_ref().and_then(|g| g.agent()))
        .or_else(|| owner.publication_gate.as_ref().and_then(|g| g.agent()))
}
pub(super) fn arm(owner: &Owner) -> Result<(), BridgeError> {
    if let Some(e) = entry(owner) {
        e.arm(&owner.id)
            .map_err(crate::asset_session::application_service::public_error)?
    }
    Ok(())
}
pub(super) fn unknown(owner: &Owner) {
    if let Some(e) = entry(owner) {
        e.unknown(Reason::CleanupUnknown)
    }
}
const CHECK: Duration = Duration::from_millis(100);
pub(super) fn endpoint(owner: &Owner, now: Instant, end: Instant) -> Instant {
    match entry(owner) {
        Some(e) => {
            let next = end.min(now + CHECK);
            if now < e.scope().read.end() {
                next.min(e.scope().read.end())
            } else {
                next
            }
        }
        None => end,
    }
}
pub(super) fn observe(owner: &Owner, inner: &Inner) {
    let Some((unknown, at)) = entry(owner).and_then(|e| e.first_stop()) else {
        return;
    };
    let mut s = lock(&owner.state);
    if s.terminal {
        return;
    }
    let old = s.cleanup_endpoint;
    s.fail_at(
        if unknown {
            BridgeError::cleanup_unknown()
        } else {
            BridgeError::new(
                "cancelled",
                "The original GitHub delegation ended. A remote action cannot be undone by STOP.",
            )
        },
        at,
    );
    let changed = old != s.cleanup_endpoint;
    let publish_unknown = unknown && !s.unknown;
    drop(s);
    if publish_unknown {
        owner.unknown(inner)
    } else if changed {
        owner.stop.send_replace(true);
        owner.changed.notify_waiters();
    }
}
