//! A typed ticket on the SAME Supervisor/Setup IO, clock and join roster.
use super::*;
#[derive(Clone, Debug)]
pub(crate) enum GitHubPlayCleanupReceipt {
    Pending,
    RetainedUnknown,
    Settled {
        outcome: Result<play_cleanup_protocol::Reply, BridgeError>,
        settled_at: Instant,
        was_unknown: bool,
    },
}
pub(crate) struct GitHubPlayCleanupTicket {
    owner: Arc<Owner>,
    receipt: Arc<Mutex<GitHubPlayCleanupReceipt>>,
}
impl GitHubPlayCleanupTicket {
    pub(crate) fn operation_id(&self) -> &str {
        &self.owner.id
    }
    pub(crate) fn stop(&self) {
        self.owner.fail(BridgeError::new(
            "cancelled",
            "Hosted cleanup was stopped; a sent dispatch cannot be undone.",
        ));
    }
    pub(crate) fn stop_at(&self, at: Instant) {
        let mut state = lock(&self.owner.state);
        if state.terminal {
            return;
        }
        state.fail_at(
            BridgeError::new(
                "cancelled",
                "Hosted cleanup was stopped; a sent dispatch cannot be undone.",
            ),
            at,
        );
        drop(state);
        self.owner.stop.send_replace(true);
        self.owner.changed.notify_waiters();
    }
    pub(crate) fn receipt(&self) -> GitHubPlayCleanupReceipt {
        lock(&self.receipt).clone()
    }
    pub(crate) fn go_claimed(&self) -> bool {
        self.owner.preflight_go_claimed.load(Ordering::SeqCst)
    }
    pub(crate) fn agent_unknown(&self) {
        native_unknown(&self.owner);
    }
    pub(crate) fn retained_heap(&self) -> Option<usize> {
        let n = self.owner.play_cleanup_request.as_ref()?.heap()?;
        match &*lock(&self.receipt) {
            GitHubPlayCleanupReceipt::Settled { outcome: Ok(r), .. } => n.checked_add(r.heap()?),
            GitHubPlayCleanupReceipt::Settled {
                outcome: Err(_), ..
            } => Some(n),
            _ => None,
        }
    }
}

// Called at the original Unknown publication after OwnerState unlock, and by
// the same ticket when its containing Connection becomes Unknown. No Doc or
// Service/Host lock; release OwnerState before touching the metadata link.
pub(super) fn native_unknown(owner: &Owner) {
    let Some(link) = owner.play_cleanup_gate.as_ref().and_then(|g| g.agent()) else {
        return;
    };
    let first = {
        let state = lock(&owner.state);
        state
            .cleanup_endpoint
            .and_then(|end| end.checked_sub(CLEANUP_TIME))
            .unwrap_or_else(Instant::now)
    };
    let go = owner.preflight_go_claimed.load(Ordering::SeqCst);
    if link.native_unknown(&owner.id, go, first).is_err() {
        link.entry().unknown();
    }
}
impl Supervisor {
    pub(crate) fn play_cleanup_profile_available(&self) -> bool {
        self.github_setup_profile_available()
    }
    pub(crate) fn start_play_cleanup(
        &self,
        request: play_cleanup_protocol::Request,
        gate: crate::asset_session::GitHubPlayCleanupGoGate,
        end: Instant,
    ) -> Result<GitHubPlayCleanupTicket, BridgeError> {
        let receipt = Arc::new(Mutex::new(GitHubPlayCleanupReceipt::Pending));
        let owner = self.admit(
            AdmissionRequest::GitHubPlayCleanup { request, gate, end },
            CompletionTarget::GitHubPlayCleanup(receipt.clone()),
        )?;
        Ok(GitHubPlayCleanupTicket { owner, receipt })
    }
}

// Compare the original service facet BEFORE taking OwnerState. No Doc/Host/
// Service guard, callback or IO is reachable here. The original watchdog's
// next observation is bounded only for this fixed agent-linked profile.
const AGENT_CHECK: Duration = Duration::from_millis(100);
pub(super) fn observe_agent(owner: &Owner, inner: &Inner, _now: Instant) {
    let Some((unknown, at)) = owner
        .play_cleanup_gate
        .as_ref()
        .and_then(|g| g.agent_first_stop())
    else {
        return;
    };
    let mut state = lock(&owner.state);
    if state.terminal {
        return;
    }
    let (changed, publish_unknown) = record_agent_stop(&mut state, unknown, at);
    drop(state);
    if publish_unknown {
        owner.unknown(inner)
    } else if changed {
        owner.stop.send_replace(true);
        owner.changed.notify_waiters();
    }
}
pub(super) fn check_deadline(owner: &Owner, now: Instant, endpoint: Instant) -> Instant {
    if owner
        .play_cleanup_gate
        .as_ref()
        .is_some_and(|g| g.agent().is_some())
    {
        endpoint.min(now + AGENT_CHECK)
    } else {
        endpoint
    }
}

// Uses actual original OwnerState failure arithmetic; only the existing owner
// publishes STOP/Unknown and joins its management jobs.
fn record_agent_stop(state: &mut OwnerState, unknown: bool, at: Instant) -> (bool, bool) {
    let before = state.cleanup_endpoint;
    state.fail_at(
        if unknown {
            BridgeError::cleanup_unknown()
        } else {
            BridgeError::new(
                "cancelled",
                "The original agent cleanup permission ended; a sent dispatch cannot be undone.",
            )
        },
        at,
    );
    let changed = before != state.cleanup_endpoint;
    let publish_unknown = unknown && !state.unknown;
    (changed, publish_unknown)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn delayed_agent_stop_uses_original_failure_plus_two_and_never_supplies_management_join() {
        let now = Instant::now();
        let end = now + Duration::from_secs(60);
        let mut state = OwnerState::new(end, None);
        let first = now + Duration::from_secs(1);
        assert_eq!(record_agent_stop(&mut state, false, first), (true, false));
        assert_eq!(state.cleanup_endpoint, Some(first + CLEANUP_TIME));
        assert!(!state.management_ready());
        assert_eq!(
            record_agent_stop(&mut state, false, first + Duration::from_secs(8)),
            (false, false)
        );
        assert_eq!(state.cleanup_endpoint, Some(first + CLEANUP_TIME));
        assert_eq!(
            record_agent_stop(&mut state, true, first + Duration::from_secs(9)),
            (false, true)
        );
        assert_eq!(state.cleanup_endpoint, Some(first + CLEANUP_TIME));
        assert!(!state.terminal && !state.management_ready());
        assert_eq!(CLEANUP_TIME, Duration::from_secs(2));
        assert_eq!(AGENT_CHECK, Duration::from_millis(100));
    }
}
