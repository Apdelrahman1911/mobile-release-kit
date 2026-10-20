//! A typed ticket on the SAME Supervisor/Setup IO, clock and join roster.
use super::*;
#[derive(Clone, Debug)]
pub(crate) enum GitHubActionsRetryReceipt {
    Pending,
    RetainedUnknown,
    Settled {
        outcome: Result<actions_retry_protocol::Reply, BridgeError>,
        settled_at: Instant,
        was_unknown: bool,
    },
}
pub(crate) struct GitHubActionsRetryTicket {
    owner: Arc<Owner>,
    receipt: Arc<Mutex<GitHubActionsRetryReceipt>>,
}
impl GitHubActionsRetryTicket {
    pub(crate) fn operation_id(&self) -> &str {
        &self.owner.id
    }
    pub(crate) fn stop(&self) {
        self.owner.fail(BridgeError::new(
            "cancelled",
            "Actions retry was stopped; an accepted retry cannot be undone.",
        ));
    }
    pub(crate) fn receipt(&self) -> GitHubActionsRetryReceipt {
        lock(&self.receipt).clone()
    }
    pub(crate) fn go_claimed(&self) -> bool {
        self.owner.preflight_go_claimed.load(Ordering::SeqCst)
    }
    pub(crate) fn retained_heap(&self) -> Option<usize> {
        let n = self.owner.actions_retry_request.as_ref()?.heap()?;
        match &*lock(&self.receipt) {
            GitHubActionsRetryReceipt::Settled { outcome: Ok(r), .. } => n.checked_add(r.heap()?),
            GitHubActionsRetryReceipt::Settled {
                outcome: Err(_), ..
            } => Some(n),
            _ => None,
        }
    }
}
impl Supervisor {
    pub(crate) fn actions_retry_profile_available(&self) -> bool {
        self.github_setup_profile_available()
    }
    pub(crate) fn start_actions_retry(
        &self,
        request: actions_retry_protocol::Request,
        gate: crate::asset_session::GitHubActionsRetryGoGate,
        end: Instant,
    ) -> Result<GitHubActionsRetryTicket, BridgeError> {
        let receipt = Arc::new(Mutex::new(GitHubActionsRetryReceipt::Pending));
        let owner = self.admit(
            AdmissionRequest::GitHubActionsRetry { request, gate, end },
            CompletionTarget::GitHubActionsRetry(receipt.clone()),
        )?;
        Ok(GitHubActionsRetryTicket { owner, receipt })
    }
}
