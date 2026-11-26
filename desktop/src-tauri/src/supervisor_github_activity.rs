//! A typed ticket on the SAME Supervisor/Setup IO, clock and join roster.
use super::*;
#[derive(Clone, Debug)]
pub(crate) enum GitHubActivityReceipt {
    Pending,
    RetainedUnknown,
    Settled {
        outcome: Result<github_activity_protocol::Reply, BridgeError>,
        settled_at: Instant,
        was_unknown: bool,
    },
}
pub(crate) struct GitHubActivityTicket {
    owner: Arc<Owner>,
    receipt: Arc<Mutex<GitHubActivityReceipt>>,
}
impl GitHubActivityTicket {
    pub(crate) fn operation_id(&self) -> &str {
        &self.owner.id
    }
    pub(crate) fn stop(&self) {
        self.owner.fail(BridgeError::new(
            "cancelled",
            "The original GitHub activity read was stopped.",
        ));
    }
    pub(crate) fn receipt(&self) -> GitHubActivityReceipt {
        lock(&self.receipt).clone()
    }
    pub(crate) fn go_claimed(&self) -> bool {
        self.owner.preflight_go_claimed.load(Ordering::SeqCst)
    }
    pub(crate) fn retained_heap(&self) -> Option<usize> {
        let n = self.owner.github_activity_request.as_ref()?.heap()?;
        match &*lock(&self.receipt) {
            GitHubActivityReceipt::Settled { outcome: Ok(r), .. } => n.checked_add(r.heap()?),
            GitHubActivityReceipt::Settled {
                outcome: Err(_), ..
            } => Some(n),
            _ => None,
        }
    }
}
impl Supervisor {
    pub(crate) fn github_activity_profile_available(&self) -> bool {
        self.github_setup_profile_available()
    }
    pub(crate) fn start_github_activity(
        &self,
        request: github_activity_protocol::Request,
        gate: crate::asset_session::GitHubActivityGoGate,
        end: Instant,
    ) -> Result<GitHubActivityTicket, BridgeError> {
        let receipt = Arc::new(Mutex::new(GitHubActivityReceipt::Pending));
        let owner = self.admit(
            AdmissionRequest::GitHubActivity { request, gate, end },
            CompletionTarget::GitHubActivity(receipt.clone()),
        )?;
        Ok(GitHubActivityTicket { owner, receipt })
    }
}
