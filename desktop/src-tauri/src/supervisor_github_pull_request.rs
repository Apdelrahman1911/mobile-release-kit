//! A typed ticket on the SAME Supervisor/Setup IO, clock and join roster.
use super::*;
#[derive(Clone, Debug)]
pub(crate) enum GitHubPullRequestReceipt {
    Pending,
    RetainedUnknown,
    Settled {
        outcome: Result<pull_request_protocol::Reply, BridgeError>,
        settled_at: Instant,
        was_unknown: bool,
    },
}
pub(crate) struct GitHubPullRequestTicket {
    owner: Arc<Owner>,
    receipt: Arc<Mutex<GitHubPullRequestReceipt>>,
}
impl GitHubPullRequestTicket {
    pub(crate) fn operation_id(&self) -> &str {
        &self.owner.id
    }
    pub(crate) fn stop(&self) {
        self.owner.fail(BridgeError::new(
            "cancelled",
            "Draft PR creation was stopped; a sent request cannot be undone.",
        ));
    }
    pub(crate) fn receipt(&self) -> GitHubPullRequestReceipt {
        lock(&self.receipt).clone()
    }
    pub(crate) fn go_claimed(&self) -> bool {
        self.owner.preflight_go_claimed.load(Ordering::SeqCst)
    }
    pub(crate) fn retained_heap(&self) -> Option<usize> {
        let n = self.owner.pull_request_request.as_ref()?.heap()?;
        match &*lock(&self.receipt) {
            GitHubPullRequestReceipt::Settled { outcome: Ok(r), .. } => n.checked_add(r.heap()?),
            GitHubPullRequestReceipt::Settled {
                outcome: Err(_), ..
            } => Some(n),
            _ => None,
        }
    }
}
impl Supervisor {
    pub(crate) fn pull_request_profile_available(&self) -> bool {
        self.github_setup_profile_available()
    }
    pub(crate) fn start_pull_request(
        &self,
        request: pull_request_protocol::Request,
        gate: crate::asset_session::GitHubPullRequestGoGate,
        end: Instant,
    ) -> Result<GitHubPullRequestTicket, BridgeError> {
        let receipt = Arc::new(Mutex::new(GitHubPullRequestReceipt::Pending));
        let owner = self.admit(
            AdmissionRequest::GitHubPullRequest { request, gate, end },
            CompletionTarget::GitHubPullRequest(receipt.clone()),
        )?;
        Ok(GitHubPullRequestTicket { owner, receipt })
    }
}
