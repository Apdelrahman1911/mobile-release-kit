//! A typed ticket on the SAME Supervisor/Setup IO, clock and join roster.
use super::*;
#[derive(Clone, Debug)]
pub(crate) enum RepositoryCreateReceipt {
    Pending,
    RetainedUnknown,
    Settled {
        outcome: Result<repository_create_protocol::Reply, BridgeError>,
        settled_at: Instant,
        was_unknown: bool,
    },
}
pub(crate) struct RepositoryCreateTicket {
    owner: Arc<Owner>,
    receipt: Arc<Mutex<RepositoryCreateReceipt>>,
}
impl RepositoryCreateTicket {
    pub(crate) fn operation_id(&self) -> &str {
        &self.owner.id
    }
    pub(crate) fn stop(&self) {
        self.owner.fail(BridgeError::new(
            "cancelled",
            "Repository creation was stopped; a sent request cannot be undone.",
        ));
    }
    pub(crate) fn receipt(&self) -> RepositoryCreateReceipt {
        lock(&self.receipt).clone()
    }
    pub(crate) fn go_claimed(&self) -> bool {
        self.owner.preflight_go_claimed.load(Ordering::SeqCst)
    }
    pub(crate) fn retained_heap(&self) -> Option<usize> {
        let n = self.owner.repository_create_request.as_ref()?.heap()?;
        match &*lock(&self.receipt) {
            RepositoryCreateReceipt::Settled { outcome: Ok(r), .. } => n.checked_add(r.heap()?),
            RepositoryCreateReceipt::Settled {
                outcome: Err(_), ..
            } => Some(n),
            _ => None,
        }
    }
}
impl Supervisor {
    pub(crate) fn repository_create_profile_available(&self) -> bool {
        self.github_setup_profile_available()
    }
    pub(crate) fn start_repository_create(
        &self,
        request: repository_create_protocol::Request,
        gate: crate::asset_session::RepositoryCreateGoGate,
        end: Instant,
    ) -> Result<RepositoryCreateTicket, BridgeError> {
        let receipt = Arc::new(Mutex::new(RepositoryCreateReceipt::Pending));
        let owner = self.admit(
            AdmissionRequest::RepositoryCreate { request, gate, end },
            CompletionTarget::RepositoryCreate(receipt.clone()),
        )?;
        Ok(RepositoryCreateTicket { owner, receipt })
    }
}
