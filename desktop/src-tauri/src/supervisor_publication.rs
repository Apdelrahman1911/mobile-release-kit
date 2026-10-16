//! Typed publication ticket on the original Supervisor roster, not a new owner.
use super::*;

#[derive(Clone, Debug)]
pub(crate) enum GitHubPublicationReceipt {
    Pending,
    RetainedUnknown,
    Settled {
        outcome: Result<publication_protocol::Reply, BridgeError>,
        settled_at: Instant,
        was_unknown: bool,
    },
}
pub(crate) struct GitHubPublicationTicket {
    owner: Arc<Owner>,
    receipt: Arc<Mutex<GitHubPublicationReceipt>>,
}
impl GitHubPublicationTicket {
    pub(crate) fn operation_id(&self) -> &str {
        &self.owner.id
    }
    pub(crate) fn stop(&self) {
        self.owner.fail(BridgeError::new(
            "cancelled",
            "The setup publication was stopped; a sent GitHub change is not undone.",
        ));
    }
    pub(crate) fn receipt(&self) -> GitHubPublicationReceipt {
        lock(&self.receipt).clone()
    }
    pub(crate) fn go_claimed(&self) -> bool {
        self.owner.preflight_go_claimed.load(Ordering::SeqCst)
    }
    pub(crate) fn retained_heap(&self) -> Option<usize> {
        let request = self.owner.publication_request.as_ref()?.heap()?;
        match &*lock(&self.receipt) {
            GitHubPublicationReceipt::Settled {
                outcome: Ok(reply), ..
            } => request.checked_add(reply.heap()?),
            GitHubPublicationReceipt::Settled {
                outcome: Err(_), ..
            } => Some(request),
            _ => None,
        }
    }
}
impl Supervisor {
    pub(crate) fn github_publication_profile_available(&self) -> bool {
        self.github_setup_profile_available()
    }
    pub(crate) fn start_github_publication(
        &self,
        request: publication_protocol::Request,
        gate: crate::asset_session::GitHubPublicationGoGate,
        end: Instant,
    ) -> Result<GitHubPublicationTicket, BridgeError> {
        let receipt = Arc::new(Mutex::new(GitHubPublicationReceipt::Pending));
        let owner = self.admit(
            AdmissionRequest::Publication { request, gate, end },
            CompletionTarget::Publication(receipt.clone()),
        )?;
        Ok(GitHubPublicationTicket { owner, receipt })
    }
}

// Reuses the existing inert Owner fixture. No drive(), runtime resolution,
// process, IO acquisition, task or successful native-finality claim is made.
#[cfg(test)]
pub(crate) struct PublicationControlFixture {
    supervisor: Supervisor,
    owner: Arc<Owner>,
}
#[cfg(test)]
impl GitHubPublicationTicket {
    pub(crate) fn control_fixture(
        request: publication_protocol::Request,
        end: Instant,
    ) -> (Self, PublicationControlFixture) {
        let supervisor = Supervisor::new(RuntimeConfig::packaged(std::path::PathBuf::from(
            "/never-opened-publication-control",
        )));
        let receipt = Arc::new(Mutex::new(GitHubPublicationReceipt::Pending));
        let mut owner = super::tests::inert_owner();
        owner.profile = Profile::GitHubPublication;
        owner.publication_request = Some(request);
        owner.publication_receipt = Some(receipt.clone());
        *lock(&owner.state) = OwnerState::new(end, None);
        let owner = Arc::new(owner);
        lock(&supervisor.inner.owners).insert(owner.key, owner.clone());
        (
            Self {
                owner: owner.clone(),
                receipt,
            },
            PublicationControlFixture { supervisor, owner },
        )
    }
}
#[cfg(test)]
impl PublicationControlFixture {
    pub(crate) fn claim(&self) -> bool {
        claim_preflight_go(
            &self.supervisor.inner,
            &self.owner,
            Profile::GitHubPublication,
        )
    }
    pub(crate) fn unknown(&self) {
        self.owner.unknown(&self.supervisor.inner);
    }
    pub(crate) fn retained(&self) -> bool {
        !self.supervisor.can_exit()
            && lock(&self.supervisor.inner.owners)
                .get(&self.owner.key)
                .is_some_and(|v| Arc::ptr_eq(v, &self.owner))
    }
}
