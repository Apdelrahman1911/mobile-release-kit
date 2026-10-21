//! Typed publication ticket on the original Supervisor roster, not a new owner.
use super::*;
use std::sync::Weak;

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
        let request = self
            .owner
            .publication_request
            .as_ref()?
            .heap()?
            .checked_add(
                self.owner
                    .publication_gate
                    .as_ref()
                    .map_or(Some(0), |g| g.counter_quote())?,
            )?;
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

/// A view of THIS admitted publication Owner's clock/STOP/management facts,
/// never a new clock, receipt-shaped DTO, worker slot or public capability.
#[derive(Clone)]
pub(crate) struct PublicationControl {
    owner: Weak<Owner>,
    inner: Weak<Inner>,
}
impl PublicationControl {
    fn new(owner: &Arc<Owner>, inner: &Arc<Inner>) -> Self {
        Self {
            owner: Arc::downgrade(owner),
            inner: Arc::downgrade(inner),
        }
    }
    pub(crate) fn current(&self) -> bool {
        self.owner.upgrade().is_some_and(|o| {
            let s = lock(&o.state);
            matches!(o.profile, Profile::GitHubPublication)
                && !s.terminal
                && !s.unknown
                && s.error.is_none()
                && Instant::now() < s.endpoint
                && !*o.stop.borrow()
        })
    }
    pub(crate) fn work_end(&self) -> Option<Instant> {
        self.owner.upgrade().map(|o| o.endpoint())
    }
    pub(crate) fn cleanup_end(&self) -> Option<Instant> {
        let o = self.owner.upgrade()?;
        let s = lock(&o.state);
        if s.terminal || s.unknown {
            return None;
        }
        let h = s.endpoint.checked_add(CLEANUP_TIME)?;
        Some(s.cleanup_endpoint.map_or(h, |f| f.min(h)))
    }
    pub(crate) fn cleanup_current(&self) -> bool {
        self.cleanup_end().is_some_and(|e| Instant::now() < e)
    }
    pub(crate) fn management_returned(&self) -> bool {
        self.owner.upgrade().is_some_and(|o| {
            let s = lock(&o.state);
            matches!(o.profile, Profile::GitHubPublication)
                && s.management_ready()
                && !s.terminal
                && !s.unknown
        })
    }
    pub(crate) fn stop_clock(&self) -> Option<watch::Receiver<bool>> {
        Some(self.owner.upgrade()?.stop.subscribe())
    }
    pub(crate) fn fail_at(&self, error: BridgeError, at: Instant) {
        if let Some(o) = self.owner.upgrade() {
            let mut s = lock(&o.state);
            if s.terminal {
                return;
            }
            s.fail_at(error, at);
            drop(s);
            o.stop.send_replace(true);
            o.changed.notify_waiters();
        }
    }
    pub(crate) fn unknown(&self) {
        if let (Some(o), Some(i)) = (self.owner.upgrade(), self.inner.upgrade()) {
            o.unknown(&i);
        }
    }
}
pub(super) async fn prepare_counter(
    inner: &Arc<Inner>,
    owner: &Arc<Owner>,
) -> Result<(), BridgeError> {
    let Some(gate) = &owner.publication_gate else {
        return Err(BridgeError::cleanup_unknown());
    };
    gate.prepare_counter(PublicationControl::new(owner, inner))
        .await
}
pub(super) async fn finalize_counter(inner: &Arc<Inner>, owner: &Arc<Owner>) -> bool {
    let Some(gate) = &owner.publication_gate else {
        return false;
    };
    gate.finalize_counter(PublicationControl::new(owner, inner))
        .await
}
impl GitHubPublicationTicket {
    pub(crate) fn counter_proof(&self) -> Option<Arc<crate::asset_session::CounterStateProof>> {
        if !matches!(
            &*lock(&self.receipt),
            GitHubPublicationReceipt::Settled {
                was_unknown: false,
                ..
            }
        ) {
            return None;
        }
        self.owner.publication_gate.as_ref()?.counter_proof()
    }
}
