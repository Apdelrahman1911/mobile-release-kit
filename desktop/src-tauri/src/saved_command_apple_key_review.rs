//! Private, one-use local-key review from actual joined current inventories.
//! Saved key publication below is detached historical DATA, never a current
//! private-key loan, certificate-request consent or signing readiness.
use super::*;

pub(super) struct Review {
    input: Arc<crate::asset_session::AppleProvisioningDocumentInput>,
    data: apple_wire::KeyReviewData,
    expires: Instant,
    used: AtomicBool,
}

fn review_expires(admitted: Instant, received: Instant) -> Option<Instant> {
    // The provider's observation starts after admission and before this event.
    // Receiving or retiring a slow review must not renew its 300-second age.
    // The worker independently enforces its original UTC validUntil at Pending.
    Some(
        admitted
            .checked_add(Duration::from_secs(300))?
            .min(received.checked_add(Duration::from_secs(300))?),
    )
}
impl Review {
    pub(super) fn matches(
        &self,
        input: &crate::asset_session::AppleProvisioningDocumentInput,
        now: Instant,
    ) -> bool {
        now < self.expires
            && !self.used.load(Ordering::SeqCst)
            && input.context().mode == apple_wire::Mode::KeyPrepare
            && input.context().reference.as_ref() == Some(&self.data.reference)
            && self.input.same_selection(input)
    }
    pub(super) fn claim(
        &self,
        input: &crate::asset_session::AppleProvisioningDocumentInput,
        now: Instant,
    ) -> Result<(), BridgeError> {
        if !self.matches(input, now) {
            return Err(apple_wire::invalid());
        }
        self.used
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| ())
            .map_err(|_| apple_wire::invalid())
    }
    pub(super) fn current_claim(
        &self,
        input: &crate::asset_session::AppleProvisioningDocumentInput,
    ) -> bool {
        self.used.load(Ordering::SeqCst)
            && Instant::now() < self.expires
            && input.context().mode == apple_wire::Mode::KeyPrepare
            && input.context().reference.as_ref() == Some(&self.data.reference)
            && self.input.same_selection(input)
    }
    pub(super) fn expires(&self) -> Instant {
        self.expires
    }
    pub(super) fn data(&self) -> apple_wire::KeyReviewData {
        self.data.clone()
    }
}

pub(super) struct SavedPublication {
    reference: apple_wire::Reference,
    context: apple_wire::Context,
    record: crate::credential_setup::KeyReference,
}

pub(super) fn publish_saved(
    registry: &mut Registry,
    active: &super::super::Active,
    owner: &Arc<Session>,
) {
    let Context::AppleProvisioning(context) = &owner.context else {
        return;
    };
    if context.mode != apple_wire::Mode::KeyPrepare
        || active.unknown
        || !active.final_join_seen
        || !owner.watchdog_joined.load(Ordering::SeqCst)
        || owner.watchdog_failed.load(Ordering::SeqCst)
        || !owner.material_retired.load(Ordering::SeqCst)
        || owner.resource_unknown.load(Ordering::SeqCst)
        || !native_complete(owner)
    {
        return;
    }
    // This may describe a key preserved after a known cancellation. Keep that
    // original outcome/reason; never turn a preservation write into success.
    if let Some(record) = super::super::apple_key::saved_reference(owner) {
        registry.key_saved = Some(SavedPublication {
            reference: apple_wire::Reference {
                operation_id: owner.id.clone(),
                owner_generation: owner.generation.clone(),
            },
            context: context.clone(),
            record,
        });
    }
}

pub(super) fn publish_review(
    registry: &mut Registry,
    owner: &Arc<Session>,
    terminal: &apple_wire::Terminal,
) {
    let Context::AppleProvisioning(context) = &owner.context else {
        return;
    };
    if context.mode != apple_wire::Mode::KeyReview
        || owner
            .apple_key
            .get()
            .is_none_or(|key| !key.clock().completed())
    {
        return;
    }
    let Some(result) = terminal
        .result
        .as_ref()
        .and_then(apple_wire::ResultData::key)
    else {
        return;
    };
    let Ok(binding) = owner.apple.request_binding() else {
        return;
    };
    if binding
        .scope
        .key
        .as_ref()
        .and_then(|key| key.vault_inventory.as_ref())
        .is_none_or(|inventory| inventory.keys != 0)
    {
        return;
    }
    let Ok(input) = owner.apple.input() else {
        return;
    };
    let Ok(route) = owner.apple.route.try_lock() else {
        return;
    };
    if route.failed
        || route.pending.is_some()
        || route.received != 1
        || route.completed != 1
        || route.ack_writing
    {
        return;
    }
    let Some((observed, at)) = &route.key_observed else {
        return;
    };
    let Some(selection) = &observed.selection else {
        return;
    };
    if observed.decision != apple_wire::KeyDecision::PrepareReview
        || observed.reason != apple_wire::KeyReason::LocalKeyRequired
        || result.decision != observed.decision
        || result.reason != observed.reason
    {
        return;
    }
    let Some(expires) = review_expires(owner.clocks.admitted, *at) else {
        return;
    };
    if Instant::now() >= expires {
        return;
    }
    registry.key_review = Some(Arc::new(Review {
        input: input.clone(),
        expires,
        used: AtomicBool::new(false),
        data: apple_wire::KeyReviewData {
            reference: apple_wire::Reference {
                operation_id: owner.id.clone(),
                owner_generation: owner.generation.clone(),
            },
            observed_at: observed.observed_at.clone(),
            valid_until: observed.valid_until.clone(),
            selection: selection.clone(),
        },
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delayed_observation_never_renews_original_review_age() {
        let admitted = Instant::now();
        let end = admitted + Duration::from_secs(300);
        for delay in [0, 1, 299, 300, 1200] {
            let received = admitted + Duration::from_secs(delay);
            assert_eq!(review_expires(admitted, received), Some(end));
            if delay >= 300 {
                assert!(received >= review_expires(admitted, received).unwrap());
            }
        }
    }
}

pub(super) fn project(registry: &Registry, projection: &mut apple_wire::Projection) {
    projection.saved_key = None;
    let Some(saved) = &registry.key_saved else {
        return;
    };
    if projection.operation_id == saved.reference.operation_id
        && projection.owner_generation == saved.reference.owner_generation
        && projection.context == saved.context
        && projection.context.mode == apple_wire::Mode::KeyPrepare
        && projection.phase == apple_wire::Phase::Terminal
        && projection.reason != apple_wire::Reason::CleanupUnknown
    {
        projection.saved_key = Some(saved.record.clone());
    }
}
