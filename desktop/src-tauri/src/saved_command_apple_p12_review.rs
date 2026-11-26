//! Same-owner, one-use P12 review; detached saved DATA is never a new loan.
use super::*;
pub(super) struct Review {
    input: Arc<crate::asset_session::AppleProvisioningDocumentInput>,
    data: apple_wire::P12ReviewData,
    expires: Instant,
    used: AtomicBool,
}
fn expires(admitted: Instant, received: Instant) -> Option<Instant> {
    Some(
        admitted
            .checked_add(Duration::from_secs(300))?
            .min(received.checked_add(Duration::from_secs(300))?),
    )
}
impl Review {
    pub(super) fn census_input(&self) -> &Arc<crate::asset_session::AppleProvisioningDocumentInput> { &self.input }
    fn selection(&self, input: &crate::asset_session::AppleProvisioningDocumentInput) -> bool {
        let mode = input.context().mode;
        matches!(mode, apple_wire::Mode::P12Reuse | apple_wire::Mode::P12Save)
            && (mode == apple_wire::Mode::P12Reuse) == self.data.selected_p12.is_some()
            && input.context().reference.as_ref() == Some(&self.data.reference)
            && self.input.same_selection(input)
    }
    pub(super) fn matches(
        &self,
        input: &crate::asset_session::AppleProvisioningDocumentInput,
        now: Instant,
    ) -> bool {
        now < self.expires && !self.used.load(Ordering::SeqCst) && self.selection(input)
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
        self.used.load(Ordering::SeqCst) && Instant::now() < self.expires && self.selection(input)
    }
    pub(super) fn expires(&self) -> Instant {
        self.expires
    }
    pub(super) fn data(&self) -> apple_wire::P12ReviewData {
        self.data.clone()
    }
}
pub(super) struct SavedPublication {
    reference: apple_wire::Reference,
    context: apple_wire::Context,
    record: crate::credential_setup::KeyReference,
}
pub(super) fn backing_bytes() -> Option<usize> {
    std::mem::size_of::<Review>()
        .checked_add(std::mem::size_of::<SavedPublication>())?
        .checked_add(16 * 1024)
}
pub(super) fn publish_saved(
    registry: &mut Registry,
    active: &super::super::Active,
    owner: &Arc<Session>,
) {
    let Context::AppleProvisioning(context) = &owner.context else {
        return;
    };
    if context.mode != apple_wire::Mode::P12Save
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
    if let Some(record) = super::super::apple_key::saved_reference(owner) {
        registry.p12_saved = Some(SavedPublication {
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
    if context.mode != apple_wire::Mode::P12Review
        || owner
            .apple_key
            .get()
            .is_none_or(|parent| !parent.clock().completed())
    {
        return;
    }
    let Some(result) = terminal
        .result
        .as_ref()
        .and_then(apple_wire::ResultData::p12)
    else {
        return;
    };
    if !matches!(
        result.decision,
        apple_wire::P12Decision::AssembleReview | apple_wire::P12Decision::ReuseReview
    ) {
        return;
    }
    let Ok(input) = owner.apple.input() else {
        return;
    };
    let Ok(binding) = owner.apple.request_binding() else {
        return;
    };
    let Some(scope) = &binding.scope.p12 else {
        return;
    };
    if (result.decision == apple_wire::P12Decision::ReuseReview) != scope.selected_p12.is_some() {
        return;
    }
    let Ok(route) = owner.apple.route.try_lock() else {
        return;
    };
    if route.failed
        || route.pending.is_some()
        || route.ack_writing
        || route.received != route.completed
    {
        return;
    }
    let Some((observed, at)) = &route.p12_observed else {
        return;
    };
    if observed.decision != result.decision || observed.reason != result.reason {
        return;
    }
    let Some(selection) = &observed.selection else {
        return;
    };
    let Some(expires) = expires(owner.clocks.admitted, *at) else {
        return;
    };
    if Instant::now() >= expires {
        return;
    }
    registry.p12_review = Some(Arc::new(Review {
        input: input.clone(),
        expires,
        used: AtomicBool::new(false),
        data: apple_wire::P12ReviewData {
            reference: apple_wire::Reference {
                operation_id: owner.id.clone(),
                owner_generation: owner.generation.clone(),
            },
            observed_at: observed.observed_at.clone(),
            valid_until: observed.valid_until.clone(),
            selection: selection.clone(),
            selected_p12: scope.selected_p12.clone(),
        },
    }));
}
pub(super) fn project(registry: &Registry, projection: &mut apple_wire::Projection) {
    projection.saved_p12 = None;
    let Some(saved) = &registry.p12_saved else {
        return;
    };
    if projection.operation_id == saved.reference.operation_id
        && projection.owner_generation == saved.reference.owner_generation
        && projection.context == saved.context
        && projection.context.mode == apple_wire::Mode::P12Save
        && projection.phase == apple_wire::Phase::Terminal
        && !projection.intent_usable
        && projection
            .outcome
            .is_some_and(|outcome| outcome != apple_wire::Outcome::Unknown)
        && projection.reason != apple_wire::Reason::CleanupUnknown
    {
        projection.saved_p12 = Some(saved.record.clone());
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn p12_review_never_renews_at_received_or_retired_status() {
        let start = Instant::now();
        for delay in [0, 1, 299, 300, 1200] {
            assert_eq!(
                expires(start, start + Duration::from_secs(delay)),
                Some(start + Duration::from_secs(300))
            );
        }
    }
}
