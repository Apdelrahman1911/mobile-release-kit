//! One current original profile review, and detached saved-record DATA. A
//! terminal/status/parsed journal row cannot reconstruct the private review.
use super::*;
use crate::apple_provisioning_journal::ProfileAction;

pub(super) struct Review {
    input: Arc<crate::asset_session::AppleProvisioningDocumentInput>,
    data: apple_wire::ProfileReviewData,
    expires: Instant,
    used: AtomicBool,
}
impl Review {
    pub(super) fn census_input(&self) -> &Arc<crate::asset_session::AppleProvisioningDocumentInput> { &self.input }
    pub(super) fn matches(
        &self,
        input: &crate::asset_session::AppleProvisioningDocumentInput,
        now: Instant,
    ) -> bool {
        now < self.expires
            && !self.used.load(Ordering::SeqCst)
            && input.context().mode.profile_save()
            && (input.context().mode == apple_wire::Mode::ProfileReuse)
                == (self.data.selection.action == ProfileAction::ReuseDownload)
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
            && self.input.same_selection(input)
    }
    pub(super) fn expires(&self) -> Instant {
        self.expires
    }
    pub(super) fn data(&self) -> apple_wire::ProfileReviewData {
        self.data.clone()
    }
}

pub(super) struct SavedPublication {
    reference: apple_wire::Reference,
    context: apple_wire::Context,
    record: crate::credential_setup::KeyReference,
}

pub(super) fn publish(
    registry: &mut Registry,
    active: &super::super::Active,
    owner: &Arc<Session>,
    terminal: &apple_wire::Terminal,
) {
    let Context::AppleProvisioning(context) = &owner.context else {
        return;
    };
    let Some(result) = terminal
        .result
        .as_ref()
        .and_then(apple_wire::ResultData::profile)
    else {
        return;
    };
    let reference = apple_wire::Reference {
        operation_id: owner.id.clone(),
        owner_generation: owner.generation.clone(),
    };
    if context.mode.profile_save()
        && result.decision == apple_wire::ProfileDecision::DownloadReturned
    {
        if let Some(record) = super::super::apple_signing::saved_reference(owner) {
            registry.profile_saved = Some(SavedPublication {
                reference,
                context: context.clone(),
                record,
            });
        }
        return;
    }
    if context.mode != apple_wire::Mode::ProfileReview
        || active.projection.outcome != Some(Outcome::Complete)
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
        || route.received != 2
        || route.completed != 2
        || route.ack_writing
    {
        return;
    }
    let Some((observed, at)) = &route.profile_observed else {
        return;
    };
    let Some(selection) = &observed.selection else {
        return;
    };
    if !observed.available
        || !observed.relationships_complete
        || !matches!(
            observed.decision,
            apple_wire::ProfileDecision::ReuseAvailable
                | apple_wire::ProfileDecision::CreateAvailable
        )
        || result.decision != observed.decision
        || result.reason != observed.reason
    {
        return;
    }
    let Some(expires) = at.checked_add(Duration::from_secs(300)) else {
        return;
    };
    if Instant::now() >= expires {
        return;
    }
    registry.profile_review = Some(Arc::new(Review {
        input: input.clone(),
        data: apple_wire::ProfileReviewData {
            reference,
            observed_at: observed.observed_at.clone(),
            valid_until: observed.valid_until.clone(),
            selection: selection.clone(),
        },
        expires,
        used: AtomicBool::new(false),
    }));
}

pub(super) fn project(registry: &Registry, projection: &mut apple_wire::Projection) {
    projection.saved_profile = None;
    let Some(saved) = &registry.profile_saved else {
        return;
    };
    if projection.operation_id == saved.reference.operation_id
        && projection.owner_generation == saved.reference.owner_generation
        && projection.context == saved.context
        && projection.context.mode.profile_save()
        && projection.phase == apple_wire::Phase::Terminal
        && projection.outcome == Some(apple_wire::Outcome::Complete)
        && projection.reason == apple_wire::Reason::None
        && projection
            .result
            .as_ref()
            .and_then(apple_wire::ResultData::profile)
            .is_some_and(|result| result.decision == apple_wire::ProfileDecision::DownloadReturned)
    {
        projection.saved_profile = Some(saved.record.clone());
    }
}
