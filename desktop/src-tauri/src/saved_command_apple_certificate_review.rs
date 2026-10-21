//! A private one-use certificate review and a separate detached history list.
//! Only the existing positive original retirement invokes these publishers.
use super::*;

pub(super) struct Review {
    input: Arc<crate::asset_session::AppleProvisioningDocumentInput>,
    data: apple_wire::CertificateReviewData,
    expires: Instant,
    used: AtomicBool,
}
impl Review {
    pub(super) fn census_input(&self) -> &Arc<crate::asset_session::AppleProvisioningDocumentInput> { &self.input }
    pub(super) fn matches(&self, input: &crate::asset_session::AppleProvisioningDocumentInput, now: Instant) -> bool {
        now < self.expires && !self.used.load(Ordering::SeqCst)
            && input.context().mode == apple_wire::Mode::CertificateCreate
            && input.context().reference.as_ref() == Some(&self.data.reference)
            && self.input.same_selection(input)
    }
    pub(super) fn claim(&self, input: &crate::asset_session::AppleProvisioningDocumentInput, now: Instant) -> Result<(), BridgeError> {
        if !self.matches(input,now) { return Err(apple_wire::invalid()); }
        self.used.compare_exchange(false,true,Ordering::SeqCst,Ordering::SeqCst).map(|_| ()).map_err(|_| apple_wire::invalid())
    }
    pub(super) fn current_claim(&self, input: &crate::asset_session::AppleProvisioningDocumentInput) -> bool {
        self.used.load(Ordering::SeqCst) && Instant::now() < self.expires
            && input.context().mode == apple_wire::Mode::CertificateCreate
            && input.context().reference.as_ref() == Some(&self.data.reference) && self.input.same_selection(input)
    }
    pub(super) fn expires(&self) -> Instant { self.expires }
    pub(super) fn data(&self) -> apple_wire::CertificateReviewData { self.data.clone() }
}
pub(super) struct Publication {
    reference: apple_wire::Reference, context: apple_wire::Context,
    history: apple_wire::CertificateRecoveryHistory,
}
pub(super) fn backing_bytes() -> Option<usize> {
    apple_wire::CERTIFICATE_RECOVERY_LIMIT.checked_mul(2)?
        .checked_add(apple_wire::IPC_LIMIT)?.checked_add(std::mem::size_of::<Publication>())?
        .checked_add(std::mem::size_of::<Review>())?.checked_add(16 * 1024)
}
pub(super) fn publish(registry: &mut Registry, owner: &Arc<Session>, terminal: &apple_wire::Terminal) {
    let Context::AppleProvisioning(context) = &owner.context else { return; };
    if context.mode != apple_wire::Mode::CertificateReview
        || owner.apple_key.get().is_none_or(|key| !key.clock().completed()) { return; }
    #[cfg(all(target_os="macos", target_pointer_width="64", any(target_arch="aarch64",target_arch="x86_64")))]
    if let Some(history) = super::native::certificate_history(owner) {
        registry.certificate_recovery=Some(Publication { reference:apple_wire::Reference {
            operation_id:owner.id.clone(),owner_generation:owner.generation.clone() }, context:context.clone(),history });
    }
    let Some(result) = terminal.result.as_ref().and_then(apple_wire::ResultData::certificate) else { return; };
    if result.decision != "request-review" || result.reason != "certificate-required" { return; }
    let Ok(input)=owner.apple.input() else { return; };
    let Ok(binding)=owner.apple.request_binding() else { return; };
    if binding.scope.certificate.as_ref().is_none_or(|scope| scope.key_preparation.is_none()) { return; }
    let Ok(route)=owner.apple.route.try_lock() else { return; };
    if route.failed || route.pending.is_some() || route.ack_writing || route.received != route.completed { return; }
    let Some((observed,at))=&route.certificate_observed else { return; };
    if observed.decision != result.decision || observed.reason != result.reason { return; }
    let Some(selection)=&observed.selection else { return; };
    let Some(expires)=review_expires(owner.clocks.admitted,*at) else { return; };
    if Instant::now() >= expires { return; }
    registry.certificate_review=Some(Arc::new(Review { input:input.clone(),expires,used:AtomicBool::new(false),
        data:apple_wire::CertificateReviewData { reference:apple_wire::Reference {
            operation_id:owner.id.clone(),owner_generation:owner.generation.clone() },
            observed_at:observed.observed_at.clone(),valid_until:observed.valid_until.clone(),selection:selection.clone() } }));
}
fn review_expires(admitted: Instant, received: Instant) -> Option<Instant> {
    Some(admitted.checked_add(Duration::from_secs(300))?.min(received.checked_add(Duration::from_secs(300))?))
}
pub(super) fn project(registry: &Registry, projection: &mut apple_wire::Projection) {
    projection.certificate_recovery=None;
    let Some(stored)=&registry.certificate_recovery else { return; };
    if projection.operation_id==stored.reference.operation_id && projection.owner_generation==stored.reference.owner_generation
        && projection.context==stored.context && projection.context.mode==apple_wire::Mode::CertificateReview
        && projection.phase==apple_wire::Phase::Terminal && projection.outcome==Some(apple_wire::Outcome::Complete)
        && projection.reason==apple_wire::Reason::None
        && projection.result.as_ref().and_then(apple_wire::ResultData::certificate).is_some() {
        projection.certificate_recovery=Some(stored.history.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn certificate_review_uses_original_admission_not_a_late_event_or_retirement() {
        let admitted=Instant::now(); let end=admitted+Duration::from_secs(300);
        for delay in [0,1,299,300,1200] {
            assert_eq!(review_expires(admitted,admitted+Duration::from_secs(delay)),Some(end));
        }
    }
}
