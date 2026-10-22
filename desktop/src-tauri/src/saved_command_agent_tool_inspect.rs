//! Saved Inspect or exactly reviewed Acquire inside the existing Tool Intent/registry.
//! No source, worker, grant or clock is constructed from a service Status.
use super::*;
use std::sync::atomic::AtomicU8;

const UNUSED: u8 = 0;
const CAPTURING: u8 = 1;
const RETURNED: u8 = 2;
const UNCERTAIN: u8 = 3;

fn clipped_end(
    prepared: Instant,
    approved: Instant,
    scope: &req::NativeScope,
    now: Instant,
) -> Result<Instant, BridgeError> {
    let end = prepared
        .min(approved)
        .min(scope.expires)
        .min(scope.read.end());
    if now >= end || scope.current(false, now).is_err() {
        return Err(refused());
    }
    Ok(end)
}
enum OriginalInput {
    SavedInspect,
    ReviewedAcquire(super::acquire::Original),
}
pub(crate) struct Approval {
    original: OriginalInput,
    owner: Weak<Inner>,
    source: Arc<crate::asset_session::ToolAcquisitionDocumentInput>,
    expires: Instant,
    review: p::Review,
}
impl Approval {
    pub(super) fn reviewed(owner: &Arc<Inner>, source: Arc<crate::asset_session::ToolAcquisitionDocumentInput>,
        expires: Instant, review: p::Review, original: super::acquire::Original) -> Arc<Self> {
        Arc::new(Self { owner: Arc::downgrade(owner), source, expires, review,
            original: OriginalInput::ReviewedAcquire(original) })
    }
    fn current_registry(&self, r: &super::super::super::Registry) -> bool {
        self.source.current() && match &self.original {
            OriginalInput::SavedInspect => self.review.kind == p::Kind::InspectSavedRequirements
                && self.review.acquisition.is_none() && self.source.context().action == wire::Action::Inspect
                && self.source.context().review.is_none(),
            OriginalInput::ReviewedAcquire(original) => self.review.kind == p::Kind::AcquireReviewedMissing
                && self.review.acquisition.as_ref().is_some_and(|selected| original.matches_registry(r, &self.source, selected)),
        }
    }
    fn matches_intent(&self, intent: &Intent) -> bool {
        match &self.original {
            OriginalInput::SavedInspect => intent.inspection.is_none()
                && intent.document.context().action == wire::Action::Inspect
                && intent.document.context().review.is_none(),
            OriginalInput::ReviewedAcquire(original) => self.review.acquisition.as_ref()
                .is_some_and(|selected| original.matches_intent(intent, selected)),
        }
    }
    pub(crate) fn review(&self) -> &p::Review {
        &self.review
    }
    pub(crate) fn expires(&self) -> Instant {
        self.expires
    }
    pub(crate) fn source(&self) -> &Arc<crate::asset_session::ToolAcquisitionDocumentInput> {
        &self.source
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(4 * std::mem::size_of::<usize>())?
            .checked_add(self.source.retained_bytes()?)?
            .checked_add(self.review.acquisition.as_ref().map_or(Some(0), p::Acquisition::retained_bytes)?)
    }
}
struct Created {
    binding: Arc<super::Binding>,
    operation: p::Operation,
}
pub(crate) struct Binding {
    approval: Arc<Approval>,
    link: Arc<req::NativeLink>,
    capture: AtomicU8,
    created: std::sync::OnceLock<Created>,
}
impl Binding {
    pub(crate) fn source(&self) -> &Arc<crate::asset_session::ToolAcquisitionDocumentInput> {
        self.approval.source()
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let mut n = self
            .approval
            .retained_bytes()?
            .checked_add(std::mem::size_of::<Self>() + 4 * std::mem::size_of::<usize>())?;
        if let Some(c) = self.created.get() {
            n = n
                .checked_add(c.binding.retained_bytes()?)?
                .checked_add(64)?;
        }
        Some(n)
    }
    pub(crate) fn begin(&self, entry: &Arc<req::Entry>) -> Result<(), BridgeError> {
        if !self.link.matches(entry)
            || self.link.scope().current(false, Instant::now()).is_err()
            || !self.source().current()
        {
            return Err(refused());
        }
        self.capture
            .compare_exchange(UNUSED, CAPTURING, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| refused())
    }
    // The synchronous original Prepare has genuinely returned. Its committed
    // binding, not !has_entered(), distinguishes Prepared from nonadmission.
    pub(crate) fn returned(&self, result: &Result<wire::Status, BridgeError>) {
        let known = !result.as_ref().is_err_and(|e| e.code == "cleanup_unknown")
            && (result.is_err() || self.created.get().is_some());
        if self
            .capture
            .compare_exchange(
                CAPTURING,
                if known { RETURNED } else { UNCERTAIN },
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
            || !known
        {
            self.link.unknown();
        }
    }
    pub(crate) fn start(&self) -> Result<wire::Start, BridgeError> {
        if self.capture.load(Ordering::Acquire) != RETURNED {
            return Err(refused());
        }
        let c = self.created.get().ok_or_else(refused)?;
        wire::start(&serde_json::json!({"operationId":c.operation.operation_id,
            "ownerGeneration":c.operation.owner_generation,"consentVersion":wire::CONSENT}))
    }
}

/// Optional argument of the original generic Prepared constructor. Fields are
/// private: only the actual Tool census/Intent path can create this value.
pub(in crate::saved_command_owner) struct Preparation {
    binding: Arc<Binding>,
    intent: Arc<Intent>,
}
impl Preparation {
    pub(in crate::saved_command_owner) fn new(
        binding: Arc<Binding>,
        intent: Arc<Intent>,
    ) -> Result<Self, BridgeError> {
        if binding.capture.load(Ordering::Acquire) != CAPTURING
            || binding.created.get().is_some()
            || !Arc::ptr_eq(&intent.document, binding.source())
            || !intent.current()
            || !binding.approval.matches_intent(&intent)
        {
            return Err(refused());
        }
        Ok(Self { binding, intent })
    }
    pub(in crate::saved_command_owner) fn clip_expiry(
        &self,
        expires: Instant,
    ) -> Result<Instant, BridgeError> {
        clipped_end(
            expires,
            self.binding.approval.expires,
            self.binding.link.scope(),
            Instant::now(),
        )
    }
    pub(in crate::saved_command_owner) fn link(
        self,
        owner: &Arc<Inner>,
        registry: &super::super::super::Registry,
        context: &Context,
        registration: u32,
        root: &RegisteredRoot,
        id: &str,
        generation: &str,
        expires: Instant,
    ) -> Result<Arc<Intent>, BridgeError> {
        let Context::ToolAcquisition(c) = context else {
            return Err(refused());
        };
        if self.binding.approval.owner.as_ptr() != Arc::as_ptr(owner)
            || !self.binding.approval.current_registry(registry)
            || !self.binding.approval.matches_intent(&self.intent)
            || !self.intent.document.matches(c, registration, root)
            || self.clip_expiry(expires)? != expires
            || self.binding.created.get().is_some()
        {
            return Err(refused());
        }
        let operation = p::Operation {
            operation_id: Id::parse(id).map_err(|_| refused())?,
            owner_generation: Some(Id::parse(generation).map_err(|_| refused())?),
            registration_generation: None,
        };
        // No renderer Prepared and no NativeLink::entered. The new typed
        // approval records the actual clipped endpoint, not a fresh grant.
        let bound = Arc::new(super::Binding {
            approval: Arc::new(super::Approval {
                owner: Arc::downgrade(owner),
                intent: Arc::downgrade(&self.intent),
                context: c.clone(),
                registration,
                root: root.clone(),
                expires,
                review: self.binding.approval.review.clone(),
            }),
            link: self.binding.link.clone(),
        });
        self.intent
            .agent
            .set(bound.clone())
            .map_err(|_| refused())?;
        // Last fallible operation before the same registry assigns Prepared
        // and bumps. If publication panics/loses its reply, keep this original.
        self.binding
            .created
            .set(Created {
                binding: bound,
                operation,
            })
            .map_err(|_| refused())?;
        Ok(self.intent)
    }
}

#[cfg(test)]
#[path = "saved_command_agent_tool_inspect_tests.rs"]
mod tests;

impl SavedCommandOwner {
    pub(crate) fn tool_setup_saved_inspect_approval(
        &self,
        source: Arc<crate::asset_session::ToolAcquisitionDocumentInput>,
        now: Instant,
    ) -> Result<Arc<Approval>, BridgeError> {
        self.require_domain(SavedCommandDomain::ToolAcquisition)?;
        let c = source.context();
        if !source.current()
            || !c.valid()
            || c.action != wire::Action::Inspect
            || c.review.is_some()
        {
            return Err(refused());
        }
        let mut r = self.inner.lock();
        self.inner.expire_prepared(&mut r, now);
        if self.inner.availability(&r, Availability::Available) != Availability::Available {
            return Err(refused());
        }
        let review = p::Review {
            kind: p::Kind::InspectSavedRequirements,
            platform: p::Platform::Android,
            draft_revision: c.draft_revision,
            baseline_generation: c.baseline_generation,
            prepared: None,
            sources: None,
            acquisition: None,
        };
        Ok(Arc::new(Approval {
            original: OriginalInput::SavedInspect,
            owner: Arc::downgrade(&self.inner),
            source,
            expires: now + INTENT,
            review,
        }))
    }
    pub(crate) fn bind_tool_setup_saved_inspect(
        &self,
        approval: Arc<Approval>,
        link: Arc<req::NativeLink>,
    ) -> Result<Arc<Binding>, BridgeError> {
        let mut r = self.inner.lock();
        self.inner.expire_prepared(&mut r, Instant::now());
        if approval.owner.as_ptr() != Arc::as_ptr(&self.inner)
            || !approval.current_registry(&r)
            || self.inner.availability(&r, Availability::Available) != Availability::Available
            || link.scope().review != approval.review
            || link.scope().expires > approval.expires
            || link.scope().current(false, Instant::now()).is_err()
        {
            return Err(refused());
        }
        Ok(Arc::new(Binding {
            approval,
            link,
            capture: AtomicU8::new(UNUSED),
            created: std::sync::OnceLock::new(),
        }))
    }
    pub(crate) fn stop_tool_setup_saved_inspect(&self, b: &Binding, why: p::Reason, at: Instant) {
        b.link.cancel(why, at);
        if let Some(c) = b.created.get() {
            // Actual Prepared retirement, including submitted Prepare then
            // Revoke before Start, follows the existing original registry.
            self.stop_tool_setup_acquisition(&c.binding, why, at);
        } else {
            match b.capture.load(Ordering::Acquire) {
                UNUSED | RETURNED => b.link.refused_unentered(why),
                CAPTURING => {} // The original capture must actually return.
                _ => b.link.unknown(),
            }
        }
    }
}
