//! A weak comparison to the SAME positively joined requirements Inspection.
//! This child cannot nominate folders, manufacture missing tools, or run a job.
use super::*;

pub(super) struct Original {
    inspection: Weak<Inspection>,
}
impl Original {
    fn current_inspection(&self, r: &super::super::super::Registry) -> Option<Arc<Inspection>> {
        let original = self.inspection.upgrade()?;
        r.tool_acquisition.review.as_ref().filter(|current| Arc::ptr_eq(current, &original))?;
        Some(original)
    }
    fn selected(inspection: &Inspection) -> Option<p::Acquisition> {
        let parts = inspection.terminal.components()?;
        let all = [p::Component::Jdk, p::Component::AndroidPlatform,
            p::Component::AndroidBuildTools, p::Component::Gradle];
        // A filtered iterator of this small enum may grow a Vec to eight.
        // Keep both retained lists inside their original four-slot allowance.
        let mut missing = Vec::with_capacity(4);
        let mut compatible = Vec::with_capacity(4);
        for (index, component) in all.into_iter().enumerate() {
            if parts.is_compatible(index) { compatible.push(component); }
            else { missing.push(component); }
        }
        let value = p::Acquisition {
            operation_id: Id::parse(&inspection.original.id).ok()?,
            owner_generation: Id::parse(&inspection.original.generation).ok()?,
            requirements_sha256: inspection.terminal.result.as_ref()?
                .get("requirements")?.get("sourcesSha256")?.as_str()?.to_owned(),
            missing,
            compatible,
        };
        value.valid().then_some(value)
    }
    fn matches_source(inspection: &Inspection, source: &crate::asset_session::ToolAcquisitionDocumentInput) -> bool {
        let Some(original) = inspection.original.tools.intent.as_ref() else { return false; };
        inspection.matches(source.context(), inspection.original.registration, &inspection.original.project)
            && !inspection.terminal.discovered_sources().is_some_and(|d| d.needs_selection())
            && source.same_saved_binding(&original.document)
            && original.current()
    }
    pub(super) fn matches_registry(&self, r: &super::super::super::Registry,
        source: &crate::asset_session::ToolAcquisitionDocumentInput, selection: &p::Acquisition) -> bool {
        self.current_inspection(r).is_some_and(|original| {
            Self::matches_source(&original, source)
                && Self::selected(&original).as_ref() == Some(selection)
        })
    }
    pub(super) fn matches_intent(&self, intent: &Intent, selection: &p::Acquisition) -> bool {
        self.inspection.upgrade().is_some_and(|original| {
            intent.inspection.as_ref().is_some_and(|current| Arc::ptr_eq(current, &original))
                && Self::matches_source(&original, &intent.document)
                && Self::selected(&original).as_ref() == Some(selection)
                && original.original.tools.intent.as_ref().is_some_and(|before| intent.known.same(&before.known))
        })
    }
}
impl SavedCommandOwner {
    pub(crate) fn tool_setup_reviewed_acquire_approval(
        &self, source: Arc<crate::asset_session::ToolAcquisitionDocumentInput>,
        selected: p::Acquisition, now: Instant,
    ) -> Result<Arc<inspect::Approval>, BridgeError> {
        self.require_domain(SavedCommandDomain::ToolAcquisition)?;
        if !selected.valid() || !source.context().valid() || source.context().action != wire::Action::Acquire {
            return Err(refused());
        }
        let mut r = self.inner.lock();
        self.inner.expire_prepared(&mut r, now);
        if self.inner.availability(&r, Availability::Available) != Availability::Available {
            return Err(refused());
        }
        let original = Original {
            inspection: Arc::downgrade(r.tool_acquisition.review.as_ref().ok_or_else(refused)?),
        };
        if !original.matches_registry(&r, &source, &selected) { return Err(refused()); }
        let c = source.context();
        let review = p::Review {
            kind: p::Kind::AcquireReviewedMissing, platform: p::Platform::Android,
            draft_revision: c.draft_revision, baseline_generation: c.baseline_generation,
            prepared: None, sources: None, acquisition: Some(selected),
        };
        Ok(inspect::Approval::reviewed(&self.inner, source, now + INTENT, review, original))
    }
}

#[cfg(test)]
#[path = "saved_command_agent_tool_acquire_tests.rs"]
mod tests;
