//! Exact original acquisition selection at the existing MAIN Doc/Edit cuts.
//! Public comparison fields never supply a source picker, Inspection or permit.
use super::*;
use crate::tool_acquisition_protocol as wire;

fn matches_context(c: &wire::Context, review: &p::Review, project: &str) -> bool {
    c.valid() && review.valid() && review.kind == p::Kind::AcquireReviewedMissing
        && c.project_id == project && c.draft_revision == review.draft_revision
        && c.baseline_generation == review.baseline_generation && c.action == wire::Action::Acquire
        && match (&c.review, &review.acquisition) {
            (Some(native), Some(selected)) => native.operation_id == selected.operation_id.as_str()
                && native.owner_generation == selected.owner_generation.as_str()
                && native.requirements_sha256 == selected.requirements_sha256,
            _ => false,
        }
}
impl DocumentBinding {
    pub(super) fn reviewed_tool_acquire_approval(
        &self, state: &DocumentState, args: &mut Allow,
        edit: &crate::edit_owner::SavedEditGuard<'_>, now: Instant,
    ) -> Result<Arc<AgentToolInspectApproval>, BridgeError> {
        if args.doctor_draft.is_some() || args.license_acknowledged
            || args.native_consent.as_deref() != Some(wire::CONSENT) {
            return Err(BridgeError::invalid());
        }
        let context = wire::prepare(&args.source_context.take().ok_or_else(BridgeError::invalid)?)?;
        if !matches_context(&context, &args.review, &args.project_id) { return Err(BridgeError::invalid()); }
        let source = self.tool_reviewed_acquire_input(state, &context, edit)?;
        self.inner.bridge.tool_acquisition.tool_setup_reviewed_acquire_approval(source,
            args.review.acquisition.clone().ok_or_else(BridgeError::invalid)?, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn acquisition_allow_requires_exact_inspection_context_and_old_consents_cannot_gain_it() {
        let raw = json!({"projectId":"p1","draftRevision":1,"baselineGeneration":2,
            "savedConfig":{"bytes":120,"sha256":"a".repeat(64)},"action":"acquire",
            "review":{"operationId":"1".repeat(32),"ownerGeneration":"2".repeat(32),"requirementsSha256":"b".repeat(64)}});
        let context = wire::prepare(&raw).unwrap();
        let review: p::Review = serde_json::from_value(json!({"kind":"acquire-reviewed-missing","platform":"android",
            "draftRevision":1,"baselineGeneration":2,"prepared":null,"sources":null,
            "acquisition":{"operationId":"1".repeat(32),"ownerGeneration":"2".repeat(32),"requirementsSha256":"b".repeat(64),
                "missing":["android-build-tools"],"compatible":["jdk","android-platform","gradle"]}})).unwrap();
        assert!(matches_context(&context, &review, "p1"));
        for (field, value) in [("operationId", "3".repeat(32)), ("ownerGeneration", "4".repeat(32)), ("requirementsSha256", "c".repeat(64))] {
            let mut other = raw.clone(); other["review"][field] = value.into();
            assert!(!matches_context(&wire::prepare(&other).unwrap(), &review, "p1"));
        }
        assert!(!matches_context(&context, &review, "p2"));
        let mut different = review.clone(); different.draft_revision += 1;
        assert!(!matches_context(&context, &different, "p1"));
        for kind in [p::Kind::InspectSavedRequirements, p::Kind::AcquireMissing, p::Kind::RegisterReviewedSources] {
            different = review.clone(); different.kind = kind;
            assert!(!matches_context(&context, &different, "p1"));
            assert_ne!(kind.consent(), review.kind.consent());
        }
        assert_eq!(review.kind.action(), crate::service_protocol::Action::PrepareTools);
    }
}
