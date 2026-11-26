//! One source-bound Inspect through the original ToolSetup grant/relay.
use super::*;
use crate::tool_acquisition_protocol as wire;

pub(super) fn same_saved_config(
    c: &wire::Context,
    saved: Option<&crate::agent_local_checks::Config>,
) -> bool {
    saved.is_some_and(|s| s.bytes == c.saved_config.bytes && s.sha256 == c.saved_config.sha256)
}
impl DocumentBinding {
    pub(super) fn saved_tool_inspect_approval(
        &self,
        state: &DocumentState,
        args: &mut Allow,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
        now: Instant,
    ) -> Result<Arc<AgentToolInspectApproval>, BridgeError> {
        if args.review.kind != p::Kind::InspectSavedRequirements
            || !args.review.valid()
            || args.doctor_draft.is_some()
            || args.license_acknowledged
            || args.native_consent.as_deref() != Some(wire::CONSENT)
        {
            return Err(BridgeError::invalid());
        }
        let c = wire::prepare(
            &args
                .source_context
                .take()
                .ok_or_else(BridgeError::invalid)?,
        )?;
        if c.project_id != args.project_id
            || c.draft_revision != args.review.draft_revision
            || c.baseline_generation != args.review.baseline_generation
            || c.action != wire::Action::Inspect
            || c.review.is_some()
        {
            return Err(BridgeError::invalid());
        }
        // Only the existing genuine returned saved lane can satisfy this
        // digest. No saved read/catalogue action is started by Allow.
        let source = self.tool_inspect_input(state, &c, edit)?;
        self.inner
            .bridge
            .tool_acquisition
            .tool_setup_saved_inspect_approval(source, now)
    }
    pub(super) fn admit_saved_tool_inspect(
        &self,
        binding: &Arc<AgentToolInspectBinding>,
        entry: &Arc<req::Entry>,
    ) -> Result<(), BridgeError> {
        binding.begin(entry)?;
        // This original synchronous caller is retained even when the eventual
        // Prepared status cannot be delivered. Never bind a latest Status.
        let result = self.prepare_tool_acquisition_bound(
            binding.source().context().clone(),
            Some((binding, entry)),
        );
        binding.returned(&result);
        result?;
        // Original one-use action/Read/STOP checks run again in normal Start.
        // Its work endpoint began at Submit, not at this later Prepare return.
        self.start_tool_acquisition_agent(binding.start()?, entry.submitted_at(), Some(entry))
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_service_saved_config_must_equal_the_original_allow_context() {
        let context = wire::prepare(
            &serde_json::json!({"projectId":"p1", "draftRevision":1, "baselineGeneration":2,
            "savedConfig":{"bytes":7,"sha256":"a".repeat(64)}, "action":"inspect", "review":null}),
        )
        .unwrap();
        let mut saved = crate::agent_local_checks::Config {
            bytes: 7,
            sha256: "a".repeat(64),
        };
        assert!(same_saved_config(&context, Some(&saved)));
        assert!(!same_saved_config(&context, None));
        saved.bytes = 8;
        assert!(!same_saved_config(&context, Some(&saved)));
        saved.bytes = 7;
        saved.sha256 = "b".repeat(64);
        assert!(!same_saved_config(&context, Some(&saved)));
    }
}
