//! Two fixed adapters into the original publication owner, not a new executor.
use super::*;
use crate::{
    github_publication_protocol as p, service_github_action_protocol as wire,
    service_github_action_requests::Entry,
};
impl DocumentBinding {
    pub(super) fn github_publication_agent_start(
        &self,
        entry: &Arc<Entry>,
    ) -> Result<(), BridgeError> {
        // Public selection is not request input. Use only the installed native
        // scope; the original adapter repeats its actual identity/Edit checks.
        let command = match &entry.scope().review {
            wire::Review::SetupPublish(v) => p::Command::Publish(p::PublishArgs {
                session_id: v.session_id.clone(),
                expected_revision: v.expected_revision,
                consent_id: v.consent_id.clone(),
                confirm: true,
            }),
            wire::Review::SetupReconcile(v) => p::Command::Reconcile(p::ReconcileArgs {
                session_id: v.session_id.clone(),
                expected_revision: v.expected_revision,
                marker: v.marker.clone(),
            }),
            _ => return Err(BridgeError::invalid()),
        };
        // No app-data/path authority is fabricated. The original method refuses
        // Counter BEFORE attempting its native state/Host facet.
        self.github_publication_execute(command, None, Some(entry.clone()))?;
        Ok(())
    }
}
