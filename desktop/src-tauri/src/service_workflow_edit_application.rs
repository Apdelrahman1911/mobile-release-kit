//! Only authentication and comparison/enqueue. Actual MAIN supplies its own
//! immutable draft and calls the original WorkflowEdit owner.
use super::*;
use crate::{
    service_configuration_requests::Source, service_workflow_edit_protocol as wire,
    service_workflow_edit_requests::Entry,
};
impl ApplicationService {
    pub(super) fn workflow_edit_prepare(
        &self,
        client: &ClientSession,
        input: wire::Prepare,
    ) -> Result<p::ResponseBody, Error> {
        if !wire::platform_supported() { return Err(Error::Unavailable); }
        input.validate()?;
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &input.origin.project_id)?;
        let point = Self::identity_point(&state, &input.origin.project_id)?;
        if self
            .configuration_requests
            .workflow_edit_entry(&input.origin)
            .is_err()
            && !point.fresh
        {
            return Err(Error::Conflict);
        }
        // Missing/invalid saved configuration is not a refusal here. The
        // genuine workflow_edit core, not this observation, inspects conflicts.
        self.configuration_requests
            .workflow_edit_prepare(
                input,
                Source {
                    runtime_id: point.runtime_id,
                    root: point.root,
                    device: point.device,
                    inode: point.inode,
                    observation_revision: point.revision,
                },
                live_grant(&state)?.reserve_read.clone(),
            )
            .map(p::ResponseBody::WorkflowEditRequest)
    }
    pub(super) fn workflow_edit_apply(
        &self,
        client: &ClientSession,
        input: wire::Apply,
    ) -> Result<p::ResponseBody, Error> {
        if !wire::platform_supported() { return Err(Error::Unavailable); }
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &input.origin.project_id)?;
        self.configuration_requests
            .workflow_edit_entry(&input.origin)?
            .apply(input)
            .map(p::ResponseBody::WorkflowEditRequest)
    }
    pub(super) fn workflow_edit_query(
        &self,
        client: &ClientSession,
        q: &wire::Query,
        cancel: bool,
    ) -> Result<p::ResponseBody, Error> {
        let at = Instant::now();
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &q.project_id)?;
        let entry = self.configuration_requests.workflow_edit_entry(q)?;
        if cancel {
            entry.cancel(at)?;
        }
        entry.status().map(p::ResponseBody::WorkflowEditRequest)
    }
    pub(crate) fn workflow_edit_current(&self, entry: &Entry, opening: bool) -> Result<(), Error> {
        let state = self.lock()?;
        self.check(&state)?;
        let grant = live_grant(&state)?;
        if entry.input.origin.service_instance != self.instance
            || !grant.projects.contains(&entry.input.origin.project_id)
            || !Arc::ptr_eq(&entry.read, &grant.reserve_read)
            || !entry.live(Instant::now())
        {
            return Err(Error::AccessDenied);
        }
        let point = Self::identity_point(&state, &entry.input.origin.project_id)?;
        if point.runtime_id != entry.source.runtime_id
            || point.root != entry.source.root
            || point.device != entry.source.device
            || point.inode != entry.source.inode
            || opening && (!point.fresh || point.revision != entry.source.observation_revision)
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub(crate) fn publish_workflow_edit_history(&self) -> Result<(), Error> {
        for entry in self.configuration_requests.workflow_edit_entries()? {
            if let Some((id, state, settlement)) = entry.history()? {
                let result = self.begin_operation(
                    &entry.source.runtime_id,
                    id,
                    p::Action::EditGitHubWorkflows,
                    state,
                    settlement,
                );
                if entry.history_returned(result.is_ok()).is_err() || result.is_err() {
                    entry.unknown();
                    self.fence_native_history();
                    return Err(Error::StateUnknown);
                }
            }
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "service_workflow_edit_application_tests.rs"]
mod tests;
