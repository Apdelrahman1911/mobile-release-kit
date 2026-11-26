//! Authenticated comparison/enqueue only. No native owner, Window, engine or
//! filesystem executor is called by IPC. The real main Webview continues it.
use super::*;
use crate::{service_metadata_text_protocol as wire, service_metadata_text_requests as requests};

impl ApplicationService {
    fn metadata_text_client(
        &self,
        state: &State,
        client: &ClientSession,
        project: &Id,
    ) -> Result<(), Error> {
        self.check(state)?;
        let grant = live_grant(state)?;
        if client.instance != self.instance
            || client.grant_id != grant.id
            || !grant.projects.contains(project)
        {
            return Err(Error::AccessDenied);
        }
        Ok(())
    }
    pub(super) fn metadata_text_read(
        &self,
        client: &ClientSession,
        input: wire::Read,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.metadata_text_client(&state, client, &input.origin.project_id)?;
        let point = Self::identity_point(&state, &input.origin.project_id)?;
        let prior = self
            .configuration_requests
            .metadata_entry(&input.origin)
            .ok();
        if prior.is_none()
            && (!point.fresh
                || !state
                    .saved
                    .projects
                    .iter()
                    .find(|p| p.binding.project_id == input.origin.project_id)
                    .and_then(|p| p.observation.as_ref())
                    .is_some_and(|p| p.configuration.state == p::ConfigurationState::FormatValid))
        {
            return Err(Error::Conflict);
        }
        let result = self.configuration_requests.metadata_read(
            input,
            requests::Source {
                runtime_id: point.runtime_id,
                root: point.root,
                device: point.device,
                inode: point.inode,
                observation_revision: point.revision,
            },
            live_grant(&state)?.reserve_read.clone(),
        );
        drop(state);
        result.map(p::ResponseBody::MetadataTextRequest)
    }
    pub(super) fn metadata_text_prepare(
        &self,
        client: &ClientSession,
        input: wire::Prepare,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.metadata_text_client(&state, client, &input.origin.project_id)?;
        let result = self
            .configuration_requests
            .metadata_entry(&input.origin)?
            .prepare(input);
        drop(state);
        result.map(p::ResponseBody::MetadataTextRequest)
    }
    pub(super) fn metadata_text_apply(
        &self,
        client: &ClientSession,
        input: wire::Apply,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.metadata_text_client(&state, client, &input.origin.project_id)?;
        let result = self
            .configuration_requests
            .metadata_entry(&input.origin)?
            .apply(input);
        drop(state);
        result.map(p::ResponseBody::MetadataTextRequest)
    }
    pub(super) fn metadata_text_query(
        &self,
        client: &ClientSession,
        q: &wire::Query,
        cancel: bool,
    ) -> Result<p::ResponseBody, Error> {
        let requested_at = Instant::now();
        let state = self.lock()?;
        self.metadata_text_client(&state, client, &q.project_id)?;
        // A replacement READ can observe/STOP the exact old request, but cannot
        // renew its original READ facet, source, permission, or native session.
        let entry = self.configuration_requests.metadata_entry(q)?;
        if cancel {
            entry.cancel(requested_at)?
        }
        let result = entry.status();
        drop(state);
        result.map(p::ResponseBody::MetadataTextRequest)
    }
    /// OFF Doc/Edit: original registration/grant comparison may read Store.
    /// The same facet (not just equal grant contents) must remain installed.
    pub(crate) fn metadata_text_current(
        &self,
        entry: &requests::Entry,
        opening: bool,
    ) -> Result<(), Error> {
        let state = self.lock()?;
        self.check(&state)?;
        let grant = live_grant(&state)?;
        if entry.input().origin.service_instance != self.instance
            || !grant.projects.contains(&entry.input().origin.project_id)
            || !Arc::ptr_eq(&grant.reserve_read, &entry.read)
            || !entry.live(Instant::now())
        {
            return Err(Error::AccessDenied);
        }
        let point = Self::identity_point(&state, &entry.input().origin.project_id)?;
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
    /// Existing retained shell relay, OFF Doc/Edit. Only a final observer or
    /// absorbing unknown original makes a row eligible. First write is new-ID
    /// CAS; a lost history ACK never triggers another write or edit replay.
    pub(crate) fn publish_metadata_text_history(&self) -> Result<(), Error> {
        for entry in self.configuration_requests.metadata_entries()? {
            if let Some((id, state, settlement)) = entry.history()? {
                if let Err(error) = self.begin_operation(
                    &entry.source.runtime_id,
                    id,
                    p::Action::EditMetadataText,
                    state,
                    settlement,
                ) {
                    self.fence_native_history();
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "service_metadata_text_application_tests.rs"]
mod tests;
