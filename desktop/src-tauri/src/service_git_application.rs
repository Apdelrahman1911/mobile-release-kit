//! Fixed authenticated Stage/Unstage DATA on the existing service. The socket
//! never enters a Document, Git, source, runtime or publication owner.
use super::*;
use crate::{service_git_protocol as git, service_git_requests as requests};

impl ApplicationService {
    pub(crate) fn git_index_requests(&self) -> &Arc<requests::Inbox> {
        &self.git_index_requests
    }
    pub(crate) fn git_index_point(
        &self,
        runtime: &str,
    ) -> Result<crate::agent_identity_requests::SavedPoint, Error> {
        let state = self.lock()?;
        self.check(&state)?;
        let id = state.runtime_aliases.get(runtime).ok_or(Error::Conflict)?;
        if !live_grant(&state)?.projects.contains(id) {
            return Err(Error::AccessDenied);
        }
        let point = Self::identity_point(&state, id)?;
        if point.runtime_id != runtime {
            return Err(Error::Conflict);
        }
        // Git authority comes from the actual native Observe, not config
        // freshness or a passive snapshot. This copies only the saved binding.
        Ok(point)
    }
    fn git_index_authorize(
        &self,
        state: &State,
        client: &ClientSession,
        id: &Id,
    ) -> Result<(), Error> {
        self.authorize_build_client(state, client, id)?;
        Self::identity_point(state, id)?; // Current native runtime alias required.
        Ok(())
    }
    pub(super) fn git_index_scope(
        &self,
        client: &ClientSession,
        id: &Id,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.git_index_authorize(&state, client, id)?;
        let result = self
            .git_index_requests
            .scope(id)
            .map(p::ResponseBody::GitIndexScope);
        drop(state);
        result
    }
    pub(super) fn git_index_prepare(
        &self,
        client: &ClientSession,
        input: git::Prepare,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.git_index_authorize(&state, client, &input.origin.project_id)?;
        let result = self
            .git_index_requests
            .prepare(input)
            .map(p::ResponseBody::GitIndexRequest);
        drop(state);
        result
    }
    pub(super) fn git_index_start(
        &self,
        client: &ClientSession,
        input: &git::Start,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.git_index_authorize(&state, client, &input.origin.project_id)?;
        let result = self
            .git_index_requests
            .start(input)
            .map(p::ResponseBody::GitIndexRequest);
        drop(state);
        result
    }
    pub(super) fn git_index_query(
        &self,
        client: &ClientSession,
        query: &git::Query,
        cancel: bool,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.git_index_authorize(&state, client, &query.project_id)?;
        // Revoke cannot linearize between authorization and this memory-only
        // copy/STOP. Write-consent expiry never bypasses ordinary read access.
        let result = self
            .git_index_requests
            .query(query, cancel)
            .map(p::ResponseBody::GitIndexRequest);
        drop(state);
        result
    }
}

#[cfg(test)]
#[path = "service_git_application_tests.rs"]
mod tests;
