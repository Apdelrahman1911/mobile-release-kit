//! Authenticated IDs-only cleanup on the original service. No native imports.
use super::*;
use crate::{service_play_cleanup_protocol as wire, service_play_cleanup_requests as requests};
pub(crate) struct Point {
    pub(crate) saved: crate::agent_identity_requests::SavedPoint,
    pub(crate) read: Arc<crate::service_version_reserve_requests::ReadPermission>,
}
impl ApplicationService {
    pub(crate) fn play_cleanup_requests(&self) -> &Arc<requests::Inbox> {
        &self.play_cleanup_requests
    }
    /// OFF Doc/Edit; check() actually reads the original private Service store.
    pub(crate) fn play_cleanup_point(&self, runtime: &str) -> Result<Point, Error> {
        let state = self.lock()?;
        self.check(&state)?;
        let id = state.runtime_aliases.get(runtime).ok_or(Error::Conflict)?;
        let grant = live_grant(&state)?;
        if !grant.projects.contains(id) {
            return Err(Error::AccessDenied);
        }
        let saved = Self::identity_point(&state, id)?;
        if saved.runtime_id != runtime || !saved.fresh {
            return Err(Error::Conflict);
        }
        Ok(Point {
            saved,
            read: grant.reserve_read.clone(),
        })
    }
    pub(super) fn service_play_cleanup_submit(
        &self,
        client: &ClientSession,
        input: wire::Submit,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &input.origin.project_id)?;
        Self::identity_point(&state, &input.origin.project_id)?;
        let result = self
            .play_cleanup_requests
            .submit(input)
            .map(p::ResponseBody::PlayCleanupRequest);
        drop(state);
        result
    }
    pub(super) fn service_play_cleanup_query(
        &self,
        client: &ClientSession,
        q: &wire::Query,
        cancel: bool,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &q.project_id)?;
        Self::identity_point(&state, &q.project_id)?;
        let result = self
            .play_cleanup_requests
            .query(q, cancel)
            .map(p::ResponseBody::PlayCleanupRequest);
        drop(state);
        result
    }
}

#[cfg(test)]
#[path = "service_play_cleanup_application_tests.rs"]
mod tests;
