//! Store delegation stays in the SAME authenticated service. IPC only
//! enqueues bounded DATA; the retained Desktop relay enters the Saved owner.
use super::*;
use crate::{service_store_protocol as wire, service_store_requests as requests};
pub(crate) struct StorePoint {
    pub(crate) saved: crate::agent_local_checks::SavedPoint,
    pub(crate) read: Arc<crate::service_version_reserve_requests::ReadPermission>,
}
impl ApplicationService {
    pub(crate) fn store_requests(&self) -> &Arc<requests::Inbox> {
        &self.store_requests
    }
    pub(crate) fn store_point(&self, runtime: &str) -> Result<StorePoint, Error> {
        let state = self.lock()?;
        self.check(&state)?;
        let id = state.runtime_aliases.get(runtime).ok_or(Error::Conflict)?;
        let grant = live_grant(&state)?;
        if !grant.projects.contains(id) {
            return Err(Error::AccessDenied);
        }
        let saved = Self::build_point(&state, id)?;
        if saved.runtime_id != runtime || !saved.fresh || saved.config.is_none() {
            return Err(Error::Conflict);
        }
        Ok(StorePoint {
            saved,
            read: grant.reserve_read.clone(),
        })
    }
    /// Off Doc/Edit: use the existing Projects writer before possible local
    /// snapshot/journal effects. No status call creates a fresh observation.
    pub(crate) fn consume_store_observation(
        &self,
        scope: &requests::NativeScope,
    ) -> Result<(), Error> {
        let mut state = self.lock()?;
        self.check(&state)?;
        let grant = live_grant(&state)?;
        if !grant.projects.contains(&scope.project_id)
            || !Arc::ptr_eq(&scope.read, &grant.reserve_read)
            || !scope.matches(&Self::build_point(&state, &scope.project_id)?)
        {
            return Err(Error::Conflict);
        }
        scope.current(false, Instant::now())?;
        let mut next = state.saved.clone();
        let observation = next
            .projects
            .iter_mut()
            .find(|p| p.binding.project_id == scope.project_id)
            .and_then(|p| p.observation.as_mut())
            .ok_or(Error::Conflict)?;
        observation.stale = true;
        observation.revision = state.revision.0.checked_add(1).ok_or(Error::StateUnknown)?;
        self.save(&mut state, next)
    }
    pub(super) fn service_store_submit(
        &self,
        client: &ClientSession,
        input: wire::Submit,
    ) -> Result<p::ResponseBody, Error> {
        let at = Instant::now(); // T before service lock/IO/queue; no later reset.
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &input.origin.project_id)?;
        let result = self
            .store_requests
            .submit(input, at)
            .map(p::ResponseBody::StoreRequest);
        drop(state);
        result
    }
    pub(super) fn service_store_query(
        &self,
        client: &ClientSession,
        q: &wire::Query,
        cancel: bool,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &q.project_id)?;
        let result = self
            .store_requests
            .query(q, cancel)
            .map(p::ResponseBody::StoreRequest);
        drop(state);
        result
    }
}
