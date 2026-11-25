//! The existing authenticated service only queues DATA. Both phases retain
//! their original request ID; only the Desktop relay enters the Saved owner.
use super::*;
use crate::{service_store_prepare_protocol as wire, service_store_requests::preparation::Scope};
impl ApplicationService {
    pub(super) fn service_store_preparation(
        &self,
        client: &ClientSession,
        input: wire::Submit,
        start: bool,
    ) -> Result<p::ResponseBody, Error> {
        let at = Instant::now(); // Original Start T, before any lock/IO/queue.
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &input.origin.project_id)?;
        let result = if start {
            self.store_requests
                .preparation_entry(&input.origin)?
                .submit_start(input, at)
        } else {
            self.store_requests.submit_preparation(input, at)
        };
        drop(state);
        result.map(|s| p::ResponseBody::StorePreparation(Box::new(s)))
    }
    /// Same saved-project writer, same READ identity and old observation. An
    /// earlier read/list/status cannot supply permission for this phase.
    pub(crate) fn consume_store_preparation_observation(&self, scope: &Scope) -> Result<(), Error> {
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
}
