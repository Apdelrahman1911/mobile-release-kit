//! Scalar local-history requests on the original Store book and READ facet.
use super::*;
use crate::service_local_history_protocol as wire;
impl ApplicationService {
    pub(super) fn service_local_history_scope(
        &self,
        client: &ClientSession,
        project: &Id,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, project)?;
        let access = self.store_requests.history_access()?;
        if access.project_id.as_ref().is_some_and(|id| id != project) {
            return Err(Error::Conflict);
        }
        Ok(p::ResponseBody::LocalHistoryAccess(Box::new(access)))
    }
    pub(super) fn service_local_history_submit(
        &self,
        client: &ClientSession,
        input: wire::Submit,
    ) -> Result<p::ResponseBody, Error> {
        let at = Instant::now();
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &input.origin.project_id)?;
        self.store_requests
            .submit_history(input, at)
            .map(|s| p::ResponseBody::LocalHistoryRequest(Box::new(s)))
    }
    pub(super) fn service_local_history_query(
        &self,
        client: &ClientSession,
        q: &wire::Query,
        cancel: bool,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &q.project_id)?;
        self.store_requests
            .query_history(q, cancel)
            .map(|s| p::ResponseBody::LocalHistoryRequest(Box::new(s)))
    }
}
