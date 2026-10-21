//! Authenticated Reserve requests on the SAME running application service.
//! No IPC callback opens a Document, calls a Store or enters a native runner.
use super::*;
use crate::{
    service_version_reserve_protocol as wire, service_version_reserve_requests as requests,
};

pub(crate) struct ReservePoint {
    pub(crate) saved: crate::agent_identity_requests::SavedPoint,
    pub(crate) read: Arc<requests::ReadPermission>,
}
impl ApplicationService {
    pub(crate) fn version_reserve_requests(&self) -> &Arc<requests::Inbox> {
        &self.version_reserve_requests
    }
    /// Called OFF Doc/Edit. check() really reads the existing service store.
    pub(crate) fn version_reserve_point(&self, runtime: &str) -> Result<ReservePoint, Error> {
        let state = self.lock()?;
        self.check(&state)?;
        let id = state.runtime_aliases.get(runtime).ok_or(Error::Conflict)?;
        let grant = live_grant(&state)?;
        if !grant.projects.contains(id) {
            return Err(Error::AccessDenied);
        }
        let saved = Self::identity_point(&state, id)?;
        if saved.runtime_id != runtime {
            return Err(Error::Conflict);
        }
        Ok(ReservePoint {
            saved,
            read: grant.reserve_read.clone(),
        })
    }
    pub(crate) fn version_reserve_original_current(
        &self,
        scope: &requests::NativeScope,
    ) -> Result<(), Error> {
        let point = self.version_reserve_point(&scope.runtime_id)?;
        if point.saved.project_id != scope.project_id || !Arc::ptr_eq(&point.read, &scope.read) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub(super) fn service_version_reserve_review(&self,client:&ClientSession,input:crate::service_version_reserve_review_protocol::Request)->Result<p::ResponseBody,Error>{
        let started=Instant::now(); // BEFORE service/Store wait, never reset at MAIN.
        input.validate()?;
        let state=self.lock()?;
        self.authorize_build_client(&state,client,&input.origin.project_id)?;
        let saved=Self::identity_point(&state,&input.origin.project_id)?;
        let read=live_grant(&state)?.reserve_read.clone();
        self.version_reserve_requests.enqueue_review(input,crate::service_version_reserve_review_requests::Scope{saved,read},started).map(p::ResponseBody::VersionReserveReview)
    }
    pub(super) fn service_version_reserve_submit(
        &self,
        client: &ClientSession,
        input: wire::Submit,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &input.origin.project_id)?;
        Self::identity_point(&state, &input.origin.project_id)?;
        // The current READ guard spans this finite memory-only enqueue. The
        // separate exact Review/grant still authorizes actual execution.
        let result = self
            .version_reserve_requests
            .submit(input)
            .map(p::ResponseBody::VersionReserveRequest);
        drop(state);
        result
    }
    pub(super) fn service_version_reserve_query(
        &self,
        client: &ClientSession,
        q: &wire::Query,
        cancel: bool,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &q.project_id)?;
        Self::identity_point(&state, &q.project_id)?;
        let result = if self.version_reserve_requests.review_kind(q)?{
            self.version_reserve_requests.review_status(Some(q),cancel)?.ok_or(Error::Conflict).map(p::ResponseBody::VersionReserveReview)
        }else{self.version_reserve_requests.query(q,cancel).map(p::ResponseBody::VersionReserveRequest)};
        drop(state);
        result
    }
}

#[cfg(test)]
#[path = "service_version_reserve_application_tests.rs"]
mod tests;
