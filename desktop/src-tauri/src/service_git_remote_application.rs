//! Five closed Remote actions under the SAME service/read authorization and
//! finite Git inbox. No service request enters Doc or executes Git here.
use super::*;
use crate::service_git_remote_protocol as remote;

impl ApplicationService {
    pub(in crate::application_service) fn git_remote_scope(
        &self,
        client: &ClientSession,
        id: &Id,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.git_index_authorize(&state, client, id)?;
        let result = self
            .git_index_requests
            .remote_scope(id)
            .map(p::ResponseBody::GitRemoteScope);
        drop(state);
        result
    }
    pub(in crate::application_service) fn git_remote_prepare(
        &self,
        client: &ClientSession,
        input: remote::Prepare,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.git_index_authorize(&state, client, &input.origin.project_id)?;
        let result = self
            .git_index_requests
            .prepare_remote(input)
            .map(p::ResponseBody::GitRemoteRequest);
        drop(state);
        result
    }
    pub(in crate::application_service) fn git_remote_start(
        &self,
        client: &ClientSession,
        input: &remote::Start,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.git_index_authorize(&state, client, &input.origin.project_id)?;
        let result = self
            .git_index_requests
            .start_remote(input)
            .map(p::ResponseBody::GitRemoteRequest);
        drop(state);
        result
    }
    pub(in crate::application_service) fn git_remote_query(
        &self,
        client: &ClientSession,
        input: &remote::Query,
        cancel: bool,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.git_index_authorize(&state, client, &input.project_id)?;
        let result = self
            .git_index_requests
            .query_remote(input, cancel)
            .map(p::ResponseBody::GitRemoteRequest);
        drop(state);
        result
    }
}

#[cfg(test)]
#[path = "service_git_remote_application_tests.rs"]
mod tests;
