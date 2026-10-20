//! Five closed local actions under the SAME service/read authorization and
//! finite Git inbox. No service request enters Doc or executes Git here.
use super::*;
use crate::service_git_repository_protocol as repository;

impl ApplicationService {
    pub(in crate::application_service) fn git_repository_scope(
        &self,
        client: &ClientSession,
        id: &Id,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.git_index_authorize(&state, client, id)?;
        let result = self
            .git_index_requests
            .repository_scope(id)
            .map(p::ResponseBody::GitRepositoryScope);
        drop(state);
        result
    }
    pub(in crate::application_service) fn git_repository_prepare(
        &self,
        client: &ClientSession,
        input: repository::Prepare,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.git_index_authorize(&state, client, &input.origin.project_id)?;
        let result = self
            .git_index_requests
            .prepare_repository(input)
            .map(p::ResponseBody::GitRepositoryRequest);
        drop(state);
        result
    }
    pub(in crate::application_service) fn git_repository_start(
        &self,
        client: &ClientSession,
        input: &repository::Start,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.git_index_authorize(&state, client, &input.origin.project_id)?;
        let result = self
            .git_index_requests
            .start_repository(input)
            .map(p::ResponseBody::GitRepositoryRequest);
        drop(state);
        result
    }
    pub(in crate::application_service) fn git_repository_query(
        &self,
        client: &ClientSession,
        input: &repository::Query,
        cancel: bool,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.git_index_authorize(&state, client, &input.project_id)?;
        let result = self
            .git_index_requests
            .query_repository(input, cancel)
            .map(p::ResponseBody::GitRepositoryRequest);
        drop(state);
        result
    }
}

#[cfg(test)]
#[path = "service_git_repository_application_tests.rs"]
mod tests;
