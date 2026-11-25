//! Closed Commit routes under the SAME service/read authorization guard.
//! No socket-to-Document call or native/Store work occurs here.
use super::*;
use crate::service_git_commit_protocol as commit;

impl ApplicationService {
    pub(in crate::application_service) fn git_commit_scope(
        &self,
        client: &ClientSession,
        id: &Id,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.git_index_authorize(&state, client, id)?;
        let result = self
            .git_index_requests
            .commit_scope(id)
            .map(p::ResponseBody::GitCommitScope);
        drop(state);
        result
    }
    pub(in crate::application_service) fn git_commit_prepare(
        &self,
        client: &ClientSession,
        input: commit::Prepare,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.git_index_authorize(&state, client, &input.origin.project_id)?;
        let result = self
            .git_index_requests
            .prepare_commit(input)
            .map(p::ResponseBody::GitCommitRequest);
        drop(state);
        result
    }
    pub(in crate::application_service) fn git_commit_start(
        &self,
        client: &ClientSession,
        input: &commit::Start,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.git_index_authorize(&state, client, &input.origin.project_id)?;
        let result = self
            .git_index_requests
            .start_commit(input)
            .map(p::ResponseBody::GitCommitRequest);
        drop(state);
        result
    }
    pub(in crate::application_service) fn git_commit_query(
        &self,
        client: &ClientSession,
        input: &commit::Query,
        cancel: bool,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.git_index_authorize(&state, client, &input.project_id)?;
        let result = self
            .git_index_requests
            .query_commit(input, cancel)
            .map(p::ResponseBody::GitCommitRequest);
        drop(state);
        result
    }
}

#[cfg(test)]
#[path = "service_git_commit_application_tests.rs"]
mod tests;
