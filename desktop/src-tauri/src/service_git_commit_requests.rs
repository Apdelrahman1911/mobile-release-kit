//! Commit facade on the SAME finite inbox, native links, lease and tombstones.
use super::*;
use crate::service_git_commit_protocol as c;

impl Inbox {
    pub(crate) fn allow_commit(&self, scope: Arc<NativeScope>) -> Result<c::Access, Error> {
        let value = c::Access(self.allow_for(scope, Family::Commit)?.files()?);
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn commit_access(&self) -> Result<c::Access, Error> {
        let book = self.lock()?;
        Ok(c::Access(access(&book, None, Family::Commit)?.files()?))
    }
    pub(crate) fn commit_scope(&self, project: &Id) -> Result<c::Scope, Error> {
        let book = self.lock()?;
        Ok(c::Scope(p::Scope {
            service_instance: self.instance.clone(),
            project_id: project.clone(),
            access: access(&book, Some(project), Family::Commit)?.files()?,
        }))
    }
    pub(crate) fn revoke_commit(&self) -> Result<c::Access, Error> {
        Ok(c::Access(self.revoke_for(Family::Commit)?.files()?))
    }
    pub(crate) fn prepare_commit(&self, input: c::Prepare) -> Result<c::Status, Error> {
        let value = c::Status(self.prepare_for(input, Family::Commit)?.files()?);
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn start_commit(&self, input: &c::Start) -> Result<c::Status, Error> {
        let book = self.lock()?;
        let value = c::Status(
            self.find(&book, &input.origin, Family::Commit)?
                .request_start(input)?.files()?,
        );
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn query_commit(&self, input: &c::Query, cancel: bool) -> Result<c::Status, Error> {
        let book = self.lock()?;
        let entry = self.find(&book, input, Family::Commit)?;
        if cancel {
            entry.cancel(p::Reason::UserCancelled, Instant::now());
        }
        let value = c::Status(entry.status()?.files()?);
        value.validate()?;
        Ok(value)
    }
}

#[cfg(test)]
#[path = "service_git_commit_requests_tests.rs"]
mod tests;
