//! Local-repository facade on the SAME grant, finite inbox and native links.
//! All methods are bounded memory operations; no service/Doc/IO callback.
use super::*;

impl Inbox {
    pub(crate) fn allow_repository(
        &self,
        scope: Arc<NativeScope>,
    ) -> Result<repository::Access, Error> {
        self.allow_for(scope, Family::Repository)?.repository()
    }
    pub(crate) fn repository_access(&self) -> Result<repository::Access, Error> {
        let book = self.lock()?;
        access(&book, None, Family::Repository)?.repository()
    }
    pub(crate) fn repository_scope(&self, project: &Id) -> Result<repository::Scope, Error> {
        let book = self.lock()?;
        let value = repository::Scope {
            service_instance: self.instance.clone(),
            project_id: project.clone(),
            access: access(&book, Some(project), Family::Repository)?.repository()?,
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn revoke_repository(&self) -> Result<repository::Access, Error> {
        self.revoke_for(Family::Repository)?.repository()
    }
    pub(crate) fn prepare_repository(
        &self,
        input: repository::Prepare,
    ) -> Result<repository::Status, Error> {
        self.prepare_for(input, Family::Repository)?.repository()
    }
    pub(crate) fn start_repository(
        &self,
        input: &repository::Start,
    ) -> Result<repository::Status, Error> {
        let book = self.lock()?;
        self.find(&book, &input.origin, Family::Repository)?
            .request_start(input)?
            .repository()
    }
    pub(crate) fn query_repository(
        &self,
        input: &repository::Query,
        cancel: bool,
    ) -> Result<repository::Status, Error> {
        let book = self.lock()?;
        let entry = self.find(&book, input, Family::Repository)?;
        if cancel {
            entry.cancel(p::Reason::UserCancelled, Instant::now());
        }
        entry.status()?.repository()
    }
}

#[cfg(test)]
#[path = "service_git_repository_requests_tests.rs"]
mod tests;
