//! Fixed IPC enqueue/query only. The original Desktop relay invokes native
//! owners; this service never inspects sources, downloads or runs tool probes.
use super::*;
use crate::{service_tool_setup_protocol as wire, service_tool_setup_requests as req};
pub(crate) struct ToolPoint {
    pub(crate) saved: crate::agent_local_checks::SavedPoint,
    pub(crate) read: Arc<crate::service_version_reserve_requests::ReadPermission>,
}
impl ApplicationService {
    pub(crate) fn tool_setup_point(
        &self,
        runtime: &str,
        kind: wire::Kind,
    ) -> Result<ToolPoint, Error> {
        let state = self.lock()?;
        self.check(&state)?;
        let id = state.runtime_aliases.get(runtime).ok_or(Error::Conflict)?;
        let grant = live_grant(&state)?;
        if !grant.projects.contains(id) {
            return Err(Error::AccessDenied);
        }
        let saved = Self::build_point(&state, id)?;
        if saved.runtime_id != runtime
            || !saved.fresh
            || (kind != wire::Kind::Doctor && saved.config.is_none())
        {
            return Err(Error::Conflict);
        }
        Ok(ToolPoint {
            saved,
            read: grant.reserve_read.clone(),
        })
    }

    pub(crate) fn tool_setup_requests(&self) -> &Arc<req::Inbox> {
        &self.tool_setup_requests
    }
    pub(crate) fn tool_setup_current(&self, scope: &req::NativeScope) -> Result<(), Error> {
        let state = self.lock()?;
        self.check(&state)?;
        let grant = live_grant(&state)?;
        if !grant.projects.contains(&scope.project_id)
            || !Arc::ptr_eq(&scope.read, &grant.reserve_read)
            || !scope.matches(&Self::build_point(&state, &scope.project_id)?)
        {
            return Err(Error::Conflict);
        }
        scope.current(false, Instant::now())
    }
    pub(super) fn tool_setup_submit(
        &self,
        client: &ClientSession,
        input: wire::Submit,
    ) -> Result<p::ResponseBody, Error> {
        let at = Instant::now(); // Before service lock/queue; original native T.
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &input.origin.project_id)?;
        self.tool_setup_requests
            .submit(input, at)
            .map(p::ResponseBody::ToolSetupRequest)
    }
    pub(super) fn tool_setup_query(
        &self,
        client: &ClientSession,
        input: &wire::Query,
        cancel: bool,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &input.project_id)?;
        self.tool_setup_requests
            .query(input, cancel)
            .map(p::ResponseBody::ToolSetupRequest)
    }
}
