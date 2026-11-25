//! Apple delegation stays in the SAME authenticated service. IPC only
//! enqueues bounded DATA; the retained Desktop relay enters the Saved owner.
use super::*;
use crate::{
    service_apple_provisioning_protocol as wire, service_apple_provisioning_requests as requests,
};
pub(crate) struct AppleProvisioningPoint {
    pub(crate) saved: crate::agent_local_checks::SavedPoint,
    pub(crate) read: Arc<crate::service_version_reserve_requests::ReadPermission>,
}
impl ApplicationService {
    pub(crate) fn apple_provisioning_requests(&self) -> &Arc<requests::Inbox> {
        &self.apple_provisioning_requests
    }
    pub(crate) fn apple_provisioning_point(
        &self,
        runtime: &str,
    ) -> Result<AppleProvisioningPoint, Error> {
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
        Ok(AppleProvisioningPoint {
            saved,
            read: grant.reserve_read.clone(),
        })
    }
    /// Off Doc/Edit: use the existing Projects writer before possible local
    /// snapshot/journal effects. No status call creates a fresh observation.
    pub(crate) fn consume_apple_provisioning_observation(
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
    pub(crate) fn apple_preparation_current(&self,e:&requests::preparation::Entry)->Result<(),Error>{
        let state=self.lock()?;self.check(&state)?;let grant=live_grant(&state)?;
        let saved=Self::build_point(&state,&e.scope.project.project_id)?;
        let p=&e.scope.project;
        if !grant.projects.contains(&p.project_id)||!Arc::ptr_eq(&grant.reserve_read,&e.scope.read)
            ||saved.runtime_id!=p.runtime_id||saved.root!=p.root||saved.device!=p.device||saved.inode!=p.inode||saved.revision!=p.revision||!saved.fresh||saved.config!=p.config{return Err(Error::Conflict);}
        e.current()
    }
    pub(super) fn service_apple_prepare(&self,client:&ClientSession,input:crate::service_apple_provisioning_prepare_protocol::Submit)->Result<p::ResponseBody,Error>{
        let at=Instant::now();let state=self.lock()?;self.authorize_build_client(&state,client,&input.origin.project_id)?;
        self.apple_provisioning_requests.submit_preparation(input,at).map(p::ResponseBody::AppleProvisioningPreparation)
    }
    pub(super) fn service_apple_provisioning_submit(
        &self,
        client: &ClientSession,
        input: wire::Submit,
    ) -> Result<p::ResponseBody, Error> {
        let at = Instant::now(); // T before service lock/IO/queue; no later reset.
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &input.origin.project_id)?;
        let result = self
            .apple_provisioning_requests
            .submit(input, at)
            .map(p::ResponseBody::AppleProvisioningRequest);
        drop(state);
        result
    }
    pub(super) fn service_apple_provisioning_query(
        &self,
        client: &ClientSession,
        q: &wire::Query,
        cancel: bool,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &q.project_id)?;
        let result = match self.apple_provisioning_requests.preparation(q){
            Ok(e)=>{if cancel{e.scope.stop(wire::Reason::UserCancelled,Instant::now());}e.status().map(p::ResponseBody::AppleProvisioningPreparation)},
            Err(Error::Conflict)=>self.apple_provisioning_requests.query(q,cancel).map(p::ResponseBody::AppleProvisioningRequest),
            Err(e)=>Err(e),
        };
        drop(state);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn apple_cli_history_only_front_refuses_all_live_methods() {
        let id = |c: char| crate::service_protocol::Id::parse(&c.to_string().repeat(32)).unwrap();
        let q = wire::Query {
            project_id: id('1'),
            service_instance: id('2'),
            request_id: id('3'),
        };
        for body in [
            p::RequestBody::AppleProvisioningPrepare(crate::service_apple_provisioning_prepare_protocol::Submit { origin:q.clone(),grant_id:id('4'),scope_id:id('5') }),
            p::RequestBody::AppleProvisioningSubmit(wire::Submit {
                origin: q.clone(),
                grant_id: id('4'),
                review_id: id('5'),
            }),
            p::RequestBody::AppleProvisioningStatus(q.clone()),
            p::RequestBody::AppleProvisioningCancel(q),
        ] {
            assert!(!super::super::history_policy::history_request(&body));
        }
    }
}
