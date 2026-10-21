//! Existing authenticated READ facet + memory-only immutable Apply requests.
//! IPC never supplies a Window, path, full draft, source proof or executor.
use super::*;
use crate::{service_version_edit_protocol as w, service_version_edit_requests as requests};
impl ApplicationService {
    pub(crate) fn version_edit_requests(&self) -> &Arc<requests::Inbox> {
        &self.version_edit_requests
    }
    pub(super) fn service_version_edit_prepare(&self,client:&ClientSession,input:crate::service_version_edit_prepare_protocol::Prepare)->Result<p::ResponseBody,Error>{
        input.validate()?;
        let state=self.lock()?;self.authorize_build_client(&state,client,&input.origin.project_id)?;
        let saved=Self::identity_point(&state,&input.origin.project_id)?;
        if self.version_edit_requests.is_preparation(&input.origin).is_ok(){
            let old=self.version_edit_requests.preparation(&input.origin)?;
            if old.input!=input{return Err(Error::Conflict)}
            return old.status().map(p::ResponseBody::VersionEditPreparation);
        }
        if matches!(&input.selection,crate::service_version_edit_prepare_protocol::Selection::Manual{..})
            && (!saved.fresh||!state.saved.projects.iter().find(|p|p.binding.project_id==input.origin.project_id)
                .and_then(|p|p.observation.as_ref()).is_some_and(|p|p.configuration.state==p::ConfigurationState::FormatValid)){return Err(Error::Conflict)}
        self.version_edit_requests.prepare(input,requests::Scope{saved,read:live_grant(&state)?.reserve_read.clone()}).map(p::ResponseBody::VersionEditPreparation)
    }
    /// This may check the existing Store; no Doc/Edit guard may be held.
    pub(crate) fn version_prepare_current(&self,entry:&crate::service_version_edit_prepare_requests::Entry,opening:bool)->Result<(),Error>{
        self.version_edit_current(&entry.scope)?;
        if !entry.live(){return Err(Error::Expired)}
        if opening&&matches!(&entry.input.selection,crate::service_version_edit_prepare_protocol::Selection::Manual{..}){
            let point=self.version_reserve_point(&entry.scope.saved.runtime_id)?;
            if !point.saved.fresh||point.saved.revision!=entry.scope.saved.revision{return Err(Error::Conflict)}
        }
        Ok(())
    }
    pub(super) fn service_version_edit_submit(
        &self,
        client: &ClientSession,
        input: w::Submit,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &input.origin.project_id)?;
        Self::identity_point(&state, &input.origin.project_id)?;
        let result = self
            .version_edit_requests
            .submit(input)
            .map(p::ResponseBody::VersionEditRequest);
        drop(state);
        result
    }
    pub(super) fn service_version_edit_query(
        &self,
        client: &ClientSession,
        q: &w::Query,
        cancel: bool,
    ) -> Result<p::ResponseBody, Error> {
        let at = Instant::now();
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &q.project_id)?;
        Self::identity_point(&state, &q.project_id)?;
        if self.version_edit_requests.is_preparation(q)? {
            let e=self.version_edit_requests.preparation(q)?;
            if cancel{e.cancel(at)?;}
            return e.status().map(p::ResponseBody::VersionEditPreparation);
        }
        let entry = self.version_edit_requests.entry(q)?;
        if cancel {
            entry.cancel(at)?;
        }
        let result = entry.status().map(p::ResponseBody::VersionEditRequest);
        drop(state);
        result
    }
    /// May check Store; caller must not hold Document/Edit. No observation is
    /// relabelled fresh after the intentional ordinary Open/Prepare invalidation.
    pub(crate) fn version_edit_current(&self, scope: &requests::Scope) -> Result<(), Error> {
        let point = self.version_reserve_point(&scope.saved.runtime_id)?;
        if !Arc::ptr_eq(&scope.read, &point.read)
            || scope.saved.project_id != point.saved.project_id
            || scope.saved.root != point.saved.root
            || scope.saved.device != point.saved.device
            || scope.saved.inode != point.saved.inode
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        application_service::tests::{passive, register_fixture},
        application_state_store::Fixture,
    };
    #[test]
    fn genuine_service_read_reconnect_revoke_and_alias_never_mint_prepared_apply() {
        let f = Fixture::new();
        let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let service = Arc::new(ApplicationService::open(store.clone()).unwrap());
        let (id, root) = register_fixture(&service, &f.app, "project", "version-project");
        service
            .publish_passive_snapshot("version-project", &passive(&root, &"a".repeat(64)))
            .unwrap();
        assert!(service.admit_client().is_err());
        service
            .allow_agent_read(vec![id.clone()], Duration::from_secs(300))
            .unwrap();
        let first = service.admit_client().unwrap();
        let point = service.version_reserve_point("version-project").unwrap();
        let scope = requests::Scope {
            saved: point.saved,
            read: point.read,
        };
        assert!(service.version_edit_current(&scope).is_ok());
        let input = w::Submit {
            origin: w::Query {
                project_id: id.clone(),
                service_instance: service.instance().clone(),
                request_id: Id::random().unwrap(),
            },
            grant_id: Id::random().unwrap(),
            session_id: Id::random().unwrap(),
            plan_token: Id::random().unwrap(),
            reviewed: true,
        };
        // Actual Service authorization reaches an empty Inbox, not a fake
        // native Prepared or successful lease install.
        assert_eq!(
            service
                .service_version_edit_submit(&first, input.clone())
                .err(),
            Some(Error::AccessDenied)
        );
        let reconnected = service.admit_client().unwrap();
        assert_ne!(first.client_id, reconnected.client_id);
        assert_eq!(
            service
                .service_version_edit_submit(&reconnected, input.clone())
                .err(),
            Some(Error::AccessDenied)
        );
        assert!(service
            .android_tools_client_current(&reconnected, &id)
            .is_ok());
        service
            .allow_agent_read(vec![id.clone()], Duration::from_secs(300))
            .unwrap();
        assert!(service.version_edit_current(&scope).is_err());
        assert!(scope.read.stop(Instant::now()).unwrap().is_some());
        assert!(service
            .service_version_edit_submit(&first, input.clone())
            .is_err());
        let newer = service.admit_client().unwrap();
        service
            .state
            .lock()
            .unwrap()
            .runtime_aliases
            .remove("version-project");
        assert!(service.service_version_edit_submit(&newer, input).is_err());
        assert!(service.android_tools_client_current(&newer, &id).is_err());
        assert!(service
            .version_edit_requests()
            .catalogue(&id)
            .unwrap()
            .is_empty());
        service.stop().unwrap();
        store.close().unwrap();
    }
    #[test]
    fn combined_prepare_uses_saved_config_freshness_but_no_cached_version_proof() {
        use crate::service_version_edit_prepare_protocol as prep;
        let f=Fixture::new();
        let store=Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let service=Arc::new(ApplicationService::open(store.clone()).unwrap());
        let (id,root)=register_fixture(&service,&f.app,"project","version-preparation");
        service.allow_agent_read(vec![id.clone()],Duration::from_secs(300)).unwrap();
        let client=service.admit_client().unwrap();
        let input=prep::Prepare{origin:w::Query{project_id:id.clone(),service_instance:service.instance().clone(),request_id:Id::random().unwrap()},
            selection:prep::Selection::Manual{values:prep::Values{name:"1.2".into(),build:"8".into()}}};
        assert!(service.service_version_edit_prepare(&client,input.clone()).is_err()); // no saved CONFIG observation
        let reserved=prep::Prepare{origin:input.origin.clone(),selection:prep::Selection::Reserved{reservation_id:Id::random().unwrap()}};
        let p::ResponseBody::VersionEditPreparation(waiting)=service.service_version_edit_prepare(&client,reserved.clone()).unwrap() else{panic!("preparation metadata")};
        assert_eq!(waiting.phase,prep::Phase::Queued);
        assert!(waiting.original.is_none()&&waiting.checkout.is_none()&&waiting.review.is_none()); // not a reconstructed handoff
        service.service_version_edit_query(&client,&reserved.origin,true).unwrap();
        service.publish_passive_snapshot("version-preparation",&passive(&root,&"a".repeat(64))).unwrap();
        let mut manual=input;manual.origin.request_id=Id::random().unwrap();
        let p::ResponseBody::VersionEditPreparation(queued)=service.service_version_edit_prepare(&client,manual.clone()).unwrap() else{panic!("manual metadata")};
        assert_eq!(queued.phase,prep::Phase::Queued);
        assert!(queued.original.is_none()&&queued.checkout.is_none()&&queued.proposed.is_none());
        let e=service.version_edit_requests().preparation(&manual.origin).unwrap();
        assert!(service.version_prepare_current(&e,true).is_ok());
        service.invalidate_native("version-preparation").unwrap();
        assert!(service.version_prepare_current(&e,true).is_err());
        // Intentional original Open publication invalidates the saved CONFIG.
        // Later phases use actual native checkout/chain, not freshness renewal.
        assert!(service.version_prepare_current(&e,false).is_ok());
        assert!(service.service_version_edit_prepare(&client,manual.clone()).is_ok());
        let mut changed=manual.clone();changed.selection=prep::Selection::Manual{values:prep::Values{name:"2.0".into(),build:"9".into()}};
        assert!(service.service_version_edit_prepare(&client,changed).is_err());
        service.allow_agent_read(vec![id.clone()],Duration::from_secs(300)).unwrap();
        assert!(service.version_prepare_current(&e,false).is_err());
        assert!(service.service_version_edit_query(&client,&manual.origin,false).is_err());
        let renewed=service.admit_client().unwrap();
        let p::ResponseBody::VersionEditPreparation(old)=service.service_version_edit_query(&renewed,&manual.origin,false).unwrap() else{panic!("same stored kind")};
        assert_eq!(old.origin,manual.origin);
        assert_eq!(old.phase,prep::Phase::Final); // queued never entered; no native result manufactured
        assert_eq!(old.result.unwrap().effect,w::Effect::NotStarted);
        service.state.lock().unwrap().runtime_aliases.remove("version-preparation");
        assert!(service.service_version_edit_query(&renewed,&manual.origin,false).is_err());
        assert!(service.android_tools_client_current(&renewed,&id).is_err());
        service.stop().unwrap();store.close().unwrap();
    }
}
