//! Fixed iOS client verbs; same live read session AND separately approved
//! one-use build grant. No Document/native owner is called under service.state.
use super::*;
use crate::agent_ios_archive as archive;
impl ApplicationService {
    /// Recovery is the only Build source permitted without a saved config.
    /// Identity/revision and READ are captured atomically from the SAME state.
    pub(crate) fn ios_recovery_point_with_read(&self, runtime:&str) -> Result<(crate::agent_local_checks::SavedPoint,
        Arc<crate::service_version_reserve_requests::ReadPermission>),Error> {
        let state=self.lock()?; self.check(&state)?;
        let id=state.runtime_aliases.get(runtime).ok_or(Error::Conflict)?;
        let grant=live_grant(&state)?;
        if !grant.projects.contains(id) { return Err(Error::AccessDenied); }
        let point=Self::build_point(&state,id)?;
        if point.runtime_id!=runtime || !point.fresh { return Err(Error::Conflict); }
        Ok((point,grant.reserve_read.clone()))
    }
    pub(super) fn prepare_agent_ios_archive(
        &self,
        client: &ClientSession,
        input: archive::Prepare,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &input.project_id)?;
        let point = Self::build_point(&state, &input.project_id)?;
        let result = self
            .build_requests
            .prepare_ios_read(input, &point, &live_grant(&state)?.reserve_read)
            .and_then(archive::RequestStatus::try_from)
            .map(p::ResponseBody::IosArchiveRequest);
        drop(state);
        result
    }
    pub(super) fn start_agent_ios_archive(
        &self,
        client: &ClientSession,
        input: &archive::Start,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &input.origin.project_id)?;
        let result = self
            .build_requests
            .start_ios_read(input, &Self::build_point(&state, &input.origin.project_id)?, &live_grant(&state)?.reserve_read)
            .and_then(archive::RequestStatus::try_from)
            .map(p::ResponseBody::IosArchiveRequest);
        drop(state);
        result
    }
    pub(super) fn query_agent_ios_archive(
        &self,
        client: &ClientSession,
        query: &archive::Query,
        cancel: bool,
    ) -> Result<p::ResponseBody, Error> {
        // Hold the SAME grant through bounded query/STOP. Revoke cannot return
        // before a stale client subsequently gains access in an unlock gap.
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &query.project_id)?;
        let result = self
            .build_requests
            .query(archive::FAMILY, query, cancel)
            .and_then(archive::RequestStatus::try_from)
            .map(p::ResponseBody::IosArchiveRequest);
        drop(state);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application_service::tests::{passive, register_fixture};
    use crate::application_state_store::Fixture;
    #[test]
    fn configless_recovery_uses_actual_source_read_and_history_without_weakening_saved_builds() {
        // Existing task-owned private Service fixture. No native approval,
        // recovery engine, account/signing state or external IO is exercised.
        let f=Fixture::new();let store=Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let service=ApplicationService::open(store.clone()).unwrap();
        let (project,root)=register_fixture(&service,&f.app,"recovery-project","project-1");
        let mut snapshot=passive(&root,&"a".repeat(64));
        snapshot["config"]=serde_json::json!({"state":"missing","content":null,"data":null});
        service.publish_passive_snapshot("project-1",&snapshot).unwrap();
        service.allow_agent_read(vec![project.clone()],Duration::from_secs(60)).unwrap();
        let client=service.admit_client().unwrap();
        assert!(service.build_point_for_runtime("project-1").is_err()); // old saved path unchanged
        let (point,read)=service.ios_recovery_point_with_read("project-1").unwrap();
        assert!(point.config.is_none()&&point.fresh);
        assert!(service.ios_recovery_point_with_read("other").is_err());
        let document=Arc::new(());let (changes,_)=tokio::sync::watch::channel(0);
        let scope=Arc::new(archive::NativeScope {project_id:project.clone(),runtime_id:point.runtime_id.clone(),root:point.root.clone(),
            device:point.device,inode:point.inode,registration:1,input_revision:1,document:Arc::downgrade(&document),
            observation_revision:point.revision,input:crate::agent_build_requests::NativeInput::Recovery,read:Some(read.clone()),changes,
            review:archive::recovery::Review {mode:archive::recovery::Mode::LocalIosRecovery,recovery:archive::recovery::Intent::Inspect}.into()});
        service.build_requests.allow(scope.clone()).unwrap();
        let request=archive::Prepare {service_instance:service.instance().clone(),project_id:project,request_id:Id::random().unwrap(),
            expected_observation_revision:point.revision};
        let queued=service.prepare_agent_ios_archive(&client,request.clone()).unwrap();
        assert!(matches!(queued,p::ResponseBody::IosArchiveRequest(archive::RequestStatus::Recovery(_))));
        assert!(service.prepare_agent_android_build(&client,request.clone()).is_err());
        let claim=service.build_requests.claim(archive::FAMILY).unwrap().unwrap();
        let op=Id::random().unwrap();let generation=Id::random().unwrap();
        let link=claim.entry().bind(archive::FAMILY,op.clone(),generation.clone(),1,Instant::now()+Duration::from_secs(300)).unwrap();
        let start=archive::Start {origin:request.query(),operation_id:op,owner_generation:generation};
        assert!(service.start_agent_ios_archive(&client,&start).is_err());
        claim.returned(true);
        let (_,data)=link.entry().claim_history().unwrap().unwrap();
        let written=service.begin_operation(&scope.runtime_id,data.operation_id().clone(),p::Action::Build,data.state(),data.settlement());
        link.entry().history_returned(data.status_revision(),written).unwrap();
        service.start_agent_ios_archive(&client,&start).unwrap();
        let claim=service.build_requests.claim(archive::FAMILY).unwrap().unwrap();
        service.consume_build_observation(&scope).unwrap();link.consume_start(archive::FAMILY).unwrap();claim.returned(true);
        assert!(service.ios_recovery_point_with_read("project-1").is_err()); // consumed point is not refreshed
        let original=service.start_agent_ios_archive(&client,&start).unwrap();
        let bytes=serde_json::to_vec(&original).unwrap();assert!(bytes.len()<24*1024);
        assert!(!String::from_utf8(bytes).unwrap().contains(root.to_str().unwrap()));
        assert!(service.build_requests.claim(archive::FAMILY).unwrap().is_none());
        service.revoke_agent_read().unwrap();
        assert!(link.entry().stop_at(Instant::now()).is_some());
        assert!(service.query_agent_ios_archive(&client,&request.query(),false).is_err());
        service.stop().unwrap();drop(service);store.close().unwrap();
    }
    #[test]
    fn same_service_ios_wire_needs_its_own_grant_and_reconnect_cannot_reprepare_or_cross_family() {
        // The existing bounded private-state fixture, not a Desktop approval.
        let f = Fixture::new();
        let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let service = ApplicationService::open(store.clone()).unwrap();
        let (project, root) = register_fixture(&service, &f.app, "project", "project-1");
        service
            .publish_passive_snapshot("project-1", &passive(&root, &"a".repeat(64)))
            .unwrap();
        service
            .allow_agent_read(vec![project.clone()], Duration::from_secs(60))
            .unwrap();
        let client = service.admit_client().unwrap();
        let point = service.build_point_for_runtime("project-1").unwrap();
        let input = archive::Prepare {
            service_instance: service.instance().clone(),
            project_id: project.clone(),
            request_id: Id::random().unwrap(),
            expected_observation_revision: point.revision,
        };
        assert_eq!(
            service
                .prepare_agent_ios_archive(&client, input.clone())
                .unwrap_err(),
            Error::AccessDenied
        );
        let document = Arc::new(());
        let (changes, _) = tokio::sync::watch::channel(0);
        let scope = Arc::new(archive::NativeScope {
            project_id: project.clone(),
            runtime_id: point.runtime_id.clone(),
            root: point.root.clone(),
            device: point.device,
            inode: point.inode,
            registration: 1,
            input_revision: 1,
            document: Arc::downgrade(&document),
            observation_revision: point.revision,
            review: archive::Review {
                mode: archive::Mode::SavedIosUnsignedArchive,
                signing: None,
                saved_config: point.config.clone().unwrap(),
                saved_version: archive::Version {
                    bytes: 32,
                    sha256: "b".repeat(64),
                    name: "1.2.3".into(),
                    build: 7,
                },
            }
            .into(),
            read: None,
            input: crate::agent_build_requests::NativeInput::Saved { draft_revision: 1, baseline_generation: 1 },
            changes,
        });
        service.build_requests.allow(scope.clone()).unwrap();
        assert!(service
            .prepare_agent_android_build(&client, input.clone())
            .is_err());
        service
            .prepare_agent_ios_archive(&client, input.clone())
            .unwrap();
        let claim = service
            .build_requests
            .claim(archive::FAMILY)
            .unwrap()
            .unwrap();
        let operation = Id::random().unwrap();
        let generation = Id::random().unwrap();
        let link = claim
            .entry()
            .bind(
                archive::FAMILY,
                operation.clone(),
                generation.clone(),
                1,
                Instant::now() + Duration::from_secs(300),
            )
            .unwrap();
        let entry = claim.entry().clone();
        assert!(entry.claim_history().unwrap().is_none());
        claim.returned(true);
        // Actual original private Service writer, not a manufactured native
        // receipt. Its inert Prepared DATA cannot start Xcode in this fixture.
        let (first, data) = entry.claim_history().unwrap().unwrap();
        assert!(first);
        let written = service.begin_operation(&scope.runtime_id, data.operation_id().clone(),
            p::Action::Build, data.state(), data.settlement());
        entry.history_returned(data.status_revision(), written).unwrap();
        let next = service.admit_client().unwrap();
        assert_ne!(client.client_id, next.client_id);
        let body = service
            .prepare_agent_ios_archive(&next, input.clone())
            .unwrap();
        let p::ResponseBody::IosArchiveRequest(s) = body else {
            panic!("wrong fixed response")
        };
        let archive::RequestStatus::Saved(s) = s else { panic!("saved request changed family"); };
        assert_eq!(s.operation.unwrap().operation_id, operation);
        let start = archive::Start {
            origin: input.query(),
            operation_id: operation,
            owner_generation: generation,
        };
        service.start_agent_ios_archive(&next, &start).unwrap();
        let claim = service
            .build_requests
            .claim(archive::FAMILY)
            .unwrap()
            .unwrap();
        link.consume_start(archive::FAMILY).unwrap();
        claim.returned(true);
        service.consume_build_observation(&scope).unwrap();
        service.start_agent_ios_archive(&next, &start).unwrap();
        service
            .prepare_agent_ios_archive(&next, input.clone())
            .unwrap();
        assert!(service
            .build_requests
            .claim(archive::FAMILY)
            .unwrap()
            .is_none());
        assert_eq!(
            service
                .build_requests
                .entries(archive::FAMILY)
                .unwrap()
                .len(),
            1
        );
        assert!(service
            .query_agent_android_build(&next, &input.query(), true)
            .is_err());
        assert!(link.entry().stop_at(Instant::now()).is_none());
        service.revoke_agent_read().unwrap();
        assert_eq!(
            service
                .query_agent_ios_archive(&next, &input.query(), false)
                .unwrap_err(),
            Error::AccessDenied
        );
        service.stop().unwrap();
        drop(service);
        store.close().unwrap();
    }
}
