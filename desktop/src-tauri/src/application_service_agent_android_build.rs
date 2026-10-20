//! Authenticated fixed DATA requests, on the SAME service/store. Neither
//! socket workers nor service.state call native document/build owners.
use super::*;
use crate::{agent_android_build as build, agent_local_checks::SavedPoint};

impl ApplicationService {
    pub(crate) fn build_requests(&self) -> &Arc<build::Inbox> {
        &self.build_requests
    }
    pub(super) fn build_point(state: &State, id: &Id) -> Result<SavedPoint, Error> {
        let base = Self::identity_point(state, id)?;
        let config = state
            .saved
            .projects
            .iter()
            .find(|p| &p.binding.project_id == id)
            .and_then(|p| p.observation.as_ref())
            .map(|p| &p.configuration)
            .filter(|c| c.state == p::ConfigurationState::FormatValid)
            .and_then(|c| {
                let c = build::Config {
                    bytes: u32::try_from(c.bytes?).ok()?,
                    sha256: c.sha256.clone()?,
                };
                c.valid().then_some(c)
            });
        Ok(SavedPoint {
            project_id: base.project_id,
            runtime_id: base.runtime_id,
            root: base.root,
            device: base.device,
            inode: base.inode,
            revision: base.revision,
            fresh: base.fresh,
            config,
        })
    }
    pub(crate) fn build_point_for_runtime(&self, runtime: &str) -> Result<SavedPoint, Error> {
        let state = self.lock()?;
        self.check(&state)?;
        let id = state.runtime_aliases.get(runtime).ok_or(Error::Conflict)?;
        if !live_grant(&state)?.projects.contains(id) {
            return Err(Error::AccessDenied);
        }
        let point = Self::build_point(&state, id)?;
        if point.runtime_id != runtime || !point.fresh || point.config.is_none() {
            return Err(Error::Conflict);
        }
        Ok(point)
    }
    /// Start's possible project effects make the old shared observation stale.
    /// The original Doc/Edit inputs are rematched AFTER this existing writer.
    pub(crate) fn consume_build_observation(
        &self,
        scope: &build::NativeScope,
    ) -> Result<(), Error> {
        let mut state = self.lock()?;
        self.check(&state)?;
        if !live_grant(&state)?.projects.contains(&scope.project_id)
            || !scope.matches(&Self::build_point(&state, &scope.project_id)?)
        {
            return Err(Error::Conflict);
        }
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
    pub(super) fn authorize_build_client(
        &self,
        state: &State,
        client: &ClientSession,
        project: &Id,
    ) -> Result<(), Error> {
        self.check(state)?;
        let grant = live_grant(state)?;
        if client.instance != self.instance
            || grant.id != client.grant_id
            || !grant.projects.contains(project)
        {
            return Err(Error::AccessDenied);
        }
        Ok(())
    }
    pub(super) fn prepare_agent_android_build(
        &self,
        client: &ClientSession,
        input: build::Prepare,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &input.project_id)?;
        let point = Self::build_point(&state, &input.project_id)?;
        let result = self
            .build_requests
            .prepare(build::FAMILY,input, &point)
            .and_then(build::Status::try_from).map(p::ResponseBody::AndroidBuildRequest);
        drop(state);
        result
    }
    pub(super) fn start_agent_android_build(
        &self,
        client: &ClientSession,
        input: &build::Start,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &input.origin.project_id)?;
        // Same grant lock through the bounded memory-only enqueue. A different
        // connection can inspect this exact one-use request, not create Start.
        let result = self
            .build_requests
            .start(build::FAMILY,input)
            .and_then(build::Status::try_from).map(p::ResponseBody::AndroidBuildRequest);
        drop(state);
        result
    }
    pub(super) fn query_agent_android_build(
        &self,
        client: &ClientSession,
        query: &build::Query,
        cancel: bool,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &query.project_id)?;
        let result = self
            .build_requests
            .query(build::FAMILY,query, cancel)
            .and_then(build::Status::try_from).map(p::ResponseBody::AndroidBuildRequest);
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
    fn actual_service_read_grant_is_not_build_consent_and_reconnect_never_reprepares() {
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
        let first = service.admit_client().unwrap();
        let point = service.build_point_for_runtime("project-1").unwrap();
        let input = build::Prepare {
            service_instance: service.instance().clone(),
            project_id: project.clone(),
            request_id: Id::random().unwrap(),
            expected_observation_revision: point.revision,
        };
        assert_eq!(
            service
                .prepare_agent_android_build(&first, input.clone())
                .unwrap_err(),
            Error::AccessDenied
        );
        let document = Arc::new(());
        let (changes, _) = tokio::sync::watch::channel(0);
        let scope = Arc::new(build::NativeScope {
            project_id: project.clone(),
            runtime_id: point.runtime_id.clone(),
            root: point.root.clone(),
            device: point.device,
            inode: point.inode,
            registration: 1,
            input_revision: 1,
            document: Arc::downgrade(&document),
            observation_revision: point.revision,
            review: build::Review {
                mode: build::Mode::SavedAndroidBuildStructureAndVersion,
                saved_config: point.config.clone().unwrap(),
                saved_version: build::Version {
                    bytes: 32,
                    sha256: "b".repeat(64),
                    name: "1.2.3".into(),
                    build: 7,
                },
                tools: build::Tools {
                    instance: Id::random().unwrap(),
                    catalog_generation: 1,
                    record_sha256: "c".repeat(64),
                },
            }.into(),
            draft_revision: 1,
            baseline_generation: 1,
            changes,
        });
        // Inert native-scope DATA. No native Document/Android approval is minted.
        service.build_requests.allow(scope.clone()).unwrap();
        service
            .prepare_agent_android_build(&first, input.clone())
            .unwrap();
        let claim = service.build_requests.claim(build::FAMILY).unwrap().unwrap();
        let operation = Id::random().unwrap();
        let generation = Id::random().unwrap();
        let link = claim
            .entry()
            .bind(build::FAMILY,
                operation.clone(),
                generation.clone(),
                1,
                Instant::now() + Duration::from_secs(300),
            )
            .unwrap();
        claim.returned(true);
        let second = service.admit_client().unwrap();
        assert_ne!(first.client_id, second.client_id);
        service
            .prepare_agent_android_build(&second, input.clone())
            .unwrap();
        assert_eq!(service.build_requests.entries(build::FAMILY).unwrap().len(), 1);
        let start = build::Start {
            origin: input.query(),
            operation_id: operation,
            owner_generation: generation,
        };
        service.start_agent_android_build(&second, &start).unwrap();
        let start_claim = service.build_requests.claim(build::FAMILY).unwrap().unwrap();
        link.consume_start(build::FAMILY).unwrap();
        start_claim.returned(true);
        service.consume_build_observation(&scope).unwrap();
        assert!(service.build_point_for_runtime("project-1").is_err());
        service
            .prepare_agent_android_build(&second, input.clone())
            .unwrap(); // Same original even when stale.
        service.start_agent_android_build(&second, &start).unwrap();
        assert!(service.build_requests.claim(build::FAMILY).unwrap().is_none());
        service.revoke_agent_read().unwrap();
        assert_eq!(
            service
                .query_agent_android_build(&second, &input.query(), false)
                .unwrap_err(),
            Error::AccessDenied
        );
        service.stop().unwrap();
        drop(service);
        store.close().unwrap();
    }
}
