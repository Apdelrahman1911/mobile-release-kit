//! Fixed iOS client verbs; same live read session AND separately approved
//! one-use build grant. No Document/native owner is called under service.state.
use super::*;
use crate::agent_ios_archive as archive;
impl ApplicationService {
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
            .prepare(archive::FAMILY, input, &point)
            .and_then(archive::Status::try_from)
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
            .start(archive::FAMILY, input)
            .and_then(archive::Status::try_from)
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
            .and_then(archive::Status::try_from)
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
                saved_config: point.config.clone().unwrap(),
                saved_version: archive::Version {
                    bytes: 32,
                    sha256: "b".repeat(64),
                    name: "1.2.3".into(),
                    build: 7,
                },
            }
            .into(),
            draft_revision: 1,
            baseline_generation: 1,
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
        claim.returned(true);
        let next = service.admit_client().unwrap();
        assert_ne!(client.client_id, next.client_id);
        let body = service
            .prepare_agent_ios_archive(&next, input.clone())
            .unwrap();
        let p::ResponseBody::IosArchiveRequest(s) = body else {
            panic!("wrong fixed response")
        };
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
