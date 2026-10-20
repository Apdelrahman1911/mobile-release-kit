//! Closed memory admission + existing saved-state writer. Never calls a native
//! owner, supplies a document/window, starts an executor, or upgrades read access.
use super::*;
use crate::agent_local_checks as local;

impl ApplicationService {
    pub(crate) fn local_checks(&self) -> &Arc<local::Inbox> {
        &self.local_checks
    }
    fn local_point(state: &State, id: &Id) -> Result<local::SavedPoint, Error> {
        let base = Self::identity_point(state, id)?;
        let configuration = state
            .saved
            .projects
            .iter()
            .find(|p| &p.binding.project_id == id)
            .and_then(|p| p.observation.as_ref())
            .map(|p| &p.configuration);
        let config = configuration
            .filter(|c| c.state == p::ConfigurationState::FormatValid)
            .and_then(|c| {
                let config = local::Config {
                    bytes: u32::try_from(c.bytes?).ok()?,
                    sha256: c.sha256.clone()?,
                };
                config.valid().then_some(config)
            });
        Ok(local::SavedPoint {
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
    /// Only comparison DATA. Callers must be outside Doc/Edit/Host controls.
    pub(crate) fn local_check_point(&self, runtime_id: &str) -> Result<local::SavedPoint, Error> {
        let state = self.lock()?;
        self.check(&state)?;
        let id = state
            .runtime_aliases
            .get(runtime_id)
            .ok_or(Error::Conflict)?;
        if !live_grant(&state)?.projects.contains(id) {
            return Err(Error::AccessDenied);
        }
        let point = Self::local_point(&state, id)?;
        if point.runtime_id != runtime_id || !point.fresh || point.config.is_none() {
            return Err(Error::Conflict);
        }
        Ok(point)
    }
    pub(crate) fn consume_local_check_observation(
        &self,
        scope: &local::NativeScope,
    ) -> Result<(), Error> {
        let mut state = self.lock()?;
        self.check(&state)?;
        if !live_grant(&state)?.projects.contains(&scope.project_id)
            || !Self::local_point(&state, &scope.project_id)?.matches(scope)
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
    pub(super) fn submit_local_check(
        &self,
        client: &ClientSession,
        input: local::Submit,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.check(&state)?;
        let grant = live_grant(&state)?;
        if client.instance != self.instance
            || grant.id != client.grant_id
            || !grant.projects.contains(&input.project_id)
        {
            return Err(Error::AccessDenied);
        }
        let point = Self::local_point(&state, &input.project_id)?;
        // SAME read-grant guard through bounded memory admission. The distinct
        // native one-use grant is checked by Inbox; no read-only upgrade.
        let result = self
            .local_checks
            .submit(input, &point)
            .map(p::ResponseBody::LocalCheck);
        drop(state);
        result
    }
    pub(super) fn query_local_check(
        &self,
        client: &ClientSession,
        query: &local::Query,
        cancel: bool,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.check(&state)?;
        let grant = live_grant(&state)?;
        if client.instance != self.instance
            || grant.id != client.grant_id
            || !grant.projects.contains(&query.project_id)
        {
            return Err(Error::AccessDenied);
        }
        // Query/STOP never consume another execution permission. A new socket
        // client can refer to the exact per-launch original request. Keep the
        // SAME read-grant guard through this bounded memory-only call, so a
        // concurrent revoke cannot authorize a late query or STOP.
        let result = self
            .local_checks
            .query(query, cancel)
            .map(p::ResponseBody::LocalCheck);
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
    fn original_service_read_revoke_reconnect_and_stale_retry_never_grant_execution() {
        // Actual private-state fixture and Service, but the native scope is
        // inert DATA. No Desktop owner, worker, source tool or process starts.
        let f = Fixture::new();
        let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let service = ApplicationService::open(store.clone()).unwrap();
        let (project, root) = register_fixture(&service, &f.app, "project", "project-1");
        service
            .publish_passive_snapshot("project-1", &passive(&root, &"a".repeat(64)))
            .unwrap();
        service
            .allow_agent_read(vec![project.clone()], Duration::from_secs(30))
            .unwrap();
        let first = service.admit_client().unwrap();
        let point = service.local_check_point("project-1").unwrap();
        let input = local::Submit {
            service_instance: service.instance().clone(),
            project_id: project.clone(),
            request_id: Id::random().unwrap(),
            expected_observation_revision: point.revision,
        };
        assert_eq!(
            service
                .submit_local_check(&first, input.clone())
                .unwrap_err(),
            Error::AccessDenied
        );
        let doc = Arc::new(());
        let (changes, _) = tokio::sync::watch::channel(0);
        let scope = Arc::new(local::NativeScope {
            project_id: project.clone(),
            runtime_id: point.runtime_id.clone(),
            root: point.root.clone(),
            device: point.device,
            inode: point.inode,
            registration: 1,
            input_revision: 1,
            document: Arc::downgrade(&doc),
            observation_revision: point.revision,
            config: point.config.clone().unwrap(),
            draft_revision: 1,
            baseline_generation: 1,
            changes,
        });
        service.local_checks.allow(scope.clone()).unwrap();
        assert!(matches!(
            service.submit_local_check(&first, input.clone()).unwrap(),
            p::ResponseBody::LocalCheck(_)
        ));
        service.consume_local_check_observation(&scope).unwrap();
        assert_eq!(
            service.local_check_point("project-1").err(),
            Some(Error::Conflict)
        );
        assert!(service.submit_local_check(&first, input.clone()).is_ok()); // Same body, no second enqueue despite stale data.
        assert_eq!(service.local_checks.entries().unwrap().len(), 1);
        service.revoke_agent_read().unwrap();
        assert_eq!(
            service
                .query_local_check(&first, &input.query(), true)
                .unwrap_err(),
            Error::AccessDenied
        );
        assert_eq!(
            service
                .local_checks
                .query(&input.query(), false)
                .unwrap()
                .request_state,
            local::RequestState::Queued
        );
        service
            .allow_agent_read(vec![project], Duration::from_secs(30))
            .unwrap();
        let reconnected = service.admit_client().unwrap();
        assert_eq!(
            service
                .query_local_check(&first, &input.query(), true)
                .unwrap_err(),
            Error::AccessDenied
        );
        assert!(service
            .query_local_check(&reconnected, &input.query(), false)
            .is_ok());
        let p::ResponseBody::LocalCheck(stopped) = service
            .query_local_check(&reconnected, &input.query(), true)
            .unwrap()
        else {
            panic!("closed reply")
        };
        assert_eq!(
            stopped.request_state,
            local::RequestState::CancelledBeforeAdmission
        );
        assert!(stopped.operation.is_none());
        assert!(service.local_checks.access().unwrap().consumed);
        let mut repeated = input;
        repeated.request_id = Id::random().unwrap();
        assert!(service.submit_local_check(&reconnected, repeated).is_err());
        service.stop().unwrap();
        store.close().unwrap();
    }
}
