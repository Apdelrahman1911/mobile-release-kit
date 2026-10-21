//! Existing authenticated READ facet + memory-only immutable Apply requests.
//! IPC never supplies a Window, path, full draft, source proof or executor.
use super::*;
use crate::{service_version_edit_protocol as w, service_version_edit_requests as requests};
impl ApplicationService {
    pub(crate) fn version_edit_requests(&self) -> &Arc<requests::Inbox> {
        &self.version_edit_requests
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
}
