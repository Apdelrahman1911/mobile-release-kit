//! Authenticated request DATA only; the existing relay retains all native work.
//! The saved observation may already be stale because the SAME identity Open
//! invalidated it. A private retained native checkout, never this cache, is the
//! source authority for this narrowly delegated proposal.
use super::*;
use crate::agent_identity_requests::{self as identity, actions as action};

impl ApplicationService {
    pub(crate) fn identity_action_current(&self, entry: &identity::Entry) -> Result<(), Error> {
        let state = self.lock()?;
        self.check(&state)?;
        if entry.input().service_instance != self.instance
            || !live_grant(&state)?
                .projects
                .contains(&entry.input().project_id)
        {
            return Err(Error::AccessDenied);
        }
        let point = Self::identity_point(&state, &entry.input().project_id)?;
        let scope = entry.scope();
        if point.runtime_id != scope.runtime_id
            || point.root != scope.root
            || point.device != scope.device
            || point.inode != scope.inode
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub(super) fn identity_action_request(
        &self,
        client: &ClientSession,
        query: &identity::Query,
        kind: Option<action::Kind>,
        start: Option<&action::Start>,
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
        // Retain the existing read-admission lock across memory-only enqueue.
        // Inbox callbacks never take Doc/Edit/Host or perform service/store IO.
        let result = self
            .identity_requests
            .identity_action(query, kind, start, cancel)
            .map(p::ResponseBody::IdentityAction);
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
    fn actual_read_access_cannot_prepare_or_start_an_undelegated_proposal() {
        let f = Fixture::new();
        let service =
            ApplicationService::open(Arc::new(PrivateStateDirectory::open(&f.app).unwrap()))
                .unwrap();
        let (project, root) = register_fixture(&service, &f.app, "project", "project-1");
        service
            .publish_passive_snapshot("project-1", &passive(&root, &"a".repeat(64)))
            .unwrap();
        service
            .allow_agent_read(vec![project.clone()], Duration::from_secs(60))
            .unwrap();
        let client = service.admit_client().unwrap();
        let query = identity::Query {
            service_instance: service.instance().clone(),
            project_id: project,
            intent_id: Id::random().unwrap(),
        };
        assert!(service
            .identity_action_request(&client, &query, Some(action::Kind::Prepare), None, false)
            .is_err());
        assert!(service
            .identity_requests
            .claim_identity_action()
            .unwrap()
            .is_none());
        service.stop().unwrap();
        service.store.close().unwrap();
    }
}
