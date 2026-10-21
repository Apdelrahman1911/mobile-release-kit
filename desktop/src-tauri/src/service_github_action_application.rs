//! Authenticated IDs-only three-action delegation on the original service. No native imports.
use super::*;
use crate::{service_github_action_protocol as wire, service_github_action_requests as requests};
pub(crate) struct Point {
    pub(crate) saved: crate::agent_identity_requests::SavedPoint,
    pub(crate) read: Arc<crate::service_version_reserve_requests::ReadPermission>,
}
impl ApplicationService {
    pub(crate) fn github_action_requests(&self) -> &Arc<requests::Inbox> {
        &self.github_action_requests
    }
    /// OFF Doc/Edit; check() actually reads the original private Service store.
    pub(crate) fn github_action_point(&self, runtime: &str) -> Result<Point, Error> {
        let state = self.lock()?;
        self.check(&state)?;
        let id = state.runtime_aliases.get(runtime).ok_or(Error::Conflict)?;
        let grant = live_grant(&state)?;
        if !grant.projects.contains(id) {
            return Err(Error::AccessDenied);
        }
        let saved = Self::identity_point(&state, id)?;
        if saved.runtime_id != runtime || !saved.fresh {
            return Err(Error::Conflict);
        }
        Ok(Point {
            saved,
            read: grant.reserve_read.clone(),
        })
    }
    pub(super) fn service_github_action_submit(
        &self,
        client: &ClientSession,
        input: wire::Submit,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &input.origin.project_id)?;
        Self::identity_point(&state, &input.origin.project_id)?;
        let result = self
            .github_action_requests
            .submit(input)
            .map(p::ResponseBody::GitHubActionRequest);
        drop(state);
        result
    }
    pub(super) fn service_github_action_query(
        &self,
        client: &ClientSession,
        q: &wire::Query,
        cancel: bool,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &q.project_id)?;
        Self::identity_point(&state, &q.project_id)?;
        let result = self
            .github_action_requests
            .query(q, cancel)
            .map(p::ResponseBody::GitHubActionRequest);
        drop(state);
        result
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
    fn copied_status_presend_rechecks_project_alias_and_same_read_grant() {
        // Actual original Service/private StatePort; no socket, native owner,
        // provider or Desktop consent is entered. Only the queued metadata
        // scope is inert DATA. In particular there is no retirement receipt.
        let fixture = Fixture::new();
        let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
        let service = ApplicationService::open(store.clone()).unwrap();
        let (project, root) = register_fixture(&service, &fixture.app, "project", "project-1");
        let (other, _) = register_fixture(&service, &fixture.app, "other", "project-2");
        service
            .publish_passive_snapshot("project-1", &passive(&root, &"a".repeat(64)))
            .unwrap();
        service
            .allow_agent_read(vec![project.clone()], Duration::from_secs(30))
            .unwrap();
        let client = service.admit_client().unwrap();
        let point = service.github_action_point("project-1").unwrap();
        let document = Arc::new(());
        let scope = requests::NativeScope::new(
            point.saved.project_id,
            point.saved.runtime_id,
            point.saved.root,
            point.saved.device,
            point.saved.inode,
            point.saved.revision,
            wire::Review::from_prepared(wire::Kind::RepositoryCreate, wire::PreparedReference {
                session_id: "github-connection-1".into(),
                consent_id: "a".repeat(32),
                expected_revision: 1,
                prepared_sha256: "b".repeat(64),
            }).unwrap(),
            Arc::new(()),
            Instant::now() + Duration::from_secs(20),
            point.read,
            Arc::downgrade(&document),
            tokio::sync::watch::channel(0).0,
        );
        let grant = Id::random().unwrap();
        service
            .github_action_requests()
            .allow(scope, grant.clone())
            .unwrap();
        let origin = wire::Query {
            project_id: project.clone(),
            service_instance: service.instance().clone(),
            request_id: Id::random().unwrap(),
        };
        let request = |body| p::Request {
            version: 1,
            request_id: Id::random().unwrap(),
            request: body,
        };
        let before = store.read(Namespace::Projects).unwrap();
        let submitted = service.dispatch(
            &client,
            request(p::RequestBody::GitHubActionSubmit(wire::Submit {
                origin: origin.clone(),
                grant_id: grant,
            })),
        );
        assert!(matches!(
            submitted.response,
            p::ResponseBody::GitHubActionRequest(_)
        ));
        let copied = service.dispatch(
            &client,
            request(p::RequestBody::GitHubActionStatus(origin.clone())),
        );
        // Encode before changing registration, just as serve_exchange does.
        let encoded = p::encode_response(&copied).unwrap();
        assert!(!encoded.is_empty());
        let p::ResponseBody::GitHubActionRequest(view) = &copied.response else {
            panic!("expected the same queued GitHub request");
        };
        assert_eq!(view.origin, origin);
        assert_eq!(view.state, wire::State::Queued);
        assert!(view.operation_id.is_none());
        assert_eq!(view.effect, wire::Effect::NotSent);
        assert_eq!(view.settlement, p::Settlement::Pending);
        let presend = |client: &ClientSession| {
            service.android_tools_client_current(client, &view.origin.project_id)
        };
        assert_eq!(presend(&client), Ok(()));

        service
            .state
            .lock()
            .unwrap()
            .runtime_aliases
            .remove("project-1");
        // The former generic fallback still succeeds: same service/grant is
        // insufficient once the copied response's project has disappeared.
        assert_eq!(service.client_current(&client), Ok(()));
        assert_eq!(presend(&client), Err(Error::Conflict));
        // Deliberate DATA corruption seam, not a production alias replacement:
        // rebinding the old runtime label cannot authorize the old project.
        service
            .state
            .lock()
            .unwrap()
            .runtime_aliases
            .insert("project-1".into(), other);
        assert_eq!(service.client_current(&client), Ok(()));
        assert_eq!(presend(&client), Err(Error::Conflict));
        service
            .state
            .lock()
            .unwrap()
            .runtime_aliases
            .insert("project-1".into(), project.clone());
        assert_eq!(presend(&client), Ok(()));

        service.revoke_agent_read().unwrap();
        assert_eq!(presend(&client), Err(Error::AccessDenied));
        service
            .allow_agent_read(vec![project], Duration::from_secs(30))
            .unwrap();
        let next_client = service.admit_client().unwrap();
        assert_eq!(presend(&client), Err(Error::AccessDenied));
        assert_eq!(presend(&next_client), Ok(()));
        // Re-Allow can read the retained ID, never revive the old READ/client
        // or invent a new submission/native completion.
        let next = service.dispatch(
            &next_client,
            request(p::RequestBody::GitHubActionStatus(origin.clone())),
        );
        let p::ResponseBody::GitHubActionRequest(next) = next.response else {
            panic!("expected retained same-request metadata");
        };
        assert_eq!(next.origin, origin);
        assert_eq!(next.reason, wire::Reason::PermissionRevoked);
        assert_eq!(next.state, wire::State::Stopping);
        assert!(next.operation_id.is_none());
        assert_eq!(next.effect, wire::Effect::NotSent);
        assert_eq!(next.settlement, p::Settlement::Pending);
        assert_eq!(service.github_action_requests().entries().unwrap().len(), 1);
        let after = store.read(Namespace::Projects).unwrap();
        assert_eq!(before.revision, after.revision);
        assert_eq!(before.bytes, after.bytes);
        service.stop().unwrap();
        store.close().unwrap();
    }
}
