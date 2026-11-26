//! Original Service/read grant around bounded request memory. No IPC caller
//! obtains a vault reference, Document mutex, native admission or private bytes.
use super::*;
use crate::{service_upload_key_protocol as wire, service_upload_key_requests as requests};
pub(crate) struct UploadKeyPoint {
    pub(crate) saved: crate::agent_identity_requests::SavedPoint,
    pub(crate) read: Arc<requests::ReadPermission>,
}
impl ApplicationService {
    pub(crate) fn upload_key_requests(&self) -> &Arc<requests::Inbox> {
        &self.upload_key_requests
    }
    pub(crate) fn upload_key_point(&self, runtime: &str) -> Result<UploadKeyPoint, Error> {
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
        Ok(UploadKeyPoint {
            saved,
            read: grant.upload_key_read.clone(),
        })
    }
    pub(super) fn upload_key_scope(
        &self,
        client: &ClientSession,
        project: &Id,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, project)?;
        let out = self
            .upload_key_requests
            .access(Some(project))
            .map(p::ResponseBody::UploadKeyAccess);
        drop(state);
        out
    }
    pub(super) fn upload_key_submit(
        &self,
        client: &ClientSession,
        input: wire::Submit,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &input.origin.project_id)?;
        let out = self
            .upload_key_requests
            .submit(input)
            .map(p::ResponseBody::UploadKeyRequest);
        drop(state);
        out
    }
    pub(super) fn upload_key_query(
        &self,
        client: &ClientSession,
        q: &wire::Query,
        cancel: bool,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &q.project_id)?;
        let out = self
            .upload_key_requests
            .query(q, cancel)
            .map(p::ResponseBody::UploadKeyRequest);
        drop(state);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application_service::tests::{passive, register_fixture};
    use crate::application_state_store::Fixture;
    fn id(n: u32) -> Id {
        Id::parse(&format!("{n:032x}")).unwrap()
    }
    // Existing private Store fixture only. No vault/key/tool, native scope
    // proof, caller, daemon or IPC socket is started by either case.
    #[test]
    fn reconnect_and_revoke_preserve_the_original_request_not_a_new_permission() {
        let fixture = Fixture::new();
        let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
        let service = ApplicationService::open(store.clone()).unwrap();
        let (project, root) =
            register_fixture(&service, &fixture.app, "upload-project", "upload-project");
        service
            .publish_passive_snapshot("upload-project", &passive(&root, &"a".repeat(64)))
            .unwrap();
        service
            .allow_agent_read(vec![project.clone()], Duration::from_secs(300))
            .unwrap();
        let first = service.admit_client().unwrap();
        assert!(
            matches!(service.upload_key_scope(&first,&project).unwrap(),p::ResponseBody::UploadKeyAccess(a) if a.grant_id.is_none())
        );
        let q = wire::Query {
            project_id: project.clone(),
            service_instance: service.instance.clone(),
            request_id: id(3),
        };
        let input = wire::Submit {
            origin: q.clone(),
            grant_id: id(4),
        };
        assert!(service.upload_key_submit(&first, input.clone()).is_err());
        // Inert exact scope DATA exercises Service ownership only; it cannot
        // capture a PreparedSetup/Preview or cause the absent Asset relay GO.
        let point = service.upload_key_point("upload-project").unwrap();
        let identity = Arc::new(());
        let scope = Arc::new(requests::NativeScope {
            project_id: project.clone(),
            runtime_id: "upload-project".into(),
            kind: wire::Kind::BindReviewed,
            end: Instant::now() + Duration::from_secs(100),
            read: point.read,
            identity: Arc::downgrade(&identity),
            changes: tokio::sync::watch::channel(0).0,
        });
        service
            .upload_key_requests
            .allow(scope, input.grant_id.clone())
            .unwrap();
        assert!(
            matches!(service.upload_key_submit(&first,input.clone()).unwrap(),p::ResponseBody::UploadKeyRequest(s) if s.state==wire::State::Queued)
        );
        let second = service.admit_client().unwrap();
        assert!(
            matches!(service.upload_key_query(&second,&q,false).unwrap(),p::ResponseBody::UploadKeyRequest(s) if s.origin==q)
        );
        service.revoke_agent_read().unwrap();
        assert!(service.upload_key_query(&second, &q, false).is_err());
        service
            .allow_agent_read(vec![project.clone()], Duration::from_secs(300))
            .unwrap();
        let fresh = service.admit_client().unwrap();
        assert!(
            matches!(service.upload_key_query(&fresh,&q,false).unwrap(),p::ResponseBody::UploadKeyRequest(s) if s.state==wire::State::Cancelled && s.asset_operation_id.is_none())
        );
        assert!(
            matches!(service.upload_key_submit(&fresh,input).unwrap(),p::ResponseBody::UploadKeyRequest(s) if s.state==wire::State::Cancelled)
        );
        assert!(
            !service
                .upload_key_requests
                .access(Some(&project))
                .unwrap()
                .enabled
        );
        drop(service);
        drop(store);
        drop(fixture);
    }
    #[test]
    fn foreign_project_client_and_replaced_read_facet_cannot_borrow_upload_key_scope() {
        let fixture = Fixture::new();
        let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
        let service = ApplicationService::open(store.clone()).unwrap();
        let (a, aroot) = register_fixture(&service, &fixture.app, "upload-a", "upload-a");
        let (b, broot) = register_fixture(&service, &fixture.app, "upload-b", "upload-b");
        service
            .publish_passive_snapshot("upload-a", &passive(&aroot, &"a".repeat(64)))
            .unwrap();
        service
            .publish_passive_snapshot("upload-b", &passive(&broot, &"b".repeat(64)))
            .unwrap();
        service
            .allow_agent_read(vec![a.clone()], Duration::from_secs(300))
            .unwrap();
        let old = service.admit_client().unwrap();
        let point = service.upload_key_point("upload-a").unwrap();
        let identity = Arc::new(());
        assert!(service.upload_key_scope(&old, &b).is_err());
        assert!(service.upload_key_point("upload-b").is_err());
        service
            .allow_agent_read(vec![b.clone()], Duration::from_secs(300))
            .unwrap();
        let stale = Arc::new(requests::NativeScope {
            project_id: a.clone(),
            runtime_id: "upload-a".into(),
            kind: wire::Kind::GenerateNew,
            end: Instant::now() + Duration::from_secs(100),
            read: point.read,
            identity: Arc::downgrade(&identity),
            changes: tokio::sync::watch::channel(0).0,
        });
        assert!(service.upload_key_requests.allow(stale, id(4)).is_err());
        assert!(service.upload_key_scope(&old, &a).is_err());
        let current = service.admit_client().unwrap();
        assert!(service.upload_key_scope(&current, &b).is_ok());
        assert!(service.upload_key_scope(&current, &a).is_err());
        drop(service);
        drop(store);
        drop(fixture);
    }
}
