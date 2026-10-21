//! Actual main-Webview continuation of a Desktop-prepared Import. No picker,
//! source bytes, executor or replacement image owner enters this facade.
use super::*;
use crate::{
    application_service::ApplicationService,
    application_service_host::NativeProject,
    edit_owner::{MetadataImagesDecision, MetadataImagesStep},
    service_metadata_images_protocol as p, service_metadata_images_requests as requests,
};
use serde::Deserialize;
use std::sync::Weak;
fn public(e: crate::service_protocol::Error) -> BridgeError {
    application_service::public_error(e)
}
fn refused() -> BridgeError {
    BridgeError::new(
        "cli_access_changed",
        "Keep the same prepared image preview and original Desktop read permission.",
    )
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Allow {
    project_id: String,
    original: p::Original,
    status_revision: u32,
    nonce: crate::service_protocol::Id,
    consent: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Revoke {
    nonce: crate::service_protocol::Id,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Apply {
    intent: String,
    origin: p::Query,
}
pub(crate) fn raw_request(b: &[u8]) -> Result<Value, BridgeError> {
    if b.is_empty() || b.len() > p::REQUEST_BYTES {
        return Err(BridgeError::invalid());
    }
    let v = crate::protocol::strict_json(b)?;
    if !v.is_object() {
        return Err(BridgeError::invalid());
    }
    Ok(v)
}
pub(crate) fn status_request(v: Value) -> Result<Option<p::Query>, BridgeError> {
    p::bounded(&v, p::REQUEST_BYTES).map_err(public)?;
    if v.as_object().is_some_and(|m| m.is_empty()) {
        Ok(None)
    } else {
        serde_json::from_value(v)
            .map(Some)
            .map_err(|_| BridgeError::invalid())
    }
}
pub(crate) fn allow_request(v: Value) -> Result<Allow, BridgeError> {
    p::bounded(&v, p::REQUEST_BYTES).map_err(public)?;
    let a: Allow = serde_json::from_value(v).map_err(|_| BridgeError::invalid())?;
    a.original.validate().map_err(public)?;
    if !crate::protocol::valid_id(&a.project_id)
        || a.status_revision == u32::MAX
        || a.consent != p::CONSENT
    {
        return Err(BridgeError::invalid());
    }
    Ok(a)
}
pub(crate) fn revoke_request(v: Value) -> Result<Revoke, BridgeError> {
    p::bounded(&v, p::REQUEST_BYTES).map_err(public)?;
    serde_json::from_value(v).map_err(|_| BridgeError::invalid())
}
pub(crate) fn apply_request(v: Value) -> Result<p::Query, BridgeError> {
    p::bounded(&v, p::REQUEST_BYTES).map_err(public)?;
    let a: Apply = serde_json::from_value(v).map_err(|_| BridgeError::invalid())?;
    if a.intent != "agent-metadata-images" {
        return Err(BridgeError::invalid());
    }
    Ok(a.origin)
}
pub(crate) struct MetadataImagesAgentGate {
    document: Weak<Inner>,
}
impl MetadataImagesAgentGate {
    pub(crate) fn same_publisher(&self, p: &RegistrationPublisher) -> bool {
        self.document
            .upgrade()
            .is_some_and(|d| p.same_slot(&d.android_registration_control))
    }
    pub(crate) fn epoch(&self) -> Result<u64, BridgeError> {
        self.document
            .upgrade()
            .ok_or_else(refused)?
            .android_registration_control
            .epoch()
    }
}
impl DocumentBinding {
    fn images_agent_service(&self) -> Result<Arc<ApplicationService>, BridgeError> {
        self.inner
            .bridge
            .application_service
            .configuration_service()
            .map_err(public)
    }
    pub(crate) fn agent_metadata_images_status(
        &self,
        q: Option<&p::Query>,
    ) -> Result<p::Access, BridgeError> {
        let service = self.images_agent_service()?;
        service.publish_metadata_images_history().map_err(public)?;
        service
            .configuration_requests()
            .images_access(q)
            .map_err(public)
    }
    pub(crate) fn agent_metadata_images_relay(&self) -> Result<Option<p::Access>, BridgeError> {
        let service = match self.images_agent_service() {
            Ok(s) => s,
            Err(e) if e.code == "cli_access_unavailable" => return Ok(None),
            Err(e) => return Err(e),
        };
        service.publish_metadata_images_history().map_err(public)?;
        service
            .configuration_requests()
            .images_access(None)
            .map(Some)
            .map_err(public)
    }
    pub(crate) fn agent_metadata_images_relay_lost(&self) {
        self.inner.bridge.edits.images_relay_lost();
        if let Ok(s) = self.images_agent_service() {
            s.configuration_requests().close(Instant::now());
        }
    }
    fn images_agent_memory(&self, state: &DocumentState) -> Result<(), BridgeError> {
        let retained =
            lookup_memory::retained_document_bytes(&self.inner, state).map_err(|_| refused())?;
        #[cfg(any(
            all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
            all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )
        ))]
        let extra =
            installation_memory::additional_document_bytes(self, state).map_err(|_| refused())?;
        #[cfg(not(any(
            all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
            all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )
        )))]
        let extra: usize = { return Err(refused()) };
        let edit = self.inner.bridge.edits.images_agent_edit_backing()?;
        retained
            .checked_add(extra)
            .and_then(|n| n.checked_add(edit))
            .filter(|n| *n <= SESSION_BYTES)
            .ok_or_else(refused)?;
        Ok(())
    }
    fn images_agent_peers(&self, state: &DocumentState) -> Result<(), BridgeError> {
        self.service_document_gate(state)?;
        self.passive_query_gate_locked(state, &self.inner.bridge)?;
        state.github.setup_ensure_idle()?;
        if !self.inner.bridge.supervisor.can_exit()
            || state.github.native_work_pending()
            || state
                .slot
                .as_ref()
                .is_some_and(|s| s.phase != Phase::Idle || !s.owner.resources_settled())
            || gh_auth::pending(state)
            || git_read::pending(state)
            || git_local::pending(state)
            || version_allocation::pending(state)
            || version_enrollment::pending(state)
        {
            return Err(refused());
        }
        self.images_agent_memory(state)
    }
    fn images_agent_same(
        &self,
        state: &DocumentState,
        old: &NativeProject,
    ) -> Result<(), BridgeError> {
        let n = self.service_project_locked(state, &old.runtime_id)?;
        if n.registration_generation != old.registration_generation
            || n.canonical_root != old.canonical_root
            || n.device != old.device
            || n.inode != old.inode
            || n.input_revision != old.input_revision
            || !Arc::ptr_eq(&n.document_identity, &old.document_identity)
        {
            return Err(refused());
        }
        Ok(())
    }
    pub(crate) fn allow_agent_metadata_images_apply(
        &self,
        w: &str,
        args: Allow,
    ) -> Result<p::Access, BridgeError> {
        let service = self.images_agent_service()?; // real Host/Store, OFF Doc/Edit
        let (project, original) = {
            let s = self.lock();
            self.images_agent_peers(&s)?;
            (
                self.service_project_locked(&s, &args.project_id)?,
                self.inner
                    .bridge
                    .edits
                    .images_prepared(w, &args.original, args.status_revision)?,
            )
        };
        let point = service
            .version_reserve_point(&project.runtime_id)
            .map_err(public)?;
        if point.saved.root != project.canonical_root
            || point.saved.device != project.device
            || point.saved.inode != project.inode
        {
            return Err(refused());
        }
        {
            let s = self.lock();
            self.images_agent_peers(&s)?;
            self.images_agent_same(&s, &project)?;
            self.inner.bridge.edits.images_install(
                w,
                original,
                project,
                requests::Scope {
                    saved: point.saved,
                    read: point.read,
                },
                args.nonce,
                &service,
                MetadataImagesAgentGate {
                    document: Arc::downgrade(&self.inner),
                },
            )?;
        }
        service
            .configuration_requests()
            .images_access(None)
            .map_err(public)
    }
    pub(crate) fn revoke_agent_metadata_images(
        &self,
        args: Revoke,
    ) -> Result<p::Revoked, BridgeError> {
        self.images_agent_service()?
            .configuration_requests()
            .images_revoke(&args.nonce, Instant::now())
            .map_err(public)
    }
    pub(crate) fn apply_agent_metadata_images(
        &self,
        w: &str,
        q: &p::Query,
    ) -> Result<crate::metadata_images_edit_protocol::MetadataImagesEditStatus, BridgeError> {
        let service = self.images_agent_service()?;
        let e = service
            .configuration_requests()
            .images_entry(q)
            .map_err(public)?;
        if !e.pending().map_err(public)? {
            return self.inner.bridge.edits.metadata_images_status();
        }
        let call = e.caller().map_err(public)?;
        let result = (|| {
            let grant = e.grant.as_ref().ok_or_else(refused)?;
            service
                .metadata_images_current(&grant.scope)
                .map_err(public)?; // OFF Doc/Edit
            self.apply_images_permitted(
                w,
                grant.review.original.session_id.as_str(),
                grant.review.original.plan_token.as_str(),
                Some(&e),
            )
        })();
        if result.is_err() {
            let _ = e.cancel(Instant::now());
            self.inner
                .bridge
                .edits
                .close_metadata_images(
                    w,
                    e.grant
                        .as_ref()
                        .ok_or_else(refused)?
                        .review
                        .original
                        .session_id
                        .as_str(),
                )
                .ok();
        }
        call.returned().map_err(public)?;
        service.publish_metadata_images_history().map_err(public)?;
        result
    }
    pub(crate) fn apply_images_permitted(
        &self,
        w: &str,
        session: &str,
        plan: &str,
        e: Option<&Arc<requests::Entry>>,
    ) -> Result<crate::metadata_images_edit_protocol::MetadataImagesEditStatus, BridgeError> {
        let (decision, link) = {
            let s = self.lock();
            self.images_agent_peers(&s)?;
            let l = self.inner.bridge.edits.images_link(w, session)?;
            self.images_agent_same(&s, &l.project)?;
            (
                self.inner
                    .bridge
                    .edits
                    .images_preclaim(w, session, plan, e)?,
                l,
            )
        };
        let MetadataImagesDecision::Apply(claim) = decision else {
            return self.inner.bridge.edits.metadata_images_status();
        };
        // The exact same original publisher/root/queue as ordinary image Apply.
        // The private Entry/GUI claim was acquired BEFORE this side effect.
        let result = (|| {
            let mut p = self
                .inner
                .android_registration_control
                .reserve(RegistrationPublisherKind::General, false)?;
            let result = (|| {
                let mut s = self.lock();
                self.images_agent_same(&s, &link.project)?;
                link.begin(&p, MetadataImagesStep::Apply)?;
                let root = self.registered_edit_root_locked_published(
                    &mut s,
                    crate::edit_protocol::EditDomain::MetadataImages,
                    |b| b.edits.metadata_images_project(w, session),
                    None,
                    &mut p,
                )?;
                link.accepted(&p, MetadataImagesStep::Apply)?;
                self.inner
                    .bridge
                    .edits
                    .apply_images_claimed(&p, w, session, plan, root, &claim)
            })();
            finish_registration_publisher(p);
            result
        })();
        if result.is_err() {
            self.inner.bridge.edits.images_claim_failed(&claim)
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p::fixtures::*;
    #[test]
    fn image_main_request_grammar_is_scalar_and_requires_the_original_apply_arm() {
        let good = serde_json::json!({"projectId":"project","original":original(),"statusRevision":4,"nonce":id('5'),"consent":p::CONSENT});
        assert!(allow_request(good.clone()).is_ok());
        for field in ["paths", "images", "choices", "recovery", "platform"] {
            let mut bad = good.clone();
            bad[field] = serde_json::json!([]);
            assert!(allow_request(bad).is_err());
        }
        let mut bad = good;
        bad["consent"] = serde_json::json!("agent-exact-metadata-text-v1");
        assert!(allow_request(bad).is_err());
        assert!(status_request(serde_json::json!({})).unwrap().is_none());
        assert_eq!(
            status_request(serde_json::to_value(query()).unwrap()).unwrap(),
            Some(query())
        );
        assert!(status_request(serde_json::json!({"requestId":id('3')})).is_err());
        assert_eq!(
            apply_request(serde_json::json!({"intent":"agent-metadata-images","origin":query()}))
                .unwrap(),
            query()
        );
        assert!(apply_request(serde_json::json!({"intent":"recover","origin":query()})).is_err());
        assert!(raw_request(&vec![b' '; p::REQUEST_BYTES + 1]).is_err());
        assert!(raw_request(br#"{"nonce":"a","nonce":"b"}"#).is_err());
    }
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )
    ))]
    #[test]
    fn actual_default_document_image_quote_fits_and_keeps_retained_capacity_charged() {
        let bridge = Arc::new(DesktopBridge::new(std::path::PathBuf::from(
            "/never-opened-image-document-census",
        )));
        let document = DocumentBinding::new(bridge.clone());
        bridge.edits.initial_document("main").unwrap();
        let mut state = document.lock();
        // Actual complete Document and Edit quotes, not a fabricated D. This
        // default census is not a native active image Session or availability.
        assert!(document.images_agent_memory(&state).is_ok());
        assert!(bridge
            .edits
            .images_prepared("main", &original(), 0)
            .is_err());
        state
            .records
            .reserve_exact(SESSION_BYTES / std::mem::size_of::<Record>() + 1);
        let capacity = state.records.capacity();
        assert!(state.records.is_empty());
        assert!(document.images_agent_memory(&state).is_err());
        assert_eq!(state.records.capacity(), capacity);
        assert!(state.records.is_empty());
    }
}
