//! Same actual main-Webview/native image Session. The IPC request cannot
//! supply a path, image buffer, source baseline, private link or new owner.
use super::*;
use crate::{
    service_metadata_images_prepare_protocol as p, service_metadata_images_prepare_requests::Kind,
};
use serde::Deserialize;
fn public(e: crate::service_protocol::Error) -> BridgeError {
    application_service::public_error(e)
}
fn refused() -> BridgeError {
    BridgeError::new(
        "cli_access_changed",
        "Keep the same opened, untouched image Import and original Desktop READ permission.",
    )
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Inspect {
    origin: p::Query,
    original: p::Original,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Prepare {
    intent: String,
    origin: p::Query,
}
pub(crate) fn inspect_request(v: Value) -> Result<Inspect, BridgeError> {
    p::bounded(&v, p::REQUEST_BYTES).map_err(public)?;
    let v: Inspect = serde_json::from_value(v).map_err(|_| BridgeError::invalid())?;
    v.original.validate().map_err(public)?;
    Ok(v)
}
pub(crate) fn prepare_request(v: Value) -> Result<p::Query, BridgeError> {
    p::bounded(&v, p::REQUEST_BYTES).map_err(public)?;
    let v: Prepare = serde_json::from_value(v).map_err(|_| BridgeError::invalid())?;
    if v.intent != "agent-metadata-images-prepare" {
        return Err(BridgeError::invalid());
    }
    Ok(v.origin)
}
impl DocumentBinding {
    pub(super) fn images_preparation_memory(&self, s: &DocumentState) -> Result<(), BridgeError> {
        let d = lookup_memory::retained_document_bytes(&self.inner, s).map_err(|_| refused())?;
        #[cfg(any(
            all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
            all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )
        ))]
        let extra =
            installation_memory::additional_document_bytes(self, s).map_err(|_| refused())?;
        #[cfg(not(any(
            all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
            all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )
        )))]
        let extra: usize = { return Err(refused()) };
        let edit = self.inner.bridge.edits.images_agent_prepare_backing()?;
        d.checked_add(extra)
            .and_then(|n| n.checked_add(edit))
            .filter(|n| *n <= SESSION_BYTES)
            .ok_or_else(refused)?;
        Ok(())
    }
    pub(crate) fn agent_metadata_images_prepare_status(
        &self,
        q: Option<&p::Query>,
    ) -> Result<Option<p::Status>, BridgeError> {
        let service = self.images_agent_service()?;
        if let Some(s) = service
            .configuration_requests()
            .images_preparation_status(q)
            .map_err(public)?
        {
            let e = service
                .configuration_requests()
                .images_preparation_entry(&s.origin)
                .map_err(public)?;
            if self.inner.bridge.edits.images_prepare_tick(&e).is_err() {
                e.unknown();
            }
        }
        service
            .publish_metadata_images_preparation_history()
            .map_err(public)?;
        service
            .configuration_requests()
            .images_preparation_status(q)
            .map_err(public)
    }
    pub(crate) fn inspect_agent_metadata_images(
        &self,
        w: &str,
        args: Inspect,
    ) -> Result<p::Status, BridgeError> {
        let service = self.images_agent_service()?;
        let e = service
            .configuration_requests()
            .images_preparation_entry(&args.origin)
            .map_err(public)?;
        if !e.pending(Kind::Read).map_err(public)? {
            return e.status().map_err(public);
        }
        let call = e.caller(Kind::Read).map_err(public)?;
        let result = (|| {
            service.metadata_images_current(&e.scope).map_err(public)?; // OFF Doc/Edit
            let s = self.lock();
            self.images_agent_peer_gates(&s)?;
            self.images_preparation_memory(&s)?;
            let project = self.service_project_locked(&s, &e.scope.saved.runtime_id)?;
            if project.canonical_root != e.scope.saved.root
                || project.device != e.scope.saved.device
                || project.inode != e.scope.saved.inode
            {
                return Err(refused());
            }
            self.inner
                .bridge
                .edits
                .inspect_agent_images(w, &e, &args.original)
        })();
        call.returned(result.is_ok()).map_err(public)?;
        service
            .publish_metadata_images_preparation_history()
            .map_err(public)?;
        result?;
        e.status().map_err(public)
    }
    pub(crate) fn prepare_agent_metadata_images(
        &self,
        w: &str,
        q: &p::Query,
    ) -> Result<crate::metadata_images_edit_protocol::MetadataImagesEditStatus, BridgeError> {
        let service = self.images_agent_service()?;
        let e = service
            .configuration_requests()
            .images_preparation_entry(q)
            .map_err(public)?;
        if !e.pending(Kind::Prepare).map_err(public)? {
            return self.inner.bridge.edits.metadata_images_status();
        }
        let call = e.caller(Kind::Prepare).map_err(public)?;
        let result = (|| {
            service.metadata_images_current(&e.scope).map_err(public)?;
            let claim = {
                let s = self.lock();
                self.images_agent_peer_gates(&s)?;
                self.images_preparation_memory(&s)?;
                let project = self.service_project_locked(&s, &e.scope.saved.runtime_id)?;
                if project.canonical_root != e.scope.saved.root
                    || project.device != e.scope.saved.device
                    || project.inode != e.scope.saved.inode
                {
                    return Err(refused());
                }
                self.inner.bridge.edits.claim_agent_images_prepare(
                    w,
                    e.clone(),
                    project,
                    &service,
                    MetadataImagesAgentGate {
                        document: Arc::downgrade(&self.inner),
                    },
                )?
            };
            let mut publisher = self
                .inner
                .android_registration_control
                .reserve(RegistrationPublisherKind::General, false)?;
            let result = (|| {
                let mut s = self.lock();
                self.images_agent_same(&s, &claim.link.project)?;
                let o = e.observation().map_err(public)?;
                self.inner.bridge.edits.images_prepare_origin(
                    w,
                    o.original.session_id.as_str(),
                    Some(&e),
                )?;
                claim.link.begin(&publisher, 0)?;
                let root = self.registered_edit_root_locked_published(
                    &mut s,
                    crate::edit_protocol::EditDomain::MetadataImages,
                    |b| {
                        b.edits
                            .metadata_images_project(w, o.original.session_id.as_str())
                    },
                    None,
                    &mut publisher,
                )?;
                claim.link.accepted(&publisher, 0)?;
                self.inner
                    .bridge
                    .edits
                    .prepare_agent_images(&publisher, w, claim, root)
            })();
            if publisher.accepted() {
                publisher.finish();
            } else {
                publisher.reject();
            }
            result
        })();
        if result.is_err() {
            self.inner.bridge.edits.images_prepare_failed(w, &e);
        }
        call.returned(result.is_ok()).map_err(public)?;
        service
            .publish_metadata_images_preparation_history()
            .map_err(public)?;
        result
    }
    pub(crate) fn cancel_agent_metadata_images_preparation(
        &self,
        q: &p::Query,
    ) -> Result<p::Status, BridgeError> {
        let service = self.images_agent_service()?;
        let e = service
            .configuration_requests()
            .images_preparation_entry(q)
            .map_err(public)?;
        e.cancel(Instant::now()).map_err(public)?;
        service
            .publish_metadata_images_preparation_history()
            .map_err(public)?;
        e.status().map_err(public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_main_inspection_and_prepare_cannot_supply_full_image_source_or_apply() {
        use crate::service_metadata_images_prepare_protocol::fixtures::observation;
        use crate::service_metadata_images_protocol::fixtures::query;
        let inspect = serde_json::json!({"origin":query(),"original":observation().original});
        assert!(inspect_request(inspect.clone()).is_ok());
        for k in ["root", "images", "paths", "expectedBaseline", "choices"] {
            let mut v = inspect.clone();
            v[k] = serde_json::json!([]);
            assert!(inspect_request(v).is_err());
        }
        let prepare =
            serde_json::json!({"intent":"agent-metadata-images-prepare","origin":query()});
        assert_eq!(prepare_request(prepare.clone()).unwrap(), query());
        for intent in ["agent-metadata-images", "recover", "prepare"] {
            let mut v = prepare.clone();
            v["intent"] = serde_json::json!(intent);
            assert!(prepare_request(v).is_err());
        }
    }
}
