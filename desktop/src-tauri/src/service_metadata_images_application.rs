//! IDs-only IPC admission on the ORIGINAL shared Config Book. Execution stays
//! in the actual main Webview and its native Image EditOwner.
use super::*;
use crate::{service_metadata_images_protocol as wire, service_metadata_images_requests as rows};
impl ApplicationService {
    pub(super) fn metadata_images_scope(
        &self,
        client: &ClientSession,
        scope: &wire::Scope,
    ) -> Result<p::ResponseBody, Error> {
        let s = self.lock()?;
        self.authorize_build_client(&s, client, &scope.project_id)?;
        Self::identity_point(&s, &scope.project_id)?;
        let current = self.configuration_requests.images_access(None)?;
        let access = if current.project_id.as_ref() == Some(&scope.project_id) {
            current
        } else {
            wire::Access::empty(self.instance.clone())
        };
        Ok(p::ResponseBody::MetadataImagesAccess(access))
    }
    pub(super) fn metadata_images_submit(
        &self,
        client: &ClientSession,
        input: wire::Submit,
    ) -> Result<p::ResponseBody, Error> {
        input.validate()?;
        let s = self.lock()?;
        self.authorize_build_client(&s, client, &input.origin.project_id)?;
        Self::identity_point(&s, &input.origin.project_id)?;
        self.configuration_requests
            .images_submit(input)
            .map(p::ResponseBody::MetadataImagesRequest)
    }
    pub(super) fn metadata_images_query(
        &self,
        client: &ClientSession,
        q: &wire::Query,
        cancel: bool,
    ) -> Result<p::ResponseBody, Error> {
        let at = Instant::now();
        let s = self.lock()?;
        self.authorize_build_client(&s, client, &q.project_id)?;
        Self::identity_point(&s, &q.project_id)?;
        if self.configuration_requests.images_preparation_kind(q)? {
            let e=self.configuration_requests.images_preparation_entry(q)?;
            if cancel {e.cancel(at)?;}
            return e.status().map(p::ResponseBody::MetadataImagesPreparation);
        }
        let e = self.configuration_requests.images_entry(q)?;
        if cancel {
            e.cancel(at)?;
        }
        e.status().map(p::ResponseBody::MetadataImagesRequest)
    }
    pub(crate) fn metadata_images_current(&self, scope: &rows::Scope) -> Result<(), Error> {
        let point = self.version_reserve_point(&scope.saved.runtime_id)?;
        if !Arc::ptr_eq(&point.read, &scope.read)
            || point.saved.project_id != scope.saved.project_id
            || point.saved.root != scope.saved.root
            || point.saved.device != scope.saved.device
            || point.saved.inode != scope.saved.inode
            || point.saved.revision != scope.saved.revision
            || scope.read.stop(Instant::now())?.is_some()
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub(crate) fn publish_metadata_images_history(&self) -> Result<(), Error> {
        for e in self.configuration_requests.images_entries()? {
            if let Some((id, state, settlement)) = e.history()? {
                let g = e.grant.as_ref().ok_or(Error::StateUnknown)?;
                let result = self.begin_operation(
                    &g.scope.saved.runtime_id,
                    id,
                    p::Action::EditMetadataImages,
                    state,
                    settlement,
                );
                // Only the actual return of the SAME existing history write can
                // publish the final row. Never retry a lost/failed history ACK.
                if e.history_returned(result.is_ok()).is_err() || result.is_err() {
                    e.unknown();
                    self.fence_native_history();
                    return Err(Error::StateUnknown);
                }
            }
        }
        Ok(())
    }
}
