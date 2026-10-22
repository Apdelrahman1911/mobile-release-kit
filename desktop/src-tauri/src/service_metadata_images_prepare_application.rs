//! READ-authorized fixed DATA/choice admission only; the genuine main Webview
//! continues the existing native image Session. No image/path executor here.
use super::*;
use crate::{
    service_metadata_images_prepare_protocol as wire, service_metadata_images_requests::Scope,
};
impl ApplicationService {
    pub(super) fn metadata_images_read(
        &self,
        client: &ClientSession,
        input: wire::Read,
    ) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &input.origin.project_id)?;
        let saved = Self::identity_point(&state, &input.origin.project_id)?;
        let read = live_grant(&state)?.reserve_read.clone();
        self.configuration_requests
            .images_read(input, Scope { saved, read })
            .map(p::ResponseBody::MetadataImagesPreparation)
    }
    pub(super) fn metadata_images_prepare(
        &self,
        client: &ClientSession,
        input: wire::Prepare,
    ) -> Result<p::ResponseBody, Error> {
        input.validate()?;
        let state = self.lock()?;
        self.authorize_build_client(&state, client, &input.origin.project_id)?;
        Self::identity_point(&state, &input.origin.project_id)?;
        self.configuration_requests
            .images_preparation_entry(&input.origin)?
            .prepare(input)
            .map(p::ResponseBody::MetadataImagesPreparation)
    }
    pub(crate) fn publish_metadata_images_preparation_history(&self) -> Result<(), Error> {
        for e in self.configuration_requests.images_preparation_entries()? {
            if let Some(state) = e.history()? {
                let result = self.begin_operation(
                    &e.scope.saved.runtime_id,
                    e.input.origin.request_id.clone(),
                    p::Action::EditMetadataImages,
                    state,
                    p::Settlement::Settled,
                );
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
