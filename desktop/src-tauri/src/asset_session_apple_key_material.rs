//! Dedicated local/iOS/candidate key setup material. The selected P8 keeps its
//! original BoundLoan; neither old Store/Signing contexts nor a public record
//! counter can provide the complete vault inventory or generation consent.
use super::*;
use crate::apple_provisioning_protocol as provisioning;
use vault::key_sources::AppleKeySources;

pub(super) fn borrow(
    document: &DocumentBinding,
    state: &DocumentState,
    context: &provisioning::Context,
    registration: u32,
    root: &asset_source::RegisteredRoot,
) -> Result<Arc<SelectedStoreMaterial>, BridgeError> {
    if !context.mode.local_key() || !context.valid() {
        return Err(refused());
    }
    let native = state
        .context
        .as_ref()
        .filter(|native| {
            native.revision == context.credential_context_revision
                && native.execution_mode == commands::ExecutionMode::Local
                && native.platform == Platform::Ios
                && native.stage == Stage::Candidate
                && native.purpose == Purpose::Provisioning
                && native.registry_generation == registration
                && native.project == *root
                && native.project_id == context.project_id
                && !native.draft.is_empty()
                && native.draft.len() <= 512 * 1024
        })
        .ok_or_else(refused)?
        .clone();
    let key = RecordKey {
        id: Token(context.record_id.clone()),
        revision: context.record_revision,
    };
    let payload = github_secret::assigned(state, &key, Kind::AscP8, &native)
        .ok_or_else(refused)?
        .clone();
    let sources = AppleKeySources::capture(document, state, &native, &key, &payload)
        .map_err(|_| refused())?;
    let result = Arc::new(SelectedStoreMaterial {
        native,
        key,
        payload,
        command: Some(StoreCommand::Provisioning(context.clone())),
        prepare_document: Some(Arc::downgrade(&document.inner)),
        execute_tools: None,
        supplemental: std::array::from_fn(|_| None),
        profile_sources: None,
        key_sources: Some(sources),
    });
    if !result.provisioning_matches(context, registration, root)
        || !result.current(state, registration, root)
    {
        return Err(refused());
    }
    result.parts()?;
    Ok(result)
}

impl SelectedStoreMaterial {
    pub(crate) fn key_sources(&self) -> Option<&Arc<AppleKeySources>> {
        self.key_sources.as_ref()
    }
    pub(super) fn key_current(
        &self,
        state: &DocumentState,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> bool {
        let Some(StoreCommand::Provisioning(context)) = &self.command else {
            return false;
        };
        let Some(sources) = &self.key_sources else {
            return false;
        };
        let Some(document) = self.prepare_document.as_ref().and_then(Weak::upgrade) else {
            return false;
        };
        context.mode.local_key()
            && self.provisioning_matches(context, registration, root)
            && self.profile_sources.is_none()
            && self.supplemental.iter().all(Option::is_none)
            && sources.current(&DocumentBinding { inner: document }, state)
            && Arc::ptr_eq(&self.native, sources.native())
            && apple_parts(&self.payload).is_some()
    }
    pub(in crate::asset_session) fn key_preservation_current(
        &self,
        document: &DocumentBinding,
        state: &DocumentState,
        original: &Arc<OriginalWork>,
        parent: &crate::saved_command_owner::AppleKeySession,
        context: &provisioning::Context,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> bool {
        context.mode == provisioning::Mode::KeyPrepare
            && self.provisioning_matches(context, registration, root)
            && self
                .prepare_document
                .as_ref()
                .is_some_and(|held| Weak::ptr_eq(held, &Arc::downgrade(&document.inner)))
            && self.profile_sources.is_none()
            && self.supplemental.iter().all(Option::is_none)
            && self.key_sources.as_ref().is_some_and(|sources| {
                Arc::ptr_eq(&self.native, sources.native())
                    && sources.preservation_current(document, state, original, parent)
            })
            && apple_parts(&self.payload).is_some()
    }
}
