//! Profile-only selected material on the original Store writer. The ordinary
//! release/read P8 role is unchanged; these five fixed inputs require a fresh
//! local/iOS/candidate Provisioning context and genuine stored P8/P12 loans.
use super::*;
use crate::apple_provisioning_protocol as provisioning;
use vault::profile_sources::AppleProfileSources;

pub(super) fn borrow(
    document: &DocumentBinding,
    state: &DocumentState,
    context: &provisioning::Context,
    registration: u32,
    root: &asset_source::RegisteredRoot,
) -> Result<Arc<SelectedStoreMaterial>, BridgeError> {
    if !context.mode.profile() || !context.valid() {
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
    let sources = AppleProfileSources::capture(document, state, &native, &key, &payload)
        .map_err(|_| refused())?;
    let selected = sources.p12().reference();
    if context.p12_record_id.as_deref() != Some(selected.record_id.as_str())
        || context.p12_record_revision != Some(selected.revision_counter)
    {
        return Err(refused());
    }
    let result = Arc::new(SelectedStoreMaterial {
        native,
        key,
        payload,
        command: Some(StoreCommand::Provisioning(context.clone())),
        prepare_document: Some(Arc::downgrade(&document.inner)),
        execute_tools: None,
        supplemental: std::array::from_fn(|_| None),
        profile_sources: Some(sources),
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
    pub(crate) fn profile_sources(&self) -> Option<&Arc<AppleProfileSources>> {
        self.profile_sources.as_ref()
    }
    pub(super) fn profile_current(
        &self,
        state: &DocumentState,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> bool {
        let Some(StoreCommand::Provisioning(context)) = &self.command else {
            return false;
        };
        let Some(sources) = &self.profile_sources else {
            return false;
        };
        let Some(document) = self.prepare_document.as_ref().and_then(Weak::upgrade) else {
            return false;
        };
        context.mode.profile()
            && self.provisioning_matches(context, registration, root)
            && self.supplemental.iter().all(Option::is_none)
            && sources.current(&DocumentBinding { inner: document }, state)
            && Arc::ptr_eq(&self.native, sources.native())
            && apple_parts(&self.payload).is_some()
    }
    pub(super) fn profile_parts(&self) -> Result<Vec<(&'static str, &[u8])>, BridgeError> {
        let Some(StoreCommand::Provisioning(context)) = &self.command else {
            return Err(refused());
        };
        if !context.mode.profile() || self.native.purpose != Purpose::Provisioning {
            return Err(refused());
        }
        let sources = self.profile_sources.as_ref().ok_or_else(refused)?;
        let (p8, key_id, issuer) = apple_parts(&self.payload).ok_or_else(refused)?;
        let [(_, p12), (_, password)] = sources.p12().private_parts().map_err(|_| refused())?;
        let mut result = Vec::new();
        result.try_reserve_exact(5).map_err(|_| refused())?;
        result.extend([
            ("asc-p8", p8),
            ("asc-key-id", key_id),
            ("asc-issuer-id", issuer),
            ("apple-p12", p12),
            ("apple-p12-password", password),
        ]);
        Ok(result)
    }
    pub(crate) fn provisioning_profile_input_bytes(&self) -> Option<usize> {
        self.profile_sources.as_ref()?;
        self.profile_parts()
            .ok()?
            .iter()
            .try_fold(0usize, |sum, (_, value)| sum.checked_add(value.len()))
    }
}
