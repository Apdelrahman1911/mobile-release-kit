//! Private comparison proof for fixed MAIN-reviewed Android key actions. This
//! child can observe the original Setup/Preview; IPC and status cannot mint it.
use super::*;
use crate::{service_upload_key_protocol as agent, service_upload_key_requests as requests};
use crate::asset_session::vault::backup_delegation;
#[path = "credential_upload_key_reuse.rs"]
mod reuse;
#[path = "credential_cli_delegation.rs"]
pub(in crate::asset_session) mod credential;

pub(in crate::asset_session) struct Proof {
    context: Weak<NativeContext>,
    store: Weak<Mutex<store::StoreBook>>,
    key: Weak<crypto::VaultKey>,
    action: Selected,
}
enum Selected {
    Prepare(reuse::Selection),
    Generate(Weak<PreparedSetup>),
    Bind {
        owner: Weak<OriginalWork>,
        token: String,
        reference: StoredRef,
        end: Instant,
    },
    Backup(backup_delegation::Selection),
}
impl Proof {
    pub(in crate::asset_session) fn retained_bytes(&self) -> usize {
        // Weak pointers keep their original allocation header/body alive even
        // after destruction of contents. No decrypted payload is copied here.
        std::mem::size_of::<Self>()
            + 3 * 2 * std::mem::size_of::<usize>()
            + std::mem::size_of::<NativeContext>()
            + std::mem::size_of::<Mutex<store::StoreBook>>()
            + std::mem::size_of::<crypto::VaultKey>()
            + match &self.action {
                Selected::Prepare(selected) => selected.extra_bytes(),
                Selected::Generate(_) => 2 * std::mem::size_of::<usize>() + std::mem::size_of::<PreparedSetup>(),
                Selected::Bind { token, .. } => {
                    2 * std::mem::size_of::<usize>() + std::mem::size_of::<OriginalWork>() + token.capacity()
                }
                Selected::Backup(s) => s.extra_bytes(), // Ordinary fixed comparison has no extra allocation.
            }
    }
    pub(in crate::asset_session) fn end(&self, now: Instant) -> Instant {
        let cap = now + Duration::from_secs(agent::ALLOW_SECONDS);
        match &self.action {
            Selected::Prepare(_) => cap,
            Selected::Generate(_) => cap,
            Selected::Bind { end, .. } => cap.min(*end),
            Selected::Backup(_) => cap,
        }
    }
    pub(in crate::asset_session) fn kind(&self) -> agent::Kind {
        match self.action {
            Selected::Prepare(_) => agent::Kind::PrepareExisting,
            Selected::Generate(_) => agent::Kind::GenerateNew,
            Selected::Bind { .. } => agent::Kind::BindReviewed,
            Selected::Backup(ref selected) => selected.kind(),
        }
    }
    fn source_current(
        &self,
        document: &DocumentBinding,
        state: &DocumentState,
    ) -> Result<(), AssetError> {
        let context = state
            .context
            .as_ref()
            .filter(|c| self.context.as_ptr() == Arc::as_ptr(c))
            .ok_or_else(|| AssetError::new(Reason::ContextStale))?;
        if context.platform != Platform::Android
            || context.execution_mode != commands::ExecutionMode::Local
            || !document.context_matches(state, context).unwrap_or(false)
        {
            return Err(AssetError::new(Reason::ContextStale));
        }
        let session = state
            .vault
            .as_ref()
            .filter(|v| v.writable())
            .ok_or_else(|| AssetError::new(Reason::VaultInterrupted))?;
        if !session
            .key
            .as_ref()
            .is_some_and(|v| self.key.as_ptr() == Arc::as_ptr(v))
            || self.store.as_ptr() != Arc::as_ptr(&session.store)
        {
            return Err(AssetError::new(Reason::ContextStale));
        }
        Ok(())
    }
    pub(in crate::asset_session) fn current(&self, document: &DocumentBinding, state: &DocumentState) -> Result<(), AssetError> {
        self.source_current(document, state)?;
        let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
        match &self.action {
            Selected::Prepare(selected) => selected.current(state)?,
            Selected::Generate(ready) => {
                let ready = ready
                    .upgrade()
                    .ok_or_else(|| AssetError::new(Reason::ContextStale))?;
                if ready.attempted.load(Ordering::SeqCst) {
                    return Err(AssetError::new(Reason::VaultInterrupted));
                }
                current_prepared(document, state, &ready)?;
                idle(state)?;
                if session
                    .rows
                    .iter()
                    .any(|r| r.authenticated.descriptor.kind == Kind::AndroidKeystore)
                {
                    return Err(AssetError::new(Reason::SourceRefused));
                }
            }
            Selected::Bind {
                owner,
                token,
                reference,
                end,
            } => {
                let slot = state
                    .slot
                    .as_ref()
                    .filter(|s| owner.as_ptr() == Arc::as_ptr(&s.owner))
                    .ok_or_else(|| AssetError::new(Reason::ContextStale))?;
                let preview = slot
                    .preview
                    .as_ref()
                    .filter(|p| p.token.0 == *token && p.action == Action::Bind)
                    .ok_or_else(|| AssetError::new(Reason::SourceRefused))?;
                let record = preview.record.as_ref().ok_or_else(AssetError::invalid)?;
                if Instant::now() >= *end
                    || slot.review_end != Some(*end)
                    || slot.phase != Phase::Preview
                    || slot.kind != Some(Kind::AndroidKeystore)
                    || !slot.owner.resources_settled()
                    || !preview_subject_valid(state, slot, preview)
                    || !usable(state, slot, record, Kind::AndroidKeystore)
                    || !slot
                        .vault
                        .reference
                        .is_some_and(|actual| same_reference(actual, *reference))
                    || !slot
                        .assessment
                        .as_ref()
                        .is_some_and(SafeAssessment::permits)
                {
                    return Err(AssetError::new(Reason::SourceRefused));
                }
            }
            Selected::Backup(selected) => selected.current(document, state)?,
        }
        Ok(())
    }
    pub(in crate::asset_session) fn attach_prepare(&self, slot: &Slot, link: &Arc<requests::NativeLink>) -> Result<(), AssetError> {
        match &self.action { Selected::Prepare(s) => s.attach(slot, link), _ => Err(AssetError::invalid()) }
    }
    pub(in crate::asset_session) fn prepared_returned(&self, document: &DocumentBinding, state: &DocumentState,
        link: &Arc<requests::NativeLink>) -> Result<(), AssetError> {
        self.source_current(document, state)?;
        match &self.action { Selected::Prepare(s) => s.returned(state, link), _ => Err(AssetError::invalid()) }
    }
    pub(in crate::asset_session) fn prepared_view(&self, document: &DocumentBinding, state: &DocumentState,
        link: &Arc<requests::NativeLink>) -> Option<agent::Prepared> {
        self.source_current(document, state).ok()?;
        match &self.action { Selected::Prepare(s) => s.view(state, link), _ => None }
    }
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    pub(in crate::asset_session) fn run(
        &self,
        document: &DocumentBinding,
        link: Arc<requests::NativeLink>,
        app: tauri::AppHandle,
    ) -> Result<Option<u32>, AssetError> {
        match &self.action {
            Selected::Prepare(selected) => selected.run(document, link).map(Some),
            Selected::Generate(_) => {
                let (revision, context_revision) = {
                    let state = document.lock();
                    self.current(document, &state)?;
                    (
                        state.revision,
                        state
                            .context
                            .as_ref()
                            .ok_or_else(AssetError::invalid)?
                            .revision,
                    )
                };
                document
                    .create_upload_key_delegated(
                        CreateRequest {
                            context_revision,
                            expected_revision: revision,
                        },
                        link,
                    )
                    .map(|_| None)
            }
            Selected::Bind { token, .. } => {
                document.bind_vault_delegated(token, Some(link)).map(|_| None)
            }
            Selected::Backup(selected) => selected.run(document, app, link).map(|_| None),
        }
    }
    #[cfg(not(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    )))]
    pub(in crate::asset_session) fn run(
        &self,
        _document: &DocumentBinding,
        _link: Arc<requests::NativeLink>,
        #[cfg(feature = "desktop-shell")] _app: tauri::AppHandle,
    ) -> Result<Option<u32>, AssetError> {
        Err(AssetError::new(Reason::Unqualified))
    }
}

pub(in crate::asset_session) fn capture(
    document: &DocumentBinding,
    state: &DocumentState,
    selected: &agent::Selection,
    context_revision: u32,
    revision: u32,
) -> Result<Proof, AssetError> {
    capture_qualified(document, state, selected, context_revision, revision,
        crate::asset_session::vault::backup_desktop::Qualification::Ordinary)
}

pub(in crate::asset_session) fn capture_qualified(document: &DocumentBinding, state: &DocumentState,
    selected: &agent::Selection, context_revision: u32, revision: u32,
    qualification: crate::asset_session::vault::backup_desktop::Qualification) -> Result<Proof, AssetError> {
    if state.revision != revision
        || !selected.valid()
        || selected.kind() == agent::Kind::GenerateNew && !available(document)
    {
        return Err(AssetError::new(Reason::Unqualified));
    }
    let context = state
        .context
        .as_ref()
        .filter(|c| c.revision == context_revision)
        .ok_or_else(|| AssetError::new(Reason::ContextStale))?;
    let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
    let action = match selected {
        agent::Selection::PrepareExisting { record_id, expected_revision } =>
            Selected::Prepare(reuse::Selection::capture(state, record_id, *expected_revision)?),
        agent::Selection::GenerateNew { .. } => Selected::Generate(Arc::downgrade(
            session
                .upload_key_setup
                .ready
                .as_ref()
                .ok_or_else(AssetError::invalid)?,
        )),
        agent::Selection::BindReviewed {
            preview_operation_id,
            preview_token,
        } => {
            let slot = state
                .slot
                .as_ref()
                .filter(|s| s.owner.id == *preview_operation_id)
                .ok_or_else(AssetError::invalid)?;
            Selected::Bind {
                owner: Arc::downgrade(&slot.owner),
                token: preview_token.clone().into_boxed_str().into_string(),
                reference: slot.vault.reference.ok_or_else(AssetError::invalid)?,
                end: slot.review_end.ok_or_else(AssetError::invalid)?,
            }
        }
        agent::Selection::BackupEncrypted { .. } | agent::Selection::RestoreEncrypted { .. } => {
            Selected::Backup(backup_delegation::Selection::capture_qualified(document, state, selected, qualification)?)
        }
        _ => return Err(AssetError::new(Reason::SourceRefused)),
    };
    let proof = Proof {
        context: Arc::downgrade(context),
        key: Arc::downgrade(session.key.as_ref().ok_or_else(AssetError::invalid)?),
        store: Arc::downgrade(&session.store),
        action,
    };
    proof.current(document, state)?;
    Ok(proof)
}

fn reference(value: KeyReference) -> Option<agent::KeyReference> {
    let v = serde_json::to_value(value).ok()?;
    let result: agent::KeyReference = serde_json::from_value(v).ok()?;
    result.valid().then_some(result)
}
/// Native-only current publication, never read from a renderer response.
pub(in crate::asset_session) fn completion(
    document: &DocumentBinding,
    state: &DocumentState,
    slot: &Slot,
) -> Option<(agent::State, agent::Reason, Option<agent::KeyReference>)> {
    if slot.operation == Operation::Prepare {
        return crate::asset_session::agent_upload_key::prepare_completion(document, state, slot);
    }
    if !matches!(
        slot.operation,
        Operation::GenerateUploadKey | Operation::Bind | Operation::PrepareBackupExport | Operation::ImportBackup
    ) || !slot.owner.resources_settled()
    {
        return None;
    }
    let normal = slot
        .owner
        .coordinator
        .try_lock()
        .is_ok_and(|b| b.receipt == JoinReceipt::Returned && b.handle.is_none())
        && slot.owner.child.try_lock().is_ok_and(|b| {
            matches!(b.receipt, JoinReceipt::Returned | JoinReceipt::New) && b.handle.is_none()
        });
    if !normal || matches!(slot.settlement, Settlement::Unknown | Settlement::LateKnown) {
        return None;
    }
    if slot.phase != Phase::Idle || slot.settlement != Settlement::Known {
        return None;
    }
    if matches!(slot.operation, Operation::PrepareBackupExport | Operation::ImportBackup) {
        let (outcome, reason, key) = backup_delegation::completion(document, state, slot)?;
        let key = match key { Some(value) => Some(reference(value)?), None => None };
        return Some((outcome, reason, key));
    }
    if slot.operation == Operation::GenerateUploadKey {
        if let Some(key) = stored_marker(document, state, slot).and_then(reference) {
            return Some((
                agent::State::SavedUnassigned,
                agent::Reason::None,
                Some(key),
            ));
        }
        if !slot
            .owner
            .vault
            .try_lock()
            .is_ok_and(|work| work.upload_key.empty() && original_joins(&slot.owner, &work))
        {
            return None;
        }
    } else if slot.reason == Reason::None
        && slot.error.is_none()
        && slot.cleanup_end.is_none()
        && !slot.owner.stopped()
        && slot.kind == Some(Kind::AndroidKeystore)
    {
        let context = state.context.as_ref()?;
        let key = slot.result_record.as_ref().or(slot.target.as_ref())?;
        let session = state.vault.as_ref()?;
        let loan = session.bound.iter().flatten().find(|loan| {
            loan.payload.kind == Kind::AndroidKeystore
                && loan.reference.matches(key)
                && Arc::ptr_eq(&loan.context, context)
                && loan.current(state, session)
        })?;
        let key = reference(KeyReference::native(
            loan.reference.identity,
            loan.reference.record,
            loan.reference.revision,
        ))?;
        return Some((agent::State::Assigned, agent::Reason::None, Some(key)));
    }
    Some(match slot.reason {
        Reason::UserCancelled | Reason::Shutdown => (
            agent::State::Cancelled,
            agent::Reason::PermissionRevoked,
            None,
        ),
        Reason::Deadline => (agent::State::Cancelled, agent::Reason::Expired, None),
        _ => (
            agent::State::RecoveryRequired,
            agent::Reason::RecoveryRequired,
            None,
        ),
    })
}
