//! Fixed nonshipping generated-key backup journey through the EXISTING vault
//! coordinator, native StoreBook and Backup Job. No SelectedPair/GuiFacts,
//! supplied paths, private bytes, new worker or production picker exemption.
//! Only comparison metadata survives the real export's ordinary private drain.
use super::super::assignment_native::remembered_bound_reference;
use super::*;
use crate::asset_session::{Action as AssetAction, Phase as AssetPhase};
use crate::shell::installed_observation::vault::{
    upload_key::{backup::Action as BackupAction, Case},
    Case as VaultCase, Control,
};
use std::path::PathBuf;

#[derive(Default)]
pub(crate) struct Trace {
    pub(in crate::asset_session) source: Option<StoredRef>,
    pub(in crate::asset_session) generator: Weak<OriginalWork>,
    pub(in crate::asset_session) export: Weak<OriginalWork>,
    pub(in crate::asset_session) pair: Option<asset_source::ComponentPair>,
    pub(in crate::asset_session) export_returned: bool,
    pub(in crate::asset_session) import: Weak<OriginalWork>,
    pub(in crate::asset_session) target: Option<StoredRef>,
    pub(in crate::asset_session) load: Weak<OriginalWork>,
    pub(in crate::asset_session) bound: Weak<OriginalWork>,
}

// Reserved for the full lifetime of this one fixed Control, including before
// either output name exists and after the pair moves to the native Sources.
// Actual native SourceBook/cipher/private buffers retain their ordinary quotes.
const PAIR_PATH_LIMIT: usize = 4096;
pub(in crate::asset_session) fn document_bytes(inner: &Arc<Inner>) -> Result<usize, Reason> {
    let book = inner
        .installed_macos_session
        .try_lock()
        .map_err(|_| Reason::Capacity)?;
    let selected = book
        .as_ref()
        .and_then(|book| book.vault.as_ref())
        .is_some_and(|control| matches!(control.case, VaultCase::UploadKey(Case::BackupRoundTrip | Case::BackupCli)));
    if !selected {
        return Ok(0);
    }
    if book.as_ref().and_then(|b|b.vault.as_ref()).is_some_and(|c|c.case==VaultCase::UploadKey(Case::BackupCli)) {
        return Ok(crate::shell::installed_observation::vault::upload_key::cli::BACKING);
    }
    std::mem::size_of::<crate::shell::installed_observation::vault::upload_key::backup::Flow>()
        .checked_add(std::mem::size_of::<asset_source::ComponentPair>())
        .and_then(|n| n.checked_add(2 * PAIR_PATH_LIMIT))
        .ok_or(Reason::Capacity)
}

pub(in crate::asset_session) fn folders(control: &Control) -> Result<[PathBuf; 2], Reason> {
    let parent = control.root().parent().ok_or(Reason::SourceRefused)?;
    let paths = [parent.join("backup"), parent.join("recovery")];
    if paths
        .iter()
        .any(|path| path.as_os_str().len() > PAIR_PATH_LIMIT)
    {
        return Err(Reason::Capacity);
    }
    Ok(paths)
}
fn restored(control: &Control) -> Result<PathBuf, Reason> {
    let path = control
        .root()
        .parent()
        .ok_or(Reason::SourceRefused)?
        .join("restored")
        .join("dev.mobile-release-kit.desktop");
    if path.as_os_str().len() > PAIR_PATH_LIMIT {
        return Err(Reason::Capacity);
    }
    Ok(path)
}
pub(in crate::asset_session) fn fresh_reference(source: StoredRef, target: StoredRef) -> bool {
    source.identity.vault != target.identity.vault
        && source.identity.generation != target.identity.generation
        && source.record != target.record
        && source.revision.random != target.revision.random
        && source.revision.counter == 1
        && target.revision.counter == 1
        && source.original != target.original
}
pub(in crate::asset_session) fn good_slot(
    state: &DocumentState,
    slot: &Slot,
    original: &Arc<OriginalWork>,
    id: u32,
    operation: Operation,
) -> bool {
    state.next_operation == id
        && slot.owner.id == id
        && Arc::ptr_eq(&slot.owner, original)
        && slot.operation == operation
        && !state.unknown
        && !state.stopping
        && !state.lock_pending
        && !state.quit_pending
        && !state.retiring
        && !state.exhausted
        && !state.lost_observed
        && slot.reason == Reason::None
        && slot.error.is_none()
        && slot.cleanup_end.is_none()
        && !slot.owner.stopped()
        && slot.settlement != Settlement::Unknown
}
pub(in crate::asset_session) fn joined(slot: &Slot) -> bool {
    slot.settlement == Settlement::Known
        && slot.owner.ended.load(Ordering::SeqCst)
        && slot.owner.resources_settled()
        && slot
            .owner
            .coordinator
            .try_lock()
            .is_ok_and(|b| b.handle.is_none() && b.receipt == JoinReceipt::Returned)
        && slot
            .owner
            .child
            .try_lock()
            .is_ok_and(|b| b.handle.is_none() && b.receipt == JoinReceipt::Returned)
}

/// Called ONLY inside the real BackupDelivered validation, after its unchanged
/// all-join/current-reference predicate succeeds. A pair is not delivery or a
/// disposal grant: the observer separately waits the real publication + drain.
/// This can neither change normal backup admission nor capture ordinary paths.
pub(in crate::asset_session) fn capture_export(
    document: &DocumentBinding,
    state: &DocumentState,
    slot: &Slot,
    work: &super::super::Work,
    session: &Session,
) -> Result<(), Reason> {
    let control = {
        let book = document
            .inner
            .installed_macos_session
            .try_lock()
            .map_err(|_| Reason::CleanupUnknown)?;
        let Some(control) = book.as_ref().and_then(|book| book.vault.as_ref()) else {
            return Ok(());
        };
        if !matches!(control.case, VaultCase::UploadKey(Case::BackupRoundTrip | Case::BackupCli)) {
            return Ok(());
        }
        control.clone()
    };
    if !control.permits(&document.inner.session_identity)
        || slot.owner.id != 6
        || state.next_operation != 6
        || !delivered_publication(&slot.owner, work, session)
    {
        return Err(Reason::SourceChanged);
    }
    let mut trace = control
        .upload
        .backup
        .native
        .try_lock()
        .map_err(|_| Reason::CleanupUnknown)?;
    let reference = trace.source.ok_or(Reason::SourceChanged)?;
    if trace.export_returned
        || trace.pair.is_some()
        || !trace
            .export
            .upgrade()
            .is_some_and(|owner| Arc::ptr_eq(&owner, &slot.owner))
        || !slot
            .vault
            .reference
            .is_some_and(|held| same_reference(held, reference))
    {
        return Err(Reason::SourceChanged);
    }
    let custody = work
        .backup
        .inner
        .as_ref()
        .ok_or(Reason::CleanupUnknown)?
        .try_lock()
        .map_err(|_| Reason::CleanupUnknown)?;
    let Content::Export {
        reference: held,
        destination: Some(destination),
        output: Some(_),
    } = &custody.content
    else {
        return Err(Reason::SourceChanged);
    };
    if !same_reference(*held, reference) {
        return Err(Reason::SourceChanged);
    }
    let pair = if control.case == VaultCase::UploadKey(Case::BackupCli) {
        let pair = destination.installed_picker_published_pair(&slot.owner)?;
        control.upload.cli.remember_targets(pair.comparison_paths()?)?;
        pair
    } else { destination.component_published_pair(&slot.owner)? };
    let paths = folders(&control)?;
    if !pair.matches_original(&slot.owner)
        || !pair.matches_folders([&paths[0], &paths[1]])
        || pair.retained_bytes().is_none_or(|n| {
            n > std::mem::size_of::<asset_source::ComponentPair>() + 2 * PAIR_PATH_LIMIT
        })
    {
        return Err(Reason::Capacity);
    }
    trace.pair = Some(pair);
    Ok(())
}

impl DocumentBinding {
    pub(in crate::asset_session) fn installed_backup_control(&self) -> Result<Arc<Control>, AssetError> {
        let control = self.installed_upload_control()?;
        if !matches!(control.case, VaultCase::UploadKey(Case::BackupRoundTrip | Case::BackupCli)) {
            return Err(AssetError::invalid());
        }
        Ok(control)
    }
    pub(in crate::asset_session) fn installed_backup_claim(&self, action: BackupAction) -> Result<Arc<Control>, AssetError> {
        let control = self.installed_backup_control()?;
        let state = self.lock();
        let selection = control
            .upload
            .backup
            .select(
                control.clone(),
                &self.inner.session_identity,
                action,
                state.next_operation,
            )
            .ok_or_else(AssetError::invalid)?;
        selection
            .consume(&self.inner.session_identity, state.next_operation)
            .ok_or_else(AssetError::invalid)
    }
    pub(crate) fn installed_generated_backup_export(&self) -> Result<(), AssetError> {
        if self.installed_backup_control()?.case != VaultCase::UploadKey(Case::BackupRoundTrip) { return Err(AssetError::invalid()); }
        if !self
            .installed_upload_sample()
            .is_some_and(|sample| sample.positive())
        {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        let control = self.installed_backup_claim(BackupAction::Export)?;
        self.reconcile();
        let mut state = self.lock();
        self.expire(&mut state, Instant::now());
        self.durable_gate(&state, true)?;
        idle(&state)?;
        let (reference, generated) = control
            .upload
            .trace
            .try_lock()
            .map_err(|_| AssetError::new(Reason::Busy))?
            .generated_reference_data()
            .ok_or_else(AssetError::invalid)?;
        let context = state.context.clone().ok_or_else(AssetError::invalid)?;
        let old = state.slot.as_ref().ok_or_else(AssetError::invalid)?;
        let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
        if !good_slot(&state, old, &generated, 5, Operation::GenerateUploadKey)
            || !joined(old)
            || !self.context_matches(&state, &context)?
            || session.identity != Some(reference.identity)
            || !session.writable()
            || session.rows.len() != 1
            || session.inventory.as_slice() != [reference.record]
            || !session.rows.iter().any(|row| {
                !row.mutation_pending
                    && row.authenticated.descriptor.kind == Kind::AndroidKeystore
                    && same_reference(row.reference(reference.identity), reference)
            })
            || !state.assignments.is_empty()
            || session.bound.iter().any(Option::is_some)
        {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        let mut slot = self.vault_owner(
            &mut state,
            Operation::PrepareBackupExport,
            Some(context),
            Some(reference.key()),
            None,
            true,
        )?;
        if slot.owner.id != 6 {
            return Err(AssetError::invalid());
        }
        slot.kind = Some(Kind::AndroidKeystore);
        slot.vault.reference = Some(reference);
        let destination = asset_source::BackupDestinations::new_component_fixture(
            &slot.owner,
            folders(&control).map_err(AssetError::new)?,
        )
        .map_err(AssetError::new)?;
        {
            let mut trace = control
                .upload
                .backup
                .native
                .try_lock()
                .map_err(|_| AssetError::new(Reason::Busy))?;
            if trace.source.is_some() || trace.export.upgrade().is_some() || trace.pair.is_some() {
                return Err(AssetError::invalid());
            }
            trace.source = Some(reference);
            trace.generator = Arc::downgrade(&generated);
            trace.export = Arc::downgrade(&slot.owner);
        }
        // Same retained private custody and budget before GO. Only the fixed
        // nonshipping component creates this sink; choose_backup is unchanged.
        let request = retain_request(
            self,
            &mut state,
            &slot,
            Content::Export {
                reference,
                output: None,
                destination: Some(destination),
            },
            RequestKind::Export,
        )?;
        let start = self.install(
            &mut state,
            slot,
            crate::asset_session::Job::Vault(super::super::Job::Backup(request)),
        )?;
        drop(state);
        let _ = start.send(());
        Ok(())
    }
    pub(crate) fn installed_generated_backup_exported(&self) -> Option<bool> {
        let control = self.installed_backup_control().ok()?;
        self.reconcile();
        let state = self.inner.state.try_lock().ok()?;
        let trace = control.upload.backup.native.try_lock().ok()?;
        let reference = trace.source?;
        let original = trace.export.upgrade()?;
        let slot = state.slot.as_ref()?;
        if !good_slot(&state, slot, &original, 6, Operation::PrepareBackupExport) {
            return Some(false);
        }
        if slot.phase != AssetPhase::Idle || !joined(slot) || !slot_private_data_empty(slot) {
            return None;
        }
        let session = state.vault.as_ref()?;
        Some(
            slot.vault.backup_export_published
                && slot
                    .vault
                    .backup_export_context
                    .is_some_and(|(revision, held)| {
                        same_reference(held, reference)
                            && state
                                .context
                                .as_ref()
                                .is_some_and(|c| c.revision == revision)
                    })
                && retirement_ready(&original)
                && owns(slot, session)
                && session.writable()
                && session.identity == Some(reference.identity)
                && session.rows.len() == 1
                && session.inventory.as_slice() == [reference.record]
                && session.rows.iter().any(|row| {
                    !row.mutation_pending
                        && same_reference(row.reference(reference.identity), reference)
                })
                && state
                    .context
                    .as_ref()
                    .is_some_and(|context| self.context_matches(&state, context).unwrap_or(false))
                && state.assignments.is_empty()
                && session.bound.iter().all(Option::is_none)
                && trace
                    .pair
                    .as_ref()
                    .is_some_and(|pair| pair.matches_original(&original)),
        )
    }
    pub(crate) fn installed_generated_backup_lock_source(&self) -> Result<(), AssetError> {
        if self.installed_generated_backup_exported() != Some(true) {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        let control = self.installed_backup_claim(BackupAction::LockSource)?;
        {
            let mut trace = control
                .upload
                .backup
                .native
                .try_lock()
                .map_err(|_| AssetError::new(Reason::Busy))?;
            if trace.export_returned {
                return Err(AssetError::invalid());
            }
            trace.export_returned = true;
        }
        self.lock_session()?;
        Ok(())
    }
    pub(crate) fn installed_generated_backup_open(&self) -> Result<(), AssetError> {
        let snapshot = self
            .installed_macos_vault_snapshot()
            .ok_or_else(AssetError::invalid)?;
        if snapshot.unknown
            || snapshot.originals != 6
            || !snapshot.empty
            || !snapshot.originals_settled
        {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        let control = self.installed_backup_claim(BackupAction::Open)?;
        self.open_encrypted(&restored(&control).map_err(AssetError::new)?)?;
        Ok(())
    }
    pub(crate) fn installed_generated_backup_prepare(&self) -> Result<(), AssetError> {
        self.installed_backup_claim(BackupAction::Prepare)?;
        self.prepare_vault_initialize()?;
        Ok(())
    }
    pub(crate) fn installed_generated_backup_initialize(&self) -> Result<(), AssetError> {
        let token = {
            let state = self.lock();
            let slot = state.slot.as_ref().ok_or_else(AssetError::invalid)?;
            let preview = slot.preview.as_ref().ok_or_else(AssetError::invalid)?;
            if state.next_operation != 8
                || slot.owner.id != 8
                || slot.operation != Operation::PrepareInitialize
                || slot.phase != AssetPhase::Preview
                || !joined(slot)
                || preview.action != AssetAction::Initialize
            {
                return Err(AssetError::new(Reason::SourceChanged));
            }
            preview.token.0.clone()
        };
        self.installed_backup_claim(BackupAction::Initialize)?;
        self.commit_vault(&token)?;
        Ok(())
    }
    pub(crate) fn installed_generated_backup_context(
        &self,
        draft: &Value,
        project: &str,
    ) -> Result<(), AssetError> {
        let control = self.installed_backup_control()?;
        let roster = self
            .inner
            .bridge
            .native_roster()
            .map_err(|_| AssetError::new(Reason::ContextStale))?;
        let (generation, root) = self
            .inner
            .bridge
            .native_project(project)
            .map_err(|_| AssetError::invalid())?;
        if roster.generation != 2
            || generation != roster.generation
            || roster.roots.len() != 1
            || roster.roots[0].path != control.project()
            || root.path != control.project()
        {
            return Err(AssetError::new(Reason::ContextStale));
        }
        self.installed_backup_claim(BackupAction::Context)?;
        self.context(commands::Context {
            project_id: project,
            draft,
            platform: Platform::Android,
            stage: Stage::Candidate,
            purpose: Purpose::Signing,
            execution_mode: if control.case == VaultCase::UploadKey(Case::BackupCli) { commands::ExecutionMode::Local } else { commands::ExecutionMode::Github },
        })?;
        Ok(())
    }
    pub(crate) fn installed_generated_backup_import(&self) -> Result<(), AssetError> {
        if self.installed_backup_control()?.case != VaultCase::UploadKey(Case::BackupRoundTrip) { return Err(AssetError::invalid()); }
        let control = self.installed_backup_claim(BackupAction::Import)?;
        self.reconcile();
        let mut state = self.lock();
        self.expire(&mut state, Instant::now());
        self.durable_gate(&state, true)?;
        idle(&state)?;
        let context = state.context.clone().ok_or_else(AssetError::invalid)?;
        if state.next_operation != 9 || !self.context_matches(&state, &context)? {
            return Err(AssetError::invalid());
        }
        let identity = {
            let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
            if !session.writable()
                || !session.rows.is_empty()
                || !session.inventory.is_empty()
                || !state.assignments.is_empty()
                || session.bound.iter().any(Option::is_some)
            {
                return Err(AssetError::new(Reason::SourceChanged));
            }
            session.identity.ok_or_else(AssetError::invalid)?
        };
        let pair = {
            let mut trace = control
                .upload
                .backup
                .native
                .try_lock()
                .map_err(|_| AssetError::new(Reason::Busy))?;
            let source = trace.source.ok_or_else(AssetError::invalid)?;
            let original = trace.export.upgrade().ok_or_else(AssetError::invalid)?;
            if !trace.export_returned
                || trace.import.upgrade().is_some()
                || trace.target.is_some()
                || identity.vault == source.identity.vault
                || identity.generation == source.identity.generation
                || !original.resources_settled()
                || !original.ended.load(Ordering::SeqCst)
                || !trace
                    .pair
                    .as_ref()
                    .is_some_and(|pair| pair.matches_original(&original))
            {
                return Err(AssetError::new(Reason::SourceChanged));
            }
            let paths = folders(&control).map_err(AssetError::new)?;
            if !trace
                .pair
                .as_ref()
                .is_some_and(|pair| pair.matches_folders([&paths[0], &paths[1]]))
            {
                return Err(AssetError::new(Reason::SourceChanged));
            }
            // One-way move BEFORE further fallible work. Failure cannot reread
            // another pair, recreate a code, re-export or retry the NEW save.
            trace.pair.take().ok_or_else(AssetError::invalid)?
        };
        let sources =
            asset_source::BackupSources::new_component_restore(pair).map_err(AssetError::new)?;
        let mut slot = self.vault_owner(
            &mut state,
            Operation::ImportBackup,
            Some(context),
            None,
            None,
            true,
        )?;
        if slot.owner.id != 10 {
            return Err(AssetError::invalid());
        }
        slot.kind = Some(Kind::AndroidKeystore);
        {
            control
                .upload
                .backup
                .native
                .try_lock()
                .map_err(|_| AssetError::new(Reason::Busy))?
                .import = Arc::downgrade(&slot.owner);
        }
        let request = prepare_import(self, &mut state, &slot, sources)?;
        let start = self.install(
            &mut state,
            slot,
            crate::asset_session::Job::Vault(super::super::Job::Backup(request)),
        )?;
        drop(state);
        let _ = start.send(());
        Ok(())
    }
    pub(crate) fn installed_generated_backup_imported(&self) -> Option<bool> {
        let control = self.installed_backup_control().ok()?;
        self.reconcile();
        let state = self.inner.state.try_lock().ok()?;
        let trace = control.upload.backup.native.try_lock().ok()?;
        let source = trace.source?;
        let original = trace.import.upgrade()?;
        let slot = state.slot.as_ref()?;
        if !good_slot(&state, slot, &original, 10, Operation::ImportBackup) {
            return Some(false);
        }
        if slot.phase != AssetPhase::Idle || !joined(slot) || !slot_private_data_empty(slot) {
            return None;
        }
        let session = state.vault.as_ref()?;
        let identity = session.identity?;
        if session.rows.len() != 1 {
            return Some(false);
        }
        let row = &session.rows[0];
        let target = row.reference(identity);
        Some(
            slot.vault.backup_new_published
                && !row.mutation_pending
                && row.authenticated.descriptor.kind == Kind::AndroidKeystore
                && fresh_reference(source, target)
                && slot
                    .result_record
                    .as_ref()
                    .is_some_and(|key| target.matches(key))
                && session.inventory.as_slice() == [target.record]
                && session.writable()
                && state
                    .context
                    .as_ref()
                    .is_some_and(|c| self.context_matches(&state, c).unwrap_or(false))
                && state.assignments.is_empty()
                && session.bound.iter().all(Option::is_none)
                && trace.export_returned
                && trace.pair.is_none(),
        )
    }
    pub(crate) fn installed_generated_backup_load(&self) -> Result<(), AssetError> {
        if self.installed_generated_backup_imported() != Some(true) {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        let control = self.installed_backup_claim(BackupAction::Load)?;
        let mut state = self.lock();
        let context = state.context.clone().ok_or_else(AssetError::invalid)?;
        let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
        if session.rows.len() != 1 {
            return Err(AssetError::invalid());
        }
        let target = session.rows[0].reference(session.identity.ok_or_else(AssetError::invalid)?);
        {
            let mut trace = control
                .upload
                .backup
                .native
                .try_lock()
                .map_err(|_| AssetError::new(Reason::Busy))?;
            if trace.target.is_some() || trace.load.upgrade().is_some() {
                return Err(AssetError::invalid());
            }
            trace.target = Some(target);
        }
        let (id, start) = self.prepare_stored_vault(&mut state, target.key(), context)?;
        let slot = state.slot.as_ref().ok_or_else(AssetError::invalid)?;
        if id != 11 || slot.owner.id != id {
            return Err(AssetError::invalid());
        }
        {
            control
                .upload
                .backup
                .native
                .try_lock()
                .map_err(|_| AssetError::new(Reason::Busy))?
                .load = Arc::downgrade(&slot.owner);
        }
        drop(state);
        let _ = start.send(());
        Ok(())
    }
    pub(crate) fn installed_generated_backup_loaded(&self) -> Option<bool> {
        let control = self.installed_backup_control().ok()?;
        self.reconcile();
        let state = self.inner.state.try_lock().ok()?;
        let trace = control.upload.backup.native.try_lock().ok()?;
        let reference = trace.target?;
        let original = trace.load.upgrade()?;
        let slot = state.slot.as_ref()?;
        if !good_slot(&state, slot, &original, 11, Operation::Prepare) {
            return Some(false);
        }
        if slot.phase != AssetPhase::Preview || !joined(slot) {
            return None;
        }
        Some(
            slot.vault
                .reference
                .is_some_and(|held| same_reference(held, reference))
                && slot.vault.loaded.as_ref().is_some_and(|payload| {
                    payload.kind == Kind::AndroidKeystore
                        && payload.material.as_ref().is_some_and(|material| {
                            matches!(&material.origin,
                    MaterialOrigin::Stored(stored) if same_reference(stored.reference, reference))
                        })
                })
                && slot
                    .assessment
                    .as_ref()
                    .is_some_and(SafeAssessment::permits)
                && state
                    .context
                    .as_ref()
                    .is_some_and(|c| self.context_matches(&state, c).unwrap_or(false))
                && state.assignments.is_empty()
                && state
                    .vault
                    .as_ref()
                    .is_some_and(|s| s.bound.iter().all(Option::is_none)),
        )
    }
    pub(crate) fn installed_generated_backup_bind(&self) -> Result<(), AssetError> {
        if self.installed_generated_backup_loaded() != Some(true) {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        let control = self.installed_backup_control()?;
        let token = {
            let state = self.lock();
            let trace = control
                .upload
                .backup
                .native
                .try_lock()
                .map_err(|_| AssetError::new(Reason::Busy))?;
            let reference = trace.target.ok_or_else(AssetError::invalid)?;
            let slot = state.slot.as_ref().ok_or_else(AssetError::invalid)?;
            let preview = slot.preview.as_ref().ok_or_else(AssetError::invalid)?;
            if slot.owner.id != 11
                || !trace
                    .load
                    .upgrade()
                    .is_some_and(|old| Arc::ptr_eq(&old, &slot.owner))
                || preview.action != AssetAction::Bind
                || !preview
                    .record
                    .as_ref()
                    .is_some_and(|key| reference.matches(key))
            {
                return Err(AssetError::new(Reason::SourceChanged));
            }
            preview.token.0.clone()
        };
        self.installed_backup_claim(BackupAction::Bind)?;
        self.bind(&token)?;
        let state = self.lock();
        let slot = state.slot.as_ref().ok_or_else(AssetError::invalid)?;
        if state.next_operation != 12 || slot.owner.id != 12 || slot.operation != Operation::Bind {
            return Err(AssetError::invalid());
        }
        let mut trace = control
            .upload
            .backup
            .native
            .try_lock()
            .map_err(|_| AssetError::new(Reason::Busy))?;
        if trace.bound.upgrade().is_some() {
            return Err(AssetError::invalid());
        }
        trace.bound = Arc::downgrade(&slot.owner);
        Ok(())
    }
    pub(crate) fn installed_generated_backup_bound(&self) -> Option<bool> {
        let control = self.installed_backup_control().ok()?;
        self.reconcile();
        let state = self.inner.state.try_lock().ok()?;
        let trace = control.upload.backup.native.try_lock().ok()?;
        let reference = trace.target?;
        let original = trace.bound.upgrade()?;
        let slot = state.slot.as_ref()?;
        if !good_slot(&state, slot, &original, 12, Operation::Bind) {
            return Some(false);
        }
        if slot.phase != AssetPhase::Idle || !joined(slot) {
            return None;
        }
        Some(
            state
                .context
                .as_ref()
                .is_some_and(|c| self.context_matches(&state, c).unwrap_or(false))
                && remembered_bound_reference(&state, slot, Kind::AndroidKeystore)
                    .is_some_and(|held| same_reference(held, reference)),
        )
    }
    pub(crate) fn installed_generated_backup_lock_target(&self) -> Result<(), AssetError> {
        if self.installed_generated_backup_bound() != Some(true) {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        self.installed_backup_claim(BackupAction::LockTarget)?;
        self.lock_session()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restored_new_identity_cannot_reuse_source_revision_or_vault() {
        let id = |byte| format::Id::from_bytes([byte; 16]).unwrap();
        let old_revision = format::Revision::new(id(4), 1).unwrap();
        let new_revision = format::Revision::new(id(8), 1).unwrap();
        let source = StoredRef {
            identity: format::Identity::new(id(1), id(2)).unwrap(),
            record: id(3),
            revision: old_revision,
            original: store::ReadWitness::lifecycle_data(id(3), old_revision),
        };
        let target = StoredRef {
            identity: format::Identity::new(id(5), id(6)).unwrap(),
            record: id(7),
            revision: new_revision,
            original: store::ReadWitness::lifecycle_data(id(7), new_revision),
        };
        assert!(fresh_reference(source, target));
        for changed in [
            source,
            StoredRef {
                identity: source.identity,
                ..target
            },
            StoredRef {
                record: source.record,
                ..target
            },
            StoredRef {
                revision: source.revision,
                ..target
            },
            StoredRef {
                original: source.original,
                ..target
            },
        ] {
            assert!(!fresh_reference(source, changed));
        }
        // These are DATA comparisons, not NEW/AEAD/generation/Bind receipts.
    }
}
