//! Nonshipping, one-case comparison carried by the ACTUAL backup proof and
//! Selectors. No flag, registration, pathname or status can manufacture it.
use super::installed_backup_observation as old;
use super::*;
use crate::shell::installed_observation::vault::{
    upload_key::{backup::Action, cli::Phase, Case},
    Case as VaultCase, Control,
};
use crate::{service_upload_key_protocol as p, service_upload_key_requests::NativeLink};
use std::sync::OnceLock;

pub(in crate::asset_session) struct Admission {
    control: Weak<Control>,
    document: Weak<()>,
    context: Weak<NativeContext>,
    store: Weak<Mutex<store::StoreBook>>,
    identity: format::Identity,
    reference: Option<StoredRef>,
    phase: Phase,
    owner: OnceLock<Weak<OriginalWork>>,
    link: OnceLock<Weak<NativeLink>>,
}
impl Admission {
    pub(in crate::asset_session) fn retained_bytes(&self) -> usize {
        // Weak allocations remain charged after their contents disappear.
        std::mem::size_of::<Self>()
            + std::mem::size_of::<Control>()
            + std::mem::size_of::<NativeContext>()
            + std::mem::size_of::<Mutex<store::StoreBook>>()
            + std::mem::size_of::<OriginalWork>()
            + std::mem::size_of::<NativeLink>()
            + 7 * 2 * std::mem::size_of::<usize>()
    }
    pub(in crate::asset_session) fn current(
        &self,
        document: &DocumentBinding,
    ) -> Result<(), AssetError> {
        let control = self.control.upgrade().ok_or_else(AssetError::invalid)?;
        if control.case != VaultCase::UploadKey(Case::BackupCli)
            || !control.permits(&document.inner.session_identity)
            || self.document.as_ptr() != Arc::as_ptr(&document.inner.session_identity)
            || control.upload.backup.phase() != self.phase.serial()
            || !document.native_qualified()
            || !qualified(document)
        {
            return Err(AssetError::new(Reason::Unqualified));
        }
        Ok(())
    }
    pub(in crate::asset_session) fn attach(
        self: &Arc<Self>,
        document: &DocumentBinding,
        state: &DocumentState,
        slot: &Slot,
        link: Option<&Arc<NativeLink>>,
    ) -> Result<(), AssetError> {
        self.current(document)?;
        let link = link.ok_or_else(AssetError::invalid)?;
        let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
        let context = slot.context.as_ref().ok_or_else(AssetError::invalid)?;
        let control = self.control.upgrade().ok_or_else(AssetError::invalid)?;
        if self.owner.get().is_some()
            || self.link.get().is_some()
            || slot.owner.id != self.phase.original()
            || state.next_operation != slot.owner.id
            || slot.operation
                != if self.phase == Phase::Export {
                    Operation::PrepareBackupExport
                } else {
                    Operation::ImportBackup
                }
            || self.context.as_ptr() != Arc::as_ptr(context)
            || self.store.as_ptr() != Arc::as_ptr(&session.store)
            || session.identity != Some(self.identity)
            || slot
                .owner
                .agent_upload_key
                .get()
                .is_none_or(|held| !Arc::ptr_eq(held, link))
            || link.entry().scope().kind != self.phase.kind()
            || self
                .reference
                .is_some_and(|reference| slot.vault.reference.is_none_or(|r| !same(r, reference)))
        {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        let selectors = slot
            .owner
            .backup_selection
            .get()
            .ok_or_else(AssetError::invalid)?;
        self.owner
            .set(Arc::downgrade(&slot.owner))
            .map_err(|_| AssetError::invalid())?;
        self.link
            .set(Arc::downgrade(link))
            .map_err(|_| AssetError::invalid())?;
        selectors
            .observation
            .set(self.clone())
            .map_err(|_| AssetError::invalid())?;
        let mut trace = control
            .upload
            .backup
            .native
            .try_lock()
            .map_err(|_| AssetError::new(Reason::Busy))?;
        match self.phase {
            Phase::Export => {
                let (reference, generated) = control
                    .upload
                    .trace
                    .try_lock()
                    .map_err(|_| AssetError::new(Reason::Busy))?
                    .generated_reference_data()
                    .ok_or_else(AssetError::invalid)?;
                if self.reference.is_none_or(|r| !same(r, reference))
                    || trace.source.is_some()
                    || trace.export.upgrade().is_some()
                    || trace.pair.is_some()
                {
                    return Err(AssetError::invalid());
                }
                trace.source = Some(reference);
                trace.generator = Arc::downgrade(&generated);
                trace.export = Arc::downgrade(&slot.owner);
            }
            Phase::Restore => {
                if !trace.export_returned
                    || trace.import.upgrade().is_some()
                    || trace.target.is_some()
                    || trace.pair.is_none()
                    || !session.rows.is_empty()
                {
                    return Err(AssetError::invalid());
                }
                trace.import = Arc::downgrade(&slot.owner);
            }
            Phase::CancelRestore => {
                if !bound_current(state, &trace) || !control.upload.cli.bound_returned() {
                    return Err(AssetError::invalid());
                }
                control
                    .upload
                    .cli
                    .cancel_owner
                    .set(Arc::downgrade(&slot.owner))
                    .map_err(|_| AssetError::invalid())?;
            }
        }
        Ok(())
    }
    /// Cleanup uses the retained original, not a newly live grant. It remains
    /// addressable after STOP and the observation deadline, without rearming.
    pub(super) fn bound(&self, owner: &OriginalWork) -> bool {
        let Some(control) = self.control.upgrade() else {
            return false;
        };
        self.document.upgrade().is_some_and(|d| control.bound(&d))
            && control.case == VaultCase::UploadKey(Case::BackupCli)
            && control.upload.backup.phase() == self.phase.serial()
            && owner.id == self.phase.original()
            && self
                .owner
                .get()
                .is_some_and(|w| w.as_ptr() == owner as *const _)
            && self.link.get().is_some_and(|w| {
                owner
                    .agent_upload_key
                    .get()
                    .is_some_and(|l| w.as_ptr() == Arc::as_ptr(l))
            })
    }
    pub(super) fn action(&self, owner: &OriginalWork) -> bool {
        self.bound(owner)
            && !owner.interrupted()
            && self
                .control
                .upgrade()
                .is_some_and(|c| self.document.upgrade().is_some_and(|d| c.permits(&d)))
    }
    pub(super) fn phase(&self) -> Phase {
        self.phase
    }
    pub(super) fn picker_returned(
        &self,
        owner: &Arc<OriginalWork>,
        call: &Arc<GuiCall>,
        choice: super::backup_selection::Choice,
    ) -> Result<(), Reason> {
        if !self.action(owner) {
            return Err(Reason::SourceChanged);
        }
        self.control
            .upgrade()
            .ok_or(Reason::SourceChanged)?
            .backup_picker_returned(owner, call, choice)
            .map_err(|_| Reason::CleanupUnknown)
    }
    pub(super) fn no_io_returned(&self, owner: &OriginalWork) -> bool {
        if self.phase != Phase::CancelRestore || !self.bound(owner) {
            return false;
        }
        self.control.upgrade().is_some_and(|c| {
            c.upload
                .cli
                .no_io
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        })
    }
}
fn same(a: StoredRef, b: StoredRef) -> bool {
    a.identity == b.identity
        && a.record == b.record
        && a.revision == b.revision
        && a.original == b.original
}
// A cancelled second chooser never entered the I/O child. Require its real
// coordinator return and the unchanged New child fact; do not reuse B's
// positive helper, which correctly demands an actually Returned I/O child.
fn cancelled_joined(slot: &Slot) -> bool {
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
            .is_ok_and(|b| b.handle.is_none() && b.receipt == JoinReceipt::New)
        && slot.owner.source.try_lock().is_ok_and(|s| s.not_started())
}
fn bound_current(state: &DocumentState, trace: &old::Trace) -> bool {
    let (Some(reference), Some(session), Some(context)) =
        (trace.target, state.vault.as_ref(), state.context.as_ref())
    else {
        return false;
    };
    session.writable()
        && session.identity == Some(reference.identity)
        && session.rows.len() == 1
        && session
            .rows
            .iter()
            .any(|r| !r.mutation_pending && same(r.reference(reference.identity), reference))
        && state.assignments.iter().any(|a| {
            a.kind == Kind::AndroidKeystore
                && a.context_revision == context.revision
                && a.record_id == reference.key().id
                && a.record_revision == reference.revision.counter
                && assignment_available(state, a)
        })
        && session
            .bound
            .iter()
            .flatten()
            .any(|b| same(b.reference, reference) && b.current(state, session))
}
/// The ordinary SelectedPair has ALREADY provided these paths. The retained
/// output comparison can only veto; it cannot populate a selection.
pub(super) fn compare_import(
    owner: &Arc<OriginalWork>,
    sources: asset_source::BackupSources,
) -> Result<asset_source::BackupSources, Reason> {
    let Some(admission) = owner
        .backup_selection
        .get()
        .and_then(|s| s.observation.get())
    else {
        return Ok(sources);
    };
    if !admission.action(owner)
        || admission.phase != Phase::Restore
        || !owner.installed_backup_import_scope()
    {
        return Err(Reason::SourceChanged);
    }
    let control = admission.control.upgrade().ok_or(Reason::SourceChanged)?;
    let pair = {
        let mut trace = control
            .upload
            .backup
            .native
            .try_lock()
            .map_err(|_| Reason::CleanupUnknown)?;
        if !trace.export_returned || trace.import.as_ptr() != Arc::as_ptr(owner) {
            return Err(Reason::SourceChanged);
        }
        trace.pair.take().ok_or(Reason::SourceChanged)?
    };
    sources.compare_installed_picker_pair(owner, pair)
}
impl DocumentBinding {
    pub(crate) fn installed_backup_cli_allow(
        &self,
        project: &str,
        phase: Phase,
    ) -> Result<p::Access, crate::error::BridgeError> {
        let bad = crate::error::BridgeError::invalid;
        let action = match phase {
            Phase::Export => Action::Export,
            Phase::Restore => Action::Import,
            Phase::CancelRestore => Action::CancelImport,
        };
        if phase == Phase::Export && self.installed_upload_sample().is_none_or(|s| !s.positive()) {
            return Err(bad());
        }
        if phase == Phase::CancelRestore && self.installed_generated_backup_bound() != Some(true) {
            return Err(bad());
        }
        let control = self.installed_backup_claim(action).map_err(|_| bad())?;
        if control.case != VaultCase::UploadKey(Case::BackupCli) {
            return Err(bad());
        }
        let (admission, args) = {
            let state = self.lock();
            let session = state.vault.as_ref().ok_or_else(bad)?;
            let context = state.context.as_ref().ok_or_else(bad)?;
            if state.next_operation.checked_add(1) != Some(phase.original())
                || context.project_id != project
                || context.execution_mode != commands::ExecutionMode::Local
                || !session.writable()
                || !self.context_matches(&state, context).map_err(|_| bad())?
            {
                return Err(bad());
            }
            let identity = session.identity.ok_or_else(bad)?;
            let reference = if phase == Phase::Export {
                let (reference, owner) = control
                    .upload
                    .trace
                    .try_lock()
                    .map_err(|_| bad())?
                    .generated_reference_data()
                    .ok_or_else(bad)?;
                let slot = state.slot.as_ref().ok_or_else(bad)?;
                if !old::good_slot(&state, slot, &owner, 5, Operation::GenerateUploadKey)
                    || !old::joined(slot)
                    || session.rows.len() != 1
                    || session.identity != Some(reference.identity)
                    || !state.assignments.is_empty()
                {
                    return Err(bad());
                }
                Some(reference)
            } else {
                None
            };
            let selection = if let Some(r) = reference {
                serde_json::json!({"kind":"backup-encrypted","recordId":r.record.token(),"expectedRevision":r.revision.counter})
            } else {
                serde_json::json!({"kind":"restore-encrypted","declaration":p::RESTORE_DECLARATION})
            };
            let consent = crate::service_protocol::Id::random().map_err(|_| bad())?;
            let raw = crate::edit_protocol::bounded(
                &serde_json::json!({"projectId":project,"consentId":consent,
                "contextRevision":context.revision,"expectedStatusRevision":state.revision,"selection":selection,
                "consentVersion":phase.kind().consent()}),
                p::RAW_LIMIT - 96,
            )?;
            let args = super::super::agent_upload_key::decode_allow(&raw)?;
            (
                Arc::new(Admission {
                    control: Arc::downgrade(&control),
                    document: Arc::downgrade(&self.inner.session_identity),
                    context: Arc::downgrade(context),
                    store: Arc::downgrade(&session.store),
                    identity,
                    reference,
                    phase,
                    owner: OnceLock::new(),
                    link: OnceLock::new(),
                }),
                args,
            )
        };
        self.allow_agent_upload_key_qualified(
            "main",
            args,
            backup_desktop::Qualification::Installed(admission),
        )
    }
    pub(crate) fn installed_backup_cli_status(
        &self,
        phase: Phase,
    ) -> Result<Option<p::Status>, AssetError> {
        let control = self.installed_backup_control()?;
        if control.case != VaultCase::UploadKey(Case::BackupCli) {
            return Err(AssetError::invalid());
        }
        self.reconcile();
        let state = self.lock();
        let Some(slot) = state
            .slot
            .as_ref()
            .filter(|s| s.owner.id == phase.original())
        else {
            return Ok(None);
        };
        let a = slot
            .owner
            .backup_selection
            .get()
            .and_then(|s| s.observation.get())
            .ok_or_else(AssetError::invalid)?;
        if a.phase != phase || !a.bound(&slot.owner) {
            return Err(AssetError::invalid());
        }
        let link = slot
            .owner
            .agent_upload_key
            .get()
            .ok_or_else(AssetError::invalid)?;
        let status = link.entry().status().map_err(|_| AssetError::invalid())?;
        status.validate().map_err(|_| AssetError::invalid())?;
        Ok(Some(status))
    }
    pub(crate) fn installed_backup_cli_second_entered(&self) -> Result<bool, AssetError> {
        let state = self.lock();
        let Some(slot) = state.slot.as_ref().filter(|s| s.owner.id == 13) else {
            return Ok(false);
        };
        Ok(slot.owner.installed_backup_second_entered())
    }
    pub(crate) fn installed_backup_cli_lock_target(&self) -> Result<(), AssetError> {
        let control = self.installed_backup_control()?;
        let state = self.lock();
        let trace = control
            .upload
            .backup
            .native
            .try_lock()
            .map_err(|_| AssetError::invalid())?;
        let slot = state.slot.as_ref().ok_or_else(AssetError::invalid)?;
        if control.case != VaultCase::UploadKey(Case::BackupCli)
            || state.next_operation != 13
            || control.upload.backup.phase() != 10
            || !control.upload.cli.no_io.load(Ordering::SeqCst)
            || control
                .upload
                .cli
                .cancel_owner
                .get()
                .is_none_or(|w| w.as_ptr() != Arc::as_ptr(&slot.owner))
            || slot.operation != Operation::ImportBackup
            || slot.reason != Reason::UserCancelled
            || slot.phase != super::super::Phase::Idle
            || !cancelled_joined(slot)
            || !bound_current(&state, &trace)
            || slot.vault.backup_new_published
            || slot.result_record.is_some()
        {
            return Err(AssetError::invalid());
        }
        drop(trace);
        drop(state);
        self.lock_session()?;
        Ok(())
    }
}
