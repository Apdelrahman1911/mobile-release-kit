//! Two closed backup picker phases on ONE existing OriginalWork.
//!
//! The first GuiCall remains owner.gui; the second is reserved before the
//! coordinator's GO. Neither is reset. The native adapter keeps selection in
//! that exact call until its actual construct/poll/close/release dispatches have
//! joined, then invokes the fixed no-path-argument handoff below. These helpers
//! are not native receipts or permission to accept renderer/CLI paths.
use super::*;
use std::path::PathBuf;

// The native selector phase only allocates its original control cells and
// bounded pathname/native message cells, never material/parser buffers. Actual
// source/payload census is performed anew AFTER both original loops joined.
pub(in crate::asset_session) const PICKER_CONTROL_BYTES: usize =
    std::mem::size_of::<OriginalWork>() + std::mem::size_of::<Slot>()
    + std::mem::size_of::<SourceBook>() + 2 * std::mem::size_of::<GuiCall>()
    + 16 * asset_source::PATH_LIMIT + 64 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::asset_session) enum Purpose { Import, Export }
impl Purpose {
    fn operation(self) -> Operation {
        match self { Self::Import => Operation::ImportBackup, Self::Export => Operation::PrepareBackupExport }
    }
    fn choices(self) -> [Choice; 2] {
        match self {
            Self::Import => [Choice::EncryptedBackup, Choice::RecoveryCode],
            Self::Export => [Choice::EncryptedDestination, Choice::RecoveryDestination],
        }
    }
}

/// Native-only closed purpose/phase. It is not serialized and carries no path,
/// material, file descriptor, caller-selected filename or qualification bit.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Choice { EncryptedBackup, RecoveryCode, EncryptedDestination, RecoveryDestination }
impl Choice {
    fn purpose(self) -> Purpose {
        match self { Self::EncryptedBackup | Self::RecoveryCode => Purpose::Import,
            Self::EncryptedDestination | Self::RecoveryDestination => Purpose::Export }
    }
    fn index(self) -> usize {
        match self { Self::EncryptedBackup | Self::EncryptedDestination => 0,
            Self::RecoveryCode | Self::RecoveryDestination => 1 }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase { First, Second, Ready, IoStarted, Aborted }
struct Progress { phase: Phase, paths: [Option<PathBuf>; 2], io_started_at: Option<Instant> }

/// Closed handoff of the two actual native selections. The only constructor
/// runs below after the original loops joined; no path/receipt constructor or
/// getter is exposed. It is not permission to skip the containing native gate.
pub(in crate::asset_session) struct SelectedPair {
    owner: Weak<OriginalWork>, purpose: Purpose, paths: [PathBuf; 2],
}
#[cfg(all(feature = "desktop-shell", target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
impl SelectedPair {
    fn current(&self, owner: &Arc<OriginalWork>, purpose: Purpose) -> bool {
        self.purpose == purpose && self.owner.upgrade().is_some_and(|held| Arc::ptr_eq(&held, owner))
            && owner.backup_selection.get().is_some_and(|selectors| selectors.io_scope(owner, purpose))
    }
    pub(super) fn into_import(self, owner: &Arc<OriginalWork>) -> Result<asset_source::BackupSources, Reason> {
        if !self.current(owner, Purpose::Import) { return Err(Reason::SourceChanged); }
        asset_source::BackupSources::new(self.paths)
    }
    pub(super) fn into_export(self, owner: &Arc<OriginalWork>) -> Result<asset_source::BackupDestinations, Reason> {
        if !self.current(owner, Purpose::Export) { return Err(Reason::SourceChanged); }
        asset_source::BackupDestinations::new(owner, self.paths)
    }
}

/// Installed once in OriginalWork before GO. No replacement/clear/reset API.
pub(in crate::asset_session) struct Selectors {
    purpose: Purpose,
    second: Arc<GuiCall>,
    progress: Mutex<Progress>,
}
impl Selectors {
    fn new(owner: Weak<OriginalWork>, document: Weak<Inner>, purpose: Purpose) -> Self {
        Self { purpose, progress: Mutex::new(Progress { phase: Phase::First,
            paths: [None, None], io_started_at: None }),
            second: Arc::new(GuiCall { owner, document,
                facts: Mutex::new(GuiFacts { dispatched: false, constructing: false,
                    created: false, showing: false, response: false, accepted: false, declined: false,
                    accepted_at: None, destroyed: false, released: false, not_created: false,
                    close_queued: false, close_ack: false, release_queued: false,
                    selected: None, refusal: None }), selected_images: Mutex::new(None), wake: Notify::new(),
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation",
                    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
                    target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
                installed_native_response_witness: Mutex::new(None),
            }),
        }
    }
    fn current(progress: &Progress, index: usize) -> bool {
        progress.io_started_at.is_none() && match (progress.phase, index) {
            (Phase::First, 0) => progress.paths.iter().all(Option::is_none),
            (Phase::Second, 1) => progress.paths[0].is_some() && progress.paths[1].is_none(),
            _ => false,
        }
    }
    fn call<'a>(&'a self, owner: &'a OriginalWork, index: usize) -> &'a Arc<GuiCall> {
        if index == 0 { &owner.gui } else { &self.second }
    }
    /// Cleanup may still act on its exact active call after STOP. New Accept is
    /// separately refused by the original document response gate.
    fn matches(&self, owner: &OriginalWork, call: &GuiCall, choice: Choice) -> bool {
        choice.purpose() == self.purpose && std::ptr::eq(call, self.call(owner, choice.index()).as_ref())
            && self.progress.try_lock().is_ok_and(|progress| Self::current(&progress, choice.index()))
    }
    fn io_scope(&self, owner: &OriginalWork, purpose: Purpose) -> bool {
        self.purpose == purpose && !owner.interrupted()
            && self.progress.try_lock().is_ok_and(|progress| progress.phase == Phase::IoStarted
                && progress.io_started_at.is_some() && progress.paths.iter().all(Option::is_none))
            && owner.gui.facts.try_lock().is_ok_and(|facts| selected_original(&facts, true))
            && self.second.facts.try_lock().is_ok_and(|facts| selected_original(&facts, true))
    }
    pub(in crate::asset_session) fn extra_settled(&self) -> bool {
        self.second.settled() && self.second.selected_images.try_lock().is_ok_and(|paths| paths.is_none())
    }
    pub(in crate::asset_session) fn wake(&self) { self.second.changed(); }
    /// The primary call is already counted by the existing owner census.
    pub(in crate::asset_session) fn retained_bytes(&self) -> Option<usize> {
        let facts = self.second.facts.try_lock().ok()?;
        let images = self.second.selected_images.try_lock().ok()?;
        if images.is_some() { return None; }
        let progress = self.progress.try_lock().ok()?;
        let mut bytes = std::mem::size_of::<GuiCall>().checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(facts.selected.as_ref().map_or(0, PathBuf::capacity))?;
        for path in progress.paths.iter().flatten() { bytes = bytes.checked_add(path.capacity())?; }
        Some(bytes)
    }
    pub(in crate::asset_session) fn settled_census_bytes(&self) -> Option<usize> {
        // Quiescence and memory are separate facts; retain the ordinary GUI
        // census's unknown/refusal checks rather than counting a stopped call
        // as known merely because a result-shaped flag says closed.
        if !self.extra_settled() || !self.second.facts.try_lock().is_ok_and(|facts|
            !facts.constructing && !facts.showing && facts.released
                && (facts.not_created && !facts.created || facts.created && facts.destroyed && !facts.not_created)
                && facts.refusal != Some(Reason::CleanupUnknown)) { return None; }
        self.retained_bytes()
    }
    fn remember_selected(&self, owner: &OriginalWork, choice: Choice) -> Result<(), Reason> {
        let mut progress = self.progress.try_lock().map_err(|_| Reason::CleanupUnknown)?;
        if choice.purpose() != self.purpose || !Self::current(&progress, choice.index()) {
            return Err(Reason::SourceChanged);
        }
        let call = self.call(owner, choice.index());
        let mut facts = call.facts.try_lock().map_err(|_| Reason::CleanupUnknown)?;
        if !selected_original(&facts, false) { return Err(Reason::CleanupUnknown); }
        let path = facts.selected.as_ref().ok_or(Reason::SourceRefused)?;
        if path.capacity() > asset_source::PATH_LIMIT { return Err(Reason::Capacity); }
        asset_source::path_hint(path)?;
        // Move from the actual original's private path cell, not an argument or
        // result-shaped pathname. Custody exists before the next picker GO.
        progress.paths[choice.index()] = facts.selected.take();
        progress.phase = if choice.index() == 0 { Phase::Second } else { Phase::Ready };
        Ok(())
    }
    fn abort_after_return(&self, owner: &OriginalWork) -> Result<(), Reason> {
        let mut progress = self.progress.try_lock().map_err(|_| Reason::CleanupUnknown)?;
        if matches!(progress.phase, Phase::IoStarted) { return Err(Reason::CleanupUnknown); }
        {
            let facts = self.second.facts.try_lock().map_err(|_| Reason::CleanupUnknown)?;
            if !facts.dispatched && !facts.created && !facts.constructing {
                // The same coordinator never dispatched this original phase.
                // Do not apply this no-object path to a dispatched/unknown call.
                drop(facts); self.second.not_created(Reason::UserCancelled);
            } else if !(facts.not_created || facts.destroyed && facts.released) {
                return Err(Reason::CleanupUnknown);
            }
        }
        if !owner.gui.facts.try_lock().is_ok_and(|facts| facts.not_created || facts.destroyed && facts.released) {
            // Preserve the active phase so an uncertain original's own native
            // close can still match. The independent no-GO second is retained.
            return Err(Reason::CleanupUnknown);
        }
        progress.phase = Phase::Aborted;
        // Already selected pathname DATA remains on this original until its
        // existing off-lock retirement. It is not adopted for deletion.
        Ok(())
    }
}

fn selected_original(facts: &GuiFacts, consumed: bool) -> bool {
    facts.dispatched && facts.created && !facts.constructing && !facts.showing && !facts.not_created
        && facts.response && facts.accepted && !facts.declined && facts.accepted_at.is_some()
        && facts.refusal.is_none() && facts.destroyed && facts.close_queued && facts.close_ack
        && facts.release_queued && facts.released && facts.selected.is_none() == consumed
}

impl OriginalWork {
    /// Fixed sink/ACL failure hook. The timestamp is the first observation
    /// saved by the SAME native snapshot, before any independent close. No
    /// document lock, output publication or replacement cleanup clock exists.
    pub(crate) fn credential_backup_sink_failed_at(&self, reason: Reason, first: Instant) {
        if let Ok(mut work) = self.vault.lock() { work.fail(reason, first.min(Instant::now())); }
        self.signal_stop();
    }
    pub(crate) fn credential_backup_sink_cleanup_expired(&self) -> bool { cleanup_expired(self) }
    /// Presence describes the closed two-picker purpose on this original. It
    /// grants neither source IO nor native qualification and is never public.
    pub(crate) fn has_credential_backup_picker(&self) -> bool { self.backup_selection.get().is_some() }
    /// Private native construction only. Root adds one OnceLock field to the
    /// ordinary constructor; this fixed method fills it before returning/GO.
    pub(in crate::asset_session) fn new_credential_backup(id: u32, document: Weak<Inner>, purpose: Purpose)
        -> Result<Arc<Self>, Reason> {
        let owner = Self::new(id, true, document.clone());
        let selectors = Selectors::new(Arc::downgrade(&owner), document, purpose);
        owner.backup_selection.set(selectors).map_err(|_| Reason::CleanupUnknown)?;
        Ok(owner)
    }
    pub(crate) fn credential_backup_dialog(&self, choice: Choice) -> Result<Arc<GuiCall>, Reason> {
        let selectors = self.backup_selection.get().ok_or(Reason::InvalidRequest)?;
        let call = selectors.call(self, choice.index());
        if !selectors.matches(self, call, choice) { return Err(Reason::SourceChanged); }
        Ok(call.clone())
    }
    pub(crate) fn credential_backup_dialog_matches(&self, call: &GuiCall, choice: Choice) -> bool {
        self.backup_selection.get().is_some_and(|selectors| selectors.matches(self, call, choice))
    }
    /// Fixed native writer may act only during this same original's export IO
    /// phase. This predicate grants no current vault/reference or FD authority.
    pub(crate) fn credential_backup_destination_scope(&self) -> bool {
        self.backup_selection.get().is_some_and(|selectors| selectors.io_scope(self, Purpose::Export))
    }
    /// Root's actual GuiCall::begin_response passes THIS call, not owner.gui.
    /// Ordinary callers still admit only their one original primary call.
    pub(in crate::asset_session) fn original_gui_call(&self, call: &GuiCall) -> bool {
        match self.backup_selection.get() {
            None => std::ptr::eq(call, self.gui.as_ref()),
            Some(selectors) => selectors.purpose.choices().iter().any(|choice| selectors.matches(self, call, *choice)),
        }
    }
    pub(in crate::asset_session) fn credential_backup_unentered_after_return(&self) -> Result<(), Reason> {
        self.backup_selection.get().ok_or(Reason::InvalidRequest)?.abort_after_return(self)
    }
    /// Fixed existing coordinator no-GO exits only: primary no-object evidence
    /// was already recorded by that original exit. Independently settle only
    /// the genuinely undispatched second phase, never an entered native call.
    pub(in crate::asset_session) fn credential_backup_no_dispatch_end(&self, reason: Reason) {
        if self.backup_selection.get().is_none() { return; }
        self.credential_backup_failed(reason);
        if let Err(cleanup) = self.credential_backup_unentered_after_return() {
            self.credential_backup_failed(cleanup);
        }
    }
    /// Sole caller: the fixed native backup panel loop, after its exact final
    /// dispatch has joined. No pathname/result/receipt argument is accepted.
    #[cfg(all(feature = "desktop-shell", target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(crate) fn credential_backup_panel_selected(&self, choice: Choice) -> Result<(), Reason> {
        let inner = self.gui.document.upgrade().ok_or(Reason::DocumentLost)?;
        let document = DocumentBinding { inner };
        let mut state = document.lock();
        let owner = self.gui.owner().ok_or(Reason::DocumentLost)?;
        picker_gate(&document, &state, &owner, choice.purpose())?;
        let selectors = self.backup_selection.get().ok_or(Reason::InvalidRequest)?;
        selectors.remember_selected(self, choice)?;
        document.bump(&mut state);
        Ok(())
    }
}

#[cfg(all(feature = "desktop-shell", target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
fn picker_gate(document: &DocumentBinding, state: &DocumentState, owner: &Arc<OriginalWork>, purpose: Purpose) -> Result<(), Reason> {
    document.durable_gate(state, true).map_err(|error| error.reason)?;
    current_gate(document, state, owner)?;
    let slot = state.slot.as_ref().filter(|slot| slot.operation == purpose.operation()
        && slot.reason == Reason::None).ok_or(Reason::SourceChanged)?;
    let context = slot.context.as_ref().ok_or(Reason::ContextStale)?;
    if !document.context_matches(state, context).map_err(|error| error.reason)?
        || owner.backup_selection.get().is_none_or(|selectors| selectors.purpose != purpose) {
        return Err(Reason::ContextStale);
    }
    Ok(())
}

/// Called only under the genuine current document gate after BOTH fixed native
/// loops returned. This is the sole IO deadline start; native Accept callbacks
/// for these two phases must not call set_endpoint(now + WORK).
fn take_pair_and_start_io(owner: &OriginalWork, selectors: &Selectors, at: Instant) -> Result<[PathBuf; 2], Reason> {
    let mut progress = selectors.progress.try_lock().map_err(|_| Reason::CleanupUnknown)?;
    if owner.interrupted() || owner.endpoint().is_some() || progress.phase != Phase::Ready
        || progress.io_started_at.is_some() || progress.paths.iter().any(Option::is_none)
        || !owner.gui.facts.try_lock().is_ok_and(|facts| selected_original(&facts, true))
        || !selectors.second.facts.try_lock().is_ok_and(|facts| selected_original(&facts, true)) {
        return Err(Reason::SourceChanged);
    }
    let end = at.checked_add(WORK).ok_or(Reason::Capacity)?;
    progress.io_started_at = Some(at); progress.phase = Phase::IoStarted;
    owner.set_endpoint(Some(end));
    if owner.endpoint() != Some(end) || owner.interrupted() { return Err(Reason::CleanupUnknown); }
    Ok([progress.paths[0].take().ok_or(Reason::CleanupUnknown)?,
        progress.paths[1].take().ok_or(Reason::CleanupUnknown)?])
}

/// Actual fixed two-panel adapter, called by the SAME original vault Job.
/// It creates no coordinator/child, retries no phase and performs no private
/// read/generation until both selectors are settled and the one IO gate starts.
#[cfg(all(feature = "desktop-shell", target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(super) async fn run(document: &DocumentBinding, owner: &Arc<OriginalWork>, app: &tauri::AppHandle, purpose: Purpose)
    -> Result<SelectedPair, Reason> {
    for choice in purpose.choices() {
        let admitted = {
            let state = document.lock(); picker_gate(document, &state, owner, purpose)
        };
        if let Err(reason) = admitted { return Err(refuse_before_io(owner, reason)); }
        let result = crate::shell::run_owned_backup_dialog(app, owner, choice).await;
        match result {
            Ok(true) => {}, // The native helper retained this exact call's path.
            Ok(false) => {
                return Err(refuse_before_io(owner, Reason::UserCancelled));
            },
            Err(reason) => {
                return Err(refuse_before_io(owner, reason));
            },
        }
    }
    let result = (|| {
        let mut state = document.lock(); picker_gate(document, &state, owner, purpose)?;
        let selectors = owner.backup_selection.get().ok_or(Reason::InvalidRequest)?;
        let paths = take_pair_and_start_io(owner, selectors, Instant::now())?;
        state.slot.as_mut().ok_or(Reason::SourceChanged)?.phase = super::super::Phase::Capturing;
        document.bump(&mut state);
        Ok(paths)
    })();
    match result { Ok(paths) => Ok(SelectedPair { owner: Arc::downgrade(owner), purpose, paths }),
        Err(reason) => Err(refuse_before_io(owner, reason)) }
}

#[cfg(all(feature = "desktop-shell", target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
fn refuse_before_io(owner: &OriginalWork, reason: Reason) -> Reason {
    // No document/Work lock here. The real first failure precedes all remaining
    // independent no-GO/close observations and never receives a renewed grace.
    owner.credential_backup_failed(reason);
    let primary = match owner.gui.facts() {
        Some(facts) if !facts.dispatched && !facts.created && !facts.constructing => {
            drop(facts); owner.gui.not_created(reason); true
        },
        Some(facts) => facts.not_created || facts.destroyed && facts.released,
        None => false,
    };
    // A primary uncertainty does not prevent the independent never-dispatched
    // second original from recording its genuine no-GO outcome.
    let secondary = owner.credential_backup_unentered_after_return();
    if !primary || secondary.is_err() {
        owner.credential_backup_failed(Reason::CleanupUnknown);
        Reason::CleanupUnknown
    } else { reason }
}

/// SAME original vault coordinator: two native selectors, retained pair/quote,
/// then the existing fixed Child::Backup. There is no second install/GO, no
/// synthetic source snapshot and no path returned through public status.
#[cfg(all(feature = "desktop-shell", target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(super) async fn run_selected(document: &DocumentBinding, owner: &Arc<OriginalWork>, app: &tauri::AppHandle,
    purpose: Purpose) -> Result<super::super::Staged, Reason> {
    let pair = run(document, owner, app, purpose).await?;
    let prepared = {
        let mut state = document.lock();
        let gate = picker_gate(document, &state, owner, purpose);
        match gate {
            Err(reason) => Err(reason),
            Ok(()) => {
                // Synchronous, under the original document lock. Temporarily
                // split its exact Slot solely for the existing census/preparer
                // borrow; ALWAYS restore it, including every registry refusal.
                let slot = state.slot.take().ok_or(Reason::SourceChanged)?;
                let result = (|| match purpose {
                    Purpose::Import => {
                        let sources = pair.into_import(owner)?;
                        backup_native::prepare_import(document, &mut state, &slot, sources).map_err(|error| error.reason)
                    },
                    Purpose::Export => {
                        let reference = slot.vault.reference.ok_or(Reason::SourceChanged)?;
                        let destination = pair.into_export(owner)?;
                        backup_native::prepare_export_to(document, &mut state, &slot, reference, destination).map_err(|error| error.reason)
                    },
                })();
                state.slot = Some(slot);
                if result.is_ok() { document.bump(&mut state); }
                result
            },
        }
    };
    let request = match prepared {
        Ok(request) => request,
        Err(reason) => { owner.credential_backup_failed(reason); return Err(reason); },
    };
    backup_native::run(document, owner, request).await
}

/// Fixed native entry functions, not IPC routes. Root must wire only after
/// original macOS picker/store/private-sink qualification; no availability bit
/// is changed here. Both paths use the existing durable/document/native-context
/// gate, explicit action and single installed original coordinator.
#[cfg(all(feature = "desktop-shell", target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
impl DocumentBinding {
    pub(crate) fn choose_credential_backup_export(&self, app: tauri::AppHandle, context_revision: u32,
        reference: commands::RecordRef<'_>) -> Result<AssetStatus, AssetError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now());
        self.durable_gate(&state, true)?; idle(&state)?;
        let context = self.current_context(&mut state, context_revision)?;
        let key = own_record(reference)?;
        let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
        let row = session.row(&key).filter(|row| !row.mutation_pending).ok_or_else(AssetError::invalid)?;
        let reference = row.reference(session.identity.ok_or_else(AssetError::invalid)?);
        let kind = row.authenticated.descriptor.kind;
        session_kind_gate(&context, kind)?;
        let mut slot = self.backup_picker_slot(&mut state, context, Purpose::Export, Some(key))?;
        slot.kind = Some(kind); slot.vault.reference = Some(reference);
        let start = self.install(&mut state, slot, super::super::Job::Vault(Job::BackupPick { app, purpose: Purpose::Export }))?;
        let status = self.snapshot(&state); drop(state); let _ = start.send(()); Ok(status)
    }
    pub(crate) fn choose_credential_backup_import(&self, app: tauri::AppHandle, context_revision: u32)
        -> Result<AssetStatus, AssetError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now());
        self.durable_gate(&state, true)?; idle(&state)?;
        let context = self.current_context(&mut state, context_revision)?;
        if state.vault.as_ref().is_none_or(|session| session.rows.len() >= store::DESCRIPTOR_COUNT) {
            return Err(AssetError::new(Reason::Capacity));
        }
        let slot = self.backup_picker_slot(&mut state, context, Purpose::Import, None)?;
        let start = self.install(&mut state, slot, super::super::Job::Vault(Job::BackupPick { app, purpose: Purpose::Import }))?;
        let status = self.snapshot(&state); drop(state); let _ = start.send(()); Ok(status)
    }
    fn backup_picker_slot(&self, state: &mut DocumentState, context: Arc<NativeContext>, purpose: Purpose,
        target: Option<RecordKey>) -> Result<Slot, AssetError> {
        // Fixed prior-document census plus the bounded future picker controls,
        // NOT an unentered GUI pretending to be settled for a material loan.
        let live = lookup_memory::retained_document_bytes(&self.inner, state).map_err(|_| AssetError::new(Reason::Capacity))?;
        let extra = installation_memory::additional_document_bytes(self, state).map_err(AssetError::new)?;
        let total = live.checked_add(extra).and_then(|bytes| bytes.checked_add(PICKER_CONTROL_BYTES))
            .ok_or_else(|| AssetError::new(Reason::Capacity))?;
        if total > store::RESIDENT_BYTES || total > store::WORKING_BYTES { return Err(AssetError::new(Reason::Capacity)); }
        let roster = self.vault_roster(state)?;
        if roster.generation != context.registry_generation { return Err(AssetError::new(Reason::ContextStale)); }
        let id = self.next_operation(state)?;
        // Reserve both genuine GuiCalls before the ordinary install barrier.
        let owner = OriginalWork::new_credential_backup(id, Arc::downgrade(&self.inner), purpose).map_err(AssetError::new)?;
        let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
        if session.registry_generation != roster.generation { return Err(AssetError::new(Reason::ContextStale)); }
        attach(&owner, session, true, false)?;
        let mut slot = Slot::new(owner, purpose.operation(), Some(context), target, None);
        slot.vault.generation = Some(roster.generation); slot.vault.lease = Some(session.store.clone());
        Ok(slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> Arc<OriginalWork> {
        OriginalWork::new_credential_backup(1, Weak::new(), Purpose::Import).unwrap()
    }
    fn selected_data(call: &GuiCall, path: &str) {
        // Predicate DATA only. No native panel, dispatch, worker or account is
        // created, and neither original coordinator/child receipt is changed.
        let mut facts = call.facts().unwrap();
        facts.dispatched = true; facts.created = true; facts.response = true;
        facts.accepted = true; facts.accepted_at = Some(Instant::now());
        facts.destroyed = true; facts.close_queued = true; facts.close_ack = true;
        facts.release_queued = true; facts.released = true;
        facts.selected = Some(path.into());
    }

    #[test]
    fn both_distinct_original_calls_exist_before_go_and_id_is_not_binding() {
        let owner = owner();
        let selectors = owner.backup_selection.get().unwrap();
        assert!(!Arc::ptr_eq(&owner.gui, &selectors.second));
        assert!(Arc::ptr_eq(&selectors.second.owner().unwrap(), &owner));
        for call in [&owner.gui, &selectors.second] {
            let facts = call.facts().unwrap();
            assert!(!facts.dispatched && !facts.constructing && !facts.created && !facts.not_created);
        }
        assert!(owner.credential_backup_dialog(Choice::EncryptedBackup).is_ok());
        assert!(owner.credential_backup_dialog(Choice::RecoveryCode).is_err());
        assert!(owner.credential_backup_dialog(Choice::EncryptedDestination).is_err());
        let other = OriginalWork::new_credential_backup(1, Weak::new(), Purpose::Import).unwrap();
        assert!(!owner.credential_backup_dialog_matches(&other.gui, Choice::EncryptedBackup));
        assert!(owner.coordinator.lock().unwrap().receipt == JoinReceipt::New);
        assert!(owner.child.try_lock().unwrap().receipt == JoinReceipt::New);
    }

    #[test]
    fn first_path_stays_with_original_and_only_both_closed_start_one_io_clock() {
        let owner = owner();
        let selectors = owner.backup_selection.get().unwrap();
        owner.set_endpoint(None); // DATA standing in for actual presented().
        selected_data(&owner.gui, "/private/synthetic-backup.mrkbackup");
        selectors.remember_selected(&owner, Choice::EncryptedBackup).unwrap();
        assert!(owner.endpoint().is_none());
        assert!(selectors.progress.lock().unwrap().paths[0].is_some());
        assert!(owner.gui.facts().unwrap().selected.is_none());
        assert!(owner.credential_backup_dialog(Choice::RecoveryCode).is_ok());
        assert!(take_pair_and_start_io(&owner, selectors, Instant::now()).is_err());
        assert!(owner.endpoint().is_none());
        selected_data(&selectors.second, "/private/synthetic-recovery.mrkcode");
        selectors.remember_selected(&owner, Choice::RecoveryCode).unwrap();
        selectors.second.facts().unwrap().released = false;
        assert!(take_pair_and_start_io(&owner, selectors, Instant::now()).is_err());
        assert!(owner.endpoint().is_none());
        selectors.second.facts().unwrap().released = true;
        let at = Instant::now();
        let paths = take_pair_and_start_io(&owner, selectors, at).unwrap();
        assert!(paths[0] != paths[1]);
        let first_end = owner.endpoint();
        assert_eq!(first_end, at.checked_add(WORK));
        assert!(take_pair_and_start_io(&owner, selectors, at + Duration::from_secs(1)).is_err());
        assert_eq!(owner.endpoint(), first_end);
        assert!(!owner.original_gui_call(&owner.gui));
        assert!(owner.coordinator.lock().unwrap().receipt == JoinReceipt::New);
    }

    #[test]
    fn a_dispatched_unknown_second_cannot_become_not_created_or_reset() {
        let owner = owner();
        let selectors = owner.backup_selection.get().unwrap();
        selected_data(&owner.gui, "/private/synthetic-backup.mrkbackup");
        selectors.remember_selected(&owner, Choice::EncryptedBackup).unwrap();
        selectors.second.facts().unwrap().dispatched = true;
        assert!(owner.credential_backup_unentered_after_return().is_err());
        assert!(!selectors.second.facts().unwrap().not_created);
        assert!(selectors.progress.lock().unwrap().phase == Phase::Second);
        assert!(selectors.progress.lock().unwrap().paths[0].is_some());
        assert!(owner.credential_backup_dialog(Choice::EncryptedBackup).is_err());
    }

    #[test]
    fn same_original_no_go_exit_settles_only_the_genuinely_unentered_second() {
        // The no-object transitions below are predicate DATA, not native
        // receipts. No dispatcher, original worker or account operation runs.
        let owner = owner();
        let deadline = owner.endpoint();
        owner.gui.not_created(Reason::UserCancelled);
        owner.credential_backup_no_dispatch_end(Reason::UserCancelled);
        let selectors = owner.backup_selection.get().unwrap();
        assert!(selectors.second.facts().unwrap().not_created);
        assert!(selectors.extra_settled());
        assert!(selectors.progress.lock().unwrap().phase == Phase::Aborted);
        assert!(owner.stopped());
        assert_eq!(owner.endpoint(), deadline);
        assert!(owner.coordinator.lock().unwrap().receipt == JoinReceipt::New);
        assert!(!owner.control_resources_settled());
    }

    #[test]
    fn secondary_call_and_retained_selections_are_charged_without_early_census_credit() {
        let owner = owner(); let selectors = owner.backup_selection.get().unwrap();
        let base = selectors.retained_bytes().unwrap();
        assert!(base >= std::mem::size_of::<GuiCall>());
        assert!(selectors.settled_census_bytes().is_none());
        selected_data(&owner.gui, "/private/synthetic-backup.mrkbackup");
        let bytes = owner.gui.facts().unwrap().selected.as_ref().unwrap().capacity();
        selectors.remember_selected(&owner, Choice::EncryptedBackup).unwrap();
        assert_eq!(selectors.retained_bytes(), Some(base + bytes));
        assert!(selectors.settled_census_bytes().is_none());
        selected_data(&selectors.second, "/private/synthetic-recovery.mrkcode");
        let code_path = selectors.second.facts().unwrap().selected.as_ref().unwrap().capacity();
        selectors.remember_selected(&owner, Choice::RecoveryCode).unwrap();
        assert_eq!(selectors.settled_census_bytes(), Some(base + bytes + code_path));
        selectors.second.facts().unwrap().refusal = Some(Reason::CleanupUnknown);
        assert!(selectors.extra_settled()); // Native quiescence remains distinct.
        assert!(selectors.settled_census_bytes().is_none());
        assert_eq!(selectors.retained_bytes(), Some(base + bytes + code_path));
    }
}
