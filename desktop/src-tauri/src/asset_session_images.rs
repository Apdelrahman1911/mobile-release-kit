//! Public listing-image selection, borrowing the existing original document
//! slot, source book, native dialog, coordinator, STOP and retirement machinery.
//! Only safe metadata is projected. A batch is never a credential or a retry.
use super::*;
use crate::{edit_protocol::{Capability as EditCapability, EditAvailability, EditDomain},
    metadata_images_commands::{SelectionCancel, SelectionStart}, metadata_images_edit_protocol::{self as wire,
        Selection, SelectionPhase as ImagePhase, SelectionReason as ImageReason, SelectionSettlement as ImageSettlement}};
use std::path::PathBuf;

// Path/name/source-book/GUI and both bounded metadata projections, plus ten
// size+1 EOF bytes, fit inside this conservative in-session control reservation.
// Native dialog/provider-internal selection storage is not a process-RSS claim.
const CONTROL_RESERVE: usize = 1024 * 1024;
// Separate from image controls: two bounded 64-record GitHub journals and
// their current reviews/run, connection material, evidence and settled quit
// controls may coexist with an image selection. Each typed journal has a
// 256KiB wire ceiling; 1MiB EACH covers its bounded Vec/String capacities and
// the private review copy. The remaining 1MiB covers connection (64KiB wire),
// evidence (64KiB wire, fixed small row rosters), quit and document cells.
// This is charged INSIDE the same session quota, not extra raw-byte credit or
// a claim about GUI/provider, allocator, renderer or whole-process RSS.
const DOCUMENT_CONTROL_RESERVE: usize = 3 * 1024 * 1024;
const SELECTION_STATUS_LIMIT: usize = 32 * 1024;

#[derive(Clone, Copy)]
struct Failure { reason: Reason, at: Instant, unknown: bool }
#[derive(Default)]
pub(super) struct FailureLatch { first: Option<Failure>, pending: bool }
impl FailureLatch {
    fn record(&mut self, reason: Reason, at: Instant) {
        match &mut self.first {
            None => { self.first = Some(Failure { reason, at, unknown: reason == Reason::CleanupUnknown }); self.pending = true; },
            Some(first) => {
                if at < first.at { first.at = at; first.reason = reason; self.pending = true; }
                if reason == Reason::CleanupUnknown && !first.unknown { first.unknown = true; self.pending = true; }
            },
        }
    }
    fn take_pending(&mut self) -> Option<Failure> {
        if !std::mem::take(&mut self.pending) { return None; } self.first
    }
}

// The source callback may run with SourceBook held. It never takes/re-enters
// the document/source/child/GUI mutexes, schedules work or performs cleanup.
// Its timestamp is sampled BEFORE this small latch's lock. The existing
// coordinator wake/expiry projects it through the original Slot::stop clock.
pub(super) fn source_failure(owner: &Arc<OriginalWork>, reason: Reason) {
    source_failure_at(owner, reason, Instant::now());
}
fn source_failure_at(owner: &Arc<OriginalWork>, reason: Reason, at: Instant) {
    {
        let (mut latch, poisoned) = match owner.image_failure.lock() {
            Ok(latch) => (latch, false), Err(error) => (error.into_inner(), true),
        };
        latch.record(reason, at);
        if poisoned { latch.record(Reason::CleanupUnknown, at); }
    }
    owner.stop();
}
pub(super) fn observe_failure(state: &mut DocumentState) -> bool {
    let Some(slot) = state.slot.as_mut().filter(|slot| slot.operation.images() || slot.operation.required_notes()) else { return false; };
    let failure = {
        let (mut latch, poisoned) = match slot.owner.image_failure.lock() {
            Ok(latch) => (latch, false), Err(error) => (error.into_inner(), true),
        };
        if poisoned { latch.record(Reason::CleanupUnknown, Instant::now()); }
        latch.take_pending()
    };
    let Some(failure) = failure else { return false; };
    if slot.source == SourceState::Pending { slot.source = SourceState::Refused; }
    slot.stop(failure.reason, failure.at);
    state.unknown |= failure.unknown;
    true
}

pub(super) struct Binding {
    operation_id: String, project_id: String, context: wire::Context,
    pub(super) root: asset_source::RegisteredRoot, generation: u32,
    selection_token: Token, pub(super) byte_limit: usize,
}
impl Binding {
    pub(super) fn source_budget(&self) -> asset_source::PublicImageBudget {
        // Both halves were charged by persistent_bytes BEFORE this reservation:
        // one half for source/batch material, the other for GUI/status/owner cells.
        // No extra raw bytes and no independent budget owner are created here.
        asset_source::PublicImageBudget { payload_bytes: self.byte_limit,
            retained_bytes: self.byte_limit.checked_add(CONTROL_RESERVE / 2).unwrap_or(0) }
    }
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(self.operation_id.capacity())?.checked_add(self.project_id.capacity())?
            .checked_add(self.context.locale.capacity())?.checked_add(self.context.asset_type.capacity())?
            .checked_add(self.root.path.capacity())?.checked_add(self.selection_token.0.capacity())
    }
    fn matches(&self, generation: u32, root: &asset_source::RegisteredRoot) -> bool { self.generation == generation && self.root == *root }
    fn initial(&self) -> Selection {
        Selection { operation_id: self.operation_id.clone(), project_id: self.project_id.clone(), platform: self.context.platform,
            locale: self.context.locale.clone(),
            asset_type: self.context.asset_type.clone(), phase: ImagePhase::Selecting, reason: ImageReason::None,
            settlement: ImageSettlement::Pending, selection_token: None, items: Vec::new() }
    }
}

pub(super) struct Registry {
    active: Option<Selection>, last: Option<Selection>, observed_capability: Option<EditAvailability>,
}
impl Registry {
    pub(super) fn new() -> Self { Self { active: None, last: None, observed_capability: None } }
    fn row(&self, id: &str) -> Option<&Selection> {
        self.active.as_ref().filter(|row| row.operation_id == id)
            .or_else(|| self.last.as_ref().filter(|row| row.operation_id == id))
    }
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        let mut total = std::mem::size_of::<Self>();
        for row in self.active.iter().chain(&self.last) {
            total = total.checked_add(row.operation_id.capacity())?.checked_add(row.project_id.capacity())?
                .checked_add(row.locale.capacity())?.checked_add(row.asset_type.capacity())?
                .checked_add(row.selection_token.as_ref().map_or(0, String::capacity))?
                .checked_add(row.items.capacity().checked_mul(std::mem::size_of::<wire::SelectedItem>())?)?;
            for item in &row.items {
                total = total.checked_add(item.item_id.capacity())?.checked_add(item.display_name.capacity())?.checked_add(item.sha256.capacity())?;
            }
        }
        Some(total)
    }
}

pub(super) fn pending(state: &DocumentState) -> bool {
    state.slot.as_ref().is_some_and(|slot| slot.operation.images() && (slot.phase != Phase::Idle || !slot.owner.resources_settled()))
}
fn published_selection(slot: &Slot, binding: &Arc<Binding>) -> bool {
    slot.operation.images() && slot.images.as_ref().is_some_and(|original| Arc::ptr_eq(original, binding))
        && slot.phase == Phase::Selected && slot.reason == Reason::None && slot.cleanup_end.is_none()
        && slot.settlement == Settlement::Known && slot.image_batch.is_some()
        && slot.source == SourceState::Captured && !slot.owner.stopped()
        && slot.selection.as_ref() == Some(&binding.selection_token)
}
pub(super) fn own_settled_selection(slot: &Slot, binding: &Arc<Binding>) -> bool {
    published_selection(slot, binding) && slot.owner.project_path_settled(true)
}
fn matched_selection(state: &DocumentState, project_id: &str, selection_token: &str) -> Option<(Arc<Binding>, Arc<OriginalWork>)> {
    let slot = state.slot.as_ref().filter(|slot| slot.operation.images()
        && slot.selection.as_ref().is_some_and(|token| token.0 == selection_token))?;
    let binding = slot.images.as_ref().filter(|binding| binding.project_id == project_id
        && binding.selection_token.0 == selection_token)?;
    Some((binding.clone(), slot.owner.clone()))
}
fn consumed_selection(slot: &Slot) -> bool {
    // Set only by the successful one-way enqueue below after strict original
    // finality. Transient try-lock contention cannot turn it into Cancel or
    // grant cancellation authority over the separate active edit owner.
    slot.operation.images() && slot.phase == Phase::Idle && slot.reason == Reason::None && slot.cleanup_end.is_none()
        && slot.settlement == Settlement::Known && slot.image_batch.is_none() && slot.selection.is_none() && slot.source == SourceState::Captured
}
fn reason(reason: Reason, captured: bool) -> ImageReason {
    match reason {
        Reason::None => ImageReason::None,
        Reason::UserCancelled => ImageReason::Cancelled,
        Reason::UnsupportedPlatform => ImageReason::UnsupportedPlatform,
        Reason::Unqualified | Reason::Closed => ImageReason::RuntimeUnqualified,
        Reason::InvalidRequest | Reason::UnsupportedFormat | Reason::ProjectOverlap => ImageReason::InvalidSelection,
        Reason::SourceChanged | Reason::ContextStale | Reason::ExclusionUnconfirmed => ImageReason::SourceChanged,
        Reason::Capacity | Reason::MaterialLimit | Reason::ParserLimit => ImageReason::SelectionLimit,
        Reason::Busy => ImageReason::Busy,
        Reason::DocumentLost => ImageReason::WindowLost,
        Reason::Shutdown => ImageReason::Shutdown,
        Reason::Deadline | Reason::ReviewExpired => ImageReason::ActiveTimeout,
        Reason::CleanupUnknown => ImageReason::CleanupUnknown,
        Reason::SourceRefused if !captured => ImageReason::DialogFailed,
        _ => ImageReason::SourceUnavailable,
    }
}
fn refused(reason: ImageReason) -> BridgeError {
    match reason {
        ImageReason::Busy => BridgeError::new("metadata_images_busy", "Finish or cancel the original image selection or operation first."),
        ImageReason::SelectionLimit => BridgeError::new("metadata_images_selection_limit", "Select a smaller image batch, or close unused signing inputs to free session capacity."),
        ImageReason::UnsupportedPlatform | ImageReason::RuntimeUnqualified => BridgeError::unavailable("Public image selection is not qualified in this application profile."),
        ImageReason::SourceChanged => BridgeError::new("metadata_images_source_changed", "The original selection or project changed. Select the files again after the original operation settles."),
        ImageReason::WindowLost | ImageReason::CallerLost => BridgeError::new("metadata_images_owner_lost", "The original window no longer owns this image selection."),
        ImageReason::Shutdown => BridgeError::shutdown(),
        ImageReason::CleanupUnknown => BridgeError::cleanup_unknown(),
        _ => BridgeError::invalid(),
    }
}
fn selection_not_admitted(mut error: BridgeError) -> BridgeError {
    // Method-scoped negative admission fact, never a cleanup/idle receipt for
    // some OTHER original owner. No caller may apply this after installation.
    error.code = "metadata_images_selection_not_admitted".into(); error.retryable = false; error
}
fn import_not_matched() -> BridgeError {
    BridgeError::new("metadata_images_import_not_matched", "This request did not match the original project and image selection. No selection token was consumed and no image edit was started.")
}
fn edit_error_reason(error: &BridgeError) -> Reason {
    match error.code.as_str() {
        "cleanup_unknown" => Reason::CleanupUnknown,
        "shutting_down" => Reason::Shutdown,
        "invalid_edit_owner" => Reason::DocumentLost,
        "busy" | "quit_pending" | "metadata_images_busy" => Reason::Busy,
        "metadata_images_source_changed" => Reason::SourceChanged,
        "metadata_images_selection_limit" => Reason::MaterialLimit,
        "unavailable" | "runtime_unavailable" => Reason::Unqualified,
        _ => Reason::SourceRefused,
    }
}
fn retire_matching_import_failure(state: &mut DocumentState, binding: &Arc<Binding>, owner: &Arc<OriginalWork>,
    edit_claimed: bool, mut error: BridgeError, at: Instant) -> BridgeError {
    let Some(slot) = state.slot.as_mut().filter(|slot| slot.operation.images() && Arc::ptr_eq(&slot.owner, owner)
        && slot.images.as_ref().is_some_and(|original| Arc::ptr_eq(original, binding))) else { return error; };
    // This is the SAME positively matched original, never a lookup by token
    // after expiry/admission. Its STOP irrevocably retires the original token.
    slot.stop(edit_error_reason(&error), at);
    if !edit_claimed && slot.selection.is_none() && owner.stopped() {
        // A narrow fact about THIS Open invocation only: no EditOwner was
        // claimed. Selection cleanup, document/global idle and any other
        // owner's finality remain unknown until their original observations.
        error.code = "metadata_images_import_not_admitted".into(); error.retryable = false;
    }
    error
}

pub(super) fn refresh(state: &mut DocumentState) {
    let Some(slot) = &state.slot else { return; };
    let Some(binding) = slot.images.as_ref().filter(|_| slot.operation.images()) else { return; };
    let Some(mut row) = state.images.row(&binding.operation_id).cloned() else { return; };
    row.selection_token = None;
    if state.unknown || state.exhausted || slot.phase == Phase::Unknown || matches!(slot.settlement, Settlement::Unknown | Settlement::LateKnown) {
        row.phase = ImagePhase::Unknown; row.reason = ImageReason::CleanupUnknown;
        row.settlement = if slot.settlement == Settlement::LateKnown && slot.owner.resources_settled() {
            ImageSettlement::LateKnown
        } else { ImageSettlement::Unknown };
    } else if slot.cleanup_end.is_some() || slot.reason != Reason::None {
        row.reason = reason(slot.reason, slot.source != SourceState::NotRun);
        if slot.phase == Phase::Idle && slot.owner.resources_settled() && !state.retiring {
            row.phase = if slot.reason == Reason::UserCancelled { ImagePhase::Cancelled } else { ImagePhase::Failed };
            row.settlement = ImageSettlement::Known;
        } else {
            row.phase = if slot.source == SourceState::NotRun { ImagePhase::Selecting } else { ImagePhase::Capturing };
            row.settlement = ImageSettlement::Pending;
        }
    } else if published_selection(slot, binding) && !row.items.is_empty() {
        // Publication already latched strict positive original finality.
        // A concurrent read-only custody census cannot regress that receipt
        // merely by temporarily holding a try-lock. Open still rechecks the
        // exact originals and consumes/retire-fails on admission refusal.
        row.phase = ImagePhase::Selected; row.reason = ImageReason::None; row.settlement = ImageSettlement::Known;
        row.selection_token = slot.selection.as_ref().map(|token| token.0.clone());
    } else if consumed_selection(slot) && !row.items.is_empty() {
        // Successful one-way transfer. A consumed selection is not cancelled,
        // and cancelling it must not route into the distinct active EditOwner.
        row.phase = ImagePhase::Selected; row.reason = ImageReason::None; row.settlement = ImageSettlement::Known;
    } else {
        row.phase = if slot.source == SourceState::NotRun { ImagePhase::Selecting } else { ImagePhase::Capturing };
        row.reason = ImageReason::None; row.settlement = ImageSettlement::Pending;
    }
    let terminal = matches!(row.phase, ImagePhase::Selected | ImagePhase::Cancelled | ImagePhase::Failed)
        && row.settlement == ImageSettlement::Known || row.phase == ImagePhase::Unknown && row.settlement == ImageSettlement::LateKnown;
    if terminal {
        if state.images.active.as_ref().is_some_and(|old| old.operation_id == row.operation_id) { state.images.active = None; }
        state.images.last = Some(row);
    } else {
        if state.images.last.as_ref().is_some_and(|old| old.operation_id == row.operation_id) { state.images.last = None; }
        state.images.active = Some(row);
    }
}

// Count persistent session holdings conservatively (shared payloads may be
// counted twice, never omitted). The old idle slot is retired by install/run_job
// before any image bytes are allocated. Its controls cannot be recycled early.
pub(super) fn persistent_bytes(state: &DocumentState) -> Result<usize, Reason> {
    let mut total = CONTROL_RESERVE + DOCUMENT_CONTROL_RESERVE;
    let mut add = |bytes: usize| -> Result<(), Reason> {
        total = total.checked_add(bytes).ok_or(Reason::Capacity)?; Ok(())
    };
    add(state.required_notes.retained_bytes().ok_or(Reason::Capacity)?)?;
    add(state.records.capacity().checked_mul(std::mem::size_of::<Record>()).ok_or(Reason::Capacity)?)?;
    for record in &state.records {
        add(RECORD_METADATA_BYTES)?; add(record.key.id.0.capacity())?;
        if let Some(material) = &record.payload.material { add(material.retained_bytes().ok_or(Reason::Capacity)?)?; }
        if let Some(fields) = &record.payload.fields { add(fields.retained_bytes().ok_or(Reason::Capacity)?)?; }
    }
    add(state.assignments.capacity().checked_mul(std::mem::size_of::<Assignment>()).ok_or(Reason::Capacity)?)?;
    for assignment in &state.assignments { add(assignment.record_id.0.capacity())?; }
    if let Some(context) = &state.context {
        add(std::mem::size_of::<NativeContext>() + 2 * std::mem::size_of::<usize>())?;
        add(context.draft.capacity())?; add(context.project_id.capacity())?; add(context.project.path.capacity())?;
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(session) = &state.vault {
        add(session.data_bytes().ok_or(Reason::Capacity)?)?;
        let store = session.store().try_lock().map_err(|_| Reason::Busy)?;
        if !(store.not_started() || store.operation_quiescent() || store.settled()) { return Err(Reason::Busy); }
        add(store.retained_bytes().ok_or(Reason::Capacity)?)?;
        if let Some(key) = session.key() { add(key.retained_bytes())?; }
    }
    Ok(total)
}
fn raw_allowance(state: &DocumentState) -> Result<usize, Reason> {
    SESSION_BYTES.checked_sub(persistent_bytes(state)?).map(|remaining| remaining.min(wire::BATCH_LIMIT))
        .filter(|limit| *limit > 0).ok_or(Reason::Capacity)
}
fn selected_items(batch: &asset_source::CapturedPublicImageBatch) -> Result<Vec<wire::SelectedItem>, Reason> {
    let mut items = Vec::new(); items.try_reserve_exact(batch.images.len()).map_err(|_| Reason::Capacity)?;
    for image in &batch.images {
        let item = wire::SelectedItem { item_id: image.item_id.clone(), display_name: image.display_name.clone(),
            byte_length: u32::try_from(image.bytes.len()).map_err(|_| Reason::MaterialLimit)?, sha256: image.sha256.clone() };
        if !item.valid() { return Err(Reason::SourceRefused); }
        items.push(item);
    }
    Ok(items)
}

pub(super) fn publish(document: &DocumentBinding, state: &mut DocumentState, slot: &mut Slot,
    batch: asset_source::CapturedPublicImageBatch, binding: Arc<Binding>) {
    let admitted = (|| -> Result<Vec<wire::SelectedItem>, Reason> {
        if !slot.operation.images() || !slot.images.as_ref().is_some_and(|original| Arc::ptr_eq(original, &binding))
            || state.images.row(&binding.operation_id).is_none() { return Err(Reason::ContextStale); }
        // The source book is not-started on refusal and settled on success.
        // Require every normal ORIGINAL join, actual response/release, no STOP
        // and consumed multi-result before offering the one-use token.
        if !slot.owner.project_path_settled(true) { return Err(Reason::CleanupUnknown); }
        let selected = document.inner.bridge.native_project(&binding.project_id);
        let (generation, root) = document.registry_result(state, selected, Some(&slot.owner)).map_err(|error| error.reason)?;
        if !binding.matches(generation, &root) { return Err(Reason::SourceChanged); }
        if !(1..=wire::MAX_FILES).contains(&batch.images.len())
            || batch.retained_bytes().is_none_or(|bytes| bytes > binding.source_budget().retained_bytes)
            || batch.images.iter().any(|item| item.item_id == binding.operation_id || item.item_id == binding.selection_token.0) {
            return Err(Reason::MaterialLimit);
        }
        selected_items(&batch)
        })();
    match admitted {
        Ok(items) => {
            if let Some(row) = state.images.active.as_mut().filter(|row| row.operation_id == binding.operation_id) { row.items = items; }
            else { slot.staged = Some(Staged::Images { batch, binding }); slot.stop(Reason::ContextStale, Instant::now()); return; }
            slot.image_batch = Some(batch); slot.selection = Some(binding.selection_token.clone());
            slot.source = SourceState::Captured; slot.phase = Phase::Selected; slot.settlement = Settlement::Known;
        },
        Err(reason) => {
            // Even failed publication retains the original bytes for the shared
            // off-lock retirement; failure never creates or restores a token.
            slot.staged = Some(Staged::Images { batch, binding }); slot.stop(reason, Instant::now());
            if reason == Reason::CleanupUnknown { state.unknown = true; }
        },
    }
}

impl GuiCall {
    pub(crate) fn selected_public_images(&self, paths: Result<Vec<PathBuf>, Reason>) {
        let Some(inner) = self.document.upgrade() else { return; };
        let document = DocumentBinding { inner }; let Some(owner) = self.owner() else { return; };
        let mut state = document.lock();
        let matches = state.slot.as_ref().is_some_and(|slot| slot.operation.images() && Arc::ptr_eq(&slot.owner, &owner));
        if !matches { return; } // Never touch another document's/operation's cell.
        let mut refusal = None;
        if let Some(mut facts) = self.facts() {
            let accepted = facts.accepted && !owner.interrupted();
            match paths {
                Ok(paths) if accepted => {
                    let bounded = (1..=wire::MAX_FILES).contains(&paths.len()) && paths.capacity() <= wire::MAX_FILES
                        && paths.iter().all(|path| path.capacity() <= asset_source::PATH_LIMIT && asset_source::path_hint(path).is_ok());
                    if !bounded { refusal = Some(Reason::MaterialLimit); }
                    else if facts.selected.is_some() { refusal = Some(Reason::CleanupUnknown); }
                    else if let Ok(mut selected) = self.selected_images.lock() {
                        if selected.is_some() { refusal = Some(Reason::CleanupUnknown); } else { *selected = Some(paths); }
                    } else { refusal = Some(Reason::CleanupUnknown); }
                },
                Ok(_) => {},
                Err(reason) => refusal = Some(reason),
            }
            if let Some(reason) = refusal { if facts.refusal.is_none() { facts.refusal = Some(reason); } }
        } else { refusal = Some(Reason::CleanupUnknown); }
        if let Some(reason) = refusal {
            if let Some(slot) = state.slot.as_mut() { slot.stop(reason, Instant::now()); }
        }
        document.bump(&mut state); self.changed();
    }
    // Called only by the common GUI loop after the original native object and
    // callbacks were closed/released. Taking DATA does not grant settlement.
    pub(crate) fn take_public_images(&self) -> Result<Option<Vec<PathBuf>>, Reason> {
        self.selected_images.lock().map(|mut paths| paths.take()).map_err(|_| Reason::CleanupUnknown)
    }
}

impl DocumentBinding {
    fn metadata_images_capability(&self, state: &DocumentState, edit: EditCapability) -> EditCapability {
        let unavailable = |reason| EditCapability { available: false, reason };
        if state.unknown || state.exhausted || self.inner.bridge.supervisor.disabled() { return unavailable(EditAvailability::CleanupUnknown); }
        if state.stopping || self.inner.bridge.supervisor.stopping() { return unavailable(EditAvailability::Shutdown); }
        if !cfg!(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")) { return unavailable(EditAvailability::UnsupportedPlatform); }
        if !edit.available { return edit; }
        if !state.lifetime.original_bound() || state.lost_observed || !self.inner.bridge.metadata_images_selection_available() {
            return unavailable(EditAvailability::RuntimeUnqualified);
        }
        if let Err(error) = self.common_gate(state, false) {
            return unavailable(match error.reason {
                Reason::CleanupUnknown => EditAvailability::CleanupUnknown,
                Reason::Shutdown => EditAvailability::Shutdown,
                Reason::DocumentLost | Reason::Unqualified | Reason::Closed => EditAvailability::RuntimeUnqualified,
                _ => EditAvailability::OtherEditActive,
            });
        }
        if state.quit_pending || state.retiring || state.lock_pending || state.compatibility_picker_pending
            || state.slot.as_ref().is_some_and(|slot| !slot.operation.images() && (slot.phase != Phase::Idle || !slot.owner.resources_settled()))
            || !self.inner.bridge.edits.can_exit() || !self.inner.bridge.supervisor.can_exit()
            || state.github.native_work_pending() {
            return unavailable(EditAvailability::OtherEditActive);
        }
        edit
    }
    // Called at the first observed image failure, not deferred until the
    // coordinator is finally joined/published. STOP/endpoints remain the
    // original slot's minimum; a late result can never renew the interval.
    fn metadata_images_failed(&self, owner: &Arc<OriginalWork>, reason: Reason) -> Staged {
        source_failure(owner, reason); let mut state = self.lock();
        if state.slot.as_ref().is_some_and(|slot| slot.operation.images() && Arc::ptr_eq(&slot.owner, owner)) {
            observe_failure(&mut state); self.bump(&mut state);
        }
        Staged::Refused(reason)
    }
    fn metadata_images_selection_snapshot_locked(&self, state: &mut DocumentState) -> Result<wire::SelectionStatus, BridgeError> {
        let edit = self.inner.bridge.edits.metadata_images_status()?;
        let capability = self.metadata_images_capability(state, edit.capability);
        if state.images.observed_capability != Some(capability.reason) {
            state.images.observed_capability = Some(capability.reason); self.bump(state);
        }
        refresh(state);
        let status = wire::SelectionStatus { schema_version: 1, domain: "metadata_images_selection", window_generation: edit.window_generation,
            status_revision: state.revision, capability, active: state.images.active.clone(), last_terminal: state.images.last.clone() };
        crate::edit_protocol::bounded(&status, SELECTION_STATUS_LIMIT)?; Ok(status)
    }
    pub(crate) fn metadata_images_selection_status(&self) -> Result<wire::SelectionStatus, BridgeError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now());
        self.metadata_images_selection_snapshot_locked(&mut state)
    }
    pub(crate) fn metadata_images_selection_cancel(&self, args: SelectionCancel) -> Result<wire::SelectionStatus, BridgeError> {
        if !crate::edit_protocol::token(&args.operation_id) { return Err(BridgeError::invalid()); }
        let mut state = self.lock();
        let row = state.images.row(&args.operation_id).ok_or_else(|| refused(ImageReason::SourceChanged))?;
        let original = state.slot.as_ref().is_some_and(|slot| slot.operation.images()
            && slot.images.as_ref().is_some_and(|binding| binding.operation_id == args.operation_id));
        if !original {
            if matches!(row.settlement, ImageSettlement::Pending | ImageSettlement::Unknown) { return Err(refused(ImageReason::CleanupUnknown)); }
            return self.metadata_images_selection_snapshot_locked(&mut state);
        }
        self.expire(&mut state, Instant::now());
        let slot = state.slot.as_mut().ok_or_else(BridgeError::invalid)?;
        // A successful transfer owns no selection bytes/token. It is not a new
        // cancellation authority for whichever EditOwner is now active.
        if !consumed_selection(slot) && slot.cleanup_end.is_none()
            && !(slot.phase == Phase::Idle && slot.image_batch.is_none() && slot.selection.is_none() && slot.owner.resources_settled()) {
            let now = Instant::now();
            let reason = if slot.owner.endpoint().is_some_and(|end| now >= end) { Reason::Deadline } else { Reason::UserCancelled };
            slot.stop(reason, now); self.bump(&mut state);
        }
        drop(state); self.reconcile();
        self.metadata_images_selection_snapshot_locked(&mut self.lock())
    }
    pub(crate) fn metadata_images_edit_admit<T>(&self,
        project_id: impl FnOnce(&DesktopBridge) -> Result<String, BridgeError>,
        enqueue: impl FnOnce(&DesktopBridge, crate::edit_owner::RegisteredEditRoot) -> Result<T, BridgeError>,
    ) -> Result<T, BridgeError> {
        self.registered_edit_admit(EditDomain::MetadataImages, project_id, enqueue)
    }
    pub(crate) fn metadata_images_import_admit<T>(&self, project_id: &str, selection_token: &str,
        enqueue: impl FnOnce(&DesktopBridge, crate::edit_owner::RegisteredEditRoot, wire::ImportData, &mut bool) -> Result<T, BridgeError>,
    ) -> Result<T, BridgeError> {
        if !crate::protocol::valid_id(project_id) || !crate::edit_protocol::token(selection_token) { return Err(import_not_matched()); }
        let mut state = self.lock();
        // Match before expiry/admission. Wrong tokens must not erase or STOP an
        // unrelated original selection; matching failures always retire it.
        let (binding, owner) = matched_selection(&state, project_id, selection_token).ok_or_else(import_not_matched)?;
        let mut edit_claimed = false;
        let result = (|| {
            let registered = self.registered_edit_root_locked(&mut state, EditDomain::MetadataImages,
                |_| Ok(project_id.to_owned()), Some(&binding))?;
            if !binding.matches(registered.generation, &registered.root) { return Err(refused(ImageReason::SourceChanged)); }
            let slot = state.slot.as_mut().filter(|slot| own_settled_selection(slot, &binding))
                .ok_or_else(|| refused(ImageReason::Busy))?;
            slot.selection = None; // Permanent consumption even if enqueue fails.
            let count = slot.image_batch.as_ref().ok_or_else(BridgeError::invalid)?.images.len();
            let mut selected = Vec::new(); selected.try_reserve_exact(count).map_err(|_| refused(ImageReason::SelectionLimit))?;
            let mut protected_objects = Vec::new(); protected_objects.try_reserve_exact(count).map_err(|_| refused(ImageReason::SelectionLimit))?;
            let batch = slot.image_batch.take().ok_or_else(BridgeError::invalid)?;
            for image in batch.images {
                protected_objects.push(wire::SourceObject::from(image.source_object()));
                selected.push(wire::SelectedImageData { item_id: image.item_id, display_name: image.display_name,
                    bytes: image.bytes, sha256: image.sha256 });
            }
            let data = wire::ImportData { context: binding.context.clone(), images: selected, protected_sources: batch.protected_sources, protected_objects };
            // The sole synchronous callback must retain/retire this one moved
            // batch. No restore, byte clone, new token or Open retry on refusal.
            let result = enqueue(&self.inner.bridge, registered, data, &mut edit_claimed);
            if result.is_ok() { slot.phase = Phase::Idle; slot.review_end = None; slot.settlement = Settlement::Known; }
            result
        })();
        let result = result.map_err(|error| retire_matching_import_failure(&mut state, &binding, &owner,
            edit_claimed, error, Instant::now()));
        self.bump(&mut state); drop(state);
        if result.is_err() { self.reconcile(); }
        result
    }
}

#[cfg(feature = "desktop-shell")]
impl DocumentBinding {
    pub(crate) fn metadata_images_selection_start(&self, app: tauri::AppHandle, args: SelectionStart) -> Result<wire::SelectionStatus, BridgeError> {
        if !crate::protocol::valid_id(&args.project_id) || !args.context().valid() { return Err(selection_not_admitted(BridgeError::invalid())); }
        // Bounded native entropy preparation, like existing edit/GitHub tickets;
        // no paths, source resources, child or file bytes exist at this point.
        let tokens = random_tokens(&mut || false).map_err(|error| selection_not_admitted(refused(reason(error, false))))?;
        if !tokens_distinct(&tokens) { return Err(selection_not_admitted(BridgeError::invalid())); }
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now());
        let edit = self.inner.bridge.edits.metadata_images_status().map_err(selection_not_admitted)?;
        let capability = self.metadata_images_capability(&state, edit.capability);
        if !capability.available {
            return Err(selection_not_admitted(refused(match capability.reason {
                EditAvailability::CleanupUnknown => ImageReason::CleanupUnknown, EditAvailability::Shutdown => ImageReason::Shutdown,
                EditAvailability::OtherEditActive => ImageReason::Busy, EditAvailability::UnsupportedPlatform => ImageReason::UnsupportedPlatform,
                _ => ImageReason::RuntimeUnqualified,
            })));
        }
        idle(&state).map_err(|error| selection_not_admitted(refused(reason(error.reason, false))))?;
        let byte_limit = raw_allowance(&state).map_err(|error| selection_not_admitted(refused(reason(error, false))))?;
        let (generation, root) = self.registry_result(&mut state, self.inner.bridge.native_project(&args.project_id), None)
            .map_err(|error| selection_not_admitted(refused(reason(error.reason, false))))?;
        if state.images.row(&tokens.record.0).is_some() { return Err(selection_not_admitted(BridgeError::invalid())); }
        let binding = Arc::new(Binding { operation_id: tokens.record.0, project_id: args.project_id.clone(), context: args.context(),
            root, generation, selection_token: tokens.selection, byte_limit });
        if state.images.active.is_some() { return Err(selection_not_admitted(refused(ImageReason::Busy))); }
        let id = self.next_operation(&mut state).map_err(|error| selection_not_admitted(refused(reason(error.reason, false))))?;
        let owner = OriginalWork::new(id, true, Arc::downgrade(&self.inner));
        let mut slot = Slot::new(owner.clone(), Operation::ChooseImages, None, None, None); slot.images = Some(binding.clone());
        // No row is installed for a refused replacement. Conversely an
        // installed-but-failed original must retain its matching status row.
        let installed = self.install(&mut state, slot, Job::Images { app, binding: binding.clone() });
        let original_installed = state.slot.as_ref().is_some_and(|slot| Arc::ptr_eq(&slot.owner, &owner));
        if original_installed {
            state.images.active = Some(binding.initial()); self.bump(&mut state);
        }
        let start = installed.map_err(|error| {
            let error = refused(reason(error.reason, false));
            if original_installed { error } else { selection_not_admitted(error) }
        })?;
        let status = match self.metadata_images_selection_snapshot_locked(&mut state) {
            Ok(status) => status,
            Err(error) => {
                if let Some(slot) = state.slot.as_mut().filter(|slot| Arc::ptr_eq(&slot.owner, &owner)) {
                    slot.stop(edit_error_reason(&error), Instant::now()); self.bump(&mut state);
                }
                drop(state); drop(start); self.reconcile(); return Err(error);
            },
        };
        drop(state);
        if start.send(()).is_err() {
            self.metadata_images_failed(&owner, Reason::CleanupUnknown);
            return self.metadata_images_selection_status();
        }
        Ok(status)
    }
}

#[cfg(feature = "desktop-shell")]
pub(super) async fn run(document: &DocumentBinding, owner: &Arc<OriginalWork>, app: tauri::AppHandle, binding: Arc<Binding>) -> Staged {
    let paths = match crate::shell::run_owned_images_dialog(&app, owner).await {
        Ok(Some(paths)) => paths, Ok(None) => return document.metadata_images_failed(owner, Reason::UserCancelled),
        Err(reason) => return document.metadata_images_failed(owner, reason),
    };
    if let Err(reason) = document.phase(owner, Phase::Capturing) { return document.metadata_images_failed(owner, reason); }
    match child(owner, ChildJob::Images { paths, binding: binding.clone() }).await {
        Ok(ChildEnd::Images(batch)) => Staged::Images { batch, binding },
        Ok(ChildEnd::Refused(reason)) | Err(reason) => document.metadata_images_failed(owner, reason),
        _ => document.metadata_images_failed(owner, Reason::CleanupUnknown),
    }
}

#[cfg(test)]
mod tests {
    // Inert DATA/negative-authority predicates only: no DesktopBridge, source
    // open, native dialog, RNG, thread or fabricated ORIGINAL join is used.
    // Native success/cancel/import remains a separate qualification obligation.
    use super::*;

    fn model() -> (DocumentState, Arc<Binding>, Arc<OriginalWork>) {
        let mut state = super::super::tests::empty_state();
        state.lifetime.crash_hook_installed(); state.lifetime.started(true); state.lifetime.finished(true);
        let binding = Arc::new(Binding { operation_id: "a".repeat(32), project_id: "project-1".into(),
            context: wire::Context { platform: crate::metadata_text_edit_protocol::Platform::Android,
                locale: "en-US".into(), asset_type: "phoneScreenshots".into() },
            root: asset_source::RegisteredRoot { path: "/inert/project".into(),
                identity: asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::synthetic_evidence_identity()) },
            generation: 1, selection_token: Token("b".repeat(32)), byte_limit: wire::BATCH_LIMIT });
        let owner = OriginalWork::new(1, true, Weak::new());
        let mut slot = Slot::new(owner.clone(), Operation::ChooseImages, None, None, None);
        slot.images = Some(binding.clone()); state.slot = Some(slot); state.images.active = Some(binding.initial());
        (state, binding, owner)
    }

    #[test]
    fn image_originals_block_other_domains_but_status_cannot_create_selection_authority() {
        let (mut state, binding, owner) = model();
        assert!(Operation::ChooseImages.blocks_context() && !Operation::ChooseImages.evidence());
        assert!(pending(&state) && idle(&state).is_err() && passive_document_gate(&state).is_err());
        assert_eq!(common_document_gate(&state, true, || Ok(())).err().map(|e| e.reason), Some(Reason::Busy));
        let slot = state.slot.as_mut().unwrap();
        slot.phase = Phase::Selected; slot.settlement = Settlement::Known; slot.source = SourceState::Captured;
        slot.selection = Some(binding.selection_token.clone());
        // Claimed phases/token/body-end are not a captured batch, actual GUI
        // response, source finality or an original coordinator/child join.
        owner.ended.store(true, Ordering::SeqCst);
        assert!(!own_settled_selection(slot, &binding) && !owner.resources_settled());
        refresh(&mut state);
        let row = state.images.active.as_ref().unwrap();
        assert!(row.phase == ImagePhase::Capturing && row.settlement == ImageSettlement::Pending && row.selection_token.is_none());
        let view = serde_json::to_value(DocumentBinding::status_data(&state, false)).unwrap();
        assert_eq!(view["operation"]["operation"], "choose-images");
        for key in ["selectionToken", "assessment", "preview"] { assert!(view["operation"][key].is_null()); }
        assert!(state.records.is_empty() && state.assignments.is_empty() && state.context.is_none());
    }

    #[test]
    fn image_token_matching_is_project_scoped_and_stop_is_irreversible() {
        let (mut state, binding, owner) = model();
        state.slot.as_mut().unwrap().selection = Some(binding.selection_token.clone());
        let now = Instant::now(); owner.set_endpoint(Some(now + WORK));
        for (project, token) in [("project-2", binding.selection_token.0.as_str()), ("project-1", "wrong-token")] {
            assert!(matched_selection(&state, project, token).is_none());
            assert!(!owner.stopped() && state.slot.as_ref().unwrap().selection.as_ref() == Some(&binding.selection_token));
        }
        let (original, original_owner) = matched_selection(&state, "project-1", &binding.selection_token.0).unwrap();
        assert!(Arc::ptr_eq(&original, &binding) && Arc::ptr_eq(&original_owner, &owner));
        let slot = state.slot.as_mut().unwrap(); slot.stop(Reason::Busy, now); let cutoff = slot.cleanup_end;
        slot.stop(Reason::UserCancelled, now + WORK);
        assert_eq!(slot.cleanup_end, cutoff); assert_eq!(slot.reason, Reason::Busy);
        assert!(slot.selection.is_none() && owner.stopped());
        assert!(matched_selection(&state, "project-1", &binding.selection_token.0).is_none());
        refresh(&mut state); let row = state.images.active.as_ref().unwrap();
        assert!(row.settlement == ImageSettlement::Pending && row.selection_token.is_none());
        state.unknown = true; refresh(&mut state);
        let row = state.images.active.as_ref().unwrap();
        assert!(row.phase == ImagePhase::Unknown && row.settlement == ImageSettlement::Unknown && row.selection_token.is_none());
    }

    #[test]
    fn matching_import_preclaim_refusal_retires_only_original_token_without_claiming_cleanup() {
        for claimed in [false, true] {
            let (mut state, binding, owner) = model();
            state.slot.as_mut().unwrap().selection = Some(binding.selection_token.clone());
            let (original, original_owner) = matched_selection(&state, "project-1", &binding.selection_token.0).unwrap();
            let error = retire_matching_import_failure(&mut state, &original, &original_owner,
                claimed, BridgeError::new("busy", "Original edit admission refused."), Instant::now());
            assert_eq!(error.code, if claimed { "busy" } else { "metadata_images_import_not_admitted" });
            assert!(owner.stopped() && state.slot.as_ref().unwrap().selection.is_none());
            assert_eq!(state.slot.as_ref().unwrap().reason, Reason::Busy);
            assert!(matched_selection(&state, "project-1", &binding.selection_token.0).is_none());
            // Never turn a method-scoped no-claim fact into selected-resource
            // finality. These inert original handles never started or joined.
            assert!(!owner.resources_settled() && pending(&state));
            refresh(&mut state);
            let row = state.images.active.as_ref().unwrap();
            assert!(row.settlement == ImageSettlement::Pending && row.selection_token.is_none());
        }
    }

    #[test]
    fn matching_import_refusal_requires_original_binding_owner_and_slot_to_issue_marker() {
        for lost in 0..5 {
            let (mut state, binding, owner) = model();
            state.slot.as_mut().unwrap().selection = Some(binding.selection_token.clone());
            let (_, other_binding, other_owner) = model();
            match lost {
                0 => state.slot.as_mut().unwrap().images = Some(other_binding),
                1 => state.slot.as_mut().unwrap().owner = other_owner.clone(),
                2 => state.slot.as_mut().unwrap().images = None,
                3 => state.slot.as_mut().unwrap().operation = Operation::Prepare,
                _ => state.slot = None,
            }
            let error = retire_matching_import_failure(&mut state, &binding, &owner, false,
                BridgeError::new("busy", "Original edit admission refused."), Instant::now());
            assert_eq!(error.code, "busy");
            assert!(!owner.stopped() && !other_owner.stopped());
            if let Some(slot) = &state.slot {
                assert!(slot.selection.as_ref() == Some(&binding.selection_token) && slot.cleanup_end.is_none());
            }
        }
    }

    #[test]
    fn pending_images_cannot_be_stopped_through_credential_lock() {
        let (mut state, binding, owner) = model();
        state.slot.as_mut().unwrap().selection = Some(binding.selection_token.clone());
        for phase in [Phase::Picking, Phase::Selected, Phase::Idle, Phase::Unknown] {
            state.slot.as_mut().unwrap().phase = phase;
            for unknown in [false, true] {
                state.unknown = unknown;
                assert_eq!(credential_lock_gate(&state).err().map(|error| error.reason),
                    Some(if unknown { Reason::CleanupUnknown } else { Reason::Busy }));
                assert!(!owner.stopped() && !state.lock_pending);
                assert!(state.slot.as_ref().unwrap().selection.as_ref() == Some(&binding.selection_token));
            }
        }
        state.lifetime.invalidate();
        assert_eq!(credential_lock_gate(&state).err().map(|error| error.reason), Some(Reason::DocumentLost));
    }

    #[test]
    fn source_failure_keeps_earliest_cutoff_despite_delayed_join_or_later_close_failure() {
        let (mut state, binding, owner) = model(); let at = Instant::now();
        owner.set_endpoint(Some(at + WORK));
        state.slot.as_mut().unwrap().source = SourceState::Pending;
        // The actual callback is permitted with the source book held: it
        // writes only its original small latch/STOP, never tries to acquire
        // source/document/child/GUI again or claims a close/join happened.
        let source = owner.source.lock().unwrap();
        source_failure_at(&owner, Reason::SourceChanged, at);
        assert!(owner.stopped()); drop(source);
        // A late coordinator/body signal is not a join. Observation uses the
        // callback's original instant, not this later cancellation timestamp.
        owner.ended.store(true, Ordering::SeqCst);
        assert!(observe_failure(&mut state));
        let cutoff = Some(at + CLEANUP);
        let slot = state.slot.as_mut().unwrap();
        assert_eq!(slot.cleanup_end, cutoff); assert_eq!(slot.reason, Reason::SourceChanged);
        slot.stop(Reason::UserCancelled, at + WORK);
        assert_eq!(slot.cleanup_end, cutoff);
        assert!(!own_settled_selection(slot, &binding) && !owner.resources_settled());
        source_failure_at(&owner, Reason::CleanupUnknown, at + WORK + CLEANUP);
        assert!(observe_failure(&mut state) && state.unknown);
        assert_eq!(state.slot.as_ref().unwrap().cleanup_end, cutoff);
        assert_eq!(*owner.cleanup_end.lock().unwrap(), cutoff);
        // Repeated late results do not reset an observed latch or renew STOP.
        source_failure_at(&owner, Reason::UserCancelled, at + WORK + WORK);
        assert!(!observe_failure(&mut state));
        refresh(&mut state); let row = state.images.active.as_ref().unwrap();
        assert!(row.phase == ImagePhase::Unknown && row.settlement == ImageSettlement::Unknown && row.selection_token.is_none());
        assert!(state.slot.as_ref().unwrap().image_batch.is_none() && !owner.resources_settled());
    }

    #[test]
    fn consumed_selection_has_no_cancel_authority_and_path_data_never_grants_finality() {
        let (mut state, _binding, owner) = model();
        let slot = state.slot.as_mut().unwrap();
        slot.phase = Phase::Idle; slot.source = SourceState::Captured;
        assert!(!consumed_selection(slot));
        slot.settlement = Settlement::Known;
        // Tests the already-consumed DATA predicate, not native publication.
        // No result/token is issued; even blocked observer locks do not turn
        // the consumed row into cancellation of the active edit domain.
        let held = owner.coordinator.lock().unwrap();
        assert!(consumed_selection(slot) && !own_settled_selection(slot, slot.images.as_ref().unwrap()));
        drop(held);
        let paths = vec![PathBuf::from("/inert/public.png")];
        *owner.gui.selected_images.lock().unwrap() = Some(paths);
        assert!(!owner.resources_settled());
        let retirement = Retirement { image_paths: owner.gui.take_public_images().unwrap(), ..Retirement::default() };
        assert!(retirement.image_paths.is_some());
        assert!(owner.retain_retirement(retirement).is_ok());
        assert!(!owner.retired.load(Ordering::SeqCst) && !owner.resources_settled());
        assert!(owner.release_retirement());
        assert!(owner.retired.load(Ordering::SeqCst) && owner.gui.take_public_images().unwrap().is_none());
        assert!(!owner.resources_settled()); // Real originals still never ran/joined.
    }
}
