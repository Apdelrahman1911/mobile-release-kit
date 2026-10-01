//! Fixed text import inside the original document/GUI/source/coordinator owner.
//! Registry rows contain no text/path/digest. A private result is consumed once
//! by its original invoke, never reconstructed by status or an event.
use super::*;
use crate::{protocol::Method, required_notes_commands as input, required_notes_edit_protocol as wire};

// Separate purpose qualification; old credential/project/image receipts do not
// enable note import. Root binds this only to reviewed real native evidence.
const NATIVE_REQUIRED_NOTES_IMPORT_QUALIFIED: bool = false;
pub(super) const CONTROL_RESERVE: usize = 3 * 1024 * 1024;

pub(super) struct Binding {
    request: u32, project: String, window: String, context: wire::Context,
    pub(super) root: asset_source::RegisteredRoot, generation: u32,
}
impl Binding {
    pub(super) fn kind(&self) -> wire::Kind { self.context.kind() }
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(self.project.capacity())?.checked_add(self.window.capacity())?
            .checked_add(self.root.path.capacity())?.checked_add(self.context.retained_bytes())
    }
    fn initial(&self) -> wire::ImportStatus {
        wire::ImportStatus { schema_version: 1, request_id: self.request, project_id: self.project.clone(),
            window_generation: self.window.clone(), context: self.context.clone(), phase: wire::ImportPhase::Pending,
            outcome: None, reason: wire::ImportReason::None }
    }
}
pub(super) struct Content { pub(super) text: String, pub(super) validation: Option<wire::Validation> }
impl Content {
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        self.text.capacity().checked_add(std::mem::size_of::<Self>())?.checked_add(wire::STATUS_LIMIT)
    }
    fn selected(self, kind: wire::Kind) -> Result<wire::Imported, Self> {
        let Self { text, validation } = self;
        let Some(validation) = validation else { return Err(Self { text, validation: None }); };
        wire::Imported::selected(kind, text, validation).map_err(|(text, validation)| Self { text, validation: Some(validation) })
    }
}
pub(super) struct Registry {
    sequence: Option<u32>, active: Option<wire::ImportStatus>, last: Option<wire::ImportStatus>,
    // Content-free refusal detail belongs to this original request, not to a
    // Pending wire row. It is published only after actual original settlement.
    refusal_hint: Option<(u32, wire::ImportReason)>,
}
impl Registry {
    pub(super) fn new() -> Self { Self { sequence: None, active: None, last: None, refusal_hint: None } }
    fn row(&self, window: &str, request: u32) -> Option<&wire::ImportStatus> {
        self.active.as_ref().filter(|r| r.window_generation == window && r.request_id == request)
            .or_else(|| self.last.as_ref().filter(|r| r.window_generation == window && r.request_id == request))
    }
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        let mut total = std::mem::size_of::<Self>();
        for row in self.active.iter().chain(&self.last) {
            total = total.checked_add(row.project_id.capacity())?.checked_add(row.window_generation.capacity())?.checked_add(row.context.retained_bytes())?;
        }
        Some(total)
    }
}
pub(super) fn pending(state: &DocumentState) -> bool {
    state.slot.as_ref().is_some_and(|slot| slot.operation.required_notes() && (slot.phase != Phase::Idle || !slot.owner.resources_settled()))
}
fn refusal_reason(value: Reason) -> wire::ImportReason {
    use wire::ImportReason as R;
    match value {
        // STOP, absent GUI construction and an early/late native response are
        // refusals, never a fabricated genuine native dialog Cancel receipt.
        Reason::None | Reason::UserCancelled => R::IoError,
        Reason::UnsupportedFormat | Reason::MaterialLimit | Reason::Capacity | Reason::ParserLimit => R::InvalidFile,
        Reason::SourceChanged => R::ChangedFile, Reason::ContextStale | Reason::DocumentLost => R::ContextChanged,
        Reason::UnsupportedPlatform | Reason::Unqualified | Reason::Closed => R::Unavailable,
        Reason::CleanupUnknown => R::CleanupUnknown, _ => R::IoError,
    }
}
fn query_reason(error: BridgeError) -> Reason {
    match error.code.as_str() {
        "required_notes_cleanup_unknown" | "cleanup_unknown" => Reason::CleanupUnknown,
        "required_notes_changed" | "required_notes_config_missing" | "required_notes_config_invalid"
            | "required_notes_not_configured" | "required_notes_version_missing" | "required_notes_version_invalid" => Reason::ContextStale,
        "required_notes_sensitive" | "required_notes_encoding" | "required_notes_limit" => Reason::UnsupportedFormat,
        "required_notes_unavailable" | "runtime_unavailable" | "unavailable" => Reason::Unqualified,
        "query_timeout" => Reason::Deadline, "shutting_down" => Reason::Shutdown, _ => Reason::SourceRefused,
    }
}
fn same(slot: &Slot, owner: &Arc<OriginalWork>, binding: &Arc<Binding>) -> bool {
    slot.operation.required_notes() && Arc::ptr_eq(&slot.owner, owner)
        && slot.required_notes.as_ref().is_some_and(|original| Arc::ptr_eq(original, binding))
}
fn publication_expired(slot: &Slot, work: Option<Instant>, now: Instant) -> Option<(Reason, Instant)> {
    // The joined coordinator can legitimately clear its work endpoint. The
    // SAME slot's absolute review deadline must still bound private delivery.
    let Some(review) = slot.review_end else { return Some((Reason::CleanupUnknown, now)); };
    let (end, reason) = match work {
        Some(work) if work <= review => (work, Reason::Deadline),
        _ => (review, Reason::ReviewExpired),
    };
    (now >= end).then_some((reason, end))
}
fn refuse_private_selection(slot: &mut Slot, result: wire::Imported, why: Reason, at: Instant) {
    if let wire::Imported::Selected { text, validation, .. } = result {
        slot.note_content = Some(Content { text, validation: Some(validation) });
    }
    slot.stop(why, at);
}
pub(super) fn refresh(state: &mut DocumentState) {
    let Some(slot) = state.slot.as_ref().filter(|s| s.operation.required_notes()) else { return; };
    let Some(binding) = slot.required_notes.as_ref() else { return; };
    let Some(mut row) = state.required_notes.row(&binding.window, binding.request).cloned() else { return; };
    if state.unknown || state.exhausted || slot.phase == Phase::Unknown || slot.reason == Reason::CleanupUnknown
        || matches!(slot.settlement, Settlement::Unknown | Settlement::LateKnown) {
        row.phase = wire::ImportPhase::Unknown; row.outcome = None; row.reason = wire::ImportReason::CleanupUnknown;
    } else if slot.phase == Phase::Idle && slot.owner.resources_settled() && !state.retiring {
        // A receipt follows actual originals and private DATA retirement, not
        // a cancelled invoke, body-end flag, deadline, or a missing status row.
        row.phase = wire::ImportPhase::Settled;
        if row.outcome == Some(wire::ImportOutcome::Selected) && slot.reason == Reason::None {
            row.reason = wire::ImportReason::None;
        } else if slot.reason == Reason::UserCancelled && slot.owner.project_path_settled(false) {
            row.outcome = Some(wire::ImportOutcome::Cancelled); row.reason = wire::ImportReason::Cancelled;
        } else {
            row.outcome = Some(wire::ImportOutcome::Refused);
            row.reason = if slot.reason == Reason::UnsupportedFormat
                && state.required_notes.refusal_hint == Some((binding.request, wire::ImportReason::InvalidText)) {
                wire::ImportReason::InvalidText
            } else { refusal_reason(slot.reason) };
        }
    } else { row.phase = wire::ImportPhase::Pending; row.outcome = None; row.reason = wire::ImportReason::None; }
    if row.phase == wire::ImportPhase::Settled {
        state.required_notes.active = None; state.required_notes.last = Some(row);
    } else { state.required_notes.active = Some(row); }
}
fn original_live(document: &DocumentBinding, state: &mut DocumentState, owner: &Arc<OriginalWork>, binding: &Arc<Binding>) -> Result<(), Reason> {
    document.expire(state, Instant::now());
    document.common_gate(state, false).map_err(|e| e.reason)?;
    if state.exhausted || state.lost_observed || !state.lifetime.original_bound() { return Err(Reason::DocumentLost); }
    if let Some(reason) = document.live_session_owner_reason() { return Err(reason); }
    if !document.inner.bridge.edits.can_exit() || state.github.native_work_pending() { return Err(Reason::Busy); }
    if document.inner.bridge.edits.required_notes_window(MAIN).map_err(|_| Reason::DocumentLost)? != binding.window { return Err(Reason::DocumentLost); }
    let slot = state.slot.as_ref().filter(|s| same(s, owner, binding)).ok_or(Reason::ContextStale)?;
    if owner.interrupted() || slot.cleanup_end.is_some() || slot.reason != Reason::None { return Err(if slot.reason == Reason::None { Reason::Deadline } else { slot.reason }); }
    let selected = document.inner.bridge.native_project(&binding.project);
    let (generation, root) = document.registry_result(state, selected, Some(owner)).map_err(|e| e.reason)?;
    if binding.generation != generation || binding.root != root { return Err(Reason::ContextStale); }
    Ok(())
}
pub(super) fn publish(document: &DocumentBinding, state: &mut DocumentState, slot: &mut Slot, content: Content, binding: Arc<Binding>) {
    let admitted = (|| -> Result<(), Reason> {
        // reconcile temporarily holds the original slot separately; no lookup
        // by an untrusted renderer ID can substitute for this exact binding.
        if !same(slot, &slot.owner, &binding) || state.required_notes.row(&binding.window, binding.request).is_none()
            || !slot.owner.project_path_settled(true) || !document.inner.bridge.supervisor.can_exit()
            || !document.inner.bridge.edits.can_exit() { return Err(Reason::CleanupUnknown); }
        document.common_gate(state, false).map_err(|e| e.reason)?;
        if document.inner.bridge.edits.required_notes_window(MAIN).map_err(|_| Reason::DocumentLost)? != binding.window { return Err(Reason::DocumentLost); }
        let selected = document.inner.bridge.native_project(&binding.project);
        let (generation, root) = document.registry_result(state, selected, Some(&slot.owner)).map_err(|e| e.reason)?;
        if generation != binding.generation || root != binding.root { return Err(Reason::ContextStale); }
        if content.text.capacity() > binding.kind().byte_limit() + 1 || !content.validation.as_ref().is_some_and(|v| v.valid) { return Err(Reason::UnsupportedFormat); }
        Ok(())
    })();
    if let Err(reason) = admitted {
        slot.staged = Some(Staged::RequiredNote { content, binding }); slot.stop(reason, Instant::now());
        if reason == Reason::CleanupUnknown { state.unknown = true; }
    } else {
        slot.note_content = Some(content); slot.source = SourceState::Captured; slot.phase = Phase::Selected; slot.settlement = Settlement::Known;
    }
}
impl DocumentBinding {
    pub(crate) fn required_notes_capabilities(&self, window: &str) -> Result<wire::Capabilities, BridgeError> {
        let generation = self.inner.bridge.edits.required_notes_window(window)?;
        let state = self.lock();
        let ready = passive_document_gate(&state).is_ok() && self.common_gate(&state, false).is_ok()
            && !state.lost_observed && !state.exhausted && self.live_session_owner_reason().is_none()
            && self.inner.bridge.supervisor.can_exit() && self.inner.bridge.edits.can_exit() && !state.github.native_work_pending();
        let availability = |platform: bool, qualified: bool| wire::Availability {
            available: platform && qualified && ready,
            reason: if !platform { wire::AvailabilityReason::UnsupportedPlatform }
                else if !qualified { wire::AvailabilityReason::NotQualified }
                else if !ready { wire::AvailabilityReason::DocumentUnavailable } else { wire::AvailabilityReason::None },
        };
        let posix = cfg!(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")));
        let linux = cfg!(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"));
        Ok(wire::Capabilities { schema_version: 1, window_generation: generation,
            read: availability(posix, self.inner.bridge.supervisor.passive_method_available("required.notes.observe")),
            edit: availability(linux, self.inner.bridge.edits.required_notes_capability().available),
            import: availability(linux, self.required_notes_import_available()) })
    }
    fn required_notes_read_root(&self, state: &mut DocumentState, bridge: &DesktopBridge, window: &str, args: &input::Observe)
        -> Result<crate::edit_owner::RegisteredEditRoot, BridgeError> {
        if !std::ptr::eq(bridge, self.inner.bridge.as_ref()) || bridge.edits.required_notes_window(window)? != args.window_generation {
            return Err(wire::private_error());
        }
        self.expire(state, Instant::now()); passive_document_gate(state)?;
        self.common_gate(state, false).map_err(|_| wire::private_error())?;
        if self.live_session_owner_reason().is_some() || !bridge.edits.can_exit() || state.github.native_work_pending() { return Err(wire::private_error()); }
        let selected = bridge.native_project(&args.project_id);
        let (generation, root) = self.registry_result(state, selected, None).map_err(|_| wire::private_error())?;
        Ok(crate::edit_owner::RegisteredEditRoot { generation, root })
    }
    pub(crate) fn required_notes_observe_start(&self, bridge: &DesktopBridge, window: &str, args: &input::Observe)
        -> Result<(crate::edit_owner::RegisteredEditRoot, crate::supervisor::PassiveQuery), BridgeError> {
        let mut state = self.lock(); let registered = self.required_notes_read_root(&mut state, bridge, window, args)?;
        let query = bridge.supervisor.start_passive(Method::RequiredNotesObserve, serde_json::json!({"root": &registered.root.path, "context":&args.context}))?;
        Ok((registered, query))
    }
    pub(crate) fn required_notes_observe_recheck(&self, bridge: &DesktopBridge, window: &str, args: &input::Observe,
        original: &crate::edit_owner::RegisteredEditRoot) -> Result<(), BridgeError> {
        let mut state = self.lock();
        if self.required_notes_read_root(&mut state, bridge, window, args)? != *original { return Err(wire::private_error()); }
        Ok(())
    }
    pub(crate) fn required_notes_import_available(&self) -> bool {
        NATIVE_REQUIRED_NOTES_IMPORT_QUALIFIED && cfg!(all(feature = "desktop-shell", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))
            && self.inner.bridge.supervisor.passive_method_available("required.notes.observe")
            && self.inner.bridge.supervisor.passive_method_available("required.notes.validate")
    }
    pub(crate) fn required_notes_edit_admit<T>(&self,
        project: impl FnOnce(&DesktopBridge) -> Result<String, BridgeError>,
        enqueue: impl FnOnce(&DesktopBridge, crate::edit_owner::RegisteredEditRoot) -> Result<T, BridgeError>) -> Result<T, BridgeError> {
        self.registered_edit_admit(crate::edit_protocol::EditDomain::RequiredNotes, project, enqueue)
    }
    pub(crate) fn required_notes_import_status(&self, window: &str, generation: &str, request: u32) -> Result<wire::ImportStatusEnvelope, BridgeError> {
        if self.inner.bridge.edits.required_notes_window(window)? != generation { return Err(wire::private_error()); }
        self.reconcile(); let mut state = self.lock(); refresh(&mut state);
        let reply = wire::ImportStatusEnvelope { request_id: request, status: state.required_notes.row(generation, request).cloned() };
        crate::edit_protocol::bounded(&reply, wire::STATUS_LIMIT)?; Ok(reply)
    }
    pub(crate) fn required_notes_import_latest(&self) -> Result<Option<wire::ImportStatusEnvelope>, BridgeError> {
        self.reconcile(); let mut state = self.lock(); refresh(&mut state);
        let row = state.required_notes.active.as_ref().or(state.required_notes.last.as_ref());
        let result = row.map(|row| wire::ImportStatusEnvelope { request_id: row.request_id, status: Some(row.clone()) });
        crate::edit_protocol::bounded(&result, wire::STATUS_LIMIT)?; Ok(result)
    }
    fn required_notes_failed(&self, owner: &Arc<OriginalWork>, why: Reason, public: Option<wire::ImportReason>) -> Staged {
        images::source_failure(owner, why);
        let mut state = self.lock();
        if state.slot.as_ref().is_some_and(|s| s.operation.required_notes() && Arc::ptr_eq(&s.owner, owner)) {
            images::observe_failure(&mut state);
            let request = state.slot.as_ref().filter(|s| s.reason == why).and_then(|s| s.required_notes.as_ref()).map(|b| b.request);
            if let (Some(request), Some(public)) = (request, public) {
                state.required_notes.refusal_hint.get_or_insert((request, public));
            }
            self.bump(&mut state);
        }
        Staged::Refused(why)
    }
    #[cfg(feature = "desktop-shell")]
    pub(crate) fn choose_required_note(&self, app: tauri::AppHandle, window: &str, args: input::Import) -> Result<Arc<OriginalWork>, BridgeError> {
        if self.inner.bridge.edits.required_notes_window(window)? != args.window_generation { return Err(wire::private_error()); }
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now());
        self.common_gate(&state, false).map_err(|_| wire::private_error())?;
        idle(&state).map_err(|_| wire::private_error())?;
        if !self.required_notes_import_available() || !self.inner.bridge.supervisor.can_exit() || !self.inner.bridge.edits.can_exit()
            || state.github.native_work_pending() || self.live_session_owner_reason().is_some()
            || state.required_notes.active.is_some() || state.required_notes.sequence.is_some_and(|old| args.request_id <= old)
            || images::persistent_bytes(&state).ok().and_then(|used| used.checked_add(CONTROL_RESERVE)).is_none_or(|used| used > SESSION_BYTES) {
            return Err(wire::private_error());
        }
        let selected = self.inner.bridge.native_project(&args.project_id);
        let (generation, root) = self.registry_result(&mut state, selected, None).map_err(|_| wire::private_error())?;
        let binding = Arc::new(Binding { request: args.request_id, project: args.project_id, window: args.window_generation, context: args.context, root, generation });
        let id = self.next_operation(&mut state).map_err(|_| wire::private_error())?;
        if id == u32::MAX { return Err(wire::private_error()); }
        let owner = OriginalWork::new(id, true, Arc::downgrade(&self.inner));
        let mut slot = Slot::new(owner.clone(), Operation::ChooseRequiredNote, None, None, Some(Instant::now() + REVIEW));
        slot.required_notes = Some(binding.clone());
        let installed = self.install(&mut state, slot, Job::RequiredNote { app, binding: binding.clone() });
        if state.slot.as_ref().is_some_and(|s| Arc::ptr_eq(&s.owner, &owner)) {
            state.required_notes.sequence = Some(binding.request); state.required_notes.active = Some(binding.initial());
            state.required_notes.refusal_hint = None; self.bump(&mut state);
        }
        let start = installed.map_err(|_| wire::private_error())?;
        drop(state);
        if start.send(()).is_err() { self.required_notes_failed(&owner, Reason::CleanupUnknown, None); }
        Ok(owner)
    }
    #[cfg(feature = "desktop-shell")]
    fn required_notes_query(&self, owner: &Arc<OriginalWork>, binding: &Arc<Binding>, text: Option<&str>) -> Result<crate::supervisor::PassiveQuery, Reason> {
        let mut state = self.lock(); original_live(self, &mut state, owner, binding)?;
        if !self.required_notes_import_available() { return Err(Reason::Unqualified); }
        if text.is_some() && (!owner.gui.settled()
            || !owner.child.try_lock().is_ok_and(|book| book.receipt == JoinReceipt::Returned && book.handle.is_none())
            || !owner.source.try_lock().is_ok_and(|book| !book.not_started() && book.settled())) { return Err(Reason::CleanupUnknown); }
        let (method, params) = if let Some(text) = text {
            (Method::RequiredNotesValidate, serde_json::json!({"context": &binding.context, "text":text}))
        } else { (Method::RequiredNotesObserve, serde_json::json!({"root": &binding.root.path, "context": &binding.context})) };
        let end = owner.endpoint().ok_or(Reason::Deadline)?;
        self.inner.bridge.supervisor.start_required_notes_passive_until(method, params, end).map_err(query_reason)
    }
    #[cfg(feature = "desktop-shell")]
    pub(crate) async fn required_note_result(&self, owner: Arc<OriginalWork>) -> Result<wire::ImportEnvelope, BridgeError> {
        // Same observer-only routing as project_path_result. A lost observer
        // cannot remove original work; the existing absolute review deadline
        // retires an unconsumed private result through its original book.
        loop {
            self.reconcile();
            {
                let mut state = self.lock(); refresh(&mut state);
                let binding = state.slot.as_ref().filter(|s| s.operation.required_notes() && Arc::ptr_eq(&s.owner, &owner))
                    .and_then(|s| s.required_notes.clone()).ok_or_else(wire::private_error)?;
                let row = state.required_notes.row(&binding.window, binding.request).cloned().ok_or_else(wire::private_error)?;
                if row.phase == wire::ImportPhase::Unknown { return Ok(wire::ImportEnvelope { request_id: binding.request, result: None, status: row }); }
                if row.phase == wire::ImportPhase::Settled {
                    let result = if row.outcome == Some(wire::ImportOutcome::Cancelled) { Some(wire::Imported::cancelled()) } else { None };
                    return Ok(wire::ImportEnvelope { request_id: binding.request, result, status: row });
                }
                let ready = state.slot.as_ref().is_some_and(|s| same(s, &owner, &binding) && s.phase == Phase::Selected && s.reason == Reason::None
                    && s.cleanup_end.is_none() && s.note_content.is_some() && owner.project_path_settled(true));
                if ready {
                    if let Err(why) = original_live(self, &mut state, &owner, &binding) {
                        if let Some(s) = state.slot.as_mut() { s.stop(why, Instant::now()); }
                        self.bump(&mut state);
                    } else {
                        // Refuse revision exhaustion while private DATA is
                        // still owned by the original slot, before publication.
                        if status_successor(state.revision).is_none() || state.evidence.revision.checked_add(1).is_none() {
                            self.exhaust(&mut state, UnknownOrigin::Exhausted); continue;
                        }
                        let slot = state.slot.as_mut().ok_or_else(wire::private_error)?;
                        let content = slot.note_content.take().ok_or_else(wire::private_error)?;
                        match content.selected(binding.kind()) {
                            Err(content) => {
                                // No Selected latch precedes this final private
                                // DTO check. Keep a refusal in original custody.
                                slot.note_content = Some(content); slot.stop(Reason::UnsupportedFormat, Instant::now());
                                if slot.reason == Reason::UnsupportedFormat {
                                    state.required_notes.refusal_hint.get_or_insert((binding.request, wire::ImportReason::InvalidText));
                                }
                                self.bump(&mut state);
                            },
                            Ok(result) => {
                                // DTO validation may cross review expiry while
                                // this mutex prevents ordinary expiry polling.
                                // Check original custody first, then freshly
                                // sample the SAME work/review clock and STOP at
                                // this publication boundary, before Selected.
                                let custody = same(slot, &owner, &binding) && slot.phase == Phase::Selected
                                    && slot.cleanup_end.is_none() && slot.reason == Reason::None && owner.project_path_settled(true);
                                let work = owner.endpoint(); let now = Instant::now();
                                let refusal = publication_expired(slot, work, now).or_else(|| {
                                    if owner.stopped() { Some((if slot.reason == Reason::None { Reason::UserCancelled } else { slot.reason }, now)) }
                                    else if !custody { Some((Reason::CleanupUnknown, now)) } else { None }
                                });
                                if let Some((why, at)) = refusal {
                                    refuse_private_selection(slot, result, why, at); self.bump(&mut state); continue;
                                }
                                slot.phase = Phase::Idle; slot.review_end = None;
                                let mut row = binding.initial(); row.phase = wire::ImportPhase::Settled; row.outcome = Some(wire::ImportOutcome::Selected);
                                state.required_notes.active = None; state.required_notes.last = Some(row); self.bump(&mut state);
                                let row = state.required_notes.row(&binding.window, binding.request).cloned().ok_or_else(wire::private_error)?;
                                if row.phase != wire::ImportPhase::Settled || row.outcome != Some(wire::ImportOutcome::Selected) {
                                    // A status-revision exhaustion can revoke the
                                    // publication in bump. Restore private DATA
                                    // for the same original retirement, not drop
                                    // it under the document mutex or return it.
                                    if let wire::Imported::Selected { text, validation, .. } = result {
                                        if let Some(slot) = state.slot.as_mut() { slot.note_content = Some(Content { text, validation: Some(validation) }); }
                                    }
                                    return Ok(wire::ImportEnvelope { request_id: binding.request, result: None, status: row });
                                }
                                drop(state);
                                return Ok(wire::ImportEnvelope { request_id: binding.request, result: Some(result), status: row });
                            },
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
#[cfg(feature = "desktop-shell")]
pub(super) async fn run(document: &DocumentBinding, owner: &Arc<OriginalWork>, app: tauri::AppHandle, binding: Arc<Binding>) -> Staged {
    let first = match document.required_notes_query(owner, &binding, None) {
        Ok(query) => query.wait_required_notes(owner).await.map_err(query_reason)
            .and_then(|value| wire::observation_result(value, &binding.context).map_err(query_reason)), Err(why) => Err(why),
    };
    let first = match first {
        Ok(value) => (value.selection, value.baseline),
        Err(why) => { owner.gui.not_created(why); return document.required_notes_failed(owner, why, None); },
    };
    let path = match crate::shell::run_owned_dialog(&app, owner, crate::shell::DialogChoice::RequiredNoteText, None).await {
        Ok(Some(path)) => path, Ok(None) => return document.required_notes_failed(owner, Reason::UserCancelled, None),
        Err(why) => return document.required_notes_failed(owner, why, None),
    };
    if let Err(why) = document.phase(owner, Phase::Capturing) { return document.required_notes_failed(owner, why, None); }
    let text = match child(owner, ChildJob::RequiredNote { path, binding: binding.clone() }).await {
        Ok(ChildEnd::RequiredNote(text)) => text,
        Ok(ChildEnd::Refused(why)) | Err(why) => return document.required_notes_failed(owner, why, None),
        _ => return document.required_notes_failed(owner, Reason::CleanupUnknown, None),
    };
    let validation = match document.required_notes_query(owner, &binding, Some(&text)) {
        Ok(query) => query.wait_required_notes(owner).await.map_err(query_reason)
            .and_then(|value| wire::validation_result(value, &binding.context, &text).map_err(query_reason)), Err(why) => Err(why),
    };
    let validation = match validation {
        Ok(value) if value.valid => value,
        Ok(_) => return document.required_notes_failed(owner, Reason::UnsupportedFormat, Some(wire::ImportReason::InvalidText)),
        Err(why) => return document.required_notes_failed(owner, why, None),
    };
    let final_selection = match document.required_notes_query(owner, &binding, None) {
        Ok(query) => query.wait_required_notes(owner).await.map_err(query_reason)
            .and_then(|value| wire::observation_result(value, &binding.context).map_err(query_reason)), Err(why) => Err(why),
    };
    match final_selection {
        Ok(value) if value.selection == first.0 && value.baseline == first.1 => {
            // No pathname or original-file copy is retained after SourceBook
            // cleanup. The SAME coordinator must still stage and actually join.
            Staged::RequiredNote { content: Content { text, validation: Some(validation) }, binding }
        },
        Ok(_) => document.required_notes_failed(owner, Reason::ContextStale, None),
        Err(why) => document.required_notes_failed(owner, why, None),
    }
}

#[cfg(test)]
mod tests {
    // Inert original books only. A phase/body-end flag never manufactures
    // native finality, and this fixture never returns a successful import.
    use super::*;
    fn model() -> (DocumentState, Arc<Binding>, Arc<OriginalWork>) {
        let mut state=super::super::tests::empty_state();
        state.lifetime.crash_hook_installed(); state.lifetime.started(true); state.lifetime.finished(true);
        let binding=Arc::new(Binding {request:7,project:"project-1".into(),window:wire::tests::WINDOW.into(),
            context:wire::Context::IosAppReview {},generation:1,
            root:asset_source::RegisteredRoot {path:"/inert/project".into(),
                identity:asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::synthetic_evidence_identity())}});
        let owner=OriginalWork::new(1,true,Weak::new());
        let mut slot=Slot::new(owner.clone(),Operation::ChooseRequiredNote,None,None,None);
        slot.required_notes=Some(binding.clone()); state.slot=Some(slot);
        state.required_notes.active=Some(binding.initial()); state.required_notes.sequence=Some(binding.request);
        (state,binding,owner)
    }
    #[test]
    fn imported_phase_or_body_end_cannot_forge_source_join_or_private_finality() {
        let (mut state,binding,owner)=model();
        assert!(Operation::ChooseRequiredNote.blocks_context() && !Operation::ChooseRequiredNote.evidence());
        assert!(pending(&state) && idle(&state).is_err() && passive_document_gate(&state).is_err());
        assert_eq!(credential_lock_gate(&state).err().map(|e|e.reason),Some(Reason::Busy));
        owner.ended.store(true,Ordering::SeqCst);
        for phase in [Phase::Selected,Phase::Idle,Phase::Stopping] {
            let slot=state.slot.as_mut().unwrap(); slot.phase=phase; slot.settlement=Settlement::Known;
            slot.note_content=Some(Content {text:"PRIVATE_IMPORT_SENTINEL".into(),validation:None});
            refresh(&mut state);
            let row=state.required_notes.row(&binding.window,binding.request).unwrap();
            assert!(row.phase==wire::ImportPhase::Pending && row.outcome.is_none());
            assert!(!owner.resources_settled() && !owner.project_path_settled(true) && pending(&state));
            let encoded=serde_json::to_string(row).unwrap();
            for private in ["PRIVATE_IMPORT_SENTINEL","/inert/project","validation","sha256","byteLength"] {assert!(!encoded.contains(private));}
        }
        state.exhausted=true; refresh(&mut state);
        let row=state.required_notes.row(&binding.window,binding.request).unwrap();
        assert!(row.phase==wire::ImportPhase::Unknown && row.outcome.is_none() && row.reason==wire::ImportReason::CleanupUnknown);
        assert!(state.slot.as_ref().unwrap().note_content.is_some()); // retained for original retirement
    }
    #[test]
    fn identical_renderer_data_cannot_replace_original_binding_and_owner() {
        let (state,binding,owner)=model(); let (_,other_binding,other_owner)=model(); let slot=state.slot.as_ref().unwrap();
        assert!(same(slot,&owner,&binding));
        assert!(!same(slot,&owner,&other_binding) && !same(slot,&other_owner,&binding));
        assert!(state.required_notes.row(&binding.window,binding.request+1).is_none());
        assert!(state.required_notes.row(wire::tests::SESSION,binding.request).is_none());
        assert!(!owner.stopped() && !other_owner.stopped());
    }
    #[test]
    fn final_private_dto_refusal_returns_text_for_original_retirement_not_selected_status() {
        let context=wire::Context::IosAppReview {}; let text="PRIVATE_IMPORT_SENTINEL".to_owned();
        let missing=Content {text:text.clone(),validation:None}.selected(context.kind()).err().unwrap();
        assert_eq!(missing.text,text); assert!(missing.retained_bytes().unwrap()>=text.len());
        let mut value=wire::tests::validation_value(&context,&text); value["rawByteCount"]=serde_json::json!(0);
        let validation:wire::Validation=serde_json::from_value(value).unwrap();
        let refused=Content {text:text.clone(),validation:Some(validation)}.selected(context.kind()).err().unwrap();
        assert_eq!(refused.text,text); assert!(refused.validation.is_some());
    }
    #[test]
    fn joined_work_endpoint_none_cannot_outlive_original_review_during_private_dto() {
        let (mut state,binding,owner)=model(); let before=Instant::now(); let review=before+Duration::from_secs(1);
        // Inert joined-book DATA, not an executed coordinator/native receipt.
        owner.coordinator.lock().unwrap().receipt=JoinReceipt::Returned;
        owner.ended.store(true,Ordering::SeqCst); owner.set_endpoint(None);
        let slot=state.slot.as_mut().unwrap(); slot.review_end=Some(review); slot.phase=Phase::Selected;
        assert!(!owner.interrupted() && publication_expired(slot,owner.endpoint(),before).is_none());
        let text="PRIVATE_IMPORT_SENTINEL\r\n".to_owned(); let allocation=text.as_ptr();
        let value=wire::tests::validation_value(&binding.context,&text);
        let content=Content {text,validation:Some(serde_json::from_value(value).unwrap())};
        let result=content.selected(binding.kind()).ok().unwrap();
        // Model preemption/validation crossing the absolute review boundary;
        // no real sleep, new clock, native operation or success is fabricated.
        assert_eq!(publication_expired(slot,owner.endpoint(),review),Some((Reason::ReviewExpired,review)));
        let (why,at)=publication_expired(slot,owner.endpoint(),review+Duration::from_nanos(1)).unwrap();
        assert_eq!(why,Reason::ReviewExpired); assert_eq!(at,review);
        refuse_private_selection(slot,result,why,at);
        assert!(owner.stopped() && slot.phase==Phase::Stopping && slot.discard);
        assert_eq!(slot.review_end,Some(review)); assert_eq!(slot.cleanup_end,Some(review+CLEANUP));
        assert_eq!(*owner.cleanup_end.lock().unwrap(),Some(review+CLEANUP));
        let retained=slot.note_content.as_ref().unwrap();
        assert_eq!(retained.text.as_ptr(),allocation); assert!(retained.validation.is_some());
        refresh(&mut state);
        let row=state.required_notes.row(&binding.window,binding.request).unwrap();
        assert!(row.phase==wire::ImportPhase::Pending && row.outcome.is_none() && row.reason==wire::ImportReason::None);
        assert!(!owner.project_path_settled(true));
    }
    #[test]
    fn emit_required_notes_frontend_contract_roster() {
        // Actual production serialization/projection over inert book models.
        // The separately selected frontend consumer must accept this exact
        // emitted roster. This is transport evidence, never native finality.
        let mut capabilities=Vec::new();
        for (available,reason) in [(true,wire::AvailabilityReason::None),
            (false,wire::AvailabilityReason::UnsupportedPlatform),(false,wire::AvailabilityReason::RuntimeUnavailable),
            (false,wire::AvailabilityReason::NotQualified),(false,wire::AvailabilityReason::DocumentUnavailable)] {
            capabilities.push(wire::Capabilities {schema_version:1,window_generation:wire::tests::WINDOW.into(),
                read:wire::Availability {available,reason},edit:wire::Availability {available,reason},import:wire::Availability {available,reason}});
        }
        let mut imports=Vec::new();
        let row=|state:&DocumentState,binding:&Binding| state.required_notes.row(&binding.window,binding.request).unwrap().clone();
        let (mut state,binding,owner)=model();
        state.required_notes.refusal_hint=Some((binding.request,wire::ImportReason::InvalidText));
        state.slot.as_mut().unwrap().stop(Reason::UnsupportedFormat,Instant::now());
        refresh(&mut state); imports.push(serde_json::json!({"case":"pending-invalid-text","status":row(&state,&binding)}));
        for (case,reason,hint) in [("invalid-file",Reason::UnsupportedFormat,None),("changed-file",Reason::SourceChanged,None),
            ("invalid-text",Reason::UnsupportedFormat,Some(wire::ImportReason::InvalidText)),("unavailable",Reason::Unqualified,None),
            ("early-stop",Reason::UserCancelled,None),("context-changed",Reason::ContextStale,None)] {
            let (mut state,binding,owner)=model();
            state.required_notes.refusal_hint=hint.map(|hint|(binding.request,hint));
            // Original-not-created is sufficient for refusal settlement only.
            owner.gui.not_created(reason); owner.coordinator.lock().unwrap().receipt=JoinReceipt::Returned; owner.stop();
            let slot=state.slot.as_mut().unwrap(); slot.phase=Phase::Idle; slot.reason=reason; slot.settlement=Settlement::Known;
            refresh(&mut state); imports.push(serde_json::json!({"case":case,"status":row(&state,&binding)}));
        }
        let gui=|declined: bool| GuiFacts {dispatched:true,constructing:false,created:true,showing:false,response:true,
            accepted:!declined,declined,accepted_at:if declined {None}else{Some(Instant::now())},destroyed:true,released:true,
            not_created:false,close_queued:true,close_ack:true,release_queued:true,selected:None,refusal:None};
        for (case,declined) in [("late-stop",false),("native-cancel-model",true)] {
            let (mut state,binding,owner)=model(); *owner.gui.facts().unwrap()=gui(declined);
            owner.coordinator.lock().unwrap().receipt=JoinReceipt::Returned; owner.stop();
            let slot=state.slot.as_mut().unwrap(); slot.phase=Phase::Idle; slot.reason=Reason::UserCancelled; slot.settlement=Settlement::Known;
            refresh(&mut state); imports.push(serde_json::json!({"case":case,"status":row(&state,&binding)}));
        }
        state.unknown=true; refresh(&mut state);
        imports.push(serde_json::json!({"case":"unknown","status":row(&state,&binding)}));
        let mut selected=binding.initial(); selected.phase=wire::ImportPhase::Settled; selected.outcome=Some(wire::ImportOutcome::Selected);
        imports.push(serde_json::json!({"case":"selected-dto-only","status":selected}));
        assert!(!owner.project_path_settled(true));
        let roster=serde_json::json!({"schemaVersion":1,"capabilities":capabilities,"imports":imports});
        println!("MRK_REQUIRED_NOTES_CONTRACT_V1 {}",serde_json::to_string(&roster).unwrap());
    }
}
