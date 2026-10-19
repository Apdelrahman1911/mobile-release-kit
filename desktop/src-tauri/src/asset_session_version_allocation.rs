//! Saved-source read on the SAME Document/SavedObservation/Edit owners. No
//! renderer snapshot, service grant, allocation consent or new owner registry.
//! The sole completion is returned by the actual Supervisor retirement.
use super::*;
use crate::supervisor::{
    VersionAllocationSource, VersionAllocationSourceAdmission, VersionAllocationSourceInput,
    VersionAllocationSourceReceipt, VersionAllocationSourceRequest, VersionAllocationSourceTicket,
};
use std::sync::atomic::AtomicU8;

const RESERVED: u8 = 0;
const ARMED: u8 = 1;
const COMPLETING: u8 = 2;
const RETURNED: u8 = 3;
const UNKNOWN: u8 = 4;

pub(super) struct Lane {
    saved: Arc<SavedObservationLane>,
    input: Arc<VersionAllocationSourceInput>,
    stage: AtomicU8,
    completion_returned: AtomicBool,
    request: Mutex<Option<(String, Arc<VersionAllocationSourceRequest>)>>,
    ticket: Mutex<Option<VersionAllocationSourceTicket>>,
    result: Mutex<Option<VersionAllocationSourceReceipt>>,
    reservation_bytes: usize,
}
impl Lane {
    fn returned(&self) -> bool {
        self.stage.load(Ordering::SeqCst) == RETURNED
            && self.completion_returned.load(Ordering::SeqCst)
            && lock(&self.result).is_some()
            && lock(&self.ticket).is_none()
    }
    fn retained_bytes(&self) -> Option<usize> {
        // The whole original fixed reservation stays charged while this ticket
        // is retained, even if its public result is much smaller. No shrinking
        // clone or early FIN releases native/code backing for another owner.
        let original = if lock(&self.ticket).is_some() {
            self.reservation_bytes
        } else if self.returned() {
            self.input.retained_bytes()?.checked_add(4096)?
        } else {
            return None;
        };
        original
            .checked_add(std::mem::size_of::<Self>())?
            .checked_add(std::mem::size_of::<SavedObservationLane>())?
            .checked_add(self.saved.retained_heap_bytes()?)
    }
    fn fail_unknown(&self, document: &DocumentBinding) {
        self.stage.store(UNKNOWN, Ordering::SeqCst);
        // Do not call ControlSlot.poisoned here: its read-host retirement may
        // perform IO, and some callers still hold Doc. This original lane
        // remains an absorbing busy/exit fence; no new control owner is minted.
        document.inner.changes.send_modify(|_| {});
    }
}
pub(super) fn pending(state: &DocumentState) -> bool {
    state.version_allocation_source.as_ref().is_some_and(|lane| !lane.returned())
}
pub(super) fn retained_bytes(state: &DocumentState) -> Option<usize> {
    match &state.version_allocation_source {
        Some(lane) => lane.retained_bytes(),
        None => Some(0),
    }
}
pub(super) fn stop(state: &DocumentState) {
    if let Some(lane) = &state.version_allocation_source {
        // This is STOP on the same actual ticket; no fabricated terminal or
        // lane removal. Unknown/late result keeps ordinary operations blocked.
        if let Some(ticket) = lock(&lane.ticket).as_ref() {
            ticket.stop();
        }
    }
}

/// Weak links avoid a Document -> ticket -> gate -> Document cycle. The
/// original completion independently retains that same Document until its
/// actual return; loss/unknown never substitutes a new gate or completion.
pub(crate) struct VersionAllocationSourceGoGate {
    document: Weak<Inner>,
    lane: Weak<Lane>,
}
impl VersionAllocationSourceGoGate {
    fn original(&self, input: &Arc<VersionAllocationSourceInput>) -> Result<(DocumentBinding, Arc<Lane>), BridgeError> {
        let document = DocumentBinding { inner: self.document.upgrade().ok_or_else(changed)? };
        let lane = self.lane.upgrade().ok_or_else(changed)?;
        if !Arc::ptr_eq(&lane.input, input) || lane.stage.load(Ordering::SeqCst) != ARMED {
            return Err(changed());
        }
        Ok((document, lane))
    }
    pub(crate) fn current_control(&self, input: &Arc<VersionAllocationSourceInput>) -> bool {
        self.original(input).is_ok_and(|(document, lane)| lane.saved.current_version_source(&document.inner, input))
    }
    pub(crate) fn check_current(&self, input: &Arc<VersionAllocationSourceInput>) -> Result<(), BridgeError> {
        let (document, lane) = self.original(input)?;
        let state = document.lock();
        document.version_source_current(&state, &lane)
    }
    pub(crate) fn bind_request(
        &self,
        input: &Arc<VersionAllocationSourceInput>,
        id: &str,
        request: Arc<VersionAllocationSourceRequest>,
    ) -> Result<(), BridgeError> {
        let (document, lane) = self.original(input)?;
        let state = document.lock();
        document.version_source_current(&state, &lane)?;
        if !request.same_input(input) || !crate::protocol::valid_id(id) {
            return Err(changed());
        }
        let mut slot = lane.request.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if slot.is_some() {
            return Err(BridgeError::cleanup_unknown());
        }
        *slot = Some((id.to_owned(), request));
        Ok(())
    }
    pub(crate) fn claim(
        &self,
        input: &Arc<VersionAllocationSourceInput>,
        id: &str,
        request: &Arc<VersionAllocationSourceRequest>,
        claim_original: impl FnOnce() -> bool,
    ) -> Result<Vec<u8>, BridgeError> {
        let (document, lane) = self.original(input)?;
        let state = document.lock();
        // All checks are pure/short. NO Supervisor.can_exit/native_work_pending,
        // Host/state IO or census recursion while its driver awaits this writer.
        // Only this exact retained source lane is exempt from the busy gate.
        let edit = document.inner.bridge.edits.saved_registration_guard(&document.inner.session_identity)?;
        document.version_source_current_with_edit(&state, &lane, &edit)?;
        let original = lane.request.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if !original.as_ref().is_some_and(|(original_id, original)| original_id == id && Arc::ptr_eq(original, request))
            || !request.same_input(input)
        {
            return Err(changed());
        }
        let go = request.go()?;
        if !claim_original() {
            return Err(changed());
        }
        Ok(go)
    }
}

pub(crate) struct VersionAllocationSourceCompletion {
    document: DocumentBinding,
    lane: Arc<Lane>,
}
impl VersionAllocationSourceCompletion {
    pub(crate) fn arm(&self) -> Result<(), BridgeError> {
        self.lane
            .stage
            .compare_exchange(RESERVED, ARMED, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| ())
            .map_err(|_| BridgeError::cleanup_unknown())
    }
    pub(crate) fn unknown(&self) {
        self.lane.fail_unknown(&self.document);
    }
    pub(crate) fn complete(
        &mut self,
        source: Option<&VersionAllocationSource>,
        unknown: bool,
    ) -> Result<(), BridgeError> {
        if unknown || self.lane.stage.compare_exchange(ARMED, COMPLETING, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            self.unknown();
            return Err(BridgeError::cleanup_unknown());
        }
        let state = self.document.lock();
        if !state.version_allocation_source.as_ref().is_some_and(|current| Arc::ptr_eq(current, &self.lane)) {
            self.unknown();
            return Err(BridgeError::cleanup_unknown());
        }
        // A known pre-GO or source refusal still completes its actual native
        // lane, but cannot install source DATA or a new saved-input binding.
        if source.is_some() {
            self.document.version_source_current(&state, &self.lane)?;
        }
        Ok(())
    }
    pub(crate) fn returned(&mut self) {
        self.lane.completion_returned.store(true, Ordering::SeqCst);
        let _ = self.lane.stage.compare_exchange(COMPLETING, RETURNED, Ordering::SeqCst, Ordering::SeqCst);
        self.document.inner.changes.send_modify(|_| {});
    }
}
impl Drop for VersionAllocationSourceCompletion {
    fn drop(&mut self) {
        if !matches!(self.lane.stage.load(Ordering::SeqCst), RESERVED | RETURNED) {
            self.unknown();
        }
    }
}

fn changed() -> BridgeError {
    BridgeError::new(
        "version_source_changed",
        "Read the saved configuration and version again after the original change settles.",
    )
}
fn busy() -> BridgeError {
    BridgeError::new("busy", "Finish or stop the original saved-source inspection first.")
}

impl DocumentBinding {
    fn version_source_current(&self, state: &DocumentState, lane: &Arc<Lane>) -> Result<(), BridgeError> {
        let edit = self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
        self.version_source_current_with_edit(state, lane, &edit)
    }
    fn version_source_current_with_edit(
        &self,
        state: &DocumentState,
        lane: &Arc<Lane>,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
    ) -> Result<(), BridgeError> {
        // Source-aware peers use passive_document_gate, while this exact owner
        // uses its existing pure base. It does not visit Resources or services.
        passive_document_state_gate(state)?;
        if state.maintenance.closed()
            || !state.lifetime.original_bound()
            || state.lost_observed
            || !state.version_allocation_source.as_ref().is_some_and(|current| Arc::ptr_eq(current, lane))
            || !matches!(lane.stage.load(Ordering::SeqCst), ARMED | COMPLETING | RETURNED)
            || !lane.saved.current_version_source(&self.inner, &lane.input)
        {
            return Err(changed());
        }
        let input = state.saved_input.as_ref().ok_or_else(changed)?;
        if !input.matches_version_source(&self.inner, &lane.saved, &lane.input, edit) {
            return Err(changed());
        }
        Ok(())
    }
    /// Native admission only. The root, saved hashes/path, account/provider
    /// projection and private filesystem data are never renderer arguments.
    /// This action does not select/mint a candidate or reserve/change a version.
    fn start_version_allocation_source(&self, project_id: &str, reference: &str) -> Result<Arc<Lane>, BridgeError> {
        let started = Instant::now();
        if !crate::protocol::valid_id(project_id) || !crate::supervisor::version_allocation_source_branch(reference) {
            return Err(BridgeError::invalid());
        }
        let mut state = self.lock();
        if pending(&state) {
            return Err(busy());
        }
        self.saved_observation_gate(&state, None)?;
        if !self.inner.android_registration_control.idle_for_saved_observation()
            || !self.inner.bridge.supervisor.version_allocation_source_available()
        {
            return Err(changed());
        }
        // Retire a genuinely returned SOURCE ticket before a second code
        // reservation. No pending/unknown ticket is dropped for memory credit.
        if let Some(previous) = &state.version_allocation_source {
            if !previous.returned() {
                return Err(busy());
            }
        }
        state.version_allocation_source = None;
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        {
            // Actual same-Document census before EditGuard (its traversal can
            // consult the original Edit registry). Code remains its existing
            // separate128MiB partition; source/control use the unchanged16MiB.
            let document = lookup_memory::retained_document_bytes(&self.inner, &state)
                .map_err(|_| busy())?
                .checked_add(installation_memory::additional_document_bytes(self, &state).map_err(|_| busy())?)
                .ok_or_else(busy)?;
            let edit = self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
            let (saved, input) = state.saved_input.as_ref().ok_or_else(changed)?.version_source_input(
                &self.inner,
                project_id,
                reference,
                &edit,
            )?;
            let quote = VersionAllocationSourceAdmission::reservation_bytes()
                .and_then(|v| v.checked_add(input.retained_bytes()?))
                .and_then(|v| {
                    v.checked_add(
                        std::mem::size_of::<Lane>() + std::mem::size_of::<VersionAllocationSourceCompletion>() + 256,
                    )
                })
                .ok_or_else(busy)?;
            crate::macos_history_inventory::admission_bytes(document, quote).ok_or_else(busy)?;
            let lane = Arc::new(Lane {
                saved,
                input: input.clone(),
                stage: AtomicU8::new(RESERVED),
                completion_returned: AtomicBool::new(false),
                request: Mutex::new(None),
                ticket: Mutex::new(None),
                result: Mutex::new(None),
                reservation_bytes: quote,
            });
            let gate =
                VersionAllocationSourceGoGate { document: Arc::downgrade(&self.inner), lane: Arc::downgrade(&lane) };
            let completion = VersionAllocationSourceCompletion { document: self.clone(), lane: lane.clone() };
            let admission = VersionAllocationSourceAdmission::reserve(input, gate, completion, started)?;
            if admission.bytes() > quote {
                return Err(busy());
            }
            state.version_allocation_source = Some(lane.clone());
            // Keep Doc/Edit and the installed pending lane through original
            // roster insertion; worker IO begins only through Supervisor latch.
            let result = self.inner.bridge.supervisor.start_version_allocation_source(admission);
            match result {
                Ok(ticket) => {
                    *lock(&lane.ticket) = Some(ticket);
                    drop(edit);
                    drop(state);
                    self.inner.changes.send_modify(|_| {});
                    Ok(lane)
                }
                Err(error) => {
                    if lane.stage.load(Ordering::SeqCst) == RESERVED {
                        state.version_allocation_source = None;
                    }
                    Err(error)
                }
            }
        }
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )))]
        {
            let _ = started;
            Err(BridgeError::unavailable("The installed saved-source profile is unavailable."))
        }
    }
    pub(crate) async fn observe_version_allocation_source(
        &self,
        project_id: &str,
        reference: &str,
    ) -> Result<VersionAllocationSource, BridgeError> {
        let lane = self.start_version_allocation_source(project_id, reference)?;
        let wait = lock(&lane.ticket).as_ref().ok_or_else(BridgeError::cleanup_unknown)?.wait_original();
        // No Document/Edit/native/state lock crosses this actual original
        // observer join. The lane retains the ticket and full code reservation.
        let mut result = wait.returned().await;
        let state = self.lock();
        if !state.version_allocation_source.as_ref().is_some_and(|current| Arc::ptr_eq(current, &lane)) {
            lane.fail_unknown(self);
            return Err(BridgeError::cleanup_unknown());
        }
        match &result {
            VersionAllocationSourceReceipt::Settled { was_unknown: false, outcome, .. } => {
                if outcome.is_ok() {
                    if let Err(error) = self.version_source_current(&state, &lane) {
                        if let VersionAllocationSourceReceipt::Settled { outcome, .. } = &mut result {
                            *outcome = Err(error);
                        }
                    }
                }
                // Only after the genuine final-observer join may the actual
                // ticket/code reservation retire to bounded comparison DATA.
                *lock(&lane.result) = Some(result.clone());
                lock(&lane.ticket).take();
                lock(&lane.request).take();
                drop(state);
                self.inner.changes.send_modify(|_| {});
                match result {
                    VersionAllocationSourceReceipt::Settled { outcome, .. } => outcome,
                    _ => unreachable!(),
                }
            }
            _ => {
                lane.fail_unknown(self);
                Err(BridgeError::cleanup_unknown())
            }
        }
    }
    /// Closed native observation, not a lease for a later allocation. Unknown
    /// keeps the original ticket and STOP available, even after context loss.
    pub(crate) fn version_allocation_source_status(&self) -> Option<VersionAllocationSourceReceipt> {
        let state = self.lock();
        let lane = state.version_allocation_source.as_ref()?;
        let receipt = lock(&lane.result)
            .clone()
            .or_else(|| lock(&lane.ticket).as_ref().map(VersionAllocationSourceTicket::receipt));
        if lane.stage.load(Ordering::SeqCst) == UNKNOWN {
            Some(VersionAllocationSourceReceipt::RetainedUnknown)
        } else {
            receipt
        }
    }
    pub(crate) fn stop_version_allocation_source(&self) {
        stop(&self.lock());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn invalid_or_unbound_source_read_has_no_native_operation() {
        // Real empty Document/Supervisor owners, never a constructed positive
        // root/stamp/FIN. Refusal precedes any source/native/profile inspection.
        let bridge = Arc::new(DesktopBridge::new(std::path::PathBuf::from("/never-opened-source-control-fixture")));
        let document = DocumentBinding::new(bridge.clone());
        assert_eq!(
            document.observe_version_allocation_source("project-1", "refs/tags/v1").await.unwrap_err().code,
            "invalid_request"
        );
        assert!(document.observe_version_allocation_source("project-1", "refs/heads/main").await.is_err());
        assert!(document.version_allocation_source_status().is_none());
        document.stop_version_allocation_source();
        assert!(document.version_allocation_source_status().is_none());
        assert!(bridge.supervisor.can_exit());
    }
}
