//! Saved-source read on the SAME Document/SavedObservation/Edit owners. No
//! renderer snapshot, service grant, allocation consent or new owner registry.
//! The sole completion is returned by the actual Supervisor retirement.
use super::*;
use crate::supervisor::{
    VersionAllocationSource, VersionAllocationSourceAdmission, VersionAllocationSourceInput,
    VersionAllocationSourceReceipt, VersionAllocationSourceRequest, VersionAllocationSourceTicket,
};
use std::sync::atomic::AtomicU8;

pub(super) const RESERVED: u8 = 0;
pub(super) const ARMED: u8 = 1;
pub(super) const COMPLETING: u8 = 2;
pub(super) const RETURNED: u8 = 3;
pub(super) const UNKNOWN: u8 = 4;

pub(super) fn source_quote(input_bytes:usize)->Option<usize>{
    VersionAllocationSourceAdmission::reservation_bytes()?.checked_add(input_bytes)?.checked_add(
        std::mem::size_of::<Lane>()+std::mem::size_of::<VersionAllocationSourceCompletion>()+256)
}


pub(super) fn lock<'a, T>(slot: &'a Mutex<T>, stage: &AtomicU8) -> std::sync::LockResult<MutexGuard<'a, T>> {
    let result = slot.lock();
    if result.is_err() {
        // Preserve the original slot and its poison. Only STOP/first ticket
        // installation may recover its guard; poison never grants retirement.
        stage.store(UNKNOWN, Ordering::SeqCst);
    }
    result
}

pub(super) struct Lane {
    pub(super) saved: Arc<SavedObservationLane>,
    pub(super) input: Arc<VersionAllocationSourceInput>,
    pub(super) stage: AtomicU8,
    pub(super) completion_returned: AtomicBool,
    pub(super) request: Mutex<Option<(String, Arc<VersionAllocationSourceRequest>)>>,
    pub(super) ticket: Mutex<Option<VersionAllocationSourceTicket>>,
    pub(super) result: Mutex<Option<VersionAllocationSourceReceipt>>,
    pub(super) reservation_bytes: usize,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) reserve: Option<Arc<version_reserve::Lane>>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) review: Option<Arc<version_reserve::agent::review::Link>>,
}
impl Lane {
    pub(super) fn returned(&self) -> bool {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(reserve)=&self.reserve {
            return self.stage.load(Ordering::SeqCst)!=UNKNOWN && reserve.returned()
                && lock(&self.ticket,&self.stage).is_ok_and(|ticket|ticket.is_none());
        }
        self.stage.load(Ordering::SeqCst) == RETURNED
            && self.completion_returned.load(Ordering::SeqCst)
            && lock(&self.result, &self.stage).is_ok_and(|result| result.is_some())
            && lock(&self.ticket, &self.stage).is_ok_and(|ticket| ticket.is_none())
    }
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        // The whole original fixed reservation stays charged while this ticket
        // is retained, even if its public result is much smaller. No shrinking
        // clone or early FIN releases native/code backing for another owner.
        let has_ticket = lock(&self.ticket, &self.stage).ok()?.is_some();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let reserve=self.reserve.as_ref();
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let reserving=false;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let reserving=reserve.is_some();
        let original = if has_ticket || reserving && !self.returned() {
            self.reservation_bytes
        } else if reserving {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            { self.input.retained_bytes()?.checked_add(reserve?.keep_bytes()?)? }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            { return None; }
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
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(reserve)=&self.reserve {reserve.unknown();}
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(link)=&self.review {link.entry.unknown();}
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
    #[cfg(any(target_os="linux",target_os="macos"))]
    version_reserve::agent::stop(state,Instant::now());
    if let Some(lane) = &state.version_allocation_source {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(reserve)=&lane.reserve {reserve.stop();}
        // This is STOP on the same actual ticket; no fabricated terminal or
        // lane removal. Unknown/late result keeps ordinary operations blocked.
        let ticket = lock(&lane.ticket, &lane.stage).unwrap_or_else(|poison| poison.into_inner());
        if let Some(ticket) = ticket.as_ref() {
            ticket.stop();
        }
    }
}

/// Weak links avoid a Document -> ticket -> gate -> Document cycle. The
/// original completion independently retains that same Document until its
/// actual return; loss/unknown never substitutes a new gate or completion.
pub(crate) struct VersionAllocationSourceGoGate {
    pub(super) document: Weak<Inner>,
    pub(super) lane: Weak<Lane>,
}
impl VersionAllocationSourceGoGate {
    #[cfg(any(target_os="linux",target_os="macos"))]
    pub(crate) fn review_stop(&self,now:Instant)->Option<Result<Option<Instant>,crate::service_protocol::Error>>{
        self.lane.upgrade()?.review.as_ref().map(|l|l.entry.stop_at(now).map(|v|v.map(|s|s.1)))
    }
    fn original(&self, input: &Arc<VersionAllocationSourceInput>) -> Result<(DocumentBinding, Arc<Lane>), BridgeError> {
        let document = DocumentBinding { inner: self.document.upgrade().ok_or_else(changed)? };
        let lane = self.lane.upgrade().ok_or_else(changed)?;
        if !Arc::ptr_eq(&lane.input, input) || lane.stage.load(Ordering::SeqCst) != ARMED {
            return Err(changed());
        }
        Ok((document, lane))
    }
    pub(crate) fn current_control(&self, input: &Arc<VersionAllocationSourceInput>) -> bool {
        self.original(input).is_ok_and(|(document, lane)| {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if lane.reserve.as_ref().is_some_and(|v|!v.current_control()) {return false;}
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if lane.review.as_ref().is_some_and(|v|!v.current(&lane)) {return false;}
            lane.saved.current_version_source(&document.inner, input)
        })
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
        let mut slot = lock(&lane.request, &lane.stage).map_err(|_| BridgeError::cleanup_unknown())?;
        if slot.is_some() {
            return Err(BridgeError::cleanup_unknown());
        }
        *slot = Some((id.to_owned(), request));
        Ok(())
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn claim_reserve(&self,input:&Arc<VersionAllocationSourceInput>,id:&str,
        request:&Arc<VersionAllocationSourceRequest>,claim:impl FnOnce()->bool)
        ->Result<zeroize::Zeroizing<Vec<u8>>,BridgeError> {
        let(document,lane)=self.original(input)?;
        let state=document.lock();
        let edit=document.inner.bridge.edits.saved_registration_guard(&document.inner.session_identity)?;
        document.version_source_current_with_edit(&state,&lane,&edit)?;
        {
            let original=lock(&lane.request,&lane.stage).map_err(|_|BridgeError::cleanup_unknown())?;
            if !original.as_ref().is_some_and(|(key,bound)|key==id&&Arc::ptr_eq(bound,request))
                ||!request.same_input(input) {return Err(changed());}
        }
        document.reserve_source_go(&state,&lane,request,claim)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn check_reserve(&self,input:&Arc<VersionAllocationSourceInput>,id:&str,
        request:&Arc<VersionAllocationSourceRequest>)->Result<(),BridgeError> {
        let(document,lane)=self.original(input)?;
        let state=document.lock();
        document.version_source_current(&state,&lane)?;
        let original=lock(&lane.request,&lane.stage).map_err(|_|BridgeError::cleanup_unknown())?;
        if lane.reserve.is_none()||!original.as_ref().is_some_and(|(key,bound)|key==id&&Arc::ptr_eq(bound,request))
            ||!request.same_input(input){return Err(changed());}Ok(())
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
        let original = lock(&lane.request, &lane.stage).map_err(|_| BridgeError::cleanup_unknown())?;
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
    pub(super) document: DocumentBinding,
    pub(super) lane: Arc<Lane>,
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
    pub(super) fn version_source_current(&self, state: &DocumentState, lane: &Arc<Lane>) -> Result<(), BridgeError> {
        let edit = self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
        self.version_source_current_with_edit(state, lane, &edit)
    }
    pub(super) fn version_source_current_with_edit(
        &self,
        state: &DocumentState,
        lane: &Arc<Lane>,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
    ) -> Result<(), BridgeError> {
        // Source-aware peers use passive_document_gate, while this exact owner
        // uses its existing pure base. It does not visit Resources or services.
        passive_document_state_gate(state)?;
        if version_enrollment::pending(state) { return Err(changed()); }
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
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            if lane.review.as_ref().is_some_and(|v|!v.current(lane)){return Err(changed())}
            self.reserve_source_current(state,lane,edit)?;
        }
        Ok(())
    }
    /// Native admission only. The root, saved hashes/path, account/provider
    /// projection and private filesystem data are never renderer arguments.
    /// This action does not select/mint a candidate or reserve/change a version.
    pub(super) fn start_version_allocation_source(&self, project_id: &str, reference: &str) -> Result<Arc<Lane>, BridgeError> {
        self.start_version_allocation_source_impl(project_id,reference,#[cfg(any(target_os="linux",target_os="macos"))] None)
    }
    #[cfg(any(target_os="linux",target_os="macos"))]
    pub(super) fn start_version_allocation_source_linked(&self,project_id:&str,reference:&str,review:Option<Arc<version_reserve::agent::review::Link>>)->Result<Arc<Lane>,BridgeError>{
        self.start_version_allocation_source_impl(project_id,reference,review)
    }
    fn start_version_allocation_source_impl(&self,project_id:&str,reference:&str,
        #[cfg(any(target_os="linux",target_os="macos"))] review:Option<Arc<version_reserve::agent::review::Link>>)->Result<Arc<Lane>,BridgeError>{
        let started=Instant::now();
        #[cfg(any(target_os="linux",target_os="macos"))]
        let started=review.as_ref().map_or(started,|l|l.entry.started);
        if !crate::protocol::valid_id(project_id) || !crate::supervisor::version_allocation_source_branch(reference) {
            return Err(BridgeError::invalid());
        }
        let mut state = self.lock();
        #[cfg(any(target_os="linux",target_os="macos"))]
        if let Some(link)=&review {version_reserve::agent::review::admission(&state,link)?}else{version_reserve::agent::gui_current(&state)?}; // SAME admission lock.
        if pending(&state) {
            return Err(busy());
        }
        self.version_source_observation_gate(&state)?;
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
            // separate128MiB partition; Document/source/control share64MiB.
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
            let quote=source_quote(input.retained_bytes().ok_or_else(busy)?).ok_or_else(busy)?;
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
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                reserve: None,
                #[cfg(any(target_os="linux",target_os="macos"))]
                review:review.clone(),
            });
            let gate =
                VersionAllocationSourceGoGate { document: Arc::downgrade(&self.inner), lane: Arc::downgrade(&lane) };
            let completion = VersionAllocationSourceCompletion { document: self.clone(), lane: lane.clone() };
            let admission = VersionAllocationSourceAdmission::reserve(input, gate, completion, started)?;
            if admission.bytes() > quote {
                return Err(busy());
            }
            state.version_allocation_source = Some(lane.clone());
            #[cfg(any(target_os="linux",target_os="macos"))]
            if let Err(error)=version_reserve::agent::review::bind(&mut state,&lane){lane.fail_unknown(self);return Err(error)}
            // Keep Doc/Edit and the installed pending lane through original
            // roster insertion; worker IO begins only through Supervisor latch.
            let result = self.inner.bridge.supervisor.start_version_allocation_source(admission);
            match result {
                Ok(ticket) => {
                    // Retain this first actual ticket even if bookkeeping was
                    // poisoned; the helper leaves its lane absorbing UNKNOWN.
                    *lock(&lane.ticket, &lane.stage).unwrap_or_else(|poison| poison.into_inner()) = Some(ticket);
                    drop(edit);
                    drop(state);
                    self.inner.changes.send_modify(|_| {});
                    Ok(lane)
                }
                Err(error) => {
                    #[cfg(any(target_os="linux",target_os="macos"))]
                    let delegated=lane.review.is_some();
                    #[cfg(not(any(target_os="linux",target_os="macos")))]
                    let delegated=false;
                    if delegated {lane.fail_unknown(self)} else if lane.stage.load(Ordering::SeqCst) == RESERVED {
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
        self.finish_version_source_read(lane).await
    }
    pub(super) async fn finish_version_source_read(&self,lane:Arc<Lane>)->Result<VersionAllocationSource,BridgeError>{
        let wait = lock(&lane.ticket, &lane.stage)
            .map_err(|_| BridgeError::cleanup_unknown())?
            .as_ref()
            .ok_or_else(BridgeError::cleanup_unknown)?
            .wait_original();
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
                // Acquire every original bookkeeping slot before changing any
                // of them; poison must not publish then discard a live ticket.
                let mut stored_result = lock(&lane.result, &lane.stage).map_err(|_| BridgeError::cleanup_unknown())?;
                let mut ticket = lock(&lane.ticket, &lane.stage).map_err(|_| BridgeError::cleanup_unknown())?;
                let mut request = lock(&lane.request, &lane.stage).map_err(|_| BridgeError::cleanup_unknown())?;
                if lane.stage.load(Ordering::SeqCst) != RETURNED
                    || !lane.completion_returned.load(Ordering::SeqCst)
                {
                    lane.fail_unknown(self);
                    return Err(BridgeError::cleanup_unknown());
                }
                *stored_result = Some(result.clone());
                ticket.take();
                request.take();
                drop(request);
                drop(ticket);
                drop(stored_result);
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
        let Ok(result) = lock(&lane.result, &lane.stage) else {
            return Some(VersionAllocationSourceReceipt::RetainedUnknown);
        };
        let receipt = result.clone().or_else(|| match lock(&lane.ticket, &lane.stage) {
            Ok(ticket) => ticket.as_ref().map(VersionAllocationSourceTicket::receipt),
            Err(_) => Some(VersionAllocationSourceReceipt::RetainedUnknown),
        });
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

    #[test]
    fn poisoned_bookkeeping_retains_data_and_latches_unknown() {
        // Inert bookkeeping DATA, not a constructed native ticket or return.
        let stage = AtomicU8::new(RETURNED);
        let original = Mutex::new(Some(37_u64));
        assert_eq!(*lock(&original, &stage).unwrap(), Some(37));
        assert_eq!(stage.load(Ordering::SeqCst), RETURNED);
        let caught = std::panic::catch_unwind(|| {
            let _held = original.lock().unwrap();
            panic!("inert source bookkeeping poison");
        });
        assert!(caught.is_err());
        let retained = lock(&original, &stage).unwrap_err().into_inner();
        assert_eq!(*retained, Some(37));
        assert_eq!(stage.load(Ordering::SeqCst), UNKNOWN);
        assert!(original.is_poisoned());
        drop(retained);
        assert!(lock(&original, &stage).is_err());
        assert_eq!(stage.load(Ordering::SeqCst), UNKNOWN);
    }

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
