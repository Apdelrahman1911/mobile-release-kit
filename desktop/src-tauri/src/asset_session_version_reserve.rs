//! Explicit iOS current-inventory reservation in the SAME Document/SOURCE lane.
//! Read/review, Reserve and saved-version Review/Apply are distinct actions.
//! Original Host/Store work is outside Doc; no caller source/floor/candidate DTO
//! can replace the saved lane, P8 witness or selected-account connection.
use super::*;
use crate::{
    application_service_host::{NativeProject, NativeStateTicket},
    github_connection_session::reserve::Pins,
    supervisor::{
        VersionAllocationSource, VersionAllocationSourceAdmission, VersionAllocationSourceInput,
        VersionAllocationSourceReceipt, VersionAllocationSourceRequest, VersionReserveControl,
        VersionReserveInvocation, VersionReserveJoined,
    },
    version_allocation_state_native::{
        dialogue,
        reserve::{Selection, StateHold},
    },
    version_reserve_protocol as p,
};
use std::path::Path;
use zeroize::Zeroizing;

struct Review {
    id: String,
    input: p::Review,
    source: VersionAllocationSource,
    saved: Arc<SavedObservationLane>,
    native: Arc<VersionAllocationSourceInput>,
    store: Arc<crate::saved_command_owner::StoreVersionObservation>,
    registration: u32,
    end: Instant,
    previous: Option<String>,
}
pub(super) struct State {
    view: p::Status,
    review: Option<Review>,
    reading: Option<(String, Arc<version_allocation::Lane>)>,
    lane: Option<Arc<Lane>>,
    last_candidate: Option<String>,
}
impl State {
    pub(super) fn new() -> Self {
        Self {
            view: p::Status::idle(),
            review: None,
            reading: None,
            lane: None,
            last_candidate: None,
        }
    }
    fn bump(&mut self) {
        if let Some(next) = self.view.revision.checked_add(1).filter(|n| *n < u32::MAX) {
            self.view.revision = next
        } else {
            if let Some(lane) = &self.lane {
                lane.control.unknown();
            }
            self.view.phase = p::Phase::CleanupUnknown;
            self.view.reason = "cleanup-unknown";
            self.view.review = None;
            self.view.reservation = None;
        }
    }
    fn current_view(&mut self) -> p::Status {
        if self.lane.as_ref().is_some_and(|l| l.control.uncertain()) {
            self.view.phase = p::Phase::CleanupUnknown;
            self.view.reason = "cleanup-unknown";
            self.view.review = None;
            self.view.reservation = None;
        }
        if self
            .review
            .as_ref()
            .is_some_and(|r| Instant::now() >= r.end)
        {
            self.review = None;
            self.view.review = None;
            self.view.phase = p::Phase::Refused;
            self.view.reason = "review-expired";
            self.bump();
        }
        self.view.clone()
    }
}
pub(super) fn retained_bytes(state: &DocumentState) -> Option<usize> {
    let selected = &state.version_reserve;
    let mut bytes = std::mem::size_of::<State>().checked_add(8192)?;
    if let Some(review) = &selected.review {
        bytes = bytes
            .checked_add(review.native.retained_bytes()?)?
            .checked_add(
                std::mem::size_of::<SavedObservationLane>() + review.saved.retained_heap_bytes()?,
            )?;
    }
    if let Some((_, reading)) = &selected.reading {
        if !state
            .version_allocation_source
            .as_ref()
            .is_some_and(|v| Arc::ptr_eq(v, reading))
        {
            bytes = bytes.checked_add(reading.retained_bytes()?)?;
        }
    }
    if let Some(lane) = &selected.lane {
        let in_source = state
            .version_allocation_source
            .as_ref()
            .and_then(|s| s.reserve.as_ref())
            .is_some_and(|v| Arc::ptr_eq(v, lane));
        if !in_source {
            bytes = bytes.checked_add(lane.keep_bytes()?)?;
        }
    }
    Some(bytes)
}
pub(super) struct Lane {
    id: String,
    pins: Pins,
    control: Arc<VersionReserveControl>,
    source: Weak<version_allocation::Lane>,
    observation: Arc<crate::saved_command_owner::StoreVersionObservation>,
    template: Value,
    selection: Selection,
    host_ticket: Mutex<Option<Arc<NativeStateTicket>>>,
    invocation: Mutex<Option<Arc<VersionReserveInvocation>>>,
    joined: Mutex<Option<Arc<VersionReserveJoined>>>,
    retirement: AsyncMutex<Retirement>,
    done: AtomicBool,
    // Private data retained only after genuine observer and native-use retirement.
    reservation: Mutex<Option<dialogue::Finished>>,
    edit_data: Mutex<Option<Value>>,
    edit_claimed: AtomicBool,
}
#[derive(Default)]
struct Retirement {
    handle: Option<JoinHandle<Result<(), crate::application_state_store::StateError>>>,
    returned: Option<Result<(), crate::application_state_store::StateError>>,
    failed: bool,
}
fn held<'a, T>(
    slot: &'a Mutex<T>,
    control: &VersionReserveControl,
) -> Result<MutexGuard<'a, T>, BridgeError> {
    slot.lock().map_err(|_| {
        control.unknown();
        BridgeError::cleanup_unknown()
    })
}
impl Lane {
    pub(super) fn returned(&self) -> bool {
        self.done.load(Ordering::SeqCst) && !self.control.pending()
    }
    pub(super) fn stop(&self) {
        self.control.stop();
    }
    pub(super) fn unknown(&self) {
        self.control.unknown();
    }
    pub(super) fn current_control(&self) -> bool {
        self.control.current()
    }
    pub(super) fn keep_bytes(&self) -> Option<usize> {
        // The original fixed reserve stays charged until a subsequent explicit
        // action drops this returned lane. No FIN/state ACK credits memory.
        VersionReserveInvocation::reservation_bytes()?
            .checked_add(std::mem::size_of::<Self>() + 16 * 1024)
    }
    fn source(&self) -> Result<Arc<version_allocation::Lane>, BridgeError> {
        self.source
            .upgrade()
            .ok_or_else(BridgeError::cleanup_unknown)
    }
}
struct WaitGuard {
    lane: Arc<Lane>,
    returned: bool,
}
impl Drop for WaitGuard {
    fn drop(&mut self) {
        if !self.returned {
            self.lane.control.unknown();
        }
    }
}
fn host_error(
    control: &VersionReserveControl,
    error: crate::service_protocol::Error,
) -> BridgeError {
    // The Host reports Retiring/Closed as Unavailable after checking its
    // retained failure fence. STOP below is not a close/retirement receipt:
    // the original lane stays pending until its actual cleanup returns.
    if error == crate::service_protocol::Error::StateUnknown {
        control.unknown();
        BridgeError::cleanup_unknown()
    } else {
        control.stop();
        p::unavailable()
    }
}
#[cfg(test)]
mod host_error_tests {
    use super::*;

    #[test]
    fn reserve_command_future_is_send_without_entering_native_work() {
        // Check the actual async command's type without constructing a native
        // session or polling it. Tauri requires the same Send contract.
        fn contract(document: &DocumentBinding, app_data: &Path) {
            fn assert_send<T: Send>(_: T) {}
            assert_send(document.reserve_version("", "", app_data));
        }
        let _ = contract;
    }

    #[test]
    fn reserve_host_refusal_never_returns_or_clears_unknown_control() {
        // Original control DATA only; no Host/ticket/IO/finality is fabricated.
        let control = VersionReserveControl::new(Instant::now()).unwrap();
        let refusal = host_error(&control, crate::service_protocol::Error::Unavailable);
        assert_eq!(refusal.code, "version_reserve_unavailable");
        assert!(!control.current() && control.pending() && !control.uncertain());

        let error = host_error(&control, crate::service_protocol::Error::StateUnknown);
        assert_eq!(error.code, BridgeError::cleanup_unknown().code);
        assert!(control.pending() && control.uncertain());
        let _ = host_error(&control, crate::service_protocol::Error::Unavailable);
        assert!(control.pending() && control.uncertain());
        assert!(control.returned().is_err() && control.pending());
    }
}
impl DocumentBinding {
    fn reserve_current_with_edit(
        &self,
        state: &DocumentState,
        source: &Arc<version_allocation::Lane>,
        lane: &Arc<Lane>,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
    ) -> Result<(), BridgeError> {
        if !state
            .version_reserve
            .lane
            .as_ref()
            .is_some_and(|v| Arc::ptr_eq(v, lane))
            || !lane.control.current()
            || !source
                .reserve
                .as_ref()
                .is_some_and(|v| Arc::ptr_eq(v, lane))
            || !state.saved_input.as_ref().is_some_and(|v| {
                v.matches_version_source(&self.inner, &source.saved, &source.input, edit)
            })
            || !self.current_store_version_observation(
                state,
                &lane.observation,
                lane.pins.generation,
                &source.input.root,
                900,
            )
        {
            return Err(p::refused());
        }
        state
            .github
            .version_reserve_current(&lane.pins, &lane.control, Instant::now())
    }
    /// The original SOURCE gate calls this while it ALREADY holds Doc/Edit.
    /// No Host, Store, native-source mutex or Supervisor job census is consulted.
    pub(super) fn reserve_source_current(
        &self,
        state: &DocumentState,
        source: &Arc<version_allocation::Lane>,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
    ) -> Result<(), BridgeError> {
        if let Some(lane) = &source.reserve {
            self.reserve_current_with_edit(state, source, lane, edit)?;
        }
        Ok(())
    }
    pub(super) fn reserve_source_go(
        &self,
        state: &DocumentState,
        source: &Arc<version_allocation::Lane>,
        request: &Arc<VersionAllocationSourceRequest>,
        claim: impl FnOnce() -> bool,
    ) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
        let lane = source.reserve.as_ref().ok_or_else(BridgeError::protocol)?;
        let allocation = request
            .allocation_request()
            .ok_or_else(BridgeError::protocol)?;
        let invocation = held(&lane.invocation, &lane.control)?
            .clone()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        if !invocation.matches_request(allocation) {
            return Err(BridgeError::protocol());
        }
        state.github.version_reserve_go(
            &lane.pins,
            &lane.control,
            allocation,
            Instant::now(),
            claim,
        )
    }
    pub(crate) async fn review_version_reservation(
        &self,
        input: p::Review,
    ) -> Result<p::Status, BridgeError> {
        if !input.valid() {
            return Err(p::not_started(BridgeError::invalid()));
        }
        {
            let state = self.lock();
            if state
                .version_reserve
                .lane
                .as_ref()
                .is_some_and(|l| !l.returned())
            {
                return Err(p::not_started(p::refused()));
            }
        }
        let id = crate::service_protocol::Id::random()
            .map_err(|_| p::not_started(p::unavailable()))?
            .as_str()
            .to_owned();
        let reading =
            match self.start_version_allocation_source(&input.project_id, &input.reference) {
                Ok(original) => original,
                Err(error) => {
                    // A pre-admission refusal is not an unknown operation. Never
                    // make that claim if the actual SOURCE lane retained work.
                    let state = self.lock();
                    return Err(if version_allocation::pending(&state) {
                        error
                    } else {
                        p::not_started(error)
                    });
                }
            };
        {
            let mut state = self.lock();
            state.version_reserve.review = None;
            state.version_reserve.reading = Some((id.clone(), reading.clone()));
            state.version_reserve.view.phase = p::Phase::Reading;
            state.version_reserve.view.reason = "none";
            state.version_reserve.view.project_id = Some(input.project_id.clone());
            state.version_reserve.view.operation_id = Some(id.clone());
            state.version_reserve.view.review = None;
            state.version_reserve.view.reservation = None;
            state.version_reserve.bump();
        }
        self.inner.changes.send_modify(|_| {});
        let source = self.finish_version_source_read(reading.clone()).await;
        if let Err(error) = source {
            let mut state = self.lock();
            if state
                .version_reserve
                .reading
                .as_ref()
                .is_some_and(|(key, l)| key == &id && Arc::ptr_eq(l, &reading))
            {
                // The real observer already joined. A known refusal is a
                // typed observation, not a lost-command-ACK/renewed operation.
                // Unknown keeps its original source ticket and STOP control.
                let returned = reading.returned();
                if returned {
                    state.version_reserve.reading = None;
                }
                state.version_reserve.view.phase = if returned {
                    p::Phase::Refused
                } else {
                    p::Phase::CleanupUnknown
                };
                state.version_reserve.view.reason = if returned {
                    "source-refused"
                } else {
                    "cleanup-unknown"
                };
                state.version_reserve.bump();
                return Ok(state.version_reserve.current_view());
            }
            return Err(error);
        }
        let source = source?;
        let reviewed = (|| -> Result<p::Status, BridgeError> {
            let mut state = self.lock();
            let original = state
                .version_allocation_source
                .as_ref()
                .cloned()
                .ok_or_else(p::refused)?;
            if !state
                .version_reserve
                .reading
                .as_ref()
                .is_some_and(|(key, l)| key == &id && Arc::ptr_eq(l, &original))
            {
                return Err(p::refused());
            }
            self.version_source_current(&state, &original)?;
            if !original.returned() || !original.input.matches(&source) {
                return Err(p::refused());
            }
            let (registration, root) = self
                .inner
                .bridge
                .native_project(&input.project_id)
                .map_err(|_| p::refused())?;
            let store = self.inner.bridge.local_store.current_versions_for_saved(
                &input.project_id,
                registration,
                &root,
                &original.input.configuration_sha256,
                &original.input.version_sha256,
            )?;
            if !self.current_store_version_observation(&state, &store, registration, &root, 900) {
                return Err(p::refused());
            }
            let previous = if input.new_candidate {
                Some(state.version_reserve.last_candidate.clone().ok_or_else(||BridgeError::new(
            "version_reserve_previous_unknown","First retry the existing candidate to read its exact saved identity; it is never replaced by guessing."))?)
            } else {
                None
            };
            let view = p::ReviewView {
                id: id.clone(),
                reference: input.reference.clone(),
                increment: input.increment,
                new_candidate: input.new_candidate,
            };
            state.version_reserve.reading = None;
            state.version_reserve.review = Some(Review {
                id: id.clone(),
                input,
                source,
                saved: original.saved.clone(),
                native: original.input.clone(),
                store,
                registration,
                end: Instant::now() + Duration::from_secs(120),
                previous,
            });
            state.version_reserve.view.review = Some(view);
            state.version_reserve.view.phase = p::Phase::Reviewed;
            state.version_reserve.view.project_id = Some(original.input.project_id.clone());
            state.version_reserve.view.reason = "none";
            state.version_reserve.view.reservation = None;
            state.version_reserve.bump();
            Ok(state.version_reserve.current_view())
        })();
        if reviewed.is_err() {
            let mut state = self.lock();
            if state
                .version_reserve
                .reading
                .as_ref()
                .is_some_and(|(key, l)| key == &id && Arc::ptr_eq(l, &reading))
            {
                state.version_reserve.reading = None;
                state.version_reserve.view.phase = p::Phase::Refused;
                state.version_reserve.view.reason = "review-unavailable";
                state.version_reserve.bump();
                return Ok(state.version_reserve.current_view());
            }
        }
        reviewed
    }

    fn reserve_begin(&self, project: &str, review_id: &str) -> Result<Arc<Lane>, BridgeError> {
        let started = Instant::now();
        let control = Arc::new(VersionReserveControl::new(started)?);
        let id = crate::service_protocol::Id::random()
            .map_err(|_| p::unavailable())?
            .as_str()
            .to_owned();
        let mut state = self.lock();
        if state
            .version_reserve
            .lane
            .as_ref()
            .is_some_and(|l| !l.returned())
            || version_allocation::pending(&state)
        {
            return Err(p::refused());
        }
        self.passive_query_gate_locked(&state, &self.inner.bridge)?;
        if self.github_gate(&state) != GitHubReason::None
            || !self
                .inner
                .bridge
                .supervisor
                .version_allocation_source_available()
            || !self.inner.bridge.supervisor.can_exit()
            || !self
                .inner
                .android_registration_control
                .idle_for_saved_observation()
        {
            return Err(p::unavailable());
        }
        let review = state
            .version_reserve
            .review
            .as_ref()
            .filter(|r| {
                r.id == review_id && r.input.project_id == project && Instant::now() < r.end
            })
            .ok_or_else(p::refused)?;
        let (registration, root) = self
            .inner
            .bridge
            .native_project(project)
            .map_err(|_| p::refused())?;
        if registration != review.registration
            || root != review.native.root
            || !self.current_store_version_observation(
                &state,
                &review.store,
                registration,
                &root,
                900,
            )
        {
            return Err(p::refused());
        }
        // Old known-returned code/state reservation can be retired only for
        // this explicit new native action. Pending/Unknown is never discarded.
        state.version_reserve.lane = None;
        state.version_allocation_source = None;
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        {
            let document = lookup_memory::retained_document_bytes(&self.inner, &state)
                .map_err(|_| p::unavailable())?
                .checked_add(
                    installation_memory::additional_document_bytes(self, &state)
                        .map_err(|_| p::unavailable())?,
                )
                .ok_or_else(p::unavailable)?;
            let future = VersionAllocationSourceAdmission::reservation_bytes()
                .and_then(|n| n.checked_add(VersionReserveInvocation::reservation_bytes()?))
                .and_then(|n| n.checked_add(32 * 1024))
                .ok_or_else(p::unavailable)?;
            crate::macos_history_inventory::admission_bytes(document, future)
                .ok_or_else(p::unavailable)?;
        }
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        let review = state.version_reserve.review.take().ok_or_else(p::refused)?;
        let (saved, input) = state
            .saved_input
            .as_ref()
            .ok_or_else(p::refused)?
            .version_source_input(&self.inner, project, &review.input.reference, &edit)?;
        if !Arc::ptr_eq(&saved, &review.saved) || !input.matches(&review.source) {
            return Err(p::refused());
        }
        let binding = github_setup_project_binding(&root)?;
        let template = serde_json::json!({"identityRevision":input.configuration_sha256,"source":review.source,
            "baseVersion":{"name":review.store.context().saved_version.name,"build":review.store.context().saved_version.build},
            "platforms":["ios"],"policy":review.input.policy(),"storeContextRevision":crate::version_allocation_state_native::ios_inventory::context_digest(review.store.context()).map_err(|_|p::refused())?});
        let selection = match review.previous {
            Some(previous) => Selection::New {
                previous_request_sha256: previous,
            },
            None => Selection::InitialOrRetry,
        };
        // Arc::new_cyclic stores only weak source correlation; no ticket cycle.
        let quote = VersionAllocationSourceAdmission::reservation_bytes()
            .and_then(|n| n.checked_add(VersionReserveInvocation::reservation_bytes()?))
            .and_then(|n| n.checked_add(input.retained_bytes()? + 32 * 1024))
            .ok_or_else(p::unavailable)?;
        let pins = state.github.begin_version_reserve(
            project,
            registration,
            &binding,
            control.clone(),
            started,
        )?;
        let source = Arc::new_cyclic(|weak| {
            let reserve = Arc::new(Lane {
                id: id.clone(),
                pins,
                control: control.clone(),
                source: weak.clone(),
                observation: review.store,
                template,
                selection,
                host_ticket: Mutex::new(None),
                invocation: Mutex::new(None),
                joined: Mutex::new(None),
                retirement: AsyncMutex::new(Retirement::default()),
                done: AtomicBool::new(false),
                reservation: Mutex::new(None),
                edit_data: Mutex::new(None),
                edit_claimed: AtomicBool::new(false),
            });
            version_allocation::Lane {
                saved,
                input,
                stage: std::sync::atomic::AtomicU8::new(version_allocation::RESERVED),
                completion_returned: AtomicBool::new(false),
                request: Mutex::new(None),
                ticket: Mutex::new(None),
                result: Mutex::new(None),
                reservation_bytes: quote,
                reserve: Some(reserve),
            }
        });
        let lane = source
            .reserve
            .as_ref()
            .expect("closed reserve constructor")
            .clone();
        state.version_reserve.lane = Some(lane.clone());
        state.version_allocation_source = Some(source);
        state.version_reserve.view.review = None;
        state.version_reserve.view.reservation = None;
        state.version_reserve.view.phase = p::Phase::Reserving;
        state.version_reserve.view.project_id = Some(project.into());
        state.version_reserve.view.operation_id = Some(id);
        state.version_reserve.view.reason = "none";
        state.version_reserve.bump();
        drop(edit);
        drop(state);
        self.inner.changes.send_modify(|_| {});
        Ok(lane)
    }

    fn reserve_preentry_current(
        &self,
        state: &DocumentState,
        lane: &Arc<Lane>,
    ) -> Result<(), BridgeError> {
        passive_document_state_gate(state)?;
        if !state.lifetime.original_bound()
            || state.lost_observed
            || state.maintenance.closed()
            || version_enrollment::pending(state)
        {
            return Err(p::refused());
        }
        let source = lane.source()?;
        if !state
            .version_allocation_source
            .as_ref()
            .is_some_and(|s| Arc::ptr_eq(s, &source))
        {
            return Err(p::refused());
        }
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        self.reserve_current_with_edit(state, &source, lane, &edit)
    }
    fn reserve_native(&self, lane: &Arc<Lane>, armed: bool) -> Result<NativeProject, BridgeError> {
        let state = self.lock();
        if armed {
            self.version_source_current(&state, &lane.source()?)?;
        } else {
            self.reserve_preentry_current(&state, lane)?;
        }
        let source = lane.source()?;
        #[cfg(any(
            all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
            all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )
        ))]
        let (device, inode) = source
            .input
            .root
            .identity
            .posix()
            .map_err(|_| p::unavailable())?
            .service_identity();
        #[cfg(not(any(
            all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
            all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )
        )))]
        let (device, inode): (u64, u64) = return Err(p::unavailable());
        Ok(NativeProject {
            runtime_id: lane.pins.project_id.clone(),
            canonical_root: source.input.root.path.clone(),
            device,
            inode,
            registration_generation: lane.pins.generation,
            document_identity: self.inner.session_identity.clone(),
            input_revision: self.inner.android_registration_control.epoch()?,
        })
    }
    async fn reserve_run(&self, lane: &Arc<Lane>, app_data: &Path) -> Result<(), BridgeError> {
        // No owner exists outside this retained lane. The exact Host ticket
        // is retained before prepare may do IO; all paths join in finish.
        let native = self.reserve_native(lane, false)?;
        {
            let state = self.lock();
            self.reserve_preentry_current(&state, lane)?;
            let roster = self
                .inner
                .bridge
                .native_roster()
                .map_err(|_| p::refused())?;
            self.inner
                .bridge
                .application_service
                .reserve_native_state_location(app_data, &roster.roots)
                .map_err(|e| host_error(&lane.control, e))?;
            let ticket = self
                .inner
                .bridge
                .application_service
                .begin_native_state_until(native, lane.control.work_end())
                .map_err(|e| host_error(&lane.control, e))?;
            // Initial custody may recover a poisoned guard ONLY to retain the
            // original ticket for cleanup, never to claim it returned.
            match lane.host_ticket.lock() {
                Ok(mut slot) => *slot = Some(Arc::new(ticket)),
                Err(poison) => {
                    *poison.into_inner() = Some(Arc::new(ticket));
                    lane.control.unknown();
                    return Err(BridgeError::cleanup_unknown());
                }
            }
        }
        let ticket = held(&lane.host_ticket, &lane.control)?
            .clone()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        self.inner
            .bridge
            .application_service
            .prepare_native_state(&ticket, app_data)
            .await
            .map_err(|e| host_error(&lane.control, e))?;
        let current = self.reserve_native(lane, false)?;
        let ready = Arc::new(
            self.inner
                .bridge
                .application_service
                .finish_native_state_retained(&ticket, &current)
                .map_err(|e| host_error(&lane.control, e))?,
        );
        let native = Arc::new(StateHold::new(ready, lane.control.clone()));
        let invocation = Arc::new(VersionReserveInvocation::new(
            lane.control.clone(),
            native,
            lane.observation.clone(),
            lane.template.clone(),
            lane.selection.clone(),
            lane.pins.target.account_id.clone(),
            lane.pins.target.repository.clone(),
            lane.pins.target.repository_id.clone(),
        )?);
        *held(&lane.invocation, &lane.control)? = Some(invocation.clone());
        let wait = {
            let state = self.lock();
            self.reserve_preentry_current(&state, lane)?;
            let source = lane.source()?;
            let gate = VersionAllocationSourceGoGate {
                document: Arc::downgrade(&self.inner),
                lane: Arc::downgrade(&source),
            };
            let completion = VersionAllocationSourceCompletion {
                document: self.clone(),
                lane: source.clone(),
            };
            let admission = VersionAllocationSourceAdmission::reserve(
                source.input.clone(),
                gate,
                completion,
                lane.control.started(),
            )?
            .with_reserve(invocation)?;
            if admission.bytes() > source.reservation_bytes {
                return Err(p::unavailable());
            }
            let mut slot = version_allocation::lock(&source.ticket, &source.stage)
                .map_err(|_| BridgeError::cleanup_unknown())?;
            if slot.is_some() {
                return Err(BridgeError::cleanup_unknown());
            }
            *slot = Some(
                self.inner
                    .bridge
                    .supervisor
                    .start_version_allocation_source(admission)?,
            );
            slot.as_ref()
                .ok_or_else(BridgeError::cleanup_unknown)?
                .wait_original()
        };
        let joined = Arc::new(wait.reserved().await?);
        *held(&lane.joined, &lane.control)? = Some(joined.clone());
        {
            let mut state = self.lock();
            state
                .github
                .observe_version_reserve_control(&lane.pins, &lane.control, &joined)?;
        }
        joined.outcome()?;
        let finished = joined.finished()?;
        if finished.outcome["status"] != "reserved" {
            return Err(p::refused());
        }
        Ok(())
    }
    async fn reserve_retire(&self, lane: &Arc<Lane>) -> Result<(), BridgeError> {
        lane.control.check_cleanup()?;
        let joined = held(&lane.joined, &lane.control)?.clone();
        if !lane.control.never_admitted() && joined.is_none() {
            lane.control.unknown();
            return Err(BridgeError::cleanup_unknown());
        }
        let ticket = held(&lane.host_ticket, &lane.control)?.clone();
        if let Some(ticket) = ticket {
            // Exact completed/cancelled ticket only; never cancel a newer Host.
            match self
                .inner
                .bridge
                .application_service
                .cancel_native_state_ticket(&ticket)
            {
                Ok(()) | Err(crate::service_protocol::Error::Conflict) => {}
                Err(e) => return Err(host_error(&lane.control, e)),
            }
        }
        // Release the synchronous invocation lock before the asynchronous
        // retirement owner is awaited. Keep the same original invocation.
        let original = held(&lane.invocation, &lane.control)?.clone();
        if let Some(original) = original {
            if let Some(joined) = joined {
                let mut slot = lane.retirement.lock().await;
                if slot.handle.is_some() || slot.returned.is_some() || slot.failed {
                    lane.control.unknown();
                    return Err(BridgeError::cleanup_unknown());
                }
                let (release, enter) = oneshot::channel();
                slot.handle = Some(tokio::task::spawn_blocking(move || {
                    enter.blocking_recv().map_err(|_| {
                        crate::version_allocation_state_native::reserve::unknown_failure()
                    })?;
                    original.state.retire_original(&joined)
                }));
                if release.send(()).is_err() {
                    lane.control.unknown();
                    return Err(BridgeError::cleanup_unknown());
                }
                let result = slot
                    .handle
                    .as_mut()
                    .ok_or_else(BridgeError::cleanup_unknown)?
                    .await;
                match result {
                    Ok(result) => {
                        slot.returned = Some(result);
                        slot.handle.take();
                        result.map_err(|e| {
                            lane.control.state_failed(e, Instant::now());
                            BridgeError::cleanup_unknown()
                        })?;
                    }
                    Err(_) => {
                        slot.failed = true;
                        lane.control.unknown();
                        return Err(BridgeError::cleanup_unknown());
                    }
                }
            } else if !lane.control.never_admitted() {
                return Err(BridgeError::cleanup_unknown());
            }
        }
        lane.control.check_cleanup()
    }
    pub(crate) async fn reserve_version(
        &self,
        project: &str,
        review_id: &str,
        app_data: &Path,
    ) -> Result<p::Status, BridgeError> {
        let lane = self
            .reserve_begin(project, review_id)
            .map_err(p::not_started)?;
        let mut guard = WaitGuard {
            lane: lane.clone(),
            returned: false,
        };
        let outcome = self.reserve_run(&lane, app_data).await;
        let status = self.reserve_finish(&lane, outcome).await?;
        guard.returned = true;
        Ok(status)
    }
    async fn reserve_finish(
        &self,
        lane: &Arc<Lane>,
        mut outcome: Result<(), BridgeError>,
    ) -> Result<p::Status, BridgeError> {
        if outcome.is_err() {
            lane.control.stop();
        }
        self.reserve_retire(lane).await?;
        let joined = held(&lane.joined, &lane.control)?.clone();
        let data = joined.as_ref().and_then(|j| j.finished().ok());
        let candidate = held(&lane.invocation, &lane.control)?
            .as_ref()
            .and_then(|i| i.state.selected_hash().ok().flatten());
        let invocation = held(&lane.invocation, &lane.control)?.clone();
        if invocation.as_ref().is_some_and(|i| {
            !i.state.retired() && !(outcome.is_err() && joined.is_none() && i.state.never_entered())
        }) {
            lane.control.unknown();
            return Err(BridgeError::cleanup_unknown());
        }
        let edit_data = if outcome.is_ok() {
            Some(
                invocation
                    .as_ref()
                    .ok_or_else(BridgeError::cleanup_unknown)?
                    .reserved_edit_data(data.as_ref().ok_or_else(BridgeError::protocol)?)?,
            )
        } else {
            None
        };
        let mut state = self.lock();
        if !state
            .version_reserve
            .lane
            .as_ref()
            .is_some_and(|l| Arc::ptr_eq(l, lane))
        {
            lane.control.unknown();
            return Err(BridgeError::cleanup_unknown());
        }
        let source = lane.source()?;
        if outcome.is_ok() {
            if let Err(error) = self.version_source_current(&state, &source) {
                outcome = Err(error);
                lane.control.stop();
            }
        }
        let mut result = version_allocation::lock(&source.result, &source.stage)
            .map_err(|_| BridgeError::cleanup_unknown())?;
        let mut ticket = version_allocation::lock(&source.ticket, &source.stage)
            .map_err(|_| BridgeError::cleanup_unknown())?;
        let mut request = version_allocation::lock(&source.request, &source.stage)
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if !lane.control.never_admitted() && !source.completion_returned.load(Ordering::SeqCst) {
            lane.control.unknown();
            return Err(BridgeError::cleanup_unknown());
        }
        if let Some(joined) = &joined {
            *result = Some(joined.source_receipt());
        }
        lane.control.returned()?;
        state.github.finish_version_reserve(&lane.control)?;
        if outcome.is_ok() {
            *held(&lane.reservation, &lane.control)? = data.clone();
            *held(&lane.edit_data, &lane.control)? = edit_data;
        }
        ticket.take();
        request.take();
        lane.done.store(true, Ordering::SeqCst);
        state.version_reserve.last_candidate = candidate;
        if let (Ok(()), Some(data)) = (outcome.as_ref(), data) {
            let v = &data.outcome["reservation"];
            state.version_reserve.view.reservation = Some(p::ReservationView {
                id: lane.id.clone(),
                candidate_id: v["request"]["candidateId"]
                    .as_str()
                    .ok_or_else(BridgeError::protocol)?
                    .into(),
                name: v["version"]["name"]
                    .as_str()
                    .ok_or_else(BridgeError::protocol)?
                    .into(),
                build: v["version"]["build"]
                    .as_u64()
                    .ok_or_else(BridgeError::protocol)?,
            });
            state.version_reserve.view.phase = p::Phase::Reserved;
            state.version_reserve.view.reason = "none";
        } else {
            state.version_reserve.view.phase = p::Phase::Refused;
            state.version_reserve.view.reason = if lane.control.state_failure().is_some() {
                "state-unavailable"
            } else {
                "reservation-refused"
            };
            state.version_reserve.view.reservation = None;
        }
        state.version_reserve.bump();
        let status = state.version_reserve.current_view();
        drop(state);
        self.inner.changes.send_modify(|_| {});
        Ok(status)
    }
    pub(crate) fn version_reserve_status(&self) -> p::Status {
        self.lock().version_reserve.current_view()
    }
    pub(crate) fn cancel_version_reserve(&self, id: &str) -> Result<p::Status, BridgeError> {
        let mut state = self.lock();
        if let Some((key, source)) = &state.version_reserve.reading {
            if key == id {
                let ticket = version_allocation::lock(&source.ticket, &source.stage)
                    .map_err(|_| BridgeError::cleanup_unknown())?;
                if let Some(ticket) = ticket.as_ref() {
                    ticket.stop();
                }
                drop(ticket);
                state.version_reserve.bump();
                return Ok(state.version_reserve.current_view());
            }
        }
        let lane = state
            .version_reserve
            .lane
            .as_ref()
            .filter(|l| l.id == id)
            .ok_or_else(BridgeError::invalid)?;
        if !lane.returned() {
            lane.control.stop();
        }
        state.version_reserve.bump();
        Ok(state.version_reserve.current_view())
    }
}

/// Same native context/material/account and source binding, NOT a continuing
/// filesystem lease. Fresh Edit GitReadSources rechecks actual files off Doc.
pub(crate) struct ReservedVersionEditGate {
    document: Weak<Inner>,
    input: Arc<VersionAllocationSourceInput>,
    registration: u32,
    pins: Pins,
    observation: Arc<crate::saved_command_owner::StoreVersionObservation>,
}
impl ReservedVersionEditGate {
    pub(crate) fn same_publisher(&self, publisher: &RegistrationPublisher) -> bool {
        self.document
            .upgrade()
            .is_some_and(|d| publisher.same_slot(&d.android_registration_control))
    }
    pub(crate) fn same_observation(
        &self,
        original: &crate::saved_command_owner::StoreVersionObservation,
    ) -> bool {
        std::ptr::eq(Arc::as_ptr(&self.observation), original)
    }
    pub(crate) fn epoch(&self) -> Result<u64, BridgeError> {
        self.document
            .upgrade()
            .ok_or_else(p::refused)?
            .android_registration_control
            .epoch()
    }
    fn locked(
        &self,
        document: &DocumentBinding,
        state: &DocumentState,
        handoff: &crate::edit_owner::NativeReservedVersionHandoff,
        publisher: Option<&RegistrationPublisher>,
    ) -> Result<(), BridgeError> {
        if !self
            .document
            .upgrade()
            .is_some_and(|d| Arc::ptr_eq(&d, &document.inner))
            || !state.lifetime.original_bound()
            || state.lost_observed
            || state.unknown
            || state.exhausted
            || state.stopping
            || state.retiring
            || state.quit_pending
            || state.lock_pending
            || state.maintenance.closed()
            || !self.observation.current_for_reserved_edit(
                handoff,
                Instant::now(),
                std::time::SystemTime::now(),
                900,
            )
            || !self
                .observation
                .matches_root(self.registration, &self.input.root)
            || !self
                .observation
                .material()
                .current(state, self.registration, &self.input.root)
            || !document.native_qualified()
            || encrypted_mode(state) && !document.persistence_qualified()
        {
            return Err(p::refused());
        }
        if !handoff.epoch_ready(publisher)? {
            return Err(BridgeError::new(
                "busy",
                "Wait for the original edit publication.",
            ));
        }
        let (generation, root) = document
            .inner
            .bridge
            .native_project(&self.input.project_id)
            .map_err(|_| p::refused())?;
        if generation != self.registration || root != self.input.root {
            return Err(p::refused());
        }
        state
            .github
            .reserved_version_edit_current(&self.pins, Instant::now())
    }
    pub(crate) fn current(
        &self,
        handoff: &crate::edit_owner::NativeReservedVersionHandoff,
        publisher: Option<&RegistrationPublisher>,
    ) -> Result<(), BridgeError> {
        let inner = self.document.upgrade().ok_or_else(p::refused)?;
        let document = DocumentBinding {
            inner: inner.clone(),
        };
        // Native jobs never wait on a Document while retaining a Source/Book.
        let state = inner.state.try_lock().map_err(|e| match e {
            std::sync::TryLockError::WouldBlock => {
                BridgeError::new("busy", "Wait for the original Document observation.")
            }
            std::sync::TryLockError::Poisoned(_) => BridgeError::cleanup_unknown(),
        })?;
        self.locked(&document, &state, handoff, publisher)
    }
}
impl DocumentBinding {
    pub(crate) fn edit_reserved_version(
        &self,
        project: &str,
        reservation: &str,
    ) -> Result<crate::release_version_edit_protocol::ReleaseVersionEditStatus, BridgeError> {
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )))]
        {
            let _ = (project, reservation);
            return Err(p::unavailable());
        }
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        {
            let mut ticket = self.inner.bridge.edits.release_version_open_ticket(MAIN)?;
            let mut publisher = self
                .inner
                .android_registration_control
                .reserve(RegistrationPublisherKind::General, false)?;
            let result = (|| {
                let mut state = self.lock();
                let lane = state
                    .version_reserve
                    .lane
                    .as_ref()
                    .filter(|l| l.id == reservation && l.pins.project_id == project)
                    .cloned()
                    .ok_or_else(p::refused)?;
                let source = lane.source()?;
                if !lane.returned()
                    || !lane.control.edit_window()
                    || lane.edit_claimed.load(Ordering::SeqCst)
                    || !matches!(state.version_reserve.view.phase, p::Phase::Reserved)
                {
                    return Err(p::refused());
                }
                let edit = self
                    .inner
                    .bridge
                    .edits
                    .saved_registration_guard(&self.inner.session_identity)?;
                if !state.saved_input.as_ref().is_some_and(|s| {
                    s.reserved_version_prepublication(
                        &self.inner,
                        &source.saved,
                        &source.input,
                        &edit,
                        &publisher,
                    )
                }) || !self.current_store_version_observation(
                    &state,
                    &lane.observation,
                    lane.pins.generation,
                    &source.input.root,
                    900,
                ) {
                    return Err(p::refused());
                }
                drop(edit);
                state
                    .github
                    .reserved_version_edit_current(&lane.pins, Instant::now())?;
                let epoch = publisher.tool_source_epoch()?;
                let registration = crate::edit_owner::RegisteredEditRoot {
                    generation: lane.pins.generation,
                    root: source.input.root.clone(),
                };
                let gate = ReservedVersionEditGate {
                    document: Arc::downgrade(&self.inner),
                    input: source.input.clone(),
                    registration: registration.generation,
                    pins: lane.pins.clone(),
                    observation: lane.observation.clone(),
                };
                if lane.edit_claimed.swap(true, Ordering::SeqCst) {
                    return Err(p::refused());
                }
                let data = held(&lane.edit_data, &lane.control)?
                    .take()
                    .ok_or_else(p::refused)?;
                let handoff = crate::edit_owner::NativeReservedVersionHandoff::new(
                    gate,
                    lane.control.clone(),
                    registration.clone(),
                    data,
                    epoch,
                )?;
                handoff.begin(&publisher, crate::edit_owner::ReservedVersionStep::Open)?;
                let registered = self.registered_edit_root_locked_published(
                    &mut state,
                    crate::edit_protocol::EditDomain::ReleaseVersion,
                    |_| Ok(project.to_owned()),
                    None,
                    &mut publisher,
                )?;
                if registered != registration {
                    return Err(p::refused());
                }
                handoff.accepted(&publisher, crate::edit_owner::ReservedVersionStep::Open)?;
                handoff
                    .gate()
                    .locked(self, &state, &handoff, Some(&publisher))?;
                ticket.reserved_version(handoff)?;
                self.inner.bridge.edits.open_release_version_published(
                    &publisher,
                    MAIN,
                    project.to_owned(),
                    registered,
                    ticket,
                )
            })();
            finish_registration_publisher(publisher);
            result
        }
    }
    /// Prepare/Apply reuse their existing commands and writer. A normal manual
    /// Session has no handoff and follows the UNCHANGED registered edit path.
    pub(crate) fn release_version_phase_admit<T>(
        &self,
        session: &str,
        step: crate::edit_owner::ReservedVersionStep,
        enqueue: impl FnOnce(
            &DesktopBridge,
            crate::edit_owner::RegisteredEditRoot,
            &RegistrationPublisher,
        ) -> Result<T, BridgeError>,
    ) -> Result<T, BridgeError> {
        let access = self
            .inner
            .bridge
            .edits
            .reserved_version_access(MAIN, session)?;
        let Some(access) = access else {
            return self.release_version_edit_admit_published(
                |b| b.edits.release_version_project(MAIN, session),
                enqueue,
            );
        };
        if !matches!(
            step,
            crate::edit_owner::ReservedVersionStep::Prepare
                | crate::edit_owner::ReservedVersionStep::Apply
        ) {
            return Err(p::refused());
        }
        let mut publisher = self
            .inner
            .android_registration_control
            .reserve(RegistrationPublisherKind::General, false)?;
        let result = (|| {
            let mut state = self.lock();
            let handoff = access.handoff();
            handoff
                .gate()
                .locked(self, &state, handoff, Some(&publisher))?;
            access.begin(&publisher, step)?;
            let registered = self.registered_edit_root_locked_published(
                &mut state,
                crate::edit_protocol::EditDomain::ReleaseVersion,
                |b| b.edits.release_version_project(MAIN, session),
                None,
                &mut publisher,
            )?;
            access.accepted(&publisher, step)?;
            handoff
                .gate()
                .locked(self, &state, handoff, Some(&publisher))?;
            enqueue(&self.inner.bridge, registered, &publisher)
        })();
        if result.is_err() {
            access.failed();
        }
        finish_registration_publisher(publisher);
        result
    }
}
