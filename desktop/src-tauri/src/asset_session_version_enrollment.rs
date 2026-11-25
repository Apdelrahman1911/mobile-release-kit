//! One read/review/connect lane in the SAME Document. Explicit enrollment only:
//! GETs through the existing authenticated worker then one native state CAS.
//! No allocation/Store floor/remote creation, renderer paths or public grants.
use super::*;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::{
    application_service_host::{NativeProject, NativeStateTicket},
    application_state_store::{Cleanup, Durability, Effect, StateError},
    version_allocation_state_native::enrollment::Jobs,
};
use crate::{
    edit_owner::SavedEditStamp,
    github_connection_session::enrollment::Pins,
    supervisor::{
        VersionEnrollmentAdmission, VersionEnrollmentControl, VersionEnrollmentJoined,
        VersionEnrollmentTicket,
    },
    version_enrollment_protocol as p,
};
use std::path::Path;
use tokio::sync::Mutex as AsyncMutex;
#[path = "asset_session_version_enrollment_agent.rs"]
pub(crate) mod agent;
use crate::service_github_action_requests::Entry as AgentEntry;

struct Original {
    root: asset_source::RegisteredRoot,
    stamp: SavedEditStamp,
    pins: Pins,
    input_epoch: u64,
}
struct Review {
    id: String,
    identity: Arc<()>,
    producer: Option<Weak<AgentEntry>>,
    original: Arc<Original>,
    offer: p::Offer,
    end: Instant,
}
pub(super) struct Lane {
    id: String,
    agent: Option<Arc<AgentEntry>>,
    original: Arc<Original>,
    control: Arc<VersionEnrollmentControl>,
    end: Instant,
    request: Mutex<Option<Arc<p::Request>>>,
    ticket: Mutex<Option<VersionEnrollmentTicket>>,
    joined: Mutex<Option<Arc<VersionEnrollmentJoined>>>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    host_ticket: Mutex<Option<Arc<NativeStateTicket>>>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    jobs: AsyncMutex<Option<Jobs>>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    state_failure: Mutex<Option<StateError>>,
}
pub(super) struct State {
    view: p::Status,
    lane: Option<Arc<Lane>>,
    review: Option<Review>,
    permission: Option<agent::Permission>,
}
impl State {
    pub(super) fn new() -> Self {
        Self {
            view: p::Status::idle(),
            lane: None,
            review: None,
            permission: None,
        }
    }
    fn bump(&mut self) {
        match self.view.revision.checked_add(1).filter(|v| *v < u32::MAX) {
            Some(v) => self.view.revision = v,
            None => {
                self.view.revision = u32::MAX;
                self.unknown();
            }
        }
    }
    fn unknown(&mut self) {
        if let Some(lane) = &self.lane {
            lane.control.unknown();
            agent::unknown(lane);
        }
        self.review = None;
        self.view.review = None;
        self.view.phase = p::Phase::CleanupUnknown;
        self.view.reason = p::Reason::CleanupUnknown;
    }
    fn status(&mut self, now: Instant) -> p::Status {
        if self.lane.as_ref().is_some_and(|l| l.control.uncertain()) {
            self.unknown();
        }
        if self.review.as_ref().is_some_and(|r| now >= r.end) {
            self.review = None;
            self.view.review = None;
            self.view.phase = p::Phase::Refused;
            self.view.reason = p::Reason::Expired;
            self.bump();
        }
        self.view.clone()
    }
    fn stop(&mut self) {
        let had_review = self.review.take().is_some() || self.view.phase == p::Phase::Reviewed;
        self.view.review = None;
        if self.view.phase == p::Phase::CleanupUnknown
            || self.lane.as_ref().is_some_and(|l| l.control.uncertain())
        {
            self.unknown();
        } else if let Some(lane) = self.lane.as_ref().filter(|l| l.control.pending()) {
            lane.control.stop();
            if lane.control.uncertain() {
                self.unknown();
            } else {
                self.view.phase = p::Phase::Stopping;
                self.view.reason = p::Reason::Cancelled;
            }
        } else if had_review {
            self.view.phase = p::Phase::Refused;
            self.view.reason = p::Reason::TargetChanged;
        }
        self.bump();
    }
}
pub(super) fn pending(state: &DocumentState) -> bool {
    state.version_enrollment.view.phase == p::Phase::CleanupUnknown
        || state
            .version_enrollment
            .lane
            .as_ref()
            .is_some_and(|l| l.control.pending())
}
pub(super) fn stop(state: &mut DocumentState) {
    state.version_enrollment.stop();
}
pub(super) fn retained_bytes(state: &DocumentState) -> Option<usize> {
    let s = &state.version_enrollment;
    if pending(state) {
        return None;
    } // In-flight quote stays owned; no new partition credit.
    let mut bytes = std::mem::size_of::<State>().checked_add(agent::native_backing()?)?;
    if s.lane.is_some() {
        bytes = bytes.checked_add(p::RETAINED_LIMIT)?;
    }
    if s.review.is_some() {
        bytes = bytes.checked_add(16 * 1024)?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retired_review_is_refused_and_unknown_is_never_downgraded_by_stop() {
        // Projection-only DATA: no native admission, Store or worker is minted.
        let mut state = State::new();
        state.view.phase = p::Phase::Reviewed;
        state.view.project_id = Some("project-1".into());
        state.view.operation_id = Some("a".repeat(32));
        state.view.review = Some(p::ReviewView {
            id: "a".repeat(32),
            repository: "fixture/app".into(),
            version: p::Version {
                name: "1.2.3".into(),
                build: 7,
            },
            reservations: 1,
        });
        state.stop();
        assert_eq!(state.view.phase, p::Phase::Refused);
        assert_eq!(state.view.reason, p::Reason::TargetChanged);
        assert!(state.view.review.is_none());
        state.unknown();
        state.stop();
        assert_eq!(state.view.phase, p::Phase::CleanupUnknown);
        assert_eq!(state.view.reason, p::Reason::CleanupUnknown);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let control = VersionEnrollmentControl::new();
            let work_end = Instant::now() + Duration::from_secs(60);
            let error = host_error(&control, crate::service_protocol::Error::StateUnknown);
            assert_eq!(error.code, BridgeError::cleanup_unknown().code);
            assert!(control.uncertain() && control.pending());
            assert!(control.returned(work_end).is_err());
        }
    }
}
fn held<'a, T>(
    slot: &'a Mutex<T>,
    control: &VersionEnrollmentControl,
) -> Result<MutexGuard<'a, T>, BridgeError> {
    slot.lock().map_err(|_| {
        control.unknown();
        BridgeError::cleanup_unknown()
    })
}
fn changed() -> BridgeError {
    p::refused(p::Reason::TargetChanged)
}
fn busy() -> BridgeError {
    p::refused(p::Reason::Busy)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn host_error(
    control: &VersionEnrollmentControl,
    error: crate::service_protocol::Error,
) -> BridgeError {
    use crate::service_protocol::Error;
    // The Host retains the original structured storage/source failure. Do
    // not flatten an unknown startup/close into a reusable refused lane.
    let reason = match error {
        Error::StateUnknown => {
            control.unknown();
            return BridgeError::cleanup_unknown();
        }
        Error::Busy => p::Reason::Busy,
        Error::AccessDenied | Error::Expired => p::Reason::Expired,
        Error::Conflict => p::Reason::TargetChanged,
        Error::InvalidRequest => p::Reason::InvalidInput,
        Error::Unavailable | Error::UnsupportedPlatform | Error::RecoveryRequired => {
            p::Reason::StateUnavailable
        }
    };
    p::refused(reason)
}

pub(crate) struct VersionEnrollmentGoGate {
    document: Weak<Inner>,
    lane: Weak<Lane>,
}
impl VersionEnrollmentGoGate {
    pub(crate) fn claim(
        &self,
        id: &str,
        digest: &str,
        request: &Arc<p::Request>,
        claim: impl FnOnce() -> bool,
    ) -> Result<Vec<u8>, BridgeError> {
        let document = DocumentBinding {
            inner: self.document.upgrade().ok_or_else(changed)?,
        };
        let lane = self.lane.upgrade().ok_or_else(changed)?;
        let state = document.lock();
        let edit = document
            .inner
            .bridge
            .edits
            .saved_registration_guard(&document.inner.session_identity)?;
        document.enrollment_current_with_edit(&state, &lane, &edit)?;
        let retained = held(&lane.request, &lane.control)?;
        if !retained.as_ref().is_some_and(|r| Arc::ptr_eq(r, request)) {
            return Err(changed());
        }
        let result = state.github.version_enrollment_go(
            &lane.original.pins,
            &lane.control,
            id,
            digest,
            request,
            Instant::now(),
            claim,
        );
        if result.is_ok() {
            if let Some(entry) = &lane.agent {
                // Native GO is a conservative possible-effect fact, recorded
                // before the only protected bytes leave this original gate.
                if entry.go(&lane.id).is_err() {
                    entry.unknown(crate::service_github_action_protocol::Reason::CleanupUnknown);
                    return Err(BridgeError::cleanup_unknown());
                }
            }
        }
        drop(edit);
        result
    }
}
struct WaitGuard {
    document: DocumentBinding,
    lane: Arc<Lane>,
    returned: bool,
}
impl Drop for WaitGuard {
    fn drop(&mut self) {
        if !self.returned {
            self.lane.control.unknown();
            agent::unknown(&self.lane);
            self.document.inner.changes.send_modify(|_| {});
        }
    }
}

impl DocumentBinding {
    fn enrollment_current(
        &self,
        state: &DocumentState,
        lane: &Arc<Lane>,
    ) -> Result<(), BridgeError> {
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        self.enrollment_current_with_edit(state, lane, &edit)
    }
    fn enrollment_current_with_edit(
        &self,
        state: &DocumentState,
        lane: &Arc<Lane>,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
    ) -> Result<(), BridgeError> {
        // Pure same-Document gate only. Never call Supervisor.can_exit, Host,
        // Store, census or another worker while its original writer awaits GO.
        passive_document_state_gate(state)?;
        if state.maintenance.closed()
            || !state.lifetime.original_bound()
            || state.lost_observed
            || version_allocation::pending(state)
            || !lane.control.current()
            || Instant::now() >= lane.end
            || !state
                .version_enrollment
                .lane
                .as_ref()
                .is_some_and(|l| Arc::ptr_eq(l, lane))
            || !self
                .inner
                .android_registration_control
                .matches_epoch(lane.original.input_epoch)
        {
            return Err(changed());
        }
        let (generation, root) = self
            .inner
            .bridge
            .native_project(&lane.original.pins.project_id)
            .map_err(|_| changed())?;
        if generation != lane.original.pins.generation || root != lane.original.root {
            return Err(changed());
        }
        if !edit.matches(&lane.original.stamp) {
            return Err(changed());
        }
        state
            .github
            .version_enrollment_current(&lane.original.pins, &lane.control, Instant::now())
    }
    fn enrollment_begin(
        &self,
        project: &str,
        review_id: Option<&str>,
        entry: Option<&Arc<AgentEntry>>,
    ) -> Result<(Arc<Lane>, Option<p::Offer>), BridgeError> {
        let started = Instant::now();
        if !crate::protocol::valid_id(project) {
            return Err(BridgeError::invalid());
        }
        // Native random original ID, never a renderer-selected operation key.
        let id = crate::service_protocol::Id::random()
            .map_err(|_| p::refused(p::Reason::RuntimeUnavailable))?
            .as_str()
            .to_owned();
        let work_end = started
            .checked_add(Duration::from_secs(60))
            .ok_or_else(BridgeError::invalid)?;
        let mut state = self.lock();
        self.enrollment_origin_allowed(&state, project, review_id, entry)?;
        state.version_enrollment.status(started);
        if pending(&state) {
            return Err(busy());
        }
        self.passive_query_gate_locked(&state, &self.inner.bridge)?;
        if self.github_gate(&state) != GitHubReason::None
            || !self.inner.bridge.supervisor.version_enrollment_available()
            || !self.inner.bridge.supervisor.can_exit()
            || !self
                .inner
                .android_registration_control
                .idle_for_saved_observation()
        {
            return Err(p::refused(p::Reason::RuntimeUnavailable));
        }
        let (generation, root) = self
            .inner
            .bridge
            .native_project(project)
            .map_err(|_| changed())?;
        let binding = github_setup_project_binding(&root)?; // Correlation only, never Setup authority.
        let edit = self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
        self.enrollment_origin_current(&state, project, review_id, entry, generation, &root, &edit, started)?;
                                                            // The previous known-returned lane may retire only on this NEW explicit
                                                            // action. Pending/uncertain jobs never turn into a smaller clone credit.
        drop(edit);
        state.version_enrollment.lane = None;
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        {
            let bytes = lookup_memory::retained_document_bytes(&self.inner, &state)
                .map_err(|_| busy())?
                .checked_add(
                    installation_memory::additional_document_bytes(self, &state)
                        .map_err(|_| busy())?,
                )
                .ok_or_else(busy)?;
            let future = crate::macos_history_inventory::CODE_CONTROL_RESERVE
                .checked_add(p::RETAINED_LIMIT)
                .ok_or_else(busy)?;
            crate::macos_history_inventory::admission_bytes(bytes, future).ok_or_else(busy)?;
        }
        let edit = self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
        self.enrollment_origin_current(&state, project, review_id, entry, generation, &root, &edit, started)?;
        let reviewed = match review_id {
            Some(id) => {
                if !state.version_enrollment.review.as_ref().is_some_and(|r| {
                    r.id == id
                        && r.end > started
                        && r.original.pins.project_id == project
                        && r.original.root == root
                        && edit.matches(&r.original.stamp)
                        && agent::producer_ready(r)
                        && self
                            .inner
                            .android_registration_control
                            .matches_epoch(r.original.input_epoch)
                }) {
                    return Err(p::refused(p::Reason::ReviewChanged));
                }
                state.version_enrollment.review.take()
            }
            None => {
                state.version_enrollment.review = None;
                None
            }
        };
        state.version_enrollment.view.review = None;
        state.version_enrollment.view.phase = p::Phase::Refused;
        state.version_enrollment.view.reason = p::Reason::ReviewChanged;
        state.version_enrollment.bump();
        let stamp = if reviewed.is_none() {
            Some(edit.stamp()?)
        } else {
            None
        };
        let input_epoch = self.inner.android_registration_control.epoch()?;
        let control = Arc::new(VersionEnrollmentControl::new());
        if let Some(entry) = entry { control.bind_agent(entry.scope())?; }
        let pins = state.github.begin_version_enrollment(
            project,
            generation,
            &binding,
            control.clone(),
            reviewed.as_ref().map(|r| &r.original.pins),
            started,
        )?;
        let end = work_end.min(pins.credential_end);
        let original = match &reviewed {
            Some(r) => r.original.clone(),
            None => Arc::new(Original {
                root,
                stamp: stamp.expect("captured before connection hold"),
                pins,
                input_epoch,
            }),
        };
        let lane = Arc::new(Lane {
            id: id.clone(),
            agent: entry.cloned(),
            original,
            control,
            end,
            request: Mutex::new(None),
            ticket: Mutex::new(None),
            joined: Mutex::new(None),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            host_ticket: Mutex::new(None),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            jobs: AsyncMutex::new(None),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            state_failure: Mutex::new(None),
        });
        state.version_enrollment.lane = Some(lane.clone());
        if let Some(entry) = &lane.agent {
            if entry.enrollment_attached(&lane.id).is_err() {
                lane.control.unknown();
                agent::unknown(&lane);
                return Err(BridgeError::cleanup_unknown());
            }
        }
        state.version_enrollment.view.project_id = Some(project.into());
        state.version_enrollment.view.operation_id = Some(id);
        state.version_enrollment.view.review = None;
        state.version_enrollment.view.phase = if reviewed.is_some() {
            p::Phase::Connecting
        } else {
            p::Phase::Reading
        };
        state.version_enrollment.view.reason = p::Reason::None;
        state.version_enrollment.bump();
        drop(edit);
        drop(state);
        self.inner.changes.send_modify(|_| {});
        Ok((lane, reviewed.map(|r| r.offer)))
    }
    async fn enrollment_read(
        &self,
        lane: &Arc<Lane>,
        request: p::Request,
    ) -> Result<Arc<VersionEnrollmentJoined>, BridgeError> {
        let request = Arc::new(request);
        let wait = {
            let state = self.lock();
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            self.enrollment_current_with_edit(&state, lane, &edit)?;
            let mut stored = held(&lane.request, &lane.control)?;
            let mut ticket = held(&lane.ticket, &lane.control)?;
            if stored.is_some() || ticket.is_some() {
                return Err(BridgeError::cleanup_unknown());
            }
            *stored = Some(request.clone());
            let gate = VersionEnrollmentGoGate {
                document: Arc::downgrade(&self.inner),
                lane: Arc::downgrade(lane),
            };
            let admitted =
                VersionEnrollmentAdmission::new(request, gate, lane.control.clone(), lane.end)?;
            *ticket = Some(
                self.inner
                    .bridge
                    .supervisor
                    .start_version_enrollment(admitted)?,
            );
            let wait = ticket
                .as_ref()
                .ok_or_else(BridgeError::cleanup_unknown)?
                .wait_original();
            drop(edit);
            wait
        };
        let joined = Arc::new(wait.returned().await?);
        // Retain the actual join BEFORE any later check can fail; a result
        // callback alone cannot release the native ticket or Store use.
        *held(&lane.joined, &lane.control)? = Some(joined.clone());
        let mut state = self.lock();
        state.github.observe_version_enrollment_control(
            &lane.original.pins,
            &lane.control,
            &joined,
        )?;
        Ok(joined)
    }
    fn enrollment_offer(
        &self,
        lane: &Arc<Lane>,
        joined: &VersionEnrollmentJoined,
    ) -> Result<p::Offer, BridgeError> {
        let state = self.lock();
        self.enrollment_current(&state, lane)?;
        let reply = joined.outcome().as_ref().map_err(Clone::clone)?;
        reply
            .result
            .offer
            .clone()
            .filter(|_| reply.result.reason == p::Reason::None)
            .ok_or_else(|| p::refused(reply.result.reason))
    }
    pub(crate) async fn review_version_enrollment(&self, project: &str) -> Result<p::Status, BridgeError> {
        self.review_version_enrollment_original(project, None).await
    }
    pub(in crate::asset_session) async fn review_version_enrollment_original(
        &self, project: &str, entry: Option<Arc<AgentEntry>>,
    ) -> Result<p::Status, BridgeError> {
        let (lane, _) = self
            .enrollment_begin(project, None, entry.as_ref())
            .map_err(p::not_started)?;
        let mut guard = WaitGuard {
            document: self.clone(),
            lane: lane.clone(),
            returned: false,
        };
        let request = p::Request {
            kind: p::Kind::Review,
            target: lane.original.pins.target.clone(),
            review: None,
            previous: None,
        };
        agent::drive(self, &lane, async {
            let outcome = match self.enrollment_read(&lane, request).await {
                Ok(joined) => self.enrollment_offer(&lane, &joined),
                Err(e) => Err(e),
            };
            let status = self.enrollment_finish(&lane, outcome, false).await?;
            guard.returned = true;
            Ok(status)
        }).await
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn enrollment_native(&self, lane: &Arc<Lane>) -> Result<NativeProject, BridgeError> {
        let state = self.lock();
        self.enrollment_current(&state, lane)?;
        let (device, inode) = lane
            .original
            .root
            .identity
            .posix()
            .map_err(|_| changed())?
            .service_identity();
        Ok(NativeProject {
            runtime_id: lane.original.pins.project_id.clone(),
            canonical_root: lane.original.root.path.clone(),
            device,
            inode,
            registration_generation: lane.original.pins.generation,
            document_identity: self.inner.session_identity.clone(),
            input_revision: lane.original.input_epoch,
        })
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn enrollment_state_error(lane: &Lane, error: StateError) -> BridgeError {
        match lane.state_failure.lock() {
            Ok(mut v) => {
                v.get_or_insert(error);
            }
            Err(_) => lane.control.unknown(),
        }
        p::refused(p::Reason::StateUnavailable)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    async fn enrollment_connect(
        &self,
        lane: &Arc<Lane>,
        offer: p::Offer,
        app_data: &Path,
    ) -> Result<p::Offer, BridgeError> {
        let host = &self.inner.bridge.application_service;
        let native = self.enrollment_native(lane)?;
        {
            let state = self.lock();
            self.enrollment_current(&state, lane)?;
            let roster = self.inner.bridge.native_roster().map_err(|_| changed())?;
            // These three Host admissions are TRY-only memory checks. All
            // actual initialization/registration/state reads happen below.
            host.reserve_native_state_location(app_data, &roster.roots)
                .map_err(|e| host_error(&lane.control, e))?;
            let ticket = host
                .begin_native_state_until(native.clone(), lane.end)
                .map_err(|e| host_error(&lane.control, e))?;
            *held(&lane.host_ticket, &lane.control)? = Some(Arc::new(ticket));
        }
        let ticket = held(&lane.host_ticket, &lane.control)?
            .as_ref()
            .ok_or_else(BridgeError::cleanup_unknown)?
            .clone();
        let prepared = host.prepare_native_state(&ticket, app_data).await;
        drop(ticket);
        prepared.map_err(|e| host_error(&lane.control, e))?;
        let current = self.enrollment_native(lane)?;
        let ready = {
            let mut slot = held(&lane.host_ticket, &lane.control)?;
            let ticket = slot.take().ok_or_else(BridgeError::cleanup_unknown)?;
            let ticket = match Arc::try_unwrap(ticket) {
                Ok(ticket) => ticket,
                Err(original) => {
                    *slot = Some(original);
                    lane.control.unknown();
                    return Err(BridgeError::cleanup_unknown());
                }
            };
            Arc::new(
                host.finish_native_state(ticket, &current)
                    .map_err(|e| host_error(&lane.control, e))?,
            )
        };
        // The original ready/store/project mapping stays retained before the
        // first start-latched native job may begin_use or read the namespace.
        let previous = {
            let mut slot = lane.jobs.lock().await;
            if slot.is_some() {
                return Err(BridgeError::cleanup_unknown());
            }
            *slot = Some(
                Jobs::new(ready.clone(), offer.clone(), lane.control.clone(), lane.end)
                    .map_err(|e| Self::enrollment_state_error(lane, e))?,
            );
            let jobs = slot.as_mut().ok_or_else(BridgeError::cleanup_unknown)?;
            jobs.register_load()
                .map_err(|e| Self::enrollment_state_error(lane, e))?;
            host.native_state_current(&ready, &self.enrollment_native(lane)?)
                .map_err(|e| host_error(&lane.control, e))?;
            {
                let state = self.lock();
                let edit = self
                    .inner
                    .bridge
                    .edits
                    .saved_registration_guard(&self.inner.session_identity)?;
                self.enrollment_current_with_edit(&state, lane, &edit)?;
                jobs.release()
                    .map_err(|e| Self::enrollment_state_error(lane, e))?;
            }
            jobs.join()
                .await
                .map_err(|e| Self::enrollment_state_error(lane, e))?;
            jobs.previous().map_err(|e| {
                let error = Self::enrollment_state_error(lane, e);
                if jobs.state_too_large() {
                    p::refused(p::Reason::StateTooLarge)
                } else {
                    error
                }
            })?
        }; // Drop this exact job-book borrow before worker GO enters Doc.
        let request = p::Request {
            kind: p::Kind::Confirm,
            target: lane.original.pins.target.clone(),
            review: Some(offer.clone()),
            previous,
        };
        self.enrollment_after_load(lane, request, ready).await
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    async fn enrollment_after_load(
        &self,
        lane: &Arc<Lane>,
        request: p::Request,
        ready: Arc<crate::application_service_host::NativeStateReady>,
    ) -> Result<p::Offer, BridgeError> {
        let joined = self.enrollment_read(lane, request).await?;
        let offer = self.enrollment_offer(lane, &joined)?;
        let current = self.enrollment_native(lane)?;
        self.inner
            .bridge
            .application_service
            .native_state_current(&ready, &current)
            .map_err(|e| host_error(&lane.control, e))?;
        let mut guard = lane.jobs.lock().await;
        let jobs = guard.as_mut().ok_or_else(BridgeError::cleanup_unknown)?;
        jobs.register_commit(joined)
            .map_err(|e| Self::enrollment_state_error(lane, e))?;
        {
            let state = self.lock();
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            self.enrollment_current_with_edit(&state, lane, &edit)?;
            jobs.release()
                .map_err(|e| Self::enrollment_state_error(lane, e))?;
        }
        jobs.join()
            .await
            .map_err(|e| Self::enrollment_state_error(lane, e))?;
        jobs.committed().map_err(|e| {
            let error = Self::enrollment_state_error(lane, e);
            if jobs.state_too_large() {
                p::refused(p::Reason::StateTooLarge)
            } else {
                error
            }
        })?;
        Ok(offer)
    }
    pub(crate) async fn confirm_version_enrollment(&self, project: &str,
        review_id: &str, app_data: &Path) -> Result<p::Status, BridgeError> {
        self.confirm_version_enrollment_original(project, review_id, app_data, None).await
    }
    pub(in crate::asset_session) async fn confirm_version_enrollment_original(
        &self, project: &str, review_id: &str, app_data: &Path,
        entry: Option<Arc<AgentEntry>>,
    ) -> Result<p::Status, BridgeError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let (lane, offer) = self
                .enrollment_begin(project, Some(review_id), entry.as_ref())
                .map_err(p::not_started)?;
            let mut guard = WaitGuard {
                document: self.clone(),
                lane: lane.clone(),
                returned: false,
            };
            agent::drive(self, &lane, async {
                let outcome = self.enrollment_connect(&lane,
                    offer.ok_or_else(BridgeError::cleanup_unknown)?, app_data).await;
                let status = self.enrollment_finish(&lane, outcome, true).await?;
                guard.returned = true;
                Ok(status)
            }).await
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (project, review_id, app_data, entry);
            Err(p::not_started(p::refused(p::Reason::RuntimeUnavailable)))
        }
    }
    async fn enrollment_finish(
        &self,
        lane: &Arc<Lane>,
        mut outcome: Result<p::Offer, BridgeError>,
        connect: bool,
    ) -> Result<p::Status, BridgeError> {
        // The failed original action must contract cleanup BEFORE any Host,
        // state-job or token-retirement wait. Native/job cutoffs already held
        // by this same control are never replaced by this later observation.
        if outcome.is_err() {
            lane.control.stop();
        }
        let joined = held(&lane.joined, &lane.control)?.clone();
        if lane.control.uncertain() || joined.is_none() && !lane.control.never_admitted() {
            return Err(BridgeError::cleanup_unknown());
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.enrollment_cancel_host(lane)?;
            let mut guard = lane.jobs.lock().await;
            if let Some(jobs) = guard.as_mut() {
                jobs.stop();
                if jobs.join_pending() {
                    jobs.join()
                        .await
                        .map_err(|e| Self::enrollment_state_error(lane, e))?;
                }
            }
            if held(&lane.state_failure, &lane.control)?
                .as_ref()
                .is_some_and(|e| {
                    e.effect == Effect::Unknown
                        || e.durability == Durability::Unknown
                        || e.cleanup == Cleanup::Unknown
                })
            {
                lane.control.unknown();
                return Err(BridgeError::cleanup_unknown());
            }
            if let Some(jobs) = guard.as_mut() {
                jobs.retire_original(joined.as_deref())
                    .map_err(|e| Self::enrollment_state_error(lane, e))?;
            }
        }
        let mut state = self.lock();
        if !state
            .version_enrollment
            .lane
            .as_ref()
            .is_some_and(|v| Arc::ptr_eq(v, lane))
        {
            return Err(BridgeError::cleanup_unknown());
        }
        if outcome.is_ok() {
            if let Err(e) = self.enrollment_current(&state, lane) {
                lane.control.stop();
                outcome = Err(e);
            }
        }
        let review_end = if outcome.is_ok() && !connect {
            Some(
                joined
                    .as_ref()
                    .ok_or_else(BridgeError::cleanup_unknown)?
                    .settled_at()
                    .checked_add(Duration::from_secs(120))
                    .ok_or_else(BridgeError::cleanup_unknown)?
                    .min(lane.original.pins.credential_end),
            )
        } else {
            None
        };
        let mut ticket = held(&lane.ticket, &lane.control)?;
        lane.control.returned(lane.end)?;
        state.github.finish_version_enrollment(&lane.control)?;
        ticket.take(); // Only after actual observer + all state jobs returned.
        let s = &mut state.version_enrollment;
        match outcome {
            Ok(_) if connect => {
                s.view.phase = p::Phase::Connected;
                s.view.reason = p::Reason::Connected;
                s.review = None;
                s.view.review = None;
            }
            Ok(offer) => {
                let end = review_end.ok_or_else(BridgeError::cleanup_unknown)?;
                s.view.review = Some(p::ReviewView {
                    id: lane.id.clone(),
                    repository: offer.authority.repository.clone(),
                    version: offer.version.clone(),
                    reservations: offer.checkpoint.sequence,
                });
                s.review = Some(Review {
                    id: lane.id.clone(),
                    identity: Arc::new(()),
                    producer: lane.agent.as_ref().map(Arc::downgrade),
                    original: lane.original.clone(),
                    offer,
                    end,
                });
                s.view.phase = p::Phase::Reviewed;
                s.view.reason = p::Reason::None;
            }
            Err(error) => {
                let reason = error
                    .code
                    .strip_prefix("version_enrollment_")
                    .and_then(|v| serde_json::from_value(Value::String(v.replace('_', "-"))).ok())
                    .unwrap_or(p::Reason::ResponseInvalid);
                s.view.phase = p::Phase::Refused;
                s.view.reason = reason;
                s.view.review = None;
                s.review = None;
            }
        }
        s.bump();
        let result = s.status(Instant::now());
        drop(ticket);
        drop(state);
        agent::returned(lane, &result, connect);
        self.inner.changes.send_modify(|_| {});
        Ok(result)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn enrollment_cancel_host(&self, lane: &Lane) -> Result<(), BridgeError> {
        // OFF Doc. Keep the sole slot while using the exact original ticket;
        // no extra Arc may race its later consuming finish. Conflict can only
        // mean this native-created ticket is already retired, never permission
        // to cancel a newer startup. Actual prepare still has to return.
        let slot = held(&lane.host_ticket, &lane.control)?;
        if let Some(ticket) = slot.as_ref() {
            match self
                .inner
                .bridge
                .application_service
                .cancel_native_state_ticket(ticket)
            {
                Ok(()) | Err(crate::service_protocol::Error::Conflict) => {}
                Err(error) => return Err(host_error(&lane.control, error)),
            }
        }
        Ok(())
    }
    pub(crate) fn version_enrollment_status(&self) -> p::Status {
        self.lock().version_enrollment.status(Instant::now())
    }
    pub(crate) fn cancel_version_enrollment(&self, id: &str) -> Result<p::Status, BridgeError> {
        let mut state = self.lock();
        if state.version_enrollment.view.operation_id.as_deref() != Some(id) {
            return Err(changed());
        }
        stop(&mut state);
        let lane = state.version_enrollment.lane.clone();
        let result = state.version_enrollment.status(Instant::now());
        drop(state);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(lane) = lane {
            self.enrollment_cancel_host(&lane)?;
        }
        self.inner.changes.send_modify(|_| {});
        Ok(result)
    }
}
