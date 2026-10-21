//! Retained, default-dormant host of the existing read-only application service.
//!
//! Desktop admission uses the real DocumentBinding under its original lock.
//! Explicit foreground history instead obtains its own genuine SourceBook
//! PRE/exclusion/POST, never a synthetic Document. Neither origin constructs
//! an engine or settles an independent core action.
use crate::{
    asset_commands::Reason,
    asset_source::{self, ApplicationDirectoryExclusion, ProjectProbe, RegisteredRoot, SourceBook},
    application_service::{ApplicationService, ProjectBinding, ReadAccessStatus},
    application_state_store::{ApplicationDirectoryIdentity, Cleanup, Durability, Effect, NativeUse, PrivateStateDirectory, StateError},
    installed_cli_ipc::{self, ServerHandle},
    service_protocol as p,
};
use p::Error;
use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, TryLockError},
    time::{Duration, Instant},
};
use tokio::sync::Mutex as AsyncMutex;

#[path = "application_service_android_tools.rs"]
mod android_tools;
#[path = "application_service_repository_summary.rs"]
mod repository_summary;

#[path = "application_service_identity_history.rs"]
mod identity_history;
pub(crate) use identity_history::{IdentityCapture, IdentityObservation, IdentitySource, identity_history_document_backing_bytes};

#[path = "application_service_upload_key.rs"]
mod upload_key;
#[path = "application_service_headless.rs"]
mod headless;
use headless::StartupRef;

const ACCESS_LIFETIME: Duration = Duration::from_secs(3600);
// Work admission is not the user lease. Bounded synchronous native calls have
// checkpoints; this does not claim that a stalled kernel call is preemptible.
const STARTUP_WORK: Duration = crate::application_service::HISTORY_STARTUP_WORK;

/// Native-only facts, not an admission witness. Construct and compare these
/// ONLY inside the genuine DocumentBinding admission callback, including its
/// original SavedEditStamp recheck. No Serde/Debug exposes a path or permits
/// JSON to manufacture the original document's Arc identity.
#[derive(Clone)]
pub(crate) struct NativeProject {
    pub(crate) runtime_id: String,
    pub(crate) canonical_root: PathBuf,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) registration_generation: u32,
    pub(crate) document_identity: Arc<()>,
    pub(crate) input_revision: u64,
}
impl NativeProject {
    fn same_registration(&self, other: &Self) -> bool {
        self.runtime_id == other.runtime_id
            && self.canonical_root == other.canonical_root
            && self.device == other.device && self.inode == other.inode
            && self.registration_generation == other.registration_generation
            && Arc::ptr_eq(&self.document_identity, &other.document_identity)
    }
    fn same_input(&self, other: &Self) -> bool {
        self.same_registration(other) && self.input_revision == other.input_revision
    }
    fn valid(&self) -> bool {
        !self.runtime_id.is_empty() && self.runtime_id.len() <= 64
            && self.runtime_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && self.registration_generation != 0 && self.inode != 0
            && ordinary_absolute(&self.canonical_root)
    }
}

pub(crate) struct AllowTicket {
    owner: Arc<()>, epoch: u64, source_epoch: u64,
    original: NativeProject, expires: Instant, startup_expires: Instant,
    apple_preparation: Option<std::sync::Weak<crate::service_apple_provisioning_requests::preparation::Entry>>,
}
/// Explicit native Desktop setup, not an agent-access grant. The wrapped
/// ticket is never passed to finish_allow or exposed through IPC.
pub(crate) struct NativeStateTicket(AllowTicket);
/// The original initialized storage binding. This is not a worker-finality
/// receipt: native consumers must separately hold the Store's NativeUse until
/// their original jobs (including the last journal write) have actually joined.
pub(crate) struct NativeStateReady {
    owner: Arc<()>, source_epoch: u64, original: NativeProject,
    store: Arc<PrivateStateDirectory>, project: ProjectBinding,
}
impl NativeStateReady {
    pub(crate) fn store(&self) -> &Arc<PrivateStateDirectory> { &self.store }
    pub(crate) fn project_binding(&self) -> &ProjectBinding { &self.project }
    /// Call OFF document/host guards, in the parent's retained original IO job.
    /// Retain the returned lease before admitting any subsequent native work.
    pub(crate) fn begin_use(self: &Arc<Self>) -> Result<NativeStateLease, StateError> {
        let native_use = Arc::new(self.store.begin_native_use()?);
        Ok(NativeStateLease { ready: self.clone(), native_use })
    }
}
/// No Drop cleanup: a missing original parent must not make an active native
/// use look joined. The actual all-jobs receipt gates Store token retirement.
pub(crate) struct NativeStateLease {
    ready: Arc<NativeStateReady>, native_use: Arc<NativeUse>,
}
impl NativeStateLease {
    pub(crate) fn context(&self) -> &NativeStateReady { &self.ready }
    pub(crate) fn store(&self) -> &Arc<PrivateStateDirectory> { &self.ready.store }
    pub(crate) fn project_binding(&self) -> &ProjectBinding { &self.ready.project }
    pub(crate) fn native_use(&self) -> &Arc<NativeUse> { &self.native_use }
}
pub(crate) struct SnapshotTicket {
    owner: Arc<()>, source_epoch: u64, original: NativeProject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HostStage {
    Admission, OpenStore, OpenService, Register, Start, Publish, Invalidate,
    Revoke, Join, StopService, CloseStore, ProbeSources, CloseSources,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HostFailure {
    pub(crate) stage: HostStage,
    pub(crate) code: Error,
    /// Preserve the original structured storage error where that API returns
    /// one. An Error-only service API does not authorize inventing these facts.
    pub(crate) state: Option<StateError>,
}
impl HostFailure {
    fn simple(stage: HostStage, code: Error) -> Self { Self { stage, code, state: None } }
    fn storage(stage: HostStage, state: StateError) -> Self { Self { stage, code: state.code, state: Some(state) } }
    fn unknown(self) -> bool {
        self.code == Error::StateUnknown || self.state.is_some_and(|state|
            state.effect == Effect::Unknown || state.durability == Durability::Unknown || state.cleanup == Cleanup::Unknown)
    }
}

#[derive(Clone)]
pub(crate) struct HostShutdownReport {
    pub(crate) failures: Vec<HostFailure>,
    pub(crate) workers_joined: Option<usize>,
    originals_closed: bool,
}
impl HostShutdownReport {
    /// A refused feature is not failed cleanup. Conversely a later successful
    /// close never erases an earlier unconfirmed effect/durability/cleanup.
    pub(crate) fn settled(&self) -> bool {
        self.originals_closed && !self.failures.iter().any(|failure| failure.unknown())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase { Dormant, Starting, Ready, Listening, Retiring, Closed }
struct Control {
    phase: Phase, epoch: u64, source_epoch: u64, pending: Option<u64>, prepared: Option<u64>,
    prepared_binding: Option<ProjectBinding>,
    native_location: Option<PathBuf>, native_roots: Vec<RegisteredRoot>,
    store: Option<Arc<PrivateStateDirectory>>,
    service: Option<Arc<ApplicationService>>,
    registered: BTreeMap<String, NativeProject>,
    fence: Option<Error>, failures: Vec<HostFailure>,
}
impl Control {
    fn available(&self) -> Result<(), Error> {
        if let Some(error) = self.fence { return Err(error); }
        if matches!(self.phase, Phase::Retiring | Phase::Closed) { return Err(Error::Unavailable); }
        Ok(())
    }
    fn retire_pending(&mut self) -> Result<(), Error> {
        self.pending = None; self.prepared = None; self.prepared_binding = None;
        self.epoch = match self.epoch.checked_add(1) {
            Some(value) => value,
            None => { self.fail(HostFailure::simple(HostStage::Admission, Error::StateUnknown)); return Err(Error::StateUnknown); }
        };
        Ok(())
    }
    fn remember(&mut self, failure: HostFailure) {
        // Closed stages/codes bound this list; repeated refused callers cannot
        // grow an unbounded diagnostic log. No raw error text is retained.
        if !self.failures.contains(&failure) { self.failures.push(failure); }
    }
    fn fail(&mut self, failure: HostFailure) {
        self.remember(failure);
        self.fence.get_or_insert(failure.code);
        self.pending = None; self.prepared = None; self.prepared_binding = None;
        // A permanent Host failure must revoke reads immediately, without
        // waiting behind a service mutex whose owner may be doing Store IO.
        // The original service/listener still perform their actual shutdown.
        if let Some(service) = &self.service { service.fence_native_history(); }
    }
}
#[derive(Default)]
struct Originals {
    location: Option<PathBuf>,
    source_epoch: Option<u64>, source: Option<SourceBook>, exclusion: Option<ApplicationDirectoryExclusion>,
    store: Option<Arc<PrivateStateDirectory>>,
    service: Option<Arc<ApplicationService>>,
    server: Option<ServerHandle>,
    shutdown: Option<HostShutdownReport>,
    headless_sources: Option<headless::Sources>,
}

pub(crate) struct ApplicationHost {
    identity: Arc<()>, control: Mutex<Control>, originals: AsyncMutex<Originals>,
    history_lease: Option<Arc<crate::application_service::HistoryLease>>,
    history_started: std::sync::atomic::AtomicBool,
    history: Arc<identity_history::History>,
    android_tools: Arc<crate::service_android_tools::ObservationSlot>,
    repository_summary: Arc<crate::service_repository_summary::ObservationSlot>,
}
impl ApplicationHost {
    /// No path lookup, directory, reservation, socket or background task.
    pub(crate) fn new() -> Self {
        Self { identity: Arc::new(()), history_lease: None, history_started: std::sync::atomic::AtomicBool::new(false), control: Mutex::new(Control {
            phase: Phase::Dormant, epoch: 0, source_epoch: 0, pending: None, prepared: None, prepared_binding: None,
            native_location: None, native_roots: Vec::new(), store: None, service: None,
            registered: BTreeMap::new(), fence: None, failures: Vec::new(),
        }), originals: AsyncMutex::new(Originals::default()), history: Arc::new(identity_history::History::default()),
            android_tools: Arc::new(crate::service_android_tools::ObservationSlot::default()),
            repository_summary: Arc::new(crate::service_repository_summary::ObservationSlot::default()) }
    }
    fn lock(&self) -> Result<MutexGuard<'_, Control>, Error> {
        match self.control.lock() {
            Ok(state) => Ok(state),
            Err(poisoned) => Err(Self::reject_poisoned_control(poisoned.into_inner())),
        }
    }
    /// Native admission runs under the original document lock. Older service
    /// callers may hold Control across IO, so never queue behind that work.
    fn try_native_lock(&self) -> Result<MutexGuard<'_, Control>, Error> {
        match self.control.try_lock() {
            Ok(state) => Ok(state),
            Err(TryLockError::WouldBlock) => Err(Error::Busy),
            Err(TryLockError::Poisoned(poisoned)) => Err(Self::reject_poisoned_control(poisoned.into_inner())),
        }
    }
    fn reject_poisoned_control(mut state: MutexGuard<'_, Control>) -> Error {
        // Cleanup ONLY: never recover an admission from a poisoned guard.
        state.pending = None; state.prepared = None; state.prepared_binding = None;
        state.phase = Phase::Retiring;
        state.fence.get_or_insert(Error::StateUnknown);
        state.remember(HostFailure::simple(HostStage::Admission, Error::StateUnknown));
        let service = state.service.clone();
        drop(state);
        if let Some(service) = service { service.fence_native_history(); }
        Error::StateUnknown
    }
    fn check_allow(&self, state: &Control, ticket: &AllowTicket) -> Result<(), Error> {
        state.available()?;
        if !Arc::ptr_eq(&self.identity, &ticket.owner) || state.pending != Some(ticket.epoch)
            || state.source_epoch != ticket.source_epoch { return Err(Error::AccessDenied); }
        if Instant::now() >= ticket.expires { return Err(Error::Expired); }
        Ok(())
    }
    fn check_startup(&self, state: &Control, ticket: &AllowTicket) -> Result<(), Error> {
        self.check_allow(state, ticket)?;
        if let Some(entry)=&ticket.apple_preparation{entry.upgrade().ok_or(Error::AccessDenied)?.current()?;}
        if Instant::now() >= ticket.startup_expires { Err(Error::Expired) } else { Ok(()) }
    }
    /// Under the real DocumentBinding lock, inspect the COMPLETE genuine native
    /// roster before beginning Allow. This reservation itself performs no IO;
    /// later project registrations must call check_project_root under that same
    /// original document lock before publishing a new registry member.
    pub(crate) fn reserve_native_location(&self, app_data: &Path,
        registered_roots: &[RegisteredRoot]) -> Result<(), Error> {
        let mut state = self.lock()?;
        Self::reserve_location_locked(&mut state, app_data, registered_roots)
    }
    /// Native preparation holds the Document lock. Never queue that lock
    /// behind an older Host caller performing storage IO under Control.
    pub(crate) fn reserve_native_state_location(&self, app_data: &Path,
        registered_roots: &[RegisteredRoot]) -> Result<(), Error> {
        let mut state = self.try_native_lock()?;
        Self::reserve_location_locked(&mut state, app_data, registered_roots)
    }
    fn reserve_location_locked(state: &mut Control, app_data: &Path,
        registered_roots: &[RegisteredRoot]) -> Result<(), Error> {
        state.available()?;
        if state.phase == Phase::Starting { return Err(Error::Busy); }
        if !ordinary_absolute(app_data)
            || app_data.file_name().and_then(|v| v.to_str()) != Some("dev.mobile-release-kit.desktop")
            || registered_roots.len() > p::PROJECT_LIMIT { return Err(Error::InvalidRequest); }
        if state.native_location.as_ref().is_some_and(|original| original != app_data) { return Err(Error::Conflict); }
        for root in registered_roots {
            let (_, inode) = root.identity.posix().map_err(source_error)?.service_identity();
            if !ordinary_absolute(&root.path) || inode == 0 { return Err(Error::InvalidRequest); }
            if overlap(&root.path, app_data) { return Err(Error::Conflict); }
        }
        if state.native_roots != registered_roots { state.retire_pending()?; }
        state.native_location = Some(app_data.to_owned());
        state.native_roots = registered_roots.to_vec();
        Ok(())
    }
    pub(crate) fn check_project_root(&self, proof: &ProjectProbe) -> Result<(), Error> {
        let mut state = self.lock()?;
        state.available()?;
        // Native creation uses the complete roster captured at admission.
        // Refuse publication BEFORE probe/create, not after private files may
        // already have appeared below a newly selected project.
        if state.phase == Phase::Starting { return Err(Error::Busy); }
        let root = proof.path();
        let (device, inode) = proof.identity().posix().map_err(source_error)?.service_identity();
        if !ordinary_absolute(root) || inode == 0 { return Err(Error::InvalidRequest); }
        if state.native_location.as_ref().is_some_and(|location| overlap(root, location)) { return Err(Error::Conflict); }
        if let Some(store) = state.store.clone() {
            let current = match held_application_root(&store) {
                Ok(root) => root,
                Err(error) => { state.fail(HostFailure::storage(HostStage::Register, error)); return Err(error.code); }
            };
            if !proof.excludes_application(Some(&current)) { return Err(Error::Conflict); }
            store.excludes_project(device, inode).map_err(|error| error.code)?;
        }
        // A dormant Host owns no application-directory exclusion. The same
        // Document's tool cache may still require one; its independent final
        // ProjectProbe validator must check that marker before registration.
        // Absence of our store never waives another owner's marker or errors.
        // A new native registration may arrive between the complete roster
        // reservation and prepare. Keep it in that SAME pre-create exclusion
        // set AND retire pending Allow. A new member cannot inherit an earlier
        // complete-roster proof. After construction its genuine ProjectProbe
        // must have checked BOTH vault and exact current application root.
        let selected = RegisteredRoot { path: root.to_owned(), identity: proof.identity() };
        if state.native_location.is_some() && !state.native_roots.contains(&selected) {
            if state.native_roots.len() == p::PROJECT_LIMIT { return Err(Error::InvalidRequest); }
            state.retire_pending()?;
            state.native_roots.push(selected);
        }
        Ok(())
    }
    /// Capture under real native selection admission; the later genuine source
    /// owner must prove this root, and final registration rematches its marker.
    /// Dormant means no IO. Failure never silently becomes an absent exclusion.
    pub(crate) fn native_exclusion_root(&self) -> Result<Option<RegisteredRoot>, Error> {
        let mut state = self.lock()?;
        state.available()?;
        if state.phase == Phase::Starting { return Err(Error::Busy); }
        let Some(store) = state.store.clone() else { return Ok(None); };
        match held_application_root(&store) {
            Ok(root) => Ok(Some(root)),
            Err(error) => { state.fail(HostFailure::storage(HostStage::Register, error)); Err(error.code) }
        }
    }
    pub(crate) fn begin_allow(&self, original: NativeProject) -> Result<AllowTicket, Error> {
        self.begin_start(original, true, None)
    }
    pub(crate) fn begin_native_state(&self, original: NativeProject) -> Result<NativeStateTicket, Error> {
        self.begin_start(original, false, None).map(NativeStateTicket)
    }
    /// A native action that already owns a deadline cannot buy another full
    /// startup interval. The original smaller bound remains authoritative.
    pub(crate) fn begin_native_state_until(&self, original: NativeProject,
        work_end: Instant) -> Result<NativeStateTicket, Error> {
        self.begin_start(original, false, Some(work_end)).map(NativeStateTicket)
    }
    /// Only the already claimed same Apple preparation can tighten this
    /// native ticket. Its READ/STOP is sampled by the original source callbacks.
    pub(crate) fn bind_apple_preparation(&self,ticket:&mut NativeStateTicket,entry:&Arc<crate::service_apple_provisioning_requests::preparation::Entry>)->Result<(),Error>{
        if !Arc::ptr_eq(&ticket.0.owner,&self.identity)||ticket.0.apple_preparation.is_some()||ticket.0.startup_expires>entry.end()
            ||ticket.0.original.runtime_id!=entry.scope.project.runtime_id{return Err(Error::Conflict);}
        entry.current()?;ticket.0.apple_preparation=Some(Arc::downgrade(entry));Ok(())
    }
    /// Retire only this unfinished ticket. A late caller cannot cancel a newer
    /// startup or close its originals. Actual Host shutdown still joins them.
    pub(crate) fn cancel_native_state_ticket(&self, ticket: &NativeStateTicket) -> Result<(), Error> {
        let mut state = self.try_native_lock()?;
        if !Arc::ptr_eq(&ticket.0.owner, &self.identity)
            || state.pending != Some(ticket.0.epoch) || state.epoch != ticket.0.epoch {
            return Err(Error::Conflict);
        }
        state.retire_pending()
    }
    fn begin_start(&self, original: NativeProject, revoke_read: bool,
        work_end: Option<Instant>) -> Result<AllowTicket, Error> {
        if self.history_lease.is_some() { return Err(Error::AccessDenied); }
        let mut state = if revoke_read { self.lock()? } else { self.try_native_lock()? };
        state.available()?;
        if state.phase == Phase::Starting { return Err(Error::Busy); }
        if work_end.is_some_and(|end| Instant::now() >= end) { return Err(Error::Expired); }
        state.retire_pending()?;
        if let Some(service) = state.service.clone().filter(|_| revoke_read) {
            if let Err(error) = service.revoke_agent_read() {
                state.fail(HostFailure::simple(HostStage::Revoke, error)); return Err(error);
            }
        }
        if !original.valid() { return Err(Error::InvalidRequest); }
        let location = state.native_location.as_ref().ok_or(Error::Unavailable)?;
        if overlap(&original.canonical_root, location) { return Err(Error::Conflict); }
        if !state.native_roots.iter().any(|root| root.path == original.canonical_root
            && root.identity.posix().is_ok_and(|id| id.service_identity() == (original.device, original.inode))) {
            return Err(Error::Conflict);
        }
        let now = Instant::now();
        let expires = now.checked_add(ACCESS_LIFETIME).ok_or(Error::StateUnknown)?;
        let startup_limit = now.checked_add(STARTUP_WORK).ok_or(Error::StateUnknown)?;
        let startup_expires = work_end.map_or(startup_limit, |end| end.min(startup_limit));
        if now >= startup_expires { return Err(Error::Expired); }
        state.pending = Some(state.epoch);
        Ok(AllowTicket { owner: self.identity.clone(), epoch: state.epoch,
            source_epoch: state.source_epoch, original, expires, startup_expires, apple_preparation:None })
    }
    /// Ordinary selection changes retire an unfinished Allow, but do not
    /// transfer, extend or revoke an already granted original project's lease.
    pub(crate) fn retire_allow(&self) -> Result<(), Error> { self.lock()?.retire_pending() }

    /// The caller resolves this fixed native app_local_data_dir, never JSON.
    /// Retain each original immediately, including partial construction. The
    /// existing start() has no internal await: its created ServerHandle is
    /// retained in the same poll, before any subsequent suspension. An observer
    /// cancelled waiting for this async book has not begun construction.
    pub(crate) async fn prepare(&self, ticket: &AllowTicket, app_data: &Path) -> Result<(), Error> {
        self.prepare_storage(StartupRef::Document(ticket), app_data, true).await
    }
    pub(crate) async fn prepare_native_state(&self, ticket: &NativeStateTicket, app_data: &Path) -> Result<(), Error> {
        self.prepare_storage(StartupRef::Document(&ticket.0), app_data, false).await
    }
    fn startup_current(&self, ticket: &AllowTicket) -> Result<(), Error> {
        let state = self.lock()?;
        self.check_startup(&state, ticket)?;
        if state.phase != Phase::Starting { return Err(Error::AccessDenied); }
        Ok(())
    }
    fn startup_failure(&self, failure: HostFailure) -> Error {
        if let Ok(mut state) = self.lock() { state.fail(failure); }
        failure.code
    }
    async fn prepare_storage(&self, ticket: StartupRef<'_>, app_data: &Path, start_agent_endpoint: bool) -> Result<(), Error> {
        let mut originals = self.originals.lock().await;
        let roots = {
            let mut state = self.lock()?;
            ticket.check(self, &state)?;
            if state.phase == Phase::Starting { return Err(Error::Busy); }
            if state.native_location.as_deref() != Some(app_data)
                || overlap(ticket.path(), app_data) {
                return Err(Error::Conflict);
            }
            if originals.location.as_ref().is_some_and(|location| location != app_data) { return Err(Error::Conflict); }
            if originals.source_epoch == Some(ticket.epoch()) { return Err(Error::Conflict); }
            if originals.source.as_ref().is_some_and(|book| !book.not_started() && !book.settled()) {
                state.fail(HostFailure::simple(HostStage::ProbeSources, Error::StateUnknown)); return Err(Error::StateUnknown);
            }
            state.phase = Phase::Starting;
            originals.location = Some(app_data.to_owned());
            // The original book is retained BEFORE native entry. A panic or
            // cancellation cannot erase its original acquisition/close facts.
            // Only explicit native setup/Allow replaces a KNOWN closed book.
            originals.source_epoch = Some(ticket.epoch());
            originals.source = Some(SourceBook::new()); originals.exclusion = None;
            state.native_roots.clone()
        };
        // No Document, Edit or Host.control guard spans source probing, private
        // Store creation or the service's existing serialized registration IO.
        // Originals remains the one retained startup/cleanup owner. Starting
        // fences changes to the complete native roster until this job returns.
        let result = async {
            let result = asset_source::probe_application_directory_exclusion(originals.source.as_mut().unwrap(),
                app_data, &roots, &mut || self.startup_current_origin(ticket).is_err());
            match result {
                Ok(proof) => originals.exclusion = Some(proof),
                Err(reason) => {
                    let error = source_error(reason);
                    return Err(self.startup_failure(HostFailure::simple(HostStage::ProbeSources, error)));
                }
            }
            if !originals.source.as_ref().is_some_and(SourceBook::settled) {
                return Err(self.startup_failure(HostFailure::simple(HostStage::CloseSources, Error::StateUnknown)));
            }
            self.history_source_bound(&originals)?;
            self.startup_current_origin(ticket)?;
            let exclusion = originals.exclusion.as_ref().ok_or(Error::StateUnknown)?;
            let (parent, existing) = exclusion.store_expectation(app_data, &roots).map_err(source_error)?;
            let metadata = |(device, inode, mode, uid, gid)| ApplicationDirectoryIdentity { device, inode, mode, uid, gid };
            let expected = (metadata(parent), existing.map(metadata));
            let excluded_projects: Vec<_> = roots.iter().map(|root| root.identity.posix()
                .map(|id| id.service_identity()).map_err(source_error)).collect::<Result<_, _>>()?;
            if originals.store.is_none() {
                let store = match PrivateStateDirectory::open_after_exclusion(app_data, &excluded_projects, expected, ticket.deadline()) {
                    Ok(store) => Arc::new(store),
                    Err(error) => return Err(self.startup_failure(HostFailure::storage(HostStage::OpenStore, error))),
                };
                // Retain BEFORE rechecking a possibly cancelled native ticket.
                originals.store = Some(store.clone());
                self.lock()?.store = Some(store);
            } else if let Err(error) = originals.store.as_ref().unwrap().check_application_exclusion(expected) {
                return Err(self.startup_failure(HostFailure::storage(HostStage::Register, error)));
            }
            self.startup_current_origin(ticket)?;
            let store = originals.store.as_ref().ok_or(Error::StateUnknown)?.clone();
            for (device, inode) in excluded_projects {
                if let Err(error) = store.excludes_project(device, inode) {
                    return Err(self.startup_failure(HostFailure::storage(HostStage::Register, error)));
                }
            }
            self.startup_current_origin(ticket)?;
            // The service is the existing local project/history owner, not an
            // agent grant. Native setup needs its stable IDs without an IPC
            // listener; later explicit Allow reuses these same originals.
            if originals.service.is_none() {
                let opened = match &self.history_lease {
                    Some(lease) => ApplicationService::open_history(store.clone(), lease.clone()),
                    None => ApplicationService::open_with_observations(store.clone(), self.android_tools.clone(), self.repository_summary.clone()),
                };
                let service = match opened {
                    Ok(service) => Arc::new(service),
                    Err(error) => return Err(self.startup_failure(HostFailure::simple(HostStage::OpenService, error))),
                };
                originals.service = Some(service.clone());
                self.lock()?.service = Some(service);
            }
            self.startup_current_origin(ticket)?;
            let service = originals.service.as_ref().ok_or(Error::StateUnknown)?;
            let (device, inode) = ticket.identity()?;
            let binding = service.register_native(ticket.alias(), ticket.path(), device, inode)
                .map_err(|error| self.startup_failure(HostFailure::simple(HostStage::Register, error)))?;
            {
                let mut state = self.lock()?;
                ticket.check(self, &state)?;
                ticket.register(&mut state);
                state.prepared_binding = Some(binding);
            }
            if start_agent_endpoint && originals.server.is_none() {
                let service = originals.service.as_ref().ok_or(Error::StateUnknown)?.clone();
                match installed_cli_ipc::start(service).await {
                    Ok(server) => originals.server = Some(server),
                    Err(error) => return Err(self.startup_failure(HostFailure::simple(HostStage::Start, error))),
                }
            }
            self.startup_current_origin(ticket)?;
            Ok(())
        }.await;
        let mut state = self.lock()?;
        // Never change Retiring/Closed back into a reusable phase. A cancelled
        // ticket may leave real initialized storage, but cannot grant access.
        if state.phase == Phase::Starting {
            state.phase = if originals.server.is_some() { Phase::Listening }
                else if originals.store.is_some() { Phase::Ready } else { Phase::Dormant };
        }
        result?;
        ticket.check(self, &state)?;
        state.prepared = Some(ticket.epoch());
        Ok(())
    }
    pub(crate) fn finish_native_state(&self, ticket: NativeStateTicket, current: &NativeProject) -> Result<NativeStateReady, Error> {
        self.finish_native_state_retained(&ticket, current)
    }
    /// The GitLocal original job retains its sole ticket on a refused or
    /// uncertain handoff. Same pending/epoch/current checks, no cloned ticket
    /// or new authority; an error is not proof that pending remained intact.
    pub(crate) fn finish_native_state_retained(&self, ticket: &NativeStateTicket, current: &NativeProject) -> Result<NativeStateReady, Error> {
        let mut state = self.try_native_lock()?;
        self.check_startup(&state, &ticket.0)?;
        state.pending = None;
        if state.prepared.take() != Some(ticket.0.epoch)
            || !matches!(state.phase, Phase::Ready | Phase::Listening)
            || !ticket.0.original.same_input(current) { return Err(Error::Conflict); }
        let project = state.prepared_binding.take().ok_or(Error::StateUnknown)?;
        if project.canonical_root != current.canonical_root.to_str().ok_or(Error::Conflict)?
            || (project.device, project.inode) != (current.device, current.inode) { return Err(Error::Conflict); }
        Ok(NativeStateReady { owner: self.identity.clone(), source_epoch: state.source_epoch,
            original: current.clone(), project, store: state.store.clone().ok_or(Error::Unavailable)? })
    }
    /// A TRY-only memory context recheck, not a Store read or operation grant.
    pub(crate) fn native_state_current(&self, lease: &NativeStateReady, current: &NativeProject) -> Result<(), Error> {
        let state = self.try_native_lock()?; state.available()?;
        if !matches!(state.phase, Phase::Ready | Phase::Listening) { return Err(Error::Busy); }
        if !Arc::ptr_eq(&self.identity, &lease.owner) || state.source_epoch != lease.source_epoch
            || !lease.original.same_input(current)
            || !state.store.as_ref().is_some_and(|store| Arc::ptr_eq(store, &lease.store)) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    /// Call at the genuine original passive completion, after rechecking the
    /// held native document/root/SavedEditStamp. No old result can grant access
    /// after revoke, replacement selection, input changes or accepted quit.
    pub(crate) fn finish_allow(&self, ticket: AllowTicket, current: &NativeProject,
        snapshot: &serde_json::Value) -> Result<ReadAccessStatus, Error> {
        let mut state = self.lock()?;
        self.check_allow(&state, &ticket)?;
        state.pending = None;
        let prepared = state.prepared.take();
        state.prepared_binding = None;
        if prepared != Some(ticket.epoch) || state.phase != Phase::Listening || !ticket.original.same_input(current) {
            return Err(Error::Conflict);
        }
        let service = state.service.clone().ok_or(Error::Unavailable)?;
        let result = (|| {
            let observation = service.publish_passive_snapshot(&current.runtime_id, snapshot)?;
            let remaining = ticket.expires.saturating_duration_since(Instant::now());
            if remaining.is_zero() { return Err(Error::Expired); }
            service.allow_agent_read(vec![observation.project_id], remaining)
        })();
        if let Err(error) = result {
            // Expiry consumes this consent, not the installation. Re-enabling
            // requires a new explicit native Allow, never an automatic retry.
            if error != Error::Expired { state.fail(HostFailure::simple(HostStage::Publish, error)); }
        }
        result
    }
    // Called OFF Document/Edit guards. Never starts a dormant Host or
    // replaces its service; only the genuine current registration may link.
    pub(crate) fn identity_request_service(&self, original: &NativeProject) -> Result<Arc<ApplicationService>, Error> {
        let state = self.lock()?; state.available()?;
        if state.phase != Phase::Listening { return Err(Error::Unavailable); }
        if !state.registered.get(&original.runtime_id).is_some_and(|bound| bound.same_registration(original)) {
            return Err(Error::Conflict);
        }
        let service = state.service.clone().ok_or(Error::Unavailable)?;
        service.native_history_current()?;
        Ok(service)
    }
    // Memory-only consumer lookup after the existing Host lock; OFF Doc/Edit.
    // Does not initialize, renew READ, fabricate a native registration or run IO.
    pub(crate) fn configuration_service(&self)->Result<Arc<ApplicationService>,Error>{
        let state=self.lock()?;state.available()?;
        if state.phase!=Phase::Listening{return Err(Error::Unavailable);}
        let service=state.service.clone().ok_or(Error::Unavailable)?;
        service.native_history_current()?;Ok(service)
    }
    pub(crate) fn snapshot_ticket(&self, original: &NativeProject) -> Result<Option<SnapshotTicket>, Error> {
        let state = self.lock()?; state.available()?;
        if state.service.is_none() { return Ok(None); }
        let Some(registered) = state.registered.get(&original.runtime_id) else { return Ok(None); };
        if !registered.same_registration(original) { return Err(Error::Conflict); }
        Ok(Some(SnapshotTicket { owner: self.identity.clone(), source_epoch: state.source_epoch, original: original.clone() }))
    }
    pub(crate) fn publish_snapshot(&self, ticket: SnapshotTicket, current: &NativeProject,
        snapshot: &serde_json::Value) -> Result<(), Error> {
        let mut state = self.lock()?; state.available()?;
        if !Arc::ptr_eq(&self.identity, &ticket.owner) || ticket.source_epoch != state.source_epoch
            || !ticket.original.same_input(current)
            || !state.registered.get(&current.runtime_id).is_some_and(|registered| registered.same_registration(current)) {
            return Err(Error::Conflict);
        }
        let service = state.service.clone().ok_or(Error::Unavailable)?;
        match service.publish_passive_snapshot(&current.runtime_id, snapshot) {
            Ok(_) => Ok(()),
            Err(error) => { state.fail(HostFailure::simple(HostStage::Publish, error)); Err(error) }
        }
    }
    /// Invoke synchronously at genuine saved-edit/input mutation admission.
    /// The global stamp conservatively fences outstanding reads across projects
    /// in this small slice; it is not a replacement for domain revocations.
    pub(crate) fn invalidate_native(&self, runtime_id: &str) -> Result<(), Error> {
        self.invalidate_selected(Some(runtime_id))
    }
    pub(crate) fn invalidate_all_native(&self) -> Result<(), Error> {
        self.invalidate_selected(None)
    }
    fn invalidate_selected(&self, runtime_id: Option<&str>) -> Result<(), Error> {
        let mut state = self.lock()?;
        state.retire_pending()?;
        state.source_epoch = match state.source_epoch.checked_add(1) {
            Some(value) => value,
            None => { state.fail(HostFailure::simple(HostStage::Invalidate, Error::StateUnknown)); return Err(Error::StateUnknown); }
        };
        state.available()?;
        let targets: Vec<String> = state.registered.keys()
            .filter(|id| runtime_id.is_none_or(|selected| id.as_str() == selected)).cloned().collect();
        let mut first_error = None;
        if let Some(service) = state.service.clone() {
            for target in targets {
                if let Err(error) = service.invalidate_native(&target) {
                    first_error.get_or_insert(error);
                    state.fail(HostFailure::simple(HostStage::Invalidate, error));
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
    pub(crate) fn status(&self) -> Result<ReadAccessStatus, Error> {
        let state = self.lock()?; state.available()?;
        match &state.service { Some(service) => service.read_access_status(), None => Ok(denied()) }
    }
    pub(crate) fn revoke(&self) -> Result<ReadAccessStatus, Error> {
        let mut state = self.lock()?;
        state.retire_pending()?;
        if let Some(service) = state.service.clone() {
            if let Err(error) = service.revoke_agent_read() {
                state.fail(HostFailure::simple(HostStage::Revoke, error)); return Err(error);
            }
        }
        Ok(denied())
    }
    /// Accepted exit/document retirement only. A cancelled quit does not call
    /// this method, and therefore does not silently destroy existing consent.
    pub(crate) fn retire_for_exit(&self) -> Result<(), Error> {
        self.stop_history(); // Immediate history fence; never waits behind Store/control IO.
        self.repository_summary.retire(); // SAME relay DATA, no late publication after retirement.
        self.android_tools.unavailable(); // Memory-only; no late relay publication can revive it.
        self.history.retire_capture(); // Memory-only barrier before existing Host/Service work.
        let mut state = self.lock()?;
        state.pending = None; state.prepared = None; state.phase = Phase::Retiring;
        if let Some(service) = state.service.clone() {
            if let Err(error) = service.revoke_agent_read() {
                state.fail(HostFailure::simple(HostStage::Revoke, error)); return Err(error);
            }
        }
        Ok(())
    }
    pub(crate) async fn shutdown(&self) -> HostShutdownReport {
        // Retire before the first await so a waiting shutdown observer cannot
        // allow a concurrent startup/result to issue another grant.
        let retire_error = self.retire_for_exit().err();
        let mut originals = self.originals.lock().await;
        if let Some(report) = &originals.shutdown { return report.clone(); }
        let mut failures = match self.control.lock() {
            Ok(state) => state.failures.clone(),
            // Cleanup-only diagnostic custody, never operational reuse of a
            // poisoned mutex. Originals are separately retained in this book.
            Err(poisoned) => poisoned.into_inner().failures.clone(),
        };
        if let Some(error) = retire_error { remember(&mut failures, HostFailure::simple(HostStage::Revoke, error)); }
        let mut originals_closed = true;
        if let Some(sources) = originals.headless_sources.as_mut() {
            if !sources.retire() {
                originals_closed = false;
                remember(&mut failures, HostFailure::simple(HostStage::CloseSources, Error::StateUnknown));
            }
        }
        if let Some(source) = originals.source.as_mut() {
            if !source.retire_application_probe() {
                originals_closed = false;
                remember(&mut failures, HostFailure::simple(HostStage::CloseSources, Error::StateUnknown));
            }
        }
        let workers_joined = if let Some(server) = originals.server.as_mut() {
            // Borrow, never take: cancellation preserves the exact join owner.
            match server.shutdown().await {
                Ok(receipt) => Some(receipt.workers_joined),
                Err(error) => {
                    remember(&mut failures, HostFailure::simple(HostStage::Join, error)); None
                }
            }
        } else { None };
        if let Some(service) = &originals.service {
            if let Err(error) = service.stop() {
                originals_closed = false; remember(&mut failures, HostFailure::simple(HostStage::StopService, error));
            }
        }
        if let Some(store) = &originals.store {
            if let Err(error) = store.close() {
                originals_closed = false; remember(&mut failures, HostFailure::storage(HostStage::CloseStore, error));
            }
        }
        // A returned Error from the awaited original server does not by itself
        // prove or disprove worker closure. The original store refuses close
        // while its endpoint lease is active; the existing IPC owner settles
        // that lease only after known original listener/worker closes+joins.
        // Thus successful original store closure can support resource finality
        // after a positively settled namespace conflict, without deleting the
        // conflicting entry. Every retained UNKNOWN still vetoes settled().
        match self.control.lock() {
            Ok(mut state) => {
                for failure in &state.failures { remember(&mut failures, *failure); }
                state.phase = Phase::Closed; state.pending = None; state.prepared = None;
            }
            Err(poisoned) => {
                // Include failures recorded while the original join was
                // pending, and a newly observed poisoned host ledger itself.
                for failure in &poisoned.into_inner().failures { remember(&mut failures, *failure); }
                remember(&mut failures, HostFailure::simple(HostStage::Admission, Error::StateUnknown));
            }
        }
        let report = HostShutdownReport { failures, workers_joined, originals_closed };
        // No await separates the joined receipt, all close attempts and this
        // cached outcome. Later observers cannot retry a consumed original.
        originals.shutdown = Some(report.clone());
        report
    }
}

fn ordinary_absolute(path: &Path) -> bool {
    let Some(text) = path.to_str() else { return false; };
    path.is_absolute() && text.len() <= 4096 && !text.contains('\0') && !text.contains("//")
        && !text.split('/').any(|part| part == "." || part == "..")
        && path.components().all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}
fn overlap(one: &Path, other: &Path) -> bool { one.starts_with(other) || other.starts_with(one) }
fn held_application_root(store: &PrivateStateDirectory) -> Result<RegisteredRoot, StateError> {
    let (path, id) = store.native_application_root()?;
    Ok(RegisteredRoot { path, identity: asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::vault_original(
        id.device, id.inode, id.mode, id.uid, id.gid)) })
}
fn source_error(reason: Reason) -> Error {
    match reason {
        Reason::CleanupUnknown => Error::StateUnknown,
        Reason::UnsupportedPlatform | Reason::UnsupportedFilesystem => Error::Unavailable,
        Reason::UserCancelled | Reason::Deadline => Error::Expired,
        Reason::Capacity | Reason::InvalidRequest => Error::InvalidRequest,
        _ => Error::Conflict,
    }
}
fn denied() -> ReadAccessStatus { ReadAccessStatus { enabled: false, remaining_ms: 0, project_ids: Vec::new() } }
fn remember(failures: &mut Vec<HostFailure>, failure: HostFailure) {
    if !failures.contains(&failure) { failures.push(failure); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{application_service::tests::passive, application_state_store::{Fixture, Namespace, Revision, DIRECTORY}};
    use std::{fs::File, future::Future, os::unix::fs::{MetadataExt, PermissionsExt}, task::Poll};

    #[test]
    fn native_state_location_never_waits_for_control_and_keeps_fixed_path_checks() {
        // Only the real memory lock and unopened path DATA. No Store, source
        // probe, service, endpoint or replacement thread is created.
        let host = ApplicationHost::new();
        let path = Path::new("/unopened-native-state/dev.mobile-release-kit.desktop");
        {
            let _original = host.control.lock().unwrap();
            assert_eq!(host.reserve_native_state_location(path, &[]), Err(Error::Busy));
        }
        assert_eq!(host.reserve_native_state_location(path, &[]), Ok(()));
        assert_eq!(host.reserve_native_state_location(Path::new("/unopened-native-state/wrong-name"), &[]), Err(Error::InvalidRequest));
        assert_eq!(host.reserve_native_state_location(Path::new("/other-native-state/dev.mobile-release-kit.desktop"), &[]), Err(Error::Conflict));
        let state = host.control.lock().unwrap();
        assert_eq!(state.native_location.as_deref(), Some(path));
        assert!(state.native_roots.is_empty());
        assert!(state.phase == Phase::Dormant);
        assert!(state.store.is_none() && state.service.is_none() && state.pending.is_none());
    }

    #[test]
    fn native_startup_keeps_original_deadline_and_cancels_only_its_ticket() {
        let f = Fixture::new();
        let original = project(&f);
        let host = ApplicationHost::new();
        reserve(&host, &f, &original);
        let end = Instant::now() + Duration::from_secs(5);
        let first = host.begin_native_state_until(original.clone(), end).unwrap();
        assert_eq!(first.0.startup_expires, end);
        let second = host.begin_native_state(original.clone()).unwrap();
        assert_eq!(host.cancel_native_state_ticket(&first), Err(Error::Conflict));
        {
            let state = host.control.lock().unwrap();
            assert_eq!(state.pending, Some(second.0.epoch));
            assert_eq!(host.cancel_native_state_ticket(&second), Err(Error::Busy));
        }
        assert_eq!(host.cancel_native_state_ticket(&second), Ok(()));
        assert_eq!(host.cancel_native_state_ticket(&second), Err(Error::Conflict));
        assert!(matches!(host.begin_native_state_until(original, Instant::now()), Err(Error::Expired)));
        let state = host.control.lock().unwrap();
        assert!(state.pending.is_none() && state.store.is_none() && state.service.is_none());
    }

    fn runtime() -> tokio::runtime::Runtime { tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap() }
    fn project(f: &Fixture) -> NativeProject {
        let root = f.app.parent().unwrap().join("project");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let original = File::open(&root).unwrap(); let metadata = original.metadata().unwrap();
        NativeProject { runtime_id: "project-1".into(), canonical_root: root, device: metadata.dev(), inode: metadata.ino(),
            registration_generation: 2, document_identity: Arc::new(()), input_revision: 1 }
    }
    fn list() -> p::Request { p::Request { version: p::VERSION, request_id: p::Id::random().unwrap(), request: p::RequestBody::Projects(p::Empty {}) } }
    fn reserve(host: &ApplicationHost, f: &Fixture, project: &NativeProject) {
        host.reserve_native_location(&f.app, &[fixture_root(&project.canonical_root)]).unwrap();
    }
    fn fixture_root(path: &Path) -> RegisteredRoot {
        let held = File::open(path).unwrap(); let id = held.metadata().unwrap();
        let root = RegisteredRoot { path: path.to_owned(), identity: asset_source::ProjectIdentity::Posix(
            asset_source::DirectoryIdentity::vault_original(id.dev(), id.ino(), id.mode(), id.uid(), id.gid())) };
        nix::unistd::close(held).unwrap(); root
    }
    /// ONLY the lifecycle tests seed retained ordinary Store/Service originals.
    /// No SourceBook result, native project proof or filesystem qualification is
    /// fabricated. Native startup admission is tested separately below; Mac
    /// APFS/EXT4 successful source qualification is not inferred on overlayfs.
    async fn seed_lifecycle_fixture(host: &ApplicationHost, ticket: &AllowTicket, app: &Path) -> Result<(), Error> {
        let mut originals = host.originals.lock().await;
        {
            let mut state = host.lock()?; host.check_allow(&state, ticket)?;
            if originals.store.is_none() {
                originals.location = Some(app.to_owned());
                let store = Arc::new(PrivateStateDirectory::open(app).map_err(|error| error.code)?);
                originals.store = Some(store.clone()); state.store = Some(store.clone());
            }
            if originals.service.is_none() {
                let service = match ApplicationService::open_with_android_tools(originals.store.as_ref().unwrap().clone(), host.android_tools.clone()) {
                    Ok(service) => Arc::new(service),
                    Err(error) => { state.fail(HostFailure::simple(HostStage::OpenService, error)); return Err(error); }
                };
                originals.service = Some(service.clone()); state.service = Some(service);
            }
            originals.service.as_ref().unwrap().register_native(&ticket.original.runtime_id, &ticket.original.canonical_root,
                ticket.original.device, ticket.original.inode)?;
            state.registered.insert(ticket.original.runtime_id.clone(), ticket.original.clone());
        }
        if originals.server.is_none() { originals.server = Some(installed_cli_ipc::start(originals.service.as_ref().unwrap().clone()).await?); }
        let mut state = host.lock()?; host.check_allow(&state, ticket)?;
        state.phase = Phase::Listening; state.prepared = Some(ticket.epoch); Ok(())
    }
    async fn enable(host: &ApplicationHost, f: &Fixture, project: &NativeProject) {
        reserve(host, f, project);
        let ticket = host.begin_allow(project.clone()).unwrap(); seed_lifecycle_fixture(host, &ticket, &f.app).await.unwrap();
        let status = host.finish_allow(ticket, project, &passive(&project.canonical_root, &"1".repeat(64))).unwrap();
        assert!(status.enabled); assert!(status.remaining_ms <= 3_600_000); assert_eq!(status.project_ids.len(), 1);
    }
    #[test]
    fn dormant_status_revoke_and_shutdown_create_no_private_state() {
        runtime().block_on(async {
            let f = Fixture::short(); let host = ApplicationHost::new();
            host.reserve_native_location(&f.app, &[]).unwrap();
            assert!(!host.status().unwrap().enabled); assert!(!host.revoke().unwrap().enabled);
            host.retire_allow().unwrap();
            let report = host.shutdown().await;
            assert!(report.settled()); assert!(report.failures.is_empty()); assert!(report.workers_joined.is_none());
            assert!(!f.app.exists());

            // A failed original Store open may have created private bytes
            // without yielding a Store handle. Its fence must not turn into
            // "no private root" for later native registration. This inert
            // ledger fault does not fabricate a successful source probe.
            for failure in [HostFailure::simple(HostStage::OpenStore, Error::Conflict),
                HostFailure::storage(HostStage::OpenStore, StateError {
                    code: Error::Conflict, effect: Effect::Applied,
                    durability: Durability::Unknown, cleanup: Cleanup::Known,
                })] {
                let host = ApplicationHost::new();
                host.control.lock().unwrap().fail(failure);
                assert!(host.control.lock().unwrap().store.is_none());
                assert_eq!(host.native_exclusion_root().err(), Some(Error::Conflict));
                let report = host.shutdown().await;
                assert_eq!(report.settled(), !failure.unknown());
                assert!(report.failures.contains(&failure));
                assert!(!f.app.exists());
            }
        });
    }
    #[test]
    fn native_initialized_state_does_not_grant_cli_and_later_allow_reuses_it() {
        runtime().block_on(async {
            let f = Fixture::short(); let project = project(&f); let host = ApplicationHost::new();
            reserve(&host, &f, &project);
            let ticket = host.begin_native_state(project.clone()).unwrap();
            // Same scope as seed_lifecycle_fixture above: actual private Store
            // and IPC behavior, NOT successful native SourceBook qualification.
            let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
            let service = Arc::new(ApplicationService::open_with_android_tools(store.clone(), host.android_tools.clone()).unwrap());
            let binding = service.register_native(&project.runtime_id, &project.canonical_root, project.device, project.inode).unwrap();
            {
                let mut originals = host.originals.lock().await;
                originals.location = Some(f.app.clone()); originals.store = Some(store.clone());
                originals.service = Some(service.clone());
                let mut state = host.lock().unwrap();
                state.store = Some(store.clone()); state.phase = Phase::Ready;
                state.service = Some(service.clone()); state.prepared_binding = Some(binding.clone());
                state.registered.insert(project.runtime_id.clone(), project.clone());
                state.prepared = Some(ticket.0.epoch);
            }
            let lease = Arc::new(host.finish_native_state(ticket, &project).unwrap());
            assert!(Arc::ptr_eq(lease.store(), &store));
            assert!(lease.project_binding() == &binding);
            host.native_state_current(&lease, &project).unwrap();
            {
                let _held = host.control.lock().unwrap();
                assert_eq!(host.native_state_current(&lease, &project), Err(Error::Busy));
            }
            // No native worker exists in this Store/Service lifecycle fixture.
            // Reusing one Ready context still requires distinct serial tokens;
            // dropping a lease is never the token retirement operation.
            let first = lease.begin_use().unwrap();
            assert!(Arc::ptr_eq(&first.ready, &lease));
            assert_eq!(lease.begin_use().err().unwrap().code, Error::Busy);
            store.retire_native_use(first.native_use()).unwrap();
            let second = lease.begin_use().unwrap();
            assert!(Arc::ptr_eq(&second.ready, &lease));
            assert!(!Arc::ptr_eq(first.native_use(), second.native_use()));
            assert_eq!(store.check_native_use(first.native_use()).err().unwrap().code, Error::Conflict);
            store.retire_native_use(second.native_use()).unwrap();
            drop((first, second));
            let mut changed = project.clone(); changed.input_revision += 1;
            assert_eq!(host.native_state_current(&lease, &changed), Err(Error::Conflict));
            assert!(!host.status().unwrap().enabled);
            assert_eq!(installed_cli_ipc::request(&f.app, &list()).await.err(), Some(Error::Unavailable));
            {
                let originals = host.originals.lock().await;
                assert!(Arc::ptr_eq(originals.service.as_ref().unwrap(), &service));
                assert!(originals.server.is_none());
            }
            assert!(!f.app.join(DIRECTORY).join("s").exists());
            assert!(!f.app.join(DIRECTORY).join("agent.connection").exists());
            enable(&host, &f, &project).await;
            assert!(Arc::ptr_eq(host.originals.lock().await.store.as_ref().unwrap(), &store));
            assert!(Arc::ptr_eq(host.originals.lock().await.service.as_ref().unwrap(), &service));
            assert!(host.status().unwrap().enabled);
            assert_eq!(host.status().unwrap().project_ids, vec![binding.project_id]);
            host.invalidate_native(&project.runtime_id).unwrap();
            assert_eq!(host.native_state_current(&lease, &project), Err(Error::Conflict));
            drop(lease);
            assert!(host.shutdown().await.settled());
        });
    }
    #[test]
    fn starting_fences_roster_changes_and_cancellation_remains_memory_only() {
        runtime().block_on(async {
            let f = Fixture::short(); let project = project(&f); let host = ApplicationHost::new();
            reserve(&host, &f, &project);
            let ticket = host.begin_native_state(project.clone()).unwrap();
            {
                let state = host.control.lock().unwrap();
                let pending = state.pending;
                assert_eq!(host.begin_native_state(project.clone()).err(), Some(Error::Busy));
                assert_eq!(host.finish_native_state(ticket, &project).err(), Some(Error::Busy));
                assert_eq!(state.pending, pending);
            }
            let ticket = host.begin_native_state(project.clone()).unwrap();
            // Inert admission state only, no made-up source or IO receipt.
            host.control.lock().unwrap().phase = Phase::Starting;
            assert_eq!(host.reserve_native_location(&f.app, &[]), Err(Error::Busy));
            assert_eq!(host.native_exclusion_root().err(), Some(Error::Busy));
            assert_eq!(host.begin_allow(project.clone()).err(), Some(Error::Busy));
            host.retire_allow().unwrap();
            assert_eq!(host.startup_current(&ticket.0), Err(Error::AccessDenied));
            assert!(!f.app.exists());
            assert!(host.shutdown().await.settled());
        });
    }
    #[test]
    fn failed_host_fences_reads_without_waiting_for_service_io_mutex() {
        runtime().block_on(async {
            let f = Fixture::short(); let project = project(&f); let host = ApplicationHost::new();
            enable(&host, &f, &project).await;
            let service = host.originals.lock().await.service.as_ref().unwrap().clone();
            crate::application_service::tests::with_state_locked(&service, || {
                assert_eq!(host.startup_failure(HostFailure::simple(HostStage::OpenStore, Error::Conflict)), Error::Conflict);
                assert_eq!(service.native_history_current(), Err(Error::StateUnknown));
            });
            // The fence is not a shutdown receipt. The original listener and
            // Store are still retained for the normal actual joined cleanup.
            assert!(host.originals.lock().await.server.is_some());
            assert!(host.shutdown().await.settled());
        });
    }
    #[test]
    fn waiting_startup_cancellation_and_stale_allow_never_grant() {
        runtime().block_on(async {
            let f = Fixture::short(); let project = project(&f); let host = ApplicationHost::new();
            reserve(&host, &f, &project);
            let first = host.begin_allow(project.clone()).unwrap();
            let held = host.originals.lock().await;
            let mut pending = Box::pin(host.prepare(&first, &f.app));
            std::future::poll_fn(|cx| { assert!(pending.as_mut().poll(cx).is_pending()); Poll::Ready(()) }).await;
            host.revoke().unwrap(); drop(pending); drop(held);
            assert!(!f.app.exists());
            assert_eq!(host.prepare(&first, &f.app).await.err(), Some(Error::AccessDenied));
            let mut expired = host.begin_allow(project.clone()).unwrap(); expired.startup_expires = Instant::now();
            assert_eq!(host.prepare(&expired, &f.app).await.err(), Some(Error::Expired));
            assert!(!f.app.exists()); assert!(host.originals.lock().await.source.is_none());
            let second = host.begin_allow(project.clone()).unwrap(); seed_lifecycle_fixture(&host, &second, &f.app).await.unwrap();
            host.retire_allow().unwrap();
            assert_eq!(host.finish_allow(second, &project, &passive(&project.canonical_root, &"1".repeat(64))).err().map(|e| e), Some(Error::AccessDenied));
            assert!(!host.status().unwrap().enabled);
            assert!(host.shutdown().await.settled());
        });
    }
    #[test]
    fn grant_requires_original_document_registration_and_input_and_selection_does_not_transfer() {
        runtime().block_on(async {
            let f = Fixture::short(); let project = project(&f); let host = ApplicationHost::new();
            reserve(&host, &f, &project);
            for changed in [NativeProject { document_identity: Arc::new(()), ..project.clone() },
                NativeProject { registration_generation: 3, ..project.clone() },
                NativeProject { input_revision: 2, ..project.clone() }] {
                let ticket = host.begin_allow(project.clone()).unwrap(); seed_lifecycle_fixture(&host, &ticket, &f.app).await.unwrap();
                assert_eq!(host.finish_allow(ticket, &changed, &passive(&project.canonical_root, &"1".repeat(64))).err().map(|e| e), Some(Error::Conflict));
                assert!(!host.status().unwrap().enabled);
            }
            enable(&host, &f, &project).await;
            let unprepared = host.begin_allow(project.clone()).unwrap();
            assert_eq!(host.finish_allow(unprepared, &project, &passive(&project.canonical_root, &"1".repeat(64))).err(), Some(Error::Conflict));
            assert!(!host.status().unwrap().enabled);
            enable(&host, &f, &project).await;
            let before = host.status().unwrap(); host.retire_allow().unwrap(); let after = host.status().unwrap();
            assert!(after.enabled); assert_eq!(before.project_ids, after.project_ids); assert!(after.remaining_ms <= before.remaining_ms);
            let response = installed_cli_ipc::request(&f.app, &list()).await.unwrap();
            let bytes = p::encode_response(&response).unwrap();
            assert!(!String::from_utf8(bytes).unwrap().contains("private fixture sentinel"));
            assert!(host.shutdown().await.settled());
        });
    }
    #[test]
    fn stale_snapshot_after_invalidation_cannot_freshen_saved_observation() {
        runtime().block_on(async {
            let f = Fixture::short(); let mut project = project(&f); let host = Arc::new(ApplicationHost::new());
            // Exercise the actual fixed native-control binding, not a direct
            // Host invalidation call. The Store/Service fixture above still
            // makes no claim of successful native filesystem qualification.
            let control = Arc::new(crate::saved_command_owner::AndroidRegistrationControl::default());
            control.bind_application_service(&host);
            let mut initial = control.reserve(crate::saved_command_owner::AndroidRegistrationPublisherKind::General, false).unwrap();
            initial.accept(crate::android_registration_app_protocol::Reason::ContextChanged).unwrap();
            initial.finish();
            project.input_revision = control.epoch().unwrap();
            enable(&host, &f, &project).await;
            let old = host.snapshot_ticket(&project).unwrap().unwrap();
            let mut publisher = control.reserve(crate::saved_command_owner::AndroidRegistrationPublisherKind::General, false).unwrap();
            publisher.accept(crate::android_registration_app_protocol::Reason::ContextChanged).unwrap();
            let original_core_result = passive(&project.canonical_root, &"1".repeat(64));
            // Even reusing the old numeric native stamp cannot defeat the
            // synchronously captured host-side mutation fence.
            assert_eq!(host.publish_snapshot(old, &project, &original_core_result), Err(Error::Conflict));
            match installed_cli_ipc::request(&f.app, &list()).await.unwrap().response {
                p::ResponseBody::Projects(rows) => assert!(rows[0].observation.as_ref().unwrap().stale), _ => panic!("wrong response"),
            }
            publisher.finish();
            project.input_revision = control.epoch().unwrap();
            let fresh = host.snapshot_ticket(&project).unwrap().unwrap();
            host.publish_snapshot(fresh, &project, &passive(&project.canonical_root, &"2".repeat(64))).unwrap();
            match installed_cli_ipc::request(&f.app, &list()).await.unwrap().response {
                p::ResponseBody::Projects(rows) => assert!(!rows[0].observation.as_ref().unwrap().stale), _ => panic!("wrong response"),
            }
            assert_eq!(original_core_result.pointer("/config/data/mustNotEscape").unwrap(), "private fixture sentinel");
            assert!(host.shutdown().await.settled());
        });
    }
    #[test]
    fn malformed_private_service_state_retains_original_store_without_reset_or_retry() {
        runtime().block_on(async {
            let f = Fixture::short(); let project = project(&f);
            let store = PrivateStateDirectory::open(&f.app).unwrap();
            store.replace(Namespace::Projects, Revision(0), b"not a service document").unwrap(); store.close().unwrap();
            let preserved = std::fs::read(f.app.join(DIRECTORY).join("projects.state")).unwrap();
            let host = ApplicationHost::new(); reserve(&host, &f, &project); let ticket = host.begin_allow(project).unwrap();
            assert_eq!(seed_lifecycle_fixture(&host, &ticket, &f.app).await.err(), Some(Error::RecoveryRequired));
            assert!(host.originals.lock().await.store.is_some());
            assert_eq!(host.prepare(&ticket, &f.app).await.err(), Some(Error::RecoveryRequired));
            let report = host.shutdown().await;
            assert!(report.settled()); assert!(report.failures.iter().any(|f| f.stage == HostStage::OpenService));
            assert_eq!(std::fs::read(f.app.join(DIRECTORY).join("projects.state")).unwrap(), preserved);
        });
    }
    #[test]
    fn failed_publication_denies_access_without_rewriting_original_core_result() {
        runtime().block_on(async {
            let f = Fixture::short(); let project = project(&f); let host = ApplicationHost::new();
            enable(&host, &f, &project).await;
            let ticket = host.snapshot_ticket(&project).unwrap().unwrap();
            let original_core_result = passive(&project.canonical_root, &"2".repeat(64));
            let before = original_core_result.clone();
            std::fs::write(f.app.join(DIRECTORY).join("projects.state"), b"changed synthetic state").unwrap();
            assert!(host.publish_snapshot(ticket, &project, &original_core_result).is_err());
            assert_eq!(original_core_result, before); assert!(host.status().is_err());
            assert!(installed_cli_ipc::request(&f.app, &list()).await.is_err());
            let report = host.shutdown().await;
            assert!(!report.failures.is_empty());
            assert!(report.failures.iter().any(|f| f.stage == HostStage::Publish));
            assert!(report.failures.iter().any(|f| f.stage == HostStage::Join));
            // The original listener/workers and store really closed. Preserve
            // the feature/storage conflict without trapping a normal quit.
            assert!(report.settled());
        });
    }
    #[test]
    fn unknown_publication_collects_join_stop_and_revoke_failures_without_claiming_settlement() {
        runtime().block_on(async {
            let f = Fixture::short(); let project = project(&f); let host = ApplicationHost::new();
            enable(&host, &f, &project).await;
            let ticket = host.snapshot_ticket(&project).unwrap().unwrap();
            let service = host.originals.lock().await.service.as_ref().unwrap().clone();
            crate::application_service::tests::poison_fixture(&service);
            let original_core_result = passive(&project.canonical_root, &"2".repeat(64));
            let before = original_core_result.clone();
            assert_eq!(host.publish_snapshot(ticket, &project, &original_core_result), Err(Error::StateUnknown));
            let report = host.shutdown().await;
            assert_eq!(original_core_result, before); assert!(!report.settled());
            for stage in [HostStage::Publish, HostStage::Revoke, HostStage::Join, HostStage::StopService] {
                assert!(report.failures.iter().any(|f| f.stage == stage && f.code == Error::StateUnknown));
            }
            assert!(!f.app.join(DIRECTORY).join("s").exists());
            assert!(!f.app.join(DIRECTORY).join("agent.connection").exists());

            // Poisoning the HOST book is different: its original service is
            // still healthy. A post-admission invalidation must synchronously
            // revoke old CLI access, without changing the independent action
            // or treating the poison as original listener/worker closure.
            let f = Fixture::short(); let project = self::project(&f); let host = ApplicationHost::new();
            enable(&host, &f, &project).await;
            let _ = installed_cli_ipc::request(&f.app, &list()).await.unwrap();
            let original_core_result = passive(&project.canonical_root, &"3".repeat(64));
            let preserved = original_core_result.clone();
            let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = host.control.lock().unwrap(); panic!("synthetic host control poison");
            }));
            assert!(poisoned.is_err());
            assert_eq!(host.invalidate_all_native(), Err(Error::StateUnknown));
            assert_eq!(original_core_result, preserved);
            assert!(installed_cli_ipc::request(&f.app, &list()).await.is_err());
            assert!(host.originals.lock().await.server.is_some());
            let report = host.shutdown().await;
            assert!(report.workers_joined.unwrap() >= 1); assert!(!report.settled());
            assert!(report.failures.iter().any(|f| f.stage == HostStage::Admission && f.code == Error::StateUnknown));
            assert!(!f.app.join(DIRECTORY).join("s").exists());
            assert!(!f.app.join(DIRECTORY).join("agent.connection").exists());
        });
    }
    #[test]
    fn cancelled_shutdown_observer_retains_original_listener_and_workers() {
        runtime().block_on(async {
            let f = Fixture::short(); let project = project(&f); let host = ApplicationHost::new();
            enable(&host, &f, &project).await;
            let _ = installed_cli_ipc::request(&f.app, &list()).await.unwrap();
            let stalled = tokio::net::UnixStream::connect(f.app.join(DIRECTORY).join("s")).await.unwrap();
            let mut shutdown = Box::pin(host.shutdown());
            std::future::poll_fn(|cx| { assert!(shutdown.as_mut().poll(cx).is_pending()); Poll::Ready(()) }).await;
            drop(shutdown);
            assert!(host.originals.lock().await.server.is_some());
            let report = host.shutdown().await;
            nix::unistd::close(stalled.into_std().unwrap()).unwrap();
            assert!(report.settled()); assert!(report.workers_joined.unwrap() >= 1);
            assert!(!f.app.join(DIRECTORY).join("s").exists());
            assert!(!f.app.join(DIRECTORY).join("agent.connection").exists());
            let repeated = host.shutdown().await;
            assert_eq!(repeated.workers_joined, report.workers_joined); assert_eq!(repeated.failures, report.failures);
        });
    }
    #[test]
    fn project_overlap_is_refused_before_creating_service_files() {
        runtime().block_on(async {
            let f = Fixture::short(); let project = project(&f); let host = ApplicationHost::new();
            let ancestor = f.app.parent().unwrap();
            assert_eq!(host.reserve_native_location(&f.app, &[
                fixture_root(&project.canonical_root), fixture_root(ancestor),
            ]), Err(Error::Conflict));
            assert!(host.begin_allow(project.clone()).is_err());
            reserve(&host, &f, &project);
            let ticket = host.begin_allow(project.clone()).unwrap();
            let other = ancestor.join("other").join("dev.mobile-release-kit.desktop");
            assert_eq!(host.prepare(&ticket, &other).await.err(), Some(Error::Conflict));
            // A changed COMPLETE native roster retires the pending attempt;
            // it cannot use an earlier exclusion result before construction.
            let second = ancestor.join("second-project"); std::fs::create_dir(&second).unwrap();
            host.reserve_native_location(&f.app, &[
                fixture_root(&project.canonical_root), fixture_root(&second),
            ]).unwrap();
            assert_eq!(host.prepare(&ticket, &f.app).await.err(), Some(Error::AccessDenied));
            assert!(!f.app.exists()); assert!(host.originals.lock().await.source.is_none());
            assert!(host.shutdown().await.settled());
        });
    }
    #[test]
    fn native_source_admission_precedes_private_state_and_retains_original_book() {
        runtime().block_on(async {
            let f = Fixture::short(); let project = project(&f); let host = ApplicationHost::new();
            reserve(&host, &f, &project); let ticket = host.begin_allow(project.clone()).unwrap();
            // Inspect the real filesystem, without replacing native policy.
            // On the current overlayfs VPS this proves refusal/closure ONLY.
            #[cfg(target_os = "linux")]
            let root_qualified = nix::sys::statfs::statfs(Path::new("/")).unwrap().filesystem_type() == nix::sys::statfs::EXT4_SUPER_MAGIC;
            #[cfg(target_os = "macos")]
            let root_qualified = nix::sys::statfs::statfs(Path::new("/")).unwrap().filesystem_type_name() == "apfs";
            let result = host.prepare(&ticket, &f.app).await;
            if !root_qualified {
                assert_eq!(result.err(), Some(Error::Unavailable));
                assert!(!f.app.exists()); assert!(host.status().is_err());
                let originals = host.originals.lock().await;
                assert!(originals.source.as_ref().unwrap().settled());
                assert!(originals.store.is_none()); assert!(originals.server.is_none());
            } else {
                result.unwrap();
                assert!(host.originals.lock().await.source.as_ref().unwrap().settled());
                assert!(host.finish_allow(ticket, &project, &passive(&project.canonical_root, &"1".repeat(64))).unwrap().enabled);
            }
            assert!(host.shutdown().await.settled());
        });
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_apfs_selection_requires_current_service_exclusion_and_rejects_reverse_alias() {
        runtime().block_on(async {
            let f = Fixture::short(); let project = project(&f); let host = ApplicationHost::new();
            let mut before_book = SourceBook::new();
            let before = asset_source::probe_project(&mut before_book, project.canonical_root.clone(), &[], &mut || false).unwrap();
            assert!(before_book.settled());
            reserve(&host, &f, &project); let ticket = host.begin_allow(project.clone()).unwrap();
            host.prepare(&ticket, &f.app).await.unwrap();
            let application = host.native_exclusion_root().unwrap().unwrap();
            assert_eq!(host.check_project_root(&before), Err(Error::Conflict));
            let mut current_book = SourceBook::new();
            let current = asset_source::probe_project_excluding_private_roots(&mut current_book,
                project.canonical_root.clone(), &[], None, Some(&application), &mut || false).unwrap();
            assert!(current_book.settled()); host.check_project_root(&current).unwrap();

            // A genuine extra marker does not start/grant the dormant Host.
            // The separate cache validator remains responsible for that marker.
            let dormant = ApplicationHost::new();
            dormant.check_project_root(&current).unwrap();
            assert!(dormant.native_exclusion_root().unwrap().is_none());
            assert!(dormant.shutdown().await.settled());
            assert_eq!(dormant.check_project_root(&current), Err(Error::Unavailable));

            let inside = f.app.join("synthetic-project"); std::fs::create_dir(&inside).unwrap();
            // Actual APFS Data-volume spelling, not invented identity DATA.
            let alternate = Path::new("/System/Volumes/Data").join(inside.strip_prefix("/").unwrap());
            let mut alias_book = SourceBook::new();
            assert_eq!(asset_source::probe_project_excluding_private_roots(&mut alias_book,
                alternate.clone(), &[], None, Some(&application), &mut || false).err(), Some(Reason::ProjectOverlap));
            assert!(alias_book.settled());
            assert!(host.shutdown().await.settled());

            // Startup's COMPLETE roster must catch that same reverse alias,
            // before opening/writing the existing private service directory.
            let preserved = std::fs::read(f.app.join(DIRECTORY).join("projects.state")).unwrap();
            let host = ApplicationHost::new();
            host.reserve_native_location(&f.app, &[fixture_root(&project.canonical_root), fixture_root(&alternate)]).unwrap();
            let ticket = host.begin_allow(project).unwrap();
            assert_eq!(host.prepare(&ticket, &f.app).await.err(), Some(Error::Conflict));
            assert!(host.originals.lock().await.store.is_none());
            assert!(host.originals.lock().await.source.as_ref().unwrap().settled());
            assert_eq!(std::fs::read(f.app.join(DIRECTORY).join("projects.state")).unwrap(), preserved);
            assert!(host.shutdown().await.settled());

            // Current registered roots are re-probed, not trusted from an old
            // registration stamp after their actual directories are replaced.
            let f = Fixture::short(); let project = self::project(&f); let host = ApplicationHost::new();
            reserve(&host, &f, &project); let ticket = host.begin_allow(project.clone()).unwrap();
            std::fs::rename(&project.canonical_root, project.canonical_root.with_file_name("retained-project")).unwrap();
            std::fs::create_dir(&project.canonical_root).unwrap();
            std::fs::set_permissions(&project.canonical_root, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(host.prepare(&ticket, &f.app).await.err(), Some(Error::Conflict));
            assert!(!f.app.exists()); assert!(host.originals.lock().await.source.as_ref().unwrap().settled());
            assert!(host.shutdown().await.settled());
        });
    }
}

#[cfg(test)]
#[path="application_service_git_local_tests.rs"]
mod git_local_lock_tests;
