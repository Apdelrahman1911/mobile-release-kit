//! Retained, default-dormant host of the existing read-only application service.
//!
//! The real DocumentBinding supplies/rechecks native facts under its original
//! admission lock. This module never calls back into that document, accepts a
//! renderer root, constructs an engine, or settles an independent core action.
use crate::{
    asset_commands::Reason,
    asset_source::{self, ApplicationDirectoryExclusion, ProjectProbe, RegisteredRoot, SourceBook},
    application_service::{ApplicationService, ReadAccessStatus},
    application_state_store::{ApplicationDirectoryIdentity, Cleanup, Durability, Effect, PrivateStateDirectory, StateError},
    installed_cli_ipc::{self, ServerHandle},
    service_protocol as p,
};
use p::Error;
use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use tokio::sync::Mutex as AsyncMutex;

const ACCESS_LIFETIME: Duration = Duration::from_secs(3600);
// Work admission is not the user lease. Bounded synchronous native calls have
// checkpoints; this does not claim that a stalled kernel call is preemptible.
const STARTUP_WORK: Duration = Duration::from_secs(30);

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
enum Phase { Dormant, Starting, Listening, Retiring, Closed }
struct Control {
    phase: Phase, epoch: u64, source_epoch: u64, pending: Option<u64>, prepared: Option<u64>,
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
        self.pending = None; self.prepared = None;
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
        self.pending = None; self.prepared = None;
        if let Some(service) = &self.service {
            if let Err(error) = service.revoke_agent_read() {
                self.remember(HostFailure::simple(HostStage::Revoke, error));
            }
        }
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
}

pub(crate) struct ApplicationHost {
    identity: Arc<()>, control: Mutex<Control>, originals: AsyncMutex<Originals>,
}
impl ApplicationHost {
    /// No path lookup, directory, reservation, socket or background task.
    pub(crate) fn new() -> Self {
        Self { identity: Arc::new(()), control: Mutex::new(Control {
            phase: Phase::Dormant, epoch: 0, source_epoch: 0, pending: None, prepared: None,
            native_location: None, native_roots: Vec::new(), store: None, service: None,
            registered: BTreeMap::new(), fence: None, failures: Vec::new(),
        }), originals: AsyncMutex::new(Originals::default()) }
    }
    fn lock(&self) -> Result<MutexGuard<'_, Control>, Error> {
        match self.control.lock() {
            Ok(state) => Ok(state),
            Err(poisoned) => {
                // Cleanup ONLY: a core mutation must not leave an old fresh
                // observation readable merely because our invalidation book
                // was poisoned. Never recover an admission from this guard.
                let service = {
                    let mut state = poisoned.into_inner();
                    state.pending = None; state.prepared = None; state.phase = Phase::Retiring;
                    state.fence.get_or_insert(Error::StateUnknown);
                    state.remember(HostFailure::simple(HostStage::Admission, Error::StateUnknown));
                    state.service.clone()
                };
                if let Some(service) = service {
                    if let Err(error) = service.revoke_agent_read() {
                        let mut state = match self.control.lock() {
                            Ok(state) => state, Err(poisoned) => poisoned.into_inner(),
                        };
                        state.remember(HostFailure::simple(HostStage::Revoke, error));
                    }
                }
                Err(Error::StateUnknown)
            }
        }
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
        if Instant::now() >= ticket.startup_expires { Err(Error::Expired) } else { Ok(()) }
    }
    /// Under the real DocumentBinding lock, inspect the COMPLETE genuine native
    /// roster before beginning Allow. This reservation itself performs no IO;
    /// later project registrations must call check_project_root under that same
    /// original document lock before publishing a new registry member.
    pub(crate) fn reserve_native_location(&self, app_data: &Path,
        registered_roots: &[RegisteredRoot]) -> Result<(), Error> {
        let mut state = self.lock()?; state.available()?;
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
        } else if !proof.excludes_application(None) { return Err(Error::Conflict); }
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
        let Some(store) = state.store.clone() else { return Ok(None); };
        match held_application_root(&store) {
            Ok(root) => Ok(Some(root)),
            Err(error) => { state.fail(HostFailure::storage(HostStage::Register, error)); Err(error.code) }
        }
    }
    pub(crate) fn begin_allow(&self, original: NativeProject) -> Result<AllowTicket, Error> {
        let mut state = self.lock()?;
        state.available()?;
        state.retire_pending()?;
        if let Some(service) = state.service.clone() {
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
        let startup_expires = now.checked_add(STARTUP_WORK).ok_or(Error::StateUnknown)?;
        state.pending = Some(state.epoch);
        Ok(AllowTicket { owner: self.identity.clone(), epoch: state.epoch,
            source_epoch: state.source_epoch, original, expires, startup_expires })
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
        let mut originals = self.originals.lock().await;
        {
            let mut state = self.lock()?;
            self.check_startup(&state, ticket)?;
            if state.native_location.as_deref() != Some(app_data)
                || overlap(&ticket.original.canonical_root, app_data) {
                return Err(Error::Conflict);
            }
            if originals.location.as_ref().is_some_and(|location| location != app_data) { return Err(Error::Conflict); }
            if originals.source_epoch == Some(ticket.epoch) { return Err(Error::Conflict); }
            if originals.source.as_ref().is_some_and(|book| !book.not_started() && !book.settled()) {
                state.fail(HostFailure::simple(HostStage::ProbeSources, Error::StateUnknown)); return Err(Error::StateUnknown);
            }
            state.phase = Phase::Starting;
            originals.location = Some(app_data.to_owned());
            // The original book is retained BEFORE native entry. A panic or
            // cancellation cannot erase its original acquisition/close facts.
            // Only an explicit new native Allow may replace a KNOWN closed book.
            originals.source_epoch = Some(ticket.epoch);
            originals.source = Some(SourceBook::new()); originals.exclusion = None;
            let result = asset_source::probe_application_directory_exclusion(originals.source.as_mut().unwrap(),
                app_data, &state.native_roots, &mut || Instant::now() >= ticket.startup_expires);
            match result {
                Ok(proof) => originals.exclusion = Some(proof),
                Err(reason) => {
                    let error = source_error(reason);
                    state.fail(HostFailure::simple(HostStage::ProbeSources, error)); return Err(error);
                }
            }
            if !originals.source.as_ref().is_some_and(SourceBook::settled) {
                state.fail(HostFailure::simple(HostStage::CloseSources, Error::StateUnknown)); return Err(Error::StateUnknown);
            }
            self.check_startup(&state, ticket)?;
            let exclusion = originals.exclusion.as_ref().ok_or(Error::StateUnknown)?;
            let (parent, existing) = exclusion.store_expectation(app_data, &state.native_roots).map_err(source_error)?;
            let metadata = |(device, inode, mode, uid, gid)| ApplicationDirectoryIdentity { device, inode, mode, uid, gid };
            let expected = (metadata(parent), existing.map(metadata));
            let excluded_projects: Vec<_> = state.native_roots.iter().map(|root| root.identity.posix()
                .map(|id| id.service_identity()).map_err(source_error)).collect::<Result<_, _>>()?;
            if originals.store.is_none() {
                let store = match PrivateStateDirectory::open_after_exclusion(app_data, &excluded_projects, expected, ticket.startup_expires) {
                    Ok(store) => Arc::new(store),
                    Err(error) => { state.fail(HostFailure::storage(HostStage::OpenStore, error)); return Err(error.code); }
                };
                originals.store = Some(store.clone());
                state.store = Some(store.clone());
                if let Err(error) = self.check_startup(&state, ticket) {
                    state.fail(HostFailure::simple(HostStage::OpenService, error)); return Err(error);
                }
                let service = match ApplicationService::open(store) {
                    Ok(service) => Arc::new(service),
                    Err(error) => { state.fail(HostFailure::simple(HostStage::OpenService, error)); return Err(error); }
                };
                originals.service = Some(service.clone()); state.service = Some(service);
            } else if let Err(error) = originals.store.as_ref().unwrap().check_application_exclusion(expected) {
                state.fail(HostFailure::storage(HostStage::Register, error)); return Err(error.code);
            }
            self.check_startup(&state, ticket)?;
            let store = originals.store.as_ref().ok_or(Error::StateUnknown)?;
            for (device, inode) in excluded_projects {
                if let Err(error) = store.excludes_project(device, inode) {
                    state.fail(HostFailure::storage(HostStage::Register, error)); return Err(error.code);
                }
            }
            let service = originals.service.as_ref().ok_or(Error::StateUnknown)?;
            if let Err(error) = service.register_native(&ticket.original.runtime_id, &ticket.original.canonical_root,
                ticket.original.device, ticket.original.inode) {
                state.fail(HostFailure::simple(HostStage::Register, error)); return Err(error);
            }
            state.registered.insert(ticket.original.runtime_id.clone(), ticket.original.clone());
        }
        self.check_startup(&self.lock()?, ticket)?;
        if originals.server.is_none() {
            let service = originals.service.as_ref().ok_or(Error::StateUnknown)?.clone();
            match installed_cli_ipc::start(service).await {
                Ok(server) => originals.server = Some(server),
                Err(error) => {
                    self.lock()?.fail(HostFailure::simple(HostStage::Start, error));
                    return Err(error);
                }
            }
        }
        let mut state = self.lock()?;
        self.check_startup(&state, ticket)?;
        state.phase = Phase::Listening; state.prepared = Some(ticket.epoch);
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
                let service = match ApplicationService::open(store) {
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
            let f = Fixture::short(); let mut project = project(&f); let host = ApplicationHost::new();
            enable(&host, &f, &project).await;
            let old = host.snapshot_ticket(&project).unwrap().unwrap();
            host.invalidate_all_native().unwrap();
            let original_core_result = passive(&project.canonical_root, &"1".repeat(64));
            // Even reusing the old numeric native stamp cannot defeat the
            // synchronously captured host-side mutation fence.
            assert_eq!(host.publish_snapshot(old, &project, &original_core_result), Err(Error::Conflict));
            match installed_cli_ipc::request(&f.app, &list()).await.unwrap().response {
                p::ResponseBody::Projects(rows) => assert!(rows[0].observation.as_ref().unwrap().stale), _ => panic!("wrong response"),
            }
            project.input_revision += 1;
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
