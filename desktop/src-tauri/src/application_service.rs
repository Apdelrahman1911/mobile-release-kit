//! Shared saved observations, explicit read consent and durable project IDs.
//!
//! The running GUI remains the genuine native host in this first slice. It
//! publishes only after original owners return. This module never constructs
//! DocumentBinding, substitutes a window ID, launches an engine, accesses a
//! credential, or derives operation finality from a cached response.
use crate::{application_state_store::{Namespace, PrivateStateDirectory, Revision}, service_protocol as p};
use p::{Error, Id};
use serde::{Deserialize, Serialize};
use std::{collections::{BTreeMap, BTreeSet}, path::{Component, Path}, sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex, MutexGuard}, time::{Duration, Instant}};

const MAX_ACCESS: Duration = Duration::from_secs(60 * 60);

/// PRIVATE native preference binding, never accepted by the service protocol.
/// Actual RegisteredRoot/held native descriptors remain operation authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProjectBinding {
    pub(crate) project_id: Id,
    pub(crate) canonical_root: String,
    pub(crate) device: u64,
    pub(crate) inode: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProjectRecord { binding: ProjectBinding, observation: Option<p::SavedObservation> }
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Persisted { version: u32, projects: Vec<ProjectRecord>, operations: Vec<p::OperationObservation> }
impl Persisted {
    fn empty() -> Self { Self { version: 1, projects: Vec::new(), operations: Vec::new() } }
    fn validate(&self, revision: Revision) -> Result<(), Error> {
        if self.version != 1 || self.projects.len() > p::PROJECT_LIMIT || self.operations.len() > p::OPERATION_LIMIT { return Err(Error::RecoveryRequired); }
        let (mut ids, mut paths, mut identities, mut operations) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        for project in &self.projects {
            if valid_root(Path::new(&project.binding.canonical_root)).is_err() || project.binding.inode == 0
                || !ids.insert(project.binding.project_id.clone()) || !paths.insert(&project.binding.canonical_root)
                || !identities.insert((project.binding.device, project.binding.inode)) { return Err(Error::RecoveryRequired); }
            if let Some(observation) = &project.observation {
                observation.configuration.validate().map_err(|_| Error::RecoveryRequired)?;
                if observation.revision == 0 || observation.revision > revision.0 || observation.issue_count > 20_000 { return Err(Error::RecoveryRequired); }
            }
        }
        for operation in &self.operations {
            if !ids.contains(&operation.project_id) || !operations.insert(operation.operation_id.clone())
                || operation.observation_revision == 0 || operation.observation_revision > revision.0
                || !consistent_status(operation.state, operation.settlement) { return Err(Error::RecoveryRequired); }
        }
        Ok(())
    }
}

struct Grant { id: Id, projects: BTreeSet<Id>, expires: Instant }
struct State {
    revision: Revision, saved: Persisted,
    // Runtime aliases are NEVER persisted or restored. Each genuine native
    // picker must supply a fresh binding in this service instance.
    runtime_aliases: BTreeMap<String, Id>, grant: Option<Grant>, stopped: bool,
}

/// Not serializable/constructible by a protocol request. Only admission under
/// the current owner's monotonic grant can issue a connected client session.
pub(crate) struct ClientSession { client_id: Id, session_id: Id, grant_id: Id, instance: Id }
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReadAccessStatus { pub(crate) enabled: bool, pub(crate) remaining_ms: u64, pub(crate) project_ids: Vec<Id> }

#[path = "application_service_agent_local_checks.rs"]
mod local_checks;
#[path = "application_service_agent_android_build.rs"]
mod agent_android_build;
#[path = "application_service_agent_ios_archive.rs"]
mod agent_ios_archive;
#[path = "application_service_request_catalogue.rs"]
mod request_catalogue;

pub(crate) struct ApplicationService { store: Arc<PrivateStateDirectory>, instance: Id, state: Mutex<State>, native_history_fenced: AtomicBool,
    android_tools: Arc<crate::service_android_tools::ObservationSlot>,
    identity_requests: Arc<crate::agent_identity_requests::Inbox>,
    local_checks: Arc<crate::agent_local_checks::Inbox>, build_requests: Arc<crate::agent_build_requests::Inbox> }
#[path = "application_service_identity_actions.rs"]
mod identity_actions;

impl ApplicationService {
    pub(crate) fn open(store: Arc<PrivateStateDirectory>) -> Result<Self, Error> {
        Self::open_with_android_tools(store, Arc::new(crate::service_android_tools::ObservationSlot::default()))
    }
    // SAME service and store. The native Host retains this bounded DATA cell
    // only so relay loss can invalidate it without waiting behind store IO.
    pub(crate) fn open_with_android_tools(store: Arc<PrivateStateDirectory>,
        android_tools: Arc<crate::service_android_tools::ObservationSlot>) -> Result<Self, Error> {
        let snapshot = store.read(Namespace::Projects).map_err(|e| e.code)?;
        let mut saved = if snapshot.bytes.is_empty() && snapshot.revision == Revision(0) { Persisted::empty() }
            else { serde_json::from_slice::<Persisted>(&snapshot.bytes).map_err(|_| Error::RecoveryRequired)? };
        for project in &mut saved.projects {
            if let Some(observation) = &mut project.observation { observation.normalize_setup_analysis(); }
        }
        saved.validate(snapshot.revision)?;
        // Remembered facts remain readable, but restart does not reacquire the
        // original project, operation, credential or observation authority.
        for project in &mut saved.projects { if let Some(observation) = &mut project.observation { observation.stale = true; } }
        for operation in &mut saved.operations { operation.stale = true; }
        let instance = Id::random()?;
        let identity_requests = Arc::new(crate::agent_identity_requests::Inbox::new(instance.clone()));
        let local_checks = Arc::new(crate::agent_local_checks::Inbox::new(instance.clone()));
        let build_requests = Arc::new(crate::agent_build_requests::Inbox::new(instance.clone()));
        Ok(Self { store, instance, identity_requests, local_checks, build_requests, android_tools, native_history_fenced: AtomicBool::new(false), state: Mutex::new(State { revision: snapshot.revision, saved,
            runtime_aliases: BTreeMap::new(), grant: None, stopped: false }) })
    }
    pub(crate) fn instance(&self) -> &Id { &self.instance }
    pub(crate) fn identity_requests(&self) -> &Arc<crate::agent_identity_requests::Inbox> { &self.identity_requests }
    // Saved comparison only, never RegisteredRoot authority. Every caller which
    // may hold Document/Edit must obtain it OFF those guards and recheck its
    // original native root/SavedEditStamp before admitting a GUI review.
    fn identity_point(state: &State, id: &Id) -> Result<crate::agent_identity_requests::SavedPoint, Error> {
        let (runtime_id, _) = state.runtime_aliases.iter().find(|(_, project)| *project == id).ok_or(Error::Conflict)?;
        let project = state.saved.projects.iter().find(|project| &project.binding.project_id == id).ok_or(Error::Conflict)?;
        let observation = project.observation.as_ref();
        Ok(crate::agent_identity_requests::SavedPoint { project_id: id.clone(), runtime_id: runtime_id.clone(),
            root: Path::new(&project.binding.canonical_root).to_path_buf(), device: project.binding.device, inode: project.binding.inode,
            revision: observation.map_or(0, |saved| saved.revision), fresh: observation.is_some_and(|saved| !saved.stale) })
    }
    pub(crate) fn identity_request_point(&self, runtime_id: &str) -> Result<crate::agent_identity_requests::SavedPoint, Error> {
        let state = self.lock()?; self.check(&state)?;
        let id = state.runtime_aliases.get(runtime_id).ok_or(Error::Conflict)?;
        if !live_grant(&state)?.projects.contains(id) { return Err(Error::AccessDenied); }
        let point = Self::identity_point(&state, id)?;
        if point.runtime_id != runtime_id || !point.fresh { return Err(Error::Conflict); }
        Ok(point)
    }
    fn submit_identity(&self, client: &ClientSession, input: crate::agent_identity_requests::Submit) -> Result<p::ResponseBody, Error> {
        let state = self.lock()?; self.check(&state)?;
        let grant = live_grant(&state)?;
        if client.instance != self.instance || grant.id != client.grant_id || !grant.projects.contains(&input.project_id) {
            return Err(Error::AccessDenied);
        }
        // A stale point can observe an identical earlier request; Inbox
        // refuses it for a NEW intent before allocating a proposal. Retain the
        // original grant guard through the memory-only put, so read revocation
        // cannot race authorization/enqueue. Inbox never calls Doc/Host/IO.
        let point = Self::identity_point(&state, &input.project_id)?;
        let origin = crate::agent_identity_requests::Origin { instance: self.instance.clone(), client: client.client_id.clone(), session: client.session_id.clone() };
        let result = self.identity_requests.submit(origin, input, &point).map(p::ResponseBody::IdentityIntent);
        drop(state); result
    }
    fn query_identity(&self, client: &ClientSession, query: &crate::agent_identity_requests::Query) -> Result<p::ResponseBody, Error> {
        {
            let state = self.lock()?; self.check(&state)?;
            let grant = live_grant(&state)?;
            if client.instance != self.instance || grant.id != client.grant_id || !grant.projects.contains(&query.project_id) {
                return Err(Error::AccessDenied);
            }
        }
        self.identity_requests.query(query).map(p::ResponseBody::IdentityIntent)
    }
    pub(crate) fn state_directory(&self) -> &Arc<PrivateStateDirectory> { &self.store }
    /// Permanent original-service read fence. Native observation callbacks must
    /// not wait for the state mutex, which real store IO can hold. No Allow or
    /// later successful write clears this flag; original cleanup still runs.
    pub(crate) fn fence_native_history(&self) { self.native_history_fenced.store(true, Ordering::Release); }
    pub(crate) fn native_history_current(&self) -> Result<(), Error> {
        if self.native_history_fenced.load(Ordering::Acquire) { Err(Error::StateUnknown) } else { Ok(()) }
    }
    fn lock(&self) -> Result<MutexGuard<'_, State>, Error> { self.state.lock().map_err(|_| Error::StateUnknown) }
    fn check(&self, state: &State) -> Result<(), Error> {
        self.native_history_current()?;
        if state.stopped { return Err(Error::Unavailable); }
        // Missing/replaced state cannot be concealed by an in-memory cache.
        let snapshot = self.store.read(Namespace::Projects).map_err(|e| e.code)?;
        if snapshot.revision != state.revision { return Err(Error::Conflict); }
        self.native_history_current()
    }
    fn save(&self, state: &mut State, next: Persisted) -> Result<(), Error> {
        let revision = Revision(state.revision.0.checked_add(1).ok_or(Error::StateUnknown)?);
        next.validate(revision)?;
        let bytes = serde_json::to_vec(&next).map_err(|_| Error::StateUnknown)?;
        let stored = self.store.replace(Namespace::Projects, state.revision, &bytes).map_err(|e| e.code)?;
        if stored.revision != revision { state.stopped = true; return Err(Error::StateUnknown); }
        state.saved = next; state.revision = revision; Ok(())
    }

    /// Call only with a completed actual native registration. These arguments
    /// are preference facts; no external client endpoint accepts them.
    pub(crate) fn register_native(&self, runtime_id: &str, canonical_root: &Path, device: u64, inode: u64) -> Result<ProjectBinding, Error> {
        if runtime_id.is_empty() || runtime_id.len() > 64 || !runtime_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') || inode == 0 {
            return Err(Error::InvalidRequest);
        }
        let path = valid_root(canonical_root)?;
        self.store.excludes_project(device, inode).map_err(|e| e.code)?;
        let mut state = self.lock()?; self.check(&state)?;
        let known = state.saved.projects.iter().find(|p| p.binding.canonical_root == path);
        let binding = if let Some(known) = known {
            if (known.binding.device, known.binding.inode) != (device, inode) { return Err(Error::Conflict); }
            known.binding.clone()
        } else {
            // A move or replaced path is not permission to create an empty
            // project/credential preference slot. Migration must be explicit.
            if state.saved.projects.iter().any(|p| (p.binding.device, p.binding.inode) == (device, inode)) { return Err(Error::Conflict); }
            if state.saved.projects.len() >= p::PROJECT_LIMIT || state.runtime_aliases.contains_key(runtime_id) { return Err(Error::Conflict); }
            let binding = ProjectBinding { project_id: Id::random()?, canonical_root: path.to_owned(), device, inode };
            let mut next = state.saved.clone();
            next.projects.push(ProjectRecord { binding: binding.clone(), observation: None });
            self.save(&mut state, next)?;
            binding
        };
        if state.runtime_aliases.get(runtime_id).is_some_and(|id| id != &binding.project_id)
            || state.runtime_aliases.iter().any(|(alias, id)| alias != runtime_id && id == &binding.project_id) { return Err(Error::Conflict); }
        state.runtime_aliases.insert(runtime_id.to_owned(), binding.project_id.clone());
        Ok(binding)
    }
    pub(crate) fn native_binding(&self, runtime_id: &str) -> Result<ProjectBinding, Error> {
        let state = self.lock()?; self.check(&state)?;
        let id = state.runtime_aliases.get(runtime_id).ok_or(Error::Conflict)?;
        state.saved.projects.iter().find(|p| &p.binding.project_id == id).map(|p| p.binding.clone()).ok_or(Error::Conflict)
    }

    /// A redacted projection of the exact ORIGINAL completed passive response.
    /// No arbitrary payload or diagnostic from that response is persisted.
    pub(crate) fn publish_passive_snapshot(&self, runtime_id: &str, snapshot: &serde_json::Value) -> Result<p::ProjectObservation, Error> {
        let mut state = self.lock()?; self.check(&state)?;
        let project_id = state.runtime_aliases.get(runtime_id).ok_or(Error::Conflict)?.clone();
        let index = state.saved.projects.iter().position(|p| p.binding.project_id == project_id).ok_or(Error::Conflict)?;
        if snapshot.get("root").and_then(|v| v.as_str()) != Some(state.saved.projects[index].binding.canonical_root.as_str())
            || snapshot.get("observationScope").and_then(|v| v.as_str()) != Some("single-request-non-atomic")
            || snapshot.pointer("/assurance/projectCodeExecuted").and_then(|v| v.as_bool()) != Some(false)
            || snapshot.pointer("/assurance/toolsProbed").and_then(|v| v.as_bool()) != Some(false) { return Err(Error::Conflict); }
        let configuration = snapshot.get("config").ok_or(Error::InvalidRequest)?;
        let config_state = match configuration.get("state").and_then(|v| v.as_str()) {
            Some("missing") => p::ConfigurationState::Missing, Some("invalid") => p::ConfigurationState::Invalid,
            Some("format-valid") => p::ConfigurationState::FormatValid, Some("unavailable") => p::ConfigurationState::Unavailable,
            _ => return Err(Error::InvalidRequest),
        };
        let (bytes, sha256) = match configuration.get("content") {
            Some(serde_json::Value::Null) => (None, None),
            Some(value) if value.is_object() => (Some(value.get("bytes").and_then(|v| v.as_u64()).ok_or(Error::InvalidRequest)?),
                Some(value.get("sha256").and_then(|v| v.as_str()).ok_or(Error::InvalidRequest)?.to_owned())),
            _ => return Err(Error::InvalidRequest),
        };
        let saved_config = p::SavedConfiguration { state: config_state, bytes, sha256 }; saved_config.validate()?;
        let partial = snapshot.pointer("/discovery/partial").and_then(|v| v.as_bool()).ok_or(Error::InvalidRequest)?;
        let issues = snapshot.get("issues").and_then(|v| v.as_array()).ok_or(Error::InvalidRequest)?.len();
        if issues > 20_000 { return Err(Error::InvalidRequest); }
        // Same completed passive response, no new read or readiness analysis.
        // Unsupported optional DATA must not discard the useful base result.
        let setup_analysis = crate::service_setup_guidance::project(snapshot.get("setupAnalysis"), config_state, partial);
        if state.saved.projects[index].observation.as_ref().is_some_and(|previous| !previous.stale
            && previous.configuration == saved_config && previous.discovery_partial == partial && previous.issue_count == issues as u32
            && previous.setup_analysis == setup_analysis) {
            // Idle saved-file polling is not a new observation revision when
            // every retained fact is unchanged. A stale->fresh return still
            // persists below, even if the same saved bytes were observed.
            return Ok(view(&state, &state.saved.projects[index]));
        }
        let revision = state.revision.0.checked_add(1).ok_or(Error::StateUnknown)?;
        let mut next = state.saved.clone();
        next.projects[index].observation = Some(p::SavedObservation { revision, stale: false, configuration: saved_config,
            discovery_partial: partial, issue_count: issues as u32, setup_analysis });
        self.save(&mut state, next)?;
        Ok(view(&state, &state.saved.projects[index]))
    }
    pub(crate) fn invalidate_native(&self, runtime_id: &str) -> Result<(), Error> {
        let mut state = self.lock()?; self.check(&state)?;
        let id = state.runtime_aliases.get(runtime_id).ok_or(Error::Conflict)?.clone();
        let mut next = state.saved.clone();
        let project = next.projects.iter_mut().find(|p| p.binding.project_id == id).ok_or(Error::Conflict)?;
        // Still check the original store above. Repeated invalidations need no
        // durable rewrite; the host separately fences each input publication.
        if project.observation.as_ref().is_none_or(|observation| observation.stale) { return Ok(()); }
        if let Some(observation) = &mut project.observation {
            observation.stale = true;
            observation.revision = state.revision.0.checked_add(1).ok_or(Error::StateUnknown)?;
        }
        // Only invalidate DATA. Existing credential assessments/plans still
        // need their original domain owners' revocation, wired by the host.
        self.save(&mut state, next)
    }
    /// First publication of a genuine original operation. A fresh native
    /// session may not adopt an older pending row, even on an ID collision.
    pub(crate) fn begin_operation(&self, runtime_id: &str, operation_id: Id, action: p::Action, operation_state: p::OperationState,
        settlement: p::Settlement) -> Result<(), Error> {
        self.write_operation(runtime_id, operation_id, action, operation_state, settlement, true)
    }
    pub(crate) fn publish_operation(&self, runtime_id: &str, operation_id: Id, action: p::Action, operation_state: p::OperationState,
        settlement: p::Settlement) -> Result<(), Error> {
        self.write_operation(runtime_id, operation_id, action, operation_state, settlement, false)
    }
    fn write_operation(&self, runtime_id: &str, operation_id: Id, action: p::Action, operation_state: p::OperationState,
        settlement: p::Settlement, require_new: bool) -> Result<(), Error> {
        if !consistent_status(operation_state, settlement) { return Err(Error::InvalidRequest); }
        let mut state = self.lock()?; self.check(&state)?;
        let id = state.runtime_aliases.get(runtime_id).ok_or(Error::Conflict)?.clone();
        let mut next = state.saved.clone();
        let observation = p::OperationObservation { operation_id: operation_id.clone(), project_id: id.clone(), action,
            state: operation_state, settlement, observation_revision: state.revision.0.checked_add(1).ok_or(Error::StateUnknown)?, stale: false };
        if let Some(existing) = next.operations.iter_mut().find(|op| op.operation_id == operation_id) {
            if require_new || existing.project_id != id || existing.action != action { return Err(Error::Conflict); }
            // Unknown is absorbing in this cache. Reconciliation belongs to the
            // original journal/owner and must publish a distinct observation.
            if existing.state == p::OperationState::Unknown && operation_state != p::OperationState::Unknown { return Err(Error::Conflict); }
            if existing.settlement == p::Settlement::Unknown && settlement != p::Settlement::Unknown { return Err(Error::Conflict); }
            if existing.settlement == p::Settlement::Settled && settlement != p::Settlement::Settled { return Err(Error::Conflict); }
            *existing = observation;
        } else {
            if next.operations.len() >= p::OPERATION_LIMIT { return Err(Error::Busy); }
            next.operations.push(observation);
        }
        self.save(&mut state, next)
    }

    pub(crate) fn allow_agent_read(&self, projects: Vec<Id>, lifetime: Duration) -> Result<ReadAccessStatus, Error> {
        self.native_history_current()?;
        if projects.is_empty() || projects.len() > p::PROJECT_LIMIT || lifetime.is_zero() || lifetime > MAX_ACCESS { return Err(Error::InvalidRequest); }
        let mut state = self.lock()?; self.check(&state)?;
        let selected: BTreeSet<_> = projects.into_iter().collect();
        if selected.iter().any(|id| !state.runtime_aliases.values().any(|registered| registered == id)) { return Err(Error::Conflict); }
        state.grant = Some(Grant { id: Id::random()?, projects: selected, expires: Instant::now().checked_add(lifetime).ok_or(Error::InvalidRequest)? });
        let status = access_status(&state);
        self.native_history_current()?; Ok(status)
    }
    pub(crate) fn revoke_agent_read(&self) -> Result<(), Error> { self.lock()?.grant = None; Ok(()) }
    pub(crate) fn read_access_status(&self) -> Result<ReadAccessStatus, Error> {
        self.native_history_current()?;
        let state = self.lock()?; let status = access_status(&state);
        self.native_history_current()?; Ok(status)
    }
    pub(crate) fn admit_client(&self) -> Result<ClientSession, Error> {
        self.native_history_current()?;
        let state = self.lock()?; self.check(&state)?;
        let grant = live_grant(&state)?;
        let client = ClientSession { client_id: Id::random()?, session_id: Id::random()?, grant_id: grant.id.clone(), instance: self.instance.clone() };
        self.native_history_current()?; Ok(client)
    }
    pub(crate) fn client_current(&self, client: &ClientSession) -> Result<(), Error> {
        self.native_history_current()?;
        let state = self.lock()?; self.check(&state)?;
        if client.instance != self.instance || live_grant(&state)?.id != client.grant_id { return Err(Error::AccessDenied); }
        self.native_history_current()
    }
    /// Fixed read-only pre-send recheck. This is not a native tool callback.
    pub(crate) fn android_tools_client_current(&self, client: &ClientSession, project: &Id) -> Result<(), Error> {
        let state = self.lock()?; self.check(&state)?;
        let grant = live_grant(&state)?;
        if client.instance != self.instance || grant.id != client.grant_id || !grant.projects.contains(project) {
            return Err(Error::AccessDenied);
        }
        if !state.runtime_aliases.values().any(|id| id == project) { return Err(Error::Conflict); }
        self.native_history_current()
    }
    pub(crate) fn dispatch(&self, client: &ClientSession, request: p::Request) -> p::Response {
        let result = (|| {
            self.native_history_current()?;
            if request.version != p::VERSION { return Err(Error::InvalidRequest); }
            // These two fixed routes touch only the bounded proposal inbox.
            // No native callback, executor or GUI approval runs in a socket.
            match &request.request {
                p::RequestBody::Requests(query) => return self.discover_requests(client, &query.project_id),
                p::RequestBody::AndroidBuildPrepare(input) => return self.prepare_agent_android_build(client, input.clone()),
                p::RequestBody::AndroidBuildStart(input) => return self.start_agent_android_build(client, input),
                p::RequestBody::AndroidBuildStatus(query) => return self.query_agent_android_build(client, query, false),
                p::RequestBody::AndroidBuildCancel(query) => return self.query_agent_android_build(client, query, true),
                p::RequestBody::IosArchivePrepare(input) => return self.prepare_agent_ios_archive(client, input.clone()),
                p::RequestBody::IosArchiveStart(input) => return self.start_agent_ios_archive(client, input),
                p::RequestBody::IosArchiveStatus(query) => return self.query_agent_ios_archive(client, query, false),
                p::RequestBody::IosArchiveCancel(query) => return self.query_agent_ios_archive(client, query, true),
                p::RequestBody::LocalCheckSubmit(input) => return self.submit_local_check(client, input.clone()),
                p::RequestBody::LocalCheckStatus(query) => return self.query_local_check(client, query, false),
                p::RequestBody::LocalCheckCancel(query) => return self.query_local_check(client, query, true),
                p::RequestBody::IdentityPrepare(q) => return self.identity_action_request(client, q, Some(crate::agent_identity_requests::actions::Kind::Prepare), None, false),
                p::RequestBody::IdentityStart(s) => return self.identity_action_request(client, &s.origin, Some(crate::agent_identity_requests::actions::Kind::Start), Some(s), false),
                p::RequestBody::IdentityActionStatus(q) => return self.identity_action_request(client, q, None, None, false),
                p::RequestBody::IdentityCancel(q) => return self.identity_action_request(client, q, None, None, true),
                p::RequestBody::IdentitySubmit(input) => return self.submit_identity(client, input.clone()),
                p::RequestBody::IdentityIntent(query) => return self.query_identity(client, query),
                _ => {},
            }
            let state = self.lock()?; self.check(&state)?;
            let grant = live_grant(&state)?;
            if request.version != p::VERSION || client.instance != self.instance || grant.id != client.grant_id { return Err(Error::AccessDenied); }
            let allowed = |id: &Id| if grant.projects.contains(id) { Ok(()) } else { Err(Error::AccessDenied) };
            let project = |id: &Id| state.saved.projects.iter().find(|p| &p.binding.project_id == id).map(|p| view(&state, p)).ok_or(Error::Conflict);
            Ok(match request.request {
                p::RequestBody::Requests(_) | p::RequestBody::IdentityPrepare(_) | p::RequestBody::IdentityStart(_) | p::RequestBody::IdentityActionStatus(_) | p::RequestBody::IdentityCancel(_)
                | p::RequestBody::IdentitySubmit(_) | p::RequestBody::IdentityIntent(_) | p::RequestBody::LocalCheckSubmit(_)
                    | p::RequestBody::LocalCheckStatus(_) | p::RequestBody::LocalCheckCancel(_)
                    | p::RequestBody::AndroidBuildPrepare(_) | p::RequestBody::AndroidBuildStart(_) | p::RequestBody::AndroidBuildStatus(_) | p::RequestBody::AndroidBuildCancel(_)
                    | p::RequestBody::IosArchivePrepare(_) | p::RequestBody::IosArchiveStart(_) | p::RequestBody::IosArchiveStatus(_) | p::RequestBody::IosArchiveCancel(_) => return Err(Error::InvalidRequest),
                p::RequestBody::Info(_) => p::ResponseBody::Info(p::ServiceInfo { read_only: false, read_grant_authorizes_execution: false, local_checks_require_separate_grant: true, requires_running_desktop: true,
                    cached_observations_are_authority: false, remaining_access_ms: remaining(grant) }),
                p::RequestBody::Projects(_) => p::ResponseBody::Projects(state.saved.projects.iter().filter(|p| grant.projects.contains(&p.binding.project_id)).map(|p| view(&state, p)).collect()),
                p::RequestBody::Observe(query) => { allowed(&query.project_id)?; p::ResponseBody::Observation(project(&query.project_id)?) }
                p::RequestBody::AndroidTools(query) => {
                    allowed(&query.project_id)?;
                    if !state.runtime_aliases.values().any(|id| id == &query.project_id) { return Err(Error::Conflict); }
                    // Retain this exact grant/alias guard through the bounded
                    // memory copy; no native callback or store write occurs.
                    p::ResponseBody::AndroidTools(self.android_tools.view(query.project_id))
                }
                p::RequestBody::Operations(query) => { allowed(&query.project_id)?; p::ResponseBody::Operations(state.saved.operations.iter().filter(|op| op.project_id == query.project_id).cloned().collect()) }
                p::RequestBody::Operation(query) => {
                    allowed(&query.project_id)?;
                    p::ResponseBody::Operation(state.saved.operations.iter().find(|op| op.project_id == query.project_id && op.operation_id == query.operation_id).cloned().ok_or(Error::Conflict)?)
                }
            })
        })();
        // Recheck after building the read result; IPC also repeats the same
        // atomic fence through client_current immediately before sending bytes.
        let result = self.native_history_current().and(result);
        p::Response { version: p::VERSION, request_id: request.request_id, service_instance: self.instance.clone(),
            client_id: client.client_id.clone(), session_id: client.session_id.clone(), response: result.unwrap_or_else(p::ResponseBody::Error) }
    }
    /// The IPC owner must first stop accepting, notify and join all original
    /// workers. This revokes admission but does not pretend to join them.
    pub(crate) fn stop(&self) -> Result<(), Error> { self.android_tools.unavailable(); self.build_requests.close(); self.local_checks.close(); self.identity_requests.close(); let mut state = self.lock()?; state.stopped = true; state.grant = None; Ok(()) }
}

fn valid_root(path: &Path) -> Result<&str, Error> {
    let text = path.to_str().ok_or(Error::InvalidRequest)?;
    if !path.is_absolute() || text.len() > 4096 || text.contains('\0') || text.contains("//")
        || path.components().any(|p| !matches!(p, Component::RootDir | Component::Normal(_)))
        || text.split('/').any(|s| s == "." || s == "..") { return Err(Error::InvalidRequest); }
    Ok(text)
}
fn view(state: &State, project: &ProjectRecord) -> p::ProjectObservation {
    p::ProjectObservation { project_id: project.binding.project_id.clone(), registered_in_current_host: state.runtime_aliases.values().any(|id| id == &project.binding.project_id),
        observation: project.observation.clone() }
}
fn consistent_status(state: p::OperationState, settlement: p::Settlement) -> bool {
    use p::{OperationState as S, Settlement as F};
    match state {
        S::Prepared | S::Running | S::CancellationRequested => settlement == F::Pending,
        S::Succeeded | S::Failed | S::Cancelled => settlement == F::Settled,
        S::Unknown => settlement == F::Unknown,
        S::RecoveryRequired => matches!(settlement, F::Settled | F::Unknown),
    }
}
fn live_grant(state: &State) -> Result<&Grant, Error> {
    let grant = state.grant.as_ref().ok_or(Error::AccessDenied)?;
    if Instant::now() >= grant.expires { return Err(Error::Expired); }
    Ok(grant)
}
fn remaining(grant: &Grant) -> u64 { grant.expires.saturating_duration_since(Instant::now()).as_millis().min(u64::MAX as u128) as u64 }
fn access_status(state: &State) -> ReadAccessStatus {
    match live_grant(state) {
        Ok(grant) if !state.stopped => ReadAccessStatus { enabled: true, remaining_ms: remaining(grant), project_ids: grant.projects.iter().cloned().collect() },
        _ => ReadAccessStatus { enabled: false, remaining_ms: 0, project_ids: Vec::new() },
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::application_state_store::Fixture;
    use std::{fs::File, os::unix::fs::MetadataExt, path::PathBuf};
    /// Test-only real mutex hold; no simulated write or native authority.
    pub(crate) fn with_state_locked<T>(service: &ApplicationService, body: impl FnOnce() -> T) -> T {
        let _original = service.state.lock().unwrap(); body()
    }
    pub(crate) fn register_fixture(service: &ApplicationService, app: &Path, name: &str, runtime: &str) -> (Id, PathBuf) {
        let root = app.parent().unwrap().join(name);
        std::fs::create_dir(&root).unwrap();
        let held = File::open(&root).unwrap(); let metadata = held.metadata().unwrap();
        let binding = service.register_native(runtime, &root, metadata.dev(), metadata.ino()).unwrap();
        (binding.project_id, root)
    }
    pub(crate) fn passive(root: &Path, hash: &str) -> serde_json::Value {
        serde_json::json!({"root":root.to_str().unwrap(),"observationScope":"single-request-non-atomic",
            "config":{"state":"format-valid","content":{"bytes":42,"sha256":hash},"data":{"mustNotEscape":"private fixture sentinel"}},
            "discovery":{"partial":false},"assurance":{"projectCodeExecuted":false,"toolsProbed":false},"issues":[]})
    }
    pub(crate) fn poison_fixture(service: &ApplicationService) {
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _original = service.state.lock().unwrap();
            panic!("synthetic service-state poisoning");
        }));
        assert!(poisoned.is_err());
    }
    fn request(body: p::RequestBody) -> p::Request { p::Request { version: 1, request_id: Id::random().unwrap(), request: body } }
    #[test]
    fn android_tools_read_keeps_scope_alias_revoke_and_store_checks() {
        use crate::service_android_tools::{Capture, Compatibility, Freshness, ObservationSlot};
        let f = Fixture::new(); let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let slot = Arc::new(ObservationSlot::default());
        let service = ApplicationService::open_with_android_tools(store.clone(), slot.clone()).unwrap();
        let (id, _) = register_fixture(&service, &f.app, "project", "project-1");
        let (other, _) = register_fixture(&service, &f.app, "other", "project-2");
        service.allow_agent_read(vec![id.clone()], Duration::from_secs(30)).unwrap();
        let client = service.admit_client().unwrap();
        let before = store.read(Namespace::Projects).unwrap();
        // Actual service-state guard held: native publication cannot wait for
        // this guard or run its usual store check/write path.
        with_state_locked(&service, || slot.publish(crate::service_android_tools::tests::catalogue()));
        let read = |id: Id| request(p::RequestBody::AndroidTools(p::ProjectQuery { project_id: id }));
        let result = service.dispatch(&client, read(id.clone()));
        match result.response {
            p::ResponseBody::AndroidTools(view) => {
                assert_eq!(view.capture, Capture::Observed);
                assert_eq!(view.freshness, Freshness::HistoricalNotRevalidated);
                assert_eq!(view.project_compatibility, Compatibility::NotChecked);
                assert_eq!(view.project_id, id);
            }
            _ => panic!("wrong response"),
        }
        assert_eq!(service.dispatch(&client, read(other)).response, p::ResponseBody::Error(Error::AccessDenied));
        service.state.lock().unwrap().runtime_aliases.remove("project-1");
        assert_eq!(service.dispatch(&client, read(id.clone())).response, p::ResponseBody::Error(Error::Conflict));
        // Losing the alias AFTER constructing a reply also refuses the same
        // original client's final transport recheck.
        assert_eq!(service.android_tools_client_current(&client, &id), Err(Error::Conflict));
        service.state.lock().unwrap().runtime_aliases.insert("project-1".into(), id.clone());
        service.revoke_agent_read().unwrap();
        assert_eq!(service.dispatch(&client, read(id.clone())).response, p::ResponseBody::Error(Error::AccessDenied));
        assert_eq!(service.android_tools_client_current(&client, &id), Err(Error::AccessDenied));
        service.allow_agent_read(vec![id.clone()], Duration::from_secs(30)).unwrap();
        assert_eq!(service.dispatch(&client, read(id.clone())).response, p::ResponseBody::Error(Error::AccessDenied));
        let client = service.admit_client().unwrap(); slot.unavailable();
        match service.dispatch(&client, read(id.clone())).response {
            p::ResponseBody::AndroidTools(view) => { assert_eq!(view.capture, Capture::Unavailable); assert!(view.observation.is_none()); }
            _ => panic!("wrong response"),
        }
        service.state.lock().unwrap().grant.as_mut().unwrap().expires = Instant::now();
        assert_eq!(service.dispatch(&client, read(id.clone())).response, p::ResponseBody::Error(Error::Expired));
        assert_eq!(service.android_tools_client_current(&client, &id), Err(Error::Expired));
        let after = store.read(Namespace::Projects).unwrap();
        assert_eq!(before.revision, after.revision); assert_eq!(before.bytes, after.bytes);
        service.stop().unwrap(); store.close().unwrap();
    }
    #[test]
    fn android_tools_restart_does_not_restore_observations_or_access() {
        use crate::service_android_tools::{Capture, ObservationSlot};
        let f = Fixture::new(); let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let slot = Arc::new(ObservationSlot::default());
        let service = ApplicationService::open_with_android_tools(store.clone(), slot.clone()).unwrap();
        let (id, root) = register_fixture(&service, &f.app, "project", "project-1");
        slot.publish(crate::service_android_tools::tests::catalogue());
        service.allow_agent_read(vec![id.clone()], Duration::from_secs(30)).unwrap();
        let before = store.read(Namespace::Projects).unwrap();
        service.stop().unwrap(); store.close().unwrap(); drop((service, store));
        let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let service = ApplicationService::open(store.clone()).unwrap();
        assert!(service.admit_client().is_err()); assert!(service.native_binding("project-1").is_err());
        let held = File::open(&root).unwrap(); let metadata = held.metadata().unwrap();
        let rebound = service.register_native("project-9", &root, metadata.dev(), metadata.ino()).unwrap();
        nix::unistd::close(held).unwrap(); assert_eq!(rebound.project_id, id);
        service.allow_agent_read(vec![id.clone()], Duration::from_secs(30)).unwrap();
        let client = service.admit_client().unwrap();
        match service.dispatch(&client, request(p::RequestBody::AndroidTools(p::ProjectQuery { project_id: id }))).response {
            p::ResponseBody::AndroidTools(view) => { assert_eq!(view.capture, Capture::Unobserved); assert!(view.observation.is_none()); }
            _ => panic!("wrong response"),
        }
        let after = store.read(Namespace::Projects).unwrap();
        assert_eq!(before.revision, after.revision); assert_eq!(before.bytes, after.bytes);
        service.stop().unwrap(); store.close().unwrap();
    }
    #[test]
    fn stable_ids_survive_restart_but_aliases_and_grants_do_not() {
        let f = Fixture::new(); let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let service = ApplicationService::open(store.clone()).unwrap();
        let (id, root) = register_fixture(&service, &f.app, "project", "project-1");
        service.publish_passive_snapshot("project-1", &passive(&root, &"1".repeat(64))).unwrap();
        service.allow_agent_read(vec![id.clone()], Duration::from_secs(30)).unwrap();
        let client = service.admit_client().unwrap();
        let before = service.dispatch(&client, request(p::RequestBody::Observe(p::ProjectQuery { project_id: id.clone() })));
        assert!(!String::from_utf8(p::encode_response(&before).unwrap()).unwrap().contains("private fixture sentinel"));
        service.stop().unwrap(); drop(service); store.close().unwrap(); drop(store);
        let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap()); let service = ApplicationService::open(store.clone()).unwrap();
        assert!(service.admit_client().is_err()); assert!(service.native_binding("project-1").is_err());
        let stat = File::open(&root).unwrap().metadata().unwrap();
        let restored = service.register_native("project-7", &root, stat.dev(), stat.ino()).unwrap();
        assert_eq!(restored.project_id, id);
        service.allow_agent_read(vec![id.clone()], Duration::from_secs(30)).unwrap();
        let client = service.admit_client().unwrap();
        let response = service.dispatch(&client, request(p::RequestBody::Observe(p::ProjectQuery { project_id: id })));
        match response.response { p::ResponseBody::Observation(project) => assert!(project.observation.unwrap().stale), _ => panic!("wrong response") }
        service.stop().unwrap(); store.close().unwrap();
    }
    #[test]
    fn replacement_move_or_wrong_alias_cannot_query_another_project() {
        let f = Fixture::new(); let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap()); let service = ApplicationService::open(store.clone()).unwrap();
        let (_, root) = register_fixture(&service, &f.app, "project", "project-1");
        let (_, other) = register_fixture(&service, &f.app, "other", "project-2");
        assert_eq!(service.publish_passive_snapshot("project-1", &passive(&other, &"1".repeat(64))).err(), Some(Error::Conflict));
        let stat = File::open(&root).unwrap().metadata().unwrap();
        assert!(service.register_native("project-1", &other, stat.dev(), stat.ino()).is_err());
        let moved = root.with_extension("moved"); std::fs::rename(&root, &moved).unwrap();
        assert!(service.register_native("project-3", &moved, stat.dev(), stat.ino()).is_err());
        std::fs::create_dir(&root).unwrap(); let replacement = File::open(&root).unwrap().metadata().unwrap();
        assert!(service.register_native("project-3", &root, replacement.dev(), replacement.ino()).is_err());
        service.stop().unwrap(); store.close().unwrap();
    }
    #[test]
    fn scope_revocation_expiry_and_status_do_not_create_authority() {
        let f = Fixture::new(); let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap()); let service = ApplicationService::open(store.clone()).unwrap();
        let (first, _) = register_fixture(&service, &f.app, "project", "project-1");
        let (second, _) = register_fixture(&service, &f.app, "other", "project-2");
        service.allow_agent_read(vec![first.clone()], Duration::from_secs(30)).unwrap(); let client = service.admit_client().unwrap();
        let result = service.dispatch(&client, request(p::RequestBody::Observe(p::ProjectQuery { project_id: second })));
        assert_eq!(result.response, p::ResponseBody::Error(Error::AccessDenied));
        assert!(service.publish_operation("project-1", Id::random().unwrap(), p::Action::Build, p::OperationState::Succeeded, p::Settlement::Pending).is_err());
        let operation = Id::random().unwrap();
        service.publish_operation("project-1", operation.clone(), p::Action::Build, p::OperationState::Unknown, p::Settlement::Unknown).unwrap();
        assert!(service.publish_operation("project-1", operation, p::Action::Build, p::OperationState::Succeeded, p::Settlement::Settled).is_err());
        service.revoke_agent_read().unwrap(); assert_eq!(service.client_current(&client).err(), Some(Error::AccessDenied));
        service.allow_agent_read(vec![first], Duration::from_secs(30)).unwrap();
        assert_eq!(service.client_current(&client).err(), Some(Error::AccessDenied));
        service.state.lock().unwrap().grant.as_mut().unwrap().expires = Instant::now();
        assert_eq!(service.admit_client().err().map(|e| e), Some(Error::Expired));
        service.stop().unwrap(); store.close().unwrap();
    }
    #[test]
    fn identical_fresh_passive_observation_does_not_advance_or_rewrite() {
        let f = Fixture::new(); let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let service = ApplicationService::open(store.clone()).unwrap();
        let (_, root) = register_fixture(&service, &f.app, "project", "project-1");
        let saved = passive(&root, &"1".repeat(64));
        let first = service.publish_passive_snapshot("project-1", &saved).unwrap();
        let before = store.read(Namespace::Projects).unwrap();
        assert_eq!(service.publish_passive_snapshot("project-1", &saved).unwrap(), first);
        let after = store.read(Namespace::Projects).unwrap();
        assert_eq!(after.revision, before.revision); assert_eq!(after.bytes, before.bytes);
        service.invalidate_native("project-1").unwrap();
        let stale = store.read(Namespace::Projects).unwrap();
        service.invalidate_native("project-1").unwrap();
        let still_stale = store.read(Namespace::Projects).unwrap();
        assert_eq!(still_stale.revision, stale.revision);
        assert_eq!(still_stale.bytes, stale.bytes);
        let refreshed = service.publish_passive_snapshot("project-1", &saved).unwrap().observation.unwrap();
        assert!(!refreshed.stale); assert!(refreshed.revision > first.observation.unwrap().revision);
        assert!(store.read(Namespace::Projects).unwrap().revision.0 > before.revision.0);
        service.stop().unwrap(); store.close().unwrap();
    }
    #[test]
    fn recovery_unknown_settlement_is_absorbing_for_same_operation() {
        let f = Fixture::new(); let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let service = ApplicationService::open(store.clone()).unwrap();
        register_fixture(&service, &f.app, "project", "project-1");
        let operation = Id::random().unwrap();
        service.publish_operation("project-1", operation.clone(), p::Action::Build, p::OperationState::RecoveryRequired, p::Settlement::Unknown).unwrap();
        let before = store.read(Namespace::Projects).unwrap();
        for (state, settlement) in [(p::OperationState::Running, p::Settlement::Pending),
            (p::OperationState::Succeeded, p::Settlement::Settled), (p::OperationState::RecoveryRequired, p::Settlement::Settled)] {
            assert_eq!(service.publish_operation("project-1", operation.clone(), p::Action::Build, state, settlement).err(), Some(Error::Conflict));
        }
        assert_eq!(store.read(Namespace::Projects).unwrap().revision, before.revision);
        assert_eq!(store.read(Namespace::Projects).unwrap().bytes, before.bytes);
        service.stop().unwrap(); store.close().unwrap();
    }

    #[test]
    fn optional_setup_guidance_uses_original_store_redaction_and_dedup() {
        use crate::service_setup_guidance as guidance;
        let f = Fixture::new(); let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let service = ApplicationService::open(store.clone()).unwrap();
        let (id, root) = register_fixture(&service, &f.app, "project", "project-1");
        let mut saved = passive(&root, &"1".repeat(64));
        let absent = service.publish_passive_snapshot("project-1", &saved).unwrap().observation.unwrap();
        assert!(absent.setup_analysis.is_none());
        saved["setupAnalysis"] = guidance::fixture(&[guidance::Platform::Android], p::ConfigurationState::FormatValid, false);
        saved["setupAnalysis"]["requirements"][0]["summary"] = serde_json::json!("never-store-summary-sentinel");
        saved["setupAnalysis"]["requirements"][0]["reference"] = serde_json::json!("never-store-path-sentinel/file");
        let projected = service.publish_passive_snapshot("project-1", &saved).unwrap().observation.unwrap();
        assert!(projected.setup_analysis.is_some()); assert!(projected.revision > absent.revision);
        let before = store.read(Namespace::Projects).unwrap();
        assert!(!String::from_utf8(before.bytes.clone()).unwrap().contains("sentinel"));
        saved["setupAnalysis"]["requirements"][0]["summary"] = serde_json::json!("Different discarded text.");
        assert_eq!(service.publish_passive_snapshot("project-1", &saved).unwrap().observation.unwrap(), projected);
        let unchanged = store.read(Namespace::Projects).unwrap();
        assert_eq!(unchanged.revision, before.revision); assert_eq!(unchanged.bytes, before.bytes);
        saved["setupAnalysis"]["requirements"][0]["state"] = serde_json::json!("needs-input");
        let changed = service.publish_passive_snapshot("project-1", &saved).unwrap().observation.unwrap();
        assert!(changed.revision > projected.revision);
        service.allow_agent_read(vec![id.clone()], Duration::from_secs(30)).unwrap();
        let client = service.admit_client().unwrap();
        let request = request(p::RequestBody::Observe(p::ProjectQuery { project_id: id }));
        let response = service.dispatch(&client, request.clone());
        let bytes = p::encode_response(&response).unwrap();
        let decoded = p::decode_response(&bytes, &request.request_id, service.instance()).unwrap();
        assert_eq!(decoded, response);
        let mut incompatible = serde_json::to_value(&response).unwrap();
        incompatible["response"]["value"]["observation"]["setupAnalysis"]["discoveryPartial"] = serde_json::json!(true);
        let decoded = p::decode_response(&serde_json::to_vec(&incompatible).unwrap(), &request.request_id, service.instance()).unwrap();
        match decoded.response { p::ResponseBody::Observation(row) => {
            let observed = row.observation.unwrap(); assert!(observed.setup_analysis.is_none());
            assert_eq!(observed.configuration, changed.configuration);
        }, _ => panic!("wrong response") }
        saved["setupAnalysis"]["schemaVersion"] = serde_json::json!(2);
        let unavailable = service.publish_passive_snapshot("project-1", &saved).unwrap().observation.unwrap();
        assert!(unavailable.setup_analysis.is_none()); assert!(unavailable.revision > changed.revision);
        assert_eq!(unavailable.configuration, changed.configuration);
        let before = store.read(Namespace::Projects).unwrap();
        service.publish_passive_snapshot("project-1", &saved).unwrap();
        let after = store.read(Namespace::Projects).unwrap();
        assert_eq!(before.revision, after.revision); assert_eq!(before.bytes, after.bytes);
        saved["config"]["content"]["sha256"] = serde_json::json!("bad");
        assert_eq!(service.publish_passive_snapshot("project-1", &saved).err(), Some(Error::InvalidRequest));
        service.stop().unwrap(); store.close().unwrap();
    }
    #[test]
    fn setup_guidance_restart_is_stale_and_optional_damage_does_not_hide_base_damage() {
        use crate::service_setup_guidance as guidance;
        let f = Fixture::new(); let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let service = ApplicationService::open(store.clone()).unwrap();
        let (id, root) = register_fixture(&service, &f.app, "project", "project-1");
        let mut saved = passive(&root, &"1".repeat(64));
        saved["setupAnalysis"] = guidance::fixture(&[guidance::Platform::Ios], p::ConfigurationState::FormatValid, false);
        let original = service.publish_passive_snapshot("project-1", &saved).unwrap().observation.unwrap();
        service.stop().unwrap(); drop(service); store.close().unwrap(); drop(store);
        let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let service = ApplicationService::open(store.clone()).unwrap();
        assert!(service.admit_client().is_err()); assert!(service.native_binding("project-1").is_err());
        let stat = File::open(&root).unwrap().metadata().unwrap();
        assert_eq!(service.register_native("project-9", &root, stat.dev(), stat.ino()).unwrap().project_id, id);
        service.allow_agent_read(vec![id.clone()], Duration::from_secs(30)).unwrap();
        let client = service.admit_client().unwrap();
        let response = service.dispatch(&client, request(p::RequestBody::Observe(p::ProjectQuery { project_id: id })));
        match response.response { p::ResponseBody::Observation(row) => {
            let restored = row.observation.unwrap(); assert!(restored.stale);
            assert_eq!(restored.setup_analysis, original.setup_analysis);
        }, _ => panic!("wrong response") }
        let refreshed = service.publish_passive_snapshot("project-9", &saved).unwrap().observation.unwrap();
        assert!(!refreshed.stale); assert!(refreshed.revision > original.revision);
        service.stop().unwrap(); drop(service);
        // Exact original store CAS, not a replacement/mocked filesystem owner.
        let current = store.read(Namespace::Projects).unwrap();
        let mut data: serde_json::Value = serde_json::from_slice(&current.bytes).unwrap();
        data["projects"][0]["observation"]["setupAnalysis"]["discoveryPartial"] = serde_json::json!(true);
        store.replace(Namespace::Projects, current.revision, &serde_json::to_vec(&data).unwrap()).unwrap();
        let reopened = ApplicationService::open(store.clone()).unwrap();
        assert!(reopened.state.lock().unwrap().saved.projects[0].observation.as_ref().unwrap().setup_analysis.is_none());
        reopened.stop().unwrap(); drop(reopened);
        let current = store.read(Namespace::Projects).unwrap();
        data["projects"][0]["observation"]["setupAnalysis"] = serde_json::json!({"unsupported": "no-default-empty"});
        store.replace(Namespace::Projects, current.revision, &serde_json::to_vec(&data).unwrap()).unwrap();
        let reopened = ApplicationService::open(store.clone()).unwrap();
        let observed = reopened.state.lock().unwrap().saved.projects[0].observation.clone().unwrap();
        assert!(observed.setup_analysis.is_none()); assert_eq!(observed.configuration, original.configuration);
        reopened.stop().unwrap(); drop(reopened);
        let current = store.read(Namespace::Projects).unwrap();
        data["projects"][0]["observation"]["issueCount"] = serde_json::json!(20_001);
        store.replace(Namespace::Projects, current.revision, &serde_json::to_vec(&data).unwrap()).unwrap();
        assert_eq!(ApplicationService::open(store.clone()).err(), Some(Error::RecoveryRequired));
        store.close().unwrap();
    }
}
