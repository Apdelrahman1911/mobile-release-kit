//! Shared saved observations, explicit read consent and durable project IDs.
//!
//! The running GUI remains the genuine native host in this first slice. It
//! publishes only after original owners return. This module never constructs
//! DocumentBinding, substitutes a window ID, launches an engine, accesses a
//! credential, or derives operation finality from a cached response.
use crate::{application_state_store::{Namespace, PrivateStateDirectory, Revision}, service_protocol as p};
use p::{Error, Id};
use serde::{Deserialize, Serialize};
use std::{collections::{BTreeMap, BTreeSet}, path::{Component, Path}, sync::{Arc, Mutex, MutexGuard}, time::{Duration, Instant}};

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

pub(crate) struct ApplicationService { store: Arc<PrivateStateDirectory>, instance: Id, state: Mutex<State> }
impl ApplicationService {
    pub(crate) fn open(store: Arc<PrivateStateDirectory>) -> Result<Self, Error> {
        let snapshot = store.read(Namespace::Projects).map_err(|e| e.code)?;
        let mut saved = if snapshot.bytes.is_empty() && snapshot.revision == Revision(0) { Persisted::empty() }
            else { serde_json::from_slice::<Persisted>(&snapshot.bytes).map_err(|_| Error::RecoveryRequired)? };
        saved.validate(snapshot.revision)?;
        // Remembered facts remain readable, but restart does not reacquire the
        // original project, operation, credential or observation authority.
        for project in &mut saved.projects { if let Some(observation) = &mut project.observation { observation.stale = true; } }
        for operation in &mut saved.operations { operation.stale = true; }
        Ok(Self { store, instance: Id::random()?, state: Mutex::new(State { revision: snapshot.revision, saved,
            runtime_aliases: BTreeMap::new(), grant: None, stopped: false }) })
    }
    pub(crate) fn instance(&self) -> &Id { &self.instance }
    pub(crate) fn state_directory(&self) -> &Arc<PrivateStateDirectory> { &self.store }
    fn lock(&self) -> Result<MutexGuard<'_, State>, Error> { self.state.lock().map_err(|_| Error::StateUnknown) }
    fn check(&self, state: &State) -> Result<(), Error> {
        if state.stopped { return Err(Error::Unavailable); }
        // Missing/replaced state cannot be concealed by an in-memory cache.
        let snapshot = self.store.read(Namespace::Projects).map_err(|e| e.code)?;
        if snapshot.revision != state.revision { return Err(Error::Conflict); }
        Ok(())
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
        if state.saved.projects[index].observation.as_ref().is_some_and(|previous| !previous.stale
            && previous.configuration == saved_config && previous.discovery_partial == partial && previous.issue_count == issues as u32) {
            // Idle saved-file polling is not a new observation revision when
            // every retained fact is unchanged. A stale->fresh return still
            // persists below, even if the same saved bytes were observed.
            return Ok(view(&state, &state.saved.projects[index]));
        }
        let revision = state.revision.0.checked_add(1).ok_or(Error::StateUnknown)?;
        let mut next = state.saved.clone();
        next.projects[index].observation = Some(p::SavedObservation { revision, stale: false, configuration: saved_config,
            discovery_partial: partial, issue_count: issues as u32 });
        self.save(&mut state, next)?;
        Ok(view(&state, &state.saved.projects[index]))
    }
    pub(crate) fn invalidate_native(&self, runtime_id: &str) -> Result<(), Error> {
        let mut state = self.lock()?; self.check(&state)?;
        let id = state.runtime_aliases.get(runtime_id).ok_or(Error::Conflict)?.clone();
        let mut next = state.saved.clone();
        let project = next.projects.iter_mut().find(|p| p.binding.project_id == id).ok_or(Error::Conflict)?;
        if let Some(observation) = &mut project.observation {
            observation.stale = true;
            observation.revision = state.revision.0.checked_add(1).ok_or(Error::StateUnknown)?;
        }
        // Only invalidate DATA. Existing credential assessments/plans still
        // need their original domain owners' revocation, wired by the host.
        self.save(&mut state, next)
    }
    pub(crate) fn publish_operation(&self, runtime_id: &str, operation_id: Id, action: p::Action, operation_state: p::OperationState,
        settlement: p::Settlement) -> Result<(), Error> {
        if !consistent_status(operation_state, settlement) { return Err(Error::InvalidRequest); }
        let mut state = self.lock()?; self.check(&state)?;
        let id = state.runtime_aliases.get(runtime_id).ok_or(Error::Conflict)?.clone();
        let mut next = state.saved.clone();
        let observation = p::OperationObservation { operation_id: operation_id.clone(), project_id: id.clone(), action,
            state: operation_state, settlement, observation_revision: state.revision.0.checked_add(1).ok_or(Error::StateUnknown)?, stale: false };
        if let Some(existing) = next.operations.iter_mut().find(|op| op.operation_id == operation_id) {
            if existing.project_id != id || existing.action != action { return Err(Error::Conflict); }
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
        if projects.is_empty() || projects.len() > p::PROJECT_LIMIT || lifetime.is_zero() || lifetime > MAX_ACCESS { return Err(Error::InvalidRequest); }
        let mut state = self.lock()?; self.check(&state)?;
        let selected: BTreeSet<_> = projects.into_iter().collect();
        if selected.iter().any(|id| !state.runtime_aliases.values().any(|registered| registered == id)) { return Err(Error::Conflict); }
        state.grant = Some(Grant { id: Id::random()?, projects: selected, expires: Instant::now().checked_add(lifetime).ok_or(Error::InvalidRequest)? });
        Ok(access_status(&state))
    }
    pub(crate) fn revoke_agent_read(&self) -> Result<(), Error> { self.lock()?.grant = None; Ok(()) }
    pub(crate) fn read_access_status(&self) -> Result<ReadAccessStatus, Error> { let state = self.lock()?; Ok(access_status(&state)) }
    pub(crate) fn admit_client(&self) -> Result<ClientSession, Error> {
        let state = self.lock()?; self.check(&state)?;
        let grant = live_grant(&state)?;
        Ok(ClientSession { client_id: Id::random()?, session_id: Id::random()?, grant_id: grant.id.clone(), instance: self.instance.clone() })
    }
    pub(crate) fn client_current(&self, client: &ClientSession) -> Result<(), Error> {
        let state = self.lock()?; self.check(&state)?;
        if client.instance != self.instance || live_grant(&state)?.id != client.grant_id { return Err(Error::AccessDenied); }
        Ok(())
    }
    pub(crate) fn dispatch(&self, client: &ClientSession, request: p::Request) -> p::Response {
        let result = (|| {
            let state = self.lock()?; self.check(&state)?;
            let grant = live_grant(&state)?;
            if request.version != p::VERSION || client.instance != self.instance || grant.id != client.grant_id { return Err(Error::AccessDenied); }
            let allowed = |id: &Id| if grant.projects.contains(id) { Ok(()) } else { Err(Error::AccessDenied) };
            let project = |id: &Id| state.saved.projects.iter().find(|p| &p.binding.project_id == id).map(|p| view(&state, p)).ok_or(Error::Conflict);
            Ok(match request.request {
                p::RequestBody::Info(_) => p::ResponseBody::Info(p::ServiceInfo { read_only: true, requires_running_desktop: true,
                    cached_observations_are_authority: false, remaining_access_ms: remaining(grant) }),
                p::RequestBody::Projects(_) => p::ResponseBody::Projects(state.saved.projects.iter().filter(|p| grant.projects.contains(&p.binding.project_id)).map(|p| view(&state, p)).collect()),
                p::RequestBody::Observe(query) => { allowed(&query.project_id)?; p::ResponseBody::Observation(project(&query.project_id)?) }
                p::RequestBody::Operations(query) => { allowed(&query.project_id)?; p::ResponseBody::Operations(state.saved.operations.iter().filter(|op| op.project_id == query.project_id).cloned().collect()) }
                p::RequestBody::Operation(query) => {
                    allowed(&query.project_id)?;
                    p::ResponseBody::Operation(state.saved.operations.iter().find(|op| op.project_id == query.project_id && op.operation_id == query.operation_id).cloned().ok_or(Error::Conflict)?)
                }
            })
        })();
        p::Response { version: p::VERSION, request_id: request.request_id, service_instance: self.instance.clone(),
            client_id: client.client_id.clone(), session_id: client.session_id.clone(), response: result.unwrap_or_else(p::ResponseBody::Error) }
    }
    /// The IPC owner must first stop accepting, notify and join all original
    /// workers. This revokes admission but does not pretend to join them.
    pub(crate) fn stop(&self) -> Result<(), Error> { let mut state = self.lock()?; state.stopped = true; state.grant = None; Ok(()) }
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
}
