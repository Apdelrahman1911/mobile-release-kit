//! The fixed VersionAllocations port over the ORIGINAL private state directory.
//!
//! This is not a filesystem opener, public RPC, allocation algorithm or grant.
//! The native caller retains this port before `load` and performs every IO call
//! OUTSIDE Document/Edit locks. It must obtain the actual service project/root
//! binding off-lock, then rematch its original Document ticket under the lock.
//! A supplied binding, protected-branch boolean or successful state ACK is DATA,
//! not proof of source, Store freshness, repository authority or permission to PUT.
//!
//! No route is installed here. Python remains the sole version/ledger policy
//! implementation. These checks constrain the state shape, exact owned rows and
//! monotonic journal transitions; they do not reimplement version arithmetic.
use crate::{
    application_service::ProjectBinding,
    application_state_store::{Cleanup, Durability, Effect, Namespace, PrivateStateDirectory, Revision, Snapshot, StateError},
    github_connection_protocol::{coordinate, numeric_id},
    github_preflight_protocol::{branch, hex},
    protocol::{strict_version_allocation_state_json, strict_version_enrollment_state_json},
    service_protocol::{Error, Id},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt::Write as _, sync::Arc};

#[path = "version_allocation_protocol_native.rs"]
pub(crate) mod dialogue;
#[path = "version_allocation_state_jobs.rs"]
pub(crate) mod jobs;
#[path = "version_enrollment_state_native.rs"]
pub(crate) mod enrollment;
#[path="version_allocation_ios_inventory.rs"]
pub(crate) mod ios_inventory;
#[path="version_allocation_android_inventory.rs"]
pub(crate) mod play_inventory;
#[path="version_allocation_paired_inventory.rs"]
pub(crate) mod paired_inventory;
#[path="version_reserve_state_native.rs"]
pub(crate) mod reserve;

const PROTOCOL: &str = "mrk-version-allocation-state/1";
const ALLOCATION_PROTOCOL: &str = "mrk-version-allocation/1";
const STATE_LIMIT: usize = 1024 * 1024;
const ROW_LIMIT: usize = 16 * 1024;
const AUTHORITY_LIMIT: usize = 8;
const LOCAL_LIMIT: usize = 64;
const REMOTE_WRITES: u8 = 5;
type Result<T> = std::result::Result<T, StateError>;

fn need(value: bool) -> Result<()> {
    if value { Ok(()) } else { Err(Error::InvalidRequest.into()) }
}
fn unknown() -> StateError {
    StateError { code: Error::StateUnknown, effect: Effect::Unknown,
        durability: Durability::Unknown, cleanup: Cleanup::Unknown }
}
fn uuid(value: &str) -> bool {
    value.len() == 36 && [8, 13, 18, 23].into_iter().all(|i| value.as_bytes()[i] == b'-')
        && value.as_bytes()[14] == b'4' && b"89ab".contains(&value.as_bytes()[19])
        && value.bytes().enumerate().all(|(i, b)| [8, 13, 18, 23].contains(&i)
            || b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn shared_id(value: &str) -> bool { Id::parse(value).is_ok() || uuid(value) }
fn full_ref(value: &str) -> bool {
    value.len() <= 220 && value.strip_prefix("refs/heads/").or_else(|| value.strip_prefix("refs/tags/"))
        .is_some_and(branch)
}
fn closed(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|v| v.len() == keys.len() && keys.iter().all(|k| v.contains_key(*k)))
}
fn string(value: &Value, valid: impl FnOnce(&str) -> bool) -> bool { value.as_str().is_some_and(valid) }
fn integer(value: &Value, min: u64, max: u64) -> bool { value.as_u64().is_some_and(|n| (min..=max).contains(&n)) }

/// The Python codec uses sorted ASCII JSON, including UTF-16 escapes for the
/// nullable Store marketing-format DATA. Do not normalize IDs or Unicode text.
fn canonical<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(value).map_err(|_| StateError::from(Error::InvalidRequest))?;
    value.sort_all_objects();
    let utf8 = serde_json::to_string(&value).map_err(|_| StateError::from(Error::InvalidRequest))?;
    need(utf8.len() <= limit)?;
    let mut ascii = String::with_capacity(utf8.len());
    for ch in utf8.chars() {
        if ch < '\u{7f}' { ascii.push(ch); }
        else {
            for unit in ch.encode_utf16(&mut [0u16; 2]).iter() {
                write!(&mut ascii, "\\u{unit:04x}").map_err(|_| StateError::from(Error::InvalidRequest))?;
            }
        }
        need(ascii.len() <= limit)?;
    }
    Ok(ascii.into_bytes())
}
fn hash<T: Serialize>(domain: &[u8], value: &T) -> Result<String> {
    let mut hash = Sha256::new(); hash.update(domain); hash.update(canonical(value, ROW_LIMIT)?);
    Ok(format!("{:x}", hash.finalize()))
}
fn decode<T: for<'a> Deserialize<'a>>(value: Value) -> Result<T> {
    let bytes = canonical(&value, ROW_LIMIT)?;
    let checked = strict_version_allocation_state_json(&bytes).map_err(|_| StateError::from(Error::InvalidRequest))?;
    serde_json::from_value(checked).map_err(|_| Error::InvalidRequest.into())
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Authority {
    project_id: String, repository: String, repository_id: String,
    ledger_id: String, genesis_sha256: String, protected_branch: bool,
}
impl Authority {
    fn valid(&self) -> bool {
        shared_id(&self.project_id) && coordinate(&self.repository) && numeric_id(&self.repository_id)
            && uuid(&self.ledger_id) && hex(&self.genesis_sha256, 64) && self.protected_branch
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Checkpoint { sequence: u32, head_sha256: String, commit: String }
impl Checkpoint {
    fn valid(&self) -> bool { self.sequence <= 64 && hex(&self.head_sha256, 64) && hex(&self.commit, 40) }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct Request(Value);
impl Request {
    fn project(&self) -> &str { self.0["projectId"].as_str().unwrap_or("") }
    fn candidate(&self) -> &str { self.0["candidateId"].as_str().unwrap_or("") }
    fn schema_version(&self) -> u32 { match self.0["policy"]["schemaVersion"].as_u64() {Some(2)=>2,Some(3)=>3,Some(4)=>4,_=>1} }
    fn request_hash(&self) -> Result<String> { hash(match self.schema_version() {2=>ios_inventory::REQUEST_DOMAIN,3=>play_inventory::REQUEST_DOMAIN,4=>paired_inventory::REQUEST_DOMAIN,_=>b"mrk:allocation-request:1\0"}, self) }
    fn reservation_domain(&self) -> &'static [u8] { match self.schema_version() {2=>ios_inventory::RESERVATION_DOMAIN,3=>play_inventory::RESERVATION_DOMAIN,4=>paired_inventory::RESERVATION_DOMAIN,_=>b"mrk:allocation-reservation:1\0"} }
    fn observations_valid(&self, values: &[Value]) -> bool {
        if self.schema_version() == 4 { paired_inventory::observations_shape(values,self) }
        else if self.schema_version() == 3 { values.len() == 1 && values.iter().all(|v| play_inventory::observation_shape(v,self)) }
        else if self.schema_version() == 2 { values.len() == 1 && values.iter().all(|v| ios_inventory::observation_shape(v,self)) }
        else { values.len() <= 2 && values.iter().all(observation_shape) }
    }
    fn valid(&self) -> bool {
        let v = &self.0;
        let source = &v["source"]; let policy = &v["policy"];
        let newer = matches!(policy["schemaVersion"].as_u64(),Some(2|3|4));
        let rules = policy["rules"].as_array();
        let mut refs = BTreeSet::new();
        closed(v, if newer { &["projectId", "candidateId", "identityRevision", "source", "baseVersion", "platforms", "policy", "storeContextRevision"] }
            else { &["projectId", "candidateId", "identityRevision", "source", "baseVersion", "platforms", "policy"] })
            && shared_id(self.project()) && uuid(self.candidate()) && string(&v["identityRevision"], |s| hex(s, 64))
            && closed(source, &["commit", "tree", "ref", "configurationSha256", "versionSha256"])
            && ["commit", "tree"].into_iter().all(|k| string(&source[k], |s| hex(s, 40)))
            && ["configurationSha256", "versionSha256"].into_iter().all(|k| string(&source[k], |s| hex(s, 64)))
            && string(&source["ref"], full_ref) && version_shape(&v["baseVersion"])
            && [json!(["android"]), json!(["ios"]), json!(["android", "ios"])].contains(&v["platforms"])
            && closed(policy, if newer { &["schemaVersion", "mode", "rules", "buildCeiling", "storeMaxAgeSeconds", "storeScope"] }
                else { &["schemaVersion", "mode", "rules", "buildCeiling", "storeMaxAgeSeconds"] })
            && (if newer { (if self.schema_version()==2 {v["platforms"] == json!(["ios"]) && policy["storeScope"] == ios_inventory::POLICY_SCOPE}
                else if self.schema_version()==3 {v["platforms"]==json!(["android"])&&policy["storeScope"]==play_inventory::POLICY_SCOPE}
                else {v["platforms"]==json!(["android","ios"])&&policy["storeScope"]==paired_inventory::POLICY_SCOPE})
                && string(&v["storeContextRevision"], |s| hex(s, 64)) } else { policy["schemaVersion"].as_u64() == Some(1) })
            && policy["mode"] == "automatic"
            && integer(&policy["buildCeiling"], 1, 2_100_000_000) && integer(&policy["storeMaxAgeSeconds"], 1, 3600)
            && rules.is_some_and(|rules| !rules.is_empty() && rules.len() <= 32 && rules.iter().all(|r|
                closed(r, &["ref", "increment"]) && string(&r["ref"], |s| full_ref(s) && refs.insert(s.to_owned()))
                && string(&r["increment"], |s| ["build", "patch", "minor", "major"].contains(&s))))
    }
}
fn version_shape(v: &Value) -> bool {
    // Same bounded wire shape as release_version_protocol, NOT a second
    // marketing/iOS range policy. The existing Python parser decides support.
    closed(v, &["name", "build"]) && integer(&v["build"], 1, 2_100_000_000)
        && string(&v["name"], |s| !s.is_empty() && s.len() <= 64
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b)))
}
fn observation_shape(v: &Value) -> bool {
    closed(v, &["platform", "identityRevision", "revision", "observedAt", "maxBuild", "marketingVersion", "complete", "formatSupported", "scope"])
        && string(&v["platform"], |s| ["android", "ios"].contains(&s))
        && ["identityRevision", "revision"].into_iter().all(|k| string(&v[k], |s| hex(s, 64)))
        && integer(&v["observedAt"], 0, i64::MAX as u64) && integer(&v["maxBuild"], 0, 2_100_000_000)
        && (v["marketingVersion"].is_null() || string(&v["marketingVersion"], |s| !s.is_empty() && s.chars().count() <= 64))
        && v["complete"].is_boolean() && v["formatSupported"].is_boolean() && v["scope"] == "application-all-builds"
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Reservation {
    sequence: u32, previous_sha256: String, request: Request, request_sha256: String,
    version: Value, store_observations: Vec<Value>, allocated_at: u64, sha256: String,
}
impl Reservation {
    fn valid(&self) -> Result<()> {
        need((1..=64).contains(&self.sequence) && hex(&self.previous_sha256, 64) && self.request.valid()
            && version_shape(&self.version) && self.store_observations.len() <= 2
            && self.request.observations_valid(&self.store_observations) && self.allocated_at <= i64::MAX as u64)?;
        need(self.request_sha256 == self.request.request_hash()?)?;
        let mut value = serde_json::to_value(self).map_err(|_| StateError::from(Error::InvalidRequest))?;
        value.as_object_mut().ok_or_else(|| StateError::from(Error::InvalidRequest))?.remove("sha256");
        need(self.sha256 == hash(self.request.reservation_domain(), &value)?)
    }
    fn at_or_before(&self, checkpoint: &Checkpoint) -> bool {
        self.sequence <= checkpoint.sequence && (self.sequence != checkpoint.sequence || self.sha256 == checkpoint.head_sha256)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pending {
    schema_version: u32, protocol: String, authority: Authority, checkpoint: Checkpoint,
    expected_blob: String, reservation: Reservation,
}
impl Pending {
    fn valid(&self) -> Result<()> {
        need(self.schema_version == self.reservation.request.schema_version()
            && self.protocol == match self.schema_version {2=>ios_inventory::PROTOCOL,3=>play_inventory::PROTOCOL,4=>paired_inventory::PROTOCOL,_=>ALLOCATION_PROTOCOL}
            && self.authority.valid()
            && self.checkpoint.valid() && hex(&self.expected_blob, 40)
            && self.reservation.request.project() == self.authority.project_id
            && self.reservation.sequence == self.checkpoint.sequence + 1
            && self.reservation.previous_sha256 == self.checkpoint.head_sha256)?;
        self.reservation.valid()?; canonical(self, ROW_LIMIT - 1)?; Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityState { authority: Authority, checkpoint: Checkpoint, pending: Option<Pending> }
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Enrollment { local_project_id: String, authority_project_id: String }
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Candidate { local_project_id: String, request: Request, reservation: Option<Reservation> }
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct State {
    schema_version: u32, protocol: String, authorities: Vec<AuthorityState>,
    enrollments: Vec<Enrollment>, candidates: Vec<Candidate>,
}
impl State {
    fn empty() -> Self {
        Self { schema_version: 3, protocol: PROTOCOL.to_owned(), authorities: Vec::new(), enrollments: Vec::new(), candidates: Vec::new() }
    }
    fn parse(snapshot: &Snapshot) -> Result<Self> { Self::parse_original(snapshot, false) }
    fn parse_original(snapshot: &Snapshot, enrollment: bool) -> Result<Self> {
        if snapshot.revision == Revision(0) && snapshot.bytes.is_empty() { return Ok(Self::empty()); }
        let bytes = &snapshot.bytes;
        need(!bytes.is_empty() && bytes.len() <= STATE_LIMIT && bytes.last() == Some(&b'\n')
            && bytes.iter().filter(|b| **b == b'\n').count() == 1)?;
        let parsed = if enrollment {
            strict_version_enrollment_state_json(&bytes[..bytes.len() - 1])
        } else { strict_version_allocation_state_json(&bytes[..bytes.len() - 1]) };
        let mut value = parsed.map_err(|error| StateError::from(
            if enrollment && error.code == "version_enrollment_state_limit" { Error::Unavailable }
            else { Error::RecoveryRequired }))?;
        let version = value["schemaVersion"].as_u64().ok_or_else(|| StateError::from(Error::RecoveryRequired))?;
        let keys: &[&str] = match version {
            1 => &["schemaVersion", "protocol", "authorities"],
            2 => &["schemaVersion", "protocol", "authorities", "enrollments"],
            3 => &["schemaVersion", "protocol", "authorities", "enrollments", "candidates"],
            _ => return Err(Error::RecoveryRequired.into()),
        };
        need(closed(&value, keys) && value["protocol"] == PROTOCOL)?;
        // Validate the legacy schema's OWN canonical bytes before any in-memory
        // addition. Neither load nor a retry rewrites it or infers enrollment.
        let mut encoded = canonical(&value, STATE_LIMIT - 1)?; encoded.push(b'\n'); need(encoded == *bytes)?;
        if version < 3 { value["candidates"] = json!([]); }
        if version == 1 { value["enrollments"] = json!([]); }
        value["schemaVersion"] = json!(3);
        let state: Self = serde_json::from_value(value).map_err(|_| StateError::from(Error::RecoveryRequired))?;
        state.valid()?;
        // Missing nullable fields and any typed-decoder normalization are not
        // legacy upgrades. Round-trip that schema, just as the Python codec does.
        let mut checked = serde_json::to_value(&state).map_err(|_| StateError::from(Error::RecoveryRequired))?;
        let object = checked.as_object_mut().ok_or_else(|| StateError::from(Error::RecoveryRequired))?;
        if version < 3 { object.remove("candidates"); }
        if version == 1 { object.remove("enrollments"); }
        object.insert("schemaVersion".to_owned(), json!(version));
        let mut encoded = canonical(&checked, STATE_LIMIT - 1)?; encoded.push(b'\n'); need(encoded == *bytes)?;
        Ok(state)
    }
    fn valid(&self) -> Result<()> {
        need(self.schema_version == 3 && self.protocol == PROTOCOL && self.authorities.len() <= AUTHORITY_LIMIT
            && self.enrollments.len() <= LOCAL_LIMIT && self.candidates.len() <= LOCAL_LIMIT)?;
        need(self.authorities.windows(2).all(|w| w[0].authority.project_id < w[1].authority.project_id)
            && self.enrollments.windows(2).all(|w| w[0].local_project_id < w[1].local_project_id)
            && self.candidates.windows(2).all(|w| w[0].local_project_id < w[1].local_project_id))?;
        for row in &self.authorities {
            need(row.authority.valid() && row.checkpoint.valid()
                && (row.checkpoint.sequence != 0 || row.checkpoint.head_sha256 == row.authority.genesis_sha256))?;
            if let Some(pending) = &row.pending {
                pending.valid()?;
                need(pending.authority == row.authority && pending.checkpoint.sequence <= row.checkpoint.sequence
                    && (pending.checkpoint.sequence != row.checkpoint.sequence || pending.checkpoint.head_sha256 == row.checkpoint.head_sha256))?;
            }
        }
        for row in &self.enrollments {
            need(Id::parse(&row.local_project_id).is_ok()
                && self.authorities.iter().any(|a| a.authority.project_id == row.authority_project_id))?;
        }
        let mut seen = BTreeSet::new();
        for row in &self.candidates {
            need(row.request.valid() && seen.insert((row.request.project(), row.request.candidate())))?;
            let authority = self.enrolled(&row.local_project_id, row.request.project())?;
            if let Some(reserved) = &row.reservation {
                reserved.valid()?;
                need(reserved.request == row.request && reserved.at_or_before(&authority.checkpoint))?;
            }
            if let Some(pending) = &authority.pending {
                if pending.reservation.request.candidate() == row.request.candidate() {
                    need(pending.reservation.request == row.request && row.reservation.is_none())?;
                }
            }
        }
        Ok(())
    }
    fn enrolled(&self, local: &str, shared: &str) -> Result<&AuthorityState> {
        need(self.enrollments.iter().any(|e| e.local_project_id == local && e.authority_project_id == shared))?;
        self.authorities.iter().find(|a| a.authority.project_id == shared).ok_or_else(|| Error::Conflict.into())
    }
    fn candidate(&self, local: &str) -> Option<&Candidate> { self.candidates.iter().find(|r| r.local_project_id == local) }
    fn bytes(&self) -> Result<Vec<u8>> {
        self.valid()?;
        let mut bytes = canonical(self, STATE_LIMIT - 1)?; bytes.push(b'\n');
        strict_version_allocation_state_json(&bytes).map_err(|_| StateError::from(Error::InvalidRequest))?;
        Ok(bytes)
    }
}

/// Only these five worker transitions exist. Each payload remains bounded DATA
/// from the original finite allocation worker, not a renderer-selected writer.
pub(crate) enum Transition {
    Checkpoint(Value), Pending(Value), Rejected(Value),
    Resolved { pending: Value, checkpoint: Value },
    Reused { reservation: Value, checkpoint: Value },
}
pub(crate) struct WriteAck { pub(crate) revision: Revision, pub(crate) payload_sha256: String }
struct Attempt { state: State, bytes: Vec<u8>, returned: Option<Snapshot> }

/// One original native action, including any failed/uncertain write. Never
/// replace this with a newly loaded port to clear failure or obtain another PUT.
pub(crate) struct VersionAllocationStatePort {
    store: Arc<PrivateStateDirectory>, project: ProjectBinding, authority: Authority,
    snapshot: Option<Snapshot>, state: Option<State>, bound: Option<Request>,
    attempted: Option<Attempt>, failure: Option<StateError>, poisoned: bool, remote_writes: u8, bounded: bool,
}
impl VersionAllocationStatePort {
    /// Pure construction. The original caller retains this object BEFORE load.
    /// `project` must be from the native service mapping, never a protocol DTO.
    pub(crate) fn new(store: Arc<PrivateStateDirectory>, project: ProjectBinding, authority: Value) -> Result<Self> {
        let authority: Authority = decode(authority)?;
        need(authority.valid() && project.inode != 0 && Id::parse(project.project_id.as_str()).is_ok())?;
        Ok(Self { store, project, authority, snapshot: None, state: None, bound: None,
            attempted: None, failure: None, poisoned: false, remote_writes: 0, bounded: false })
    }
    /// Pure rematch only. Fresh native service/root/Document checks belong to
    /// the original caller; this does NOT check the filesystem or claim a lease.
    pub(crate) fn matches_native_binding(&self, store: &Arc<PrivateStateDirectory>, project: &ProjectBinding) -> bool {
        Arc::ptr_eq(&self.store, store) && &self.project == project
    }
    pub(crate) fn failure(&self) -> Option<StateError> { self.failure.or_else(|| self.poisoned.then(unknown)) }
    fn usable(&self) -> Result<()> { if self.poisoned { Err(self.failure().unwrap_or_else(unknown)) } else { Ok(()) } }
    fn state(&self) -> Result<&State> {
        self.usable()?; self.state.as_ref().ok_or_else(|| Error::Unavailable.into())
    }
    pub(crate) fn snapshot(&self) -> Result<&Snapshot> {
        self.usable()?; self.snapshot.as_ref().ok_or_else(|| Error::Unavailable.into())
    }
    pub(crate) fn load(&mut self) -> Result<()> { self.load_bounded(STATE_LIMIT) }
    // Private child-only enrollment subset; ordinary/recovery callers retain
    // the exact 1MiB / 50k-node behavior. There is no caller-selected decoder.
    fn load_bounded(&mut self, limit: usize) -> Result<()> {
        self.usable()?; need(self.snapshot.is_none() && [256 * 1024, STATE_LIMIT].contains(&limit))?;
        self.bounded = limit != STATE_LIMIT;
        self.poisoned = true;
        let loaded = self.store.read(Namespace::VersionAllocations);
        match loaded {
            Err(error) => { self.failure = Some(error); return Err(error); }
            Ok(snapshot) => self.snapshot = Some(snapshot),
        }
        let result = (|| {
            let snapshot = self.snapshot.as_ref().ok_or_else(unknown)?;
            // Keep the FULL original before either byte or complexity refusal.
            if snapshot.bytes.len() > limit { return Err(Error::Unavailable.into()); }
            let state = if limit == STATE_LIMIT { State::parse(snapshot)? }
                else { State::parse_original(snapshot, true)? };
            if state.enrollments.iter().any(|e| e.local_project_id == self.project.project_id.as_str()) {
                need(state.enrolled(self.project.project_id.as_str(), &self.authority.project_id)?.authority == self.authority)?;
            }
            let bound = state.candidate(self.project.project_id.as_str()).map(|c| c.request.clone());
            self.state = Some(state); self.bound = bound; Ok(())
        })();
        if let Err(error) = result { self.failure = Some(error); return Err(error); }
        self.poisoned = false; Ok(())
    }
    fn store(&mut self, state: State) -> Result<WriteAck> {
        self.usable()?;
        let expected = self.snapshot()?.revision;
        let next_revision = Revision(expected.0.checked_add(1).ok_or_else(|| StateError::from(Error::RecoveryRequired))?);
        let bytes = state.bytes()?;
        if self.bounded {
            strict_version_enrollment_state_json(&bytes).map_err(|error|
                StateError::from(if error.code == "version_enrollment_state_limit" { Error::Unavailable } else { Error::RecoveryRequired }))?;
        }
        // Retain attempted input and latch BEFORE the sole native call. A panic
        // or cancellation cannot expose a second usable writer. The original
        // native Store retains its own intent fence and exact error facts too.
        self.attempted = Some(Attempt { state, bytes, returned: None }); self.poisoned = true;
        let result = self.store.replace(Namespace::VersionAllocations, expected,
            &self.attempted.as_ref().ok_or_else(unknown)?.bytes);
        let snapshot = match result {
            Err(error) => { self.failure = Some(error); return Err(error); }
            Ok(snapshot) => snapshot,
        };
        self.attempted.as_mut().ok_or_else(unknown)?.returned = Some(snapshot);
        let attempt = self.attempted.as_ref().ok_or_else(unknown)?;
        let returned = attempt.returned.as_ref().ok_or_else(unknown)?;
        if returned.revision != next_revision || returned.bytes != attempt.bytes {
            let error = unknown(); self.failure = Some(error); return Err(error);
        }
        let ack = WriteAck { revision: returned.revision, payload_sha256: format!("{:x}", Sha256::digest(&returned.bytes)) };
        let mut attempt = self.attempted.take().ok_or_else(unknown)?;
        self.bound = attempt.state.candidate(self.project.project_id.as_str()).map(|c| c.request.clone());
        self.state = Some(attempt.state); self.snapshot = attempt.returned.take();
        self.poisoned = false; Ok(ack)
    }
    /// Separate explicit native-verified genesis enrollment. It never overwrites
    /// an existing authority checkpoint/pending row or rebinds a local project.
    pub(crate) fn enroll(&mut self, genesis_checkpoint: Value) -> Result<WriteAck> {
        let checkpoint: Checkpoint = decode(genesis_checkpoint)?;
        need(checkpoint.valid() && checkpoint.sequence == 0 && checkpoint.head_sha256 == self.authority.genesis_sha256)?;
        let mut next = self.state()?.clone();
        need(!next.enrollments.iter().any(|r| r.local_project_id == self.project.project_id.as_str()))?;
        if let Some(existing) = next.authorities.iter().find(|r| r.authority.project_id == self.authority.project_id) {
            need(existing.authority == self.authority)?;
        } else {
            next.authorities.push(AuthorityState { authority: self.authority.clone(), checkpoint, pending: None });
            next.authorities.sort_by(|a, b| a.authority.project_id.cmp(&b.authority.project_id));
        }
        next.enrollments.push(Enrollment { local_project_id: self.project.project_id.as_str().to_owned(),
            authority_project_id: self.authority.project_id.clone() });
        next.enrollments.sort_by(|a, b| a.local_project_id.cmp(&b.local_project_id)); self.store(next)
    }
    fn enrolled(&self) -> Result<&AuthorityState> {
        let row = self.state()?.enrolled(self.project.project_id.as_str(), &self.authority.project_id)?;
        need(row.authority == self.authority)?; Ok(row)
    }
    pub(crate) fn admit_request(&self, request: &Value) -> Result<()> {
        self.enrolled()?;
        let current = self.state()?.candidate(self.project.project_id.as_str()).ok_or_else(|| StateError::from(Error::Conflict))?;
        need(self.bound.as_ref() == Some(&current.request) && &current.request.0 == request)
    }
    pub(crate) fn selected_request(&self) -> Result<&Value> {
        let request = self.bound.as_ref().ok_or_else(|| StateError::from(Error::Unavailable))?;
        self.admit_request(&request.0)?; Ok(&request.0)
    }
    /// Explicit new-candidate action ONLY. `template` has no candidateId; a
    /// refresh/retry uses selected_request instead. OS randomness is consumed
    /// once, then the FULL request is retained through the actual durable CAS.
    pub(crate) fn select_new(&mut self, mut template: Value, previous_request: Option<&Value>) -> Result<WriteAck> {
        need(closed(&template, if matches!(template["policy"]["schemaVersion"].as_u64(),Some(2|3|4)) {
            &["projectId", "identityRevision", "source", "baseVersion", "platforms", "policy", "storeContextRevision"]
        } else { &["projectId", "identityRevision", "source", "baseVersion", "platforms", "policy"] }))?;
        template["candidateId"] = json!("00000000-0000-4000-8000-000000000000");
        let mut request: Request = decode(template)?;
        need(request.valid() && request.project() == self.authority.project_id && self.enrolled()?.pending.is_none())?;
        let current = self.state()?.candidate(self.project.project_id.as_str());
        need(current.map(|c| &c.request.0) == previous_request)?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| StateError::from(Error::Unavailable))?;
        random[6] = (random[6] & 0x0f) | 0x40; random[8] = (random[8] & 0x3f) | 0x80;
        let raw = crate::service_protocol::hex(&random);
        request.0["candidateId"] = json!(format!("{}-{}-{}-{}-{}", &raw[..8], &raw[8..12], &raw[12..16], &raw[16..20], &raw[20..]));
        need(current.is_none_or(|c| c.request.candidate() != request.candidate()))?;
        self.select(request)
    }
    /// Legacy pending DATA remains unowned until this separate explicit action
    /// adopts the EXACT original request for read-only reconciliation. No UUID
    /// is minted, and another local selection cannot claim the original sender.
    pub(crate) fn adopt_legacy_pending(&mut self, request: Value) -> Result<WriteAck> {
        let request: Request = decode(request)?;
        need(self.state()?.candidate(self.project.project_id.as_str()).is_none()
            && self.enrolled()?.pending.as_ref().is_some_and(|p| p.reservation.request == request))?;
        self.select(request)
    }
    fn select(&mut self, request: Request) -> Result<WriteAck> {
        let mut next = self.state()?.clone();
        next.candidates.retain(|c| c.local_project_id != self.project.project_id.as_str());
        next.candidates.push(Candidate { local_project_id: self.project.project_id.as_str().to_owned(), request, reservation: None });
        next.candidates.sort_by(|a, b| a.local_project_id.cmp(&b.local_project_id)); self.store(next)
    }
    /// The original worker schedule establishes Git/HTTP facts. This port only
    /// permits the matching journal transition. A positive return acknowledges
    /// local storage, NOT worker/process finality, currentness or a PUT grant.
    pub(crate) fn apply(&mut self, expected: Revision, request: &Value, change: Transition) -> Result<WriteAck> {
        self.admit_request(request)?;
        need(self.snapshot()?.revision == expected && self.remote_writes < REMOTE_WRITES)?;
        let mut next = self.state()?.clone();
        let row = next.authorities.iter_mut().find(|a| a.authority == self.authority).ok_or_else(|| StateError::from(Error::Conflict))?;
        let candidate = next.candidates.iter_mut().find(|c| c.local_project_id == self.project.project_id.as_str())
            .ok_or_else(|| StateError::from(Error::Conflict))?;
        match change {
            Transition::Checkpoint(value) => {
                let checkpoint: Checkpoint = decode(value)?;
                need(checkpoint.valid() && checkpoint.sequence >= row.checkpoint.sequence && checkpoint != row.checkpoint
                    && (checkpoint.sequence != row.checkpoint.sequence || checkpoint.head_sha256 == row.checkpoint.head_sha256)
                    && checkpoint.commit != row.checkpoint.commit)?;
                row.checkpoint = checkpoint;
            }
            Transition::Pending(value) => {
                let pending: Pending = decode(value)?; pending.valid()?;
                need(row.pending.is_none() && candidate.reservation.is_none() && pending.authority == row.authority
                    && pending.checkpoint == row.checkpoint && pending.reservation.request == candidate.request)?;
                row.pending = Some(pending);
            }
            Transition::Rejected(value) => {
                let pending: Pending = decode(value)?; pending.valid()?;
                need(row.pending.as_ref() == Some(&pending) && pending.reservation.request == candidate.request)?;
                row.pending = None;
            }
            Transition::Resolved { pending, checkpoint } => {
                let pending: Pending = decode(pending)?; pending.valid()?;
                let checkpoint: Checkpoint = decode(checkpoint)?;
                need(row.pending.as_ref() == Some(&pending) && row.checkpoint == checkpoint
                    && pending.reservation.request == candidate.request && pending.reservation.at_or_before(&checkpoint))?;
                candidate.reservation = Some(pending.reservation); row.pending = None;
            }
            Transition::Reused { reservation, checkpoint } => {
                let reservation: Reservation = decode(reservation)?; reservation.valid()?;
                let checkpoint: Checkpoint = decode(checkpoint)?;
                need(row.pending.is_none() && checkpoint == row.checkpoint && reservation.request == candidate.request
                    && reservation.at_or_before(&checkpoint) && candidate.reservation.as_ref().is_none_or(|r| r == &reservation))?;
                candidate.reservation = Some(reservation);
                // Even identical retained bytes MUST reach the actual CAS. A
                // fresh ACK, not a remembered checkpoint, closes the reuse path.
            }
        }
        self.remote_writes += 1; self.store(next)
    }
}

#[cfg(test)]
mod tests {
    // Actual private-state IO in disposable fixtures, and pure codec checks.
    // No Document admission, network, process, Store, auth or native GO proof.
    use super::*;
    use crate::application_state_store::Fixture;

    fn authority() -> Value {
        json!({"projectId":"11111111-1111-4111-8111-111111111111","repository":"fixture/repository",
            "repositoryId":"27","ledgerId":"33333333-3333-4333-8333-333333333333",
            "genesisSha256":"a".repeat(64),"protectedBranch":true})
    }
    fn checkpoint() -> Value { json!({"sequence":0,"headSha256":"a".repeat(64),"commit":"c".repeat(40)}) }
    pub(super) fn request() -> Value {
        json!({"projectId":"11111111-1111-4111-8111-111111111111",
            "candidateId":"22222222-2222-4222-8222-222222222222","identityRevision":"b".repeat(64),
            "source":{"commit":"d".repeat(40),"tree":"e".repeat(40),"ref":"refs/heads/main",
                "configurationSha256":"f".repeat(64),"versionSha256":"c".repeat(64)},
            "baseVersion":{"name":"1.2.3","build":40},"platforms":["android"],
            "policy":{"schemaVersion":1,"mode":"automatic","rules":[{"ref":"refs/heads/main","increment":"build"}],
                "buildCeiling":2100000000u64,"storeMaxAgeSeconds":900}})
    }
    fn template() -> Value {
        let mut value = request(); value.as_object_mut().unwrap().remove("candidateId"); value
    }
    fn project(local: &str) -> ProjectBinding {
        ProjectBinding { project_id: Id::parse(local).unwrap(), canonical_root: "/synthetic/project".to_owned(), device: 1, inode: 2 }
    }
    pub(super) fn prepared(fixture: &Fixture) -> (Arc<PrivateStateDirectory>, VersionAllocationStatePort) {
        let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
        let mut port = VersionAllocationStatePort::new(store.clone(), project(&"a".repeat(32)), authority()).unwrap();
        port.load().unwrap(); port.enroll(checkpoint()).unwrap(); port.select_new(template(), None).unwrap();
        (store, port)
    }
    pub(super) fn pending(request: &Value) -> Value {
        let mut reservation = json!({"sequence":1,"previousSha256":"a".repeat(64),"request":request,
            "requestSha256":hash(b"mrk:allocation-request:1\0", request).unwrap(),
            "version":{"name":"1.2.3","build":41},"storeObservations":[{
                "platform":"android","identityRevision":"b".repeat(64),"revision":"f".repeat(64),
                "observedAt":2000,"maxBuild":40,"marketingVersion":"1.2.3","complete":true,
                "formatSupported":true,"scope":"application-all-builds"}],"allocatedAt":2000});
        reservation["sha256"] = json!(hash(b"mrk:allocation-reservation:1\0", &reservation).unwrap());
        json!({"schemaVersion":1,"protocol":ALLOCATION_PROTOCOL,"authority":authority(),
            "checkpoint":checkpoint(),"expectedBlob":"d".repeat(40),"reservation":reservation})
    }
    pub(super) fn advanced(pending: &Value) -> Value {
        json!({"sequence":1,"headSha256":pending["reservation"]["sha256"],"commit":"e".repeat(40)})
    }
    fn persisted(value: &Value) -> Vec<u8> {
        let mut bytes = canonical(value, STATE_LIMIT - 1).unwrap(); bytes.push(b'\n'); bytes
    }

    #[test]
    fn load_never_initializes_enrolls_or_mutates_other_namespaces() {
        let f = Fixture::new(); let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let mut port = VersionAllocationStatePort::new(store.clone(), project(&"a".repeat(32)), authority()).unwrap();
        assert!(port.snapshot().is_err()); port.load().unwrap();
        assert_eq!(port.snapshot().unwrap().revision, Revision(0));
        assert!(port.snapshot().unwrap().bytes.is_empty()); assert!(port.selected_request().is_err());
        for namespace in [Namespace::Projects, Namespace::CredentialReferences, Namespace::VersionAllocations] {
            let snapshot = store.read(namespace).unwrap(); assert_eq!(snapshot.revision, Revision(0)); assert!(snapshot.bytes.is_empty());
        }
        let empty_nonzero = Snapshot { revision: Revision(1), bytes: Vec::new() };
        assert!(State::parse(&empty_nonzero).is_err()); assert!(port.load().is_err()); store.close().unwrap();
    }
    #[test]
    fn explicit_new_id_is_durable_and_resume_never_remints_or_rebinds() {
        let f = Fixture::new(); let (store, mut port) = prepared(&f);
        let request = port.selected_request().unwrap().clone();
        assert!(uuid(request["candidateId"].as_str().unwrap()));
        assert_eq!(port.snapshot().unwrap().revision, Revision(2));
        let mut resumed = VersionAllocationStatePort::new(store.clone(), port.project.clone(), authority()).unwrap();
        resumed.load().unwrap(); assert_eq!(resumed.selected_request().unwrap(), &request);
        assert_eq!(resumed.snapshot().unwrap().revision, Revision(2));
        let mut changed = request.clone(); changed["source"]["tree"] = json!("a".repeat(40));
        assert!(resumed.admit_request(&changed).is_err());
        assert!(port.select_new(template(), None).is_err());
        assert!(port.select_new(template(), Some(&changed)).is_err());
        assert!(resumed.matches_native_binding(&store, &port.project));
        let mut replaced = port.project.clone(); replaced.inode += 1;
        assert!(!resumed.matches_native_binding(&store, &replaced));
        port.select_new(template(), Some(&request)).unwrap();
        assert_ne!(port.selected_request().unwrap()["candidateId"], request["candidateId"]);
        assert_eq!(store.read(Namespace::VersionAllocations).unwrap().revision, Revision(3)); store.close().unwrap();
    }
    #[test]
    fn real_pending_and_resolution_acks_retain_reservation_then_identical_reuse_cas() {
        let f = Fixture::new(); let (store, mut port) = prepared(&f);
        let request = port.selected_request().unwrap().clone(); let pending = pending(&request); let checkpoint = advanced(&pending);
        let ack = port.apply(Revision(2), &request, Transition::Pending(pending.clone())).unwrap();
        assert_eq!(ack.revision, Revision(3));
        let persisted = store.read(Namespace::VersionAllocations).unwrap();
        assert_eq!(ack.payload_sha256, format!("{:x}", Sha256::digest(&persisted.bytes)));
        let state = State::parse(&persisted).unwrap(); assert!(state.authorities[0].pending.is_some());
        assert!(state.candidates[0].reservation.is_none());
        port.apply(Revision(3), &request, Transition::Checkpoint(checkpoint.clone())).unwrap();
        port.apply(Revision(4), &request, Transition::Resolved { pending: pending.clone(), checkpoint: checkpoint.clone() }).unwrap();
        let reserved = port.snapshot().unwrap().bytes.clone();
        let mut resumed = VersionAllocationStatePort::new(store.clone(), port.project.clone(), authority()).unwrap();
        resumed.load().unwrap();
        let state = resumed.state().unwrap(); assert!(state.authorities[0].pending.is_none());
        assert!(state.candidates[0].reservation.as_ref().is_some_and(|r| r.request.0 == request));
        let ack = resumed.apply(Revision(5), &request, Transition::Reused { reservation: pending["reservation"].clone(), checkpoint }).unwrap();
        assert_eq!(ack.revision, Revision(6)); assert_eq!(resumed.snapshot().unwrap().bytes, reserved);
        assert_eq!(store.read(Namespace::Projects).unwrap().revision, Revision(0)); store.close().unwrap();
    }
    #[test]
    fn known_stale_native_cas_keeps_failed_attempt_and_blocks_second_write_or_reload() {
        let f = Fixture::new(); let (store, mut first) = prepared(&f);
        let request = first.selected_request().unwrap().clone(); let pending = pending(&request);
        let mut stale = VersionAllocationStatePort::new(store.clone(), first.project.clone(), authority()).unwrap();
        stale.load().unwrap();
        first.apply(Revision(2), &request, Transition::Pending(pending.clone())).unwrap();
        let error = stale.apply(Revision(2), &request, Transition::Pending(pending.clone())).err().unwrap();
        assert_eq!(error.code, Error::Conflict); assert_eq!(error.effect, Effect::None);
        assert_eq!(error.durability, Durability::NotApplicable); assert_eq!(error.cleanup, Cleanup::Known);
        assert_eq!(stale.failure(), Some(error)); assert!(stale.attempted.is_some());
        assert!(stale.apply(Revision(2), &request, Transition::Pending(pending)).is_err());
        assert!(stale.load().is_err()); assert_eq!(store.read(Namespace::VersionAllocations).unwrap().revision, Revision(3));
        store.close().unwrap();
    }
    #[test]
    fn remote_existing_reuse_still_requires_real_cas_even_if_payload_is_identical() {
        let f = Fixture::new(); let (store, mut port) = prepared(&f);
        let request = port.selected_request().unwrap().clone(); let pending = pending(&request); let checkpoint = advanced(&pending);
        port.apply(Revision(2), &request, Transition::Checkpoint(checkpoint.clone())).unwrap();
        port.apply(Revision(3), &request, Transition::Reused { reservation: pending["reservation"].clone(), checkpoint: checkpoint.clone() }).unwrap();
        let bytes = port.snapshot().unwrap().bytes.clone();
        // The actual state owner permits a same-byte cooperating replacement.
        store.replace(Namespace::VersionAllocations, Revision(4), &bytes).unwrap();
        let error = port.apply(Revision(4), &request, Transition::Reused { reservation: pending["reservation"].clone(), checkpoint }).err().unwrap();
        assert_eq!(error.code, Error::Conflict); assert_eq!(port.failure(), Some(error));
        assert_eq!(store.read(Namespace::VersionAllocations).unwrap().revision, Revision(5)); store.close().unwrap();
    }
    #[test]
    fn legacy_pending_has_no_owner_until_explicit_exact_reconcile_adoption() {
        let f = Fixture::new(); let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let request = request(); let pending = pending(&request);
        let legacy = json!({"schemaVersion":2,"protocol":PROTOCOL,
            "authorities":[{"authority":authority(),"checkpoint":checkpoint(),"pending":pending}],
            "enrollments":[{"localProjectId":"a".repeat(32),"authorityProjectId":authority()["projectId"]}]});
        let original = persisted(&legacy); store.replace(Namespace::VersionAllocations, Revision(0), &original).unwrap();
        let mut port = VersionAllocationStatePort::new(store.clone(), project(&"a".repeat(32)), authority()).unwrap(); port.load().unwrap();
        assert_eq!(port.snapshot().unwrap().bytes, original); assert!(port.selected_request().is_err());
        assert!(port.select_new(template(), None).is_err());
        let mut wrong = request.clone(); wrong["identityRevision"] = json!("c".repeat(64));
        assert!(port.adopt_legacy_pending(wrong).is_err());
        port.adopt_legacy_pending(request.clone()).unwrap();
        assert_eq!(port.selected_request().unwrap(), &request);
        assert_eq!(serde_json::to_value(&port.state().unwrap().authorities[0].pending).unwrap(), pending);
        let mut second = VersionAllocationStatePort::new(store.clone(), project(&"b".repeat(32)), authority()).unwrap();
        second.load().unwrap(); second.enroll(checkpoint()).unwrap();
        let before = second.snapshot().unwrap().bytes.clone();
        assert!(second.adopt_legacy_pending(request).is_err());
        assert_eq!(store.read(Namespace::VersionAllocations).unwrap().bytes, before); store.close().unwrap();
    }
    #[test]
    fn closed_canonical_legacy_and_candidate_bindings_reject_lossy_or_foreign_state() {
        let authority_state = json!({"authority":authority(),"checkpoint":checkpoint(),"pending":null});
        for version in [1, 2, 3] {
            let mut row = json!({"schemaVersion":version,"protocol":PROTOCOL,"authorities":[authority_state.clone()]});
            if version >= 2 { row["enrollments"] = json!([]); }
            if version == 3 { row["candidates"] = json!([]); }
            let original = persisted(&row);
            let parsed = State::parse(&Snapshot { revision: Revision(7), bytes: original.clone() }).unwrap();
            assert!(parsed.candidates.is_empty() && parsed.enrollments.is_empty());
            row["authorities"][0].as_object_mut().unwrap().remove("pending");
            assert!(State::parse(&Snapshot { revision: Revision(7), bytes: persisted(&row) }).is_err());
            let duplicate = String::from_utf8(original).unwrap().replacen("\"schemaVersion\":", "\"schemaVersion\":3,\"schemaVersion\":", 1);
            assert!(State::parse(&Snapshot { revision: Revision(7), bytes: duplicate.into_bytes() }).is_err());
        }
        assert!(shared_id("11111111-1111-4111-8111-111111111111"));
        assert!(shared_id("11111111111141118111111111111111"));
        assert_ne!("11111111-1111-4111-8111-111111111111", "11111111111141118111111111111111");
        for id in ["0".repeat(32), "A".repeat(32), "11111111-1111-5111-8111-111111111111".to_owned()] { assert!(!shared_id(&id)); }
        let mut reservation = pending(&request())["reservation"].clone();
        reservation["request"]["source"]["tree"] = json!("f".repeat(40));
        assert!(decode::<Reservation>(reservation).unwrap().valid().is_err());
    }
    #[test]
    fn python_canonical_full_request_hash_and_unicode_encoding_are_preserved() {
        // Python AllocationRequest.parse(request()).sha256, not a source hash.
        assert_eq!(hash(b"mrk:allocation-request:1\0", &request()).unwrap(),
            "9398c88cb8def785ac8a9d5ef5acaaeb0c462845cd5224889a0f5fbe1243a7a1");
        assert_eq!(canonical(&json!({"z":"\u{1f642}\u{7f}","a":"\u{e9}"}), 100).unwrap(),
            b"{\"a\":\"\\u00e9\",\"z\":\"\\ud83d\\ude42\\u007f\"}");
        assert!(canonical(&json!("\u{1f642}"), 5).is_err());
        assert!(!Request({ let mut r = request(); r["policy"]["mode"] = json!("manual"); r }).valid());
    }
}

#[path="version_counter_setup_state_native.rs"]
pub(crate) mod counter_setup;
