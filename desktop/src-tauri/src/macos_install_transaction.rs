//! Closed maintenance transaction DATA, not an Installer, native observer or
//! action capability. Supplying a matching label cannot establish a package's
//! authenticity, original custody, an actual join, or permission to write.
//! State names an expected capsule ID; the later capsule binds actual state
//! bytes. Neither record claims its own writer's future close or process exit.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::{macos_install_maintenance::{ActionData, ReleaseData, ReleaseSetData, PREDECESSOR_LIMIT},
    macos_install_record::{DirectoryIdentity, FILE_LIMIT, PAYLOAD_LIMIT}, protocol::strict_json};

pub const STATE_LIMIT: usize = 16 * 1024;
pub const INTENT_LIMIT: usize = 16 * 1024;
pub const CAPSULE_LIMIT: usize = 64 * 1024;
pub const REQUEST_EXPORT_LIMIT: usize = 64 * 1024;
pub const PRODUCER_CONTROL_LIMIT: usize = crate::macos_install_producer::DESCRIPTOR_LIMIT
    + crate::macos_install_producer::SIGNATURE_LIMIT;
pub const INVOCATION_LIMIT: usize = 64;
pub const STATE_NAME: &str = "installation-v2.json";
/// A request ID correlates one exact original Installer invocation with a
/// unique pending export. It does not authenticate a package or grant writes.
pub fn export_name_data(request_id: &str) -> Result<String> {
    require(hex(request_id, 32), TransactionDataError::Binding)?;
    Ok(format!("MobileReleaseKit-InstallerResult-v2-{request_id}.json"))
}
/// The native caller must first prove this basename belongs to its actual
/// completed package. No path lookup, newest-file selection, or authority is
/// inferred here. Finder's fixed name requests a fresh random correlation ID.
pub fn request_from_package_name_data(name: &str) -> Result<Option<String>> {
    if name == "Install.pkg" { return Ok(None); }
    let request = name.strip_prefix("MobileReleaseKit-Request-")
        .and_then(|value| value.strip_suffix(".pkg")).ok_or(TransactionDataError::Binding)?;
    require(hex(request, 32), TransactionDataError::Binding)?;
    Ok(Some(request.into()))
}
const INTENT_KIND: &str = "mrk-macos-maintenance-intent-v2";
const STATE_KIND: &str = "mrk-macos-maintenance-state-v2";
const CAPSULE_KIND: &str = "mrk-macos-maintenance-capsule-v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionDataError { Shape, Limit, Binding, ReusedIdentity, Transition }
type Result<T> = std::result::Result<T, TransactionDataError>;
fn require(ok: bool, why: TransactionDataError) -> Result<()> { if ok { Ok(()) } else { Err(why) } }
fn hex(value: &str, width: usize) -> bool {
    value.len() == width && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}
fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn object(value: &serde_json::Value) -> Result<()> { require(value.is_object(), TransactionDataError::Shape) }
fn field<'a>(value: &'a serde_json::Value, name: &str) -> Result<&'a serde_json::Value> {
    value.get(name).ok_or(TransactionDataError::Shape)
}
fn record_field(value: &serde_json::Value, name: &str, nullable: bool) -> Result<()> {
    let nested = field(value, name)?;
    if nullable && nested.is_null() { Ok(()) } else { object(nested) }
}
fn records<'a>(value: &'a serde_json::Value, name: &str, limit: usize) -> Result<&'a [serde_json::Value]> {
    let items = field(value, name)?.as_array().ok_or(TransactionDataError::Shape)?;
    require(items.len() <= limit, TransactionDataError::Limit)?;
    for item in items { object(item)?; }
    Ok(items)
}
fn raw(bytes: &[u8], limit: usize) -> Result<serde_json::Value> {
    require(!bytes.is_empty() && bytes.len() <= limit, TransactionDataError::Limit)?;
    let value = strict_json(bytes).map_err(|_| TransactionDataError::Shape)?;
    object(&value)?; Ok(value)
}
fn decode<T: DeserializeOwned>(value: serde_json::Value) -> Result<T> {
    serde_json::from_value(value).map_err(|_| TransactionDataError::Shape)
}
fn encode<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| TransactionDataError::Shape)?;
    bytes.push(b'\n');
    require(bytes.len() <= limit, TransactionDataError::Limit)?;
    Ok(bytes)
}
/// Fixed single-component DATA names. The native caller still owns EXCL,
/// no-follow lookup, original identity and all publication/close observations.
pub fn intent_name_data(invocation: &str) -> Result<String> { evidence_name(invocation, "intent") }
pub fn archived_state_name_data(invocation: &str) -> Result<String> { evidence_name(invocation, "state") }
pub fn capsule_name_data(invocation: &str) -> Result<String> { evidence_name(invocation, "capsule") }
fn evidence_name(invocation: &str, role: &str) -> Result<String> {
    require(hex(invocation, 32), TransactionDataError::Binding)?;
    Ok(format!(".maintenance-{invocation}.{role}.json"))
}
pub fn retained_app_name_data(invocation: &str) -> Result<String> {
    require(hex(invocation, 32), TransactionDataError::Binding)?;
    Ok(format!(".retained-app-{invocation}"))
}
fn header(schema: u32, kind: &str, expected_kind: &str, target: &str, invocation: &str, request_id: &str,
    expected: &ReleaseSetData) -> Result<()> {
    require(schema == 2 && kind == expected_kind && target == expected.target_data().target()
        && hex(invocation, 32) && hex(request_id, 32), TransactionDataError::Binding)
}
fn pair(expected: &ReleaseSetData, action: ActionData, old: Option<&ReleaseData>, new: &ReleaseData, current: bool) -> Result<()> {
    require(expected.contains_data(new) && (!current || new == expected.current_data())
        && old.is_none_or(|r| expected.contains_data(r)), TransactionDataError::Binding)?;
    require(match action {
        ActionData::FreshInstall => old.is_none(),
        ActionData::SamePackageNoop | ActionData::RestoreFixedApp => old == Some(new),
        ActionData::Update => old.is_some_and(|r| new.is_strictly_newer_data(r)),
        ActionData::Uninstall => false,
    }, TransactionDataError::Binding)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StateLink { invocation: String, sha256: String }
impl StateLink { fn valid(&self) -> bool { hex(&self.invocation, 32) && hex(&self.sha256, 64) } }

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IntentWire {
    schema_version: u32, kind: String, target: String, invocation: String, request_id: String, action: ActionData,
    previous: Option<ReleaseData>, next: ReleaseData, previous_state: Option<StateLink>,
}
/// Validated comparison input only; no Deserialize bypass or mutation methods.
#[derive(Debug)]
pub struct IntentData { wire: IntentWire, body_sha256: String }
impl IntentData {
    pub fn parse_data(bytes: &[u8], expected: &ReleaseSetData) -> Result<Self> {
        Self::parse_selected_data(bytes, expected, true)
    }
    /// An explicitly linked historical intent is compared to the same producer
    /// set. Its old next tuple is not substituted for the current selection.
    pub fn parse_recorded_data(bytes: &[u8], expected: &ReleaseSetData) -> Result<Self> {
        Self::parse_selected_data(bytes, expected, false)
    }
    fn parse_selected_data(bytes: &[u8], expected: &ReleaseSetData, current: bool) -> Result<Self> {
        let value = raw(bytes, INTENT_LIMIT)?;
        record_field(&value, "previous", true)?; record_field(&value, "next", false)?;
        record_field(&value, "previousState", true)?;
        let wire: IntentWire = decode(value)?;
        header(wire.schema_version, &wire.kind, INTENT_KIND, &wire.target, &wire.invocation, &wire.request_id, expected)?;
        pair(expected, wire.action, wire.previous.as_ref(), &wire.next, current)?;
        require(match &wire.previous_state {
            None => wire.action == ActionData::FreshInstall,
            Some(link) => link.valid() && link.invocation != wire.invocation && wire.previous.is_some(),
        }, TransactionDataError::Binding)?;
        Ok(Self { wire, body_sha256: digest(bytes) })
    }
    pub fn invocation_data(&self) -> &str { &self.wire.invocation }
    pub fn request_id_data(&self) -> &str { &self.wire.request_id }
    pub fn digest_data(&self) -> &str { &self.body_sha256 }
    pub fn action_data(&self) -> ActionData { self.wire.action }
    pub fn next_data(&self) -> &ReleaseData { &self.wire.next }
    pub fn previous_data(&self) -> Option<&ReleaseData> { self.wire.previous.as_ref() }
    pub fn previous_state_data(&self) -> Option<(&str, &str)> {
        self.wire.previous_state.as_ref().map(|link| (link.invocation.as_str(), link.sha256.as_str()))
    }
    /// Construct comparison DATA only after the original observer selected the
    /// action. A previous successful WORKER capsule is necessary; no file is
    /// asked to attest its old outer Installer's future exit.
    pub fn encode_data(invocation: &str, request_id: &str, action: ActionData,
        previous: Option<(&StateData, &CapsuleData)>, expected: &ReleaseSetData) -> Result<Vec<u8>> {
        let wire = IntentWire { schema_version: 2, kind: INTENT_KIND.into(),
            target: expected.target_data().target().into(), invocation: invocation.into(), request_id: request_id.into(), action,
            previous: previous.map(|(state, _)| state.wire.current.release.clone()),
            next: expected.current_data().clone(), previous_state: previous.map(|(state, _)| StateLink {
                invocation: state.wire.invocation.clone(), sha256: state.body_sha256.clone() }) };
        let bytes = encode(&wire, INTENT_LIMIT)?;
        let parsed = Self::parse_data(&bytes, expected)?;
        require(previous_matches(&parsed, previous), TransactionDataError::Binding)?;
        Ok(bytes)
    }
}

/// Directory identity is DATA, not a live ACL/mount/xattr/name observation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AppIdentity {
    device: i64, inode: u64, mode: u32, uid: u32, gid: u32, flags: u32,
}
impl AppIdentity {
    fn valid(&self) -> bool { self.device > 0 && self.inode > 0 && self.mode == 0o040555
        && self.uid == 0 && self.gid == 0 && self.flags == 0 }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "location", rename_all = "kebab-case", deny_unknown_fields)]
enum AppSlot { Canonical { identity: AppIdentity }, Retained { invocation: String, identity: AppIdentity } }
impl AppSlot {
    fn identity(&self) -> &AppIdentity { match self { Self::Canonical { identity } | Self::Retained { identity, .. } => identity } }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Generation {
    release: ReleaseData, instance: String, release_directory: DirectoryIdentity, app: AppSlot,
}
fn generation_shape(value: &serde_json::Value) -> Result<()> {
    object(value)?; record_field(value, "release", false)?; record_field(value, "releaseDirectory", false)?;
    record_field(value, "app", false)?; record_field(field(value, "app")?, "identity", false)
}
impl Generation {
    fn valid(&self, expected: &ReleaseSetData) -> bool {
        expected.contains_data(&self.release) && hex(&self.instance, 32) && self.release_directory.valid()
            && self.app.identity().valid() && match &self.app {
                AppSlot::Canonical { .. } => true,
                AppSlot::Retained { invocation, .. } => hex(invocation, 32),
            }
    }
    fn same_runtime(&self, other: &Self) -> bool {
        self.release == other.release && self.instance == other.instance && self.release_directory == other.release_directory
    }
    fn same_objects(&self, other: &Self) -> bool { self.same_runtime(other) && self.app.identity() == other.app.identity() }
}
/// Observed identity DATA for the native writer/reader. Construction validates
/// shape, not a syscall, signature, ACL, mount, original name or permission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppIdentityData(AppIdentity);
impl AppIdentityData {
    pub fn from_original_fields_data(device: i64, inode: u64, mode: u32, uid: u32, gid: u32, flags: u32) -> Result<Self> {
        let value = AppIdentity { device, inode, mode, uid, gid, flags };
        require(value.valid(), TransactionDataError::Binding)?; Ok(Self(value))
    }
    pub fn fields_data(&self) -> (i64, u64, u32, u32, u32, u32) {
        (self.0.device, self.0.inode, self.0.mode, self.0.uid, self.0.gid, self.0.flags)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationData(Generation);
impl GenerationData {
    pub fn from_original_fields_data(expected: &ReleaseSetData, release: &ReleaseData, instance: &str,
        release_directory: DirectoryIdentity, app: AppIdentityData) -> Result<Self> {
        let value = Generation { release: release.clone(), instance: instance.into(), release_directory,
            app: AppSlot::Canonical { identity: app.0 } };
        require(value.valid(expected), TransactionDataError::Binding)?;
        require((value.release_directory.device, value.release_directory.inode)
            != (value.app.identity().device, value.app.identity().inode), TransactionDataError::ReusedIdentity)?;
        Ok(Self(value))
    }
    pub fn release_data(&self) -> &ReleaseData { &self.0.release }
    pub fn instance_data(&self) -> &str { &self.0.instance }
    pub fn release_directory_data(&self) -> DirectoryIdentity { self.0.release_directory }
    pub fn app_identity_data(&self) -> AppIdentityData { AppIdentityData(self.0.app.identity().clone()) }
    pub fn retained_invocation_data(&self) -> Option<&str> {
        match &self.0.app { AppSlot::Canonical { .. } => None, AppSlot::Retained { invocation, .. } => Some(invocation) }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum StatePhase { MutationRecorded, InverseRecorded, PartialRecorded }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvidenceRef { invocation: String, intent_sha256: String, state_sha256: String, capsule_sha256: String }
#[derive(Clone, Copy)]
pub struct EvidenceLinkData<'a> {
    pub invocation: &'a str, pub intent_sha256: &'a str, pub state_sha256: &'a str, pub capsule_sha256: &'a str,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Residue {
    invocation: String, release: ReleaseData, staging_present: bool, runtime_present: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StateWire {
    schema_version: u32, kind: String, target: String, invocation: String, request_id: String, capsule_invocation: String,
    intended_action: ActionData, phase: StatePhase, current: Generation, retained: Vec<Generation>,
    previous_evidence: Vec<EvidenceRef>, residue: Option<Residue>,
}
#[derive(Debug)]
pub struct StateData { wire: StateWire, body_sha256: String }
impl StateData {
    pub fn parse_data(bytes: &[u8], expected: &ReleaseSetData) -> Result<Self> {
        let value = raw(bytes, STATE_LIMIT)?;
        generation_shape(field(&value, "current")?)?;
        for item in records(&value, "retained", PREDECESSOR_LIMIT)? { generation_shape(item)?; }
        records(&value, "previousEvidence", INVOCATION_LIMIT - 1)?;
        record_field(&value, "residue", true)?;
        if !field(&value, "residue")?.is_null() { record_field(field(&value, "residue")?, "release", false)?; }
        let wire: StateWire = decode(value)?;
        header(wire.schema_version, &wire.kind, STATE_KIND, &wire.target, &wire.invocation, &wire.request_id, expected)?;
        require(wire.capsule_invocation == wire.invocation && wire.intended_action != ActionData::Uninstall
            && wire.current.valid(expected) && matches!(wire.current.app, AppSlot::Canonical { .. }), TransactionDataError::Binding)?;
        let mut generations = vec![&wire.current];
        let mut identities = BTreeSet::new();
        for identity in [(wire.current.release_directory.device, wire.current.release_directory.inode),
            (wire.current.app.identity().device, wire.current.app.identity().inode)] {
            require(identities.insert(identity), TransactionDataError::ReusedIdentity)?;
        }
        let mut names = BTreeSet::new();
        for item in &wire.retained {
            require(item.valid(expected) && match &item.app {
                AppSlot::Retained { invocation, .. } => names.insert(invocation.as_str()), _ => false,
            }, TransactionDataError::Binding)?;
            require(!generations.iter().any(|old| old.release == item.release || old.instance == item.instance
                || old.release_directory == item.release_directory || old.app.identity() == item.app.identity()),
                TransactionDataError::ReusedIdentity)?;
            for identity in [(item.release_directory.device, item.release_directory.inode),
                (item.app.identity().device, item.app.identity().inode)] {
                require(identities.insert(identity), TransactionDataError::ReusedIdentity)?;
            }
            generations.push(item);
        }
        let mut previous = "";
        for item in &wire.previous_evidence {
            require(hex(&item.invocation, 32) && item.invocation != wire.invocation && item.invocation.as_str() > previous
                && [&item.intent_sha256, &item.state_sha256, &item.capsule_sha256].iter().all(|x| hex(x, 64)), TransactionDataError::Binding)?;
            previous = &item.invocation;
        }
        // Every retained name is explicitly linked, never an unknown historical
        // directory adopted merely because it has the right spelling.
        for name in names {
            require(name == wire.invocation || wire.previous_evidence.iter().any(|item| item.invocation == name),
                TransactionDataError::Binding)?;
        }
        if let Some(residue) = &wire.residue {
            require(wire.phase != StatePhase::MutationRecorded && residue.invocation == wire.invocation
                && residue.release == *expected.current_data() && (residue.staging_present || residue.runtime_present), TransactionDataError::Binding)?;
        }
        require(wire.phase != StatePhase::InverseRecorded || wire.intended_action == ActionData::Update,
            TransactionDataError::Binding)?;
        Ok(Self { wire, body_sha256: digest(bytes) })
    }
    pub fn invocation_data(&self) -> &str { &self.wire.invocation }
    pub fn request_id_data(&self) -> &str { &self.wire.request_id }
    pub fn digest_data(&self) -> &str { &self.body_sha256 }
    pub fn action_data(&self) -> ActionData { self.wire.intended_action }
    pub fn current_data(&self) -> GenerationData { GenerationData(self.wire.current.clone()) }
    pub fn retained_data(&self) -> impl Iterator<Item = GenerationData> + '_ {
        self.wire.retained.iter().cloned().map(GenerationData)
    }
    pub fn evidence_data(&self) -> impl Iterator<Item = EvidenceLinkData<'_>> {
        self.wire.previous_evidence.iter().map(|item| EvidenceLinkData { invocation: &item.invocation,
            intent_sha256: &item.intent_sha256, state_sha256: &item.state_sha256, capsule_sha256: &item.capsule_sha256 })
    }
    pub fn mutation_recorded_data(&self) -> bool { self.wire.phase == StatePhase::MutationRecorded && self.wire.residue.is_none() }
    fn next_evidence(previous: Option<(&StateData, &CapsuleData)>) -> Result<Vec<EvidenceRef>> {
        let Some((old, capsule)) = previous else { return Ok(Vec::new()); };
        require(old.wire.previous_evidence.len() < INVOCATION_LIMIT - 1, TransactionDataError::Limit)?;
        let mut refs = old.wire.previous_evidence.clone();
        refs.push(EvidenceRef { invocation: old.wire.invocation.clone(), intent_sha256: capsule.wire.intent_sha256.clone(),
            state_sha256: old.body_sha256.clone(), capsule_sha256: capsule.body_sha256.clone() });
        refs.sort_by(|a, b| a.invocation.cmp(&b.invocation)); Ok(refs)
    }
    /// Records actual supplied generation observations and derives the exact
    /// retained/evidence set. It does not publish, close, commit or authenticate.
    pub fn encode_applied_data(intent: &IntentData, previous: Option<(&StateData, &CapsuleData)>,
        current: &GenerationData, expected: &ReleaseSetData) -> Result<Vec<u8>> {
        require(previous_matches(intent, previous) && current.0.release == intent.wire.next
            && matches!(current.0.app, AppSlot::Canonical { .. }), TransactionDataError::Binding)?;
        let mut retained = previous.map_or_else(Vec::new, |(old, _)| old.wire.retained.clone());
        let shape = match (intent.wire.action, previous) {
            (ActionData::FreshInstall, None) => true,
            (ActionData::SamePackageNoop, Some((old, _))) => old.wire.current == current.0,
            (ActionData::RestoreFixedApp, Some((old, _))) => old.wire.current.same_runtime(&current.0),
            (ActionData::Update, Some((old, _))) => {
                require(retained.len() < PREDECESSOR_LIMIT, TransactionDataError::Limit)?;
                let mut held = old.wire.current.clone();
                held.app = AppSlot::Retained { invocation: intent.wire.invocation.clone(), identity: held.app.identity().clone() };
                retained.push(held); true
            },
            _ => false,
        };
        require(shape, TransactionDataError::Binding)?;
        let wire = StateWire { schema_version: 2, kind: STATE_KIND.into(), target: intent.wire.target.clone(),
            invocation: intent.wire.invocation.clone(), request_id: intent.wire.request_id.clone(), capsule_invocation: intent.wire.invocation.clone(),
            intended_action: intent.wire.action, phase: StatePhase::MutationRecorded, current: current.0.clone(),
            retained, previous_evidence: Self::next_evidence(previous)?, residue: None };
        let bytes = encode(&wire, STATE_LIMIT)?; Self::parse_data(&bytes, expected)?; Ok(bytes)
    }
    /// Only the known one-inverse path may supply these observations. A failed
    /// update is retained as such; restored A is not relabeled as successful B.
    pub fn encode_inverse_data(intent: &IntentData, previous: (&StateData, &CapsuleData),
        staging_present: bool, runtime_present: bool, expected: &ReleaseSetData) -> Result<Vec<u8>> {
        require(intent.wire.action == ActionData::Update && previous_matches(intent, Some(previous))
            && staging_present && runtime_present, TransactionDataError::Binding)?;
        let wire = StateWire { schema_version: 2, kind: STATE_KIND.into(), target: intent.wire.target.clone(),
            invocation: intent.wire.invocation.clone(), request_id: intent.wire.request_id.clone(), capsule_invocation: intent.wire.invocation.clone(),
            intended_action: intent.wire.action, phase: StatePhase::InverseRecorded,
            current: previous.0.wire.current.clone(), retained: previous.0.wire.retained.clone(),
            previous_evidence: Self::next_evidence(Some(previous))?, residue: Some(Residue {
                invocation: intent.wire.invocation.clone(), release: intent.wire.next.clone(), staging_present, runtime_present }) };
        let bytes = encode(&wire, STATE_LIMIT)?; Self::parse_data(&bytes, expected)?; Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum WorkerOutcome { Applied, SamePackage, RestoredApp, InverseRecorded, Refused, Partial, Unknown }
/// Actual original returns must be supplied by the native parent, not decoded
/// from a worker's assertion about its own future join or inherited-gate close.
pub struct WriterObservationData {
    pub returned: bool, pub exit_code: Option<u8>, pub original_joined: bool, pub result_eof: bool,
    pub original_closes_known: bool, pub within_original_deadline: bool,
    pub payload_write_count: u64, pub payload_write_bytes: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordedOutcomeData { Applied, SamePackage, RestoredApp, InverseRecorded, Refused, Partial, Unknown }
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkerFacts {
    returned: bool, exit_code: Option<u8>, original_joined: bool, result_eof: bool,
    original_closes_known: bool, within_original_deadline: bool, payload_write_count: u64, payload_write_bytes: u64,
}
impl WorkerFacts {
    fn settled_data(&self) -> bool { self.returned && self.original_joined && self.result_eof
        && self.original_closes_known && self.within_original_deadline }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CapsuleWire {
    schema_version: u32, kind: String, target: String, invocation: String, request_id: String, intended_action: ActionData,
    previous: Option<ReleaseData>, next: ReleaseData, actual_current: Option<ReleaseData>,
    intent_sha256: String, state_sha256: Option<String>, outcome: WorkerOutcome, writer: WorkerFacts,
}
#[derive(Debug)]
pub struct CapsuleData { wire: CapsuleWire, body_sha256: String }
impl CapsuleData {
    pub fn parse_data(bytes: &[u8], expected: &ReleaseSetData) -> Result<Self> {
        Self::parse_selected_data(bytes, expected, true)
    }
    /// Historical capsule DATA may name only a tuple in the independently
    /// selected producer set. It does not select a new expected release/target.
    pub fn parse_recorded_data(bytes: &[u8], expected: &ReleaseSetData) -> Result<Self> {
        Self::parse_selected_data(bytes, expected, false)
    }
    fn parse_selected_data(bytes: &[u8], expected: &ReleaseSetData, current: bool) -> Result<Self> {
        let value = raw(bytes, CAPSULE_LIMIT)?;
        for name in ["previous", "actualCurrent"] { record_field(&value, name, true)?; }
        for name in ["next", "writer"] { record_field(&value, name, false)?; }
        field(&value, "stateSha256")?; field(field(&value, "writer")?, "exitCode")?;
        let wire: CapsuleWire = decode(value)?;
        header(wire.schema_version, &wire.kind, CAPSULE_KIND, &wire.target, &wire.invocation, &wire.request_id, expected)?;
        pair(expected, wire.intended_action, wire.previous.as_ref(), &wire.next, current)?;
        require(hex(&wire.intent_sha256, 64) && wire.state_sha256.as_ref().is_none_or(|h| hex(h, 64))
            && wire.actual_current.as_ref().is_none_or(|r| expected.contains_data(r))
            && wire.writer.returned == wire.writer.exit_code.is_some()
            && (!wire.writer.original_joined || wire.writer.returned)
            && (wire.writer.payload_write_count == 0) == (wire.writer.payload_write_bytes == 0)
            && wire.writer.payload_write_count <= wire.writer.payload_write_bytes
            && wire.writer.payload_write_bytes <= PAYLOAD_LIMIT,
            TransactionDataError::Binding)?;
        Ok(Self { wire, body_sha256: digest(bytes) })
    }
    pub fn digest_data(&self) -> &str { &self.body_sha256 }
    pub fn invocation_data(&self) -> &str { &self.wire.invocation }
    pub fn request_id_data(&self) -> &str { &self.wire.request_id }
    pub fn intent_digest_data(&self) -> &str { &self.wire.intent_sha256 }
    pub fn encode_data(intent: &IntentData, previous: Option<(&StateData, &CapsuleData)>, state: Option<&StateData>,
        actual_current: Option<&ReleaseData>, outcome: RecordedOutcomeData, observed: WriterObservationData,
        expected: &ReleaseSetData) -> Result<Vec<u8>> {
        let wire_outcome = match outcome {
            RecordedOutcomeData::Applied => WorkerOutcome::Applied, RecordedOutcomeData::SamePackage => WorkerOutcome::SamePackage,
            RecordedOutcomeData::RestoredApp => WorkerOutcome::RestoredApp, RecordedOutcomeData::InverseRecorded => WorkerOutcome::InverseRecorded,
            RecordedOutcomeData::Refused => WorkerOutcome::Refused, RecordedOutcomeData::Partial => WorkerOutcome::Partial,
            RecordedOutcomeData::Unknown => WorkerOutcome::Unknown,
        };
        let wire = CapsuleWire { schema_version: 2, kind: CAPSULE_KIND.into(), target: intent.wire.target.clone(),
            invocation: intent.wire.invocation.clone(), request_id: intent.wire.request_id.clone(), intended_action: intent.wire.action,
            previous: intent.wire.previous.clone(), next: intent.wire.next.clone(), actual_current: actual_current.cloned(),
            intent_sha256: intent.body_sha256.clone(), state_sha256: state.map(|s| s.body_sha256.clone()), outcome: wire_outcome,
            writer: WorkerFacts { returned: observed.returned, exit_code: observed.exit_code,
                original_joined: observed.original_joined, result_eof: observed.result_eof,
                original_closes_known: observed.original_closes_known, within_original_deadline: observed.within_original_deadline,
                payload_write_count: observed.payload_write_count, payload_write_bytes: observed.payload_write_bytes } };
        let bytes = encode(&wire, CAPSULE_LIMIT)?;
        let capsule = Self::parse_data(&bytes, expected)?;
        let correspondence = correspondence_data(intent, previous, state, Some(&capsule));
        let wanted = match outcome {
            RecordedOutcomeData::Applied | RecordedOutcomeData::SamePackage | RecordedOutcomeData::RestoredApp => CorrespondenceData::MatchingRecordedData,
            RecordedOutcomeData::InverseRecorded => CorrespondenceData::InverseRecorded,
            RecordedOutcomeData::Refused | RecordedOutcomeData::Partial => CorrespondenceData::FailureRecorded,
            RecordedOutcomeData::Unknown => CorrespondenceData::Indeterminate,
        };
        require(correspondence == wanted, TransactionDataError::Binding)?; Ok(bytes)
    }
}

/// Comparison labels only. Even MatchingRecordedData does not establish that
/// these files were trusted, this is the current invocation, or any native event
/// occurred. The actual owner must retain those independent original proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorrespondenceData { Pending, Mismatch, Indeterminate, FailureRecorded, InverseRecorded, MatchingRecordedData }
fn previous_matches(intent: &IntentData, previous: Option<(&StateData, &CapsuleData)>) -> bool {
    match (&intent.wire.previous_state, previous) {
        (None, None) => true,
        (Some(link), Some((state, capsule))) => {
            let c = &capsule.wire;
            link.invocation == state.wire.invocation && link.sha256 == state.body_sha256
                && intent.wire.previous.as_ref() == Some(&state.wire.current.release)
                && state.wire.phase == StatePhase::MutationRecorded && state.wire.residue.is_none()
                && c.invocation == state.wire.invocation && c.target == intent.wire.target
                && c.request_id == state.wire.request_id && intent.wire.request_id != state.wire.request_id
                && c.intended_action == state.wire.intended_action
                && c.state_sha256.as_deref() == Some(state.body_sha256.as_str())
                && c.actual_current.as_ref() == Some(&state.wire.current.release)
                && c.next == state.wire.current.release && c.writer.settled_data() && c.writer.exit_code == Some(0)
                && match c.outcome {
                    WorkerOutcome::Applied => matches!(c.intended_action, ActionData::FreshInstall | ActionData::Update)
                        && c.writer.payload_write_count > 0,
                    WorkerOutcome::SamePackage => c.intended_action == ActionData::SamePackageNoop && c.writer.payload_write_count == 0,
                    WorkerOutcome::RestoredApp => c.intended_action == ActionData::RestoreFixedApp && c.writer.payload_write_count > 0,
                    _ => false,
                }
        },
        _ => false,
    }
}
fn evidence_matches(state: &StateWire, previous: Option<(&StateData, &CapsuleData)>) -> bool {
    let Some((old, capsule)) = previous else { return state.previous_evidence.is_empty(); };
    let mut expected = old.wire.previous_evidence.clone();
    expected.push(EvidenceRef { invocation: old.wire.invocation.clone(), intent_sha256: capsule.wire.intent_sha256.clone(),
        state_sha256: old.body_sha256.clone(), capsule_sha256: capsule.body_sha256.clone() });
    expected.sort_by(|a, b| a.invocation.cmp(&b.invocation));
    state.previous_evidence == expected
}
pub fn correspondence_data(intent: &IntentData, previous: Option<(&StateData, &CapsuleData)>, state: Option<&StateData>,
    capsule: Option<&CapsuleData>) -> CorrespondenceData {
    if intent.wire.previous_state.is_some() && previous.is_none() { return CorrespondenceData::Pending; }
    if !previous_matches(intent, previous) { return CorrespondenceData::Mismatch; }
    let Some(capsule) = capsule else { return CorrespondenceData::Pending; };
    let c = &capsule.wire; let i = &intent.wire;
    if c.invocation != i.invocation || c.request_id != i.request_id || c.target != i.target || c.intended_action != i.action
        || c.previous != i.previous || c.next != i.next || c.intent_sha256 != intent.body_sha256 {
        return CorrespondenceData::Mismatch;
    }
    if !c.writer.settled_data() || c.outcome == WorkerOutcome::Unknown { return CorrespondenceData::Indeterminate; }
    if let Some(state) = state {
        if c.state_sha256.as_deref() != Some(state.body_sha256.as_str()) || state.wire.invocation != i.invocation
            || state.wire.request_id != i.request_id || state.wire.target != i.target || state.wire.intended_action != i.action
            || c.actual_current.as_ref() != Some(&state.wire.current.release) { return CorrespondenceData::Mismatch; }
    } else if c.state_sha256.is_some() { return CorrespondenceData::Pending; }
    if matches!(c.outcome, WorkerOutcome::Refused | WorkerOutcome::Partial) {
        return if c.writer.exit_code.is_some_and(|code| code != 0) { CorrespondenceData::FailureRecorded }
            else { CorrespondenceData::Mismatch };
    }
    let Some(state) = state else { return CorrespondenceData::Pending; };
    let s = &state.wire;
    if !evidence_matches(s, previous) { return CorrespondenceData::Mismatch; }
    let previous = previous.map(|(state, _)| state);
    if c.outcome == WorkerOutcome::InverseRecorded {
        return if i.action == ActionData::Update && s.phase == StatePhase::InverseRecorded
            && previous.is_some_and(|old| old.wire.current == s.current && old.wire.retained == s.retained)
            && s.residue.as_ref().is_some_and(|r| r.staging_present && r.runtime_present && r.release == i.next)
            && c.writer.exit_code.is_some_and(|code| code != 0) {
            CorrespondenceData::InverseRecorded
        } else { CorrespondenceData::Mismatch };
    }
    if c.writer.exit_code != Some(0) || s.phase != StatePhase::MutationRecorded || s.residue.is_some()
        || s.current.release != i.next { return CorrespondenceData::Mismatch; }
    let objects = match i.action {
        ActionData::FreshInstall => c.outcome == WorkerOutcome::Applied && c.writer.payload_write_count > 0
            && s.retained.is_empty() && s.previous_evidence.is_empty(),
        ActionData::SamePackageNoop => c.outcome == WorkerOutcome::SamePackage && c.writer.payload_write_count == 0
            && previous.is_some_and(|old| old.wire.current == s.current && old.wire.retained == s.retained),
        ActionData::RestoreFixedApp => c.outcome == WorkerOutcome::RestoredApp && c.writer.payload_write_count > 0
            && previous.is_some_and(|old| old.wire.current.same_runtime(&s.current) && old.wire.retained == s.retained),
        ActionData::Update => c.outcome == WorkerOutcome::Applied && c.writer.payload_write_count > 0 && previous.is_some_and(|old| {
            s.retained.len() == old.wire.retained.len() + 1
                && old.wire.retained.iter().all(|retained| s.retained.contains(retained))
                && s.retained.iter().any(|retained| old.wire.current.same_objects(retained)
                    && matches!(&retained.app, AppSlot::Retained { invocation, .. } if invocation == &i.invocation))
        }),
        ActionData::Uninstall => false,
    };
    if objects { CorrespondenceData::MatchingRecordedData } else { CorrespondenceData::Mismatch }
}

#[derive(Clone, Copy, Debug)]
pub struct GenerationCostData { pub files: u64, pub bytes: u64 }
#[derive(Debug)]
pub struct BudgetData { payload_bytes: u64, payload_files: u64 }
impl BudgetData {
    /// Numbers supplied by an actual future inventory observer, including ALL
    /// retained/current physical payloads AND incoming staging, not merely a
    /// count of release names. This neither observes nor reserves those objects.
    pub fn checked_data(generations: &[GenerationCostData], invocation_count: usize, evidence_bytes: u64,
        control_bytes: u64, original_records: u64, live_fds: u64) -> Result<Self> {
        require(!generations.is_empty() && generations.len() <= PREDECESSOR_LIMIT + 1
            && invocation_count > 0 && invocation_count <= INVOCATION_LIMIT && control_bytes <= 16 * 1024 * 1024
            && original_records <= 24576 && live_fds <= 96, TransactionDataError::Limit)?;
        let (mut payload_bytes, mut payload_files) = (0u64, 0u64);
        for generation in generations {
            require(generation.files > 0 && generation.files <= FILE_LIMIT as u64 && generation.bytes <= PAYLOAD_LIMIT,
                TransactionDataError::Limit)?;
            payload_bytes = payload_bytes.checked_add(generation.bytes).ok_or(TransactionDataError::Limit)?;
            payload_files = payload_files.checked_add(generation.files).ok_or(TransactionDataError::Limit)?;
        }
        // Includes each unique result alongside its linked records. The
        // overall PAYLOAD_LIMIT is unchanged; exports cannot evade it merely
        // because their fixed parent is Application Support, not install root.
        let evidence_bound = (invocation_count as u64).checked_mul((INTENT_LIMIT + STATE_LIMIT + CAPSULE_LIMIT + REQUEST_EXPORT_LIMIT) as u64)
            .ok_or(TransactionDataError::Limit)?;
        // The pair is persisted outside payload/record hashes, but occupies
        // actual storage in every current/retained generation. Reserve its full
        // bounded extent even before an incoming original pair is published.
        let producer_bound = (generations.len() as u64).checked_mul(PRODUCER_CONTROL_LIMIT as u64)
            .ok_or(TransactionDataError::Limit)?;
        require(evidence_bytes <= evidence_bound && payload_bytes.checked_add(evidence_bytes)
                .and_then(|n| n.checked_add(producer_bound)).is_some_and(|n| n <= PAYLOAD_LIMIT)
            && payload_files <= (PREDECESSOR_LIMIT as u64 + 1) * FILE_LIMIT as u64, TransactionDataError::Limit)?;
        Ok(Self { payload_bytes, payload_files })
    }
    pub fn payload_totals_data(&self) -> (u64, u64) { (self.payload_files, self.payload_bytes) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepData { Reobserved, Prepared, RuntimePublished, MetadataPublished, OldAppQuarantined, AppPublished,
    StatePublished, NewAppWithdrawn, OldAppRestored, StateRestored, OriginalsSettled }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnedData { KnownSuccess, KnownRefusal, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressOutcomeData { InProgress, Recorded, Refused, Unknown, InverseRecorded }
/// Finite returned-effect accounting only. No clock call, handle, permission or
/// operation dispatch; an actual owner must supply the SAME original endpoint,
/// observations and returned effects. A true supplied bit is not their proof.
#[derive(Debug)]
pub struct ProgressData {
    action: ActionData, end: u64, last_observed: u64, expired: bool, next: usize, unknown: bool, failed: bool,
    sequence_invalid: bool,
    inverse_started: bool, inverse_admitted: bool, inverse_complete: bool, inverse_next: usize,
    old_quarantined: bool, app_published: bool, state_published: bool, settled: bool,
}
impl ProgressData {
    pub fn new_data(action: ActionData, observed_start: u64, original_endpoint: u64) -> Result<Self> {
        require(action != ActionData::Uninstall && observed_start < original_endpoint, TransactionDataError::Binding)?;
        Ok(Self { action, end: original_endpoint, last_observed: observed_start, expired: false, next: 0, unknown: false,
            failed: false, sequence_invalid: false, inverse_started: false, inverse_admitted: false, inverse_complete: false, inverse_next: 0,
            old_quarantined: false, app_published: false, state_published: false, settled: false })
    }
    fn forward(&self) -> &'static [StepData] {
        use StepData::*;
        match self.action {
            ActionData::FreshInstall => &[Prepared, RuntimePublished, MetadataPublished, AppPublished, StatePublished, OriginalsSettled],
            ActionData::SamePackageNoop => &[Reobserved, StatePublished, OriginalsSettled],
            ActionData::RestoreFixedApp => &[Reobserved, Prepared, AppPublished, StatePublished, OriginalsSettled],
            ActionData::Update => &[Reobserved, Prepared, RuntimePublished, MetadataPublished, OldAppQuarantined, AppPublished, StatePublished, OriginalsSettled],
            ActionData::Uninstall => &[],
        }
    }
    fn returned(&mut self, returned: ReturnedData, at: u64) -> bool {
        // Late returned successes do not disappear; the original effect still
        // exists. They can never authorize the next effect or an inverse.
        if returned == ReturnedData::Unknown || at < self.last_observed { self.unknown = true; }
        self.last_observed = self.last_observed.max(at);
        self.expired |= at >= self.end;
        if returned != ReturnedData::KnownSuccess || self.expired { self.failed = true; }
        !self.unknown && !self.failed
    }
    /// A real validation/persistence refusal after a known effect is not a
    /// second publication or an out-of-order returned effect. Keep the effect
    /// and latch failure/uncertainty without manufacturing another step.
    pub fn stop_data(&mut self, returned: ReturnedData, observed_after: u64) -> Result<()> {
        require(returned != ReturnedData::KnownSuccess, TransactionDataError::Transition)?;
        // A post-effect failure during/after inverse settlement must not let the
        // historical inverse_complete bit become a successful current outcome.
        if self.inverse_started { self.sequence_invalid = true; self.inverse_admitted = false; }
        self.returned(returned, observed_after);
        Err(TransactionDataError::Transition)
    }
    pub fn forward_return_data(&mut self, step: StepData, returned: ReturnedData, observed_after: u64) -> Result<()> {
        if self.failed || self.unknown || self.inverse_started || self.settled || self.forward().get(self.next) != Some(&step) {
            self.sequence_invalid = true; self.failed = true;
            self.returned(returned, observed_after);
            return Err(TransactionDataError::Transition);
        }
        // Account known original publication even when its return is late.
        if returned == ReturnedData::KnownSuccess {
            self.old_quarantined |= step == StepData::OldAppQuarantined;
            self.app_published |= step == StepData::AppPublished;
            self.state_published |= step == StepData::StatePublished;
            self.settled |= step == StepData::OriginalsSettled;
            self.next += 1;
        }
        if self.returned(returned, observed_after) { Ok(()) } else { Err(TransactionDataError::Transition) }
    }
    pub fn begin_inverse_data(&mut self, observed_before: u64, same_originals: bool, exclusive_destinations_absent: bool) -> Result<()> {
        let allowed = self.action == ActionData::Update && self.failed && !self.unknown && !self.inverse_started
            && !self.expired && !self.sequence_invalid && !self.settled && !self.state_published && self.old_quarantined
            && observed_before >= self.last_observed && observed_before < self.end
            && same_originals && exclusive_destinations_absent;
        // Attempt and admission are distinct: a refused begin must never open
        // the inverse-return path or relabel already settled forward work.
        self.inverse_started = true;
        self.inverse_admitted = allowed;
        self.last_observed = self.last_observed.max(observed_before);
        self.expired |= observed_before >= self.end;
        if allowed { Ok(()) } else { self.failed = true; Err(TransactionDataError::Transition) }
    }
    pub fn inverse_return_data(&mut self, step: StepData, returned: ReturnedData, observed_after: u64) -> Result<()> {
        use StepData::*;
        let steps: &[StepData] = if self.app_published { &[NewAppWithdrawn, OldAppRestored, StateRestored, OriginalsSettled] }
            else { &[OldAppRestored, StateRestored, OriginalsSettled] };
        if !self.inverse_admitted || self.unknown || self.expired || self.settled || steps.get(self.inverse_next) != Some(&step) {
            self.sequence_invalid = true; self.inverse_admitted = false; self.failed = true;
            self.returned(returned, observed_after);
            return Err(TransactionDataError::Transition);
        }
        if returned == ReturnedData::KnownSuccess {
            self.inverse_next += 1; self.settled |= step == OriginalsSettled;
        }
        if returned == ReturnedData::Unknown || observed_after < self.last_observed { self.unknown = true; }
        self.last_observed = self.last_observed.max(observed_after);
        self.expired |= observed_after >= self.end;
        if returned != ReturnedData::KnownSuccess || self.unknown || self.expired {
            self.inverse_admitted = false; return Err(TransactionDataError::Transition);
        }
        self.inverse_complete = self.settled; Ok(())
    }
    pub fn outcome_data(&self) -> ProgressOutcomeData {
        if self.unknown { ProgressOutcomeData::Unknown }
        // Retain the historical inverse-complete fact, but never let it turn a
        // subsequent contradictory/late returned effect into a positive label.
        else if self.sequence_invalid || self.expired { ProgressOutcomeData::Refused }
        else if self.inverse_complete { ProgressOutcomeData::InverseRecorded }
        else if self.failed { ProgressOutcomeData::Refused }
        else if self.settled { ProgressOutcomeData::Recorded } else { ProgressOutcomeData::InProgress }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos_install_maintenance::MaintenanceTargetData;
    use serde_json::{json, Value};
    // Inert unsigned comparison data, never native package/installation proof.
    fn release(n: u32) -> Value { json!({"profile":"fixed-macos26-arm64-maintenance-v2",
        "packageIdentifier":"dev.mobile-release-kit.desktop.installed","bundleIdentifier":"dev.mobile-release-kit.desktop",
        "packageVersion":format!("0.{n}.0"),"release":format!("macos26-arm64-data-{n}"),"sourceCommit":format!("{n:040x}"),
        "protocolSha256":"a".repeat(64),"runtimeManifestSha256":format!("{n:064x}"),
        "inventorySha256":format!("{:064x}",n+20),"signingPolicySha256":"b".repeat(64),"packageSha256":format!("{:064x}",n+40)}) }
    fn bytes(v: &Value) -> Vec<u8> { serde_json::to_vec(v).unwrap() }
    const RELEASE_FIELDS: &[&str] = &["profile", "packageIdentifier", "bundleIdentifier", "packageVersion", "release", "sourceCommit",
        "protocolSha256", "runtimeManifestSha256", "inventorySha256", "signingPolicySha256", "packageSha256"];
    fn positional(value: &Value, keys: &[&str]) -> Value {
        Value::Array(keys.iter().map(|key| value[*key].clone()).collect())
    }
    fn expected() -> ReleaseSetData { ReleaseSetData::parse_for_target_data(&bytes(&json!({"schemaVersion":2,
        "current":release(3),"acceptedPredecessors":[release(2)]})), MaintenanceTargetData::Arm64).unwrap() }
    fn id(n: u32) -> String { format!("{n:032x}") }
    fn parent(n: u64) -> Value { json!({"device":1,"inode":n,"mode":0o040755,"uid":0,"gid":0,"flags":0}) }
    fn generation(n: u32) -> Value { json!({"release":release(n),"instance":id(n),"releaseDirectory":parent(100+u64::from(n)),
        "app":{"location":"canonical","identity":{"device":1,"inode":200+u64::from(n),"mode":0o040555,"uid":0,"gid":0,"flags":0}}}) }
    fn state(n: u32, invocation: u32) -> Value { json!({"schemaVersion":2,"kind":STATE_KIND,
        "target":"aarch64-apple-darwin","invocation":id(invocation),"requestId":id(invocation+100),"capsuleInvocation":id(invocation),
        "intendedAction":"fresh-install","phase":"mutation-recorded","current":generation(n),
        "retained":[],"previousEvidence":[],"residue":null}) }
    fn intent(action: &str, old: Option<&Value>) -> Value {
        let previous = old.map(|v| v["current"]["release"].clone());
        json!({"schemaVersion":2,"kind":INTENT_KIND,"target":"aarch64-apple-darwin","invocation":id(9),"requestId":id(109),
            "action":action,"previous":previous,"next":release(3),"previousState":old.map(|v| json!({"invocation":v["invocation"],"sha256":digest(&bytes(v))}))})
    }
    fn capsule(intent: &Value, state: &Value, outcome: &str) -> Value { json!({"schemaVersion":2,"kind":CAPSULE_KIND,
        "target":"aarch64-apple-darwin","invocation":intent["invocation"],"requestId":intent["requestId"],"intendedAction":intent["action"],
        "previous":intent["previous"],"next":intent["next"],"actualCurrent":state["current"]["release"],
        "intentSha256":digest(&bytes(intent)),"stateSha256":digest(&bytes(state)),"outcome":outcome,
        "writer":{"returned":true,"exitCode":0,"originalJoined":true,"resultEof":true,"originalClosesKnown":true,
            "withinOriginalDeadline":true,"payloadWriteCount":if outcome == "same-package" { 0 } else { 1 },
            "payloadWriteBytes":if outcome == "same-package" { 0 } else { 1 }}}) }
    fn prior_capsule(old: &Value) -> Value {
        let i = json!({"invocation":old["invocation"],"requestId":old["requestId"],"action":old["intendedAction"],"previous":null,
            "next":old["current"]["release"]});
        capsule(&i, old, "applied")
    }
    fn record_previous(state: &mut Value, old: &Value) {
        let c = prior_capsule(old);
        let mut rows = old["previousEvidence"].as_array().unwrap().clone();
        rows.push(json!({"invocation":old["invocation"],"intentSha256":c["intentSha256"],
            "stateSha256":digest(&bytes(old)),"capsuleSha256":digest(&bytes(&c))}));
        rows.sort_by(|a,b| a["invocation"].as_str().cmp(&b["invocation"].as_str()));
        state["previousEvidence"] = json!(rows);
    }
    fn retained(mut value: Value, invocation: u32) -> Value {
        value["app"]["location"] = json!("retained"); value["app"]["invocation"] = json!(id(invocation)); value
    }
    fn compare(i: &Value, old: Option<&Value>, s: &Value, c: &Value) -> CorrespondenceData {
        let expected = expected(); let i = IntentData::parse_data(&bytes(i), &expected).unwrap();
        let prior = old.map(|v| (StateData::parse_data(&bytes(v), &expected).unwrap(),
            CapsuleData::parse_recorded_data(&bytes(&prior_capsule(v)), &expected).unwrap()));
        let s = StateData::parse_data(&bytes(s), &expected).unwrap(); let c = CapsuleData::parse_data(&bytes(c), &expected).unwrap();
        correspondence_data(&i, prior.as_ref().map(|(s,c)| (s,c)), Some(&s), Some(&c))
    }
    #[test]
    fn records_are_bounded_closed_objects_including_every_nested_record() {
        let e = expected(); let old = state(2, 2); let i = intent("update", Some(&old));
        let mut s = state(3, 9); s["intendedAction"] = json!("update"); s["retained"] = json!([retained(generation(2), 9)]);
        record_previous(&mut s, &old);
        let c = capsule(&i, &s, "applied");
        // Full-arity sequence encodings would otherwise be accepted by derived
        // Deserialize; empty arrays alone do not protect the map-only contract.
        for (path, keys) in [("/previous", RELEASE_FIELDS), ("/next", RELEASE_FIELDS),
            ("/previousState", &["invocation", "sha256"][..])] {
            let mut value = i.clone(); let sequence = positional(value.pointer(path).unwrap(), keys);
            *value.pointer_mut(path).unwrap() = sequence;
            assert!(IntentData::parse_data(&bytes(&value), &e).is_err(), "{path}");
        }
        let state_records: &[(&str, &[&str])] = &[
            ("/current", &["release", "instance", "releaseDirectory", "app"]), ("/current/release", RELEASE_FIELDS),
            ("/current/releaseDirectory", &["device", "inode", "mode", "uid", "gid", "flags"]),
            ("/current/app", &["location", "identity"]), ("/current/app/identity", &["device", "inode", "mode", "uid", "gid", "flags"]),
            ("/retained/0", &["release", "instance", "releaseDirectory", "app"]), ("/retained/0/release", RELEASE_FIELDS),
            ("/retained/0/releaseDirectory", &["device", "inode", "mode", "uid", "gid", "flags"]),
            ("/retained/0/app", &["location", "invocation", "identity"]),
            ("/retained/0/app/identity", &["device", "inode", "mode", "uid", "gid", "flags"]),
            ("/previousEvidence/0", &["invocation", "intentSha256", "stateSha256", "capsuleSha256"])];
        for (path, keys) in state_records {
            let mut value = s.clone(); let sequence = positional(value.pointer(path).unwrap(), keys);
            *value.pointer_mut(path).unwrap() = sequence;
            assert!(StateData::parse_data(&bytes(&value), &e).is_err(), "{path}");
        }
        for (path, keys) in [("/previous", RELEASE_FIELDS), ("/next", RELEASE_FIELDS), ("/actualCurrent", RELEASE_FIELDS),
            ("/writer", &["returned", "exitCode", "originalJoined", "resultEof", "originalClosesKnown", "withinOriginalDeadline", "payloadWriteCount", "payloadWriteBytes"][..])] {
            let mut value = c.clone(); let sequence = positional(value.pointer(path).unwrap(), keys);
            *value.pointer_mut(path).unwrap() = sequence;
            assert!(CapsuleData::parse_data(&bytes(&value), &e).is_err(), "{path}");
        }
        assert!(IntentData::parse_data(&bytes(&positional(&i, &["schemaVersion", "kind", "target", "invocation", "requestId", "action", "previous", "next", "previousState"])), &e).is_err());
        assert!(StateData::parse_data(&bytes(&positional(&s, &["schemaVersion", "kind", "target", "invocation", "requestId", "capsuleInvocation", "intendedAction", "phase", "current", "retained", "previousEvidence", "residue"])), &e).is_err());
        assert!(CapsuleData::parse_data(&bytes(&positional(&c, &["schemaVersion", "kind", "target", "invocation", "requestId", "intendedAction", "previous", "next", "actualCurrent", "intentSha256", "stateSha256", "outcome", "writer"])), &e).is_err());
        for bad in [b"[]".as_slice(), b"{\"schemaVersion\":2,\"schemaVersion\":2}", b"\xff", b"{\"schemaVersion\":NaN}"] {
            assert!(IntentData::parse_data(bad, &e).is_err()); assert!(StateData::parse_data(bad, &e).is_err());
            assert!(CapsuleData::parse_data(bad, &e).is_err());
        }
        assert!(IntentData::parse_data(&vec![b' '; INTENT_LIMIT + 1], &e).is_err());
        assert!(StateData::parse_data(&vec![b' '; STATE_LIMIT + 1], &e).is_err());
        assert!(CapsuleData::parse_data(&vec![b' '; CAPSULE_LIMIT + 1], &e).is_err());
        for key in ["authority", "parentFutureExit", "path"] {
            let mut value = s.clone(); value[key] = json!(true); assert!(StateData::parse_data(&bytes(&value), &e).is_err());
        }
        assert_eq!(compare(&i, Some(&old), &s, &c), CorrespondenceData::MatchingRecordedData);
    }
    #[test]
    fn capsule_requires_exact_intent_state_target_and_original_worker_facts_data() {
        let e = expected(); let i = intent("fresh-install", None); let s = state(3, 9); let c = capsule(&i, &s, "applied");
        let ip = IntentData::parse_data(&bytes(&i), &e).unwrap(); let sp = StateData::parse_data(&bytes(&s), &e).unwrap();
        assert_eq!(correspondence_data(&ip, None, Some(&sp), None), CorrespondenceData::Pending);
        assert_eq!(compare(&i, None, &s, &c), CorrespondenceData::MatchingRecordedData);
        // Count actual positive write returns, not descriptor records. Both
        // live and historical capsules keep the same required byte accounting.
        for (count, written) in [(24577u64, 24577u64), (1, PAYLOAD_LIMIT)] {
            let mut short = c.clone(); short["writer"]["payloadWriteCount"] = json!(count);
            short["writer"]["payloadWriteBytes"] = json!(written);
            assert!(CapsuleData::parse_data(&bytes(&short), &e).is_ok());
            assert!(CapsuleData::parse_recorded_data(&bytes(&short), &e).is_ok());
            assert_eq!(compare(&i, None, &s, &short), CorrespondenceData::MatchingRecordedData);
        }
        for (count, written) in [(1u64, 0u64), (0, 1), (2, 1), (1, PAYLOAD_LIMIT + 1),
            (PAYLOAD_LIMIT + 1, PAYLOAD_LIMIT + 1)] {
            let mut invalid = c.clone(); invalid["writer"]["payloadWriteCount"] = json!(count);
            invalid["writer"]["payloadWriteBytes"] = json!(written);
            assert!(CapsuleData::parse_data(&bytes(&invalid), &e).is_err());
            assert!(CapsuleData::parse_recorded_data(&bytes(&invalid), &e).is_err());
        }
        let mut missing_bytes = c.clone(); missing_bytes["writer"].as_object_mut().unwrap().remove("payloadWriteBytes");
        assert!(CapsuleData::parse_data(&bytes(&missing_bytes), &e).is_err());
        assert!(CapsuleData::parse_recorded_data(&bytes(&missing_bytes), &e).is_err());
        for name in ["invocation", "requestId", "intentSha256", "stateSha256"] {
            let mut altered = c.clone(); altered[name] = json!("f".repeat(if name == "invocation" || name == "requestId" { 32 } else { 64 }));
            assert_eq!(compare(&i, None, &s, &altered), CorrespondenceData::Mismatch, "{name}");
        }
        for fact in ["originalJoined", "resultEof", "originalClosesKnown", "withinOriginalDeadline"] {
            let mut altered = c.clone(); altered["writer"][fact] = json!(false);
            assert_eq!(compare(&i, None, &s, &altered), CorrespondenceData::Indeterminate, "{fact}");
        }
        let mut unavailable = c.clone(); unavailable["writer"]["returned"] = json!(false);
        unavailable["writer"]["originalJoined"] = json!(false); unavailable["writer"]["exitCode"] = Value::Null;
        assert_eq!(compare(&i, None, &s, &unavailable), CorrespondenceData::Indeterminate);
        let mut mixed = c.clone(); mixed["target"] = json!(MaintenanceTargetData::Intel.target());
        assert!(CapsuleData::parse_data(&bytes(&mixed), &e).is_err());
        let mut wrong = c.clone(); wrong["writer"]["exitCode"] = json!(true);
        assert!(CapsuleData::parse_data(&bytes(&wrong), &e).is_err());
        let mut missing = unavailable.clone(); missing["writer"].as_object_mut().unwrap().remove("exitCode");
        assert!(CapsuleData::parse_data(&bytes(&missing), &e).is_err());
        let mut missing = c.clone(); missing.as_object_mut().unwrap().remove("stateSha256");
        assert!(CapsuleData::parse_data(&bytes(&missing), &e).is_err());
        let cp = CapsuleData::parse_data(&bytes(&c), &e).unwrap();
        assert_eq!(correspondence_data(&ip, None, None, Some(&cp)), CorrespondenceData::Pending);
        // The identical DATA contract also works for a caller-selected Intel
        // tuple; neither a capsule nor its state chooses that expectation.
        let mut intel_release = release(3); intel_release["profile"] = json!("fixed-macos26-x86_64-maintenance-v2");
        intel_release["release"] = json!("macos26-x86_64-data-3");
        let intel_expected = ReleaseSetData::parse_for_target_data(&bytes(&json!({"schemaVersion":2,
            "current":intel_release,"acceptedPredecessors":[]})), MaintenanceTargetData::Intel).unwrap();
        let mut ii = i.clone(); ii["target"] = json!(MaintenanceTargetData::Intel.target()); ii["next"] = intel_release.clone();
        let mut ss = s.clone(); ss["target"] = json!(MaintenanceTargetData::Intel.target()); ss["current"]["release"] = intel_release;
        let mut cc = capsule(&ii, &ss, "applied"); cc["target"] = json!(MaintenanceTargetData::Intel.target());
        let ii = IntentData::parse_data(&bytes(&ii), &intel_expected).unwrap();
        let ss = StateData::parse_data(&bytes(&ss), &intel_expected).unwrap();
        let cc = CapsuleData::parse_data(&bytes(&cc), &intel_expected).unwrap();
        assert_eq!(correspondence_data(&ii, None, Some(&ss), Some(&cc)), CorrespondenceData::MatchingRecordedData);
        // A recorded Update is ordered within the selected history too: both
        // tuples being accepted predecessors is not permission for a downgrade.
        let historical = ReleaseSetData::parse_for_target_data(&bytes(&json!({"schemaVersion":2,
            "current":release(4),"acceptedPredecessors":[release(2),release(3)]})), MaintenanceTargetData::Arm64).unwrap();
        let old = state(2,2); let hi = intent("update", Some(&old));
        let mut hs = state(3,9); hs["intendedAction"] = json!("update");
        let hc = capsule(&hi, &hs, "applied");
        assert!(CapsuleData::parse_recorded_data(&bytes(&hc), &historical).is_ok());
        assert!(CapsuleData::parse_data(&bytes(&hc), &historical).is_err());
        let mut downgrade = hc.clone(); downgrade["previous"] = release(3); downgrade["next"] = release(2);
        downgrade["actualCurrent"] = release(2);
        assert!(CapsuleData::parse_recorded_data(&bytes(&downgrade), &historical).is_err());
        let mut same = hc.clone(); same["previous"] = same["next"].clone();
        assert!(CapsuleData::parse_recorded_data(&bytes(&same), &historical).is_err());
    }
    #[test]
    fn same_package_has_new_invocation_zero_payload_writes_and_no_generation_replacement() {
        let old = state(3, 3); let i = intent("same-package-noop", Some(&old));
        let mut s = state(3, 9); s["intendedAction"] = json!("same-package-noop"); record_previous(&mut s, &old);
        let c = capsule(&i, &s, "same-package");
        assert_eq!(compare(&i, Some(&old), &s, &c), CorrespondenceData::MatchingRecordedData);
        let mut writes = c.clone(); writes["writer"]["payloadWriteCount"] = json!(1);
        writes["writer"]["payloadWriteBytes"] = json!(1);
        assert_eq!(compare(&i, Some(&old), &s, &writes), CorrespondenceData::Mismatch);
        let mut replaced = s.clone(); replaced["current"]["app"]["identity"]["inode"] = json!(999);
        let changed = capsule(&i, &replaced, "same-package");
        assert_eq!(compare(&i, Some(&old), &replaced, &changed), CorrespondenceData::Mismatch);
        let mut missing_evidence = s.clone(); missing_evidence["previousEvidence"] = json!([]);
        assert_eq!(compare(&i, Some(&old), &missing_evidence, &capsule(&i, &missing_evidence, "same-package")), CorrespondenceData::Mismatch);
        let e = expected(); let ip = IntentData::parse_data(&bytes(&i), &e).unwrap();
        let sp = StateData::parse_data(&bytes(&s), &e).unwrap(); let cp = CapsuleData::parse_data(&bytes(&c), &e).unwrap();
        let op = StateData::parse_data(&bytes(&old), &e).unwrap();
        assert_eq!(correspondence_data(&ip, None, Some(&sp), Some(&cp)), CorrespondenceData::Pending);
        let mut old_capsule = prior_capsule(&old); old_capsule["writer"]["originalJoined"] = json!(false);
        let oc = CapsuleData::parse_recorded_data(&bytes(&old_capsule), &e).unwrap();
        assert_eq!(correspondence_data(&ip, Some((&op,&oc)), Some(&sp), Some(&cp)), CorrespondenceData::Mismatch);
        let mut old_capsule = prior_capsule(&old); old_capsule["intentSha256"] = json!("e".repeat(64));
        let oc = CapsuleData::parse_recorded_data(&bytes(&old_capsule), &e).unwrap();
        assert_eq!(correspondence_data(&ip, Some((&op,&oc)), Some(&sp), Some(&cp)), CorrespondenceData::Mismatch);
        let mut replay = i.clone(); replay["invocation"] = old["invocation"].clone();
        assert!(IntentData::parse_data(&bytes(&replay), &expected()).is_err());
        let mut restore = i.clone(); restore["action"] = json!("restore-fixed-app");
        replaced["intendedAction"] = json!("restore-fixed-app");
        let restored = capsule(&restore, &replaced, "restored-app");
        assert_eq!(compare(&restore, Some(&old), &replaced, &restored), CorrespondenceData::MatchingRecordedData);
        replaced["current"]["releaseDirectory"]["inode"] = json!(1000);
        let changed = capsule(&restore, &replaced, "restored-app");
        assert_eq!(compare(&restore, Some(&old), &replaced, &changed), CorrespondenceData::Mismatch);
    }
    #[test]
    fn retained_generations_and_inverse_never_adopt_partial_or_unrelated_state() {
        let e = expected(); let old = state(2, 2); let i = intent("update", Some(&old));
        let mut s = state(3, 9); s["intendedAction"] = json!("update"); s["retained"] = json!([retained(generation(2), 9)]);
        record_previous(&mut s, &old);
        let c = capsule(&i, &s, "applied"); assert_eq!(compare(&i, Some(&old), &s, &c), CorrespondenceData::MatchingRecordedData);
        let mut duplicate = s.clone(); duplicate["retained"] = json!([retained(generation(2), 9),retained(generation(2), 8)]);
        assert!(StateData::parse_data(&bytes(&duplicate), &e).is_err());
        let mut unrelated = s.clone(); unrelated["retained"][0]["app"]["invocation"] = json!(id(77));
        assert!(StateData::parse_data(&bytes(&unrelated), &e).is_err());
        let mut alias = s.clone(); alias["retained"][0]["app"]["identity"]["inode"] = s["current"]["releaseDirectory"]["inode"].clone();
        assert!(StateData::parse_data(&bytes(&alias), &e).is_err());
        let mut missing = s.clone(); missing["retained"] = json!([]);
        assert_eq!(compare(&i, Some(&old), &missing, &capsule(&i, &missing, "applied")), CorrespondenceData::Mismatch);
        let mut inverse = old.clone(); inverse["invocation"] = json!(id(9)); inverse["requestId"] = json!(id(109)); inverse["capsuleInvocation"] = json!(id(9));
        inverse["intendedAction"] = json!("update"); inverse["phase"] = json!("inverse-recorded");
        inverse["residue"] = json!({"invocation":id(9),"release":release(3),"stagingPresent":true,"runtimePresent":true});
        record_previous(&mut inverse, &old);
        let mut restored = capsule(&i, &inverse, "inverse-recorded"); restored["writer"]["exitCode"] = json!(20);
        assert_eq!(compare(&i, Some(&old), &inverse, &restored), CorrespondenceData::InverseRecorded);
        restored["outcome"] = json!("applied"); restored["writer"]["exitCode"] = json!(0);
        assert_eq!(compare(&i, Some(&old), &inverse, &restored), CorrespondenceData::Mismatch);
        for (path, keys) in [("/residue", &["invocation", "release", "stagingPresent", "runtimePresent"][..]),
            ("/residue/release", RELEASE_FIELDS)] {
            let mut value = inverse.clone(); let sequence = positional(value.pointer(path).unwrap(), keys);
            *value.pointer_mut(path).unwrap() = sequence;
            assert!(StateData::parse_data(&bytes(&value), &e).is_err());
        }
    }
    #[test]
    fn constructed_action_chain_keeps_runtime_identity_and_exact_linked_worker_evidence() {
        // These are comparison DATA, not package trust, native writes, or an
        // assertion that a historical outer Installer ever returned success.
        let a = ReleaseSetData::parse_for_target_data(&bytes(&json!({"schemaVersion":2,
            "current":release(2),"acceptedPredecessors":[]})), MaintenanceTargetData::Arm64).unwrap();
        let b = expected();
        let roundtrip = ReleaseSetData::parse_for_target_data(&b.encode_data().unwrap(), b.target_data()).unwrap();
        assert_eq!(roundtrip.current_data(), b.current_data());
        assert_eq!(roundtrip.predecessor_data(), b.predecessor_data());
        let app = |inode| AppIdentityData::from_original_fields_data(1,inode,0o040555,0,0,0).unwrap();
        let directory = |inode| DirectoryIdentity { device:1,inode,mode:0o040755,uid:0,gid:0,flags:0 };
        let observed = |writes, code| WriterObservationData { returned:true,exit_code:Some(code),original_joined:true,
            result_eof:true,original_closes_known:true,within_original_deadline:true,
            payload_write_count:writes,payload_write_bytes:writes };
        let original = GenerationData::from_original_fields_data(&a,a.current_data(),&id(2),directory(102),app(202)).unwrap();
        let fresh_i = IntentData::parse_data(&IntentData::encode_data(&id(2),&id(102),ActionData::FreshInstall,None,&a).unwrap(),&a).unwrap();
        let fresh_s = StateData::parse_data(&StateData::encode_applied_data(&fresh_i,None,&original,&a).unwrap(),&a).unwrap();
        let fresh_c = CapsuleData::parse_data(&CapsuleData::encode_data(&fresh_i,None,Some(&fresh_s),Some(a.current_data()),
            RecordedOutcomeData::Applied,observed(24_577,0),&a).unwrap(),&a).unwrap();
        assert_eq!(correspondence_data(&fresh_i,None,Some(&fresh_s),Some(&fresh_c)),CorrespondenceData::MatchingRecordedData);
        // Required linkage prevents a prior request export being presented as
        // this operation. Matching IDs remain comparison DATA, not authority.
        assert_ne!(fresh_i.request_id_data(),fresh_i.invocation_data());
        assert_eq!(fresh_i.request_id_data(),fresh_s.request_id_data());
        assert_eq!(fresh_i.request_id_data(),fresh_c.request_id_data());
        assert_eq!(request_from_package_name_data("Install.pkg").unwrap(),None);
        assert_eq!(request_from_package_name_data(&format!("MobileReleaseKit-Request-{}.pkg",id(102))).unwrap(),Some(id(102)));
        assert_eq!(export_name_data(&id(102)).unwrap(),format!("MobileReleaseKit-InstallerResult-v2-{}.json",id(102)));
        for bad in ["Other.pkg".into(),"../Install.pkg".into(),"Install.pkg/".into(),
            format!("MobileReleaseKit-Request-{}.pkg","0".repeat(32)),
            format!("MobileReleaseKit-Request-{}.pkg","A".repeat(32)),
            format!("MobileReleaseKit-Request-{}.pkg.trailing",id(102))] {
            assert!(request_from_package_name_data(&bad).is_err());
        }
        let mut missing = serde_json::to_value(&fresh_i.wire).unwrap();
        missing.as_object_mut().unwrap().remove("requestId");
        assert!(IntentData::parse_data(&bytes(&missing),&a).is_err());
        let mut missing = serde_json::to_value(&fresh_s.wire).unwrap();
        missing.as_object_mut().unwrap().remove("requestId");
        assert!(StateData::parse_data(&bytes(&missing),&a).is_err());
        let mut missing = serde_json::to_value(&fresh_c.wire).unwrap();
        missing.as_object_mut().unwrap().remove("requestId");
        assert!(CapsuleData::parse_data(&bytes(&missing),&a).is_err());
        let mut changed = serde_json::to_value(&fresh_c.wire).unwrap(); changed["requestId"] = json!(id(999));
        let wrong = CapsuleData::parse_data(&bytes(&changed),&a).unwrap();
        assert_eq!(correspondence_data(&fresh_i,None,Some(&fresh_s),Some(&wrong)),CorrespondenceData::Mismatch);
        let mut changed = serde_json::to_value(&fresh_s.wire).unwrap(); changed["requestId"] = json!(id(999));
        let wrong = StateData::parse_data(&bytes(&changed),&a).unwrap();
        assert_eq!(correspondence_data(&fresh_i,None,Some(&wrong),Some(&fresh_c)),CorrespondenceData::Mismatch);
        assert!(IntentData::encode_data(&id(5),fresh_i.request_id_data(),ActionData::SamePackageNoop,Some((&fresh_s,&fresh_c)),&a).is_err());
        assert!(IntentData::encode_data(&id(2),&id(102),ActionData::SamePackageNoop,Some((&fresh_s,&fresh_c)),&a).is_err());
        let noop_i = IntentData::parse_data(&IntentData::encode_data(&id(5),&id(105),ActionData::SamePackageNoop,Some((&fresh_s,&fresh_c)),&a).unwrap(),&a).unwrap();
        let noop_s = StateData::parse_data(&StateData::encode_applied_data(&noop_i,Some((&fresh_s,&fresh_c)),&original,&a).unwrap(),&a).unwrap();
        let noop_c = CapsuleData::parse_data(&CapsuleData::encode_data(&noop_i,Some((&fresh_s,&fresh_c)),Some(&noop_s),Some(a.current_data()),
            RecordedOutcomeData::SamePackage,observed(0,0),&a).unwrap(),&a).unwrap();
        assert_eq!(noop_s.current_data(),original);
        assert_eq!(noop_s.evidence_data().map(|e| e.invocation).collect::<Vec<_>>(),[id(2).as_str()]);
        assert_eq!(noop_s.retained_data().count(),0);
        assert!(CapsuleData::encode_data(&noop_i,Some((&fresh_s,&fresh_c)),Some(&noop_s),Some(a.current_data()),
            RecordedOutcomeData::SamePackage,observed(1,0),&a).is_err());
        let restored = GenerationData::from_original_fields_data(&a,a.current_data(),original.instance_data(),
            original.release_directory_data(),app(302)).unwrap();
        assert!(StateData::encode_applied_data(&noop_i,Some((&fresh_s,&fresh_c)),&restored,&a).is_err());
        let restore_i = IntentData::parse_data(&IntentData::encode_data(&id(6),&id(106),ActionData::RestoreFixedApp,Some((&noop_s,&noop_c)),&a).unwrap(),&a).unwrap();
        let restore_s = StateData::parse_data(&StateData::encode_applied_data(&restore_i,Some((&noop_s,&noop_c)),&restored,&a).unwrap(),&a).unwrap();
        let restore_c = CapsuleData::parse_data(&CapsuleData::encode_data(&restore_i,Some((&noop_s,&noop_c)),Some(&restore_s),Some(a.current_data()),
            RecordedOutcomeData::RestoredApp,observed(17,0),&a).unwrap(),&a).unwrap();
        assert_eq!(restore_s.current_data().instance_data(),original.instance_data());
        assert_eq!(restore_s.current_data().release_directory_data(),original.release_directory_data());
        assert_ne!(restore_s.current_data().app_identity_data(),original.app_identity_data());
        let wrong_runtime = GenerationData::from_original_fields_data(&a,a.current_data(),original.instance_data(),directory(303),app(302)).unwrap();
        assert!(StateData::encode_applied_data(&restore_i,Some((&noop_s,&noop_c)),&wrong_runtime,&a).is_err());
        let update_i_bytes = IntentData::encode_data(&id(7),&id(107),ActionData::Update,Some((&restore_s,&restore_c)),&b).unwrap();
        let update_i = IntentData::parse_data(&update_i_bytes,&b).unwrap();
        let next = GenerationData::from_original_fields_data(&b,b.current_data(),&id(3),directory(103),app(203)).unwrap();
        let update_s = StateData::parse_data(&StateData::encode_applied_data(&update_i,Some((&restore_s,&restore_c)),&next,&b).unwrap(),&b).unwrap();
        let update_c = CapsuleData::parse_data(&CapsuleData::encode_data(&update_i,Some((&restore_s,&restore_c)),Some(&update_s),Some(b.current_data()),
            RecordedOutcomeData::Applied,observed(31,0),&b).unwrap(),&b).unwrap();
        let retained = update_s.retained_data().collect::<Vec<_>>();
        assert_eq!(retained.len(),1); assert_eq!(retained[0].release_directory_data(),original.release_directory_data());
        assert_eq!(retained[0].app_identity_data(),restored.app_identity_data());
        assert_eq!(retained[0].retained_invocation_data(),Some(id(7).as_str()));
        assert_eq!(update_s.evidence_data().map(|e| e.invocation.to_owned()).collect::<Vec<_>>(),[id(2),id(5),id(6)]);
        assert_eq!(correspondence_data(&update_i,Some((&restore_s,&restore_c)),Some(&update_s),Some(&update_c)),CorrespondenceData::MatchingRecordedData);
        let inverse_s = StateData::parse_data(&StateData::encode_inverse_data(&update_i,(&restore_s,&restore_c),true,true,&b).unwrap(),&b).unwrap();
        let inverse_c = CapsuleData::parse_data(&CapsuleData::encode_data(&update_i,Some((&restore_s,&restore_c)),Some(&inverse_s),Some(a.current_data()),
            RecordedOutcomeData::InverseRecorded,observed(31,20),&b).unwrap(),&b).unwrap();
        assert!(!inverse_s.mutation_recorded_data()); assert_eq!(inverse_s.current_data(),restored);
        assert_eq!(correspondence_data(&update_i,Some((&restore_s,&restore_c)),Some(&inverse_s),Some(&inverse_c)),CorrespondenceData::InverseRecorded);
        assert!(IntentData::encode_data(&id(8),&id(108),ActionData::Update,Some((&inverse_s,&inverse_c)),&b).is_err());
        assert!(StateData::encode_inverse_data(&update_i,(&restore_s,&restore_c),false,true,&b).is_err());
        assert!(CapsuleData::encode_data(&update_i,Some((&restore_s,&restore_c)),Some(&update_s),Some(b.current_data()),
            RecordedOutcomeData::Applied,WriterObservationData { original_joined:false,..observed(31,0) },&b).is_err());
        assert!(GenerationData::from_original_fields_data(&a,b.current_data(),&id(3),directory(103),app(203)).is_err());
        for bad in ["", ".", "../other", &"0".repeat(32), &"A".repeat(32)] {
            assert!(intent_name_data(bad).is_err()); assert!(archived_state_name_data(bad).is_err());
            assert!(capsule_name_data(bad).is_err()); assert!(retained_app_name_data(bad).is_err());
            assert!(export_name_data(bad).is_err());
        }
    }
    #[test]
    fn returned_effects_enforce_order_same_endpoint_one_inverse_and_absorbing_unknown() {
        use ReturnedData::*; use StepData::*;
        let mut update = ProgressData::new_data(ActionData::Update, 1, 100).unwrap();
        for step in [Reobserved, Prepared, RuntimePublished, MetadataPublished, OldAppQuarantined] {
            update.forward_return_data(step, KnownSuccess, 20).unwrap();
        }
        assert!(update.forward_return_data(AppPublished, KnownRefusal, 30).is_err());
        update.begin_inverse_data(31, true, true).unwrap();
        for step in [OldAppRestored, StateRestored, OriginalsSettled] { update.inverse_return_data(step, KnownSuccess, 40).unwrap(); }
        assert_eq!(update.outcome_data(), ProgressOutcomeData::InverseRecorded);
        assert!(update.begin_inverse_data(41, true, true).is_err());
        // Rejected admission performed no new effect; the recorded inverse
        // remains historical DATA. Actual later returns are different.
        assert_eq!(update.outcome_data(), ProgressOutcomeData::InverseRecorded);
        for (forward, late) in [(false,false),(true,false),(false,true),(true,true)] {
            let mut value = ProgressData::new_data(ActionData::Update, 1, 100).unwrap();
            for step in [Reobserved, Prepared, RuntimePublished, MetadataPublished, OldAppQuarantined] {
                value.forward_return_data(step, KnownSuccess, 20).unwrap();
            }
            assert!(value.forward_return_data(AppPublished, KnownRefusal, 30).is_err());
            value.begin_inverse_data(31, true, true).unwrap();
            for step in [OldAppRestored, StateRestored, OriginalsSettled] { value.inverse_return_data(step, KnownSuccess, 40).unwrap(); }
            let returned = if forward { value.forward_return_data(Reobserved, KnownSuccess, if late { 100 } else { 41 }) }
                else { value.inverse_return_data(OldAppRestored, KnownSuccess, if late { 100 } else { 41 }) };
            assert!(returned.is_err()); assert!(value.inverse_complete);
            assert_eq!(value.outcome_data(), ProgressOutcomeData::Refused);
        }
        let mut unknown = ProgressData::new_data(ActionData::FreshInstall, 1, 100).unwrap();
        assert!(unknown.forward_return_data(Prepared, Unknown, 20).is_err());
        assert!(unknown.forward_return_data(Prepared, KnownSuccess, 21).is_err());
        assert!(unknown.begin_inverse_data(22, true, true).is_err());
        assert_eq!(unknown.outcome_data(), ProgressOutcomeData::Unknown);
        let mut late = ProgressData::new_data(ActionData::SamePackageNoop, 1, 100).unwrap();
        late.forward_return_data(Reobserved, KnownSuccess, 10).unwrap(); late.forward_return_data(StatePublished, KnownSuccess, 20).unwrap();
        assert!(late.forward_return_data(OriginalsSettled, KnownSuccess, 100).is_err());
        assert_eq!(late.outcome_data(), ProgressOutcomeData::Refused);
        let mut order = ProgressData::new_data(ActionData::Update, 1, 100).unwrap();
        assert!(order.forward_return_data(AppPublished, KnownSuccess, 10).is_err());
        assert!(order.forward_return_data(Reobserved, KnownSuccess, 11).is_err());
        assert_eq!(order.outcome_data(), ProgressOutcomeData::Refused);
        // Refused inverse admission is not a permit; late known forward effects
        // cannot gain a new window by supplying an earlier comparison timestamp.
        for mode in ["unowned", "late", "wrong-name", "late-monotonic"] {
            let mut value = ProgressData::new_data(ActionData::Update, 1, 100).unwrap();
            for step in [Reobserved, Prepared, RuntimePublished, MetadataPublished] {
                value.forward_return_data(step, KnownSuccess, 20).unwrap();
            }
            if mode == "late" || mode == "late-monotonic" {
                assert!(value.forward_return_data(OldAppQuarantined, KnownSuccess, 100).is_err());
                assert!(value.expired); assert_eq!(value.end, 100);
            } else {
                value.forward_return_data(OldAppQuarantined, KnownSuccess, 20).unwrap();
                assert!(value.forward_return_data(AppPublished, KnownRefusal, 30).is_err());
            }
            let (begin_at, returned_at) = if mode == "late-monotonic" { (101, 102) } else { (31, 40) };
            assert!(value.begin_inverse_data(begin_at, mode != "unowned", mode != "wrong-name").is_err());
            // Admission alone reports no new effect. Its refusal preserves the
            // known quarantine, including a late return, without inverse authority.
            assert_eq!(value.outcome_data(), ProgressOutcomeData::Refused);
            assert!(value.old_quarantined); assert!(!value.inverse_admitted);
            assert!(value.inverse_return_data(OldAppRestored, KnownSuccess, returned_at).is_err());
            // Only the backwards returned observation (40 after 100) makes the
            // effect account Unknown; monotonic expired returns remain Refused.
            assert_eq!(value.outcome_data(), if mode == "late" { ProgressOutcomeData::Unknown }
                else { ProgressOutcomeData::Refused });
            assert!(value.old_quarantined); assert!(!value.inverse_complete);
            if mode == "late" {
                assert!(value.forward_return_data(Reobserved, KnownSuccess, 101).is_err());
                assert_eq!(value.outcome_data(), ProgressOutcomeData::Unknown);
            }
        }
        assert!(late.begin_inverse_data(21, true, true).is_err());
        assert_ne!(late.outcome_data(), ProgressOutcomeData::InverseRecorded);
        let mut bad_inverse = ProgressData::new_data(ActionData::Update, 1, 100).unwrap();
        for step in [Reobserved, Prepared, RuntimePublished, MetadataPublished, OldAppQuarantined] {
            bad_inverse.forward_return_data(step, KnownSuccess, 20).unwrap();
        }
        assert!(bad_inverse.forward_return_data(AppPublished, KnownRefusal, 30).is_err());
        bad_inverse.begin_inverse_data(31, true, true).unwrap();
        assert!(bad_inverse.inverse_return_data(StateRestored, KnownSuccess, 35).is_err());
        assert!(bad_inverse.inverse_return_data(OldAppRestored, KnownSuccess, 40).is_err());
        assert_eq!(bad_inverse.outcome_data(), ProgressOutcomeData::Refused);
        assert!(bad_inverse.inverse_return_data(OldAppRestored, Unknown, 41).is_err());
        assert_eq!(bad_inverse.outcome_data(), ProgressOutcomeData::Unknown);
        for after_state in [false, true] {
            let mut value = ProgressData::new_data(ActionData::Update, 1, 100).unwrap();
            for step in [Reobserved, Prepared, RuntimePublished, MetadataPublished, OldAppQuarantined, AppPublished] {
                value.forward_return_data(step, KnownSuccess, 20).unwrap();
            }
            if after_state {
                value.forward_return_data(StatePublished, KnownSuccess, 25).unwrap();
                assert!(value.forward_return_data(OriginalsSettled, KnownRefusal, 30).is_err());
                assert!(value.begin_inverse_data(31, true, true).is_err());
                assert_eq!(value.outcome_data(), ProgressOutcomeData::Refused);
            } else {
                assert!(value.forward_return_data(StatePublished, KnownRefusal, 30).is_err());
                value.begin_inverse_data(31, true, true).unwrap();
                for step in [NewAppWithdrawn, OldAppRestored, StateRestored, OriginalsSettled] {
                    value.inverse_return_data(step, KnownSuccess, 40).unwrap();
                }
                assert_eq!(value.outcome_data(), ProgressOutcomeData::InverseRecorded);
            }
        }
        // A real POST/fsync failure follows a positively returned mutation. It
        // must latch failure without inventing a duplicate publication, and a
        // failed inverse POST must never retain a positive current outcome.
        for (after_inverse, refusal) in [(false,KnownRefusal),(true,KnownRefusal),(false,Unknown),(true,Unknown)] {
            let mut value = ProgressData::new_data(ActionData::Update,1,100).unwrap();
            for step in [Reobserved,Prepared,RuntimePublished,MetadataPublished,OldAppQuarantined] {
                value.forward_return_data(step,KnownSuccess,20).unwrap();
            }
            assert!(value.stop_data(KnownSuccess,21).is_err());
            assert_eq!(value.outcome_data(),ProgressOutcomeData::InProgress);
            assert!(value.stop_data(KnownRefusal,22).is_err());
            assert!(value.old_quarantined && !value.sequence_invalid);
            value.begin_inverse_data(23,true,true).unwrap();
            value.inverse_return_data(OldAppRestored,KnownSuccess,24).unwrap();
            if after_inverse {
                value.inverse_return_data(StateRestored,KnownSuccess,25).unwrap();
                value.inverse_return_data(OriginalsSettled,KnownSuccess,26).unwrap();
                assert_eq!(value.outcome_data(),ProgressOutcomeData::InverseRecorded);
            }
            assert!(value.stop_data(refusal,27).is_err());
            assert!(value.old_quarantined && value.sequence_invalid && !value.inverse_admitted);
            assert_eq!(value.inverse_complete,after_inverse);
            assert_eq!(value.outcome_data(),if refusal == Unknown { ProgressOutcomeData::Unknown } else { ProgressOutcomeData::Refused });
            assert!(value.inverse_return_data(StateRestored,KnownSuccess,28).is_err());
            assert_ne!(value.outcome_data(),ProgressOutcomeData::InverseRecorded);
        }
    }
    #[test]
    fn retained_storage_and_original_budget_arithmetic_refuse_before_effects() {
        let one = GenerationCostData { files: 10, bytes: 1024 };
        let admitted = BudgetData::checked_data(&[one, one], 2, 4096, 4096, 100, 12).unwrap();
        assert_eq!(admitted.payload_totals_data(), (20, 2048));
        let record_and_result = (INTENT_LIMIT + STATE_LIMIT + CAPSULE_LIMIT + REQUEST_EXPORT_LIMIT) as u64;
        let payload = GenerationCostData { files:1, bytes:PAYLOAD_LIMIT-record_and_result-PRODUCER_CONTROL_LIMIT as u64 };
        assert!(BudgetData::checked_data(&[payload],1,record_and_result,0,2,2).is_ok());
        let too_large = GenerationCostData { files:1, bytes:payload.bytes+1 };
        assert!(BudgetData::checked_data(&[too_large],1,record_and_result,0,2,2).is_err());
        assert!(BudgetData::checked_data(&[one],1,record_and_result+1,0,2,2).is_err());
        // Signed control bytes cannot evade the aggregate merely by living
        // outside versions/<release>. The payload-only accessor stays truthful.
        let nine = PREDECESSOR_LIMIT + 1;
        let remaining = PAYLOAD_LIMIT-record_and_result-(nine as u64)*PRODUCER_CONTROL_LIMIT as u64;
        let mut costs = vec![GenerationCostData { files:1, bytes:0 }; nine];
        costs[0].bytes = remaining;
        assert_eq!(BudgetData::checked_data(&costs,1,record_and_result,0,24576,96).unwrap().payload_totals_data(),
            (nine as u64, remaining));
        costs[0].bytes += 1;
        assert!(BudgetData::checked_data(&costs,1,record_and_result,0,24576,96).is_err());
        for (count, evidence, control, records, fds) in [(0,0,0,0,0),(INVOCATION_LIMIT+1,0,0,0,0),
            (1,u64::MAX,0,0,0),(1,0,16*1024*1024+1,0,0),(1,0,0,24577,0),(1,0,0,0,97)] {
            assert!(BudgetData::checked_data(&[one], count, evidence, control, records, fds).is_err());
        }
        assert!(BudgetData::checked_data(&[one; PREDECESSOR_LIMIT+2], 1, 0, 0, 0, 0).is_err());
        assert!(BudgetData::checked_data(&[GenerationCostData { files: 1, bytes: PAYLOAD_LIMIT }, one], 1,0,0,0,0).is_err());
        assert!(BudgetData::checked_data(&[GenerationCostData { files: u64::MAX, bytes: 0 }], 1,0,0,0,0).is_err());
        assert!(BudgetData::checked_data(&[], 1,0,0,0,0).is_err());
    }
}
