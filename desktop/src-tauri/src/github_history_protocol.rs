//! Closed readonly History DATA. Neither a frame nor a digest grants source,
//! process, credential, attestation or Store authority.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use crate::{error::BridgeError, github_connection_protocol::{bounds, nullable, numeric_id},
    protocol::{strict_json, valid_id}};

// Finite typed projection envelope; the containing native debit reserves
// eight simultaneous wire/typed/receipt/status copies, not unbounded JSON.
pub(crate) const RETAINED_REPLY_LIMIT:usize=64*1024;
pub(crate) const WIRE_COPY_RESERVE:usize=8*RETAINED_REPLY_LIMIT;
pub(crate) const PROTOCOL: &str = "mrk-github-history/1";
pub(crate) const EVENT: &str = "github-history-status";
pub(crate) const TOOLING: &str = "Apdelrahman1911/mobile-release-kit";
pub(crate) const ASSURANCE: &str = "authenticated-retained-workflow-evidence-not-current-store-state";
pub(crate) const INITIAL_LIMIT: usize = 16 * 1024;
pub(crate) const GO_LIMIT: usize = 8 * 1024;
pub(crate) const READY_LIMIT: usize = 512;
pub(crate) const TERMINAL_LIMIT: usize = 32 * 1024;
pub(crate) const RESULT_LIMIT: usize = 16 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 64 * 1024;
pub(crate) const LAST_REVISION: u32 = u32::MAX - 1;
pub(crate) const CONFIG_LIMIT: u64 = 512 * 1024;
pub(crate) const PROVIDER_LIMIT: u64 = 128 * 1024 * 1024;

pub(crate) fn hex(value: &str, size: usize) -> bool {
    value.len() == size && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.chars().take(maximum + 1).count() <= maximum && !value.chars().any(char::is_control)
}
fn coordinate(value: &str) -> bool {
    let Some((owner, repo)) = value.split_once('/') else { return false; };
    text(value, 255) && !owner.is_empty() && !repo.is_empty()
        && owner.bytes().chain(repo.bytes()).all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
fn utc(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !value.is_ascii() || bytes.len() < 20 || bytes.len() > 27 || bytes.last() != Some(&b'Z') { return false; }
    if bytes.len() > 20 && (bytes[19] != b'.' || bytes.len() < 22 || !bytes[20..bytes.len()-1].iter().all(u8::is_ascii_digit)) { return false; }
    let mut whole = [0u8; 20]; whole[..19].copy_from_slice(&bytes[..19]); whole[19] = b'Z';
    std::str::from_utf8(&whole).is_ok_and(crate::github_connection_protocol::utc)
}
fn revision(value: u32) -> bool { (1..=LAST_REVISION).contains(&value) }
fn decimal(value: &str, positive: bool) -> bool {
    !value.is_empty() && value.len() <= 20 && value.bytes().all(|b| b.is_ascii_digit())
        && (value == "0" && !positive || !value.starts_with('0')) && value.parse::<u64>().is_ok()
}
fn signed(value: &str) -> bool { value.parse::<i64>().is_ok_and(|n| n.to_string() == value) }
fn absolute(value: &str) -> bool {
    value.starts_with('/') && value.len() <= 4096 && text(value,4096)
        && (value == "/" || value[1..].split('/').all(|p| !p.is_empty() && p != "." && p != ".."))
}
// This grammar has no sequence-valued field at any depth. Requiring map/scalar
// nodes before serde prevents named-struct positional-array aliases. This is
// only the closed History wire; it does not alter any shared JSON decoder.
fn nodes(value: &Value) -> bool { match value {
    Value::Array(_) => false,
    Value::Object(map) => map.iter().all(|(key, val)| !key.chars().any(char::is_control) && nodes(val)),
    Value::String(s) => !s.chars().any(char::is_control), _ => true,
} }
fn wire(value: &Value, bytes: usize, count: usize, depth: usize) -> bool {
    value.is_object() && bounds(value, bytes, count, depth) && nodes(value)
}
fn fits<T: Serialize>(value: &T, bytes: usize) -> bool {
    serde_json::to_value(value).ok().is_some_and(|v| wire(&v, bytes, 4096, 16))
}
fn frame(raw: &[u8], limit: usize) -> Result<Value, BridgeError> {
    if raw.len() < 3 || raw.len() > limit || raw.last() != Some(&b'\n') { return Err(BridgeError::protocol()); }
    let body = &raw[..raw.len()-1];
    if body.first() != Some(&b'{') || body.last() != Some(&b'}') || body.iter().any(|b| matches!(b,b'\r'|b'\n')) {
        return Err(BridgeError::protocol());
    }
    let value = strict_json(body)?;
    if !wire(&value, limit - 1, 4096, 16) { return Err(BridgeError::protocol()); }
    Ok(value)
}
fn encode<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, BridgeError> {
    if !fits(value, limit - 1) { return Err(BridgeError::invalid()); }
    let mut raw = serde_json::to_vec(value).map_err(|_| BridgeError::invalid())?; raw.push(b'\n'); Ok(raw)
}
fn strings(values: &[&String]) -> Option<usize> {
    values.iter().try_fold(0usize, |n, s| n.checked_add(s.capacity()))
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None, Unqualified, NotConnected, Busy, InvalidInput, TargetChanged, ConfigInvalid, PlatformDisabled,
    PublisherUnconfigured, UnsupportedTooling, ProviderUnavailable, ProviderMismatch, RuntimeUnavailable,
    ResourcesUnavailable, Unauthorized, Forbidden, NotFoundOrInaccessible, RateLimited, NetworkUnavailable,
    TlsFailed, ResponseInvalid, ResponseLimit, ArtifactMissing, ArtifactExpired, EvidenceInvalid,
    AttestationNotConfirmed, ProducerPending, Cancelled, Expired, CleanupUnknown,
}
impl Reason {
    fn unavailable(self) -> bool { matches!(self, Self::Unqualified | Self::PublisherUnconfigured | Self::UnsupportedTooling
        | Self::ProviderUnavailable | Self::RuntimeUnavailable | Self::ResourcesUnavailable | Self::Unauthorized | Self::Forbidden
        | Self::NotFoundOrInaccessible | Self::RateLimited | Self::NetworkUnavailable | Self::TlsFailed | Self::ArtifactMissing
        | Self::ArtifactExpired | Self::ProducerPending) }
    fn refused(self) -> bool { matches!(self, Self::InvalidInput | Self::TargetChanged | Self::ConfigInvalid | Self::PlatformDisabled
        | Self::ProviderMismatch | Self::ResponseInvalid | Self::ResponseLimit | Self::EvidenceInvalid | Self::AttestationNotConfirmed) }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Stage { Candidate, ExternalTesting, ProductionSubmit }
impl Stage {
    pub(crate) fn name(self) -> &'static str { match self { Self::Candidate => "candidate", Self::ExternalTesting => "external-testing", Self::ProductionSubmit => "production-submit" } }
    fn artifact_name(self) -> &'static str { match self { Self::Candidate => "candidate", Self::ExternalTesting => "external", Self::ProductionSubmit => "production" } }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Platform { Android, Ios }
impl Platform { fn name(self) -> &'static str { match self { Self::Android => "android", Self::Ios => "ios" } } }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Selection { pub(crate) run_id: String, pub(crate) attempt: u32, pub(crate) stage: Stage, pub(crate) platform: Platform }
impl Selection {
    pub(crate) fn valid(&self) -> bool { numeric_id(&self.run_id) && (1..=100).contains(&self.attempt) }
    pub(crate) fn retained_heap_bytes(&self) -> usize { self.run_id.capacity() }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) schema_version: u32, pub(crate) project_binding: String, pub(crate) config_sha256: String,
    pub(crate) repository: String, pub(crate) repository_id: String, pub(crate) account_id: String,
    pub(crate) tooling_repository: String, pub(crate) tooling_sha: String, pub(crate) selection: Selection,
}
impl Context {
    pub(crate) fn valid(&self) -> bool { self.schema_version == 1 && hex(&self.project_binding,64) && hex(&self.config_sha256,64)
        && coordinate(&self.repository) && numeric_id(&self.repository_id) && numeric_id(&self.account_id)
        && self.tooling_repository == TOOLING && hex(&self.tooling_sha,40) && self.selection.valid() }
    pub(crate) fn retained_heap_bytes(&self) -> Option<usize> {
        strings(&[&self.project_binding,&self.config_sha256,&self.repository,&self.repository_id,&self.account_id,
            &self.tooling_repository,&self.tooling_sha])?.checked_add(self.selection.retained_heap_bytes())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Authority {
    workflow: String, caller_path: String, reusable_repository: String, reusable_path: String, reusable_commit: String,
    run_id: String, attempt: u32, head_sha: String, #[serde(rename = "ref")] reference: String, event: String,
}
impl Authority {
    fn valid(&self, context: &Context) -> bool { text(&self.workflow,255)
        && self.caller_path == format!(".github/workflows/mobile-{}.yml",context.selection.stage.name())
        && self.reusable_path == format!(".github/workflows/reusable-{}.yml",context.selection.stage.name())
        && self.reusable_repository == context.tooling_repository && self.reusable_commit == context.tooling_sha
        && numeric_id(&self.run_id) && (1..=100).contains(&self.attempt) && hex(&self.head_sha,40)
        && text(&self.reference,512) && self.reference.starts_with("refs/heads/") && self.reference.len() > 11
        && self.event == "workflow_dispatch" }
    fn retained_heap_bytes(&self) -> Option<usize> { strings(&[&self.workflow,&self.caller_path,&self.reusable_repository,
        &self.reusable_path,&self.reusable_commit,&self.run_id,&self.head_sha,&self.reference,&self.event]) }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Source { commit: String, tree: String }
impl Source { fn valid(&self) -> bool { hex(&self.commit,40) && hex(&self.tree,40) }
    fn retained_heap_bytes(&self) -> Option<usize> { strings(&[&self.commit,&self.tree]) } }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Version { name: String, build: u32 }
impl Version {
    fn valid(&self, platform: Platform) -> bool {
        if !text(&self.name,64) || !(1..=2100000000).contains(&self.build) { return false; }
        let (base,suffix) = match self.name.find(['-','+']) { Some(i) => (&self.name[..i],Some(&self.name[i+1..])), None => (self.name.as_str(),None) };
        if let Some(suffix) = suffix { if platform == Platform::Ios || suffix.is_empty()
            || !suffix.bytes().all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b)) { return false; } }
        let mut count=0usize;
        for part in base.split('.') { count+=1; if part.is_empty() || !part.bytes().all(|b|b.is_ascii_digit()) { return false; } }
        count>=2 && count<=if platform==Platform::Ios {3} else {4}
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Outcome { Mutated, Reconciled, AlreadyPresent, OperatorAuthorizedReconciliation, OperatorAuthorizedRetry, OperatorAuthorizedCreateRetry }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Evidence {
    artifact_id: String, artifact_sha256: String, artifact_name: String, producer_job_id: String,
    produced_by: Authority, authorized_by: Authority, candidate_source: Source, operation_source: Source,
    version: Version, application_id: String, outcome: Outcome, candidate_manifest_sha256: String,
    operation_intent_sha256: String, receipt_sha256: String, provenance_sha256: String,
}
impl Evidence {
    fn valid(&self,c:&Context)->bool {
        numeric_id(&self.artifact_id) && numeric_id(&self.producer_job_id)
            && self.artifact_name == format!("mobile-release-{}-evidence-{}",c.selection.stage.artifact_name(),c.selection.platform.name())
            && self.produced_by.valid(c) && self.authorized_by.valid(c)
            && self.produced_by.run_id == c.selection.run_id && self.produced_by.attempt == c.selection.attempt
            && self.candidate_source.valid() && self.operation_source.valid() && self.version.valid(c.selection.platform)
            && text(&self.application_id,255) && [&self.artifact_sha256,&self.candidate_manifest_sha256,
                &self.operation_intent_sha256,&self.receipt_sha256,&self.provenance_sha256].iter().all(|v|hex(v,64))
    }
    fn retained_heap_bytes(&self)->Option<usize> {
        strings(&[&self.artifact_id,&self.artifact_sha256,&self.artifact_name,&self.producer_job_id,&self.version.name,
            &self.application_id,&self.candidate_manifest_sha256,&self.operation_intent_sha256,&self.receipt_sha256,&self.provenance_sha256])?
            .checked_add(self.produced_by.retained_heap_bytes()?)?.checked_add(self.authorized_by.retained_heap_bytes()?)?
            .checked_add(self.candidate_source.retained_heap_bytes()?)?.checked_add(self.operation_source.retained_heap_bytes()?)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Verification { Verified, Unavailable, Refused }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResultData {
    schema_version: u32, pub(crate) context: Context, observed_at: String, verification: Verification,
    reason: Reason, #[serde(deserialize_with="nullable")] evidence: Option<Evidence>, assurance: String,
}
impl ResultData {
    pub(crate) fn valid(&self)->bool { self.schema_version==1 && self.context.valid() && utc(&self.observed_at) && self.assurance==ASSURANCE
        && match (self.verification,&self.evidence) {
            (Verification::Verified,Some(e))=>self.reason==Reason::None && e.valid(&self.context),
            (Verification::Unavailable,None)=>self.reason.unavailable(), (Verification::Refused,None)=>self.reason.refused(), _=>false,
        } && fits(self,RESULT_LIMIT) }
    pub(crate) fn retained_heap_bytes(&self)->Option<usize> { self.context.retained_heap_bytes()?
        .checked_add(strings(&[&self.observed_at,&self.assurance])?)?
        .checked_add(self.evidence.as_ref().map_or(Some(0),Evidence::retained_heap_bytes)?) }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase { Running, Stopping, Settled, CleanupUnknown }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Operation { pub(crate) id: String, pub(crate) phase: Phase, pub(crate) reason: Reason, pub(crate) selection: Selection }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Status {
    pub(crate) schema_version: u32, pub(crate) revision: u32, #[serde(deserialize_with="nullable")] pub(crate) session_id: Option<String>,
    pub(crate) available: bool, pub(crate) reason: Reason, #[serde(deserialize_with="nullable")] pub(crate) operation: Option<Operation>,
    #[serde(deserialize_with="nullable")] pub(crate) result: Option<ResultData>,
}
impl Status {
    pub(crate) fn fits_wire(&self)->bool {
        if self.schema_version!=1 || !revision(self.revision) || self.session_id.as_ref().is_some_and(|id|!valid_id(id))
            || self.available!=(self.reason==Reason::None) { return false; }
        if let Some(op)=&self.operation {
            if !valid_id(&op.id) || !op.selection.valid() || self.session_id.is_none() { return false; }
            if op.phase!=Phase::Settled {
                let expected=match op.phase {Phase::Running=>Reason::None,Phase::Stopping=>Reason::Cancelled,_=>Reason::CleanupUnknown};
                if op.reason!=expected || self.available || self.result.is_some()
                    || op.phase==Phase::CleanupUnknown && self.reason!=Reason::CleanupUnknown { return false; }
            } else if matches!(op.reason,Reason::Busy|Reason::CleanupUnknown) { return false; }
        }
        if self.available && (self.session_id.is_none() || self.operation.as_ref().is_some_and(|op|op.phase!=Phase::Settled)) { return false; }
        if let Some(result)=&self.result { if !result.valid() || !self.operation.as_ref().is_some_and(|op|
            op.phase==Phase::Settled && op.reason==Reason::None && op.selection==result.context.selection) { return false; } }
        self.retained_heap_bytes().and_then(|n|n.checked_add(std::mem::size_of::<Self>())).is_some_and(|n|n<=RETAINED_REPLY_LIMIT)
            && fits(self,RESPONSE_LIMIT)
    }
    pub(crate) fn retained_heap_bytes(&self)->Option<usize> {
        let mut bytes=self.session_id.as_ref().map_or(0,String::capacity);
        if let Some(op)=&self.operation { bytes=bytes.checked_add(op.id.capacity())?.checked_add(op.selection.retained_heap_bytes())?; }
        bytes.checked_add(self.result.as_ref().map_or(Some(0),ResultData::retained_heap_bytes)?)
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct StartArgs { pub(crate) session_id: String, pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32, pub(crate) selection: Selection }
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct CancelArgs { pub(crate) operation_id: String }
pub(crate) enum Command { Status, Start(StartArgs), Cancel(CancelArgs) }
pub(crate) fn decode_command(name:&str,value:&Value)->Result<Command,BridgeError> {
    if !wire(value,4096,64,4) { return Err(BridgeError::invalid()); }
    match name {
        "github_history_status" if value.as_object().is_some_and(|v|v.is_empty())=>Ok(Command::Status),
        "github_history_start"=> {
            let args=StartArgs::deserialize(value).map_err(|_|BridgeError::invalid())?;
            if !valid_id(&args.session_id) || !revision(args.expected_revision) || !revision(args.expected_connection_revision) || !args.selection.valid() {
                return Err(BridgeError::invalid()); }
            Ok(Command::Start(args))
        },
        "github_history_cancel"=> {
            let args=CancelArgs::deserialize(value).map_err(|_|BridgeError::invalid())?;
            if !valid_id(&args.operation_id) { return Err(BridgeError::invalid()); } Ok(Command::Cancel(args))
        }, _=>Err(BridgeError::invalid()),
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectoryIdentity { pub(crate) device:String,pub(crate) inode:String,pub(crate) mode:u32,pub(crate) uid:u32,pub(crate) gid:u32 }
impl DirectoryIdentity {
    pub(crate) fn valid(&self)->bool { decimal(&self.device,true)&&decimal(&self.inode,true)&&self.mode&0o170000==0o040000 }
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{strings(&[&self.device,&self.inode])}
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct FileIdentity {
    pub(crate) device:String,pub(crate) inode:String,pub(crate) mode:u32,pub(crate) uid:u32,pub(crate) gid:u32,
    pub(crate) nlink:String,pub(crate) bytes:String,pub(crate) mtime_seconds:String,pub(crate) ctime_seconds:String,
    pub(crate) mtime_nanos:u32,pub(crate) ctime_nanos:u32,pub(crate) flags:u32,
}
impl FileIdentity {
    pub(crate) fn valid(&self,maximum:u64,nonempty:bool)->bool { decimal(&self.device,true)&&decimal(&self.inode,true)
        && self.mode&0o170000==0o100000 && self.nlink=="1" && decimal(&self.bytes,nonempty)
        && self.bytes.parse::<u64>().is_ok_and(|n|n<=maximum) && signed(&self.mtime_seconds)&&signed(&self.ctime_seconds)
        && self.mtime_nanos<1_000_000_000 && self.ctime_nanos<1_000_000_000 }
    pub(crate) fn retained_heap_bytes(&self)->Option<usize> { strings(&[&self.device,&self.inode,&self.nlink,&self.bytes,&self.mtime_seconds,&self.ctime_seconds]) }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) enum NativeProfile { #[serde(rename="macos-arm64")] Arm64,#[serde(rename="macos-x86_64")] X86_64 }
impl NativeProfile { pub(crate) fn target(self)->&'static str { match self {Self::Arm64=>"aarch64-apple-darwin",Self::X86_64=>"x86_64-apple-darwin"} } }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Provider { pub(crate) relative_path:String,pub(crate) version:String,pub(crate) target:String,
    pub(crate) source_manifest_sha256:String,pub(crate) sha256:String,pub(crate) identity:FileIdentity }
impl Provider {
    pub(crate) fn valid(&self,profile:NativeProfile)->bool {self.relative_path=="tools/gh"&&self.version=="2.88.1"
        &&self.target==profile.target()&&hex(&self.source_manifest_sha256,64)&&hex(&self.sha256,64)&&self.identity.valid(PROVIDER_LIMIT,true)}
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{strings(&[&self.relative_path,&self.version,&self.target,&self.source_manifest_sha256,&self.sha256])?
        .checked_add(self.identity.retained_heap_bytes()?)}
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Clock { pub(crate) name:String,pub(crate) work_end_ns:String,pub(crate) hard_end_ns:String }
impl Clock {
    pub(crate) fn valid(&self)->bool {self.name=="CLOCK_UPTIME_RAW"&&decimal(&self.work_end_ns,true)&&decimal(&self.hard_end_ns,true)
        &&self.work_end_ns.parse::<u64>().ok().zip(self.hard_end_ns.parse::<u64>().ok()).is_some_and(|(w,h)|h>=w&&h-w<=10_000_000_000)}
    fn retained_heap_bytes(&self)->Option<usize>{strings(&[&self.name,&self.work_end_ns,&self.hard_end_ns])}
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Native {
    pub(crate) profile:NativeProfile,pub(crate) project_root:String,pub(crate) root_identity:DirectoryIdentity,
    pub(crate) config_identity:FileIdentity,pub(crate) work_root:String,pub(crate) work_identity:DirectoryIdentity,
    pub(crate) provider:Provider,pub(crate) parent_descriptor_reservation:u32,pub(crate) clock:Clock,
}
impl Native {
    fn valid(&self)->bool { absolute(&self.project_root)&&absolute(&self.work_root)&&self.root_identity.valid()&&self.work_identity.valid()
        && self.work_identity.mode&0o7777==0o700 && self.config_identity.valid(CONFIG_LIMIT,false)&&self.provider.valid(self.profile)
        &&self.parent_descriptor_reservation<=56&&self.clock.valid() }
    fn retained_heap_bytes(&self)->Option<usize>{strings(&[&self.project_root,&self.work_root])?.checked_add(self.root_identity.retained_heap_bytes()?)?
        .checked_add(self.config_identity.retained_heap_bytes()?)?.checked_add(self.work_identity.retained_heap_bytes()?)?
        .checked_add(self.provider.retained_heap_bytes()?)?.checked_add(self.clock.retained_heap_bytes()?)}
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase")]
pub(crate) struct Initial { pub(crate) protocol:String,pub(crate) id:String,pub(crate) owner_generation:String,pub(crate) context:Context,pub(crate) native:Native }
impl Initial {
    pub(crate) fn encode(&self)->Result<Vec<u8>,BridgeError>{
        if self.protocol!=PROTOCOL||!valid_id(&self.id)||!valid_id(&self.owner_generation)||!self.context.valid()||!self.native.valid(){return Err(BridgeError::invalid());}
        encode(self,INITIAL_LIMIT)
    }
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{strings(&[&self.protocol,&self.id,&self.owner_generation])?
        .checked_add(self.context.retained_heap_bytes()?)?.checked_add(self.native.retained_heap_bytes()?)}
}
pub(crate) fn request_digest(raw:&[u8])->String {format!("{:x}",Sha256::digest(raw))}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Ready {request_sha256:String}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyFrame {protocol:String,id:String,ready:Ready}
pub(crate) fn decode_ready(raw:&[u8],id:&str,digest:&str)->Result<(),BridgeError>{
    let value:ReadyFrame=serde_json::from_value(frame(raw,READY_LIMIT)?).map_err(|_|BridgeError::protocol())?;
    if value.protocol!=PROTOCOL||value.id!=id||value.ready.request_sha256!=digest||!valid_id(id)||!hex(digest,64){return Err(BridgeError::protocol());}Ok(())
}
pub(crate) fn encode_go(id:&str,digest:&str,token:&str)->Result<Vec<u8>,BridgeError>{
    if !valid_id(id)||!hex(digest,64)||token.is_empty()||token.len()>4096||!token.bytes().all(|b|(0x21..=0x7e).contains(&b)){return Err(BridgeError::invalid());}
    // Borrow token once into the bounded original writer; no token Value/Debug.
    let mut raw=Vec::with_capacity(GO_LIMIT);
    raw.extend_from_slice(b"{\"protocol\":\"mrk-github-history/1\",\"id\":");
    serde_json::to_writer(&mut raw,id).map_err(|_|BridgeError::invalid())?;
    raw.extend_from_slice(b",\"go\":{\"requestSha256\":");
    serde_json::to_writer(&mut raw,digest).map_err(|_|BridgeError::invalid())?;
    raw.extend_from_slice(b",\"token\":");serde_json::to_writer(&mut raw,token).map_err(|_|BridgeError::invalid())?;
    raw.extend_from_slice(b"}}\n");if raw.len()>GO_LIMIT{return Err(BridgeError::invalid());}Ok(raw)
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Lifetime {
    pub(crate) complete:bool,pub(crate) fatal:bool,pub(crate) contained:bool,
    #[serde(deserialize_with="nullable")] pub(crate) command_dispatched:Option<bool>,
    pub(crate) commands:u32,pub(crate) verifier_calls:u32,pub(crate) input_closed:bool,
    pub(crate) handlers_restored:bool,pub(crate) invocation_closed:bool,pub(crate) stop_observed:bool,
}
impl Lifetime {
    fn valid(&self)->bool{self.commands<=128&&self.verifier_calls<=19&&self.verifier_calls<=self.commands
        &&(!matches!(self.command_dispatched,Some(true))||self.commands>=1)}
    pub(crate) fn originals_settled(&self)->bool{self.valid()&&!self.fatal&&self.contained&&self.command_dispatched.is_some()
        &&self.input_closed&&self.handlers_restored&&self.invocation_closed}
    pub(crate) fn complete(&self)->bool{self.originals_settled()&&self.complete&&!self.stop_observed}
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Reply {protocol:String,id:String,request_sha256:String,
    #[serde(deserialize_with="nullable")] pub(crate) result:Option<ResultData>,pub(crate) reason:Reason,pub(crate) lifetime:Lifetime}
pub(crate) fn decode_reply(raw:&[u8],initial:&Initial,digest:&str)->Result<Reply,BridgeError>{
    let reply:Reply=serde_json::from_value(frame(raw,TERMINAL_LIMIT)?).map_err(|_|BridgeError::protocol())?;
    if reply.protocol!=PROTOCOL||reply.id!=initial.id||reply.request_sha256!=digest||!hex(digest,64)||!reply.lifetime.valid(){return Err(BridgeError::protocol());}
    if let Some(result)=&reply.result {
        if reply.reason!=Reason::None||!reply.lifetime.complete()||!result.valid()||result.context!=initial.context{return Err(BridgeError::protocol());}
    }else if matches!(reply.reason,Reason::None|Reason::Busy|Reason::NotConnected){return Err(BridgeError::protocol());}
    if reply.retained_heap_bytes().and_then(|n|n.checked_add(std::mem::size_of::<Reply>())).is_none_or(|n|n>RETAINED_REPLY_LIMIT){
        return Err(BridgeError::new("history_resources_unavailable","The finite History reply storage was exceeded."));
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn context()->Context{Context{schema_version:1,project_binding:"a".repeat(64),config_sha256:"b".repeat(64),
        repository:"owner/repository".into(),repository_id:"1".into(),account_id:"2".into(),tooling_repository:TOOLING.into(),
        tooling_sha:"c".repeat(40),selection:Selection{run_id:"3".into(),attempt:1,stage:Stage::ExternalTesting,platform:Platform::Android}}}
    fn identity()->FileIdentity{FileIdentity{device:"1".into(),inode:"2".into(),mode:0o100644,uid:501,gid:20,nlink:"1".into(),
        bytes:"1".into(),mtime_seconds:"0".into(),ctime_seconds:"-1".into(),mtime_nanos:0,ctime_nanos:999999999,flags:0}}
    fn initial()->Initial{Initial{protocol:PROTOCOL.into(),id:"history-1".into(),owner_generation:"generation-1".into(),context:context(),
        native:Native{profile:NativeProfile::Arm64,project_root:"/Users/example/project".into(),
            root_identity:DirectoryIdentity{device:"1".into(),inode:"3".into(),mode:0o40755,uid:501,gid:20},config_identity:identity(),
            work_root:"/private/tmp/mrk-history-00000000000000000000000000000000".into(),
            work_identity:DirectoryIdentity{device:"1".into(),inode:"4".into(),mode:0o40700,uid:501,gid:20},
            provider:Provider{relative_path:"tools/gh".into(),version:"2.88.1".into(),target:NativeProfile::Arm64.target().into(),
                source_manifest_sha256:"d".repeat(64),sha256:"e".repeat(64),identity:FileIdentity{mode:0o100555,uid:0,..identity()}},
            parent_descriptor_reservation:56,clock:Clock{name:"CLOCK_UPTIME_RAW".into(),work_end_ns:"1".into(),hard_end_ns:"10000000001".into()}}}}
    fn line(value:&Value)->Vec<u8>{let mut raw=serde_json::to_vec(value).unwrap();raw.push(b'\n');raw}
    #[test]
    fn closed_history_commands_frames_and_original_context(){
        let start=json!({"sessionId":"s","expectedRevision":LAST_REVISION,"expectedConnectionRevision":1,"selection":context().selection});
        assert!(decode_command("github_history_start",&start).is_ok());
        assert!(decode_command("github_history_status",&json!({})).is_ok());
        assert!(decode_command("github_history_cancel",&json!({"operationId":"h"})).is_ok());
        for field in ["expectedRevision","expectedConnectionRevision"]{for value in [json!(0),json!(u32::MAX),json!(true),json!(1.5)]{
            let mut wrong=start.clone();wrong[field]=value;assert!(decode_command("github_history_start",&wrong).is_err());}}
        let mut wrong=start.clone();wrong["selection"]=json!(["3",1,"external-testing","android"]);
        assert!(decode_command("github_history_start",&wrong).is_err());
        assert!(decode_command("github_history_cancel",&json!(["h"])).is_err());
        let actual=initial();let raw=actual.encode().unwrap();let digest=request_digest(&raw);
        let ready=json!({"protocol":PROTOCOL,"id":actual.id,"ready":{"requestSha256":digest}});
        assert!(decode_ready(&line(&ready),&actual.id,&digest).is_ok());
        assert!(decode_ready(&line(&ready),"other",&digest).is_err());
        let mut wrong=ready.clone();wrong["ready"]=json!([digest]);assert!(decode_ready(&line(&wrong),&actual.id,&digest).is_err());
        let mut wrong=line(&ready);wrong.extend_from_slice(b"{}\n");assert!(decode_ready(&wrong,&actual.id,&digest).is_err());
        for token in ["","space here","bad\n","bad\u{7f}"]{assert!(encode_go(&actual.id,&digest,token).is_err());}
        assert!(encode_go(&actual.id,&digest,&"x".repeat(4096)).is_ok());
        assert!(encode_go(&actual.id,&digest,&"x".repeat(4097)).is_err());
        let result=json!({"schemaVersion":1,"context":actual.context,"observedAt":"2026-10-09T00:00:00.123456Z",
            "verification":"unavailable","reason":"artifact-missing","evidence":null,"assurance":ASSURANCE});
        let terminal=json!({"protocol":PROTOCOL,"id":actual.id,"requestSha256":digest,"result":result,"reason":"none",
            "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":true,"commands":1,"verifierCalls":0,
            "inputClosed":true,"handlersRestored":true,"invocationClosed":true,"stopObserved":false}});
        assert!(decode_reply(&line(&terminal),&actual,&digest).is_ok());
        for pointer in ["/result/context","/result/context/selection","/result","/lifetime"]{
            let mut wrong=terminal.clone();*wrong.pointer_mut(pointer).unwrap()=json!([]);assert!(decode_reply(&line(&wrong),&actual,&digest).is_err());}
        for pointer in ["/lifetime/complete","/lifetime/contained","/lifetime/inputClosed","/lifetime/handlersRestored","/lifetime/invocationClosed"]{
            let mut wrong=terminal.clone();*wrong.pointer_mut(pointer).unwrap()=json!(false);assert!(decode_reply(&line(&wrong),&actual,&digest).is_err());}
        for pointer in ["/lifetime/fatal","/lifetime/stopObserved"]{let mut wrong=terminal.clone();*wrong.pointer_mut(pointer).unwrap()=json!(true);
            assert!(decode_reply(&line(&wrong),&actual,&digest).is_err());}
        let mut wrong=terminal.clone();wrong["result"]["context"]["configSha256"]=json!("f".repeat(64));
        assert!(decode_reply(&line(&wrong),&actual,&digest).is_err());
        let mut wrong=terminal.clone();wrong["lifetime"]["commandDispatched"]=Value::Null;assert!(decode_reply(&line(&wrong),&actual,&digest).is_err());
        let mut wrong=terminal.clone();wrong["result"]["reason"]=json!("none");assert!(decode_reply(&line(&wrong),&actual,&digest).is_err());
        let mut refusal=terminal.clone();refusal["result"]=Value::Null;refusal["reason"]=json!("cancelled");
        refusal["lifetime"]["complete"]=json!(false);refusal["lifetime"]["stopObserved"]=json!(true);
        let known=decode_reply(&line(&refusal),&actual,&digest).unwrap();
        assert!(known.lifetime.originals_settled()&&!known.lifetime.complete());
        refusal["lifetime"]["fatal"]=json!(true);
        assert!(!decode_reply(&line(&refusal),&actual,&digest).unwrap().lifetime.originals_settled());
        refusal["lifetime"]["fatal"]=json!(false);refusal["lifetime"]["commandDispatched"]=json!(false);
        refusal["lifetime"]["commands"]=json!(2);refusal["lifetime"]["verifierCalls"]=json!(1);
        assert!(decode_reply(&line(&refusal),&actual,&digest).unwrap().lifetime.originals_settled());
        refusal["lifetime"]["verifierCalls"]=json!(3);assert!(decode_reply(&line(&refusal),&actual,&digest).is_err());
    }
    #[test]
    fn complete_history_result_shapes_and_retained_status_are_bounded(){
        let c=context();let authority=json!({"workflow":"w".repeat(255),"callerPath":".github/workflows/mobile-external-testing.yml",
            "reusableRepository":TOOLING,"reusablePath":".github/workflows/reusable-external-testing.yml","reusableCommit":c.tooling_sha,
            "runId":"3","attempt":1,"headSha":"a".repeat(40),"ref":format!("refs/heads/{}","x".repeat(501)),"event":"workflow_dispatch"});
        let result=json!({"schemaVersion":1,"context":c,"observedAt":"2024-02-29T23:59:59.123456Z","verification":"verified","reason":"none",
            "evidence":{"artifactId":"4","artifactSha256":"a".repeat(64),"artifactName":"mobile-release-external-evidence-android","producerJobId":"5",
            "producedBy":authority,"authorizedBy":authority,"candidateSource":{"commit":"a".repeat(40),"tree":"b".repeat(40)},
            "operationSource":{"commit":"c".repeat(40),"tree":"d".repeat(40)},"version":{"name":"1.2.3-release","build":2100000000},
            "applicationId":"x".repeat(255),"outcome":"operator-authorized-create-retry","candidateManifestSha256":"a".repeat(64),
            "operationIntentSha256":"b".repeat(64),"receiptSha256":"c".repeat(64),"provenanceSha256":"d".repeat(64)},"assurance":ASSURANCE});
        let result:ResultData=serde_json::from_value(result).unwrap();assert!(result.valid());
        let mut status=Status{schema_version:1,revision:LAST_REVISION,session_id:Some("s".repeat(64)),available:true,reason:Reason::None,
            operation:Some(Operation{id:"o".repeat(64),phase:Phase::Settled,reason:Reason::None,selection:c.selection}),result:Some(result)};
        assert!(status.fits_wire()&&status.retained_heap_bytes().unwrap()<RESPONSE_LIMIT);
        status.available=false;status.reason=Reason::CleanupUnknown;assert!(status.fits_wire()); // earlier settled result unchanged
        status.operation.as_mut().unwrap().phase=Phase::Running;assert!(!status.fits_wire());
        for stamp in ["2023-02-29T00:00:00Z","0000-01-01T00:00:00Z","2024-01-01T00:00:60Z","2024-01-01T00:00:00.1234567Z"]{assert!(!utc(stamp));}
        assert!(utc("2024-01-01T00:00:00Z"));
        let mut file=identity();file.ctime_seconds="-0".into();assert!(!file.valid(CONFIG_LIMIT,false));
        file=identity();file.bytes=(CONFIG_LIMIT+1).to_string();assert!(!file.valid(CONFIG_LIMIT,false));
        let mut request=initial();request.native.parent_descriptor_reservation=57;assert!(request.encode().is_err());
        request=initial();request.native.clock.hard_end_ns="10000000002".into();assert!(request.encode().is_err());
    }
}
impl Reply {
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{strings(&[&self.protocol,&self.id,&self.request_sha256])?
        .checked_add(self.result.as_ref().map_or(Some(0),ResultData::retained_heap_bytes)?)}
}
