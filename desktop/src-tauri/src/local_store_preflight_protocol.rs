//! Closed local Store-access DATA; no upload/release authority.
//! A core terminal is provisional until this operation's original native joins.
use std::path::Path;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::{asset_source::RegisteredRoot, edit_protocol::{bounded, token}, error::BridgeError,
    protocol::{check_value, strict_json, valid_id}};
#[path = "apple_provisioning_bundle_read.rs"]
mod bundle_read;
#[path = "apple_provisioning_profile_read.rs"]
mod profile_read;

pub(crate) const PROTOCOL: &str = "mrk-local-store-preflight/1";
pub(crate) const CONSENT: &str = "local-android-store-access-v1";
pub(crate) const APPLE_CONSENT: &str = "local-ios-store-access-v1";
pub(crate) const EVENT: &str = "local-store-preflight-state-changed";
pub(crate) const IPC_LIMIT: usize = 8192;
pub(crate) const REQUEST_LIMIT: usize = 16 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 16 * 1024; // Both frames, framing and rejected drain bytes.
pub(crate) const STATUS_LIMIT: usize = 16 * 1024;

fn keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key)))
}
pub(crate) fn invalid() -> BridgeError { BridgeError::new("local_store_preflight_invalid", "The local Store access-check request is invalid.") }
/// Called only on original InvokeBody::Raw bytes; never a reserialized Value.
pub(crate) fn raw_request(bytes: &[u8]) -> Result<Value, BridgeError> {
    if !(1..=IPC_LIMIT).contains(&bytes.len()) { return Err(invalid()); }
    strict_json(bytes).map_err(|_| invalid())
}
fn sha(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Content { pub(crate) bytes: u32, pub(crate) sha256: String }
impl Content { fn valid(&self) -> bool { (1..=524288).contains(&self.bytes) && sha(&self.sha256) } }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Platform { Android }
// Access alone can select Apple. The Android-only type above is deliberately
// retained for Prepare/Execute/Reconcile; their serde grammar never widens.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AccessPlatform { Android, Ios }
impl AccessPlatform {
    pub(crate) fn consent(self)->&'static str { match self {Self::Android=>CONSENT,Self::Ios=>APPLE_CONSENT} }
    fn commands(self)->u32 {match self {Self::Android=>6,Self::Ios=>7}}
    fn scope(self)->&'static str {match self {Self::Android=>"local-android-store-access-no-publishing",Self::Ios=>"local-ios-store-access-no-publishing"}}
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum AppleSelection { Ios }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Operation { LocalStorePreflight }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ExecutionMode { Local }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) project_id: String, pub(crate) draft_revision: u32, pub(crate) baseline_generation: u32,
    pub(crate) saved_config: Content, pub(crate) saved_version: crate::android_build_protocol::SavedVersion,
    pub(crate) credential_context_revision: u32, pub(crate) record_id: String, pub(crate) record_revision: u32,
    pub(crate) execution_mode: ExecutionMode, pub(crate) platform: AccessPlatform, pub(crate) operation: Operation,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "bundle_read::optional_query")]
    pub(crate) query: Option<bundle_read::Query>,
}
impl Context {
    fn valid(&self) -> bool { valid_id(&self.project_id) && self.draft_revision < u32::MAX
        && self.baseline_generation < u32::MAX && self.saved_config.valid() && self.saved_version.valid()
        && self.credential_context_revision > 0 && self.credential_context_revision < u32::MAX
        && token(&self.record_id) && self.record_revision > 0 && self.record_revision < u32::MAX
        && (self.query.is_none() || self.platform == AccessPlatform::Ios) }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepare {
    pub(crate) project_id: String, pub(crate) draft_revision: u32, pub(crate) baseline_generation: u32,
    pub(crate) saved_config: Content, pub(crate) saved_version: crate::android_build_protocol::SavedVersion,
    pub(crate) credential_context_revision: u32, pub(crate) record_id: String, pub(crate) record_revision: u32,
    pub(crate) execution_mode: ExecutionMode,
    #[serde(default)] platform: Option<AppleSelection>,
    #[serde(default, deserialize_with = "bundle_read::optional_query")] query: Option<bundle_read::Query>,
}
impl Prepare {
    pub(crate) fn context(&self) -> Context { Context { project_id: self.project_id.clone(), draft_revision: self.draft_revision,
        baseline_generation: self.baseline_generation, saved_config: self.saved_config.clone(),
        saved_version: self.saved_version.clone(), credential_context_revision: self.credential_context_revision,
        record_id: self.record_id.clone(), record_revision: self.record_revision, execution_mode: self.execution_mode,
        platform: if self.platform.is_some(){AccessPlatform::Ios}else{AccessPlatform::Android}, operation: Operation::LocalStorePreflight,
        query: self.query } }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Start { pub(crate) operation_id: String, pub(crate) owner_generation: String, consent_version: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cancel { pub(crate) operation_id: String, pub(crate) owner_generation: String }
pub(crate) fn prepare(value: &Value) -> Result<Prepare, BridgeError> {
    if !keys(value, &["projectId", "draftRevision", "baselineGeneration", "savedConfig", "savedVersion",
        "credentialContextRevision", "recordId", "recordRevision", "executionMode"])
        && !(keys(value, &["projectId", "draftRevision", "baselineGeneration", "savedConfig", "savedVersion",
            "credentialContextRevision", "recordId", "recordRevision", "executionMode", "platform"])
            && value.get("platform").and_then(Value::as_str)==Some("ios"))
        && !(keys(value, &["projectId", "draftRevision", "baselineGeneration", "savedConfig", "savedVersion",
            "credentialContextRevision", "recordId", "recordRevision", "executionMode", "platform", "query"])
            && value.get("platform").and_then(Value::as_str)==Some("ios")
            && matches!(value.get("query").and_then(Value::as_str),Some("bundle-id-registration"|"app-store-profile-reuse"))) { return Err(invalid()); }
    let input = Prepare::deserialize(value).map_err(|_| invalid())?;
    if !input.context().valid() { return Err(invalid()); } Ok(input)
}
pub(crate) fn start(value: &Value) -> Result<Start, BridgeError> {
    if !keys(value, &["operationId", "ownerGeneration", "consentVersion"]) { return Err(invalid()); }
    let input = Start::deserialize(value).map_err(|_| invalid())?;
    if !token(&input.operation_id) || !token(&input.owner_generation) || !matches!(input.consent_version.as_str(),CONSENT|APPLE_CONSENT|bundle_read::CONSENT|profile_read::CONSENT) { return Err(invalid()); } Ok(input)
}
impl Start {
    pub(crate) fn matches_context(&self, context:&Context)->bool {
        if let Some(query)=context.query { return context.platform == AccessPlatform::Ios && self.consent_version == query.consent(); }
        self.consent_version == context.platform.consent()
    }
}
pub(crate) fn cancel(value: &Value) -> Result<Cancel, BridgeError> {
    if !keys(value, &["operationId", "ownerGeneration"]) { return Err(invalid()); }
    let input = Cancel::deserialize(value).map_err(|_| invalid())?;
    if !token(&input.operation_id) || !token(&input.owner_generation) { return Err(invalid()); } Ok(input)
}
pub(crate) fn status_request(value: &Value) -> Result<(), BridgeError> { if keys(value, &[]) { Ok(()) } else { Err(invalid()) } }

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub(crate) enum Profile {
    #[serde(rename = "macos-x86_64")] MacosX64,
    #[serde(rename = "macos-arm64")] MacosArm64,
}
impl Profile {
    pub(crate) fn current() -> Option<Self> {
        if cfg!(all(target_os = "macos", target_arch = "x86_64")) { Some(Self::MacosX64) }
        else if cfg!(all(target_os = "macos", target_arch = "aarch64")) { Some(Self::MacosArm64) }
        else { None }
    }
}
#[derive(Serialize)]
pub(crate) struct RootIdentity {
    pub(crate) device: String, pub(crate) inode: String, pub(crate) mode: u32, pub(crate) uid: u32, pub(crate) gid: u32,
}
fn decimal(value: &str) -> bool { !value.is_empty() && (value == "0" || !value.starts_with('0'))
    && value.bytes().all(|b| b.is_ascii_digit()) && value.parse::<u64>().is_ok() }
fn native_path(path: &Path) -> Option<&str> {
    let text = path.to_str()?;
    if text.len() > 4096 || !text.starts_with('/') || text.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}' || c == '\\' || c == ':') { return None; }
    if text != "/" {
        let mut count = 0usize;
        for part in text[1..].split('/') {
            count += 1;
            if count > 128 || part.is_empty() || part == "." || part == ".." || part.len() > 255 { return None; }
        }
    }
    Some(text)
}
pub(crate) fn request(operation: &str, generation: &str, context: &Context, profile: Profile,
    project: &RegisteredRoot, cwd: &Path, credential_config: &Content) -> Result<Vec<u8>, BridgeError> {
    if !token(operation) || !token(generation) || !context.valid() || !credential_config.valid() { return Err(invalid()); }
    let identity = project.identity.posix().map_err(|_| invalid())?.preflight_identity();
    if !decimal(&identity.device) || !decimal(&identity.inode) || identity.inode == "0" || identity.mode & 0o170000 != 0o040000 { return Err(invalid()); }
    let value = json!({"protocol":PROTOCOL,"operationId":operation,"ownerGeneration":generation,"context":context,
        "native":{"profile":profile,"projectRoot":native_path(&project.path).ok_or_else(invalid)?,
            "rootIdentity":identity,"cwd":native_path(cwd).ok_or_else(invalid)?,"credentialConfig":credential_config}});
    check_value(&value).map_err(|_| invalid())?;
    let mut bytes = bounded(&value, REQUEST_LIMIT - 1).map_err(|_| invalid())?;
    bytes.push(b'\n'); Ok(bytes)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Outcome { Complete, Refused, Cancelled, TimedOut, Failed, Unknown }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None, Cancelled, ContextChanged, DocumentLost, Shutdown, TimedOut, ProtocolError, RuntimeUnavailable, IntentExpired,
    StaleIntent, SavedSourceChanged, SavedSourceInvalid, CredentialsUnavailable, QueryPrerequisites, CommandIncomplete, CleanupUnknown,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum CoreStatus { Pass, Fail, Missing, Blocked, Invalid, Skip, Manual, Configured, NotApplicable }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CheckId { CredentialFormat, QueryPrerequisites, RuntimeUnavailable, BundleUnavailable, StoreAccess }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Finding { check: CheckId, status: CoreStatus }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Limitation { NonPublishing, NoProjectCommands, NoBuildOrSigning, NoReleaseReadiness,
    PointInTimeAccountAccess, SavedInputsNotAtomic, NoTeamVerification, NoGlobalAvailabilityClaim, NoProvisioningChanges,
    MetadataOnly, NoPrivateKeyMatch, NoProfileAuthentication, NoAccountCertificateInventory }
const LIMITATIONS: [Limitation; 6] = [Limitation::NonPublishing, Limitation::NoProjectCommands,
    Limitation::NoBuildOrSigning, Limitation::NoReleaseReadiness, Limitation::PointInTimeAccountAccess,
    Limitation::SavedInputsNotAtomic];
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResultData { schema_version: u32, scope: String, findings: Vec<Finding>, limitations: Vec<Limitation>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "bundle_read::optional_observation")]
    observation: Option<bundle_read::Observation>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "profile_read::optional_summary")]
    profile_reuse: Option<profile_read::Summary>,
}
impl ResultData {
    fn valid(&self, context:&Context) -> bool {
        if let Some(query)=context.query { return context.platform == AccessPlatform::Ios && match query {
            bundle_read::Query::BundleIdRegistration => bundle_read::valid_result(self),
            bundle_read::Query::AppStoreProfileReuse => profile_read::valid_result(self),
        }; }
        self.observation.is_none() && self.profile_reuse.is_none() && self.schema_version == 1 && self.scope == context.platform.scope()
            && self.limitations.as_slice() == LIMITATIONS && self.findings.len() <= 16
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum CoreStop { None, Cancelled, TimedOut }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Lifetime {
    complete: bool, fatal: bool, contained: bool, command_dispatched: Option<bool>, commands: u32, profile_calls: u32,
    input_closed: bool, handlers_restored: bool, invocation_closed: bool, stop_observed: CoreStop,
}
impl Lifetime {
    pub(crate) fn settled(&self) -> bool { self.complete && !self.fatal && self.contained && self.command_dispatched.is_some()
        && self.input_closed && self.handlers_restored && self.invocation_closed && self.profile_calls == 0 }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Terminal {
    schema_version: u32, context: Context, pub(crate) outcome: Outcome, pub(crate) reason: Reason,
    pub(crate) result: Option<ResultData>, pub(crate) lifetime: Lifetime,
}
impl Terminal {
    fn valid(&self, context: &Context) -> bool {
        if self.schema_version != 1 || &self.context != context || !self.context.valid() || self.lifetime.profile_calls != 0
            || self.lifetime.commands > context.platform.commands() { return false; }
        if self.outcome == Outcome::Complete {
            return self.reason == Reason::None && self.lifetime.settled() && self.lifetime.stop_observed == CoreStop::None
                && self.result.as_ref().is_some_and(|r| r.valid(context));
        }
        if self.result.is_some() || self.reason == Reason::None { return false; }
        if self.outcome == Outcome::Unknown { return self.reason == Reason::CleanupUnknown && !self.lifetime.settled(); }
        if !self.lifetime.settled() { return false; }
        match self.outcome {
            Outcome::Cancelled => self.reason == Reason::Cancelled && self.lifetime.stop_observed == CoreStop::Cancelled,
            Outcome::TimedOut => self.reason == Reason::TimedOut && self.lifetime.stop_observed == CoreStop::TimedOut,
            Outcome::Refused | Outcome::Failed => true,
            _ => false,
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Accepted { schema_version: u32, context: Context }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope { protocol: String, operation_id: String, owner_generation: String, sequence: u32, kind: String, payload: Value }
pub(crate) enum Frame { Accepted, Terminal(Terminal) }
pub(crate) fn decode(bytes: &[u8], operation: &str, generation: &str, context: &Context) -> Result<Frame, BridgeError> {
    if bytes.len() < 3 || bytes.len() > RESPONSE_LIMIT || !bytes.ends_with(b"\n") || bytes[0] != b'{'
        || bytes[bytes.len() - 2] != b'}' || bytes[..bytes.len() - 1].iter().any(|b| *b == b'\r' || *b == b'\n') { return Err(BridgeError::protocol()); }
    let value = strict_json(&bytes[..bytes.len() - 1])?;
    let envelope = Envelope::deserialize(&value).map_err(|_| BridgeError::protocol())?;
    if envelope.protocol != PROTOCOL || envelope.operation_id != operation || envelope.owner_generation != generation
        || !token(operation) || !token(generation) { return Err(BridgeError::protocol()); }
    match (envelope.sequence, envelope.kind.as_str()) {
        (0, "accepted") => {
            let accepted = Accepted::deserialize(&envelope.payload).map_err(|_| BridgeError::protocol())?;
            if accepted.schema_version != 1 || &accepted.context != context || !accepted.context.valid() { return Err(BridgeError::protocol()); }
            Ok(Frame::Accepted)
        }
        (1, "terminal") => {
            // Required nullable fields cannot use serde's omitted-Option default.
            if !keys(&envelope.payload, &["schemaVersion", "context", "outcome", "reason", "result", "lifetime"])
                || !envelope.payload.get("lifetime").is_some_and(|l| keys(l, &["complete", "fatal", "contained", "commandDispatched", "commands",
                    "profileCalls", "inputClosed", "handlersRestored", "invocationClosed", "stopObserved"])) { return Err(BridgeError::protocol()); }
            if let Some(result) = envelope.payload.get("result").filter(|v| !v.is_null()) {
                let rows = result.get("findings").and_then(Value::as_array).ok_or_else(BridgeError::protocol)?;
                if rows.len() > 16 || rows.iter().any(|row| !keys(row, &["check", "status"])) { return Err(BridgeError::protocol()); }
            }
            let terminal = Terminal::deserialize(&envelope.payload).map_err(|_| BridgeError::protocol())?;
            if !terminal.valid(context) { return Err(BridgeError::protocol()); } Ok(Frame::Terminal(terminal))
        }
        _ => Err(BridgeError::protocol()),
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase { AwaitingConsent, Starting, Running, Stopping, Terminal, Unknown }
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Availability { Available, Busy, Shutdown, CleanupUnknown, DocumentLost, UnsupportedPlatform, RuntimeUnqualified }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Projection {
    pub(crate) operation_id: String, pub(crate) owner_generation: String, pub(crate) context: Context, pub(crate) phase: Phase,
    pub(crate) intent_usable: bool, pub(crate) outcome: Option<Outcome>, pub(crate) reason: Reason, pub(crate) result: Option<ResultData>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version: u32, pub(crate) status_revision: u32, pub(crate) availability: Availability, pub(crate) operation: Option<Projection>,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    fn input() -> Value { json!({"projectId":"fixture","draftRevision":1,"baselineGeneration":2,
        "savedConfig":{"bytes":100,"sha256":"a".repeat(64)},
        "savedVersion":{"source":"release/version.properties","bytes":40,"sha256":"b".repeat(64),"name":"1.2.3","build":42},
        "credentialContextRevision":3,"recordId":"c".repeat(32),"recordRevision":4,"executionMode":"local"}) }
    pub(crate) fn context() -> Context { prepare(&input()).unwrap().context() }
    pub(crate) fn complete() -> Value { json!({"schemaVersion":1,"context":context(),"outcome":"complete","reason":"none",
        "result":{"schemaVersion":1,"scope":"local-android-store-access-no-publishing",
            "findings":[{"check":"store-access","status":"FAIL"}],"limitations":LIMITATIONS},
        "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":false,"commands":0,
            "profileCalls":0,"inputClosed":true,"handlersRestored":true,"invocationClosed":true,"stopObserved":"none"}}) }
    #[test]
    fn local_consent_is_closed_and_terminal_cannot_hide_unknown_ownership() {
        let value=input(); let context=prepare(&value).unwrap().context();
        for (name, invalid_value) in [("executionMode",json!("github")),("recordRevision",json!(0)),
            ("credentialContextRevision",json!(true)),("environment",json!({})),("credentials",json!("private"))] {
            let mut bad=value.clone();bad[name]=invalid_value;assert!(prepare(&bad).is_err());
        }
        assert!(start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":"saved-offline-android-v1"})).is_err());
        let lifetime=json!({"complete":true,"fatal":false,"contained":true,"commandDispatched":false,"commands":0,
            "profileCalls":0,"inputClosed":true,"handlersRestored":true,"invocationClosed":true,"stopObserved":"none"});
        let terminal=json!({"schemaVersion":1,"context":context,"outcome":"complete","reason":"none",
            "result":{"schemaVersion":1,"scope":"local-android-store-access-no-publishing",
                "findings":[{"check":"store-access","status":"FAIL"}],"limitations":LIMITATIONS},"lifetime":lifetime});
        assert!(Terminal::deserialize(&terminal).unwrap().valid(&context));
        for name in ["complete","contained","inputClosed","handlersRestored","invocationClosed"] {
            let mut bad=terminal.clone();bad["lifetime"][name]=json!(false);
            assert!(!Terminal::deserialize(&bad).unwrap().valid(&context));
            bad["outcome"]=json!("unknown");bad["reason"]=json!("cleanup-unknown");bad["result"]=Value::Null;
            assert!(Terminal::deserialize(&bad).unwrap().valid(&context));
        }
        let mut bad=terminal.clone();bad["result"]["findings"][0]["message"]=json!("private provider response");
        assert!(Terminal::deserialize(&bad).is_err());
        #[cfg(not(target_os="macos"))]
        assert_eq!(Profile::current(),None);
    }
    #[test]
    fn apple_access_consent_scope_and_seven_calls_do_not_widen_google_mutations(){
        let mut value=input();value["platform"]=json!("ios");let c=prepare(&value).unwrap().context();
        assert_eq!(c.platform,AccessPlatform::Ios);
        for bad in [json!("android"),Value::Null,json!("macos")] {value["platform"]=bad;assert!(prepare(&value).is_err());}
        assert!(serde_json::from_value::<Platform>(json!("ios")).is_err());
        for consent in [CONSENT,APPLE_CONSENT] {
            let start=start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":consent})).unwrap();
            assert_eq!(start.matches_context(&c),consent==APPLE_CONSENT);
            assert_eq!(start.matches_context(&context()),consent==CONSENT);
        }
        let mut t=complete();t["context"]=json!(c);t["result"]["scope"]=json!(c.platform.scope());t["lifetime"]["commands"]=json!(7);
        assert!(Terminal::deserialize(&t).unwrap().valid(&c));
        assert!(!Terminal::deserialize(&t).unwrap().valid(&context()));
        t["lifetime"]["commands"]=json!(8);assert!(!Terminal::deserialize(&t).unwrap().valid(&c));
        t["lifetime"]["commands"]=json!(7);t["lifetime"]["inputClosed"]=json!(false);
        assert!(!Terminal::deserialize(&t).unwrap().valid(&c));
        t["outcome"]=json!("unknown");t["reason"]=json!("cleanup-unknown");t["result"]=Value::Null;
        assert!(Terminal::deserialize(&t).unwrap().valid(&c));
    }

}
