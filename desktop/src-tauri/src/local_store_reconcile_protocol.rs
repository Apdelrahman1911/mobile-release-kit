//! Closed local Store target readback DATA; only the genuine current native owner grants an action.
//! A core terminal is provisional until this operation's original native joins.
use std::path::Path;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::{asset_source::RegisteredRoot, edit_protocol::{bounded, token}, error::BridgeError,
    protocol::{check_value, strict_json, valid_id}};

pub(crate) const PROTOCOL: &str = "mrk-local-store-reconcile/1";
pub(crate) const CONSENT: &str = "local-android-store-reconcile-v1";
pub(crate) const READINESS_CONSENT:&str="local-ios-external-readiness-v1";
pub(crate) const APPLE_CONSENT: &str = "local-ios-store-reconcile-v1";
pub(crate) const SETTLEMENT_CONSENT: &str = "local-android-recovery-settle-v1";
pub(crate) const EVENT: &str = "local-store-reconcile-state-changed";
pub(crate) const IPC_LIMIT: usize = 16 * 1024;
pub(crate) const REQUEST_LIMIT: usize = 16 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 64 * 1024; // Aggregate cap including up to five settlement frames and rejected drain bytes.
pub(crate) const STATUS_LIMIT: usize = 16 * 1024;

fn keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key)))
}
pub(crate) fn invalid() -> BridgeError { BridgeError::new("local_store_reconcile_invalid", "The local Store reconciliation request is invalid.") }
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
pub(crate) use crate::local_store_preflight_protocol::{ExecutionMode,Profile,Outcome,Phase,Availability};
// This domain alone supports Apple readback, never Apple recovery settlement.
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="lowercase")]
pub(crate) enum Platform {Android,Ios}
impl Platform {
    fn name(self)->&'static str {match self {Self::Android=>"android",Self::Ios=>"ios"}}
    fn commands(self)->u32 {match self {Self::Android=>14,Self::Ios=>15}}
    fn scope(self)->&'static str {match self {Self::Android=>"local-android-store-reconcile",Self::Ios=>"local-ios-store-reconcile"}}
}
#[derive(Deserialize)]
#[serde(rename_all="lowercase")]
enum AppleSelection {Ios}
pub(crate) use crate::local_release_history_protocol::Head;
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Operation { LocalStoreReconcile, LocalStoreRecoverySettle }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="kebab-case")]
pub(crate) enum Settlement { RecordCurrentTarget }
fn settlement_field<'de,D:serde::Deserializer<'de>>(decoder:D)->Result<Option<Settlement>,D::Error>{
    Ok(Some(Settlement::deserialize(decoder)?))
}
fn uuid(v:&str)->bool { crate::local_release_history_protocol::journal_uuid(v) }
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
pub(crate) enum ReadinessAction {ExternalReadiness}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Readiness {
    pub(crate) action:ReadinessAction,pub(crate) stage_operation_id:String,
    pub(crate) execution_receipt_sha256:String,
    pub(crate) supplemental_assignments:crate::local_store_prepare_protocol::StageAssignments,
}
impl Readiness {
    fn valid(&self,candidate:&str,primary:&str)->bool {uuid(&self.stage_operation_id)&&self.stage_operation_id!=candidate
        &&sha(&self.execution_receipt_sha256)&&self.supplemental_assignments.valid(primary)}
    pub(crate) fn heap_bytes(&self)->Option<usize>{self.stage_operation_id.capacity().checked_add(self.execution_receipt_sha256.capacity())?
        .checked_add(self.supplemental_assignments.heap_bytes()?)}
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) project_id: String, pub(crate) draft_revision: u32, pub(crate) baseline_generation: u32,
    pub(crate) saved_config: Content, pub(crate) saved_version: crate::android_build_protocol::SavedVersion,
    pub(crate) credential_context_revision: u32, pub(crate) record_id: String, pub(crate) record_revision: u32,
    pub(crate) execution_mode: ExecutionMode, pub(crate) platform: Platform, pub(crate) operation: Operation,
    pub(crate) candidate_operation_id:String, pub(crate) candidate_sha256:String, pub(crate) confirmation:String,
    pub(crate) intent_sha256:String,
    #[serde(default,skip_serializing_if="Option::is_none",deserialize_with="settlement_field")]
    pub(crate) settlement:Option<Settlement>,
    #[serde(flatten)] pub(crate) readiness:Option<Readiness>,
}
impl<'de> Deserialize<'de> for Context {
    fn deserialize<D:serde::Deserializer<'de>>(decoder:D)->Result<Self,D::Error>{
        let mut value=Value::deserialize(decoder)?;let operation=value.get("operation").and_then(Value::as_str).map(str::to_owned);
        if !matches!(value.get("platform").and_then(Value::as_str),Some("android"|"ios")){return Err(serde::de::Error::custom("invalid reconcile context"));}
        let map=value.as_object_mut().ok_or_else(||serde::de::Error::custom("invalid reconcile context"))?;map.remove("operation");
        if map.get("platform").and_then(Value::as_str)==Some("android"){map.remove("platform");}
        let context=prepare(&value).map_err(|_|serde::de::Error::custom("invalid reconcile context"))?.context();
        let expected=if context.settling(){"local-store-recovery-settle"}else{"local-store-reconcile"};
        if operation.as_deref()!=Some(expected){return Err(serde::de::Error::custom("invalid reconcile context"));}Ok(context)
    }
}
impl Context {
    pub(crate) fn settling(&self)->bool { self.platform==Platform::Android && self.operation==Operation::LocalStoreRecoverySettle && self.settlement==Some(Settlement::RecordCurrentTarget) }
    pub(crate) fn refreshing(&self)->bool {self.platform==Platform::Ios&&self.operation==Operation::LocalStoreReconcile&&self.settlement.is_none()&&self.readiness.is_some()}
    pub(crate) fn checkpointing(&self)->bool {self.settling()||self.refreshing()}
    pub(crate) fn head_valid(&self,head:u32)->bool {(if self.refreshing(){11}else{6}..=if self.refreshing(){508}else if self.settling(){512}else{513}).contains(&head)}
    pub(crate) fn asset_stage(&self)->crate::asset_commands::Stage {if self.refreshing(){crate::asset_commands::Stage::ExternalTesting}else{crate::asset_commands::Stage::Candidate}}
    pub(crate) fn consent(&self)->&'static str { if self.refreshing(){READINESS_CONSENT}else if self.settling(){SETTLEMENT_CONSENT}else if self.platform==Platform::Ios{APPLE_CONSENT}else{CONSENT} }
    pub(crate) fn frame_limit(&self)->usize { if self.checkpointing(){5}else{4} }
    fn valid(&self) -> bool { ((self.operation==Operation::LocalStoreReconcile&&self.settlement.is_none())||self.settling()) && valid_id(&self.project_id) && self.draft_revision < u32::MAX
        && self.baseline_generation < u32::MAX && self.saved_config.valid() && self.saved_version.valid()
        && self.credential_context_revision > 0 && self.credential_context_revision < u32::MAX
        && token(&self.record_id) && self.record_revision > 0 && self.record_revision < u32::MAX
        && uuid(&self.candidate_operation_id) && sha(&self.candidate_sha256) && sha(&self.intent_sha256)
        &&self.readiness.as_ref().is_none_or(|r|self.refreshing()&&r.valid(&self.candidate_operation_id,&self.record_id))
        && self.confirmation==format!("{}:{}:{}:{}",if self.refreshing(){"external-testing"}else{"candidate"},self.platform.name(),self.saved_version.name,self.saved_version.build) }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepare {
    pub(crate) project_id: String, pub(crate) draft_revision: u32, pub(crate) baseline_generation: u32,
    pub(crate) saved_config: Content, pub(crate) saved_version: crate::android_build_protocol::SavedVersion,
    pub(crate) credential_context_revision: u32, pub(crate) record_id: String, pub(crate) record_revision: u32,
    pub(crate) execution_mode: ExecutionMode,
    pub(crate) candidate_operation_id:String, pub(crate) candidate_sha256:String, pub(crate) confirmation:String,
    pub(crate) intent_sha256:String,
    #[serde(default)] platform:Option<AppleSelection>,
    #[serde(default,skip_serializing_if="Option::is_none",deserialize_with="settlement_field")]
    pub(crate) settlement:Option<Settlement>,
    #[serde(skip)] readiness:Option<Readiness>,
}
impl Prepare {
    pub(crate) fn context(&self) -> Context { Context { project_id: self.project_id.clone(), draft_revision: self.draft_revision,
        baseline_generation: self.baseline_generation, saved_config: self.saved_config.clone(),
        saved_version: self.saved_version.clone(), credential_context_revision: self.credential_context_revision,
        record_id: self.record_id.clone(), record_revision: self.record_revision, execution_mode: self.execution_mode,
        platform: if self.platform.is_some(){Platform::Ios}else{Platform::Android}, operation: if self.settlement.is_some(){Operation::LocalStoreRecoverySettle}else{Operation::LocalStoreReconcile}, candidate_operation_id:self.candidate_operation_id.clone(),
        candidate_sha256:self.candidate_sha256.clone(),confirmation:self.confirmation.clone(),
        intent_sha256:self.intent_sha256.clone(),settlement:self.settlement,readiness:self.readiness.clone() } }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Start { pub(crate) operation_id: String, pub(crate) owner_generation: String, pub(crate) consent_version: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cancel { pub(crate) operation_id: String, pub(crate) owner_generation: String }
pub(crate) fn prepare(value: &Value) -> Result<Prepare, BridgeError> {
    let mut expected=vec!["projectId", "draftRevision", "baselineGeneration", "savedConfig", "savedVersion",
        "credentialContextRevision", "recordId", "recordRevision", "executionMode", "candidateOperationId", "candidateSha256", "confirmation", "intentSha256"];
    let readiness=if value.get("action").is_some(){
        if value.get("action").and_then(Value::as_str)!=Some("external-readiness")
            ||value.get("platform").and_then(Value::as_str)!=Some("ios")||value.get("settlement").is_some()
            ||!value.get("supplementalAssignments").is_some_and(|a|keys(a,&["reviewContact","commitment","reviewDemo"])){return Err(invalid());}
        expected.extend(["action","stageOperationId","executionReceiptSha256","supplementalAssignments"]);
        Some(Readiness::deserialize(json!({"action":value["action"],"stageOperationId":value["stageOperationId"],
            "executionReceiptSha256":value["executionReceiptSha256"],"supplementalAssignments":value["supplementalAssignments"]})).map_err(|_|invalid())?)
    }else{None};
    if value.get("platform").is_some(){
        if value.get("platform").and_then(Value::as_str)!=Some("ios")||value.get("settlement").is_some(){return Err(invalid());}
        expected.push("platform");
    }
    if value.get("settlement").is_some(){
        if value.get("settlement").and_then(Value::as_str)!=Some("record-current-target"){return Err(invalid());}
        expected.push("settlement");
    }
    if !keys(value, &expected) { return Err(invalid()); }
    let mut base=value.clone();if readiness.is_some(){for name in ["action","stageOperationId","executionReceiptSha256","supplementalAssignments"]{base.as_object_mut().unwrap().remove(name);}}
    let mut input = Prepare::deserialize(base).map_err(|_| invalid())?;input.readiness=readiness;
    if !input.context().valid() { return Err(invalid()); } Ok(input)
}
pub(crate) fn start(value: &Value) -> Result<Start, BridgeError> {
    if !keys(value, &["operationId", "ownerGeneration", "consentVersion"]) { return Err(invalid()); }
    let input = Start::deserialize(value).map_err(|_| invalid())?;
    if !token(&input.operation_id) || !token(&input.owner_generation) || !matches!(input.consent_version.as_str(),CONSENT|SETTLEMENT_CONSENT|APPLE_CONSENT|READINESS_CONSENT) { return Err(invalid()); } Ok(input)
}
pub(crate) fn cancel(value: &Value) -> Result<Cancel, BridgeError> {
    if !keys(value, &["operationId", "ownerGeneration"]) { return Err(invalid()); }
    let input = Cancel::deserialize(value).map_err(|_| invalid())?;
    if !token(&input.operation_id) || !token(&input.owner_generation) { return Err(invalid()); } Ok(input)
}
pub(crate) fn status_request(value: &Value) -> Result<(), BridgeError> { if keys(value, &[]) { Ok(()) } else { Err(invalid()) } }

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
pub(crate) struct Native {pub(crate) home:std::path::PathBuf,pub(crate) lease_fd:u32,pub(crate) nonce:String,
    pub(crate) work_end_ns:u64,pub(crate) hard_end_ns:u64,pub(crate) authorization_id:String,
    pub(crate) tooling_version:&'static str,pub(crate) tooling_commit:&'static str}
impl Native {fn valid(&self)->bool{(3..=255).contains(&self.lease_fd)&&self.nonce.len()==32&&token(&self.nonce)&&self.nonce!="0".repeat(32)
    &&self.work_end_ns>0&&self.hard_end_ns>self.work_end_ns&&self.hard_end_ns-self.work_end_ns<=10_000_000_000
    &&uuid(&self.authorization_id)&&self.tooling_version==crate::runtime::CORE_VERSION&&self.tooling_commit.len()==40
    &&self.tooling_commit.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}}
pub(crate) fn request(operation: &str, generation: &str, context: &Context, profile: Profile,
    project: &RegisteredRoot, cwd: &Path, credential_config: &Content, native:&Native) -> Result<Vec<u8>, BridgeError> {
    if !token(operation) || !token(generation) || !context.valid() || !credential_config.valid() || !native.valid() { return Err(invalid()); }
    let identity = project.identity.posix().map_err(|_| invalid())?.preflight_identity();
    if !decimal(&identity.device) || !decimal(&identity.inode) || identity.inode == "0" || identity.mode & 0o170000 != 0o040000 { return Err(invalid()); }
    let value = json!({"protocol":PROTOCOL,"operationId":operation,"ownerGeneration":generation,"context":context,
        "native":{"profile":profile,"projectRoot":native_path(&project.path).ok_or_else(invalid)?,
            "rootIdentity":identity,"cwd":native_path(cwd).ok_or_else(invalid)?,"credentialConfig":credential_config,
            "home":native_path(&native.home).ok_or_else(invalid)?,"leaseFd":native.lease_fd,"nonce":native.nonce,
            "clock":{"workEndNs":native.work_end_ns.to_string(),"hardEndNs":native.hard_end_ns.to_string()},
            "authorizationId":native.authorization_id,"tooling":{"version":native.tooling_version,"commit":native.tooling_commit}}});
    check_value(&value).map_err(|_| invalid())?;
    let mut bytes = bounded(&value, REQUEST_LIMIT - 1).map_err(|_| invalid())?;
    bytes.push(b'\n'); Ok(bytes)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None, ReconcileUnavailable, RecoverySettleUnavailable, Cancelled, ContextChanged, DocumentLost, Shutdown, TimedOut, ProtocolError, RuntimeUnavailable, IntentExpired,
    StaleIntent, SavedSourceChanged, SavedSourceInvalid, CredentialsUnavailable, QueryPrerequisites, CommandIncomplete, CleanupUnknown,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="kebab-case")]
enum Limitation {NonPublishing,NotRetryPermission,OldEvidencePreserved,SavedInputsNotAtomic}
const LIMITATIONS:[Limitation;4]=[Limitation::NonPublishing,Limitation::NotRetryPermission,Limitation::OldEvidencePreserved,Limitation::SavedInputsNotAtomic];
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
struct Version {name:String,build:u32}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Destination {channel:String,release_status:String}
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
enum ReceiptResult {Reconciled}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct AndroidReconciliationReceipt {operation_id:String,candidate_sha256:String,intent_sha256:String,receipt_sha256:String,authorization_id:String,
    source_commit:String,source_tree:String,application_id:String,version:Version,destination:Destination,observed_at:String,result:ReceiptResult,limitations:Vec<Limitation>,observation:String,prior_execution_finality:String}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct AppleDestination {channel:String}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct IosReconciliationReceipt {operation_id:String,candidate_sha256:String,intent_sha256:String,receipt_sha256:String,authorization_id:String,
    source_commit:String,source_tree:String,bundle_id:String,app_store_app_id:String,version:Version,destination:AppleDestination,observed_at:String,result:ReceiptResult,limitations:Vec<Limitation>,observation:String,prior_execution_finality:String}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(untagged)]
pub(crate) enum ReconciliationReceipt {Android(AndroidReconciliationReceipt),Ios(IosReconciliationReceipt)}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct ReadinessReceipt {
    operation_id:String,candidate_operation_id:String,candidate_sha256:String,intent_sha256:String,execution_receipt_sha256:String,
    receipt_sha256:String,authorization_id:String,source_commit:String,source_tree:String,bundle_id:String,app_store_app_id:String,
    version:Version,destination:AppleDestination,observed_at:String,result:String,state:String,
    limitations:Vec<Limitation>,observation:String,prior_execution_finality:String,
}
impl ReadinessReceipt {
    fn valid_shape(&self,operation:&str)->bool {
        let p=self;let hex=|v:&str,n|v.len()==n&&v.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b));
        p.operation_id==operation&&uuid(operation)&&uuid(&p.candidate_operation_id)&&p.candidate_operation_id!=operation
            &&sha(&p.candidate_sha256)&&sha(&p.intent_sha256)&&sha(&p.execution_receipt_sha256)&&sha(&p.receipt_sha256)&&uuid(&p.authorization_id)
            &&hex(&p.source_commit,40)&&hex(&p.source_tree,40)&&p.bundle_id.len()<=255&&p.bundle_id.split('.').count()>=2
            &&p.bundle_id.split('.').all(|v|v.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)&&v.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'))
            &&(1..=20).contains(&p.app_store_app_id.len())&&p.app_store_app_id.bytes().all(|b|b.is_ascii_digit())
            &&!p.version.name.is_empty()&&p.version.name.len()<=64&&p.version.name.bytes().all(|b|b.is_ascii_alphanumeric()||b".+-".contains(&b))
            &&(1..=2_100_000_000).contains(&p.version.build)&&p.destination.channel=="testflight-external"&&utc_second(&p.observed_at)
            &&p.result=="ready"&&p.state=="available-to-testers"&&p.limitations==LIMITATIONS&&p.prior_execution_finality=="not-established"
    }
    pub(crate) fn valid_review(&self,operation:&str)->bool {self.valid_shape(operation)&&self.observation=="current-external-readiness-files-only"}
    fn valid_current(&self,c:&Context,authorization:&str)->bool {
        c.readiness.as_ref().is_some_and(|r|c.refreshing()&&self.valid_shape(&r.stage_operation_id)
            &&self.observation=="current-external-target-only"&&self.candidate_operation_id==c.candidate_operation_id
            &&self.candidate_sha256==c.candidate_sha256&&self.intent_sha256==c.intent_sha256&&self.execution_receipt_sha256==r.execution_receipt_sha256
            &&self.authorization_id==authorization&&self.version.name==c.saved_version.name&&self.version.build==c.saved_version.build)
    }
}
#[derive(Clone,Debug,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase")]
pub(crate) struct ResultData {schema_version:u32,scope:String,head_sequence:u32,
    #[serde(skip_serializing_if="Option::is_none")] reconciliation_receipt:Option<ReconciliationReceipt>,
    #[serde(skip_serializing_if="Option::is_none")] readiness_receipt:Option<ReadinessReceipt>,
}
impl<'de> Deserialize<'de> for ResultData {
    fn deserialize<D:serde::Deserializer<'de>>(decoder:D)->Result<Self,D::Error>{
        let value=Value::deserialize(decoder)?;let readiness=value.get("scope").and_then(Value::as_str)==Some("local-ios-external-readiness");
        let field=if readiness{"readinessReceipt"}else{"reconciliationReceipt"};
        if !keys(&value,&["schemaVersion","scope","headSequence",field]){return Err(serde::de::Error::custom("invalid reconcile result"));}
        #[derive(Deserialize)] #[serde(rename_all="camelCase")] struct Base {schema_version:u32,scope:String,head_sequence:u32}
        let b=Base::deserialize(&value).map_err(serde::de::Error::custom)?;
        Ok(Self{schema_version:b.schema_version,scope:b.scope,head_sequence:b.head_sequence,
            reconciliation_receipt:if readiness{None}else{Some(ReconciliationReceipt::deserialize(&value[field]).map_err(serde::de::Error::custom)?)},
            readiness_receipt:if readiness{Some(ReadinessReceipt::deserialize(&value[field]).map_err(serde::de::Error::custom)?)}else{None}})
    }
}
fn utc_second(value:&str)->bool{
    let d=value.as_bytes();
    if d.len()!=20||!d.iter().enumerate().all(|(i,b)|match i{4|7=>*b==b'-',10=>*b==b'T',13|16=>*b==b':',19=>*b==b'Z',_=>b.is_ascii_digit()}){return false;}
    let n=|a:usize,b:usize|d[a..b].iter().fold(0u32,|v,c|v*10+u32::from(c-b'0'));
    let y=n(0,4);let m=n(5,7);let days=match m{1|3|5|7|8|10|12=>31,4|6|9|11=>30,2=>if y%4==0&&(y%100!=0||y%400==0){29}else{28},_=>0};
    y>=1&&(1..=days).contains(&n(8,10))&&n(11,13)<24&&n(14,16)<60&&n(17,19)<60
}
// Closed summary DATA shared with read-only History. It is not a Reconcile
// Context, original authorization comparison or native completion observation.
impl ReconciliationReceipt {
    fn platform(&self)->Platform {match self {Self::Android(_)=>Platform::Android,Self::Ios(_)=>Platform::Ios}}
    fn version(&self)->&Version {match self {Self::Android(p)=>&p.version,Self::Ios(p)=>&p.version}}
    fn binding(&self)->(&str,&str,&str) {match self {Self::Android(p)=>(&p.candidate_sha256,&p.intent_sha256,&p.authorization_id),Self::Ios(p)=>(&p.candidate_sha256,&p.intent_sha256,&p.authorization_id)}}
    pub(crate) fn valid_for(&self,operation:&str)->bool {
        self.valid_shape(operation)&&match self {Self::Android(p)=>p.observation=="current-internal-target-only",Self::Ios(p)=>p.observation=="current-internal-build-only"}
    }
    pub(crate) fn valid_recovery_review(&self,operation:&str)->bool {
        matches!(self,Self::Android(p) if p.observation=="current-recovery-files-only")&&self.valid_shape(operation)
    }
    fn valid_shape(&self,operation:&str)->bool {
        let(id,receipt,commit,tree,app,date,limits,finality)=match self {
            Self::Android(p)=>(&p.operation_id,&p.receipt_sha256,&p.source_commit,&p.source_tree,&p.application_id,&p.observed_at,&p.limitations,&p.prior_execution_finality),
            Self::Ios(p)=>(&p.operation_id,&p.receipt_sha256,&p.source_commit,&p.source_tree,&p.bundle_id,&p.observed_at,&p.limitations,&p.prior_execution_finality),
        };
        let(candidate,intent,authorization)=self.binding();let version=self.version();
        let hex=|v:&str,n|v.len()==n&&v.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b));
        let separator=if self.platform()==Platform::Ios{b'-'}else{b'_'};
        let app_valid=app.len()<=255&&app.split('.').count()>=2&&app.split('.').all(|v|
            v.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)&&v.bytes().all(|b|b.is_ascii_alphanumeric()||b==separator));
        let destination=match self {Self::Android(p)=>p.destination.channel=="internal"&&p.destination.release_status=="completed",
            Self::Ios(p)=>p.destination.channel=="testflight-internal"&&(1..=20).contains(&p.app_store_app_id.len())&&p.app_store_app_id.bytes().all(|b|b.is_ascii_digit())};
        id==operation&&uuid(operation)&&sha(candidate)&&sha(intent)&&sha(receipt)&&uuid(authorization)&&hex(commit,40)&&hex(tree,40)&&app_valid
            &&!version.name.is_empty()&&version.name.len()<=64&&version.name.bytes().all(|b|b.is_ascii_alphanumeric()||b".+-".contains(&b))
            &&(1..=2_100_000_000).contains(&version.build)&&finality=="not-established"
            &&destination&&utc_second(date)&&*limits==LIMITATIONS
    }
}
impl ResultData {
    fn valid(&self,c:&Context,authorization:&str)->bool {
        if c.refreshing(){return self.schema_version==1&&self.scope=="local-ios-external-readiness"&&(12..=509).contains(&self.head_sequence)
            &&self.reconciliation_receipt.is_none()&&uuid(authorization)&&self.readiness_receipt.as_ref().is_some_and(|p|p.valid_current(c,authorization));}
        let Some(p)=&self.reconciliation_receipt else{return false;};let(candidate,intent,observed_authorization)=p.binding();
        self.readiness_receipt.is_none()&&self.schema_version==1&&self.scope==(if c.settling(){"local-android-recovery-settlement"}else{c.platform.scope()})
            &&(if c.settling(){7}else{6}..=513).contains(&self.head_sequence)
            &&p.platform()==c.platform&&p.valid_for(&c.candidate_operation_id)&&candidate==c.candidate_sha256&&intent==c.intent_sha256
            &&uuid(authorization)&&observed_authorization==authorization
            &&p.version().name==c.saved_version.name&&p.version().build==c.saved_version.build
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
    fn valid(&self, context: &Context, authorization:&str) -> bool {
        if self.schema_version != 1 || &self.context != context || !self.context.valid() || self.lifetime.profile_calls != 0
            || self.lifetime.commands > context.platform.commands() { return false; }
        if self.outcome == Outcome::Complete {
            return self.reason == Reason::None && self.lifetime.settled() && self.lifetime.stop_observed == CoreStop::None
                && self.lifetime.commands==context.platform.commands() && self.lifetime.command_dispatched==Some(true)
                && self.result.as_ref().is_some_and(|r| r.valid(context,authorization));
        }
        if self.result.is_some() || self.reason == Reason::None
            ||self.reason==Reason::RecoverySettleUnavailable&&!context.settling()
            ||self.reason==Reason::ReconcileUnavailable&&context.settling() { return false; }
        if self.outcome == Outcome::Unknown { return self.reason == Reason::CleanupUnknown && !self.lifetime.settled(); }
        if !self.lifetime.settled() { return false; }
        match self.outcome {
            Outcome::Cancelled => self.reason == Reason::Cancelled && self.lifetime.stop_observed == CoreStop::Cancelled,
            Outcome::TimedOut => self.reason == Reason::TimedOut && self.lifetime.stop_observed == CoreStop::TimedOut,
            Outcome::Refused | Outcome::Failed => self.lifetime.stop_observed==CoreStop::None
                && !matches!(self.reason,Reason::Cancelled|Reason::TimedOut|Reason::CleanupUnknown),
            _ => false,
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Accepted { schema_version: u32, context: Context }
#[derive(Clone,Debug,PartialEq,Eq)]
pub(crate) enum Event {LeaseReady,HistoryHead(Head),RecoverySettled(Head),ExternalReady(Head)}
pub(crate) enum Frame {Accepted,Event(Event),Terminal(Terminal)}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Envelope {protocol:String,operation_id:String,owner_generation:String,nonce:String,request_sha256:String,sequence:u32,kind:String,payload:Value}
pub(crate) struct Decoder {next:u32,failed:bool,terminal:bool,head:Option<Head>,authorization:String}
impl Decoder {
    /// The caller supplies its original native-generated request authorization,
    /// not a value reconstructed from any response or renderer input.
    pub(crate) fn new(authorization:&str)->Result<Self,BridgeError>{
        if !uuid(authorization){return Err(invalid());}
        Ok(Self{next:0,failed:false,terminal:false,head:None,authorization:authorization.into()})
    }
    pub(crate) fn finish(&mut self)->bool{if !self.terminal{self.failed=true;}!self.failed}
    pub(crate) fn decode(&mut self,bytes:&[u8],operation:&str,generation:&str,context:&Context,nonce:&str,digest:&str)->Result<Frame,BridgeError>{
        if self.failed||self.terminal{return Err(BridgeError::protocol());}
        let result=(||{
            if !(3..=16*1024).contains(&bytes.len())||!bytes.ends_with(b"\n")||bytes[0]!=b'{'||bytes[bytes.len()-2]!=b'}'
                ||bytes[..bytes.len()-1].iter().any(|b|*b==b'\r'||*b==b'\n'){return Err(BridgeError::protocol());}
            let value=strict_json(&bytes[..bytes.len()-1])?;
            let e=Envelope::deserialize(&value).map_err(|_|BridgeError::protocol())?;
            if e.protocol!=PROTOCOL||e.operation_id!=operation||e.owner_generation!=generation||e.nonce!=nonce||e.request_sha256!=digest
                ||e.sequence!=self.next||self.next>=context.frame_limit() as u32||!token(operation)||!token(generation)||nonce.len()!=32||!token(nonce)||nonce=="0".repeat(32)||!sha(digest){return Err(BridgeError::protocol());}
            if e.kind=="terminal" {
                if self.next==0||!keys(&e.payload,&["schemaVersion","context","outcome","reason","result","lifetime"])
                    ||!e.payload.get("lifetime").is_some_and(|l|keys(l,&["complete","fatal","contained","commandDispatched","commands","profileCalls","inputClosed","handlersRestored","invocationClosed","stopObserved"])) {return Err(BridgeError::protocol());}
                let t=Terminal::deserialize(&e.payload).map_err(|_|BridgeError::protocol())?;
                if !t.valid(context,&self.authorization)||t.outcome==Outcome::Complete&&(self.next!=(if context.checkpointing(){4}else{3})||!self.head.as_ref().is_some_and(|h|t.result.as_ref().is_some_and(|r|r.head_sequence==h.sequence))){return Err(BridgeError::protocol());}
                self.terminal=true;return Ok(Frame::Terminal(t));
            }
            if self.next==0 {
                if e.kind!="accepted"{return Err(BridgeError::protocol());}
                let a=Accepted::deserialize(&e.payload).map_err(|_|BridgeError::protocol())?;
                if a.schema_version!=1||a.context!=*context||!a.context.valid(){return Err(BridgeError::protocol());}return Ok(Frame::Accepted);
            }
            if bytes.len()>2048{return Err(BridgeError::protocol());}
            match (self.next,e.kind.as_str()) {
                (1,"lease-ready")=>{if !keys(&e.payload,&[]){return Err(BridgeError::protocol());}Ok(Frame::Event(Event::LeaseReady))},
                (2,"history-head")=>{
                    let head=Head::deserialize(&e.payload).map_err(|_|BridgeError::protocol())?;
                    if !head.valid()||!context.head_valid(head.sequence){return Err(BridgeError::protocol());}
                    self.head=Some(head.clone());Ok(Frame::Event(Event::HistoryHead(head)))
                },
                (3,"recovery-settled") if context.settling()=>{
                    if !keys(&e.payload,&["head","phase"])||e.payload.get("phase").and_then(Value::as_str)!=Some("target-reconciled"){return Err(BridgeError::protocol());}
                    let head=Head::deserialize(&e.payload["head"]).map_err(|_|BridgeError::protocol())?;
                    if !head.valid()||!self.head.as_ref().is_some_and(|old|old.sequence<513&&head.sequence==old.sequence+1){return Err(BridgeError::protocol());}
                    self.head=Some(head.clone());Ok(Frame::Event(Event::RecoverySettled(head)))
                },
                (3,"external-ready") if context.refreshing()=>{
                    if !keys(&e.payload,&["head","phase"])||e.payload.get("phase").and_then(Value::as_str)!=Some("external-ready"){return Err(BridgeError::protocol());}
                    let head=Head::deserialize(&e.payload["head"]).map_err(|_|BridgeError::protocol())?;
                    if !head.valid()||!self.head.as_ref().is_some_and(|old|context.head_valid(old.sequence)&&head.sequence==old.sequence+1){return Err(BridgeError::protocol());}
                    self.head=Some(head.clone());Ok(Frame::Event(Event::ExternalReady(head)))
                },_=>Err(BridgeError::protocol()),
            }
        })();if result.is_err(){self.failed=true;}else{self.next+=1;}result
    }
}

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
    const UUID:&str="12345678-1234-4234-8234-123456789abc";
    const AUTH:&str="23456789-1234-4234-8234-123456789abc";
    pub(crate) fn input()->Value{let mut v=crate::local_store_prepare_protocol::tests::input();v["intentSha256"]=json!("e".repeat(64));v}
    pub(crate) fn context()->Context{prepare(&input()).unwrap().context()}
    pub(crate) fn terminal()->Value{json!({"schemaVersion":1,"context":context(),"outcome":"complete","reason":"none",
        "result":{"schemaVersion":1,"scope":"local-android-store-reconcile","headSequence":6,
            "reconciliationReceipt":{"operationId":UUID,"candidateSha256":"d".repeat(64),"intentSha256":"e".repeat(64),
                "receiptSha256":"f".repeat(64),"authorizationId":AUTH,"sourceCommit":"a".repeat(40),"sourceTree":"b".repeat(40),
                "applicationId":"dev.example.app","version":{"name":"1.2.3","build":42},
                "destination":{"channel":"internal","releaseStatus":"completed"},"observedAt":"2026-10-17T00:00:00Z",
                "result":"reconciled","limitations":LIMITATIONS,"observation":"current-internal-target-only","priorExecutionFinality":"not-established"}},
        "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":true,"commands":14,
            "profileCalls":0,"inputClosed":true,"handlersRestored":true,"invocationClosed":true,"stopObserved":"none"}})}
    fn frame(sequence:u32,kind:&str,payload:Value)->Vec<u8>{let mut bytes=serde_json::to_vec(&json!({"protocol":PROTOCOL,
        "operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"nonce":"c".repeat(32),"requestSha256":"d".repeat(64),
        "sequence":sequence,"kind":kind,"payload":payload})).unwrap();bytes.push(b'\n');bytes}
    fn read(d:&mut Decoder,sequence:u32,kind:&str,payload:Value)->Result<Frame,BridgeError>{d.decode(&frame(sequence,kind,payload),&"a".repeat(32),&"b".repeat(32),&context(),&"c".repeat(32),&"d".repeat(64))}
    fn prefix(head:u32)->Decoder{let mut d=Decoder::new(AUTH).unwrap();
        read(&mut d,0,"accepted",json!({"schemaVersion":1,"context":context()})).unwrap();
        read(&mut d,1,"lease-ready",json!({})).unwrap();
        read(&mut d,2,"history-head",json!({"sequence":head,"sha256":"a".repeat(64)})).unwrap();d}
    #[test]
    fn local_reconcile_native_request_has_new_authorization_and_no_android_tools(){
        let c=context();assert!(c.valid());assert!(crate::local_store_prepare_protocol::prepare(&input()).is_err());
        assert!(crate::local_store_execute_protocol::prepare(&input()).is_err());
        for(name,value)in[("toolchainSelection",json!({})),("authorizationId",json!(AUTH)),("intentSha256",json!("bad")),("executionMode",json!("github"))]{
            let mut v=input();v[name]=value;assert!(prepare(&v).is_err());}
        let project=RegisteredRoot{path:"/inert/project".into(),identity:crate::asset_source::ProjectIdentity::Posix(crate::asset_source::DirectoryIdentity::synthetic_evidence_identity())};
        let mut native=Native{home:"/inert/home".into(),lease_fd:3,nonce:"c".repeat(32),work_end_ns:1_200_000_000_000,hard_end_ns:1_210_000_000_000,
            authorization_id:AUTH.into(),tooling_version:crate::runtime::CORE_VERSION,tooling_commit:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
        for profile in [Profile::MacosArm64,Profile::MacosX64]{
            let bytes=request(&"a".repeat(32),&"b".repeat(32),&c,profile,&project,Path::new("/inert/runtime"),&Content{bytes:40,sha256:"a".repeat(64)},&native).unwrap();
            let value:Value=serde_json::from_slice(&bytes).unwrap();assert_eq!(value["native"]["authorizationId"],AUTH);
            assert!(value["native"].get("toolchain").is_none());assert!(value["context"].get("toolchainSelection").is_none());
        }
        native.authorization_id="renderer-id".into();assert!(!native.valid());
        for consent in [crate::local_store_prepare_protocol::CONSENT,crate::local_store_execute_protocol::CONSENT]{
            assert!(start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":consent})).is_err());}
        assert!(start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":CONSENT})).is_ok());
        assert!(raw_request(b"{\"projectId\":\"a\",\"projectId\":\"b\"}").is_err());
    }
    #[test]
    fn local_reconcile_four_frames_bind_acknowledged_head_and_readback_only(){
        for head in [6,512,513]{let mut d=prefix(head);let mut t=terminal();t["result"]["headSequence"]=json!(head);
            assert!(read(&mut d,3,"terminal",t).is_ok());assert!(d.finish());assert!(read(&mut d,3,"terminal",terminal()).is_err());}
        for bad_head in [1,5,514]{let mut d=Decoder::new(AUTH).unwrap();read(&mut d,0,"accepted",json!({"schemaVersion":1,"context":context()})).unwrap();read(&mut d,1,"lease-ready",json!({})).unwrap();
            assert!(read(&mut d,2,"history-head",json!({"sequence":bad_head,"sha256":"a".repeat(64)})).is_err());}
        let mut wrong_head=terminal();wrong_head["result"]["headSequence"]=json!(7);assert!(read(&mut prefix(6),3,"terminal",wrong_head).is_err());
        assert!(read(&mut prefix(6),3,"execute-pending",json!({"sequence":7,"sha256":"a".repeat(64)})).is_err());
        for(path,value)in[("authorizationId",json!(UUID)),("candidateSha256",json!("a".repeat(64))),("intentSha256",json!("a".repeat(64))),
            ("result",json!("accepted")),("observation",json!("current-execution-files-only")),("priorExecutionFinality",json!("established")),("rawStoreState",json!({}))]{
            let mut bad=terminal();bad["result"]["reconciliationReceipt"][path]=value;assert!(read(&mut prefix(6),3,"terminal",bad).is_err());}
        let mut d=Decoder::new(UUID).unwrap();for(seq,kind,payload)in[(0,"accepted",json!({"schemaVersion":1,"context":context()})),(1,"lease-ready",json!({})),(2,"history-head",json!({"sequence":6,"sha256":"a".repeat(64)}))]{read(&mut d,seq,kind,payload).unwrap();}
        assert!(read(&mut d,3,"terminal",terminal()).is_err());
    }
    #[test]
    fn local_reconcile_failure_prefixes_and_original_closes_are_not_promoted(){
        for count in 1..=3{let mut d=Decoder::new(AUTH).unwrap();
            read(&mut d,0,"accepted",json!({"schemaVersion":1,"context":context()})).unwrap();
            if count>1{read(&mut d,1,"lease-ready",json!({})).unwrap();}if count>2{read(&mut d,2,"history-head",json!({"sequence":6,"sha256":"a".repeat(64)})).unwrap();}
            let mut v=terminal();v["outcome"]=json!("failed");v["reason"]=json!("reconcile-unavailable");v["result"]=Value::Null;v["lifetime"]["commands"]=json!(count);
            assert!(read(&mut d,count,"terminal",v).is_ok());assert!(d.finish());}
        for field in ["complete","contained","inputClosed","handlersRestored","invocationClosed","commandDispatched"]{let mut v=terminal();v["lifetime"][field]=json!(false);assert!(read(&mut prefix(6),3,"terminal",v).is_err());}
        for count in [0,6,13,15]{let mut v=terminal();v["lifetime"]["commands"]=json!(count);assert!(read(&mut prefix(6),3,"terminal",v).is_err());}
        for(outcome,reason,stop)in[("failed","cancelled","none"),("refused","timed-out","none"),("failed","reconcile-unavailable","cancelled")]{
            let mut v=terminal();v["outcome"]=json!(outcome);v["reason"]=json!(reason);v["result"]=Value::Null;v["lifetime"]["stopObserved"]=json!(stop);
            assert!(read(&mut prefix(6),3,"terminal",v).is_err());}
        let mut unknown=terminal();unknown["outcome"]=json!("unknown");unknown["reason"]=json!("cleanup-unknown");unknown["result"]=Value::Null;
        unknown["lifetime"]["complete"]=json!(false);unknown["lifetime"]["stopObserved"]=json!("cancelled");
        assert!(read(&mut prefix(6),3,"terminal",unknown).is_ok());
    }
    fn settle_context()->Context{let mut v=input();v["settlement"]=json!("record-current-target");prepare(&v).unwrap().context()}
    fn settle_read(d:&mut Decoder,seq:u32,kind:&str,payload:Value)->Result<Frame,BridgeError>{
        d.decode(&frame(seq,kind,payload),&"a".repeat(32),&"b".repeat(32),&settle_context(),&"c".repeat(32),&"d".repeat(64))
    }
    fn settle_prefix(head:u32)->Decoder{
        let mut d=Decoder::new(AUTH).unwrap();settle_read(&mut d,0,"accepted",json!({"schemaVersion":1,"context":settle_context()})).unwrap();
        settle_read(&mut d,1,"lease-ready",json!({})).unwrap();settle_read(&mut d,2,"history-head",json!({"sequence":head,"sha256":"a".repeat(64)})).unwrap();d
    }
    fn settle_terminal(head:u32)->Value{let mut t=terminal();t["context"]=json!(settle_context());
        t["result"]["scope"]=json!("local-android-recovery-settlement");t["result"]["headSequence"]=json!(head);t}
    #[test]
    fn local_recovery_context_and_consent_cannot_upgrade_read_only_reconcile(){
        let ordinary=context();let settlement=settle_context();
        assert!(!ordinary.settling()&&settlement.settling());assert_eq!(ordinary.consent(),CONSENT);assert_eq!(settlement.consent(),SETTLEMENT_CONSENT);
        assert_eq!(ordinary.frame_limit(),4);assert_eq!(settlement.frame_limit(),5);
        for bad in [Value::Null,json!(true),json!("record"),json!({})]{let mut v=input();v["settlement"]=bad;assert!(prepare(&v).is_err());}
        let mut hybrid=json!(settlement);hybrid["operation"]=json!("local-store-reconcile");assert!(Context::deserialize(&hybrid).is_err());
        let mut null=json!(ordinary);null["settlement"]=Value::Null;assert!(Context::deserialize(&null).is_err());
        let start_value=|consent|json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":consent});
        assert!(start(&start_value(SETTLEMENT_CONSENT)).is_ok());assert!(start(&start_value("saved-ios-signed-export-v2")).is_err());
        // A live result's observation is not the offline recovery receipt.
        let r=ResultData::deserialize(&settle_terminal(7)["result"]).unwrap();assert!(r.valid(&settlement,AUTH));assert!(!r.valid(&ordinary,AUTH));
        assert!(!r.reconciliation_receipt.as_ref().unwrap().valid_recovery_review(UUID));
    }
    #[test]
    fn local_recovery_checkpoint_requires_next_head_then_five_frames_and_original_closes(){
        for before in [6,511,512]{let mut d=settle_prefix(before);
            settle_read(&mut d,3,"recovery-settled",json!({"head":{"sequence":before+1,"sha256":"b".repeat(64)},"phase":"target-reconciled"})).unwrap();
            assert!(settle_read(&mut d,4,"terminal",settle_terminal(before+1)).is_ok());assert!(d.finish());}
        assert!(settle_read(&mut settle_prefix(6),3,"terminal",settle_terminal(7)).is_err());
        for (head,phase) in [(6,"target-reconciled"),(8,"target-reconciled"),(7,"settled-success")]{
            assert!(settle_read(&mut settle_prefix(6),3,"recovery-settled",json!({"head":{"sequence":head,"sha256":"b".repeat(64)},"phase":phase})).is_err());}
        let mut d=Decoder::new(AUTH).unwrap();settle_read(&mut d,0,"accepted",json!({"schemaVersion":1,"context":settle_context()})).unwrap();
        settle_read(&mut d,1,"lease-ready",json!({})).unwrap();assert!(settle_read(&mut d,2,"history-head",json!({"sequence":513,"sha256":"a".repeat(64)})).is_err());
        for field in ["inputClosed","handlersRestored","invocationClosed"]{let mut d=settle_prefix(6);
            settle_read(&mut d,3,"recovery-settled",json!({"head":{"sequence":7,"sha256":"b".repeat(64)},"phase":"target-reconciled"})).unwrap();
            let mut t=settle_terminal(7);t["lifetime"][field]=json!(false);assert!(settle_read(&mut d,4,"terminal",t).is_err());}
        let mut failed=settle_terminal(7);failed["result"]=Value::Null;failed["outcome"]=json!("failed");failed["reason"]=json!("recovery-settle-unavailable");
        assert!(settle_read(&mut settle_prefix(6),3,"terminal",failed.clone()).is_ok());
        failed["context"]=json!(context());assert!(read(&mut prefix(6),3,"terminal",failed).is_err());
    }

    pub(crate) fn ios_context()->Context{let mut v=input();v["platform"]=json!("ios");v["confirmation"]=json!("candidate:ios:1.2.3:42");prepare(&v).unwrap().context()}
    fn ios_terminal()->Value{let mut v=terminal();v["context"]=json!(ios_context());v["lifetime"]["commands"]=json!(15);
        v["result"]["scope"]=json!("local-ios-store-reconcile");let p=v["result"]["reconciliationReceipt"].as_object_mut().unwrap();
        p.remove("applicationId");p.insert("bundleId".into(),json!("dev.example.ios-app"));p.insert("appStoreAppId".into(),json!("001234"));
        p.insert("destination".into(),json!({"channel":"testflight-internal"}));p.insert("observation".into(),json!("current-internal-build-only"));v}
    fn ios_read(d:&mut Decoder,seq:u32,kind:&str,payload:Value)->Result<Frame,BridgeError>{
        d.decode(&frame(seq,kind,payload),&"a".repeat(32),&"b".repeat(32),&ios_context(),&"c".repeat(32),&"d".repeat(64))}
    fn ios_prefix(head:u32)->Decoder{let mut d=Decoder::new(AUTH).unwrap();
        ios_read(&mut d,0,"accepted",json!({"schemaVersion":1,"context":ios_context()})).unwrap();ios_read(&mut d,1,"lease-ready",json!({})).unwrap();
        ios_read(&mut d,2,"history-head",json!({"sequence":head,"sha256":"a".repeat(64)})).unwrap();d}
    #[test]
    fn local_ios_reconcile_original_context_consent_and_request_have_no_tools_or_settlement(){
        let c=ios_context();assert!(c.valid());assert!(!c.settling());assert_eq!(c.consent(),APPLE_CONSENT);assert_eq!(c.frame_limit(),4);
        assert_eq!(Context::deserialize(&json!(c)).unwrap(),c);
        let mut v=input();v["platform"]=json!("ios");v["confirmation"]=json!("candidate:ios:1.2.3:42");assert!(prepare(&v).is_ok());
        for (key,value) in [("settlement",Value::Null),("settlement",json!("record-current-target")),("platform",Value::Null),("platform",json!("android")),
            ("platform",json!("macos")),("confirmation",json!("candidate:android:1.2.3:42")),("signingTools",json!({})),("uploadSelection",json!({})),("toolchainSelection",json!({})),("authorizationId",json!(AUTH))]{
            let mut bad=v.clone();bad[key]=value;assert!(prepare(&bad).is_err(),"{key}");}
        let mut settlement=c.clone();settlement.operation=Operation::LocalStoreRecoverySettle;settlement.settlement=Some(Settlement::RecordCurrentTarget);
        assert!(!settlement.valid()&&!settlement.settling());
        for token in [CONSENT,APPLE_CONSENT,SETTLEMENT_CONSENT]{assert!(start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":token})).is_ok());}
        assert!(context().valid());assert!(settle_context().valid());
        let project=RegisteredRoot{path:"/inert/project".into(),identity:crate::asset_source::ProjectIdentity::Posix(crate::asset_source::DirectoryIdentity::synthetic_evidence_identity())};
        let native=Native{home:"/inert/home".into(),lease_fd:3,nonce:"c".repeat(32),work_end_ns:1_200_000_000_000,hard_end_ns:1_210_000_000_000,
            authorization_id:AUTH.into(),tooling_version:crate::runtime::CORE_VERSION,tooling_commit:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
        for profile in [Profile::MacosArm64,Profile::MacosX64]{let raw=request(&"a".repeat(32),&"b".repeat(32),&c,profile,&project,Path::new("/inert/runtime"),&Content{bytes:40,sha256:"a".repeat(64)},&native).unwrap();
            let value:Value=serde_json::from_slice(&raw).unwrap();assert_eq!(value["context"]["platform"],"ios");assert_eq!(value["native"]["authorizationId"],AUTH);
            for field in ["toolchain","signingTools","uploadSelection","transportTools"]{assert!(value["native"].get(field).is_none());}}
    }
    #[test]
    fn local_ios_reconcile_four_frames_exact_receipt_and_fifteen_roles_do_not_repair_finality(){
        let good=ios_terminal();assert_eq!(good["result"]["reconciliationReceipt"].as_object().unwrap().len(),16);
        assert_eq!(serde_json::to_value(ResultData::deserialize(&good["result"]).unwrap()).unwrap(),good["result"]);
        for head in [6,512,513]{let mut d=ios_prefix(head);let mut v=good.clone();v["result"]["headSequence"]=json!(head);
            assert!(ios_read(&mut d,3,"terminal",v).is_ok());assert!(d.finish());}
        for (field,value) in [("authorizationId",json!(UUID)),("candidateSha256",json!("a".repeat(64))),("intentSha256",json!("a".repeat(64))),
            ("applicationId",json!("dev.example.app")),("appStoreAppId",json!(123)),("bundleId",json!("dev.bad_id")),("result",json!("accepted")),
            ("observation",json!("current-internal-target-only")),("observation",json!("current-recovery-files-only")),("priorExecutionFinality",json!("established"))]{
            let mut v=good.clone();v["result"]["reconciliationReceipt"][field]=value;assert!(ios_read(&mut ios_prefix(6),3,"terminal",v).is_err(),"{field}");}
        for count in [0,14,16]{let mut v=good.clone();v["lifetime"]["commands"]=json!(count);assert!(ios_read(&mut ios_prefix(6),3,"terminal",v).is_err());}
        for field in ["complete","contained","inputClosed","handlersRestored","invocationClosed","commandDispatched"]{let mut v=good.clone();v["lifetime"][field]=json!(false);assert!(ios_read(&mut ios_prefix(6),3,"terminal",v).is_err());}
        let mut v=good.clone();v["result"]["headSequence"]=json!(7);assert!(ios_read(&mut ios_prefix(6),3,"terminal",v).is_err());
        assert!(ios_read(&mut ios_prefix(6),3,"recovery-settled",json!({"head":{"sequence":7,"sha256":"a".repeat(64)},"phase":"target-reconciled"})).is_err());
        let result=ResultData::deserialize(&good["result"]).unwrap();assert!(!result.valid(&context(),AUTH));assert!(!result.reconciliation_receipt.as_ref().unwrap().valid_recovery_review(UUID));
        let mut failed=good.clone();failed["outcome"]=json!("failed");failed["reason"]=json!("reconcile-unavailable");failed["result"]=Value::Null;failed["lifetime"]["commands"]=json!(7);
        assert!(ios_read(&mut ios_prefix(6),3,"terminal",failed.clone()).is_ok());
        failed["reason"]=json!("recovery-settle-unavailable");assert!(ios_read(&mut ios_prefix(6),3,"terminal",failed).is_err());
        let mut unknown=good;unknown["outcome"]=json!("unknown");unknown["reason"]=json!("cleanup-unknown");unknown["result"]=Value::Null;unknown["lifetime"]["complete"]=json!(false);
        assert!(ios_read(&mut ios_prefix(6),3,"terminal",unknown).is_ok());
    }

    pub(crate) fn readiness_input()->Value {
        let mut v=input();v["platform"]=json!("ios");v["action"]=json!("external-readiness");
        v["confirmation"]=json!("external-testing:ios:1.2.3:42");
        v["stageOperationId"]=json!("34567890-1234-4234-8234-123456789abc");v["executionReceiptSha256"]=json!("9".repeat(64));
        v["supplementalAssignments"]=crate::local_store_prepare_protocol::tests::stage_input(true,false)["supplementalAssignments"].clone();v
    }
    pub(crate) fn readiness_context()->Context {prepare(&readiness_input()).unwrap().context()}
    pub(crate) fn readiness_terminal(head:u32)->Value {
        let mut t=ios_terminal();t["context"]=json!(readiness_context());
        let mut r=t["result"]["reconciliationReceipt"].clone();r["operationId"]=readiness_input()["stageOperationId"].clone();
        r["candidateOperationId"]=json!(UUID);r["executionReceiptSha256"]=json!("9".repeat(64));
        r["destination"]=json!({"channel":"testflight-external"});r["result"]=json!("ready");r["state"]=json!("available-to-testers");
        r["observation"]=json!("current-external-target-only");
        t["result"]=json!({"schemaVersion":1,"scope":"local-ios-external-readiness","headSequence":head,"readinessReceipt":r});t
    }
    fn readiness_read(d:&mut Decoder,seq:u32,kind:&str,payload:Value)->Result<Frame,BridgeError>{
        d.decode(&frame(seq,kind,payload),&"a".repeat(32),&"b".repeat(32),&readiness_context(),&"c".repeat(32),&"d".repeat(64))}
    fn readiness_prefix(before:u32,checkpoint:bool)->Decoder {
        let mut d=Decoder::new(AUTH).unwrap();readiness_read(&mut d,0,"accepted",json!({"schemaVersion":1,"context":readiness_context()})).unwrap();
        readiness_read(&mut d,1,"lease-ready",json!({})).unwrap();readiness_read(&mut d,2,"history-head",json!({"sequence":before,"sha256":"a".repeat(64)})).unwrap();
        if checkpoint{readiness_read(&mut d,3,"external-ready",json!({"head":{"sequence":before+1,"sha256":"b".repeat(64)},"phase":"external-ready"})).unwrap();}d
    }
    #[test]
    fn local_external_readiness_requires_explicit_original_context_and_separate_consent(){
        let v=readiness_input();let c=readiness_context();assert!(c.refreshing()&&c.checkpointing()&&!c.settling());
        assert_eq!(c.consent(),READINESS_CONSENT);assert_eq!(c.asset_stage(),crate::asset_commands::Stage::ExternalTesting);assert_eq!(c.frame_limit(),5);
        assert_eq!(Context::deserialize(&json!(c)).unwrap(),c);
        for(field,value)in[("action",Value::Null),("action",json!("recover")),("platform",json!("android")),("settlement",json!("record-current-target")),
            ("stage",json!("external-testing")),("stageOperationId",json!(UUID)),("executionReceiptSha256",json!("F".repeat(64))),
            ("confirmation",json!("candidate:ios:1.2.3:42")),("supplementalAssignments",Value::Null),("readinessReceiptSha256",json!("a".repeat(64))),
            ("signingTools",json!({})),("authorizationId",json!(AUTH))]{let mut bad=v.clone();bad[field]=value;assert!(prepare(&bad).is_err(),"{field}");}
        for field in ["action","stageOperationId","executionReceiptSha256","supplementalAssignments","platform"]{let mut bad=v.clone();bad.as_object_mut().unwrap().remove(field);assert!(prepare(&bad).is_err());}
        let mut bad=v.clone();bad["supplementalAssignments"].as_object_mut().unwrap().remove("reviewDemo");assert!(prepare(&bad).is_err());
        let mut duplicate=v.clone();duplicate["supplementalAssignments"]["commitment"]=duplicate["supplementalAssignments"]["reviewContact"].clone();assert!(prepare(&duplicate).is_err());
        assert!(context().valid()&&ios_context().valid()&&settle_context().valid());
        assert_ne!(c.consent(),ios_context().consent());assert_ne!(c.consent(),settle_context().consent());
        assert!(start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":READINESS_CONSENT})).is_ok());
        let project=RegisteredRoot{path:"/inert/project".into(),identity:crate::asset_source::ProjectIdentity::Posix(crate::asset_source::DirectoryIdentity::synthetic_evidence_identity())};
        let native=Native{home:"/inert/home".into(),lease_fd:3,nonce:"c".repeat(32),work_end_ns:1_200_000_000_000,hard_end_ns:1_210_000_000_000,
            authorization_id:AUTH.into(),tooling_version:crate::runtime::CORE_VERSION,tooling_commit:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
        for profile in [Profile::MacosArm64,Profile::MacosX64]{let raw=request(&"a".repeat(32),&"b".repeat(32),&c,profile,&project,Path::new("/inert/runtime"),&Content{bytes:40,sha256:"a".repeat(64)},&native).unwrap();
            let value:Value=serde_json::from_slice(&raw).unwrap();assert_eq!(value["context"],json!(c));assert_eq!(value["native"]["authorizationId"],AUTH);
            for field in ["toolchain","signingTools","uploadSelection"]{assert!(value["native"].get(field).is_none());}}
    }
    #[test]
    fn local_external_readiness_five_frames_bind_original_execution_and_checkpoint_closes(){
        let good=readiness_terminal(12);assert_eq!(good["result"]["readinessReceipt"].as_object().unwrap().len(),19);
        assert_eq!(serde_json::to_value(ResultData::deserialize(&good["result"]).unwrap()).unwrap(),good["result"]);
        for before in [11,507,508]{let mut d=readiness_prefix(before,true);assert!(readiness_read(&mut d,4,"terminal",readiness_terminal(before+1)).is_ok()&&d.finish());}
        for before in [6,10,509,513]{let mut d=Decoder::new(AUTH).unwrap();readiness_read(&mut d,0,"accepted",json!({"schemaVersion":1,"context":readiness_context()})).unwrap();readiness_read(&mut d,1,"lease-ready",json!({})).unwrap();
            assert!(readiness_read(&mut d,2,"history-head",json!({"sequence":before,"sha256":"a".repeat(64)})).is_err());}
        assert!(readiness_read(&mut readiness_prefix(11,false),3,"terminal",good.clone()).is_err());
        for(head,phase)in[(11,"external-ready"),(13,"external-ready"),(12,"target-reconciled")]{assert!(readiness_read(&mut readiness_prefix(11,false),3,"external-ready",json!({"head":{"sequence":head,"sha256":"b".repeat(64)},"phase":phase})).is_err());}
        for(field,value)in[("authorizationId",json!(UUID)),("operationId",json!(UUID)),("candidateOperationId",json!(AUTH)),("executionReceiptSha256",json!("8".repeat(64))),
            ("candidateSha256",json!("a".repeat(64))),("intentSha256",json!("a".repeat(64))),("state",json!("waiting-for-review")),("result",json!("reconciled")),
            ("observation",json!("current-external-readiness-files-only")),("priorExecutionFinality",json!("established"))]{
            let mut bad=good.clone();bad["result"]["readinessReceipt"][field]=value;assert!(readiness_read(&mut readiness_prefix(11,true),4,"terminal",bad).is_err(),"{field}");}
        for field in ["inputClosed","handlersRestored","invocationClosed","complete","contained"]{let mut bad=good.clone();bad["lifetime"][field]=json!(false);assert!(readiness_read(&mut readiness_prefix(11,true),4,"terminal",bad).is_err());}
        for count in [14,16]{let mut bad=good.clone();bad["lifetime"]["commands"]=json!(count);assert!(readiness_read(&mut readiness_prefix(11,true),4,"terminal",bad).is_err());}
        for field in ["reconciliationReceipt","readinessReceipt"]{let mut bad=good.clone();bad["result"][field]=Value::Null;assert!(readiness_read(&mut readiness_prefix(11,true),4,"terminal",bad).is_err());}
        let mut failed=good.clone();failed["result"]=Value::Null;failed["outcome"]=json!("failed");failed["reason"]=json!("reconcile-unavailable");
        assert!(readiness_read(&mut readiness_prefix(11,true),4,"terminal",failed).is_ok());
        let mut unknown=good;unknown["outcome"]=json!("unknown");unknown["reason"]=json!("cleanup-unknown");unknown["result"]=Value::Null;unknown["lifetime"]["complete"]=json!(false);
        assert!(readiness_read(&mut readiness_prefix(11,true),4,"terminal",unknown).is_ok());
    }

}
