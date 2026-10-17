//! Closed local Store preparation DATA; a temporary uncommitted edit is not publication authority.
//! A core terminal is provisional until this operation's original native joins.
use std::path::Path;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::{asset_source::RegisteredRoot, edit_protocol::{bounded, token}, error::BridgeError,
    protocol::{check_value, strict_json, valid_id}};

pub(crate) const PROTOCOL: &str = "mrk-local-store-prepare/1";
pub(crate) const CONSENT: &str = "local-android-store-prepare-v1";
pub(crate) const APPLE_CONSENT: &str = "local-ios-store-prepare-v1";
pub(crate) const EVENT: &str = "local-store-prepare-state-changed";
pub(crate) const IPC_LIMIT: usize = 8192;
pub(crate) const REQUEST_LIMIT: usize = 16 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 64 * 1024; // Six frames, framing and rejected drain bytes.
pub(crate) const STATUS_LIMIT: usize = 16 * 1024;

fn keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key)))
}
pub(crate) fn invalid() -> BridgeError { BridgeError::new("local_store_prepare_invalid", "The local Store preparation request is invalid.") }
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
// Prepare owns its platform type; Execute/Reconcile retain their own exact readers.
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="lowercase")]
pub(crate) enum Platform { Android, Ios }
impl Platform {
    fn name(self)->&'static str { match self {Self::Android=>"android",Self::Ios=>"ios"} }
    fn consent(self)->&'static str { match self {Self::Android=>CONSENT,Self::Ios=>APPLE_CONSENT} }
    fn commands(self)->u32 { match self {Self::Android=>14,Self::Ios=>15} }
    fn scope(self)->&'static str { match self {Self::Android=>"local-android-store-prepare",Self::Ios=>"local-ios-store-prepare"} }
}
// Explicit later-stage DATA shared with Execute/History. This is not a grant.
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
pub(crate) enum StoreStage { ExternalTesting, ProductionSubmit }
impl StoreStage {
    pub(crate) fn name(self)->&'static str {match self {Self::ExternalTesting=>"external-testing",Self::ProductionSubmit=>"production-submit"}}
    pub(crate) fn asset_stage(self)->crate::asset_commands::Stage {match self {Self::ExternalTesting=>crate::asset_commands::Stage::ExternalTesting,Self::ProductionSubmit=>crate::asset_commands::Stage::Production}}
    pub(crate) fn prepared_head(self)->u32 {match self {Self::ExternalTesting=>9,Self::ProductionSubmit=>13}}
    pub(crate) fn executed_head(self)->u32 {self.prepared_head()+2}
}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct StageRecord {pub(crate) record_id:String,pub(crate) record_revision:u32}
impl StageRecord {fn valid(&self)->bool {token(&self.record_id)&&self.record_revision>0&&self.record_revision<u32::MAX}}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct StageAssignments {
    pub(crate) review_contact:StageRecord,pub(crate) commitment:StageRecord,pub(crate) review_demo:Option<StageRecord>,
}
impl StageAssignments {
    pub(crate) fn valid(&self,primary:&str)->bool {
        let refs=[Some(&self.review_contact),Some(&self.commitment),self.review_demo.as_ref()];
        refs.iter().flatten().all(|r|r.valid()&&r.record_id!=primary)
            &&refs.iter().enumerate().all(|(i,r)|r.is_none_or(|r|refs.iter().skip(i+1).flatten().all(|s|r.record_id!=s.record_id)))
    }
    pub(crate) fn heap_bytes(&self)->Option<usize>{self.review_contact.record_id.capacity().checked_add(self.commitment.record_id.capacity())?
        .checked_add(self.review_demo.as_ref().map_or(0,|r|r.record_id.capacity()))}
}
// Context serialization flattens these exact keys. Context deserialization
// reuses the explicit request reader, so null/partial/hybrid forms cannot pass.
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct LaterStage {
    pub(crate) stage:StoreStage,pub(crate) predecessor_operation_id:String,pub(crate) predecessor_receipt_sha256:String,
    #[serde(default,skip_serializing_if="Option::is_none")] pub(crate) supplemental_assignments:Option<StageAssignments>,
}
impl LaterStage {
    pub(crate) fn valid(&self,candidate:&str,primary:&str,ios:bool)->bool {
        uuid(&self.predecessor_operation_id)&&sha(&self.predecessor_receipt_sha256)
            &&(if self.stage==StoreStage::ExternalTesting{self.predecessor_operation_id==candidate}else{self.predecessor_operation_id!=candidate})
            &&match (ios,self.supplemental_assignments.as_ref()){(true,Some(a))=>a.valid(primary),(false,None)=>true,_=>false}
    }
    pub(crate) fn operation_valid(&self,stage_operation:&str,candidate:&str)->bool {
        uuid(stage_operation)&&stage_operation!=candidate&&stage_operation!=self.predecessor_operation_id
    }
    pub(crate) fn heap_bytes(&self)->Option<usize>{self.predecessor_operation_id.capacity().checked_add(self.predecessor_receipt_sha256.capacity())?
        .checked_add(self.supplemental_assignments.as_ref().map_or(Some(0),StageAssignments::heap_bytes)?)}
}
pub(crate) fn later_request(value:&Value,fields:&[&str])->Result<Option<LaterStage>,BridgeError>{
    if value.get("stage").is_none(){return Ok(None);}
    let ios=value.get("platform").and_then(Value::as_str)==Some("ios");
    let extra=if ios{&["platform","stage","predecessorOperationId","predecessorReceiptSha256","supplementalAssignments"][..]}
        else{&["platform","stage","predecessorOperationId","predecessorReceiptSha256"][..]};
    if !keys(value,&[fields,extra].concat())||!matches!(value.get("platform").and_then(Value::as_str),Some("android"|"ios")){return Err(invalid());}
    if ios&&!value.get("supplementalAssignments").is_some_and(|a|keys(a,&["reviewContact","commitment","reviewDemo"])){return Err(invalid());}
    let mut stage=json!({"stage":value["stage"],"predecessorOperationId":value["predecessorOperationId"],"predecessorReceiptSha256":value["predecessorReceiptSha256"]});
    if ios{stage["supplementalAssignments"]=value["supplementalAssignments"].clone();}
    LaterStage::deserialize(stage).map(Some).map_err(|_|invalid())
}
pub(crate) use crate::local_release_history_protocol::Head;
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Operation { LocalStorePrepare }
fn uuid(v:&str)->bool { crate::local_release_history_protocol::journal_uuid(v) }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) project_id: String, pub(crate) draft_revision: u32, pub(crate) baseline_generation: u32,
    pub(crate) saved_config: Content, pub(crate) saved_version: crate::android_build_protocol::SavedVersion,
    pub(crate) credential_context_revision: u32, pub(crate) record_id: String, pub(crate) record_revision: u32,
    pub(crate) execution_mode: ExecutionMode, pub(crate) platform: Platform, pub(crate) operation: Operation,
    pub(crate) candidate_operation_id:String, pub(crate) candidate_sha256:String, pub(crate) confirmation:String,
    #[serde(flatten)] pub(crate) later:Option<LaterStage>,
}
impl<'de> Deserialize<'de> for Context {
    fn deserialize<D:serde::Deserializer<'de>>(decoder:D)->Result<Self,D::Error>{
        let mut value=Value::deserialize(decoder)?;
        if value.get("operation").and_then(Value::as_str)!=Some("local-store-prepare")
            ||!matches!(value.get("platform").and_then(Value::as_str),Some("android"|"ios")){return Err(serde::de::Error::custom("invalid prepare context"));}
        let map=value.as_object_mut().ok_or_else(||serde::de::Error::custom("invalid prepare context"))?;
        map.remove("operation");if !map.contains_key("stage")&&map.get("platform").and_then(Value::as_str)==Some("android"){map.remove("platform");}
        prepare(&value).map(|v|v.context()).map_err(|_|serde::de::Error::custom("invalid prepare context"))
    }
}
impl Context {
    pub(crate) fn consent(&self)->&'static str {match (self.platform,self.later.is_some()){
        (Platform::Android,true)=>"local-android-store-stage-prepare-v1",(Platform::Ios,true)=>"local-ios-store-stage-prepare-v1",_=>self.platform.consent()}}
    pub(crate) fn asset_stage(&self)->crate::asset_commands::Stage {self.later.as_ref().map_or(crate::asset_commands::Stage::Candidate,|s|s.stage.asset_stage())}
    fn valid(&self) -> bool { valid_id(&self.project_id) && self.draft_revision < u32::MAX
        && self.baseline_generation < u32::MAX && self.saved_config.valid() && self.saved_version.valid()
        && self.credential_context_revision > 0 && self.credential_context_revision < u32::MAX
        && token(&self.record_id) && self.record_revision > 0 && self.record_revision < u32::MAX
        && uuid(&self.candidate_operation_id) && sha(&self.candidate_sha256)
        && self.later.as_ref().is_none_or(|s|s.valid(&self.candidate_operation_id,&self.record_id,self.platform==Platform::Ios))
        && self.confirmation==format!("{}:{}:{}:{}",self.later.as_ref().map_or("candidate",|s|s.stage.name()),self.platform.name(),self.saved_version.name,self.saved_version.build) }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepare {
    pub(crate) project_id: String, pub(crate) draft_revision: u32, pub(crate) baseline_generation: u32,
    pub(crate) saved_config: Content, pub(crate) saved_version: crate::android_build_protocol::SavedVersion,
    pub(crate) credential_context_revision: u32, pub(crate) record_id: String, pub(crate) record_revision: u32,
    pub(crate) execution_mode: ExecutionMode,
    #[serde(default)] platform:Option<Platform>,
    #[serde(skip)] pub(crate) later:Option<LaterStage>,
    pub(crate) candidate_operation_id:String, pub(crate) candidate_sha256:String, pub(crate) confirmation:String,
}
impl Prepare {
    pub(crate) fn context(&self) -> Context { Context { project_id: self.project_id.clone(), draft_revision: self.draft_revision,
        baseline_generation: self.baseline_generation, saved_config: self.saved_config.clone(),
        saved_version: self.saved_version.clone(), credential_context_revision: self.credential_context_revision,
        record_id: self.record_id.clone(), record_revision: self.record_revision, execution_mode: self.execution_mode,
        platform: self.platform.unwrap_or(Platform::Android), operation: Operation::LocalStorePrepare, candidate_operation_id:self.candidate_operation_id.clone(),
        candidate_sha256:self.candidate_sha256.clone(),confirmation:self.confirmation.clone(),later:self.later.clone() } }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Start { pub(crate) operation_id: String, pub(crate) owner_generation: String, consent_version: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cancel { pub(crate) operation_id: String, pub(crate) owner_generation: String }
pub(crate) fn prepare(value: &Value) -> Result<Prepare, BridgeError> {
    let fields=["projectId", "draftRevision", "baselineGeneration", "savedConfig", "savedVersion",
        "credentialContextRevision", "recordId", "recordRevision", "executionMode", "candidateOperationId", "candidateSha256", "confirmation"];
    let later=later_request(value,&fields)?;
    if later.is_none()&&!keys(value,&fields) && !(keys(value,&[fields.as_slice(), &["platform"]].concat())
        && value.get("platform").and_then(Value::as_str)==Some("ios")) { return Err(invalid()); }
    let mut candidate=value.clone();
    if later.is_some(){for key in ["stage","predecessorOperationId","predecessorReceiptSha256","supplementalAssignments"]{candidate.as_object_mut().ok_or_else(invalid)?.remove(key);}}
    let mut input = Prepare::deserialize(&candidate).map_err(|_| invalid())?;input.later=later;
    if !input.context().valid() { return Err(invalid()); } Ok(input)
}
pub(crate) fn start(value: &Value) -> Result<Start, BridgeError> {
    if !keys(value, &["operationId", "ownerGeneration", "consentVersion"]) { return Err(invalid()); }
    let input = Start::deserialize(value).map_err(|_| invalid())?;
    if !token(&input.operation_id) || !token(&input.owner_generation) || !matches!(input.consent_version.as_str(),CONSENT|APPLE_CONSENT|"local-android-store-stage-prepare-v1"|"local-ios-store-stage-prepare-v1") { return Err(invalid()); } Ok(input)
}
impl Start {
    pub(crate) fn matches_context(&self,context:&Context)->bool { self.consent_version==context.consent() }
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
    if !token(operation) || context.later.is_some()&&crate::android_build_protocol::candidate_uuid(operation).is_none() || !token(generation) || !context.valid() || !credential_config.valid() || !native.valid() { return Err(invalid()); }
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
    None, PrepareUnavailable, Cancelled, ContextChanged, DocumentLost, Shutdown, TimedOut, ProtocolError, RuntimeUnavailable, IntentExpired,
    StaleIntent, SavedSourceChanged, SavedSourceInvalid, CredentialsUnavailable, QueryPrerequisites, CommandIncomplete, CleanupUnknown,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="kebab-case")]
enum Limitation {NonPublishing,PrepareNotExecute,TemporaryEditMayExpire,CurrentAscSnapshotMayChange,CurrentBundleNotHistoricalFinality,SavedInputsNotAtomic}
const LIMITATIONS:[Limitation;5]=[Limitation::NonPublishing,Limitation::PrepareNotExecute,Limitation::TemporaryEditMayExpire,Limitation::CurrentBundleNotHistoricalFinality,Limitation::SavedInputsNotAtomic];
const APPLE_LIMITATIONS:[Limitation;5]=[Limitation::NonPublishing,Limitation::PrepareNotExecute,Limitation::CurrentAscSnapshotMayChange,Limitation::CurrentBundleNotHistoricalFinality,Limitation::SavedInputsNotAtomic];
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
struct Version {name:String,build:u32}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Destination {channel:String,release_status:String}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct AndroidPreparedIntent {operation_id:String,candidate_sha256:String,intent_sha256:String,store_precondition_sha256:String,
    source_commit:String,source_tree:String,application_id:String,version:Version,destination:Destination,observed_at:String,limitations:Vec<Limitation>}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
struct AppleDestination {channel:String}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct IOSPreparedIntent {operation_id:String,candidate_sha256:String,intent_sha256:String,store_precondition_sha256:String,
    source_commit:String,source_tree:String,bundle_id:String,app_store_app_id:String,version:Version,
    destination:AppleDestination,observed_at:String,limitations:Vec<Limitation>}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct AndroidStagePrepared {
    operation_id:String,stage:StoreStage,candidate_operation_id:String,candidate_sha256:String,
    predecessor_operation_id:String,predecessor_receipt_sha256:String,intent_sha256:String,store_precondition_sha256:String,
    source_commit:String,source_tree:String,application_id:String,version:Version,destination:Destination,observed_at:String,limitations:Vec<StageLimitation>,
}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct IOSStagePrepared {
    operation_id:String,stage:StoreStage,candidate_operation_id:String,candidate_sha256:String,
    predecessor_operation_id:String,predecessor_receipt_sha256:String,intent_sha256:String,store_precondition_sha256:String,
    source_commit:String,source_tree:String,bundle_id:String,app_store_app_id:String,version:Version,destination:StageAppleDestination,observed_at:String,limitations:Vec<StageLimitation>,
}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(untagged)]
pub(crate) enum StageAppleDestination {External(StageAppleExternal),Production(StageAppleProduction)}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct StageAppleExternal {channel:String}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct StageAppleProduction {channel:String,automatic_release:bool}
impl StageAppleDestination {pub(crate) fn valid(&self,stage:StoreStage)->bool {match (stage,self){
    (StoreStage::ExternalTesting,Self::External(v))=>v.channel=="testflight-external",
    (StoreStage::ProductionSubmit,Self::Production(v))=>v.channel=="app-store-review"&&!v.automatic_release,_=>false,
}}}
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
pub(crate) enum StageLimitation {NonPublishing,PrepareNotExecute,CurrentStoreSnapshotMayChange,OriginalBinaryReused,PriorNativeFinalityNotEstablished,SavedInputsNotAtomic,NotPublicRelease}
const STAGE_PREPARE_LIMITATIONS:[StageLimitation;6]=[StageLimitation::NonPublishing,StageLimitation::PrepareNotExecute,StageLimitation::CurrentStoreSnapshotMayChange,
    StageLimitation::OriginalBinaryReused,StageLimitation::PriorNativeFinalityNotEstablished,StageLimitation::SavedInputsNotAtomic];
pub(crate) const STAGE_EXECUTE_LIMITATIONS:[StageLimitation;4]=[StageLimitation::OriginalBinaryReused,StageLimitation::NotPublicRelease,
    StageLimitation::PriorNativeFinalityNotEstablished,StageLimitation::SavedInputsNotAtomic];
pub(crate) fn stage_lineage(stage:StoreStage,operation:&str,candidate:&str,predecessor:&str,digest:&str)->bool {
    uuid(operation)&&uuid(candidate)&&uuid(predecessor)&&operation!=candidate&&operation!=predecessor&&sha(digest)
        &&if stage==StoreStage::ExternalTesting{predecessor==candidate}else{predecessor!=candidate}
}
pub(crate) fn stage_android_destination(stage:StoreStage,channel:&str,status:&str)->bool {match stage {
    StoreStage::ExternalTesting=>!channel.trim().is_empty()&&channel.chars().count()<=100&&!channel.contains(['\0','\r','\n'])
        &&!matches!(channel,"internal"|"production")&&status=="completed",
    StoreStage::ProductionSubmit=>channel=="production"&&status=="draft",
}}
pub(crate) fn stage_identity(candidate:&str,intent:&str,commit:&str,tree:&str,app:&str,ios:bool,name:&str,build:u32,date:&str)->bool {
    let hex=|v:&str,n|v.len()==n&&v.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b));
    let separator=if ios{b'-'}else{b'_'};
    sha(candidate)&&sha(intent)&&hex(commit,40)&&hex(tree,40)&&app.len()<=255&&app.split('.').count()>=2
        &&app.split('.').all(|v|v.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)&&v.bytes().all(|b|b.is_ascii_alphanumeric()||b==separator))
        &&!name.is_empty()&&name.len()<=64&&name.bytes().all(|b|b.is_ascii_alphanumeric()||b".+-".contains(&b))
        &&(1..=2_100_000_000).contains(&build)&&crate::local_store_execute_protocol::utc_second(date)
}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(untagged)]
pub(crate) enum PreparedIntent {Android(AndroidPreparedIntent),Ios(IOSPreparedIntent),AndroidStage(AndroidStagePrepared),IosStage(IOSStagePrepared)}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct ResultData {schema_version:u32,scope:String,head_sequence:u32,prepared_intent:PreparedIntent}
// Shared bounded summary DATA, not a Store/runtime/Document grant. Review uses
// this same grammar without manufacturing an earlier Prepare Context/finality.
impl PreparedIntent {
    pub(crate) fn platform(&self)->Platform {match self {Self::Android(_)|Self::AndroidStage(_)=>Platform::Android,Self::Ios(_)|Self::IosStage(_)=>Platform::Ios}}
    fn version(&self)->&Version {match self {Self::Android(p)=>&p.version,Self::Ios(p)=>&p.version,Self::AndroidStage(p)=>&p.version,Self::IosStage(p)=>&p.version}}
    fn candidate_hash(&self)->&str {match self {Self::Android(p)=>&p.candidate_sha256,Self::Ios(p)=>&p.candidate_sha256,Self::AndroidStage(p)=>&p.candidate_sha256,Self::IosStage(p)=>&p.candidate_sha256}}
    pub(crate) fn stage(&self)->Option<StoreStage>{match self{Self::AndroidStage(p)=>Some(p.stage),Self::IosStage(p)=>Some(p.stage),_=>None}}
    pub(crate) fn stage_binding(&self)->Option<(&str,&str,&str)>{match self{Self::AndroidStage(p)=>Some((&p.candidate_operation_id,&p.predecessor_operation_id,&p.predecessor_receipt_sha256)),Self::IosStage(p)=>Some((&p.candidate_operation_id,&p.predecessor_operation_id,&p.predecessor_receipt_sha256)),_=>None}}
    pub(crate) fn valid_for(&self,operation:&str)->bool {
        match self {
            Self::AndroidStage(p)=>return p.operation_id==operation&&stage_lineage(p.stage,operation,&p.candidate_operation_id,&p.predecessor_operation_id,&p.predecessor_receipt_sha256)
                &&sha(&p.store_precondition_sha256)&&stage_identity(&p.candidate_sha256,&p.intent_sha256,&p.source_commit,&p.source_tree,&p.application_id,false,&p.version.name,p.version.build,&p.observed_at)
                &&stage_android_destination(p.stage,&p.destination.channel,&p.destination.release_status)&&p.limitations==STAGE_PREPARE_LIMITATIONS,
            Self::IosStage(p)=>return p.operation_id==operation&&stage_lineage(p.stage,operation,&p.candidate_operation_id,&p.predecessor_operation_id,&p.predecessor_receipt_sha256)
                &&sha(&p.store_precondition_sha256)&&stage_identity(&p.candidate_sha256,&p.intent_sha256,&p.source_commit,&p.source_tree,&p.bundle_id,true,&p.version.name,p.version.build,&p.observed_at)
                &&(1..=20).contains(&p.app_store_app_id.len())&&p.app_store_app_id.bytes().all(|b|b.is_ascii_digit())
                &&p.destination.valid(p.stage)&&p.limitations==STAGE_PREPARE_LIMITATIONS,
            _=>{},
        }
        let (id,candidate,intent,precondition,commit,tree,app,date,limits)=match self {
            Self::Android(p)=>(&p.operation_id,&p.candidate_sha256,&p.intent_sha256,&p.store_precondition_sha256,
                &p.source_commit,&p.source_tree,&p.application_id,&p.observed_at,&p.limitations),
            Self::Ios(p)=>(&p.operation_id,&p.candidate_sha256,&p.intent_sha256,&p.store_precondition_sha256,
                &p.source_commit,&p.source_tree,&p.bundle_id,&p.observed_at,&p.limitations),
            Self::AndroidStage(_)|Self::IosStage(_)=>return false,
        };
        let version=self.version();
        let hex=|v:&str,n|v.len()==n&&v.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b));
        let separator=if self.platform()==Platform::Ios{b'-'}else{b'_'};
        let app_valid=app.len()<=255&&app.split('.').count()>=2&&app.split('.').all(|v|
            v.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)&&v.bytes().all(|b|b.is_ascii_alphanumeric()||b==separator));
        let date=date.as_bytes();
        let timestamp=date.len()==20&&date.iter().enumerate().all(|(i,b)|match i{4|7=>*b==b'-',10=>*b==b'T',13|16=>*b==b':',19=>*b==b'Z',_=>b.is_ascii_digit()});
        let destination=match self {
            Self::Android(p)=>p.destination.channel=="internal"&&p.destination.release_status=="completed"&&*limits==LIMITATIONS,
            Self::Ios(p)=>p.destination.channel=="testflight-internal"&&*limits==APPLE_LIMITATIONS
                &&(1..=20).contains(&p.app_store_app_id.len())&&p.app_store_app_id.bytes().all(|b|b.is_ascii_digit()),
            Self::AndroidStage(_)|Self::IosStage(_)=>false,
        };
        id==operation&&uuid(operation)&&sha(candidate)&&sha(intent)&&sha(precondition)&&hex(commit,40)&&hex(tree,40)
            &&app_valid&&!version.name.is_empty()&&version.name.len()<=64
            &&version.name.bytes().all(|b|b.is_ascii_alphanumeric()||b".+-".contains(&b))
            &&(1..=2_100_000_000).contains(&version.build)&&destination&&timestamp
    }
}
impl ResultData {
    fn valid(&self,c:&Context,operation:Option<&str>)->bool {
        let p=&self.prepared_intent;
        if let Some(later)=&c.later {
            let Some(id)=operation.and_then(crate::android_build_protocol::candidate_uuid)else{return false;};
            return self.schema_version==1&&self.scope==format!("local-{}-store-stage-prepare",c.platform.name())
                &&(later.stage.prepared_head()..=511).contains(&self.head_sequence)&&p.platform()==c.platform&&p.stage()==Some(later.stage)
                &&p.stage_binding()==Some((c.candidate_operation_id.as_str(),later.predecessor_operation_id.as_str(),later.predecessor_receipt_sha256.as_str()))
                &&p.valid_for(&id)&&p.candidate_hash()==c.candidate_sha256&&p.version().name==c.saved_version.name&&p.version().build==c.saved_version.build;
        }
        if p.stage().is_some(){return false;}
        self.schema_version==1&&self.scope==c.platform.scope()
            &&(if c.platform==Platform::Ios{5}else{1}..=513).contains(&self.head_sequence)
            &&p.platform()==c.platform&&p.valid_for(&c.candidate_operation_id)
            &&p.candidate_hash()==c.candidate_sha256
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
    fn valid(&self, context: &Context) -> bool {self.valid_owner(context,None)}
    fn valid_owner(&self, context:&Context,operation:Option<&str>)->bool {
        if self.schema_version != 1 || &self.context != context || !self.context.valid() || self.lifetime.profile_calls != 0
            || self.lifetime.commands > context.platform.commands() { return false; }
        if self.outcome == Outcome::Complete {
            return self.reason == Reason::None && self.lifetime.settled() && self.lifetime.stop_observed == CoreStop::None
                && self.lifetime.commands==context.platform.commands() && self.lifetime.command_dispatched==Some(true)
                && self.result.as_ref().is_some_and(|r| r.valid(context,operation));
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
#[derive(Clone,Debug,PartialEq,Eq)]
pub(crate) enum Event {LeaseReady,HistoryHead(Head),PreparePending(Head),PrepareSettled(Head)}
pub(crate) enum Frame {Accepted,Event(Event),Terminal(Terminal)}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Envelope {protocol:String,operation_id:String,owner_generation:String,nonce:String,request_sha256:String,sequence:u32,kind:String,payload:Value}
pub(crate) struct Decoder {next:u32,failed:bool,terminal:bool,head:Option<Head>}
impl Decoder {
    pub(crate) fn new()->Self{Self{next:0,failed:false,terminal:false,head:None}}
    pub(crate) fn finish(&mut self)->bool{if !self.terminal{self.failed=true;}!self.failed}
    pub(crate) fn decode(&mut self,bytes:&[u8],operation:&str,generation:&str,context:&Context,nonce:&str,digest:&str)->Result<Frame,BridgeError>{
        if self.failed||self.terminal{return Err(BridgeError::protocol());}
        let result=(||{
            if !(3..=16*1024).contains(&bytes.len())||!bytes.ends_with(b"\n")||bytes[0]!=b'{'||bytes[bytes.len()-2]!=b'}'
                ||bytes[..bytes.len()-1].iter().any(|b|*b==b'\r'||*b==b'\n'){return Err(BridgeError::protocol());}
            let value=strict_json(&bytes[..bytes.len()-1])?;
            let e=Envelope::deserialize(&value).map_err(|_|BridgeError::protocol())?;
            if e.protocol!=PROTOCOL||e.operation_id!=operation||e.owner_generation!=generation||e.nonce!=nonce||e.request_sha256!=digest
                ||e.sequence!=self.next||self.next>=6||!token(operation)||!token(generation){return Err(BridgeError::protocol());}
            if e.kind=="terminal" {
                if self.next==0||!keys(&e.payload,&["schemaVersion","context","outcome","reason","result","lifetime"])
                    ||!e.payload.get("lifetime").is_some_and(|l|keys(l,&["complete","fatal","contained","commandDispatched","commands","profileCalls","inputClosed","handlersRestored","invocationClosed","stopObserved"])) {return Err(BridgeError::protocol());}
                let t=Terminal::deserialize(&e.payload).map_err(|_|BridgeError::protocol())?;
                if !t.valid_owner(context,Some(operation))||t.outcome==Outcome::Complete&&(self.next!=5||!self.head.as_ref().is_some_and(|h|t.result.as_ref().is_some_and(|r|r.head_sequence==h.sequence))){return Err(BridgeError::protocol());}
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
                (2,"history-head")|(3,"prepare-pending")|(4,"prepare-settled")=>{
                    let body=if self.next==4 {
                        if !keys(&e.payload,&["head","phase"])||e.payload["phase"]!="prepared"{return Err(BridgeError::protocol());}&e.payload["head"]
                    }else{&e.payload};
                    let head=Head::deserialize(body).map_err(|_|BridgeError::protocol())?;
                    if !head.valid()||self.next==2&&(head.sequence>if context.later.is_some(){509}else{511}
                        ||context.later.as_ref().is_some_and(|s|head.sequence<s.stage.prepared_head()-2))||self.next>2&&!self.head.as_ref().is_some_and(|p|p.sequence<513&&head.sequence==p.sequence+1){return Err(BridgeError::protocol());}
                    self.head=Some(head.clone());Ok(Frame::Event(match self.next{2=>Event::HistoryHead(head),3=>Event::PreparePending(head),_=>Event::PrepareSettled(head)}))
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
    pub(crate) fn input()->Value{json!({"projectId":"fixture","draftRevision":1,"baselineGeneration":2,
        "savedConfig":{"bytes":100,"sha256":"a".repeat(64)},
        "savedVersion":{"source":"release/version.properties","bytes":40,"sha256":"b".repeat(64),"name":"1.2.3","build":42},
        "credentialContextRevision":3,"recordId":"c".repeat(32),"recordRevision":4,"executionMode":"local",
        "candidateOperationId":UUID,"candidateSha256":"d".repeat(64),"confirmation":"candidate:android:1.2.3:42"})}
    pub(crate) fn context()->Context{prepare(&input()).unwrap().context()}
    fn lifetime()->Value{json!({"complete":true,"fatal":false,"contained":true,"commandDispatched":true,"commands":14,
        "profileCalls":0,"inputClosed":true,"handlersRestored":true,"invocationClosed":true,"stopObserved":"none"})}
    fn complete()->Value{json!({"schemaVersion":1,"context":context(),"outcome":"complete","reason":"none",
        "result":{"schemaVersion":1,"scope":"local-android-store-prepare","headSequence":5,
            "preparedIntent":{"operationId":UUID,"candidateSha256":"d".repeat(64),"intentSha256":"e".repeat(64),
                "storePreconditionSha256":"f".repeat(64),"sourceCommit":"a".repeat(40),"sourceTree":"b".repeat(40),
                "applicationId":"dev.example.app","version":{"name":"1.2.3","build":42},
                "destination":{"channel":"internal","releaseStatus":"completed"},"observedAt":"2026-10-16T20:00:00Z","limitations":LIMITATIONS}},"lifetime":lifetime()})}
    fn frame(sequence:u32,kind:&str,payload:Value)->Vec<u8>{let mut bytes=serde_json::to_vec(&json!({"protocol":PROTOCOL,
        "operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"nonce":"c".repeat(32),"requestSha256":"d".repeat(64),
        "sequence":sequence,"kind":kind,"payload":payload})).unwrap();bytes.push(b'\n');bytes}
    fn read(decoder:&mut Decoder,bytes:&[u8])->Result<Frame,BridgeError>{decoder.decode(bytes,&"a".repeat(32),&"b".repeat(32),&context(),&"c".repeat(32),&"d".repeat(64))}
    fn frames()->Vec<Vec<u8>>{vec![frame(0,"accepted",json!({"schemaVersion":1,"context":context()})),frame(1,"lease-ready",json!({})),
        frame(2,"history-head",json!({"sequence":3,"sha256":"a".repeat(64)})),frame(3,"prepare-pending",json!({"sequence":4,"sha256":"b".repeat(64)})),
        frame(4,"prepare-settled",json!({"head":{"sequence":5,"sha256":"c".repeat(64)},"phase":"prepared"})),frame(5,"terminal",complete())]}
    fn apple_complete()->Value {
        let mut value=complete();value["context"]["platform"]=json!("ios");
        value["context"]["confirmation"]=json!("candidate:ios:1.2.3:42");
        value["result"]["scope"]=json!("local-ios-store-prepare");
        let summary=&mut value["result"]["preparedIntent"];
        summary.as_object_mut().unwrap().remove("applicationId");
        summary["bundleId"]=json!("dev.example.my-app");summary["appStoreAppId"]=json!("0012345678");
        summary["destination"]=json!({"channel":"testflight-internal"});summary["limitations"]=json!(APPLE_LIMITATIONS);
        value["lifetime"]["commands"]=json!(15);value
    }
    #[test]
    fn local_ios_prepare_requires_distinct_consent_and_closed_fifteen_call_result(){
        let mut input=input();input["platform"]=json!("ios");input["confirmation"]=json!("candidate:ios:1.2.3:42");
        let c=prepare(&input).unwrap().context();assert_eq!(c.platform,Platform::Ios);
        for field in [Value::Null,json!("android"),json!("macos")] {let mut bad=input.clone();bad["platform"]=field;assert!(prepare(&bad).is_err());}
        for token in [CONSENT,APPLE_CONSENT] {let consent=start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":token})).unwrap();
            assert_eq!(consent.matches_context(&c),token==APPLE_CONSENT);assert_eq!(consent.matches_context(&context()),token==CONSENT);}
        assert!(crate::local_store_execute_protocol::prepare(&input).is_err());
        assert!(crate::local_store_reconcile_protocol::prepare(&input).is_err());
        let value=apple_complete();let check=|v:&Value|Terminal::deserialize(v).is_ok_and(|t|t.valid(&c));
        assert!(check(&value));assert!(!Terminal::deserialize(&value).unwrap().valid(&context()));
        assert_eq!(serde_json::to_value(Terminal::deserialize(&value).unwrap()).unwrap(),value);
        for count in [0,14,16]{let mut bad=value.clone();bad["lifetime"]["commands"]=json!(count);assert!(!check(&bad));}
        for(field,v)in[("applicationId",json!("dev.example.app")),("appStoreAppId",Value::Null),("appStoreAppId",json!(123)),
            ("appStoreAppId",json!("1".repeat(21))),("appStoreAppId",json!("-1")),("bundleId",json!("dev.bad_name")),
            ("destination",json!({"channel":"testflight-internal","releaseStatus":"completed"})),("limitations",json!(LIMITATIONS))]{
            let mut bad=value.clone();bad["result"]["preparedIntent"][field]=v;assert!(!check(&bad),"{field}");}
        let mut bad=value.clone();bad["result"]["headSequence"]=json!(4);assert!(!check(&bad));
        let mut d=Decoder::new();for (sequence,raw) in frames().iter().enumerate(){
            let mut row:Value=serde_json::from_slice(raw).unwrap();
            if sequence==0{row["payload"]["context"]=json!(c);}
            if sequence==5{row["payload"]=value.clone();}
            let mut bytes=serde_json::to_vec(&row).unwrap();bytes.push(b'\n');
            d.decode(&bytes,&"a".repeat(32),&"b".repeat(32),&c,&"c".repeat(32),&"d".repeat(64)).unwrap();
        }assert!(d.finish());
    }
    #[test]
    fn local_prepare_requires_exact_candidate_consent_not_access_or_execute(){
        let c=context();assert!(c.valid());
        for(name,value)in[("executionMode",json!("github")),("authorizationId",json!(UUID)),("candidateOperationId",json!("a".repeat(32))),
            ("candidateSha256",json!("bad")),("confirmation",json!("production:android:1.2.3:42")),("recordRevision",json!(0))]{
            let mut v=input();v[name]=value;assert!(prepare(&v).is_err());
        }
        for token in [crate::local_store_preflight_protocol::CONSENT,"local-android-release-execute-v1"]{
            assert!(start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":token})).is_err());
        }
        assert!(start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":CONSENT})).is_ok());
        assert!(raw_request(b"{\"projectId\":\"a\",\"projectId\":\"b\"}").is_err());
        assert!(crate::local_store_preflight_protocol::prepare(&input()).is_err());
        // Same canonical UUID4 grammar as the authenticated journal, not a permissive parser.
        for id in ["", "12345678123442348234123456789abc", "12345678-1234-1234-8234-123456789abc",
            "12345678-1234-4234-7234-123456789abc", "12345678-1234-4234-8234-123456789ABC",
            "12345678-1234-4234-8234-123456789abé"] {
            let mut bad=input();bad["candidateOperationId"]=json!(id);assert!(prepare(&bad).is_err());
        }
    }
    #[test]
    fn local_prepare_decoder_requires_original_order_and_final_checkpoint(){
        let rows=frames();let mut d=Decoder::new();for row in &rows{assert!(read(&mut d,row).is_ok());}assert!(d.finish());assert!(read(&mut d,&rows[5]).is_err());
        for missing in 1..=4{let mut d=Decoder::new();let mut refused=false;for(i,row)in rows.iter().enumerate(){if i!=missing&&read(&mut d,row).is_err(){refused=true;break;}}assert!(refused);}
        for(sequence,kind,payload)in[(2,"history-head",json!({"sequence":512,"sha256":"a".repeat(64)})),
            (3,"prepare-pending",json!({"sequence":5,"sha256":"b".repeat(64)})),
            (4,"prepare-settled",json!({"head":{"sequence":5,"sha256":"c".repeat(64)},"phase":"settled-failure"}))]{
            let mut d=Decoder::new();for row in rows.iter().take(sequence as usize){read(&mut d,row).unwrap();}
            assert!(read(&mut d,&frame(sequence,kind,payload)).is_err());assert!(read(&mut d,&rows[sequence as usize]).is_err());
        }
        let mut d=Decoder::new();let mut bad:Value=serde_json::from_slice(&rows[0]).unwrap();bad["nonce"]=json!("e".repeat(32));let mut bytes=serde_json::to_vec(&bad).unwrap();bytes.push(b'\n');assert!(read(&mut d,&bytes).is_err());
    }
    #[test]
    fn local_prepare_success_binds_candidate_version_ledger_and_known_closes(){
        let c=context();assert!(Terminal::deserialize(&complete()).unwrap().valid(&c));
        for name in ["complete","contained","inputClosed","handlersRestored","invocationClosed","commandDispatched"]{
            let mut bad=complete();bad["lifetime"][name]=json!(false);assert!(!Terminal::deserialize(&bad).unwrap().valid(&c));
        }
        for count in [0,6,13,15]{let mut bad=complete();bad["lifetime"]["commands"]=json!(count);assert!(!Terminal::deserialize(&bad).unwrap().valid(&c));}
        for(path,value)in[("candidateSha256",json!("a".repeat(64))),("operationId",json!("23456789-1234-4234-8234-123456789abc")),("sourceTree",json!("bad"))]{
            let mut bad=complete();bad["result"]["preparedIntent"][path]=value;assert!(!Terminal::deserialize(&bad).unwrap().valid(&c));
        }
        let mut bad=complete();bad["result"]["preparedIntent"]["version"]["build"]=json!(43);assert!(!Terminal::deserialize(&bad).unwrap().valid(&c));
        let mut bad=complete();bad["result"]["preparedIntent"]["destination"]["channel"]=json!("production");assert!(!Terminal::deserialize(&bad).unwrap().valid(&c));
        let mut bad=complete();bad["result"]["preparedIntent"]["rawStoreState"]=json!({});assert!(Terminal::deserialize(&bad).is_err());
        let mut bad=complete();bad["result"]["headSequence"]=json!(4);let mut d=Decoder::new();for row in frames().iter().take(5){read(&mut d,row).unwrap();}assert!(read(&mut d,&frame(5,"terminal",bad)).is_err());
    }
    #[test]
    fn local_prepare_known_failed_prefix_never_requires_or_fakes_settlement_phase(){
        let rows=frames();for prefix in 1..=4{
            let mut d=Decoder::new();for row in rows.iter().take(prefix){read(&mut d,row).unwrap();}
            let mut failure=complete();failure["outcome"]=json!("failed");failure["reason"]=json!("prepare-unavailable");failure["result"]=Value::Null;failure["lifetime"]["commands"]=json!(prefix);
            assert!(read(&mut d,&frame(prefix as u32,"terminal",failure)).is_ok());assert!(d.finish());
        }
        let mut missing=complete();missing.as_object_mut().unwrap().remove("result");let mut d=Decoder::new();read(&mut d,&rows[0]).unwrap();assert!(read(&mut d,&frame(1,"terminal",missing)).is_err());
    }
    pub(crate) const STAGE_ID:&str="22345678-1234-4234-8234-123456789abc";
    pub(crate) fn stage_input(ios:bool,production:bool)->Value {
        let mut v=input();let stage=if production{"production-submit"}else{"external-testing"};let platform=if ios{"ios"}else{"android"};
        v["platform"]=json!(platform);v["stage"]=json!(stage);v["confirmation"]=json!(format!("{stage}:{platform}:1.2.3:42"));
        v["predecessorOperationId"]=json!(if production{"32345678-1234-4234-8234-123456789abc"}else{UUID});v["predecessorReceiptSha256"]=json!("a".repeat(64));
        if ios{v["supplementalAssignments"]=json!({"reviewContact":{"recordId":"e".repeat(32),"recordRevision":2},"commitment":{"recordId":"f".repeat(32),"recordRevision":3},"reviewDemo":null});}v
    }
    pub(crate) fn stage_complete(ios:bool,production:bool)->Value {
        let c=prepare(&stage_input(ios,production)).unwrap().context();let mut v=if ios{apple_complete()}else{complete()};
        v["context"]=json!(c);v["result"]["scope"]=json!(format!("local-{}-store-stage-prepare",if ios{"ios"}else{"android"}));
        v["result"]["headSequence"]=json!(if production{13}else{9});let p=&mut v["result"]["preparedIntent"];
        p["operationId"]=json!(STAGE_ID);p["stage"]=json!(c.later.as_ref().unwrap().stage);p["candidateOperationId"]=json!(UUID);
        p["predecessorOperationId"]=json!(c.later.as_ref().unwrap().predecessor_operation_id);p["predecessorReceiptSha256"]=json!("a".repeat(64));p["limitations"]=json!(STAGE_PREPARE_LIMITATIONS);
        p["destination"]=if ios{if production{json!({"channel":"app-store-review","automaticRelease":false})}else{json!({"channel":"testflight-external"})}}
            else if production{json!({"channel":"production","releaseStatus":"draft"})}else{json!({"channel":"Closed testing team","releaseStatus":"completed"})};v
    }
    #[test]
    fn local_stage_prepare_explicit_lineage_and_original_uuid_never_widen_candidate(){
        for ios in [false,true]{for production in [false,true]{
            let input=stage_input(ios,production);let c=prepare(&input).unwrap().context();assert!(c.valid());
            assert_eq!(Context::deserialize(json!(c)).unwrap(),c);assert!(c.later.is_some());
            let consent=start(&json!({"operationId":STAGE_ID.replace('-',""),"ownerGeneration":"a".repeat(32),"consentVersion":c.consent()})).unwrap();assert!(consent.matches_context(&c));assert!(!consent.matches_context(&context()));
            for key in ["stage","platform","predecessorOperationId","predecessorReceiptSha256"]{let mut bad=input.clone();bad.as_object_mut().unwrap().remove(key);assert!(prepare(&bad).is_err(),"{key}");}
            for(key,value)in[("stage",json!("candidate")),("stageOperationId",json!(STAGE_ID)),("authorizationId",json!(STAGE_ID)),("toolchainSelection",json!({}))]{let mut bad=input.clone();bad[key]=value;assert!(prepare(&bad).is_err());}
            let value=stage_complete(ios,production);let t=Terminal::deserialize(&value).unwrap();assert!(!t.valid(&c));
            assert!(t.valid_owner(&c,Some(&STAGE_ID.replace('-',""))));assert!(!t.valid_owner(&c,Some(&"a".repeat(32))));
            let mut bad=value.clone();bad["result"]["preparedIntent"]["operationId"]=json!("42345678-1234-4234-8234-123456789abc");assert!(!Terminal::deserialize(bad).unwrap().valid_owner(&c,Some(&STAGE_ID.replace('-',""))));
        }}
        let mut hybrid=input();hybrid["platform"]=json!("android");assert!(prepare(&hybrid).is_err());
        let mut ios=stage_input(true,false);ios["supplementalAssignments"].as_object_mut().unwrap().remove("reviewDemo");assert!(prepare(&ios).is_err());
    }
    #[test]
    fn local_stage_prepare_actual_decoder_requires_room_and_all_four_acks(){
        let c=prepare(&stage_input(false,false)).unwrap().context();let operation=STAGE_ID.replace('-',"");
        let data=stage_complete(false,false);let mut rows=frames();
        for(i,raw)in rows.iter_mut().enumerate(){let mut v:Value=serde_json::from_slice(raw).unwrap();v["operationId"]=json!(operation);
            if i==0{v["payload"]["context"]=json!(c);}if i==2{v["payload"]["sequence"]=json!(7);}if i==3{v["payload"]["sequence"]=json!(8);}if i==4{v["payload"]["head"]["sequence"]=json!(9);}if i==5{v["payload"]=data.clone();}
            *raw=serde_json::to_vec(&v).unwrap();raw.push(b'\n');}
        let read=|d:&mut Decoder,b:&[u8]|d.decode(b,&operation,&"b".repeat(32),&c,&"c".repeat(32),&"d".repeat(64));
        let mut d=Decoder::new();for r in &rows{read(&mut d,r).unwrap();}assert!(d.finish());
        for first in [6,510,511]{let mut d=Decoder::new();read(&mut d,&rows[0]).unwrap();read(&mut d,&rows[1]).unwrap();
            let mut v:Value=serde_json::from_slice(&rows[2]).unwrap();v["payload"]["sequence"]=json!(first);let mut bytes=serde_json::to_vec(&v).unwrap();bytes.push(b'\n');assert!(read(&mut d,&bytes).is_err());}
        let mut d=Decoder::new();for r in rows.iter().take(4){read(&mut d,r).unwrap();}assert!(read(&mut d,&rows[5]).is_err());
    }

}
