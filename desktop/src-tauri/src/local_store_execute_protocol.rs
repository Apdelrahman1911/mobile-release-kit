//! Closed local Store execution DATA; only the genuine current native owner grants an action.
//! A core terminal is provisional until this operation's original native joins.
use std::path::Path;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::{asset_source::RegisteredRoot, edit_protocol::{bounded, token}, error::BridgeError,
    protocol::{check_value, strict_json, valid_id}};

pub(crate) const PROTOCOL: &str = "mrk-local-store-execute/1";
pub(crate) const CONSENT: &str = "local-android-store-execute-v1";
pub(crate) const APPLE_CONSENT: &str = "local-ios-store-execute-v1";
pub(crate) const EVENT: &str = "local-store-execute-state-changed";
pub(crate) const IPC_LIMIT: usize = 16 * 1024;
pub(crate) const REQUEST_LIMIT: usize = 16 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 64 * 1024; // Six frames, framing and rejected drain bytes.
pub(crate) const STATUS_LIMIT: usize = 16 * 1024;

fn keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key)))
}
pub(crate) fn invalid() -> BridgeError { BridgeError::new("local_store_execute_invalid", "The local Store execution request is invalid.") }
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
// Execute-only selection: no widening of other Store domains.
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="lowercase")]
pub(crate) enum Platform {Android,Ios}
impl Platform {
    fn name(self)->&'static str {match self {Self::Android=>"android",Self::Ios=>"ios"}}
    fn consent(self)->&'static str {match self {Self::Android=>CONSENT,Self::Ios=>APPLE_CONSENT}}
    fn commands(self)->u32 {match self {Self::Android=>14,Self::Ios=>16}}
    fn scope(self)->&'static str {match self {Self::Android=>"local-android-store-execute",Self::Ios=>"local-ios-store-execute"}}
}
pub(crate) use crate::local_store_prepare_protocol::{LaterStage,StoreStage};
pub(crate) use crate::local_release_history_protocol::Head;
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Operation { LocalStoreExecute }
fn uuid(v:&str)->bool { crate::local_release_history_protocol::journal_uuid(v) }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) project_id: String, pub(crate) draft_revision: u32, pub(crate) baseline_generation: u32,
    pub(crate) saved_config: Content, pub(crate) saved_version: crate::android_build_protocol::SavedVersion,
    pub(crate) credential_context_revision: u32, pub(crate) record_id: String, pub(crate) record_revision: u32,
    pub(crate) execution_mode: ExecutionMode, pub(crate) platform: Platform, pub(crate) operation: Operation,
    pub(crate) candidate_operation_id:String, pub(crate) candidate_sha256:String, pub(crate) confirmation:String,
    pub(crate) intent_sha256:String,
    #[serde(flatten)] pub(crate) later:Option<LaterStage>,
    #[serde(default,skip_serializing_if="Option::is_none")] pub(crate) stage_operation_id:Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub(crate) toolchain_selection:Option<crate::android_build_protocol::MacToolchainSelection>,
}
impl<'de> Deserialize<'de> for Context {
    fn deserialize<D:serde::Deserializer<'de>>(decoder:D)->Result<Self,D::Error>{
        let mut value=Value::deserialize(decoder)?;
        if value.get("operation").and_then(Value::as_str)!=Some("local-store-execute")
            ||!matches!(value.get("platform").and_then(Value::as_str),Some("android"|"ios")){return Err(serde::de::Error::custom("invalid execute context"));}
        let map=value.as_object_mut().ok_or_else(||serde::de::Error::custom("invalid execute context"))?;
        map.remove("operation");if !map.contains_key("stage")&&map.get("platform").and_then(Value::as_str)==Some("android"){map.remove("platform");}
        prepare(&value).map(|v|v.context()).map_err(|_|serde::de::Error::custom("invalid execute context"))
    }
}
impl Context {
    pub(crate) fn consent(&self)->&'static str {match (self.platform,self.later.is_some()){
        (Platform::Android,true)=>"local-android-store-stage-execute-v1",(Platform::Ios,true)=>"local-ios-store-stage-execute-v1",_=>self.platform.consent()}}
    pub(crate) fn asset_stage(&self)->crate::asset_commands::Stage {self.later.as_ref().map_or(crate::asset_commands::Stage::Candidate,|s|s.stage.asset_stage())}
    fn commands(&self)->u32 {if self.later.is_some()&&self.platform==Platform::Ios{15}else{self.platform.commands()}}
    fn valid(&self) -> bool { valid_id(&self.project_id) && self.draft_revision < u32::MAX
        && self.baseline_generation < u32::MAX && self.saved_config.valid() && self.saved_version.valid()
        && self.credential_context_revision > 0 && self.credential_context_revision < u32::MAX
        && token(&self.record_id) && self.record_revision > 0 && self.record_revision < u32::MAX
        && uuid(&self.candidate_operation_id) && sha(&self.candidate_sha256) && sha(&self.intent_sha256)
        && match &self.later {
            Some(s)=>self.toolchain_selection.is_none()&&s.valid(&self.candidate_operation_id,&self.record_id,self.platform==Platform::Ios)
                &&self.stage_operation_id.as_deref().is_some_and(|id|s.operation_valid(id,&self.candidate_operation_id)),
            None=>self.stage_operation_id.is_none()&&match self.platform{Platform::Android=>self.toolchain_selection.as_ref().is_some_and(|v|v.valid()),Platform::Ios=>self.toolchain_selection.is_none()},
        }
        && self.confirmation==format!("{}:{}:{}:{}",self.later.as_ref().map_or("candidate",|s|s.stage.name()),self.platform.name(),self.saved_version.name,self.saved_version.build) }
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
    #[serde(default)] platform:Option<Platform>,
    #[serde(skip)] pub(crate) later:Option<LaterStage>,
    #[serde(default)] pub(crate) stage_operation_id:Option<String>,
    #[serde(default)] pub(crate) toolchain_selection:Option<crate::android_build_protocol::MacToolchainSelection>,
}
impl Prepare {
    pub(crate) fn context(&self) -> Context { Context { project_id: self.project_id.clone(), draft_revision: self.draft_revision,
        baseline_generation: self.baseline_generation, saved_config: self.saved_config.clone(),
        saved_version: self.saved_version.clone(), credential_context_revision: self.credential_context_revision,
        record_id: self.record_id.clone(), record_revision: self.record_revision, execution_mode: self.execution_mode,
        platform: self.platform.unwrap_or(Platform::Android), operation: Operation::LocalStoreExecute, candidate_operation_id:self.candidate_operation_id.clone(),
        candidate_sha256:self.candidate_sha256.clone(),confirmation:self.confirmation.clone(),
        intent_sha256:self.intent_sha256.clone(),toolchain_selection:self.toolchain_selection.clone(),later:self.later.clone(),stage_operation_id:self.stage_operation_id.clone() } }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Start { pub(crate) operation_id: String, pub(crate) owner_generation: String, consent_version: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cancel { pub(crate) operation_id: String, pub(crate) owner_generation: String }
pub(crate) fn prepare(value: &Value) -> Result<Prepare, BridgeError> {
    let fields=["projectId","draftRevision","baselineGeneration","savedConfig","savedVersion",
        "credentialContextRevision","recordId","recordRevision","executionMode","candidateOperationId","candidateSha256","confirmation","intentSha256"];
    let later=crate::local_store_prepare_protocol::later_request(value,&[fields.as_slice(),&["stageOperationId"]].concat()).map_err(|_|invalid())?;
    if later.is_none()&&!keys(value,&[fields.as_slice(), &["toolchainSelection"]].concat())
        && !(keys(value,&[fields.as_slice(), &["platform"]].concat())&&value.get("platform").and_then(Value::as_str)==Some("ios")) {return Err(invalid());}
    let mut candidate=value.clone();
    if later.is_some(){for key in ["stage","predecessorOperationId","predecessorReceiptSha256","supplementalAssignments"]{candidate.as_object_mut().ok_or_else(invalid)?.remove(key);}}
    let mut input = Prepare::deserialize(&candidate).map_err(|_| invalid())?;input.later=later;
    if !input.context().valid() { return Err(invalid()); } Ok(input)
}
pub(crate) fn start(value: &Value) -> Result<Start, BridgeError> {
    if !keys(value, &["operationId", "ownerGeneration", "consentVersion"]) { return Err(invalid()); }
    let input = Start::deserialize(value).map_err(|_| invalid())?;
    if !token(&input.operation_id) || !token(&input.owner_generation) || !matches!(input.consent_version.as_str(),CONSENT|APPLE_CONSENT|"local-android-store-stage-execute-v1"|"local-ios-store-stage-execute-v1") { return Err(invalid()); } Ok(input)
}
impl Start {pub(crate) fn matches_context(&self,context:&Context)->bool{self.consent_version==context.consent()}}
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
#[derive(Clone,Debug,Serialize)]
#[serde(rename_all="camelCase")]
pub(crate) struct UploadSelection {
    schema_version:u32,developer_directory:String,
    app_identity:crate::ios_archive_protocol::RootIdentity,developer_identity:crate::ios_archive_protocol::RootIdentity,
    xcrun:crate::ios_archive_protocol::ToolIdentity,
}
impl UploadSelection {
    pub(crate) fn new_data(path:&Path,app:crate::ios_archive_protocol::RootIdentity,developer:crate::ios_archive_protocol::RootIdentity,
        xcrun:crate::ios_archive_protocol::ToolIdentity)->Result<Self,BridgeError>{
        let directory=native_path(path).ok_or_else(invalid)?;
        if !crate::ios_toolchain::upload_developer(directory){return Err(invalid());}
        let root=|v:&crate::ios_archive_protocol::RootIdentity|v.valid()&&v.uid==0&&v.mode&0o022==0;
        // Existing fixed system-tool validator; no new permissive tool grammar.
        if !xcrun.valid()||xcrun.uid!=0||xcrun.mode&0o022!=0||!root(&app)||!root(&developer){return Err(invalid());}
        Ok(Self{schema_version:1,developer_directory:directory.into(),app_identity:app,developer_identity:developer,xcrun})
    }
}
#[derive(Clone,Debug)]
pub(crate) enum NativeTools {
    Stage,
    Android(crate::android_build_protocol::ToolchainBinding),
    Ios{signing_tools:crate::ios_archive_protocol::SigningToolBindings,upload_selection:UploadSelection},
}
pub(crate) struct Native {pub(crate) home:std::path::PathBuf,pub(crate) lease_fd:u32,pub(crate) nonce:String,
    pub(crate) work_end_ns:u64,pub(crate) hard_end_ns:u64,pub(crate) authorization_id:String,
    pub(crate) tooling_version:&'static str,pub(crate) tooling_commit:&'static str,
    pub(crate) tools:NativeTools}
impl Native {fn valid(&self)->bool{(3..=255).contains(&self.lease_fd)&&self.nonce.len()==32&&token(&self.nonce)&&self.nonce!="0".repeat(32)
    &&self.work_end_ns>0&&self.hard_end_ns>self.work_end_ns&&self.hard_end_ns-self.work_end_ns<=10_000_000_000
    &&uuid(&self.authorization_id)&&self.tooling_version==crate::runtime::CORE_VERSION&&self.tooling_commit.len()==40
    &&self.tooling_commit.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}}
pub(crate) fn request(operation: &str, generation: &str, context: &Context, profile: Profile,
    project: &RegisteredRoot, cwd: &Path, credential_config: &Content, native:&Native) -> Result<Vec<u8>, BridgeError> {
    if !token(operation) || !token(generation) || !context.valid() || !credential_config.valid() || !native.valid() { return Err(invalid()); }
    let tools_profile=match profile {Profile::MacosArm64=>crate::android_build_protocol::Profile::MacArm64,Profile::MacosX64=>crate::android_build_protocol::Profile::MacX64};
    match (&native.tools,context.platform,context.toolchain_selection.as_ref(),context.later.is_some()) {
        (NativeTools::Stage,_,None,true)=>{},
        (NativeTools::Android(binding),Platform::Android,Some(selected),false) if binding.matches_selection(tools_profile,selected)=>{},
        (NativeTools::Ios{..},Platform::Ios,None,false)=>{},_=>return Err(invalid()),
    }
    let identity = project.identity.posix().map_err(|_| invalid())?.preflight_identity();
    if !decimal(&identity.device) || !decimal(&identity.inode) || identity.inode == "0" || identity.mode & 0o170000 != 0o040000 { return Err(invalid()); }
    let mut value = json!({"protocol":PROTOCOL,"operationId":operation,"ownerGeneration":generation,"context":context,
        "native":{"profile":profile,"projectRoot":native_path(&project.path).ok_or_else(invalid)?,
            "rootIdentity":identity,"cwd":native_path(cwd).ok_or_else(invalid)?,"credentialConfig":credential_config,
            "home":native_path(&native.home).ok_or_else(invalid)?,"leaseFd":native.lease_fd,"nonce":native.nonce,
            "clock":{"workEndNs":native.work_end_ns.to_string(),"hardEndNs":native.hard_end_ns.to_string()},
            "authorizationId":native.authorization_id,"tooling":{"version":native.tooling_version,"commit":native.tooling_commit}}});
    match &native.tools {
        NativeTools::Stage=>{},
        NativeTools::Android(binding)=>value["native"]["toolchain"]=json!(binding),
        NativeTools::Ios{signing_tools,upload_selection}=>{value["native"]["signingTools"]=json!(signing_tools);value["native"]["uploadSelection"]=json!(upload_selection);},
    }
    check_value(&value).map_err(|_| invalid())?;
    let mut bytes = bounded(&value, REQUEST_LIMIT - 1).map_err(|_| invalid())?;
    bytes.push(b'\n'); Ok(bytes)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None, ExecuteUnavailable, Cancelled, ContextChanged, DocumentLost, Shutdown, TimedOut, ProtocolError, RuntimeUnavailable, IntentExpired,
    StaleIntent, SavedSourceChanged, SavedSourceInvalid, CredentialsUnavailable, QueryPrerequisites, CommandIncomplete, CleanupUnknown,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="kebab-case")]
enum Limitation {InternalTestingOnly,NotPublicRelease,PriorPrepareFinalityNotEstablished,SavedInputsNotAtomic}
const LIMITATIONS:[Limitation;4]=[Limitation::InternalTestingOnly,Limitation::NotPublicRelease,Limitation::PriorPrepareFinalityNotEstablished,Limitation::SavedInputsNotAtomic];
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
struct Version {name:String,build:u32}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Destination {channel:String,release_status:String}
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
enum ReceiptResult {Accepted,Reconciled}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct AndroidExecutionReceipt {operation_id:String,candidate_sha256:String,intent_sha256:String,receipt_sha256:String,authorization_id:String,
    source_commit:String,source_tree:String,application_id:String,version:Version,destination:Destination,observed_at:String,result:ReceiptResult,limitations:Vec<Limitation>}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct AppleDestination {channel:String}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct IosExecutionReceipt {operation_id:String,candidate_sha256:String,intent_sha256:String,receipt_sha256:String,authorization_id:String,
    source_commit:String,source_tree:String,bundle_id:String,app_store_app_id:String,version:Version,destination:AppleDestination,observed_at:String,result:ReceiptResult,limitations:Vec<Limitation>}
use crate::local_store_prepare_protocol::{StageAppleDestination,StageLimitation,STAGE_EXECUTE_LIMITATIONS,stage_identity,stage_lineage,stage_android_destination};
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
enum StageState {AvailableToTesters,Draft,SubmittedForReview,InReview,Approved,PendingDeveloperRelease}
impl StageState {fn valid(self,stage:StoreStage,ios:bool)->bool {match (ios,stage){
    (false,StoreStage::ExternalTesting)=>self==Self::AvailableToTesters,(false,StoreStage::ProductionSubmit)=>self==Self::Draft,
    (true,StoreStage::ExternalTesting)=>matches!(self,Self::AvailableToTesters|Self::SubmittedForReview|Self::InReview|Self::Approved),
    (true,StoreStage::ProductionSubmit)=>matches!(self,Self::SubmittedForReview|Self::InReview|Self::Approved|Self::PendingDeveloperRelease),
}}}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct AndroidStageExecution {
    operation_id:String,stage:StoreStage,candidate_operation_id:String,candidate_sha256:String,
    predecessor_operation_id:String,predecessor_receipt_sha256:String,intent_sha256:String,receipt_sha256:String,authorization_id:String,
    source_commit:String,source_tree:String,application_id:String,version:Version,destination:Destination,observed_at:String,
    result:ReceiptResult,state:StageState,limitations:Vec<StageLimitation>,
}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct IOSStageExecution {
    operation_id:String,stage:StoreStage,candidate_operation_id:String,candidate_sha256:String,
    predecessor_operation_id:String,predecessor_receipt_sha256:String,intent_sha256:String,receipt_sha256:String,authorization_id:String,
    source_commit:String,source_tree:String,bundle_id:String,app_store_app_id:String,version:Version,destination:StageAppleDestination,observed_at:String,
    result:ReceiptResult,state:StageState,limitations:Vec<StageLimitation>,
}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(untagged)]
pub(crate) enum ExecutionReceipt {Android(AndroidExecutionReceipt),Ios(IosExecutionReceipt),AndroidStage(AndroidStageExecution),IosStage(IOSStageExecution)}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct ResultData {schema_version:u32,scope:String,head_sequence:u32,execution_receipt:ExecutionReceipt}
pub(crate) fn utc_second(value:&str)->bool{
    let d=value.as_bytes();
    if d.len()!=20||!d.iter().enumerate().all(|(i,b)|match i{4|7=>*b==b'-',10=>*b==b'T',13|16=>*b==b':',19=>*b==b'Z',_=>b.is_ascii_digit()}){return false;}
    let n=|a:usize,b:usize|d[a..b].iter().fold(0u32,|v,c|v*10+u32::from(c-b'0'));
    let y=n(0,4);let m=n(5,7);let days=match m{1|3|5|7|8|10|12=>31,4|6|9|11=>30,2=>if y%4==0&&(y%100!=0||y%400==0){29}else{28},_=>0};
    y>=1&&(1..=days).contains(&n(8,10))&&n(11,13)<24&&n(14,16)<60&&n(17,19)<60
}
// Closed summary DATA shared with read-only History. It is not an Execute
// Context, original authorization comparison or native completion observation.
impl ExecutionReceipt {
    pub(crate) fn platform(&self)->Platform {match self {Self::Android(_)|Self::AndroidStage(_)=>Platform::Android,Self::Ios(_)|Self::IosStage(_)=>Platform::Ios}}
    fn version(&self)->&Version {match self {Self::Android(p)=>&p.version,Self::Ios(p)=>&p.version,Self::AndroidStage(p)=>&p.version,Self::IosStage(p)=>&p.version}}
    fn binding(&self)->(&str,&str,&str) {match self {Self::Android(p)=>(&p.candidate_sha256,&p.intent_sha256,&p.authorization_id),Self::Ios(p)=>(&p.candidate_sha256,&p.intent_sha256,&p.authorization_id),Self::AndroidStage(p)=>(&p.candidate_sha256,&p.intent_sha256,&p.authorization_id),Self::IosStage(p)=>(&p.candidate_sha256,&p.intent_sha256,&p.authorization_id)}}
    pub(crate) fn stage(&self)->Option<StoreStage>{match self{Self::AndroidStage(p)=>Some(p.stage),Self::IosStage(p)=>Some(p.stage),_=>None}}
    pub(crate) fn stage_binding(&self)->Option<(&str,&str,&str)>{match self{Self::AndroidStage(p)=>Some((&p.candidate_operation_id,&p.predecessor_operation_id,&p.predecessor_receipt_sha256)),Self::IosStage(p)=>Some((&p.candidate_operation_id,&p.predecessor_operation_id,&p.predecessor_receipt_sha256)),_=>None}}
    pub(crate) fn valid_for(&self,operation:&str)->bool {
        match self {
            Self::AndroidStage(p)=>return p.operation_id==operation&&stage_lineage(p.stage,operation,&p.candidate_operation_id,&p.predecessor_operation_id,&p.predecessor_receipt_sha256)
                &&sha(&p.receipt_sha256)&&uuid(&p.authorization_id)&&stage_identity(&p.candidate_sha256,&p.intent_sha256,&p.source_commit,&p.source_tree,&p.application_id,false,&p.version.name,p.version.build,&p.observed_at)
                &&stage_android_destination(p.stage,&p.destination.channel,&p.destination.release_status)&&p.result==ReceiptResult::Accepted
                &&p.state.valid(p.stage,false)&&p.limitations==STAGE_EXECUTE_LIMITATIONS,
            Self::IosStage(p)=>return p.operation_id==operation&&stage_lineage(p.stage,operation,&p.candidate_operation_id,&p.predecessor_operation_id,&p.predecessor_receipt_sha256)
                &&sha(&p.receipt_sha256)&&uuid(&p.authorization_id)&&stage_identity(&p.candidate_sha256,&p.intent_sha256,&p.source_commit,&p.source_tree,&p.bundle_id,true,&p.version.name,p.version.build,&p.observed_at)
                &&(1..=20).contains(&p.app_store_app_id.len())&&p.app_store_app_id.bytes().all(|b|b.is_ascii_digit())
                &&p.destination.valid(p.stage)&&p.result==ReceiptResult::Accepted&&p.state.valid(p.stage,true)&&p.limitations==STAGE_EXECUTE_LIMITATIONS,
            _=>{},
        }
        let(id,receipt,commit,tree,app,date,limits)=match self {
            Self::Android(p)=>(&p.operation_id,&p.receipt_sha256,&p.source_commit,&p.source_tree,&p.application_id,&p.observed_at,&p.limitations),
            Self::Ios(p)=>(&p.operation_id,&p.receipt_sha256,&p.source_commit,&p.source_tree,&p.bundle_id,&p.observed_at,&p.limitations),
            Self::AndroidStage(_)|Self::IosStage(_)=>return false,
        };
        let(candidate,intent,authorization)=self.binding();let version=self.version();
        let hex=|v:&str,n|v.len()==n&&v.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b));
        let separator=if self.platform()==Platform::Ios{b'-'}else{b'_'};
        let app_valid=app.len()<=255&&app.split('.').count()>=2&&app.split('.').all(|v|
            v.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)&&v.bytes().all(|b|b.is_ascii_alphanumeric()||b==separator));
        let destination=match self {Self::Android(p)=>p.destination.channel=="internal"&&p.destination.release_status=="completed",
            Self::Ios(p)=>p.destination.channel=="testflight-internal"&&(1..=20).contains(&p.app_store_app_id.len())&&p.app_store_app_id.bytes().all(|b|b.is_ascii_digit()),Self::AndroidStage(_)|Self::IosStage(_)=>false};
        id==operation&&uuid(operation)&&sha(candidate)&&sha(intent)&&sha(receipt)&&uuid(authorization)&&hex(commit,40)&&hex(tree,40)&&app_valid
            &&!version.name.is_empty()&&version.name.len()<=64&&version.name.bytes().all(|b|b.is_ascii_alphanumeric()||b".+-".contains(&b))
            &&(1..=2_100_000_000).contains(&version.build)&&destination&&utc_second(date)&&*limits==LIMITATIONS
    }
}
impl ResultData {
    fn valid(&self,c:&Context,authorization:&str)->bool {
        let p=&self.execution_receipt;let(candidate,intent,observed_authorization)=p.binding();
        if let Some(later)=&c.later {
            return self.schema_version==1&&self.scope==format!("local-{}-store-stage-execute",c.platform.name())
                &&(later.stage.executed_head()..=513).contains(&self.head_sequence)&&p.platform()==c.platform&&p.stage()==Some(later.stage)
                &&p.stage_binding()==Some((c.candidate_operation_id.as_str(),later.predecessor_operation_id.as_str(),later.predecessor_receipt_sha256.as_str()))
                &&c.stage_operation_id.as_deref().is_some_and(|id|p.valid_for(id))&&candidate==c.candidate_sha256&&intent==c.intent_sha256
                &&uuid(authorization)&&observed_authorization==authorization&&p.version().name==c.saved_version.name&&p.version().build==c.saved_version.build;
        }
        if p.stage().is_some(){return false;}
        self.schema_version==1&&self.scope==c.platform.scope()&&(7..=513).contains(&self.head_sequence)
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
            || self.lifetime.commands > context.commands() { return false; }
        if self.outcome == Outcome::Complete {
            return self.reason == Reason::None && self.lifetime.settled() && self.lifetime.stop_observed == CoreStop::None
                && self.lifetime.commands==context.commands() && self.lifetime.command_dispatched==Some(true)
                && self.result.as_ref().is_some_and(|r| r.valid(context,authorization));
        }
        if self.result.is_some() || self.reason == Reason::None { return false; }
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
pub(crate) enum Event {LeaseReady,HistoryHead(Head),ExecutePending(Head),ExecuteSettled(Head)}
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
                ||e.sequence!=self.next||self.next>=6||!token(operation)||!token(generation)||nonce.len()!=32||!token(nonce)||nonce=="0".repeat(32)||!sha(digest){return Err(BridgeError::protocol());}
            if e.kind=="terminal" {
                if self.next==0||!keys(&e.payload,&["schemaVersion","context","outcome","reason","result","lifetime"])
                    ||!e.payload.get("lifetime").is_some_and(|l|keys(l,&["complete","fatal","contained","commandDispatched","commands","profileCalls","inputClosed","handlersRestored","invocationClosed","stopObserved"])) {return Err(BridgeError::protocol());}
                let t=Terminal::deserialize(&e.payload).map_err(|_|BridgeError::protocol())?;
                if !t.valid(context,&self.authorization)||t.outcome==Outcome::Complete&&(self.next!=5||!self.head.as_ref().is_some_and(|h|t.result.as_ref().is_some_and(|r|r.head_sequence==h.sequence))){return Err(BridgeError::protocol());}
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
                (2,"history-head")|(3,"execute-pending")|(4,"execute-settled")=>{
                    let body=if self.next==4 {
                        if !keys(&e.payload,&["head","phase"])||e.payload["phase"]!="settled-success"{return Err(BridgeError::protocol());}&e.payload["head"]
                    }else{&e.payload};
                    let head=Head::deserialize(body).map_err(|_|BridgeError::protocol())?;
                    if !head.valid()||self.next==2&&!(context.later.as_ref().map_or(5,|s|s.stage.prepared_head())..=511).contains(&head.sequence)||self.next>2&&!self.head.as_ref().is_some_and(|p|p.sequence<513&&head.sequence==p.sequence+1){return Err(BridgeError::protocol());}
                    self.head=Some(head.clone());Ok(Frame::Event(match self.next{2=>Event::HistoryHead(head),3=>Event::ExecutePending(head),_=>Event::ExecuteSettled(head)}))
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
    pub(crate) fn input()->Value{
        let mut v=crate::local_store_prepare_protocol::tests::input();
        v["intentSha256"]=json!("e".repeat(64));
        v["toolchainSelection"]=json!({"instance":"f".repeat(32),"ownerUid":501,"catalogGeneration":1,
            "recordSha256":"a".repeat(64),"inventorySha256":"b".repeat(64),"osProviderSha256":"c".repeat(64)});v
    }
    pub(crate) fn context()->Context{prepare(&input()).unwrap().context()}
    fn lifetime()->Value{json!({"complete":true,"fatal":false,"contained":true,"commandDispatched":true,"commands":14,
        "profileCalls":0,"inputClosed":true,"handlersRestored":true,"invocationClosed":true,"stopObserved":"none"})}
    fn complete()->Value{json!({"schemaVersion":1,"context":context(),"outcome":"complete","reason":"none",
        "result":{"schemaVersion":1,"scope":"local-android-store-execute","headSequence":7,
            "executionReceipt":{"operationId":UUID,"candidateSha256":"d".repeat(64),"intentSha256":"e".repeat(64),
                "receiptSha256":"f".repeat(64),"authorizationId":AUTH,"sourceCommit":"a".repeat(40),"sourceTree":"b".repeat(40),
                "applicationId":"dev.example.app","version":{"name":"1.2.3","build":42},
                "destination":{"channel":"internal","releaseStatus":"completed"},"observedAt":"2026-10-17T00:00:00Z",
                "result":"accepted","limitations":LIMITATIONS}},"lifetime":lifetime()})}
    fn frame(sequence:u32,kind:&str,payload:Value)->Vec<u8>{let mut bytes=serde_json::to_vec(&json!({"protocol":PROTOCOL,
        "operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"nonce":"c".repeat(32),"requestSha256":"d".repeat(64),
        "sequence":sequence,"kind":kind,"payload":payload})).unwrap();bytes.push(b'\n');bytes}
    fn read(d:&mut Decoder,bytes:&[u8])->Result<Frame,BridgeError>{d.decode(bytes,&"a".repeat(32),&"b".repeat(32),&context(),&"c".repeat(32),&"d".repeat(64))}
    fn frames()->Vec<Vec<u8>>{vec![frame(0,"accepted",json!({"schemaVersion":1,"context":context()})),frame(1,"lease-ready",json!({})),
        frame(2,"history-head",json!({"sequence":5,"sha256":"a".repeat(64)})),frame(3,"execute-pending",json!({"sequence":6,"sha256":"b".repeat(64)})),
        frame(4,"execute-settled",json!({"head":{"sequence":7,"sha256":"c".repeat(64)},"phase":"settled-success"})),frame(5,"terminal",complete())]}
    #[test]
    fn local_execute_requires_current_intent_tools_and_separate_consent(){
        assert!(context().valid());assert!(crate::local_store_prepare_protocol::prepare(&input()).is_err());
        assert!(prepare(&crate::local_store_prepare_protocol::tests::input()).is_err());
        for(name,value)in[("executionMode",json!("github")),("authorizationId",json!(AUTH)),("candidateOperationId",json!("a".repeat(32))),
            ("candidateSha256",json!("bad")),("intentSha256",json!("bad")),("confirmation",json!("production:android:1.2.3:42")),("recordRevision",json!(0))]{
            let mut v=input();v[name]=value;assert!(prepare(&v).is_err());
        }
        for name in ["ownerUid","catalogGeneration"]{let mut v=input();v["toolchainSelection"][name]=json!(0);assert!(prepare(&v).is_err());}
        for consent in [crate::local_store_preflight_protocol::CONSENT,crate::local_store_prepare_protocol::CONSENT]{
            assert!(start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":consent})).is_err());
        }
        assert!(start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":CONSENT})).is_ok());
        assert!(raw_request(b"{\"projectId\":\"a\",\"projectId\":\"b\"}").is_err());
        assert!(Decoder::new("renderer-id").is_err());
    }
    #[test]
    fn local_execute_native_request_binds_original_mac_selection_and_profile(){
        use crate::android_build_protocol::{Profile as ToolsProfile,RootIdentity as ToolsIdentity,ToolchainBinding};
        let c=context();let selected=c.toolchain_selection.as_ref().unwrap();
        let binding=ToolchainBinding::new_macos_data(ToolsProfile::MacArm64,&selected.root_data(),
            ToolsIdentity{device:"1".into(),inode:"2".into(),mode:0o040555,uid:0,gid:0},selected).unwrap();
        assert!(binding.matches_selection(ToolsProfile::MacArm64,selected));
        assert!(!binding.matches_selection(ToolsProfile::MacX64,selected));
        assert!(!binding.matches_selection(ToolsProfile::LinuxX64,selected));
        for key in ["instance","ownerUid","catalogGeneration","recordSha256","inventorySha256","osProviderSha256"]{
            let mut v=serde_json::to_value(selected).unwrap();v[key]=match key{"ownerUid"=>json!(502),"catalogGeneration"=>json!(2),"instance"=>json!("a".repeat(32)),_=>json!("d".repeat(64))};
            let other=serde_json::from_value(v).unwrap();assert!(!binding.matches_selection(ToolsProfile::MacArm64,&other));
        }
        let project=RegisteredRoot{path:"/inert/project".into(),identity:crate::asset_source::ProjectIdentity::Posix(crate::asset_source::DirectoryIdentity::synthetic_evidence_identity())};
        let mut native=Native{home:"/inert/home".into(),lease_fd:3,nonce:"c".repeat(32),work_end_ns:1_200_000_000_000,hard_end_ns:1_210_000_000_000,
            authorization_id:AUTH.into(),tooling_version:crate::runtime::CORE_VERSION,tooling_commit:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",tools:NativeTools::Android(binding)};
        let credentials=Content{bytes:40,sha256:"a".repeat(64)};
        let encode=|n:&Native,profile|request(&"a".repeat(32),&"b".repeat(32),&c,profile,&project,Path::new("/inert/runtime"),&credentials,n);
        let bytes=encode(&native,Profile::MacosArm64).unwrap();let v:Value=serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["native"]["authorizationId"],AUTH);assert_eq!(v["native"]["toolchain"]["selection"],json!(selected));
        assert!(encode(&native,Profile::MacosX64).is_err());native.authorization_id="renderer-id".into();assert!(encode(&native,Profile::MacosArm64).is_err());
    }
    #[test]
    fn local_execute_decoder_requires_original_order_and_final_checkpoint(){
        let rows=frames();let mut d=Decoder::new(AUTH).unwrap();for row in &rows{assert!(read(&mut d,row).is_ok());}assert!(d.finish());assert!(read(&mut d,&rows[5]).is_err());
        for missing in 1..=4{let mut d=Decoder::new(AUTH).unwrap();let mut refused=false;for(i,row)in rows.iter().enumerate(){if i!=missing&&read(&mut d,row).is_err(){refused=true;break;}}assert!(refused);}
        for(sequence,kind,payload)in[(2,"history-head",json!({"sequence":4,"sha256":"a".repeat(64)})),(2,"history-head",json!({"sequence":512,"sha256":"a".repeat(64)})),
            (3,"execute-pending",json!({"sequence":7,"sha256":"b".repeat(64)})),
            (4,"execute-settled",json!({"head":{"sequence":7,"sha256":"c".repeat(64)},"phase":"prepared"}))]{
            let mut d=Decoder::new(AUTH).unwrap();for row in rows.iter().take(sequence as usize){read(&mut d,row).unwrap();}
            assert!(read(&mut d,&frame(sequence,kind,payload)).is_err());assert!(read(&mut d,&rows[sequence as usize]).is_err());
        }
        for field in ["protocol","operationId","ownerGeneration","nonce","requestSha256"]{
            let mut bad:Value=serde_json::from_slice(&rows[0]).unwrap();bad[field]=json!("e".repeat(32));let mut bytes=serde_json::to_vec(&bad).unwrap();bytes.push(b'\n');
            assert!(read(&mut Decoder::new(AUTH).unwrap(),&bytes).is_err());
        }
    }
    #[test]
    fn local_execute_success_binds_native_authorization_receipt_and_known_closes(){
        let c=context();assert!(Terminal::deserialize(&complete()).unwrap().valid(&c,AUTH));
        let mut reconciled=complete();reconciled["result"]["executionReceipt"]["result"]=json!("reconciled");assert!(Terminal::deserialize(&reconciled).unwrap().valid(&c,AUTH));
        for name in ["complete","contained","inputClosed","handlersRestored","invocationClosed","commandDispatched"]{
            let mut bad=complete();bad["lifetime"][name]=json!(false);assert!(!Terminal::deserialize(&bad).unwrap().valid(&c,AUTH));
        }
        for count in [0,6,13,15]{let mut bad=complete();bad["lifetime"]["commands"]=json!(count);assert!(!Terminal::deserialize(&bad).unwrap().valid(&c,AUTH));}
        for(path,value)in[("candidateSha256",json!("a".repeat(64))),("intentSha256",json!("a".repeat(64))),("receiptSha256",json!("bad")),
            ("authorizationId",json!(UUID)),("operationId",json!(AUTH)),("sourceTree",json!("bad")),("observedAt",json!("2026-02-30T00:00:00Z"))]{
            let mut bad=complete();bad["result"]["executionReceipt"][path]=value;assert!(!Terminal::deserialize(&bad).unwrap().valid(&c,AUTH));
        }
        let mut bad=complete();bad["result"]["executionReceipt"]["version"]["build"]=json!(43);assert!(!Terminal::deserialize(&bad).unwrap().valid(&c,AUTH));
        let mut bad=complete();bad["result"]["executionReceipt"]["destination"]["channel"]=json!("production");assert!(!Terminal::deserialize(&bad).unwrap().valid(&c,AUTH));
        let mut bad=complete();bad["result"]["executionReceipt"]["rawStoreState"]=json!({});assert!(Terminal::deserialize(&bad).is_err());
        let mut bad=complete();bad["result"]["headSequence"]=json!(8);let mut d=Decoder::new(AUTH).unwrap();for row in frames().iter().take(5){read(&mut d,row).unwrap();}assert!(read(&mut d,&frame(5,"terminal",bad)).is_err());
        let mut d=Decoder::new(UUID).unwrap();for row in frames().iter().take(5){read(&mut d,row).unwrap();}assert!(read(&mut d,&frames()[5]).is_err());
    }
    #[test]
    fn local_execute_failure_keeps_actual_prefix_including_entered_final_helper(){
        let rows=frames();for prefix in 1..=5{
            let mut d=Decoder::new(AUTH).unwrap();for row in rows.iter().take(prefix){read(&mut d,row).unwrap();}
            let mut failure=complete();failure["outcome"]=json!("failed");failure["reason"]=json!("execute-unavailable");failure["result"]=Value::Null;failure["lifetime"]["commands"]=json!(prefix);
            assert!(read(&mut d,&frame(prefix as u32,"terminal",failure)).is_ok());assert!(d.finish());
        }
        let mut missing=complete();missing.as_object_mut().unwrap().remove("result");let mut d=Decoder::new(AUTH).unwrap();read(&mut d,&rows[0]).unwrap();assert!(read(&mut d,&frame(1,"terminal",missing)).is_err());
        for(outcome,reason,stop)in[("cancelled","cancelled","cancelled"),("timed-out","timed-out","timed-out")]{
            let mut v=complete();v["outcome"]=json!(outcome);v["reason"]=json!(reason);v["result"]=Value::Null;v["lifetime"]["stopObserved"]=json!(stop);
            assert!(Terminal::deserialize(&v).unwrap().valid(&context(),AUTH));v["reason"]=json!("none");assert!(!Terminal::deserialize(&v).unwrap().valid(&context(),AUTH));
        }
        for outcome in ["failed","refused"]{for(reason,stop)in[("cancelled","none"),("timed-out","none"),("cleanup-unknown","none"),("execute-unavailable","cancelled"),("execute-unavailable","timed-out")]{
            let mut v=complete();v["outcome"]=json!(outcome);v["reason"]=json!(reason);v["result"]=Value::Null;v["lifetime"]["stopObserved"]=json!(stop);
            assert!(!Terminal::deserialize(&v).unwrap().valid(&context(),AUTH));
        }}
        // An uncertain cleanup must retain the original observed stop rather than
        // erase it or reinterpret the provisional result as a known cancellation.
        for stop in ["none","cancelled","timed-out"]{
            let mut v=complete();v["outcome"]=json!("unknown");v["reason"]=json!("cleanup-unknown");v["result"]=Value::Null;
            v["lifetime"]["complete"]=json!(false);v["lifetime"]["stopObserved"]=json!(stop);assert!(Terminal::deserialize(&v).unwrap().valid(&context(),AUTH));
        }
    }
    #[test]
    fn local_ios_execute_native_selection_is_exact_data_not_android_or_renderer_paths(){
        use crate::ios_archive_protocol::{RootIdentity,ToolIdentity,SigningToolBindings};
        let root=RootIdentity{device:"1".into(),inode:"2".into(),mode:0o040555,uid:0,gid:0};
        let tool=ToolIdentity{device:"1".into(),inode:"3".into(),mode:0o100555,uid:0,gid:0,links:1,size:4096,mtime_ns:"1".into(),ctime_ns:"2".into()};
        let selection=|p:&str,r:RootIdentity,t:ToolIdentity|UploadSelection::new_data(Path::new(p),r,root.clone(),t);
        for path in ["/Applications/Xcode.app/Contents/Developer","/Applications/Xcode_26.app/Contents/Developer"]{assert!(selection(path,root.clone(),tool.clone()).is_ok());}
        for path in ["/tmp/Xcode.app/Contents/Developer","/Library/Developer/CommandLineTools","/Applications/Xcode.app/../Contents/Developer","/Applications/Xcode.app/Contents/Developer/", "/Applications/Other.app/Contents/Developer"]{assert!(selection(path,root.clone(),tool.clone()).is_err());}
        let path="/Applications/Xcode.app/Contents/Developer";
        let mut writable=root.clone();writable.mode=0o040775;assert!(selection(path,writable,tool.clone()).is_err());
        let mut linked=tool.clone();linked.links=2;assert!(selection(path,root.clone(),linked).is_err());
        let upload_selection=selection(path,root.clone(),tool.clone()).unwrap();
        let signing_tools=SigningToolBindings::new_data(tool.clone(),tool.clone(),tool).unwrap();
        let native=Native{home:"/inert/home".into(),lease_fd:3,nonce:"c".repeat(32),work_end_ns:1_200_000_000_000,hard_end_ns:1_210_000_000_000,
            authorization_id:AUTH.into(),tooling_version:crate::runtime::CORE_VERSION,tooling_commit:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",tools:NativeTools::Ios{signing_tools,upload_selection}};
        let mut v=input();v.as_object_mut().unwrap().remove("toolchainSelection");v["platform"]=json!("ios");v["confirmation"]=json!("candidate:ios:1.2.3:42");let c=prepare(&v).unwrap().context();
        let project=RegisteredRoot{path:"/inert/project".into(),identity:crate::asset_source::ProjectIdentity::Posix(crate::asset_source::DirectoryIdentity::synthetic_evidence_identity())};
        let credentials=Content{bytes:40,sha256:"a".repeat(64)};
        for profile in [Profile::MacosArm64,Profile::MacosX64]{
            let bytes=request(&"a".repeat(32),&"b".repeat(32),&c,profile,&project,Path::new("/inert/runtime"),&credentials,&native).unwrap();
            let value:Value=serde_json::from_slice(&bytes).unwrap();
            assert!(keys(&value["native"]["uploadSelection"],&["schemaVersion","developerDirectory","appIdentity","developerIdentity","xcrun"]));
            assert!(keys(&value["native"]["signingTools"],&["security","codesign","openssl"]));
            assert!(value["native"].get("toolchain").is_none()&&value["context"].get("toolchainSelection").is_none());
            assert!(request(&"a".repeat(32),&"b".repeat(32),&context(),profile,&project,Path::new("/inert/runtime"),&credentials,&native).is_err());
        }
    }
    #[test]
    fn local_ios_execute_exact_platform_consent_receipt_and_actual_sixteen_roles(){
        let mut v=input();v.as_object_mut().unwrap().remove("toolchainSelection");v["platform"]=json!("ios");v["confirmation"]=json!("candidate:ios:1.2.3:42");
        let c=prepare(&v).unwrap().context();assert_eq!(c.platform,Platform::Ios);assert!(c.toolchain_selection.is_none());
        for (key,value) in [("toolchainSelection",Value::Null),("developerDirectory",json!("/Applications/Xcode.app/Contents/Developer")),("platform",json!("android"))] {
            let mut bad=v.clone();bad[key]=value;assert!(prepare(&bad).is_err());
        }
        let mut context=json!(c);context["toolchainSelection"]=Value::Null;assert!(Context::deserialize(&context).is_err());
        for consent in [CONSENT,APPLE_CONSENT] {let start=start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":consent})).unwrap();assert_eq!(start.matches_context(&c),consent==APPLE_CONSENT);}
        let mut done=complete();done["context"]=json!(c);done["lifetime"]["commands"]=json!(16);done["result"]["scope"]=json!("local-ios-store-execute");
        let receipt=done["result"]["executionReceipt"].as_object_mut().unwrap();receipt.remove("applicationId");receipt.insert("bundleId".into(),json!("dev.example.ios-app"));receipt.insert("appStoreAppId".into(),json!("0012345"));receipt.insert("destination".into(),json!({"channel":"testflight-internal"}));
        assert!(Terminal::deserialize(&done).unwrap().valid(&c,AUTH));
        for calls in [14,15,17] {let mut bad=done.clone();bad["lifetime"]["commands"]=json!(calls);assert!(!Terminal::deserialize(&bad).unwrap().valid(&c,AUTH));}
        let mut bad=done.clone();bad["result"]["executionReceipt"]["applicationId"]=json!("dev.example.app");assert!(Terminal::deserialize(&bad).is_err());
        let mut bad=done.clone();bad["result"]["executionReceipt"]["authorizationId"]=json!(UUID);assert!(!Terminal::deserialize(&bad).unwrap().valid(&c,AUTH));
        let mut bad=done.clone();bad["result"]["executionReceipt"]["destination"]["channel"]=json!("testflight-external");assert!(!Terminal::deserialize(&bad).unwrap().valid(&c,AUTH));
        let mut bad=done;bad["outcome"]=json!("failed");bad["reason"]=json!("execute-unavailable");bad["result"]=Value::Null;bad["lifetime"]["commands"]=json!(7);assert!(Terminal::deserialize(&bad).unwrap().valid(&c,AUTH));
        bad["lifetime"]["stopObserved"]=json!("cancelled");assert!(!Terminal::deserialize(&bad).unwrap().valid(&c,AUTH));
    }

    pub(crate) fn stage_input(ios:bool,production:bool)->Value{let mut v=crate::local_store_prepare_protocol::tests::stage_input(ios,production);
        v["stageOperationId"]=json!(crate::local_store_prepare_protocol::tests::STAGE_ID);v["intentSha256"]=json!("e".repeat(64));v}
    pub(crate) fn stage_complete(ios:bool,production:bool)->Value{
        let mut v=crate::local_store_prepare_protocol::tests::stage_complete(ios,production);v["context"]=json!(prepare(&stage_input(ios,production)).unwrap().context());
        let mut receipt=v["result"]["preparedIntent"].take();receipt.as_object_mut().unwrap().remove("storePreconditionSha256");
        receipt["receiptSha256"]=json!("f".repeat(64));receipt["authorizationId"]=json!(AUTH);receipt["result"]=json!("accepted");
        receipt["state"]=json!(if ios{"submitted-for-review"}else if production{"draft"}else{"available-to-testers"});receipt["limitations"]=json!(STAGE_EXECUTE_LIMITATIONS);
        v["result"]=json!({"schemaVersion":1,"scope":format!("local-{}-store-stage-execute",if ios{"ios"}else{"android"}),"headSequence":if production{15}else{11},"executionReceipt":receipt});v
    }
    #[test]
    fn local_stage_execute_has_no_tool_tuple_and_checks_original_authorization(){
        for ios in [false,true]{for production in [false,true]{
            let request=stage_input(ios,production);let c=prepare(&request).unwrap().context();assert_eq!(Context::deserialize(json!(c)).unwrap(),c);
            assert!(c.toolchain_selection.is_none());assert_eq!(c.commands(),if ios{15}else{14});
            let native=Native{home:"/inert/home".into(),lease_fd:3,nonce:"c".repeat(32),work_end_ns:1_200_000_000_000,hard_end_ns:1_210_000_000_000,
                authorization_id:AUTH.into(),tooling_version:crate::runtime::CORE_VERSION,tooling_commit:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",tools:NativeTools::Stage};
            let project=RegisteredRoot{path:"/inert/project".into(),identity:crate::asset_source::ProjectIdentity::Posix(crate::asset_source::DirectoryIdentity::synthetic_evidence_identity())};
            let credentials=Content{bytes:40,sha256:"a".repeat(64)};
            for profile in [Profile::MacosArm64,Profile::MacosX64]{
                let bytes=super::request(&"a".repeat(32),&"b".repeat(32),&c,profile,&project,Path::new("/inert/runtime"),&credentials,&native).unwrap();
                let value:Value=serde_json::from_slice(&bytes).unwrap();
                assert!(keys(&value["native"],&["profile","projectRoot","rootIdentity","cwd","credentialConfig","home","leaseFd","nonce","clock","authorizationId","tooling"]));
                assert_eq!(value["context"],json!(c));
                assert!(super::request(&"a".repeat(32),&"b".repeat(32),&context(),profile,&project,Path::new("/inert/runtime"),&credentials,&native).is_err());
            }
            for key in ["toolchainSelection","uploadSelection","signingTools","authorizationId"]{let mut bad=request.clone();bad[key]=json!({});assert!(prepare(&bad).is_err());}
            for key in ["stageOperationId","stage","platform"]{let mut bad=request.clone();bad.as_object_mut().unwrap().remove(key);assert!(prepare(&bad).is_err());}
            let v=stage_complete(ios,production);let t=Terminal::deserialize(&v).unwrap();assert!(t.valid(&c,AUTH));assert!(!t.valid(&c,"42345678-1234-4234-8234-123456789abc"));
            for(field,value)in[("result",json!("reconciled")),("state",json!("released")),("predecessorReceiptSha256",json!("b".repeat(64))),
                ("candidateOperationId",json!(crate::local_store_prepare_protocol::tests::STAGE_ID))]{let mut bad=v.clone();bad["result"]["executionReceipt"][field]=value;assert!(!Terminal::deserialize(bad).is_ok_and(|t|t.valid(&c,AUTH)));}
            let mut bad=v.clone();bad["lifetime"]["commands"]=json!(if ios{16}else{6});assert!(!Terminal::deserialize(bad).unwrap().valid(&c,AUTH));
            let consent=start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":c.consent()})).unwrap();assert!(consent.matches_context(&c));assert!(!consent.matches_context(&context()));
        }}
    }

}
