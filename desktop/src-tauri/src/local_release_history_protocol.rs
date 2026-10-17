//! Closed local enrollment/history DATA; no upload/release authority.
//! A core terminal is provisional until this operation's original native joins.
use std::{path::Path,time::{Instant,Duration}};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::{asset_source::RegisteredRoot, edit_protocol::{bounded, token}, error::BridgeError,
    protocol::{check_value, strict_json, valid_id}};

pub(crate) const PROTOCOL: &str = "mrk-local-release-history/1";
pub(crate) const CONSENT: &str = "local-release-history-v1";
pub(crate) const CANDIDATE_CONSENT: &str = "local-android-candidate-inputs-v1";
pub(crate) const IOS_CANDIDATE_CONSENT:&str="local-ios-candidate-inputs-v1";
pub(crate) const EVENT: &str = "local-release-history-state-changed";
pub(crate) const IPC_LIMIT: usize = 8192;
pub(crate) const REQUEST_LIMIT: usize = 16 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 32 * 1024; // All phase frames and rejected drain bytes.
pub(crate) const STATUS_LIMIT: usize = 16 * 1024;

fn keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key)))
}
pub(crate) fn invalid() -> BridgeError { BridgeError::new("local_release_history_invalid", "The local release history request is invalid.") }
/// Called only on original InvokeBody::Raw bytes; never a reserialized Value.
pub(crate) fn raw_request(bytes: &[u8]) -> Result<Value, BridgeError> {
    if !(1..=IPC_LIMIT).contains(&bytes.len()) { return Err(invalid()); }
    strict_json(bytes).map_err(|_| invalid())
}
fn sha(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="lowercase")]
pub(crate) enum ExecutionMode { Local }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="kebab-case")]
pub(crate) enum Action { Enroll, Verify, ReviewInputs, AbandonInputs, ReviewPrepared, ReviewExecution, ReviewReconcile, ReviewRecovery, ReviewStagePrepared, ReviewStageExecution, ReviewExternalReadiness }
impl Action {
    pub(crate) fn stage(self)->bool{matches!(self,Self::ReviewStagePrepared|Self::ReviewStageExecution|Self::ReviewExternalReadiness)}
    pub(crate) fn candidate(self)->bool{matches!(self,Self::ReviewInputs|Self::AbandonInputs|Self::ReviewPrepared|Self::ReviewExecution|Self::ReviewReconcile|Self::ReviewRecovery|Self::ReviewStagePrepared|Self::ReviewStageExecution|Self::ReviewExternalReadiness)}
    pub(crate) fn consent(self)->&'static str{if self.candidate(){CANDIDATE_CONSENT}else{CONSENT}}
}
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="lowercase")]
pub(crate) enum CandidatePlatform{Android,Ios}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase")]
pub(crate) struct Context {
    pub(crate) project_id:String,pub(crate) execution_mode:ExecutionMode,pub(crate) action:Action,
    #[serde(skip_serializing_if="Option::is_none")]
    pub(crate) candidate_operation_id:Option<String>,
    #[serde(skip_serializing_if="Option::is_none")] pub(crate) stage_operation_id:Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub(crate) platform:Option<CandidatePlatform>,
}
impl Context {
    pub(crate) fn consent(&self)->&'static str{if self.platform==Some(CandidatePlatform::Ios){IOS_CANDIDATE_CONSENT}else{self.action.consent()}}
    pub(crate) fn selected_operation_id(&self)->Option<&str>{if self.action.stage(){self.stage_operation_id.as_deref()}else{self.candidate_operation_id.as_deref()}}
    pub(crate) fn valid(&self)->bool{valid_id(&self.project_id)&&if self.action.stage(){
        self.platform.is_some()&&(self.action!=Action::ReviewExternalReadiness||self.platform==Some(CandidatePlatform::Ios))&&self.candidate_operation_id.is_none()&&self.stage_operation_id.as_deref().is_some_and(journal_uuid)
    }else{self.stage_operation_id.is_none()&&self.platform!=Some(CandidatePlatform::Android)
        &&(self.platform.is_none()||matches!(self.action,Action::ReviewInputs|Action::AbandonInputs|Action::ReviewPrepared|Action::ReviewExecution|Action::ReviewReconcile))
        &&if self.action.candidate(){self.candidate_operation_id.as_deref().is_some_and(journal_uuid)}else{self.candidate_operation_id.is_none()}}}
}
impl<'de> Deserialize<'de> for Context {
    fn deserialize<D:serde::Deserializer<'de>>(decoder:D)->Result<Self,D::Error>{
        let value=Value::deserialize(decoder)?;
        #[derive(Deserialize)]
        #[serde(rename_all="camelCase",deny_unknown_fields)]
        struct Data{project_id:String,execution_mode:ExecutionMode,action:Action,candidate_operation_id:Option<String>,stage_operation_id:Option<String>,platform:Option<CandidatePlatform>}
        let data=Data::deserialize(&value).map_err(serde::de::Error::custom)?;
        let expected=if data.action.stage(){&["projectId","executionMode","action","stageOperationId","platform"][..]}else if data.platform.is_some(){&["projectId","executionMode","action","candidateOperationId","platform"][..]}else if data.action.candidate(){&["projectId","executionMode","action","candidateOperationId"][..]}
            else{&["projectId","executionMode","action"][..]};
        let result=Self{project_id:data.project_id,execution_mode:data.execution_mode,action:data.action,candidate_operation_id:data.candidate_operation_id,stage_operation_id:data.stage_operation_id,platform:data.platform};
        if !keys(&value,expected)||!result.valid(){return Err(serde::de::Error::custom("invalid local history context"));}Ok(result)
    }
}
// Prepare and retained Context share one closed grammar, including absence (not
// null) of candidateOperationId for the two original actions.
pub(crate) type Prepare=Context;
impl Context {pub(crate) fn context(&self)->Context{self.clone()}}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Start { pub(crate) operation_id: String, pub(crate) owner_generation: String, consent_version: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cancel { pub(crate) operation_id: String, pub(crate) owner_generation: String }
pub(crate) fn prepare(value: &Value) -> Result<Prepare, BridgeError> {
    let input = Prepare::deserialize(value).map_err(|_| invalid())?;
    if !input.context().valid() { return Err(invalid()); } Ok(input)
}
pub(crate) fn start(value: &Value) -> Result<Start, BridgeError> {
    if !keys(value, &["operationId", "ownerGeneration", "consentVersion"]) { return Err(invalid()); }
    let input = Start::deserialize(value).map_err(|_| invalid())?;
    if !token(&input.operation_id) || !token(&input.owner_generation) || !matches!(input.consent_version.as_str(),CONSENT|CANDIDATE_CONSENT|IOS_CANDIDATE_CONSENT) { return Err(invalid()); } Ok(input)
}
impl Start {pub(crate) fn consents(&self,expected:&str)->bool{self.consent_version==expected}}
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
pub(crate) struct RequestOriginal {pub(crate) bytes:Vec<u8>,pub(crate) nonce:String,pub(crate) sha256:String}
pub(crate) fn request(operation:&str,generation:&str,context:&Context,profile:Profile,project:&RegisteredRoot,
    cwd:&Path,home:&Path,lease_fd:u32,nonce:[u8;16],work_end:u64,hard_end:u64)->Result<RequestOriginal,BridgeError>{
    use sha2::{Digest,Sha256};
    if !token(operation)||!token(generation)||!context.valid()||!(3..=255).contains(&lease_fd)||nonce==[0;16]
        ||work_end==0||hard_end<work_end||hard_end-work_end>2_000_000_000{return Err(invalid());}
    let identity=project.identity.posix().map_err(|_|invalid())?.preflight_identity();
    if !decimal(&identity.device)||!decimal(&identity.inode)||identity.inode=="0"||identity.mode&0o170000!=0o040000||identity.mode&0o7022!=0{return Err(invalid());}
    let nonce=nonce.iter().map(|b|format!("{b:02x}")).collect::<String>();
    let value=json!({"protocol":PROTOCOL,"operationId":operation,"ownerGeneration":generation,"context":context,
        "native":{"profile":profile,"projectRoot":native_path(&project.path).ok_or_else(invalid)?,"rootIdentity":identity,
            "cwd":native_path(cwd).ok_or_else(invalid)?,"home":native_path(home).ok_or_else(invalid)?,"leaseFd":lease_fd,"nonce":nonce,
            "clock":{"workEndNs":work_end.to_string(),"hardEndNs":hard_end.to_string()}}});
    check_value(&value)?;let mut bytes=bounded(&value,REQUEST_LIMIT-1)?;bytes.push(b'\n');
    let sha256=format!("{:x}",Sha256::digest(&bytes));Ok(RequestOriginal{bytes,nonce,sha256})
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Outcome { Complete, Refused, Cancelled, TimedOut, Failed, Unknown }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None, Cancelled, ContextChanged, DocumentLost, Shutdown, TimedOut, ProtocolError, RuntimeUnavailable, IntentExpired,
    StaleIntent, SavedSourceChanged, SavedSourceInvalid, CredentialsUnavailable, QueryPrerequisites, CommandIncomplete, CleanupUnknown,
    JournalUnavailable, EnrollmentExists, RecoveryRequired, ProjectBusy,
}
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
pub(crate) enum HistoryPhase {InputsPending,InputsReady,PreparePending,PromotionPending,Prepared,ExecutePending,SettledSuccess,SettledFailure,ReconciliationRequired,TargetReconciled,ExternalReady}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct HistoryRow {operation_id:String,phase:HistoryPhase,recovery_required:bool}
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
enum Limitation {NoStoreAuthority,NoBuildOrPublishing,KeychainIntactRollbackBoundary}
const LIMITATIONS:[Limitation;3]=[Limitation::NoStoreAuthority,Limitation::NoBuildOrPublishing,Limitation::KeychainIntactRollbackBoundary];
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct ResultData {schema_version:u32,scope:String,enrolled:bool,head_sequence:u32,history:Vec<HistoryRow>,limitations:Vec<Limitation>,
    // None=old grammar absent; Some(None)=new grammar explicit null. Bare
    // Option cannot preserve that boundary through Deserialize/Serialize.
    #[serde(default,skip_serializing_if="Option::is_none",deserialize_with="candidate_field")]
    candidate_inputs:Option<Option<ReviewedInputs>>,
    #[serde(default,skip_serializing_if="Option::is_none",deserialize_with="prepared_field")]
    prepared_intent:Option<Option<PreparedReview>>,
    #[serde(default,skip_serializing_if="Option::is_none",deserialize_with="execution_field")]
    execution_receipt:Option<Option<ExecutionReview>>,
    #[serde(default,skip_serializing_if="Option::is_none",deserialize_with="recovery_field")]
    reconciliation_receipt:Option<Option<crate::local_store_reconcile_protocol::ReconciliationReceipt>>,
    #[serde(default,skip_serializing_if="Option::is_none",deserialize_with="readiness_field")]
    readiness_receipt:Option<Option<crate::local_store_reconcile_protocol::ReadinessReceipt>>,
}
fn readiness_field<'de,D:serde::Deserializer<'de>>(decoder:D)->Result<Option<Option<crate::local_store_reconcile_protocol::ReadinessReceipt>>,D::Error>{
    Ok(Some(Option::<crate::local_store_reconcile_protocol::ReadinessReceipt>::deserialize(decoder)?))
}
fn candidate_field<'de,D:serde::Deserializer<'de>>(decoder:D)->Result<Option<Option<ReviewedInputs>>,D::Error>{
    Ok(Some(Option::<ReviewedInputs>::deserialize(decoder)?))
}
fn prepared_field<'de,D:serde::Deserializer<'de>>(decoder:D)->Result<Option<Option<PreparedReview>>,D::Error>{
    Ok(Some(Option::<PreparedReview>::deserialize(decoder)?))
}
fn recovery_field<'de,D:serde::Deserializer<'de>>(decoder:D)->Result<Option<Option<crate::local_store_reconcile_protocol::ReconciliationReceipt>>,D::Error>{
    Ok(Some(Option::<crate::local_store_reconcile_protocol::ReconciliationReceipt>::deserialize(decoder)?))
}
fn execution_field<'de,D:serde::Deserializer<'de>>(decoder:D)->Result<Option<Option<ExecutionReview>>,D::Error>{
    Ok(Some(Option::<ExecutionReview>::deserialize(decoder)?))
}
#[derive(Clone,Debug,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase")]
struct ExecutionReview {
    #[serde(flatten)]
    receipt:crate::local_store_execute_protocol::ExecutionReceipt,
    observation:String,prior_execution_finality:String,
}
impl<'de> Deserialize<'de> for ExecutionReview {
    fn deserialize<D:serde::Deserializer<'de>>(decoder:D)->Result<Self,D::Error>{
        let mut value=Value::deserialize(decoder)?;
        let mut fields=vec!["operationId","candidateSha256","intentSha256","receiptSha256","authorizationId","sourceCommit","sourceTree","version","destination","observedAt","result","limitations","observation","priorExecutionFinality"];
        if value.get("stage").is_some(){fields.extend(["stage","candidateOperationId","predecessorOperationId","predecessorReceiptSha256","state"]);}
        if value.get("bundleId").is_some(){fields.extend(["bundleId","appStoreAppId"]);}else{fields.push("applicationId");}
        if !keys(&value,&fields){return Err(serde::de::Error::custom("invalid execution review"));}
        let object=value.as_object_mut().ok_or_else(||serde::de::Error::custom("invalid execution review"))?;
        let observation=String::deserialize(object.remove("observation").unwrap()).map_err(serde::de::Error::custom)?;
        let prior_execution_finality=String::deserialize(object.remove("priorExecutionFinality").unwrap()).map_err(serde::de::Error::custom)?;
        let receipt=crate::local_store_execute_protocol::ExecutionReceipt::deserialize(&value).map_err(serde::de::Error::custom)?;
        Ok(Self{receipt,observation,prior_execution_finality})
    }
}
impl ExecutionReview {
    fn matches_platform(&self,context:&Context)->bool{
        (self.receipt.platform()==crate::local_store_execute_protocol::Platform::Ios)==(context.platform==Some(CandidatePlatform::Ios))
    }
    fn valid(&self,operation:&str)->bool{self.receipt.valid_for(operation)
        &&self.observation=="current-execution-files-only"&&self.prior_execution_finality=="not-established"}
}
#[derive(Clone,Debug,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase")]
struct PreparedReview {
    #[serde(flatten)]
    intent:crate::local_store_prepare_protocol::PreparedIntent,
    observation:String,prior_prepare_finality:String,
}
// Exact13/14-key admission keeps the corresponding11/12-key Prepare grammar closed;
// deny_unknown_fields + flatten would not provide that boundary on deserialize.
impl<'de> Deserialize<'de> for PreparedReview {
    fn deserialize<D:serde::Deserializer<'de>>(decoder:D)->Result<Self,D::Error>{
        let mut value=Value::deserialize(decoder)?;
        let mut fields=vec!["operationId","candidateSha256","intentSha256","storePreconditionSha256","sourceCommit","sourceTree","version","destination","observedAt","limitations","observation","priorPrepareFinality"];
        if value.get("stage").is_some(){fields.extend(["stage","candidateOperationId","predecessorOperationId","predecessorReceiptSha256"]);}
        if value.get("bundleId").is_some(){fields.extend(["bundleId","appStoreAppId"]);}else{fields.push("applicationId");}
        if !keys(&value,&fields){return Err(serde::de::Error::custom("invalid prepared review"));}
        let object=value.as_object_mut().ok_or_else(||serde::de::Error::custom("invalid prepared review"))?;
        let observation=String::deserialize(object.remove("observation").unwrap()).map_err(serde::de::Error::custom)?;
        let prior_prepare_finality=String::deserialize(object.remove("priorPrepareFinality").unwrap()).map_err(serde::de::Error::custom)?;
        let intent=crate::local_store_prepare_protocol::PreparedIntent::deserialize(&value).map_err(serde::de::Error::custom)?;
        Ok(Self{intent,observation,prior_prepare_finality})
    }
}
impl PreparedReview {
    fn valid(&self,operation:&str)->bool{self.intent.valid_for(operation)
        &&self.observation=="current-prepared-files-only"&&self.prior_prepare_finality=="not-established"}
    fn matches_platform(&self,context:&Context)->bool {
        self.intent.platform()==if context.platform==Some(CandidatePlatform::Ios){crate::local_store_prepare_protocol::Platform::Ios}
            else{crate::local_store_prepare_protocol::Platform::Android}
    }
}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(untagged)]
enum ReviewedInputs{Android(CandidateInputs),Ios(crate::ios_archive_protocol::CandidateInputs)}
impl ReviewedInputs{fn valid(&self,context:&Context,id:&str)->bool{match(self,context.platform){
    (Self::Android(v),None)=>v.valid(id),
    (Self::Ios(v),Some(CandidatePlatform::Ios))=>journal_uuid(id)&&v.valid(&id.replace('-',"")),
    _=>false,
}}}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct CandidateInputs {operation_id:String,candidate_sha256:String,source_commit:String,source_tree:String,
    application_id:String,version:CandidateVersion,files:[CandidateFile;3],observation:String,prior_create_finality:String}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
struct CandidateVersion{name:String,build:u32}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct CandidateFile{file_name:String,bytes:u64,sha256:String}
impl CandidateInputs {
    pub(crate) fn valid(&self,operation:&str)->bool{
        let git=|v:&str|v.len()==40&&v.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b));
        let mut count=0;
        // Same selected Android application/version grammar as AndroidBuild.
        let app=self.application_id.len()<=255&&self.application_id.split('.').all(|part|{
            count+=1;part.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                &&part.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_')})&&count>=2;
        self.operation_id==operation&&journal_uuid(operation)&&sha(&self.candidate_sha256)&&git(&self.source_commit)&&git(&self.source_tree)
            &&app&&!self.version.name.is_empty()&&self.version.name.len()<=64
            &&self.version.name.bytes().all(|b|b.is_ascii_alphanumeric()||b".+-".contains(&b))
            &&(1..=2_100_000_000).contains(&self.version.build)
            &&self.files.iter().zip([("app-release.aab",1_073_741_824),("store-metadata.zip",536_870_912),("validation-report.json",65_536)])
                .all(|(file,(name,max))|file.file_name==name&&(1..=max).contains(&file.bytes)&&sha(&file.sha256))
            &&self.observation=="current-bundle-only"&&self.prior_create_finality=="not-established"
    }
    pub(crate) fn matches_build(&self,app:&str,name:&str,build:u32,bytes:u64,hash:&str)->bool{
        self.valid(&self.operation_id) && self.application_id==app && self.version.name==name && self.version.build==build
            && self.files[0].bytes==bytes && self.files[0].sha256==hash
    }
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{
        let mut bytes=0usize;
        for value in [&self.operation_id,&self.candidate_sha256,&self.source_commit,&self.source_tree,&self.application_id,
            &self.version.name,&self.observation,&self.prior_create_finality]{bytes=bytes.checked_add(value.capacity())?;}
        for row in &self.files{bytes=bytes.checked_add(row.file_name.capacity())?.checked_add(row.sha256.capacity())?;}Some(bytes)
    }

}

pub(crate) fn journal_uuid(v:&str)->bool{let b=v.as_bytes();b.len()==36&&b[8]==b'-'&&b[13]==b'-'&&b[18]==b'-'&&b[23]==b'-'&&b[14]==b'4'
    &&matches!(b[19],b'8'|b'9'|b'a'|b'b')&&b.iter().enumerate().all(|(i,c)|matches!(i,8|13|18|23)||c.is_ascii_digit()||(b'a'..=b'f').contains(c))}
impl ResultData {fn valid(&self)->bool{self.schema_version==1&&self.scope=="local-release-history"&&self.enrolled
    &&(1..=513).contains(&self.head_sequence)&&self.history.len()<=64&&self.history.len()<(self.head_sequence as usize)
    &&self.limitations==LIMITATIONS&&self.history.iter().enumerate().all(|(i,r)|journal_uuid(&r.operation_id)
        &&!self.history[..i].iter().any(|p|p.operation_id==r.operation_id)
        &&r.recovery_required!=matches!(r.phase,HistoryPhase::SettledSuccess|HistoryPhase::SettledFailure|HistoryPhase::TargetReconciled|HistoryPhase::ExternalReady))}}
impl ResultData {
    fn matches_context(&self,context:&Context)->bool{
        if !context.valid()||!self.valid()||context.action!=Action::ReviewRecovery&&self.reconciliation_receipt.is_some()
            ||context.action!=Action::ReviewExternalReadiness&&self.readiness_receipt.is_some(){return false;}
        if !context.action.candidate(){return self.candidate_inputs.is_none()&&self.prepared_intent.is_none()&&self.execution_receipt.is_none();}
        let Some(id)=context.selected_operation_id() else{return false;};
        let Some(row)=self.history.iter().find(|row|row.operation_id==id) else{return false;};
        if context.action==Action::ReviewExternalReadiness {
            return self.head_sequence>=12&&row.phase==HistoryPhase::ExternalReady&&self.candidate_inputs.is_none()
                &&self.prepared_intent.is_none()&&self.execution_receipt.is_none()&&self.reconciliation_receipt.is_none()
                &&self.readiness_receipt.as_ref().and_then(Option::as_ref).is_some_and(|r|r.valid_review(id));
        }
        if context.action==Action::ReviewStagePrepared {
            return row.phase==HistoryPhase::Prepared&&self.candidate_inputs.is_none()&&self.execution_receipt.is_none()
                &&self.prepared_intent.as_ref().and_then(Option::as_ref).is_some_and(|p|p.valid(id)&&p.matches_platform(context)
                    &&p.intent.stage().is_some_and(|stage|self.head_sequence>=stage.prepared_head()));
        }
        if context.action==Action::ReviewStageExecution {
            return row.phase==HistoryPhase::SettledSuccess&&self.candidate_inputs.is_none()&&self.prepared_intent.is_none()
                &&self.execution_receipt.as_ref().and_then(Option::as_ref).is_some_and(|p|p.valid(id)&&p.matches_platform(context)
                    &&p.receipt.stage().is_some_and(|stage|self.head_sequence>=stage.executed_head()));
        }
        if context.action==Action::ReviewRecovery {
            return self.head_sequence>=7&&row.phase==HistoryPhase::TargetReconciled&&self.candidate_inputs.is_none()&&self.prepared_intent.is_none()&&self.execution_receipt.is_none()
                &&self.reconciliation_receipt.as_ref().and_then(Option::as_ref).is_some_and(|r|r.valid_recovery_review(id));
        }
        if context.action==Action::ReviewPrepared {
            // Latest state for this selected operation, not necessarily the
            // final operation in the genuine journal's public current table.
            return self.head_sequence>=5&&row.phase==HistoryPhase::Prepared&&self.candidate_inputs.is_none()&&self.execution_receipt.is_none()
                &&self.prepared_intent.as_ref().and_then(Option::as_ref).is_some_and(|p|p.valid(id)&&p.matches_platform(context)&&p.intent.stage().is_none());
        }
        if context.action==Action::ReviewReconcile {
            return self.head_sequence>=6&&self.history.last().is_some_and(|r|r.operation_id==id)
                &&matches!(row.phase,HistoryPhase::ExecutePending|HistoryPhase::SettledSuccess|HistoryPhase::SettledFailure|HistoryPhase::ReconciliationRequired)
                &&self.candidate_inputs.is_none()&&self.execution_receipt.is_none()
                &&self.prepared_intent.as_ref().and_then(Option::as_ref).is_some_and(|p|p.valid(id)&&p.matches_platform(context)&&p.intent.stage().is_none());
        }
        if context.action==Action::ReviewExecution {
            return self.head_sequence>=7&&row.phase==HistoryPhase::SettledSuccess&&self.candidate_inputs.is_none()&&self.prepared_intent.is_none()
                &&self.execution_receipt.as_ref().and_then(Option::as_ref).is_some_and(|p|p.valid(id)&&p.matches_platform(context)&&p.receipt.stage().is_none());
        }
        if self.prepared_intent.is_some()||self.execution_receipt.is_some(){return false;}
        match(context.action,row.phase,&self.candidate_inputs){
            (Action::ReviewInputs,HistoryPhase::InputsReady,Some(Some(bundle)))=>bundle.valid(context,id),
            (Action::ReviewInputs,HistoryPhase::InputsPending|HistoryPhase::SettledFailure,Some(None))=>true,
            (Action::AbandonInputs,HistoryPhase::SettledFailure,Some(None))=>self.history.last().is_some_and(|row|row.operation_id==id),
            _=>false,
        }
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
        && self.input_closed && self.handlers_restored && self.invocation_closed && self.profile_calls == 0 && self.commands == 0 && self.command_dispatched == Some(false) }
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
            || self.lifetime.commands != 0 { return false; }
        if self.outcome == Outcome::Complete {
            return self.reason == Reason::None && self.lifetime.settled() && self.lifetime.stop_observed == CoreStop::None
                && self.result.as_ref().is_some_and(|r| r.matches_context(context));
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
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Head {pub(crate) sequence:u32,pub(crate) sha256:String}
impl Head {pub(crate) fn valid(&self)->bool{(1..=513).contains(&self.sequence)&&sha(&self.sha256)}}
#[derive(Clone,Debug,PartialEq,Eq)]
pub(crate) enum Event {LeaseReady,EmptyJournalReady,DurableGenesis(Head),HistoryHead(Head),AbandonedHead(Head)}
pub(crate) enum Frame {Accepted,Event(Event),Terminal(Terminal)}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Envelope{protocol:String,operation_id:String,owner_generation:String,nonce:String,request_sha256:String,sequence:u32,kind:String,payload:Value}
pub(crate) struct Decoder {next:u32,failed:bool,terminal:bool,candidate_head:Option<Head>}
impl Decoder {
    pub(crate) fn finish(&mut self)->bool{if !self.terminal{self.failed=true;}!self.failed&&self.terminal}
    pub(crate) fn new()->Self{Self{next:0,failed:false,terminal:false,candidate_head:None}}
    pub(crate) fn decode(&mut self,bytes:&[u8],operation:&str,generation:&str,context:&Context,nonce:&str,digest:&str)->Result<Frame,BridgeError>{
        if self.failed||self.terminal{return Err(BridgeError::protocol());}
        let result=(||{
            if !(3..=16*1024).contains(&bytes.len())||!bytes.ends_with(b"\n")||bytes[0]!=b'{'||bytes[bytes.len()-2]!=b'}'
                ||bytes[..bytes.len()-1].iter().any(|b|*b==b'\r'||*b==b'\n'){return Err(BridgeError::protocol());}
            let value=strict_json(&bytes[..bytes.len()-1])?;
            let e=Envelope::deserialize(&value).map_err(|_|BridgeError::protocol())?;
            if e.protocol!=PROTOCOL||e.operation_id!=operation||e.owner_generation!=generation||e.nonce!=nonce
                ||e.request_sha256!=digest||e.sequence!=self.next||self.next>=8{return Err(BridgeError::protocol());}
            let expected=match (context.action,self.next){(_,0)=>"accepted",(_,1)=>"lease-ready",(Action::Enroll,2)=>"empty-journal-ready",(Action::Enroll,3)=>"durable-genesis",(Action::Verify|Action::ReviewInputs|Action::AbandonInputs|Action::ReviewPrepared|Action::ReviewExecution|Action::ReviewReconcile|Action::ReviewRecovery|Action::ReviewStagePrepared|Action::ReviewStageExecution|Action::ReviewExternalReadiness,2)=>"history-head",(Action::AbandonInputs,3)=>"abandoned-head",_=>"terminal"};
            if e.kind=="terminal" {
                if self.next==0||!keys(&e.payload,&["schemaVersion","context","outcome","reason","result","lifetime"])
                    ||!e.payload.get("lifetime").is_some_and(|l|keys(l,&["complete","fatal","contained","commandDispatched","commands","profileCalls","inputClosed","handlersRestored","invocationClosed","stopObserved"])) {return Err(BridgeError::protocol());}
                let t=Terminal::deserialize(&e.payload).map_err(|_|BridgeError::protocol())?;
                if !t.valid(context)||t.outcome==Outcome::Complete&&expected!="terminal"{return Err(BridgeError::protocol());}
                if t.outcome==Outcome::Complete&&context.action.candidate()
                    &&!self.candidate_head.as_ref().is_some_and(|head|t.result.as_ref().is_some_and(|r|r.head_sequence==head.sequence)){
                    return Err(BridgeError::protocol());
                }
                self.terminal=true;return Ok(Frame::Terminal(t));
            }
            if e.kind!=expected||bytes.len()>1024{return Err(BridgeError::protocol());}
            match e.kind.as_str(){
                "accepted"=>{let a=Accepted::deserialize(&e.payload).map_err(|_|BridgeError::protocol())?;
                    if a.schema_version!=1||a.context!=*context||!a.context.valid(){return Err(BridgeError::protocol());}Ok(Frame::Accepted)},
                "lease-ready"|"empty-journal-ready"=>{if !keys(&e.payload,&[]){return Err(BridgeError::protocol());}
                    Ok(Frame::Event(if e.kind=="lease-ready"{Event::LeaseReady}else{Event::EmptyJournalReady}))},
                "durable-genesis"|"history-head"|"abandoned-head"=>{let h=Head::deserialize(&e.payload).map_err(|_|BridgeError::protocol())?;
                    if !h.valid()||e.kind=="durable-genesis"&&h.sequence!=1{return Err(BridgeError::protocol());}
                    if e.kind=="abandoned-head" {
                        if !self.candidate_head.as_ref().is_some_and(|previous|previous.sequence<513&&h.sequence==previous.sequence+1){return Err(BridgeError::protocol());}
                        self.candidate_head=Some(h.clone());return Ok(Frame::Event(Event::AbandonedHead(h)));
                    }
                    if context.action.candidate(){
                        if context.action==Action::AbandonInputs&&h.sequence==513{return Err(BridgeError::protocol());}
                        self.candidate_head=Some(h.clone());
                    }
                    Ok(Frame::Event(if e.kind=="durable-genesis"{Event::DurableGenesis(h)}else{Event::HistoryHead(h)}))},
                _=>Err(BridgeError::protocol()),
            }
        })();
        if result.is_err(){self.failed=true;}else{self.next+=1;}result
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
mod tests {
    use super::*;
    #[test]
    fn local_stage_history_uses_explicit_stage_id_and_never_relabels_candidate_review(){
        for ios in [false,true]{for execution in [false,true]{
            let id=crate::local_store_prepare_protocol::tests::STAGE_ID;
            let request=json!({"projectId":"registered-project","executionMode":"local","action":if execution{"review-stage-execution"}else{"review-stage-prepared"},
                "platform":if ios{"ios"}else{"android"},"stageOperationId":id});
            let c=prepare(&request).unwrap();assert_eq!(serde_json::to_value(&c).unwrap(),request);
            let source=if execution{crate::local_store_execute_protocol::tests::stage_complete(ios,false)}else{crate::local_store_prepare_protocol::tests::stage_complete(ios,false)};
            let field=if execution{"executionReceipt"}else{"preparedIntent"};let mut summary=source["result"][field].clone();
            summary["observation"]=json!(if execution{"current-execution-files-only"}else{"current-prepared-files-only"});
            summary[if execution{"priorExecutionFinality"}else{"priorPrepareFinality"}]=json!("not-established");
            let mut value=json!({"schemaVersion":1,"scope":"local-release-history","enrolled":true,"headSequence":source["result"]["headSequence"],
                "history":[{"operationId":id,"phase":if execution{"settled-success"}else{"prepared"},"recoveryRequired":!execution}],"limitations":LIMITATIONS});value[field]=summary;
            let result=ResultData::deserialize(&value).unwrap();assert!(result.matches_context(&c));
            let mut old=request.clone();old["action"]=json!(if execution{"review-execution"}else{"review-prepared"});old.as_object_mut().unwrap().remove("stageOperationId");old["candidateOperationId"]=json!(id);
            if !ios{old.as_object_mut().unwrap().remove("platform");}assert!(!result.matches_context(&prepare(&old).unwrap()));
            let mut hybrid=request.clone();hybrid["candidateOperationId"]=json!(id);assert!(prepare(&hybrid).is_err());
            let mut wrong=c.clone();wrong.stage_operation_id=Some("42345678-1234-4234-8234-123456789abc".into());assert!(!result.matches_context(&wrong));
        }}
    }

    fn context(action:Action)->Context {Context{project_id:"registered-project".into(),execution_mode:ExecutionMode::Local,action,platform:None,stage_operation_id:None,candidate_operation_id:action.candidate().then(||"12345678-1234-4234-9234-123456789abc".into())}}
    fn frame(c:&Context,sequence:u32,kind:&str,payload:Value)->Vec<u8>{let mut v=serde_json::to_vec(&json!({"protocol":PROTOCOL,
        "operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"nonce":"c".repeat(32),"requestSha256":"d".repeat(64),
        "sequence":sequence,"kind":kind,"payload":payload})).unwrap();v.push(b'\n');let _=c;v}
    fn decode(d:&mut Decoder,c:&Context,seq:u32,kind:&str,payload:Value)->Result<Frame,BridgeError>{d.decode(&frame(c,seq,kind,payload),&"a".repeat(32),&"b".repeat(32),c,&"c".repeat(32),&"d".repeat(64))}
    fn result()->Value{json!({"schemaVersion":1,"scope":"local-release-history","enrolled":true,"headSequence":1,"history":[],
        "limitations":["no-store-authority","no-build-or-publishing","keychain-intact-rollback-boundary"]})}
    fn terminal(c:&Context)->Value{json!({"schemaVersion":1,"context":c,"outcome":"complete","reason":"none","result":result(),
        "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":false,"commands":0,"profileCalls":0,
        "inputClosed":true,"handlersRestored":true,"invocationClosed":true,"stopObserved":"none"}})}
    #[test]
    fn local_release_history_real_decoder_requires_complete_closed_phase_sequence(){
        for action in [Action::Enroll,Action::Verify]{let c=context(action);let mut d=Decoder::new();
            assert!(matches!(decode(&mut d,&c,0,"accepted",json!({"schemaVersion":1,"context":c})).unwrap(),Frame::Accepted));
            assert!(decode(&mut d,&c,1,"lease-ready",json!({})).is_ok());
            let last=if action==Action::Enroll{assert!(decode(&mut d,&c,2,"empty-journal-ready",json!({})).is_ok());
                assert!(decode(&mut d,&c,3,"durable-genesis",json!({"sequence":1,"sha256":"e".repeat(64)})).is_ok());4}
                else{assert!(decode(&mut d,&c,2,"history-head",json!({"sequence":1,"sha256":"e".repeat(64)})).is_ok());3};
            assert!(matches!(decode(&mut d,&c,last,"terminal",terminal(&c)).unwrap(),Frame::Terminal(_)));assert!(d.finish());
            assert!(decode(&mut d,&c,last,"terminal",terminal(&c)).is_err());
        }
    }
    #[test]
    fn local_release_history_original_nonce_replay_and_truncated_terminal_refuse(){
        let c=context(Action::Enroll);
        let accepted=json!({"schemaVersion":1,"context":c});let raw=frame(&c,0,"accepted",accepted.clone());
        let mut d=Decoder::new();assert!(d.decode(&raw,&"a".repeat(32),&"b".repeat(32),&c,&"f".repeat(32),&"d".repeat(64)).is_err());
        assert!(decode(&mut d,&c,0,"accepted",accepted.clone()).is_err());
        let mut d=Decoder::new();assert!(decode(&mut d,&c,0,"accepted",accepted.clone()).is_ok());
        assert!(decode(&mut d,&c,1,"terminal",terminal(&c)).is_err());assert!(!d.finish());
        let mut d=Decoder::new();assert!(decode(&mut d,&c,0,"accepted",accepted).is_ok());assert!(!d.finish());
        assert!(raw_request(br#"{"projectId":"a","projectId":"b","executionMode":"local","action":"enroll"}"#).is_err());
        assert!(prepare(&json!({"projectId":"p","executionMode":"github","action":"enroll"})).is_err());
    }
    fn candidate_result(c:&Context,phase:&str)->Value{
        let mut r=result();r["headSequence"]=json!(3);
        r["history"]=json!([{"operationId":c.candidate_operation_id,"phase":phase,"recoveryRequired":phase!="settled-failure"}]);
        r["candidateInputs"]=if phase=="inputs-ready"{json!({"operationId":c.candidate_operation_id,
            "candidateSha256":"a".repeat(64),"sourceCommit":"b".repeat(40),"sourceTree":"c".repeat(40),
            "applicationId":"dev.example.app","version":{"name":"1.2.3","build":12},
            "files":[{"fileName":"app-release.aab","bytes":1073741824u64,"sha256":"d".repeat(64)},
                {"fileName":"store-metadata.zip","bytes":536870912u64,"sha256":"e".repeat(64)},
                {"fileName":"validation-report.json","bytes":65536,"sha256":"f".repeat(64)}],
            "observation":"current-bundle-only","priorCreateFinality":"not-established"})}else{Value::Null};r
    }
    #[test]
    fn local_release_history_ios_platform_has_original_distinct_consent(){
        for action in [Action::ReviewInputs,Action::AbandonInputs,Action::ReviewPrepared,Action::ReviewExecution,Action::ReviewReconcile]{
            let mut c=context(action);c.platform=Some(CandidatePlatform::Ios);let value=json!(c);
            assert_eq!(prepare(&value).unwrap(),c);assert_eq!(c.consent(),IOS_CANDIDATE_CONSENT);
            for token in [CONSENT,CANDIDATE_CONSENT,IOS_CANDIDATE_CONSENT]{let input=start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":token})).unwrap();
                assert_eq!(input.consents(c.consent()),token==IOS_CANDIDATE_CONSENT);}
            for platform in [Value::Null,json!("android"),json!("macos")]{let mut v=value.clone();v["platform"]=platform;assert!(prepare(&v).is_err());}
        }
        for action in [Action::Enroll,Action::Verify,Action::ReviewRecovery]{
            let mut value=json!(context(action));value["platform"]=json!("ios");assert!(prepare(&value).is_err());}
    }
    #[test]
    fn local_release_history_ios_summary_is_current_bundle_not_android_or_create_finality(){
        let mut c=context(Action::ReviewInputs);c.platform=Some(CandidatePlatform::Ios);
        let android=candidate_result(&c,"inputs-ready");assert!(!ResultData::deserialize(&android).unwrap().matches_context(&c));
        let mut v=android.clone();v["candidateInputs"].as_object_mut().unwrap().remove("applicationId");
        v["candidateInputs"]["bundleId"]=json!("dev.example.app");
        v["candidateInputs"]["files"][0]["fileName"]=json!("export/App.ipa");
        v["candidateInputs"]["archive"]=json!({"directory":"archive.xcarchive","entries":2,"bytes":200,"sha256":"a".repeat(64)});
        assert!(ResultData::deserialize(&v).unwrap().matches_context(&c));
        let mut other=c.clone();other.platform=None;assert!(!ResultData::deserialize(&v).unwrap().matches_context(&other));
        for fault in ["hybrid","roster","path","prior","identity"]{let mut x=v.clone();match fault{
            "hybrid"=>x["candidateInputs"]["applicationId"]=json!("dev.example.app"),
            "roster"=>x["candidateInputs"]["files"][0]["fileName"]=json!("app-release.aab"),
            "path"=>x["candidateInputs"]["archive"]["directory"]=json!("elsewhere.xcarchive"),
            "prior"=>x["candidateInputs"]["priorCreateFinality"]=json!("complete"),
            _=>x["candidateInputs"]["operationId"]=json!("12345678-1234-4234-9234-123456789abd"),}
            assert!(!ResultData::deserialize(&x).is_ok_and(|r|r.matches_context(&c)),"{fault}");}
        let mut d=Decoder::new();decode(&mut d,&c,0,"accepted",json!({"schemaVersion":1,"context":c})).unwrap();
        decode(&mut d,&c,1,"lease-ready",json!({})).unwrap();decode(&mut d,&c,2,"history-head",json!({"sequence":3,"sha256":"e".repeat(64)})).unwrap();
        let mut t=terminal(&c);t["result"]=v;assert!(decode(&mut d,&c,3,"terminal",t).is_ok());assert!(d.finish());
        assert!(ResultData::deserialize(candidate_result(&c,"inputs-pending")).unwrap().matches_context(&c));
        c.action=Action::AbandonInputs;assert!(ResultData::deserialize(candidate_result(&c,"settled-failure")).unwrap().matches_context(&c));
    }
    #[test]
    fn local_release_history_candidate_context_and_consent_are_action_specific(){
        for action in [Action::Enroll,Action::Verify,Action::ReviewInputs,Action::AbandonInputs,Action::ReviewPrepared,Action::ReviewExecution,Action::ReviewReconcile,Action::ReviewRecovery]{
            let c=context(action);let value=serde_json::to_value(&c).unwrap();
            assert_eq!(prepare(&value).unwrap(),c);assert_eq!(Context::deserialize(&value).unwrap(),c);
            assert_eq!(value.as_object().unwrap().len(),if action.candidate(){4}else{3});
            for token in [CONSENT,CANDIDATE_CONSENT]{
                let input=start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":token})).unwrap();
                assert_eq!(input.consents(context(action).consent()),token==action.consent());
            }
            let mut bad=value.clone();bad["candidateOperationId"]=Value::Null;
            assert!(prepare(&bad).is_err()&&Context::deserialize(&bad).is_err());
            if action.candidate(){
                let mut bad=value.clone();bad.as_object_mut().unwrap().remove("candidateOperationId");assert!(prepare(&bad).is_err());
                let mut bad=value;bad["candidateOperationId"]=json!("12345678-1234-1234-9234-123456789abc");assert!(prepare(&bad).is_err());
            }
        }
    }
    #[test]
    fn local_release_history_candidate_summary_cannot_create_old_finality_or_change_roster(){
        let c=context(Action::ReviewInputs);let ready=candidate_result(&c,"inputs-ready");
        let check=|v:&Value|ResultData::deserialize(v).is_ok_and(|r|r.matches_context(&c));
        assert!(check(&ready));
        for phase in ["inputs-pending","settled-failure"]{
            let value=candidate_result(&c,phase);let parsed=ResultData::deserialize(&value).unwrap();
            assert!(parsed.matches_context(&c));assert!(serde_json::to_value(parsed).unwrap()["candidateInputs"].is_null());
        }
        let mut missing=ready.clone();missing.as_object_mut().unwrap().remove("candidateInputs");assert!(!check(&missing));
        let mut null=ready.clone();null["candidateInputs"]=Value::Null;assert!(!check(&null));
        let mut old=result();old["candidateInputs"]=Value::Null;
        assert!(!ResultData::deserialize(&old).unwrap().matches_context(&context(Action::Verify)));
        assert!(!serde_json::to_value(ResultData::deserialize(&result()).unwrap()).unwrap().as_object().unwrap().contains_key("candidateInputs"));
        for (field,value) in [("priorCreateFinality",json!("complete")),("observation",json!("build-complete")),
            ("operationId",json!("12345678-1234-4234-9234-123456789abd")),("applicationId",json!("_dev.example")),
            ("sourceCommit",json!("a".repeat(64)))]{
            let mut bad=ready.clone();bad["candidateInputs"][field]=value;assert!(!check(&bad));
        }
        for i in 0..3{
            let mut bad=ready.clone();let n=bad["candidateInputs"]["files"][i]["bytes"].as_u64().unwrap();
            bad["candidateInputs"]["files"][i]["bytes"]=json!(n+1);assert!(!check(&bad));
        }
        let mut bad=ready.clone();bad["candidateInputs"]["files"].as_array_mut().unwrap().reverse();assert!(!check(&bad));
        let mut bad=ready.clone();bad["candidateInputs"]["path"]=json!("/arbitrary");assert!(!check(&bad));
        let c=context(Action::AbandonInputs);let mut value=candidate_result(&c,"settled-failure");
        assert!(ResultData::deserialize(&value).unwrap().matches_context(&c));
        value["headSequence"]=json!(4);value["history"].as_array_mut().unwrap().push(json!({"operationId":"12345678-1234-4234-9234-123456789abd","phase":"inputs-pending","recoveryRequired":true}));
        assert!(!ResultData::deserialize(&value).unwrap().matches_context(&c));
    }
    fn prefix(c:&Context,head:u32)->Decoder{
        let mut d=Decoder::new();decode(&mut d,c,0,"accepted",json!({"schemaVersion":1,"context":c})).unwrap();
        decode(&mut d,c,1,"lease-ready",json!({})).unwrap();
        decode(&mut d,c,2,"history-head",json!({"sequence":head,"sha256":"e".repeat(64)})).unwrap();d
    }
    #[test]
    fn local_release_history_candidate_phases_bind_successor_and_terminal_head(){
        for action in [Action::ReviewInputs,Action::AbandonInputs]{
            let c=context(action);let mut d=prefix(&c,2);let mut t=terminal(&c);
            t["result"]=candidate_result(&c,if action==Action::ReviewInputs{"inputs-pending"}else{"settled-failure"});
            let end=if action==Action::AbandonInputs{
                assert!(decode(&mut d,&c,3,"abandoned-head",json!({"sequence":3,"sha256":"f".repeat(64)})).is_ok());4
            }else{t["result"]["headSequence"]=json!(2);3};
            assert!(decode(&mut d,&c,end,"terminal",t.clone()).is_ok()&&d.finish());
            let mut d=prefix(&c,2);if action==Action::AbandonInputs{decode(&mut d,&c,3,"abandoned-head",json!({"sequence":3,"sha256":"f".repeat(64)})).unwrap();}
            t["result"]["headSequence"]=json!(4);assert!(decode(&mut d,&c,end,"terminal",t).is_err());
        }
        let c=context(Action::AbandonInputs);
        for next in [2,4,514]{let mut d=prefix(&c,2);assert!(decode(&mut d,&c,3,"abandoned-head",json!({"sequence":next,"sha256":"f".repeat(64)})).is_err());}
        let mut d=Decoder::new();decode(&mut d,&c,0,"accepted",json!({"schemaVersion":1,"context":c})).unwrap();decode(&mut d,&c,1,"lease-ready",json!({})).unwrap();
        assert!(decode(&mut d,&c,2,"history-head",json!({"sequence":513,"sha256":"e".repeat(64)})).is_err());
        let c=context(Action::ReviewInputs);let mut d=prefix(&c,513);let mut t=terminal(&c);t["result"]=candidate_result(&c,"inputs-pending");t["result"]["headSequence"]=json!(513);
        assert!(decode(&mut d,&c,3,"terminal",t).is_ok());
        let c=context(Action::Verify);let mut d=prefix(&c,2);assert!(decode(&mut d,&c,3,"abandoned-head",json!({"sequence":3,"sha256":"f".repeat(64)})).is_err());
    }

    #[test]
    fn local_release_history_review_reconcile_requires_current_last_execute_chain(){
        let c=context(Action::ReviewReconcile);let mut ready=prepared_result(&c);
        ready["history"].as_array_mut().unwrap().truncate(1);
        ready["headSequence"]=json!(6);ready["history"][0]["phase"]=json!("execute-pending");ready["history"][0]["recoveryRequired"]=json!(true);
        assert!(ResultData::deserialize(&ready).unwrap().matches_context(&c));
        assert!(!ResultData::deserialize(&ready).unwrap().matches_context(&context(Action::ReviewPrepared)));
        for phase in ["settled-success","settled-failure","reconciliation-required"]{let mut value=ready.clone();value["headSequence"]=json!(7);value["history"][0]["phase"]=json!(phase);value["history"][0]["recoveryRequired"]=json!(phase=="reconciliation-required");assert!(ResultData::deserialize(&value).unwrap().matches_context(&c));}
        for phase in ["prepared","prepare-pending","inputs-ready"]{let mut value=ready.clone();value["history"][0]["phase"]=json!(phase);assert!(!ResultData::deserialize(&value).unwrap().matches_context(&c));}
        let mut older=ready.clone();older["history"].as_array_mut().unwrap().push(json!({"operationId":"23456789-1234-4234-8234-123456789abc","phase":"inputs-pending","recoveryRequired":true}));assert!(!ResultData::deserialize(&older).unwrap().matches_context(&c));
        for head in [6,513]{let mut d=prefix(&c,head);let mut t=terminal(&c);t["result"]=ready.clone();t["result"]["headSequence"]=json!(head);assert!(decode(&mut d,&c,3,"terminal",t).is_ok());assert!(d.finish());}
        for key in ["preparedIntent","candidateInputs","executionReceipt"]{let mut value=ready.clone();value[key]=Value::Null;assert!(!ResultData::deserialize(&value).unwrap().matches_context(&c));}
    }
    fn prepared_result(c:&Context)->Value {
        let mut r=result();r["headSequence"]=json!(7);
        // Selected operation is prepared but a later, different operation exists.
        r["history"]=json!([
            {"operationId":c.candidate_operation_id,"phase":"prepared","recoveryRequired":true},
            {"operationId":"12345678-1234-4234-9234-123456789abd","phase":"inputs-ready","recoveryRequired":true}]);
        r["preparedIntent"]=json!({"operationId":c.candidate_operation_id,"candidateSha256":"a".repeat(64),
            "intentSha256":"b".repeat(64),"storePreconditionSha256":"c".repeat(64),"sourceCommit":"d".repeat(40),
            "sourceTree":"e".repeat(40),"applicationId":"dev.example.app","version":{"name":"1.2.3","build":12},
            "destination":{"channel":"internal","releaseStatus":"completed"},"observedAt":"2026-10-16T20:00:00Z",
            "limitations":["non-publishing","prepare-not-execute","temporary-edit-may-expire","current-bundle-not-historical-finality","saved-inputs-not-atomic"],
            "observation":"current-prepared-files-only","priorPrepareFinality":"not-established"});r
    }
    #[test]
    fn local_release_history_prepared_review_is_exact_read_only_summary_not_prepare_finality(){
        let c=context(Action::ReviewPrepared);let ready=prepared_result(&c);
        let check=|v:&Value|ResultData::deserialize(v).is_ok_and(|r|r.matches_context(&c));
        assert!(check(&ready));
        assert_eq!(serde_json::to_value(ResultData::deserialize(&ready).unwrap()).unwrap(),ready);
        assert_eq!(ready.as_object().unwrap().len(),7);
        assert_eq!(ready["preparedIntent"].as_object().unwrap().len(),13);
        for name in ready["preparedIntent"].as_object().unwrap().keys(){
            let mut bad=ready.clone();bad["preparedIntent"].as_object_mut().unwrap().remove(name);assert!(!check(&bad),"{name}");
        }
        for (field,value) in [("operationId",json!("12345678-1234-4234-9234-123456789abd")),
            ("candidateSha256",json!("not-a-digest")),("intentSha256",json!("b".repeat(63))),
            ("storePreconditionSha256",json!("C".repeat(64))),("sourceCommit",json!("d".repeat(64))),
            ("sourceTree",json!("")),("applicationId",json!("_dev.example")),("observedAt",json!("yesterday")),
            ("observation",json!("prepared")),("priorPrepareFinality",json!("complete")),("path",json!("/arbitrary"))]{
            let mut bad=ready.clone();bad["preparedIntent"][field]=value;assert!(!check(&bad),"{field}");
        }
        for value in [json!(0),json!(2_100_000_001u32)]{let mut bad=ready.clone();bad["preparedIntent"]["version"]["build"]=value;assert!(!check(&bad));}
        for value in [json!(""),json!("a".repeat(65)),json!("1/2")]{let mut bad=ready.clone();bad["preparedIntent"]["version"]["name"]=value;assert!(!check(&bad));}
        let mut bad=ready.clone();bad["preparedIntent"]["destination"]["channel"]=json!("production");assert!(!check(&bad));
        let mut bad=ready.clone();bad["preparedIntent"]["limitations"].as_array_mut().unwrap().reverse();assert!(!check(&bad));
        let mut bad=ready.clone();bad["preparedIntent"]=Value::Null;assert!(!check(&bad));
        let mut bad=ready.clone();bad.as_object_mut().unwrap().remove("preparedIntent");assert!(!check(&bad));
        let mut bad=ready.clone();bad["candidateInputs"]=Value::Null;assert!(!check(&bad));
        // No old action accepts the new field, including explicit null. Removing
        // observation markers yields only the shared11-field DATA, not authority.
        let mut summary=ready["preparedIntent"].clone();
        assert!(crate::local_store_prepare_protocol::PreparedIntent::deserialize(&summary).is_err());
        summary.as_object_mut().unwrap().remove("observation");summary.as_object_mut().unwrap().remove("priorPrepareFinality");
        assert!(crate::local_store_prepare_protocol::PreparedIntent::deserialize(&summary).unwrap().valid_for(c.candidate_operation_id.as_deref().unwrap()));
        for action in [Action::Enroll,Action::Verify,Action::ReviewInputs,Action::AbandonInputs]{
            let old_c=context(action);let old=if action.candidate(){candidate_result(&old_c,if action==Action::AbandonInputs{"settled-failure"}else{"inputs-ready"})}else{result()};
            assert!(ResultData::deserialize(&old).unwrap().matches_context(&old_c));
            for value in [Value::Null,ready["preparedIntent"].clone()]{
                let mut bad=old.clone();bad["preparedIntent"]=value;
                assert!(!ResultData::deserialize(&bad).unwrap().matches_context(&old_c));
            }
        }
    }
    #[test]
    fn local_ios_prepared_history_is_exact_platform_summary_not_reconcile_permission(){
        let mut c=context(Action::ReviewPrepared);c.platform=Some(CandidatePlatform::Ios);
        let mut ready=prepared_result(&c);let summary=&mut ready["preparedIntent"];
        summary.as_object_mut().unwrap().remove("applicationId");summary["bundleId"]=json!("dev.example.my-app");summary["appStoreAppId"]=json!("0012345678");
        summary["destination"]=json!({"channel":"testflight-internal"});
        summary["limitations"]=json!(["non-publishing","prepare-not-execute","current-asc-snapshot-may-change","current-bundle-not-historical-finality","saved-inputs-not-atomic"]);
        let check=|v:&Value|ResultData::deserialize(v).is_ok_and(|r|r.matches_context(&c));
        assert!(check(&ready));assert_eq!(ready["preparedIntent"].as_object().unwrap().len(),14);
        assert_eq!(serde_json::to_value(ResultData::deserialize(&ready).unwrap()).unwrap(),ready);
        assert!(!ResultData::deserialize(&ready).unwrap().matches_context(&context(Action::ReviewPrepared)));
        assert!(!check(&prepared_result(&context(Action::ReviewPrepared))));
        for field in ready["preparedIntent"].as_object().unwrap().keys(){let mut bad=ready.clone();bad["preparedIntent"].as_object_mut().unwrap().remove(field);assert!(!check(&bad),"{field}");}
        for(field,value)in[("applicationId",json!("dev.example.app")),("appStoreAppId",Value::Null),("priorPrepareFinality",json!("complete"))]{
            let mut bad=ready.clone();bad["preparedIntent"][field]=value;assert!(!check(&bad));}
        // A platform match alone does not make this earlier selected row the current last operation.
        let mut reconcile=ready.clone();reconcile["headSequence"]=json!(6);reconcile["history"][0]["phase"]=json!("execute-pending");
        for platform in [None,Some(CandidatePlatform::Ios)]{let mut other=context(Action::ReviewReconcile);other.platform=platform;
            assert!(!ResultData::deserialize(&reconcile).unwrap().matches_context(&other));}
    }
    #[test]
    fn local_release_history_ios_reconcile_requires_current_last_execution_and_exact_prepared_files(){
        let mut c=context(Action::ReviewReconcile);c.platform=Some(CandidatePlatform::Ios);assert!(prepare(&json!(c)).is_ok());
        let mut ready=prepared_result(&c);ready["history"].as_array_mut().unwrap().truncate(1);ready["headSequence"]=json!(6);
        ready["history"][0]["phase"]=json!("execute-pending");ready["history"][0]["recoveryRequired"]=json!(true);
        let p=&mut ready["preparedIntent"];p.as_object_mut().unwrap().remove("applicationId");p["bundleId"]=json!("dev.example.ios-app");p["appStoreAppId"]=json!("001234");
        p["destination"]=json!({"channel":"testflight-internal"});p["limitations"]=json!(["non-publishing","prepare-not-execute","current-asc-snapshot-may-change","current-bundle-not-historical-finality","saved-inputs-not-atomic"]);
        assert_eq!(p.as_object().unwrap().len(),14);
        let check=|v:&Value|ResultData::deserialize(v).is_ok_and(|r|r.matches_context(&c));assert!(check(&ready));
        for head in [6,513]{let mut d=prefix(&c,head);let mut t=terminal(&c);t["result"]=ready.clone();t["result"]["headSequence"]=json!(head);
            assert!(decode(&mut d,&c,3,"terminal",t).is_ok());assert!(d.finish());}
        for phase in ["settled-success","settled-failure","reconciliation-required"]{let mut v=ready.clone();v["headSequence"]=json!(7);v["history"][0]["phase"]=json!(phase);v["history"][0]["recoveryRequired"]=json!(phase=="reconciliation-required");assert!(check(&v));}
        let mut older=ready.clone();older["history"].as_array_mut().unwrap().push(json!({"operationId":"23456789-1234-4234-8234-123456789abc","phase":"inputs-pending","recoveryRequired":true}));assert!(!check(&older));
        for phase in ["prepared","prepare-pending","inputs-ready","target-reconciled"]{let mut bad=ready.clone();bad["history"][0]["phase"]=json!(phase);assert!(!check(&bad));}
        for key in ["preparedIntent","candidateInputs","executionReceipt","reconciliationReceipt"]{let mut bad=ready.clone();bad[key]=Value::Null;assert!(!check(&bad));}
        let mut android=c.clone();android.platform=None;assert!(!ResultData::deserialize(&ready).unwrap().matches_context(&android));
        let mut recovery=c.clone();recovery.action=Action::ReviewRecovery;assert!(prepare(&json!(recovery)).is_err());assert!(!ResultData::deserialize(&ready).unwrap().matches_context(&recovery));
        let mut bad=ready;bad["preparedIntent"]["observation"]=json!("current-internal-build-only");assert!(!check(&bad));
    }
    #[test]
    fn local_release_history_prepared_review_requires_selected_prepared_row_not_global_latest(){
        let c=context(Action::ReviewPrepared);let ready=prepared_result(&c);
        let check=|v:&Value|ResultData::deserialize(v).is_ok_and(|r|r.matches_context(&c));
        for head in [5,7,513]{let mut good=ready.clone();good["headSequence"]=json!(head);assert!(check(&good));}
        for head in [1,4,514]{let mut bad=ready.clone();bad["headSequence"]=json!(head);assert!(!check(&bad));}
        for phase in ["inputs-pending","inputs-ready","prepare-pending","execute-pending","settled-success","settled-failure","reconciliation-required"]{
            let mut bad=ready.clone();bad["history"][0]["phase"]=json!(phase);
            bad["history"][0]["recoveryRequired"]=json!(!phase.starts_with("settled-"));assert!(!check(&bad));
        }
        let mut bad=ready.clone();bad["history"][0]["recoveryRequired"]=json!(false);assert!(!check(&bad));
        let mut bad=ready.clone();bad["history"].as_array_mut().unwrap().remove(0);assert!(!check(&bad));
        let mut bad=ready.clone();let duplicate=bad["history"][0].clone();bad["history"].as_array_mut().unwrap().push(duplicate);assert!(!check(&bad));
    }
    #[test]
    fn local_release_history_prepared_review_keeps_original_phase_and_failure_finality(){
        let c=context(Action::ReviewPrepared);
        let rows=[("accepted",json!({"schemaVersion":1,"context":c})),("lease-ready",json!({})),
            ("history-head",json!({"sequence":7,"sha256":"e".repeat(64)}))];
        let mut t=terminal(&c);t["result"]=prepared_result(&c);
        let mut d=Decoder::new();for (i,(kind,payload)) in rows.iter().enumerate(){decode(&mut d,&c,i as u32,kind,payload.clone()).unwrap();}
        assert!(decode(&mut d,&c,3,"terminal",t.clone()).is_ok()&&d.finish());
        for prefix in 1..=3 {
            let mut d=Decoder::new();for (i,(kind,payload)) in rows.iter().take(prefix).enumerate(){decode(&mut d,&c,i as u32,kind,payload.clone()).unwrap();}
            let mut failed=t.clone();failed["outcome"]=json!("refused");failed["reason"]=json!("recovery-required");failed["result"]=Value::Null;
            assert!(decode(&mut d,&c,prefix as u32,"terminal",failed).is_ok()&&d.finish());
        }
        for mutation in 0..4 {
            let mut d=Decoder::new();let prefix=if mutation==0{2}else{3};
            for (i,(kind,payload)) in rows.iter().take(prefix).enumerate(){decode(&mut d,&c,i as u32,kind,payload.clone()).unwrap();}
            let mut bad=t.clone();match mutation {
                0=>{},1=>bad["result"]["headSequence"]=json!(8),
                2=>bad["lifetime"]["inputClosed"]=json!(false),_=>bad["lifetime"]["commands"]=json!(1),
            }
            assert!(decode(&mut d,&c,prefix as u32,"terminal",bad).is_err()&&!d.finish());
        }
        let mut d=Decoder::new();for (i,(kind,payload)) in rows.iter().enumerate(){decode(&mut d,&c,i as u32,kind,payload.clone()).unwrap();}
        assert!(decode(&mut d,&c,3,"abandoned-head",json!({"sequence":8,"sha256":"f".repeat(64)})).is_err());
    }
    fn execution_result(c:&Context)->Value {
        let mut r=prepared_result(c);r["headSequence"]=json!(8);
        r["history"][0]["phase"]=json!("settled-success");r["history"][0]["recoveryRequired"]=json!(false);
        r["history"][1]["phase"]=json!("inputs-pending");
        let mut receipt=r.as_object_mut().unwrap().remove("preparedIntent").unwrap();
        let object=receipt.as_object_mut().unwrap();object.remove("storePreconditionSha256");object.remove("priorPrepareFinality");
        receipt["receiptSha256"]=json!("f".repeat(64));receipt["authorizationId"]=json!("12345678-1234-4234-9234-123456789abd");
        receipt["result"]=json!("accepted");receipt["observation"]=json!("current-execution-files-only");receipt["priorExecutionFinality"]=json!("not-established");
        receipt["limitations"]=json!(["internal-testing-only","not-public-release","prior-prepare-finality-not-established","saved-inputs-not-atomic"]);
        r["executionReceipt"]=receipt;r
    }
    #[test]
    fn local_release_history_execution_review_is_exact_receipt_not_old_finality(){
        let c=context(Action::ReviewExecution);let ready=execution_result(&c);
        let check=|v:&Value|ResultData::deserialize(v).is_ok_and(|r|r.matches_context(&c));
        assert!(check(&ready));assert_eq!(serde_json::to_value(ResultData::deserialize(&ready).unwrap()).unwrap(),ready);
        assert_eq!(ready.as_object().unwrap().len(),7);assert_eq!(ready["executionReceipt"].as_object().unwrap().len(),15);
        for key in ready["executionReceipt"].as_object().unwrap().keys(){
            let mut bad=ready.clone();bad["executionReceipt"].as_object_mut().unwrap().remove(key);assert!(!check(&bad),"{key}");
        }
        for(field,value) in [("operationId",json!("12345678-1234-4234-9234-123456789abd")),("receiptSha256",json!("f".repeat(63))),
            ("authorizationId",json!("12345678-1234-1234-9234-123456789abd")),("candidateSha256",json!("A".repeat(64))),
            ("intentSha256",json!(false)),("sourceCommit",json!("d".repeat(64))),("result",json!("pending")),
            ("applicationId",json!("dev._bad")),("observedAt",json!("2026-02-30T12:00:00Z")),
            ("observation",json!("current-store-state")),("priorExecutionFinality",json!("complete")),("path",json!("/private"))]{
            let mut bad=ready.clone();bad["executionReceipt"][field]=value;assert!(!check(&bad),"{field}");
        }
        for value in [json!(0),json!(2_100_000_001u32)]{let mut bad=ready.clone();bad["executionReceipt"]["version"]["build"]=value;assert!(!check(&bad));}
        for value in [json!(""),json!("a".repeat(65)),json!("1/2")]{let mut bad=ready.clone();bad["executionReceipt"]["version"]["name"]=value;assert!(!check(&bad));}
        for key in ["candidateInputs","preparedIntent"]{let mut bad=ready.clone();bad[key]=Value::Null;assert!(!check(&bad));}
        let mut bad=ready.clone();bad["executionReceipt"]=Value::Null;assert!(!check(&bad));
        let mut bad=ready.clone();bad.as_object_mut().unwrap().remove("executionReceipt");assert!(!check(&bad));
        let mut bad=ready.clone();bad["executionReceipt"]["destination"]["channel"]=json!("production");assert!(!check(&bad));
        let mut bad=ready.clone();bad["executionReceipt"]["limitations"].as_array_mut().unwrap().reverse();assert!(!check(&bad));
        for action in [Action::Enroll,Action::Verify,Action::ReviewInputs,Action::AbandonInputs,Action::ReviewPrepared]{
            let old=context(action);let base=if action==Action::ReviewPrepared{prepared_result(&old)}else if action.candidate(){candidate_result(&old,if action==Action::AbandonInputs{"settled-failure"}else{"inputs-ready"})}else{result()};
            assert!(ResultData::deserialize(&base).unwrap().matches_context(&old));
            for receipt in [Value::Null,ready["executionReceipt"].clone()]{let mut bad=base.clone();bad["executionReceipt"]=receipt;assert!(!ResultData::deserialize(&bad).unwrap().matches_context(&old));}
        }
        // Removing observation markers exposes only shared13 DATA. The actual
        // Execute decoder separately retains original context/AUTH comparisons.
        let mut summary=ready["executionReceipt"].clone();assert!(crate::local_store_execute_protocol::ExecutionReceipt::deserialize(&summary).is_err());
        summary.as_object_mut().unwrap().remove("observation");summary.as_object_mut().unwrap().remove("priorExecutionFinality");
        assert!(crate::local_store_execute_protocol::ExecutionReceipt::deserialize(&summary).unwrap().valid_for(c.candidate_operation_id.as_deref().unwrap()));
    }
    #[test]
    fn local_release_history_ios_execution_has_exact_sixteen_fields_and_no_recovery(){
        let mut c=context(Action::ReviewExecution);c.platform=Some(CandidatePlatform::Ios);assert!(prepare(&json!(c)).is_ok());
        let mut ready=execution_result(&c);let receipt=ready["executionReceipt"].as_object_mut().unwrap();
        receipt.remove("applicationId");receipt.insert("bundleId".into(),json!("dev.example.ios-app"));receipt.insert("appStoreAppId".into(),json!("000123"));receipt.insert("destination".into(),json!({"channel":"testflight-internal"}));
        assert_eq!(receipt.len(),16);assert!(ResultData::deserialize(&ready).unwrap().matches_context(&c));
        let mut android=c.clone();android.platform=None;assert!(!ResultData::deserialize(&ready).unwrap().matches_context(&android));
        let mut unsupported=c.clone();unsupported.action=Action::ReviewRecovery;assert!(!unsupported.valid());
        let mut reconcile=c.clone();reconcile.action=Action::ReviewReconcile;assert!(reconcile.valid());assert!(!ResultData::deserialize(&ready).unwrap().matches_context(&reconcile));
        for (key,value) in [("applicationId",json!("dev.example.app")),("appStoreAppId",json!(123)),("priorExecutionFinality",json!("complete")),("observation",json!("current-store-state"))]{
            let mut bad=ready.clone();bad["executionReceipt"][key]=value;assert!(!ResultData::deserialize(&bad).is_ok_and(|r|r.matches_context(&c)));
        }
        let mut earlier=ready;earlier["headSequence"]=json!(513);assert!(ResultData::deserialize(&earlier).unwrap().matches_context(&c));
    }
    #[test]
    fn local_release_history_execution_review_requires_selected_success_not_latest_operation(){
        let c=context(Action::ReviewExecution);let ready=execution_result(&c);
        let check=|v:&Value|ResultData::deserialize(v).is_ok_and(|r|r.matches_context(&c));
        for head in [8,513]{let mut good=ready.clone();good["headSequence"]=json!(head);assert!(check(&good));}
        let mut first=ready.clone();first["headSequence"]=json!(7);first["history"].as_array_mut().unwrap().pop();assert!(check(&first));
        for head in [1,6,514]{let mut bad=ready.clone();bad["headSequence"]=json!(head);assert!(!check(&bad));}
        for phase in ["inputs-pending","inputs-ready","prepare-pending","prepared","execute-pending","settled-failure","reconciliation-required"]{
            let mut bad=ready.clone();bad["history"][0]["phase"]=json!(phase);bad["history"][0]["recoveryRequired"]=json!(!phase.starts_with("settled-"));assert!(!check(&bad));
        }
        let mut bad=ready.clone();bad["history"][0]["recoveryRequired"]=json!(true);assert!(!check(&bad));
        let mut bad=ready.clone();bad["history"].as_array_mut().unwrap().remove(0);assert!(!check(&bad));
        let mut bad=ready.clone();let duplicate=bad["history"][0].clone();bad["history"].as_array_mut().unwrap().push(duplicate);assert!(!check(&bad));
    }
    #[test]
    fn local_release_history_execution_review_keeps_read_only_phases_and_finality(){
        let c=context(Action::ReviewExecution);
        let rows=[("accepted",json!({"schemaVersion":1,"context":c})),("lease-ready",json!({})),("history-head",json!({"sequence":8,"sha256":"e".repeat(64)}))];
        let mut t=terminal(&c);t["result"]=execution_result(&c);
        let mut d=Decoder::new();for(i,(kind,payload))in rows.iter().enumerate(){decode(&mut d,&c,i as u32,kind,payload.clone()).unwrap();}
        assert!(decode(&mut d,&c,3,"terminal",t.clone()).is_ok()&&d.finish());
        for prefix in 1..=3{
            let mut d=Decoder::new();for(i,(kind,payload))in rows.iter().take(prefix).enumerate(){decode(&mut d,&c,i as u32,kind,payload.clone()).unwrap();}
            let mut failed=t.clone();failed["outcome"]=json!("refused");failed["reason"]=json!("journal-unavailable");failed["result"]=Value::Null;
            assert!(decode(&mut d,&c,prefix as u32,"terminal",failed).is_ok()&&d.finish());
        }
        for mutation in 0..4{
            let mut d=Decoder::new();let prefix=if mutation==0{2}else{3};
            for(i,(kind,payload))in rows.iter().take(prefix).enumerate(){decode(&mut d,&c,i as u32,kind,payload.clone()).unwrap();}
            let mut bad=t.clone();match mutation{0=>{},1=>bad["result"]["headSequence"]=json!(9),2=>bad["lifetime"]["inputClosed"]=json!(false),_=>bad["lifetime"]["commands"]=json!(1)}
            assert!(decode(&mut d,&c,prefix as u32,"terminal",bad).is_err()&&!d.finish());
        }
        let mut d=Decoder::new();for(i,(kind,payload))in rows.iter().enumerate(){decode(&mut d,&c,i as u32,kind,payload.clone()).unwrap();}
        assert!(decode(&mut d,&c,3,"abandoned-head",json!({"sequence":9,"sha256":"f".repeat(64)})).is_err());
    }
    #[test]
    fn local_release_history_public_summary_cannot_hide_recovery_or_exceed_journal_bound(){
        let mut v=result();v["headSequence"]=json!(2);v["history"]=json!([{"operationId":"12345678-1234-4234-9234-123456789abc","phase":"inputs-pending","recoveryRequired":true}]);
        assert!(ResultData::deserialize(&v).unwrap().valid());
        v["history"][0]["recoveryRequired"]=json!(false);assert!(!ResultData::deserialize(&v).unwrap().valid());
        v["history"][0]["phase"]=json!("settled-success");assert!(ResultData::deserialize(&v).unwrap().valid());
        v["headSequence"]=json!(514);assert!(!ResultData::deserialize(&v).unwrap().valid());v["headSequence"]=json!(513);
        let row=v["history"][0].clone();v["history"]=json!(vec![row;65]);assert!(!ResultData::deserialize(&v).unwrap().valid());
        let c=context(Action::Verify);let mut t=terminal(&c);t["lifetime"]["inputClosed"]=json!(false);
        assert!(!Terminal::deserialize(&t).unwrap().valid(&c));
    }
    fn recovery_result(c:&Context)->Value{
        let mut r=execution_result(c);r["history"][0]["phase"]=json!("target-reconciled");
        r.as_object_mut().unwrap().remove("executionReceipt");
        let mut receipt=crate::local_store_reconcile_protocol::tests::terminal()["result"]["reconciliationReceipt"].clone();
        receipt["operationId"]=json!(c.candidate_operation_id);receipt["observation"]=json!("current-recovery-files-only");r["reconciliationReceipt"]=receipt;r
    }
    #[test]
    fn local_release_history_recovery_review_is_distinct_current_files_not_live_or_old_finality(){
        let c=context(Action::ReviewRecovery);let ready=recovery_result(&c);
        let check=|v:&Value|ResultData::deserialize(v).is_ok_and(|r|r.matches_context(&c));
        assert!(check(&ready));assert_eq!(serde_json::to_value(ResultData::deserialize(&ready).unwrap()).unwrap(),ready);
        assert_eq!(ready.as_object().unwrap().len(),7);assert_eq!(ready["reconciliationReceipt"].as_object().unwrap().len(),15);
        for head in [8,513]{let mut good=ready.clone();good["headSequence"]=json!(head);assert!(check(&good));}
        let mut first=ready.clone();first["headSequence"]=json!(7);first["history"].as_array_mut().unwrap().pop();assert!(check(&first));
        for head in [6,514]{let mut bad=first.clone();bad["headSequence"]=json!(head);assert!(!check(&bad));}
        for phase in ["execute-pending","settled-success","settled-failure","reconciliation-required"]{
            let mut bad=ready.clone();bad["history"][0]["phase"]=json!(phase);bad["history"][0]["recoveryRequired"]=json!(!phase.starts_with("settled-"));assert!(!check(&bad));}
        let mut bad=ready.clone();bad["history"][0]["recoveryRequired"]=json!(true);assert!(!check(&bad));
        for(key,value) in [("observation",json!("current-internal-target-only")),("priorExecutionFinality",json!("established")),
            ("result",json!("accepted")),("receiptSha256",json!("wrong")),("authorizationId",json!("not-native")),("privatePath",json!("/no"))]{
            let mut bad=ready.clone();bad["reconciliationReceipt"][key]=value;assert!(!check(&bad));}
        for key in ready["reconciliationReceipt"].as_object().unwrap().keys(){let mut bad=ready.clone();bad["reconciliationReceipt"].as_object_mut().unwrap().remove(key);assert!(!check(&bad));}
        for key in ["candidateInputs","preparedIntent","executionReceipt","reconciliationReceipt"]{let mut bad=ready.clone();bad[key]=Value::Null;assert!(!check(&bad));}
        let mut missing=ready.clone();missing.as_object_mut().unwrap().remove("reconciliationReceipt");assert!(!check(&missing));
        for action in [Action::Verify,Action::ReviewPrepared,Action::ReviewExecution,Action::ReviewReconcile]{assert!(!ResultData::deserialize(&ready).unwrap().matches_context(&context(action)));}
        let receipt=crate::local_store_reconcile_protocol::ReconciliationReceipt::deserialize(&ready["reconciliationReceipt"]).unwrap();
        assert!(!receipt.valid_for(c.candidate_operation_id.as_deref().unwrap()));
        assert!(receipt.valid_recovery_review(c.candidate_operation_id.as_deref().unwrap()));
    }
    #[test]
    fn local_release_history_recovery_review_keeps_two_events_and_all_original_close_checks(){
        let c=context(Action::ReviewRecovery);let ready=recovery_result(&c);let mut t=terminal(&c);t["result"]=ready;
        assert!(decode(&mut prefix(&c,8),&c,3,"terminal",t.clone()).is_ok());
        for field in ["inputClosed","handlersRestored","invocationClosed"]{let mut bad=t.clone();bad["lifetime"][field]=json!(false);assert!(decode(&mut prefix(&c,8),&c,3,"terminal",bad).is_err());}
        let mut wrong=t.clone();wrong["result"]["headSequence"]=json!(9);assert!(decode(&mut prefix(&c,8),&c,3,"terminal",wrong).is_err());
        assert!(decode(&mut prefix(&c,8),&c,3,"recovery-settled",json!({"head":{"sequence":9,"sha256":"a".repeat(64)},"phase":"target-reconciled"})).is_err());
        t["outcome"]=json!("refused");t["reason"]=json!("recovery-required");t["result"]=Value::Null;assert!(decode(&mut prefix(&c,8),&c,3,"terminal",t).is_ok());
    }

    #[test]
    fn local_release_history_external_readiness_is_exact_offline_observation_not_old_finality(){
        let id="34567890-1234-4234-8234-123456789abc";
        let c=prepare(&json!({"projectId":"registered-project","executionMode":"local","action":"review-external-readiness","platform":"ios","stageOperationId":id})).unwrap();
        assert_eq!(c.consent(),IOS_CANDIDATE_CONSENT);assert_eq!(c.selected_operation_id(),Some(id));
        let mut ready=result();ready["headSequence"]=json!(12);ready["history"]=json!([{"operationId":id,"phase":"external-ready","recoveryRequired":false}]);
        let mut receipt=crate::local_store_reconcile_protocol::tests::readiness_terminal(12)["result"]["readinessReceipt"].clone();
        receipt["observation"]=json!("current-external-readiness-files-only");ready["readinessReceipt"]=receipt;
        let check=|v:&Value|ResultData::deserialize(v).is_ok_and(|r|r.matches_context(&c));assert!(check(&ready));
        assert_eq!(serde_json::to_value(ResultData::deserialize(&ready).unwrap()).unwrap(),ready);
        assert_eq!(ready.as_object().unwrap().len(),7);assert_eq!(ready["readinessReceipt"].as_object().unwrap().len(),19);
        let mut later=ready.clone();later["headSequence"]=json!(513);later["history"].as_array_mut().unwrap().push(json!({"operationId":"45678901-1234-4234-8234-123456789abc","phase":"promotion-pending","recoveryRequired":true}));assert!(check(&later));
        for field in ["candidateInputs","preparedIntent","executionReceipt","reconciliationReceipt","readinessReceipt"]{let mut bad=ready.clone();bad[field]=Value::Null;assert!(!check(&bad));}
        for(field,value)in[("observation",json!("current-external-target-only")),("priorExecutionFinality",json!("complete")),("operationId",json!("12345678-1234-4234-8234-123456789abc")),("state",json!("waiting-for-review"))]{let mut bad=ready.clone();bad["readinessReceipt"][field]=value;assert!(!check(&bad));}
        let mut bad=ready.clone();bad["headSequence"]=json!(11);assert!(!check(&bad));bad=ready.clone();bad["history"][0]["phase"]=json!("settled-success");assert!(!check(&bad));
        for(field,value)in[("platform",json!("android")),("candidateOperationId",json!(id)),("action",json!("review-stage-execution"))]{let mut value_context=json!(c);value_context[field]=value;
            assert!(!Context::deserialize(&value_context).is_ok_and(|other|ResultData::deserialize(&ready).unwrap().matches_context(&other)));}
        let mut t=terminal(&c);t["result"]=ready;
        let mut d=prefix(&c,12);assert!(decode(&mut d,&c,3,"terminal",t.clone()).is_ok()&&d.finish());
        for field in ["inputClosed","handlersRestored","invocationClosed"]{let mut bad=t.clone();bad["lifetime"][field]=json!(false);assert!(decode(&mut prefix(&c,12),&c,3,"terminal",bad).is_err());}
        assert!(decode(&mut prefix(&c,12),&c,3,"external-ready",json!({"head":{"sequence":13,"sha256":"a".repeat(64)},"phase":"external-ready"})).is_err());
    }

}

// Closed helper callback DATA: nominal H is checked, but only an actual failure
// or STOP may be projected as Some(F+2) into the existing LookupBook API.
pub(crate) fn helper_cleanup_projection(now:Instant,hard:Instant,end:Instant,failed:bool)->Result<Option<Instant>,()>{
    if end>hard || now>=end{return Err(());}
    Ok(failed.then_some(end))
}
#[cfg(test)]
mod local_release_history_cleanup_tests {
    use super::*;
    #[test]
    fn local_release_history_healthy_cleanup_does_not_manufacture_failure(){
        let now=Instant::now();let hard=now+Duration::from_secs(62);
        assert_eq!(helper_cleanup_projection(now,hard,hard,false),Ok(None));
        assert_eq!(helper_cleanup_projection(now,hard,now+Duration::from_secs(2),true),Ok(Some(now+Duration::from_secs(2))));
        assert!(helper_cleanup_projection(hard,hard,hard,false).is_err());
        assert!(helper_cleanup_projection(now,hard,hard+Duration::from_nanos(1),false).is_err());
    }
}
