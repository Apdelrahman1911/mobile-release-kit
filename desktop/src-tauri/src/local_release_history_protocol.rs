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
pub(crate) enum Action { Enroll, Verify, ReviewInputs, AbandonInputs }
impl Action {
    pub(crate) fn candidate(self)->bool{matches!(self,Self::ReviewInputs|Self::AbandonInputs)}
    pub(crate) fn consent(self)->&'static str{if self.candidate(){CANDIDATE_CONSENT}else{CONSENT}}
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase")]
pub(crate) struct Context {
    pub(crate) project_id:String,pub(crate) execution_mode:ExecutionMode,pub(crate) action:Action,
    #[serde(skip_serializing_if="Option::is_none")]
    pub(crate) candidate_operation_id:Option<String>,
}
impl Context {pub(crate) fn valid(&self)->bool{valid_id(&self.project_id)&&if self.action.candidate(){
    self.candidate_operation_id.as_deref().is_some_and(journal_uuid)
}else{self.candidate_operation_id.is_none()}}}
impl<'de> Deserialize<'de> for Context {
    fn deserialize<D:serde::Deserializer<'de>>(decoder:D)->Result<Self,D::Error>{
        let value=Value::deserialize(decoder)?;
        #[derive(Deserialize)]
        #[serde(rename_all="camelCase",deny_unknown_fields)]
        struct Data{project_id:String,execution_mode:ExecutionMode,action:Action,candidate_operation_id:Option<String>}
        let data=Data::deserialize(&value).map_err(serde::de::Error::custom)?;
        let expected=if data.action.candidate(){&["projectId","executionMode","action","candidateOperationId"][..]}
            else{&["projectId","executionMode","action"][..]};
        let result=Self{project_id:data.project_id,execution_mode:data.execution_mode,action:data.action,candidate_operation_id:data.candidate_operation_id};
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
    if !token(&input.operation_id) || !token(&input.owner_generation) || !matches!(input.consent_version.as_str(),CONSENT|CANDIDATE_CONSENT) { return Err(invalid()); } Ok(input)
}
impl Start {pub(crate) fn consents(&self,action:Action)->bool{self.consent_version==action.consent()}}
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
pub(crate) enum HistoryPhase {InputsPending,InputsReady,PreparePending,Prepared,ExecutePending,SettledSuccess,SettledFailure,ReconciliationRequired}
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
    candidate_inputs:Option<Option<CandidateInputs>>,
}
fn candidate_field<'de,D:serde::Deserializer<'de>>(decoder:D)->Result<Option<Option<CandidateInputs>>,D::Error>{
    Ok(Some(Option::<CandidateInputs>::deserialize(decoder)?))
}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct CandidateInputs {operation_id:String,candidate_sha256:String,source_commit:String,source_tree:String,
    application_id:String,version:CandidateVersion,files:[CandidateFile;3],observation:String,prior_create_finality:String}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
struct CandidateVersion{name:String,build:u32}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct CandidateFile{file_name:String,bytes:u64,sha256:String}
impl CandidateInputs {
    fn valid(&self,operation:&str)->bool{
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
}

fn journal_uuid(v:&str)->bool{let b=v.as_bytes();b.len()==36&&b[8]==b'-'&&b[13]==b'-'&&b[18]==b'-'&&b[23]==b'-'&&b[14]==b'4'
    &&matches!(b[19],b'8'|b'9'|b'a'|b'b')&&b.iter().enumerate().all(|(i,c)|matches!(i,8|13|18|23)||c.is_ascii_digit()||(b'a'..=b'f').contains(c))}
impl ResultData {fn valid(&self)->bool{self.schema_version==1&&self.scope=="local-release-history"&&self.enrolled
    &&(1..=513).contains(&self.head_sequence)&&self.history.len()<=64&&self.history.len()<(self.head_sequence as usize)
    &&self.limitations==LIMITATIONS&&self.history.iter().enumerate().all(|(i,r)|journal_uuid(&r.operation_id)
        &&!self.history[..i].iter().any(|p|p.operation_id==r.operation_id)
        &&r.recovery_required!=matches!(r.phase,HistoryPhase::SettledSuccess|HistoryPhase::SettledFailure))}}
impl ResultData {
    fn matches_context(&self,context:&Context)->bool{
        if !self.valid(){return false;}
        if !context.action.candidate(){return self.candidate_inputs.is_none();}
        let Some(id)=context.candidate_operation_id.as_deref() else{return false;};
        let Some(row)=self.history.iter().find(|row|row.operation_id==id) else{return false;};
        match(context.action,row.phase,&self.candidate_inputs){
            (Action::ReviewInputs,HistoryPhase::InputsReady,Some(Some(bundle)))=>bundle.valid(id),
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
            let expected=match (context.action,self.next){(_,0)=>"accepted",(_,1)=>"lease-ready",(Action::Enroll,2)=>"empty-journal-ready",(Action::Enroll,3)=>"durable-genesis",(Action::Verify|Action::ReviewInputs|Action::AbandonInputs,2)=>"history-head",(Action::AbandonInputs,3)=>"abandoned-head",_=>"terminal"};
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
    fn context(action:Action)->Context {Context{project_id:"registered-project".into(),execution_mode:ExecutionMode::Local,action,candidate_operation_id:action.candidate().then(||"12345678-1234-4234-9234-123456789abc".into())}}
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
    fn local_release_history_candidate_context_and_consent_are_action_specific(){
        for action in [Action::Enroll,Action::Verify,Action::ReviewInputs,Action::AbandonInputs]{
            let c=context(action);let value=serde_json::to_value(&c).unwrap();
            assert_eq!(prepare(&value).unwrap(),c);assert_eq!(Context::deserialize(&value).unwrap(),c);
            assert_eq!(value.as_object().unwrap().len(),if action.candidate(){4}else{3});
            for token in [CONSENT,CANDIDATE_CONSENT]{
                let input=start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":token})).unwrap();
                assert_eq!(input.consents(action),token==action.consent());
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
    #[test]
    fn local_release_history_candidate_phases_bind_successor_and_terminal_head(){
        fn prefix(c:&Context,head:u32)->Decoder{
            let mut d=Decoder::new();decode(&mut d,c,0,"accepted",json!({"schemaVersion":1,"context":c})).unwrap();
            decode(&mut d,c,1,"lease-ready",json!({})).unwrap();
            decode(&mut d,c,2,"history-head",json!({"sequence":head,"sha256":"e".repeat(64)})).unwrap();d
        }
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
