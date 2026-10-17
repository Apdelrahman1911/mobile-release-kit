//! Closed local Android target readback DATA; only the genuine current native owner grants an action.
//! A core terminal is provisional until this operation's original native joins.
use std::path::Path;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::{asset_source::RegisteredRoot, edit_protocol::{bounded, token}, error::BridgeError,
    protocol::{check_value, strict_json, valid_id}};

pub(crate) const PROTOCOL: &str = "mrk-local-store-reconcile/1";
pub(crate) const CONSENT: &str = "local-android-store-reconcile-v1";
pub(crate) const EVENT: &str = "local-store-reconcile-state-changed";
pub(crate) const IPC_LIMIT: usize = 16 * 1024;
pub(crate) const REQUEST_LIMIT: usize = 16 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 64 * 1024; // Four frames, framing and rejected drain bytes.
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
pub(crate) use crate::local_store_preflight_protocol::{Platform,ExecutionMode,Profile,Outcome,Phase,Availability};
pub(crate) use crate::local_release_history_protocol::Head;
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Operation { LocalStoreReconcile }
fn uuid(v:&str)->bool { crate::local_release_history_protocol::journal_uuid(v) }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) project_id: String, pub(crate) draft_revision: u32, pub(crate) baseline_generation: u32,
    pub(crate) saved_config: Content, pub(crate) saved_version: crate::android_build_protocol::SavedVersion,
    pub(crate) credential_context_revision: u32, pub(crate) record_id: String, pub(crate) record_revision: u32,
    pub(crate) execution_mode: ExecutionMode, pub(crate) platform: Platform, pub(crate) operation: Operation,
    pub(crate) candidate_operation_id:String, pub(crate) candidate_sha256:String, pub(crate) confirmation:String,
    pub(crate) intent_sha256:String,
}
impl Context {
    fn valid(&self) -> bool { valid_id(&self.project_id) && self.draft_revision < u32::MAX
        && self.baseline_generation < u32::MAX && self.saved_config.valid() && self.saved_version.valid()
        && self.credential_context_revision > 0 && self.credential_context_revision < u32::MAX
        && token(&self.record_id) && self.record_revision > 0 && self.record_revision < u32::MAX
        && uuid(&self.candidate_operation_id) && sha(&self.candidate_sha256) && sha(&self.intent_sha256)
        && self.confirmation==format!("candidate:android:{}:{}",self.saved_version.name,self.saved_version.build) }
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
}
impl Prepare {
    pub(crate) fn context(&self) -> Context { Context { project_id: self.project_id.clone(), draft_revision: self.draft_revision,
        baseline_generation: self.baseline_generation, saved_config: self.saved_config.clone(),
        saved_version: self.saved_version.clone(), credential_context_revision: self.credential_context_revision,
        record_id: self.record_id.clone(), record_revision: self.record_revision, execution_mode: self.execution_mode,
        platform: Platform::Android, operation: Operation::LocalStoreReconcile, candidate_operation_id:self.candidate_operation_id.clone(),
        candidate_sha256:self.candidate_sha256.clone(),confirmation:self.confirmation.clone(),
        intent_sha256:self.intent_sha256.clone() } }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Start { pub(crate) operation_id: String, pub(crate) owner_generation: String, consent_version: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cancel { pub(crate) operation_id: String, pub(crate) owner_generation: String }
pub(crate) fn prepare(value: &Value) -> Result<Prepare, BridgeError> {
    if !keys(value, &["projectId", "draftRevision", "baselineGeneration", "savedConfig", "savedVersion",
        "credentialContextRevision", "recordId", "recordRevision", "executionMode", "candidateOperationId", "candidateSha256", "confirmation", "intentSha256"]) { return Err(invalid()); }
    let input = Prepare::deserialize(value).map_err(|_| invalid())?;
    if !input.context().valid() { return Err(invalid()); } Ok(input)
}
pub(crate) fn start(value: &Value) -> Result<Start, BridgeError> {
    if !keys(value, &["operationId", "ownerGeneration", "consentVersion"]) { return Err(invalid()); }
    let input = Start::deserialize(value).map_err(|_| invalid())?;
    if !token(&input.operation_id) || !token(&input.owner_generation) || input.consent_version != CONSENT { return Err(invalid()); } Ok(input)
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
    None, ReconcileUnavailable, Cancelled, ContextChanged, DocumentLost, Shutdown, TimedOut, ProtocolError, RuntimeUnavailable, IntentExpired,
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
pub(crate) struct ReconciliationReceipt {operation_id:String,candidate_sha256:String,intent_sha256:String,receipt_sha256:String,authorization_id:String,
    source_commit:String,source_tree:String,application_id:String,version:Version,destination:Destination,observed_at:String,result:ReceiptResult,limitations:Vec<Limitation>,observation:String,prior_execution_finality:String}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct ResultData {schema_version:u32,scope:String,head_sequence:u32,reconciliation_receipt:ReconciliationReceipt}
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
    pub(crate) fn valid_for(&self,operation:&str)->bool {
        let p=self;
        let hex=|v:&str,n|v.len()==n&&v.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b));
        let app=p.application_id.len()<=255&&p.application_id.split('.').count()>=2&&p.application_id.split('.').all(|v|
            v.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)&&v.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_'));
        p.operation_id==operation&&uuid(operation)&&sha(&p.candidate_sha256)&&sha(&p.intent_sha256)&&sha(&p.receipt_sha256)
            &&uuid(&p.authorization_id)&&hex(&p.source_commit,40)&&hex(&p.source_tree,40)&&app
            &&!p.version.name.is_empty()&&p.version.name.len()<=64
            &&p.version.name.bytes().all(|b|b.is_ascii_alphanumeric()||b".+-".contains(&b))
            &&(1..=2_100_000_000).contains(&p.version.build)
            &&p.observation=="current-internal-target-only"&&p.prior_execution_finality=="not-established"
            &&p.destination.channel=="internal"&&p.destination.release_status=="completed"&&utc_second(&p.observed_at)&&p.limitations==LIMITATIONS
    }
}
impl ResultData {
    fn valid(&self,c:&Context,authorization:&str)->bool {
        let p=&self.reconciliation_receipt;
        self.schema_version==1&&self.scope=="local-android-store-reconcile"&&(6..=513).contains(&self.head_sequence)
            &&p.valid_for(&c.candidate_operation_id)&&p.candidate_sha256==c.candidate_sha256&&p.intent_sha256==c.intent_sha256
            &&uuid(authorization)&&p.authorization_id==authorization
            &&p.version.name==c.saved_version.name&&p.version.build==c.saved_version.build
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
            || self.lifetime.commands > 14 { return false; }
        if self.outcome == Outcome::Complete {
            return self.reason == Reason::None && self.lifetime.settled() && self.lifetime.stop_observed == CoreStop::None
                && self.lifetime.commands==14 && self.lifetime.command_dispatched==Some(true)
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
pub(crate) enum Event {LeaseReady,HistoryHead(Head)}
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
                ||e.sequence!=self.next||self.next>=4||!token(operation)||!token(generation)||nonce.len()!=32||!token(nonce)||nonce=="0".repeat(32)||!sha(digest){return Err(BridgeError::protocol());}
            if e.kind=="terminal" {
                if self.next==0||!keys(&e.payload,&["schemaVersion","context","outcome","reason","result","lifetime"])
                    ||!e.payload.get("lifetime").is_some_and(|l|keys(l,&["complete","fatal","contained","commandDispatched","commands","profileCalls","inputClosed","handlersRestored","invocationClosed","stopObserved"])) {return Err(BridgeError::protocol());}
                let t=Terminal::deserialize(&e.payload).map_err(|_|BridgeError::protocol())?;
                if !t.valid(context,&self.authorization)||t.outcome==Outcome::Complete&&(self.next!=3||!self.head.as_ref().is_some_and(|h|t.result.as_ref().is_some_and(|r|r.head_sequence==h.sequence))){return Err(BridgeError::protocol());}
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
                    if !head.valid()||!(6..=513).contains(&head.sequence){return Err(BridgeError::protocol());}
                    self.head=Some(head.clone());Ok(Frame::Event(Event::HistoryHead(head)))
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
    fn terminal()->Value{json!({"schemaVersion":1,"context":context(),"outcome":"complete","reason":"none",
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
}
