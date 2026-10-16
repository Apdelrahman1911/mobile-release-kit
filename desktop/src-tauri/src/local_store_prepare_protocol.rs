//! Closed local Android preparation DATA; a temporary uncommitted edit is not publication authority.
//! A core terminal is provisional until this operation's original native joins.
use std::path::Path;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::{asset_source::RegisteredRoot, edit_protocol::{bounded, token}, error::BridgeError,
    protocol::{check_value, strict_json, valid_id}};

pub(crate) const PROTOCOL: &str = "mrk-local-store-prepare/1";
pub(crate) const CONSENT: &str = "local-android-store-prepare-v1";
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
pub(crate) use crate::local_store_preflight_protocol::{Platform,ExecutionMode,Profile,Outcome,Phase,Availability};
pub(crate) use crate::local_release_history_protocol::Head;
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Operation { LocalStorePrepare }
fn uuid(v:&str)->bool { uuid::Uuid::parse_str(v).is_ok_and(|u|u.get_version_num()==4 && u.get_variant()==uuid::Variant::RFC4122 && u.to_string()==v) }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) project_id: String, pub(crate) draft_revision: u32, pub(crate) baseline_generation: u32,
    pub(crate) saved_config: Content, pub(crate) saved_version: crate::android_build_protocol::SavedVersion,
    pub(crate) credential_context_revision: u32, pub(crate) record_id: String, pub(crate) record_revision: u32,
    pub(crate) execution_mode: ExecutionMode, pub(crate) platform: Platform, pub(crate) operation: Operation,
    pub(crate) candidate_operation_id:String, pub(crate) candidate_sha256:String, pub(crate) confirmation:String,
}
impl Context {
    fn valid(&self) -> bool { valid_id(&self.project_id) && self.draft_revision < u32::MAX
        && self.baseline_generation < u32::MAX && self.saved_config.valid() && self.saved_version.valid()
        && self.credential_context_revision > 0 && self.credential_context_revision < u32::MAX
        && token(&self.record_id) && self.record_revision > 0 && self.record_revision < u32::MAX
        && uuid(&self.candidate_operation_id) && sha(&self.candidate_sha256)
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
}
impl Prepare {
    pub(crate) fn context(&self) -> Context { Context { project_id: self.project_id.clone(), draft_revision: self.draft_revision,
        baseline_generation: self.baseline_generation, saved_config: self.saved_config.clone(),
        saved_version: self.saved_version.clone(), credential_context_revision: self.credential_context_revision,
        record_id: self.record_id.clone(), record_revision: self.record_revision, execution_mode: self.execution_mode,
        platform: Platform::Android, operation: Operation::LocalStorePrepare, candidate_operation_id:self.candidate_operation_id.clone(),
        candidate_sha256:self.candidate_sha256.clone(),confirmation:self.confirmation.clone() } }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Start { pub(crate) operation_id: String, pub(crate) owner_generation: String, consent_version: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cancel { pub(crate) operation_id: String, pub(crate) owner_generation: String }
pub(crate) fn prepare(value: &Value) -> Result<Prepare, BridgeError> {
    if !keys(value, &["projectId", "draftRevision", "baselineGeneration", "savedConfig", "savedVersion",
        "credentialContextRevision", "recordId", "recordRevision", "executionMode", "candidateOperationId", "candidateSha256", "confirmation"]) { return Err(invalid()); }
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
    None, PrepareUnavailable, Cancelled, ContextChanged, DocumentLost, Shutdown, TimedOut, ProtocolError, RuntimeUnavailable, IntentExpired,
    StaleIntent, SavedSourceChanged, SavedSourceInvalid, CredentialsUnavailable, QueryPrerequisites, CommandIncomplete, CleanupUnknown,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="kebab-case")]
enum Limitation {NonPublishing,PrepareNotExecute,TemporaryEditMayExpire,CurrentBundleNotHistoricalFinality,SavedInputsNotAtomic}
const LIMITATIONS:[Limitation;5]=[Limitation::NonPublishing,Limitation::PrepareNotExecute,Limitation::TemporaryEditMayExpire,Limitation::CurrentBundleNotHistoricalFinality,Limitation::SavedInputsNotAtomic];
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
struct Version {name:String,build:u32}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Destination {channel:String,release_status:String}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct PreparedIntent {operation_id:String,candidate_sha256:String,intent_sha256:String,store_precondition_sha256:String,
    source_commit:String,source_tree:String,application_id:String,version:Version,destination:Destination,observed_at:String,limitations:Vec<Limitation>}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct ResultData {schema_version:u32,scope:String,head_sequence:u32,prepared_intent:PreparedIntent}
impl ResultData {
    fn valid(&self,c:&Context)->bool {
        let p=&self.prepared_intent;
        let hex=|v:&str,n|v.len()==n&&v.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b));
        let app=p.application_id.len()<=255&&p.application_id.split('.').count()>=2&&p.application_id.split('.').all(|v|
            v.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)&&v.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_'));
        let date=p.observed_at.as_bytes();
        let timestamp=date.len()==20&&date.iter().enumerate().all(|(i,b)|match i{4|7=>*b==b'-',10=>*b==b'T',13|16=>*b==b':',19=>*b==b'Z',_=>b.is_ascii_digit()});
        self.schema_version==1&&self.scope=="local-android-store-prepare"&&(1..=513).contains(&self.head_sequence)
            &&p.operation_id==c.candidate_operation_id&&uuid(&p.operation_id)&&p.candidate_sha256==c.candidate_sha256
            &&sha(&p.intent_sha256)&&sha(&p.store_precondition_sha256)&&hex(&p.source_commit,40)&&hex(&p.source_tree,40)
            &&app&&p.version.name==c.saved_version.name&&p.version.build==c.saved_version.build
            &&p.destination.channel=="internal"&&p.destination.release_status=="completed"&&timestamp&&p.limitations==LIMITATIONS
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
            || self.lifetime.commands > 14 { return false; }
        if self.outcome == Outcome::Complete {
            return self.reason == Reason::None && self.lifetime.settled() && self.lifetime.stop_observed == CoreStop::None
                && self.lifetime.commands==14 && self.lifetime.command_dispatched==Some(true)
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
                if !t.valid(context)||t.outcome==Outcome::Complete&&(self.next!=5||!self.head.as_ref().is_some_and(|h|t.result.as_ref().is_some_and(|r|r.head_sequence==h.sequence))){return Err(BridgeError::protocol());}
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
                    if !head.valid()||self.next==2&&head.sequence>511||self.next>2&&!self.head.as_ref().is_some_and(|p|p.sequence<513&&head.sequence==p.sequence+1){return Err(BridgeError::protocol());}
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
}
