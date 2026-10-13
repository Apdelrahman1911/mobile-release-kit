//! Closed artifact observation DATA. A terminal never proves native original finality.
use std::path::Path;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::{asset_source::RegisteredRoot, edit_protocol::{bounded, token}, error::BridgeError,
    protocol::{strict_json, valid_id}};

pub(crate) const PROTOCOL: &str = "mrk-artifact-inspection/1";
pub(crate) const CONSENT: &str = "selected-artifact-inspection-v1";
pub(crate) const EVENT: &str = "artifact-inspection-state-changed";
pub(crate) const IPC_LIMIT: usize = 8192;
pub(crate) const REQUEST_LIMIT: usize = 32768;
pub(crate) const RESPONSE_LIMIT: usize = 65536;
pub(crate) const STATUS_LIMIT: usize = 65536;
pub(crate) const RESULT_LIMIT: usize = 16384;
fn keys(v:&Value,names:&[&str])->bool { v.as_object().is_some_and(|o|o.len()==names.len()&&names.iter().all(|n|o.contains_key(*n))) }
pub(crate) fn invalid()->BridgeError { BridgeError::new("artifact_inspection_invalid","The artifact inspection request is invalid.") }
pub(crate) fn raw_request(raw:&[u8])->Result<Value,BridgeError> {
    if !(1..=IPC_LIMIT).contains(&raw.len()){return Err(invalid());} strict_json(raw).map_err(|_|invalid())
}
fn sha(v:&str)->bool { v.len()==64&&v.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)) }
pub(crate) fn label(v:&str)->bool { !v.is_empty()&&v.len()<=255&&v!="."&&v!=".."&&!v.chars().any(|c|c.is_control()||matches!(c,'/'|'\\'|':')) }
fn uint(v:&str)->bool { !v.is_empty()&&(v=="0"||!v.starts_with('0'))&&v.bytes().all(|b|b.is_ascii_digit())&&v.parse::<u64>().is_ok() }
fn signed(v:&str)->bool { v.parse::<i64>().is_ok_and(|n|n.to_string()==v) }
fn native_path(p:&Path)->Option<&str> {
    let s=p.to_str()?;if s.len()>4096||!s.starts_with('/')||s.chars().any(|c|c.is_control()||matches!(c,'\\'|':')){return None;}
    if s!="/" {let mut n=0;for part in s[1..].split('/') {n+=1;if n>128||part.is_empty()||part=="."||part==".."||part.len()>255{return None;}}}Some(s)
}
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="lowercase")]
pub(crate) enum Format { Aab, Ipa }
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="lowercase")]
pub(crate) enum Role { Artifact, Archive, Dsyms }
impl Role {pub(crate) fn index(self)->usize {match self {Self::Artifact=>0,Self::Archive=>1,Self::Dsyms=>2}}}
pub(crate) const ROLES:[Role;3]=[Role::Artifact,Role::Archive,Role::Dsyms];
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="lowercase")]
pub(crate) enum Kind { File, Directory }
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Content {pub(crate) bytes:u32,pub(crate) sha256:String}
impl Content {fn valid(&self)->bool {(1..=524288).contains(&self.bytes)&&sha(&self.sha256)}}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selections {pub(crate) artifact:String,pub(crate) archive:Option<String>,pub(crate) dsyms:Option<String>}
impl Selections {
    pub(crate) fn get(&self,role:Role)->Option<&str>{match role{Role::Artifact=>Some(&self.artifact),Role::Archive=>self.archive.as_deref(),Role::Dsyms=>self.dsyms.as_deref()}}
    fn valid(&self,format:Format)->bool {
        token(&self.artifact)&&self.archive.as_ref().is_none_or(|v|token(v)&&v!=&self.artifact)
            &&self.dsyms.as_ref().is_none_or(|v|token(v)&&v!=&self.artifact&&self.archive.as_ref().is_some_and(|a|a!=v))
            &&(format==Format::Ipa||(self.archive.is_none()&&self.dsyms.is_none()))
    }
}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) project_id:String,pub(crate) draft_revision:u32,pub(crate) baseline_generation:u32,
    pub(crate) saved_config:Content,pub(crate) format:Format,pub(crate) selections:Selections,
}
impl Context {
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{
        let mut n=self.project_id.capacity().checked_add(self.saved_config.sha256.capacity())?.checked_add(self.selections.artifact.capacity())?;
        for v in [&self.selections.archive,&self.selections.dsyms].into_iter().flatten(){n=n.checked_add(v.capacity())?;}Some(n)
    }
pub(crate) fn valid(&self)->bool {valid_id(&self.project_id)&&self.draft_revision<u32::MAX&&self.baseline_generation<u32::MAX&&self.saved_config.valid()&&self.selections.valid(self.format)}}
pub(crate) type Prepare=Context;
impl Prepare {pub(crate) fn context(&self)->Context{self.clone()}}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Pick {pub(crate) project_id:String,pub(crate) format:Format,pub(crate) role:Role}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Start {pub(crate) operation_id:String,pub(crate) owner_generation:String,consent_version:String}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Cancel {pub(crate) operation_id:String,pub(crate) owner_generation:String}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Discard {pub(crate) selection_generation:u32,pub(crate) operation_id:Option<String>,pub(crate) owner_generation:Option<String>}
pub(crate) fn pick(v:&Value)->Result<Pick,BridgeError>{if !keys(v,&["projectId","format","role"]){return Err(invalid());}let p=Pick::deserialize(v).map_err(|_|invalid())?;if !valid_id(&p.project_id)||(p.format==Format::Aab&&p.role!=Role::Artifact){return Err(invalid());}Ok(p)}
pub(crate) fn prepare(v:&Value)->Result<Prepare,BridgeError>{
    if !keys(v,&["projectId","draftRevision","baselineGeneration","savedConfig","format","selections"])||!v.get("savedConfig").is_some_and(|s|keys(s,&["bytes","sha256"]))||!v.get("selections").is_some_and(|s|keys(s,&["artifact","archive","dsyms"])) {return Err(invalid());}
    let p=Prepare::deserialize(v).map_err(|_|invalid())?;if !p.valid(){return Err(invalid());}Ok(p)
}
pub(crate) fn start(v:&Value)->Result<Start,BridgeError>{if !keys(v,&["operationId","ownerGeneration","consentVersion"]){return Err(invalid());}let p=Start::deserialize(v).map_err(|_|invalid())?;if !token(&p.operation_id)||!token(&p.owner_generation)||p.consent_version!=CONSENT{return Err(invalid());}Ok(p)}
pub(crate) fn cancel(v:&Value)->Result<Cancel,BridgeError>{if !keys(v,&["operationId","ownerGeneration"]){return Err(invalid());}let p=Cancel::deserialize(v).map_err(|_|invalid())?;if !token(&p.operation_id)||!token(&p.owner_generation){return Err(invalid());}Ok(p)}
pub(crate) fn discard(v:&Value)->Result<Discard,BridgeError>{
    if !keys(v,&["selectionGeneration","operationId","ownerGeneration"]){return Err(invalid());}
    let p=Discard::deserialize(v).map_err(|_|invalid())?;
    if !matches!((&p.operation_id,&p.owner_generation),(None,None))&&!matches!((&p.operation_id,&p.owner_generation),(Some(a),Some(b)) if token(a)&&token(b)){return Err(invalid());}Ok(p)
}
pub(crate) fn status_request(v:&Value)->Result<(),BridgeError>{if keys(v,&[]){Ok(())}else{Err(invalid())}}

#[derive(Clone,Copy,Debug,Serialize,PartialEq,Eq)]
pub(crate) enum Profile {#[serde(rename="macos-arm64")] MacosArm64,#[serde(rename="macos-x86_64")] MacosX64}
impl Profile {pub(crate) fn current()->Option<Self>{if cfg!(all(target_os="macos",target_arch="aarch64",target_pointer_width="64")){Some(Self::MacosArm64)}else if cfg!(all(target_os="macos",target_arch="x86_64",target_pointer_width="64")){Some(Self::MacosX64)}else{None}}}
/// Native-produced comparison only; never a deserializable renderer FD/capability.
#[derive(Clone,Debug,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase")]
pub(crate) struct OriginalIdentity {
    pub(crate) device:String,pub(crate) inode:String,pub(crate) mode:u32,pub(crate) uid:u32,pub(crate) gid:u32,
    pub(crate) nlink:String,pub(crate) bytes:String,pub(crate) mtime_seconds:String,pub(crate) mtime_nanos:u32,
    pub(crate) ctime_seconds:String,pub(crate) ctime_nanos:u32,pub(crate) flags:u32,
}
impl OriginalIdentity {
pub(crate) fn retained_bytes(&self)->Option<usize>{[&self.device,&self.inode,&self.nlink,&self.bytes,&self.mtime_seconds,&self.ctime_seconds].iter().try_fold(0usize,|n,s|n.checked_add(s.capacity()))}
pub(crate) fn valid(&self,kind:Kind)->bool {
    uint(&self.device)&&uint(&self.inode)&&self.inode!="0"&&uint(&self.nlink)&&self.nlink!="0"&&uint(&self.bytes)
        &&signed(&self.mtime_seconds)&&signed(&self.ctime_seconds)&&self.mtime_nanos<1_000_000_000&&self.ctime_nanos<1_000_000_000
        &&match kind{Kind::File=>self.mode&0o170000==0o100000&&self.nlink=="1",Kind::Directory=>self.mode&0o170000==0o040000}
}}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
pub(crate) struct Original<'a> {pub(crate) selection_id:&'a str,pub(crate) role:Role,pub(crate) path:&'a str,pub(crate) kind:Kind,pub(crate) identity:&'a OriginalIdentity}
/// The owner supplies the actual native source/catalog loan; this only encodes DATA.
pub(crate) fn request(operation:&str,generation:&str,context:&Context,profile:Profile,project:&RegisteredRoot,cwd:&Path,
    originals:&[Original<'_>],android:Option<&crate::android_build_protocol::ToolchainBinding>,ios:bool,parent_descriptors:u32)->Result<Vec<u8>,BridgeError>{
    if !token(operation)||!token(generation)||!context.valid()||parent_descriptors>=192||originals.is_empty()||originals.len()>3
        ||(context.format==Format::Aab&&ios)||(context.format==Format::Ipa&&android.is_some()){return Err(invalid());}
    let mut at=0;
    for role in ROLES {if let Some(id)=context.selections.get(role){let original=originals.get(at).ok_or_else(invalid)?;
        if original.role!=role||original.selection_id!=id||native_path(Path::new(original.path)).is_none()||!original.identity.valid(original.kind)
            ||role==Role::Artifact&&original.kind!=Kind::File{return Err(invalid());}at+=1;}}
    if at!=originals.len(){return Err(invalid());}
    if let Some(binding)=android {
        let value=serde_json::to_value(binding).map_err(|_|invalid())?;
        if value.get("schemaVersion").and_then(Value::as_u64)!=Some(2)
            ||!value.get("selection").is_some_and(Value::is_object){return Err(invalid());}
    }
    let root=project.identity.posix().map_err(|_|invalid())?.preflight_identity();
    let v=json!({"protocol":PROTOCOL,"operationId":operation,"ownerGeneration":generation,"context":context,
        "native":{"profile":profile,"projectRoot":native_path(&project.path).ok_or_else(invalid)?,"rootIdentity":root,"cwd":native_path(cwd).ok_or_else(invalid)?,
            "originals":originals,"tools":{"android":android,"ios":ios.then_some("macos-artifact-ios-system-v1")},"parentDescriptorReservation":parent_descriptors}});
    let mut raw=bounded(&v,REQUEST_LIMIT-1).map_err(|_|invalid())?;raw.push(b'\n');Ok(raw)
}

#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
pub(crate) enum Outcome {Complete,Refused,Cancelled,TimedOut,Failed,Unknown}
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
pub(crate) enum Reason {
    None,Cancelled,ContextChanged,DocumentLost,Shutdown,TimedOut,ProtocolError,RuntimeUnavailable,IntentExpired,StaleIntent,
    SavedConfigMissing,SavedConfigInvalid,SavedConfigChanged,SavedConfigSensitive,SavedConfigUnsafe,SavedConfigTooLarge,
    PlatformDisabled,ProjectAdmissionRefused,InputLimit,ResultLimit,CommandIncomplete,CleanupUnknown,
    SavedVersionMissing,SavedVersionInvalid,SavedVersionChanged,SavedVersionUnsafe,SavedVersionTooLarge,
    SelectionMissing,SelectionChanged,SelectionUnsafe,ToolchainUnavailable,ToolchainMismatch,ResourcesUnavailable,
}
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
pub(crate) enum Check {ByteIdentity,Structure,Manifest,ExpectedIdentity,ExpectedVersion,Signature,ProfileEntitlements,CurrentValidity,SignerPolicy,ArchivePair,Symbols}
pub(crate) const CHECKS:[Check;11]=[Check::ByteIdentity,Check::Structure,Check::Manifest,Check::ExpectedIdentity,Check::ExpectedVersion,Check::Signature,Check::ProfileEntitlements,Check::CurrentValidity,Check::SignerPolicy,Check::ArchivePair,Check::Symbols];
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="snake_case")]
pub(crate) enum CheckStatus {Pass,Fail,Unavailable,NotApplicable}
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
pub(crate) enum CheckReason {None,UnsupportedFormat,InputLimit,MalformedStructure,IdentityMismatch,VersionMismatch,ToolsUnavailable,SignatureInvalid,SignerUnobserved,SavedPolicyMissing,SignerMismatch,ProfileInvalid,SigningTimeInvalid,ArchiveNotSelected,PairMismatch,SymbolsNotSelected,SymbolsMismatch,PrerequisiteNotRun}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckResult {pub(crate) check:Check,pub(crate) status:CheckStatus,pub(crate) reason:CheckReason}
impl CheckResult {
    fn valid(&self,format:Format)->bool {
        use Check::*;use CheckReason as R;use CheckStatus as S;
        if format==Format::Aab&&matches!(self.check,ProfileEntitlements|ArchivePair|Symbols){return self.status==S::NotApplicable&&self.reason==R::None;}
        match self.status {
            S::Pass=>self.reason==R::None,
            S::NotApplicable=>false,
            S::Fail=>match self.check {
                ByteIdentity=>false,
                Structure=>matches!(self.reason,R::UnsupportedFormat|R::InputLimit|R::MalformedStructure),
                Manifest=>self.reason==R::MalformedStructure,ExpectedIdentity=>self.reason==R::IdentityMismatch,
                ExpectedVersion=>self.reason==R::VersionMismatch,Signature=>self.reason==R::SignatureInvalid,
                ProfileEntitlements=>self.reason==R::ProfileInvalid,CurrentValidity=>self.reason==R::SigningTimeInvalid,
                SignerPolicy=>self.reason==R::SignerMismatch,ArchivePair=>self.reason==R::PairMismatch,Symbols=>self.reason==R::SymbolsMismatch,
            },
            S::Unavailable=>match self.check {
                ByteIdentity|Structure=>false,
                Manifest|Signature|ProfileEntitlements|CurrentValidity=>matches!(self.reason,R::ToolsUnavailable|R::PrerequisiteNotRun),
                ExpectedIdentity|ExpectedVersion=>self.reason==R::PrerequisiteNotRun,
                SignerPolicy=>matches!(self.reason,R::SavedPolicyMissing|R::SignerUnobserved|R::PrerequisiteNotRun),
                ArchivePair=>matches!(self.reason,R::ArchiveNotSelected|R::PrerequisiteNotRun),
                Symbols=>matches!(self.reason,R::SymbolsNotSelected|R::PrerequisiteNotRun),
            },
        }
    }
}
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
pub(crate) enum Limitation {ByteObservationNotSourceProvenance,CurrentSignatureNotStoreOrReleaseAuthority,SavedInputsNotUnsavedDraft,NoBuildSignUploadOrStoreOperation,ExternalChangesCanMakeResultsStale}
pub(crate) const LIMITATIONS:[Limitation;5]=[Limitation::ByteObservationNotSourceProvenance,Limitation::CurrentSignatureNotStoreOrReleaseAuthority,Limitation::SavedInputsNotUnsavedDraft,Limitation::NoBuildSignUploadOrStoreOperation,Limitation::ExternalChangesCanMakeResultsStale];
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
pub(crate) enum DigestMethod {#[serde(rename="sha256-file")] File,#[serde(rename="sha256-tree-v1")] Tree}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Digest {pub(crate) method:DigestMethod,pub(crate) sha256:String}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Artifact {pub(crate) role:Role,pub(crate) selection_id:String,pub(crate) label:String,pub(crate) kind:Kind,pub(crate) bytes:u64,pub(crate) entries:u32,pub(crate) identity:Digest}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct UsedVersion {pub(crate) bytes:u32,pub(crate) sha256:String,pub(crate) name:String,pub(crate) build:u32}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Observed {
    pub(crate) application_id:Option<String>,pub(crate) bundle_id:Option<String>,pub(crate) version_name:Option<String>,
    pub(crate) version_build:Option<String>,pub(crate) signer_sha256:Option<String>,pub(crate) team_id:Option<String>,
}
fn text(v:&Option<String>,max:usize,ascii:bool)->bool {v.as_ref().is_none_or(|s|!s.is_empty()&&s.len()<=max&&!s.chars().any(char::is_control)&&(!ascii||s.is_ascii()))}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct ResultData {
    pub(crate) schema_version:u32,pub(crate) scope:String,pub(crate) format:Format,pub(crate) used_config:Content,
    pub(crate) used_version:UsedVersion,pub(crate) artifacts:Vec<Artifact>,pub(crate) observed:Observed,
    pub(crate) checks:Vec<CheckResult>,pub(crate) limitations:Vec<Limitation>,
}
impl ResultData {
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{
        let mut n=self.scope.capacity().checked_add(self.used_config.sha256.capacity())?.checked_add(self.used_version.sha256.capacity())?.checked_add(self.used_version.name.capacity())?
            .checked_add(self.artifacts.capacity().checked_mul(std::mem::size_of::<Artifact>())?)?
            .checked_add(self.checks.capacity().checked_mul(std::mem::size_of::<CheckResult>())?)?
            .checked_add(self.limitations.capacity().checked_mul(std::mem::size_of::<Limitation>())?)?;
        for row in &self.artifacts{n=n.checked_add(row.selection_id.capacity())?.checked_add(row.label.capacity())?.checked_add(row.identity.sha256.capacity())?;}
        for v in [&self.observed.application_id,&self.observed.bundle_id,&self.observed.version_name,&self.observed.version_build,&self.observed.signer_sha256,&self.observed.team_id].into_iter().flatten(){n=n.checked_add(v.capacity())?;}
        Some(n)
    }
    fn valid(&self,c:&Context)->bool {
        if self.schema_version!=1||self.scope!="selected-artifact-bytes-only"||self.format!=c.format||self.used_config!=c.saved_config
            ||!self.used_config.valid()||!(1..=65536).contains(&self.used_version.bytes)||!sha(&self.used_version.sha256)
            ||self.used_version.name.is_empty()||self.used_version.name.len()>64||!self.used_version.name.bytes().all(|b|b.is_ascii_alphanumeric()||b".+-".contains(&b))
            ||!(1..=2_100_000_000).contains(&self.used_version.build)||self.limitations.as_slice()!=LIMITATIONS
            ||self.checks.len()!=CHECKS.len()||!self.checks.iter().zip(CHECKS).all(|(r,id)|r.check==id&&r.valid(c.format)){return false;}
        let o=&self.observed;
        if !text(&o.application_id,255,false)||!text(&o.bundle_id,255,false)||!text(&o.version_name,256,false)||!text(&o.version_build,64,true)
            ||!text(&o.team_id,128,true)||o.signer_sha256.as_ref().is_some_and(|s|!sha(s)){return false;}
        if c.format==Format::Aab&&(o.bundle_id.is_some()||o.team_id.is_some()
            ||self.checks[7].status!=CheckStatus::Unavailable||self.checks[7].reason!=CheckReason::PrerequisiteNotRun)
            ||c.format==Format::Ipa&&o.application_id.is_some(){return false;}
        for (present,index,missing) in [(c.selections.archive.is_some(),9,CheckReason::ArchiveNotSelected),(c.selections.dsyms.is_some(),10,CheckReason::SymbolsNotSelected)]{
            let row=&self.checks[index];
            if c.format==Format::Ipa&&((!present&&(row.status!=CheckStatus::Unavailable||row.reason!=missing))||(present&&row.reason==missing)){return false;}
        }
        if self.artifacts.is_empty()||self.artifacts.len()>3{return false;}
        let mut at=0;let mut total=0u64;
        for role in ROLES {if let Some(id)=c.selections.get(role){
            let Some(a)=self.artifacts.get(at)else{return false;};
            if a.role!=role||a.selection_id!=id||!label(&a.label)||!sha(&a.identity.sha256)
                ||role==Role::Artifact&&(a.kind!=Kind::File||a.bytes==0&&self.checks[1].status!=CheckStatus::Fail){return false;}
            match a.kind {
                Kind::File=>if a.entries!=1||a.identity.method!=DigestMethod::File||a.bytes>if c.format==Format::Aab{1<<30}else{4<<30}{return false;},
                Kind::Directory=>if !(1..=8192).contains(&a.entries)||a.identity.method!=DigestMethod::Tree||a.bytes>16<<30{return false;},
            }
            let Some(sum)=total.checked_add(a.bytes)else{return false;};total=sum;at+=1;
        }}
        at==self.artifacts.len()&&total<=16<<30
    }
}
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
enum CoreStop {None,Cancelled,TimedOut}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Lifetime {
    complete:bool,fatal:bool,contained:bool,command_dispatched:Option<bool>,commands:u32,profile_calls:u32,
    input_closed:bool,handlers_restored:bool,invocation_closed:bool,stop_observed:CoreStop,
}
impl Lifetime {pub(crate) fn settled(&self)->bool {self.complete&&!self.fatal&&self.contained&&self.command_dispatched.is_some()
    &&self.commands<=4096&&self.profile_calls<=128&&self.input_closed&&self.handlers_restored&&self.invocation_closed}}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Terminal {schema_version:u32,context:Context,pub(crate) outcome:Outcome,pub(crate) reason:Reason,pub(crate) result:Option<ResultData>,pub(crate) lifetime:Lifetime}
impl Terminal {
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{self.context.retained_heap_bytes()?.checked_add(self.result.as_ref().map_or(Some(0),ResultData::retained_heap_bytes)?) }
    fn valid(&self,c:&Context)->bool {
        if self.schema_version!=1||self.context!=*c||!c.valid()||self.lifetime.commands>4096||self.lifetime.profile_calls>128{return false;}
        if self.outcome==Outcome::Complete{return self.reason==Reason::None&&self.lifetime.settled()&&self.lifetime.stop_observed==CoreStop::None&&self.result.as_ref().is_some_and(|r|r.valid(c));}
        if self.result.is_some()||self.reason==Reason::None{return false;}
        if self.outcome==Outcome::Unknown{return self.reason==Reason::CleanupUnknown&&!self.lifetime.settled();}
        if !self.lifetime.settled(){return false;}
        match self.outcome {
            Outcome::Cancelled=>self.reason==Reason::Cancelled&&self.lifetime.stop_observed==CoreStop::Cancelled,
            Outcome::TimedOut=>self.reason==Reason::TimedOut&&self.lifetime.stop_observed==CoreStop::TimedOut,
            Outcome::Refused|Outcome::Failed=>true,_=>false,
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Accepted {schema_version:u32,context:Context}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Envelope {protocol:String,operation_id:String,owner_generation:String,sequence:u32,kind:String,payload:Value}
pub(crate) enum Frame {Accepted,Terminal(Terminal)}
pub(crate) fn decode(raw:&[u8],operation:&str,generation:&str,context:&Context)->Result<Frame,BridgeError>{
    if raw.len()<3||raw.len()>RESPONSE_LIMIT||!raw.ends_with(b"\n")||raw[0]!=b'{'||raw[raw.len()-2]!=b'}'
        ||raw[..raw.len()-1].iter().any(|b|matches!(*b,b'\r'|b'\n')){return Err(BridgeError::protocol());}
    let value=strict_json(&raw[..raw.len()-1])?;if !keys(&value,&["protocol","operationId","ownerGeneration","sequence","kind","payload"]){return Err(BridgeError::protocol());}let e=Envelope::deserialize(&value).map_err(|_|BridgeError::protocol())?;
    if e.protocol!=PROTOCOL||e.operation_id!=operation||e.owner_generation!=generation||!token(operation)||!token(generation){return Err(BridgeError::protocol());}
    if !e.payload.get("context").is_some_and(|v|prepare(v).is_ok_and(|c|c==*context)){return Err(BridgeError::protocol());}
    match(e.sequence,e.kind.as_str()){
        (0,"accepted")=>{if !keys(&e.payload,&["schemaVersion","context"]){return Err(BridgeError::protocol());}let a=Accepted::deserialize(&e.payload).map_err(|_|BridgeError::protocol())?;if a.schema_version!=1||a.context!=*context||!a.context.valid(){return Err(BridgeError::protocol());}Ok(Frame::Accepted)},
        (1,"terminal")=>{
            if !keys(&e.payload,&["schemaVersion","context","outcome","reason","result","lifetime"])
                ||!e.payload.get("lifetime").is_some_and(|v|keys(v,&["complete","fatal","contained","commandDispatched","commands","profileCalls","inputClosed","handlersRestored","invocationClosed","stopObserved"])){return Err(BridgeError::protocol());}
            if let Some(r)=e.payload.get("result").filter(|r|!r.is_null()){
                bounded(r,RESULT_LIMIT).map_err(|_|BridgeError::protocol())?;
                // Named structs also deserialize positional arrays; validate
                // every fixed object node before serde, not just its values.
                if !keys(r,&["schemaVersion","scope","format","usedConfig","usedVersion","artifacts","observed","checks","limitations"])
                    ||!r.get("usedConfig").is_some_and(|v|keys(v,&["bytes","sha256"]))
                    ||!r.get("usedVersion").is_some_and(|v|keys(v,&["bytes","sha256","name","build"]))
                    ||!r.get("observed").is_some_and(|o|keys(o,&["applicationId","bundleId","versionName","versionBuild","signerSha256","teamId"]))
                    ||!r.get("artifacts").and_then(Value::as_array).is_some_and(|a|a.len()<=3&&a.iter().all(|v|
                        keys(v,&["role","selectionId","label","kind","bytes","entries","identity"])
                            &&v.get("identity").is_some_and(|v|keys(v,&["method","sha256"]))))
                    ||!r.get("checks").and_then(Value::as_array).is_some_and(|a|a.len()==CHECKS.len()
                        &&a.iter().all(|v|keys(v,&["check","status","reason"]))){return Err(BridgeError::protocol());}
            }
            let t=Terminal::deserialize(&e.payload).map_err(|_|BridgeError::protocol())?;if !t.valid(context){return Err(BridgeError::protocol());}Ok(Frame::Terminal(t))
        },
        _=>Err(BridgeError::protocol()),
    }
}
#[derive(Clone,Copy,Debug,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
pub(crate) enum Phase {AwaitingConsent,Starting,Running,Stopping,Terminal,Unknown}
#[derive(Clone,Copy,Debug,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
pub(crate) enum Availability {Available,Busy,Shutdown,CleanupUnknown,DocumentLost,UnsupportedPlatform,RuntimeUnqualified}
#[derive(Clone,Debug,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase")]
pub(crate) struct Projection {
    pub(crate) operation_id:String,pub(crate) owner_generation:String,pub(crate) context:Context,pub(crate) phase:Phase,
    pub(crate) intent_usable:bool,pub(crate) outcome:Option<Outcome>,pub(crate) reason:Reason,pub(crate) result:Option<ResultData>,
}
#[derive(Clone,Copy,Debug,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
pub(crate) enum SelectionPhase {Idle,Picking,Ready,Stopping,Unknown}
#[derive(Clone,Copy,Debug,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
pub(crate) enum SelectionReason {None,Cancelled,ContextChanged,DocumentLost,Shutdown,SourceRefused,SourceChanged,UnsupportedFormat,InputLimit,CleanupUnknown}
#[derive(Clone,Debug,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase")]
pub(crate) struct PickOperation {pub(crate) operation_id:u32,pub(crate) role:Role}
#[derive(Clone,Debug,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase")]
pub(crate) struct Selected {pub(crate) selection_id:String,pub(crate) role:Role,pub(crate) label:String,pub(crate) kind:Kind}
#[derive(Clone,Debug,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase")]
pub(crate) struct Selection {
    pub(crate) generation:u32,pub(crate) project_id:Option<String>,pub(crate) format:Option<Format>,pub(crate) phase:SelectionPhase,
    pub(crate) reason:SelectionReason,pub(crate) operation:Option<PickOperation>,pub(crate) items:Vec<Selected>,
}
#[derive(Clone,Debug,Serialize)]
#[serde(rename_all="camelCase")]
pub(crate) struct Status {pub(crate) schema_version:u32,pub(crate) status_revision:u32,pub(crate) availability:Availability,pub(crate) selection:Selection,pub(crate) operation:Option<Projection>}
pub(crate) fn bounded_status(status:&Status)->Result<Vec<u8>,BridgeError>{
    let value=serde_json::to_value(status).map_err(|_|invalid())?;bounded(&value,STATUS_LIMIT).map_err(|_|invalid())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    fn context_value()->Value {json!({"projectId":"project-1","draftRevision":1,"baselineGeneration":1,
        "savedConfig":{"bytes":2,"sha256":"a".repeat(64)},"format":"ipa",
        "selections":{"artifact":"1".repeat(32),"archive":null,"dsyms":null}})}
    pub(crate) fn context()->Context {prepare(&context_value()).unwrap()}
    pub(crate) fn terminal()->Value {
        let checks:Vec<_>=CHECKS.iter().map(|check|match check{
            Check::ArchivePair=>json!({"check":check,"status":"unavailable","reason":"archive-not-selected"}),
            Check::Symbols=>json!({"check":check,"status":"unavailable","reason":"symbols-not-selected"}),
            _=>json!({"check":check,"status":"pass","reason":"none"})}).collect();
        json!({"protocol":PROTOCOL,"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"sequence":1,"kind":"terminal","payload":{
            "schemaVersion":1,"context":context_value(),"outcome":"complete","reason":"none","result":{
                "schemaVersion":1,"scope":"selected-artifact-bytes-only","format":"ipa","usedConfig":{"bytes":2,"sha256":"a".repeat(64)},
                "usedVersion":{"bytes":10,"sha256":"b".repeat(64),"name":"1.0","build":1},
                "artifacts":[{"role":"artifact","selectionId":"1".repeat(32),"label":"sample.ipa","kind":"file","bytes":100,"entries":1,"identity":{"method":"sha256-file","sha256":"c".repeat(64)}}],
                "observed":{"applicationId":null,"bundleId":null,"versionName":null,"versionBuild":null,"signerSha256":null,"teamId":null},
                "checks":checks,"limitations":LIMITATIONS},
            "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":false,"commands":0,"profileCalls":2,
                "inputClosed":true,"handlersRestored":true,"invocationClosed":true,"stopObserved":"none"}}})
    }
    fn decode_value(v:&Value)->Result<Frame,BridgeError>{let mut raw=serde_json::to_vec(v).unwrap();raw.push(b'\n');decode(&raw,&"a".repeat(32),&"b".repeat(32),&context())}
    #[test]
    fn selected_ids_are_closed_distinct_and_never_paths_or_other_domain_consent(){
        assert!(prepare(&context_value()).is_ok());
        assert!(pick(&json!(["project", "ipa", "artifact"])).is_err());
        assert!(start(&json!(["a".repeat(32),"b".repeat(32),CONSENT])).is_err());
        assert!(cancel(&json!(["a".repeat(32),"b".repeat(32)])).is_err());
        assert!(discard(&json!([0,null,null])).is_err());assert!(status_request(&json!([])).is_err());
        let mut tuple=context_value();let saved=&tuple["savedConfig"];
        tuple["savedConfig"]=json!([saved["bytes"],saved["sha256"]]);assert!(prepare(&tuple).is_err());
        let c=context_value();assert!(prepare(&json!([c["projectId"],c["draftRevision"],c["baselineGeneration"],c["savedConfig"],c["format"],c["selections"]])).is_err());
        let mut tuple=context_value();tuple["selections"]=json!([tuple["selections"]["artifact"],null,null]);assert!(prepare(&tuple).is_err());
        let mut v=context_value();v["selections"].as_object_mut().unwrap().remove("archive");assert!(prepare(&v).is_err());
        let mut v=context_value();v["format"]=json!("aab");v["selections"]["archive"]=json!("2".repeat(32));assert!(prepare(&v).is_err());
        v["format"]=json!("ipa");v["selections"]["archive"]=v["selections"]["artifact"].clone();assert!(prepare(&v).is_err());
        let mut v=context_value();v["path"]=json!("/tmp/example.ipa");assert!(prepare(&v).is_err());
        assert!(raw_request(br#"{"projectId":"p","projectId":"q"}"#).is_err());
        assert!(start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":"saved-offline-android-v1"})).is_err());
        assert!(discard(&json!({"selectionGeneration":0,"operationId":null})).is_err());
        assert!(discard(&json!({"selectionGeneration":0,"operationId":null,"ownerGeneration":null})).is_ok());
        assert!(discard(&json!({"selectionGeneration":0,"operationId":"a".repeat(32),"ownerGeneration":null})).is_err());
    }
    #[test]
    fn originals_have_lossless_full_tuples_without_claiming_payload_or_native_custody(){
        let mut id=OriginalIdentity{device:"1".into(),inode:"2".into(),mode:0o100644,uid:501,gid:20,nlink:"1".into(),bytes:u64::MAX.to_string(),
            mtime_seconds:i64::MIN.to_string(),mtime_nanos:999999999,ctime_seconds:"0".into(),ctime_nanos:0,flags:0};
        assert!(id.valid(Kind::File));assert!(!id.valid(Kind::Directory));
        let mut changed=id.clone();changed.flags=1;assert_ne!(changed,id);
        changed=id.clone();changed.ctime_nanos=1;assert_ne!(changed,id);
        changed=id.clone();changed.bytes="0".into();assert_ne!(changed,id);

        id.nlink="2".into();assert!(!id.valid(Kind::File));id.mode=0o40755;assert!(id.valid(Kind::Directory));
        id.ctime_seconds="-0".into();assert!(!id.valid(Kind::Directory));id.ctime_seconds="0".into();
        id.mtime_nanos=1_000_000_000;assert!(!id.valid(Kind::Directory));
        assert!(!label("../secret"));assert!(!label("bad\nlabel"));assert!(label("sample.ipa"));
        assert!(native_path(Path::new("/tmp/../a.ipa")).is_none());
        assert!(native_path(Path::new("/tmp/a.ipa")).is_some());
    }
    #[test]
    fn actual_profile_counts_and_negative_checks_never_replace_original_finality(){
        let v=terminal();assert!(decode_value(&v).is_ok());
        for key in ["complete","contained","inputClosed","handlersRestored","invocationClosed"]{
            let mut cut=v.clone();cut["payload"]["lifetime"][key]=json!(false);assert!(decode_value(&cut).is_err());
        }
        let mut cut=v.clone();cut["payload"]["lifetime"]["fatal"]=json!(true);assert!(decode_value(&cut).is_err());
        let mut cut=v.clone();cut["payload"]["lifetime"]["profileCalls"]=json!(129);assert!(decode_value(&cut).is_err());
        let mut cut=v.clone();cut["payload"]["lifetime"].as_object_mut().unwrap().remove("commandDispatched");assert!(decode_value(&cut).is_err());
        let mut cut=v.clone();cut["payload"]["context"]["selections"].as_object_mut().unwrap().remove("archive");assert!(decode_value(&cut).is_err());
        let mut cut=v.clone();cut["payload"]["result"]["checks"][1]=json!({"check":"structure","status":"fail","reason":"malformed-structure"});
        assert!(decode_value(&cut).is_ok()); // Completed byte observation is not all-green certification.
        cut["payload"]["result"]["checks"][0]=json!({"check":"byte-identity","status":"unavailable","reason":"prerequisite-not-run"});
        assert!(decode_value(&cut).is_err());
        let mut cut=v.clone();cut["payload"]["outcome"]=json!("unknown");cut["payload"]["reason"]=json!("cleanup-unknown");cut["payload"]["result"]=Value::Null;
        assert!(decode_value(&cut).is_err());cut["payload"]["lifetime"]["complete"]=json!(false);assert!(decode_value(&cut).is_ok());
    }
    #[test]
    fn exact_result_frames_and_status_headroom_do_not_truncate_or_accept_unbounded_strings(){
        // Finite exact serde field orders; array-shaped known values cannot
        // bypass the private protocol's named-object grammar.
        for (path,names) in [
            ("/payload", &["schemaVersion","context","outcome","reason","result","lifetime"][..]),
            ("/payload/context", &["projectId","draftRevision","baselineGeneration","savedConfig","format","selections"][..]),
            ("/payload/context/savedConfig", &["bytes","sha256"][..]),
            ("/payload/context/selections", &["artifact","archive","dsyms"][..]),
            ("/payload/lifetime", &["complete","fatal","contained","commandDispatched","commands","profileCalls","inputClosed","handlersRestored","invocationClosed","stopObserved"][..]),
            ("/payload/result", &["schemaVersion","scope","format","usedConfig","usedVersion","artifacts","observed","checks","limitations"][..]),
            ("/payload/result/usedConfig", &["bytes","sha256"][..]),
            ("/payload/result/usedVersion", &["bytes","sha256","name","build"][..]),
            ("/payload/result/artifacts/0", &["role","selectionId","label","kind","bytes","entries","identity"][..]),
            ("/payload/result/artifacts/0/identity", &["method","sha256"][..]),
            ("/payload/result/observed", &["applicationId","bundleId","versionName","versionBuild","signerSha256","teamId"][..]),
            ("/payload/result/checks/0", &["check","status","reason"][..]),
        ]{
            let mut v=terminal();let object=v.pointer(path).unwrap();
            let array=Value::Array(names.iter().map(|name|object[*name].clone()).collect());
            *v.pointer_mut(path).unwrap()=array;assert!(decode_value(&v).is_err(),"{path}");
        }
        let mut v=terminal();v["payload"]["result"]["observed"]["applicationId"]=json!("foreign.application");assert!(decode_value(&v).is_err());
        let mut v=terminal();v["payload"]["result"]["artifacts"][0]["bytes"]=json!(0);assert!(decode_value(&v).is_err());
        v["payload"]["result"]["checks"][1]["status"]=json!("fail");v["payload"]["result"]["checks"][1]["reason"]=json!("malformed-structure");assert!(decode_value(&v).is_ok());
        for i in [9,10]{let mut v=terminal();v["payload"]["result"]["checks"][i]["status"]=json!("pass");v["payload"]["result"]["checks"][i]["reason"]=json!("none");assert!(decode_value(&v).is_err());}
        let mut c=context();c.format=Format::Aab;
        let mut r:ResultData=serde_json::from_value(terminal()["payload"]["result"].clone()).unwrap();r.format=Format::Aab;
        r.checks[6]=CheckResult{check:Check::ProfileEntitlements,status:CheckStatus::NotApplicable,reason:CheckReason::None};
        r.checks[7]=CheckResult{check:Check::CurrentValidity,status:CheckStatus::Unavailable,reason:CheckReason::PrerequisiteNotRun};
        r.checks[9]=CheckResult{check:Check::ArchivePair,status:CheckStatus::NotApplicable,reason:CheckReason::None};
        r.checks[10]=CheckResult{check:Check::Symbols,status:CheckStatus::NotApplicable,reason:CheckReason::None};
        assert!(r.valid(&c));r.observed.bundle_id=Some("a.b".into());assert!(!r.valid(&c));r.observed.bundle_id=None;
        r.observed.team_id=Some("TEAM".into());assert!(!r.valid(&c));r.observed.team_id=None;
        r.checks[7].reason=CheckReason::ToolsUnavailable;assert!(!r.valid(&c));

        let mut v=terminal();v["payload"]["result"]["artifacts"][0]["label"]=json!("x".repeat(RESULT_LIMIT));assert!(decode_value(&v).is_err());
        let v=terminal();let mut raw=serde_json::to_vec(&v).unwrap();raw.extend_from_slice(b"\n\n");assert!(decode(&raw,&"a".repeat(32),&"b".repeat(32),&context()).is_err());
        let mut status=Status{schema_version:1,status_revision:0,availability:Availability::Available,
            selection:Selection{generation:0,project_id:None,format:None,phase:SelectionPhase::Idle,reason:SelectionReason::None,operation:None,items:vec![]},operation:None};
        assert!(bounded_status(&status).is_ok());status.selection.project_id=Some("x".repeat(STATUS_LIMIT));assert!(bounded_status(&status).is_err());
        let mut v=terminal();v["payload"]["result"]["observed"].as_object_mut().unwrap().remove("teamId");assert!(decode_value(&v).is_err());
        let mut v=terminal();v["payload"]["result"]["usedVersion"]["build"]=json!("1");assert!(decode_value(&v).is_err());
    }
}
