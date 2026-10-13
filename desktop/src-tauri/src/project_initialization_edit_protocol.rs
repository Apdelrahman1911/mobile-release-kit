//! Closed initialization DATA. Only the existing registered edit owner has custody.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use crate::{edit_protocol::{self as edit, bounded, token, Capability, ChildFrame, CoreEditOutcome,
    CoreReason, Effect, Journal, NativeEditReason, NativeFinality, Phase, ResourceState},
    github_workflow_edit_protocol::{self as workflow, RegisteredIdentity, TemplateSet, Tooling, WorkflowId},
    error::BridgeError, protocol::{check_value, strict_json}};

pub const DOMAIN: &str = "project_initialization";
pub const PROTOCOL: &str = "mrk-project-initialization/1";
pub const EVENT: &str = "project-initialization-state-changed";
pub const RESPONSE_LIMIT: usize = 1024 * 1024;
pub const VIEW_LIMIT: usize = 768 * 1024;
pub const INVENTORY_LIMIT: usize = 128 * 1024;
pub const STATUS_LIMIT: usize = edit::STATUS_LIMIT;
const MAX_FILE: u32 = 8 * 1024 * 1024;
const WORKFLOWS: [WorkflowId; 4] = [WorkflowId::Preflight, WorkflowId::Candidate, WorkflowId::ExternalTesting, WorkflowId::ProductionSubmit];
// deserialize_with deliberately has no default: a required nullable key may
// contain null, but omission is not the same wire shape.
fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> { Option::<T>::deserialize(d) }
fn keys(v: &Value, names: &[&str]) -> bool { v.as_object().is_some_and(|o| o.len() == names.len() && names.iter().all(|k| o.contains_key(*k))) }
fn hex(s: &str, n: usize) -> bool { s.len() == n && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
fn digest(b: &[u8]) -> String { format!("{:x}", Sha256::digest(b)) }
fn path(s: &str) -> bool {
    !s.is_empty() && s.len() <= 4096 && !s.contains(['\\', ':']) && !s.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
        && s.split('/').all(|c| !c.is_empty() && c != "." && c != ".." && c.len() <= 255 && !c.ends_with(['.', ' ']))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="snake_case")]
pub enum Intent { Initialize, Recover }
#[derive(Deserialize)]
#[serde(tag="intent", rename_all="snake_case", deny_unknown_fields)]
pub(crate) enum Open {
    Initialize { #[serde(rename="projectId")] project_id:String, draft:Value,
        #[serde(rename="toolingRepository")] tooling_repository:String, #[serde(rename="toolingSha")] tooling_sha:String,
        #[serde(rename="draftRevision")] draft_revision:u32, #[serde(rename="baselineGeneration")] baseline_generation:u32 },
    Recover { #[serde(rename="projectId")] project_id:String },
}
impl Open {
    pub(crate) fn project_id(&self)->&str { match self { Self::Initialize{project_id,..}|Self::Recover{project_id}=>project_id } }
    pub(crate) fn intent(&self)->Intent { match self { Self::Initialize{..}=>Intent::Initialize,Self::Recover{..}=>Intent::Recover } }
    pub(crate) fn counters(&self)->(u32,u32) { match self { Self::Initialize{draft_revision,baseline_generation,..}=>(*draft_revision,*baseline_generation),Self::Recover{..}=>(0,0) } }
    pub(crate) fn valid(&self)->bool {
        crate::protocol::valid_id(self.project_id()) && match self {
            Self::Initialize{draft,tooling_repository,tooling_sha,draft_revision,baseline_generation,..}=>draft.is_object()
                && workflow::value_bounds(draft,28,512*1024).is_ok() && workflow::tooling_coordinate_valid(tooling_repository,tooling_sha)
                && *draft_revision < u32::MAX && *baseline_generation < u32::MAX,
            Self::Recover{..}=>true,
        }
    }
    pub(crate) fn params(self, root:&std::path::Path, identity:RegisteredIdentity)->Value {
        match self {
            Self::Initialize{draft,tooling_repository,tooling_sha,..}=>json!({"root":root,"registeredIdentity":identity,
                "intent":"initialize","draft":draft,"toolingRepository":tooling_repository,"toolingSha":tooling_sha}),
            Self::Recover{..}=>json!({"root":root,"registeredIdentity":identity,"intent":"recover"}),
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Prepare { pub session_id:String,pub revision:String,pub intent:Intent }
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Apply { pub session_id:String,pub plan_token:String,pub intent:Intent }
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Observed { pub schema_version:u32,pub file_count:u32,pub directory_count:u32 }
impl Observed { fn valid(&self)->bool { self.schema_version==1 && (6..=256).contains(&self.file_count) && self.directory_count<=256 } }
#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="snake_case")]
pub enum Kind { Configuration, Gitignore, Workflow, Metadata }
fn role(index:usize,kind:Kind,p:&str)->bool {
    path(p) && match index { 0=>kind==Kind::Configuration && p=="release/mobile-release.json",1=>kind==Kind::Gitignore && p==".gitignore",
        2..=5=>kind==Kind::Workflow && p==WORKFLOWS[index-2].path(),_=>kind==Kind::Metadata }
}
fn observed_limit(kind:Kind)->u32 {if kind==Kind::Workflow {1024*1024} else {limit(kind)}}
fn limit(kind:Kind)->u32 { match kind { Kind::Configuration=>512*1024,Kind::Workflow=>16*1024,Kind::Gitignore=>1024*1024,Kind::Metadata=>MAX_FILE } }
#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="snake_case")]
pub enum Action { Create, Preserve, Append }
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct FileView { pub index:u32,pub kind:Kind,pub path:String,pub action:Action,#[serde(deserialize_with="required_option")]pub before_bytes:Option<u32>,pub after_bytes:u32 }
impl FileView {
    fn valid(&self,index:usize)->bool {
        self.index as usize==index && role(index,self.kind,&self.path) && self.after_bytes<=limit(self.kind)
            && self.before_bytes.is_none_or(|n| n<=observed_limit(self.kind))
            && (!matches!(self.kind,Kind::Configuration|Kind::Workflow) || self.after_bytes>0)
            && match self.action {
                Action::Create=>self.before_bytes.is_none() && (self.kind!=Kind::Metadata || self.after_bytes==0),
                Action::Preserve=>self.before_bytes==Some(self.after_bytes),
                Action::Append=>self.kind==Kind::Gitignore && self.before_bytes.is_some_and(|n| self.after_bytes>n),
            }
    }
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct WorkflowView { pub id:WorkflowId,pub path:String,pub content:String,pub byte_length:u32,pub sha256:String }
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct InitializationView {
    pub schema_version:u32,pub kind:String,pub files:Vec<FileView>,pub directory_count:u32,pub create_directories:Vec<String>,
    pub configuration_preview:Value,pub workflows:Vec<WorkflowView>,pub ignore_additions:Vec<String>,pub template_set:TemplateSet,pub tooling:Tooling,
}
fn inventory_paths<'a>(paths:impl Iterator<Item=&'a str>)->bool {
    let rows:Vec<&str>=paths.collect();
    let set:BTreeSet<&str>=rows.iter().copied().collect();
    if set.len()!=rows.len() || rows.len()>256 {return false;}
    rows.iter().all(|p| p.match_indices('/').all(|(n,_)| !set.contains(&p[..n])))
        && rows.get(6..).is_none_or(|tail| tail.windows(2).all(|p| p[0]<p[1]))
}
impl InitializationView {
    pub(crate) fn valid(&self)->bool {
        if self.schema_version!=1 || self.kind!="project-initialization" || !(6..=256).contains(&self.files.len())
            || self.directory_count>256 || self.create_directories.len()>self.directory_count as usize
            || bounded(self,VIEW_LIMIT).is_err() || bounded(&(&self.files,&self.create_directories),INVENTORY_LIMIT).is_err()
            || !self.files.iter().enumerate().all(|(i,f)|f.valid(i)) || !inventory_paths(self.files.iter().map(|f|f.path.as_str()))
            || !edit::preview(&self.configuration_preview) || !workflow::template_tooling_valid(&self.template_set,&self.tooling)
            || self.workflows.len()!=4 || !edit::ignore_additions_valid(&self.ignore_additions) {return false;}
        let mut parents=BTreeSet::new();
        for f in &self.files {for (i,_) in f.path.match_indices('/') {parents.insert(&f.path[..i]);}}
        if parents.len()!=self.directory_count as usize || self.create_directories.iter().any(|p|!path(p)||!parents.contains(p.as_str()))
            || !self.create_directories.windows(2).all(|p|(p[0].matches('/').count(),&p[0])<(p[1].matches('/').count(),&p[1])) {return false;}
        let ignore=&self.files[1];
        if (ignore.action==Action::Preserve)!=self.ignore_additions.is_empty() {return false;}
        self.workflows.iter().zip(WORKFLOWS).enumerate().all(|(i,(w,id))| w.id==id && w.path==id.path()
            && w.byte_length>0 && w.byte_length<=16*1024 && w.content.len()==w.byte_length as usize
            && hex(&w.sha256,64) && digest(w.content.as_bytes())==w.sha256 && self.files[i+2].after_bytes==w.byte_length)
    }
    pub(crate) fn changes(&self)->bool {self.files.iter().any(|f|f.action!=Action::Preserve)}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="snake_case")]
pub enum RecoveryState { Idle, Recoverable, Conflict }
#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="snake_case")]
pub enum RecoveryReason { None, IncompleteJournal, ForeignJournal, LegacyJournal, InvalidJournal, UnsupportedDescriptor, ResourceChanged, TargetChanged, ControlChanged, NamespaceChanged }
#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="snake_case")]
pub enum RecoveryAction { Rollback, PreparingCleanup, CommittedCleanup, RolledBackCleanup }
#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="snake_case")]
pub enum RecoveryEffect { Preserve, RemoveNew, RestoreOriginal, KeepCommitted }
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Summary { pub byte_length:u32,pub sha256:String,pub mode:u32 }
impl Summary {fn valid(&self,kind:Kind,before:bool)->bool {self.byte_length<=(if before {observed_limit(kind)}else{limit(kind)})&&hex(&self.sha256,64)&&self.mode<=0o777}}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct RecoveryFile {pub index:u32,pub kind:Kind,pub path:String,pub effect:RecoveryEffect,#[serde(deserialize_with="required_option")]pub before:Option<Summary>,#[serde(deserialize_with="required_option")]pub after:Option<Summary>}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct ConfigurationBinding {pub byte_length:u32,pub sha256:String}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Context {pub configuration:ConfigurationBinding,pub template_set:TemplateSet,pub tooling:Tooling}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct PrivateCleanup {pub file_count:u32,pub directory_count:u32,pub scope:String}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct RecoveryView {pub schema_version:u32,pub kind:String,pub state:RecoveryState,pub reason:RecoveryReason,
    #[serde(deserialize_with="required_option")]pub action:Option<RecoveryAction>,#[serde(deserialize_with="required_option")]pub transaction_id:Option<String>,#[serde(deserialize_with="required_option")]pub context:Option<Context>,pub files:Vec<RecoveryFile>,pub private_cleanup:PrivateCleanup}
impl RecoveryView {
    pub(crate) fn valid(&self)->bool {
        let cleanup=&self.private_cleanup;
        if self.schema_version!=1||self.kind!="project-initialization-recovery"||bounded(self,VIEW_LIMIT).is_err()
            ||bounded(&self.files,INVENTORY_LIMIT).is_err()||cleanup.scope!="inspected-owned-journal-only"
            ||cleanup.file_count>1024||cleanup.directory_count>257 {return false;}
        if self.state!=RecoveryState::Recoverable {return self.action.is_none()&&self.transaction_id.is_none()&&self.context.is_none()
            &&self.files.is_empty()&&cleanup.file_count==0&&cleanup.directory_count==0
            &&(self.reason==RecoveryReason::None)==(self.state==RecoveryState::Idle);}
        let Some(context)=&self.context else{return false;};
        if self.reason!=RecoveryReason::None||self.action.is_none()||!self.transaction_id.as_deref().is_some_and(token)
            ||context.configuration.byte_length==0||context.configuration.byte_length>512*1024||!hex(&context.configuration.sha256,64)
            ||!workflow::template_tooling_valid(&context.template_set,&context.tooling) {return false;}
        if self.files.is_empty() {return matches!(self.action,Some(RecoveryAction::CommittedCleanup|RecoveryAction::RolledBackCleanup))
            &&cleanup.file_count==2&&cleanup.directory_count==1;}
        if !(6..=256).contains(&self.files.len())||!inventory_paths(self.files.iter().map(|f|f.path.as_str())) {return false;}
        self.files.iter().enumerate().all(|(i,f)|{
            if f.index as usize!=i||!role(i,f.kind,&f.path)||f.before.as_ref().is_some_and(|s|!s.valid(f.kind,true))
                ||f.after.as_ref().is_some_and(|s|!s.valid(f.kind,false)||(f.kind==Kind::Metadata&&s.byte_length!=0)
                    ||(matches!(f.kind,Kind::Configuration|Kind::Workflow)&&s.byte_length==0)) {return false;}
            if f.before.is_some()&&f.after.is_some()&&f.kind!=Kind::Gitignore{return false;}
            if let Some(after)=&f.after {if f.before.as_ref().map_or(after.mode!=0o644,|old|old.mode!=after.mode) {return false;}}
            let expected=match (&f.after,self.action) {
                (None,_)=>RecoveryEffect::Preserve,
                (Some(_),Some(RecoveryAction::Rollback)) if f.before.is_none()=>RecoveryEffect::RemoveNew,
                (Some(_),Some(RecoveryAction::Rollback))=>RecoveryEffect::RestoreOriginal,
                (Some(_),Some(RecoveryAction::CommittedCleanup))=>RecoveryEffect::KeepCommitted,
                _=>RecoveryEffect::Preserve,
            };
            f.effect==expected&&(f.effect!=RecoveryEffect::RestoreOriginal||f.kind==Kind::Gitignore)
        })
    }
    pub(crate) fn same(&self,other:&Self)->bool {bounded(self,VIEW_LIMIT).ok().zip(bounded(other,VIEW_LIMIT).ok()).is_some_and(|(a,b)|a==b)}
    pub(crate) fn expected_success(&self)->Option<Effect> {if !self.valid()||self.state!=RecoveryState::Recoverable {return None;}
        Some(match self.action? {RecoveryAction::Rollback=>Effect::RolledBack,RecoveryAction::CommittedCleanup=>Effect::Committed,
            RecoveryAction::RolledBackCleanup=>Effect::RolledBack,RecoveryAction::PreparingCleanup=>Effect::NotStarted})}
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct ConflictFile {pub kind:Kind,pub path:String,pub before_bytes:u32}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct ConflictView {pub schema_version:u32,pub reason:String,pub files:Vec<ConflictFile>}
impl ConflictView {fn valid(&self)->bool {let mut previous=None;self.schema_version==1&&self.reason=="existing_targets_differ"
    &&(1..=5).contains(&self.files.len())&&self.files.iter().all(|f|{
        let index=if f.kind==Kind::Configuration&&f.path=="release/mobile-release.json"{Some(0)}else{WORKFLOWS.iter().position(|id|f.kind==Kind::Workflow&&f.path==id.path()).map(|i|i+2)};
        let Some(index)=index else{return false;};let ordered=previous.is_none_or(|p|p<index);previous=Some(index);ordered&&f.before_bytes<=observed_limit(f.kind)
    })}}
#[derive(Clone,Serialize)]
#[serde(tag="intent",rename_all="snake_case")]
pub enum Checkout {
    Initialize {revision:String,#[serde(rename="draftRevision")] draft_revision:u32,#[serde(rename="baselineGeneration")] baseline_generation:u32,observed:Observed},
    Recover {revision:String,recovery:RecoveryView},
}
impl Checkout {pub(crate) fn revision(&self)->&str {match self {Self::Initialize{revision,..}|Self::Recover{revision,..}=>revision}}}
#[derive(Clone,Serialize)]
#[serde(tag="intent",rename_all="snake_case")]
pub enum Prepared {
    Initialize {revision:String,#[serde(rename="planToken")] plan_token:String,#[serde(rename="draftRevision")] draft_revision:u32,#[serde(rename="baselineGeneration")] baseline_generation:u32,view:InitializationView},
    Recover {revision:String,#[serde(rename="planToken")] plan_token:String,recovery:RecoveryView},
}
impl Prepared {pub(crate) fn plan_token(&self)->&str {match self {Self::Initialize{plan_token,..}|Self::Recover{plan_token,..}=>plan_token}}}
#[derive(Clone)]
pub(crate) struct Details {pub intent:Intent,pub counters:(u32,u32),pub checkout:Option<Checkout>,pub prepared:Option<Prepared>,pub conflict:Option<ConflictView>}
impl Details {
    pub(crate) fn new(intent:Intent,counters:(u32,u32))->Self {Self{intent,counters,checkout:None,prepared:None,conflict:None}}
    pub(crate) fn revision(&self)->Option<&str>{self.checkout.as_ref().map(Checkout::revision)}
    pub(crate) fn plan_token(&self)->Option<&str>{self.prepared.as_ref().map(Prepared::plan_token)}
    pub(crate) fn can_prepare(&self)->bool {match (&self.intent,&self.checkout) {(Intent::Initialize,Some(Checkout::Initialize{..}))=>true,
        (Intent::Recover,Some(Checkout::Recover{recovery,..}))=>recovery.state==RecoveryState::Recoverable,_=>false}}
    pub(crate) fn accept_opened(&mut self,opened:Opened)->bool {if self.checkout.is_some()||opened.intent()!=self.intent||!opened.valid(){return false;}
        self.checkout=Some(match opened {Opened::Initialize{revision,observed,..}=>Checkout::Initialize{revision,observed,draft_revision:self.counters.0,baseline_generation:self.counters.1},
            Opened::Recover{revision,recovery,..}=>Checkout::Recover{revision,recovery}});true}
    pub(crate) fn accept_prepared(&mut self,reply:PreparedReply)->bool {
        if self.prepared.is_some()||reply.intent()!=self.intent||!reply.valid()||self.revision()!=Some(reply.revision())||!self.can_prepare(){return false;}
        self.prepared=Some(match reply {
            PreparedReply::Initialize{revision,plan_token,view,..}=>{
                if !matches!(&self.checkout,Some(Checkout::Initialize{observed,..}) if observed.file_count as usize==view.files.len()&&observed.directory_count==view.directory_count){return false;}
                Prepared::Initialize{revision,plan_token,view,draft_revision:self.counters.0,baseline_generation:self.counters.1}},
            PreparedReply::Recover{revision,plan_token,recovery,..}=>{
                if !matches!(&self.checkout,Some(Checkout::Recover{recovery:old,..}) if old.same(&recovery)){return false;}
                Prepared::Recover{revision,plan_token,recovery}},
        });true
    }
    pub(crate) fn valid(&self)->bool {
        if self.counters.0==u32::MAX || self.counters.1==u32::MAX || self.intent==Intent::Recover && self.counters!=(0,0) {return false;}
        if let Some(checkout)=&self.checkout {match checkout {
            Checkout::Initialize{revision,draft_revision,baseline_generation,observed} =>
                if self.intent!=Intent::Initialize||!token(revision)||(*draft_revision,*baseline_generation)!=self.counters||!observed.valid(){return false;},
            Checkout::Recover{revision,recovery}=>if self.intent!=Intent::Recover||!token(revision)||!recovery.valid(){return false;},
        }}
        if let Some(prepared)=&self.prepared {
            if !token(prepared.plan_token())||Some(prepared.plan_token())==self.revision(){return false;}
            match (prepared,&self.checkout) {
                (Prepared::Initialize{revision,draft_revision,baseline_generation,view,..},Some(Checkout::Initialize{revision:old,observed,..}))=>
                    if revision!=old||(*draft_revision,*baseline_generation)!=self.counters||!view.valid()
                        ||view.files.len()!=observed.file_count as usize||view.directory_count!=observed.directory_count{return false;},
                (Prepared::Recover{revision,recovery,..},Some(Checkout::Recover{revision:old,recovery:observed}))=>
                    if revision!=old||recovery.state!=RecoveryState::Recoverable||!recovery.valid()||!observed.same(recovery){return false;},
                _=>return false,
            }
        }
        self.conflict.as_ref().is_none_or(|v| self.intent==Intent::Initialize&&self.checkout.is_some()&&self.prepared.is_none()&&v.valid())
    }
    pub(crate) fn terminal_admissible(&self,applied:bool,core:&CoreEditOutcome)->bool {
        if !self.valid()||!core.valid()||applied&&self.prepared.is_none(){return false;}
        if self.intent==Intent::Recover {
            if core.effect==Effect::Unchanged||!applied&&core.journal==Journal::Clean{return false;}
            if let Some(Checkout::Recover{recovery:view,..})=&self.checkout {
                let valid=match view.action {
                    Some(RecoveryAction::CommittedCleanup)=>core.effect==Effect::Committed,
                    Some(RecoveryAction::RolledBackCleanup)=>core.effect==Effect::RolledBack,
                    Some(RecoveryAction::PreparingCleanup)=>core.effect==Effect::NotStarted,
                    Some(RecoveryAction::Rollback)=>core.effect==Effect::NotStarted||applied&&matches!(core.effect,Effect::RolledBack|Effect::Unknown),
                    None=>core.effect==Effect::NotStarted,
                };
                if !valid||view.state==RecoveryState::Recoverable&&core.journal==Journal::NotCreated{return false;}
            } else if !matches!(core.effect,Effect::NotStarted|Effect::Unknown)||!matches!(core.journal,Journal::NotCreated|Journal::Unknown){return false;}
            if applied&&core.reason==CoreReason::None {
                return matches!(&self.prepared,Some(Prepared::Recover{recovery,..}) if recovery.expected_success()==Some(core.effect.clone()))
                    &&core.journal==Journal::Clean&&core.resources==ResourceState::Settled;
            }
            return true;
        }
        if !applied{return matches!(core.effect,Effect::NotStarted|Effect::Unknown)&&matches!(core.journal,Journal::NotCreated|Journal::Unknown);}
        let Some(Prepared::Initialize{view,..})=&self.prepared else{return false;};
        if matches!(core.effect,Effect::Unchanged|Effect::Committed|Effect::RolledBack)
            &&(core.effect==Effect::Unchanged)==view.changes(){return false;}
        if core.reason==CoreReason::None {return core.effect==(if view.changes(){Effect::Committed}else{Effect::Unchanged})
            &&core.resources==ResourceState::Settled&&core.journal==(if core.effect==Effect::Unchanged{Journal::NotCreated}else{Journal::Clean});}
        true
    }

}
#[derive(Clone,Serialize)]
#[serde(rename_all="camelCase")]
pub struct Projection {pub domain:&'static str,pub intent:Intent,pub project_id:String,pub session_id:String,pub owner_generation:String,
    pub phase:Phase,pub review_remaining_ms:u32,pub checkout:Option<Checkout>,pub prepared:Option<Prepared>,pub conflict:Option<ConflictView>,
    pub apply_submitted:bool,pub core_outcome:Option<CoreEditOutcome>,pub native_reason:NativeEditReason,pub native_finality:NativeFinality,pub late_settled:bool}
#[derive(Clone,Serialize)]
#[serde(rename_all="camelCase")]
pub struct InitializationStatus {pub schema_version:u32,pub domain:&'static str,pub window_generation:String,pub status_revision:u32,
    pub capability:Capability,pub active:Option<Projection>,pub last_terminal:Option<Projection>}
#[derive(Deserialize)]
#[serde(tag="intent",rename_all="snake_case",deny_unknown_fields)]
pub enum Opened {
    Initialize {revision:String,observed:Observed,#[serde(rename="scopeResources")] scope_resources:ResourceState},
    Recover {revision:String,recovery:RecoveryView,#[serde(rename="scopeResources")] scope_resources:ResourceState},
}
impl Opened {
    fn intent(&self)->Intent{match self{Self::Initialize{..}=>Intent::Initialize,Self::Recover{..}=>Intent::Recover}}
    fn valid(&self)->bool{match self{Self::Initialize{revision,observed,scope_resources}=>token(revision)&&observed.valid()&&*scope_resources==ResourceState::Settled,
        Self::Recover{revision,recovery,scope_resources}=>token(revision)&&recovery.valid()&&*scope_resources==ResourceState::Settled}}
}
#[derive(Deserialize)]
#[serde(tag="intent",rename_all="snake_case",deny_unknown_fields)]
pub enum PreparedReply {
    Initialize {revision:String,#[serde(rename="planToken")]plan_token:String,view:InitializationView,#[serde(rename="scopeResources")]scope_resources:ResourceState},
    Recover {revision:String,#[serde(rename="planToken")]plan_token:String,recovery:RecoveryView,#[serde(rename="scopeResources")]scope_resources:ResourceState},
}
impl PreparedReply {
    fn intent(&self)->Intent{match self{Self::Initialize{..}=>Intent::Initialize,Self::Recover{..}=>Intent::Recover}}
    pub(crate) fn revision(&self)->&str{match self{Self::Initialize{revision,..}|Self::Recover{revision,..}=>revision}}
    fn valid(&self)->bool{match self{
        Self::Initialize{revision,plan_token,view,scope_resources}=>token(revision)&&token(plan_token)&&revision!=plan_token&&view.valid()&&*scope_resources==ResourceState::Settled,
        Self::Recover{revision,plan_token,recovery,scope_resources}=>token(revision)&&token(plan_token)&&revision!=plan_token&&recovery.valid()
            &&recovery.state==RecoveryState::Recoverable&&*scope_resources==ResourceState::Settled}}
}
#[derive(Deserialize)]
#[serde(tag="kind",rename_all="lowercase",deny_unknown_fields)]
pub enum TerminalReply {
    Outcome {intent:Intent,#[serde(rename="planToken",deserialize_with="required_option")]plan_token:Option<String>,effect:Effect,journal:Journal,resources:ResourceState,reason:CoreReason},
    Conflict {intent:Intent,revision:String,conflict:ConflictView,effect:Effect,journal:Journal,resources:ResourceState,reason:CoreReason},
}
impl TerminalReply {
    pub(crate) fn intent(&self)->Intent{match self{Self::Outcome{intent,..}|Self::Conflict{intent,..}=>*intent}}
    pub(crate) fn plan_token(&self)->Option<&str>{match self{Self::Outcome{plan_token,..}=>plan_token.as_deref(),Self::Conflict{..}=>None}}
    pub(crate) fn outcome(&self)->CoreEditOutcome{let (effect,journal,resources,reason)=match self{Self::Outcome{effect,journal,resources,reason,..}|Self::Conflict{effect,journal,resources,reason,..}=>(effect,journal,resources,reason)};
        CoreEditOutcome{effect:effect.clone(),journal:journal.clone(),resources:resources.clone(),reason:reason.clone()}}
    fn valid(&self)->bool{self.outcome().valid()&&match self{
        Self::Outcome{plan_token,..}=>plan_token.as_deref().is_none_or(token),
        Self::Conflict{intent,revision,conflict,effect,journal,resources,reason}=>*intent==Intent::Initialize&&token(revision)&&conflict.valid()
            &&*effect==Effect::NotStarted&&*journal==Journal::NotCreated&&*resources==ResourceState::Settled&&*reason==CoreReason::None}}
}
pub(crate) fn request(session:&str,seq:u32,op:&str,params:Value)->Result<Vec<u8>,BridgeError>{
    if !token(session){return Err(BridgeError::invalid());}
    let intent=serde_json::from_value::<Intent>(params.get("intent").cloned().unwrap_or(Value::Null)).ok();
    let valid=match(seq,op){
        (0,"open")=>{
            let root=params.get("root").and_then(Value::as_str).is_some_and(|s|!s.is_empty()&&s.len()<=4096);
            let identity=params.get("registeredIdentity").is_some_and(|v|RegisteredIdentity::deserialize(v).is_ok_and(|v|v.valid()));
            root&&identity&&match intent{
                Some(Intent::Recover)=>keys(&params,&["root","registeredIdentity","intent"]),
                Some(Intent::Initialize)=>keys(&params,&["root","registeredIdentity","intent","draft","toolingRepository","toolingSha"])
                    &&params["draft"].is_object()&&workflow::value_bounds(&params["draft"],28,512*1024).is_ok()
                    &&params["toolingRepository"].as_str().zip(params["toolingSha"].as_str()).is_some_and(|(r,s)|workflow::tooling_coordinate_valid(r,s)),None=>false}},
        (1,"prepare")=>keys(&params,&["revision","intent"])&&intent.is_some()&&params["revision"].as_str().is_some_and(token),
        (2,"apply")=>keys(&params,&["planToken","intent"])&&intent.is_some()&&params["planToken"].as_str().is_some_and(token),
        (1|2,"discard")=>keys(&params,&[]),_=>false,
    };
    if !valid{return Err(BridgeError::invalid());}
    let value=json!({"protocol":PROTOCOL,"session":session,"seq":seq,"op":op,"params":params});check_value(&value)?;
    let mut bytes=bounded(&value,edit::REQUEST_LIMIT-1)?;bytes.push(b'\n');Ok(bytes)
}
pub(crate) fn decode(bytes:&[u8],session:&str)->Result<ChildFrame,BridgeError>{
    if bytes.len()>RESPONSE_LIMIT||!bytes.ends_with(b"\n"){return Err(BridgeError::protocol());}
    let body=&bytes[..bytes.len()-1];
    if body.first()!=Some(&b'{')||body.last()!=Some(&b'}')||body.iter().any(|b|matches!(*b,b'\r'|b'\n')){return Err(BridgeError::protocol());}
    let v=strict_json(body)?;
    if !keys(&v,&["protocol","session","seq","kind","result"])||v["protocol"]!=PROTOCOL||v["session"]!=session{return Err(BridgeError::protocol());}
    let raw=&v["result"];check_value(raw).map_err(|_|BridgeError::protocol())?; // Same global20k/32; typed256-row inventory is not the workflow draft8k.
    match(v["seq"].as_u64(),v["kind"].as_str()){
        (Some(0),Some("opened"))=>{let x=Opened::deserialize(raw).map_err(|_|BridgeError::protocol())?;if !x.valid(){return Err(BridgeError::protocol());}Ok(ChildFrame::InitializationOpened(x))},
        (Some(1),Some("prepared"))=>{let x=PreparedReply::deserialize(raw).map_err(|_|BridgeError::protocol())?;if !x.valid(){return Err(BridgeError::protocol());}Ok(ChildFrame::InitializationPrepared(x))},
        (Some(n @ 0..=2),Some("terminal"))=>{bounded(raw,edit::TERMINAL_LIMIT).map_err(|_|BridgeError::protocol())?;let x=TerminalReply::deserialize(raw).map_err(|_|BridgeError::protocol())?;
            if !x.valid(){return Err(BridgeError::protocol());}Ok(ChildFrame::InitializationTerminal(n as u32,x))},_=>Err(BridgeError::protocol())}
}


#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) const REVISION:&str="11111111111111111111111111111111";
    pub(crate) const PLAN:&str="22222222222222222222222222222222";
    const SESSION:&str="33333333333333333333333333333333";
    fn envelope(seq:u32,kind:&str,result:Value)->Vec<u8>{let mut b=serde_json::to_vec(&json!({"protocol":PROTOCOL,"session":SESSION,"seq":seq,"kind":kind,"result":result})).unwrap();b.push(b'\n');b}
    fn preview()->Value {
        let a=json!({"basis":"schema-policy","projectCodeExecuted":false,"toolsProbed":false,"credentialsRead":false,
            "gitObserved":false,"storeContacted":false,"writesPerformed":false,"releaseReadiness":"unknown"});
        json!({"schemaVersion":1,"validation":{"valid":true,"state":"format-valid","issues":[],"requirements":[],"assurance":a.clone()},
            "comparison":{"baseProvided":false,"kind":"proposed-create","state":"complete","semanticallyChanged":true,
                "counts":{"added":0,"changed":0,"removed":0},"changes":[],"unreviewedCount":0},"fields":[],"assurance":a})
    }
    pub(crate) fn view()->InitializationView {
        let mut files=vec![FileView{index:0,kind:Kind::Configuration,path:"release/mobile-release.json".into(),action:Action::Create,before_bytes:None,after_bytes:2},
            FileView{index:1,kind:Kind::Gitignore,path:".gitignore".into(),action:Action::Create,before_bytes:None,after_bytes:18}];
        let workflows=WORKFLOWS.iter().enumerate().map(|(i,id)|{
            files.push(FileView{index:(i+2)as u32,kind:Kind::Workflow,path:id.path().into(),action:Action::Create,before_bytes:None,after_bytes:2});
            WorkflowView{id:*id,path:id.path().into(),content:"x\n".into(),byte_length:2,sha256:digest(b"x\n")}
        }).collect();
        InitializationView{schema_version:1,kind:"project-initialization".into(),files,directory_count:3,
            create_directories:vec![".github".into(),"release".into(),".github/workflows".into()],configuration_preview:preview(),workflows,
            ignore_additions:vec![".mobile-release/".into()],template_set:TemplateSet{core_version:"0.3.0".into(),resource_version:1,resource_sha256:"a".repeat(64)},
            tooling:Tooling{repository:"example/toolkit".into(),sha:"b".repeat(40),schema_reference:format!("https://raw.githubusercontent.com/example/toolkit/{}/schemas/project.schema.json","b".repeat(40)),state:"format-only".into()}}
    }
    pub(crate) fn recovery(action:RecoveryAction)->RecoveryView {
        let v=view();
        let effect=if action==RecoveryAction::Rollback{RecoveryEffect::RemoveNew}else if action==RecoveryAction::CommittedCleanup{RecoveryEffect::KeepCommitted}else{RecoveryEffect::Preserve};
        RecoveryView{schema_version:1,kind:"project-initialization-recovery".into(),state:RecoveryState::Recoverable,reason:RecoveryReason::None,
            action:Some(action),transaction_id:Some("c".repeat(32)),context:Some(Context{configuration:ConfigurationBinding{byte_length:2,sha256:digest(b"{}")},template_set:v.template_set,tooling:v.tooling}),
            files:v.files.into_iter().map(|f|RecoveryFile{index:f.index,kind:f.kind,path:f.path,effect,before:None,
                after:Some(Summary{byte_length:f.after_bytes,sha256:"d".repeat(64),mode:0o644})}).collect(),
            private_cleanup:PrivateCleanup{file_count:14,directory_count:4,scope:"inspected-owned-journal-only".into()}}
    }
    pub(crate) fn detail(action:RecoveryAction)->Details {
        let v=recovery(action); let mut d=Details::new(Intent::Recover,(0,0));
        assert!(d.accept_opened(Opened::Recover{revision:REVISION.into(),recovery:v.clone(),scope_resources:ResourceState::Settled}));
        assert!(d.accept_prepared(PreparedReply::Recover{revision:REVISION.into(),plan_token:PLAN.into(),recovery:v,scope_resources:ResourceState::Settled}));d
    }
    #[test]
    fn fixed_open_and_response_shapes_never_borrow_other_edit_intents() {
        let original=json!({"projectId":"project-1","intent":"initialize","draft":{},"toolingRepository":"example/toolkit","toolingSha":"b".repeat(40),"draftRevision":7,"baselineGeneration":3});
        assert!(crate::edit_commands::initialization_open(&original).is_ok());
        for key in ["projectId","intent","draft","toolingRepository","toolingSha","draftRevision","baselineGeneration"] {
            let mut bad=original.clone();bad.as_object_mut().unwrap().remove(key);assert!(crate::edit_commands::initialization_open(&bad).is_err());
        }
        let mut extra=original.clone();extra["root"]=json!("/untrusted");assert!(crate::edit_commands::initialization_open(&extra).is_err());
        assert!(crate::edit_commands::initialization_open(&json!({"projectId":"project-1","intent":"recover"})).is_ok());
        let identity=json!({"device":"1","inode":"2","mode":0o40755,"uid":501,"gid":20});
        assert!(request(SESSION,0,"open",json!({"root":"/inert","registeredIdentity":identity,"intent":"initialize","draft":{},"toolingRepository":"example/toolkit","toolingSha":"b".repeat(40)})).is_ok());
        assert!(request(SESSION,1,"prepare",json!({"revision":REVISION,"intent":"initialize"})).is_ok());
        assert!(request(SESSION,1,"prepare",json!({"revision":REVISION,"intent":"initialize","draft":{}})).is_err());
        assert!(request(SESSION,2,"apply",json!({"planToken":PLAN,"intent":"recover"})).is_ok());
        assert!(request(SESSION,2,"apply",json!({"planToken":PLAN})).is_err());
        let raw=envelope(0,"opened",json!({"intent":"initialize","revision":REVISION,"observed":{"schemaVersion":1,"fileCount":6,"directoryCount":3},"scopeResources":"settled"}));
        assert!(matches!(decode(&raw,SESSION),Ok(ChildFrame::InitializationOpened(_))));
        assert!(decode(&raw,REVISION).is_err());assert!(workflow::decode(&raw,SESSION).is_err());assert!(edit::decode(&raw,SESSION).is_err());
        let duplicate=String::from_utf8(raw.clone()).unwrap().replacen("\"intent\":\"initialize\"","\"intent\":\"initialize\",\"intent\":\"initialize\"",1);
        assert!(decode(duplicate.as_bytes(),SESSION).is_err());
        let conflict=json!({"kind":"conflict","intent":"initialize","revision":REVISION,"conflict":{"schemaVersion":1,"reason":"existing_targets_differ",
            "files":[{"kind":"workflow","path":WORKFLOWS[0].path(),"beforeBytes":1024*1024}]},"effect":"not_started","journal":"not_created","resources":"settled","reason":"none"});
        assert!(decode(&envelope(1,"terminal",conflict.clone()),SESSION).is_ok());
        let mut excessive=conflict;excessive["conflict"]["files"][0]["beforeBytes"]=json!(1024*1024+1);assert!(decode(&envelope(1,"terminal",excessive),SESSION).is_err());
        let outcome=json!({"kind":"outcome","intent":"initialize","planToken":null,"effect":"not_started","journal":"not_created","resources":"settled","reason":"none"});
        assert!(decode(&envelope(0,"terminal",outcome.clone()),SESSION).is_ok());
        let mut missing=outcome;missing.as_object_mut().unwrap().remove("planToken");assert!(decode(&envelope(0,"terminal",missing),SESSION).is_err());
    }
    #[test]
    fn complete_inventory_and_redacted_review_remain_closed_and_bounded() {
        let v=view();assert!(v.valid());
        let mut d=Details::new(Intent::Initialize,(7,3));assert!(d.accept_opened(Opened::Initialize{revision:REVISION.into(),observed:Observed{schema_version:1,file_count:6,directory_count:3},scope_resources:ResourceState::Settled}));
        let reply=||PreparedReply::Initialize{revision:REVISION.into(),plan_token:PLAN.into(),view:v.clone(),scope_resources:ResourceState::Settled};
        assert!(d.accept_prepared(reply()));assert!(!d.accept_prepared(reply()));assert!(d.valid());
        for change in 0..13 {let mut bad=v.clone();match change {
            0=>bad.files[0].action=Action::Append,1=>bad.files[0].before_bytes=Some(2),2=>bad.files[0].path="../escape".into(),
            3=>bad.workflows[0].content="different".into(),4=>bad.workflows[0].sha256="f".repeat(64),5=>bad.files[2].after_bytes=3,
            6=>bad.directory_count=4,7=>bad.create_directories.reverse(),8=>bad.ignore_additions.push(bad.ignore_additions[0].clone()),
            9=>bad.tooling.state="verified".into(),10=>bad.configuration_preview["assurance"]["writesPerformed"]=json!(true),
            11=>bad.files[0].after_bytes=512*1024+1,_=>bad.files[3].path=bad.files[2].path.clone(),};assert!(!bad.valid(),"{change}");}
        let mut full=v.clone();for i in 6..256{full.files.push(FileView{index:i,kind:Kind::Metadata,path:format!("metadata/{i:03}.txt"),action:Action::Create,before_bytes:None,after_bytes:0});}
        full.directory_count=4;full.create_directories=vec![".github".into(),"metadata".into(),"release".into(),".github/workflows".into()];assert!(full.valid());
        let full_reply=envelope(1,"prepared",json!({"intent":"initialize","revision":REVISION,"planToken":PLAN,"view":full,"scopeResources":"settled"}));
        assert!(matches!(decode(&full_reply,SESSION),Ok(ChildFrame::InitializationPrepared(_))));
        let mut wrong=serde_json::to_value(v).unwrap();wrong["files"][0].as_object_mut().unwrap().remove("beforeBytes");
        assert!(InitializationView::deserialize(&wrong).is_err());
    }
    #[test]
    fn recovery_keeps_historical_effects_but_never_mints_clean_before_apply() {
        for (action,effect,pending) in [(RecoveryAction::Rollback,Effect::RolledBack,Effect::NotStarted),
            (RecoveryAction::PreparingCleanup,Effect::NotStarted,Effect::NotStarted),(RecoveryAction::CommittedCleanup,Effect::Committed,Effect::Committed),
            (RecoveryAction::RolledBackCleanup,Effect::RolledBack,Effect::RolledBack)] {
            let d=detail(action);assert!(d.valid());
            let prior=CoreEditOutcome{effect:pending,journal:Journal::RecoveryRequired,resources:ResourceState::Settled,reason:CoreReason::PendingState};
            assert!(d.terminal_admissible(false,&prior));
            let ok=CoreEditOutcome{effect,journal:Journal::Clean,resources:ResourceState::Settled,reason:CoreReason::None};
            assert!(!d.terminal_admissible(false,&ok));assert!(d.terminal_admissible(true,&ok));
            let mut changed=d.clone();if let Some(Prepared::Recover{recovery,..})=&mut changed.prepared{recovery.transaction_id=Some("e".repeat(32));}
            assert!(!changed.valid());assert!(!changed.terminal_admissible(true,&ok));
        }
        let mut suffix=recovery(RecoveryAction::CommittedCleanup);suffix.files.clear();suffix.private_cleanup.file_count=2;suffix.private_cleanup.directory_count=1;assert!(suffix.valid());
        for count in [0,1,3]{let mut bad=suffix.clone();bad.private_cleanup.file_count=count;assert!(!bad.valid());}
        let mut bad=suffix.clone();bad.action=Some(RecoveryAction::PreparingCleanup);assert!(!bad.valid());
        let mut value=serde_json::to_value(suffix).unwrap();value.as_object_mut().unwrap().remove("context");assert!(RecoveryView::deserialize(&value).is_err());
        let mut full=recovery(RecoveryAction::PreparingCleanup);
        for i in 6..256{full.files.push(RecoveryFile{index:i,kind:Kind::Metadata,path:format!("metadata/{i:03}.txt"),effect:RecoveryEffect::Preserve,
            before:Some(Summary{byte_length:0,sha256:digest(b""),mode:0o644}),after:None});}
        assert!(full.valid());assert!(decode(&envelope(0,"opened",json!({"intent":"recover","revision":REVISION,"recovery":full,"scopeResources":"settled"})),SESSION).is_ok());
    }
}
