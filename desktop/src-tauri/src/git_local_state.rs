//! One operation row per stable native project in the EXISTING Store Book.
//! This is not a second database, job owner, process grant or recovery retry.
//! IO methods run only in original finite jobs, outside Doc/Edit/Host locks.
use crate::{application_service::ProjectBinding, application_state_store::{Cleanup,Durability,Effect,Namespace,NativeUse,
    PrivateStateDirectory,Revision,Snapshot,StateError},git_local_protocol as wire,protocol::{strict_json,valid_id},
    service_protocol::Error,supervisor::GitLocalNativeJoined,git_branch_protocol as branch};
use serde::{Deserialize,Serialize};
use std::sync::Arc;

const PROTOCOL:&str="mrk-git-operations/1";
pub(crate) const STATE_LIMIT:usize=128*1024;
pub(crate) const MAX_ROWS:usize=32;
pub(crate) const STATE_BACKING:usize=4*STATE_LIMIT;
type Result<T>=std::result::Result<T,StateError>;
fn need(v:bool)->Result<()> {if v {Ok(())} else {Err(Error::Conflict.into())}}
fn unknown()->StateError {StateError {code:Error::StateUnknown,effect:Effect::Unknown,durability:Durability::Unknown,cleanup:Cleanup::Unknown}}
fn project_id(v:&str)->bool {v.len()==32 && v.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)) && v.bytes().any(|b|b!=b'0')}
fn snapshot_matches(retained:&Snapshot,expected:Revision,current:&Snapshot)->bool {
    retained.revision==expected && current.revision==expected && current.bytes==retained.bytes
}

#[derive(Clone,Copy,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
enum Phase {Preparing,Candidate,Finished}
#[derive(Clone,Copy,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
pub(crate) enum Completion {Succeeded,Failed,Cancelled,RecoveryRequired}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Row {
    project_id:String,operation_id:String,action:wire::Kind,review_digest:String,expected_revision:String,
    expected_ref:Option<String>,expected_head:Option<String>,expected_index:String,
    candidate_index:Option<String>,candidate_commit:Option<String>,phase:Phase,outcome:Option<Completion>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    branch:Option<branch::Journal>,
}
impl Row {
    fn preparing(project:&ProjectBinding,id:&str,review:&wire::Review)->Result<Self> {
        need(project_id(project.project_id.as_str()) && project.device!=0 && project.inode!=0 && std::path::Path::new(&project.canonical_root).is_absolute()
            && valid_id(id) && review.valid())?;
        let row=Self {project_id:project.project_id.as_str().to_owned(),operation_id:id.into(),action:review.action(),
            review_digest:review.review_digest().into(),expected_revision:review.expected_revision().into(),expected_ref:review.branch().map(str::to_owned),
            expected_head:review.head().map(str::to_owned),expected_index:review.expected_index().into(),candidate_index:None,candidate_commit:None,
            phase:Phase::Preparing,outcome:None,branch:review.branch_details().map(branch::Journal::preparing)};
        row.validate()?;Ok(row)
    }
    fn has_candidate(&self)->bool {
        self.candidate_index.is_some()||self.candidate_commit.is_some()
            ||self.branch.as_ref().is_some_and(|b|b.candidate_ref_oid.is_some())
    }
    fn intent(&self)->Option<wire::Intent> {
        if let Some(b)=&self.branch {
            Some(wire::Intent::Branch(branch::Intent {action:branch::Kind::Create,expected_revision:self.expected_revision.clone(),
                expected_reference_revision:b.expected_reference_revision.clone(),expected_ref:self.expected_ref.clone(),
                expected_head:self.expected_head.clone()?,expected_index:self.expected_index.clone(),target_ref:b.target_ref.clone(),
                expected_target_absent:b.expected_target_absent,candidate_ref_oid:b.candidate_ref_oid.clone()?}))
        } else {
            Some(wire::Intent::Files(wire::FileIntent {action:self.action,expected_revision:self.expected_revision.clone(),expected_ref:self.expected_ref.clone(),
                expected_head:self.expected_head.clone(),expected_index:self.expected_index.clone(),candidate_index:self.candidate_index.clone(),
                candidate_commit:self.candidate_commit.clone()}))
        }
    }
    fn validate(&self)->Result<()> {
        use crate::git_read_protocol as read;
        need(project_id(&self.project_id) && valid_id(&self.operation_id) && read::digest(&self.review_digest)
            && read::digest(&self.expected_revision) && read::digest(&self.expected_index)
            && self.expected_head.as_deref().is_none_or(read::oid) && self.expected_ref.as_deref().is_none_or(read::branch)
            && (self.expected_head.is_some()||self.expected_ref.is_some())
            && (self.action!=wire::Kind::Commit||self.expected_ref.is_some())
            && match self.action {
                wire::Kind::BranchCreate=>self.candidate_index.is_none() && self.candidate_commit.is_none()
                    && self.branch.as_ref().is_some_and(|b|b.valid(self.expected_head.as_deref())
                        && self.expected_ref.as_deref()!=Some(b.target_ref.as_str())),
                _=>self.branch.is_none(),
            }
            && (!self.has_candidate()||self.intent().is_some_and(|v|v.valid())))?;
        need(match self.phase {
            Phase::Preparing=> !self.has_candidate() && self.outcome.is_none(),
            Phase::Candidate=> self.has_candidate() && self.outcome.is_none(),
            Phase::Finished=>match self.outcome {
                Some(Completion::Succeeded)=>self.has_candidate(),
                Some(Completion::Failed|Completion::Cancelled)=>!self.has_candidate(),
                Some(Completion::RecoveryRequired)=>true,
                None=>false,
            }
        })
    }
    fn replaceable(&self)->bool {self.phase==Phase::Finished && matches!(self.outcome,Some(Completion::Succeeded|Completion::Failed|Completion::Cancelled))}
    fn same_original(&self,original:&Row)->bool {
        self.project_id==original.project_id && self.operation_id==original.operation_id && self.action==original.action
            && self.review_digest==original.review_digest && self.expected_revision==original.expected_revision
            && self.expected_ref==original.expected_ref && self.expected_head==original.expected_head && self.expected_index==original.expected_index
            && match (&self.branch,&original.branch) {
                (Some(b),Some(o))=>b.same_original(o),(None,None)=>true,_=>false,
            }
    }
    fn candidate(&mut self,intent:&wire::Intent)->Result<()> {
        need(self.phase==Phase::Preparing && intent.valid() && self.action==intent.action() && self.expected_revision==intent.expected_revision()
            && self.expected_ref.as_deref()==intent.expected_ref() && self.expected_head.as_deref()==intent.expected_head()
            && self.expected_index==intent.expected_index())?;
        match (&mut self.branch,intent.branch_details()) {
            (Some(b),Some(i))=>{need(b.accepts(i))?;b.candidate_ref_oid=Some(i.candidate_ref_oid.clone());},
            (None,None)=>{self.candidate_index=intent.candidate_index().map(str::to_owned);self.candidate_commit=intent.candidate_commit().map(str::to_owned);},
            _=>return Err(Error::Conflict.into()),
        }
        self.phase=Phase::Candidate;self.validate()
    }
    fn finish(&mut self,outcome:Completion)->Result<()> {
        need(self.phase!=Phase::Finished)?;
        // A persisted candidate makes a cancelled/refused child uncertain with
        // respect to publication. No negative result is upgraded to unsent.
        need(!matches!(outcome,Completion::Failed|Completion::Cancelled)||!self.has_candidate())?;
        need(outcome!=Completion::Succeeded||self.has_candidate())?;
        self.phase=Phase::Finished;self.outcome=Some(outcome);self.validate()
    }
}
#[derive(Deserialize,Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct State {schema_version:u8,protocol:String,rows:Vec<Row>}
impl State {
    fn empty()->Self {Self {schema_version:1,protocol:PROTOCOL.into(),rows:vec![]}}
    fn bytes(&self)->Result<Vec<u8>> {
        need(matches!(self.schema_version,1|2) && self.protocol==PROTOCOL && !self.rows.is_empty() && self.rows.len()<=MAX_ROWS
            && self.rows.windows(2).all(|p|p[0].project_id<p[1].project_id))?;
        // Supervisor text is process-local, not a global or durable operation
        // identity. Rows are partitioned by the service's stable project ID;
        // only the retained live Original/NativeUse can amend a pending row.
        for row in &self.rows {
            need(self.schema_version==2 || row.branch.is_none() && row.action!=wire::Kind::BranchCreate)?;
            row.validate()?;
        }
        let value=serde_json::to_value(self).map_err(|_|StateError::from(Error::InvalidRequest))?;
        let mut bytes=serde_json::to_vec(&value).map_err(|_|StateError::from(Error::InvalidRequest))?;
        bytes.push(b'\n');need(bytes.len()<=STATE_LIMIT)?;Ok(bytes)
    }
    fn decode(snapshot:&Snapshot)->Result<Self> {
        let result=(|| {
            need(snapshot.bytes.len()<=STATE_LIMIT)?;
            if snapshot.bytes.is_empty() {need(snapshot.revision==Revision(0))?;return Ok(Self::empty());}
            need(snapshot.revision!=Revision(0))?;
            let value=strict_json(&snapshot.bytes).map_err(|_|StateError::from(Error::InvalidRequest))?;
            let state:Self=serde_json::from_value(value).map_err(|_|StateError::from(Error::InvalidRequest))?;
            need(state.bytes()?==snapshot.bytes)?;Ok(state)
        })();result.map_err(|_:StateError|Error::RecoveryRequired.into())
    }
    fn reserve(&mut self,row:Row)->Result<()> {
        need(row.phase==Phase::Preparing)?;
        let branch = row.action==wire::Kind::BranchCreate;
        if let Some(index)=self.rows.iter().position(|r|r.project_id==row.project_id) {
            if !self.rows[index].replaceable() {return Err(Error::RecoveryRequired.into());}
            self.rows[index]=row;
        } else {if self.rows.len()>=MAX_ROWS {return Err(Error::Busy.into());}self.rows.push(row);}
        // Only explicit branch Apply's Preparing CAS upgrades the same document.
        // Reading schema1 never rewrites it; other pending rows stay exact.
        if branch {self.schema_version=2;}
        self.rows.sort_by(|a,b|a.project_id.cmp(&b.project_id));self.bytes()?;Ok(())
    }
}

/// Minted/retained before the Preparing CAS. Never reconstructed from a row,
/// ID, readback, public status or a later NativeUse. No Clone/serde/Debug.
pub(crate) struct Original {
    native_use:Arc<NativeUse>,project:ProjectBinding,preparing:Row,
}
impl Original {
    pub(crate) fn matches(&self,native_use:&Arc<NativeUse>,project:&ProjectBinding,id:&str)->bool {
        Arc::ptr_eq(&self.native_use,native_use) && &self.project==project && self.preparing.operation_id==id
    }
}
pub(crate) struct Ack {pub(crate) revision:Revision,pub(crate) row:Row,pub(crate) original:Arc<Original>}

pub(crate) struct GitLocalJournal {
    store:Arc<PrivateStateDirectory>,native_use:Arc<NativeUse>,project:ProjectBinding,
    opened:bool,failure:Option<StateError>,snapshot:Option<Snapshot>,original:Option<Arc<Original>>,
    #[cfg(test)] lose_next_ack:bool,
}
impl GitLocalJournal {
    pub(crate) fn new(store:Arc<PrivateStateDirectory>,native_use:Arc<NativeUse>,project:ProjectBinding)->Self {
        Self {store,native_use,project,opened:false,failure:None,snapshot:None,original:None,#[cfg(test)]lose_next_ack:false}
    }
    pub(crate) fn is_for(&self,store:&Arc<PrivateStateDirectory>,native_use:&Arc<NativeUse>,project:&ProjectBinding)->bool {
        Arc::ptr_eq(&self.store,store)&&Arc::ptr_eq(&self.native_use,native_use)&&&self.project==project
    }
    pub(crate) fn original(&self)->Option<&Arc<Original>> {self.original.as_ref()}
    pub(crate) fn failure(&self)->Option<StateError> {self.failure}
    fn healthy(&self)->Result<()> {self.failure.map_or(Ok(()),Err)}
    /// Explicit Apply only. Same original finite startup/job clocks surround
    /// this call. Ordinary status/read never calls it or enables the namespace.
    pub(crate) fn open(&mut self)->Result<Revision> {
        self.healthy()?;need(!self.opened && self.snapshot.is_none())?;
        self.opened=true;self.failure=Some(unknown()); // Pre-latch through IO/adoption, including unwinding.
        let result=(|| {
            self.store.check_native_use(&self.native_use)?;
            let snapshot=self.store.enable_git_operations(&self.native_use)?;
            State::decode(&snapshot)?;
            let revision=snapshot.revision;self.snapshot=Some(snapshot);Ok(revision)
        })();
        match result {Ok(value)=>{self.failure=None;Ok(value)},Err(error)=>{self.failure=Some(error);Err(error)}}
    }
    fn current(&mut self,expected:Revision)->Result<State> {
        self.healthy()?;
        let snapshot=self.snapshot.as_ref().ok_or_else(||StateError::from(Error::Conflict))?;
        need(snapshot.revision==expected)?;
        self.failure=Some(unknown());
        let result=(|| {
            self.store.check_native_use(&self.native_use)?;
            let current=self.store.read(Namespace::GitOperations)?;
            need(snapshot_matches(snapshot,expected,&current))?;
            State::decode(&current)
        })();
        match result {Ok(value)=>{self.failure=None;Ok(value)},Err(error)=>{self.failure=Some(error);Err(error)}}
    }
    fn publish(&mut self,expected:Revision,state:&State,row:Row,original:Arc<Original>)->Result<Ack> {
        let bytes=state.bytes()?;let next=expected.0.checked_add(1).map(Revision).ok_or_else(unknown)?;
        self.healthy()?;self.failure=Some(unknown());
        let result=(|| {
            self.store.check_native_use(&self.native_use)?;
            let snapshot=self.store.replace(Namespace::GitOperations,expected,&bytes)?;
            if snapshot.revision!=next||snapshot.bytes!=bytes {return Err(unknown());}
            #[cfg(test)] if std::mem::take(&mut self.lose_next_ack) {return Err(unknown());}
            // The original byte/revision comparison and adoption are INSIDE
            // the pre-latched region. No panic/unknown return enables retry.
            self.snapshot=Some(snapshot);Ok(Ack {revision:next,row,original})
        })();
        match result {Ok(value)=>{self.failure=None;Ok(value)},Err(error)=>{self.failure=Some(error);Err(error)}}
    }
    pub(crate) fn prepare(&mut self,expected:Revision,id:&str,review:&wire::Review)->Result<Ack> {
        self.healthy()?;need(self.original.is_none())?;
        let row=Row::preparing(&self.project,id,review)?;let mut state=self.current(expected)?;
        state.reserve(row.clone())?;
        let original=Arc::new(Original {native_use:self.native_use.clone(),project:self.project.clone(),preparing:row.clone()});
        self.original=Some(original.clone()); // Before any actual Preparing write.
        self.publish(expected,&state,row,original)
    }
    fn retained(&self,original:&Arc<Original>)->Result<()> {
        self.healthy()?;need(self.original.as_ref().is_some_and(|held|Arc::ptr_eq(held,original))
            && original.matches(&self.native_use,&self.project,&original.preparing.operation_id))
    }
    pub(crate) fn candidate(&mut self,expected:Revision,original:&Arc<Original>,candidate:&wire::Intent)->Result<Ack> {
        self.retained(original)?;let mut state=self.current(expected)?;
        let row=state.rows.iter_mut().find(|r|r.same_original(&original.preparing)).ok_or_else(||StateError::from(Error::Conflict))?;
        row.candidate(candidate)?;let row=row.clone();self.publish(expected,&state,row,original.clone())
    }
    /// This fixed witness must come from the SAME actual Supervisor after
    /// child/pipe/source/runtime/driver/watchdog joins, before final CAS. The
    /// later NativeUse-retire job has its own join and cannot be this witness.
    pub(crate) fn finish(&mut self,expected:Revision,original:&Arc<Original>,joined:&GitLocalNativeJoined)->Result<Ack> {
        self.retained(original)?;need(joined.matches(&self.native_use,original))?;
        let mut state=self.current(expected)?;
        let row=state.rows.iter_mut().find(|r|r.same_original(&original.preparing)).ok_or_else(||StateError::from(Error::Conflict))?;
        row.finish(joined.completion())?;let row=row.clone();self.publish(expected,&state,row,original.clone())
    }
}

#[cfg(test)]
#[path="git_local_state_tests.rs"]
mod tests;

#[cfg(test)]
#[path="git_branch_state_tests.rs"]
mod branch_tests;
