//! One operation row per stable native project in the EXISTING Store Book.
//! This is not a second database, job owner, process grant or recovery retry.
//! IO methods run only in original finite jobs, outside Doc/Edit/Host locks.
use crate::{application_service::ProjectBinding, application_state_store::{Cleanup,Durability,Effect,Namespace,NativeUse,
    PrivateStateDirectory,Revision,Snapshot,StateError},git_local_protocol as wire,protocol::{strict_json,valid_id},
    service_protocol::Error,supervisor::GitLocalNativeJoined,git_branch_protocol as branch,git_switch_protocol as switch,git_rename_protocol as rename,git_fast_forward_protocol as ff,git_init_protocol as init,git_fetch_state as fetch};
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
    expected_ref:Option<String>,expected_head:Option<String>,expected_index:Option<String>,
    candidate_index:Option<String>,candidate_commit:Option<String>,phase:Phase,outcome:Option<Completion>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    branch:Option<branch::Journal>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    switch:Option<switch::Journal>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    rename:Option<rename::Journal>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    fast_forward:Option<ff::Journal>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    initialization:Option<init::Journal>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    fetch:Option<fetch::Journal>,
}
impl Row {
    fn preparing(project:&ProjectBinding,id:&str,review:&wire::Review)->Result<Self> {
        need(project_id(project.project_id.as_str()) && project.device!=0 && project.inode!=0 && std::path::Path::new(&project.canonical_root).is_absolute()
            && valid_id(id) && review.valid())?;
        let row=Self {project_id:project.project_id.as_str().to_owned(),operation_id:id.into(),action:review.action(),
            review_digest:review.review_digest().into(),expected_revision:review.expected_revision().into(),expected_ref:review.branch().map(str::to_owned),
            expected_head:review.head().map(str::to_owned),expected_index:review.expected_index().map(str::to_owned),candidate_index:None,candidate_commit:None,
            phase:Phase::Preparing,outcome:None,branch:review.branch_details().map(branch::Journal::preparing),switch:review.switch_details().map(switch::Journal::preparing),rename:review.rename_details().map(rename::Journal::preparing),fast_forward:review.fast_forward_details().map(ff::Journal::preparing),initialization:review.init_details().map(init::Journal::preparing),fetch:review.fetch_details().map(fetch::Journal::preparing)};
        row.validate()?;Ok(row)
    }
    fn has_candidate(&self)->bool {
        self.candidate_index.is_some()||self.candidate_commit.is_some()
            ||self.branch.as_ref().is_some_and(|b|b.candidate_ref_oid.is_some())
            ||self.rename.as_ref().is_some_and(|r|r.candidate.is_some())
            ||self.initialization.as_ref().is_some_and(|i|i.candidate.is_some())
            ||self.fetch.as_ref().is_some_and(|f|f.candidate.is_some())
    }
    fn intent(&self)->Option<wire::Intent> {
        if let Some(f)=&self.fetch {f.candidate.clone().map(wire::Intent::Fetch)}
        else if let Some(i)=&self.initialization {i.candidate.clone().map(wire::Intent::Initialize)}
        else if let Some(f)=&self.fast_forward {
            f.intent(&self.expected_revision,self.expected_ref.as_deref()?,self.expected_head.as_deref()?,
                self.expected_index.as_deref()?,self.candidate_index.as_deref()?).map(wire::Intent::FastForward)
        } else if let Some(r)=&self.rename {
            r.intent(&self.expected_revision,self.expected_ref.as_deref()?,self.expected_head.as_deref()?,self.expected_index.as_deref()?).map(wire::Intent::Rename)
        } else if let Some(s)=&self.switch {
            s.intent(&self.expected_revision,self.expected_ref.as_deref()?,self.expected_head.as_deref()?,
                self.expected_index.as_deref()?,self.candidate_index.as_deref()?).map(wire::Intent::Switch)
        } else if let Some(b)=&self.branch {
            Some(wire::Intent::Branch(branch::Intent {action:branch::Kind::Create,expected_revision:self.expected_revision.clone(),
                expected_reference_revision:b.expected_reference_revision.clone(),expected_ref:self.expected_ref.clone(),
                expected_head:self.expected_head.clone()?,expected_index:self.expected_index.clone()?,target_ref:b.target_ref.clone(),
                expected_target_absent:b.expected_target_absent,candidate_ref_oid:b.candidate_ref_oid.clone()?}))
        } else {
            Some(wire::Intent::Files(wire::FileIntent {action:self.action,expected_revision:self.expected_revision.clone(),expected_ref:self.expected_ref.clone(),
                expected_head:self.expected_head.clone(),expected_index:self.expected_index.clone()?,candidate_index:self.candidate_index.clone(),
                candidate_commit:self.candidate_commit.clone()}))
        }
    }
    fn validate(&self)->Result<()> {
        use crate::git_read_protocol as read;
        need(project_id(&self.project_id) && valid_id(&self.operation_id) && read::digest(&self.review_digest)
            && read::digest(&self.expected_revision)
            && if self.action==wire::Kind::Initialize {self.expected_index.is_none()}else{self.expected_index.as_deref().is_some_and(read::digest)}
            && self.expected_head.as_deref().is_none_or(read::oid) && self.expected_ref.as_deref().is_none_or(read::branch)
            && (self.action==wire::Kind::Initialize && self.expected_head.is_none() && self.expected_ref.is_none()
                || self.action!=wire::Kind::Initialize && (self.expected_head.is_some()||self.expected_ref.is_some()))
            && (self.action!=wire::Kind::Commit||self.expected_ref.is_some())
            && (self.action==wire::Kind::Initialize || self.initialization.is_none())
            && (self.action==wire::Kind::Fetch || self.fetch.is_none())
            && match self.action {
                wire::Kind::Fetch=>self.initialization.is_none() && self.fast_forward.is_none() && self.branch.is_none()
                    && self.switch.is_none() && self.rename.is_none() && self.candidate_index.is_none() && self.candidate_commit.is_none()
                    && self.fetch.as_ref().is_some_and(|f|self.expected_index.as_deref().is_some_and(|index|
                        f.valid(&self.expected_revision,self.expected_head.as_deref(),self.expected_ref.as_deref(),index,&self.review_digest))),
                wire::Kind::Initialize=>self.fast_forward.is_none() && self.branch.is_none() && self.switch.is_none() && self.rename.is_none()
                    && self.candidate_index.is_none() && self.candidate_commit.is_none()
                    && self.initialization.as_ref().is_some_and(|i|i.valid(&self.expected_revision)),
                wire::Kind::FastForward=>self.branch.is_none() && self.switch.is_none() && self.rename.is_none() && self.candidate_commit.is_none()
                    && self.fast_forward.as_ref().is_some_and(|f|f.valid(self.expected_head.as_deref(),self.expected_ref.as_deref(),self.candidate_index.as_deref())),
                wire::Kind::BranchRename=>self.fast_forward.is_none() && self.branch.is_none() && self.switch.is_none() && self.candidate_index.is_none() && self.candidate_commit.is_none()
                    && self.rename.as_ref().is_some_and(|r|r.valid(self.expected_head.as_deref(),self.expected_ref.as_deref())),
                wire::Kind::BranchSwitch=>self.fast_forward.is_none() && self.rename.is_none() && self.branch.is_none() && self.candidate_commit.is_none()
                    && self.switch.as_ref().is_some_and(|s|s.valid(self.expected_head.as_deref(),self.expected_ref.as_deref(),self.candidate_index.as_deref())),
                wire::Kind::BranchCreate=>self.fast_forward.is_none() && self.rename.is_none() && self.switch.is_none() && self.candidate_index.is_none() && self.candidate_commit.is_none()
                    && self.branch.as_ref().is_some_and(|b|b.valid(self.expected_head.as_deref())
                        && self.expected_ref.as_deref()!=Some(b.target_ref.as_str())),
                _=>self.fast_forward.is_none() && self.branch.is_none() && self.switch.is_none() && self.rename.is_none(),
            }
            && (!self.has_candidate()||self.intent().is_some_and(|v|v.valid())))?;
        need(self.switch.as_ref().is_none_or(|s|s.final_state.as_ref().is_none_or(|d|
            self.phase==Phase::Finished && self.has_candidate()
            && match self.outcome {Some(Completion::Succeeded)=>d.successful(),Some(Completion::RecoveryRequired)=>d.valid(),_=>false})))?;
        need(self.action!=wire::Kind::BranchSwitch || self.outcome!=Some(Completion::Succeeded)
            || self.switch.as_ref().and_then(|s|s.final_state.as_ref()).is_some_and(switch::FinalData::successful))?;
        need(self.rename.as_ref().is_none_or(|r|r.final_state.as_ref().is_none_or(|d|
            self.phase==Phase::Finished && self.has_candidate()
            && match self.outcome {Some(Completion::Succeeded)=>d.successful(r.config_moved),Some(Completion::RecoveryRequired)=>d.valid_for(r.logging,r.config_moved),_=>false})))?;
        need(self.action!=wire::Kind::BranchRename || self.outcome!=Some(Completion::Succeeded)
            || self.rename.as_ref().is_some_and(|r|r.final_state.as_ref().is_some_and(|d|d.successful(r.config_moved))))?;
        need(self.fast_forward.as_ref().is_none_or(|f|f.final_state.as_ref().is_none_or(|d|
            self.phase==Phase::Finished && self.has_candidate()
            && match self.outcome {Some(Completion::Succeeded)=>d.successful(),Some(Completion::RecoveryRequired)=>d.valid(),_=>false})))?;
        need(self.action!=wire::Kind::FastForward || self.outcome!=Some(Completion::Succeeded)
            || self.fast_forward.as_ref().and_then(|f|f.final_state.as_ref()).is_some_and(ff::FinalData::successful))?;
        need(self.fetch.as_ref().is_none_or(|f|f.final_state.as_ref().is_none_or(|d|
            self.phase==Phase::Finished && self.has_candidate()
            && match self.outcome {Some(Completion::Succeeded)=>d.successful(f.candidate.as_ref()),
                Some(Completion::RecoveryRequired)=>d.valid(f.candidate.as_ref()),_=>false})))?;
        need(self.action!=wire::Kind::Fetch || self.outcome!=Some(Completion::Succeeded)
            || self.fetch.as_ref().is_some_and(|f|f.final_state.as_ref().is_some_and(|d|d.successful(f.candidate.as_ref()))))?;
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
            } && match (&self.switch,&original.switch) {
                (Some(s),Some(o))=>s.same_original(o),(None,None)=>true,_=>false,
            } && match (&self.fast_forward,&original.fast_forward) {
                (Some(f),Some(o))=>f.same_original(o),(None,None)=>true,_=>false,
            } && match (&self.rename,&original.rename) {
                (Some(r),Some(o))=>r.same_original(o),(None,None)=>true,_=>false,
            } && match (&self.fetch,&original.fetch) {
                (Some(f),Some(o))=>f.same_original(o),(None,None)=>true,_=>false,
            } && match (&self.initialization,&original.initialization) {
                (Some(i),Some(o))=>i.same_original(o),(None,None)=>true,_=>false,
            }
    }
    fn candidate(&mut self,intent:&wire::Intent)->Result<()> {
        need(self.phase==Phase::Preparing && intent.valid() && self.action==intent.action() && self.expected_revision==intent.expected_revision()
            && self.expected_ref.as_deref()==intent.expected_ref() && self.expected_head.as_deref()==intent.expected_head()
            && self.expected_index.as_deref()==intent.expected_index())?;
        if let Some(f)=&mut self.fetch {
            let proposed=intent.fetch_details().ok_or_else(||StateError::from(Error::Conflict))?;
            need(f.accepts(proposed))?;f.candidate=Some(proposed.clone());
        } else if let Some(i)=&mut self.initialization {
            let proposed=intent.init_details().ok_or_else(||StateError::from(Error::Conflict))?;
            need(i.accepts(proposed))?;i.candidate=Some(proposed.clone());
        } else if let Some(f)=&mut self.fast_forward {
            let i=intent.fast_forward_details().ok_or_else(||StateError::from(Error::Conflict))?;
            need(f.accepts(i))?;f.candidate(i);self.candidate_index=Some(i.candidate_index.clone());
        } else if let Some(r)=&mut self.rename {
            let i=intent.rename_details().ok_or_else(||StateError::from(Error::Conflict))?;
            need(r.accepts(i))?;r.candidate(i);
        } else if let Some(s)=&mut self.switch {
            let i=intent.switch_details().ok_or_else(||StateError::from(Error::Conflict))?;
            need(s.accepts(i))?;s.candidate(i);self.candidate_index=Some(i.candidate_index.clone());
        } else {
            need(intent.fast_forward_details().is_none() && intent.switch_details().is_none() && intent.rename_details().is_none() && intent.init_details().is_none() && intent.fetch_details().is_none())?;
            match (&mut self.branch,intent.branch_details()) {
                (Some(b),Some(i))=>{need(b.accepts(i))?;b.candidate_ref_oid=Some(i.candidate_ref_oid.clone());},
                (None,None)=>{self.candidate_index=intent.candidate_index().map(str::to_owned);self.candidate_commit=intent.candidate_commit().map(str::to_owned);},
                _=>return Err(Error::Conflict.into()),
            }
        }
        self.phase=Phase::Candidate;self.validate()
    }
    fn finish(&mut self,outcome:Completion)->Result<()> {self.finish_with_switch(outcome,None)}
    fn finish_with_switch(&mut self,outcome:Completion,details:Option<&switch::FinalData>)->Result<()> {self.finish_with_details(outcome,details,None)}
    fn finish_with_details(&mut self,outcome:Completion,details:Option<&switch::FinalData>,renamed:Option<&rename::FinalData>)->Result<()> {
        self.finish_with_fast_forward(outcome,details,renamed,None)
    }
    fn finish_with_fast_forward(&mut self,outcome:Completion,details:Option<&switch::FinalData>,renamed:Option<&rename::FinalData>,forwarded:Option<&ff::FinalData>)->Result<()> {
        self.finish_with_fetch(outcome,details,renamed,forwarded,None)
    }
    fn finish_with_fetch(&mut self,outcome:Completion,details:Option<&switch::FinalData>,renamed:Option<&rename::FinalData>,forwarded:Option<&ff::FinalData>,fetched:Option<&fetch::FinalData>)->Result<()> {
        need(self.phase!=Phase::Finished)?;
        need(details.is_none() || self.action==wire::Kind::BranchSwitch && self.has_candidate()
            && matches!(outcome,Completion::Succeeded|Completion::RecoveryRequired)
            && details.is_some_and(switch::FinalData::valid)
            && self.switch.as_ref().is_some_and(|s|s.final_state.is_none()))?;
        need(self.action!=wire::Kind::BranchSwitch || outcome!=Completion::Succeeded
            || details.is_some_and(switch::FinalData::successful))?;
        need(renamed.is_none() || self.action==wire::Kind::BranchRename && self.has_candidate()
            && matches!(outcome,Completion::Succeeded|Completion::RecoveryRequired)
            && self.rename.as_ref().is_some_and(|r|r.final_state.is_none() && renamed.is_some_and(|d|d.valid_for(r.logging,r.config_moved))))?;
        need(self.action!=wire::Kind::BranchRename || outcome!=Completion::Succeeded
            || self.rename.as_ref().is_some_and(|r|renamed.is_some_and(|d|d.successful(r.config_moved))))?;
        need(forwarded.is_none() || self.action==wire::Kind::FastForward && self.has_candidate()
            && matches!(outcome,Completion::Succeeded|Completion::RecoveryRequired)
            && forwarded.is_some_and(ff::FinalData::valid)
            && self.fast_forward.as_ref().is_some_and(|f|f.final_state.is_none()))?;
        need(self.action!=wire::Kind::FastForward || outcome!=Completion::Succeeded
            || forwarded.is_some_and(ff::FinalData::successful))?;
        need(fetched.is_none() || self.action==wire::Kind::Fetch && self.has_candidate()
            && matches!(outcome,Completion::Succeeded|Completion::RecoveryRequired)
            && self.fetch.as_ref().is_some_and(|f|f.final_state.is_none() && fetched.is_some_and(|d|d.valid(f.candidate.as_ref()))))?;
        need(self.action!=wire::Kind::Fetch || outcome!=Completion::Succeeded
            || self.fetch.as_ref().is_some_and(|f|fetched.is_some_and(|d|d.successful(f.candidate.as_ref()))))?;
        // A persisted candidate makes a cancelled/refused child uncertain with
        // respect to publication. No negative result is upgraded to unsent.
        need(!matches!(outcome,Completion::Failed|Completion::Cancelled)||!self.has_candidate())?;
        need(outcome!=Completion::Succeeded||self.has_candidate())?;
        if let Some(details)=details {
            self.switch.as_mut().ok_or_else(||StateError::from(Error::Conflict))?.final_state=Some(details.clone());
        }
        if let Some(details)=renamed {
            self.rename.as_mut().ok_or_else(||StateError::from(Error::Conflict))?.final_state=Some(details.clone());
        }
        if let Some(details)=forwarded {
            self.fast_forward.as_mut().ok_or_else(||StateError::from(Error::Conflict))?.final_state=Some(details.clone());
        }
        if let Some(details)=fetched {
            self.fetch.as_mut().ok_or_else(||StateError::from(Error::Conflict))?.final_state=Some(details.clone());
        }
        self.phase=Phase::Finished;self.outcome=Some(outcome);self.validate()
    }
}
#[derive(Deserialize,Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct State {schema_version:u8,protocol:String,rows:Vec<Row>}
impl State {
    fn empty()->Self {Self {schema_version:1,protocol:PROTOCOL.into(),rows:vec![]}}
    fn bytes(&self)->Result<Vec<u8>> {
        need((1..=7).contains(&self.schema_version) && self.protocol==PROTOCOL && !self.rows.is_empty() && self.rows.len()<=MAX_ROWS
            && self.rows.windows(2).all(|p|p[0].project_id<p[1].project_id))?;
        // Supervisor text is process-local, not a global or durable operation
        // identity. Rows are partitioned by the service's stable project ID;
        // only the retained live Original/NativeUse can amend a pending row.
        for row in &self.rows {
            need(self.schema_version>=2 || row.branch.is_none() && row.action!=wire::Kind::BranchCreate)?;
            need(self.schema_version>=3 || row.switch.is_none() && row.action!=wire::Kind::BranchSwitch)?;
            need(self.schema_version>=4 || row.rename.is_none() && row.action!=wire::Kind::BranchRename)?;
            need(self.schema_version>=5 || row.fast_forward.is_none() && row.action!=wire::Kind::FastForward)?;
            need(self.schema_version>=6 || row.fetch.is_none() && row.action!=wire::Kind::Fetch)?;
            need(self.schema_version>=7 || row.initialization.is_none() && row.action!=wire::Kind::Initialize)?;
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
        let schema = match row.action {wire::Kind::FastForward=>5,wire::Kind::Fetch=>6,wire::Kind::Initialize=>7,wire::Kind::BranchRename=>4,wire::Kind::BranchSwitch=>3,wire::Kind::BranchCreate=>2,_=>1};
        if let Some(index)=self.rows.iter().position(|r|r.project_id==row.project_id) {
            if !self.rows[index].replaceable() {return Err(Error::RecoveryRequired.into());}
            self.rows[index]=row;
        } else {if self.rows.len()>=MAX_ROWS {return Err(Error::Busy.into());}self.rows.push(row);}
        // Only explicit Apply's Preparing CAS can upgrade the same document.
        // Reads never rewrite schema1/2; all other pending rows stay exact.
        self.schema_version=self.schema_version.max(schema);
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
        row.finish_with_fetch(joined.completion(),joined.switch_final(),joined.rename_final(),joined.fast_forward_final(),joined.fetch_final())?;let row=row.clone();self.publish(expected,&state,row,original.clone())
    }
}

#[cfg(test)]
#[path="git_local_state_tests.rs"]
mod tests;

#[cfg(test)]
#[path="git_branch_state_tests.rs"]
mod branch_tests;

#[cfg(test)]
#[path="git_switch_state_tests.rs"]
mod switch_tests;

#[cfg(test)]
#[path="git_rename_state_tests.rs"]
mod rename_tests;

#[cfg(test)]
#[path="git_fast_forward_state_tests.rs"]
mod fast_forward_tests;
#[cfg(test)]
#[path="git_init_state_tests.rs"]
mod init_tests;

#[cfg(test)]
#[path="git_fetch_state_tests.rs"]
mod fetch_tests;
