//! Closed content-only switch DATA in the existing GitLocal protocol.
//! No input is an original source, publication receipt, Store ACK or consent.
//! The original worker enforces repository policy; these types bind its exact
//! finite result and the same native-held source projection, never caller FDs.
use crate::{error::BridgeError, git_branch_protocol as branch, git_local_protocol as local,
    git_read_protocol as read};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const MAX_FILES:usize=8;
pub(crate) const MAX_BYTES:u64=8*1024*1024;
pub(crate) const FILE_LIMIT:u64=4*1024*1024;
pub(crate) const INDEX_LIMIT:u64=1024*1024;
pub(crate) const LOG_LIMIT:u64=60*1024;
pub(crate) const REVIEW_KEYS:&[&str]=&["action","name","targetRef","targetOid","expectedRevision",
    "expectedReferenceRevision","head","branch","expectedIndex","paths","trackedCount","contentOnly","files","log","reviewDigest"];
pub(crate) const INTENT_KEYS:&[&str]=&["action","expectedRevision","expectedReferenceRevision","expectedRef",
    "expectedHead","expectedIndex","targetRef","targetOid","candidateIndex","originalHead","candidateHead",
    "originalLog","candidateLog","logEnabled","footprint"];
pub(crate) const RESULT_KEYS:&[&str]=&["operationId","action","state","settlement","reason","observation","intent","effectPhase","retainedPaths"];
fn need(v:bool)->Result<(),BridgeError>{if v {Ok(())} else {Err(BridgeError::protocol())}}
pub(crate) fn hash(v:&[u8])->String {Sha256::digest(v).iter().map(|b|format!("{b:02x}")).collect()}
pub(crate) fn reason(v:&str)->bool {
    matches!(v,"switch-dirty"|"switch-layout"|"switch-target"|"switch-conversion"|"switch-identity-required"|"switch-log-limit"|"switch-file-mode")
}
#[derive(Clone,Copy,Deserialize,Serialize,PartialEq,Eq)]
pub(crate) enum Kind {#[serde(rename="branch-switch")] Switch}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Action {
    pub(crate) kind:Kind,pub(crate) expected_revision:String,pub(crate) expected_reference_revision:String,pub(crate) name:String,
}
impl Action {
    pub(crate) fn valid(&self)->bool {
        branch::name(&self.name)&&read::digest(&self.expected_revision)&&read::digest(&self.expected_reference_revision)
    }
}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct File {
    pub(crate) path:String,pub(crate) mode:String,pub(crate) source_oid:String,pub(crate) target_oid:String,
    pub(crate) source_sha256:String,pub(crate) target_sha256:String,pub(crate) target_size:u64,
}
impl File {
    fn valid(&self,width:usize)->bool {
        read::relative(&self.path)&&matches!(self.mode.as_str(),"100644"|"100755")
            &&read::oid(&self.source_oid)&&read::oid(&self.target_oid)&&self.source_oid.len()==width&&self.target_oid.len()==width
            &&self.source_oid!=self.target_oid&&read::digest(&self.source_sha256)&&read::digest(&self.target_sha256)
            &&self.target_size<=FILE_LIMIT
    }
    pub(crate) fn mode_bits(&self)->u32 {if self.mode=="100755" {0o100755} else {0o100644}}
}
fn valid_files(files:&[File],width:usize)->bool {
    files.len()<=MAX_FILES &&files.iter().all(|v|v.valid(width))&&files.windows(2).all(|v|v[0].path<v[1].path)
        &&files.iter().try_fold(0u64,|n,v|n.checked_add(v.target_size)).is_some_and(|n|n<=MAX_BYTES)
}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Log {pub(crate) enabled:bool,pub(crate) original_kind:String,pub(crate) original_sha256:String}
impl Log {
    pub(crate) fn valid(&self)->bool {
        read::digest(&self.original_sha256)&&match self.original_kind.as_str() {
            "absent"=>self.original_sha256==hash(b"absent"),"file"=>self.enabled,_=>false,
        }
    }
}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Review {
    pub(crate) action:Kind,pub(crate) name:String,pub(crate) target_ref:String,pub(crate) target_oid:String,
    pub(crate) expected_revision:String,pub(crate) expected_reference_revision:String,pub(crate) head:String,pub(crate) branch:String,
    pub(crate) expected_index:String,pub(crate) paths:Vec<String>,pub(crate) tracked_count:u16,pub(crate) content_only:bool,
    pub(crate) files:Vec<File>,pub(crate) log:Log,pub(crate) review_digest:String,
}
impl Review {
    pub(crate) fn valid(&self)->bool {
        branch::name(&self.name)&&self.target_ref==format!("refs/heads/{}",self.name)&&read::branch(&self.branch)
            &&self.branch!=self.target_ref&&read::oid(&self.head)&&read::oid(&self.target_oid)&&self.head.len()==self.target_oid.len()
            &&read::digest(&self.expected_revision)&&read::digest(&self.expected_reference_revision)
            &&read::digest(&self.expected_index)&&read::digest(&self.review_digest)&&self.content_only
            &&self.tracked_count<=256&&self.files.len()<=usize::from(self.tracked_count)&&valid_files(&self.files,self.head.len())
            &&self.paths.len()==self.files.len()&&self.paths.iter().zip(&self.files).all(|(p,f)|p==&f.path)&&self.log.valid()
    }
    pub(crate) fn matches(&self,action:&Action)->bool {
        self.valid()&&action.valid()&&self.name==action.name&&self.expected_revision==action.expected_revision
            &&self.expected_reference_revision==action.expected_reference_revision
    }
}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Intent {
    pub(crate) action:Kind,pub(crate) expected_revision:String,pub(crate) expected_reference_revision:String,
    pub(crate) expected_ref:String,pub(crate) expected_head:String,pub(crate) expected_index:String,
    pub(crate) target_ref:String,pub(crate) target_oid:String,pub(crate) candidate_index:String,
    pub(crate) original_head:String,pub(crate) candidate_head:String,pub(crate) original_log:String,
    pub(crate) candidate_log:String,pub(crate) log_enabled:bool,pub(crate) footprint:String,
}
impl Intent {
    pub(crate) fn valid(&self)->bool {
        read::branch(&self.expected_ref)&&self.target_ref.strip_prefix("refs/heads/").is_some_and(branch::name)
            &&self.expected_ref!=self.target_ref&&read::oid(&self.expected_head)&&read::oid(&self.target_oid)
            &&self.expected_head.len()==self.target_oid.len()
            &&[&self.expected_revision,&self.expected_reference_revision,&self.expected_index,&self.candidate_index,
               &self.original_head,&self.candidate_head,&self.original_log,&self.candidate_log,&self.footprint].iter().all(|s|read::digest(s))
            &&self.original_head==hash(format!("ref: {}\n",self.expected_ref).as_bytes())
            &&self.candidate_head==hash(format!("ref: {}\n",self.target_ref).as_bytes())
            &&(self.log_enabled||self.candidate_log==hash(b"absent"))
    }
    pub(crate) fn matches(&self,r:&Review)->bool {
        self.valid()&&r.valid()&&self.expected_revision==r.expected_revision&&self.expected_reference_revision==r.expected_reference_revision
            &&self.expected_ref==r.branch&&self.expected_head==r.head&&self.expected_index==r.expected_index
            &&self.target_ref==r.target_ref&&self.target_oid==r.target_oid&&self.original_log==r.log.original_sha256&&self.log_enabled==r.log.enabled
    }
}

// Private projections only, deliberately no Deserialize or renderer endpoint.
#[derive(Clone,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase")]
pub(crate) struct TargetLock {
    pub(crate) identity:read::FileIdentity,pub(crate) parent_before:read::FileIdentity,pub(crate) parent_locked:read::FileIdentity,
}
#[derive(Clone,Serialize,PartialEq,Eq)]
pub(crate) struct NamedSnapshot {pub(crate) path:String,pub(crate) snapshot:read::Snapshot}
#[derive(Clone,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase")]
pub(crate) struct Sources {pub(crate) target_lock:TargetLock,pub(crate) head_log:Option<read::Snapshot>,pub(crate) files:Vec<NamedSnapshot>}
fn file(snapshot:&read::Snapshot,uid:u32,limit:u64)->bool {
    let v=snapshot.identity;
    v.0>0&&v.1>0&&v.2&0o170000==0o100000&&v.2&0o7022==0&&v.3==uid&&v.5==1&&v.6<=limit&&read::digest(&snapshot.sha256)
}
fn parent(v:read::FileIdentity,uid:u32)->bool {
    v.0>0&&v.1>0&&v.2&0o170000==0o040000&&v.2&0o7022==0&&v.3==uid&&v.5>0
}
pub(crate) fn parent_transition(before:read::FileIdentity,after:read::FileIdentity)->bool {
    (before.0,before.1,before.2,before.3,before.4,before.5)==(after.0,after.1,after.2,after.3,after.4,after.5)
}
// Darwin replacement creation inherits its held parent group. This comparison
// merely refuses unsupported per-file group overrides before GO; it never
// changes ownership or supplies a source/replace capability.
pub(crate) fn replacement_group(original:read::FileIdentity,parent:read::DirectoryIdentity)->bool {
    original.4==parent.4
}
impl Sources {
    pub(crate) fn valid(&self,native:&read::Native,review:&Review)->bool {
        let lock=&self.target_lock;
        native.valid()&&review.valid()&&native.files.index.as_ref().is_some_and(|s|file(s,native.uid,INDEX_LIMIT)&&s.sha256==review.expected_index)
            &&native.files.head.sha256==hash(format!("ref: {}\n",review.branch).as_bytes())
            &&file(&read::Snapshot {identity:lock.identity,sha256:hash(b"")},native.uid,0)&&lock.identity.2==0o100600
            &&parent(lock.parent_before,native.uid)&&parent(lock.parent_locked,native.uid)&&parent_transition(lock.parent_before,lock.parent_locked)
            &&match &self.head_log {Some(s)=>review.log.original_kind=="file"&&file(s,native.uid,LOG_LIMIT)&&s.sha256==review.log.original_sha256,
                                   None=>review.log.original_kind=="absent"}
            &&self.files.len()==review.files.len()&&self.files.iter().zip(&review.files).all(|(s,f)|s.path==f.path
                &&file(&s.snapshot,native.uid,FILE_LIMIT)&&s.snapshot.identity.2==f.mode_bits()&&s.snapshot.sha256==f.source_sha256)
            &&self.files.iter().try_fold(0u64,|n,v|n.checked_add(v.snapshot.identity.6)).is_some_and(|n|n<=MAX_BYTES)
    }
}

/// Schema3-only part of the SAME per-project row. Only explicit Apply's
/// Preparing CAS upgrades the envelope; old pending rows remain byte-exact.
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct CandidateData {pub(crate) head:String,pub(crate) log:String,pub(crate) footprint:String}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Journal {
    pub(crate) expected_reference_revision:String,pub(crate) target_ref:String,pub(crate) target_oid:String,
    pub(crate) files:Vec<File>,pub(crate) log:Log,pub(crate) candidate:Option<CandidateData>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub(crate) final_state:Option<FinalData>,
}
impl Journal {
    pub(crate) fn preparing(review:&Review)->Self {
        Self {expected_reference_revision:review.expected_reference_revision.clone(),target_ref:review.target_ref.clone(),target_oid:review.target_oid.clone(),
            files:review.files.clone(),log:review.log.clone(),candidate:None,final_state:None}
    }
    pub(crate) fn valid(&self,head:Option<&str>,reference:Option<&str>,index:Option<&str>)->bool {
        head.is_some_and(|h|read::oid(h)&&h.len()==self.target_oid.len())&&reference.is_some_and(read::branch)
            &&reference!=Some(self.target_ref.as_str())&&self.target_ref.strip_prefix("refs/heads/").is_some_and(branch::name)
            &&read::oid(&self.target_oid)&&read::digest(&self.expected_reference_revision)&&valid_files(&self.files,self.target_oid.len())&&self.log.valid()
            &&self.final_state.as_ref().is_none_or(|d|self.candidate.is_some()&&d.valid()
                &&(d.effect_phase!="head-log-returned"||self.log.enabled))
            &&match (&self.candidate,index) {
                (None,None)=>true,
                (Some(c),Some(i))=>read::digest(i)&&c.head==hash(format!("ref: {}\n",self.target_ref).as_bytes())
                    &&read::digest(&c.log)&&read::digest(&c.footprint)&&(self.log.enabled||c.log==hash(b"absent")),
                _=>false,
            }
    }
    pub(crate) fn same_original(&self,old:&Self)->bool {
        self.expected_reference_revision==old.expected_reference_revision&&self.target_ref==old.target_ref&&self.target_oid==old.target_oid
            &&self.files==old.files&&self.log==old.log
    }
    pub(crate) fn accepts(&self,intent:&Intent)->bool {
        self.candidate.is_none()&&self.final_state.is_none()&&intent.valid()&&self.expected_reference_revision==intent.expected_reference_revision
            &&self.target_ref==intent.target_ref&&self.target_oid==intent.target_oid&&self.log.enabled==intent.log_enabled&&self.log.original_sha256==intent.original_log
    }
    pub(crate) fn candidate(&mut self,intent:&Intent) {
        self.candidate=Some(CandidateData {head:intent.candidate_head.clone(),log:intent.candidate_log.clone(),footprint:intent.footprint.clone()});
    }
    pub(crate) fn intent(&self,revision:&str,reference:&str,head:&str,old_index:&str,index:&str)->Option<Intent> {
        let c=self.candidate.as_ref()?;
        Some(Intent {action:Kind::Switch,expected_revision:revision.into(),expected_reference_revision:self.expected_reference_revision.clone(),
            expected_ref:reference.into(),expected_head:head.into(),expected_index:old_index.into(),target_ref:self.target_ref.clone(),target_oid:self.target_oid.clone(),
            candidate_index:index.into(),original_head:hash(format!("ref: {reference}\n").as_bytes()),candidate_head:c.head.clone(),
            original_log:self.log.original_sha256.clone(),candidate_log:c.log.clone(),log_enabled:self.log.enabled,footprint:c.footprint.clone()})
    }
}

pub(crate) fn effect(publication:local::Publication)->Option<&'static str> {
    match publication {
        local::Publication::NotReported=>Some("not-published"),local::Publication::SwitchCheckoutReturned=>Some("worktree-returned"),
        local::Publication::SwitchLogReturned=>Some("head-log-returned"),local::Publication::SwitchHeadReturned=>Some("head-returned"),
        local::Publication::SwitchIndexReturned=>Some("index-returned"),_=>None,
    }
}
fn retained_path(path:&str)->bool {
    let p:Vec<_>=path.split('/').collect();
    p.len()==3&&p[0]==".git"&&p[1].strip_prefix("mrk-git-").is_some_and(|name|!name.is_empty()&&name.len()<=64
        &&name.bytes().all(|b|b.is_ascii_alphanumeric()||b"_-".contains(&b)))
        &&matches!(p[2],"index"|"execution-index"|"HEAD"|"HEAD-log"|"checkout-mode")
}
/// Bounded historical recovery DATA. Only the original joined final-CAS path
/// records this; reading it can neither settle a live task nor retry checkout.
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct FinalData {pub(crate) effect_phase:String,pub(crate) retained_paths:Vec<String>}
impl FinalData {
    pub(crate) fn valid(&self)->bool {
        matches!(self.effect_phase.as_str(),"worktree-returned"|"head-log-returned"|"head-returned"|"index-returned")
            &&self.retained_paths.len()<=5&&self.retained_paths.iter().all(|p|retained_path(p))
            &&self.retained_paths.windows(2).all(|v|v[0]<v[1])
    }
    pub(crate) fn successful(&self)->bool {self.valid()&&self.effect_phase=="index-returned"&&self.retained_paths.is_empty()}
    pub(crate) fn from_returned(request:&local::Request,candidate:&local::Candidate,terminal:&local::Terminal,
        publication:local::Publication)->Result<Self,BridgeError> {
        need(request.phase==local::Phase::Apply&&request.action.kind()==local::Kind::BranchSwitch
            &&terminal.phase==local::Phase::Apply&&terminal.action==local::Kind::BranchSwitch
            &&terminal.status==read::Outcome::Ok&&terminal.child_declared_settled()&&terminal.publication==publication
            &&publication!=local::Publication::NotReported
            &&request.binding.as_ref().is_some_and(|b|candidate.intent.matches(&b.review))
            &&terminal.result["operationId"]==request.id
            &&terminal.result["intent"]==serde_json::to_value(&candidate.intent).map_err(|_|BridgeError::protocol())?)?;
        validate_applied(request,terminal,Some(candidate))?;
        let value=Self {effect_phase:terminal.result["effectPhase"].as_str().ok_or_else(BridgeError::protocol)?.into(),
            retained_paths:terminal.result["retainedPaths"].as_array().ok_or_else(BridgeError::protocol)?
                .iter().map(|p|p.as_str().map(str::to_owned).ok_or_else(BridgeError::protocol)).collect::<Result<_,_>>()?};
        need(value.valid())?;Ok(value)
    }
}
pub(crate) fn validate_applied(request:&local::Request,terminal:&local::Terminal,candidate:Option<&local::Candidate>)->Result<(),BridgeError> {
    let value=&terminal.result;
    let phase=effect(terminal.publication).ok_or_else(BridgeError::protocol)?;
    need(value["effectPhase"].as_str()==Some(phase))?;
    let retained=value["retainedPaths"].as_array().filter(|v|v.len()<=5).ok_or_else(BridgeError::protocol)?;
    need(retained.iter().all(|v|v.as_str().is_some_and(retained_path))
        &&retained.windows(2).all(|v|v[0].as_str()<v[1].as_str()))?;
    let intent=candidate.and_then(|v|v.intent.switch_details());
    need(terminal.publication==local::Publication::NotReported||intent.is_some())?;
    need(terminal.publication!=local::Publication::SwitchLogReturned||intent.is_some_and(|i|i.log_enabled))?;
    if value["state"]=="succeeded" {
        let intent=intent.ok_or_else(BridgeError::protocol)?;
        need(terminal.publication==local::Publication::SwitchIndexReturned&&retained.is_empty()&&value["reason"].is_null()
            &&read::observation(&value["observation"])&&value["observation"]["head"].as_str()==Some(intent.target_oid.as_str())
            &&value["observation"]["branch"].as_str()==Some(intent.target_ref.as_str())
            &&terminal.first_failure_ns.is_none()&&terminal.cleanup_end_ns==request.clock.hard_end_ns)
    } else {
        need(value["reason"].as_str().is_some_and(|v|read::reason(v)||reason(v))&&value["observation"].is_null()&&terminal.first_failure_ns.is_some()
            &&if value["state"]=="recovery-required" {intent.is_some()} else {
                value["state"]=="failed"&&terminal.publication==local::Publication::NotReported&&retained.is_empty()
            })
    }
}

#[cfg(test)]
#[path="git_switch_protocol_tests.rs"]
pub(crate) mod tests;
