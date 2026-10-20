//! Fixed local Git DATA, not a process/source/publisher/Store authority.
//! Draft author/message stay private; public projections contain only bounded
//! review/intent facts. Child publication and terminal frames never settle the
//! original native invocation. No serialized plan is accepted for execution.
use crate::{error::BridgeError, git_read_protocol as read, git_branch_protocol as branch, git_switch_protocol as switch, git_rename_protocol as rename, git_fast_forward_protocol as ff, protocol::{strict_json, valid_id}};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[path = "service_git_commit_native.rs"]
mod service_commit;

pub(crate) use read::{Clock, Context, Directories, DirectoryIdentity, FileIdentity, Files, Native, Snapshot};
pub(crate) use read::{INDEX_LIMIT, TOOL_LIMIT, TOOL_PATH};
pub(crate) const PROTOCOL: &str = "mrk-git-local/1";
pub(crate) const REQUEST_LIMIT: usize = 96 * 1024;
pub(crate) const READY_LIMIT: usize = 512;
pub(crate) const CANDIDATE_LIMIT: usize = 4 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 2 * 1024 * 1024;
pub(crate) const WORK_SECONDS: u64 = 45;
pub(crate) const HARD_SECONDS: u64 = 55;
// Read backing plus the retained private draft/review and one candidate frame.
// Original runtime/source/Store job backing is charged separately.
pub(crate) const DATA_BACKING: usize = read::DATA_BACKING + 1024 * 1024;
// Public action + private action + full reviewed path set + diff path set can
// each retain 64KiB beside a 256KiB diff, plus Values/strings/stamp backing.
pub(crate) const REVIEW_BACKING: usize = 1024 * 1024;

/// GitLocal-only storage arithmetic. The actual Document census includes the
/// retained read/preparer/review; none is presumed discarded before admission.
/// The writer independently includes its complete original code reservation.
/// This is not a process RSS bound, a source grant, or credit for another lane.
pub(crate) fn admission_bytes(document: usize, future: usize) -> Option<usize> {
    const DOCUMENT_BACKING: usize = 16 * 1024 * 1024;
    const WRITER_BACKING: usize = 16 * 1024 * 1024;
    let code = crate::macos_history_inventory::CODE_CONTROL_RESERVE;
    let writer = future.checked_sub(code)?;
    let total = document.checked_add(future)?;
    let limit = code.checked_add(DOCUMENT_BACKING)?.checked_add(WRITER_BACKING)?;
    if document > DOCUMENT_BACKING || writer > WRITER_BACKING || total > limit { return None; }
    Some(total)
}

fn need(v: bool) -> Result<(), BridgeError> { if v { Ok(()) } else { Err(BridgeError::protocol()) } }
fn keys(v: &Value, names: &[&str]) -> bool {
    v.as_object().is_some_and(|o| o.len() == names.len() && names.iter().all(|n| o.contains_key(*n)))
}
fn hash(bytes: &[u8]) -> String { Sha256::digest(bytes).iter().map(|b|format!("{b:02x}")).collect() }
fn paths(v: &[String]) -> bool {
    !v.is_empty() && v.len() <= 64 && v.iter().all(|p|read::relative(p)) && v.windows(2).all(|p|p[0] < p[1])
}
fn frame(bytes: &[u8], limit: usize) -> Result<Value, BridgeError> {
    need(!bytes.is_empty() && bytes.len() <= limit && bytes.last() == Some(&b'\n')
        && bytes.iter().filter(|b|**b == b'\n').count() == 1)?;
    strict_json(bytes)
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="lowercase")]
pub(crate) enum Kind { Stage, Unstage, Commit, #[serde(rename="branch-create")] BranchCreate, #[serde(rename="branch-switch")] BranchSwitch, #[serde(rename="branch-rename")] BranchRename, #[serde(rename="fast-forward")] FastForward }
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="lowercase")]
pub(crate) enum Phase { Prepare, Apply }
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity { name: String, email: String }
impl Identity {
    fn valid(&self) -> bool {
        !self.name.is_empty() && read::text(&self.name,128,false) && !self.name.contains('<') && !self.name.contains('>')
            && !self.email.is_empty() && read::text(&self.email,254,false)
            && !self.email.chars().any(|c|c.is_whitespace() || matches!(c,'<'|'>'))
            && self.email.split('@').count() == 2 && self.email.split('@').all(|v|!v.is_empty())
    }
}
// Serialize is used only for the private child request. No Debug and no public
// projection containing the file draft. Exact tagged branch DATA has neither
// paths/message/identity nor a fabricated empty whole-index review.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum Action { Files(FileAction), Branch(branch::Action), Switch(switch::Action), Rename(rename::Action), FastForward(ff::Action) }
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct FileAction {
    pub(crate) kind: Kind,
    pub(crate) expected_revision: String,
    pub(crate) paths: Vec<String>,
    message: Option<String>,
    identity: Option<Identity>,
}
impl Action {
    /// Closed index-only DATA construction; no commit draft fields are exposed.
    pub(crate) fn index(kind: Kind, expected_revision: String, paths: Vec<String>) -> Result<Self, BridgeError> {
        let action = Self::Files(FileAction { kind, expected_revision, paths, message: None, identity: None });
        if matches!(kind, Kind::Stage | Kind::Unstage) && action.valid() { Ok(action) }
        else { Err(BridgeError::invalid()) }
    }
    pub(crate) fn kind(&self) -> Kind { match self { Self::Files(v)=>v.kind, Self::Branch(_)=>Kind::BranchCreate, Self::Switch(_)=>Kind::BranchSwitch, Self::FastForward(_)=>Kind::FastForward, Self::Rename(_)=>Kind::BranchRename } }
    pub(crate) fn expected_revision(&self) -> &str { match self { Self::Files(v)=>&v.expected_revision, Self::Branch(v)=>&v.expected_revision, Self::Switch(v)=>&v.expected_revision,Self::FastForward(v)=>&v.expected_revision, Self::Rename(v)=>&v.expected_revision } }
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::Branch(v)=>v.valid(), Self::Switch(v)=>v.valid(),Self::FastForward(v)=>v.valid(), Self::Rename(v)=>v.valid(),
            Self::Files(v)=>read::digest(&v.expected_revision) && match v.kind {
                Kind::Commit => v.paths.is_empty()
                    && v.identity.as_ref().is_some_and(Identity::valid)
                    && v.message.as_ref().is_some_and(|m| !m.trim().is_empty() && read::text(m,4096,true) && !m.contains('\r')),
                Kind::Stage|Kind::Unstage => paths(&v.paths) && v.message.is_none() && v.identity.is_none(),
                Kind::BranchCreate|Kind::BranchSwitch|Kind::BranchRename|Kind::FastForward => false,
            },
        }
    }
    pub(crate) fn public(&self) -> PublicAction {
        match self {
            Self::Files(v)=>PublicAction::Files(PublicFileAction {kind:v.kind,expected_revision:v.expected_revision.clone(),paths:v.paths.clone()}),
            Self::Branch(v)=>PublicAction::Branch(v.clone()),
            Self::Switch(v)=>PublicAction::Switch(v.clone()),Self::FastForward(v)=>PublicAction::FastForward(v.clone()),
            Self::Rename(v)=>PublicAction::Rename(v.clone()),
        }
    }
}
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum PublicAction { Files(PublicFileAction), Branch(branch::Action), Switch(switch::Action), Rename(rename::Action), FastForward(ff::Action) }
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase")]
pub(crate) struct PublicFileAction { pub(crate) kind:Kind, pub(crate) expected_revision:String, pub(crate) paths:Vec<String> }
pub(crate) struct Prepare {
    pub(crate) project_id: String, pub(crate) expected_document_revision: u32, pub(crate) action: Action,
}
pub(crate) struct Apply {
    pub(crate) project_id: String, pub(crate) expected_document_revision: u32, pub(crate) review_id: String,
}
pub(crate) enum Command { Prepare(Prepare), Apply(Apply), Discard(String), Status, Cancel(String) }
pub(crate) fn decode_command(name: &str, raw: &[u8]) -> Result<Command, BridgeError> {
    let limit = if name == "git_local_prepare" {REQUEST_LIMIT} else {1024};
    need(raw.len().saturating_add(name.len()).saturating_add(32) <= limit)?;
    let body = strict_json(raw)?;
    if name == "git_local_status" && keys(&body,&[]) { return Ok(Command::Status); }
    let field = match name { "git_local_discard" => "reviewId", "git_local_cancel" => "operationId", _ => "" };
    if !field.is_empty() && keys(&body,&[field]) {
        let id = body[field].as_str().filter(|v|valid_id(v)).ok_or_else(BridgeError::invalid)?.into();
        return Ok(if field == "reviewId" {Command::Discard(id)} else {Command::Cancel(id)});
    }
    need(match name {
        "git_local_prepare" => keys(&body,&["projectId","expectedDocumentRevision","action"])
            && if body["action"]["kind"] == "fast-forward" {
                keys(&body["action"],&["kind","expectedRevision","expectedReferenceRevision","targetRef","targetOid"])
            } else if matches!(body["action"]["kind"].as_str(),Some("branch-create"|"branch-switch"|"branch-rename")) {
                keys(&body["action"],&["kind","expectedRevision","expectedReferenceRevision","name"])
            } else { keys(&body["action"],&["kind","expectedRevision","paths","message","identity"]) },
        "git_local_apply" => keys(&body,&["projectId","expectedDocumentRevision","reviewId"]),
        _ => false,
    })?;
    let project_id = body["projectId"].as_str().filter(|v|valid_id(v)).ok_or_else(BridgeError::invalid)?.into();
    let revision = body["expectedDocumentRevision"].as_u64().and_then(|v|u32::try_from(v).ok())
        .filter(|v|*v != 0 && *v != u32::MAX).ok_or_else(BridgeError::invalid)?;
    if name == "git_local_prepare" {
        let action: Action = serde_json::from_value(body["action"].clone()).map_err(|_|BridgeError::invalid())?;
        need(action.valid())?;
        Ok(Command::Prepare(Prepare {project_id,expected_document_revision:revision,action}))
    } else {
        let review_id = body["reviewId"].as_str().filter(|v|valid_id(v)).ok_or_else(BridgeError::invalid)?.into();
        Ok(Command::Apply(Apply {project_id,expected_document_revision:revision,review_id}))
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum Review { Files(FileReview), Branch(branch::Review), Switch(switch::Review), Rename(rename::Review), FastForward(ff::Review) }
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct FileReview {
    pub(crate) action: Kind, pub(crate) expected_revision: String, pub(crate) paths: Vec<String>,
    pub(crate) whole_index: bool, pub(crate) head: Option<String>, pub(crate) branch: Option<String>,
    pub(crate) expected_index: String, pub(crate) review_digest: String,
}
impl Review {
    pub(crate) fn action(&self) -> Kind { match self {Self::Files(v)=>v.action, Self::Branch(_)=>Kind::BranchCreate, Self::Switch(_)=>Kind::BranchSwitch, Self::FastForward(_)=>Kind::FastForward, Self::Rename(_)=>Kind::BranchRename} }
    pub(crate) fn expected_revision(&self) -> &str { match self {Self::Files(v)=>&v.expected_revision, Self::Branch(v)=>&v.expected_revision, Self::Switch(v)=>&v.expected_revision,Self::FastForward(v)=>&v.expected_revision, Self::Rename(v)=>&v.expected_revision} }
    pub(crate) fn head(&self) -> Option<&str> { match self {Self::Files(v)=>v.head.as_deref(), Self::Branch(v)=>Some(&v.head), Self::Switch(v)=>Some(&v.head),Self::FastForward(v)=>Some(&v.head), Self::Rename(v)=>Some(&v.head)} }
    pub(crate) fn branch(&self) -> Option<&str> { match self {Self::Files(v)=>v.branch.as_deref(), Self::Branch(v)=>v.branch.as_deref(), Self::Switch(v)=>Some(&v.branch),Self::FastForward(v)=>Some(&v.branch), Self::Rename(v)=>Some(&v.branch)} }
    pub(crate) fn expected_index(&self) -> &str { match self {Self::Files(v)=>&v.expected_index, Self::Branch(v)=>&v.expected_index, Self::Switch(v)=>&v.expected_index,Self::FastForward(v)=>&v.expected_index, Self::Rename(v)=>&v.expected_index} }
    pub(crate) fn review_digest(&self) -> &str { match self {Self::Files(v)=>&v.review_digest, Self::Branch(v)=>&v.review_digest, Self::Switch(v)=>&v.review_digest,Self::FastForward(v)=>&v.review_digest, Self::Rename(v)=>&v.review_digest} }
    pub(crate) fn file(&self) -> Option<&FileReview> { match self {Self::Files(v)=>Some(v),_=>None} }
    pub(crate) fn fast_forward_details(&self) -> Option<&ff::Review> {match self {Self::FastForward(v)=>Some(v),_=>None}}
    pub(crate) fn rename_details(&self) -> Option<&rename::Review> {match self {Self::Rename(v)=>Some(v),_=>None}}
    pub(crate) fn switch_details(&self) -> Option<&switch::Review> {match self {Self::Switch(v)=>Some(v),_=>None}}
    pub(crate) fn branch_details(&self) -> Option<&branch::Review> { match self {Self::Branch(v)=>Some(v),_=>None} }
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::Branch(v)=>v.valid(), Self::Switch(v)=>v.valid(),Self::FastForward(v)=>v.valid(), Self::Rename(v)=>v.valid(),
            Self::Files(v)=>!matches!(v.action,Kind::BranchCreate|Kind::BranchSwitch|Kind::BranchRename|Kind::FastForward) && read::digest(&v.expected_revision)
                && read::digest(&v.expected_index) && read::digest(&v.review_digest)
                && paths(&v.paths) && v.whole_index == (v.action == Kind::Commit)
                && v.head.as_deref().is_none_or(read::oid) && v.branch.as_deref().is_none_or(read::branch)
                && (v.head.is_some() || v.branch.is_some()) && (v.action != Kind::Commit || v.branch.is_some()),
        }
    }
    fn matches(&self, action: &Action) -> bool {
        self.valid() && action.valid() && match (self,action) {
            (Self::Branch(v),Action::Branch(a))=>v.matches(a),
            (Self::Switch(v),Action::Switch(a))=>v.matches(a),
            (Self::FastForward(v),Action::FastForward(a))=>v.matches(a),
            (Self::Rename(v),Action::Rename(a))=>v.matches(a),
            (Self::Files(v),Action::Files(a))=>v.action == a.kind && v.expected_revision == a.expected_revision
                && (a.kind == Kind::Commit || v.paths == a.paths),
            _=>false,
        }
    }
    fn decode(value:&Value) -> Result<Self,BridgeError> {
        need(if value["action"] == "fast-forward" {
            keys(value,ff::REVIEW_KEYS)
        } else if value["action"] == "branch-switch" {
            keys(value,switch::REVIEW_KEYS)
        } else if value["action"] == "branch-rename" {
            keys(value,rename::REVIEW_KEYS)
        } else if value["action"] == "branch-create" {
            keys(value,&["action","name","targetRef","expectedRevision","expectedReferenceRevision","head","branch","expectedIndex","reviewDigest"])
        } else { keys(value,&["action","expectedRevision","paths","wholeIndex","head","branch","expectedIndex","reviewDigest"]) })?;
        serde_json::from_value(value.clone()).map_err(|_|BridgeError::protocol())
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum Intent { Files(FileIntent), Branch(branch::Intent), Switch(switch::Intent), Rename(rename::Intent), FastForward(ff::Intent) }
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct FileIntent {
    pub(crate) action: Kind, pub(crate) expected_revision: String, pub(crate) expected_ref: Option<String>,
    pub(crate) expected_head: Option<String>, pub(crate) expected_index: String,
    pub(crate) candidate_index: Option<String>, pub(crate) candidate_commit: Option<String>,
}
impl Intent {
    pub(crate) fn action(&self) -> Kind { match self {Self::Files(v)=>v.action,Self::Branch(_)=>Kind::BranchCreate, Self::Switch(_)=>Kind::BranchSwitch, Self::FastForward(_)=>Kind::FastForward, Self::Rename(_)=>Kind::BranchRename} }
    pub(crate) fn expected_revision(&self) -> &str { match self {Self::Files(v)=>&v.expected_revision,Self::Branch(v)=>&v.expected_revision, Self::Switch(v)=>&v.expected_revision,Self::FastForward(v)=>&v.expected_revision, Self::Rename(v)=>&v.expected_revision} }
    pub(crate) fn expected_ref(&self) -> Option<&str> { match self {Self::Files(v)=>v.expected_ref.as_deref(),Self::Branch(v)=>v.expected_ref.as_deref(),Self::Switch(v)=>Some(&v.expected_ref),Self::FastForward(v)=>Some(&v.expected_ref),Self::Rename(v)=>Some(&v.expected_ref)} }
    pub(crate) fn expected_head(&self) -> Option<&str> { match self {Self::Files(v)=>v.expected_head.as_deref(),Self::Branch(v)=>Some(&v.expected_head),Self::Switch(v)=>Some(&v.expected_head),Self::FastForward(v)=>Some(&v.expected_head),Self::Rename(v)=>Some(&v.expected_head)} }
    pub(crate) fn expected_index(&self) -> &str { match self {Self::Files(v)=>&v.expected_index,Self::Branch(v)=>&v.expected_index, Self::Switch(v)=>&v.expected_index,Self::FastForward(v)=>&v.expected_index, Self::Rename(v)=>&v.expected_index} }
    pub(crate) fn candidate_index(&self) -> Option<&str> { match self {Self::Files(v)=>v.candidate_index.as_deref(),Self::Branch(_)|Self::Rename(_)=>None,Self::Switch(v)=>Some(&v.candidate_index),Self::FastForward(v)=>Some(&v.candidate_index)} }
    pub(crate) fn candidate_commit(&self) -> Option<&str> { match self {Self::Files(v)=>v.candidate_commit.as_deref(),Self::Branch(_)|Self::Switch(_)|Self::Rename(_)|Self::FastForward(_)=>None} }
    pub(crate) fn reference_oid(&self) -> Option<&str> { match self {Self::Files(v) if v.action==Kind::Commit=>v.candidate_commit.as_deref(),Self::Branch(v)=>Some(&v.candidate_ref_oid),Self::FastForward(v)=>Some(&v.target_oid),_=>None} }
    pub(crate) fn fast_forward_details(&self) -> Option<&ff::Intent> {match self {Self::FastForward(v)=>Some(v),_=>None}}
    pub(crate) fn rename_details(&self) -> Option<&rename::Intent> {match self {Self::Rename(v)=>Some(v),_=>None}}
    pub(crate) fn switch_details(&self) -> Option<&switch::Intent> {match self {Self::Switch(v)=>Some(v),_=>None}}
    pub(crate) fn branch_details(&self) -> Option<&branch::Intent> { match self {Self::Branch(v)=>Some(v),_=>None} }
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::Branch(v)=>v.valid(), Self::Switch(v)=>v.valid(),Self::FastForward(v)=>v.valid(), Self::Rename(v)=>v.valid(),
            Self::Files(v)=>read::digest(&v.expected_revision) && read::digest(&v.expected_index)
                && v.expected_head.as_deref().is_none_or(read::oid) && v.expected_ref.as_deref().is_none_or(read::branch)
                && (v.expected_head.is_some() || v.expected_ref.is_some()) && match v.action {
                    Kind::Commit => v.expected_ref.is_some() && v.candidate_index.is_none()
                        && v.candidate_commit.as_deref().is_some_and(|oid|read::oid(oid)
                            && v.expected_head.as_ref().is_none_or(|h|h.len() == oid.len())),
                    Kind::Stage|Kind::Unstage => v.candidate_commit.is_none() && v.candidate_index.as_deref().is_some_and(read::digest),
                    Kind::BranchCreate|Kind::BranchSwitch|Kind::BranchRename|Kind::FastForward=>false,
                },
        }
    }
    pub(crate) fn matches(&self, review: &Review) -> bool {
        self.valid() && review.valid() && match (self,review) {
            (Self::Branch(v),Review::Branch(r))=>v.matches(r),
            (Self::Switch(v),Review::Switch(r))=>v.matches(r),
            (Self::FastForward(v),Review::FastForward(r))=>v.matches(r),
            (Self::Rename(v),Review::Rename(r))=>v.matches(r),
            (Self::Files(v),Review::Files(r))=>v.action == r.action && v.expected_revision == r.expected_revision
                && v.expected_ref == r.branch && v.expected_head == r.head && v.expected_index == r.expected_index,
            _=>false,
        }
    }
    fn decode(value:&Value) -> Result<Self,BridgeError> {
        need(if value["action"] == "fast-forward" {
            keys(value,ff::INTENT_KEYS)
        } else if value["action"] == "branch-switch" {
            keys(value,switch::INTENT_KEYS)
        } else if value["action"] == "branch-rename" {
            keys(value,rename::INTENT_KEYS)
        } else if value["action"] == "branch-create" {
            keys(value,&["action","expectedRevision","expectedReferenceRevision","expectedRef","expectedHead","expectedIndex","targetRef","expectedTargetAbsent","candidateRefOid"])
        } else { keys(value,&["action","expectedRevision","expectedRef","expectedHead","expectedIndex","candidateIndex","candidateCommit"]) })?;
        serde_json::from_value(value.clone()).map_err(|_|BridgeError::protocol())
    }
}
pub(crate) struct ApplyBinding { pub(crate) review: Review, pub(crate) journal_revision: u64 }
pub(crate) struct Request {
    pub(crate) id: String, pub(crate) action: Action, pub(crate) context: Context, pub(crate) clock: Clock,
    pub(crate) phase: Phase, pub(crate) binding: Option<ApplyBinding>, pub(crate) digest: String,
    pub(crate) native: Native, pub(crate) switch_sources:Option<switch::Sources>, pub(crate) rename_sources:Option<rename::Sources>, pub(crate) fast_forward_sources:Option<ff::Sources>, bytes: Vec<u8>,
}
impl Request {
    pub(crate) fn from_original(id: &str, action: &Action, context: &Context, native: &Native,
        clock: Clock, binding: Option<ApplyBinding>) -> Result<Self,BridgeError> {
        Self::from_sources(id,action,context,native,clock,binding,None,None,None)
    }
    /// Projection from the SAME retained native Book; never public input or a
    /// substitute for the Preparing row/current Doc/actual source checks.
    pub(crate) fn from_switch_original(id:&str,action:&Action,context:&Context,native:&Native,
        clock:Clock,binding:Option<ApplyBinding>,sources:Option<switch::Sources>)->Result<Self,BridgeError> {
        need(action.kind()==Kind::BranchSwitch)?;
        Self::from_sources(id,action,context,native,clock,binding,sources,None,None)
    }
    pub(crate) fn from_rename_original(id:&str,action:&Action,context:&Context,native:&Native,
        clock:Clock,binding:Option<ApplyBinding>,sources:Option<rename::Sources>)->Result<Self,BridgeError> {
        need(action.kind()==Kind::BranchRename)?;
        Self::from_sources(id,action,context,native,clock,binding,None,sources,None)
    }
    pub(crate) fn from_fast_forward_original(id:&str,action:&Action,context:&Context,native:&Native,
        clock:Clock,binding:Option<ApplyBinding>,sources:Option<ff::Sources>)->Result<Self,BridgeError> {
        need(action.kind()==Kind::FastForward)?;
        Self::from_sources(id,action,context,native,clock,binding,None,None,sources)
    }
    fn from_sources(id:&str,action:&Action,context:&Context,native:&Native,
        clock:Clock,binding:Option<ApplyBinding>,switch_sources:Option<switch::Sources>,rename_sources:Option<rename::Sources>,fast_forward_sources:Option<ff::Sources>)->Result<Self,BridgeError> {
        need(valid_id(id) && action.valid() && valid_id(&context.project_id) && valid_id(&context.revision)
            && native.valid() && clock.work_end_ns > 0 && clock.hard_end_ns <= i64::MAX as u64
            && clock.hard_end_ns.checked_sub(clock.work_end_ns) == Some(10_000_000_000))?;
        let phase = if let Some(selected) = &binding {
            let index = native.files.index.as_ref().map(|v|v.sha256.clone()).unwrap_or_else(||hash(b"absent"));
            need(selected.review.matches(action) && selected.review.expected_index() == index
                && (1..=u64::MAX-2).contains(&selected.journal_revision))?;
            Phase::Apply
        } else { Phase::Prepare };
        let mut value=json!({"protocol":PROTOCOL,"id":id,"phase":phase,"action":action,
            "reviewDigest":binding.as_ref().map(|s|s.review.review_digest()),
            "journalRevision":binding.as_ref().map(|s|s.journal_revision),"context":context,"native":native,"clock":clock});
        if action.kind()==Kind::BranchSwitch {
            need(match (&binding,&switch_sources) {
                (None,None)=>true,(Some(b),Some(s))=>b.review.switch_details().is_some_and(|r|s.valid(native,r)),_=>false,
            })?;
            value["switch"]=serde_json::to_value(&switch_sources).map_err(|_|BridgeError::protocol())?;
        } else {need(switch_sources.is_none())?;}
        if action.kind()==Kind::BranchRename {
            need(match (&binding,&rename_sources) {
                (None,None)=>true,(Some(b),Some(s))=>b.review.rename_details().is_some_and(|r|s.valid(native,r)),_=>false,
            })?;
            value["rename"]=serde_json::to_value(&rename_sources).map_err(|_|BridgeError::protocol())?;
        } else {need(rename_sources.is_none())?;}
        if action.kind()==Kind::FastForward {
            need(match (&binding,&fast_forward_sources) {
                (None,None)=>true,(Some(b),Some(s))=>b.review.fast_forward_details().is_some_and(|r|s.valid(native,r)),_=>false,
            })?;
            value["fastForward"]=serde_json::to_value(&fast_forward_sources).map_err(|_|BridgeError::protocol())?;
        } else {need(fast_forward_sources.is_none())?;}
        let mut bytes=serde_json::to_vec(&value).map_err(|_|BridgeError::protocol())?;
        bytes.push(b'\n'); need(bytes.len() <= REQUEST_LIMIT)?;
        let digest = hash(&bytes);
        Ok(Self {id:id.into(),action:action.clone(),context:context.clone(),clock,phase,binding,digest,native:native.clone(),switch_sources,rename_sources,fast_forward_sources,bytes})
    }
    pub(crate) fn bytes(&self) -> &[u8] { &self.bytes }
    pub(crate) fn go(&self) -> Vec<u8> { format!("MRK-GIT-LOCAL-GO/1 {}\n",self.digest).into_bytes() }
    pub(crate) fn ready(&self, bytes:&[u8]) -> Result<(),BridgeError> {
        let row = frame(bytes,READY_LIMIT)?;
        need(keys(&row,&["protocol","id","digest"]) && row["protocol"] == PROTOCOL && row["id"] == self.id && row["digest"] == self.digest)
    }
    pub(crate) fn candidate(&self, bytes:&[u8]) -> Result<Candidate,BridgeError> {
        let binding = self.binding.as_ref().ok_or_else(BridgeError::protocol)?;
        let row = frame(bytes,CANDIDATE_LIMIT)?;
        need(keys(&row,&["protocol","kind","id","digest","reviewDigest","intent"]) && row["protocol"] == PROTOCOL
            && row["kind"] == "candidate" && row["id"] == self.id && row["digest"] == self.digest
            && row["reviewDigest"] == binding.review.review_digest())?;
        let intent = Intent::decode(&row["intent"])?;
        need(intent.matches(&binding.review))?;
        Ok(Candidate {request_digest:self.digest.clone(),digest:hash(bytes),intent})
    }
    /// Only formats DATA after the original driver has joined its Store CAS
    /// and rematched Doc/consent. The codec cannot confer that permission.
    pub(crate) fn ack(&self, candidate:&Candidate, revision:u64) -> Result<Vec<u8>,BridgeError> {
        let binding = self.binding.as_ref().ok_or_else(BridgeError::protocol)?;
        need(candidate.request_digest == self.digest && candidate.intent.matches(&binding.review)
            && revision == binding.journal_revision + 1)?;
        Ok(format!("MRK-GIT-LOCAL-ACK/1 {} {} {}\n",self.digest,candidate.digest,revision).into_bytes())
    }
    pub(crate) fn terminal(&self, bytes:&[u8], candidate:Option<&Candidate>) -> Result<Terminal,BridgeError> {
        if let Some(candidate) = candidate {
            let binding = self.binding.as_ref().ok_or_else(BridgeError::protocol)?;
            need(candidate.request_digest == self.digest && candidate.intent.matches(&binding.review))?;
        }
        let row = frame(bytes,RESPONSE_LIMIT-READY_LIMIT-CANDIDATE_LIMIT)?;
        need(keys(&row,&["protocol","kind","id","digest","phase","action","status","reason","result","publication","firstFailureNs","cleanupEndNs"])
            && row["protocol"] == PROTOCOL && row["kind"] == "terminal" && row["id"] == self.id && row["digest"] == self.digest)?;
        let terminal:Terminal = serde_json::from_value(row).map_err(|_|BridgeError::protocol())?;
        need(terminal.phase == self.phase && terminal.action == self.action.kind() && terminal.cleanup_end_ns > 0
            && terminal.cleanup_end_ns <= self.clock.hard_end_ns)?;
        if let Some(first) = terminal.first_failure_ns {
            need(first > 0 && first <= terminal.cleanup_end_ns && terminal.cleanup_end_ns-first <= 10_000_000_000)?;
        }
        if terminal.status != read::Outcome::Ok {
            need(terminal.reason.as_deref().is_some_and(|v|self.reason(v)) && terminal.result.is_null()
                && terminal.publication == Publication::NotReported
                && (terminal.first_failure_ns.is_some() || terminal.status == read::Outcome::CleanupUnknown))?;
        } else {
            need(terminal.reason.is_none())?;
            if self.phase == Phase::Prepare {
                need(candidate.is_none() && terminal.first_failure_ns.is_none() && terminal.cleanup_end_ns == self.clock.hard_end_ns
                    && terminal.publication == Publication::NotReported
                    && keys(&terminal.result,if matches!(self.action.kind(),Kind::BranchCreate|Kind::BranchSwitch|Kind::BranchRename|Kind::FastForward) {&["review"]} else {&["review","diff"]}))?;
                let review = Review::decode(&terminal.result["review"])?;
                need(review.matches(&self.action))?;
                if let Some(review) = review.file() {
                    read::validate_result(&read::Action {kind:read::Kind::Diff,expected_revision:Some(review.expected_revision.clone()),
                        paths:review.paths.clone(),staged:self.action.kind() != Kind::Stage},&terminal.result["diff"])?;
                }
            } else { self.validate_applied(&terminal,candidate)?; }
        }
        Ok(terminal)
    }
    fn reason(&self,value:&str)->bool {read::reason(value) || self.action.kind()==Kind::BranchCreate && branch::reason(value)
        || self.action.kind()==Kind::BranchSwitch && switch::reason(value)
        || self.action.kind()==Kind::BranchRename && rename::reason(value)
        || self.action.kind()==Kind::FastForward && ff::reason(value)}
    fn validate_applied(&self, terminal:&Terminal, candidate:Option<&Candidate>) -> Result<(),BridgeError> {
        let r = &terminal.result;
        need(keys(r,if self.action.kind()==Kind::FastForward {ff::RESULT_KEYS}
            else if self.action.kind()==Kind::BranchSwitch {switch::RESULT_KEYS}
            else if self.action.kind()==Kind::BranchRename {rename::RESULT_KEYS}
            else {&["operationId","action","state","settlement","reason","observation","intent"]})
            && r["operationId"] == self.id && r["action"] == json!(self.action.kind()) && r["settlement"] == "settled")?;
        let state = r["state"].as_str().ok_or_else(BridgeError::protocol)?;
        need(matches!(state,"succeeded"|"failed"|"recovery-required"))?;
        if r["intent"].is_null() { need(candidate.is_none() && terminal.publication == Publication::NotReported)?; }
        else {
            let candidate = candidate.ok_or_else(BridgeError::protocol)?;
            let intent = Intent::decode(&r["intent"])?;
            need(candidate.request_digest == self.digest && intent == candidate.intent)?;
        }
        if self.action.kind()==Kind::FastForward {return ff::validate_applied(self,terminal,candidate)}
        if self.action.kind()==Kind::BranchSwitch {return switch::validate_applied(self,terminal,candidate)}
        if self.action.kind()==Kind::BranchRename {return rename::validate_applied(self,terminal,candidate)}
        if terminal.publication != Publication::NotReported {
            need(candidate.is_some() && terminal.publication == match self.action.kind() {
                Kind::Commit=>Publication::RefReturned,Kind::BranchCreate=>Publication::BranchRefReturned,
                Kind::Stage|Kind::Unstage=>Publication::IndexReturned,
                Kind::BranchSwitch|Kind::BranchRename|Kind::FastForward=>return Err(BridgeError::protocol()),
            })?;
        }
        if state == "succeeded" {
            need(terminal.publication != Publication::NotReported && r["reason"].is_null() && read::observation(&r["observation"])
                && terminal.first_failure_ns.is_none() && terminal.cleanup_end_ns == self.clock.hard_end_ns)?;
            let candidate = candidate.ok_or_else(BridgeError::protocol)?;
            need(r["observation"]["branch"] == json!(candidate.intent.expected_ref())
                && r["observation"]["head"] == json!(if self.action.kind() == Kind::Commit {candidate.intent.candidate_commit()} else {candidate.intent.expected_head()}))?;
        } else {
            need(r["reason"].as_str().is_some_and(|v|self.reason(v)) && r["observation"].is_null() && terminal.first_failure_ns.is_some())?;
        }
        Ok(())
    }
}
pub(crate) struct Candidate { request_digest:String, pub(crate) digest:String, pub(crate) intent:Intent }
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="kebab-case")]
pub(crate) enum Publication { NotReported, IndexReturned, RefReturned, BranchRefReturned,
    SwitchCheckoutReturned, SwitchLogReturned, SwitchHeadReturned, SwitchIndexReturned,
    RenameNewLogReturned, RenameOldLogReturned, RenameRefReturned, RenameHeadLogReturned, RenameHeadReturned, RenameConfigReturned, FfWorktreeReturned, FfIndexReturned, FfRefReturned }
#[derive(Clone, Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Terminal {
    protocol:String, kind:String, id:String, digest:String,
    pub(crate) phase:Phase, pub(crate) action:Kind, pub(crate) status:read::Outcome, pub(crate) reason:Option<String>,
    pub(crate) result:Value, pub(crate) publication:Publication, pub(crate) first_failure_ns:Option<u64>, pub(crate) cleanup_end_ns:u64,
}
impl Terminal {
    pub(crate) fn child_declared_settled(&self) -> bool {
        self.status != read::Outcome::CleanupUnknown && self.reason.as_deref() != Some("unknown")
            && self.result["reason"] != "unknown"
    }
    pub(crate) fn review(&self) -> Result<Review,BridgeError> {
        need(self.phase == Phase::Prepare && self.status == read::Outcome::Ok)?;
        Review::decode(&self.result["review"])
    }
}

// Same operation-only progress vocabulary as GitRead. No public draft/native
// snapshot/Store grant, and no child terminal can mint Settled or a review ID.
#[derive(Clone, Serialize)]
#[serde(rename_all="camelCase")]
pub(crate) struct Projection {
    pub(crate) operation_id:String, pub(crate) context:Context, pub(crate) phase:Phase, pub(crate) action:PublicAction,
    pub(crate) stage:read::Phase, pub(crate) outcome:Option<read::Outcome>, pub(crate) reason:Option<String>, pub(crate) result:Value,
}
#[derive(Clone, Serialize)]
#[serde(rename_all="camelCase")]
pub(crate) struct Prepared {
    pub(crate) review_id:String, pub(crate) context:Context, pub(crate) action:PublicAction,
    pub(crate) review:Review,
    #[serde(skip_serializing_if="Option::is_none")]
    pub(crate) diff:Option<Value>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all="camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version:u8, pub(crate) document_revision:u32, pub(crate) available:bool,
    pub(crate) review:Option<Prepared>, pub(crate) operation:Option<Projection>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all="camelCase")]
pub(crate) struct StartRequest {
    pub(crate) phase:Phase, pub(crate) project_id:String, pub(crate) expected_document_revision:u32,
    pub(crate) action:Option<PublicAction>, pub(crate) review_id:Option<String>,
}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
pub(crate) struct StartResult {
    pub(crate) schema_version:u8, pub(crate) admission:read::Admission, pub(crate) request:StartRequest,
    pub(crate) status:Status, pub(crate) reason:Option<read::StartRefusal>,
}

#[cfg(test)]
#[path="git_local_protocol_tests.rs"]
mod tests;
