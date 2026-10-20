//! Fixed local Git DATA, not a process/source/publisher/Store authority.
//! Draft author/message stay private; public projections contain only bounded
//! review/intent facts. Child publication and terminal frames never settle the
//! original native invocation. No serialized plan is accepted for execution.
use crate::{error::BridgeError, git_read_protocol as read, protocol::{strict_json, valid_id}};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

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
pub(crate) enum Kind { Stage, Unstage, Commit }
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
// projection containing this type. Core retains its stricter secret heuristic.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Action {
    pub(crate) kind: Kind,
    pub(crate) expected_revision: String,
    pub(crate) paths: Vec<String>,
    message: Option<String>,
    identity: Option<Identity>,
}
impl Action {
    pub(crate) fn valid(&self) -> bool {
        read::digest(&self.expected_revision) && match self.kind {
            Kind::Commit => self.paths.is_empty()
                && self.identity.as_ref().is_some_and(Identity::valid)
                && self.message.as_ref().is_some_and(|m| !m.trim().is_empty() && read::text(m,4096,true) && !m.contains('\r')),
            _ => paths(&self.paths) && self.message.is_none() && self.identity.is_none(),
        }
    }
    pub(crate) fn public(&self) -> PublicAction {
        PublicAction {kind:self.kind,expected_revision:self.expected_revision.clone(),paths:self.paths.clone()}
    }
}
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase")]
pub(crate) struct PublicAction { pub(crate) kind:Kind, pub(crate) expected_revision:String, pub(crate) paths:Vec<String> }
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
            && keys(&body["action"],&["kind","expectedRevision","paths","message","identity"]),
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
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Review {
    pub(crate) action: Kind, pub(crate) expected_revision: String, pub(crate) paths: Vec<String>,
    pub(crate) whole_index: bool, pub(crate) head: Option<String>, pub(crate) branch: Option<String>,
    pub(crate) expected_index: String, pub(crate) review_digest: String,
}
impl Review {
    pub(crate) fn valid(&self) -> bool {
        read::digest(&self.expected_revision) && read::digest(&self.expected_index) && read::digest(&self.review_digest)
            && paths(&self.paths) && self.whole_index == (self.action == Kind::Commit)
            && self.head.as_deref().is_none_or(read::oid) && self.branch.as_deref().is_none_or(read::branch)
            && (self.head.is_some() || self.branch.is_some()) && (self.action != Kind::Commit || self.branch.is_some())
    }
    fn matches(&self, action: &Action) -> bool {
        self.valid() && self.action == action.kind && self.expected_revision == action.expected_revision
            && (action.kind == Kind::Commit || self.paths == action.paths)
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Intent {
    pub(crate) action: Kind, pub(crate) expected_revision: String, pub(crate) expected_ref: Option<String>,
    pub(crate) expected_head: Option<String>, pub(crate) expected_index: String,
    pub(crate) candidate_index: Option<String>, pub(crate) candidate_commit: Option<String>,
}
impl Intent {
    pub(crate) fn valid(&self) -> bool {
        read::digest(&self.expected_revision) && read::digest(&self.expected_index)
            && self.expected_head.as_deref().is_none_or(read::oid) && self.expected_ref.as_deref().is_none_or(read::branch)
            && (self.expected_head.is_some() || self.expected_ref.is_some()) && match self.action {
                Kind::Commit => self.expected_ref.is_some() && self.candidate_index.is_none()
                    && self.candidate_commit.as_deref().is_some_and(|v|read::oid(v)
                        && self.expected_head.as_ref().is_none_or(|h|h.len() == v.len())),
                _ => self.candidate_commit.is_none() && self.candidate_index.as_deref().is_some_and(read::digest),
            }
    }
    pub(crate) fn matches(&self, review: &Review) -> bool {
        self.valid() && self.action == review.action && self.expected_revision == review.expected_revision
            && self.expected_ref == review.branch && self.expected_head == review.head && self.expected_index == review.expected_index
    }
}
pub(crate) struct ApplyBinding { pub(crate) review: Review, pub(crate) journal_revision: u64 }
pub(crate) struct Request {
    pub(crate) id: String, pub(crate) action: Action, pub(crate) context: Context, pub(crate) clock: Clock,
    pub(crate) phase: Phase, pub(crate) binding: Option<ApplyBinding>, pub(crate) digest: String,
    pub(crate) native: Native, bytes: Vec<u8>,
}
impl Request {
    pub(crate) fn from_original(id: &str, action: &Action, context: &Context, native: &Native,
        clock: Clock, binding: Option<ApplyBinding>) -> Result<Self,BridgeError> {
        need(valid_id(id) && action.valid() && valid_id(&context.project_id) && valid_id(&context.revision)
            && native.valid() && clock.work_end_ns > 0 && clock.hard_end_ns <= i64::MAX as u64
            && clock.hard_end_ns.checked_sub(clock.work_end_ns) == Some(10_000_000_000))?;
        let phase = if let Some(selected) = &binding {
            let index = native.files.index.as_ref().map(|v|v.sha256.clone()).unwrap_or_else(||hash(b"absent"));
            need(selected.review.matches(action) && selected.review.expected_index == index
                && (1..=u64::MAX-2).contains(&selected.journal_revision))?;
            Phase::Apply
        } else { Phase::Prepare };
        let mut bytes = serde_json::to_vec(&json!({"protocol":PROTOCOL,"id":id,"phase":phase,"action":action,
            "reviewDigest":binding.as_ref().map(|s|&s.review.review_digest),
            "journalRevision":binding.as_ref().map(|s|s.journal_revision),"context":context,"native":native,"clock":clock}))
            .map_err(|_|BridgeError::protocol())?;
        bytes.push(b'\n'); need(bytes.len() <= REQUEST_LIMIT)?;
        let digest = hash(&bytes);
        Ok(Self {id:id.into(),action:action.clone(),context:context.clone(),clock,phase,binding,digest,native:native.clone(),bytes})
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
            && row["reviewDigest"] == binding.review.review_digest)?;
        let intent:Intent = serde_json::from_value(row["intent"].clone()).map_err(|_|BridgeError::protocol())?;
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
        need(terminal.phase == self.phase && terminal.action == self.action.kind && terminal.cleanup_end_ns > 0
            && terminal.cleanup_end_ns <= self.clock.hard_end_ns)?;
        if let Some(first) = terminal.first_failure_ns {
            need(first > 0 && first <= terminal.cleanup_end_ns && terminal.cleanup_end_ns-first <= 10_000_000_000)?;
        }
        if terminal.status != read::Outcome::Ok {
            need(terminal.reason.as_deref().is_some_and(read::reason) && terminal.result.is_null()
                && terminal.publication == Publication::NotReported
                && (terminal.first_failure_ns.is_some() || terminal.status == read::Outcome::CleanupUnknown))?;
        } else {
            need(terminal.reason.is_none())?;
            if self.phase == Phase::Prepare {
                need(candidate.is_none() && terminal.first_failure_ns.is_none() && terminal.cleanup_end_ns == self.clock.hard_end_ns
                    && terminal.publication == Publication::NotReported && keys(&terminal.result,&["review","diff"]))?;
                let review:Review = serde_json::from_value(terminal.result["review"].clone()).map_err(|_|BridgeError::protocol())?;
                need(review.matches(&self.action))?;
                read::validate_result(&read::Action {kind:read::Kind::Diff,expected_revision:Some(review.expected_revision),
                    paths:review.paths,staged:self.action.kind != Kind::Stage},&terminal.result["diff"])?;
            } else { self.validate_applied(&terminal,candidate)?; }
        }
        Ok(terminal)
    }
    fn validate_applied(&self, terminal:&Terminal, candidate:Option<&Candidate>) -> Result<(),BridgeError> {
        let r = &terminal.result;
        need(keys(r,&["operationId","action","state","settlement","reason","observation","intent"])
            && r["operationId"] == self.id && r["action"] == json!(self.action.kind) && r["settlement"] == "settled")?;
        let state = r["state"].as_str().ok_or_else(BridgeError::protocol)?;
        need(matches!(state,"succeeded"|"failed"|"recovery-required"))?;
        if r["intent"].is_null() { need(candidate.is_none() && terminal.publication == Publication::NotReported)?; }
        else {
            let candidate = candidate.ok_or_else(BridgeError::protocol)?;
            let intent:Intent = serde_json::from_value(r["intent"].clone()).map_err(|_|BridgeError::protocol())?;
            need(candidate.request_digest == self.digest && intent == candidate.intent)?;
        }
        if terminal.publication != Publication::NotReported {
            need(candidate.is_some() && terminal.publication == if self.action.kind == Kind::Commit {Publication::RefReturned} else {Publication::IndexReturned})?;
        }
        if state == "succeeded" {
            need(terminal.publication != Publication::NotReported && r["reason"].is_null() && read::observation(&r["observation"])
                && terminal.first_failure_ns.is_none() && terminal.cleanup_end_ns == self.clock.hard_end_ns)?;
            let candidate = candidate.ok_or_else(BridgeError::protocol)?;
            need(r["observation"]["branch"] == json!(candidate.intent.expected_ref)
                && r["observation"]["head"] == json!(if self.action.kind == Kind::Commit {&candidate.intent.candidate_commit} else {&candidate.intent.expected_head}))?;
        } else {
            need(r["reason"].as_str().is_some_and(read::reason) && r["observation"].is_null() && terminal.first_failure_ns.is_some())?;
        }
        Ok(())
    }
}
pub(crate) struct Candidate { request_digest:String, pub(crate) digest:String, pub(crate) intent:Intent }
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="kebab-case")]
pub(crate) enum Publication { NotReported, IndexReturned, RefReturned }
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
        serde_json::from_value(self.result["review"].clone()).map_err(|_|BridgeError::protocol())
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
    pub(crate) review:Review, pub(crate) diff:Value,
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
