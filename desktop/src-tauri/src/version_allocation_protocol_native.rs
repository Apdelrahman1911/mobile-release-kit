//! Fixed private allocation dialogue, a child of the original state port.
//!
//! Uses that port's existing typed state/row codec; no second allocator, file
//! opener, candidate selector, general byte writer, credential or GO authority.
//! The Supervisor must retain/join the actual state job and rematch the original
//! Document admission before releasing an ACK. Parsed frames prove none of that.
use super::{canonical, closed, decode, hash, hex, observation_shape, Authority, Checkpoint,
    Pending, Request as AllocationRequest, Reservation, Revision, StateError, Transition,
    VersionAllocationStatePort, WriteAck};
use crate::{application_service::ProjectBinding, application_state_store::PrivateStateDirectory,
    error::BridgeError, github_connection_protocol::{bounds, numeric_id, GitHubReadControl},
    metadata_images_edit_protocol::base64, protocol::{strict_json, valid_id}};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use zeroize::Zeroizing;

pub(crate) const PROTOCOL: &str = "mrk-version-allocation-runtime/1";
pub(crate) const INITIAL_LIMIT: usize = 8192;
pub(crate) const READY_LIMIT: usize = 512;
pub(crate) const REQUEST_LIMIT: usize = 16 * 1024;
pub(crate) const OBSERVATIONS_LIMIT: usize = 4096;
pub(crate) const TOKEN_LIMIT: usize = 4096;
pub(crate) const STATE_LIMIT: usize = 1024 * 1024;
pub(crate) const STATE_BASE64_LIMIT: usize = 4 * ((STATE_LIMIT + 2) / 3);
pub(crate) const GO_LIMIT: usize = STATE_BASE64_LIMIT + REQUEST_LIMIT + OBSERVATIONS_LIMIT + 2 * TOKEN_LIMIT + 1024;
pub(crate) const TRANSITION_LIMIT: usize = 16 * 1024 + 512;
pub(crate) const STATE_FRAME_LIMIT: usize = TRANSITION_LIMIT + 1024;
pub(crate) const ACK_LIMIT: usize = 1024;
pub(crate) const FIN_LIMIT: usize = 32 * 1024;
pub(crate) const MAX_TRANSITIONS: u8 = 5;
// Total framed traffic, not Rust/CPython DOM, allocator or process RSS limits.
pub(crate) const INPUT_TOTAL_LIMIT: usize = INITIAL_LIMIT + GO_LIMIT + MAX_TRANSITIONS as usize * ACK_LIMIT;
pub(crate) const OUTPUT_TOTAL_LIMIT: usize = READY_LIMIT + MAX_TRANSITIONS as usize * STATE_FRAME_LIMIT + FIN_LIMIT;
pub(crate) const WORK_SECONDS: u64 = 60;
pub(crate) const HARD_SECONDS: u64 = 70;
type Result<T> = std::result::Result<T, BridgeError>;

fn require(value: bool) -> Result<()> { if value { Ok(()) } else { Err(BridgeError::protocol()) } }
fn data<T>(value: std::result::Result<T, StateError>) -> Result<T> { value.map_err(|_| BridgeError::protocol()) }
fn digest(raw: &[u8]) -> String { format!("{:x}", Sha256::digest(raw)) }
fn encoded<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>> {
    let mut raw = data(canonical(value, maximum - 1))?; raw.push(b'\n'); Ok(raw)
}
fn frame(raw: &[u8], maximum: usize) -> Result<Value> {
    require(raw.len() > 1 && raw.len() <= maximum && raw.last() == Some(&b'\n')
        && raw.iter().filter(|b| **b == b'\n').count() == 1 && !raw.contains(&b'\r'))?;
    let value = strict_json(&raw[..raw.len() - 1])?;
    require(bounds(&value, maximum - 1, 2048, 16) && encoded(&value, maximum)? == raw)?;
    Ok(value)
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Kind { Reserve, Reconcile }
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Clock { name: &'static str, work_end_ns: String, hard_end_ns: String }
impl Clock {
    /// Endpoint DATA from the original native ClockBridge, not a new timer.
    pub(crate) fn new(work: u64, hard: u64) -> Result<Self> {
        require(work != 0 && hard.checked_sub(work).is_some_and(|n| n <= 10_000_000_000))?;
        Ok(Self { name: "CLOCK_UPTIME_RAW", work_end_ns: work.to_string(), hard_end_ns: hard.to_string() })
    }
}

/// Pure snapshot of an ALREADY loaded, enrolled and selected native port.
/// No token is retained here. Only the GO buffer briefly contains its borrowed
/// value, on Zeroizing backing; Rust never clones it into a serde Value/String.
pub(crate) struct Request {
    id: String, kind: Kind, authority: Authority, local_project_id: String,
    store: Arc<PrivateStateDirectory>, project: ProjectBinding,
    selected: AllocationRequest, initial: Vec<u8>, initial_digest: String,
    initial_revision: Revision, initial_state_sha256: String,
    go_prefix: Vec<u8>, go_suffix: Vec<u8>,
}
impl Request {
    pub(crate) fn from_port(port: &VersionAllocationStatePort, id: &str, kind: Kind,
        account_id: &str, clock: Clock, observations: &[Value]) -> Result<Self> {
        require(valid_id(id) && numeric_id(account_id) && observations.len() <= 2
            && observations.iter().all(observation_shape))?;
        let selected = AllocationRequest(data(port.selected_request())?.clone());
        let row = data(port.enrolled())?;
        require((kind == Kind::Reconcile) == row.pending.is_some()
            && row.pending.as_ref().is_none_or(|p| p.reservation.request == selected))?;
        let snapshot = data(port.snapshot())?;
        require(!snapshot.bytes.is_empty() && snapshot.bytes.len() <= STATE_LIMIT)?;
        let authority = port.authority.clone();
        let local_project_id = port.project.project_id.as_str().to_owned();
        let initial = encoded(&json!({"protocol":PROTOCOL,"id":id,"action":{
            "kind":kind,"localProjectId":local_project_id,"authority":authority,"accountId":account_id,
            "candidateId":selected.candidate(),"requestSha256":data(hash(b"mrk:allocation-request:1\0", &selected))?,"clock":clock}}), INITIAL_LIMIT)?;
        let initial_digest = digest(&initial);
        let public = json!({"observations":observations,"request":selected,
            "requestSha256":initial_digest,"state":{"revision":snapshot.revision.0,"payload":base64(&snapshot.bytes)?}});
        data(canonical(&observations, OBSERVATIONS_LIMIT))?;
        data(canonical(&selected, REQUEST_LIMIT))?;
        // These exact sorted fields precede token in Python's canonical GO.
        let mut go_prefix = b"{\"go\":".to_vec();
        let mut public = data(canonical(&public, GO_LIMIT - 2 * TOKEN_LIMIT - 256))?;
        require(public.pop() == Some(b'}'))?;
        go_prefix.extend(public); go_prefix.extend(b",\"token\":");
        let go_suffix = format!("}},\"id\":\"{id}\",\"protocol\":\"{PROTOCOL}\"}}\n").into_bytes();
        require(go_prefix.len().checked_add(2 * TOKEN_LIMIT + 2).and_then(|n| n.checked_add(go_suffix.len()))
            .is_some_and(|n| n <= GO_LIMIT))?;
        Ok(Self { id:id.to_owned(), kind, authority, local_project_id, store:port.store.clone(), project:port.project.clone(),
            selected, initial, initial_digest,
            initial_revision:snapshot.revision, initial_state_sha256:digest(&snapshot.bytes), go_prefix, go_suffix })
    }
    pub(crate) fn initial(&self) -> &[u8] { &self.initial }
    pub(crate) fn initial_digest(&self) -> &str { &self.initial_digest }
    pub(crate) fn selected(&self) -> &Value { &self.selected.0 }
    pub(crate) fn kind(&self) -> Kind { self.kind }
    pub(crate) fn ready(&self, raw: &[u8]) -> Result<()> {
        let value = frame(raw, READY_LIMIT)?;
        require(value == json!({"protocol":PROTOCOL,"id":self.id,"ready":{"requestSha256":self.initial_digest}}))
    }
    /// Called only from the native token/GO gate. Its successful return is still
    /// bytes, not permission; the original owner separately claims and writes.
    pub(crate) fn go(&self, token: &str) -> Result<Zeroizing<Vec<u8>>> {
        require(!token.is_empty() && token.len() <= TOKEN_LIMIT && token.bytes().all(|b| (0x21..=0x7e).contains(&b)))?;
        let mut raw = Zeroizing::new(Vec::new());
        raw.try_reserve_exact(self.go_prefix.len() + token.len() * 2 + 2 + self.go_suffix.len())
            .map_err(|_| BridgeError::invalid())?;
        raw.extend_from_slice(&self.go_prefix);
        serde_json::to_writer(&mut *raw, token).map_err(|_| BridgeError::protocol())?;
        raw.extend_from_slice(&self.go_suffix);
        require(raw.len() <= GO_LIMIT)?; Ok(raw)
    }
    pub(crate) fn matches_port(&self, port: &VersionAllocationStatePort) -> bool {
        port.matches_native_binding(&self.store, &self.project) && port.authority == self.authority
            && port.project.project_id.as_str() == self.local_project_id
            && port.admit_request(&self.selected.0).is_ok()
    }
    pub(crate) fn matches_initial_port(&self, port: &VersionAllocationStatePort) -> bool {
        self.matches_port(port) && port.snapshot().is_ok_and(|s| s.revision == self.initial_revision
            && digest(&s.bytes) == self.initial_state_sha256)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum StepKind { Checkpoint, Pending, Rejected, Resolved, Reused }
pub(crate) struct Step {
    pub(crate) sequence: u8, pub(crate) expected_revision: Revision,
    pub(crate) payload_sha256: String, request_digest: String, kind: StepKind, change: Value,
}
impl Step {
    pub(crate) fn kind(&self) -> StepKind { self.kind }
    pub(crate) fn matches_request(&self, request: &Request) -> bool { self.request_digest == request.initial_digest }
    pub(crate) fn transition(&self) -> Transition {
        match self.kind {
            StepKind::Checkpoint => Transition::Checkpoint(self.change["checkpoint"].clone()),
            StepKind::Pending => Transition::Pending(self.change["pending"].clone()),
            StepKind::Rejected => Transition::Rejected(self.change["pending"].clone()),
            StepKind::Resolved => Transition::Resolved { pending:self.change["pending"].clone(), checkpoint:self.change["checkpoint"].clone() },
            StepKind::Reused => Transition::Reused { reservation:self.change["reservation"].clone(), checkpoint:self.change["checkpoint"].clone() },
        }
    }
    /// Compare the actual returned native ACK before encoding any success. No
    /// boolean or worker echo stands in for the original `port.apply` return.
    pub(crate) fn ack(&self, request: &Request, ack: &WriteAck) -> Result<Vec<u8>> {
        require(self.request_digest == request.initial_digest && self.expected_revision.0.checked_add(1) == Some(ack.revision.0)
            && self.payload_sha256 == ack.payload_sha256)?;
        encoded(&json!({"protocol":PROTOCOL,"id":request.id,"ack":{"requestSha256":request.initial_digest,
            "sequence":self.sequence,"revision":ack.revision.0,"payloadSha256":ack.payload_sha256,
            "effect":"committed","durability":"durable","cleanup":"settled"}}), ACK_LIMIT)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage { Reading, Pending, Terminal }
/// One stdout cursor, never a second prefetch/reader. It is held by the original
/// Supervisor dialogue. A parsed Step is outstanding until its joined ACK is
/// accepted; an error latches the cursor rather than reopening/retrying it.
pub(crate) struct Cursor {
    request_digest: String, sequence: u8, revision: Revision, state_sha256: String, stage: Stage,
    pending_started: bool, outstanding: Option<Arc<Step>>, poisoned: bool, finished: bool,
}
impl Cursor {
    pub(crate) fn new(request: &Request) -> Self {
        Self { request_digest:request.initial_digest.clone(), sequence:0, revision:request.initial_revision, state_sha256:request.initial_state_sha256.clone(),
            stage:if request.kind == Kind::Reconcile { Stage::Pending } else { Stage::Reading },
            pending_started:request.kind == Kind::Reconcile, outstanding:None, poisoned:false, finished:false }
    }
    pub(crate) fn step(&mut self, request: &Request, raw: &[u8]) -> Result<Arc<Step>> {
        let usable = !self.poisoned && self.outstanding.is_none() && !self.finished && self.stage != Stage::Terminal;
        self.poisoned = true; require(usable && self.request_digest == request.initial_digest)?;
        let value = frame(raw, STATE_FRAME_LIMIT)?;
        require(closed(&value, &["protocol","id","state"]) && value["protocol"] == PROTOCOL && value["id"] == request.id)?;
        let state = &value["state"];
        require(closed(state, &["requestSha256","sequence","expectedRevision","payloadSha256","transition"])
            && state["requestSha256"] == request.initial_digest && self.sequence < MAX_TRANSITIONS
            && state["sequence"].as_u64() == Some(self.sequence as u64 + 1)
            && state["expectedRevision"].as_u64() == Some(self.revision.0) && self.revision.0 != u64::MAX)?;
        let payload_sha256 = state["payloadSha256"].as_str().filter(|s| hex(s,64)).ok_or_else(BridgeError::protocol)?.to_owned();
        let change = &state["transition"];
        let kind = match change["kind"].as_str() {
            Some("checkpoint") => { require(closed(change,&["kind","checkpoint"]))?; StepKind::Checkpoint },
            Some("pending") => { require(closed(change,&["kind","pending"]))?; StepKind::Pending },
            Some("rejected") => { require(closed(change,&["kind","pending"]))?; StepKind::Rejected },
            Some("resolved") => { require(closed(change,&["kind","pending","checkpoint"]))?; StepKind::Resolved },
            Some("reused") => { require(closed(change,&["kind","reservation","checkpoint"]))?; StepKind::Reused },
            _ => return Err(BridgeError::protocol()),
        };
        if let Some(value) = change.get("checkpoint") { let checkpoint:Checkpoint = data(decode(value.clone()))?; require(checkpoint.valid())?; }
        if let Some(value) = change.get("pending") {
            let pending:Pending = data(decode(value.clone()))?; data(pending.valid())?;
            require(pending.authority == request.authority && pending.reservation.request == request.selected)?;
        }
        if let Some(value) = change.get("reservation") {
            let reservation:Reservation = data(decode(value.clone()))?; data(reservation.valid())?;
            require(reservation.request == request.selected)?;
        }
        require(match kind {
            StepKind::Checkpoint => true,
            StepKind::Pending => request.kind == Kind::Reserve && self.stage == Stage::Reading && !self.pending_started,
            StepKind::Rejected => request.kind == Kind::Reserve && self.stage == Stage::Pending,
            StepKind::Resolved => self.stage == Stage::Pending,
            StepKind::Reused => request.kind == Kind::Reserve && self.stage == Stage::Reading && !self.pending_started,
        })?;
        data(canonical(change, TRANSITION_LIMIT))?;
        let step = Arc::new(Step { sequence:self.sequence+1, expected_revision:self.revision, payload_sha256,
            request_digest:request.initial_digest.clone(), kind, change:change.clone() });
        self.outstanding = Some(step.clone()); self.poisoned = false; Ok(step)
    }
    /// Original native job join is a separate Supervisor prerequisite. Passing
    /// a WriteAck manually to this DATA codec never creates that join/GO proof.
    pub(crate) fn applied(&mut self, request: &Request, step: &Arc<Step>, ack: &WriteAck) -> Result<Vec<u8>> {
        let usable = !self.poisoned && self.outstanding.as_ref().is_some_and(|original| Arc::ptr_eq(original,step)) && !self.finished;
        self.poisoned = true; require(usable && self.request_digest == request.initial_digest)?;
        require(step.sequence == self.sequence + 1 && step.expected_revision == self.revision)?;
        let raw = step.ack(request, ack)?;
        self.sequence = step.sequence; self.revision = ack.revision; self.state_sha256 = ack.payload_sha256.clone();
        match step.kind {
            StepKind::Checkpoint => {},
            StepKind::Pending => { self.pending_started = true; self.stage = Stage::Pending; },
            StepKind::Rejected | StepKind::Resolved | StepKind::Reused => self.stage = Stage::Terminal,
        }
        self.outstanding = None; self.poisoned = false; Ok(raw)
    }
    pub(crate) fn stop(&mut self) { self.poisoned = true; }
    pub(crate) fn finish(&mut self, request: &Request, port: &VersionAllocationStatePort, raw: &[u8]) -> Result<Finished> {
        let usable = !self.poisoned && self.outstanding.is_none() && !self.finished;
        self.poisoned = true; require(usable && self.request_digest == request.initial_digest)?;
        require(request.matches_port(port))?;
        let value = frame(raw, FIN_LIMIT)?;
        require(closed(&value,&["protocol","id","finished"]) && value["protocol"] == PROTOCOL && value["id"] == request.id)?;
        let row = &value["finished"];
        require(closed(row,&["requestSha256","sequence","revision","payloadSha256","outcome"])
            && row["requestSha256"] == request.initial_digest && row["sequence"].as_u64() == Some(self.sequence as u64)
            && row["revision"].as_u64() == Some(self.revision.0) && row["payloadSha256"] == self.state_sha256)?;
        let snapshot = data(port.snapshot())?;
        require(snapshot.revision == self.revision && digest(&snapshot.bytes) == self.state_sha256)?;
        let outcome = &row["outcome"];
        require(closed(outcome,&["schemaVersion","status","reason","reservation","checkpoint","writeClaimed","writeAcknowledged","control","releaseEligibility","assurance"])
            && outcome["schemaVersion"].as_u64() == Some(1) && outcome["releaseEligibility"] == "not-established"
            && outcome["assurance"] == "repository-allocation-data-not-native-finality")?;
        let status = outcome["status"].as_str().ok_or_else(BridgeError::protocol)?;
        require(["reserved","conflict","rejected","unavailable","recovery-required"].contains(&status)
            && outcome["reason"].as_str().is_some_and(reason))?;
        let claimed = outcome["writeClaimed"].as_bool().ok_or_else(BridgeError::protocol)?;
        let acknowledged = outcome["writeAcknowledged"].as_bool().ok_or_else(BridgeError::protocol)?;
        require(!acknowledged || claimed)?;
        require(!claimed || request.kind == Kind::Reserve && self.pending_started)?;
        let control:GitHubReadControl = serde_json::from_value(outcome["control"].clone()).map_err(|_| BridgeError::protocol())?;
        require(control.valid())?;
        let local = data(port.enrolled())?;
        let checkpoint = if outcome["checkpoint"].is_null() { None } else { let row:Checkpoint = data(decode(outcome["checkpoint"].clone()))?; require(row.valid())?; Some(row) };
        require((status == "reserved") == !outcome["reservation"].is_null()
            && (status == "reserved") == (outcome["reason"] == "none")
            && checkpoint.as_ref().is_none_or(|c| c == &local.checkpoint))?;
        if status == "reserved" {
            require(control.reason == crate::github_connection_protocol::Reason::None)?;
            let reservation:Reservation = data(decode(outcome["reservation"].clone()))?; data(reservation.valid())?;
            let candidate = data(port.state())?.candidate(&request.local_project_id).ok_or_else(BridgeError::protocol)?;
            require(outcome["reason"] == "none" && reservation.request == request.selected && local.pending.is_none()
                && checkpoint.as_ref() == Some(&local.checkpoint) && candidate.reservation.as_ref() == Some(&reservation)
                && self.stage == Stage::Terminal)?;
        }
        self.finished = true; self.poisoned = false;
        Ok(Finished { outcome:outcome.clone(), control })
    }
}

/// Private worker DATA only, before stdin shutdown/stdout EOF and actual joins.
/// Never serialize this as a public success or feed its reservation to an edit
/// without the current original RELEASE_VERSION checkout and explicit Apply.
pub(crate) struct Finished { pub(crate) outcome:Value, pub(crate) control:GitHubReadControl }
fn reason(value: &str) -> bool {
    matches!(value,"none"|"invalid-input"|"invalid-policy"|"manual-policy"|"ambiguous-rule"|"ref-not-allowed"
        |"unsupported-version"|"build-exhausted"|"ios-integer-build-exhausted"|"store-observation-incomplete"
        |"store-observation-stale"|"store-identity-changed"|"store-platform-mismatch"|"store-format-unsupported"
        |"reservation-consumed"|"authority-unavailable"|"authority-untrusted"|"authority-changed"|"authority-missing"
        |"authority-rewound"|"ledger-invalid"|"ledger-full"|"candidate-binding-conflict"|"conditional-conflict"
        |"pending-unresolved"|"journal-unavailable"|"source-changed"|"invalid-allocation"|"unauthorized"|"forbidden"
        |"rate-limited"|"target-changed"|"not-found-or-inaccessible"|"network-unavailable"|"tls-failed"|"response-invalid"
        |"response-limit"|"expired"|"cancelled")
}

#[cfg(test)]
mod tests {
    // Real disposable private-store/job fixtures plus wire DATA, not an actual
    // Document/worker, token acquisition, HTTP or Store API operation.
    use super::*;
    use crate::application_state_store::{Fixture, Namespace};
    use crate::service_protocol::Id;
    use super::super::jobs::{Failure as JobFailure, Jobs};
    use std::{sync::Mutex, time::{Duration, Instant}};

    fn authority() -> Value { json!({"projectId":"11111111-1111-4111-8111-111111111111","repository":"fixture/repository",
        "repositoryId":"27","ledgerId":"33333333-3333-4333-8333-333333333333","genesisSha256":"a".repeat(64),"protectedBranch":true}) }
    fn checkpoint() -> Value { json!({"sequence":0,"headSha256":"a".repeat(64),"commit":"c".repeat(40)}) }
    fn template() -> Value { json!({"projectId":authority()["projectId"],"identityRevision":"b".repeat(64),
        "source":{"commit":"d".repeat(40),"tree":"e".repeat(40),"ref":"refs/heads/main","configurationSha256":"f".repeat(64),"versionSha256":"c".repeat(64)},
        "baseVersion":{"name":"1.2.3","build":40},"platforms":["android"],"policy":{"schemaVersion":1,"mode":"automatic",
            "rules":[{"ref":"refs/heads/main","increment":"build"}],"buildCeiling":2100000000u64,"storeMaxAgeSeconds":900}}) }
    fn prepared(f: &Fixture) -> (Arc<PrivateStateDirectory>, VersionAllocationStatePort) {
        let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let project = ProjectBinding { project_id:Id::parse(&"b".repeat(32)).unwrap(), canonical_root:"/synthetic/version-project".into(),device:1,inode:2 };
        let mut port = VersionAllocationStatePort::new(store.clone(),project,authority()).unwrap();
        port.load().unwrap(); port.enroll(checkpoint()).unwrap(); port.select_new(template(),None).unwrap(); (store,port)
    }
    fn request(port: &VersionAllocationStatePort, kind: Kind) -> Request {
        Request::from_port(port,"allocation-data-1",kind,"17",Clock::new(70_000_000_000,80_000_000_000).unwrap(),&[]).unwrap()
    }
    fn pending(port: &VersionAllocationStatePort) -> Value {
        let request = port.selected_request().unwrap();
        let mut r = json!({"sequence":1,"previousSha256":"a".repeat(64),"request":request,
            "requestSha256":hash(b"mrk:allocation-request:1\0",request).unwrap(),"version":{"name":"1.2.3","build":41},
            "storeObservations":[],"allocatedAt":2000});
        r["sha256"] = json!(hash(b"mrk:allocation-reservation:1\0",&r).unwrap());
        json!({"schemaVersion":1,"protocol":"mrk-version-allocation/1","authority":authority(),"checkpoint":checkpoint(),"expectedBlob":"d".repeat(40),"reservation":r})
    }
    fn step(request: &Request, sequence: u8, revision: Revision, payload: &str, change: Value) -> Vec<u8> {
        encoded(&json!({"protocol":PROTOCOL,"id":request.id,"state":{"requestSha256":request.initial_digest,
            "sequence":sequence,"expectedRevision":revision.0,"payloadSha256":payload,"transition":change}}),STATE_FRAME_LIMIT).unwrap()
    }
    fn finished(request: &Request, cursor: &Cursor, outcome: Value) -> Vec<u8> {
        encoded(&json!({"protocol":PROTOCOL,"id":request.id,"finished":{"requestSha256":request.initial_digest,"sequence":cursor.sequence,
            "revision":cursor.revision.0,"payloadSha256":cursor.state_sha256,"outcome":outcome}}),FIN_LIMIT).unwrap()
    }
    fn outcome(status: &str, reason: &str) -> Value { json!({"schemaVersion":1,"status":status,"reason":reason,"reservation":null,"checkpoint":null,
        "writeClaimed":false,"writeAcknowledged":false,"control":{"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false},
        "releaseEligibility":"not-established","assurance":"repository-allocation-data-not-native-finality"}) }
    fn pending_step(port: &VersionAllocationStatePort, request: &Request, cursor: &mut Cursor) -> Arc<Step> {
        let pending = pending(port); let mut next = port.state().unwrap().clone();
        next.authorities[0].pending = Some(decode(pending.clone()).unwrap());
        let raw = step(request,1,port.snapshot().unwrap().revision,&digest(&next.bytes().unwrap()),json!({"kind":"pending","pending":pending}));
        cursor.step(request,&raw).unwrap()
    }

    #[test]
    fn go_is_exact_ascii_and_private_token_is_not_in_the_initial_or_retained_public_parts() {
        let f = Fixture::new(); let (store,port) = prepared(&f); let request = request(&port,Kind::Reserve);
        let token = "\\\"".repeat(TOKEN_LIMIT/2);
        let raw = request.go(&token).unwrap(); let parsed = strict_json(&raw).unwrap();
        assert!(!request.initial.windows(token.len()).any(|part| part == token.as_bytes()));
        assert!(!request.go_prefix.windows(token.len()).any(|part| part == token.as_bytes()));
        assert_eq!(parsed["go"]["token"],token); assert_eq!(encoded(&parsed,GO_LIMIT).unwrap(),*raw);
        assert_eq!(parsed["go"]["request"],*port.selected_request().unwrap());
        assert_eq!(parsed["go"]["state"]["revision"].as_u64(),Some(2));
        assert!(request.go(&(token+"x")).is_err()); assert!(request.go("line\nbreak").is_err());
        let ready = encoded(&json!({"protocol":PROTOCOL,"id":request.id,"ready":{"requestSha256":request.initial_digest}}),READY_LIMIT).unwrap();
        request.ready(&ready).unwrap(); assert!(request.ready(&[ready.as_slice(),b"\n"].concat()).is_err());
        assert!(request.matches_initial_port(&port)); store.close().unwrap();
    }
    #[test]
    fn no_selection_wrong_mode_and_changed_native_binding_do_not_build_or_match_a_request() {
        let f = Fixture::new(); let (store,mut port) = prepared(&f);
        assert!(Request::from_port(&port,"allocation-data-1",Kind::Reconcile,"17",Clock::new(1,2).unwrap(),&[]).is_err());
        let request = request(&port,Kind::Reserve); port.project.inode += 1;
        assert!(!request.matches_port(&port)); port.project.inode -= 1;
        port.bound = None;
        assert!(Request::from_port(&port,"allocation-data-1",Kind::Reserve,"17",Clock::new(1,2).unwrap(),&[]).is_err());
        assert!(Clock::new(0,1).is_err()); assert!(Clock::new(1,10_000_000_002).is_err()); store.close().unwrap();
    }
    #[test]
    fn a_second_outstanding_step_or_foreign_full_request_poison_the_single_cursor() {
        let f = Fixture::new(); let (store,port) = prepared(&f); let request = request(&port,Kind::Reserve);
        let mut cursor = Cursor::new(&request);
        let change = json!({"kind":"checkpoint","checkpoint":{"sequence":0,"headSha256":"a".repeat(64),"commit":"f".repeat(40)}});
        let raw = step(&request,1,Revision(2),&"b".repeat(64),change);
        let first = cursor.step(&request,&raw).unwrap(); assert!(cursor.step(&request,&raw).is_err());
        assert!(cursor.applied(&request,&first,&WriteAck { revision:Revision(3),payload_sha256:"b".repeat(64) }).is_err());
        let mut wrong = pending(&port); wrong["reservation"]["request"]["source"]["tree"] = json!("f".repeat(40));
        let raw = step(&request,1,Revision(2),&"b".repeat(64),json!({"kind":"pending","pending":wrong}));
        assert!(Cursor::new(&request).step(&request,&raw).is_err()); store.close().unwrap();
    }
    #[test]
    fn actual_port_return_precedes_ack_and_stop_preserves_pending_without_releasing_success() {
        let f = Fixture::new(); let (store,mut port) = prepared(&f); let request = request(&port,Kind::Reserve);
        let pending = pending(&port); let mut next = port.state().unwrap().clone();
        next.authorities[0].pending = Some(decode(pending.clone()).unwrap());
        let expected = digest(&next.bytes().unwrap());
        let raw = step(&request,1,Revision(2),&expected,json!({"kind":"pending","pending":pending}));
        let mut cursor = Cursor::new(&request); let step = cursor.step(&request,&raw).unwrap();
        let ack = port.apply(step.expected_revision,request.selected(),step.transition()).unwrap();
        assert_eq!(ack.revision,Revision(3)); assert_eq!(ack.payload_sha256,expected);
        let bytes = step.ack(&request,&ack).unwrap(); assert_eq!(frame(&bytes,ACK_LIMIT).unwrap()["ack"]["cleanup"],"settled");
        cursor.stop(); assert!(cursor.applied(&request,&step,&ack).is_err());
        assert!(port.enrolled().unwrap().pending.is_some());
        assert_eq!(store.read(Namespace::VersionAllocations).unwrap().revision,Revision(3));
        assert!(Request::from_port(&port,"allocation-data-2",Kind::Reserve,"17",Clock::new(1,2).unwrap(),&[]).is_err());
        Request::from_port(&port,"allocation-data-2",Kind::Reconcile,"17",Clock::new(1,2).unwrap(),&[]).unwrap(); store.close().unwrap();
    }
    #[test]
    fn remote_reservation_data_without_a_reused_cas_never_finishes_as_reserved() {
        let f = Fixture::new(); let (store,mut port) = prepared(&f); let pending = pending(&port);
        let checkpoint = json!({"sequence":1,"headSha256":pending["reservation"]["sha256"],"commit":"e".repeat(40)});
        let selected = port.selected_request().unwrap().clone();
        port.apply(Revision(2),&selected,Transition::Checkpoint(checkpoint.clone())).unwrap();
        let request = request(&port,Kind::Reserve); let mut cursor = Cursor::new(&request);
        let mut result = outcome("reserved","none"); result["reservation"] = pending["reservation"].clone(); result["checkpoint"] = checkpoint.clone();
        let raw = finished(&request,&cursor,result.clone()); assert!(cursor.finish(&request,&port,&raw).is_err());
        let mut cursor = Cursor::new(&request); let mut next = port.state().unwrap().clone();
        next.candidates[0].reservation = Some(decode(pending["reservation"].clone()).unwrap());
        let raw = step(&request,1,Revision(3),&digest(&next.bytes().unwrap()),
            json!({"kind":"reused","reservation":pending["reservation"],"checkpoint":checkpoint}));
        let step = cursor.step(&request,&raw).unwrap();
        let ack = port.apply(step.expected_revision,request.selected(),step.transition()).unwrap();
        cursor.applied(&request,&step,&ack).unwrap();
        for reason in ["cancelled","expired","unauthorized","response-invalid","rate-limited"] {
            // Replay only the recorded DATA cursor; no second native CAS is made.
            let mut rejected = Cursor::new(&request); let step = rejected.step(&request,&raw).unwrap();
            rejected.applied(&request,&step,&ack).unwrap();
            let mut veto = result.clone(); veto["control"]["reason"] = json!(reason);
            if reason == "rate-limited" { veto["control"]["cooldownSeconds"] = json!(5); }
            let control:GitHubReadControl = serde_json::from_value(veto["control"].clone()).unwrap();
            assert!(control.valid());
            let terminal = finished(&request,&rejected,veto);
            assert!(rejected.finish(&request,&port,&terminal).is_err());
            let terminal = finished(&request,&rejected,result.clone());
            assert!(rejected.finish(&request,&port,&terminal).is_err());
        }
        let raw = finished(&request,&cursor,result); let terminal = cursor.finish(&request,&port,&raw).unwrap();
        assert_eq!(terminal.outcome["releaseEligibility"],"not-established"); assert!(cursor.finish(&request,&port,&raw).is_err());
        store.close().unwrap();
    }
    #[test]
    fn fixed_bounds_and_reconcile_never_grant_selection_or_another_pending_step() {
        assert_eq!(GO_LIMIT,1_427_800); assert_eq!(INPUT_TOTAL_LIMIT,1_441_112); assert_eq!(OUTPUT_TOTAL_LIMIT,122_880);
        let f = Fixture::new(); let (store,mut port) = prepared(&f); let pending = pending(&port);
        let selected = port.selected_request().unwrap().clone(); port.apply(Revision(2),&selected,Transition::Pending(pending.clone())).unwrap();
        let request = request(&port,Kind::Reconcile);
        for change in [json!({"kind":"select","request":selected}),json!({"kind":"pending","pending":pending.clone()}),
            json!({"kind":"rejected","pending":pending})] {
            let raw = step(&request,1,Revision(3),&"b".repeat(64),change);
            assert!(Cursor::new(&request).step(&request,&raw).is_err());
        }
        let mut bad = outcome("unavailable","authority-unavailable"); bad["writeClaimed"] = json!(true);
        let mut cursor = Cursor::new(&request); let raw = finished(&request,&cursor,bad);
        assert!(cursor.finish(&request,&port,&raw).is_err()); store.close().unwrap();
    }
    #[test]
    fn registered_but_unreleased_actual_state_job_joins_without_any_cas() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            let f = Fixture::new(); let (store,port) = prepared(&f); let request = Arc::new(request(&port,Kind::Reserve));
            let mut cursor = Cursor::new(&request); let step = pending_step(&port,&request,&mut cursor);
            let port = Arc::new(Mutex::new(port)); let (stop,stopped) = tokio::sync::watch::channel(false);
            let mut jobs = Jobs::new(request,port,stopped,Instant::now()+Duration::from_secs(60)).unwrap();
            jobs.register(step.clone()).unwrap(); assert!(jobs.join_pending());
            assert_eq!(store.read(Namespace::VersionAllocations).unwrap().revision,Revision(2));
            stop.send_replace(true); jobs.stop_before_release();
            let joined = jobs.join_current().await.unwrap();
            assert!(matches!(joined.original_result(),Err(JobFailure::NotReleased)));
            assert!(joined.checked_ack(&step).is_err()); assert!(jobs.failed() && jobs.all_returned());
            assert!(jobs.register(step).is_err());
            assert_eq!(store.read(Namespace::VersionAllocations).unwrap().revision,Revision(2)); store.close().unwrap();
        });
    }
    #[test]
    fn original_state_job_return_is_retained_when_stop_arrives_between_cas_and_ack() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            let f = Fixture::new(); let (store,port) = prepared(&f); let request = Arc::new(request(&port,Kind::Reserve));
            let mut cursor = Cursor::new(&request); let step = pending_step(&port,&request,&mut cursor);
            let port = Arc::new(Mutex::new(port)); let (stop,stopped) = tokio::sync::watch::channel(false);
            let mut jobs = Jobs::new(request,port.clone(),stopped,Instant::now()+Duration::from_secs(60)).unwrap();
            jobs.register(step.clone()).unwrap(); jobs.release_registered().unwrap();
            let joined = jobs.join_current().await.unwrap();
            assert_eq!(joined.checked_ack(&step).unwrap().revision,Revision(3)); assert!(jobs.all_returned());
            // Retiring this same job owner vetoes ACK immediately, even before
            // the enclosing Supervisor's independent STOP broadcast arrives.
            jobs.stop_before_release();
            assert!(matches!(joined.checked_ack(&step),Err(JobFailure::Stopped)));
            stop.send_replace(true);
            assert_eq!(joined.original_result().as_ref().unwrap().revision,Revision(3));
            assert!(port.lock().unwrap().enrolled().unwrap().pending.is_some());
            assert_eq!(store.read(Namespace::VersionAllocations).unwrap().revision,Revision(3)); store.close().unwrap();
        });
    }
    #[test]
    fn original_state_job_preserves_real_native_stale_cas_error_and_never_reopens() {
        use crate::{application_state_store::{Effect,Durability,Cleanup},service_protocol::Error};
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            let f = Fixture::new(); let (store,port) = prepared(&f); let request = Arc::new(request(&port,Kind::Reserve));
            let mut cursor = Cursor::new(&request); let step = pending_step(&port,&request,&mut cursor);
            let before = port.snapshot().unwrap().bytes.clone();
            store.replace(Namespace::VersionAllocations,Revision(2),&before).unwrap();
            let port = Arc::new(Mutex::new(port)); let (_stop,stopped) = tokio::sync::watch::channel(false);
            let mut jobs = Jobs::new(request,port.clone(),stopped,Instant::now()+Duration::from_secs(60)).unwrap();
            jobs.register(step.clone()).unwrap(); jobs.release_registered().unwrap();
            let joined = jobs.join_current().await.unwrap();
            let Err(JobFailure::Native(error)) = joined.original_result() else { panic!("original native error missing") };
            assert_eq!((error.code,error.effect,error.durability,error.cleanup),(Error::Conflict,Effect::None,Durability::NotApplicable,Cleanup::Known));
            assert!(matches!(joined.checked_ack(&step),Err(JobFailure::Native(_))));
            assert!(jobs.failed() && jobs.all_returned()); assert!(jobs.register(step).is_err());
            assert!(port.lock().unwrap().load().is_err());
            let observed = store.read(Namespace::VersionAllocations).unwrap(); assert_eq!(observed.revision,Revision(3));
            assert_eq!(observed.bytes,before); store.close().unwrap();
        });
    }
}
