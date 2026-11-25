//! One genuine pending iOS input transaction: ordinary Inspect then a fresh
//! explicit Recover. Passive original-session DATA only; no iOS mode grant,
//! replacement owner, cancellation hold, journal writer or third operation.
use std::{fs::OpenOptions, os::{fd::AsFd, unix::fs::{MetadataExt, OpenOptionsExt}}, path::Path,
    sync::{Arc, OnceLock, Weak, atomic::{AtomicBool, AtomicU8, Ordering}}};
use serde::Serialize;
use serde_json::{json, Value};
use crate::{asset_session::DocumentBinding, error::BridgeError, project_recovery_owner::ProjectRecoveryOwner,
    project_recovery_protocol as wire};
use super::{Case as ShellCase, Observation, Step as ShellStep, FileFact};

pub(super) const NAME: &str = "project-recovery-pending";
const ANDROID: &[u8] = b"synthetic original Android input\n";
const IOS: &[u8] = b"synthetic original iOS input\n";
const FOREIGN: &[u8] = b"synthetic foreign iOS input; preserve\n";
const UNRELATED: &[u8] = b"unrelated synthetic file; preserve\n";
const IGNORE: &[u8] = b".mobile-release/\n";

// Same shared saved-command facts shape as the Linux two-original observer.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OriginalFacts {
    pub(crate) domain: &'static str, pub(crate) id: String, pub(crate) generation: String,
    pub(crate) inspection_joined: bool, pub(crate) acquisition_joined: bool, pub(crate) attempted: bool, pub(crate) no_child: bool,
    pub(crate) child_waited_success: bool, pub(crate) stdin_closed: bool, pub(crate) stdout_eof_closed: bool, pub(crate) stderr_eof_closed: bool,
    pub(crate) io_joined: bool, pub(crate) core_lifetime_settled: bool, pub(crate) runtime_ledger_settled: bool, pub(crate) runtime_settlement_joined: bool,
    pub(crate) driver_joined: bool, pub(crate) manager_joined: bool, pub(crate) observer_joined: bool, pub(crate) watchdog_joined: bool,
    pub(crate) retired_before_cutoff: bool, pub(crate) active_retained: bool, pub(crate) resource_unknown: bool,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Snapshot {
    pub(crate) facts: OriginalFacts, pub(crate) projection: wire::Projection, pub(crate) accepted: bool,
    pub(crate) core_terminal: bool, pub(crate) core_fatal: bool, pub(crate) review_minted: bool,
}
fn final_facts(f: &OriginalFacts) -> bool {
    f.domain == "project-recovery" && crate::edit_protocol::token(&f.id) && crate::edit_protocol::token(&f.generation)
        && f.inspection_joined && f.acquisition_joined && f.attempted && !f.no_child && f.child_waited_success
        && f.stdin_closed && f.stdout_eof_closed && f.stderr_eof_closed && f.io_joined && f.core_lifetime_settled
        && f.runtime_ledger_settled && f.runtime_settlement_joined && f.driver_joined && f.manager_joined
        && f.observer_joined && f.watchdog_joined && f.retired_before_cutoff && !f.active_retained && !f.resource_unknown
}
fn original(snapshot: &Snapshot, prepared: &wire::Projection) -> bool {
    snapshot.facts.id == prepared.operation_id && snapshot.facts.generation == prepared.owner_generation
        && snapshot.projection.operation_id == prepared.operation_id && snapshot.projection.owner_generation == prepared.owner_generation
        && snapshot.projection.context == prepared.context && !snapshot.projection.intent_usable
}
fn final_snapshot(snapshot: &Snapshot, prepared: &wire::Projection, action: wire::Action) -> bool {
    let p = &snapshot.projection;
    if !original(snapshot,prepared) || !final_facts(&snapshot.facts) || !snapshot.accepted || !snapshot.core_terminal
        || snapshot.core_fatal || snapshot.review_minted != (action == wire::Action::Inspect)
        || p.phase != wire::Phase::Terminal || p.outcome != Some(wire::Outcome::Complete) || p.reason != wire::Reason::None
        || p.effect != Some(if action == wire::Action::Inspect { wire::Effect::Inspection } else { wire::Effect::RecoveryAttempted }) {
        return false;
    }
    match action {
        wire::Action::Inspect => p.result.as_ref().is_some_and(|r| r.action == wire::Action::Inspect
            && r.observation.as_ref().is_some_and(|o| o.status == wire::InspectionStatus::Pending && o.eligible()
                && o.quiescence == wire::Quiescence::Original && o.roles == [wire::Role::AndroidServices, wire::Role::IosServices])),
        wire::Action::Recover => p.context.review.as_ref().is_some_and(|review| p.result.as_ref().is_some_and(|result|
            serde_json::to_value(result).is_ok_and(|r| r["action"] == "recover" && r["observation"].is_null()
                && r["recoveredSession"].as_str() == review.session.as_deref()))),
    }
}
fn same_projection_original(current: &wire::Projection, prepared: &wire::Projection) -> bool {
    current.operation_id == prepared.operation_id && current.owner_generation == prepared.owner_generation
        && current.context == prepared.context && !current.intent_usable && current.phase != wire::Phase::Unknown
}
fn settled_status(status: &wire::Status, final_projection: &wire::Projection, prepared: &wire::Projection) -> Result<bool, ()> {
    let current = status.operation.as_ref().ok_or(())?;
    if status.schema_version != 1 || !matches!(status.availability, wire::Availability::Available | wire::Availability::Busy)
        || !same_projection_original(current,prepared) { return Err(()); }
    if current == final_projection { return Ok(status.availability == wire::Availability::Available); }
    // Status is sampled before the saved original snapshot, outside Record.
    // A same-original earlier public Starting/Running sample may legitimately
    // precede retirement. Defer one finite poll; never repeat an action, reset
    // the original deadline, or admit a foreign/Unknown/different terminal.
    if status.availability == wire::Availability::Busy && matches!(current.phase,wire::Phase::Starting|wire::Phase::Running)
        && current.outcome.is_none() && current.result.is_none() && current.effect.is_none() && current.reason == wire::Reason::None {
        Ok(false)
    } else { Err(()) }
}
fn claim_transition(claims: &AtomicU8, action: wire::Action) -> bool {
    let (old, next) = if action == wire::Action::Inspect { (0, 1) } else { (1, 3) };
    claims.compare_exchange(old, next, Ordering::SeqCst, Ordering::SeqCst).is_ok()
}
pub(crate) struct Admission { control: Arc<Control>, document: Weak<()>, owner: Weak<()> }
impl Admission {
    pub(crate) fn document_matches(&self, original: &Arc<()>) -> bool {
        self.document.upgrade().is_some_and(|bound| Arc::ptr_eq(&bound, original))
    }
    pub(crate) fn consume(self, original: &Arc<()>) -> Result<Arc<Control>, BridgeError> {
        let q = self.control.original.get().and_then(Weak::upgrade).ok_or_else(BridgeError::invalid)?;
        let r = q.record().ok_or_else(BridgeError::cleanup_unknown)?;
        if self.control.normal_selection.get().is_none() || self.document.upgrade().is_none()
            || !self.owner.upgrade().is_some_and(|bound| Arc::ptr_eq(&bound, original))
            || !r.attached || r.started || r.loaded || !q.timely() || q.case != ShellCase::PendingRecovery
            || !q.recovery.as_ref().is_some_and(|control| Arc::ptr_eq(control, &self.control))
            || self.control.admitted.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return Err(BridgeError::invalid());
        }
        drop(r); Ok(self.control)
    }
}
pub(crate) struct Control {
    original: OnceLock<Weak<Observation>>, document: OnceLock<Weak<()>>, owner: OnceLock<Weak<()>>,
    normal_selection: OnceLock<()>, admitted: AtomicBool, claims: AtomicU8, failed: AtomicBool,
}
impl Control {
    pub(super) fn new() -> Arc<Self> { Arc::new(Self { original: OnceLock::new(), document: OnceLock::new(),
        owner: OnceLock::new(), normal_selection: OnceLock::new(), admitted: AtomicBool::new(false),
        claims: AtomicU8::new(0), failed: AtomicBool::new(false) }) }
    fn attach(self: &Arc<Self>, q: &Arc<Observation>, document: &DocumentBinding, owner: &ProjectRecoveryOwner) -> Result<(), BridgeError> {
        if q.case != ShellCase::PendingRecovery || !q.timely() || std::thread::current().id() != q.main { return Err(BridgeError::invalid()); }
        let (doc, bound) = document.installed_recovery_identities(); let direct = owner.installed_recovery_identity();
        if doc.upgrade().is_none() || direct.upgrade().is_none() || !Weak::ptr_eq(&bound, &direct) { return Err(BridgeError::invalid()); }
        // Passive read before either observer admission. Do not call Status
        // here: Status publishes a revision and would invalidate virgin custody.
        owner.observe_installed_selection()?;
        if self.normal_selection.set(()).is_err() || self.original.set(Arc::downgrade(q)).is_err()
            || self.document.set(doc.clone()).is_err() || self.owner.set(bound.clone()).is_err() { return Err(BridgeError::invalid()); }
        document.admit_installed_recovery(Admission { control: self.clone(), document: doc, owner: bound })
    }
    pub(crate) fn permits(&self) -> bool {
        // Called under the saved-owner registry. No Record/document/native lock.
        self.admitted.load(Ordering::SeqCst) && self.normal_selection.get().is_some() && !self.failed.load(Ordering::SeqCst)
            && self.document.get().and_then(Weak::upgrade).is_some() && self.owner.get().and_then(Weak::upgrade).is_some()
            && self.original.get().and_then(Weak::upgrade).is_some_and(|q| q.timely() && q.case == ShellCase::PendingRecovery
                && q.recovery.as_ref().is_some_and(|control| std::ptr::eq(control.as_ref(), self)))
    }
    pub(crate) fn claim(&self, action: wire::Action) -> Result<(), BridgeError> {
        if self.permits() && claim_transition(&self.claims, action) { Ok(()) } else { Err(BridgeError::invalid()) }
    }
    pub(crate) fn claimed(&self, action: wire::Action) -> bool {
        self.permits() && self.claims.load(Ordering::SeqCst) == if action == wire::Action::Inspect { 1 } else { 3 }
    }
    pub(crate) fn unavailable_witness(&self) {
        self.failed.store(true, Ordering::SeqCst);
        if let Some(q) = self.original.get().and_then(Weak::upgrade) { q.fail_with("recovery-original-contract"); }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Command { Prepare, Start, Status, Cancel }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step { Navigate, Ready, Inspect, WaitInspect, ReadInspect, Review, ReadReview, Acknowledge, ReadChecked, Start, WaitRecover, ReadFinal }
#[derive(Clone, Default)]
pub(super) struct Record {
    requests: [u8; 4], replies: [u8; 4], pending: Option<usize>, status_requested: u8, status_returned: u8,
    requested: [Option<wire::Context>; 2], prepared: [Option<wire::Projection>; 2], originals: [Option<Snapshot>; 2], initial: bool,
    inspect_visible: bool, review_unchecked: bool, acknowledged: bool, review_checked: bool, final_visible: bool,
}
impl Record {
    pub(super) fn sample_ready(&self, step: Step) -> bool {
        match step { Step::WaitInspect => self.replies[..2] == [1,1], Step::WaitRecover => self.replies[2..] == [1,1], _ => true }
    }
    fn request(&mut self, step: Step, command: Command, body: &Value, project: Option<&str>) -> bool {
        if command == Command::Status {
            if wire::status_request(body).is_err() || self.status_requested >= 96 { return false; }
            self.status_requested += 1; return true;
        }
        let i = match command {
            Command::Prepare if body["action"] == "inspect" && matches!(step, Step::Inspect | Step::WaitInspect) => 0,
            Command::Start if matches!(step, Step::Inspect | Step::WaitInspect) => 1,
            Command::Prepare if body["action"] == "recover" && matches!(step, Step::Review | Step::ReadReview) => 2,
            Command::Start if matches!(step, Step::Start | Step::WaitRecover) => 3,
            _ => return false,
        };
        if self.requests[i] != 0 || self.pending.is_some() || (i == 2 && !self.inspect_visible)
            || (i == 3 && !self.review_checked) { return false; }
        if matches!(i, 0 | 2) {
            let Ok(input) = wire::prepare(body) else { return false; };
            if project != Some(input.project_id.as_str()) { return false; }
            self.requested[i/2] = Some(input.context());
        } else if !wire::start(body).is_ok_and(|v| self.prepared[if i == 1 { 0 } else { 1 }].as_ref().is_some_and(|p|
            p.operation_id == v.operation_id && p.owner_generation == v.owner_generation)) { return false; }
        self.requests[i] = 1; self.pending = Some(i); true
    }
    fn result(&mut self, command: Command, result: &Result<wire::Status, BridgeError>) -> bool {
        let Ok(status) = result else { return false; };
        if status.schema_version != 1 || status.availability == wire::Availability::CleanupUnknown
            || status.operation.as_ref().is_some_and(|p| p.phase == wire::Phase::Unknown) { return false; }
        if command == Command::Status {
            if self.status_returned >= self.status_requested { return false; }
            self.status_returned += 1; return true;
        }
        let Some(i) = self.pending else { return false; };
        if !matches!((command,i), (Command::Prepare,0|2) | (Command::Start,1|3)) || self.replies[i] != 0 { return false; }
        let Some(op) = status.operation.as_ref() else { return false; };
        let j = i / 2;
        if matches!(i,0|2) {
            if self.prepared[j].is_some() || op.phase != wire::Phase::AwaitingConsent || !op.intent_usable
                || op.outcome.is_some() || op.result.is_some() || op.effect.is_some() || op.reason != wire::Reason::None
                || !crate::edit_protocol::token(&op.operation_id) || !crate::edit_protocol::token(&op.owner_generation)
                || !self.requested[j].as_ref().is_some_and(|input| input.project_id == op.context.project_id
                    && input.draft_revision == op.context.draft_revision && input.baseline_generation == op.context.baseline_generation
                    && input.action == op.context.action)
                || op.context.action != if j == 0 { wire::Action::Inspect } else { wire::Action::Recover }
                || !op.context.valid() { return false; }
            if j == 1 {
                let Some(prior) = self.prepared[0].as_ref() else { return false; };
                let inspected = self.originals[0].as_ref().and_then(|s| s.projection.result.as_ref()).and_then(|r| r.observation.as_ref());
                if prior.operation_id == op.operation_id || prior.owner_generation == op.owner_generation
                    || prior.context.project_id != op.context.project_id || prior.context.draft_revision != op.context.draft_revision
                    || prior.context.baseline_generation != op.context.baseline_generation || inspected.is_none()
                    || op.context.review.as_ref() != inspected { return false; }
            }
            self.prepared[j] = Some(op.clone());
        } else if self.prepared[j].as_ref().is_none_or(|p| p.operation_id != op.operation_id
            || p.owner_generation != op.owner_generation || p.context != op.context) { return false; }
        self.pending = None; self.replies[i] = 1; true
    }
    pub(super) fn advance(&mut self, step: Step, control: &Control, status: &wire::Status, snapshot: Option<Snapshot>) -> Option<Step> {
        if status.schema_version != 1 || status.availability == wire::Availability::CleanupUnknown
            || status.operation.as_ref().is_some_and(|op| op.phase == wire::Phase::Unknown) { control.unavailable_witness(); return None; }
        if step == Step::Ready {
            if status.availability != wire::Availability::Available || status.operation.is_some() { return None; }
            self.initial = true; return Some(step);
        }
        let i = match step { Step::WaitInspect => 0, Step::WaitRecover => 1, _ => return Some(step) };
        if self.replies[i*2..i*2+2] != [1,1] { return None; }
        let prepared = self.prepared[i].as_ref()?;
        if !status.operation.as_ref().is_some_and(|current| same_projection_original(current, prepared))
            || !matches!(status.availability,wire::Availability::Available|wire::Availability::Busy) {
            control.unavailable_witness(); return None;
        }
        let snapshot = snapshot?;
        if snapshot.facts.resource_unknown || !original(&snapshot,prepared) || snapshot.projection.phase == wire::Phase::Unknown {
            control.unavailable_witness(); return None;
        }
        if !snapshot.facts.retired_before_cutoff { return None; }
        let p = &snapshot.projection;
        if !final_snapshot(&snapshot,prepared,if i == 0 { wire::Action::Inspect } else { wire::Action::Recover }) {
            control.unavailable_witness(); return None;
        }
        match settled_status(status,p,prepared) {
            Ok(true) => {}, Ok(false) => return None, Err(()) => { control.unavailable_witness(); return None; },
        }
        self.originals[i] = Some(snapshot); Some(if i == 0 { Step::ReadInspect } else { Step::ReadFinal })
    }
    fn inspected(&self) -> Option<&wire::Observation> {
        self.originals[0].as_ref()?.projection.result.as_ref()?.observation.as_ref()
    }
    pub(super) fn dom(&mut self, step: Step, value: &Value) -> Result<Option<Step>, ()> {
        let ready = || value == &json!({"state":"ready"});
        let next = match step {
            Step::Navigate if ready() => Step::Ready,
            Step::Ready if self.initial && *value == json!({"state":"ready","inspectAvailable":true,"recoverAvailable":false}) => Step::Inspect,
            Step::Inspect if ready() => Step::WaitInspect,
            Step::ReadInspect if *value == json!({"state":"ready","settled":true,"outcome":"complete","status":"pending",
                "session":self.inspected().ok_or(())?.session,"recoverAvailable":true,"originalQuiescenceVisible":true}) => {
                self.inspect_visible = true; Step::Review
            },
            Step::Review if ready() => Step::ReadReview,
            Step::ReadReview if self.replies[2] == 1 && *value == json!({"state":"ready","checked":false,"runAvailable":false,
                "session":self.inspected().ok_or(())?.session}) => { self.review_unchecked = true; Step::Acknowledge },
            Step::Acknowledge if self.review_unchecked && ready() => { self.acknowledged = true; Step::ReadChecked },
            Step::ReadChecked if self.acknowledged && *value == json!({"state":"ready","checked":true,"runAvailable":true,
                "session":self.inspected().ok_or(())?.session}) => { self.review_checked = true; Step::Start },
            Step::Start if ready() => Step::WaitRecover,
            Step::ReadFinal if self.originals[1].is_some() && *value == json!({"state":"ready","settled":true,"outcome":"complete",
                "restored":true,"session":self.inspected().ok_or(())?.session}) => { self.final_visible = true; return Ok(None); },
            _ => return Err(()),
        };
        Ok(Some(next))
    }
    pub(super) fn report(&self, control: &Control) -> Option<Value> {
        if self.requests != [1;4] || self.replies != self.requests || self.pending.is_some()
            || self.status_returned != self.status_requested || !self.initial || !self.inspect_visible || !self.review_unchecked
            || !self.acknowledged || !self.review_checked || !self.final_visible || control.normal_selection.get().is_none()
            || control.failed.load(Ordering::SeqCst) || control.claims.load(Ordering::SeqCst) != 3
            || !self.originals.iter().all(|s| s.as_ref().is_some_and(|s| final_facts(&s.facts))) { return None; }
        Some(json!({"schemaVersion":1,"scope":"project-build-input-recovery-native-observation-v1","case":NAME,
            "ordinaryProfileAvailableBeforeAdmission":true,"originals":self.originals,"prepared":self.prepared,
            "requests":self.requests,"replies":self.replies,"statusCallsReturned":self.status_returned,
            "freshUncheckedReview":true,"explicitAcknowledgement":true,"exactSessionReviewed":true,"finalVisible":true,
            "workMs":120000,"hardMs":130000,"observationMs":315000,"outerInvocationMs":325000,
            "commandDispatches":0,"profileCalls":0,"signedModesActivated":false,"shippingBinaryQualified":false}))
    }
}
impl Observation {
    pub(crate) fn attach_recovery(self: &Arc<Self>, document: &DocumentBinding, owner: &ProjectRecoveryOwner) -> Result<(), BridgeError> {
        if let Some(control) = &self.recovery { control.attach(self, document, owner)?; } Ok(())
    }
    pub(crate) fn recovery_request(&self, command: Command, body: &Value) {
        if self.recovery.is_none() { return; }
        let Some(mut r) = self.record() else { return; };
        let step = match r.step { ShellStep::Recovery(step) => step, _ if command == Command::Status => Step::Navigate,
            _ => { self.fail_with("recovery-request-contract"); return; } };
        let project = r.project.as_ref().map(|p| p.id.clone());
        if !self.timely() || !r.recovery_record.as_mut().is_some_and(|record| record.request(step,command,body,project.as_deref())) {
            self.fail_with("recovery-request-contract");
        }
    }
    pub(crate) fn recovery_result(&self, command: Command, value: &Result<wire::Status, BridgeError>) {
        if self.recovery.is_none() { return; }
        let Some(mut r) = self.record() else { return; };
        if !self.timely() || !r.recovery_record.as_mut().is_some_and(|record| record.result(command,value)) { self.fail_with("recovery-result-contract"); }
    }
}

// The outer Python owner inventories every bounded journal member before UI
// entry. Here retain exact synthetic originals and require real native/core
// restoration; never write, promote or parse a journal as recovery authority.
pub(super) struct Fixture {
    root: [u64;6], private: [u64;6], ignore: FileFact, unrelated: FileFact,
    android: FileFact, foreign: FileFact, ios: FileFact, final_readback: bool,
}
fn pending_directory(path: &Path, uid: u32) -> Result<(), ()> {
    let before = std::fs::symlink_metadata(path).map_err(|_| ())?;
    if !before.is_dir() || before.uid() != uid || before.mode() & 0o7777 != 0o700 { return Err(()); }
    let file = OpenOptions::new().read(true).custom_flags(nix::libc::O_NOFOLLOW|nix::libc::O_CLOEXEC|nix::libc::O_DIRECTORY)
        .open(path).map_err(|_| ())?;
    let result = (|| {
        let original = super::identity(&before)?;
        if super::identity(&file.metadata().map_err(|_| ())?)? != original { return Err(()); }
        mrk_macos_installed_native::empty_acl(file.as_fd()).map_err(|_| ())?;
        mrk_macos_installed_native::no_xattrs(file.as_fd()).map_err(|_| ())?;
        let mut buffer = vec![0u8;65536]; let mut names = Vec::new(); let mut eof = false;
        for _ in 0..20 {
            let used = mrk_macos_installed_native::directory_block(file.as_fd(), &mut buffer).map_err(|_| ())?;
            if used == 0 { eof = true; break; }
            let mut offset = 0;
            while offset < used {
                if used-offset < 11 { return Err(()); }
                let inode = u64::from_ne_bytes(buffer[offset..offset+8].try_into().map_err(|_| ())?);
                let kind = buffer[offset+8]; let length = usize::from(u16::from_ne_bytes([buffer[offset+9],buffer[offset+10]]));
                let next = offset.checked_add(11+length).filter(|n| *n<=used).ok_or(())?;
                let name = std::str::from_utf8(&buffer[offset+11..next]).map_err(|_| ())?; offset=next;
                if name == "." || name == ".." { continue; }
                let checkpoint = name.strip_prefix("checkpoint-").and_then(|s| s.strip_suffix(".json"))
                    .filter(|s| s.len()==3 && s.bytes().all(|b| b.is_ascii_digit())).and_then(|s| s.parse::<u8>().ok()).filter(|i| *i<128);
                if names.len() >= 131 || inode == 0 || kind != nix::libc::DT_REG || names.iter().any(|n| n == name)
                    || (!matches!(name,"header.json"|"intent.json"|"backup-1") && checkpoint.is_none()) { return Err(()); }
                names.push(name.to_owned());
            }
        }
        names.sort();
        let mut expected = vec!["backup-1".to_owned(),"header.json".to_owned(),"intent.json".to_owned()];
        if !(4..=131).contains(&names.len()) { return Err(()); }
        expected.extend((0..names.len()-3).map(|i| format!("checkpoint-{i:03}.json"))); expected.sort();
        if !eof || names != expected || super::identity(&file.metadata().map_err(|_| ())?)? != original
            || super::identity(&std::fs::symlink_metadata(path).map_err(|_| ())?)? != original { return Err(()); } Ok(())
    })();
    let closed = nix::unistd::close(std::os::fd::OwnedFd::from(file)).is_ok();
    if !closed { return Err(()); } result
}
impl Fixture {
    pub(super) fn capture(root: &Path, uid: u32) -> Result<Self, ()> {
        let root_id = super::directory(root,uid,0o700,&[".gitignore",".mobile-release","google-services.json","saved-foreign-ios","unrelated.txt"])?;
        let private = super::directory(&root.join(".mobile-release"),uid,0o700,&["build-inputs"])?;
        pending_directory(&root.join(".mobile-release/build-inputs"),uid)?;
        Ok(Self { root: root_id, private, ignore:super::file_fact(&root.join(".gitignore"),IGNORE,uid)?,
            unrelated:super::file_fact(&root.join("unrelated.txt"),UNRELATED,uid)?, android:super::file_fact(&root.join("google-services.json"),ANDROID,uid)?,
            foreign:super::file_fact(&root.join("saved-foreign-ios"),FOREIGN,uid)?,
            ios:super::file_fact(&root.join(".mobile-release/build-inputs/backup-1"),IOS,uid)?, final_readback:false })
    }
    pub(super) fn root_identity(&self) -> [u64;6] { self.root }
    pub(super) fn ignore(&self) -> FileFact { self.ignore.clone() }
    pub(super) fn verify(&self, root: &Path, uid: u32) -> Result<(), ()> {
        let entries = if self.final_readback { vec![".gitignore",".mobile-release","GoogleService-Info.plist","google-services.json","saved-foreign-ios","unrelated.txt"] }
            else { vec![".gitignore",".mobile-release","google-services.json","saved-foreign-ios","unrelated.txt"] };
        if super::directory(root,uid,0o700,&entries)?[..5] != self.root[..5]
            || super::directory(&root.join(".mobile-release"),uid,0o700,if self.final_readback { &[] } else { &["build-inputs"] })?[..5] != self.private[..5]
            || super::file_fact(&root.join(".gitignore"),IGNORE,uid)? != self.ignore
            || super::file_fact(&root.join("unrelated.txt"),UNRELATED,uid)? != self.unrelated
            || super::file_fact(&root.join("google-services.json"),ANDROID,uid)? != self.android
            || super::file_fact(&root.join("saved-foreign-ios"),FOREIGN,uid)? != self.foreign { return Err(()); }
        let ios = super::file_fact(&root.join(if self.final_readback { "GoogleService-Info.plist" } else { ".mobile-release/build-inputs/backup-1" }),IOS,uid)?;
        if ios.identity[..8] != self.ios.identity[..8] || ios.sha256 != self.ios.sha256 { return Err(()); }
        if !self.final_readback { pending_directory(&root.join(".mobile-release/build-inputs"),uid)?; }
        Ok(())
    }
    pub(super) fn finalize(&mut self, root: &Path, uid: u32) -> Result<(), ()> {
        if self.final_readback { return Err(()); }
        self.final_readback = true;
        // Absorbing on error: never restore an earlier fixture or replay Recover.
        self.verify(root,uid)
    }
}

pub(super) fn snapshot_failure(value: &Value, root: &Path) -> Option<&'static str> {
    if value["root"].as_str() != root.to_str() { return Some("snapshot-value-root"); }
    if value["observationScope"] != "single-request-non-atomic" || !super::assurance(value,"static-text") { return Some("snapshot-value-scope"); }
    if value["config"]["path"] != "release/mobile-release.json" || value["config"]["state"] != "missing"
        || !value["config"]["data"].is_null() || !value["config"]["content"].is_null() { return Some("snapshot-config-state"); }
    if value["discovery"]["state"] != "unverified" || value["discovery"]["partial"] != false { return Some("snapshot-discovery-state"); }
    None
}
pub(super) fn script(step: Step) -> Option<String> {
    let body = match step {
        Step::Navigate => "const n=document.querySelector('nav[aria-label=\"Workspace navigation\"] button[aria-label=\"Recovery\"]');if(!n||n.disabled)throw 0;n.click();return {state:'ready'};",
        Step::Ready => "if(!card)return {state:'wait'};return {state:'ready',inspectAvailable:available('Inspect build-input state'),recoverAvailable:available('Review recovery attempt')};",
        Step::Inspect => "return click('Inspect build-input state');",
        Step::Review => "return click('Review recovery attempt');",
        Step::ReadReview | Step::ReadChecked => "const g=card?.querySelector('[aria-label=\"Confirm the exact build-input recovery attempt\"]');if(!g)return {state:'wait'};const c=g.querySelector('input[type=checkbox]'),b=button(run,g);if(!c||c.disabled||!b)throw 0;show(g);return {state:'ready',checked:c.checked,runAvailable:!b.disabled,session:session(g)};",
        Step::Acknowledge => "const c=card?.querySelector('[aria-label=\"Confirm the exact build-input recovery attempt\"] input[type=checkbox]');if(!c||c.disabled||c.checked)throw 0;show(c);c.click();return {state:'ready'};",
        Step::Start => "return click(run);",
        Step::ReadInspect => "const p=progress();if(!p)return {state:'wait'};const r=card.querySelector('.session-review');if(!r)throw 0;return {state:'ready',settled:true,outcome:outcome(p),status:text(r.querySelector('.badge')),session:session(r),recoverAvailable:available('Review recovery attempt'),originalQuiescenceVisible:text(r).includes('The record contains the original consumer-finality observation.')};",
        Step::ReadFinal => "const p=progress();if(!p)return {state:'wait'};return {state:'ready',settled:true,outcome:outcome(p),restored:text(p).includes('Reviewed build-input session recovered.'),session:session(p)};",
        Step::WaitInspect | Step::WaitRecover => return None,
    };
    Some(format!(r#"(() => {{try {{
        const text=n=>n?.textContent?.trim()??'',run='Recover reviewed build inputs';
        const cards=[...document.querySelectorAll('section.card')].filter(n=>text(n.querySelector('h2'))==='Recover project build inputs');if(cards.length>1)throw 0;const card=cards[0];
        const button=(name,root=card)=>{{const a=root?[...root.querySelectorAll('button')].filter(n=>text(n)===name):[];if(a.length>1)throw 0;return a[0];}};
        const available=name=>{{const b=button(name);return !!b&&!b.disabled;}};
        const show=n=>{{n.scrollIntoView({{block:'center'}});const b=n.getBoundingClientRect();if(b.width<=0||b.height<=0||getComputedStyle(n).visibility!=='visible')throw 0;}};
        const click=name=>{{const b=button(name);if(!b||b.disabled)return {{state:'wait'}};show(b);b.click();return {{state:'ready'}};}};
        const session=root=>{{const codes=root.querySelectorAll('p code');if(codes.length!==1||!/^[0-9a-f]{{32}}$/.test(text(codes[0])))throw 0;return text(codes[0]);}};
        const progress=()=>{{const p=card?.querySelector('.session-progress');if(text(p?.querySelector('.badge'))!=='Original operation settled')return null;show(p);return p;}};
        const outcome=p=>{{const rows=[...p.querySelectorAll(':scope > p')].filter(n=>text(n).startsWith('Outcome: '));if(rows.length!==1)throw 0;return text(rows[0]).slice(9);}};
        {body}
    }}catch{{return {{state:'error'}};}}}})()"#))
}

// Inert DTO/atomic/transition controls in the existing native DATA entry. No
// native owner, file, core invocation, background task or grant is constructed.
pub(super) fn data_checks() -> bool {
    let observation = wire::Observation { status:wire::InspectionStatus::Pending, session:Some("e".repeat(32)),
        roles:vec![wire::Role::AndroidServices,wire::Role::IosServices], quiescence:wire::Quiescence::Original };
    let make = |action| -> Option<(wire::Projection,Snapshot)> {
        let inspect = action == wire::Action::Inspect;
        let context = wire::Context { project_id:"inert-recovery-data".into(),draft_revision:1,baseline_generation:1,
            action,review:(!inspect).then(||observation.clone()) };
        let prepared = wire::Projection { operation_id:if inspect {"a"} else {"c"}.repeat(32),
            owner_generation:if inspect {"b"} else {"d"}.repeat(32),context,phase:wire::Phase::AwaitingConsent,
            intent_usable:true,outcome:None,reason:wire::Reason::None,result:None,effect:None };
        let result = serde_json::from_value(json!({"schemaVersion":1,"scope":"project-build-inputs-only","action":action,
            "observation":if inspect {Some(&observation)} else {None}, "recoveredSession":if inspect {None} else {observation.session.as_ref()},
            "limitations":["build-inputs-only-not-store-or-account-recovery","recorded-quiescence-not-new-worker-proof",
                "foreign-changes-preserved","cancellation-does-not-undo-completed-cleanup","project-and-release-readiness-not-assessed"]})).ok()?;
        let projection = wire::Projection { phase:wire::Phase::Terminal,intent_usable:false,outcome:Some(wire::Outcome::Complete),
            result:Some(result),effect:Some(if inspect {wire::Effect::Inspection} else {wire::Effect::RecoveryAttempted}),..prepared.clone() };
        let facts = OriginalFacts { domain:"project-recovery",id:prepared.operation_id.clone(),generation:prepared.owner_generation.clone(),
            inspection_joined:true,acquisition_joined:true,attempted:true,no_child:false,child_waited_success:true,stdin_closed:true,
            stdout_eof_closed:true,stderr_eof_closed:true,io_joined:true,core_lifetime_settled:true,runtime_ledger_settled:true,
            runtime_settlement_joined:true,driver_joined:true,manager_joined:true,observer_joined:true,watchdog_joined:true,
            retired_before_cutoff:true,active_retained:false,resource_unknown:false };
        Some((prepared,Snapshot {facts,projection,accepted:true,core_terminal:true,core_fatal:false,review_minted:inspect}))
    };
    let Some((inspect,first)) = make(wire::Action::Inspect) else { return false; };
    let Some((recover,second)) = make(wire::Action::Recover) else { return false; };
    let status = |p:wire::Projection| wire::Status {schema_version:1,status_revision:7,availability:wire::Availability::Available,operation:Some(p)};
    if !final_snapshot(&first,&inspect,wire::Action::Inspect) || !final_snapshot(&second,&recover,wire::Action::Recover)
        || final_snapshot(&first,&recover,wire::Action::Recover) { return false; }
    let fact_mutations: [fn(&mut OriginalFacts);19] = [|f|f.inspection_joined=false,|f|f.acquisition_joined=false,|f|f.attempted=false,
        |f|f.no_child=true,|f|f.child_waited_success=false,|f|f.stdin_closed=false,|f|f.stdout_eof_closed=false,|f|f.stderr_eof_closed=false,
        |f|f.io_joined=false,|f|f.core_lifetime_settled=false,|f|f.runtime_ledger_settled=false,|f|f.runtime_settlement_joined=false,
        |f|f.driver_joined=false,|f|f.manager_joined=false,|f|f.observer_joined=false,|f|f.watchdog_joined=false,
        |f|f.retired_before_cutoff=false,|f|f.active_retained=true,|f|f.resource_unknown=true];
    for change in fact_mutations { let mut bad=first.clone();change(&mut bad.facts);
        if final_snapshot(&bad,&inspect,wire::Action::Inspect) { return false; } }
    let mutations: [fn(&mut Snapshot);8] = [|s|s.accepted=false,|s|s.core_terminal=false,|s|s.core_fatal=true,
        |s|s.review_minted=false,|s|s.facts.id="f".repeat(32),|s|s.projection.owner_generation="f".repeat(32),
        |s|s.projection.context.draft_revision+=1,|s|s.projection.phase=wire::Phase::Unknown];
    for change in mutations { let mut bad=first.clone();change(&mut bad);
        if final_snapshot(&bad,&inspect,wire::Action::Inspect) { return false; } }
    let mut prior=status(inspect.clone());prior.availability=wire::Availability::Busy;
    for phase in [wire::Phase::Starting,wire::Phase::Running] {
        let p=prior.operation.as_mut().unwrap();p.phase=phase;p.intent_usable=false;
        if settled_status(&prior,&first.projection,&inspect) != Ok(false) { return false; }
    }
    prior.operation=Some(first.projection.clone());
    if settled_status(&prior,&first.projection,&inspect) != Ok(false)
        || settled_status(&status(first.projection.clone()),&first.projection,&inspect) != Ok(true) { return false; }
    for p in [second.projection.clone(),wire::Projection {phase:wire::Phase::Unknown,..first.projection.clone()},
        wire::Projection {outcome:Some(wire::Outcome::Failed),..first.projection.clone()}] {
        if settled_status(&status(p),&first.projection,&inspect).is_ok() { return false; }
    }
    let claims=AtomicU8::new(0);
    if claim_transition(&claims,wire::Action::Recover) || !claim_transition(&claims,wire::Action::Inspect)
        || claim_transition(&claims,wire::Action::Inspect) || !claim_transition(&claims,wire::Action::Recover)
        || claim_transition(&claims,wire::Action::Recover) || claim_transition(&claims,wire::Action::Inspect) { return false; }
    let mut record=Record::default();
    let request=|action| json!({"projectId":"inert-recovery-data","draftRevision":1,"baselineGeneration":1,"action":action});
    if record.sample_ready(Step::WaitInspect) || record.sample_ready(Step::WaitRecover)
        || record.request(Step::Start,Command::Start,&json!({}),Some("inert-recovery-data"))
        || !record.request(Step::Inspect,Command::Prepare,&request(wire::Action::Inspect),Some("inert-recovery-data"))
        || !record.result(Command::Prepare,&Ok(status(inspect.clone()))) { return false; }
    let start=|p:&wire::Projection| json!({"operationId":p.operation_id,"ownerGeneration":p.owner_generation,"consentVersion":wire::CONSENT});
    if !record.request(Step::Inspect,Command::Start,&start(&inspect),None)
        || !record.result(Command::Start,&Ok(status(first.projection.clone()))) || !record.sample_ready(Step::WaitInspect) { return false; }
    record.originals[0]=Some(first.clone()); record.inspect_visible=true;
    if !record.request(Step::Review,Command::Prepare,&request(wire::Action::Recover),Some("inert-recovery-data")) { return false; }
    let mut wrong=recover.clone();wrong.context.review.as_mut().unwrap().session=Some("f".repeat(32));
    if record.clone().result(Command::Prepare,&Ok(status(wrong)))
        || !record.result(Command::Prepare,&Ok(status(recover.clone())))
        || record.request(Step::Start,Command::Start,&start(&recover),None) { return false; }
    let review=|checked| json!({"state":"ready","checked":checked,"runAvailable":checked,"session":observation.session});
    if record.dom(Step::ReadReview,&review(true)).is_ok()
        || record.dom(Step::ReadReview,&review(false)) != Ok(Some(Step::Acknowledge))
        || record.dom(Step::Acknowledge,&json!({"state":"ready"})) != Ok(Some(Step::ReadChecked))
        || record.dom(Step::ReadChecked,&review(true)) != Ok(Some(Step::Start))
        || !record.request(Step::Start,Command::Start,&start(&recover),None)
        || !record.result(Command::Start,&Ok(status(second.projection.clone()))) || !record.sample_ready(Step::WaitRecover)
        || record.request(Step::Start,Command::Start,&start(&recover),None)
        || record.request(Step::WaitRecover,Command::Cancel,&json!({}),None) { return false; }
    let case=ShellCase::PendingRecovery;
    case.project_name()=="project" && case.quit_id()==2 && case.rounds()==0 && !case.inputs() && !case.loses_document()
        && script(Step::WaitInspect).is_none() && script(Step::WaitRecover).is_none()
}
