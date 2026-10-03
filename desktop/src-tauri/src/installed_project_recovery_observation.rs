//! Finite installed Q observation: one original document, Inspect then Recover.
//! It neither replaces the engine nor settles an owner. The separate partial
//! case deliberately remains Unknown and can never emit a success receipt.
use std::{path::Path, sync::{Arc, Condvar, Mutex, OnceLock, Weak, atomic::{AtomicBool, AtomicU8, Ordering}}, time::{Duration, Instant}};
use serde::Serialize;
use serde_json::{json, Value};
use tauri::Manager;
use crate::{error::BridgeError, project_recovery_protocol as wire};
use super::{Observation, Case as ShellCase, Step as ShellStep};
pub(crate) use super::commands::OriginalFacts;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Case { Pending, Cancel, CleanupOnly, Partial }
impl Case {
    pub(crate) const ALL: [Self; 4] = [Self::Pending, Self::Cancel, Self::CleanupOnly, Self::Partial];
    pub(crate) fn name(self) -> &'static str { match self {
        Self::Pending => "project-recovery-pending", Self::Cancel => "project-recovery-cancel",
        Self::CleanupOnly => "project-recovery-cleanup-only", Self::Partial => "project-recovery-partial",
    } }
    pub(super) fn parse(value: &std::ffi::OsStr) -> Option<Self> { Self::ALL.into_iter().find(|c| value == std::ffi::OsStr::new(c.name())) }
    pub(super) fn failure_leaf(self) -> &'static str { match self {
        Self::Pending => "shell-project-recovery-pending-failure.labels", Self::Cancel => "shell-project-recovery-cancel-failure.labels",
        Self::CleanupOnly => "shell-project-recovery-cleanup-only-failure.labels", Self::Partial => "shell-project-recovery-partial-failure.labels",
    } }
    pub(super) fn verified_line(self) -> Option<&'static [u8]> { match self {
        Self::Pending => Some(b"MRK_INSTALLED_SHELL_OBSERVATION=project-recovery-pending-verified\n"),
        Self::Cancel => Some(b"MRK_INSTALLED_SHELL_OBSERVATION=project-recovery-cancel-verified\n"),
        Self::CleanupOnly => Some(b"MRK_INSTALLED_SHELL_OBSERVATION=project-recovery-cleanup-only-verified\n"),
        Self::Partial => None,
    } }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Snapshot {
    pub(crate) facts: OriginalFacts, pub(crate) projection: wire::Projection, pub(crate) accepted: bool,
    pub(crate) core_terminal: bool, pub(crate) core_fatal: bool, pub(crate) review_minted: bool,
}
fn io_final(f: &OriginalFacts) -> bool {
    f.domain == "project-recovery" && f.inspection_joined && f.acquisition_joined && f.attempted && !f.no_child
        && f.child_waited_success && f.stdin_closed && f.stdout_eof_closed && f.stderr_eof_closed && f.io_joined
}
fn final_facts(f: &OriginalFacts) -> bool {
    io_final(f) && f.core_lifetime_settled && f.runtime_ledger_settled && f.runtime_settlement_joined
        && f.driver_joined && f.manager_joined && f.observer_joined && f.watchdog_joined
        && f.retired_before_cutoff && !f.active_retained && !f.resource_unknown
}
fn original(snapshot: &Snapshot, prepared: &wire::Projection) -> bool {
    snapshot.facts.id == prepared.operation_id && snapshot.facts.generation == prepared.owner_generation
        && snapshot.projection.operation_id == prepared.operation_id && snapshot.projection.owner_generation == prepared.owner_generation
        && snapshot.projection.context == prepared.context && !snapshot.projection.intent_usable
}
fn retained_unknown(snapshot: &Snapshot) -> bool {
    io_final(&snapshot.facts) && snapshot.accepted && snapshot.core_terminal && snapshot.core_fatal
        && snapshot.facts.resource_unknown && snapshot.facts.active_retained && !snapshot.facts.retired_before_cutoff
        && !snapshot.facts.core_lifetime_settled && !snapshot.facts.runtime_ledger_settled && !snapshot.facts.runtime_settlement_joined
        && snapshot.projection.phase == wire::Phase::Unknown && snapshot.projection.outcome == Some(wire::Outcome::Unknown)
        && snapshot.projection.reason == wire::Reason::CleanupUnknown && snapshot.projection.result.is_none() && !snapshot.review_minted
}
fn claim_transition(claims: &AtomicU8, action: wire::Action) -> bool {
    let (old, next) = if action == wire::Action::Inspect { (0, 1) } else { (1, 3) };
    claims.compare_exchange(old, next, Ordering::SeqCst, Ordering::SeqCst).is_ok()
}
// Only setup constructs this moved token. It carries no path, review stamp,
// result, Session or substitute runtime/worker ownership.
pub(crate) struct Admission { control: Arc<Control>, document: Weak<()>, owner: Weak<()> }
impl Admission {
    pub(crate) fn document_matches(&self, original: &Arc<()>) -> bool {
        self.document.upgrade().is_some_and(|bound| Arc::ptr_eq(&bound, original))
    }
    pub(crate) fn consume(self, original: &Arc<()>) -> Result<Arc<Control>, BridgeError> {
        if self.document.upgrade().is_none() || !self.owner.upgrade().is_some_and(|bound| Arc::ptr_eq(&bound, original)) {
            return Err(BridgeError::invalid());
        }
        self.control.consume()?; Ok(self.control)
    }
}
#[derive(Default)]
struct Hold { entered: bool, released: bool, failed: bool, snapshot: Option<Snapshot> }
#[derive(Default)]
struct Record {
    requests: [u8; 6], replies: [u8; 6], pending: Option<usize>, prepared: [Option<wire::Projection>; 2],
    originals: [Option<Snapshot>; 2], initial: bool, inspect_visible: bool, review_unchecked: bool,
    acknowledged: bool, review_checked: bool, held_observed: bool, peer_refused: bool,
    unknown_visible: bool, status_visible: bool, final_visible: bool, negative_written: bool,
}
pub(crate) struct Control {
    pub(crate) case: Case, original: OnceLock<Weak<Observation>>, document: OnceLock<Weak<()>>,
    issued: AtomicBool, admitted: AtomicBool, claims: AtomicU8, failed: AtomicBool,
    hold: Mutex<Hold>, blocking: Condvar, record: Mutex<Record>, negative: Mutex<Option<rustix::fd::OwnedFd>>,
}
impl Control {
    pub(super) fn new(case: Case) -> Arc<Self> { Arc::new(Self { case, original: OnceLock::new(), document: OnceLock::new(),
        issued: AtomicBool::new(false), admitted: AtomicBool::new(false), claims: AtomicU8::new(0), failed: AtomicBool::new(false),
        hold: Mutex::new(Hold::default()), blocking: Condvar::new(), record: Mutex::new(Record::default()), negative: Mutex::new(None) }) }
    fn original(&self) -> Result<Arc<Observation>, BridgeError> {
        self.original.get().and_then(Weak::upgrade).ok_or_else(BridgeError::invalid)
    }
    fn record(&self) -> Option<std::sync::MutexGuard<'_, Record>> {
        match self.record.lock() { Ok(record) => Some(record), Err(_) => { self.unavailable_witness(); None } }
    }
    pub(crate) fn unavailable_witness(&self) {
        self.failed.store(true, Ordering::SeqCst); if let Ok(q) = self.original() { q.fail(); }
    }
    fn consume(&self) -> Result<(), BridgeError> {
        let q = self.original()?; let r = q.record().ok_or_else(BridgeError::cleanup_unknown)?;
        if !super::route() || q.case != ShellCase::Recovery(self.case) || !r.attached || r.started
            || q.failed.load(Ordering::SeqCst) || self.failed.load(Ordering::SeqCst) || !self.issued.load(Ordering::SeqCst)
            || !q.recovery.as_ref().is_some_and(|o| std::ptr::eq(o.as_ref(), self))
            || self.admitted.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return Err(BridgeError::invalid());
        }
        Ok(())
    }
    pub(crate) fn permits(&self) -> bool {
        self.admitted.load(Ordering::SeqCst) && !self.failed.load(Ordering::SeqCst)
            && self.document.get().and_then(Weak::upgrade).is_some()
            && self.original().is_ok_and(|q| q.case == ShellCase::Recovery(self.case) && !q.failed.load(Ordering::SeqCst)
                && q.recovery.as_ref().is_some_and(|o| std::ptr::eq(o.as_ref(), self)))
    }
    pub(crate) fn claim(&self, action: wire::Action) -> Result<(), BridgeError> {
        if self.permits() && claim_transition(&self.claims, action) { Ok(()) } else { Err(BridgeError::invalid()) }
    }
    pub(crate) fn claimed(&self, action: wire::Action) -> bool {
        self.permits() && self.claims.load(Ordering::SeqCst) == (if action == wire::Action::Inspect { 1 } else { 3 })
    }
    pub(crate) fn cancel_case(&self) -> bool { self.case == Case::Cancel }
    pub(crate) fn prepare_hold(&self, snapshot: Snapshot) -> bool {
        let Ok(mut hold) = self.hold.lock() else { self.unavailable_witness(); return false; };
        if self.case != Case::Cancel || hold.snapshot.is_some() || hold.entered || hold.released
            || snapshot.projection.context.action != wire::Action::Recover || !io_final(&snapshot.facts)
            || !snapshot.accepted || !snapshot.core_terminal || snapshot.core_fatal || !snapshot.facts.core_lifetime_settled
            || !snapshot.facts.active_retained || snapshot.facts.resource_unknown || snapshot.facts.runtime_ledger_settled
            || snapshot.facts.runtime_settlement_joined || snapshot.facts.retired_before_cutoff {
            self.unavailable_witness(); return false;
        }
        hold.snapshot = Some(snapshot); true
    }
    pub(crate) fn hold_settlement(&self, endpoint: Instant) -> bool {
        let end = endpoint.min(Instant::now() + Duration::from_secs(2));
        let Ok(mut hold) = self.hold.lock() else { self.unavailable_witness(); return false; };
        if self.case != Case::Cancel || hold.entered || hold.released || hold.failed || hold.snapshot.is_none() {
            self.unavailable_witness(); return false;
        }
        hold.entered = true;
        while !hold.released {
            let Some(left) = end.checked_duration_since(Instant::now()) else {
                hold.failed = true; self.unavailable_witness(); return false;
            };
            let Ok((next, _)) = self.blocking.wait_timeout(hold, left) else { self.unavailable_witness(); return false; };
            hold = next;
        }
        if Instant::now() >= end { hold.failed = true; self.unavailable_witness(); false } else { !hold.failed }
    }
    fn release_hold(&self) -> bool {
        let Ok(mut hold) = self.hold.lock() else { self.unavailable_witness(); return false; };
        if !hold.entered || hold.failed { self.unavailable_witness(); return false; }
        if !hold.released { hold.released = true; self.blocking.notify_all(); } true
    }
    pub(super) fn attach(self: &Arc<Self>, q: &Arc<Observation>, document: &crate::asset_session::DocumentBinding) -> Result<(), BridgeError> {
        {
            let r = q.record().ok_or_else(BridgeError::cleanup_unknown)?;
            if q.case != ShellCase::Recovery(self.case) || !r.attached || r.started || q.project_path().is_none()
                || self.issued.swap(true, Ordering::SeqCst) { return Err(BridgeError::invalid()); }
            self.original.set(Arc::downgrade(q)).map_err(|_| BridgeError::invalid())?;
        }
        let (original_document, original_owner) = document.installed_recovery_identities();
        self.document.set(original_document.clone()).map_err(|_| BridgeError::invalid())?;
        if self.case == Case::Partial {
            *self.negative.lock().map_err(|_| BridgeError::cleanup_unknown())? = Some(negative_sink().ok_or_else(BridgeError::invalid)?);
        }
        document.admit_installed_recovery(Admission { control: self.clone(), document: original_document, owner: original_owner })
    }
    pub(super) fn snapshot(&self, project_id: &str, result: &Result<Value, BridgeError>) {
        let Ok(q) = self.original() else { self.unavailable_witness(); return; };
        let Some(mut r) = q.record_at(super::Boundary::Result) else { return; };
        if !result.as_ref().is_ok_and(|v| r.project.as_ref().is_some_and(|p| p.id == project_id
            && v["root"].as_str() == Some(p.path.as_str())) && v["observationScope"] == "single-request-non-atomic"
            && v["config"]["path"] == "release/mobile-release.json" && v["config"]["state"] == "missing"
            && v["discovery"]["state"] == "unverified" && v["discovery"]["partial"] == false)
            || r.snapshot_requests != 1 || r.snapshot || !matches!(r.step, ShellStep::Selected | ShellStep::ReadSnapshot) {
            self.unavailable_witness(); return;
        }
        r.snapshot = true;
    }
    pub(super) fn request(&self, command: Command, body: &Value) {
        let Ok(q) = self.original() else { self.unavailable_witness(); return; };
        let Some(shell) = q.record_at(super::Boundary::Request) else { return; };
        let Some(mut r) = self.record() else { return; };
        let step = match shell.step { ShellStep::Recovery(step) => step, _ => {
            if command != Command::Status { self.unavailable_witness(); } return;
        } };
        if command == Command::Status && !matches!(step, Step::Status | Step::ReadStatus) { return; }
        let i = match command {
            Command::Prepare if body["action"] == "inspect" && matches!(step, Step::Inspect | Step::WaitInspect) => 0,
            Command::Start if matches!(step, Step::Inspect | Step::WaitInspect) => 1,
            Command::Prepare if body["action"] == "recover" && matches!(step, Step::Review | Step::ReadReview) => 2,
            Command::Start if matches!(step, Step::Start | Step::WaitRecover) => 3,
            Command::Cancel if matches!(step, Step::Cancel | Step::WaitFinal) => 4,
            Command::Status if matches!(step, Step::Status | Step::ReadStatus) => 5,
            _ => { self.unavailable_witness(); return; },
        };
        if r.requests[i] != 0 || r.pending.is_some() || (i == 2 && !r.inspect_visible)
            || (i == 3 && !r.review_checked) || (i == 4 && !r.held_observed && !r.status_visible)
            || (i == 5 && !r.unknown_visible) { self.unavailable_witness(); return; }
        if matches!(i, 0 | 2) {
            if !shell.project.as_ref().is_some_and(|p| body["projectId"].as_str() == Some(p.id.as_str()))
                || body["draftRevision"].as_u64().is_none() || body["baselineGeneration"].as_u64().is_none() {
                self.unavailable_witness(); return;
            }
        } else if i != 5 {
            let original = r.prepared[if i == 1 { 0 } else { 1 }].as_ref();
            if !original.is_some_and(|p| body["operationId"].as_str() == Some(p.operation_id.as_str())
                && body["ownerGeneration"].as_str() == Some(p.owner_generation.as_str())) {
                self.unavailable_witness(); return;
            }
        }
        r.requests[i] = 1; r.pending = Some(i);
    }
    pub(super) fn returned(&self, command: Command, result: &Result<wire::Status, BridgeError>) {
        let Some(mut r) = self.record() else { return; };
        if command == Command::Status && r.pending != Some(5) { return; }
        let Some(i) = r.pending.take() else { self.unavailable_witness(); return; };
        if !matches!((command, i), (Command::Prepare, 0 | 2) | (Command::Start, 1 | 3) | (Command::Cancel, 4) | (Command::Status, 5))
            || r.replies[i] != 0 { self.unavailable_witness(); return; }
        let Some(operation) = result.as_ref().ok().and_then(|s| s.operation.as_ref()) else { self.unavailable_witness(); return; };
        if matches!(i, 0 | 2) {
            let j = i / 2;
            if r.prepared[j].is_some() || operation.phase != wire::Phase::AwaitingConsent || !operation.intent_usable
                || operation.outcome.is_some() || operation.result.is_some()
                || operation.context.action != if j == 0 { wire::Action::Inspect } else { wire::Action::Recover }
                || (j == 1 && r.prepared[0].as_ref().is_none_or(|prior| prior.operation_id == operation.operation_id
                    || prior.owner_generation == operation.owner_generation || prior.context.project_id != operation.context.project_id
                    || prior.context.draft_revision != operation.context.draft_revision
                    || prior.context.baseline_generation != operation.context.baseline_generation)) {
                self.unavailable_witness(); return;
            }
            r.prepared[j] = Some(operation.clone());
        } else if r.prepared[if i == 1 { 0 } else { 1 }].as_ref().is_none_or(|p|
            p.operation_id != operation.operation_id || p.owner_generation != operation.owner_generation || p.context != operation.context) {
            self.unavailable_witness(); return;
        }
        if i == 4 && (if self.case == Case::Partial { operation.phase != wire::Phase::Unknown || operation.reason != wire::Reason::CleanupUnknown }
            else { operation.reason != wire::Reason::Cancelled || operation.outcome == Some(wire::Outcome::Complete) }) {
            self.unavailable_witness(); return;
        }
        r.replies[i] = 1;
    }
    fn next(&self, q: &Observation, old: Step, next: Step) {
        let Some(mut r) = q.record_at(super::Boundary::Settlement) else { return; };
        if r.step != ShellStep::Recovery(old) || r.pending.is_some() { self.unavailable_witness(); return; }
        r.step = ShellStep::Recovery(next);
    }
    pub(super) fn tick(&self, app: &tauri::AppHandle, step: Step) -> bool {
        if step == Step::Retained { return false; }
        let Ok(q) = self.original() else { self.unavailable_witness(); return false; };
        let state = app.state::<super::super::ShellState>();
        let Ok(status) = state.document.project_recovery_status() else { self.unavailable_witness(); return false; };
        let Some(mut r) = self.record() else { return false; };
        let mut next = None;
        match step {
            Step::Ready => {
                if status.availability != wire::Availability::Available || status.operation.is_some() { return false; }
                r.initial = true;
            },
            Step::WaitInspect => {
                if r.replies[..2] != [1, 1] { return false; }
                let Some(snapshot) = state.bridge.project_recovery.installed_observation_snapshot(wire::Action::Inspect) else { return false; };
                if snapshot.facts.resource_unknown { self.unavailable_witness(); return false; }
                if !snapshot.facts.retired_before_cutoff { return false; }
                let expected = if self.case == Case::CleanupOnly { wire::InspectionStatus::CleanupOnly } else { wire::InspectionStatus::Pending };
                if !r.prepared[0].as_ref().is_some_and(|p| original(&snapshot, p)) || !final_facts(&snapshot.facts)
                    || !snapshot.accepted || !snapshot.core_terminal || snapshot.core_fatal || !snapshot.review_minted
                    || snapshot.projection.phase != wire::Phase::Terminal || snapshot.projection.outcome != Some(wire::Outcome::Complete)
                    || snapshot.projection.reason != wire::Reason::None || !snapshot.projection.result.as_ref().is_some_and(|result|
                        result.action == wire::Action::Inspect && result.observation.as_ref().is_some_and(|o|
                            o.status == expected && o.quiescence == wire::Quiescence::Original && o.eligible())) {
                    self.unavailable_witness(); return false;
                }
                r.originals[0] = Some(snapshot); next = Some(Step::ReadInspect);
            },
            Step::WaitRecover if self.case == Case::Cancel => {
                if r.replies[3] != 1 { return false; }
                let snapshot = { let Ok(hold) = self.hold.lock() else { self.unavailable_witness(); return false; };
                    if !hold.entered { return false; } if hold.failed || hold.released { self.unavailable_witness(); return false; }
                    hold.snapshot.clone() };
                let Some(snapshot) = snapshot else { self.unavailable_witness(); return false; };
                if !r.prepared[1].as_ref().is_some_and(|p| original(&snapshot, p)) || state.bridge.project_recovery.can_exit()
                    || status.operation.as_ref().is_none_or(|op| op.phase == wire::Phase::Terminal || op.outcome == Some(wire::Outcome::Complete))
                    || !peer_refusal(&state.document, &snapshot.projection, false) { self.unavailable_witness(); return false; }
                r.held_observed = true; r.peer_refused = true; next = Some(Step::ReadHeld);
            },
            Step::WaitRecover | Step::WaitFinal => {
                if r.replies[3] != 1 || step == Step::WaitFinal && r.replies[4] != 1 { return false; }
                if self.case == Case::Cancel && step == Step::WaitFinal && !self.release_hold() { return false; }
                let Some(snapshot) = state.bridge.project_recovery.installed_observation_snapshot(wire::Action::Recover) else { return false; };
                if !r.prepared[1].as_ref().is_some_and(|p| original(&snapshot, p)) { self.unavailable_witness(); return false; }
                if self.case == Case::Partial {
                    // Unknown may be published before the original pipe joins.
                    // Observe that actual later boundary; never treat an early
                    // incomplete snapshot as either acceptance or a failure.
                    if !snapshot.facts.resource_unknown || !io_final(&snapshot.facts) { return false; }
                    if !retained_unknown(&snapshot) || state.bridge.project_recovery.can_exit()
                        || status.availability != wire::Availability::CleanupUnknown
                        || !peer_refusal(&state.document, &snapshot.projection, true) { self.unavailable_witness(); return false; }
                    r.peer_refused = true; r.originals[1] = Some(snapshot);
                    next = Some(if step == Step::WaitFinal { Step::ReadRetained } else { Step::ReadUnknown });
                } else {
                    if snapshot.facts.resource_unknown { self.unavailable_witness(); return false; }
                    if !snapshot.facts.retired_before_cutoff { return false; }
                    let outcome = if self.case == Case::Cancel { wire::Outcome::Cancelled } else { wire::Outcome::Complete };
                    if !final_facts(&snapshot.facts) || !snapshot.accepted || !snapshot.core_terminal || snapshot.core_fatal
                        || snapshot.review_minted || snapshot.projection.phase != wire::Phase::Terminal
                        || snapshot.projection.outcome != Some(outcome)
                        || snapshot.projection.reason != if self.case == Case::Cancel { wire::Reason::Cancelled } else { wire::Reason::None }
                        || !state.bridge.project_recovery.can_exit() { self.unavailable_witness(); return false; }
                    r.originals[1] = Some(snapshot); next = Some(Step::ReadFinal);
                }
            },
            _ => {},
        }
        drop(r);
        if let Some(next) = next { self.next(&q, step, next); false } else { true }
    }
    pub(super) fn dom(&self, step: Step, value: &Value) {
        let Ok(q) = self.original() else { self.unavailable_witness(); return; };
        let Some(mut shell) = q.record_at(super::Boundary::Dom) else { return; };
        if shell.step != ShellStep::Recovery(step) || shell.pending.take() != Some(super::Pending::Dom(ShellStep::Recovery(step))) {
            self.unavailable_witness(); return;
        }
        if value == &json!({"state":"wait"}) { return; }
        if value["state"] != "ready" { self.unavailable_witness(); return; }
        let Some(mut r) = self.record() else { return; };
        let next = match step {
            Step::Navigate => Step::Ready,
            Step::Ready if r.initial && value["inspectAvailable"] == true && value["recoverAvailable"] == false => Step::Inspect,
            Step::Inspect => Step::WaitInspect,
            Step::ReadInspect if r.originals[0].is_some() && value["settled"] == true && value["outcome"] == "complete"
                && value["status"] == if self.case == Case::CleanupOnly { "cleanup-only" } else { "pending" }
                && value["recoverAvailable"] == true => { r.inspect_visible = true; Step::Review },
            Step::Review => Step::ReadReview,
            Step::ReadReview if r.replies[2] == 1 && value["checked"] == false && value["runAvailable"] == false => {
                r.review_unchecked = true; Step::Acknowledge
            },
            Step::Acknowledge if r.review_unchecked => { r.acknowledged = true; Step::ReadChecked },
            Step::ReadChecked if r.acknowledged && value["checked"] == true && value["runAvailable"] == true => {
                r.review_checked = true; Step::Start
            },
            Step::Start => Step::WaitRecover,
            Step::ReadHeld if r.held_observed && r.peer_refused && value["pending"] == true
                && value["complete"] == false && value["inspectAvailable"] == false => Step::Cancel,
            Step::ReadUnknown if self.case == Case::Partial && value["unknown"] == true && value["partialWarning"] == true
                && value["inspectAvailable"] == false && value["recoverAvailable"] == false => {
                r.unknown_visible = true; Step::Status
            },
            Step::Status => Step::ReadStatus,
            Step::ReadStatus if r.replies[5] == 1 && value["unknown"] == true => { r.status_visible = true; Step::Cancel },
            Step::Cancel => Step::WaitFinal,
            Step::ReadRetained if r.status_visible && r.replies[4] == 1 && value["unknown"] == true && value["partialWarning"] == true => {
                if !shell_prefix_complete(&shell) || self.negative_report(&mut r).is_none() { self.unavailable_witness(); return; }
                Step::Retained
            },
            Step::ReadFinal if r.originals[1].is_some() && value["settled"] == true
                && value["outcome"] == if self.case == Case::Cancel { "cancelled" } else { "complete" } => {
                r.final_visible = true; shell.step = ShellStep::Close; return;
            },
            _ => { self.unavailable_witness(); return; },
        };
        shell.step = ShellStep::Recovery(next);
    }
    fn positive_complete(&self, r: &Record) -> bool {
        self.case != Case::Partial && !self.failed.load(Ordering::SeqCst) && r.pending.is_none()
            && self.claims.load(Ordering::SeqCst) == 3 && r.requests == [1,1,1,1,u8::from(self.case == Case::Cancel),0]
            && r.replies == r.requests && r.initial && r.inspect_visible && r.review_unchecked && r.acknowledged && r.review_checked
            && r.final_visible && r.originals.iter().all(|o| o.as_ref().is_some_and(|s| final_facts(&s.facts)))
            && (self.case != Case::Cancel || r.held_observed && r.peer_refused && self.hold.lock().is_ok_and(|h| h.entered && h.released && !h.failed))
    }
    pub(super) fn complete(&self) -> bool { self.record().is_some_and(|r| self.positive_complete(&r)) }
    fn report_value(&self, r: &Record, final_application: bool) -> Value {
        json!({"schemaVersion":1,"scope":"project-build-input-recovery-native-observation-v1","case":self.case.name(),
            "sourceCommit":option_env!("GITHUB_SHA"),"testOnlyQualification":true,"applicationFinal":final_application,
            "bootstrapReturned":true,"projectSelectionObserved":true,
            "originals":r.originals,"requests":r.requests,"replies":r.replies,
            "freshUncheckedReview":r.review_unchecked,"explicitAcknowledgement":r.acknowledged,
            "heldSettlementObserved":r.held_observed,"peerAdmissionRefused":r.peer_refused,
            "originalStatusReturned":r.replies[5]==1,"originalCancelReturned":r.replies[4]==1,
            "partialWarningVisible":r.unknown_visible,"finalVisible":r.final_visible,
            "commandDispatches":0,"profileCalls":0,"ordinaryActivation":false})
    }
    pub(super) fn report(&self) -> Option<Vec<u8>> {
        let q = self.original().ok()?;
        if !q.record().is_some_and(|r| shell_prefix_complete(&r)) { return None; }
        let r = self.record()?; if !self.positive_complete(&r) { return None; }
        let raw = serde_json::to_vec(&self.report_value(&r, true)).ok()?;
        (raw.len() <= 8192).then_some(raw)
    }
    fn negative_report(&self, r: &mut Record) -> Option<()> {
        if self.case != Case::Partial || r.negative_written || r.pending.is_some() || !r.peer_refused || !r.unknown_visible
            || r.requests != [1;6] || r.replies != [1;6] || !r.status_visible || self.failed.load(Ordering::SeqCst)
            || self.claims.load(Ordering::SeqCst) != 3 || !r.initial || !r.inspect_visible
            || !r.review_unchecked || !r.acknowledged || !r.review_checked
            || !r.originals[0].as_ref().is_some_and(|s| final_facts(&s.facts) && s.review_minted)
            || !r.originals[1].as_ref().is_some_and(retained_unknown) { return None; }
        let mut raw = serde_json::to_vec(&self.report_value(r, false)).ok()?; raw.push(b'\n');
        if raw.len() > 8192 { return None; }
        let slot = self.negative.lock().ok()?;
        let fd = slot.as_ref()?;
        r.negative_written = true;
        // Deliberately retain this original descriptor with the Unknown app.
        // The parent reads only after its original command has stopped/joined
        // the experiment. A write is observation DATA, not a close receipt.
        (rustix::io::write(fd, &raw).ok() == Some(raw.len())).then_some(())
    }
}

fn shell_prefix_complete(r: &super::Record) -> bool {
    r.info && r.catalog && !r.environment && r.cancelled && r.pickers[0].settled(false)
        && r.selected && r.pickers[1].settled(true) && r.snapshot && r.snapshot_visible
        && r.snapshot_requests == 1 && r.project_witness.is_some() && r.requests == [0; 4]
        && r.sessions.is_empty() && !r.open_pending && r.prepare_pending.is_none()
}

fn peer_refusal(document: &crate::asset_session::DocumentBinding, projection: &wire::Projection, unknown: bool) -> bool {
    use crate::offline_preflight_protocol::Availability;
    let context = &projection.context;
    let Ok(input) = crate::offline_preflight_protocol::prepare(&json!({"projectId":context.project_id,
        "draftRevision":context.draft_revision,"baselineGeneration":context.baseline_generation,
        "savedConfig":{"bytes":1,"sha256":"a".repeat(64)}})) else { return false; };
    let availability = if unknown { Availability::CleanupUnknown } else { Availability::Busy };
    let clear = |status: &crate::offline_preflight_protocol::Status|
        status.availability == availability && status.operation.is_none();
    if !document.offline_preflight_status().is_ok_and(|status| clear(&status)) { return false; }
    // DocumentBinding rejects before allocation. Its typed unavailable error
    // deliberately hides the cleanup detail; the original status supplies it.
    let expected = if unknown { "offline_preflight_unavailable" } else { "offline_preflight_busy" };
    document.prepare_offline_preflight(input).is_err_and(|e| e.code == expected)
        && document.offline_preflight_status().is_ok_and(|status| clear(&status))
}
fn negative_sink() -> Option<rustix::fd::OwnedFd> {
    use std::os::unix::fs::MetadataExt;
    use rustix::fs::{self, Mode, OFlags};
    let root = super::control_root()?;
    for ancestor in root.ancestors() {
        let m = std::fs::symlink_metadata(ancestor).ok()?;
        if !m.is_dir() || m.uid() != 0 || m.gid() != 0 || m.mode() & 0o022 != 0 { return None; }
    }
    let parent = fs::open(&root, OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).ok()?;
    let before = fs::fstat(&parent).ok()?;
    let fd = fs::openat(&parent, "shell-project-recovery-partial.observation", OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK, Mode::empty()).ok()?;
    let item = fs::fstat(&fd).ok()?; let after = fs::fstat(&parent).ok()?;
    let group = rustix::process::getegid();
    if before.st_mode != 0o040711 || before.st_uid != 0 || before.st_gid != 0
        || group.as_raw() == 0 || group != rustix::process::getgid() || item.st_mode != 0o100620
        || item.st_uid != 0 || item.st_gid != group.as_raw() || item.st_nlink != 1 || item.st_size != 0
        || item.st_dev != before.st_dev || (before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid)
            != (after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_gid) { return None; }
    Some(fd)
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command { Prepare, Start, Status, Cancel }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step { Navigate, Ready, Inspect, WaitInspect, ReadInspect, Review, ReadReview, Acknowledge, ReadChecked,
    Start, WaitRecover, ReadHeld, ReadUnknown, Status, ReadStatus, Cancel, WaitFinal, ReadFinal, ReadRetained, Retained }

pub(super) fn script(step: Step, case: Case) -> Option<String> {
    let body = match step {
        Step::Navigate => "const n=document.querySelector('nav[aria-label=\"Workspace navigation\"] button[aria-label=\"Recovery\"]');if(!n||n.disabled)throw 0;n.click();return {state:'ready'};",
        Step::Ready => "if(!card)return {state:'wait'};return {state:'ready',inspectAvailable:available('Inspect build-input state'),recoverAvailable:available('Review recovery attempt')};",
        Step::Inspect => "return click('Inspect build-input state');",
        Step::Review => "return click('Review recovery attempt');",
        Step::ReadReview | Step::ReadChecked => "const g=card?.querySelector('[aria-label=\"Confirm the exact build-input recovery attempt\"]');if(!g)return {state:'wait'};const c=g.querySelector('input[type=checkbox]'),b=button(run,g);if(!c||c.disabled||!b)throw 0;show(g);return {state:'ready',checked:c.checked,runAvailable:!b.disabled};",
        Step::Acknowledge => "const c=card?.querySelector('[aria-label=\"Confirm the exact build-input recovery attempt\"] input[type=checkbox]');if(!c||c.disabled||c.checked)throw 0;show(c);c.click();return {state:'ready'};",
        Step::Start => "return click(run);",
        Step::Cancel => "return click('Cancel original operation');",
        Step::Status => "return click('Check original status');",
        Step::ReadInspect | Step::ReadFinal => "if(!card)return {state:'wait'};const p=card.querySelector('.session-progress'),b=p?.querySelector('.badge');if(text(b)!=='Original operation settled')return {state:'wait'};show(p);const o=[...p.querySelectorAll(':scope > p')].find(n=>text(n).startsWith('Outcome: '));if(!o)throw 0;const review=card.querySelector('.session-review .badge');return {state:'ready',settled:true,outcome:text(o).slice(9),status:text(review),recoverAvailable:available('Review recovery attempt')};",
        Step::ReadHeld => "if(!card)return {state:'wait'};const p=card.querySelector('.session-progress');if(!p)return {state:'wait'};show(p);return {state:'ready',pending:!text(p).includes('Original operation settled'),complete:text(p).includes('Outcome: complete'),inspectAvailable:available('Inspect build-input state')};",
        Step::ReadUnknown | Step::ReadStatus | Step::ReadRetained => "if(!card)return {state:'wait'};const p=card.querySelector('.session-progress');if(text(p?.querySelector('.badge'))!=='Original cleanup unknown')return {state:'wait'};show(p);return {state:'ready',unknown:true,partialWarning:text(p).includes('Cleanup may have partly completed.'),inspectAvailable:available('Inspect build-input state'),recoverAvailable:available('Review recovery attempt')};",
        Step::WaitInspect | Step::WaitRecover | Step::WaitFinal | Step::Retained => return None,
    };
    Some(format!(r#"(() => {{try {{
        const text=n=>n?.textContent?.trim()??'',run={run:?};
        const card=[...document.querySelectorAll('section.card')].find(n=>text(n.querySelector('h2'))==='Recover project build inputs');
        const button=(name,root=card)=>{{const a=root?[...root.querySelectorAll('button')].filter(n=>text(n)===name):[];if(a.length>1)throw 0;return a[0];}};
        const available=name=>{{const b=button(name);return !!b&&!b.disabled;}};
        const show=n=>{{n.scrollIntoView({{block:'center'}});const b=n.getBoundingClientRect();if(b.width<=0||b.height<=0||getComputedStyle(n).visibility!=='visible')throw 0;}};
        const click=name=>{{const b=button(name);if(!b||b.disabled)return {{state:'wait'}};show(b);b.click();return {{state:'ready'}};}};
        {body}
    }}catch{{return {{state:'error'}};}}}})()"#, run=if case == Case::CleanupOnly { "Retire reviewed metadata" } else { "Recover reviewed build inputs" }))
}

pub(super) fn assert_contracts() {
    // Inert DATA only: no Observation, runtime, fixture or positive owner is made.
    for case in Case::ALL {
        assert_eq!(Case::parse(std::ffi::OsStr::new(case.name())), Some(case));
        assert_eq!(case.verified_line().is_none(), case == Case::Partial);
        assert!(!Control::new(case).permits()); assert!(!Control::new(case).complete());
    }
    let claims = AtomicU8::new(0);
    assert!(!claim_transition(&claims, wire::Action::Recover));
    assert!(claim_transition(&claims, wire::Action::Inspect));
    assert!(!claim_transition(&claims, wire::Action::Inspect));
    assert!(claim_transition(&claims, wire::Action::Recover));
    assert!(!claim_transition(&claims, wire::Action::Recover));
    assert!(!claim_transition(&claims, wire::Action::Inspect));
    assert_eq!(claims.load(Ordering::SeqCst), 3);
    let original = Arc::new(()); let foreign = Arc::new(());
    let control = Control::new(Case::Pending);
    let token = Admission { control: control.clone(), document: Arc::downgrade(&original), owner: Arc::downgrade(&original) };
    assert!(token.document_matches(&original)); assert!(!token.document_matches(&foreign));
    assert!(token.consume(&foreign).is_err()); assert!(!control.admitted.load(Ordering::SeqCst));
    let owner = crate::project_recovery_owner::ProjectRecoveryOwner::new(crate::runtime::RuntimeConfig::packaged(Path::new("/unopened-recovery-runtime").into()));
    assert!(owner.can_exit()); assert!(owner.installed_observation_snapshot(wire::Action::Inspect).is_none());
    assert!(owner.installed_observation_snapshot(wire::Action::Recover).is_none());
}
