//! One finite installed ordinary-record inspection journey. The existing
//! relay observes two real Document originals, then the normal native Quit.
//! This module creates no worker, installation path, project or cleanup owner.
use super::{Case, DocumentBinding, Observation, Step as OuterStep};
use crate::asset_session::{InstallationOriginalFacts, InstallationReadObservation, InstalledMacInstallationWitness};
use crate::installation::{CheckPhase, CheckReason, CheckSettlement, CheckStatus, Matching};
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::Arc;

pub(super) const NAME: &str = "installation-inspection";
pub(super) const CANCELLED_ID: u32 = 1;
pub(super) const MATCHING_ID: u32 = 2;
pub(super) const QUIT_ID: u32 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step { StartCancelled, WaitFirstRead, Cancel, WaitCancelled, StartMatching, WaitMatching }

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct FirstRead { verified_files: u32, verified_bytes: u64 }
impl FirstRead {
    fn checked((files, bytes): (u32, u64)) -> Option<Self> {
        (files > 0 && files as usize <= crate::macos_install_record::FILE_LIMIT
            && bytes > 0 && bytes <= crate::macos_install_record::PAYLOAD_LIMIT)
            .then_some(Self { verified_files: files, verified_bytes: bytes })
    }
    fn valid(self) -> bool { Self::checked((self.verified_files, self.verified_bytes)) == Some(self) }
    fn snapshot(raw: Option<(u32, u64)>) -> Result<Option<Self>, ()> {
        match raw { None => Ok(None), Some(value) => Self::checked(value).map(Some).ok_or(()) }
    }
}
fn status_identity(status: CheckStatus, id: u32) -> bool {
    status.schema_version == 1 && (1..u32::MAX).contains(&status.status_revision)
        && status.available && status.operation_id == Some(id)
}
fn starting(status: CheckStatus, id: u32) -> bool {
    status_identity(status, id) && !status.can_start && status.phase == CheckPhase::Checking
        && status.reason == CheckReason::None && status.settlement == CheckSettlement::Pending
        && status.assessment.is_none()
}
fn status_transition(previous: CheckStatus, next: CheckStatus) -> bool {
    next.status_revision > previous.status_revision || next == previous
}
fn cancellation_status(status: CheckStatus) -> bool {
    status_identity(status, CANCELLED_ID) && status.reason == CheckReason::Cancelled
        && status.assessment.is_none()
        && ((status.phase == CheckPhase::Stopping && status.settlement == CheckSettlement::Pending && !status.can_start)
            || (status.phase == CheckPhase::Refused && status.settlement == CheckSettlement::Known && status.can_start))
}
fn matching_status(status: CheckStatus) -> bool {
    status_identity(status, MATCHING_ID) && status.can_start && status.phase == CheckPhase::Observed
        && status.reason == CheckReason::None && status.settlement == CheckSettlement::Known
        && status.assessment.is_some_and(|value| value.bytes > 0
            && Matching::checked(value.files as usize, value.bytes) == Some(value))
}
fn joined(facts: InstallationOriginalFacts) -> bool {
    facts.normal_coordinator_joined && facts.normal_child_joined && facts.native_settled
        && facts.storage_disposed && facts.resources_settled
}

struct Active {
    started: CheckStatus, last: CheckStatus,
    // This exact Arc is returned with started by the core. It was attached to
    // that OriginalWork before GO; no observation is attached after dispatch.
    observation: Arc<InstallationReadObservation>, first_read: Option<FirstRead>,
    cancel_requested: bool, cancel_returned: bool,
}
impl Active {
    fn update(&mut self, status: CheckStatus, id: u32) -> bool {
        if !status_identity(status, id) || !status_transition(self.last, status) { return false; }
        self.last = status; true
    }
    fn complete(&self, first_read: FirstRead, facts: InstallationOriginalFacts) -> Completed {
        Completed { started: self.started, status: self.last, first_read, facts,
            cancel_requested: self.cancel_requested, cancel_returned: self.cancel_returned }
    }
}
#[derive(Clone, Copy)]
struct Completed {
    started: CheckStatus, status: CheckStatus, first_read: FirstRead,
    facts: InstallationOriginalFacts, cancel_requested: bool, cancel_returned: bool,
}
impl Completed {
    fn same(&self, other: &Self) -> bool {
        let facts = |row: InstallationOriginalFacts| [row.normal_coordinator_joined, row.normal_child_joined,
            row.native_settled, row.storage_disposed, row.resources_settled, row.stopped];
        self.started == other.started && self.status == other.status && self.first_read == other.first_read
            && self.cancel_requested == other.cancel_requested && self.cancel_returned == other.cancel_returned
            && facts(self.facts) == facts(other.facts)
    }
    fn valid(&self, cancelled: bool) -> bool {
        let id = if cancelled { CANCELLED_ID } else { MATCHING_ID };
        starting(self.started, id) && status_identity(self.status, id)
            && self.status.status_revision > self.started.status_revision
            && self.first_read.valid() && joined(self.facts) && self.facts.stopped == cancelled
            && self.cancel_requested == cancelled && self.cancel_returned == cancelled
            && if cancelled { cancellation_status(self.status) && self.status.settlement == CheckSettlement::Known }
                else { matching_status(self.status) && self.status.assessment.is_some_and(|assessment|
                    self.first_read.verified_files <= assessment.files && self.first_read.verified_bytes <= assessment.bytes) }
    }
    fn value(&self) -> Value {
        json!({"start":self.started,"firstRead":self.first_read,"cancelRequestedOnce":self.cancel_requested,
            "cancelReturned":self.cancel_returned,"status":self.status,"originals":self.facts})
    }
}
#[derive(Default)]
pub(super) struct Record {
    active: Option<Active>, cancelled: Option<Completed>, matching: Option<Completed>, normal_quit: bool,
    // Captured once before the first inspection, retained through normal Quit.
    // Only immutable original identity: no native handle or project authority.
    witness: Option<Arc<InstalledMacInstallationWitness>>,
}
impl Record {
    pub(super) fn witness(&self) -> Option<Arc<InstalledMacInstallationWitness>> { self.witness.clone() }
    fn completed(&self) -> bool {
        self.active.is_none() && self.cancelled.as_ref().is_some_and(|row| row.valid(true))
            && self.matching.as_ref().is_some_and(|row| row.valid(false))
            && self.cancelled.as_ref().zip(self.matching.as_ref()).is_some_and(|(cancelled, matching)|
                matching.started.status_revision > cancelled.status.status_revision)
    }
    pub(super) fn final_originals(&mut self, quit_id: u32, inspection_id: u32, observed_finality: bool) -> bool {
        if quit_id != QUIT_ID || inspection_id != MATCHING_ID || !observed_finality || self.normal_quit || !self.completed() { return false; }
        self.normal_quit = true; true
    }
    pub(super) fn report(&self) -> Option<Value> {
        if !self.normal_quit || !self.completed() { return None; }
        Some(json!({"mechanism":"original-document-ordinary-installation-v1","recordKind":"ordinary",
            "projectSelected":false,"firstReadCancellationBoundary":"completed-file-read-before-exact-original-stop",
            "cancelled":self.cancelled.as_ref()?.value(),"matching":self.matching.as_ref()?.value(),
            "normalQuit":{"operationId":QUIT_ID,"inspectionId":MATCHING_ID,"noProjectFinality":self.normal_quit},
            "limits":{"readOnly":true,"maintenance":"unavailable","network":"not-part-of-this-operation",
                "credentials":"not-part-of-this-operation"}}))
    }
}

// Only the fixed, unsaved Android-shaped fixture's immutable expected DATA.
// Do not clone Fixture wholesale: other variants contain their own histories.
// No descriptor, native owner or project capability is copied by this snapshot.
struct FixtureData {
    root: std::path::PathBuf, uid: u32, root_identity: [u64; 6], app_identity: [u64; 6],
    untouched: [super::FileFact; 3], ignore: super::FileFact,
}
impl FixtureData {
    fn shape(fixture: &super::Fixture) -> bool {
        let fact = |row: &super::FileFact| row.sha256.len() == 64
            && row.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        fixture.root.is_absolute() && fixture.root.to_str().is_some_and(|s| s.len() <= 1024)
            && fixture.app_identity.is_some() && fixture.untouched.as_ref().is_some_and(|rows| rows.iter().all(fact))
            && fact(&fixture.ignore) && fixture.config.is_none() && fixture.release.is_none()
            && fixture.ios.is_none() && fixture.project_fields.is_none() && fixture.recovery.is_none()
            && fixture.local_edits.is_none() && fixture.checks.is_none() && !fixture.written && !fixture.mutated
    }
    fn capture(fixture: &super::Fixture) -> Option<Self> {
        if !Self::shape(fixture) { return None; }
        Some(Self { root: fixture.root.clone(), uid: fixture.uid, root_identity: fixture.root_identity,
            app_identity: fixture.app_identity?, untouched: fixture.untouched.as_ref()?.clone(), ignore: fixture.ignore.clone() })
    }
    fn matches(&self, fixture: &super::Fixture) -> bool {
        Self::shape(fixture) && self.root == fixture.root && self.uid == fixture.uid
            && self.root_identity == fixture.root_identity && Some(self.app_identity) == fixture.app_identity
            && Some(&self.untouched) == fixture.untouched.as_ref() && self.ignore == fixture.ignore
    }
    fn verify(&self) -> Result<(), ()> {
        // Reuse the exact original verifier (including native ACL/xattr reads
        // and consuming FD closes), but with only this bounded copied DATA.
        let expected = super::Fixture { root: self.root.clone(), uid: self.uid, root_identity: self.root_identity,
            app_identity: Some(self.app_identity), untouched: Some(self.untouched.clone()), ignore: self.ignore.clone(),
            config: None, release: None, ios: None, project_fields: None, recovery: None, local_edits: None, checks: None, written: false, mutated: false };
        expected.verify(false)
    }
}

pub(super) struct FinalReadback {
    fixture: FixtureData, cancelled: Completed, matching: Completed, normal_quit: bool,
}
impl FinalReadback {
    pub(super) fn capture(r: &super::Record) -> Option<Self> {
        let record = r.installation_record.as_ref()?;
        if !Self::exit_shape(r) || !record.normal_quit || !record.completed() { return None; }
        Some(Self { fixture: FixtureData::capture(&r.fixture)?, cancelled: *record.cancelled.as_ref()?,
            matching: *record.matching.as_ref()?, normal_quit: record.normal_quit })
    }
    fn exit_shape(r: &super::Record) -> bool {
        no_project(r) && r.step == OuterStep::Exit && r.actual_exit && r.originals_final
            && r.relay_joined && r.pending.is_none() && r.file_readback
    }
    fn originals_match(&self, record: &Record) -> bool {
        record.completed() && record.normal_quit == self.normal_quit
            && record.cancelled.as_ref().is_some_and(|row| row.same(&self.cancelled))
            && record.matching.as_ref().is_some_and(|row| row.same(&self.matching))
    }
    pub(super) fn matches(&self, r: &super::Record) -> bool {
        Self::exit_shape(r) && self.fixture.matches(&r.fixture)
            && r.installation_record.as_ref().is_some_and(|record| self.originals_match(record))
    }
    pub(super) fn verify(&self) -> Result<(), ()> { self.fixture.verify() }
}

pub(super) fn no_project(r: &super::Record) -> bool {
    r.project_calls == 0 && !r.cancel_returned && !r.project_returned && r.project.is_none()
        && r.project_selection.is_none() && r.project_witness.is_none() && r.picker_witness.is_none()
        && !r.cancel_settled && !r.project_settled && r.snapshot_requests == 0 && r.snapshots == 0 && !r.snapshot_pending
        && r.sessions.is_empty() && !r.open_pending && r.prepare_pending.is_none() && r.review_witness.is_none()
        && r.prepared_open.is_none() && r.accessibility.is_none() && r.identity_binding.is_none()
        && r.completion_selection.is_none() && r.open_progress.is_none() && r.panel_history.is_empty()
        && r.file_attached == [false;7] && r.file_actions == [false;7]
        && r.field_attached == [false;super::project_fields::COUNT] && r.field_actions == [false;super::project_fields::COUNT]
        && r.session_record.is_none() && r.ios_record.is_none() && r.project_field_record.is_none() && r.vault_record.is_none()
        && !r.reload_requested && !r.reload_returned && !r.reload_navigation && !r.loss_seen && !r.loss_settled
        && !r.fixture.written && !r.fixture.mutated
}
impl Observation {
    pub(super) fn installation_tick(self: &Arc<Self>, document: &DocumentBinding, step: Step) {
        if self.case != Case::Installation || !self.timely() { self.fail_with("installation-original-contract"); return; }
        if matches!(step, Step::StartCancelled | Step::StartMatching) {
            let cancelled = step == Step::StartCancelled;
            let id = if cancelled { CANCELLED_ID } else { MATCHING_ID };
            {
                let Some(r) = self.record() else { return; };
                let Some(record) = r.installation_record.as_ref() else { self.fail_with("installation-original-contract"); return; };
                if r.step != OuterStep::Installation(step) || !no_project(&r) || record.active.is_some()
                    || record.normal_quit || record.matching.is_some()
                    || if cancelled { record.cancelled.is_some() || record.witness.is_some() }
                        else { record.witness.is_none() || !record.cancelled.as_ref().is_some_and(|row| row.valid(true)) } {
                    self.fail_with("installation-original-contract"); return;
                }
            }
            if !self.timely() { return; }
            // No Observation::Record mutex crosses any Document call.
            if cancelled {
                let Some(witness) = document.installed_macos_installation() else {
                    self.fail_with("installation-original-contract"); return;
                };
                let Some(mut r) = self.record() else { return; };
                if !self.timely() { return; }
                if r.step != OuterStep::Installation(step) || !no_project(&r) { self.fail_with("installation-original-contract"); return; }
                let Some(record) = r.installation_record.as_mut() else { self.fail_with("installation-original-contract"); return; };
                if record.active.is_some() || record.normal_quit || record.cancelled.is_some() || record.matching.is_some()
                    || record.witness.is_some() { self.fail_with("installation-original-contract"); return; }
                record.witness = Some(Arc::new(witness));
            }
            if !self.timely() { return; }
            let Ok((started, observation)) = document.inspect_installation_observed(cancelled) else {
                self.fail_with("installation-request-contract"); return;
            };
            if !starting(started, id) { self.fail_with("installation-status-contract"); return; }
            let Some(mut r) = self.record() else { return; };
            if !self.timely() { return; }
            if r.step != OuterStep::Installation(step) || !no_project(&r) { self.fail_with("installation-original-contract"); return; }
            let Some(record) = r.installation_record.as_mut() else { self.fail_with("installation-original-contract"); return; };
            if record.active.is_some() || record.witness.is_none() || !cancelled && !record.cancelled.as_ref().is_some_and(|row|
                row.valid(true) && started.status_revision > row.status.status_revision) {
                self.fail_with("installation-original-contract"); return;
            }
            record.active = Some(Active { started, last: started, observation, first_read: None, cancel_requested: false, cancel_returned: false });
            r.step = OuterStep::Installation(if cancelled { Step::WaitFirstRead } else { Step::WaitMatching });
            return;
        }
        let (id, observation) = {
            let Some(mut r) = self.record() else { return; };
            if r.step != OuterStep::Installation(step) || !no_project(&r) { self.fail_with("installation-original-contract"); return; }
            let Some(active) = r.installation_record.as_mut().and_then(|row| row.active.as_mut()) else {
                self.fail_with("installation-original-contract"); return;
            };
            let id = if step == Step::WaitMatching { MATCHING_ID } else { CANCELLED_ID };
            if !status_identity(active.last, id) { self.fail_with("installation-original-contract"); return; }
            if step == Step::Cancel {
                if active.cancel_requested || active.cancel_returned || !starting(active.last, id)
                    || !active.first_read.is_some_and(FirstRead::valid) {
                    self.fail_with("installation-first-read-contract"); return;
                }
                // Spend before calling the real exact-original cancel. Even an
                // error or a lost Record reply cannot authorize a retry.
                active.cancel_requested = true;
            }
            (id, active.observation.clone())
        };
        if !self.timely() { return; }
        let result = if step == Step::Cancel { document.cancel_installation(id) } else { document.installation_status() };
        let Ok(status) = result else { self.fail_with("installation-request-contract"); return; };
        // These are files/bytes, NEVER an operation id. Identity comes only
        // from the start-returned status and the same pre-GO-bound Arc above.
        // One publication snapshot per tick: None now may become Some on the
        // next tick. A second read must never reinterpret that valid race.
        let raw_first = observation.first_read();
        let Ok(first) = FirstRead::snapshot(raw_first) else { self.fail_with("installation-first-read-contract"); return; };
        let facts = if matches!(step, Step::WaitCancelled | Step::WaitMatching) {
            document.installation_observer_facts(id)
        } else { None };
        let Some(mut r) = self.record() else { return; };
        if !self.timely() { return; }
        if r.step != OuterStep::Installation(step) || !no_project(&r) { self.fail_with("installation-original-contract"); return; }
        let Some(record) = r.installation_record.as_mut() else { self.fail_with("installation-original-contract"); return; };
        let Some(active) = record.active.as_mut() else { self.fail_with("installation-original-contract"); return; };
        if !Arc::ptr_eq(&active.observation, &observation) || !active.update(status, id) {
            self.fail_with("installation-status-contract"); return;
        }
        match step {
            Step::WaitFirstRead => {
                if !starting(status, id) || active.cancel_requested || active.first_read.is_some() {
                    self.fail_with("installation-first-read-contract"); return;
                }
                if let Some(first) = first {
                    active.first_read = Some(first); r.step = OuterStep::Installation(Step::Cancel);
                } // Absent at this tick waits for the next original-bound snapshot.
            },
            Step::Cancel => {
                if !cancellation_status(status) || first != active.first_read || !active.cancel_requested || active.cancel_returned {
                    self.fail_with("installation-status-contract"); return;
                }
                active.cancel_returned = true; r.step = OuterStep::Installation(Step::WaitCancelled);
            },
            Step::WaitCancelled => {
                if !cancellation_status(status) || first != active.first_read || !active.cancel_requested || !active.cancel_returned {
                    self.fail_with("installation-status-contract"); return;
                }
                if status.settlement != CheckSettlement::Known { return; }
                let Some(facts) = facts else { return; };
                if !facts.stopped { self.fail_with("installation-finality-contract"); return; }
                if !joined(facts) { return; } // Same original endpoint, no new owner or allowance.
                let Some(first) = first else { self.fail_with("installation-first-read-contract"); return; };
                let completed = record.active.take().expect("same original checked above").complete(first, facts);
                if !completed.valid(true) || record.cancelled.is_some() { self.fail_with("installation-finality-contract"); return; }
                // Save the real original facts BEFORE replacing its core slot.
                record.cancelled = Some(completed); r.step = OuterStep::Installation(Step::StartMatching);
            },
            Step::WaitMatching => {
                if active.cancel_requested || active.cancel_returned { self.fail_with("installation-original-contract"); return; }
                if starting(status, id) { return; }
                if !matching_status(status) { self.fail_with("installation-status-contract"); return; }
                let Some(first) = first else { self.fail_with("installation-first-read-contract"); return; };
                let Some(facts) = facts else { return; };
                if facts.stopped { self.fail_with("installation-finality-contract"); return; }
                if !joined(facts) { return; }
                let completed = active.complete(first, facts);
                if !completed.valid(false) || active.first_read.is_some() || record.matching.is_some() || record.normal_quit {
                    self.fail_with("installation-finality-contract"); return;
                }
                let Some(cancelled) = record.cancelled.as_ref().copied().filter(|row| row.valid(true)
                    && completed.started.status_revision > row.status.status_revision) else {
                    self.fail_with("installation-finality-contract"); return;
                };
                if r.file_readback { self.fail_with("installation-finality-contract"); return; }
                let Some(fixture) = FixtureData::capture(&r.fixture) else { self.fail_with("installation-finality-contract"); return; };
                // Preserve the same active original and its start-bound Arc.
                // No observer Record guard crosses real filesystem/native I/O.
                drop(r);
                if !self.timely() { return; }
                if fixture.verify().is_err() { self.fail_with("installation-finality-contract"); return; }
                let Some(mut r) = self.record() else { return; };
                if !self.timely() { return; }
                if self.case != Case::Installation || r.step != OuterStep::Installation(Step::WaitMatching)
                    || !no_project(&r) || r.file_readback || !fixture.matches(&r.fixture) {
                    self.fail_with("installation-finality-contract"); return;
                }
                let Some(record) = r.installation_record.as_mut() else { self.fail_with("installation-original-contract"); return; };
                if record.matching.is_some() || record.normal_quit
                    || !record.cancelled.as_ref().is_some_and(|row| row.same(&cancelled))
                    || !record.active.as_ref().is_some_and(|active| Arc::ptr_eq(&active.observation, &observation)
                        && active.first_read.is_none() && active.complete(first, facts).same(&completed)) {
                    self.fail_with("installation-original-contract"); return;
                }
                // Only this same, timely original publishes success before
                // normal Quit stops/disposes its core slot. The Arc is retained
                // above until after the post-readback identity comparison.
                let completed = record.active.take().expect("same original revalidated above").complete(first, facts);
                record.matching = Some(completed);
                if !record.completed() { self.fail_with("installation-finality-contract"); return; }
                r.file_readback = true; r.step = OuterStep::Close;
            },
            Step::StartCancelled | Step::StartMatching => self.fail_with("installation-original-contract"),
        }
    }
}

pub(super) fn data_checks() -> bool {
    // Literal wire DATA only: no Document, file, native API or actual receipt.
    let start = |id, revision| CheckStatus { schema_version: 1, status_revision: revision, available: true,
        can_start: false, operation_id: Some(id), phase: CheckPhase::Checking, reason: CheckReason::None,
        settlement: CheckSettlement::Pending, assessment: None };
    let facts = |stopped| InstallationOriginalFacts { normal_coordinator_joined: true, normal_child_joined: true,
        native_settled: true, storage_disposed: true, resources_settled: true, stopped };
    let first = FirstRead { verified_files: 1, verified_bytes: 7 };
    // Frozen absence remains absence even if a later tick observes publication.
    // Invalid Some is refused rather than confused with not-yet-published None.
    let first_tick = FirstRead::snapshot(None);
    let next_tick = FirstRead::snapshot(Some((1, 7)));
    if first_tick != Ok(None) || next_tick != Ok(Some(first)) { return false; }
    let cancelled = CheckStatus { status_revision: 3, phase: CheckPhase::Refused, reason: CheckReason::Cancelled,
        settlement: CheckSettlement::Known, can_start: true, ..start(CANCELLED_ID, 1) };
    let matched = CheckStatus { status_revision: 5, phase: CheckPhase::Observed, settlement: CheckSettlement::Known,
        can_start: true, assessment: Matching::checked(3, 19), ..start(MATCHING_ID, 4) };
    let row = |cancel| Completed { started: if cancel { start(CANCELLED_ID, 1) } else { start(MATCHING_ID, 4) },
        status: if cancel { cancelled } else { matched }, first_read: first,
        facts: facts(cancel), cancel_requested: cancel, cancel_returned: cancel };
    if !row(true).valid(true) || !row(false).valid(false) || row(true).valid(false) || row(false).valid(true)
        || !status_transition(cancelled, cancelled) || status_transition(cancelled, start(CANCELLED_ID, 1))
        || status_transition(cancelled, CheckStatus { can_start: false, ..cancelled }) { return false; }
    for bad in [(0, 7), (1, 0), (crate::macos_install_record::FILE_LIMIT as u32 + 1, 7),
        (1, crate::macos_install_record::PAYLOAD_LIMIT + 1)] {
        if FirstRead::checked(bad).is_some() || FirstRead::snapshot(Some(bad)).is_ok() { return false; }
    }
    for status in [CheckStatus { operation_id: Some(3), ..matched }, CheckStatus { operation_id: Some(1), ..matched },
        CheckStatus { schema_version: 2, ..matched }, CheckStatus { status_revision: 0, ..matched },
        CheckStatus { status_revision: u32::MAX, ..matched }, CheckStatus { available: false, ..matched },
        CheckStatus { can_start: false, ..matched }, CheckStatus { assessment: None, ..matched },
        CheckStatus { phase: CheckPhase::Unknown, ..matched }, CheckStatus { reason: CheckReason::Cancelled, ..matched },
        CheckStatus { settlement: CheckSettlement::LateKnown, ..matched }, CheckStatus { settlement: CheckSettlement::Unknown, ..matched }] {
        let mut value = row(false); value.status = status; if value.valid(false) { return false; }
    }
    for finality in [InstallationOriginalFacts { normal_coordinator_joined: false, ..facts(false) },
        InstallationOriginalFacts { normal_child_joined: false, ..facts(false) },
        InstallationOriginalFacts { native_settled: false, ..facts(false) },
        InstallationOriginalFacts { storage_disposed: false, ..facts(false) },
        InstallationOriginalFacts { resources_settled: false, ..facts(false) },
        InstallationOriginalFacts { stopped: true, ..facts(false) }] {
        let mut value = row(false); value.facts = finality; if value.valid(false) { return false; }
    }
    let mut value = row(true); value.cancel_returned = false; if value.valid(true) { return false; }
    let mut value = row(true); value.facts.stopped = false; if value.valid(true) { return false; }
    let mut value = row(true); value.status.assessment = Matching::checked(3, 19); if value.valid(true) { return false; }
    let mut value = row(false); value.first_read.verified_bytes = 20; if value.valid(false) { return false; }
    let mut record = Record { cancelled: Some(row(true)), matching: Some(row(false)), ..Record::default() };
    if !record.completed() || record.report().is_some() || record.final_originals(2, 2, true)
        || record.final_originals(3, 1, true) || record.final_originals(3, 2, false)
        || !record.final_originals(3, 2, true) || record.report().is_none() || record.final_originals(3, 2, true) { return false; }
    // Bounded snapshot DATA only; neither capture/matches nor these changes
    // open any file. Actual verify(false) is exercised only by the native run.
    let fixture = || {
        let fact = super::FileFact { identity: [7; 9], sha256: "a".repeat(64) };
        super::Fixture { root: "/private/tmp/inert-installation-fixture".into(), uid: 501,
            root_identity: [8; 6], app_identity: Some([9; 6]),
            untouched: Some([fact.clone(), fact.clone(), fact.clone()]), ignore: fact,
            config: None, release: None, ios: None, project_fields: None, recovery: None, local_edits: None, checks: None, written: false, mutated: false }
    };
    let original = fixture();
    let Some(frozen) = FixtureData::capture(&original) else { return false; };
    if !frozen.matches(&original) { return false; }
    let mut changed = fixture(); changed.uid += 1; if frozen.matches(&changed) { return false; }
    let mut changed = fixture(); changed.root.push("other"); if frozen.matches(&changed) { return false; }
    let mut changed = fixture(); changed.root_identity[5] += 1; if frozen.matches(&changed) { return false; }
    let mut changed = fixture(); changed.app_identity.as_mut().unwrap()[0] += 1; if frozen.matches(&changed) { return false; }
    let mut changed = fixture(); changed.untouched.as_mut().unwrap()[1].identity[7] += 1; if frozen.matches(&changed) { return false; }
    let mut changed = fixture(); changed.ignore.sha256 = "b".repeat(64); if frozen.matches(&changed) { return false; }
    let mut changed = fixture(); changed.config = Some(changed.ignore.clone()); if FixtureData::capture(&changed).is_some() { return false; }
    let mut changed = fixture(); changed.release = Some([1; 6]); if FixtureData::capture(&changed).is_some() { return false; }
    let mut changed = fixture(); changed.written = true; if FixtureData::capture(&changed).is_some() { return false; }
    let mut changed = fixture(); changed.mutated = true; if FixtureData::capture(&changed).is_some() { return false; }
    let mut changed = fixture(); changed.untouched = None; if FixtureData::capture(&changed).is_some() { return false; }
    let mut changed = fixture(); changed.app_identity = None; if FixtureData::capture(&changed).is_some() { return false; }
    let mut changed = fixture(); changed.ignore.sha256.push('a'); if FixtureData::capture(&changed).is_some() { return false; }
    let mut changed = fixture(); changed.root = format!("/{}", "x".repeat(1024)).into(); if FixtureData::capture(&changed).is_some() { return false; }
    let final_readback = FinalReadback { fixture: frozen, cancelled: row(true), matching: row(false), normal_quit: true };
    if !final_readback.originals_match(&record) { return false; }
    record.normal_quit = false; if final_readback.originals_match(&record) { return false; } record.normal_quit = true;
    record.matching.as_mut().unwrap().status.status_revision += 1;
    if final_readback.originals_match(&record) { return false; } record.matching = Some(row(false));
    record.cancelled.as_mut().unwrap().first_read.verified_bytes += 1;
    if final_readback.originals_match(&record) { return false; } record.cancelled = Some(row(true));
    let mut changed = row(false); changed.facts.storage_disposed = false;
    if changed.same(&row(false)) || !row(false).same(&row(false)) { return false; }
    true
}
