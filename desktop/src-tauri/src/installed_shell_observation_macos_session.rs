//! Closed synthetic input observations through the original Mac document/UI.
//! No captured bytes, native response, assessment or release result is injected.
use std::{path::{Path, PathBuf}, os::unix::fs::MetadataExt};
use serde_json::{json, Value};
use crate::{asset_commands as input, asset_session::{AssetStatus, DocumentBinding, InstalledMacSessionSnapshot},
    ios_archive_protocol as wire};
use super::{ios::Case, Observation};

// Mechanical DER envelopes from credential_apple's existing inert fixtures.
// They are deliberately not usable Apple signing material.
pub(super) const PFX: &[u8] = b"\x30\x30\x02\x01\x03\x30\x2b\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01\xa0\x1e\x04\x1c\x70\x72\x69\x76\x61\x74\x65\x2d\x65\x6e\x76\x65\x6c\x6f\x70\x65\x2d\x6f\x6e\x6c\x79\x2d\x63\x61\x6e\x61\x72\x79";
pub(super) const PROFILE: &[u8] = b"\x30\x43\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02\xa0\x36\x30\x34\x02\x01\x01\x31\x00\x30\x2b\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01\xa0\x1e\x04\x1c\x70\x72\x69\x76\x61\x74\x65\x2d\x65\x6e\x76\x65\x6c\x6f\x70\x65\x2d\x6f\x6e\x6c\x79\x2d\x63\x61\x6e\x61\x72\x79\x31\x00";
pub(super) const FIREBASE: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>BUNDLE_ID</key><string>org.example.mrk.observed</string></dict></plist>\n";

pub(super) fn count(case: Case) -> usize { if case.signed() { 2 } else if case == Case::SigningInputs { 7 } else { 0 } }
pub(super) fn role(index: u8) -> Option<&'static str> { ["p12", "profile", "firebase", "overlap", "link", "public", "cancel"].get(usize::from(index)).copied() }
fn kind(index: u8) -> Option<&'static str> { match index { 0 | 3..=6 => Some("apple-p12"), 1 => Some("apple-profile"), 2 => Some("ios-firebase"), _ => None } }
fn source_state(index: u8) -> Option<(&'static str, &'static str)> { match index {
    0..=2 => Some(("captured", "none")), 3 => Some(("refused", "project-overlap")),
    4 | 5 => Some(("refused", "source-refused")), 6 => Some(("pending", "user-cancelled")), _ => None,
} }
pub(super) fn choose_id(case: Case, index: u8) -> Option<u32> {
    if usize::from(index) >= count(case) { return None; }
    if case.signed() { Some(if index == 0 { 2 } else { 7 }) }
    else { [2, 4, 6, 8, 9, 10, 11].get(usize::from(index)).copied() }
}
pub(super) fn file_index(case: Case, id: u32) -> Option<u8> { (0..count(case) as u8).find(|index| choose_id(case, *index) == Some(id)) }
fn input_root(project: &Path, case: Case) -> Option<PathBuf> { Some(project.parent()?.join("state").join(case.name()).join("inputs")) }
pub(super) fn targets(project: &Path, case: Case) -> Option<Vec<PathBuf>> {
    if !case.inputs() { return Some(Vec::new()); }
    let root = input_root(project, case)?;
    let mut paths = vec![root.join("synthetic.p12"), root.join("synthetic.mobileprovision")];
    if !case.signed() { paths.extend([root.join("GoogleService-Info.plist"), project.join("overlap.p12"),
        root.join("linked.p12"), root.join("public.p12"), root.join("synthetic.p12")]); }
    Some(paths)
}
struct LinkFact { identity: [u64; 9] }
fn link_fact(path: &Path, uid: u32) -> Result<LinkFact, ()> {
    let before = std::fs::symlink_metadata(path).map_err(|_| ())?;
    if !before.file_type().is_symlink() || before.uid() != uid || before.nlink() != 1
        || std::fs::read_link(path).map_err(|_| ())? != Path::new("synthetic.p12") { return Err(()); }
    let identity = super::identity(&before)?;
    if super::identity(&std::fs::symlink_metadata(path).map_err(|_| ())?)? != identity { return Err(()); }
    Ok(LinkFact { identity })
}
pub(super) struct Fixture { case: Case, root: [u64; 6], files: Vec<super::FileFact>, link: Option<LinkFact> }
impl Fixture {
    fn entries(case: Case) -> &'static [&'static str] { if case.signed() { &["synthetic.p12", "synthetic.mobileprovision"] }
        else { &["synthetic.p12", "synthetic.mobileprovision", "GoogleService-Info.plist", "linked.p12", "public.p12"] } }
    fn originals(case: Case) -> Vec<(&'static str, &'static [u8], u32)> {
        let mut rows = vec![("synthetic.p12", PFX, 0o600), ("synthetic.mobileprovision", PROFILE, 0o600)];
        if !case.signed() { rows.extend([("GoogleService-Info.plist", FIREBASE, 0o600), ("public.p12", PFX, 0o644)]); }
        rows
    }
    pub(super) fn capture(project: &Path, uid: u32, case: Case) -> Result<Self, ()> {
        if !case.inputs() { return Err(()); }
        let root = input_root(project, case).ok_or(())?;
        let identity = super::directory_with_link(&root, uid, 0o700, Self::entries(case), (!case.signed()).then_some("linked.p12"))?;
        let files = Self::originals(case).into_iter().map(|(name, bytes, mode)| super::file_fact_mode(&root.join(name), bytes, uid, mode)).collect::<Result<Vec<_>, _>>()?;
        let link = if case.signed() { None } else { Some(link_fact(&root.join("linked.p12"), uid)?) };
        Ok(Self { case, root: identity, files, link })
    }
    pub(super) fn verify(&self, project: &Path, uid: u32) -> Result<(), ()> {
        let root = input_root(project, self.case).ok_or(())?;
        if super::directory_with_link(&root, uid, 0o700, Self::entries(self.case), self.link.as_ref().map(|_| "linked.p12"))? != self.root { return Err(()); }
        for ((name, bytes, mode), original) in Self::originals(self.case).into_iter().zip(&self.files) {
            if super::file_fact_mode(&root.join(name), bytes, uid, mode)? != *original { return Err(()); }
        }
        if let Some(original) = &self.link { if link_fact(&root.join("linked.p12"), uid)?.identity != original.identity { return Err(()); } }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step { Navigate, Platform, Purpose, Open, Ready, Kind(u8), Choose(u8), Native(u8), Chosen(u8), Fields(u8),
    Prepare(u8), Prepared(u8), Keep(u8), Kept(u8), Discard(u8, bool), Discarded(u8, bool),
    Reassess(u8), Reassessed(u8), Bind(u8), Bound(u8), Archive, LockPage, Lock, ConfirmLock, Locked, Done }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Command { Status, Open, Context, Choose, Prepare, Delete, Commit, Bind, Discard, Lock }
impl Command { fn index(self) -> usize { self as usize } }
fn command(step: Step) -> Option<Command> { match step {
    Step::Open | Step::Ready => Some(Command::Open), Step::Choose(_) | Step::Native(_) => Some(Command::Choose),
    Step::Prepare(_) | Step::Prepared(_) | Step::Reassess(_) | Step::Reassessed(_) => Some(Command::Prepare),
    Step::Keep(_) | Step::Kept(_) => Some(Command::Commit), Step::Bind(_) | Step::Bound(_) => Some(Command::Bind),
    Step::Discard(..) | Step::Discarded(..) => Some(Command::Discard), Step::ConfirmLock | Step::Locked => Some(Command::Lock), _ => None,
} }
fn index(step: Step) -> Option<u8> { match step {
    Step::Kind(i) | Step::Choose(i) | Step::Native(i) | Step::Chosen(i) | Step::Fields(i) | Step::Prepare(i) | Step::Prepared(i)
        | Step::Keep(i) | Step::Kept(i) | Step::Discard(i, _) | Step::Discarded(i, _) | Step::Reassess(i) | Step::Reassessed(i)
        | Step::Bind(i) | Step::Bound(i) => Some(i), _ => None,
} }
#[derive(Clone, Default)]
struct Row { source: Option<Value>, reason: Option<Value>, native: bool, assessment: Option<Value>,
    record: Option<(String, u32)>, assigned: Option<u32> }
#[derive(Clone)]
pub(super) struct Record {
    case: Case, requests: [u8; 10], returns: [u8; 10], inputs: [u8; 10], status: Value,
    context_revision: Option<u32>, rows: Vec<Row>, completed: usize, locked: bool,
    original_count: usize, all_settled: bool, archive_ready: bool,
}
impl Record {
    pub(super) fn new(case: Case) -> Self { Self { case, requests: [0; 10], returns: [0; 10], inputs: [0; 10],
        status: Value::Null, context_revision: None, rows: vec![Row::default(); count(case)], completed: 0,
        locked: false, original_count: 0, all_settled: false, archive_ready: false } }
    fn request(&mut self, step: Option<Step>, cmd: Command) -> bool {
        if cmd == Command::Status { return true; }
        let Some(step) = step else { return false; };
        let allowed = command(step) == Some(cmd) || cmd == Command::Context && matches!(step, Step::Open | Step::Ready);
        let n = cmd.index();
        if !allowed || self.requests[n] != self.returns[n] || self.requests[n] >= 16
            || cmd == Command::Context && self.requests[n] >= 1 { return false; }
        self.requests[n] += 1; true
    }
    fn input(&mut self, cmd: Command) -> bool {
        let n = cmd.index();
        if self.inputs[n].checked_add(1) != Some(self.requests[n]) { return false; }
        self.inputs[n] += 1; true
    }
    fn returned(&self, cmd: Command) -> bool { self.requests[cmd.index()] > 0 && self.requests[cmd.index()] == self.returns[cmd.index()] }
    fn result<E: serde::Serialize>(&mut self, cmd: Command, result: &Result<AssetStatus, E>) -> bool {
        if cmd == Command::Status { return true; }
        let n = cmd.index();
        if self.returns[n].checked_add(1) != Some(self.requests[n]) { return false; }
        let Ok(status) = result else { return false; };
        let Ok(value) = serde_json::to_value(status) else { return false; };
        if !self.observe_status(&value) { return false; }
        if matches!(cmd, Command::Context | Command::Choose | Command::Prepare | Command::Commit | Command::Bind)
            && self.inputs[n] != self.requests[n] { return false; }
        self.returns[n] += 1; true
    }
    fn observe_status(&mut self, status: &Value) -> bool {
        if status["schemaVersion"] != 2 || !status["persistence"].is_null()
            || status["records"].as_array().is_none_or(|rows| rows.len() > 2)
            || status["assignments"].as_array().is_none_or(|rows| rows.len() > 2)
            || status["operation"]["settlement"].as_str().is_some_and(|s| matches!(s, "unknown" | "late-known")) { return false; }
        if self.status["statusRevision"].as_u64().is_some_and(|old| status["statusRevision"].as_u64().is_some_and(|new| new < old)) { return true; }
        self.status = status.clone(); true
    }
    fn context(&self) -> bool { self.status["mode"] == "session" && self.status["context"]["platform"] == "ios"
        && self.status["context"]["stage"] == "candidate" && self.status["context"]["purpose"] == "signing"
        && self.status["context"]["revision"].as_u64() == self.context_revision.map(u64::from) }
    pub(super) fn native_pending(&self, i: u8) -> bool { usize::from(i) == self.completed && self.rows.get(usize::from(i)).is_some_and(|r| !r.native) }
    pub(super) fn ready_for_native(&self, i: u8, snapshot: &InstalledMacSessionSnapshot) -> bool {
        self.native_pending(i) && self.returned(Command::Choose) && snapshot.originals_settled
            && Some(snapshot.originals as u32) == choose_id(self.case, i)
    }
    pub(super) fn native_finished(&mut self, i: u8, document: &DocumentBinding, target: &Path) -> bool {
        let Some(id) = choose_id(self.case, i) else { return false; };
        let Some(witness) = document.installed_macos_file_original(id, i != 6) else { return false; };
        if !self.native_pending(i) || witness.selected.as_deref() != (i != 6).then_some(target) || !witness.callback_returned { return false; }
        let op = &self.status["operation"];
        // Genuine Cancel sets STOP before Staged::Refused could be published.
        // The ordinary status therefore retains its pending source label even
        // after actual known settlement. The native witness above separately
        // requires that this original's source book never began. Do not turn
        // that display label into either a capture or a fabricated refusal.
        let Some((source, reason)) = source_state(i) else { return false; };
        if op["operationId"] != id || op["operation"] != "choose-file" || op["settlement"] != "known"
            || op["source"] != source || op["reason"] != reason || !self.context()
            || (i < 3 && (op["phase"] != "selected" || op["selectionToken"].as_str().is_none_or(|v| !crate::edit_protocol::token(v))))
            || (i >= 3 && (op["phase"] != "idle" || !op["selectionToken"].is_null() || !op["assessment"].is_null() || !op["preview"].is_null())) { return false; }
        let row = &mut self.rows[usize::from(i)]; row.native = true; row.source = Some(op["source"].clone()); row.reason = Some(op["reason"].clone()); true
    }
    pub(super) fn observe(&mut self, snapshot: &InstalledMacSessionSnapshot) -> bool {
        if snapshot.originals > 12 || !self.observe_status(&snapshot.status) { return false; }
        self.original_count = snapshot.originals; self.all_settled = snapshot.originals_settled; true
    }
    pub(super) fn advance(&mut self, step: Step, snapshot: &InstalledMacSessionSnapshot) -> Result<bool, ()> {
        if !self.observe(snapshot) { return Err(()); }
        let op = &self.status["operation"];
        if let Some(i) = index(step) { if usize::from(i) >= self.rows.len() || usize::from(i) != self.completed { return Err(()); } }
        let ready = match step {
            Step::Ready => {
                if !self.returned(Command::Open) || !self.returned(Command::Context) { return Ok(false); }
                let revision = self.status["context"]["revision"].as_u64().and_then(|n| u32::try_from(n).ok()).filter(|n| *n == 1).ok_or(())?;
                self.context_revision = Some(revision); self.context() && snapshot.originals_settled && snapshot.originals == 1
            },
            Step::Chosen(i) => self.returned(Command::Choose) && snapshot.originals_settled && self.rows[usize::from(i)].native,
            Step::Prepared(i) | Step::Reassessed(i) => {
                if !self.returned(Command::Prepare) || !snapshot.originals_settled || op["phase"] != "preview" { return Ok(false); }
                let reassess = matches!(step, Step::Reassessed(_));
                let expected_id = choose_id(self.case, i).ok_or(())? + if reassess { 3 } else { 1 };
                let assessment = assessment(&op["assessment"], i).ok_or(())?;
                if !self.context() || op["operation"] != "prepare" || op["operationId"] != expected_id
                    || op["settlement"] != "known" || op["preview"]["action"] != if reassess { "bind" } else { "save" }
                    || op["preview"]["subject"]["kind"].as_str() != kind(i) { return Err(()); }
                if reassess {
                    let (id, revision) = self.rows[usize::from(i)].record.as_ref().ok_or(())?;
                    if op["preview"]["subject"]["recordId"].as_str() != Some(id) || op["preview"]["subject"]["recordRevision"] != *revision
                        || self.rows[usize::from(i)].assessment.as_ref() != Some(&assessment) { return Err(()); }
                } else { self.rows[usize::from(i)].assessment = Some(assessment); }
                true
            },
            Step::Kept(i) => {
                if !self.returned(Command::Commit) || !snapshot.originals_settled || op["phase"] != "preview" { return Ok(false); }
                let subject = &op["preview"]["subject"];
                let id = subject["recordId"].as_str().filter(|id| crate::edit_protocol::token(id)).ok_or(())?;
                let records = self.status["records"].as_array().ok_or(())?;
                if op["operation"] != "commit" || op["operationId"] != choose_id(self.case, i).ok_or(())? + 2
                    || op["preview"]["action"] != "bind" || subject["recordRevision"] != 1 || subject["kind"].as_str() != kind(i)
                    || records.len() != usize::from(i) + 1 || records.iter().filter(|r| r["recordId"] == id && r["revision"] == 1
                        && r["kind"].as_str() == kind(i) && r["availability"] == "unassigned" && r["storage"] == "session").count() != 1 { return Err(()); }
                self.rows[usize::from(i)].record = Some((id.to_owned(), 1)); true
            },
            Step::Discarded(_, _) => self.returned(Command::Discard) && snapshot.originals_settled
                && op["phase"] == "idle" && op["preview"].is_null() && op["selectionToken"].is_null(),
            Step::Bound(i) => {
                if !self.returned(Command::Bind) || !snapshot.originals_settled || op["phase"] != "idle" { return Ok(false); }
                let (id, revision) = self.rows[usize::from(i)].record.as_ref().ok_or(())?;
                let context = self.context_revision.ok_or(())?;
                let rows = self.status["assignments"].as_array().ok_or(())?;
                if !self.context() || op["operation"] != "bind" || op["operationId"] != choose_id(self.case, i).ok_or(())? + 4
                    || rows.len() != usize::from(i) + 1 || rows.iter().filter(|r| r["recordId"].as_str() == Some(id)
                        && r["recordRevision"] == *revision && r["contextRevision"] == context
                        && r["kind"].as_str() == kind(i) && r["availability"] == "available").count() != 1 { return Err(()); }
                self.rows[usize::from(i)].assigned = Some(context); true
            },
            Step::Locked => {
                if !self.returned(Command::Lock) || !snapshot.empty || !snapshot.originals_settled || snapshot.originals != 11 { return Ok(false); }
                if op["operationId"] != 11 || op["operation"] != "lock" || op["reason"] != "user-cancelled"
                    || op["phase"] != "idle" || op["settlement"] != "known" { return Err(()); }
                self.locked = true; true
            },
            Step::Archive | Step::Done | Step::Native(_) => false,
            _ => snapshot.originals_settled,
        };
        Ok(ready)
    }
    fn next(&mut self, i: u8) -> Result<Step, ()> {
        if self.completed != usize::from(i) { return Err(()); }
        self.completed += 1;
        if self.completed < self.rows.len() { Ok(Step::Kind(i + 1)) }
        else if self.case.signed() { self.archive_ready = true; Ok(Step::Archive) } else { Ok(Step::Lock) }
    }
    pub(super) fn dom(&mut self, step: Step, value: &Value) -> Result<Step, ()> {
        if value != &json!({"state":"ready"}) { return Err(()); }
        Ok(match step {
            Step::Navigate => Step::Platform, Step::Platform => Step::Purpose, Step::Purpose => Step::Open,
            Step::Open => Step::Ready, Step::Ready => Step::Kind(0), Step::Kind(i) => Step::Choose(i),
            Step::Choose(i) => Step::Native(i),
            Step::Chosen(i) if i >= 3 => self.next(i)?,
            Step::Chosen(0) => Step::Fields(0), Step::Chosen(i) => Step::Prepare(i), Step::Fields(i) => Step::Prepare(i),
            Step::Prepare(i) => Step::Prepared(i),
            Step::Prepared(i) => if self.case.signed() { Step::Keep(i) } else { Step::Discard(i, false) },
            Step::Keep(i) => Step::Kept(i), Step::Kept(i) => Step::Discard(i, true),
            Step::Discard(i, kept) => Step::Discarded(i, kept), Step::Discarded(i, true) => Step::Reassess(i),
            Step::Discarded(i, false) => self.next(i)?, Step::Reassess(i) => Step::Reassessed(i),
            Step::Reassessed(i) => Step::Bind(i), Step::Bind(i) => Step::Bound(i), Step::Bound(i) => self.next(i)?,
            Step::LockPage => Step::Lock, Step::Lock => Step::ConfirmLock, Step::ConfirmLock => Step::Locked,
            Step::Locked if self.locked => Step::Done, _ => return Err(()),
        })
    }
    pub(super) fn signing_policy(&self) -> Option<wire::SigningPolicy> {
        if !self.case.signed() || !self.archive_ready || self.completed != 2 || self.locked { return None; }
        let assignments = self.rows.iter().enumerate().map(|(i, row)| {
            let (id, revision) = row.record.as_ref()?;
            Some(wire::SigningAssignment { kind: kind(i as u8)?.to_owned(), record_id: id.clone(),
                record_revision: *revision, context_revision: row.assigned? })
        }).collect::<Option<Vec<_>>>()?;
        Some(wire::SigningPolicy { team_id: "INERT12345".into(), distribution_certificate_sha256: "c".repeat(64), assignments })
    }
    pub(super) fn final_originals(&mut self, snapshot: &InstalledMacSessionSnapshot) -> bool {
        self.observe(snapshot) && self.locked && snapshot.empty && snapshot.originals_settled && snapshot.originals == 12
    }
    pub(super) fn report(&self, normal_registered: bool) -> Option<Value> {
        let signed = self.case.signed();
        let expected = [0, 1, 1, if signed { 2 } else { 7 }, if signed { 4 } else { 3 },
            0, if signed { 2 } else { 0 }, if signed { 2 } else { 0 }, if signed { 2 } else { 3 }, 1];
        let expected_inputs = [0, 0, 1, expected[3], expected[4], 0, expected[6], expected[7], 0, 0];
        if !normal_registered || !self.case.inputs() || !self.locked || !self.all_settled || self.context_revision != Some(1)
            || self.original_count != 12 || self.completed != self.rows.len()
            || self.requests != expected || self.returns != expected || self.inputs != expected_inputs { return None; }
        let rows = self.rows.iter().enumerate().map(|(i, row)| {
            let (source, reason) = source_state(i as u8)?;
            if !row.native || row.assessment.is_some() != (i < 3)
                || row.source.as_ref().and_then(Value::as_str) != Some(source) || row.reason.as_ref().and_then(Value::as_str) != Some(reason)
                || row.record.is_some() != signed || row.assigned.is_some() != signed
                || signed && (!row.record.as_ref().is_some_and(|r| crate::edit_protocol::token(&r.0) && r.1 == 1)
                    || row.assigned != self.context_revision) { return None; }
            Some(json!({"role":role(i as u8)?,"kind":kind(i as u8)?,"operationId":choose_id(self.case,i as u8)?,
                "nativeResponse":if i == 6 { "decline" } else { "accept" },"exactNativeSelection":if i == 6 { None } else { Some(true) },
                "source":row.source,"reason":row.reason,"originalWorkerAndNativeSettled":true,
                "openIdentityMatched":if i == 6 { None } else { Some(true) },"openInputJoined":if i == 6 { None } else { Some(true) },
                "assessment":row.assessment,"recordId":row.record.as_ref().map(|r| r.0.as_str()),
                "keptRevision":row.record.as_ref().map(|r| r.1),"assignedContextRevision":row.assigned}))
        }).collect::<Option<Vec<_>>>()?;
        Some(json!({"schemaVersion":2,"oneUseOriginalDocumentRegistration":normal_registered,
            "selection":"ordinary-installed-macos-session","mode":"session",
            "context":{"platform":"ios","stage":"candidate","purpose":"signing"},"rows":rows,
            "originalOperations":12,"allOriginalsSettled":true,"memorySessionLocked":true,"originalProjectAndQuitSettled":true,
            "observationMs":if self.case.signed() { 315000 } else { 45000 },"outerInvocationMs":if self.case.signed() { 325000 } else { 60000 }}))
    }
}
fn assessment(value: &Value, i: u8) -> Option<Value> {
    let expected = kind(i)?; let fields = value["fields"].as_array()?;
    let state = if i == 2 { "format-valid" } else { "configured" };
    let identity = if i == 2 { "match" } else { "not-applicable" };
    if value["schemaVersion"] != 1 || value["policyVersion"] != input::POLICY
        || value["kind"] != expected || value["state"] != state || value["identity"] != identity
        || value["context"] != json!({"platform":"ios","stage":"candidate","purpose":"signing"})
        || value["applicability"]["state"] != "required" || value["applicability"]["reason"] != "selected"
        || fields.len() != if i == 0 { 2 } else { 1 }
        || fields.iter().any(|f| f["presence"] != "supplied" || f["state"] != state
            || !f["issues"].as_array().is_some_and(Vec::is_empty)) { return None; }
    let assurance = &value["assurance"];
    if assurance["basis"] != "supplied-input-only" || assurance["nativeValidation"] != "not-run" || assurance["serviceValidation"] != "not-run"
        || assurance["releaseReadiness"] != "unknown" || ["selectedFilesRead","keyringAccessed","storageWritesPerformed","projectCodeExecuted"]
            .iter().any(|key| assurance[*key] != false) { return None; }
    let scopes = fields.iter().flat_map(|f| f["checks"].as_array().into_iter().flatten()).map(|c| c["scope"].as_str()).collect::<Option<Vec<_>>>()?;
    let expected_scopes: &[&str] = match i { 0 => &["pfx-envelope","value-admission"], 1 => &["cms-signed-data-envelope"],
        2 => &["plist-document","firebase-shape","application-identity"], _ => return None };
    let outcomes = fields.iter().flat_map(|f| f["checks"].as_array().into_iter().flatten())
        .map(|c| c["outcome"].as_str()).collect::<Option<Vec<_>>>()?;
    let expected_outcomes: &[&str] = match i { 0 => &["asserted-pass", "passed"], 1 => &["asserted-pass"],
        2 => &["asserted-pass", "passed", "passed"], _ => return None };
    if scopes != expected_scopes || outcomes != expected_outcomes { return None; }
    Some(json!({"state":state,"identity":identity,"fieldScopes":scopes}))
}

/// Small comparison/routing regressions only; no document, file, native panel,
/// worker or persisted report is produced by these synthetic DATA checks.
pub(super) fn data_checks() -> bool {
    for case in Case::ALL {
        let expected: &[u32] = if case.signed() { &[2, 7] } else if case == Case::SigningInputs { &[2, 4, 6, 8, 9, 10, 11] } else { &[] };
        if count(case) != expected.len() || choose_id(case, expected.len() as u8).is_some()
            || file_index(case, 1).is_some() || file_index(case, 12).is_some() { return false; }
        for (i, id) in expected.iter().copied().enumerate() {
            if choose_id(case, i as u8) != Some(id) || file_index(case, id) != Some(i as u8) { return false; }
        }
    }
    let status = json!({"schemaVersion":2,"statusRevision":1,"persistence":null,"records":[],"assignments":[],"operation":null});
    let mut record = Record::new(Case::SigningInputs);
    if !record.observe_status(&status) || record.report(true).is_some() { return false; }
    for (key, replacement) in [("schemaVersion", json!(1)), ("persistence", json!({})),
        ("operation", json!({"settlement":"unknown"})), ("operation", json!({"settlement":"late-known"}))] {
        let mut changed = status.clone(); changed[key] = replacement;
        if record.observe_status(&changed) { return false; }
    }
    if record.request(Some(Step::Open), Command::Bind) || !record.request(Some(Step::Open), Command::Context)
        || record.request(Some(Step::Ready), Command::Context) || !record.input(Command::Context)
        || record.input(Command::Context) { return false; }
    let assessment_value = json!({"schemaVersion":1,"policyVersion":input::POLICY,"kind":"apple-p12",
        "state":"configured","identity":"not-applicable","context":{"platform":"ios","stage":"candidate","purpose":"signing"},
        "applicability":{"state":"required","reason":"selected"},"fields":[
            {"presence":"supplied","state":"configured","issues":[],"checks":[{"scope":"pfx-envelope","outcome":"asserted-pass"}]},
            {"presence":"supplied","state":"configured","issues":[],"checks":[{"scope":"value-admission","outcome":"passed"}]}],
        "assurance":{"basis":"supplied-input-only","nativeValidation":"not-run","serviceValidation":"not-run","releaseReadiness":"unknown",
            "selectedFilesRead":false,"keyringAccessed":false,"storageWritesPerformed":false,"projectCodeExecuted":false}});
    let Some(p12) = assessment(&assessment_value, 0) else { return false; };
    for (pointer, replacement) in [("/assurance/nativeValidation", json!("passed")), ("/fields/0/checks/0/outcome", json!("failed")),
        ("/applicability/state", json!("not-applicable")), ("/identity", json!("match"))] {
        let mut changed = assessment_value.clone(); let Some(field) = changed.pointer_mut(pointer) else { return false; };
        *field = replacement; if assessment(&changed, 0).is_some() { return false; }
    }
    let mut signed = Record::new(Case::SignedRefusal);
    signed.requests = [0,1,1,2,4,0,2,2,2,1]; signed.returns = signed.requests;
    signed.inputs = [0,0,1,2,4,0,2,2,0,0]; signed.context_revision = Some(1);
    signed.completed = 2; signed.locked = true; signed.all_settled = true; signed.original_count = 12;
    for (i, row) in signed.rows.iter_mut().enumerate() {
        row.native = true; row.source = Some(json!("captured")); row.reason = Some(json!("none"));
        row.assessment = Some(if i == 0 { p12.clone() } else { json!({"state":"configured","identity":"not-applicable","fieldScopes":["cms-signed-data-envelope"]}) });
        row.record = Some(((i + 1).to_string().repeat(32),1)); row.assigned = Some(1);
    }
    let Some(report) = signed.report(true) else { return false; };
    if signed.report(false).is_some() || report["schemaVersion"] != 2
        || report["oneUseOriginalDocumentRegistration"] != true || report["selection"] != "ordinary-installed-macos-session"
        || report.get("oneUseOriginalDocumentAdmission").is_some()
        || report["rows"][0]["recordId"] != "1".repeat(32) || report["rows"][1]["recordId"] != "2".repeat(32) { return false; }
    let mut pending = signed.clone(); pending.all_settled = false;
    let mut extra = signed.clone(); extra.requests[Command::Prepare.index()] += 1; extra.returns = extra.requests;
    let mut unassigned = signed.clone(); unassigned.rows[1].assigned = None;
    let mut wrong_revision = signed.clone(); wrong_revision.rows[0].record.as_mut().unwrap().1 = 2;
    pending.report(true).is_none() && extra.report(true).is_none() && unassigned.report(true).is_none() && wrong_revision.report(true).is_none()
}

impl Observation {
    pub(crate) fn session_request(&self, command: Command) {
        if !self.case.inputs() { return; }
        let Some(mut r) = self.record() else { return; };
        let step = if let super::Step::Session(step) = r.step { Some(step) } else { None };
        if !self.timely() || !r.session_record.as_mut().is_some_and(|s| s.request(step, command)) { self.fail_with("session-request-contract"); }
    }
    pub(crate) fn session_result<E: serde::Serialize>(&self, command: Command, result: &Result<AssetStatus,E>) {
        if !self.case.inputs() { return; }
        let Some(mut r) = self.record() else { return; };
        if !self.timely() || !r.session_record.as_mut().is_some_and(|s| s.result(command, result)) { self.fail_with("session-result-contract"); }
    }
    pub(crate) fn session_prepare_result(&self, result: &Result<AssetStatus,input::CommandError>) { self.session_result(Command::Prepare, result); }
    pub(crate) fn session_context_input(&self, args: &input::Context<'_>) {
        if !self.case.inputs() { return; }
        let Some(mut r) = self.record() else { return; };
        if !r.project.as_ref().is_some_and(|p| p.id == args.project_id) || args.draft != &self.base
            || args.platform != input::Platform::Ios || args.stage != input::Stage::Candidate || args.purpose != input::Purpose::Signing
            || !r.session_record.as_mut().is_some_and(|s| s.input(Command::Context)) { self.fail_with("session-request-contract"); }
    }
    pub(crate) fn session_choose_input(&self, args: &input::Choose<'_>) {
        if !self.case.inputs() { return; }
        let Some(mut r) = self.record() else { return; };
        let i = if let super::Step::Session(step) = r.step { index(step) } else { None };
        let valid = r.session_record.as_mut().is_some_and(|s| i.is_some_and(|i| kind(i) == Some(args.kind.name())
            && usize::from(i) == s.completed) && args.replacement.is_none() && s.context_revision == Some(args.context_revision) && s.input(Command::Choose));
        if !valid { self.fail_with("session-request-contract"); }
    }
    pub(crate) fn session_prepare_input(&self, args: &input::Prepare<'_>) {
        if !self.case.inputs() { return; }
        let Some(mut r) = self.record() else { return; };
        let step = if let super::Step::Session(step) = r.step { step } else { self.fail_with("session-request-contract"); return; };
        let Some(s) = r.session_record.as_mut() else { self.fail_with("session-request-contract"); return; };
        let valid = match (step, &args.source) {
            (Step::Prepare(i) | Step::Prepared(i), input::Source::Selection(token)) => s.status["operation"]["selectionToken"].as_str() == Some(*token)
                && args.fields == Some(&if i == 0 { json!({"password":"fictional-p12-password"}) } else { json!({}) }),
            (Step::Reassess(i) | Step::Reassessed(i), input::Source::Record(record)) => args.fields.is_none()
                && s.rows[usize::from(i)].record.as_ref().is_some_and(|(id,revision)| id == record.record_id && *revision == record.expected_revision),
            _ => false,
        };
        if !valid || args.label.is_some() || s.context_revision != Some(args.context_revision) || !s.input(Command::Prepare) { self.fail_with("session-request-contract"); }
    }
    pub(crate) fn session_confirmation_input(&self, token: &str, bind: bool) {
        if !self.case.inputs() { return; }
        let Some(mut r) = self.record() else { return; };
        let Some(s) = r.session_record.as_mut() else { self.fail_with("session-request-contract"); return; };
        if s.status["operation"]["preview"]["token"].as_str() != Some(token)
            || s.status["operation"]["preview"]["action"] != if bind { "bind" } else { "save" }
            || !s.input(if bind { Command::Bind } else { Command::Commit }) { self.fail_with("session-request-contract"); }
    }
}

/// Ordinary controls only. Select changes are explicitly untrusted standard
/// DOM events; no React state, IPC, selection path or result is injected.
pub(super) fn script(step: Step) -> Option<String> {
    let body = match step {
        Step::Navigate | Step::LockPage => "return nav('Credentials');".into(),
        Step::Platform => "return selectValue('Platform','ios');".into(),
        Step::Purpose => "return selectValue('Input purpose','signing');".into(),
        Step::Open => "return click('Start session — keep inputs in memory');".into(),
        Step::Ready => "const p=panel();if(!text(p).includes('Context submitted · not yet policy-validated'))return wait();return ready();".into(),
        Step::Kind(i) => format!("return selectValue('What would you like to provide?',{});", serde_json::to_string(kind(i)?).ok()?),
        Step::Choose(_) => "return click('Select file…');".into(),
        Step::Chosen(i) if i < 3 => "const f=panel().querySelector('form.session-inputs');if(!f)return wait();return ready();".into(),
        Step::Chosen(_) | Step::Discarded(..) => "const p=panel(),s=p.querySelector('.session-progress');if(!s||text(s.querySelector('.badge'))!=='idle'||p.querySelector('[aria-label=\"Explicit private-input review\"]'))return wait();show(s);return ready();".into(),
        Step::Fields(0) => r#"const f=panel().querySelector('form.session-inputs');if(!f)return wait();const fields=f.querySelectorAll('input');if(fields.length!==1)throw 0;
            const i=fields[0];if(!i.id.endsWith('-password')||i.type!=='password'||i.autocomplete!=='new-password'||i.readOnly)throw 0;
            if(i.disabled)return wait();show(i);i.focus();i.select();if(!document.execCommand('insertText',false,'fictional-p12-password'))throw 0;return ready();"#.into(),
        Step::Prepare(_) => "return click('Prepare private review',panel().querySelector('form.session-inputs'));".into(),
        Step::Prepared(_) | Step::Reassessed(_) => r#"const p=panel(),r=p.querySelector('[aria-label="Explicit private-input review"]'),a=p.querySelector('.session-assessment');
            if(!r||!a)return wait();const b=[...r.querySelectorAll('button')].find(b=>['Keep for this session','Assign to this context'].includes(text(b)));
            if(!b||b.disabled)return wait();if(!text(a).includes('Native validation')||!text(a).includes('not run'))throw 0;show(a);show(r);return ready();"#.into(),
        Step::Keep(_) => "return click('Keep for this session',review());".into(),
        Step::Kept(i) => format!("const rows=panel().querySelectorAll('.session-records article');if(rows.length!=={})return wait();if(!text(rows[{}]).includes('Revision 1'))throw 0;show(rows[{}]);return ready();",i+1,i,i),
        Step::Discard(..) => "return click('Discard review',review());".into(),
        Step::Reassess(i) => format!("const rows=panel().querySelectorAll('.session-records article');if(rows.length!=={})return wait();return click('Review assignment',rows[{}]);", i+1,i),
        Step::Bind(_) => "return click('Assign to this context',review());".into(),
        Step::Bound(i) => format!("const rows=panel().querySelectorAll('.session-records article');if(rows.length!=={}||text(rows[{}].querySelector('.badge'))!=='Assigned to current submitted context')return wait();show(rows[{}]);return ready();",i+1,i,i),
        Step::Lock => "return click('Discard session…');".into(),
        Step::ConfirmLock => "return click('Discard session copies',panel().querySelector('[aria-label=\"Confirm private-input lock\"]'));".into(),
        Step::Locked => "const p=panel();if(p.querySelector('.session-records')||!button('Start session — keep inputs in memory',p))return wait();return ready();".into(),
        _ => return None,
    };
    Some(format!(r#"(()=>{{try{{'use strict';
        const text=e=>(e?.textContent??'').trim().replace(/\s+/g,' '),wait=()=>({{state:'wait'}}),ready=()=>({{state:'ready'}});
        const show=e=>{{if(!e||!e.isConnected)throw 0;e.scrollIntoView({{block:'center'}});const r=e.getBoundingClientRect();if(r.width<=0||r.height<=0)throw 0;}};
        const button=(label,root=document)=>[...root.querySelectorAll('button')].find(b=>text(b)===label);
        const panel=()=>{{const p=document.querySelectorAll('.credential-session');if(p.length!==1)throw 0;return p[0];}};
        const review=()=>panel().querySelector('[aria-label="Explicit private-input review"]');
        const click=(label,root)=>{{if(root===null)return wait();const b=button(label,root??panel());if(!b||b.disabled)return wait();show(b);b.click();return ready();}};
        const nav=label=>{{const b=document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="'+label+'"]');if(!b||b.disabled)return wait();show(b);b.click();return ready();}};
        const selectValue=(label,value)=>{{const p=panel(),labels=[...p.querySelectorAll('label')].filter(l=>text(l)===label);if(labels.length!==1)return wait();
            const s=document.getElementById(labels[0].htmlFor);if(!(s instanceof HTMLSelectElement)||s.disabled)return wait();const choices=[...s.options].flatMap((o,i)=>o.value===value?[i]:[]);
            if(choices.length!==1||s.options[choices[0]].disabled)throw 0;show(s);if(s.selectedIndex!==choices[0]){{s.focus();s.selectedIndex=choices[0];s.dispatchEvent(new Event('change',{{bubbles:true}}));}}return ready();}};
        {body}
    }}catch{{return {{state:'error'}}}}}})()"#))
}
