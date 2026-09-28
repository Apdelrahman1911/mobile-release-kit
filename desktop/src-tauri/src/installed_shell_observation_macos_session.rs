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

// Inert JKS header + opaque remainder, not a usable key or password proof.
pub(super) const JKS: &[u8] = b"\xfe\xed\xfe\xed\x00\x00\x00\x02\x00\x00\x00\x00\xff\x00\x80\xfe";
pub(super) const ANDROID_FIREBASE: &[u8] = br#"{"client":[{"client_info":{"android_client_info":{"package_name":"org.example.mrk.observed"}}}]}"#;
pub(super) const ANDROID_MISMATCH: &[u8] = br#"{"client":[{"client_info":{"android_client_info":{"package_name":"org.example.mrk.other"}}}]}"#;
pub(super) fn count(case: Case) -> usize { if case.signed() { 2 } else if case.input_only() { 7 } else { 0 } }
pub(super) fn role(case: Case, index: u8) -> Option<&'static str> {
    let roles = if case == Case::AndroidInputs { ["keystore", "firebase", "firebase-mismatch", "overlap", "link", "public", "cancel"] }
        else { ["p12", "profile", "firebase", "overlap", "link", "public", "cancel"] };
    (usize::from(index) < count(case)).then(|| roles[usize::from(index)])
}
fn kind(case: Case, index: u8) -> Option<&'static str> {
    if usize::from(index) >= count(case) { return None; }
    if case == Case::AndroidInputs { return match index { 0 | 3..=6 => Some("android-keystore"), 1 | 2 => Some("android-firebase"), _ => None }; }
    match index { 0 | 3..=6 => Some("apple-p12"), 1 => Some("apple-profile"), 2 => Some("ios-firebase"), _ => None }
}
fn source_state(index: u8) -> Option<(&'static str, &'static str)> { match index {
    0..=2 => Some(("captured", "none")), 3 => Some(("refused", "project-overlap")),
    4 | 5 => Some(("refused", "source-refused")), 6 => Some(("pending", "user-cancelled")), _ => None,
} }
pub(super) fn accepted(case: Case, index: u8) -> bool { usize::from(index) < count(case) && index != 6 }
fn kept(case: Case, index: u8) -> bool { case.signed() || case == Case::AndroidInputs && index < 2 }
pub(super) fn lock_original(case: Case) -> u32 { case.session_final_original().and_then(|id| id.checked_sub(1)).unwrap_or(0) }
pub(super) fn quit_original(case: Case) -> u32 { case.session_final_original().unwrap_or(0) }
fn scope(case: Case, revision: u32) -> Value {
    json!({"platform":if case == Case::AndroidInputs { "android" } else { "ios" },
        "stage":if case == Case::AndroidInputs && revision == 2 { "production" } else { "candidate" },
        "purpose":if case == Case::AndroidInputs { "full" } else { "signing" }})
}
fn android_transition() -> Value {
    json!({"previous":scope(Case::AndroidInputs,1),"current":scope(Case::AndroidInputs,2),
        "previousRevision":1,"currentRevision":2,"preservedRecords":2,"assignmentsUnavailable":2,
        "oldPreviewRetired":true,"oldSelectionRetired":true,"originalsSettled":true})
}
fn fields(case: Case, index: u8) -> Value {
    if index != 0 { return json!({}); }
    if case == Case::AndroidInputs { json!({"storePassword":"fictional-store-password", "keyAlias":"fictional-key-alias", "keyPassword":"fictional-key-password"}) }
    else { json!({"password":"fictional-p12-password"}) }
}
pub(super) fn choose_id(case: Case, index: u8) -> Option<u32> {
    if usize::from(index) >= count(case) { return None; }
    if case.signed() { Some(if index == 0 { 2 } else { 7 }) }
    else if case == Case::AndroidInputs { [2, 7, 12, 14, 15, 16, 17].get(usize::from(index)).copied() }
    else { [2, 4, 6, 8, 9, 10, 11].get(usize::from(index)).copied() }
}
pub(super) fn file_index(case: Case, id: u32) -> Option<u8> { (0..count(case) as u8).find(|index| choose_id(case, *index) == Some(id)) }
fn input_root(project: &Path, case: Case) -> Option<PathBuf> { Some(project.parent()?.join("state").join(case.name()).join("inputs")) }
pub(super) fn targets(project: &Path, case: Case) -> Option<Vec<PathBuf>> {
    if !case.inputs() { return Some(Vec::new()); }
    let root = input_root(project, case)?;
    if case == Case::AndroidInputs { return Some(vec![root.join("synthetic.jks"), root.join("google-services.json"),
        root.join("wrong-google-services.json"), project.join("overlap.jks"), root.join("linked.jks"), root.join("public.jks"), root.join("synthetic.jks")]); }
    let mut paths = vec![root.join("synthetic.p12"), root.join("synthetic.mobileprovision")];
    if !case.signed() { paths.extend([root.join("GoogleService-Info.plist"), project.join("overlap.p12"),
        root.join("linked.p12"), root.join("public.p12"), root.join("synthetic.p12")]); }
    Some(paths)
}
struct LinkFact { identity: [u64; 9] }
fn link_fact(path: &Path, target: &str, uid: u32) -> Result<LinkFact, ()> {
    let before = std::fs::symlink_metadata(path).map_err(|_| ())?;
    if !before.file_type().is_symlink() || before.uid() != uid || before.nlink() != 1
        || std::fs::read_link(path).map_err(|_| ())? != Path::new(target) { return Err(()); }
    let identity = super::identity(&before)?;
    if super::identity(&std::fs::symlink_metadata(path).map_err(|_| ())?)? != identity { return Err(()); }
    Ok(LinkFact { identity })
}
pub(super) struct Fixture { case: Case, root: [u64; 6], files: Vec<super::FileFact>, link: Option<LinkFact> }
impl Fixture {
    fn link(case: Case) -> Option<(&'static str, &'static str)> {
        if case.signed() { None } else if case == Case::AndroidInputs { Some(("linked.jks", "synthetic.jks")) }
        else { Some(("linked.p12", "synthetic.p12")) }
    }
    fn entries(case: Case) -> &'static [&'static str] { if case == Case::AndroidInputs {
        &["synthetic.jks", "google-services.json", "wrong-google-services.json", "linked.jks", "public.jks"]
    } else if case.signed() { &["synthetic.p12", "synthetic.mobileprovision"] }
        else { &["synthetic.p12", "synthetic.mobileprovision", "GoogleService-Info.plist", "linked.p12", "public.p12"] } }
    fn originals(case: Case) -> Vec<(&'static str, &'static [u8], u32)> {
        if case == Case::AndroidInputs { return vec![("synthetic.jks", JKS, 0o600), ("google-services.json", ANDROID_FIREBASE, 0o600),
            ("wrong-google-services.json", ANDROID_MISMATCH, 0o600), ("public.jks", JKS, 0o644)]; }
        let mut rows = vec![("synthetic.p12", PFX, 0o600), ("synthetic.mobileprovision", PROFILE, 0o600)];
        if !case.signed() { rows.extend([("GoogleService-Info.plist", FIREBASE, 0o600), ("public.p12", PFX, 0o644)]); }
        rows
    }
    pub(super) fn capture(project: &Path, uid: u32, case: Case) -> Result<Self, ()> {
        if !case.inputs() { return Err(()); }
        let root = input_root(project, case).ok_or(())?;
        let identity = super::directory_with_link(&root, uid, 0o700, Self::entries(case), Self::link(case).map(|(name, _)| name))?;
        let files = Self::originals(case).into_iter().map(|(name, bytes, mode)| super::file_fact_mode(&root.join(name), bytes, uid, mode)).collect::<Result<Vec<_>, _>>()?;
        let link = Self::link(case).map(|(name, target)| link_fact(&root.join(name), target, uid)).transpose()?;
        Ok(Self { case, root: identity, files, link })
    }
    pub(super) fn verify(&self, project: &Path, uid: u32) -> Result<(), ()> {
        let root = input_root(project, self.case).ok_or(())?;
        if super::directory_with_link(&root, uid, 0o700, Self::entries(self.case), Self::link(self.case).map(|(name, _)| name))? != self.root { return Err(()); }
        for ((name, bytes, mode), original) in Self::originals(self.case).into_iter().zip(&self.files) {
            if super::file_fact_mode(&root.join(name), bytes, uid, mode)? != *original { return Err(()); }
        }
        if let Some(original) = &self.link { let (name, target) = Self::link(self.case).ok_or(())?;
            if link_fact(&root.join(name), target, uid)?.identity != original.identity { return Err(()); } }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step { Navigate, Platform, Purpose, Open, Ready, ChangeStage, StageChanged, Kind(u8), Choose(u8), Native(u8), Chosen(u8), Fields(u8),
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
    context_revision: Option<u32>, context_transition: Option<Value>, rows: Vec<Row>, completed: usize, locked: bool,
    original_count: usize, all_settled: bool, archive_ready: bool,
}
impl Record {
    pub(super) fn new(case: Case) -> Self { Self { case, requests: [0; 10], returns: [0; 10], inputs: [0; 10],
        status: Value::Null, context_revision: None, context_transition: None, rows: vec![Row::default(); count(case)], completed: 0,
        locked: false, original_count: 0, all_settled: false, archive_ready: false } }
    fn request(&mut self, step: Option<Step>, cmd: Command) -> bool {
        if cmd == Command::Status { return true; }
        let Some(step) = step else { return false; };
        let initial_context = matches!(step, Step::Open | Step::Ready) && self.requests[Command::Context.index()] == 0;
        let changed_context = self.case == Case::AndroidInputs && matches!(step, Step::ChangeStage | Step::StageChanged)
            && self.completed == 2 && self.context_revision == Some(1) && self.context_transition.is_none()
            && self.requests[Command::Context.index()] == 1;
        let allowed = if cmd == Command::Context { initial_context || changed_context } else { command(step) == Some(cmd) };
        let n = cmd.index();
        if !allowed || self.requests[n] != self.returns[n] || self.requests[n] >= 16 { return false; }
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
    fn context(&self) -> bool {
        let Some(revision) = self.context_revision else { return false; };
        let expected = scope(self.case, revision);
        self.status["mode"] == "session" && self.status["context"]["platform"] == expected["platform"]
            && self.status["context"]["stage"] == expected["stage"] && self.status["context"]["purpose"] == expected["purpose"]
            && self.status["context"]["revision"].as_u64() == Some(u64::from(revision))
    }
    fn retained_android_records(&self) -> bool {
        let (Some(records), Some(assignments)) = (self.status["records"].as_array(), self.status["assignments"].as_array()) else { return false; };
        self.case == Case::AndroidInputs && records.len() == 2 && assignments.len() == 2
            && self.rows[..2].iter().enumerate().all(|(i,row)| row.record.as_ref().is_some_and(|(id,revision)|
                row.assigned == Some(1) && *revision == 1
                    && records.iter().filter(|r| r["recordId"].as_str() == Some(id) && r["revision"] == *revision
                        && r["kind"].as_str() == kind(self.case,i as u8) && r["storage"] == "session" && r["availability"] == "unassigned").count() == 1
                    && assignments.iter().filter(|r| r["recordId"].as_str() == Some(id) && r["recordRevision"] == *revision
                        && r["contextRevision"] == 1 && r["kind"].as_str() == kind(self.case,i as u8)
                        && r["availability"] == "unavailable").count() == 1))
    }
    pub(super) fn native_pending(&self, i: u8) -> bool { usize::from(i) == self.completed && self.rows.get(usize::from(i)).is_some_and(|r| !r.native) }
    pub(super) fn ready_for_native(&self, i: u8, snapshot: &InstalledMacSessionSnapshot) -> bool {
        self.native_pending(i) && self.returned(Command::Choose) && snapshot.originals_settled
            && Some(snapshot.originals as u32) == choose_id(self.case, i)
    }
    pub(super) fn native_finished(&mut self, i: u8, document: &DocumentBinding, target: &Path) -> bool {
        let Some(id) = choose_id(self.case, i) else { return false; };
        let Some(witness) = document.installed_macos_file_original(id, accepted(self.case, i)) else { return false; };
        if !self.native_pending(i) || witness.selected.as_deref() != accepted(self.case, i).then_some(target) || !witness.callback_returned { return false; }
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
        if self.case == Case::AndroidInputs && i >= 2 && !self.retained_android_records() { return false; }
        let row = &mut self.rows[usize::from(i)]; row.native = true; row.source = Some(op["source"].clone()); row.reason = Some(op["reason"].clone()); true
    }
    pub(super) fn observe(&mut self, snapshot: &InstalledMacSessionSnapshot) -> bool {
        if snapshot.originals > quit_original(self.case) as usize || !self.observe_status(&snapshot.status) { return false; }
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
            Step::StageChanged => {
                if self.case != Case::AndroidInputs || self.context_revision != Some(1) || self.context_transition.is_some()
                    || self.completed != 2 { return Err(()); }
                if !self.returned(Command::Context) || self.returns[Command::Context.index()] != 2 || !snapshot.originals_settled { return Ok(false); }
                if self.status["context"]["revision"] != 2 || !self.retained_android_records()
                    || snapshot.originals != 11 || op["phase"] != "idle" || !op["preview"].is_null() || !op["selectionToken"].is_null() { return Err(()); }
                self.context_revision = Some(2);
                if !self.context() { return Err(()); }
                self.context_transition = Some(android_transition());
                true
            },
            Step::Chosen(i) => self.returned(Command::Choose) && snapshot.originals_settled && self.rows[usize::from(i)].native,
            Step::Prepared(i) | Step::Reassessed(i) => {
                if !self.returned(Command::Prepare) || !snapshot.originals_settled { return Ok(false); }
                let reassess = matches!(step, Step::Reassessed(_));
                let mismatch = self.case == Case::AndroidInputs && i == 2;
                if mismatch && reassess { return Err(()); }
                if op["phase"] != if mismatch { "selected" } else { "preview" } { return Ok(false); }
                let expected_id = choose_id(self.case, i).ok_or(())? + if reassess { 3 } else { 1 };
                let assessment = assessment(&op["assessment"], self.case, i, self.context_revision.ok_or(())?).ok_or(())?;
                if !self.context() || op["operation"] != "prepare" || op["operationId"] != expected_id
                    || op["settlement"] != "known" { return Err(()); }
                if mismatch {
                    if !op["preview"].is_null() || op["selectionToken"].as_str().is_none_or(|v| !crate::edit_protocol::token(v))
                        || self.context_transition.is_none() || !self.retained_android_records() { return Err(()); }
                } else if op["preview"]["action"] != if reassess { "bind" } else { "save" }
                    || op["preview"]["subject"]["kind"].as_str() != kind(self.case, i) { return Err(()); }
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
                    || op["preview"]["action"] != "bind" || subject["recordRevision"] != 1 || subject["kind"].as_str() != kind(self.case, i)
                    || records.len() != usize::from(i) + 1 || records.iter().filter(|r| r["recordId"] == id && r["revision"] == 1
                        && r["kind"].as_str() == kind(self.case, i) && r["availability"] == "unassigned" && r["storage"] == "session").count() != 1 { return Err(()); }
                self.rows[usize::from(i)].record = Some((id.to_owned(), 1)); true
            },
            Step::Discarded(i, _) => self.returned(Command::Discard) && snapshot.originals_settled
                && op["phase"] == "idle" && op["preview"].is_null() && op["selectionToken"].is_null()
                && (self.case != Case::AndroidInputs || i != 2 || self.retained_android_records()),
            Step::Bound(i) => {
                if !self.returned(Command::Bind) || !snapshot.originals_settled || op["phase"] != "idle" { return Ok(false); }
                let (id, revision) = self.rows[usize::from(i)].record.as_ref().ok_or(())?;
                let context = self.context_revision.ok_or(())?;
                let rows = self.status["assignments"].as_array().ok_or(())?;
                if !self.context() || op["operation"] != "bind" || op["operationId"] != choose_id(self.case, i).ok_or(())? + 4
                    || rows.len() != usize::from(i) + 1 || rows.iter().filter(|r| r["recordId"].as_str() == Some(id)
                        && r["recordRevision"] == *revision && r["contextRevision"] == context
                        && r["kind"].as_str() == kind(self.case, i) && r["availability"] == "available").count() != 1 { return Err(()); }
                self.rows[usize::from(i)].assigned = Some(context); true
            },
            Step::Locked => {
                if !self.returned(Command::Lock) || !snapshot.empty || !snapshot.originals_settled || snapshot.originals != lock_original(self.case) as usize { return Ok(false); }
                if op["operationId"] != lock_original(self.case) || op["operation"] != "lock" || op["reason"] != "user-cancelled"
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
        if self.case == Case::AndroidInputs && self.completed == 2 { Ok(Step::ChangeStage) }
        else if self.completed < self.rows.len() { Ok(Step::Kind(i + 1)) }
        else if self.case.signed() { self.archive_ready = true; Ok(Step::Archive) } else { Ok(Step::Lock) }
    }
    pub(super) fn dom(&mut self, step: Step, value: &Value) -> Result<Step, ()> {
        if value != &json!({"state":"ready"}) { return Err(()); }
        Ok(match step {
            Step::Navigate => Step::Platform, Step::Platform => Step::Purpose, Step::Purpose => Step::Open,
            Step::Open => Step::Ready, Step::Ready => Step::Kind(0), Step::ChangeStage => Step::StageChanged, Step::StageChanged => Step::Kind(2), Step::Kind(i) => Step::Choose(i),
            Step::Choose(i) => Step::Native(i),
            Step::Chosen(i) if i >= 3 => self.next(i)?,
            Step::Chosen(0) => Step::Fields(0), Step::Chosen(i) => Step::Prepare(i), Step::Fields(i) => Step::Prepare(i),
            Step::Prepare(i) => Step::Prepared(i),
            Step::Prepared(i) => if kept(self.case, i) { Step::Keep(i) } else { Step::Discard(i, false) },
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
            Some(wire::SigningAssignment { kind: kind(self.case, i as u8)?.to_owned(), record_id: id.clone(),
                record_revision: *revision, context_revision: row.assigned? })
        }).collect::<Option<Vec<_>>>()?;
        Some(wire::SigningPolicy { team_id: "INERT12345".into(), distribution_certificate_sha256: "c".repeat(64), assignments })
    }
    pub(super) fn final_originals(&mut self, snapshot: &InstalledMacSessionSnapshot) -> bool {
        self.observe(snapshot) && self.locked && snapshot.empty && snapshot.originals_settled && snapshot.originals == quit_original(self.case) as usize
    }
    pub(super) fn report(&self, normal_registered: bool) -> Option<Value> {
        let signed = self.case.signed();
        let android = self.case == Case::AndroidInputs;
        let expected = if android { [0,1,2,7,5,0,2,2,3,1] } else { [0, 1, 1, if signed { 2 } else { 7 }, if signed { 4 } else { 3 },
            0, if signed { 2 } else { 0 }, if signed { 2 } else { 0 }, if signed { 2 } else { 3 }, 1] };
        let expected_inputs = [0, 0, expected[2], expected[3], expected[4], 0, expected[6], expected[7], 0, 0];
        if !normal_registered || !self.case.inputs() || !self.locked || !self.all_settled || self.context_revision != Some(if android { 2 } else { 1 })
            || self.context_transition.is_some() != android || self.original_count != quit_original(self.case) as usize || self.completed != self.rows.len()
            || self.requests != expected || self.returns != expected || self.inputs != expected_inputs { return None; }
        if android && self.context_transition.as_ref() != Some(&android_transition())
            || self.rows.iter().enumerate().any(|(i,row)| row.record.as_ref().is_some_and(|record|
                self.rows[..i].iter().any(|prior| prior.record.as_ref().is_some_and(|old| old.0 == record.0)))) { return None; }
        let rows = self.rows.iter().enumerate().map(|(i, row)| {
            let (source, reason) = source_state(i as u8)?;
            let keep = kept(self.case, i as u8);
            if !row.native || row.assessment.is_some() != (i < 3)
                || row.source.as_ref().and_then(Value::as_str) != Some(source) || row.reason.as_ref().and_then(Value::as_str) != Some(reason)
                || row.record.is_some() != keep || row.assigned.is_some() != keep
                || keep && (!row.record.as_ref().is_some_and(|r| crate::edit_protocol::token(&r.0) && r.1 == 1)
                    || row.assigned != Some(1)) { return None; }
            Some(json!({"role":role(self.case, i as u8)?,"kind":kind(self.case, i as u8)?,"operationId":choose_id(self.case,i as u8)?,
                "nativeResponse":if accepted(self.case,i as u8) { "accept" } else { "decline" },
                "exactNativeSelection":if accepted(self.case,i as u8) { Some(true) } else { None },
                "source":row.source,"reason":row.reason,"originalWorkerAndNativeSettled":true,
                "openIdentityMatched":if accepted(self.case,i as u8) { Some(true) } else { None },
                "openInputJoined":if accepted(self.case,i as u8) { Some(true) } else { None },
                "assessment":row.assessment,"recordId":row.record.as_ref().map(|r| r.0.as_str()),
                "keptRevision":row.record.as_ref().map(|r| r.1),"assignedContextRevision":row.assigned}))
        }).collect::<Option<Vec<_>>>()?;
        let mut report = json!({"schemaVersion":2,"oneUseOriginalDocumentRegistration":normal_registered,
            "selection":"ordinary-installed-macos-session","mode":"session",
            "context":scope(self.case,self.context_revision?),"rows":rows,
            "originalOperations":quit_original(self.case),"allOriginalsSettled":true,"memorySessionLocked":true,"originalProjectAndQuitSettled":true,
            "observationMs":if signed { 315000 } else { 45000 },"outerInvocationMs":if signed { 325000 } else { 60000 }});
        if let Some(transition) = &self.context_transition { report["contextTransition"] = transition.clone(); }
        Some(report)
    }
}

fn assessment(value: &Value, case: Case, i: u8, revision: u32) -> Option<Value> {
    let expected = kind(case, i)?; let fields = value["fields"].as_array()?;
    let android = case == Case::AndroidInputs;
    let firebase = if android { i == 1 || i == 2 } else { i == 2 };
    let mismatch = android && i == 2;
    let state = if mismatch { "invalid" } else if firebase { "format-valid" } else { "configured" };
    let identity = if mismatch { "mismatch" } else if firebase { "match" } else { "not-applicable" };
    let issues = if mismatch { json!(["identity-mismatch"]) } else { json!([]) };
    if value["schemaVersion"] != 1 || value["policyVersion"] != input::POLICY
        || value["kind"] != expected || value["state"] != state || value["identity"] != identity
        || value["context"] != scope(case, revision)
        || value["applicability"]["state"] != "required" || value["applicability"]["reason"] != "selected"
        || fields.len() != if i == 0 { if android { 4 } else { 2 } } else { 1 }
        || fields.iter().any(|f| f["presence"] != "supplied" || f["state"] != state || f["issues"] != issues) { return None; }
    if android {
        let expected_ids: &[&str] = if i == 0 { &["file","storePassword","keyAlias","keyPassword"] } else { &["file"] };
        if fields.iter().map(|f| f["id"].as_str()).collect::<Option<Vec<_>>>()? != expected_ids { return None; }
    }
    let assurance = &value["assurance"];
    if assurance["basis"] != "supplied-input-only" || assurance["nativeValidation"] != "not-run" || assurance["serviceValidation"] != "not-run"
        || assurance["releaseReadiness"] != "unknown" || ["selectedFilesRead","keyringAccessed","storageWritesPerformed","projectCodeExecuted"]
            .iter().any(|key| assurance[*key] != false) { return None; }
    let scopes = fields.iter().flat_map(|f| f["checks"].as_array().into_iter().flatten()).map(|c| c["scope"].as_str()).collect::<Option<Vec<_>>>()?;
    let expected_scopes: &[&str] = if android { match i {
        0 => &["jks-header","value-admission","value-admission","identifier-format","value-admission"],
        1 | 2 => &["json-document","firebase-shape","application-identity"], _ => return None,
    } } else { match i { 0 => &["pfx-envelope","value-admission"], 1 => &["cms-signed-data-envelope"],
        2 => &["plist-document","firebase-shape","application-identity"], _ => return None } };
    let outcomes = fields.iter().flat_map(|f| f["checks"].as_array().into_iter().flatten())
        .map(|c| c["outcome"].as_str()).collect::<Option<Vec<_>>>()?;
    let expected_outcomes: &[&str] = if android { match i {
        0 => &["asserted-pass","passed","passed","passed","passed"], 1 => &["asserted-pass","passed","passed"],
        2 => &["asserted-pass","passed","failed"], _ => return None,
    } } else { match i { 0 => &["asserted-pass", "passed"], 1 => &["asserted-pass"],
        2 => &["asserted-pass", "passed", "passed"], _ => return None } };
    if scopes != expected_scopes || outcomes != expected_outcomes { return None; }
    let mut result = json!({"state":state,"identity":identity,"fieldScopes":scopes});
    if android { result["fieldOutcomes"] = json!(outcomes); result["issues"] = issues; }
    Some(result)
}

/// Small comparison/routing regressions only; no document, file, native panel,
/// worker or persisted report is produced by these synthetic DATA checks.
pub(super) fn data_checks() -> bool {
    for case in Case::ALL {
        let expected: &[u32] = if case.signed() { &[2, 7] } else if case == Case::SigningInputs { &[2, 4, 6, 8, 9, 10, 11] }
            else if case == Case::AndroidInputs { &[2, 7, 12, 14, 15, 16, 17] } else { &[] };
        let final_id = if case == Case::AndroidInputs { Some(18) } else if case.inputs() { Some(12) } else { None };
        if case.session_final_original() != final_id || quit_original(case) != final_id.unwrap_or(0)
            || lock_original(case) != final_id.and_then(|id| id.checked_sub(1)).unwrap_or(0)
            || count(case) != expected.len() || choose_id(case, expected.len() as u8).is_some()
            || file_index(case, 1).is_some() || file_index(case, quit_original(case)).is_some() { return false; }
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
    let Some(p12) = assessment(&assessment_value, Case::SignedRefusal, 0, 1) else { return false; };
    for (pointer, replacement) in [("/assurance/nativeValidation", json!("passed")), ("/fields/0/checks/0/outcome", json!("failed")),
        ("/applicability/state", json!("not-applicable")), ("/identity", json!("match"))] {
        let mut changed = assessment_value.clone(); let Some(field) = changed.pointer_mut(pointer) else { return false; };
        *field = replacement; if assessment(&changed, Case::SignedRefusal, 0, 1).is_some() { return false; }
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
    if pending.report(true).is_some() || extra.report(true).is_some() || unassigned.report(true).is_some() || wrong_revision.report(true).is_some() { return false; }
    // Android DATA exercises the actual finite request/report comparisons only.
    // No synthetic record escapes as an observed native result.
    let mut android = Record::new(Case::AndroidInputs);
    if android.request(Some(Step::ChangeStage), Command::Context) { return false; }
    android.requests[Command::Context.index()] = 1; android.returns = android.requests; android.inputs = android.requests;
    android.context_revision = Some(1); android.completed = 2;
    if android.request(Some(Step::Kind(2)), Command::Context) || !android.request(Some(Step::ChangeStage), Command::Context)
        || android.request(Some(Step::StageChanged), Command::Context) { return false; }
    let mismatch = json!({"schemaVersion":1,"policyVersion":input::POLICY,"kind":"android-firebase",
        "state":"invalid","identity":"mismatch","context":scope(Case::AndroidInputs,2),
        "applicability":{"state":"required","reason":"selected"},"fields":[{"id":"file","presence":"supplied","state":"invalid",
            "issues":["identity-mismatch"],"checks":[{"scope":"json-document","outcome":"asserted-pass"},
                {"scope":"firebase-shape","outcome":"passed"},{"scope":"application-identity","outcome":"failed"}]}],
        "assurance":assessment_value["assurance"]});
    let Some(mismatch_summary) = assessment(&mismatch, Case::AndroidInputs, 2, 2) else { return false; };
    if assessment(&mismatch, Case::AndroidInputs, 2, 1).is_some() { return false; }
    for (pointer, replacement) in [("/identity",json!("match")),("/fields/0/checks/2/outcome",json!("passed")),("/fields/0/issues",json!([]))] {
        let mut bad = mismatch.clone(); let Some(v) = bad.pointer_mut(pointer) else { return false; }; *v = replacement;
        if assessment(&bad, Case::AndroidInputs, 2, 2).is_some() { return false; }
    }
    android.requests = [0,1,2,7,5,0,2,2,3,1]; android.returns = android.requests;
    android.inputs = [0,0,2,7,5,0,2,2,0,0]; android.context_revision = Some(2); android.context_transition = Some(android_transition());
    android.completed = 7; android.locked = true; android.all_settled = true; android.original_count = 18;
    for (i,row) in android.rows.iter_mut().enumerate() {
        let Some((source,reason)) = source_state(i as u8) else { return false; };
        row.native = true; row.source = Some(json!(source)); row.reason = Some(json!(reason));
        row.assessment = if i == 2 { Some(mismatch_summary.clone()) } else if i < 2 { Some(if i == 0 { json!({"state":"configured","identity":"not-applicable",
            "fieldScopes":["jks-header","value-admission","value-admission","identifier-format","value-admission"],
            "fieldOutcomes":["asserted-pass","passed","passed","passed","passed"],"issues":[]}) }
            else { json!({"state":"format-valid","identity":"match","fieldScopes":["json-document","firebase-shape","application-identity"],
                "fieldOutcomes":["asserted-pass","passed","passed"],"issues":[]}) }) } else { None };
        if i < 2 { row.record = Some(((i + 1).to_string().repeat(32),1)); row.assigned = Some(1); }
    }
    let Some(report) = android.report(true) else { return false; };
    if report["originalOperations"] != 18 || report["context"]["stage"] != "production"
        || report["rows"][2]["recordId"] != Value::Null || android.signing_policy().is_some() { return false; }
    let mut duplicate = android.clone(); duplicate.rows[1].record = duplicate.rows[0].record.clone();
    let mut stale = android.clone(); stale.context_revision = Some(1);
    let mut missing_transition = android.clone(); missing_transition.context_transition = None;
    let mut unknown = android.clone(); unknown.all_settled = false;
    let mut fabricated_assignment = android.clone(); fabricated_assignment.rows[2].record = Some(("f".repeat(32),1));
    for originals in [0, 1, 2, 12, 17, 19] {
        let mut partial = android.clone(); partial.original_count = originals;
        let snapshot = InstalledMacSessionSnapshot { status: status.clone(), originals, originals_settled: true, empty: true };
        if partial.final_originals(&snapshot) || partial.report(true).is_some() { return false; }
    }
    let lock_status = json!({"schemaVersion":2,"statusRevision":1,"persistence":null,"records":[],"assignments":[],
        "operation":{"operationId":17,"operation":"lock","phase":"idle","settlement":"known","reason":"user-cancelled"}});
    let mut lock_record = android.clone(); lock_record.locked = false;
    let locked = InstalledMacSessionSnapshot { status: lock_status.clone(), originals: 17, originals_settled: true, empty: true };
    if lock_record.advance(Step::Locked, &locked) != Ok(true) || !lock_record.locked { return false; }
    for (originals, id) in [(11,11), (16,16), (17,11), (17,18), (18,17)] {
        let mut wrong = lock_status.clone(); wrong["operation"]["operationId"] = json!(id);
        let snapshot = InstalledMacSessionSnapshot { status: wrong, originals, originals_settled: true, empty: true };
        let mut candidate = android.clone(); candidate.locked = false;
        if candidate.advance(Step::Locked, &snapshot) == Ok(true) || candidate.locked { return false; }
    }
    let final_snapshot = InstalledMacSessionSnapshot { status: status.clone(), originals: 18, originals_settled: true, empty: true };
    let mut final_record = android.clone();
    if !final_record.final_originals(&final_snapshot) { return false; }
    for (settled, empty) in [(false, true), (true, false)] {
        let snapshot = InstalledMacSessionSnapshot { status: status.clone(), originals: 18, originals_settled: settled, empty };
        if android.clone().final_originals(&snapshot) { return false; }
    }
    duplicate.report(true).is_none() && stale.report(true).is_none() && missing_transition.report(true).is_none()
        && unknown.report(true).is_none() && fabricated_assignment.report(true).is_none()
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
        let project_matches = r.project.as_ref().is_some_and(|p| p.id == args.project_id) && args.draft == &self.base;
        let valid = r.session_record.as_mut().is_some_and(|s| {
            let android = s.case == Case::AndroidInputs;
            let changed = android && s.requests[Command::Context.index()] == 2;
            project_matches && args.platform == if android { input::Platform::Android } else { input::Platform::Ios }
                && args.stage == if changed { input::Stage::Production } else { input::Stage::Candidate }
                && args.purpose == if android { input::Purpose::Full } else { input::Purpose::Signing }
                && s.input(Command::Context)
        });
        if !valid { self.fail_with("session-request-contract"); }
    }
    pub(crate) fn session_choose_input(&self, args: &input::Choose<'_>) {
        if !self.case.inputs() { return; }
        let Some(mut r) = self.record() else { return; };
        let i = if let super::Step::Session(step) = r.step { index(step) } else { None };
        let valid = r.session_record.as_mut().is_some_and(|s| i.is_some_and(|i| kind(s.case, i) == Some(args.kind.name())
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
                && args.fields == Some(&fields(s.case, i)),
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
pub(super) fn script(case: Case, step: Step) -> Option<String> {
    let body = match step {
        Step::Navigate | Step::LockPage => "return nav('Credentials');".into(),
        Step::Platform => format!("return selectValue('Platform','{}');", if case == Case::AndroidInputs { "android" } else { "ios" }),
        Step::Purpose => format!("return selectValue('Input purpose','{}');", if case == Case::AndroidInputs { "full" } else { "signing" }),
        Step::ChangeStage if case == Case::AndroidInputs => "return selectValue('Release stage','production');".into(),
        Step::StageChanged if case == Case::AndroidInputs => r#"const p=panel(),rows=p.querySelectorAll('.session-records article');
            if(!text(p).includes('Context submitted · not yet policy-validated')||rows.length!==2)return wait();
            if([...rows].some(r=>text(r.querySelector('.badge'))!=='Not assigned to the current draft'))return wait();
            if(p.querySelector('[aria-label="Explicit private-input review"]')||p.querySelector('form.session-inputs'))throw 0;
            rows.forEach(show);return ready();"#.into(),
        Step::Open => "return click('Start session — keep inputs in memory');".into(),
        Step::Ready => "const p=panel();if(!text(p).includes('Context submitted · not yet policy-validated'))return wait();return ready();".into(),
        Step::Kind(i) => format!("return selectValue('What would you like to provide?',{});", serde_json::to_string(kind(case, i)?).ok()?),
        Step::Choose(_) => "return click('Select file…');".into(),
        Step::Chosen(i) if i < 3 => "const f=panel().querySelector('form.session-inputs');if(!f)return wait();return ready();".into(),
        Step::Chosen(_) | Step::Discarded(..) => "const p=panel(),s=p.querySelector('.session-progress');if(!s||text(s.querySelector('.badge'))!=='idle'||p.querySelector('[aria-label=\"Explicit private-input review\"]'))return wait();show(s);return ready();".into(),
        Step::Fields(0) if case == Case::AndroidInputs => r#"const f=panel().querySelector('form.session-inputs');if(!f)return wait();
            const fields=[...f.querySelectorAll('input')],names=['storePassword','keyAlias','keyPassword'],values=['fictional-store-password','fictional-key-alias','fictional-key-password'];
            if(fields.length!==3||fields.some((i,n)=>!i.id.endsWith('-'+names[n])||i.type!=='password'||i.autocomplete!=='new-password'||i.readOnly))throw 0;
            if(fields.some(i=>i.disabled))return wait();
            for(let n=0;n<fields.length;n++){const i=fields[n];show(i);i.focus();i.select();if(!document.execCommand('insertText',false,values[n]))throw 0;}return ready();"#.into(),
        Step::Fields(0) => r#"const f=panel().querySelector('form.session-inputs');if(!f)return wait();const fields=f.querySelectorAll('input');if(fields.length!==1)throw 0;
            const i=fields[0];if(!i.id.endsWith('-password')||i.type!=='password'||i.autocomplete!=='new-password'||i.readOnly)throw 0;
            if(i.disabled)return wait();show(i);i.focus();i.select();if(!document.execCommand('insertText',false,'fictional-p12-password'))throw 0;return ready();"#.into(),
        Step::Prepare(_) => "return click('Prepare private review',panel().querySelector('form.session-inputs'));".into(),
        Step::Prepared(2) if case == Case::AndroidInputs => r#"const p=panel(),a=p.querySelector('.session-assessment');if(!a)return wait();
            if(!text(a).includes('Needs correction')||!text(a).includes('The Firebase application identity does not match the submitted project draft.'))return wait();
            if(p.querySelector('[aria-label="Explicit private-input review"]')||button('Keep for this session',p)||button('Assign to this context',p))throw 0;
            if(!text(a).includes('Native validation: not run')||!text(a).includes('Service validation: not run'))throw 0;show(a);return ready();"#.into(),
        Step::Prepared(_) | Step::Reassessed(_) => r#"const p=panel(),r=p.querySelector('[aria-label="Explicit private-input review"]'),a=p.querySelector('.session-assessment');
            if(!r||!a)return wait();const b=[...r.querySelectorAll('button')].find(b=>['Keep for this session','Assign to this context'].includes(text(b)));
            if(!b||b.disabled)return wait();if(!text(a).includes('Native validation')||!text(a).includes('not run'))throw 0;show(a);show(r);return ready();"#.into(),
        Step::Keep(_) => "return click('Keep for this session',review());".into(),
        Step::Kept(i) => format!("const rows=panel().querySelectorAll('.session-records article');if(rows.length!=={})return wait();if(!text(rows[{}]).includes('Revision 1'))throw 0;show(rows[{}]);return ready();",i+1,i,i),
        Step::Discard(2, false) if case == Case::AndroidInputs => "return click('Request cancel / discard this operation',panel().querySelector('.session-progress'));".into(),
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
