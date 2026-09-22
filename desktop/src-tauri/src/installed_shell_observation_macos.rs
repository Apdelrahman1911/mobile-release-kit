//! Four fixed observations of the ordinary installed AppKit/WK application.
//! The existing relay is the only controller. Its endpoint vetoes success and
//! actions; the separately reviewed original invocation owner bounds process
//! return/EOF. No replacement document, reply, cleanup owner or runtime exists.
use std::{ffi::OsStr, fs::OpenOptions, io::{Read, Write},
    os::{fd::AsFd, unix::fs::{MetadataExt, OpenOptionsExt}}, path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, atomic::{AtomicBool, AtomicU8, Ordering}},
    thread::ThreadId, time::{Duration, Instant}};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tauri::Manager;
use crate::{asset_session::{DocumentBinding, InstalledMacProjectWitness, InstalledMacPickerWitness, NativeResponse}, bridge::{AppInfo, Project},
    edit_owner::{EditOwner, InstalledConfigFinality, InstalledMacReviewWitness}, edit_protocol::{self as edit, ConfigEditStatus, EditProjection},
    error::BridgeError, supervisor::Supervisor};
use super::owned_macos::observation::{observed_panel, observe_panel_action, prepare_open_input,
    ObservedPanel, PanelAction, PreparedOpenInput};

// Closed public categories only. The first winner is published before failure;
// no Record lock, native call, path, or arbitrary error text enters this latch.
const FAILURE_REASONS: &[&str] = &[
    "observer-invariant", "observer-deadline", "observer-record-unavailable", "observer-data-check",
    "dom-dispatch-refused", "dom-pending-custody", "dom-callback-size", "dom-callback-json",
    "dom-callback-object", "dom-callback-state", "picker-unexpected-result",
    "native-wrong-thread", "native-step", "native-pending-custody", "native-original-id",
    "native-kind", "native-not-started", "native-ineligible", "native-action-attempted",
    "native-action-returned", "native-callback-returned", "native-response-present",
    "native-selection-present", "native-close-attempted", "native-closed", "native-attachment-lost",
    "native-preaction-history", "native-dismissed", "native-duplicate-action",
    "native-ax-not-trusted", "native-ax-trust", "native-ax-binding", "native-ax-input", "native-ax-custody",
    "cancel-unexpected-project", "cancel-duplicate-result",
    "adapter-wrong-thread", "adapter-book-borrow", "adapter-original-call", "adapter-original-owner",
    "adapter-original-binding", "adapter-missing-facts", "adapter-missing-panel", "adapter-ineligible",
    "adapter-native-observation", "adapter-native-action",
    "asset_invalid_request", "asset_closed", "asset_unqualified", "asset_unsupported_platform",
    "asset_unsupported_filesystem", "asset_unsupported_format", "asset_busy", "asset_source_refused",
    "asset_source_changed", "asset_material_limit", "asset_parser_limit", "asset_project_overlap",
    "asset_exclusion_unconfirmed", "asset_capacity", "assessment_context_stale", "asset_user_cancelled",
    "asset_review_expired", "asset_deadline", "asset_document_lost", "asset_shutdown", "asset_cleanup_unknown",
];
const _: () = assert!(FAILURE_REASONS.len() < u8::MAX as usize);
fn latch_failure(first: &AtomicU8, failed: &AtomicBool, reason: &'static str) {
    // Unknown internal labels degrade only to generic failure, never raw text.
    let code = FAILURE_REASONS.iter().position(|label| *label == reason).map_or(1, |index| index as u8 + 1);
    let _ = first.compare_exchange(0, code, Ordering::SeqCst, Ordering::SeqCst);
    failed.store(true, Ordering::SeqCst);
}
fn first_failure_reason(first: &AtomicU8) -> Option<&'static str> {
    FAILURE_REASONS.get(usize::from(first.load(Ordering::SeqCst).checked_sub(1)?)).copied()
}

/// A read-only readiness predicate, never an action/close/finality permit.
fn panel_readiness(panel: &ObservedPanel, id: u32, quit: bool, ever_attached: bool,
    same_action_returned: bool) -> Result<bool, &'static str> {
    let native = &panel.native;
    if panel.id != id { return Err("native-original-id"); }
    if matches!(native.kind, mrk_macos_installed_native::PanelKind::Quit) != quit { return Err("native-kind"); }
    if !native.started { return Err("native-not-started"); }
    if !panel.action_allowed { return Err("native-ineligible"); }
    if native.action_attempted { return Err("native-action-attempted"); }
    if native.action_returned { return Err("native-action-returned"); }
    if native.callback_returned { return Err("native-callback-returned"); }
    if native.response.is_some() { return Err("native-response-present"); }
    if native.selected.is_some() { return Err("native-selection-present"); }
    if native.close_attempted { return Err("native-close-attempted"); }
    if native.closed { return Err("native-closed"); }
    if !native.attached {
        if ever_attached { return Err("native-attachment-lost"); }
        if native.directory_bound || native.directory_returned || native.directory_ready || same_action_returned {
            return Err("native-preaction-history");
        }
        // dismissed is an instantaneous not-visible/not-parented sample. Before
        // first attachment and with NO history, either value can mean not ready.
        return Ok(false);
    }
    if native.dismissed { return Err("native-dismissed"); }
    Ok(true)
}

const METHODS: [&str; 8] = ["capabilities", "catalog", "project.snapshot", "config.validate",
    "config.suggest", "config.preview", "environment.requirements", "github.setup.propose"];
const APP_ID: &str = "org.example.mrk.observed";
const VERSION: &[u8] = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n";
const SOURCE: &[u8] = b"plugins { id(\"com.android.application\") }\nandroid { defaultConfig { applicationId = \"org.example.mrk.observed\" } }\n";
const KEEP: &[u8] = b"MRK_MACOS_AQUA_KEEP\n";
const IGNORE_PREFIX: &[u8] = b"# MRK Mac Aqua user ignore\nuser-output/\n";
const STALE_MARKER: &[u8] = b"# MRK Mac Aqua stale base\n";
const IGNORE_LINES: [&str; 7] = [".mobile-release/", ".mobile-release-init-prepare/", ".mobile-release-init/",
    ".mobile-release-init-cleanup/", ".mobile-release-metadata-text-prepare/", ".mobile-release-metadata-text/",
    ".mobile-release-metadata-text-cleanup/"];
// Fixed synthetic DATA shared with staging. This is not a second serializer:
// every real request/result is compared with these bytes, never manufactured.
const CONFIG: &[u8] = br#"{
  "android": {
    "applicationId": "org.example.mrk.observed",
    "enabled": true,
    "identityStatus": "unverified"
  },
  "ios": {
    "enabled": false
  },
  "metadata": {
    "androidLocales": [
      "en-US"
    ],
    "iosLocales": [],
    "root": "release/store"
  },
  "projectChecks": {
    "androidArtifact": [],
    "iosArtifact": [],
    "preflight": []
  },
  "schemaVersion": 1,
  "services": {
    "androidFirebase": "disabled",
    "iosFirebase": "disabled"
  },
  "source": {
    "candidateBranch": "main",
    "productionBranch": "main"
  },
  "version": {
    "buildKey": "BUILD_NUMBER",
    "nameKey": "VERSION_NAME",
    "source": "version.properties"
  }
}
"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case { FirstSave, NoopStale, PickerLoss, SaveLoss }
impl Case {
    fn name(self) -> &'static str { match self {
        Self::FirstSave => "first-save", Self::NoopStale => "noop-stale",
        Self::PickerLoss => "picker-loss", Self::SaveLoss => "save-loss",
    }}
    fn selected_id(self) -> u32 { if self == Self::FirstSave { 2 } else { 1 } }
    fn quit_id(self) -> u32 { if self == Self::FirstSave { 4 } else { 2 } }
    fn loses_document(self) -> bool { matches!(self, Self::PickerLoss | Self::SaveLoss) }
    fn rounds(self) -> usize { match self { Self::FirstSave | Self::NoopStale => 2, Self::SaveLoss => 1, Self::PickerLoss => 0 } }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Bootstrap, Environment, ReadEnvironment, Dashboard, ChooseCancel, CancelProject, CancelSettled, ReadCancelled,
    ChooseProject, SetProject, OpenProject, ProjectSettled, Snapshot, Settings, Suggest, Suggestion, Adopt, Draft,
    Validate, Validation, Preview, Previewed, RequirementsPage, LoadRequirements, Requirements,
    GitHubPage, GitHubRepository, GitHubSha, GitHubPropose, GitHubProposal, ReturnSettings,
    Prepare(usize), Review(usize), OpenConfirmation(usize), Confirmation(usize), KeepReviewing,
    KeptReview, Acknowledge(usize), Acknowledged(usize), Apply(usize), Applied(usize),
    ReadbackPage, Refresh, Readback, SavedSettings, ChangeDraft, ChangedDraft, MutateIgnore,
    CloseCancel, QuitCancel, QuitCancelled, RetainedReview, Close, Quit, Exit,
    PickerPending, Reload, Lost,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DomDispatch { step: Step, sequence: u16 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pending { Dom(DomDispatch), Native(Step), Accessibility(u32), Close(Step), Reload, FailureClose }

fn dom_step_entry(pending: Option<Pending>, current: Step, original: DomDispatch) -> bool {
    (1..=160).contains(&original.sequence) && current == original.step && pending == Some(Pending::Dom(original))
}
// Only the wrapper's actual synchronous body return authorizes this call. A
// successful body may already have advanced Step; the original marker remains.
fn retire_returned_dom(pending: &mut Option<Pending>, original: DomDispatch) -> bool {
    if !(1..=160).contains(&original.sequence) || *pending != Some(Pending::Dom(original)) { return false; }
    *pending = None; true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProjectReturn { Lost, Cancelled, Selected }
fn project_return_route(case: Case, step: Step, reload_requested: bool, cancel_returned: bool,
    project_returned: bool, result: &Result<Option<Project>, crate::asset_commands::AssetError>) -> Result<ProjectReturn, &'static str> {
    // Deliberate document loss has its own original result contract, including
    // duplicate refusal. It must precede the ordinary error classification.
    if reload_requested && case == Case::PickerLoss {
        if project_returned || result.as_ref().is_ok_and(Option::is_some) { return Err("observer-invariant"); }
        return Ok(ProjectReturn::Lost);
    }
    let cancel = case == Case::FirstSave && matches!(step, Step::CancelProject | Step::CancelSettled);
    if cancel && cancel_returned { return Err("cancel-duplicate-result"); }
    match result {
        // The invoke error can precede the DOM acknowledgement of its click.
        // Reconstruct only the public Reason category, never supplied text/code.
        Err(error) => Err(crate::asset_commands::AssetError::new(error.reason).code),
        Ok(None) if cancel => Ok(ProjectReturn::Cancelled),
        Ok(Some(_)) if cancel => Err("cancel-unexpected-project"),
        Ok(Some(_)) if matches!(step, Step::OpenProject | Step::ProjectSettled) => Ok(ProjectReturn::Selected),
        _ => Err("picker-unexpected-result"),
    }
}

fn native_step_entry(on_main: bool, timely: bool) -> Result<bool, &'static str> {
    // Wrong-thread uncertainty survives even when the endpoint already failed.
    if !on_main { return Err("native-wrong-thread"); }
    Ok(timely)
}
// Called only after this synchronous native-step body actually returned. A
// late pre-action return is known no-action, not repair of an unknown dispatch.
fn retire_returned_native(pending: &mut Option<Pending>, current: Step, returned: Step) -> bool {
    if current != returned || *pending != Some(Pending::Native(returned)) { return false; }
    *pending = None; true
}
fn open_step_entry(pending: Option<Pending>, current: Step, id: u32) -> bool {
    matches!(id, 1 | 2) && current == Step::OpenProject && pending == Some(Pending::Accessibility(id))
}
fn retire_returned_open(pending: &mut Option<Pending>, current: Step, id: u32) -> bool {
    if !open_step_entry(*pending, current, id) { return false; }
    *pending = None; true
}
#[derive(Clone, Copy)]
struct OpenInputSample {
    id: u32, prepared: bool, entered: bool, attempted: Option<bool>, press_returned: Option<bool>,
    returned: bool, retired: bool, identity_matched: Option<bool>, control_matched: Option<bool>,
    cleanup_returned: Option<bool>, diagnostic: Option<mrk_macos_installed_native::AxDiagnostic>,
}
impl OpenInputSample {
    fn preparing(id: u32) -> Self {
        Self { id, prepared: false, entered: false, attempted: Some(false), press_returned: Some(false),
            returned: false, retired: false, identity_matched: None, control_matched: None, cleanup_returned: None, diagnostic: None }
    }
    fn enter(&mut self) {
        self.entered = true; self.attempted = None; self.press_returned = None;
    }
    fn complete(&mut self, result: &mrk_macos_installed_native::AxInputReturn, retired: bool) {
        self.returned = true; self.retired = retired;
        if let Some(report) = result.report {
            self.attempted = Some(report.attempted); self.press_returned = Some(report.press_returned);
            self.identity_matched = Some(report.identity_matched); self.control_matched = Some(report.control_matched);
            self.cleanup_returned = Some(report.cleanup_returned); self.diagnostic = Some(report.diagnostic);
            if report.diagnostic.error == "none" && !result.timely() {
                self.diagnostic = Some(mrk_macos_installed_native::AxDiagnostic { site: "cleanup", error: "deadline" });
            }
        } else { self.diagnostic = Some(mrk_macos_installed_native::AxDiagnostic { site: "entry", error: "custody" }); }
    }
    fn succeeded(self) -> bool {
        self.prepared && self.entered && self.returned && self.retired && self.attempted == Some(true)
            && self.press_returned == Some(true) && self.identity_matched == Some(true) && self.control_matched == Some(true)
            && self.cleanup_returned == Some(true)
            && self.diagnostic == Some(mrk_macos_installed_native::AxDiagnostic { site: "press", error: "none" })
    }
    fn value(self) -> Value {
        json!({"mechanism":"accessibility-press", "step":"OpenProject", "id":self.id,
            "prepared":self.prepared, "entered":self.entered, "attempted":self.attempted, "pressReturned":self.press_returned,
            "returned":self.returned, "retired":self.retired, "identityMatched":self.identity_matched,
            "controlMatched":self.control_matched, "cleanupReturned":self.cleanup_returned,
            "site":self.diagnostic.map(|d| d.site), "error":self.diagnostic.map(|d| d.error)})
    }
}
#[derive(Clone, Copy)]
struct NativeDispatch { step: Step, entered: bool, returned: bool }
#[derive(Clone, Copy)]
struct NativeActionSample {
    step: Step, id: u32, diagnostic: mrk_macos_installed_native::PanelActionDiagnostic,
}
#[derive(Clone, Copy)]
struct PanelSample {
    step: Step, id: u32, kind: &'static str, parent_present: bool, panel_present: bool,
    parent_references_panel: Option<bool>, panel_references_parent: Option<bool>, panel_visible: Option<bool>,
}
impl PanelSample {
    fn from_original(step: Step, panel: &ObservedPanel) -> Self {
        let native = &panel.native;
        Self { step, id: panel.id,
            kind: match native.kind { mrk_macos_installed_native::PanelKind::Project => "project",
                mrk_macos_installed_native::PanelKind::Quit => "quit" },
            parent_present: native.parent_present, panel_present: native.panel_present,
            parent_references_panel: native.parent_references_panel,
            panel_references_parent: native.panel_references_parent, panel_visible: native.panel_visible }
    }
}

fn same_panel_action_returned(step: Step, actions: &[bool; 5]) -> Result<bool, &'static str> {
    match step {
        Step::CancelProject => Ok(actions[0]),
        Step::SetProject | Step::OpenProject | Step::PickerPending => Ok(actions[1] || actions[2]),
        Step::QuitCancel => Ok(actions[3]), Step::Quit => Ok(actions[4]),
        _ => Err("native-step"),
    }
}

#[derive(Clone, PartialEq, Eq)]
struct FileFact { identity: [u64; 9], sha256: String }
fn identity(m: &std::fs::Metadata) -> Result<[u64; 9], ()> {
    Ok([m.dev(), m.ino(), u64::from(m.mode()), u64::from(m.uid()), u64::from(m.gid()), m.nlink(), m.len(),
        u64::try_from(m.mtime()).map_err(|_| ())?.checked_mul(1_000_000_000).and_then(|v|
            u64::try_from(m.mtime_nsec()).ok().filter(|n| *n < 1_000_000_000).and_then(|n| v.checked_add(n))).ok_or(())?,
        u64::try_from(m.ctime()).map_err(|_| ())?.checked_mul(1_000_000_000).and_then(|v|
            u64::try_from(m.ctime_nsec()).ok().filter(|n| *n < 1_000_000_000).and_then(|n| v.checked_add(n))).ok_or(())?])
}
fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn file_fact(path: &Path, expected: &[u8], uid: u32) -> Result<FileFact, ()> {
    if expected.len() > 4096 { return Err(()); }
    let before = std::fs::symlink_metadata(path).map_err(|_| ())?;
    if !before.is_file() || before.uid() != uid || before.mode() & 0o7777 != 0o600
        || before.nlink() != 1 || before.len() != expected.len() as u64 { return Err(()); }
    let mut file = OpenOptions::new().read(true).custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path).map_err(|_| ())?;
    let result = (|| {
        let original = identity(&before)?;
        if identity(&file.metadata().map_err(|_| ())?)? != original { return Err(()); }
        mrk_macos_installed_native::empty_acl(file.as_fd()).map_err(|_| ())?;
        mrk_macos_installed_native::no_xattrs(file.as_fd()).map_err(|_| ())?;
        let mut bytes = Vec::with_capacity(expected.len() + 1);
        (&mut file).take(expected.len() as u64 + 1).read_to_end(&mut bytes).map_err(|_| ())?;
        if bytes != expected || identity(&file.metadata().map_err(|_| ())?)? != original
            || identity(&std::fs::symlink_metadata(path).map_err(|_| ())?)? != original { return Err(()); }
        Ok(FileFact { identity: original, sha256: digest(&bytes) })
    })();
    let closed = nix::unistd::close(std::os::fd::OwnedFd::from(file)).is_ok();
    if !closed { return Err(()); } result
}
fn directory(path: &Path, uid: u32, mode: u32, entries: &[&str]) -> Result<[u64; 6], ()> {
    let before = std::fs::symlink_metadata(path).map_err(|_| ())?;
    if !before.is_dir() || before.uid() != uid || before.mode() & 0o7777 != mode { return Err(()); }
    let file = OpenOptions::new().read(true).custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY)
        .open(path).map_err(|_| ())?;
    let result = (|| {
        let original = identity(&before)?;
        if identity(&file.metadata().map_err(|_| ())?)? != original { return Err(()); }
        mrk_macos_installed_native::empty_acl(file.as_fd()).map_err(|_| ())?;
        mrk_macos_installed_native::no_xattrs(file.as_fd()).map_err(|_| ())?;
        // Reuse the installed native descriptor reader, not an unowned
        // fdopendir/Drop close. This private fixed roster has at most16 names.
        let mut buffer = vec![0u8;65536]; let mut actual = Vec::new(); let mut eof = false;
        for _ in 0..20 {
            let used = mrk_macos_installed_native::directory_block(file.as_fd(),&mut buffer).map_err(|_| ())?;
            if used == 0 { eof = true; break; }
            let mut offset = 0;
            while offset < used {
                if used - offset < 11 { return Err(()); }
                let inode = u64::from_ne_bytes(buffer[offset..offset+8].try_into().map_err(|_| ())?);
                let kind = buffer[offset+8];
                let length = usize::from(u16::from_ne_bytes([buffer[offset+9],buffer[offset+10]]));
                let next = offset.checked_add(11+length).filter(|v| *v <= used).ok_or(())?;
                let name = std::str::from_utf8(&buffer[offset+11..next]).map_err(|_| ())?; offset = next;
                if name == "." || name == ".." { continue; }
                if actual.len() >= 16 || inode == 0 || !matches!(kind,nix::libc::DT_DIR|nix::libc::DT_REG)
                    || !entries.contains(&name) || actual.iter().any(|v| v == name) { return Err(()); }
                actual.push(name.to_owned());
            }
        }
        actual.sort(); let mut expected = entries.to_vec(); expected.sort();
        if !eof || actual != expected || identity(&file.metadata().map_err(|_| ())?)? != original
            || identity(&std::fs::symlink_metadata(path).map_err(|_| ())?)? != original { return Err(()); }
        Ok([before.dev(), before.ino(), u64::from(before.mode()), u64::from(before.uid()), u64::from(before.gid()), before.nlink()])
    })();
    if nix::unistd::close(std::os::fd::OwnedFd::from(file)).is_err() { return Err(()); } result
}
struct Fixture {
    root: PathBuf, uid: u32, root_identity: [u64; 6], app_identity: [u64; 6],
    untouched: [FileFact; 3], ignore: FileFact, config: Option<FileFact>, release: Option<[u64; 6]>,
    written: bool, mutated: bool,
}
impl Fixture {
    fn ignore_bytes(saved: bool, mutated: bool) -> Vec<u8> {
        let mut bytes = IGNORE_PREFIX.to_vec();
        if saved { for line in IGNORE_LINES { bytes.extend_from_slice(line.as_bytes()); bytes.push(b'\n'); } }
        if mutated { bytes.extend_from_slice(STALE_MARKER); } bytes
    }
    fn capture(root: PathBuf, uid: u32, case: Case) -> Result<Self, ()> {
        let saved = case == Case::NoopStale;
        let root_identity = directory(&root, uid, 0o700, if saved {
            &[".gitignore", "app", "keep.txt", "release", "version.properties"]
        } else { &[".gitignore", "app", "keep.txt", "version.properties"] })?;
        let app_identity = directory(&root.join("app"), uid, 0o700, &["build.gradle.kts"])?;
        let untouched = [file_fact(&root.join("app/build.gradle.kts"), SOURCE, uid)?,
            file_fact(&root.join("version.properties"), VERSION, uid)?, file_fact(&root.join("keep.txt"), KEEP, uid)?];
        let ignore = file_fact(&root.join(".gitignore"), &Self::ignore_bytes(saved, false), uid)?;
        let (config, release) = if saved { (Some(file_fact(&root.join("release/mobile-release.json"), CONFIG, uid)?),
            Some(directory(&root.join("release"), uid, 0o755, &["mobile-release.json"])?)) } else { (None, None) };
        Ok(Self { root, uid, root_identity, app_identity, untouched, ignore, config, release, written: false, mutated: false })
    }
    fn verify(&self, saved: bool) -> Result<(), ()> {
        let root = directory(&self.root, self.uid, 0o700, if saved { &[".gitignore", "app", "keep.txt", "release", "version.properties"] }
            else { &[".gitignore", "app", "keep.txt", "version.properties"] })?;
        if root[..5] != self.root_identity[..5] || directory(&self.root.join("app"), self.uid, 0o700, &["build.gradle.kts"])? != self.app_identity {
            return Err(());
        }
        for ((path, bytes), original) in [("app/build.gradle.kts", SOURCE), ("version.properties", VERSION), ("keep.txt", KEEP)]
            .into_iter().zip(&self.untouched) {
            if &file_fact(&self.root.join(path), bytes, self.uid)? != original { return Err(()); }
        }
        if file_fact(&self.root.join(".gitignore"), &Self::ignore_bytes(saved, self.mutated), self.uid)? != self.ignore { return Err(()); }
        if saved {
            if Some(file_fact(&self.root.join("release/mobile-release.json"), CONFIG, self.uid)?) != self.config
                || Some(directory(&self.root.join("release"), self.uid, 0o755, &["mobile-release.json"])?) != self.release { return Err(()); }
        } else if self.config.is_some() || self.release.is_some() { return Err(()); }
        Ok(())
    }
    fn saved(&mut self) -> Result<(), ()> {
        if self.written || self.mutated || self.config.is_some() || self.release.is_some() { return Err(()); }
        self.ignore = file_fact(&self.root.join(".gitignore"), &Self::ignore_bytes(true, false), self.uid)?;
        self.config = Some(file_fact(&self.root.join("release/mobile-release.json"), CONFIG, self.uid)?);
        self.release = Some(directory(&self.root.join("release"), self.uid, 0o755, &["mobile-release.json"])?);
        self.verify(true)?; self.written = true; Ok(())
    }
    fn mutate_ignore(&mut self, end: Instant, failed: &AtomicBool) -> Result<(), ()> {
        let current = || !failed.load(Ordering::SeqCst) && Instant::now() < end;
        if !current() { return Err(()); }
        if self.written || self.mutated || self.config.is_none() { return Err(()); }
        self.verify(true)?;
        let path = self.root.join(".gitignore");
        if !current() { return Err(()); }
        let mut file = OpenOptions::new().read(true).append(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC).open(&path).map_err(|_| ())?;
        let result = (|| {
            if identity(&file.metadata().map_err(|_| ())?)? != self.ignore.identity
                || identity(&std::fs::symlink_metadata(&path).map_err(|_| ())?)? != self.ignore.identity { return Err(()); }
            mrk_macos_installed_native::empty_acl(file.as_fd()).map_err(|_| ())?;
            mrk_macos_installed_native::no_xattrs(file.as_fd()).map_err(|_| ())?;
            let old = Self::ignore_bytes(true, false); let mut observed = Vec::with_capacity(old.len() + 1);
            (&mut file).take(old.len() as u64 + 1).read_to_end(&mut observed).map_err(|_| ())?;
            if observed != old || identity(&file.metadata().map_err(|_| ())?)? != self.ignore.identity { return Err(()); }
            // One fixed append to the prebound original. A partial error is
            // absorbing; never retry, restore, rename or delete its evidence.
            // The prechecks may block. Recheck THIS original endpoint at the
            // last boundary before the only write, not just at relay entry.
            if !current() { return Err(()); }
            if file.write(STALE_MARKER).map_err(|_| ())? != STALE_MARKER.len() || !current() { return Err(()); }
            file.sync_all().map_err(|_| ())?;
            if !current() { return Err(()); }
            let after = identity(&file.metadata().map_err(|_| ())?)?;
            if after[..6] != self.ignore.identity[..6] || after[6] != (old.len() + STALE_MARKER.len()) as u64
                || identity(&std::fs::symlink_metadata(&path).map_err(|_| ())?)? != after { return Err(()); }
            Ok(after)
        })();
        let closed = nix::unistd::close(std::os::fd::OwnedFd::from(file)).is_ok();
        if !closed || !current() { return Err(()); }
        let after = result?;
        let checked = file_fact(&path, &Self::ignore_bytes(true, true), self.uid)?;
        if checked.identity != after || !current() { return Err(()); }
        self.ignore = checked; self.mutated = true; self.verify(true)?;
        current().then_some(()).ok_or(())
    }
}

struct Session {
    projection: EditProjection, prepare_requested: bool, prepare_returned: bool,
    review: Option<Value>, review_visible: bool, confirmation_count: u8, acknowledged: bool,
    apply_requested: bool, apply_returned: bool, finality: Option<InstalledConfigFinality>,
}
impl Session {
    fn live_review(&self) -> bool { self.projection.phase == edit::Phase::Reviewing && self.projection.review_remaining_ms > 0
        && !self.projection.apply_submitted && self.projection.native_reason == edit::NativeEditReason::None
        && self.projection.native_finality == edit::NativeFinality::Pending && self.projection.core_outcome.is_none()
        && self.prepare_returned && self.review.is_some() && self.finality.is_none() }
}
struct Record {
    step: Step, pending: Option<Pending>, evaluations: u16, attached: bool, started: bool, loaded: bool,
    native_dispatch: Option<NativeDispatch>, last_panel: Option<PanelSample>, native_action: Option<NativeActionSample>,
    ax_trusted: bool, prepared_open: Option<PreparedOpenInput>, accessibility: Option<OpenInputSample>,
    initial_navigation: bool, info: bool, catalog: bool, methods: usize, capability: bool,
    project_calls: u8, cancel_returned: bool, project_returned: bool, project: Option<Project>,
    project_witness: Option<InstalledMacProjectWitness>, picker_witness: Option<InstalledMacPickerWitness>,
    cancel_settled: bool, project_settled: bool, selected_native: bool, panel_attached: [bool; 4],
    native_actions_returned: [bool; 5], snapshot_requests: u8, snapshot_pending: bool, snapshots: u8,
    suggestion_requested: bool, suggestion: Option<Value>, validation_requested: bool, validation: bool,
    preview_requested: bool, preview: Option<Value>, requirements_requested: bool, requirements: Option<Value>,
    github_requested: bool, workflows: Option<Value>, draft_visible: bool, guidance_visible: bool,
    sessions: Vec<Session>, open_pending: bool, prepare_pending: Option<usize>, generation: Option<String>, status_revision: Option<u32>,
    review_witness: Option<InstalledMacReviewWitness>,
    keep_reviewing: bool, saved_visible: bool, noop_visible: bool, stale_visible: bool, file_readback: bool,
    quit_cancelled: bool, close_count: u8, reload_requested: bool, reload_returned: bool, reload_navigation: bool,
    loss_seen: bool, loss_settled: bool, relay_joined: bool, actual_exit: bool, originals_final: bool,
    failure_close_requested: bool, failure_quit_attempted: bool,
    fixture: Fixture,
}
fn failure_context(r: &Record) -> Value {
    let pending = r.pending.map(|pending| {
        let (kind, step) = match pending {
            Pending::Dom(original) => ("dom", Some(original.step)), Pending::Native(step) => ("native", Some(step)),
            Pending::Accessibility(_) => ("accessibility", Some(Step::OpenProject)),
            Pending::Close(step) => ("close", Some(step)), Pending::Reload => ("reload", None),
            Pending::FailureClose => ("failure-close", None),
        };
        json!({"kind":kind, "step":step.map(|step| format!("{step:?}"))})
    });
    // Only the last regular native-step dispatch/sample, not a history. These
    // body-return flags do not describe AppKit completion or cleanup/finality.
    let native = r.native_dispatch.map(|native| json!({"step":format!("{:?}", native.step),
        "entered":native.entered, "returned":native.returned}));
    let panel = r.last_panel.map(|panel| json!({"step":format!("{:?}", panel.step),
        "id":panel.id, "kind":panel.kind, "parentPresent":panel.parent_present, "panelPresent":panel.panel_present,
        "parentReferencesPanel":panel.parent_references_panel, "panelReferencesParent":panel.panel_references_parent,
        "panelVisible":panel.panel_visible}));
    let action = r.native_action.map(|action| json!({"step":format!("{:?}", action.step), "id":action.id,
        "action":action.diagnostic.action, "domain":action.diagnostic.domain,
        "site":action.diagnostic.site, "error":action.diagnostic.error}));
    json!({"pending":pending, "nativeHandler":native, "lastPanel":panel, "nativeAction":action,
        "accessibility":r.accessibility.map(OpenInputSample::value)})
}
pub(super) struct Observation {
    case: Case, main: ThreadId, end: Instant, project_path: PathBuf, base: Value,
    failed: AtomicBool, failure_reason: AtomicU8, failure_reported: AtomicBool, record: Mutex<Record>,
}
impl Observation {
    fn new(case: Case, fixture: Fixture) -> Result<Self, ()> {
        let base = crate::protocol::strict_json(CONFIG).map_err(|_| ())?;
        Ok(Self { case, main: std::thread::current().id(), end: Instant::now() + Duration::from_secs(45),
            project_path: fixture.root.clone(), base, failed: AtomicBool::new(false), failure_reason: AtomicU8::new(0),
            failure_reported: AtomicBool::new(false),
            record: Mutex::new(Record {
                step: Step::Bootstrap, pending: None, evaluations: 0, attached: false, started: false, loaded: false,
                native_dispatch: None, last_panel: None, native_action: None,
                ax_trusted: false, prepared_open: None, accessibility: None,
                initial_navigation: false, info: false, catalog: false, methods: 0, capability: false,
                project_calls: 0, cancel_returned: false, project_returned: false, project: None,
                project_witness: None, picker_witness: None,
                cancel_settled: false, project_settled: false, selected_native: false, panel_attached: [false; 4],
                native_actions_returned: [false; 5], snapshot_requests: 0, snapshot_pending: false, snapshots: 0,
                suggestion_requested: false, suggestion: None, validation_requested: false, validation: false,
                preview_requested: false, preview: None, requirements_requested: false, requirements: None,
                github_requested: false, workflows: None, draft_visible: false, guidance_visible: false,
                sessions: Vec::with_capacity(2), open_pending: false, prepare_pending: None, generation: None, status_revision: None,
                review_witness: None,
                keep_reviewing: false, saved_visible: false, noop_visible: false, stale_visible: false, file_readback: false,
                quit_cancelled: false, close_count: 0, reload_requested: false, reload_returned: false, reload_navigation: false,
                loss_seen: false, loss_settled: false, relay_joined: false, actual_exit: false, originals_final: false,
                failure_close_requested: false, failure_quit_attempted: false, fixture,
            }) })
    }
    fn fail(&self) { self.fail_with("observer-invariant"); }
    fn fail_with(&self, reason: &'static str) { latch_failure(&self.failure_reason, &self.failed, reason); }
    fn record(&self) -> Option<MutexGuard<'_, Record>> {
        match self.record.lock() { Ok(r) => Some(r), Err(_) => { self.fail_with("observer-record-unavailable"); None } }
    }
    fn timely(&self) -> bool {
        if self.failed.load(Ordering::SeqCst) { return false; }
        if Instant::now() >= self.end { self.fail_with("observer-deadline"); false } else { true }
    }
    fn report_failure(&self) {
        if !self.failed.load(Ordering::SeqCst) || self.failure_reported.load(Ordering::SeqCst) { return; }
        let Some(reason) = first_failure_reason(&self.failure_reason) else { return; };
        let Ok(r) = self.record.try_lock() else { return; };
        // This reason is latched only after the original action body returns.
        // Let its matching Record publication precede the one-shot report;
        // unrelated failures still report truthful unknown/nonreturned DATA.
        if matches!(reason, "adapter-native-action" | "native-ax-binding") && r.pending == Some(Pending::Native(r.step))
            && r.native_dispatch.is_some_and(|native| native.step == r.step && native.entered && !native.returned) {
            return;
        }
        if matches!(reason, "native-ax-input" | "native-ax-custody")
            && matches!(r.pending, Some(Pending::Accessibility(_)))
            && r.accessibility.is_some_and(|sample| sample.entered && !sample.returned) { return; }
        if self.failure_reported.swap(true, Ordering::SeqCst) { return; }
        // Fixed labels and the already recorded sample only; no new native
        // observation. Later cleanup cannot replace the first reason/sample.
        let _ = writeln!(std::io::stderr().lock(), "MRK_MACOS_AQUA_FAILURE_STEP={:?}\nMRK_MACOS_AQUA_FAILURE_REASON={}\nMRK_MACOS_AQUA_FAILURE_CONTEXT={}",
            r.step, reason, failure_context(&r));
    }
    pub(super) fn attach(&self, _: &Supervisor) -> Result<(), BridgeError> {
        let Some(mut r) = self.record() else { return Err(BridgeError::cleanup_unknown()); };
        if std::thread::current().id() != self.main || r.attached || !self.timely() {
            self.fail(); return Err(BridgeError::invalid());
        }
        r.attached = true; Ok(())
    }
    pub(super) fn navigation(&self, trusted: bool, allowed: bool) {
        let Some(mut r) = self.record() else { return; };
        if !trusted || !r.attached { self.fail(); return; }
        if !r.initial_navigation && !r.loaded && allowed { r.initial_navigation = true; return; }
        if self.case.loses_document() && r.reload_requested && !r.reload_navigation && r.loaded && !allowed {
            r.reload_navigation = true; return;
        }
        self.fail();
    }
    pub(super) fn page_load(&self, trusted: bool, finished: bool) {
        let Some(mut r) = self.record() else { return; };
        if !trusted || !r.attached { self.fail(); return; }
        if r.reload_requested {
            // A real second Started can invalidate even if native navigation
            // ordering varies. Finished cannot bind or restore the original.
            if !finished && !r.loss_seen && r.loaded { r.loss_seen = true; return; }
            self.fail(); return;
        }
        if if finished { !r.started || r.loaded } else { r.started } { self.fail(); return; }
        if finished { r.loaded = true; } else { r.started = true; }
    }
    pub(super) fn app_info(&self, info: &AppInfo) {
        let Some(methods) = info.capabilities.as_ref().and_then(|v| v["methods"].as_array()) else { self.fail(); return; };
        let Some(actions) = info.capabilities.as_ref().and_then(|v| v["actions"].as_array()) else { self.fail(); return; };
        let available = |m: &&Value| m["available"].as_bool() == Some(true);
        let valid = info.runtime.state == "available" && info.runtime.mode == "bundled" && info.runtime.reason.is_none()
            && info.app_name == "Mobile Release Kit" && info.app_version == env!("CARGO_PKG_VERSION")
            && info.project_selection.available && info.project_selection.reason.is_none()
            && !info.project_path_selection.available
            && (METHODS.len()..=64).contains(&methods.len()) && (1..=64).contains(&actions.len())
            && methods.iter().filter(available).count() == METHODS.len()
            && METHODS.iter().all(|name| methods.iter().filter(available).filter(|m| m["method"].as_str() == Some(*name)).count() == 1)
            && methods.iter().all(|m| m["available"].is_boolean())
            && actions.iter().all(|a| a["available"].as_bool() == Some(false));
        let Some(mut r) = self.record() else { return; };
        if !valid || r.info || r.reload_requested { self.fail(); return; }
        r.info = true; r.methods = methods.len();
    }
    pub(super) fn catalog(&self, result: &Result<Value, BridgeError>) {
        let valid = result.as_ref().ok().and_then(|v| v["fields"].as_array()).is_some_and(|fields|
            fields.len() <= 64 && fields.iter().filter(|f| f["path"].as_str() == Some("version.source")
                && ["label", "requiredness", "what", "why", "where", "format", "requiredWhen", "failure"].iter().all(|k|
                    f[*k].as_str().is_some_and(|s| !s.is_empty() && s.len() <= 16384))).count() == 1);
        let Some(mut r) = self.record() else { return; };
        if !r.info || r.catalog || !valid || r.reload_requested { self.fail(); return; } r.catalog = true;
    }
    pub(super) fn project_result(&self, result: &Result<Option<Project>, crate::asset_commands::AssetError>) {
        let Some(mut r) = self.record() else { return; };
        match project_return_route(self.case, r.step, r.reload_requested, r.cancel_returned, r.project_returned, result) {
            Ok(ProjectReturn::Lost) => { r.project_returned = true; return; },
            Ok(ProjectReturn::Cancelled) => { r.cancel_returned = true; return; },
            Ok(ProjectReturn::Selected) => {},
            Err(reason) => { self.fail_with(reason); return; },
        }
        let Ok(Some(project)) = result else { self.fail(); return; };
        if !matches!(r.step, Step::OpenProject | Step::ProjectSettled) || r.project.is_some()
            || Path::new(&project.path) != self.project_path || project.name != self.case.name() || !crate::protocol::valid_id(&project.id) {
            self.fail(); return;
        }
        r.project_returned = true; r.project = Some(project.clone());
    }
    pub(super) fn snapshot_request(&self, project: &str) {
        let Some(mut r) = self.record() else { return; };
        let allowed = r.snapshot_requests == 0 && matches!(r.step, Step::OpenProject | Step::ProjectSettled | Step::Snapshot)
            || self.case == Case::FirstSave && r.snapshot_requests == 1 && matches!(r.step, Step::Refresh | Step::Readback);
        if !allowed || r.snapshot_pending || r.reload_requested || !r.project.as_ref().is_some_and(|p| p.id == project) {
            self.fail(); return;
        }
        r.snapshot_requests += 1; r.snapshot_pending = true;
    }
    pub(super) fn snapshot(&self, project: &str, result: &Result<Value, BridgeError>) {
        let Some(mut r) = self.record() else { return; };
        let saved = self.case == Case::NoopStale || r.snapshot_requests == 2;
        let valid = result.as_ref().is_ok_and(|v| {
            let config = &v["config"]; let hints = &v["discovery"]["hints"];
            v["root"].as_str() == self.project_path.to_str() && v["observationScope"] == "single-request-non-atomic"
                && config["path"] == "release/mobile-release.json" && assurance(v, "static-text")
                && v["issues"].as_array().is_some_and(Vec::is_empty)
                && hints["android"]["applicationId"] == APP_ID && hints["android"]["module"] == ":app"
                && hints["android"]["buildFile"] == "app/build.gradle.kts" && hints["versionSource"] == "version.properties"
                && hints["versionNameKey"] == "VERSION_NAME" && hints["versionBuildKey"] == "BUILD_NUMBER"
                && v["discovery"]["partial"] == false && v["discovery"]["state"] == "unverified"
                && if saved { config["state"] == "format-valid" && config["data"] == self.base
                    && config["content"] == json!({"bytes":CONFIG.len(), "sha256":digest(CONFIG)})
                    && config["issues"].as_array().is_some_and(Vec::is_empty) }
                else { config["state"] == "missing" && config["data"].is_null() && config["content"].is_null()
                    && config["issues"].as_array().is_some_and(|issues| issues.len() == 1 && issues[0]["code"] == "config.missing") }
        });
        if !valid || !r.snapshot_pending || !r.project.as_ref().is_some_and(|p| p.id == project) || r.snapshots + 1 != r.snapshot_requests {
            self.fail(); return;
        }
        r.snapshot_pending = false; r.snapshots += 1;
    }
    pub(super) fn suggest_request(&self, hints: &Value) {
        let Some(mut r) = self.record() else { return; };
        if self.case == Case::NoopStale || !matches!(r.step, Step::Suggest | Step::Suggestion) || r.suggestion_requested
            || *hints != json!({"platforms":["android"],"androidApplicationId":APP_ID,
                "versionSource":"version.properties","versionNameKey":"VERSION_NAME","versionBuildKey":"BUILD_NUMBER"}) {
            self.fail(); return;
        } r.suggestion_requested = true;
    }
    pub(super) fn suggestion(&self, result: &Result<Value, BridgeError>) {
        let Some(mut r) = self.record() else { return; };
        let Some(v) = result.as_ref().ok().filter(|v| v["draft"] == self.base && v["schemaVersion"] == 1
            && v["platformSelectionRequired"] == false && format_valid(&v["validation"]) && assurance(v,"schema-policy")) else { self.fail(); return; };
        if !r.suggestion_requested || r.suggestion.is_some() { self.fail(); return; }
        let Some(rows) = v["provenance"].as_array().filter(|a| !a.is_empty() && a.len() <= 64) else { self.fail(); return; };
        let projected: Option<Vec<Value>> = rows.iter().map(|row| {
            let path = row["path"].as_str()?; let source = row["source"].as_str()?;
            (path.len() <= 128 && matches!(source,"hint"|"default"|"example")).then(|| json!({"path":path,"source":source}))
        }).collect();
        let Some(projected) = projected else { self.fail(); return; }; r.suggestion = Some(Value::Array(projected));
    }
    pub(super) fn validate_request(&self, draft: &Value) {
        let Some(mut r) = self.record() else { return; };
        if !r.draft_visible || r.validation_requested || !matches!(r.step, Step::Validate | Step::Validation) || *draft != self.base {
            self.fail(); return;
        } r.validation_requested = true;
    }
    pub(super) fn validation(&self, result: &Result<Value, BridgeError>) {
        let Some(mut r) = self.record() else { return; };
        if !r.validation_requested || r.validation || !result.as_ref().is_ok_and(format_valid) { self.fail(); return; } r.validation = true;
    }
    pub(super) fn preview_request(&self, base: &Value, draft: &Value) {
        let Some(mut r) = self.record() else { return; };
        let expected = if self.case == Case::NoopStale { &self.base } else { &Value::Null };
        if !r.validation || r.preview_requested || !matches!(r.step, Step::Preview | Step::Previewed) || base != expected || draft != &self.base {
            self.fail(); return;
        } r.preview_requested = true;
    }
    pub(super) fn preview_result(&self, result: &Result<Value, BridgeError>) {
        let Some(mut r) = self.record() else { return; };
        let Some(v) = result.as_ref().ok().filter(|v| format_valid(&v["validation"]) && assurance(v,"schema-policy")
            && v["comparison"]["state"] == "complete" && v["comparison"]["unreviewedCount"] == 0
            && v["comparison"]["baseProvided"].as_bool() == Some(self.case == Case::NoopStale)) else { self.fail(); return; };
        if !r.preview_requested || r.preview.is_some() { self.fail(); return; }
        r.preview = Some(json!({"counts":v["comparison"]["counts"],"fields":v["fields"].as_array().map(Vec::len),
            "valid":v["validation"]["state"]}));
    }
    pub(super) fn requirements_request(&self, body: &Value) {
        let Some(mut r) = self.record() else { return; };
        if self.case != Case::FirstSave || r.requirements_requested || !matches!(r.step,Step::LoadRequirements|Step::Requirements)
            || *body != json!({"draft":self.base,"platform":"android","operation":"build"}) { self.fail(); return; }
        r.requirements_requested = true;
    }
    pub(super) fn requirements(&self, result: &Result<crate::environment::Requirements, BridgeError>) {
        let Some(mut r) = self.record() else { return; };
        let Some(v) = result.as_ref().ok().and_then(|r| edit::bounded(r, crate::environment::RESPONSE_LIMIT).ok())
            .and_then(|raw| crate::protocol::strict_json(&raw).ok()) else { self.fail(); return; };
        let Some(rows) = v["requirements"].as_array().filter(|rows| rows.len() == 3) else { self.fail(); return; };
        if !r.requirements_requested || r.requirements.is_some() || v["hostPlatform"] != "macos" || v["state"] != "requirements-only"
            || v["context"] != json!({"platform":"android","operation":"build"}) || !assurance(&v,"schema-policy")
            || !rows.iter().zip(["android-jdk","android-gradle-wrapper","android-sdk"]).all(|(row,id)|
                row["id"] == id && row["presence"] == "unknown" && row["inspection"] == "not-run" && row["versionState"] == "unknown") {
            self.fail(); return;
        }
        r.requirements = Some(json!(rows.iter().map(|row| json!({"label":row["help"]["label"],
            "where":format!("Where to find it: {}",row["help"]["where"].as_str().unwrap_or(""))})).collect::<Vec<_>>()));
    }
    pub(super) fn github_request(&self, body: &Value) {
        let Some(mut r) = self.record() else { return; };
        if self.case != Case::FirstSave || r.github_requested || !matches!(r.step,Step::GitHubPropose|Step::GitHubProposal)
            || *body != json!({"draft":self.base,"toolingRepository":"example/toolkit","toolingSha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","suppliedSnapshot":null}) {
            self.fail(); return;
        } r.github_requested = true;
    }
    pub(super) fn github_proposal(&self, result: &Result<Value, BridgeError>) {
        let Some(mut r) = self.record() else { return; };
        let Some(v) = result.as_ref().ok().filter(|v| v["state"] == "proposed" && format_valid(&v["validation"])
            && assurance(v,"schema-policy") && v["facts"]["githubContacted"] == false
            && v["facts"]["applyAvailable"] == false && v["facts"]["snapshotProvided"] == false) else { self.fail(); return; };
        let Some(rows) = v["workflows"].as_array().filter(|v| v.len() == 4) else { self.fail(); return; };
        if !r.github_requested || r.workflows.is_some() { self.fail(); return; }
        let expected_paths = [".github/workflows/mobile-preflight.yml",".github/workflows/mobile-candidate.yml",
            ".github/workflows/mobile-external-testing.yml",".github/workflows/mobile-production-submit.yml"];
        let mut expected = Vec::with_capacity(4);
        for (row,path) in rows.iter().zip(expected_paths) {
            let Some(content) = row["content"].as_str().filter(|s| s.len() <= 8192) else { self.fail(); return; };
            if row["path"] != path || row["byteLength"].as_u64() != Some(content.len() as u64)
                || row["sha256"].as_str() != Some(digest(content.as_bytes()).as_str()) || row["comparison"] != "not-supplied" { self.fail(); return; }
            expected.push(json!({"path":path,"content":content}));
        }
        r.workflows = Some(Value::Array(expected));
    }
    fn expected_base(&self, round: usize) -> &Value {
        if self.case == Case::NoopStale || round == 1 { &self.base } else { &Value::Null }
    }
    fn expected_draft(&self, round: usize) -> Value {
        let mut draft = self.base.clone();
        if self.case == Case::NoopStale && round == 1 { draft["version"]["source"] = json!("stale-version.properties"); }
        draft
    }
    fn revisions(&self, round: usize) -> (u32, u32) {
        match (self.case,round) { (Case::FirstSave,1) => (1,2), (Case::NoopStale,1) => (2,1), _ => (1,1) }
    }
    fn no_op(&self, round: usize) -> bool { self.case == Case::NoopStale && round == 0 || self.case == Case::FirstSave && round == 1 }
    fn review_sample(&self, view: &edit::PreparedConfigView, round: usize) -> Option<Value> {
        edit::bounded(view, 128 * 1024).ok()?;
        let create = self.case != Case::NoopStale && round == 0;
        let replace = self.case == Case::NoopStale && round == 1;
        let no_op = self.no_op(round);
        let before_ignore = Fixture::ignore_bytes(!create,false).len() as u32;
        let after_ignore = Fixture::ignore_bytes(true,false).len() as u32;
        if view.schema_version != 1 || view.files.len() != 2 || view.create_release_directory != create
            || view.rewrites_config_formatting != replace || !format_valid(&view.preview["validation"]) || !assurance(&view.preview,"schema-policy") {
            return None;
        }
        let config = &view.files[0]; let ignore = &view.files[1];
        if config.path != "release/mobile-release.json" || config.action != (if create { "create" } else if replace { "replace" } else { "preserve" })
            || config.before_bytes != (!create).then_some(CONFIG.len() as u32)
            || config.after_bytes != (CONFIG.len() as u32 + if replace { 6 } else { 0 })
            || ignore.path != ".gitignore" || ignore.action != (if create { "append" } else { "preserve" })
            || ignore.before_bytes != Some(before_ignore) || ignore.after_bytes != after_ignore
            || !view.ignore_additions.iter().map(String::as_str).eq(if create { IGNORE_LINES.as_slice() } else { &[] }.iter().copied()) {
            return None;
        }
        let c = &view.preview["comparison"];
        if c["baseProvided"].as_bool() != Some(!create) || c["state"] != "complete" || c["unreviewedCount"] != 0
            || c["semanticallyChanged"].as_bool() != Some(!no_op)
            || no_op && c["counts"] != json!({"added":0,"changed":0,"removed":0})
            || replace && c["counts"] != json!({"added":0,"changed":1,"removed":0}) { return None; }
        Some(json!({"files":view.files,"release":view.create_release_directory,"rewrite":view.rewrites_config_formatting,
            "ignore":view.ignore_additions,"counts":c["counts"],
            "basis":if no_op { "The native plan contains no file writes" } else { "Only this reviewed native inventory can be applied" },
            "badge":if no_op { "No writes planned" } else { "Explicit Apply required" }}))
    }
    pub(super) fn open_request(&self, project: &str) {
        let Some(mut r) = self.record() else { return; };
        let round = r.sessions.len();
        if round >= self.case.rounds() || !matches!(r.step,Step::Prepare(i)|Step::Review(i) if i == round)
            || !r.capability || !r.draft_visible || r.open_pending || r.reload_requested
            || !r.project.as_ref().is_some_and(|p| p.id == project)
            || round > 0 && !r.sessions[round - 1].finality.is_some() { self.fail(); return; }
        r.open_pending = true;
    }
    pub(super) fn open_result(&self, result: &Result<ConfigEditStatus, BridgeError>, edits: &EditOwner) {
        {
            let Some(mut r) = self.record() else { return; };
            let Some(owner) = result.as_ref().ok().and_then(|s| s.active.as_ref()) else { self.fail(); return; };
            if !r.open_pending || r.sessions.len() >= self.case.rounds() || owner.phase != edit::Phase::Opening
                || owner.checkout.is_some() || owner.prepared.is_some() || owner.apply_submitted
                || !r.project.as_ref().is_some_and(|p| p.id == owner.project_id)
                || r.sessions.iter().any(|s| s.projection.session_id == owner.session_id) { self.fail(); return; }
            r.open_pending = false;
            r.sessions.push(Session { projection: owner.clone(), prepare_requested: false, prepare_returned: false,
                review: None, review_visible: false, confirmation_count: 0, acknowledged: false,
                apply_requested: false, apply_returned: false, finality: None });
        }
        if let Ok(status) = result { self.edit_status(status,edits); }
    }
    pub(super) fn prepare_request(&self, args: &edit::PrepareConfigEdit) {
        let Some(mut r) = self.record() else { return; };
        let Some(round) = r.sessions.len().checked_sub(1) else { self.fail(); return; };
        let session = &r.sessions[round];
        if !matches!(r.step,Step::Prepare(i)|Step::Review(i) if i == round) || r.prepare_pending.is_some()
            || session.prepare_requested || session.projection.phase != edit::Phase::Editing
            || session.projection.session_id != args.session_id || r.reload_requested
            || !session.projection.checkout.as_ref().is_some_and(|c| c.revision == args.revision && c.base == args.expected_base)
            || args.expected_base != *self.expected_base(round) || args.draft != self.expected_draft(round)
            || (args.draft_revision,args.baseline_generation) != self.revisions(round) { self.fail(); return; }
        r.sessions[round].prepare_requested = true; r.prepare_pending = Some(round);
    }
    pub(super) fn prepare_result(&self, result: &Result<ConfigEditStatus, BridgeError>, edits: &EditOwner) {
        {
            let Some(mut r) = self.record() else { return; };
            let Some(round) = r.prepare_pending.take() else { self.fail(); return; };
            let Some(owner) = result.as_ref().ok().and_then(|s| s.active.as_ref()) else { self.fail(); return; };
            let session = &mut r.sessions[round];
            if session.prepare_returned || owner.phase != edit::Phase::Preparing || owner.apply_submitted
                || owner.prepared.is_some() || owner.session_id != session.projection.session_id
                || owner.checkout.as_ref().map(|c| &c.revision) != session.projection.checkout.as_ref().map(|c| &c.revision) { self.fail(); return; }
            session.prepare_returned = true;
        }
        if let Ok(status) = result { self.edit_status(status,edits); }
    }
    pub(super) fn apply_request(&self, id: &str, token: &str) {
        let Some(mut r) = self.record() else { return; };
        let round = match r.step { Step::Apply(i)|Step::Applied(i) => i, _ => { self.fail(); return; } };
        if self.case == Case::SaveLoss || r.reload_requested || self.case == Case::FirstSave && round != 0
            || self.case == Case::NoopStale && round == 1 && !r.fixture.mutated { self.fail(); return; }
        let Some(session) = r.sessions.get_mut(round) else { self.fail(); return; };
        if session.apply_requested || !session.acknowledged || !session.review_visible || !session.live_review()
            || session.projection.session_id != id || !session.projection.prepared.as_ref().is_some_and(|p| p.plan_token == token)
            || session.confirmation_count != (if self.case == Case::FirstSave { 2 } else { 1 }) { self.fail(); return; }
        session.apply_requested = true;
    }
    pub(super) fn apply_result(&self, result: &Result<ConfigEditStatus, BridgeError>, edits: &EditOwner) {
        {
            let Some(mut r) = self.record() else { return; };
            let Some(owner) = result.as_ref().ok().and_then(|s| s.active.as_ref()) else { self.fail(); return; };
            let Some(session) = r.sessions.iter_mut().find(|s| s.projection.session_id == owner.session_id) else { self.fail(); return; };
            if !session.apply_requested || session.apply_returned || owner.phase != edit::Phase::Applying || !owner.apply_submitted
                || owner.prepared.as_ref().map(|p| &p.plan_token) != session.projection.prepared.as_ref().map(|p| &p.plan_token) { self.fail(); return; }
            session.apply_returned = true;
        }
        if let Ok(status) = result { self.edit_status(status,edits); }
    }
    pub(super) fn close_request(&self) { self.fail(); } // Native Quit/loss, never synthetic Close IPC, owns EOF.
    pub(super) fn edit_status(&self, status: &ConfigEditStatus, edits: &EditOwner) {
        let Some(mut r) = self.record() else { return; };
        if status.schema_version != 1 || !edit::token(&status.window_generation) { self.fail(); return; }
        if r.status_revision.is_some_and(|old| old > status.status_revision) { return; }
        if let Some(before) = &r.generation {
            if before != &status.window_generation && !r.reload_requested { self.fail(); return; }
        } else { r.generation = Some(status.window_generation.clone()); }
        if status.capability.available && status.capability.reason == edit::EditAvailability::Available && !r.reload_requested { r.capability = true; }
        for p in status.last_terminal.iter().chain(status.active.iter()) {
            let Some(round) = r.sessions.iter().position(|s| s.projection.session_id == p.session_id) else {
                if r.open_pending { continue; } self.fail(); return;
            };
            let old = &r.sessions[round].projection;
            if p.domain != edit::EditDomain::Configuration || p.workflow.is_some() || p.metadata_text.is_some()
                || p.project_id != old.project_id || p.owner_generation != old.owner_generation || p.late_settled
                || !edit::token(&p.session_id) || p.phase == edit::Phase::Unknown || p.native_finality == edit::NativeFinality::Unknown
                || phase(p.phase) < phase(old.phase) || p.apply_submitted && !r.sessions[round].apply_requested
                || old.apply_submitted && !p.apply_submitted { self.fail(); return; }
            if let Some(c) = &p.checkout {
                if !edit::token(&c.revision) || c.base != *self.expected_base(round)
                    || old.checkout.as_ref().is_some_and(|v| v.revision != c.revision || v.base != c.base) { self.fail(); return; }
            } else if old.checkout.is_some() { self.fail(); return; }
            if let Some(prepared) = &p.prepared {
                let Some(review) = self.review_sample(&prepared.view,round) else { self.fail(); return; };
                if !r.sessions[round].prepare_requested || !edit::token(&prepared.plan_token)
                    || !p.checkout.as_ref().is_some_and(|c| c.revision == prepared.revision)
                    || (prepared.draft_revision,prepared.baseline_generation) != self.revisions(round)
                    || old.prepared.as_ref().is_some_and(|v| v.plan_token != prepared.plan_token)
                    || r.sessions[round].review.as_ref().is_some_and(|v| v != &review) { self.fail(); return; }
                r.sessions[round].review = Some(review);
            } else if r.sessions[round].review.is_some() { self.fail(); return; }
            let cancelled = self.case == Case::SaveLoss || self.case == Case::FirstSave && round == 1;
            let expected_native = if cancelled && phase(p.phase) >= phase(edit::Phase::Finalizing) {
                if self.case == Case::SaveLoss { edit::NativeEditReason::WindowLost } else { edit::NativeEditReason::Shutdown }
            } else { edit::NativeEditReason::None };
            if p.native_reason != expected_native { self.fail(); return; }
            if let Some(core) = &p.core_outcome {
                let (effect,journal,reason) = if cancelled { (edit::Effect::NotStarted,edit::Journal::NotCreated,edit::CoreReason::Cancelled) }
                    else if self.case == Case::FirstSave { (edit::Effect::Committed,edit::Journal::Clean,edit::CoreReason::None) }
                    else if round == 0 { (edit::Effect::Unchanged,edit::Journal::NotCreated,edit::CoreReason::None) }
                    else { (edit::Effect::NotStarted,edit::Journal::NotCreated,edit::CoreReason::StaleRevision) };
                if core.effect != effect || core.journal != journal || core.reason != reason || core.resources != edit::ResourceState::Settled {
                    self.fail(); return;
                }
            }
            if p.phase == edit::Phase::Final {
                if p.native_finality != edit::NativeFinality::Settled || p.core_outcome.is_none() || p.prepared.is_none()
                    || p.apply_submitted != !cancelled || cancelled && !(r.reload_requested || r.close_count == 2) { self.fail(); return; }
                if r.sessions[round].finality.is_none() {
                    let Some(facts) = edits.installed_observation_final(&p.session_id) else { self.fail(); return; };
                    if !finality(&facts,p,if cancelled { 2 } else { 3 }) { self.fail(); return; }
                    r.sessions[round].finality = Some(facts);
                }
            }
            r.sessions[round].projection = p.clone();
        }
        r.status_revision = Some(status.status_revision);
    }
    pub(super) fn tick(self: &Arc<Self>, app: &tauri::AppHandle) {
        if std::thread::current().id() == self.main { self.fail(); return; }
        // Drain the one prepared original even after failure/deadline: known
        // non-entry may retire its barrier, never dispatch a late Press.
        if self.accessibility_step() {
            if !self.timely() { self.report_failure(); self.failure_shutdown(app); }
            return;
        }
        if !self.timely() { self.report_failure(); self.failure_shutdown(app); return; }
        let state = app.state::<super::ShellState>();
        let step = {
            let Some(mut r) = self.record() else { return; };
            if !r.attached || !r.loaded || r.pending.is_some() { return; }
            if r.step == Step::Bootstrap {
                if !r.info || !r.catalog || !r.capability || !state.document.installed_macos_live() { return; }
                r.step = Step::Environment;
            }
            match r.step {
                Step::CancelSettled => {
                    if !r.cancel_returned { return; }
                    let Some(w) = state.document.installed_macos_cancelled(1) else { return; };
                    if w.operation_id != 1 || w.response != NativeResponse::Decline || !w.callback_returned || w.selected.is_some() {
                        self.fail(); return;
                    }
                    r.cancel_settled = true; r.step = Step::ReadCancelled; return;
                },
                Step::ProjectSettled => {
                    let Some(returned) = &r.project else { return; };
                    let Some((project,witness,response)) = state.document.installed_macos_project(self.case.selected_id()) else { return; };
                    if project.id != returned.id || project.path != returned.path || project.name != returned.name
                        || response.operation_id != self.case.selected_id() || response.response != NativeResponse::Accept
                        || response.selected.as_deref() != Some(self.project_path.as_path()) || !response.callback_returned {
                        self.fail(); return;
                    }
                    r.project_witness = Some(witness); r.project_settled = true; r.step = Step::Snapshot; return;
                },
                Step::PickerPending => {
                    let Some(witness) = state.document.installed_macos_picker_pending(1) else { return; };
                    if r.project.is_some() || r.project_returned { self.fail(); return; }
                    // Capture the same original before issuing a real reload.
                    if r.picker_witness.is_none() { r.picker_witness = Some(witness); }
                },
                Step::QuitCancelled => {
                    let Some(project) = &r.project_witness else { self.fail(); return; };
                    let Some(response) = state.document.installed_macos_quit_cancelled(3,project) else { return; };
                    if response.response != NativeResponse::Decline || !response.callback_returned || response.selected.is_some()
                        || response.operation_id != 3 || !r.sessions.get(1).is_some_and(Session::live_review) { self.fail(); return; }
                    let Some(witness) = r.review_witness.as_ref() else { self.fail(); return; };
                    // Publication/read-lock readiness is not a native failure.
                    // Keep polling under the SAME original tick deadline.
                    if !state.bridge.edits.installed_macos_review_retained(witness) { return; }
                    // The separately captured original review witness below
                    // must also prove its original deadline did not renew.
                    r.quit_cancelled = true; r.step = Step::RetainedReview; return;
                },
                Step::Lost => {
                    if !r.reload_returned || !(r.reload_navigation || r.loss_seen) { return; }
                    let settled = if self.case == Case::PickerLoss {
                        r.picker_witness.as_ref().is_some_and(|w| state.document.installed_macos_picker_lost(w))
                    } else {
                        r.project_witness.as_ref().is_some_and(|w| state.document.installed_macos_project_lost(w))
                            && r.sessions.first().is_some_and(|s| s.finality.is_some())
                            && r.review_witness.as_ref().is_some_and(|w| state.bridge.edits.installed_macos_lost(w))
                    };
                    if !settled { return; }
                    if r.fixture.verify(false).is_err() { self.fail(); return; }
                    r.loss_settled = true; r.file_readback = true; r.step = Step::Close; return;
                },
                Step::MutateIgnore => {
                    if self.case != Case::NoopStale || !r.sessions.get(1).is_some_and(|s| s.review_visible && s.live_review())
                        || r.fixture.mutate_ignore(self.end, &self.failed).is_err() { self.fail(); return; }
                    r.step = Step::OpenConfirmation(1); return;
                },
                Step::Applied(round) => {
                    let Some(session) = r.sessions.get(round) else { self.fail(); return; };
                    if !session.apply_returned || session.finality.is_none() { return; }
                    if !r.file_readback || round == 1 {
                        let checked = if self.case == Case::FirstSave { r.fixture.saved() } else { r.fixture.verify(true) };
                        if checked.is_err() { self.fail(); return; } r.file_readback = true;
                    }
                },
                Step::Snapshot if r.snapshots != 1 => return,
                Step::Suggestion if r.suggestion.is_none() => return,
                Step::Validation if !r.validation => return,
                Step::Previewed if r.preview.is_none() => return,
                Step::Requirements if r.requirements.is_none() => return,
                Step::GitHubProposal if r.workflows.is_none() => return,
                Step::Review(i) if !r.sessions.get(i).is_some_and(|s| s.prepare_returned && s.live_review()) => return,
                Step::Readback if r.snapshots != 2 => return,
                Step::Exit => return,
                _ => {},
            }
            r.step
        };
        let Some(window) = app.get_webview_window(super::MAIN_WINDOW) else { self.fail(); return; };
        if matches!(step, Step::Close | Step::CloseCancel) {
            let Some(mut r) = self.record() else { return; };
            if !state.document.installed_macos_safe_quit() || step == Step::CloseCancel
                && (!r.sessions.get(1).is_some_and(|s| s.review_visible && s.live_review()) || r.close_count != 0) { self.fail(); return; }
            if step == Step::CloseCancel {
                if r.review_witness.is_some() { self.fail(); return; }
                // Do not mark or dispatch close before original publication.
                let Some(w) = state.bridge.edits.installed_macos_review(&r.sessions[1].projection.session_id) else { return; };
                r.review_witness = Some(w);
            }
            r.pending = Some(Pending::Close(step));
            r.step = if step == Step::CloseCancel { Step::QuitCancel } else { Step::Quit };
            drop(r);
            if !self.timely() {
                // No close was dispatched. Clear only this local pending
                // marker so ordinary failure shutdown may still be considered.
                if let Some(mut r) = self.record() {
                    if r.pending == Some(Pending::Close(step)) { r.pending = None; }
                }
                return;
            }
            if window.close().is_err() { self.fail(); } return;
        }
        if matches!(step,Step::CancelProject|Step::SetProject|Step::OpenProject|Step::QuitCancel|Step::Quit|Step::PickerPending) {
            {
                let Some(mut r) = self.record() else { return; };
                // The entry check preceded this lock. A late tick must not
                // overwrite the first failure's returned sample or dispatch.
                if !self.timely() { return; }
                r.pending = Some(Pending::Native(step));
                r.native_dispatch = Some(NativeDispatch { step, entered: false, returned: false });
                r.last_panel = None; r.native_action = None;
            }
            let q = self.clone();
            if window.run_on_main_thread(move || q.native_step(step)).is_err() { self.fail(); } return;
        }
        if step == Step::Reload {
            {
                let Some(mut r) = self.record() else { return; };
                if !self.case.loses_document() || r.reload_requested { self.fail(); return; }
                if self.case == Case::SaveLoss {
                    let Some(session) = r.sessions.first().filter(|s| s.review_visible && s.live_review()) else { self.fail(); return; };
                    if r.review_witness.is_some() { self.fail(); return; }
                    // No reload flags or effect while the witness is not ready.
                    let Some(w) = state.bridge.edits.installed_macos_review(&session.projection.session_id) else { return; };
                    r.review_witness = Some(w);
                }
                r.reload_requested = true; r.pending = Some(Pending::Reload);
            }
            // A real WK reload attempt. The production navigation/Started
            // callback invalidates the existing document; no direct lost().
            let q = self.clone(); let reload = window.clone();
            if window.run_on_main_thread(move || {
                if !q.timely() { return; }
                // Established public Tauri eval dispatches a real WK reload.
                // The navigation/loss witness below, not this dispatch return,
                // proves the actual original-document invalidation.
                let result = reload.eval("window.location.reload()");
                let Some(mut r) = q.record() else { return; };
                if r.pending.take() != Some(Pending::Reload) || result.is_err() { q.fail(); return; }
                r.reload_returned = true; r.step = Step::Lost;
            }).is_err() { self.fail(); } return;
        }
        let original = {
            let Some(mut r) = self.record() else { return; };
            if r.evaluations >= 160 { self.fail(); return; }
            r.evaluations += 1;
            let original = DomDispatch { step, sequence: r.evaluations };
            r.pending = Some(Pending::Dom(original)); original
        };
        let Some(script) = script(step) else { self.fail(); return; };
        let q = self.clone();
        // Only one unresolved callback. Dispatch Ok is not its completion;
        // missing callback remains pending rather than replaying a click.
        if !self.timely() {
            // The eval has not been called: this is known non-dispatch,
            // not the repair of an uncertain callback or a cleared failure.
            if let Some(mut r) = self.record() {
                if r.pending == Some(Pending::Dom(original)) { r.pending = None; }
            }
            return;
        }
        if window.eval_with_callback(script,move |value| q.dom(original,&value)).is_err() {
            self.fail_with("dom-dispatch-refused");
        }
    }
    fn open_admission(&self, input: &PreparedOpenInput, after_press: bool) -> Option<bool> {
        let admitted = {
            let r = self.record()?;
            if !r.ax_trusted || input.id != self.case.selected_id() || !open_step_entry(r.pending, r.step, input.id)
                || r.prepared_open.is_some() || !r.accessibility.is_some_and(|s|
                    s.id == input.id && s.prepared && s.entered && !s.returned && !s.retired) { return None; }
            input.admitted(after_press)?
        }; // ALL Record/GuiFacts/owner-endpoint guards gone before AX IPC.
        Some(admitted && self.timely() && (after_press || !input.stopped()))
    }
    fn accessibility_step(&self) -> bool {
        let input = {
            let Some(mut r) = self.record() else { return true; };
            let Some(Pending::Accessibility(id)) = r.pending else { return false; };
            if id != self.case.selected_id() || !open_step_entry(r.pending, r.step, id) {
                self.fail_with("native-ax-custody"); return true;
            }
            // The synchronous relay owns a taken packet until actual return.
            // Missing/unknown custody is never permission to prepare again.
            let Some(input) = r.prepared_open.take() else { return true; };
            if input.id != id || !r.accessibility.is_some_and(|s| s.id == id && s.prepared && !s.entered && !s.returned)
                || !r.native_dispatch.is_some_and(|n| n.step == Step::OpenProject && n.entered && n.returned) {
                self.fail_with("native-ax-custody"); return true;
            }
            if !self.timely() {
                let retired = input.no_entry(input.admitted(true).is_some());
                if let Some(sample) = r.accessibility.as_mut() {
                    sample.retired = retired;
                    sample.diagnostic = Some(mrk_macos_installed_native::AxDiagnostic { site: "entry",
                        error: if Instant::now() >= self.end { "deadline" } else { "ineligible" } });
                }
                let current = r.step;
                if !retired || !retire_returned_open(&mut r.pending, current, id) { self.fail_with("native-ax-custody"); }
                return true; // Positive no FFI entry; no CF work or action flags.
            }
            if !input.enter() { self.fail_with("native-ax-custody"); return true; }
            if let Some(sample) = r.accessibility.as_mut() { sample.enter(); }
            input
        };
        // Existing retained/joined relay only: no spawn, task, thread or wait.
        // The main preparation body returned and its PANEL borrow is gone.
        let result = input.press(self.end, |after_press| self.open_admission(&input, after_press));
        if result.report.is_some_and(|r| !r.succeeded()) || !result.timely() { self.fail_with("native-ax-input"); }
        else if !result.custody_known { self.fail_with("native-ax-custody"); }
        let Some(mut r) = self.record() else { input.returned(&result, false); return true; };
        let matching = open_step_entry(r.pending, r.step, input.id) && r.prepared_open.is_none()
            && r.accessibility.is_some_and(|s| s.id == input.id && s.prepared && s.entered && !s.returned && !s.retired);
        // A publication lock may have waited after the final C callback. Check
        // same-original facts custody again; poison cannot retire the barrier.
        let retired = input.returned(&result, matching && input.admitted(true).is_some());
        if !matching { self.fail_with("native-ax-custody"); return true; }
        if let Some(sample) = r.accessibility.as_mut() { sample.complete(&result, retired); }
        if !retired { self.fail_with("native-ax-custody"); return true; }
        let current = r.step;
        if !retire_returned_open(&mut r.pending, current, input.id) { self.fail_with("native-ax-custody"); return true; }
        if !result.timely() { self.fail_with("native-ax-input"); return true; }
        if self.timely() && r.accessibility.is_some_and(OpenInputSample::succeeded) {
            if r.native_actions_returned[2] { self.fail_with("native-duplicate-action"); return true; }
            r.native_actions_returned[2] = true; r.selected_native = true; r.step = Step::ProjectSettled;
        }
        true
    }
    fn native_step(&self, step: Step) {
        let timely = self.timely();
        {
            let Some(mut r) = self.record() else { return; };
            if r.pending == Some(Pending::Native(step)) && r.step == step {
                if let Some(native) = r.native_dispatch.as_mut().filter(|native| native.step == step) { native.entered = true; }
            }
        }
        let mut action_diagnostic = None;
        let mut prepared_open = None; let mut open_sample = None;
        let result = self.native_step_body(step, timely, &mut action_diagnostic, &mut prepared_open, &mut open_sample);
        // Preserve the exact first refusal before any Record/cleanup failure.
        if let Err(reason) = result { self.fail_with(reason); }
        let Some(mut r) = self.record() else { return; };
        if r.pending != Some(Pending::Native(step)) || r.step != step { self.fail_with("native-pending-custody"); return; }
        if let Some(native) = r.native_dispatch.as_mut().filter(|native| native.step == step) { native.returned = true; }
        if result == Err("adapter-native-action") && first_failure_reason(&self.failure_reason) == Some("adapter-native-action") {
            r.native_action = action_diagnostic; // This same first error's returned DATA only.
        }
        if let Some(sample) = open_sample {
            if r.accessibility.is_some() { self.fail_with("native-ax-custody"); return; }
            r.accessibility = Some(sample);
        }
        // Keep the historical wrong-thread refusal conservative. Diagnostics
        // never authorize retirement; a different/unknown owner is untouched.
        if matches!(result, Err("native-wrong-thread" | "native-pending-custody")) { return; }
        let current = r.step;
        if !retire_returned_native(&mut r.pending, current, step) { self.fail_with("native-pending-custody"); return; }
        if let Some(input) = prepared_open {
            if step != Step::OpenProject || result != Ok(false) || r.prepared_open.is_some()
                || !r.native_dispatch.is_some_and(|n| n.step == step && n.entered && n.returned) {
                self.fail_with("native-ax-custody"); return;
            }
            // Publish only the returned preparation, not an action/dispatch
            // success. Nothing native runs after this handoff from the body.
            r.pending = Some(Pending::Accessibility(input.id)); r.prepared_open = Some(input); return;
        }
        match result {
            Ok(false) => {},
            Err(_) => {},
            Ok(true) => {
                let (index,next) = match step {
                    Step::CancelProject => (0,Step::CancelSettled), Step::SetProject => (1,Step::OpenProject),
                    Step::QuitCancel => (3,Step::QuitCancelled),
                    Step::Quit => (4,Step::Exit), Step::PickerPending => { r.step = Step::Reload; return; },
                    _ => { self.fail_with("native-step"); return; },
                };
                if r.native_actions_returned[index] { self.fail_with("native-duplicate-action"); return; }
                r.native_actions_returned[index] = true;
                r.step = next;
            },
        }
    }
    fn native_step_body(&self, step: Step, timely: bool,
        action_diagnostic: &mut Option<NativeActionSample>, prepared_open: &mut Option<PreparedOpenInput>,
        open_sample: &mut Option<OpenInputSample>) -> Result<bool, &'static str> {
        // This returned body has made no native query/action. Keep failed,
        // first reason, Step and original endpoint; only its matching slot may
        // retire in the caller, permitting ordinary failure shutdown to check.
        if !native_step_entry(std::thread::current().id() == self.main, timely)? { return Ok(false); }
        let (id,quit) = match step {
            Step::CancelProject | Step::PickerPending => (1,false),
            Step::SetProject | Step::OpenProject => (self.case.selected_id(),false),
            Step::QuitCancel => (3,true), Step::Quit => (self.case.quit_id(),true), _ => return Err("native-step"),
        };
        {
            let r = self.record().ok_or("observer-record-unavailable")?;
            if r.pending != Some(Pending::Native(step)) || r.step != step { return Err("native-pending-custody"); }
        }
        let Some(panel) = observed_panel().map_err(|error| error.reason())? else { return Ok(false); };
        {
            let mut r = self.record().ok_or("observer-record-unavailable")?;
            if r.pending != Some(Pending::Native(step)) || r.step != step { return Err("native-pending-custody"); }
            r.last_panel = Some(PanelSample::from_original(step, &panel));
            if !panel_readiness(&panel, id, quit, r.panel_attached[(id - 1) as usize],
                same_panel_action_returned(step, &r.native_actions_returned)?)? {
                // Only this known never-attached/no-history phase may wait.
                // No action, progress fact, or renewed endpoint is produced.
                return Ok(false);
            }
            r.panel_attached[(id - 1) as usize] = true;
        }
        if step == Step::PickerPending { return Ok(true); } // Observation only; never dismiss-as-Cancel.
        if step == Step::OpenProject && (!panel.native.directory_ready || !panel.native.directory_bound || !panel.native.directory_returned) {
            return Ok(false); // Before any Open action; original deadline remains unchanged.
        }
        if step == Step::OpenProject {
            if !self.timely() { return Err("observer-deadline"); }
            let mut sample = OpenInputSample::preparing(id);
            let prepared = prepare_open_input(id).map_err(|error| {
                sample.diagnostic = error.binding_diagnostic(); error.reason()
            });
            sample.prepared = prepared.is_ok(); *open_sample = Some(sample);
            *prepared_open = Some(prepared?);
            return Ok(false); // Deliberately NOT a native action return.
        }
        let action = match step {
            Step::CancelProject => PanelAction::ProjectCancel,
            Step::SetProject => PanelAction::ProjectDirectory(&self.project_path),
            Step::QuitCancel => PanelAction::QuitCancel, Step::Quit => PanelAction::QuitConfirm, _ => return Err("native-step"),
        };
        if !self.timely() { return Err("observer-deadline"); }
        // The original native API rechecks exact attachment before action.
        observe_panel_action(id,action).map_err(|error| {
            *action_diagnostic = error.action_diagnostic().map(|diagnostic| NativeActionSample { step, id, diagnostic });
            error.reason()
        })
    }
    pub(super) fn close_prevented(&self) {
        let Some(mut r) = self.record() else { return; };
        if self.failed.load(Ordering::SeqCst) && r.failure_close_requested { return; }
        let Some(Pending::Close(request)) = r.pending.take() else { self.fail(); return; };
        if !matches!((request,r.step),(Step::CloseCancel,Step::QuitCancel)|(Step::Close,Step::Quit)) {
            self.fail(); return;
        } r.close_count += 1;
    }
    fn failure_shutdown(self: &Arc<Self>, app: &tauri::AppHandle) {
        let state = app.state::<super::ShellState>();
        let Some(window) = app.get_webview_window(super::MAIN_WINDOW) else { return; };
        let Some(mut r) = self.record() else { return; };
        if r.pending.is_some() || r.failure_quit_attempted { return; }
        if !r.failure_close_requested {
            if !state.document.installed_macos_safe_quit() { return; }
            r.pending = Some(Pending::FailureClose); drop(r);
            let q = self.clone(); let closing = window.clone();
            if window.run_on_main_thread(move || {
                // Document/GuiFacts admission is not TLS PANEL absence.
                // Observe on its actual main thread; any retained object or
                // uncertainty vetoes this sole ordinary shutdown request.
                let absent = matches!(observed_panel(), Ok(None));
                let admitted = absent && closing.state::<super::ShellState>().document.installed_macos_safe_quit();
                let Some(mut r) = q.record() else { return; };
                if r.pending.take() != Some(Pending::FailureClose) { q.fail(); return; }
                if !admitted { r.failure_quit_attempted = true; return; }
                r.failure_close_requested = true; drop(r);
                // Cleanup may run after the action endpoint, but can never
                // clear the failed latch or make this case successful.
                if closing.close().is_err() {
                    if let Some(mut r) = q.record() { r.failure_quit_attempted = true; }
                }
            }).is_err() {
                if let Some(mut r) = self.record() { r.failure_quit_attempted = true; }
            }
            return;
        }
        r.pending = Some(Pending::Native(Step::Quit)); drop(r);
        let q = self.clone();
        if window.run_on_main_thread(move || {
            let result = (|| -> Result<Option<u32>, ()> {
                let Some(p) = observed_panel().map_err(|_| ())? else { return Ok(None); };
                if !matches!(p.native.kind,mrk_macos_installed_native::PanelKind::Quit) || !p.action_allowed
                    || !p.native.started || !p.native.attached || p.native.action_attempted || p.native.close_attempted
                    || p.native.callback_returned || p.native.response.is_some() { return Err(()); }
                Ok(Some(p.id))
            })();
            let Some(mut r) = q.record() else { return; };
            r.pending = None;
            match result {
                Ok(None) => {}, // No object existed; no native action was attempted.
                Ok(Some(id)) => {
                    r.failure_quit_attempted = true; drop(r);
                    // No retry even if this ordinary Quit action is refused.
                    let _ = observe_panel_action(id,PanelAction::QuitConfirm);
                },
                Err(()) => r.failure_quit_attempted = true,
            }
        }).is_err() {
            if let Some(mut r) = self.record() { r.failure_quit_attempted = true; }
        }
    }
    fn dom(&self, original: DomDispatch, raw: &str) {
        let Some(mut r) = self.record() else { return; };
        if !dom_step_entry(r.pending, r.step, original) { self.fail_with("dom-pending-custody"); return; }
        // Keep this guard and marker throughout the body: no lock reacquisition,
        // second dispatch or substituted callback can acquire its custody. A
        // panic unwinds with the marker retained and poisons this Record lock.
        self.dom_body(&mut r, original.step, raw);
        // Known returned bookkeeping only, including late/malformed failures.
        // This does not restore success or establish native/invocation finality.
        if !retire_returned_dom(&mut r.pending, original) { self.fail_with("dom-pending-custody"); }
    }
    fn dom_body(&self, r: &mut Record, step: Step, raw: &str) {
        if !self.timely() { return; }
        if raw.len() > 128 * 1024 { self.fail_with("dom-callback-size"); return; }
        let Ok(v) = crate::protocol::strict_json(raw.as_bytes()) else { self.fail_with("dom-callback-json"); return; };
        let Some(object) = v.as_object() else { self.fail_with("dom-callback-object"); return; };
        if v["state"] == "wait" && object.len() == 1 { return; }
        if v["state"] != "ready" { self.fail_with("dom-callback-state"); return; }
        let review_round = match step { Step::Review(i) => Some(i), Step::KeptReview => Some(0), Step::RetainedReview => Some(1), _ => None };
        if let Some(i) = review_round {
            if !r.sessions.get(i).is_some_and(|s| s.live_review() && s.review.as_ref() == v.get("review"))
                || v["project"].as_str() != self.project_path.to_str() { self.fail(); return; }
            if matches!(step,Step::KeptReview|Step::RetainedReview) && r.fixture.verify(step == Step::RetainedReview).is_err() {
                self.fail(); return;
            }
        }
        let valid = match step {
            Step::ReadEnvironment => v["mode"] == "available" && v["title"] == "Bundled runtime"
                && v["platform"] == "macos" && v["rows"].as_u64() == Some(r.methods as u64)
                && v["available"].as_u64() == Some(8) && v["unavailable"].as_u64() == Some((r.methods - 8) as u64),
            Step::ReadCancelled => r.cancel_settled && v["unselected"] == true && v["chooseEnabled"] == true,
            Step::Snapshot => r.project_settled && r.snapshots == 1 && v["name"] == self.case.name()
                && v["configuration"] == (if self.case == Case::NoopStale { "Format-valid only" } else { "Not configured" }),
            Step::Suggestion => r.suggestion.as_ref() == v.get("provenance"),
            Step::Draft => v["source"] == "version.properties" && v["saveAvailable"] == true
                && v["dirty"].as_bool() == Some(self.case != Case::NoopStale),
            Step::Validation => r.validation && v["title"] == "Format validation complete" && v["issues"] == 0,
            Step::Previewed => r.preview.as_ref() == v.get("preview") && v["current"] == true,
            Step::Requirements => r.requirements.as_ref() == v.get("roles") && v["host"] == "Core host: macos"
                && v["notChecked"] == 3,
            Step::GitHubProposal => r.workflows.as_ref() == v.get("workflows") && v["localAvailable"] == false
                && v["remoteAvailable"] == false && v["badge"] == "GitHub not contacted",
            Step::Confirmation(i)|Step::Acknowledged(i) => {
                let Some(s) = r.sessions.get(i) else { self.fail(); return; };
                let acknowledged = matches!(step,Step::Acknowledged(_));
                s.live_review() && v["project"].as_str() == self.project_path.to_str()
                    && s.review.as_ref().is_some_and(|sample| v["files"] == sample["files"])
                    && v["title"] == (if self.no_op(i) { "Confirm the no-op plan?" } else { "Apply this configuration save?" })
                    && v["checked"].as_bool() == Some(acknowledged) && v["applyAvailable"].as_bool() == Some(acknowledged)
                    && v["draftRevision"].as_u64() == Some(self.revisions(i).0 as u64)
            },
            Step::Applied(i) => {
                let Some(s) = r.sessions.get(i) else { self.fail(); return; };
                let Some(core) = &s.projection.core_outcome else { self.fail(); return; };
                let expected = match (self.case,i) { (Case::FirstSave,0) => "Submitted configuration saved",
                    (Case::NoopStale,0) => "No changes needed", (Case::NoopStale,1) => "Save session ended; draft retained", _ => "" };
                s.finality.is_some() && v["title"] == expected && v["source"] == self.expected_draft(i)["version"]["source"]
                    && v["facts"] == json!([["Transaction effect",core.effect],["Journal",core.journal],
                        ["Core resources",core.resources],["Native finality","settled"]])
                    && (i != 1 || v["code"] == "stale_revision" && v["dirty"] == true)
            },
            Step::Readback => r.snapshots == 2 && v["name"] == self.case.name() && v["configuration"] == "Format-valid only"
                && v["applicationId"] == APP_ID && v["stale"] == false,
            Step::ChangedDraft => v["source"] == "stale-version.properties" && v["dirty"] == true && v["saveAvailable"] == true,
            _ => true,
        };
        if !valid { self.fail(); return; }
        // Parsing and witness/fixture checks spend the same original deadline.
        // Recheck immediately before any ready flags, counts or Step transition.
        if !self.timely() { return; }
        r.step = match step {
            Step::Environment => Step::ReadEnvironment, Step::ReadEnvironment => Step::Dashboard,
            Step::Dashboard => if self.case == Case::FirstSave { Step::ChooseCancel } else { Step::ChooseProject },
            Step::ChooseCancel => { r.project_calls += 1; Step::CancelProject }, Step::ReadCancelled => Step::ChooseProject,
            Step::ChooseProject => { r.project_calls += 1; if self.case == Case::PickerLoss { Step::PickerPending } else { Step::SetProject } },
            Step::Snapshot => Step::Settings, Step::Settings => if self.case == Case::NoopStale { Step::Draft } else { Step::Suggest },
            Step::Suggest => Step::Suggestion, Step::Suggestion => Step::Adopt, Step::Adopt => Step::Draft,
            Step::Draft => { r.draft_visible = true; Step::Validate }, Step::Validate => Step::Validation,
            Step::Validation => Step::Preview, Step::Preview => Step::Previewed,
            Step::Previewed => if self.case == Case::FirstSave { Step::RequirementsPage } else { Step::Prepare(0) },
            Step::RequirementsPage => Step::LoadRequirements, Step::LoadRequirements => Step::Requirements,
            Step::Requirements => Step::GitHubPage, Step::GitHubPage => Step::GitHubRepository,
            Step::GitHubRepository => Step::GitHubSha, Step::GitHubSha => Step::GitHubPropose,
            Step::GitHubPropose => Step::GitHubProposal, Step::GitHubProposal => { r.guidance_visible = true; Step::ReturnSettings },
            Step::ReturnSettings => Step::Prepare(0), Step::Prepare(i) => Step::Review(i),
            Step::Review(i) => {
                r.sessions[i].review_visible = true;
                if self.case == Case::SaveLoss { Step::Reload } else if i == 1 {
                    if self.case == Case::FirstSave { Step::CloseCancel } else { Step::MutateIgnore }
                } else { Step::OpenConfirmation(i) }
            },
            Step::OpenConfirmation(i) => { r.sessions[i].confirmation_count += 1; Step::Confirmation(i) },
            Step::Confirmation(i) => if self.case == Case::FirstSave && !r.keep_reviewing { Step::KeepReviewing } else { Step::Acknowledge(i) },
            Step::KeepReviewing => Step::KeptReview, Step::KeptReview => { r.keep_reviewing = true; Step::OpenConfirmation(0) },
            Step::Acknowledge(i) => Step::Acknowledged(i), Step::Acknowledged(i) => { r.sessions[i].acknowledged = true; Step::Apply(i) },
            Step::Apply(i) => Step::Applied(i),
            Step::Applied(i) => match (self.case,i) {
                (Case::FirstSave,0) => { r.saved_visible = true; Step::ReadbackPage },
                (Case::NoopStale,0) => { r.noop_visible = true; Step::ChangeDraft },
                (Case::NoopStale,1) => { r.stale_visible = true; Step::Close }, _ => { self.fail(); return; },
            },
            Step::ReadbackPage => Step::Refresh, Step::Refresh => Step::Readback, Step::Readback => Step::SavedSettings,
            Step::SavedSettings => Step::Prepare(1), Step::ChangeDraft => Step::ChangedDraft, Step::ChangedDraft => Step::Prepare(1),
            Step::RetainedReview => Step::Close, _ => { self.fail(); return; },
        };
    }
    pub(super) fn relay_joined(&self, joined: bool) {
        let Some(mut r) = self.record() else { return; };
        if !joined || r.relay_joined { self.fail(); return; } r.relay_joined = true;
    }
    pub(super) fn actual_exit(&self, ready: bool, document: &DocumentBinding, edits: &EditOwner) {
        if let Ok(status) = edits.status() { self.edit_status(&status,edits); } else { self.fail(); }
        let Some(mut r) = self.record() else { return; };
        let finality = document.installed_macos_final(self.case.quit_id(),r.project_witness.as_ref(),r.picker_witness.as_ref(),self.case.loses_document());
        if !ready || !finality || !r.relay_joined || r.actual_exit || r.step != Step::Exit || r.pending.is_some()
            || !r.native_actions_returned[4] || !r.sessions.iter().all(|s| s.finality.is_some()) { self.fail(); return; }
        r.originals_final = true; r.actual_exit = true;
    }
    fn finish(&self) -> Option<Value> {
        if !self.timely() { return None; }
        let r = self.record()?;
        let common = r.attached && r.loaded && r.info && r.catalog && r.capability && r.actual_exit && r.originals_final
            && r.relay_joined && r.pending.is_none() && r.step == Step::Exit && r.file_readback
            && r.ax_trusted && r.prepared_open.is_none()
            && (if self.case == Case::PickerLoss { r.accessibility.is_none() }
                else { r.accessibility.is_some_and(|s| s.id == self.case.selected_id() && s.succeeded()) })
            && r.sessions.len() == self.case.rounds() && r.sessions.iter().all(|s| s.review_visible && s.finality.is_some())
            && (self.case == Case::FirstSave || r.panel_attached == [true,true,false,false])
            && r.project_calls == (if self.case == Case::FirstSave { 2 } else { 1 });
        let specific = match self.case {
            Case::FirstSave => r.cancel_settled && r.project_settled && r.keep_reviewing && r.saved_visible && r.guidance_visible
                && r.snapshots == 2 && r.quit_cancelled && r.close_count == 2 && r.native_actions_returned == [true;5]
                && r.panel_attached == [true;4] && r.fixture.written && !r.fixture.mutated,
            Case::NoopStale => r.project_settled && r.noop_visible && r.stale_visible && r.fixture.mutated && !r.fixture.written
                && r.close_count == 1 && r.native_actions_returned == [false,true,true,false,true] && r.snapshots == 1,
            Case::PickerLoss => r.picker_witness.is_some() && r.project.is_none() && r.sessions.is_empty()
                && r.native_actions_returned == [false,false,false,false,true] && r.loss_settled && r.close_count == 1,
            Case::SaveLoss => r.project_settled && r.review_witness.is_some() && r.loss_settled && r.close_count == 1
                && r.native_actions_returned == [false,true,true,false,true] && r.sessions[0].apply_requested == false,
        };
        if !common || !specific || r.fixture.verify(matches!(self.case,Case::FirstSave|Case::NoopStale)).is_err() { return None; }
        let sessions: Vec<_> = r.sessions.iter().map(|s| {
            let f = s.finality.as_ref()?; let p = s.projection.prepared.as_ref()?;
            Some(json!({"draftRevision":p.draft_revision,"baselineGeneration":p.baseline_generation,
                "files":p.view.files,"createReleaseDirectory":p.view.create_release_directory,
                "reviewMatched":s.review_visible,"confirmationsOpened":s.confirmation_count,"acknowledged":s.acknowledged,
                "apply":s.apply_requested,"outcome":s.projection.core_outcome,"nativeReason":s.projection.native_reason,
                "nativeFinality":s.projection.native_finality,"writerFrames":f.writer_frames,"stdoutFrames":f.stdout_frames,
                "originalsJoined":finality(f,&s.projection,if s.apply_requested { 3 } else { 2 })}))
        }).collect::<Option<Vec<_>>>()?;
        let report = json!({"schemaVersion":1,"sourceCommit":option_env!("GITHUB_SHA"),"runId":option_env!("GITHUB_RUN_ID"),
            "runAttempt":option_env!("GITHUB_RUN_ATTEMPT"),"case":self.case.name(),"instrumentedEngineeringApp":true,
            "shippingBinaryQualified":false,"distributionQualified":false,"methods":"eight-passive","actionsAvailable":false,
            "native":{"projectCancelSettled":r.cancel_settled,"selectedPathMatched":r.selected_native && r.project_settled,
                "panelAttachments":r.panel_attached,"controlReturns":r.native_actions_returned,
                "accessibilityTrustedWithoutPrompt":r.ax_trusted,"projectOpenInput":r.accessibility.map(OpenInputSample::value),
                "quitCancelKeptOriginalReview":r.quit_cancelled,"originalDocumentAndQuitSettled":r.originals_final},
            "saveSessions":sessions,"freshCoreReadback":self.case == Case::FirstSave && r.snapshots == 2,
            "syntheticFileReadback":r.file_readback,"staleMarkerWriterReturnedAndClosed":r.fixture.mutated,
            "reload":{"requested":r.reload_requested,"dispatchReturned":r.reload_returned,"navigationDenied":r.reload_navigation,
                "secondStarted":r.loss_seen,"originalLossSettled":r.loss_settled,"webProcessCrashTested":false},
            "originalRelayJoined":r.relay_joined,"actualExit":r.actual_exit,
            "scope":"programmatic genuine controls; no Store, release, distribution or physical-device evidence"});
        self.timely().then_some(report)
    }
}

fn phase(p: edit::Phase) -> u8 { match p { edit::Phase::Opening => 0,edit::Phase::Editing => 1,edit::Phase::Preparing => 2,
    edit::Phase::Reviewing => 3,edit::Phase::Applying => 4,edit::Phase::Finalizing => 5,edit::Phase::Final => 6,edit::Phase::Unknown => 7 } }
fn finality(f: &InstalledConfigFinality, p: &EditProjection, frames: usize) -> bool {
    f.session_id == p.session_id && f.project_id == p.project_id && f.owner_generation == p.owner_generation
        && f.writer_frames == frames && f.stdout_frames == 3 && f.inspection_joined && f.acquisition_joined && f.child_waited_success
        && f.stdin_closed && f.stdout_eof_closed && f.stderr_eof_closed && f.io_joined
        && f.driver_joined && f.watchdog_joined && f.manager_joined && f.runtime_ledger_settled && f.runtime_settlement_joined
}
fn assurance(v: &Value, basis: &str) -> bool { v["assurance"]["basis"] == basis && v["assurance"]["releaseReadiness"] == "unknown"
    && ["projectCodeExecuted","toolsProbed","credentialsRead","gitObserved","storeContacted","writesPerformed"]
        .iter().all(|k| v["assurance"][*k] == false) }
fn format_valid(v: &Value) -> bool { v["valid"] == true && v["state"] == "format-valid" && v["issues"].as_array().is_some_and(Vec::is_empty)
    && v["requirements"].as_array().is_some_and(|r| r.len() <= 128 && r.iter().all(|r| r["state"] == "unknown")) && assurance(v,"schema-policy") }

// Synchronous expressions operate only existing production controls. No direct
// invoke/reducer access, DTO injection, synthetic event, Promise or hidden UI.
// `wait` is returned only before an action, so completed side effects never
// replay. Every returned read is from actual DOM/controller rendering.
fn script(step: Step) -> Option<String> {
    let body = match step {
        Step::Environment|Step::RequirementsPage => "return nav('Environment');",
        Step::Dashboard|Step::ReadbackPage => "return nav('Dashboard');",
        Step::Settings|Step::ReturnSettings|Step::SavedSettings => "return nav('Project settings');",
        Step::GitHubPage => "return nav('GitHub');",
        Step::ReadEnvironment => r#"const card=document.querySelector('.runtime-card'),rows=[...document.querySelectorAll('.capability-list > div')];
            if (!selected('Environment')||!card||rows.length<8) return wait(); if(rows.length>64)throw 0;
            show(card);const versions=[...card.querySelectorAll('.runtime-versions strong')].map(text);if(versions.length!==3)throw 0;
            return {state:'ready',title:text(card.querySelector('h2')),mode:text(card.querySelector('.badge')),platform:versions[2],rows:rows.length,
                available:rows.filter(r=>text(r.querySelector('.badge'))==='Available · passive').length,
                unavailable:rows.filter(r=>text(r.querySelector('.badge'))==='Unavailable').length};"#,
        Step::ChooseCancel|Step::ChooseProject => r#"if(!selected('Dashboard'))return wait();
            const b=[...document.querySelectorAll('.page-heading button')].find(b=>text(b)==='Choose a project');
            if(!b||b.disabled)return wait();show(b);b.click();return ready();"#,
        Step::ReadCancelled => r#"const b=[...document.querySelectorAll('.page-heading button')].find(b=>text(b)==='Choose a project');
            if(!b||b.disabled)return wait();show(b);return {state:'ready',chooseEnabled:!b.disabled,
                unselected:text(document.querySelector('.project-identity h2'))==='Your next release, organized.'&&!document.querySelector('.observation-facts,.draft-banner')};"#,
        Step::Snapshot => r#"const facts=document.querySelector('.observation-facts');if(!selected('Dashboard')||!facts)return wait();show(facts);
            return {state:'ready',name:text(document.querySelector('.project-identity h2')),configuration:text(document.querySelector('.project-badges .badge'))};"#,
        Step::Suggest => r#"const b=document.querySelector('.suggestion-card button[aria-describedby="suggestion-reason"]');
            if(!selected('Project settings')||!b||b.disabled)return wait();if(text(b)!=='Prepare suggested draft'||document.querySelector('.draft-banner,.suggestion-result'))throw 0;
            show(b);b.click();return ready();"#,
        Step::Suggestion => r#"const result=document.querySelector('.suggestion-result');if(!result)return wait();
            const rows=[...result.querySelectorAll('.provenance-list > li')];if(!rows.length||rows.length>64)throw 0;show(result);
            const codes={'Unverified hint':'hint','Core default':'default','Example only':'example'};
            return {state:'ready',provenance:rows.map(row=>({path:text(row.querySelector('code')),source:codes[text(row.querySelector('.badge'))]??'error'}))};"#,
        Step::Adopt => r#"const b=document.querySelector('.suggestion-adopt button');if(!b||b.disabled)return wait();
            if(text(b)!=='Use as an in-memory draft'||document.querySelector('.draft-banner'))throw 0;show(b);b.click();return ready();"#,
        Step::Draft|Step::ChangedDraft => r#"if(!selected('Project settings')||!document.querySelector('.draft-banner')||!field())return wait();return {state:'ready',...draft()};"#,
        Step::Validate => "return toolbar('draft-validation-reason','Validate only');",
        Step::Validation => r#"const card=document.querySelector('.validation-card');if(!card)return wait();show(card);
            return {state:'ready',title:text(card.querySelector('h2')),issues:card.querySelectorAll('.issues > li').length};"#,
        Step::Preview => "return toolbar('draft-review-reason','Review draft changes');",
        Step::Previewed => r#"const r=document.querySelector('.draft-review');if(!r)return wait();show(r);
            const detail=r.querySelector('.context-details'),nums=[...r.querySelectorAll('.review-counts > span > strong')].map(number);
            if(!detail||nums.length!==3)throw 0;const sections=r.querySelectorAll(':scope > .review-section-heading');if(sections.length!==2)throw 0;
            return {state:'ready',current:text(r.querySelector('.section-heading .badge'))==='Current draft · retained baseline',
                preview:{counts:{added:nums[0],changed:nums[1],removed:nums[2]},fields:detail.querySelectorAll('ul > li').length,valid:text(sections[1].querySelector('.badge'))}};"#,
        Step::LoadRequirements => r#"if(!selected('Environment'))return wait();const controls=document.querySelector('.environment-controls');if(!controls)return wait();
            const platform=controls.querySelector('#environment-platform'),op=controls.querySelector('#environment-operation');
            if(!platform||!op||platform.disabled||op.disabled||platform.value!=='android'||op.value!=='build')throw 0;
            const b=[...controls.closest('section.card').querySelectorAll('.button-row button')].find(b=>text(b)==='Load draft requirements');
            if(!b||b.disabled)return wait();show(b);b.click();return ready();"#,
        Step::Requirements => r#"const list=document.querySelector('.environment-requirements');if(!list)return wait();const card=list.closest('section.card');
            if(card.getAttribute('aria-busy')!=='false')return wait();const rows=[...list.querySelectorAll(':scope > article.tool-card')];if(rows.length!==3)throw 0;
            const roles=rows.map(row=>{show(row);const p=[...row.querySelectorAll(':scope > p')];if(p.length!==3)throw 0;
                const help=row.querySelector('.help-button');if(!help||help.disabled||help.getAttribute('aria-label')!=='Help: '+text(row.querySelector('h3')))throw 0;
                return {label:text(row.querySelector('h3')),where:text(p[2])}});
            return {state:'ready',roles,host:text(card.querySelector(':scope > .button-row .save-note')),
                notChecked:rows.filter(row=>text(row.querySelector('.button-row .badge'))==='Not checked').length};"#,
        Step::GitHubRepository => r#"if(!selected('GitHub')||!document.querySelector('form.github-form'))return wait();const g=github();if(g.repo.value!==''||g.sha.value!==''||g.comparison.checked)throw 0;
            insert(g.repo,'example/toolkit','');return ready();"#,
        Step::GitHubSha => r#"const g=github();if(g.repo.value!=='example/toolkit'||g.sha.value!==''||g.comparison.checked)throw 0;
            insert(g.sha,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','');return ready();"#,
        Step::GitHubPropose => r#"const g=github();if(g.repo.value!=='example/toolkit'||g.sha.value!=='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'||g.comparison.checked)throw 0;
            if(g.button.disabled)return wait();if(text(g.button)!=='Preview GitHub setup')throw 0;show(g.button);g.button.click();return ready();"#,
        Step::GitHubProposal => r#"const p=document.querySelector('.github-proposal');if(!p)return wait();const rows=[...p.querySelectorAll('details.github-workflow')];
            if(rows.length!==4)throw 0;const workflows=rows.map(row=>{const summary=row.querySelector(':scope > summary');if(!summary)throw 0;
                show(summary);if(!row.open)summary.click();if(!row.open)throw 0;const pre=row.querySelector('pre'),code=pre?.querySelector('code');
                if(!pre||!code||code.textContent.length>8192)throw 0;show(pre);return {path:text(summary.querySelector('code')),content:code.textContent}});
            const local=document.querySelector('button[aria-describedby="github-workflow-start-reason"]'),remote=[...document.querySelectorAll('.github-disabled-actions button')];
            if(!local||remote.length!==3)throw 0;return {state:'ready',workflows,localAvailable:!local.disabled,remoteAvailable:remote.some(b=>!b.disabled),badge:text(p.querySelector('.badge'))};"#,
        Step::Prepare(_) => "return toolbar('draft-save-reason','Prepare save review');",
        Step::Review(_)|Step::KeptReview|Step::RetainedReview => r#"if(document.querySelector('dialog'))return wait();const p=document.querySelector('.native-save-panel');
            const r=p?.querySelector('.save-review'),b=p?.querySelector('.save-actions button.primary');if(!r||!b||b.disabled)return wait();
            if(!['Apply reviewed save','Review no-op confirmation'].includes(text(b)))throw 0;
            const path=p.querySelectorAll(':scope > .save-project-path code');if(path.length!==1)throw 0;show(path[0]);
            return {state:'ready',project:text(path[0]),review:review(r)};"#,
        Step::OpenConfirmation(_) => r#"if(document.querySelector('dialog'))throw 0;const b=document.querySelector('.native-save-panel .save-actions button.primary');
            if(!b||b.disabled)return wait();if(!['Apply reviewed save','Review no-op confirmation'].includes(text(b)))throw 0;show(b);b.click();return ready();"#,
        Step::Confirmation(_)|Step::Acknowledged(_) => r#"const d=document.querySelector('dialog.save-confirm-dialog');if(!d||!d.open)return wait();const c=confirm();
            const p=c.dialog.querySelectorAll('.save-project-path code'),first=c.dialog.querySelector('.dialog-content > p');
            const revision=/^This confirms submitted draft revision ([0-9]{1,10}), not any later edits\. /.exec(text(first));if(p.length!==1||!revision)throw 0;
            return {state:'ready',project:text(p[0]),title:text(c.dialog.querySelector('h2')),files:inventory(c.dialog),draftRevision:Number(revision[1]),checked:c.check.checked,applyAvailable:!c.apply.disabled};"#,
        Step::KeepReviewing => r#"const c=confirm();if(c.check.checked||!c.apply.disabled)throw 0;show(c.keep);c.keep.click();return ready();"#,
        Step::Acknowledge(_) => r#"const c=confirm();if(c.check.checked||!c.apply.disabled)throw 0;show(c.check);c.check.click();return ready();"#,
        Step::Apply(_) => r#"const c=confirm();if(!c.check.checked||c.apply.disabled)throw 0;show(c.apply);c.apply.click();return ready();"#,
        Step::Applied(_) => r#"if(document.querySelector('dialog'))return wait();const p=document.querySelector('.native-save-panel'),f=p?.querySelector('.save-outcome-facts');
            if(!f)return wait();const rows=[...f.querySelectorAll(':scope > div')];if(rows.length!==4)throw 0;
            const d=draft();if(!d.saveAvailable)return wait();show(f);return {state:'ready',...d,title:text(p.querySelector('h2')),
                code:text(p.querySelector('.error-code')),facts:rows.map(row=>[text(row.querySelector('dt')),text(row.querySelector('dd'))])};"#,
        Step::Refresh => r#"if(!selected('Dashboard'))return wait();const b=[...document.querySelectorAll('.observation-card button')].find(b=>text(b)==='Refresh static view');
            if(!b||b.disabled)return wait();show(b);b.click();return ready();"#,
        Step::Readback => r#"if(!selected('Dashboard'))return wait();const id=document.querySelector('.identity-strip .identity-detail strong');if(!id)return wait();show(id);
            return {state:'ready',applicationId:text(id),name:text(document.querySelector('.project-identity h2')),configuration:text(document.querySelector('.project-badges .badge')),
                stale:[...document.querySelectorAll('.notice-info strong')].some(e=>text(e)==='This static observation predates the last settled save check')};"#,
        Step::ChangeDraft => r#"const f=field();if(!f)return wait();insert(f,'stale-version.properties','version.properties');return ready();"#,
        _ => return None,
    };
    Some(format!(r#"(() => {{try{{
        const ready=()=>({{state:'ready'}}),wait=()=>({{state:'wait'}}),text=e=>(e?.textContent??'').replace(/\s+/g,' ').trim();
        const visible=e=>!!e&&e.getClientRects().length>0&&getComputedStyle(e).visibility!=='hidden';
        const show=e=>{{if(!e)throw 0;e.scrollIntoView({{block:'center'}});if(!visible(e))throw 0}};
        const selected=name=>!!document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="'+name+'"][aria-current="page"]');
        const nav=name=>{{const b=document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="'+name+'"]');if(!b)return wait();if(b.disabled)throw 0;show(b);b.click();return ready()}};
        const number=e=>{{const s=text(e);if(!/^[0-9]{{1,7}}$/.test(s))throw 0;return Number(s)}};
        const field=()=>{{const rows=[...document.querySelectorAll('.form-field')].filter(f=>f.querySelector('.help-button')?.getAttribute('aria-label')==='Help: Committed version file');
            if(!rows.length)return null;if(rows.length!==1)throw 0;const input=rows[0].querySelector('input[type="text"]');if(!input||input.disabled||input.value.length>512)throw 0;return input}};
        const draft=()=>{{const f=field(),banner=document.querySelector('.draft-banner'),save=document.querySelector('.draft-toolbar button[aria-describedby="draft-save-reason"]');
            if(!f||!banner||!save||!selected('Project settings'))throw 0;show(f);return {{source:f.value,dirty:text(banner.querySelector('.badge'))==='Unsaved changes',saveAvailable:!save.disabled}}}};
        const toolbar=(reason,label)=>{{if(!selected('Project settings'))return wait();if(document.querySelector('dialog'))throw 0;const b=document.querySelector('.draft-toolbar button[aria-describedby="'+reason+'"]');
            if(!b||b.disabled)return wait();if(text(b)!==label)throw 0;show(b);b.click();return ready()}};
        const insert=(input,replacement,before)=>{{if(input.value!==before||input.disabled||input.readOnly)throw 0;show(input);input.focus();input.select();
            if(document.activeElement!==input||input.selectionStart!==0||input.selectionEnd!==before.length||!document.execCommand('insertText',false,replacement))throw 0}};
        const github=()=>{{const forms=document.querySelectorAll('form.github-form');
            if(!selected('GitHub')||forms.length!==1||document.querySelector('dialog,.github-assertions'))throw 0;
            const form=forms[0],repos=form.querySelectorAll('input#github-toolkit-repository'),shas=form.querySelectorAll('input#github-toolkit-sha');
            const comparison=form.querySelector('.github-comparison-toggle input[type="checkbox"]'),button=form.querySelector('.github-propose-action button[type="submit"]');
            if(repos.length!==1||shas.length!==1||!comparison||!button)throw 0;const repo=repos[0],sha=shas[0];
            if([repo,sha].some(i=>i.type!=='text'||i.disabled||i.readOnly)||repo.value.length>140||sha.value.length>40)throw 0;return {{repo,sha,comparison,button}}}};
        const inventory=root=>{{const tables=root.querySelectorAll('.save-files table');if(tables.length!==1)throw 0;const t=tables[0];
            if(text(t.querySelector('caption'))!=='Exact native destination inventory')throw 0;show(t);const rows=[...t.querySelectorAll('tbody > tr')];if(rows.length!==2)throw 0;
            const action={{'Create':'create','Replace document':'replace','Append fixed rules':'append','Preserve original':'preserve'}};
            const bytes=(e,absent)=>{{const s=text(e);if(absent&&s==='Observed absent')return null;const m=/^([0-9]{{1,7}}) bytes$/.exec(s);if(!m)throw 0;return Number(m[1])}};
            return rows.map(row=>{{const cells=row.querySelectorAll(':scope > td');if(cells.length!==3||!action[text(cells[0])])throw 0;
                return {{path:text(row.querySelector('th code')),action:action[text(cells[0])],beforeBytes:bytes(cells[1],true),afterBytes:bytes(cells[2],false)}}}})}};
        const review=r=>{{const files=inventory(r),ignore=[...r.querySelectorAll('.save-ignore li code')].map(text),counts=[...r.querySelectorAll('.review-counts > span > strong')].map(number);
            if(ignore.length>7||counts.length!==3)throw 0;return {{files,release:[...r.querySelectorAll(':scope > .save-note code')].some(e=>text(e)==='release'),rewrite:!!r.querySelector(':scope > .notice-warning'),
                ignore,counts:{{added:counts[0],changed:counts[1],removed:counts[2]}},basis:text(r.querySelector('.review-basis strong')),badge:text(r.querySelector('.review-counts .badge'))}}}};
        const confirm=()=>{{const dialogs=document.querySelectorAll('dialog');if(dialogs.length!==1)throw 0;const d=dialogs[0];
            if(!d.classList.contains('save-confirm-dialog')||!d.open||!visible(d)||d.querySelector('[role="alert"]'))throw 0;
            const checks=d.querySelectorAll('.save-confirm-choice input[type="checkbox"]'),buttons=d.querySelectorAll('.button-row > button');
            if(checks.length!==1||checks[0].disabled||buttons.length!==2||buttons[0].disabled||text(buttons[0])!=='Keep reviewing'
                ||!['Apply reviewed save','Confirm no-op plan'].includes(text(buttons[1])))throw 0;return {{dialog:d,check:checks[0],keep:buttons[0],apply:buttons[1]}}}};
        {body}
    }}catch{{return {{state:'error'}}}}}})()"#))
}

fn route() -> Option<(PathBuf,u32)> {
    let (source,run,attempt) = (option_env!("GITHUB_SHA")?,option_env!("GITHUB_RUN_ID")?,option_env!("GITHUB_RUN_ATTEMPT")?);
    let decimal = |s: &str| !s.is_empty() && s.len() <= 20 && !s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit());
    // The reviewed invocation owner checks its actual hosted source/ref/run
    // before launch. No Actions routing values enter the clean app environment;
    // only this immutable compiled tuple derives the fixed fixture namespace.
    if source.len() != 40 || !source.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !decimal(run) || !decimal(attempt) { return None; }
    let expected = Path::new(crate::macos_install_paths::APP).join("Contents/MacOS/mobile-release-kit-desktop");
    if std::env::current_exe().ok()? != expected || !mrk_macos_installed_native::main_thread() { return None; }
    let uid = mrk_macos_installed_native::real_user().ok()?;
    let root = PathBuf::from(format!("/private/tmp/mrk-macos-aqua-{source}-{run}-{attempt}"));
    directory(&root,uid,0o700,&["first-save","noop-stale","picker-loss","save-loss","state"]).ok()?;
    Some((root,uid))
}

// Pure regression checks in the already-required instrumented native entry.
// These do not call AppKit, acquire files, dispatch actions, or supply receipts.
fn observer_data_checks() -> bool {
    use mrk_macos_installed_native::{PanelKind, PanelObservation, PanelResponse};
    crate::asset_session::assert_project_selection_gate_contract();
    // Compiled profile DATA only: this inert path is never resolved or opened.
    // The real builder must still establish every installed/native original.
    let profile = crate::runtime::RuntimeConfig::packaged(PathBuf::from("/inert-mrk-profile-not-opened"));
    if !profile.project_selection_profile_available() || profile.project_path_selection_profile_available()
        || profile.evidence_selection_profile_available() { return false; }
    if !mrk_macos_installed_native::installed_observation_flags_data_check()
        || !super::owned_macos::observation::open_release_data_check() { return false; }
    let mut prepared = OpenInputSample::preparing(2);
    prepared.prepared = true;
    if prepared.succeeded() || prepared.entered || prepared.attempted != Some(false) || prepared.returned { return false; }
    prepared.enter();
    if prepared.succeeded() || !prepared.entered || prepared.attempted.is_some() || prepared.press_returned.is_some()
        || prepared.returned || prepared.retired { return false; }
    for id in [1, 2] {
        let mut pending = Some(Pending::Accessibility(id));
        if !open_step_entry(pending, Step::OpenProject, id)
            || retire_returned_open(&mut pending, Step::ProjectSettled, id)
            || retire_returned_open(&mut pending, Step::OpenProject, 3 - id)
            || pending != Some(Pending::Accessibility(id))
            || !retire_returned_open(&mut pending, Step::OpenProject, id) || pending.is_some() { return false; }
    }
    for pending in [None, Some(Pending::Native(Step::OpenProject)), Some(Pending::Accessibility(0)),
        Some(Pending::Accessibility(3)), Some(Pending::Close(Step::OpenProject)), Some(Pending::FailureClose)] {
        let mut unchanged = pending;
        if open_step_entry(unchanged, Step::OpenProject, 2) || retire_returned_open(&mut unchanged, Step::OpenProject, 2)
            || unchanged != pending { return false; }
    }
    let fresh = || ObservedPanel { id: 1, action_allowed: true, native: PanelObservation {
        kind: PanelKind::Project, started: true, attached: false, directory_bound: false,
        parent_present: true, panel_present: true, parent_references_panel: Some(false),
        panel_references_parent: Some(false), panel_visible: Some(false),
        directory_returned: false, directory_ready: false, action_attempted: false, action_returned: false,
        callback_returned: false, response: None, selected: None, close_attempted: false, dismissed: false, closed: false,
    }};
    for dismissed in [false, true] {
        let mut panel = fresh(); panel.native.dismissed = dismissed;
        if panel_readiness(&panel, 1, false, false, false) != Ok(false) { return false; }
        if panel_readiness(&panel, 1, false, true, false) != Err("native-attachment-lost") { return false; }
        if panel_readiness(&panel, 1, false, false, true) != Err("native-preaction-history") { return false; }
        panel.native.attached = true;
        panel.native.parent_references_panel = Some(true); panel.native.panel_references_parent = Some(true);
        panel.native.panel_visible = Some(true);
        let expected = if dismissed { Err("native-dismissed") } else { Ok(true) };
        if panel_readiness(&panel, 1, false, false, false) != expected { return false; }
    }
    let mutations: [fn(&mut ObservedPanel); 14] = [
        |p| p.id = 2, |p| p.native.kind = PanelKind::Quit, |p| p.native.started = false,
        |p| p.action_allowed = false, |p| p.native.action_attempted = true, |p| p.native.action_returned = true,
        |p| p.native.callback_returned = true, |p| p.native.response = Some(PanelResponse::Decline),
        |p| p.native.selected = Some(PathBuf::from("/synthetic")), |p| p.native.close_attempted = true,
        |p| p.native.closed = true, |p| p.native.directory_bound = true,
        |p| p.native.directory_returned = true, |p| p.native.directory_ready = true,
    ];
    for mutation in mutations {
        let mut panel = fresh(); mutation(&mut panel);
        if panel_readiness(&panel, 1, false, false, false).is_ok() { return false; }
    }
    for (step, original) in [(Step::CancelProject, 0), (Step::SetProject, 1), (Step::OpenProject, 2),
        (Step::PickerPending, 1), (Step::QuitCancel, 3), (Step::Quit, 4)] {
        let mut prior = [true; 5]; prior[original] = false;
        if matches!(step, Step::SetProject | Step::OpenProject | Step::PickerPending) { prior[1] = false; prior[2] = false; }
        if same_panel_action_returned(step, &prior) != Ok(false) { return false; }
        prior[original] = true;
        if same_panel_action_returned(step, &prior) != Ok(true) { return false; }
    }
    for pending in [None, Some(Pending::Native(Step::Quit)), Some(Pending::Accessibility(2)),
        Some(Pending::Dom(DomDispatch { step: Step::CancelProject, sequence: 1 })),
        Some(Pending::Close(Step::CancelProject)), Some(Pending::Reload), Some(Pending::FailureClose)] {
        let mut original = pending;
        if retire_returned_native(&mut original, Step::CancelProject, Step::CancelProject) || original != pending { return false; }
    }
    let mut original = Some(Pending::Native(Step::CancelProject));
    if retire_returned_native(&mut original, Step::Quit, Step::CancelProject)
        || original != Some(Pending::Native(Step::CancelProject)) { return false; }
    if !retire_returned_native(&mut original, Step::CancelProject, Step::CancelProject) || original.is_some() { return false; }
    for (on_main, timely, expected) in [(false, false, Err("native-wrong-thread")),
        (false, true, Err("native-wrong-thread")), (true, false, Ok(false)), (true, true, Ok(true))] {
        let result = native_step_entry(on_main, timely);
        if result != expected { return false; }
        let mut pending = Some(Pending::Native(Step::CancelProject));
        // The same entry result and refusal rule as native_step: late main
        // no-action may retire; either wrong-thread refusal must stay pending.
        if result == Ok(false) && !retire_returned_native(&mut pending, Step::CancelProject, Step::CancelProject) { return false; }
        if pending.is_none() != (on_main && !timely) { return false; }
    }
    let first_dom = DomDispatch { step: Step::ChooseCancel, sequence: 1 };
    let next_dom = DomDispatch { sequence: 2, ..first_dom };
    for pending in [None, Some(Pending::Native(first_dom.step)), Some(Pending::Close(first_dom.step)), Some(Pending::Accessibility(2)),
        Some(Pending::Reload), Some(Pending::FailureClose), Some(Pending::Dom(next_dom)),
        Some(Pending::Dom(DomDispatch { step: Step::ChooseProject, ..first_dom }))] {
        let mut unchanged = pending;
        if dom_step_entry(unchanged, first_dom.step, first_dom)
            || retire_returned_dom(&mut unchanged, first_dom) || unchanged != pending { return false; }
    }
    for sequence in [0, 161] {
        let invalid = DomDispatch { sequence, ..first_dom };
        let mut pending = Some(Pending::Dom(invalid));
        if dom_step_entry(pending, invalid.step, invalid) || retire_returned_dom(&mut pending, invalid)
            || pending != Some(Pending::Dom(invalid)) { return false; }
    }
    for returned in [first_dom, next_dom, DomDispatch { sequence: 160, ..first_dom }] {
        let mut pending = Some(Pending::Dom(returned));
        let mut current = returned.step;
        if !dom_step_entry(pending, current, returned) { return false; }
        current = Step::CancelProject; // A successful body may advance Step.
        if dom_step_entry(pending, current, returned) || pending != Some(Pending::Dom(returned))
            || !retire_returned_dom(&mut pending, returned) || pending.is_some() { return false; }
    }
    // Repeated polls at the same Step have distinct original custody. A stale
    // callback cannot enter or retire the next poll, even if its body had failed.
    let mut pending = Some(Pending::Dom(next_dom));
    if dom_step_entry(pending, next_dom.step, first_dom) || retire_returned_dom(&mut pending, first_dom)
        || pending != Some(Pending::Dom(next_dom)) || !dom_step_entry(pending, next_dom.step, next_dom)
        || !retire_returned_dom(&mut pending, next_dom) { return false; }

    use crate::asset_commands::{AssetError, Reason};
    let empty = Ok(None);
    let selected = Ok(Some(Project { id: "synthetic".into(), name: "synthetic".into(), path: "/synthetic".into() }));
    let error = Err(AssetError { code: "untrusted-supplied-code", message: "untrusted-supplied-message",
        retryable: true, ..AssetError::new(Reason::SourceRefused) });
    for step in [Step::ChooseCancel, Step::ChooseProject, Step::SetProject] {
        if project_return_route(Case::FirstSave, step, false, false, false, &error) != Err("asset_source_refused") { return false; }
        for result in [&empty, &selected] {
            if project_return_route(Case::FirstSave, step, false, false, false, result) != Err("picker-unexpected-result") { return false; }
        }
    }
    for step in [Step::CancelProject, Step::CancelSettled] {
        if project_return_route(Case::FirstSave, step, false, false, false, &empty) != Ok(ProjectReturn::Cancelled)
            || project_return_route(Case::FirstSave, step, false, false, false, &selected) != Err("cancel-unexpected-project")
            || project_return_route(Case::FirstSave, step, false, false, false, &error) != Err("asset_source_refused") { return false; }
        for result in [&empty, &selected, &error] {
            if project_return_route(Case::FirstSave, step, false, true, false, result) != Err("cancel-duplicate-result") { return false; }
        }
    }
    for step in [Step::OpenProject, Step::ProjectSettled] {
        if project_return_route(Case::FirstSave, step, false, false, false, &selected) != Ok(ProjectReturn::Selected)
            || project_return_route(Case::FirstSave, step, false, false, false, &empty) != Err("picker-unexpected-result")
            || project_return_route(Case::FirstSave, step, false, false, false, &error) != Err("asset_source_refused") { return false; }
    }
    for result in [&empty, &error] {
        if project_return_route(Case::PickerLoss, Step::Lost, true, false, false, result) != Ok(ProjectReturn::Lost) { return false; }
    }
    for result in [&empty, &selected, &error] {
        if project_return_route(Case::PickerLoss, Step::Lost, true, false, true, result) != Err("observer-invariant") { return false; }
    }
    if project_return_route(Case::PickerLoss, Step::Lost, true, false, false, &selected) != Err("observer-invariant")
        || project_return_route(Case::PickerLoss, Step::PickerPending, false, false, false, &error) != Err("asset_source_refused")
        || project_return_route(Case::SaveLoss, Step::Lost, true, false, false, &error) != Err("asset_source_refused") { return false; }

    // Every closed reason survives later generic cleanup/deadline failures.
    for reason in FAILURE_REASONS {
        if !reason.is_ascii() || reason.len() > 48 { return false; }
        let first = AtomicU8::new(0); let failed = AtomicBool::new(false);
        if first_failure_reason(&first).is_some() { return false; }
        latch_failure(&first, &failed, *reason);
        if !failed.load(Ordering::SeqCst) || first_failure_reason(&first) != Some(*reason) { return false; }
        latch_failure(&first, &failed, "observer-invariant");
        latch_failure(&first, &failed, "observer-deadline");
        latch_failure(&first, &failed, "native-wrong-thread");
        let mut pending = Some(Pending::Dom(first_dom));
        // DATA for a known returned body after failure/deadline; retirement
        // changes only this marker, never the first failure or success latch.
        if !retire_returned_dom(&mut pending, first_dom) || pending.is_some()
            || !failed.load(Ordering::SeqCst) || first_failure_reason(&first) != Some(*reason) { return false; }
    }
    true
}
pub(crate) fn main() -> std::process::ExitCode {
    if !observer_data_checks() {
        super::diagnostic(b"MRK_MACOS_AQUA_FAILURE_REASON=observer-data-check\nMRK_MACOS_AQUA=failed\n");
        return std::process::ExitCode::FAILURE;
    }
    let mut args = std::env::args_os().skip(1);
    let case = match args.next().as_deref() {
        Some(v) if v == OsStr::new("first-save") => Case::FirstSave, Some(v) if v == OsStr::new("noop-stale") => Case::NoopStale,
        Some(v) if v == OsStr::new("picker-loss") => Case::PickerLoss, Some(v) if v == OsStr::new("save-loss") => Case::SaveLoss,
        _ => { super::diagnostic(b"MRK_MACOS_AQUA=route-refused\n"); return std::process::ExitCode::FAILURE; },
    };
    let input = route().filter(|_| args.next().is_none()).and_then(|(root,uid)| Fixture::capture(root.join(case.name()),uid,case).ok())
        .and_then(|fixture| Observation::new(case,fixture).ok());
    let Some(q) = input.map(Arc::new) else { super::diagnostic(b"MRK_MACOS_AQUA=fixture-refused\n"); return std::process::ExitCode::FAILURE; };
    let trusted = mrk_macos_installed_native::installed_accessibility_trusted();
    if trusted != Ok(true) {
        q.fail_with(if trusted == Ok(false) { "native-ax-not-trusted" } else { "native-ax-trust" });
        q.report_failure(); super::diagnostic(b"MRK_MACOS_AQUA=failed\n"); return std::process::ExitCode::FAILURE;
    }
    if let Some(mut r) = q.record() { r.ax_trusted = true; } else { return std::process::ExitCode::FAILURE; }
    if !q.timely() { q.report_failure(); return std::process::ExitCode::FAILURE; }
    // Routing is DATA only. The ordinary builder/core/installed selector still
    // establish every runtime, native project, document and edit boundary.
    let returned = super::run_builder(super::builder().manage(q.clone()));
    let report = matches!(returned,Ok(0)).then(|| q.finish()).flatten();
    let Some(report) = report.and_then(|v| edit::bounded(&v,16 * 1024 - 1).ok()) else {
        q.fail(); q.report_failure(); super::diagnostic(b"MRK_MACOS_AQUA=failed\n"); return std::process::ExitCode::FAILURE;
    };
    if !q.timely() { q.report_failure(); return std::process::ExitCode::FAILURE; }
    let mut out = std::io::stdout().lock();
    if out.write_all(b"MRK_MACOS_AQUA_RESULT=").and_then(|_| out.write_all(&report)).and_then(|_| out.write_all(b"\n"))
        .and_then(|_| out.flush()).is_ok() && q.timely() { std::process::ExitCode::SUCCESS } else { std::process::ExitCode::FAILURE }
}
