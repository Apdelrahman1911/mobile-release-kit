//! Three bounded observations of the NORMAL builder/bridge/packaged selector.
//! No alternate runtime, document, IPC command, timer, task or shutdown owner.
//! Only the existing relay drives these steps; failures cannot authorize exit.
use std::{ffi::OsStr, io::Write, path::{Path, PathBuf}, sync::{Arc, Mutex, MutexGuard, atomic::{AtomicBool, Ordering}},
    thread::ThreadId, time::{Duration, Instant}};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tauri::Manager;
use crate::{asset_session::{InstalledEvidenceWitness, InstalledProjectWitness}, bridge::{AppInfo, Project},
    candidate_evidence_protocol as evidence, edit_owner::{EditOwner, InstalledConfigFinality},
    edit_protocol::{self as edit, ConfigEditStatus, EditProjection}, error::BridgeError, supervisor::{HeldAppInfo, Supervisor}};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case { Positive, Outstanding, ProjectPaths }
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Bootstrap, Environment, ReadEnvironment, Dashboard, ChooseCancel, Cancel, Cancelled, ReadCancelled,
    ChooseSelect, SetProject, SelectProject, Selected, ReadSnapshot, Settings, Suggest, ReadSuggestion, Adopt, ReadDraft,
    GuidanceEnvironment, LoadRequirements, ReadRequirements, GitHub, ReadGitHubEmpty, EnterRepository, EnterSha,
    ReadGitHubInputs, ProposeGitHub, ReadProposal, OpenWorkflows, ReadWorkflows, GuidanceSettings, ReadRetainedDraft,
    PrepareSave, ReadSaveReview, OpenConfirmation, ReadConfirmation, KeepReviewing, ReadKeptReview,
    ReopenConfirmation, ReadReopenedConfirmation, Acknowledge, ReadAcknowledged, Apply, ReadSaved,
    SavedDashboard, Refresh, ReadReadback, ReadVersion, ReadVersionCard, Metadata, LoadMetadata, ReadMetadata,
    EnterTitle, EnterShortDescription, EnterFullDescription, ReadMetadataInputs, ValidateMetadata, ReadMetadataValidation,
    SavedSettings, ReadSavedDraft, Artifacts, ReadEvidenceEmpty, ChooseEvidenceCancel, CancelEvidence, EvidenceCancelled, ReadEvidenceCancelled,
    ChooseEvidenceSelect, SetEvidence, SelectEvidence, EvidenceSelected, ReadEvidenceSelected, InspectEvidence, EvidenceObserved, ReadEvidenceObserved,
    CandidateSettings, ReadCandidateDraft, PrepareNoop, ReadNoopReview, Close, Quit, Exit, Paths(PathStep),
}
impl Step {
    fn failure_line(self) -> &'static [u8] {
        match self {
            Self::Bootstrap => b"MRK_INSTALLED_SHELL_FAILURE_STEP=Bootstrap\n",
            Self::Environment => b"MRK_INSTALLED_SHELL_FAILURE_STEP=Environment\n",
            Self::ReadEnvironment => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadEnvironment\n",
            Self::Dashboard => b"MRK_INSTALLED_SHELL_FAILURE_STEP=Dashboard\n",
            Self::ChooseCancel => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ChooseCancel\n",
            Self::Cancel => b"MRK_INSTALLED_SHELL_FAILURE_STEP=Cancel\n",
            Self::Cancelled => b"MRK_INSTALLED_SHELL_FAILURE_STEP=Cancelled\n",
            Self::ReadCancelled => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadCancelled\n",
            Self::ChooseSelect => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ChooseSelect\n",
            Self::SetProject => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SetProject\n",
            Self::SelectProject => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SelectProject\n",
            Self::Selected => b"MRK_INSTALLED_SHELL_FAILURE_STEP=Selected\n",
            Self::ReadSnapshot => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadSnapshot\n",
            Self::Settings => b"MRK_INSTALLED_SHELL_FAILURE_STEP=Settings\n",
            Self::Suggest => b"MRK_INSTALLED_SHELL_FAILURE_STEP=Suggest\n",
            Self::ReadSuggestion => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadSuggestion\n",
            Self::Adopt => b"MRK_INSTALLED_SHELL_FAILURE_STEP=Adopt\n",
            Self::ReadDraft => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadDraft\n",
            Self::GuidanceEnvironment => b"MRK_INSTALLED_SHELL_FAILURE_STEP=GuidanceEnvironment\n",
            Self::LoadRequirements => b"MRK_INSTALLED_SHELL_FAILURE_STEP=LoadRequirements\n",
            Self::ReadRequirements => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadRequirements\n",
            Self::GitHub => b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHub\n",
            Self::ReadGitHubEmpty => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadGitHubEmpty\n",
            Self::EnterRepository => b"MRK_INSTALLED_SHELL_FAILURE_STEP=EnterRepository\n",
            Self::EnterSha => b"MRK_INSTALLED_SHELL_FAILURE_STEP=EnterSha\n",
            Self::ReadGitHubInputs => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadGitHubInputs\n",
            Self::ProposeGitHub => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ProposeGitHub\n",
            Self::ReadProposal => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadProposal\n",
            Self::OpenWorkflows => b"MRK_INSTALLED_SHELL_FAILURE_STEP=OpenWorkflows\n",
            Self::ReadWorkflows => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadWorkflows\n",
            Self::GuidanceSettings => b"MRK_INSTALLED_SHELL_FAILURE_STEP=GuidanceSettings\n",
            Self::ReadRetainedDraft => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadRetainedDraft\n",
            Self::PrepareSave => b"MRK_INSTALLED_SHELL_FAILURE_STEP=PrepareSave\n",
            Self::ReadSaveReview => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadSaveReview\n",
            Self::OpenConfirmation => b"MRK_INSTALLED_SHELL_FAILURE_STEP=OpenConfirmation\n",
            Self::ReadConfirmation => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadConfirmation\n",
            Self::KeepReviewing => b"MRK_INSTALLED_SHELL_FAILURE_STEP=KeepReviewing\n",
            Self::ReadKeptReview => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadKeptReview\n",
            Self::ReopenConfirmation => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReopenConfirmation\n",
            Self::ReadReopenedConfirmation => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadReopenedConfirmation\n",
            Self::Acknowledge => b"MRK_INSTALLED_SHELL_FAILURE_STEP=Acknowledge\n",
            Self::ReadAcknowledged => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadAcknowledged\n",
            Self::Apply => b"MRK_INSTALLED_SHELL_FAILURE_STEP=Apply\n",
            Self::ReadSaved => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadSaved\n",
            Self::SavedDashboard => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SavedDashboard\n",
            Self::Refresh => b"MRK_INSTALLED_SHELL_FAILURE_STEP=Refresh\n",
            Self::ReadReadback => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadReadback\n",
            Self::ReadVersion => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadVersion\n",
            Self::ReadVersionCard => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadVersionCard\n",
            Self::Metadata => b"MRK_INSTALLED_SHELL_FAILURE_STEP=Metadata\n",
            Self::LoadMetadata => b"MRK_INSTALLED_SHELL_FAILURE_STEP=LoadMetadata\n",
            Self::ReadMetadata => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadMetadata\n",
            Self::EnterTitle => b"MRK_INSTALLED_SHELL_FAILURE_STEP=EnterTitle\n",
            Self::EnterShortDescription => b"MRK_INSTALLED_SHELL_FAILURE_STEP=EnterShortDescription\n",
            Self::EnterFullDescription => b"MRK_INSTALLED_SHELL_FAILURE_STEP=EnterFullDescription\n",
            Self::ReadMetadataInputs => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadMetadataInputs\n",
            Self::ValidateMetadata => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ValidateMetadata\n",
            Self::ReadMetadataValidation => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadMetadataValidation\n",
            Self::SavedSettings => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SavedSettings\n",
            Self::ReadSavedDraft => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadSavedDraft\n",
            Self::Artifacts => b"MRK_INSTALLED_SHELL_FAILURE_STEP=Artifacts\n",
            Self::ReadEvidenceEmpty => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadEvidenceEmpty\n",
            Self::ChooseEvidenceCancel => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ChooseEvidenceCancel\n",
            Self::CancelEvidence => b"MRK_INSTALLED_SHELL_FAILURE_STEP=CancelEvidence\n",
            Self::EvidenceCancelled => b"MRK_INSTALLED_SHELL_FAILURE_STEP=EvidenceCancelled\n",
            Self::ReadEvidenceCancelled => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadEvidenceCancelled\n",
            Self::ChooseEvidenceSelect => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ChooseEvidenceSelect\n",
            Self::SetEvidence => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SetEvidence\n",
            Self::SelectEvidence => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SelectEvidence\n",
            Self::EvidenceSelected => b"MRK_INSTALLED_SHELL_FAILURE_STEP=EvidenceSelected\n",
            Self::ReadEvidenceSelected => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadEvidenceSelected\n",
            Self::InspectEvidence => b"MRK_INSTALLED_SHELL_FAILURE_STEP=InspectEvidence\n",
            Self::EvidenceObserved => b"MRK_INSTALLED_SHELL_FAILURE_STEP=EvidenceObserved\n",
            Self::ReadEvidenceObserved => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadEvidenceObserved\n",
            Self::CandidateSettings => b"MRK_INSTALLED_SHELL_FAILURE_STEP=CandidateSettings\n",
            Self::ReadCandidateDraft => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadCandidateDraft\n",
            Self::PrepareNoop => b"MRK_INSTALLED_SHELL_FAILURE_STEP=PrepareNoop\n",
            Self::ReadNoopReview => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ReadNoopReview\n",
            Self::Close => b"MRK_INSTALLED_SHELL_FAILURE_STEP=Close\n",
            Self::Quit => b"MRK_INSTALLED_SHELL_FAILURE_STEP=Quit\n",
            Self::Exit => b"MRK_INSTALLED_SHELL_FAILURE_STEP=Exit\n",
            Self::Paths(step) => step.failure_line(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pending { Dom(Step), Project(Step), Evidence(Step), Path(PathStep), Close, Gtk }
#[derive(Clone, Copy)]
enum Boundary { Bootstrap, Request, Result, Dom, Gtk, Settlement, Exit }
impl Boundary {
    fn failure_line(self) -> &'static [u8] {
        match self {
            Self::Bootstrap => b"MRK_INSTALLED_SHELL_FAILURE_PHASE=bootstrap\n",
            Self::Request => b"MRK_INSTALLED_SHELL_FAILURE_PHASE=request\n",
            Self::Result => b"MRK_INSTALLED_SHELL_FAILURE_PHASE=result\n",
            Self::Dom => b"MRK_INSTALLED_SHELL_FAILURE_PHASE=dom\n",
            Self::Gtk => b"MRK_INSTALLED_SHELL_FAILURE_PHASE=gtk\n",
            Self::Settlement => b"MRK_INSTALLED_SHELL_FAILURE_PHASE=settlement\n",
            Self::Exit => b"MRK_INSTALLED_SHELL_FAILURE_PHASE=exit\n",
        }
    }
}

const PROJECT_SOURCE: &str = "plugins { id(\"com.android.application\") }\nandroid { defaultConfig { applicationId = \"org.example.mrk.observed\" } }\n";
const APP_ID: &str = "org.example.mrk.observed";
const FIELD: &str = "version.source";
const METHODS: [&str; 12] = ["capabilities", "catalog", "project.snapshot", "config.validate", "config.suggest", "config.preview",
    "github.setup.propose", "metadata.text.observe", "metadata.text.validate", "environment.requirements", "release.version.observe", "artifacts.candidate.observe"];
const TOOLKIT_REPOSITORY: &str = "example/toolkit";
const TOOLKIT_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GITHUB_RESOURCE: &str = "4d486fc24ebf24271dbb5227174df7c8f28a530a97011e004da643fdad7fe17c";
const WORKFLOWS: [(&str, &str, usize); 4] = [
    ("preflight", ".github/workflows/mobile-preflight.yml", 567),
    ("candidate", ".github/workflows/mobile-candidate.yml", 1379),
    ("external-testing", ".github/workflows/mobile-external-testing.yml", 2150),
    ("production-submit", ".github/workflows/mobile-production-submit.yml", 2881),
];

// Source-bound synthetic fixture output DATA. The outer fixture's focused pure
// core contract derives these bytes from config.suggest + the real serializer;
// this observer never serializes a replacement config or opens the fixture.
const CONFIG_BYTES: u32 = 684;
const CONFIG_SHA256: &str = "0c47aaffe3971b122f21ebddf8070ab29014c4b7c79a56e23335ed110f1e6acc";
const VERSION_SOURCE: &str = "version.properties";
const VERSION_BYTES: u32 = 34;
const VERSION_SHA256: &str = "a811da0677c243236101fb4aa93319d28b731f963f8a295c1028b8aee136386b";
const METADATA_FIELDS: [(&str, &str, u32); 3] = [
    ("title.txt", "Public title", 30), ("short_description.txt", "Public summary", 80),
    ("full_description.txt", "Public description", 4000),
];
const IGNORE_BYTES: u32 = 208;
const IGNORE_LINES: [&str; 7] = [".mobile-release/", ".mobile-release-init-prepare/", ".mobile-release-init/", ".mobile-release-init-cleanup/",
    ".mobile-release-metadata-text-prepare/", ".mobile-release-metadata-text/", ".mobile-release-metadata-text-cleanup/"];

// This is the fixed original service's protected sibling, not an environment
// path or a renderer-selected fixture. It is only passed to GtkFileChooser.
fn project_path() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    if executable.file_name()? != OsStr::new("shell-observer") { return None; }
    let root = executable.parent()?;
    if root.parent()? != Path::new("/var/lib") { return None; }
    let parts: Vec<_> = root.file_name()?.to_str()?.strip_prefix("mrk-ubuntu-native-")?.split('-').collect();
    if parts.len() != 2 || !parts.iter().all(|part| !part.is_empty() && part.len() <= 20
        && !part.starts_with('0') && part.bytes().all(|byte| byte.is_ascii_digit())) { return None; }
    Some(root.join("positive-project"))
}

// One fixed root-prepared diagnostic leaf. O_PATH permits binding the0711
// parent without granting directory read permission to the dropped runner.
// OwnedFd closes once on every Rust return/drop path; no raw FD is exported.
fn failure_sink(case: Case) -> Option<rustix::fd::OwnedFd> {
    use std::os::unix::fs::MetadataExt;
    use rustix::fs::{self, Mode, OFlags};
    let project = project_path()?;
    let root = project.parent()?;
    for ancestor in root.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).ok()?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.gid() != 0
            || metadata.mode() & 0o022 != 0 { return None; }
    }
    let parent = fs::open(root, OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty()).ok()?;
    let before = fs::fstat(&parent).ok()?;
    if before.st_mode != 0o040711 || before.st_uid != 0 || before.st_gid != 0 { return None; }
    let leaf = match case {
        Case::Positive => "shell-positive-failure.labels",
        Case::Outstanding => "shell-quit-outstanding-failure.labels",
        Case::ProjectPaths => "shell-project-paths-failure.labels",
    };
    let fd = fs::openat(&parent, leaf, OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty()).ok()?;
    let item = fs::fstat(&fd).ok()?;
    let group = rustix::process::getegid();
    let after = fs::fstat(&parent).ok()?;
    if group.as_raw() == 0 || group != rustix::process::getgid()
        || item.st_mode != 0o100620 || item.st_uid != 0 || item.st_gid != group.as_raw()
        || item.st_nlink != 1 || item.st_size != 0 || item.st_dev != before.st_dev
        || (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid)
            != (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid) { return None; }
    Some(fd)
}

const FAILURE_PAIR_LIMIT: usize = 512;
fn failure_pair(trace: (Step, Boundary)) -> Option<([u8; FAILURE_PAIR_LIMIT], usize)> {
    let step = trace.0.failure_line();
    let boundary = trace.1.failure_line();
    let length = step.len().checked_add(boundary.len())?;
    let mut bytes = [0_u8; FAILURE_PAIR_LIMIT];
    bytes.get_mut(..step.len())?.copy_from_slice(step);
    bytes.get_mut(step.len()..length)?.copy_from_slice(boundary);
    Some((bytes, length))
}

fn assert_failure_pair_contract() {
    // Pure byte contracts only; no open, write, GTK or process work.
    for trace in [(Step::Bootstrap, Boundary::Bootstrap), (Step::PrepareSave, Boundary::Request),
        (Step::Paths(PathStep::Settled(10)), Boundary::Settlement), (Step::Exit, Boundary::Exit)] {
        let expected = [trace.0.failure_line(), trace.1.failure_line()].concat();
        assert!(failure_pair(trace).is_some_and(|(bytes, length)|
            length <= FAILURE_PAIR_LIMIT && bytes.get(..length) == Some(expected.as_slice())));
    }
}

#[derive(Default)]
struct Picker {
    created: bool, selected: bool, activated: bool, responded: bool, filename: bool,
    disposal: bool, destroyed: bool, released: bool, returned: bool,
}
impl Picker {
    fn settled(&self, select: bool) -> bool {
        self.created && self.activated && self.responded && self.destroyed && self.released && self.returned
            && self.selected == select && self.filename == select
    }
}

// One closed native path case. Operation indices refer only to this fixed
// eleven-item roster, never renderer-supplied actions or filesystem authority.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PathStep { Start, ReadDraft, Preview(u8), ReadPreview(u8), Browse(u8), Set(u8), Activate(u8),
    Settled(u8), ReadField(u8), Ios, Metadata, Settings, General, FinalIos }
impl PathStep {
    fn failure_line(self) -> &'static [u8] {
        match self {
            Self::Start | Self::ReadDraft => b"MRK_INSTALLED_SHELL_FAILURE_STEP=PathDraft\n",
            Self::Preview(_) | Self::ReadPreview(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=PathPreview\n",
            Self::Browse(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=PathBrowse\n",
            Self::Set(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=PathSet\n",
            Self::Activate(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=PathActivate\n",
            Self::Settled(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=PathSettlement\n",
            Self::ReadField(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=PathField\n",
            _ => b"MRK_INSTALLED_SHELL_FAILURE_STEP=PathNavigation\n",
        }
    }
}
#[derive(Clone, Copy)]
struct PathCase { field: crate::asset_commands::ProjectPathField, name: &'static str, label: &'static str,
    path: Option<&'static str>, relative: Option<&'static str>, reason: crate::asset_commands::Reason }
use crate::asset_commands::{ProjectPathField as PF, Reason as PR};
const PATH_CASES: [PathCase; 11] = [
    PathCase { field: PF::VersionSource, name:"version.source", label:"Committed version file", path:None, relative:None, reason:PR::UserCancelled },
    PathCase { field: PF::VersionSource, name:"version.source", label:"Committed version file", path:Some("path-project/inputs/VERSION"), relative:Some("inputs/VERSION"), reason:PR::None },
    PathCase { field: PF::IosProject, name:"ios.project", label:"Xcode project", path:Some("path-project/ios/Example.xcodeproj"), relative:Some("ios/Example.xcodeproj"), reason:PR::None },
    PathCase { field: PF::IosWorkspace, name:"ios.workspace", label:"Xcode workspace", path:Some("path-project/ios/Example.xcworkspace"), relative:Some("ios/Example.xcworkspace"), reason:PR::None },
    PathCase { field: PF::MetadataRoot, name:"metadata.root", label:"Store metadata folder", path:None, relative:None, reason:PR::UserCancelled },
    PathCase { field: PF::MetadataRoot, name:"metadata.root", label:"Store metadata folder", path:Some("path-project/metadata"), relative:Some("metadata"), reason:PR::None },
    PathCase { field: PF::VersionSource, name:"version.source", label:"Committed version file", path:Some("path-outside/VERSION"), relative:None, reason:PR::SourceRefused },
    PathCase { field: PF::VersionSource, name:"version.source", label:"Committed version file", path:Some("path-project/inputs/link-input"), relative:None, reason:PR::SourceRefused },
    PathCase { field: PF::VersionSource, name:"version.source", label:"Committed version file", path:Some("path-project/inputs/kind-input"), relative:None, reason:PR::SourceRefused },
    PathCase { field: PF::IosProject, name:"ios.project", label:"Xcode project", path:Some("path-project/ios/Kind.xcodeproj"), relative:None, reason:PR::SourceRefused },
    PathCase { field: PF::IosWorkspace, name:"ios.workspace", label:"Xcode workspace", path:Some("path-project/ios/Example.xcworkspace"), relative:None, reason:PR::SourceChanged },
];
#[derive(Default)]
struct PathOperation { picker: Picker, requested: bool, returned: bool, settled: bool, visible: bool }
struct Paths {
    operations: [PathOperation; 11], base: Option<Value>, draft: Option<Value>, patched: Option<Value>,
    previews_requested: u8, previews: [Option<Value>; 3], previews_visible: u8, draft_visible: bool,
    pair_visible: bool, final_pair_visible: bool, fixture: Option<PathFixture>,
}
impl Paths {
    fn new(root: Option<&Path>) -> Self {
        Self { operations: std::array::from_fn(|_| PathOperation::default()), base:None, draft:None, patched:None,
            previews_requested:0, previews:std::array::from_fn(|_| None), previews_visible:0, draft_visible:false,
            pair_visible:false, final_pair_visible:false, fixture:root.and_then(|root| PathFixture::capture(root).ok()) }
    }
    fn complete(&self) -> bool {
        self.operations.iter().enumerate().all(|(i, op)| op.requested && op.returned && op.settled && op.visible
            && op.picker.settled(PATH_CASES[i].path.is_some())) && self.base.is_some() && self.draft.is_some() && self.patched.is_some()
            && self.previews_requested == 3 && self.previews_visible == 3 && self.previews.iter().all(Option::is_some)
            && self.draft_visible && self.pair_visible && self.final_pair_visible
            && self.fixture.as_ref().is_some_and(|f| f.mutations == 4)
    }
}
// Metadata only. The outer owner alone hashes the five inert file payloads.
// No descriptor is retained and no production source-probe state is changed.
type FixtureIdentity = [u64; 9];
fn fixture_identity(path: &Path) -> Result<FixtureIdentity, ()> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path).map_err(|_| ())?;
    let ns = |sec: i64, nano: i64| -> Result<u64, ()> {
        u64::try_from(sec).ok().and_then(|s| s.checked_mul(1_000_000_000))
            .and_then(|s| u64::try_from(nano).ok().filter(|n| *n < 1_000_000_000).and_then(|n| s.checked_add(n))).ok_or(())
    };
    Ok([m.dev(),m.ino(),u64::from(m.mode()),u64::from(m.uid()),u64::from(m.gid()),m.nlink(),m.len(),ns(m.mtime(),m.mtime_nsec())?,ns(m.ctime(),m.ctime_nsec())?])
}
const PATH_NODES: [(&str, bool); 14] = [
    ("path-project",true),("path-project/inputs",true),("path-project/inputs/VERSION",false),
    ("path-project/inputs/link-input",false),("path-project/inputs/kind-input",false),("path-project/inputs/kind-directory",true),
    ("path-project/ios",true),("path-project/ios/Example.xcodeproj",true),("path-project/ios/Example.xcworkspace",true),
    ("path-project/ios/Kind.xcodeproj",true),("path-project/ios/Kind.file",false),("path-project/metadata",true),
    ("path-outside",true),("path-outside/VERSION",false),
];
struct PathFixture { root: PathBuf, originals: Vec<FixtureIdentity>, ancestors: Vec<(PathBuf, FixtureIdentity)>, mutations: u8, link: Option<FixtureIdentity> }
impl PathFixture {
    fn name(index: usize, stage: u8) -> &'static str {
        match (index,stage) {
            (3,1..=4) => "path-project/inputs/link-original", (4,2..=4) => "path-project/inputs/kind-original",
            (5,2..=4) => "path-project/inputs/kind-input", (9,3..=4) => "path-project/ios/Kind.original",
            (10,3..=4) => "path-project/ios/Kind.xcodeproj", _ => PATH_NODES[index].0,
        }
    }
    fn capture(project: &Path) -> Result<Self, ()> {
        if project.file_name() != Some(OsStr::new("path-project")) { return Err(()); }
        let root = project.parent().ok_or(())?.to_path_buf();
        if project_path().as_ref().and_then(|p| p.parent()) != Some(root.as_path()) { return Err(()); }
        let mut ancestors = Vec::new();
        for path in root.ancestors() {
            let id = fixture_identity(path)?;
            if id[2] & 0o170000 != 0o040000 || id[2] & 0o022 != 0 || id[3] != 0 || id[4] != 0 { return Err(()); }
            ancestors.push((path.to_path_buf(),id));
        }
        let mut originals = Vec::new();
        for (name,directory) in PATH_NODES {
            let id = fixture_identity(&root.join(name))?;
            if id[0] != ancestors[0].1[0] || id[1] == 0 || id[2] != (if directory { 0o040700 } else { 0o100600 })
                || id[3] != u64::from(rustix::process::getuid().as_raw()) || id[4] != u64::from(rustix::process::getgid().as_raw())
                || (if directory { id[5] == 0 || id[5] > 16 || id[6] > 1 << 20 } else { id[5] != 1 || id[6] != 26 })
                || originals.iter().any(|old: &FixtureIdentity| old[..2] == id[..2]) { return Err(()); }
            originals.push(id);
        }
        let fixture = Self { root,originals,ancestors,mutations:0,link:None }; fixture.verify(0)?; Ok(fixture)
    }
    fn verify(&self, stage: u8) -> Result<(), ()> {
        if stage > 4 { return Err(()); }
        for (path,original) in &self.ancestors {
            if fixture_identity(path)?[..5] != original[..5] { return Err(()); }
        }
        let mut identities = Vec::new();
        for (i,(_,directory)) in PATH_NODES.iter().enumerate() {
            let name = Self::name(i,stage); let path = self.root.join(name); let now = fixture_identity(&path)?; let old = self.originals[i];
            let mode = if i == 0 && stage == 4 { 0o040500 } else { old[2] };
            if now[..2] != old[..2] || now[2] != mode || now[3..6] != old[3..6] { return Err(()); }
            let parent_changed = i == 1 && stage >= 1 || i == 6 && stage >= 3;
            let renamed = Self::name(i,stage) != PATH_NODES[i].0;
            if parent_changed {
                if now[6] > 1 << 20 || now[7] < old[7] || now[8] < old[8] { return Err(()); }
            } else if now[6..8] != old[6..8] || (if renamed || i == 0 && stage == 4 { now[8] < old[8] } else { now[8] != old[8] }) { return Err(()); }
            if *directory {
                let mut expected: Vec<_> = (0..14).filter_map(|j| {
                    let child = Path::new(Self::name(j,stage));
                    (child.parent() == Some(Path::new(name))).then(|| child.file_name().unwrap().to_os_string())
                }).collect();
                if i == 1 && stage >= 1 { expected.push(OsStr::new("link-input").to_os_string()); }
                expected.sort(); let mut found = Vec::new();
                for child in std::fs::read_dir(&path).map_err(|_| ())? {
                    let child = child.map_err(|_| ())?.file_name();
                    if found.len() >= expected.len() || !expected.contains(&child) { return Err(()); }
                    found.push(child);
                }
                found.sort(); if found != expected || fixture_identity(&path)? != now { return Err(()); }
            }
            identities.push((path,now));
        }
        if stage >= 1 {
            let path = self.root.join("path-project/inputs/link-input"); let id = fixture_identity(&path)?;
            if id[0] != self.originals[0][0] || id[1] == 0 || id[2] != 0o120777 || id[3..5] != self.originals[0][3..5]
                || id[5] != 1 || id[6] != 13 || self.link.as_ref().is_some_and(|old| *old != id) || self.originals.iter().any(|old| old[..2] == id[..2])
                || std::fs::read_link(&path).map_err(|_| ())? != Path::new("link-original") || fixture_identity(&path)? != id { return Err(()); }
        }
        if identities.iter().any(|(path,id)| fixture_identity(path).ok().as_ref() != Some(id)) { return Err(()); }
        Ok(())
    }
    fn transition(&mut self, operation: u32) -> Result<(), ()> {
        use std::os::unix::fs::PermissionsExt;
        if !(10..=13).contains(&operation) || self.mutations != (operation - 10) as u8 { return Err(()); }
        self.verify(self.mutations)?;
        let rename = |from: &str,to: &str| -> Result<(), ()> {
            let target = self.root.join(to);
            if !matches!(std::fs::symlink_metadata(&target),Err(e) if e.kind() == std::io::ErrorKind::NotFound) { return Err(()); }
            rustix::fs::renameat_with(rustix::fs::CWD,self.root.join(from),rustix::fs::CWD,&target,rustix::fs::RenameFlags::NOREPLACE).map_err(|_| ())
        };
        match operation {
            10 => { rename("path-project/inputs/link-input","path-project/inputs/link-original")?;
                std::os::unix::fs::symlink("link-original",self.root.join("path-project/inputs/link-input")).map_err(|_| ())?; },
            11 => { rename("path-project/inputs/kind-input","path-project/inputs/kind-original")?;
                rename("path-project/inputs/kind-directory","path-project/inputs/kind-input")?; },
            12 => { rename("path-project/ios/Kind.xcodeproj","path-project/ios/Kind.original")?;
                rename("path-project/ios/Kind.file","path-project/ios/Kind.xcodeproj")?; },
            13 => std::fs::set_permissions(self.root.join("path-project"),std::fs::Permissions::from_mode(0o500)).map_err(|_| ())?,
            _ => return Err(()),
        }
        self.verify(self.mutations + 1)?;
        if operation == 10 { self.link = Some(fixture_identity(&self.root.join("path-project/inputs/link-input"))?); }
        self.mutations += 1; Ok(())
    }
}


fn path_field_display(draft: &Value, case: PathCase) -> Value {
    let (parent,leaf) = case.name.split_once('.').unwrap(); let value = draft.get(parent).and_then(|p| p.get(leaf));
    serde_json::json!({"label":case.label,"value":value.and_then(Value::as_str).unwrap_or(""),
        "presence":if value.is_none() { "Not set" } else if value.and_then(Value::as_str) == Some("") { "Empty string" } else { "Set" },"browse":true})
}
fn path_preview_display(value: &Value) -> Option<Value> {
    if edit::bounded(value,262144).is_err() || value["schemaVersion"].as_u64() != Some(1) || !assurance(value,"schema-policy") { return None; }
    let c = &value["comparison"]; let v = &value["validation"];
    let fields = value["fields"].as_array().filter(|rows| rows.len() <= 64)?;
    let changes = c["changes"].as_array().filter(|rows| rows.len() <= 64)?;
    let issues = v["issues"].as_array().filter(|rows| rows.len() <= 128)?;
    let summary = |value: &Value| -> Option<String> {
        if !value["present"].as_bool()? { return Some("Not set".into()); }
        Some(match value["type"].as_str()? {
            "null" => "null".into(),"array" | "object" => {
                let (label,kind) = if value["type"] == "array" { ("Array","items") } else { ("Object","keys") };
                match value.get("count") { Some(count) => format!("{label} · {} {kind}",count.as_u64()?),None => label.into() }
            },
            "string" => "String · value omitted".into(),"boolean" => "Boolean · value omitted".into(),
            "number" => "Number · value omitted".into(),_ => return None,
        })
    };
    let mut rows = Vec::new();
    for row in changes { rows.push(serde_json::json!([row["path"].as_str()?,row["operation"].as_str()?,summary(&row["before"])?,summary(&row["after"])?])); }
    let mut contexts = Vec::new();
    for row in fields { contexts.push(serde_json::json!([row["path"].as_str()?,row["state"].as_str()?,
        if row["present"].as_bool()? { "Present" } else { "Not set" },row["reason"].as_str()?])); }
    let mut displayed_issues = Vec::new();
    for row in issues { displayed_issues.push(serde_json::json!([if row["status"].as_str()? == "INVALID" { "Needs correction" } else { "Incomplete" },
        row["message"].as_str()?,row["remediation"].as_str()?,row["code"].as_str()?])); }
    Some(serde_json::json!({"badge":"Current draft · retained baseline",
        "basis":if c["baseProvided"].as_bool()? { "Compared with the retained draft baseline" } else { "Proposed new configuration; file existence not checked" },
        "counts":[c["counts"]["added"].as_u64()?,c["counts"]["changed"].as_u64()?,c["counts"]["removed"].as_u64()?],
        "comparison":if c["state"].as_str()? == "partial" { "Partial comparison" } else { "Known-field comparison complete" },
        "changes":rows,"contexts":contexts,"validation":[if v["valid"].as_bool()? { "Format-valid only" } else { "Format validation needs attention" },v["state"].as_str()?],
        "issues":displayed_issues}))
}

fn assurance(value: &Value, basis: &str) -> bool {
    // This assurance belongs to each passive reply, never to the whole Save
    // observation: the explicit configuration Apply DOES perform writes.
    value.get("assurance").is_some_and(|a| a.get("basis").and_then(Value::as_str) == Some(basis)
        && a.get("releaseReadiness").and_then(Value::as_str) == Some("unknown")
        && ["projectCodeExecuted", "toolsProbed", "credentialsRead", "gitObserved", "storeContacted", "writesPerformed"]
            .iter().all(|key| a.get(*key).and_then(Value::as_bool) == Some(false)))
}
fn format_valid(value: &Value) -> bool {
    // Observe the existing core verdict, not another configuration validator.
    value["valid"].as_bool() == Some(true) && value["state"].as_str() == Some("format-valid")
        && value["issues"].as_array().is_some_and(Vec::is_empty)
        && value["requirements"].as_array().is_some_and(|rows| rows.len() <= 128
            && rows.iter().all(|row| row["state"].as_str() == Some("unknown"))) && assurance(value, "schema-policy")
}
fn keys(value: &Value, names: &[&str]) -> bool {
    value.as_object().is_some_and(|row| row.len() == names.len() && names.iter().all(|name| row.contains_key(*name)))
}
const HELP_KEYS: [&str; 8] = ["label", "requiredness", "what", "why", "where", "format", "requiredWhen", "failure"];
#[derive(PartialEq, Eq)]
struct HelpSample { values: [String; 8] }
impl HelpSample {
    fn read(field: &Value) -> Option<Self> {
        let mut values = std::array::from_fn(|_| String::new());
        for (index, key) in HELP_KEYS.iter().enumerate() {
            let text = field.get(*key)?.as_str()?;
            if text.is_empty() || text.len() > 16384 || text.encode_utf16().count() > 4096 { return None; }
            values[index] = text.to_owned();
        }
        Some(Self { values })
    }
}

fn requirements_display(result: &crate::environment::Requirements) -> Option<Value> {
    // Serialize the original already-admitted private DTO under its unchanged
    // limit. Retain displayed comparison DATA only; never expose DTO fields.
    let raw = crate::edit_protocol::bounded(result, crate::environment::RESPONSE_LIMIT).ok()?;
    let value = crate::protocol::strict_json(&raw).ok()?;
    if value["schemaVersion"].as_u64() != Some(1) || value["hostPlatform"].as_str() != Some("linux")
        || value["context"] != serde_json::json!({"platform":"android","operation":"build"})
        || value["platformEnabled"].as_bool() != Some(true) || value["state"].as_str() != Some("requirements-only")
        || value["coverage"].as_str() != Some("toolchain-prerequisites-only")
        || value["nativeInspection"].as_str() != Some("unavailable") || value["dependencyCompleteness"].as_str() != Some("unknown")
        || !assurance(&value, "schema-policy") { return None; }
    let rows = value["requirements"].as_array().filter(|rows| rows.len() == 3)?;
    let mut displayed = Vec::new();
    for (index, (row, role)) in rows.iter().zip(["android-jdk", "android-gradle-wrapper", "android-sdk"]).enumerate() {
        let baseline = &row["baseline"];
        if row["id"].as_str() != Some(role) || row["presence"].as_str() != Some("unknown")
            || row["versionState"].as_str() != Some("unknown") || row["inspection"].as_str() != Some("not-run")
            || baseline["kind"].as_str() != Some(if index == 0 { "workflow-reference" } else { "project-defined" })
            || !(if index == 0 { baseline["version"].as_str() == Some("21") } else { baseline.get("version") == Some(&Value::Null) })
            || !["build", "sha256", "maxBytes"].iter().all(|key| baseline.get(*key) == Some(&Value::Null)) { return None; }
        let help = HelpSample::read(&row["help"])?;
        if help.values[1] != "required" { return None; }
        displayed.push(serde_json::json!({"label":help.values[0], "helpLabel":format!("Help: {}", help.values[0]),
            "help":[help.values[2], help.values[6], format!("Where to find it: {}", help.values[4])], "badges":["Not checked"],
            "baseline":[if index == 0 { "Workflow reference · not a local compatibility rule" } else { "Defined by your project" },
                baseline["version"].as_str().unwrap_or("No universal version inferred")]}));
    }
    Some(serde_json::json!({"heading":"Build / archive prerequisites", "badges":["Tools not checked","Release readiness unknown"],
        "host":"Core host: linux", "roles":displayed, "limitations":value["limitations"]}))
}

struct ProposalSample { display: Value, workflows: Value }
impl ProposalSample {
    fn read(value: &Value, draft: &Value) -> Option<Self> {
        crate::edit_protocol::bounded(value, 256 * 1024).ok()?;
        let schema = format!("https://raw.githubusercontent.com/{TOOLKIT_REPOSITORY}/{TOOLKIT_SHA}/schemas/project.schema.json");
        if !keys(value, &["schemaVersion", "state", "validation", "facts", "assurance", "templateSet", "tooling", "workflows", "settings"])
            || value["schemaVersion"].as_u64() != Some(1) || value["state"].as_str() != Some("proposed")
            || !format_valid(&value["validation"]) || !assurance(value, "schema-policy")
            || value["facts"] != serde_json::json!({"githubContacted":false,"repositoryObserved":false,"toolingRefResolved":false,
                "templateCompatibility":"unknown","comparisonBasis":"caller-supplied-digest-summary","snapshotProvided":false,"applyAvailable":false})
            || value["templateSet"] != serde_json::json!({"coreVersion":crate::runtime::CORE_VERSION,"resourceVersion":1,"resourceSha256":GITHUB_RESOURCE})
            || value["tooling"] != serde_json::json!({"repository":TOOLKIT_REPOSITORY,"sha":TOOLKIT_SHA,"schemaReference":schema,"state":"format-only"})
            || value["settings"]["configPath"].as_str() != Some("release/mobile-release.json")
            || value["settings"]["sourcePolicy"] != serde_json::json!({"candidateBranch":draft["source"]["candidateBranch"],
                "productionBranch":draft["source"]["productionBranch"],"basis":"configured-policy"}) { return None; }
        let rows = value["workflows"].as_array().filter(|rows| rows.len() == WORKFLOWS.len())?;
        let mut workflows = Vec::new();
        for (row, (id, path, size)) in rows.iter().zip(WORKFLOWS) {
            let content = row["content"].as_str()?;
            let digest = format!("{:x}", Sha256::digest(content.as_bytes()));
            if !keys(row, &["id", "path", "content", "byteLength", "sha256", "comparison"])
                || row["id"].as_str() != Some(id) || row["path"].as_str() != Some(path)
                || content.len() != size || content.encode_utf16().count() > 4096 || row["byteLength"].as_u64() != Some(size as u64)
                || row["sha256"].as_str() != Some(digest.as_str()) || row["comparison"].as_str() != Some("not-supplied") { return None; }
            workflows.push(serde_json::json!({"path":path,"comparison":"Not supplied · presence unknown",
                "metadata":format!("{size} UTF-8 bytes · Core-reported SHA256 {digest}"),"content":content}));
        }
        // Only genuine response fields enter these private expected displays.
        // Fixed surrounding labels are UI disclaimers, not substituted replies.
        Some(Self { workflows: Value::Array(workflows), display: serde_json::json!({
            "heading":"Passive proposal — nothing applied by this preview", "badge":"GitHub not contacted",
            "description":"Complete caller text from the shared core. This preview saves no files and observes no GitHub, Git or Store state. Any separate native operation is reported in Local workflow files.",
            "facts":[["Toolkit repository",value["tooling"]["repository"]], ["Toolkit commit · format-only",value["tooling"]["sha"]],
                ["Installed core / resource version",format!("{} / {}", value["templateSet"]["coreVersion"].as_str()?, value["templateSet"]["resourceVersion"].as_u64()?)],
                ["Shipped resource SHA256 · identity only",value["templateSet"]["resourceSha256"]],
                ["Remote ref / template compatibility","Not resolved / unknown"], ["Repository / release readiness","Not observed / unknown"],
                ["Draft assessment","Format-valid only · not saved by this preview"], ["Informational schema reference · not fetched or saved",value["tooling"]["schemaReference"]]],
            "settings":[["Caller configuration convention · not an observed file",value["settings"]["configPath"]],
                ["Source basis","Configured policy only · protection unverified"], ["Candidate branch policy",value["settings"]["sourcePolicy"]["candidateBranch"]],
                ["Production branch policy",value["settings"]["sourcePolicy"]["productionBranch"]]],
            "scope":["No project code was executed, tools probed, credentials read, files written or workflow dispatched. This is not a full init configuration, metadata skeleton, .gitignore transaction or an Apply plan.",
                "No comparison summary was supplied; existing workflow presence is unknown. A match is not a verified no-op or an unchanged repository."],
            "workflowHeading":"Four read-only workflow previews", "workflowDescription":"Selectable text only. Paths and hashes identify proposed content, not existing repository files or permission to overwrite them.",
            "settingsHeading":"Environment checklist · not configured", "settingsDescription":"Desired policy and unresolved administrator work, not remote API requests. Existing environments, approvals, permissions and values remain unknown.",
            "localReviewAvailable":false, "remoteAvailable":false
        }) })
    }
}

#[derive(Default)]
struct Guidance {
    requirements_called: bool, requirements: Option<Value>, requirements_visible: bool,
    github_empty: bool, repository_entered: bool, sha_entered: bool, inputs_visible: bool,
    github_called: bool, proposal: Option<ProposalSample>, proposal_visible: bool, workflows_visible: bool, draft_retained: bool,
}
impl Guidance {
    fn complete(&self) -> bool {
        self.requirements_called && self.requirements.is_some() && self.requirements_visible && self.github_empty
            && self.repository_entered && self.sha_entered && self.inputs_visible && self.github_called
            && self.proposal.is_some() && self.proposal_visible && self.workflows_visible && self.draft_retained
    }
}

struct VersionSample { name: String, build: u64, pair_matched: bool, display: Value }
impl VersionSample {
    fn read(result: &crate::release_version_protocol::Observation) -> Option<Self> {
        // Project only the genuine already-admitted DTO; neither these bytes
        // nor the saved pair comparisons are returned to the renderer.
        let raw = edit::bounded(result, crate::release_version_protocol::RESULT_LIMIT).ok()?;
        let value = crate::protocol::strict_json(&raw).ok()?;
        let pair_matched = value["savedConfig"] == serde_json::json!({"bytes":CONFIG_BYTES,"sha256":CONFIG_SHA256})
            && value["savedVersion"] == serde_json::json!({"bytes":VERSION_BYTES,"sha256":VERSION_SHA256});
        if !keys(&value, &["schemaVersion", "source", "version", "savedConfig", "savedVersion", "observationScope", "assurance"])
            || value["schemaVersion"].as_u64() != Some(2) || value["source"].as_str() != Some(VERSION_SOURCE)
            || value["version"] != serde_json::json!({"name":"1.2.3","build":7}) || !pair_matched
            || value["observationScope"].as_str() != Some("single-request-non-atomic") || !assurance(&value, "static-text") { return None; }
        let name = value["version"]["name"].as_str()?.to_owned(); let build = value["version"]["build"].as_u64()?;
        let source = value["source"].as_str()?;
        Some(Self { display: serde_json::json!({"name":name,"build":format!("Build number {build}"),
            "badge":"Observed from saved version file","source":source,"sourceText":format!("Returned saved source:{source}"),
            "scope":"One non-atomic read. External changes are not continuously monitored. No artifact check or full preflight; release readiness is not assessed.",
            "config":"Saved config: release/mobile-release.json","readAvailable":true}), name, build, pair_matched })
    }
}

fn metadata_display(fields: Vec<Value>, validation: Option<Value>) -> Value {
    serde_json::json!({"context":"android / en-US","badge":"Selected text only","fields":fields,
        "loadLabel":"Refresh text","loadAvailable":true,"validateAvailable":true,"reviewAvailable":false,"validation":validation})
}
fn metadata_inputs(display: &Value) -> Option<Value> {
    let fields = display["fields"].as_array().filter(|fields| fields.len() == METADATA_FIELDS.len())?;
    Some(Value::Array(fields.iter().map(|field| serde_json::json!({"id":field["id"],"text":field["text"]})).collect()))
}
struct MetadataSample { absent: usize, empty: Value, edited: Value }
impl MetadataSample {
    fn read(result: &crate::metadata_text_edit_protocol::Observation) -> Option<Self> {
        let raw = edit::bounded(result, crate::metadata_text_edit_protocol::RESPONSE_LIMIT).ok()?;
        let value = crate::protocol::strict_json(&raw).ok()?;
        let baseline_fields: Vec<_> = METADATA_FIELDS.iter().map(|(id, _, _)| serde_json::json!({"id":id,"state":"absent"})).collect();
        if !keys(&value, &["schemaVersion", "platform", "locale", "metadataRoot", "observationScope", "baseline", "fields", "assurance"])
            || value["schemaVersion"].as_u64() != Some(1) || value["platform"].as_str() != Some("android")
            || value["locale"].as_str() != Some("en-US") || value["metadataRoot"].as_str() != Some("release/store")
            || value["observationScope"].as_str() != Some("single-request-non-atomic") || !assurance(&value, "static-text")
            || value["baseline"] != serde_json::json!({"config":{"byteLength":CONFIG_BYTES,"sha256":CONFIG_SHA256},"fields":baseline_fields}) { return None; }
        let rows = value["fields"].as_array().filter(|rows| rows.len() == METADATA_FIELDS.len())?;
        let mut empty = Vec::new(); let mut edited = Vec::new();
        for (row, (id, text, _)) in rows.iter().zip(METADATA_FIELDS) {
            if *row != serde_json::json!({"id":id,"path":format!("release/store/android/en-US/{id}"),"state":"absent"}) { return None; }
            // Absence produces an empty editor, never fabricated file content.
            // The second display is a comparison for explicit browser edits.
            for (target, text, badge) in [(&mut empty, "", "Missing · observed"), (&mut edited, text, "Unsaved text")] {
                target.push(serde_json::json!({"id":row["id"],"path":row["path"],"text":text,"badges":["Required",badge],
                    "count":{"characterCount":null,"limit":null,"bytes":text.len()},"invalid":null}));
            }
        }
        Some(Self { absent: rows.len(), empty: metadata_display(empty, None), edited: metadata_display(edited, None) })
    }
}
fn metadata_validation_display(result: &crate::metadata_text_edit_protocol::ValidationResult, observed: &MetadataSample, inputs: &Value) -> Option<Value> {
    let raw = edit::bounded(result, crate::metadata_text_edit_protocol::RESPONSE_LIMIT).ok()?;
    let value = crate::protocol::strict_json(&raw).ok()?;
    if !keys(&value, &["schemaVersion", "platform", "valid", "state", "fields", "assurance"])
        || value["schemaVersion"].as_u64() != Some(1) || value["platform"].as_str() != Some("android")
        || value["valid"].as_bool() != Some(true) || value["state"].as_str() != Some("format-valid")
        || !assurance(&value, "schema-policy") { return None; }
    let rows = value["fields"].as_array().filter(|rows| rows.len() == METADATA_FIELDS.len())?;
    let originals = observed.empty["fields"].as_array().filter(|rows| rows.len() == METADATA_FIELDS.len())?;
    let supplied = inputs.as_array().filter(|rows| rows.len() == METADATA_FIELDS.len())?;
    let mut fields = Vec::new();
    for (((row, original), input), (id, text, limit)) in rows.iter().zip(originals).zip(supplied).zip(METADATA_FIELDS) {
        if !keys(row, &["id", "valid", "characterCount", "limit", "issues"]) || row["id"].as_str() != Some(id)
            || row["valid"].as_bool() != Some(true) || row["characterCount"].as_u64() != Some(text.len() as u64)
            || row["limit"].as_u64() != Some(u64::from(limit)) || !row["issues"].as_array().is_some_and(Vec::is_empty)
            || *input != serde_json::json!({"id":id,"text":text}) { return None; }
        // Counts/limits come from the actual validation; text comes from the
        // preceding DOM read, matched to the genuine one-call request.
        fields.push(serde_json::json!({"id":row["id"],"path":original["path"],"text":input["text"],"badges":["Required","Unsaved text"],
            "count":{"characterCount":row["characterCount"],"limit":row["limit"],"bytes":input["text"].as_str()?.len()},"invalid":"false"}));
    }
    Some(metadata_display(fields, Some(serde_json::json!({"badge":"Format-valid selected text",
        "text":"Format-valid selected text Not a saved file, whole-metadata validation, native asset check, Store approval or release-readiness result."}))))
}
#[derive(Default)]
struct SavedReads {
    version_called: bool, version: Option<VersionSample>, version_visible: bool,
    metadata_called: bool, metadata: Option<MetadataSample>, metadata_visible: bool,
    entered: [bool; 3], inputs: Option<Value>, validation_called: bool, validation: Option<Value>, validation_visible: bool, draft_retained: bool,
}
impl SavedReads {
    fn complete(&self) -> bool {
        self.version_called && self.version.as_ref().is_some_and(|sample| sample.pair_matched) && self.version_visible
            && self.metadata_called && self.metadata.as_ref().is_some_and(|sample| sample.absent == METADATA_FIELDS.len()) && self.metadata_visible
            && self.entered.iter().all(|entered| *entered) && self.inputs.is_some() && self.validation_called
            && self.validation.is_some() && self.validation_visible && self.draft_retained
    }
}

fn candidate_context(selection: Option<&evidence::Selection>, cancelled: bool) -> Value {
    serde_json::json!({"heading":"Understand your saved candidate evidence.",
        "description":"Choose an existing final-evidence folder. The core checks three documents without changing your project, original files or Store state.",
        "assurance":["Local document consistency; provenance and artifact bytes unverified.",
            "No artifact bytes, signing, GitHub authenticity, Store state, release readiness or recovery safety are established here."],
        "folder":{"heading":"Evidence folder","description":"Separate from the source project. No files need to be copied or renamed.",
            "source":"Source project: positive-project · unchanged by evidence selection",
            "selection":format!("Evidence folder: {}", selection.map_or("Not selected", |s| s.display_name.as_str())),
            "buttons":[["Choose evidence folder",true],["Inspect documents",selection.is_some()],["Check operation status",true]],
            "reason":if selection.is_some() { "Ready to inspect the fixed documents. This does not authorize a release or retry." }
                else { "Choose the retained final-evidence folder to begin. Originals stay in place and are read only." },
            "status":if cancelled { vec!["Original operation cancelled and settled. No new result was accepted.",
                "The original evidence operation was cancelled. No new document observation was accepted."] } else { Vec::<&str>::new() }}})
}
fn candidate_empty_display(selection: Option<&evidence::Selection>, cancelled: bool) -> Value {
    serde_json::json!({"context":candidate_context(selection, cancelled),"result":{
        "heading":"No current document observation",
        "description":"An empty view does not mean a candidate was never released or that recovery is safe. Existing release evidence remains unchanged."}})
}
struct CandidateSample { value: Value, display: Value }
impl CandidateSample {
    fn read(result: &evidence::Observation, selection: &evidence::Selection) -> Option<Self> {
        let raw = edit::bounded(result, evidence::RESULT_LIMIT).ok()?;
        let value = crate::protocol::strict_json(&raw).ok()?;
        // Fixed expected fixture DATA, compared with the genuine core DTO. It
        // is never returned to the renderer, registered, sealed or substituted
        // for the original result. Declared payloads are deliberately absent.
        let expected = serde_json::json!({"schemaVersion":1,"outcome":"consistent",
            "documents":[{"kind":"manifest","state":"valid"},{"kind":"receipt","state":"valid"},{"kind":"intent","state":"valid"}],
            "summary":{"platform":"android","applicationId":"com.example.reader","version":{"marketing":"1.2.3","build":42},
                "source":{"commit":"2".repeat(40),"tree":"3".repeat(40)},
                "artifacts":[{"logicalName":"android-aab","declaredBytes":"12345678","sha256":"6".repeat(64)},
                    {"logicalName":"store-metadata","declaredBytes":"34567","sha256":"5".repeat(64)},
                    {"logicalName":"validation-report","declaredBytes":"2345","sha256":"7".repeat(64)}],
                "recordedRuns":{"authorizedBy":{"runId":"1000000000","attempt":"1"},"executedBy":{"runId":"1000000000","attempt":"1"},
                    "producedBy":{"runId":"1000000000","attempt":"1"}},
                "documentPayloadSha256":{"manifest":"177b5f3e92b3b02b99489bb6e7a6aaca183b16c371218715f79872e1597e8c16",
                    "receipt":"2633c2a44967b6cc6900f3f88831d383b0b5b1f43d0876d6f8b7b4fcdda53018",
                    "intent":"24b9829c7ee58f579ec82f16cc469d5b27641054baece581bec588cb370f8b29"}},
            "assurance":{"level":"local-document-consistency","documentsOnly":true,"artifactBytesVerified":false,"workflowAuthenticated":false,
                "storeStateObserved":false,"comparedWithSourceProject":false,"releaseReady":false,"recoveryAuthorized":false}});
        if value != expected { return None; }
        let summary = &value["summary"];
        let artifacts = summary["artifacts"].as_array()?.iter().zip(["Android App Bundle", "Store metadata", "Validation report"])
            .map(|(artifact, name)| Some(serde_json::json!([name, format!("Declared size: {} bytes", artifact["declaredBytes"].as_str()?),
                format!("Declared SHA-256: {}", artifact["sha256"].as_str()?)]))).collect::<Option<Vec<_>>>()?;
        let runs = ["authorizedBy", "executedBy", "producedBy"].iter().zip(["Manifest records authorization", "Manifest records execution", "Manifest records production"])
            .map(|(role, label)| { let run = &summary["recordedRuns"][*role]; Some(serde_json::json!([label,
                format!("Run {} · attempt {}", run["runId"].as_str()?, run["attempt"].as_str()?)])) }).collect::<Option<Vec<_>>>()?;
        let digests: Vec<_> = ["manifest", "receipt", "intent"].iter().map(|kind| serde_json::json!([kind,summary["documentPayloadSha256"][*kind]])).collect();
        let display = serde_json::json!({"context":candidate_context(Some(selection), false),"result":{
            "headings":[["Documents agree","Formats, canonical self-digests and candidate bindings agree under the core rules. This is not authenticated provenance or a release approval.","Documents only",null],
                ["Declared candidate identity","Read from the manifest, not compared with your project or the Stores.",null,"Help: Declared candidate identity"],
                ["Declared artifacts","No artifact file is opened, measured or hashed by this inspector.",null,"Help: Declared artifacts"],
                ["Manifest-recorded runs","These are unauthenticated declarations, not live workflow status.",null,"Help: Manifest-recorded runs"],
                ["Canonical document payload digests","These are self-integrity digests, not raw-file hashes or signatures.",null,"Help: Document payload digests"]],
            "documents":[["candidate-manifest.json","Format + self-digest valid"],["candidate-receipt.json","Format + self-digest valid"],
                ["operation/candidate-operation-intent.json","Format + self-digest valid"]],
            "identity":[["Platform",if summary["platform"].as_str()? == "android" { "Android" } else { "iOS" }],["Application ID",summary["applicationId"]],
                ["Version / build",format!("{} / {}", summary["version"]["marketing"].as_str()?, summary["version"]["build"].as_u64()?)],
                ["Source commit",summary["source"]["commit"]],["Source tree",summary["source"]["tree"]]],
            "artifacts":artifacts,"runs":runs,"digests":digests}});
        Some(Self { value, display })
    }
}
#[derive(Default)]
struct Candidate {
    initial_idle: bool, initial_visible: bool, pickers: [Picker; 2],
    choose_requests: u8, choose_pending: Option<usize>, choose_returned: [bool; 2], status_pending: u16, latest: Option<evidence::Status>,
    cancel_status: bool, cancelled: bool, cancel_visible: bool,
    selection_status: Option<evidence::Selection>, selected: Option<InstalledEvidenceWitness>, selected_visible: bool,
    observe_requests: u8, observe_pending: bool, observe_returned: bool, observation_status: Option<evidence::Observation>,
    observed: Option<CandidateSample>, observed_visible: bool, draft_retained: bool,
}
impl Candidate {
    fn documents_complete(&self) -> bool {
        self.initial_idle && self.initial_visible && self.choose_requests == 2 && self.choose_pending.is_none()
            && self.choose_returned == [true; 2] && self.status_pending == 0
            && self.cancel_status && self.cancelled && self.cancel_visible && self.pickers[0].settled(false)
            && self.selection_status.is_some() && self.selected.is_some() && self.selected_visible && self.pickers[1].settled(true)
            && self.observe_requests == 1 && !self.observe_pending && self.observe_returned && self.observation_status.is_some()
            && self.observed.is_some() && self.observed_visible
    }
    fn complete(&self) -> bool { self.documents_complete() && self.draft_retained }
    fn status(&mut self, status: &evidence::Status, closing: bool) -> bool {
        // These are actual command replies, not fabricated native finality.
        // Match the original revision/binding and ignore only genuine older
        // replies exactly as the existing controller does. Poll counts vary.
        let Ok(revision) = status.revision.parse::<u64>() else { return false; };
        if status.schema_version != 1 || status.availability != "available" || revision.to_string() != status.revision { return false; }
        if let Some(old) = &self.latest {
            let Ok(before) = old.revision.parse::<u64>() else { return false; };
            if revision < before { return true; }
            if revision == before { return status == old; }
        }
        let id = status.operation.as_ref().and_then(|op| evidence::operation_id(&op.operation_id));
        if self.latest.as_ref().and_then(|old| old.operation.as_ref()).and_then(|op| evidence::operation_id(&op.operation_id)) > id { return false; }
        if closing {
            // Quit normally revokes selection/result. Earlier positive facts
            // stay latched; exit uses the original slot5/Quit6 witness instead.
            return id == Some(5) && matches!(status.phase, evidence::Phase::Refused | evidence::Phase::Stopping)
                && status.problem == Some(evidence::Problem::StaleSelection) && status.selection.is_none() && status.result.is_none();
        }
        let valid = match id {
            None => self.choose_requests == 0 && status.phase == evidence::Phase::Idle && status.operation.is_none()
                && status.selection.is_none() && status.result.is_none() && status.problem.is_none(),
            Some(3) => self.choose_requests >= 1 && status.operation.as_ref().is_some_and(|op| op.kind == evidence::OperationKind::Choose && op.selection_id.is_none())
                && status.selection.is_none() && status.result.is_none()
                && match status.phase {
                    evidence::Phase::Choosing => !self.cancel_status && status.problem.is_none(),
                    evidence::Phase::Stopping | evidence::Phase::Cancelled => self.pickers[0].activated && status.problem == Some(evidence::Problem::Cancelled),
                    _ => false,
                },
            Some(4) => self.choose_requests == 2 && self.cancelled && status.result.is_none() && status.problem.is_none()
                && status.operation.as_ref().is_some_and(|op| op.kind == evidence::OperationKind::Choose && op.selection_id.is_none())
                && match status.phase {
                    evidence::Phase::Choosing => self.selection_status.is_none() && status.selection.is_none(),
                    evidence::Phase::Selected => status.selection.as_ref().is_some_and(|selection| evidence::selection_id(&selection.selection_id)
                        && selection.display_name == "candidate-evidence" && self.selection_status.as_ref().is_none_or(|old| old == selection)),
                    _ => false,
                },
            Some(5) => self.observe_requests == 1 && status.problem.is_none() && self.selected.as_ref().is_some_and(|selected|
                status.selection.as_ref() == Some(&selected.selection) && status.operation.as_ref().is_some_and(|op|
                    op.kind == evidence::OperationKind::Observe && op.selection_id.as_deref() == Some(selected.selection.selection_id.as_str())))
                && match status.phase {
                    evidence::Phase::Observing => self.observation_status.is_none() && status.result.is_none(),
                    evidence::Phase::Observed => status.result.as_ref().is_some_and(|result| self.observation_status.as_ref().is_none_or(|old| old == result)),
                    _ => false,
                },
            _ => false,
        };
        if !valid { return false; }
        match status.phase {
            evidence::Phase::Idle => self.initial_idle = true,
            evidence::Phase::Cancelled => self.cancel_status = true,
            evidence::Phase::Selected => self.selection_status = status.selection.clone(),
            evidence::Phase::Observed => self.observation_status = status.result.clone(),
            _ => {},
        }
        self.latest = Some(status.clone()); true
    }
}

fn review_sample(view: &edit::PreparedConfigView, no_op: bool) -> Option<Value> {
    if edit::bounded(view, 128 * 1024).is_err() || view.schema_version != 1 || view.files.len() != 2
        || view.create_release_directory != !no_op || view.rewrites_config_formatting
        || !format_valid(&view.preview["validation"]) || !assurance(&view.preview, "schema-policy") { return None; }
    for (file, path, size) in [(&view.files[0], "release/mobile-release.json", CONFIG_BYTES), (&view.files[1], ".gitignore", IGNORE_BYTES)] {
        if file.path != path || file.after_bytes != size || file.before_bytes != no_op.then_some(size)
            || file.action != (if no_op { "preserve" } else { "create" }) { return None; }
    }
    if if no_op { !view.ignore_additions.is_empty() } else { !view.ignore_additions.iter().map(String::as_str).eq(IGNORE_LINES) } { return None; }
    let comparison = &view.preview["comparison"];
    if comparison["baseProvided"].as_bool() != Some(no_op) || comparison["state"].as_str() != Some("complete")
        || comparison["kind"].as_str() != Some(if no_op { "compare" } else { "proposed-create" })
        || comparison["semanticallyChanged"].as_bool() != Some(!no_op) || comparison["unreviewedCount"].as_u64() != Some(0)
        || !comparison["changes"].as_array().is_some_and(|changes| changes.len() <= 64 && changes.is_empty() == no_op)
        || no_op && comparison["counts"] != serde_json::json!({"added":0,"changed":0,"removed":0}) { return None; }
    Some(serde_json::json!({"files":view.files,"release":view.create_release_directory,"rewrite":view.rewrites_config_formatting,
        "ignore":view.ignore_additions,"counts":comparison["counts"],
        "basis":if no_op { "The native plan contains no file writes" } else { "Only this reviewed native inventory can be applied" },
        "badge":if no_op { "No writes planned" } else { "Explicit Apply required" }}))
}
fn phase_order(phase: edit::Phase) -> u8 {
    match phase { edit::Phase::Opening => 0, edit::Phase::Editing => 1, edit::Phase::Preparing => 2,
        edit::Phase::Reviewing => 3, edit::Phase::Applying => 4, edit::Phase::Finalizing => 5, edit::Phase::Final => 6, edit::Phase::Unknown => 7 }
}
fn original_final(facts: &InstalledConfigFinality, projection: &EditProjection, no_op: bool) -> bool {
    facts.session_id == projection.session_id && facts.project_id == projection.project_id && facts.owner_generation == projection.owner_generation
        && facts.writer_frames == (if no_op { 2 } else { 3 }) && facts.stdout_frames == 3
        && facts.inspection_joined && facts.acquisition_joined && facts.child_waited_success
        && facts.stdin_closed && facts.stdout_eof_closed && facts.stderr_eof_closed && facts.io_joined
        && facts.driver_joined && facts.watchdog_joined && facts.manager_joined
        && facts.runtime_ledger_settled && facts.runtime_settlement_joined
}
struct SaveSession {
    projection: EditProjection, prepared: Option<Value>, review: Option<Value>,
    prepare_requested: bool, prepare_returned: bool, review_visible: bool, finality: Option<InstalledConfigFinality>,
}
impl SaveSession {
    fn live_review(&self) -> bool {
        self.projection.phase == edit::Phase::Reviewing && self.projection.review_remaining_ms > 0
            && !self.projection.apply_submitted && self.projection.native_reason == edit::NativeEditReason::None
            && self.projection.native_finality == edit::NativeFinality::Pending && self.projection.core_outcome.is_none()
            && self.prepared.is_some() && self.review.is_some() && self.finality.is_none()
    }
}
struct Record {
    attached: bool, started: bool, loaded: bool, info: bool, methods: usize, catalog: bool, environment: bool,
    pickers: [Picker; 2], cancel_returned: bool, cancelled: bool, project: Option<Project>, selected: bool,
    project_witness: Option<InstalledProjectWitness>, candidate: Candidate, paths: Paths,
    snapshot_requests: u8, snapshot: bool, snapshot_visible: bool, suggest_called: bool, suggested: Option<Value>, provenance: Option<Value>,
    provenance_visible: bool, adopted: bool, draft_visible: bool, guidance: Guidance,
    capability: bool, generation: Option<String>, native_revision: Option<u32>, sessions: Vec<SaveSession>, requests: [u8; 4],
    open_pending: bool, prepare_pending: Option<usize>, apply_returned: bool,
    confirmation_opened: u8, kept_reviewing: bool, acknowledged: bool, saved_visible: bool,
    readback: bool, readback_visible: bool, saved_reads: SavedReads, saved_draft_retained: bool, noop_outstanding: bool, originals_final: bool,
    step: Step, pending: Option<Pending>, evaluations: u16, trace: (Step, Boundary),
    close_prevented: bool, native_id: Option<u32>, activated: bool,
    responded: bool, disposal_response: bool, destroyed: bool, released: bool, gtk_returned: bool,
    relay_joined: bool, exit: bool, held: Option<HeldAppInfo>,
}
fn saved_read_context(r: &Record) -> bool {
    // Inspect only the original already-retired Save. Passive reads do not
    // acquire an edit owner or pretend that later observations are atomic.
    r.saved_visible && r.readback && r.readback_visible && r.snapshot_requests == 2 && r.apply_returned
        && r.requests == [1, 1, 1, 0] && !r.open_pending && r.prepare_pending.is_none()
        && r.sessions.len() == 1 && r.sessions[0].finality.is_some()
        && r.sessions[0].projection.phase == edit::Phase::Final && r.sessions[0].projection.native_finality == edit::NativeFinality::Settled
}
pub(super) struct Observation {
    case: Case, main: ThreadId, end: Instant, project_path: Option<PathBuf>, evidence_path: Option<PathBuf>, failed: AtomicBool,
    failure_reported: AtomicBool, failure_sink: rustix::fd::OwnedFd, record: Mutex<Record>,
}
impl Observation {
    fn new(case: Case, failure_sink: rustix::fd::OwnedFd) -> Self {
        let end = Instant::now() + Duration::from_secs(45);
        let project_path = (case != Case::Outstanding).then(project_path).flatten().map(|path|
            if case == Case::ProjectPaths { path.with_file_name("path-project") } else { path });
        let paths = Paths::new((case == Case::ProjectPaths).then_some(project_path.as_deref()).flatten());
        let evidence_path = project_path.as_ref().and_then(|path| path.parent()).map(|root| root.join("candidate-evidence"));
        Self { case, main: std::thread::current().id(), end,
            failed: AtomicBool::new(case != Case::Outstanding && (project_path.is_none() || evidence_path.is_none())
                || case == Case::ProjectPaths && paths.fixture.is_none()), project_path, evidence_path,
            failure_reported: AtomicBool::new(false), failure_sink, record: Mutex::new(Record {
                attached: false, started: false, loaded: false, info: false, methods: 0, catalog: false, environment: false,
                step: Step::Bootstrap, pending: None, evaluations: 0, trace: (Step::Bootstrap, Boundary::Bootstrap),
                pickers: std::array::from_fn(|_| Picker::default()), cancel_returned: false, cancelled: false, project: None, selected: false,
                project_witness: None, candidate: Candidate::default(), paths,
                snapshot_requests: 0, snapshot: false, snapshot_visible: false, suggest_called: false, suggested: None, provenance: None,
                provenance_visible: false, adopted: false, draft_visible: false, guidance: Guidance::default(),
                capability: false, generation: None, native_revision: None, sessions: Vec::new(), requests: [0; 4],
                open_pending: false, prepare_pending: None, apply_returned: false,
                confirmation_opened: 0, kept_reviewing: false, acknowledged: false, saved_visible: false,
                readback: false, readback_visible: false, saved_reads: SavedReads::default(), saved_draft_retained: false, noop_outstanding: false, originals_final: false,
                close_prevented: false, native_id: None, activated: false, responded: false, disposal_response: false,
                destroyed: false, released: false, gtk_returned: false, relay_joined: false, exit: false, held: None,
            }) }
    }
    fn fail(&self) { self.failed.store(true, Ordering::SeqCst); }
    fn record(&self) -> Option<MutexGuard<'_, Record>> {
        match self.record.lock() { Ok(record) => Some(record), Err(_) => { self.fail(); None } }
    }
    fn record_at(&self, boundary: Boundary) -> Option<MutexGuard<'_, Record>> {
        let mut r = self.record()?;
        if !self.failed.load(Ordering::SeqCst) { r.trace = (r.step, boundary); }
        Some(r)
    }
    fn report_failure(&self) {
        if !self.failed.load(Ordering::SeqCst) || self.failure_reported.load(Ordering::SeqCst) { return; }
        let trace = match self.record.try_lock() { Ok(r) => r.trace, Err(_) => return };
        if self.failure_reported.swap(true, Ordering::SeqCst) { return; }
        // Two fixed enum labels, outside every record/GTK lock. No paths,
        // opaque identifiers, DTOs, exception bodies or terminal transcript.
        // One unbuffered attempt before stderr: partial/EINTR/error is not
        // retried, formatted or allowed to affect the original failure latch.
        if let Some((bytes, length)) = failure_pair(trace) {
            if let Some(pair) = bytes.get(..length) { let _ = rustix::io::write(&self.failure_sink, pair); }
        }
        super::diagnostic(trace.0.failure_line()); super::diagnostic(trace.1.failure_line());
    }
    pub(super) fn attach(&self, supervisor: &Supervisor) -> Result<(), BridgeError> {
        if std::thread::current().id() != self.main { self.fail(); return Err(BridgeError::invalid()); }
        // This is the supervisor just created by DesktopBridge::new in setup,
        // before the real window/bootstrap. Positive leaves all hooks unarmed.
        if self.case == Case::Outstanding { supervisor.arm_initial_app_info_shutdown()?; }
        let mut record = self.record_at(Boundary::Bootstrap).ok_or_else(BridgeError::cleanup_unknown)?;
        if record.attached { self.fail(); return Err(BridgeError::invalid()); }
        record.attached = true;
        Ok(())
    }
    pub(super) fn page_load(&self, trusted: bool, finished: bool) {
        let Some(mut r) = self.record_at(Boundary::Bootstrap) else { return; };
        if !trusted || !r.attached || if finished { !r.started || r.loaded } else { r.started } { self.fail(); return; }
        if finished { r.loaded = true; } else { r.started = true; }
    }
    pub(super) fn app_info(&self, info: &AppInfo) {
        if self.case == Case::Outstanding {
            if info.runtime.state == "available" || info.capabilities.is_some() { self.fail(); }
            return;
        }
        let Some(methods) = info.capabilities.as_ref().and_then(|c| c.get("methods")).and_then(Value::as_array) else { self.fail(); return; };
        let Some(actions) = info.capabilities.as_ref().and_then(|c| c.get("actions")).and_then(Value::as_array) else { self.fail(); return; };
        if !(METHODS.len()..=64).contains(&methods.len()) || actions.is_empty() || actions.len() > 64 { self.fail(); return; }
        let available = |m: &&Value| m.get("available").and_then(Value::as_bool) == Some(true);
        let valid = info.runtime.state == "available" && info.runtime.mode == "bundled" && info.runtime.reason.is_none()
            && info.app_name == "Mobile Release Kit" && info.app_version == env!("CARGO_PKG_VERSION")
            && info.project_selection.available && info.project_selection.reason.is_none()
            && (self.case != Case::ProjectPaths || info.project_path_selection.available && info.project_path_selection.reason.is_none())
            && methods.iter().filter(available).count() == METHODS.len()
            && METHODS.iter().all(|name| methods.iter().filter(available).filter(|m| m.get("method").and_then(Value::as_str) == Some(*name)).count() == 1)
            && methods.iter().all(|m| m.get("available").and_then(Value::as_bool).is_some())
            && actions.iter().all(|a| a.get("available").and_then(Value::as_bool) == Some(false));
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        if !valid || r.info { self.fail(); return; }
        r.info = true; r.methods = methods.len();
    }
    pub(super) fn unexpected(&self) { self.fail(); }
    pub(super) fn catalog(&self, result: &Result<Value, BridgeError>) {
        // Bootstrap still consumes the real catalogue. Guidance later uses the
        // adopted draft; field-help, Unset and standalone Validate/Review are not replayed.
        let valid = result.as_ref().ok().and_then(|v| v.get("fields")).and_then(Value::as_array)
            .filter(|fields| fields.len() <= 64).is_some_and(|fields| {
                let mut matches = fields.iter().filter(|field| field["path"].as_str() == Some(FIELD));
                let Some(field) = matches.next() else { return false; };
                matches.next().is_none() && field["requiredness"].as_str() == Some("required")
                    && ["label", "requiredness", "what", "why", "where", "format", "requiredWhen", "failure"].iter().all(|key|
                        field[*key].as_str().is_some_and(|text| !text.is_empty() && text.len() <= 16384 && text.encode_utf16().count() <= 4096))
            });
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        if self.case == Case::Outstanding || !r.info || r.catalog || !valid { self.fail(); return; }
        if self.case == Case::ProjectPaths && !result.as_ref().is_ok_and(|value| PATH_CASES.iter().all(|case|
            value["fields"].as_array().is_some_and(|fields| fields.iter().filter(|field| field["path"].as_str() == Some(case.name)
                && field["label"].as_str() == Some(case.label) && field["input"].as_str() == Some("text")).count() == 1))) { self.fail(); return; }
        r.catalog = true;
    }
    pub(super) fn project_path(&self) -> Option<&Path> { self.project_path.as_deref() }
    pub(super) fn evidence_path(&self) -> Option<&Path> { self.evidence_path.as_deref() }
    pub(super) fn project_result(&self, result: &Result<Option<Project>, crate::asset_commands::AssetError>) {
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        if self.case == Case::Outstanding { self.fail(); return; }
        match result {
            Ok(None) if r.step == Step::Cancelled && !r.cancel_returned && r.pickers[0].responded && r.pickers[0].returned => r.cancel_returned = true,
            Ok(Some(project)) if r.step == Step::Selected && r.cancelled && r.project.is_none() && r.pickers[1].responded && r.pickers[1].returned
                && self.project_path().is_some_and(|path| Path::new(&project.path) == path)
                && project.name == (if self.case == Case::ProjectPaths { "path-project" } else { "positive-project" }) && crate::protocol::valid_id(&project.id) => r.project = Some(project.clone()),
            _ => self.fail(),
        }
    }
    pub(super) fn snapshot_request(&self, project_id: &str) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        let allowed = match r.snapshot_requests {
            0 => matches!(r.step, Step::Selected | Step::ReadSnapshot) && !r.snapshot,
            1 => matches!(r.step, Step::Refresh | Step::ReadReadback) && r.saved_visible && !r.readback
                && r.sessions.first().is_some_and(|session| session.finality.is_some()),
            _ => false,
        };
        if self.case == Case::Outstanding || !allowed || !r.project.as_ref().is_some_and(|project| project.id == project_id) { self.fail(); return; }
        r.snapshot_requests += 1;
    }
    pub(super) fn snapshot(&self, project_id: &str, result: &Result<Value, BridgeError>) {
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        let saved = r.snapshot_requests == 2;
        let valid = result.as_ref().is_ok_and(|value| {
            let config = &value["config"]; let discovery = &value["discovery"]; let scan = &discovery["scan"];
            let configuration = if saved {
                config["state"].as_str() == Some("format-valid") && config["issues"].as_array().is_some_and(Vec::is_empty)
                    && r.suggested.as_ref() == config.get("data")
                    // Exact raw-byte descriptor is produced by the fresh core
                    // file reader, not by this observer or a renderer baseline.
                    && config["content"] == serde_json::json!({"bytes":CONFIG_BYTES,"sha256":CONFIG_SHA256})
                    && r.sessions.first().and_then(|session| session.projection.prepared.as_ref())
                        .is_some_and(|prepared| prepared.view.files[0].after_bytes == CONFIG_BYTES)
            } else {
                config["state"].as_str() == Some("missing") && config.get("data") == Some(&Value::Null)
                    && config.get("content") == Some(&Value::Null)
                    && config["issues"].as_array().is_some_and(|issues| issues.len() == 1 && issues[0]["code"].as_str() == Some("config.missing"))
            };
            r.project.as_ref().is_some_and(|project| project.id == project_id && value["root"].as_str() == Some(project.path.as_str()))
                && value["observationScope"].as_str() == Some("single-request-non-atomic")
                && config["path"].as_str() == Some("release/mobile-release.json") && configuration
                && discovery["state"].as_str() == Some("unverified") && discovery["partial"].as_bool() == Some(false)
                && (if self.case == Case::ProjectPaths {
                    discovery["hints"] == serde_json::json!({"ios":{"projects":["ios/Example.xcodeproj","ios/Kind.xcodeproj"],
                        "workspaces":["ios/Example.xcworkspace"],"workspace":"ios/Example.xcworkspace",
                        "schemes":[],"bundleIds":[],"generatedProjectSources":[]}})
                        && scan["sourceFiles"].as_u64() == Some(0) && scan["sourceBytes"].as_u64() == Some(0)
                        && scan["entries"].as_u64() == Some(11) && scan["excludedEntries"].as_u64() == Some(0)
                } else { discovery["hints"].as_object().is_some_and(|hints| hints.len() == 4)
                && discovery["hints"]["android"]["applicationId"].as_str() == Some(APP_ID)
                && discovery["hints"]["android"]["module"].as_str() == Some(":app")
                && discovery["hints"]["android"]["buildFile"].as_str() == Some("app/build.gradle.kts")
                && discovery["hints"]["versionSource"].as_str() == Some(VERSION_SOURCE)
                && discovery["hints"]["versionNameKey"].as_str() == Some("VERSION_NAME")
                && discovery["hints"]["versionBuildKey"].as_str() == Some("BUILD_NUMBER")
                && scan["sourceFiles"].as_u64() == Some(if saved { 3 } else { 2 })
                && scan["sourceBytes"].as_u64() == Some(PROJECT_SOURCE.len() as u64 + u64::from(VERSION_BYTES) + if saved { u64::from(CONFIG_BYTES) } else { 0 })
                && scan["entries"].as_u64() == Some(if saved { 6 } else { 3 })
                && scan["excludedEntries"].as_u64() == Some(u64::from(saved)) })
                && value["issues"].as_array().is_some_and(Vec::is_empty) && assurance(value, "static-text")
        });
        let stage = if saved { matches!(r.step, Step::Refresh | Step::ReadReadback) && r.saved_visible && !r.readback }
            else { r.snapshot_requests == 1 && matches!(r.step, Step::Selected | Step::ReadSnapshot) && !r.snapshot };
        if self.case == Case::Outstanding || !stage || !valid { self.fail(); return; }
        if saved { r.readback = true; } else { r.snapshot = true; }
    }
    pub(super) fn suggest_request(&self, hints: &Value) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        if self.case != Case::Positive || !r.snapshot_visible || !matches!(r.step, Step::Suggest | Step::ReadSuggestion)
            || r.suggest_called || *hints != serde_json::json!({"platforms":["android"],"androidApplicationId":APP_ID,
                "versionSource":VERSION_SOURCE,"versionNameKey":"VERSION_NAME","versionBuildKey":"BUILD_NUMBER"}) { self.fail(); return; }
        r.suggest_called = true;
    }
    pub(super) fn suggestion(&self, result: &Result<Value, BridgeError>) {
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        let Some(value) = result.as_ref().ok().filter(|value| value["schemaVersion"].as_u64() == Some(1)
            && value["platformSelectionRequired"].as_bool() == Some(false) && assurance(value, "schema-policy")
            && format_valid(&value["validation"])
            && value["draft"]["android"]["enabled"].as_bool() == Some(true)
            && value["draft"]["android"]["applicationId"].as_str() == Some(APP_ID)
            && value["draft"]["android"]["identityStatus"].as_str() == Some("unverified")
            && value["draft"]["ios"]["enabled"].as_bool() == Some(false)
            && value["draft"]["version"]["source"].as_str() == Some(VERSION_SOURCE)
            && value["draft"]["version"]["nameKey"].as_str() == Some("VERSION_NAME")
            && value["draft"]["version"]["buildKey"].as_str() == Some("BUILD_NUMBER")) else { self.fail(); return; };
        let Some(provenance) = value["provenance"].as_array().filter(|rows| !rows.is_empty() && rows.len() <= 64) else { self.fail(); return; };
        let mut projected = Vec::new();
        for row in provenance {
            let (Some(path), Some(source)) = (row["path"].as_str(), row["source"].as_str()) else { self.fail(); return; };
            if path.is_empty() || path.len() > 128 || !matches!(source, "hint" | "default" | "example") { self.fail(); return; }
            projected.push(serde_json::json!({"path":path,"source":source}));
        }
        if self.case != Case::Positive || !r.suggest_called || r.suggested.is_some() || !matches!(r.step, Step::Suggest | Step::ReadSuggestion)
            || !["android.enabled", "android.applicationId"].iter().all(|path| provenance.iter().any(|row| row["path"].as_str() == Some(*path) && row["source"].as_str() == Some("hint")))
            || !["version.source", "version.nameKey", "version.buildKey"].iter().all(|path| provenance.iter().any(|row|
                row["path"].as_str() == Some(*path) && row["source"].as_str() == Some("hint"))) { self.fail(); return; }
        // Private comparison DATA copied from the genuine core response. Never
        // sent to the renderer, installed in its reducer, or printed in a log.
        r.suggested = Some(value["draft"].clone()); r.provenance = Some(Value::Array(projected));
    }
    pub(super) fn requirements_request(&self, body: &Value) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        if self.case != Case::Positive || !r.adopted || !r.draft_visible || r.requests != [0; 4] || !r.sessions.is_empty() || r.open_pending
            || r.guidance.requirements_called
            || !matches!(r.step, Step::LoadRequirements | Step::ReadRequirements)
            || !keys(body, &["draft", "platform", "operation"]) || body["platform"].as_str() != Some("android")
            || body["operation"].as_str() != Some("build")
            || !r.suggested.as_ref().is_some_and(|draft| body.get("draft") == Some(draft)) { self.fail(); return; }
        r.guidance.requirements_called = true;
    }
    pub(super) fn requirements(&self, result: &Result<crate::environment::Requirements, BridgeError>) {
        let sample = result.as_ref().ok().and_then(requirements_display);
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        if self.case != Case::Positive || !r.adopted || !r.draft_visible || r.requests != [0; 4] || !r.sessions.is_empty() || r.open_pending
            || !r.guidance.requirements_called || r.guidance.requirements.is_some() || sample.is_none()
            || !matches!(r.step, Step::LoadRequirements | Step::ReadRequirements) { self.fail(); return; }
        r.guidance.requirements = sample;
    }
    pub(super) fn github_request(&self, body: &Value) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        if self.case != Case::Positive || !r.adopted || !r.draft_visible || r.requests != [0; 4] || !r.sessions.is_empty() || r.open_pending
            || !r.guidance.requirements_visible || !r.guidance.github_empty
            || !r.guidance.repository_entered || !r.guidance.sha_entered || !r.guidance.inputs_visible || r.guidance.github_called
            || !matches!(r.step, Step::ProposeGitHub | Step::ReadProposal)
            || !keys(body, &["draft", "toolingRepository", "toolingSha", "suppliedSnapshot"])
            || body["toolingRepository"].as_str() != Some(TOOLKIT_REPOSITORY) || body["toolingSha"].as_str() != Some(TOOLKIT_SHA)
            || body.get("suppliedSnapshot") != Some(&Value::Null)
            || !r.suggested.as_ref().is_some_and(|draft| body.get("draft") == Some(draft)) { self.fail(); return; }
        r.guidance.github_called = true;
    }
    pub(super) fn github_proposal(&self, result: &Result<Value, BridgeError>) {
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        let sample = result.as_ref().ok().and_then(|value| r.suggested.as_ref().and_then(|draft| ProposalSample::read(value, draft)));
        if self.case != Case::Positive || !r.adopted || !r.draft_visible || r.requests != [0; 4] || !r.sessions.is_empty() || r.open_pending
            || !r.guidance.github_called || r.guidance.proposal.is_some() || sample.is_none()
            || !matches!(r.step, Step::ProposeGitHub | Step::ReadProposal) { self.fail(); return; }
        r.guidance.proposal = sample;
    }
    pub(super) fn release_version_request(&self, body: &Value) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        if self.case != Case::Positive || !saved_read_context(&r) || r.saved_reads.version_called
            || !matches!(r.step, Step::ReadVersion | Step::ReadVersionCard) || !keys(body, &["projectId"])
            || !r.project.as_ref().is_some_and(|project| body["projectId"].as_str() == Some(project.id.as_str())) { self.fail(); return; }
        r.saved_reads.version_called = true;
    }
    pub(super) fn release_version(&self, result: &Result<crate::release_version_protocol::Observation, BridgeError>) {
        let sample = result.as_ref().ok().and_then(VersionSample::read);
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        if self.case != Case::Positive || !saved_read_context(&r) || !r.saved_reads.version_called || r.saved_reads.version.is_some()
            || sample.is_none() || !matches!(r.step, Step::ReadVersion | Step::ReadVersionCard) { self.fail(); return; }
        r.saved_reads.version = sample;
    }
    pub(super) fn metadata_request(&self, body: &Value) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        if self.case != Case::Positive || !saved_read_context(&r) || !r.saved_reads.version_visible || r.saved_reads.metadata_called
            || !matches!(r.step, Step::LoadMetadata | Step::ReadMetadata) || !keys(body, &["projectId", "platform", "locale"])
            || body["platform"].as_str() != Some("android") || body["locale"].as_str() != Some("en-US")
            || !r.project.as_ref().is_some_and(|project| body["projectId"].as_str() == Some(project.id.as_str())) { self.fail(); return; }
        r.saved_reads.metadata_called = true;
    }
    pub(super) fn metadata_observation(&self, result: &Result<crate::metadata_text_edit_protocol::Observation, BridgeError>) {
        let sample = result.as_ref().ok().and_then(MetadataSample::read);
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        if self.case != Case::Positive || !saved_read_context(&r) || !r.saved_reads.version_visible
            || !r.saved_reads.metadata_called || r.saved_reads.metadata.is_some() || sample.is_none()
            || !matches!(r.step, Step::LoadMetadata | Step::ReadMetadata) { self.fail(); return; }
        r.saved_reads.metadata = sample;
    }
    pub(super) fn metadata_validation_request(&self, body: &Value) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        if self.case != Case::Positive || !saved_read_context(&r) || !r.saved_reads.metadata_visible
            || !r.saved_reads.entered.iter().all(|entered| *entered) || r.saved_reads.validation_called
            || !matches!(r.step, Step::ValidateMetadata | Step::ReadMetadataValidation)
            || !keys(body, &["platform", "fields"]) || body["platform"].as_str() != Some("android")
            || !r.saved_reads.inputs.as_ref().is_some_and(|inputs| body.get("fields") == Some(inputs)) { self.fail(); return; }
        r.saved_reads.validation_called = true;
    }
    pub(super) fn metadata_validation(&self, result: &Result<crate::metadata_text_edit_protocol::ValidationResult, BridgeError>) {
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        let sample = result.as_ref().ok().and_then(|result| r.saved_reads.metadata.as_ref().and_then(|observed|
            r.saved_reads.inputs.as_ref().and_then(|inputs| metadata_validation_display(result, observed, inputs))));
        if self.case != Case::Positive || !saved_read_context(&r) || !r.saved_reads.metadata_visible
            || !r.saved_reads.validation_called || r.saved_reads.validation.is_some() || sample.is_none()
            || !matches!(r.step, Step::ValidateMetadata | Step::ReadMetadataValidation) { self.fail(); return; }
        r.saved_reads.validation = sample;
    }
    pub(super) fn evidence_choose_request(&self, body: &Value) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        let index = usize::from(r.candidate.choose_requests);
        let allowed = match index {
            0 => matches!(r.step, Step::ChooseEvidenceCancel | Step::CancelEvidence) && r.candidate.initial_idle && r.candidate.initial_visible,
            1 => matches!(r.step, Step::ChooseEvidenceSelect | Step::SetEvidence) && r.candidate.cancelled && r.candidate.cancel_visible,
            _ => false,
        };
        if self.case != Case::Positive || !allowed || !keys(body, &[]) || !saved_read_context(&r) || !r.saved_reads.complete()
            || !r.saved_draft_retained || r.project_witness.is_none() || r.candidate.choose_pending.is_some() { self.fail(); return; }
        r.candidate.choose_requests += 1; r.candidate.choose_pending = Some(index);
    }
    pub(super) fn evidence_choose_result(&self, result: &Result<evidence::Status, BridgeError>) {
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        let Some(index) = r.candidate.choose_pending.take() else { self.fail(); return; };
        let Some(status) = result.as_ref().ok() else { self.fail(); return; };
        if self.case != Case::Positive || index > 1 || r.candidate.choose_returned[index]
            || status.phase != evidence::Phase::Choosing || status.selection.is_some() || status.result.is_some() || status.problem.is_some()
            || !status.operation.as_ref().is_some_and(|op| evidence::operation_id(&op.operation_id) == Some(index as u32 + 3)
                && op.kind == evidence::OperationKind::Choose && op.selection_id.is_none()) { self.fail(); return; }
        r.candidate.choose_returned[index] = true;
        if !r.candidate.status(status, false) { self.fail(); }
    }
    pub(super) fn evidence_status_request(&self, body: &Value) {
        if self.case == Case::Outstanding { return; }
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        let Some(pending) = r.candidate.status_pending.checked_add(1) else { self.fail(); return; };
        if !keys(body, &[]) { self.fail(); return; }
        // The normal controller checks Idle at connection, long before this
        // page is visited, and later polls the same operation. No extra poll
        // or exact polling count is introduced by this observer.
        r.candidate.status_pending = pending;
    }
    pub(super) fn evidence_status_result(&self, result: &Result<evidence::Status, BridgeError>) {
        if self.case == Case::Outstanding { return; }
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        let Some(pending) = r.candidate.status_pending.checked_sub(1) else { self.fail(); return; };
        r.candidate.status_pending = pending;
        let closing = r.close_prevented;
        if !result.as_ref().is_ok_and(|status| r.candidate.status(status, closing)) { self.fail(); }
    }
    pub(super) fn evidence_observe_request(&self, body: &Value) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        if self.case != Case::Positive || !matches!(r.step, Step::InspectEvidence | Step::EvidenceObserved)
            || !saved_read_context(&r) || !r.saved_reads.complete() || !r.saved_draft_retained
            || !r.candidate.selected_visible || r.candidate.observe_requests != 0 || r.candidate.observe_pending
            || !keys(body, &["selectionId"]) || !r.candidate.selected.as_ref().is_some_and(|selected|
                body["selectionId"].as_str() == Some(selected.selection.selection_id.as_str())) { self.fail(); return; }
        r.candidate.observe_requests = 1; r.candidate.observe_pending = true;
    }
    pub(super) fn evidence_observe_result(&self, result: &Result<evidence::Status, BridgeError>) {
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        let Some(status) = result.as_ref().ok() else { self.fail(); return; };
        if self.case != Case::Positive || !r.candidate.observe_pending || r.candidate.observe_returned || r.candidate.observe_requests != 1
            || status.phase != evidence::Phase::Observing || status.result.is_some() || status.problem.is_some()
            || !r.candidate.selected.as_ref().is_some_and(|selected| status.selection.as_ref() == Some(&selected.selection)
                && status.operation.as_ref().is_some_and(|op| op.operation_id == "5" && op.kind == evidence::OperationKind::Observe
                    && op.selection_id.as_deref() == Some(selected.selection.selection_id.as_str()))) { self.fail(); return; }
        r.candidate.observe_pending = false; r.candidate.observe_returned = true;
        if !r.candidate.status(status, false) { self.fail(); }
    }
    pub(super) fn open_request(&self, project_id: &str) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        let index = r.sessions.len();
        let allowed = match index {
            0 => matches!(r.step, Step::PrepareSave | Step::ReadSaveReview) && r.draft_visible && r.guidance.complete(),
            1 => matches!(r.step, Step::PrepareNoop | Step::ReadNoopReview) && r.saved_draft_retained && r.readback_visible && r.saved_reads.complete() && r.candidate.complete()
                && r.sessions[0].finality.is_some() && r.saved_visible && r.requests == [1, 1, 1, 0],
            _ => false,
        };
        if self.case != Case::Positive || !allowed || !r.capability || r.open_pending || usize::from(r.requests[0]) != index
            || !r.project.as_ref().is_some_and(|project| project.id == project_id) { self.fail(); return; }
        r.open_pending = true; r.requests[0] += 1;
    }
    pub(super) fn open_result(&self, result: &Result<ConfigEditStatus, BridgeError>, edits: &EditOwner) {
        {
            let Some(mut r) = self.record_at(Boundary::Result) else { return; };
            let Some(status) = result.as_ref().ok() else { self.fail(); return; };
            let Some(owner) = status.active.as_ref() else { self.fail(); return; };
            if self.case != Case::Positive || !r.open_pending || r.sessions.len() >= 2 || usize::from(r.requests[0]) != r.sessions.len() + 1
                || owner.phase != edit::Phase::Opening || owner.checkout.is_some() || owner.prepared.is_some() || owner.apply_submitted
                || r.sessions.iter().any(|session| session.projection.session_id == owner.session_id)
                || !r.project.as_ref().is_some_and(|project| project.id == owner.project_id) { self.fail(); return; }
            r.open_pending = false;
            r.sessions.push(SaveSession { projection: owner.clone(), prepared: None, review: None,
                prepare_requested: false, prepare_returned: false, review_visible: false, finality: None });
        }
        if let Ok(status) = result { self.edit_status(status, edits); }
    }
    pub(super) fn prepare_request(&self, args: &edit::PrepareConfigEdit) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        let index = usize::from(r.requests[1]);
        let Some(session) = r.sessions.get(index) else { self.fail(); return; };
        let allowed = if index == 0 { matches!(r.step, Step::PrepareSave | Step::ReadSaveReview) }
            else { index == 1 && matches!(r.step, Step::PrepareNoop | Step::ReadNoopReview) && r.readback_visible && r.saved_draft_retained && r.saved_reads.complete() && r.candidate.complete() };
        let base = if index == 0 { &Value::Null } else { r.suggested.as_ref().unwrap_or(&Value::Null) };
        if self.case != Case::Positive || !allowed || r.prepare_pending.is_some() || session.prepare_requested
            || session.projection.phase != edit::Phase::Editing || session.projection.session_id != args.session_id
            || !session.projection.checkout.as_ref().is_some_and(|checkout| checkout.revision == args.revision && checkout.base == args.expected_base)
            || &args.expected_base != base || r.suggested.as_ref() != Some(&args.draft)
            || args.draft_revision != 1 || args.baseline_generation != index as u32 + 1 { self.fail(); return; }
        r.sessions[index].prepare_requested = true; r.prepare_pending = Some(index); r.requests[1] += 1;
    }
    pub(super) fn prepare_result(&self, result: &Result<ConfigEditStatus, BridgeError>, edits: &EditOwner) {
        {
            let Some(mut r) = self.record_at(Boundary::Result) else { return; };
            let Some(index) = r.prepare_pending.take() else { self.fail(); return; };
            let Some(owner) = result.as_ref().ok().and_then(|status| status.active.as_ref()) else { self.fail(); return; };
            let session = &mut r.sessions[index];
            if session.prepare_returned || owner.session_id != session.projection.session_id || owner.phase != edit::Phase::Preparing
                || owner.prepared.is_some() || owner.apply_submitted || owner.checkout.as_ref().map(|checkout| &checkout.revision)
                    != session.projection.checkout.as_ref().map(|checkout| &checkout.revision) { self.fail(); return; }
            session.prepare_returned = true;
        }
        if let Ok(status) = result { self.edit_status(status, edits); }
    }
    pub(super) fn apply_request(&self, session_id: &str, plan_token: &str) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        if self.case != Case::Positive || !matches!(r.step, Step::Apply | Step::ReadSaved) || r.requests != [1, 1, 0, 0]
            || r.confirmation_opened != 2 || !r.kept_reviewing || !r.acknowledged
            || !r.sessions.first().is_some_and(|session| session.review_visible && session.prepare_returned && session.live_review()
                && session.projection.session_id == session_id
                && session.projection.prepared.as_ref().is_some_and(|prepared| prepared.plan_token == plan_token)) { self.fail(); return; }
        r.requests[2] += 1;
    }
    pub(super) fn apply_result(&self, result: &Result<ConfigEditStatus, BridgeError>, edits: &EditOwner) {
        {
            let Some(mut r) = self.record_at(Boundary::Result) else { return; };
            let Some(owner) = result.as_ref().ok().and_then(|status| status.active.as_ref()) else { self.fail(); return; };
            if r.apply_returned || r.requests != [1, 1, 1, 0] || owner.phase != edit::Phase::Applying || !owner.apply_submitted
                || !r.sessions.first().is_some_and(|session| session.projection.session_id == owner.session_id
                    && session.projection.prepared.as_ref().map(|prepared| &prepared.plan_token)
                        == owner.prepared.as_ref().map(|prepared| &prepared.plan_token)) { self.fail(); return; }
            r.apply_returned = true;
        }
        if let Ok(status) = result { self.edit_status(status, edits); }
    }
    pub(super) fn close_request(&self) {
        if let Some(mut r) = self.record_at(Boundary::Request) { r.requests[3] = r.requests[3].saturating_add(1); }
        self.fail(); // Keep reviewing is not Close; native Quit owns the sole EOF.
    }
    pub(super) fn edit_status(&self, status: &ConfigEditStatus, edits: &EditOwner) {
        if self.case != Case::Positive { return; }
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        if status.schema_version != 1 || !edit::token(&status.window_generation)
            || r.generation.as_ref().is_some_and(|generation| generation != &status.window_generation) { self.fail(); return; }
        if r.generation.is_none() { r.generation = Some(status.window_generation.clone()); }
        if r.native_revision.is_some_and(|revision| status.status_revision < revision) { return; }
        if let Some(active) = &status.active {
            if !r.sessions.iter().any(|session| session.projection.session_id == active.session_id) {
                // A relay may see admission between the real Open call and its
                // synchronous reply hook. Do not guess that original identity.
                if r.open_pending && usize::from(r.requests[0]) == r.sessions.len() + 1 { return; }
                self.fail(); return;
            }
        }
        if status.capability.available && status.capability.reason == edit::EditAvailability::Available { r.capability = true; }
        else if r.capability && !(r.close_prevented && status.capability.reason == edit::EditAvailability::Shutdown && !status.capability.available) {
            self.fail(); return;
        }
        for projection in status.last_terminal.iter().chain(status.active.iter()) {
            let Some(index) = r.sessions.iter().position(|session| session.projection.session_id == projection.session_id) else { self.fail(); return; };
            let no_op = index == 1;
            let base = if no_op { r.suggested.as_ref().unwrap_or(&Value::Null) } else { &Value::Null };
            let old = &r.sessions[index].projection;
            if projection.domain != edit::EditDomain::Configuration || projection.workflow.is_some() || projection.metadata_text.is_some()
                || projection.project_id != old.project_id || projection.owner_generation != status.window_generation
                || !edit::token(&projection.session_id) || projection.late_settled || projection.phase == edit::Phase::Unknown
                || phase_order(projection.phase) < phase_order(old.phase) || projection.native_finality == edit::NativeFinality::Unknown
                || projection.apply_submitted != (!no_op && r.requests[2] == 1 && phase_order(projection.phase) >= phase_order(edit::Phase::Applying))
                || projection.native_reason != (if no_op && r.close_prevented && phase_order(projection.phase) >= phase_order(edit::Phase::Finalizing) {
                    edit::NativeEditReason::Shutdown
                } else { edit::NativeEditReason::None }) { self.fail(); return; }
            if let Some(checkout) = &projection.checkout {
                if !edit::token(&checkout.revision) || &checkout.base != base
                    || old.checkout.as_ref().is_some_and(|before| before.revision != checkout.revision || before.base != checkout.base)
                    || no_op && r.sessions[0].projection.checkout.as_ref().is_some_and(|before| before.revision == checkout.revision) { self.fail(); return; }
            } else if old.checkout.is_some() { self.fail(); return; }
            if let Some(prepared) = &projection.prepared {
                let Some(review) = review_sample(&prepared.view, no_op) else { self.fail(); return; };
                let Ok(value) = serde_json::to_value(prepared) else { self.fail(); return; };
                if !r.sessions[index].prepare_requested || !edit::token(&prepared.plan_token)
                    || !projection.checkout.as_ref().is_some_and(|checkout| checkout.revision == prepared.revision)
                    || prepared.draft_revision != 1 || prepared.baseline_generation != index as u32 + 1
                    || r.sessions[index].prepared.as_ref().is_some_and(|before| before != &value)
                    || no_op && r.sessions[0].projection.prepared.as_ref().is_some_and(|before| before.plan_token == prepared.plan_token) { self.fail(); return; }
                r.sessions[index].prepared = Some(value); r.sessions[index].review = Some(review);
            } else if r.sessions[index].prepared.is_some() { self.fail(); return; }
            if let Some(core) = &projection.core_outcome {
                if core.effect != (if no_op { edit::Effect::NotStarted } else { edit::Effect::Committed })
                    || core.journal != (if no_op { edit::Journal::NotCreated } else { edit::Journal::Clean })
                    || core.resources != edit::ResourceState::Settled
                    || core.reason != (if no_op { edit::CoreReason::Cancelled } else { edit::CoreReason::None })
                    || phase_order(projection.phase) < phase_order(edit::Phase::Finalizing) { self.fail(); return; }
            }
            if projection.phase == edit::Phase::Final {
                if projection.native_finality != edit::NativeFinality::Settled || projection.core_outcome.is_none()
                    || projection.prepared.is_none() || no_op && !r.noop_outstanding { self.fail(); return; }
                if r.sessions[index].finality.is_none() {
                    let Some(facts) = edits.installed_observation_final(&projection.session_id) else { self.fail(); return; };
                    if !original_final(&facts, projection, no_op) { self.fail(); return; }
                    r.sessions[index].finality = Some(facts);
                }
            } else if projection.native_finality != edit::NativeFinality::Pending { self.fail(); return; }
            r.sessions[index].projection = projection.clone();
        }
        r.native_revision = Some(status.status_revision);
    }

    pub(super) fn path_request(&self, args: &crate::asset_commands::ChooseProjectPath<'_>) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        let index = match r.step { Step::Paths(PathStep::Browse(i) | PathStep::Set(i) | PathStep::Activate(i)) => i, _ => { self.fail(); return; } };
        let Some(case) = PATH_CASES.get(index as usize) else { self.fail(); return; };
        if self.case != Case::ProjectPaths || !r.project.as_ref().is_some_and(|p| p.id == args.project_id) || args.field != case.field
            || !r.paths.draft_visible || r.paths.previews_visible < 1 || r.paths.operations[index as usize].requested
            || r.paths.operations[..index as usize].iter().any(|op| !op.settled || !op.visible) { self.fail(); return; }
        r.paths.operations[index as usize].requested = true;
    }
    pub(super) fn path_result(&self, result: &Result<Option<crate::asset_commands::ProjectPathResult>,BridgeError>) {
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        let index = match r.step { Step::Paths(PathStep::Settled(i)) => i, _ => { self.fail(); return; } };
        let Some(case) = PATH_CASES.get(index as usize) else { self.fail(); return; };
        let matched = match (result,case.reason) {
            (Ok(None),PR::UserCancelled) => true,
            (Ok(Some(result)),PR::None) => r.project.as_ref().is_some_and(|project| serde_json::to_value(result).ok()
                == Some(serde_json::json!({"projectId":project.id,"field":case.name,"relativePath":case.relative}))),
            (Err(error),PR::SourceRefused | PR::SourceChanged) => *error == crate::asset_commands::project_path_error(case.reason),
            _ => false,
        };
        let op = &mut r.paths.operations[index as usize];
        if self.case != Case::ProjectPaths || !matched || !op.requested || op.returned || !op.picker.returned { self.fail(); return; }
        op.returned = true;
    }
    pub(super) fn path_created(&self, id: u32, field: PF) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        let Some(index) = id.checked_sub(3).filter(|i| *i < 11) else { self.fail(); return; };
        let index = index as usize;
        if self.case != Case::ProjectPaths || !r.paths.operations[index].requested || PATH_CASES[index].field != field
            || r.paths.operations[index].picker.created
            || !matches!(r.step,Step::Paths(PathStep::Browse(i) | PathStep::Set(i) | PathStep::Activate(i)) if i as usize == index) { self.fail(); return; }
        r.paths.operations[index].picker.created = true;
    }
    pub(super) fn path_dialog(&self, id: u32, index: u8) -> Result<(PF,bool),()> {
        let Some(r) = self.record_at(Boundary::Gtk) else { return Err(()); };
        let Some(case) = PATH_CASES.get(index as usize) else { return Err(()); };
        if self.failed.load(Ordering::SeqCst) || Instant::now() >= self.end || self.case != Case::ProjectPaths
            || id != u32::from(index)+3 || !r.paths.operations[index as usize].requested
            || !r.paths.operations[index as usize].picker.created
            || !matches!(r.pending,Some(Pending::Path(PathStep::Set(i) | PathStep::Activate(i))) if i == index) { self.fail(); return Err(()); }
        Ok((case.field,!r.paths.operations[index as usize].picker.selected))
    }
    pub(super) fn path_target(&self, index: u8) -> Option<PathBuf> {
        if self.case != Case::ProjectPaths { return None; }
        let path = PATH_CASES.get(index as usize)?.path?;
        Some(self.project_path()?.parent()?.join(path))
    }
    pub(super) fn path_selection(&self, id: u32, index: u8) -> Result<(),()> {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return Err(()); };
        if self.case != Case::ProjectPaths || Instant::now() >= self.end || self.failed.load(Ordering::SeqCst)
            || id != u32::from(index)+3 || r.pending != Some(Pending::Path(PathStep::Set(index))) { self.fail(); return Err(()); }
        let Some(op) = r.paths.operations.get_mut(index as usize) else { self.fail(); return Err(()); };
        if !op.picker.created || op.picker.selected || op.picker.activated { self.fail(); return Err(()); }
        op.picker.selected = true; Ok(())
    }
    pub(super) fn path_activation(&self, id: u32, index: u8) -> Result<(),()> {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return Err(()); };
        let Some(case) = PATH_CASES.get(index as usize) else { return Err(()); };
        if self.case != Case::ProjectPaths || Instant::now() >= self.end || self.failed.load(Ordering::SeqCst)
            || id != u32::from(index)+3 || r.pending != Some(Pending::Path(PathStep::Activate(index))) { self.fail(); return Err(()); }
        let op = &mut r.paths.operations[index as usize];
        if !op.picker.created || op.picker.activated || op.picker.selected != case.path.is_some() { self.fail(); return Err(()); }
        op.picker.activated = true; Ok(())
    }
    pub(super) fn path_filename(&self, id: u32, field: PF, path: Option<&Path>) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        let Some(index) = id.checked_sub(3).filter(|i| *i < 11) else { self.fail(); return; };
        let index = index as usize;
        if self.case != Case::ProjectPaths || self.failed.load(Ordering::SeqCst) || Instant::now() >= self.end
            || PATH_CASES[index].field != field || path.is_none() || path != self.path_target(index as u8).as_deref()
            || !r.paths.operations[index].picker.activated || r.paths.operations[index].picker.filename
            || r.paths.operations[index].picker.responded { self.fail(); return; }
        // Exactly after the production filename() return and BEFORE its
        // selected_path publication. This callback changes only fixed fixture
        // metadata; it does not start a worker or manufacture a source result.
        if id >= 10 && !r.paths.fixture.as_mut().is_some_and(|fixture| fixture.transition(id).is_ok()) { self.fail(); return; }
        if Instant::now() >= self.end { self.fail(); return; }
        r.paths.operations[index].picker.filename = true;
    }
    pub(super) fn path_response(&self, id: u32, accepted: bool, cancelled: bool, disposal: bool) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        let Some(index) = id.checked_sub(3).filter(|i| *i < 11) else { self.fail(); return; };
        let select = PATH_CASES[index as usize].path.is_some(); let p = &mut r.paths.operations[index as usize].picker;
        if self.case != Case::ProjectPaths || !p.activated || p.destroyed || p.released { self.fail(); return; }
        if !p.responded && !disposal && (select && accepted && !cancelled && p.filename || !select && cancelled && !accepted && !p.filename) { p.responded = true; }
        else if p.responded && p.returned && disposal && !accepted && !cancelled && !p.disposal { p.disposal = true; }
        else { self.fail(); }
    }
    fn path_gtk_returned(&self, path: PathStep, result: Result<bool,()>) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        if r.pending.take() != Some(Pending::Path(path)) || r.step != Step::Paths(path) { self.fail(); return; }
        let (index,selecting) = match path { PathStep::Set(i) => (i,true), PathStep::Activate(i) => (i,false), _ => { self.fail(); return; } };
        let Some(op) = r.paths.operations.get_mut(index as usize) else { self.fail(); return; };
        match result {
            Ok(false) if !op.picker.activated && (!selecting || !op.picker.selected) => {},
            Ok(true) if selecting && op.picker.selected && !op.picker.activated => r.step = Step::Paths(PathStep::Activate(index)),
            Ok(true) if !selecting && op.picker.activated && op.picker.responded && !op.picker.returned => {
                op.picker.returned = true; r.step = Step::Paths(PathStep::Settled(index));
            }, _ => self.fail(),
        }
    }
    pub(super) fn preview_request(&self, base: &Value, draft: &Value) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        let index = match r.step { Step::Paths(PathStep::Preview(i) | PathStep::ReadPreview(i)) if i < 3 => i, _ => { self.fail(); return; } };
        if self.case != Case::ProjectPaths || r.paths.previews_requested != index || r.paths.previews_visible != index
            || !r.paths.draft_visible || r.requests != [0;4] || !r.sessions.is_empty()
            || edit::bounded(base,crate::asset_commands::DRAFT_LIMIT).is_err() || edit::bounded(draft,crate::asset_commands::DRAFT_LIMIT).is_err() { self.fail(); return; }
        if index == 0 {
            if r.paths.base.is_some() || r.paths.draft.is_some() || !draft.is_object() { self.fail(); return; }
            r.paths.base = Some(base.clone()); r.paths.draft = Some(draft.clone());
        } else {
            let Some(mut patched) = r.paths.draft.clone() else { self.fail(); return; };
            for case in PATH_CASES.iter().filter(|case| case.relative.is_some()) {
                let Some((parent,leaf)) = case.name.split_once('.') else { self.fail(); return; };
                let Some(object) = patched.as_object_mut().and_then(|root| root.entry(parent.to_owned()).or_insert_with(|| serde_json::json!({})).as_object_mut()) else { self.fail(); return; };
                object.insert(leaf.to_owned(),Value::String(case.relative.unwrap().to_owned()));
            }
            if r.paths.base.as_ref() != Some(base) || &patched != draft || index == 2 && r.paths.patched.as_ref() != Some(draft)
                || r.paths.operations[..if index == 1 { 6 } else { 11 }].iter().any(|op| !op.settled || !op.visible) { self.fail(); return; }
            r.paths.patched = Some(patched);
        }
        r.paths.previews_requested += 1;
    }
    pub(super) fn preview_result(&self, result: &Result<Value,BridgeError>) {
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        let Some(index) = r.paths.previews_requested.checked_sub(1).filter(|i| *i < 3) else { self.fail(); return; };
        if self.case != Case::ProjectPaths || !matches!(r.step,Step::Paths(PathStep::Preview(i) | PathStep::ReadPreview(i)) if i == index)
            || r.paths.previews[index as usize].is_some() { self.fail(); return; }
        let Some(sample) = result.as_ref().ok().and_then(path_preview_display) else { self.fail(); return; };
        r.paths.previews[index as usize] = Some(sample);
    }
    fn path_dom(&self, step: PathStep, value: &Value) {
        let Some(mut r) = self.record_at(Boundary::Dom) else { return; };
        if self.case != Case::ProjectPaths || r.pending.take() != Some(Pending::Dom(Step::Paths(step))) || r.step != Step::Paths(step) { self.fail(); return; }
        if *value == serde_json::json!({"state":"wait"}) { return; }
        if value["state"].as_str() != Some("ready") { self.fail(); return; }
        let valid = match step {
            PathStep::ReadDraft => keys(value,&["state","dirty","browse"]) && value["dirty"].as_bool() == Some(true) && value["browse"].as_bool() == Some(true),
            PathStep::ReadPreview(index) => keys(value,&["state","display"]) && r.paths.previews.get(index as usize).and_then(Option::as_ref) == value.get("display"),
            PathStep::ReadField(index) => {
                let Some(case) = PATH_CASES.get(index as usize) else { self.fail(); return; };
                let Some(mut draft) = r.paths.draft.clone() else { self.fail(); return; };
                for positive in PATH_CASES[..=index as usize].iter().filter(|c| c.relative.is_some()) {
                    let (parent,leaf) = positive.name.split_once('.').unwrap();
                    let Some(object) = draft.as_object_mut().and_then(|root| root.entry(parent.to_owned()).or_insert_with(|| serde_json::json!({})).as_object_mut()) else { self.fail(); return; };
                    object.insert(leaf.to_owned(),Value::String(positive.relative.unwrap().to_owned()));
                }
                let notice = match case.reason { PR::UserCancelled => Some("Selection cancelled. No draft or baseline was changed."),
                    PR::SourceRefused => Some("Choose a supported existing item inside the current project. Outside paths, links and unsupported item kinds are refused."),
                    PR::SourceChanged => Some("The selected item or project changed during selection. No draft or baseline was changed."), _ => None };
                let pair = if matches!(index,3 | 10) { Some(serde_json::json!([path_field_display(&draft,PATH_CASES[2]),path_field_display(&draft,PATH_CASES[3])])) } else { None };
                keys(value,&["state","field","dirty","notice","pair"]) && r.paths.operations[index as usize].settled
                    && value.get("field") == Some(&path_field_display(&draft,*case)) && value["dirty"].as_bool() == Some(true)
                    && value["notice"] == serde_json::json!(notice) && value["pair"] == serde_json::json!(pair)
            },
            _ => keys(value,&["state"]),
        };
        if !valid { self.fail(); return; }
        r.step = match step {
            PathStep::Start => Step::Paths(PathStep::ReadDraft),
            PathStep::ReadDraft => { r.paths.draft_visible = true; Step::Paths(PathStep::Preview(0)) },
            PathStep::Preview(index) => Step::Paths(PathStep::ReadPreview(index)),
            PathStep::ReadPreview(index) => { r.paths.previews_visible += 1; match index {
                0 => Step::Paths(PathStep::Browse(0)), 1 => Step::Paths(PathStep::Settings), 2 => Step::Close, _ => { self.fail(); return; } } },
            PathStep::Browse(index) => Step::Paths(if PATH_CASES[index as usize].path.is_some() { PathStep::Set(index) } else { PathStep::Activate(index) }),
            PathStep::ReadField(index) => {
                r.paths.operations[index as usize].visible = true;
                if index == 3 { r.paths.pair_visible = true; } if index == 10 { r.paths.final_pair_visible = true; }
                Step::Paths(match index { 1 => PathStep::Ios, 3 => PathStep::Metadata, 5 => PathStep::Preview(1),
                    8 => PathStep::FinalIos, 10 => PathStep::Preview(2), _ => PathStep::Browse(index+1) })
            },
            PathStep::Ios => Step::Paths(PathStep::Browse(2)), PathStep::Metadata => Step::Paths(PathStep::Browse(4)),
            PathStep::Settings => Step::Paths(PathStep::General), PathStep::General => Step::Paths(PathStep::Browse(6)),
            PathStep::FinalIos => Step::Paths(PathStep::Browse(9)),
            _ => { self.fail(); return; },
        };
    }
    fn paths_report(&self) -> Option<Vec<u8>> {
        let r = self.record()?; let p = &r.paths;
        if self.case != Case::ProjectPaths || !r.exit || !r.originals_final || !p.complete() || r.requests != [0;4] { return None; }
        let counts = |predicate: fn(usize,&PathOperation)->bool| p.operations.iter().enumerate().filter(|(i,op)| predicate(*i,op)).count();
        serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"fixture":"project-paths-v1","gate":"installed-project-profile",
            "scope":"point-in-time-path-metadata-only","assetAuthorityCreated":false,"saveRequests":r.requests.iter().sum::<u8>(),
            "cancel":[{"field":"version.source","operation":3},{"field":"metadata.root","operation":7}],
            "select":PATH_CASES.iter().enumerate().filter_map(|(i,c)| c.relative.map(|relative| serde_json::json!({"field":c.name,"operation":i+3,"relativePath":relative}))).collect::<Vec<_>>(),
            "refused":[{"case":"outside","code":"project_path_unsafe","operation":9},
                {"case":"post-selection-symlink","code":"project_path_unsafe","operation":10},
                {"case":"post-selection-directory-for-file","code":"project_path_unsafe","operation":11},
                {"case":"post-selection-file-for-directory","code":"project_path_unsafe","operation":12},
                {"case":"changed-root-mode","code":"project_path_changed","operation":13}],
            "draft":{"baselineUnchanged":p.base.is_some(),"positivePatchMatched":p.patched.is_some(),"previews":p.previews_visible,
                "refusalsUnchanged":p.previews[2].is_some(),"xcodePairRetained":p.pair_visible && p.final_pair_visible},
            "fixtureMutations":{"actorReturned":p.fixture.as_ref()?.mutations,"newWorker":false},
            "originals":{"childNew":counts(|i,o| o.settled && PATH_CASES[i].path.is_none()),
                "childReturned":counts(|i,o| o.settled && PATH_CASES[i].path.is_some()),"coordinatorReturned":counts(|_,o| o.settled),
                "failedJoins":0,"filenameReads":counts(|_,o| o.picker.filename),"guiSettled":counts(|i,o| o.picker.settled(PATH_CASES[i].path.is_some())),
                "sourceClosed":counts(|i,o| o.settled && PATH_CASES[i].path.is_some() && i != 6),
                "sourceUnstarted":counts(|i,o| o.settled && (PATH_CASES[i].path.is_none() || i == 6))},
            "projectOriginalsSettled":r.cancelled && r.selected,"registryUnchanged":r.originals_final,
            "requestResultDomMatched":counts(|_,o| o.requested && o.returned && o.visible),
            "quit":{"operation":14,"exit":r.exit,"originalsSettled":r.originals_final,"relayJoined":r.relay_joined}
        })).ok().filter(|raw| raw.len()+1 <= 2048)
    }
    pub(super) fn tick(self: &Arc<Self>, app: &tauri::AppHandle) {
        if self.failed.load(Ordering::SeqCst) { self.report_failure(); return; }
        if Instant::now() >= self.end || std::thread::current().id() == self.main { self.fail(); self.report_failure(); return; }
        let step = {
            let Some(mut r) = self.record_at(Boundary::Settlement) else { return; };
            if !r.attached || !r.loaded || r.pending.is_some() { return; }
            if r.step == Step::Bootstrap {
                // Observe the same owners after start_relay returned and its
                // barrier opened. Teardown may legitimately report document loss.
                let state = app.state::<super::ShellState>();
                match (state.bridge.preflight.original_for_test().observed_document_lost_for_test(),
                       state.bridge.android_build.original_for_test().observed_document_lost_for_test()) {
                    (Some(false), Some(false)) => {},
                    (Some(true), _) | (_, Some(true)) => { self.fail(); return; },
                    _ => return, // No absent/busy/unknown observation becomes false.
                }
            }
            if r.step == Step::Bootstrap && self.case != Case::Outstanding {
                if !r.info || !r.catalog { return; }
                r.step = Step::Environment;
            }
            // Wait for already-requested native replies without spending DOM
            // evaluations on work that has not returned. No new task/deadline.
            let native_pending = match r.step {
                Step::Paths(PathStep::ReadPreview(index)) => r.paths.previews.get(index as usize).is_none_or(Option::is_none),
                Step::ReadSnapshot => !r.snapshot,
                Step::ReadSuggestion => r.suggested.is_none(),
                Step::ReadRequirements => r.guidance.requirements.is_none(),
                Step::ReadProposal => r.guidance.proposal.is_none(),
                Step::ReadSaveReview => !r.sessions.first().is_some_and(|session| session.prepare_returned && session.review.is_some()),
                Step::ReadSaved => !r.apply_returned || !r.sessions.first().is_some_and(|session| session.finality.is_some()),
                Step::ReadReadback => !r.readback,
                Step::ReadVersionCard => r.saved_reads.version.is_none(),
                Step::ReadMetadata => r.saved_reads.metadata.is_none(),
                Step::ReadMetadataValidation => r.saved_reads.validation.is_none(),
                Step::ReadEvidenceEmpty => !r.candidate.initial_idle,
                Step::CancelEvidence => !r.candidate.choose_returned[0],
                Step::SetEvidence => !r.candidate.choose_returned[1],
                Step::ReadNoopReview => !r.sessions.get(1).is_some_and(|session| session.prepare_returned && session.review.is_some()),
                _ => false,
            };
            if native_pending { return; }
            r.step
        };
        if step == Step::Bootstrap {
            // The original J seam holds this actual initial app-info child
            // before its writer. No query, candidate constructor or resource
            // lock is introduced here. The returned token retains that owner.
            match app.state::<super::ShellState>().bridge.supervisor.retain_held_app_info() {
                Ok(Some(held)) => {
                    let Some(mut r) = self.record_at(Boundary::Settlement) else { return; };
                    if r.held.is_some() { self.fail(); return; }
                    r.held = Some(held); r.step = Step::Close;
                },
                Ok(None) => {}, Err(_) => self.fail(),
            }
            return;
        }
        if matches!(step, Step::Cancelled | Step::Selected) {
            // IPC completion is only a display receipt. Read the same retained
            // document/operation/source/worker/coordinator originals before any
            // next UI intent; no new task, request, clock or owner is created.
            let state = app.state::<super::ShellState>();
            if step == Step::Cancelled {
                if !state.document.installed_observation_cancelled() { return; }
                let Some(mut r) = self.record_at(Boundary::Settlement) else { return; };
                if !r.cancel_returned || !r.pickers[0].settled(false) { return; }
                r.cancelled = true; r.step = Step::ReadCancelled;
            } else {
                let Some(project) = state.document.installed_observation_project() else { return; };
                let Some(mut r) = self.record_at(Boundary::Settlement) else { return; };
                let Some(returned) = &r.project else { return; };
                if project.id != returned.id || project.path != returned.path || project.name != returned.name { self.fail(); return; }
                if !r.pickers[1].settled(true) { return; }
                let Some(witness) = state.document.installed_observation_project_witness(&project) else { return; };
                if r.project_witness.is_some() { self.fail(); return; }
                r.project_witness = Some(witness);
                r.selected = true; r.step = Step::ReadSnapshot;
            }
            return;
        }
        if let Step::Paths(PathStep::Settled(index)) = step {
            let Some(case) = PATH_CASES.get(index as usize) else { self.fail(); return; };
            let state = app.state::<super::ShellState>();
            let Some(mut r) = self.record_at(Boundary::Settlement) else { return; };
            let Some(project) = r.project_witness.as_ref() else { self.fail(); return; };
            let op = &r.paths.operations[index as usize];
            if !op.returned || !op.picker.settled(case.path.is_some())
                || !state.document.installed_observation_path(project,u32::from(index)+3,case.field,case.reason,case.relative) { return; }
            if op.settled { self.fail(); return; }
            r.paths.operations[index as usize].settled = true; r.step = Step::Paths(PathStep::ReadField(index)); return;
        }
        if matches!(step, Step::EvidenceCancelled | Step::EvidenceSelected | Step::EvidenceObserved) {
            let state = app.state::<super::ShellState>();
            let Some(mut r) = self.record_at(Boundary::Settlement) else { return; };
            let Some(project) = r.project_witness.as_ref() else { self.fail(); return; };
            // Borrow only the original retained document facts. The result
            // poll is not proof of worker/coordinator/supervisor retirement.
            match step {
                Step::EvidenceCancelled => {
                    if !r.candidate.choose_returned[0] || !r.candidate.cancel_status || !r.candidate.pickers[0].settled(false)
                        || !state.document.installed_observation_evidence_cancelled(project) { return; }
                    r.candidate.cancelled = true; r.step = Step::ReadEvidenceCancelled;
                },
                Step::EvidenceSelected => {
                    if !r.candidate.choose_returned[1] || !r.candidate.pickers[1].settled(true) { return; }
                    let Some(selection) = r.candidate.selection_status.as_ref() else { return; };
                    let Some(original) = state.document.installed_observation_evidence_selected(project) else { return; };
                    if original.selection != *selection || r.candidate.selected.is_some() { self.fail(); return; }
                    r.candidate.selected = Some(original); r.step = Step::ReadEvidenceSelected;
                },
                Step::EvidenceObserved => {
                    if !r.candidate.observe_returned { return; }
                    let Some(returned) = r.candidate.observation_status.as_ref() else { return; };
                    let Some(selection) = r.candidate.selected.as_ref() else { self.fail(); return; };
                    let Some(original) = state.document.installed_observation_evidence_observed(project, selection) else { return; };
                    if &original != returned || r.candidate.observed.is_some() { self.fail(); return; }
                    let Some(sample) = CandidateSample::read(returned, &selection.selection) else { self.fail(); return; };
                    r.candidate.observed = Some(sample); r.step = Step::ReadEvidenceObserved;
                },
                _ => { self.fail(); return; },
            }
            return;
        }
        if step == Step::Exit { return; }
        {
            let Some(mut r) = self.record_at(Boundary::Settlement) else { return; };
            r.pending = Some(match step {
                Step::Close => {
                    if self.case == Case::Positive {
                        if !r.sessions.get(1).is_some_and(|session| session.review_visible && session.live_review())
                            || r.requests != [2, 2, 1, 0] || !r.readback_visible || !r.saved_draft_retained || !r.saved_reads.complete()
                            || !r.candidate.complete() { self.fail(); return; }
                        r.noop_outstanding = true;
                    }
                    if self.case == Case::ProjectPaths && (!r.paths.complete() || r.requests != [0;4] || !r.sessions.is_empty()) { self.fail(); return; }
                    r.step = Step::Quit; Pending::Close
                },
                Step::Quit => { if !r.close_prevented { self.fail(); return; } Pending::Gtk },
                Step::Paths(path @ (PathStep::Set(_) | PathStep::Activate(_))) => Pending::Path(path),
                Step::Cancel | Step::SetProject | Step::SelectProject => Pending::Project(step),
                Step::CancelEvidence | Step::SetEvidence | Step::SelectEvidence => Pending::Evidence(step),
                _ => {
                    if r.evaluations >= 128 { self.fail(); return; }
                    r.evaluations += 1; Pending::Dom(step)
                },
            });
        }
        let Some(window) = app.get_webview_window(super::MAIN_WINDOW) else { self.fail(); return; };
        match step {
            Step::Close => { if window.close().is_err() { self.fail(); } },
            Step::Quit => {
                let q = self.clone(); let app = app.clone();
                if window.run_on_main_thread(move || {
                    let result = super::owned_gtk::activate_observed_quit(&app, &q);
                    q.gtk_returned(result);
                }).is_err() { self.fail(); }
            },
            Step::Paths(path @ (PathStep::Set(index) | PathStep::Activate(index))) => {
                let q = self.clone(); let app = app.clone();
                if window.run_on_main_thread(move || {
                    let result = if matches!(path,PathStep::Set(_)) { super::owned_gtk::select_observed_path(&app,&q,index) }
                        else { super::owned_gtk::activate_observed_path(&app,&q,index) };
                    q.path_gtk_returned(path,result);
                }).is_err() { self.fail(); }
            },
            Step::Cancel | Step::SetProject | Step::SelectProject => {
                let q = self.clone(); let app = app.clone();
                if window.run_on_main_thread(move || {
                    let result = if step == Step::SetProject { super::owned_gtk::select_observed_folder(&app, &q, false) }
                        else { super::owned_gtk::activate_observed_folder(&app, &q, step == Step::SelectProject, false) };
                    q.project_gtk_returned(step, result);
                }).is_err() { self.fail(); }
            },
            Step::CancelEvidence | Step::SetEvidence | Step::SelectEvidence => {
                let q = self.clone(); let app = app.clone();
                if window.run_on_main_thread(move || {
                    let result = if step == Step::SetEvidence { super::owned_gtk::select_observed_folder(&app, &q, true) }
                        else { super::owned_gtk::activate_observed_folder(&app, &q, step == Step::SelectEvidence, true) };
                    q.evidence_gtk_returned(step, result);
                }).is_err() { self.fail(); }
            },
            _ => {
                let Some(script) = script(step) else { self.fail(); return; };
                let q = self.clone();
                // Outer Ok is dispatch, never an evaluation or DOM receipt.
                // An absent callback remains pending; it is never retried.
                if window.eval_with_callback(script, move |value| q.dom(step, &value)).is_err() { self.fail(); }
            },
        }
    }
    fn dom(&self, step: Step, raw: &str) {
        if raw.len() > 262144 || Instant::now() >= self.end { self.fail(); return; }
        let Ok(value) = crate::protocol::strict_json(raw.as_bytes()) else { self.fail(); return; };
        if let Step::Paths(path) = step { self.path_dom(path,&value); return; }
        let Some(object) = value.as_object() else { self.fail(); return; };
        let Some(mut r) = self.record_at(Boundary::Dom) else { return; };
        if r.pending.take() != Some(Pending::Dom(step)) || r.step != step { self.fail(); return; }
        match value.get("state").and_then(Value::as_str) {
            Some("wait") if object.len() == 1 => return,
            Some("ready") => {}, _ => { self.fail(); return; },
        }
        let draft = |saved: bool, available: bool| value["unsaved"].as_bool() == Some(!saved)
            && value["saved"].as_bool() == Some(saved) && value["saveAvailable"].as_bool() == Some(available);
        let source = || r.suggested.as_ref().is_some_and(|suggested| value["source"].as_str() == suggested["version"]["source"].as_str());
        let review = |index: usize| r.sessions.get(index).is_some_and(|session| session.prepare_returned && session.live_review()
            && session.review.as_ref() == value.get("review"))
            && r.project.as_ref().is_some_and(|project| value["projectPath"].as_str() == Some(project.path.as_str()));
        let valid = match step {
            Step::ReadEnvironment => {
                let versions = value.get("versions").and_then(Value::as_array);
                let available = value.get("available").and_then(Value::as_array);
                object.len() == 7 && value["title"].as_str() == Some("Bundled runtime") && value["badge"].as_str() == Some("available")
                    && value["rows"].as_u64() == Some(r.methods as u64) && value["unavailable"].as_u64() == Some((r.methods - METHODS.len()) as u64)
                    && versions.is_some_and(|v| v.len() == 3 && v[0].as_str() == Some(env!("CARGO_PKG_VERSION"))
                        && v[1].as_str() == Some(crate::runtime::CORE_VERSION) && v[2].as_str() == Some("linux"))
                    && available.is_some_and(|a| a.len() == METHODS.len() && a.iter().zip([
                        "Read engine capabilities", "Load schema & field help", "Read a static project observation",
                        "Validate a configuration draft", "Suggest an unverified configuration draft", "Review draft changes and field requirements",
                        "Prepare a GitHub setup preview", "Read selected public metadata text", "Validate supplied public text",
                        "Explain project toolchain requirements", "release.version.observe", "artifacts.candidate.observe",
                    ]).all(|(actual, expected)| actual.as_str() == Some(expected)))
            },
            Step::ReadCancelled => object.len() == 3 && r.cancelled && value["unselected"].as_bool() == Some(true)
                && value["chooseEnabled"].as_bool() == Some(true),
            Step::ReadSnapshot => object.len() == 4 && r.selected && r.snapshot
                && value["configuration"].as_str() == Some("Not configured")
                && value["sourceFiles"].as_str() == Some(if self.case == Case::ProjectPaths { "0 recognized files" } else { "2 recognized files" })
                && value["name"].as_str() == Some(if self.case == Case::ProjectPaths { "path-project" } else { "positive-project" }),
            Step::ReadSuggestion => object.len() == 2 && r.suggested.is_some() && r.provenance.as_ref() == value.get("provenance"),
            Step::ReadDraft | Step::ReadRetainedDraft => object.len() == 5 && r.adopted && r.capability && source() && draft(false, true)
                && (step != Step::ReadRetainedDraft || r.guidance.workflows_visible),
            Step::ReadRequirements => object.len() == 2 && r.guidance.requirements_called
                && r.guidance.requirements.as_ref().is_some_and(|display| value.get("display") == Some(display)),
            Step::ReadGitHubEmpty => object.len() == 3 && r.guidance.requirements_visible && !r.guidance.github_empty
                && value["inputs"] == serde_json::json!({"repository":"","sha":"","comparison":false,"previewAvailable":false})
                && r.suggested.as_ref().is_some_and(|draft| value["branches"] == serde_json::json!(
                    [draft["source"]["candidateBranch"],draft["source"]["productionBranch"]])),
            Step::ReadGitHubInputs => object.len() == 2 && r.guidance.repository_entered && r.guidance.sha_entered
                && value["inputs"] == serde_json::json!({"repository":TOOLKIT_REPOSITORY,"sha":TOOLKIT_SHA,"comparison":false,"previewAvailable":true}),
            Step::ReadProposal => object.len() == 2 && r.guidance.github_called
                && r.guidance.proposal.as_ref().is_some_and(|sample| value.get("display") == Some(&sample.display)),
            Step::ReadWorkflows => object.len() == 2 && r.guidance.proposal_visible
                && r.guidance.proposal.as_ref().is_some_and(|sample| value.get("workflows") == Some(&sample.workflows)),
            Step::ReadSaveReview | Step::ReadKeptReview => object.len() == 6 && review(0) && draft(false, false)
                && r.requests == [1, 1, 0, 0] && (step != Step::ReadKeptReview || r.confirmation_opened == 1),
            Step::ReadNoopReview => object.len() == 6 && review(1) && draft(true, false)
                && r.requests == [2, 2, 1, 0] && r.readback_visible && r.saved_draft_retained && r.saved_reads.complete() && r.candidate.complete(),
            Step::ReadConfirmation | Step::ReadReopenedConfirmation | Step::ReadAcknowledged => {
                let acknowledged = step == Step::ReadAcknowledged;
                let dialog = &value["confirmation"];
                object.len() == 2 && r.requests == [1, 1, 0, 0]
                    && r.sessions.first().is_some_and(|session| session.review_visible && session.live_review()
                        && session.review.as_ref().is_some_and(|review| dialog["files"] == review["files"]))
                    && r.project.as_ref().is_some_and(|project| dialog["projectPath"].as_str() == Some(project.path.as_str()))
                    && keys(dialog, &["title", "projectPath", "draftRevision", "files", "release", "rewrite", "checked", "applyAvailable"])
                    && dialog["title"].as_str() == Some("Apply this configuration save?") && dialog["draftRevision"].as_u64() == Some(1)
                    && dialog["release"].as_bool() == Some(true) && dialog["rewrite"].as_bool() == Some(false)
                    && dialog["checked"].as_bool() == Some(acknowledged) && dialog["applyAvailable"].as_bool() == Some(acknowledged)
                    && r.confirmation_opened == (if step == Step::ReadConfirmation { 1 } else { 2 })
                    && (step == Step::ReadConfirmation || r.kept_reviewing)
            },
            Step::ReadSaved => object.len() == 9 && source() && draft(true, true) && r.apply_returned
                && r.sessions.first().is_some_and(|session| session.finality.is_some())
                && value["title"].as_str() == Some("Submitted configuration saved")
                && value["banner"].as_str() == Some("The submitted revision was saved")
                && value["staleSnapshot"].as_bool() == Some(true)
                && value["facts"] == serde_json::json!([["Transaction effect","committed"],["Journal","clean"],
                    ["Core resources","settled"],["Native finality","settled"]]),
            Step::ReadReadback => object.len() == 6 && r.readback && r.snapshot_requests == 2 && r.saved_visible
                && value["configuration"].as_str() == Some("Format-valid only") && value["sourceFiles"].as_str() == Some("3 recognized files")
                && value["name"].as_str() == Some("positive-project") && value["applicationId"].as_str() == Some(APP_ID)
                && value["staleSnapshot"].as_bool() == Some(false),
            Step::ReadVersionCard => object.len() == 2 && saved_read_context(&r) && r.saved_reads.version_called
                && r.saved_reads.version.as_ref().is_some_and(|sample| value.get("display") == Some(&sample.display)),
            Step::ReadMetadata => object.len() == 2 && saved_read_context(&r) && r.saved_reads.version_visible && r.saved_reads.metadata_called
                && r.saved_reads.metadata.as_ref().is_some_and(|sample| value.get("display") == Some(&sample.empty)),
            Step::EnterTitle => object.len() == 1 && saved_read_context(&r) && r.saved_reads.metadata_visible && r.saved_reads.entered == [false; 3],
            Step::EnterShortDescription => object.len() == 1 && saved_read_context(&r) && r.saved_reads.metadata_visible && r.saved_reads.entered == [true, false, false],
            Step::EnterFullDescription => object.len() == 1 && saved_read_context(&r) && r.saved_reads.metadata_visible && r.saved_reads.entered == [true, true, false],
            Step::ReadMetadataInputs => object.len() == 2 && saved_read_context(&r) && r.saved_reads.metadata_visible
                && r.saved_reads.entered.iter().all(|entered| *entered) && r.saved_reads.inputs.is_none()
                && r.saved_reads.metadata.as_ref().is_some_and(|sample| value.get("display") == Some(&sample.edited)),
            Step::ReadMetadataValidation => object.len() == 2 && saved_read_context(&r) && r.saved_reads.validation_called
                && r.saved_reads.validation.as_ref().is_some_and(|display| value.get("display") == Some(display))
                && r.saved_reads.inputs.is_some() && r.saved_reads.inputs == metadata_inputs(&value["display"]),
            Step::ReadSavedDraft => object.len() == 6 && r.readback_visible && r.saved_reads.complete() && source() && draft(true, true)
                && value["staleSnapshot"].as_bool() == Some(false),
            Step::ReadEvidenceEmpty => object.len() == 2 && saved_read_context(&r) && r.saved_reads.complete() && r.saved_draft_retained
                && r.project_witness.is_some() && r.candidate.initial_idle && !r.candidate.initial_visible
                && value.get("display") == Some(&candidate_empty_display(None, false)),
            Step::ReadEvidenceCancelled => object.len() == 2 && r.candidate.cancel_status && r.candidate.cancelled && r.candidate.pickers[0].settled(false)
                && value.get("display") == Some(&candidate_empty_display(None, true)),
            Step::ReadEvidenceSelected => object.len() == 2 && r.candidate.cancel_visible && r.candidate.pickers[1].settled(true)
                && r.candidate.selected.as_ref().is_some_and(|selected| value.get("display") == Some(&candidate_empty_display(Some(&selected.selection), false))),
            Step::ReadEvidenceObserved => object.len() == 2 && r.candidate.observe_requests == 1 && r.candidate.observe_returned
                && r.candidate.observed.as_ref().is_some_and(|sample| value.get("display") == Some(&sample.display)),
            Step::ReadCandidateDraft => object.len() == 6 && r.saved_draft_retained && r.readback_visible && r.saved_reads.complete()
                && r.candidate.documents_complete() && source() && draft(true, true) && value["staleSnapshot"].as_bool() == Some(false),
            _ => object.len() == 1,
        };
        if !valid { self.fail(); return; }
        r.step = match step {
            Step::Environment => Step::ReadEnvironment,
            Step::ReadEnvironment => { r.environment = true; Step::Dashboard },
            Step::Dashboard => Step::ChooseCancel,
            Step::ChooseCancel => Step::Cancel,
            Step::ReadCancelled => Step::ChooseSelect,
            Step::ChooseSelect => Step::SetProject,
            Step::ReadSnapshot => { r.snapshot_visible = true; Step::Settings },
            Step::Settings => if self.case == Case::ProjectPaths { Step::Paths(PathStep::Start) } else { Step::Suggest },
            Step::Suggest => Step::ReadSuggestion,
            Step::ReadSuggestion => { r.provenance_visible = true; Step::Adopt },
            Step::Adopt => { r.adopted = true; Step::ReadDraft },
            Step::ReadDraft => { r.draft_visible = true; Step::GuidanceEnvironment },
            Step::GuidanceEnvironment => Step::LoadRequirements,
            Step::LoadRequirements => Step::ReadRequirements,
            Step::ReadRequirements => { r.guidance.requirements_visible = true; Step::GitHub },
            Step::GitHub => Step::ReadGitHubEmpty,
            Step::ReadGitHubEmpty => { r.guidance.github_empty = true; Step::EnterRepository },
            Step::EnterRepository => { r.guidance.repository_entered = true; Step::EnterSha },
            Step::EnterSha => { r.guidance.sha_entered = true; Step::ReadGitHubInputs },
            Step::ReadGitHubInputs => { r.guidance.inputs_visible = true; Step::ProposeGitHub },
            Step::ProposeGitHub => Step::ReadProposal,
            Step::ReadProposal => { r.guidance.proposal_visible = true; Step::OpenWorkflows },
            Step::OpenWorkflows => Step::ReadWorkflows,
            Step::ReadWorkflows => { r.guidance.workflows_visible = true; Step::GuidanceSettings },
            Step::GuidanceSettings => Step::ReadRetainedDraft,
            Step::ReadRetainedDraft => { r.guidance.draft_retained = true; Step::PrepareSave },
            Step::PrepareSave => Step::ReadSaveReview,
            Step::ReadSaveReview => { r.sessions[0].review_visible = true; Step::OpenConfirmation },
            Step::OpenConfirmation => { r.confirmation_opened += 1; Step::ReadConfirmation },
            Step::ReadConfirmation => Step::KeepReviewing,
            Step::KeepReviewing => Step::ReadKeptReview,
            Step::ReadKeptReview => { r.kept_reviewing = true; Step::ReopenConfirmation },
            Step::ReopenConfirmation => { r.confirmation_opened += 1; Step::ReadReopenedConfirmation },
            Step::ReadReopenedConfirmation => Step::Acknowledge,
            Step::Acknowledge => Step::ReadAcknowledged,
            Step::ReadAcknowledged => { r.acknowledged = true; Step::Apply },
            Step::Apply => Step::ReadSaved,
            Step::ReadSaved => { r.saved_visible = true; Step::SavedDashboard },
            Step::SavedDashboard => Step::Refresh,
            Step::Refresh => Step::ReadReadback,
            Step::ReadReadback => { r.readback_visible = true; Step::ReadVersion },
            Step::ReadVersion => Step::ReadVersionCard,
            Step::ReadVersionCard => { r.saved_reads.version_visible = true; Step::Metadata },
            Step::Metadata => Step::LoadMetadata,
            Step::LoadMetadata => Step::ReadMetadata,
            Step::ReadMetadata => { r.saved_reads.metadata_visible = true; Step::EnterTitle },
            Step::EnterTitle => { r.saved_reads.entered[0] = true; Step::EnterShortDescription },
            Step::EnterShortDescription => { r.saved_reads.entered[1] = true; Step::EnterFullDescription },
            Step::EnterFullDescription => { r.saved_reads.entered[2] = true; Step::ReadMetadataInputs },
            Step::ReadMetadataInputs => { r.saved_reads.inputs = metadata_inputs(&value["display"]); Step::ValidateMetadata },
            Step::ValidateMetadata => Step::ReadMetadataValidation,
            Step::ReadMetadataValidation => {
                r.saved_reads.validation_visible = true;
                r.saved_reads.draft_retained = r.saved_reads.inputs.is_some() && r.saved_reads.inputs == metadata_inputs(&value["display"]);
                Step::SavedSettings
            },
            Step::SavedSettings => Step::ReadSavedDraft,
            Step::ReadSavedDraft => { r.saved_draft_retained = true; Step::Artifacts },
            Step::Artifacts => Step::ReadEvidenceEmpty,
            Step::ReadEvidenceEmpty => { r.candidate.initial_visible = true; Step::ChooseEvidenceCancel },
            Step::ChooseEvidenceCancel => Step::CancelEvidence,
            Step::ReadEvidenceCancelled => { r.candidate.cancel_visible = true; Step::ChooseEvidenceSelect },
            Step::ChooseEvidenceSelect => Step::SetEvidence,
            Step::ReadEvidenceSelected => { r.candidate.selected_visible = true; Step::InspectEvidence },
            Step::InspectEvidence => Step::EvidenceObserved,
            Step::ReadEvidenceObserved => { r.candidate.observed_visible = true; Step::CandidateSettings },
            Step::CandidateSettings => Step::ReadCandidateDraft,
            Step::ReadCandidateDraft => { r.candidate.draft_retained = true; Step::PrepareNoop },
            Step::PrepareNoop => Step::ReadNoopReview,
            Step::ReadNoopReview => { r.sessions[1].review_visible = true; Step::Close },
            _ => { self.fail(); return; },
        };
    }
    pub(super) fn close_prevented(&self) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        if r.pending.take() != Some(Pending::Close) || r.step != Step::Quit || r.close_prevented { self.fail(); return; }
        r.close_prevented = true;
    }
    pub(super) fn project_created(&self, id: u32) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        let allowed = match id {
            1 => matches!(r.step, Step::ChooseCancel | Step::Cancel) && !r.cancelled,
            2 => matches!(r.step, Step::ChooseSelect | Step::SetProject) && r.cancelled,
            _ => false,
        };
        if self.case == Case::Outstanding || !allowed || r.pickers[(id - 1) as usize].created { self.fail(); return; }
        r.pickers[(id - 1) as usize].created = true;
    }
    pub(super) fn project_selection(&self, id: u32) -> Result<(), ()> {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return Err(()); };
        if self.failed.load(Ordering::SeqCst) || Instant::now() >= self.end || self.case == Case::Outstanding
            || id != 2 || r.pending != Some(Pending::Project(Step::SetProject))
            || !r.pickers[1].created || r.pickers[1].selected { self.fail(); return Err(()); }
        r.pickers[1].selected = true; Ok(())
    }
    pub(super) fn project_activation(&self, id: u32, select: bool) -> Result<(), ()> {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return Err(()); };
        let index = usize::from(select);
        let step = if select { Step::SelectProject } else { Step::Cancel };
        if self.failed.load(Ordering::SeqCst) || Instant::now() >= self.end || self.case == Case::Outstanding
            || id != index as u32 + 1 || r.pending != Some(Pending::Project(step))
            || !r.pickers[index].created || r.pickers[index].activated || r.pickers[index].selected != select { self.fail(); return Err(()); }
        r.pickers[index].activated = true; Ok(())
    }
    pub(super) fn project_filename(&self, id: u32, path: Option<&Path>) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        if id != 2 || !r.pickers[1].activated || r.pickers[1].filename || r.pickers[1].responded
            || path.is_none() || path != self.project_path() { self.fail(); return; }
        r.pickers[1].filename = true;
    }
    pub(super) fn project_response(&self, id: u32, accepted: bool, cancelled: bool, disposal: bool) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        if self.case == Case::Outstanding || !(1..=2).contains(&id) { self.fail(); return; }
        let p = &mut r.pickers[(id - 1) as usize];
        if !p.activated || p.destroyed || p.released { self.fail(); return; }
        if !p.responded && !disposal && (id == 1 && cancelled && !accepted && !p.filename
            || id == 2 && accepted && !cancelled && p.filename) { p.responded = true; }
        else if p.responded && p.returned && disposal && !accepted && !cancelled && !p.disposal { p.disposal = true; }
        else { self.fail(); }
    }
    fn project_gtk_returned(&self, step: Step, result: Result<bool, ()>) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        if r.pending.take() != Some(Pending::Project(step)) || r.step != step { self.fail(); return; }
        let index = usize::from(step != Step::Cancel);
        match result {
            Ok(false) if !r.pickers[index].activated && (step != Step::SetProject || !r.pickers[index].selected) => {},
            Ok(true) if step == Step::SetProject && r.pickers[1].selected && !r.pickers[1].activated => r.step = Step::SelectProject,
            Ok(true) if r.pickers[index].activated && r.pickers[index].responded && !r.pickers[index].returned => {
                r.pickers[index].returned = true;
                r.step = if index == 0 { Step::Cancelled } else { Step::Selected };
            },
            _ => self.fail(),
        }
    }
    pub(super) fn evidence_created(&self, id: u32) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        let allowed = match id {
            3 => matches!(r.step, Step::ChooseEvidenceCancel | Step::CancelEvidence) && r.candidate.choose_requests == 1 && r.candidate.initial_visible,
            4 => matches!(r.step, Step::ChooseEvidenceSelect | Step::SetEvidence) && r.candidate.choose_requests == 2 && r.candidate.cancel_visible,
            _ => false,
        };
        if self.case != Case::Positive || !allowed || r.candidate.pickers[(id - 3) as usize].created { self.fail(); return; }
        r.candidate.pickers[(id - 3) as usize].created = true;
    }
    pub(super) fn evidence_selection(&self, id: u32) -> Result<(), ()> {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return Err(()); };
        if self.failed.load(Ordering::SeqCst) || Instant::now() >= self.end || self.case != Case::Positive
            || id != 4 || r.pending != Some(Pending::Evidence(Step::SetEvidence))
            || !r.candidate.pickers[1].created || r.candidate.pickers[1].selected { self.fail(); return Err(()); }
        r.candidate.pickers[1].selected = true; Ok(())
    }
    pub(super) fn evidence_activation(&self, id: u32, select: bool) -> Result<(), ()> {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return Err(()); };
        let index = usize::from(select);
        let step = if select { Step::SelectEvidence } else { Step::CancelEvidence };
        if self.failed.load(Ordering::SeqCst) || Instant::now() >= self.end || self.case != Case::Positive
            || id != index as u32 + 3 || r.pending != Some(Pending::Evidence(step))
            || !r.candidate.pickers[index].created || r.candidate.pickers[index].activated || r.candidate.pickers[index].selected != select { self.fail(); return Err(()); }
        r.candidate.pickers[index].activated = true; Ok(())
    }
    pub(super) fn evidence_filename(&self, id: u32, path: Option<&Path>) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        if id != 4 || !r.candidate.pickers[1].activated || r.candidate.pickers[1].filename || r.candidate.pickers[1].responded
            || path.is_none() || path != self.evidence_path() { self.fail(); return; }
        r.candidate.pickers[1].filename = true;
    }
    pub(super) fn evidence_response(&self, id: u32, accepted: bool, cancelled: bool, disposal: bool) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        if self.case != Case::Positive || !(3..=4).contains(&id) { self.fail(); return; }
        let p = &mut r.candidate.pickers[(id - 3) as usize];
        if !p.activated || p.destroyed || p.released { self.fail(); return; }
        if !p.responded && !disposal && (id == 3 && cancelled && !accepted && !p.filename
            || id == 4 && accepted && !cancelled && p.filename) { p.responded = true; }
        else if p.responded && p.returned && disposal && !accepted && !cancelled && !p.disposal { p.disposal = true; }
        else { self.fail(); }
    }
    fn evidence_gtk_returned(&self, step: Step, result: Result<bool, ()>) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        if r.pending.take() != Some(Pending::Evidence(step)) || r.step != step { self.fail(); return; }
        let index = usize::from(step != Step::CancelEvidence);
        match result {
            Ok(false) if !r.candidate.pickers[index].activated && (step != Step::SetEvidence || !r.candidate.pickers[index].selected) => {},
            Ok(true) if step == Step::SetEvidence && r.candidate.pickers[1].selected && !r.candidate.pickers[1].activated => r.step = Step::SelectEvidence,
            Ok(true) if r.candidate.pickers[index].activated && r.candidate.pickers[index].responded && !r.candidate.pickers[index].returned => {
                r.candidate.pickers[index].returned = true;
                r.step = if index == 0 { Step::EvidenceCancelled } else { Step::EvidenceSelected };
            },
            _ => self.fail(),
        }
    }
    pub(super) fn native_created(&self, id: u32, quit: bool) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        if !quit || id == 0 || self.case == Case::Positive && id != 6 || self.case == Case::ProjectPaths && id != 14
            || !r.close_prevented || r.step != Step::Quit || r.native_id.is_some() { self.fail(); return; }
        r.native_id = Some(id);
    }
    pub(super) fn native_activation(&self, id: u32) -> Result<(), ()> {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return Err(()); };
        if self.failed.load(Ordering::SeqCst) || Instant::now() >= self.end || r.native_id != Some(id)
            || r.pending != Some(Pending::Gtk) || r.activated { self.fail(); return Err(()); }
        r.activated = true; Ok(())
    }
    pub(super) fn native_response(&self, id: u32, accepted: bool, disposal: bool) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        if r.native_id != Some(id) || !r.activated || r.destroyed || r.released { self.fail(); return; }
        if accepted && !disposal && !r.responded { r.responded = true; }
        else if disposal && !accepted && r.responded && r.gtk_returned && !r.disposal_response {
            // At most one close-generated DeleteEvent, witnessed by the same
            // original close_ack/accepted/returned-None facts in shell.rs.
            r.disposal_response = true;
        } else { self.fail(); }
    }
    fn gtk_returned(&self, result: Result<bool, ()>) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        if r.pending.take() != Some(Pending::Gtk) { self.fail(); return; }
        match result {
            Ok(false) if !r.activated => {},
            Ok(true) if r.activated && r.responded => { r.gtk_returned = true; r.step = Step::Exit; },
            _ => self.fail(),
        }
    }
    pub(super) fn native_destroyed(&self, id: u32, seen: bool) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        if self.case != Case::Outstanding && (1..=2).contains(&id) {
            let p = &mut r.pickers[(id - 1) as usize];
            if !seen || !p.responded || p.destroyed { self.fail(); return; }
            p.destroyed = true; return;
        }
        if self.case == Case::ProjectPaths && (3..=13).contains(&id) {
            let p = &mut r.paths.operations[(id-3) as usize].picker;
            if !seen || !p.responded || p.destroyed { self.fail(); return; }
            p.destroyed = true; return;
        }
        if self.case == Case::Positive && (3..=4).contains(&id) {
            let p = &mut r.candidate.pickers[(id - 3) as usize];
            if !seen || !p.responded || p.destroyed { self.fail(); return; }
            p.destroyed = true; return;
        }
        if !seen || r.native_id != Some(id) || !r.responded || r.destroyed { self.fail(); return; }
        r.destroyed = true;
    }
    pub(super) fn native_released(&self, id: u32, seen: bool) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        if self.case != Case::Outstanding && (1..=2).contains(&id) {
            let p = &mut r.pickers[(id - 1) as usize];
            if !seen || !p.destroyed || p.released { self.fail(); return; }
            p.released = true; return;
        }
        if self.case == Case::ProjectPaths && (3..=13).contains(&id) {
            let p = &mut r.paths.operations[(id-3) as usize].picker;
            if !seen || !p.destroyed || p.released { self.fail(); return; }
            p.released = true; return;
        }
        if self.case == Case::Positive && (3..=4).contains(&id) {
            let p = &mut r.candidate.pickers[(id - 3) as usize];
            if !seen || !p.destroyed || p.released { self.fail(); return; }
            p.released = true; return;
        }
        if !seen || r.native_id != Some(id) || !r.destroyed || r.released { self.fail(); return; }
        r.released = true;
    }
    pub(super) fn relay_joined(&self, joined: bool) {
        let Some(mut r) = self.record_at(Boundary::Settlement) else { return; };
        if !joined || !r.released || !r.gtk_returned || r.relay_joined { self.fail(); return; }
        r.relay_joined = true;
    }
    pub(super) fn actual_exit(&self, ready: bool, document: &crate::asset_session::DocumentBinding, edits: &EditOwner) {
        // The relay may have stopped before its last publication. Read only the
        // SAME already-retired original ledger facts; never start cleanup here.
        if self.case == Case::Positive {
            match edits.status() { Ok(status) => self.edit_status(&status, edits), Err(_) => self.fail() }
        }
        let originals_final = if self.case == Case::Outstanding { true } else {
            let Some(r) = self.record_at(Boundary::Exit) else { return; };
            if self.case == Case::ProjectPaths { r.paths.complete() && r.project_witness.as_ref().is_some_and(|project| document.installed_observation_paths_final(project)) }
            else { r.candidate.complete() && r.project_witness.as_ref().is_some_and(|project| document.installed_observation_candidate_final(project)) }
        };
        let Some(mut r) = self.record_at(Boundary::Exit) else { return; };
        if !ready || !originals_final || !r.relay_joined || !r.released || r.exit
            || self.case == Case::Positive && (r.sessions.len() != 2 || !r.sessions.iter().all(|session| session.finality.is_some())) { self.fail(); return; }
        r.originals_final = originals_final; r.exit = true;
    }
    fn finish(&self) -> bool {
        let held = match self.record() { Some(mut r) => r.held.take(), None => return false };
        let retired = match (self.case, held) {
            (Case::Positive | Case::ProjectPaths, None) => true,
            (Case::Outstanding, Some(mut held)) => {
                // Borrow/join the same original after the NORMAL event loop
                // exits. No additional task, shutdown call, or replacement
                // settlement flag. The once-captured observation end is reused.
                tauri::async_runtime::block_on(held.observe_retired(self.end)).is_ok()
            },
            _ => false,
        };
        let Some(r) = self.record() else { return false; };
        retired && !self.failed.load(Ordering::SeqCst) && Instant::now() < self.end && r.attached && r.loaded
            && r.close_prevented && r.activated && r.responded && r.destroyed && r.released && r.gtk_returned
            && r.relay_joined && r.exit && r.pending.is_none() && r.step == Step::Exit
            && (self.case == Case::Outstanding || self.case == Case::ProjectPaths && r.info && r.catalog && r.environment
                && r.cancelled && r.pickers[0].settled(false) && r.selected && r.pickers[1].settled(true) && r.snapshot && r.snapshot_visible
                && r.snapshot_requests == 1 && r.paths.complete() && r.requests == [0;4] && r.sessions.is_empty() && r.originals_final
                || self.case == Case::Positive && r.info && r.catalog && r.environment
                && r.cancelled && r.pickers[0].settled(false) && r.selected && r.pickers[1].settled(true)
                && r.snapshot && r.snapshot_visible && r.suggested.is_some() && r.provenance_visible && r.adopted && r.draft_visible
                && r.guidance.complete() && r.capability && r.requests == [2, 2, 1, 0] && !r.open_pending && r.prepare_pending.is_none() && r.apply_returned
                && r.confirmation_opened == 2 && r.kept_reviewing && r.acknowledged && r.saved_visible
                && r.snapshot_requests == 2 && r.readback && r.readback_visible && r.saved_reads.complete() && r.saved_draft_retained && r.noop_outstanding
                && r.sessions.len() == 2 && r.sessions.iter().all(|session| session.prepare_returned && session.review_visible && session.finality.is_some())
                && r.project_witness.is_some() && r.candidate.complete() && r.originals_final)
    }
    fn positive_report(&self) -> Option<Vec<u8>> {
        let r = self.record()?;
        if self.case != Case::Positive || !r.exit || !r.originals_final || r.sessions.len() != 2 || !r.guidance.complete() || !r.saved_reads.complete() { return None; }
        let version = r.saved_reads.version.as_ref()?; let metadata = r.saved_reads.metadata.as_ref()?;
        let finals: Vec<_> = r.sessions.iter().filter_map(|session| session.finality.as_ref()).collect();
        if finals.len() != 2 { return None; }
        let count = |test: fn(&InstalledConfigFinality) -> bool| finals.iter().filter(|facts| test(facts)).count();
        let prepared: Vec<_> = r.sessions.iter().filter_map(|session| session.projection.prepared.as_ref()).collect();
        if prepared.len() != 2 { return None; }
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion":3,"fixture":"android-saved-readonly-v1","projectGateContract":true,"methods":"twelve-passive","passiveActions":false,
            "cancel":{"operation":1,"widget":"cancel","guiSettled":r.pickers[0].settled(false),"originalsSettled":r.cancelled,"registered":false},
            "select":{"operation":2,"widget":"select","filenameRead":r.pickers[1].filename,"guiSettled":r.pickers[1].settled(true),"originalsSettled":r.selected,"registered":r.project.is_some()},
            "snapshot":{"initial":"missing","sourceFiles":2,"androidHint":r.snapshot},
            "suggestion":{"coreProvenance":r.provenance_visible,"explicitAdoption":r.adopted},
            "save":{"capability":r.capability,"requests":{"open":r.requests[0],"prepare":r.requests[1],"apply":r.requests[2],"close":r.requests[3]},
                "bindingsMatched":r.sessions.iter().all(|session| session.prepare_requested && session.prepare_returned),
                "draftRevisions":prepared.iter().map(|p| p.draft_revision).collect::<Vec<_>>(),
                "baselineGenerations":prepared.iter().map(|p| p.baseline_generation).collect::<Vec<_>>(),"reviewMatched":r.sessions[0].review_visible,
                "createReleaseDirectory":prepared[0].view.create_release_directory,
                "confirmation":{"opened":r.confirmation_opened,"keepReviewing":r.kept_reviewing,"applyBeforeAck":0,"acknowledged":r.acknowledged},
                "outcome":["committed","clean","settled","none"],"nativeFinality":"settled","savedVisible":r.saved_visible,
                "baselineAdvanced":prepared[1].baseline_generation == prepared[0].baseline_generation + 1},
            "readback":{"fresh":r.readback && r.snapshot_requests == 2,"domMatched":r.readback_visible,"draftMatched":r.saved_draft_retained,
                "size":CONFIG_BYTES,"sha256":CONFIG_SHA256},
            "noop":{"reviewMatched":r.sessions[1].review_visible,"apply":0,"quitOutstanding":r.noop_outstanding,
                "outcome":["not_started","not_created","settled","cancelled"],"nativeReason":"shutdown"},
            "originals":{"sessions":finals.len(),"writerFrames":finals.iter().map(|f| f.writer_frames).collect::<Vec<_>>(),
                "stdoutFrames":finals.iter().map(|f| f.stdout_frames).collect::<Vec<_>>(),
                "startupJoined":count(|f| f.inspection_joined && f.acquisition_joined),"childWaited":count(|f| f.child_waited_success),
                "ioSettled":count(|f| f.stdin_closed && f.stdout_eof_closed && f.stderr_eof_closed && f.io_joined),
                "ownersJoined":count(|f| f.driver_joined && f.watchdog_joined && f.manager_joined),
                "runtimeLedgerSettled":count(|f| f.runtime_ledger_settled),"runtimeSettlementJoined":count(|f| f.runtime_settlement_joined)},
            "quit":{"operation":6,"originalsSettled":r.originals_final,"relayJoined":r.relay_joined,"exit":r.exit},
            "guidance":{"draftUnchanged":r.guidance.draft_retained && r.sessions.iter().all(|session| session.prepare_requested && session.prepare_returned),
                "requirements":{"requestResultDomMatched":r.guidance.requirements_called && r.guidance.requirements.is_some() && r.guidance.requirements_visible,
                    "context":"android/build","roles":3},
                "github":{"requestResultDomMatched":r.guidance.github_called && r.guidance.proposal.is_some() && r.guidance.proposal_visible && r.guidance.workflows_visible,
                    "explicitInputs":r.guidance.github_empty && r.guidance.repository_entered && r.guidance.sha_entered && r.guidance.inputs_visible,
                    "browserEdit":"insertText","workflowCount":4},
                "assuranceActions":false,"releaseReadiness":"unknown"},
            "savedReads":{"version":{"requestResultDomMatched":r.saved_reads.version_called && r.saved_reads.version.is_some() && r.saved_reads.version_visible,
                    "pairMatched":version.pair_matched,"name":version.name,"build":version.build},
                "metadata":{"observeRequestResultDomMatched":r.saved_reads.metadata_called && r.saved_reads.metadata.is_some() && r.saved_reads.metadata_visible,
                    "absent":metadata.absent,"validateRequestResultDomMatched":r.saved_reads.validation_called && r.saved_reads.validation.is_some() && r.saved_reads.validation_visible,
                    "browserEdit":"insertText","draftRetained":r.saved_reads.draft_retained},"scope":"single-request-non-atomic"}
        })).ok().filter(|raw| raw.len() + 1 <= 2048)
    }
    fn candidate_report(&self) -> Option<Vec<u8>> {
        let r = self.record()?;
        if self.case != Case::Positive || !r.exit || !r.originals_final || !r.candidate.complete() || r.sessions.len() != 2 { return None; }
        let c = &r.candidate; let sample = c.observed.as_ref()?; let a = &sample.value["assurance"];
        let preserved = r.project_witness.is_some() && c.cancelled && c.selected.is_some() && c.observed.is_some() && r.originals_final;
        let whole_draft = c.draft_retained && r.saved_draft_retained && r.requests == [2, 2, 1, 0]
            && r.sessions[1].prepare_requested && r.sessions[1].prepare_returned;
        serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"fixture":"android-candidate-documents-v1",
            "gate":"installed-project-profile+candidate-passive","privacy":"independent-predicate+gtk-readback",
            "cancel":{"operation":3,"requestMatched":c.choose_requests == 2 && c.choose_returned[0],"gtkSettled":c.pickers[0].settled(false),
                "tokenJoined":c.cancelled,"probeUnstarted":c.cancelled,"coordinatorJoined":c.cancelled,"noRegistration":c.cancelled},
            "select":{"operation":4,"requestMatched":c.choose_requests == 2 && c.choose_returned[1],"gtkSettled":c.pickers[1].settled(true),
                "filenameMatched":c.pickers[1].filename,"tokenJoined":c.selected.is_some(),"probeJoined":c.selected.is_some(),
                "coordinatorJoined":c.selected.is_some(),"selectionMatched":c.selected.as_ref().is_some_and(|s| c.selection_status.as_ref() == Some(&s.selection))},
            "observe":{"operation":5,"requests":c.observe_requests,"requestResultDomMatched":c.observe_returned && c.observed_visible,
                "bindingMatched":c.observed.is_some(),"coordinatorJoined":c.observed.is_some(),"supervisorIdle":c.observed.is_some(),"knownIdle":c.observed.is_some()},
            "preserved":{"sourceProject":preserved,"registry":preserved,"credentialStateEmpty":preserved,"savedReads":r.saved_reads.complete(),"wholeDraft":whole_draft},
            "scope":{"documents":sample.value["documents"].as_array()?.len(),"formatsDigestsBindingsMatched":c.observed_visible && sample.value["outcome"].as_str() == Some("consistent"),
                "artifactPayloadsObserved":a["artifactBytesVerified"],"sourceCompared":a["comparedWithSourceProject"],
                // A documents-only result cannot be a signature verdict.
                "signingVerified":a["documentsOnly"].as_bool() == Some(false),"storeObserved":a["storeStateObserved"],
                "releaseReady":a["releaseReady"],"recoveryAuthority":a["recoveryAuthorized"]},
            "quit":{"operation":6,"gtkSettled":r.native_id == Some(6) && r.gtk_returned && r.destroyed && r.released,
                "coordinatorJoined":r.originals_final,"relayJoined":r.relay_joined,"exit":r.exit}})).ok().filter(|raw| raw.len() + 1 <= 2048)
    }
}

// Fixed synchronous DOM expressions. Click only existing UI controls, wait for
// later React/effect rendering, and return actual bounded text for comparison.
// No injected DTO, controller/invoke call, .value assignment, synthetic dispatch,
// async Promise, substitute reply, alternate bootstrap or review owner.

fn path_script(step: PathStep) -> Option<String> {
    let body = match step {
        PathStep::Start => r#"const b=[...document.querySelectorAll('.empty-state button')].find(b=>text(b)==='Start an empty draft');
            if (!selected('Project settings') || !b) return {state:'wait'};
            if (b.disabled || document.querySelector('.draft-banner')) throw 0;
            b.scrollIntoView({block:'center'}); if (!visible(b)) throw 0; b.click(); return {state:'ready'};"#.to_owned(),
        PathStep::ReadDraft => r#"if (!selected('Project settings') || !document.querySelector('.draft-banner')) return {state:'wait'};
            const f=field('Committed version file'); if (!f || f.button.disabled) return {state:'wait'};
            return {state:'ready',dirty:dirty(),browse:!f.button.disabled};"#.to_owned(),
        PathStep::Ios | PathStep::FinalIos | PathStep::General => {
            let label = if step == PathStep::General { "General" } else { "iOS" };
            format!(r#"if (!selected('Project settings')) return {{state:'wait'}};
                const b=[...document.querySelectorAll('[aria-label="Settings section"] button')].find(b=>text(b)==='{label}');
                if (!b || b.disabled) throw 0; b.scrollIntoView({{block:'center'}}); if (!visible(b)) throw 0;
                b.click(); return {{state:'ready'}};"#)
        },
        PathStep::Metadata | PathStep::Settings => {
            let label = if step == PathStep::Metadata { "Metadata" } else { "Project settings" };
            format!(r#"const b=document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="{label}"]');
                if (!b || b.disabled) throw 0; b.click(); return {{state:'ready'}};"#)
        },
        PathStep::Browse(index) => {
            let case = PATH_CASES.get(index as usize)?;
            format!(r#"const f=field({}); if (!f || f.button.disabled) return {{state:'wait'}};
                f.button.scrollIntoView({{block:'center'}}); if (!visible(f.button) || text(f.button)!=='Browse existing…') throw 0;
                f.button.click(); return {{state:'ready'}};"#,serde_json::to_string(case.label).ok()?)
        },
        PathStep::ReadField(index) => {
            let case = PATH_CASES.get(index as usize)?;
            let pair = if matches!(index,3 | 10) { "[readField('Xcode project'),readField('Xcode workspace')]" } else { "null" };
            format!(r#"const f=field({}); if (!f || f.button.disabled || text(f.button)!=='Browse existing…') return {{state:'wait'}};
                const notices=[...document.querySelectorAll('main > .notice[role="status"]')]; if (notices.length>1) throw 0;
                return {{state:'ready',field:readField({}),dirty:dirty(),notice:notices.length?text(notices[0].querySelector(':scope > span')):null,pair:{pair}}};"#,
                serde_json::to_string(case.label).ok()?,serde_json::to_string(case.label).ok()?)
        },
        PathStep::Preview(_) => r#"const b=document.querySelector('.draft-toolbar button[aria-describedby="draft-review-reason"]');
            if (!b || b.disabled || text(b)!=='Review draft changes') return {state:'wait'};
            b.scrollIntoView({block:'center'}); if (!visible(b)) throw 0; b.click(); return {state:'ready'};"#.to_owned(),
        PathStep::ReadPreview(_) => r#"const b=document.querySelector('.draft-toolbar button[aria-describedby="draft-review-reason"]');
            const r=document.querySelector('.draft-review');
            if (!b || b.disabled || text(b)!=='Review draft changes' || !r || text(r.querySelector('.section-heading .badge'))!=='Current draft · retained baseline') return {state:'wait'};
            const details=r.querySelector('.context-details'); if (!details) throw 0;
            if (!details.open) details.querySelector('summary').click(); if (!details.open) throw 0;
            const changes=[...r.querySelectorAll('.review-table tbody > tr')],contexts=[...details.querySelectorAll('ul > li')],issues=[...r.querySelectorAll(':scope > .issues > li')];
            if (changes.length>64 || contexts.length>64 || issues.length>128) throw 0;
            const counts=[...r.querySelectorAll('.review-counts > span > strong')].map(e=>{const t=text(e);if(!/^[0-9]{1,3}$/.test(t))throw 0;return Number(t)});
            if (counts.length!==3) throw 0;
            const sections=[...r.querySelectorAll(':scope > .review-section-heading')]; if(sections.length!==2)throw 0;
            const display={badge:text(r.querySelector('.section-heading .badge')),basis:text(r.querySelector('.review-basis strong')),
                counts,comparison:text(r.querySelector('.review-counts .badge')),
                changes:changes.map(row=>{row.scrollIntoView({block:'center'});if(!visible(row))throw 0;
                    const c=[...row.querySelectorAll(':scope > td')];if(c.length!==3)throw 0;return[text(row.querySelector('th code')),...c.map(text)]}),
                contexts:contexts.map(row=>{row.scrollIntoView({block:'center'});if(!visible(row))throw 0;
                    const h=row.querySelector('.context-detail-title');return[text(h.querySelector('code')),text(h.querySelector('.badge')),text(h.querySelector(':scope > span:not(.badge)')),text(row.querySelector(':scope > p'))]}),
                validation:[text(sections[1].querySelector('h3')),text(sections[1].querySelector('.badge'))],
                issues:issues.map(row=>{row.scrollIntoView({block:'center'});if(!visible(row))throw 0;
                    return[text(row.querySelector(':scope > .badge')),text(row.querySelector('strong')),text(row.querySelector('p')),text(row.querySelector('code'))]})};
            return {state:'ready',display};"#.to_owned(),
        _ => return None,
    };
    Some(format!(r#"(() => {{ try {{
        const text=e=>(e?.textContent??'').replace(/\s+/g,' ').trim();
        const visible=e=>!!e&&e.getClientRects().length>0&&getComputedStyle(e).visibility!=='hidden';
        const selected=name=>!!document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="'+name+'"][aria-current="page"]');
        if(document.querySelector('dialog[open], main > [role="alert"]')) throw 0;
        const dirty=()=>{{const b=document.querySelector('.draft-banner');if(!b)throw 0;return text(b.querySelector('.badge'))==='Unsaved changes'}};
        const field=label=>{{const rows=[...document.querySelectorAll('.form-field')].filter(f=>f.querySelector('.help-button')?.getAttribute('aria-label')==='Help: '+label);
            if(rows.length===0)return null;if(rows.length!==1)throw 0;const row=rows[0],input=row.querySelector('input[type="text"]'),button=row.querySelector('button[aria-label="Browse existing '+label+'"]');
            if(!input||!button||input.value.length>512)throw 0;return {{row,input,button,label}}}};
        const fieldValue=f=>{{f.row.scrollIntoView({{block:'center'}});if(!visible(f.row)||!visible(f.input))throw 0;
            return {{label:f.label,value:f.input.value,presence:text(f.row.querySelector('.field-presence')),browse:!f.button.disabled}}}};
        const readField=label=>{{const f=field(label);if(!f)throw 0;return fieldValue(f)}};
        {body}
    }} catch {{ return {{state:'error'}} }} }})()"#))
}

fn script(step: Step) -> Option<String> {
    if let Step::Paths(path) = step { return path_script(path); }
    let body = match step {
        Step::Environment | Step::GuidanceEnvironment => r#"
            const b = document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Environment"]');
            if (!b) return {state:'wait'}; if (b.disabled) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadEnvironment => r#"
            const selectedTab = document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Environment"][aria-current="page"]');
            const card = document.querySelector('.runtime-card');
            if (!selectedTab || !card) return {state:'wait'};
            card.scrollIntoView({block:'start'}); if (!visible(card)) return {state:'error'};
            const rows = [...document.querySelectorAll('.capability-list > div')];
            if (rows.length < 2 || rows.length > 64) return {state:'error'};
            const available = rows.filter(r => text(r.querySelector('.badge')) === 'Available · passive').map(r => text(r.querySelector('strong')));
            const versions = [...card.querySelectorAll('.runtime-versions strong')].map(text);
            return {state:'ready', title:text(card.querySelector('h2')), badge:text(card.querySelector('.badge')),
                versions, available, rows:rows.length, unavailable:rows.filter(r => text(r.querySelector('.badge')) === 'Unavailable').length};"#,
        Step::Dashboard | Step::SavedDashboard => r#"
            const b = document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Dashboard"]');
            if (!b) return {state:'wait'}; if (b.disabled) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ChooseCancel | Step::ChooseSelect => r#"
            if (!selected('Dashboard') || !document.querySelector('.project-overview')) return {state:'wait'};
            const b = [...document.querySelectorAll('.page-heading button')].find(b => text(b) === 'Choose a project');
            if (!b || b.disabled) return {state:'wait'};
            b.scrollIntoView({block:'center'}); if (!visible(b)) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadCancelled => r#"
            const b = [...document.querySelectorAll('.page-heading button')].find(b => text(b) === 'Choose a project');
            if (!selected('Dashboard') || !b || !visible(b) || b.disabled) return {state:'wait'};
            return {state:'ready', unselected:text(document.querySelector('.project-identity h2')) === 'Your next release, organized.'
                && !document.querySelector('.observation-facts, .draft-banner'), chooseEnabled:!b.disabled};"#,
        Step::ReadSnapshot => r#"
            const facts = document.querySelector('.observation-facts');
            const refresh = [...document.querySelectorAll('.observation-card button')].find(b => text(b) === 'Refresh static view');
            if (!selected('Dashboard') || !facts || !refresh || refresh.disabled) return {state:'wait'};
            facts.scrollIntoView({block:'center'}); if (!visible(facts)) return {state:'error'};
            return {state:'ready', configuration:text(document.querySelector('.project-badges .badge')),
                sourceFiles:text(facts.querySelector('strong')), name:text(document.querySelector('.project-identity h2'))};"#,
        Step::Settings | Step::GuidanceSettings | Step::SavedSettings | Step::CandidateSettings => r#"
            const b = document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Project settings"]');
            if (!b || b.disabled) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::Suggest => r#"
            if (!selected('Project settings')) return {state:'wait'};
            const b = document.querySelector('.suggestion-card button[aria-describedby="suggestion-reason"]');
            if (!b || b.disabled) return {state:'wait'};
            if (text(b) !== 'Prepare suggested draft' || document.querySelector('.draft-banner, .suggestion-result')) return {state:'error'};
            b.scrollIntoView({block:'center'}); if (!visible(b)) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadSuggestion => r#"
            const result = document.querySelector('.suggestion-result');
            if (!result) return {state:'wait'};
            const b = result.querySelector('.suggestion-adopt button');
            if (!b || b.disabled || document.querySelector('.draft-banner')) return {state:'error'};
            const rows = [...result.querySelectorAll('.provenance-list > li')];
            if (rows.length === 0 || rows.length > 64) return {state:'error'};
            result.scrollIntoView({block:'start'}); if (!visible(result)) return {state:'error'};
            const codes = {'Unverified hint':'hint', 'Core default':'default', 'Example only':'example'};
            return {state:'ready', provenance:rows.map(row => ({path:text(row.querySelector('code')), source:codes[text(row.querySelector('.badge'))] ?? 'error'}))};"#,
        Step::Adopt => r#"
            const b = document.querySelector('.suggestion-adopt button');
            if (!b || b.disabled || text(b) !== 'Use as an in-memory draft' || document.querySelector('.draft-banner')) return {state:'error'};
            b.scrollIntoView({block:'center'}); if (!visible(b)) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadDraft | Step::ReadRetainedDraft => r#"
            if (!selected('Project settings') || !field() || !document.querySelector('.draft-banner')) return {state:'wait'};
            const draft = draftState(); if (!draft.saveAvailable) return {state:'wait'};
            return {state:'ready', source:sourceValue(), ...draft};"#,
        Step::LoadRequirements => r#"
            if (!selected('Environment')) return {state:'wait'};
            const controls = document.querySelector('.environment-controls'); if (!controls) return {state:'wait'};
            const platform = controls.querySelector('#environment-platform'), operation = controls.querySelector('#environment-operation');
            if (!platform || !operation || platform.disabled || operation.disabled || platform.value !== 'android' || operation.value !== 'build'
                || document.querySelector('.environment-requirements, dialog')) return {state:'error'};
            controls.scrollIntoView({block:'center'}); if (!visible(platform) || !visible(operation)) return {state:'error'};
            const card = controls.closest('section.card');
            const b = [...card.querySelectorAll('.button-row button')].find(b => text(b) === 'Load draft requirements');
            if (!b || b.disabled) return {state:'wait'};
            b.scrollIntoView({block:'center'}); if (!visible(b)) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadRequirements => r#"
            if (!selected('Environment')) return {state:'error'};
            const list = document.querySelector('.environment-requirements'); if (!list) return {state:'wait'};
            const card = list.closest('section.card'); if (card.getAttribute('aria-busy') !== 'false') return {state:'wait'};
            const rows = [...list.querySelectorAll(':scope > article.tool-card')]; if (rows.length !== 3) return {state:'error'};
            const status = card.querySelector(':scope > .button-row');
            const roles = rows.map(row => {
                row.scrollIntoView({block:'center'}); if (!visible(row)) throw 0;
                const help = row.querySelector('.help-button'); if (!help || help.disabled) throw 0;
                return {label:text(row.querySelector('h3')), helpLabel:help.getAttribute('aria-label'),
                    help:[...row.querySelectorAll(':scope > p')].map(text), badges:[...row.querySelectorAll('.button-row .badge')].map(text),
                    baseline:[...row.querySelectorAll('.environment-baseline > *')].map(text)};
            });
            return {state:'ready', display:{heading:text(card.querySelector('h2')), badges:[...status.querySelectorAll('.badge')].map(text),
                host:text(status.querySelector('.save-note')), roles, limitations:[...card.querySelectorAll(':scope > ul.plain-list > li > span')].map(text)}};"#,
        Step::GitHub => r#"
            const b = document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="GitHub"]');
            if (!b || b.disabled) return {state:'error'}; b.click(); return {state:'ready'};"#,
        Step::ReadGitHubEmpty => r#"
            if (!selected('GitHub') || !document.querySelector('form.github-form')) return {state:'wait'};
            const g = githubInputs();
            if (document.querySelector('.github-proposal') || text(g.form.querySelector('.github-draft > strong')) !== 'positive-project · current draft'
                || text(g.button) !== 'Preview GitHub setup') return {state:'error'};
            g.form.scrollIntoView({block:'start'}); if (!visible(g.repository) || !visible(g.sha)) return {state:'error'};
            return {state:'ready', inputs:inputValues(g), branches:[...g.form.querySelectorAll('.github-draft .github-facts dd code')].map(text)};"#,
        Step::EnterRepository => r#"
            const g = githubInputs();
            if (g.repository.value !== '' || g.sha.value !== '' || g.comparison.checked || !g.button.disabled) return {state:'error'};
            const input = g.repository; input.scrollIntoView({block:'center'}); if (!visible(input)) return {state:'error'};
            input.focus(); input.select();
            if (document.activeElement !== input || input.selectionStart !== 0 || input.selectionEnd !== 0
                || !document.execCommand('insertText', false, 'example/toolkit')) return {state:'error'};
            return {state:'ready'};"#,
        Step::EnterSha => r#"
            const g = githubInputs();
            if (g.repository.value !== 'example/toolkit' || g.sha.value !== '' || g.comparison.checked || !g.button.disabled) return {state:'error'};
            const input = g.sha; input.scrollIntoView({block:'center'}); if (!visible(input)) return {state:'error'};
            input.focus(); input.select();
            if (document.activeElement !== input || input.selectionStart !== 0 || input.selectionEnd !== 0
                || !document.execCommand('insertText', false, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')) return {state:'error'};
            return {state:'ready'};"#,
        Step::ReadGitHubInputs => r#"
            const g = githubInputs();
            if (g.repository.value !== 'example/toolkit' || g.sha.value !== 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' || g.comparison.checked) return {state:'error'};
            if (g.button.disabled) return {state:'wait'};
            return {state:'ready', inputs:inputValues(g)};"#,
        Step::ProposeGitHub => r#"
            const g = githubInputs();
            if (g.repository.value !== 'example/toolkit' || g.sha.value !== 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' || g.comparison.checked
                || g.button.disabled || text(g.button) !== 'Preview GitHub setup' || document.querySelector('.github-proposal')) return {state:'error'};
            g.button.scrollIntoView({block:'center'}); if (!visible(g.button)) return {state:'error'};
            g.button.click(); return {state:'ready'};"#,
        Step::ReadProposal => r#"
            const g = githubInputs(); const proposal = document.querySelector('.github-proposal');
            if (!proposal || g.button.disabled) return {state:'wait'};
            proposal.scrollIntoView({block:'start'}); if (!visible(proposal)) return {state:'error'};
            const cards = [...proposal.children]; if (cards.length !== 3 || cards.some(card => !card.classList.contains('card'))) return {state:'error'};
            const facts = card => [...card.querySelectorAll('.github-facts > div')].map(row => [text(row.querySelector('dt')),text(row.querySelector('dd'))]);
            const local = document.querySelector('button[aria-describedby="github-workflow-start-reason"]');
            const remote = [...document.querySelectorAll('.github-disabled-actions button')];
            if (!local || remote.length !== 3) return {state:'error'};
            return {state:'ready', display:{heading:text(cards[0].querySelector('h2')), badge:text(cards[0].querySelector('.badge')),
                description:text(cards[0].querySelector('.section-heading p')), facts:facts(cards[0]), settings:facts(cards[2]),
                scope:[text(cards[0].querySelector('.github-scope-note')),text(cards[1].querySelector('.github-scope-note'))],
                workflowHeading:text(cards[1].querySelector('h2')), workflowDescription:text(cards[1].querySelector('.section-heading p')),
                settingsHeading:text(cards[2].querySelector('h2')), settingsDescription:text(cards[2].querySelector('.section-heading p')),
                localReviewAvailable:!local.disabled, remoteAvailable:remote.some(b => !b.disabled)}};"#,
        Step::OpenWorkflows => r#"
            if (!selected('GitHub')) return {state:'error'};
            const rows = [...document.querySelectorAll('.github-proposal details.github-workflow')];
            if (rows.length !== 4 || rows.some(row => row.open)) return {state:'error'};
            for (const row of rows) {
                const summary = row.querySelector(':scope > summary'); if (!summary) return {state:'error'};
                summary.scrollIntoView({block:'center'}); if (!visible(summary)) return {state:'error'}; summary.click();
            }
            return {state:'ready'};"#,
        Step::ReadWorkflows => r#"
            if (!selected('GitHub')) return {state:'error'};
            const rows = [...document.querySelectorAll('.github-proposal details.github-workflow')];
            if (rows.length !== 4) return {state:'error'}; if (rows.some(row => !row.open)) return {state:'wait'};
            return {state:'ready', workflows:rows.map(row => {
                const pre = row.querySelector('pre'); const path = text(row.querySelector('summary > code'));
                if (!pre || pre.getAttribute('aria-label') !== 'Read-only proposed content for ' + path) throw 0;
                pre.scrollIntoView({block:'start'}); if (!visible(pre)) throw 0;
                return {path, comparison:text(row.querySelector('summary > .badge')), metadata:text(row.querySelector('.github-workflow-meta')), content:text(pre.querySelector('code'))};
            })};"#,
        Step::PrepareSave | Step::PrepareNoop => r#"
            if (!selected('Project settings') || document.querySelector('dialog')) return {state:'error'};
            const b = document.querySelector('.draft-toolbar button[aria-describedby="draft-save-reason"]');
            if (!b || b.disabled) return {state:'wait'};
            if (text(b) !== 'Prepare save review') return {state:'error'};
            b.scrollIntoView({block:'center'}); if (!visible(b)) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadSaveReview | Step::ReadKeptReview | Step::ReadNoopReview => r#"
            if (!selected('Project settings') || document.querySelector('dialog')) return {state:'wait'};
            const panel = document.querySelector('.native-save-panel'), review = panel?.querySelector('.save-review');
            const apply = panel?.querySelector('.save-actions button.primary');
            if (!review || !apply || apply.disabled) return {state:'wait'};
            if (!['Apply reviewed save','Review no-op confirmation'].includes(text(apply))) return {state:'error'};
            const paths = panel.querySelectorAll(':scope > .save-project-path code'); if (paths.length !== 1) return {state:'error'};
            paths[0].scrollIntoView({block:'center'}); if (!visible(paths[0])) return {state:'error'};
            return {state:'ready', projectPath:text(paths[0]), review:reviewDisplay(review), ...draftState()};"#,
        Step::OpenConfirmation | Step::ReopenConfirmation => r#"
            if (!selected('Project settings') || document.querySelector('dialog')) return {state:'error'};
            const panel = document.querySelector('.native-save-panel'), b = panel?.querySelector('.save-actions button.primary');
            if (!panel?.querySelector('.save-review') || !b || b.disabled || text(b) !== 'Apply reviewed save') return {state:'error'};
            b.scrollIntoView({block:'center'}); if (!visible(b)) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadConfirmation | Step::ReadReopenedConfirmation | Step::ReadAcknowledged => r#"
            const d = document.querySelector('dialog.save-confirm-dialog');
            if (!d || !d.open || !visible(d)) return {state:'wait'};
            return {state:'ready', confirmation:confirmationDisplay()};"#,
        Step::KeepReviewing => r#"
            const c = confirmationControls(); if (c.check.checked || !c.apply.disabled) return {state:'error'};
            c.keep.scrollIntoView({block:'center'}); if (!visible(c.keep)) return {state:'error'};
            c.keep.click(); return {state:'ready'};"#,
        Step::Acknowledge => r#"
            const c = confirmationControls(); if (c.check.checked || !c.apply.disabled) return {state:'error'};
            c.check.scrollIntoView({block:'center'}); if (!visible(c.check)) return {state:'error'};
            c.check.click(); return {state:'ready'};"#,
        Step::Apply => r#"
            const c = confirmationControls(); if (!c.check.checked || c.apply.disabled) return {state:'error'};
            c.apply.scrollIntoView({block:'center'}); if (!visible(c.apply)) return {state:'error'};
            c.apply.click(); return {state:'ready'};"#,
        Step::ReadSaved => r#"
            if (!selected('Project settings') || document.querySelector('dialog')) return {state:'wait'};
            const panel = document.querySelector('.native-save-panel'), facts = panel?.querySelector('.save-outcome-facts');
            if (!facts || !document.querySelector('.draft-banner')) return {state:'wait'};
            const draft = draftState(); if (!draft.saved || !draft.saveAvailable) return {state:'wait'};
            facts.scrollIntoView({block:'center'}); if (!visible(facts)) return {state:'error'};
            const rows = [...facts.querySelectorAll(':scope > div')]; if (rows.length !== 4) return {state:'error'};
            return {state:'ready', source:sourceValue(), ...draft, title:text(panel.querySelector('h2')),
                banner:text(document.querySelector('.draft-banner strong')), staleSnapshot:staleSettings(),
                facts:rows.map(row => [text(row.querySelector('dt')),text(row.querySelector('dd'))])};"#,
        Step::Refresh => r#"
            if (!selected('Dashboard') || !document.querySelector('.observation-facts')) return {state:'wait'};
            if (text(document.querySelector('.project-badges .badge')) !== 'Earlier static observation') return {state:'error'};
            const b = [...document.querySelectorAll('.observation-card button')].find(b => text(b) === 'Refresh static view');
            if (!b || b.disabled) return {state:'wait'};
            b.scrollIntoView({block:'center'}); if (!visible(b)) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadReadback => r#"
            if (!selected('Dashboard')) return {state:'wait'};
            const facts = document.querySelector('.observation-facts');
            const refresh = [...document.querySelectorAll('.observation-card button')].find(b => text(b) === 'Refresh static view');
            const identity = document.querySelector('.identity-strip .identity-detail strong');
            if (!facts || !refresh || refresh.disabled || !identity) return {state:'wait'};
            identity.scrollIntoView({block:'center'}); if (!visible(identity)) return {state:'error'};
            return {state:'ready', configuration:text(document.querySelector('.project-badges .badge')),
                sourceFiles:text(facts.querySelector('strong')), name:text(document.querySelector('.project-identity h2')),
                applicationId:text(identity), staleSnapshot:[...document.querySelectorAll('.notice-info strong')].some(e => text(e) === 'This static observation predates the last settled save check')};"#,
        Step::ReadVersion => r#"
            if (!selected('Dashboard')) return {state:'error'};
            const cards = document.querySelectorAll('section[aria-label="Saved version and build"]');
            if (cards.length !== 1) return {state:'error'};
            const card = cards[0], live = card.querySelector('div[aria-live="polite"]'), buttons = card.querySelectorAll(':scope > button');
            if (!live || buttons.length !== 1 || text(buttons[0]) !== 'Read saved version') return {state:'error'};
            const b = buttons[0]; if (b.disabled) return {state:'wait'};
            if (live.getAttribute('aria-busy') !== 'false' || live.children.length !== 1 || text(live.querySelector('strong.summary-value')) !== 'Not read') return {state:'error'};
            b.scrollIntoView({block:'center'}); if (!visible(b)) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadVersionCard => r#"
            if (!selected('Dashboard')) return {state:'error'};
            const cards = document.querySelectorAll('section[aria-label="Saved version and build"]');
            if (cards.length !== 1) return {state:'error'};
            const card = cards[0], live = card.querySelector('div[aria-live="polite"]'), buttons = card.querySelectorAll(':scope > button');
            if (!live || buttons.length !== 1 || text(buttons[0]) !== 'Read saved version') return {state:'error'};
            const name = live.querySelector('strong.summary-value');
            if (live.getAttribute('aria-busy') === 'true' || buttons[0].disabled || ['Not read','Reading…'].includes(text(name))) return {state:'wait'};
            const paragraphs = [...live.querySelectorAll(':scope > p')], badges = live.querySelectorAll(':scope > .badge'), scope = card.querySelectorAll(':scope > p');
            if (live.getAttribute('aria-busy') !== 'false' || live.children.length !== 4 || paragraphs.length !== 2 || badges.length !== 1 || scope.length !== 1) return {state:'error'};
            const sources = paragraphs[1].querySelectorAll(':scope > code'); if (sources.length !== 1) return {state:'error'};
            card.scrollIntoView({block:'center'});
            if (![card, name, ...paragraphs, badges[0], scope[0], buttons[0]].every(visible)) return {state:'error'};
            return {state:'ready', display:{name:text(name), build:text(paragraphs[0]), badge:text(badges[0]), source:text(sources[0]),
                sourceText:text(paragraphs[1]), scope:text(scope[0]), config:text(card.querySelector('.summary-foot code')), readAvailable:!buttons[0].disabled}};"#,
        Step::Metadata => r#"
            const b = document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Metadata"]');
            if (!b || b.disabled) return {state:'error'}; b.click(); return {state:'ready'};"#,
        Step::LoadMetadata => r#"
            if (!selected('Metadata') || !document.querySelector('.metadata-text-editor')) return {state:'wait'};
            const m = metadataControls(); if (m.load.disabled) return {state:'wait'};
            if (text(m.load) !== 'Load public text' || !m.validate.disabled || m.editor.querySelector('.metadata-text-fields, .metadata-validation-status')) return {state:'error'};
            m.load.scrollIntoView({block:'center'}); if (!visible(m.load)) return {state:'error'};
            m.load.click(); return {state:'ready'};"#,
        Step::ReadMetadata => r#"
            const m = metadataControls();
            if (!m.editor.querySelector('.metadata-text-fields') || m.load.disabled || m.validate.disabled) return {state:'wait'};
            return {state:'ready', display:metadataDisplay(m)};"#,
        Step::EnterTitle => r#"
            return insertMetadataText(0, 'Public title', ['', '', '']);"#,
        Step::EnterShortDescription => r#"
            return insertMetadataText(1, 'Public summary', ['Public title', '', '']);"#,
        Step::EnterFullDescription => r#"
            return insertMetadataText(2, 'Public description', ['Public title', 'Public summary', '']);"#,
        Step::ReadMetadataInputs => r#"
            const m = metadataControls(); if (m.load.disabled || m.validate.disabled) return {state:'wait'};
            if (m.editor.querySelector('.metadata-validation-status')) return {state:'error'};
            return {state:'ready', display:metadataDisplay(m)};"#,
        Step::ValidateMetadata => r#"
            const m = metadataControls(), rows = metadataRows(m);
            if (m.load.disabled || m.validate.disabled || text(m.load) !== 'Refresh text' || text(m.validate) !== 'Validate text'
                || m.editor.querySelector('.metadata-validation-status')
                || rows.some((row, index) => row.input.value !== ['Public title','Public summary','Public description'][index])) return {state:'error'};
            m.validate.scrollIntoView({block:'center'}); if (!visible(m.validate)) return {state:'error'};
            m.validate.click(); return {state:'ready'};"#,
        Step::ReadMetadataValidation => r#"
            const m = metadataControls();
            if (m.load.disabled || m.validate.disabled || !m.editor.querySelector('.metadata-validation-status')) return {state:'wait'};
            return {state:'ready', display:metadataDisplay(m)};"#,
        Step::ReadSavedDraft | Step::ReadCandidateDraft => r#"
            if (!selected('Project settings') || !field() || !document.querySelector('.draft-banner')) return {state:'wait'};
            const draft = draftState(); if (!draft.saved || !draft.saveAvailable) return {state:'wait'};
            return {state:'ready', source:sourceValue(), ...draft, staleSnapshot:staleSettings()};"#,
        Step::Artifacts => r#"
            const b = document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Artifacts"]');
            if (!b || b.disabled) return {state:'error'}; b.click(); return {state:'ready'};"#,
        Step::ReadEvidenceEmpty => r#"
            if (!selected('Artifacts') || !document.querySelector('#evidence-start-reason')) return {state:'wait'};
            const c = evidenceControls(); if (!evidenceReady(c)) return {state:'wait'};
            return {state:'ready', display:evidenceDisplay(c, false)};"#,
        Step::ChooseEvidenceCancel | Step::ChooseEvidenceSelect => r#"
            const c = evidenceControls(); if (!evidenceReady(c)) return {state:'wait'};
            c.choose.scrollIntoView({block:'center'}); if (!visible(c.choose)) return {state:'error'};
            c.choose.click(); return {state:'ready'};"#,
        Step::ReadEvidenceCancelled => r#"
            const c = evidenceControls(); if (!evidenceReady(c)
                || ![...c.status.querySelectorAll(':scope > p')].some(p => text(p) === 'Original operation cancelled and settled. No new result was accepted.')) return {state:'wait'};
            return {state:'ready', display:evidenceDisplay(c, false)};"#,
        Step::ReadEvidenceSelected => r#"
            const c = evidenceControls(); if (!evidenceReady(c) || c.inspect.disabled) return {state:'wait'};
            return {state:'ready', display:evidenceDisplay(c, false)};"#,
        Step::InspectEvidence => r#"
            const c = evidenceControls(); if (!evidenceReady(c) || c.inspect.disabled) return {state:'wait'};
            c.inspect.scrollIntoView({block:'center'}); if (!visible(c.inspect)) return {state:'error'};
            c.inspect.click(); return {state:'ready'};"#,
        Step::ReadEvidenceObserved => r#"
            const c = evidenceControls(); if (!evidenceReady(c) || c.inspect.disabled
                || text(c.result.querySelector('h2')) !== 'Documents agree') return {state:'wait'};
            return {state:'ready', display:evidenceDisplay(c, true)};"#,
        _ => return None,
    };
    Some(format!(r#"(() => {{ try {{
        if (document.querySelector('.preview-banner, .fatal-error, #main-content > .notice-danger, .native-save-panel .notice-danger')) return {{state:'error'}};
        const text = e => {{ if (!e) throw 0; const t=e.textContent; if (typeof t!=='string' || t.length>4096) throw 0; return t; }};
        const visible = e => {{ const r=e.getBoundingClientRect(), s=getComputedStyle(e); return e.isConnected && r.width>0 && r.height>0 && s.display!=='none' && s.visibility==='visible'; }};
        const selected = label => [...document.querySelectorAll('nav[aria-label="Workspace navigation"] button[aria-current="page"]')].some(b => b.getAttribute('aria-label')===label);
        const evidenceControls = () => {{
            const reasons=document.querySelectorAll('#evidence-start-reason');
            if (!selected('Artifacts') || reasons.length!==1 || document.querySelector('dialog')) throw 0;
            const reason=reasons[0], folder=reason.closest('section.card'), result=folder?.nextElementSibling;
            const warning=folder?.previousElementSibling, heading=warning?.previousElementSibling;
            if (!folder || !result?.matches('section.card') || !warning?.matches('.notice.notice-warning') || !heading?.matches('.page-heading')
                || folder.querySelector('.notice-danger') || result.querySelector('details, dialog, a, input, textarea, select, [role="alert"]')
                || text(heading.querySelector('.eyebrow'))!=='ARTIFACTS') throw 0;
            const buttons=[...folder.querySelectorAll(':scope > .button-row > button')];
            const statuses=folder.querySelectorAll(':scope > [role="status"][aria-live="polite"]');
            if (buttons.length<3 || buttons.length>4 || statuses.length!==1 || text(buttons[0])!=='Choose evidence folder' || text(buttons[1])!=='Inspect documents'
                || buttons.slice(0,2).some(b => b.type!=='button' || b.getAttribute('aria-describedby')!=='evidence-start-reason')) throw 0;
            return {{reason,folder,result,warning,heading,buttons,choose:buttons[0],inspect:buttons[1],check:buttons[2],status:statuses[0]}};
        }};
        const evidenceReady = c => !c.choose.disabled && !c.check.disabled && text(c.check)==='Check operation status';
        const evidenceDisplay = (c, observed) => {{
            const show=e => {{ e.scrollIntoView({{block:'center'}}); if (!visible(e)) throw 0; }};
            const paragraphs=[...c.folder.querySelectorAll(':scope > p')], folderHelp=c.folder.querySelector('.section-heading > .help-button');
            if (c.buttons.length!==3 || paragraphs.length!==3 || paragraphs[2]!==c.reason || !folderHelp || folderHelp.disabled
                || folderHelp.getAttribute('aria-label')!=='Help: Evidence folder') throw 0;
            for (const element of [c.heading,c.warning,...paragraphs,...c.buttons,folderHelp]) show(element);
            const context={{heading:text(c.heading.querySelector('h1')),description:text(c.heading.querySelector('p')),
                assurance:[text(c.warning.querySelector('strong')),text(c.warning.querySelector('p'))],
                folder:{{heading:text(c.folder.querySelector('.section-heading h2')),description:text(c.folder.querySelector('.section-heading p')),
                    source:text(paragraphs[0]),selection:text(paragraphs[1]),buttons:c.buttons.map(b => [text(b),!b.disabled]),reason:text(c.reason),
                    status:[...c.status.querySelectorAll(':scope > p')].map(p => {{ show(p); return text(p); }})}}}};
            if (!observed) {{
                if (c.result.children.length!==1 || !c.result.firstElementChild.matches('.section-heading')) throw 0;
                show(c.result); return {{context,result:{{heading:text(c.result.querySelector('h2')),description:text(c.result.querySelector('p'))}}}};
            }}
            const headings=[...c.result.querySelectorAll(':scope > .section-heading')], lists=[...c.result.querySelectorAll(':scope > ul.plain-list')];
            const definitions=[...c.result.querySelectorAll(':scope > dl.help-definitions')];
            if (c.result.children.length!==10 || headings.length!==5 || lists.length!==2 || definitions.length!==3
                || c.result.querySelectorAll('button').length!==4 || lists.some(list => list.children.length!==3)) throw 0;
            const projectedHeadings=headings.map((row,index) => {{
                show(row); const badges=[...row.querySelectorAll(':scope > .badge')], helps=[...row.querySelectorAll(':scope > .help-button')];
                if (badges.length!==(index===0?1:0) || helps.length!==(index===0?0:1) || helps.some(b => b.disabled)) throw 0;
                return [text(row.querySelector('h2')),text(row.querySelector('p')),badges.length?text(badges[0]):null,helps.length?helps[0].getAttribute('aria-label'):null];
            }});
            const documents=[...lists[0].children].map(row => {{ show(row);
                if (row.tagName!=='LI' || row.children.length!==2) throw 0;
                return [text(row.querySelector(':scope > code')),text(row.querySelector(':scope > .badge'))]; }});
            const artifacts=[...lists[1].children].map(row => {{ show(row); const paragraphs=[...row.querySelectorAll(':scope > div > p')];
                if (row.tagName!=='LI' || row.children.length!==1 || paragraphs.length!==2) throw 0;
                return [text(row.querySelector('strong')),...paragraphs.map(text)]; }});
            const dl=(root,count) => {{ const rows=[...root.querySelectorAll(':scope > div')]; if (rows.length!==count) throw 0;
                return rows.map(row => {{ show(row); if (row.children.length!==2) throw 0;
                    return [text(row.querySelector(':scope > dt')),text(row.querySelector(':scope > dd'))]; }}); }};
            return {{context,result:{{headings:projectedHeadings,documents,identity:dl(definitions[0],5),artifacts,runs:dl(definitions[1],3),digests:dl(definitions[2],3)}}}};
        }};
        const githubInputs = () => {{
            const forms=document.querySelectorAll('form.github-form');
            if (!selected('GitHub') || forms.length!==1 || document.querySelector('dialog, .github-assertions')) throw 0;
            const form=forms[0], repositories=form.querySelectorAll('input#github-toolkit-repository'), shas=form.querySelectorAll('input#github-toolkit-sha');
            const comparison=form.querySelector('.github-comparison-toggle input[type="checkbox"]'), button=form.querySelector('.github-propose-action button[type="submit"]');
            if (repositories.length!==1 || shas.length!==1 || !comparison || !button) throw 0;
            const repository=repositories[0], sha=shas[0];
            if ([repository,sha].some(input => input.type!=='text' || input.disabled || input.readOnly) || repository.value.length>140 || sha.value.length>40) throw 0;
            return {{form,repository,sha,comparison,button}};
        }};
        const inputValues = g => ({{repository:g.repository.value,sha:g.sha.value,comparison:g.comparison.checked,previewAvailable:!g.button.disabled}});
        const metadataControls = () => {{
            const editors=document.querySelectorAll('.metadata-text-editor');
            if (!selected('Metadata') || editors.length!==1 || document.querySelector('dialog, .metadata-native-review, .metadata-latest-observation')) throw 0;
            const editor=editors[0]; if (editor.querySelector('.notice-danger, .notice-warning, .review-caution, .issues')) throw 0;
            const contexts=editor.querySelectorAll('.metadata-context-row select'), loads=editor.querySelectorAll('.metadata-context-row > button.button.secondary');
            const validations=editor.querySelectorAll('.metadata-text-actions > button.button.secondary'), reviews=editor.querySelectorAll('.metadata-text-actions > button.button.primary');
            if (contexts.length!==1 || loads.length!==1 || validations.length!==1 || reviews.length!==1) throw 0;
            const context=contexts[0], load=loads[0], validate=validations[0], review=reviews[0];
            if (context.disabled || !context.value || context.selectedOptions.length!==1 || text(context.selectedOptions[0])!=='android / en-US'
                || context.selectedOptions[0].parentElement?.getAttribute('label')!=='Current saved configuration'
                || !review.disabled || text(review)!=='Review changes') throw 0;
            return {{editor,context,load,validate,review}};
        }};
        const metadataRows = m => {{
            const rows=[...m.editor.querySelectorAll('.metadata-text-fields > .metadata-text-field')]; if (rows.length!==3) throw 0;
            return rows.map((row, index) => {{
                const codes=row.querySelectorAll(':scope > code'), inputs=row.querySelectorAll(':scope > textarea');
                if (codes.length!==1 || inputs.length!==1) throw 0;
                const path=text(codes[0]), id=['title.txt','short_description.txt','full_description.txt'][index], input=inputs[0];
                if (path!=='release/store/android/en-US/'+id || input.disabled || input.readOnly || input.value.length>32768
                    || !input.id || row.querySelector('.inline-heading label')?.getAttribute('for')!==input.id) throw 0;
                return {{row,id,path,input}};
            }});
        }};
        const metadataCount = element => {{
            const match=/^(No core character count yet — use Validate text\.|Core count: (.+) \/ (.+) Unicode characters) · (.+) UTF-8 bytes of the 32 KiB editor budget\. No original bytes\.$/.exec(text(element));
            if (!match) throw 0;
            // Parse only displayed numbers, then require the browser's actual
            // locale rendering (including the 4,000 grouping), not loose digits.
            const number = shown => {{ const value=Number(shown.replace(/[^0-9]/g,''));
                if (!Number.isSafeInteger(value) || value.toLocaleString()!==shown) throw 0; return value; }};
            return {{characterCount:match[2]===undefined?null:number(match[2]), limit:match[3]===undefined?null:number(match[3]), bytes:number(match[4])}};
        }};
        const metadataDisplay = m => {{
            if (text(m.validate)!=='Validate text') throw 0;
            const statuses=m.editor.querySelectorAll('.metadata-validation-status'); if (statuses.length>1) throw 0;
            const fields=metadataRows(m).map(item => {{
                item.row.scrollIntoView({{block:'center'}}); if (!visible(item.row) || !visible(item.input)) throw 0;
                const badges=[...item.row.querySelectorAll('.inline-heading .badge')]; if (badges.length!==2) throw 0;
                return {{id:item.id,path:item.path,text:item.input.value,badges:badges.map(text),count:metadataCount(item.row.querySelector('.metadata-count')),
                    invalid:item.input.getAttribute('aria-invalid')}};
            }});
            if (statuses.length) {{ statuses[0].scrollIntoView({{block:'center'}}); if (!visible(statuses[0])) throw 0; }}
            return {{context:text(m.context.selectedOptions[0]),badge:text(m.editor.querySelector('.section-heading .badge')),fields,
                loadLabel:text(m.load),loadAvailable:!m.load.disabled,validateAvailable:!m.validate.disabled,reviewAvailable:!m.review.disabled,
                validation:statuses.length?{{badge:text(statuses[0].querySelector('.badge')),text:text(statuses[0])}}:null}};
        }};
        const insertMetadataText = (index, replacement, before) => {{
            const m=metadataControls(), rows=metadataRows(m);
            if (m.load.disabled || m.validate.disabled || text(m.load)!=='Refresh text' || text(m.validate)!=='Validate text'
                || m.editor.querySelector('.metadata-validation-status') || rows.some((row, offset) => row.input.value!==before[offset])) throw 0;
            const input=rows[index].input; input.scrollIntoView({{block:'center'}}); if (!visible(input)) throw 0;
            input.focus(); input.select();
            if (document.activeElement!==input || input.selectionStart!==0 || input.selectionEnd!==0
                || !document.execCommand('insertText', false, replacement)) throw 0;
            return {{state:'ready'}};
        }};
        const field = () => [...document.querySelectorAll('.form-field')].find(f => f.querySelector('.help-button')?.getAttribute('aria-label')==='Help: Committed version file');
        const sourceValue = () => {{
            const f=field(); if (!f || document.querySelector('.suggestion-card') || text(f.querySelector('.field-presence'))!=='Set') throw 0;
            f.scrollIntoView({{block:'center'}}); const input=f.querySelector('input');
            if (!visible(f) || !input || input.value.length>512) throw 0; return input.value;
        }};
        const draftState = () => {{
            const banner=document.querySelector('.draft-banner'), save=document.querySelector('.draft-toolbar button[aria-describedby="draft-save-reason"]');
            if (!banner || !save || !selected('Project settings') || document.querySelector('dialog')) throw 0;
            const badge=text(banner.querySelector('.badge'));
            return {{unsaved:badge==='Unsaved changes', saved:badge==='Settled submitted revision'
                && text(banner.querySelector('strong'))==='The submitted revision was saved'
                && text(document.querySelector('.draft-toolbar-status .badge'))==='Saved revision · not verified', saveAvailable:!save.disabled}};
        }};
        const staleSettings = () => [...document.querySelectorAll('.context-refresh-note')].some(e => text(e).startsWith('The latest static observation predates the last settled native save check.'));
        const inventory = root => {{
            const tables=root.querySelectorAll('.save-files table'); if (tables.length!==1) throw 0;
            const table=tables[0]; if (text(table.querySelector('caption'))!=='Exact native destination inventory') throw 0;
            table.scrollIntoView({{block:'center'}}); if (!visible(table)) throw 0;
            const rows=[...table.querySelectorAll('tbody > tr')]; if (rows.length!==2) throw 0;
            const actions={{'Create':'create','Replace document':'replace','Append fixed rules':'append','Preserve original':'preserve'}};
            const bytes=(value, absent) => {{ if (absent && value==='Observed absent') return null;
                const match=/^([0-9]{{1,7}}) bytes$/.exec(value); if (!match) throw 0; return Number(match[1]); }};
            return rows.map(row => {{ const cells=[...row.querySelectorAll(':scope > td')]; if (cells.length!==3) throw 0;
                const action=actions[text(cells[0])]; if (!action) throw 0;
                return {{path:text(row.querySelector(':scope > th code')),action,beforeBytes:bytes(text(cells[1]),true),afterBytes:bytes(text(cells[2]),false)}};
            }});
        }};
        const reviewDisplay = review => {{
            const files=inventory(review), ignore=[...review.querySelectorAll('.save-ignore li code')]; if (ignore.length>7) throw 0;
            for (const line of ignore) {{ line.scrollIntoView({{block:'center'}}); if (!visible(line)) throw 0; }}
            const counts=[...review.querySelectorAll('.review-counts > span > strong')].map(e => {{ const t=text(e); if (!/^[0-9]{{1,2}}$/.test(t)) throw 0; return Number(t); }});
            if (counts.length!==3) throw 0;
            return {{files,release:[...review.querySelectorAll(':scope > .save-note code')].some(e => text(e)==='release'),
                rewrite:!!review.querySelector(':scope > .notice-warning'),ignore:ignore.map(text),counts:{{added:counts[0],changed:counts[1],removed:counts[2]}},
                basis:text(review.querySelector('.review-basis strong')),badge:text(review.querySelector('.review-counts .badge'))}};
        }};
        const confirmationControls = () => {{
            const dialogs=document.querySelectorAll('dialog'); if (!selected('Project settings') || dialogs.length!==1) throw 0;
            const dialog=dialogs[0]; if (!dialog.classList.contains('save-confirm-dialog') || !dialog.open || !visible(dialog) || dialog.querySelector('[role="alert"]')) throw 0;
            const choices=dialog.querySelectorAll('.save-confirm-choice input[type="checkbox"]'), buttons=[...dialog.querySelectorAll('.button-row > button')];
            if (choices.length!==1 || choices[0].disabled || buttons.length!==2 || buttons[0].disabled
                || text(buttons[0])!=='Keep reviewing' || text(buttons[1])!=='Apply reviewed save'
                || text(dialog.querySelector('.save-confirm-choice'))!=='I reviewed this exact inventory and understand that cancellation may be too late after Apply.') throw 0;
            return {{dialog,check:choices[0],keep:buttons[0],apply:buttons[1]}};
        }};
        const confirmationDisplay = () => {{
            const c=confirmationControls(), paragraphs=[...c.dialog.querySelectorAll('.dialog-content > p')];
            const revision=/^This confirms submitted draft revision ([0-9]{{1,10}}), not any later edits\. /.exec(text(paragraphs[0]));
            const paths=c.dialog.querySelectorAll('.save-project-path code'); if (!revision || paths.length!==1) throw 0;
            return {{title:text(c.dialog.querySelector('h2')),projectPath:text(paths[0]),draftRevision:Number(revision[1]),files:inventory(c.dialog),
                release:paragraphs.some(p => text(p)==='The missing release directory is included.'),rewrite:!!c.dialog.querySelector('.review-caution'),
                checked:c.check.checked,applyAvailable:!c.apply.disabled}};
        }};
        {body}
    }} catch {{ return {{state:'error'}}; }} }})()"#))
}

fn assert_recent_files_suppression_contract() {
    use super::{requires_recent_files_suppression, DialogChoice};
    use crate::credential_format::FileKind;

    // Exercise the production branch without inheriting global GTK settings
    // from an earlier Project picker, which could mask an EvidenceFolder omission.
    assert!(requires_recent_files_suppression(DialogChoice::File(FileKind::AndroidKeystore)));
    assert!(requires_recent_files_suppression(DialogChoice::File(FileKind::AndroidFirebase)));
    assert!(requires_recent_files_suppression(DialogChoice::Project));
    assert!(requires_recent_files_suppression(DialogChoice::EvidenceFolder));
    for field in [crate::asset_commands::ProjectPathField::VersionSource, crate::asset_commands::ProjectPathField::IosProject,
                  crate::asset_commands::ProjectPathField::IosWorkspace, crate::asset_commands::ProjectPathField::MetadataRoot] {
        assert!(requires_recent_files_suppression(DialogChoice::ProjectPath(field)));
    }
    assert!(!requires_recent_files_suppression(DialogChoice::Quit));
}

fn route() -> bool {
    let Some(source) = option_env!("GITHUB_SHA") else { return false; };
    source.len() == 40 && source.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && [("GITHUB_ACTIONS", "true"), ("RUNNER_ENVIRONMENT", "github-hosted"),
            ("MRK_DESKTOP_HOSTED_CHECKS", "installed-shell-connection-v1"), ("GITHUB_SHA", source)]
            .iter().all(|(key, value)| std::env::var(key).ok().as_deref() == Some(*value))
        && rustix::process::getuid().as_raw() != 0 && rustix::process::getuid() == rustix::process::geteuid()
}
pub(crate) fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os().skip(1);
    let case = match args.next().as_deref() {
        Some(value) if value == OsStr::new("positive") => Some(Case::Positive),
        Some(value) if value == OsStr::new("quit-outstanding") => Some(Case::Outstanding),
        Some(value) if value == OsStr::new("project-paths") => Some(Case::ProjectPaths),
        _ => None,
    };
    let Some(case) = case.filter(|_| args.next().is_none() && route()) else {
        super::diagnostic(b"MRK_INSTALLED_SHELL_OBSERVATION=route-refused\n");
        return std::process::ExitCode::FAILURE;
    };
    let Some(failure_sink) = failure_sink(case) else {
        super::diagnostic(b"MRK_INSTALLED_SHELL_OBSERVATION=route-refused\n");
        return std::process::ExitCode::FAILURE;
    };
    let q = Arc::new(Observation::new(case, failure_sink));
    // This target has no libtest harness. Execute the existing pure contracts
    // and positive configuration-domain contracts before GTK; a failed
    // assertion cannot reach the success report.
    crate::bridge::assert_native_capability_intersection_contract();
    crate::runtime::assert_packaged_shell_allowlist_contract();
    assert_recent_files_suppression_contract();
    assert_failure_pair_contract();
    if case == Case::Positive {
        crate::asset_session::assert_project_selection_gate_contract();
        crate::asset_session::assert_installed_evidence_gate_contract();
        crate::candidate_evidence_protocol::assert_candidate_wire_contract();
        crate::runtime::assert_installed_configuration_profile_contract();
        crate::installed_runtime::assert_installed_configuration_slots_contract();
        crate::edit_owner::assert_installed_configuration_owner_contract();
    }
    if case == Case::ProjectPaths {
        crate::asset_commands::assert_project_path_command_contracts();
        crate::asset_commands::assert_project_path_wiring_contract();
        crate::asset_source::assert_project_path_source_contracts();
        crate::asset_session::assert_project_path_document_contracts();
        crate::bridge::assert_project_path_availability_contract();
    }
    // Routing DATA is not native admission. The ordinary builder constructs
    // DesktopBridge::new / RuntimeConfig::packaged and owes every real check.
    let returned = super::run_builder(super::builder().manage(q.clone()));
    if !matches!(returned, Ok(0)) || !q.finish() {
        q.fail(); q.report_failure();
        super::diagnostic(b"MRK_INSTALLED_SHELL_OBSERVATION=failed\n");
        return std::process::ExitCode::FAILURE;
    }
    let line: &[u8] = match case {
        Case::Positive => b"MRK_INSTALLED_SHELL_OBSERVATION=positive-verified\n",
        Case::Outstanding => b"MRK_INSTALLED_SHELL_OBSERVATION=quit-outstanding-verified\n",
        Case::ProjectPaths => b"MRK_INSTALLED_SHELL_OBSERVATION=project-paths-verified\n",
    };
    let mut stdout = std::io::stdout().lock();
    if stdout.write_all(b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n")
        .and_then(|_| {
            if case == Case::ProjectPaths {
                let report = q.paths_report().ok_or_else(|| std::io::Error::other("project paths receipt unavailable"))?;
                stdout.write_all(b"MRK_INSTALLED_SHELL_PROJECT_PATHS=")?;
                stdout.write_all(&report)?; return stdout.write_all(b"\n");
            }
            if case != Case::Positive { return Ok(()); }
            let report = q.positive_report().ok_or_else(|| std::io::Error::other("positive receipt unavailable"))?;
            stdout.write_all(b"MRK_INSTALLED_SHELL_PROJECT_DRAFT=")?;
            stdout.write_all(&report)?; stdout.write_all(b"\n")
        })
        .and_then(|_| {
            if case != Case::Positive { return Ok(()); }
            let report = q.candidate_report().ok_or_else(|| std::io::Error::other("candidate receipt unavailable"))?;
            stdout.write_all(b"MRK_INSTALLED_SHELL_CANDIDATE_DOCUMENTS=")?;
            stdout.write_all(&report)?; stdout.write_all(b"\n")
        })
        .and_then(|_| stdout.write_all(line)).is_ok() { std::process::ExitCode::SUCCESS } else { std::process::ExitCode::FAILURE }
}
