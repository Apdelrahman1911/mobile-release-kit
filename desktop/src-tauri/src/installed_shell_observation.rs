//! Bounded observations of the NORMAL builder/bridge/packaged selector.
//! No alternate runtime, document, IPC command, timer, task or shutdown owner.
//! Only the existing relay drives these steps; failures cannot authorize exit.
use std::{ffi::OsStr, io::Write, path::{Path, PathBuf}, sync::{Arc, Mutex, MutexGuard, atomic::{AtomicBool, AtomicU32, Ordering}},
    thread::ThreadId, time::{Duration, Instant}};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tauri::Manager;
use crate::{asset_session::{InstalledEvidenceWitness, InstalledProjectWitness, InstalledSessionSnapshot, InstalledSessionFailure}, bridge::{AppInfo, Project},
    candidate_evidence_protocol as evidence, credential_assessment::InstalledAssessmentFailure,
    edit_owner::{EditOwner, InstalledConfigFinality, InstalledWorkflowFinality, InstalledMetadataFinality, InstalledVersionFinality},
    github_workflow_edit_protocol as workflow, metadata_text_edit_protocol as metadata, release_version_edit_protocol as version,
    edit_protocol::{self as edit, ConfigEditStatus, EditProjection}, error::BridgeError, supervisor::{HeldAppInfo, Supervisor}};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case { Positive, Outstanding, ProjectPaths, WorkflowApply, Session(SessionCase), MetadataSave, VersionSave, Commands(commands::Case), SettledFailure }
#[path = "installed_tools_observation.rs"]
pub(crate) mod commands;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionCase { Inputs, Refusals, Loss, Deadline }
impl SessionCase {
    fn name(self) -> &'static str { match self { Self::Inputs => "session-inputs", Self::Refusals => "session-refusals", Self::Loss => "session-loss", Self::Deadline => "session-deadline" } }
    fn assessments(self) -> usize { match self { Self::Inputs => 7, Self::Refusals => 6, _ => 1 } }
}
impl Case {
    fn session(self) -> Option<SessionCase> { match self { Self::Session(case) => Some(case), _ => None } }
    fn commands(self) -> Option<commands::Case> { match self { Self::Commands(case) => Some(case), _ => None } }
}
// A moved, private, one-use setup token, never renderer/environment authority.
pub(crate) struct SessionAdmission { original: std::sync::Weak<Observation>, case: SessionCase }
impl SessionAdmission {
    pub(crate) fn consume(self) -> Result<SessionCase, BridgeError> {
        let original = self.original.upgrade().ok_or_else(BridgeError::invalid)?;
        let mut r = original.record().ok_or_else(BridgeError::cleanup_unknown)?;
        if original.failed.load(Ordering::SeqCst) || !route() || original.case != Case::Session(self.case)
            || !r.attached || r.started || !r.session.admission_issued || r.session.admitted { return Err(BridgeError::invalid()); }
        r.session.admitted = true; Ok(self.case)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Bootstrap, Environment, ReadEnvironment, Dashboard, ChooseCancel, Cancel, Cancelled, ReadCancelled, SettledFailure,
    ChooseSelect, SetProject, SelectProject, Selected, ReadSnapshot, Settings, Suggest, ReadSuggestion, Adopt, ReadDraft,
    GuidanceEnvironment, LoadRequirements, ReadRequirements, GitHub, ReadGitHubEmpty, EnterRepository, EnterSha,
    ReadGitHubInputs, ProposeGitHub, ReadProposal, OpenWorkflows, ReadWorkflows, GuidanceSettings, ReadRetainedDraft,
    PrepareSave, ReadSaveReview, OpenConfirmation, ReadConfirmation, KeepReviewing, ReadKeptReview,
    ReopenConfirmation, ReadReopenedConfirmation, Acknowledge, ReadAcknowledged, Apply, ReadSaved,
    SavedDashboard, Refresh, ReadReadback, ReadVersion, ReadVersionCard, Metadata, LoadMetadata, ReadMetadata,
    EnterTitle, EnterShortDescription, EnterFullDescription, ReadMetadataInputs, ValidateMetadata, ReadMetadataValidation,
    SavedSettings, ReadSavedDraft, Artifacts, ReadEvidenceEmpty, ChooseEvidenceCancel, CancelEvidence, EvidenceCancelled, ReadEvidenceCancelled,
    ChooseEvidenceSelect, SetEvidence, SelectEvidence, EvidenceSelected, ReadEvidenceSelected, InspectEvidence, EvidenceObserved, ReadEvidenceObserved,
    CandidateSettings, ReadCandidateDraft, PrepareNoop, ReadNoopReview, Close, Quit, Exit, Paths(PathStep), Workflow(WorkflowStep), Session(SessionStep), MetadataSave(MetadataStep), VersionSave(VersionStep), Commands(commands::Step),
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
            Self::SettledFailure => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SettledFailure\n",
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
            Self::Workflow(step) => step.failure_line(),
            Self::Session(step) => step.failure_line(),
            Self::MetadataSave(step) => step.failure_line(),
            Self::VersionSave(step) => step.failure_line(),
            Self::Commands(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=ToolsOffline\n",
        }
    }
}


#[derive(Clone, Copy, PartialEq, Eq)]
enum VersionStep {
    Open(u8), ReadOpen(u8), Name(u8), Build(u8), ReadInputs(u8), Review(u8), ReadReview(u8),
    Confirm(u8), ReadConfirmation(u8), Check(u8), ReadChecked(u8), Type(u8), ReadTyped(u8),
    Apply(u8), ReadSaved(u8), Readback(u8), ReadReadback(u8),
}
impl VersionStep {
    fn index(self) -> usize { usize::from(match self {
        Self::Open(i) | Self::ReadOpen(i) | Self::Name(i) | Self::Build(i) | Self::ReadInputs(i)
        | Self::Review(i) | Self::ReadReview(i) | Self::Confirm(i) | Self::ReadConfirmation(i)
        | Self::Check(i) | Self::ReadChecked(i) | Self::Type(i) | Self::ReadTyped(i)
        | Self::Apply(i) | Self::ReadSaved(i) | Self::Readback(i) | Self::ReadReadback(i) => i,
    }) }
    fn failure_line(self) -> &'static [u8] { match self {
        Self::Open(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=VersionOpen\n",
        Self::ReadOpen(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=VersionReadOpen\n",
        Self::Name(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=VersionName\n",
        Self::Build(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=VersionBuild\n",
        Self::ReadInputs(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=VersionReadInputs\n",
        Self::Review(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=VersionReview\n",
        Self::ReadReview(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=VersionReadReview\n",
        Self::Confirm(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=VersionConfirm\n",
        Self::ReadConfirmation(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=VersionReadConfirmation\n",
        Self::Check(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=VersionCheck\n",
        Self::ReadChecked(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=VersionReadChecked\n",
        Self::Type(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=VersionType\n",
        Self::ReadTyped(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=VersionReadTyped\n",
        Self::Apply(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=VersionApply\n",
        Self::ReadSaved(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=VersionReadSaved\n",
        Self::Readback(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=VersionReadback\n",
        Self::ReadReadback(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=VersionReadReadback\n",
    } }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MetadataStep {
    Navigate, Load, ReadLoaded, Short, Full, ReadInputs, Validate, ReadValidation,
    Review(u8), OpenText(u8), ReadReview(u8), CloseReview, ReadClosed,
    Confirm, ReadConfirmation, Check, ReadChecked, Type, ReadTyped, Apply, ReadSaved,
    Refresh, ReadReadback,
}
impl MetadataStep {
    fn failure_line(self) -> &'static [u8] {
        match self {
            Self::Navigate => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataNavigate\n",
            Self::Load => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataLoad\n",
            Self::ReadLoaded => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataReadLoaded\n",
            Self::Short => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataShort\n",
            Self::Full => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataFull\n",
            Self::ReadInputs => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataReadInputs\n",
            Self::Validate => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataValidate\n",
            Self::ReadValidation => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataReadValidation\n",
            Self::Review(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataReview\n",
            Self::OpenText(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataOpenText\n",
            Self::ReadReview(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataReadReview\n",
            Self::CloseReview => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataCloseReview\n",
            Self::ReadClosed => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataReadClosed\n",
            Self::Confirm => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataConfirm\n",
            Self::ReadConfirmation => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataReadConfirmation\n",
            Self::Check => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataCheck\n",
            Self::ReadChecked => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataReadChecked\n",
            Self::Type => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataType\n",
            Self::ReadTyped => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataReadTyped\n",
            Self::Apply => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataApply\n",
            Self::ReadSaved => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataReadSaved\n",
            Self::Refresh => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataRefresh\n",
            Self::ReadReadback => b"MRK_INSTALLED_SHELL_FAILURE_STEP=MetadataReadReadback\n",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WorkflowStep {
    GitHub(u8), Pin(u8), ReadPin(u8), Start(u8), OpenText(u8), ReadReview(u8),
    Confirm(u8), ReadConfirmation(u8), Keep, ReadKept, Reconfirm, ReadReconfirmation,
    Acknowledge(u8), ReadAcknowledged(u8), Apply(u8), ReadResult(u8), Settings(u8), ReadDraft(u8),
}
impl WorkflowStep {
    fn failure_line(self) -> &'static [u8] {
        match self {
            Self::GitHub(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=WorkflowGitHub\n",
            Self::Pin(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=WorkflowPin\n",
            Self::ReadPin(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=WorkflowReadPin\n",
            Self::Start(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=WorkflowStart\n",
            Self::OpenText(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=WorkflowOpenText\n",
            Self::ReadReview(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=WorkflowReadReview\n",
            Self::Confirm(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=WorkflowConfirm\n",
            Self::ReadConfirmation(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=WorkflowReadConfirmation\n",
            Self::Keep => b"MRK_INSTALLED_SHELL_FAILURE_STEP=WorkflowKeep\n",
            Self::ReadKept => b"MRK_INSTALLED_SHELL_FAILURE_STEP=WorkflowReadKept\n",
            Self::Reconfirm => b"MRK_INSTALLED_SHELL_FAILURE_STEP=WorkflowReconfirm\n",
            Self::ReadReconfirmation => b"MRK_INSTALLED_SHELL_FAILURE_STEP=WorkflowReadReconfirmation\n",
            Self::Acknowledge(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=WorkflowAcknowledge\n",
            Self::ReadAcknowledged(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=WorkflowReadAcknowledged\n",
            Self::Apply(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=WorkflowApply\n",
            Self::ReadResult(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=WorkflowReadResult\n",
            Self::Settings(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=WorkflowSettings\n",
            Self::ReadDraft(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=WorkflowReadDraft\n",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pending { Dom(Step), Project(Step), Evidence(Step), Path(PathStep), Session(SessionStep), Close, Gtk }

// A fixed recipe, not a second controller: each action uses the rendered
// control and each read compares the actual original's safe projection.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionAction {
    Open, Kind(&'static str), Platform(&'static str), Replacement(u8),
    Choose(&'static str, &'static str, Option<&'static str>), Fields(&'static str),
    Prepare(&'static str, &'static str), Reassess(u8, &'static str), Keep, Assign,
    ReviewRemoval(u8), Remove, Remember(&'static str), Stale(&'static str),
    CancelOperation, Discard, ConfirmDiscard, QuitCancel, Held,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionStep { Navigate, Run(u8, SessionAction), Read(u8, SessionAction), SetFile(u8), ActivateFile(u8), Capture(u8),
    QuitCancel, QuitPreserved, Reload, Loss, Deadline, Finality }
impl SessionStep {
    fn recipe_index(self) -> Option<u8> {
        match self {
            Self::Run(index,_) | Self::Read(index,_) | Self::SetFile(index) | Self::ActivateFile(index) | Self::Capture(index) => Some(index),
            _ => None,
        }
    }
    fn failure_line(self) -> &'static [u8] {
        match self {
            Self::Navigate => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionNavigate\n",
            Self::Run(_,SessionAction::Open) | Self::Read(_,SessionAction::Open) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionOpen\n",
            Self::Run(_,SessionAction::Platform(_)) | Self::Read(_,SessionAction::Platform(_)) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionContext\n",
            Self::Run(_,SessionAction::Kind(_) | SessionAction::Replacement(_)) | Self::Read(_,SessionAction::Kind(_) | SessionAction::Replacement(_)) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionConfigure\n",
            Self::Run(_,SessionAction::Choose(..)) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionChoose\n",
            Self::SetFile(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionSetFile\n",
            Self::ActivateFile(_) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionActivateFile\n",
            Self::Capture(_) | Self::Read(_,SessionAction::Choose(..)) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionCapture\n",
            Self::Run(_,SessionAction::Fields(_)) | Self::Read(_,SessionAction::Fields(_)) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionFields\n",
            Self::Run(_,SessionAction::Prepare(..) | SessionAction::Reassess(..)) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionPrepare\n",
            Self::Read(_,SessionAction::Prepare(..) | SessionAction::Reassess(..) | SessionAction::ReviewRemoval(_)) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionReview\n",
            Self::Run(_,SessionAction::Keep) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionKeep\n",
            Self::Run(_,SessionAction::Assign) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionAssign\n",
            Self::Read(_,SessionAction::Keep | SessionAction::Assign | SessionAction::Remove) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionRecord\n",
            Self::Run(_,SessionAction::ReviewRemoval(_) | SessionAction::Remove) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionRemove\n",
            Self::Run(_,SessionAction::Remember(_) | SessionAction::Stale(_)) | Self::Read(_,SessionAction::Remember(_) | SessionAction::Stale(_)) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionStaleAction\n",
            Self::Run(_,SessionAction::CancelOperation | SessionAction::Discard | SessionAction::ConfirmDiscard) | Self::Read(_,SessionAction::CancelOperation | SessionAction::Discard | SessionAction::ConfirmDiscard) => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionDiscard\n",
            Self::Run(_,SessionAction::QuitCancel) | Self::Read(_,SessionAction::QuitCancel) | Self::QuitCancel => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionQuitCancel\n",
            Self::QuitPreserved => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionQuitPreserved\n",
            Self::Reload => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionReload\n",
            Self::Loss => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionLoss\n",
            Self::Deadline => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionDeadline\n",
            Self::Run(_,SessionAction::Held) | Self::Read(_,SessionAction::Held) | Self::Finality => b"MRK_INSTALLED_SHELL_FAILURE_STEP=SessionFinality\n",
        }
    }
}

// Cached observer diagnostics, not native status or authority. Every token is
// closed and public; no input, identifier, path, DTO or error is retained.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionRejection { NotRecorded, UnknownNativeSnapshot, NativeReadinessInvariant, EvaluationBudget,
    UnavailableScript, EvaluationDispatch, StepPendingInvariant,
    GtkThread, GtkDialogBook, GtkDialogOriginal, GtkOwnerBinding, GtkOwnerInterrupted, GtkOwnerFacts,
    GtkDialogProperties, GtkSelectionSetter, GtkResponseWidget, GtkActionWidget, GtkDialogRecord,
    GtkObserverEndpoint, GtkSelectionState, GtkActivationState, GtkFilenameState, GtkFilenameAbsent,
    GtkFilenameDifferent, GtkResponseState, GtkResponseContract, GtkReturnRole, GtkReturnState,
    GtkDestroyState, GtkReleaseState,
    LostNativeSnapshot, UnboundNativeSnapshot, RequestCounterUnderflow,
    RequestCounterSurplus, StaleReplyContract, CapabilityCleanupUnknown,
    CapabilityShutdown, CapabilityDocumentLost, CapabilityUnsupportedPlatform,
    CapabilityUnqualified, CapabilityClosed, CapabilityUnavailable,
    ReplyAssetInvalidRequest, ReplyAssetClosed, ReplyAssetUnqualified,
    ReplyAssetUnsupportedPlatform, ReplyAssetUnsupportedFilesystem, ReplyAssetUnsupportedFormat,
    ReplyAssetBusy, ReplyAssetSourceRefused, ReplyAssetSourceChanged,
    ReplyAssetMaterialLimit, ReplyAssetParserLimit, ReplyAssetProjectOverlap,
    ReplyAssetExclusionUnconfirmed, ReplyAssetCapacity, ReplyAssessmentContextStale,
    ReplyAssetUserCancelled, ReplyAssetReviewExpired, ReplyAssetDeadline,
    ReplyAssetDocumentLost, ReplyAssetShutdown, ReplyAssetCleanupUnknown,
    ReplyAssessmentInvalidRequest, ReplyAssessmentLimit, ReplyAssessmentVersion,
    ReplyAssessmentPolicyStale, ReplyAssessmentContextInvalid, ReplyAssessmentUnavailable,
    ReplyBusy, ReplyShuttingDown, ReplyQueryTimeout,
    ReplyCleanupUnknown, ReplyCodeUnavailable,
}
impl SessionRejection {
    fn token(self) -> &'static [u8] {
        match self {
            Self::NotRecorded => b"not-recorded",
            Self::UnknownNativeSnapshot => b"unknown-native-snapshot",
            Self::NativeReadinessInvariant => b"native-readiness-invariant",
            Self::EvaluationBudget => b"evaluation-budget",
            Self::UnavailableScript => b"unavailable-projection-script",
            Self::EvaluationDispatch => b"evaluation-dispatch",
            Self::StepPendingInvariant => b"step-pending-invariant",
            Self::GtkThread => b"gtk-thread",
            Self::GtkDialogBook => b"gtk-dialog-book",
            Self::GtkDialogOriginal => b"gtk-dialog-original",
            Self::GtkOwnerBinding => b"gtk-owner-binding",
            Self::GtkOwnerInterrupted => b"gtk-owner-interrupted",
            Self::GtkOwnerFacts => b"gtk-owner-facts",
            Self::GtkDialogProperties => b"gtk-dialog-properties",
            Self::GtkSelectionSetter => b"gtk-selection-setter",
            Self::GtkResponseWidget => b"gtk-response-widget",
            Self::GtkActionWidget => b"gtk-action-widget",
            Self::GtkDialogRecord => b"gtk-dialog-record",
            Self::GtkObserverEndpoint => b"gtk-observer-endpoint",
            Self::GtkSelectionState => b"gtk-selection-state",
            Self::GtkActivationState => b"gtk-activation-state",
            Self::GtkFilenameState => b"gtk-filename-state",
            Self::GtkFilenameAbsent => b"gtk-filename-absent",
            Self::GtkFilenameDifferent => b"gtk-filename-different",
            Self::GtkResponseState => b"gtk-response-state",
            Self::GtkResponseContract => b"gtk-response-contract",
            Self::GtkReturnRole => b"gtk-return-role",
            Self::GtkReturnState => b"gtk-return-state",
            Self::GtkDestroyState => b"gtk-destroy-state",
            Self::GtkReleaseState => b"gtk-release-state",
            Self::LostNativeSnapshot => b"lost-native-snapshot",
            Self::UnboundNativeSnapshot => b"unbound-native-snapshot",
            Self::RequestCounterUnderflow => b"request-counter-underflow",
            Self::RequestCounterSurplus => b"request-counter-surplus",
            Self::StaleReplyContract => b"stale-reply-contract",
            Self::CapabilityCleanupUnknown => b"capability-cleanup-unknown",
            Self::CapabilityShutdown => b"capability-shutdown",
            Self::CapabilityDocumentLost => b"capability-document-lost",
            Self::CapabilityUnsupportedPlatform => b"capability-unsupported-platform",
            Self::CapabilityUnqualified => b"capability-unqualified",
            Self::CapabilityClosed => b"capability-closed",
            Self::CapabilityUnavailable => b"capability-unavailable",
            Self::ReplyAssetInvalidRequest => b"reply-asset-invalid-request",
            Self::ReplyAssetClosed => b"reply-asset-closed",
            Self::ReplyAssetUnqualified => b"reply-asset-unqualified",
            Self::ReplyAssetUnsupportedPlatform => b"reply-asset-unsupported-platform",
            Self::ReplyAssetUnsupportedFilesystem => b"reply-asset-unsupported-fs",
            Self::ReplyAssetUnsupportedFormat => b"reply-asset-unsupported-format",
            Self::ReplyAssetBusy => b"reply-asset-busy",
            Self::ReplyAssetSourceRefused => b"reply-asset-source-refused",
            Self::ReplyAssetSourceChanged => b"reply-asset-source-changed",
            Self::ReplyAssetMaterialLimit => b"reply-asset-material-limit",
            Self::ReplyAssetParserLimit => b"reply-asset-parser-limit",
            Self::ReplyAssetProjectOverlap => b"reply-asset-project-overlap",
            Self::ReplyAssetExclusionUnconfirmed => b"reply-asset-excl-unconfirmed",
            Self::ReplyAssetCapacity => b"reply-asset-capacity",
            Self::ReplyAssessmentContextStale => b"reply-assessment-context-stale",
            Self::ReplyAssetUserCancelled => b"reply-asset-user-cancelled",
            Self::ReplyAssetReviewExpired => b"reply-asset-review-expired",
            Self::ReplyAssetDeadline => b"reply-asset-deadline",
            Self::ReplyAssetDocumentLost => b"reply-asset-document-lost",
            Self::ReplyAssetShutdown => b"reply-asset-shutdown",
            Self::ReplyAssetCleanupUnknown => b"reply-asset-cleanup-unknown",
            Self::ReplyAssessmentInvalidRequest => b"reply-assessment-invalid-request",
            Self::ReplyAssessmentLimit => b"reply-assessment-limit",
            Self::ReplyAssessmentVersion => b"reply-assessment-version",
            Self::ReplyAssessmentPolicyStale => b"reply-assessment-policy-stale",
            Self::ReplyAssessmentContextInvalid => b"reply-assessment-context-invalid",
            Self::ReplyAssessmentUnavailable => b"reply-assessment-unavailable",
            Self::ReplyBusy => b"reply-busy",
            Self::ReplyShuttingDown => b"reply-shutting-down",
            Self::ReplyQueryTimeout => b"reply-query-timeout",
            Self::ReplyCleanupUnknown => b"reply-cleanup-unknown",
            Self::ReplyCodeUnavailable => b"reply-code-unavailable",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionWait { NotSampled, RequestNotSeen, ReplyPending, OwnerUnsettled, PhaseNotReady, DisplayMismatch, ControlsMismatch,
    GtkDialogAbsent, GtkActionInsensitive, GtkSelectionAbsent, GtkSelectionDifferent }
impl SessionWait {
    fn token(self) -> &'static [u8] {
        match self {
            Self::NotSampled => b"not-sampled",
            Self::RequestNotSeen => b"request-not-yet-seen",
            Self::ReplyPending => b"native-reply-pending",
            Self::OwnerUnsettled => b"original-owner-unsettled",
            Self::PhaseNotReady => b"native-phase-not-ready",
            Self::DisplayMismatch => b"rendered-display-mismatch",
            Self::ControlsMismatch => b"rendered-control-mismatch",
            Self::GtkDialogAbsent => b"gtk-dialog-absent",
            Self::GtkActionInsensitive => b"gtk-action-insensitive",
            Self::GtkSelectionAbsent => b"gtk-selection-absent",
            Self::GtkSelectionDifferent => b"gtk-selection-different",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct SessionDiagnostic {
    step: SessionStep, evaluations: u16, rejection: SessionRejection, wait: SessionWait, first_failure: InstalledSessionFailure,
    assessment: InstalledAssessmentFailure, gtk_callbacks: SessionGtkCallbacks,
}
impl SessionDiagnostic {
    fn sample(step: Step, evaluations: u16, previous: Option<Self>) -> Option<Self> {
        let Step::Session(step) = step else { return None; };
        Some(Self { step, evaluations, rejection: SessionRejection::NotRecorded,
            wait: previous.filter(|old| old.step == step).map_or(SessionWait::NotSampled, |old| old.wait),
            first_failure: InstalledSessionFailure::not_recorded(), assessment: InstalledAssessmentFailure::none(),
            gtk_callbacks: previous.filter(|old| old.step == step)
                .map_or_else(|| SessionGtkCallbacks::initial(step), |old| old.gtk_callbacks) })
    }
}

// Only authenticated original helper notifications for one exact role/index.
// Reserved is pending admission, not dispatch success or callback-entry proof;
// returned is the helper notification, not closure exit or owner settlement.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionGtkReturns { None, One, Multiple }
#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionGtkPhase { Idle, Reserved, WaitObserved }
#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionGtkCallbacks { NotApplicable, Active { returns: SessionGtkReturns, phase: SessionGtkPhase } }
impl SessionGtkCallbacks {
    fn initial(step: SessionStep) -> Self {
        if matches!(step, SessionStep::SetFile(_) | SessionStep::ActivateFile(_)) {
            Self::Active { returns: SessionGtkReturns::None, phase: SessionGtkPhase::Idle }
        } else { Self::NotApplicable }
    }
    fn matches_step(self, step: SessionStep) -> bool {
        matches!(step, SessionStep::SetFile(_) | SessionStep::ActivateFile(_)) != matches!(self, Self::NotApplicable)
    }
    fn reserved(&mut self) {
        if let Self::Active { phase, .. } = self { *phase = SessionGtkPhase::Reserved; }
    }
    fn wait_observed(&mut self) {
        if let Self::Active { phase, .. } = self { *phase = SessionGtkPhase::WaitObserved; }
    }
    fn returned(&mut self) {
        if let Self::Active { returns, phase } = self {
            *returns = match *returns { SessionGtkReturns::None => SessionGtkReturns::One,
                SessionGtkReturns::One | SessionGtkReturns::Multiple => SessionGtkReturns::Multiple };
            *phase = SessionGtkPhase::Idle;
        }
    }
    fn token(self) -> &'static [u8] {
        use SessionGtkReturns as R;
        use SessionGtkPhase as P;
        match self {
            Self::NotApplicable => b"na",
            Self::Active { returns:R::None, phase:P::Idle } => b"0i",
            Self::Active { returns:R::None, phase:P::Reserved } => b"0p",
            Self::Active { returns:R::None, phase:P::WaitObserved } => b"0w",
            Self::Active { returns:R::One, phase:P::Idle } => b"1i",
            Self::Active { returns:R::One, phase:P::Reserved } => b"1p",
            Self::Active { returns:R::One, phase:P::WaitObserved } => b"1w",
            Self::Active { returns:R::Multiple, phase:P::Idle } => b"mi",
            Self::Active { returns:R::Multiple, phase:P::Reserved } => b"mp",
            Self::Active { returns:R::Multiple, phase:P::WaitObserved } => b"mw",
        }
    }
}

// Map only cached public DATA to closed tokens; never render the input string.
fn session_reply_rejection(code: &str) -> SessionRejection {
    match code {
        "asset_invalid_request" => SessionRejection::ReplyAssetInvalidRequest,
        "asset_closed" => SessionRejection::ReplyAssetClosed,
        "asset_unqualified" => SessionRejection::ReplyAssetUnqualified,
        "asset_unsupported_platform" => SessionRejection::ReplyAssetUnsupportedPlatform,
        "asset_unsupported_filesystem" => SessionRejection::ReplyAssetUnsupportedFilesystem,
        "asset_unsupported_format" => SessionRejection::ReplyAssetUnsupportedFormat,
        "asset_busy" => SessionRejection::ReplyAssetBusy,
        "asset_source_refused" => SessionRejection::ReplyAssetSourceRefused,
        "asset_source_changed" => SessionRejection::ReplyAssetSourceChanged,
        "asset_material_limit" => SessionRejection::ReplyAssetMaterialLimit,
        "asset_parser_limit" => SessionRejection::ReplyAssetParserLimit,
        "asset_project_overlap" => SessionRejection::ReplyAssetProjectOverlap,
        "asset_exclusion_unconfirmed" => SessionRejection::ReplyAssetExclusionUnconfirmed,
        "asset_capacity" => SessionRejection::ReplyAssetCapacity,
        "assessment_context_stale" => SessionRejection::ReplyAssessmentContextStale,
        "asset_user_cancelled" => SessionRejection::ReplyAssetUserCancelled,
        "asset_review_expired" => SessionRejection::ReplyAssetReviewExpired,
        "asset_deadline" => SessionRejection::ReplyAssetDeadline,
        "asset_document_lost" => SessionRejection::ReplyAssetDocumentLost,
        "asset_shutdown" => SessionRejection::ReplyAssetShutdown,
        "asset_cleanup_unknown" => SessionRejection::ReplyAssetCleanupUnknown,
        "assessment_invalid_request" => SessionRejection::ReplyAssessmentInvalidRequest,
        "assessment_limit" => SessionRejection::ReplyAssessmentLimit,
        "assessment_version" => SessionRejection::ReplyAssessmentVersion,
        "assessment_policy_stale" => SessionRejection::ReplyAssessmentPolicyStale,
        "assessment_context_invalid" => SessionRejection::ReplyAssessmentContextInvalid,
        "assessment_unavailable" => SessionRejection::ReplyAssessmentUnavailable,
        "busy" => SessionRejection::ReplyBusy,
        "shutting_down" => SessionRejection::ReplyShuttingDown,
        "query_timeout" => SessionRejection::ReplyQueryTimeout,
        "cleanup_unknown" => SessionRejection::ReplyCleanupUnknown,
        _ => SessionRejection::ReplyCodeUnavailable,
    }
}
fn session_capability_rejection(reason: Option<&str>) -> SessionRejection {
    match reason {
        Some("cleanup-unknown") => SessionRejection::CapabilityCleanupUnknown,
        Some("shutdown") => SessionRejection::CapabilityShutdown,
        Some("document-lost") => SessionRejection::CapabilityDocumentLost,
        Some("unsupported-platform") => SessionRejection::CapabilityUnsupportedPlatform,
        Some("unqualified") => SessionRejection::CapabilityUnqualified,
        Some("closed") => SessionRejection::CapabilityClosed,
        _ => SessionRejection::CapabilityUnavailable,
    }
}

fn session_file_wait_pending(actual: Step, pending: Option<Pending>, index: u8, activating: bool) -> bool {
    let expected = Step::Session(if activating { SessionStep::ActivateFile(index) } else { SessionStep::SetFile(index) });
    actual == expected && pending == Some(Pending::Dom(expected))
}

use SessionAction as SA;
const SESSION_INPUTS: &[SA] = &[
    SA::Open, SA::Choose("input.jks","android-keystore",None), SA::Fields("android-keystore"), SA::Prepare("android-keystore","save"), SA::Keep, SA::Assign,
    SA::Kind("android-firebase"), SA::Choose("firebase.json","android-firebase",None), SA::Prepare("android-firebase","save"), SA::Keep, SA::Assign,
    SA::Kind("google-wif"), SA::Fields("google-wif"), SA::Prepare("google-wif","save"), SA::Keep, SA::Assign,
    SA::Platform("project"), SA::Kind("project-read-token"), SA::Fields("project-read-token"), SA::Prepare("project-read-token","save"), SA::Keep, SA::Assign,
    SA::Platform("android"), SA::Reassess(0,"android-keystore"), SA::Assign,
    SA::Kind("android-keystore"), SA::Replacement(0), SA::Choose("replacement.jks","android-keystore",None), SA::Fields("android-keystore"), SA::Prepare("android-keystore","save"), SA::Keep, SA::Assign,
    SA::ReviewRemoval(1), SA::Remove, SA::Reassess(1,"google-wif"), SA::QuitCancel,
];
const SESSION_REFUSALS: &[SA] = &[
    SA::Open, SA::Choose("overlap.jks","android-keystore",Some("project-overlap")),
    SA::Choose("link.jks","android-keystore",Some("source-refused")), SA::Choose("public.jks","android-keystore",Some("source-refused")),
    SA::Choose("changed.jks","android-keystore",Some("source-changed")),
    SA::Choose("input.jks","android-keystore",None), SA::Prepare("android-keystore","missing"), SA::CancelOperation,
    SA::Kind("android-firebase"), SA::Choose("firebase-mismatch.json","android-firebase",None), SA::Prepare("android-firebase","mismatch"), SA::CancelOperation,
    SA::Kind("android-keystore"), SA::Choose("input.jks","android-keystore",None), SA::Fields("android-keystore"), SA::Prepare("android-keystore","save"), SA::Keep, SA::Assign,
    SA::Reassess(0,"android-keystore"), SA::Remember("bind"), SA::Platform("project"), SA::Stale("bind"),
    SA::Platform("android"), SA::Replacement(0), SA::Choose("replacement.jks","android-keystore",None), SA::Fields("android-keystore"), SA::Prepare("android-keystore","save"),
    SA::Remember("save"), SA::Platform("project"), SA::Stale("save"), SA::Platform("android"), SA::Reassess(0,"android-keystore"), SA::Assign,
    SA::Replacement(0), SA::Choose("","android-keystore",Some("user-cancelled")), SA::Discard, SA::ConfirmDiscard, SA::Open,
];
const SESSION_INTERRUPTION: &[SA] = &[
    SA::Open, SA::Choose("input.jks","android-keystore",None), SA::Fields("android-keystore"), SA::Prepare("android-keystore","held"), SA::Held,
];
impl SessionCase { fn recipe(self) -> &'static [SA] { match self { Self::Inputs => SESSION_INPUTS, Self::Refusals => SESSION_REFUSALS, _ => SESSION_INTERRUPTION } } }
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionCommand { Status, Open, Context, Choose, Prepare, Delete, Commit, Bind, Discard, Lock }
impl SessionCommand { fn index(self) -> usize { self as usize } }
#[derive(Default)]
struct SessionReply {
    status: Option<Value>, error: Option<String>, ordinal: u8, assessment: InstalledAssessmentFailure,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct SessionRefusal { rejection: SessionRejection, assessment: InstalledAssessmentFailure }
impl From<SessionRejection> for SessionRefusal {
    fn from(rejection: SessionRejection) -> Self { Self { rejection, assessment: InstalledAssessmentFailure::none() } }
}
fn session_reply_refusal(command: usize, requested: u8, returned: u8, base: u8, reply: &SessionReply) -> Option<SessionRefusal> {
    let code = reply.error.as_deref()?;
    // Only the original, fully returned Prepare in this recipe step supplies
    // assessment provenance. No old reply, native slot, owner or query lookup.
    let assessment = if command == SessionCommand::Prepare.index() && requested == returned
        && base.checked_add(1) == Some(requested) && reply.ordinal == requested && reply.status.is_none() {
        reply.assessment
    } else { InstalledAssessmentFailure::none() };
    Some(SessionRefusal { rejection: session_reply_rejection(code), assessment })
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionPresentation { Native, DeadlineError }
struct SessionSample {
    snapshot: InstalledSessionSnapshot, presentation: SessionPresentation, display: Option<Value>,
}
struct SessionFile { id: u32, index: u8, kind: &'static str, select: bool, picker: Picker }
struct SessionRecord {
    admission_issued: bool, admitted: bool, fixture: Option<SessionFixture>,
    diagnostic: Option<SessionDiagnostic>,
    draft: Option<Value>,
    requests: [u8;10], returns: [u8;10], base_requests: [u8;10], replies: [SessionReply;10],
    before: Option<InstalledSessionSnapshot>, sampled: Option<SessionSample>, remembered: Option<InstalledSessionSnapshot>,
    replacement: Option<(String,u32,usize)>, files: Vec<SessionFile>,
    kind: &'static str, platform: &'static str, recipe_done: usize, captures: u8, captures_closed: u8,
    assessed: u8, kept: u8, assigned: u8, removed: u8, reassessed: bool, context_revoked: bool, replaced: bool,
    refused: Vec<&'static str>, missing: bool, mismatch: bool, stale_keep: bool, stale_assign: bool,
    cancel_preserved: bool, cancel_revoked: bool, reopened: bool,
    quit_cancel: Picker, quit_cancel_id: Option<u32>, cancel_close_prevented: bool, quit_review: Option<InstalledSessionSnapshot>, quit_preserved: bool,
    navigation: u8, loss: bool, loss_rendered: bool, deadline: bool, cleanup: Option<Instant>,
    queries: Option<crate::supervisor::InstalledSessionQueries>, r1_final: bool,
}
impl SessionRecord {
    fn new(_case: Option<SessionCase>) -> Self { Self {
        admission_issued:false,admitted:false,fixture:None,diagnostic:None,draft:None,requests:[0;10],returns:[0;10],base_requests:[0;10],replies:std::array::from_fn(|_| SessionReply::default()),
        before:None,sampled:None,remembered:None,replacement:None,files:Vec::new(),kind:"android-keystore",platform:"android",recipe_done:0,
        captures:0,captures_closed:0,assessed:0,kept:0,assigned:0,removed:0,reassessed:false,context_revoked:false,replaced:false,refused:Vec::new(),
        missing:false,mismatch:false,stale_keep:false,stale_assign:false,cancel_preserved:false,cancel_revoked:false,reopened:false,
        quit_cancel:Picker::default(),quit_cancel_id:None,cancel_close_prevented:false,quit_review:None,quit_preserved:false,navigation:0,loss:false,loss_rendered:false,deadline:false,cleanup:None,
        queries:None,r1_final:false,
    } }
}

fn session_kind_label(kind: &str) -> Option<&'static str> {
    match kind { "android-keystore" => Some("Android upload keystore"), "android-firebase" => Some("Android Firebase client document"),
        "google-wif" => Some("Google workload identity federation"), "project-read-token" => Some("Private project dependency access"), _ => None }
}
fn session_field_names(kind: &str) -> &'static [&'static str] {
    match kind { "android-keystore" => &["storePassword","keyAlias","keyPassword"], "google-wif" => &["provider","serviceAccount"],
        "project-read-token" => &["token"], _ => &[] }
}
fn session_display(snapshot: &InstalledSessionSnapshot, presentation: SessionPresentation) -> Option<Value> {
    let status = &snapshot.status;
    let records: Option<Vec<_>> = status["records"].as_array()?.iter().enumerate().map(|(i,record)| {
        let kind = record["kind"].as_str()?;
        let availability = record["availability"].as_str()?;
        Some(serde_json::json!({"heading":format!("{} · item {}",session_kind_label(kind)?,i+1),
            "revision":format!("Revision {} · retained only in this session",record["revision"].as_u64()?),
            "availability":match availability { "assigned" => "Assigned to current submitted context", "mutation-pending" => "Change pending · unavailable", "unassigned" => "Not assigned to the current draft", _ => return None }}))
    }).collect();
    let operation = &status["operation"];
    let preview = &operation["preview"];
    let review = if preview.is_null() { Value::Null } else {
        Value::String(match preview["action"].as_str()? { "save" => "Keep for this session", "bind" => "Assign to this context", "delete" => "Remove session copy", _ => return None }.into())
    };
    let assessment = &operation["assessment"];
    let assessed = if assessment.is_null() { Value::Null } else {
        let label = |value: &Value| -> Option<&'static str> { match value.as_str()? {
            "not-applicable" => Some("Not required here"), "missing" => Some("Missing"), "unknown" => Some("Not established"),
            "invalid" => Some("Needs correction"), "configured" => Some("Configured only"), "format-valid" => Some("Format / identity match"), _ => None } };
        let fields: Option<Vec<_>> = assessment["fields"].as_array()?.iter().map(|field| Some(serde_json::json!({
            "state":label(&field["state"])?, "presence":if field["presence"].as_str()? == "supplied" { "Supplied · value not displayed" } else { "Not supplied" },
            "issues":field["issues"].as_array()?.len(),
        }))).collect();
        serde_json::json!({"state":label(&assessment["state"])?,"fields":fields?,"assurance":["Native validation: not run","Service validation: not run","Release readiness: unknown"]})
    };
    Some(serde_json::json!({"mode":if status["mode"] == "session" { "Session open · no persistence" } else { "Session closed" },
        // A rejected Prepare invalidates frontend observation trust even when
        // the native context survives. Only its guarded Deadline step selects
        // this presentation; a native reason/event alone is not that reply.
        "context":!status["context"].is_null() && !snapshot.lost && presentation != SessionPresentation::DeadlineError,
        "records":records?,"review":review,"assessment":assessed,
        "phase":operation.get("phase").cloned().unwrap_or(Value::Null),
        "settlement":operation.get("settlement").cloned().unwrap_or(Value::Null)}))
}
fn assert_session_display_contract() {
    // Pure presentation DATA, not an original owner or native admission.
    let mut snapshot = InstalledSessionSnapshot {
        status: serde_json::json!({"mode":"session","context":{"revision":1},"records":[],
            "operation":{"phase":"idle","settlement":"known","reason":"deadline","preview":null,"assessment":null}}),
        owner:None, review_end:None, cleanup_end:None, work_end:None, payloads:Vec::new(), sources:Vec::new(),
        settled:true, lost:false, bound:true, unknown:false, quit_pending:false, quit_declined:false, empty:true, first_failure:None,
    };
    let ordinary = session_display(&snapshot,SessionPresentation::Native).expect("ordinary session display");
    assert_eq!(ordinary,serde_json::json!({"mode":"Session open · no persistence","context":true,"records":[],
        "review":null,"assessment":null,"phase":"idle","settlement":"known"}));
    let mut expected_error = ordinary.clone(); expected_error["context"] = Value::Bool(false);
    let error = session_display(&snapshot,SessionPresentation::DeadlineError).expect("deadline error display");
    assert_eq!(error,expected_error); // No other field is ignored or rewritten.
    assert!(session_script(SessionStep::Deadline,"android-keystore","android",None,Some(&error),SessionPresentation::Native).is_none());
    assert!(session_script(SessionStep::Deadline,"android-keystore","android",None,Some(&error),SessionPresentation::DeadlineError).is_some());
    assert!(session_script(SessionStep::Loss,"android-keystore","android",None,Some(&error),SessionPresentation::DeadlineError).is_none());
    snapshot.lost = true; snapshot.bound = false;
    assert_eq!(session_display(&snapshot,SessionPresentation::Native),Some(expected_error));
}
fn session_action_command(action: SA) -> Option<SessionCommand> {
    match action { SA::Open => Some(SessionCommand::Open), SA::Platform(_) => Some(SessionCommand::Context),
        SA::Choose(..) => Some(SessionCommand::Choose), SA::Prepare(..) | SA::Reassess(..) => Some(SessionCommand::Prepare),
        SA::Keep | SA::Remove => Some(SessionCommand::Commit), SA::Assign => Some(SessionCommand::Bind),
        SA::ReviewRemoval(_) => Some(SessionCommand::Delete), SA::ConfirmDiscard => Some(SessionCommand::Lock), SA::CancelOperation => Some(SessionCommand::Discard), _ => None }
}
fn session_original_clock(original: Option<Instant>, current: Option<Instant>, settled: bool) -> bool {
    // Retirement legitimately clears the original work clock; that is not a
    // renewed clock. While work remains, its exact captured endpoint must stay.
    original.is_some() && if settled { current.is_none() } else { current == original }
}
fn assert_session_recipe_contract() {
    for (case, assessments, choosers) in [(SessionCase::Inputs,7,3),(SessionCase::Refusals,6,9),
        (SessionCase::Loss,1,1),(SessionCase::Deadline,1,1)] {
        let recipe=case.recipe();
        assert!(recipe.len()<64 && recipe.first()==Some(&SA::Open));
        assert_eq!(recipe.iter().filter(|a| matches!(a,SA::Prepare(..)|SA::Reassess(..))).count(),assessments);
        assert_eq!(case.assessments(),assessments);
        assert_eq!(recipe.iter().filter(|a| matches!(a,SA::Choose(..))).count(),choosers);
        assert!(recipe.iter().all(|a| !matches!(a,SA::Fields("android-firebase"))));
        if matches!(case,SessionCase::Loss|SessionCase::Deadline) {
            assert!(recipe.last()==Some(&SA::Held));
            assert!(recipe.iter().all(|a| !matches!(a,SA::Keep|SA::Assign|SA::Remove)));
        }
    }
    let end=Instant::now();
    assert!(session_original_clock(Some(end),Some(end),false));
    assert!(session_original_clock(Some(end),None,true));
    assert!(!session_original_clock(None,None,true));
    assert!(!session_original_clock(Some(end),None,false));
    assert!(!session_original_clock(Some(end),Some(end),true));
    assert!(!session_original_clock(Some(end),end.checked_add(Duration::from_millis(1)),false));
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Boundary { Bootstrap, Request, Result, Dom, Gtk, Settlement, Deadline, Exit }
impl Boundary {
    fn failure_line(self) -> &'static [u8] {
        match self {
            Self::Bootstrap => b"MRK_INSTALLED_SHELL_FAILURE_PHASE=bootstrap\n",
            Self::Request => b"MRK_INSTALLED_SHELL_FAILURE_PHASE=request\n",
            Self::Result => b"MRK_INSTALLED_SHELL_FAILURE_PHASE=result\n",
            Self::Dom => b"MRK_INSTALLED_SHELL_FAILURE_PHASE=dom\n",
            Self::Gtk => b"MRK_INSTALLED_SHELL_FAILURE_PHASE=gtk\n",
            Self::Settlement => b"MRK_INSTALLED_SHELL_FAILURE_PHASE=settlement\n",
            Self::Deadline => b"MRK_INSTALLED_SHELL_FAILURE_PHASE=deadline\n",
            Self::Exit => b"MRK_INSTALLED_SHELL_FAILURE_PHASE=exit\n",
        }
    }
}

// Last observation made by an already-admitted Bootstrap tick. This is cached
// diagnostic history, never a current owner/finality receipt. The one result
// category records an original callback instead of a wait predicate.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BootstrapProgress {
    NotSampled, Attachment, PageLoad, OriginalRegistrySample, AppInfoCatalog,
    HeldAppInfo, Advanced, AppInfoReturnedBeforeHold,
}
impl BootstrapProgress {
    fn failure_line(self) -> &'static [u8] {
        match self {
            Self::NotSampled => b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=not-sampled\n",
            Self::Attachment => b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=attachment\n",
            Self::PageLoad => b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=page-load\n",
            Self::OriginalRegistrySample => b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=original-registry-sample\n",
            Self::AppInfoCatalog => b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=app-info-catalog\n",
            Self::HeldAppInfo => b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=held-app-info\n",
            Self::Advanced => b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=advanced\n",
            Self::AppInfoReturnedBeforeHold => b"MRK_INSTALLED_SHELL_BOOTSTRAP_PROGRESS=app-info-returned-before-hold\n",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum OutstandingInfo { ShutdownUnavailable, ReturnedBeforeHold, Unexpected }
fn outstanding_info(step: Step, available: bool, capabilities: bool) -> OutstandingInfo {
    if available || capabilities { OutstandingInfo::Unexpected }
    else if matches!(step, Step::Close | Step::Quit | Step::Exit) { OutstandingInfo::ShutdownUnavailable }
    else { OutstandingInfo::ReturnedBeforeHold }
}
// One absorbing value publishes both failure and its original source site.
// 0: no failure; 1: unknown site; 2..=65536: first-party source line + 1.
// No reset, second publication, extra mutex or shutdown dependency.
struct FailureLatch(AtomicU32);
impl FailureLatch {
    fn new(failed: bool) -> Self { Self(AtomicU32::new(u32::from(failed))) }
    fn load(&self, order: Ordering) -> bool { self.0.load(order) != 0 }
    fn mark(&self, value: u32) -> bool {
        self.0.compare_exchange(0, value, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    }
    fn mark_unknown(&self) -> bool { self.mark(1) }
    fn mark_site(&self, line: u32) -> bool {
        self.mark(if (1..=u32::from(u16::MAX)).contains(&line) { line + 1 } else { 1 })
    }
    #[track_caller]
    fn mark_caller(&self) -> bool { self.mark_site(std::panic::Location::caller().line()) }
    fn site(&self) -> Option<u16> {
        match self.0.load(Ordering::SeqCst) { value @ 2..=65536 => Some((value - 1) as u16), _ => None }
    }
}
fn assert_failure_latch_contract() {
    let generic = FailureLatch::new(false);
    let original_line = line!() + 1;
    assert!(generic.mark_caller());
    assert!(generic.load(Ordering::SeqCst) && generic.site() == Some(original_line as u16));
    assert!(!generic.mark_site(1) && !generic.mark_unknown() && generic.site() == Some(original_line as u16));
    for initial in [false, true] {
        let typed = FailureLatch::new(initial);
        assert!(typed.mark_unknown() == !initial);
        assert!(!typed.mark_site(65535) && typed.load(Ordering::SeqCst) && typed.site().is_none());
    }
    for line in [0, 65536, u32::MAX] {
        let unknown = FailureLatch::new(false);
        assert!(unknown.mark_site(line) && unknown.load(Ordering::SeqCst) && unknown.site().is_none());
        assert!(!unknown.mark_site(123));
    }
    let upper = FailureLatch::new(false);
    assert!(upper.mark_site(65535) && upper.site() == Some(65535));
}
fn latch_failure(failed: &FailureLatch, trace: &mut (Step, Boundary), progress: &mut BootstrapProgress,
    next_trace: (Step, Boundary), next_progress: BootstrapProgress) -> bool {
    // The caller holds the existing Record mutex. Reporting reads these facts
    // together under that mutex; only the first failure may replace them.
    if failed.mark_unknown() { *trace = next_trace; *progress = next_progress; true } else { false }
}
fn latch_session_diagnostic(failed: &FailureLatch, diagnostic: &mut Option<SessionDiagnostic>, next: SessionDiagnostic) {
    // The existing Record mutex also protects the matching trace. A later
    // callback or deadline cannot relabel this first cached rejection.
    if failed.mark_unknown() { *diagnostic = Some(next); }
}
fn latch_path_diagnostic(failed: &FailureLatch, diagnostic: &mut Option<PathDiagnostic>, next: PathDiagnostic) {
    // The caller holds Record, including the matching trace. Generic failure,
    // an earlier callback or a deadline winner cannot be relabelled later.
    if failed.mark_unknown() { *diagnostic = Some(next); }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FailureQuitAction { Close, Activate }
// DATA for one handoff to normal quit, never an owner or exit/finality permit.
// Claims are monotone, including after an unsuccessful external dispatch. This
// state cannot clear the failed recipe, renew a clock, or start shutdown itself.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct FailureQuit {
    armed: bool, refused: bool, close_requested: bool, close_prevented: bool,
    id: Option<u32>, selects_ok: bool, pending: bool, activated: bool,
    responded: bool, disposal: bool, destroyed: bool, released: bool, returned: bool,
    relay_observed: Option<bool>, loop_exit_observed: Option<bool>,
}
impl FailureQuit {
    fn begin(&mut self, original: Option<Self>) {
        if self.armed { return; }
        *self = original.unwrap_or(Self { selects_ok: true, ..Self::default() });
        self.armed = true;
    }
    fn refuse(&mut self) { self.refused = true; }
    fn reserve(&mut self, failed: bool, before_end: bool) -> Option<FailureQuitAction> {
        if !failed || !self.armed || self.refused { return None; }
        if !before_end { self.refuse(); return None; }
        if !self.close_requested {
            self.close_requested = true; return Some(FailureQuitAction::Close);
        }
        if self.close_prevented && self.id.is_some() && !self.pending && !self.activated
            && !self.responded && !self.returned && !self.destroyed && !self.released {
            self.pending = true; return Some(FailureQuitAction::Activate);
        }
        None
    }
    fn closed(&mut self) {
        if !self.armed || self.refused || self.close_prevented || self.id.is_some() { self.refuse(); return; }
        // A genuine CloseRequested may precede the relay's first failed tick.
        // That existing request must not be replaced by another window.close().
        self.close_requested = true; self.close_prevented = true;
    }
    fn created(&mut self, id: u32, quit: bool) {
        if !self.armed || self.refused || !self.close_prevented || !quit || id == 0 || self.id.is_some() {
            self.refuse(); return;
        }
        self.id = Some(id);
    }
    fn eligible(&self, id: u32) -> bool {
        self.armed && !self.refused && self.close_requested && self.close_prevented && self.id == Some(id)
            && self.pending && !self.activated && !self.responded && !self.returned && !self.destroyed && !self.released
    }
    fn choice(&self, id: u32) -> Result<bool, ()> {
        if self.eligible(id) { Ok(self.selects_ok) } else { Err(()) }
    }
    fn activate(&mut self, id: u32, before_end: bool) -> Result<(), ()> {
        if !before_end || !self.eligible(id) { self.refuse(); return Err(()); }
        self.activated = true; Ok(())
    }
    fn response(&mut self, id: u32, accepted: bool, declined: bool, disposal: bool) {
        if self.refused || self.id != Some(id) || !self.activated || self.destroyed || self.released {
            self.refuse(); return;
        }
        if !self.responded && !disposal && accepted == self.selects_ok && declined != self.selects_ok {
            self.responded = true;
        } else if self.responded && self.returned && disposal && !accepted && !declined && !self.disposal {
            self.disposal = true;
        } else { self.refuse(); }
    }
    fn activation_returned(&mut self, result: Result<bool, ()>) {
        if self.refused || !self.pending || !self.activated || self.returned || result != Ok(true) { self.refuse(); return; }
        // Return is not consent: the original GTK response can arrive later.
        self.returned = true;
    }
    fn destroyed(&mut self, id: u32, seen: bool) {
        if self.refused || self.id != Some(id) || !seen || !self.responded || self.destroyed || self.released { self.refuse(); return; }
        self.destroyed = true;
    }
    fn released(&mut self, id: u32, seen: bool) {
        if self.refused || self.id != Some(id) || !seen || !self.destroyed || self.released { self.refuse(); return; }
        self.released = true;
    }
    fn native_handoff_complete(&self) -> bool {
        // pending is the consumed one-shot activation claim, not an owner join.
        // The optional disposal response is not consent; the actual OK is.
        self.armed && !self.refused && self.close_requested && self.close_prevented
            && self.id.is_some_and(|id| id != 0) && self.selects_ok && self.pending
            && self.activated && self.responded && self.returned && self.destroyed && self.released
    }
    fn observe_relay(&mut self, joined: bool) {
        // DATA from the existing original await only. No claim/refusal changes.
        self.relay_observed = Some(self.relay_observed.is_none() && joined && self.native_handoff_complete());
    }
    fn observe_loop_exit(&mut self, ready: bool) {
        self.loop_exit_observed = Some(self.loop_exit_observed.is_none() && ready
            && self.relay_observed == Some(true) && self.native_handoff_complete());
    }
    fn returned_handoff(&self, normal_return: bool) -> bool {
        normal_return && self.native_handoff_complete()
            && self.relay_observed == Some(true) && self.loop_exit_observed == Some(true)
    }
}

fn failure_handoff_line(failed: bool, normal_return: bool, snapshot: Option<FailureQuit>) -> Option<&'static [u8]> {
    if failed && snapshot.is_some_and(|quit| quit.returned_handoff(normal_return)) {
        Some(b"MRK_INSTALLED_SHELL_FAILURE_HANDOFF=original-quit-relay-loop-returned\n")
    } else { None }
}

fn assert_failure_quit_contract() {
    // The actual tick/callback helper, with inert original-event DATA only.
    // These assertions do not click GTK, run cleanup, or prove native finality.
    let id = 73;
    let step = SessionStep::Read(6, SA::Prepare("android-keystore", "missing"));
    let mut trace = (Step::Session(step), Boundary::Settlement);
    let mut progress = BootstrapProgress::Advanced;
    let failed = FailureLatch::new(false);
    let first = SessionDiagnostic { step, evaluations: 25, rejection: SessionRejection::ReplyAssessmentUnavailable,
        wait: SessionWait::ReplyPending, first_failure: InstalledSessionFailure::not_recorded(), assessment: InstalledAssessmentFailure::none(), gtk_callbacks:SessionGtkCallbacks::NotApplicable };
    let mut diagnostic = None;
    latch_session_diagnostic(&failed, &mut diagnostic, first);
    let frame = failure_pair(trace, progress, diagnostic, None);
    assert!(frame.is_some());
    let mut quit = FailureQuit::default(); quit.begin(None);
    let unclaimed = quit;
    assert!(quit.reserve(false, true).is_none() && quit == unclaimed);
    assert!(quit.reserve(failed.load(Ordering::SeqCst), true) == Some(FailureQuitAction::Close));
    assert!(quit.reserve(true, true).is_none());
    quit.closed();
    assert!(quit.reserve(true, true).is_none()); // Original question not created yet.
    quit.created(id, true);
    assert!(quit.reserve(true, true) == Some(FailureQuitAction::Activate));
    assert!(quit.reserve(true, true).is_none() && quit.choice(id) == Ok(true));
    assert!(quit.activate(id, true).is_ok());
    quit.activation_returned(Ok(true));
    assert!(quit.returned && !quit.responded && !quit.released); // Return is not consent.
    quit.response(id, true, false, false);
    quit.response(id, false, false, true);
    quit.destroyed(id, true); quit.released(id, true);
    assert!(!quit.refused && quit.released && quit.reserve(true, true).is_none());
    // The actual terminal observation methods never change native claims or
    // manufacture positive recipe/cleanup receipts. Disposal is optional.
    let native = FailureQuit { disposal: false, ..quit };
    assert!(native.native_handoff_complete() && !native.returned_handoff(true));
    let mut observed = native; observed.observe_relay(true);
    assert!(!observed.returned_handoff(true));
    observed.observe_loop_exit(true);
    assert!(observed.returned_handoff(true) && !observed.returned_handoff(false));
    assert!(failure_handoff_line(true, true, Some(observed)).is_some_and(|line|
        line == b"MRK_INSTALLED_SHELL_FAILURE_HANDOFF=original-quit-relay-loop-returned\n"));
    // Missing snapshot includes unavailable/poisoned Record; false normal_return
    // covers both pre-loop initialization error and an actual nonzero loop return.
    assert!(failure_handoff_line(true, true, None).is_none());
    assert!(failure_handoff_line(false, true, Some(observed)).is_none());
    assert!(failure_handoff_line(true, false, Some(observed)).is_none());
    assert!(FailureQuit { relay_observed: None, loop_exit_observed: None, ..observed } == native);
    for mut missing in [
        FailureQuit { armed: false, ..native }, FailureQuit { refused: true, ..native },
        FailureQuit { close_requested: false, ..native }, FailureQuit { close_prevented: false, ..native },
        FailureQuit { id: None, ..native }, FailureQuit { id: Some(0), ..native },
        FailureQuit { selects_ok: false, ..native }, FailureQuit { pending: false, ..native },
        FailureQuit { activated: false, ..native }, FailureQuit { responded: false, ..native },
        FailureQuit { returned: false, ..native }, FailureQuit { destroyed: false, ..native },
        FailureQuit { released: false, ..native },
    ] {
        let before = missing; missing.observe_relay(true); missing.observe_loop_exit(true);
        assert!(missing.relay_observed == Some(false) && missing.loop_exit_observed == Some(false));
        assert!(failure_handoff_line(true, true, Some(missing)).is_none());
        assert!(FailureQuit { relay_observed: None, loop_exit_observed: None, ..missing } == before);
    }
    let mut false_relay = native; false_relay.observe_relay(false); false_relay.observe_relay(true);
    false_relay.observe_loop_exit(true);
    assert!(false_relay.relay_observed == Some(false) && !false_relay.returned_handoff(true));
    let mut repeated_relay = native; repeated_relay.observe_relay(true); repeated_relay.observe_relay(true);
    repeated_relay.observe_loop_exit(true);
    assert!(repeated_relay.relay_observed == Some(false) && !repeated_relay.returned_handoff(true));
    let mut false_exit = native; false_exit.observe_relay(true); false_exit.observe_loop_exit(false);
    false_exit.observe_loop_exit(true);
    assert!(false_exit.loop_exit_observed == Some(false) && !false_exit.returned_handoff(true));
    let mut repeated_exit = observed; repeated_exit.observe_loop_exit(true);
    assert!(repeated_exit.loop_exit_observed == Some(false) && !repeated_exit.returned_handoff(true));
    let mut reversed = native; reversed.observe_loop_exit(true); reversed.observe_relay(true);
    reversed.observe_loop_exit(true);
    assert!(reversed.loop_exit_observed == Some(false) && !reversed.returned_handoff(true));
    latch_session_diagnostic(&failed, &mut diagnostic, SessionDiagnostic { rejection: SessionRejection::GtkReturnState, ..first });
    assert!(!latch_failure(&failed, &mut trace, &mut progress, (Step::Exit, Boundary::Deadline), BootstrapProgress::NotSampled));
    assert!(failed.load(Ordering::SeqCst) && diagnostic == Some(first));
    assert!(failure_pair(trace, progress, diagnostic, None) == frame);

    // A previously reserved Close is adopted, never sent a second time.
    let mut closing = FailureQuit::default();
    closing.begin(Some(FailureQuit { close_requested: true, selects_ok: true, ..FailureQuit::default() }));
    assert!(closing.reserve(true, true).is_none());
    closing.closed(); closing.created(id, true);
    assert!(closing.reserve(true, true) == Some(FailureQuitAction::Activate));
    // Conversely a genuine CloseRequested before the first failed tick already
    // owns that request, even when the failed recipe had unrelated pending work.
    let mut external_close = FailureQuit::default(); external_close.begin(None); external_close.closed();
    assert!(external_close.close_requested && external_close.reserve(true, true).is_none());

    for selects_ok in [false, true] {
        let original = FailureQuit { close_requested: true, close_prevented: true, id: Some(id), selects_ok,
            ..FailureQuit::default() };
        let mut created = FailureQuit::default(); created.begin(Some(original));
        assert!(created.reserve(true, true) == Some(FailureQuitAction::Activate));
        assert!(created.choice(id) == Ok(selects_ok)); // Existing QuitCancel stays Cancel.
        for response_first in [false, true] {
            let mut pending = FailureQuit::default();
            pending.begin(Some(FailureQuit { pending: true, ..original }));
            assert!(pending.reserve(true, true).is_none()); // Adopt the queued original callback.
            assert!(pending.choice(id) == Ok(selects_ok) && pending.activate(id, true).is_ok());
            if response_first { pending.response(id, selects_ok, !selects_ok, false); }
            pending.activation_returned(Ok(true));
            if !response_first { pending.response(id, selects_ok, !selects_ok, false); }
            pending.destroyed(id, true); pending.released(id, true);
            assert!(!pending.refused && pending.returned && pending.responded && pending.released);
            let retained = pending; pending.begin(None);
            assert!(pending == retained && pending.reserve(true, true).is_none());
        }
        for responded in [false, true] {
            let mut activated = FailureQuit::default();
            activated.begin(Some(FailureQuit { pending: true, activated: true, responded, ..original }));
            assert!(activated.reserve(true, true).is_none() && activated.choice(id).is_err());
            activated.activation_returned(Ok(true));
            if !responded { activated.response(id, selects_ok, !selects_ok, false); }
            assert!(!activated.refused && activated.returned && activated.reserve(true, true).is_none());
        }
        let mut returned = FailureQuit::default();
        returned.begin(Some(FailureQuit { pending: true, activated: true, responded: true, returned: true, ..original }));
        assert!(returned.reserve(true, true).is_none() && returned.choice(id).is_err());
    }

    let awaiting = || {
        let mut q = FailureQuit::default(); q.begin(None);
        assert!(q.reserve(true, true) == Some(FailureQuitAction::Close));
        q.closed(); q.created(id, true);
        assert!(q.reserve(true, true) == Some(FailureQuitAction::Activate)); q
    };
    for result in [Ok(false), Err(())] {
        let mut q = awaiting(); q.activation_returned(result);
        assert!(q.refused && q.pending && q.reserve(true, true).is_none());
    }
    let mut wrong = awaiting(); assert!(wrong.choice(id + 1).is_err());
    assert!(wrong.activate(id + 1, true).is_err() && wrong.refused && wrong.reserve(true, true).is_none());
    let mut late = awaiting(); assert!(late.activate(id, false).is_err());
    assert!(late.refused && !late.activated && late.reserve(true, true).is_none());
    let mut duplicate = awaiting(); assert!(duplicate.activate(id, true).is_ok());
    assert!(duplicate.activate(id, true).is_err() && duplicate.reserve(true, true).is_none());
    let mut declined = awaiting(); assert!(declined.activate(id, true).is_ok());
    declined.response(id, false, true, false);
    assert!(declined.refused && !declined.responded && declined.reserve(true, true).is_none());
    let mut returned = awaiting(); assert!(returned.activate(id, true).is_ok());
    returned.activation_returned(Ok(true)); returned.activation_returned(Ok(true));
    assert!(returned.refused && returned.reserve(true, true).is_none());
    let mut destruction = awaiting(); destruction.destroyed(id, true);
    assert!(destruction.refused && !destruction.destroyed && destruction.reserve(true, true).is_none());
    let mut release = awaiting(); release.released(id, true);
    assert!(release.refused && !release.released && release.reserve(true, true).is_none());
    for (native_id, is_quit) in [(0, true), (id, false)] {
        let mut q = FailureQuit::default(); q.begin(None); q.closed(); q.created(native_id, is_quit);
        assert!(q.refused && q.id.is_none() && q.reserve(true, true).is_none());
    }
    let mut repeated = awaiting(); repeated.created(id, true);
    assert!(repeated.refused && repeated.reserve(true, true).is_none());
    // Missing/blocked native dialog, refused dispatch, and the original end can
    // never release a claim. No later tick recreates an owner or renews a budget.
    let mut blocked = FailureQuit::default(); blocked.begin(None);
    assert!(blocked.reserve(true, true) == Some(FailureQuitAction::Close)); blocked.closed();
    for _ in 0..3 { assert!(blocked.reserve(true, true).is_none()); }
    assert!(blocked.reserve(true, false).is_none() && blocked.refused);
    assert!(blocked.reserve(true, true).is_none());
    for mut q in [unclaimed, closing, awaiting()] {
        q.refuse(); let retained = q; q.begin(None);
        assert!(q == retained && q.reserve(true, true).is_none());
    }
    let mut due = FailureQuit::default(); due.begin(None);
    assert!(due.reserve(true, false).is_none() && !due.close_requested);
    assert!(due.reserve(true, true).is_none());
}

const PROJECT_SOURCE: &str = "plugins { id(\"com.android.application\") }\nandroid { defaultConfig { applicationId = \"org.example.mrk.observed\" } }\n";
const APP_ID: &str = "org.example.mrk.observed";
const FIELD: &str = "version.source";
const METHODS: [&str; 12] = ["capabilities", "catalog", "project.snapshot", "config.validate", "config.suggest", "config.preview",
    "github.setup.propose", "metadata.text.observe", "metadata.text.validate", "environment.requirements", "release.version.observe", "artifacts.candidate.observe"];
const TOOLKIT_REPOSITORY: &str = "example/toolkit";
const TOOLKIT_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONFLICT_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
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
const IGNORE_BYTES: u32 = 299;
const IGNORE_LINES: [&str; 10] = [".mobile-release/", ".mobile-release-init-prepare/", ".mobile-release-init/", ".mobile-release-init-cleanup/",
    ".mobile-release-metadata-text-prepare/", ".mobile-release-metadata-text/", ".mobile-release-metadata-text-cleanup/",
    ".mobile-release-version-prepare/", ".mobile-release-version/", ".mobile-release-version-cleanup/"];

// Control and synthetic DATA have distinct protected parents. No environment,
// renderer input or CLI option chooses either root.
fn control_root_from_executable(executable: &Path) -> Option<PathBuf> {
    if executable.file_name()? != OsStr::new("shell-observer") { return None; }
    let root = executable.parent()?;
    if root.parent()? != Path::new("/var/lib") { return None; }
    let parts: Vec<_> = root.file_name()?.to_str()?.strip_prefix("mrk-ubuntu-native-")?.split('-').collect();
    if parts.len() != 2 || !parts.iter().all(|part| !part.is_empty() && part.len() <= 20
        && !part.starts_with('0') && part.bytes().all(|byte| byte.is_ascii_digit())) { return None; }
    let expected = Path::new("/var/lib").join(format!("mrk-ubuntu-native-{}-{}", parts[0], parts[1]));
    if executable.as_os_str() != expected.join("shell-observer").as_os_str() { return None; }
    Some(expected)
}
fn control_root() -> Option<PathBuf> {
    control_root_from_executable(&std::env::current_exe().ok()?)
}
fn project_path_from_executable(executable: &Path) -> Option<PathBuf> {
    let control = control_root_from_executable(executable)?;
    let suffix = control.file_name()?.to_str()?.strip_prefix("mrk-ubuntu-native-")?;
    Some(Path::new("/var/lib").join(format!("mrk-ubuntu-shell-fixtures-{suffix}")).join("positive-project"))
}
fn project_path() -> Option<PathBuf> {
    project_path_from_executable(&std::env::current_exe().ok()?)
}
fn assert_shell_fixture_path_contract() {
    assert_session_fixture_roster_contract();
    // Pure path DATA: no filesystem access, GTK or native operation.
    for ids in ["10-2", "99999999999999999999-99999999999999999999"] {
        let control = Path::new("/var/lib").join(format!("mrk-ubuntu-native-{ids}"));
        let executable = control.join("shell-observer");
        assert_eq!(control_root_from_executable(&executable), Some(control));
        assert_eq!(project_path_from_executable(&executable),
            Some(Path::new("/var/lib").join(format!("mrk-ubuntu-shell-fixtures-{ids}")).join("positive-project")));
    }
    for path in ["/var/lib/mrk-ubuntu-native-10-2/shell-normal", "/tmp/mrk-ubuntu-native-10-2/shell-observer",
        "/var/lib/mrk-ubuntu-shell-fixtures-10-2/shell-observer", "/var/lib/mrk-ubuntu-native-0-2/shell-observer",
        "/var/lib/mrk-ubuntu-native-10-02/shell-observer", "/var/lib/mrk-ubuntu-native-100000000000000000000-2/shell-observer",
        "/var/lib/mrk-ubuntu-native-10-2-3/shell-observer", "/var/lib/mrk-ubuntu-native-10-x/shell-observer",
        "/var/lib/mrk-ubuntu-native-10-/shell-observer", "/var/lib/mrk-ubuntu-native-10-2/./shell-observer",
        "/var//lib/mrk-ubuntu-native-10-2/shell-observer", "var/lib/mrk-ubuntu-native-10-2/shell-observer"] {
        assert!(control_root_from_executable(Path::new(path)).is_none());
        assert!(project_path_from_executable(Path::new(path)).is_none());
    }
}

// One fixed root-prepared diagnostic leaf. O_PATH permits binding the0711
// parent without granting directory read permission to the dropped runner.
// OwnedFd closes once on every Rust return/drop path; no raw FD is exported.
fn failure_sink(case: Case) -> Option<rustix::fd::OwnedFd> {
    use std::os::unix::fs::MetadataExt;
    use rustix::fs::{self, Mode, OFlags};
    let root = control_root()?;
    for ancestor in root.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).ok()?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.gid() != 0
            || metadata.mode() & 0o022 != 0 { return None; }
    }
    let parent = fs::open(&root, OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty()).ok()?;
    let before = fs::fstat(&parent).ok()?;
    if before.st_mode != 0o040711 || before.st_uid != 0 || before.st_gid != 0 { return None; }
    let leaf = match case {
        Case::Positive => "shell-positive-failure.labels",
        Case::Outstanding => "shell-quit-outstanding-failure.labels",
        Case::ProjectPaths => "shell-project-paths-failure.labels",
        Case::WorkflowApply => "shell-workflow-apply-failure.labels",
        Case::Session(SessionCase::Inputs) => "shell-session-inputs-failure.labels",
        Case::Session(SessionCase::Refusals) => "shell-session-refusals-failure.labels",
        Case::Session(SessionCase::Loss) => "shell-session-loss-failure.labels",
        Case::Session(SessionCase::Deadline) => "shell-session-deadline-failure.labels",
        Case::MetadataSave => "shell-metadata-save-failure.labels",
        Case::VersionSave => "shell-version-save-failure.labels",
        Case::Commands(case) => case.failure_leaf(),
        Case::SettledFailure => "shell-settled-failure-failure.labels",
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
// v6 keeps every v5 field: eval saves 7B, ;g= plus its closed token adds 5B.
// Never omit/truncate a field to fit the unchanged 512B sink.
const SESSION_FAILURE_FRAME_BOUND: usize = 507;
// Path v2 retains the three lines and adds bounded timing/callback/wait DATA.
// The historical v1 reader keeps its 256B bound; the common sink is unchanged.
const PATH_FAILURE_FRAME_BOUND: usize = 384;
fn failure_pair(trace: (Step, Boundary), progress: BootstrapProgress, session: Option<SessionDiagnostic>,
    path: Option<PathDiagnostic>) -> Option<([u8; FAILURE_PAIR_LIMIT], usize)> {
    fn append(bytes: &mut [u8; FAILURE_PAIR_LIMIT], length: &mut usize, part: &[u8]) -> Option<()> {
        let end = length.checked_add(part.len())?;
        bytes.get_mut(*length..end)?.copy_from_slice(part); *length = end; Some(())
    }
    fn decimal(value: u16) -> Option<([u8; 3], usize)> {
        if value > 128 { return None; }
        Some(([b'0' + (value / 100) as u8, b'0' + ((value / 10) % 10) as u8, b'0' + (value % 10) as u8],
            if value >= 100 { 0 } else if value >= 10 { 1 } else { 2 }))
    }
    fn path_millis(bytes: &mut [u8; FAILURE_PAIR_LIMIT], length: &mut usize, value: u128) -> Option<()> {
        if value > 999_999 { return append(bytes,length,b"over"); }
        let mut digits = [b'0';6]; let mut remainder = value; let mut begin = 5;
        loop {
            digits[begin] += (remainder % 10) as u8; remainder /= 10;
            if remainder == 0 { break; }
            begin -= 1;
        }
        append(bytes,length,&digits[begin..])
    }
    let mut bytes = [0_u8; FAILURE_PAIR_LIMIT];
    let mut length = 0;
    match (trace.0, path) {
        (Step::Paths(step), Some(diagnostic)) if diagnostic.step == step && session.is_none() => {
            if step.recipe_index().is_some_and(|index| index > 10) { return None; }
            // Prefix first: a short write must not look like a complete legacy
            // three-line Path frame with its new diagnostic silently omitted.
            append(&mut bytes, &mut length, b"MRK_INSTALLED_SHELL_PATH_FAILURE=v2;index=")?;
            if let Some(index) = step.recipe_index() {
                let (digits, begin) = decimal(u16::from(index))?; append(&mut bytes, &mut length, &digits[begin..])?;
            } else { append(&mut bytes, &mut length, b"none")?; }
            append(&mut bytes, &mut length, b";reject=")?;
            append(&mut bytes, &mut length, diagnostic.rejection.token())?;
            append(&mut bytes, &mut length, b";start=")?;
            path_millis(&mut bytes,&mut length,diagnostic.step_entry_ms)?;
            append(&mut bytes, &mut length, b";now=")?;
            path_millis(&mut bytes,&mut length,diagnostic.sample_ms)?;
            for (label,count) in [(b";rsv=".as_slice(),diagnostic.reservations),
                (b";in=".as_slice(),diagnostic.entries),(b";out=".as_slice(),diagnostic.returns)] {
                append(&mut bytes,&mut length,label)?; append(&mut bytes,&mut length,count.token())?;
            }
            append(&mut bytes,&mut length,b";cb=")?;
            append(&mut bytes,&mut length,diagnostic.callback.token())?;
            append(&mut bytes,&mut length,b";wait=")?;
            append(&mut bytes,&mut length,diagnostic.wait.token())?;
            append(&mut bytes, &mut length, b"\n")?;
        },
        (Step::Paths(_), _) | (_, Some(_)) => return None,
        (_, None) => {},
    }
    append(&mut bytes, &mut length, trace.0.failure_line())?;
    append(&mut bytes, &mut length, trace.1.failure_line())?;
    append(&mut bytes, &mut length, progress.failure_line())?;
    if path.is_some() && length > PATH_FAILURE_FRAME_BOUND { return None; }
    match (trace.0, session) {
        (Step::Session(step), Some(diagnostic)) if diagnostic.step == step => {
            if diagnostic.evaluations > 128 || step.recipe_index().is_some_and(|index| index >= 64)
                || diagnostic.rejection == SessionRejection::EvaluationBudget && diagnostic.evaluations != 128
                || !diagnostic.gtk_callbacks.matches_step(step)
                || matches!(diagnostic.wait, SessionWait::GtkSelectionAbsent | SessionWait::GtkSelectionDifferent)
                    && !matches!(step, SessionStep::ActivateFile(_)) { return None; }
            append(&mut bytes, &mut length, b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v6;index=")?;
            if let Some(index) = step.recipe_index() {
                let (digits, begin) = decimal(u16::from(index))?; append(&mut bytes, &mut length, &digits[begin..])?;
            } else { append(&mut bytes, &mut length, b"none")?; }
            append(&mut bytes, &mut length, b";eval=")?;
            let (digits, begin) = decimal(diagnostic.evaluations)?; append(&mut bytes, &mut length, &digits[begin..])?;
            append(&mut bytes, &mut length, b";reject=")?;
            append(&mut bytes, &mut length, diagnostic.rejection.token())?;
            append(&mut bytes, &mut length, b";wait=")?;
            append(&mut bytes, &mut length, diagnostic.wait.token())?;
            append(&mut bytes, &mut length, b";o=")?;
            append(&mut bytes, &mut length, diagnostic.first_failure.origin_token())?;
            append(&mut bytes, &mut length, b";d=")?;
            append(&mut bytes, &mut length, diagnostic.first_failure.detail_token())?;
            append(&mut bytes, &mut length, b";a=")?;
            append(&mut bytes, &mut length, diagnostic.first_failure.association_token())?;
            append(&mut bytes, &mut length, b";q=")?;
            let (query, size) = diagnostic.first_failure.query_token();
            append(&mut bytes, &mut length, &query[..size])?;
            append(&mut bytes, &mut length, b";w=")?;
            append(&mut bytes, &mut length, diagnostic.first_failure.worker_token())?;
            let (origin, class, cause, admission) = diagnostic.assessment.tokens();
            append(&mut bytes, &mut length, b";ao=")?;
            append(&mut bytes, &mut length, origin)?;
            append(&mut bytes, &mut length, b";ac=")?;
            append(&mut bytes, &mut length, class)?;
            append(&mut bytes, &mut length, b";ax=")?;
            append(&mut bytes, &mut length, cause)?;
            append(&mut bytes, &mut length, b";af=")?;
            append(&mut bytes, &mut length, admission)?;
            append(&mut bytes, &mut length, b";u=")?;
            append(&mut bytes, &mut length, diagnostic.first_failure.unknown_boundary_token())?;
            append(&mut bytes, &mut length, b";g=")?;
            append(&mut bytes, &mut length, diagnostic.gtk_callbacks.token())?;
            append(&mut bytes, &mut length, b"\n")?;
            if length > SESSION_FAILURE_FRAME_BOUND { return None; }
        },
        (Step::Session(_), _) | (_, Some(_)) => return None,
        (_, None) => {},
    }
    Some((bytes, length))
}

#[test]
fn session_failure_frame_contract_is_inert() { assert_failure_pair_contract(); }

fn failure_frame(trace: (Step, Boundary), progress: BootstrapProgress, session: Option<SessionDiagnostic>,
    path: Option<PathDiagnostic>, evidence: Option<EvidenceDiagnostic>) -> Option<([u8; FAILURE_PAIR_LIMIT], usize)> {
    let Some(diagnostic) = evidence else { return failure_pair(trace, progress, session, path); };
    if session.is_some() || path.is_some() || !diagnostic.valid(trace) { return None; }
    let (legacy, legacy_length) = failure_pair(trace, progress, None, None)?;
    let mut bytes = [0_u8; FAILURE_PAIR_LIMIT]; let mut length = 0_usize;
    // Prefix FIRST: a partial write cannot look like a complete old frame.
    // Every value below is a closed token, never renderer/engine error text.
    for part in [b"MRK_INSTALLED_SHELL_EVIDENCE_FAILURE=v1;callback=".as_slice(), diagnostic.callback.token(),
        b";check=", diagnostic.check.token(), b";phase=", diagnostic.phase_token(),
        b";problem=", diagnostic.problem_token(), b";error=", diagnostic.error.token(), b"\n", &legacy[..legacy_length]] {
        let end = length.checked_add(part.len())?;
        bytes.get_mut(length..end)?.copy_from_slice(part); length = end;
    }
    Some((bytes, length))
}

fn assert_failure_pair_contract() {
    // Pure byte contracts only; no open, write, GTK or process work.
    for trace in [(Step::Bootstrap, Boundary::Bootstrap), (Step::PrepareSave, Boundary::Request),
        (Step::SelectProject, Boundary::Deadline), (Step::SettledFailure, Boundary::Dom),
        (Step::Exit, Boundary::Exit)] {
        for progress in [BootstrapProgress::NotSampled, BootstrapProgress::Attachment, BootstrapProgress::PageLoad,
            BootstrapProgress::OriginalRegistrySample, BootstrapProgress::AppInfoCatalog, BootstrapProgress::HeldAppInfo,
            BootstrapProgress::Advanced, BootstrapProgress::AppInfoReturnedBeforeHold] {
            let expected = [trace.0.failure_line(), trace.1.failure_line(), progress.failure_line()].concat();
            assert!(failure_pair(trace, progress, None, None).is_some_and(|(bytes, length)|
                length <= FAILURE_PAIR_LIMIT && bytes.get(..length) == Some(expected.as_slice())));
        }
    }
    for step in [Step::Bootstrap, Step::Environment, Step::Close, Step::Quit, Step::Exit] {
        for (available, capabilities) in [(false, false), (true, false), (false, true), (true, true)] {
            let result = outstanding_info(step, available, capabilities);
            assert!(result == if available || capabilities { OutstandingInfo::Unexpected }
                else if matches!(step, Step::Close | Step::Quit | Step::Exit) { OutstandingInfo::ShutdownUnavailable }
                else { OutstandingInfo::ReturnedBeforeHold });
        }
    }
    for deadline_first in [false, true] {
        let failed = FailureLatch::new(false);
        let mut trace = (Step::Bootstrap, Boundary::Bootstrap);
        let mut progress = BootstrapProgress::NotSampled;
        let deadline = ((Step::Bootstrap, Boundary::Deadline), BootstrapProgress::NotSampled);
        let early = ((Step::Bootstrap, Boundary::Result), BootstrapProgress::AppInfoReturnedBeforeHold);
        let (first, second) = if deadline_first { (deadline, early) } else { (early, deadline) };
        latch_failure(&failed, &mut trace, &mut progress, first.0, first.1);
        latch_failure(&failed, &mut trace, &mut progress, second.0, second.1);
        assert!(failed.load(Ordering::SeqCst) && trace == first.0 && progress == first.1);
    }
    let step = SessionStep::Read(63,SA::Prepare("android-keystore","save"));
    let trace = (Step::Session(step),Boundary::Settlement);
    let first = SessionDiagnostic { step, evaluations:128, rejection:SessionRejection::EvaluationBudget, wait:SessionWait::DisplayMismatch, first_failure:InstalledSessionFailure::not_recorded(), assessment:InstalledAssessmentFailure::none(), gtk_callbacks:SessionGtkCallbacks::NotApplicable };
    let expected = [step.failure_line(), Boundary::Settlement.failure_line(), BootstrapProgress::Advanced.failure_line(),
        b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v6;index=63;eval=128;reject=evaluation-budget;wait=rendered-display-mismatch;o=not-recorded;d=none;a=unassociated;q=na;w=na;ao=none;ac=na;ax=none;af=na;u=na;g=na\n"].concat();
    assert!(failure_pair(trace,BootstrapProgress::Advanced,Some(first),None).is_some_and(|(bytes,length)|
        length <= FAILURE_PAIR_LIMIT && bytes.get(..length) == Some(expected.as_slice())));
    let longest = SessionDiagnostic { step:SessionStep::QuitPreserved,evaluations:128,
        rejection:SessionRejection::UnavailableScript,wait:SessionWait::ControlsMismatch, first_failure:InstalledSessionFailure::not_recorded(), assessment:InstalledAssessmentFailure::none(), gtk_callbacks:SessionGtkCallbacks::NotApplicable };
    let expected = [longest.step.failure_line(),Boundary::Settlement.failure_line(),BootstrapProgress::AppInfoReturnedBeforeHold.failure_line(),
        b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v6;index=none;eval=128;reject=unavailable-projection-script;wait=rendered-control-mismatch;o=not-recorded;d=none;a=unassociated;q=na;w=na;ao=none;ac=na;ax=none;af=na;u=na;g=na\n"].concat();
    assert!(failure_pair((Step::Session(longest.step),Boundary::Settlement),BootstrapProgress::AppInfoReturnedBeforeHold,Some(longest),None)
        .is_some_and(|(bytes,length)|length <= FAILURE_PAIR_LIMIT && bytes.get(..length) == Some(expected.as_slice())));
    let bound = SessionDiagnostic { first_failure:InstalledSessionFailure::contract_sample(), ..longest };
    let expected = [bound.step.failure_line(),Boundary::Settlement.failure_line(),BootstrapProgress::AppInfoReturnedBeforeHold.failure_line(),
        b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v6;index=none;eval=128;reject=unavailable-projection-script;wait=rendered-control-mismatch;o=supervisor-disabled;d=none;a=bound;q=unavailable.spawn-other.xf;w=settle-unknown;ao=none;ac=na;ax=none;af=na;u=settlement;g=na\n"].concat();
    assert!(failure_pair((Step::Session(bound.step),Boundary::Settlement),BootstrapProgress::AppInfoReturnedBeforeHold,Some(bound),None)
        .is_some_and(|(bytes,length)|length <= SESSION_FAILURE_FRAME_BOUND && bytes.get(..length) == Some(expected.as_slice())
            && bytes[..length].is_ascii() && bytes[..length].iter().filter(|byte| **byte == b'\n').count() == 4));
    let (origin_bound, class_bound, cause_bound, admission_bound) = InstalledAssessmentFailure::token_bounds();
    assert!(origin_bound <= 7 && class_bound <= 24 && cause_bound <= 11 && admission_bound <= 22);
    assert_eq!(311 + 5 * 3 + 19 + 15 + 12 + 26 + 14 + 3 * 4 + 7 + 24 + 11 + 4 + 22 + 3 + 14 - 7 + 5, SESSION_FAILURE_FRAME_BOUND);
    assert_eq!(FAILURE_PAIR_LIMIT - SESSION_FAILURE_FRAME_BOUND, 5);
    for evaluations in [0,9,10,99,100,128] {
        for step in [SessionStep::Navigate,SessionStep::Read(0,SA::Prepare("android-keystore","save")),SessionStep::Read(63,SA::ReviewRemoval(1))] {
            let diagnostic = SessionDiagnostic { step,evaluations,rejection:SessionRejection::NotRecorded,wait:SessionWait::NotSampled, first_failure:InstalledSessionFailure::not_recorded(), assessment:InstalledAssessmentFailure::none(), gtk_callbacks:SessionGtkCallbacks::NotApplicable };
            let expected = format!("MRK_INSTALLED_SHELL_SESSION_FAILURE=v6;index={};eval={evaluations};reject=not-recorded;wait=not-sampled;o=not-recorded;d=none;a=unassociated;q=na;w=na;ao=none;ac=na;ax=none;af=na;u=na;g=na\n",
                step.recipe_index().map_or_else(|| "none".to_owned(),|index|index.to_string()));
            assert!(failure_pair((Step::Session(step),Boundary::Settlement),BootstrapProgress::Advanced,Some(diagnostic),None)
                .is_some_and(|(bytes,length)|bytes[..length].ends_with(expected.as_bytes())));
        }
    }
    assert!(failure_pair(trace,BootstrapProgress::Advanced,None,None).is_none());
    assert!(failure_pair((Step::Bootstrap,Boundary::Bootstrap),BootstrapProgress::NotSampled,Some(first),None).is_none());
    for bad in [SessionDiagnostic { step:SessionStep::Read(62,SA::Prepare("android-keystore","save")),..first },
        SessionDiagnostic { evaluations:129,..first },SessionDiagnostic { evaluations:127,..first }] {
        assert!(failure_pair(trace,BootstrapProgress::Advanced,Some(bad),None).is_none());
    }
    let outside = SessionDiagnostic { step:SessionStep::Read(64,SA::Prepare("android-keystore","save")),..first };
    assert!(failure_pair((Step::Session(outside.step),Boundary::Settlement),BootstrapProgress::Advanced,Some(outside),None).is_none());
    let sampled = SessionDiagnostic::sample(trace.0,127,Some(first)).unwrap();
    assert!(sampled.wait == SessionWait::DisplayMismatch && sampled.rejection == SessionRejection::NotRecorded && sampled.evaluations == 127);
    let other = SessionStep::Read(62,SA::Prepare("android-keystore","save"));
    assert!(SessionDiagnostic::sample(Step::Session(other),128,Some(first)).unwrap().wait == SessionWait::NotSampled);
    assert!(SessionDiagnostic::sample(Step::Close,128,Some(first)).is_none());
    let failed = FailureLatch::new(false); let mut retained = None;
    latch_session_diagnostic(&failed,&mut retained,first);
    latch_session_diagnostic(&failed,&mut retained,SessionDiagnostic { step:other,wait:SessionWait::ReplyPending,
        first_failure:bound.first_failure,..first });
    assert!(retained == Some(first));
    assert_eq!(retained.unwrap().first_failure.unknown_boundary_token(), b"na");
    let mut frozen_trace = trace; let mut progress = BootstrapProgress::Advanced;
    assert!(!latch_failure(&failed,&mut frozen_trace,&mut progress,(Step::Session(other),Boundary::Deadline),BootstrapProgress::NotSampled));
    assert!(retained == Some(first) && frozen_trace == trace && progress == BootstrapProgress::Advanced);
    let failed = FailureLatch::new(false);
    let deadline_diagnostic = SessionDiagnostic::sample(trace.0,127,Some(first));
    let mut retained = None;
    if latch_failure(&failed,&mut frozen_trace,&mut progress,(trace.0,Boundary::Deadline),BootstrapProgress::Advanced) {
        retained = deadline_diagnostic;
    }
    latch_session_diagnostic(&failed,&mut retained,first);
    assert!(retained == deadline_diagnostic && frozen_trace == (trace.0,Boundary::Deadline));
    let failed = FailureLatch::new(false); let mut retained = None;
    latch_session_diagnostic(&failed,&mut retained,bound);
    latch_session_diagnostic(&failed,&mut retained,first);
    assert!(retained == Some(bound));
    assert_eq!(retained.unwrap().first_failure.unknown_boundary_token(), b"settlement");
    assert!(!latch_failure(&failed,&mut frozen_trace,&mut progress,(trace.0,Boundary::Deadline),BootstrapProgress::NotSampled));
    assert!(retained == Some(bound));
    assert!(SessionDiagnostic::sample(Step::Session(bound.step),128,Some(bound)).unwrap().first_failure
        == InstalledSessionFailure::not_recorded());

    let mut gtk_callbacks = SessionGtkCallbacks::initial(SessionStep::ActivateFile(3));
    gtk_callbacks.reserved(); gtk_callbacks.wait_observed();
    let gtk = SessionDiagnostic { step:SessionStep::ActivateFile(3),evaluations:16,
        rejection:SessionRejection::GtkObserverEndpoint,wait:SessionWait::GtkActionInsensitive, first_failure:InstalledSessionFailure::not_recorded(), assessment:InstalledAssessmentFailure::none(), gtk_callbacks };
    let gtk_trace = (Step::Session(gtk.step),Boundary::Gtk);
    let expected = [gtk.step.failure_line(),Boundary::Gtk.failure_line(),BootstrapProgress::Advanced.failure_line(),
        b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v6;index=3;eval=16;reject=gtk-observer-endpoint;wait=gtk-action-insensitive;o=not-recorded;d=none;a=unassociated;q=na;w=na;ao=none;ac=na;ax=none;af=na;u=na;g=0w\n"].concat();
    assert!(failure_pair(gtk_trace,BootstrapProgress::Advanced,Some(gtk),None).is_some_and(|(bytes,length)|
        length <= FAILURE_PAIR_LIMIT && bytes.get(..length) == Some(expected.as_slice())));
    let same = SessionDiagnostic::sample(gtk_trace.0,16,Some(gtk)).unwrap();
    assert!(same.wait == SessionWait::GtkActionInsensitive && same.rejection == SessionRejection::NotRecorded);
    for step in [SessionStep::SetFile(3),SessionStep::ActivateFile(4)] {
        assert!(SessionDiagnostic::sample(Step::Session(step),16,Some(gtk)).unwrap().wait == SessionWait::NotSampled);
    }
    for activating in [false,true] {
        let actual = Step::Session(if activating { SessionStep::ActivateFile(3) } else { SessionStep::SetFile(3) });
        let pending = Some(Pending::Dom(actual));
        assert!(session_file_wait_pending(actual,pending,3,activating));
        assert!(!session_file_wait_pending(actual,pending,3,!activating));
        assert!(!session_file_wait_pending(actual,pending,4,activating));
        for wrong in [None,Some(Pending::Gtk),Some(Pending::Dom(Step::Session(SessionStep::Capture(3)))),
            Some(Pending::Dom(Step::Session(if activating { SessionStep::SetFile(3) } else { SessionStep::ActivateFile(3) }))),
            Some(Pending::Dom(Step::Session(if activating { SessionStep::ActivateFile(4) } else { SessionStep::SetFile(4) })))] {
            assert!(!session_file_wait_pending(actual,wrong,3,activating));
        }
        assert!(!session_file_wait_pending(Step::Session(SessionStep::Capture(3)),pending,3,activating));
    }
    for deadline_first in [false,true] {
        let failed = FailureLatch::new(false);
        let mut trace = gtk_trace;
        let mut progress = BootstrapProgress::Advanced;
        let mut retained = Some(same);
        for deadline in [deadline_first,!deadline_first] {
            if deadline {
                if latch_failure(&failed,&mut trace,&mut progress,(gtk_trace.0,Boundary::Deadline),BootstrapProgress::Advanced) {
                    retained = Some(same);
                }
            } else {
                // record_at(Gtk) may update the trace only before first failure.
                if !failed.load(Ordering::SeqCst) { trace = gtk_trace; }
                latch_session_diagnostic(&failed,&mut retained,gtk);
            }
        }
        assert!(failed.load(Ordering::SeqCst) && progress == BootstrapProgress::Advanced);
        assert!(trace == if deadline_first { (gtk_trace.0,Boundary::Deadline) } else { gtk_trace });
        assert!(retained == Some(if deadline_first { same } else { gtk }));
    }
    // Closed helper progress is not native liveness or original-owner finality.
    let mut na = SessionGtkCallbacks::initial(SessionStep::Navigate);
    na.reserved(); na.wait_observed(); na.returned();
    assert_eq!(na.token(), b"na");
    assert!(!na.matches_step(SessionStep::ActivateFile(3)));
    for step in [SessionStep::SetFile(3), SessionStep::ActivateFile(3)] {
        let mut callbacks = SessionGtkCallbacks::initial(step);
        assert_eq!(callbacks.token(), b"0i");
        callbacks.reserved(); assert_eq!(callbacks.token(), b"0p");
        callbacks.wait_observed(); assert_eq!(callbacks.token(), b"0w");
        callbacks.returned(); assert_eq!(callbacks.token(), b"1i");
        callbacks.reserved(); assert_eq!(callbacks.token(), b"1p");
        callbacks.wait_observed(); assert_eq!(callbacks.token(), b"1w");
        callbacks.returned(); assert_eq!(callbacks.token(), b"mi");
        for _ in 0..3 {
            callbacks.reserved(); assert_eq!(callbacks.token(), b"mp");
            callbacks.wait_observed(); assert_eq!(callbacks.token(), b"mw");
            callbacks.returned(); assert_eq!(callbacks.token(), b"mi");
        }
        let diagnostic = SessionDiagnostic { step, gtk_callbacks:callbacks, ..gtk };
        assert!(SessionDiagnostic::sample(Step::Session(step),16,Some(diagnostic)).unwrap().gtk_callbacks == callbacks);
        for other in [SessionStep::SetFile(4),SessionStep::ActivateFile(4),SessionStep::Navigate] {
            assert!(SessionDiagnostic::sample(Step::Session(other),16,Some(diagnostic)).unwrap().gtk_callbacks
                == SessionGtkCallbacks::initial(other));
        }
        let other_role = if matches!(step,SessionStep::SetFile(_)) { SessionStep::ActivateFile(3) } else { SessionStep::SetFile(3) };
        assert_eq!(SessionDiagnostic::sample(Step::Session(other_role),16,Some(diagnostic)).unwrap().gtk_callbacks.token(),b"0i");
        assert!(!callbacks.matches_step(SessionStep::Capture(3)));
    }
    for wait in [SessionWait::GtkSelectionAbsent,SessionWait::GtkSelectionDifferent] {
        let diagnostic = SessionDiagnostic { wait,..gtk };
        assert!(failure_pair(gtk_trace,BootstrapProgress::Advanced,Some(diagnostic),None).is_some_and(|(bytes,length)|
            length <= SESSION_FAILURE_FRAME_BOUND && bytes[..length].ends_with(b";u=na;g=0w\n")));
        let wrong_role = SessionDiagnostic { step:SessionStep::SetFile(3),..diagnostic };
        assert!(failure_pair((Step::Session(wrong_role.step),Boundary::Gtk),BootstrapProgress::Advanced,Some(wrong_role),None).is_none());
    }
    assert!(failure_pair(gtk_trace,BootstrapProgress::Advanced,
        Some(SessionDiagnostic { gtk_callbacks:SessionGtkCallbacks::NotApplicable,..gtk }),None).is_none());
    for deadline_first in [false,true] {
        let failed = FailureLatch::new(false);
        let mut trace = gtk_trace; let mut progress = BootstrapProgress::Advanced;
        let mut retained = Some(gtk); let mut pending = Some(Pending::Dom(gtk_trace.0));
        if deadline_first { assert!(latch_failure(&failed,&mut trace,&mut progress,(gtk_trace.0,Boundary::Deadline),BootstrapProgress::Advanced)); }
        // Actual return authentication consumes pending even after failure.
        assert!(pending.take() == Some(Pending::Dom(gtk_trace.0)));
        if !failed.load(Ordering::SeqCst) { retained.as_mut().unwrap().gtk_callbacks.returned(); }
        assert!(pending.is_none());
        if !deadline_first { assert!(latch_failure(&failed,&mut trace,&mut progress,(gtk_trace.0,Boundary::Deadline),BootstrapProgress::Advanced)); }
        let frozen = retained;
        if !failed.load(Ordering::SeqCst) { retained.as_mut().unwrap().gtk_callbacks.returned(); }
        assert!(retained == frozen);
        assert_eq!(retained.unwrap().gtk_callbacks.token(),if deadline_first { b"0w" } else { b"1i" });
    }
    // Inert codes only: these contracts do not identify a historical failure.
    for (code, rejection) in [("asset_deadline",SessionRejection::ReplyAssetDeadline),
        ("assessment_context_stale",SessionRejection::ReplyAssessmentContextStale),
        ("assessment_unavailable",SessionRejection::ReplyAssessmentUnavailable),
        ("asset_unsupported_filesystem",SessionRejection::ReplyAssetUnsupportedFilesystem),
        ("asset_exclusion_unconfirmed",SessionRejection::ReplyAssetExclusionUnconfirmed),
        ("",SessionRejection::ReplyCodeUnavailable), ("future_code",SessionRejection::ReplyCodeUnavailable),
        ("asset_deadline\n/private/inert",SessionRejection::ReplyCodeUnavailable)] {
        assert!(session_reply_rejection(code) == rejection);
    }
    for (reason, rejection) in [(Some("cleanup-unknown"),SessionRejection::CapabilityCleanupUnknown),
        (Some("shutdown"),SessionRejection::CapabilityShutdown), (None,SessionRejection::CapabilityUnavailable),
        (Some("none"),SessionRejection::CapabilityUnavailable), (Some("future-reason"),SessionRejection::CapabilityUnavailable)] {
        assert!(session_capability_rejection(reason) == rejection);
    }
    let step = SessionStep::Read(29,SA::Prepare("android-keystore","save"));
    let trace = (Step::Session(step),Boundary::Settlement);
    let pending = SessionDiagnostic { step,evaluations:73,rejection:SessionRejection::NotRecorded,wait:SessionWait::ReplyPending, first_failure:InstalledSessionFailure::not_recorded(), assessment:InstalledAssessmentFailure::none(), gtk_callbacks:SessionGtkCallbacks::NotApplicable };
    let sampled = SessionDiagnostic::sample(trace.0,73,Some(pending)).unwrap();
    assert!(sampled.wait == SessionWait::ReplyPending && sampled.rejection == SessionRejection::NotRecorded);
    assert!(SessionRejection::ReplyAssessmentInvalidRequest.token().len() == 32);
    for rejection in [SessionRejection::ReplyAssessmentInvalidRequest,SessionRejection::ReplyAssessmentUnavailable,
        SessionRejection::ReplyCodeUnavailable,SessionRejection::CapabilityUnavailable] {
        let diagnostic = SessionDiagnostic { rejection,..sampled };
        let expected = [step.failure_line(),Boundary::Settlement.failure_line(),BootstrapProgress::Advanced.failure_line(),
            b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v6;index=29;eval=73;reject=",rejection.token(),
            b";wait=native-reply-pending;o=not-recorded;d=none;a=unassociated;q=na;w=na;ao=none;ac=na;ax=none;af=na;u=na;g=na\n"].concat();
        assert!(failure_pair(trace,BootstrapProgress::Advanced,Some(diagnostic),None).is_some_and(|(bytes,length)|
            length <= FAILURE_PAIR_LIMIT && bytes.get(..length) == Some(expected.as_slice())));
    }
    let typed = SessionDiagnostic { rejection:SessionRejection::ReplyAssetDeadline,..sampled };
    for deadline_first in [false,true] {
        let failed = FailureLatch::new(false); let mut retained = Some(sampled);
        let mut frozen_trace = trace; let mut progress = BootstrapProgress::Advanced;
        for deadline in [deadline_first,!deadline_first] {
            if deadline {
                if latch_failure(&failed,&mut frozen_trace,&mut progress,(trace.0,Boundary::Deadline),BootstrapProgress::Advanced) {
                    retained = Some(sampled);
                }
            } else { latch_session_diagnostic(&failed,&mut retained,typed); }
        }
        latch_session_diagnostic(&failed,&mut retained,SessionDiagnostic { rejection:SessionRejection::LostNativeSnapshot,..typed });
        assert!(retained == Some(if deadline_first { sampled } else { typed }));
        assert!(frozen_trace == if deadline_first { (trace.0,Boundary::Deadline) } else { trace });
    }

    // A previous wait is not a returned outcome. Capture only this ordinal's
    // Prepare error, and latch rejection + packet together without sampling R1.
    let packet = InstalledAssessmentFailure::contract_sample();
    assert_eq!(packet.tokens().3, b"missing-compile-anchor");
    let reply = SessionReply { error:Some("assessment_unavailable".to_owned()),ordinal:2,assessment:packet,..SessionReply::default() };
    let original = session_reply_refusal(SessionCommand::Prepare.index(),2,2,1,&reply).unwrap();
    assert!(original.rejection == SessionRejection::ReplyAssessmentUnavailable && original.assessment == packet);
    for (command,requested,returned,base) in [(SessionCommand::Prepare,2,1,1), (SessionCommand::Prepare,2,2,2),
        (SessionCommand::Prepare,3,3,2), (SessionCommand::Prepare,2,3,1), (SessionCommand::Prepare,0,0,255),
        (SessionCommand::Context,2,2,1), (SessionCommand::Choose,2,2,1)] {
        let refused = session_reply_refusal(command.index(),requested,returned,base,&reply).unwrap();
        assert!(refused.rejection == original.rejection && refused.assessment == InstalledAssessmentFailure::none());
    }
    let absent = SessionReply { error:Some("assessment_unavailable".to_owned()),ordinal:2,..SessionReply::default() };
    assert!(session_reply_refusal(SessionCommand::Prepare.index(),2,2,1,&absent).unwrap().assessment == InstalledAssessmentFailure::none());
    let successful = SessionReply { status:Some(Value::Null),ordinal:2,assessment:packet,..SessionReply::default() };
    assert!(session_reply_refusal(SessionCommand::Prepare.index(),2,2,1,&successful).is_none());
    for action in [SA::Prepare("android-keystore","missing"),SA::Reassess(0,"android-keystore")] {
        let step = SessionStep::Read(6,action); let trace = (Step::Session(step),Boundary::Settlement);
        let pending = SessionDiagnostic { step,evaluations:13,wait:SessionWait::ReplyPending,
            rejection:SessionRejection::NotRecorded,first_failure:InstalledSessionFailure::not_recorded(),assessment:InstalledAssessmentFailure::none(), gtk_callbacks:SessionGtkCallbacks::NotApplicable };
        let sampled = SessionDiagnostic::sample(trace.0,13,Some(pending)).unwrap();
        let rejected = SessionDiagnostic { rejection:original.rejection,assessment:original.assessment,..sampled };
        let expected = [step.failure_line(),Boundary::Settlement.failure_line(),BootstrapProgress::Advanced.failure_line(),
            b"MRK_INSTALLED_SHELL_SESSION_FAILURE=v6;index=6;eval=13;reject=reply-assessment-unavailable;wait=native-reply-pending;o=not-recorded;d=none;a=unassociated;q=na;w=na;ao=bridge;ac=runtime-unavailable;ax=prepare;af=missing-compile-anchor;u=na;g=na\n"].concat();
        assert!(failure_pair(trace,BootstrapProgress::Advanced,Some(rejected),None).is_some_and(|(bytes,length)|
            length <= SESSION_FAILURE_FRAME_BOUND && bytes.get(..length) == Some(expected.as_slice())));
        assert!(SessionDiagnostic::sample(trace.0,13,Some(rejected)).unwrap().assessment == InstalledAssessmentFailure::none());
        for first in [rejected,SessionDiagnostic { assessment:InstalledAssessmentFailure::none(),..rejected }] {
            let failed = FailureLatch::new(false); let mut retained = Some(sampled);
            latch_session_diagnostic(&failed,&mut retained,first);
            latch_session_diagnostic(&failed,&mut retained,SessionDiagnostic { rejection:SessionRejection::LostNativeSnapshot,
                first_failure:InstalledSessionFailure::contract_sample(),assessment:InstalledAssessmentFailure::contract_result_sample(),..rejected });
            assert!(retained == Some(first)); // An absent first packet cannot be filled later either.
            // Nor may a later original admission fill/replace the first packet.
            latch_session_diagnostic(&failed,&mut retained,rejected);
            assert!(retained == Some(first));
        }
        for deadline_first in [false,true] {
            let failed = FailureLatch::new(false); let mut retained = Some(sampled);
            let mut frozen_trace = trace; let mut progress = BootstrapProgress::Advanced;
            for deadline in [deadline_first,!deadline_first] {
                if deadline {
                    if latch_failure(&failed,&mut frozen_trace,&mut progress,(trace.0,Boundary::Deadline),BootstrapProgress::Advanced) { retained = Some(sampled); }
                } else { latch_session_diagnostic(&failed,&mut retained,rejected); }
            }
            assert!(retained == Some(if deadline_first { sampled } else { rejected }));
            assert!(frozen_trace == if deadline_first { (trace.0,Boundary::Deadline) } else { trace });
        }
    }

    // Path frames start with their version; recipe IDs never name previews.
    for index in 0..=10 {
        for step in [PathStep::Browse(index),PathStep::Set(index),PathStep::Activate(index),PathStep::Settled(index),PathStep::ReadField(index)] {
            assert_eq!(step.recipe_index(),Some(index));
            let diagnostic = PathDiagnostic::sample(Step::Paths(step),0,None).unwrap();
            let callback = if matches!(step,PathStep::Set(_) | PathStep::Activate(_)) { "idle" } else { "na" };
            let prefix = format!("MRK_INSTALLED_SHELL_PATH_FAILURE=v2;index={index};reject=not-recorded;start=0;now=0;rsv=0;in=0;out=0;cb={callback};wait=not-sampled\n");
            let expected = [prefix.as_bytes(),step.failure_line(),Boundary::Gtk.failure_line(),BootstrapProgress::Advanced.failure_line()].concat();
            assert!(failure_pair((Step::Paths(step),Boundary::Gtk),BootstrapProgress::Advanced,None,Some(diagnostic))
                .is_some_and(|(bytes,length)|length <= PATH_FAILURE_FRAME_BOUND && bytes.get(..length) == Some(expected.as_slice())));
        }
    }
    for step in [PathStep::Start,PathStep::ReadDraft,PathStep::Preview(0),PathStep::Preview(1),PathStep::Preview(2),
        PathStep::ReadPreview(0),PathStep::ReadPreview(1),PathStep::ReadPreview(2),PathStep::Ios,PathStep::Metadata,
        PathStep::Settings,PathStep::General,PathStep::FinalIos] {
        assert_eq!(step.recipe_index(),None);
        let diagnostic = PathDiagnostic::sample(Step::Paths(step),0,None).unwrap();
        let expected = [b"MRK_INSTALLED_SHELL_PATH_FAILURE=v2;index=none;reject=not-recorded;start=0;now=0;rsv=0;in=0;out=0;cb=na;wait=not-sampled\n".as_slice(),step.failure_line(),
            Boundary::Settlement.failure_line(),BootstrapProgress::AppInfoReturnedBeforeHold.failure_line()].concat();
        assert!(failure_pair((Step::Paths(step),Boundary::Settlement),BootstrapProgress::AppInfoReturnedBeforeHold,None,Some(diagnostic))
            .is_some_and(|(bytes,length)|length <= PATH_FAILURE_FRAME_BOUND && bytes.get(..length) == Some(expected.as_slice())));
    }
    let path_step = PathStep::Activate(0);
    let path_trace = (Step::Paths(path_step),Boundary::Gtk);
    let path_plain = PathDiagnostic::sample(path_trace.0,0,None).unwrap();
    let path_gtk = PathDiagnostic { rejection:PathRejection::GtkInitialFolder,..path_plain };
    let expected = [b"MRK_INSTALLED_SHELL_PATH_FAILURE=v2;index=0;reject=gtk-initial-folder;start=0;now=0;rsv=0;in=0;out=0;cb=idle;wait=not-sampled\n".as_slice(),
        path_step.failure_line(),Boundary::Gtk.failure_line(),BootstrapProgress::Advanced.failure_line()].concat();
    assert!(failure_pair(path_trace,BootstrapProgress::Advanced,None,Some(path_gtk))
        .is_some_and(|(bytes,length)|bytes.get(..length) == Some(expected.as_slice()) && bytes[..length].is_ascii()
            && bytes[..length].iter().filter(|byte| **byte == b'\n').count() == 4));
    assert!(failure_pair(path_trace,BootstrapProgress::Advanced,None,None).is_none());
    assert!(failure_pair(path_trace,BootstrapProgress::Advanced,Some(first),Some(path_gtk)).is_none());
    assert!(failure_pair(gtk_trace,BootstrapProgress::Advanced,Some(gtk),Some(path_gtk)).is_none());
    assert!(failure_pair((Step::Close,Boundary::Gtk),BootstrapProgress::Advanced,None,Some(path_gtk)).is_none());
    for step in [PathStep::Set(0),PathStep::Activate(1)] {
        assert!(failure_pair(path_trace,BootstrapProgress::Advanced,None,Some(PathDiagnostic { step,..path_gtk })).is_none());
    }
    for index in [11,255] {
        for step in [PathStep::Browse(index),PathStep::Set(index),PathStep::Activate(index),PathStep::Settled(index),PathStep::ReadField(index)] {
            let diagnostic = PathDiagnostic::sample(Step::Paths(step),0,None).unwrap();
            assert!(failure_pair((Step::Paths(step),Boundary::Gtk),BootstrapProgress::Advanced,None,Some(diagnostic)).is_none());
        }
    }
    assert!(PathDiagnostic::sample(Step::Close,0,None).is_none());
    let extension = b";start=999999;now=999999;rsv=m;in=m;out=m;cb=reserved;wait=initial-folder-absent";
    assert!(174 + 77 + extension.len() <= PATH_FAILURE_FRAME_BOUND && PATH_FAILURE_FRAME_BOUND < FAILURE_PAIR_LIMIT);
    let mut timed = PathDiagnostic::sample(path_trace.0,43_000,None).unwrap();
    for round in 0..3 {
        timed.mark(PathCallback::Reserved);
        assert!(timed.callback == PathCallback::Reserved && timed.reservations == if round == 0 { PathCount::One } else { PathCount::Many });
        timed.mark(PathCallback::Entered); timed.wait = PathWait::SelectionDifferent;
        timed.mark(PathCallback::Returned);
        timed = PathDiagnostic::sample(path_trace.0,44_000 + round,Some(timed)).unwrap();
    }
    assert!(timed.step_entry_ms == 43_000 && timed.sample_ms == 44_002 && timed.wait == PathWait::SelectionDifferent
        && timed.entries == PathCount::Many && timed.returns == PathCount::Many && timed.callback == PathCallback::Returned);
    let reset = PathDiagnostic::sample(Step::Paths(PathStep::Activate(1)),44_010,Some(timed)).unwrap();
    assert!(reset.step_entry_ms == 44_010 && reset.sample_ms == 44_010 && reset.wait == PathWait::NotSampled
        && reset.reservations == PathCount::Zero && reset.entries == PathCount::Zero && reset.returns == PathCount::Zero);
    for time in [999_999,1_000_000,u128::MAX] {
        let maximal = PathDiagnostic { step_entry_ms:time,sample_ms:time,wait:PathWait::InitialFolderAbsent,
            rejection:PathRejection::GtkFixtureTransition,..timed };
        let (bytes,length) = failure_pair(path_trace,BootstrapProgress::AppInfoReturnedBeforeHold,None,Some(maximal)).unwrap();
        let text = std::str::from_utf8(&bytes[..length]).unwrap();
        assert!(length <= PATH_FAILURE_FRAME_BOUND && text.contains(if time == 999_999 { ";start=999999;now=999999;" } else { ";start=over;now=over;" }));
    }
    let frozen = FailureLatch::new(false); let mut retained = Some(timed);
    latch_path_diagnostic(&frozen,&mut retained,PathDiagnostic { rejection:PathRejection::GtkDispatch,..timed });
    let first_timed = retained;
    latch_path_diagnostic(&frozen,&mut retained,reset);
    assert!(retained == first_timed && retained.unwrap().step_entry_ms == 43_000);
    // A generic failure can arrive immediately after a step transition, before
    // record_at runs again. Its complete frame must use the actual new step.
    let mut transition_trace = path_trace;
    let next = PathDiagnostic::sample_trace(&mut transition_trace,Step::Paths(PathStep::Activate(1)),44_010,Some(timed));
    let generic_failure = FailureLatch::new(false); generic_failure.mark_unknown();
    assert!(generic_failure.load(Ordering::SeqCst) && transition_trace == (Step::Paths(PathStep::Activate(1)),Boundary::Gtk)
        && next == Some(reset) && failure_pair(transition_trace,BootstrapProgress::Advanced,None,next).is_some());
    let leaving = PathDiagnostic::sample_trace(&mut transition_trace,Step::Close,44_020,next);
    assert!(leaving.is_none() && transition_trace == (Step::Close,Boundary::Gtk)
        && failure_pair(transition_trace,BootstrapProgress::Advanced,None,leaving).is_some());
    let mut unrelated = (Step::Environment,Boundary::Dom);
    assert!(PathDiagnostic::sample_trace(&mut unrelated,Step::ReadEnvironment,20,None).is_none()
        && unrelated == (Step::Environment,Boundary::Dom));
    // Each possible first winner retains matching trace/reason. A later return
    // at another recipe cannot erase a real GTK cause or invent one for generic
    // failure/deadline. The actual callbacks perform these writes under Record.
    for order in [[0,1,2],[0,2,1],[1,0,2],[1,2,0],[2,0,1],[2,1,0]] {
        let failed = FailureLatch::new(false);
        let original_trace = (path_trace.0,Boundary::Settlement);
        let mut trace = original_trace; let mut progress = BootstrapProgress::Advanced;
        let mut retained = Some(path_plain);
        for event in order {
            match event {
                0 => { failed.mark_unknown(); },
                1 => {
                    if !failed.load(Ordering::SeqCst) { trace = path_trace; retained = PathDiagnostic::sample(path_trace.0,0,retained); }
                    latch_path_diagnostic(&failed,&mut retained,path_gtk);
                },
                2 => {
                    let next = PathDiagnostic::sample(path_trace.0,0,retained);
                    if latch_failure(&failed,&mut trace,&mut progress,(path_trace.0,Boundary::Deadline),BootstrapProgress::Advanced) { retained = next; }
                },
                _ => unreachable!(),
            }
        }
        latch_path_diagnostic(&failed,&mut retained,PathDiagnostic { step:PathStep::Activate(4),rejection:PathRejection::GtkReturnState,..path_plain });
        assert!(failed.load(Ordering::SeqCst) && progress == BootstrapProgress::Advanced);
        assert!(retained == Some(if order[0] == 1 { path_gtk } else { path_plain }));
        assert!(trace == match order[0] { 0 => original_trace,1 => path_trace,_ => (path_trace.0,Boundary::Deadline) });
    }
}

// Original destruction facts only. ProjectPath records an admitted Cancel as
// declined; ordinary project/evidence pickers deliberately do not. Later close,
// release and document-owner settlement are separate observations.
pub(super) fn file_destroyed(facts: &crate::asset_session::GuiFacts, path_choice: bool) -> bool {
    facts.destroyed && facts.response && facts.refusal.is_none()
        && if path_choice { facts.accepted != facts.declined } else { !facts.declined }
}

fn assert_file_destroyed_contract() {
    use crate::asset_session::GuiFacts;
    let facts = |accepted, declined| GuiFacts {
        dispatched: true, constructing: false, created: true, showing: false,
        response: true, accepted, declined, accepted_at: None,
        destroyed: true, released: false, not_created: false,
        close_queued: true, close_ack: false, release_queued: false,
        selected: None, refusal: None,
    };
    // These synthetic values prove only the predicate, never native finality.
    for (path_choice, accepted, declined, expected) in [
        (true, true, false, true), (true, false, true, true),
        (true, false, false, false), (true, true, true, false),
        (false, true, false, true), (false, false, false, true),
        (false, false, true, false), (false, true, true, false),
    ] {
        assert_eq!(file_destroyed(&facts(accepted, declined), path_choice), expected);
        if expected {
            let mut missing = facts(accepted, declined); missing.destroyed = false;
            assert!(!file_destroyed(&missing, path_choice));
            let mut missing = facts(accepted, declined); missing.response = false;
            assert!(!file_destroyed(&missing, path_choice));
            let mut refused = facts(accepted, declined); refused.refusal = Some(PR::SourceRefused);
            assert!(!file_destroyed(&refused, path_choice));
        }
    }
}

#[derive(Default)]
struct Picker {
    created: bool, selected: bool, activated: bool, responded: bool, filename: bool,
    disposal: bool, destroyed: bool, released: bool, returned: bool,
}
impl Picker {
    fn activation_returned(&mut self, result: Result<bool, ()>) -> bool {
        // Only the actual completed activation callback latches return. GTK
        // may defer its genuine response until after emit_clicked unwinds.
        if result != Ok(true) || !self.created || !self.activated || self.returned { return false; }
        self.returned = true; true
    }
    fn settled(&self, select: bool) -> bool {
        self.created && self.activated && self.responded && self.destroyed && self.released && self.returned
            && self.selected == select && self.filename == select
    }
}

fn assert_picker_activation_return_contract() {
    // Inert state assertions only, never native response or settlement receipts.
    for select in [false, true] {
        for response_first in [false, true] {
            let mut p = Picker { created: true, selected: select, activated: true, ..Picker::default() };
            if response_first { p.responded = true; p.filename = select; }
            assert!(p.activation_returned(Ok(true)));
            assert!(!p.settled(select));
            assert!(!p.activation_returned(Ok(true))); // No second activation return.
            if !response_first { p.responded = true; p.filename = select; }
            assert!(!p.settled(select));
            p.destroyed = true; assert!(!p.settled(select));
            p.released = true; assert!(p.settled(select));
            assert!(!p.settled(!select));
        }
        let complete = || Picker { created: true, selected: select, activated: true, responded: true,
            filename: select, destroyed: true, released: true, returned: true, ..Picker::default() };
        for incomplete in [Picker { created: false, ..complete() }, Picker { activated: false, ..complete() },
            Picker { responded: false, ..complete() }, Picker { destroyed: false, ..complete() },
            Picker { released: false, ..complete() }, Picker { returned: false, ..complete() },
            Picker { selected: !select, ..complete() }, Picker { filename: !select, ..complete() }] {
            assert!(!incomplete.settled(select));
        }
        for result in [Ok(false), Err(())] {
            let mut p = Picker { created: true, selected: select, activated: true, ..Picker::default() };
            assert!(!p.activation_returned(result)); assert!(!p.returned);
        }
    }
    for (created, activated) in [(false, true), (true, false)] {
        let mut p = Picker { created, activated, ..Picker::default() };
        assert!(!p.activation_returned(Ok(true))); assert!(!p.returned);
    }
}

// One closed native path case. Operation indices refer only to this fixed
// eleven-item roster, never renderer-supplied actions or filesystem authority.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PathStep { Start, ReadDraft, Preview(u8), ReadPreview(u8), Browse(u8), Set(u8), Activate(u8),
    Settled(u8), ReadField(u8), Ios, Metadata, Settings, General, FinalIos }
impl PathStep {
    fn recipe_index(self) -> Option<u8> {
        match self {
            Self::Browse(index) | Self::Set(index) | Self::Activate(index) | Self::Settled(index) | Self::ReadField(index) => Some(index),
            // Preview indices are rounds, not entries in PATH_CASES.
            _ => None,
        }
    }
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
// Closed observer DATA only: no filename, private path, identifier or native
// query is retained or produced by these diagnostics.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PathRejection { NotRecorded, GtkThread, GtkDialogBook, GtkDialogOriginal, GtkOwnerBinding,
    GtkOwnerInterrupted, GtkOwnerFacts, GtkDialogProperties, GtkInitialFolder, GtkTarget, GtkSelectionSetter,
    GtkResponseWidget, GtkActionWidget, GtkObserverEndpoint, GtkDialogRecord, GtkSelectionState, GtkActivationState,
    GtkFilenameState, GtkFilenameAbsent, GtkFilenameDifferent, GtkFixtureTransition, GtkResponseState,
    GtkResponseContract, GtkReturnState, GtkDispatch, GtkDestroyState, GtkReleaseState }
impl PathRejection {
    fn token(self) -> &'static [u8] {
        match self {
            Self::NotRecorded => b"not-recorded",
            Self::GtkThread => b"gtk-thread",
            Self::GtkDialogBook => b"gtk-dialog-book",
            Self::GtkDialogOriginal => b"gtk-dialog-original",
            Self::GtkOwnerBinding => b"gtk-owner-binding",
            Self::GtkOwnerInterrupted => b"gtk-owner-interrupted",
            Self::GtkOwnerFacts => b"gtk-owner-facts",
            Self::GtkDialogProperties => b"gtk-dialog-properties",
            Self::GtkInitialFolder => b"gtk-initial-folder",
            Self::GtkTarget => b"gtk-target",
            Self::GtkSelectionSetter => b"gtk-selection-setter",
            Self::GtkResponseWidget => b"gtk-response-widget",
            Self::GtkActionWidget => b"gtk-action-widget",
            Self::GtkObserverEndpoint => b"gtk-observer-endpoint",
            Self::GtkDialogRecord => b"gtk-dialog-record",
            Self::GtkSelectionState => b"gtk-selection-state",
            Self::GtkActivationState => b"gtk-activation-state",
            Self::GtkFilenameState => b"gtk-filename-state",
            Self::GtkFilenameAbsent => b"gtk-filename-absent",
            Self::GtkFilenameDifferent => b"gtk-filename-different",
            Self::GtkFixtureTransition => b"gtk-fixture-transition",
            Self::GtkResponseState => b"gtk-response-state",
            Self::GtkResponseContract => b"gtk-response-contract",
            Self::GtkReturnState => b"gtk-return-state",
            Self::GtkDispatch => b"gtk-dispatch",
            Self::GtkDestroyState => b"gtk-destroy-state",
            Self::GtkReleaseState => b"gtk-release-state",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct PathDiagnostic { step: PathStep, rejection: PathRejection, step_entry_ms: u128, sample_ms: u128,
    reservations: PathCount, entries: PathCount, returns: PathCount, callback: PathCallback, wait: PathWait }
impl PathDiagnostic {
    fn sample_trace(trace: &mut (Step,Boundary), step: Step, elapsed_ms: u128, previous: Option<Self>) -> Option<Self> {
        // A real Path transition changes the diagnostic context in this same
        // Record critical section. Preserve the boundary already observed.
        if matches!(step,Step::Paths(_)) || matches!(trace.0,Step::Paths(_)) || previous.is_some() { trace.0 = step; }
        Self::sample(step,elapsed_ms,previous)
    }
    fn sample(step: Step, elapsed_ms: u128, previous: Option<Self>) -> Option<Self> {
        let Step::Paths(step) = step else { return None; };
        if let Some(mut old) = previous.filter(|old| old.step == step) {
            old.sample_ms = elapsed_ms; return Some(old);
        }
        Some(Self { step, rejection: PathRejection::NotRecorded, step_entry_ms: elapsed_ms, sample_ms: elapsed_ms,
            reservations: PathCount::Zero, entries: PathCount::Zero, returns: PathCount::Zero,
            callback: if matches!(step,PathStep::Set(_) | PathStep::Activate(_)) { PathCallback::Idle } else { PathCallback::NotApplicable },
            wait: PathWait::NotSampled })
    }
    fn mark(&mut self, callback: PathCallback) {
        match callback {
            PathCallback::Reserved => self.reservations.advance(),
            PathCallback::Entered => self.entries.advance(),
            PathCallback::Returned => self.returns.advance(),
            _ => return,
        }
        self.callback = callback;
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum PathCount { Zero, One, Many }
impl PathCount {
    fn advance(&mut self) { *self = if *self == Self::Zero { Self::One } else { Self::Many }; }
    fn token(self) -> &'static [u8] { match self { Self::Zero => b"0", Self::One => b"1", Self::Many => b"m" } }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum PathCallback { NotApplicable, Idle, Reserved, Entered, Returned }
impl PathCallback {
    fn token(self) -> &'static [u8] { match self { Self::NotApplicable => b"na", Self::Idle => b"idle",
        Self::Reserved => b"reserved", Self::Entered => b"entered", Self::Returned => b"returned" } }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PathWait { NotSampled, DialogAbsent, InitialFolderAbsent, SelectionAbsent, SelectionDifferent, ResponseInsensitive }
impl PathWait {
    fn token(self) -> &'static [u8] { match self { Self::NotSampled => b"not-sampled", Self::DialogAbsent => b"dialog-absent",
        Self::InitialFolderAbsent => b"initial-folder-absent", Self::SelectionAbsent => b"selection-absent",
        Self::SelectionDifferent => b"selection-different", Self::ResponseInsensitive => b"response-insensitive" } }
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
    diagnostic: Option<PathDiagnostic>,
    operations: [PathOperation; 11], base: Option<Value>, draft: Option<Value>, patched: Option<Value>,
    previews_requested: u8, previews: [Option<Value>; 3], previews_visible: u8, draft_visible: bool,
    pair_visible: bool, final_pair_visible: bool, fixture: Option<PathFixture>,
}
impl Paths {
    fn new(root: Option<&Path>) -> Self {
        Self { diagnostic:None, operations: std::array::from_fn(|_| PathOperation::default()), base:None, draft:None, patched:None,
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
            if id[2] & 0o170000 != 0o040000 || id[2] & 0o022 != 0 || id[3] != 0 || id[4] != 0
                || (if path == root.as_path() { id[2] != 0o040755 } else { id[2] & 0o005 != 0o005 }) { return Err(()); }
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
            "localReviewAvailable":true, "remoteAvailable":false
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
        Self::read_values(result,"1.2.3",7,VERSION_SHA256)
    }
    fn read_values(result: &crate::release_version_protocol::Observation, expected_name: &str, expected_build: u64, expected_digest: &str) -> Option<Self> {
        // Project only the genuine already-admitted DTO; neither these bytes
        // nor the saved pair comparisons are returned to the renderer.
        let raw = edit::bounded(result, crate::release_version_protocol::RESULT_LIMIT).ok()?;
        let value = crate::protocol::strict_json(&raw).ok()?;
        let pair_matched = value["savedConfig"] == serde_json::json!({"bytes":CONFIG_BYTES,"sha256":CONFIG_SHA256})
            && value["savedVersion"] == serde_json::json!({"bytes":VERSION_BYTES,"sha256":expected_digest});
        if !keys(&value, &["schemaVersion", "source", "version", "savedConfig", "savedVersion", "observationScope", "assurance"])
            || value["schemaVersion"].as_u64() != Some(2) || value["source"].as_str() != Some(VERSION_SOURCE)
            || value["version"] != serde_json::json!({"name":expected_name,"build":expected_build}) || !pair_matched
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
    let mut display = metadata_display(fields, Some(serde_json::json!({"badge":"Format-valid selected text",
        "text":"Format-valid selected text Not a saved file, whole-metadata validation, native asset check, Store approval or release-readiness result."})));
    // The independent native metadata status must also be available/idle;
    // ReadMetadataValidation waits for that actual original before this DOM.
    display["reviewAvailable"] = serde_json::json!(true);
    Some(display)
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
// Closed, failure-only observations. No DTO, path, identifier or arbitrary
// BridgeError string can enter the original bounded diagnostic channel.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EvidenceCallback { Status, ObserveStart }
impl EvidenceCallback {
    fn token(self) -> &'static [u8] { match self { Self::Status => b"status", Self::ObserveStart => b"observe-start" } }
    fn permits(self, step: Step) -> bool { match self {
        Self::Status => !matches!(step, Step::Paths(_) | Step::Session(_)),
        Self::ObserveStart => matches!(step, Step::InspectEvidence | Step::EvidenceObserved),
    } }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvidenceCheck {
    StatusPending, Bridge, Case, ObservePending, ObserveReturned, ObserveRequests,
    Revision, Schema, Availability, PreviousRevision, EqualRevision, OperationOrder,
    Operation, OperationKind, OperationSelection, Phase, Problem, Result, Selection,
    SelectionWitness, SelectionFormat, SelectionName, SelectionChanged, ChooseRequests,
    CancelStatus, PickerActivated, Cancelled, ObservationPresent, ObservationChanged,
}
impl EvidenceCheck {
    fn token(self) -> &'static [u8] { match self {
        Self::StatusPending => b"status-pending", Self::Bridge => b"bridge", Self::Case => b"case",
        Self::ObservePending => b"observe-pending", Self::ObserveReturned => b"observe-returned",
        Self::ObserveRequests => b"observe-requests", Self::Revision => b"revision", Self::Schema => b"schema",
        Self::Availability => b"availability", Self::PreviousRevision => b"previous-revision",
        Self::EqualRevision => b"equal-revision", Self::OperationOrder => b"operation-order",
        Self::Operation => b"operation", Self::OperationKind => b"operation-kind",
        Self::OperationSelection => b"operation-selection", Self::Phase => b"phase", Self::Problem => b"problem",
        Self::Result => b"result", Self::Selection => b"selection", Self::SelectionWitness => b"selection-witness",
        Self::SelectionFormat => b"selection-format", Self::SelectionName => b"selection-name",
        Self::SelectionChanged => b"selection-changed", Self::ChooseRequests => b"choose-requests",
        Self::CancelStatus => b"cancel-status", Self::PickerActivated => b"picker-activated", Self::Cancelled => b"cancelled",
        Self::ObservationPresent => b"observation-present", Self::ObservationChanged => b"observation-changed",
    } }
}
fn evidence_require(accepted: bool, check: EvidenceCheck) -> Result<(), EvidenceCheck> {
    if accepted { Ok(()) } else { Err(check) }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum EvidenceError { None, Unavailable, Busy, Cancelled, StaleSelection, UnsafeSelection, ObservationFailed,
    Limit, Deadline, CleanupUnknown, Invalid, RuntimeUnavailable, Protocol, Shutdown, QueryTimeout, Other }
impl EvidenceError {
    fn classify(error: &BridgeError) -> Self { match error.code.as_str() {
        "artifact_evidence_unavailable" => Self::Unavailable, "artifact_evidence_busy" => Self::Busy,
        "artifact_evidence_cancelled" => Self::Cancelled, "artifact_evidence_stale_selection" => Self::StaleSelection,
        "artifact_evidence_unsafe_selection" => Self::UnsafeSelection,
        "artifact_evidence_observation_failed" => Self::ObservationFailed, "artifact_evidence_limit" => Self::Limit,
        "artifact_evidence_deadline" => Self::Deadline, "artifact_evidence_cleanup_unknown" | "cleanup_unknown" => Self::CleanupUnknown,
        "artifact_evidence_invalid" | "invalid_request" => Self::Invalid, "runtime_unavailable" => Self::RuntimeUnavailable,
        "protocol_error" => Self::Protocol, "shutting_down" => Self::Shutdown, "query_timeout" => Self::QueryTimeout,
        _ => Self::Other,
    } }
    fn token(self) -> &'static [u8] { match self {
        Self::None => b"none", Self::Unavailable => b"unavailable", Self::Busy => b"busy", Self::Cancelled => b"cancelled",
        Self::StaleSelection => b"stale-selection", Self::UnsafeSelection => b"unsafe-selection",
        Self::ObservationFailed => b"observation-failed", Self::Limit => b"limit", Self::Deadline => b"deadline",
        Self::CleanupUnknown => b"cleanup-unknown", Self::Invalid => b"invalid", Self::RuntimeUnavailable => b"runtime-unavailable",
        Self::Protocol => b"protocol", Self::Shutdown => b"shutdown", Self::QueryTimeout => b"query-timeout", Self::Other => b"other",
    } }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct EvidenceDiagnostic { step: Step, callback: EvidenceCallback, check: EvidenceCheck,
    phase: Option<evidence::Phase>, problem: Option<evidence::Problem>, error: EvidenceError }
impl EvidenceDiagnostic {
    fn valid(self, trace: (Step, Boundary)) -> bool {
        if trace != (self.step, Boundary::Result) || !self.callback.permits(self.step) { return false; }
        match self.check {
            EvidenceCheck::Bridge => self.phase.is_none() && self.problem.is_none() && self.error != EvidenceError::None,
            EvidenceCheck::StatusPending => self.callback == EvidenceCallback::Status && self.phase.is_none()
                && self.problem.is_none() && self.error == EvidenceError::None,
            _ => self.phase.is_some() && self.error == EvidenceError::None
                && (!matches!(self.check, EvidenceCheck::Case | EvidenceCheck::ObservePending | EvidenceCheck::ObserveReturned)
                    || self.callback == EvidenceCallback::ObserveStart),
        }
    }
    fn phase_token(self) -> &'static [u8] { match self.phase {
        None => b"na", Some(evidence::Phase::Idle) => b"idle", Some(evidence::Phase::Choosing) => b"choosing",
        Some(evidence::Phase::Selected) => b"selected", Some(evidence::Phase::Observing) => b"observing",
        Some(evidence::Phase::Observed) => b"observed", Some(evidence::Phase::Stopping) => b"stopping",
        Some(evidence::Phase::Cancelled) => b"cancelled", Some(evidence::Phase::Refused) => b"refused",
        Some(evidence::Phase::Unknown) => b"unknown",
    } }
    fn problem_token(self) -> &'static [u8] { match self.problem {
        None if self.phase.is_none() => b"na", None => b"none",
        Some(evidence::Problem::Unavailable) => b"unavailable", Some(evidence::Problem::Busy) => b"busy",
        Some(evidence::Problem::Cancelled) => b"cancelled", Some(evidence::Problem::StaleSelection) => b"stale-selection",
        Some(evidence::Problem::UnsafeSelection) => b"unsafe-selection", Some(evidence::Problem::ObservationFailed) => b"observation-failed",
        Some(evidence::Problem::Limit) => b"limit", Some(evidence::Problem::Deadline) => b"deadline",
        Some(evidence::Problem::CleanupUnknown) => b"cleanup-unknown",
    } }
}
fn latch_evidence_diagnostic(failed: &FailureLatch, trace: &mut (Step, Boundary),
    retained: &mut Option<EvidenceDiagnostic>, next: EvidenceDiagnostic) {
    // Record is held by the caller. Winning the original failure latch is the
    // only authority to publish both this detail and its matching trace.
    if failed.mark_unknown() {
        *trace = (next.step, Boundary::Result); *retained = Some(next);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SnapshotCheck { Bridge, Project, Root, Scope, ConfigPath, ConfigState, ConfigIssues, ConfigData,
    Issues, DiscoveryState, DiscoveryPartial, Assurance, RequestCount, AlreadyObserved, Stage, OtherCallback }
impl SnapshotCheck {
    fn token(self) -> &'static [u8] { match self {
        Self::Bridge => b"bridge", Self::Project => b"project", Self::Root => b"root", Self::Scope => b"scope",
        Self::ConfigPath => b"config-path", Self::ConfigState => b"config-state", Self::ConfigIssues => b"config-issues",
        Self::ConfigData => b"config-data", Self::Issues => b"issues", Self::DiscoveryState => b"discovery-state",
        Self::DiscoveryPartial => b"discovery-partial", Self::Assurance => b"assurance", Self::RequestCount => b"request-count",
        Self::AlreadyObserved => b"already-observed", Self::Stage => b"stage", Self::OtherCallback => b"other-callback",
    } }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct SnapshotRejection { check: SnapshotCheck, error: EvidenceError }
impl SnapshotRejection {
    fn plain(check: SnapshotCheck) -> Self { Self { check, error: EvidenceError::None } }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct SnapshotDiagnostic { step: Step, rejection: SnapshotRejection }
impl SnapshotDiagnostic {
    fn valid(self, trace: (Step, Boundary)) -> bool {
        trace == (self.step, Boundary::Result) && self.rejection.check != SnapshotCheck::OtherCallback
            && (self.rejection.check == SnapshotCheck::Bridge) == (self.rejection.error != EvidenceError::None)
            && (self.rejection.check != SnapshotCheck::Stage || !matches!(self.step, Step::Selected | Step::ReadSnapshot))
    }
}
fn session_snapshot_expected() -> Value {
    serde_json::json!({"android":{"applicationId":"org.assessment.fixture","enabled":true,"identityStatus":"unverified"},"ios":{"enabled":false},
        "metadata":{"androidLocales":["en-US"],"iosLocales":[],"root":"release/store"},"projectChecks":{"androidArtifact":[],"iosArtifact":[],"preflight":[]},
        "schemaVersion":1,"services":{"androidFirebase":"required","iosFirebase":"disabled"},"source":{"candidateBranch":"main","productionBranch":"main","projectReadTokenRequired":true},
        "version":{"buildKey":"BUILD_NUMBER","nameKey":"VERSION_NAME","source":"version.properties"}})
}
fn snapshot_require(valid: bool, check: SnapshotCheck) -> Result<(), SnapshotRejection> {
    if valid { Ok(()) } else { Err(SnapshotRejection::plain(check)) }
}
fn session_snapshot_check(project: Option<&Project>, project_id: &str, result: &Result<Value, BridgeError>,
    requests: u8, observed: bool, step: Step) -> Result<(), SnapshotRejection> {
    // Same conjunction and short-circuit precedence as the original callback.
    // Only the rejected predicate is retained; never the supplied DTO or error.
    let expected = session_snapshot_expected();
    let value = result.as_ref().map_err(|error| SnapshotRejection {
        check: SnapshotCheck::Bridge, error: EvidenceError::classify(error) })?;
    let project = project.filter(|p| p.id == project_id).ok_or(SnapshotRejection::plain(SnapshotCheck::Project))?;
    snapshot_require(value["root"].as_str() == Some(project.path.as_str()), SnapshotCheck::Root)?;
    snapshot_require(value["observationScope"] == "single-request-non-atomic", SnapshotCheck::Scope)?;
    snapshot_require(value["config"]["path"] == "release/mobile-release.json", SnapshotCheck::ConfigPath)?;
    snapshot_require(value["config"]["state"] == "format-valid", SnapshotCheck::ConfigState)?;
    snapshot_require(value["config"]["issues"].as_array().is_some_and(Vec::is_empty), SnapshotCheck::ConfigIssues)?;
    snapshot_require(value["config"]["data"] == expected, SnapshotCheck::ConfigData)?;
    snapshot_require(value["issues"].as_array().is_some_and(Vec::is_empty), SnapshotCheck::Issues)?;
    snapshot_require(value["discovery"]["state"] == "unverified", SnapshotCheck::DiscoveryState)?;
    snapshot_require(value["discovery"]["partial"] == false, SnapshotCheck::DiscoveryPartial)?;
    snapshot_require(assurance(value, "static-text"), SnapshotCheck::Assurance)?;
    snapshot_require(requests == 1, SnapshotCheck::RequestCount)?;
    snapshot_require(!observed, SnapshotCheck::AlreadyObserved)?;
    snapshot_require(matches!(step, Step::Selected | Step::ReadSnapshot), SnapshotCheck::Stage)
}
#[track_caller]
fn latch_snapshot_diagnostic(failed: &FailureLatch, trace: &mut (Step, Boundary),
    retained: &mut Option<SnapshotDiagnostic>, next: SnapshotDiagnostic) {
    // Record is held. The source site and failure become visible in one CAS;
    // the same first winner alone can publish this matching structured DATA.
    if failed.mark_caller() { *trace = (next.step, Boundary::Result); *retained = Some(next); }
}
fn snapshot_failure_frame(trace: (Step, Boundary), progress: BootstrapProgress, site: Option<u16>,
    diagnostic: Option<SnapshotDiagnostic>) -> Option<([u8; FAILURE_PAIR_LIMIT], usize)> {
    let line = site.filter(|line| *line != 0)?;
    let rejection = match diagnostic {
        Some(next) if next.valid(trace) => next.rejection,
        None if matches!(trace.0, Step::Selected | Step::ReadSnapshot) => SnapshotRejection::plain(SnapshotCheck::OtherCallback),
        _ => return None,
    };
    let mut digits = [b'0'; 5]; let mut remainder = line; let mut begin = 4;
    loop {
        digits[begin] += (remainder % 10) as u8; remainder /= 10;
        if remainder == 0 { break; }
        begin -= 1;
    }
    let mut bytes = [0_u8; FAILURE_PAIR_LIMIT]; let mut length = 0_usize;
    // This four-line frame is independent of legacy Session/Path formatting.
    // A true wrong-stage rejection must not invent a legacy diagnostic.
    for part in [b"MRK_INSTALLED_SHELL_SNAPSHOT_FAILURE=v1;site=".as_slice(), &digits[begin..],
        b";check=", rejection.check.token(), b";error=", rejection.error.token(), b"\n",
        trace.0.failure_line(), trace.1.failure_line(), progress.failure_line()] {
        let end = length.checked_add(part.len())?;
        bytes.get_mut(length..end)?.copy_from_slice(part); length = end;
    }
    Some((bytes, length))
}
fn assert_snapshot_rejection_contract() {
    let project = Project { id: "selected".into(), name: "fixture".into(), path: "/private/fixture".into() };
    let value = serde_json::json!({"root":project.path.as_str(),"observationScope":"single-request-non-atomic",
        "config":{"path":"release/mobile-release.json","state":"format-valid","issues":[],"data":session_snapshot_expected()},
        "issues":[],"discovery":{"state":"unverified","partial":false},"assurance":{"basis":"static-text","releaseReadiness":"unknown",
            "projectCodeExecuted":false,"toolsProbed":false,"credentialsRead":false,"gitObserved":false,"storeContacted":false,"writesPerformed":false}});
    let legacy = |project: Option<&Project>, id: &str, result: &Result<Value, BridgeError>, requests: u8, observed: bool, step: Step| {
        let expected = session_snapshot_expected();
        result.as_ref().is_ok_and(|value| project.is_some_and(|p| p.id == id && value["root"].as_str() == Some(p.path.as_str()))
            && value["observationScope"] == "single-request-non-atomic" && value["config"]["path"] == "release/mobile-release.json"
            && value["config"]["state"] == "format-valid" && value["config"]["issues"].as_array().is_some_and(Vec::is_empty)
            && value["config"]["data"] == expected && value["issues"].as_array().is_some_and(Vec::is_empty)
            && value["discovery"]["state"] == "unverified" && value["discovery"]["partial"] == false && assurance(value,"static-text"))
            && requests == 1 && !observed && matches!(step, Step::Selected | Step::ReadSnapshot)
    };
    for step in [Step::Selected, Step::ReadSnapshot] {
        let result = Ok(value.clone());
        assert!(legacy(Some(&project), "selected", &result, 1, false, step));
        assert!(session_snapshot_check(Some(&project), "selected", &result, 1, false, step).is_ok());
    }
    let mutations: &[(SnapshotCheck, fn(&mut Value))] = &[
        (SnapshotCheck::Root, |v| v["root"] = Value::Null),
        (SnapshotCheck::Scope, |v| v["observationScope"] = Value::Null),
        (SnapshotCheck::ConfigPath, |v| v["config"]["path"] = Value::Null),
        (SnapshotCheck::ConfigState, |v| v["config"]["state"] = Value::Null),
        (SnapshotCheck::ConfigIssues, |v| v["config"]["issues"] = Value::Null),
        (SnapshotCheck::ConfigData, |v| v["config"]["data"] = Value::Null),
        (SnapshotCheck::Issues, |v| v["issues"] = Value::Null),
        (SnapshotCheck::DiscoveryState, |v| v["discovery"]["state"] = Value::Null),
        (SnapshotCheck::DiscoveryPartial, |v| v["discovery"]["partial"] = Value::Null),
        (SnapshotCheck::Assurance, |v| v["assurance"]["writesPerformed"] = Value::Bool(true)),
    ];
    for (check, mutate) in mutations {
        let mut wrong = value.clone(); mutate(&mut wrong); let result = Ok(wrong);
        for (requests, observed, step) in [(1, false, Step::Selected), (0, true, Step::Close)] {
            assert!(!legacy(Some(&project), "selected", &result, requests, observed, step));
            assert!(session_snapshot_check(Some(&project), "selected", &result, requests, observed, step)
                == Err(SnapshotRejection::plain(*check)));
        }
    }
    let result = Ok(value);
    for (selected, id, requests, observed, step, check) in [
        (None, "selected", 0, true, Step::Close, SnapshotCheck::Project),
        (Some(&project), "other", 1, false, Step::Selected, SnapshotCheck::Project),
        (Some(&project), "selected", 0, true, Step::Close, SnapshotCheck::RequestCount),
        (Some(&project), "selected", 2, false, Step::Selected, SnapshotCheck::RequestCount),
        (Some(&project), "selected", 1, true, Step::Close, SnapshotCheck::AlreadyObserved),
        (Some(&project), "selected", 1, false, Step::Close, SnapshotCheck::Stage),
    ] {
        assert!(!legacy(selected, id, &result, requests, observed, step));
        assert!(session_snapshot_check(selected, id, &result, requests, observed, step) == Err(SnapshotRejection::plain(check)));
    }
    let error = Err(BridgeError::new("query_timeout", "private error must never enter a failure frame"));
    assert!(session_snapshot_check(None, "other", &error, 0, true, Step::Close)
        == Err(SnapshotRejection { check: SnapshotCheck::Bridge, error: EvidenceError::QueryTimeout }));
}
fn assert_snapshot_frame_contract() {
    for step in [Step::ReadSnapshot, Step::Session(SessionStep::QuitPreserved), Step::Paths(PathStep::Activate(0))] {
        let next = SnapshotDiagnostic { step, rejection: SnapshotRejection::plain(SnapshotCheck::Root) };
        let trace = (step, Boundary::Result);
        let (bytes, length) = snapshot_failure_frame(trace, BootstrapProgress::Advanced, Some(65535), Some(next)).unwrap();
        let expected = [b"MRK_INSTALLED_SHELL_SNAPSHOT_FAILURE=v1;site=65535;check=root;error=none\n".as_slice(),
            step.failure_line(), Boundary::Result.failure_line(), BootstrapProgress::Advanced.failure_line()].concat();
        assert_eq!(&bytes[..length], expected.as_slice());
        assert!(length <= FAILURE_PAIR_LIMIT && bytes[..length].iter().filter(|b| **b == b'\n').count() == 4);
        assert!(snapshot_failure_frame(trace, BootstrapProgress::Advanced, None, Some(next)).is_none());
        assert!(snapshot_failure_frame(trace, BootstrapProgress::Advanced, Some(0), Some(next)).is_none());
        assert!(snapshot_failure_frame((step, Boundary::Dom), BootstrapProgress::Advanced, Some(10), Some(next)).is_none());
    }
    let step = Step::Session(SessionStep::QuitPreserved); let trace = (step, Boundary::Result);
    let wrong_stage = SnapshotDiagnostic { step, rejection: SnapshotRejection::plain(SnapshotCheck::Stage) };
    assert!(snapshot_failure_frame(trace, BootstrapProgress::Advanced, Some(12), Some(wrong_stage)).is_some());
    assert!(snapshot_failure_frame((Step::Selected, Boundary::Result), BootstrapProgress::Advanced, Some(12),
        Some(SnapshotDiagnostic { step: Step::Selected, ..wrong_stage })).is_none());
    assert!(snapshot_failure_frame(trace, BootstrapProgress::Advanced, Some(12), None).is_none());
    for boundary in [Boundary::Request, Boundary::Result, Boundary::Dom] {
        let (bytes, length) = snapshot_failure_frame((Step::ReadSnapshot, boundary), BootstrapProgress::Advanced, Some(9), None).unwrap();
        assert!(bytes[..length].starts_with(b"MRK_INSTALLED_SHELL_SNAPSHOT_FAILURE=v1;site=9;check=other-callback;error=none\n"));
    }
    for rejection in [SnapshotRejection::plain(SnapshotCheck::Bridge), SnapshotRejection::plain(SnapshotCheck::OtherCallback),
        SnapshotRejection { check: SnapshotCheck::Root, error: EvidenceError::Other }] {
        assert!(snapshot_failure_frame(trace, BootstrapProgress::Advanced, Some(12), Some(SnapshotDiagnostic { step, rejection })).is_none());
    }
    for generic_first in [false, true] {
        let failed = FailureLatch::new(false); let mut retained = None;
        let original = (Step::ReadSnapshot, Boundary::Dom); let mut retained_trace = original;
        if generic_first { assert!(failed.mark_site(17)); }
        latch_snapshot_diagnostic(&failed, &mut retained_trace, &mut retained, wrong_stage);
        let first_site = failed.site();
        assert!(!failed.mark_site(18));
        let mut evidence = None;
        latch_evidence_diagnostic(&failed, &mut retained_trace, &mut evidence, EvidenceDiagnostic {
            step: Step::EvidenceObserved, callback: EvidenceCallback::Status, check: EvidenceCheck::Bridge,
            phase: None, problem: None, error: EvidenceError::Other });
        assert!(evidence.is_none() && failed.site() == first_site);
        assert!(retained == if generic_first { None } else { Some(wrong_stage) });
        assert!(retained_trace == if generic_first { original } else { trace });
        let prior_typed = FailureLatch::new(true); let mut absent = None; let mut trace = original;
        latch_snapshot_diagnostic(&prior_typed, &mut trace, &mut absent, wrong_stage);
        assert!(absent.is_none() && trace == original && prior_typed.site().is_none());
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
        self.checked_status(status, closing).is_ok()
    }
    fn checked_status(&mut self, status: &evidence::Status, closing: bool) -> Result<(), EvidenceCheck> {
        use EvidenceCheck as C;
        // These are actual command replies, not fabricated native finality.
        // Match the original revision/binding and ignore only genuine older
        // replies exactly as the existing controller does. Poll counts vary.
        let revision = status.revision.parse::<u64>().map_err(|_| C::Revision)?;
        evidence_require(status.schema_version == 1, C::Schema)?;
        evidence_require(status.availability == "available", C::Availability)?;
        evidence_require(revision.to_string() == status.revision, C::Revision)?;
        if let Some(old) = &self.latest {
            let before = old.revision.parse::<u64>().map_err(|_| C::PreviousRevision)?;
            if revision < before { return Ok(()); }
            if revision == before { return evidence_require(status == old, C::EqualRevision); }
        }
        let id = status.operation.as_ref().and_then(|op| evidence::operation_id(&op.operation_id));
        evidence_require(self.latest.as_ref().and_then(|old| old.operation.as_ref())
            .and_then(|op| evidence::operation_id(&op.operation_id)) <= id, C::OperationOrder)?;
        if closing {
            // Quit normally revokes selection/result. Earlier positive facts
            // stay latched; exit uses the original slot5/Quit6 witness instead.
            evidence_require(id == Some(5), C::Operation)?;
            evidence_require(matches!(status.phase, evidence::Phase::Refused | evidence::Phase::Stopping), C::Phase)?;
            evidence_require(status.problem == Some(evidence::Problem::StaleSelection), C::Problem)?;
            evidence_require(status.selection.is_none(), C::Selection)?;
            return evidence_require(status.result.is_none(), C::Result);
        }
        match id {
            None => {
                evidence_require(self.choose_requests == 0, C::ChooseRequests)?;
                evidence_require(status.phase == evidence::Phase::Idle, C::Phase)?;
                evidence_require(status.operation.is_none(), C::Operation)?;
                evidence_require(status.selection.is_none(), C::Selection)?;
                evidence_require(status.result.is_none(), C::Result)?;
                evidence_require(status.problem.is_none(), C::Problem)?;
            },
            Some(3) => {
                evidence_require(self.choose_requests >= 1, C::ChooseRequests)?;
                let op = status.operation.as_ref().ok_or(C::Operation)?;
                evidence_require(op.kind == evidence::OperationKind::Choose, C::OperationKind)?;
                evidence_require(op.selection_id.is_none(), C::OperationSelection)?;
                evidence_require(status.selection.is_none(), C::Selection)?;
                evidence_require(status.result.is_none(), C::Result)?;
                match status.phase {
                    evidence::Phase::Choosing => {
                        evidence_require(!self.cancel_status, C::CancelStatus)?;
                        evidence_require(status.problem.is_none(), C::Problem)?;
                    },
                    evidence::Phase::Stopping | evidence::Phase::Cancelled => {
                        evidence_require(self.pickers[0].activated, C::PickerActivated)?;
                        evidence_require(status.problem == Some(evidence::Problem::Cancelled), C::Problem)?;
                    },
                    _ => return Err(C::Phase),
                }
            },
            Some(4) => {
                evidence_require(self.choose_requests == 2, C::ChooseRequests)?;
                evidence_require(self.cancelled, C::Cancelled)?;
                evidence_require(status.result.is_none(), C::Result)?;
                evidence_require(status.problem.is_none(), C::Problem)?;
                let op = status.operation.as_ref().ok_or(C::Operation)?;
                evidence_require(op.kind == evidence::OperationKind::Choose, C::OperationKind)?;
                evidence_require(op.selection_id.is_none(), C::OperationSelection)?;
                match status.phase {
                    evidence::Phase::Choosing => {
                        evidence_require(self.selection_status.is_none(), C::SelectionChanged)?;
                        evidence_require(status.selection.is_none(), C::Selection)?;
                    },
                    evidence::Phase::Selected => {
                        let selection = status.selection.as_ref().ok_or(C::Selection)?;
                        evidence_require(evidence::selection_id(&selection.selection_id), C::SelectionFormat)?;
                        evidence_require(selection.display_name == "candidate-evidence", C::SelectionName)?;
                        evidence_require(self.selection_status.as_ref().is_none_or(|old| old == selection), C::SelectionChanged)?;
                    },
                    _ => return Err(C::Phase),
                }
            },
            Some(5) => {
                evidence_require(self.observe_requests == 1, C::ObserveRequests)?;
                evidence_require(status.problem.is_none(), C::Problem)?;
                let selected = self.selected.as_ref().ok_or(C::SelectionWitness)?;
                evidence_require(status.selection.as_ref() == Some(&selected.selection), C::Selection)?;
                let op = status.operation.as_ref().ok_or(C::Operation)?;
                evidence_require(op.kind == evidence::OperationKind::Observe, C::OperationKind)?;
                evidence_require(op.selection_id.as_deref() == Some(selected.selection.selection_id.as_str()), C::OperationSelection)?;
                match status.phase {
                    evidence::Phase::Observing => {
                        evidence_require(self.observation_status.is_none(), C::ObservationPresent)?;
                        evidence_require(status.result.is_none(), C::Result)?;
                    },
                    evidence::Phase::Observed => {
                        let result = status.result.as_ref().ok_or(C::Result)?;
                        evidence_require(self.observation_status.as_ref().is_none_or(|old| old == result), C::ObservationChanged)?;
                    },
                    _ => return Err(C::Phase),
                }
            },
            _ => return Err(C::Operation),
        }
        match status.phase {
            evidence::Phase::Idle => self.initial_idle = true,
            evidence::Phase::Cancelled => self.cancel_status = true,
            evidence::Phase::Selected => self.selection_status = status.selection.clone(),
            evidence::Phase::Observed => self.observation_status = status.result.clone(),
            _ => {},
        }
        self.latest = Some(status.clone()); Ok(())
    }
}

fn assert_evidence_failure_contract() {
    // Inert original-state contracts, run in the existing native policy gate.
    // These observations neither start a worker nor prove native finality.
    let mut status = evidence::Status::unavailable(7); status.availability = "available"; status.problem = None;
    let mut candidate = Candidate::default();
    assert_eq!(candidate.checked_status(&status, false), Ok(()));
    assert!(candidate.initial_idle && candidate.latest.as_ref() == Some(&status));
    let mut older = status.clone(); older.revision = "6".into(); older.phase = evidence::Phase::Unknown;
    older.problem = Some(evidence::Problem::CleanupUnknown);
    assert_eq!(candidate.checked_status(&older, false), Ok(()));
    assert!(candidate.latest.as_ref() == Some(&status) && candidate.observation_status.is_none());
    let mut equal = status.clone(); equal.problem = Some(evidence::Problem::Busy);
    assert_eq!(candidate.checked_status(&equal, false), Err(EvidenceCheck::EqualRevision));
    assert!(candidate.latest.as_ref() == Some(&status));
    let mut choose = status.clone(); choose.revision = "8".into(); choose.phase = evidence::Phase::Choosing;
    choose.operation = Some(evidence::Operation { operation_id: "3".into(), kind: evidence::OperationKind::Choose, selection_id: None });
    assert_eq!(candidate.checked_status(&choose, false), Err(EvidenceCheck::ChooseRequests));
    assert!(candidate.latest.as_ref() == Some(&status));
    candidate.choose_requests = 1;
    assert_eq!(candidate.checked_status(&choose, false), Ok(()));
    let mut cancelled = choose.clone(); cancelled.revision = "9".into(); cancelled.phase = evidence::Phase::Cancelled;
    cancelled.problem = Some(evidence::Problem::Cancelled);
    assert_eq!(candidate.checked_status(&cancelled, false), Err(EvidenceCheck::PickerActivated));
    assert!(!candidate.cancel_status && candidate.latest.as_ref() == Some(&choose));
    candidate.pickers[0].activated = true;
    assert_eq!(candidate.checked_status(&cancelled, false), Ok(()));
    assert!(candidate.cancel_status && candidate.latest.as_ref() == Some(&cancelled));
    let mut closing = cancelled.clone(); closing.revision = "10".into(); closing.phase = evidence::Phase::Refused;
    closing.problem = Some(evidence::Problem::StaleSelection); closing.operation.as_mut().unwrap().operation_id = "5".into();
    assert_eq!(candidate.checked_status(&closing, true), Ok(()));
    assert!(candidate.latest.as_ref() == Some(&cancelled)); // Closing never replaces prior accepted facts.
    let mut malformed = status.clone(); malformed.revision = "07".into();
    assert_eq!(candidate.checked_status(&malformed, false), Err(EvidenceCheck::Revision));

    let first = EvidenceDiagnostic { step: Step::EvidenceObserved, callback: EvidenceCallback::Status,
        check: EvidenceCheck::Problem, phase: Some(evidence::Phase::Refused), problem: Some(evidence::Problem::Deadline),
        error: EvidenceError::None };
    let trace = (first.step, Boundary::Result);
    let (bytes, length) = failure_frame(trace, BootstrapProgress::Advanced, None, None, Some(first)).unwrap();
    assert!(length <= FAILURE_PAIR_LIMIT && bytes[..length].starts_with(
        b"MRK_INSTALLED_SHELL_EVIDENCE_FAILURE=v1;callback=status;check=problem;phase=refused;problem=deadline;error=none\n"));
    let (legacy, legacy_length) = failure_pair(trace, BootstrapProgress::Advanced, None, None).unwrap();
    assert_eq!(&bytes[length-legacy_length..length], &legacy[..legacy_length]);
    assert!(failure_frame(trace, BootstrapProgress::Advanced, None, None, None)
        == failure_pair(trace, BootstrapProgress::Advanced, None, None));
    assert!(failure_frame((first.step, Boundary::Deadline), BootstrapProgress::Advanced, None, None, Some(first)).is_none());
    assert!(failure_frame((Step::InspectEvidence, Boundary::Result), BootstrapProgress::Advanced, None, None, Some(first)).is_none());
    let path = PathDiagnostic::sample(Step::Paths(PathStep::Activate(0)), 0, None).unwrap();
    assert!(failure_frame(trace, BootstrapProgress::Advanced, None, Some(path), Some(first)).is_none());
    let wrong_role = EvidenceDiagnostic { step: Step::ReadEvidenceObserved, callback: EvidenceCallback::ObserveStart, ..first };
    assert!(!wrong_role.valid((wrong_role.step, Boundary::Result)));
    let unknown = EvidenceError::classify(&BridgeError::new("unrecognized-code", "not diagnostic output"));
    assert!(unknown == EvidenceError::Other && unknown.token() == b"other");
    let bridge = EvidenceDiagnostic { check: EvidenceCheck::Bridge, phase: None, problem: None, error: unknown, ..first };
    assert!(failure_frame(trace, BootstrapProgress::Advanced, None, None, Some(bridge)).is_some());
    assert!(!EvidenceDiagnostic { phase: first.phase, ..bridge }.valid(trace));
    assert!(!EvidenceDiagnostic { callback: EvidenceCallback::ObserveStart, check: EvidenceCheck::StatusPending,
        phase: None, problem: None, ..first }.valid(trace));

    for already_failed in [false, true] {
        let failed = FailureLatch::new(already_failed);
        let original_trace = (Step::Bootstrap, Boundary::Bootstrap);
        let mut retained_trace = original_trace; let mut retained = None;
        latch_evidence_diagnostic(&failed, &mut retained_trace, &mut retained, first);
        latch_evidence_diagnostic(&failed, &mut retained_trace, &mut retained, bridge);
        assert!(failed.load(Ordering::SeqCst));
        assert!(retained == if already_failed { None } else { Some(first) });
        assert!(retained_trace == if already_failed { original_trace } else { trace });
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
// Bounded read-only witnesses from four distinct originals. A final witness is
// frozen before another Open can replace the native owner's sole last slot.
struct WorkflowSession {
    projection: workflow::Projection, prepared: Option<Value>, review: Option<Value>, conflict: Option<Value>,
    prepare_requested: bool, prepare_returned: bool, binding: Option<(u32, u32)>,
    review_visible: bool, result_visible: bool, config_blocked: bool,
    confirmation_opened: u8, kept_reviewing: bool, acknowledged: bool, apply_requested: bool, apply_returned: bool,
    finality: Option<InstalledWorkflowFinality>,
}
impl WorkflowSession {
    fn live_review(&self) -> bool {
        self.projection.phase == edit::Phase::Reviewing && self.projection.review_remaining_ms > 0
            && !self.projection.apply_submitted && self.projection.native_reason == edit::NativeEditReason::None
            && self.projection.native_finality == edit::NativeFinality::Pending && self.projection.core_outcome.is_none()
            && self.projection.conflict.is_none() && self.prepared.is_some() && self.review.is_some() && self.finality.is_none()
    }
}
#[derive(Default)]
struct WorkflowRecord {
    capability: bool, native_revision: Option<u32>, sessions: Vec<WorkflowSession>, requests: [u8; 4],
    open_pending: bool, prepare_pending: Option<usize>, pin_changed: bool, pin_restored: bool,
    draft_reads: u8, outstanding: bool,
}
impl WorkflowRecord {
    fn complete(&self) -> bool {
        self.capability && self.requests == [4, 4, 2, 0] && !self.open_pending && self.prepare_pending.is_none()
            && self.pin_changed && self.pin_restored && self.draft_reads == 4 && self.outstanding && self.sessions.len() == 4
            && self.sessions.iter().enumerate().all(|(index, session)| session.prepare_requested && session.prepare_returned
                && session.binding == Some((1, 1)) && session.config_blocked && session.finality.is_some()
                && session.review_visible == (index != 1) && session.result_visible == (index != 3)
                && session.apply_requested == matches!(index, 0 | 2)
                && session.apply_returned == matches!(index, 0 | 2)
                && session.confirmation_opened == (if index == 0 { 2 } else if index == 2 { 1 } else { 0 })
                && session.kept_reviewing == (index == 0) && session.acknowledged == matches!(index, 0 | 2))
    }
}
fn workflow_observed(proposal: &ProposalSample, index: usize) -> Option<Value> {
    let mut rows = Vec::new();
    for (offset, (id, _, size)) in WORKFLOWS.iter().enumerate() {
        let content = proposal.workflows.get(offset)?.get("content")?.as_str()?;
        let digest = format!("{:x}", Sha256::digest(content.as_bytes()));
        rows.push(if index == 0 && offset != 0 { serde_json::json!({"id":id,"state":"absent"}) }
            else { serde_json::json!({"id":id,"state":"present","byteLength":size,"sha256":digest}) });
    }
    Some(Value::Array(rows))
}
fn workflow_review_sample(view: &workflow::PreparedView, proposal: &ProposalSample, index: usize) -> Option<Value> {
    if index == 1 || index > 3 || edit::bounded(view, workflow::RESPONSE_LIMIT).is_err()
        || view.schema_version != 1 || view.files.len() != 4 || !view.create_directories.is_empty()
        || serde_json::to_value(&view.template_set).ok()? != serde_json::json!({"coreVersion":crate::runtime::CORE_VERSION,
            "resourceVersion":1,"resourceSha256":GITHUB_RESOURCE})
        || serde_json::to_value(&view.tooling).ok()? != serde_json::json!({"repository":TOOLKIT_REPOSITORY,"sha":TOOLKIT_SHA,
            "schemaReference":format!("https://raw.githubusercontent.com/{TOOLKIT_REPOSITORY}/{TOOLKIT_SHA}/schemas/project.schema.json"),"state":"format-only"}) { return None; }
    let mut files = Vec::new(); let mut texts = Vec::new();
    let observations = workflow_observed(proposal, index)?;
    for (offset, (file, (id, path, size))) in view.files.iter().zip(WORKFLOWS).enumerate() {
        let preserve = index != 0 || offset == 0;
        let generated = &file.generated;
        let content = proposal.workflows.get(offset)?.get("content")?.as_str()?;
        let digest = format!("{:x}", Sha256::digest(content.as_bytes()));
        let mut observed = observations.get(offset)?.clone(); observed.as_object_mut()?.remove("id");
        if serde_json::to_value(file.id).ok()?.as_str() != Some(id) || file.path != path
            || file.action != (if preserve { workflow::Action::Preserve } else { workflow::Action::Create })
            || serde_json::to_value(&file.observed).ok()? != observed
            || generated.content != content || generated.content.len() != size
            || generated.byte_length as usize != size || generated.sha256 != digest { return None; }
        files.push(serde_json::json!({"path":path,"action":file.action,"observed":file.observed,
            "generated":{"byteLength":generated.byte_length,"sha256":generated.sha256}}));
        // Display-only line prefixes, not a caller generator or disk oracle.
        let newline = content.ends_with('\n');
        let lines: Vec<_> = content.strip_suffix('\n').unwrap_or(content).split('\n').collect();
        let before = if preserve { path } else { "/dev/null" };
        let range = if preserve { format!("-1,{}", lines.len()) } else { "-0,0".into() };
        let prefix = if preserve { ' ' } else { '+' };
        let diff = format!("--- {before}\n+++ {path}\n@@ {range} +1,{} @@\n{}\n{}", lines.len(),
            lines.iter().map(|line| format!("{prefix}{line}")).collect::<Vec<_>>().join("\n"),
            if newline { "" } else { "\\ No newline at end of file\n" });
        texts.push(serde_json::json!({"path":path,"badge":if preserve { "Full unchanged context" } else { "Full added text" },
            "label":format!("Complete {} for {path}", if preserve { "unchanged generated context" } else { "added diff" }),"content":diff}));
    }
    Some(serde_json::json!({"files":files,"texts":texts,
        "basis":if index == 0 { "Only absent callers will be created" } else { "No file writes are planned" },
        "facts":[["Toolkit repository",TOOLKIT_REPOSITORY],["Toolkit commit · format-only",TOOLKIT_SHA],
            ["Core / resource version",format!("{} / 1",crate::runtime::CORE_VERSION)],["Resource identity SHA256",GITHUB_RESOURCE],
            ["Schema reference · informational, not fetched or saved",view.tooling.schema_reference]],
        "note":"Existing ancestors are preserved. New directories use 0755; new files request 0644 subject to inherited umask. Exact-preserved originals are not rewritten or chmodded.",
        "caution":"Draft validation was required for this plan, but no configuration save is required or performed. The toolkit ref and template compatibility are not remotely verified. GitHub, credentials, unknown workflow siblings, .gitignore, Git/index state and release operations are outside this plan."}))
}
fn workflow_conflict_sample(view: &workflow::ConflictView, proposal: &ProposalSample) -> Option<Value> {
    if view.schema_version != 1 || view.reason != "existing_workflow_differs" || view.conflicts.len() != 4
        || edit::bounded(view, 4096).is_err() { return None; }
    let observed = workflow_observed(proposal, 1)?;
    let mut rows = Vec::new();
    for (offset, (file, (id, _, size))) in view.conflicts.iter().zip(WORKFLOWS).enumerate() {
        let mut expected = observed.get(offset)?.clone(); expected.as_object_mut()?.remove("id");
        if serde_json::to_value(file.id).ok()?.as_str() != Some(id) || serde_json::to_value(&file.observed).ok()? != expected { return None; }
        rows.push(serde_json::json!({"id":id,"bytes":size,"sha256":expected["sha256"]}));
    }
    Some(serde_json::json!({"heading":"Observed differing callers · no Apply token","rows":rows,
        "caution":"Only summaries actually obtained by the original capture are shown. Existing YAML is not exposed; no subset, force or overwrite option is available."}))
}
fn workflow_original_final(facts: &InstalledWorkflowFinality, projection: &workflow::Projection, index: usize) -> bool {
    projection.domain == workflow::DOMAIN && facts.session_id == projection.session_id
        && facts.project_id == projection.project_id && facts.owner_generation == projection.owner_generation
        && facts.writer_frames == (if matches!(index, 0 | 2) { 3 } else { 2 })
        && facts.stdout_frames == (if index == 1 { 2 } else { 3 })
        && facts.inspection_joined && facts.acquisition_joined && facts.child_waited_success
        && facts.stdin_closed && facts.stdout_eof_closed && facts.stderr_eof_closed && facts.io_joined
        && facts.driver_joined && facts.watchdog_joined && facts.manager_joined
        && facts.runtime_ledger_settled && facts.runtime_settlement_joined
}
fn workflow_start_step(step: Step, index: usize) -> bool {
    matches!(step, Step::Workflow(WorkflowStep::Start(i) | WorkflowStep::OpenText(i) | WorkflowStep::ReadResult(i)) if usize::from(i) == index)
}

// One fixed public bundle. These DATA comparisons grant no filesystem or
// owner authority. All text is obtained through the genuine controller/core.
fn metadata_baseline(saved: bool) -> Value {
    let fields: Vec<_> = METADATA_FIELDS.iter().enumerate().map(|(index, (id, text, _))| {
        if !saved && index == 2 { serde_json::json!({"id":id,"state":"absent"}) }
        else {
            let text = if !saved && index == 1 { "Old summary" } else { text };
            serde_json::json!({"id":id,"state":"present","byteLength":text.len(),"sha256":format!("{:x}",Sha256::digest(text.as_bytes()))})
        }
    }).collect();
    serde_json::json!({"config":{"byteLength":CONFIG_BYTES,"sha256":CONFIG_SHA256},"fields":fields})
}
fn metadata_saved_observation(result: &metadata::Observation, saved: bool) -> Option<Value> {
    let raw = edit::bounded(result, metadata::RESPONSE_LIMIT).ok()?;
    let value = crate::protocol::strict_json(&raw).ok()?;
    if !keys(&value, &["schemaVersion","platform","locale","metadataRoot","observationScope","baseline","fields","assurance"])
        || value["schemaVersion"] != 1 || value["platform"] != "android" || value["locale"] != "en-US"
        || value["metadataRoot"] != "release/store" || value["observationScope"] != "single-request-non-atomic"
        || value["baseline"] != metadata_baseline(saved) || !assurance(&value,"static-text") { return None; }
    let rows = value["fields"].as_array().filter(|rows| rows.len() == 3)?;
    for (index, (row, (id, text, _))) in rows.iter().zip(METADATA_FIELDS).enumerate() {
        let mut expected = value["baseline"]["fields"][index].clone();
        expected["path"] = serde_json::json!(format!("release/store/android/en-US/{id}"));
        if saved || index != 2 { expected["text"] = serde_json::json!(if !saved && index == 1 { "Old summary" } else { text }); }
        if row != &expected { return None; }
    }
    Some(value)
}
fn metadata_validation_sample(result: &metadata::ValidationResult) -> Option<Value> {
    let raw = edit::bounded(result, metadata::RESPONSE_LIMIT).ok()?;
    let value = crate::protocol::strict_json(&raw).ok()?;
    let rows: Vec<_> = METADATA_FIELDS.iter().map(|(id,text,limit)| serde_json::json!({"id":id,"valid":true,
        "characterCount":text.len(),"limit":limit,"issues":[]})).collect();
    (keys(&value,&["schemaVersion","platform","valid","state","fields","assurance"])
        && value["schemaVersion"] == 1 && value["platform"] == "android" && value["valid"] == true
        && value["state"] == "format-valid" && value["fields"] == serde_json::json!(rows)
        && assurance(&value,"schema-policy")).then_some(value)
}
fn metadata_save_display(edited: bool, validated: bool, saved: bool, available: bool) -> Value {
    let fields: Vec<_> = METADATA_FIELDS.iter().enumerate().map(|(index,(id,text,_))| {
        let text = if edited { *text } else { match index { 0 => "Public title", 1 => "Old summary", _ => "" } };
        let badge = if saved { "Saved baseline" } else if edited && index > 0 { "Unsaved text" }
            else if index == 2 { "Missing · observed" } else { "Observed original" };
        serde_json::json!({"id":id,"path":format!("release/store/android/en-US/{id}"),"text":text,
            "badges":["Required",badge],"invalid":if validated && !saved { Some("false") } else { None }})
    }).collect();
    serde_json::json!({"context":"android / en-US","badge":"Selected text only","fields":fields,
        "loadLabel":"Refresh text","loadAvailable":true,"validateAvailable":true,"reviewAvailable":available,
        "validation":if saved { Some("Stale validation") } else if validated { Some("Format-valid selected text") } else { None }})
}
fn metadata_review_sample(view: &metadata::PreparedView) -> Option<Value> {
    if edit::bounded(view,metadata::VIEW_LIMIT).is_err() || view.schema_version != 1
        || view.platform != metadata::Platform::Android || view.locale != "en-US" || view.metadata_root != "release/store"
        || !view.create_directories.is_empty() || view.files.len() != 3 || metadata_validation_sample(&view.validation).is_none() { return None; }
    let mut expected = Vec::new();
    for (index,(id,text,_)) in METADATA_FIELDS.iter().enumerate() {
        let old = if index == 0 { Some("Public title") } else if index == 1 { Some("Old summary") } else { None };
        let before = old.map_or_else(|| serde_json::json!({"state":"absent"}), |text|
            serde_json::json!({"state":"present","text":text,"byteLength":text.len(),"sha256":format!("{:x}",Sha256::digest(text.as_bytes()))}));
        expected.push(serde_json::json!({"id":id,"path":format!("release/store/android/en-US/{id}"),
            "action":match index { 0 => "preserve", 1 => "replace", _ => "create" },"before":before,
            "after":{"text":text,"byteLength":text.len(),"sha256":format!("{:x}",Sha256::digest(text.as_bytes()))},"lineEndingsChanged":false}));
    }
    let actual = serde_json::to_value(&view.files).ok()?;
    (actual == serde_json::json!(expected)).then_some(actual)
}
struct MetadataSession {
    projection: metadata::Projection, prepared: Option<Value>, review: Option<Value>, binding: Option<(u32,u32)>,
    first_revision: u32, open_returned: bool,
    prepare_requested: bool, prepare_returned: bool, review_visible: bool, config_blocked: bool,
    close_requested: bool, close_returned: bool, apply_requested: bool, apply_returned: bool,
    finality: Option<InstalledMetadataFinality>,
}
impl MetadataSession {
    fn live_review(&self) -> bool {
        self.open_returned && self.projection.phase == edit::Phase::Reviewing && self.projection.review_remaining_ms > 0
            && !self.projection.apply_submitted && self.projection.native_reason == edit::NativeEditReason::None
            && self.projection.native_finality == edit::NativeFinality::Pending && self.projection.core_outcome.is_none()
            && self.prepared.is_some() && self.review.is_some() && self.finality.is_none()
    }
}
struct MetadataOpen {
    index: usize, after_revision: u32, project_id: String, generation: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MetadataOpenMatch { First, Reply }
#[derive(Default)]
struct MetadataRecord {
    capability: bool, ready: bool, native_revision: Option<u32>, saved_config: Option<Value>,
    observations: Vec<Value>, observe_requests: u8, observe_pending: bool, loaded_visible: bool,
    entered: [bool;2], inputs: Option<Value>, validation_requested: bool, validation: Option<Value>, validation_visible: bool,
    sessions: Vec<MetadataSession>, requests: [u8;4], open_pending: Option<MetadataOpen>, prepare_pending: Option<usize>,
    retained_after_close: bool, confirmation_opened: u8, initially_disabled: bool, checkbox_only_disabled: bool,
    typed_save: bool, acknowledged: bool, saved_visible: bool, readback_visible: bool,
}
impl MetadataRecord {
    fn open_match(&self, status: &metadata::MetadataTextEditStatus, returned: bool) -> Option<MetadataOpenMatch> {
        let pending = self.open_pending.as_ref()?;
        let owner = status.active.as_ref()?;
        if pending.index >= 2 || usize::from(self.requests[0]) != pending.index + 1
            || status.schema_version != 1 || status.domain != metadata::DOMAIN
            || status.window_generation != pending.generation || !edit::token(&status.window_generation)
            || status.status_revision <= pending.after_revision
            || !status.capability.available || status.capability.reason != edit::EditAvailability::Available
            || owner.domain != metadata::DOMAIN || owner.project_id != pending.project_id
            || owner.owner_generation != pending.generation || !edit::token(&owner.session_id)
            || owner.platform != metadata::Platform::Android || owner.locale != "en-US"
            || owner.prepared.is_some() || owner.core_outcome.is_some() || owner.apply_submitted || owner.late_settled
            || owner.native_reason != edit::NativeEditReason::None || owner.native_finality != edit::NativeFinality::Pending
            || (if returned { owner.phase != edit::Phase::Opening } else { !matches!(owner.phase,edit::Phase::Opening | edit::Phase::Editing) })
            || (owner.phase == edit::Phase::Opening) != owner.checkout.is_none() { return None; }
        if self.sessions.len() == pending.index {
            if self.native_revision.is_some_and(|revision|status.status_revision < revision)
                || self.sessions.iter().any(|s|!s.open_returned || s.finality.is_none() || s.projection.session_id == owner.session_id) { return None; }
            if let Some(checkout) = &owner.checkout {
                if !edit::token(&checkout.revision) || checkout.metadata_root != "release/store"
                    || serde_json::to_value(&checkout.baseline).ok() != self.observations.first().map(|o|o["baseline"].clone())
                    || self.sessions.iter().any(|s|s.projection.checkout.as_ref().is_some_and(|c|c.revision == checkout.revision)) { return None; }
            }
            Some(MetadataOpenMatch::First)
        } else {
            let session = self.sessions.get(pending.index)?;
            (returned && self.sessions.len() == pending.index + 1 && !session.open_returned
                && session.projection.session_id == owner.session_id && session.projection.project_id == owner.project_id
                && session.projection.owner_generation == owner.owner_generation && status.status_revision <= session.first_revision)
                .then_some(MetadataOpenMatch::Reply)
        }
    }
    fn observe_open(&mut self, status: &metadata::MetadataTextEditStatus, returned: bool, config: Option<&ConfigEditStatus>) -> bool {
        let Some(matched) = self.open_match(status,returned) else { return false; };
        let Some(pending) = self.open_pending.as_ref() else { return false; };
        let index = pending.index;
        if matched == MetadataOpenMatch::First {
            let Some(config) = config else { return false; };
            if config.schema_version != 1 || config.window_generation != pending.generation
                || config.status_revision < status.status_revision || config.capability.available
                || config.capability.reason != edit::EditAvailability::OtherEditActive
                || config.active.is_some() || config.last_terminal.is_some() { return false; }
            let Some(owner) = status.active.as_ref() else { return false; };
            self.sessions.push(MetadataSession { projection:owner.clone(), prepared:None, review:None, binding:None,
                first_revision:status.status_revision, open_returned:false,
                prepare_requested:false, prepare_returned:false, review_visible:false, config_blocked:true,
                close_requested:false, close_returned:false, apply_requested:false, apply_returned:false, finality:None });
        } else if config.is_some() { return false; }
        if returned {
            // The actual captured Opening reply is independent evidence. It
            // never replaces a newer genuine Editing/Preparing/Reviewing event.
            self.sessions[index].open_returned = true; self.open_pending = None;
        }
        true
    }
    fn record_prepare(&mut self, args: &metadata::PrepareMetadataTextEdit) -> bool {
        let index = usize::from(self.requests[1]);
        let Some(session) = self.sessions.get(index) else { return false; };
        if self.prepare_pending.is_some() || session.prepare_requested || session.binding.is_some()
            || session.projection.phase != edit::Phase::Editing || session.projection.session_id != args.session_id
            || args.draft_revision != 2 || args.baseline_generation != 0
            || !session.projection.checkout.as_ref().is_some_and(|c|c.revision == args.revision && c.baseline == args.expected_baseline)
            || serde_json::to_value(&args.expected_baseline).ok() != self.observations.first().and_then(|o|o.get("baseline")).cloned()
            || serde_json::to_value(&args.fields).ok().as_ref() != self.inputs.as_ref() || !session.config_blocked { return false; }
        // A genuine Editing event can cause Prepare before Open's captured
        // reply returns. Event-bound identity/checkout are sufficient for this
        // request, but never for visible review, Close, Apply or completion.
        let session = &mut self.sessions[index];
        session.prepare_requested = true; session.binding = Some((args.draft_revision,args.baseline_generation));
        self.prepare_pending = Some(index); self.requests[1] += 1;
        true
    }
    fn complete(&self) -> bool {
        self.capability && self.saved_config.is_some() && self.observe_requests == 2 && self.observations.len() == 2
            && !self.observe_pending && self.loaded_visible && self.entered == [true;2] && self.inputs.is_some()
            && self.validation_requested && self.validation.is_some() && self.validation_visible
            && self.requests == [2,2,1,1] && self.open_pending.is_none() && self.prepare_pending.is_none()
            && self.retained_after_close && self.confirmation_opened == 1 && self.initially_disabled && self.checkbox_only_disabled
            && self.typed_save && self.acknowledged && self.saved_visible && self.readback_visible && self.sessions.len() == 2
            && self.sessions.iter().enumerate().all(|(index,s)| s.open_returned && s.prepare_requested && s.prepare_returned && s.binding == Some((2,0))
                && s.review_visible && s.config_blocked && s.finality.is_some()
                && s.close_requested == (index == 0) && s.close_returned == (index == 0)
                && s.apply_requested == (index == 1) && s.apply_returned == (index == 1))
    }
}
fn metadata_start_step(step: Step, index: usize) -> bool {
    matches!(step,Step::MetadataSave(MetadataStep::Review(i) | MetadataStep::OpenText(i) | MetadataStep::ReadReview(i)) if usize::from(i) == index)
}
fn metadata_original_final(facts: &InstalledMetadataFinality, projection: &metadata::Projection) -> bool {
    projection.domain == metadata::DOMAIN && facts.session_id == projection.session_id
        && facts.project_id == projection.project_id && facts.owner_generation == projection.owner_generation
        && facts.writer_frames == (if projection.apply_submitted { 3 } else { 2 }) && facts.stdout_frames == 3
        && facts.inspection_joined && facts.acquisition_joined && facts.child_waited_success
        && facts.stdin_closed && facts.stdout_eof_closed && facts.stderr_eof_closed && facts.io_joined
        && facts.driver_joined && facts.watchdog_joined && facts.manager_joined
        && facts.runtime_ledger_settled && facts.runtime_settlement_joined
}

fn assert_metadata_open_race_contract() {
    // Inert data through the SAME binding/reply/Prepare predicates used below.
    // No owner, native status call, UI, clock, file or finality evidence is made.
    let generation = "0".repeat(32); let session_id = "1".repeat(32); let revision = "2".repeat(32);
    let fields = serde_json::json!(METADATA_FIELDS.iter().map(|(id,text,_)|
        serde_json::json!({"id":id,"text":text})).collect::<Vec<_>>());
    let opening = metadata::MetadataTextEditStatus { schema_version:1, domain:metadata::DOMAIN,
        window_generation:generation.clone(), status_revision:11,
        capability:edit::Capability { available:true, reason:edit::EditAvailability::Available },
        active:Some(metadata::Projection { domain:metadata::DOMAIN, project_id:"inert-project".into(),
            session_id:session_id.clone(), owner_generation:generation.clone(), platform:metadata::Platform::Android,
            locale:"en-US".into(), phase:edit::Phase::Opening, review_remaining_ms:1000, checkout:None, prepared:None,
            apply_submitted:false, core_outcome:None, native_reason:edit::NativeEditReason::None,
            native_finality:edit::NativeFinality::Pending, late_settled:false }), last_terminal:None };
    let mut editing = opening.clone(); editing.status_revision = 12;
    let active = editing.active.as_mut().unwrap(); active.phase = edit::Phase::Editing;
    active.checkout = Some(metadata::Checkout { revision:revision.clone(), metadata_root:"release/store".into(),
        baseline:serde_json::from_value(metadata_baseline(false)).unwrap() });
    let config = ConfigEditStatus { schema_version:1, window_generation:generation.clone(), status_revision:13,
        capability:edit::Capability { available:false, reason:edit::EditAvailability::OtherEditActive }, active:None, last_terminal:None };
    let pending = |index,after_revision| MetadataOpen { index, after_revision, project_id:"inert-project".into(), generation:generation.clone() };
    let record = || MetadataRecord { native_revision:Some(10), open_pending:Some(pending(0,10)), requests:[1,0,0,0],
        observations:vec![serde_json::json!({"baseline":metadata_baseline(false)})], inputs:Some(fields.clone()), ..MetadataRecord::default() };
    let args: metadata::PrepareMetadataTextEdit = serde_json::from_value(serde_json::json!({
        "sessionId":session_id,"revision":revision,"expectedBaseline":metadata_baseline(false),"fields":fields,
        "draftRevision":2,"baselineGeneration":0})).unwrap();

    let mut reply_first = record();
    assert!(reply_first.observe_open(&opening,true,Some(&config)));
    assert!(reply_first.open_pending.is_none() && reply_first.sessions[0].open_returned);
    assert_eq!(reply_first.sessions[0].projection.phase,edit::Phase::Opening);
    assert!(reply_first.sessions[0].projection.checkout.is_none() && !reply_first.record_prepare(&args));
    assert!(!reply_first.observe_open(&opening,true,None)); // Duplicate reply is not a new original.

    // Cover both schedules: Editing before the Open hook, and the actual
    // controller Prepare before that hook. The captured older Opening cannot
    // replace the checkout, pending Prepare, or first native revision.
    for prepare_before_reply in [false,true] {
        let mut early = record();
        assert!(early.observe_open(&editing,false,Some(&config)));
        assert!(early.sessions[0].config_blocked && !early.sessions[0].open_returned);
        assert_eq!(early.sessions[0].first_revision,12);
        early.native_revision = Some(editing.status_revision); // Completed native projection reconciliation.
        if prepare_before_reply { assert!(early.record_prepare(&args)); }
        let before = serde_json::to_value(&early.sessions[0].projection).unwrap();
        assert!(!early.observe_open(&opening,true,Some(&config))); // No second snapshot path.
        assert!(early.observe_open(&opening,true,None));
        assert_eq!(serde_json::to_value(&early.sessions[0].projection).unwrap(),before);
        assert_eq!(early.native_revision,Some(12));
        if !prepare_before_reply { assert!(early.record_prepare(&args)); }
        assert_eq!(early.prepare_pending,Some(0)); assert_eq!(early.sessions[0].binding,Some((2,0)));
        assert!(early.sessions[0].prepare_requested && early.sessions[0].open_returned && !early.record_prepare(&args));
    }

    let mut no_reply = record(); assert!(no_reply.observe_open(&editing,false,Some(&config)));
    assert!(no_reply.record_prepare(&args));
    // Isolate the real visible-review gate with otherwise-ready inert data.
    no_reply.sessions[0].projection.phase = edit::Phase::Reviewing;
    no_reply.sessions[0].prepared = Some(Value::Null); no_reply.sessions[0].review = Some(Value::Null);
    assert!(!no_reply.sessions[0].live_review() && no_reply.open_pending.is_some());
    let mut foreign = opening.clone(); foreign.active.as_mut().unwrap().session_id = "3".repeat(32);
    assert!(!no_reply.observe_open(&foreign,true,None));
    let mut too_late = opening.clone(); too_late.status_revision = 13;
    assert!(!no_reply.observe_open(&too_late,true,None));
    assert!(no_reply.observe_open(&opening,true,None) && no_reply.sessions[0].live_review());
    assert_eq!(no_reply.sessions[0].projection.phase,edit::Phase::Reviewing);

    let mutations: [fn(&mut metadata::MetadataTextEditStatus);11] = [
        |s|s.status_revision = 10,
        |s|s.domain = "wrong-domain",
        |s|s.window_generation = "4".repeat(32),
        |s|s.active.as_mut().unwrap().project_id = "other-project".into(),
        |s|s.active.as_mut().unwrap().owner_generation = "4".repeat(32),
        |s|s.active.as_mut().unwrap().domain = "wrong-domain",
        |s|s.active.as_mut().unwrap().platform = metadata::Platform::Ios,
        |s|s.active.as_mut().unwrap().locale = "fr-FR".into(),
        |s|s.active.as_mut().unwrap().phase = edit::Phase::Preparing,
        |s|s.active.as_mut().unwrap().checkout = None,
        |s|s.active.as_mut().unwrap().checkout.as_mut().unwrap().metadata_root = "other/root".into(),
    ];
    for mutate in mutations {
        let mut wrong = editing.clone(); mutate(&mut wrong);
        let mut sample = record(); assert!(!sample.observe_open(&wrong,false,Some(&config)) && sample.sessions.is_empty());
    }
    let mut missing_config = record(); assert!(!missing_config.observe_open(&editing,false,None));
    let mut stale_config = config.clone(); stale_config.status_revision = 11;
    assert!(!missing_config.observe_open(&editing,false,Some(&stale_config)));
    let mut available_config = config.clone(); available_config.capability.available = true;
    assert!(!missing_config.observe_open(&editing,false,Some(&available_config)) && missing_config.sessions.is_empty());

    // Inert settled-first-original data isolates second-original ID reuse;
    // these booleans are never passed to a native observation or receipt.
    reply_first.sessions[0].finality = Some(InstalledMetadataFinality { session_id:session_id.clone(),
        project_id:"inert-project".into(), owner_generation:generation.clone(), writer_frames:2, stdout_frames:3,
        inspection_joined:true, acquisition_joined:true, child_waited_success:true, stdin_closed:true,
        stdout_eof_closed:true, stderr_eof_closed:true, io_joined:true, driver_joined:true, watchdog_joined:true,
        manager_joined:true, runtime_ledger_settled:true, runtime_settlement_joined:true });
    reply_first.open_pending = Some(pending(1,20)); reply_first.requests[0] = 2;
    let mut reused = opening.clone(); reused.status_revision = 21;
    assert_eq!(reply_first.open_match(&reused,true),None);
    reused.active.as_mut().unwrap().session_id = "3".repeat(32);
    assert_eq!(reply_first.open_match(&reused,true),Some(MetadataOpenMatch::First));
}


// Three fixed, serial UI submissions. These are expected public fixture DATA,
// never substitute checkout, plan, status, result, original or finality objects.
const VERSION_EDIT_SHA256: &str = "3b8dbd6b58e9f42a0ed893e73020cf2f8ddde787e2b1a153da49d382b1e7a9d4";
const VERSION_TEXTS: [&str; 2] = ["VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n", "VERSION_NAME=2.3.4\nBUILD_NUMBER=8\n"];
const VERSION_BINDINGS: [(u32,u32);3] = [(2,0),(4,1),(4,2)];
const VERSION_JOURNALS: [&str;3] = [".mobile-release-version-prepare", ".mobile-release-version", ".mobile-release-version-cleanup"];
fn version_values(index: usize) -> Option<version::Values> {
    let (name,build) = match index { 0 => ("1.2.3","7"), 1 | 2 => ("2.3.4","8"), _ => return None };
    Some(version::Values { name:name.into(), build:build.into() })
}
fn version_digest(index: usize) -> Option<&'static str> {
    match index { 0 => Some(VERSION_SHA256), 1 | 2 => Some(VERSION_EDIT_SHA256), _ => None }
}
fn version_baseline(index: usize) -> Option<Value> {
    Some(serde_json::json!({"savedConfig":{"bytes":CONFIG_BYTES,"sha256":CONFIG_SHA256},
        "savedVersion":if index == 0 { serde_json::json!({"state":"absent"}) } else {
            serde_json::json!({"state":"present","bytes":VERSION_BYTES,"sha256":version_digest(index.checked_sub(1)?)?}) }}))
}
fn version_checkout_matches(index: usize, checkout: &version::Checkout) -> bool {
    index < 3 && edit::token(&checkout.revision) && checkout.source == VERSION_SOURCE
        && checkout.name_key == "VERSION_NAME" && checkout.build_key == "BUILD_NUMBER" && !checkout.ios_enabled
        && checkout.values == (if index == 0 { None } else { version_values(index - 1) })
        && serde_json::to_value(&checkout.baseline).ok() == version_baseline(index)
}
fn version_review_sample(index: usize, view: &version::PreparedView) -> Option<Value> {
    let values = version_values(index)?; let after_text = VERSION_TEXTS[usize::from(index != 0)];
    let before = if index == 0 { serde_json::json!({"state":"absent"}) } else {
        serde_json::json!({"state":"present","text":VERSION_TEXTS[usize::from(index == 2)],
            "bytes":VERSION_BYTES,"sha256":version_digest(index - 1)?}) };
    let after = serde_json::json!({"text":after_text,"bytes":VERSION_BYTES,"sha256":version_digest(index)?});
    let action = match index { 0 => "create", 1 => "replace", 2 => "preserve", _ => return None };
    let expected = serde_json::json!({"schemaVersion":1,"source":VERSION_SOURCE,"nameKey":"VERSION_NAME","buildKey":"BUILD_NUMBER",
        "iosEnabled":false,"intent":if index == 0 { "create" } else { "edit" },"values":values,
        "file":{"path":VERSION_SOURCE,"action":action,"before":before,"after":after,
            "requestedMode":if index == 0 { 0o644 } else { 0o600 },"preserveMode":index != 0},
        "createDirectories":[],"lineEndings":{"before":if index == 0 { vec![] } else { vec!["lf"] },
            "after":["lf"],"finalNewlineBefore":index != 0,"finalNewlineAfter":true,"preserved":index != 0},
        "validation":{"valid":true,"state":"format-valid","issues":[]}});
    if serde_json::to_value(view).ok()? != expected { return None; }
    Some(serde_json::json!({
        "title":match index { 0 => "Create the observed-absent source", 1 => "Edit only the two selected value spans", _ => "Preserve the exact original" },
        "facts":[
            format!("{VERSION_SOURCE} — {action}. Saved name key VERSION_NAME; build key BUILD_NUMBER. Saved iOS policy is disabled."),
            format!("Reviewed values: {} · Build {}. Core format-valid only; Store acceptance and artifact agreement remain unknown.",values.name,values.build),
            if index == 0 { "Creation emits exactly two KEY=VALUE lines, UTF-8/LF with a final newline. No serializer or automatic version bump is used." }
                else { "Unrelated bytes, spacing, quotes, comments, all separators and final-newline presence are preserved. No serializer or automatic version bump is used." },
            if index == 0 { "Request new-file mode 0644. New-file and directory modes are subject to the native umask; parent directories request 0755." }
                else { "Preserve original mode 0600." },
            "No parent directories will be created. Saved configuration and .gitignore are rechecked read-only dependencies.",
            "Complete bounded text, never a truncated diff. The browser may display separators similarly; the explicit styles, byte counts and native hashes describe the frozen bytes."
        ],"before":before,"after":after
    }))
}
fn version_fixture_absent(path: &Path) -> bool {
    matches!(std::fs::symlink_metadata(path),Err(error) if error.kind() == std::io::ErrorKind::NotFound)
}
struct VersionFixture { originals: [FixtureIdentity;5] }
impl VersionFixture {
    fn sample(root: &Path) -> Option<[FixtureIdentity;5]> {
        let names = ["","release","release/mobile-release.json",".gitignore","unrelated.txt"];
        let mut rows = Vec::with_capacity(names.len());
        for (index,name) in names.iter().enumerate() {
            let row = fixture_identity(&root.join(name)).ok()?;
            if row[2] != (if index < 2 { 0o040700 } else { 0o100600 })
                || row[3] != u64::from(rustix::process::geteuid().as_raw())
                || row[4] != u64::from(rustix::process::getegid().as_raw())
                || index >= 2 && (row[5] != 1 || row[6] != [u64::from(CONFIG_BYTES),u64::from(IGNORE_BYTES),36][index - 2]) { return None; }
            rows.push(row);
        }
        rows.try_into().ok()
    }
    fn begin(root: &Path) -> Option<Self> {
        let originals = Self::sample(root)?;
        if !version_fixture_absent(&root.join(VERSION_SOURCE))
            || !VERSION_JOURNALS.iter().all(|name|version_fixture_absent(&root.join(name)))
            || Self::sample(root)? != originals { return None; }
        Some(Self { originals })
    }
    fn after_original_final(&self, root: &Path) -> Option<FixtureIdentity> {
        // Only called after the genuine original finality getter succeeded.
        // Fixed metadata samples do not read text, change files or authorize cleanup.
        let before = Self::sample(root)?;
        if before[0][..6] != self.originals[0][..6] || before[1..] != self.originals[1..]
            || !VERSION_JOURNALS.iter().all(|name|version_fixture_absent(&root.join(name))) { return None; }
        let source = fixture_identity(&root.join(VERSION_SOURCE)).ok()?;
        if source[2] != 0o100600 || source[3..5] != self.originals[2][3..5]
            || source[5] != 1 || source[6] != u64::from(VERSION_BYTES)
            || fixture_identity(&root.join(VERSION_SOURCE)).ok()? != source || Self::sample(root)? != before { return None; }
        Some(source)
    }
}
struct VersionSession {
    projection: version::Projection, prepared: Option<Value>, review: Option<Value>, binding: Option<(u32,u32)>,
    first_revision: u32, open_returned: bool, open_visible: bool, entered: [bool;2], inputs_visible: bool,
    prepare_requested: bool, prepare_returned: bool, review_visible: bool, config_blocked: bool,
    confirmation_opened: bool, initially_disabled: bool, checkbox_only_disabled: bool, typed_save: bool, acknowledged: bool,
    apply_requested: bool, apply_returned: bool, saved_visible: bool, readback_visible: bool,
    finality: Option<InstalledVersionFinality>, source_final: Option<FixtureIdentity>,
}
impl VersionSession {
    fn live_review(&self) -> bool {
        self.open_returned && self.projection.phase == edit::Phase::Reviewing && self.projection.review_remaining_ms > 0
            && !self.projection.apply_submitted && self.projection.native_reason == edit::NativeEditReason::None
            && self.projection.native_finality == edit::NativeFinality::Pending && self.projection.core_outcome.is_none()
            && self.prepared.is_some() && self.review.is_some() && self.finality.is_none()
    }
    fn complete(&self, index: usize) -> bool {
        self.open_returned && self.open_visible && self.entered == (if index == 2 { [false;2] } else { [true;2] })
            && self.inputs_visible && self.prepare_requested && self.prepare_returned && self.binding == VERSION_BINDINGS.get(index).copied()
            && self.review_visible && self.config_blocked && self.confirmation_opened && self.initially_disabled
            && self.checkbox_only_disabled && self.typed_save && self.acknowledged && self.apply_requested && self.apply_returned
            && self.saved_visible && self.readback_visible && self.finality.is_some() && self.source_final.is_some()
            && self.projection.phase == edit::Phase::Final && self.projection.native_finality == edit::NativeFinality::Settled
            && !self.projection.late_settled
    }
}
struct VersionOpen { index: usize, after_revision: u32, project_id: String, generation: String }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VersionOpenMatch { First, Reply }
#[derive(Default)]
struct VersionRecord {
    capability: bool, ready: bool, native_revision: Option<u32>, saved_config: Option<Value>, fixture: Option<VersionFixture>,
    sessions: Vec<VersionSession>, requests: [u8;4], open_pending: Option<VersionOpen>, prepare_pending: Option<usize>,
    observe_requests: u8, observe_pending: bool, observations: Vec<VersionSample>,
}
impl VersionRecord {
    fn open_match(&self, status: &version::ReleaseVersionEditStatus, returned: bool) -> Option<VersionOpenMatch> {
        let pending = self.open_pending.as_ref()?; let owner = status.active.as_ref()?;
        if pending.index >= 3 || usize::from(self.requests[0]) != pending.index + 1
            || status.schema_version != 1 || status.domain != version::DOMAIN || status.window_generation != pending.generation
            || !edit::token(&status.window_generation) || status.status_revision <= pending.after_revision
            || !status.capability.available || status.capability.reason != edit::EditAvailability::Available
            || owner.domain != version::DOMAIN || owner.project_id != pending.project_id || owner.owner_generation != pending.generation
            || !edit::token(&owner.session_id) || owner.prepared.is_some() || owner.core_outcome.is_some() || owner.apply_submitted || owner.late_settled
            || owner.native_reason != edit::NativeEditReason::None || owner.native_finality != edit::NativeFinality::Pending
            || (if returned { owner.phase != edit::Phase::Opening } else { !matches!(owner.phase,edit::Phase::Opening | edit::Phase::Editing) })
            || (owner.phase == edit::Phase::Opening) != owner.checkout.is_none() { return None; }
        if self.sessions.len() == pending.index {
            if self.native_revision.is_some_and(|revision|status.status_revision < revision)
                || self.sessions.iter().enumerate().any(|(i,s)|!s.complete(i) || s.projection.session_id == owner.session_id) { return None; }
            if let Some(checkout) = &owner.checkout {
                if !version_checkout_matches(pending.index,checkout)
                    || self.sessions.iter().any(|s|s.projection.checkout.as_ref().is_some_and(|c|c.revision == checkout.revision)) { return None; }
            }
            Some(VersionOpenMatch::First)
        } else {
            let session = self.sessions.get(pending.index)?;
            (returned && self.sessions.len() == pending.index + 1 && !session.open_returned
                && session.projection.session_id == owner.session_id && session.projection.project_id == owner.project_id
                && session.projection.owner_generation == owner.owner_generation && status.status_revision <= session.first_revision)
                .then_some(VersionOpenMatch::Reply)
        }
    }
    fn observe_open(&mut self, status: &version::ReleaseVersionEditStatus, returned: bool, config: Option<&ConfigEditStatus>) -> bool {
        let Some(matched) = self.open_match(status,returned) else { return false; };
        let Some(pending) = self.open_pending.as_ref() else { return false; }; let index = pending.index;
        if matched == VersionOpenMatch::First {
            let Some(config) = config else { return false; };
            if config.schema_version != 1 || config.window_generation != pending.generation || config.status_revision < status.status_revision
                || config.capability.available || config.capability.reason != edit::EditAvailability::OtherEditActive
                || config.active.is_some() || config.last_terminal.is_some() { return false; }
            let Some(owner) = status.active.as_ref() else { return false; };
            self.sessions.push(VersionSession { projection:owner.clone(), prepared:None, review:None, binding:None,
                first_revision:status.status_revision, open_returned:false, open_visible:false, entered:[false;2], inputs_visible:false,
                prepare_requested:false, prepare_returned:false, review_visible:false, config_blocked:true,
                confirmation_opened:false, initially_disabled:false, checkbox_only_disabled:false, typed_save:false, acknowledged:false,
                apply_requested:false, apply_returned:false, saved_visible:false, readback_visible:false, finality:None, source_final:None });
        } else if config.is_some() { return false; }
        if returned {
            // Preserve later actual events; the original captured Opening reply
            // independently closes the request/reply obligation, never regresses it.
            self.sessions[index].open_returned = true; self.open_pending = None;
        }
        true
    }
    fn record_prepare(&mut self, args: &version::PrepareReleaseVersionEdit) -> bool {
        let index = usize::from(self.requests[1]); let Some(session) = self.sessions.get(index) else { return false; };
        if index >= 3 || self.prepare_pending.is_some() || session.prepare_requested || session.binding.is_some()
            || !session.open_visible || !session.inputs_visible || !session.config_blocked
            || session.projection.phase != edit::Phase::Editing || session.projection.session_id != args.session_id
            || (args.draft_revision,args.baseline_generation) != VERSION_BINDINGS[index]
            || args.intent != (if index == 0 { version::Intent::Create } else { version::Intent::Edit })
            || Some(args.values.clone()) != version_values(index)
            || !session.projection.checkout.as_ref().is_some_and(|c|c.revision == args.revision && c.baseline == args.expected_baseline)
            || serde_json::to_value(&args.expected_baseline).ok() != version_baseline(index) { return false; }
        let session = &mut self.sessions[index]; session.prepare_requested = true;
        session.binding = Some((args.draft_revision,args.baseline_generation));
        self.prepare_pending = Some(index); self.requests[1] += 1; true
    }
    fn complete(&self) -> bool {
        self.capability && self.saved_config.is_some() && self.fixture.is_some() && self.requests == [3,3,3,0]
            && self.open_pending.is_none() && self.prepare_pending.is_none() && self.observe_requests == 3 && !self.observe_pending
            && self.observations.len() == 3 && self.observations.iter().all(|o|o.pair_matched)
            && self.sessions.len() == 3 && self.sessions.iter().enumerate().all(|(i,s)|s.complete(i))
            && self.sessions[1].source_final.is_some_and(|s|self.sessions[0].source_final.is_some_and(|old|s[..2] != old[..2]))
            && self.sessions[2].source_final == self.sessions[1].source_final
    }
}
fn version_original_final(facts: &InstalledVersionFinality, projection: &version::Projection) -> bool {
    projection.domain == version::DOMAIN && facts.session_id == projection.session_id && facts.project_id == projection.project_id
        && facts.owner_generation == projection.owner_generation && facts.writer_frames == 3 && facts.stdout_frames == 3
        && facts.inspection_joined && facts.acquisition_joined && facts.child_waited_success
        && facts.stdin_closed && facts.stdout_eof_closed && facts.stderr_eof_closed && facts.io_joined
        && facts.driver_joined && facts.watchdog_joined && facts.manager_joined
        && facts.runtime_ledger_settled && facts.runtime_settlement_joined
}

fn version_editor_display(index: usize, edited: bool, saved: bool, reviewing: bool) -> Option<Value> {
    if index >= 3 { return None; }
    let original = if saved { version_values(index) } else if index == 0 { None } else { version_values(index - 1) };
    let current = if edited || saved { version_values(index)? } else { original.clone().unwrap_or(version::Values { name:String::new(),build:String::new() }) };
    let mut digests = vec![format!("Saved config: {CONFIG_BYTES} bytes · SHA256 {CONFIG_SHA256}")];
    if saved || index != 0 {
        digests.push(format!("Saved source: {VERSION_BYTES} bytes · SHA256 {}",version_digest(if saved { index } else { index - 1 })?));
    }
    Some(serde_json::json!({"title":if original.is_none() { "Create saved version values" } else { "Edit saved version values" },
        "project":"Project: version-project. No automatic bump, trimming or numeric coercion.",
        "badge":"Separate native writer","selection":[
            format!("Saved source: {VERSION_SOURCE}"),
            "Saved keys: VERSION_NAME and BUILD_NUMBER. iOS policy is disabled.",
            original.as_ref().map(|v|format!("Original values: {} · Build {}. These may need policy correction.",v.name,v.build))
                .unwrap_or("Observed absent: creation is explicit. The empty fields below are not detected values.".into())],
        "digests":digests,"values":current,"openAvailable":saved,
        "reviewLabel":if original.is_none() { "Validate and review creation" } else { "Validate and review values" },
        "reviewAvailable":!reviewing && (saved || edited || index != 0)}))
}
fn version_outcome_display(index: usize, session: &VersionSession) -> Option<Value> {
    let prepared = session.projection.prepared.as_ref()?; let core = session.projection.core_outcome.as_ref()?;
    let raw = serde_json::to_value(core).ok()?;
    Some(serde_json::json!({"title":if index == 2 { "Submitted version values unchanged and rechecked" } else { "Submitted version values saved" },
        "submitted":format!("Submitted review: {} · Build {} · {}.",prepared.view.values.name,prepared.view.values.build,prepared.view.source),
        "facts":format!("Core effect: {}; journal: {}; native finality: settled. Reason: {}.",
            raw["effect"].as_str()?,raw["journal"].as_str()?,raw["reason"].as_str()?)}))
}

fn assert_version_open_race_contract() {
    // Inert DATA through the same request/reply predicates, not a native
    // execution, acquired original, settled session, filesystem or receipt.
    let generation = "0".repeat(32); let session_id = "1".repeat(32); let revision = "2".repeat(32);
    let opening = version::ReleaseVersionEditStatus { schema_version:1, domain:version::DOMAIN,
        window_generation:generation.clone(), status_revision:11,
        capability:edit::Capability { available:true, reason:edit::EditAvailability::Available },
        active:Some(version::Projection { domain:version::DOMAIN, project_id:"inert-project".into(),
            session_id:session_id.clone(), owner_generation:generation.clone(), phase:edit::Phase::Opening,
            review_remaining_ms:1000, checkout:None, prepared:None, apply_submitted:false, core_outcome:None,
            native_reason:edit::NativeEditReason::None, native_finality:edit::NativeFinality::Pending, late_settled:false }),
        last_terminal:None };
    let mut editing = opening.clone(); editing.status_revision = 12;
    let active = editing.active.as_mut().unwrap(); active.phase = edit::Phase::Editing;
    active.checkout = Some(version::Checkout { revision:revision.clone(), source:VERSION_SOURCE.into(),
        name_key:"VERSION_NAME".into(), build_key:"BUILD_NUMBER".into(), ios_enabled:false, values:None,
        baseline:serde_json::from_value(version_baseline(0).unwrap()).unwrap() });
    let config = ConfigEditStatus { schema_version:1, window_generation:generation.clone(), status_revision:13,
        capability:edit::Capability { available:false, reason:edit::EditAvailability::OtherEditActive }, active:None, last_terminal:None };
    let record = || VersionRecord { native_revision:Some(10), requests:[1,0,0,0],
        open_pending:Some(VersionOpen { index:0,after_revision:10,project_id:"inert-project".into(),generation:generation.clone() }),
        ..VersionRecord::default() };
    let args: version::PrepareReleaseVersionEdit = serde_json::from_value(serde_json::json!({
        "sessionId":session_id,"revision":revision,"expectedBaseline":version_baseline(0).unwrap(),"intent":"create",
        "values":{"name":"1.2.3","build":"7"},"draftRevision":2,"baselineGeneration":0})).unwrap();
    let mut reply_first = record();
    assert!(reply_first.observe_open(&opening,true,Some(&config)));
    assert!(reply_first.open_pending.is_none() && reply_first.sessions[0].open_returned);
    assert_eq!(reply_first.sessions[0].projection.phase,edit::Phase::Opening);
    assert!(!reply_first.record_prepare(&args) && !reply_first.observe_open(&opening,true,None));
    for prepare_before_reply in [false,true] {
        let mut early = record();
        assert!(early.observe_open(&editing,false,Some(&config)));
        assert_eq!(early.sessions[0].first_revision,12);
        assert!(early.sessions[0].config_blocked && !early.sessions[0].open_returned);
        early.native_revision = Some(12);
        // Isolate request/reply scheduling; no UI observation is claimed.
        early.sessions[0].open_visible = true; early.sessions[0].inputs_visible = true;
        if prepare_before_reply { assert!(early.record_prepare(&args)); }
        let before = serde_json::to_value(&early.sessions[0].projection).unwrap();
        assert!(!early.observe_open(&opening,true,Some(&config)));
        assert!(early.observe_open(&opening,true,None));
        assert_eq!(serde_json::to_value(&early.sessions[0].projection).unwrap(),before);
        assert_eq!(early.native_revision,Some(12));
        if !prepare_before_reply { assert!(early.record_prepare(&args)); }
        assert_eq!(early.prepare_pending,Some(0)); assert_eq!(early.sessions[0].binding,Some((2,0)));
        assert!(!early.record_prepare(&args) && !early.complete());
    }
    let mut no_reply = record(); assert!(no_reply.observe_open(&editing,false,Some(&config)));
    no_reply.sessions[0].projection.phase = edit::Phase::Reviewing;
    no_reply.sessions[0].prepared = Some(Value::Null); no_reply.sessions[0].review = Some(Value::Null);
    assert!(!no_reply.sessions[0].live_review() && no_reply.open_pending.is_some());
    let mut foreign = opening.clone(); foreign.active.as_mut().unwrap().session_id = "3".repeat(32);
    assert!(!no_reply.observe_open(&foreign,true,None));
    let mut later = opening.clone(); later.status_revision = 13;
    assert!(!no_reply.observe_open(&later,true,None));
    assert!(no_reply.observe_open(&opening,true,None) && no_reply.sessions[0].live_review());
    assert_eq!(no_reply.sessions[0].projection.phase,edit::Phase::Reviewing);
    assert!(!no_reply.complete()); // No native original/finality can be minted by these DATA.
    let mutations: [fn(&mut version::ReleaseVersionEditStatus);10] = [
        |s|s.status_revision = 10,
        |s|s.domain = "wrong-domain",
        |s|s.window_generation = "4".repeat(32),
        |s|s.active.as_mut().unwrap().project_id = "other-project".into(),
        |s|s.active.as_mut().unwrap().owner_generation = "4".repeat(32),
        |s|s.active.as_mut().unwrap().domain = "wrong-domain",
        |s|s.active.as_mut().unwrap().phase = edit::Phase::Preparing,
        |s|s.active.as_mut().unwrap().checkout = None,
        |s|s.active.as_mut().unwrap().checkout.as_mut().unwrap().source = "other-source".into(),
        |s|s.active.as_mut().unwrap().checkout.as_mut().unwrap().ios_enabled = true,
    ];
    for mutate in mutations {
        let mut wrong = editing.clone(); mutate(&mut wrong);
        let mut sample = record(); assert!(!sample.observe_open(&wrong,false,Some(&config)) && sample.sessions.is_empty());
    }
    let mut missing = record(); assert!(!missing.observe_open(&editing,false,None));
    let mut stale = config.clone(); stale.status_revision = 11;
    assert!(!missing.observe_open(&editing,false,Some(&stale)));
    let mut available = config.clone(); available.capability.available = true;
    assert!(!missing.observe_open(&editing,false,Some(&available)) && missing.sessions.is_empty());
}

struct Record {
    attached: bool, started: bool, loaded: bool, info: bool, methods: usize, catalog: bool, environment: bool,
    pickers: [Picker; 2], cancel_returned: bool, cancelled: bool, project: Option<Project>, selected: bool,
    project_witness: Option<InstalledProjectWitness>, candidate: Candidate, paths: Paths, workflow: WorkflowRecord, metadata: MetadataRecord, version: VersionRecord,
    session: SessionRecord,
    snapshot_requests: u8, snapshot: bool, snapshot_visible: bool, suggest_called: bool, suggested: Option<Value>, provenance: Option<Value>,
    provenance_visible: bool, adopted: bool, draft_visible: bool, guidance: Guidance,
    capability: bool, generation: Option<String>, native_revision: Option<u32>, sessions: Vec<SaveSession>, requests: [u8; 4],
    open_pending: bool, prepare_pending: Option<usize>, apply_returned: bool,
    confirmation_opened: u8, kept_reviewing: bool, acknowledged: bool, saved_visible: bool,
    readback: bool, readback_visible: bool, saved_reads: SavedReads, saved_draft_retained: bool, noop_outstanding: bool, originals_final: bool,
    step: Step, pending: Option<Pending>, evaluations: u16, trace: (Step, Boundary), bootstrap: BootstrapProgress,
    evidence_diagnostic: Option<EvidenceDiagnostic>, snapshot_diagnostic: Option<SnapshotDiagnostic>,
    close_prevented: bool, native_id: Option<u32>, activated: bool,
    responded: bool, disposal_response: bool, destroyed: bool, released: bool, gtk_returned: bool,
    relay_joined: bool, exit: bool, held: Option<HeldAppInfo>, failure_quit: FailureQuit,
}
fn failure_quit(r: &mut Record) -> &mut FailureQuit {
    if !r.failure_quit.armed {
        // Adopt only already-observed original facts. Keep the recipe step,
        // pending callback and success flags untouched, including QuitCancel.
        let original = if matches!(r.step, Step::Session(SessionStep::QuitCancel | SessionStep::QuitPreserved)) {
            let p = &r.session.quit_cancel;
            Some(FailureQuit { close_requested: true, close_prevented: r.session.cancel_close_prevented,
                id: r.session.quit_cancel_id, selects_ok: false, pending: r.pending == Some(Pending::Gtk) || p.activated || p.returned,
                activated: p.activated, responded: p.responded, disposal: p.disposal,
                destroyed: p.destroyed, released: p.released, returned: p.returned, ..FailureQuit::default() })
        } else if matches!(r.step, Step::Quit | Step::Exit) || r.close_prevented || r.native_id.is_some() {
            Some(FailureQuit { close_requested: true, close_prevented: r.close_prevented, id: r.native_id, selects_ok: true,
                pending: r.pending == Some(Pending::Gtk) || r.activated || r.gtk_returned,
                activated: r.activated, responded: r.responded, disposal: r.disposal_response,
                destroyed: r.destroyed, released: r.released, returned: r.gtk_returned, ..FailureQuit::default() })
        } else { None };
        r.failure_quit.begin(original);
    }
    &mut r.failure_quit
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
    case: Case, main: ThreadId, start: Instant, end: Instant, project_path: Option<PathBuf>, evidence_path: Option<PathBuf>, failed: FailureLatch,
    failure_reported: AtomicBool, failure_sink: rustix::fd::OwnedFd, record: Mutex<Record>, commands: Option<Arc<commands::Control>>,
}
impl Observation {
    fn new(case: Case, failure_sink: rustix::fd::OwnedFd) -> Self {
        let start = Instant::now(); let end = start + Duration::from_secs(45);
        let project_path = (case != Case::Outstanding).then(project_path).flatten().map(|path|
            match case { Case::ProjectPaths => path.with_file_name("path-project"),
                Case::WorkflowApply => path.with_file_name("workflow-project"),
                Case::Session(case) => path.with_file_name(case.name()).join("project"),
                Case::Commands(case) => path.with_file_name(case.name()).join("project"),
                Case::MetadataSave => path.with_file_name("metadata-project"),
                Case::VersionSave => path.with_file_name("version-project"), _ => path });
        let paths = Paths::new((case == Case::ProjectPaths).then_some(project_path.as_deref()).flatten());
        let evidence_path = project_path.as_ref().and_then(|path| path.parent()).map(|root| root.join("candidate-evidence"));
        Self { case, main: std::thread::current().id(), start, end,
            failed: FailureLatch::new(case != Case::Outstanding && (project_path.is_none() || evidence_path.is_none())
                || case == Case::ProjectPaths && paths.fixture.is_none()), project_path, evidence_path,
            failure_reported: AtomicBool::new(false), failure_sink, commands: case.commands().map(commands::Control::new), record: Mutex::new(Record {
                attached: false, started: false, loaded: false, info: false, methods: 0, catalog: false, environment: false,
                step: Step::Bootstrap, pending: None, evaluations: 0, trace: (Step::Bootstrap, Boundary::Bootstrap),
                bootstrap: BootstrapProgress::NotSampled, evidence_diagnostic: None, snapshot_diagnostic: None,
                pickers: std::array::from_fn(|_| Picker::default()), cancel_returned: false, cancelled: false, project: None, selected: false,
                project_witness: None, candidate: Candidate::default(), paths, workflow: WorkflowRecord::default(), metadata: MetadataRecord::default(), version: VersionRecord::default(),
                session: SessionRecord::new(case.session()),
                snapshot_requests: 0, snapshot: false, snapshot_visible: false, suggest_called: false, suggested: None, provenance: None,
                provenance_visible: false, adopted: false, draft_visible: false, guidance: Guidance::default(),
                capability: false, generation: None, native_revision: None, sessions: Vec::new(), requests: [0; 4],
                open_pending: false, prepare_pending: None, apply_returned: false,
                confirmation_opened: 0, kept_reviewing: false, acknowledged: false, saved_visible: false,
                readback: false, readback_visible: false, saved_reads: SavedReads::default(), saved_draft_retained: false, noop_outstanding: false, originals_final: false,
                close_prevented: false, native_id: None, activated: false, responded: false, disposal_response: false,
                destroyed: false, released: false, gtk_returned: false, relay_joined: false, exit: false, held: None,
                failure_quit: FailureQuit::default(),
            }) }
    }
    #[track_caller]
    fn fail(&self) { self.failed.mark_caller(); }
    fn record(&self) -> Option<MutexGuard<'_, Record>> {
        match self.record.lock() { Ok(record) => Some(record), Err(_) => { self.fail(); None } }
    }
    fn record_at(&self, boundary: Boundary) -> Option<MutexGuard<'_, Record>> {
        let mut r = self.record()?;
        if !self.failed.load(Ordering::SeqCst) {
            r.trace = (r.step, boundary);
            r.session.diagnostic = SessionDiagnostic::sample(r.step,r.evaluations,r.session.diagnostic);
            self.path_sample(&mut r);
        }
        Some(r)
    }
    fn session_wait(&self, r: &mut Record, wait: SessionWait) {
        if !self.failed.load(Ordering::SeqCst) {
            if let Some(mut diagnostic) = SessionDiagnostic::sample(r.step,r.evaluations,r.session.diagnostic) {
                diagnostic.wait = wait; r.session.diagnostic = Some(diagnostic);
            }
        }
    }
    fn session_fail(&self, r: &mut Record, rejection: SessionRejection) {
        self.session_fail_with_first_origin(r, rejection, InstalledSessionFailure::not_recorded());
    }
    fn session_fail_with_first_origin(&self, r: &mut Record, rejection: SessionRejection, first_failure: InstalledSessionFailure) {
        self.session_fail_with_diagnostics(r, rejection, first_failure, InstalledAssessmentFailure::none());
    }
    fn session_fail_with_assessment(&self, r: &mut Record, refusal: SessionRefusal) {
        self.session_fail_with_diagnostics(r, refusal.rejection, InstalledSessionFailure::not_recorded(), refusal.assessment);
    }
    fn session_fail_with_diagnostics(&self, r: &mut Record, rejection: SessionRejection,
        first_failure: InstalledSessionFailure, assessment: InstalledAssessmentFailure) {
        if let Some(mut diagnostic) = SessionDiagnostic::sample(r.trace.0,r.evaluations,r.session.diagnostic) {
            diagnostic.rejection = rejection; diagnostic.first_failure = first_failure; diagnostic.assessment = assessment;
            latch_session_diagnostic(&self.failed,&mut r.session.diagnostic,diagnostic);
        } else { self.fail(); }
    }
    fn path_fail(&self, r: &mut Record, rejection: PathRejection) {
        if let Some(mut diagnostic) = PathDiagnostic::sample(r.trace.0,self.start.elapsed().as_millis(),r.paths.diagnostic) {
            diagnostic.rejection = rejection;
            latch_path_diagnostic(&self.failed,&mut r.paths.diagnostic,diagnostic);
        } else { self.fail(); }
    }
    fn path_sample(&self, r: &mut Record) -> bool {
        if !self.failed.load(Ordering::SeqCst) {
            let step = r.step; let previous = r.paths.diagnostic;
            r.paths.diagnostic = PathDiagnostic::sample_trace(&mut r.trace,step,self.start.elapsed().as_millis(),previous);
            true
        } else { false }
    }
    fn path_callback(&self, step: PathStep, callback: PathCallback) {
        let Some(mut r) = self.record() else { return; };
        if self.failed.load(Ordering::SeqCst) || r.step != Step::Paths(step) { return; }
        if self.path_sample(&mut r) {
            if let Some(diagnostic) = r.paths.diagnostic.as_mut() { diagnostic.mark(callback); }
        }
    }
    pub(super) fn path_wait(&self, wait: PathWait) {
        // Call only after leaving DIALOG/GuiFacts borrows. This is cached DATA,
        // never a reason to skip the original helper or return bookkeeping.
        let Some(mut r) = self.record() else { return; };
        if self.failed.load(Ordering::SeqCst) { return; }
        if self.path_sample(&mut r) {
            if let Some(diagnostic) = r.paths.diagnostic.as_mut() { diagnostic.wait = wait; }
        }
    }
    fn evidence_fail(&self, r: &mut Record, callback: EvidenceCallback, check: EvidenceCheck,
        status: Option<&evidence::Status>, error: EvidenceError) {
        let next = EvidenceDiagnostic { step: r.step, callback, check,
            phase: status.map(|value| value.phase), problem: status.and_then(|value| value.problem), error };
        if !next.valid((r.step, Boundary::Result)) { self.fail(); return; }
        let Record { trace, evidence_diagnostic, .. } = r;
        latch_evidence_diagnostic(&self.failed, trace, evidence_diagnostic, next);
    }
    fn report_failure(&self) {
        if !self.failed.load(Ordering::SeqCst) || self.failure_reported.load(Ordering::SeqCst) { return; }
        let (trace, progress, session, path, evidence, snapshot, site) = match self.record.try_lock() {
            Ok(r) => (r.trace, r.bootstrap, r.session.diagnostic, r.paths.diagnostic, r.evidence_diagnostic,
                r.snapshot_diagnostic, self.failed.site()), Err(_) => return };
        if self.failure_reported.swap(true, Ordering::SeqCst) { return; }
        // Fixed enums and bounded cached counters/recipe indices, outside every
        // record/GTK lock. No identifiers, DTOs, inputs or exception bodies.
        // One unbuffered attempt before stderr: partial/EINTR/error is not
        // retried, formatted or allowed to affect the original failure latch.
        let frame = if snapshot.is_some() || site.is_some() && matches!(trace.0, Step::Selected | Step::ReadSnapshot) {
            snapshot_failure_frame(trace, progress, site, snapshot)
        } else { failure_frame(trace, progress, session, path, evidence) };
        if let Some((bytes, length)) = frame {
            if let Some(pair) = bytes.get(..length) { let _ = rustix::io::write(&self.failure_sink, pair); }
        }
        super::diagnostic(trace.0.failure_line()); super::diagnostic(trace.1.failure_line());
        super::diagnostic(progress.failure_line());
    }
    fn report_failure_handoff(&self, normal_return: bool) {
        // Copy DATA nonblockingly; the guard is gone before diagnostic output.
        // Missing facts/channel are not a reason to retry or alter the verdict.
        let snapshot = self.record.try_lock().ok().map(|r| r.failure_quit);
        if let Some(line) = failure_handoff_line(self.failed.load(Ordering::SeqCst), normal_return, snapshot) {
            super::diagnostic(line);
        }
    }
    fn refuse_failure_quit(&self) {
        if let Some(mut r) = self.record() { failure_quit(&mut r).refuse(); }
    }
    fn failure_tick(self: &Arc<Self>, app: &tauri::AppHandle) {
        if !self.failed.load(Ordering::SeqCst) { return; }
        self.report_failure();
        let action = {
            let Some(mut r) = self.record() else { return; };
            if std::thread::current().id() == self.main || !r.attached { failure_quit(&mut r).refuse(); return; }
            failure_quit(&mut r).reserve(self.failed.load(Ordering::SeqCst), Instant::now() < self.end)
        };
        // All claims precede external calls and every Record guard is gone.
        // A refused/missing original stays refused; only the existing relay
        // waits for an original native-created callback, never redispatches it.
        let Some(action) = action else { return; };
        let Some(window) = app.get_webview_window(super::MAIN_WINDOW) else { self.refuse_failure_quit(); return; };
        match action {
            FailureQuitAction::Close => { if window.close().is_err() { self.refuse_failure_quit(); } },
            FailureQuitAction::Activate => {
                let q = self.clone(); let app = app.clone();
                if window.run_on_main_thread(move || {
                    let result = super::owned_gtk::activate_observed_quit(&app, &q);
                    q.gtk_returned(result);
                }).is_err() { self.refuse_failure_quit(); }
            },
        }
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
    pub(super) fn attach_session(self: &Arc<Self>, document: &crate::asset_session::DocumentBinding) -> Result<(), BridgeError> {
        let Some(case) = self.case.session() else { return Ok(()); };
        let mut r = self.record().ok_or_else(BridgeError::cleanup_unknown)?;
        if !r.attached || r.session.admission_issued || r.started || self.project_path().is_none() { return Err(BridgeError::invalid()); }
        r.session.fixture = Some(SessionFixture::capture(self.project_path().ok_or_else(BridgeError::invalid)?,case).map_err(|_| BridgeError::invalid())?);
        r.session.admission_issued = true; drop(r);
        document.admit_installed_session(SessionAdmission { original: Arc::downgrade(self), case })
    }
    pub(super) fn attach_commands(self: &Arc<Self>, document: &crate::asset_session::DocumentBinding) -> Result<(), BridgeError> {
        if let Some(commands) = &self.commands { commands.attach(self, document)?; } Ok(())
    }
    pub(super) fn commands_request(&self, command: commands::Command, value: &Value) {
        if let Some(commands) = &self.commands { commands.request(command, value); }
    }
    pub(super) fn commands_result<T: serde::Serialize>(&self, command: commands::Command, result: &Result<T, BridgeError>) {
        if let Some(commands) = &self.commands { commands.returned(command, result); }
    }
    pub(super) fn page_load(&self, trusted: bool, finished: bool) {
        let Some(mut r) = self.record_at(Boundary::Bootstrap) else { return; };
        if !trusted || !r.attached || if finished { !r.started || r.loaded } else { r.started } { self.fail(); return; }
        if finished { r.loaded = true; } else { r.started = true; }
    }
    pub(super) fn app_info(&self, info: &AppInfo) {
        if self.case == Case::Outstanding {
            // The original result may arrive during genuine Quit, including
            // after finish took the held token. Do not require later GUI flags.
            let Some(mut r) = self.record() else { return; };
            let result = outstanding_info(r.step, info.runtime.state == "available", info.capabilities.is_some());
            if result != OutstandingInfo::ShutdownUnavailable {
                let next = if result == OutstandingInfo::ReturnedBeforeHold { BootstrapProgress::AppInfoReturnedBeforeHold }
                    else { r.bootstrap };
                let Record { step, trace, bootstrap, .. } = &mut *r;
                latch_failure(&self.failed, trace, bootstrap, (*step, Boundary::Result), next);
            }
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
            && methods.iter().filter(available).count() == METHODS.len() + usize::from(self.case.session().is_some())
            && METHODS.iter().all(|name| methods.iter().filter(available).filter(|m| m.get("method").and_then(Value::as_str) == Some(*name)).count() == 1)
            && (self.case.session().is_none() || methods.iter().filter(available).filter(|m| m["method"].as_str() == Some("credentials.assess")).count() == 1)
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
                && project.name == (match self.case { Case::ProjectPaths => "path-project", Case::WorkflowApply => "workflow-project",
                    Case::Session(_) | Case::Commands(_) => "project", Case::MetadataSave => "metadata-project",
                    Case::VersionSave => "version-project", _ => "positive-project" })
                && crate::protocol::valid_id(&project.id) => r.project = Some(project.clone()),
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
        if let Some(commands) = &self.commands { commands.snapshot(project_id, result); return; }
        if self.case.session().is_some() { self.session_snapshot_result(project_id,result); return; }
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        let saved = r.snapshot_requests == 2;
        let initial_saved = matches!(self.case,Case::MetadataSave | Case::VersionSave);
        let valid = result.as_ref().is_ok_and(|value| {
            let config = &value["config"]; let discovery = &value["discovery"]; let scan = &discovery["scan"];
            let configuration = if initial_saved {
                config["state"].as_str() == Some("format-valid") && config["issues"].as_array().is_some_and(Vec::is_empty)
                    && config["data"].is_object()
                    && config["content"] == serde_json::json!({"bytes":CONFIG_BYTES,"sha256":CONFIG_SHA256})
            } else if saved {
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
                } else if self.case == Case::VersionSave {
                    discovery["hints"] == serde_json::json!({}) && scan["sourceFiles"].as_u64() == Some(1)
                        && scan["sourceBytes"].as_u64() == Some(u64::from(CONFIG_BYTES))
                        && scan["entries"].as_u64() == Some(4) && scan["excludedEntries"].as_u64() == Some(1)
                } else { discovery["hints"].as_object().is_some_and(|hints| hints.len() == 4)
                && discovery["hints"]["android"]["applicationId"].as_str() == Some(APP_ID)
                && discovery["hints"]["android"]["module"].as_str() == Some(":app")
                && discovery["hints"]["android"]["buildFile"].as_str() == Some("app/build.gradle.kts")
                && discovery["hints"]["versionSource"].as_str() == Some(VERSION_SOURCE)
                && discovery["hints"]["versionNameKey"].as_str() == Some("VERSION_NAME")
                && discovery["hints"]["versionBuildKey"].as_str() == Some("BUILD_NUMBER")
                && scan["sourceFiles"].as_u64() == Some(if saved || initial_saved { 3 } else { 2 })
                && scan["sourceBytes"].as_u64() == Some(PROJECT_SOURCE.len() as u64 + u64::from(VERSION_BYTES) + if saved || initial_saved { u64::from(CONFIG_BYTES) } else { 0 })
                && scan["entries"].as_u64() == Some(if initial_saved { 12 } else if self.case == Case::WorkflowApply { 5 } else if saved { 6 } else { 3 })
                && scan["excludedEntries"].as_u64() == Some(if self.case == Case::WorkflowApply { 2 } else { u64::from(saved || initial_saved) }) })
                && value["issues"].as_array().is_some_and(Vec::is_empty) && assurance(value, "static-text")
        });
        let stage = if saved { matches!(r.step, Step::Refresh | Step::ReadReadback) && r.saved_visible && !r.readback }
            else { r.snapshot_requests == 1 && matches!(r.step, Step::Selected | Step::ReadSnapshot) && !r.snapshot };
        if self.case == Case::Outstanding || !stage || !valid { self.fail(); return; }
        if self.case == Case::MetadataSave { r.metadata.saved_config = result.as_ref().ok().and_then(|v|v["config"].get("data")).cloned(); }
        if self.case == Case::VersionSave { r.version.saved_config = result.as_ref().ok().and_then(|v|v["config"].get("data")).cloned(); }
        if saved { r.readback = true; } else { r.snapshot = true; }
    }
    pub(super) fn suggest_request(&self, hints: &Value) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        if !matches!(self.case, Case::Positive | Case::WorkflowApply) || !r.snapshot_visible || !matches!(r.step, Step::Suggest | Step::ReadSuggestion)
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
        if !matches!(self.case, Case::Positive | Case::WorkflowApply) || !r.suggest_called || r.suggested.is_some() || !matches!(r.step, Step::Suggest | Step::ReadSuggestion)
            || !["android.enabled", "android.applicationId"].iter().all(|path| provenance.iter().any(|row| row["path"].as_str() == Some(*path) && row["source"].as_str() == Some("hint")))
            || !["version.source", "version.nameKey", "version.buildKey"].iter().all(|path| provenance.iter().any(|row|
                row["path"].as_str() == Some(*path) && row["source"].as_str() == Some("hint"))) { self.fail(); return; }
        // Private comparison DATA copied from the genuine core response. Never
        // sent to the renderer, installed in its reducer, or printed in a log.
        r.suggested = Some(value["draft"].clone()); r.provenance = Some(Value::Array(projected));
    }
    pub(super) fn requirements_request(&self, body: &Value) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        if !matches!(self.case, Case::Positive | Case::WorkflowApply) || !r.adopted || !r.draft_visible || r.requests != [0; 4] || !r.sessions.is_empty() || r.open_pending
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
        if !matches!(self.case, Case::Positive | Case::WorkflowApply) || !r.adopted || !r.draft_visible || r.requests != [0; 4] || !r.sessions.is_empty() || r.open_pending
            || !r.guidance.requirements_called || r.guidance.requirements.is_some() || sample.is_none()
            || !matches!(r.step, Step::LoadRequirements | Step::ReadRequirements) { self.fail(); return; }
        r.guidance.requirements = sample;
    }
    pub(super) fn github_request(&self, body: &Value) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        if !matches!(self.case, Case::Positive | Case::WorkflowApply) || !r.adopted || !r.draft_visible || r.requests != [0; 4] || !r.sessions.is_empty() || r.open_pending
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
        if !matches!(self.case, Case::Positive | Case::WorkflowApply) || !r.adopted || !r.draft_visible || r.requests != [0; 4] || !r.sessions.is_empty() || r.open_pending
            || !r.guidance.github_called || r.guidance.proposal.is_some() || sample.is_none()
            || !matches!(r.step, Step::ProposeGitHub | Step::ReadProposal) { self.fail(); return; }
        r.guidance.proposal = sample;
    }
    pub(super) fn release_version_request(&self, body: &Value) {
        if self.case == Case::VersionSave { self.version_save_observe_request(body); return; }
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        if self.case != Case::Positive || !saved_read_context(&r) || r.saved_reads.version_called
            || !matches!(r.step, Step::ReadVersion | Step::ReadVersionCard) || !keys(body, &["projectId"])
            || !r.project.as_ref().is_some_and(|project| body["projectId"].as_str() == Some(project.id.as_str())) { self.fail(); return; }
        r.saved_reads.version_called = true;
    }
    pub(super) fn release_version(&self, result: &Result<crate::release_version_protocol::Observation, BridgeError>) {
        if self.case == Case::VersionSave { self.version_save_observed(result); return; }
        let sample = result.as_ref().ok().and_then(VersionSample::read);
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        if self.case != Case::Positive || !saved_read_context(&r) || !r.saved_reads.version_called || r.saved_reads.version.is_some()
            || sample.is_none() || !matches!(r.step, Step::ReadVersion | Step::ReadVersionCard) { self.fail(); return; }
        r.saved_reads.version = sample;
    }
    pub(super) fn metadata_request(&self, body: &Value) {
        if self.case == Case::MetadataSave { self.metadata_save_observe_request(body); return; }
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        if self.case != Case::Positive || !saved_read_context(&r) || !r.saved_reads.version_visible || r.saved_reads.metadata_called
            || !matches!(r.step, Step::LoadMetadata | Step::ReadMetadata) || !keys(body, &["projectId", "platform", "locale"])
            || body["platform"].as_str() != Some("android") || body["locale"].as_str() != Some("en-US")
            || !r.project.as_ref().is_some_and(|project| body["projectId"].as_str() == Some(project.id.as_str())) { self.fail(); return; }
        r.saved_reads.metadata_called = true;
    }
    pub(super) fn metadata_observation(&self, result: &Result<crate::metadata_text_edit_protocol::Observation, BridgeError>) {
        if self.case == Case::MetadataSave { self.metadata_save_observed(result); return; }
        let sample = result.as_ref().ok().and_then(MetadataSample::read);
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        if self.case != Case::Positive || !saved_read_context(&r) || !r.saved_reads.version_visible
            || !r.saved_reads.metadata_called || r.saved_reads.metadata.is_some() || sample.is_none()
            || !matches!(r.step, Step::LoadMetadata | Step::ReadMetadata) { self.fail(); return; }
        r.saved_reads.metadata = sample;
    }
    pub(super) fn metadata_validation_request(&self, body: &Value) {
        if self.case == Case::MetadataSave { self.metadata_save_validate_request(body); return; }
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        if self.case != Case::Positive || !saved_read_context(&r) || !r.saved_reads.metadata_visible
            || !r.saved_reads.entered.iter().all(|entered| *entered) || r.saved_reads.validation_called
            || !matches!(r.step, Step::ValidateMetadata | Step::ReadMetadataValidation)
            || !keys(body, &["platform", "fields"]) || body["platform"].as_str() != Some("android")
            || !r.saved_reads.inputs.as_ref().is_some_and(|inputs| body.get("fields") == Some(inputs)) { self.fail(); return; }
        r.saved_reads.validation_called = true;
    }
    pub(super) fn metadata_validation(&self, result: &Result<crate::metadata_text_edit_protocol::ValidationResult, BridgeError>) {
        if self.case == Case::MetadataSave { self.metadata_save_validated(result); return; }
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
        let Some(pending) = r.candidate.status_pending.checked_sub(1) else {
            self.evidence_fail(&mut r, EvidenceCallback::Status, EvidenceCheck::StatusPending, None, EvidenceError::None); return;
        };
        r.candidate.status_pending = pending;
        let closing = r.close_prevented;
        match result {
            Err(error) => self.evidence_fail(&mut r, EvidenceCallback::Status, EvidenceCheck::Bridge, None, EvidenceError::classify(error)),
            Ok(status) => if let Err(check) = r.candidate.checked_status(status, closing) {
                self.evidence_fail(&mut r, EvidenceCallback::Status, check, Some(status), EvidenceError::None);
            },
        }
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
        let status = match result {
            Ok(status) => status,
            Err(error) => {
                self.evidence_fail(&mut r, EvidenceCallback::ObserveStart, EvidenceCheck::Bridge, None, EvidenceError::classify(error)); return;
            },
        };
        let accepted = (|| {
            use EvidenceCheck as C;
            evidence_require(self.case == Case::Positive, C::Case)?;
            evidence_require(r.candidate.observe_pending, C::ObservePending)?;
            evidence_require(!r.candidate.observe_returned, C::ObserveReturned)?;
            evidence_require(r.candidate.observe_requests == 1, C::ObserveRequests)?;
            evidence_require(status.phase == evidence::Phase::Observing, C::Phase)?;
            evidence_require(status.result.is_none(), C::Result)?;
            evidence_require(status.problem.is_none(), C::Problem)?;
            let selected = r.candidate.selected.as_ref().ok_or(C::SelectionWitness)?;
            evidence_require(status.selection.as_ref() == Some(&selected.selection), C::Selection)?;
            let op = status.operation.as_ref().ok_or(C::Operation)?;
            evidence_require(op.operation_id == "5", C::Operation)?;
            evidence_require(op.kind == evidence::OperationKind::Observe, C::OperationKind)?;
            evidence_require(op.selection_id.as_deref() == Some(selected.selection.selection_id.as_str()), C::OperationSelection)
        })();
        if let Err(check) = accepted {
            self.evidence_fail(&mut r, EvidenceCallback::ObserveStart, check, Some(status), EvidenceError::None); return;
        }
        r.candidate.observe_pending = false; r.candidate.observe_returned = true;
        if let Err(check) = r.candidate.checked_status(status, false) {
            self.evidence_fail(&mut r, EvidenceCallback::ObserveStart, check, Some(status), EvidenceError::None);
        }
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
        if matches!(self.case, Case::WorkflowApply | Case::MetadataSave | Case::VersionSave) {
            let Some(mut r) = self.record_at(Boundary::Result) else { return; };
            if status.schema_version != 1 || !edit::token(&status.window_generation)
                || r.generation.as_ref().is_some_and(|generation| generation != &status.window_generation)
                || status.active.is_some() || status.last_terminal.is_some() { self.fail(); return; }
            if r.generation.is_none() { r.generation = Some(status.window_generation.clone()); }
            if r.native_revision.is_some_and(|revision| status.status_revision < revision)
                || r.workflow.native_revision.is_some_and(|revision| status.status_revision < revision)
                || r.metadata.native_revision.is_some_and(|revision| status.status_revision < revision)
                || r.version.native_revision.is_some_and(|revision| status.status_revision < revision) { return; }
            match (status.capability.available, status.capability.reason) {
                (true, edit::EditAvailability::Available) => r.capability = true,
                (false, edit::EditAvailability::OtherEditActive) if r.workflow.open_pending
                    || r.workflow.sessions.last().is_some_and(|s| s.finality.is_none()) || r.metadata.open_pending.is_some()
                    || r.metadata.sessions.last().is_some_and(|s| s.finality.is_none()) || r.version.open_pending.is_some()
                    || r.version.sessions.last().is_some_and(|s| s.finality.is_none()) => {},
                (false, edit::EditAvailability::Shutdown) if r.close_prevented => {},
                (false, edit::EditAvailability::RuntimeUnqualified) if !r.capability => {},
                _ => { self.fail(); return; },
            }
            r.native_revision = Some(status.status_revision); return;
        }
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


    fn version_save_observe_request(&self, body: &Value) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        let v = &r.version; let index = usize::from(v.observe_requests);
        if self.case != Case::VersionSave || index >= 3 || v.observe_pending || v.observations.len() != index
            || !matches!(r.step,Step::VersionSave(VersionStep::Readback(i) | VersionStep::ReadReadback(i)) if usize::from(i) == index)
            || v.sessions.len() != index + 1 || !v.sessions.get(index).is_some_and(|s|s.saved_visible && s.open_returned
                && s.apply_returned && s.finality.is_some() && s.source_final.is_some())
            || !keys(body,&["projectId"]) || !r.project.as_ref().is_some_and(|p|body["projectId"].as_str() == Some(p.id.as_str())) { self.fail(); return; }
        r.version.observe_pending = true; r.version.observe_requests += 1;
    }
    fn version_save_observed(&self, result: &Result<crate::release_version_protocol::Observation,BridgeError>) {
        let Some(mut r) = self.record_at(Boundary::Result) else { return; }; let index = r.version.observations.len();
        let sample = result.as_ref().ok().and_then(|result| {
            let values = version_values(index)?;
            VersionSample::read_values(result,&values.name,if index == 0 { 7 } else { 8 },version_digest(index)?)
        });
        if self.case != Case::VersionSave || index >= 3 || !r.version.observe_pending || sample.is_none()
            || usize::from(r.version.observe_requests) != index + 1
            || !matches!(r.step,Step::VersionSave(VersionStep::Readback(i) | VersionStep::ReadReadback(i)) if usize::from(i) == index) { self.fail(); return; }
        let Some(sample) = sample else { self.fail(); return; };
        let Some(prepared) = r.version.sessions.get(index).and_then(|s|s.projection.prepared.as_ref()) else { self.fail(); return; };
        if prepared.view.values.name != sample.name || prepared.view.values.build != sample.build.to_string()
            || prepared.view.file.after.bytes != VERSION_BYTES || Some(prepared.view.file.after.sha256.as_str()) != version_digest(index) { self.fail(); return; }
        r.version.observations.push(sample); r.version.observe_pending = false;
    }
    pub(super) fn version_open_request(&self, args: &crate::release_version_edit_commands::Open) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; }; let v = &r.version; let index = v.sessions.len();
        if self.case != Case::VersionSave || index >= 3 || !r.snapshot_visible || v.saved_config.is_none()
            || !matches!(r.step,Step::VersionSave(VersionStep::Open(i) | VersionStep::ReadOpen(i)) if usize::from(i) == index)
            || !v.ready || !v.capability || !r.capability || v.open_pending.is_some() || v.prepare_pending.is_some()
            || v.requests != [index as u8,index as u8,index as u8,0] || v.observe_requests != index as u8 || v.observe_pending
            || v.sessions.iter().enumerate().any(|(i,s)|!s.complete(i))
            || r.requests != [0;4] || r.workflow.requests != [0;4] || r.metadata.requests != [0;4]
            || !r.project.as_ref().is_some_and(|p|p.id == args.project_id) { self.fail(); return; }
        let (Some(version_revision),Some(config_revision),Some(project),Some(generation)) =
            (v.native_revision,r.native_revision,r.project.as_ref(),r.generation.as_ref()) else { self.fail(); return; };
        let pending = VersionOpen { index, after_revision:version_revision.max(config_revision),project_id:project.id.clone(),generation:generation.clone() };
        if index == 0 {
            let Some(fixture) = self.project_path().and_then(VersionFixture::begin) else { self.fail(); return; };
            if r.version.fixture.is_some() { self.fail(); return; } r.version.fixture = Some(fixture);
        }
        r.version.open_pending = Some(pending); r.version.requests[0] += 1;
    }
    pub(super) fn version_open_result(&self, result: &Result<version::ReleaseVersionEditStatus,BridgeError>, edits: &EditOwner) {
        let Ok(status) = result else { self.fail(); return; };
        if self.case != Case::VersionSave { self.fail(); return; } self.version_status(status,edits,true);
    }
    pub(super) fn version_prepare_request(&self, args: &version::PrepareReleaseVersionEdit) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; }; let index = usize::from(r.version.requests[1]);
        if self.case != Case::VersionSave
            || !matches!(r.step,Step::VersionSave(VersionStep::Review(i) | VersionStep::ReadReview(i)) if usize::from(i) == index)
            || !r.version.record_prepare(args) { self.fail(); }
    }
    pub(super) fn version_prepare_result(&self, result: &Result<version::ReleaseVersionEditStatus,BridgeError>, edits: &EditOwner) {
        {
            let Some(mut r) = self.record_at(Boundary::Result) else { return; };
            let Some(index) = r.version.prepare_pending.take() else { self.fail(); return; };
            let Some(owner) = result.as_ref().ok().and_then(|s|s.active.as_ref()) else { self.fail(); return; };
            let Some(session) = r.version.sessions.get_mut(index) else { self.fail(); return; };
            if session.prepare_returned || owner.session_id != session.projection.session_id || owner.phase != edit::Phase::Preparing
                || owner.prepared.is_some() || owner.apply_submitted
                || owner.checkout.as_ref().map(|c|&c.revision) != session.projection.checkout.as_ref().map(|c|&c.revision) { self.fail(); return; }
            session.prepare_returned = true;
        }
        if let Ok(status) = result { self.version_edit_status(status,edits); }
    }
    pub(super) fn version_apply_request(&self, session_id: &str, plan_token: &str) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; }; let v = &r.version; let index = usize::from(v.requests[2]);
        if self.case != Case::VersionSave || index >= 3
            || !matches!(r.step,Step::VersionSave(VersionStep::Apply(i) | VersionStep::ReadSaved(i)) if usize::from(i) == index)
            || v.requests != [index as u8+1,index as u8+1,index as u8,0]
            || !v.sessions.get(index).is_some_and(|s|s.live_review() && s.prepare_returned && s.review_visible
                && s.confirmation_opened && s.initially_disabled && s.checkbox_only_disabled && s.typed_save && s.acknowledged
                && !s.apply_requested && s.projection.session_id == session_id
                && s.projection.prepared.as_ref().is_some_and(|p|p.plan_token == plan_token)) { self.fail(); return; }
        r.version.sessions[index].apply_requested = true; r.version.requests[2] += 1;
    }
    pub(super) fn version_apply_result(&self, result: &Result<version::ReleaseVersionEditStatus,BridgeError>, edits: &EditOwner) {
        {
            let Some(mut r) = self.record_at(Boundary::Result) else { return; };
            let Some(index) = usize::from(r.version.requests[2]).checked_sub(1) else { self.fail(); return; };
            let Some(owner) = result.as_ref().ok().and_then(|s|s.active.as_ref()) else { self.fail(); return; };
            let Some(session) = r.version.sessions.get_mut(index) else { self.fail(); return; };
            if !session.apply_requested || session.apply_returned || owner.session_id != session.projection.session_id
                || owner.phase != edit::Phase::Applying || !owner.apply_submitted
                || owner.prepared.as_ref().map(|p|&p.plan_token) != session.projection.prepared.as_ref().map(|p|&p.plan_token) { self.fail(); return; }
            session.apply_returned = true;
        }
        if let Ok(status) = result { self.version_edit_status(status,edits); }
    }
    pub(super) fn version_close_request(&self, _session_id: &str) {
        if let Some(mut r) = self.record_at(Boundary::Request) { r.version.requests[3] = r.version.requests[3].saturating_add(1); }
        self.fail(); // No Close is claimed by this three-Apply recipe; unexpected requests must refuse the receipt.
    }
    pub(super) fn version_close_result(&self, _result: &Result<version::ReleaseVersionEditStatus,BridgeError>, _edits: &EditOwner) {
        self.fail(); // Instrument the actual handler without manufacturing unused Close coverage.
    }
    pub(super) fn version_edit_status(&self, status: &version::ReleaseVersionEditStatus, edits: &EditOwner) {
        self.version_status(status,edits,false);
    }
    fn version_status(&self, status: &version::ReleaseVersionEditStatus, edits: &EditOwner, open_returned: bool) {
        if self.case != Case::VersionSave { return; }
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        if self.failed.load(Ordering::SeqCst) { return; }
        if status.schema_version != 1 || status.domain != version::DOMAIN || !edit::token(&status.window_generation)
            || r.generation.as_ref().is_some_and(|g|g != &status.window_generation) { self.fail(); return; }
        if r.generation.is_none() { r.generation = Some(status.window_generation.clone()); }
        if !open_returned && (r.version.native_revision.is_some_and(|revision|status.status_revision < revision)
            || r.native_revision.is_some_and(|revision|status.status_revision < revision)) { return; }
        let first_active = status.active.as_ref().is_some_and(|active|!r.version.sessions.iter().any(|s|s.projection.session_id == active.session_id));
        let config = if open_returned || first_active {
            let Some(matched) = r.version.open_match(status,open_returned) else { self.fail(); return; };
            let config = if matched == VersionOpenMatch::First {
                let Ok(config) = edits.status() else { self.fail(); return; }; Some(config)
            } else { None };
            if !r.version.observe_open(status,open_returned,config.as_ref()) { self.fail(); return; }
            if matched == VersionOpenMatch::Reply { return; }
            config
        } else { None };
        match (status.capability.available,status.capability.reason) {
            (true,edit::EditAvailability::Available) => r.version.capability = true,
            (false,edit::EditAvailability::RuntimeUnqualified) if !r.version.capability => {},
            (false,edit::EditAvailability::Shutdown) if r.close_prevented => {},
            _ => { self.fail(); return; },
        }
        r.version.ready = status.capability.available && status.capability.reason == edit::EditAvailability::Available && status.active.is_none();
        for projection in status.last_terminal.iter().chain(status.active.iter()) {
            let Some(index) = r.version.sessions.iter().position(|s|s.projection.session_id == projection.session_id) else { self.fail(); return; };
            let old = r.version.sessions[index].projection.clone(); let session = &r.version.sessions[index];
            if projection.domain != version::DOMAIN || projection.project_id != old.project_id
                || projection.owner_generation != status.window_generation || !edit::token(&projection.session_id)
                || projection.late_settled || projection.phase == edit::Phase::Unknown || phase_order(projection.phase) < phase_order(old.phase)
                || projection.native_finality == edit::NativeFinality::Unknown || projection.native_reason != edit::NativeEditReason::None
                || projection.apply_submitted != (session.apply_requested && phase_order(projection.phase) >= phase_order(edit::Phase::Applying)) { self.fail(); return; }
            if let Some(checkout) = &projection.checkout {
                if !version_checkout_matches(index,checkout)
                    || old.checkout.as_ref().is_some_and(|c|serde_json::to_value(c).ok() != serde_json::to_value(checkout).ok())
                    || r.version.sessions.iter().enumerate().any(|(i,s)|i != index
                        && s.projection.checkout.as_ref().is_some_and(|c|c.revision == checkout.revision)) { self.fail(); return; }
            } else if old.checkout.is_some() { self.fail(); return; }
            let review = if let Some(prepared) = &projection.prepared {
                let Some(review) = version_review_sample(index,&prepared.view) else { self.fail(); return; };
                let Ok(value) = serde_json::to_value(prepared) else { self.fail(); return; };
                if !session.prepare_requested || !edit::token(&prepared.plan_token)
                    || !projection.checkout.as_ref().is_some_and(|c|c.revision == prepared.revision)
                    || session.binding != Some((prepared.draft_revision,prepared.baseline_generation))
                    || session.prepared.as_ref().is_some_and(|before|before != &value)
                    || r.version.sessions.iter().enumerate().any(|(i,s)|i != index
                        && s.projection.prepared.as_ref().is_some_and(|p|p.plan_token == prepared.plan_token)) { self.fail(); return; }
                Some((value,review))
            } else { if session.prepared.is_some() { self.fail(); return; } None };
            if let Some(core) = &projection.core_outcome {
                if core.effect != (if index == 2 { edit::Effect::Unchanged } else { edit::Effect::Committed })
                    || core.journal != (if index == 2 { edit::Journal::NotCreated } else { edit::Journal::Clean })
                    || core.resources != edit::ResourceState::Settled || core.reason != edit::CoreReason::None
                    || phase_order(projection.phase) < phase_order(edit::Phase::Finalizing) { self.fail(); return; }
            }
            if projection.phase == edit::Phase::Final {
                if projection.native_finality != edit::NativeFinality::Settled || projection.core_outcome.is_none()
                    || projection.prepared.is_none() || !session.apply_requested { self.fail(); return; }
                if session.finality.is_none() {
                    // Capture before the next Open can replace last_terminal.
                    // A fast actual Final may precede its synchronous Apply reply;
                    // the recipe still waits for that separate original reply.
                    let Some(facts) = edits.installed_version_observation_final(&projection.session_id) else { self.fail(); return; };
                    if !version_original_final(&facts,projection) { self.fail(); return; }
                    let Some(source) = r.version.fixture.as_ref().and_then(|fixture|
                        self.project_path().and_then(|root|fixture.after_original_final(root))) else { self.fail(); return; };
                    if index == 1 && !r.version.sessions[0].source_final.is_some_and(|old|old[..2] != source[..2])
                        || index == 2 && r.version.sessions[1].source_final != Some(source) { self.fail(); return; }
                    r.version.sessions[index].finality = Some(facts); r.version.sessions[index].source_final = Some(source);
                }
            } else if projection.native_finality != edit::NativeFinality::Pending { self.fail(); return; }
            let session = &mut r.version.sessions[index];
            if let Some((prepared,review)) = review { session.prepared = Some(prepared); session.review = Some(review); }
            session.projection = projection.clone();
        }
        r.version.native_revision = Some(status.status_revision);
        drop(r);
        // Reconcile the genuine version projection before advancing the shared
        // revision using the one opposite-domain snapshot for this original.
        if let Some(config) = config { self.edit_status(&config,edits); }
    }

    fn metadata_save_observe_request(&self, body: &Value) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        let m = &r.metadata; let index = usize::from(m.observe_requests);
        let allowed = match index {
            0 => matches!(r.step,Step::MetadataSave(MetadataStep::Load | MetadataStep::ReadLoaded)) && m.sessions.is_empty(),
            1 => matches!(r.step,Step::MetadataSave(MetadataStep::Refresh | MetadataStep::ReadReadback)) && m.saved_visible
                && m.requests == [2,2,1,1] && m.sessions.len() == 2 && m.sessions.iter().all(|s|s.open_returned && s.finality.is_some()),
            _ => false,
        };
        if self.case != Case::MetadataSave || !allowed || m.observe_pending || m.observations.len() != index
            || !r.snapshot_visible || m.saved_config.is_none() || !keys(body,&["projectId","platform","locale"])
            || body["platform"] != "android" || body["locale"] != "en-US"
            || !r.project.as_ref().is_some_and(|p| body["projectId"].as_str() == Some(p.id.as_str())) { self.fail(); return; }
        r.metadata.observe_pending = true; r.metadata.observe_requests += 1;
    }
    fn metadata_save_observed(&self, result: &Result<metadata::Observation,BridgeError>) {
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        let index = r.metadata.observations.len();
        let sample = result.as_ref().ok().and_then(|value| metadata_saved_observation(value,index == 1));
        if self.case != Case::MetadataSave || index >= 2 || !r.metadata.observe_pending || sample.is_none()
            || usize::from(r.metadata.observe_requests) != index + 1
            || !(index == 0 && matches!(r.step,Step::MetadataSave(MetadataStep::Load | MetadataStep::ReadLoaded))
                || index == 1 && matches!(r.step,Step::MetadataSave(MetadataStep::Refresh | MetadataStep::ReadReadback))) { self.fail(); return; }
        let Some(sample) = sample else { self.fail(); return; };
        if index == 1 {
            let Some(view) = r.metadata.sessions.get(1).and_then(|s|s.projection.prepared.as_ref()).map(|p|&p.view) else { self.fail(); return; };
            if view.files.iter().zip(sample["fields"].as_array().into_iter().flatten()).any(|(file,row)|
                row["text"].as_str() != Some(file.after.text.as_str()) || row["sha256"].as_str() != Some(file.after.sha256.as_str())
                    || row["byteLength"].as_u64() != Some(u64::from(file.after.byte_length))) { self.fail(); return; }
        }
        r.metadata.observations.push(sample); r.metadata.observe_pending = false;
    }
    fn metadata_save_validate_request(&self, body: &Value) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        if self.case != Case::MetadataSave || !matches!(r.step,Step::MetadataSave(MetadataStep::Validate | MetadataStep::ReadValidation))
            || !r.metadata.loaded_visible || r.metadata.entered != [true;2] || r.metadata.validation_requested
            || !keys(body,&["platform","fields"]) || body["platform"] != "android"
            || r.metadata.inputs.as_ref() != body.get("fields") || !r.metadata.sessions.is_empty() { self.fail(); return; }
        r.metadata.validation_requested = true;
    }
    fn metadata_save_validated(&self, result: &Result<metadata::ValidationResult,BridgeError>) {
        let sample = result.as_ref().ok().and_then(metadata_validation_sample);
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        if self.case != Case::MetadataSave || !matches!(r.step,Step::MetadataSave(MetadataStep::Validate | MetadataStep::ReadValidation))
            || !r.metadata.validation_requested || r.metadata.validation.is_some() || sample.is_none() { self.fail(); return; }
        r.metadata.validation = sample;
    }
    pub(super) fn metadata_open_request(&self, args: &crate::metadata_text_commands::Open) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        let m = &r.metadata; let index = m.sessions.len();
        if self.case != Case::MetadataSave || index >= 2 || !metadata_start_step(r.step,index)
            || !m.validation_visible || !m.ready || !m.capability || !r.capability || m.open_pending.is_some()
            || usize::from(m.requests[0]) != index || m.requests[2] != 0 || r.requests != [0;4] || r.workflow.requests != [0;4]
            || m.sessions.iter().any(|s|!s.open_returned || !s.close_returned || s.finality.is_none()) || index == 1 && !m.retained_after_close
            || !r.project.as_ref().is_some_and(|p|p.id == args.project_id)
            || args.platform != metadata::Platform::Android || args.locale != "en-US" { self.fail(); return; }
        let (Some(metadata_revision),Some(config_revision),Some(project),Some(generation)) =
            (m.native_revision,r.native_revision,r.project.as_ref(),r.generation.as_ref()) else { self.fail(); return; };
        let pending = MetadataOpen { index, after_revision:metadata_revision.max(config_revision),
            project_id:project.id.clone(), generation:generation.clone() };
        r.metadata.open_pending = Some(pending); r.metadata.requests[0] += 1;
    }
    pub(super) fn metadata_open_result(&self, result: &Result<metadata::MetadataTextEditStatus,BridgeError>, edits: &EditOwner) {
        let Ok(status) = result else { self.fail(); return; };
        if self.case != Case::MetadataSave { self.fail(); return; }
        self.metadata_status(status,edits,true);
    }
    pub(super) fn metadata_prepare_request(&self, args: &metadata::PrepareMetadataTextEdit) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        let index = usize::from(r.metadata.requests[1]);
        if self.case != Case::MetadataSave || !metadata_start_step(r.step,index)
            || !r.metadata.record_prepare(args) { self.fail(); }
    }
    pub(super) fn metadata_prepare_result(&self, result: &Result<metadata::MetadataTextEditStatus,BridgeError>, edits: &EditOwner) {
        {
            let Some(mut r) = self.record_at(Boundary::Result) else { return; };
            let Some(index) = r.metadata.prepare_pending.take() else { self.fail(); return; };
            let Some(owner) = result.as_ref().ok().and_then(|status|status.active.as_ref()) else { self.fail(); return; };
            let session = &mut r.metadata.sessions[index];
            if session.prepare_returned || owner.session_id != session.projection.session_id || owner.phase != edit::Phase::Preparing
                || owner.prepared.is_some() || owner.apply_submitted
                || owner.checkout.as_ref().map(|c|&c.revision) != session.projection.checkout.as_ref().map(|c|&c.revision) { self.fail(); return; }
            session.prepare_returned = true;
        }
        if let Ok(status) = result { self.metadata_edit_status(status,edits); }
    }
    pub(super) fn metadata_close_request(&self, session_id: &str) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        if self.case != Case::MetadataSave || !matches!(r.step,Step::MetadataSave(MetadataStep::CloseReview | MetadataStep::ReadClosed))
            || r.metadata.requests != [1,1,0,0] || !r.metadata.sessions.first().is_some_and(|s|
                s.live_review() && s.review_visible && s.prepare_returned && !s.close_requested && s.projection.session_id == session_id)
            || r.metadata.confirmation_opened != 0 { self.fail(); return; }
        r.metadata.sessions[0].close_requested = true; r.metadata.requests[3] += 1;
    }
    pub(super) fn metadata_close_result(&self, result: &Result<metadata::MetadataTextEditStatus,BridgeError>, edits: &EditOwner) {
        {
            let Some(mut r) = self.record_at(Boundary::Result) else { return; };
            let Some(owner) = result.as_ref().ok().and_then(|status|status.active.as_ref()) else { self.fail(); return; };
            let Some(session) = r.metadata.sessions.first_mut() else { self.fail(); return; };
            if !session.close_requested || session.close_returned || owner.session_id != session.projection.session_id
                || owner.phase != edit::Phase::Finalizing || owner.apply_submitted || owner.native_reason != edit::NativeEditReason::Discarded
                || owner.prepared.as_ref().map(|p|&p.plan_token) != session.projection.prepared.as_ref().map(|p|&p.plan_token) { self.fail(); return; }
            session.close_returned = true;
        }
        if let Ok(status) = result { self.metadata_edit_status(status,edits); }
    }
    pub(super) fn metadata_apply_request(&self, session_id: &str, plan_token: &str) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        let m = &r.metadata;
        if self.case != Case::MetadataSave || !matches!(r.step,Step::MetadataSave(MetadataStep::Apply | MetadataStep::ReadSaved))
            || m.requests != [2,2,0,1] || !m.retained_after_close || m.confirmation_opened != 1
            || !m.initially_disabled || !m.checkbox_only_disabled || !m.typed_save || !m.acknowledged
            || !m.sessions.get(1).is_some_and(|s|s.live_review() && s.review_visible && s.prepare_returned && !s.apply_requested
                && s.projection.session_id == session_id && s.projection.prepared.as_ref().is_some_and(|p|p.plan_token == plan_token)) { self.fail(); return; }
        r.metadata.sessions[1].apply_requested = true; r.metadata.requests[2] += 1;
    }
    pub(super) fn metadata_apply_result(&self, result: &Result<metadata::MetadataTextEditStatus,BridgeError>, edits: &EditOwner) {
        {
            let Some(mut r) = self.record_at(Boundary::Result) else { return; };
            let Some(owner) = result.as_ref().ok().and_then(|status|status.active.as_ref()) else { self.fail(); return; };
            let Some(session) = r.metadata.sessions.get_mut(1) else { self.fail(); return; };
            if !session.apply_requested || session.apply_returned || owner.session_id != session.projection.session_id
                || owner.phase != edit::Phase::Applying || !owner.apply_submitted
                || owner.prepared.as_ref().map(|p|&p.plan_token) != session.projection.prepared.as_ref().map(|p|&p.plan_token) { self.fail(); return; }
            session.apply_returned = true;
        }
        if let Ok(status) = result { self.metadata_edit_status(status,edits); }
    }
    pub(super) fn metadata_edit_status(&self, status: &metadata::MetadataTextEditStatus, edits: &EditOwner) {
        self.metadata_status(status,edits,false);
    }
    fn metadata_status(&self, status: &metadata::MetadataTextEditStatus, edits: &EditOwner, open_returned: bool) {
        if !matches!(self.case,Case::Positive | Case::MetadataSave) { return; }
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        if self.failed.load(Ordering::SeqCst) { return; }
        if status.schema_version != 1 || status.domain != metadata::DOMAIN || !edit::token(&status.window_generation)
            || r.generation.as_ref().is_some_and(|generation|generation != &status.window_generation) { self.fail(); return; }
        if r.generation.is_none() { r.generation = Some(status.window_generation.clone()); }
        // An Open reply is captured before the worker starts. Match it against
        // that request/first native observation even when later events won.
        if !open_returned && (r.metadata.native_revision.is_some_and(|revision|status.status_revision < revision)
            || r.native_revision.is_some_and(|revision|status.status_revision < revision)) { return; }
        if self.case == Case::Positive {
            if status.active.is_some() || status.last_terminal.is_some()
                || status.capability.available != (status.capability.reason == edit::EditAvailability::Available) { self.fail(); return; }
            r.metadata.ready = status.capability.available;
            r.metadata.native_revision = Some(status.status_revision); return;
        }
        let first_active = status.active.as_ref().is_some_and(|active|
            !r.metadata.sessions.iter().any(|s|s.projection.session_id == active.session_id));
        let config = if open_returned || first_active {
            let Some(matched) = r.metadata.open_match(status,open_returned) else { self.fail(); return; };
            let config = if matched == MetadataOpenMatch::First {
                // Relocate the single opposite-domain snapshot per Open, do
                // not add a query or drop an event. Shell native locks have
                // already been released; status() is a callback-free registry
                // snapshot, using the existing record -> registry lock order.
                let Ok(config) = edits.status() else { self.fail(); return; }; Some(config)
            } else { None };
            if !r.metadata.observe_open(status,open_returned,config.as_ref()) { self.fail(); return; }
            if matched == MetadataOpenMatch::Reply { return; } // Never regress the actual later projection/revision.
            config
        } else { None };
        if status.capability.available && status.capability.reason == edit::EditAvailability::Available { r.metadata.capability = true; }
        else if r.metadata.capability && !(r.close_prevented && !status.capability.available
            && status.capability.reason == edit::EditAvailability::Shutdown) { self.fail(); return; }
        r.metadata.ready = status.capability.available && status.capability.reason == edit::EditAvailability::Available && status.active.is_none();
        for projection in status.last_terminal.iter().chain(status.active.iter()) {
            let Some(index) = r.metadata.sessions.iter().position(|s|s.projection.session_id == projection.session_id) else { self.fail(); return; };
            let old = r.metadata.sessions[index].projection.clone();
            let session = &r.metadata.sessions[index];
            if projection.domain != metadata::DOMAIN || projection.platform != metadata::Platform::Android || projection.locale != "en-US"
                || projection.project_id != old.project_id || projection.owner_generation != status.window_generation
                || !edit::token(&projection.session_id) || projection.late_settled || projection.phase == edit::Phase::Unknown
                || phase_order(projection.phase) < phase_order(old.phase) || projection.native_finality == edit::NativeFinality::Unknown
                || projection.apply_submitted != (session.apply_requested && phase_order(projection.phase) >= phase_order(edit::Phase::Applying))
                || projection.native_reason != (if index == 0 && session.close_requested
                    && phase_order(projection.phase) >= phase_order(edit::Phase::Finalizing) { edit::NativeEditReason::Discarded }
                    else { edit::NativeEditReason::None }) { self.fail(); return; }
            if let Some(checkout) = &projection.checkout {
                if !edit::token(&checkout.revision) || checkout.metadata_root != "release/store"
                    || serde_json::to_value(&checkout.baseline).ok() != r.metadata.observations.first().map(|o|o["baseline"].clone())
                    || old.checkout.as_ref().is_some_and(|c|serde_json::to_value(c).ok() != serde_json::to_value(checkout).ok())
                    || r.metadata.sessions.iter().enumerate().any(|(i,s)|i != index && s.projection.checkout.as_ref().is_some_and(|c|c.revision == checkout.revision)) { self.fail(); return; }
            } else if old.checkout.is_some() { self.fail(); return; }
            let review = if let Some(prepared) = &projection.prepared {
                let Some(review) = metadata_review_sample(&prepared.view) else { self.fail(); return; };
                let Ok(value) = serde_json::to_value(prepared) else { self.fail(); return; };
                if !session.prepare_requested || !edit::token(&prepared.plan_token)
                    || !projection.checkout.as_ref().is_some_and(|c|c.revision == prepared.revision)
                    || session.binding != Some((prepared.draft_revision,prepared.baseline_generation))
                    || session.prepared.as_ref().is_some_and(|before|before != &value)
                    || r.metadata.sessions.iter().enumerate().any(|(i,s)|i != index
                        && s.projection.prepared.as_ref().is_some_and(|p|p.plan_token == prepared.plan_token)) { self.fail(); return; }
                Some((value,review))
            } else { if session.prepared.is_some() { self.fail(); return; } None };
            if let Some(core) = &projection.core_outcome {
                if core.effect != (if index == 0 { edit::Effect::NotStarted } else { edit::Effect::Committed })
                    || core.journal != (if index == 0 { edit::Journal::NotCreated } else { edit::Journal::Clean })
                    || core.resources != edit::ResourceState::Settled
                    || core.reason != (if index == 0 { edit::CoreReason::Cancelled } else { edit::CoreReason::None })
                    || phase_order(projection.phase) < phase_order(edit::Phase::Finalizing) { self.fail(); return; }
            }
            if projection.phase == edit::Phase::Final {
                if projection.native_finality != edit::NativeFinality::Settled || projection.core_outcome.is_none() || projection.prepared.is_none()
                    || index == 0 && !session.close_requested || index == 1 && !session.apply_requested { self.fail(); return; }
                // A real relay final can race ahead of the synchronous command
                // reply hook. Freeze the original now; native_pending still
                // requires that distinct reply before any result DOM/next Open.
                if session.finality.is_none() {
                    let Some(facts) = edits.installed_metadata_observation_final(&projection.session_id) else { self.fail(); return; };
                    if !metadata_original_final(&facts,projection) { self.fail(); return; }
                    r.metadata.sessions[index].finality = Some(facts);
                }
            } else if projection.native_finality != edit::NativeFinality::Pending { self.fail(); return; }
            let session = &mut r.metadata.sessions[index];
            if let Some((prepared,review)) = review { session.prepared = Some(prepared); session.review = Some(review); }
            session.projection = projection.clone();
        }
        r.metadata.native_revision = Some(status.status_revision);
        // Fully reconcile/store the first metadata projection before a newer
        // Configuration snapshot can advance the shared revision. In
        // particular, real Editing and config_blocked are ready before the
        // original relay emits and the controller can immediately Prepare.
        drop(r);
        if let Some(config) = config { self.edit_status(&config,edits); }
    }

    pub(super) fn workflow_open_request(&self, project_id: &str) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        let w = &r.workflow; let index = w.sessions.len();
        if self.case != Case::WorkflowApply || index >= 4 || !workflow_start_step(r.step, index)
            || !r.guidance.complete() || !r.capability || !w.capability || w.open_pending
            || usize::from(w.requests[0]) != index || r.requests != [0; 4] || !r.sessions.is_empty()
            || w.sessions.iter().any(|s| s.finality.is_none() || !s.result_visible)
            || index > 0 && usize::from(w.draft_reads) != index
            || index == 1 && !w.pin_changed || index >= 2 && !w.pin_restored
            || !r.project.as_ref().is_some_and(|project| project.id == project_id) { self.fail(); return; }
        r.workflow.open_pending = true; r.workflow.requests[0] += 1;
    }
    pub(super) fn workflow_open_result(&self, result: &Result<workflow::WorkflowEditStatus, BridgeError>, edits: &EditOwner) {
        // This is an actual opposite-domain capability snapshot of the SAME
        // admitted owner, before returning Open to its controller.
        let Ok(config) = edits.status() else { self.fail(); return; };
        {
            let Some(mut r) = self.record_at(Boundary::Result) else { return; };
            let Some(status) = result.as_ref().ok() else { self.fail(); return; };
            let Some(owner) = status.active.as_ref() else { self.fail(); return; };
            let w = &r.workflow;
            if self.case != Case::WorkflowApply || !w.open_pending || w.sessions.len() >= 4
                || usize::from(w.requests[0]) != w.sessions.len() + 1 || owner.domain != workflow::DOMAIN
                || owner.phase != edit::Phase::Opening || owner.checkout.is_some() || owner.prepared.is_some()
                || owner.conflict.is_some() || owner.core_outcome.is_some() || owner.apply_submitted
                || w.sessions.iter().any(|s| s.projection.session_id == owner.session_id)
                || !r.project.as_ref().is_some_and(|project| project.id == owner.project_id)
                || config.window_generation != status.window_generation || config.status_revision < status.status_revision
                || config.capability.available || config.capability.reason != edit::EditAvailability::OtherEditActive
                || config.active.is_some() || config.last_terminal.is_some() { self.fail(); return; }
            r.workflow.open_pending = false;
            r.workflow.sessions.push(WorkflowSession { projection: owner.clone(), prepared: None, review: None, conflict: None,
                prepare_requested: false, prepare_returned: false, binding: None, review_visible: false, result_visible: false,
                config_blocked: true, confirmation_opened: 0, kept_reviewing: false, acknowledged: false,
                apply_requested: false, apply_returned: false, finality: None });
        }
        self.edit_status(&config, edits);
        if let Ok(status) = result { self.workflow_status(status, edits); }
    }
    pub(super) fn workflow_prepare_request(&self, args: &workflow::PrepareWorkflowEdit) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        let index = usize::from(r.workflow.requests[1]);
        let Some(session) = r.workflow.sessions.get(index) else { self.fail(); return; };
        if self.case != Case::WorkflowApply || !workflow_start_step(r.step, index)
            || r.workflow.prepare_pending.is_some() || session.prepare_requested || session.binding.is_some()
            || session.projection.phase != edit::Phase::Editing || session.projection.session_id != args.session_id
            || !session.projection.checkout.as_ref().is_some_and(|checkout| checkout.revision == args.revision)
            || r.suggested.as_ref() != Some(&args.draft) || args.draft_revision != 1 || args.baseline_generation != 1
            || args.tooling_repository != TOOLKIT_REPOSITORY || args.tooling_sha != (if index == 1 { CONFLICT_SHA } else { TOOLKIT_SHA })
            || !session.config_blocked { self.fail(); return; }
        let session = &mut r.workflow.sessions[index];
        session.prepare_requested = true; session.binding = Some((args.draft_revision, args.baseline_generation));
        r.workflow.prepare_pending = Some(index); r.workflow.requests[1] += 1;
    }
    pub(super) fn workflow_prepare_result(&self, result: &Result<workflow::WorkflowEditStatus, BridgeError>, edits: &EditOwner) {
        {
            let Some(mut r) = self.record_at(Boundary::Result) else { return; };
            let Some(index) = r.workflow.prepare_pending.take() else { self.fail(); return; };
            let Some(owner) = result.as_ref().ok().and_then(|status| status.active.as_ref()) else { self.fail(); return; };
            let session = &mut r.workflow.sessions[index];
            if session.prepare_returned || owner.session_id != session.projection.session_id || owner.phase != edit::Phase::Preparing
                || owner.prepared.is_some() || owner.conflict.is_some() || owner.apply_submitted
                || owner.checkout.as_ref().map(|c| &c.revision) != session.projection.checkout.as_ref().map(|c| &c.revision) { self.fail(); return; }
            session.prepare_returned = true;
        }
        if let Ok(status) = result { self.workflow_status(status, edits); }
    }
    pub(super) fn workflow_apply_request(&self, session_id: &str, plan_token: &str) {
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        let index = match r.step {
            Step::Workflow(WorkflowStep::Apply(i) | WorkflowStep::ReadResult(i)) if matches!(i, 0 | 2) => usize::from(i),
            _ => { self.fail(); return; },
        };
        let expected = if index == 0 { [1, 1, 0, 0] } else { [3, 3, 1, 0] };
        if self.case != Case::WorkflowApply || r.workflow.requests != expected
            || !r.workflow.sessions.get(index).is_some_and(|s| s.prepare_returned && s.review_visible && s.live_review()
                && s.confirmation_opened == (if index == 0 { 2 } else { 1 }) && s.kept_reviewing == (index == 0)
                && s.acknowledged && !s.apply_requested && s.projection.session_id == session_id
                && s.projection.prepared.as_ref().is_some_and(|p| p.plan_token == plan_token)) { self.fail(); return; }
        r.workflow.sessions[index].apply_requested = true; r.workflow.requests[2] += 1;
    }
    pub(super) fn workflow_apply_result(&self, result: &Result<workflow::WorkflowEditStatus, BridgeError>, edits: &EditOwner) {
        {
            let Some(mut r) = self.record_at(Boundary::Result) else { return; };
            let Some(owner) = result.as_ref().ok().and_then(|status| status.active.as_ref()) else { self.fail(); return; };
            let Some(session) = r.workflow.sessions.iter_mut().find(|s| s.projection.session_id == owner.session_id) else { self.fail(); return; };
            if !session.apply_requested || session.apply_returned || owner.phase != edit::Phase::Applying || !owner.apply_submitted
                || session.projection.prepared.as_ref().map(|p| &p.plan_token) != owner.prepared.as_ref().map(|p| &p.plan_token) { self.fail(); return; }
            session.apply_returned = true;
        }
        if let Ok(status) = result { self.workflow_status(status, edits); }
    }
    pub(super) fn workflow_close_request(&self) {
        if let Some(mut r) = self.record_at(Boundary::Request) { r.workflow.requests[3] = r.workflow.requests[3].saturating_add(1); }
        self.fail(); // Keep reviewing is local; native Quit must own original4.
    }
    pub(super) fn workflow_status(&self, status: &workflow::WorkflowEditStatus, edits: &EditOwner) {
        if self.case != Case::WorkflowApply { return; }
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        if status.schema_version != 1 || status.domain != workflow::DOMAIN || !edit::token(&status.window_generation)
            || r.generation.as_ref().is_some_and(|generation| generation != &status.window_generation) { self.fail(); return; }
        if r.generation.is_none() { r.generation = Some(status.window_generation.clone()); }
        if r.workflow.native_revision.is_some_and(|revision| status.status_revision < revision)
            || r.native_revision.is_some_and(|revision| status.status_revision < revision) { return; }
        if let Some(active) = &status.active {
            if !r.workflow.sessions.iter().any(|s| s.projection.session_id == active.session_id) {
                if r.workflow.open_pending && usize::from(r.workflow.requests[0]) == r.workflow.sessions.len() + 1 { return; }
                self.fail(); return;
            }
        }
        if status.capability.available && status.capability.reason == edit::EditAvailability::Available { r.workflow.capability = true; }
        else if r.workflow.capability && !(r.close_prevented && !status.capability.available
            && status.capability.reason == edit::EditAvailability::Shutdown) { self.fail(); return; }
        for projection in status.last_terminal.iter().chain(status.active.iter()) {
            let Some(index) = r.workflow.sessions.iter().position(|s| s.projection.session_id == projection.session_id) else { self.fail(); return; };
            let old = r.workflow.sessions[index].projection.clone();
            if projection.domain != workflow::DOMAIN || projection.project_id != old.project_id || projection.owner_generation != status.window_generation
                || !edit::token(&projection.session_id) || projection.late_settled || projection.phase == edit::Phase::Unknown
                || phase_order(projection.phase) < phase_order(old.phase) || projection.native_finality == edit::NativeFinality::Unknown
                || projection.apply_submitted != (r.workflow.sessions[index].apply_requested && phase_order(projection.phase) >= phase_order(edit::Phase::Applying))
                || projection.native_reason != (if index == 3 && r.close_prevented && phase_order(projection.phase) >= phase_order(edit::Phase::Finalizing) {
                    edit::NativeEditReason::Shutdown
                } else { edit::NativeEditReason::None }) { self.fail(); return; }
            let Some(proposal) = r.guidance.proposal.as_ref() else { self.fail(); return; };
            if let Some(checkout) = &projection.checkout {
                if !edit::token(&checkout.revision) || serde_json::to_value(&checkout.observed).ok() != workflow_observed(proposal, index)
                    || old.checkout.as_ref().is_some_and(|before| before.revision != checkout.revision
                        || serde_json::to_value(before).ok() != serde_json::to_value(checkout).ok())
                    || r.workflow.sessions.iter().enumerate().any(|(i, s)| i != index
                        && s.projection.checkout.as_ref().is_some_and(|c| c.revision == checkout.revision)) { self.fail(); return; }
            } else if old.checkout.is_some() { self.fail(); return; }
            let review = if let Some(prepared) = &projection.prepared {
                let Some(review) = workflow_review_sample(&prepared.view, proposal, index) else { self.fail(); return; };
                let Ok(value) = serde_json::to_value(prepared) else { self.fail(); return; };
                if !r.workflow.sessions[index].prepare_requested || !edit::token(&prepared.plan_token)
                    || !projection.checkout.as_ref().is_some_and(|c| c.revision == prepared.revision)
                    || prepared.draft_revision != 1 || prepared.baseline_generation != 1
                    || r.workflow.sessions[index].prepared.as_ref().is_some_and(|before| before != &value)
                    || r.workflow.sessions.iter().enumerate().any(|(i, s)| i != index
                        && s.projection.prepared.as_ref().is_some_and(|p| p.plan_token == prepared.plan_token)) { self.fail(); return; }
                Some((value, review))
            } else {
                if r.workflow.sessions[index].prepared.is_some() { self.fail(); return; } None
            };
            let conflict = if let Some(conflict) = &projection.conflict {
                let Some(sample) = workflow_conflict_sample(conflict, proposal) else { self.fail(); return; };
                if index != 1 || !r.workflow.sessions[index].prepare_requested || projection.prepared.is_some() || projection.apply_submitted
                    || r.workflow.sessions[index].conflict.as_ref().is_some_and(|before| before != &sample) { self.fail(); return; }
                Some(sample)
            } else {
                if r.workflow.sessions[index].conflict.is_some() { self.fail(); return; } None
            };
            if let Some(core) = &projection.core_outcome {
                if core.effect != (match index { 0 => edit::Effect::Committed, 2 => edit::Effect::Unchanged, _ => edit::Effect::NotStarted })
                    || core.journal != (if index == 0 { edit::Journal::Clean } else { edit::Journal::NotCreated })
                    || core.resources != edit::ResourceState::Settled
                    || core.reason != (if index == 3 { edit::CoreReason::Cancelled } else { edit::CoreReason::None })
                    || phase_order(projection.phase) < phase_order(edit::Phase::Finalizing) { self.fail(); return; }
            }
            if projection.phase == edit::Phase::Final {
                if projection.native_finality != edit::NativeFinality::Settled || projection.core_outcome.is_none()
                    || projection.prepared.is_some() != (index != 1) || projection.conflict.is_some() != (index == 1)
                    || index == 3 && !r.workflow.outstanding { self.fail(); return; }
                if r.workflow.sessions[index].finality.is_none() {
                    let Some(facts) = edits.installed_workflow_observation_final(&projection.session_id) else { self.fail(); return; };
                    if !workflow_original_final(&facts, projection, index) { self.fail(); return; }
                    r.workflow.sessions[index].finality = Some(facts);
                }
            } else if projection.native_finality != edit::NativeFinality::Pending { self.fail(); return; }
            let session = &mut r.workflow.sessions[index];
            if let Some((prepared, review)) = review { session.prepared = Some(prepared); session.review = Some(review); }
            if let Some(conflict) = conflict { session.conflict = Some(conflict); }
            session.projection = projection.clone();
        }
        r.workflow.native_revision = Some(status.status_revision);
    }


    fn version_dom(&self, step: VersionStep, value: &Value) {
        let Some(object) = value.as_object() else { self.fail(); return; };
        let Some(mut r) = self.record_at(Boundary::Dom) else { return; };
        let index = step.index();
        if self.case != Case::VersionSave || index >= 3 || r.pending.take() != Some(Pending::Dom(Step::VersionSave(step)))
            || r.step != Step::VersionSave(step) { self.fail(); return; }
        match value.get("state").and_then(Value::as_str) {
            Some("wait") if object.len() == 1 => return,
            Some("ready") => {}, _ => { self.fail(); return; },
        }
        let v = &r.version;
        let valid = match step {
            VersionStep::ReadOpen(_) => object.len() == 2 && value.get("display") == version_editor_display(index,false,false,false).as_ref()
                && v.sessions.get(index).is_some_and(|s|s.open_returned && s.projection.phase == edit::Phase::Editing
                    && s.projection.checkout.as_ref().is_some_and(|c|version_checkout_matches(index,c))),
            VersionStep::Name(_) => object.len() == 1 && index < 2
                && v.sessions.get(index).is_some_and(|s|s.open_visible && s.entered == [false;2]),
            VersionStep::Build(_) => object.len() == 1 && index < 2
                && v.sessions.get(index).is_some_and(|s|s.open_visible && s.entered == [true,false]),
            VersionStep::ReadInputs(_) => object.len() == 2 && value.get("display") == version_editor_display(index,true,false,false).as_ref()
                && v.sessions.get(index).is_some_and(|s|s.open_visible && s.entered == (if index == 2 { [false;2] } else { [true;2] })),
            VersionStep::ReadReview(_) => object.len() == 3 && value.get("display") == version_editor_display(index,true,false,true).as_ref()
                && v.sessions.get(index).is_some_and(|s|s.inputs_visible && s.prepare_returned && s.live_review()
                    && s.review.as_ref() == value.get("review")),
            VersionStep::ReadConfirmation(_) | VersionStep::ReadChecked(_) | VersionStep::ReadTyped(_) => {
                let checked = !matches!(step,VersionStep::ReadConfirmation(_));
                let typed = matches!(step,VersionStep::ReadTyped(_));
                let expected = version_values(index).map(|values|serde_json::json!({
                    "title":match index { 0 => "Create this saved version source?", 1 => "Save these reviewed version values?", _ => "Confirm this unchanged version file?" },
                    "selection":format!("Only {VERSION_SOURCE}, with marketing version {} and build {}. The original configuration, ignore proof, source and parents must still match.",values.name,values.build),
                    "scope":"No configuration Save, native-project rewrite, build, Git/index operation, Store request or release is included. A submitted save may finish after cancellation.",
                    "checked":checked,"typed":if typed { "SAVE" } else { "" },"applyAvailable":typed}));
                object.len() == 2 && value.get("confirmation") == expected.as_ref()
                    && v.sessions.get(index).is_some_and(|s|s.live_review() && s.review_visible && s.confirmation_opened)
            },
            VersionStep::ReadSaved(_) => object.len() == 3 && value.get("display") == version_editor_display(index,true,true,false).as_ref()
                && v.sessions.get(index).is_some_and(|s|s.open_returned && s.apply_returned && s.finality.is_some()
                    && s.source_final.is_some() && value.get("outcome") == version_outcome_display(index,s).as_ref()),
            VersionStep::ReadReadback(_) => object.len() == 4 && v.observations.len() == index + 1 && !v.observe_pending
                && value.get("display") == version_editor_display(index,true,true,false).as_ref()
                && v.sessions.get(index).is_some_and(|s|s.saved_visible && s.finality.is_some()
                    && value.get("outcome") == version_outcome_display(index,s).as_ref())
                && v.observations.get(index).is_some_and(|s|value.get("readback") == Some(&s.display)),
            _ => object.len() == 1,
        };
        if !valid { self.fail(); return; }
        let i = index as u8;
        let next = match step {
            VersionStep::Open(_) => VersionStep::ReadOpen(i),
            VersionStep::ReadOpen(_) => { r.version.sessions[index].open_visible = true;
                if index == 2 { VersionStep::ReadInputs(i) } else { VersionStep::Name(i) } },
            VersionStep::Name(_) => { r.version.sessions[index].entered[0] = true; VersionStep::Build(i) },
            VersionStep::Build(_) => { r.version.sessions[index].entered[1] = true; VersionStep::ReadInputs(i) },
            VersionStep::ReadInputs(_) => { r.version.sessions[index].inputs_visible = true; VersionStep::Review(i) },
            VersionStep::Review(_) => VersionStep::ReadReview(i),
            VersionStep::ReadReview(_) => { r.version.sessions[index].review_visible = true; VersionStep::Confirm(i) },
            VersionStep::Confirm(_) => { r.version.sessions[index].confirmation_opened = true; VersionStep::ReadConfirmation(i) },
            VersionStep::ReadConfirmation(_) => { r.version.sessions[index].initially_disabled = true; VersionStep::Check(i) },
            VersionStep::Check(_) => VersionStep::ReadChecked(i),
            VersionStep::ReadChecked(_) => { r.version.sessions[index].checkbox_only_disabled = true; VersionStep::Type(i) },
            VersionStep::Type(_) => VersionStep::ReadTyped(i),
            VersionStep::ReadTyped(_) => { r.version.sessions[index].typed_save = true; r.version.sessions[index].acknowledged = true; VersionStep::Apply(i) },
            VersionStep::Apply(_) => VersionStep::ReadSaved(i),
            VersionStep::ReadSaved(_) => { r.version.sessions[index].saved_visible = true; VersionStep::Readback(i) },
            VersionStep::Readback(_) => VersionStep::ReadReadback(i),
            VersionStep::ReadReadback(_) => { r.version.sessions[index].readback_visible = true;
                if index == 2 { r.step = Step::Close; return; } VersionStep::Open(i+1) },
        };
        r.step = Step::VersionSave(next);
    }

    fn metadata_dom(&self, step: MetadataStep, value: &Value) {
        let Some(object) = value.as_object() else { self.fail(); return; };
        let Some(mut r) = self.record_at(Boundary::Dom) else { return; };
        if self.case != Case::MetadataSave || r.pending.take() != Some(Pending::Dom(Step::MetadataSave(step)))
            || r.step != Step::MetadataSave(step) { self.fail(); return; }
        match value.get("state").and_then(Value::as_str) {
            Some("wait") if object.len() == 1 => return,
            Some("ready") => {}, _ => { self.fail(); return; },
        }
        let m = &r.metadata;
        let outcome = |index: usize| {
            let Some(session) = m.sessions.get(index) else { return false; };
            if !session.open_returned { return false; }
            let Some(core) = session.projection.core_outcome.as_ref() else { return false; };
            let Ok(core) = serde_json::to_value(core) else { return false; };
            value["outcome"] == serde_json::json!({"title":if index == 0 { "Text review ended; draft kept" } else { "Text saved" },
                "project":"metadata-project · android / en-US",
                "effect":format!("{} / {}",core["effect"].as_str().unwrap_or(""),core["journal"].as_str().unwrap_or("")),
                "resources":format!("{} / settled",core["resources"].as_str().unwrap_or("")),"reason":core["reason"]})
        };
        let valid = match step {
            MetadataStep::ReadLoaded => object.len() == 2 && m.observations.len() == 1 && !m.observe_pending
                && value["display"] == metadata_save_display(false,false,false,false),
            MetadataStep::Short => object.len() == 1 && m.loaded_visible && m.entered == [false;2],
            MetadataStep::Full => object.len() == 1 && m.loaded_visible && m.entered == [true,false],
            MetadataStep::ReadInputs => object.len() == 2 && m.entered == [true;2]
                && value["display"] == metadata_save_display(true,false,false,false),
            MetadataStep::ReadValidation => object.len() == 2 && m.validation_requested && m.validation.is_some() && m.ready
                && value["display"] == metadata_save_display(true,true,false,true)
                && m.inputs.is_some() && m.inputs == metadata_inputs(&value["display"]),
            MetadataStep::ReadReview(index) => object.len() == 3 && index < 2
                && m.sessions.get(usize::from(index)).is_some_and(|s|s.prepare_returned && s.live_review() && s.review.as_ref() == value.get("review"))
                && m.inputs.as_ref() == value.get("draft"),
            MetadataStep::ReadClosed => object.len() == 3 && m.requests == [1,1,0,1] && m.ready
                && m.sessions.first().is_some_and(|s|s.finality.is_some() && s.close_returned) && outcome(0)
                && value["display"] == metadata_save_display(true,true,false,true)
                && m.inputs == metadata_inputs(&value["display"]),
            MetadataStep::ReadConfirmation | MetadataStep::ReadChecked | MetadataStep::ReadTyped => {
                let checked = step != MetadataStep::ReadConfirmation;
                let typed = step == MetadataStep::ReadTyped;
                let files = m.sessions.get(1).and_then(|s|s.projection.prepared.as_ref()).map(|p|
                    p.view.files.iter().map(|file|serde_json::json!([file.path,file.action])).collect::<Vec<_>>());
                object.len() == 2 && m.requests == [2,2,0,1] && m.confirmation_opened == 1
                    && m.sessions.get(1).is_some_and(|s|s.live_review() && s.review_visible) && files.is_some()
                    && value["confirmation"] == serde_json::json!({"title":"Save this reviewed locale bundle?","files":files,
                        "checked":checked,"typed":if typed { "SAVE" } else { "" },"applyAvailable":typed})
            },
            MetadataStep::ReadSaved => object.len() == 3 && m.requests == [2,2,1,1]
                && m.sessions.get(1).is_some_and(|s|s.finality.is_some() && s.apply_returned) && outcome(1)
                && value["display"] == metadata_save_display(true,true,true,false)
                && m.inputs == metadata_inputs(&value["display"]),
            MetadataStep::ReadReadback => object.len() == 3 && m.saved_visible && m.observations.len() == 2 && !m.observe_pending
                && outcome(1) && value["display"] == metadata_save_display(true,true,true,false)
                && m.inputs == metadata_inputs(&value["display"]),
            _ => object.len() == 1,
        };
        if !valid { self.fail(); return; }
        let next = match step {
            MetadataStep::Navigate => MetadataStep::Load,
            MetadataStep::Load => MetadataStep::ReadLoaded,
            MetadataStep::ReadLoaded => { r.metadata.loaded_visible = true; MetadataStep::Short },
            MetadataStep::Short => { r.metadata.entered[0] = true; MetadataStep::Full },
            MetadataStep::Full => { r.metadata.entered[1] = true; MetadataStep::ReadInputs },
            MetadataStep::ReadInputs => { r.metadata.inputs = metadata_inputs(&value["display"]); MetadataStep::Validate },
            MetadataStep::Validate => MetadataStep::ReadValidation,
            MetadataStep::ReadValidation => { r.metadata.validation_visible = true; MetadataStep::Review(0) },
            MetadataStep::Review(index) => MetadataStep::OpenText(index),
            MetadataStep::OpenText(index) => MetadataStep::ReadReview(index),
            MetadataStep::ReadReview(index) => {
                r.metadata.sessions[usize::from(index)].review_visible = true;
                if index == 0 { MetadataStep::CloseReview } else { MetadataStep::Confirm }
            },
            MetadataStep::CloseReview => MetadataStep::ReadClosed,
            MetadataStep::ReadClosed => { r.metadata.retained_after_close = true; MetadataStep::Review(1) },
            MetadataStep::Confirm => { r.metadata.confirmation_opened += 1; MetadataStep::ReadConfirmation },
            MetadataStep::ReadConfirmation => { r.metadata.initially_disabled = true; MetadataStep::Check },
            MetadataStep::Check => MetadataStep::ReadChecked,
            MetadataStep::ReadChecked => { r.metadata.checkbox_only_disabled = true; MetadataStep::Type },
            MetadataStep::Type => MetadataStep::ReadTyped,
            MetadataStep::ReadTyped => { r.metadata.typed_save = true; r.metadata.acknowledged = true; MetadataStep::Apply },
            MetadataStep::Apply => MetadataStep::ReadSaved,
            MetadataStep::ReadSaved => { r.metadata.saved_visible = true; MetadataStep::Refresh },
            MetadataStep::Refresh => MetadataStep::ReadReadback,
            MetadataStep::ReadReadback => { r.metadata.readback_visible = true; r.step = Step::Close; return; },
        };
        r.step = Step::MetadataSave(next);
    }

    fn workflow_dom(&self, step: WorkflowStep, value: &Value) {
        let Some(object) = value.as_object() else { self.fail(); return; };
        let Some(mut r) = self.record_at(Boundary::Dom) else { return; };
        if self.case != Case::WorkflowApply || r.pending.take() != Some(Pending::Dom(Step::Workflow(step)))
            || r.step != Step::Workflow(step) { self.fail(); return; }
        match value.get("state").and_then(Value::as_str) {
            Some("wait") if object.len() == 1 => return,
            Some("ready") => {}, _ => { self.fail(); return; },
        }
        let review = |index: usize| r.workflow.sessions.get(index).is_some_and(|s| s.prepare_returned && s.live_review()
            && s.review.as_ref() == value.get("review"));
        let valid = match step {
            WorkflowStep::ReadPin(index) => object.len() == 2 && matches!(index, 1 | 2)
                && value["inputs"] == serde_json::json!({"repository":TOOLKIT_REPOSITORY,
                    "sha":if index == 1 { CONFLICT_SHA } else { TOOLKIT_SHA },"comparison":false}),
            WorkflowStep::ReadReview(index) => object.len() == 2 && review(usize::from(index)),
            WorkflowStep::ReadKept => object.len() == 2 && review(0) && r.workflow.requests == [1, 1, 0, 0]
                && r.workflow.sessions[0].confirmation_opened == 1,
            WorkflowStep::ReadConfirmation(index) | WorkflowStep::ReadAcknowledged(index) => {
                let acknowledged = matches!(step, WorkflowStep::ReadAcknowledged(_));
                object.len() == 2 && matches!(index, 0 | 2)
                    && r.workflow.sessions.get(usize::from(index)).is_some_and(|s| s.live_review() && s.review_visible
                        && s.confirmation_opened == (if index == 0 && acknowledged { 2 } else { 1 })
                        && (!acknowledged || index != 0 || s.kept_reviewing)
                        && s.review.as_ref().is_some_and(|review| value["confirmation"] == serde_json::json!({
                            "title":if index == 0 { "Apply this four-caller bundle?" } else { "Confirm four unchanged callers?" },
                            "draftRevision":1,"pin":format!("{TOOLKIT_REPOSITORY}@{TOOLKIT_SHA}"),"files":review["files"],
                            "checked":acknowledged,"applyAvailable":acknowledged})))
            },
            WorkflowStep::ReadReconfirmation => object.len() == 2 && r.workflow.requests == [1, 1, 0, 0]
                && r.workflow.sessions.first().is_some_and(|s| s.live_review() && s.confirmation_opened == 2 && s.kept_reviewing
                    && s.review.as_ref().is_some_and(|review| value["confirmation"] == serde_json::json!({
                        "title":"Apply this four-caller bundle?","draftRevision":1,"pin":format!("{TOOLKIT_REPOSITORY}@{TOOLKIT_SHA}"),
                        "files":review["files"],"checked":false,"applyAvailable":false}))),
            WorkflowStep::ReadResult(index) => object.len() == 8 && index < 3
                && r.workflow.sessions.get(usize::from(index)).is_some_and(|s| s.finality.is_some() && s.prepare_returned
                    && s.apply_returned == (index != 1)
                    && value["conflict"] == s.conflict.clone().unwrap_or(Value::Null))
                && value["title"].as_str() == Some(match index { 0 => "Reviewed local workflow bundle installed",
                    1 => "Local workflow bundle refused", _ => "Four callers verified unchanged" })
                && value["facts"] == serde_json::json!([["Transaction effect",match index { 0 => "committed", 1 => "not_started", _ => "unchanged" }],
                    ["Journal",if index == 0 { "clean" } else { "not_created" }],["Core resources","settled"],["Native finality","settled"]])
                && value["startAvailable"].as_bool() == Some(true) && value["applyAvailable"].as_bool() == Some(false)
                && value["closeAvailable"].as_bool() == Some(false) && value["hasReview"].as_bool() == Some(index != 1),
            WorkflowStep::ReadDraft(index) => object.len() == 5 && index < 4 && r.workflow.draft_reads == index
                && value["unsaved"].as_bool() == Some(true) && value["saved"].as_bool() == Some(false)
                && value["saveAvailable"].as_bool() == Some(index != 3)
                && r.suggested.as_ref().is_some_and(|draft| value["source"].as_str() == draft["version"]["source"].as_str())
                && r.workflow.sessions.get(usize::from(index)).is_some_and(|s| if index == 3 { s.live_review() && s.review_visible }
                    else { s.finality.is_some() && s.result_visible }),
            _ => object.len() == 1,
        };
        if !valid { self.fail(); return; }
        let next = match step {
            WorkflowStep::GitHub(index) => if matches!(index, 1 | 2) { WorkflowStep::Pin(index) } else { WorkflowStep::Start(index) },
            WorkflowStep::Pin(index) => WorkflowStep::ReadPin(index),
            WorkflowStep::ReadPin(index) => {
                if index == 1 { r.workflow.pin_changed = true; } else { r.workflow.pin_restored = true; }
                WorkflowStep::Start(index)
            },
            WorkflowStep::Start(index) => if index == 1 { WorkflowStep::ReadResult(index) } else { WorkflowStep::OpenText(index) },
            WorkflowStep::OpenText(index) => WorkflowStep::ReadReview(index),
            WorkflowStep::ReadReview(index) => {
                r.workflow.sessions[usize::from(index)].review_visible = true;
                if index == 3 { WorkflowStep::Settings(index) } else { WorkflowStep::Confirm(index) }
            },
            WorkflowStep::Confirm(index) => {
                r.workflow.sessions[usize::from(index)].confirmation_opened += 1; WorkflowStep::ReadConfirmation(index)
            },
            WorkflowStep::ReadConfirmation(index) => if index == 0 { WorkflowStep::Keep } else { WorkflowStep::Acknowledge(index) },
            WorkflowStep::Keep => WorkflowStep::ReadKept,
            WorkflowStep::ReadKept => { r.workflow.sessions[0].kept_reviewing = true; WorkflowStep::Reconfirm },
            WorkflowStep::Reconfirm => { r.workflow.sessions[0].confirmation_opened += 1; WorkflowStep::ReadReconfirmation },
            WorkflowStep::ReadReconfirmation => WorkflowStep::Acknowledge(0),
            WorkflowStep::Acknowledge(index) => WorkflowStep::ReadAcknowledged(index),
            WorkflowStep::ReadAcknowledged(index) => { r.workflow.sessions[usize::from(index)].acknowledged = true; WorkflowStep::Apply(index) },
            WorkflowStep::Apply(index) => WorkflowStep::ReadResult(index),
            WorkflowStep::ReadResult(index) => { r.workflow.sessions[usize::from(index)].result_visible = true; WorkflowStep::Settings(index) },
            WorkflowStep::Settings(index) => WorkflowStep::ReadDraft(index),
            WorkflowStep::ReadDraft(index) => {
                r.workflow.draft_reads += 1;
                if index == 3 { r.step = Step::Close; return; }
                WorkflowStep::GitHub(index + 1)
            },
        };
        r.step = Step::Workflow(next);
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
    pub(super) fn path_failed(&self, rejection: PathRejection) {
        // Shell callers have left every DIALOG/GuiFacts borrow. Record-held
        // callbacks use path_fail directly and never reacquire this mutex.
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        self.path_fail(&mut r,rejection);
    }
    pub(super) fn path_dialog(&self, id: u32, index: u8) -> Result<(PF,bool),()> {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return Err(()); };
        let Some(case) = PATH_CASES.get(index as usize) else { self.path_fail(&mut r,PathRejection::GtkDialogRecord); return Err(()); };
        if self.failed.load(Ordering::SeqCst) { return Err(()); }
        if Instant::now() >= self.end { self.path_fail(&mut r,PathRejection::GtkObserverEndpoint); return Err(()); }
        if self.case != Case::ProjectPaths || id != u32::from(index)+3 || !r.paths.operations[index as usize].requested
            || !r.paths.operations[index as usize].picker.created
            || !matches!(r.pending,Some(Pending::Path(PathStep::Set(i) | PathStep::Activate(i))) if i == index) {
            self.path_fail(&mut r,PathRejection::GtkDialogRecord); return Err(());
        }
        Ok((case.field,!r.paths.operations[index as usize].picker.selected))
    }
    pub(super) fn path_target(&self, index: u8) -> Option<PathBuf> {
        if self.case != Case::ProjectPaths { return None; }
        let path = PATH_CASES.get(index as usize)?.path?;
        Some(self.project_path()?.parent()?.join(path))
    }
    pub(super) fn path_selection(&self, id: u32, index: u8) -> Result<(),()> {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return Err(()); };
        if self.case != Case::ProjectPaths { self.path_fail(&mut r,PathRejection::GtkDialogRecord); return Err(()); }
        if Instant::now() >= self.end { self.path_fail(&mut r,PathRejection::GtkObserverEndpoint); return Err(()); }
        if self.failed.load(Ordering::SeqCst) { return Err(()); }
        if id != u32::from(index)+3 || r.pending != Some(Pending::Path(PathStep::Set(index))) {
            self.path_fail(&mut r,PathRejection::GtkDialogRecord); return Err(());
        }
        let Some(op) = r.paths.operations.get_mut(index as usize) else { self.path_fail(&mut r,PathRejection::GtkDialogRecord); return Err(()); };
        if !op.picker.created || op.picker.selected || op.picker.activated { self.path_fail(&mut r,PathRejection::GtkSelectionState); return Err(()); }
        op.picker.selected = true; Ok(())
    }
    pub(super) fn path_activation(&self, id: u32, index: u8) -> Result<(),()> {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return Err(()); };
        let Some(case) = PATH_CASES.get(index as usize) else { self.path_fail(&mut r,PathRejection::GtkDialogRecord); return Err(()); };
        if self.case != Case::ProjectPaths { self.path_fail(&mut r,PathRejection::GtkDialogRecord); return Err(()); }
        if Instant::now() >= self.end { self.path_fail(&mut r,PathRejection::GtkObserverEndpoint); return Err(()); }
        if self.failed.load(Ordering::SeqCst) { return Err(()); }
        if id != u32::from(index)+3 || r.pending != Some(Pending::Path(PathStep::Activate(index))) {
            self.path_fail(&mut r,PathRejection::GtkDialogRecord); return Err(());
        }
        let op = &mut r.paths.operations[index as usize];
        if !op.picker.created || op.picker.activated || op.picker.selected != case.path.is_some() { self.path_fail(&mut r,PathRejection::GtkActivationState); return Err(()); }
        op.picker.activated = true; Ok(())
    }
    pub(super) fn path_filename(&self, id: u32, field: PF, path: Option<&Path>) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        let Some(index) = id.checked_sub(3).filter(|i| *i < 11) else { self.path_fail(&mut r,PathRejection::GtkFilenameState); return; };
        let index = index as usize;
        if self.case != Case::ProjectPaths { self.path_fail(&mut r,PathRejection::GtkFilenameState); return; }
        if self.failed.load(Ordering::SeqCst) { return; }
        if Instant::now() >= self.end { self.path_fail(&mut r,PathRejection::GtkObserverEndpoint); return; }
        if PATH_CASES[index].field != field { self.path_fail(&mut r,PathRejection::GtkFilenameState); return; }
        if path.is_none() { self.path_fail(&mut r,PathRejection::GtkFilenameAbsent); return; }
        if path != self.path_target(index as u8).as_deref() { self.path_fail(&mut r,PathRejection::GtkFilenameDifferent); return; }
        if !r.paths.operations[index].picker.activated || r.paths.operations[index].picker.filename
            || r.paths.operations[index].picker.responded { self.path_fail(&mut r,PathRejection::GtkFilenameState); return; }
        // Exactly after the production filename() return and BEFORE its
        // selected_path publication. This callback changes only fixed fixture
        // metadata; it does not start a worker or manufacture a source result.
        if id >= 10 && !r.paths.fixture.as_mut().is_some_and(|fixture| fixture.transition(id).is_ok()) { self.path_fail(&mut r,PathRejection::GtkFixtureTransition); return; }
        if Instant::now() >= self.end { self.path_fail(&mut r,PathRejection::GtkObserverEndpoint); return; }
        r.paths.operations[index].picker.filename = true;
    }
    pub(super) fn path_response(&self, id: u32, accepted: bool, cancelled: bool, disposal: bool) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        let Some(index) = id.checked_sub(3).filter(|i| *i < 11) else { self.path_fail(&mut r,PathRejection::GtkResponseState); return; };
        let select = PATH_CASES[index as usize].path.is_some(); let p = &mut r.paths.operations[index as usize].picker;
        if self.case != Case::ProjectPaths || !p.activated || p.destroyed || p.released { self.path_fail(&mut r,PathRejection::GtkResponseState); return; }
        if !p.responded && !disposal && (select && accepted && !cancelled && p.filename || !select && cancelled && !accepted && !p.filename) { p.responded = true; }
        else if p.responded && p.returned && disposal && !accepted && !cancelled && !p.disposal { p.disposal = true; }
        else { self.path_fail(&mut r,PathRejection::GtkResponseContract); }
    }
    fn path_gtk_returned(&self, path: PathStep, result: Result<bool,()>) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        if r.pending.take() != Some(Pending::Path(path)) || r.step != Step::Paths(path) { self.path_fail(&mut r,PathRejection::GtkReturnState); return; }
        let (index,selecting) = match path { PathStep::Set(i) => (i,true), PathStep::Activate(i) => (i,false), _ => { self.path_fail(&mut r,PathRejection::GtkReturnState); return; } };
        let Some(op) = r.paths.operations.get_mut(index as usize) else { self.path_fail(&mut r,PathRejection::GtkReturnState); return; };
        match result {
            Ok(false) if !op.picker.activated && (!selecting || !op.picker.selected) => {},
            Ok(true) if selecting && op.picker.selected && !op.picker.activated => r.step = Step::Paths(PathStep::Activate(index)),
            Ok(true) if !selecting => {
                if !op.picker.activation_returned(result) { self.path_fail(&mut r,PathRejection::GtkReturnState); return; }
                r.step = Step::Paths(PathStep::Settled(index));
            }, _ => self.path_fail(&mut r,PathRejection::GtkReturnState),
        }
        self.path_sample(&mut r);
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
        self.path_sample(&mut r);
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
        if self.failed.load(Ordering::SeqCst) { self.failure_tick(app); return; }
        if Instant::now() >= self.end {
            // Preserve the first failure even if another callback failed while
            // this relay was acquiring the record. Report only after unlock.
            if let Some(mut r) = self.record() {
                let diagnostic = SessionDiagnostic::sample(r.step,r.evaluations,r.session.diagnostic);
                let path_diagnostic = PathDiagnostic::sample(r.step,self.start.elapsed().as_millis(),r.paths.diagnostic);
                let Record { step, trace, bootstrap, .. } = &mut *r;
                let progress = *bootstrap;
                if latch_failure(&self.failed, trace, bootstrap, (*step, Boundary::Deadline), progress) {
                    r.session.diagnostic = diagnostic;
                    r.paths.diagnostic = path_diagnostic;
                }
            }
            self.failure_tick(app); return;
        }
        if std::thread::current().id() == self.main { self.fail(); self.failure_tick(app); return; }
        let step = {
            let Some(mut r) = self.record_at(Boundary::Settlement) else { return; };
            if self.failed.load(Ordering::SeqCst) { return; }
            if !r.attached {
                if r.step == Step::Bootstrap { r.bootstrap = BootstrapProgress::Attachment; }
                return;
            }
            if !r.loaded {
                if r.step == Step::Bootstrap { r.bootstrap = BootstrapProgress::PageLoad; }
                return;
            }
            if r.pending.is_some() { return; }
            if r.step == Step::Bootstrap {
                // Observe the same owners after start_relay returned and its
                // barrier opened. Teardown may legitimately report document loss.
                let state = app.state::<super::ShellState>();
                match (state.bridge.preflight.original_for_test().observed_document_lost_for_test(),
                       state.bridge.android_build.original_for_test().observed_document_lost_for_test()) {
                    (Some(false), Some(false)) => {},
                    (Some(true), _) | (_, Some(true)) => { self.fail(); return; },
                    _ => { r.bootstrap = BootstrapProgress::OriginalRegistrySample; return; },
                    // No absent/busy/unknown observation becomes false.
                }
            }
            if r.step == Step::Bootstrap && self.case != Case::Outstanding {
                if !r.info || !r.catalog { r.bootstrap = BootstrapProgress::AppInfoCatalog; return; }
                r.step = if self.case.session().is_some() || self.commands.is_some() { Step::Dashboard } else { Step::Environment }; r.bootstrap = BootstrapProgress::Advanced;
            }
            if r.step == Step::Bootstrap { r.bootstrap = BootstrapProgress::HeldAppInfo; }
            // Wait for already-requested native replies without spending DOM
            // evaluations on work that has not returned. No new task/deadline.
            let native_pending = match r.step {
                Step::VersionSave(VersionStep::ReadOpen(index)) => !r.version.sessions.get(usize::from(index))
                    .is_some_and(|s|s.open_returned && s.projection.phase == edit::Phase::Editing),
                Step::VersionSave(VersionStep::ReadReview(index)) => !r.version.sessions.get(usize::from(index))
                    .is_some_and(|s|s.prepare_returned && s.live_review()),
                Step::VersionSave(VersionStep::ReadSaved(index)) => !r.version.sessions.get(usize::from(index))
                    .is_some_and(|s|s.open_returned && s.apply_returned && s.finality.is_some() && s.source_final.is_some()),
                Step::VersionSave(VersionStep::ReadReadback(index)) => r.version.observe_pending
                    || r.version.observations.len() != usize::from(index)+1,
                Step::MetadataSave(MetadataStep::OpenText(index) | MetadataStep::ReadReview(index)) =>
                    !r.metadata.sessions.get(usize::from(index)).is_some_and(|s|s.prepare_returned && s.live_review()),
                Step::MetadataSave(MetadataStep::ReadLoaded) => r.metadata.observations.len() != 1 || r.metadata.observe_pending,
                Step::MetadataSave(MetadataStep::ReadValidation) => r.metadata.validation.is_none() || !r.metadata.ready,
                Step::MetadataSave(MetadataStep::ReadClosed) => !r.metadata.ready
                    || !r.metadata.sessions.first().is_some_and(|s|s.open_returned && s.close_returned && s.finality.is_some()),
                Step::MetadataSave(MetadataStep::ReadSaved) => !r.metadata.sessions.get(1).is_some_and(|s|s.open_returned && s.apply_returned && s.finality.is_some()),
                Step::MetadataSave(MetadataStep::ReadReadback) => r.metadata.observations.len() != 2 || r.metadata.observe_pending,
                Step::Workflow(WorkflowStep::OpenText(index) | WorkflowStep::ReadReview(index)) =>
                    !r.workflow.sessions.get(usize::from(index)).is_some_and(|s| s.prepare_returned && s.live_review()),
                Step::Workflow(WorkflowStep::ReadResult(index)) =>
                    !r.workflow.sessions.get(usize::from(index)).is_some_and(|s| s.prepare_returned && s.finality.is_some()
                        && (index == 1 || s.apply_returned)),
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
                Step::ReadMetadataValidation => r.saved_reads.validation.is_none() || !r.metadata.ready,
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
                    if !self.failed.load(Ordering::SeqCst) { r.bootstrap = BootstrapProgress::Advanced; }
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
            r.paths.operations[index as usize].settled = true; r.step = Step::Paths(PathStep::ReadField(index));
            self.path_sample(&mut r); return;
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
        if let Step::Session(step) = step { self.session_tick(app,step); return; }
        if let Step::Commands(step) = step {
            let Some(commands) = &self.commands else { self.fail(); return; };
            if !commands.tick(app, step) { return; }
        }
        {
            let Some(mut r) = self.record_at(Boundary::Settlement) else { return; };
            // A failed handoff cannot race a later recipe Close/GTK reservation.
            if self.failed.load(Ordering::SeqCst) { return; }
            r.pending = Some(match step {
                Step::Close => {
                    if self.case == Case::Positive {
                        if !r.sessions.get(1).is_some_and(|session| session.review_visible && session.live_review())
                            || r.requests != [2, 2, 1, 0] || !r.readback_visible || !r.saved_draft_retained || !r.saved_reads.complete()
                            || !r.candidate.complete() { self.fail(); return; }
                        r.noop_outstanding = true;
                    }
                    if self.case == Case::ProjectPaths && (!r.paths.complete() || r.requests != [0;4] || !r.sessions.is_empty()) { self.fail(); return; }
                    if self.case == Case::WorkflowApply {
                        if r.requests != [0; 4] || !r.sessions.is_empty() || r.workflow.requests != [4, 4, 2, 0]
                            || r.workflow.draft_reads != 4 || r.workflow.sessions.len() != 4
                            || !r.workflow.sessions[..3].iter().all(|s| s.finality.is_some() && s.result_visible)
                            || !r.workflow.sessions[3].live_review() || !r.workflow.sessions[3].review_visible { self.fail(); return; }
                        r.workflow.outstanding = true;
                    }
                    if self.case == Case::MetadataSave && (!r.metadata.complete() || r.requests != [0;4]
                        || !r.sessions.is_empty() || r.workflow.requests != [0;4]) { self.fail(); return; }
                    if self.case == Case::VersionSave && (!r.version.complete() || r.requests != [0;4]
                        || !r.sessions.is_empty() || r.workflow.requests != [0;4] || r.metadata.requests != [0;4]) { self.fail(); return; }
                    if self.commands.as_ref().is_some_and(|c| !c.complete() || r.requests != [0;4] || !r.sessions.is_empty()
                        || r.workflow.requests != [0;4]) { self.fail(); return; }
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
                // Reservation is not proof that a main-thread callback queued.
                self.path_callback(path,PathCallback::Reserved);
                if window.run_on_main_thread(move || {
                    q.path_callback(path,PathCallback::Entered);
                    let result = if matches!(path,PathStep::Set(_)) { super::owned_gtk::select_observed_path(&app,&q,index) }
                        else { super::owned_gtk::activate_observed_path(&app,&q,index) };
                    q.path_callback(path,PathCallback::Returned);
                    q.path_gtk_returned(path,result);
                }).is_err() {
                    if let Some(mut r) = self.record() { self.path_fail(&mut r,PathRejection::GtkDispatch); } else { self.fail(); }
                }
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
                let Some(script) = script(step, self.case) else { self.fail(); return; };
                let q = self.clone();
                // Outer Ok is dispatch, never an evaluation or DOM receipt.
                // An absent callback remains pending; it is never retried.
                if window.eval_with_callback(script, move |value| q.dom(step, &value)).is_err() { self.fail(); }
            },
        }
    }
    fn dom(&self, step: Step, raw: &str) {
        if raw.len() > 262144 { self.fail(); return; }
        if Instant::now() >= self.end { self.fail(); return; }
        let Ok(value) = crate::protocol::strict_json(raw.as_bytes()) else { self.fail(); return; };
        if let Step::Commands(step) = step {
            if let Some(commands) = &self.commands { commands.dom(step, &value); } else { self.fail(); } return;
        }
        if let Step::Session(session) = step { self.session_dom(session,&value); return; }
        if let Step::Paths(path) = step { self.path_dom(path,&value); return; }
        if let Step::Workflow(workflow) = step { self.workflow_dom(workflow, &value); return; }
        if let Step::MetadataSave(metadata) = step { self.metadata_dom(metadata, &value); return; }
        if let Step::VersionSave(version) = step { self.version_dom(version, &value); return; }
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
            Step::ReadSnapshot if self.case.session().is_some() || self.commands.is_some() => object.len() == 4 && r.selected && r.snapshot
                && value["configuration"].as_str() == Some("Format-valid only") && value["name"].as_str() == Some("project")
                && value["sourceFiles"].as_str().is_some_and(|text| text.ends_with(" recognized files")),
            Step::ReadSnapshot => object.len() == 4 && r.selected && r.snapshot
                && value["configuration"].as_str() == Some(if matches!(self.case,Case::MetadataSave | Case::VersionSave) { "Format-valid only" } else { "Not configured" })
                && value["sourceFiles"].as_str() == Some(if self.case == Case::ProjectPaths { "0 recognized files" }
                    else if self.case == Case::MetadataSave { "3 recognized files" }
                    else if self.case == Case::VersionSave { "1 recognized files" } else { "2 recognized files" })
                && value["name"].as_str() == Some(match self.case { Case::ProjectPaths => "path-project",
                    Case::WorkflowApply => "workflow-project", Case::MetadataSave => "metadata-project",
                    Case::VersionSave => "version-project", _ => "positive-project" }),
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
            Step::ReadMetadataValidation => object.len() == 2 && saved_read_context(&r) && r.saved_reads.validation_called && r.metadata.ready
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
        if self.case == Case::SettledFailure && step == Step::ReadCancelled {
            // The original Choose/Cancel operation and its GTK picker already
            // settled in tick. Only the actual valid unselected DOM above may
            // contradict this one recipe's deliberate "project selected" demand.
            // Do not alter application state, owner facts, pending work or Quit.
            if Instant::now() >= self.end { self.fail(); return; }
            let Record { trace, bootstrap, .. } = &mut *r;
            let progress = *bootstrap;
            latch_failure(&self.failed, trace, bootstrap, (Step::SettledFailure, Boundary::Dom), progress);
            return; // The existing next failed tick alone requests real Close.
        }
        r.step = match step {
            Step::Environment => Step::ReadEnvironment,
            Step::ReadEnvironment => { r.environment = true; Step::Dashboard },
            Step::Dashboard => Step::ChooseCancel,
            Step::ChooseCancel => Step::Cancel,
            Step::ReadCancelled => Step::ChooseSelect,
            Step::ChooseSelect => Step::SetProject,
            Step::ReadSnapshot => { r.snapshot_visible = true;
                if self.commands.is_some() { Step::Commands(commands::Step::Navigate) }
                else if self.case.session().is_some() { Step::Session(SessionStep::Navigate) }
                else if self.case == Case::MetadataSave { Step::MetadataSave(MetadataStep::Navigate) }
                else if self.case == Case::VersionSave { Step::VersionSave(VersionStep::Open(0)) } else { Step::Settings } },
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
            Step::ReadRetainedDraft => { r.guidance.draft_retained = true;
                if self.case == Case::WorkflowApply { Step::Workflow(WorkflowStep::GitHub(0)) } else { Step::PrepareSave } },
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
        self.path_sample(&mut r);
    }
    pub(super) fn close_prevented(&self) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        if self.failed.load(Ordering::SeqCst) { failure_quit(&mut r).closed(); return; }
        if r.step==Step::Session(SessionStep::QuitCancel) {
            if r.pending!=Some(Pending::Close) || r.session.cancel_close_prevented {
                self.fail(); failure_quit(&mut r).closed(); return;
            }
            r.pending = None; r.session.cancel_close_prevented=true; return;
        }
        if r.pending != Some(Pending::Close) || r.step != Step::Quit || r.close_prevented {
            self.fail(); failure_quit(&mut r).closed(); return;
        }
        r.pending = None; r.close_prevented = true;
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
            Ok(true) if matches!(step, Step::Cancel | Step::SelectProject) => {
                if !r.pickers[index].activation_returned(result) { self.fail(); return; }
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
            Ok(true) if matches!(step, Step::CancelEvidence | Step::SelectEvidence) => {
                if !r.candidate.pickers[index].activation_returned(result) { self.fail(); return; }
                r.step = if index == 0 { Step::EvidenceCancelled } else { Step::EvidenceSelected };
            },
            _ => self.fail(),
        }
    }
    pub(super) fn native_created(&self, id: u32, quit: bool) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        if self.failed.load(Ordering::SeqCst) { failure_quit(&mut r).created(id, quit); return; }
        if r.step==Step::Session(SessionStep::QuitCancel) {
            if !quit || id<=2 || !r.session.cancel_close_prevented || r.session.quit_cancel_id.is_some() { self.fail(); return; }
            r.session.quit_cancel_id=Some(id); r.session.quit_cancel.created=true; return;
        }
        if !quit || id == 0 || self.case == Case::Positive && id != 6 || self.case == Case::ProjectPaths && id != 14
            || matches!(self.case,Case::WorkflowApply | Case::MetadataSave | Case::VersionSave | Case::Commands(_)) && id != 3
            || !r.close_prevented || r.step != Step::Quit || r.native_id.is_some() { self.fail(); return; }
        r.native_id = Some(id);
    }
    pub(super) fn native_activation(&self, id: u32) -> Result<(), ()> {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return Err(()); };
        if self.failed.load(Ordering::SeqCst) { return failure_quit(&mut r).activate(id, Instant::now() < self.end); }
        if r.step==Step::Session(SessionStep::QuitCancel) {
            if self.failed.load(Ordering::SeqCst) || Instant::now()>=self.end || r.pending!=Some(Pending::Gtk)
                || r.session.quit_cancel_id!=Some(id) || r.session.quit_cancel.activated { self.fail(); return Err(()); }
            r.session.quit_cancel.activated=true; return Ok(());
        }
        if self.failed.load(Ordering::SeqCst) || Instant::now() >= self.end || r.native_id != Some(id)
            || r.pending != Some(Pending::Gtk) || r.activated { self.fail(); return Err(()); }
        r.activated = true; Ok(())
    }
    pub(super) fn native_response(&self, id: u32, accepted: bool, declined: bool, disposal: bool) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        if self.failed.load(Ordering::SeqCst) { failure_quit(&mut r).response(id, accepted, declined, disposal); return; }
        if r.session.quit_cancel_id==Some(id) {
            let p=&mut r.session.quit_cancel;
            if !p.activated || p.destroyed || p.released { self.fail(); return; }
            if !p.responded && declined && !accepted && !disposal { p.responded=true; }
            else if p.responded && p.returned && disposal && !accepted && !declined && !p.disposal { p.disposal=true; }
            else { self.fail(); } return;
        }
        if declined { self.fail(); return; }
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
        if self.failed.load(Ordering::SeqCst) { failure_quit(&mut r).activation_returned(result); return; }
        if r.pending != Some(Pending::Gtk) { self.fail(); failure_quit(&mut r).refuse(); return; }
        if r.step==Step::Session(SessionStep::QuitCancel) {
            if result==Ok(false) && !r.session.quit_cancel.activated { r.pending = None; return; }
            if !r.session.quit_cancel.activation_returned(result) { self.fail(); failure_quit(&mut r).refuse(); return; }
            r.pending = None; r.step=Step::Session(SessionStep::QuitPreserved); return;
        }
        match result {
            Ok(false) if !r.activated => { r.pending = None; },
            Ok(true) if r.activated && r.responded => { r.pending = None; r.gtk_returned = true; r.step = Step::Exit; },
            _ => { self.fail(); failure_quit(&mut r).refuse(); },
        }
    }
    pub(super) fn native_destroyed(&self, id: u32, seen: bool) {
        let Some(mut r) = self.record_at(Boundary::Gtk) else { return; };
        if self.failed.load(Ordering::SeqCst) {
            let quit = failure_quit(&mut r);
            if quit.id == Some(id) { quit.destroyed(id, seen); return; }
        }
        if self.case.session().is_some() && id>2 {
            let p=if r.session.quit_cancel_id==Some(id) { Some(&mut r.session.quit_cancel) }
                else { r.session.files.iter_mut().find(|file| file.id==id).map(|file| &mut file.picker) };
            if let Some(p)=p { if !seen || !p.responded || p.destroyed { self.session_fail(&mut r,SessionRejection::GtkDestroyState); return; } p.destroyed=true; return; }
        }
        if self.case != Case::Outstanding && (1..=2).contains(&id) {
            let p = &mut r.pickers[(id - 1) as usize];
            if !seen || !p.responded || p.destroyed { self.fail(); return; }
            p.destroyed = true; return;
        }
        if self.case == Case::ProjectPaths && (3..=13).contains(&id) {
            let p = &mut r.paths.operations[(id-3) as usize].picker;
            if !seen || !p.responded || p.destroyed { self.path_fail(&mut r,PathRejection::GtkDestroyState); return; }
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
        if self.failed.load(Ordering::SeqCst) {
            let quit = failure_quit(&mut r);
            if quit.id == Some(id) { quit.released(id, seen); return; }
        }
        if self.case.session().is_some() && id>2 {
            let p=if r.session.quit_cancel_id==Some(id) { Some(&mut r.session.quit_cancel) }
                else { r.session.files.iter_mut().find(|file| file.id==id).map(|file| &mut file.picker) };
            if let Some(p)=p { if !seen || !p.destroyed || p.released { self.session_fail(&mut r,SessionRejection::GtkReleaseState); return; } p.released=true; return; }
        }
        if self.case != Case::Outstanding && (1..=2).contains(&id) {
            let p = &mut r.pickers[(id - 1) as usize];
            if !seen || !p.destroyed || p.released { self.fail(); return; }
            p.released = true; return;
        }
        if self.case == Case::ProjectPaths && (3..=13).contains(&id) {
            let p = &mut r.paths.operations[(id-3) as usize].picker;
            if !seen || !p.destroyed || p.released { self.path_fail(&mut r,PathRejection::GtkReleaseState); return; }
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
        if self.failed.load(Ordering::SeqCst) { r.failure_quit.observe_relay(joined); }
        if !joined || !r.released || !r.gtk_returned || r.relay_joined { self.fail(); return; }
        r.relay_joined = true;
    }
    pub(super) fn actual_exit(&self, ready: bool, document: &crate::asset_session::DocumentBinding, edits: &EditOwner) {
        // The relay may have stopped before its last publication. Read only the
        // SAME already-retired original ledger facts; never start cleanup here.
        if self.case == Case::Positive {
            match edits.status() { Ok(status) => self.edit_status(&status, edits), Err(_) => self.fail() }
        }
        if self.case == Case::WorkflowApply {
            match edits.status() { Ok(status) => self.edit_status(&status, edits), Err(_) => self.fail() }
            match edits.workflow_status() { Ok(status) => self.workflow_status(&status, edits), Err(_) => self.fail() }
        }
        if self.case == Case::MetadataSave {
            match edits.status() { Ok(status) => self.edit_status(&status, edits), Err(_) => self.fail() }
            match edits.metadata_text_status() { Ok(status) => self.metadata_edit_status(&status, edits), Err(_) => self.fail() }
        }
        if self.case == Case::VersionSave {
            match edits.status() { Ok(status) => self.edit_status(&status, edits), Err(_) => self.fail() }
            match edits.release_version_status() { Ok(status) => self.version_edit_status(&status, edits), Err(_) => self.fail() }
        }
        let originals_final = if self.case == Case::Outstanding { true } else {
            let Some(r) = self.record_at(Boundary::Exit) else { return; };
            if self.case == Case::ProjectPaths { r.paths.complete() && r.project_witness.as_ref().is_some_and(|project| document.installed_observation_paths_final(project)) }
            else if matches!(self.case,Case::WorkflowApply | Case::MetadataSave | Case::VersionSave | Case::Commands(_)) { r.project_witness.is_some()
                && self.commands.as_ref().is_none_or(|c| c.complete()) && document.installed_observation_final() }
            else if let Some(case) = self.case.session() { self.session_behavior_complete(&r)
                && r.project_witness.as_ref().is_some_and(|project| document.installed_session_final(project,case == SessionCase::Loss)) }
            else { r.candidate.complete() && r.project_witness.as_ref().is_some_and(|project| document.installed_observation_candidate_final(project)) }
        };
        let Some(mut r) = self.record_at(Boundary::Exit) else { return; };
        if self.failed.load(Ordering::SeqCst) { r.failure_quit.observe_loop_exit(ready); }
        if !ready || !originals_final || !r.relay_joined || !r.released || r.exit
            || self.case == Case::Positive && (r.sessions.len() != 2 || !r.sessions.iter().all(|session| session.finality.is_some()))
            || self.case == Case::WorkflowApply && !r.workflow.complete()
            || self.case == Case::MetadataSave && !r.metadata.complete()
            || self.case == Case::VersionSave && !r.version.complete() { self.fail(); return; }
        if let Some(case) = self.case.session() {
            if r.session.queries.is_some() { self.fail(); return; }
            match document.take_installed_session_queries() {
                Ok(queries) if queries.count() == case.assessments() => r.session.queries = Some(queries),
                Ok(queries) => { r.session.queries = Some(queries); self.fail(); return; },
                Err(_) => { self.fail(); return; },
            }
        }
        r.originals_final = originals_final; r.exit = true;
    }
    fn finish(&self) -> bool {
        let (held, queries) = match self.record() {
            Some(mut r) if r.exit && r.originals_final => (r.held.take(),r.session.queries.take()), _ => return false,
        };
        let session_retired = if let Some(mut queries) = queries {
            let retired = self.case.session().is_some_and(|case| queries.count() == case.assessments())
                && tauri::async_runtime::block_on(queries.observe_retired(self.end));
            let Some(mut r) = self.record() else { return false; };
            // Retain consumed/failed originals on failure, never repoll them or
            // replace their owner. Success also retains their final DATA here.
            r.session.queries = Some(queries); r.session.r1_final = retired; retired
        } else { self.case.session().is_none() };
        let retired = match (self.case, held) {
            (Case::Positive | Case::ProjectPaths | Case::WorkflowApply | Case::Session(_) | Case::MetadataSave | Case::VersionSave | Case::Commands(_), None) => true,
            (Case::Outstanding, Some(mut held)) => {
                // Borrow/join the same original after the NORMAL event loop
                // exits. No additional task, shutdown call, or replacement
                // settlement flag. The once-captured observation end is reused.
                tauri::async_runtime::block_on(held.observe_retired(self.end)).is_ok()
            },
            _ => false,
        };
        let Some(r) = self.record() else { return false; };
        retired && session_retired && !self.failed.load(Ordering::SeqCst) && Instant::now() < self.end && r.attached && r.loaded
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
                && r.project_witness.is_some() && r.candidate.complete() && r.originals_final
                || self.case == Case::WorkflowApply && r.info && r.catalog && r.environment
                && r.cancelled && r.pickers[0].settled(false) && r.selected && r.pickers[1].settled(true)
                && r.snapshot && r.snapshot_visible && r.snapshot_requests == 1 && r.suggested.is_some()
                && r.provenance_visible && r.adopted && r.draft_visible && r.guidance.complete()
                && r.capability && r.requests == [0; 4] && r.sessions.is_empty() && !r.open_pending && r.prepare_pending.is_none()
                && r.workflow.complete() && r.project_witness.is_some() && r.originals_final
                || self.case == Case::MetadataSave && r.info && r.catalog && r.environment
                && r.cancelled && r.pickers[0].settled(false) && r.selected && r.pickers[1].settled(true)
                && r.snapshot && r.snapshot_visible && r.snapshot_requests == 1 && r.metadata.complete()
                && r.requests == [0;4] && r.sessions.is_empty() && !r.open_pending && r.prepare_pending.is_none()
                && r.workflow.requests == [0;4] && r.workflow.sessions.is_empty() && r.project_witness.is_some() && r.originals_final
                || self.case == Case::VersionSave && r.info && r.catalog && r.environment
                && r.cancelled && r.pickers[0].settled(false) && r.selected && r.pickers[1].settled(true)
                && r.snapshot && r.snapshot_visible && r.snapshot_requests == 1 && r.version.complete()
                && r.requests == [0;4] && r.sessions.is_empty() && !r.open_pending && r.prepare_pending.is_none()
                && r.workflow.requests == [0;4] && r.workflow.sessions.is_empty() && r.metadata.requests == [0;4]
                && r.metadata.sessions.is_empty() && r.project_witness.is_some() && r.originals_final
                || self.case.session().is_some() && r.info && r.catalog && !r.environment
                && r.cancelled && r.pickers[0].settled(false) && r.selected && r.pickers[1].settled(true)
                && r.snapshot && r.snapshot_visible && r.snapshot_requests == 1 && r.project_witness.is_some()
                && r.requests == [0;4] && r.sessions.is_empty() && !r.open_pending && r.prepare_pending.is_none()
                && self.session_behavior_complete(&r) && r.originals_final && r.session.r1_final
                || self.commands.as_ref().is_some_and(|c| c.complete()) && r.info && r.catalog && !r.environment
                && r.cancelled && r.pickers[0].settled(false) && r.selected && r.pickers[1].settled(true)
                && r.snapshot && r.snapshot_visible && r.snapshot_requests == 1 && r.project_witness.is_some()
                && r.requests == [0;4] && r.sessions.is_empty() && !r.open_pending && r.prepare_pending.is_none()
                && r.workflow.requests == [0;4] && r.workflow.sessions.is_empty() && r.originals_final)
    }

    fn version_report(&self) -> Option<Vec<u8>> {
        let r = self.record()?;
        if self.case != Case::VersionSave || !r.exit || !r.originals_final || !r.version.complete() { return None; }
        let v = &r.version; let fixture = v.fixture.as_ref()?;
        let finals: Vec<_> = v.sessions.iter().filter_map(|s|s.finality.as_ref()).collect();
        if finals.len() != 3 { return None; }
        let count = |test: fn(&InstalledVersionFinality)->bool| finals.iter().filter(|facts|test(facts)).count();
        let sessions = |test: fn(&VersionSession)->bool| v.sessions.iter().filter(|session|test(session)).count();
        let outcomes: Option<Vec<_>> = v.sessions.iter().map(|s|s.projection.core_outcome.as_ref()
            .map(|core|serde_json::json!([core.effect,core.journal,core.resources,core.reason]))).collect();
        let actions: Option<Vec<_>> = v.sessions.iter().map(|s|s.projection.prepared.as_ref().map(|p|p.view.file.action)).collect();
        let bindings: Option<Vec<_>> = v.sessions.iter().map(|s|s.binding).collect();
        let modes: Option<Vec<_>> = v.sessions.iter().map(|s|s.source_final.map(|f|f[2] & 0o7777)).collect();
        let prepared: Option<Vec<_>> = v.sessions.iter().map(|s|s.projection.prepared.as_ref()).collect();
        let prepared = prepared?;
        let distinct_originals = v.sessions.iter().enumerate().all(|(i,s)|
            v.sessions[..i].iter().all(|prior|prior.projection.session_id != s.projection.session_id));
        let distinct_plans = prepared.iter().enumerate().all(|(i,p)|prepared[..i].iter().all(|prior|prior.plan_token != p.plan_token));
        let plan_matched = v.observations.iter().zip(prepared.iter()).filter(|(o,p)|
            o.pair_matched && o.name == p.view.values.name && o.build.to_string() == p.view.values.build).count();
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion":1,"fixture":"release-version-save-v1","gate":"installed-version-profile",
            "project":{"cancelSettled":r.cancelled && r.pickers[0].settled(false),
                "registered":r.selected && r.pickers[1].settled(true) && r.project_witness.is_some(),"snapshot":r.snapshot && r.snapshot_visible},
            "requests":{"observe":v.observe_requests,"open":v.requests[0],"prepare":v.requests[1],"apply":v.requests[2],"close":v.requests[3],
                "configuration":r.requests,"workflow":r.workflow.requests,"metadata":r.metadata.requests},
            "draft":{"bindings":bindings?,"wholeMatched":v.sessions.iter().enumerate().all(|(i,s)|s.binding == VERSION_BINDINGS.get(i).copied()),
                "browserEdit":"insertText"},
            "reviews":{"fullText":sessions(|s|s.review_visible),"actions":actions?,"distinctOriginals":distinct_originals,
                "distinctPlans":distinct_plans,"configBlocked":sessions(|s|s.config_blocked)},
            "confirmation":{"opened":sessions(|s|s.confirmation_opened),"initiallyDisabled":sessions(|s|s.initially_disabled),
                "checkboxOnlyDisabled":sessions(|s|s.checkbox_only_disabled),"typedSave":sessions(|s|s.typed_save),"acknowledged":sessions(|s|s.acknowledged)},
            "outcomes":outcomes?,"nativeReasons":v.sessions.iter().map(|s|s.projection.native_reason).collect::<Vec<_>>(),
            "originals":{"sessions":finals.len(),"writerFrames":finals.iter().map(|f|f.writer_frames).collect::<Vec<_>>(),
                "stdoutFrames":finals.iter().map(|f|f.stdout_frames).collect::<Vec<_>>(),
                "startupJoined":count(|f|f.inspection_joined && f.acquisition_joined),"childWaited":count(|f|f.child_waited_success),
                "ioSettled":count(|f|f.stdin_closed && f.stdout_eof_closed && f.stderr_eof_closed && f.io_joined),
                "ownersJoined":count(|f|f.driver_joined && f.watchdog_joined && f.manager_joined),
                "runtimeLedgerSettled":count(|f|f.runtime_ledger_settled),"runtimeSettlementJoined":count(|f|f.runtime_settlement_joined)},
            "readback":{"values":v.observations.iter().map(|o|serde_json::json!([o.name,o.build])).collect::<Vec<_>>(),
                "planMatched":plan_matched,"savedBaseline":sessions(|s|s.saved_visible),"originalObservations":v.observations.len()},
            "filesystem":{"preservedFiles":fixture.originals[2..].len(),"parents":fixture.originals[..2].len(),"afterModes":modes?,
                "replaceIdentityChanged":v.sessions[1].source_final.is_some_and(|s|v.sessions[0].source_final.is_some_and(|old|s[..2] != old[..2])),
                "preserveFull9":v.sessions[2].source_final == v.sessions[1].source_final},
            "quit":{"operation":r.native_id?,"gtkSettled":r.native_id == Some(3) && r.gtk_returned && r.destroyed && r.released,
                "originalsSettled":r.originals_final,"relayJoined":r.relay_joined,"exit":r.exit},
            "domain":version::DOMAIN,"nativeFinality":v.sessions.iter().map(|s|s.projection.native_finality).collect::<Vec<_>>(),
            "lateSettled":v.sessions.iter().map(|s|s.projection.late_settled).collect::<Vec<_>>()
        })).ok().filter(|raw|raw.len()+1 <= 2048)
    }

    fn metadata_report(&self) -> Option<Vec<u8>> {
        let r = self.record()?;
        if self.case != Case::MetadataSave || !r.exit || !r.originals_final || !r.metadata.complete() { return None; }
        let m = &r.metadata;
        let finals: Vec<_> = m.sessions.iter().filter_map(|s|s.finality.as_ref()).collect();
        if finals.len() != 2 { return None; }
        let count = |test: fn(&InstalledMetadataFinality)->bool| finals.iter().filter(|facts|test(facts)).count();
        let outcomes: Option<Vec<_>> = m.sessions.iter().map(|s|s.projection.core_outcome.as_ref()
            .map(|core|serde_json::json!([core.effect,core.journal,core.resources,core.reason]))).collect();
        let prepared = m.sessions[1].projection.prepared.as_ref()?;
        let actions: Vec<_> = [metadata::Action::Create,metadata::Action::Replace,metadata::Action::Preserve].iter()
            .map(|action|prepared.view.files.iter().filter(|file|file.action == *action).count()).collect();
        let (revision,baseline_generation) = m.sessions[1].binding?;
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion":1,"fixture":"android-metadata-save-v1","gate":"installed-metadata-profile",
            "project":{"cancelSettled":r.cancelled && r.pickers[0].settled(false),
                "registered":r.selected && r.pickers[1].settled(true) && r.project_witness.is_some(),"snapshot":r.snapshot && r.snapshot_visible},
            "requests":{"observe":m.observe_requests,"validate":u8::from(m.validation_requested),
                "open":m.requests[0],"prepare":m.requests[1],"apply":m.requests[2],"close":m.requests[3],
                "configuration":r.requests,"workflow":r.workflow.requests},
            "draft":{"revision":revision,"baselineGeneration":baseline_generation,
                "wholeMatched":m.sessions.iter().all(|s|s.binding == Some((revision,baseline_generation))),
                "retainedAfterClose":m.retained_after_close,"browserEdit":"insertText"},
            "reviews":{"fullText":m.sessions.iter().filter(|s|s.review_visible).count(),"actions":actions,
                "distinctOriginals":m.sessions[0].projection.session_id != m.sessions[1].projection.session_id,
                "configBlocked":m.sessions.iter().filter(|s|s.config_blocked).count()},
            "confirmation":{"opened":m.confirmation_opened,"initiallyDisabled":m.initially_disabled,
                "checkboxOnlyDisabled":m.checkbox_only_disabled,"typedSave":m.typed_save,"acknowledged":m.acknowledged},
            "outcomes":outcomes?,"nativeReasons":m.sessions.iter().map(|s|s.projection.native_reason).collect::<Vec<_>>(),
            "originals":{"sessions":finals.len(),"writerFrames":finals.iter().map(|f|f.writer_frames).collect::<Vec<_>>(),
                "stdoutFrames":finals.iter().map(|f|f.stdout_frames).collect::<Vec<_>>(),
                "startupJoined":count(|f|f.inspection_joined && f.acquisition_joined),"childWaited":count(|f|f.child_waited_success),
                "ioSettled":count(|f|f.stdin_closed && f.stdout_eof_closed && f.stderr_eof_closed && f.io_joined),
                "ownersJoined":count(|f|f.driver_joined && f.watchdog_joined && f.manager_joined),
                "runtimeLedgerSettled":count(|f|f.runtime_ledger_settled),"runtimeSettlementJoined":count(|f|f.runtime_settlement_joined)},
            "readback":{"planMatched":m.readback_visible,"savedBaseline":m.saved_visible,"originalObservation":m.observations.len() == 2 && !m.observe_pending},
            "quit":{"operation":r.native_id?,"gtkSettled":r.native_id == Some(3) && r.gtk_returned && r.destroyed && r.released,
                "originalsSettled":r.originals_final,"relayJoined":r.relay_joined,"exit":r.exit}
        })).ok().filter(|raw|raw.len()+1 <= 2048)
    }
    fn report_session_queries(&self) -> std::io::Result<()> {
        let mut r = self.record().ok_or_else(|| std::io::Error::other("session originals unavailable"))?;
        if self.failed.load(Ordering::SeqCst) || Instant::now() >= self.end || !r.exit || !r.originals_final
            || !r.session.r1_final || !self.session_behavior_complete(&r)
            || !r.session.queries.as_mut().is_some_and(|queries| queries.report_retired()) {
            return Err(std::io::Error::other("session originals unconfirmed"));
        }
        Ok(())
    }
    fn session_report(&self) -> Option<Vec<u8>> {
        let case = self.case.session()?; let r = self.record()?; let s = &r.session;
        if !r.exit || !r.originals_final || !s.r1_final || !self.session_behavior_complete(&r) { return None; }
        let behavior = match case {
            SessionCase::Inputs => serde_json::json!({
                "kinds":["android-keystore","android-firebase","google-wif","project-read-token"],
                "assessments":s.assessed,"fileChoosers":s.files.len(),"capturedFiles":s.captures,"kept":s.kept,"assigned":s.assigned,
                "reassessedWithoutRecapture":s.reassessed,"contextRevoked":s.context_revoked,"replacementSameIdNextRevision":s.replaced,
                "removed":s.removed,"quitCancelPreserved":s.quit_preserved,
            }),
            SessionCase::Refusals => serde_json::json!({
                "assessments":s.assessed,"fileChoosers":s.files.len(),"capturesClosed":s.captures_closed,"sourceRefusals":s.refused,
                "missingCompanionRefused":s.missing,"firebaseMismatchRefused":s.mismatch,"staleKeepRefused":s.stale_keep,
                "staleAssignRefused":s.stale_assign,"cancelledReplacementPreservedBytes":s.cancel_preserved,
                "cancelledReplacementRevokedAssignment":s.cancel_revoked,"discardReopenEmpty":s.reopened,
            }),
            SessionCase::Loss => serde_json::json!({
                "assessments":s.assessed,"fileChoosers":s.files.len(),"navigationDenied":s.navigation == 2,"lostStatusRedacted":s.loss_rendered,
                "oldCallbacksRefused":s.loss,"noRebind":s.loss,"noLateSuccess":s.loss && s.r1_final,
                "lossHoldReleasedByOriginalStop":s.loss && s.r1_final,
            }),
            SessionCase::Deadline => serde_json::json!({
                "assessments":s.assessed,"fileChoosers":s.files.len(),"originalDeadline":s.deadline,"firstCleanupPreserved":s.cleanup.is_some() && s.deadline,
                "noPreview":s.deadline,"queryResult":"query_timeout","assetReason":"deadline",
            }),
        };
        serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"case":case.name(),"profile":"installed-linux-session-inputs",
            "methods":"thirteen-passive-including-supplied-input-assessment",
            "project":{"cancelSettled":r.cancelled && r.pickers[0].settled(false),"selectedSettled":r.selected && r.pickers[1].settled(true),"snapshotMatched":r.snapshot && r.snapshot_visible},
            "safety":{"persistentStorage":false,"storeContacted":false,"signingVerified":false,"releaseReady":false},
            "originals":{"assetJoined":r.originals_final,"sourceClosed":r.originals_final,"r1Joined":s.r1_final,
                "guiSettled":r.destroyed && r.released && r.gtk_returned && s.files.iter().all(|f| f.picker.settled(f.select)),"relayJoined":r.relay_joined,"exit":r.exit},
            "behavior":behavior})).ok().filter(|raw| raw.len() + 1 <= 2048)
    }
    fn workflow_report(&self) -> Option<Vec<u8>> {
        let r = self.record()?;
        if self.case != Case::WorkflowApply || !r.exit || !r.originals_final || !r.workflow.complete() { return None; }
        let w = &r.workflow;
        let finals: Vec<_> = w.sessions.iter().filter_map(|s| s.finality.as_ref()).collect();
        if finals.len() != 4 { return None; }
        let count = |test: fn(&InstalledWorkflowFinality) -> bool| finals.iter().filter(|facts| test(facts)).count();
        let outcomes: Option<Vec<_>> = w.sessions.iter().map(|s| s.projection.core_outcome.as_ref()
            .map(|core| serde_json::json!([core.effect,core.journal,core.resources,core.reason]))).collect();
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion":1,"fixture":"android-workflow-apply-v1","gate":"installed-workflow-profile",
            "project":{"cancelSettled":r.cancelled && r.pickers[0].settled(false),"registered":r.selected && r.pickers[1].settled(true) && r.project_witness.is_some(),
                "snapshot":r.snapshot && r.snapshot_visible,"adopted":r.adopted && r.provenance_visible},
            "requests":{"open":w.requests[0],"prepare":w.requests[1],"apply":w.requests[2],"close":w.requests[3],"configuration":r.requests},
            "draft":{"wholeMatched":w.sessions.iter().all(|s| s.binding == Some((1,1))),"revision":1,"baselineGeneration":1,
                "unsavedReads":w.draft_reads,"neverSaved":r.sessions.is_empty() && r.requests == [0;4]},
            "pins":{"explicit":r.guidance.inputs_visible,"changed":w.pin_changed,"restored":w.pin_restored,"browserEdit":"insertText"},
            "reviews":{"fullText":w.sessions.iter().enumerate().all(|(i,s)| s.review_visible == (i!=1)),
                "conflictNoToken":w.sessions[1].result_visible && w.sessions[1].projection.prepared.is_none() && w.sessions[1].conflict.is_some(),
                "conflictReason":w.sessions[1].projection.conflict.as_ref()?.reason,
                "configBlocked":w.sessions.iter().filter(|s| s.config_blocked).count()},
            "confirmation":{"opened":w.sessions.iter().map(|s|s.confirmation_opened).collect::<Vec<_>>(),
                "keepReviewing":w.sessions[0].kept_reviewing,"acknowledged":w.sessions.iter().filter(|s|s.acknowledged).count()},
            "outcomes":outcomes?,"nativeReasons":w.sessions.iter().map(|s|s.projection.native_reason).collect::<Vec<_>>(),
            "originals":{"sessions":finals.len(),"writerFrames":finals.iter().map(|f|f.writer_frames).collect::<Vec<_>>(),
                "stdoutFrames":finals.iter().map(|f|f.stdout_frames).collect::<Vec<_>>(),
                "startupJoined":count(|f|f.inspection_joined && f.acquisition_joined),"childWaited":count(|f|f.child_waited_success),
                "ioSettled":count(|f|f.stdin_closed && f.stdout_eof_closed && f.stderr_eof_closed && f.io_joined),
                "ownersJoined":count(|f|f.driver_joined && f.watchdog_joined && f.manager_joined),
                "runtimeLedgerSettled":count(|f|f.runtime_ledger_settled),"runtimeSettlementJoined":count(|f|f.runtime_settlement_joined)},
            "quit":{"operation":3,"pendingReview":w.outstanding,"gtkSettled":r.native_id == Some(3) && r.gtk_returned && r.destroyed && r.released,
                "originalsSettled":r.originals_final,"relayJoined":r.relay_joined,"exit":r.exit}
        })).ok().filter(|raw| raw.len() + 1 <= 2048)
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

// Fixed synchronous session expressions use the separately reviewed standard
// select change stimulus. The old recipes below remain button/insertText-only.
// No injected DTO, controller/invoke call, async Promise, substitute reply,
// alternate bootstrap or review owner exists on either path.

impl Observation {
    fn session_action(&self, step: Step) -> Option<(u8,SA)> {
        let (index, action) = match step { Step::Session(SessionStep::Run(i,a) | SessionStep::Read(i,a)) => (i,a),
            Step::Session(SessionStep::SetFile(i) | SessionStep::ActivateFile(i) | SessionStep::Capture(i)) => (i,*self.case.session()?.recipe().get(usize::from(i))?), _ => return None };
        (self.case.session()?.recipe().get(usize::from(index)) == Some(&action)).then_some((index,action))
    }
    fn session_next(&self, r: &mut Record, index: u8) {
        let Some(case) = self.case.session() else { self.fail(); return; };
        if r.session.recipe_done != usize::from(index) { self.fail(); return; }
        r.session.recipe_done += 1; r.session.before = None; r.session.sampled = None;
        r.step = match case.recipe().get(r.session.recipe_done) {
            Some(action) => Step::Session(SessionStep::Run(index + 1,*action)), None => Step::Session(SessionStep::Finality),
        };
    }
    pub(super) fn session_request(&self, command: SessionCommand) {
        if command == SessionCommand::Status { return; }
        let Some(mut r) = self.record_at(Boundary::Request) else { return; };
        let expected = self.session_action(r.step).is_some_and(|(_,action)| session_action_command(action) == Some(command)
            || action == SA::Open && command == SessionCommand::Context
            || action == SA::Stale("save") && command == SessionCommand::Commit
            || action == SA::Stale("bind") && command == SessionCommand::Bind)
            || self.case == Case::Session(SessionCase::Loss) && r.step == Step::Session(SessionStep::Loss) && command == SessionCommand::Discard;
        let index = command.index();
        if self.case.session().is_none() || !r.session.admitted || !expected || r.session.requests[index] == u8::MAX
            || r.session.requests[index] != r.session.returns[index] { self.fail(); return; }
        r.session.requests[index] += 1;
    }
    pub(super) fn session_result<E: serde::Serialize>(&self, command: SessionCommand, result: &Result<crate::asset_session::AssetStatus,E>) {
        self.session_record_result(command, result, InstalledAssessmentFailure::none());
    }
    pub(super) fn session_prepare_result(&self, result: &Result<crate::asset_session::AssetStatus,crate::asset_commands::CommandError>) {
        let assessment = result.as_ref().err().map_or_else(InstalledAssessmentFailure::none, |error| error.installed_assessment_failure());
        self.session_record_result(SessionCommand::Prepare, result, assessment);
    }
    fn session_record_result<E: serde::Serialize>(&self, command: SessionCommand,
        result: &Result<crate::asset_session::AssetStatus,E>, assessment: InstalledAssessmentFailure) {
        if command == SessionCommand::Status || self.case.session().is_none() { return; }
        let Some(mut r) = self.record_at(Boundary::Result) else { return; }; let index = command.index();
        if r.session.requests[index] != r.session.returns[index].saturating_add(1) { self.fail(); return; }
        let ordinal = r.session.requests[index];
        let reply = match result {
            Ok(status) => match serde_json::to_value(status) {
                Ok(value) => SessionReply { status:Some(value),error:None,ordinal,assessment:InstalledAssessmentFailure::none() },
                Err(_) => { self.fail(); return; }
            },
            Err(error) => {
                // Both production error serializers use a fixed safe code;
                // no message, field input or exception text is retained.
                let code = serde_json::to_value(error).ok().and_then(|v| v["code"].as_str().filter(|s| s.len() <= 64 && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')).map(str::to_owned));
                let Some(code) = code else { self.fail(); return; }; SessionReply { status:None,error:Some(code),ordinal,assessment }
            }
        };
        r.session.returns[index] += 1; r.session.replies[index] = reply;
    }
    pub(super) fn session_context_input(&self, args: &crate::asset_commands::Context<'_>) {
        if self.case.session().is_none() { return; }
        let Some(r) = self.record_at(Boundary::Request) else { return; };
        let platform = match self.session_action(r.step) { Some((_,SA::Platform(platform))) => platform, _ => r.session.platform };
        use crate::asset_commands::{Platform,Stage,Purpose};
        if !r.project.as_ref().is_some_and(|p| p.id == args.project_id) || r.session.draft.as_ref() != Some(args.draft)
            || args.platform != (if platform == "android" { Platform::Android } else { Platform::Project })
            || args.stage != Stage::Candidate || args.purpose != Purpose::Full { self.fail(); }
    }
    pub(super) fn session_choose_input(&self, args: &crate::asset_commands::Choose<'_>) {
        if self.case.session().is_none() { return; }
        let Some(r) = self.record_at(Boundary::Request) else { return; };
        let Some((_,SA::Choose(_,kind,_))) = self.session_action(r.step) else { self.fail(); return; };
        let expected = r.session.replacement.as_ref().map(|(id,revision,_)| (id.as_str(),*revision));
        let actual = args.replacement.as_ref().map(|record| (record.record_id,record.expected_revision));
        if args.kind.name() != kind || expected != actual || !r.session.before.as_ref().is_some_and(|before|
            before.status["context"]["revision"].as_u64() == Some(u64::from(args.context_revision))) { self.fail(); }
    }
    pub(super) fn session_prepare_input(&self, args: &crate::asset_commands::Prepare<'_>) {
        if self.case.session().is_none() { return; }
        let Some(r) = self.record_at(Boundary::Request) else { return; };
        let Some(before) = r.session.before.as_ref() else { self.fail(); return; };
        use crate::asset_commands::Source;
        let valid = match (self.session_action(r.step), &args.source) {
            (Some((_,SA::Prepare(kind,_))), Source::Selection(token)) => ["android-keystore","android-firebase"].contains(&kind)
                && before.status["operation"]["selectionToken"].as_str() == Some(*token),
            (Some((_,SA::Prepare(kind,_))), Source::Scalar { kind: actual, replacement }) => actual.name() == kind
                && replacement.as_ref().map(|record| (record.record_id,record.expected_revision)) == r.session.replacement.as_ref().map(|(id,revision,_)| (id.as_str(),*revision)),
            (Some((_,SA::Reassess(index,kind))), Source::Record(record)) => before.status["records"].get(usize::from(index)).is_some_and(|value|
                value["kind"].as_str() == Some(kind) && value["recordId"].as_str() == Some(record.record_id)
                    && value["revision"].as_u64() == Some(u64::from(record.expected_revision))),
            _ => false,
        };
        if !valid || before.status["context"]["revision"].as_u64() != Some(u64::from(args.context_revision)) { self.fail(); }
    }
    pub(super) fn session_confirmation_input(&self, token: &str, bind: bool) {
        if self.case.session().is_none() { return; }
        let Some(r) = self.record_at(Boundary::Request) else { return; };
        let stale = self.session_action(r.step).is_some_and(|(_,a)| matches!(a,SA::Stale(_)));
        let original = if stale { r.session.remembered.as_ref() } else { r.session.before.as_ref() };
        if !original.is_some_and(|before| before.status["operation"]["preview"]["token"].as_str() == Some(token)
            && (before.status["operation"]["preview"]["action"] == "bind") == bind) { self.fail(); }
    }
    fn session_snapshot_result(&self, project_id: &str, result: &Result<Value,BridgeError>) {
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        if let Err(rejection) = session_snapshot_check(r.project.as_ref(), project_id, result, r.snapshot_requests, r.snapshot, r.step) {
            let next = SnapshotDiagnostic { step: r.step, rejection };
            let Record { trace, snapshot_diagnostic, .. } = &mut *r;
            latch_snapshot_diagnostic(&self.failed, trace, snapshot_diagnostic, next); return;
        }
        r.session.draft = result.as_ref().ok().and_then(|v| v["config"].get("data")).cloned(); r.snapshot = true;
    }
    pub(super) fn navigation(&self, trusted: bool, allowed: bool) {
        if self.case.session().is_none() { return; }
        let Some(mut r) = self.record_at(Boundary::Result) else { return; };
        let valid = if r.session.navigation == 0 { trusted && allowed && !r.started }
            else { self.case == Case::Session(SessionCase::Loss) && r.session.navigation == 1 && trusted && !allowed
                && matches!(r.step,Step::Session(SessionStep::Reload | SessionStep::Loss)) };
        if !valid { self.fail(); return; } r.session.navigation += 1;
    }
    fn session_native_ready(&self, r: &Record, action: SA, snapshot: &InstalledSessionSnapshot) -> Result<Option<SessionWait>,SessionRefusal> {
        let s = &r.session;
        if snapshot.unknown { return Err(SessionRejection::UnknownNativeSnapshot.into()); }
        if snapshot.lost { return Err(SessionRejection::LostNativeSnapshot.into()); }
        if !snapshot.bound { return Err(SessionRejection::UnboundNativeSnapshot.into()); }
        if snapshot.status["capability"]["available"] != true {
            return Err(session_capability_rejection(snapshot.status["capability"]["reason"].as_str()).into());
        }
        for index in 1..10 {
            let extra_context = action == SA::Open && index == SessionCommand::Context.index();
            let expected = session_action_command(action).is_some_and(|command| command.index() == index) || extra_context;
            let stale = matches!(action,SA::Stale("save")) && index == SessionCommand::Commit.index()
                || matches!(action,SA::Stale("bind")) && index == SessionCommand::Bind.index();
            let delta = s.requests[index].checked_sub(s.base_requests[index]).ok_or(SessionRejection::RequestCounterUnderflow)?;
            if delta > u8::from(expected || stale) { return Err(SessionRejection::RequestCounterSurplus.into()); }
            if expected && delta == 0 { return Ok(Some(SessionWait::RequestNotSeen)); }
            if s.returns[index] < s.requests[index] { return Ok(Some(SessionWait::ReplyPending)); }
            if expected {
                if let Some(refusal) = session_reply_refusal(index, s.requests[index], s.returns[index], s.base_requests[index], &s.replies[index]) { return Err(refusal); }
            }
            if stale && delta != 0 && !matches!(s.replies[index].error.as_deref(),Some("asset_invalid_request"|"assessment_context_stale")) { return Err(SessionRejection::StaleReplyContract.into()); }
        }
        if !snapshot.settled { return Ok(Some(SessionWait::OwnerUnsettled)); }
        let op = &snapshot.status["operation"];
        let stable = match action {
            SA::Prepare(_,"save") | SA::Reassess(..) | SA::Keep | SA::ReviewRemoval(_) => op["phase"] == "preview" && op["settlement"] == "known",
            SA::Prepare(_,"missing" | "mismatch") => op["phase"] == "selected" && op["settlement"] == "known",
            SA::Choose(_,_,None) => op["phase"] == "selected" && op["settlement"] == "known",
            SA::Choose(_,_,Some(_)) | SA::Assign | SA::Remove | SA::CancelOperation | SA::ConfirmDiscard | SA::Platform(_) | SA::Open => op["phase"] == "idle" && op["settlement"] == "known",
            _ => true,
        };
        Ok((!stable).then_some(SessionWait::PhaseNotReady))
    }
    fn session_accept_action(&self, r: &mut Record, action: SA, snapshot: &InstalledSessionSnapshot) -> bool {
        let s = &mut r.session; let Some(before) = s.before.as_ref() else { return false; };
        let status = &snapshot.status; let old = &before.status; let op = &status["operation"];
        let unchanged = snapshot.same_payloads(before);
        let unassigned = |value: &Value| value["assignments"].as_array().is_some_and(|rows| rows.iter().all(|a| a["availability"] == "unavailable"));
        let ctx = &status["context"];
        let context = ctx["platform"].as_str() == Some(s.platform) && ctx["stage"] == "candidate" && ctx["purpose"] == "full"
            && r.project.as_ref().is_some_and(|p| ctx["projectId"].as_str() == Some(p.id.as_str()));
        match action {
            SA::Open => {
                if old["mode"] != "closed" || status["mode"] != "session" || !context || !status["records"].as_array().is_some_and(Vec::is_empty)
                    || !status["assignments"].as_array().is_some_and(Vec::is_empty) { return false; }
                if s.requests[SessionCommand::Open.index()] == 2 { if !before.empty { return false; } s.reopened = true; }
            },
            SA::Kind(kind) => { if !unchanged || old["context"] != status["context"] { return false; } s.kind=kind; s.replacement=None; },
            SA::Platform(platform) => {
                if !unchanged || ctx["platform"].as_str() != Some(platform) || ctx["stage"] != "candidate" || ctx["purpose"] != "full"
                    || ctx["revision"].as_u64() != old["context"]["revision"].as_u64().and_then(|n| n.checked_add(1))
                    || !unassigned(status) || !op["preview"].is_null() || !op["selectionToken"].is_null() { return false; }
                if old["assignments"].as_array().is_some_and(|rows| rows.iter().any(|a| a["availability"] == "available")) { s.context_revoked=true; }
                s.platform=platform; s.replacement=None;
            },
            SA::Replacement(index) => {
                let Some(original) = before.payloads.get(usize::from(index)) else { return false; };
                if !unchanged || old["records"][usize::from(index)]["kind"].as_str() != Some(s.kind) { return false; }
                s.replacement=Some(original.clone());
            },
            SA::Choose(file,kind,refusal) => {
                let Some(file_op) = s.files.last() else { return false; };
                if !context || !unchanged || !file_op.picker.settled(!file.is_empty()) || file_op.kind != kind
                    || op["operation"] != "choose-file" || op["operationId"].as_u64() != Some(u64::from(file_op.id)) { return false; }
                let Some((_,facts)) = snapshot.sources.iter().find(|(id,_)| *id == file_op.id) else { return false; };
                if file.is_empty() {
                    if facts.begun || facts.originals != 0 || facts.closes != 0 || facts.reads != 0 || facts.eof { return false; }
                } else {
                    if !facts.begun || !facts.settled || facts.closes == 0 || facts.closes + facts.no_handle != facts.originals { return false; }
                    s.captures_closed += 1;
                }
                if let Some(reason) = refusal {
                    if op["reason"].as_str() != Some(reason) || !op["selectionToken"].is_null() || !op["preview"].is_null() { return false; }
                    if reason == "source-changed" && (!facts.eof || facts.bytes != 12 || !facts.terminal_checked || facts.terminal_matched
                        || !s.fixture.as_ref().is_some_and(SessionFixture::changed)) { return false; }
                    if reason != "user-cancelled" { s.refused.push(reason); }
                    else {
                        let Some(original) = s.replacement.as_ref() else { return false; };
                        if !snapshot.payloads.contains(original) || !unassigned(status) { return false; }
                        s.cancel_preserved=true; s.cancel_revoked=true;
                    }
                } else {
                    if op["reason"] != "none" || op["source"] != "captured" || !op["selectionToken"].as_str().is_some_and(|t| t.len()==32)
                        || !facts.eof || facts.reads < 2 || !facts.terminal_checked || !facts.terminal_matched
                        || facts.bytes != (if kind == "android-keystore" { 12 } else if file == "firebase-mismatch.json" { 93 } else { 95 }) { return false; }
                    s.captures += 1;
                }
                if let Some((id,revision,_)) = &s.replacement {
                    let admitted = &s.replies[SessionCommand::Choose.index()].status;
                    if !admitted.as_ref().is_some_and(|reply| reply["records"].as_array().is_some_and(|rows| rows.iter().any(|record|
                        record["recordId"].as_str()==Some(id) && record["revision"].as_u64()==Some(u64::from(*revision)) && record["availability"]=="mutation-pending"))
                        && reply["assignments"].as_array().is_some_and(|rows| rows.iter().filter(|a| a["recordId"].as_str()==Some(id)).all(|a| a["availability"]=="unavailable"))) { return false; }
                }
            },
            SA::Prepare(..) | SA::Reassess(..) => {
                let (kind,expected) = match action { SA::Prepare(kind,expected) => (kind,expected), SA::Reassess(_,kind) => (kind,"bind"), _ => return false };
                let assessment=&op["assessment"]; let assurance=&assessment["assurance"];
                if !context || !unchanged || op["operation"]!="prepare" || assessment["kind"].as_str()!=Some(kind)
                    || assessment["applicability"]["state"]!="required" || assessment["applicability"]["reason"]!="selected"
                    || assessment["context"] != serde_json::json!({"platform":s.platform,"stage":"candidate","purpose":"full"})
                    || assurance["basis"]!="supplied-input-only" || assurance["selectedFilesRead"]!=false || assurance["keyringAccessed"]!=false
                    || assurance["storageWritesPerformed"]!=false || assurance["projectCodeExecuted"]!=false || assurance["nativeValidation"]!="not-run"
                    || assurance["serviceValidation"]!="not-run" || assurance["releaseReadiness"]!="unknown" { return false; }
                if expected == "missing" {
                    if !op["preview"].is_null() || assessment["state"]!="missing" || !assessment["fields"].as_array().is_some_and(|fields|
                        fields.iter().filter(|f| f["id"]!="file").all(|f| f["presence"]=="missing" && f["issues"].as_array().is_some_and(|issues| issues.iter().any(|i| i=="required-missing")))) { return false; }
                    s.missing=true;
                } else if expected == "mismatch" {
                    if !op["preview"].is_null() || assessment["state"]!="invalid" || assessment["identity"]!="mismatch" { return false; } s.mismatch=true;
                } else {
                    if !["format-valid","configured"].contains(&assessment["state"].as_str().unwrap_or("")) || op["preview"]["action"].as_str()!=Some(expected)
                        || op["preview"]["subject"]["kind"].as_str()!=Some(kind) || snapshot.review_end.is_none() || snapshot.cleanup_end.is_some()
                        || snapshot.work_end.is_some() || !assessment["fields"].as_array().is_some_and(|fields| fields.iter().all(|f|
                            f["presence"]=="supplied" && f["issues"].as_array().is_some_and(Vec::is_empty))) { return false; }
                    if let SA::Reassess(index,_) = action {
                        let Some(record)=old["records"].get(usize::from(index)) else { return false; };
                        if op["preview"]["subject"]["recordId"]!=record["recordId"] || op["preview"]["subject"]["recordRevision"]!=record["revision"]
                            || snapshot.sources!=before.sources { return false; } s.reassessed=true;
                    }
                }
                s.assessed+=1;
            },
            SA::Keep => {
                let previous=&old["operation"]["preview"]; let subject=&previous["subject"];
                if previous["action"]!="save" || op["operation"]!="commit" || op["preview"]["action"]!="bind" || snapshot.review_end!=before.review_end
                    || status["context"]!=old["context"] || op["preview"]["subject"]["kind"]!=subject["kind"] { return false; }
                let id=&op["preview"]["subject"]["recordId"]; let revision=&op["preview"]["subject"]["recordRevision"];
                let Some(record)=status["records"].as_array().and_then(|rows| rows.iter().find(|r| &r["recordId"]==id)) else { return false; };
                if &record["revision"]!=revision || record["availability"]!="unassigned" || status["assignments"].as_array().is_none_or(|rows| rows.iter().any(|a| &a["recordId"]==id && a["availability"]=="available")) { return false; }
                if subject["change"]=="replace" {
                    if *id!=subject["recordId"] || revision.as_u64()!=subject["recordRevision"].as_u64().and_then(|n| n.checked_add(1))
                        || snapshot.payloads.len()!=before.payloads.len() || snapshot.same_payloads(before) { return false; } s.replaced=true;
                } else if subject["change"]!="new" || revision.as_u64()!=Some(1) || snapshot.payloads.len()!=before.payloads.len()+1 { return false; }
                s.kept+=1;
            },
            SA::Assign => {
                let subject=&old["operation"]["preview"]["subject"];
                if !context || !unchanged || old["operation"]["preview"]["action"]!="bind" || op["operation"]!="bind" || !op["preview"].is_null()
                    || !status["assignments"].as_array().is_some_and(|rows| rows.iter().any(|a| a["recordId"]==subject["recordId"]
                        && a["recordRevision"]==subject["recordRevision"] && a["kind"]==subject["kind"] && a["contextRevision"]==ctx["revision"] && a["availability"]=="available")) { return false; }
                s.assigned+=1;
            },
            SA::ReviewRemoval(index) => {
                let Some(record)=old["records"].get(usize::from(index)) else { return false; };
                if !unchanged || op["preview"]["action"]!="delete" || op["preview"]["subject"]["recordId"]!=record["recordId"]
                    || op["preview"]["subject"]["recordRevision"]!=record["revision"] { return false; }
            },
            SA::Remove => {
                let id=&old["operation"]["preview"]["subject"]["recordId"];
                if old["operation"]["preview"]["action"]!="delete" || op["operation"]!="commit" || snapshot.payloads.len()+1!=before.payloads.len()
                    || status["records"].as_array().is_none_or(|rows| rows.iter().any(|r| &r["recordId"]==id))
                    || status["assignments"].as_array().is_none_or(|rows| rows.iter().any(|a| &a["recordId"]==id)) { return false; } s.removed+=1;
            },
            SA::Remember(action) => { if old["operation"]["preview"]["action"].as_str()!=Some(action) || !snapshot.same_review(before) { return false; } s.remembered=Some(snapshot.clone()); },
            SA::Stale(action) => {
                let Some(remembered)=&s.remembered else { return false; };
                if !unchanged || !snapshot.same_payloads(remembered) || !op["preview"].is_null() || !unassigned(status)
                    || status["context"]["revision"]==remembered.status["context"]["revision"] { return false; }
                if action=="save" { s.stale_keep=true; } else if action=="bind" { s.stale_assign=true; } else { return false; }
                s.remembered=None;
            },
            SA::CancelOperation => { if !unchanged || op["reason"]!="user-cancelled" || !op["preview"].is_null() || !op["selectionToken"].is_null() { return false; } },
            SA::ConfirmDiscard => { if !snapshot.empty || !status["records"].as_array().is_some_and(Vec::is_empty) || !status["assignments"].as_array().is_some_and(Vec::is_empty) { return false; } },
            SA::Discard | SA::Fields(_) => if !unchanged { return false; },
            SA::QuitCancel | SA::Held => return false,
        }
        true
    }
}

impl Observation {
    fn session_tick(self: &Arc<Self>, app: &tauri::AppHandle, step: SessionStep) {
        let state=app.state::<super::ShellState>();
        if let SessionStep::Capture(index)=step {
            if self.case==Case::Session(SessionCase::Refusals) {
                if let Some(checkpoint)=state.document.installed_session_capture_checkpoint().filter(|c| c.reached()) {
                    let changed = {
                        let Some(mut r)=self.record_at(Boundary::Settlement) else { return; };
                        let Some(fixture)=r.session.fixture.as_mut() else { self.fail(); return; };
                        if fixture.changed() { true } else { fixture.change_source().is_ok() && checkpoint.release() }
                    };
                    if !changed { let _=checkpoint.release(); self.fail(); return; }
                }
            }
            let Some(mut r)=self.record_at(Boundary::Settlement) else { return; };
            let Some(action)=self.case.session().and_then(|c| c.recipe().get(usize::from(index))).copied() else { self.fail(); return; };
            r.step=Step::Session(SessionStep::Read(index,action));
            // Leave the original source checkpoint reachable until its same
            // worker reaches EOF; the next read tick also checks it below.
        }
        let Some(snapshot)=state.document.installed_session_snapshot() else { return; };
        if snapshot.unknown {
            if let Some(mut r)=self.record() {
                self.session_fail_with_first_origin(&mut r,SessionRejection::UnknownNativeSnapshot,
                    snapshot.first_failure.unwrap_or_else(InstalledSessionFailure::not_recorded));
            } else { self.fail(); }
            return;
        }
        let step=match self.record().map(|r| r.step) { Some(Step::Session(step))=>step,_=>return };
        if matches!(step,SessionStep::Read(_,SA::Choose("changed.jks",_,_))) {
            if let Some(checkpoint)=state.document.installed_session_capture_checkpoint().filter(|c| c.reached()) {
                let changed = {
                    let Some(mut r)=self.record_at(Boundary::Settlement) else { return; };
                    let Some(fixture)=r.session.fixture.as_mut() else { self.fail(); return; };
                    if fixture.changed() { true } else { fixture.change_source().is_ok() && checkpoint.release() }
                };
                if !changed { let _=checkpoint.release(); self.fail(); return; }
            }
        }
        let Some(window)=app.get_webview_window(super::MAIN_WINDOW) else { self.fail(); return; };
        if matches!(step,SessionStep::SetFile(_) | SessionStep::ActivateFile(_)) {
            let index=match step { SessionStep::SetFile(i) | SessionStep::ActivateFile(i)=>i,_=>return };
            {
                let Some(mut r)=self.record_at(Boundary::Settlement) else { return; };
                if self.failed.load(Ordering::SeqCst) { return; }
                if r.pending.is_some() { self.session_fail(&mut r,SessionRejection::StepPendingInvariant); return; } r.pending=Some(Pending::Dom(Step::Session(step)));
                if let Some(diagnostic) = r.session.diagnostic.as_mut() { diagnostic.gtk_callbacks.reserved(); }
            }
            let q=self.clone(); let app=app.clone();
            if window.run_on_main_thread(move || {
                let result=if matches!(step,SessionStep::SetFile(_)) { super::owned_gtk::select_observed_session_file(&app,&q,index) }
                    else { super::owned_gtk::activate_observed_session_file(&app,&q,index) };
                q.session_file_returned(step,result);
            }).is_err() { self.fail(); } return;
        }
        if step==SessionStep::QuitCancel {
            {
                let Some(mut r)=self.record_at(Boundary::Settlement) else { return; };
                if self.failed.load(Ordering::SeqCst) { return; }
                if r.pending.is_some() { return; } r.pending=Some(Pending::Gtk);
            }
            let q=self.clone(); let app=app.clone();
            if window.run_on_main_thread(move || { let result=super::owned_gtk::activate_observed_quit(&app,&q); q.gtk_returned(result); }).is_err() { self.fail(); }
            return;
        }
        let script={
            let Some(mut r)=self.record_at(Boundary::Settlement) else { return; };
            if self.failed.load(Ordering::SeqCst) { return; }
            if r.pending.is_some() { return; }
            let mut presentation=SessionPresentation::Native;
            match step {
                SessionStep::Run(index,action) => {
                    if r.session.recipe_done!=usize::from(index) || self.case.session().and_then(|c| c.recipe().get(usize::from(index)))!=Some(&action) { self.session_fail(&mut r,SessionRejection::StepPendingInvariant); return; }
                    if r.session.before.is_none() { r.session.base_requests=r.session.requests; r.session.before=Some(snapshot.clone()); }
                    if action==SA::QuitCancel {
                        if !snapshot.settled || snapshot.status["operation"]["preview"]["action"]!="bind" || snapshot.review_end.is_none() { self.fail(); return; }
                        r.session.quit_review=Some(snapshot); r.step=Step::Session(SessionStep::QuitCancel); r.pending=Some(Pending::Close);
                        drop(r); if window.close().is_err() { self.fail(); } return;
                    }
                    if action==SA::Held {
                        if !snapshot.owner.as_ref().is_some_and(|owner| state.bridge.supervisor.installed_session_query_held(owner.id))
                            || snapshot.settled || snapshot.work_end.is_none() || snapshot.cleanup_end.is_some()
                            || snapshot.status["operation"]["phase"]!="assessing" || !snapshot.status["operation"]["preview"].is_null() { return; }
                        r.session.before=Some(snapshot); r.step=Step::Session(if self.case==Case::Session(SessionCase::Loss) { SessionStep::Reload } else { SessionStep::Deadline }); return;
                    }
                },
                SessionStep::Read(_,SA::Prepare(_,"held")) => {
                    if r.session.requests[SessionCommand::Prepare.index()]!=1 || r.session.returns[SessionCommand::Prepare.index()]!=0
                        || !snapshot.owner.as_ref().is_some_and(|owner| state.bridge.supervisor.installed_session_query_held(owner.id)) { return; }
                },
                SessionStep::Read(_,action) => match self.session_native_ready(&r,action,&snapshot) {
                    Ok(None)=>{},
                    Ok(Some(wait))=>{self.session_wait(&mut r,wait);return;},
                    Err(refusal)=>{self.session_fail_with_assessment(&mut r,refusal);return;},
                },
                SessionStep::QuitPreserved => {
                    if !snapshot.quit_declined || snapshot.quit_pending || !r.session.quit_cancel.settled(false) { return; }
                    if !r.session.quit_review.as_ref().is_some_and(|before| snapshot.same_review(before) && snapshot.same_payloads(before)) { self.fail(); return; }
                },
                SessionStep::Loss | SessionStep::Deadline => {
                    let Some(before)=r.session.before.as_ref() else { self.fail(); return; };
                    let original_work=before.work_end;
                    if !snapshot.owner.as_ref().zip(before.owner.as_ref()).is_some_and(|(now,old)| Arc::ptr_eq(now,old))
                        || !session_original_clock(original_work,snapshot.work_end,snapshot.settled)
                        || !snapshot.status["operation"]["preview"].is_null() { self.fail(); return; }
                    // Finish the immutable before-sample borrow without delaying cleanup recording.
                    let context_unchanged=snapshot.status["context"]==before.status["context"];
                    if let Some(cleanup)=snapshot.cleanup_end {
                        if r.session.cleanup.is_some_and(|old| old!=cleanup) { self.fail(); return; } r.session.cleanup=Some(cleanup);
                    }
                    if !snapshot.settled || r.session.returns[SessionCommand::Prepare.index()]!=1 { return; }
                    let valid=if step==SessionStep::Loss { r.session.navigation==2 && snapshot.lost && !snapshot.bound && snapshot.empty
                        && snapshot.status["context"].is_null() && snapshot.status["records"]==serde_json::json!([]) && snapshot.status["assignments"]==serde_json::json!([])
                        && snapshot.status["operation"]["selectionToken"].is_null() && snapshot.status["operation"]["assessment"].is_null()
                        && snapshot.status["operation"]["reason"]=="document-lost" }
                        else { !snapshot.lost && snapshot.bound && snapshot.status["operation"]["reason"]=="deadline"
                            && !snapshot.status["context"].is_null() && context_unchanged
                            && snapshot.status["operation"]["assessment"].is_null()
                            && snapshot.cleanup_end==original_work.and_then(|end| end.checked_add(Duration::from_secs(2))) };
                    if !valid || snapshot.cleanup_end.is_none() || r.session.replies[SessionCommand::Prepare.index()].error.as_deref()!=Some(if step==SessionStep::Loss { "asset_document_lost" } else { "asset_deadline" }) { self.fail(); return; }
                    // Select only after this same original's settled snapshot,
                    // unchanged clocks and actual own Prepare rejection match.
                    if step==SessionStep::Deadline { presentation=SessionPresentation::DeadlineError; }
                },
                SessionStep::Finality => {
                    if r.session.requests!=r.session.returns { return; }
                    if !self.session_behavior_complete(&r) || !r.session.fixture.as_ref().is_some_and(|fixture| fixture.verify().is_ok()) { self.fail(); return; }
                    if !snapshot.settled || snapshot.quit_pending { return; }
                    r.step=Step::Close; return;
                },
                SessionStep::Navigate | SessionStep::Reload => {},
                _ => { self.session_fail(&mut r,SessionRejection::StepPendingInvariant); return; },
            }
            if r.evaluations>=128 { self.session_fail(&mut r,SessionRejection::EvaluationBudget); return; }
            let replacement=if let SessionStep::Run(_,SA::Replacement(index))=step {
                let Some(record)=snapshot.status["records"].get(usize::from(index)) else { self.fail(); return; };
                Some(format!("Replace session item {} · revision {}",index+1,record["revision"].as_u64().unwrap_or(0)))
            } else { None };
            let display=session_display(&snapshot,presentation);
            let script=session_script(step,r.session.kind,r.session.platform,replacement.as_deref(),display.as_ref(),presentation);
            if script.is_none() { self.session_fail(&mut r,SessionRejection::UnavailableScript); return; }
            // Freeze the expected display with its original sample. A callback
            // must not derive presentation from a newer status or reply.
            r.session.sampled=Some(SessionSample { snapshot,presentation,display }); r.evaluations+=1; r.pending=Some(Pending::Session(step));
            if !self.failed.load(Ordering::SeqCst) {
                r.session.diagnostic=SessionDiagnostic::sample(r.step,r.evaluations,r.session.diagnostic);
            }
            script
        };
        let Some(script)=script else { self.fail(); return; }; let q=self.clone();
        if window.eval_with_callback(script,move |raw| q.dom(Step::Session(step),&raw)).is_err() {
            if let Some(mut r)=self.record() { self.session_fail(&mut r,SessionRejection::EvaluationDispatch); } else { self.fail(); }
        }
    }
    fn session_dom(&self, step: SessionStep, value: &Value) {
        let Some(mut r)=self.record_at(Boundary::Dom) else { return; };
        if r.pending.take()!=Some(Pending::Session(step)) || r.step!=Step::Session(step) { self.session_fail(&mut r,SessionRejection::StepPendingInvariant); return; }
        if value==&serde_json::json!({"state":"wait"}) {
            let wait=if matches!(step,SessionStep::Read(..) | SessionStep::QuitPreserved | SessionStep::Deadline | SessionStep::Loss) {
                SessionWait::DisplayMismatch
            } else { SessionWait::ControlsMismatch };
            self.session_wait(&mut r,wait); return;
        }
        if value["state"]!="ready" { self.session_fail(&mut r,SessionRejection::StepPendingInvariant); return; }
        let Some(SessionSample { snapshot,presentation,display })=r.session.sampled.take() else { self.session_fail(&mut r,SessionRejection::StepPendingInvariant); return; };
        if (step==SessionStep::Deadline)!=(presentation==SessionPresentation::DeadlineError) {
            self.session_fail(&mut r,SessionRejection::StepPendingInvariant); return;
        }
        match step {
            SessionStep::Navigate => {
                if !keys(value,&["state"]) { self.fail(); return; } r.step=Step::Session(SessionStep::Run(0,SA::Open));
            },
            SessionStep::Run(index,action) => {
                if !keys(value,&["state"]) { self.fail(); return; }
                if matches!(action,SA::Fields(_)) {
                    if !self.session_accept_action(&mut r,action,&snapshot) { self.fail(); return; } self.session_next(&mut r,index);
                } else if let SA::Choose(file,_,_)=action {
                    r.step=Step::Session(if file.is_empty() { SessionStep::ActivateFile(index) } else { SessionStep::SetFile(index) });
                } else { r.step=Step::Session(SessionStep::Read(index,action)); }
            },
            SessionStep::Reload => {
                if !keys(value,&["state"]) { self.fail(); return; } r.step=Step::Session(SessionStep::Loss);
            },
            SessionStep::Read(index,action) => {
                if !keys(value,&["state","display","controls"]) { self.fail(); return; }
                if display.as_ref()!=value.get("display") { self.session_wait(&mut r,SessionWait::DisplayMismatch); return; }
                let controls=&value["controls"];
                let valid=match action {
                    SA::Kind(kind) => controls["kind"].as_str()==Some(kind)
                        && controls["formNames"]==serde_json::json!(if ["android-keystore","android-firebase"].contains(&kind) { &[][..] } else { session_field_names(kind) })
                        && controls["filePrompt"].as_str()==Some(if kind=="android-keystore" { "jks" } else if kind=="android-firebase" { "firebase" } else { "none" }),
                    SA::Replacement(index) => snapshot.status["records"].get(usize::from(index)).is_some_and(|record| controls["replacement"].as_str()==Some(format!("Replace session item {} · revision {}",index+1,record["revision"].as_u64().unwrap_or(0)).as_str())),
                    SA::Platform(platform) => controls["platform"].as_str()==Some(platform),
                    SA::Discard => controls["discardConfirmation"]==true,
                    _ => true,
                };
                if !valid { self.session_wait(&mut r,SessionWait::ControlsMismatch); return; }
                if matches!(action,SA::Prepare(_,"held")) { r.session.assessed+=1; }
                else if !self.session_accept_action(&mut r,action,&snapshot) { self.fail(); return; }
                self.session_next(&mut r,index);
            },
            SessionStep::QuitPreserved => {
                if !keys(value,&["state","display","controls"]) || display.as_ref()!=value.get("display") {
                    self.session_wait(&mut r,SessionWait::DisplayMismatch); return;
                }
                r.session.quit_preserved=true; let index=r.session.recipe_done as u8; self.session_next(&mut r,index);
            },
            SessionStep::Loss | SessionStep::Deadline => {
                if !keys(value,&["state","display","controls"]) || display.as_ref()!=value.get("display") {
                    self.session_wait(&mut r,SessionWait::DisplayMismatch); return;
                }
                if step==SessionStep::Loss { r.session.loss=true; r.session.loss_rendered=true; } else { r.session.deadline=true; }
                r.session.recipe_done=self.case.session().map_or(0,|c| c.recipe().len()); r.step=Step::Session(SessionStep::Finality);
            },
            _=>self.fail(),
        }
    }
    fn session_behavior_complete(&self, r: &Record) -> bool {
        let Some(case)=self.case.session() else { return false; }; let s=&r.session;
        s.admitted && s.draft.is_some() && s.requests==s.returns && s.recipe_done==case.recipe().len() && s.assessed==case.assessments() as u8
            && s.requests[SessionCommand::Prepare.index()]==s.assessed && s.returns[SessionCommand::Prepare.index()]==s.assessed
            && s.files.iter().all(|file| file.picker.settled(file.select))
            && match case {
                SessionCase::Inputs=>s.files.len()==3 && s.captures==3 && s.captures_closed==3 && s.kept==5 && s.assigned==6 && s.removed==1
                    && s.reassessed && s.context_revoked && s.replaced && s.quit_preserved,
                SessionCase::Refusals=>s.files.len()==9 && s.captures_closed==8 && s.refused==["project-overlap","source-refused","source-refused","source-changed"]
                    && s.missing && s.mismatch && s.stale_keep && s.stale_assign && s.cancel_preserved && s.cancel_revoked && s.reopened,
                SessionCase::Loss=>s.files.len()==1 && s.captures==1 && s.loss && s.loss_rendered && s.navigation==2 && s.kept==0 && s.assigned==0
                    && s.requests[SessionCommand::Discard.index()]<=1 && (s.requests[SessionCommand::Discard.index()]==0
                        || s.replies[SessionCommand::Discard.index()].error.as_deref()==Some("asset_document_lost")),
                SessionCase::Deadline=>s.files.len()==1 && s.captures==1 && s.deadline && s.cleanup.is_some() && s.kept==0 && s.assigned==0,
            }
    }
}

impl Observation {
    pub(super) fn session_file_failed(&self, rejection: SessionRejection) {
        // Shell callers have left every DIALOG/GuiFacts borrow before entering.
        // Record-held callbacks use session_fail on their existing guard instead.
        let Some(mut r)=self.record_at(Boundary::Gtk) else { return; };
        self.session_fail(&mut r,rejection);
    }
    pub(super) fn session_file_wait(&self, index: u8, activating: bool, wait: SessionWait) {
        // Authenticate the actual pending role AND index before sampling. A late
        // SetFile callback cannot attach a wait to ActivateFile at the same index.
        let Some(mut r)=self.record() else { return; };
        if !session_file_wait_pending(r.step,r.pending,index,activating) || self.failed.load(Ordering::SeqCst) { return; }
        r.trace=(r.step,Boundary::Gtk);
        if !self.failed.load(Ordering::SeqCst) {
            if let Some(mut diagnostic) = SessionDiagnostic::sample(r.step,r.evaluations,r.session.diagnostic) {
                diagnostic.wait = wait; diagnostic.gtk_callbacks.wait_observed();
                r.session.diagnostic = Some(diagnostic);
            }
        }
    }
    pub(super) fn session_file_created(&self, id: u32, kind: crate::credential_format::FileKind) {
        let Some(mut r)=self.record_at(Boundary::Gtk) else { return; };
        let Some((index,SA::Choose(file,expected,_)))=self.session_action(r.step) else { self.fail(); return; };
        let name=match kind { crate::credential_format::FileKind::AndroidKeystore=>"android-keystore", crate::credential_format::FileKind::AndroidFirebase=>"android-firebase" };
        if name!=expected || id<=2 || r.session.files.len()>=9 || r.session.files.iter().any(|f| f.id==id || f.index==index) { self.fail(); return; }
        r.session.files.push(SessionFile {id,index,kind:expected,select:!file.is_empty(),picker:Picker {created:true,..Picker::default()}});
    }
    pub(super) fn session_file_dialog(&self, id: u32, index: u8) -> Result<(&'static str,bool),()> {
        let Some(mut r)=self.record_at(Boundary::Gtk) else { return Err(()); };
        let Some(file)=r.session.files.last().filter(|file| file.id==id && file.index==index) else {
            self.session_fail(&mut r,SessionRejection::GtkDialogRecord); return Err(());
        };
        if self.failed.load(Ordering::SeqCst) { return Err(()); }
        if Instant::now()>=self.end { self.session_fail(&mut r,SessionRejection::GtkObserverEndpoint); return Err(()); }
        if !file.picker.created || file.picker.responded || file.picker.destroyed
            || !matches!(r.pending,Some(Pending::Dom(Step::Session(SessionStep::SetFile(i) | SessionStep::ActivateFile(i)))) if i==index) {
            self.session_fail(&mut r,SessionRejection::GtkDialogRecord); return Err(());
        }
        Ok((file.kind,file.select))
    }
    pub(super) fn session_file_target(&self, index: u8) -> Option<PathBuf> {
        let SA::Choose(file,_,_)=*self.case.session()?.recipe().get(usize::from(index))? else { return None; };
        if file.is_empty() { return None; }
        let project=self.project_path()?;
        Some(if file=="overlap.jks" { project.join(file) } else { project.parent()?.join("sources").join(file) })
    }
    pub(super) fn session_file_selection(&self, id: u32, index: u8) -> Result<(),()> {
        let Some(mut r)=self.record_at(Boundary::Gtk) else { return Err(()); };
        if self.failed.load(Ordering::SeqCst) { return Err(()); }
        if Instant::now()>=self.end { self.session_fail(&mut r,SessionRejection::GtkObserverEndpoint); return Err(()); }
        if r.pending!=Some(Pending::Dom(Step::Session(SessionStep::SetFile(index)))) {
            self.session_fail(&mut r,SessionRejection::GtkSelectionState); return Err(());
        }
        let Some(file)=r.session.files.last_mut().filter(|file| file.id==id && file.index==index) else {
            self.session_fail(&mut r,SessionRejection::GtkSelectionState); return Err(());
        };
        if !file.select || file.picker.selected || file.picker.activated {
            self.session_fail(&mut r,SessionRejection::GtkSelectionState); return Err(());
        }
        file.picker.selected=true; Ok(())
    }
    pub(super) fn session_file_activation(&self, id: u32, index: u8) -> Result<(),()> {
        let Some(mut r)=self.record_at(Boundary::Gtk) else { return Err(()); };
        if self.failed.load(Ordering::SeqCst) { return Err(()); }
        if Instant::now()>=self.end { self.session_fail(&mut r,SessionRejection::GtkObserverEndpoint); return Err(()); }
        if r.pending!=Some(Pending::Dom(Step::Session(SessionStep::ActivateFile(index)))) {
            self.session_fail(&mut r,SessionRejection::GtkActivationState); return Err(());
        }
        let Some(file)=r.session.files.last_mut().filter(|file| file.id==id && file.index==index) else {
            self.session_fail(&mut r,SessionRejection::GtkActivationState); return Err(());
        };
        if file.picker.selected!=file.select || file.picker.activated {
            self.session_fail(&mut r,SessionRejection::GtkActivationState); return Err(());
        }
        file.picker.activated=true; Ok(())
    }
    pub(super) fn session_file_filename(&self, id: u32, path: Option<&Path>) {
        let Some(mut r)=self.record_at(Boundary::Gtk) else { return; };
        let Some(file)=r.session.files.last_mut().filter(|file| file.id==id) else {
            self.session_fail(&mut r,SessionRejection::GtkFilenameState); return;
        };
        if !file.select || !file.picker.activated || file.picker.filename || file.picker.responded {
            self.session_fail(&mut r,SessionRejection::GtkFilenameState); return;
        }
        if path.is_none() { self.session_fail(&mut r,SessionRejection::GtkFilenameAbsent); return; }
        if path!=self.session_file_target(file.index).as_deref() { self.session_fail(&mut r,SessionRejection::GtkFilenameDifferent); return; }
        file.picker.filename=true;
    }
    pub(super) fn session_file_response(&self, id: u32, accepted: bool, cancelled: bool, disposal: bool) {
        let Some(mut r)=self.record_at(Boundary::Gtk) else { return; };
        let Some(file)=r.session.files.last_mut().filter(|file| file.id==id) else {
            self.session_fail(&mut r,SessionRejection::GtkResponseState); return;
        }; let p=&mut file.picker;
        if !p.activated || p.destroyed || p.released { self.session_fail(&mut r,SessionRejection::GtkResponseState); return; }
        if !p.responded && !disposal && accepted==file.select && cancelled!=file.select && p.filename==file.select { p.responded=true; }
        else if p.responded && p.returned && disposal && !accepted && !cancelled && !p.disposal { p.disposal=true; }
        else { self.session_fail(&mut r,SessionRejection::GtkResponseContract); }
    }
    fn session_file_returned(&self, step: SessionStep, result: Result<bool,()>) {
        let Some(mut r)=self.record_at(Boundary::Gtk) else { return; };
        // Always preserve original pending/return bookkeeping, including after a
        // callback or helper already latched its more precise first rejection.
        if r.pending.take()!=Some(Pending::Dom(Step::Session(step))) || r.step!=Step::Session(step) {
            self.session_fail(&mut r,SessionRejection::GtkReturnRole); return;
        }
        let index=match step { SessionStep::SetFile(i) | SessionStep::ActivateFile(i)=>i,_=>{self.session_fail(&mut r,SessionRejection::GtkReturnRole);return;} };
        if !self.failed.load(Ordering::SeqCst) {
            if let Some(diagnostic) = r.session.diagnostic.as_mut() { diagnostic.gtk_callbacks.returned(); }
        }
        let Some(file)=r.session.files.last_mut().filter(|file| file.index==index) else {
            if result!=Ok(false) { self.session_fail(&mut r,SessionRejection::GtkReturnState); } return;
        };
        match result {
            Ok(false) if !file.picker.activated && (step!=SessionStep::SetFile(index) || !file.picker.selected)=>{},
            Ok(true) if step==SessionStep::SetFile(index) && file.picker.selected && !file.picker.activated=>r.step=Step::Session(SessionStep::ActivateFile(index)),
            Ok(true) if step==SessionStep::ActivateFile(index)=>{
                if !file.picker.activation_returned(result) { self.session_fail(&mut r,SessionRejection::GtkReturnState); return; } r.step=Step::Session(SessionStep::Capture(index));
            }, _=>self.session_fail(&mut r,SessionRejection::GtkReturnState),
        }
    }
    pub(super) fn quit_selects_ok(&self, id: u32) -> Result<bool,()> {
        let Some(mut r)=self.record_at(Boundary::Gtk) else { return Err(()); };
        if self.failed.load(Ordering::SeqCst) { return failure_quit(&mut r).choice(id); }
        if r.step==Step::Session(SessionStep::QuitCancel) && r.session.quit_cancel_id==Some(id) { Ok(false) }
        else if r.step==Step::Quit && r.native_id==Some(id) { Ok(true) } else { Err(()) }
    }
}

fn session_script(step: SessionStep, kind: &str, platform: &str, replacement: Option<&str>, expected_display: Option<&Value>, presentation: SessionPresentation) -> Option<String> {
    if (step==SessionStep::Deadline)!=(presentation==SessionPresentation::DeadlineError) { return None; }
    let body=match step {
        SessionStep::Navigate=>r#"const b=document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Credentials"]');
            if(!b||b.disabled)return {state:'wait'};show(b);b.click();return {state:'ready'};"#.to_owned(),
        SessionStep::Run(_,action)=>match action {
            SA::Kind(next) | SA::Platform(next)=>{
                let (label,old)=if matches!(action,SA::Kind(_)) { ("What would you like to provide?",kind) } else { ("Platform",platform) };
                let label=serde_json::to_string(label).ok()?;let old=serde_json::to_string(old).ok()?;let next=serde_json::to_string(next).ok()?;
                format!(r#"const s=select({label});if(!s||s.disabled)return {{state:'wait'}};if(s.options[s.selectedIndex]?.value!=={old})throw 0;
                    const indices=[...s.options].flatMap((o,i)=>o.value==={next}?[i]:[]);if(indices.length!==1||s.options[indices[0]].disabled)throw 0;
                    show(s);s.focus();s.selectedIndex=indices[0];s.dispatchEvent(new Event('change',{{bubbles:true}}));return {{state:'ready'}};"#)
            },
            SA::Replacement(_)=>{
                let label=serde_json::to_string(replacement?).ok()?;
                format!(r#"const s=select('New or replacement copy?');if(!s||s.disabled)return {{state:'wait'}};if(s.selectedIndex!==0)throw 0;
                    const matches=[...s.options].flatMap((o,i)=>text(o)==={label}?[i]:[]);if(matches.length!==1||matches[0]===0||s.options[matches[0]].disabled)throw 0;
                    show(s);s.focus();s.selectedIndex=matches[0];s.dispatchEvent(new Event('change',{{bubbles:true}}));return {{state:'ready'}};"#)
            },
            SA::Fields(kind)=>{
                let fields: &[(&str,&str)]=match kind {
                    "android-keystore"=>&[("storePassword","fictional-store-password"),("keyAlias","fixture_alias"),("keyPassword","fictional-key-password")],
                    "google-wif"=>&[("provider","projects/123/locations/global/workloadIdentityPools/fixture/providers/fixture"),("serviceAccount","fixture@fixture-project.iam.gserviceaccount.com")],
                    "project-read-token"=>&[("token","fictional-read-token")],_=>return None,
                };
                let fields=serde_json::to_string(fields).ok()?;
                format!(r#"const forms=panel().querySelectorAll('form.session-inputs');if(forms.length!==1)return {{state:'wait'}};
                    const form=forms[0],fields={fields},inputs=[...form.querySelectorAll('input')];if(inputs.length!==fields.length)throw 0;
                    const pairs=fields.map(([name,fictional])=>{{const candidates=inputs.filter(i=>i.id.endsWith('-'+name));if(candidates.length!==1)throw 0;
                        const input=candidates[0],labels=[...form.querySelectorAll('label')].filter(l=>l.htmlFor===input.id);
                        if(labels.length!==1||input.type!=='password'||input.autocomplete!=='new-password'||input.readOnly)throw 0;return [input,fictional];}});
                    if(pairs.some(([i])=>i.disabled))return {{state:'wait'}};
                    for(const [input,fictional] of pairs){{show(input);input.focus();input.select();if(!document.execCommand('insertText',false,fictional))throw 0;}}
                    return {{state:'ready'}};"#)
            },
            SA::Remember(action)=>{
                let label=if action=="bind" { "Assign to this context" } else { "Keep for this session" };let label=serde_json::to_string(label).ok()?;
                format!(r#"if(Object.prototype.hasOwnProperty.call(window,'__mrkInstalledSessionButton'))throw 0;
                    const b=button({label},panel().querySelector('.session-review[aria-label="Explicit session review"]'));
                    if(!b||b.disabled)return {{state:'wait'}};show(b);window.__mrkInstalledSessionButton={{button:b,label:{label}}};return {{state:'ready'}};"#)
            },
            SA::Stale(action)=>{
                let label=serde_json::to_string(if action=="bind" { "Assign to this context" } else { "Keep for this session" }).ok()?;
                format!(r#"const old=window.__mrkInstalledSessionButton;if(!old||old.label!=={label}||!(old.button instanceof HTMLButtonElement))throw 0;
                    if(old.button.isConnected&&!old.button.disabled)throw 0;
                    old.button.click();delete window.__mrkInstalledSessionButton;return {{state:'ready'}};"#)
            },
            SA::Reassess(index,_) | SA::ReviewRemoval(index)=>{
                let label=if matches!(action,SA::Reassess(..)) { "Review assignment" } else { "Review removal…" };
                let label=serde_json::to_string(label).ok()?;
                format!(r#"const rows=panel().querySelectorAll('.session-records article');if(rows.length<={index})return {{state:'wait'}};
                    return click({label},rows[{index}]);"#)
            },
            SA::Open=>"return click('Start session — keep inputs in memory');".into(),
            SA::Choose(..)=>"return click('Select file…');".into(),
            SA::Prepare(..)=>"return click('Prepare private review',panel().querySelector('form.session-inputs'));".into(),
            SA::Keep=>"return click('Keep for this session',panel().querySelector('.session-review[aria-label=\"Explicit session review\"]'));".into(),
            SA::Assign=>"return click('Assign to this context',panel().querySelector('.session-review[aria-label=\"Explicit session review\"]'));".into(),
            SA::Remove=>"return click('Remove session copy',panel().querySelector('.session-review[aria-label=\"Explicit session review\"]'));".into(),
            SA::CancelOperation=>"return click('Request cancel / discard this operation',panel().querySelector('.session-progress'));".into(),
            SA::Discard=>"return click('Discard session…');".into(),
            SA::ConfirmDiscard=>"return click('Discard session copies',panel().querySelector('[aria-label=\"Confirm session discard\"]'));".into(),
            SA::QuitCancel | SA::Held=>return None,
        },
        SessionStep::Reload=>r#"if(Object.prototype.hasOwnProperty.call(window,'__mrkInstalledSessionButton'))throw 0;
            const b=button('Request cancel / discard this operation',panel().querySelector('.session-progress'));
            if(!b)return {state:'wait'};if(!b.disabled)throw 0;
            window.__mrkInstalledSessionButton={button:b,label:'loss-discard'};
            window.location.reload();return {state:'ready'};"#.into(),
        SessionStep::Read(..) | SessionStep::QuitPreserved | SessionStep::Deadline | SessionStep::Loss=>{
            let expected=serde_json::to_string(expected_display?).ok()?;
            let deadline=if presentation==SessionPresentation::DeadlineError { r#"const contexts=[...p.querySelectorAll('.session-context')].filter(c=>text(c.querySelector('h3'))==='Release context');
                if(contexts.length!==1)throw 0;const badges=contexts[0].querySelectorAll(':scope > .inline-heading > .badge');
                if(badges.length!==1||text(badges[0])!=='Context not current')return {state:'wait'};show(badges[0]);
                const alerts=p.querySelectorAll(':scope > .notice-danger[role="alert"]');if(alerts.length!==1)return {state:'wait'};
                const codes=alerts[0].querySelectorAll('.error-code'),titles=alerts[0].querySelectorAll('strong');
                if(codes.length!==1||titles.length!==1||text(codes[0])!=='asset_deadline'||text(titles[0])!=='The session action was not confirmed')return {state:'wait'};
                show(alerts[0]);show(codes[0]);show(titles[0]);
                if(p.querySelector('.session-review,.session-assessment')||[...p.querySelectorAll('button')].some(b=>['Keep for this session','Assign to this context','Remove session copy'].includes(text(b))))return {state:'wait'};
                const recovery=button('Check session status',p);if(!recovery||recovery.disabled)return {state:'wait'};show(recovery);"# } else { "" };
            let loss=if step==SessionStep::Loss { r#"const old=window.__mrkInstalledSessionButton;
                if(!old||old.label!=='loss-discard'||!(old.button instanceof HTMLButtonElement)||!p.querySelector('.notice-warning'))throw 0;
                if(old.button.isConnected&&!old.button.disabled)throw 0;old.button.click();delete window.__mrkInstalledSessionButton;"# } else { "" };
            format!(r#"const p=panel(),display=readDisplay();if(!equal(display,{expected}))return {{state:'wait'}};
                {deadline}const controls=readControls();{loss}return {{state:'ready',display,controls}};"#)
        }, _=>return None,
    };
    // Session selects explicitly use untrusted standard DOM change events;
    // old recipes below retain their no-synthetic-dispatch guarantee. Neither
    // path accesses React internals, invokes IPC, reads private input values,
    // injects filenames/DTOs or replaces the production controller.
    Some(format!(r#"(()=>{{try{{
        const equal=(a,b)=>{{if(a===b)return true;if(!a||!b||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;
            const ak=Object.keys(a).sort(),bk=Object.keys(b).sort();return ak.length===bk.length&&ak.every((k,i)=>k===bk[i]&&equal(a[k],b[k]));}};
        const text=e=>{{if(!e||typeof e.textContent!=='string'||e.textContent.length>4096)throw 0;return e.textContent;}};
        const show=e=>{{if(!e)throw 0;e.scrollIntoView({{block:'center'}});const r=e.getBoundingClientRect(),s=getComputedStyle(e);
            if(!e.isConnected||r.width<=0||r.height<=0||s.display==='none'||s.visibility!=='visible')throw 0;}};
        const panel=()=>{{const rows=document.querySelectorAll('.credential-session');if(rows.length!==1||!document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Credentials"][aria-current="page"]'))throw 0;return rows[0];}};
        const button=(label,root=panel())=>{{if(!root)return null;const rows=[...root.querySelectorAll('button')].filter(b=>text(b)===label);if(rows.length>1)throw 0;return rows[0]??null;}};
        const click=(label,root=panel())=>{{const b=button(label,root);if(!b||b.disabled)return {{state:'wait'}};show(b);b.click();return {{state:'ready'}};}};
        const select=label=>{{const p=panel(),labels=[...p.querySelectorAll('label')].filter(l=>text(l)===label);if(labels.length===0)return null;
            if(labels.length!==1||!labels[0].htmlFor)throw 0;const s=document.getElementById(labels[0].htmlFor);
            if(!(s instanceof HTMLSelectElement)||!p.contains(s)||s.id!==labels[0].htmlFor||s.options.length===0||s.options.length>33)throw 0;return s;}};
        const readDisplay=()=>{{const p=panel(),op=p.querySelector('.session-progress'),assessment=p.querySelector('.session-assessment'),review=p.querySelector('.session-review[aria-label="Explicit session review"]');
            const context=[...p.querySelectorAll('.session-context')].find(c=>text(c.querySelector('h3'))==='Release context');if(!context)throw 0;
            const records=[...p.querySelectorAll('.session-records article')].map(row=>{{show(row);return {{heading:text(row.querySelector('h4')),revision:text(row.querySelector('p')),availability:text(row.querySelector('.badge'))}};}});
            let assessed=null;if(assessment){{const fields=[...assessment.querySelectorAll('.session-field-results > li')].map(row=>({{state:text(row.querySelector(':scope > .inline-heading > .badge')),presence:text(row.querySelector(':scope > p')),issues:row.querySelectorAll(':scope > ul > li').length}}));
                assessed={{state:text(assessment.querySelector('.credential-row-heading > .badge')),fields,assurance:[...assessment.querySelectorAll('.session-assurance > .badge')].map(text)}};}}
            let action=null;if(review){{const rows=[...review.querySelectorAll('button')].filter(b=>['Keep for this session','Assign to this context','Remove session copy'].includes(text(b)));if(rows.length!==1)return null;
                if(rows[0].disabled)return null;action=text(rows[0]);}}
            let phase=null,settlement=null;if(op){{phase=text(op.querySelector('.badge'));const match=/Settlement: (pending|known|unknown|late-known)(?:\s|$)/.exec(text(op.querySelector(':scope > p')));if(!match)throw 0;settlement=match[1];}}
            return {{mode:text(p.querySelector(':scope > h3 .badge')),context:text(context.querySelector('.badge'))==='Context submitted · not yet policy-validated',records,review:action,assessment:assessed,phase,settlement}};}};
        const readControls=()=>{{const p=panel(),kind=select('What would you like to provide?'),platform=select('Platform'),replacement=select('New or replacement copy?');
            const names=['storePassword','keyAlias','keyPassword','provider','serviceAccount','token'];
            const formNames=[...p.querySelectorAll('form.session-inputs input')].map(input=>{{if(input.type!=='password')throw 0;const matches=names.filter(n=>input.id.endsWith('-'+n));if(matches.length!==1)throw 0;return matches[0];}});
            const prompts=[...p.querySelectorAll('.session-selection > p')].map(text);const filePrompt=prompts.some(p=>p.startsWith('Select a private .jks'))?'jks':prompts.some(p=>p.startsWith('Select the Android google-services.json'))?'firebase':'none';
            return {{platform:platform?.options[platform.selectedIndex]?.value??null,kind:kind?.options[kind.selectedIndex]?.value??null,
                replacement:replacement?text(replacement.options[replacement.selectedIndex]):null,formNames,filePrompt,discardConfirmation:!!p.querySelector('[aria-label="Confirm session discard"]')}};}};
        {body}
    }}catch{{return {{state:'error'}};}}}})()"#))
}

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


fn version_script(step: VersionStep) -> Option<String> {
    let index = step.index(); if index >= 3 { return None; }
    let body = match step {
        VersionStep::Open(_) => r#"const e=editor(),b=openButton(e);if (b.disabled) return {state:'wait'};
            if (document.querySelector('dialog')) throw 0;show(b);b.click();return {state:'ready'};"#,
        VersionStep::ReadOpen(_) => r#"const e=editor();if (!e.querySelector('.version-selection')) return {state:'wait'};
            const m=controls();if (!m.open.disabled || phase>0 && m.review.disabled) return {state:'wait'};
            return {state:'ready',display:display(m)};"#,
        VersionStep::Name(_) if index < 2 => r#"return insert(0,phase===0?'1.2.3':'2.3.4',phase===0?['','']:['1.2.3','7']);"#,
        VersionStep::Build(_) if index < 2 => r#"return insert(1,phase===0?'7':'8',phase===0?['1.2.3','']:['2.3.4','7']);"#,
        VersionStep::Name(_) | VersionStep::Build(_) => return None,
        VersionStep::ReadInputs(_) => r#"const m=controls();return {state:'ready',display:display(m)};"#,
        VersionStep::Review(_) => r#"const m=controls();if (m.review.disabled) return {state:'wait'};
            if (document.querySelector('dialog')) throw 0;show(m.review);m.review.click();return {state:'ready'};"#,
        VersionStep::ReadReview(_) => r#"const m=controls();if (!m.editor.querySelector('.version-review')) return {state:'wait'};
            if (document.querySelector('dialog')) throw 0;return {state:'ready',display:display(m),review:review(m)};"#,
        VersionStep::Confirm(_) => r#"const m=controls(),buttons=[...m.editor.querySelectorAll(':scope > button.button.primary')];
            const label=['Create version file…','Save version values…','Confirm unchanged values…'][phase];
            if (buttons.length!==1 || text(buttons[0])!==label || buttons[0].disabled || document.querySelector('dialog')) throw 0;
            show(buttons[0]);buttons[0].click();return {state:'ready'};"#,
        VersionStep::ReadConfirmation(_) | VersionStep::ReadChecked(_) | VersionStep::ReadTyped(_) => r#"if (!document.querySelector('.version-editor > dialog[open].confirm-dialog')) return {state:'wait'};
            return {state:'ready',confirmation:confirmationDisplay()};"#,
        VersionStep::Check(_) => r#"const c=confirmation();if (c.check.checked || c.input.value!=='' || !c.apply.disabled) throw 0;
            show(c.check);c.check.click();return {state:'ready'};"#,
        VersionStep::Type(_) => r#"const c=confirmation();if (!c.check.checked || c.input.value!=='' || !c.apply.disabled) throw 0;
            show(c.input);c.input.focus();c.input.select();if (document.activeElement!==c.input || c.input.selectionStart!==0 || c.input.selectionEnd!==0
                || !document.execCommand('insertText',false,'SAVE')) throw 0;return {state:'ready'};"#,
        VersionStep::Apply(_) => r#"const c=confirmation();if (!c.check.checked || c.input.value!=='SAVE' || c.apply.disabled) throw 0;
            show(c.apply);c.apply.click();return {state:'ready'};"#,
        VersionStep::ReadSaved(_) => r#"const m=controls();if (document.querySelector('dialog') || m.open.disabled || m.review.disabled) return {state:'wait'};
            return {state:'ready',display:display(m),outcome:outcome(m)};"#,
        VersionStep::Readback(_) => r#"const p=passive();if (p.button.disabled || p.live.getAttribute('aria-busy')==='true') return {state:'wait'};
            if (document.querySelector('dialog')) throw 0;show(p.button);p.button.click();return {state:'ready'};"#,
        VersionStep::ReadReadback(_) => r#"const m=controls(),p=passive();if (p.button.disabled || p.live.getAttribute('aria-busy')==='true') return {state:'wait'};
            if (document.querySelector('dialog')) throw 0;return {state:'ready',display:display(m),outcome:outcome(m),readback:readback(p)};"#,
    };
    // The actual original handler/status hooks separately attest every native
    // boundary. This script only operates and reads existing visible controls.
    let phase = format!("const phase={index};");
    Some([r#"(() => { try {
        if (document.querySelector('.preview-banner, .fatal-error, #main-content > .notice-danger')) throw 0;
        const text=e=>{if (!e || typeof e.textContent!=='string' || e.textContent.length>4096) throw 0;return e.textContent;};
        const visible=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);return e.isConnected && r.width>0 && r.height>0 && s.display!=='none' && s.visibility==='visible';};
        const show=e=>{if (!e) throw 0;e.scrollIntoView({block:'center'});if (!visible(e)) throw 0;};
        const selected=()=>[...document.querySelectorAll('nav[aria-label="Workspace navigation"] button[aria-current="page"]')].some(b=>b.getAttribute('aria-label')==='Dashboard');
        const editor=()=>{
            const editors=document.querySelectorAll('section[aria-label="Edit or create saved version values"]');
            if (!selected() || editors.length!==1) throw 0;const e=editors[0];
            if (e.querySelector('.notice-danger, .review-caution, [role="alert"]')) throw 0;return e;
        };
        const openButton=e=>{
            const groups=e.querySelectorAll(':scope > .button-row');if (groups.length<1 || groups.length>2) throw 0;
            const buttons=groups[0].querySelectorAll(':scope > button');
            if (buttons.length!==3 || text(buttons[0])!=='Open saved version editor'
                || text(buttons[1])!=='Project Settings / ignore prerequisite' || text(buttons[2])!=='Check writer availability') throw 0;
            return buttons[0];
        };
        const controls=()=>{
            const e=editor(),groups=e.querySelectorAll(':scope > .button-row');
            const fields=[...e.querySelectorAll(':scope > .version-values > div')];
            if (groups.length!==2 || fields.length!==2) throw 0;
            const inputs=fields.map((field,index)=>{
                const input=field.querySelector(':scope > input'),label=field.querySelector(':scope > label');
                if (!input || !label || !input.id || label.getAttribute('for')!==input.id || input.disabled || input.readOnly
                    || input.type!=='text' || input.maxLength!==(index===0?64:10)
                    || !text(label).startsWith(index===0?'Marketing version':'Build number') || input.value.length>(index===0?64:10)) throw 0;
                return input;
            });
            const buttons=groups[1].querySelectorAll(':scope > button');
            if (buttons.length!==3 || !['Validate and review creation','Validate and review values'].includes(text(buttons[0]))
                || text(buttons[1])!=='Discard value changes' || text(buttons[2])!=='Reload saved values') throw 0;
            return {editor:e,open:openButton(e),review:buttons[0],inputs};
        };
        const display=m=>{
            const e=m.editor,selection=e.querySelectorAll(':scope > .version-selection');
            if (selection.length!==1) throw 0;const paragraphs=selection[0].querySelectorAll(':scope > p');
            const digests=selection[0].querySelectorAll(':scope > code.version-digest');
            if (paragraphs.length!==3 || digests.length<1 || digests.length>2) throw 0;
            [...paragraphs,...digests,...m.inputs].forEach(show);
            return {title:text(e.querySelector(':scope > .section-heading h2')),project:text(e.querySelector(':scope > p')),
                badge:text(e.querySelector(':scope > .section-heading .badge')),selection:[...paragraphs].map(text),digests:[...digests].map(text),
                values:{name:m.inputs[0].value,build:m.inputs[1].value},openAvailable:!m.open.disabled,
                reviewLabel:text(m.review),reviewAvailable:!m.review.disabled};
        };
        const insert=(index,replacement,before)=>{
            const m=controls();if (document.querySelector('dialog') || m.inputs.some((input,i)=>input.value!==before[i])) throw 0;
            const input=m.inputs[index];show(input);input.focus();input.select();
            if (document.activeElement!==input || input.selectionStart!==0 || input.selectionEnd!==before[index].length
                || !document.execCommand('insertText',false,replacement)) throw 0;return {state:'ready'};
        };
        const raw=(element,before)=>{
            if (text(element.querySelector(':scope > h4'))!==(before?'Complete original text':'Complete reviewed text')) throw 0;
            const pres=element.querySelectorAll(':scope > pre');show(element);
            if (before && pres.length===0) {
                if (text(element.querySelector(':scope > p'))!=='Observed absent. Empty or malformed files are not treated as absence.') throw 0;
                return {state:'absent'};
            }
            if (pres.length!==1 || pres[0].getAttribute('aria-label')!=='Complete '+(before?'original':'reviewed')+' version source') throw 0;
            show(pres[0]);const content=text(pres[0].querySelector(':scope > code'));
            const size=/^([0-9]+) UTF-8 bytes · lf · Final line ending present$/.exec(text(element.querySelector(':scope > p')));
            const digest=/^SHA256 ([0-9a-f]{64})$/.exec(text(element.querySelector(':scope > code.version-digest')));
            if (!size || !digest) throw 0;const bytes=Number(size[1]);
            if (!Number.isSafeInteger(bytes) || String(bytes)!==size[1] || bytes>4096) throw 0;
            const value={text:content,bytes,sha256:digest[1]};return before?{state:'present',...value}:value;
        };
        const review=m=>{
            const views=m.editor.querySelectorAll(':scope > .version-review');if (views.length!==1) throw 0;const view=views[0];
            const facts=view.querySelectorAll(':scope > p'),sides=view.querySelectorAll('.version-raw-grid > .version-raw');
            if (facts.length!==6 || sides.length!==2) throw 0;[...facts].forEach(show);
            return {title:text(view.querySelector(':scope > h3')),facts:[...facts].map(text),before:raw(sides[0],true),after:raw(sides[1],false)};
        };
        const confirmation=()=>{
            const e=editor(),dialogs=document.querySelectorAll('dialog');
            if (dialogs.length!==1 || dialogs[0].parentElement!==e || !dialogs[0].classList.contains('confirm-dialog')
                || !dialogs[0].open || dialogs[0].querySelector('[role="alert"]')) throw 0;
            const dialog=dialogs[0],checks=dialog.querySelectorAll('.save-confirm-check input[type="checkbox"]');
            const inputs=dialog.querySelectorAll('.dialog-content > input'),buttons=dialog.querySelectorAll('.button-row > button');
            if (checks.length!==1 || inputs.length!==1 || buttons.length!==2 || checks[0].disabled || inputs[0].disabled || inputs[0].readOnly
                || inputs[0].type!=='text' || inputs[0].value.length>4 || buttons[0].disabled || text(buttons[0])!=='Keep reviewing'
                || text(buttons[1])!==['Create version file','Save version values','Confirm unchanged values'][phase]
                || text(dialog.querySelector('.save-confirm-check'))!=='I reviewed the full original/after text, exact destination, byte comparisons, mode and directory/line-ending facts.') throw 0;
            return {dialog,check:checks[0],input:inputs[0],apply:buttons[1]};
        };
        const confirmationDisplay=()=>{
            const c=confirmation(),paragraphs=c.dialog.querySelectorAll('.dialog-content > p');
            if (paragraphs.length!==2) throw 0;[c.check,c.input,c.apply,...paragraphs].forEach(show);
            return {title:text(c.dialog.querySelector('h2')),selection:text(paragraphs[0]),scope:text(paragraphs[1]),
                checked:c.check.checked,typed:c.input.value,applyAvailable:!c.apply.disabled};
        };
        const outcome=m=>{
            const panels=m.editor.querySelectorAll(':scope > .version-status'),notices=panels.length===1?panels[0].querySelectorAll(':scope > .notice-info'): [];
            if (panels.length!==1 || notices.length!==1 || notices[0].getAttribute('role')!=='status') throw 0;
            const content=notices[0].querySelector(':scope > div'),paragraphs=content?.querySelectorAll(':scope > p');
            if (!content || paragraphs.length!==3
                || text(paragraphs[2])!=='This receipt is for the submitted revision only, not later edits. Read saved version again explicitly before using its new values for build consent.') throw 0;
            show(content);return {title:text(content.querySelector(':scope > strong')),submitted:text(paragraphs[0]),facts:text(paragraphs[1])};
        };
        const passive=()=>{
            const cards=document.querySelectorAll('section[aria-label="Saved version and build"]');
            if (!selected() || cards.length!==1) throw 0;const card=cards[0],live=card.querySelector('div[aria-live="polite"]'),buttons=card.querySelectorAll(':scope > button');
            if (!live || buttons.length!==1 || text(buttons[0])!=='Read saved version') throw 0;return {card,live,button:buttons[0]};
        };
        const readback=p=>{
            const name=p.live.querySelector('strong.summary-value'),paragraphs=[...p.live.querySelectorAll(':scope > p')];
            const badges=p.live.querySelectorAll(':scope > .badge'),scope=p.card.querySelectorAll(':scope > p');
            if (p.live.getAttribute('aria-busy')!=='false' || p.live.children.length!==4 || paragraphs.length!==2 || badges.length!==1 || scope.length!==1) throw 0;
            const sources=paragraphs[1].querySelectorAll(':scope > code');if (sources.length!==1) throw 0;
            [p.card,name,...paragraphs,badges[0],scope[0],p.button].forEach(show);
            return {name:text(name),build:text(paragraphs[0]),badge:text(badges[0]),source:text(sources[0]),sourceText:text(paragraphs[1]),
                scope:text(scope[0]),config:text(p.card.querySelector('.summary-foot code')),readAvailable:!p.button.disabled};
        };
    "#,&phase,body,r#" } catch { return {state:'error'}; } })()"#].concat())
}

fn metadata_script(step: MetadataStep) -> Option<String> {
    if matches!(step,MetadataStep::Review(index) | MetadataStep::OpenText(index) | MetadataStep::ReadReview(index) if index > 1) { return None; }
    let body = match step {
        MetadataStep::Navigate => r#"const b=document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Metadata"]');
            if (!b || b.disabled || document.querySelector('dialog')) throw 0; show(b); b.click(); return {state:'ready'};"#,
        MetadataStep::Load => r#"if (!selected('Metadata') || !document.querySelector('.metadata-text-editor')) return {state:'wait'};
            const m=controls(); if (m.load.disabled) return {state:'wait'};
            if (text(m.load)!=='Load public text' || !m.validate.disabled || !m.review.disabled || document.querySelector('.metadata-text-fields, .metadata-save-panel')) throw 0;
            show(m.load); m.load.click(); return {state:'ready'};"#,
        MetadataStep::ReadLoaded => r#"const m=controls(); if (m.load.disabled || text(m.load)!=='Refresh text' || !m.editor.querySelector('.metadata-text-fields')) return {state:'wait'};
            return {state:'ready',display:display(m)};"#,
        MetadataStep::Short => r#"return insert(1,'Public summary',['Public title','Old summary','']);"#,
        MetadataStep::Full => r#"return insert(2,'Public description',['Public title','Public summary','']);"#,
        MetadataStep::ReadInputs => r#"const m=controls();return {state:'ready',display:display(m)};"#,
        MetadataStep::Validate => r#"const m=controls();if (m.validate.disabled || !m.review.disabled || text(m.validate)!=='Validate text'
            || m.editor.querySelector('.metadata-validation-status')) throw 0;
            show(m.validate); m.validate.click();return {state:'ready'};"#,
        MetadataStep::ReadValidation => r#"const m=controls();if (m.validate.disabled || m.review.disabled || !m.editor.querySelector('.metadata-validation-status')) return {state:'wait'};
            return {state:'ready',display:display(m)};"#,
        MetadataStep::Review(_) => r#"const m=controls();if (m.review.disabled || document.querySelector('dialog')) return {state:'wait'};
            show(m.review);m.review.click();return {state:'ready'};"#,
        MetadataStep::OpenText(_) => r#"if (!document.querySelector('.metadata-native-review')) return {state:'wait'};
            const p=panel();if (text(p.querySelector('.section-heading h2'))!=='Review text changes') return {state:'wait'};
            const rows=p.querySelectorAll('.metadata-file-review');if (rows.length!==3 || document.querySelector('dialog')) throw 0;
            for (const row of rows) {const summary=row.querySelector(':scope > summary');show(summary);if (!row.open) summary.click();}
            return {state:'ready'};"#,
        MetadataStep::ReadReview(_) => r#"const m=controls(),p=panel();if (text(p.querySelector('.section-heading h2'))!=='Review text changes') return {state:'wait'};
            if (document.querySelector('dialog')) throw 0;return {state:'ready',review:review(),draft:rows(m).map(row=>({id:row.id,text:row.input.value}))};"#,
        MetadataStep::CloseReview => r#"const p=panel(),buttons=[...p.querySelectorAll(':scope > .button-row button')];
            const matches=buttons.filter(b=>text(b)==='Close review, keep draft');if (matches.length!==1 || matches[0].disabled || document.querySelector('dialog')) throw 0;
            show(matches[0]);matches[0].click();return {state:'ready'};"#,
        MetadataStep::ReadClosed => r#"const m=controls(),p=panel();if (text(p.querySelector('.section-heading h2'))!=='Text review ended; draft kept' || m.review.disabled) return {state:'wait'};
            return {state:'ready',display:display(m),outcome:outcome()};"#,
        MetadataStep::Confirm => r#"const p=panel(),buttons=[...p.querySelectorAll(':scope > .button-row button.primary')];
            if (buttons.length!==1 || buttons[0].disabled || text(buttons[0])!=='Save text…' || document.querySelector('dialog')) throw 0;
            show(buttons[0]);buttons[0].click();return {state:'ready'};"#,
        MetadataStep::ReadConfirmation | MetadataStep::ReadChecked | MetadataStep::ReadTyped => r#"if (!document.querySelector('dialog[open].metadata-confirm-dialog')) return {state:'wait'};
            return {state:'ready',confirmation:confirmationDisplay()};"#,
        MetadataStep::Check => r#"const c=confirmation();if (c.check.checked || c.input.value!=='' || !c.apply.disabled) throw 0;
            show(c.check);c.check.click();return {state:'ready'};"#,
        MetadataStep::Type => r#"const c=confirmation();if (!c.check.checked || c.input.value!=='' || !c.apply.disabled) throw 0;
            show(c.input);c.input.focus();c.input.select();if (document.activeElement!==c.input || c.input.selectionStart!==0 || c.input.selectionEnd!==0
                || !document.execCommand('insertText',false,'SAVE')) throw 0;return {state:'ready'};"#,
        MetadataStep::Apply => r#"const c=confirmation();if (!c.check.checked || c.input.value!=='SAVE' || c.apply.disabled) throw 0;
            show(c.apply);c.apply.click();return {state:'ready'};"#,
        MetadataStep::ReadSaved | MetadataStep::ReadReadback => r#"const m=controls(),p=panel();
            if (document.querySelector('dialog') || text(p.querySelector('.section-heading h2'))!=='Text saved' || m.load.disabled || text(m.load)!=='Refresh text') return {state:'wait'};
            return {state:'ready',display:display(m),outcome:outcome()};"#,
        MetadataStep::Refresh => r#"const m=controls();if (m.load.disabled || text(m.load)!=='Refresh text' || document.querySelector('dialog')) throw 0;
            show(m.load);m.load.click();return {state:'ready'};"#,
    };
    // Fixed existing renderer controls only. No invoke/controller access,
    // injected DTO, fabricated reply, synthetic event or input.value setter.
    Some([r#"(() => { try {
        if (document.querySelector('.preview-banner, .fatal-error, #main-content > .notice-danger, .metadata-save-panel .notice-danger')) throw 0;
        const text=e=>{if (!e || typeof e.textContent!=='string' || e.textContent.length>4096) throw 0;return e.textContent;};
        const visible=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);return e.isConnected && r.width>0 && r.height>0 && s.display!=='none' && s.visibility==='visible';};
        const show=e=>{if (!e) throw 0;e.scrollIntoView({block:'center'});if (!visible(e)) throw 0;};
        const selected=label=>[...document.querySelectorAll('nav[aria-label="Workspace navigation"] button[aria-current="page"]')].some(b=>b.getAttribute('aria-label')===label);
        const ids=['title.txt','short_description.txt','full_description.txt'];
        const controls=()=>{
            const editors=document.querySelectorAll('.metadata-text-editor');if (!selected('Metadata') || editors.length!==1) throw 0;
            const editor=editors[0];if (editor.querySelector('.notice-danger, .notice-warning, .review-caution, .issues, .metadata-latest-observation')) throw 0;
            const contexts=editor.querySelectorAll('.metadata-context-row select'),loads=editor.querySelectorAll('.metadata-context-row > button.button.secondary');
            const validations=editor.querySelectorAll('.metadata-text-actions > button.button.secondary'),reviews=editor.querySelectorAll('.metadata-text-actions > button.button.primary');
            if (contexts.length!==1 || loads.length!==1 || validations.length!==1 || reviews.length!==1) throw 0;
            const context=contexts[0];if (context.disabled || !context.value || context.selectedOptions.length!==1
                || text(context.selectedOptions[0])!=='android / en-US' || context.selectedOptions[0].parentElement?.getAttribute('label')!=='Current saved configuration'
                || text(reviews[0])!=='Review changes') throw 0;
            return {editor,context,load:loads[0],validate:validations[0],review:reviews[0]};
        };
        const rows=m=>{
            const elements=[...m.editor.querySelectorAll('.metadata-text-fields > .metadata-text-field')];if (elements.length!==3) throw 0;
            return elements.map((row,index)=>{const codes=row.querySelectorAll(':scope > code'),inputs=row.querySelectorAll(':scope > textarea');
                if (codes.length!==1 || inputs.length!==1) throw 0;const input=inputs[0],id=ids[index],path=text(codes[0]);
                if (path!=='release/store/android/en-US/'+id || input.disabled || input.readOnly || input.value.length>32768
                    || !input.id || row.querySelector('.inline-heading label')?.getAttribute('for')!==input.id) throw 0;
                return {row,input,id,path};});
        };
        const display=m=>{
            if (text(m.validate)!=='Validate text') throw 0;
            const statuses=m.editor.querySelectorAll('.metadata-validation-status');if (statuses.length>1) throw 0;
            const fields=rows(m).map(item=>{show(item.row);show(item.input);const badges=[...item.row.querySelectorAll('.inline-heading .badge')];if (badges.length!==2) throw 0;
                return {id:item.id,path:item.path,text:item.input.value,badges:badges.map(text),invalid:item.input.getAttribute('aria-invalid')};});
            return {context:text(m.context.selectedOptions[0]),badge:text(m.editor.querySelector('.section-heading .badge')),fields,
                loadLabel:text(m.load),loadAvailable:!m.load.disabled,validateAvailable:!m.validate.disabled,reviewAvailable:!m.review.disabled,
                validation:statuses.length?text(statuses[0].querySelector('.badge')):null};
        };
        const insert=(index,replacement,before)=>{
            const m=controls(),items=rows(m);if (m.load.disabled || m.validate.disabled || !m.review.disabled || text(m.load)!=='Refresh text'
                || m.editor.querySelector('.metadata-validation-status') || items.some((item,offset)=>item.input.value!==before[offset])) throw 0;
            const input=items[index].input;show(input);input.focus();input.select();
            if (document.activeElement!==input || input.selectionStart!==0 || input.selectionEnd!==before[index].length
                || !document.execCommand('insertText',false,replacement)) throw 0;return {state:'ready'};
        };
        const panel=()=>{const panels=document.querySelectorAll('.metadata-save-panel');if (!selected('Metadata') || panels.length!==1) throw 0;return panels[0];};
        const raw=(element,path,before)=>{
            if (text(element.querySelector('h4'))!==(before?'Original bytes':'Reviewed replacement bytes')) throw 0;
            const pres=element.querySelectorAll('pre');show(element);
            if (before && pres.length===0) {if (text(element.querySelector('p'))!=='Observed absent. No original text was fabricated.') throw 0;return {state:'absent'};}
            if (pres.length!==1 || pres[0].getAttribute('aria-label')!==`Complete ${before?'original':'reviewed'} public text for ${path}`) throw 0;
            show(pres[0]);const content=text(pres[0].querySelector('code'));
            const numbers=/^(.+) UTF-8 bytes · No line endings · No final line ending$/.exec(text(element.querySelector('p')));
            const digest=/^SHA256 ([0-9a-f]{64})$/.exec(text(element.querySelector('.metadata-digest')));
            if (!numbers || !digest) throw 0;const byteLength=Number(numbers[1].replace(/[^0-9]/g,''));
            if (!Number.isSafeInteger(byteLength) || byteLength.toLocaleString()!==numbers[1]) throw 0;
            const result={text:content,byteLength,sha256:digest[1]};return before?{state:'present',...result}:result;
        };
        const review=()=>{
            const p=panel(),views=p.querySelectorAll('.metadata-native-review');if (views.length!==1) throw 0;const view=views[0];
            const tables=view.querySelectorAll('.review-table'),details=[...view.querySelectorAll('.metadata-file-review')];
            if (tables.length!==1 || text(tables[0].querySelector('caption'))!=='Files in this review' || details.length!==3 || details.some(d=>!d.open)) throw 0;
            const inventory=[...tables[0].querySelectorAll('tbody > tr')];if (inventory.length!==3) throw 0;
            if (text(view.querySelector(':scope > .save-note'))!=='No missing directories need to be created. Exact-preserved files keep their bytes, mode and identity. No file is deleted or renamed.') throw 0;
            return inventory.map((row,index)=>{
                show(row);const cells=row.querySelectorAll(':scope > td');if (cells.length!==3) throw 0;
                const path=text(row.querySelector(':scope > th code')),label=text(cells[0]);
                const action=label==='Preserve exact original'?'preserve':label==='Replace reviewed original'?'replace':label==='Create absent file'?'create':null;
                const detail=details[index],sides=detail.querySelectorAll('.metadata-raw-grid > .metadata-raw');
                if (!action || path!=='release/store/android/en-US/'+ids[index] || sides.length!==2
                    || text(detail.querySelector('summary > code'))!==path || text(detail.querySelector('summary > .badge'))!==action) throw 0;
                const before=raw(sides[0],path,true),after=raw(sides[1],path,false);
                if (text(cells[1])!==`${before.state==='absent'?'Absent':before.byteLength+' bytes'} → ${after.byteLength} bytes`
                    || text(cells[2])!=='Unchanged') throw 0;
                return {id:ids[index],path,action,before,after,lineEndingsChanged:false};
            });
        };
        const outcome=()=>{
            const p=panel(),details=p.querySelectorAll('.metadata-outcome-details');if (details.length!==1) throw 0;
            if (!details[0].open) {const summary=details[0].querySelector(':scope > summary');show(summary);summary.click();}
            const facts=[...details[0].querySelectorAll('.save-outcome-facts > div')];if (facts.length!==4) throw 0;
            const labels=['Original project / locale','Effect / journal','Core / native resources','Reason'];
            const values=facts.map((row,index)=>{show(row);if (text(row.querySelector('dt'))!==labels[index]) throw 0;return text(row.querySelector('dd'));});
            return {title:text(p.querySelector('.section-heading h2')),project:values[0],effect:values[1],resources:values[2],reason:values[3]};
        };
        const confirmation=()=>{
            const dialogs=document.querySelectorAll('dialog');if (dialogs.length!==1 || !dialogs[0].classList.contains('metadata-confirm-dialog')
                || !dialogs[0].open || dialogs[0].querySelector('[role="alert"]')) throw 0;
            const dialog=dialogs[0],checks=dialog.querySelectorAll('.save-confirm-check input[type="checkbox"]');
            const inputs=dialog.querySelectorAll('.dialog-content > input'),buttons=dialog.querySelectorAll('.button-row > button');
            if (checks.length!==1 || inputs.length!==1 || buttons.length!==2 || checks[0].disabled || inputs[0].disabled || inputs[0].readOnly
                || inputs[0].type!=='text' || inputs[0].value.length>4 || buttons[0].disabled || text(buttons[0])!=='Keep reviewing' || text(buttons[1])!=='Save text'
                || text(dialog.querySelector('.save-confirm-check'))!=='I reviewed all exact paths, full original/replacement text, digests and line-ending changes.') throw 0;
            return {dialog,check:checks[0],input:inputs[0],apply:buttons[1]};
        };
        const confirmationDisplay=()=>{
            const c=confirmation(),files=[...c.dialog.querySelectorAll('.metadata-confirm-files > li')];if (files.length!==3) throw 0;
            const rows=files.map((row,index)=>{show(row);const path=text(row.querySelector('code')),match=/ — (create|replace|preserve)$/.exec(text(row));
                if (path!=='release/store/android/en-US/'+ids[index] || !match || text(row)!==path+match[0]) throw 0;return [path,match[1]];});
            show(c.check);show(c.input);show(c.apply);
            return {title:text(c.dialog.querySelector('h2')),files:rows,checked:c.check.checked,typed:c.input.value,applyAvailable:!c.apply.disabled};
        };
    "#,body,r#" } catch { return {state:'error'}; } })()"#].concat())
}

fn workflow_script(step: WorkflowStep) -> Option<String> {
    let body = match step {
        WorkflowStep::GitHub(_) => r#"const b=document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="GitHub"]');
            if (!b || b.disabled) throw 0; b.click(); return {state:'ready'};"#.to_owned(),
        WorkflowStep::Pin(index) => {
            let (before, after) = match index { 1 => (TOOLKIT_SHA, CONFLICT_SHA), 2 => (CONFLICT_SHA, TOOLKIT_SHA), _ => return None };
            format!(r#"if (!selected('GitHub')) return {{state:'wait'}};
                const g=inputs(); if (g.repository.value!=='example/toolkit' || g.sha.value!=='{before}' || g.comparison.checked) throw 0;
                const input=g.sha; show(input); input.focus(); input.select();
                if (document.activeElement!==input || input.selectionStart!==0 || input.selectionEnd!==40
                    || !document.execCommand('insertText',false,'{after}')) throw 0; return {{state:'ready'}};"#)
        },
        WorkflowStep::ReadPin(_) => r#"const g=inputs(); return {state:'ready',
            inputs:{repository:g.repository.value,sha:g.sha.value,comparison:g.comparison.checked}};"#.to_owned(),
        WorkflowStep::Start(index) => {
            if index > 3 { return None; }
            let pin = if index == 1 { CONFLICT_SHA } else { TOOLKIT_SHA };
            format!(r#"if (!selected('GitHub')) return {{state:'wait'}};
                const g=inputs(), p=panel(), b=start(p);
                if (g.repository.value!=='example/toolkit' || g.sha.value!=='{pin}' || g.comparison.checked) throw 0;
                if (b.disabled) return {{state:'wait'}}; remoteClosed(); show(b); b.click(); return {{state:'ready'}};"#)
        },
        WorkflowStep::OpenText(_) => r#"if (!selected('GitHub')) return {state:'wait'};
            const p=panel(), review=p.querySelector(':scope > .workflow-review');
            if (!review || text(p.querySelector('h2'))!=='Review the fresh native workflow plan') return {state:'wait'};
            const rows=[...review.querySelectorAll('details.github-workflow')]; if (rows.length!==4) throw 0;
            for (const row of rows) { const summary=row.querySelector(':scope > summary'); show(summary); if (!row.open) summary.click(); }
            return {state:'ready'};"#.to_owned(),
        WorkflowStep::ReadReview(_) | WorkflowStep::ReadKept => r#"if (document.querySelector('dialog')) return {state:'wait'};
            const p=panel(), review=p.querySelector(':scope > .workflow-review'), b=p.querySelector('.save-actions button.primary');
            if (!review || !b || b.disabled || text(p.querySelector('h2'))!=='Review the fresh native workflow plan') return {state:'wait'};
            return {state:'ready',review:reviewDisplay(review)};"#.to_owned(),
        WorkflowStep::Confirm(index) => {
            let label = match index { 0 => "Confirm reviewed local files", 2 => "Review unchanged confirmation", _ => return None };
            format!(r#"const p=panel(), b=p.querySelector('.save-actions button.primary');
                if (!b || b.disabled || text(b)!=='{label}' || document.querySelector('dialog')) throw 0;
                show(b); b.click(); return {{state:'ready'}};"#)
        },
        WorkflowStep::Reconfirm => r#"const p=panel(), b=p.querySelector('.save-actions button.primary');
            if (!b || b.disabled || text(b)!=='Confirm reviewed local files' || document.querySelector('dialog')) throw 0;
            show(b); b.click(); return {state:'ready'};"#.to_owned(),
        WorkflowStep::ReadConfirmation(_) | WorkflowStep::ReadReconfirmation | WorkflowStep::ReadAcknowledged(_) =>
            r#"if (!document.querySelector('dialog.workflow-confirm-dialog[open]')) return {state:'wait'};
                return {state:'ready',confirmation:confirmationDisplay()};"#.to_owned(),
        WorkflowStep::Keep => r#"const c=confirmation(); if (c.check.checked || !c.apply.disabled) throw 0;
            show(c.keep); c.keep.click(); return {state:'ready'};"#.to_owned(),
        WorkflowStep::Acknowledge(_) => r#"const c=confirmation(); if (c.check.checked || !c.apply.disabled) throw 0;
            show(c.check); c.check.click(); return {state:'ready'};"#.to_owned(),
        WorkflowStep::Apply(_) => r#"const c=confirmation(); if (!c.check.checked || c.apply.disabled) throw 0;
            show(c.apply); c.apply.click(); return {state:'ready'};"#.to_owned(),
        WorkflowStep::ReadResult(index) => {
            let title = match index { 0 => "Reviewed local workflow bundle installed", 1 => "Local workflow bundle refused",
                2 => "Four callers verified unchanged", _ => return None };
            format!(r#"if (document.querySelector('dialog')) return {{state:'wait'}};
                const p=panel(), b=start(p), title=text(p.querySelector('h2'));
                if (title!=='{title}' || b.disabled || !p.querySelector('.save-outcome-facts')) return {{state:'wait'}};
                remoteClosed(); const conflict=p.querySelector('.workflow-conflict');
                const rows=conflict?[...conflict.querySelectorAll('ul > li')]:[];
                if (conflict && rows.length!==4) throw 0;
                const facts=[...p.querySelectorAll(':scope > .save-outcome-facts > div')].map(row=>{{show(row);return [text(row.querySelector('dt')),text(row.querySelector('dd'))];}});
                const close=[...p.querySelectorAll('.save-actions button')].filter(b=>['Close workflow review / keep draft','Request cancellation'].includes(text(b)));
                return {{state:'ready',title,facts,startAvailable:!b.disabled,
                    applyAvailable:!!p.querySelector('.save-actions button.primary:not(:disabled)'),closeAvailable:close.some(b=>!b.disabled),
                    hasReview:!!p.querySelector(':scope > .workflow-review'),
                    conflict:conflict?{{heading:text(conflict.querySelector('h3')),rows:rows.map(row=>{{show(row);
                        return {{id:text(row.querySelector('strong')),bytes:count(text(row.querySelector('span')),' observed bytes'),sha256:text(row.querySelector('code'))}};}}),
                        caution:text(conflict.querySelector(':scope > p'))}}:null}};"#)
        },
        WorkflowStep::Settings(_) => r#"const b=document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Project settings"]');
            if (!b || b.disabled || document.querySelector('dialog')) throw 0; b.click(); return {state:'ready'};"#.to_owned(),
        WorkflowStep::ReadDraft(index) => {
            if index > 3 { return None; }
            let available = if index == 3 { "false" } else { "true" };
            format!(r#"if (!selected('Project settings') || document.querySelector('dialog')) return {{state:'wait'}};
                const banner=document.querySelector('.draft-banner'), save=document.querySelector('.draft-toolbar button[aria-describedby="draft-save-reason"]');
                const field=[...document.querySelectorAll('.form-field')].find(f=>f.querySelector('.help-button')?.getAttribute('aria-label')==='Help: Committed version file');
                if (!banner || !save || !field || (!save.disabled)!=={available}) return {{state:'wait'}};
                const input=field.querySelector('input'); if (!input || input.value.length>512 || text(field.querySelector('.field-presence'))!=='Set'
                    || document.querySelector('.suggestion-card')) throw 0; show(field);
                return {{state:'ready',source:input.value,unsaved:text(banner.querySelector('.badge'))==='Unsaved changes',
                    saved:text(banner.querySelector('.badge'))==='Settled submitted revision',saveAvailable:!save.disabled}};"#)
        },
    };
    Some(format!(r#"(() => {{ try {{
        if (document.querySelector('.preview-banner, .fatal-error, #main-content > .notice-danger, .native-workflow-panel .notice-danger')) throw 0;
        const text=e=>{{if (!e || typeof e.textContent!=='string' || e.textContent.length>4096) throw 0; return e.textContent;}};
        const visible=e=>{{const r=e.getBoundingClientRect(),s=getComputedStyle(e);return e.isConnected && r.width>0 && r.height>0 && s.display!=='none' && s.visibility==='visible';}};
        const show=e=>{{if (!e) throw 0;e.scrollIntoView({{block:'center'}});if (!visible(e)) throw 0;}};
        const selected=label=>[...document.querySelectorAll('nav[aria-label="Workspace navigation"] button[aria-current="page"]')].some(b=>b.getAttribute('aria-label')===label);
        const panel=()=>{{const rows=document.querySelectorAll('section.native-workflow-panel');if (!selected('GitHub') || rows.length!==1) throw 0;return rows[0];}};
        const start=p=>{{const rows=p.querySelectorAll('button[aria-describedby="github-workflow-start-reason"]');
            if (rows.length!==1 || text(rows[0])!=='Review local workflow files') throw 0;return rows[0];}};
        const remoteClosed=()=>{{const rows=[...document.querySelectorAll('.github-disabled-actions button')];if (rows.length!==3 || rows.some(b=>!b.disabled)) throw 0;}};
        const inputs=()=>{{if (!selected('GitHub') || document.querySelector('dialog, .github-assertions')) throw 0;
            const forms=document.querySelectorAll('form.github-form');if (forms.length!==1) throw 0;const form=forms[0];
            const repository=form.querySelector('#github-toolkit-repository'),sha=form.querySelector('#github-toolkit-sha'),comparison=form.querySelector('.github-comparison-toggle input');
            if (!repository || !sha || !comparison || [repository,sha].some(i=>i.type!=='text' || i.disabled || i.readOnly)
                || repository.value.length>140 || sha.value.length>40 || text(form.querySelector('.github-draft > strong'))!=='workflow-project · current draft') throw 0;
            return {{repository,sha,comparison}};}};
        const count=(raw,suffix)=>{{if (!raw.endsWith(suffix)) throw 0;const n=raw.slice(0,-suffix.length);
            if (!/^(?:[0-9]{{1,5}}|[0-9]{{1,2}},[0-9]{{3}})$/.test(n)) throw 0;return Number(n.replace(',',''));}};
        const cellText=cell=>[...cell.childNodes].filter(n=>n.nodeType===Node.TEXT_NODE).map(n=>n.textContent).join('');
        const inventory=root=>{{const tables=root.querySelectorAll('.workflow-files table');if (tables.length!==1) throw 0;
            const table=tables[0];if (text(table.querySelector('caption'))!=='Complete native workflow inventory — all four or refuse') throw 0;
            const rows=[...table.querySelectorAll('tbody > tr')];if (rows.length!==4) throw 0;
            return rows.map(row=>{{show(row);const cells=[...row.querySelectorAll(':scope > td')];if (cells.length!==3) throw 0;
                const label=text(cells[0]),action=label==='Create absent file'?'create':label==='Preserve exact original'?'preserve':null;
                if (!action) throw 0;const absent=text(cells[1])==='Observed absent';
                return {{path:text(row.querySelector(':scope > th code')),action,
                    observed:absent?{{state:'absent'}}:{{state:'present',byteLength:count(cellText(cells[1]),' bytes'),sha256:text(cells[1].querySelector('code'))}},
                    generated:{{byteLength:count(cellText(cells[2]),' bytes'),sha256:text(cells[2].querySelector('code'))}}}};}});
        }};
        const reviewDisplay=review=>{{const rows=[...review.querySelectorAll('details.github-workflow')];if (rows.length!==4 || rows.some(row=>!row.open)) throw 0;
            const texts=rows.map(row=>{{const pre=row.querySelector('pre');show(pre);return {{path:text(row.querySelector('summary > code')),
                badge:text(row.querySelector('summary > .badge')),label:pre.getAttribute('aria-label'),content:text(pre.querySelector('code'))}};}});
            const facts=[...review.querySelectorAll(':scope > .github-facts > div')].map(row=>{{show(row);return [text(row.querySelector('dt')),text(row.querySelector('dd'))];}});
            return {{files:inventory(review),texts,basis:text(review.querySelector('.review-basis strong')),facts,
                note:text(review.querySelector(':scope > .save-note')),caution:text(review.querySelector(':scope > .review-caution'))}};
        }};
        const confirmation=()=>{{const dialogs=document.querySelectorAll('dialog');if (!selected('GitHub') || dialogs.length!==1) throw 0;
            const dialog=dialogs[0];if (!dialog.classList.contains('workflow-confirm-dialog') || !dialog.open || dialog.querySelector('[role="alert"]')) throw 0;
            const checks=dialog.querySelectorAll('.save-confirm-choice input[type="checkbox"]'),buttons=[...dialog.querySelectorAll('.button-row > button')];
            if (checks.length!==1 || checks[0].disabled || buttons.length!==2 || buttons[0].disabled || text(buttons[0])!=='Keep reviewing'
                || !['Apply reviewed local files','Confirm unchanged plan'].includes(text(buttons[1]))
                || text(dialog.querySelector('.save-confirm-choice'))!=='I reviewed all four paths and complete text. This only installs or preserves local callers; it does not save configuration, contact GitHub or execute a release.') throw 0;
            return {{dialog,check:checks[0],keep:buttons[0],apply:buttons[1]}};}};
        const confirmationDisplay=()=>{{const c=confirmation(),p=c.dialog.querySelector('.dialog-content > p');
            const revision=/^This confirms the native plan made from draft revision ([0-9]{{1,10}}) and toolkit pin /.exec(text(p));if (!revision) throw 0;
            return {{title:text(c.dialog.querySelector('h2')),draftRevision:Number(revision[1]),pin:text(p.querySelector('code')),
                files:inventory(c.dialog),checked:c.check.checked,applyAvailable:!c.apply.disabled}};}};
        {body}
    }} catch {{ return {{state:'error'}}; }} }})()"#))
}

fn script(step: Step, case: Case) -> Option<String> {
    if let Step::Commands(step) = step { return commands::script(step, case.commands()?); }
    if let Step::Paths(path) = step { return path_script(path); }
    if let Step::Workflow(workflow) = step { return workflow_script(workflow); }
    if let Step::MetadataSave(metadata) = step { return metadata_script(metadata); }
    if let Step::VersionSave(version) = step { return version_script(version); }
    let project_name = match case { Case::WorkflowApply => "workflow-project", Case::Session(_) | Case::Commands(_) => "project", Case::MetadataSave => "metadata-project",
        Case::VersionSave => "version-project", _ => "positive-project" };
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
            if (document.querySelector('.github-proposal') || text(g.form.querySelector('.github-draft > strong')) !== projectName + ' · current draft'
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
            if (m.load.disabled || m.validate.disabled || m.review.disabled || !m.editor.querySelector('.metadata-validation-status')) return {state:'wait'};
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
        const projectName = '{project_name}';
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
                || text(review)!=='Review changes') throw 0;
            const validation=editor.querySelector('.metadata-validation-status .badge');
            const valid=validation && text(validation)==='Format-valid selected text';
            if (!valid && !review.disabled) throw 0;
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
            const files=inventory(review), ignore=[...review.querySelectorAll('.save-ignore li code')]; if (ignore.length>{ignore_limit}) throw 0;
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
    }} catch {{ return {{state:'error'}}; }} }})()"#, ignore_limit = IGNORE_LINES.len()))
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
        Some(value) if value == OsStr::new("workflow-apply") => Some(Case::WorkflowApply),
        Some(value) if value == OsStr::new("session-inputs") => Some(Case::Session(SessionCase::Inputs)),
        Some(value) if value == OsStr::new("session-refusals") => Some(Case::Session(SessionCase::Refusals)),
        Some(value) if value == OsStr::new("session-loss") => Some(Case::Session(SessionCase::Loss)),
        Some(value) if value == OsStr::new("session-deadline") => Some(Case::Session(SessionCase::Deadline)),
        Some(value) if value == OsStr::new("metadata-save") => Some(Case::MetadataSave),
        Some(value) if value == OsStr::new("version-save") => Some(Case::VersionSave),
        Some(value) if cfg!(target_os = "linux") && value == OsStr::new("settled-failure") => Some(Case::SettledFailure),
        Some(value) => commands::Case::parse(value).map(Case::Commands),
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
    assert_evidence_failure_contract();
    assert_failure_latch_contract();
    assert_snapshot_rejection_contract();
    assert_snapshot_frame_contract();
    assert_failure_quit_contract();
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    crate::credential_assessment::assert_installed_assessment_failure_contract();
    assert_file_destroyed_contract();
    assert_picker_activation_return_contract();
    assert_shell_fixture_path_contract();
    if case.session().is_some() {
        crate::runtime::assert_installed_session_selection_contract();
        crate::asset_session::assert_installed_session_owner_contract();
        assert_session_recipe_contract();
        assert_session_display_contract();
    }
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
    if case == Case::WorkflowApply {
        crate::asset_session::assert_project_selection_gate_contract();
        crate::runtime::assert_installed_workflow_profile_contract();
        crate::installed_runtime::assert_installed_workflow_slots_contract();
        crate::edit_owner::assert_installed_workflow_owner_contract();
    }
    if case == Case::MetadataSave {
        crate::asset_session::assert_project_selection_gate_contract();
        crate::runtime::assert_installed_metadata_profile_contract();
        crate::installed_runtime::assert_installed_metadata_slots_contract();
        crate::edit_owner::assert_installed_metadata_owner_contract();
        assert_metadata_open_race_contract();
    }
    if case == Case::VersionSave {
        crate::asset_session::assert_project_selection_gate_contract();
        crate::runtime::assert_installed_version_profile_contract();
        crate::installed_runtime::assert_installed_version_slots_contract();
        crate::edit_owner::assert_installed_version_owner_contract();
        assert_version_open_race_contract();
    }
    if case.commands().is_some() { commands::assert_contracts(); }
    // Routing DATA is not native admission. The ordinary builder constructs
    // DesktopBridge::new / RuntimeConfig::packaged and owes every real check.
    let returned = super::run_builder(super::builder().manage(q.clone()));
    if !matches!(returned, Ok(0)) || !q.finish() {
        q.fail(); q.report_failure();
        q.report_failure_handoff(matches!(&returned, Ok(0)));
        super::diagnostic(b"MRK_INSTALLED_SHELL_OBSERVATION=failed\n");
        return std::process::ExitCode::FAILURE;
    }
    let line: &[u8] = match case {
        Case::Positive => b"MRK_INSTALLED_SHELL_OBSERVATION=positive-verified\n",
        Case::Outstanding => b"MRK_INSTALLED_SHELL_OBSERVATION=quit-outstanding-verified\n",
        Case::ProjectPaths => b"MRK_INSTALLED_SHELL_OBSERVATION=project-paths-verified\n",
        Case::WorkflowApply => b"MRK_INSTALLED_SHELL_OBSERVATION=workflow-apply-verified\n",
        Case::Session(SessionCase::Inputs) => b"MRK_INSTALLED_SHELL_OBSERVATION=session-inputs-verified\n",
        Case::Session(SessionCase::Refusals) => b"MRK_INSTALLED_SHELL_OBSERVATION=session-refusals-verified\n",
        Case::Session(SessionCase::Loss) => b"MRK_INSTALLED_SHELL_OBSERVATION=session-loss-verified\n",
        Case::Session(SessionCase::Deadline) => b"MRK_INSTALLED_SHELL_OBSERVATION=session-deadline-verified\n",
        Case::MetadataSave => b"MRK_INSTALLED_SHELL_OBSERVATION=metadata-save-verified\n",
        Case::VersionSave => b"MRK_INSTALLED_SHELL_OBSERVATION=version-save-verified\n",
        Case::Commands(case) => case.verified_line(),
        // A missing deliberate rejection must never become a positive receipt.
        Case::SettledFailure => return std::process::ExitCode::FAILURE,
    };
    let mut stdout = std::io::stdout().lock();
    if stdout.write_all(b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n")
        .and_then(|_| {
            if let Some(commands) = &q.commands {
                let report = commands.report().ok_or_else(|| std::io::Error::other("tools/offline receipt unavailable"))?;
                stdout.write_all(b"MRK_INSTALLED_SHELL_TOOLS_OFFLINE=")?;
                stdout.write_all(&report)?; return stdout.write_all(b"\n");
            }
            if case == Case::VersionSave {
                let report = q.version_report().ok_or_else(||std::io::Error::other("version receipt unavailable"))?;
                stdout.write_all(b"MRK_INSTALLED_SHELL_VERSION_SAVE=")?;
                stdout.write_all(&report)?; return stdout.write_all(b"\n");
            }
            if case == Case::MetadataSave {
                let report = q.metadata_report().ok_or_else(||std::io::Error::other("metadata receipt unavailable"))?;
                stdout.write_all(b"MRK_INSTALLED_SHELL_METADATA_SAVE=")?;
                stdout.write_all(&report)?; return stdout.write_all(b"\n");
            }
            if case.session().is_some() {
                let report = q.session_report().ok_or_else(|| std::io::Error::other("session receipt unavailable"))?;
                // finish already joined/checked all original queries. Only
                // now, after CONTRACTS, emit their retained maps in the frozen
                // parser order; never publish an early contract to fit it.
                stdout.flush()?;
                q.report_session_queries()?;
                stdout.write_all(b"MRK_INSTALLED_SHELL_SESSION_INPUTS=")?;
                stdout.write_all(&report)?; return stdout.write_all(b"\n");
            }
            if case == Case::WorkflowApply {
                let report = q.workflow_report().ok_or_else(|| std::io::Error::other("workflow receipt unavailable"))?;
                stdout.write_all(b"MRK_INSTALLED_SHELL_WORKFLOW_APPLY=")?;
                stdout.write_all(&report)?; return stdout.write_all(b"\n");
            }
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

// BEGIN installed session fixture inventory (root-owned)
// Metadata and finite directory rosters only. The outside publication owner
// hashes the fictional bytes; SourceBook alone owns any open source original.
// This object never opens a file body, repairs a fixture, or grants cleanup.
const SESSION_FIXTURE_NAMESPACE: [&str; 19] = [
    "candidate-evidence", "metadata-project", "offline-cancel", "offline-drift", "offline-negative", "offline-pass", "offline-settlement",
    "path-outside", "path-project", "positive-project", "session-deadline", "session-inputs", "session-loss", "session-refusals",
    "tools-cancel", "tools-observed", "tools-settlement", "version-project", "workflow-project",
];
const SESSION_FIXTURE_COMMON: [(&str, u64, u64); 9] = [
    (".", 0o040700, 0), ("project", 0o040700, 0),
    ("project/release", 0o040700, 0), ("sources", 0o040700, 0),
    ("project/release/mobile-release.json", 0o100600, 608),
    ("project/version.properties", 0o100600, 34),
    ("sources/input.jks", 0o100600, 12),
    ("sources/replacement.jks", 0o100600, 12),
    ("sources/firebase.json", 0o100600, 95),
];
const SESSION_FIXTURE_REFUSALS: [(&str, u64, u64); 6] = [
    ("project/overlap.jks", 0o100600, 12),
    ("sources/changed.jks", 0o100600, 12),
    ("sources/changed-next.jks", 0o100600, 12),
    ("sources/public.jks", 0o100644, 12),
    ("sources/firebase-mismatch.json", 0o100600, 93),
    ("sources/link.jks", 0o120777, 9),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionFixturePhase { Original, Attempted, Changed }

struct SessionFixture {
    case: SessionCase,
    root: PathBuf,
    // Namespace is first (all nine identity fields); protected shared ancestors and
    // the search-only control root retain identity/mode/owner, not timestamps
    // that unrelated activity in /var/lib can legitimately change.
    ancestors: Vec<(PathBuf, FixtureIdentity)>,
    originals: Vec<(&'static str, FixtureIdentity)>,
    phase: SessionFixturePhase,
}

fn session_fixture_nodes(case: SessionCase, changed: bool) -> Vec<(&'static str, u64, u64)> {
    let mut nodes = SESSION_FIXTURE_COMMON.to_vec();
    if case == SessionCase::Refusals {
        nodes.extend(SESSION_FIXTURE_REFUSALS.into_iter()
            .filter(|(name, _, _)| !changed || *name != "sources/changed-next.jks"));
    }
    nodes
}

fn session_fixture_children(nodes: &[(&'static str, u64, u64)], name: &str) -> Vec<&'static str> {
    let parent = Path::new(if name == "." { "" } else { name });
    nodes.iter().filter_map(|(child, _, _)| {
        let child = Path::new(*child);
        (child.parent() == Some(parent)).then(|| child.file_name().and_then(OsStr::to_str)).flatten()
    }).collect()
}

fn assert_session_fixture_roster_contract() {
    // Exercise the actual bounded child-name derivation, without filesystem
    // access or treating these synthetic rows as a native observation.
    for case in [SessionCase::Inputs, SessionCase::Refusals, SessionCase::Loss, SessionCase::Deadline] {
        let nodes = session_fixture_nodes(case, false);
        assert_eq!(nodes.len(), if case == SessionCase::Refusals { 15 } else { 9 });
        let mut names: Vec<_> = nodes.iter().map(|(name, _, _)| *name).collect();
        names.sort(); names.dedup(); assert_eq!(names.len(), nodes.len());
        let children = |parent| { let mut names = session_fixture_children(&nodes, parent); names.sort(); names };
        assert_eq!(children("."), ["project", "sources"]);
        assert_eq!(children("project/release"), ["mobile-release.json"]);
        assert_eq!(children("project"), if case == SessionCase::Refusals {
            vec!["overlap.jks", "release", "version.properties"]
        } else { vec!["release", "version.properties"] });
        assert_eq!(children("sources"), if case == SessionCase::Refusals {
            vec!["changed-next.jks", "changed.jks", "firebase-mismatch.json", "firebase.json", "input.jks", "link.jks", "public.jks", "replacement.jks"]
        } else { vec!["firebase.json", "input.jks", "replacement.jks"] });
    }
    let before = session_fixture_nodes(SessionCase::Refusals, false);
    let after = session_fixture_nodes(SessionCase::Refusals, true);
    assert_eq!(after.len(), 14);
    assert_eq!(after, before.into_iter().filter(|(name, _, _)| *name != "sources/changed-next.jks").collect::<Vec<_>>());
    assert!(!session_fixture_children(&after, "sources").contains(&"changed-next.jks"));
}

fn session_fixture_directory(path: &Path, expected: &[&str]) -> Result<(), ()> {
    let mut found = Vec::with_capacity(expected.len());
    for entry in std::fs::read_dir(path).map_err(|_| ())? {
        let name = entry.map_err(|_| ())?.file_name().into_string().map_err(|_| ())?;
        if found.len() >= expected.len() || !expected.contains(&name.as_str()) { return Err(()); }
        found.push(name);
    }
    found.sort();
    let mut expected = expected.to_vec(); expected.sort();
    if found.iter().map(String::as_str).ne(expected) { return Err(()); }
    Ok(())
}

impl SessionFixture {
    fn capture(project: &Path, case: SessionCase) -> Result<Self, ()> {
        let executable = std::env::current_exe().map_err(|_| ())?;
        let positive = project_path_from_executable(&executable).ok_or(())?;
        let namespace = positive.parent().ok_or(())?;
        let root = namespace.join(case.name());
        if project.as_os_str() != root.join("project").as_os_str()
            || rustix::process::getuid().as_raw() == 0 || rustix::process::getgid().as_raw() == 0
            || rustix::process::getuid() != rustix::process::geteuid()
            || rustix::process::getgid() != rustix::process::getegid() { return Err(()); }
        let mut ancestors: Vec<(PathBuf, FixtureIdentity)> = Vec::with_capacity(5);
        for path in namespace.ancestors() {
            if ancestors.len() >= 4 { return Err(()); }
            let id = fixture_identity(path)?;
            if id[0] == 0 || id[1] == 0 || id[2] & 0o170000 != 0o040000
                || id[2] & 0o022 != 0 || id[3..5] != [0, 0]
                || (if path == namespace {
                    id[2] != 0o040755 || id[5] == 0 || id[5] > (SESSION_FIXTURE_NAMESPACE.len() as u64 + 2) || id[6] > 1 << 20
                } else { id[2] & 0o005 != 0o005 })
                || ancestors.iter().any(|(_, old)| old[0] != id[0] || old[..2] == id[..2]) { return Err(()); }
            ancestors.push((path.to_path_buf(), id));
        }
        if ancestors.len() != 4 { return Err(()); }
        let control = control_root_from_executable(&executable).ok_or(())?;
        let id = fixture_identity(&control)?;
        if id[0] != ancestors[0].1[0] || id[1] == 0 || id[2..5] != [0o040711, 0, 0]
            || ancestors.iter().any(|(_, old)| old[..2] == id[..2]) { return Err(()); }
        ancestors.push((control, id));
        let mut fixture = Self { case, root, ancestors, originals: Vec::new(), phase: SessionFixturePhase::Original };
        fixture.originals = fixture.inventory(false)?;
        fixture.verify()?;
        Ok(fixture)
    }

    fn namespace_unchanged(&self) -> Result<(), ()> {
        for (index, (path, old)) in self.ancestors.iter().enumerate() {
            let now = fixture_identity(path)?;
            if if index == 0 { now != *old } else { now[..5] != old[..5] } { return Err(()); }
        }
        let (namespace, original) = &self.ancestors[0];
        session_fixture_directory(namespace, &SESSION_FIXTURE_NAMESPACE)?;
        if fixture_identity(namespace)? != *original { return Err(()); }
        Ok(())
    }

    fn inventory(&self, changed: bool) -> Result<Vec<(&'static str, FixtureIdentity)>, ()> {
        self.namespace_unchanged()?;
        let specs = session_fixture_nodes(self.case, changed);
        let mut rows: Vec<(&'static str, FixtureIdentity)> = Vec::with_capacity(specs.len());
        for &(name, mode, size) in &specs {
            let path = if name == "." { self.root.clone() } else { self.root.join(name) };
            let id = fixture_identity(&path)?;
            if id[0] != self.ancestors[0].1[0] || id[1] == 0 || id[2] != mode
                || id[3] != u64::from(rustix::process::getuid().as_raw())
                || id[4] != u64::from(rustix::process::getgid().as_raw())
                || self.ancestors.iter().any(|(_, old)| old[..2] == id[..2])
                || rows.iter().any(|(_, old)| old[..2] == id[..2]) { return Err(()); }
            if mode == 0o040700 {
                if id[5] == 0 || id[5] > 16 || id[6] > 1 << 20 { return Err(()); }
                let children = session_fixture_children(&specs, name);
                session_fixture_directory(&path, &children)?;
            } else {
                if id[5] != 1 || id[6] != size { return Err(()); }
                if mode == 0o120777 && std::fs::read_link(&path).map_err(|_| ())?.as_os_str() != OsStr::new("input.jks") {
                    return Err(());
                }
            }
            if fixture_identity(&path)? != id { return Err(()); }
            rows.push((name, id));
        }
        // Rechecking every original also catches changes during later roster
        // observations. The exact rosters exclude all pending/unknown names.
        for (name, id) in &rows {
            let path = if *name == "." { self.root.clone() } else { self.root.join(name) };
            if fixture_identity(&path)? != *id { return Err(()); }
        }
        self.namespace_unchanged()?;
        Ok(rows)
    }

    fn verify(&self) -> Result<(), ()> {
        if self.phase == SessionFixturePhase::Attempted
            || self.inventory(self.changed())? != self.originals { return Err(()); }
        Ok(())
    }

    fn change_source(&mut self) -> Result<(), ()> {
        if self.case != SessionCase::Refusals || self.phase != SessionFixturePhase::Original { return Err(()); }
        // Consume the one attempt even if precheck fails. Neither an error nor
        // an uncertain postcheck permits a second mutation or a fresh baseline.
        self.phase = SessionFixturePhase::Attempted;
        if self.inventory(false)? != self.originals { return Err(()); }
        let before_next = self.originals.iter().find(|(name, _)| *name == "sources/changed-next.jks").ok_or(())?.1;
        std::fs::rename(self.root.join("sources/changed-next.jks"), self.root.join("sources/changed.jks")).map_err(|_| ())?;
        let after = self.inventory(true)?;
        if after.len().checked_add(1) != Some(self.originals.len()) { return Err(()); }
        for (name, now) in &after {
            let old = self.originals.iter().find(|(prior, _)| prior == name).ok_or(())?.1;
            let accepted = match *name {
                "sources" => now[..6] == old[..6],
                "sources/changed.jks" => now[..8] == before_next[..8],
                _ => *now == old,
            };
            if !accepted { return Err(()); }
        }
        // Store the observed post-rename ctime and directory metadata once;
        // later verification may not forgive another timestamp/identity drift.
        if self.inventory(true)? != after { return Err(()); }
        self.originals = after;
        self.phase = SessionFixturePhase::Changed;
        Ok(())
    }

    fn changed(&self) -> bool { self.phase == SessionFixturePhase::Changed }
}
// END installed session fixture inventory (root-owned)
