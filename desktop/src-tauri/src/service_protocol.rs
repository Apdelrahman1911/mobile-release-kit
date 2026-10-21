//! Closed application-observation protocol shared by the GUI host and CLI.
//!
//! These are DATA, not document, filesystem, credential or finality witnesses.
//! In particular, a deserialized operation status cannot settle original work.
use serde::{Deserialize, Serialize};
use std::fmt;

pub const VERSION: u32 = 1;
pub const REQUEST_BYTES: usize = 4096;
pub const RESPONSE_BYTES: usize = 256 * 1024;
pub const PROJECT_LIMIT: usize = 64;
pub const OPERATION_LIMIT: usize = 256;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Id(String);
impl Id {
    pub fn parse(value: &str) -> Result<Self, Error> {
        if value.len() != 32 || value.bytes().all(|b| b == b'0')
            || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(Error::InvalidRequest);
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str { &self.0 }
    pub(crate) fn retained_bytes(&self) -> usize { self.0.capacity() }
    pub(crate) fn random() -> Result<Self, Error> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| Error::Unavailable)?;
        Self::parse(&hex(&bytes)).map_err(|_| Error::Unavailable)
    }
}
impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("Id(..)") }
}
impl TryFrom<String> for Id {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Self::Error> { Self::parse(&value) }
}
impl From<Id> for String { fn from(value: Id) -> Self { value.0 } }

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes { text.push(DIGITS[(byte >> 4) as usize] as char); text.push(DIGITS[(byte & 15) as usize] as char); }
    text
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    InvalidRequest, Unavailable, AccessDenied, Expired, Busy, Conflict,
    RecoveryRequired, StateUnknown, UnsupportedPlatform,
}
impl Error {
    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidRequest => "The service request is invalid or unsupported.",
            Self::Unavailable => "Enable Desktop agent read access, or explicitly start mrk serve-history for cached reads only.",
            Self::AccessDenied => "This host or grant does not allow the request. Actions require separate Desktop permission; serve-history allows only five cached reads.",
            Self::Expired => "Read access expired. Explicitly allow it in Desktop or start a new foreground history invocation; access is not renewed automatically.",
            Self::Busy => "The application service is busy. Try again after current work settles.",
            Self::Conflict => "Saved service state changed. Reopen Desktop and inspect the conflict; do not replace the state files.",
            Self::RecoveryRequired => "Application service state needs recovery. Preserve its files; it has not been reset.",
            Self::StateUnknown => "Service storage or shutdown is unconfirmed. Preserve state and do not retry a mutation.",
            Self::UnsupportedPlatform => "This platform does not yet support the installed agent service.",
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.message()) }
}
impl std::error::Error for Error {}

/// Exact native-vault reference. A preference never authenticates a payload or
/// authorizes its use; the original vault must reassess and explicitly bind it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialReference {
    pub vault_id: Id,
    pub generation_id: Id,
    pub record_id: Id,
    pub revision_id: Id,
    pub revision_counter: u32,
}
impl CredentialReference {
    pub fn validate(&self) -> Result<(), Error> {
        if self.revision_counter == 0 || self.vault_id == self.generation_id
            || self.record_id == self.vault_id || self.record_id == self.generation_id
            || self.revision_id == self.vault_id || self.revision_id == self.generation_id || self.revision_id == self.record_id {
            Err(Error::InvalidRequest)
        } else { Ok(()) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    ObserveProject, EditConfiguration, EditProjectIdentity, GitStage, GitUnstage,
    GitCommit, GitFetch, GitPush, GitPushNewBranch, GitInitialize, GitBranchCreate, GitBranchSwitch, GitBranchRename, GitFastForward, GitSetUpstream, AssignCredential, GenerateCredential, Build, Release, LocalProjectChecks,
}

/// Future operation-specific adapters may compare this DATA with a genuine
/// service-owned permit. Receiving this object alone never creates a permit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationContext {
    pub project_id: Id,
    pub client_id: Id,
    pub session_id: Id,
    pub action: Action,
    pub expected_observation_revision: u64,
    pub operation_id: Id,
    pub authorization_id: Id,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationState {
    Prepared, Running, Succeeded, Failed, CancellationRequested, Cancelled,
    RecoveryRequired, Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Settlement { Pending, Settled, Unknown }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationObservation {
    pub operation_id: Id,
    pub project_id: Id,
    pub action: Action,
    pub state: OperationState,
    pub settlement: Settlement,
    pub observation_revision: u64,
    pub stale: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigurationState { Missing, Invalid, FormatValid, Unavailable }

/// The original passive engine's redacted saved-file summary, not config data,
/// source text, arbitrary issues, paths, secret values or account identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedConfiguration {
    pub state: ConfigurationState,
    pub bytes: Option<u64>,
    pub sha256: Option<String>,
}
impl SavedConfiguration {
    pub fn validate(&self) -> Result<(), Error> {
        if self.bytes.is_some() != self.sha256.is_some()
            || self.bytes.is_some_and(|bytes| bytes > 1024 * 1024)
            || self.sha256.as_ref().is_some_and(|hash| hash.len() != 64
                || !hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            || self.state == ConfigurationState::Missing && self.bytes.is_some() {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedObservation {
    pub revision: u64,
    pub stale: bool,
    pub configuration: SavedConfiguration,
    pub discovery_partial: bool,
    pub issue_count: u32,
    #[serde(default, deserialize_with = "crate::service_setup_guidance::deserialize_optional", skip_serializing_if = "Option::is_none")]
    pub setup_analysis: Option<crate::service_setup_guidance::SetupAnalysis>,
}
impl SavedObservation {
    // Optional guidance cannot contradict its enclosing saved observation or
    // conceal a failure of the required base fields. It grants no operation.
    pub(crate) fn normalize_setup_analysis(&mut self) {
        if self.setup_analysis.as_ref().is_some_and(|analysis|
            !analysis.matches(self.configuration.state, self.discovery_partial)) {
            self.setup_analysis = None;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectObservation {
    pub project_id: Id,
    /// Remembered projects are not automatically native registrations.
    pub registered_in_current_host: bool,
    pub observation: Option<SavedObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectQuery { pub project_id: Id }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationQuery { pub project_id: Id, pub operation_id: Id }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", deny_unknown_fields)]
pub enum RequestBody {
    #[serde(rename="play-cleanup.submit")] PlayCleanupSubmit(crate::service_play_cleanup_protocol::Submit),
    #[serde(rename="play-cleanup.status")] PlayCleanupStatus(crate::service_play_cleanup_protocol::Query),
    #[serde(rename="play-cleanup.cancel")] PlayCleanupCancel(crate::service_play_cleanup_protocol::Query),
    #[serde(rename="upload-key.scope")] UploadKeyScope(ProjectQuery),
    #[serde(rename="upload-key.submit")] UploadKeySubmit(crate::service_upload_key_protocol::Submit),
    #[serde(rename="upload-key.status")] UploadKeyStatus(crate::service_upload_key_protocol::Query),
    #[serde(rename="upload-key.cancel")] UploadKeyCancel(crate::service_upload_key_protocol::Query),
    #[serde(rename="configuration.read")] ConfigurationRead(crate::service_configuration_protocol::Read),
    #[serde(rename="configuration.prepare")] ConfigurationPrepare(crate::service_configuration_protocol::Prepare),
    #[serde(rename="configuration.apply")] ConfigurationApply(crate::service_configuration_protocol::Apply),
    #[serde(rename="configuration.status")] ConfigurationStatus(crate::service_configuration_protocol::Query),
    #[serde(rename="configuration.cancel")] ConfigurationCancel(crate::service_configuration_protocol::Query),
    #[serde(rename="store.submit")] StoreSubmit(crate::service_store_protocol::Submit),
    #[serde(rename="apple-provisioning.submit")] AppleProvisioningSubmit(crate::service_apple_provisioning_protocol::Submit),
    #[serde(rename="store.status")] StoreStatus(crate::service_store_protocol::Query),
    #[serde(rename="apple-provisioning.status")] AppleProvisioningStatus(crate::service_apple_provisioning_protocol::Query),
    #[serde(rename="store.cancel")] StoreCancel(crate::service_store_protocol::Query),
    #[serde(rename="apple-provisioning.cancel")] AppleProvisioningCancel(crate::service_apple_provisioning_protocol::Query),
    #[serde(rename="version-reserve.submit")] VersionReserveSubmit(crate::service_version_reserve_protocol::Submit),
    #[serde(rename="version-reserve.status")] VersionReserveStatus(crate::service_version_reserve_protocol::Query),
    #[serde(rename="version-reserve.cancel")] VersionReserveCancel(crate::service_version_reserve_protocol::Query),
    #[serde(rename="git-index.scope")] GitIndexScope(ProjectQuery),
    #[serde(rename="git-index.prepare")] GitIndexPrepare(crate::service_git_protocol::Prepare),
    #[serde(rename="git-index.start")] GitIndexStart(crate::service_git_protocol::Start),
    #[serde(rename="git-index.status")] GitIndexStatus(crate::service_git_protocol::Query),
    #[serde(rename="git-index.cancel")] GitIndexCancel(crate::service_git_protocol::Query),
    #[serde(rename="git-commit.scope")] GitCommitScope(ProjectQuery),
    #[serde(rename="git-commit.prepare")] GitCommitPrepare(crate::service_git_commit_protocol::Prepare),
    #[serde(rename="git-commit.start")] GitCommitStart(crate::service_git_commit_protocol::Start),
    #[serde(rename="git-commit.status")] GitCommitStatus(crate::service_git_commit_protocol::Query),
    #[serde(rename="git-commit.cancel")] GitCommitCancel(crate::service_git_commit_protocol::Query),
    #[serde(rename="git-repository.scope")] GitRepositoryScope(ProjectQuery),
    #[serde(rename="git-repository.prepare")] GitRepositoryPrepare(crate::service_git_repository_protocol::Prepare),
    #[serde(rename="git-repository.start")] GitRepositoryStart(crate::service_git_repository_protocol::Start),
    #[serde(rename="git-repository.status")] GitRepositoryStatus(crate::service_git_repository_protocol::Query),
    #[serde(rename="git-repository.cancel")] GitRepositoryCancel(crate::service_git_repository_protocol::Query),
    #[serde(rename="git-remote.scope")] GitRemoteScope(ProjectQuery),
    #[serde(rename="git-remote.prepare")] GitRemotePrepare(crate::service_git_remote_protocol::Prepare),
    #[serde(rename="git-remote.start")] GitRemoteStart(crate::service_git_remote_protocol::Start),
    #[serde(rename="git-remote.status")] GitRemoteStatus(crate::service_git_remote_protocol::Query),
    #[serde(rename="git-remote.cancel")] GitRemoteCancel(crate::service_git_remote_protocol::Query),
    #[serde(rename = "service.info")] Info(Empty),
    #[serde(rename = "projects.list")] Projects(Empty),
    #[serde(rename = "project.observation")] Observe(ProjectQuery),
    #[serde(rename = "android-tools.observation")] AndroidTools(ProjectQuery),
    #[serde(rename = "request.list")] Requests(ProjectQuery),
    #[serde(rename = "repository.observation")] Repository(ProjectQuery),
    #[serde(rename = "operation.list")] Operations(ProjectQuery),
    #[serde(rename = "operation.status")] Operation(OperationQuery),
    #[serde(rename = "local-check.submit")] LocalCheckSubmit(crate::agent_local_checks::Submit),
    #[serde(rename = "local-check.status")] LocalCheckStatus(crate::agent_local_checks::Query),
    #[serde(rename = "local-check.cancel")] LocalCheckCancel(crate::agent_local_checks::Query),
    #[serde(rename = "android-build.prepare")] AndroidBuildPrepare(crate::agent_android_build::Prepare),
    #[serde(rename = "android-build.start")] AndroidBuildStart(crate::agent_android_build::Start),
    #[serde(rename = "android-build.status")] AndroidBuildStatus(crate::agent_android_build::Query),
    #[serde(rename = "android-build.cancel")] AndroidBuildCancel(crate::agent_android_build::Query),
    #[serde(rename = "ios-archive.prepare")] IosArchivePrepare(crate::agent_ios_archive::Prepare),
    #[serde(rename = "ios-archive.start")] IosArchiveStart(crate::agent_ios_archive::Start),
    #[serde(rename = "ios-archive.status")] IosArchiveStatus(crate::agent_ios_archive::Query),
    #[serde(rename = "ios-archive.cancel")] IosArchiveCancel(crate::agent_ios_archive::Query),
    #[serde(rename = "identity.request")] IdentitySubmit(crate::agent_identity_requests::Submit),
    #[serde(rename = "identity.request-status")] IdentityIntent(crate::agent_identity_requests::Query),
    #[serde(rename = "identity.prepare")] IdentityPrepare(crate::agent_identity_requests::Query),
    #[serde(rename = "identity.start")] IdentityStart(crate::agent_identity_requests::actions::Start),
    #[serde(rename = "identity.status")] IdentityActionStatus(crate::agent_identity_requests::Query),
    #[serde(rename = "identity.cancel")] IdentityCancel(crate::agent_identity_requests::Query),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request { pub version: u32, pub request_id: Id, pub request: RequestBody }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceInfo {
    pub read_only: bool,
    pub read_grant_authorizes_execution: bool,
    pub local_checks_require_separate_grant: bool,
    pub requires_running_desktop: bool,
    pub cached_observations_are_authority: bool,
    pub remaining_access_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ResponseBody {
    PlayCleanupRequest(crate::service_play_cleanup_protocol::Status),
    UploadKeyAccess(crate::service_upload_key_protocol::Access),
    UploadKeyRequest(crate::service_upload_key_protocol::Status),
    ConfigurationRequest(crate::service_configuration_protocol::Status),
    VersionReserveRequest(crate::service_version_reserve_protocol::Status),
    StoreRequest(crate::service_store_protocol::Status),
    AppleProvisioningRequest(crate::service_apple_provisioning_protocol::Status),
    GitIndexScope(crate::service_git_protocol::Scope),
    GitIndexRequest(crate::service_git_protocol::Status),
    GitCommitScope(crate::service_git_commit_protocol::Scope),
    GitCommitRequest(crate::service_git_commit_protocol::Status),
    GitRepositoryScope(crate::service_git_repository_protocol::Scope),
    GitRepositoryRequest(crate::service_git_repository_protocol::Status),
    GitRemoteScope(crate::service_git_remote_protocol::Scope),
    GitRemoteRequest(crate::service_git_remote_protocol::Status),
    Info(ServiceInfo), Projects(Vec<ProjectObservation>), Observation(ProjectObservation),
    Operations(Vec<OperationObservation>), Operation(OperationObservation), Error(Error),
    AndroidTools(crate::service_android_tools::View),
    Requests(crate::service_request_catalogue::Catalogue),
    Repository(crate::service_repository_summary::View),
    IdentityIntent(crate::agent_identity_requests::IntentStatus),
    IdentityAction(crate::agent_identity_requests::actions::Status),
    LocalCheck(crate::agent_local_checks::Status),
    AndroidBuildRequest(crate::agent_android_build::Status),
    IosArchiveRequest(crate::agent_ios_archive::Status),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Response {
    pub version: u32,
    pub request_id: Id,
    pub service_instance: Id,
    pub client_id: Id,
    pub session_id: Id,
    pub response: ResponseBody,
}

fn nesting(bytes: &[u8]) -> Result<(), Error> {
    let (mut depth, mut quoted, mut escape) = (0u32, false, false);
    for byte in bytes {
        if quoted {
            if escape { escape = false; } else if *byte == b'\\' { escape = true; } else if *byte == b'"' { quoted = false; }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => { depth += 1; if depth > 16 { return Err(Error::InvalidRequest); } }
                b'}' | b']' => { depth = depth.checked_sub(1).ok_or(Error::InvalidRequest)?; }
                _ => {}
            }
        }
    }
    if depth != 0 || quoted { return Err(Error::InvalidRequest); }
    Ok(())
}
pub fn decode_request(bytes: &[u8]) -> Result<Request, Error> {
    if bytes.is_empty() || bytes.len() > REQUEST_BYTES { return Err(Error::InvalidRequest); }
    nesting(bytes)?;
    let request: Request = serde_json::from_slice(bytes).map_err(|_| Error::InvalidRequest)?;
    if request.version != VERSION { return Err(Error::InvalidRequest); }
    if matches!(&request.request,RequestBody::PlayCleanupSubmit(_)|RequestBody::PlayCleanupStatus(_)|RequestBody::PlayCleanupCancel(_))
        && bytes.len()>crate::service_play_cleanup_protocol::RAW_LIMIT {return Err(Error::InvalidRequest);}
    if matches!(&request.request, RequestBody::UploadKeyScope(_) | RequestBody::UploadKeySubmit(_) | RequestBody::UploadKeyStatus(_) | RequestBody::UploadKeyCancel(_))
        && bytes.len() > crate::service_upload_key_protocol::RAW_LIMIT { return Err(Error::InvalidRequest); }
    if matches!(&request.request,RequestBody::StoreSubmit(_)|RequestBody::StoreStatus(_)|RequestBody::StoreCancel(_))
        &&bytes.len()>crate::service_store_protocol::RAW_LIMIT{return Err(Error::InvalidRequest);}
    if matches!(&request.request,RequestBody::AppleProvisioningSubmit(_)|RequestBody::AppleProvisioningStatus(_)|RequestBody::AppleProvisioningCancel(_))
        &&bytes.len()>crate::service_apple_provisioning_protocol::RAW_LIMIT{return Err(Error::InvalidRequest);}
    if matches!(&request.request, RequestBody::VersionReserveSubmit(_) | RequestBody::VersionReserveStatus(_) | RequestBody::VersionReserveCancel(_))
        && bytes.len() > crate::service_version_reserve_protocol::RAW_LIMIT { return Err(Error::InvalidRequest); }
    if let RequestBody::GitIndexStart(input) | RequestBody::GitCommitStart(input) | RequestBody::GitRepositoryStart(input) | RequestBody::GitRemoteStart(input) = &request.request { input.validate()?; }
    if let RequestBody::ConfigurationRead(input)=&request.request{if input.expected_observation_revision==0{return Err(Error::InvalidRequest);}}
    if let RequestBody::ConfigurationPrepare(input)=&request.request{input.change.validate()?;}
    if let RequestBody::ConfigurationApply(input)=&request.request{if !input.reviewed{return Err(Error::InvalidRequest);}}
    if let RequestBody::IdentitySubmit(input) = &request.request { input.validate()?; }
    if let RequestBody::LocalCheckSubmit(input) = &request.request { input.validate()?; }
    if let RequestBody::AndroidBuildPrepare(input) = &request.request { input.validate()?; }
    if let RequestBody::IosArchivePrepare(input) = &request.request { input.validate()?; }
    Ok(request)
}
pub fn encode_request(request: &Request) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(request).map_err(|_| Error::InvalidRequest)?;
    decode_request(&bytes)?;
    Ok(bytes)
}
pub fn encode_response(response: &Response) -> Result<Vec<u8>, Error> {
    validate_response(response)?;
    let bytes = serde_json::to_vec(response).map_err(|_| Error::StateUnknown)?;
    if bytes.len() > RESPONSE_BYTES { return Err(Error::StateUnknown); }
    Ok(bytes)
}
pub fn decode_response(bytes: &[u8], request_id: &Id, instance: &Id) -> Result<Response, Error> {
    if bytes.is_empty() || bytes.len() > RESPONSE_BYTES { return Err(Error::InvalidRequest); }
    nesting(bytes)?;
    let mut response: Response = serde_json::from_slice(bytes).map_err(|_| Error::InvalidRequest)?;
    if response.version != VERSION || &response.request_id != request_id || &response.service_instance != instance {
        return Err(Error::Conflict);
    }
    let projects = match &mut response.response {
        ResponseBody::Projects(rows) => rows.as_mut_slice(),
        ResponseBody::Observation(row) => std::slice::from_mut(row),
        _ => &mut [],
    };
    if projects.len() > PROJECT_LIMIT { return Err(Error::InvalidRequest); }
    for project in projects {
        if let Some(saved) = &mut project.observation { saved.normalize_setup_analysis(); }
    }
    validate_response(&response)?;
    Ok(response)
}
fn validate_response(response: &Response) -> Result<(), Error> {
    fn project(project: &ProjectObservation) -> Result<(), Error> {
        if let Some(saved) = &project.observation {
            if saved.revision == 0 || saved.issue_count > 20_000 { return Err(Error::InvalidRequest); }
            saved.configuration.validate()?;
        }
        Ok(())
    }
    fn operation(operation: &OperationObservation) -> Result<(), Error> {
        use OperationState as S;
        use Settlement as F;
        let consistent = match operation.state {
            S::Prepared | S::Running | S::CancellationRequested => operation.settlement == F::Pending,
            S::Succeeded | S::Failed | S::Cancelled => operation.settlement == F::Settled,
            S::Unknown => operation.settlement == F::Unknown,
            S::RecoveryRequired => matches!(operation.settlement, F::Settled | F::Unknown),
        };
        if operation.observation_revision == 0 || !consistent { return Err(Error::InvalidRequest); }
        Ok(())
    }
    if response.version != VERSION { return Err(Error::InvalidRequest); }
    match &response.response {
        ResponseBody::PlayCleanupRequest(row)=>{
            row.validate()?;
            if row.origin.service_instance!=response.service_instance || serde_json::to_vec(response).map_err(|_|Error::InvalidRequest)?.len()>crate::service_play_cleanup_protocol::STATUS_LIMIT {
                return Err(Error::InvalidRequest);
            }
        },
        ResponseBody::Info(info) if !matches!((info.read_only, info.requires_running_desktop), (false, true) | (true, false))
            || info.read_grant_authorizes_execution || !info.local_checks_require_separate_grant || info.cached_observations_are_authority
            || info.remaining_access_ms > 3_600_000 => return Err(Error::InvalidRequest),
        ResponseBody::Projects(rows) => {
            if rows.len() > PROJECT_LIMIT { return Err(Error::InvalidRequest); }
            let mut seen = std::collections::BTreeSet::new();
            for row in rows { project(row)?; if !seen.insert(&row.project_id) { return Err(Error::InvalidRequest); } }
        }
        ResponseBody::UploadKeyAccess(row) => { row.validate()?; if serde_json::to_vec(row).map_err(|_| Error::InvalidRequest)?.len() > crate::service_upload_key_protocol::VIEW_LIMIT { return Err(Error::InvalidRequest); } },
        ResponseBody::UploadKeyRequest(row) => { row.validate()?; if serde_json::to_vec(row).map_err(|_| Error::InvalidRequest)?.len() > crate::service_upload_key_protocol::VIEW_LIMIT { return Err(Error::InvalidRequest); } },
        ResponseBody::ConfigurationRequest(row)=>{
            row.validate()?;
            if row.origin.service_instance!=response.service_instance||serde_json::to_vec(response).map_err(|_|Error::InvalidRequest)?.len()>crate::service_configuration_protocol::STATUS_BYTES{return Err(Error::InvalidRequest);}
        },
        ResponseBody::StoreRequest(row)=>{
            row.validate()?;
            if row.origin.service_instance!=response.service_instance||serde_json::to_vec(response).map_err(|_|Error::InvalidRequest)?.len()>crate::service_store_protocol::STATUS_LIMIT{return Err(Error::InvalidRequest);}
        },
        ResponseBody::AppleProvisioningRequest(row)=>{
            row.validate()?;
            if row.origin.service_instance!=response.service_instance||serde_json::to_vec(response).map_err(|_|Error::InvalidRequest)?.len()>crate::service_apple_provisioning_protocol::STATUS_LIMIT{return Err(Error::InvalidRequest);}
        },
        ResponseBody::VersionReserveRequest(row) => {
            row.validate()?;
            if row.origin.service_instance != response.service_instance
                || serde_json::to_vec(response).map_err(|_|Error::InvalidRequest)?.len() > crate::service_version_reserve_protocol::STATUS_LIMIT
            { return Err(Error::InvalidRequest); }
        },
        ResponseBody::GitIndexScope(row) => {
            row.validate()?; if row.service_instance != response.service_instance { return Err(Error::InvalidRequest); }
            crate::service_git_protocol::response_bound(response, true)?;
        },
        ResponseBody::GitIndexRequest(row) => {
            row.validate()?; if row.origin.service_instance != response.service_instance { return Err(Error::InvalidRequest); }
            crate::service_git_protocol::response_bound(response, false)?;
        },
        ResponseBody::GitCommitScope(row) => {
            row.validate()?; if row.0.service_instance != response.service_instance { return Err(Error::InvalidRequest); }
            crate::service_git_protocol::response_bound(response, true)?;
        },
        ResponseBody::GitCommitRequest(row) => {
            row.validate()?; if row.0.origin.service_instance != response.service_instance { return Err(Error::InvalidRequest); }
            crate::service_git_protocol::response_bound(response, false)?;
        },
        ResponseBody::GitRepositoryScope(row) => {
            row.validate()?; if row.service_instance != response.service_instance { return Err(Error::InvalidRequest); }
            crate::service_git_protocol::encoded_bound(response, crate::service_git_repository_protocol::ACCESS_LIMIT)?;
        },
        ResponseBody::GitRepositoryRequest(row) => {
            row.validate()?; if row.origin.service_instance != response.service_instance { return Err(Error::InvalidRequest); }
            crate::service_git_protocol::response_bound(response, false)?;
        },
        ResponseBody::GitRemoteScope(row) => {
            row.validate()?; if row.service_instance != response.service_instance { return Err(Error::InvalidRequest); }
            crate::service_git_protocol::encoded_bound(response, crate::service_git_remote_protocol::ACCESS_LIMIT)?;
        },
        ResponseBody::GitRemoteRequest(row) => {
            row.validate()?; if row.progress.origin.service_instance != response.service_instance { return Err(Error::InvalidRequest); }
            crate::service_git_protocol::response_bound(response, false)?;
        },
        ResponseBody::Observation(row) => project(row)?,
        ResponseBody::AndroidTools(row) => row.validate()?,
        ResponseBody::Repository(row) => row.validate()?,
        ResponseBody::Requests(row) => { row.validate()?; if row.service_instance != response.service_instance { return Err(Error::InvalidRequest); } },
        ResponseBody::Operations(rows) => {
            if rows.len() > OPERATION_LIMIT { return Err(Error::InvalidRequest); }
            let mut seen = std::collections::BTreeSet::new();
            for row in rows { operation(row)?; if !seen.insert(&row.operation_id) { return Err(Error::InvalidRequest); } }
        }
        ResponseBody::Operation(row) => operation(row)?,
        ResponseBody::IdentityIntent(row) => { row.validate()?; if row.service_instance != response.service_instance { return Err(Error::InvalidRequest); } },
        ResponseBody::IdentityAction(row) => { row.validate()?; if row.origin.service_instance != response.service_instance { return Err(Error::InvalidRequest); } },
        ResponseBody::LocalCheck(row) => { row.validate()?; if row.origin.service_instance != response.service_instance { return Err(Error::InvalidRequest); } },
        ResponseBody::AndroidBuildRequest(row) => { row.validate()?; if row.origin.service_instance != response.service_instance { return Err(Error::InvalidRequest); } },
        ResponseBody::IosArchiveRequest(row) => { row.validate()?; if row.origin.service_instance != response.service_instance { return Err(Error::InvalidRequest); } },
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_requests_reject_duplicate_unknown_and_generic_commands() {
        let prefix = r#"{"version":1,"requestId":"11111111111111111111111111111111","request":"#;
        for bad in [r#"{"method":"shell","params":{}}}"#, r#"{"method":"projects.list","params":{"root":"/"}}}"#,
            r#"{"method":"projects.list","method":"service.info","params":{}}}"#,
            r#"{"method":"projects.list","params":{},"params":{}}}"#] {
            assert!(decode_request(format!("{prefix}{bad}").as_bytes()).is_err());
        }
        let valid = format!(r#"{prefix}{{"method":"projects.list","params":{{}}}}}}"#);
        assert!(decode_request(valid.as_bytes()).is_ok());
        assert!(decode_request(valid.replace("\"version\":1", "\"version\":1,\"version\":1").as_bytes()).is_err());
    }
    #[test]
    fn service_info_accepts_only_desktop_or_foreground_history_tuple() {
        let request_id = Id::parse(&"1".repeat(32)).unwrap();
        let instance = Id::parse(&"2".repeat(32)).unwrap();
        for read_only in [false, true] { for requires_running_desktop in [false, true] {
            let info = ServiceInfo { read_only, requires_running_desktop, read_grant_authorizes_execution: false,
                local_checks_require_separate_grant: true, cached_observations_are_authority: false, remaining_access_ms: 30_000 };
            let response = Response { version: VERSION, request_id: request_id.clone(), service_instance: instance.clone(),
                client_id: Id::parse(&"3".repeat(32)).unwrap(), session_id: Id::parse(&"4".repeat(32)).unwrap(),
                response: ResponseBody::Info(info.clone()) };
            if read_only == requires_running_desktop { assert!(encode_response(&response).is_err()); continue; }
            let bytes = encode_response(&response).unwrap();
            assert_eq!(decode_response(&bytes, &request_id, &instance).unwrap(), response);
            for changed in [ServiceInfo { read_grant_authorizes_execution: true, ..info.clone() },
                ServiceInfo { local_checks_require_separate_grant: false, ..info.clone() },
                ServiceInfo { cached_observations_are_authority: true, ..info.clone() },
                ServiceInfo { remaining_access_ms: 3_600_001, ..info }] {
                assert!(encode_response(&Response { response: ResponseBody::Info(changed), ..response.clone() }).is_err());
            }
        }}
    }
    #[test]
    fn bounded_identifiers_and_credential_generations() {
        assert!(Id::parse("project-1").is_err());
        assert!(Id::parse(&"0".repeat(32)).is_err());
        assert!(Id::parse(&"A".repeat(32)).is_err());
        assert!(decode_request(&vec![b' '; REQUEST_BYTES + 1]).is_err());
        assert!(nesting(&[vec![b'['; 17], vec![b']'; 17]].concat()).is_err());
        let id = Id::parse(&"1".repeat(32)).unwrap();
        let reference = CredentialReference { vault_id: id.clone(), generation_id: id.clone(), record_id: id.clone(),
            revision_id: id, revision_counter: 0 };
        assert!(reference.validate().is_err());
        let valid = CredentialReference { vault_id: Id::parse(&"1".repeat(32)).unwrap(), generation_id: Id::parse(&"2".repeat(32)).unwrap(),
            record_id: Id::parse(&"3".repeat(32)).unwrap(), revision_id: Id::parse(&"4".repeat(32)).unwrap(), revision_counter: 1 };
        assert!(valid.validate().is_ok());
        for alias in [&valid.vault_id, &valid.generation_id, &valid.record_id] {
            assert!(CredentialReference { revision_id: alias.clone(), ..valid.clone() }.validate().is_err());
        }
    }
}
