//! Closed protected-workflow release request DTOs. This module owns no credential, consent,
//! filesystem, process, timer or network capability. A parsed record is DATA.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use crate::{error::BridgeError, github_connection_protocol::{bounds, coordinate, nullable,
    numeric_id, utc, GitHubReadControl}, protocol::{strict_json, valid_id}};

pub(crate) const PROTOCOL: &str = "mrk-github-release/1";
pub(crate) const EVENT: &str = "github-release-status";
pub(crate) const INITIAL_LIMIT: usize = 16 * 1024;
pub(crate) const READY_LIMIT: usize = 512;
pub(crate) const GO_LIMIT: usize = 8 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 256 * 1024;
pub(crate) const RECORD_LIMIT: usize = 64;
pub(crate) const TOOLING_REPOSITORY: &str = "Apdelrahman1911/mobile-release-kit";
pub(crate) const ASSURANCE: &str = "github-workflow-observation-not-release-evidence";
pub(crate) const TOOLING_SHA: Option<&str> = option_env!("MRK_GITHUB_RELEASE_TOOLING_SHA");
pub(crate) const CANDIDATE_SHA256: Option<&str> = option_env!("MRK_GITHUB_RELEASE_CANDIDATE_SHA256");
pub(crate) const EXTERNAL_SHA256: Option<&str> = option_env!("MRK_GITHUB_RELEASE_EXTERNAL_SHA256");
pub(crate) const PRODUCTION_SHA256: Option<&str> = option_env!("MRK_GITHUB_RELEASE_PRODUCTION_SHA256");
pub(crate) const ORIGINAL_ASSURANCE: &str = "declared-original-references-not-authenticated-release-evidence";
pub(crate) const DESTINATION_ASSURANCE: &str = "current-dispatch-config-not-authenticated-original-destination";
pub(crate) const PREPARED_LIMIT: usize = 3900;
pub(crate) const RUN_LIMIT: usize = 4096;
pub(crate) use crate::github_preflight_protocol::{hex, branch, Kind, Effect, RunStatus, Conclusion, Phase};
fn journal(kind: Kind) -> &'static str { match kind {
    Kind::Prepare => "not-applicable", Kind::Dispatch => "durable-intent",
    Kind::Track | Kind::Reconcile => "matched-intent", Kind::Pending => "loaded",
} }
fn plain(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.chars().all(|c| c >= ' ' && c != '\u{7f}')
}

pub(crate) fn publisher_bound() -> bool {
    TOOLING_SHA.is_some_and(|v| hex(v, 40)) && [CANDIDATE_SHA256, EXTERNAL_SHA256, PRODUCTION_SHA256]
        .iter().all(|v| v.is_some_and(|v| hex(v, 64)))
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Platform { Android, Ios }
impl Platform { pub(crate) fn text(self) -> &'static str { match self { Self::Android => "android", Self::Ios => "ios" } } }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Stage { Candidate, ExternalTesting, ProductionSubmit }
impl Stage {
    pub(crate) fn text(self) -> &'static str { match self {
        Self::Candidate => "candidate", Self::ExternalTesting => "external-testing", Self::ProductionSubmit => "production-submit",
    } }
    pub(crate) fn workflow_path(self) -> String { format!(".github/workflows/mobile-{}.yml", self.text()) }
    pub(crate) fn environment(self) -> &'static str { match self {
        Self::Candidate => "mobile-candidate", Self::ExternalTesting => "mobile-external-testing", Self::ProductionSubmit => "mobile-production",
    } }
    fn caller_pin(self) -> Option<&'static str> { match self {
        Self::Candidate => CANDIDATE_SHA256, Self::ExternalTesting => EXTERNAL_SHA256, Self::ProductionSubmit => PRODUCTION_SHA256,
    } }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Version { pub(crate) name: String, pub(crate) build: u32 }
impl Version {
    // Wire/display bounds only. The existing core owns version semantics.
    fn valid(&self) -> bool { !self.name.is_empty() && self.name.len() <= 64
        && self.name.bytes().all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
        && (1..=2_100_000_000).contains(&self.build) }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Selection {
    pub(crate) stage: Stage,
    #[serde(deserialize_with = "nullable")] pub(crate) candidate_run_id: Option<String>,
    #[serde(deserialize_with = "nullable")] pub(crate) external_run_id: Option<String>,
    #[serde(deserialize_with = "nullable")] pub(crate) recovery_run_id: Option<String>,
    #[serde(deserialize_with = "nullable")] pub(crate) original_source_sha: Option<String>,
    #[serde(deserialize_with = "nullable")] pub(crate) original_version: Option<Version>,
}
impl Selection {
    pub(crate) fn valid(&self) -> bool {
        let original = self.stage != Stage::Candidate || self.recovery_run_id.is_some();
        [&self.candidate_run_id, &self.external_run_id, &self.recovery_run_id].iter()
            .all(|v| v.as_ref().is_none_or(|id| numeric_id(id)))
            && original == self.original_source_sha.is_some() && original == self.original_version.is_some()
            && self.original_source_sha.as_ref().is_none_or(|v| hex(v, 40))
            && self.original_version.as_ref().is_none_or(Version::valid)
            && (self.stage != Stage::Candidate || self.candidate_run_id.is_none() && self.external_run_id.is_none())
            && (self.stage == Stage::ProductionSubmit || self.external_run_id.is_none())
            && (self.stage == Stage::Candidate || self.recovery_run_id.is_some() || self.candidate_run_id.is_some())
            && (self.stage != Stage::ProductionSubmit || self.recovery_run_id.is_some() || self.external_run_id.is_some())
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason { None, Unqualified, PublisherUnconfigured, NotConnected, Busy, InvalidInput,
    TargetChanged, Expired, RateLimited, Cancelled, CleanupUnknown, RuntimeUnavailable, ConsentExpired,
    CallerMismatch, WorkflowUnavailable, SourceChanged, UnresolvedRun, AmbiguousRun, RunChanged,
    JobsIncomplete, Unauthorized, Forbidden, NotFoundOrInaccessible, NetworkUnavailable, TlsFailed,
    ResponseInvalid, ResponseLimit, ConfigInvalid, VersionInvalid, PlatformDisabled, BranchMismatch, SourceTreeUnavailable }
impl Reason {
    pub(crate) fn private(self) -> bool { !matches!(self, Self::Unqualified | Self::PublisherUnconfigured | Self::NotConnected
        | Self::Busy | Self::InvalidInput | Self::CleanupUnknown | Self::RuntimeUnavailable | Self::ConsentExpired) }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Target {
    pub(crate) project_binding: String, pub(crate) repository: String,
    pub(crate) account_id: String, pub(crate) repository_id: String, pub(crate) branch: String,
    pub(crate) tooling_repository: String, pub(crate) tooling_sha: String,
    pub(crate) platform: Platform, pub(crate) marker: String, pub(crate) selection: Selection,
}
impl Target {
    pub(crate) fn valid(&self) -> bool {
        hex(&self.project_binding, 64) && coordinate(&self.repository) && numeric_id(&self.account_id)
            && numeric_id(&self.repository_id) && branch(&self.branch) && self.tooling_repository == TOOLING_REPOSITORY
            && hex(&self.tooling_sha, 40) && hex(&self.marker, 32) && self.selection.valid()
    }
    pub(crate) fn publisher_bound(&self) -> bool { self.valid() && TOOLING_SHA == Some(self.tooling_sha.as_str()) && publisher_bound() }
    pub(crate) fn title(&self) -> String { format!("MRK Desktop {} [{}]", self.selection.stage.text(), self.marker) }
    pub(crate) fn full_ref(&self) -> String { format!("refs/heads/{}", self.branch) }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Destination { pub(crate) application_id: String, pub(crate) destination: String, pub(crate) assurance: String }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Requirement { pub(crate) name: String, pub(crate) kind: String, pub(crate) reason: String }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepared {
    pub(crate) target: Target, pub(crate) source_sha: String, pub(crate) source_tree: String, pub(crate) workflow_id: String,
    pub(crate) workflow_path: String, pub(crate) caller_sha256: String, pub(crate) observed_at: String,
    pub(crate) expected_ref: String, pub(crate) display_title: String, pub(crate) config_sha256: String,
    pub(crate) version_source: String, pub(crate) version_sha256: String, pub(crate) current_version: Version,
    pub(crate) destination: Destination, pub(crate) checklist: Vec<Requirement>, pub(crate) environment: String,
    pub(crate) confirmation: String, pub(crate) original_assurance: String,
}
impl Prepared {
    pub(crate) fn valid(&self) -> bool {
        let mut seen = std::collections::BTreeSet::new();
        let original = self.target.selection.original_version.as_ref().unwrap_or(&self.current_version);
        self.target.valid() && hex(&self.source_sha, 40) && hex(&self.source_tree, 40)
            && numeric_id(&self.workflow_id) && self.workflow_path == self.target.selection.stage.workflow_path()
            && hex(&self.caller_sha256, 64) && utc(&self.observed_at) && self.expected_ref == self.target.full_ref()
            && self.display_title == self.target.title() && hex(&self.config_sha256, 64)
            && crate::release_version_protocol::relative_display_path(&self.version_source)
            && hex(&self.version_sha256, 64) && self.current_version.valid()
            && plain(&self.destination.application_id, 255) && plain(&self.destination.destination, 256)
            && self.destination.assurance == DESTINATION_ASSURANCE && self.original_assurance == ORIGINAL_ASSURANCE
            && self.environment == self.target.selection.stage.environment() && self.checklist.len() <= 16
            && self.checklist.iter().all(|row| row.name.strip_prefix("MOBILE_RELEASE_").is_some_and(|suffix|
                !suffix.is_empty() && suffix.len() <= 96 && suffix.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'))
                && seen.insert(&row.name) && ["secret", "variable", "file", "manual"].contains(&row.kind.as_str())
                && plain(&row.reason, 192))
            && self.confirmation == format!("{}:{}:{}:{}", self.target.selection.stage.text(), self.target.platform.text(), original.name, original.build)
            && serde_json::to_vec(self).is_ok_and(|v| v.len() <= PREPARED_LIMIT)
    }
    pub(crate) fn publisher_bound(&self) -> bool {
        self.valid() && self.target.publisher_bound() && self.target.selection.stage.caller_pin() == Some(self.caller_sha256.as_str())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Action {
    pub(crate) kind: Kind, pub(crate) target: Target,
    #[serde(deserialize_with = "nullable")] pub(crate) prepared: Option<Prepared>,
    #[serde(deserialize_with = "nullable")] pub(crate) run_id: Option<String>,
}
impl Action {
    pub(crate) fn valid(&self) -> bool {
        self.kind != Kind::Pending && self.target.valid() && (self.kind == Kind::Prepare) == self.prepared.is_none()
            && self.prepared.as_ref().is_none_or(|v| v.valid() && v.target == self.target)
            && (self.kind == Kind::Track) == self.run_id.is_some() && self.run_id.as_ref().is_none_or(|v| numeric_id(v))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Scope { pub(crate) project_binding: String, pub(crate) repository: String,
    pub(crate) account_id: String, pub(crate) repository_id: String }
impl Scope {
    pub(crate) fn valid(&self) -> bool { hex(&self.project_binding, 64) && coordinate(&self.repository)
        && numeric_id(&self.account_id) && numeric_id(&self.repository_id) }
    pub(crate) fn matches(&self, target: &Target) -> bool { self.project_binding == target.project_binding
        && self.repository == target.repository && self.account_id == target.account_id && self.repository_id == target.repository_id }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PendingRecord { pub(crate) prepared: Prepared,
    #[serde(deserialize_with = "nullable")] pub(crate) run_id: Option<String> }
impl PendingRecord { pub(crate) fn valid(&self) -> bool { self.prepared.valid() && self.run_id.as_ref().is_none_or(|v| numeric_id(v)) } }

// This is nonsecret request DATA. Home can only be supplied by native account
// selection, not by any public command decoder or renderer DTO.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Request { pub(crate) action: Option<Action>, pub(crate) pending_scope: Option<Scope>, pub(crate) home: Option<String> }
impl Request {
    pub(crate) fn kind(&self) -> Kind { self.action.as_ref().map_or(Kind::Pending, |v| v.kind) }
    pub(crate) fn valid(&self) -> bool {
        self.action.is_some() != self.pending_scope.is_some() && self.action.as_ref().is_none_or(Action::valid)
            && self.pending_scope.as_ref().is_none_or(Scope::valid) && (self.kind() == Kind::Prepare) == self.home.is_none()
            && self.home.as_ref().is_none_or(|v| v.starts_with('/') && v.len() <= 4016 && !v.bytes().any(|b| b < 32 || b == 127))
    }
}
pub(crate) fn encode_initial(id: &str, request: &Request) -> Result<Vec<u8>, BridgeError> {
    if !valid_id(id) || !request.valid() { return Err(BridgeError::invalid()); }
    let value = serde_json::json!({"protocol": PROTOCOL, "id": id, "action": request.action,
        "pendingScope": request.pending_scope, "home": request.home});
    let mut raw = serde_json::to_vec(&value).map_err(|_| BridgeError::invalid())?; raw.push(b'\n');
    if raw.len() > INITIAL_LIMIT { return Err(BridgeError::invalid()); } Ok(raw)
}
pub(crate) fn request_digest(raw: &[u8]) -> String { format!("{:x}", Sha256::digest(raw)) }
fn frame(raw: &[u8], limit: usize, nodes: usize, depth: usize) -> Result<Value, BridgeError> {
    if raw.len() < 3 || raw.len() > limit || !raw.ends_with(b"\n") { return Err(BridgeError::protocol()); }
    let body = &raw[..raw.len() - 1];
    if body.first() != Some(&b'{') || body.last() != Some(&b'}') || body.iter().any(|b| matches!(b, b'\n' | b'\r')) {
        return Err(BridgeError::protocol());
    }
    let value = strict_json(body)?;
    if !bounds(&value, limit, nodes, depth) { return Err(BridgeError::protocol()); } Ok(value)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ready { request_sha256: String, journal: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyEnvelope { protocol: String, id: String, ready: Ready }
pub(crate) fn decode_ready(raw: &[u8], id: &str, digest: &str, kind: Kind) -> Result<(), BridgeError> {
    let value: ReadyEnvelope = serde_json::from_value(frame(raw, READY_LIMIT, 32, 4)?).map_err(|_| BridgeError::protocol())?;
    if value.protocol != PROTOCOL || value.id != id || value.ready.request_sha256 != digest || value.ready.journal != journal(kind) {
        return Err(BridgeError::protocol());
    } Ok(())
}
pub(crate) fn encode_go(id: &str, digest: &str, token: Option<&str>, kind: Kind) -> Result<Vec<u8>, BridgeError> {
    if !valid_id(id) || !hex(digest, 64) || (kind == Kind::Pending) != token.is_none()
        || token.is_some_and(|v| v.is_empty() || v.len() > 4096 || !v.bytes().all(|b| (0x21..=0x7e).contains(&b))) {
        return Err(BridgeError::invalid());
    }
    // One private writer buffer. No Value/token DTO, Debug or serialized public
    // request can accidentally retain a credential copy.
    let mut raw = Vec::with_capacity(GO_LIMIT);
    raw.extend_from_slice(b"{\"protocol\":\"mrk-github-release/1\",\"id\":");
    serde_json::to_writer(&mut raw, id).map_err(|_| BridgeError::invalid())?;
    raw.extend_from_slice(b",\"go\":{\"requestSha256\":");
    serde_json::to_writer(&mut raw, digest).map_err(|_| BridgeError::invalid())?;
    raw.extend_from_slice(b",\"token\":");
    serde_json::to_writer(&mut raw, &token).map_err(|_| BridgeError::invalid())?;
    raw.extend_from_slice(b"}}\n");
    if raw.len() > GO_LIMIT { return Err(BridgeError::invalid()); } Ok(raw)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum JobKind { InputGuard, Android, Ios, AndroidResolve, AndroidOnline, AndroidBuild, AndroidStore,
    IosResolve, IosOnline, IosBuild, IosStore }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Job { pub(crate) id: String, pub(crate) kind: JobKind, pub(crate) status: RunStatus,
    #[serde(deserialize_with = "nullable")] pub(crate) conclusion: Option<Conclusion> }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Run { pub(crate) id: String, pub(crate) attempt: u32, pub(crate) status: RunStatus,
    #[serde(deserialize_with = "nullable")] pub(crate) conclusion: Option<Conclusion>,
    pub(crate) observed_at: String, pub(crate) jobs: Vec<Job>, pub(crate) url: String, pub(crate) assurance: String }
impl Run {
    pub(crate) fn valid(&self, prepared: &Prepared) -> bool {
        let mut ids = std::collections::BTreeSet::new(); let mut kinds = std::collections::BTreeSet::new();
        let candidate = prepared.target.selection.stage == Stage::Candidate;
        let required = match (candidate, prepared.target.platform) {
            (true, Platform::Android) => vec![JobKind::InputGuard, JobKind::AndroidResolve, JobKind::AndroidStore],
            (true, Platform::Ios) => vec![JobKind::InputGuard, JobKind::IosResolve, JobKind::IosStore],
            (false, Platform::Android) => vec![JobKind::InputGuard, JobKind::Android],
            (false, Platform::Ios) => vec![JobKind::InputGuard, JobKind::Ios],
        };
        numeric_id(&self.id) && self.attempt == 1 && (self.status == RunStatus::Completed) == self.conclusion.is_some()
            && utc(&self.observed_at) && self.assurance == ASSURANCE && self.jobs.len() <= (if candidate { 9 } else { 3 })
            && self.url == format!("https://github.com/{}/actions/runs/{}", prepared.target.repository, self.id)
            && self.jobs.iter().all(|row| numeric_id(&row.id) && ids.insert(&row.id) && kinds.insert(row.kind)
                && (row.kind == JobKind::InputGuard || candidate != matches!(row.kind, JobKind::Android | JobKind::Ios))
                && (row.status == RunStatus::Completed) == row.conclusion.is_some())
            // A reused candidate can legitimately skip online/build. Observation
            // is not authentication of artifacts or complete release evidence.
            && (self.conclusion != Some(Conclusion::Success) || required.iter().all(|kind|
                self.jobs.iter().any(|row| row.kind == *kind && row.status == RunStatus::Completed
                    && row.conclusion == Some(Conclusion::Success))))
            && serde_json::to_vec(self).is_ok_and(|v| v.len() <= RUN_LIMIT)
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Outcome {
    pub(crate) schema_version: u32, pub(crate) action: Kind, pub(crate) reason: Reason, pub(crate) effect: Effect,
    #[serde(deserialize_with = "nullable")] pub(crate) prepared: Option<Prepared>,
    #[serde(deserialize_with = "nullable")] pub(crate) run_id: Option<String>,
    #[serde(deserialize_with = "nullable")] pub(crate) run: Option<Run>, pub(crate) control: GitHubReadControl,
}
impl Outcome {
    pub(crate) fn valid(&self, request: &Request) -> bool {
        let Some(action) = &request.action else { return false; };
        if self.schema_version != 1 || self.action != action.kind || !self.reason.private() || !self.control.valid()
            || self.run_id.as_ref().is_some_and(|v| !numeric_id(v)) { return false; }
        // Header credential/cooldown controls are never hidden by a nicer action
        // result. The policy's domain refusals legitimately retain control:none.
        if self.control.reason != crate::github_connection_protocol::Reason::None {
            let expected = serde_json::to_value(self.control.reason).ok();
            if expected != serde_json::to_value(self.reason).ok() { return false; }
        }
        match self.action {
            Kind::Prepare => self.effect == Effect::None && self.run_id.is_none() && self.run.is_none()
                && (self.reason == Reason::None) == self.prepared.is_some()
                && self.prepared.as_ref().is_none_or(|v| v.publisher_bound() && v.target == action.target),
            Kind::Dispatch => self.prepared.is_none() && self.run.is_none() && self.effect != Effect::None
                && (self.effect == Effect::Accepted) == (self.reason == Reason::None)
                && (self.effect == Effect::Accepted) == self.run_id.is_some(),
            Kind::Track | Kind::Reconcile => self.effect == Effect::None && self.prepared.is_none()
                && (self.reason == Reason::None) == self.run.is_some() && self.run.is_some() == self.run_id.is_some()
                && self.run.as_ref().is_none_or(|run| action.prepared.as_ref().is_some_and(|prepared|
                    run.valid(prepared) && Some(&run.id) == self.run_id.as_ref()
                        && action.run_id.as_ref().is_none_or(|id| id == &run.id))),
            Kind::Pending => false,
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reply {
    protocol: String, id: String,
    #[serde(deserialize_with = "nullable")] pub(crate) result: Option<Outcome>,
    #[serde(deserialize_with = "nullable")] pub(crate) pending: Option<Vec<PendingRecord>>,
}
pub(crate) fn decode_reply(id: &str, raw: &[u8], request: &Request) -> Result<Reply, BridgeError> {
    let reply: Reply = serde_json::from_value(frame(raw, RESPONSE_LIMIT, 20_000, 16)?).map_err(|_| BridgeError::protocol())?;
    if reply.protocol != PROTOCOL || reply.id != id || !request.valid() { return Err(BridgeError::protocol()); }
    if let Some(scope) = &request.pending_scope {
        let Some(records) = &reply.pending else { return Err(BridgeError::protocol()); };
        let mut seen = std::collections::BTreeSet::new();
        if reply.result.is_some() || records.len() > RECORD_LIMIT || !records.iter().all(|row|
            row.valid() && row.prepared.publisher_bound() && scope.matches(&row.prepared.target)
                && seen.insert(&row.prepared.target.marker)) { return Err(BridgeError::protocol()); }
    } else if reply.pending.is_some() || !reply.result.as_ref().is_some_and(|v| v.valid(request)) { return Err(BridgeError::protocol()); }
    Ok(reply)
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Operation { pub(crate) id: String, pub(crate) kind: Kind, pub(crate) phase: Phase,
    pub(crate) reason: Reason, pub(crate) effect: Effect }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version: u32, pub(crate) revision: u32, pub(crate) session_id: Option<String>,
    pub(crate) available: bool, pub(crate) reason: Reason, pub(crate) operation: Option<Operation>,
    pub(crate) prepared: Option<Prepared>, pub(crate) consent_expires_at: Option<String>,
    pub(crate) pending: Vec<PendingRecord>, pub(crate) run: Option<Run>,
}
impl Status {
    pub(crate) fn fits_wire(&self) -> bool {
        self.pending.len() <= RECORD_LIMIT && serde_json::to_vec(self).is_ok_and(|v| v.len() <= RESPONSE_LIMIT)
    }
}
pub(crate) fn complete_status_ceiling() -> Option<usize> {
    // Exact serializer overhead, including keys, punctuation, quoted IDs,
    // null replacement, record separators and the largest fixed enum fields.
    // Reserve BOTH a full review and full run even though current operation
    // rules never publish them together. Prepared/Run bounds count escaped
    // UTF-8 JSON bytes, not code points or typical fixture sizes.
    let envelope = Status { schema_version: 1, revision: u32::MAX, session_id: Some("s".repeat(64)),
        available: false, reason: Reason::NotFoundOrInaccessible,
        operation: Some(Operation { id: "o".repeat(64), kind: Kind::Reconcile, phase: Phase::CleanupUnknown,
            reason: Reason::NotFoundOrInaccessible, effect: Effect::PotentiallyApplied }),
        prepared: None, consent_expires_at: Some("9999-12-31T23:59:59Z".into()), pending: Vec::new(), run: None };
    let outer = serde_json::to_vec(&envelope).ok()?.len();
    let record = serde_json::to_vec(&serde_json::json!({"prepared":null, "runId":"18446744073709551615"})).ok()?.len();
    Some(outer + RECORD_LIMIT * (record - 4 + PREPARED_LIMIT) + RECORD_LIMIT.saturating_sub(1)
        + PREPARED_LIMIT - 4 + RUN_LIMIT - 4)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ControlArgs { pub(crate) session_id: String, pub(crate) expected_revision: u32 }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PrepareArgs { pub(crate) session_id: String, pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32, pub(crate) branch: String, pub(crate) platform: Platform, pub(crate) selection: Selection }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DispatchArgs { pub(crate) session_id: String, pub(crate) expected_revision: u32,
    pub(crate) consent_id: String, pub(crate) confirm: bool, pub(crate) confirmation: String }
impl DispatchArgs {
    pub(crate) fn matches_review(&self, prepared: &Prepared) -> bool {
        self.confirm && self.consent_id == prepared.target.marker && self.confirmation == prepared.confirmation
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ObserveArgs { pub(crate) session_id: String, pub(crate) expected_revision: u32, pub(crate) marker: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CancelArgs { pub(crate) operation_id: String }
pub(crate) enum Command { Status, Prepare(PrepareArgs), Dispatch(DispatchArgs), Track(ObserveArgs), Reconcile(ObserveArgs), Pending(ControlArgs), Cancel(CancelArgs) }
pub(crate) fn decode_command(name: &str, value: &Value) -> Result<Command, BridgeError> {
    // One closed nested selection; never serialize a large untrusted Value to
    // discover that it was over-bound. No renderer URL/home/token/schedule.
    if !bounds(value, 4096, 64, 4) || !value.as_object().is_some_and(|v| v.len() <= 6) {
        return Err(BridgeError::invalid());
    }
    fn read<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, BridgeError> {
        serde_json::from_value(value.clone()).map_err(|_| BridgeError::invalid())
    }
    let command = match name {
        "github_release_status" if value.as_object().is_some_and(|v| v.is_empty()) => Command::Status,
        "github_release_prepare" => { let v: PrepareArgs = read(value)?;
            if !valid_id(&v.session_id) || v.expected_revision == 0 || v.expected_connection_revision == 0 || !branch(&v.branch) || !v.selection.valid() { return Err(BridgeError::invalid()); }
            Command::Prepare(v) },
        "github_release_dispatch" => { let v: DispatchArgs = read(value)?;
            if !valid_id(&v.session_id) || v.expected_revision == 0 || !hex(&v.consent_id, 32) || !v.confirm || !plain(&v.confirmation, 160) { return Err(BridgeError::invalid()); }
            Command::Dispatch(v) },
        "github_release_track" | "github_release_reconcile" => { let v: ObserveArgs = read(value)?;
            if !valid_id(&v.session_id) || v.expected_revision == 0 || !hex(&v.marker, 32) { return Err(BridgeError::invalid()); }
            if name == "github_release_track" { Command::Track(v) } else { Command::Reconcile(v) } },
        "github_release_pending" => { let v: ControlArgs = read(value)?;
            if !valid_id(&v.session_id) || v.expected_revision == 0 { return Err(BridgeError::invalid()); }
            Command::Pending(v) },
        "github_release_cancel" => { let v: CancelArgs = read(value)?;
            if !valid_id(&v.operation_id) { return Err(BridgeError::invalid()); } Command::Cancel(v) },
        _ => return Err(BridgeError::invalid()),
    }; Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Supplied DATA only: no session/token owner, path, process, service or
    // runtime qualification is constructed by these protocol tests.
    fn review(stage: Stage, platform: Platform, recovery: bool) -> Prepared {
        let original = stage != Stage::Candidate || recovery;
        let selected = Selection { stage,
            candidate_run_id: (stage != Stage::Candidate && !recovery).then(|| "101".into()),
            external_run_id: (stage == Stage::ProductionSubmit && !recovery).then(|| "102".into()),
            recovery_run_id: recovery.then(|| "103".into()),
            original_source_sha: original.then(|| "f".repeat(40)),
            original_version: original.then(|| Version { name: "1.2.3".into(), build: 42 }) };
        let target = Target { project_binding: "b".repeat(64), repository: "owner/app".into(),
            account_id: "11".into(), repository_id: "22".into(), branch: "release/ui".into(),
            tooling_repository: TOOLING_REPOSITORY.into(), tooling_sha: "c".repeat(40),
            platform, marker: "d".repeat(32), selection: selected };
        Prepared { expected_ref: target.full_ref(), display_title: target.title(), target,
            source_sha: "a".repeat(40), source_tree: "e".repeat(40), workflow_id: "33".into(),
            workflow_path: stage.workflow_path(), caller_sha256: "0".repeat(64), observed_at: "2026-09-26T18:00:00Z".into(),
            config_sha256: "1".repeat(64), version_source: "release/version.properties".into(),
            version_sha256: "2".repeat(64), current_version: Version { name: "2.0.0".into(), build: 99 },
            destination: Destination { application_id: "org.fixture.app".into(), destination: "internal".into(),
                assurance: DESTINATION_ASSURANCE.into() }, checklist: Vec::new(), environment: stage.environment().into(),
            confirmation: format!("{}:{}:{}", stage.text(), platform.text(), if original { "1.2.3:42" } else { "2.0.0:99" }),
            original_assurance: ORIGINAL_ASSURANCE.into() }
    }

    #[test]
    fn public_release_commands_have_no_foreign_authority_and_require_original_data() {
        let selected = review(Stage::ProductionSubmit, Platform::Android, false);
        let args = serde_json::json!({"sessionId":"session-1", "expectedRevision":1,
            "expectedConnectionRevision":2,"branch":"release/ui","platform":"android", "selection":selected.target.selection});
        assert!(decode_command("github_release_prepare", &args).is_ok());
        assert!(crate::github_preflight_protocol::decode_command("github_preflight_prepare", &args).is_err());
        for key in ["token", "url", "home", "toolingSha", "runId", "retry", "family"] {
            let mut changed = args.clone(); changed[key] = Value::String("INERT".into());
            assert!(decode_command("github_release_prepare", &changed).is_err());
        }
        for key in ["candidateRunId", "externalRunId", "originalSourceSha", "originalVersion"] {
            let mut changed = args.clone(); changed["selection"][key] = Value::Null;
            assert!(decode_command("github_release_prepare", &changed).is_err());
        }
        let mut both = args.clone(); both["platform"] = Value::String("both".into());
        assert!(decode_command("github_release_prepare", &both).is_err());
        let mut invented = args; invented["selection"]["recoveryConfirmation"] = Value::String("INERT".into());
        assert!(decode_command("github_release_prepare", &invented).is_err());
    }

    #[test]
    fn typed_confirmation_binds_exact_stage_platform_and_original_not_current_version() {
        for stage in [Stage::Candidate, Stage::ExternalTesting, Stage::ProductionSubmit] {
            for platform in [Platform::Android, Platform::Ios] {
                for recovery in [false, true] {
                    let selected = review(stage, platform, recovery); assert!(selected.valid());
                    let mut args: DispatchArgs = serde_json::from_value(serde_json::json!({"sessionId":"session-1", "expectedRevision":3,
                        "consentId":selected.target.marker,"confirm":true,"confirmation":selected.confirmation})).unwrap();
                    assert!(args.matches_review(&selected));
                    args.confirmation.push(' '); assert!(!args.matches_review(&selected));
                    args.confirmation = selected.confirmation.clone(); args.confirm = false;
                    assert!(!args.matches_review(&selected));
                    args.confirm = true; args.consent_id = "1".repeat(32); assert!(!args.matches_review(&selected));
                    if stage != Stage::Candidate || recovery {
                        let mut changed = selected.clone();
                        changed.confirmation = format!("{}:{}:2.0.0:99", stage.text(), platform.text());
                        assert!(!changed.valid());
                    }
                }
            }
        }
        let preflight = serde_json::json!({"sessionId":"session-1","expectedRevision":1,"consentId":"d".repeat(32),"confirm":true});
        assert!(crate::github_preflight_protocol::decode_command("github_preflight_dispatch", &preflight).is_ok());
        assert!(decode_command("github_release_dispatch", &preflight).is_err());
        let mut changed = review(Stage::Candidate, Platform::Ios, false); changed.original_assurance = "authenticated".into();
        assert!(!changed.valid());
    }

    #[test]
    fn ready_go_and_initial_frames_are_distinct_and_credential_free_until_go() {
        let prepared = review(Stage::Candidate, Platform::Android, false);
        let request = Request { action: Some(Action { kind: Kind::Dispatch, target: prepared.target.clone(), prepared: Some(prepared), run_id: None }),
            pending_scope: None, home: Some("/home/mrk".into()) };
        let raw = encode_initial("release-1", &request).unwrap();
        let value: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(value["protocol"], PROTOCOL); assert!(value.get("token").is_none());
        let digest = request_digest(&raw);
        let ready = format!("{{\"protocol\":\"{PROTOCOL}\",\"id\":\"release-1\",\"ready\":{{\"requestSha256\":\"{digest}\",\"journal\":\"durable-intent\"}}}}\n");
        assert!(decode_ready(ready.as_bytes(), "release-1", &digest, Kind::Dispatch).is_ok());
        assert!(decode_ready(ready.as_bytes(), "release-1", &digest, Kind::Prepare).is_err());
        assert!(crate::github_preflight_protocol::decode_ready(ready.as_bytes(), "release-1", &digest, Kind::Dispatch).is_err());
        assert!(decode_ready(ready.replace(PROTOCOL, crate::github_preflight_protocol::PROTOCOL).as_bytes(), "release-1", &digest, Kind::Dispatch).is_err());
        assert!(decode_ready(format!("{ready}{ready}").as_bytes(), "release-1", &digest, Kind::Dispatch).is_err());
        assert!(encode_go("release-1", &digest, None, Kind::Dispatch).is_err());
        assert!(encode_go("release-1", &digest, Some("INERT"), Kind::Pending).is_err());
        assert!(encode_go("release-1", &digest, None, Kind::Pending).is_ok());
        let go = encode_go("release-1", &digest, Some("INERT"), Kind::Dispatch).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&go).unwrap()["protocol"], PROTOCOL);
    }

    #[test]
    fn candidate_observation_requires_resolve_store_not_rebuild_or_release_evidence_claim() {
        let selected = review(Stage::Candidate, Platform::Android, false);
        let mut run = Run { id: "44".into(), attempt: 1, status: RunStatus::Completed, conclusion: Some(Conclusion::Success),
            observed_at: selected.observed_at.clone(), url: "https://github.com/owner/app/actions/runs/44".into(), assurance: ASSURANCE.into(),
            jobs: [JobKind::InputGuard, JobKind::AndroidResolve, JobKind::AndroidStore].into_iter().enumerate()
                .map(|(i, kind)| Job { id: (50 + i).to_string(), kind, status: RunStatus::Completed, conclusion: Some(Conclusion::Success) }).collect() };
        assert!(run.valid(&selected));
        run.jobs.push(Job { id: "60".into(), kind: JobKind::AndroidBuild, status: RunStatus::Completed, conclusion: Some(Conclusion::Skipped) });
        assert!(run.valid(&selected));
        run.jobs[2].conclusion = Some(Conclusion::Skipped); assert!(!run.valid(&selected));
        run.jobs[2].conclusion = Some(Conclusion::Success); run.attempt = 2; assert!(!run.valid(&selected));
        run.attempt = 1; run.assurance = "release-ready".into(); assert!(!run.valid(&selected));
        run.assurance = ASSURANCE.into(); assert!(!run.valid(&review(Stage::ExternalTesting, Platform::Android, false)));
        run.jobs = [JobKind::InputGuard, JobKind::Android].into_iter().enumerate().map(|(i, kind)| Job {
            id: (50 + i).to_string(), kind, status: RunStatus::Completed, conclusion: Some(Conclusion::Success) }).collect();
        assert!(run.valid(&review(Stage::ExternalTesting, Platform::Android, false)));
    }

    #[test]
    fn full_retained_status_counts_utf8_escaping_all_records_and_current_result() {
        let mut selected = review(Stage::Candidate, Platform::Android, true);
        selected.target.repository = format!("{}/{}", "a".repeat(39), "b".repeat(100));
        selected.target.branch = "b".repeat(200); selected.expected_ref = selected.target.full_ref();
        selected.target.account_id = "18446744073709551615".into();
        selected.target.repository_id = selected.target.account_id.clone(); selected.workflow_id = selected.target.account_id.clone();
        selected.target.selection.recovery_run_id = Some(selected.target.account_id.clone());
        let version = format!("1.0+{}", "v".repeat(60));
        selected.target.selection.original_version = Some(Version { name: version.clone(), build: 2_100_000_000 });
        selected.current_version = Version { name: version.clone(), build: 2_100_000_000 };
        selected.confirmation = format!("candidate:android:{version}:2100000000");
        selected.version_source = format!("{}/{}/{}", "a".repeat(248), "é".repeat(124), "v".repeat(14));
        assert_eq!(selected.version_source.len(), 512);
        // These characters need JSON escaping, while the path uses multibyte
        // UTF-8. Count serialization, never string length/code point estimates.
        selected.destination.application_id = "\"\\é".repeat(40);
        selected.destination.destination = "\"\\é".repeat(40);
        for i in 0..16 {
            selected.checklist.push(Requirement { name: format!("MOBILE_RELEASE_FIXTURE_{i}"), kind: "secret".into(), reason: "r".repeat(192) });
            if serde_json::to_vec(&selected).unwrap().len() > PREPARED_LIMIT { selected.checklist.pop(); break; }
        }
        for field in [0, 1] {
            loop {
                let n = serde_json::to_vec(&selected).unwrap().len();
                if n == PREPARED_LIMIT { break; }
                let value = if field == 0 { &mut selected.destination.destination } else { &mut selected.destination.application_id };
                if value.len() >= if field == 0 { 256 } else { 255 } { break; }
                value.push('x');
            }
        }
        while serde_json::to_vec(&selected).unwrap().len() < PREPARED_LIMIT {
            let name = &mut selected.checklist.last_mut().unwrap().name;
            assert!(name.strip_prefix("MOBILE_RELEASE_").unwrap().len() < 96); name.push('X');
        }
        assert!(selected.valid()); assert_eq!(serde_json::to_vec(&selected).unwrap().len(), PREPARED_LIMIT);
        let mut pending = Vec::new();
        for i in 0..RECORD_LIMIT {
            let mut row = selected.clone(); row.target.marker = format!("{i:032x}"); row.display_title = row.target.title();
            assert!(row.valid());
            pending.push(PendingRecord { prepared: row, run_id: Some((u64::MAX - i as u64).to_string()) });
        }
        let run = Run { id: u64::MAX.to_string(), attempt: 1, status: RunStatus::Completed,
            conclusion: Some(Conclusion::StartupFailure), observed_at: "9999-12-31T23:59:59Z".into(),
            url: format!("https://github.com/{}/actions/runs/{}", selected.target.repository, u64::MAX), assurance: ASSURANCE.into(),
            jobs: [JobKind::InputGuard, JobKind::AndroidResolve, JobKind::AndroidOnline, JobKind::AndroidBuild, JobKind::AndroidStore,
                   JobKind::IosResolve, JobKind::IosOnline, JobKind::IosBuild, JobKind::IosStore].into_iter().enumerate().map(|(i, kind)| Job {
                       id: (u64::MAX - i as u64).to_string(), kind, status: RunStatus::Completed, conclusion: Some(Conclusion::StartupFailure) }).collect() };
        assert!(run.valid(&selected));
        let mut status = Status { schema_version: 1, revision: u32::MAX, session_id: Some("s".repeat(64)), available: false,
            reason: Reason::NotFoundOrInaccessible,
            operation: Some(Operation { id: "o".repeat(64), kind: Kind::Reconcile, phase: Phase::CleanupUnknown,
                reason: Reason::NotFoundOrInaccessible, effect: Effect::PotentiallyApplied }),
            prepared: Some(selected), consent_expires_at: Some("9999-12-31T23:59:59Z".into()), pending, run: Some(run) };
        // Even this conservative simultaneous prepared+run envelope must fit;
        // production normally publishes only the result of its one operation.
        let serialized = serde_json::to_vec(&status).unwrap();
        let ceiling = complete_status_ceiling().unwrap();
        assert!(serialized.len() <= ceiling && ceiling <= RESPONSE_LIMIT && status.fits_wire());
        assert!(bounds(&serde_json::from_slice(&serialized).unwrap(), RESPONSE_LIMIT, 20_000, 16));
        assert!(ceiling + (RECORD_LIMIT + 1) * 100 > RESPONSE_LIMIT); // The former4000 cap was not enough.
        status.pending.push(status.pending[0].clone()); assert!(!status.fits_wire());
    }
}

// Read-only retained DATA capacities for the document installation census.
// Inline structs are charged by their owner. No clone, serializer, authority,
// credential copy, allocation, native call or settlement transition occurs here.
impl Target {
    fn retained_heap_bytes(&self) -> Option<usize> {
        let mut bytes = 0usize;
        for value in [&self.project_binding, &self.repository, &self.account_id, &self.repository_id, &self.branch, &self.tooling_repository, &self.tooling_sha, &self.marker] {
            bytes = bytes.checked_add(value.capacity())?;
        }
        for value in [&self.selection.candidate_run_id, &self.selection.external_run_id,
            &self.selection.recovery_run_id, &self.selection.original_source_sha] {
            bytes = bytes.checked_add(value.as_ref().map_or(0, String::capacity))?;
        }
        if let Some(version) = &self.selection.original_version { bytes = bytes.checked_add(version.name.capacity())?; }
        Some(bytes)
    }
}
impl Prepared {
    pub(crate) fn retained_heap_bytes(&self) -> Option<usize> {
        if self.checklist.len() > 16 { return None; }
        let mut bytes = self.target.retained_heap_bytes()?;
        for value in [&self.source_sha, &self.source_tree, &self.workflow_id, &self.workflow_path, &self.caller_sha256, &self.observed_at, &self.expected_ref, &self.display_title, &self.config_sha256, &self.version_source, &self.version_sha256, &self.current_version.name, &self.destination.application_id, &self.destination.destination, &self.destination.assurance, &self.environment, &self.confirmation, &self.original_assurance] {
            bytes = bytes.checked_add(value.capacity())?;
        }
        bytes = bytes.checked_add(self.checklist.capacity().checked_mul(std::mem::size_of::<Requirement>())?)?;
        for row in &self.checklist {
            bytes = bytes.checked_add(row.name.capacity())?.checked_add(row.kind.capacity())?.checked_add(row.reason.capacity())?;
        }
        Some(bytes)
    }
}
impl Run {
    fn retained_heap_bytes(&self) -> Option<usize> {
        if self.jobs.len() > 9 { return None; }
        let mut bytes = self.jobs.capacity().checked_mul(std::mem::size_of::<Job>())?;
        for value in [&self.id, &self.observed_at, &self.url, &self.assurance] {
            bytes = bytes.checked_add(value.capacity())?;
        }
        for row in &self.jobs { bytes = bytes.checked_add(row.id.capacity())?; }
        Some(bytes)
    }
}
impl Status {
    pub(crate) fn retained_heap_bytes(&self) -> Option<usize> {
        if self.pending.len() > RECORD_LIMIT { return None; }
        let mut bytes = self.pending.capacity().checked_mul(std::mem::size_of::<PendingRecord>())?
            .checked_add(self.session_id.as_ref().map_or(0, String::capacity))?
            .checked_add(self.consent_expires_at.as_ref().map_or(0, String::capacity))?;
        if let Some(operation) = &self.operation { bytes = bytes.checked_add(operation.id.capacity())?; }
        if let Some(prepared) = &self.prepared { bytes = bytes.checked_add(prepared.retained_heap_bytes()?)?; }
        // A PotentiallyApplied remote journal entry remains retained DATA, not
        // native cleanup Unknown. Every entry and spare vector cell is charged.
        for row in &self.pending {
            bytes = bytes.checked_add(row.prepared.retained_heap_bytes()?)?
                .checked_add(row.run_id.as_ref().map_or(0, String::capacity))?;
        }
        if let Some(run) = &self.run { bytes = bytes.checked_add(run.retained_heap_bytes()?)?; }
        Some(bytes)
    }
}
