//! Closed P2 DATA and reciprocal Python framing; no credential or GO authority.
//! Core owns credential/schema policy. Only the original native document may
//! supply assignments, current consent, private READ bytes and sealed GO bytes.
use std::{collections::BTreeSet, io::{self, Write}};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use crate::{asset_commands::{Kind as AssetKind, Platform, Stage, Purpose}, error::BridgeError,
    github_connection_protocol::{bounds, coordinate, nullable, numeric_id, utc, GitHubReadControl},
    github_preflight_protocol::{branch, hex}, protocol::{strict_json, valid_id}};

pub(crate) const PROTOCOL: &str = "mrk-github-input-group-action/1";
pub(crate) const ENVELOPE_PROTOCOL: &str = "mrk-github-input-group/1";
pub(crate) const EVENT: &str = "github-input-group-status";
pub(crate) const ASSURANCE: &str = "metadata-only-not-secret-value-or-write-confirmation";
pub(crate) const INITIAL_LIMIT: usize = 16 * 1024;
pub(crate) const READ_LIMIT: usize = 8 * 1024;
pub(crate) const READY_LIMIT: usize = 512;
pub(crate) const RECHECKED_LIMIT: usize = 8 * 1024;
pub(crate) const OUTCOME_LIMIT: usize = 1024;
pub(crate) const GO_LIMIT: usize = 96 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 256 * 1024;
pub(crate) const STDOUT_LIMIT: usize = 271_872;
pub(crate) const RECORD_LIMIT: usize = 64;
pub(crate) const ENVELOPE_LIMIT: usize = 48_000;
pub(crate) const PRIVATE_RECORD_LIMIT: usize = 3900;
// A reserved allowance INSIDE the unchanged 64 MiB document quota, not an
// allocation and not a second quota. Covers the input-time 20k-node JSON arena,
// bounded history/receipt clones, canonical scratch, original IO and sealing.
// Exact native payload/context Arcs are separately deduplicated by the census.
// See the source capsule MEMORY.md; source bounds are not an RSS/native proof.
pub(crate) const WORKING_RESERVATION: usize = 20 * 1024 * 1024;
pub(crate) use crate::github_release_protocol::{TOOLING_REPOSITORY, TOOLING_SHA};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None, Unqualified, RuntimeUnavailable, PublisherUnconfigured, NotConnected, InvalidInput,
    Busy, Unauthorized, Forbidden, NotFoundOrInaccessible, TargetChanged, RateLimited,
    NetworkUnavailable, TlsFailed, ResponseInvalid, ResponseLimit, Expired, Stale, Cancelled,
    CleanupUnknown, ContextStale, AssignmentUnavailable, ConfigMismatch, CallerIncompatible,
    EnvironmentUnready, RunnerUnverified, RunnerCollision, InputInvalid, DestinationLimit, SealingUnavailable,
    ConsentExpired, SourceChanged, MetadataChanged, JournalIncomplete,
}
impl Reason {
    fn private(self) -> bool { !matches!(self, Self::Unqualified | Self::RuntimeUnavailable | Self::PublisherUnconfigured
        | Self::NotConnected | Self::InvalidInput | Self::Busy | Self::Stale | Self::CleanupUnknown | Self::RunnerCollision) }
    fn rejection(self) -> bool { matches!(self, Self::Unauthorized | Self::Forbidden | Self::NotFoundOrInaccessible
        | Self::InputInvalid | Self::RateLimited) }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Kind { Prepare, Apply, Reconcile, Pending }
impl Kind {
    fn journal(self) -> &'static str { match self {
        Self::Prepare => "not-applicable", Self::Apply => "opened", Self::Reconcile => "matched-intent", Self::Pending => "loaded",
    } }
}
// Public operation vocabulary is deliberately separate from the four private
// P2 action kinds: the runner read can never select a P2 write phase.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum OperationKind { Prepare, Apply, Reconcile, Pending, RunnerCheck }
impl From<Kind> for OperationKind {
    fn from(value: Kind) -> Self { match value { Kind::Prepare => Self::Prepare, Kind::Apply => Self::Apply,
        Kind::Reconcile => Self::Reconcile, Kind::Pending => Self::Pending } }
}
impl PartialEq<Kind> for OperationKind { fn eq(&self, other: &Kind) -> bool { *self == OperationKind::from(*other) } }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase { Running, Settled, CleanupUnknown }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Settlement { NotRun, Pending, Confirmed, Unknown }
impl Settlement { fn private(self) -> bool { self != Self::Pending } }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Finality { Pending, Settled, Unknown }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Scope { pub(crate) platform: Platform, pub(crate) stage: Stage, pub(crate) purpose: Purpose }
impl Scope {
    pub(crate) fn valid(&self) -> bool { self.platform != Platform::Project }
    pub(crate) fn environment(&self) -> &'static str { match self.stage {
        Stage::Candidate => "mobile-candidate", Stage::ExternalTesting => "mobile-external-testing", Stage::Production => "mobile-production",
    } }
    pub(crate) fn caller_path(&self) -> &'static str { match self.stage {
        Stage::Candidate => ".github/workflows/mobile-candidate.yml", Stage::ExternalTesting => ".github/workflows/mobile-external-testing.yml",
        Stage::Production => ".github/workflows/mobile-production-submit.yml",
    } }
    fn caller_pin(&self) -> Option<&'static str> { match self.stage {
        Stage::Candidate => crate::github_release_protocol::CANDIDATE_SHA256,
        Stage::ExternalTesting => crate::github_release_protocol::EXTERNAL_SHA256,
        Stage::Production => crate::github_release_protocol::PRODUCTION_SHA256,
    } }
}
// The same reviewed immutable caller bytes as release setup, NOT its runtime
// qualification or dispatch permission. P2 owns separate native admission.
pub(crate) fn publisher_bound() -> bool { crate::github_release_protocol::publisher_bound() }
pub(crate) fn secret_name(kind: AssetKind) -> &'static str { match kind {
    AssetKind::AndroidKeystore => "MOBILE_RELEASE_INPUT_ANDROID_KEYSTORE_V1",
    AssetKind::AndroidFirebase => "MOBILE_RELEASE_INPUT_ANDROID_FIREBASE_V1",
    AssetKind::AppleP12 => "MOBILE_RELEASE_INPUT_APPLE_P12_V1",
    AssetKind::AppleProfile => "MOBILE_RELEASE_INPUT_APPLE_PROFILE_V1",
    AssetKind::AscP8 => "MOBILE_RELEASE_INPUT_ASC_P8_V1",
    AssetKind::IosFirebase => "MOBILE_RELEASE_INPUT_IOS_FIREBASE_V1",
    AssetKind::GoogleWif => "MOBILE_RELEASE_INPUT_GOOGLE_WIF_V1",
    AssetKind::ProjectReadToken => "MOBILE_RELEASE_INPUT_PROJECT_READ_TOKEN_V1",
    AssetKind::AppleReviewContact => "MOBILE_RELEASE_INPUT_APPLE_REVIEW_CONTACT_V1",
    AssetKind::AppleReviewDemoAccount => "MOBILE_RELEASE_INPUT_APPLE_REVIEW_DEMO_ACCOUNT_V1",
    AssetKind::AppleOperationCommitment => "MOBILE_RELEASE_INPUT_APPLE_OPERATION_COMMITMENT_V1",
} }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AssignmentRef {
    pub(crate) kind: AssetKind, pub(crate) record_id: String, pub(crate) record_revision: u32, pub(crate) context_revision: u32,
}
impl AssignmentRef {
    pub(crate) fn valid(&self) -> bool { hex(&self.record_id, 32) && self.record_revision > 0 && self.context_revision > 0 }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Target {
    pub(crate) project_binding: String, pub(crate) repository: String, pub(crate) account_id: String,
    pub(crate) repository_id: String, pub(crate) branch: String, pub(crate) tooling_repository: String,
    pub(crate) tooling_sha: String, pub(crate) scope: Scope, pub(crate) kind: AssetKind,
    pub(crate) marker: String, pub(crate) native_config_sha256: String,
}
impl Target {
    pub(crate) fn valid(&self) -> bool { hex(&self.project_binding, 64) && coordinate(&self.repository)
        && numeric_id(&self.account_id) && numeric_id(&self.repository_id) && branch(&self.branch)
        && self.tooling_repository == TOOLING_REPOSITORY && hex(&self.tooling_sha, 40) && self.scope.valid()
        && hex(&self.marker, 32) && hex(&self.native_config_sha256, 64) }
    pub(crate) fn publisher_bound(&self) -> bool { self.valid() && publisher_bound() && TOOLING_SHA == Some(self.tooling_sha.as_str()) }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Metadata {
    Present { #[serde(rename = "createdAt")] created_at: String, #[serde(rename = "updatedAt")] updated_at: String,
        #[serde(rename = "observedAt")] observed_at: String },
    MissingOrInaccessible { #[serde(rename = "observedAt")] observed_at: String },
}
impl Metadata {
    pub(crate) fn observed_at(&self) -> &str { match self { Self::Present { observed_at, .. } | Self::MissingOrInaccessible { observed_at } => observed_at } }
    fn valid(&self) -> bool { utc(self.observed_at()) && match self {
        Self::Present { created_at, updated_at, .. } => utc(created_at) && utc(updated_at) && created_at <= updated_at, Self::MissingOrInaccessible { .. } => true,
    } }
    fn same_identity(&self, other: &Self) -> bool { match (self, other) {
        (Self::Present { created_at: a, updated_at: b, .. }, Self::Present { created_at: c, updated_at: d, .. }) => a == c && b == d,
        (Self::MissingOrInaccessible { .. }, Self::MissingOrInaccessible { .. }) => true, _ => false,
    } }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PublicKey { pub(crate) key_id: String, pub(crate) key: String }
impl PublicKey {
    fn valid(&self) -> bool {
        if self.key_id.is_empty() || self.key_id.len() > 128 || !self.key_id.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
            || self.key.len() != 44 { return false; }
        let mut raw = [0u8; 33]; let Ok(n) = STANDARD.decode_slice(&self.key, &mut raw) else { return false; };
        let mut canonical = [0u8; 44];
        n == 32 && STANDARD.encode_slice(&raw[..32], &mut canonical).is_ok_and(|n| n == 44) && canonical.as_slice() == self.key.as_bytes()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BranchPolicy { protected_branches: bool, custom_branch_policies: bool }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reviewer { #[serde(rename = "type")] kind: ReviewerKind, id: String }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ReviewerKind { User, Team }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", deny_unknown_fields)]
pub(crate) enum Rule {
    #[serde(rename = "wait_timer")] WaitTimer { id: String, #[serde(rename = "waitTimer")] wait_timer: u32 },
    #[serde(rename = "required_reviewers")] RequiredReviewers { id: String, #[serde(rename = "preventSelfReview")] prevent_self_review: bool, reviewers: Vec<Reviewer> },
    #[serde(rename = "branch_policy")] BranchPolicy { id: String },
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EnvironmentPolicy {
    can_admins_bypass: bool, #[serde(deserialize_with = "nullable")] branch_policy: Option<BranchPolicy>, rules: Vec<Rule>,
}
impl EnvironmentPolicy {
    fn valid(&self) -> bool {
        if self.rules.len() > 8 || self.branch_policy.as_ref().is_some_and(|b| b.protected_branches && b.custom_branch_policies) { return false; }
        let mut kinds = BTreeSet::new();
        self.rules.iter().all(|r| match r {
            Rule::WaitTimer { id, wait_timer } => numeric_id(id) && *wait_timer <= 43200 && kinds.insert(0),
            Rule::RequiredReviewers { id, reviewers, .. } => numeric_id(id) && (1..=6).contains(&reviewers.len()) && kinds.insert(1)
                && reviewers.iter().all(|v| numeric_id(&v.id)) && reviewers.iter().collect::<BTreeSet<_>>().len() == reviewers.len(),
            Rule::BranchPolicy { id } => numeric_id(id) && kinds.insert(2),
        }) && encoded(self, 1536).is_ok()
    }
}
/// Contains no credential value, but the policy/key are PRIVATE protocol DATA:
/// public status constructs PublicTarget explicitly instead of serializing this.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepared {
    pub(crate) target: Target, pub(crate) source_sha: String, pub(crate) caller_sha256: String,
    pub(crate) config_sha256: String, pub(crate) environment_id: String, pub(crate) environment_policy: EnvironmentPolicy,
    pub(crate) public_key: PublicKey, pub(crate) metadata: Metadata, pub(crate) observed_at: String,
}
impl Prepared {
    pub(crate) fn valid(&self) -> bool {
        self.target.valid() && hex(&self.source_sha, 40) && hex(&self.caller_sha256, 64) && hex(&self.config_sha256, 64)
            && numeric_id(&self.environment_id) && self.environment_policy.valid() && self.public_key.valid() && self.metadata.valid()
            && self.metadata.observed_at() == self.observed_at && encoded(self, 4096).is_ok()
            && encoded(&serde_json::json!({"prepared":self,"write":{"state":"explicitly-rejected","reason":"not-found-or-inaccessible"},
                "intentSha256":"0".repeat(64)}), PRIVATE_RECORD_LIMIT).is_ok()
    }
    pub(crate) fn production_reviewed(&self) -> bool {
        self.target.scope.stage != Stage::Production || self.environment_policy.valid() && self.environment_policy.rules.iter().any(|rule|
            matches!(rule, Rule::RequiredReviewers { reviewers, .. } if !reviewers.is_empty()))
    }
    pub(crate) fn public_record_fits(&self) -> bool {
        let worst = PublicRecord { original_operation_id: self.target.marker.clone(), target: self.public_target(),
            write: RemoteWrite::ExplicitlyRejected { reason: Reason::NotFoundOrInaccessible },
            completion: Completion { journal: Settlement::Confirmed, cleanup: Settlement::Confirmed, finality: Finality::Unknown },
            reason: Reason::NotFoundOrInaccessible };
        encoded(&worst, PRIVATE_RECORD_LIMIT).is_ok()
    }
    pub(crate) fn publisher_bound(&self) -> bool {
        self.valid() && self.target.publisher_bound() && self.target.scope.caller_pin() == Some(self.caller_sha256.as_str())
    }
    pub(crate) fn same_original(&self, current: &Self) -> bool {
        self.target == current.target && self.source_sha == current.source_sha && self.caller_sha256 == current.caller_sha256
            && self.config_sha256 == current.config_sha256 && self.environment_id == current.environment_id
            && self.environment_policy == current.environment_policy && self.public_key == current.public_key
            && self.metadata.same_identity(&current.metadata)
        // Deliberately ignore ONLY these two observations' timestamps. Consent
        // and durable intent keep the original Prepared including timestamps.
    }
    pub(crate) fn intent_digest(&self) -> Result<String, BridgeError> {
        let mut raw = canonical(&serde_json::json!({"schemaVersion":1,"protocol":PROTOCOL,"prepared":self}), 8191)?;
        raw.push(b'\n'); Ok(digest(&raw))
    }
    pub(crate) fn snapshot_digest(&self) -> Result<String, BridgeError> { Ok(digest(&encoded(self, 4096)?)) }
    pub(crate) fn public_target(&self) -> PublicTarget {
        PublicTarget { project_binding: self.target.project_binding.clone(), repository: self.target.repository.clone(),
            account_id: self.target.account_id.clone(), repository_id: self.target.repository_id.clone(),
            environment: self.target.scope.environment().into(), environment_id: self.environment_id.clone(), branch: self.target.branch.clone(),
            source_sha: self.source_sha.clone(), tooling_sha: self.target.tooling_sha.clone(), caller_path: self.target.scope.caller_path().into(),
            caller_sha256: self.caller_sha256.clone(), config_sha256: self.config_sha256.clone(), scope: self.target.scope.clone(),
            kind: self.target.kind, secret_name: secret_name(self.target.kind).into(), protocol: ENVELOPE_PROTOCOL.into() }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Action { pub(crate) kind: Kind, pub(crate) target: Target, #[serde(deserialize_with = "nullable")] pub(crate) prepared: Option<Prepared> }
impl Action {
    fn valid(&self) -> bool { self.kind != Kind::Pending && self.target.valid() && (self.kind == Kind::Prepare) == self.prepared.is_none()
        && self.prepared.as_ref().is_none_or(|v| v.valid() && v.target == self.target) }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PendingScope { pub(crate) project_binding: String, pub(crate) repository: String, pub(crate) account_id: String, pub(crate) repository_id: String }
impl PendingScope {
    pub(crate) fn valid(&self) -> bool { hex(&self.project_binding, 64) && coordinate(&self.repository) && numeric_id(&self.account_id) && numeric_id(&self.repository_id) }
    pub(crate) fn matches(&self, t: &Target) -> bool { self.project_binding == t.project_binding && self.repository == t.repository
        && self.account_id == t.account_id && self.repository_id == t.repository_id }
}
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Request { pub(crate) action: Option<Action>, pub(crate) pending_scope: Option<PendingScope>, pub(crate) home: Option<String> }
impl Request {
    pub(crate) fn kind(&self) -> Kind { self.action.as_ref().map_or(Kind::Pending, |v| v.kind) }
    pub(crate) fn valid(&self) -> bool { self.action.is_some() != self.pending_scope.is_some() && self.action.as_ref().is_none_or(Action::valid)
        && self.pending_scope.as_ref().is_none_or(PendingScope::valid) && (self.kind() == Kind::Prepare) == self.home.is_none()
        && self.home.as_ref().is_none_or(|v| v.starts_with('/') && v.len() <= 4016 && !v.bytes().any(|b| b < 32 || b == 127)) }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum RemoteWrite {
    NotAttempted, AttemptedOutcomeUnknown,
    AcknowledgedCreated { #[serde(rename = "statusCode")] status_code: u16 },
    AcknowledgedUpdated { #[serde(rename = "statusCode")] status_code: u16 },
    ExplicitlyRejected { reason: Reason },
}
impl RemoteWrite {
    pub(crate) fn valid(&self) -> bool { match self {
        Self::AcknowledgedCreated { status_code } => *status_code == 201, Self::AcknowledgedUpdated { status_code } => *status_code == 204,
        Self::ExplicitlyRejected { reason } => reason.rejection(), _ => true,
    } }
    pub(crate) fn acknowledged(&self) -> bool { matches!(self, Self::AcknowledgedCreated { .. } | Self::AcknowledgedUpdated { .. }) }
    pub(crate) fn observed(&self) -> bool { self.acknowledged() || matches!(self, Self::ExplicitlyRejected { .. }) }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PrivateRecord { pub(crate) prepared: Prepared, pub(crate) write: RemoteWrite, pub(crate) intent_sha256: String }
impl PrivateRecord {
    pub(crate) fn valid(&self) -> bool { self.prepared.valid() && self.write.valid()
        && self.prepared.intent_digest().is_ok_and(|digest| self.intent_sha256 == digest) && encoded(self, PRIVATE_RECORD_LIMIT).is_ok() }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Observation { pub(crate) original_operation_id: String, pub(crate) metadata: Metadata, pub(crate) assurance: String }
impl Observation { fn valid(&self, marker: &str) -> bool { self.original_operation_id == marker && self.metadata.valid() && self.assurance == ASSURANCE } }
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Outcome {
    pub(crate) schema_version: u32, pub(crate) action: Kind, pub(crate) reason: Reason,
    #[serde(deserialize_with = "nullable")] pub(crate) prepared: Option<Prepared>,
    #[serde(deserialize_with = "nullable")] pub(crate) record: Option<PrivateRecord>,
    #[serde(deserialize_with = "nullable")] pub(crate) observation: Option<Observation>,
    pub(crate) control: GitHubReadControl, pub(crate) network_cleanup: Settlement, pub(crate) journal: Settlement,
}
impl Outcome {
    fn valid(&self, action: &Action) -> bool {
        if self.schema_version != 1 || self.action != action.kind || !self.reason.private() || !self.control.valid()
            || !self.network_cleanup.private() || !self.journal.private() { return false; }
        if self.action == Kind::Prepare {
            return self.record.is_none() && self.observation.is_none() && self.journal == Settlement::NotRun
                && (self.reason == Reason::None) == self.prepared.is_some()
                && self.prepared.as_ref().is_none_or(|v| v.valid() && v.target == action.target
                    && self.network_cleanup == Settlement::Confirmed && self.control.reason == crate::github_connection_protocol::Reason::None);
        }
        if self.prepared.is_some() || action.prepared.is_none() || self.record.as_ref().is_some_and(|r|
            !r.valid() || Some(&r.prepared) != action.prepared.as_ref()) { return false; }
        if self.action == Kind::Apply {
            self.observation.is_none() && (self.reason != Reason::None || self.record.as_ref().is_some_and(|v| v.write.acknowledged())
                && self.network_cleanup == Settlement::Confirmed && self.journal == Settlement::Confirmed
                && self.control.reason == crate::github_connection_protocol::Reason::None)
        } else { self.action == Kind::Reconcile && self.record.is_some()
            && (self.reason == Reason::None) == self.observation.is_some()
            && self.observation.as_ref().is_none_or(|v| v.valid(&action.target.marker) && self.network_cleanup == Settlement::Confirmed) }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reply { protocol: String, id: String, #[serde(deserialize_with = "nullable")] pub(crate) result: Option<Outcome>,
    #[serde(deserialize_with = "nullable")] pub(crate) pending: Option<Vec<PrivateRecord>> }
pub(crate) fn decode_reply(raw: &[u8], id: &str, request: &Request) -> Result<Reply, BridgeError> {
    let reply: Reply = serde_json::from_value(frame(raw, RESPONSE_LIMIT, 20_000, 16)?).map_err(|_| BridgeError::protocol())?;
    if reply.protocol != PROTOCOL || reply.id != id || !request.valid() { return Err(BridgeError::protocol()); }
    if let Some(action) = &request.action {
        if reply.pending.is_some() || !reply.result.as_ref().is_some_and(|v| v.valid(action)) { return Err(BridgeError::protocol()); }
    } else {
        let scope = request.pending_scope.as_ref().ok_or_else(BridgeError::protocol)?;
        let records = reply.pending.as_ref().ok_or_else(BridgeError::protocol)?; let mut markers = BTreeSet::new();
        if reply.result.is_some() || records.len() > RECORD_LIMIT || !records.iter().all(|v| v.valid()
            && scope.matches(&v.prepared.target) && markers.insert(v.prepared.target.marker.as_str())) { return Err(BridgeError::protocol()); }
    }
    Ok(reply)
}

pub(crate) fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
/// Integer-only canonical domain shared with the Python corpus. Sorting is
/// explicit even if serde_json gains preserve_order through another dependency.
pub(crate) fn canonical(value: &Value, limit: usize) -> Result<Vec<u8>, BridgeError> {
    // Borrow the original tree. Do not duplicate a potentially 512 KiB config
    // in another Value/string arena just to sort object keys.
    fn emit(v: &Value, out: &mut Limited, depth: usize, remaining: &mut usize) -> Result<(), BridgeError> {
        *remaining = remaining.checked_sub(1).ok_or_else(BridgeError::protocol)?;
        if depth > 24 { return Err(BridgeError::protocol()); }
        fn io<E>(_: E) -> BridgeError { BridgeError::protocol() }
        match v {
            Value::Null | Value::Bool(_) | Value::String(_) => serde_json::to_writer(out,v).map_err(io),
            Value::Number(n) if n.is_i64() || n.is_u64() => serde_json::to_writer(out,n).map_err(io),
            Value::Array(items) => {
                out.write_all(b"[").map_err(io)?;
                for (index,item) in items.iter().enumerate() {
                    if index != 0 { out.write_all(b",").map_err(io)?; }
                    emit(item,out,depth+1,remaining)?;
                }
                out.write_all(b"]").map_err(io)
            },
            Value::Object(items) => {
                if items.len() > *remaining || depth == 24 && !items.is_empty() { return Err(BridgeError::protocol()); }
                let mut keys: Vec<_> = items.keys().collect(); keys.sort_unstable();
                out.write_all(b"{").map_err(io)?;
                for (index,key) in keys.into_iter().enumerate() {
                    *remaining = remaining.checked_sub(1).ok_or_else(BridgeError::protocol)?;
                    if index != 0 { out.write_all(b",").map_err(io)?; }
                    serde_json::to_writer(&mut *out,key).map_err(|_| BridgeError::protocol())?;
                    out.write_all(b":").map_err(io)?; emit(&items[key],out,depth+1,remaining)?;
                }
                out.write_all(b"}").map_err(io)
            }, _ => Err(BridgeError::protocol()),
        }
    }
    let mut writer = Limited::new(limit)?; emit(value,&mut writer,0,&mut 20_000)?; Ok(writer.bytes)
}
fn encoded(value: &impl Serialize, limit: usize) -> Result<Vec<u8>, BridgeError> {
    canonical(&serde_json::to_value(value).map_err(|_| BridgeError::protocol())?, limit)
}
struct Limited { bytes: Vec<u8>, limit: usize }
impl Limited {
    fn new(limit: usize) -> Result<Self, BridgeError> { let mut bytes = Vec::new(); bytes.try_reserve_exact(limit).map_err(|_| BridgeError::protocol())?;
        if bytes.capacity() > limit { return Err(BridgeError::protocol()); } Ok(Self { bytes, limit }) }
}
impl Write for Limited {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() > self.limit.saturating_sub(self.bytes.len()) { return Err(io::Error::new(io::ErrorKind::InvalidData, "P2 byte bound")); }
        self.bytes.extend_from_slice(data); Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
fn frame(raw: &[u8], limit: usize, nodes: usize, depth: usize) -> Result<Value, BridgeError> {
    if raw.len() < 3 || raw.len() > limit || !raw.ends_with(b"\n") { return Err(BridgeError::protocol()); }
    let body = &raw[..raw.len() - 1];
    if body.first() != Some(&b'{') || body.last() != Some(&b'}') || body.iter().any(|b| matches!(b, b'\n' | b'\r')) { return Err(BridgeError::protocol()); }
    let value = strict_json(body)?; if !bounds(&value, limit, nodes, depth) { return Err(BridgeError::protocol()); } Ok(value)
}
pub(crate) fn encode_initial(id: &str, request: &Request) -> Result<Vec<u8>, BridgeError> {
    if !valid_id(id) || !request.valid() { return Err(BridgeError::invalid()); }
    let mut raw = encoded(&serde_json::json!({"protocol":PROTOCOL,"id":id,"action":request.action,
        "pendingScope":request.pending_scope,"home":request.home}), INITIAL_LIMIT - 1)?; raw.push(b'\n'); Ok(raw)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ready { request_sha256: String, phase: String, journal: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyEnvelope { protocol: String, id: String, ready: Ready }
pub(crate) fn decode_ready(raw: &[u8], id: &str, request_digest: &str, kind: Kind) -> Result<(), BridgeError> {
    let r: ReadyEnvelope = serde_json::from_value(frame(raw, READY_LIMIT, 32, 4)?).map_err(|_| BridgeError::protocol())?;
    if r.protocol != PROTOCOL || r.id != id || r.ready.request_sha256 != request_digest || r.ready.phase != "observe"
        || r.ready.journal != kind.journal() { return Err(BridgeError::protocol()); } Ok(())
}
/// Original native writer backing only; no Clone/Debug/Serialize or IPC getter.
pub(crate) struct PrivateFrame(Zeroizing<Vec<u8>>);
impl PrivateFrame {
    pub(crate) fn into_zeroizing(self) -> Zeroizing<Vec<u8>> { self.0 }
    pub(crate) fn retained_capacity(&self) -> usize { self.0.capacity() }
}
pub(crate) fn encode_read(id: &str, request_digest: &str, token: Option<&str>, kind: Kind) -> Result<PrivateFrame, BridgeError> {
    if !valid_id(id) || !hex(request_digest, 64) || (kind == Kind::Pending) != token.is_none()
        || token.is_some_and(|v| v.is_empty() || v.len() > 4096 || !v.bytes().all(|b| (0x21..=0x7e).contains(&b))) { return Err(BridgeError::invalid()); }
    let mut out = PrivateWriter::new(READ_LIMIT)?;
    out.write_all(b"{\"protocol\":\"mrk-github-input-group-action/1\",\"id\":").map_err(|_| BridgeError::invalid())?;
    serde_json::to_writer(&mut out, id).map_err(|_| BridgeError::invalid())?;
    out.write_all(b",\"read\":{\"requestSha256\":").map_err(|_| BridgeError::invalid())?;
    serde_json::to_writer(&mut out, request_digest).map_err(|_| BridgeError::invalid())?;
    out.write_all(b",\"token\":").map_err(|_| BridgeError::invalid())?;
    serde_json::to_writer(&mut out, &token).map_err(|_| BridgeError::invalid())?;
    out.write_all(b"}}\n").map_err(|_| BridgeError::invalid())?; Ok(PrivateFrame(out.bytes))
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Rechecked { pub(crate) request_sha256: String, pub(crate) snapshot_sha256: String,
    pub(crate) intent_sha256: String, pub(crate) snapshot: Prepared }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecheckedEnvelope { protocol: String, id: String, rechecked: Rechecked }
pub(crate) fn decode_rechecked(raw: &[u8], id: &str, request_digest: &str, original: &Prepared) -> Result<Rechecked, BridgeError> {
    let r: RecheckedEnvelope = serde_json::from_value(frame(raw, RECHECKED_LIMIT, 2000, 16)?).map_err(|_| BridgeError::protocol())?;
    if r.protocol != PROTOCOL || r.id != id || r.rechecked.request_sha256 != request_digest || !r.rechecked.snapshot.valid()
        || !original.same_original(&r.rechecked.snapshot) || r.rechecked.snapshot_sha256 != r.rechecked.snapshot.snapshot_digest()?
        || r.rechecked.intent_sha256 != original.intent_digest()? { return Err(BridgeError::protocol()); }
    Ok(r.rechecked)
}
pub(crate) fn encode_go(id: &str, rechecked: &Rechecked, body: &[u8]) -> Result<PrivateFrame, BridgeError> {
    if !valid_id(id) || !hex(&rechecked.request_sha256,64) || !hex(&rechecked.snapshot_sha256,64) || !hex(&rechecked.intent_sha256,64)
        || body.is_empty() || body.len() > crate::github_input_seal::MAX_PUT_BODY_BYTES { return Err(BridgeError::invalid()); }
    let mut out = PrivateWriter::new(GO_LIMIT)?;
    out.write_all(b"{\"protocol\":\"mrk-github-input-group-action/1\",\"id\":").map_err(|_| BridgeError::invalid())?;
    serde_json::to_writer(&mut out, id).map_err(|_| BridgeError::invalid())?;
    out.write_all(b",\"go\":{\"requestSha256\":").map_err(|_| BridgeError::invalid())?;
    serde_json::to_writer(&mut out, &rechecked.request_sha256).map_err(|_| BridgeError::invalid())?;
    out.write_all(b",\"snapshotSha256\":").map_err(|_| BridgeError::invalid())?;
    serde_json::to_writer(&mut out, &rechecked.snapshot_sha256).map_err(|_| BridgeError::invalid())?;
    out.write_all(b",\"intentSha256\":").map_err(|_| BridgeError::invalid())?;
    serde_json::to_writer(&mut out, &rechecked.intent_sha256).map_err(|_| BridgeError::invalid())?;
    out.write_all(b",\"putBodyBase64\":\"").map_err(|_| BridgeError::invalid())?;
    out.base64(body)?; out.write_all(b"\"}}\n").map_err(|_| BridgeError::invalid())?; Ok(PrivateFrame(out.bytes))
}
/// One exact-capacity private buffer; serialization errors wipe the partial
/// frame. A separate String/Value containing credential text is never created.
pub(crate) struct PrivateWriter { bytes: Zeroizing<Vec<u8>>, limit: usize }
impl PrivateWriter {
    pub(crate) fn new(limit: usize) -> Result<Self, BridgeError> {
        let mut bytes = Zeroizing::new(Vec::new()); bytes.try_reserve_exact(limit).map_err(|_| BridgeError::invalid())?;
        if bytes.capacity() > limit { return Err(BridgeError::invalid()); } Ok(Self { bytes, limit })
    }
    pub(crate) fn finish(self) -> Zeroizing<Vec<u8>> { self.bytes }
    pub(crate) fn base64(&mut self, input: &[u8]) -> Result<(), BridgeError> {
        let count = input.len().checked_add(2).and_then(|v| v.checked_div(3)).and_then(|v| v.checked_mul(4)).ok_or_else(BridgeError::invalid)?;
        let old = self.bytes.len(); let end = old.checked_add(count).filter(|n| *n <= self.limit).ok_or_else(BridgeError::invalid)?;
        self.bytes.resize(end, 0);
        if STANDARD.encode_slice(input, &mut self.bytes[old..end]).map_err(|_| BridgeError::invalid())? != count { return Err(BridgeError::invalid()); }
        Ok(())
    }
}
impl Write for PrivateWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() > self.limit.saturating_sub(self.bytes.len()) { return Err(io::Error::new(io::ErrorKind::InvalidData, "P2 private byte bound")); }
        self.bytes.extend_from_slice(data); Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RemoteFact { request_sha256: String, snapshot_sha256: String, intent_sha256: String,
    pub(crate) write: RemoteWrite, pub(crate) control: GitHubReadControl }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutcomeEnvelope { protocol: String, id: String, outcome: RemoteFact }
pub(crate) fn decode_outcome(raw: &[u8], id: &str, rechecked: &Rechecked) -> Result<RemoteFact, BridgeError> {
    let r: OutcomeEnvelope = serde_json::from_value(frame(raw, OUTCOME_LIMIT, 64, 6)?).map_err(|_| BridgeError::protocol())?;
    let v = &r.outcome;
    if r.protocol != PROTOCOL || r.id != id || v.request_sha256 != rechecked.request_sha256
        || v.snapshot_sha256 != rechecked.snapshot_sha256 || v.intent_sha256 != rechecked.intent_sha256
        || !v.write.valid() || matches!(v.write, RemoteWrite::NotAttempted) || !v.control.valid() { return Err(BridgeError::protocol()); }
    Ok(r.outcome)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PublicTarget {
    pub(crate) project_binding: String, pub(crate) repository: String, pub(crate) repository_id: String, pub(crate) account_id: String,
    pub(crate) environment: String, pub(crate) environment_id: String, pub(crate) branch: String, pub(crate) source_sha: String,
    pub(crate) tooling_sha: String, pub(crate) caller_path: String, pub(crate) caller_sha256: String, pub(crate) config_sha256: String,
    pub(crate) scope: Scope, pub(crate) kind: AssetKind, pub(crate) secret_name: String, pub(crate) protocol: String,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PublicPrepared {
    pub(crate) consent_id: String, pub(crate) target: PublicTarget, pub(crate) assignment: AssignmentRef, pub(crate) fields: Vec<&'static str>,
    pub(crate) metadata: Metadata, pub(crate) destination: Destination, pub(crate) effect: &'static str,
    pub(crate) observed_at: String, pub(crate) consent_expires_at: String,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Destination { pub(crate) state: &'static str, pub(crate) plaintext_limit_bytes: usize }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Completion { pub(crate) journal: Settlement, pub(crate) cleanup: Settlement, pub(crate) finality: Finality }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PublicRecord { pub(crate) original_operation_id: String, pub(crate) target: PublicTarget,
    pub(crate) write: RemoteWrite, pub(crate) completion: Completion, pub(crate) reason: Reason }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Operation { pub(crate) id: String, pub(crate) kind: OperationKind, pub(crate) phase: Phase, pub(crate) reason: Reason }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status { pub(crate) schema_version: u32, pub(crate) revision: u32, pub(crate) session_id: Option<String>,
    pub(crate) available: bool, pub(crate) reason: Reason, pub(crate) operation: Option<Operation>, pub(crate) prepared: Option<PublicPrepared>,
    pub(crate) records: Vec<PublicRecord>, pub(crate) observation: Option<Observation>,
    pub(crate) runner: Option<crate::github_runner_prerequisite_protocol::Summary> }

impl Status {
    pub(crate) fn fits_wire(&self) -> bool { encoded(self,RESPONSE_LIMIT).is_ok() }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ControlArgs { pub(crate) session_id: String, pub(crate) expected_revision: u32 }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PrepareArgs { pub(crate) session_id: String, pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32, pub(crate) expected_asset_status_revision: u32,
    pub(crate) branch: String, pub(crate) assignment: AssignmentRef }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ApplyArgs { pub(crate) session_id: String, pub(crate) expected_revision: u32,
    pub(crate) consent_id: String, pub(crate) confirm_upsert_whole_group: bool }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReconcileArgs { pub(crate) session_id: String, pub(crate) expected_revision: u32, pub(crate) original_operation_id: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CancelArgs { pub(crate) operation_id: String }
pub(crate) enum Command { Status, RunnerCheck(crate::github_runner_prerequisite_protocol::CheckArgs), Prepare(PrepareArgs), Apply(ApplyArgs), Reconcile(ReconcileArgs), Pending(ControlArgs), Cancel(CancelArgs) }
pub(crate) fn decode_command(name: &str, value: &Value) -> Result<Command, BridgeError> {
    if !bounds(value, 2048, 32, 3) { return Err(BridgeError::invalid()); }
    let control = |id: &str, revision| valid_id(id) && revision > 0;
    Ok(match name {
        "github_input_group_status" if value.as_object().is_some_and(|o| o.is_empty()) => Command::Status,
        "github_input_runner_check" => {
            let v: crate::github_runner_prerequisite_protocol::CheckArgs = serde_json::from_value(value.clone()).map_err(|_| BridgeError::invalid())?;
            if !v.valid() { return Err(BridgeError::invalid()); } Command::RunnerCheck(v)
        },
        "github_input_group_prepare" => { let v: PrepareArgs = serde_json::from_value(value.clone()).map_err(|_| BridgeError::invalid())?;
            if !control(&v.session_id,v.expected_revision) || v.expected_connection_revision == 0 || v.expected_asset_status_revision == 0
                || !branch(&v.branch) || !v.assignment.valid() { return Err(BridgeError::invalid()); } Command::Prepare(v) },
        "github_input_group_apply" => { let v: ApplyArgs = serde_json::from_value(value.clone()).map_err(|_| BridgeError::invalid())?;
            if !control(&v.session_id,v.expected_revision) || !hex(&v.consent_id,32) || !v.confirm_upsert_whole_group { return Err(BridgeError::invalid()); } Command::Apply(v) },
        "github_input_group_reconcile" => { let v: ReconcileArgs = serde_json::from_value(value.clone()).map_err(|_| BridgeError::invalid())?;
            if !control(&v.session_id,v.expected_revision) || !hex(&v.original_operation_id,32) { return Err(BridgeError::invalid()); } Command::Reconcile(v) },
        "github_input_group_pending" => { let v: ControlArgs = serde_json::from_value(value.clone()).map_err(|_| BridgeError::invalid())?;
            if !control(&v.session_id,v.expected_revision) { return Err(BridgeError::invalid()); } Command::Pending(v) },
        "github_input_group_cancel" => { let v: CancelArgs = serde_json::from_value(value.clone()).map_err(|_| BridgeError::invalid())?;
            if !valid_id(&v.operation_id) { return Err(BridgeError::invalid()); } Command::Cancel(v) },
        _ => return Err(BridgeError::invalid()),
    })
}
#[cfg(test)]
#[path = "github_input_group_test_data.rs"]
pub(crate) mod test_data;

#[cfg(test)]
#[path = "github_input_group_protocol_tests.rs"]
mod tests;
