//! Closed repository-setting DATA. No credential, consent or execution owner.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use crate::{error::BridgeError, github_connection_protocol::{self as connection, bounds, coordinate,
    numeric_id, nullable, utc, GitHubReadControl}, protocol::{strict_json, valid_id}};

pub(crate) const PROTOCOL: &str = "mrk-github-setup/1";
pub(crate) const EVENT: &str = "github-remote-setup-status";
pub(crate) const INITIAL_LIMIT: usize = 8192;
pub(crate) const READY_LIMIT: usize = 512;
pub(crate) const GO_LIMIT: usize = 8192;
pub(crate) const RESPONSE_LIMIT: usize = 65536;
pub(crate) const LAST_REVISION: u32 = u32::MAX - 1;

pub(crate) fn hex(value: &str, size: usize) -> bool {
    value.len() == size && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Kind { Prepare, Apply }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Permission { Read, Write }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AllowedActions { All, LocalOnly, Selected }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum Selection {
    #[serde(rename = "actions_enabled")]
    ActionsEnabled { enabled: bool },
    #[serde(rename = "workflow_token_policy")]
    WorkflowTokenPolicy {
        #[serde(rename = "defaultWorkflowPermissions")] default_workflow_permissions: Permission,
        #[serde(rename = "canApprovePullRequestReviews")] can_approve_pull_request_reviews: bool,
    },
    #[serde(rename = "environment_protection")]
    Environment(EnvironmentSelection),
}
impl Selection {
    pub(crate) fn name(&self) -> &'static str { match self {
        Self::ActionsEnabled { .. } => "actions_enabled", Self::WorkflowTokenPolicy { .. } => "workflow_token_policy",
        Self::Environment(_) => "environment_protection",
    } }
    pub(crate) fn valid(&self) -> bool { match self { Self::Environment(v) => v.valid(), _ => true } }
    fn retained_heap_bytes(&self) -> usize { match self { Self::Environment(v) => v.retained_heap_bytes(), _ => 0 } }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged, deny_unknown_fields)]
pub(crate) enum Policy {
    Actions { enabled: bool, allowed_actions: AllowedActions, sha_pinning_required: bool },
    Workflow { default_workflow_permissions: Permission, can_approve_pull_request_reviews: bool },
}
impl Policy {
    pub(crate) fn changed(self, selection: Selection) -> Option<Self> { match (self, selection) {
        (Self::Actions { allowed_actions, sha_pinning_required, .. }, Selection::ActionsEnabled { enabled }) =>
            Some(Self::Actions { enabled, allowed_actions, sha_pinning_required }),
        (Self::Workflow { .. }, Selection::WorkflowTokenPolicy { default_workflow_permissions, can_approve_pull_request_reviews }) =>
            Some(Self::Workflow { default_workflow_permissions, can_approve_pull_request_reviews }),
        _ => None,
    } }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Target {
    pub(crate) project_binding: String, pub(crate) repository: String,
    pub(crate) account_id: String, pub(crate) repository_id: String, pub(crate) selection: Selection,
}
impl Target {
    pub(crate) fn valid(&self) -> bool { hex(&self.project_binding, 64) && coordinate(&self.repository)
        && numeric_id(&self.account_id) && numeric_id(&self.repository_id) && self.selection.valid()
        && (!matches!(&self.selection, Selection::Environment(_)) || environment_id(&self.account_id) && environment_id(&self.repository_id)) }
    pub(crate) fn retained_heap_bytes(&self) -> Option<usize> {
        self.project_binding.capacity().checked_add(self.repository.capacity())?
            .checked_add(self.account_id.capacity())?.checked_add(self.repository_id.capacity())?
            .checked_add(self.selection.retained_heap_bytes())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RepositoryPrepared {
    pub(crate) target: Target, pub(crate) before: Policy, pub(crate) after: Policy,
    pub(crate) observed_at: String, pub(crate) confirmation: String,
}
impl RepositoryPrepared {
    fn confirmation(&self) -> String { Self::confirmation_for(&self.target) }
    fn confirmation_for(target: &Target) -> String {
        format!("Change {} for {}? Review the exact before and after values. Enabling Actions can allow configured workflows to run; write tokens or review approvals grant additional privileges. GitHub does not provide an atomic compare-and-set here: another administrator can change settings after this review. This does not configure secrets, change local workflows, or qualify a release.", target.selection.name(), target.repository)
    }
    pub(crate) fn valid(&self) -> bool { self.target.valid() && utc(&self.observed_at)
        && self.before.changed(self.target.selection.clone()) == Some(self.after) && self.before != self.after
        && self.confirmation == self.confirmation() }
    pub(crate) fn retained_heap_bytes(&self) -> Option<usize> { self.target.retained_heap_bytes()?
        .checked_add(self.observed_at.capacity())?.checked_add(self.confirmation.capacity()) }
}
pub(crate) const ENVIRONMENT_CONFIRMATION: &str = "Send these exact GitHub create-or-update environment fields? A concurrent edit can be overwritten, a deleted environment recreated, or a newly created environment updated. There is no atomic compare-and-set. Protected-branches mode allows all branches if none are protected. Administrator bypass is not observed or configured here; review it on GitHub. This does not provision secrets or prove complete environment protection. Cancel does not undo a sent request.";
pub(crate) const ENVIRONMENT_POLICY_LIMIT: usize = 1024;
pub(crate) const ENVIRONMENT_FACTS_LIMIT: usize = 1536;
pub(crate) const ENVIRONMENT_PREPARED_LIMIT: usize = 4096;
pub(crate) const ENVIRONMENT_RETAINED_LIMIT: usize = 65536;
fn environment_id(value: &str) -> bool {
    numeric_id(value) && value.parse::<u64>().is_ok_and(|v| v <= i64::MAX as u64)
}
fn environment_login(value: &str) -> bool {
    !value.is_empty() && value.len() <= 39 && !value.contains("--")
        && value.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && value.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
fn environment_wire_fits<T: Serialize>(value: &T, maximum: usize) -> bool {
    serde_json::to_vec(value).ok().is_some_and(|v| v.len() <= maximum)
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum EnvironmentMode { Configure, Create }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum EnvironmentStage { Candidate, ExternalTesting, Production }
impl EnvironmentStage {
    fn name(self) -> &'static str { match self { Self::Candidate => "mobile-candidate",
        Self::ExternalTesting => "mobile-external-testing", Self::Production => "mobile-production" } }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum EnvironmentBranches { All, Protected }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EnvironmentSelection {
    pub(crate) mode: EnvironmentMode, pub(crate) stage: EnvironmentStage, pub(crate) wait_timer_minutes: u32,
    #[serde(deserialize_with = "nullable")] pub(crate) prevent_self_review: Option<bool>,
    #[serde(deserialize_with = "nullable")] pub(crate) reviewer_login: Option<String>,
    #[serde(deserialize_with = "nullable")] pub(crate) branches: Option<EnvironmentBranches>,
}
impl EnvironmentSelection {
    fn valid(&self) -> bool { self.wait_timer_minutes <= 43200 && match self.mode {
        EnvironmentMode::Configure => self.reviewer_login.is_none() && self.branches.is_none(),
        EnvironmentMode::Create => self.prevent_self_review == Some(true) && self.branches.is_some()
            && self.reviewer_login.as_ref().is_some_and(|v| environment_login(v)),
    } }
    fn retained_heap_bytes(&self) -> usize { self.reviewer_login.as_ref().map_or(0, String::capacity) }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum EnvironmentReviewerType { Team, User }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvironmentReviewerId {
    #[serde(rename = "type")] pub(crate) kind: EnvironmentReviewerType, pub(crate) id: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EnvironmentReviewers { pub(crate) prevent_self_review: bool, pub(crate) reviewers: Vec<EnvironmentReviewerId> }
impl EnvironmentReviewers {
    fn valid(&self) -> bool { !self.reviewers.is_empty() && self.reviewers.len() <= 6
        && self.reviewers.iter().all(|v| environment_id(&v.id))
        && self.reviewers.windows(2).all(|v| v[0] < v[1]) }
    fn retained_heap_bytes(&self) -> Option<usize> {
        let mut bytes = self.reviewers.capacity().checked_mul(std::mem::size_of::<EnvironmentReviewerId>())?;
        for value in &self.reviewers { bytes = bytes.checked_add(value.id.capacity())?; } Some(bytes)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EnvironmentPolicy {
    pub(crate) wait_timer_minutes: u32, pub(crate) protected_branches: bool,
    #[serde(deserialize_with = "nullable")] pub(crate) required_reviewers: Option<EnvironmentReviewers>,
}
impl EnvironmentPolicy {
    fn valid(&self) -> bool { self.wait_timer_minutes <= 43200
        && self.required_reviewers.as_ref().is_none_or(EnvironmentReviewers::valid)
        && environment_wire_fits(self, ENVIRONMENT_POLICY_LIMIT) }
    fn retained_heap_bytes(&self) -> Option<usize> {
        self.required_reviewers.as_ref().map_or(Some(0), EnvironmentReviewers::retained_heap_bytes)
    }
    fn unchanged_for(&self, selection: &EnvironmentSelection) -> bool {
        selection.mode == EnvironmentMode::Configure && self.wait_timer_minutes == selection.wait_timer_minutes
            && selection.prevent_self_review.is_none_or(|wanted|
                self.required_reviewers.as_ref().is_some_and(|v| v.prevent_self_review == wanted))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvironmentFacts {
    pub(crate) name: String,
    #[serde(deserialize_with = "nullable")] pub(crate) id: Option<String>,
    #[serde(deserialize_with = "nullable")] pub(crate) policy: Option<EnvironmentPolicy>,
}
impl EnvironmentFacts {
    fn valid(&self) -> bool {
        [EnvironmentStage::Candidate, EnvironmentStage::ExternalTesting, EnvironmentStage::Production].iter().any(|v| v.name() == self.name)
            && match (&self.id, &self.policy) { (None, None) => true,
                (Some(id), Some(policy)) => environment_id(id) && policy.valid(), _ => false }
            && environment_wire_fits(self, ENVIRONMENT_FACTS_LIMIT)
    }
    fn retained_heap_bytes(&self) -> Option<usize> { self.name.capacity().checked_add(self.id.as_ref().map_or(0, String::capacity))?
        .checked_add(self.policy.as_ref().map_or(Some(0), EnvironmentPolicy::retained_heap_bytes)?) }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum EnvironmentPermission { Read, Write, Admin }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvironmentReviewer { pub(crate) id: String, pub(crate) login: String, pub(crate) permission: EnvironmentPermission }
impl EnvironmentReviewer {
    fn valid(&self) -> bool { environment_id(&self.id) && environment_login(&self.login) }
    fn retained_heap_bytes(&self) -> Option<usize> { self.id.capacity().checked_add(self.login.capacity()) }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EnvironmentPrepared {
    pub(crate) target: Target, pub(crate) before: EnvironmentFacts, pub(crate) after: EnvironmentPolicy,
    #[serde(deserialize_with = "nullable")] pub(crate) reviewer: Option<EnvironmentReviewer>,
    pub(crate) observed_at: String, pub(crate) confirmation: String,
}
impl EnvironmentPrepared {
    fn valid(&self) -> bool {
        let Selection::Environment(selection) = &self.target.selection else { return false; };
        if !self.target.valid() || !self.before.valid() || !self.after.valid() || !utc(&self.observed_at)
            || self.before.name != selection.stage.name() || self.confirmation != ENVIRONMENT_CONFIRMATION
            || self.after.wait_timer_minutes != selection.wait_timer_minutes { return false; }
        let changed = match selection.mode {
            EnvironmentMode::Configure => self.reviewer.is_none() && self.before.policy.as_ref().is_some_and(|old|
                old != &self.after && old.protected_branches == self.after.protected_branches
                && match (&old.required_reviewers, &self.after.required_reviewers) {
                    (None, None) => selection.prevent_self_review.is_none(),
                    (Some(a), Some(b)) => a.reviewers == b.reviewers
                        && b.prevent_self_review == selection.prevent_self_review.unwrap_or(a.prevent_self_review),
                    _ => false,
                }),
            EnvironmentMode::Create => self.before.id.is_none() && self.reviewer.as_ref().is_some_and(|reviewer|
                reviewer.valid() && selection.reviewer_login.as_ref().is_some_and(|login| reviewer.login.eq_ignore_ascii_case(login))
                && self.after.protected_branches == (selection.branches == Some(EnvironmentBranches::Protected))
                && self.after.required_reviewers.as_ref().is_some_and(|rule| rule.prevent_self_review && rule.reviewers.len() == 1
                    && rule.reviewers[0].kind == EnvironmentReviewerType::User && rule.reviewers[0].id == reviewer.id)),
        };
        changed && environment_wire_fits(self, ENVIRONMENT_PREPARED_LIMIT)
    }
    fn retained_heap_bytes(&self) -> Option<usize> {
        self.target.retained_heap_bytes()?.checked_add(self.before.retained_heap_bytes()?)?
            .checked_add(self.after.retained_heap_bytes()?)?
            .checked_add(self.reviewer.as_ref().map_or(Some(0), EnvironmentReviewer::retained_heap_bytes)?)?
            .checked_add(self.observed_at.capacity())?.checked_add(self.confirmation.capacity())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum Prepared { Repository(RepositoryPrepared), Environment(EnvironmentPrepared) }
impl Prepared {
    pub(crate) fn target(&self) -> &Target { match self { Self::Repository(v) => &v.target, Self::Environment(v) => &v.target } }
    pub(crate) fn valid(&self) -> bool { match self { Self::Repository(v) => v.valid(), Self::Environment(v) => v.valid() } }
    pub(crate) fn retained_heap_bytes(&self) -> Option<usize> { match self {
        Self::Repository(v) => v.retained_heap_bytes(), Self::Environment(v) => v.retained_heap_bytes(),
    } }
    fn matches_before(&self, observed: &Observation) -> bool { match (self, observed) {
        (Self::Repository(v), Observation::Repository(p)) => v.before == *p,
        (Self::Environment(v), Observation::Environment(p)) => v.before == *p, _ => false,
    } }
    fn matches_after(&self, observed: &Observation) -> bool { match (self, observed) {
        (Self::Repository(v), Observation::Repository(p)) => v.after == *p,
        (Self::Environment(v), Observation::Environment(p)) => p.name == v.before.name && p.id.is_some()
            && p.policy.as_ref() == Some(&v.after) && (v.before.id.is_none() || p.id == v.before.id), _ => false,
    } }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum Observation { Repository(Policy), Environment(EnvironmentFacts) }
impl Observation {
    fn valid_for(&self, target: &Target) -> bool { match (self, &target.selection) {
        (Self::Repository(policy), Selection::ActionsEnabled { .. } | Selection::WorkflowTokenPolicy { .. }) =>
            policy.changed(target.selection.clone()).is_some(),
        (Self::Environment(facts), Selection::Environment(selection)) => facts.valid() && facts.name == selection.stage.name(),
        _ => false,
    } }
    fn unchanged_for(&self, target: &Target) -> bool { match (self, &target.selection) {
        (Self::Repository(policy), _) => policy.changed(target.selection.clone()) == Some(*policy),
        (Self::Environment(facts), Selection::Environment(selection)) =>
            facts.policy.as_ref().is_some_and(|v| v.unchanged_for(selection)), _ => false,
    } }
    fn retained_heap_bytes(&self) -> Option<usize> { match self { Self::Repository(_) => Some(0),
        Self::Environment(v) => v.retained_heap_bytes() } }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) kind: Kind, pub(crate) target: Target,
    #[serde(deserialize_with = "nullable")] pub(crate) prepared: Option<Prepared>,
}
impl Request {
    pub(crate) fn kind(&self) -> Kind { self.kind }
    pub(crate) fn valid(&self) -> bool { self.target.valid() && match (&self.kind, &self.prepared) {
        (Kind::Prepare, None) => true,
        (Kind::Apply, Some(prepared)) => prepared.valid() && prepared.target() == &self.target,
        _ => false,
    } }
    pub(crate) fn retained_heap_bytes(&self) -> Option<usize> { self.target.retained_heap_bytes()?
        .checked_add(self.prepared.as_ref().map_or(Some(0), Prepared::retained_heap_bytes)?) }
}
fn frame(raw: &[u8], limit: usize, nodes: usize, depth: usize) -> Result<Value, BridgeError> {
    if raw.len() < 3 || raw.len() > limit || !raw.ends_with(b"\n") { return Err(BridgeError::protocol()); }
    let body = &raw[..raw.len()-1];
    if body.first() != Some(&b'{') || body.last() != Some(&b'}')
        || body.iter().any(|b| matches!(b, b'\r' | b'\n')) { return Err(BridgeError::protocol()); }
    let value = strict_json(body)?;
    if !bounds(&value, limit, nodes, depth) { return Err(BridgeError::protocol()); } Ok(value)
}
pub(crate) fn encode_initial(id: &str, request: &Request) -> Result<Vec<u8>, BridgeError> {
    if !valid_id(id) || !request.valid() { return Err(BridgeError::invalid()); }
    let value = serde_json::json!({"protocol": PROTOCOL, "id": id, "action": request});
    if !bounds(&value, INITIAL_LIMIT - 1, 256, 8) { return Err(BridgeError::invalid()); }
    let mut raw = serde_json::to_vec(&value).map_err(|_| BridgeError::invalid())?; raw.push(b'\n');
    if raw.len() > INITIAL_LIMIT { return Err(BridgeError::invalid()); } Ok(raw)
}
pub(crate) fn request_digest(raw: &[u8]) -> String { format!("{:x}", Sha256::digest(raw)) }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ready { request_sha256: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyEnvelope { protocol: String, id: String, ready: Ready }
pub(crate) fn decode_ready(raw: &[u8], id: &str, digest: &str) -> Result<(), BridgeError> {
    let frame = frame(raw, READY_LIMIT, 32, 4)?;
    // Serde named structs also accept positional sequences. The public/private
    // protocol requires an object, not an equivalent positional representation.
    if !frame.get("ready").is_some_and(Value::is_object) { return Err(BridgeError::protocol()); }
    let value: ReadyEnvelope = serde_json::from_value(frame)
        .map_err(|_| BridgeError::protocol())?;
    if value.protocol != PROTOCOL || value.id != id || value.ready.request_sha256 != digest {
        return Err(BridgeError::protocol());
    } Ok(())
}
pub(crate) fn encode_go(id: &str, digest: &str, token: &str) -> Result<Vec<u8>, BridgeError> {
    if !valid_id(id) || !hex(digest, 64) || token.is_empty() || token.len() > 4096
        || !token.bytes().all(|b| (0x21..=0x7e).contains(&b)) { return Err(BridgeError::invalid()); }
    // One writer buffer; no token Value, public struct, log, Debug or journal.
    let mut raw = Vec::with_capacity(GO_LIMIT);
    raw.extend_from_slice(b"{\"protocol\":\"mrk-github-setup/1\",\"id\":");
    serde_json::to_writer(&mut raw, id).map_err(|_| BridgeError::invalid())?;
    raw.extend_from_slice(b",\"go\":{\"requestSha256\":");
    serde_json::to_writer(&mut raw, digest).map_err(|_| BridgeError::invalid())?;
    raw.extend_from_slice(b",\"token\":");
    serde_json::to_writer(&mut raw, token).map_err(|_| BridgeError::invalid())?;
    raw.extend_from_slice(b"}}\n");
    if raw.len() > GO_LIMIT { return Err(BridgeError::invalid()); } Ok(raw)
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason { None, NoChange, PolicyUnsupported, PolicyChanged, OrganizationRestricted, RepositoryArchived,
    Unauthorized, Forbidden, NotFoundOrInaccessible, TargetChanged, RateLimited, NetworkUnavailable, TlsFailed,
    ResponseInvalid, ResponseLimit, Expired, Cancelled, Unqualified, NotConnected, Busy, InvalidInput,
    CleanupUnknown, RuntimeUnavailable, ConsentExpired }
impl Reason {
    fn private(self) -> bool { !matches!(self, Self::Unqualified | Self::NotConnected | Self::Busy | Self::InvalidInput
        | Self::CleanupUnknown | Self::RuntimeUnavailable | Self::ConsentExpired) }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Effect { NotStarted, Unknown, ReadbackConfirmed }
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Outcome {
    pub(crate) schema_version: u32, pub(crate) action: Kind, pub(crate) reason: Reason, pub(crate) effect: Effect,
    pub(crate) write_claimed: bool, pub(crate) write_acknowledged: bool,
    #[serde(deserialize_with = "nullable")] pub(crate) prepared: Option<Prepared>,
    #[serde(deserialize_with = "nullable")] pub(crate) observed: Option<Observation>,
    pub(crate) control: GitHubReadControl,
}
impl Outcome {
    pub(crate) fn retained_heap_bytes(&self) -> Option<usize> {
        self.prepared.as_ref().map_or(Some(0), Prepared::retained_heap_bytes)?
            .checked_add(self.observed.as_ref().map_or(Some(0), Observation::retained_heap_bytes)?)?
            .checked_add(self.control.credential_expires_at.as_ref().map_or(0, String::capacity))
    }
    fn valid(&self, request: &Request) -> bool {
        if self.schema_version != 1 || self.action != request.kind || !self.reason.private() || !self.control.valid()
            || self.write_acknowledged && !self.write_claimed
            || self.observed.as_ref().is_some_and(|value| !value.valid_for(&request.target)) { return false; }
        if self.control.reason != connection::Reason::None
            && serde_json::to_value(self.control.reason).ok() != serde_json::to_value(self.reason).ok() { return false; }
        match self.action {
            Kind::Prepare => self.effect == Effect::NotStarted && !self.write_claimed && !self.write_acknowledged
                && (self.reason == Reason::None) == self.prepared.is_some()
                && matches!(self.reason, Reason::None | Reason::NoChange) == self.observed.is_some()
                && self.prepared.as_ref().is_none_or(|p| p.valid() && p.target() == &request.target
                    && self.observed.as_ref().is_some_and(|v| p.matches_before(v)))
                && (self.reason != Reason::NoChange || self.observed.as_ref().is_some_and(|v| v.unchanged_for(&request.target))),
            Kind::Apply => self.prepared.is_none() && self.reason != Reason::NoChange &&
                if self.effect == Effect::ReadbackConfirmed {
                    self.reason == Reason::None && self.write_acknowledged
                        && request.prepared.as_ref().is_some_and(|p| self.observed.as_ref().is_some_and(|v| p.matches_after(v)))
                } else { self.reason != Reason::None && self.observed.is_none()
                    && self.effect == if self.write_claimed { Effect::Unknown } else { Effect::NotStarted } },
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reply { protocol: String, id: String, pub(crate) result: Outcome }
impl Reply {
    pub(crate) fn retained_heap_bytes(&self) -> Option<usize> {
        self.protocol.capacity().checked_add(self.id.capacity())?.checked_add(self.result.retained_heap_bytes()?)
    }
}
// Keep the new environment wire object-only before named-struct Serde
// deserialization. Serde still enforces the complete exact field sets/types;
// these fixed shape checks reject its alternative positional-sequence form.
fn environment_policy_shape(value: &Value) -> bool {
    value.is_object() && match value.get("requiredReviewers") {
        Some(Value::Null) => true,
        Some(rule) if rule.is_object() => rule.get("reviewers").and_then(Value::as_array)
            .is_some_and(|rows| rows.iter().all(Value::is_object)),
        _ => false,
    }
}
fn environment_facts_shape(value: &Value) -> bool {
    value.is_object() && match value.get("policy") {
        Some(Value::Null) => true, Some(policy) => environment_policy_shape(policy), _ => false,
    }
}
fn environment_prepared_shape(value: &Value) -> bool {
    value.is_object() && value.get("target").is_some_and(|target| target.is_object()
        && target.get("selection").is_some_and(Value::is_object))
        && value.get("before").is_some_and(environment_facts_shape)
        && value.get("after").is_some_and(environment_policy_shape)
        && value.get("reviewer").is_some_and(|reviewer| reviewer.is_null() || reviewer.is_object())
}
fn environment_reply_shape(value: &Value) -> bool {
    let Some(result) = value.get("result").filter(|v| v.is_object()) else { return false; };
    result.get("control").is_some_and(Value::is_object)
        && result.get("prepared").is_some_and(|v| v.is_null() || environment_prepared_shape(v))
        && result.get("observed").is_some_and(|v| v.is_null() || environment_facts_shape(v))
}
pub(crate) fn decode_reply(id: &str, raw: &[u8], request: &Request) -> Result<Reply, BridgeError> {
    let frame = frame(raw, RESPONSE_LIMIT, 1024, 12)?;
    if matches!(&request.target.selection, Selection::Environment(_)) && !environment_reply_shape(&frame) {
        return Err(BridgeError::protocol());
    }
    let reply: Reply = serde_json::from_value(frame)
        .map_err(|_| BridgeError::protocol())?;
    if reply.protocol != PROTOCOL || reply.id != id || !request.valid() || !reply.result.valid(request) {
        return Err(BridgeError::protocol());
    } Ok(reply)
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase { Running, Stopping, Settled, CleanupUnknown }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Operation { pub(crate) id: String, pub(crate) kind: Kind, pub(crate) phase: Phase,
    pub(crate) reason: Reason, pub(crate) effect: Effect,
    pub(crate) write_claimed: Option<bool>, pub(crate) write_acknowledged: Option<bool> }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConsentView { pub(crate) id: String, pub(crate) expires_at: String, pub(crate) prepared: Prepared }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status { pub(crate) schema_version: u32, pub(crate) revision: u32, pub(crate) session_id: Option<String>,
    pub(crate) available: bool, pub(crate) reason: Reason, pub(crate) operation: Option<Operation>,
    pub(crate) consent: Option<ConsentView>, pub(crate) observed: Option<Observation> }
impl Status {
    pub(crate) fn fits_wire(&self) -> bool { serde_json::to_value(self).ok().is_some_and(|value|
        bounds(&value, RESPONSE_LIMIT, 1024, 12)) }
    pub(crate) fn retained_heap_bytes(&self) -> Option<usize> {
        let mut bytes = self.session_id.as_ref().map_or(0, String::capacity);
        if let Some(v) = &self.operation { bytes = bytes.checked_add(v.id.capacity())?; }
        if let Some(v) = &self.consent { bytes = bytes.checked_add(v.id.capacity())?
            .checked_add(v.expires_at.capacity())?.checked_add(v.prepared.retained_heap_bytes()?)?; }
        bytes.checked_add(self.observed.as_ref().map_or(Some(0), Observation::retained_heap_bytes)?)
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PrepareArgs { pub(crate) session_id: String, pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32, pub(crate) selection: Selection }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ApplyArgs { pub(crate) session_id: String, pub(crate) expected_revision: u32,
    pub(crate) consent_id: String, pub(crate) confirm: bool }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DiscardArgs { pub(crate) session_id: String, pub(crate) expected_revision: u32, pub(crate) consent_id: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CancelArgs { pub(crate) operation_id: String }
pub(crate) enum Command { Status, Prepare(PrepareArgs), Apply(ApplyArgs), Discard(DiscardArgs), Cancel(CancelArgs) }
fn revision(value: u32) -> bool { value != 0 && value <= LAST_REVISION }
pub(crate) fn decode_command(name: &str, value: &Value) -> Result<Command, BridgeError> {
    if !value.is_object() || !bounds(value, 4096, 64, 4) { return Err(BridgeError::invalid()); }
    fn read<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, BridgeError> {
        serde_json::from_value(v.clone()).map_err(|_| BridgeError::invalid())
    }
    let command = match name {
        "github_remote_setup_status" if value.as_object().is_some_and(|v| v.is_empty()) => Command::Status,
        "github_remote_setup_prepare" => { let v: PrepareArgs = read(value)?;
            if !valid_id(&v.session_id) || !revision(v.expected_revision) || !revision(v.expected_connection_revision) || !v.selection.valid() { return Err(BridgeError::invalid()); }
            Command::Prepare(v) },
        "github_remote_setup_apply" => { let v: ApplyArgs = read(value)?;
            if !valid_id(&v.session_id) || !revision(v.expected_revision) || !hex(&v.consent_id, 32) || !v.confirm { return Err(BridgeError::invalid()); }
            Command::Apply(v) },
        "github_remote_setup_discard" => { let v: DiscardArgs = read(value)?;
            if !valid_id(&v.session_id) || !revision(v.expected_revision) || !hex(&v.consent_id, 32) { return Err(BridgeError::invalid()); }
            Command::Discard(v) },
        "github_remote_setup_cancel" => { let v: CancelArgs = read(value)?;
            if !valid_id(&v.operation_id) { return Err(BridgeError::invalid()); } Command::Cancel(v) },
        _ => return Err(BridgeError::invalid()),
    }; Ok(command)
}

// New environment-only retained DATA ceiling. The parts are real capacities
// or an explicitly conservative clone reservation, never wire byte lengths.
pub(crate) fn environment_retention_fits(parts: &[Option<usize>]) -> bool {
    parts.iter().try_fold(0usize, |sum, value| sum.checked_add((*value)?))
        .is_some_and(|total| total <= ENVIRONMENT_RETAINED_LIMIT)
}
pub(crate) fn future_status_fits(request: &Request, session: &str) -> bool {
    if !request.valid() || !valid_id(session) { return false; }
    if matches!(&request.target.selection, Selection::Environment(_)) {
        // Size only: the ceiling is deliberately not parsed into authoritative
        // Prepared/Facts. Six longest IDs, both reviewer types, longest fixed
        // name, full before/after/observed and reviewer cover both modes.
        let reviewers: Vec<Value> = (0..6).map(|i| serde_json::json!({"type":"Team",
            "id":format!("922337203685477580{}", i)})).collect();
        let policy = serde_json::json!({"waitTimerMinutes":43200,"protectedBranches":false,
            "requiredReviewers":{"preventSelfReview":false,"reviewers":reviewers}});
        let facts = serde_json::json!({"name":"mobile-external-testing","id":"9223372036854775807","policy":policy});
        let value = serde_json::json!({"schemaVersion":1,"revision":LAST_REVISION,"sessionId":session,
            "available":false,"reason":"not-found-or-inaccessible","operation":{"id":"x".repeat(64),"kind":"prepare",
            "phase":"cleanup-unknown","reason":"not-found-or-inaccessible","effect":"readback-confirmed",
            "writeClaimed":false,"writeAcknowledged":false},"consent":{"id":"a".repeat(32),"expiresAt":"9999-12-31T23:59:59Z",
            "prepared":{"target":request.target,"before":facts,"after":policy,
            "reviewer":{"id":"9223372036854775807","login":"x".repeat(39),"permission":"write"},
            "observedAt":"9999-12-31T23:59:59Z","confirmation":ENVIRONMENT_CONFIRMATION}},"observed":facts});
        return bounds(&value, RESPONSE_LIMIT - 512, 1024, 12);
    }
    // Size-only ceiling, never parsed as a Policy/Prepared or retained as
    // authority. Both mutually exclusive policy fields are charged together;
    // each eventual before/after/observed policy is strictly smaller. The
    // remaining 512 bytes cover all fixed operation reason/phase/id variants.
    let policy_ceiling = serde_json::json!({"enabled":false,"allowed_actions":"local_only","sha_pinning_required":false,
        "default_workflow_permissions":"write","can_approve_pull_request_reviews":false});
    let value = serde_json::json!({"schemaVersion":1,"revision":LAST_REVISION,"sessionId":session,
        "available":false,"reason":"not-found-or-inaccessible", "operation":{"id":"x".repeat(64),"kind":"prepare",
        "phase":"cleanup-unknown","reason":"not-found-or-inaccessible","effect":"readback-confirmed",
        "writeClaimed":false,"writeAcknowledged":false},"consent":{"id":"a".repeat(32),"expiresAt":"9999-12-31T23:59:59Z",
        "prepared":{"target":request.target,"before":policy_ceiling,"after":policy_ceiling,
        "observedAt":"9999-12-31T23:59:59Z","confirmation":RepositoryPrepared::confirmation_for(&request.target)}},"observed":policy_ceiling});
    bounds(&value, RESPONSE_LIMIT - 512, 512, 10)
}

// Existing native DATA group calls these real codecs. No network, child,
// credential material, installed runtime, or original effect is constructed.
#[cfg(test)]
pub(crate) fn data_checks() {
    use serde_json::json;
    let target = Target { project_binding: "a".repeat(64), repository: "owner/repository".into(),
        account_id: "1".into(), repository_id: "2".into(), selection: Selection::ActionsEnabled { enabled: true } };
    let request = Request { kind: Kind::Prepare, target: target.clone(), prepared: None };
    let initial = encode_initial("setup-1", &request).unwrap();
    assert!(initial.len() <= INITIAL_LIMIT && initial.ends_with(b"\n"));
    let digest = request_digest(&initial);
    let ready = json!({"protocol":PROTOCOL,"id":"setup-1","ready":{"requestSha256":digest}});
    let line = |value: &Value| { let mut raw = serde_json::to_vec(value).unwrap(); raw.push(b'\n'); raw };
    assert!(decode_ready(&line(&ready), "setup-1", &digest).is_ok());
    assert!(decode_ready(&line(&ready), "setup-2", &digest).is_err());
    let mut positional=ready.clone();positional["ready"]=json!([digest]);
    assert!(decode_ready(&line(&positional), "setup-1", &digest).is_err());
    let mut wrong = ready.clone(); wrong["ready"]["journal"] = Value::Null;
    assert!(decode_ready(&line(&wrong), "setup-1", &digest).is_err());
    let mut wrong = line(&ready); wrong.extend_from_slice(b"{}\n");
    assert!(decode_ready(&wrong, "setup-1", &digest).is_err());
    let mut wrong = line(&ready); wrong.pop(); assert!(decode_ready(&wrong,"setup-1",&digest).is_err());
    assert!(decode_ready(&vec![b' '; READY_LIMIT+1], "setup-1", &digest).is_err());
    let go = encode_go("setup-1", &digest, "inert-test-token").unwrap();
    let go: Value = serde_json::from_slice(&go).unwrap();
    assert_eq!(go["go"]["requestSha256"], digest);
    assert_eq!(go["go"]["token"], "inert-test-token");
    for token in ["", "has space", "bad\n", "bad\u{7f}"] { assert!(encode_go("setup-1",&digest,token).is_err()); }
    assert!(encode_go("setup-1", &digest, &"x".repeat(4097)).is_err());
    assert!(encode_go("setup-1", "not-digest", "inert").is_err());
    let before = Policy::Actions { enabled: false, allowed_actions: AllowedActions::Selected, sha_pinning_required: true };
    let mut prepared = RepositoryPrepared { target: target.clone(), before, after: before.changed(target.selection.clone()).unwrap(),
        observed_at: "2026-10-09T00:00:00Z".into(), confirmation: String::new() };
    prepared.confirmation = prepared.confirmation(); assert!(prepared.valid());
    let control = json!({"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false});
    let result = json!({"schemaVersion":1,"action":"prepare","reason":"none","effect":"not-started",
        "writeClaimed":false,"writeAcknowledged":false,"prepared":prepared,"observed":before,"control":control});
    let envelope = |result: Value| json!({"protocol":PROTOCOL,"id":"setup-1","result":result});
    let parsed = decode_reply("setup-1",&line(&envelope(result.clone())),&request).unwrap();
    assert_eq!(parsed.result.observed,Some(Observation::Repository(before)));
    for field in ["writeClaimed","writeAcknowledged"] {
        let mut bad=result.clone(); bad[field]=json!(0);
        assert!(decode_reply("setup-1",&line(&envelope(bad)),&request).is_err());
    }
    for field in ["enabled","sha_pinning_required"] {
        let mut bad=result.clone(); bad["prepared"]["after"][field]=json!(1);
        assert!(decode_reply("setup-1",&line(&envelope(bad)),&request).is_err());
    }
    let mut bad=result.clone(); bad["prepared"]["after"]["allowed_actions"]=json!("all");
    assert!(decode_reply("setup-1",&line(&envelope(bad)),&request).is_err());
    let mut bad=result.clone(); bad["prepared"]["target"]["repositoryId"]=json!("3");
    assert!(decode_reply("setup-1",&line(&envelope(bad)),&request).is_err());
    let apply=Request { kind:Kind::Apply,target:target.clone(),prepared:Some(Prepared::Repository(prepared.clone())) };
    let committed=json!({"schemaVersion":1,"action":"apply","reason":"none","effect":"readback-confirmed",
        "writeClaimed":true,"writeAcknowledged":true,"prepared":null,"observed":prepared.after,"control":control});
    assert!(decode_reply("setup-1",&line(&envelope(committed.clone())),&apply).is_ok());
    for (field,value) in [("writeClaimed",json!(false)),("writeAcknowledged",json!(false)),("observed",Value::Null),
        ("reason",json!("cancelled")),("effect",json!("not-started"))] {
        let mut bad=committed.clone();bad[field]=value;assert!(decode_reply("setup-1",&line(&envelope(bad)),&apply).is_err());
    }
    assert!(decode_reply("setup-1",&line(&envelope(committed)),&request).is_err());
    for (claimed,acknowledged) in [(false,false),(true,false),(true,true)] {
        let failed=json!({"schemaVersion":1,"action":"apply","reason":"network-unavailable",
            "effect":if claimed {"unknown"} else {"not-started"},"writeClaimed":claimed,"writeAcknowledged":acknowledged,
            "prepared":null,"observed":null,"control":control});
        assert!(decode_reply("setup-1",&line(&envelope(failed)),&apply).is_ok());
    }
    let workflow = Policy::Workflow { default_workflow_permissions: Permission::Read, can_approve_pull_request_reviews:false };
    let selection = Selection::WorkflowTokenPolicy { default_workflow_permissions:Permission::Write,can_approve_pull_request_reviews:true };
    assert_eq!(workflow.changed(selection.clone()),Some(Policy::Workflow { default_workflow_permissions:Permission::Write,can_approve_pull_request_reviews:true }));
    assert!(workflow.changed(target.selection.clone()).is_none() && before.changed(selection).is_none());
    for value in [json!({"default_workflow_permissions":"write","can_approve_pull_request_reviews":1}),
        json!({"enabled":true,"allowed_actions":"all"}),json!({"enabled":true,"allowed_actions":"all","sha_pinning_required":false,"extra":0})] {
        assert!(serde_json::from_value::<Policy>(value).is_err());
    }
    let args=json!({"sessionId":"session-1","expectedRevision":1,"expectedConnectionRevision":2,
        "selection":{"kind":"actions_enabled","enabled":true}});
    assert!(decode_command("github_remote_setup_prepare",&args).is_ok());
    let mut bad=args.clone();bad["selection"]["enabled"]=json!(1);assert!(decode_command("github_remote_setup_prepare",&bad).is_err());
    let mut bad=args;bad["url"]=json!("https://example.invalid");assert!(decode_command("github_remote_setup_prepare",&bad).is_err());
    for confirm in [json!(false),json!(1),Value::Null] {
        assert!(decode_command("github_remote_setup_apply",&json!({"sessionId":"s","expectedRevision":1,"consentId":"a".repeat(32),"confirm":confirm})).is_err());
    }
    assert!(future_status_fits(&request,"session-1") && future_status_fits(&apply,"session-1"));
    // Real closed environment codecs, not a parallel mock parser. Maximum
    // six-reviewer configure and explicit observed-absent create share the
    // original Initial/READY/GO/reply frames and same numeric bounds.
    let env_selection = json!({"kind":"environment_protection","mode":"configure","stage":"external-testing",
        "waitTimerMinutes":43200,"preventSelfReview":true,"reviewerLogin":null,"branches":null});
    let mut env_target = serde_json::to_value(&target).unwrap(); env_target["selection"] = env_selection.clone();
    let rows: Vec<Value> = (0..6).map(|i| json!({"type":if i < 3 {"Team"} else {"User"},
        "id":format!("922337203685477580{}", i)})).collect();
    let env_before = json!({"name":"mobile-external-testing","id":"9223372036854775807","policy":{
        "waitTimerMinutes":0,"protectedBranches":true,"requiredReviewers":{"preventSelfReview":false,"reviewers":rows}}});
    let mut env_after=env_before["policy"].clone();env_after["waitTimerMinutes"]=json!(43200);
    env_after["requiredReviewers"]["preventSelfReview"]=json!(true);
    let env_prepared=json!({"target":env_target,"before":env_before,"after":env_after,"reviewer":null,
        "observedAt":"2026-10-09T00:00:00Z","confirmation":ENVIRONMENT_CONFIRMATION});
    let env_prepare: Request=serde_json::from_value(json!({"kind":"prepare","target":env_target,"prepared":null})).unwrap();
    let env_apply: Request=serde_json::from_value(json!({"kind":"apply","target":env_target,"prepared":env_prepared})).unwrap();
    assert!(env_prepare.valid() && env_apply.valid());
    assert!(future_status_fits(&env_prepare,"session-1") && future_status_fits(&env_apply,"session-1"));
    for value in [&env_prepare,&env_apply] {
        let encoded=encode_initial("setup-1",value).unwrap();
        assert!(encoded.len()<=INITIAL_LIMIT && bounds(&serde_json::from_slice::<Value>(&encoded).unwrap(),INITIAL_LIMIT,256,8));
        let hash=request_digest(&encoded);
        assert!(decode_ready(&line(&json!({"protocol":PROTOCOL,"id":"setup-1","ready":{"requestSha256":hash}})),"setup-1",&hash).is_ok());
        assert!(encode_go("setup-1",&hash,"inert-test-token").is_ok());
    }
    let env_result=json!({"schemaVersion":1,"action":"prepare","reason":"none","effect":"not-started",
        "writeClaimed":false,"writeAcknowledged":false,"prepared":env_prepared,"observed":env_before,"control":control});
    assert!(decode_reply("setup-1",&line(&envelope(env_result.clone())),&env_prepare).is_ok());
    assert!(decode_reply("setup-1",&line(&envelope(env_result.clone())),&request).is_err());
    for pointer in ["/prepared/after/protectedBranches","/prepared/after/requiredReviewers/preventSelfReview",
        "/observed/policy/protectedBranches","/observed/policy/requiredReviewers/preventSelfReview"] {
        let mut bad=env_result.clone();*bad.pointer_mut(pointer).unwrap()=json!(1);
        assert!(decode_reply("setup-1",&line(&envelope(bad)),&env_prepare).is_err());
    }
    for id in [json!("0"),json!("01"),json!("9223372036854775808"),json!(1),json!(true)] {
        let mut bad=env_result.clone();bad["prepared"]["after"]["requiredReviewers"]["reviewers"][0]["id"]=id;
        assert!(decode_reply("setup-1",&line(&envelope(bad)),&env_prepare).is_err());
    }
    for field in ["reviewer","confirmation"] {
        let mut bad=env_result.clone();bad["prepared"].as_object_mut().unwrap().remove(field);
        assert!(decode_reply("setup-1",&line(&envelope(bad)),&env_prepare).is_err());
    }
    for path in ["/prepared/after/requiredReviewers/reviewers","/observed/policy/requiredReviewers/reviewers"] {
        for alteration in 0..3 {
            let mut bad=env_result.clone();let rows=bad.pointer_mut(path).unwrap().as_array_mut().unwrap();
            match alteration {0=>rows.swap(0,1),1=>rows[1]=rows[0].clone(),_=>rows.push(rows[0].clone())}
            assert!(decode_reply("setup-1",&line(&envelope(bad)),&env_prepare).is_err());
        }
    }
    let mut wrong=env_prepared.clone();wrong["after"]["protectedBranches"]=json!(false);
    assert!(!serde_json::from_value::<Prepared>(wrong).unwrap().valid());
    for field in ["accountId","repositoryId"] {
        let mut bad=env_target.clone();bad[field]=json!("9223372036854775808");
        assert!(!serde_json::from_value::<Target>(bad).unwrap().valid());
    }
    let mut current=env_before.clone();current["policy"]=env_after.clone();
    let env_committed=json!({"schemaVersion":1,"action":"apply","reason":"none","effect":"readback-confirmed",
        "writeClaimed":true,"writeAcknowledged":true,"prepared":null,"observed":current,"control":control});
    assert!(decode_reply("setup-1",&line(&envelope(env_committed.clone())),&env_apply).is_ok());
    for (field,value) in [("id",json!("3")),("id",Value::Null),("name",json!("mobile-production")),("policy",env_before["policy"].clone())] {
        let mut bad=env_committed.clone();bad["observed"][field]=value;
        assert!(decode_reply("setup-1",&line(&envelope(bad)),&env_apply).is_err());
    }
    let mut no_change=env_result.clone();no_change["reason"]=json!("no-change");no_change["prepared"]=Value::Null;
    no_change["observed"]=current.clone();
    assert!(decode_reply("setup-1",&line(&envelope(no_change.clone())),&env_prepare).is_ok());
    no_change["observed"]=env_before.clone();assert!(decode_reply("setup-1",&line(&envelope(no_change)),&env_prepare).is_err());
    let mut create_target=env_target.clone();create_target["selection"]=json!({"kind":"environment_protection","mode":"create",
        "stage":"production","waitTimerMinutes":10,"preventSelfReview":true,"reviewerLogin":"Explicit-Reviewer","branches":"protected"});
    let absent=json!({"name":"mobile-production","id":null,"policy":null});
    let create_after=json!({"waitTimerMinutes":10,"protectedBranches":true,"requiredReviewers":{"preventSelfReview":true,
        "reviewers":[{"type":"User","id":"42"}]}});
    let create_prepared=json!({"target":create_target,"before":absent,"after":create_after,
        "reviewer":{"id":"42","login":"explicit-reviewer","permission":"write"},"observedAt":"2026-10-09T00:00:00Z","confirmation":ENVIRONMENT_CONFIRMATION});
    let create_prepare:Request=serde_json::from_value(json!({"kind":"prepare","target":create_target,"prepared":null})).unwrap();
    let create_apply:Request=serde_json::from_value(json!({"kind":"apply","target":create_target,"prepared":create_prepared})).unwrap();
    assert!(create_apply.valid() && future_status_fits(&create_apply,"session-1"));
    let mut create_result=env_result.clone();create_result["prepared"]=create_prepared.clone();create_result["observed"]=absent;
    assert!(decode_reply("setup-1",&line(&envelope(create_result.clone())),&create_prepare).is_ok());
    for (field,value) in [("login",json!("other")),("permission",json!("triage")),("id",json!("43"))] {
        let mut bad=create_result.clone();bad["prepared"]["reviewer"][field]=value;
        assert!(decode_reply("setup-1",&line(&envelope(bad)),&create_prepare).is_err());
    }
    let mut created=env_committed.clone();created["observed"]=json!({"name":"mobile-production","id":"123","policy":create_after});
    assert!(decode_reply("setup-1",&line(&envelope(created.clone())),&create_apply).is_ok());
    created["observed"]["id"]=Value::Null;assert!(decode_reply("setup-1",&line(&envelope(created)),&create_apply).is_err());
    for selection in [env_selection,create_target["selection"].clone()] {
        let args=json!({"sessionId":"session-1","expectedRevision":1,"expectedConnectionRevision":2,"selection":selection});
        assert!(decode_command("github_remote_setup_prepare",&args).is_ok());
        for (field,value) in [("waitTimerMinutes",json!(true)),("waitTimerMinutes",json!(43201)),("stage",json!("arbitrary")),("preventSelfReview",json!(1))] {
            let mut bad=args.clone();bad["selection"][field]=value;
            assert!(decode_command("github_remote_setup_prepare",&bad).is_err());
        }
        let mut bad=args;bad["selection"].as_object_mut().unwrap().remove("reviewerLogin");
        assert!(decode_command("github_remote_setup_prepare",&bad).is_err());
    }
    // Each new named struct's valid object replaced by its otherwise accepted
    // Serde positional sequence must fail at the ACTUAL decoder boundary.
    for (pointer, fields) in [
        ("/result", vec!["schemaVersion","action","reason","effect","writeClaimed","writeAcknowledged","prepared","observed","control"]),
        ("/result/control",vec!["reason","credentialExpiresAt","cooldownSeconds","cooldownBlocked"]),
        ("/result/prepared",vec!["target","before","after","reviewer","observedAt","confirmation"]),
        ("/result/prepared/target",vec!["projectBinding","repository","accountId","repositoryId","selection"]),
        ("/result/prepared/before",vec!["name","id","policy"]),
        ("/result/prepared/before/policy",vec!["waitTimerMinutes","protectedBranches","requiredReviewers"]),
        ("/result/prepared/after",vec!["waitTimerMinutes","protectedBranches","requiredReviewers"]),
        ("/result/prepared/after/requiredReviewers",vec!["preventSelfReview","reviewers"]),
        ("/result/prepared/after/requiredReviewers/reviewers/0",vec!["type","id"]),
        ("/result/observed",vec!["name","id","policy"]),
        ("/result/observed/policy",vec!["waitTimerMinutes","protectedBranches","requiredReviewers"]),
        ("/result/observed/policy/requiredReviewers",vec!["preventSelfReview","reviewers"]),
        ("/result/observed/policy/requiredReviewers/reviewers/0",vec!["type","id"]),
    ] {
        let mut bad=envelope(env_result.clone());let node=bad.pointer_mut(pointer).unwrap();
        *node=Value::Array(fields.iter().map(|field|node[*field].clone()).collect());
        assert!(decode_reply("setup-1",&line(&bad),&env_prepare).is_err(),"positional {pointer}");
    }
    let mut bad=envelope(create_result.clone());
    bad["result"]["prepared"]["reviewer"]=json!(["42","explicit-reviewer","write"]);
    assert!(decode_reply("setup-1",&line(&bad),&create_prepare).is_err());
    let mut bad=envelope(create_result.clone());
    bad["result"]["prepared"]["target"]["selection"]=json!(["create","production",10,true,"Explicit-Reviewer","protected"]);
    assert!(decode_reply("setup-1",&line(&bad),&create_prepare).is_err());
    assert!(decode_command("github_remote_setup_prepare",&json!(["session-1",1,2,create_target["selection"]])).is_err());
    assert!(decode_command("github_remote_setup_apply",&json!(["session-1",1,"a".repeat(32),true])).is_err());
    assert!(decode_command("github_remote_setup_discard",&json!(["session-1",1,"a".repeat(32)])).is_err());
    assert!(decode_command("github_remote_setup_cancel",&json!(["setup-1"])).is_err());
    let mut retained_reply=decode_reply("setup-1",&line(&envelope(env_result.clone())),&env_prepare).unwrap();
    let Some(Prepared::Environment(ref mut retained_prepared))=retained_reply.result.prepared else {panic!("environment DATA");};
    retained_prepared.after.required_reviewers.as_mut().unwrap().reviewers.reserve(32);
    let clone=retained_reply.clone();
    assert!(retained_reply.retained_heap_bytes().unwrap()>clone.retained_heap_bytes().unwrap());
    assert_eq!(retained_reply.retained_heap_bytes(),retained_reply.result.retained_heap_bytes()
        .and_then(|v|v.checked_add(retained_reply.protocol.capacity()))
        .and_then(|v|v.checked_add(retained_reply.id.capacity())));
    // Capacity, not serialized length: Vec spare slots and each retained string
    // are charged monotonically. Same helper gates actual pre-start/publication.
    assert!(environment_retention_fits(&[Some(ENVIRONMENT_RETAINED_LIMIT)]));
    assert!(!environment_retention_fits(&[Some(ENVIRONMENT_RETAINED_LIMIT),Some(1)]));
    assert!(!environment_retention_fits(&[Some(usize::MAX),Some(1)]));
    assert!(!environment_retention_fits(&[None]));
    let mut heap_policy:EnvironmentPolicy=serde_json::from_value(env_after).unwrap();
    let old=heap_policy.retained_heap_bytes().unwrap();
    let rule=heap_policy.required_reviewers.as_mut().unwrap();let slots=rule.reviewers.capacity();
    rule.reviewers.reserve(24);let added_slots=rule.reviewers.capacity()-slots;
    let old_string=rule.reviewers[0].id.capacity();rule.reviewers[0].id.reserve(80);
    let added_string=rule.reviewers[0].id.capacity()-old_string;
    assert_eq!(heap_policy.retained_heap_bytes().unwrap()-old,
        added_slots*std::mem::size_of::<EnvironmentReviewerId>()+added_string);
    let mut facts:EnvironmentFacts=serde_json::from_value(current).unwrap();facts.policy=Some(heap_policy);
    let observed=Observation::Environment(facts);let observed_bytes=observed.retained_heap_bytes().unwrap();
    let mut status=Status {schema_version:1,revision:1,session_id:None,available:false,reason:Reason::NotConnected,
        operation:None,consent:None,observed:None};
    let old=status.retained_heap_bytes().unwrap();status.observed=Some(observed);
    assert_eq!(status.retained_heap_bytes(),Some(old+observed_bytes));
    let mut oversize=env_apply.clone();
    let Some(Prepared::Environment(value))=&mut oversize.prepared else { panic!("environment test fixture"); };
    value.confirmation.reserve(ENVIRONMENT_RETAINED_LIMIT);
    assert!(oversize.valid()); // Semantic/wire validity is not a retained-budget waiver.
    assert!(!environment_retention_fits(&[oversize.retained_heap_bytes()]));
}
