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
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum Selection {
    #[serde(rename = "actions_enabled")]
    ActionsEnabled { enabled: bool },
    #[serde(rename = "workflow_token_policy")]
    WorkflowTokenPolicy {
        #[serde(rename = "defaultWorkflowPermissions")] default_workflow_permissions: Permission,
        #[serde(rename = "canApprovePullRequestReviews")] can_approve_pull_request_reviews: bool,
    },
}
impl Selection {
    pub(crate) fn name(self) -> &'static str { match self {
        Self::ActionsEnabled { .. } => "actions_enabled", Self::WorkflowTokenPolicy { .. } => "workflow_token_policy",
    } }
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
        && numeric_id(&self.account_id) && numeric_id(&self.repository_id) }
    pub(crate) fn retained_heap_bytes(&self) -> Option<usize> {
        self.project_binding.capacity().checked_add(self.repository.capacity())?
            .checked_add(self.account_id.capacity())?.checked_add(self.repository_id.capacity())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepared {
    pub(crate) target: Target, pub(crate) before: Policy, pub(crate) after: Policy,
    pub(crate) observed_at: String, pub(crate) confirmation: String,
}
impl Prepared {
    fn confirmation(&self) -> String { Self::confirmation_for(&self.target) }
    fn confirmation_for(target: &Target) -> String {
        format!("Change {} for {}? Review the exact before and after values. Enabling Actions can allow configured workflows to run; write tokens or review approvals grant additional privileges. GitHub does not provide an atomic compare-and-set here: another administrator can change settings after this review. This does not configure secrets, change local workflows, or qualify a release.", target.selection.name(), target.repository)
    }
    pub(crate) fn valid(&self) -> bool { self.target.valid() && utc(&self.observed_at)
        && self.before.changed(self.target.selection) == Some(self.after) && self.before != self.after
        && self.confirmation == self.confirmation() }
    pub(crate) fn retained_heap_bytes(&self) -> Option<usize> { self.target.retained_heap_bytes()?
        .checked_add(self.observed_at.capacity())?.checked_add(self.confirmation.capacity()) }
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
        (Kind::Apply, Some(prepared)) => prepared.valid() && prepared.target == self.target,
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
    let value: ReadyEnvelope = serde_json::from_value(frame(raw, READY_LIMIT, 32, 4)?)
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
    #[serde(deserialize_with = "nullable")] pub(crate) observed: Option<Policy>,
    pub(crate) control: GitHubReadControl,
}
impl Outcome {
    fn valid(&self, request: &Request) -> bool {
        if self.schema_version != 1 || self.action != request.kind || !self.reason.private() || !self.control.valid()
            || self.write_acknowledged && !self.write_claimed
            || self.observed.is_some_and(|policy| policy.changed(request.target.selection).is_none()) { return false; }
        if self.control.reason != connection::Reason::None
            && serde_json::to_value(self.control.reason).ok() != serde_json::to_value(self.reason).ok() { return false; }
        match self.action {
            Kind::Prepare => self.effect == Effect::NotStarted && !self.write_claimed && !self.write_acknowledged
                && (self.reason == Reason::None) == self.prepared.is_some()
                && matches!(self.reason, Reason::None | Reason::NoChange) == self.observed.is_some()
                && self.prepared.as_ref().is_none_or(|p| p.valid() && p.target == request.target && self.observed == Some(p.before))
                && (self.reason != Reason::NoChange || self.observed.is_some_and(|p| p.changed(request.target.selection) == Some(p))),
            Kind::Apply => self.prepared.is_none() && self.reason != Reason::NoChange &&
                if self.effect == Effect::ReadbackConfirmed {
                    self.reason == Reason::None && self.write_acknowledged
                        && request.prepared.as_ref().is_some_and(|p| self.observed == Some(p.after))
                } else { self.reason != Reason::None && self.observed.is_none()
                    && self.effect == if self.write_claimed { Effect::Unknown } else { Effect::NotStarted } },
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reply { protocol: String, id: String, pub(crate) result: Outcome }
pub(crate) fn decode_reply(id: &str, raw: &[u8], request: &Request) -> Result<Reply, BridgeError> {
    let reply: Reply = serde_json::from_value(frame(raw, RESPONSE_LIMIT, 1024, 12)?)
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
    pub(crate) consent: Option<ConsentView>, pub(crate) observed: Option<Policy> }
impl Status {
    pub(crate) fn fits_wire(&self) -> bool { serde_json::to_value(self).ok().is_some_and(|value|
        bounds(&value, RESPONSE_LIMIT, 1024, 12)) }
    pub(crate) fn retained_heap_bytes(&self) -> Option<usize> {
        let mut bytes = self.session_id.as_ref().map_or(0, String::capacity);
        if let Some(v) = &self.operation { bytes = bytes.checked_add(v.id.capacity())?; }
        if let Some(v) = &self.consent { bytes = bytes.checked_add(v.id.capacity())?
            .checked_add(v.expires_at.capacity())?.checked_add(v.prepared.retained_heap_bytes()?)?; }
        Some(bytes)
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
    if !bounds(value, 4096, 64, 4) { return Err(BridgeError::invalid()); }
    fn read<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, BridgeError> {
        serde_json::from_value(v.clone()).map_err(|_| BridgeError::invalid())
    }
    let command = match name {
        "github_remote_setup_status" if value.as_object().is_some_and(|v| v.is_empty()) => Command::Status,
        "github_remote_setup_prepare" => { let v: PrepareArgs = read(value)?;
            if !valid_id(&v.session_id) || !revision(v.expected_revision) || !revision(v.expected_connection_revision) { return Err(BridgeError::invalid()); }
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

pub(crate) fn future_status_fits(request: &Request, session: &str) -> bool {
    if !request.valid() || !valid_id(session) { return false; }
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
        "observedAt":"9999-12-31T23:59:59Z","confirmation":Prepared::confirmation_for(&request.target)}},"observed":policy_ceiling});
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
    let mut prepared = Prepared { target: target.clone(), before, after: before.changed(target.selection).unwrap(),
        observed_at: "2026-10-09T00:00:00Z".into(), confirmation: String::new() };
    prepared.confirmation = prepared.confirmation(); assert!(prepared.valid());
    let control = json!({"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false});
    let result = json!({"schemaVersion":1,"action":"prepare","reason":"none","effect":"not-started",
        "writeClaimed":false,"writeAcknowledged":false,"prepared":prepared,"observed":before,"control":control});
    let envelope = |result: Value| json!({"protocol":PROTOCOL,"id":"setup-1","result":result});
    let parsed = decode_reply("setup-1",&line(&envelope(result.clone())),&request).unwrap();
    assert_eq!(parsed.result.observed,Some(before));
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
    let apply=Request { kind:Kind::Apply,target:target.clone(),prepared:Some(prepared.clone()) };
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
    assert_eq!(workflow.changed(selection),Some(Policy::Workflow { default_workflow_permissions:Permission::Write,can_approve_pull_request_reviews:true }));
    assert!(workflow.changed(target.selection).is_none() && before.changed(selection).is_none());
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
}
