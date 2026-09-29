//! Closed runner-inventory DATA boundary. Only an original settled native
//! runner ticket can turn these facts into ephemeral input consent authority.
use std::collections::BTreeSet;
use serde::{Deserialize, Serialize};
use crate::{error::BridgeError, github_input_group_protocol as input,
    github_connection_protocol::{bounds, coordinate, nullable, numeric_id, utc, GitHubReadControl, PrivateWriter, Reason as ControlReason},
    protocol::{strict_json, valid_id}};

pub(crate) const PROTOCOL: &str = "mrk-github-runner-prerequisite/1";
pub(crate) const REQUEST_LIMIT: usize = 8192;
pub(crate) const RESPONSE_LIMIT: usize = 256 * 1024;
pub(crate) const OBSERVATION_SECONDS: u64 = 120;
pub(crate) const LABELS: [&str; 2] = ["ubuntu-24.04", "macos-26"];

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PublicResult { Safe, Refused, Expired }
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Coverage { Repository, OrganizationWide }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Summary {
    pub(crate) result: PublicResult, pub(crate) checked_at: Option<String>, pub(crate) expires_at: Option<String>,
    pub(crate) group_count: Option<u16>, pub(crate) runner_count: Option<u16>, pub(crate) scope: Option<Coverage>,
    pub(crate) reason: input::Reason,
}
impl Summary {
    pub(crate) fn refused(reason: input::Reason) -> Self {
        Self { result: PublicResult::Refused, checked_at: None, expires_at: None,
            group_count: None, runner_count: None, scope: None, reason }
    }
    pub(crate) fn expire(&mut self, reason: input::Reason) {
        if self.result == PublicResult::Safe { self.result = PublicResult::Expired; self.reason = reason; }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CheckArgs {
    pub(crate) session_id: String, pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32, pub(crate) expected_asset_status_revision: u32,
    pub(crate) context_revision: u32,
}
impl CheckArgs {
    pub(crate) fn valid(&self) -> bool { valid_id(&self.session_id) && self.expected_revision > 0
        && self.expected_connection_revision > 0 && self.expected_asset_status_revision > 0 && self.context_revision > 0 }
}

/// No token-bearing Value/Serialize/Clone is constructed. The existing one
/// private writer owns its original request bytes and wipes partial failures.
pub(crate) fn encode_request(id: &str, repository: &str, account: &str, repository_id: &str, token: &str) -> Result<Vec<u8>, BridgeError> {
    if !valid_id(id) || !coordinate(repository) || !numeric_id(account) || !numeric_id(repository_id)
        || token.is_empty() || token.len() > 4096 || !token.bytes().all(|b| (0x21..=0x7e).contains(&b)) { return Err(BridgeError::invalid()); }
    let mut bytes = Vec::new(); bytes.try_reserve_exact(REQUEST_LIMIT).map_err(|_| BridgeError::invalid())?;
    if bytes.capacity() > REQUEST_LIMIT { return Err(BridgeError::invalid()); }
    let mut writer = PrivateWriter { bytes };
    writer.append(b"{\"protocol\":")?; writer.string(PROTOCOL)?; writer.append(b",\"id\":")?; writer.string(id)?;
    writer.append(b",\"params\":{\"repository\":")?; writer.string(repository)?;
    writer.append(b",\"expectedAccountId\":")?; writer.string(account)?;
    writer.append(b",\"expectedRepositoryId\":")?; writer.string(repository_id)?;
    writer.append(b",\"token\":")?; writer.string(token)?; writer.append(b"}}")?; writer.bytes.push(b'\n');
    Ok(std::mem::take(&mut writer.bytes))
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub(crate) enum OwnerKind { User, Organization }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner { id: String, #[serde(rename = "type")] kind: OwnerKind }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Runner { id: String, labels: Vec<String> }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Group { id: String, inherited: bool, runners: Vec<Runner> }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Inventories {
    account_id: String, repository_id: String, repository: String, owner: Owner,
    repository_runners: Vec<Runner>, groups: Vec<Group>, observed_at: String,
}
// Reduced PRIVATE facts; raw names/labels/API objects are dropped by the closed
// decoder. The exact normalized reply is hashed before its original buffer dies.
pub(crate) struct Facts {
    pub(crate) account_id: String, pub(crate) repository_id: String, pub(crate) repository: String,
    pub(crate) owner_id: String, pub(crate) owner_kind: OwnerKind, pub(crate) observed_at: String,
    pub(crate) group_count: u16, pub(crate) runner_count: u16, pub(crate) digest: String,
}
impl Facts {
    pub(crate) fn summary(&self, expires_at: String) -> Summary {
        Summary { result: PublicResult::Safe, checked_at: Some(self.observed_at.clone()), expires_at: Some(expires_at),
            group_count: Some(self.group_count), runner_count: Some(self.runner_count),
            scope: Some(if self.owner_kind == OwnerKind::Organization { Coverage::OrganizationWide } else { Coverage::Repository }),
            reason: input::Reason::None }
    }
}
fn labels_valid(labels: &[String]) -> bool {
    if labels.len() > 64 { return false; }
    let mut previous: Option<&str> = None;
    labels.iter().all(|label| {
        // Core performs full Unicode casefold. Native enforces the normalized
        // boundary's ordering/case and independently rejects the fixed ASCII
        // labels, including the Unicode long-s alias for macos. No new Unicode
        // policy engine is needed to validate this finite published label set.
        let valid = !label.is_empty() && label.len() <= 256 && !label.chars().any(|c| c.is_uppercase() || c < ' ' || c == '\u{7f}')
            && previous.is_none_or(|old| old < label.as_str())
            && !LABELS.contains(&label.as_str()) && label.replace('\u{17f}', "s") != "macos-26";
        previous = Some(label.as_str()); valid
    })
}
fn runners_valid<'a>(rows: &'a [Runner], seen: &mut BTreeSet<&'a str>) -> bool {
    rows.len() <= 100 && rows.iter().all(|row| numeric_id(&row.id) && seen.insert(&row.id) && labels_valid(&row.labels))
}
impl Inventories {
    fn valid(&self) -> bool {
        if !numeric_id(&self.account_id) || !numeric_id(&self.repository_id) || !coordinate(&self.repository)
            || !numeric_id(&self.owner.id) || !utc(&self.observed_at) || self.groups.len() > 8
            || self.owner.kind == OwnerKind::User && !self.groups.is_empty() { return false; }
        let mut seen = BTreeSet::new(); let mut groups = BTreeSet::new();
        runners_valid(&self.repository_runners, &mut seen) && self.groups.iter().all(|group|
            numeric_id(&group.id) && groups.insert(&group.id) && runners_valid(&group.runners, &mut seen)) && seen.len() <= 900
    }
    fn reduce(self, digest: String) -> Facts {
        Facts { account_id: self.account_id, repository_id: self.repository_id, repository: self.repository,
            owner_id: self.owner.id, owner_kind: self.owner.kind, observed_at: self.observed_at,
            group_count: self.groups.len() as u16,
            runner_count: (self.repository_runners.len() + self.groups.iter().map(|g| g.runners.len()).sum::<usize>()) as u16, digest }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrivateOutcome {
    schema_version: u32, reason: input::Reason, #[serde(deserialize_with = "nullable")] facts: Option<Inventories>,
    control: GitHubReadControl, network_cleanup: input::Settlement,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope { protocol: String, id: String, result: PrivateOutcome }
/// No Deserialize/Clone/Serialize constructor for the accepted boundary result.
pub(crate) struct Reply {
    pub(crate) reason: input::Reason, pub(crate) facts: Option<Facts>, pub(crate) control: GitHubReadControl,
    pub(crate) network_cleanup: input::Settlement,
}
fn runner_reason(reason: input::Reason) -> bool {
    matches!(reason, input::Reason::None | input::Reason::Unauthorized | input::Reason::Forbidden
        | input::Reason::NotFoundOrInaccessible | input::Reason::TargetChanged | input::Reason::RateLimited
        | input::Reason::NetworkUnavailable | input::Reason::TlsFailed | input::Reason::ResponseInvalid
        | input::Reason::ResponseLimit | input::Reason::Expired | input::Reason::Cancelled | input::Reason::RunnerCollision)
}
pub(crate) fn decode_reply(id: &str, bytes: &[u8]) -> Result<Reply, BridgeError> {
    if !valid_id(id) || bytes.len() > RESPONSE_LIMIT || !bytes.ends_with(b"\n") { return Err(BridgeError::protocol()); }
    let raw = &bytes[..bytes.len()-1];
    if raw.first() != Some(&b'{') || raw.last() != Some(&b'}') || raw.iter().any(|b| matches!(*b, b'\n' | b'\r')) { return Err(BridgeError::protocol()); }
    let value = strict_json(raw)?;
    if !bounds(&value, RESPONSE_LIMIT-1, 20_000, 12) { return Err(BridgeError::protocol()); }
    let envelope: Envelope = serde_json::from_value(value).map_err(|_| BridgeError::protocol())?;
    let result = envelope.result;
    if envelope.protocol != PROTOCOL || envelope.id != id || result.schema_version != 1 || !runner_reason(result.reason)
        || !result.control.valid() || result.network_cleanup == input::Settlement::Pending { return Err(BridgeError::protocol()); }
    if result.reason == input::Reason::None {
        if result.network_cleanup != input::Settlement::Confirmed || result.control.reason != ControlReason::None
            || !result.facts.as_ref().is_some_and(Inventories::valid) { return Err(BridgeError::protocol()); }
    } else if result.facts.is_some() || result.control.reason != ControlReason::None
        && ![crate::github_input_group_session::connection_reason(result.control.reason), input::Reason::ResponseInvalid, input::Reason::ResponseLimit].contains(&result.reason) {
        return Err(BridgeError::protocol());
    }
    Ok(Reply { reason: result.reason, facts: result.facts.map(|v| v.reduce(input::digest(raw))),
        control: result.control, network_cleanup: result.network_cleanup })
}

#[cfg(test)]
#[path = "github_runner_prerequisite_protocol_tests.rs"]
mod tests;
