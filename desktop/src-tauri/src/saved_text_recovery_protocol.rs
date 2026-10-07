//! Closed DATA for the two saved-text restart routes. A view, token or prior
//! journal identifier never supplies filesystem authority to the current lease.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::{edit_protocol::{bounded, token, CoreEditOutcome, CoreReason, EditDomain, Effect, Journal, ResourceState},
    error::BridgeError, github_workflow_edit_protocol::{value_bounds, RegisteredIdentity},
    metadata_text_edit_protocol as metadata, release_version_edit_protocol as version};

pub(crate) const VIEW_LIMIT: usize = 16 * 1024;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Domain { MetadataText, ReleaseVersion }
impl Domain {
    pub(crate) fn matches(self, domain: EditDomain) -> bool {
        matches!((self, domain), (Self::MetadataText, EditDomain::MetadataText) | (Self::ReleaseVersion, EditDomain::ReleaseVersion))
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State { Idle, Conflict, Recoverable }
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Reason { None, LegacyJournal, IncompleteJournal, InvalidJournal, ForeignJournal, DependencyChanged, TargetChanged }
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action { Rollback, CommittedCleanup, RolledBackCleanup, PreparingCleanup }
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileEffect { Preserve, RemoveNew, RestoreOriginal, KeepCommitted }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TextSelection { pub platform: metadata::Platform, pub locale: String, pub metadata_root: String }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VersionSelection { pub source: String, pub name_key: String, pub build_key: String, pub ios_enabled: bool }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Selection { Text(TextSelection), Version(VersionSelection) }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Digest { pub byte_length: u32, pub sha256: String, pub mode: u16 }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct File { pub path: String, pub effect: FileEffect, pub before: Option<Digest>, pub after: Option<Digest> }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Cleanup { pub file_count: u8, pub directory_count: u8, pub scope: String }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct View {
    pub schema_version: u32, pub kind: String, pub domain: Domain, pub state: State, pub reason: Reason,
    pub action: Option<Action>, pub transaction_id: Option<String>, pub selection: Option<Selection>, pub files: Vec<File>,
    pub private_cleanup: Cleanup,
}
fn keys(value: &Value, names: &[&str]) -> bool {
    value.as_object().is_some_and(|v| v.len() == names.len() && names.iter().all(|name| v.contains_key(*name)))
}
impl View {
    pub(crate) fn valid(&self, domain: EditDomain) -> bool {
        if self.schema_version != 1 || self.kind != "saved-text-recovery" || !self.domain.matches(domain)
            || self.private_cleanup.scope != "inspected-owned-journal-only" || self.private_cleanup.file_count > 14
            || self.private_cleanup.directory_count > 11 || bounded(self, VIEW_LIMIT).is_err() { return false; }
        if self.state != State::Recoverable {
            return (self.state == State::Idle) == (self.reason == Reason::None) && self.action.is_none()
                && self.transaction_id.is_none() && self.selection.is_none() && self.files.is_empty()
                && self.private_cleanup.file_count == 0 && self.private_cleanup.directory_count == 0;
        }
        if self.reason != Reason::None || !self.transaction_id.as_deref().is_some_and(token) { return false; }
        let Some(action) = self.action else { return false; };
        let (paths, limit) = match (&self.selection, self.domain) {
            (Some(Selection::Text(selected)), Domain::MetadataText)
                if metadata::target_context(&selected.metadata_root, selected.platform, &selected.locale) => {
                (selected.platform.ids().iter().map(|id| metadata::field_path(&selected.metadata_root,
                    selected.platform, &selected.locale, *id)).collect::<Vec<_>>(), metadata::TEXT_LIMIT)
            },
            (Some(Selection::Version(selected)), Domain::ReleaseVersion)
                if version::selection(&selected.source, &selected.name_key, &selected.build_key) => (vec![selected.source.clone()], version::TEXT_LIMIT),
            _ => return false,
        };
        self.files.len() == paths.len() && self.files.iter().zip(paths).all(|(file, path)| {
            file.path == path && (file.before.is_some() || file.after.is_some())
                && [&file.before, &file.after].into_iter().flatten().all(|digest| digest.byte_length as usize <= limit
                    && digest.mode <= 0o777 && digest.sha256.len() == 64
                    && digest.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
                && file.effect == match (action, file.after.is_some(), file.before.is_some()) {
                    (Action::Rollback, true, false) => FileEffect::RemoveNew,
                    (Action::Rollback, true, true) => FileEffect::RestoreOriginal,
                    (Action::CommittedCleanup, true, _) => FileEffect::KeepCommitted,
                    _ => FileEffect::Preserve,
                }
        })
    }
    pub(crate) fn expected_success(&self) -> Option<Effect> {
        if self.state != State::Recoverable { return None; }
        self.action.map(|action| match action { Action::Rollback | Action::RolledBackCleanup => Effect::RolledBack,
            Action::CommittedCleanup => Effect::Committed, Action::PreparingCleanup => Effect::NotStarted })
    }
    fn observed_effect(&self) -> Effect {
        match self.action { Some(Action::CommittedCleanup) => Effect::Committed,
            Some(Action::RolledBackCleanup) => Effect::RolledBack, _ => Effect::NotStarted }
    }
    pub(crate) fn from_value(value: &Value, domain: EditDomain) -> Result<Self, BridgeError> {
        value_bounds(value, 16, VIEW_LIMIT).map_err(|_| BridgeError::protocol())?;
        if !keys(value, &["schemaVersion","kind","domain","state","reason","action","transactionId","selection","files","privateCleanup"])
            || !value["files"].as_array().is_some_and(|files| files.iter().all(|file|
                keys(file, &["path","effect","before","after"]))) { return Err(BridgeError::protocol()); }
        let view = Self::deserialize(value).map_err(|_| BridgeError::protocol())?;
        if !view.valid(domain) { return Err(BridgeError::protocol()); }
        Ok(view)
    }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkout { pub revision: String, pub view: View }
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Prepared { pub revision: String, pub plan_token: String, pub view: View }
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Details { pub checkout: Option<Checkout>, pub prepared: Option<Prepared> }
impl Details {
    pub(crate) fn revision(&self) -> Option<&str> { self.checkout.as_ref().map(|c| c.revision.as_str()) }
    pub(crate) fn plan_token(&self) -> Option<&str> { self.prepared.as_ref().map(|p| p.plan_token.as_str()) }
    pub(crate) fn terminal_admissible(&self, submitted: bool, core: &CoreEditOutcome) -> bool {
        if !outcome_valid(core) || core.effect == Effect::Unchanged { return false; }
        if submitted {
            let (Some(checkout), Some(prepared)) = (&self.checkout, &self.prepared) else { return false; };
            if checkout.revision != prepared.revision || checkout.view != prepared.view || prepared.view.state != State::Recoverable {
                return false;
            }
            if core.reason == CoreReason::None {
                return core.journal == Journal::Clean && core.resources == ResourceState::Settled
                    && prepared.view.expected_success().is_some_and(|effect| core.effect == effect);
            }
            // An error cannot turn an already observed commit into not_started.
            let observed = checkout.view.observed_effect();
            return !matches!(core.journal, Journal::NotCreated)
                && (!matches!(observed, Effect::Committed | Effect::RolledBack) || core.effect == observed || core.effect == Effect::Unknown);
        }
        if let Some(checkout) = &self.checkout {
            let journal = if checkout.view.state == State::Idle { Journal::NotCreated } else { Journal::RecoveryRequired };
            return core.effect == checkout.view.observed_effect() && core.journal == journal
                || core.reason != CoreReason::None && (core.effect == Effect::Unknown || core.journal == Journal::Unknown);
        }
        // A real scope/capture/close error can retain a proven old commit even
        // if no opened frame could be published. It is never Apply success.
        core.reason != CoreReason::None && core.journal != Journal::Clean
    }
}
pub(crate) fn outcome_valid(core: &CoreEditOutcome) -> bool {
    core.valid() || core.reason == CoreReason::None && core.resources == ResourceState::Settled
        && core.journal == Journal::RecoveryRequired && matches!(core.effect, Effect::NotStarted | Effect::Committed | Effect::RolledBack)
}
pub struct Opened { pub revision: String, pub recovery: View }
pub struct PreparedReply { pub revision: String, pub plan_token: String, pub recovery: View }
pub(crate) fn opened(raw: &Value, domain: EditDomain) -> Result<Opened, BridgeError> {
    if !keys(raw, &["revision","recovery","scopeResources"]) || raw["scopeResources"] != "settled" { return Err(BridgeError::protocol()); }
    let revision = raw["revision"].as_str().filter(|r| token(r)).ok_or_else(BridgeError::protocol)?.to_owned();
    Ok(Opened { revision, recovery: View::from_value(&raw["recovery"], domain)? })
}
pub(crate) fn prepared(raw: &Value, domain: EditDomain) -> Result<PreparedReply, BridgeError> {
    if !keys(raw, &["revision","planToken","recovery","scopeResources"]) || raw["scopeResources"] != "settled" { return Err(BridgeError::protocol()); }
    let revision = raw["revision"].as_str().filter(|r| token(r)).ok_or_else(BridgeError::protocol)?.to_owned();
    let plan_token = raw["planToken"].as_str().filter(|p| token(p) && *p != revision).ok_or_else(BridgeError::protocol)?.to_owned();
    let recovery = View::from_value(&raw["recovery"], domain)?;
    if recovery.state != State::Recoverable { return Err(BridgeError::protocol()); }
    Ok(PreparedReply { revision, plan_token, recovery })
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Intent { Recover }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Open { pub project_id: String, pub intent: Intent }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepare { pub session_id: String, pub revision: String, pub intent: Intent }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Apply { pub session_id: String, pub plan_token: String, pub intent: Intent }
pub(crate) fn open(body: &Value) -> Result<Open, BridgeError> {
    value_bounds(body, 4, 512)?;
    let args = Open::deserialize(body).map_err(|_| BridgeError::invalid())?;
    if !crate::protocol::valid_id(&args.project_id) { return Err(BridgeError::invalid()); } Ok(args)
}
pub(crate) fn prepare(body: &Value) -> Result<Prepare, BridgeError> {
    value_bounds(body, 4, 512)?;
    let args = Prepare::deserialize(body).map_err(|_| BridgeError::invalid())?;
    if !token(&args.session_id) || !token(&args.revision) { return Err(BridgeError::invalid()); } Ok(args)
}
pub(crate) fn apply(body: &Value) -> Result<Apply, BridgeError> {
    value_bounds(body, 4, 512)?;
    let args = Apply::deserialize(body).map_err(|_| BridgeError::invalid())?;
    if !token(&args.session_id) || !token(&args.plan_token) { return Err(BridgeError::invalid()); } Ok(args)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrivateOpen { root: String, registered_identity: RegisteredIdentity, intent: Intent }
pub(crate) fn private_request(seq: u32, op: &str, params: &Value) -> bool {
    match (seq, op) {
        (0, "open") => PrivateOpen::deserialize(params).is_ok_and(|p| p.root.len() > 1 && p.root.len() <= 4096
            && !p.root.contains('\0') && p.registered_identity.valid()),
        (1, "prepare") => keys(params, &["revision","intent"]) && params["intent"] == "recover" && params["revision"].as_str().is_some_and(token),
        (2, "apply") => keys(params, &["planToken","intent"]) && params["intent"] == "recover" && params["planToken"].as_str().is_some_and(token),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn view(domain: EditDomain, action: &str) -> Value {
        let text = domain == EditDomain::MetadataText;
        let paths = if text { vec!["release/metadata/android/en-US/title.txt", "release/metadata/android/en-US/short_description.txt", "release/metadata/android/en-US/full_description.txt"] }
            else { vec!["public/version.properties"] };
        json!({"schemaVersion":1,"kind":"saved-text-recovery","domain":if text { "metadata_text" } else { "release_version" },
            "state":"recoverable","reason":"none","action":action,"transactionId":"a".repeat(32),
            "selection":if text { json!({"platform":"android","locale":"en-US","metadataRoot":"release/metadata"}) }
                else { json!({"source":"public/version.properties","nameKey":"VERSION_NAME","buildKey":"BUILD_NUMBER","iosEnabled":true}) },
            "files":paths.into_iter().map(|path| json!({"path":path,"before":null,
                "after":{"byteLength":2,"sha256":"b".repeat(64),"mode":420},
                "effect":match action { "rollback"=>"remove_new","committed_cleanup"=>"keep_committed",_=>"preserve" }})).collect::<Vec<_>>(),
            "privateCleanup":{"fileCount":4,"directoryCount":0,"scope":"inspected-owned-journal-only"}})
    }
    #[test]
    fn recovery_is_closed_two_domain_data_with_action_bound_effects_and_no_serialized_authority() {
        for domain in [EditDomain::MetadataText, EditDomain::ReleaseVersion] {
            for action in ["rollback","committed_cleanup","rolled_back_cleanup","preparing_cleanup"] {
                let raw = view(domain, action); let original = View::from_value(&raw, domain).unwrap();
                assert!(View::from_value(&raw, EditDomain::MetadataImages).is_err());
                assert!(View::from_value(&raw, if domain == EditDomain::MetadataText { EditDomain::ReleaseVersion } else { EditDomain::MetadataText }).is_err());
                for (pointer, value) in [("/transactionId",json!("../old")),("/privateCleanup/fileCount",json!(15)),
                    ("/privateCleanup/directoryCount",json!(12)),("/privateCleanup/scope",json!("all-state")),
                    ("/files/0/after/mode",json!(512)),("/files/0/after/byteLength",json!(65537)),
                    ("/files/0/path",json!("../foreign")),("/files/0/effect",json!("delete")),("/state",json!("idle"))] {
                    let mut bad=raw.clone(); *bad.pointer_mut(pointer).unwrap()=value; assert!(View::from_value(&bad,domain).is_err());
                }
                for key in ["selection","transactionId","action"] { let mut bad=raw.clone(); bad.as_object_mut().unwrap().remove(key); assert!(View::from_value(&bad,domain).is_err()); }
                let mut bad=raw.clone(); bad["files"][0].as_object_mut().unwrap().remove("before"); assert!(View::from_value(&bad,domain).is_err());
                let mut bad=raw.clone(); bad["files"][0]["after"]["rawText"]=json!("not-a-receipt"); assert!(View::from_value(&bad,domain).is_err());
                let details=Details { checkout:Some(Checkout {revision:"c".repeat(32),view:original.clone()}),
                    prepared:Some(Prepared {revision:"c".repeat(32),plan_token:"d".repeat(32),view:original.clone()}) };
                let success=CoreEditOutcome {effect:original.expected_success().unwrap(),journal:Journal::Clean,resources:ResourceState::Settled,reason:CoreReason::None};
                assert!(details.terminal_admissible(true,&success)); assert!(!details.terminal_admissible(false,&success));
                let mut bad=success.clone(); bad.effect=Effect::Unchanged; assert!(!details.terminal_admissible(true,&bad));
                let mut bad=success.clone(); bad.journal=Journal::RecoveryRequired; assert!(!details.terminal_admissible(true,&bad));
                let observed=CoreEditOutcome {effect:original.observed_effect(),journal:Journal::RecoveryRequired,resources:ResourceState::Settled,reason:CoreReason::None};
                assert!(details.terminal_admissible(false,&observed)); assert!(!observed.valid());
            }
        }
        let mut idle=view(EditDomain::MetadataText,"rollback"); idle["state"]=json!("idle"); idle["action"]=Value::Null;
        idle["transactionId"]=Value::Null; idle["selection"]=Value::Null; idle["files"]=json!([]); idle["privateCleanup"]["fileCount"]=json!(0);
        assert!(View::from_value(&idle,EditDomain::MetadataText).is_ok());
        for reason in ["legacy_journal","incomplete_journal","invalid_journal","foreign_journal","dependency_changed","target_changed"] {
            let mut conflict=idle.clone(); conflict["state"]=json!("conflict"); conflict["reason"]=json!(reason);
            assert!(View::from_value(&conflict,EditDomain::MetadataText).is_ok());
            assert!(prepared(&json!({"revision":"a".repeat(32),"planToken":"b".repeat(32),"recovery":conflict,"scopeResources":"settled"}),EditDomain::MetadataText).is_err());
        }
    }
}
