//! Installed GitHub observations on the ordinary document, UI and Supervisor.
//! The existing relay/exit observer drive this bounded adapter. It creates no
//! replacement query, process owner, timer, picker or shutdown task.
use std::sync::{Arc, Mutex, Weak, atomic::{AtomicBool, Ordering}};
use serde_json::{json, Value};
use tauri::Manager;
use tokio::sync::Mutex as AsyncMutex;
use crate::{error::BridgeError, github_connection_protocol as wire, supervisor::{Supervisor,
    github_tls_peer_owner::installed::{InstalledPeer, ProductWitness, N, PEER_SHA}}};
use super::{Observation, Case as ShellCase, Step as ShellStep, Pending, Boundary};
pub(crate) use crate::supervisor::github_tls_peer_owner::installed::Case;
impl Case {
    pub(super) fn failure_leaf(self)->&'static str {match self {
        Self::ConnectRefresh=>"shell-github-connect-refresh-failure.labels",
        Self::RealCa=>"shell-github-real-ca-refusal-failure.labels",
        Self::WrongName=>"shell-github-wrong-name-failure.labels",
        Self::Expired=>"shell-github-expired-failure.labels",
        Self::Ragged=>"shell-github-ragged-failure.labels",
        Self::Length=>"shell-github-length-failure.labels",
        Self::Chunk=>"shell-github-chunk-failure.labels",
        Self::HeaderLimit=>"shell-github-header-limit-failure.labels",
        Self::BodyLimit=>"shell-github-body-limit-failure.labels",
        Self::ChunkLimit=>"shell-github-chunk-limit-failure.labels",
        Self::Unauthorized=>"shell-github-unauthorized-failure.labels",
        Self::Rate=>"shell-github-rate-failure.labels",
        Self::Identity=>"shell-github-identity-failure.labels",
        Self::Redirect=>"shell-github-redirect-failure.labels",
        Self::AmbientFixed=>"shell-github-ambient-fixed-failure.labels",
        Self::AmbientNoRescue=>"shell-github-ambient-no-rescue-failure.labels",
        Self::HandshakeDeadline=>"shell-github-handshake-deadline-failure.labels",
        Self::HeaderDeadline=>"shell-github-header-deadline-failure.labels",
        Self::BodyDeadline=>"shell-github-body-deadline-failure.labels",
        Self::Cancel=>"shell-github-cancel-failure.labels",
        Self::Quit=>"shell-github-quit-failure.labels",
        Self::Unknown=>"shell-github-unknown-failure.labels",
        Self::NormalNegative=>"shell-github-normal-negative-failure.labels",
        Self::DnsDeadline=>"shell-github-dns-deadline-failure.labels",Self::ConnectDeadline=>"shell-github-connect-deadline-failure.labels",
    }}
    pub(super) fn verified_line(self)->&'static [u8] {match self {
        Self::ConnectRefresh=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-connect-refresh-verified\n",
        Self::RealCa=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-real-ca-refusal-verified\n",
        Self::WrongName=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-wrong-name-verified\n",
        Self::Expired=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-expired-verified\n",
        Self::Ragged=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-ragged-verified\n",
        Self::Length=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-length-verified\n",
        Self::Chunk=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-chunk-verified\n",
        Self::HeaderLimit=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-header-limit-verified\n",
        Self::BodyLimit=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-body-limit-verified\n",
        Self::ChunkLimit=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-chunk-limit-verified\n",
        Self::Unauthorized=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-unauthorized-verified\n",
        Self::Rate=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-rate-verified\n",
        Self::Identity=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-identity-verified\n",
        Self::Redirect=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-redirect-verified\n",
        Self::AmbientFixed=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-ambient-fixed-verified\n",
        Self::AmbientNoRescue=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-ambient-no-rescue-verified\n",
        Self::HandshakeDeadline=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-handshake-deadline-verified\n",
        Self::HeaderDeadline=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-header-deadline-verified\n",
        Self::BodyDeadline=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-body-deadline-verified\n",
        Self::Cancel=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-cancel-verified\n",
        Self::Quit=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-quit-verified\n",
        Self::Unknown=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-unknown-verified\n",
        Self::NormalNegative=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-normal-negative-verified\n",
        Self::DnsDeadline=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-dns-deadline-verified\n",
        Self::ConnectDeadline=>b"MRK_INSTALLED_SHELL_OBSERVATION=github-connect-deadline-verified\n",
    }}
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Step { Navigate, ReadGuidanceReload, ReloadGuidance, EnterRepository, Entry, EnterToken, Token, Connect, Observe,
    Refresh, ObserveRefresh, Status, ReadStatus, Disconnect, Disconnected, InjectUnknown, Unknown }
impl Step {
    pub(super) fn failure_line(self) -> &'static [u8] {
        match self {
            Self::Navigate=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubNavigate\n",
            Self::ReadGuidanceReload=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubGuidanceReady\n",
            Self::ReloadGuidance=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubGuidanceReload\n",
            Self::EnterRepository=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubRepository\n",
            Self::Entry=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubEntry\n",
            Self::EnterToken=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubToken\n",
            Self::Token=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubTokenReady\n",
            Self::Connect=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubConnect\n",
            Self::Observe=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubObserve\n",
            Self::Refresh=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubRefresh\n",
            Self::ObserveRefresh=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubRefreshed\n",
            Self::Status=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubStatus\n",
            Self::ReadStatus=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubStatusRead\n",
            Self::Disconnect=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubDisconnect\n",
            Self::Disconnected=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubDisconnected\n",
            Self::InjectUnknown=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubUnknownInject\n",
            Self::Unknown=>b"MRK_INSTALLED_SHELL_FAILURE_STEP=GitHubUnknown\n",
        }
    }
}

// Closed accounting for the one ordinary guidance-reload button. These facts
// do not replace bootstrap, authorize a request, or make retained help current.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum GuidanceClick { #[default] Unreserved, Pending, Returned, Refused }
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum GuidanceReloadScope { Outside, ClickPending, AwaitReplies }
pub(super) fn guidance_reload_scope(step: ShellStep, pending: Option<Pending>, live: bool) -> GuidanceReloadScope {
    if !live { return GuidanceReloadScope::Outside; }
    match (step, pending) {
        (ShellStep::GitHubReadOnly(Step::ReloadGuidance), Some(Pending::Dom(ShellStep::GitHubReadOnly(Step::ReloadGuidance)))) => GuidanceReloadScope::ClickPending,
        (ShellStep::GitHubReadOnly(Step::EnterRepository), None) => GuidanceReloadScope::AwaitReplies,
        _ => GuidanceReloadScope::Outside,
    }
}
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct GuidanceReload { click: GuidanceClick, info: bool, catalog: bool }
impl GuidanceReload {
    pub(super) fn reserve(&mut self) -> bool {
        if *self != Self::default() { return false; }
        self.click = GuidanceClick::Pending; true
    }
    fn permits(&self, scope: GuidanceReloadScope) -> bool {
        matches!((scope, self.click), (GuidanceReloadScope::ClickPending, GuidanceClick::Pending)
            | (GuidanceReloadScope::AwaitReplies, GuidanceClick::Returned))
    }
    pub(super) fn app_info(&mut self, scope: GuidanceReloadScope) -> bool {
        if !self.permits(scope) || self.info || self.catalog { return false; }
        self.info = true; true
    }
    pub(super) fn catalog(&mut self, scope: GuidanceReloadScope) -> bool {
        if !self.permits(scope) || !self.info || self.catalog { return false; }
        self.catalog = true; true
    }
    pub(super) fn click_returned(&mut self, value: &Value) -> bool {
        if self.click != GuidanceClick::Pending { return false; }
        let ready = value.as_object().is_some_and(|object| object.len() == 1 && value["state"] == "ready");
        self.click = if ready { GuidanceClick::Returned } else { GuidanceClick::Refused };
        ready
    }
    pub(super) fn complete(&self) -> bool { self.click == GuidanceClick::Returned && self.info && self.catalog }
}
fn assert_guidance_reload_contracts() {
    use GuidanceReloadScope::{AwaitReplies, ClickPending, Outside};
    let click = ShellStep::GitHubReadOnly(Step::ReloadGuidance);
    let replies = ShellStep::GitHubReadOnly(Step::EnterRepository);
    assert!(guidance_reload_scope(click, Some(Pending::Dom(click)), true) == ClickPending);
    assert!(guidance_reload_scope(replies, None, true) == AwaitReplies);
    for (step, pending, live) in [(click, None, true), (click, Some(Pending::Dom(replies)), true),
        (replies, Some(Pending::Dom(replies)), true), (click, Some(Pending::Dom(click)), false),
        (replies, None, false), (ShellStep::Bootstrap, None, true),
        (ShellStep::GitHubReadOnly(Step::ReadGuidanceReload), None, true),
        (ShellStep::GitHubReadOnly(Step::Entry), None, true)] {
        assert!(guidance_reload_scope(step, pending, live) == Outside);
    }
    // All legitimate callback orders use the same original reservation. The
    // parent holds EnterRepository until all three actual replies are present.
    for early in 0..=2 {
        let mut reload = GuidanceReload::default();
        assert!(!reload.complete() && !reload.app_info(ClickPending) && !reload.catalog(ClickPending));
        assert!(reload.reserve() && !reload.reserve());
        assert!(!reload.catalog(ClickPending) && !reload.app_info(Outside) && !reload.app_info(AwaitReplies));
        if early >= 1 { assert!(reload.app_info(ClickPending)); }
        if early == 2 { assert!(reload.catalog(ClickPending)); }
        assert!(!reload.complete());
        assert!(reload.click_returned(&json!({"state":"ready"})));
        assert!(!reload.app_info(ClickPending));
        if early == 0 { assert!(reload.app_info(AwaitReplies)); }
        if early < 2 { assert!(reload.catalog(AwaitReplies)); }
        assert!(reload.complete() && !reload.reserve());
        assert!(!reload.click_returned(&json!({"state":"ready"})) && !reload.app_info(AwaitReplies) && !reload.catalog(AwaitReplies));
    }
    for callback in [json!({"state":"wait"}), json!({"state":"error"}), json!({"state":"ready","extra":true}), json!(null)] {
        let mut reload = GuidanceReload::default(); assert!(reload.reserve());
        assert!(!reload.click_returned(&callback) && reload.click == GuidanceClick::Refused);
        assert!(!reload.reserve() && !reload.click_returned(&json!({"state":"ready"}))
            && !reload.app_info(ClickPending) && !reload.app_info(AwaitReplies) && !reload.complete());
    }
}

// Closed diagnostic DATA from this original Entry tick/callback only. A cache
// is not a first-failure receipt: only the winner of the existing failure latch
// freezes a separate copy. No Status, DOM text, token, owner or new clock lives here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EntryOrigin { EvaluationBudget, Deadline, CallbackShape, ScriptError, ReadyRefused }
impl EntryOrigin {
    fn token(self) -> &'static str { match self {
        Self::EvaluationBudget => "evaluation-budget", Self::Deadline => "deadline",
        Self::CallbackShape => "callback-shape", Self::ScriptError => "script-error",
        Self::ReadyRefused => "ready-refused",
    }}
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum EntryPresence { #[default] NotObserved, Absent, Present }
impl EntryPresence {
    fn token(self) -> &'static str { match self { Self::NotObserved => "not-observed", Self::Absent => "absent", Self::Present => "present" } }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct EntryNative {
    presence: EntryPresence, available: Option<bool>, reason: Option<wire::Reason>, session: Option<bool>,
}
impl EntryNative {
    fn sample(status: Option<&wire::Status>) -> Self {
        match status {
            None => Self { presence: EntryPresence::Absent, ..Self::default() },
            Some(status) => Self { presence: EntryPresence::Present,
                available: Some(status.capability.read_only_session_available),
                reason: Some(status.capability.reason), session: Some(status.session.is_some()) },
        }
    }
    fn ready(self) -> bool { self.presence == EntryPresence::Present && self.available == Some(true) && self.session == Some(false) }
    fn valid(self) -> bool {
        match self.presence {
            EntryPresence::NotObserved | EntryPresence::Absent => self.available.is_none() && self.reason.is_none() && self.session.is_none(),
            EntryPresence::Present => match (self.available, self.reason, self.session) {
                (Some(available), Some(reason), Some(_)) => available == (reason == wire::Reason::None),
                _ => false,
            },
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum EntryDomState { #[default] NotObserved, Wait, Ready, Error }
impl EntryDomState {
    fn token(self) -> &'static str { match self {
        Self::NotObserved => "not-observed", Self::Wait => "wait", Self::Ready => "ready", Self::Error => "error",
    }}
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct EntryDom {
    state: EntryDomState, selected: Option<bool>, form: Option<bool>, submit: Option<bool>, enabled: Option<bool>,
    help: Option<bool>, repository: Option<bool>, guide: Option<bool>,
}
impl EntryDom {
    fn error() -> Self { Self { state: EntryDomState::Error, ..Self::default() } }
    fn ready_bits(self) -> bool { self.selected == Some(true) && self.form == Some(true) && self.submit == Some(true) && self.enabled == Some(true) }
    fn valid(self) -> bool {
        let fields = [self.selected, self.form, self.submit, self.enabled, self.help, self.repository, self.guide];
        match self.state {
            EntryDomState::NotObserved | EntryDomState::Error => fields.iter().all(Option::is_none),
            EntryDomState::Wait | EntryDomState::Ready => {
                self.selected.is_some() && self.form.is_some() && self.submit.is_some()
                    && (self.submit != Some(true) || self.form == Some(true))
                    && self.enabled.is_some() == (self.submit == Some(true))
                    && (self.form != Some(true) || self.guide.is_some())
                    && (self.help != Some(true) || self.guide == Some(true))
                    && if self.state == EntryDomState::Wait { !self.ready_bits() && self.help.is_none() }
                       else { self.ready_bits() && self.help.is_some() }
            },
        }
    }
    fn parse(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        if object.len() == 1 && value["state"] == "error" { return Some(Self::error()); }
        const KEYS: [&str; 9] = ["state", "entryAvailable", "helpPresent", "selected", "formPresent",
            "submitPresent", "submitEnabled", "repositoryExpected", "helpContainerPresent"];
        if object.len() != KEYS.len() || !KEYS.iter().all(|key| object.contains_key(*key)) { return None; }
        let nullable = |key: &str| match object.get(key) {
            Some(Value::Null) => Some(None), Some(Value::Bool(value)) => Some(Some(*value)), _ => None,
        };
        let state = if value["state"] == "wait" { EntryDomState::Wait }
            else if value["state"] == "ready" { EntryDomState::Ready } else { return None; };
        let sample = Self { state, selected: Some(value["selected"].as_bool()?), form: Some(value["formPresent"].as_bool()?),
            submit: Some(value["submitPresent"].as_bool()?), enabled: nullable("submitEnabled")?,
            help: nullable("helpPresent")?, repository: nullable("repositoryExpected")?, guide: nullable("helpContainerPresent")? };
        (sample.valid() && value["entryAvailable"].as_bool()? == sample.ready_bits()).then_some(sample)
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct EntrySamples {
    native: EntryNative, native_eval: Option<u16>, dom: EntryDom, dom_eval: Option<u16>,
}
impl EntrySamples {
    fn valid(self, evaluations: u16) -> bool {
        self.native.valid() && self.dom.valid()
            && self.native_eval.is_some() == (self.native.presence != EntryPresence::NotObserved)
            && self.dom_eval.is_some() == (self.dom.state != EntryDomState::NotObserved)
            && self.native_eval.is_none_or(|value| value <= evaluations)
            && self.dom_eval.is_none_or(|value| value > 0 && value <= evaluations)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EntryFailure { origin: EntryOrigin, evaluations: u16, samples: EntrySamples }
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct EntryDiagnostic { cache: EntrySamples, frozen: Option<EntryFailure> }
impl EntryDiagnostic {
    fn native(&mut self, sample: EntryNative, evaluations: u16) {
        if self.frozen.is_none() { self.cache.native = sample; self.cache.native_eval = Some(evaluations); }
    }
    fn dom(&mut self, sample: EntryDom, evaluations: u16) {
        if self.frozen.is_none() { self.cache.dom = sample; self.cache.dom_eval = Some(evaluations); }
    }
    pub(super) fn freeze(&mut self, evaluations: u16, origin: EntryOrigin) {
        if self.frozen.is_none() { self.frozen = Some(EntryFailure { origin, evaluations, samples: self.cache }); }
    }
}
pub(super) fn latch_entry_diagnostic(failed: &super::FailureLatch, diagnostic: &mut EntryDiagnostic, evaluations: u16, origin: EntryOrigin) {
    // Caller holds the existing parent Record. A generic or other first winner
    // leaves frozen absent: reporting must not substitute the live cache.
    if failed.mark_unknown() { diagnostic.freeze(evaluations, origin); }
}
fn entry_bool(value: Option<bool>) -> &'static str { match value { None => "na", Some(false) => "0", Some(true) => "1" } }
fn entry_reason(value: Option<wire::Reason>) -> &'static str {
    let Some(value) = value else { return "na"; };
    match value {
        wire::Reason::None => "none", wire::Reason::Unqualified => "unqualified", wire::Reason::RuntimeUnavailable => "runtime-unavailable",
        wire::Reason::PublisherUnconfigured => "publisher-unconfigured", wire::Reason::NotConnected => "not-connected",
        wire::Reason::InvalidInput => "invalid-input", wire::Reason::Busy => "busy", wire::Reason::Unauthorized => "unauthorized",
        wire::Reason::Forbidden => "forbidden", wire::Reason::NotFoundOrInaccessible => "not-found-or-inaccessible",
        wire::Reason::TargetChanged => "target-changed", wire::Reason::RateLimited => "rate-limited",
        wire::Reason::NetworkUnavailable => "network-unavailable", wire::Reason::TlsFailed => "tls-failed",
        wire::Reason::ResponseInvalid => "response-invalid", wire::Reason::ResponseLimit => "response-limit",
        wire::Reason::Expired => "expired", wire::Reason::Stale => "stale", wire::Reason::Cancelled => "cancelled",
        wire::Reason::CleanupUnknown => "cleanup-unknown",
    }
}
pub(super) fn entry_failure_pair(trace: (ShellStep, Boundary), progress: super::BootstrapProgress,
    diagnostic: EntryDiagnostic) -> Option<([u8; super::FAILURE_PAIR_LIMIT], usize)> {
    if trace.0 != ShellStep::GitHubReadOnly(Step::Entry) { return None; }
    let first = diagnostic.frozen;
    if first.is_some_and(|first| first.evaluations > 128 || !first.samples.valid(first.evaluations)
        || first.origin == EntryOrigin::EvaluationBudget && first.evaluations != 128
        || matches!(first.origin, EntryOrigin::CallbackShape | EntryOrigin::ScriptError) && first.samples.dom.state != EntryDomState::Error
        || first.origin == EntryOrigin::ReadyRefused && (first.samples.dom.state != EntryDomState::Ready || first.samples.dom.help != Some(false))
        || matches!(first.origin, EntryOrigin::CallbackShape | EntryOrigin::ScriptError | EntryOrigin::ReadyRefused)
            && (first.samples.dom_eval != Some(first.evaluations) || trace.1 != Boundary::Dom)
        || first.origin == EntryOrigin::EvaluationBudget && trace.1 != Boundary::Settlement
        || first.origin == EntryOrigin::Deadline && trace.1 != Boundary::Deadline) {
        return None;
    }
    // An absent frozen copy emits no cached native/DOM facts or invented count.
    let sample = first.map(|first| first.samples).unwrap_or_default();
    let (labels, labels_len) = super::failure_pair(trace, progress, None, None)?;
    let mut bytes = [0_u8; super::FAILURE_PAIR_LIMIT]; let mut length = 0;
    fn append(bytes: &mut [u8; super::FAILURE_PAIR_LIMIT], length: &mut usize, part: &[u8]) -> Option<()> {
        let end = length.checked_add(part.len())?; bytes.get_mut(*length..end)?.copy_from_slice(part); *length = end; Some(())
    }
    fn count(bytes: &mut [u8; super::FAILURE_PAIR_LIMIT], length: &mut usize, value: Option<u16>) -> Option<()> {
        let Some(mut value) = value else { return append(bytes, length, b"na"); };
        if value > 128 { return None; }
        let mut digits = [b'0'; 3]; let mut begin = 2;
        loop { digits[begin] += (value % 10) as u8; value /= 10; if value == 0 { break; } begin -= 1; }
        append(bytes, length, &digits[begin..])
    }
    // Prefix first: a proper prefix can never masquerade as three old labels.
    append(&mut bytes, &mut length, b"MRK_INSTALLED_SHELL_GITHUB_ENTRY_FAILURE=v1;o=")?;
    append(&mut bytes, &mut length, first.map(|first| first.origin.token()).unwrap_or("not-recorded").as_bytes())?;
    for (label, value) in [(b";eval=".as_slice(), first.map(|first| first.evaluations)), (b";ne=".as_slice(), sample.native_eval)] {
        append(&mut bytes, &mut length, label)?; count(&mut bytes, &mut length, value)?;
    }
    for (label, value) in [(b";ns=".as_slice(), sample.native.presence.token()), (b";cap=".as_slice(), entry_bool(sample.native.available)),
        (b";reason=".as_slice(), entry_reason(sample.native.reason)), (b";sess=".as_slice(), entry_bool(sample.native.session))] {
        append(&mut bytes, &mut length, label)?; append(&mut bytes, &mut length, value.as_bytes())?;
    }
    append(&mut bytes, &mut length, b";de=")?; count(&mut bytes, &mut length, sample.dom_eval)?;
    for (label, value) in [(b";dom=".as_slice(), sample.dom.state.token()), (b";sel=".as_slice(), entry_bool(sample.dom.selected)),
        (b";form=".as_slice(), entry_bool(sample.dom.form)), (b";submit=".as_slice(), entry_bool(sample.dom.submit)),
        (b";enabled=".as_slice(), entry_bool(sample.dom.enabled)), (b";help=".as_slice(), entry_bool(sample.dom.help)),
        (b";repo=".as_slice(), entry_bool(sample.dom.repository)), (b";guide=".as_slice(), entry_bool(sample.dom.guide))] {
        append(&mut bytes, &mut length, label)?; append(&mut bytes, &mut length, value.as_bytes())?;
    }
    append(&mut bytes, &mut length, b"\n")?; append(&mut bytes, &mut length, labels.get(..labels_len)?)?;
    Some((bytes, length))
}

fn assert_entry_diagnostic_contracts() {
    // Inert closed DATA only. These assertions open no owner, GUI, clock or FD.
    let mut status = crate::github_connection_session::ConnectionState::new().snapshot();
    status.capability.read_only_session_available = true; status.capability.reason = wire::Reason::None;
    let native = EntryNative::sample(Some(&status));
    let absent = EntryNative::sample(None);
    assert!(native.valid() && native.ready() && absent.valid() && !absent.ready());
    assert!(absent.presence == EntryPresence::Absent && absent.available.is_none()
        && EntryNative::default().presence == EntryPresence::NotObserved);
    let ready_value = json!({"state":"ready","entryAvailable":true,"helpPresent":true,
        "selected":true,"formPresent":true,"submitPresent":true,"submitEnabled":true,
        "repositoryExpected":false,"helpContainerPresent":true});
    let ready = EntryDom::parse(&ready_value).unwrap();
    assert!(ready.ready_bits() && ready.repository == Some(false)); // Not another readiness gate.
    let wait_value = json!({"state":"wait","entryAvailable":false,"helpPresent":null,
        "selected":true,"formPresent":true,"submitPresent":true,"submitEnabled":false,
        "repositoryExpected":true,"helpContainerPresent":true});
    let waiting = EntryDom::parse(&wait_value).unwrap();
    assert!(waiting.state == EntryDomState::Wait && waiting.enabled == Some(false) && waiting.help.is_none());
    assert_eq!(EntryDom::parse(&json!({"state":"error"})), Some(EntryDom::error()));
    for invalid in [json!({"state":"wait"}), json!({"state":"error","extra":true}), json!(null)] {
        assert!(EntryDom::parse(&invalid).is_none());
    }
    for (key, value) in [("entryAvailable", json!(false)), ("selected", json!(null)),
        ("submitEnabled", json!(false)), ("helpContainerPresent", json!(false)),
        ("repositoryExpected", json!("never export a value")), ("extra", json!(true))] {
        let mut invalid = ready_value.clone(); invalid[key] = value;
        assert!(EntryDom::parse(&invalid).is_none());
    }
    let mut false_help = ready_value.clone(); false_help["helpPresent"] = json!(false);
    let refused = EntryDom::parse(&false_help).unwrap();
    let trace = (ShellStep::GitHubReadOnly(Step::Entry), Boundary::Settlement);
    let progress = super::BootstrapProgress::Advanced;
    let mut diagnostic = EntryDiagnostic::default();
    diagnostic.native(native, 128); diagnostic.dom(waiting, 128);
    let failed = super::FailureLatch::new(false);
    latch_entry_diagnostic(&failed, &mut diagnostic, 128, EntryOrigin::EvaluationBudget);
    let first = diagnostic;
    let (bytes, length) = entry_failure_pair(trace, progress, diagnostic).unwrap();
    let frame = std::str::from_utf8(&bytes[..length]).unwrap();
    assert!(frame.contains(";o=evaluation-budget;eval=128;ne=128;")
        && frame.contains(";de=128;dom=wait;") && frame.contains(";enabled=0;help=na;repo=1;guide=1\n"));
    diagnostic.native(absent, 128); diagnostic.dom(EntryDom::error(), 128);
    latch_entry_diagnostic(&failed, &mut diagnostic, 128, EntryOrigin::ScriptError);
    let mut late_trace = trace; let mut late_progress = progress;
    if super::latch_failure(&failed, &mut late_trace, &mut late_progress,
        (trace.0, Boundary::Deadline), progress) { diagnostic.freeze(128, EntryOrigin::Deadline); }
    assert_eq!(diagnostic, first);
    assert!(late_trace == trace && late_progress == progress);

    // An earlier generic winner freezes NOTHING; never promote its live cache.
    let mut generic = EntryDiagnostic::default();
    generic.native(native, 128); generic.dom(waiting, 128);
    let generic_failed = super::FailureLatch::new(true);
    latch_entry_diagnostic(&generic_failed, &mut generic, 128, EntryOrigin::EvaluationBudget);
    generic.dom(refused, 128);
    assert!(generic.frozen.is_none());
    assert_eq!(entry_failure_pair(trace, progress, generic),
        entry_failure_pair(trace, progress, EntryDiagnostic::default()));
    let (bytes, length) = entry_failure_pair(trace, progress, generic).unwrap();
    assert!(std::str::from_utf8(&bytes[..length]).unwrap().starts_with(
        "MRK_INSTALLED_SHELL_GITHUB_ENTRY_FAILURE=v1;o=not-recorded;eval=na;ne=na;ns=not-observed;cap=na;reason=na;sess=na;de=na;dom=not-observed;sel=na;form=na;submit=na;enabled=na;help=na;repo=na;guide=na\n"));

    let deadline_failed = super::FailureLatch::new(false);
    let mut deadline = EntryDiagnostic::default(); deadline.native(absent, 127);
    let mut deadline_trace = trace; let mut deadline_progress = progress;
    if super::latch_failure(&deadline_failed, &mut deadline_trace, &mut deadline_progress,
        (trace.0, Boundary::Deadline), progress) { deadline.freeze(127, EntryOrigin::Deadline); }
    let deadline_first = deadline;
    deadline.dom(waiting, 128);
    latch_entry_diagnostic(&deadline_failed, &mut deadline, 128, EntryOrigin::EvaluationBudget);
    assert_eq!(deadline, deadline_first);
    let (bytes, length) = entry_failure_pair(deadline_trace, deadline_progress, deadline).unwrap();
    assert!(std::str::from_utf8(&bytes[..length]).unwrap().contains(
        ";o=deadline;eval=127;ne=127;ns=absent;cap=na;reason=na;sess=na;de=na;dom=not-observed;"));
    let mut invalid = first; invalid.frozen.as_mut().unwrap().evaluations = 127;
    assert!(entry_failure_pair(trace, progress, invalid).is_none());
    assert!(entry_failure_pair((ShellStep::GitHubReadOnly(Step::Token), trace.1), progress, first).is_none());

    // Maximal representatives for each closed native/DOM shape: all bounded
    // counters use three digits; nullable DOM fields use na whenever legal.
    // 0/1 have equal length, and every shorter count/field only shrinks a frame.
    let reasons = [wire::Reason::None, wire::Reason::Unqualified, wire::Reason::RuntimeUnavailable,
        wire::Reason::PublisherUnconfigured, wire::Reason::NotConnected, wire::Reason::InvalidInput,
        wire::Reason::Busy, wire::Reason::Unauthorized, wire::Reason::Forbidden, wire::Reason::NotFoundOrInaccessible,
        wire::Reason::TargetChanged, wire::Reason::RateLimited, wire::Reason::NetworkUnavailable, wire::Reason::TlsFailed,
        wire::Reason::ResponseInvalid, wire::Reason::ResponseLimit, wire::Reason::Expired, wire::Reason::Stale,
        wire::Reason::Cancelled, wire::Reason::CleanupUnknown];
    let mut natives = vec![EntryNative::default(), absent];
    natives.extend(reasons.into_iter().map(|reason| EntryNative { presence: EntryPresence::Present,
        available: Some(reason == wire::Reason::None), reason: Some(reason), session: Some(false) }));
    let doms = [EntryDom::default(), EntryDom::error(),
        EntryDom { state: EntryDomState::Wait, selected: Some(false), form: Some(false), submit: Some(false), ..EntryDom::default() },
        EntryDom { state: EntryDomState::Ready, selected: Some(true), form: Some(true), submit: Some(true),
            enabled: Some(true), help: Some(false), guide: Some(false), ..EntryDom::default() }];
    let longest_progress = super::BootstrapProgress::AppInfoReturnedBeforeHold;
    for boundary in [Boundary::Bootstrap, Boundary::Request, Boundary::Result, Boundary::Dom,
        Boundary::Gtk, Boundary::Settlement, Boundary::Deadline, Boundary::Exit] {
        assert!(boundary.failure_line().len() <= Boundary::Settlement.failure_line().len());
    }
    for sample in [super::BootstrapProgress::NotSampled, super::BootstrapProgress::Attachment,
        super::BootstrapProgress::PageLoad, super::BootstrapProgress::OriginalRegistrySample,
        super::BootstrapProgress::AppInfoCatalog, super::BootstrapProgress::HeldAppInfo,
        super::BootstrapProgress::Advanced, longest_progress] {
        assert!(sample.failure_line().len() <= longest_progress.failure_line().len());
    }
    let mut maximum = 0;
    for native in natives {
        for dom in doms {
            for origin in [EntryOrigin::EvaluationBudget, EntryOrigin::Deadline, EntryOrigin::CallbackShape,
                EntryOrigin::ScriptError, EntryOrigin::ReadyRefused] {
                let boundary = match origin { EntryOrigin::EvaluationBudget => Boundary::Settlement,
                    EntryOrigin::Deadline => Boundary::Deadline, _ => Boundary::Dom };
                let samples = EntrySamples { native, native_eval: (native.presence != EntryPresence::NotObserved).then_some(128),
                    dom, dom_eval: (dom.state != EntryDomState::NotObserved).then_some(128) };
                let diagnostic = EntryDiagnostic { cache: EntrySamples::default(),
                    frozen: Some(EntryFailure { origin, evaluations: 128, samples }) };
                if let Some((_, length)) = entry_failure_pair((trace.0, boundary), longest_progress, diagnostic) {
                    maximum = maximum.max(length);
                }
            }
        }
    }
    let (_, unrecorded) = entry_failure_pair(trace, longest_progress, EntryDiagnostic::default()).unwrap();
    assert!(unrecorded <= maximum);
    // Includes repo and guide, plus the longest existing three label lines.
    assert_eq!(maximum, 380); assert!(maximum <= super::FAILURE_PAIR_LIMIT);
}

#[derive(Clone, Copy)]
pub(crate) enum Command { Status, Connect, Refresh, Disconnect }
#[derive(Default)]
struct Record {
    attached: bool, peer_started: bool, peer_ready: bool, setup_claimed: bool,
    project_id: Option<String>, session_id: Option<String>, operation_ids: Vec<String>,
    replies: [u8;3], explicit_status: bool, latest: Option<wire::Status>,
    entry: bool, token_supplied: bool, token_cleared: bool, running_visible: bool,
    outcomes: Vec<Value>, status_visible: bool, disconnected: bool, unknown_visible: bool,
    unknown_injected: bool, close_ready: bool, physical_final: bool, final_checked: bool,
    peer_receipt: Option<Value>,
}
pub(crate) struct Control {
    case: Case, original: Mutex<Option<Weak<Observation>>>, failed: AtomicBool,
    record: Mutex<Record>, peer: AsyncMutex<InstalledPeer>, product: Arc<ProductWitness>,
}
impl Control {
    pub(super) fn new(case:Case)->Arc<Self> {
        let peer=InstalledPeer::new(case);let product=ProductWitness::new(case,&peer);
        Arc::new(Self{case,original:Mutex::new(None),failed:AtomicBool::new(false),
            record:Mutex::new(Record::default()),peer:AsyncMutex::new(peer),product})
    }
    fn original(&self)->Option<Arc<Observation>> { self.original.lock().ok()?.as_ref()?.upgrade() }
    fn fail(&self) { self.failed.store(true,Ordering::SeqCst);if let Some(q)=self.original(){q.fail();} }
    fn entry_fail(&self, q: &Observation, shell: &mut super::Record, origin: EntryOrigin) {
        self.failed.store(true, Ordering::SeqCst); q.github_entry_fail(shell, origin);
    }
    fn record(&self)->Option<std::sync::MutexGuard<'_,Record>> {
        match self.record.lock(){Ok(record)=>Some(record),Err(_)=>{self.fail();None}}
    }
    pub(super) fn profile(&self)->crate::runtime::GitHubReadOnlyObservationProfile { self.case.profile() }
    pub(super) fn attach(&self,q:&Arc<Observation>,supervisor:&Supervisor)->Result<(),BridgeError> {
        let mut slot=self.original.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        if slot.is_some() || !super::route() || q.case!=ShellCase::GitHub(self.case) || q.failed.load(Ordering::SeqCst)
            || !q.github.as_ref().is_some_and(|c|std::ptr::eq(c.as_ref(),self)) {return Err(BridgeError::invalid());}
        *slot=Some(Arc::downgrade(q));drop(slot);
        self.product.attach(supervisor).map_err(|_|BridgeError::invalid())?;
        let mut r=self.record().ok_or_else(BridgeError::cleanup_unknown)?;
        if r.attached{return Err(BridgeError::invalid());}r.attached=true;Ok(())
    }
    pub(super) fn status(&self,status:&wire::Status) {
        if self.failed.load(Ordering::SeqCst){return;}
        // The exact public decoder protects the same bounded status contract.
        let valid=serde_json::to_vec(status).is_ok_and(|raw|wire::decode_status(&raw).is_ok());
        if !valid{self.fail();return;}
        let Some(mut r)=self.record() else{return;};
        if r.latest.as_ref().is_some_and(|old|old.revision>status.revision){return;}
        r.latest=Some(status.clone());
    }
    pub(super) fn result(&self,command:Command,result:&Result<wire::Status,BridgeError>) {
        let Some(q)=self.original() else{self.fail();return;};
        if q.failed.load(Ordering::SeqCst){return;}
        let Ok(status)=result else{self.fail();return;};
        self.status(status);
        let Some(shell)=q.record_at(Boundary::Result) else{return;};
        let step=shell.step;
        let Some(mut r)=self.record() else{return;};
        match command {
            Command::Status=>{
                if matches!(step,ShellStep::GitHubReadOnly(Step::Status|Step::ReadStatus)) {
                    if r.explicit_status || !r.latest.as_ref().is_some_and(|s|s==status){self.fail();return;}
                    r.explicit_status=true;
                }
            },
            Command::Connect|Command::Refresh=>{
                let index=usize::from(matches!(command,Command::Refresh));
                let kind=if index==0{wire::OperationKind::Connect}else{wire::OperationKind::Refresh};
                let Some(session)=status.session.as_ref() else{self.fail();return;};
                let Some(operation)=status.operation.as_ref() else{self.fail();return;};
                if r.replies[index]!=0 || index==1&&self.case!=Case::ConnectRefresh
                    || operation.kind!=kind || operation.phase!=wire::Phase::Running || operation.reason!=wire::Reason::None
                    || session.state!=wire::SessionState::Checking || session.target_repository!="owner/app"
                    || r.project_id.as_deref()!=Some(session.project_id.as_str())
                    || (index==0 && r.session_id.is_some()) || (index==1 && r.session_id.as_deref()!=Some(session.id.as_str()))
                    || r.operation_ids.iter().any(|old|old==&operation.id) {self.fail();return;}
                if index==0{r.session_id=Some(session.id.clone());}
                r.operation_ids.push(operation.id.clone());r.replies[index]+=1;
            },
            Command::Disconnect=>{
                if r.replies[2]!=0 || matches!(self.case,Case::Quit|Case::Unknown)
                    || status.session.as_ref().is_some_and(|s|Some(s.id.as_str())!=r.session_id.as_deref()
                        ||s.project_id!=r.project_id.as_deref().unwrap_or("")||s.target_repository!="owner/app")
                    {self.fail();return;}
                r.replies[2]=1;
            },
        }
    }
    // Called by the SAME existing async relay, never a nested block_on/task.
    pub(super) async fn relay(&self,app:&tauri::AppHandle) {
        let Some(q)=self.original() else{self.fail();return;};
        if q.failed.load(Ordering::SeqCst){return;}
        let step=match q.record(){Some(r)=>r.step,None=>return};
        let state=app.state::<super::super::ShellState>();
        if step==ShellStep::GitHubReadOnly(Step::Connect) {
            let start=match self.record(){Some(mut r) if !r.setup_claimed=>{r.setup_claimed=true;true},_=>false};
            if start {
                let Some(root)=super::control_root() else{self.fail();return;};
                let mut peer=self.peer.lock().await;
                if peer.prepare(root,q.end).is_err(){self.fail();return;}
                if let Some(mut r)=self.record(){r.peer_started=true;}
                if peer.start().await.is_err(){self.fail();return;}
                if let Some(mut r)=self.record(){r.peer_ready=true;}
            }
        }
        if step==ShellStep::GitHubReadOnly(Step::InjectUnknown) {
            let inject=match self.record(){Some(r)=>!r.unknown_injected,_=>return};
            if inject {
                if !self.peer.lock().await.first_get() || self.product.inject_unknown(&state.bridge.supervisor).is_err(){self.fail();return;}
                if let Some(mut r)=self.record(){r.unknown_injected=true;}
                let Some(mut shell)=q.record_at(Boundary::Settlement) else{return;};
                if shell.step!=step || shell.pending.is_some(){self.fail();return;}
                shell.step=ShellStep::GitHubReadOnly(Step::Unknown);
            }
        }
        if self.product.observe_retired(&state.bridge.supervisor,q.end).await.is_err(){self.fail();}
    }
    pub(super) fn tick(&self,app:&tauri::AppHandle,step:Step)->bool {
        let Some(q)=self.original() else{self.fail();return false;};
        let Some(shell)=q.record() else{return false;};
        let project=shell.project.as_ref().map(|p|p.id.clone());
        if !shell.snapshot_visible || shell.project_witness.is_none(){self.fail();return false;}
        if step == Step::ReadGuidanceReload && (!shell.info || !shell.catalog || !shell.selected || !shell.snapshot) {
            self.fail(); return false;
        }
        drop(shell);
        let Some(mut r)=self.record() else{return false;};
        if r.project_id.is_none(){r.project_id=project;}
        if step == Step::Entry {
            let sample = EntryNative::sample(r.latest.as_ref());
            let ready = sample.ready();
            drop(r); // Never acquire the parent Record under this Control guard.
            let Some(mut shell) = q.record() else { return false; };
            if shell.step == ShellStep::GitHubReadOnly(Step::Entry) && !q.failed.load(Ordering::SeqCst) {
                let evaluations = shell.evaluations;
                shell.github_entry.native(sample, evaluations);
            }
            return ready;
        }
        let Some(status)=r.latest.as_ref() else{return false;};
        let state=app.state::<super::super::ShellState>();
        match step {
            Step::Connect=>r.peer_ready && r.token_supplied && r.replies[0]==0,
            Step::Observe if self.case.active_control()=>r.replies[0]==1
                && status.operation.as_ref().is_some_and(|o|o.phase==wire::Phase::Running)
                && self.peer.try_lock().is_ok_and(|p|p.first_get()),
            Step::Observe|Step::ObserveRefresh=>{
                let expected=if step==Step::ObserveRefresh{2}else{1};
                self.product.evidence().len()==expected && status.operation.as_ref().is_some_and(|o|o.phase==wire::Phase::Settled)
            },
            Step::ReadStatus=>r.explicit_status,
            Step::Disconnected=>r.replies[2]==1 && status.session.is_none() && status.operation.is_none()
                && self.product.complete(&state.bridge.supervisor),
            Step::Unknown=>r.unknown_injected && status.session.as_ref().is_some_and(|s|s.state==wire::SessionState::CleanupUnknown)
                && status.operation.as_ref().is_some_and(|o|o.phase==wire::Phase::CleanupUnknown)
                && self.product.complete(&state.bridge.supervisor),
            Step::InjectUnknown=>false,
            _=>true,
        }
    }
    pub(super) fn dom(&self,step:Step,value:&Value) {
        let Some(q)=self.original() else{self.fail();return;};
        let Some(mut shell)=q.record_at(Boundary::Dom) else{return;};
        if shell.step!=ShellStep::GitHubReadOnly(step)||shell.pending.take()!=Some(Pending::Dom(ShellStep::GitHubReadOnly(step))){self.fail();return;}
        // This effectful step never takes the generic wait/re-evaluation path.
        // Even malformed/wait callbacks permanently spend its one reservation.
        if step == Step::ReloadGuidance && (q.failed.load(Ordering::SeqCst) || !shell.github_guidance.click_returned(value)) { self.fail(); return; }
        if step == Step::Entry {
            // Capture the existing wait callback before its generic early return.
            // No Control lock or native resample is taken under this parent guard.
            let (sample, origin) = match EntryDom::parse(value) {
                None => (EntryDom::error(), Some(EntryOrigin::CallbackShape)),
                Some(sample) => {
                    let origin = match sample.state {
                        EntryDomState::Error => Some(EntryOrigin::ScriptError),
                        EntryDomState::Ready if sample.help != Some(true) => Some(EntryOrigin::ReadyRefused),
                        _ => None,
                    };
                    (sample, origin)
                },
            };
            if !q.failed.load(Ordering::SeqCst) {
                let evaluations = shell.evaluations;
                shell.github_entry.dom(sample, evaluations);
            }
            if let Some(origin) = origin { self.entry_fail(&q, &mut shell, origin); return; }
            if sample.state == EntryDomState::Wait { return; }
        }
        let Some(object)=value.as_object() else{self.fail();return;};
        if value["state"]=="wait"&&object.len()==1{return;}
        if value["state"]!="ready"{self.fail();return;}
        let Some(mut r)=self.record() else{return;};
        if matches!(step,Step::Observe|Step::ObserveRefresh|Step::ReadStatus|Step::Disconnected|Step::Unknown) {
            let Some(status)=r.latest.as_ref() else{self.fail();return;};
            match dom_observation(value,status) {
                DomObservation::Stale=>return, // Render catches up; never advances this original step.
                DomObservation::Refused=>{self.fail();return;},
                DomObservation::Matches=>{},
            }
        }
        let valid=match step {
            Step::Entry=>object.len()==9&&value["entryAvailable"]==true&&value["helpPresent"]==true,
            Step::Token=>object.len()==2&&value["supplied"]==true,
            Step::Observe|Step::ObserveRefresh|Step::ReadStatus|Step::Disconnected|Step::Unknown=>true,
            _=>object.len()==1,
        };
        if !valid{self.fail();return;}
        let next=match step {
            Step::Navigate=>Step::ReadGuidanceReload,
            Step::ReadGuidanceReload=>Step::ReloadGuidance,
            Step::ReloadGuidance=>Step::EnterRepository,
            Step::EnterRepository=>Step::Entry,
            Step::Entry=>{r.entry=true;Step::EnterToken},
            Step::EnterToken=>Step::Token,
            Step::Token=>{r.token_supplied=true;Step::Connect},
            Step::Connect=>Step::Observe,
            Step::Observe if self.case.active_control()=>{
                if !value["tokenEmpty"].as_bool().unwrap_or(false)||value["phase"]!="running"{self.fail();return;}
                r.token_cleared=true;r.running_visible=true;
                match self.case {
                    Case::Cancel=>Step::Disconnect,
                    Case::Unknown=>Step::InjectUnknown,
                    Case::Quit=>{r.close_ready=true;shell.step=ShellStep::Close;return;},
                    _=>{self.fail();return;},
                }
            },
            Step::Observe|Step::ObserveRefresh=>{
                if value["phase"]!="settled"||value["tokenEmpty"]!=true{self.fail();return;}
                let Some(status)=r.latest.as_ref() else{self.fail();return;};
                if status.operation.as_ref().is_none_or(|o|o.reason!=ui_reason(self.case)){self.fail();return;}
                let summary=summary(status);r.outcomes.push(summary);r.token_cleared=true;
                if self.case==Case::ConnectRefresh && step==Step::Observe{Step::Refresh}else{Step::Status}
            },
            Step::Refresh=>Step::ObserveRefresh,
            Step::Status=>Step::ReadStatus,
            Step::ReadStatus=>{r.status_visible=true;Step::Disconnect},
            Step::Disconnect=>Step::Disconnected,
            Step::Disconnected=>{
                if value["sessionId"]!=Value::Null||value["tokenEmpty"]!=true{self.fail();return;}
                r.disconnected=true;r.close_ready=true;shell.step=ShellStep::Close;return;
            },
            Step::Unknown=>{
                if value["connectEnabled"]!=false||value["refreshEnabled"]!=false||value["tokenEmpty"]!=true{self.fail();return;}
                r.unknown_visible=true;r.close_ready=true;shell.step=ShellStep::Close;return;
            },
            _=>{self.fail();return;},
        };
        shell.step=ShellStep::GitHubReadOnly(next);
    }
    pub(super) fn ready_to_close(&self)->bool {
        !self.failed.load(Ordering::SeqCst)&&self.record().is_some_and(|r|r.close_ready)
    }
    // Existing exit observer only, after the real document's original Quit,
    // product cleanup and native dialog finality. Failure still settles peers
    // through their same original handles, without publishing a success byte.
    pub(super) async fn settle_for_exit(&self,app:&tauri::AppHandle)->bool {
        let Some(q)=self.original() else{self.fail();return false;};
        let state=app.state::<super::super::ShellState>();
        if !state.document.can_exit(){return false;}
        if self.record().is_some_and(|r|r.physical_final){return true;}
        let product=self.product.observe_retired(&state.bridge.supervisor,q.end).await
            .is_ok_and(|final_seen|final_seen&&self.product.complete(&state.bridge.supervisor));
        let success=product&&!q.failed.load(Ordering::SeqCst)&&self.ready_to_close();
        let mut peer=self.peer.lock().await;
        let physical=peer.settle(success,q.end).await;
        let checked=success&&physical&&peer.validate(self.product.endpoint()).is_ok();
        if !checked{self.fail();}
        let Some(mut r)=self.record() else{return false;};
        r.physical_final=physical;r.final_checked=checked;
        if checked{r.peer_receipt=Some(peer.evidence());}
        physical
    }
    pub(super) fn complete(&self)->bool {
        !self.failed.load(Ordering::SeqCst)&&self.record().is_some_and(|r|
            r.attached&&r.peer_started&&r.peer_ready&&r.entry&&r.token_supplied&&r.token_cleared&&r.close_ready
            &&r.physical_final&&r.final_checked&&r.replies[0]==1&&r.replies[1]==u8::from(self.case==Case::ConnectRefresh)
            &&r.operation_ids.len()==self.case.reads()&&r.peer_receipt.is_some()
            &&self.product.evidence().iter().zip(&r.operation_ids).all(|(original,id)|original["operationId"].as_str()==Some(id.as_str()))
            &&if self.case.active_control(){r.running_visible&&r.outcomes.is_empty()&&!r.status_visible&&!r.explicit_status
                &&match self.case{Case::Cancel=>r.disconnected&&r.replies[2]==1,
                    Case::Quit=>!r.disconnected&&r.replies[2]==0,
                    Case::Unknown=>r.unknown_injected&&r.unknown_visible&&!r.disconnected&&r.replies[2]==0,_=>false}}
            else{r.outcomes.len()==self.case.reads()&&r.explicit_status&&r.status_visible&&r.disconnected&&r.replies[2]==1})
    }
    pub(super) fn report(&self)->Option<Vec<u8>> {
        if !self.complete(){return None;}
        let q=self.original()?;let shell=q.record()?;let r=self.record()?;
        if !shell.exit||!shell.originals_final||!shell.relay_joined||!shell.github_guidance.complete(){return None;}
        serde_json::to_vec(&json!({
            "schemaVersion":1,"fixture":"github-readonly-installed-v1","case":self.case.name(),"sourceCommit":option_env!("GITHUB_SHA")?,
            "normalManifestSha256":N,"productManifestSha256":self.case.manifest(),
            "protocolSha256":"860d1cee0072730a487ac8e632206c69e3ba676cab849b144a61755c4b84e41e",
            "peerSha256":if self.case.no_peer(){None}else{Some(PEER_SHA)},
            "project":{"cancelSettled":shell.cancelled&&shell.pickers[0].settled(false),
                "registered":shell.selected&&shell.pickers[1].settled(true)&&shell.project_witness.is_some(),
                "snapshot":shell.snapshot&&shell.snapshot_visible},
            "nativeSession":{"connect":r.replies[0],"refresh":r.replies[1],"disconnect":r.replies[2],
                "retainedStatus":r.status_visible&&r.explicit_status,"runningObserved":r.running_visible,
                "outcomes":r.outcomes,"cleared":r.disconnected,"unknownRetained":r.unknown_visible,
                "tokenFieldCleared":r.token_cleared},
            "originals":self.product.evidence(),"peer":r.peer_receipt,
            "quit":{"originalsFinal":shell.originals_final,"relayJoined":shell.relay_joined,
                "gtkSettled":shell.gtk_returned&&shell.destroyed&&shell.released,"exit":shell.exit},
            "notProven":self.case.not_proven()
        })).ok().filter(|raw|raw.len()<=32768)
    }
}
fn ui_reason(case:Case)->wire::Reason {
    use wire::Reason as R;
    match case {
        Case::ConnectRefresh|Case::AmbientFixed=>R::None,
        Case::RealCa|Case::WrongName|Case::Expired|Case::Ragged|Case::AmbientNoRescue=>R::TlsFailed,
        Case::HeaderLimit|Case::BodyLimit|Case::ChunkLimit=>R::ResponseLimit,
        Case::Unauthorized|Case::NormalNegative=>R::Unauthorized,Case::Identity=>R::TargetChanged,
        Case::HandshakeDeadline|Case::HeaderDeadline|Case::BodyDeadline|Case::DnsDeadline|Case::ConnectDeadline=>R::NetworkUnavailable,
        Case::Cancel|Case::Quit=>R::Cancelled,Case::Unknown=>R::CleanupUnknown,_=>R::ResponseInvalid,
    }
}
fn reason_help(reason:wire::Reason)->Option<&'static str> {
    use wire::Reason as R;
    Some(match reason{
        R::None=>"The reported observation is available, not release or mutation authority.",
        R::TlsFailed=>"TLS verification failed. Do not disable verification or supply alternate trust.",
        R::ResponseLimit=>"The bounded response limit was reached. No broader discovery is authorized.",
        R::ResponseInvalid=>"The original result did not satisfy the closed response contract.",
        R::Unauthorized=>"Authentication was refused. Retire the original request before explicitly authenticating again.",
        R::TargetChanged=>"The original account, repository or context identity changed. Do not adopt the replacement.",
        R::NetworkUnavailable=>"The bounded read failed. Raw service diagnostics are not displayed.",
        R::Cancelled=>"Local retirement was requested; actual original settlement must still be observed.",
        R::CleanupUnknown=>"Original cleanup is unknown. Further requests stay blocked even after late success.",
        _=>return None,
    })
}
fn summary(status:&wire::Status)->Value {
    json!({"revision":status.revision,"sessionId":status.session.as_ref().map(|s|&s.id),
        "projectId":status.session.as_ref().map(|s|&s.project_id),"target":status.session.as_ref().map(|s|&s.target_repository),
        "sessionState":status.session.as_ref().map(|s|s.state),"kind":status.operation.as_ref().map(|o|o.kind),
        "phase":status.operation.as_ref().map(|o|o.phase),"reason":status.operation.as_ref().map(|o|o.reason),
        "facts":[status.account.state,status.repository.state,status.automation.state],
        "accountId":status.account.value.as_ref().map(|a|&a.id),"repositoryId":status.repository.value.as_ref().map(|r|&r.id),
        "workflowRows":status.automation.value.as_ref().map_or(0,|a|a.workflows.len())})
}
fn dom_matches(value:&Value,status:&wire::Status)->bool {
    let summary=summary(status);
    let fields=["revision","sessionId","projectId","target","sessionState","kind","phase","facts","accountId","repositoryId","workflowRows"];
    value.as_object().is_some_and(|v|v.len()==18)
        &&fields.iter().all(|key|value.get(*key)==summary.get(*key))
        &&value["tokenEmpty"]==true&&value["remoteUnavailable"]==true
        &&value["reasonText"].as_str()==if let Some(op)=status.operation.as_ref(){reason_help(op.reason)}else{Some("")}
        &&(status.session.is_none()||value["connectEnabled"]==false)
        &&(status.session.as_ref().is_none_or(|s|s.state!=wire::SessionState::CleanupUnknown)||value["refreshEnabled"]==false)
}
#[derive(Debug, PartialEq, Eq)]
enum DomObservation { Stale, Matches, Refused }
fn dom_observation(value:&Value,status:&wire::Status)->DomObservation {
    if !super::keys(value,&["state","revision","sessionId","projectId","target","sessionState","kind","phase",
        "reasonText","facts","accountId","repositoryId","workflowRows","tokenEmpty","connectEnabled","refreshEnabled",
        "disconnectEnabled","remoteUnavailable"]) || value["state"]!="ready"
        || ["tokenEmpty","connectEnabled","refreshEnabled","disconnectEnabled","remoteUnavailable"].iter()
            .any(|key|!value[*key].is_boolean()) {return DomObservation::Refused;}
    match value["revision"].as_u64() {
        Some(revision) if revision>0 && revision<u64::from(status.revision)=>DomObservation::Stale,
        Some(revision) if revision==u64::from(status.revision) && dom_matches(value,status)=>DomObservation::Matches,
        _=>DomObservation::Refused,
    }
}
pub(super) fn assert_contracts() {
    assert_guidance_reload_contracts();
    assert_entry_diagnostic_contracts();
    crate::supervisor::github_tls_peer_owner::installed::assert_contracts();
    let mut status=crate::github_connection_session::ConnectionState::new().snapshot();
    status.revision=2;
    let mut value=summary(&status);
    let fields=value.as_object_mut().unwrap();fields.remove("reason");
    for (key,item) in [("state",json!("ready")),("reasonText",json!("")),("tokenEmpty",json!(true)),
        ("connectEnabled",json!(false)),("refreshEnabled",json!(false)),("disconnectEnabled",json!(false)),
        ("remoteUnavailable",json!(true))] {fields.insert(key.into(),item);}
    assert_eq!(dom_observation(&value,&status),DomObservation::Matches);
    let mut stale=value.clone();stale["revision"]=json!(1);
    assert_eq!(dom_observation(&stale,&status),DomObservation::Stale);
    for (key,item) in [("revision",json!(0)),("revision",json!(3)),("revision",json!(true)),
        ("accountId",json!("99")),("reasonText",json!("not the native reason")),("tokenEmpty",json!(false)),
        ("remoteUnavailable",json!(false)),("disconnectEnabled",json!("false")),("extra",json!(0))] {
        let mut changed=value.clone();changed[key]=item;
        assert_eq!(dom_observation(&changed,&status),DomObservation::Refused);
    }
    let mut unknown=status.clone();
    unknown.capability.read_only_session_available=false;unknown.capability.reason=wire::Reason::CleanupUnknown;
    unknown.session=Some(wire::Session{id:"github-session-1".into(),project_id:"project-1".into(),
        target_repository:"owner/app".into(),state:wire::SessionState::CleanupUnknown,expires_at:None});
    unknown.operation=Some(wire::Operation{id:"query-1".into(),kind:wire::OperationKind::Connect,
        phase:wire::Phase::CleanupUnknown,reason:wire::Reason::CleanupUnknown});
    for (state,reason) in [(&mut unknown.account.state,&mut unknown.account.reason),
        (&mut unknown.repository.state,&mut unknown.repository.reason),(&mut unknown.automation.state,&mut unknown.automation.reason)] {
        *state=wire::FactState::Unavailable;*reason=wire::Reason::CleanupUnknown;
    }
    assert!(wire::decode_status(&serde_json::to_vec(&unknown).unwrap()).is_ok());
    value["sessionId"]=json!("github-session-1");value["projectId"]=json!("project-1");value["target"]=json!("owner/app");
    value["sessionState"]=json!("cleanup-unknown");
    value["kind"]=json!("connect");value["phase"]=json!("cleanup-unknown");
    value["reasonText"]=json!(reason_help(wire::Reason::CleanupUnknown).unwrap());
    value["facts"]=json!(["unavailable","unavailable","unavailable"]);
    assert_eq!(dom_observation(&value,&unknown),DomObservation::Matches);
    value["connectEnabled"]=json!(true);
    assert_eq!(dom_observation(&value,&unknown),DomObservation::Refused);
    value["connectEnabled"]=json!(false);value["refreshEnabled"]=json!(true);
    assert_eq!(dom_observation(&value,&unknown),DomObservation::Refused);
}
pub(super) fn script(step:Step)->Option<String> {
    let body=match step{
        Step::Navigate=>r#"const b=document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="GitHub"]');
            if(!b||b.disabled)return {state:'wait'};show(b);b.click();return {state:'ready'};"#,
        Step::ReadGuidanceReload=>r#"const current=guidanceReload();if(!current||current.button.disabled)return {state:'wait'};
            if(Object.hasOwn(window,'__mrkInstalledGitHubGuidanceReload'))throw 0;
            show(current.button);window.__mrkInstalledGitHubGuidanceReload=current;return {state:'ready'};"#,
        Step::ReloadGuidance=>r#"const original=window.__mrkInstalledGitHubGuidanceReload;
            delete window.__mrkInstalledGitHubGuidanceReload;
            const current=guidanceReload();if(!original||!current||original.card!==current.card||original.button!==current.button||current.button.disabled)throw 0;
            show(current.button);current.button.click();return {state:'ready'};"#,
        Step::EnterRepository=>r#"if(!selected())return {state:'wait'};const input=card()?.querySelector('input[placeholder="OWNER/REPO"]');
            if(!input||input.disabled)return {state:'wait'};edit(input,'owner/app');return {state:'ready'};"#,
        Step::Entry=>r#"const c=card(),form=c?.querySelector('form.github-form'),b=form?.querySelector('button[type="submit"]'),s=!!selected();
            const input=c?.querySelector('input[placeholder="OWNER/REPO"]');
            const sample={entryAvailable:s&&!!form&&!!b&&!b.disabled,helpPresent:null,selected:s,formPresent:!!form,submitPresent:!!b,
                submitEnabled:b?!b.disabled:null,repositoryExpected:input?input.value==='owner/app':null,
                helpContainerPresent:c?!!c.querySelector('[aria-label="Core GitHub connection help"]'):null};
            if(!s||!form||!b||b.disabled)return {state:'wait',...sample};show(form);
            return {state:'ready',...sample,helpPresent:!!c.querySelector('[aria-label="Core GitHub connection help"]')&&text(c).includes('No GitHub App registration is needed')};"#,
        Step::EnterToken=>r#"const input=card()?.querySelector('form.github-form input[type="password"]');
            if(!input||input.disabled)return {state:'wait'};edit(input,'INERT_NOT_A_CREDENTIAL');return {state:'ready'};"#,
        Step::Token=>r#"const input=card()?.querySelector('form.github-form input[type="password"]');
            if(!input)return {state:'wait'};return {state:'ready',supplied:input.value==='INERT_NOT_A_CREDENTIAL'};"#,
        Step::Connect=>r#"return click('Connect for read-only observations');"#,
        Step::Refresh=>r#"return click('Refresh observation');"#,
        Step::Status=>r#"return click('Read retained Status');"#,
        Step::Disconnect=>r#"return click('Disconnect original session');"#,
        Step::InjectUnknown=>return None,
        Step::Observe|Step::ObserveRefresh|Step::ReadStatus|Step::Disconnected|Step::Unknown=>r#"
            const c=card();if(!selected()||!c)return {state:'wait'};show(c);
            const paragraphs=[...c.querySelectorAll(':scope > p.save-note')],row=paragraphs.find(p=>/^(Original native|Retained \/ stale original) status/.test(text(p)));
            if(!row)return {state:'wait'};const codes=[...row.querySelectorAll('code')].map(text),native=text(row),revision=/revision ([1-9][0-9]*)\./.exec(native);
            if(!revision||![0,3].includes(codes.length))throw 0;
            const session=/:\s*(checking|connected|expired|disconnecting|failed|cleanup-unknown)\.$/.exec(native);
            const op=paragraphs.find(p=>/^Original (connect|refresh|disconnect):/.test(text(p))),operation=op?/^Original (connect|refresh|disconnect): (running|settled|cleanup-unknown)\./.exec(text(op)):null;
            if(op&&!operation||codes.length===3&&!session)throw 0;
            const facts=[...c.querySelectorAll(':scope > h3')].map(h=>text(h.nextElementSibling?.querySelector('.badge')));
            if(facts.length!==3)throw 0;
            const account=[...c.querySelectorAll(':scope > p')].find(p=>p.querySelector('strong')&&p.querySelector('code')),
                repository=c.querySelector('dl.github-facts > div:first-child code'),table=c.querySelector('table.review-table tbody');
            const token=c.querySelector('input[type="password"]'),connect=c.querySelector('form.github-form button[type="submit"]');
            return {state:'ready',revision:Number(revision[1]),sessionId:codes[0]??null,projectId:codes[1]??null,target:codes[2]??null,
                sessionState:session?.[1]??null,kind:operation?.[1]??null,phase:operation?.[2]??null,
                reasonText:operation?text(op).slice(operation[0].length).trim():'',
                facts,accountId:account?text(account.querySelector('code')):null,repositoryId:repository?text(repository):null,
                workflowRows:table?table.querySelectorAll('tr').length:0,tokenEmpty:!token||token.value==='',
                connectEnabled:!!connect&&!connect.disabled,refreshEnabled:!!button('Refresh observation')&&!button('Refresh observation').disabled,
                disconnectEnabled:!!button('Disconnect original session')&&!button('Disconnect original session').disabled,
                remoteUnavailable:text(document.querySelector('[aria-label="Remote GitHub setup unavailable"]')).includes('No remote mutations or workflow dispatch.')};"#,
    };
    Some(format!(r#"(()=>{{try{{
        const text=n=>n?.textContent?.trim()??'',card=()=>document.querySelector('[aria-label="GitHub connection and observations"]');
        const selected=()=>!!document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="GitHub"][aria-current="page"]');
        const show=n=>{{n.scrollIntoView({{block:'center'}});const r=n.getBoundingClientRect();if(r.width<=0||r.height<=0||getComputedStyle(n).visibility!=='visible')throw 0;}};
        const button=name=>{{const rows=[...(card()?.querySelectorAll('button')??[])].filter(b=>text(b)===name);if(rows.length>1)throw 0;return rows[0];}};
        const click=name=>{{const b=button(name);if(!b||b.disabled)return {{state:'wait'}};show(b);b.click();return {{state:'ready'}};}};
        const guidanceReload=()=>{{
            if(!selected())return null;const cards=document.querySelectorAll('section[aria-label="GitHub connection and observations"]');
            if(cards.length>1)throw 0;if(cards.length!==1)return null;const c=cards[0];
            if(c.querySelector('form.github-form'))throw 0;
            const retained=[...c.querySelectorAll(':scope > p.review-caution[role="status"]')].filter(p=>text(p)==='Previously loaded help is retained for reading only; it does not enable entry.');
            if(retained.length>1)throw 0;
            if(retained.length!==1||!c.querySelector('[aria-label="Core GitHub connection help"]'))return null;
            const rows=[...document.querySelectorAll('button')].filter(b=>text(b)==='Reload service and connection guidance');
            if(rows.length>1)throw 0;if(rows.length!==1)return null;const b=rows[0];
            if(b.type!=='button'||b.form!==null||!b.isConnected||b.ownerDocument!==document||!b.parentElement?.classList.contains('button-row'))throw 0;
            return {{card:c,button:b}};
        }};
        const edit=(input,value)=>{{show(input);input.focus();input.select();if(!document.execCommand('insertText',false,value))throw 0;}};
        {body}
    }}catch{{return {{state:'error'}};}}}})()"#))
}
