//! Bounded, session-only GitHub state under the actual DocumentBinding mutex.
//! This is not another process owner. Only the existing Supervisor's final
//! mailbox receipt releases an active read; a reply or Unknown never does.
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use crate::{error::BridgeError, github_connection_protocol::{self as wire, Account, Automation,
    Authorization, AuthorizationPhase, Capability, ConnectTokenArgs, StartDeviceArgs, DeviceLogin, Fact, FactState, GitHubReadControl, GitHubReadFacts,
    GitHubReadOutcome, Operation, OperationKind, Phase, Reason, Repository, Session, SessionState,
    Status, UnobservedFacts}, github_device_protocol::{self as device, Secret},
    supervisor::{GitHubReadReceipt, GitHubReadTicket, GitHubDeviceState, GitHubDeviceTicket, Supervisor}};

// Historical development entry stays closed. The separate normal installed
// selector below supplies capability DATA, not a substitute for original
// document/project registration, per-request runtime custody or finality.
const GITHUB_CONNECTION_NATIVE_QUALIFIED: bool = false;
const LIFETIME: Duration = Duration::from_secs(60 * 60);
pub(crate) fn qualified() -> bool {
    GITHUB_CONNECTION_NATIVE_QUALIFIED && crate::runtime::GITHUB_TLS_PROFILE_QUALIFIED
        && cfg!(all(feature = "development-runtime", debug_assertions,
            target_os = "linux", target_arch = "x86_64", target_env = "gnu"))
}

// Only the actual document's Supervisor supplies installed availability. The
// same sealed profile is selected again inside its original inspection worker.
// Session-only memory neither depends on nor enables credential-asset storage.
pub(crate) fn qualified_for(supervisor: &Supervisor) -> bool {
    supervisor.github_readonly_profile_available() || qualified()
}

// Supplied private-session DATA for PG01 only. No ticket, socket, credential
// collection or GitHub qualification is minted by the offline registration.
#[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
    any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
pub(crate) fn offline_fixture_private(permit: &crate::offline_preflight_owner::OfflineRegistrationPermit,
    owner: &crate::offline_preflight_owner::OfflinePreflightOwner) -> Result<ConnectionState, BridgeError> {
    let (id, _, generation) = permit.validate(owner)?;
    if !permit.gate_evidence() { return Err(crate::offline_preflight_owner::unavailable()); }
    let mut state = tests::fixture(Instant::now());
    let private = state.private.as_mut().ok_or_else(crate::offline_preflight_owner::unavailable)?;
    private.project_id = id.into(); private.generation = generation;
    let session = state.status.session.as_mut().ok_or_else(crate::offline_preflight_owner::unavailable)?;
    session.project_id = id.into(); session.state = SessionState::Connected;
    state.status.operation.as_mut().ok_or_else(crate::offline_preflight_owner::unavailable)?.phase = Phase::Settled;
    if state.native_work_pending() || state.registration() != Some((id, generation)) {
        return Err(crate::offline_preflight_owner::unavailable());
    }
    Ok(state)
}

/// These codes mean refusal before a NEW read ticket/session was installed.
/// Do not map an unknown IPC/framework failure or a post-admission outcome here.
pub(crate) fn refused(reason: Reason) -> BridgeError {
    let (code, message) = match reason {
        Reason::Unqualified => ("unqualified", "Read-only GitHub connection is not qualified in this build."),
        Reason::PublisherUnconfigured => ("publisher_unconfigured", "The publisher has not configured GitHub device sign-in for this application."),
        Reason::Busy => ("busy", "Finish or disconnect the original GitHub operation first."),
        Reason::RuntimeUnavailable => ("runtime_unavailable", "The fixed GitHub runtime is unavailable."),
        Reason::CleanupUnknown => ("cleanup_unknown", "Original cleanup is unconfirmed; keep the original session for retirement."),
        Reason::TargetChanged => ("target_changed", "The original project or GitHub target changed."),
        Reason::Expired => ("expired", "Disconnect the expired session before connecting again."),
        Reason::RateLimited => ("rate_limited", "The original GitHub read-not-before limit still applies."),
        Reason::Cancelled => ("cancelled", "This document is no longer accepting GitHub reads."),
        _ => ("invalid_input", "The GitHub request does not match the supported input or current session."),
    };
    BridgeError::new(&format!("github_connection_refused_{code}"), message)
}
fn admission_error(error: BridgeError) -> BridgeError {
    refused(match error.code.as_str() {
        "busy" => Reason::Busy, "cleanup_unknown" => Reason::CleanupUnknown,
        "runtime_unavailable" => Reason::RuntimeUnavailable, "shutting_down" | "cancelled" => Reason::Cancelled,
        _ => Reason::InvalidInput,
    })
}
fn outcome_error(error: &BridgeError) -> Reason {
    match error.code.as_str() {
        "cleanup_unknown" => Reason::CleanupUnknown,
        "protocol_error" => Reason::ResponseInvalid,
        "output_limit" | "stdout_limit" | "stderr_limit" => Reason::ResponseLimit,
        "runtime_unavailable" => Reason::RuntimeUnavailable,
        "cancelled" | "shutting_down" => Reason::Cancelled,
        // A child/DNS/read deadline is not proof the credential expired.
        _ => Reason::NetworkUnavailable,
    }
}
fn retryable(reason: Reason) -> bool {
    matches!(reason, Reason::NetworkUnavailable | Reason::TlsFailed | Reason::ResponseLimit
        | Reason::RateLimited | Reason::Forbidden | Reason::NotFoundOrInaccessible)
}
fn retires(reason: Reason) -> bool {
    matches!(reason, Reason::Unauthorized | Reason::TargetChanged | Reason::ResponseInvalid
        | Reason::Expired | Reason::Cancelled)
}
fn unobserved<T>() -> Fact<T> {
    Fact { state: FactState::NotObserved, value: None, observed_at: None, reason: Reason::NotConnected }
}
fn unavailable<T>(reason: Reason) -> Fact<T> {
    Fact { state: FactState::Unavailable, value: None, observed_at: None, reason }
}
fn stale<T>(fact: &mut Fact<T>, reason: Reason) {
    if fact.value.is_some() { fact.state = FactState::Stale; fact.reason = reason; }
    else { *fact = unavailable(reason); }
}
fn merge<T>(old: Fact<T>, new: Fact<T>) -> Fact<T> {
    if new.state == FactState::Observed || old.value.is_none() { new }
    else { let mut old = old; stale(&mut old, new.reason); old }
}
fn empty_status(revision: u32, reason: Reason) -> Status {
    Status { schema_version: 2, revision,
        capability: Capability { read_only_session_available: reason == Reason::None, reason,
            device_login: if device::publisher().is_some() { DeviceLogin::NotQualified } else { DeviceLogin::PublisherUnconfigured },
            publisher_name: device::publisher().map(|p| p.display_name.clone()), storage: "session-only".into() },
        session: None, operation: None, authorization: None, account: unobserved(), repository: unobserved(), automation: unobserved(), input_metadata: None,
        facts: UnobservedFacts { remote_mutation_available: false, dispatch_available: false,
            repository_actions_settings_observation: "not-run".into(), environment_observation: "not-run".into(),
            secret_observation: "not-run".into(), variable_observation: "not-run".into(),
            protection_observation: "not-run".into(), runner_observation: "not-run".into(),
            template_compatibility: "unknown".into(), release_readiness: "unknown".into() } }
}

// Original subsecond clock pair. Later wall-clock samples, status ticks and
// refreshes cannot move this endpoint forward. Display UTC is not authority.
struct CredentialClock { admitted: Instant, wall: SystemTime, end: Instant, display: String }
impl CredentialClock {
    fn new(admitted: Instant, wall: SystemTime) -> Option<Self> {
        Some(Self { admitted, wall, end: admitted.checked_add(LIFETIME)?,
            display: display_utc(wall.checked_add(LIFETIME)?)? })
    }
    fn display_end(&self, end: Instant) -> Option<String> {
        display_utc(self.wall.checked_add(end.checked_duration_since(self.admitted)?)?)
    }
    fn shorten_from(&mut self, original_start: Instant, seconds: u32) -> bool {
        let Some(end) = original_start.checked_add(Duration::from_secs(u64::from(seconds))) else { return false; };
        if end < self.end {
            let Some(display) = self.display_end(end) else { return false; };
            self.end = end; self.display = display;
        }
        true
    }
    fn shorten(&mut self, timestamp: &str) -> bool {
        let Some(server) = parse_utc(timestamp) else { return false; };
        let end = match server.duration_since(self.wall) {
            Ok(delta) => match self.admitted.checked_add(delta) { Some(end) => end, None => return false },
            Err(_) => self.admitted,
        };
        if end < self.end { self.end = end; self.display = timestamp.into(); }
        true
    }
}
fn leap(year: u32) -> bool { year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) }
fn month_days(year: u32, month: u32) -> u32 {
    match month { 2 => if leap(year) { 29 } else { 28 }, 4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31, _ => 0 }
}
fn parse_utc(text: &str) -> Option<SystemTime> {
    let b = text.as_bytes();
    if b.len() != 20 || !b.is_ascii() || b[4] != b'-' || b[7] != b'-' || b[10] != b'T'
        || b[13] != b':' || b[16] != b':' || b[19] != b'Z'
        || b.iter().enumerate().any(|(i, v)| ![4, 7, 10, 13, 16, 19].contains(&i) && !v.is_ascii_digit()) { return None; }
    let n = |a: usize, z: usize| text.get(a..z)?.parse::<u32>().ok();
    let (y, m, d, h, minute, s) = (n(0, 4)?, n(5, 7)?, n(8, 10)?, n(11, 13)?, n(14, 16)?, n(17, 19)?);
    if y == 0 || d == 0 || d > month_days(y, m) || h > 23 || minute > 59 || s > 59 { return None; }
    // Finite canonical years1..9999; do not add a permissive date parser.
    let before = |year: u32| { let v = i64::from(year - 1); 365 * v + v / 4 - v / 100 + v / 400 };
    let days = before(y) - before(1970) + (1..m).map(|month| i64::from(month_days(y, month))).sum::<i64>() + i64::from(d - 1);
    let seconds = days * 86400 + i64::from(h * 3600 + minute * 60 + s);
    if seconds < 0 { UNIX_EPOCH.checked_sub(Duration::from_secs(seconds.unsigned_abs())) }
    else { UNIX_EPOCH.checked_add(Duration::from_secs(seconds as u64)) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github_connection_protocol::{Coverage, Permission, Permissions, Presence, Visibility, Workflow, WorkflowState};
    use crate::github_workflow_edit_protocol::WorkflowId;

    // Supplied DATA only. There is deliberately no runtime, fake Child, ticket
    // factory, socket, filesystem fixture or claim of native finality here.
    pub(super) fn fixture(at: Instant) -> ConnectionState {
        let mut state = ConnectionState::new();
        let clock = CredentialClock::new(at, parse_utc("2026-09-17T12:00:00Z").unwrap()).unwrap();
        state.private = Some(PrivateSession { id: "github-session-1".into(), project_id: "project-1".into(), repository: "owner/app".into(),
            generation: 2, stop_id: "github-disconnect-1".into(), unknown_id: "github-unknown-1".into(),
            clock, token: Some(Secret::new("INERT_NOT_A_CREDENTIAL".into())),
            account_pin: None, repository_pin: None, ticket: None, device: None, retirement: None, remove_after_settlement: false, inspection: None });
        state.status.session = Some(Session { id: "github-session-1".into(), project_id: "project-1".into(), target_repository: "owner/app".into(),
            state: SessionState::Checking, expires_at: Some("2026-09-17T13:00:00Z".into()) });
        state.status.operation = Some(Operation { id: "original-data-1".into(), kind: OperationKind::Connect, phase: Phase::Running, reason: Reason::None });
        state
    }
    fn observed<T>(value: T) -> Fact<T> { Fact { state: FactState::Observed, value: Some(value), observed_at: Some("2026-09-17T12:00:01Z".into()), reason: Reason::None } }
    fn result() -> GitHubReadOutcome {
        GitHubReadOutcome { metadata: None, facts: GitHubReadFacts { schema_version: 1,
            account: observed(Account { id: "11".into(), login: "owner".into() }),
            repository: observed(Repository { id: "22".into(), full_name: "owner/app".into(), default_branch: "main".into(), visibility: Visibility::Private,
                archived: false, permissions: Permissions { pull: Permission::ReportedAllowed, push: Permission::Unknown, admin: Permission::Unknown } }),
            automation: observed(Automation { coverage: Coverage::Complete, workflows: [WorkflowId::Preflight, WorkflowId::Candidate, WorkflowId::ExternalTesting, WorkflowId::ProductionSubmit]
                .into_iter().map(|id| Workflow { id, remote_id: None, presence: Presence::NotListed, state: WorkflowState::Unknown }).collect() }) },
            control: GitHubReadControl { reason: Reason::None, credential_expires_at: None, cooldown_seconds: None, cooldown_blocked: false } }
    }
    fn valid(state: &ConnectionState) {
        let bytes = serde_json::to_vec(&state.snapshot()).unwrap();
        assert!(wire::decode_status(&bytes).is_ok(), "native projection must obey the public DTO");
        assert!(!String::from_utf8(bytes).unwrap().contains("INERT_NOT_A_CREDENTIAL"));
    }
    fn settle(state: &mut ConnectionState, value: GitHubReadOutcome, original: Instant, observed: Instant, was_unknown: bool) {
        let before = state.status.clone(); state.accept_final(Ok(value), original, was_unknown, observed);
        state.capability(observed, Reason::None); state.finish(before); valid(state);
    }
    fn refresh_data(state: &mut ConnectionState) {
        state.status.operation = Some(Operation { id: "original-data-2".into(), kind: OperationKind::Refresh, phase: Phase::Running, reason: Reason::None });
        state.status.session.as_mut().unwrap().state = SessionState::Checking; state.fact_retirement(Reason::Stale);
    }

    fn inspection_selection() -> crate::github_environment_metadata::Selection {
        crate::github_environment_metadata::Selection { stage:"production".into(),
            name:"MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION".into() }
    }
    fn inspection_data(state: &mut ConnectionState) {
        refresh_data(state);
        state.status.operation.as_mut().unwrap().kind = OperationKind::Inspect;
        state.private.as_mut().unwrap().inspection = Some(inspection_selection());
    }
    fn inspection_result() -> GitHubReadOutcome {
        use crate::github_environment_metadata::{Observation, Environment, Field, FieldKind};
        let mut value = result();
        value.facts.automation = unavailable(Reason::Cancelled);
        value.metadata = Some(Observation { selection: inspection_selection(),
            environment: observed(Environment { id:"33".into(), name:"mobile-production".into() }),
            field: observed(Field { name:inspection_selection().name, kind:FieldKind::Variable,
                created_at:"2026-09-17T12:00:00Z".into(), updated_at:"2026-09-17T12:00:00Z".into() }) });
        value
    }
    #[test]
    fn environment_input_metadata_settlement_is_original_selected_and_refresh_stales_it() {
        let at = Instant::now(); let mut state = fixture(at);
        settle(&mut state, result(), at, at, false);
        let endpoint = state.private.as_ref().unwrap().clock.end;
        inspection_data(&mut state);
        assert!(state.status.input_metadata.is_none());
        settle(&mut state, inspection_result(), at + Duration::from_secs(1), at + Duration::from_secs(1), false);
        assert!(state.private.as_ref().unwrap().inspection.is_none());
        assert_eq!(state.private.as_ref().unwrap().clock.end, endpoint);
        assert_eq!(state.status.operation.as_ref().unwrap().kind, OperationKind::Inspect);
        assert_eq!(state.status.input_metadata.as_ref().unwrap().field.state, FactState::Observed);
        assert_eq!(state.status.facts.variable_observation, "metadata-only");
        assert_eq!(state.status.facts.secret_observation, "not-run");
        assert!(!state.status.facts.remote_mutation_available);
        assert_eq!(state.status.facts.release_readiness, "unknown");
        let before = state.snapshot(); refresh_data(&mut state);
        state.status.operation.as_mut().unwrap().id = "original-data-3".into();
        state.finish(before); valid(&state);
        assert_eq!(state.status.input_metadata.as_ref().unwrap().field.state, FactState::Stale);
        assert_eq!(state.status.input_metadata.as_ref().unwrap().selection, inspection_selection());
    }
    #[test]
    fn environment_input_selection_mismatch_retires_without_erasing_original_cooldown() {
        let at = Instant::now(); let mut state = fixture(at);
        settle(&mut state, result(), at, at, false); inspection_data(&mut state);
        let mut wrong = inspection_result();
        let observation = wrong.metadata.as_mut().unwrap();
        observation.selection.name = "MOBILE_RELEASE_ANDROID_KEY_ALIAS".into();
        observation.field.value.as_mut().unwrap().name = observation.selection.name.clone();
        wrong.control.reason = Reason::RateLimited; wrong.control.cooldown_seconds = Some(7);
        settle(&mut state, wrong, at + Duration::from_secs(1), at + Duration::from_secs(1), false);
        assert_eq!(state.status.operation.as_ref().unwrap().reason, Reason::ResponseInvalid);
        assert_eq!(state.cooldown, Some(at + Duration::from_secs(8)));
        assert!(state.private.as_ref().unwrap().token.is_none());
        assert!(state.status.input_metadata.is_none());
        assert_eq!(state.status.session.as_ref().unwrap().state, SessionState::Failed);
    }
    #[test]
    fn environment_input_late_metadata_never_revives_expired_cancelled_or_unknown_session() {
        // Supplied phase DATA, not proof of an OS stop, a ticket or native finality.
        let at = Instant::now();
        for mode in ["expired", "cancelled", "unknown"] {
            let mut state = fixture(at); settle(&mut state, result(), at, at, false); inspection_data(&mut state);
            let now = if mode == "expired" { at + LIFETIME } else { at + Duration::from_secs(2) };
            if mode == "cancelled" { state.retire(Reason::Cancelled); }
            if mode == "unknown" { state.unknown(); }
            settle(&mut state, inspection_result(), at + Duration::from_secs(1), now, mode == "unknown");
            assert!(state.status.input_metadata.is_none());
            assert!(state.private.as_ref().unwrap().token.is_none());
            assert_ne!(state.status.session.as_ref().unwrap().state, SessionState::Connected);
            assert_eq!(state.status.facts.variable_observation, "not-run");
        }
    }

    // Public/private phase DATA only. Setting a supplied public capability here
    // cannot activate publisher registration, qualification or Supervisor admission.
    fn device_fixture(at: Instant) -> ConnectionState {
        let mut state = fixture(at);
        let private = state.private.as_mut().unwrap(); private.token = None;
        private.device = Some(DeviceAuthorization { end: at + Duration::from_secs(900), code: None,
            interval: 5, next_poll: None, polls: 0, ticket: None, checking_access: false });
        state.status.capability.device_login = DeviceLogin::Available;
        state.status.capability.publisher_name = Some("Synthetic publisher DATA".into());
        state.status.capability.reason = Reason::Busy; state.status.capability.read_only_session_available = false;
        state.status.operation.as_mut().unwrap().kind = OperationKind::Authorize;
        state.status.authorization = Some(Authorization { phase: AuthorizationPhase::RequestingCode, user_code: None, expires_at: None });
        valid(&state); state
    }
    fn device_code_data(state: &mut ConnectionState, start: Instant, settled: Instant, now: Instant, expiry: u32, interval: u32) {
        let before = state.snapshot();
        state.accept_device_result(Ok(device::Outcome::Code { device_code: Secret::new("0123456789012345678901234567890123456789".into()),
            user_code: "AB12-CD34".into(), expires_in: expiry, interval }), device::Step::Start, start, settled, false, now);
        state.finish(before); valid(state);
    }
    fn poll_data(state: &mut ConnectionState, result: device::Outcome, started: Instant, settled: Instant, now: Instant) {
        // Supply the phase after a separately admitted original poll. No native
        // ticket, socket or original-settlement fact is forged by this fixture.
        let auth = state.private.as_mut().unwrap().device.as_mut().unwrap();
        auth.next_poll = None; auth.polls += 1;
        let before = state.snapshot();
        state.accept_device_result(Ok(result), device::Step::Poll, started, settled, false, now);
        state.finish(before); valid(state);
    }
    #[test]
    fn device_original_expiry_and_settled_poll_schedule_do_not_renew() {
        let at = Instant::now(); let mut state = device_fixture(at);
        let operation = state.status.operation.as_ref().unwrap().id.clone();
        device_code_data(&mut state, at, at + Duration::from_secs(2), at + Duration::from_secs(2), 40, 1);
        let auth = state.private.as_ref().unwrap().device.as_ref().unwrap();
        assert_eq!(auth.end, at + Duration::from_secs(40));
        assert_eq!(auth.interval, 5); assert_eq!(auth.next_poll, Some(at + Duration::from_secs(7)));
        assert_eq!(auth.poll_due(at + Duration::from_secs(6)), Ok(false));
        assert_eq!(auth.poll_due(at + Duration::from_secs(7)), Ok(true));
        poll_data(&mut state, device::Outcome::SlowDown { interval: 7 }, at + Duration::from_secs(7), at + Duration::from_secs(9), at + Duration::from_secs(9));
        let auth = state.private.as_ref().unwrap().device.as_ref().unwrap();
        assert_eq!(auth.interval, 10); assert_eq!(auth.next_poll, Some(at + Duration::from_secs(19)));
        assert_eq!(state.status.authorization.as_ref().unwrap().phase, AuthorizationPhase::SlowDown);
        poll_data(&mut state, device::Outcome::Pending { interval: Some(2) }, at + Duration::from_secs(19), at + Duration::from_secs(21), at + Duration::from_secs(21));
        let auth = state.private.as_mut().unwrap().device.as_mut().unwrap();
        assert_eq!(auth.interval, 10); assert_eq!(auth.next_poll, Some(at + Duration::from_secs(31)));
        assert_eq!(auth.end, at + Duration::from_secs(40));
        auth.polls = device::POLL_LIMIT; assert_eq!(auth.poll_due(at + Duration::from_secs(31)), Err(Reason::ResponseLimit));
        assert_eq!(state.status.operation.as_ref().unwrap().id, operation);
        assert_eq!(state.private.as_ref().unwrap().clock.end, at + LIFETIME);
        assert!(state.native_work_pending() && !state.private.as_ref().unwrap().original_pending());
        state.reconcile(at + Duration::from_secs(40), Reason::None); valid(&state);
        assert!(state.material_settled() && !state.native_work_pending());
        assert_eq!(state.status.session.as_ref().unwrap().state, SessionState::Expired);
    }
    #[test]
    fn device_token_is_private_until_final_identity_bracket_and_keeps_original_ceiling() {
        let at = Instant::now(); let mut state = device_fixture(at);
        device_code_data(&mut state, at, at, at, 900, 5);
        poll_data(&mut state, device::Outcome::Token { token: Secret::new("ghu_SYNTHETIC_NOT_A_CREDENTIAL".into()), expires_in: Some(28_800) },
            at + Duration::from_secs(5), at + Duration::from_secs(6), at + Duration::from_secs(6));
        assert_eq!(state.status.session.as_ref().unwrap().state, SessionState::Checking);
        let auth = state.status.authorization.as_ref().unwrap();
        assert_eq!(auth.phase, AuthorizationPhase::CheckingAccess); assert!(auth.user_code.is_none());
        assert!(state.private.as_ref().unwrap().device.as_ref().unwrap().code.is_none());
        assert!(state.private.as_ref().unwrap().token.is_some());
        assert_eq!(state.private.as_ref().unwrap().clock.end, at + LIFETIME);
        assert!(!serde_json::to_string(&state.snapshot()).unwrap().contains("ghu_"));
        assert_eq!(state.status.account.state, FactState::NotObserved);
        let original = state.status.operation.as_ref().unwrap().id.clone();
        settle(&mut state, result(), at + Duration::from_secs(8), at + Duration::from_secs(8), false);
        assert_eq!(state.status.operation.as_ref().unwrap().id, original);
        assert_eq!(state.status.operation.as_ref().unwrap().kind, OperationKind::Authorize);
        assert_eq!(state.status.session.as_ref().unwrap().state, SessionState::Connected);
        assert!(state.status.authorization.is_none() && state.private.as_ref().unwrap().device.is_none());
        assert_eq!(state.private.as_ref().unwrap().account_pin.as_deref(), Some("11"));
        assert_eq!(state.private.as_ref().unwrap().repository_pin.as_deref(), Some("22"));
    }
    #[test]
    fn device_shortened_expiry_and_late_cancelled_or_unknown_token_never_adopt() {
        let at = Instant::now(); let mut late_code = device_fixture(at);
        device_code_data(&mut late_code, at, at + Duration::from_secs(2), at + Duration::from_secs(3), 1, 5);
        assert_eq!(late_code.status.session.as_ref().unwrap().state, SessionState::Expired);
        assert!(late_code.material_settled() && late_code.status.authorization.is_none());
        for reason in [Reason::Cancelled, Reason::Expired, Reason::TargetChanged, Reason::CleanupUnknown] {
            let mut state = device_fixture(at); device_code_data(&mut state, at, at, at, 900, 5);
            if reason == Reason::CleanupUnknown { state.unknown(); } else { state.retire(reason); }
            let snapshot = state.snapshot();
            state.accept_device_result(Ok(device::Outcome::Token { token: Secret::new("ghu_LATE_SYNTHETIC".into()), expires_in: None }),
                device::Step::Poll, at, at, reason == Reason::CleanupUnknown, at);
            valid(&state);
            assert_eq!(state.snapshot(), snapshot);
            assert!(state.material_settled() && state.status.authorization.is_none());
            assert!(state.private.as_ref().unwrap().token.is_none());
        }
    }
    #[test]
    fn device_ambiguous_failure_is_terminal_and_cooldown_survives_disconnect() {
        let at = Instant::now(); let mut state = device_fixture(at); device_code_data(&mut state, at, at, at, 900, 5);
        poll_data(&mut state, device::Outcome::Failed { reason: Reason::RateLimited, cooldown_seconds: Some(60), cooldown_blocked: false },
            at + Duration::from_secs(5), at + Duration::from_secs(6), at + Duration::from_secs(8));
        assert_eq!(state.cooldown, Some(at + Duration::from_secs(66)));
        assert_eq!(state.status.operation.as_ref().unwrap().kind, OperationKind::Authorize);
        assert_eq!(state.status.operation.as_ref().unwrap().phase, Phase::Settled);
        assert_eq!(state.private.as_ref().unwrap().retirement, Some(Reason::RateLimited));
        assert!(state.material_settled());
        state.disconnect("github-session-1", at + Duration::from_secs(9), Reason::None).unwrap(); valid(&state);
        assert_eq!(state.status.capability.reason, Reason::RateLimited);
        let mut state = device_fixture(at);
        state.accept_device_result(Err(BridgeError::protocol()), device::Step::Start, at, at, false, at);
        valid(&state); assert_eq!(state.private.as_ref().unwrap().retirement, Some(Reason::ResponseInvalid));
        assert!(state.material_settled() && state.status.authorization.is_none());
    }
    #[test]
    fn browser_gate_is_exact_current_read_only_and_closes_at_original_deadline() {
        let at = Instant::now(); let mut state = device_fixture(at); device_code_data(&mut state, at, at, at, 900, 5);
        let snapshot = state.snapshot(); let revision = snapshot.revision;
        assert!(state.allow_device_page("github-session-1", revision, at, Reason::None).is_ok());
        for (id, revision, when, external) in [
            ("replacement", revision, at, Reason::None), ("github-session-1", revision - 1, at, Reason::None),
            ("github-session-1", revision, at + Duration::from_secs(900), Reason::None),
            ("github-session-1", revision, at, Reason::Busy), ("github-session-1", revision, at, Reason::Cancelled)] {
            assert!(state.allow_device_page(id, revision, when, external).is_err());
        }
        assert_eq!(state.snapshot(), snapshot); // No observation/revision/poll at handoff.
        state.private.as_mut().unwrap().device.as_mut().unwrap().checking_access = true;
        assert!(state.allow_device_page("github-session-1", revision, at, Reason::None).is_err());
    }

    #[test]
    fn saved_preflight_requires_explicit_disconnect_of_retained_private_session() {
        let at = Instant::now();
        assert!(ConnectionState::new().registration().is_none());
        let mut state = fixture(at); // Existing inert DATA, no original ticket.
        state.status.session.as_mut().unwrap().state = SessionState::Connected;
        state.status.operation.as_mut().unwrap().phase = Phase::Settled;
        assert!(!state.native_work_pending());
        assert!(!state.material_settled()); // The idle original still retains its token.
        assert_eq!(state.registration(), Some(("project-1", 2)));
        state.retire(Reason::Expired);
        assert!(state.material_settled()); // Token retirement is not Disconnect.
        assert!(!state.native_work_pending());
        assert_eq!(state.registration(), Some(("project-1", 2)));
        state.disconnect("github-session-1", at, Reason::None).unwrap();
        assert!(state.registration().is_none());
        assert!(state.snapshot().session.is_none());
        assert!(state.material_settled());
    }

    #[test]
    fn admission_pair_preserves_subseconds_and_server_expiry_can_only_shorten() {
        let at = Instant::now();
        let wall = parse_utc("2026-09-17T12:00:00Z").unwrap() + Duration::from_millis(750);
        let mut clock = CredentialClock::new(at, wall).unwrap();
        assert_eq!(clock.end, at + LIFETIME);
        assert_eq!(clock.display, "2026-09-17T13:00:00Z");
        assert!(clock.shorten("2026-09-17T12:00:10Z"));
        assert_eq!(clock.end, at + Duration::from_millis(9250));
        let end = clock.end;
        assert!(clock.shorten("2026-09-18T12:00:00Z")); assert_eq!(clock.end, end);
        assert!(clock.shorten("1900-01-01T00:00:00Z")); assert_eq!(clock.end, at);
        assert!(!clock.shorten("2025-02-29T00:00:00Z")); assert_eq!(clock.end, at);
        for value in ["1970-01-01T00:00:00Z", "2000-02-29T23:59:59Z", "9999-12-31T23:59:59Z"] {
            assert_eq!(display_utc(parse_utc(value).unwrap()).as_deref(), Some(value));
        }
    }
    #[test]
    fn native_gate_and_fixed_refusals_do_not_publish_private_material() {
        assert!(!qualified()); valid(&ConnectionState::new());
        let codes = [Reason::Unqualified, Reason::Busy, Reason::InvalidInput, Reason::RuntimeUnavailable,
            Reason::CleanupUnknown, Reason::TargetChanged, Reason::Expired, Reason::RateLimited, Reason::Cancelled]
            .map(|reason| { let error = refused(reason); assert!(!error.retryable); error.code });
        assert_eq!(codes.iter().collect::<std::collections::BTreeSet<_>>().len(), 9);
        assert!(codes.iter().all(|code| code.starts_with("github_connection_refused_")));
        assert!(!retryable(Reason::ResponseInvalid)); assert!(!retryable(Reason::Unauthorized));
    }
    #[test]
    fn supplied_final_facts_pin_identity_without_conflating_repository_access() {
        let at = Instant::now(); let mut state = fixture(at);
        settle(&mut state, result(), at, at, false);
        assert_eq!(state.private.as_ref().unwrap().account_pin.as_deref(), Some("11"));
        assert_eq!(state.private.as_ref().unwrap().repository_pin.as_deref(), Some("22"));
        refresh_data(&mut state);
        let mut inaccessible = result(); inaccessible.control.reason = Reason::Forbidden;
        inaccessible.facts.repository = unavailable(Reason::Forbidden); inaccessible.facts.automation = unavailable(Reason::Cancelled);
        settle(&mut state, inaccessible, at, at, false);
        assert_eq!(state.status.session.as_ref().unwrap().state, SessionState::Connected);
        assert_eq!(state.status.repository.state, FactState::Stale); assert_eq!(state.status.automation.state, FactState::Stale);
        refresh_data(&mut state);
        let mut replaced = result(); replaced.facts.repository.value.as_mut().unwrap().id = "23".into();
        settle(&mut state, replaced, at, at, false);
        assert_eq!(state.status.session.as_ref().unwrap().state, SessionState::Failed);
        assert_eq!(state.status.operation.as_ref().unwrap().reason, Reason::TargetChanged);
        assert_eq!(state.private.as_ref().unwrap().repository_pin.as_deref(), Some("22"));
        assert!(state.private.as_ref().unwrap().token.is_none());
    }
    #[test]
    fn known_cooldown_survives_invalid_expiry_disconnect_and_token_lifetime() {
        let at = Instant::now(); let mut state = fixture(at);
        let mut value = result(); value.control.reason = Reason::ResponseInvalid; value.control.cooldown_seconds = Some(7200);
        settle(&mut state, value, at, at + Duration::from_secs(5), false);
        assert!(state.private.as_ref().unwrap().token.is_none()); assert_eq!(state.cooldown, Some(at + Duration::from_secs(7200)));
        state.disconnect("github-session-1", at + Duration::from_secs(5), Reason::None).unwrap();
        assert!(state.status.session.is_none()); valid(&state);
        for seconds in [6, 3601, 7199] {
            state.reconcile(at + Duration::from_secs(seconds), Reason::None);
            assert_eq!(state.status.capability.reason, Reason::RateLimited);
            assert_eq!(state.cooldown, Some(at + Duration::from_secs(7200))); valid(&state);
        }
        state.reconcile(at + Duration::from_secs(7200), Reason::None); assert!(state.status.capability.read_only_session_available);
        let limit = GitHubReadControl { reason: Reason::RateLimited, credential_expires_at: None, cooldown_seconds: None, cooldown_blocked: true };
        assert!(state.apply_control(&limit, at));
        state.reconcile(at + Duration::from_secs(800000), Reason::None);
        assert_eq!(state.status.capability.reason, Reason::RateLimited); assert!(state.cooldown_blocked);
    }
    #[test]
    fn supplied_unknown_stays_absorbing_after_late_final_data_and_disconnect() {
        let at = Instant::now(); let mut state = fixture(at);
        let running_id = state.status.operation.as_ref().unwrap().id.clone();
        state.unknown(); valid(&state);
        assert_eq!(state.status.operation.as_ref().unwrap().id, running_id);
        settle(&mut state, result(), at, at, true);
        assert_eq!(state.status.session.as_ref().unwrap().state, SessionState::CleanupUnknown);
        assert_eq!(state.status.capability.reason, Reason::CleanupUnknown);
        assert_ne!(state.status.account.state, FactState::Observed);
        state.disconnect("github-session-1", at, Reason::None).unwrap(); valid(&state);
        assert!(state.unknown); assert!(state.status.session.is_some());
        assert!(state.material_settled()); // This supplied fixture had no native originals.
    }
    #[test]
    fn later_unknown_uses_reserved_identity_without_rewriting_terminal_operations() {
        let at = Instant::now();
        for terminal in [Reason::None, Reason::Expired, Reason::ResponseInvalid] {
            let mut state = fixture(at);
            let mut value = result();
            if terminal == Reason::ResponseInvalid { value.control.reason = terminal; }
            settle(&mut state, value, at, at, false);
            if terminal == Reason::Expired { state.reconcile(at + LIFETIME, Reason::None); }
            let completed = state.status.operation.clone().unwrap();
            let original_end = state.private.as_ref().unwrap().clock.end;
            assert_eq!(completed.phase, Phase::Settled); assert_eq!(completed.reason, terminal);

            state.unknown(); valid(&state);
            let unknown = state.status.operation.as_ref().unwrap();
            assert_ne!(unknown.id, completed.id);
            assert_eq!(unknown.id, "github-unknown-1");
            assert_eq!(unknown.kind, OperationKind::Disconnect);
            assert_eq!(unknown.phase, Phase::CleanupUnknown);
            assert_eq!(unknown.reason, Reason::CleanupUnknown);
            let retained = state.snapshot();
            state.unknown(); state.reconcile(at + LIFETIME, Reason::None);
            assert_eq!(state.snapshot(), retained);
            // Supplied final DATA only: not a forged native ticket/close proof.
            settle(&mut state, result(), at, at + LIFETIME, true);
            assert_eq!(state.snapshot(), retained);
            assert_eq!(state.private.as_ref().unwrap().clock.end, original_end);
            assert!(state.material_settled()); assert!(state.unknown);
        }
    }
    #[test]
    fn supplied_retirement_preserves_running_identity_until_final_data() {
        let at = Instant::now();
        for reason in [Reason::Expired, Reason::Cancelled, Reason::TargetChanged] {
            let mut state = fixture(at);
            // Finite projection DATA for an already-retiring read. This does
            // not exercise stop/wait/pipe custody, which needs native evidence.
            state.private.as_mut().unwrap().retirement = Some(reason);
            state.status.session.as_mut().unwrap().state = SessionState::Disconnecting;
            state.status.operation = Some(Operation { id: "github-disconnect-1".into(), kind: OperationKind::Disconnect,
                phase: Phase::Running, reason: Reason::None });
            state.fact_retirement(reason); state.capability(at, Reason::None); valid(&state);
            let running = state.status.operation.clone().unwrap();
            assert!(state.private.as_ref().unwrap().token.is_some());
            settle(&mut state, result(), at, at, false);
            let completed = state.status.operation.as_ref().unwrap();
            assert_eq!(completed.id, running.id); assert_eq!(completed.kind, running.kind);
            assert_eq!(completed.phase, Phase::Settled); assert_eq!(completed.reason, reason);
            assert_eq!(state.status.session.as_ref().unwrap().state,
                if reason == Reason::Expired { SessionState::Expired } else { SessionState::Failed });
            assert!(!state.status.capability.read_only_session_available);
            assert!(state.private.as_ref().unwrap().token.is_none());
        }
    }
    #[test]
    fn rejected_private_fact_veto_retires_only_after_supplied_final_receipt() {
        let at = Instant::now();
        for reason in ["unauthorized", "target-changed", "response-invalid", "rate-limited"] {
            let mut state = fixture(at); settle(&mut state, result(), at, at, false);
            refresh_data(&mut state);
            let before = state.snapshot();
            let unavailable = |reason: &str| serde_json::json!({"state":"unavailable", "value":null, "observedAt":null, "reason":reason});
            let frame = serde_json::json!({"protocol":wire::PRIVATE_PROTOCOL, "id":"original-data-2",
                "facts":{"schemaVersion":1,"account":unavailable(reason),"repository":unavailable("cancelled"),"automation":unavailable("cancelled")},
                "control":{"reason":"forbidden","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false}});
            let mut bytes = serde_json::to_vec(&frame).unwrap(); bytes.push(b'\n');
            let decoded = wire::decode_private_response("original-data-2", &bytes);
            assert!(decoded.is_err());
            assert_eq!(state.snapshot(), before); assert!(state.private.as_ref().unwrap().token.is_some());
            state.accept_final(decoded, at, false, at);
            state.capability(at, Reason::None); state.finish(before); valid(&state);
            assert_eq!(state.status.operation.as_ref().unwrap().phase, Phase::Settled);
            assert_eq!(state.status.operation.as_ref().unwrap().reason, Reason::ResponseInvalid);
            assert_eq!(state.status.session.as_ref().unwrap().state, SessionState::Failed);
            assert!(!state.status.capability.read_only_session_available);
            assert!(state.private.as_ref().unwrap().token.is_none());
            assert_eq!(state.cooldown, None); // No selected-field salvage.
        }
    }
    #[test]
    fn expiry_retires_under_a_distinct_operation_and_never_resurrects() {
        let at = Instant::now(); let mut state = fixture(at); settle(&mut state, result(), at, at, false);
        let completed = state.status.operation.clone().unwrap();
        state.reconcile(at + LIFETIME, Reason::None); valid(&state);
        assert_eq!(completed.reason, Reason::None); assert_ne!(state.status.operation.as_ref().unwrap().id, completed.id);
        assert_eq!(state.status.session.as_ref().unwrap().state, SessionState::Expired);
        let expired = state.snapshot();
        state.retire(Reason::TargetChanged); state.reconcile(at + LIFETIME + Duration::from_secs(1), Reason::None);
        assert_eq!(state.snapshot(), expired);
        state.disconnect("github-session-1", at + LIFETIME, Reason::None).unwrap(); valid(&state); assert!(state.status.session.is_none());
    }
    #[test]
    fn revision_exhaustion_has_one_redacted_nonwrapping_final_snapshot() {
        let at = Instant::now(); let mut state = fixture(at); settle(&mut state, result(), at, at, false);
        state.status.revision = u32::MAX - 1;
        assert!(state.room().is_err()); valid(&state);
        let final_status = state.snapshot(); assert_eq!(final_status.revision, u32::MAX); assert!(final_status.session.is_none());
        state.reconcile(at + LIFETIME, Reason::None); state.unknown();
        assert_eq!(state.snapshot(), final_status); assert!(state.exhausted); assert!(state.material_settled());
    }
    #[test]
    fn helper_work_deadline_is_not_credential_expiry_or_fresh_account_evidence() {
        let at = Instant::now(); let mut state = fixture(at); let mut value = result();
        value.control.reason = Reason::Expired;
        value.facts.account = unavailable(Reason::Expired); value.facts.repository = unavailable(Reason::Cancelled); value.facts.automation = unavailable(Reason::Cancelled);
        settle(&mut state, value, at, at, false);
        assert_eq!(state.status.operation.as_ref().unwrap().reason, Reason::NetworkUnavailable);
        assert_eq!(state.status.session.as_ref().unwrap().state, SessionState::Failed);
        assert_eq!(state.status.account.reason, Reason::NetworkUnavailable);
        assert!(state.private.as_ref().unwrap().token.is_some()); assert_eq!(state.private.as_ref().unwrap().clock.end, at + LIFETIME);
        assert!(retryable(state.status.operation.as_ref().unwrap().reason));
    }
    #[test]
    fn preflight_terminal_data_keeps_original_session_after_disconnect_without_credential() {
        // Supplied terminal DATA, no native ticket, run or cleanup receipt.
        use crate::github_preflight_protocol as p;
        let at = Instant::now(); let mut state = fixture(at); settle(&mut state, result(), at, at, false);
        state.preflight.view.session_id = Some("github-session-1".into());
        state.preflight.view.operation = Some(p::Operation { id: "preflight-original".into(), kind: p::Kind::Prepare,
            phase: p::Phase::Settled, reason: p::Reason::Cancelled, effect: p::Effect::None });
        let original = state.preflight.view.operation.clone();
        state.disconnect("github-session-1", at, Reason::None).unwrap();
        let retained = state.preflight_status(false, at, Reason::None);
        assert!(state.private.is_none() && state.material_settled());
        assert_eq!(retained.session_id.as_deref(), Some("github-session-1"));
        assert_eq!(retained.operation, original); assert!(!retained.available);
        assert!(!serde_json::to_string(&retained).unwrap().contains("INERT_NOT_A_CREDENTIAL"));
    }
    #[test]
    fn release_terminal_data_keeps_original_session_without_restoring_consent_or_token() {
        use crate::github_release_protocol as p;
        let at = Instant::now(); let mut state = fixture(at); settle(&mut state, result(), at, at, false);
        state.release.view.session_id = Some("github-session-1".into());
        state.release.view.operation = Some(p::Operation { id: "release-original".into(), kind: p::Kind::Dispatch,
            phase: p::Phase::Settled, reason: p::Reason::NetworkUnavailable, effect: p::Effect::PotentiallyApplied });
        let original = state.release.view.operation.clone();
        state.disconnect("github-session-1", at, Reason::None).unwrap();
        let retained = state.release_status(false, at, Reason::None);
        assert!(state.private.is_none() && state.material_settled());
        assert_eq!(retained.session_id.as_deref(), Some("github-session-1"));
        assert_eq!(retained.operation, original); assert!(!retained.available);
        assert!(retained.prepared.is_none() && state.release.consent.is_none());
        assert!(!serde_json::to_string(&retained).unwrap().contains("INERT_NOT_A_CREDENTIAL"));
    }
}
fn display_utc(time: SystemTime) -> Option<String> {
    let seconds = time.duration_since(UNIX_EPOCH).ok()?.as_secs();
    let mut days = seconds / 86400;
    let mut year = 1970;
    while year <= 9999 {
        let count = if leap(year) { 366 } else { 365 };
        if days < count { break; } days -= count; year += 1;
    }
    if year > 9999 { return None; }
    let mut month = 1;
    while days >= u64::from(month_days(year, month)) { days -= u64::from(month_days(year, month)); month += 1; }
    let remainder = seconds % 86400;
    Some(format!("{year:04}-{month:02}-{:02}T{:02}:{:02}:{:02}Z", days + 1, remainder / 3600, remainder / 60 % 60, remainder % 60))
}

// No Debug/Clone/Serialize on private material. Dropping a ticket never stops
// its owner; we retain it until its actual Settled variant has been consumed.
struct PrivateSession {
    id: String, project_id: String, repository: String, generation: u32, stop_id: String, unknown_id: String,
    clock: CredentialClock, token: Option<Secret>, account_pin: Option<String>, repository_pin: Option<String>,
    ticket: Option<GitHubReadTicket>, device: Option<DeviceAuthorization>, retirement: Option<Reason>, remove_after_settlement: bool,
    inspection: Option<crate::github_environment_metadata::Selection>,
}
impl PrivateSession {
    fn original_pending(&self) -> bool { self.ticket.is_some() || self.device.as_ref().is_some_and(|v| v.ticket.is_some()) }
    fn authorization_expired(&self, now: Instant) -> bool { self.device.as_ref().is_some_and(|v| now >= v.end) }
}
// One retained phase in the existing private session, not a second owner. Waiting
// has no native worker but still conflicts with other document actions.
struct DeviceAuthorization {
    end: Instant, code: Option<Secret>, interval: u32, next_poll: Option<Instant>, polls: u32,
    ticket: Option<GitHubDeviceTicket>, checking_access: bool,
}
impl DeviceAuthorization {
    fn poll_due(&self, now: Instant) -> Result<bool, Reason> {
        if self.next_poll.is_none_or(|next| now < next) { return Ok(false); }
        if self.polls >= device::POLL_LIMIT { return Err(Reason::ResponseLimit); }
        Ok(true)
    }
}
pub(crate) struct ConnectionState {
    status: Status, private: Option<PrivateSession>, next_session: u32,
    cooldown: Option<Instant>, cooldown_blocked: bool, unknown: bool, exhausted: bool, device_profile_available: bool,
    preflight: crate::github_preflight_session::State,
    release: crate::github_release_session::State,
    input: crate::github_input_group_session::State,
}
impl ConnectionState {
    pub(crate) fn new() -> Self {
        Self { status: empty_status(1, Reason::Unqualified), private: None, next_session: 0,
            cooldown: None, cooldown_blocked: false, unknown: false, exhausted: false, device_profile_available: false,
            preflight: crate::github_preflight_session::State::new(), release: crate::github_release_session::State::new(),
            input: crate::github_input_group_session::State::new() }
    }
    pub(crate) fn snapshot(&self) -> Status { self.status.clone() }
    pub(crate) fn registration(&self) -> Option<(&str, u32)> {
        self.private.as_ref().map(|s| (s.project_id.as_str(), s.generation))
    }
    pub(crate) fn material_settled(&self) -> bool {
        if !self.input.material_settled() { return false; }
        self.private.as_ref().is_none_or(|s| s.token.is_none() && s.ticket.is_none() && s.device.is_none()) && !self.preflight.native_work_pending() && !self.release.native_work_pending() && !self.input.native_work_pending()
    }
    pub(crate) fn native_work_pending(&self) -> bool { self.private.as_ref().is_some_and(|s| s.ticket.is_some() || s.device.is_some()) || self.preflight.native_work_pending() || self.release.native_work_pending() || self.input.native_work_pending() }
    fn fact_retirement(&mut self, reason: Reason) {
        stale(&mut self.status.account, reason); stale(&mut self.status.repository, reason); stale(&mut self.status.automation, reason);
        if let Some(metadata) = &mut self.status.input_metadata { metadata.stale(reason); }
        self.revoke_input_runner(crate::github_input_group_session::connection_reason(reason));
    }
    fn finish(&mut self, before: Status) {
        let flags = self.status.input_metadata.as_ref().map_or(("not-run", "not-run", "not-run"), |v| v.flags());
        self.status.facts.environment_observation = flags.0.into();
        self.status.facts.secret_observation = flags.1.into();
        self.status.facts.variable_observation = flags.2.into();
        if self.exhausted { self.status = empty_status(u32::MAX, Reason::Unqualified); return; }
        if self.status != before {
            if let Some(next) = before.revision.checked_add(1).filter(|v| *v < u32::MAX) { self.status.revision = next; }
            else { self.exhaust(); }
        }
    }
    fn room(&mut self) -> Result<(), BridgeError> {
        if self.input.retirement_pending() { return Err(refused(Reason::Busy)); }
        if self.exhausted || self.preflight.exhausted || self.release.exhausted || self.input.exhausted || self.status.revision >= u32::MAX - 1 { self.exhaust(); return Err(refused(Reason::CleanupUnknown)); }
        if self.unknown { return Err(refused(Reason::CleanupUnknown)); } Ok(())
    }
    pub(crate) fn exhaust(&mut self) {
        self.exhausted = true; self.unknown = true;
        self.retire_inner(Reason::CleanupUnknown, false);
        self.status = empty_status(u32::MAX, Reason::Unqualified);
    }
    pub(crate) fn unknown(&mut self) {
        let before = self.status.clone(); self.unknown_inner(); self.finish(before);
    }
    fn unknown_inner(&mut self) {
        self.unknown = true;
        self.preflight.unknown(); self.release.unknown(); self.input.unknown();
        self.unknown_operation();
        self.retire_inner(Reason::CleanupUnknown, false);
        if let Some(session) = &mut self.status.session {
            session.state = SessionState::CleanupUnknown;
            self.status.capability.read_only_session_available = false; self.status.capability.reason = Reason::CleanupUnknown;
            self.fact_retirement(Reason::CleanupUnknown);
        } else {
            self.status.capability.read_only_session_available = false; self.status.capability.reason = Reason::RuntimeUnavailable;
        }
    }
    fn unknown_operation(&mut self) {
        let (Some(private), Some(operation)) = (&self.private, &mut self.status.operation) else { return; };
        // A published terminal receipt is immutable. Reserve this separate
        // identity before Connect admission, rather than minting replacement
        // operations on repeated Unknown or rewriting an earlier settlement.
        if operation.phase == Phase::Settled {
            operation.id = private.unknown_id.clone(); operation.kind = OperationKind::Disconnect;
        }
        operation.phase = Phase::CleanupUnknown; operation.reason = Reason::CleanupUnknown;
    }
    pub(crate) fn retire(&mut self, reason: Reason) {
        let before = self.status.clone(); self.retire_inner(reason, false); self.finish(before);
    }
    fn retire_inner(&mut self, reason: Reason, remove: bool) {
        self.preflight.stop(); self.release.stop(); self.input.stop();
        self.status.authorization = None;
        let Some(private) = &mut self.private else { return; };
        private.remove_after_settlement |= remove;
        let first = private.retirement.is_none();
        if first { private.retirement = Some(reason); }
        if let Some(ticket) = &private.ticket { ticket.stop(); }
        if let Some(auth) = &mut private.device {
            auth.code = None; auth.next_poll = None;
            if let Some(ticket) = &auth.ticket { ticket.stop(); }
        }
        if !self.unknown && (first || remove && self.status.operation.as_ref().is_none_or(|op| op.kind != OperationKind::Disconnect)) {
            self.status.operation = Some(Operation { id: private.stop_id.clone(), kind: OperationKind::Disconnect,
                phase: Phase::Running, reason: Reason::None });
        }
        let reason = private.retirement.unwrap_or(reason);
        if let Some(session) = &mut self.status.session { session.state = if self.unknown { SessionState::CleanupUnknown } else { SessionState::Disconnecting }; }
        self.fact_retirement(if self.unknown { Reason::CleanupUnknown } else { reason });
        if self.private.as_ref().is_some_and(|s| !s.original_pending()) && !self.preflight.native_work_pending() && !self.release.native_work_pending() && !self.input.native_work_pending() { self.complete_retirement(); }
    }
    fn complete_retirement(&mut self) {
        let Some(private) = &mut self.private else { return; };
        if private.original_pending() || self.preflight.native_work_pending() || self.release.native_work_pending() || self.input.native_work_pending() { return; }
        private.token = None; private.device = None; self.status.authorization = None;
        if self.unknown {
            if let Some(session) = &mut self.status.session { session.state = SessionState::CleanupUnknown; }
            self.unknown_operation();
            return;
        }
        if private.remove_after_settlement {
            self.private = None; self.status = empty_status(self.status.revision, self.status.capability.reason); return;
        }
        let reason = private.retirement.unwrap_or(Reason::Cancelled);
        if let Some(session) = &mut self.status.session { session.state = if reason == Reason::Expired { SessionState::Expired } else { SessionState::Failed }; }
        if let Some(op) = &mut self.status.operation {
            if op.phase == Phase::Running { op.phase = Phase::Settled; op.reason = reason; }
        }
    }
    fn apply_control(&mut self, control: &GitHubReadControl, original_at: Instant) -> bool {
        // Independent read limits survive disconnect, token replacement and a
        // response-invalid expiry policy. The caller supplies the original read
        // control Instant; a later status poll must never move that endpoint.
        self.cooldown_blocked |= control.cooldown_blocked;
        if let Some(seconds) = control.cooldown_seconds {
            match original_at.checked_add(Duration::from_secs(u64::from(seconds))) {
                Some(end) => self.cooldown = Some(self.cooldown.map_or(end, |old| old.max(end))),
                None => self.cooldown_blocked = true,
            }
        }
        let mut shortened=false;
        if let Some(timestamp) = &control.credential_expires_at {
            let Some(private) = &mut self.private else { return false; };
            let end=private.clock.end;
            if !private.clock.shorten(timestamp) { return false; }
            shortened=private.clock.end<end;
            if let Some(session) = &mut self.status.session { session.expires_at = Some(private.clock.display.clone()); }
        }
        // A changed credential/control retires old runner authority. The
        // current runner read has already cleared its predecessor; do not
        // cancel it merely because its own refusal/control arrived early.
        if self.input.runner.observation.is_some() && (shortened || control.reason!=Reason::None
            || control.cooldown_blocked || control.cooldown_seconds.is_some()) {
            self.revoke_input_runner(if shortened {crate::github_input_group_protocol::Reason::Expired}
                else if control.reason!=Reason::None {crate::github_input_group_session::connection_reason(control.reason)}
                else {crate::github_input_group_protocol::Reason::RateLimited});
        }
        true
    }
    fn capability(&mut self, now: Instant, external: Reason) {
        let reason = if self.unknown {
            if self.status.session.is_some() { Reason::CleanupUnknown } else { Reason::RuntimeUnavailable }
        } else if external != Reason::None { external }
        else if self.cooldown_blocked || self.cooldown.is_some_and(|end| now < end) { Reason::RateLimited }
        else if self.native_work_pending() { Reason::Busy }
        else if let Some(reason) = self.private.as_ref().and_then(|s| s.retirement) { reason }
        else { Reason::None };
        self.status.capability.reason = reason; self.status.capability.read_only_session_available = reason == Reason::None;
        self.status.capability.publisher_name = device::publisher().map(|p| p.display_name.clone());
        self.status.capability.device_login = if device::publisher().is_none() { DeviceLogin::PublisherUnconfigured }
            else if self.device_profile_available { DeviceLogin::Available } else { DeviceLogin::NotQualified };
    }
    /// Observe only the ORIGINAL mailbox and fixed clocks. No inspection,
    /// network, spawn, timer, join replacement or callback into the document.
    pub(crate) fn reconcile(&mut self, now: Instant, external: Reason) {
        let before = self.status.clone();
        if self.private.as_ref().is_some_and(|s| s.retirement.is_none() && (now >= s.clock.end || s.authorization_expired(now))) { self.retire_inner(Reason::Expired, false); }
        self.consume_device_original(now, external);
        let receipt = self.private.as_ref().and_then(|s| s.ticket.as_ref()).map(GitHubReadTicket::receipt);
        match receipt {
            Some(GitHubReadReceipt::RetainedUnknown) => self.unknown_inner(),
            Some(GitHubReadReceipt::Settled { outcome, settled_at, was_unknown }) => {
                let retiring = self.private.as_ref().is_some_and(|s| s.retirement.is_some());
                // A pending quit question can delay positive publication; Cancel
                // does not destroy the earlier connection or extend any clock.
                if external == Reason::None || retiring || self.unknown || was_unknown {
                    self.accept_final(outcome, settled_at, was_unknown, now);
                }
            },
            Some(GitHubReadReceipt::Pending) | None => {},
        }
        self.reconcile_preflight(now, external); self.reconcile_release(now, external); self.reconcile_runner(now,external); self.reconcile_input(now,external);
        self.capability(now, external); self.finish(before);
    }
    fn accept_final(&mut self, mut result: Result<GitHubReadOutcome, BridgeError>, settled_at: Instant, was_unknown: bool, now: Instant) {
        // This function is reached only via the actual Settled mailbox above.
        // It is also tested with explicitly supplied DATA, not a mock OS proof.
        let Some(private) = &mut self.private else { return; }; private.ticket = None;
        let expected_inspection = private.inspection.take();
        let mut reason = result.as_ref().map_or_else(outcome_error, |v| v.control.reason);
        if let Ok(outcome) = &result { if !self.apply_control(&outcome.control, settled_at) { reason = Reason::ResponseInvalid; } }
        if was_unknown || reason == Reason::CleanupUnknown || self.unknown { self.unknown_inner(); return; }
        if self.private.as_ref().is_some_and(|s| s.retirement.is_some()) { self.complete_retirement(); return; }
        if self.private.as_ref().is_some_and(|s| now >= s.clock.end || s.authorization_expired(now)) { self.retire_inner(Reason::Expired, false); return; }
        // The final identity bracket settles the SAME public Authorize. Its
        // local original deadline has already been checked above, before release.
        if let Some(private) = &mut self.private { private.device = None; }
        self.status.authorization = None;
        if reason == Reason::Expired {
            reason = Reason::NetworkUnavailable;
            if let Ok(outcome) = &mut result {
                for fact_reason in [&mut outcome.facts.account.reason, &mut outcome.facts.repository.reason, &mut outcome.facts.automation.reason] {
                    if *fact_reason == Reason::Expired { *fact_reason = Reason::NetworkUnavailable; }
                }
                if let Some(metadata) = &mut outcome.metadata {
                    for reason in [&mut metadata.environment.reason, &mut metadata.field.reason] {
                        if *reason == Reason::Expired { *reason = Reason::NetworkUnavailable; }
                    }
                }
            }
        }
        if result.as_ref().is_ok_and(|v| v.metadata.as_ref().map(|v| &v.selection) != expected_inspection.as_ref()) {
            reason = Reason::ResponseInvalid;
        }
        let mismatch = result.as_ref().is_ok_and(|v| {
            self.private.as_ref().is_some_and(|s|
                v.facts.account.value.as_ref().is_some_and(|v| s.account_pin.as_ref().is_some_and(|pin| pin != &v.id))
                || v.facts.repository.value.as_ref().is_some_and(|v| !v.full_name.eq_ignore_ascii_case(&s.repository)
                    || s.repository_pin.as_ref().is_some_and(|pin| pin != &v.id)))
        });
        if mismatch { reason = Reason::TargetChanged; }
        if let Some(op) = &mut self.status.operation { op.phase = Phase::Settled; op.reason = reason; }
        if retires(reason) {
            if let Some(private) = &mut self.private { private.retirement = Some(reason); }
            self.fact_retirement(reason); self.complete_retirement(); return;
        }
        match result {
            Ok(outcome) => {
                self.accept_facts(outcome.facts);
                if let Some(metadata) = outcome.metadata { self.status.input_metadata = Some(metadata); }
            },
            Err(_) => self.fact_retirement(reason),
        }
        if let Some(session) = &mut self.status.session {
            session.state = if self.status.account.state == FactState::Observed { SessionState::Connected } else { SessionState::Failed };
            if session.state == SessionState::Failed && self.status.operation.as_ref().is_some_and(|op| op.kind == OperationKind::Authorize) {
                if let Some(private) = &mut self.private { private.retirement = Some(reason); }
                self.complete_retirement();
            }
        }
    }
    fn accept_facts(&mut self, facts: GitHubReadFacts) {
        if let Some(private) = &mut self.private {
            if private.account_pin.is_none() { private.account_pin = facts.account.value.as_ref().map(|v| v.id.clone()); }
            if private.repository_pin.is_none() { private.repository_pin = facts.repository.value.as_ref().map(|v| v.id.clone()); }
        }
        self.status.account = merge(std::mem::replace(&mut self.status.account, unobserved()), facts.account);
        self.status.repository = merge(std::mem::replace(&mut self.status.repository, unobserved()), facts.repository);
        self.status.automation = merge(std::mem::replace(&mut self.status.automation, unobserved()), facts.automation);
        if self.status.account.value.is_none() {
            self.status.repository = unavailable(self.status.account.reason); self.status.automation = unavailable(self.status.account.reason);
        } else if self.status.account.state != FactState::Observed {
            stale(&mut self.status.repository, self.status.account.reason); stale(&mut self.status.automation, self.status.account.reason);
        }
        if self.status.repository.value.is_none() { self.status.automation = unavailable(self.status.repository.reason); }
        else if self.status.repository.state != FactState::Observed { stale(&mut self.status.automation, self.status.repository.reason); }
    }
    pub(crate) fn connect(&mut self, args: ConnectTokenArgs, generation: u32, supervisor: &Supervisor,
        now: Instant, wall: SystemTime) -> Result<Status, BridgeError> {
        self.room()?;
        if self.private.is_some() { return Err(refused(Reason::Busy)); }
        if !self.status.capability.read_only_session_available { return Err(refused(self.status.capability.reason)); }
        let Some(sequence) = self.next_session.checked_add(1) else { self.exhaust(); return Err(refused(Reason::CleanupUnknown)); };
        let clock = CredentialClock::new(now, wall).ok_or_else(|| refused(Reason::RuntimeUnavailable))?;
        // Allocate private/session/stop/unknown metadata before synchronous
        // admission. No fallible decode or registration follows ticket creation.
        let id = format!("github-session-{sequence}");
        let session = Session { id: id.clone(), project_id: args.project_id.clone(), target_repository: args.repository.clone(),
            state: SessionState::Checking, expires_at: Some(clock.display.clone()) };
        let mut private = PrivateSession { id, project_id: args.project_id, repository: args.repository,
            generation, stop_id: format!("github-disconnect-{sequence}"), unknown_id: format!("github-unknown-{sequence}"),
            clock, token: Some(Secret::new(args.token)),
            account_pin: None, repository_pin: None, ticket: None, device: None, retirement: None, remove_after_settlement: false, inspection: None };
        let mut operation = Operation { id: String::with_capacity(64), kind: OperationKind::Connect, phase: Phase::Running, reason: Reason::None };
        let ticket = supervisor.start_github_readonly(&private.repository, None, None,
            private.token.as_deref().ok_or_else(|| refused(Reason::InvalidInput))?).map_err(admission_error)?;
        operation.id.push_str(ticket.operation_id());
        private.ticket = Some(ticket);
        self.private = Some(private); self.next_session = sequence;
        let preflight_before = self.preflight.snapshot();
        self.preflight.revoke_consent(); self.preflight.view.pending.clear(); self.preflight.view.run = None;
        self.preflight.view.operation = None; self.preflight.view.session_id = None;
        self.preflight.finish(preflight_before);
        let release_before = self.release.snapshot();
        self.release.revoke_consent(); self.release.view.pending.clear(); self.release.view.run = None;
        self.release.view.operation = None; self.release.view.session_id = None;
        self.input.reset_session_view();
        self.release.finish(release_before);
        self.revoke_input_material();
        let before = self.status.clone();
        self.status.session = Some(session); self.status.operation = Some(operation); self.status.authorization = None;
        self.status.account = unobserved(); self.status.repository = unobserved(); self.status.automation = unobserved(); self.status.input_metadata = None;
        self.capability(now, Reason::None); self.finish(before); Ok(self.snapshot())
    }
    pub(crate) fn refresh(&mut self, id: &str, revision: u32, supervisor: &Supervisor, now: Instant) -> Result<Status, BridgeError> {
        self.refresh_selected(id, revision, supervisor, now, None)
    }
    pub(crate) fn inspect(&mut self, args: wire::InspectArgs, supervisor: &Supervisor, now: Instant) -> Result<Status, BridgeError> {
        let selection = crate::github_environment_metadata::Selection { stage: args.stage, name: args.name };
        if !selection.valid() { return Err(refused(Reason::InvalidInput)); }
        self.refresh_selected(&args.session_id, args.expected_revision, supervisor, now, Some(selection))
    }
    fn refresh_selected(&mut self, id: &str, revision: u32, supervisor: &Supervisor, now: Instant,
        selection: Option<crate::github_environment_metadata::Selection>) -> Result<Status, BridgeError> {
        self.room()?;
        if revision != self.status.revision { return Err(refused(Reason::TargetChanged)); }
        let private = self.private.as_ref().filter(|s| s.id == id).ok_or_else(|| refused(Reason::InvalidInput))?;
        if private.ticket.is_some() || private.device.is_some() || self.preflight.native_work_pending() || self.release.native_work_pending() || self.input.native_work_pending() { return Err(refused(Reason::Busy)); }
        if let Some(reason) = private.retirement { return Err(refused(reason)); }
        if !self.status.capability.read_only_session_available { return Err(refused(self.status.capability.reason)); }
        if now >= private.clock.end { self.retire(Reason::Expired); return Err(refused(Reason::Expired)); }
        let allowed = self.status.session.as_ref().is_some_and(|s| s.state == SessionState::Connected
            || s.state == SessionState::Failed && self.status.operation.as_ref().is_some_and(|op| op.kind != OperationKind::Authorize && op.phase == Phase::Settled && retryable(op.reason)));
        if !allowed { return Err(refused(Reason::InvalidInput)); }
        if selection.is_some() && (private.account_pin.is_none() || private.repository_pin.is_none()
            || self.status.account.state != FactState::Observed || self.status.repository.state != FactState::Observed) {
            return Err(refused(Reason::InvalidInput));
        }
        let mut operation = Operation { id: String::with_capacity(64),
            kind: if selection.is_some() { OperationKind::Inspect } else { OperationKind::Refresh },
            phase: Phase::Running, reason: Reason::None };
        let token = private.token.as_deref().ok_or_else(|| refused(Reason::Expired))?;
        let ticket = if let Some(selection) = &selection {
            supervisor.start_github_metadata(&private.repository, private.account_pin.as_deref(), private.repository_pin.as_deref(),
                token, selection, private.clock.end)
        } else {
            supervisor.start_github_readonly(&private.repository, private.account_pin.as_deref(), private.repository_pin.as_deref(), token)
        }.map_err(admission_error)?;
        let preflight_before = self.preflight.snapshot(); self.preflight.revoke_consent(); self.preflight.finish(preflight_before);
        let release_before = self.release.snapshot(); self.release.revoke_consent(); self.release.finish(release_before);
        self.revoke_input_material();
        operation.id.push_str(ticket.operation_id());
        // There is no await or callback between the recheck and storing the
        // exact original ticket in this same document-owned state.
        if let Some(private) = &mut self.private { private.ticket = Some(ticket); private.inspection = selection; }
        let before = self.status.clone();
        self.status.operation = Some(operation);
        if let Some(session) = &mut self.status.session { session.state = SessionState::Checking; }
        self.fact_retirement(Reason::Stale); self.capability(now, Reason::None); self.finish(before); Ok(self.snapshot())
    }
    pub(crate) fn disconnect(&mut self, id: &str, now: Instant, external: Reason) -> Result<Status, BridgeError> {
        if !self.private.as_ref().is_some_and(|s| s.id == id) { return Err(refused(Reason::InvalidInput)); }
        let before = self.status.clone();
        self.retire_inner(Reason::Cancelled, true); self.capability(now, external); self.finish(before);
        Ok(self.snapshot())
    }
}

// The shell's existing relay observes first, then separately drives one due
// device step. None of these methods creates a second timer/task/credential owner.
impl ConnectionState {
    pub(crate) fn observe_device_capability(&mut self, supervisor: &Supervisor) {
        let before = self.status.clone();
        self.device_profile_available = qualified_for(supervisor) && supervisor.github_device_profile_available();
        self.status.capability.publisher_name = device::publisher().map(|p| p.display_name.clone());
        self.status.capability.device_login = if device::publisher().is_none() { DeviceLogin::PublisherUnconfigured }
            else if self.device_profile_available { DeviceLogin::Available } else { DeviceLogin::NotQualified };
        self.finish(before);
    }
    pub(crate) fn begin_device(&mut self, args: StartDeviceArgs, generation: u32, supervisor: &Supervisor,
        now: Instant, wall: SystemTime) -> Result<Status, BridgeError> {
        self.room()?;
        if self.private.is_some() { return Err(refused(Reason::Busy)); }
        let publisher = device::publisher().ok_or_else(|| refused(Reason::PublisherUnconfigured))?;
        if self.status.capability.device_login != DeviceLogin::Available || !self.device_profile_available {
            return Err(refused(Reason::Unqualified));
        }
        if !self.status.capability.read_only_session_available { return Err(refused(self.status.capability.reason)); }
        let Some(sequence) = self.next_session.checked_add(1) else { self.exhaust(); return Err(refused(Reason::CleanupUnknown)); };
        let clock = CredentialClock::new(now, wall).ok_or_else(|| refused(Reason::RuntimeUnavailable))?;
        let end = now.checked_add(Duration::from_secs(device::AUTHORIZATION_SECONDS)).ok_or_else(|| refused(Reason::RuntimeUnavailable))?.min(clock.end);
        let id = format!("github-session-{sequence}");
        let session = Session { id: id.clone(), project_id: args.project_id.clone(), target_repository: args.repository.clone(),
            state: SessionState::Checking, expires_at: Some(clock.display.clone()) };
        let mut private = PrivateSession { id, project_id: args.project_id, repository: args.repository, generation,
            stop_id: format!("github-disconnect-{sequence}"), unknown_id: format!("github-unknown-{sequence}"),
            clock, token: None, account_pin: None, repository_pin: None, ticket: None, inspection: None,
            device: Some(DeviceAuthorization { end, code: None, interval: 5, next_poll: None, polls: 0, ticket: None, checking_access: false }),
            retirement: None, remove_after_settlement: false };
        let operation = Operation { id: format!("github-authorize-{sequence}"), kind: OperationKind::Authorize, phase: Phase::Running, reason: Reason::None };
        let original = private.device.as_mut().ok_or_else(|| refused(Reason::InvalidInput))?;
        let ticket = supervisor.start_github_device(device::Step::Start, &publisher.client_id, None, end).map_err(admission_error)?;
        // Infallible integration after the SAME original Supervisor registered.
        original.ticket = Some(ticket);
        self.private = Some(private); self.next_session = sequence;
        let preflight_before = self.preflight.snapshot();
        self.preflight.revoke_consent(); self.preflight.view.pending.clear(); self.preflight.view.run = None;
        self.preflight.view.operation = None; self.preflight.view.session_id = None; self.preflight.finish(preflight_before);
        let release_before = self.release.snapshot();
        self.release.revoke_consent(); self.release.view.pending.clear(); self.release.view.run = None;
        self.release.view.operation = None; self.release.view.session_id = None;
        self.input.reset_session_view(); self.release.finish(release_before);
        self.revoke_input_material();
        let before = self.status.clone();
        self.status.session = Some(session); self.status.operation = Some(operation);
        self.status.authorization = Some(Authorization { phase: AuthorizationPhase::RequestingCode, user_code: None, expires_at: None });
        self.status.account = unobserved(); self.status.repository = unobserved(); self.status.automation = unobserved(); self.status.input_metadata = None;
        self.capability(now, Reason::None); self.finish(before); Ok(self.snapshot())
    }
    fn consume_device_original(&mut self, now: Instant, external: Reason) {
        let Some(ticket) = self.private.as_ref().and_then(|p| p.device.as_ref()).and_then(|a| a.ticket.as_ref()) else { return; };
        match ticket.state() {
            GitHubDeviceState::Pending => return,
            GitHubDeviceState::RetainedUnknown => { self.unknown_inner(); return; },
            GitHubDeviceState::Settled { was_unknown } => {
                if external != Reason::None && !self.unknown && !was_unknown
                    && self.private.as_ref().is_some_and(|p| p.retirement.is_none()) { return; }
            },
        }
        let step = ticket.step(); let started_at = ticket.started_at();
        let result = ticket.take_settled(); // One consuming mailbox read, never Clone or Debug.
        if let Some(auth) = self.private.as_mut().and_then(|p| p.device.as_mut()) { auth.ticket = None; }
        let Some(result) = result else { self.unknown_inner(); return; };
        self.accept_device_result(result.outcome, step, started_at, result.settled_at, result.was_unknown, now);
    }
    fn accept_device_result(&mut self, result: Result<device::Outcome, BridgeError>, step: device::Step,
        started_at: Instant, settled_at: Instant, was_unknown: bool, now: Instant) {
        // Production reaches this only after actual original retirement. Tests
        // supply DATA here; they do not manufacture a ticket or native receipt.
        if let Ok(device::Outcome::Failed { reason, cooldown_seconds, cooldown_blocked }) = &result {
            let control = GitHubReadControl { reason: *reason, credential_expires_at: None,
                cooldown_seconds: *cooldown_seconds, cooldown_blocked: *cooldown_blocked };
            self.apply_control(&control, settled_at);
        }
        if was_unknown || self.unknown || result.as_ref().is_err_and(|e| e.code == "cleanup_unknown") {
            self.unknown_inner(); return;
        }
        let Some(private) = self.private.as_ref() else { return; };
        if private.retirement.is_some() { self.complete_retirement(); return; }
        if now >= private.clock.end || private.authorization_expired(now) {
            self.retire_inner(Reason::Expired, false); return;
        }
        let outcome = match result { Ok(value) => value, Err(error) => { self.fail_device(outcome_error(&error)); return; } };
        if let Err(reason) = self.apply_device_result(outcome, step, started_at, settled_at) { self.fail_device(reason); }
        else if self.private.as_ref().is_some_and(|p| now >= p.clock.end || p.authorization_expired(now)) {
            self.retire_inner(Reason::Expired, false); // A shortened start/credential expiry is effective NOW.
        }
    }
    fn apply_device_result(&mut self, result: device::Outcome, step: device::Step,
        started_at: Instant, settled_at: Instant) -> Result<(), Reason> {
        let private = self.private.as_mut().ok_or(Reason::ResponseInvalid)?;
        let auth = private.device.as_mut().ok_or(Reason::ResponseInvalid)?;
        if auth.ticket.is_some() || private.ticket.is_some() || auth.checking_access { return Err(Reason::ResponseInvalid); }
        match result {
            device::Outcome::Code { device_code, user_code, expires_in, interval } if step == device::Step::Start
                && auth.code.is_none() && auth.next_poll.is_none() && auth.polls == 0 => {
                let end = started_at.checked_add(Duration::from_secs(u64::from(expires_in))).ok_or(Reason::ResponseInvalid)?.min(auth.end);
                let display = private.clock.display_end(end).ok_or(Reason::ResponseInvalid)?;
                let interval = interval.max(5);
                let next_poll = settled_at.checked_add(Duration::from_secs(u64::from(interval))).ok_or(Reason::ResponseInvalid)?;
                auth.end = end; auth.code = Some(device_code); auth.interval = interval; auth.next_poll = Some(next_poll);
                self.status.authorization = Some(Authorization { phase: AuthorizationPhase::Waiting,
                    user_code: Some(user_code), expires_at: Some(display) });
            },
            device::Outcome::Pending { interval } if step == device::Step::Poll && auth.code.is_some() && auth.next_poll.is_none() => {
                let interval = auth.interval.max(interval.unwrap_or(5)).max(5);
                let next_poll = settled_at.checked_add(Duration::from_secs(u64::from(interval))).ok_or(Reason::ResponseInvalid)?;
                auth.interval = interval; auth.next_poll = Some(next_poll);
                self.status.authorization.as_mut().ok_or(Reason::ResponseInvalid)?.phase = AuthorizationPhase::Waiting;
            },
            device::Outcome::SlowDown { interval } if step == device::Step::Poll && auth.code.is_some() && auth.next_poll.is_none() => {
                let interval = auth.interval.checked_add(5).ok_or(Reason::ResponseLimit)?.max(interval);
                let next_poll = settled_at.checked_add(Duration::from_secs(u64::from(interval))).ok_or(Reason::ResponseInvalid)?;
                auth.interval = interval; auth.next_poll = Some(next_poll);
                self.status.authorization.as_mut().ok_or(Reason::ResponseInvalid)?.phase = AuthorizationPhase::SlowDown;
            },
            device::Outcome::Token { token, expires_in } if step == device::Step::Poll && auth.code.is_some()
                && auth.next_poll.is_none() && private.token.is_none() => {
                if let Some(seconds) = expires_in {
                    if !private.clock.shorten_from(started_at, seconds) { return Err(Reason::ResponseInvalid); }
                }
                let public = self.status.authorization.as_mut().ok_or(Reason::ResponseInvalid)?;
                if public.expires_at.is_none() { return Err(Reason::ResponseInvalid); }
                // Move the original once into the EXISTING session credential slot.
                // Never publish a token or refresh credential to a renderer/event.
                private.token = Some(token); auth.code = None; auth.checking_access = true;
                public.phase = AuthorizationPhase::CheckingAccess; public.user_code = None;
                if let Some(session) = &mut self.status.session { session.expires_at = Some(private.clock.display.clone()); }
            },
            device::Outcome::Failed { reason, .. } => return Err(reason),
            _ => return Err(Reason::ResponseInvalid),
        }
        Ok(())
    }
    fn fail_device(&mut self, reason: Reason) {
        if reason == Reason::CleanupUnknown { self.unknown_inner(); return; }
        self.status.authorization = None;
        if let Some(operation) = &mut self.status.operation { operation.phase = Phase::Settled; operation.reason = reason; }
        if let Some(private) = &mut self.private { private.retirement = Some(reason); }
        self.fact_retirement(reason); self.complete_retirement();
    }
    pub(crate) fn advance_device_if_due(&mut self, supervisor: &Supervisor, now: Instant, external: Reason) {
        if external != Reason::None || self.private.as_ref().is_none_or(|p| p.device.is_none() || p.retirement.is_some()) { return; }
        let before = self.status.clone();
        if self.room().is_err() { return; }
        let Some(private) = &mut self.private else { return; };
        if now >= private.clock.end || private.authorization_expired(now) {
            self.retire_inner(Reason::Expired, false); self.capability(now, external); self.finish(before); return;
        }
        let Some(auth) = private.device.as_mut() else { return; };
        if auth.ticket.is_some() || private.ticket.is_some() { return; }
        let end = auth.end.min(private.clock.end);
        let error = if auth.checking_access {
            match private.token.as_deref() {
                Some(token) => match supervisor.start_github_readonly_until(&private.repository, token, end) {
                    Ok(ticket) => { private.ticket = Some(ticket); None }, Err(error) => Some(error),
                },
                None => Some(BridgeError::protocol()),
            }
        } else {
            match auth.poll_due(now) {
                Ok(false) => return, Ok(true) => {},
                Err(reason) => { self.fail_device(reason); self.capability(now, external); self.finish(before); return; },
            }
            match (device::publisher(), auth.code.as_deref()) {
                (Some(publisher), Some(code)) => match supervisor.start_github_device(device::Step::Poll, &publisher.client_id, Some(code), end) {
                    Ok(ticket) => { auth.ticket = Some(ticket); auth.polls += 1; auth.next_poll = None; None },
                    Err(error) => Some(error),
                },
                _ => Some(BridgeError::protocol()),
            }
        };
        if let Some(error) = error {
            // A pre-registration capacity refusal spends no send. All errors
            // AFTER an actual admission instead arrive via that original ticket;
            // a transport ambiguity never reaches this resumable capacity case.
            if error.code != "busy" { self.fail_device(outcome_error(&error)); }
        }
        self.capability(now, external); self.finish(before);
    }
    pub(crate) fn allow_device_page(&self, id: &str, revision: u32, now: Instant, external: Reason) -> Result<(), BridgeError> {
        if external != Reason::None { return Err(refused(external)); }
        if self.unknown || self.exhausted { return Err(refused(Reason::CleanupUnknown)); }
        if revision != self.status.revision { return Err(refused(Reason::TargetChanged)); }
        let private = self.private.as_ref().filter(|p| p.id == id && p.retirement.is_none()).ok_or_else(|| refused(Reason::TargetChanged))?;
        let auth = private.device.as_ref().filter(|a| !a.checking_access && a.code.is_some()).ok_or_else(|| refused(Reason::InvalidInput))?;
        if now >= auth.end || now >= private.clock.end { return Err(refused(Reason::Expired)); }
        if self.status.capability.device_login != DeviceLogin::Available || !self.status.authorization.as_ref().is_some_and(|a|
            matches!(a.phase, AuthorizationPhase::Waiting | AuthorizationPhase::SlowDown)) {
            return Err(refused(Reason::InvalidInput));
        }
        Ok(()) // Original synchronous claim; the caller hands off one fixed URL.
    }
}

// The action family shares THIS original session's token, monotonic endpoint,
// cooldown, registration and retirement. Its metadata module owns no credential.
impl ConnectionState {
    pub(crate) fn preflight_status(&mut self, qualified: bool, now: Instant, external: Reason) -> crate::github_preflight_protocol::Status {
        use crate::{github_preflight_protocol::Reason as R, github_preflight_session::connection_reason};
        let before = self.preflight.snapshot(); self.preflight.expire_consent(now);
        let reason = if self.unknown || self.exhausted || self.preflight.exhausted || self.release.exhausted || self.input.exhausted { R::CleanupUnknown }
            else if external != Reason::None { connection_reason(external) }
            else if !crate::github_preflight_protocol::publisher_bound() { R::PublisherUnconfigured }
            else if !qualified { R::Unqualified }
            else if self.native_work_pending() { R::Busy }
            else if let Some(private) = &self.private {
                if let Some(reason) = private.retirement { connection_reason(reason) }
                else if now >= private.clock.end { R::Expired }
                else if self.cooldown_blocked || self.cooldown.is_some_and(|end| now < end) { R::RateLimited }
                else if private.token.is_none() || private.account_pin.is_none() || private.repository_pin.is_none()
                    || self.status.account.state != FactState::Observed || self.status.repository.state != FactState::Observed
                    || !self.status.session.as_ref().is_some_and(|s| s.state == SessionState::Connected) { R::NotConnected }
                else { R::None }
            } else { R::NotConnected };
        self.preflight.view.available = reason == R::None; self.preflight.view.reason = reason;
        // Preserve the original terminal operation's nonsecret session binding
        // after retirement. Otherwise a lost admission reply followed by an
        // exact settled event could never be correlated by its original UI.
        // A fresh Connect already clears the old operation and session view.
        if let Some(private) = &self.private { self.preflight.view.session_id = Some(private.id.clone()); }
        else if self.preflight.view.operation.is_none() { self.preflight.view.session_id = None; }
        self.preflight.finish(before); self.preflight.snapshot()
    }
    fn preflight_context(&mut self, session_id: &str, revision: u32, generation: u32,
        project_binding: &str, now: Instant) -> Result<(String, crate::github_preflight_protocol::Scope), BridgeError> {
        use crate::{github_preflight_protocol as p, github_preflight_session as s};
        self.room().map_err(|_| s::refused(p::Reason::CleanupUnknown))?;
        if self.preflight.view.revision != revision { return Err(s::refused(p::Reason::TargetChanged)); }
        if self.native_work_pending() { return Err(s::refused(p::Reason::Busy)); }
        if !self.preflight.view.available { return Err(s::refused(self.preflight.view.reason)); }
        let private = self.private.as_ref().filter(|v| v.id == session_id && v.generation == generation)
            .ok_or_else(|| s::refused(p::Reason::TargetChanged))?;
        if now >= private.clock.end || private.token.is_none() || private.retirement.is_some() { return Err(s::refused(p::Reason::Expired)); }
        if self.cooldown_blocked || self.cooldown.is_some_and(|end| now < end) { return Err(s::refused(p::Reason::RateLimited)); }
        let repository = self.status.repository.value.as_ref().filter(|v| v.full_name.eq_ignore_ascii_case(&private.repository))
            .ok_or_else(|| s::refused(p::Reason::NotConnected))?;
        let scope = p::Scope { project_binding: project_binding.into(), repository: repository.full_name.clone(),
            account_id: private.account_pin.clone().ok_or_else(|| s::refused(p::Reason::NotConnected))?,
            repository_id: private.repository_pin.clone().ok_or_else(|| s::refused(p::Reason::NotConnected))? };
        if !scope.valid() { return Err(s::refused(p::Reason::InvalidInput)); }
        Ok((private.project_id.clone(), scope))
    }
    fn preflight_start(&mut self, request: crate::github_preflight_protocol::Request, root: crate::asset_source::RegisteredRoot,
        gate: crate::asset_session::GitHubPreflightGoGate, supervisor: &Supervisor, now: Instant) -> Result<crate::github_preflight_protocol::Status, BridgeError> {
        use crate::{github_preflight_protocol as p, github_preflight_session as s};
        if !supervisor.github_preflight_profile_available() || !p::publisher_bound() { return Err(s::refused(p::Reason::Unqualified)); }
        if !request.valid() || self.native_work_pending() { return Err(s::refused(p::Reason::Busy)); }
        let private = self.private.as_ref().ok_or_else(|| s::refused(p::Reason::NotConnected))?;
        let (session_id, project_id, generation) = (private.id.clone(), private.project_id.clone(), private.generation);
        // Register the original owner synchronously before exposing its ticket.
        // Native final GO waits for this same document lock; no token is copied.
        let ticket = supervisor.start_github_preflight(request.clone(), gate).map_err(|error|
            s::refused(match error.code.as_str() { "busy" => p::Reason::Busy, "cleanup_unknown" => p::Reason::CleanupUnknown,
                "shutting_down" | "cancelled" => p::Reason::Cancelled, _ => p::Reason::RuntimeUnavailable }))?;
        let other = self.release.snapshot(); self.release.revoke_consent(); self.release.finish(other);
        self.revoke_input_material();
        self.preflight.start(s::Active { ticket, request, session_id, project_id, generation, root });
        let before = self.status.clone(); self.capability(now, Reason::None); self.finish(before);
        Ok(self.preflight.snapshot())
    }
    pub(crate) fn preflight_prepare(&mut self, args: crate::github_preflight_protocol::PrepareArgs,
        generation: u32, root: crate::asset_source::RegisteredRoot, project_binding: &str, marker: String,
        gate: crate::asset_session::GitHubPreflightGoGate, supervisor: &Supervisor, now: Instant) -> Result<crate::github_preflight_protocol::Status, BridgeError> {
        use crate::{github_preflight_protocol as p, github_preflight_session as s};
        if self.status.revision != args.expected_connection_revision { return Err(s::refused(p::Reason::TargetChanged)); }
        let (_, scope) = self.preflight_context(&args.session_id, args.expected_revision, generation, project_binding, now)?;
        let target = p::Target { project_binding: scope.project_binding, repository: scope.repository, account_id: scope.account_id,
            repository_id: scope.repository_id, branch: args.branch, tooling_repository: p::TOOLING_REPOSITORY.into(),
            tooling_sha: p::TOOLING_SHA.ok_or_else(|| s::refused(p::Reason::PublisherUnconfigured))?.into(), platform: args.platform, marker };
        if !target.publisher_bound() { return Err(s::refused(p::Reason::InvalidInput)); }
        self.preflight_start(p::Request { action: Some(p::Action { kind: p::Kind::Prepare, target, prepared: None, run_id: None }),
            pending_scope: None, home: None }, root, gate, supervisor, now)
    }
    pub(crate) fn preflight_dispatch(&mut self, args: crate::github_preflight_protocol::DispatchArgs,
        generation: u32, root: crate::asset_source::RegisteredRoot, project_binding: &str, home: String,
        gate: crate::asset_session::GitHubPreflightGoGate, supervisor: &Supervisor, now: Instant) -> Result<crate::github_preflight_protocol::Status, BridgeError> {
        use crate::{github_preflight_protocol as p, github_preflight_session as s};
        let (project_id, scope) = self.preflight_context(&args.session_id, args.expected_revision, generation, project_binding, now)?;
        let valid = self.preflight.consent.as_ref().is_some_and(|v| v.session_id == args.session_id && v.project_id == project_id
            && v.generation == generation && v.root == root && now < v.end && v.prepared.target.marker == args.consent_id
            && scope.matches(&v.prepared.target) && v.prepared.publisher_bound() && args.confirm);
        if !valid { return Err(s::refused(p::Reason::ConsentExpired)); }
        let before = self.preflight.snapshot();
        let consent = self.preflight.consent.take().ok_or_else(|| s::refused(p::Reason::ConsentExpired))?;
        self.preflight.revoke_consent(); self.preflight.finish(before); // Consume even on later admission refusal.
        let action = p::Action { kind: p::Kind::Dispatch, target: consent.prepared.target.clone(), prepared: Some(consent.prepared), run_id: None };
        self.preflight_start(p::Request { action: Some(action), pending_scope: None, home: Some(home) }, root, gate, supervisor, now)
    }
    pub(crate) fn preflight_observe(&mut self, kind: crate::github_preflight_protocol::Kind, args: crate::github_preflight_protocol::ObserveArgs,
        generation: u32, root: crate::asset_source::RegisteredRoot, project_binding: &str, home: String,
        gate: crate::asset_session::GitHubPreflightGoGate, supervisor: &Supervisor, now: Instant) -> Result<crate::github_preflight_protocol::Status, BridgeError> {
        use crate::{github_preflight_protocol as p, github_preflight_session as s};
        let (_, scope) = self.preflight_context(&args.session_id, args.expected_revision, generation, project_binding, now)?;
        let record = self.preflight.record(&args.marker).filter(|row| scope.matches(&row.prepared.target) && row.prepared.publisher_bound())
            .ok_or_else(|| s::refused(p::Reason::TargetChanged))?.clone();
        if !matches!(kind, p::Kind::Track | p::Kind::Reconcile) || (kind == p::Kind::Track) != record.run_id.is_some() {
            return Err(s::refused(p::Reason::InvalidInput));
        }
        let action = p::Action { kind, target: record.prepared.target.clone(), prepared: Some(record.prepared), run_id: record.run_id };
        self.preflight_start(p::Request { action: Some(action), pending_scope: None, home: Some(home) }, root, gate, supervisor, now)
    }
    pub(crate) fn preflight_pending(&mut self, args: crate::github_preflight_protocol::ControlArgs,
        generation: u32, root: crate::asset_source::RegisteredRoot, project_binding: &str, home: String,
        gate: crate::asset_session::GitHubPreflightGoGate, supervisor: &Supervisor, now: Instant) -> Result<crate::github_preflight_protocol::Status, BridgeError> {
        let (_, scope) = self.preflight_context(&args.session_id, args.expected_revision, generation, project_binding, now)?;
        self.preflight_start(crate::github_preflight_protocol::Request { action: None, pending_scope: Some(scope), home: Some(home) }, root, gate, supervisor, now)
    }
    pub(crate) fn preflight_cancel(&mut self, id: &str) -> Result<crate::github_preflight_protocol::Status, BridgeError> {
        self.preflight.cancel(id)?; Ok(self.preflight.snapshot())
    }
    pub(crate) fn preflight_active_registration(&self) -> Option<(&str, u32, &crate::asset_source::RegisteredRoot)> {
        self.preflight.active.as_ref().map(|v| (v.project_id.as_str(), v.generation, &v.root))
    }
    pub(crate) fn preflight_go(&self, id: &str, digest: &str, request: &crate::github_preflight_protocol::Request,
        now: Instant, claim: impl FnOnce() -> bool) -> Result<Vec<u8>, BridgeError> {
        use crate::{github_preflight_protocol as p, github_preflight_session as s};
        let active = self.preflight.active.as_ref().filter(|v| v.ticket.operation_id() == id && &v.request == request)
            .ok_or_else(|| s::refused(p::Reason::TargetChanged))?;
        let private = self.private.as_ref().filter(|v| v.id == active.session_id && v.project_id == active.project_id
            && v.generation == active.generation && v.ticket.is_none() && v.device.is_none() && v.retirement.is_none() && v.token.is_some())
            .ok_or_else(|| s::refused(p::Reason::TargetChanged))?;
        if self.unknown || self.exhausted || self.preflight.exhausted || self.release.exhausted || self.input.exhausted { return Err(s::refused(p::Reason::CleanupUnknown)); }
        if self.release.native_work_pending() || self.input.native_work_pending() { return Err(s::refused(p::Reason::Busy)); }
        if now >= private.clock.end { return Err(s::refused(p::Reason::Expired)); }
        if self.cooldown_blocked || self.cooldown.is_some_and(|end| now < end) { return Err(s::refused(p::Reason::RateLimited)); }
        let (account, repository, coordinate) = request.action.as_ref().map(|a|
            (&a.target.account_id, &a.target.repository_id, &a.target.repository))
            .or_else(|| request.pending_scope.as_ref().map(|v| (&v.account_id, &v.repository_id, &v.repository)))
            .ok_or_else(BridgeError::protocol)?;
        if private.account_pin.as_ref() != Some(account) || private.repository_pin.as_ref() != Some(repository)
            || !coordinate.eq_ignore_ascii_case(&private.repository) { return Err(s::refused(p::Reason::TargetChanged)); }
        let bytes = p::encode_go(id, digest, if request.kind() == p::Kind::Pending { None } else { private.token.as_deref() }, request.kind())?;
        // The short claim runs under this same document lock, before returning
        // the sole writer buffer. It can win only once against revocation.
        if !claim() { return Err(s::refused(p::Reason::Cancelled)); } Ok(bytes)
    }
    fn reconcile_preflight(&mut self, now: Instant, external: Reason) {
        use crate::{github_preflight_protocol as p, github_preflight_session as s, supervisor::GitHubPreflightReceipt as R};
        let before = self.preflight.snapshot(); self.preflight.expire_consent(now);
        match self.preflight.receipt() {
            Some(R::RetainedUnknown) => self.unknown_inner(),
            Some(R::Settled { outcome, settled_at, was_unknown }) => {
                let retiring = self.private.as_ref().is_none_or(|v| v.retirement.is_some());
                if external == Reason::None || retiring || was_unknown || self.unknown {
                    self.accept_preflight(outcome, settled_at, was_unknown, now);
                }
            },
            Some(R::Pending) | None => {},
        }
        if self.unknown { self.preflight.unknown(); }
        else if external != Reason::None { self.preflight.view.available = false; self.preflight.view.reason = s::connection_reason(external); }
        if self.preflight.active.as_ref().is_some_and(|v| v.ticket.go_claimed()) {
            if let Some(op) = &mut self.preflight.view.operation {
                if op.kind == p::Kind::Dispatch && op.effect == p::Effect::NotSent { op.effect = p::Effect::PotentiallyApplied; }
            }
        }
        self.preflight.finish(before);
    }
    fn accept_preflight(&mut self, result: Result<crate::github_preflight_protocol::Reply, BridgeError>, settled_at: Instant,
        was_unknown: bool, now: Instant) {
        use crate::{github_preflight_protocol as p, github_preflight_session as s};
        let Some(active) = self.preflight.active.take() else { self.unknown_inner(); return; };
        let kind = active.request.kind(); let go_claimed = active.ticket.go_claimed();
        let mut reason = result.as_ref().map_or_else(s::outcome_reason, |reply| reply.result.as_ref().map_or(p::Reason::None, |v| v.reason));
        if let Ok(reply) = &result {
            if reply.result.as_ref().is_some_and(|v| !self.apply_control(&v.control, settled_at)) { reason = p::Reason::ResponseInvalid; }
        }
        if reason == p::Reason::Expired { reason = p::Reason::NetworkUnavailable; } // Helper deadline is not token expiry.
        if self.private.as_ref().is_some_and(|v| now >= v.clock.end && v.retirement.is_none()) { self.retire_inner(Reason::Expired, false); }
        let retirement = self.private.as_ref().and_then(|v| v.retirement);
        let unknown = was_unknown || self.unknown || reason == p::Reason::CleanupUnknown;
        let mut effect = if kind == p::Kind::Dispatch {
            if go_claimed { p::Effect::PotentiallyApplied } else { p::Effect::NotSent }
        } else { p::Effect::None };
        // An intent/known ID is only recovery DATA, never another dispatch
        // grant. Keep it even if a later channel/cleanup result was lost.
        if kind == p::Kind::Dispatch && go_claimed {
            if let Some(prepared) = active.request.action.as_ref().and_then(|a| a.prepared.clone()) {
                if self.preflight.retain_record(p::PendingRecord { prepared, run_id: None }).is_err() { reason = p::Reason::ResponseInvalid; }
            }
        }
        if unknown {
            self.unknown_inner();
            if let Some(op) = &mut self.preflight.view.operation { op.phase = p::Phase::CleanupUnknown; op.reason = p::Reason::CleanupUnknown; op.effect = effect; }
            self.complete_retirement(); return;
        }
        if let Some(retired) = retirement { reason = s::connection_reason(retired); }
        else if let Ok(reply) = result {
            if reason == p::Reason::None {
                let publication = (|| -> Result<(), BridgeError> {
                    if let Some(records) = reply.pending { self.preflight.view.pending = records; }
                    if let Some(outcome) = reply.result {
                        effect = outcome.effect;
                        if let Some(prepared) = outcome.prepared {
                            let private = self.private.as_ref().ok_or_else(BridgeError::protocol)?;
                            let end = settled_at.checked_add(Duration::from_secs(120)).ok_or_else(BridgeError::protocol)?.min(private.clock.end);
                            if now >= end { return Err(s::refused(p::Reason::ConsentExpired)); }
                            let wall = private.clock.wall.checked_add(end.duration_since(private.clock.admitted)).ok_or_else(BridgeError::protocol)?;
                            self.preflight.view.consent_expires_at = Some(display_utc(wall).ok_or_else(BridgeError::protocol)?);
                            self.preflight.view.prepared = Some(prepared.clone());
                            self.preflight.consent = Some(s::Consent { prepared, end, session_id: active.session_id.clone(),
                                project_id: active.project_id.clone(), generation: active.generation, root: active.root.clone() });
                        }
                        if let Some(run_id) = outcome.run_id {
                            let prepared = active.request.action.as_ref().and_then(|v| v.prepared.clone()).ok_or_else(BridgeError::protocol)?;
                            self.preflight.retain_record(p::PendingRecord { prepared, run_id: Some(run_id) })?;
                        }
                        self.preflight.view.run = outcome.run;
                    }
                    Ok(())
                })();
                if let Err(error) = publication { reason = s::outcome_reason(&error); self.preflight.revoke_consent(); self.preflight.view.run = None; }
            } else if let Some(outcome) = reply.result {
                // A positively settled helper can still prove it never entered
                // POST after branch/account refusal; a native failure cannot.
                if kind == p::Kind::Dispatch { effect = outcome.effect; }
            }
        }
        if reason != p::Reason::None && effect == p::Effect::Accepted { effect = p::Effect::PotentiallyApplied; }
        if let Some(op) = &mut self.preflight.view.operation { op.phase = p::Phase::Settled; op.reason = reason; op.effect = effect; }
        let retire = match reason {
            p::Reason::Unauthorized => Some(Reason::Unauthorized), p::Reason::TargetChanged => Some(Reason::TargetChanged),
            p::Reason::ResponseInvalid => Some(Reason::ResponseInvalid), p::Reason::Expired => Some(Reason::Expired),
            p::Reason::Cancelled => Some(Reason::Cancelled), _ => None,
        };
        if let Some(reason) = retire { self.retire_inner(reason, false); }
        if retirement.is_some() { self.complete_retirement(); }
    }
}

// The action family shares THIS original session's token, monotonic endpoint,
// cooldown, registration and retirement. Its metadata module owns no credential.
impl ConnectionState {
    pub(crate) fn release_status(&mut self, qualified: bool, now: Instant, external: Reason) -> crate::github_release_protocol::Status {
        use crate::{github_release_protocol::Reason as R, github_release_session::connection_reason};
        let before = self.release.snapshot(); self.release.expire_consent(now);
        let reason = if self.unknown || self.exhausted || self.preflight.exhausted || self.release.exhausted || self.input.exhausted { R::CleanupUnknown }
            else if external != Reason::None { connection_reason(external) }
            else if !crate::github_release_protocol::publisher_bound() { R::PublisherUnconfigured }
            else if !qualified { R::Unqualified }
            else if self.native_work_pending() { R::Busy }
            else if let Some(private) = &self.private {
                if let Some(reason) = private.retirement { connection_reason(reason) }
                else if now >= private.clock.end { R::Expired }
                else if self.cooldown_blocked || self.cooldown.is_some_and(|end| now < end) { R::RateLimited }
                else if private.token.is_none() || private.account_pin.is_none() || private.repository_pin.is_none()
                    || self.status.account.state != FactState::Observed || self.status.repository.state != FactState::Observed
                    || !self.status.session.as_ref().is_some_and(|s| s.state == SessionState::Connected) { R::NotConnected }
                else { R::None }
            } else { R::NotConnected };
        self.release.view.available = reason == R::None; self.release.view.reason = reason;
        // Preserve the original terminal operation's nonsecret session binding
        // after retirement. Otherwise a lost admission reply followed by an
        // exact settled event could never be correlated by its original UI.
        // A fresh Connect already clears the old operation and session view.
        if let Some(private) = &self.private { self.release.view.session_id = Some(private.id.clone()); }
        else if self.release.view.operation.is_none() { self.release.view.session_id = None; }
        self.release.finish(before); self.release.snapshot()
    }
    fn release_context(&mut self, session_id: &str, revision: u32, generation: u32,
        project_binding: &str, now: Instant) -> Result<(String, crate::github_release_protocol::Scope), BridgeError> {
        use crate::{github_release_protocol as p, github_release_session as s};
        self.room().map_err(|_| s::refused(p::Reason::CleanupUnknown))?;
        if self.release.view.revision != revision { return Err(s::refused(p::Reason::TargetChanged)); }
        if self.native_work_pending() { return Err(s::refused(p::Reason::Busy)); }
        if !self.release.view.available { return Err(s::refused(self.release.view.reason)); }
        let private = self.private.as_ref().filter(|v| v.id == session_id && v.generation == generation)
            .ok_or_else(|| s::refused(p::Reason::TargetChanged))?;
        if now >= private.clock.end || private.token.is_none() || private.retirement.is_some() { return Err(s::refused(p::Reason::Expired)); }
        if self.cooldown_blocked || self.cooldown.is_some_and(|end| now < end) { return Err(s::refused(p::Reason::RateLimited)); }
        let repository = self.status.repository.value.as_ref().filter(|v| v.full_name.eq_ignore_ascii_case(&private.repository))
            .ok_or_else(|| s::refused(p::Reason::NotConnected))?;
        let scope = p::Scope { project_binding: project_binding.into(), repository: repository.full_name.clone(),
            account_id: private.account_pin.clone().ok_or_else(|| s::refused(p::Reason::NotConnected))?,
            repository_id: private.repository_pin.clone().ok_or_else(|| s::refused(p::Reason::NotConnected))? };
        if !scope.valid() { return Err(s::refused(p::Reason::InvalidInput)); }
        Ok((private.project_id.clone(), scope))
    }
    fn release_start(&mut self, request: crate::github_release_protocol::Request, root: crate::asset_source::RegisteredRoot,
        gate: crate::asset_session::GitHubReleaseGoGate, supervisor: &Supervisor, now: Instant) -> Result<crate::github_release_protocol::Status, BridgeError> {
        use crate::{github_release_protocol as p, github_release_session as s};
        if !supervisor.github_release_profile_available() || !p::publisher_bound() { return Err(s::refused(p::Reason::Unqualified)); }
        if !request.valid() || self.native_work_pending() { return Err(s::refused(p::Reason::Busy)); }
        // Refuse before installing an owner or consuming any send capability
        // if complete retained history plus a future bounded result cannot be
        // published. A successful POST must never create unpublishable DATA.
        if !self.release.view.fits_wire() || !p::complete_status_ceiling().is_some_and(|n| n <= p::RESPONSE_LIMIT) {
            return Err(s::refused(p::Reason::RuntimeUnavailable));
        }
        let private = self.private.as_ref().ok_or_else(|| s::refused(p::Reason::NotConnected))?;
        let (session_id, project_id, generation) = (private.id.clone(), private.project_id.clone(), private.generation);
        // Register the original owner synchronously before exposing its ticket.
        // Native final GO waits for this same document lock; no token is copied.
        let ticket = supervisor.start_github_release(request.clone(), gate).map_err(|error|
            s::refused(match error.code.as_str() { "busy" => p::Reason::Busy, "cleanup_unknown" => p::Reason::CleanupUnknown,
                "shutting_down" | "cancelled" => p::Reason::Cancelled, _ => p::Reason::RuntimeUnavailable }))?;
        let other = self.preflight.snapshot(); self.preflight.revoke_consent(); self.preflight.finish(other);
        self.revoke_input_material();
        self.release.start(s::Active { ticket, request, session_id, project_id, generation, root });
        let before = self.status.clone(); self.capability(now, Reason::None); self.finish(before);
        Ok(self.release.snapshot())
    }
    pub(crate) fn release_prepare(&mut self, args: crate::github_release_protocol::PrepareArgs,
        generation: u32, root: crate::asset_source::RegisteredRoot, project_binding: &str, marker: String,
        gate: crate::asset_session::GitHubReleaseGoGate, supervisor: &Supervisor, now: Instant) -> Result<crate::github_release_protocol::Status, BridgeError> {
        use crate::{github_release_protocol as p, github_release_session as s};
        if self.status.revision != args.expected_connection_revision { return Err(s::refused(p::Reason::TargetChanged)); }
        let (_, scope) = self.release_context(&args.session_id, args.expected_revision, generation, project_binding, now)?;
        let target = p::Target { project_binding: scope.project_binding, repository: scope.repository, account_id: scope.account_id,
            repository_id: scope.repository_id, branch: args.branch, tooling_repository: p::TOOLING_REPOSITORY.into(),
            tooling_sha: p::TOOLING_SHA.ok_or_else(|| s::refused(p::Reason::PublisherUnconfigured))?.into(), platform: args.platform, marker, selection: args.selection };
        if !target.publisher_bound() { return Err(s::refused(p::Reason::InvalidInput)); }
        self.release_start(p::Request { action: Some(p::Action { kind: p::Kind::Prepare, target, prepared: None, run_id: None }),
            pending_scope: None, home: None }, root, gate, supervisor, now)
    }
    pub(crate) fn release_dispatch(&mut self, args: crate::github_release_protocol::DispatchArgs,
        generation: u32, root: crate::asset_source::RegisteredRoot, project_binding: &str, home: String,
        gate: crate::asset_session::GitHubReleaseGoGate, supervisor: &Supervisor, now: Instant) -> Result<crate::github_release_protocol::Status, BridgeError> {
        use crate::{github_release_protocol as p, github_release_session as s};
        let (project_id, scope) = self.release_context(&args.session_id, args.expected_revision, generation, project_binding, now)?;
        let valid = self.release.consent.as_ref().is_some_and(|v| v.session_id == args.session_id && v.project_id == project_id
            && v.generation == generation && v.root == root && now < v.end
            && scope.matches(&v.prepared.target) && v.prepared.publisher_bound() && args.matches_review(&v.prepared));
        if !valid { return Err(s::refused(p::Reason::ConsentExpired)); }
        let before = self.release.snapshot();
        let consent = self.release.consent.take().ok_or_else(|| s::refused(p::Reason::ConsentExpired))?;
        self.release.revoke_consent(); self.release.finish(before); // Consume even on later admission refusal.
        let action = p::Action { kind: p::Kind::Dispatch, target: consent.prepared.target.clone(), prepared: Some(consent.prepared), run_id: None };
        self.release_start(p::Request { action: Some(action), pending_scope: None, home: Some(home) }, root, gate, supervisor, now)
    }
    pub(crate) fn release_observe(&mut self, kind: crate::github_release_protocol::Kind, args: crate::github_release_protocol::ObserveArgs,
        generation: u32, root: crate::asset_source::RegisteredRoot, project_binding: &str, home: String,
        gate: crate::asset_session::GitHubReleaseGoGate, supervisor: &Supervisor, now: Instant) -> Result<crate::github_release_protocol::Status, BridgeError> {
        use crate::{github_release_protocol as p, github_release_session as s};
        let (_, scope) = self.release_context(&args.session_id, args.expected_revision, generation, project_binding, now)?;
        let record = self.release.record(&args.marker).filter(|row| scope.matches(&row.prepared.target) && row.prepared.publisher_bound())
            .ok_or_else(|| s::refused(p::Reason::TargetChanged))?.clone();
        if !matches!(kind, p::Kind::Track | p::Kind::Reconcile) || (kind == p::Kind::Track) != record.run_id.is_some() {
            return Err(s::refused(p::Reason::InvalidInput));
        }
        let action = p::Action { kind, target: record.prepared.target.clone(), prepared: Some(record.prepared), run_id: record.run_id };
        self.release_start(p::Request { action: Some(action), pending_scope: None, home: Some(home) }, root, gate, supervisor, now)
    }
    pub(crate) fn release_pending(&mut self, args: crate::github_release_protocol::ControlArgs,
        generation: u32, root: crate::asset_source::RegisteredRoot, project_binding: &str, home: String,
        gate: crate::asset_session::GitHubReleaseGoGate, supervisor: &Supervisor, now: Instant) -> Result<crate::github_release_protocol::Status, BridgeError> {
        let (_, scope) = self.release_context(&args.session_id, args.expected_revision, generation, project_binding, now)?;
        self.release_start(crate::github_release_protocol::Request { action: None, pending_scope: Some(scope), home: Some(home) }, root, gate, supervisor, now)
    }
    pub(crate) fn release_cancel(&mut self, id: &str) -> Result<crate::github_release_protocol::Status, BridgeError> {
        self.release.cancel(id)?; Ok(self.release.snapshot())
    }
    pub(crate) fn release_active_registration(&self) -> Option<(&str, u32, &crate::asset_source::RegisteredRoot)> {
        self.release.active.as_ref().map(|v| (v.project_id.as_str(), v.generation, &v.root))
    }
    pub(crate) fn release_go(&self, id: &str, digest: &str, request: &crate::github_release_protocol::Request,
        now: Instant, claim: impl FnOnce() -> bool) -> Result<Vec<u8>, BridgeError> {
        use crate::{github_release_protocol as p, github_release_session as s};
        let active = self.release.active.as_ref().filter(|v| v.ticket.operation_id() == id && &v.request == request)
            .ok_or_else(|| s::refused(p::Reason::TargetChanged))?;
        let private = self.private.as_ref().filter(|v| v.id == active.session_id && v.project_id == active.project_id
            && v.generation == active.generation && v.ticket.is_none() && v.device.is_none() && v.retirement.is_none() && v.token.is_some())
            .ok_or_else(|| s::refused(p::Reason::TargetChanged))?;
        if self.unknown || self.exhausted || self.preflight.exhausted || self.release.exhausted || self.input.exhausted { return Err(s::refused(p::Reason::CleanupUnknown)); }
        if self.preflight.native_work_pending() || self.input.native_work_pending() { return Err(s::refused(p::Reason::Busy)); }
        if now >= private.clock.end { return Err(s::refused(p::Reason::Expired)); }
        if self.cooldown_blocked || self.cooldown.is_some_and(|end| now < end) { return Err(s::refused(p::Reason::RateLimited)); }
        let (account, repository, coordinate) = request.action.as_ref().map(|a|
            (&a.target.account_id, &a.target.repository_id, &a.target.repository))
            .or_else(|| request.pending_scope.as_ref().map(|v| (&v.account_id, &v.repository_id, &v.repository)))
            .ok_or_else(BridgeError::protocol)?;
        if private.account_pin.as_ref() != Some(account) || private.repository_pin.as_ref() != Some(repository)
            || !coordinate.eq_ignore_ascii_case(&private.repository) { return Err(s::refused(p::Reason::TargetChanged)); }
        let bytes = p::encode_go(id, digest, if request.kind() == p::Kind::Pending { None } else { private.token.as_deref() }, request.kind())?;
        // The short claim runs under this same document lock, before returning
        // the sole writer buffer. It can win only once against revocation.
        if !claim() { return Err(s::refused(p::Reason::Cancelled)); } Ok(bytes)
    }
    fn reconcile_release(&mut self, now: Instant, external: Reason) {
        use crate::{github_release_protocol as p, github_release_session as s, supervisor::GitHubReleaseReceipt as R};
        let before = self.release.snapshot(); self.release.expire_consent(now);
        match self.release.receipt() {
            Some(R::RetainedUnknown) => self.unknown_inner(),
            Some(R::Settled { outcome, settled_at, was_unknown }) => {
                let retiring = self.private.as_ref().is_none_or(|v| v.retirement.is_some());
                if external == Reason::None || retiring || was_unknown || self.unknown {
                    self.accept_release(outcome, settled_at, was_unknown, now);
                }
            },
            Some(R::Pending) | None => {},
        }
        if self.unknown { self.release.unknown(); }
        else if external != Reason::None { self.release.view.available = false; self.release.view.reason = s::connection_reason(external); }
        if self.release.active.as_ref().is_some_and(|v| v.ticket.go_claimed()) {
            if let Some(op) = &mut self.release.view.operation {
                if op.kind == p::Kind::Dispatch && op.effect == p::Effect::NotSent { op.effect = p::Effect::PotentiallyApplied; }
            }
        }
        self.release.finish(before);
    }
    fn accept_release(&mut self, result: Result<crate::github_release_protocol::Reply, BridgeError>, settled_at: Instant,
        was_unknown: bool, now: Instant) {
        use crate::{github_release_protocol as p, github_release_session as s};
        let Some(active) = self.release.active.take() else { self.unknown_inner(); return; };
        let kind = active.request.kind(); let go_claimed = active.ticket.go_claimed();
        let mut reason = result.as_ref().map_or_else(s::outcome_reason, |reply| reply.result.as_ref().map_or(p::Reason::None, |v| v.reason));
        if let Ok(reply) = &result {
            if reply.result.as_ref().is_some_and(|v| !self.apply_control(&v.control, settled_at)) { reason = p::Reason::ResponseInvalid; }
        }
        if reason == p::Reason::Expired { reason = p::Reason::NetworkUnavailable; } // Helper deadline is not token expiry.
        if self.private.as_ref().is_some_and(|v| now >= v.clock.end && v.retirement.is_none()) { self.retire_inner(Reason::Expired, false); }
        let retirement = self.private.as_ref().and_then(|v| v.retirement);
        let unknown = was_unknown || self.unknown || reason == p::Reason::CleanupUnknown;
        let mut effect = if kind == p::Kind::Dispatch {
            if go_claimed { p::Effect::PotentiallyApplied } else { p::Effect::NotSent }
        } else { p::Effect::None };
        // An intent/known ID is only recovery DATA, never another dispatch
        // grant. Keep it even if a later channel/cleanup result was lost.
        if kind == p::Kind::Dispatch && go_claimed {
            if let Some(prepared) = active.request.action.as_ref().and_then(|a| a.prepared.clone()) {
                if self.release.retain_record(p::PendingRecord { prepared, run_id: None }).is_err() { reason = p::Reason::ResponseInvalid; }
            }
        }
        if unknown {
            self.unknown_inner();
            if let Some(op) = &mut self.release.view.operation { op.phase = p::Phase::CleanupUnknown; op.reason = p::Reason::CleanupUnknown; op.effect = effect; }
            self.complete_retirement(); return;
        }
        if let Some(retired) = retirement { reason = s::connection_reason(retired); }
        else if let Ok(reply) = result {
            if reason == p::Reason::None {
                let publication = (|| -> Result<(), BridgeError> {
                    if let Some(records) = reply.pending { self.release.view.pending = records; }
                    if let Some(outcome) = reply.result {
                        effect = outcome.effect;
                        if let Some(prepared) = outcome.prepared {
                            let private = self.private.as_ref().ok_or_else(BridgeError::protocol)?;
                            let end = settled_at.checked_add(Duration::from_secs(120)).ok_or_else(BridgeError::protocol)?.min(private.clock.end);
                            if now >= end { return Err(s::refused(p::Reason::ConsentExpired)); }
                            let wall = private.clock.wall.checked_add(end.duration_since(private.clock.admitted)).ok_or_else(BridgeError::protocol)?;
                            self.release.view.consent_expires_at = Some(display_utc(wall).ok_or_else(BridgeError::protocol)?);
                            self.release.view.prepared = Some(prepared.clone());
                            self.release.consent = Some(s::Consent { prepared, end, session_id: active.session_id.clone(),
                                project_id: active.project_id.clone(), generation: active.generation, root: active.root.clone() });
                        }
                        if let Some(run_id) = outcome.run_id {
                            let prepared = active.request.action.as_ref().and_then(|v| v.prepared.clone()).ok_or_else(BridgeError::protocol)?;
                            self.release.retain_record(p::PendingRecord { prepared, run_id: Some(run_id) })?;
                        }
                        self.release.view.run = outcome.run;
                    }
                    Ok(())
                })();
                if let Err(error) = publication { reason = s::outcome_reason(&error); self.release.revoke_consent(); self.release.view.run = None; }
            } else if let Some(outcome) = reply.result {
                // A positively settled helper can still prove it never entered
                // POST after branch/account refusal; a native failure cannot.
                if kind == p::Kind::Dispatch { effect = outcome.effect; }
            }
        }
        if reason != p::Reason::None && effect == p::Effect::Accepted { effect = p::Effect::PotentiallyApplied; }
        if let Some(op) = &mut self.release.view.operation { op.phase = p::Phase::Settled; op.reason = reason; op.effect = effect; }
        let retire = match reason {
            p::Reason::Unauthorized => Some(Reason::Unauthorized), p::Reason::TargetChanged => Some(Reason::TargetChanged),
            p::Reason::ResponseInvalid => Some(Reason::ResponseInvalid), p::Reason::Expired => Some(Reason::Expired),
            p::Reason::Cancelled => Some(Reason::Cancelled), _ => None,
        };
        if let Some(reason) = retire { self.retire_inner(reason, false); }
        if retirement.is_some() { self.complete_retirement(); }
    }
}

#[path = "github_connection_input_group.rs"]
mod input_group;
