//! Bounded, session-only GitHub state under the actual DocumentBinding mutex.
//! This is not another process owner. Only the existing Supervisor's final
//! mailbox receipt releases an active read; a reply or Unknown never does.
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use crate::{error::BridgeError, github_connection_protocol::{self as wire, Account, Automation,
    Capability, ConnectTokenArgs, DeviceLogin, Fact, FactState, GitHubReadControl, GitHubReadFacts,
    GitHubReadOutcome, Operation, OperationKind, Phase, Reason, Repository, Session, SessionState,
    Status, UnobservedFacts}, supervisor::{GitHubReadReceipt, GitHubReadTicket, Supervisor}};

// Independently qualified document/picker/quit AND original runtime/TLS custody
// are required. Neither the asset gate, a renderer flag nor a bundle inspection
// can enable credential collection or this latent owner route.
const GITHUB_CONNECTION_NATIVE_QUALIFIED: bool = false;
const LIFETIME: Duration = Duration::from_secs(60 * 60);
pub(crate) fn qualified() -> bool {
    GITHUB_CONNECTION_NATIVE_QUALIFIED && crate::runtime::GITHUB_TLS_PROFILE_QUALIFIED
        && cfg!(all(feature = "development-runtime", debug_assertions,
            target_os = "linux", target_arch = "x86_64", target_env = "gnu"))
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
    Status { schema_version: 1, revision,
        capability: Capability { read_only_session_available: reason == Reason::None, reason,
            device_login: DeviceLogin::PublisherUnconfigured, storage: "session-only".into() },
        session: None, operation: None, account: unobserved(), repository: unobserved(), automation: unobserved(),
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
            clock, token: Some("INERT_NOT_A_CREDENTIAL".into()),
            account_pin: None, repository_pin: None, ticket: None, retirement: None, remove_after_settlement: false });
        state.status.session = Some(Session { id: "github-session-1".into(), project_id: "project-1".into(), target_repository: "owner/app".into(),
            state: SessionState::Checking, expires_at: Some("2026-09-17T13:00:00Z".into()) });
        state.status.operation = Some(Operation { id: "original-data-1".into(), kind: OperationKind::Connect, phase: Phase::Running, reason: Reason::None });
        state
    }
    fn observed<T>(value: T) -> Fact<T> { Fact { state: FactState::Observed, value: Some(value), observed_at: Some("2026-09-17T12:00:01Z".into()), reason: Reason::None } }
    fn result() -> GitHubReadOutcome {
        GitHubReadOutcome { facts: GitHubReadFacts { schema_version: 1,
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
    clock: CredentialClock, token: Option<String>, account_pin: Option<String>, repository_pin: Option<String>,
    ticket: Option<GitHubReadTicket>, retirement: Option<Reason>, remove_after_settlement: bool,
}
pub(crate) struct ConnectionState {
    status: Status, private: Option<PrivateSession>, next_session: u32,
    cooldown: Option<Instant>, cooldown_blocked: bool, unknown: bool, exhausted: bool,
}
impl ConnectionState {
    pub(crate) fn new() -> Self {
        Self { status: empty_status(1, Reason::Unqualified), private: None, next_session: 0,
            cooldown: None, cooldown_blocked: false, unknown: false, exhausted: false }
    }
    pub(crate) fn snapshot(&self) -> Status { self.status.clone() }
    pub(crate) fn registration(&self) -> Option<(&str, u32)> {
        self.private.as_ref().map(|s| (s.project_id.as_str(), s.generation))
    }
    pub(crate) fn material_settled(&self) -> bool {
        self.private.as_ref().is_none_or(|s| s.token.is_none() && s.ticket.is_none())
    }
    pub(crate) fn native_work_pending(&self) -> bool { self.private.as_ref().is_some_and(|s| s.ticket.is_some()) }
    fn fact_retirement(&mut self, reason: Reason) {
        stale(&mut self.status.account, reason); stale(&mut self.status.repository, reason); stale(&mut self.status.automation, reason);
    }
    fn finish(&mut self, before: Status) {
        if self.exhausted { self.status = empty_status(u32::MAX, Reason::Unqualified); return; }
        if self.status != before {
            if let Some(next) = before.revision.checked_add(1).filter(|v| *v < u32::MAX) { self.status.revision = next; }
            else { self.exhaust(); }
        }
    }
    fn room(&mut self) -> Result<(), BridgeError> {
        if self.exhausted || self.status.revision >= u32::MAX - 1 { self.exhaust(); return Err(refused(Reason::CleanupUnknown)); }
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
        let Some(private) = &mut self.private else { return; };
        private.remove_after_settlement |= remove;
        let first = private.retirement.is_none();
        if first { private.retirement = Some(reason); }
        if let Some(ticket) = &private.ticket { ticket.stop(); }
        if !self.unknown && (first || remove && self.status.operation.as_ref().is_none_or(|op| op.kind != OperationKind::Disconnect)) {
            self.status.operation = Some(Operation { id: private.stop_id.clone(), kind: OperationKind::Disconnect,
                phase: Phase::Running, reason: Reason::None });
        }
        let reason = private.retirement.unwrap_or(reason);
        if let Some(session) = &mut self.status.session { session.state = if self.unknown { SessionState::CleanupUnknown } else { SessionState::Disconnecting }; }
        self.fact_retirement(if self.unknown { Reason::CleanupUnknown } else { reason });
        if self.private.as_ref().is_some_and(|s| s.ticket.is_none()) { self.complete_retirement(); }
    }
    fn complete_retirement(&mut self) {
        let Some(private) = &mut self.private else { return; };
        if private.ticket.is_some() { return; }
        private.token = None;
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
    fn apply_control(&mut self, control: &GitHubReadControl, settled_at: Instant) -> bool {
        // Independent read limits survive disconnect, token replacement and a
        // response-invalid expiry policy. Never base them on observation time.
        self.cooldown_blocked |= control.cooldown_blocked;
        if let Some(seconds) = control.cooldown_seconds {
            match settled_at.checked_add(Duration::from_secs(u64::from(seconds))) {
                Some(end) => self.cooldown = Some(self.cooldown.map_or(end, |old| old.max(end))),
                None => self.cooldown_blocked = true,
            }
        }
        if let Some(timestamp) = &control.credential_expires_at {
            let Some(private) = &mut self.private else { return false; };
            if !private.clock.shorten(timestamp) { return false; }
            if let Some(session) = &mut self.status.session { session.expires_at = Some(private.clock.display.clone()); }
        }
        true
    }
    fn capability(&mut self, now: Instant, external: Reason) {
        let reason = if self.unknown {
            if self.status.session.is_some() { Reason::CleanupUnknown } else { Reason::RuntimeUnavailable }
        } else if external != Reason::None { external }
        else if self.cooldown_blocked || self.cooldown.is_some_and(|end| now < end) { Reason::RateLimited }
        else if self.private.as_ref().is_some_and(|s| s.ticket.is_some()) { Reason::Busy }
        else if let Some(reason) = self.private.as_ref().and_then(|s| s.retirement) { reason }
        else { Reason::None };
        self.status.capability.reason = reason; self.status.capability.read_only_session_available = reason == Reason::None;
    }
    /// Observe only the ORIGINAL mailbox and fixed clocks. No inspection,
    /// network, spawn, timer, join replacement or callback into the document.
    pub(crate) fn reconcile(&mut self, now: Instant, external: Reason) {
        let before = self.status.clone();
        if self.private.as_ref().is_some_and(|s| s.retirement.is_none() && now >= s.clock.end) { self.retire_inner(Reason::Expired, false); }
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
        self.capability(now, external); self.finish(before);
    }
    fn accept_final(&mut self, mut result: Result<GitHubReadOutcome, BridgeError>, settled_at: Instant, was_unknown: bool, now: Instant) {
        // This function is reached only via the actual Settled mailbox above.
        // It is also tested with explicitly supplied DATA, not a mock OS proof.
        let Some(private) = &mut self.private else { return; }; private.ticket = None;
        let mut reason = result.as_ref().map_or_else(outcome_error, |v| v.control.reason);
        if let Ok(outcome) = &result { if !self.apply_control(&outcome.control, settled_at) { reason = Reason::ResponseInvalid; } }
        if was_unknown || reason == Reason::CleanupUnknown || self.unknown { self.unknown_inner(); return; }
        if self.private.as_ref().is_some_and(|s| s.retirement.is_some()) { self.complete_retirement(); return; }
        if self.private.as_ref().is_some_and(|s| now >= s.clock.end) { self.retire_inner(Reason::Expired, false); return; }
        if reason == Reason::Expired {
            reason = Reason::NetworkUnavailable;
            if let Ok(outcome) = &mut result {
                for fact_reason in [&mut outcome.facts.account.reason, &mut outcome.facts.repository.reason, &mut outcome.facts.automation.reason] {
                    if *fact_reason == Reason::Expired { *fact_reason = Reason::NetworkUnavailable; }
                }
            }
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
            Ok(outcome) => self.accept_facts(outcome.facts),
            Err(_) => self.fact_retirement(reason),
        }
        if let Some(session) = &mut self.status.session {
            session.state = if self.status.account.state == FactState::Observed { SessionState::Connected } else { SessionState::Failed };
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
            clock, token: Some(args.token),
            account_pin: None, repository_pin: None, ticket: None, retirement: None, remove_after_settlement: false };
        let mut operation = Operation { id: String::with_capacity(64), kind: OperationKind::Connect, phase: Phase::Running, reason: Reason::None };
        let ticket = supervisor.start_github_readonly(&private.repository, None, None,
            private.token.as_deref().ok_or_else(|| refused(Reason::InvalidInput))?).map_err(admission_error)?;
        operation.id.push_str(ticket.operation_id());
        private.ticket = Some(ticket);
        self.private = Some(private); self.next_session = sequence;
        let before = self.status.clone();
        self.status.session = Some(session); self.status.operation = Some(operation);
        self.status.account = unobserved(); self.status.repository = unobserved(); self.status.automation = unobserved();
        self.capability(now, Reason::None); self.finish(before); Ok(self.snapshot())
    }
    pub(crate) fn refresh(&mut self, id: &str, revision: u32, supervisor: &Supervisor, now: Instant) -> Result<Status, BridgeError> {
        self.room()?;
        if revision != self.status.revision { return Err(refused(Reason::TargetChanged)); }
        let private = self.private.as_ref().filter(|s| s.id == id).ok_or_else(|| refused(Reason::InvalidInput))?;
        if private.ticket.is_some() { return Err(refused(Reason::Busy)); }
        if let Some(reason) = private.retirement { return Err(refused(reason)); }
        if !self.status.capability.read_only_session_available { return Err(refused(self.status.capability.reason)); }
        if now >= private.clock.end { self.retire(Reason::Expired); return Err(refused(Reason::Expired)); }
        let allowed = self.status.session.as_ref().is_some_and(|s| s.state == SessionState::Connected
            || s.state == SessionState::Failed && self.status.operation.as_ref().is_some_and(|op| op.phase == Phase::Settled && retryable(op.reason)));
        if !allowed { return Err(refused(Reason::InvalidInput)); }
        let mut operation = Operation { id: String::with_capacity(64), kind: OperationKind::Refresh, phase: Phase::Running, reason: Reason::None };
        let ticket = supervisor.start_github_readonly(&private.repository, private.account_pin.as_deref(), private.repository_pin.as_deref(),
            private.token.as_deref().ok_or_else(|| refused(Reason::Expired))?).map_err(admission_error)?;
        operation.id.push_str(ticket.operation_id());
        // There is no await or callback between the recheck and storing the
        // exact original ticket in this same document-owned state.
        if let Some(private) = &mut self.private { private.ticket = Some(ticket); }
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
