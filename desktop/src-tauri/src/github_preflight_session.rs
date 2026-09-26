//! Nonsecret preflight state embedded in the original GitHub ConnectionState.
//! No independent worker, credential, clock renewal, retry or cleanup owner.
use std::time::Instant;
use crate::{asset_source::RegisteredRoot, error::BridgeError, github_preflight_protocol as wire,
    supervisor::{GitHubPreflightReceipt, GitHubPreflightTicket}};

pub(crate) fn refused(reason: wire::Reason) -> BridgeError {
    let message = match reason {
        wire::Reason::PublisherUnconfigured => "This application has no reviewed immutable GitHub preflight toolkit binding.",
        wire::Reason::NotConnected => "Connect the selected project to GitHub before preparing a preflight.",
        wire::Reason::ConsentExpired => "The preflight review expired or was already used. Prepare a fresh review; do not retry an uncertain dispatch.",
        wire::Reason::Busy => "The original operation must settle before another preflight action.",
        wire::Reason::CleanupUnknown => "Original cleanup is unconfirmed. Keep this application open for retirement.",
        wire::Reason::Unqualified => "This build has not qualified GitHub preflight execution on this platform.",
        wire::Reason::RateLimited => "The original GitHub rate-limit interval still applies.",
        wire::Reason::Expired => "The original GitHub credential expired. Disconnect and authenticate again.",
        wire::Reason::Cancelled => "This document is no longer accepting preflight work.",
        wire::Reason::TargetChanged => "The original project, GitHub account, repository or review changed.",
        _ => "The request does not match the current supported preflight action.",
    };
    let name = serde_json::to_value(reason).ok().and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "invalid-input".into());
    BridgeError::new(&format!("github_preflight_refused_{}", name.replace('-', "_")), message)
}
pub(crate) fn connection_reason(value: crate::github_connection_protocol::Reason) -> wire::Reason {
    use crate::github_connection_protocol::Reason as R;
    match value {
        R::None => wire::Reason::None, R::Unqualified => wire::Reason::Unqualified,
        R::RuntimeUnavailable => wire::Reason::RuntimeUnavailable, R::PublisherUnconfigured => wire::Reason::PublisherUnconfigured,
        R::NotConnected => wire::Reason::NotConnected, R::Busy => wire::Reason::Busy, R::Expired => wire::Reason::Expired,
        R::RateLimited => wire::Reason::RateLimited, R::Cancelled => wire::Reason::Cancelled,
        R::CleanupUnknown => wire::Reason::CleanupUnknown, R::TargetChanged => wire::Reason::TargetChanged,
        R::Unauthorized => wire::Reason::Unauthorized, R::Forbidden => wire::Reason::Forbidden,
        R::NotFoundOrInaccessible => wire::Reason::NotFoundOrInaccessible,
        R::NetworkUnavailable => wire::Reason::NetworkUnavailable, R::TlsFailed => wire::Reason::TlsFailed,
        R::ResponseInvalid => wire::Reason::ResponseInvalid, R::ResponseLimit => wire::Reason::ResponseLimit,
        _ => wire::Reason::InvalidInput,
    }
}
pub(crate) fn outcome_reason(value: &BridgeError) -> wire::Reason {
    match value.code.as_str() {
        "cleanup_unknown" => wire::Reason::CleanupUnknown, "protocol_error" => wire::Reason::ResponseInvalid,
        "output_limit" | "stdout_limit" | "stderr_limit" => wire::Reason::ResponseLimit,
        "cancelled" | "shutting_down" => wire::Reason::Cancelled,
        "runtime_unavailable" => wire::Reason::RuntimeUnavailable, _ => wire::Reason::NetworkUnavailable,
    }
}

pub(crate) struct Active {
    pub(crate) ticket: GitHubPreflightTicket, pub(crate) request: wire::Request,
    pub(crate) session_id: String, pub(crate) project_id: String, pub(crate) generation: u32,
    pub(crate) root: RegisteredRoot,
}
pub(crate) struct Consent {
    pub(crate) prepared: wire::Prepared, pub(crate) end: Instant, pub(crate) session_id: String,
    pub(crate) project_id: String, pub(crate) generation: u32, pub(crate) root: RegisteredRoot,
}
pub(crate) struct State {
    pub(crate) view: wire::Status, pub(crate) active: Option<Active>, pub(crate) consent: Option<Consent>,
    pub(crate) exhausted: bool,
}
impl State {
    pub(crate) fn new() -> Self {
        Self { view: wire::Status { schema_version: 1, revision: 1, session_id: None, available: false,
            reason: wire::Reason::Unqualified, operation: None, prepared: None, consent_expires_at: None,
            pending: Vec::new(), run: None }, active: None, consent: None, exhausted: false }
    }
    pub(crate) fn snapshot(&self) -> wire::Status { self.view.clone() }
    pub(crate) fn finish(&mut self, before: wire::Status) {
        if self.view == before { return; }
        if self.exhausted { self.view.revision = u32::MAX; return; }
        if let Some(next) = before.revision.checked_add(1).filter(|v| *v < u32::MAX) { self.view.revision = next; }
        else { self.exhausted = true; self.unknown(); self.view.revision = u32::MAX; }
    }
    pub(crate) fn revoke_consent(&mut self) { self.consent = None; self.view.prepared = None; self.view.consent_expires_at = None; }
    pub(crate) fn expire_consent(&mut self, now: Instant) {
        if self.consent.as_ref().is_some_and(|v| now >= v.end) { self.revoke_consent(); }
    }
    pub(crate) fn stop(&mut self) {
        let before = self.snapshot(); self.revoke_consent();
        if let Some(active) = &self.active { active.ticket.stop(); }
        self.finish(before);
    }
    pub(crate) fn unknown(&mut self) {
        let before = self.snapshot(); self.revoke_consent();
        if let Some(active) = &self.active { active.ticket.stop(); }
        self.view.available = false; self.view.reason = wire::Reason::CleanupUnknown;
        if let Some(op) = &mut self.view.operation {
            if self.active.is_some() { op.phase = wire::Phase::CleanupUnknown; op.reason = wire::Reason::CleanupUnknown; }
            if op.kind == wire::Kind::Dispatch && self.active.as_ref().is_some_and(|v| v.ticket.go_claimed()) {
                op.effect = wire::Effect::PotentiallyApplied;
            }
        }
        self.finish(before);
    }
    pub(crate) fn native_work_pending(&self) -> bool { self.active.is_some() }
    pub(crate) fn receipt(&self) -> Option<GitHubPreflightReceipt> { self.active.as_ref().map(|v| v.ticket.receipt()) }
    pub(crate) fn start(&mut self, active: Active) {
        let before = self.snapshot(); self.revoke_consent(); self.view.run = None;
        self.view.operation = Some(wire::Operation { id: active.ticket.operation_id().into(), kind: active.request.kind(),
            phase: wire::Phase::Running, reason: wire::Reason::None,
            effect: if active.request.kind() == wire::Kind::Dispatch { wire::Effect::NotSent } else { wire::Effect::None } });
        self.view.session_id = Some(active.session_id.clone()); self.view.available = false; self.view.reason = wire::Reason::Busy;
        self.active = Some(active); self.finish(before);
    }
    pub(crate) fn cancel(&mut self, id: &str) -> Result<(), BridgeError> {
        let active = self.active.as_ref().filter(|v| v.ticket.operation_id() == id)
            .ok_or_else(|| refused(wire::Reason::InvalidInput))?;
        let before = self.snapshot(); active.ticket.stop(); self.revoke_consent();
        if let Some(op) = &mut self.view.operation {
            if op.phase != wire::Phase::CleanupUnknown { op.reason = wire::Reason::Cancelled; }
        }
        self.finish(before); Ok(())
    }
    pub(crate) fn record(&self, marker: &str) -> Option<&wire::PendingRecord> {
        self.view.pending.iter().find(|row| row.prepared.target.marker == marker)
    }
    pub(crate) fn retain_record(&mut self, record: wire::PendingRecord) -> Result<(), BridgeError> {
        if let Some(old) = self.view.pending.iter_mut().find(|row| row.prepared.target.marker == record.prepared.target.marker) {
            if old.prepared != record.prepared || old.run_id.is_some() && old.run_id != record.run_id {
                return Err(BridgeError::protocol());
            }
            *old = record; return Ok(());
        }
        if self.view.pending.len() >= wire::RECORD_LIMIT { return Err(BridgeError::protocol()); }
        self.view.pending.push(record); Ok(())
    }
}
