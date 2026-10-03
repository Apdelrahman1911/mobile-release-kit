//! Nonsecret release state embedded in the original GitHub ConnectionState.
//! No independent worker, credential, clock renewal, retry or cleanup owner.
use std::time::Instant;
use crate::{asset_source::RegisteredRoot, error::BridgeError, github_release_protocol as wire,
    supervisor::{GitHubReleaseReceipt, GitHubReleaseTicket}};

pub(crate) fn refused(reason: wire::Reason) -> BridgeError {
    let message = match reason {
        wire::Reason::PublisherUnconfigured => "This application has no reviewed immutable GitHub release toolkit binding.",
        wire::Reason::NotConnected => "Connect the selected project to GitHub before preparing a release.",
        wire::Reason::ConsentExpired => "The release review expired or was already used. Prepare a fresh review; do not retry an uncertain dispatch.",
        wire::Reason::Busy => "The original operation must settle before another release action.",
        wire::Reason::CleanupUnknown => "Original cleanup is unconfirmed. Keep this application open for retirement.",
        wire::Reason::Unqualified => "This build has not qualified GitHub release execution on this platform.",
        wire::Reason::RateLimited => "The original GitHub rate-limit interval still applies.",
        wire::Reason::Expired => "The original GitHub credential expired. Disconnect and authenticate again.",
        wire::Reason::Cancelled => "This document is no longer accepting release work.",
        wire::Reason::TargetChanged => "The original project, GitHub account, repository or review changed.",
        _ => "The request does not match the current supported release action.",
    };
    let name = serde_json::to_value(reason).ok().and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "invalid-input".into());
    BridgeError::new(&format!("github_release_refused_{}", name.replace('-', "_")), message)
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
    pub(crate) ticket: GitHubReleaseTicket, pub(crate) request: wire::Request,
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
    pub(crate) fn receipt(&self) -> Option<GitHubReleaseReceipt> { self.active.as_ref().map(|v| v.ticket.receipt()) }
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

// Read-only retained DATA capacities for the document installation census.
// Inline structs are charged by their owner. No clone, serializer, authority,
// credential copy, allocation, native call or settlement transition occurs here.
impl State {
    pub(crate) fn retained_heap_bytes_if_quiescent(&self) -> Option<usize> {
        // A native ticket is opaque even if a copied status looks terminal.
        // Conversely a remote uncertain effect does not erase its journal.
        if self.active.is_some() || self.exhausted || self.view.reason == wire::Reason::CleanupUnknown
            || self.view.operation.as_ref().is_some_and(|operation|
                operation.phase != wire::Phase::Settled || operation.reason == wire::Reason::CleanupUnknown) {
            return None;
        }
        let mut bytes = self.view.retained_heap_bytes()?;
        if let Some(consent) = &self.consent {
            // This is a separate owned Prepared, not an alias of view.prepared.
            bytes = bytes.checked_add(consent.prepared.retained_heap_bytes()?)?
                .checked_add(consent.session_id.capacity())?.checked_add(consent.project_id.capacity())?
                .checked_add(consent.root.path.capacity())?;
        }
        Some(bytes)
    }
}

#[cfg(all(test, any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
mod installation_memory_capacity_tests {
    use super::*;
    // Invalid path/empty review text is intentional inert allocation DATA. It
    // cannot pass a wire/domain gate and constructs no native ticket or permit.
    fn prepared(cap: usize) -> wire::Prepared { wire::Prepared { target: wire::Target { project_binding: String::with_capacity(cap), repository: String::with_capacity(cap), account_id: String::with_capacity(cap), repository_id: String::with_capacity(cap), branch: String::with_capacity(cap), tooling_repository: String::with_capacity(cap), tooling_sha: String::with_capacity(cap), marker: String::with_capacity(cap), platform: wire::Platform::Android, selection: wire::Selection { stage: wire::Stage::Candidate, candidate_run_id: None, external_run_id: None, recovery_run_id: None, original_source_sha: None, original_version: None, recovery_confirmation: None } }, source_sha: String::with_capacity(cap), source_tree: String::with_capacity(cap), workflow_id: String::with_capacity(cap), workflow_path: String::with_capacity(cap), caller_sha256: String::with_capacity(cap), observed_at: String::with_capacity(cap), expected_ref: String::with_capacity(cap), display_title: String::with_capacity(cap), config_sha256: String::with_capacity(cap), version_source: String::with_capacity(cap), version_sha256: String::with_capacity(cap), environment: String::with_capacity(cap), confirmation: String::with_capacity(cap), original_assurance: String::with_capacity(cap), current_version: wire::Version { name: String::with_capacity(cap), build: 1 },
            destination: wire::Destination { application_id: String::with_capacity(cap), destination: String::with_capacity(cap), assurance: String::with_capacity(cap) },
            checklist: Vec::with_capacity(4) } }
    #[test]
    fn consent_journal_and_run_all_keep_their_distinct_capacity_charges() {
        let mut state = State::new(); state.view.prepared = Some(prepared(17));
        let before = state.retained_heap_bytes_if_quiescent().unwrap();
        let consent = Consent { prepared: prepared(29), end: Instant::now(),
            session_id: String::with_capacity(91), project_id: String::with_capacity(93), generation: 0,
            root: RegisteredRoot { path: std::path::PathBuf::with_capacity(4097),
                identity: crate::asset_source::ProjectIdentity::Posix(crate::asset_source::DirectoryIdentity::synthetic_evidence_identity()) } };
        let consent_bytes = consent.prepared.retained_heap_bytes().unwrap() + consent.session_id.capacity()
            + consent.project_id.capacity() + consent.root.path.capacity();
        state.consent = Some(consent);
        assert_eq!(state.retained_heap_bytes_if_quiescent(), Some(before + consent_bytes));
        let row = wire::PendingRecord { prepared: prepared(47), run_id: Some(String::with_capacity(97)) };
        let row_bytes = row.prepared.retained_heap_bytes().unwrap() + row.run_id.as_ref().unwrap().capacity();
        state.view.pending.reserve_exact(3); state.view.pending.push(row);
        let journal = state.view.pending.capacity() * std::mem::size_of::<wire::PendingRecord>() + row_bytes;
        assert_eq!(state.retained_heap_bytes_if_quiescent(), Some(before + consent_bytes + journal));
        let mut run = wire::Run { id: String::with_capacity(101), attempt: 1, status: wire::RunStatus::Queued,
            conclusion: None, observed_at: String::with_capacity(103), jobs: Vec::with_capacity(3),
            url: String::with_capacity(107), assurance: String::with_capacity(109) };
        run.jobs.push(wire::Job { id: String::with_capacity(113), kind: wire::JobKind::InputGuard,
            status: wire::RunStatus::Queued, conclusion: None });
        let run_bytes = run.id.capacity() + run.observed_at.capacity() + run.url.capacity()
            + run.assurance.capacity() + run.jobs.capacity() * std::mem::size_of::<wire::Job>() + run.jobs[0].id.capacity();
        state.view.run = Some(run);
        assert_eq!(state.retained_heap_bytes_if_quiescent(), Some(before + consent_bytes + journal + run_bytes));
    }
    #[test]
    fn release_selection_options_and_checklist_rows_are_not_flat_wire_sizes() {
        let mut value = prepared(7); let before = value.retained_heap_bytes().unwrap();
        value.target.selection.candidate_run_id = Some(String::with_capacity(17));
        value.target.selection.external_run_id = Some(String::with_capacity(19));
        value.target.selection.recovery_run_id = Some(String::with_capacity(23));
        value.target.selection.original_source_sha = Some(String::with_capacity(29));
        value.target.selection.original_version = Some(wire::Version { name: String::with_capacity(31), build: 1 });
        value.target.selection.recovery_confirmation = Some(String::with_capacity(347));
        let selection = [&value.target.selection.candidate_run_id, &value.target.selection.external_run_id,
            &value.target.selection.recovery_run_id, &value.target.selection.original_source_sha, &value.target.selection.recovery_confirmation].iter()
            .map(|entry| entry.as_ref().unwrap().capacity()).sum::<usize>()
            + value.target.selection.original_version.as_ref().unwrap().name.capacity();
        let row = wire::Requirement { name: String::with_capacity(37), kind: String::with_capacity(41), reason: String::with_capacity(43) };
        let row_bytes = row.name.capacity() + row.kind.capacity() + row.reason.capacity();
        value.checklist.push(row); // Uses its pre-existing spare allocation.
        assert_eq!(value.retained_heap_bytes(), Some(before + selection + row_bytes));
    }
    #[test]
    fn remote_uncertain_effect_is_counted_but_cleanup_unknown_is_not_promoted() {
        let mut state = State::new();
        state.view.operation = Some(wire::Operation { id: String::with_capacity(31), kind: wire::Kind::Dispatch,
            phase: wire::Phase::Settled, reason: wire::Reason::UnresolvedRun, effect: wire::Effect::PotentiallyApplied });
        state.view.pending.push(wire::PendingRecord { prepared: prepared(19), run_id: None });
        assert!(state.retained_heap_bytes_if_quiescent().is_some());
        state.view.operation.as_mut().unwrap().phase = wire::Phase::CleanupUnknown;
        assert!(state.retained_heap_bytes_if_quiescent().is_none());
        assert_eq!(state.view.pending.len(), 1);
        assert_eq!(state.view.operation.as_ref().unwrap().effect, wire::Effect::PotentiallyApplied);
        state.view.operation.as_mut().unwrap().phase = wire::Phase::Settled;
        state.exhausted = true; assert!(state.retained_heap_bytes_if_quiescent().is_none());
    }
}
