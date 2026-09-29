//! P2 state belongs to the existing ConnectionState/document, not a second
//! token, scheduler or cleanup owner. Private assignment loans never enter IPC.
use std::{sync::{Arc,Weak}, time::Instant};
use crate::{asset_session::GitHubInputMaterial, asset_source::RegisteredRoot, error::BridgeError,
    github_input_group_protocol as wire, github_runner_prerequisite_session as runner, supervisor::{GitHubInputGroupReceipt,GitHubInputGroupTicket}};

pub(crate) fn refused(reason: wire::Reason) -> BridgeError {
    let message = match reason {
        wire::Reason::Unqualified => "Whole input-group transfer is not qualified for this installed platform.",
        wire::Reason::PublisherUnconfigured => "This application has no reviewed input-group-aware toolkit binding.",
        wire::Reason::NotConnected => "Connect the selected project to GitHub before observing its input destination.",
        wire::Reason::Busy => "Wait for the original operation and its private material retirement to finish.",
        wire::Reason::CleanupUnknown => "Original cleanup is unconfirmed. Keep this application open for original retirement.",
        wire::Reason::ConsentExpired => "The one-use whole-group review expired or was consumed. Read its original status before preparing another.",
        wire::Reason::ContextStale | wire::Reason::AssignmentUnavailable => "The original assigned input or release context changed. Review and assign it again.",
        wire::Reason::RunnerUnverified => "Check runner safety for the current project context before preparing this input group.",
        wire::Reason::RunnerCollision => "A self-hosted runner uses ubuntu-24.04 or macos-26. Remove that label before trying again; organization checks include every organization and inherited group.",
        wire::Reason::ResponseLimit => "The response exceeded a fixed size or complexity limit. Runner checks allow at most 8 complete groups and 100 runners per list; nothing was omitted.",
        wire::Reason::EnvironmentUnready => "The required source-bound environment protection is not verified. No input update is available.",
        wire::Reason::DestinationLimit => "The complete input or original native memory allowance is too large. Nothing was split or omitted.",
        wire::Reason::RateLimited => "The original GitHub rate-limit interval still applies.",
        wire::Reason::Expired => "The original GitHub credential expired. Authenticate again after original retirement.",
        wire::Reason::Cancelled => "This document is no longer accepting input-group operations.",
        wire::Reason::TargetChanged => "The original project, account, repository or review changed.",
        _ => "The request does not match the current supported whole input-group operation.",
    };
    let code = serde_json::to_value(reason).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_else(|| "invalid-input".into());
    BridgeError::new(&format!("github_input_group_refused_{}",code.replace('-',"_")),message)
}
pub(crate) fn connection_reason(reason: crate::github_connection_protocol::Reason) -> wire::Reason {
    use crate::github_connection_protocol::Reason as R;
    match reason {
        R::None => wire::Reason::None, R::Unqualified => wire::Reason::Unqualified,
        R::RuntimeUnavailable => wire::Reason::RuntimeUnavailable, R::PublisherUnconfigured => wire::Reason::PublisherUnconfigured,
        R::NotConnected => wire::Reason::NotConnected, R::Busy => wire::Reason::Busy, R::Expired => wire::Reason::Expired,
        R::RateLimited => wire::Reason::RateLimited, R::Cancelled => wire::Reason::Cancelled, R::Stale => wire::Reason::Stale,
        R::CleanupUnknown => wire::Reason::CleanupUnknown, R::TargetChanged => wire::Reason::TargetChanged,
        R::Unauthorized => wire::Reason::Unauthorized, R::Forbidden => wire::Reason::Forbidden,
        R::NotFoundOrInaccessible => wire::Reason::NotFoundOrInaccessible,
        R::NetworkUnavailable => wire::Reason::NetworkUnavailable, R::TlsFailed => wire::Reason::TlsFailed,
        R::ResponseInvalid => wire::Reason::ResponseInvalid, R::ResponseLimit => wire::Reason::ResponseLimit,
        _ => wire::Reason::InvalidInput,
    }
}
pub(crate) fn outcome_reason(error: &BridgeError) -> wire::Reason {
    if let Some(code) = error.code.strip_prefix("github_input_group_refused_") {
        let reason = match code {
            "none" => wire::Reason::None, "unqualified" => wire::Reason::Unqualified,
            "runtime_unavailable" => wire::Reason::RuntimeUnavailable, "publisher_unconfigured" => wire::Reason::PublisherUnconfigured,
            "not_connected" => wire::Reason::NotConnected, "invalid_input" => wire::Reason::InvalidInput, "busy" => wire::Reason::Busy,
            "unauthorized" => wire::Reason::Unauthorized, "forbidden" => wire::Reason::Forbidden,
            "not_found_or_inaccessible" => wire::Reason::NotFoundOrInaccessible, "target_changed" => wire::Reason::TargetChanged,
            "rate_limited" => wire::Reason::RateLimited, "network_unavailable" => wire::Reason::NetworkUnavailable,
            "tls_failed" => wire::Reason::TlsFailed, "response_invalid" => wire::Reason::ResponseInvalid,
            "response_limit" => wire::Reason::ResponseLimit, "expired" => wire::Reason::Expired, "stale" => wire::Reason::Stale,
            "cancelled" => wire::Reason::Cancelled, "cleanup_unknown" => wire::Reason::CleanupUnknown,
            "context_stale" => wire::Reason::ContextStale, "assignment_unavailable" => wire::Reason::AssignmentUnavailable,
            "config_mismatch" => wire::Reason::ConfigMismatch, "caller_incompatible" => wire::Reason::CallerIncompatible,
            "environment_unready" => wire::Reason::EnvironmentUnready, "runner_unverified" => wire::Reason::RunnerUnverified,
            "runner_collision" => wire::Reason::RunnerCollision, "input_invalid" => wire::Reason::InputInvalid,
            "destination_limit" => wire::Reason::DestinationLimit, "sealing_unavailable" => wire::Reason::SealingUnavailable,
            "consent_expired" => wire::Reason::ConsentExpired, "source_changed" => wire::Reason::SourceChanged,
            "metadata_changed" => wire::Reason::MetadataChanged, "journal_incomplete" => wire::Reason::JournalIncomplete,
            _ => wire::Reason::ResponseInvalid,
        };
        return reason;
    }
    match error.code.as_str() {
        "cleanup_unknown" => wire::Reason::CleanupUnknown, "protocol_error" => wire::Reason::ResponseInvalid,
        "output_limit" | "stdout_limit" | "stderr_limit" => wire::Reason::ResponseLimit,
        "cancelled" | "shutting_down" => wire::Reason::Cancelled,
        "runtime_unavailable" => wire::Reason::RuntimeUnavailable,
        "github_input_group_refused_runner_unverified" => wire::Reason::RunnerUnverified,
        "github_input_group_refused_consent_expired" => wire::Reason::ConsentExpired,
        "github_input_group_refused_assignment_unavailable" => wire::Reason::AssignmentUnavailable,
        "github_input_group_refused_sealing_unavailable" => wire::Reason::SealingUnavailable,
        _ => wire::Reason::NetworkUnavailable,
    }
}

pub(crate) struct Active {
    pub(crate) ticket: GitHubInputGroupTicket, pub(crate) request: wire::Request,
    pub(crate) session_id: String, pub(crate) project_id: String, pub(crate) generation: u32, pub(crate) root: RegisteredRoot,
    pub(crate) material: Option<Arc<GitHubInputMaterial>>, pub(crate) material_revoked: bool,
    pub(crate) runner: Option<runner::BoundRunner>,
    pub(crate) admitted_at: Instant, pub(crate) consent_end: Option<Instant>, pub(crate) control_observed: bool, pub(crate) reply_control_observed: bool,
}
pub(crate) struct Consent {
    pub(crate) prepared: wire::Prepared, pub(crate) end: Instant, pub(crate) session_id: String,
    pub(crate) project_id: String, pub(crate) generation: u32, pub(crate) root: RegisteredRoot,
    pub(crate) material: Arc<GitHubInputMaterial>, pub(crate) revoked: bool, pub(crate) runner: Option<runner::BoundRunner>,
}
/// One former consent plus one finished active loan. Overflow never discards
/// a private Arc: its old active/consent slot remains retained and unavailable.
#[derive(Default)]
pub(crate) struct MaterialRetirement { slots: [Option<Arc<GitHubInputMaterial>>;2], registration: Option<(u64,Weak<()>)> }
/// Constructed only AFTER the original off-lock book has actually been dropped.
/// Neither Clone nor an IPC/native-completion Boolean is a disposal receipt.
pub(crate) struct MaterialRetired { registration: Option<(u64,Weak<()>)> }
struct DeferredFinality { operation: Option<wire::Operation>, record: Option<(String,wire::Completion)> }
impl MaterialRetirement {
    pub(crate) fn empty(&self) -> bool { self.slots.iter().all(Option::is_none) }
    pub(crate) fn dispose(mut self) -> MaterialRetired {
        let registration=self.registration.take();
        drop(self); // Actual original Arc disposal, outside the document gate.
        MaterialRetired {registration}
    }
    fn retain(&mut self, material: Arc<GitHubInputMaterial>) -> Result<(),Arc<GitHubInputMaterial>> {
        if let Some(slot) = self.slots.iter_mut().find(|slot| slot.is_none()) { *slot = Some(material); Ok(()) }
        else { Err(material) }
    }
}
pub(crate) struct State {
    pub(crate) view: wire::Status, pub(crate) active: Option<Active>, pub(crate) consent: Option<Consent>,
    pub(crate) exhausted: bool, pub(crate) records: Vec<wire::PrivateRecord>, retirement: MaterialRetirement,
    pub(crate) runner: runner::State,
    retirement_generation: u64, retirement_in_flight: Option<(u64,Weak<()>)>, deferred_finality: Option<DeferredFinality>,
}
impl State {
    pub(crate) fn new() -> Self {
        Self { view: wire::Status { schema_version:1,revision:1,session_id:None,available:false,reason:wire::Reason::Unqualified,
            operation:None,prepared:None,records:Vec::new(),observation:None,runner:None }, active:None,consent:None,exhausted:false,runner:runner::State::default(),
            records:Vec::new(),retirement:MaterialRetirement::default(),retirement_generation:0,retirement_in_flight:None,deferred_finality:None }
    }
    pub(crate) fn snapshot(&self) -> wire::Status { self.view.clone() }
    pub(crate) fn finish(&mut self, before: wire::Status) {
        if self.view == before { return; }
        if self.exhausted { self.view.revision = u32::MAX; return; }
        if let Some(next) = before.revision.checked_add(1).filter(|v| *v < u32::MAX) { self.view.revision = next; }
        else { self.exhausted = true; self.mark_unknown(); self.view.revision = u32::MAX; }
    }
    pub(crate) fn material_settled(&self) -> bool {
        self.consent.is_none() && self.active.as_ref().is_none_or(|v| v.material.is_none()) && !self.retirement_pending()
    }
    pub(crate) fn retirement_pending(&self) -> bool {
        !self.retirement.empty() || self.retirement_in_flight.is_some() || self.deferred_finality.is_some()
    }
    pub(crate) fn take_retirement(&mut self,document:&Arc<()>) -> MaterialRetirement {
        if self.retirement.empty() { return MaterialRetirement::default(); }
        if self.retirement_in_flight.is_some() { self.unknown(); return MaterialRetirement::default(); }
        let Some(generation)=self.retirement_generation.checked_add(1) else {
            self.exhausted=true; self.unknown(); return MaterialRetirement::default();
        };
        self.retirement_generation=generation;
        let registration=(generation,Arc::downgrade(document));self.retirement_in_flight=Some(registration.clone());
        let mut book=std::mem::take(&mut self.retirement);book.registration=Some(registration);book
    }
    /// Stage only public positive terminal DATA. Original native process/IO
    /// settlement is already observed, but its action-loan drop is still owed.
    pub(crate) fn defer_material_finality(&mut self,operation_id:Option<&str>,marker:Option<&str>) {
        if self.retirement.empty() { return; }
        if self.deferred_finality.is_some() || self.retirement_in_flight.is_some() { self.unknown(); return; }
        let operation=if let Some(id)=operation_id {
            let Some(op)=self.view.operation.as_ref().filter(|op|op.id==id).cloned() else {self.unknown();return;};
            if op.phase==wire::Phase::CleanupUnknown {return;}
            if op.phase!=wire::Phase::Settled {self.unknown();return;}
            Some(op)
        } else {
            // A failed admission has no new original native ticket. Defer its
            // NotAttempted row only; do not relabel the previous Prepare ticket.
            if marker.is_none() {self.unknown();return;} None
        };
        if self.view.prepared.is_some() || self.view.observation.is_some() {self.unknown();return;}
        self.view.available=false;self.view.reason=wire::Reason::Busy;
        let record=if let Some(marker)=marker {
            let Some(row)=self.view.records.iter_mut().find(|row|row.original_operation_id==marker) else {self.unknown();return;};
            let desired=(marker.to_owned(),row.completion.clone());
            if row.completion.cleanup==wire::Settlement::Confirmed {row.completion.cleanup=wire::Settlement::Pending;}
            if row.completion.finality==wire::Finality::Settled {row.completion.finality=wire::Finality::Pending;}
            Some(desired)
        } else {None};
        if operation.is_some() {if let Some(op)=&mut self.view.operation {op.phase=wire::Phase::Running;}}
        self.deferred_finality=Some(DeferredFinality {operation,record});
    }
    pub(crate) fn finish_retirement(&mut self,receipt:MaterialRetired) {
        let Some((generation,document))=receipt.registration else {return;};
        let before=self.snapshot();
        if !self.retirement_in_flight.as_ref().is_some_and(|(original,identity)|*original==generation && Weak::ptr_eq(identity,&document)) {
            self.mark_unknown();self.finish(before);return;
        }
        self.retirement_in_flight=None;
        if let Some(deferred)=self.deferred_finality.take() {
            let mut unknown=self.exhausted || self.view.reason==wire::Reason::CleanupUnknown;
            if let Some(operation)=deferred.operation {
                let Some(op)=self.view.operation.as_mut().filter(|op|op.id==operation.id && op.kind==operation.kind) else {
                    self.mark_unknown();self.finish(before);return;
                };
                unknown=unknown || op.phase==wire::Phase::CleanupUnknown;
                if unknown {op.phase=wire::Phase::CleanupUnknown;op.reason=wire::Reason::CleanupUnknown;}
                else {op.phase=operation.phase;}
            }
            if let Some((marker,completion))=deferred.record {
                let Some(row)=self.view.records.iter_mut().find(|row|row.original_operation_id==marker) else {
                    self.mark_unknown();self.finish(before);return;
                };
                if unknown {row.completion.cleanup=wire::Settlement::Unknown;row.completion.finality=wire::Finality::Unknown;row.reason=wire::Reason::CleanupUnknown;}
                else {
                    // Never erase a newer unknown/control/remote/journal fact.
                    if row.completion.cleanup==wire::Settlement::Pending {row.completion.cleanup=completion.cleanup;}
                    if row.completion.finality==wire::Finality::Pending {row.completion.finality=completion.finality;}
                }
            }
        }
        self.finish(before);
    }
    pub(crate) fn materials(&self) -> impl Iterator<Item=&Arc<GitHubInputMaterial>> {
        self.consent.iter().map(|v| &v.material).chain(self.active.iter().filter_map(|v| v.material.as_ref()))
            .chain(self.retirement.slots.iter().filter_map(Option::as_ref))
    }
    pub(crate) fn memory_reserved(&self) -> bool {
        // The same fixed working row covers bounded action DATA/history as well
        // as active buffers. No quota reset at Prepare -> consent -> Apply.
        self.active.is_some() || !self.material_settled() || self.records.capacity() != 0 || self.view.records.capacity() != 0
            || self.view.operation.is_some() || self.view.prepared.is_some() || self.view.observation.is_some()
            || self.runner.reserved() || self.view.runner.is_some()
    }
    pub(crate) fn memory_capacity(&self) -> usize {
        // Status can expose the original connection session before any P2 work
        // is admitted. Its small native String backing is still counted, but
        // polling status alone must not silently reserve an unadmitted work row.
        if self.memory_reserved() { wire::WORKING_RESERVATION }
        else { self.view.session_id.as_ref().map_or(0, String::capacity) }
    }
    pub(crate) fn revoke_consent(&mut self) {
        self.view.prepared = None;
        if let Some(mut consent) = self.consent.take() {
            consent.revoked = true;
            match self.retirement.retain(consent.material.clone()) {
                Ok(()) => {}, // Registered book owns it before this Arc drops.
                Err(material) => { drop(material); self.consent = Some(consent); self.exhausted = true; }
            }
        }
    }
    pub(crate) fn expire_consent(&mut self, now: Instant) {
        if self.runner.expire(now,&mut self.view.runner) { self.revoke_consent(); }
        if self.consent.as_ref().is_some_and(|v| now >= v.end || v.revoked) { self.revoke_consent(); }
    }
    pub(crate) fn revoke_runner(&mut self, reason: wire::Reason) {
        let before=self.snapshot(); self.runner.invalidate(reason,&mut self.view.runner); self.revoke_consent();
        if let Some(active)=self.active.as_mut().filter(|v|v.request.kind()==wire::Kind::Apply) {
            active.material_revoked=true; active.ticket.stop();
        }
        self.finish(before);
    }
    pub(crate) fn revoke_material(&mut self) {
        let before = self.snapshot(); self.revoke_consent();
        if let Some(active) = self.active.as_mut().filter(|v| v.material.is_some()) { active.material_revoked = true; active.ticket.stop(); }
        self.finish(before);
    }
    pub(crate) fn stop(&mut self) {
        let before = self.snapshot(); self.revoke_consent(); self.runner.invalidate(wire::Reason::Cancelled,&mut self.view.runner);
        if let Some(active) = &mut self.active { active.material_revoked = true; active.ticket.stop(); }
        self.finish(before);
    }
    fn mark_unknown(&mut self) {
        self.runner.invalidate(wire::Reason::CleanupUnknown,&mut self.view.runner);
        if self.runner.active.is_some() {
            if let Some(op)=&mut self.view.operation {op.phase=wire::Phase::CleanupUnknown;op.reason=wire::Reason::CleanupUnknown;}
        }
        self.revoke_consent(); self.view.available = false; self.view.reason = wire::Reason::CleanupUnknown;
        if let Some(deferred)=&self.deferred_finality {
            if let Some(operation)=&deferred.operation {
                if let Some(op)=self.view.operation.as_mut().filter(|op|op.id==operation.id) {op.phase=wire::Phase::CleanupUnknown;op.reason=wire::Reason::CleanupUnknown;}
            }
            if let Some((marker,_))=&deferred.record {
                if let Some(row)=self.view.records.iter_mut().find(|row|&row.original_operation_id==marker) {
                    row.completion.cleanup=wire::Settlement::Unknown;row.completion.finality=wire::Finality::Unknown;row.reason=wire::Reason::CleanupUnknown;
                }
            }
        }
        if let Some(active) = &mut self.active {
            active.material_revoked = true; active.ticket.stop();
            if let Some(op) = &mut self.view.operation { op.phase = wire::Phase::CleanupUnknown; op.reason = wire::Reason::CleanupUnknown; }
            if active.request.kind() == wire::Kind::Apply {
                if let Some(marker) = active.request.action.as_ref().map(|a| a.target.marker.as_str()) {
                    if let Some(row) = self.view.records.iter_mut().find(|r| r.original_operation_id == marker) {
                        if active.ticket.go_claimed() && row.write == wire::RemoteWrite::NotAttempted { row.write = wire::RemoteWrite::AttemptedOutcomeUnknown; }
                        row.completion.cleanup = wire::Settlement::Unknown; row.completion.finality = wire::Finality::Unknown;
                        row.reason = wire::Reason::CleanupUnknown;
                    }
                }
            }
        }
    }
    pub(crate) fn unknown(&mut self) { let before = self.snapshot(); self.mark_unknown(); self.finish(before); }
    pub(crate) fn native_work_pending(&self) -> bool { self.active.is_some() || self.runner.active.is_some() }
    pub(crate) fn receipt(&self) -> Option<GitHubInputGroupReceipt> { self.active.as_ref().map(|v| v.ticket.receipt()) }
    pub(crate) fn start(&mut self, active: Active) {
        let before = self.snapshot(); self.view.prepared = None; self.view.observation = None;
        self.view.session_id = Some(active.session_id.clone()); self.view.available = false; self.view.reason = wire::Reason::Busy;
        self.view.operation = Some(wire::Operation { id:active.ticket.operation_id().into(),kind:active.request.kind().into(),
            phase:wire::Phase::Running,reason:wire::Reason::None });
        self.active = Some(active); self.finish(before);
    }
    pub(crate) fn take_finished(&mut self) -> Option<Active> {
        let mut active = self.active.take()?;
        if let Some(material) = active.material.take() {
            if self.consent.as_ref().is_some_and(|v| !v.revoked && Arc::ptr_eq(&v.material,&material)) {
                // Exact Arc has transferred into the registered consent. This
                // clone cannot be the final private backing under the gate.
                drop(material); return Some(active);
            }
            if let Err(material) = self.retirement.retain(material) {
                active.material = Some(material); self.active = Some(active); self.mark_unknown(); return None;
            }
        }
        Some(active)
    }
    pub(crate) fn cancel(&mut self, id: &str) -> Result<(),BridgeError> {
        if self.runner.active.as_ref().is_some_and(|active|active.ticket.operation_id()==id) {
            let before=self.snapshot();self.runner.invalidate(wire::Reason::Cancelled,&mut self.view.runner);self.revoke_consent();
            if let Some(operation)=&mut self.view.operation {if operation.phase!=wire::Phase::CleanupUnknown {operation.reason=wire::Reason::Cancelled;}}
            self.finish(before);return Ok(());
        }
        if !self.active.as_ref().is_some_and(|v| v.ticket.operation_id() == id) { return Err(refused(wire::Reason::InvalidInput)); }
        let before = self.snapshot(); self.revoke_consent();
        if let Some(active) = &mut self.active { active.material_revoked = true; active.ticket.stop(); }
        if let Some(op) = &mut self.view.operation { if op.phase != wire::Phase::CleanupUnknown { op.reason = wire::Reason::Cancelled; } }
        self.finish(before); Ok(())
    }
    pub(crate) fn record(&self, marker: &str) -> Option<&wire::PrivateRecord> {
        self.records.iter().find(|r| r.prepared.target.marker == marker)
    }
    pub(crate) fn retain_record(&mut self, record: wire::PrivateRecord, completion: wire::Completion, reason: wire::Reason) -> Result<(),BridgeError> {
        if !record.valid() || !record.prepared.public_record_fits() { return Err(BridgeError::protocol()); }
        let marker = &record.prepared.target.marker;
        if let Some(index) = self.records.iter().position(|r| &r.prepared.target.marker == marker) {
            let old = &mut self.records[index];
            let public = self.view.records.get_mut(index).filter(|v| &v.original_operation_id == marker).ok_or_else(BridgeError::protocol)?;
            if old.prepared != record.prepared || old.intent_sha256 != record.intent_sha256 { return Err(BridgeError::protocol()); }
            // A later missing/failed journal or RESULT cannot erase a correlated
            // authenticated 201/204 (or an explicit rejection) already observed.
            if public.write.observed() && public.write != record.write {
                if record.write.observed() { return Err(BridgeError::protocol()); }
            } else { old.write = record.write.clone(); public.write = record.write; }
            public.completion = completion; public.reason = reason;
            return Ok(());
        }
        if self.records.len() >= wire::RECORD_LIMIT || self.view.records.len() != self.records.len() { return Err(BridgeError::protocol()); }
        for capacity in [self.records.capacity(),self.view.records.capacity()] { if capacity > wire::RECORD_LIMIT { return Err(BridgeError::protocol()); } }
        self.records.try_reserve_exact(1).map_err(|_| BridgeError::protocol())?;
        self.view.records.try_reserve_exact(1).map_err(|_| BridgeError::protocol())?;
        if self.records.capacity() > wire::RECORD_LIMIT || self.view.records.capacity() > wire::RECORD_LIMIT { return Err(BridgeError::protocol()); }
        self.view.records.push(wire::PublicRecord { original_operation_id:marker.clone(),target:record.prepared.public_target(),
            write:record.write.clone(),completion,reason }); self.records.push(record); Ok(())
    }
    pub(crate) fn observe_remote(&mut self, marker: &str, write: &wire::RemoteWrite) -> Result<(),BridgeError> {
        if !write.valid() || matches!(write,wire::RemoteWrite::NotAttempted) { return Err(BridgeError::protocol()); }
        let index = self.records.iter().position(|r| r.prepared.target.marker == marker).ok_or_else(BridgeError::protocol)?;
        let row = self.view.records.get_mut(index).ok_or_else(BridgeError::protocol)?;
        if row.write.observed() && row.write != *write { return Err(BridgeError::protocol()); }
        row.write = write.clone(); self.records[index].write = write.clone(); Ok(())
    }
    pub(crate) fn reset_session_view(&mut self) {
        // Called only after current native owners settle. On-disk history is
        // not deleted; load it under its original target in the new session.
        let before = self.snapshot(); self.revoke_consent();
        // Release metadata Vec backing too: clear() would leave an empty
        // allocation alive after the action/history allowance became idle.
        self.records = Vec::new(); self.view.records = Vec::new(); self.view.observation = None;
        self.runner=runner::State::default();self.view.runner=None;
        self.view.operation = None; self.view.session_id = None; self.finish(before);
    }
}

#[cfg(test)]
#[path = "github_input_group_session_tests.rs"]
mod tests;
