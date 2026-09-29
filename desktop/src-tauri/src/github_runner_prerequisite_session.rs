//! Ephemeral runner evidence inside the original ConnectionState input book.
//! No token, payload, filesystem path reload, persisted grant or second owner.
use std::{sync::Arc, time::{Duration, Instant}};
use crate::{asset_session::{GitHubInputMaterial, GitHubRunnerContext}, asset_source::RegisteredRoot,
    error::BridgeError, github_input_group_protocol as input, github_input_group_session::refused,
    github_runner_prerequisite_protocol as wire,
    supervisor::{GitHubRunnerTicket, GitHubRunnerResult, GitHubRunnerObservedControl, OPERATION_TIME}};

#[derive(Clone)]
pub(crate) struct Binding {
    pub(crate) context: Arc<GitHubRunnerContext>, pub(crate) scope: input::PendingScope,
    pub(crate) session_id: String, pub(crate) project_id: String,
}
pub(crate) struct Active {
    pub(crate) ticket: GitHubRunnerTicket, pub(crate) binding: Binding, pub(crate) credential_end: Instant,
    pub(crate) control_observed: bool, pub(crate) revoked: Option<input::Reason>,
}
pub(crate) struct Evidence { binding: Binding, facts: wire::Facts, end: Instant, tooling_sha: &'static str }
pub(crate) struct BoundRunner { evidence: Arc<Evidence>, prepared: input::Prepared }
#[derive(Default)]
pub(crate) struct State { pub(crate) active: Option<Active>, pub(crate) observation: Option<Arc<Evidence>> }

fn observation_end(admitted: Instant, credential_end: Instant) -> Option<Instant> {
    admitted.checked_add(Duration::from_secs(wire::OBSERVATION_SECONDS)).map(|v| v.min(credential_end))
}
fn original_times(admitted: Instant, observed: Instant, settled: Instant, now: Instant, credential_end: Instant) -> bool {
    admitted <= observed && observed <= settled && settled <= now && now < credential_end
        && admitted.checked_add(OPERATION_TIME).is_some_and(|end| settled < end.min(credential_end))
        && observation_end(admitted,credential_end).is_some_and(|end| now < end)
}
impl Evidence {
    /// Takes the private consuming result type whose constructor is confined to
    /// the original Supervisor. Supplying a decoded Reply is insufficient.
    pub(crate) fn from_original(result: GitHubRunnerResult, active: &Active,
        observed: &GitHubRunnerObservedControl, now: Instant, credential_end: Instant) -> Result<Arc<Self>, BridgeError> {
        if result.was_unknown || !result.belongs_to(&active.ticket) { return Err(refused(input::Reason::CleanupUnknown)); }
        let reply = result.outcome?;
        if reply.reason != input::Reason::None { return Err(refused(reply.reason)); }
        let admitted = active.ticket.admitted_at();
        if let Some(reason)=active.revoked { return Err(refused(reason)); }
        if !active.control_observed || !original_times(admitted, observed.observed_at, result.settled_at, now,
            credential_end.min(active.credential_end)) { return Err(refused(input::Reason::Expired)); }
        if reply.network_cleanup != input::Settlement::Confirmed || observed.control != reply.control
            || reply.control.reason != crate::github_connection_protocol::Reason::None { return Err(refused(input::Reason::CleanupUnknown)); }
        let facts = reply.facts.ok_or_else(BridgeError::protocol)?;
        if facts.account_id != active.binding.scope.account_id || facts.repository_id != active.binding.scope.repository_id
            || !facts.repository.eq_ignore_ascii_case(&active.binding.scope.repository) { return Err(refused(input::Reason::TargetChanged)); }
        let tooling_sha = input::TOOLING_SHA.filter(|_| input::publisher_bound()).ok_or_else(|| refused(input::Reason::PublisherUnconfigured))?;
        let end = observation_end(admitted,credential_end.min(active.credential_end)).ok_or_else(BridgeError::protocol)?;
        Ok(Arc::new(Self { binding: active.binding.clone(), facts, end, tooling_sha }))
    }
    pub(crate) fn end(&self) -> Instant { self.end }
    pub(crate) fn context(&self) -> &Arc<GitHubRunnerContext> { &self.binding.context }
    pub(crate) fn summary(&self, expires: String) -> wire::Summary { self.facts.summary(expires) }
    pub(crate) fn current(&self, session: &str, project: &str, scope: &input::PendingScope, generation: u32,
        root: &RegisteredRoot, now: Instant) -> bool {
        now < self.end && self.binding.session_id == session && self.binding.project_id == project && &self.binding.scope == scope
            && self.binding.context.generation() == generation && self.binding.context.root() == root
            && input::TOOLING_SHA == Some(self.tooling_sha) && input::publisher_bound()
            && wire::LABELS == ["ubuntu-24.04", "macos-26"]
    }
    pub(crate) fn bind(self: &Arc<Self>, prepared: &input::Prepared, material: &GitHubInputMaterial, now: Instant) -> Result<BoundRunner, BridgeError> {
        if now >= self.end || !self.binding.scope.matches(&prepared.target) || prepared.target.tooling_sha != self.tooling_sha
            || !self.binding.context.matches_material(material) || prepared.target.native_config_sha256 != self.binding.context.config_digest()
            || !prepared.publisher_bound() { return Err(refused(input::Reason::RunnerUnverified)); }
        if !prepared.production_reviewed() { return Err(refused(input::Reason::EnvironmentUnready)); }
        Ok(BoundRunner { evidence: self.clone(), prepared: prepared.clone() })
    }
}
impl BoundRunner {
    pub(crate) fn end(&self) -> Instant { self.evidence.end }
    pub(crate) fn current(&self, evidence: &Arc<Evidence>, prepared: &input::Prepared, material: &GitHubInputMaterial, now: Instant) -> bool {
        Arc::ptr_eq(evidence,&self.evidence) && now < self.evidence.end && &self.prepared == prepared
            && self.evidence.binding.context.matches_material(material) && prepared.production_reviewed()
    }
}
impl State {
    pub(crate) fn contexts(&self) -> impl Iterator<Item=&Arc<GitHubRunnerContext>> {
        self.active.iter().map(|v| &v.binding.context).chain(self.observation.iter().map(|v| v.context()))
    }
    pub(crate) fn invalidate(&mut self, reason: input::Reason, summary: &mut Option<wire::Summary>) {
        self.observation = None;
        if let Some(active) = &mut self.active { active.revoked = active.revoked.or(Some(reason)); active.ticket.stop(); }
        if let Some(summary) = summary { summary.expire(reason); }
    }
    pub(crate) fn expire(&mut self, now: Instant, summary: &mut Option<wire::Summary>) -> bool {
        if self.observation.as_ref().is_some_and(|value| now >= value.end) {
            self.invalidate(input::Reason::Expired,summary); true
        } else { false }
    }
    pub(crate) fn reserved(&self) -> bool { self.active.is_some() || self.observation.is_some() }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admission_clock_and_original_credential_are_never_refreshed_by_poll_or_settlement() {
        let at = Instant::now(); let token = at + Duration::from_secs(300);
        assert_eq!(observation_end(at,token),Some(at + Duration::from_secs(120)));
        assert_eq!(observation_end(at,at + Duration::from_secs(30)),Some(at + Duration::from_secs(30)));
        assert!(original_times(at,at+Duration::from_secs(1),at+Duration::from_secs(2),at+Duration::from_secs(119),token));
        assert!(!original_times(at,at+Duration::from_secs(1),at+Duration::from_secs(2),at+Duration::from_secs(120),token));
        assert!(!original_times(at,at+Duration::from_secs(11),at+Duration::from_secs(12),at+Duration::from_secs(12),token));
        assert!(!original_times(at,at+Duration::from_secs(3),at+Duration::from_secs(2),at+Duration::from_secs(4),token));
        assert!(!original_times(at,at,at+Duration::from_secs(1),at+Duration::from_secs(30),at+Duration::from_secs(30)));
        // Pure monotonic arithmetic DATA, never an original native receipt.
    }
}
