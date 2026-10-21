//! Main-window grant and existing retained relay; no new command executor.
use super::*;
use crate::{
    application_service::ApplicationService,
    application_service_host::NativeProject,
    github_connection_session::action_delegation as native,
    service_github_action_protocol as p, service_github_action_requests as r,
    service_protocol::{Error, Id},
};
use std::sync::atomic::{AtomicBool, Ordering};
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Allow {
    selection: native::Selection,
    consent_version: String,
}
pub(crate) fn decode<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, BridgeError> {
    if b.is_empty() || b.len() > p::RAW_LIMIT {
        return Err(BridgeError::invalid());
    }
    // Only the closed Allow / Query / Empty structs call this fixed route.
    // Deserialize them directly: their deny_unknown_fields and duplicate-field
    // checks refuse an unexpected container before constructing a Value tree.
    // from_slice also requires the original complete input (no trailing JSON).
    serde_json::from_slice(b).map_err(|_| BridgeError::invalid())
}
#[cfg(test)]
#[path = "service_github_action_native_tests.rs"]
mod tests;

fn public(e: Error) -> BridgeError {
    application_service::public_error(e)
}
fn same(a: &NativeProject, b: &NativeProject) -> bool {
    a.runtime_id == b.runtime_id
        && a.canonical_root == b.canonical_root
        && a.device == b.device
        && a.inode == b.inode
        && a.registration_generation == b.registration_generation
        && a.input_revision == b.input_revision
        && Arc::ptr_eq(&a.document_identity, &b.document_identity)
}
struct AllowReturned<'a>(&'a AtomicBool);
impl Drop for AllowReturned<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release)
    }
}
impl DocumentBinding {
    fn github_action_service(&self) -> Result<Option<Arc<ApplicationService>>, BridgeError> {
        self.inner
            .agent_github_action_service
            .get()
            .map(|s| s.upgrade().ok_or_else(|| public(Error::Unavailable)))
            .transpose()
    }
    fn github_action_review(
        &self,
        s: &mut DocumentState,
        a: &native::Selection,
    ) -> Result<(native::Review, NativeProject), BridgeError> {
        self.expire(s, Instant::now());
        self.service_document_gate(s)?;
        let gate = self.github_gate(s);
        let supervisor = &self.inner.bridge.supervisor;
        let now = Instant::now();
        let available = match a.kind() {
            p::Kind::RepositoryCreate => {
                s.github
                    .repository_create_status(
                        supervisor.repository_create_profile_available(),
                        now,
                        gate,
                    )
                    .available
            }
            p::Kind::DraftPrCreate | p::Kind::PrCreate => {
                s.github
                    .pull_request_status(supervisor.pull_request_profile_available(), now, gate)
                    .available
            }
            p::Kind::FailedJobsRetry => {
                s.github
                    .actions_retry_status(supervisor.actions_retry_profile_available(), now, gate)
                    .available
            }
            p::Kind::SetupPublish | p::Kind::SetupReconcile => s.github
                .publication_status(supervisor.github_publication_profile_available(), now, gate).available,
        };
        if !available {
            return Err(public(Error::Unavailable));
        }
        let (id, g) = s
            .github
            .registration()
            .map(|(id, g)| (id.to_owned(), g))
            .ok_or_else(|| public(Error::Conflict))?;
        let (generation, root) = self
            .registry_result(s, self.inner.bridge.native_project(&id), None)
            .map_err(|_| public(Error::Conflict))?;
        if g != generation {
            return Err(public(Error::Conflict));
        }
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        let review = match a.kind() {
            p::Kind::RepositoryCreate => s
                .github
                .repository_create_agent_review(a, generation, &root, &edit, now),
            p::Kind::DraftPrCreate | p::Kind::PrCreate => s
                .github
                .pull_request_agent_review(a, generation, &root, &edit, now),
            p::Kind::FailedJobsRetry => s
                .github
                .actions_retry_agent_review(a, generation, &root, &edit, now),
            p::Kind::SetupPublish | p::Kind::SetupReconcile => s.github.publication_agent_review(a, generation, &root, &edit, now),
        }?;
        let native = self.service_project_locked(s, &id)?;
        if native.canonical_root != root.path || native.registration_generation != generation {
            return Err(public(Error::Conflict));
        }
        Ok((review, native))
    }
    pub(crate) fn agent_github_action_access(
        &self,
        window: &str,
    ) -> Result<p::Access, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        match self.github_action_service()? {
            Some(s) => s.github_action_requests().access().map_err(public),
            None => Ok(p::Access::empty()),
        }
    }
    /// Exact original-row observation, not the latest lease. A coalesced relay
    /// update cannot replace the final row that this retained caller still needs.
    pub(crate) fn agent_github_action_request_status(
        &self,
        window: &str,
        query: &p::Query,
    ) -> Result<p::Status, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        self.github_action_service()?
            .ok_or_else(|| public(Error::Unavailable))?
            .github_action_requests()
            .query_for_document(query, &self.inner.session_identity)
            .map_err(public)
    }
    pub(crate) fn allow_agent_github_action(
        &self,
        window: &str,
        args: Allow,
    ) -> Result<p::Access, BridgeError> {
        if window != MAIN || !args.selection.valid() || args.consent_version != args.selection.kind().consent() {
            return Err(BridgeError::invalid());
        }
        if self
            .inner
            .agent_github_action_allow_pending
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(public(Error::Busy));
        }
        let _returned = AllowReturned(&self.inner.agent_github_action_allow_pending);
        // Epoch exists before the first off-Doc lookup, including the first Allow.
        let epoch = self
            .inner
            .agent_github_action_revoke_epoch
            .load(Ordering::Acquire);
        let (review, original) = {
            let mut s = self.lock();
            self.github_action_review(&mut s, &args.selection)?
        };
        let service = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&original)
            .map_err(public)?;
        let point = service
            .github_action_point(&original.runtime_id)
            .map_err(public)?;
        if point.saved.root != original.canonical_root
            || (point.saved.device, point.saved.inode) != (original.device, original.inode)
        {
            return Err(public(Error::Conflict));
        }
        let grant_id = Id::random().map_err(public)?;
        let mut s = self.lock();
        let (current, current_native) = self.github_action_review(&mut s, &args.selection)?;
        if epoch == u64::MAX
            || epoch
                != self
                    .inner
                    .agent_github_action_revoke_epoch
                    .load(Ordering::Acquire)
            || !same(&original, &current_native)
            || !Arc::ptr_eq(&review.identity, &current.identity)
            || review.data != current.data
            || !self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?
                .matches(&review.stamp)
        {
            return Err(public(Error::Conflict));
        }
        service.native_history_current().map_err(public)?;
        if let Some(old) = self.github_action_service()? {
            if !Arc::ptr_eq(&old, &service) {
                return Err(public(Error::Conflict));
            }
        } else {
            self.inner
                .agent_github_action_service
                .set(Arc::downgrade(&service))
                .map_err(|_| public(Error::Conflict))?;
        }
        let scope = r::NativeScope::new(
            point.saved.project_id,
            original.runtime_id,
            original.canonical_root,
            original.device,
            original.inode,
            original.input_revision,
            review.data.clone(),
            review.identity.clone(),
            review.end.min(point.read.end()),
            point.read,
            Arc::downgrade(&self.inner.session_identity),
            self.inner.changes.clone(),
        );
        let access = service
            .github_action_requests()
            .allow(scope.clone(), grant_id)
            .map_err(public)?;
        let installed = match review.data.kind() {
            p::Kind::RepositoryCreate => s.github.repository_create_agent_allow(&review, &scope),
            p::Kind::DraftPrCreate | p::Kind::PrCreate => s.github.pull_request_agent_allow(&review, &scope),
            p::Kind::FailedJobsRetry => s.github.actions_retry_agent_allow(&review, &scope),
            p::Kind::SetupPublish | p::Kind::SetupReconcile => s.github.publication_agent_allow(&review, &scope),
        };
        if let Err(e) = installed {
            scope.unused_closed();
            return Err(e);
        }
        Ok(access)
    }
    pub(crate) fn revoke_agent_github_action(
        &self,
        window: &str,
    ) -> Result<p::Access, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        self.inner
            .agent_github_action_revoke_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
            .map_err(|_| public(Error::StateUnknown))?;
        let mut s = self.lock();
        let Some(service) = self.github_action_service()? else {
            return Ok(p::Access::empty());
        };
        if let Some(scope) = service.github_action_requests().scope().map_err(public)? {
            scope.revoke(p::Reason::PermissionRevoked, Instant::now());
            match scope.review.kind() {
                p::Kind::RepositoryCreate => s.github.repository_create_agent_revoke(&scope),
                p::Kind::DraftPrCreate | p::Kind::PrCreate => s.github.pull_request_agent_revoke(&scope),
                p::Kind::FailedJobsRetry => s.github.actions_retry_agent_revoke(&scope),
                p::Kind::SetupPublish | p::Kind::SetupReconcile => s.github.publication_agent_revoke(&scope),
            }
        }
        service
            .github_action_requests()
            .revoke(p::Reason::PermissionRevoked, Instant::now())
            .map_err(public)
    }
    fn github_action_start(
        &self,
        service: &Arc<ApplicationService>,
        entry: &Arc<r::Entry>,
    ) -> Result<(), BridgeError> {
        let scope = entry.scope();
        scope.current(false).map_err(public)?;
        // Existing Service check actually reads its original state. No Doc is held.
        let point = service
            .github_action_point(&scope.runtime_id)
            .map_err(public)?;
        if point.saved.project_id != scope.project_id
            || point.saved.root != scope.root
            || (point.saved.device, point.saved.inode) != (scope.device, scope.inode)
            || !Arc::ptr_eq(&point.read, &scope.read)
        {
            return Err(public(Error::Conflict));
        }
        {
            let s = self.lock();
            self.service_document_gate(&s)?;
            service.native_history_current().map_err(public)?;
            let n = self.service_project_locked(&s, &scope.runtime_id)?;
            if n.input_revision != scope.input_revision
                || n.canonical_root != scope.root
                || (n.device, n.inode) != (scope.device, scope.inode)
                || scope
                    .document
                    .upgrade()
                    .is_none_or(|d| !Arc::ptr_eq(&d, &n.document_identity))
                || self
                    .github_action_service()?
                    .is_none_or(|s| !Arc::ptr_eq(&s, service))
            {
                return Err(public(Error::Conflict));
            }
        }
        // These are the same typed adapters used by the GUI. Every adapter rechecks
        // its own Doc/root/Edit/Connection and optional origin before Consent.take.
        let v = &scope.review;
        match v.kind() {
            p::Kind::RepositoryCreate => {
                let v = v.prepared().ok_or_else(BridgeError::invalid)?;
                let a = crate::github_repository_create_protocol::CreateArgs {
                    session_id: v.session_id.clone(),
                    expected_revision: v.expected_revision,
                    consent_id: v.consent_id.clone(),
                    confirm: true,
                };
                self.repository_create_execute(
                    crate::github_repository_create_protocol::Command::Create(a),
                    Some(entry.clone()),
                )?;
            }
            p::Kind::DraftPrCreate | p::Kind::PrCreate => {
                let v = v.prepared().ok_or_else(BridgeError::invalid)?;
                let a = crate::github_pull_request_protocol::CreateArgs {
                    session_id: v.session_id.clone(),
                    expected_revision: v.expected_revision,
                    consent_id: v.consent_id.clone(),
                    confirm: true,
                };
                self.pull_request_execute(
                    crate::github_pull_request_protocol::Command::Create(a),
                    Some(entry.clone()),
                )?;
            }
            p::Kind::FailedJobsRetry => {
                let v = v.prepared().ok_or_else(BridgeError::invalid)?;
                let a = crate::github_actions_retry_protocol::StartArgs {
                    session_id: v.session_id.clone(),
                    expected_revision: v.expected_revision,
                    consent_id: v.consent_id.clone(),
                    confirm: true,
                };
                self.actions_retry_execute(
                    crate::github_actions_retry_protocol::Command::Start(a),
                    Some(entry.clone()),
                )?;
            }
            p::Kind::SetupPublish | p::Kind::SetupReconcile => self.github_publication_agent_start(entry)?,
        }
        Ok(())
    }
    pub(crate) fn github_action_agent_tick(&self) {
        let Some(service) = self.github_action_service().ok().flatten() else {
            return;
        };
        if let Ok(Some(call)) = service.github_action_requests().claim() {
            let e = call.entry().clone();
            let result = self.github_action_start(&service, &e).map_err(|error| {
                if error.code == "cleanup_unknown" || error.code == "cli_access_unknown" {
                    p::Reason::CleanupUnknown
                } else {
                    e.first_reason().unwrap_or(p::Reason::NativeRefused)
                }
            });
            call.returned(result)
        }
        let Ok(entries) = service.github_action_requests().entries() else {
            return;
        };
        for e in entries {
            let Ok(Some(h)) = e.claim_history() else {
                continue;
            };
            let result = if h.first {
                service.begin_operation(
                    &e.scope().runtime_id,
                    e.origin().request_id.clone(),
                    e.scope().review.kind().action(),
                    h.fact.state(),
                    h.fact.settlement(),
                )
            } else {
                service.publish_operation(
                    &e.scope().runtime_id,
                    e.origin().request_id.clone(),
                    e.scope().review.kind().action(),
                    h.fact.state(),
                    h.fact.settlement(),
                )
            };
            let _ = h.returned(result);
        }
    }
    pub(crate) fn github_action_agent_relay_closed(&self) {
        let _ = self.inner.agent_github_action_revoke_epoch.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |v| v.checked_add(1),
        );
        if let Ok(Some(s)) = self.github_action_service() {
            s.github_action_requests().close(Instant::now());
        }
    }
}
