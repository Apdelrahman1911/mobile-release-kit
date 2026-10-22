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
    selection: native::dispatch::Selection,
    consent_version: String,
    expected_permission_revision: p::activity::PermissionRevision,
}
// MAIN-only typed result; no map-heavy Value copy of the compact snapshot.
use p::activity::MainAccess;
fn access_revision(access: p::Access, revision: u64) -> MainAccess {
    MainAccess { access, permission_revision: p::activity::PermissionRevision(revision) }
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
        a: &native::dispatch::Selection,
    ) -> Result<(native::Review, NativeProject), BridgeError> {
        self.expire(s, Instant::now());
        self.service_document_gate(s)?;
        let gate = self.github_gate(s);
        let supervisor = &self.inner.bridge.supervisor;
        let now = Instant::now();
        let legacy=a.legacy();
        let available = match a.kind() {
            p::Kind::PreflightPrepare | p::Kind::PreflightDispatch | p::Kind::PreflightPending | p::Kind::PreflightObserve => s.github.preflight_status(supervisor.github_preflight_profile_available(),now,gate).available,
            p::Kind::ReleasePrepare | p::Kind::ReleaseDispatch | p::Kind::ReleasePending | p::Kind::ReleaseObserve => s.github.release_status(supervisor.github_release_profile_available(),now,gate).available,
            p::Kind::CounterPrepare | p::Kind::CounterCreate | p::Kind::PublicationPending | p::Kind::CounterReconcile => s.github.publication_status(supervisor.github_publication_profile_available(),now,gate).available,

            p::Kind::ActivityOverview => s.github.github_activity_status(supervisor.github_activity_profile_available(), now, gate).available,
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
        if a.kind().dispatch_family() && (root.path.capacity() > native::dispatch::ROOT_BACKING
            || !dispatch::main_call_fits()) { return Err(BridgeError::invalid()); }
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        let review = match a.kind() {
            p::Kind::PreflightPrepare | p::Kind::PreflightDispatch | p::Kind::PreflightPending | p::Kind::PreflightObserve => s.github.preflight_agent_review(a.input().ok_or_else(BridgeError::invalid)?,generation,&root,&github_setup_project_binding(&root)?,&edit,now,None),
            p::Kind::ReleasePrepare | p::Kind::ReleaseDispatch | p::Kind::ReleasePending | p::Kind::ReleaseObserve => s.github.release_agent_review(a.input().ok_or_else(BridgeError::invalid)?,generation,&root,&github_setup_project_binding(&root)?,&edit,now,None),
            p::Kind::CounterPrepare | p::Kind::CounterCreate | p::Kind::PublicationPending | p::Kind::CounterReconcile => s.github.counter_agent_review(a.input().ok_or_else(BridgeError::invalid)?,generation,&root,&github_setup_project_binding(&root)?,&edit,now,None),

            p::Kind::ActivityOverview => s.github.github_activity_agent_review(legacy.as_ref().ok_or_else(BridgeError::invalid)?, generation, &root,
                &github_setup_project_binding(&root)?, &edit, now),
            p::Kind::RepositoryCreate => s
                .github
                .repository_create_agent_review(legacy.as_ref().ok_or_else(BridgeError::invalid)?, generation, &root, &edit, now),
            p::Kind::DraftPrCreate | p::Kind::PrCreate => s
                .github
                .pull_request_agent_review(legacy.as_ref().ok_or_else(BridgeError::invalid)?, generation, &root, &edit, now),
            p::Kind::FailedJobsRetry => s
                .github
                .actions_retry_agent_review(legacy.as_ref().ok_or_else(BridgeError::invalid)?, generation, &root, &edit, now),
            p::Kind::SetupPublish | p::Kind::SetupReconcile => s.github.publication_agent_review(legacy.as_ref().ok_or_else(BridgeError::invalid)?, generation, &root, &edit, now),
        }?;
        let native = self.service_project_locked(s, &id)?;
        if (a.kind().dispatch_family() && native.canonical_root.capacity() > native::dispatch::ROOT_BACKING)
            || native.canonical_root != root.path || native.registration_generation != generation {
            return Err(public(Error::Conflict));
        }
        Ok((review, native))
    }
    pub(crate) fn agent_github_action_access(
        &self,
        window: &str,
    ) -> Result<MainAccess, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let _s = self.lock(); // same revision/inbox snapshot as all counter writers
        let revision = self.inner.agent_github_action_revoke_epoch.load(Ordering::Acquire);
        let access = match self.github_action_service()? {
            Some(s) => s.github_action_requests().access().map_err(public)?,
            None => p::Access::empty(),
        };
        Ok(access_revision(access, revision))
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
    ) -> Result<MainAccess, BridgeError> {
        if window != MAIN || !args.selection.valid() || !args.selection.retained_fits() || args.consent_version != args.selection.kind().consent() {
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
        // The user supplied the revision of its ACTUALLY joined Access call.
        // Never replace it with a load performed after delayed async dispatch.
        let epoch = args.expected_permission_revision;
        let (review, original) = {
            let mut s = self.lock();
            epoch.successor(self.inner.agent_github_action_revoke_epoch.load(Ordering::Acquire))
                .ok_or_else(|| public(Error::Conflict))?;
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
        // Revoke/relay close use this same Doc; no racing load/store window.
        let next = epoch.successor(self.inner.agent_github_action_revoke_epoch.load(Ordering::Acquire))
            .ok_or_else(|| public(Error::Conflict))?;
        let (current, current_native) = self.github_action_review(&mut s, &args.selection)?;
        if !same(&original, &current_native)
            || !Arc::ptr_eq(&review.identity, &current.identity)
            || review.data != current.data
            || review.activity != current.activity
            || review.dispatch != current.dispatch
            || !self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?
                .matches(&review.stamp)
        {
            return Err(public(Error::Conflict));
        }
        drop(current);
        drop(current_native);
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
        // SAME final Doc cut. Consume N BEFORE the first possibly installing
        // call. Any subsequent refusal/lost reply leaves N permanently spent.
        self.consume_github_action_permission_locked(&s, epoch, next)?;
        let access = match service.github_action_requests().allow(scope.clone(), grant_id) {
            Ok(access)=>access,
            Err(error)=>{scope.unused_closed(); return Err(public(error));}
        };
        let installed = match review.data.kind() {
            p::Kind::PreflightPrepare | p::Kind::PreflightDispatch | p::Kind::PreflightPending | p::Kind::PreflightObserve => s.github.preflight_agent_allow(review,&scope),
            p::Kind::ReleasePrepare | p::Kind::ReleaseDispatch | p::Kind::ReleasePending | p::Kind::ReleaseObserve => s.github.release_agent_allow(review,&scope),
            p::Kind::CounterPrepare | p::Kind::CounterCreate | p::Kind::PublicationPending | p::Kind::CounterReconcile => s.github.counter_agent_allow(review,&scope),

            p::Kind::ActivityOverview => s.github.github_activity_agent_allow(review, &scope),
            p::Kind::RepositoryCreate => s.github.repository_create_agent_allow(&review, &scope),
            p::Kind::DraftPrCreate | p::Kind::PrCreate => s.github.pull_request_agent_allow(&review, &scope),
            p::Kind::FailedJobsRetry => s.github.actions_retry_agent_allow(&review, &scope),
            p::Kind::SetupPublish | p::Kind::SetupReconcile => s.github.publication_agent_allow(&review, &scope),
        };
        if let Err(e) = installed {
            scope.unused_closed();
            return Err(e);
        }
        Ok(access_revision(access, next))
    }
    // Called with the original final Doc guard, immediately before Inbox.allow.
    // A later installation/response error never rolls the consumed revision back.
    fn consume_github_action_permission_locked(&self, _state: &DocumentState,
        expected: p::activity::PermissionRevision, next: u64) -> Result<(), BridgeError> {
        if expected.successor(self.inner.agent_github_action_revoke_epoch.load(Ordering::Acquire)) != Some(next) {
            return Err(public(Error::Conflict));
        }
        self.inner.agent_github_action_revoke_epoch.store(next, Ordering::Release);
        Ok(())
    }
    pub(crate) fn revoke_agent_github_action(
        &self,
        window: &str,
    ) -> Result<MainAccess, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let at = Instant::now(); // invocation-time STOP, before waiting for Doc
        let mut s = self.lock();
        let revision = self.inner.agent_github_action_revoke_epoch.load(Ordering::Acquire);
        let next = revision.checked_add(1);
        if let Some(next) = next { self.inner.agent_github_action_revoke_epoch.store(next, Ordering::Release); }
        let Some(service) = self.github_action_service()? else {
            return next.map(|n| access_revision(p::Access::empty(), n)).ok_or_else(|| public(Error::StateUnknown));
        };
        let scope = service.github_action_requests().scope();
        if let Ok(Some(scope)) = &scope {
            scope.revoke(p::Reason::PermissionRevoked, at);
            match scope.review.kind() {
                p::Kind::PreflightPrepare | p::Kind::PreflightDispatch | p::Kind::PreflightPending | p::Kind::PreflightObserve => s.github.preflight_agent_revoke(scope),
                p::Kind::ReleasePrepare | p::Kind::ReleaseDispatch | p::Kind::ReleasePending | p::Kind::ReleaseObserve => s.github.release_agent_revoke(scope),
                p::Kind::CounterPrepare | p::Kind::CounterCreate | p::Kind::PublicationPending | p::Kind::CounterReconcile => s.github.counter_agent_revoke(scope),

                p::Kind::ActivityOverview => s.github.github_activity_agent_revoke(scope),
                p::Kind::RepositoryCreate => s.github.repository_create_agent_revoke(scope),
                p::Kind::DraftPrCreate | p::Kind::PrCreate => s.github.pull_request_agent_revoke(scope),
                p::Kind::FailedJobsRetry => s.github.actions_retry_agent_revoke(scope),
                p::Kind::SetupPublish | p::Kind::SetupReconcile => s.github.publication_agent_revoke(scope),
            }
        }
        // Even overflow or a poisoned scope lookup cannot skip the original
        // cancellation. Unknown stays absorbing and all original rows remain.
        let access = service.github_action_requests().revoke(p::Reason::PermissionRevoked, at);
        if scope.is_err() || access.is_err() { service.github_action_requests().fence(); }
        let access = access.map_err(public)?;
        scope.map_err(public)?;
        let next = next.ok_or_else(|| public(Error::StateUnknown))?;
        Ok(access_revision(access, next))
    }
    fn github_action_start(
        &self,
        service: &Arc<ApplicationService>,
        entry: &Arc<r::Entry>,
        app_data:Option<std::path::PathBuf>,
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
            p::Kind::PreflightPrepare | p::Kind::PreflightDispatch | p::Kind::PreflightPending | p::Kind::PreflightObserve | p::Kind::ReleasePrepare | p::Kind::ReleaseDispatch | p::Kind::ReleasePending | p::Kind::ReleaseObserve | p::Kind::CounterPrepare | p::Kind::CounterCreate | p::Kind::PublicationPending | p::Kind::CounterReconcile => self.github_dispatch_agent_start(entry,app_data)?,
            p::Kind::ActivityOverview => {
                let p::Review::ActivityOverview(r) = v else { return Err(BridgeError::invalid()); };
                self.github_activity_execute(crate::github_activity_protocol::Command::Read(crate::github_activity_protocol::ReadArgs {
                    session_id: r.session_id.clone(), project_id: scope.runtime_id.clone(),
                    expected_revision: r.expected_revision, expected_connection_revision: r.expected_connection_revision,
                    selection: crate::github_activity_protocol::Selection::Overview { branch: None },
                }), Some(entry.clone()))?;
            }
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
    pub(crate) fn github_action_agent_tick(&self, app_data:Option<std::path::PathBuf>) {
        let Some(service) = self.github_action_service().ok().flatten() else {
            return;
        };
        if let Ok(Some(call)) = service.github_action_requests().claim() {
            let e = call.entry().clone();
            let result = self.github_action_start(&service, &e, app_data).map_err(|error| {
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
        let at = Instant::now();
        let _s = self.lock();
        let old = self.inner.agent_github_action_revoke_epoch.load(Ordering::Acquire);
        if let Some(next) = old.checked_add(1) { self.inner.agent_github_action_revoke_epoch.store(next, Ordering::Release); }
        // Overflow never skips original close. No Service Store/IO under Doc.
        if let Ok(Some(s)) = self.github_action_service() { s.github_action_requests().close(at); }
    }
}

// Only new Prepare allows the bounded native Release selection. Other MAIN
// variants and all IPC/CLI commands retain their original1024-byte envelope.
pub(crate) fn decode_allow(b:&[u8])->Result<Allow,BridgeError>{
    if b.is_empty()||b.len()>4096{return Err(BridgeError::invalid());}
    let args:Allow=serde_json::from_slice(b).map_err(|_|BridgeError::invalid())?;
    if b.len()>args.selection.limit()||!args.selection.valid()||!args.selection.retained_fits(){return Err(BridgeError::invalid());}
    Ok(args)
}
#[path="service_github_dispatch_native.rs"]
mod dispatch;
