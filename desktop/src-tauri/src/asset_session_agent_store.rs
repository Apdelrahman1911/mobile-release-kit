//! Main-document delegation of ONE existing prepared, nonpublishing Store
//! step. The old relay/owner/GO/STOP/history paths do the work; IPC is DATA.
use super::*;
use crate::{
    application_service::ApplicationService,
    application_service_host::NativeProject,
    edit_owner::SavedEditStamp,
    saved_command_owner::{AgentStoreApproval, AgentStoreBinding, SavedCommandOwner},
    service_protocol::{Error, Id},
    service_store_protocol as p, service_store_requests as requests,
};
use serde::Deserialize;
pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, BridgeError> {
    if bytes.is_empty() || bytes.len() > p::RAW_LIMIT {
        return Err(BridgeError::invalid());
    }
    super::agent_identity::decode(bytes)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Allow {
    kind: p::Kind,
    operation_id: Id,
    owner_generation: Id,
    expected_status_revision: u32,
    consent_version: String,
}
pub(super) struct Grant {
    scope: Arc<requests::NativeScope>,
    binding: Arc<AgentStoreBinding>,
    approval: Arc<AgentStoreApproval>,
    native: NativeProject,
    stamp: SavedEditStamp,
}
fn public(e: Error) -> BridgeError {
    super::application_service::public_error(e)
}
impl DocumentBinding {
    fn store_delegate_owner(&self, kind: p::Kind) -> &SavedCommandOwner {
        match kind {
            p::Kind::AccessCheck => self.inner.bridge.local_store.agent_store_original(),
            p::Kind::CandidatePrepare => {
                self.inner.bridge.local_store_prepare.agent_store_original()
            }
        }
    }
    fn store_delegate_gate(
        &self,
        s: &DocumentState,
        kind: p::Kind,
    ) -> crate::local_store_preflight_protocol::Availability {
        match kind {
            p::Kind::AccessCheck => self.local_store_gate(s),
            p::Kind::CandidatePrepare => self.local_store_prepare_gate(s),
        }
    }
    fn agent_store_service(&self) -> Result<Option<Arc<ApplicationService>>, BridgeError> {
        self.inner
            .agent_store_service
            .get()
            .map(|s| s.upgrade().ok_or_else(|| public(Error::Unavailable)))
            .transpose()
    }
    fn agent_store_material(
        &self,
        s: &DocumentState,
        a: &AgentStoreApproval,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> Result<Arc<SelectedStoreMaterial>, BridgeError> {
        let r = a.review();
        match r.kind {
            p::Kind::AccessCheck => {
                let m = self
                    .inner
                    .bridge
                    .local_store
                    .prepared_material(r.operation_id.as_str(), r.owner_generation.as_str())?;
                self.recheck_store_preflight_material(s, &m, registration, root)?;
                self.store_preflight_budget(s, &m)?;
                Ok(m)
            }
            p::Kind::CandidatePrepare => {
                let m = self
                    .inner
                    .bridge
                    .local_store_prepare
                    .prepared_material(r.operation_id.as_str(), r.owner_generation.as_str())?;
                self.recheck_store_prepare_material(s, &m, registration, root)?;
                self.store_prepare_budget(s, &m)?;
                Ok(m)
            }
        }
    }
    fn agent_store_current(
        &self,
        s: &DocumentState,
        g: &Grant,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> Result<(), BridgeError> {
        self.service_document_gate(s)?;
        if !edit.matches(&g.stamp)
            || !self
                .inner
                .android_registration_control
                .matches_epoch(g.native.input_revision)
            || !g.approval.matches_root(registration, root)
            || g.native.registration_generation != registration
            || g.native.canonical_root != root.path
            || !root
                .identity
                .posix()
                .is_ok_and(|p| p.service_identity() == (g.native.device, g.native.inode))
            || !Arc::ptr_eq(&g.native.document_identity, &self.inner.session_identity)
        {
            return Err(public(Error::Conflict));
        }
        Ok(())
    }
    pub(crate) fn agent_store_access(&self, window: &str) -> Result<p::Access, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        match self.agent_store_service()? {
            Some(service) => service.store_requests().access().map_err(public),
            None => Ok(p::Access::empty()),
        }
    }
    pub(crate) fn allow_agent_store(
        &self,
        window: &str,
        args: Allow,
    ) -> Result<p::Access, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let (native, stamp, approval, epoch) = {
            let mut state = self.lock();
            self.service_document_gate(&state)?;
            if state
                .agent_store_grant
                .as_ref()
                .is_some_and(|g| !g.scope.retired.load(Ordering::Acquire))
                || self.store_delegate_gate(&state, args.kind)
                    != crate::local_store_preflight_protocol::Availability::Available
            {
                return Err(public(Error::Busy));
            }
            let approval = self.store_delegate_owner(args.kind).store_approval(
                args.kind,
                &args.operation_id,
                &args.owner_generation,
                args.expected_status_revision,
            )?;
            if args.consent_version != args.kind.consent(approval.review().platform) {
                return Err(BridgeError::invalid());
            }
            let selected = self
                .registry_result(
                    &mut state,
                    self.inner.bridge.native_project(approval.project()),
                    None,
                )
                .map_err(|_| public(Error::Conflict))?;
            if !approval.matches_root(selected.0, &selected.1) {
                return Err(public(Error::Conflict));
            }
            self.agent_store_material(&state, &approval, selected.0, &selected.1)?;
            let native = self.service_project_locked(&state, approval.project())?;
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            let epoch = self.inner.agent_store_revoke_epoch.load(Ordering::Acquire);
            if epoch == u64::MAX {
                return Err(public(Error::StateUnknown));
            }
            (native, edit.stamp()?, approval, epoch)
        };
        // Genuine Host/Store IO only OFF Doc/Edit/Saved locks. No startup,
        // Read grant creation or credential discovery is hidden in Allow.
        let service = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&native)
            .map_err(public)?;
        let point = service.store_point(&native.runtime_id).map_err(public)?;
        let scope = Arc::new(requests::NativeScope {
            project_id: point.saved.project_id.clone(),
            runtime_id: native.runtime_id.clone(),
            review_id: Id::random().map_err(public)?,
            review: approval.review().clone(),
            root: native.canonical_root.clone(),
            device: native.device,
            inode: native.inode,
            observation_revision: point.saved.revision,
            expires: approval.expires(),
            read: point.read,
            document: Arc::downgrade(&self.inner.session_identity),
            witness: approval.witness(),
            control: requests::Control::new(),
            retired: std::sync::atomic::AtomicBool::new(false),
            changes: self.inner.changes.clone(),
        });
        if !scope.matches(&point.saved) {
            return Err(public(Error::Conflict));
        }
        let grant_id = Id::random().map_err(public)?;
        let mut state = self.lock();
        self.service_document_gate(&state)?;
        if self.inner.agent_store_revoke_epoch.load(Ordering::Acquire) != epoch
            || self.store_delegate_gate(&state, args.kind)
                != crate::local_store_preflight_protocol::Availability::Available
            || state
                .agent_store_grant
                .as_ref()
                .is_some_and(|g| !g.scope.retired.load(Ordering::Acquire))
        {
            return Err(public(Error::AccessDenied));
        }
        let (registration, root) = self
            .registry_result(
                &mut state,
                self.inner.bridge.native_project(approval.project()),
                None,
            )
            .map_err(|_| public(Error::Conflict))?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        if !edit.matches(&stamp)
            || !self
                .inner
                .android_registration_control
                .matches_epoch(native.input_revision)
            || !approval.matches_root(registration, &root)
            || !self
                .store_delegate_owner(args.kind)
                .store_approval_current(&approval)
        {
            return Err(public(Error::Conflict));
        }
        self.agent_store_material(&state, &approval, registration, &root)?;
        service.store_requests().can_allow().map_err(public)?;
        if let Some(old) = self.inner.agent_store_service.get() {
            if old.as_ptr() != Arc::as_ptr(&service) {
                return Err(public(Error::Conflict));
            }
        } else {
            self.inner
                .agent_store_service
                .set(Arc::downgrade(&service))
                .map_err(|_| public(Error::StateUnknown))?;
        }
        // This small link attaches to the existing Prepared before publication.
        // If any subsequent return is lost, the original stays linked/stoppable.
        let binding = self
            .store_delegate_owner(args.kind)
            .bind_store_approval(approval.clone(), scope.clone())?;
        let grant = Arc::new(Grant {
            scope: scope.clone(),
            binding,
            approval,
            native,
            stamp,
        });
        state.agent_store_grant = Some(grant.clone());
        match service.store_requests().allow(scope, grant_id) {
            Ok(access) => Ok(access),
            Err(e) => {
                self.store_delegate_owner(args.kind).stop_agent_store(
                    &grant.binding,
                    p::Reason::PermissionRevoked,
                    Instant::now(),
                );
                Err(public(e))
            }
        }
    }
    pub(crate) fn revoke_agent_store(&self, window: &str) -> Result<p::Access, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let state = self.lock();
        let at = Instant::now();
        // Before off-Doc Allow can install anything, including first Allow.
        let advanced = self
            .inner
            .agent_store_revoke_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |e| e.checked_add(1))
            .map_err(|_| public(Error::StateUnknown));
        if let Some(g) = &state.agent_store_grant {
            self.store_delegate_owner(g.scope.review.kind)
                .stop_agent_store(&g.binding, p::Reason::PermissionRevoked, at);
        }
        let result = match self.agent_store_service() {
            Ok(Some(s)) => s
                .store_requests()
                .revoke(p::Reason::PermissionRevoked, at)
                .map_err(public),
            Ok(None) => Ok(p::Access::empty()),
            Err(e) => Err(e),
        };
        advanced.and(result)
    }
    fn admit_agent_store(
        &self,
        service: &Arc<ApplicationService>,
        entry: &Arc<requests::Entry>,
    ) -> Result<(), BridgeError> {
        let grant = {
            let state = self.lock();
            state
                .agent_store_grant
                .as_ref()
                .filter(|g| Arc::ptr_eq(&g.scope, entry.scope()))
                .cloned()
                .ok_or_else(|| public(Error::Conflict))?
        };
        // Must attach BEFORE any blocked IO. The actual old retirement may
        // already have happened; its retained DATA is replayed only to Entry.
        grant.binding.attach(entry)?;
        if grant.scope.retired.load(Ordering::Acquire) {
            return Ok(());
        }
        entry.current().map_err(public)?;
        let current = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&grant.native)
            .map_err(public)?;
        if !Arc::ptr_eq(&current, service) {
            return Err(public(Error::Conflict));
        }
        service
            .consume_store_observation(&grant.scope)
            .map_err(public)?;
        let mut state = self.lock();
        let gate = self.store_delegate_gate(&state, grant.scope.review.kind);
        let (registration, root) = self
            .registry_result(
                &mut state,
                self.inner.bridge.native_project(&grant.native.runtime_id),
                None,
            )
            .map_err(|_| public(Error::Conflict))?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        self.agent_store_current(&state, &grant, &edit, registration, &root)?;
        if state
            .agent_store_grant
            .as_ref()
            .is_none_or(|g| !Arc::ptr_eq(g, &grant))
            || !self
                .store_delegate_owner(grant.scope.review.kind)
                .store_approval_current(&grant.approval)
        {
            return Err(public(Error::Conflict));
        }
        let material = self.agent_store_material(&state, &grant.approval, registration, &root)?;
        let admitted = self
            .store_delegate_owner(grant.scope.review.kind)
            .start_agent_store(entry, Some((registration, root)), gate, material)?;
        drop(edit);
        drop(state);
        admitted.release();
        Ok(()) // Existing original GO only.
    }
    fn stop_store_entry(&self, entry: &requests::Entry, reason: p::Reason) {
        entry.cancel(reason, Instant::now());
        let state = self.lock();
        if let Some(g) = state
            .agent_store_grant
            .as_ref()
            .filter(|g| Arc::ptr_eq(&g.scope, entry.scope()))
        {
            self.store_delegate_owner(g.scope.review.kind)
                .stop_agent_store(&g.binding, reason, Instant::now());
        } else {
            entry.unknown(p::Reason::CleanupUnknown);
        }
    }
    fn check_agent_store_original(&self) {
        let mut state = self.lock();
        let Some(g) = state.agent_store_grant.as_ref().cloned() else {
            return;
        };
        if g.scope.retired.load(Ordering::Acquire) {
            return;
        }
        let current = (|| {
            let (registration, root) = self
                .registry_result(
                    &mut state,
                    self.inner.bridge.native_project(&g.native.runtime_id),
                    None,
                )
                .map_err(|_| public(Error::Conflict))?;
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            self.agent_store_current(&state, &g, &edit, registration, &root)
        })();
        if current.is_err() {
            self.store_delegate_owner(g.scope.review.kind)
                .stop_agent_store(&g.binding, p::Reason::ContextChanged, Instant::now());
        }
    }
    pub(crate) fn service_store_tick(&self) {
        let Ok(Some(service)) = self.agent_store_service() else {
            return;
        };
        self.check_agent_store_original();
        match service.store_requests().claim() {
            Ok(Some(claim)) => {
                let result = self.admit_agent_store(&service, claim.entry());
                if result.is_err() {
                    self.stop_store_entry(claim.entry(), p::Reason::NativeRefused);
                }
                claim.returned(); // Body actually returned, NOT a native receipt.
            }
            Ok(None) => {}
            Err(_) => service.store_requests().fence(),
        }
        let _ = flush(&service);
    }
    pub(crate) fn agent_store_relay_lost(&self) {
        if let Ok(Some(s)) = self.agent_store_service() {
            s.store_requests().fence();
        }
    }
    /// Called only after same Saved owners and original relay joins on exit.
    pub(crate) fn drain_agent_store_for_exit(&self) {
        if let Ok(Some(s)) = self.agent_store_service() {
            let _ = flush(&s);
            s.store_requests().close(Instant::now());
        }
    }
}
fn flush(service: &ApplicationService) -> Result<(), Error> {
    struct Return<'a> {
        service: &'a ApplicationService,
        known: bool,
    }
    impl Drop for Return<'_> {
        fn drop(&mut self) {
            if !self.known {
                self.service.fence_native_history();
            }
        }
    }
    let mut returned = Return {
        service,
        known: false,
    };
    service.native_history_current()?;
    for entry in service.store_requests().entries()? {
        let Some(history) = entry.claim_history()? else {
            continue;
        };
        let data = &history.data;
        let result = if history.first {
            service.begin_operation(
                &entry.scope().runtime_id,
                data.operation.operation_id.clone(),
                entry.scope().review.kind.action(),
                data.state,
                history.settlement(),
            )
        } else {
            service.publish_operation(
                &entry.scope().runtime_id,
                data.operation.operation_id.clone(),
                entry.scope().review.kind.action(),
                data.state,
                history.settlement(),
            )
        };
        history.returned(result)?;
    }
    service.native_history_current()?;
    returned.known = true;
    Ok(())
}
