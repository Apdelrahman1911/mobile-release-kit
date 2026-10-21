//! MAIN-only delegation of one retained Apple Prepared. No CLI Prepare,
//! account discovery, credential import, runtime startup or synthetic consent.
use super::super::*;
use crate::{
    application_service::ApplicationService,
    application_service_host::NativeProject,
    edit_owner::SavedEditStamp,
    saved_command_owner::{AgentAppleApproval, AgentAppleBinding},
    service_apple_provisioning_protocol as p, service_apple_provisioning_requests as requests,
    service_protocol::{Error, Id},
};
use serde::Deserialize;
fn public(error: Error) -> BridgeError {
    super::super::application_service::public_error(error)
}
pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, BridgeError> {
    if bytes.is_empty() || bytes.len() > p::RAW_LIMIT {
        return Err(BridgeError::invalid());
    }
    super::super::agent_identity::decode(bytes)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Allow {
    consent_id: Id,
    mode: p::Mode,
    operation_id: Id,
    owner_generation: Id,
    expected_status_revision: u32,
    consent_version: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Revoke {
    consent_id: Id,
}
struct Nonce {
    id: Id,
    revoked: bool,
}
#[derive(Default)]
pub(crate) struct State {
    grant: Option<Arc<Grant>>,
    nonces: Vec<Nonce>,
}
impl State {
    fn reserve(&mut self, id: &Id) -> Result<(), Error> {
        if self.nonces.iter().any(|n| &n.id == id) {
            return Err(Error::Conflict);
        }
        if self.nonces.len() >= p::REQUEST_LIMIT {
            return Err(Error::Busy);
        }
        self.nonces.push(Nonce {
            id: id.clone(),
            revoked: false,
        });
        Ok(())
    }
    fn current(&self, id: &Id) -> bool {
        self.nonces.iter().any(|n| &n.id == id && !n.revoked)
    }
    fn withdraw(&mut self, id: &Id) -> Result<(), Error> {
        if let Some(n) = self.nonces.iter_mut().find(|n| &n.id == id) {
            n.revoked = true;
            return Ok(());
        }
        if self.nonces.len() >= p::REQUEST_LIMIT {
            return Err(Error::Busy);
        }
        // Revoke before the first off-Doc Allow cut must tombstone that exact
        // nonce. It does not cancel another grant or fabricate a native return.
        self.nonces.push(Nonce {
            id: id.clone(),
            revoked: true,
        });
        Ok(())
    }
}
pub(super) struct Grant {
    consent: Id,
    scope: Arc<requests::NativeScope>,
    binding: Arc<AgentAppleBinding>,
    approval: Arc<AgentAppleApproval>,
    native: NativeProject,
    stamp: SavedEditStamp,
}
impl DocumentBinding {
    fn agent_apple_service(&self) -> Result<Option<Arc<ApplicationService>>, BridgeError> {
        self.inner
            .agent_apple_service
            .get()
            .map(|s| s.upgrade().ok_or_else(|| public(Error::Unavailable)))
            .transpose()
    }
    fn agent_apple_input_current(
        &self,
        state: &DocumentState,
        approval: &AgentAppleApproval,
    ) -> Result<(), BridgeError> {
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        self.agent_apple_material_current(state, approval, &edit)
    }
    fn agent_apple_material_current(
        &self,
        state: &DocumentState,
        approval: &AgentAppleApproval,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
    ) -> Result<(), BridgeError> {
        let input = approval.input()?;
        let (registration, root) = self
            .inner
            .bridge
            .native_project(approval.project())
            .map_err(|_| public(Error::Conflict))?;
        if !approval.matches_root(registration, &root) {
            return Err(public(Error::Conflict));
        }
        input.current_locked(&self.inner, state, edit)?;
        self.recheck_apple_provisioning_material(
            state,
            input.material(),
            input.context(),
            registration,
            &root,
        )?;
        let future = crate::saved_command_owner::apple_provisioning_document_backing_bytes(
            input.context().mode,
        )
        .ok_or_else(|| public(Error::Unavailable))?;
        lookup_memory::store_admission_bytes(&self.inner, state, input.material(), future)
            .map_err(|_| public(Error::Unavailable))?;
        Ok(())
    }
    fn agent_apple_current(
        &self,
        state: &DocumentState,
        g: &Grant,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> Result<(), BridgeError> {
        self.service_document_gate(state)?;
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
    pub(crate) fn agent_apple_access(&self, window: &str) -> Result<p::Access, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        match self.agent_apple_service()? {
            Some(s) => s.apple_provisioning_requests().access().map_err(public),
            None => Ok(p::Access::empty()),
        }
    }
    pub(crate) fn agent_apple_request_status(
        &self,
        window: &str,
        q: &p::Query,
    ) -> Result<p::Status, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        self.agent_apple_service()?
            .ok_or_else(|| public(Error::Unavailable))?
            .apple_provisioning_requests()
            .query(q, false)
            .map_err(public)
    }
    pub(crate) fn allow_agent_apple(
        &self,
        window: &str,
        args: Allow,
    ) -> Result<p::Access, BridgeError> {
        if window != MAIN || args.consent_version != args.mode.consent() {
            return Err(BridgeError::invalid());
        }
        let (native, stamp, approval) = {
            let mut state = self.lock();
            self.service_document_gate(&state)?;
            state
                .agent_apple
                .reserve(&args.consent_id)
                .map_err(public)?;
            if state
                .agent_apple
                .grant
                .as_ref()
                .is_some_and(|g| !g.scope.retired.load(Ordering::Acquire))
                || self.apple_provisioning_gate(&state)
                    != crate::apple_provisioning_protocol::Availability::Available
            {
                return Err(public(Error::Busy));
            }
            let approval = self.inner.bridge.apple_provisioning.apple_approval(
                args.mode,
                &args.operation_id,
                &args.owner_generation,
                args.expected_status_revision,
            )?;
            self.agent_apple_input_current(&state, &approval)?;
            let native = self.service_project_locked(&state, approval.project())?;
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            (native, edit.stamp()?, approval)
        };
        // Existing authenticated Host/service checks are OFF Doc/Edit/Saved.
        // This never starts a Host or grants Read; missing prerequisites refuse.
        let service = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&native)
            .map_err(public)?;
        let point = service
            .apple_provisioning_point(&native.runtime_id)
            .map_err(public)?;
        let scope = Arc::new(requests::NativeScope {
            project_id: point.saved.project_id.clone(),
            runtime_id: native.runtime_id.clone(),
            review_id: approval.review().operation_id.clone(),
            review: approval.review().clone(),
            root: native.canonical_root.clone(),
            device: native.device,
            inode: native.inode,
            observation_revision: point.saved.revision,
            expires: approval.expires().min(point.read.end()),
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
        let mut state = self.lock();
        self.service_document_gate(&state)?;
        if !state.agent_apple.current(&args.consent_id)
            || state
                .agent_apple
                .grant
                .as_ref()
                .is_some_and(|g| !g.scope.retired.load(Ordering::Acquire))
            || self.apple_provisioning_gate(&state)
                != crate::apple_provisioning_protocol::Availability::Available
        {
            return Err(public(Error::AccessDenied));
        }
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
            || !self
                .inner
                .bridge
                .apple_provisioning
                .apple_approval_current(&approval)
        {
            return Err(public(Error::Conflict));
        }
        self.agent_apple_material_current(&state, &approval, &edit)?;
        service
            .apple_provisioning_requests()
            .can_allow()
            .map_err(public)?;
        if let Some(old) = self.inner.agent_apple_service.get() {
            if old.as_ptr() != Arc::as_ptr(&service) {
                return Err(public(Error::Conflict));
            }
        } else {
            self.inner
                .agent_apple_service
                .set(Arc::downgrade(&service))
                .map_err(|_| public(Error::StateUnknown))?;
        }
        let binding = self
            .inner
            .bridge
            .apple_provisioning
            .bind_apple_approval(approval.clone(), scope.clone())?;
        let grant = Arc::new(Grant {
            consent: args.consent_id.clone(),
            scope: scope.clone(),
            binding,
            approval,
            native,
            stamp,
        });
        state.agent_apple.grant = Some(grant.clone());
        match service
            .apple_provisioning_requests()
            .allow(scope, args.consent_id)
        {
            Ok(v) => Ok(v),
            Err(e) => {
                self.inner.bridge.apple_provisioning.stop_agent_apple(
                    &grant.binding,
                    p::Reason::PermissionRevoked,
                    Instant::now(),
                );
                Err(public(e))
            }
        }
    }
    pub(crate) fn revoke_agent_apple(
        &self,
        window: &str,
        args: Revoke,
    ) -> Result<p::Access, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let mut state = self.lock();
        state
            .agent_apple
            .withdraw(&args.consent_id)
            .map_err(public)?;
        let at = Instant::now();
        if let Some(g) = state
            .agent_apple
            .grant
            .as_ref()
            .filter(|g| g.consent == args.consent_id)
        {
            self.inner.bridge.apple_provisioning.stop_agent_apple(
                &g.binding,
                p::Reason::PermissionRevoked,
                at,
            );
        }
        match self.agent_apple_service()? {
            Some(s) => s
                .apple_provisioning_requests()
                .withdraw(&args.consent_id, at)
                .map_err(public),
            None => Ok(p::Access::empty()),
        }
    }
    /// SAME Doc/Edit guard as the existing Start. No public marker substitutes
    /// for this exact grant/link; the original Input/material gates follow it.
    pub(super) fn agent_apple_start_current(
        &self,
        state: &DocumentState,
        g: &Arc<Grant>,
        entry: &Arc<requests::Entry>,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> Result<(), BridgeError> {
        self.agent_apple_current(state, g, edit, registration, root)?;
        if state
            .agent_apple
            .grant
            .as_ref()
            .is_none_or(|held| !Arc::ptr_eq(held, g))
            || !state.agent_apple.current(&g.consent)
            || !Arc::ptr_eq(&g.scope, entry.scope())
            || !self
                .inner
                .bridge
                .apple_provisioning
                .apple_approval_current(&g.approval)
        {
            return Err(public(Error::Conflict));
        }
        entry.current().map_err(public)
    }
    fn admit_agent_apple(
        &self,
        service: &Arc<ApplicationService>,
        entry: &Arc<requests::Entry>,
    ) -> Result<(), BridgeError> {
        let grant = self
            .lock()
            .agent_apple
            .grant
            .as_ref()
            .filter(|g| Arc::ptr_eq(&g.scope, entry.scope()))
            .cloned()
            .ok_or_else(|| public(Error::Conflict))?;
        grant.binding.attach(entry)?; // before any off-Doc IO; retain early real retirement.
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
            .consume_apple_provisioning_observation(&grant.scope)
            .map_err(public)?;
        let input = grant.approval.input()?;
        let start = crate::apple_provisioning_protocol::Start {
            operation_id: grant.scope.review.operation_id.as_str().into(),
            owner_generation: grant.scope.review.owner_generation.as_str().into(),
            consent_version: input.context().mode.consent().into(),
        };
        self.start_apple_provisioning_delegated(start, Some((&grant, entry)))
            .map(|_| ())
    }
    fn stop_apple_entry(&self, entry: &requests::Entry, reason: p::Reason) {
        entry.cancel(reason, Instant::now());
        let state = self.lock();
        if let Some(g) = state
            .agent_apple
            .grant
            .as_ref()
            .filter(|g| Arc::ptr_eq(&g.scope, entry.scope()))
        {
            self.inner.bridge.apple_provisioning.stop_agent_apple(
                &g.binding,
                reason,
                Instant::now(),
            );
        } else {
            entry.unknown(p::Reason::CleanupUnknown)
        }
    }
    fn check_agent_apple_original(&self) {
        let state = self.lock();
        let Some(g) = state.agent_apple.grant.as_ref() else {
            return;
        };
        if g.scope.retired.load(Ordering::Acquire) {
            return;
        }
        let current = (|| {
            let (registration, root) = self
                .inner
                .bridge
                .native_project(&g.native.runtime_id)
                .map_err(|_| public(Error::Conflict))?;
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            self.agent_apple_current(&state, g, &edit, registration, &root)
        })();
        if current.is_err() {
            self.inner.bridge.apple_provisioning.stop_agent_apple(
                &g.binding,
                p::Reason::ContextChanged,
                Instant::now(),
            )
        }
    }
    pub(crate) fn service_apple_provisioning_tick(&self) {
        let Ok(Some(service)) = self.agent_apple_service() else {
            return;
        };
        self.check_agent_apple_original();
        match service.apple_provisioning_requests().claim() {
            Ok(Some(claim)) => {
                if self.admit_agent_apple(&service, claim.entry()).is_err() {
                    self.stop_apple_entry(claim.entry(), p::Reason::NativeRefused)
                }
                claim.returned(); // Actual admission caller return, NOT private/native finality.
            }
            Ok(None) => {}
            Err(_) => service.apple_provisioning_requests().fence(),
        }
        let _ = flush(&service);
    }
    pub(crate) fn agent_apple_relay_lost(&self) {
        if let Ok(Some(s)) = self.agent_apple_service() {
            s.apple_provisioning_requests().fence()
        }
    }
    /// Only after SAME native owner and relay return on exit.
    pub(crate) fn drain_agent_apple_for_exit(&self) {
        if let Ok(Some(s)) = self.agent_apple_service() {
            let _ = flush(&s);
            s.apple_provisioning_requests().close(Instant::now())
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
    for entry in service.apple_provisioning_requests().entries()? {
        let Some(history) = entry.claim_history()? else {
            continue;
        };
        let data = &history.data;
        let result = if history.first {
            service.begin_operation(
                &entry.scope().runtime_id,
                data.operation.operation_id.clone(),
                entry.scope().review.mode.action(),
                data.state,
                history.settlement(),
            )
        } else {
            service.publish_operation(
                &entry.scope().runtime_id,
                data.operation.operation_id.clone(),
                entry.scope().review.mode.action(),
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

#[cfg(test)]
#[path = "asset_session_agent_apple_provisioning_tests.rs"]
mod tests;
