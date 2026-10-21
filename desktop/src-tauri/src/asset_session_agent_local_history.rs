//! MAIN-only explicit one-use delegation of the SAME prepared History intent.
//! Off-Doc service lookup uses the genuine READ facet, not saved Store inputs.
use super::agent_store::permission::{self, MainAccess};
use super::*;
use crate::{
    application_service::ApplicationService,
    application_service_host::NativeProject,
    edit_owner::SavedEditStamp,
    saved_command_owner::{AgentHistoryApproval, AgentHistoryBinding, SavedCommandOwner},
    service_local_history_protocol as p,
    service_protocol::{Error, Id},
    service_store_requests::history as requests,
};
use serde::Deserialize;
pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, BridgeError> {
    use serde::de::DeserializeSeed;
    if bytes.is_empty() || bytes.len() > p::RAW_LIMIT {
        return Err(BridgeError::invalid());
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let mut nodes = 0;
    let value = crate::bounded_json_seed::Seed {
        nodes: &mut nodes,
        depth: 0,
        node_limit: p::RAW_NODES,
        depth_limit: 4,
    }
    .deserialize(&mut decoder)
    .map_err(|_| BridgeError::invalid())?;
    decoder.end().map_err(|_| BridgeError::invalid())?;
    T::deserialize(&value).map_err(|_| BridgeError::invalid())
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Allow {
    expected_permission_revision: String,
    kind: p::Kind,
    operation_id: Id,
    owner_generation: Id,
    expected_status_revision: u32,
    consent_version: String,
}
pub(super) struct Grant {
    pub(in crate::asset_session) scope: Arc<requests::Scope>,
    binding: Arc<AgentHistoryBinding>,
    approval: Arc<AgentHistoryApproval>,
    native: NativeProject,
    stamp: SavedEditStamp,
}
fn public(e: Error) -> BridgeError {
    super::application_service::public_error(e)
}
impl DocumentBinding {
    fn history_delegate_owner(&self) -> &SavedCommandOwner {
        self.inner.bridge.local_history.agent_original()
    }
    fn agent_history_service(&self) -> Result<Option<Arc<ApplicationService>>, BridgeError> {
        self.inner
            .agent_store_service
            .get()
            .map(|s| s.upgrade().ok_or_else(|| public(Error::Unavailable)))
            .transpose()
    }
    fn history_consent_current(
        &self,
        s: &DocumentState,
        a: &AgentHistoryApproval,
        g: u32,
        r: &asset_source::RegisteredRoot,
    ) -> bool {
        a.consent().is_some_and(|c| c.matches(&self.inner, s, g, r))
    }
    fn agent_history_current(
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
            || !self.history_consent_current(s, &g.approval, registration, root)
        {
            return Err(public(Error::Conflict));
        }
        Ok(())
    }
    pub(crate) fn agent_local_history_access(
        &self,
        window: &str,
    ) -> Result<MainAccess<p::Access>, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let _state = self.lock();
        let revision = self.inner.agent_store_revoke_epoch.load(Ordering::Acquire);
        let access = match self.agent_history_service()? {
            Some(s) => s.store_requests().history_access().map_err(public)?,
            None => p::Access::empty(),
        };
        Ok(MainAccess::new(access, revision))
    }
    pub(crate) fn allow_agent_local_history(
        &self,
        window: &str,
        args: Allow,
    ) -> Result<MainAccess<p::Access>, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let expected = permission::parse(&args.expected_permission_revision).map_err(public)?;
        let (native, stamp, approval, epoch) = {
            let mut state = self.lock();
            permission::next(&self.inner.agent_store_revoke_epoch, expected).map_err(public)?;
            self.service_document_gate(&state)?;
            if state.agent_local_history.as_ref().is_some_and(|g| {
                !g.scope.retired.load(Ordering::Acquire) || g.scope.control.first().is_err()
            }) || state
                .agent_store_preparation
                .as_ref()
                .is_some_and(|g| g.occupied())
                || state
                    .agent_store_grant
                    .as_ref()
                    .is_some_and(|g| g.occupied())
                || self.local_history_gate(&state)
                    != crate::local_release_history_protocol::Availability::Available
            {
                return Err(public(Error::Busy));
            }
            let approval = self.history_delegate_owner().history_approval(
                args.kind,
                &args.operation_id,
                &args.owner_generation,
                args.expected_status_revision,
            )?;
            if args.consent_version.as_str() != approval.review().consent() {
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
            if !self.history_consent_current(&state, &approval, selected.0, &selected.1) {
                return Err(public(Error::Conflict));
            }
            let native = self.service_project_locked(&state, approval.project())?;
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            (native, edit.stamp()?, approval, expected)
        };
        // Genuine Host/Store IO only OFF Doc/Edit/Saved locks. No startup,
        // Read grant creation or credential discovery is hidden in Allow.
        let service = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&native)
            .map_err(public)?;
        let point = service
            .version_reserve_point(&native.runtime_id)
            .map_err(public)?;
        let scope = Arc::new(requests::Scope {
            project_id: point.saved.project_id.clone(),
            runtime_id: native.runtime_id.clone(),
            review_id: Id::random().map_err(public)?,
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
        let grant_id = Id::random().map_err(public)?;
        let mut state = self.lock();
        permission::next(&self.inner.agent_store_revoke_epoch, epoch).map_err(public)?;
        self.service_document_gate(&state)?;
        if state.agent_local_history.as_ref().is_some_and(|g| {
            !g.scope.retired.load(Ordering::Acquire) || g.scope.control.first().is_err()
        }) || state
            .agent_store_preparation
            .as_ref()
            .is_some_and(|g| g.occupied())
            || self.inner.agent_store_revoke_epoch.load(Ordering::Acquire) != epoch
            || self.local_history_gate(&state)
                != crate::local_release_history_protocol::Availability::Available
            || state
                .agent_store_grant
                .as_ref()
                .is_some_and(|g| g.occupied())
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
                .history_delegate_owner()
                .history_approval_current(&approval)
        {
            return Err(public(Error::Conflict));
        }
        if !self.history_consent_current(&state, &approval, registration, &root) {
            return Err(public(Error::Conflict));
        }
        service
            .store_requests()
            .can_allow_history()
            .map_err(public)?;
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
        let revision =
            permission::consume(&self.inner.agent_store_revoke_epoch, epoch).map_err(public)?;
        let binding = self
            .history_delegate_owner()
            .bind_history_approval(approval.clone(), scope.clone())?;
        let grant = Arc::new(Grant {
            scope: scope.clone(),
            binding,
            approval,
            native,
            stamp,
        });
        state.agent_local_history = Some(grant.clone());
        match service.store_requests().allow_history(scope, grant_id) {
            Ok(access) => Ok(MainAccess::new(access, revision)),
            Err(e) => {
                self.history_delegate_owner().stop_agent_history(
                    &grant.binding,
                    p::Reason::PermissionRevoked,
                    Instant::now(),
                );
                Err(public(e))
            }
        }
    }
    pub(crate) fn revoke_agent_local_history(
        &self,
        window: &str,
    ) -> Result<MainAccess<p::Access>, BridgeError> {
        // Same shared epoch/revoke stops all three Store-book families, including
        // an in-flight first Allow before it can attach. No new permission owner.
        self.revoke_agent_store(window)?;
        self.agent_local_history_access(window)
    }
    pub(in crate::asset_session) fn stop_history_grant(
        &self,
        g: &Grant,
        reason: crate::service_store_protocol::Reason,
        at: Instant,
    ) {
        self.history_delegate_owner()
            .stop_agent_history(&g.binding, reason, at);
    }
    fn admit_agent_local_history(
        &self,
        service: &Arc<ApplicationService>,
        entry: &Arc<requests::Entry>,
    ) -> Result<(), BridgeError> {
        let grant = {
            let state = self.lock();
            state
                .agent_local_history
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
        let point = service
            .version_reserve_point(&grant.native.runtime_id)
            .map_err(public)?;
        if !grant.scope.matches(&point.saved) || !Arc::ptr_eq(&point.read, &grant.scope.read) {
            return Err(public(Error::Conflict));
        }
        let mut state = self.lock();
        let gate = self.local_history_gate(&state);
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
        self.agent_history_current(&state, &grant, &edit, registration, &root)?;
        if state
            .agent_local_history
            .as_ref()
            .is_none_or(|g| !Arc::ptr_eq(g, &grant))
            || !self
                .history_delegate_owner()
                .history_approval_current(&grant.approval)
        {
            return Err(public(Error::Conflict));
        }
        let admitted = self.history_delegate_owner().start_agent_history(
            entry,
            Some((registration, root)),
            gate,
        )?;
        drop(edit);
        drop(state);
        admitted.release();
        Ok(()) // Existing original GO only.
    }
    fn stop_history_entry(&self, entry: &requests::Entry, reason: p::Reason) {
        entry.cancel(reason, Instant::now());
        let state = self.lock();
        if let Some(g) = state
            .agent_local_history
            .as_ref()
            .filter(|g| Arc::ptr_eq(&g.scope, entry.scope()))
        {
            self.history_delegate_owner()
                .stop_agent_history(&g.binding, reason, Instant::now());
        } else {
            entry.unknown(p::Reason::CleanupUnknown);
        }
    }
    fn check_agent_history_original(&self) {
        let mut state = self.lock();
        let Some(g) = state.agent_local_history.as_ref().cloned() else {
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
            self.agent_history_current(&state, &g, &edit, registration, &root)
        })();
        if current.is_err() {
            self.history_delegate_owner().stop_agent_history(
                &g.binding,
                p::Reason::ContextChanged,
                Instant::now(),
            );
        }
    }
    pub(in crate::asset_session) fn tick_agent_local_history(
        &self,
        service: &Arc<ApplicationService>,
    ) {
        self.check_agent_history_original();
        match service.store_requests().claim_local_history() {
            Ok(Some(claim)) => {
                if self
                    .admit_agent_local_history(service, claim.entry())
                    .is_err()
                {
                    self.stop_history_entry(claim.entry(), p::Reason::NativeRefused);
                }
                claim.returned();
            }
            Ok(None) => {}
            Err(_) => service.store_requests().fence(),
        }
    }
}
pub(in crate::asset_session) fn flush(service: &ApplicationService) -> Result<(), Error> {
    for entry in service.store_requests().history_entries()? {
        let Some(history) = entry.claim_history()? else {
            continue;
        };
        let d = &history.data;
        let result = if history.first {
            service.begin_operation(
                &entry.scope().runtime_id,
                d.operation.operation_id.clone(),
                entry.scope().review.action(),
                d.state,
                history.settlement(),
            )
        } else {
            service.publish_operation(
                &entry.scope().runtime_id,
                d.operation.operation_id.clone(),
                entry.scope().review.action(),
                d.state,
                history.settlement(),
            )
        };
        history.returned(result)?;
    }
    Ok(())
}

/// Within History's explicit part of the unchanged Store2MiB debit. Originals
/// retain their source/material in the existing native census, not these weak
/// scalar comparisons. Both old and replacing grant cells remain covered.
pub(in crate::asset_session) fn native_backing_fits() -> bool {
    use std::mem::size_of;
    let cells = 2 * (size_of::<Grant>() + size_of::<NativeProject>() + size_of::<SavedEditStamp>())
        + size_of::<Allow>()
        // All three MAIN Access families may retain their three existing reply
        // copies. The revision string/slot is additive within this checked
        // 64KiB subguard, never omitted or put onto the unchanged CLI wire.
        + 9 * (size_of::<String>() + 20);
    cells
        .checked_add(6 * 4096 + 8 * 1024)
        .and_then(|n| n.checked_add(crate::saved_command_owner::agent_history_backing_bytes()?))
        .is_some_and(|n| n <= 64 * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_history_allow_raw_is_original_scalar_only_and_native_backing_bounded() {
        let original = serde_json::json!({"kind":"verify","operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"expectedStatusRevision":1,"expectedPermissionRevision":"0","consentVersion":"agent-local-history-verify-once-v1"});
        let a: Allow = decode(&serde_json::to_vec(&original).unwrap()).unwrap();
        assert_eq!(a.kind, p::Kind::Verify);
        assert_eq!(permission::parse(&a.expected_permission_revision), Ok(0));
        let mut missing = original.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("expectedPermissionRevision");
        assert!(decode::<Allow>(&serde_json::to_vec(&missing).unwrap()).is_err());
        for revision in ["00", "1\n", "18446744073709551616"] {
            let mut bad = original.clone();
            bad["expectedPermissionRevision"] = revision.into();
            let decoded: Allow = decode(&serde_json::to_vec(&bad).unwrap()).unwrap();
            assert!(permission::parse(&decoded.expected_permission_revision).is_err());
        }
        for field in [
            "platform",
            "candidateOperationId",
            "root",
            "source",
            "config",
            "material",
        ] {
            let mut bad = original.clone();
            bad[field] = "not-authority".into();
            assert!(decode::<Allow>(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        assert!(decode::<Allow>(&vec![b' '; p::RAW_LIMIT + 1]).is_err());
        assert!(decode::<Allow>(b"{\"kind\":\"enroll\",\"kind\":\"verify\"}").is_err());
        assert!(native_backing_fits());
    }
}
