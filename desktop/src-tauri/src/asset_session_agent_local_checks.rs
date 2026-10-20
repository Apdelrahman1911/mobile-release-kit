//! A named local-check permission on the genuine Desktop document. Socket
//! requests only enqueue DATA; this existing relay enters the SAME preflight
//! owner. No synthetic window, executor, project root or worker is accepted.
use super::*;
use crate::{
    agent_local_checks as agent,
    application_service::ApplicationService,
    application_service_host::NativeProject,
    edit_owner::SavedEditStamp,
    offline_preflight_protocol as wire,
    service_protocol::{Action, Error},
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Allow {
    project_id: String,
    draft_revision: u32,
    baseline_generation: u32,
    consent_version: String,
}
/// The original private stamp is never reconstructed from a CLI/GUI value.
/// Retained under the actual Doc; Arc copies cross only the off-lock IO gap.
pub(super) struct Grant {
    scope: Arc<agent::NativeScope>,
    native: NativeProject,
    stamp: SavedEditStamp,
}
fn public(error: Error) -> BridgeError {
    application_service::public_error(error)
}
fn empty() -> agent::Access {
    agent::Access {
        enabled: false,
        remaining_ms: 0,
        project_id: None,
        observation_revision: None,
        consumed: false,
    }
}
fn same_native(scope: &agent::NativeScope, native: &NativeProject) -> bool {
    scope.runtime_id == native.runtime_id
        && scope.root == native.canonical_root
        && scope.device == native.device
        && scope.inode == native.inode
        && scope.registration == native.registration_generation
        && scope.input_revision == native.input_revision
        && scope.document.as_ptr() == Arc::as_ptr(&native.document_identity)
}
impl DocumentBinding {
    fn local_check_service(&self) -> Result<Option<Arc<ApplicationService>>, BridgeError> {
        self.inner
            .agent_local_check_service
            .get()
            .map(|original| original.upgrade().ok_or_else(|| public(Error::Unavailable)))
            .transpose()
    }
    pub(crate) fn agent_local_check_access(
        &self,
        window: &str,
    ) -> Result<agent::Access, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        // Reading this memory-only permission never starts a Host or a query.
        match self.local_check_service()? {
            Some(service) => service.local_checks().access().map_err(public),
            None => Ok(empty()),
        }
    }
    pub(crate) fn allow_agent_local_check(
        &self,
        window: &str,
        args: Allow,
    ) -> Result<agent::Access, BridgeError> {
        if window != MAIN
            || !crate::protocol::valid_id(&args.project_id)
            || args.consent_version != agent::CONSENT
            || args.draft_revision == u32::MAX
            || args.baseline_generation == u32::MAX
        {
            return Err(BridgeError::invalid());
        }
        let (original, stamp, epoch) = {
            let state = self.lock();
            if self.preflight_gate(&state) != wire::Availability::Available {
                return Err(crate::offline_preflight_owner::unavailable());
            }
            self.inner.bridge.preflight.ensure_idle()?;
            let native = self.service_project_locked(&state, &args.project_id)?;
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            let epoch = self
                .inner
                .agent_local_check_revoke_epoch
                .load(Ordering::Acquire);
            if epoch == u64::MAX {
                return Err(public(Error::StateUnknown));
            }
            (native, edit.stamp()?, epoch)
        };
        // SAME already-listening Host/service. Both original mutexes can guard
        // real IO, so neither call runs with Document or Edit held.
        let service = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&original)
            .map_err(public)?;
        let saved = service
            .local_check_point(&original.runtime_id)
            .map_err(public)?;
        let mut state = self.lock();
        if self.preflight_gate(&state) != wire::Availability::Available {
            return Err(crate::offline_preflight_owner::unavailable());
        }
        self.inner.bridge.preflight.ensure_idle()?;
        let current = self.service_allow_current_locked(&state, &original, &stamp)?;
        if epoch == u64::MAX
            || self
                .inner
                .agent_local_check_revoke_epoch
                .load(Ordering::Acquire)
                != epoch
        {
            return Err(public(Error::AccessDenied));
        }
        let scope = Arc::new(agent::NativeScope {
            project_id: saved.project_id.clone(),
            runtime_id: current.runtime_id.clone(),
            root: current.canonical_root.clone(),
            device: current.device,
            inode: current.inode,
            registration: current.registration_generation,
            input_revision: current.input_revision,
            document: Arc::downgrade(&self.inner.session_identity),
            observation_revision: saved.revision,
            config: saved
                .config
                .clone()
                .ok_or_else(|| public(Error::Conflict))?,
            draft_revision: args.draft_revision,
            baseline_generation: args.baseline_generation,
            changes: self.inner.changes.clone(),
        });
        if !saved.matches(&scope) {
            return Err(public(Error::Conflict));
        }
        if let Some(weak) = self.inner.agent_local_check_service.get() {
            if weak.as_ptr() != Arc::as_ptr(&service) {
                return Err(public(Error::Conflict));
            }
        } else {
            self.inner
                .agent_local_check_service
                .set(Arc::downgrade(&service))
                .map_err(|_| public(Error::StateUnknown))?;
        }
        // All permission installation and first-Allow/revoke comparison occur
        // under the SAME Doc guard. No service.state or IO is called here.
        let access = service
            .local_checks()
            .allow(scope.clone())
            .map_err(public)?;
        state.agent_local_check_grant = Some(Arc::new(Grant {
            scope,
            native: current,
            stamp,
        }));
        Ok(access)
    }
    pub(crate) fn revoke_agent_local_check(
        &self,
        window: &str,
    ) -> Result<agent::Access, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let _state = self.lock();
        let advanced = self
            .inner
            .agent_local_check_revoke_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch.checked_add(1)
            })
            .map_err(|_| public(Error::StateUnknown));
        // Saturation or poisoned permission never skips SAME original STOP.
        let revoked = match self.local_check_service() {
            Ok(Some(service)) => service.local_checks().revoke().map_err(public),
            Ok(None) => Ok(empty()),
            Err(error) => Err(error),
        };
        advanced.and(revoked)
    }
    fn admit_local_check(
        &self,
        service: &Arc<ApplicationService>,
        entry: &Arc<agent::Entry>,
    ) -> Result<(), BridgeError> {
        let grant = {
            let state = self.lock();
            let grant = state
                .agent_local_check_grant
                .as_ref()
                .filter(|g| std::ptr::eq(g.scope.as_ref(), entry.scope()))
                .ok_or_else(|| public(Error::Conflict))?;
            if !entry.admission_live() {
                return Err(public(Error::AccessDenied));
            }
            grant.clone()
        };
        let host_service = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&grant.native)
            .map_err(public)?;
        if !Arc::ptr_eq(service, &host_service) {
            return Err(public(Error::Conflict));
        }
        // Atomically compare the SAME saved observation and mark it stale via
        // the existing Projects writer, OFF all native document/edit guards.
        // A later preclaim refusal may conservatively leave it stale; it never
        // claims that a project check ran or that a result passed.
        service
            .consume_local_check_observation(entry.scope())
            .map_err(public)?;
        let at = Instant::now();
        let state = self.lock();
        let gate = self.preflight_gate(&state); // Contains reciprocal peers; before holding Edit below.
        if gate != wire::Availability::Available {
            return Err(crate::offline_preflight_owner::unavailable());
        }
        let current = self.service_allow_current_locked(&state, &grant.native, &grant.stamp)?;
        if !same_native(entry.scope(), &current)
            || !entry.admission_live()
            || state
                .agent_local_check_grant
                .as_ref()
                .is_none_or(|g| !Arc::ptr_eq(g, &grant))
        {
            return Err(public(Error::Conflict));
        }
        let (registration, root) = self
            .inner
            .bridge
            .native_project(&entry.scope().runtime_id)?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        if !edit.matches(&grant.stamp) {
            return Err(public(Error::Conflict));
        }
        // Original IDs are linked during this SAME Prepare before publication;
        // common Start rejects ordinary GUI consent for an agent-bound intent.
        self.inner.bridge.preflight.prepare_agent_local_check(
            entry.clone(),
            registration,
            root.clone(),
            gate,
        )?;
        let admitted = self.inner.bridge.preflight.start_agent_local_check(
            entry,
            at,
            Some((registration, root)),
            gate,
        )?;
        drop(edit);
        drop(state);
        let _ = admitted.release(); // The actual original GO only after unlocking.
        Ok(())
    }
    /// Called solely by the existing, retained native relay. No new task and no
    /// callback into native owners from ApplicationService/socket workers.
    pub(crate) fn service_local_checks_tick(&self) {
        let Ok(Some(service)) = self.local_check_service() else {
            return;
        };
        match service.local_checks().claim() {
            Ok(Some(claim)) => {
                let result = self.admit_local_check(&service, claim.entry());
                claim.returned(result.is_ok());
            }
            Ok(None) => {}
            Err(_) => {
                let _ = service.local_checks().revoke();
            }
        }
        let _ = flush(&service);
    }
    pub(crate) fn agent_local_checks_relay_lost(&self) {
        if let Ok(Some(service)) = self.local_check_service() {
            let _ = service.local_checks().revoke();
        }
    }
    /// After every actual domain owner AND this same relay joined. Flush only:
    /// shutdown never dispatches a remaining queued action to clear an inbox.
    pub(crate) fn drain_local_checks_for_exit(&self) {
        if let Ok(Some(service)) = self.local_check_service() {
            service.local_checks().close();
            let _ = flush(&service); // A retained failure cannot skip Host close.
        }
    }
}
fn flush(service: &ApplicationService) -> Result<(), Error> {
    // SAME relay return, not a task or second writer. A lost/panicked write or
    // acknowledgement retains the claimed record and fences saved reads.
    struct Returned<'a> {
        service: &'a ApplicationService,
        known: bool,
    }
    impl Drop for Returned<'_> {
        fn drop(&mut self) {
            if !self.known {
                self.service.fence_native_history();
            }
        }
    }
    let mut returned = Returned {
        service,
        known: false,
    };
    let mut failed = None;
    for entry in service.local_checks().entries()? {
        let claimed = match entry.claim_history() {
            Ok(value) => value,
            Err(error) => {
                failed.get_or_insert(error);
                continue;
            }
        };
        let Some((first, data)) = claimed else {
            continue;
        };
        let result = if first {
            service.begin_operation(
                &entry.scope().runtime_id,
                data.operation_id.clone(),
                Action::LocalProjectChecks,
                data.state,
                data.settlement,
            )
        } else {
            service.publish_operation(
                &entry.scope().runtime_id,
                data.operation_id.clone(),
                Action::LocalProjectChecks,
                data.state,
                data.settlement,
            )
        };
        if let Err(error) = entry.history_returned(data.status_revision, result) {
            failed.get_or_insert(error);
        }
    }
    if let Some(error) = failed {
        Err(error)
    } else {
        returned.known = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn named_consent_has_no_root_command_or_original_authority_field() {
        let decode = |v: serde_json::Value| {
            super::super::agent_identity::decode::<Allow>(&serde_json::to_vec(&v).unwrap())
        };
        let value = serde_json::json!({"projectId":"project-1","draftRevision":4,"baselineGeneration":3,"consentVersion":agent::CONSENT});
        assert!(decode(value.clone()).is_ok());
        for field in [
            "root",
            "executable",
            "operationId",
            "clientId",
            "window",
            "savedConfig",
        ] {
            let mut extra = value.clone();
            extra[field] = serde_json::json!("untrusted");
            assert!(decode(extra).is_err());
        }
    }
    #[test]
    fn dormant_native_document_does_not_open_host_or_infer_consent() {
        let bridge = Arc::new(DesktopBridge::new(std::path::PathBuf::from(
            "/unopened-local-check-test",
        )));
        let doc = DocumentBinding::new(bridge.clone());
        assert!(!doc.agent_local_check_access(MAIN).unwrap().enabled);
        assert!(!doc.revoke_agent_local_check(MAIN).unwrap().enabled);
        assert!(doc
            .allow_agent_local_check(
                MAIN,
                Allow {
                    project_id: "project-1".into(),
                    draft_revision: 0,
                    baseline_generation: 0,
                    consent_version: agent::CONSENT.into()
                }
            )
            .is_err());
        doc.service_local_checks_tick();
        assert!(!bridge.application_service.status().unwrap().enabled);
    }
}
