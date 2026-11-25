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
    expected_permission_revision: String,
}
/// MAIN's ordering stamp is not a CLI grant or a new permission owner.
/// Keep the original five-field service/CLI Access unchanged.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainAccess {
    #[serde(flatten)]
    pub(crate) access: agent::Access,
    pub(crate) permission_revision: String,
}
fn main_access(access: agent::Access, revision: u64) -> MainAccess {
    MainAccess { access, permission_revision: revision.to_string() }
}
fn permission_revision(text: &str) -> Result<u64, BridgeError> {
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|c| c.is_ascii_digit())
        || text.len() > 1 && text.starts_with('0')
    {
        return Err(BridgeError::invalid());
    }
    text.parse().map_err(|_| BridgeError::invalid())
}
/// Called under the same Doc guard as status, final installation and Revoke.
/// Consume before off-Doc work: a refused/lost attempt cannot replay its stamp.
fn consume_allow_revision(counter: &std::sync::atomic::AtomicU64, expected: u64) -> Result<u64, BridgeError> {
    // MAX is terminal: an overflowing Revoke cannot invalidate a MAX ticket.
    let next = expected.checked_add(1).filter(|v| *v < u64::MAX)
        .ok_or_else(|| public(Error::StateUnknown))?;
    counter.compare_exchange(expected, next, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| next).map_err(|_| public(Error::AccessDenied))
}
fn allow_revision_current(counter: &std::sync::atomic::AtomicU64, expected: u64) -> Result<(), BridgeError> {
    if counter.load(Ordering::Acquire) == expected { Ok(()) } else { Err(public(Error::AccessDenied)) }
}
fn revoke_revision<T>(counter: &std::sync::atomic::AtomicU64, stop: impl FnOnce() -> Result<T, BridgeError>) -> Result<T, BridgeError> {
    let advanced = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
        .map_err(|_| public(Error::StateUnknown));
    let stopped = stop(); // Overflow must never skip the original STOP.
    advanced.and(stopped)
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
    ) -> Result<MainAccess, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        // Reading this memory-only permission never starts a Host or a query.
        let _state = self.lock();
        let access = match self.local_check_service()? {
            Some(service) => service.local_checks().access().map_err(public),
            None => Ok(empty()),
        }?;
        Ok(main_access(access, self.inner.agent_local_check_revoke_epoch.load(Ordering::Acquire)))
    }
    pub(crate) fn allow_agent_local_check(
        &self,
        window: &str,
        args: Allow,
    ) -> Result<MainAccess, BridgeError> {
        if window != MAIN
            || !crate::protocol::valid_id(&args.project_id)
            || args.consent_version != agent::CONSENT
            || args.draft_revision == u32::MAX
            || args.baseline_generation == u32::MAX
        {
            return Err(BridgeError::invalid());
        }
        let expected = permission_revision(&args.expected_permission_revision)?;
        let (original, stamp, epoch) = {
            let state = self.lock();
            let epoch = consume_allow_revision(&self.inner.agent_local_check_revoke_epoch, expected)?;
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
        allow_revision_current(&self.inner.agent_local_check_revoke_epoch, epoch)?;
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
        Ok(main_access(access, epoch))
    }
    pub(crate) fn revoke_agent_local_check(
        &self,
        window: &str,
    ) -> Result<MainAccess, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let _state = self.lock();
        // Saturation or poisoned permission never skips SAME original STOP.
        let access = revoke_revision(&self.inner.agent_local_check_revoke_epoch, || match self.local_check_service() {
            Ok(Some(service)) => service.local_checks().revoke().map_err(public),
            Ok(None) => Ok(empty()),
            Err(error) => Err(error),
        })?;
        Ok(main_access(access, self.inner.agent_local_check_revoke_epoch.load(Ordering::Acquire)))
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
        let mut state = self.lock();
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
            .registry_result(
                &mut state,
                self.inner.bridge.native_project(&entry.scope().runtime_id),
                None,
            )
            .map_err(|error| public(if error.reason == Reason::CleanupUnknown {
                Error::StateUnknown
            } else {
                Error::Conflict
            }))?;
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
        let value = serde_json::json!({"projectId":"project-1","draftRevision":4,"baselineGeneration":3,"consentVersion":agent::CONSENT,"expectedPermissionRevision":"7"});
        assert!(decode(value.clone()).is_ok());
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove("expectedPermissionRevision");
        assert!(decode(missing).is_err());
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
        let checked = doc.agent_local_check_access(MAIN).unwrap();
        assert!(!checked.access.enabled);
        assert_eq!(checked.permission_revision, "0");
        let revoked = doc.revoke_agent_local_check(MAIN).unwrap();
        assert!(!revoked.access.enabled);
        assert_eq!(revoked.permission_revision, "1");
        let error = doc
            .allow_agent_local_check(
                MAIN,
                Allow {
                    project_id: "project-1".into(),
                    draft_revision: 0,
                    baseline_generation: 0,
                    consent_version: agent::CONSENT.into(),
                    expected_permission_revision: checked.permission_revision,
                }
            )
            .err().expect("late Allow must fail before the unavailable preflight gate");
        assert_eq!(error.code, public(Error::AccessDenied).code);
        doc.service_local_checks_tick();
        assert!(!bridge.application_service.status().unwrap().enabled);
    }
    #[test]
    fn main_revision_is_closed_lossless_and_not_a_cli_access_field() {
        for value in ["0", "7", "9007199254740993", "18446744073709551615"] {
            assert_eq!(permission_revision(value).unwrap().to_string(), value);
        }
        for value in ["", "00", "01", "+1", "-1", "1.0", "1\n", "18446744073709551616"] {
            assert!(permission_revision(value).is_err(), "{value:?}");
        }
        let base = serde_json::to_value(empty()).unwrap();
        assert_eq!(base.as_object().unwrap().len(), 5);
        let main = serde_json::to_value(main_access(empty(), u64::MAX)).unwrap();
        assert_eq!(main.as_object().unwrap().len(), 6);
        assert_eq!(main["permissionRevision"], u64::MAX.to_string());
    }
    #[test]
    fn checked_allow_is_one_use_and_revoke_invalidates_both_native_cuts() {
        use std::sync::atomic::AtomicU64;
        let counter = AtomicU64::new(7);
        let checked = counter.load(Ordering::Acquire);
        revoke_revision(&counter, || Ok(())).unwrap();
        assert_eq!(consume_allow_revision(&counter, checked).unwrap_err().code, public(Error::AccessDenied).code);
        let next = consume_allow_revision(&counter, 8).unwrap();
        assert!(allow_revision_current(&counter, next).is_ok());
        // Even a lost/refused first attempt cannot reuse its earlier Check.
        assert!(consume_allow_revision(&counter, 8).is_err());
        revoke_revision(&counter, || Ok(())).unwrap();
        assert_eq!(allow_revision_current(&counter, next).unwrap_err().code, public(Error::AccessDenied).code);
    }
    #[test]
    fn terminal_revision_cannot_install_and_overflow_still_calls_original_stop() {
        use std::sync::atomic::AtomicU64;
        let counter = AtomicU64::new(u64::MAX - 1);
        assert!(consume_allow_revision(&counter, u64::MAX - 1).is_err());
        let mut stops = 0;
        revoke_revision(&counter, || { stops += 1; Ok(()) }).unwrap();
        assert_eq!(counter.load(Ordering::Acquire), u64::MAX);
        assert!(consume_allow_revision(&counter, u64::MAX).is_err());
        assert!(revoke_revision(&counter, || { stops += 1; Ok(()) }).is_err());
        assert_eq!(stops, 2);
    }
}
