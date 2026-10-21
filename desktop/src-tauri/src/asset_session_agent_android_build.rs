//! The real main document grants ONE exact saved Android build. IPC contains
//! comparison DATA only; the existing relay calls the SAME original build owner.
use super::*;
use crate::{
    agent_android_build as agent, android_build_protocol as wire,
    application_service::ApplicationService,
    application_service_host::NativeProject,
    edit_owner::SavedEditStamp,
    service_protocol::{Action, Error},
};
use serde::Deserialize;
#[path = "asset_session_agent_android_signed.rs"]
mod signed;
use crate::agent_build_requests::{MainAccess, permission_revision, permission_next};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Allow {
    input: wire::Prepare,
    toolchain_selection: wire::MacToolchainSelection,
    consent_version: String,
    expected_permission_revision: String,
}
/// The current saved reader, edit stamp and catalog comparison are ORIGINALS,
/// not decoded from the consent body. Only one grant retains this small pair.
pub(super) struct Grant {
    scope: Arc<agent::NativeScope>,
    native: NativeProject,
    stamp: SavedEditStamp,
    saved: ValidatedSavedInput,
    approval: Arc<crate::saved_command_owner::AgentAndroidBuildApproval>,
    signing: Option<signed::Pins>,
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
impl DocumentBinding {
    fn agent_android_service(&self) -> Result<Option<Arc<ApplicationService>>, BridgeError> {
        self.inner
            .agent_android_build_service
            .get()
            .map(|original| original.upgrade().ok_or_else(|| public(Error::Unavailable)))
            .transpose()
    }
    fn agent_android_registered(
        &self,
        state: &mut DocumentState,
        id: &str,
    ) -> Result<(u32, asset_source::RegisteredRoot), BridgeError> {
        self.registry_result(state, self.inner.bridge.native_project(id), None)
            .map_err(|error| {
                public(if error.reason == Reason::CleanupUnknown {
                    Error::StateUnknown
                } else {
                    Error::Conflict
                })
            })
    }
    fn agent_android_current(
        &self,
        state: &DocumentState,
        grant: &Grant,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> Result<(), BridgeError> {
        self.service_document_gate(state)?;
        if !edit.matches(&grant.stamp)
            || !self
                .inner
                .android_registration_control
                .matches_epoch(grant.native.input_revision)
            || registration != grant.native.registration_generation
            || root.path != grant.native.canonical_root
            || !root
                .identity
                .posix()
                .is_ok_and(|i| i.service_identity() == (grant.native.device, grant.native.inode))
            || !Arc::ptr_eq(
                &grant.native.document_identity,
                &self.inner.session_identity,
            )
            || !grant.saved.matches(
                &self.inner.session_identity,
                registration,
                root,
                grant.approval.input(),
            )
            || !self
                .inner
                .bridge
                .android_build
                .agent_android_build_approval_current(&grant.approval, &self.inner.session_identity)
            || !self
                .validated_saved_input_with_edit(state, grant.approval.input(), edit)?
                .same_binding(&grant.saved)
        {
            return Err(public(Error::Conflict));
        }
        self.agent_android_signing_material(state, grant, registration, root)?;
        Ok(())
    }
    pub(crate) fn agent_android_build_access(
        &self,
        window: &str,
    ) -> Result<MainAccess, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let _state = self.lock();
        let revision = self.inner.agent_android_build_revoke_epoch.load(Ordering::Acquire);
        let access = match self.agent_android_service()? {
            Some(s) => s.build_requests().access(agent::FAMILY).map_err(public)?,
            None => empty(),
        };
        Ok(MainAccess::new(access, revision))
    }
    pub(crate) fn allow_agent_android_build(
        &self,
        window: &str,
        args: Allow,
    ) -> Result<MainAccess, BridgeError> {
        let signed = args.input.signing.is_some();
        if window != MAIN || args.consent_version != if signed { agent::signed::CONSENT } else { agent::CONSENT } {
            return Err(BridgeError::invalid());
        }
        let expected = permission_revision(&args.expected_permission_revision).map_err(public)?;
        let (native, stamp, saved, approval, signing) = {
            let mut state = self.lock();
            permission_next(expected, self.inner.agent_android_build_revoke_epoch.load(Ordering::Acquire)).map_err(public)?;
            if self.android_build_gate(&state) != wire::Availability::Available {
                return Err(crate::android_build_owner::unavailable());
            }
            self.inner.bridge.android_build.ensure_idle()?;
            let (registration, root) =
                self.agent_android_registered(&mut state, &args.input.project_id)?;
            let native = self.service_project_locked(&state, &args.input.project_id)?;
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            let saved = self.validated_saved_input_with_edit(&state, &args.input, &edit)?;
            if !saved.matches(
                &self.inner.session_identity,
                registration,
                &root,
                &args.input,
            ) {
                return Err(public(Error::Conflict));
            }
            let approval = self
                .inner
                .bridge
                .android_build
                .approve_agent_android_build(
                    args.input,
                    &args.toolchain_selection,
                    &self.inner.session_identity,
                )?;
            let signing = if signed {
                let material = self.review_android_material(&state, &approval.input().context(), registration, &root)?;
                let pins = signed::Pins::capture(&material)?;
                pins.admitted(&approval)?;
                Some(pins) // Only weak comparison pins cross this Doc cut.
            } else { None };
            (native, edit.stamp()?, saved, approval, signing)
        };
        // These original Host/Service calls may perform store IO. NEVER hold
        // Doc/Edit across them. They require the already-listening read host;
        // this action cannot covertly start a listener or borrow its grant.
        let service = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&native)
            .map_err(public)?;
        let (point, read) = service.build_point_with_read(&native.runtime_id).map_err(public)?;
        let scope = Arc::new(agent::NativeScope {
            project_id: point.project_id.clone(),
            runtime_id: native.runtime_id.clone(),
            root: native.canonical_root.clone(),
            device: native.device,
            inode: native.inode,
            registration: native.registration_generation,
            input_revision: native.input_revision,
            document: Arc::downgrade(&self.inner.session_identity),
            observation_revision: point.revision,
            review: approval.review().clone().into(),
            read: signed.then_some(read),
            input: crate::agent_build_requests::NativeInput::Saved { draft_revision: approval.input().draft_revision, baseline_generation: approval.input().baseline_generation },
            changes: self.inner.changes.clone(),
        });
        if !scope.matches(&point) {
            return Err(public(Error::Conflict));
        }
        let grant = Arc::new(Grant {
            scope: scope.clone(),
            native,
            stamp,
            saved,
            approval,
            signing,
        });
        let mut state = self.lock();
        if self.android_build_gate(&state) != wire::Availability::Available {
            return Err(crate::android_build_owner::unavailable());
        }
        self.inner.bridge.android_build.ensure_idle()?;
        let (registration, root) =
            self.agent_android_registered(&mut state, &grant.native.runtime_id)?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        self.agent_android_current(&state, &grant, &edit, registration, &root)?;
        let next = permission_next(expected,
            self.inner.agent_android_build_revoke_epoch.load(Ordering::Acquire)).map_err(public)?;
        if let Some(original) = self.inner.agent_android_build_service.get() {
            if original.as_ptr() != Arc::as_ptr(&service) {
                return Err(public(Error::Conflict));
            }
        } else {
            self.inner
                .agent_android_build_service
                .set(Arc::downgrade(&service))
                .map_err(|_| public(Error::StateUnknown))?;
        }
        // Both cuts compare the SAME revision actually returned to MAIN;
        // an earlier Revoke or successful Allow cannot be silently rebased.
        // Overflow was checked before any Inbox/Doc grant installation.
        let access = service.build_requests().allow(scope).map_err(public)?;
        state.agent_android_build_grant = Some(grant);
        self.inner.agent_android_build_revoke_epoch.store(next, Ordering::Release);
        Ok(MainAccess::new(access, next))
    }
    pub(crate) fn revoke_agent_android_build(
        &self,
        window: &str,
    ) -> Result<MainAccess, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let _state = self.lock();
        let advanced = self
            .inner
            .agent_android_build_revoke_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |e| e.checked_add(1))
            .map_err(|_| public(Error::StateUnknown));
        let revoked = match self.agent_android_service() {
            Ok(Some(s)) => s.build_requests().revoke(agent::FAMILY).map_err(public),
            Ok(None) => Ok(empty()),
            Err(e) => Err(e),
        };
        // Counter failure must not skip the original STOP.
        advanced.and(revoked).map(|a| MainAccess::new(a,
            self.inner.agent_android_build_revoke_epoch.load(Ordering::Acquire)))
    }
    fn admit_agent_android_build(
        &self,
        service: &Arc<ApplicationService>,
        entry: &Arc<agent::Entry>,
        kind: agent::ClaimKind,
    ) -> Result<(), BridgeError> {
        if entry.family() != agent::FAMILY { return Err(public(Error::Conflict)); }
        let grant = {
            let state = self.lock();
            state
                .agent_android_build_grant
                .as_ref()
                .filter(|g| std::ptr::eq(g.scope.as_ref(), entry.scope()))
                .cloned()
                .ok_or_else(|| public(Error::Conflict))?
        };
        let current_service = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&grant.native)
            .map_err(public)?;
        if !Arc::ptr_eq(service, &current_service) {
            return Err(public(Error::Conflict));
        }
        match kind {
            agent::ClaimKind::Prepare => {
                let (point, read) = service.build_point_with_read(&grant.native.runtime_id).map_err(public)?;
                if !entry.prepare_live() || !entry.scope().matches(&point) || !entry.scope().matches_read(&read)
                {
                    return Err(public(Error::Conflict));
                }
            }
            agent::ClaimKind::Start => {
                if !entry.start_live() {
                    return Err(public(Error::Expired));
                }
                // The existing Projects writer marks the prior shared snapshot
                // stale BEFORE possible build effects. A later known refusal
                // may leave it stale; it never claims the build was executed.
                service
                    .consume_build_observation(entry.scope())
                    .map_err(public)?;
            }
        }
        let mut state = self.lock();
        let gate = self.android_build_gate(&state); // Same reciprocal peers, before Edit.
        if gate != wire::Availability::Available {
            return Err(crate::android_build_owner::unavailable());
        }
        let (registration, root) =
            self.agent_android_registered(&mut state, &grant.native.runtime_id)?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        self.agent_android_current(&state, &grant, &edit, registration, &root)?;
        if state
            .agent_android_build_grant
            .as_ref()
            .is_none_or(|g| !Arc::ptr_eq(g, &grant))
        {
            return Err(public(Error::Conflict));
        }
        match kind {
            agent::ClaimKind::Prepare => {
                self.inner
                    .bridge
                    .android_build
                    .prepare_agent_android_build(
                        entry.clone(),
                        grant.approval.clone(),
                        registration,
                        root.clone(),
                        gate,
                        self.agent_android_signing_material(&state, &grant, registration, &root)?,
                    )?;
            }
            agent::ClaimKind::Start => {
                let material = self.inner.bridge.android_build.agent_android_build_material(entry)?;
                match (&grant.signing, &material) {
                    (None, None) => {},
                    (Some(pins), Some(original)) if pins.matches(original) => {
                        self.recheck_android_material(&state, original, registration, &root)?;
                    },
                    _ => return Err(public(Error::Conflict)),
                }
                let admitted = self.inner.bridge.android_build.start_agent_android_build(
                    entry,
                    Some((registration, root)),
                    gate,
                    material,
                )?;
                drop(edit);
                drop(state);
                let _ = admitted.release(); // The SAME original GO, only after both guards drop.
            }
        }
        Ok(())
    }
    fn revoke_stale_agent_android(&self, service: &ApplicationService) {
        // No service-state/Host IO, no new native input reader. The existing
        // control epoch and returned saved binding detect local invalidation.
        let mut state = self.lock();
        let Some(grant) = state.agent_android_build_grant.as_ref().cloned() else {
            return;
        };
        let current = (|| {
            let (registration, root) =
                self.agent_android_registered(&mut state, &grant.native.runtime_id)?;
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            self.agent_android_current(&state, &grant, &edit, registration, &root)
        })();
        if current.is_err() {
            let _ = service.build_requests().revoke(agent::FAMILY);
        }
    }
    /// Called by the already-retained relay, never by an IPC worker or a new task.
    pub(crate) fn service_android_builds_tick(&self) {
        let Ok(Some(service)) = self.agent_android_service() else {
            return;
        };
        self.revoke_stale_agent_android(&service);
        match service.build_requests().claim(agent::FAMILY) {
            Ok(Some(claim)) => {
                let result = self.admit_agent_android_build(&service, claim.entry(), claim.kind());
                claim.returned(result.is_ok());
            }
            Ok(None) => {}
            Err(_) => {
                let _ = service.build_requests().revoke(agent::FAMILY);
            }
        }
        let _ = flush(&service, agent::FAMILY);
    }
    pub(crate) fn agent_android_builds_relay_lost(&self) {
        if let Ok(Some(s)) = self.agent_android_service() {
            let _ = s.build_requests().revoke(agent::FAMILY);
        }
    }
    /// After all original domain owners AND this same relay joined. Never
    /// dispatch remaining queued Prepare/Start to clear a shutdown inbox.
    pub(crate) fn drain_android_builds_for_exit(&self) {
        if let Ok(Some(s)) = self.agent_android_service() {
            s.build_requests().close();
            let _ = flush(&s, agent::FAMILY);
        }
    }
}
pub(super) fn flush(service: &ApplicationService, family: crate::agent_build_requests::Family) -> Result<(), Error> {
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
    for entry in service.build_requests().entries(family)? {
        let claimed = match entry.claim_history() {
            Ok(v) => v,
            Err(e) => {
                failed.get_or_insert(e);
                continue;
            }
        };
        let Some((first, data)) = claimed else {
            continue;
        };
        struct OriginalHistory<'a> { entry: &'a agent::Entry, returned: bool }
        impl Drop for OriginalHistory<'_> {
            fn drop(&mut self) { if !self.returned { self.entry.history_lost(); } }
        }
        let mut original = OriginalHistory { entry: &entry, returned: false };
        let result = if first {
            service.begin_operation(
                &entry.scope().runtime_id,
                data.operation_id().clone(),
                Action::Build,
                data.state(),
                data.settlement(),
            )
        } else {
            service.publish_operation(
                &entry.scope().runtime_id,
                data.operation_id().clone(),
                Action::Build,
                data.state(),
                data.settlement(),
            )
        };
        let result = entry.history_returned(data.status_revision(), result);
        original.returned = true;
        if let Err(e) = result { failed.get_or_insert(e); }
    }
    if let Some(e) = failed {
        Err(e)
    } else {
        returned.known = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dormant_or_foreign_document_cannot_start_a_host_or_grant_execution() {
        let bridge = Arc::new(DesktopBridge::new(std::path::PathBuf::from(
            "/unopened-agent-build-data-fixture",
        )));
        let doc = DocumentBinding::new(bridge.clone());
        assert!(!doc.agent_android_build_access(MAIN).unwrap().enabled);
        assert!(!doc.revoke_agent_android_build(MAIN).unwrap().enabled);
        assert!(doc.agent_android_build_access("other").is_err());
        doc.service_android_builds_tick();
        doc.drain_android_builds_for_exit();
        assert!(!bridge.application_service.status().unwrap().enabled);
    }
    #[test]
    fn actual_main_revoke_before_first_allow_cut_invalidates_the_returned_revision() {
        let bridge=Arc::new(DesktopBridge::new(std::path::PathBuf::from("/inert/unopened-build-revision")));
        let doc=DocumentBinding::new(bridge.clone());
        let access=doc.agent_android_build_access(MAIN).unwrap();assert_eq!(access.permission_revision,"0");
        assert_eq!(doc.revoke_agent_android_build(MAIN).unwrap().permission_revision,"1");
        let input=wire::prepare(&serde_json::json!({"projectId":"inert","draftRevision":1,"baselineGeneration":2,
            "savedConfig":{"bytes":123,"sha256":"a".repeat(64)},"savedVersion":{"source":"version.properties","bytes":32,"sha256":"b".repeat(64),"name":"1.2.3","build":7},
            "artifactValidation":{"mode":"structure-and-version","uploadCertificateSha256":null}})).unwrap();
        let selection=wire::MacToolchainSelection { instance:"c".repeat(32),owner_uid:501,catalog_generation:1,
            record_sha256:"d".repeat(64),inventory_sha256:"e".repeat(64),os_provider_sha256:"f".repeat(64) };
        let args=Allow {input,toolchain_selection:selection,consent_version:agent::CONSENT.into(),expected_permission_revision:access.permission_revision};
        assert_eq!(doc.allow_agent_android_build(MAIN,args).unwrap_err().code,public(Error::AccessDenied).code);
        assert!(doc.lock().agent_android_build_grant.is_none());assert!(doc.inner.agent_android_build_service.get().is_none());
        doc.inner.agent_android_build_revoke_epoch.store(u64::MAX,Ordering::Release);
        assert!(doc.revoke_agent_android_build(MAIN).is_err());
        assert_eq!(doc.agent_android_build_access(MAIN).unwrap().permission_revision,u64::MAX.to_string());
        assert!(!bridge.application_service.status().unwrap().enabled);
    }
    #[test]
    fn consent_body_cannot_supply_paths_commands_original_ids_or_window() {
        let base = serde_json::json!({"input":{"projectId":"project-1","draftRevision":0,"baselineGeneration":0,
            "savedConfig":{"bytes":2,"sha256":"a".repeat(64)},"savedVersion":{"source":"version.properties","bytes":3,"sha256":"b".repeat(64),"name":"1.0","build":1},
            "artifactValidation":{"mode":"structure-and-version","uploadCertificateSha256":null}},
            "toolchainSelection":{"instance":"c".repeat(32),"ownerUid":501,"catalogGeneration":1,"recordSha256":"d".repeat(64),"inventorySha256":"e".repeat(64),"osProviderSha256":"f".repeat(64)},"consentVersion":agent::CONSENT,"expectedPermissionRevision":"0"});
        let decode = |v: &Value| {
            super::super::agent_identity::decode::<Allow>(&serde_json::to_vec(v).unwrap())
        };
        assert!(decode(&base).is_ok());
        for field in [
            "root",
            "command",
            "operationId",
            "clientId",
            "window",
            "grant",
        ] {
            let mut value = base.clone();
            value[field] = serde_json::json!("untrusted");
            assert!(decode(&value).is_err());
        }
    }
}
