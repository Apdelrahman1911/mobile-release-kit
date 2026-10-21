//! The real main document grants ONE exact saved iOS build. IPC contains
//! comparison DATA only; the existing relay calls the SAME original build owner.
use super::*;
use crate::{
    agent_ios_archive as agent,
    application_service::ApplicationService,
    application_service_host::NativeProject,
    edit_owner::SavedEditStamp,
    ios_archive_protocol as wire,
    service_protocol::{Action, Error},
};
use serde::Deserialize;
#[path = "asset_session_agent_ios_recovery.rs"]
mod recovery;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SavedAllow {
    input: wire::Prepare,
    consent_version: String,
    expected_permission_revision: String,
}
#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum Allow { Saved(SavedAllow), Recovery(recovery::Allow) }
/// The current saved reader and edit stamp are ORIGINALS,
/// not decoded from the consent body. Only one grant retains this small pair.
pub(super) struct Grant {
    scope: Arc<agent::NativeScope>,
    native: NativeProject,
    source: GrantSource,
}
enum GrantSource { Saved(SavedSource), Recovery(Arc<crate::saved_command_owner::AgentIOSRecoveryApproval>) }
struct SavedSource {
    stamp: SavedEditStamp,
    saved: ValidatedSavedInput,
    approval: Arc<crate::saved_command_owner::AgentIOSArchiveApproval>,
    signing: Option<ios_signing::agent::Pin>,
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
    fn agent_ios_service(&self) -> Result<Option<Arc<ApplicationService>>, BridgeError> {
        self.inner
            .agent_ios_archive_service
            .get()
            .map(|original| original.upgrade().ok_or_else(|| public(Error::Unavailable)))
            .transpose()
    }
    fn agent_ios_registered(
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
    fn agent_ios_current(
        &self,
        state: &DocumentState,
        grant: &Grant,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> Result<(), BridgeError> {
        let GrantSource::Saved(saved) = &grant.source else {
            return self.agent_ios_recovery_current(state, grant, registration, root);
        };
        self.service_document_gate(state)?;
        if !edit.matches(&saved.stamp)
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
            || !saved.saved.matches_ios(
                &self.inner.session_identity,
                registration,
                root,
                saved.approval.input(),
            )
            || !self
                .inner
                .bridge
                .ios_archive
                .agent_ios_archive_approval_current(&saved.approval, &self.inner.session_identity)
            || !self
                .validated_ios_saved_input_with_edit(
                    state,
                    saved.approval.input(),
                    edit,
                    registration,
                    root,
                )?
                .same_binding(&saved.saved)
        {
            return Err(public(Error::Conflict));
        }
        match (&saved.signing, saved.approval.input().signing.is_some()) {
            (Some(pin), true) if pin.current(state, &saved.approval.input().context(), registration, root) => {},
            (None, false) => {},
            _ => return Err(public(Error::Conflict)),
        }
        Ok(())
    }
    pub(crate) fn agent_ios_archive_access(
        &self,
        window: &str,
    ) -> Result<agent::MainAccess, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let _state = self.lock();
        let access = match self.agent_ios_service()? {
            Some(s) => s.build_requests().access(agent::FAMILY).map_err(public)?,
            None => empty(),
        };
        let mut result = agent::MainAccess::new(access, self.inner.agent_ios_archive_revoke_epoch.load(Ordering::Acquire));
        result.recovery_inspection = self.inner.bridge.ios_archive.agent_ios_recovery_acknowledged(&self.inner.session_identity);
        Ok(result)
    }
    pub(crate) fn allow_agent_ios_archive(
        &self,
        window: &str,
        args: Allow,
    ) -> Result<agent::MainAccess, BridgeError> {
        let args = match args { Allow::Saved(v) => v, Allow::Recovery(v) => return self.allow_agent_ios_recovery(window, v) };
        let consent = match args.input.context().operation {
            wire::Operation::IOSUnsignedArchive => agent::CONSENT,
            wire::Operation::IOSSignedExport if args.input.action.is_none() && args.input.recovery.is_none() => agent::signed::CONSENT,
            _ => return Err(BridgeError::invalid()),
        };
        if window != MAIN || args.consent_version != consent { return Err(BridgeError::invalid()); }
        let expected = agent::permission_revision(&args.expected_permission_revision).map_err(public)?;
        let (native, stamp, saved, approval, signing) = {
            let mut state = self.lock();
            agent::permission_next(expected, self.inner.agent_ios_archive_revoke_epoch.load(Ordering::Acquire)).map_err(public)?;
            if self.ios_archive_gate(&state) != wire::Availability::Available {
                return Err(crate::ios_archive_owner::unavailable());
            }
            self.inner.bridge.ios_archive.ensure_idle()?;
            let (registration, root) =
                self.agent_ios_registered(&mut state, &args.input.project_id)?;
            let native = self.service_project_locked(&state, &args.input.project_id)?;
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            let saved = self.validated_ios_saved_input_with_edit(
                &state,
                &args.input,
                &edit,
                registration,
                &root,
            )?;
            if !saved.matches_ios(
                &self.inner.session_identity,
                registration,
                &root,
                &args.input,
            ) {
                return Err(public(Error::Conflict));
            }
            let signing = if args.input.signing.is_some() {
                let material = self.review_ios_material(&state, &args.input.context(), registration, &root)?;
                Some(ios_signing::agent::Pin::capture(&material)?)
            } else { None };
            let approval = self
                .inner
                .bridge
                .ios_archive
                .approve_agent_ios_archive(args.input, &self.inner.session_identity)?;
            if signing.as_ref().is_some_and(|pin| pin.retained_bytes()
                .and_then(|n| approval.signing_backing_bytes().and_then(|a| n.checked_add(a)))
                .is_none_or(|n| n > crate::agent_build_requests::SIGNED_BINDING_BYTES)) {
                return Err(public(Error::StateUnknown));
            }
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
        let (point, read) = service
            .build_point_with_read(&native.runtime_id)
            .map_err(public)?;
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
            read: signing.as_ref().map(|_| read.clone()),
            input: crate::agent_build_requests::NativeInput::Saved {
                draft_revision: approval.input().draft_revision.ok_or_else(|| public(Error::Conflict))?,
                baseline_generation: approval.input().baseline_generation.ok_or_else(|| public(Error::Conflict))?,
            },
            changes: self.inner.changes.clone(),
        });
        if !scope.matches(&point) || !scope.matches_read(&read) {
            return Err(public(Error::Conflict));
        }
        let grant = Arc::new(Grant {
            scope: scope.clone(),
            native,
            source: GrantSource::Saved(SavedSource { stamp, saved, approval, signing }),
        });
        let mut state = self.lock();
        if self.ios_archive_gate(&state) != wire::Availability::Available {
            return Err(crate::ios_archive_owner::unavailable());
        }
        self.inner.bridge.ios_archive.ensure_idle()?;
        let (registration, root) =
            self.agent_ios_registered(&mut state, &grant.native.runtime_id)?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        self.agent_ios_current(&state, &grant, &edit, registration, &root)?;
        let next = agent::permission_next(expected, self.inner.agent_ios_archive_revoke_epoch.load(Ordering::Acquire)).map_err(public)?;
        if let Some(original) = self.inner.agent_ios_archive_service.get() {
            if original.as_ptr() != Arc::as_ptr(&service) {
                return Err(public(Error::Conflict));
            }
        } else {
            self.inner
                .agent_ios_archive_service
                .set(Arc::downgrade(&service))
                .map_err(|_| public(Error::StateUnknown))?;
        }
        // Same Doc guard linearizes first-Allow against Revoke. Inbox is only
        // bounded memory, and has no reverse callback into this document.
        let access = service.build_requests().allow(scope).map_err(public)?;
        state.agent_ios_archive_grant = Some(grant);
        self.inner.agent_ios_archive_revoke_epoch.store(next, Ordering::Release);
        Ok(agent::MainAccess::new(access, next))
    }
    pub(crate) fn revoke_agent_ios_archive(
        &self,
        window: &str,
    ) -> Result<agent::MainAccess, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let _state = self.lock();
        let advanced = self
            .inner
            .agent_ios_archive_revoke_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |e| e.checked_add(1))
            .map_err(|_| public(Error::StateUnknown));
        let revoked = match self.agent_ios_service() {
            Ok(Some(s)) => s.build_requests().revoke(agent::FAMILY).map_err(public),
            Ok(None) => Ok(empty()),
            Err(e) => Err(e),
        };
        // Counter failure must not skip the original STOP.
        let access = advanced.and(revoked)?;
        Ok(agent::MainAccess::new(access, self.inner.agent_ios_archive_revoke_epoch.load(Ordering::Acquire)))
    }
    fn admit_agent_ios_archive(
        &self,
        service: &Arc<ApplicationService>,
        entry: &Arc<agent::Entry>,
        kind: agent::ClaimKind,
    ) -> Result<(), BridgeError> {
        if entry.family() != agent::FAMILY {
            return Err(public(Error::Conflict));
        }
        let grant = {
            let state = self.lock();
            state
                .agent_ios_archive_grant
                .as_ref()
                .filter(|g| std::ptr::eq(g.scope.as_ref(), entry.scope()))
                .cloned()
                .ok_or_else(|| public(Error::Conflict))?
        };
        let GrantSource::Saved(saved) = &grant.source else {
            return self.admit_agent_ios_recovery(service, entry, kind, &grant);
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
                let (point, read) = service
                    .build_point_with_read(&grant.native.runtime_id)
                    .map_err(public)?;
                if !entry.prepare_live()
                    || !entry.scope().matches(&point)
                    || !entry.scope().matches_read(&read)
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
        let gate = self.ios_archive_gate(&state); // Same reciprocal peers, before Edit.
        if gate != wire::Availability::Available {
            return Err(crate::ios_archive_owner::unavailable());
        }
        let (registration, root) =
            self.agent_ios_registered(&mut state, &grant.native.runtime_id)?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        self.agent_ios_current(&state, &grant, &edit, registration, &root)?;
        if state
            .agent_ios_archive_grant
            .as_ref()
            .is_none_or(|g| !Arc::ptr_eq(g, &grant))
        {
            return Err(public(Error::Conflict));
        }
        match kind {
            agent::ClaimKind::Prepare => {
                let material = match &saved.signing {
                    None => None,
                    Some(pin) => {
                        let original = self.review_ios_material(&state, &saved.approval.input().context(), registration, &root)?;
                        if !pin.matches(&original) { return Err(public(Error::Conflict)); }
                        Some(original)
                    },
                };
                self.inner.bridge.ios_archive.prepare_agent_ios_archive(
                    entry.clone(),
                    saved.approval.clone(),
                    registration,
                    root,
                    gate,
                    material,
                )?;
            }
            agent::ClaimKind::Start => {
                let material = self.inner.bridge.ios_archive.agent_ios_archive_prepared_material(entry)?;
                match (&saved.signing, &material) {
                    (None, None) => {},
                    (Some(pin), Some(original)) if pin.matches(original) => self.recheck_ios_material(&state, original, registration, &root)?,
                    _ => return Err(public(Error::Conflict)),
                }
                let admitted = self.inner.bridge.ios_archive.start_agent_ios_archive(
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
    fn revoke_stale_agent_ios(&self, service: &ApplicationService) {
        // No service-state/Host IO, no new native input reader. The existing
        // control epoch and returned saved binding detect local invalidation.
        let mut state = self.lock();
        let Some(grant) = state.agent_ios_archive_grant.as_ref().cloned() else {
            return;
        };
        let current = (|| {
            let (registration, root) =
                self.agent_ios_registered(&mut state, &grant.native.runtime_id)?;
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            self.agent_ios_current(&state, &grant, &edit, registration, &root)
        })();
        if current.is_err() {
            let _ = service.build_requests().revoke(agent::FAMILY);
        }
    }
    /// Called by the already-retained relay, never by an IPC worker or a new task.
    pub(crate) fn service_ios_archives_tick(&self) {
        let Ok(Some(service)) = self.agent_ios_service() else {
            return;
        };
        self.revoke_stale_agent_ios(&service);
        match service.build_requests().claim(agent::FAMILY) {
            Ok(Some(claim)) => {
                let result = self.admit_agent_ios_archive(&service, claim.entry(), claim.kind());
                claim.returned(result.is_ok());
            }
            Ok(None) => {}
            Err(_) => {
                let _ = service.build_requests().revoke(agent::FAMILY);
            }
        }
        let _ = super::agent_android_build::flush(&service, agent::FAMILY);
    }
    pub(crate) fn agent_ios_archives_relay_lost(&self) {
        if let Ok(Some(s)) = self.agent_ios_service() {
            let _ = s.build_requests().revoke(agent::FAMILY);
        }
    }
    /// After all original domain owners AND this same relay joined. Never
    /// dispatch remaining queued Prepare/Start to clear a shutdown inbox.
    pub(crate) fn drain_ios_archives_for_exit(&self) {
        if let Ok(Some(s)) = self.agent_ios_service() {
            s.build_requests().close();
            let _ = super::agent_android_build::flush(&s, agent::FAMILY);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dormant_ios_document_does_not_open_host_and_foreign_window_cannot_allow() {
        let bridge = Arc::new(DesktopBridge::new(std::path::PathBuf::from(
            "/unopened-ios-build-data-fixture",
        )));
        let doc = DocumentBinding::new(bridge.clone());
        assert!(!doc.agent_ios_archive_access(MAIN).unwrap().enabled);
        assert!(!doc.revoke_agent_ios_archive(MAIN).unwrap().enabled);
        assert!(doc.agent_ios_archive_access("other").is_err());
        doc.service_ios_archives_tick();
        doc.drain_ios_archives_for_exit();
        assert!(!bridge.application_service.status().unwrap().enabled);
    }
    #[test]
    fn ios_delayed_first_allow_cannot_rebase_a_returned_permission_revision_after_revoke() {
        let bridge=Arc::new(DesktopBridge::new("/unopened-ios-revision-data-fixture".into()));
        let doc=DocumentBinding::new(bridge.clone());
        let original=doc.agent_ios_archive_access(MAIN).unwrap();
        assert_eq!(original.permission_revision,"0");
        assert_eq!(doc.revoke_agent_ios_archive(MAIN).unwrap().permission_revision,"1");
        let context=wire::tests::signed_context();
        for signing in [None,context.signing.clone()] {
            let signed=signing.is_some();
            let input=wire::Prepare{project_id:context.project_id.clone(),draft_revision:context.draft_revision,
                baseline_generation:context.baseline_generation,saved_config:context.saved_config.clone(),
                saved_version:context.saved_version.clone(),signing,recovery:None,action:None};
            let result=doc.allow_agent_ios_archive(MAIN,Allow::Saved(SavedAllow{input,
                consent_version:if signed{agent::signed::CONSENT}else{agent::CONSENT}.into(),
                expected_permission_revision:original.permission_revision.clone()}));
            assert_eq!(result.unwrap_err(),public(Error::AccessDenied));
        }
        assert!(!doc.agent_ios_archive_access(MAIN).unwrap().enabled);
        assert!(!bridge.application_service.status().unwrap().enabled);
    }
    #[test]
    fn ios_consent_cannot_supply_tools_material_window_or_native_operation_ids() {
        let base = serde_json::json!({"input":{"projectId":"p","draftRevision":0,"baselineGeneration":0,
            "savedConfig":{"bytes":2,"sha256":"a".repeat(64)},"savedVersion":{"source":"version.properties","bytes":3,"sha256":"b".repeat(64),"name":"1.0","build":1}},"consentVersion":agent::CONSENT,"expectedPermissionRevision":"0"});
        let decode = |v: &Value| {
            super::super::agent_identity::decode::<Allow>(&serde_json::to_vec(v).unwrap())
        };
        assert!(decode(&base).is_ok());
        for field in [
            "toolchainSelection",
            "root",
            "command",
            "operationId",
            "window",
            "material",
            "grant",
        ] {
            let mut v = base.clone();
            v[field] = serde_json::json!("not-authority");
            assert!(decode(&v).is_err());
        }
        let bridge = Arc::new(DesktopBridge::new(
            "/unopened-ios-consent-data-fixture".into(),
        ));
        let doc = DocumentBinding::new(bridge.clone());
        assert!(doc
            .allow_agent_ios_archive("other", decode(&base).unwrap())
            .is_err());
        let mut v = base;
        v["consentVersion"] = serde_json::json!(crate::agent_android_build::CONSENT);
        assert!(doc
            .allow_agent_ios_archive(MAIN, decode(&v).unwrap())
            .is_err());
        assert!(!bridge.application_service.status().unwrap().enabled);
    }
}
