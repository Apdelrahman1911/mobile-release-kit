//! Original main-Document handoff for an already opened identity proposal.
//! One explicit exact-source permission, then the SAME relay/Prepare/Apply.
use super::*;
use requests::actions::{self as action, Kind};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Allow {
    intent_id: Id,
    session_id: Id,
    revision: Id,
    acknowledge_new_application: bool,
    consent_version: String,
}
impl DocumentBinding {
    fn identity_action_registered(
        &self,
        state: &DocumentState,
        entry: &requests::Entry,
    ) -> Result<(NativeProject, crate::edit_owner::RegisteredEditRoot), BridgeError> {
        let native = self.service_project_locked(state, &entry.scope().runtime_id)?;
        let (generation, root) = self
            .inner
            .bridge
            .native_project(&native.runtime_id)
            .map_err(|_| public(Error::Conflict))?;
        let scope = entry.scope();
        if native.runtime_id != scope.runtime_id
            || native.canonical_root != scope.root
            || native.device != scope.device
            || native.inode != scope.inode
            || native.registration_generation != scope.registration
            || scope.document.as_ptr() != Arc::as_ptr(&self.inner.session_identity)
        {
            return Err(public(Error::Conflict));
        }
        Ok((
            native,
            crate::edit_owner::RegisteredEditRoot { generation, root },
        ))
    }
    pub(crate) fn allow_agent_identity_action(
        &self,
        window: &str,
        input: Allow,
    ) -> Result<action::Status, BridgeError> {
        if window != MAIN || input.consent_version != action::CONSENT {
            return Err(BridgeError::invalid());
        }
        let service = self.agent_service()?;
        let entry = service
            .identity_requests()
            .entry(&input.intent_id)
            .map_err(public)?;
        let (native, approval, epoch) = {
            let state = self.lock();
            let (native, registered) = self.identity_action_registered(&state, &entry)?;
            let platform = Some(match entry.input().change.selection.platform {
                requests::Platform::Android => wire::Platform::Android,
                requests::Platform::Ios => wire::Platform::Ios,
            });
            let continuity = project_identity::current_continuity(
                &self.inner.bridge,
                &native.runtime_id,
                &registered,
                platform,
            )?;
            let approval = self.inner.bridge.edits.capture_identity_action(
                window,
                entry.clone(),
                input.session_id.as_str(),
                input.revision.as_str(),
                input.acknowledge_new_application,
                &registered,
                continuity,
            )?;
            (
                native,
                approval,
                self.inner
                    .agent_identity_revoke_epoch
                    .load(Ordering::Acquire),
            )
        };
        // Existing Host and service may perform IO. They are outside BOTH Doc
        // and Edit locks. Never initialize a dormant host or a fresh read grant.
        let original_service = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&native)
            .map_err(public)?;
        if !Arc::ptr_eq(&original_service, &service) {
            return Err(public(Error::Conflict));
        }
        service.identity_action_current(&entry).map_err(public)?;
        let state = self.lock();
        self.agent_allow_epoch(&state, epoch)?;
        let (current, registered) = self.identity_action_registered(&state, &entry)?;
        if current.input_revision != native.input_revision {
            return Err(public(Error::Conflict));
        }
        let platform = Some(match entry.input().change.selection.platform {
            requests::Platform::Android => wire::Platform::Android,
            requests::Platform::Ios => wire::Platform::Ios,
        });
        let continuity = project_identity::current_continuity(
            &self.inner.bridge,
            &native.runtime_id,
            &registered,
            platform,
        )?;
        self.inner
            .bridge
            .edits
            .allow_identity_action(window, approval, &registered, continuity)
    }
    pub(crate) fn agent_identity_action_status(
        &self,
        window: &str,
        input: IntentRequest,
    ) -> Result<Option<action::Status>, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let service = self.agent_service()?;
        let entry = service
            .identity_requests()
            .entry(&input.intent_id)
            .map_err(public)?;
        if entry.actions().is_none() {
            return Ok(None);
        }
        entry.action_status().map(Some).map_err(public)
    }
    pub(crate) fn revoke_agent_identity_action(
        &self,
        window: &str,
        input: IntentRequest,
    ) -> Result<Option<action::Status>, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let service = self.agent_service()?;
        let entry = service
            .identity_requests()
            .entry(&input.intent_id)
            .map_err(public)?;
        // Exact original only, including before Allow returns. Do not use the
        // broader proposal-lease revoke: a later intent may share that lease.
        let _state = self.lock();
        if entry.scope().document.as_ptr() != Arc::as_ptr(&self.inner.session_identity) {
            return Err(public(Error::Conflict));
        }
        self.inner
            .bridge
            .edits
            .cancel_identity_action(window, &entry)?;
        if entry.actions().is_none() {
            Ok(None)
        } else {
            entry.action_status().map(Some).map_err(public)
        }
    }
    fn admit_identity_action(
        &self,
        service: &Arc<ApplicationService>,
        claim: &action::Claim,
    ) -> Result<(), BridgeError> {
        let entry = claim.entry();
        let native = {
            let state = self.lock();
            self.identity_action_registered(&state, entry)?.0
        };
        let original_service = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&native)
            .map_err(public)?;
        if !Arc::ptr_eq(service, &original_service) {
            return Err(public(Error::Conflict));
        }
        service.identity_action_current(entry).map_err(public)?;
        if !entry.action_admitting(claim.kind()) {
            return Err(public(Error::Expired));
        }
        self.registered_edit_admit_published(
            EditDomain::ProjectIdentity,
            |_| Ok(entry.scope().runtime_id.clone()),
            |bridge, registered, publisher| {
                let platform = Some(match entry.input().change.selection.platform {
                    requests::Platform::Android => wire::Platform::Android,
                    requests::Platform::Ios => wire::Platform::Ios,
                });
                let continuity = project_identity::current_continuity(
                    bridge,
                    &entry.scope().runtime_id,
                    &registered,
                    platform,
                )?;
                match claim.kind() {
                    Kind::Prepare => bridge.edits.prepare_identity_action_published(
                        publisher,
                        MAIN,
                        entry.clone(),
                        registered,
                        continuity,
                    ),
                    Kind::Start => bridge.edits.start_identity_action_published(
                        publisher,
                        MAIN,
                        entry.clone(),
                        registered,
                        continuity,
                    ),
                }
            },
        )
        .map(|_| ())
    }
    pub(crate) fn service_identity_actions_tick(&self) {
        let Ok(service) = self.agent_service() else {
            return;
        };
        match service.identity_requests().claim_identity_action() {
            Ok(Some(claim)) => {
                let result = self.admit_identity_action(&service, &claim);
                claim.returned(result.is_ok());
            }
            Ok(None) => {}
            Err(_) => {
                let _ = service.identity_requests().revoke();
            }
        }
    }
    pub(crate) fn identity_actions_relay_lost(&self) {
        if let Ok(service) = self.agent_service() {
            let _ = service.identity_requests().revoke();
        }
    }
    pub(crate) fn drain_identity_actions_for_exit(&self) {
        // No queued work is dispatched at shutdown. History is still drained
        // by its existing owner AFTER original edits and the relay have joined.
        if let Ok(service) = self.agent_service() {
            service.identity_requests().close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dormant_document_never_creates_a_service_for_identity_delegation() {
        let bridge = Arc::new(DesktopBridge::new(std::path::PathBuf::from(
            "/inert-identity-action-doc",
        )));
        let doc = DocumentBinding::new(bridge.clone());
        let id = Id::parse(&"a".repeat(32)).unwrap();
        assert!(doc
            .allow_agent_identity_action(
                MAIN,
                Allow {
                    intent_id: id.clone(),
                    session_id: id.clone(),
                    revision: id,
                    acknowledge_new_application: true,
                    consent_version: action::CONSENT.into()
                }
            )
            .is_err());
        doc.service_identity_actions_tick();
        doc.drain_identity_actions_for_exit();
        assert!(!bridge.application_service.status().unwrap().enabled);
    }
    #[test]
    fn gui_consent_is_closed_and_new_application_is_never_implicit() {
        let id = "a".repeat(32);
        let raw = format!(
            r#"{{"intentId":"{id}","sessionId":"{id}","revision":"{id}","acknowledgeNewApplication":true,"consentVersion":"{}"}}"#,
            action::CONSENT
        );
        assert!(decode::<Allow>(raw.as_bytes()).is_ok());
        for bad in [
            raw.replace("true", "null"),
            raw.replace("\"revision\":", "\"root\":\"/foreign\",\"revision\":"),
            raw.replace(
                "\"intentId\":",
                &format!("\"intentId\":\"{id}\",\"intentId\":"),
            ),
        ] {
            assert!(decode::<Allow>(bad.as_bytes()).is_err());
        }
    }
}
