//! Genuine main-Webview/Document admission for a CLI identity proposal. These
//! fixed wrappers enter the SAME registered EditOwner; none executes a CLI
//! payload, opens a Host, supplies continuity or owns another native worker.
use super::*;
use crate::{
    agent_identity_requests as requests,
    application_service::ApplicationService,
    application_service_host::NativeProject,
    edit_owner::SavedEditStamp,
    edit_protocol::EditDomain,
    project_identity_edit_protocol as wire,
    service_protocol::{Error, Id},
};
use serde::{de::DeserializeOwned, Deserialize};
#[path = "asset_session_agent_identity_actions.rs"]
pub(crate) mod actions;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PermitRequest {
    pub(crate) project_id: String,
    pub(crate) expected_permission_revision: String,
}
/// Only the genuine MAIN Check exposes this ordering stamp. The shared
/// service/CLI and the other three-field GUI replies remain unchanged.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PermissionCheck {
    #[serde(flatten)]
    status: requests::GuiStatus,
    #[serde(serialize_with = "serialize_permission_revision")]
    permission_revision: u64,
}
fn serialize_permission_revision<S: serde::Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(value)
}
fn permission_revision(text: &str) -> Result<u64, BridgeError> {
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|c| c.is_ascii_digit())
        || text.len() > 1 && text.starts_with('0')
    {
        return Err(BridgeError::invalid());
    }
    text.parse().map_err(|_| BridgeError::invalid())
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct IntentRequest {
    pub(crate) intent_id: Id,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PrepareRequest {
    pub(crate) intent_id: Id,
    pub(crate) session_id: Id,
    pub(crate) revision: Id,
    pub(crate) acknowledge_new_application: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ApplyRequest {
    pub(crate) intent_id: Id,
    pub(crate) session_id: Id,
    pub(crate) revision: Id,
    pub(crate) plan_token: Id,
    pub(crate) reviewed: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Empty {}
/// Whole native GUI request is capped too. Strict duplicate-field JSON parsing
/// precedes the closed schema. No caller root/window/continuity/desired-ID seam.
pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, BridgeError> {
    if bytes.is_empty() || bytes.len() > crate::service_protocol::REQUEST_BYTES {
        return Err(BridgeError::invalid());
    }
    let value = crate::protocol::strict_json(bytes).map_err(|_| BridgeError::invalid())?;
    crate::protocol::check_value(&value).map_err(|_| BridgeError::invalid())?;
    T::deserialize(&value).map_err(|_| BridgeError::invalid())
}
fn public(error: Error) -> BridgeError {
    application_service::public_error(error)
}
fn scope_matches(entry: &requests::Entry, native: &NativeProject) -> bool {
    let scope = entry.scope();
    scope.runtime_id == native.runtime_id
        && scope.root == native.canonical_root
        && scope.device == native.device
        && scope.inode == native.inode
        && scope.registration == native.registration_generation
        && scope.input_revision == native.input_revision
        && scope.document.as_ptr() == Arc::as_ptr(&native.document_identity)
}
fn request_open(entry: &requests::Entry) -> wire::Open {
    let selection = &entry.input().change.selection;
    wire::Open::Edit {
        project_id: entry.scope().runtime_id.clone(),
        selection: wire::TargetSelection {
            platform: match selection.platform {
                requests::Platform::Android => wire::Platform::Android,
                requests::Platform::Ios => wire::Platform::Ios,
            },
            target: selection.target.clone(),
            project: selection.project.clone(),
        },
    }
}
fn empty_status() -> requests::GuiStatus {
    requests::GuiStatus {
        lease: requests::LeaseStatus {
            enabled: false,
            remaining_ms: 0,
            project_id: None,
        },
        pending: None,
        requests: Vec::new(),
    }
}

impl DocumentBinding {
    fn consume_agent_allow_epoch(
        &self,
        _original_guard: &DocumentState,
        expected: u64,
    ) -> Result<u64, BridgeError> {
        // MAX is terminal: a saturated Revoke must never leave a usable
        // in-flight Allow at that same value. A refused attempt is not reset.
        let next = expected.checked_add(1).filter(|next| *next < u64::MAX)
            .ok_or_else(|| public(Error::StateUnknown))?;
        self.inner.agent_identity_revoke_epoch
            .compare_exchange(expected, next, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| next).map_err(|_| public(Error::AccessDenied))
    }
    fn agent_allow_epoch(
        &self,
        _original_guard: &DocumentState,
        epoch: u64,
    ) -> Result<(), BridgeError> {
        if epoch == u64::MAX
            || self
                .inner
                .agent_identity_revoke_epoch
                .load(Ordering::Acquire)
                != epoch
        {
            Err(public(Error::AccessDenied))
        } else {
            Ok(())
        }
    }
    fn agent_service(&self) -> Result<Arc<ApplicationService>, BridgeError> {
        self.inner
            .agent_identity_service
            .get()
            .and_then(Weak::upgrade)
            .ok_or_else(|| public(Error::Unavailable))
    }
    fn remember_agent_service(&self, service: &Arc<ApplicationService>) -> Result<(), BridgeError> {
        if let Some(original) = self.inner.agent_identity_service.get() {
            return if original.as_ptr() == Arc::as_ptr(service) {
                Ok(())
            } else {
                Err(public(Error::Conflict))
            };
        }
        if self
            .inner
            .agent_identity_service
            .set(Arc::downgrade(service))
            .is_err()
        {
            return Err(public(Error::StateUnknown));
        }
        Ok(())
    }
    fn agent_context(
        &self,
        window: &str,
        project: &str,
    ) -> Result<(NativeProject, SavedEditStamp, u64), BridgeError> {
        if window != MAIN || !crate::protocol::valid_id(project) {
            return Err(BridgeError::invalid());
        }
        let state = self.lock();
        self.agent_context_locked(&state, project)
    }
    fn agent_context_locked(
        &self,
        state: &DocumentState,
        project: &str,
    ) -> Result<(NativeProject, SavedEditStamp, u64), BridgeError> {
        self.passive_query_gate_locked(state, &self.inner.bridge)?;
        let native = self.service_project_locked(state, project)?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        let epoch = self
            .inner
            .agent_identity_revoke_epoch
            .load(Ordering::Acquire);
        if epoch == u64::MAX {
            return Err(public(Error::StateUnknown));
        }
        Ok((native, edit.stamp()?, epoch))
    }
    pub(crate) fn agent_identity_status(
        &self,
        window: &str,
    ) -> Result<PermissionCheck, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let state = self.lock();
        self.service_document_gate(&state)?;
        let status = match self.inner.agent_identity_service.get() {
            None => Ok(empty_status()),
            Some(original) => original
                .upgrade()
                .ok_or_else(|| public(Error::Unavailable))?
                .identity_requests()
                .gui_status()
                .map_err(public),
        }?;
        Ok(PermissionCheck {
            status,
            permission_revision: self.inner.agent_identity_revoke_epoch.load(Ordering::Acquire),
        })
    }
    pub(crate) fn allow_agent_identity(
        &self,
        window: &str,
        args: PermitRequest,
    ) -> Result<requests::GuiStatus, BridgeError> {
        if window != MAIN || !crate::protocol::valid_id(&args.project_id) {
            return Err(BridgeError::invalid());
        }
        let expected = permission_revision(&args.expected_permission_revision)?;
        let (original, stamp, epoch) = {
            let state = self.lock();
            // Consume the original returned MAIN Check before any startup,
            // project or off-Doc Host work; never capture a fresh arrival epoch.
            let epoch = self.consume_agent_allow_epoch(&state, expected)?;
            let (original, stamp, _) = self.agent_context_locked(&state, &args.project_id)?;
            (original, stamp, epoch)
        };
        // Both may acquire original Host/Service locks and inspect durable
        // saved state. They are deliberately OUTSIDE Document/Edit guards.
        let service = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&original)
            .map_err(public)?;
        let saved = service
            .identity_request_point(&original.runtime_id)
            .map_err(public)?;
        let state = self.lock();
        self.passive_query_gate_locked(&state, &self.inner.bridge)?;
        let current = self.service_allow_current_locked(&state, &original, &stamp)?;
        self.agent_allow_epoch(&state, epoch)?;
        let scope = requests::NativeScope {
            project_id: saved.project_id.clone(),
            runtime_id: current.runtime_id,
            root: current.canonical_root,
            device: current.device,
            inode: current.inode,
            registration: current.registration_generation,
            input_revision: current.input_revision,
            document: Arc::downgrade(&self.inner.session_identity),
        };
        if !saved.matches(&scope) {
            return Err(public(Error::Conflict));
        }
        self.remember_agent_service(&service)?;
        service.identity_requests().allow(scope).map_err(public)?;
        service.identity_requests().gui_status().map_err(public)
    }
    pub(crate) fn revoke_agent_identity(
        &self,
        window: &str,
    ) -> Result<requests::GuiStatus, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let result = {
            // SAME Doc mutex spans the revoke epoch and inbox revocation. A first
            // Allow still doing off-lock IO cannot install a late permission after
            // this returns, even if its service weak link did not yet exist.
            let _state = self.lock();
            let advanced = self
                .inner
                .agent_identity_revoke_epoch
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                    epoch.checked_add(1)
                })
                .map_err(|_| public(Error::StateUnknown));
            let revoked = match self.inner.agent_identity_service.get() {
                None => Ok(empty_status()),
                Some(original) => original
                    .upgrade()
                    .ok_or_else(|| public(Error::Unavailable))
                    .and_then(|service| {
                        service.identity_requests().revoke().map_err(public)?;
                        service.identity_requests().gui_status().map_err(public)
                    }),
            };
            advanced.and(revoked)
        };
        // Even poison/missing observer cannot skip the original STOP. This is
        // not native settlement, nor a way to release its private ownership.
        self.inner.bridge.edits.revoke_agent_identity();
        result
    }
    pub(crate) fn decline_agent_identity(
        &self,
        window: &str,
        args: IntentRequest,
    ) -> Result<requests::GuiStatus, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let service = self.agent_service()?;
        service
            .identity_requests()
            .decline(&args.intent_id)
            .map_err(public)?;
        service.identity_requests().gui_status().map_err(public)
    }
    pub(crate) fn review_agent_identity(
        &self,
        window: &str,
        args: IntentRequest,
    ) -> Result<wire::IdentityStatus, BridgeError> {
        let service = self.agent_service()?;
        let entry = service
            .identity_requests()
            .entry(&args.intent_id)
            .map_err(public)?;
        let (original, stamp, _) = self.agent_context(window, &entry.scope().runtime_id)?;
        if !scope_matches(&entry, &original) {
            return Err(public(Error::Conflict));
        }
        let host_service = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&original)
            .map_err(public)?;
        if !Arc::ptr_eq(&service, &host_service) {
            return Err(public(Error::Conflict));
        }
        let saved = service
            .identity_request_point(&original.runtime_id)
            .map_err(public)?;
        if !saved.matches(entry.scope())
            || saved.revision != entry.input().expected_observation_revision
        {
            return Err(public(Error::Conflict));
        }
        // The existing ticket obtains entropy/executor outside Doc; it grants
        // no root or dispatch. Original publisher custody is unchanged too.
        let mut ticket = self.inner.bridge.edits.identity_open_ticket(window)?;
        let mut publisher = self
            .inner
            .android_registration_control
            .reserve(RegistrationPublisherKind::General, false)?;
        let result = (|| {
            let mut state = self.lock();
            self.passive_query_gate_locked(&state, &self.inner.bridge)?;
            let current = self.service_allow_current_locked(&state, &original, &stamp)?;
            if !scope_matches(&entry, &current) {
                return Err(public(Error::Conflict));
            }
            let claim = service
                .identity_requests()
                .begin_review(&entry)
                .map_err(public)?;
            let opened = (|| {
                // This is the SAME closed root/context/reciprocal-work gate as
                // ordinary GUI Open, under the same original Document mutex.
                let registered = self.registered_edit_root_locked_published(
                    &mut state,
                    EditDomain::ProjectIdentity,
                    |_| Ok(entry.scope().runtime_id.clone()),
                    None,
                    &mut publisher,
                )?;
                let args = request_open(&entry);
                let continuity = project_identity::current_continuity(
                    &self.inner.bridge,
                    args.project_id(),
                    &registered,
                    args.platform(),
                )?;
                self.inner.bridge.edits.attach_agent_identity(
                    window,
                    &mut ticket,
                    entry.clone(),
                    &registered,
                )?;
                self.inner.bridge.edits.open_identity_published(
                    &publisher, window, args, registered, ticket, continuity,
                )
            })();
            // A real linked SID survives a returned task-registration failure.
            // No later error here issues "not started" or creates a retry.
            claim.returned(opened.is_ok()).map_err(public)?;
            opened
        })();
        finish_registration_publisher(publisher);
        result
    }
    pub(crate) fn prepare_agent_identity(
        &self,
        window: &str,
        args: PrepareRequest,
    ) -> Result<wire::IdentityStatus, BridgeError> {
        let result = (|| {
            let service = self.agent_service()?;
            let entry = service
                .identity_requests()
                .entry(&args.intent_id)
                .map_err(public)?;
            let sid = self
                .inner
                .bridge
                .edits
                .agent_identity_session(window, &entry)?;
            let change = &entry.input().change;
            if sid != args.session_id.as_str()
                || change.identity_intent == requests::IdentityIntent::NewApplication
                    && !args.acknowledge_new_application
            {
                return Err(BridgeError::invalid());
            }
            self.prepare_project_identity(
                window,
                wire::Prepare::Edit {
                    session_id: sid,
                    revision: args.revision.as_str().to_owned(),
                    desired_identity: change.desired_identity.clone(),
                    identity_intent: match change.identity_intent {
                        requests::IdentityIntent::Preserve => wire::IdentityIntent::Preserve,
                        requests::IdentityIntent::NewApplication => {
                            wire::IdentityIntent::NewApplication
                        }
                    },
                },
            )
        })();
        if result.is_err() {
            self.inner.bridge.edits.retire_identity_request(window);
        }
        result
    }
    pub(crate) fn apply_agent_identity(
        &self,
        window: &str,
        args: ApplyRequest,
    ) -> Result<wire::IdentityStatus, BridgeError> {
        let result = (|| {
            let service = self.agent_service()?;
            let entry = service
                .identity_requests()
                .entry(&args.intent_id)
                .map_err(public)?;
            let sid = self
                .inner
                .bridge
                .edits
                .agent_identity_session(window, &entry)?;
            if sid != args.session_id.as_str() || !args.reviewed || args.plan_token == args.revision
            {
                return Err(BridgeError::invalid());
            }
            self.apply_project_identity(
                window,
                wire::Apply {
                    session_id: sid,
                    revision: args.revision.as_str().to_owned(),
                    plan_token: args.plan_token.as_str().to_owned(),
                    intent: wire::Intent::Edit,
                },
            )
        })();
        if result.is_err() {
            self.inner.bridge.edits.retire_identity_request(window);
        }
        result
    }
    // Close and status deliberately use the existing original native endpoints
    // and same SID; no current service/permission/root lookup is needed to STOP.
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gui_approval_cannot_supply_a_root_change_or_implicit_acknowledgement() {
        let id = "a".repeat(32);
        let revision = "b".repeat(32);
        assert!(decode::<IntentRequest>(format!(r#"{{"intentId":"{id}"}}"#).as_bytes()).is_ok());
        for raw in [
            format!(r#"{{"intentId":"{id}","window":"main"}}"#),
            format!(r#"{{"intentId":"{id}","intentId":"{id}"}}"#),
            format!(r#"{{"intentId":"{id}","desiredIdentity":"com.example.other"}}"#),
        ] {
            assert!(decode::<IntentRequest>(raw.as_bytes()).is_err());
        }
        assert!(decode::<PrepareRequest>(
            format!(r#"{{"intentId":"{id}","sessionId":"{id}","revision":"{revision}"}}"#)
                .as_bytes()
        )
        .is_err());
        assert!(decode::<Empty>(br#"{"command":"run"}"#).is_err());
        assert!(decode::<Empty>(&vec![b' '; 4097]).is_err());
    }
    #[test]
    fn unbound_document_never_opens_a_host_to_accept_a_request() {
        let bridge = Arc::new(DesktopBridge::new(std::path::PathBuf::from(
            "/unopened-agent-intent-fixture",
        )));
        let document = DocumentBinding::new(bridge.clone());
        assert!(document
            .allow_agent_identity(
                "main",
                PermitRequest {
                    project_id: "project-1".into(),
                    expected_permission_revision: "0".into(),
                }
            )
            .is_err());
        assert!(document
            .review_agent_identity(
                "main",
                IntentRequest {
                    intent_id: Id::parse(&"a".repeat(32)).unwrap()
                }
            )
            .is_err());
        assert!(
            !document
                .revoke_agent_identity("main")
                .unwrap()
                .lease
                .enabled
        );
        assert!(!bridge.application_service.status().unwrap().enabled);
    }
    #[test]
    fn revoke_before_first_service_link_rejects_original_late_allow_epoch() {
        let document = DocumentBinding::new(Arc::new(DesktopBridge::new(
            std::path::PathBuf::from("/unopened-revoke-race-fixture"),
        )));
        let captured = {
            let state = document.lock();
            let epoch = document
                .inner
                .agent_identity_revoke_epoch
                .load(Ordering::Acquire);
            document.agent_allow_epoch(&state, epoch).unwrap();
            epoch
        };
        // This is the actual native revoke method with NO linked service.
        // Only the same lock-held epoch predicate is exercised, not a made-up
        // successful project/root/permission admission on this unbound fixture.
        document.revoke_agent_identity("main").unwrap();
        let state = document.lock();
        assert!(document.inner.agent_identity_service.get().is_none());
        assert!(document.agent_allow_epoch(&state, captured).is_err());
        assert_eq!(
            document
                .inner
                .agent_identity_revoke_epoch
                .load(Ordering::Acquire),
            captured + 1
        );
    }

    #[test]
    fn main_check_revision_is_closed_decimal_and_other_reply_bytes_stay_unchanged() {
        for text in ["0", "1", "9007199254740993", "18446744073709551615"] {
            assert_eq!(permission_revision(text).unwrap().to_string(), text);
        }
        for text in ["", "00", "01", "-0", "+1", " 1", "1\n", "1\r", "1\u{2028}",
            "18446744073709551616", "100000000000000000000"]
        {
            assert!(permission_revision(text).is_err());
        }
        for raw in [
            r#"{"projectId":"project-1"}"#,
            r#"{"projectId":"project-1","expectedPermissionRevision":0}"#,
            r#"{"projectId":"project-1","expectedPermissionRevision":null}"#,
            r#"{"projectId":"project-1","expectedPermissionRevision":"0","expectedPermissionRevision":"1"}"#,
            r#"{"projectId":"project-1","expectedPermissionRevision":"0","window":"main"}"#,
        ] {
            assert!(decode::<PermitRequest>(raw.as_bytes()).is_err());
        }
        let request: PermitRequest = decode(br#"{"projectId":"project-1","expectedPermissionRevision":"9007199254740993"}"#).unwrap();
        assert_eq!(permission_revision(&request.expected_permission_revision).unwrap(), 9_007_199_254_740_993);
        let base = serde_json::to_value(empty_status()).unwrap();
        let check = serde_json::to_value(PermissionCheck { status: empty_status(), permission_revision: u64::MAX }).unwrap();
        assert_eq!(base.as_object().unwrap().len(), 3);
        assert_eq!(check.as_object().unwrap().len(), 4);
        assert_eq!(check["permissionRevision"], "18446744073709551615");
        for field in ["lease", "pending", "requests"] { assert_eq!(check[field], base[field]); }
        assert!(serde_json::to_vec(&check).unwrap().len() < 64 * 1024);
    }

    #[test]
    fn delayed_first_allow_uses_old_checked_revision_after_actual_revoke() {
        let bridge = Arc::new(DesktopBridge::new(std::path::PathBuf::from("/unopened-identity-arrival-fixture")));
        let document = DocumentBinding::new(bridge.clone());
        // No native window/root/Check is fabricated on this unbound fixture.
        // Exercise the actual late-Allow refusal before those gates or Host IO.
        assert!(document.agent_identity_status(MAIN).is_err());
        assert!(!document.revoke_agent_identity(MAIN).unwrap().lease.enabled);
        assert_eq!(document.allow_agent_identity(MAIN, PermitRequest {
            project_id: "project-1".into(), expected_permission_revision: "0".into(),
        }).err().unwrap(), public(Error::AccessDenied));
        assert_eq!(document.inner.agent_identity_revoke_epoch.load(Ordering::Acquire), 1);
        assert!(document.inner.agent_identity_service.get().is_none());
        assert!(!bridge.application_service.status().unwrap().enabled);
    }

    #[test]
    fn startup_refusal_consumes_only_initial_allow_and_cannot_replay() {
        let bridge = Arc::new(DesktopBridge::new(std::path::PathBuf::from("/unopened-identity-consume-fixture")));
        let document = DocumentBinding::new(bridge.clone());
        let input = || PermitRequest { project_id: "project-1".into(), expected_permission_revision: "0".into() };
        assert!(document.allow_agent_identity("not-main", input()).is_err());
        assert_eq!(document.inner.agent_identity_revoke_epoch.load(Ordering::Acquire), 0);
        assert!(document.allow_agent_identity(MAIN, input()).is_err());
        assert_eq!(document.inner.agent_identity_revoke_epoch.load(Ordering::Acquire), 1);
        assert_eq!(document.allow_agent_identity(MAIN, input()).err().unwrap(), public(Error::AccessDenied));
        assert!(document.agent_context(MAIN, "project-1").is_err());
        assert_eq!(document.inner.agent_identity_revoke_epoch.load(Ordering::Acquire), 1,
            "ordinary Review context does not consume a proposal-permission revision");
        assert!(document.inner.agent_identity_service.get().is_none());
        assert!(!bridge.application_service.status().unwrap().enabled);
    }

    #[test]
    fn permission_exhaustion_never_rebases_or_skips_original_revoke() {
        let document = DocumentBinding::new(Arc::new(DesktopBridge::new(std::path::PathBuf::from("/unopened-identity-exhaustion-fixture"))));
        {
            let state = document.lock();
            document.inner.agent_identity_revoke_epoch.store(u64::MAX - 2, Ordering::Release);
            assert_eq!(document.consume_agent_allow_epoch(&state, u64::MAX - 2).unwrap(), u64::MAX - 1);
            assert!(document.consume_agent_allow_epoch(&state, u64::MAX - 2).is_err());
            assert!(document.consume_agent_allow_epoch(&state, u64::MAX - 1).is_err());
            assert!(document.consume_agent_allow_epoch(&state, u64::MAX).is_err());
            assert_eq!(document.inner.agent_identity_revoke_epoch.load(Ordering::Acquire), u64::MAX - 1);
        }
        assert!(!document.revoke_agent_identity(MAIN).unwrap().lease.enabled);
        assert_eq!(document.inner.agent_identity_revoke_epoch.load(Ordering::Acquire), u64::MAX);
        assert_eq!(document.revoke_agent_identity(MAIN).err().unwrap(), public(Error::StateUnknown));
        assert_eq!(document.inner.agent_identity_revoke_epoch.load(Ordering::Acquire), u64::MAX);
        assert!(document.inner.agent_identity_service.get().is_none());
        // The real method's unconditional original Edit STOP is unchanged;
        // this fixture does not invent an active owner or settlement receipt.
    }
}
