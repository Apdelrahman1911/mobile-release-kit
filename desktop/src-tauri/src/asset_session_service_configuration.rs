//! Main-Webview-only continuation of queued configuration comparisons. IPC
//! never calls EditOwner. Host/Service IO occurs outside both Doc/Edit locks.
use super::*;
use crate::{
    application_service::ApplicationService,
    application_service_host::NativeProject,
    edit_owner::{ConfigurationAgentStep as Step, SavedEditStamp},
    service_configuration_protocol as p,
    service_configuration_requests::{Entry, Kind},
};
use std::sync::Weak;

// One additional bounded live derivation/serialization, not 32 full configs.
// The original EditOwner's source/runtime budgets and all old debits remain.
const DERIVATION_BYTES: usize = 8 * 1024 * 1024;
fn public(e: crate::service_protocol::Error) -> BridgeError {
    application_service::public_error(e)
}
fn unavailable() -> BridgeError {
    BridgeError::new(
        "cli_access_unavailable",
        "Configuration delegation requires the original running Desktop and READ permission.",
    )
}
fn matches(project: &NativeProject, entry: &Entry) -> bool {
    project.runtime_id == entry.source.runtime_id
        && project.canonical_root == entry.source.root
        && project.device == entry.source.device
        && project.inode == entry.source.inode
}
pub(crate) struct ConfigurationAgentGate {
    document: Weak<Inner>,
}
impl ConfigurationAgentGate {
    pub(crate) fn same_publisher(&self, p: &RegistrationPublisher) -> bool {
        self.document
            .upgrade()
            .is_some_and(|d| p.same_slot(&d.android_registration_control))
    }
    pub(crate) fn epoch(&self) -> Result<u64, BridgeError> {
        self.document
            .upgrade()
            .ok_or_else(unavailable)?
            .android_registration_control
            .epoch()
    }
    pub(crate) fn current(&self, original: &NativeProject) -> Result<(), BridgeError> {
        let inner = self.document.upgrade().ok_or_else(unavailable)?;
        let state = inner.state.try_lock().map_err(|e| match e {
            std::sync::TryLockError::WouldBlock => {
                BridgeError::new("busy", "Wait for the original document.")
            }
            std::sync::TryLockError::Poisoned(_) => BridgeError::cleanup_unknown(),
        })?;
        if !state.lifetime.original_bound()
            || state.lost_observed
            || state.unknown
            || state.exhausted
            || state.stopping
            || state.retiring
            || state.quit_pending
            || state.lock_pending
            || state.maintenance.closed()
            || !Arc::ptr_eq(&inner.session_identity, &original.document_identity)
        {
            return Err(unavailable());
        }
        let (generation, root) =
            inner
                .bridge
                .native_project(&original.runtime_id)
                .map_err(|e| {
                    if e.reason == Reason::CleanupUnknown {
                        BridgeError::cleanup_unknown()
                    } else {
                        unavailable()
                    }
                })?;
        let (device, inode) = root
            .identity
            .posix()
            .map_err(|_| BridgeError::invalid())?
            .service_identity();
        if generation != original.registration_generation
            || root.path != original.canonical_root
            || device != original.device
            || inode != original.inode
        {
            return Err(unavailable());
        }
        Ok(())
    }
}
impl DocumentBinding {
    fn configuration_service(&self) -> Result<Arc<ApplicationService>, BridgeError> {
        // No Doc guard here: this exact existing Host may synchronously inspect
        // its native storage. It never initializes or enables dormant access.
        self.inner
            .bridge
            .application_service
            .configuration_service()
            .map_err(public)
    }
    pub(crate) fn agent_configuration_status(
        &self,
        origin: Option<&p::Query>,
    ) -> Result<p::DesktopStatus, BridgeError> {
        let service = self.configuration_service()?;
        let requests = service.configuration_requests();
        match origin {
            Some(origin) => requests.desktop_request(origin),
            None => requests.desktop(),
        }
        .map_err(public)
    }
    pub(crate) fn agent_configuration_relay(
        &self,
    ) -> Result<Option<p::DesktopStatus>, BridgeError> {
        let service = match self.configuration_service() {
            Ok(s) => s,
            Err(e) if e.code == "cli_access_unavailable" => return Ok(None),
            Err(e) => return Err(e),
        };
        service.publish_configuration_history().map_err(public)?;
        service
            .configuration_requests()
            .desktop()
            .map(Some)
            .map_err(public)
    }
    pub(crate) fn agent_configuration_relay_lost(&self) {
        let at = Instant::now();
        self.inner.bridge.edits.configuration_agent_relay_lost(at);
        if let Ok(service) = self.configuration_service() {
            service.configuration_requests().close(at);
        }
        // Existing native Window/Doc loss is independent. READ expiry and the
        // SAME Config watchdog also stop active requests without JS/Relay.
    }
    fn configuration_agent_peers(
        &self,
        state: &DocumentState,
        opening: bool,
    ) -> Result<(), BridgeError> {
        self.passive_query_gate_locked(state, &self.inner.bridge)?;
        state.github.setup_ensure_idle()?;
        if state.github.native_work_pending()
            || !self.inner.bridge.supervisor.can_exit()
            || state
                .slot
                .as_ref()
                .is_some_and(|s| s.phase != Phase::Idle || !s.owner.resources_settled())
            || opening && !self.inner.bridge.edits.can_exit()
        {
            return Err(BridgeError::new(
                "busy",
                "Finish the original native operation first.",
            ));
        }
        #[cfg(any(
            all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
            all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )
        ))]
        {
            let retained =
                lookup_memory::retained_document_bytes(&self.inner, state).map_err(|_| {
                    BridgeError::new(
                        "cli_access_busy",
                        "Configuration comparison storage is not available.",
                    )
                })?;
            self.configuration_agent_storage(retained)?;
        }
        Ok(())
    }
    fn configuration_agent_storage(&self, retained: usize) -> Result<usize, BridgeError> {
        let edits = self.inner.bridge.edits.configuration_agent_edit_backing()?;
        retained.checked_add(edits).and_then(|n| n.checked_add(DERIVATION_BYTES))
            .filter(|n| *n <= SESSION_BYTES).ok_or_else(|| BridgeError::new(
                "cli_access_busy",
                "This configuration exceeds bounded CLI storage. Preserve the current draft and use the ordinary Desktop editor after original work settles.",
            ))
    }
    fn configuration_agent_registration(
        &self,
        original: &NativeProject,
    ) -> Result<(), BridgeError> {
        let (generation, root) = self
            .inner
            .bridge
            .native_project(&original.runtime_id)
            .map_err(|e| {
                if e.reason == Reason::CleanupUnknown {
                    BridgeError::cleanup_unknown()
                } else {
                    unavailable()
                }
            })?;
        let (device, inode) = root
            .identity
            .posix()
            .map_err(|_| BridgeError::invalid())?
            .service_identity();
        if generation != original.registration_generation
            || root.path != original.canonical_root
            || device != original.device
            || inode != original.inode
            || !Arc::ptr_eq(&self.inner.session_identity, &original.document_identity)
        {
            return Err(unavailable());
        }
        Ok(())
    }
    pub(crate) fn agent_configuration_command(
        &self,
        window: &str,
        q: p::Query,
        kind: Kind,
    ) -> Result<crate::edit_protocol::ConfigEditStatus, BridgeError> {
        let service = self.configuration_service()?;
        let entry = service.configuration_requests().entry(&q).map_err(public)?;
        let result = (|| {
            let opening = kind == Kind::Read;
            // Exact repeated bridge calls observe only. They cannot dispatch a
            // queued proposal twice, even after a lost renderer invoke ACK.
            if !entry.queued(kind).map_err(public)? {
                let status = self.inner.bridge.edits.status()?;
                let data = entry.status().map_err(public)?;
                if data.operation_id.as_ref().is_some_and(|id| {
                    status
                        .active
                        .iter()
                        .chain(status.last_terminal.iter())
                        .any(|p| p.session_id == id.as_str())
                }) {
                    return Ok(status);
                }
                return Err(BridgeError::new(
                    "cli_access_changed",
                    "This original request is no longer awaiting that step.",
                ));
            }
            let (original, stamp, existing) = {
                let state = self.lock();
                self.configuration_agent_peers(&state, opening)?;
                let original = self.service_project_locked(&state, &entry.source.runtime_id)?;
                if !matches(&original, &entry) {
                    return Err(unavailable());
                }
                let stamp: Option<SavedEditStamp> = if opening {
                    Some(
                        self.inner
                            .bridge
                            .edits
                            .saved_registration_guard(&self.inner.session_identity)?
                            .stamp()?,
                    )
                } else {
                    None
                };
                let existing = if opening {
                    None
                } else {
                    Some(
                        self.inner
                            .bridge
                            .edits
                            .configuration_agent_access(window, &entry)?,
                    )
                };
                (original, stamp, existing)
            };
            service
                .configuration_current(&entry, opening)
                .map_err(public)?; // OFF Doc/Edit, BEFORE actual publisher.
            self.configuration_edit_admit_checked(
                |state, publisher| {
                    self.configuration_agent_peers(state, opening)?;
                    self.configuration_agent_registration(&original)?;
                    if !matches(&original, &entry)
                        || !entry.live(Instant::now())
                        || service.native_history_current().is_err()
                    {
                        return Err(unavailable());
                    }
                    if let Some(stamp) = &stamp {
                        if publisher.tool_source_epoch()? != original.input_revision
                            || !self
                                .inner
                                .bridge
                                .edits
                                .saved_registration_guard(&self.inner.session_identity)?
                                .matches(stamp)
                        {
                            return Err(unavailable());
                        }
                    }
                    if !entry.dispatch(kind).map_err(public)? {
                        return Err(unavailable());
                    }
                    let link = if opening {
                        self.inner.bridge.edits.configuration_agent_link(
                            window,
                            entry.clone(),
                            &service,
                            original.clone(),
                            ConfigurationAgentGate {
                                document: Arc::downgrade(&self.inner),
                            },
                        )?
                    } else {
                        existing.ok_or_else(unavailable)?
                    };
                    link.begin(
                        publisher,
                        match kind {
                            Kind::Read => Step::Open,
                            Kind::Prepare => Step::Prepare,
                            Kind::Apply => Step::Apply,
                        },
                    )?;
                    Ok(link)
                },
                |bridge, publisher, link| {
                    link.accepted(
                        publisher,
                        match kind {
                            Kind::Read => Step::Open,
                            Kind::Prepare => Step::Prepare,
                            Kind::Apply => Step::Apply,
                        },
                    )?;
                    match kind {
                        Kind::Read => bridge
                            .edits
                            .open_agent_configuration(publisher, window, link),
                        Kind::Prepare => bridge
                            .edits
                            .prepare_agent_configuration(publisher, window, link),
                        Kind::Apply => bridge
                            .edits
                            .apply_agent_configuration(publisher, window, link),
                    }
                },
            )
        })();
        if result.is_err() {
            entry.dispatch_failed();
        }
        result
    }
    pub(crate) fn allow_agent_configuration_apply(
        &self,
        window: &str,
        args: p::Allow,
    ) -> Result<p::DesktopStatus, BridgeError> {
        let service = self.configuration_service()?;
        let entry = service
            .configuration_requests()
            .entry(&args.origin)
            .map_err(public)?;
        // Read-only Host/native comparisons finish off Doc. Recheck immutable
        // root, native revision and full retained preview under final Doc/Edit.
        service
            .configuration_current(&entry, false)
            .map_err(public)?;
        let state = self.lock();
        self.configuration_agent_peers(&state, false)?;
        let original = self.service_project_locked(&state, &entry.source.runtime_id)?;
        if !matches(&original, &entry) || service.native_history_current().is_err() {
            return Err(unavailable());
        }
        self.inner
            .bridge
            .edits
            .allow_agent_configuration(window, &entry, &args)?;
        service.configuration_requests().desktop().map_err(public)
    }
    pub(crate) fn revoke_agent_configuration(
        &self,
        window: &str,
        q: p::Query,
    ) -> Result<p::DesktopStatus, BridgeError> {
        let at = Instant::now();
        self.inner
            .bridge
            .edits
            .signal_agent_configuration_cancel(window, &q, at)?;
        let service = self.configuration_service()?;
        let entry = service.configuration_requests().entry(&q).map_err(public)?;
        // Exact original STOP remains available without selected project/idle.
        self.inner
            .bridge
            .edits
            .cancel_agent_configuration(window, &entry, at)?;
        service.configuration_requests().desktop().map_err(public)
    }
}

#[cfg(test)]
mod configuration_storage_tests {
    use super::*;
    #[test]
    fn actual_default_document_fits_configuration_quote_and_retained_capacity_refuses() {
        // Actual default owners/census; no invented D, filesystem IO, Session,
        // resource receipt, native availability or permission assertion.
        let bridge = Arc::new(DesktopBridge::new(std::path::PathBuf::from(
            "/never-opened-configuration-census",
        )));
        let document = DocumentBinding::new(bridge.clone());
        bridge.edits.initial_document("main").unwrap();
        let mut state = document.lock();
        let d = lookup_memory::retained_document_bytes(&document.inner, &state).unwrap();
        let total = document.configuration_agent_storage(d).unwrap();
        assert!(total > d + DERIVATION_BYTES && total <= SESSION_BYTES);
        // Capacity of an actual retained Vec is counted even with zero records.
        state
            .records
            .reserve_exact(SESSION_BYTES / std::mem::size_of::<Record>() + 1);
        let capacity = state.records.capacity();
        assert!(state.records.is_empty());
        let over = lookup_memory::retained_document_bytes(&document.inner, &state).unwrap();
        assert!(over > d + SESSION_BYTES);
        assert!(document.configuration_agent_storage(over).is_err());
        assert_eq!(state.records.capacity(), capacity);
        assert!(state.records.is_empty());
    }
}
