//! Main-Webview-only continuation of queued metadata_text comparisons. IPC
//! never calls EditOwner. Host/Service IO occurs outside both Doc/Edit locks.
use super::*;
use crate::{
    application_service::ApplicationService,
    application_service_host::NativeProject,
    edit_owner::{MetadataTextAgentStep as Step, SavedEditStamp},
    service_metadata_text_protocol as p,
    service_metadata_text_requests::{Call, Entry, Kind},
};
use std::sync::Weak;

// The borrowed Edit census includes fixed metadata serialization, submission
// and all pending original-caller capacities. Every old debit remains; there
// is no additional guessed partition or zero-credit for retained data.
fn public(e: crate::service_protocol::Error) -> BridgeError {
    application_service::public_error(e)
}

fn unavailable() -> BridgeError {
    BridgeError::new(
        "cli_access_unavailable",
        "MetadataText delegation requires the original running Desktop and READ permission.",
    )
}
fn matches(project: &NativeProject, entry: &Entry) -> bool {
    project.runtime_id == entry.source.runtime_id
        && project.canonical_root == entry.source.root
        && project.device == entry.source.device
        && project.inode == entry.source.inode
}
pub(crate) struct MetadataTextAgentGate {
    document: Weak<Inner>,
}
impl MetadataTextAgentGate {
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
    fn metadata_text_service(&self) -> Result<Arc<ApplicationService>, BridgeError> {
        // No Doc guard here: this exact existing Host may synchronously inspect
        // its native storage. It never initializes or enables dormant access.
        self.inner
            .bridge
            .application_service
            .configuration_service()
            .map_err(public)
    }
    pub(crate) fn agent_metadata_text_status(
        &self,
        origin: Option<&p::Query>,
    ) -> Result<p::DesktopStatus, BridgeError> {
        let service = self.metadata_text_service()?;
        let requests = service.configuration_requests();
        match origin {
            Some(origin) => requests.metadata_desktop(Some(origin)),
            None => requests.metadata_desktop(None),
        }
        .map_err(public)
    }
    pub(crate) fn agent_metadata_text_relay(
        &self,
    ) -> Result<Option<p::DesktopStatus>, BridgeError> {
        let service = match self.metadata_text_service() {
            Ok(s) => s,
            Err(e) if e.code == "cli_access_unavailable" => return Ok(None),
            Err(e) => return Err(e),
        };
        service.publish_metadata_text_history().map_err(public)?;
        service
            .configuration_requests()
            .metadata_desktop(None)
            .map(Some)
            .map_err(public)
    }
    pub(crate) fn agent_metadata_text_relay_lost(&self) {
        let at = Instant::now();
        self.inner.bridge.edits.metadata_text_agent_relay_lost(at);
        if let Ok(service) = self.metadata_text_service() {
            service.configuration_requests().close(at);
        }
        // Existing native Window/Doc loss is independent. READ expiry and the
        // SAME Config watchdog also stop active requests without JS/Relay.
    }
    fn metadata_text_agent_peers(
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
                        "MetadataText comparison storage is not available.",
                    )
                })?;
            self.metadata_text_agent_storage(retained)?;
        }
        Ok(())
    }
    fn metadata_text_agent_storage(&self, retained: usize) -> Result<usize, BridgeError> {
        let edits = self.inner.bridge.edits.metadata_text_agent_edit_backing()?;
        retained.checked_add(edits)
            .filter(|n| *n <= SESSION_BYTES).ok_or_else(|| BridgeError::new(
                "cli_access_busy",
                "This metadata_text exceeds bounded CLI storage. Preserve the current draft and use the ordinary Desktop editor after original work settles.",
            ))
    }
    fn metadata_text_agent_registration(
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

    /// Actual public Load on the same passive Supervisor. The Completion facet
    /// is armed BEFORE the original GO; its return is separate from this exact
    /// RAW continuation. Neither a status DTO nor callback can synthesize joins.
    pub(crate) async fn agent_metadata_text_read(
        &self,
        window: &str,
        q: p::Query,
    ) -> Result<crate::metadata_text_edit_protocol::Observation, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let service = self.metadata_text_service()?;
        let entry = service
            .configuration_requests()
            .metadata_entry(&q)
            .map_err(public)?;
        let mut caller: Option<Call> = None;
        let result=async {
            if !entry.queued(Kind::Read).map_err(public)?{return Err(unavailable())}
            let (original,stamp)={
                let state=self.lock();self.metadata_text_agent_peers(&state,true)?;
                let original=self.service_project_locked(&state,&entry.source.runtime_id)?;
                if !matches(&original,&entry){return Err(unavailable())}
                let stamp=self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?.stamp()?;
                (original,stamp)
            };
            service.metadata_text_current(&entry,true).map_err(public)?;
            let query={
                let state=self.lock();self.metadata_text_agent_peers(&state,true)?;
                self.metadata_text_agent_registration(&original)?;
                if !matches(&original,&entry)||!entry.live(Instant::now())
                    ||service.native_history_current().is_err()
                    ||self.inner.android_registration_control.epoch()?!=original.input_revision
                    ||!self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?.matches(&stamp)
                    ||!entry.dispatch(Kind::Read).map_err(public)?{return Err(unavailable())}
                caller=Some(entry.caller(Kind::Read).map_err(public)?);
                self.inner.bridge.supervisor.start_agent_metadata_text(
                    serde_json::json!({"root":&original.canonical_root,"platform":entry.input().platform,"locale":&entry.input().locale}),entry.clone())?
            };
            let value=query.wait().await?;
            let platform=match entry.input().platform{p::Platform::Android=>crate::metadata_text_edit_protocol::Platform::Android,p::Platform::Ios=>crate::metadata_text_edit_protocol::Platform::Ios};
            crate::metadata_text_edit_protocol::observation_result(value,platform,&entry.input().locale)
        }.await;
        if result.is_err() && caller.is_some() {
            entry.dispatch_failed()
        }
        if let Some(caller) = caller {
            caller.returned().map_err(public)?;
        }
        result
    }
    pub(crate) fn agent_metadata_text_command(
        &self,
        window: &str,
        q: p::Query,
        kind: Kind,
    ) -> Result<crate::metadata_text_edit_protocol::MetadataTextEditStatus, BridgeError> {
        if kind == Kind::Read || window != MAIN {
            return Err(BridgeError::invalid());
        }
        let service = self.metadata_text_service()?;
        let entry = service
            .configuration_requests()
            .metadata_entry(&q)
            .map_err(public)?;
        let mut caller: Option<Call> = None;
        let result = (|| {
            let opening = kind == Kind::Open;
            if !entry.queued(kind).map_err(public)? {
                let status = self.inner.bridge.edits.metadata_text_status()?;
                let data = entry.status().map_err(public)?;
                if data.original.as_ref().is_some_and(|o| {
                    status
                        .active
                        .iter()
                        .chain(status.last_terminal.iter())
                        .any(|p| {
                            p.session_id == o.session_id.as_str()
                                && p.owner_generation == o.owner_generation.as_str()
                        })
                }) {
                    return Ok(status);
                }
                return Err(unavailable());
            }
            let (original, stamp, existing) = {
                let state = self.lock();
                self.metadata_text_agent_peers(&state, opening)?;
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
                            .metadata_text_agent_access(window, &entry)?,
                    )
                };
                (original, stamp, existing)
            };
            // The intentional Open publication makes the earlier cached READ
            // observation stale. Current native root/READ identity stays exact;
            // only the initial public Load requires the cached fresh snapshot.
            service
                .metadata_text_current(&entry, false)
                .map_err(public)?;
            let mut publisher = self
                .inner
                .android_registration_control
                .reserve(RegistrationPublisherKind::General, false)?;
            let outcome = (|| {
                let mut state = self.lock();
                self.metadata_text_agent_peers(&state, opening)?;
                self.metadata_text_agent_registration(&original)?;
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
                caller = Some(entry.caller(kind).map_err(public)?);
                let link = if opening {
                    self.inner.bridge.edits.metadata_text_agent_link(
                        window,
                        entry.clone(),
                        &service,
                        original.clone(),
                        MetadataTextAgentGate {
                            document: Arc::downgrade(&self.inner),
                        },
                    )?
                } else {
                    existing.ok_or_else(unavailable)?
                };
                let step = match kind {
                    Kind::Open => Step::Open,
                    Kind::Prepare => Step::Prepare,
                    Kind::Apply => Step::Apply,
                    Kind::Read => return Err(BridgeError::invalid()),
                };
                link.begin(&publisher, step)?;
                let registration = self.registered_edit_root_locked_published(
                    &mut state,
                    crate::edit_protocol::EditDomain::MetadataText,
                    |_| Ok(entry.source.runtime_id.clone()),
                    None,
                    &mut publisher,
                )?;
                link.accepted(&publisher, step)?;
                match kind {
                    Kind::Open => self.inner.bridge.edits.open_agent_metadata_text(
                        &publisher,
                        window,
                        link,
                        registration,
                    ),
                    Kind::Prepare => self.inner.bridge.edits.prepare_agent_metadata_text(
                        &publisher,
                        window,
                        link,
                        registration,
                    ),
                    Kind::Apply => self.inner.bridge.edits.apply_agent_metadata_text(
                        &publisher,
                        window,
                        link,
                        registration,
                    ),
                    Kind::Read => Err(BridgeError::invalid()),
                }
            })();
            finish_registration_publisher(publisher);
            outcome
        })();
        if result.is_err() && caller.is_some() {
            entry.dispatch_failed()
        }
        if let Some(caller) = caller {
            caller.returned().map_err(public)?;
        }
        result
    }
    pub(crate) fn allow_agent_metadata_text_apply(
        &self,
        window: &str,
        args: p::Allow,
    ) -> Result<p::DesktopStatus, BridgeError> {
        let service = self.metadata_text_service()?;
        let entry = service
            .configuration_requests()
            .metadata_entry(&args.origin)
            .map_err(public)?;
        service
            .metadata_text_current(&entry, false)
            .map_err(public)?;
        let state = self.lock();
        self.metadata_text_agent_peers(&state, false)?;
        let original = self.service_project_locked(&state, &entry.source.runtime_id)?;
        if !matches(&original, &entry) || service.native_history_current().is_err() {
            return Err(unavailable());
        }
        self.inner
            .bridge
            .edits
            .allow_agent_metadata_text(window, &entry, &args)?;
        service
            .configuration_requests()
            .metadata_desktop(Some(&args.origin))
            .map_err(public)
    }
    pub(crate) fn revoke_agent_metadata_text(
        &self,
        window: &str,
        q: p::Query,
    ) -> Result<p::DesktopStatus, BridgeError> {
        let at = Instant::now();
        self.inner
            .bridge
            .edits
            .signal_agent_metadata_text_cancel(window, &q, at)?;
        let service = self.metadata_text_service()?;
        let entry = service
            .configuration_requests()
            .metadata_entry(&q)
            .map_err(public)?;
        self.inner
            .bridge
            .edits
            .cancel_agent_metadata_text(window, &entry, at)?;
        service
            .configuration_requests()
            .metadata_desktop(Some(&q))
            .map_err(public)
    }
}

#[cfg(all(test, any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))
)))]
mod metadata_storage_tests {
    use super::*;
    #[test]
    fn actual_default_document_fits_metadata_quote_and_retained_capacity_refuses() {
        // The SAME actual default owners and borrowed census as admission.
        // No source is opened, no native owner is run and D is not fabricated.
        let bridge = Arc::new(DesktopBridge::new(std::path::PathBuf::from(
            "/never-opened-metadata-census",
        )));
        let document = DocumentBinding::new(bridge.clone());
        bridge.edits.initial_document("main").unwrap();
        let mut state = document.lock();
        let d = lookup_memory::retained_document_bytes(&document.inner, &state).unwrap();
        let total = document.metadata_text_agent_storage(d).unwrap();
        assert!(total > d && total <= SESSION_BYTES);
        state.records.reserve_exact(SESSION_BYTES / std::mem::size_of::<Record>() + 1);
        let capacity = state.records.capacity();
        assert!(state.records.is_empty());
        let over = lookup_memory::retained_document_bytes(&document.inner, &state).unwrap();
        assert!(over > d + SESSION_BYTES);
        assert!(document.metadata_text_agent_storage(over).is_err());
        assert_eq!(state.records.capacity(), capacity);
        assert!(state.records.is_empty());
    }
}
