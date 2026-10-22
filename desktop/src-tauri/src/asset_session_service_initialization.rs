//! Genuine MAIN continuation of Initialization; Host IO is outside Doc/Edit.
//! The same registered original owns all input/child/write/finality resources.
use super::*;
use crate::{
    application_service::ApplicationService,
    application_service_host::NativeProject,
    edit_owner::{InitializationAgentStep as Step, SavedEditStamp},
    project_initialization_edit_protocol as n, service_initialization_protocol as p,
    service_initialization_requests::{Entry, Kind},
};
use serde_json::Value;
use std::sync::Weak;
fn public(e: crate::service_protocol::Error) -> BridgeError {
    application_service::public_error(e)
}
fn unavailable() -> BridgeError {
    BridgeError::new(
        "cli_access_unavailable",
        "Initialization delegation requires the original running Desktop and READ permission.",
    )
}
fn matches(project: &NativeProject, entry: &Entry) -> bool {
    project.runtime_id == entry.source.runtime_id
        && project.canonical_root == entry.source.root
        && project.device == entry.source.device
        && project.inode == entry.source.inode
}
pub(crate) struct InitializationAgentGate {
    document: Weak<Inner>,
}
impl InitializationAgentGate {
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

// Closed RAW facet of the EXISTING three initialization commands. No full draft
// enters IPC. Borrowed checks precede typed allocation; shell drops its original
// Request before entering the native owner, so Open raw trees cannot coexist
// with future reader frames after the original Session has been installed.
pub(crate) fn initialization_agent_raw(
    body: &Value,
    kind: Kind,
) -> Result<Option<(p::Query, Input)>, BridgeError> {
    if body.get("agentInitialization").is_none() {
        return Ok(None);
    }
    let map = body.as_object().ok_or_else(BridgeError::invalid)?;
    if map.len() != 3
        || map.get("agentInitialization") != Some(&Value::Bool(true))
        || !map.contains_key("origin")
        || !map.contains_key("input")
    {
        return Err(BridgeError::invalid());
    }
    crate::protocol::check_value(body)?;
    crate::edit_protocol::bounded(body, crate::edit_protocol::REQUEST_LIMIT)?;
    let origin: p::Query =
        serde::Deserialize::deserialize(&body["origin"]).map_err(|_| BridgeError::invalid())?;
    let raw = &body["input"];
    let input = match kind {
        Kind::Open => {
            if raw.get("intent").and_then(Value::as_str) != Some("initialize")
                || !raw.get("draft").is_some_and(Value::is_object)
            {
                return Err(BridgeError::invalid());
            }
            crate::github_workflow_edit_protocol::value_bounds(&raw["draft"], 28, 512 * 1024)?;
            Input::Open(crate::edit_commands::initialization_open(raw)?)
        }
        Kind::Prepare => Input::Prepare(crate::edit_commands::initialization_prepare(raw)?),
        Kind::Apply => Input::Apply(crate::edit_commands::initialization_apply(raw)?),
    };
    if input.intent() != n::Intent::Initialize {
        return Err(BridgeError::invalid());
    }
    Ok(Some((origin, input)))
}
pub(crate) fn raw_request(bytes: &[u8], kind: Kind) -> Result<(p::Query, Input), BridgeError> {
    if bytes.is_empty() || bytes.len() > crate::edit_protocol::REQUEST_LIMIT {
        return Err(BridgeError::invalid());
    }
    let body = crate::protocol::strict_json(bytes)?;
    let result = initialization_agent_raw(&body, kind)?.ok_or_else(BridgeError::invalid)?;
    // One strict bounded parse. The original Input is held; its generic tree
    // and the shell Request bytes are gone before original Session admission.
    drop(body);
    Ok(result)
}
pub(crate) enum Input {
    Open(n::Open),
    Prepare(n::Prepare),
    Apply(n::Apply),
}
impl Input {
    fn kind(&self) -> Kind {
        match self {
            Self::Open(_) => Kind::Open,
            Self::Prepare(_) => Kind::Prepare,
            Self::Apply(_) => Kind::Apply,
        }
    }
    fn intent(&self) -> n::Intent {
        match self {
            Self::Open(v) => v.intent(),
            Self::Prepare(v) => v.intent,
            Self::Apply(v) => v.intent,
        }
    }
    fn matches(&self, entry: &Entry) -> bool {
        match self {
            Self::Open(v) => {
                v.intent() == n::Intent::Initialize && v.project_id() == entry.source.runtime_id
            }
            Self::Prepare(v) => {
                v.intent == n::Intent::Initialize
                    && entry.original().is_ok_and(|o| {
                        o.session_id.as_str() == v.session_id && o.revision.as_str() == v.revision
                    })
            }
            Self::Apply(v) => {
                v.intent == n::Intent::Initialize
                    && entry
                        .original()
                        .is_ok_and(|o| o.session_id.as_str() == v.session_id)
                    && entry
                        .review()
                        .is_ok_and(|r| r.plan_token.as_str() == v.plan_token)
            }
        }
    }
}
impl DocumentBinding {
    fn initialization_service(&self) -> Result<Arc<ApplicationService>, BridgeError> {
        self.inner
            .bridge
            .application_service
            .configuration_service()
            .map_err(public)
    }
    pub(crate) fn agent_initialization_status(
        &self,
        q: Option<&p::Query>,
    ) -> Result<p::DesktopStatus, BridgeError> {
        self.initialization_service()?
            .configuration_requests()
            .initialization_desktop(q)
            .map_err(public)
    }
    pub(crate) fn agent_initialization_relay(
        &self,
    ) -> Result<Option<p::DesktopStatus>, BridgeError> {
        let service = match self.initialization_service() {
            Ok(s) => s,
            Err(e) if e.code == "cli_access_unavailable" => return Ok(None),
            Err(e) => return Err(e),
        };
        service.publish_initialization_history().map_err(public)?;
        service
            .configuration_requests()
            .initialization_desktop(None)
            .map(Some)
            .map_err(public)
    }
    pub(crate) fn agent_initialization_relay_lost(&self) {
        let at = Instant::now();
        self.inner.bridge.edits.initialization_agent_relay_lost(at);
        if let Ok(service) = self.initialization_service() {
            for entry in service
                .configuration_requests()
                .initialization_entries()
                .unwrap_or_default()
            {
                let _ = entry.cancel(at);
            }
        }
    }
    fn initialization_agent_peers(
        &self,
        state: &DocumentState,
        opening: bool,
    ) -> Result<(), BridgeError> {
        // This original gate checks actual Saved owners BEFORE the registered
        // publisher's context_changed effects. Repeat under the final same Doc.
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
        self.initialization_agent_storage(state)?;
        Ok(())
    }
    fn initialization_agent_storage(&self, state: &DocumentState) -> Result<usize, BridgeError> {
        #[cfg(any(
            all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
            all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )
        ))]
        {
            let denied = || {
                BridgeError::new("cli_access_busy","This initialization exceeds bounded storage. Preserve the original draft and pending work.")
            };
            let doc =
                lookup_memory::retained_document_bytes(&self.inner, state).map_err(|_| denied())?;
            let additional = installation_memory::additional_document_bytes(self, state)
                .map_err(|_| denied())?;
            let edit = self
                .inner
                .bridge
                .edits
                .initialization_agent_edit_backing()?;
            // Original code inspector has an independent128MiB reservation.
            // Its allocation cannot consume Document/DATA headroom: the SAME
            // existing helper separately enforces full Doc+edit DATA<=64MiB.
            crate::macos_history_inventory::admission_bytes(
                doc.checked_add(additional).ok_or_else(denied)?,
                edit,
            )
            .ok_or_else(denied)
        }
        #[cfg(not(any(
            all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
            all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )
        )))]
        {
            let _ = state;
            Err(unavailable())
        }
    }
    fn initialization_agent_registration(
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
    pub(crate) fn agent_initialization_command(
        &self,
        window: &str,
        q: p::Query,
        input: Input,
    ) -> Result<n::InitializationStatus, BridgeError> {
        let service = self.initialization_service()?;
        let entry = service
            .configuration_requests()
            .initialization_entry(&q)
            .map_err(public)?;
        if !input.matches(&entry) {
            return Err(BridgeError::invalid());
        }
        let kind = input.kind();
        if !entry.queued(kind).map_err(public)? {
            return Err(BridgeError::new("cli_access_changed","This original initialization step is no longer queued. Inspect its retained request."));
        }
        let caller = entry.caller(kind).map_err(public)?;
        let result = (|| {
            let opening = kind == Kind::Open;
            let (original, stamp, link) = {
                let state = self.lock();
                self.initialization_agent_peers(&state, opening)?;
                if !opening {
                    self.inner
                        .bridge
                        .edits
                        .initialization_agent_origin(window, Some(&entry))?;
                }
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
                let link = if let Input::Open(open) = &input {
                    self.inner.bridge.edits.initialization_agent_link(
                        window,
                        entry.clone(),
                        &service,
                        original.clone(),
                        InitializationAgentGate {
                            document: Arc::downgrade(&self.inner),
                        },
                        open,
                    )?
                } else {
                    self.inner
                        .bridge
                        .edits
                        .initialization_agent_access(window, &entry)?
                };
                (original, stamp, link)
            };
            let ticket = if let Input::Open(open) = input {
                Some(
                    self.inner
                        .bridge
                        .edits
                        .initialization_open_ticket(window, open)?,
                )
            } else {
                None
            };
            service
                .initialization_current(&entry, opening)
                .map_err(public)?; // OFF Doc/Edit
            let mut publisher = self
                .inner
                .android_registration_control
                .reserve(RegistrationPublisherKind::General, false)?;
            let result = (|| {
                let mut state = self.lock();
                self.initialization_agent_peers(&state, opening)?;
                self.initialization_agent_registration(&original)?;
                if !matches(&original, &entry)
                    || !entry.live(Instant::now())
                    || service.native_history_current().is_err()
                {
                    return Err(unavailable());
                }
                if !opening {
                    self.inner
                        .bridge
                        .edits
                        .initialization_agent_origin(window, Some(&entry))?;
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
                let step = match kind {
                    Kind::Open => Step::Open,
                    Kind::Prepare => Step::Prepare,
                    Kind::Apply => Step::Apply,
                };
                link.begin(&publisher, step)?;
                // SAME actual registered-root function, now preceded by both
                // real peer-idle cuts and the exact original publication link.
                let registration = self.registered_edit_root_locked_published(
                    &mut state,
                    crate::edit_protocol::EditDomain::ProjectInitialization,
                    |_| Ok(original.runtime_id.clone()),
                    None,
                    &mut publisher,
                )?;
                link.accepted(&publisher, step)?;
                match kind {
                    Kind::Open => self.inner.bridge.edits.open_agent_initialization(
                        &publisher,
                        window,
                        link,
                        ticket.ok_or_else(BridgeError::invalid)?,
                        registration,
                    ),
                    Kind::Prepare => self.inner.bridge.edits.prepare_agent_initialization(
                        &publisher,
                        window,
                        link,
                        registration,
                    ),
                    Kind::Apply => self.inner.bridge.edits.apply_agent_initialization(
                        &publisher,
                        window,
                        link,
                        registration,
                    ),
                }
            })();
            finish_registration_publisher(publisher);
            result
        })();
        // Actual bridge caller return. Post-install Err remains admitted Unknown;
        // neither status nor a terminal frame can supply this independent cut.
        if let Err(e) = caller.returned(result.is_ok()) {
            entry.unknown();
            return Err(public(e));
        }
        result
    }
    pub(crate) fn allow_agent_initialization(
        &self,
        window: &str,
        args: p::Allow,
    ) -> Result<p::DesktopStatus, BridgeError> {
        args.validate().map_err(public)?;
        let service = self.initialization_service()?;
        let entry = service
            .configuration_requests()
            .initialization_entry(&args.origin)
            .map_err(public)?;
        let (original, ticket) = {
            let state = self.lock();
            self.initialization_agent_peers(&state, false)?;
            self.inner
                .bridge
                .edits
                .initialization_agent_origin(window, Some(&entry))?;
            let original = self.service_project_locked(&state, &entry.source.runtime_id)?;
            if !matches(&original, &entry) {
                return Err(unavailable());
            }
            let ticket = self
                .inner
                .bridge
                .edits
                .reserve_agent_initialization(window, &entry, &args)?;
            (original, ticket)
        };
        // The native-issued request revision was consumed BEFORE this possible
        // Host/storage wait. Revoke/earlier READ cannot become a fresh consent.
        service
            .initialization_current(&entry, false)
            .map_err(public)?;
        let state = self.lock();
        self.initialization_agent_peers(&state, false)?;
        self.initialization_agent_registration(&original)?;
        if service.native_history_current().is_err() {
            return Err(unavailable());
        }
        self.inner
            .bridge
            .edits
            .allow_agent_initialization(window, &entry, &args, ticket)?;
        drop(state);
        service
            .configuration_requests()
            .initialization_desktop(Some(&args.origin))
            .map_err(public)
    }
    pub(crate) fn revoke_agent_initialization(
        &self,
        window: &str,
        q: p::Query,
    ) -> Result<p::DesktopStatus, BridgeError> {
        let at = Instant::now();
        self.inner
            .bridge
            .edits
            .signal_agent_initialization_cancel(window, &q, at)?;
        let service = self.initialization_service()?;
        let entry = service
            .configuration_requests()
            .initialization_entry(&q)
            .map_err(public)?;
        self.inner
            .bridge
            .edits
            .cancel_agent_initialization(window, &entry, at)?;
        service
            .configuration_requests()
            .initialization_desktop(Some(&q))
            .map_err(public)
    }
}
#[cfg(test)]
#[path = "asset_session_service_initialization_tests.rs"]
mod tests;
