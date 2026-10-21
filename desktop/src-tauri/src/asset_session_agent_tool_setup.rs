//! A MAIN-only delegation facade, not another tool manager. All actions
//! enter their existing original admission/body/release and retirement paths.
use super::*;
use crate::{
    application_service::ApplicationService,
    application_service_host::NativeProject,
    edit_owner::SavedEditStamp,
    environment_diagnostics_owner::{AgentDoctorApproval, AgentDoctorBinding},
    saved_command_owner::{
        AgentToolInspectApproval, AgentToolInspectBinding,
        AgentToolAcquisitionApproval, AgentToolAcquisitionBinding, AgentToolRegistrationApproval,
        AgentToolRegistrationBinding,
    },
    service_protocol::{Error, Id},
    service_tool_setup_protocol as p, service_tool_setup_requests as req,
};
use serde::Deserialize;
#[path = "asset_session_agent_tool_inspect.rs"]
mod inspect;
pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, BridgeError> {
    if bytes.is_empty() || bytes.len() > crate::environment_diagnostics_protocol::REQUEST_LIMIT {
        return Err(BridgeError::invalid());
    }
    let value = crate::protocol::strict_json(bytes).map_err(|_| BridgeError::invalid())?;
    crate::protocol::check_value(&value)?;
    T::deserialize(&value).map_err(|_| BridgeError::invalid())
}
fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Allow {
    consent_id: Id,
    project_id: String,
    review: p::Review,
    consent_version: String,
    #[serde(deserialize_with = "present")]
    doctor_draft: Option<serde_json::Value>,
    #[serde(deserialize_with = "present")]
    source_context: Option<serde_json::Value>,
    #[serde(deserialize_with = "present")]
    native_consent: Option<String>,
    license_acknowledged: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Revoke {
    consent_id: Id,
}
#[derive(Clone)]
enum Approval {
    Doctor(Arc<AgentDoctorApproval>),
    Acquisition(Arc<AgentToolAcquisitionApproval>),
    SavedInspect(Arc<AgentToolInspectApproval>),
    Sources(Arc<AgentToolRegistrationApproval>),
}
impl Approval {
    fn review(&self) -> &p::Review {
        match self {
            Self::Doctor(a) => a.review(),
            Self::Acquisition(a) => a.review(),
            Self::SavedInspect(a) => a.review(),
            Self::Sources(a) => a.review(),
        }
    }
    fn expires(&self) -> Instant {
        match self {
            Self::Doctor(a) => a.expires(),
            Self::Acquisition(a) => a.expires(),
            Self::SavedInspect(a) => a.expires(),
            Self::Sources(a) => a.expires(),
        }
    }
    fn bytes(&self) -> Option<usize> {
        match self {
            Self::Doctor(a) => a.retained_bytes(),
            Self::Acquisition(a) => a.retained_bytes(),
            Self::SavedInspect(a) => a.retained_bytes(),
            Self::Sources(a) => a.retained_bytes(),
        }
    }
}
enum NativeBinding {
    Doctor(Arc<AgentDoctorBinding>),
    Acquisition(Arc<AgentToolAcquisitionBinding>),
    SavedInspect(Arc<AgentToolInspectBinding>),
    Sources(Arc<AgentToolRegistrationBinding>),
}
impl NativeBinding {
    fn bytes(&self) -> Option<usize> {
        match self {
            Self::Doctor(a) => a.retained_bytes(),
            Self::Acquisition(a) => a.retained_bytes(),
            Self::SavedInspect(a) => a.retained_bytes(),
            Self::Sources(a) => a.retained_bytes(),
        }
    }
}
pub(super) struct Grant {
    id: Id,
    scope: Arc<req::NativeScope>,
    link: Arc<req::NativeLink>,
    binding: NativeBinding,
    native: NativeProject,
    stamp: SavedEditStamp,
}
struct Pending {
    id: Id,
    approval: Approval,
    revoked: bool,
}
#[derive(Default)]
pub(super) struct State {
    grant: Option<Arc<Grant>>,
    pending: Option<Pending>,
    spent: Vec<Id>,
    service: Option<Weak<ApplicationService>>,
    lost: bool,
}
impl State {
    fn remember(&mut self, id: &Id) -> Result<(), Error> {
        if !self.spent.contains(id) {
            if self.spent.len() >= p::CONSENT_LIMIT {
                return Err(Error::Busy);
            }
            self.spent
                .try_reserve_exact(1)
                .map_err(|_| Error::StateUnknown)?;
            self.spent.push(id.clone());
        }
        Ok(())
    }
    fn ready(&self) -> Result<(), Error> {
        if self.lost {
            return Err(Error::StateUnknown);
        }
        if self.pending.is_some()
            || self
                .grant
                .as_ref()
                .is_some_and(|g| !g.scope.retired.load(Ordering::Acquire))
        {
            return Err(Error::Busy);
        }
        Ok(())
    }
    fn begin(&mut self, id: &Id, a: Approval) -> Result<(), Error> {
        self.ready()?;
        if self.spent.contains(id) {
            return Err(Error::AccessDenied);
        }
        self.remember(id)?;
        self.pending = Some(Pending {
            id: id.clone(),
            approval: a,
            revoked: false,
        });
        Ok(())
    }
}
fn public(e: Error) -> BridgeError {
    application_service::public_error(e)
}
fn document_fits(bytes: usize) -> Result<usize, BridgeError> {
    if bytes > SESSION_BYTES {
        Err(public(Error::Busy))
    } else {
        Ok(bytes)
    }
}
fn grant_cells_bytes(runtime_capacity: usize, root_capacity: usize) -> Option<usize> {
    std::mem::size_of::<Grant>()
        .checked_add(4 * std::mem::size_of::<usize>() + 8192)?
        .checked_add(runtime_capacity)?
        .checked_add(root_capacity)
}
fn service(state: &DocumentState) -> Result<Option<Arc<ApplicationService>>, Error> {
    state
        .agent_tool_setup
        .service
        .as_ref()
        .map(|s| s.upgrade().ok_or(Error::Unavailable))
        .transpose()
}
// Admission caller and native custody only. History flush runs AFTER the
// same relay joins on quit; including it here would make a drain cycle.
pub(super) fn pending(state: &DocumentState) -> bool {
    let s = &state.agent_tool_setup;
    s.pending.is_some()
        || s.grant
            .as_ref()
            .is_some_and(|g| !g.scope.retired.load(Ordering::Acquire) || !g.link.caller_returned())
}
pub(super) fn retained_bytes(state: &DocumentState) -> Option<usize> {
    let s = &state.agent_tool_setup;
    let mut n = std::mem::size_of::<State>()
        .checked_add(p::CONSENT_LIMIT * (std::mem::size_of::<Id>() + 32))?
        .checked_add(2 * p::STATUS_LIMIT)?;
    if let Some(p) = &s.pending {
        n = n
            .checked_add(p.approval.bytes()?)?
            .checked_add(std::mem::size_of::<Pending>() + 32)?;
    }
    if let Some(g) = &s.grant {
        n = n
            .checked_add(grant_cells_bytes(
                g.native.runtime_id.capacity(),
                g.native.canonical_root.capacity(),
            )?)?
            .checked_add(g.binding.bytes()?)?;
    }
    Some(n)
}

#[cfg(test)]
#[path = "asset_session_agent_tool_setup_tests.rs"]
mod tests;
impl DocumentBinding {
    fn tool_setup_document_bytes(&self, state: &DocumentState) -> Result<usize, BridgeError> {
        // Same complete Document/picker-independent census, before taking the
        // Edit guard. Neither a successful traversal nor a serialized length
        // is itself a capacity admission.
        #[cfg(any(
            all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
            all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )
        ))]
        {
            let bytes = lookup_memory::retained_document_bytes(&self.inner, state)
                .map_err(|_| public(Error::Busy))?;
            let extras = installation_memory::additional_document_bytes(self, state)
                .map_err(|_| public(Error::Busy))?;
            document_fits(
                bytes
                    .checked_add(extras)
                    .ok_or_else(|| public(Error::Busy))?,
            )
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
            Err(public(Error::Unavailable))
        }
    }
    pub(super) fn tool_setup_admission_current(
        &self,
        s: &DocumentState,
        e: &Arc<req::Entry>,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
    ) -> Result<(), BridgeError> {
        let g = s
            .agent_tool_setup
            .grant
            .as_ref()
            .filter(|g| Arc::ptr_eq(&g.scope, e.scope()))
            .ok_or_else(|| public(Error::Conflict))?;
        self.tool_setup_scope_current(s, g, edit)?;
        g.scope.current(false, Instant::now()).map_err(public)
    }
    pub(super) fn tool_setup_admission_guard<'a>(
        &'a self,
        s: &DocumentState,
        e: &Arc<req::Entry>,
    ) -> Result<crate::edit_owner::SavedEditGuard<'a>, BridgeError> {
        // Keep this SAME guard through the original Doctor admission. A check
        // before releasing Doc would not protect the subsequent lookup/GO.
        self.tool_setup_document_bytes(s)?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        self.tool_setup_admission_current(s, e, &edit)?;
        Ok(edit)
    }

    fn tool_setup_gate(&self, s: &DocumentState, k: p::Kind) -> Result<(), BridgeError> {
        self.service_document_gate(s)?;
        let ok = match k {
            p::Kind::Doctor => {
                self.environment_gate(s)
                    == crate::environment_diagnostics_protocol::Availability::Available
            }
            p::Kind::InspectRequirements | p::Kind::InspectSavedRequirements | p::Kind::AcquireMissing => {
                self.tool_acquisition_gate(s)
                    == crate::tool_acquisition_protocol::Availability::Available
            }
            _ => {
                self.android_build_gate(s) == crate::android_build_protocol::Availability::Available
            }
        };
        if ok {
            Ok(())
        } else {
            Err(public(Error::Busy))
        }
    }
    fn tool_setup_scope_current(
        &self,
        s: &DocumentState,
        g: &Grant,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
    ) -> Result<(), BridgeError> {
        self.service_document_gate(s)?;
        if !edit.matches(&g.stamp)
            || !self
                .inner
                .android_registration_control
                .matches_epoch(g.native.input_revision)
            || !Arc::ptr_eq(&g.native.document_identity, &self.inner.session_identity)
        {
            return Err(public(Error::Conflict));
        }
        let (current, root) = self
            .inner
            .bridge
            .native_project(&g.native.runtime_id)
            .map_err(|_| public(Error::Conflict))?;
        if current != g.native.registration_generation
            || root.path != g.native.canonical_root
            || !root
                .identity
                .posix()
                .is_ok_and(|p| p.service_identity() == (g.native.device, g.native.inode))
        {
            return Err(public(Error::Conflict));
        }
        Ok(())
    }
    fn tool_setup_approval(
        &self,
        s: &DocumentState,
        args: &mut Allow,
        now: Instant,
    ) -> Result<(NativeProject, SavedEditStamp, Approval), BridgeError> {
        if !args.review.valid() || args.consent_version != args.review.kind.consent() {
            return Err(BridgeError::invalid());
        }
        self.tool_setup_gate(s, args.review.kind)?;
        let (generation, root) = self
            .inner
            .bridge
            .native_project(&args.project_id)
            .map_err(|_| public(Error::Conflict))?;
        let native = self.service_project_locked(s, &args.project_id)?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        let approval = match args.review.kind {
            p::Kind::Doctor => {
                if args.source_context.is_some()
                    || args.native_consent.is_some()
                    || args.license_acknowledged
                {
                    return Err(BridgeError::invalid());
                }
                let input = crate::environment_diagnostics_protocol::start(
                    &serde_json::json!({"projectId":args.project_id,"draft":args.doctor_draft.take().ok_or_else(BridgeError::invalid)?,
                    "draftRevision":args.review.draft_revision,"baselineGeneration":args.review.baseline_generation,"platform":args.review.platform,"operation":"build"}),
                )?;
                Approval::Doctor(
                    self.inner
                        .bridge
                        .diagnostics
                        .tool_setup_doctor_approval(input, generation, root.path, now)?,
                )
            }
            p::Kind::InspectSavedRequirements => Approval::SavedInspect(self.saved_tool_inspect_approval(s, args, &edit, now)?),
            p::Kind::InspectRequirements | p::Kind::AcquireMissing => {
                if args.doctor_draft.is_some()
                    || args.source_context.is_some()
                    || args.license_acknowledged
                    || args.native_consent.as_deref()
                        != Some(crate::tool_acquisition_protocol::CONSENT)
                {
                    return Err(BridgeError::invalid());
                }
                let a = self
                    .inner
                    .bridge
                    .tool_acquisition
                    .tool_setup_acquisition_approval(
                        args.review.kind,
                        args.review
                            .prepared
                            .as_ref()
                            .ok_or_else(BridgeError::invalid)?,
                    )?;
                if a.project() != args.project_id || !a.matches_root(generation, &root) {
                    return Err(public(Error::Conflict));
                }
                Approval::Acquisition(a)
            }
            p::Kind::InspectPickedSources | p::Kind::RegisterReviewedSources => {
                if args.doctor_draft.is_some() {
                    return Err(BridgeError::invalid());
                }
                let ids = args
                    .review
                    .sources
                    .as_ref()
                    .ok_or_else(BridgeError::invalid)?;
                let context = if args.review.kind == p::Kind::InspectPickedSources {
                    if args.native_consent.is_some() || args.license_acknowledged {
                        return Err(BridgeError::invalid());
                    }
                    let data = serde_json::json!({"schemaVersion":1,"registrationGeneration":ids.registration_generation,"sourceGeneration":ids.source_generation,"context":args.source_context.take().ok_or_else(BridgeError::invalid)?});
                    crate::android_registration_app_protocol::Inspect::parse(
                        &crate::edit_protocol::bounded(&data, 8192)?,
                    )?
                    .context
                } else {
                    let data = serde_json::json!({"schemaVersion":1,"registrationGeneration":ids.registration_generation,"sourceGeneration":ids.source_generation,"reviewId":ids.review_id,
                        "context":args.source_context.take().ok_or_else(BridgeError::invalid)?,"consentVersion":args.native_consent,"licenseAcknowledged":args.license_acknowledged});
                    crate::android_registration_app_protocol::Register::parse(
                        &crate::edit_protocol::bounded(&data, 8192)?,
                    )?
                    .context
                };
                if context.project_id != args.project_id {
                    return Err(BridgeError::invalid());
                }
                let saved = self.validated_saved_input_with_edit(s, &context, &edit)?;
                Approval::Sources(
                    self.inner
                        .bridge
                        .android_build
                        .tool_setup_original()
                        .tool_setup_registration_approval(
                            &self.inner.session_identity,
                            args.review.kind,
                            ids,
                            context,
                            generation,
                            root,
                            &saved,
                            now,
                            self.android_build_gate(s),
                        )?,
                )
            }
        };
        if approval.review() != &args.review {
            return Err(public(Error::Conflict));
        }
        Ok((native, edit.stamp()?, approval))
    }
    pub(crate) fn agent_tool_setup_access(&self, window: &str) -> Result<p::Access, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let state = self.lock();
        match service(&state).map_err(public)? {
            Some(s) => s.tool_setup_requests().access().map_err(public),
            None => Ok(p::Access::empty()),
        }
    }
    pub(crate) fn allow_agent_tool_setup(
        &self,
        window: &str,
        bytes: &[u8],
    ) -> Result<p::Access, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let at = Instant::now();
        let (id, native, stamp, approval) = {
            let mut state = self.lock();
            // Reject a second live input BEFORE decoding its Value. The same
            // Doc lock spans the one bounded RAW decode/approval, so concurrent
            // MAIN invocations cannot retain another typed Doctor draft while
            // waiting behind the pending/active original.
            state.agent_tool_setup.ready().map_err(public)?;
            let mut args: Allow = decode(bytes)?;
            let id = args.consent_id.clone();
            let tuple = self.tool_setup_approval(&state, &mut args, at)?;
            // Exact native inputs retained by this one pending slot through
            // off-lock Host work. No concurrent Allow can create another draft.
            state
                .agent_tool_setup
                .begin(&id, tuple.2.clone())
                .map_err(public)?;
            if self.tool_setup_document_bytes(&state).is_err() {
                state.agent_tool_setup.pending = None;
                return Err(public(Error::Busy));
            }
            (id, tuple.0, tuple.1, tuple.2)
        };
        let result = (|| {
            let service = self
                .inner
                .bridge
                .application_service
                .identity_request_service(&native)
                .map_err(public)?;
            let point = service
                .tool_setup_point(&native.runtime_id, approval.review().kind)
                .map_err(public)?;
            if let Approval::SavedInspect(a) = &approval {
                if !inspect::same_saved_config(a.source().context(), point.saved.config.as_ref()) { return Err(public(Error::Conflict)); }
            }
            let scope = Arc::new(req::NativeScope {
                project_id: point.saved.project_id.clone(),
                runtime_id: native.runtime_id.clone(),
                review_id: Id::random().map_err(public)?,
                review: approval.review().clone(),
                root: native.canonical_root.clone(),
                device: native.device,
                inode: native.inode,
                observation_revision: point.saved.revision,
                saved_config: point.saved.config.clone(),
                expires: approval
                    .expires()
                    .min(point.read.end())
                    .min(at + Duration::from_millis(p::INTENT_MS)),
                read: point.read,
                document: Arc::downgrade(&self.inner.session_identity),
                control: req::Control::new(),
                retired: AtomicBool::new(false),
                changes: self.inner.changes.clone(),
            });
            if !scope.matches(&point.saved) {
                return Err(public(Error::Conflict));
            }
            service
                .tool_setup_requests()
                .can_allow(&id)
                .map_err(public)?;
            if matches!(&approval, Approval::SavedInspect(_)) {
                // Re-read the SAME service SavedPoint/Read before the second
                // Doc cut. The lane below must still be the original Arc;
                // neither a newer service observation nor equal new bytes
                // can silently replace the approved source.
                service.tool_setup_current(&scope).map_err(public)?;
            }
            let mut state = self.lock();
            self.tool_setup_gate(&state, scope.review.kind)?;
            if !state
                .agent_tool_setup
                .pending
                .as_ref()
                .is_some_and(|p| p.id == id && !p.revoked)
            {
                return Err(public(Error::AccessDenied));
            }
            if let Some(old) = &state.agent_tool_setup.service {
                if old.as_ptr() != Arc::as_ptr(&service) {
                    return Err(public(Error::Conflict));
                }
            }
            let (g, root) = self
                .inner
                .bridge
                .native_project(&native.runtime_id)
                .map_err(|_| public(Error::Conflict))?;
            self.service_allow_current_locked(&state, &native, &stamp)?;
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            let link = req::NativeLink::new(scope.clone());
            let binding = match &approval {
                Approval::Doctor(a) => {
                    if !a.matches_root(g, &root) {
                        return Err(public(Error::Conflict));
                    }
                    NativeBinding::Doctor(
                        self.inner
                            .bridge
                            .diagnostics
                            .bind_tool_setup_doctor(a.clone(), link.clone())?,
                    )
                }
                Approval::Acquisition(a) => {
                    if !a.matches_root(g, &root) {
                        return Err(public(Error::Conflict));
                    }
                    NativeBinding::Acquisition(
                        self.inner
                            .bridge
                            .tool_acquisition
                            .bind_tool_setup_acquisition(a.clone(), link.clone())?,
                    )
                }
                Approval::SavedInspect(a) => {
                    self.tool_inspect_input_current(&state, a.source(), &edit)?;
                    if !inspect::same_saved_config(a.source().context(), scope.saved_config.as_ref()) { return Err(public(Error::Conflict)); }
                    NativeBinding::SavedInspect(self.inner.bridge.tool_acquisition.bind_tool_setup_saved_inspect(a.clone(), link.clone())?)
                }
                Approval::Sources(a) => {
                    if !a.matches_root(g, &root) {
                        return Err(public(Error::Conflict));
                    }
                    let saved = self.validated_saved_input_with_edit(&state, a.context(), &edit)?;
                    NativeBinding::Sources(
                        self.inner
                            .bridge
                            .android_build
                            .tool_setup_original()
                            .bind_tool_setup_registration(a.clone(), link.clone(), &saved)?,
                    )
                }
            };
            let grant = Arc::new(Grant {
                id: id.clone(),
                scope: scope.clone(),
                link,
                binding,
                native,
                stamp,
            });
            state.agent_tool_setup.grant = Some(grant.clone());
            state.agent_tool_setup.service = Some(Arc::downgrade(&service));
            // Transfer the same approval from Pending to Grant under Doc.
            // There is never another draft allocation or a debit refund: the
            // real native Binding keeps its quote until actual retirement.
            state.agent_tool_setup.pending = None;
            drop(edit);
            if let Err(error) = self.tool_setup_document_bytes(&state) {
                self.stop_tool_setup_grant(&grant, p::Reason::NativeRefused, Instant::now());
                return Err(error);
            }
            match service.tool_setup_requests().allow(scope, id.clone()) {
                Ok(a) => Ok(a),
                Err(e) => {
                    self.stop_tool_setup_grant(
                        &grant,
                        p::Reason::PermissionRevoked,
                        Instant::now(),
                    );
                    Err(public(e))
                }
            }
        })();
        let mut state = self.lock();
        if state
            .agent_tool_setup
            .pending
            .as_ref()
            .is_some_and(|p| p.id == id)
        {
            state.agent_tool_setup.pending = None;
        }
        result
    }
    fn stop_tool_setup_grant(&self, g: &Grant, why: p::Reason, at: Instant) {
        match &g.binding {
            NativeBinding::Doctor(b) => self
                .inner
                .bridge
                .diagnostics
                .stop_tool_setup_doctor(b, why, at),
            NativeBinding::Acquisition(b) => self
                .inner
                .bridge
                .tool_acquisition
                .stop_tool_setup_acquisition(b, why, at),
            NativeBinding::SavedInspect(b) => self.inner.bridge.tool_acquisition.stop_tool_setup_saved_inspect(b, why, at),
            NativeBinding::Sources(b) => self
                .inner
                .bridge
                .android_build
                .tool_setup_original()
                .stop_tool_setup_registration(b, why, at),
        }
    }
    pub(crate) fn revoke_agent_tool_setup(
        &self,
        window: &str,
        args: Revoke,
    ) -> Result<p::Access, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let at = Instant::now();
        let mut state = self.lock();
        state
            .agent_tool_setup
            .remember(&args.consent_id)
            .map_err(public)?;
        if let Some(p) = state
            .agent_tool_setup
            .pending
            .as_mut()
            .filter(|p| p.id == args.consent_id)
        {
            p.revoked = true;
        }
        if let Some(g) = state
            .agent_tool_setup
            .grant
            .as_ref()
            .filter(|g| g.id == args.consent_id)
        {
            self.stop_tool_setup_grant(g, p::Reason::PermissionRevoked, at);
        }
        match service(&state).map_err(public)? {
            Some(s) => s
                .tool_setup_requests()
                .revoke(&args.consent_id, at)
                .map_err(public),
            None => Ok(p::Access::empty()),
        }
    }
    pub(crate) fn agent_tool_setup_request_status(
        &self,
        window: &str,
        q: p::Query,
    ) -> Result<p::Status, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let s = service(&self.lock())
            .map_err(public)?
            .ok_or_else(|| public(Error::Unavailable))?;
        s.tool_setup_requests().query(&q, false).map_err(public)
    }
    fn admit_agent_tool_setup(
        &self,
        service: &Arc<ApplicationService>,
        entry: &Arc<req::Entry>,
    ) -> Result<(), BridgeError> {
        let grant = {
            let state = self.lock();
            let grant = state
                .agent_tool_setup
                .grant
                .as_ref()
                .filter(|g| Arc::ptr_eq(&g.scope, entry.scope()))
                .cloned()
                .ok_or_else(|| public(Error::Conflict))?;
            // Link the exact claimed Entry even if the following admission
            // census refuses. Its genuine returned no-effect callback must not
            // remain only in a cache while the already-claimed row waits.
            grant.link.attach(entry).map_err(public)?;
            self.tool_setup_document_bytes(&state)?;
            grant
        };
        if grant.scope.retired.load(Ordering::Acquire) {
            return Ok(());
        }
        entry.current().map_err(public)?;
        let original = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&grant.native)
            .map_err(public)?;
        if !Arc::ptr_eq(service, &original) {
            return Err(public(Error::Conflict));
        }
        service.tool_setup_current(&grant.scope).map_err(public)?;
        // First Doc cut and exact fixed copied input. Source Snapshot is made
        // NOW at original submitted_at, never at Allow or from a public report.
        match &grant.binding {
            NativeBinding::Doctor(b) => {
                let (ticket, input) = self
                    .inner
                    .bridge
                    .diagnostics
                    .tool_setup_doctor_input(b, entry)?;
                {
                    let state = self.lock();
                    let edit = self
                        .inner
                        .bridge
                        .edits
                        .saved_registration_guard(&self.inner.session_identity)?;
                    self.tool_setup_scope_current(&state, &grant, &edit)?;
                }
                self.admit_environment_diagnostics(ticket, input, Some(entry))
                    .map(|_| ())
            }
            NativeBinding::Acquisition(_) => {
                {
                    let state = self.lock();
                    let edit = self
                        .inner
                        .bridge
                        .edits
                        .saved_registration_guard(&self.inner.session_identity)?;
                    self.tool_setup_scope_current(&state, &grant, &edit)?;
                }
                let ids = grant
                    .scope
                    .review
                    .prepared
                    .as_ref()
                    .ok_or_else(BridgeError::invalid)?;
                let input = crate::tool_acquisition_protocol::start(
                    &serde_json::json!({"operationId":ids.operation_id,"ownerGeneration":ids.owner_generation,"consentVersion":crate::tool_acquisition_protocol::CONSENT}),
                )?;
                self.start_tool_acquisition_agent(input, entry.submitted_at(), Some(entry))
                    .map(|_| ())
            }
            NativeBinding::SavedInspect(b) => self.admit_saved_tool_inspect(b, entry),
            NativeBinding::Sources(b) => {
                let snapshot = {
                    let state = self.lock();
                    self.tool_setup_gate(&state, grant.scope.review.kind)?;
                    let edit = self
                        .inner
                        .bridge
                        .edits
                        .saved_registration_guard(&self.inner.session_identity)?;
                    self.tool_setup_scope_current(&state, &grant, &edit)?;
                    let context = b.context();
                    let saved = self.validated_saved_input_with_edit(&state, context, &edit)?;
                    let (g, root) = self
                        .inner
                        .bridge
                        .native_project(&context.project_id)
                        .map_err(|_| public(Error::Conflict))?;
                    self.inner
                        .bridge
                        .android_build
                        .tool_setup_original()
                        .tool_setup_registration_snapshot(
                            b,
                            entry,
                            &self.inner.session_identity,
                            g,
                            root,
                            saved,
                            self.android_build_gate(&state),
                        )?
                };
                self.admit_checked_android_registration_agent(
                    snapshot.check_originals()?,
                    Some(entry),
                )
                .map(|_| ())
            }
        }
    }
    fn check_tool_setup_original(&self) {
        let state = self.lock();
        let Some(g) = state.agent_tool_setup.grant.as_ref() else {
            return;
        };
        if g.scope.retired.load(Ordering::Acquire) {
            return;
        }
        let now = Instant::now();
        let current = (|| {
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            self.tool_setup_scope_current(&state, g, &edit)
        })();
        if current.is_err() {
            self.stop_tool_setup_grant(g, p::Reason::ContextChanged, now);
        } else if let Some((why, at)) = g.link.stop_at(now) {
            self.stop_tool_setup_grant(g, why, at);
        }
    }
    pub(crate) fn service_tool_setup_tick(&self) {
        let Ok(Some(s)) = service(&self.lock()) else {
            return;
        };
        self.check_tool_setup_original();
        match s.tool_setup_requests().claim() {
            Ok(Some(claim)) => {
                let result = self.admit_agent_tool_setup(&s, claim.entry());
                let entry = claim.entry().clone();
                claim.returned(); // Only the actual caller, never native-final.
                if result.is_err() {
                    entry.cancel(p::Reason::NativeRefused, Instant::now());
                    let state = self.lock();
                    if let Some(g) = state
                        .agent_tool_setup
                        .grant
                        .as_ref()
                        .filter(|g| Arc::ptr_eq(&g.scope, entry.scope()))
                    {
                        self.stop_tool_setup_grant(g, p::Reason::NativeRefused, Instant::now());
                    } else {
                        entry.unknown(p::Reason::CleanupUnknown);
                    }
                }
            }
            Ok(None) => {}
            Err(_) => s.tool_setup_requests().fence(),
        };
        let _ = flush(&s);
    }
    pub(crate) fn agent_tool_setup_relay_lost(&self) {
        let mut state = self.lock();
        state.agent_tool_setup.lost = true;
        if let Ok(Some(s)) = service(&state) {
            s.tool_setup_requests().fence();
        }
    }
    pub(super) fn stop_tool_setup_locked(
        &self,
        state: &mut DocumentState,
        reason: p::Reason,
        at: Instant,
    ) {
        if let Some(p) = &mut state.agent_tool_setup.pending {
            p.revoked = true;
        }
        if let Some(g) = &state.agent_tool_setup.grant {
            self.stop_tool_setup_grant(g, reason, at);
        }
    }
    pub(crate) fn drain_agent_tool_setup_for_exit(&self) {
        let state = self.lock();
        let s = service(&state);
        drop(state);
        if let Ok(Some(s)) = s {
            let _ = flush(&s);
            s.tool_setup_requests().close(Instant::now());
        }
    }
}
fn flush(service: &ApplicationService) -> Result<(), Error> {
    struct Return<'a> {
        service: &'a ApplicationService,
        known: bool,
    }
    impl Drop for Return<'_> {
        fn drop(&mut self) {
            if !self.known {
                self.service.fence_native_history();
            }
        }
    }
    let mut returned = Return {
        service,
        known: false,
    };
    service.native_history_current()?;
    for e in service.tool_setup_requests().entries()? {
        let Some(h) = e.claim_history()? else {
            continue;
        };
        let id = h
            .data
            .operation
            .as_ref()
            .map_or_else(|| e.origin().request_id.clone(), |o| o.operation_id.clone());
        let result = if h.first {
            service.begin_operation(
                &e.scope().runtime_id,
                id,
                e.scope().review.kind.action(),
                h.data.state,
                h.settlement(),
            )
        } else {
            service.publish_operation(
                &e.scope().runtime_id,
                id,
                e.scope().review.kind.action(),
                h.data.state,
                h.settlement(),
            )
        };
        h.returned(result)?;
    }
    service.native_history_current()?;
    returned.known = true;
    Ok(())
}
