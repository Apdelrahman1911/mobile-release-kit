//! MAIN-only preparation of the actual selected Apple inputs. IPC queues only
//! addresses; the existing main Webview invokes the existing async RAW caller.
use super::*;
use crate::{
    apple_provisioning_protocol as wire,
    saved_command_owner::{AgentApplePrepareLink, AgentApplePrepareSelection},
    service_apple_provisioning_prepare_protocol as data,
    service_apple_provisioning_requests::preparation as request,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Allow {
    intent: String,
    consent_id: Id,
    consent_version: String,
    selection: Value,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Address {
    intent: String,
    origin: p::Query,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Revoke {
    intent: String,
    consent_id: Id,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessRequest {
    intent: String,
}
pub(crate) fn access_request(v: Value) -> Result<(), BridgeError> {
    let a: AccessRequest = decode_value(v)?;
    if a.intent != "preparation" {
        return Err(wire::invalid());
    }
    Ok(())
}
pub(crate) fn decode_value<T: serde::de::DeserializeOwned>(v: Value) -> Result<T, BridgeError> {
    crate::edit_protocol::bounded(&v, wire::IPC_LIMIT)?;
    serde_json::from_value(v).map_err(|_| wire::invalid())
}
pub(crate) fn address(v: Value) -> Result<p::Query, BridgeError> {
    let a: Address = decode_value(v)?;
    if a.intent != "agent-apple-prepare" {
        return Err(wire::invalid());
    }
    Ok(a.origin)
}
pub(in crate::asset_session) struct Grant {
    nonce: Id,
    scope: Arc<request::Scope>,
    context: wire::Context,
    selection: Arc<AgentApplePrepareSelection>,
    material: store_material::ApplePreparationMaterial,
    native: NativeProject,
    stamp: SavedEditStamp,
}
/// Same Document original call slot for ordinary and delegated Prepare. No
/// Drop can clear it. A lost future leaves the actual caller/ticket fenced.
pub(in crate::asset_session) struct CallOriginal {
    returned: AtomicBool,
    unknown: AtomicBool,
    entry: Option<Arc<request::Entry>>,
    ticket: Mutex<Option<Arc<crate::application_service_host::NativeStateTicket>>>,
    finish_attempted: AtomicBool,
    finish_returned: AtomicBool,
    cancel_requested: AtomicBool,
}
pub(in crate::asset_session) struct Original {
    held: Arc<CallOriginal>,
    returned: bool,
}
impl Original {
    pub(in crate::asset_session) fn ticket(
        &self,
        ticket: Arc<crate::application_service_host::NativeStateTicket>,
    ) -> Result<(), BridgeError> {
        let mut slot = self
            .held
            .ticket
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if slot.is_some() {
            return Err(BridgeError::cleanup_unknown());
        }
        *slot = Some(ticket);
        Ok(())
    }
    pub(in crate::asset_session) fn finishing(&self) {
        self.held.finish_attempted.store(true, Ordering::Release);
    }
    pub(in crate::asset_session) fn finished(&self) {
        self.held.finish_returned.store(true, Ordering::Release);
    }
    pub(in crate::asset_session) fn returned(mut self) {
        // Returning from the async caller is not a successful Host finish. Keep
        // its ticket/slot fenced if no positive original finish returned.
        if self.held.ticket.lock().map_or(true, |v| {
            v.is_some() && !self.held.finish_returned.load(Ordering::Acquire)
        }) {
            self.held.unknown.store(true, Ordering::Release);
            if let Some(e) = &self.held.entry {
                e.unknown(p::Reason::CleanupUnknown);
            }
        }
        self.held.returned.store(true, Ordering::Release);
        self.returned = true;
    }
}
impl Drop for Original {
    fn drop(&mut self) {
        if !self.returned {
            self.held.unknown.store(true, Ordering::Release);
            if let Some(e) = &self.held.entry {
                e.unknown(p::Reason::CleanupUnknown);
            }
        }
    }
}
pub(in crate::asset_session) fn call_pending(state: &State) -> bool {
    state
        .call
        .as_ref()
        .is_some_and(|c| !c.returned.load(Ordering::Acquire) || c.unknown.load(Ordering::Acquire))
}
pub(in crate::asset_session) fn occupies(state: &State) -> bool {
    call_pending(state) || state.prepare.as_ref().is_some_and(|g| !g.scope.released())
}
pub(in crate::asset_session) fn matches_handoff(state: &State, e: &Arc<request::Entry>) -> bool {
    !call_pending(state)
        && state
            .prepare
            .as_ref()
            .is_some_and(|g| Arc::ptr_eq(&g.scope, &e.scope))
        && e.current_ready()
}
impl DocumentBinding {
    pub(in crate::asset_session) fn apple_prepare_original(
        &self,
        entry: Option<&Arc<request::Entry>>,
    ) -> Result<Original, BridgeError> {
        let mut state = self.lock();
        if call_pending(&state.agent_apple)
            || state
                .agent_apple
                .grant
                .as_ref()
                .is_some_and(|g| !g.scope.retired.load(Ordering::Acquire))
            || match (state.agent_apple.prepare.as_ref(), entry) {
                (Some(g), Some(e)) => !Arc::ptr_eq(&g.scope, &e.scope),
                (Some(g), None) => !g.scope.released(),
                (None, Some(_)) => true,
                _ => false,
            }
        {
            return Err(public(Error::Busy));
        }
        let held = Arc::new(CallOriginal {
            returned: AtomicBool::new(false),
            unknown: AtomicBool::new(false),
            entry: entry.cloned(),
            ticket: Mutex::new(None),
            finish_attempted: AtomicBool::new(false),
            finish_returned: AtomicBool::new(false),
            cancel_requested: AtomicBool::new(false),
        });
        state.agent_apple.call = Some(held.clone());
        Ok(Original {
            held,
            returned: false,
        })
    }
    fn prepare_grant_current(
        &self,
        state: &DocumentState,
        g: &Grant,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
    ) -> Result<(), BridgeError> {
        self.service_document_gate(state)?;
        if state.retiring
            || state.quit_pending
            || state.lock_pending
            || !state.agent_apple.current(&g.nonce)
            || !edit.matches(&g.stamp)
            || !self
                .inner
                .android_registration_control
                .matches_epoch(g.native.input_revision)
            || !Arc::ptr_eq(&g.native.document_identity, &self.inner.session_identity)
        {
            return Err(public(Error::Conflict));
        }
        let (registration, root) = self
            .inner
            .bridge
            .native_project(&g.context.project_id)
            .map_err(|_| public(Error::Conflict))?;
        if registration != g.native.registration_generation
            || root.path != g.native.canonical_root
            || !root
                .identity
                .posix()
                .is_ok_and(|v| v.service_identity() == (g.native.device, g.native.inode))
        {
            return Err(public(Error::Conflict));
        }
        let material =
            self.review_apple_provisioning_material(state, &g.context, registration, &root)?;
        if !g.material.matches(&material) {
            return Err(public(Error::Conflict));
        }
        self.apple_provisioning_saved_input(state, &g.context, registration, &root, edit)?;
        g.scope.current(Instant::now()).map_err(public)
    }
    pub(crate) fn allow_agent_apple_prepare(
        &self,
        window: &str,
        args: Allow,
    ) -> Result<data::Access, BridgeError> {
        if window != MAIN || args.intent != "preparation" || args.consent_version != data::CONSENT {
            return Err(wire::invalid());
        }
        let input = wire::prepare(&args.selection)?;
        let mode = crate::saved_command_owner::agent_apple_mode(input.context.mode)?;
        let (native, stamp, selection, material) = {
            let mut state = self.lock();
            self.service_document_gate(&state)?;
            state
                .agent_apple
                .reserve(&args.consent_id)
                .map_err(public)?;
            if occupies(&state.agent_apple)
                || state
                    .agent_apple
                    .grant
                    .as_ref()
                    .is_some_and(|g| !g.scope.retired.load(Ordering::Acquire))
                || self.apple_provisioning_gate(&state) != wire::Availability::Available
            {
                return Err(public(Error::Busy));
            }
            let selection = self
                .inner
                .bridge
                .apple_provisioning
                .apple_prepare_selection(&input.context)?;
            let native = self.service_project_locked(&state, &input.context.project_id)?;
            let (registration, root) = self
                .inner
                .bridge
                .native_project(&input.context.project_id)
                .map_err(|_| public(Error::Conflict))?;
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            self.apple_provisioning_saved_input(
                &state,
                &input.context,
                registration,
                &root,
                &edit,
            )?;
            let current = self.review_apple_provisioning_material(
                &state,
                &input.context,
                registration,
                &root,
            )?;
            let future = crate::saved_command_owner::apple_provisioning_document_backing_bytes(
                input.context.mode,
            )
            .ok_or_else(wire::invalid)?;
            lookup_memory::store_admission_bytes(&self.inner, &state, &current, future)
                .map_err(|_| public(Error::Busy))?;
            (
                native,
                edit.stamp()?,
                selection,
                current.apple_preparation_material()?,
            )
        };
        let service = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&native)
            .map_err(public)?;
        let point = service
            .apple_provisioning_point(&native.runtime_id)
            .map_err(public)?;
        if !point.saved.config.as_ref().is_some_and(|c| {
            c.bytes == input.context.saved_config.bytes
                && c.sha256 == input.context.saved_config.sha256
        }) {
            return Err(public(Error::Conflict));
        }
        let scope = request::Scope::new(
            point.saved,
            Id::random().map_err(public)?,
            mode,
            selection.expires().min(point.read.end()),
            point.read,
            Arc::downgrade(&self.inner.session_identity),
            selection.witness(),
            self.inner.changes.clone(),
        )
        .map_err(public)?;
        let grant = Arc::new(Grant {
            nonce: args.consent_id,
            scope,
            context: input.context,
            selection,
            material,
            native,
            stamp,
        });
        let mut state = self.lock();
        if occupies(&state.agent_apple)
            || state
                .agent_apple
                .grant
                .as_ref()
                .is_some_and(|g| !g.scope.retired.load(Ordering::Acquire))
            || self.apple_provisioning_gate(&state) != wire::Availability::Available
        {
            return Err(public(Error::Busy));
        }
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        self.prepare_grant_current(&state, &grant, &edit)?;
        if let Some(old) = self.inner.agent_apple_service.get() {
            if old.as_ptr() != Arc::as_ptr(&service) {
                return Err(public(Error::Conflict));
            }
        } else {
            self.inner
                .agent_apple_service
                .set(Arc::downgrade(&service))
                .map_err(|_| public(Error::StateUnknown))?;
        }
        // Native gate retained before the grant becomes visible to the service.
        state.agent_apple.prepare = Some(grant.clone());
        match service
            .apple_provisioning_requests()
            .allow_preparation(grant.scope.clone(), grant.nonce.clone())
        {
            Ok(v) => Ok(v),
            Err(e) => {
                grant
                    .scope
                    .stop(p::Reason::PermissionRevoked, Instant::now());
                grant.scope.retired();
                Err(public(e))
            }
        }
    }
    pub(crate) fn agent_apple_prepare_access(
        &self,
        window: &str,
    ) -> Result<data::Access, BridgeError> {
        if window != MAIN {
            return Err(wire::invalid());
        }
        match self.agent_apple_service()? {
            Some(s) => s
                .apple_provisioning_requests()
                .preparation_access()
                .map_err(public),
            None => Ok(data::Access::empty()),
        }
    }
    pub(crate) fn revoke_agent_apple_prepare(
        &self,
        window: &str,
        args: Revoke,
    ) -> Result<data::Access, BridgeError> {
        if window != MAIN || args.intent != "preparation" {
            return Err(wire::invalid());
        }
        let mut state = self.lock();
        state
            .agent_apple
            .withdraw(&args.consent_id)
            .map_err(public)?;
        if let Some(g) = state
            .agent_apple
            .prepare
            .as_ref()
            .filter(|g| g.nonce == args.consent_id)
        {
            g.scope.stop(p::Reason::PermissionRevoked, Instant::now());
        }
        match self.agent_apple_service()? {
            Some(s) => s
                .apple_provisioning_requests()
                .withdraw_preparation(&args.consent_id, Instant::now())
                .map_err(public),
            None => Ok(data::Access::empty()),
        }
    }
    pub(crate) fn agent_apple_preparation_status(
        &self,
        window: &str,
        q: &p::Query,
    ) -> Result<data::Status, BridgeError> {
        if window != MAIN {
            return Err(wire::invalid());
        }
        self.agent_apple_service()?
            .ok_or_else(|| public(Error::Unavailable))?
            .apple_provisioning_requests()
            .preparation(q)
            .map_err(public)?
            .status()
            .map_err(public)
    }
    pub(crate) async fn prepare_agent_apple(
        &self,
        window: &str,
        q: p::Query,
        app_data: &std::path::Path,
    ) -> Result<wire::Status, BridgeError> {
        if window != MAIN {
            return Err(wire::invalid());
        }
        let service = self
            .agent_apple_service()?
            .ok_or_else(|| public(Error::Unavailable))?;
        let entry = service
            .apple_provisioning_requests()
            .preparation(&q)
            .map_err(public)?;
        let call = entry.begin().map_err(public)?; // one actual MAIN caller, BEFORE Host/source work
        let result = async {
            let grant = {
                let state = self.lock();
                let g = state
                    .agent_apple
                    .prepare
                    .as_ref()
                    .filter(|g| Arc::ptr_eq(&g.scope, &entry.scope))
                    .cloned()
                    .ok_or_else(|| public(Error::Conflict))?;
                let edit = self
                    .inner
                    .bridge
                    .edits
                    .saved_registration_guard(&self.inner.session_identity)?;
                self.prepare_grant_current(&state, &g, &edit)?;
                g
            };
            service.apple_preparation_current(&entry).map_err(public)?; // OFF Doc/Edit
            let link = AgentApplePrepareLink::new(entry.clone(), grant.selection.clone())?;
            self.prepare_apple_provisioning_origin(
                wire::Prepare {
                    context: grant.context.clone(),
                },
                app_data,
                Some(link),
            )
            .await
        }
        .await;
        let refused = call.returned(result.is_ok()).map_err(public)?; // real native body return, not status DATA
        if refused && result.is_err() {
            // Only the original positively never-entered/no-Prepared cut may
            // return its ordinary snapshot instead of an ambiguous IPC error.
            // Exact Query + history still reports Refused, never Prepared.
            self.status_apple_provisioning()
        } else {
            result
        }
    }
    pub(in crate::asset_session) fn agent_apple_prepare_current(
        &self,
        state: &DocumentState,
        link: &AgentApplePrepareLink,
        material: &Arc<SelectedStoreMaterial>,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
    ) -> Result<(), BridgeError> {
        let g = state
            .agent_apple
            .prepare
            .as_ref()
            .filter(|g| Arc::ptr_eq(&g.scope, &link.entry.scope))
            .ok_or_else(|| public(Error::Conflict))?;
        self.prepare_grant_current(state, g, edit)?;
        if !g.material.matches(material) {
            return Err(public(Error::Conflict));
        }
        link.entry.current().map_err(public)
    }
    pub(in crate::asset_session) fn apple_prepare_tick(
        &self,
        service: &ApplicationService,
    ) -> Result<(), Error> {
        {
            let state = self.lock();
            if let Some(g) = &state.agent_apple.prepare {
                if !g.scope.released() {
                    let current = self
                        .inner
                        .bridge
                        .edits
                        .saved_registration_guard(&self.inner.session_identity)
                        .and_then(|edit| self.prepare_grant_current(&state, g, &edit));
                    if current.is_err() {
                        g.scope.stop(p::Reason::ContextChanged, Instant::now());
                    }
                }
            }
            if let Some(c) = &state.agent_apple.call {
                if let Some(e) = &c.entry {
                    if !c.returned.load(Ordering::Acquire)
                        && e.current().is_err()
                        && !c.finish_attempted.load(Ordering::Acquire)
                    {
                        if let Ok(ticket) = c.ticket.try_lock() {
                            if let Some(ticket) = ticket.as_ref() {
                                if !c.cancel_requested.swap(true, Ordering::AcqRel)
                                    && self
                                        .inner
                                        .bridge
                                        .application_service
                                        .cancel_native_state_ticket(ticket)
                                        .is_err()
                                {
                                    c.unknown.store(true, Ordering::Release);
                                    e.unknown(p::Reason::CleanupUnknown);
                                }
                            }
                        }
                    }
                }
            }
        }
        service.native_history_current()?;
        for e in service
            .apple_provisioning_requests()
            .preparation_entries()?
        {
            if let Some((reason, at)) = e.scope.first()? {
                self.inner
                    .bridge
                    .apple_provisioning
                    .stop_apple_prepare(&e, reason, at);
            }
            if let Some(history) = e.claim_history()? {
                let result = service.begin_operation(
                    &e.scope.project.runtime_id,
                    e.origin().request_id.clone(),
                    crate::service_protocol::Action::ObserveProject,
                    if history.refused {
                        crate::service_protocol::OperationState::Failed
                    } else {
                        crate::service_protocol::OperationState::Succeeded
                    },
                    crate::service_protocol::Settlement::Settled,
                );
                if let Err(error) = history.returned(result) {
                    service.fence_native_history();
                    return Err(error);
                }
            }
            self.inner
                .bridge
                .apple_provisioning
                .publish_apple_prepare(&e)
                .map_err(|_| Error::StateUnknown)?;
        }
        service.native_history_current()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(c: char) -> Id {
        Id::parse(&c.to_string().repeat(32)).unwrap()
    }
    fn caller() -> (State, Original) {
        let held = Arc::new(CallOriginal {
            returned: AtomicBool::new(false),
            unknown: AtomicBool::new(false),
            entry: None,
            ticket: Mutex::new(None),
            finish_attempted: AtomicBool::new(false),
            finish_returned: AtomicBool::new(false),
            cancel_requested: AtomicBool::new(false),
        });
        let mut state = State::default();
        state.call = Some(held.clone());
        (
            state,
            Original {
                held,
                returned: false,
            },
        )
    }
    #[test]
    fn preparation_actual_caller_drop_and_unknown_cannot_be_replaced_by_status() {
        let (state, original) = caller();
        assert!(call_pending(&state));
        original.finishing();
        assert!(call_pending(&state));
        drop(original);
        assert!(call_pending(&state));
        let c = state.call.as_ref().unwrap();
        assert!(c.unknown.load(Ordering::Acquire));
        assert!(!c.returned.load(Ordering::Acquire));
        let (state, original) = caller();
        original.returned();
        assert!(!call_pending(&state)); // positively no Host ticket
        let (state, original) = caller();
        original.held.unknown.store(true, Ordering::Release);
        original.returned();
        assert!(call_pending(&state));
    }
    #[test]
    fn preparation_fixed_raw_ids_and_shared_nonce_tombstone_do_not_grant_start() {
        let value = serde_json::json!({"intent":"agent-apple-prepare","origin":{"projectId":id('1'),"serviceInstance":id('2'),"requestId":id('3')}});
        assert!(address(value.clone()).is_ok());
        for key in [
            "context",
            "scope",
            "path",
            "password",
            "recordId",
            "consentVersion",
        ] {
            let mut v = value.clone();
            v[key] = serde_json::json!("not permitted");
            assert!(address(v).is_err());
        }
        let mut wrong = value;
        wrong["intent"] = serde_json::json!("agent-apple-start");
        assert!(address(wrong).is_err());
        let mut state = State::default();
        state.withdraw(&id('4')).unwrap();
        assert!(state.reserve(&id('4')).is_err());
        state.reserve(&id('5')).unwrap();
        assert!(state.current(&id('5')) && !state.current(&id('4')));
        assert!(state.grant.is_none() && state.prepare.is_none() && state.call.is_none());
    }
    #[test]
    fn preparation_actual_single_grant_call_and_context_metadata_fit_original_ancillary() {
        // Exact inline cells plus bounded copied metadata: four Context/RAW
        // slots (8KiB each), four4096-byte root/runtime comparisons, four8KiB
        // relay/history/status slots, SAME32 nonce cells and Arc/watch scratch.
        // Private inputs, Ready/source/journal and all32 rows remain in their
        // original independent census; none is refunded by this calculation.
        let bytes = std::mem::size_of::<Grant>()
            + std::mem::size_of::<super::super::Grant>()
            + std::mem::size_of::<CallOriginal>()
            + std::mem::size_of::<Original>()
            + std::mem::size_of::<State>()
            + std::mem::size_of::<AgentApplePrepareSelection>()
            + std::mem::size_of::<AgentApplePrepareLink>()
            + std::mem::size_of::<crate::application_service_host::NativeStateTicket>()
            + 4 * wire::IPC_LIMIT
            + 4 * (4096 + 64)
            + 4 * p::STATUS_LIMIT
            + p::REQUEST_LIMIT * (std::mem::size_of::<super::super::Nonce>() + 32)
            + 8 * 256;
        println!(
            "Apple Prepare actual ancillary={} existing128KiB={}",
            bytes,
            128 * 1024
        );
        assert!(bytes <= 128 * 1024);
        assert_eq!(
            p::DOCUMENT_BACKING,
            p::REQUEST_LIMIT * p::ROW_BACKING + 128 * 1024
        );
    }
}
