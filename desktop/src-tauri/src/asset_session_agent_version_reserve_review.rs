//! Genuine MAIN -> existing Review/SOURCE. The service holds only DATA and
//! never opens a window, reconstructs a source witness or starts an allocator.
use super::*;
use crate::{
    service_version_reserve_review_protocol as r, service_version_reserve_review_requests::Entry,
};
use std::sync::OnceLock;

pub(in crate::asset_session) struct Link {
    pub(in crate::asset_session) entry: Arc<Entry>,
    native: NativeProject,
    pub(in crate::asset_session) id: String,
    source: OnceLock<Weak<version_allocation::Lane>>,
}
impl Link {
    pub(in crate::asset_session) fn current(&self, lane: &Arc<version_allocation::Lane>) -> bool {
        self.entry.admitting()
            && self
                .source
                .get()
                .and_then(Weak::upgrade)
                .is_some_and(|v| Arc::ptr_eq(&v, lane))
    }
    pub(in crate::asset_session) fn source_returned(&self) -> bool {
        self.source
            .get()
            .and_then(Weak::upgrade)
            .is_some_and(|v| v.returned())
    }
    pub(in crate::asset_session) fn known_unentered(&self) -> bool {
        self.source.get().is_none()
    }
}
pub(in crate::asset_session) fn pending(state: &DocumentState) -> bool {
    state
        .version_reserve
        .agent
        .review_pending
        .as_ref()
        .is_some_and(|l| l.entry.pending())
}
pub(in crate::asset_session) fn admission(
    state: &DocumentState,
    link: &Arc<Link>,
) -> Result<(), BridgeError> {
    let agent = &state.version_reserve.agent;
    if agent.relay_lost
        || agent.pending.as_ref().is_some_and(|e| e.pending())
        || agent
            .review_pending
            .as_ref()
            .is_none_or(|v| !Arc::ptr_eq(v, link))
        || !link.entry.admitting()
        || state
            .version_reserve
            .review
            .as_ref()
            .is_some_and(|r| Instant::now() < r.end)
        || service(state)?.is_none_or(|s| {
            s.native_history_current().is_err()
                || s.version_reserve_requests()
                    .blocks_review_except(Some(&link.entry))
                    .unwrap_or(true)
        })
    {
        return Err(p::refused());
    }
    Ok(())
}
/// Called with the installed ORIGINAL Doc/Source lane before Supervisor start.
pub(in crate::asset_session) fn bind(
    state: &mut DocumentState,
    lane: &Arc<version_allocation::Lane>,
) -> Result<(), BridgeError> {
    let Some(link) = &lane.review else {
        return Ok(());
    };
    admission(state, link)?;
    if link.source.set(Arc::downgrade(lane)).is_err() {
        link.entry.unknown();
        return Err(BridgeError::cleanup_unknown());
    }
    link.entry.bind(&link.id).map_err(public)?;
    state.version_reserve.review = None; // Only absent/expired, checked above.
    state.version_reserve.reading = Some((link.id.clone(), lane.clone()));
    state.version_reserve.view.phase = p::Phase::Reading;
    state.version_reserve.view.reason = "none";
    state.version_reserve.view.project_id = Some(link.native.runtime_id.clone());
    state.version_reserve.view.operation_id = Some(link.id.clone());
    state.version_reserve.view.review = None;
    state.version_reserve.view.reservation = None;
    state.version_reserve.bump();
    Ok(())
}
fn same_saved(
    a: &crate::agent_identity_requests::SavedPoint,
    b: &crate::agent_identity_requests::SavedPoint,
) -> bool {
    a.project_id == b.project_id
        && a.runtime_id == b.runtime_id
        && a.root == b.root
        && (a.device, a.inode) == (b.device, b.inode)
        && a.revision == b.revision
        && a.revision != 0
        && a.fresh
        && b.fresh
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Start {
    intent: String,
    origin: r::Query,
}
pub(crate) fn start_request(v: Value) -> Result<r::Query, BridgeError> {
    r::bounded(&v, r::REQUEST_BYTES).map_err(public)?;
    let v: Start = serde_json::from_value(v).map_err(|_| BridgeError::invalid())?;
    if v.intent != "agent-version-reserve-review" {
        return Err(BridgeError::invalid());
    }
    Ok(v.origin)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Status {
    #[serde(deserialize_with = "nullable")]
    origin: Option<r::Query>,
}
fn nullable<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<r::Query>, D::Error> {
    Option::deserialize(d)
}
pub(crate) fn status_request(bytes: &[u8]) -> Result<Option<r::Query>, BridgeError> {
    if bytes.is_empty() || bytes.len().saturating_add(96) > r::REQUEST_BYTES {
        return Err(BridgeError::invalid());
    }
    let v = crate::protocol::strict_json(bytes)?;
    Ok(serde_json::from_value::<Status>(v)
        .map_err(|_| BridgeError::invalid())?
        .origin)
}
impl DocumentBinding {
    fn reserve_review_service(&self) -> Result<Arc<ApplicationService>, BridgeError> {
        self.inner
            .bridge
            .application_service
            .configuration_service()
            .map_err(public)
    }
    pub(crate) fn agent_version_reserve_review_status(
        &self,
        window: &str,
        q: Option<&r::Query>,
    ) -> Result<Option<r::Status>, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        self.reserve_review_service()?
            .version_reserve_requests()
            .review_status(q, false)
            .map_err(public)
    }
    pub(crate) fn cancel_agent_version_reserve_review(
        &self,
        window: &str,
        q: &r::Query,
    ) -> Result<Option<r::Status>, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let service = self.reserve_review_service()?;
        // This is only the exact read entry. It cannot stop a later Reserve.
        let result = service
            .version_reserve_requests()
            .review_status(Some(q), true)
            .map_err(public);
        self.inner.changes.send_modify(|_| {});
        result
    }
    fn review_entry_native(
        &self,
        state: &DocumentState,
        entry: &Arc<Entry>,
        service: &Arc<ApplicationService>,
    ) -> Result<NativeProject, BridgeError> {
        self.passive_query_gate_locked(state, &self.inner.bridge)?;
        if self.github_gate(state) != GitHubReason::None
            || !self.inner.bridge.supervisor.can_exit()
            || version_allocation::pending(state)
            || state
                .version_reserve
                .review
                .as_ref()
                .is_some_and(|r| Instant::now() < r.end)
            || state.version_reserve.agent.relay_lost
            || state
                .version_reserve
                .agent
                .pending
                .as_ref()
                .is_some_and(|e| e.pending())
            || pending(state)
            || service
                .version_reserve_requests()
                .blocks_review_except(Some(entry))
                .map_err(public)?
            || entry.stop_at(Instant::now()).map_err(public)?.is_some()
        {
            return Err(p::refused());
        }
        service.native_history_current().map_err(public)?;
        let saved = &entry.scope.saved;
        let (generation, root) = self
            .inner
            .bridge
            .native_project(&saved.runtime_id)
            .map_err(|_| p::refused())?;
        let (device, inode) = root
            .identity
            .posix()
            .map_err(|_| p::unavailable())?
            .service_identity();
        if !saved.fresh
            || saved.revision == 0
            || root.path != saved.root
            || (device, inode) != (saved.device, saved.inode)
            || state
                .version_reserve
                .agent
                .service
                .as_ref()
                .is_some_and(|v| v.as_ptr() != Arc::as_ptr(service))
        {
            return Err(p::refused());
        }
        Ok(NativeProject {
            runtime_id: saved.runtime_id.clone(),
            canonical_root: root.path,
            device,
            inode,
            registration_generation: generation,
            document_identity: self.inner.session_identity.clone(),
            input_revision: self.inner.android_registration_control.epoch()?,
        })
    }
    pub(crate) async fn review_requested_version_reservation(
        &self,
        window: &str,
        q: &r::Query,
    ) -> Result<p::Status, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let service = self.reserve_review_service()?;
        let entry = service
            .version_reserve_requests()
            .review_entry(q)
            .map_err(public)?;
        let native = {
            let state = self.lock();
            self.review_entry_native(&state, &entry, &service)
                .map_err(p::not_started)?
        };
        // The SAME actual Host/Service comparison may perform IO: no Doc held.
        let original = self
            .inner
            .bridge
            .application_service
            .identity_request_service(&native)
            .map_err(public)?;
        let point = original
            .version_reserve_point(&native.runtime_id)
            .map_err(public)?;
        if !Arc::ptr_eq(&original, &service)
            || !Arc::ptr_eq(&point.read, &entry.scope.read)
            || !same_saved(&point.saved, &entry.scope.saved)
        {
            return Err(p::not_started(p::refused()));
        }
        let id = Id::random().map_err(public)?.as_str().to_owned();
        let (link, caller) = {
            let mut state = self.lock();
            let current = self
                .review_entry_native(&state, &entry, &service)
                .map_err(p::not_started)?;
            if !same_native(&native, &current) {
                return Err(p::not_started(p::refused()));
            }
            // Permanent one-caller claim BEFORE installing the original link.
            let caller = entry.begin().map_err(|e| p::not_started(public(e)))?;
            let link = Arc::new(Link {
                entry: entry.clone(),
                native,
                id,
                source: OnceLock::new(),
            });
            state.version_reserve.agent.review_pending = Some(link.clone());
            state.version_reserve.agent.service = Some(Arc::downgrade(&service));
            (link, caller)
        };
        let options = &entry.input.options;
        let input = p::Review {
            project_id: entry.scope.saved.runtime_id.clone(),
            reference: options.reference.clone(),
            increment: options.increment,
            new_candidate: options.new_candidate,
            acknowledge_limitations: options.acknowledge_limitations,
            future_tag: options.future_tag.clone(),
        };
        let mut result = self
            .review_version_reservation_linked(input, Some(link.clone()))
            .await;
        if result
            .as_ref()
            .is_ok_and(|s| matches!(s.phase, p::Phase::Reviewed))
        {
            // native_ready was set only by the actual private constructor.
        } else if link.known_unentered() || link.source_returned() {
            entry
                .native_refused(wire::Reason::NativeRefused)
                .map_err(public)?;
            // A known returned read failure is truthful Refused, not a made-up
            // "not started" receipt for a SOURCE which really ran.
            let state = self.lock();
            let view = &state.version_reserve.view;
            if view.operation_id.as_deref() == Some(&link.id)
                && matches!(view.phase, p::Phase::Refused)
            {
                result = Ok(view.clone())
            }
        } else {
            entry.unknown();
            result = Err(BridgeError::cleanup_unknown())
        }
        caller
            .returned()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        self.inner.changes.send_modify(|_| {});
        result
    }
}

#[cfg(test)]
#[path = "asset_session_agent_version_reserve_review_tests.rs"]
mod tests;
