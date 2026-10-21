//! Reserve delegation on the SAME private Review/Lane and original 60/70
//! owner. No new runtime, credential source, counter or edit authority.
use super::*;
use crate::{
    application_service::ApplicationService,
    service_protocol::{Error, Id},
    service_version_reserve_protocol as wire, service_version_reserve_requests as requests,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[path = "asset_session_agent_version_relay.rs"]
mod relay;
#[path = "asset_session_agent_version_reserve_review.rs"]
pub(in crate::asset_session) mod review;
pub(crate) use relay::ReserveRelay;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Allow {
    project_id: String,
    review_id: Id,
    expected_reserve_revision: u32,
    expected_allow_revision: String,
    consent_version: String,
}
pub(crate) fn decode_allow(bytes: &[u8]) -> Result<Allow, BridgeError> {
    if bytes.is_empty() || bytes.len().saturating_add(96) > wire::RAW_LIMIT {
        return Err(BridgeError::invalid());
    }
    let value = crate::protocol::strict_json(bytes)?;
    let args = Allow::deserialize(&value).map_err(|_| BridgeError::invalid())?;
    if !crate::protocol::valid_id(&args.project_id)
        || !(1..u32::MAX).contains(&args.expected_reserve_revision)
        || allow_revision(&args.expected_allow_revision).is_none()
        || args.consent_version != wire::CONSENT
    {
        return Err(BridgeError::invalid());
    }
    Ok(args)
}
pub(crate) fn decode_empty(bytes: &[u8]) -> Result<(), BridgeError> {
    if bytes.is_empty() || bytes.len().saturating_add(96) > wire::RAW_LIMIT {
        return Err(BridgeError::invalid());
    }
    let value = crate::protocol::strict_json(bytes)?;
    if value.as_object().is_some_and(|v| v.is_empty()) {
        Ok(())
    } else {
        Err(BridgeError::invalid())
    }
}
// MAIN-only revocation comparison. The CLI's Access/Submit wire is unchanged.
// Fixed-width lowercase text avoids JS integer rounding; MAX is absorbing.
fn allow_revision(value: &str) -> Option<u64> {
    if value.len() != 16 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    u64::from_str_radix(value, 16).ok().filter(|v| *v < u64::MAX)
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainAccess {
    #[serde(flatten)]
    access: wire::Access,
    allow_revision: String,
}
struct Grant {
    scope: Arc<requests::NativeScope>,
    review: Arc<()>,
    native: NativeProject,
}
struct Active {
    lane: Weak<Lane>,
    link: Arc<requests::NativeLink>,
}
fn same_native(a: &NativeProject, b: &NativeProject) -> bool {
    a.runtime_id == b.runtime_id
        && a.canonical_root == b.canonical_root
        && (a.device, a.inode) == (b.device, b.inode)
        && a.registration_generation == b.registration_generation
        && a.input_revision == b.input_revision
        && Arc::ptr_eq(&a.document_identity, &b.document_identity)
}
#[derive(Default)]
pub(super) struct State {
    service: Option<Weak<ApplicationService>>,
    grant: Option<Arc<Grant>>,
    active: Option<Active>,
    pending: Option<Arc<requests::Entry>>,
    review_pending: Option<Arc<review::Link>>,
    epoch: std::sync::atomic::AtomicU64,
    relay_lost: bool,
}
impl State {
    fn allow_epoch(&self) -> Result<u64, Error> {
        let epoch = self.epoch.load(Ordering::SeqCst);
        if epoch == u64::MAX { Err(Error::StateUnknown) } else { Ok(epoch) }
    }
    // Claimed once at the first real Doc cut, not on arrival from renderer
    // DATA. Host waiting retains only this exact private successor.
    fn claim_allow(&self, expected: u64) -> Result<u64, Error> {
        if expected == u64::MAX { return Err(Error::StateUnknown); }
        let next = expected.checked_add(1).ok_or(Error::StateUnknown)?;
        match self.epoch.compare_exchange(expected, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) if next < u64::MAX => Ok(next),
            Ok(_) | Err(u64::MAX) => Err(Error::StateUnknown),
            Err(_) => Err(Error::Conflict),
        }
    }
    fn allow_current(&self, successor: u64) -> bool {
        successor < u64::MAX && self.epoch.load(Ordering::SeqCst) == successor
    }
    fn invalidate_allow(&self) -> bool {
        let old = self.epoch.fetch_update(Ordering::SeqCst, Ordering::SeqCst,
            |value| Some(value.checked_add(1).unwrap_or(u64::MAX))).unwrap();
        old < u64::MAX - 1
    }
    fn main_access(&self, access: wire::Access) -> Result<MainAccess, BridgeError> {
        access.validate().map_err(public)?;
        let result = MainAccess { access, allow_revision: format!("{:016x}", self.allow_epoch().map_err(public)?) };
        if serde_json::to_vec(&result).map_err(|_| BridgeError::protocol())?.len() > wire::STATUS_LIMIT {
            return Err(BridgeError::protocol());
        }
        Ok(result)
    }
}
pub(super) const BACKING: usize = 32 * 1024 + std::mem::size_of::<State>() + relay::BACKING;
fn public(e: Error) -> BridgeError {
    application_service::public_error(e)
}
fn error(e: &BridgeError) -> Error {
    match e.code.as_str() {
        "cleanup_unknown" | "cli_access_unknown" => Error::StateUnknown,
        "busy" | "cli_access_busy" => Error::Busy,
        "runtime_unavailable" | "version_reserve_unavailable" | "cli_access_unavailable" => {
            Error::Unavailable
        }
        _ => Error::Conflict,
    }
}
fn service(state: &DocumentState) -> Result<Option<Arc<ApplicationService>>, BridgeError> {
    state
        .version_reserve
        .agent
        .service
        .as_ref()
        .map(|s| s.upgrade().ok_or_else(|| public(Error::Unavailable)))
        .transpose()
}
pub(in crate::asset_session) fn pending(state: &DocumentState) -> bool {
    let agent = &state.version_reserve.agent;
    agent.relay_lost || agent.pending.as_ref().is_some_and(|e| e.pending()) || review::pending(state)
}
pub(in crate::asset_session) fn gui_current(state: &DocumentState) -> Result<(), BridgeError> {
    if pending(state)
        || service(state)?
            .is_some_and(|s| s.version_reserve_requests().blocks_review().unwrap_or(true))
    {
        return Err(public(Error::Busy));
    }
    Ok(())
}
/// Called at original lifecycle invalidation, not an unrelated observer's
/// later timestamp. Only memory cells/STOP, never Service/Host IO.
pub(in crate::asset_session) fn stop(state: &DocumentState, at: Instant) {
    let agent = &state.version_reserve.agent;
    if !agent.invalidate_allow() {
        // No wrapped/stale revision can grant again. Keep any actual original
        // and contract its same STOP; never drop it to make room for a grant.
        if let Some(entry) = &agent.pending { entry.unknown(); }
        if let Some(link) = &agent.review_pending { link.entry.unknown(); }
        if let Some(lane) = &state.version_reserve.lane {
            lane.control.stop_at(at);
            lane.control.unknown();
        }
    }
    if let Some(service) = agent.service.as_ref().and_then(Weak::upgrade) {
        let _ = service
            .version_reserve_requests()
            .revoke(wire::Reason::ContextChanged, at);
    }
    if let Some(active) = &agent.active {
        if let Some(lane) = active.lane.upgrade() {
            forward(&lane);
        }
    }
}
pub(super) fn forward(lane: &Lane) {
    if let Some(link) = &lane.agent {
        match link.entry().first_stop() {
            Ok(Some((wire::Reason::CleanupUnknown, at))) => {
                lane.control.stop_at(at);
                lane.control.unknown();
            }
            Ok(Some((_, at))) => lane.control.stop_at(at),
            Err(_) => lane.control.unknown(),
            Ok(None) => {}
        }
    }
}
pub(super) fn current(state: &DocumentState, lane: &Arc<Lane>) -> Result<(), BridgeError> {
    let Some(link) = &lane.agent else {
        return Ok(());
    };
    let result = (|| {
        let active = state
            .version_reserve
            .agent
            .active
            .as_ref()
            .ok_or(Error::Conflict)?;
        if active.lane.upgrade().is_none_or(|v| !Arc::ptr_eq(&v, lane))
            || !Arc::ptr_eq(&active.link, link)
        {
            return Err(Error::Conflict);
        }
        let original = service(state)
            .map_err(|_| Error::StateUnknown)?
            .ok_or(Error::Unavailable)?;
        original.native_history_current()?; // Atomic fence; no Service lock/IO.
        link.current(true)
    })();
    if result == Err(Error::StateUnknown) {
        link.entry().unknown();
        lane.control.unknown();
    } else if result.is_err() && link.entry().first_stop().is_ok_and(|v| v.is_none()) {
        link.entry()
            .cancel(wire::Reason::ContextChanged, Instant::now());
    }
    forward(lane);
    result.map_err(public)
}
pub(super) fn admission(
    state: &DocumentState,
    review: &Review,
    link: &Arc<requests::NativeLink>,
) -> Result<(), BridgeError> {
    let agent = &state.version_reserve.agent;
    let grant = agent.grant.as_ref().ok_or_else(p::refused)?;
    if agent.relay_lost
        || agent
            .pending
            .as_ref()
            .is_none_or(|e| !Arc::ptr_eq(e, link.entry()))
        || !Arc::ptr_eq(&grant.scope, link.scope())
        || !Arc::ptr_eq(&grant.review, &review.identity)
        || grant.scope.review_id.as_str() != review.id
        || grant.scope.review_revision != state.version_reserve.view.revision
    {
        return Err(p::refused());
    }
    service(state)?
        .ok_or_else(p::unavailable)?
        .native_history_current()
        .map_err(public)?;
    link.current(false).map_err(public)
}
/// Link is retained BEFORE private Review take or public Lane publication.
/// Even a simultaneous STOP/poison after allocation retains this exact Lane.
pub(super) fn bind(state: &mut DocumentState, lane: &Arc<Lane>) {
    let Some(link) = &lane.agent else {
        return;
    };
    state.version_reserve.agent.active = Some(Active {
        lane: Arc::downgrade(lane),
        link: link.clone(),
    });
    match link.arm(&lane.id) {
        Ok(true) => {}
        Ok(false) => {
            link.entry()
                .cancel(wire::Reason::PermissionRevoked, Instant::now());
            forward(lane);
        }
        Err(_) => {
            link.entry().unknown();
            lane.control.unknown();
        }
    }
}

impl DocumentBinding {
    fn reserve_review_native(
        &self,
        state: &DocumentState,
        project_id: &str,
        review_id: &Id,
        expected_reserve_revision: u32,
        claimed: Option<&Arc<requests::NativeLink>>,
    ) -> Result<(Arc<()>, NativeProject), BridgeError> {
        self.passive_query_gate_locked(state, &self.inner.bridge)?;
        // ONLY this already-retained original claim may pass its own pending
        // entry. A GUI Allow/Review never borrows this exception.
        let same_claim = claimed.is_some_and(|link| {
            state
                .version_reserve
                .agent
                .pending
                .as_ref()
                .is_some_and(|entry| Arc::ptr_eq(entry, link.entry()))
        });
        if (pending(state) && !same_claim)
            || self.github_gate(state) != GitHubReason::None
            || !self.inner.bridge.supervisor.can_exit()
            || version_allocation::pending(state)
            || !matches!(state.version_reserve.view.phase, p::Phase::Reviewed)
            || state.version_reserve.view.revision != expected_reserve_revision
        {
            return Err(p::refused());
        }
        let review = state
            .version_reserve
            .review
            .as_ref()
            .filter(|r| {
                r.id == review_id.as_str()
                    && r.input.project_id == project_id
                    && Instant::now() < r.end
            })
            .ok_or_else(p::refused)?;
        if review.delegated.as_ref().is_some_and(|v|!v.entry.ready_current(&review.identity,Instant::now())) {return Err(p::refused())}
        if let Some(link) = claimed {
            admission(state, review, link)?;
        }
        let (registration, root) = self
            .inner
            .bridge
            .native_project(project_id)
            .map_err(|_| p::refused())?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        let (saved, input) = state
            .saved_input
            .as_ref()
            .ok_or_else(p::refused)?
            .version_source_input(
                &self.inner,
                project_id,
                &review.input.reference,
                &edit,
            )?;
        if registration != review.registration
            || root != review.native.root
            || !Arc::ptr_eq(&saved, &review.saved)
            || !input.matches(&review.source)
            || !self.current_store_version_observation(
                state,
                &review.store,
                registration,
                &root,
                900,
            )
        {
            return Err(p::refused());
        }
        let (device, inode) = root
            .identity
            .posix()
            .map_err(|_| p::unavailable())?
            .service_identity();
        Ok((
            review.identity.clone(),
            NativeProject {
                runtime_id: project_id.to_owned(),
                canonical_root: root.path,
                device,
                inode,
                registration_generation: registration,
                document_identity: self.inner.session_identity.clone(),
                input_revision: self.inner.android_registration_control.epoch()?,
            },
        ))
    }
    pub(crate) fn agent_version_reserve_access(
        &self,
        window: &str,
    ) -> Result<MainAccess, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let state = self.lock();
        let Some(service) = service(&state)? else {
            return state.version_reserve.agent.main_access(wire::Access::empty());
        };
        service.native_history_current().map_err(public)?;
        let mut value = service
            .version_reserve_requests()
            .access()
            .map_err(public)?;
        // This is a comparison marker for the GUI, not edit authority. All
        // genuine native handoff/currentness checks still run in EditOwner.
        if let Some(active) = &state.version_reserve.agent.active {
            if let Some(lane) = active.lane.upgrade().filter(|lane| {
                lane.returned()
                    && lane.control.edit_window()
                    && !lane.edit_claimed.load(Ordering::SeqCst)
                    && state
                        .version_reserve
                        .lane
                        .as_ref()
                        .is_some_and(|v| Arc::ptr_eq(v, lane))
            }) {
                let entry = active.link.entry();
                let id = entry.completed_operation().map_err(public)?;
                let same = value.request_id.as_ref() == Some(&entry.input().origin.request_id)
                    && value.grant_id.as_ref() == Some(&entry.input().grant_id)
                    && value.review_id.as_ref() == Some(&entry.input().review_id)
                    && id.as_ref().map(Id::as_str) == Some(lane.id.as_str());
                if same && self.agent_reserved_current(&state, &lane).is_ok() {
                    value.completed_operation_id = id;
                }
            }
        }
        value.validate().map_err(public)?;
        state.version_reserve.agent.main_access(value)
    }
    fn agent_reserved_current(
        &self,
        state: &DocumentState,
        lane: &Arc<Lane>,
    ) -> Result<(), BridgeError> {
        passive_document_state_gate(state)?;
        if !state.lifetime.original_bound()
            || state.lost_observed
            || state.stopping
            || state.retiring
            || state.quit_pending
            || state.lock_pending
            || state.maintenance.closed()
            || !matches!(state.version_reserve.view.phase, p::Phase::Reserved)
        {
            return Err(p::refused());
        }
        let source = lane.source()?;
        let (generation, root) = self
            .inner
            .bridge
            .native_project(&lane.pins.project_id)
            .map_err(|_| p::refused())?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        if generation != lane.pins.generation
            || root != source.input.root
            || !state.saved_input.as_ref().is_some_and(|s| {
                s.matches_version_source(&self.inner, &source.saved, &source.input, &edit)
            })
            || !self.current_store_version_observation(
                state,
                &lane.observation,
                generation,
                &root,
                900,
            )
        {
            return Err(p::refused());
        }
        state
            .github
            .reserved_version_edit_current(&lane.pins, Instant::now())
    }
    pub(crate) fn allow_agent_version_reserve(
        &self,
        window: &str,
        args: Allow,
    ) -> Result<MainAccess, BridgeError> {
        if window != MAIN || args.consent_version != wire::CONSENT {
            return Err(BridgeError::invalid());
        }
        let expected = allow_revision(&args.expected_allow_revision).ok_or_else(BridgeError::invalid)?;
        let grant_id = Id::random().map_err(public)?;
        let (identity, native, epoch) = {
            let state = self.lock();
            if state.version_reserve.agent.allow_epoch().map_err(public)? != expected {
                return Err(p::refused());
            }
            let (identity, native) = self.reserve_review_native(&state, &args.project_id,
                &args.review_id, args.expected_reserve_revision, None)?;
            let successor = match state.version_reserve.agent.claim_allow(expected) {
                Ok(value) => value,
                Err(e) => {
                    if e == Error::StateUnknown { stop(&state, Instant::now()); }
                    return Err(public(e));
                }
            };
            (identity, native, successor)
        };
        // Original Host+Service can do IO. No Doc/Edit/inbox/relay guard lives here.
        let host = &self.inner.bridge.application_service;
        let original = host.identity_request_service(&native).map_err(public)?;
        let point = original
            .version_reserve_point(&native.runtime_id)
            .map_err(public)?;
        if point.saved.root != native.canonical_root
            || (point.saved.device, point.saved.inode) != (native.device, native.inode)
        {
            return Err(p::refused());
        }
        let mut state = self.lock();
        let (current, current_native) = self.reserve_review_native(&state, &args.project_id,
            &args.review_id, args.expected_reserve_revision, None)?;
        if !Arc::ptr_eq(&identity, &current)
            || !same_native(&native, &current_native)
            || !state.version_reserve.agent.allow_current(epoch)
            || state
                .version_reserve
                .agent
                .service
                .as_ref()
                .is_some_and(|v| v.as_ptr() != Arc::as_ptr(&original))
        {
            return Err(p::refused());
        }
        let review = state
            .version_reserve
            .review
            .as_ref()
            .ok_or_else(p::refused)?;
        let scope = Arc::new(requests::NativeScope {
            project_id: point.saved.project_id,
            runtime_id: args.project_id,
            review_id: args.review_id,
            review_revision: args.expected_reserve_revision,
            review_end: review.end,
            read: point.read,
            document: Arc::downgrade(&self.inner.session_identity),
            review: Arc::downgrade(&identity),
            changes: self.inner.changes.clone(),
        });
        let access = original
            .version_reserve_requests()
            .allow(scope.clone(), grant_id)
            .map_err(public)?;
        state.version_reserve.agent.service = Some(Arc::downgrade(&original));
        state.version_reserve.agent.grant = Some(Arc::new(Grant {
            scope,
            review: identity,
            native,
        }));
        state.version_reserve.agent.main_access(access)
    }
    pub(crate) fn revoke_agent_version_reserve(
        &self,
        window: &str,
    ) -> Result<MainAccess, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let at = Instant::now();
        let mut state = self.lock();
        if !state.version_reserve.agent.invalidate_allow() {
            stop(&state, at);
            return Err(public(Error::StateUnknown));
        }
        let Some(service) = service(&state)? else {
            return state.version_reserve.agent.main_access(wire::Access::empty());
        };
        let result = service
            .version_reserve_requests()
            .revoke(wire::Reason::PermissionRevoked, at)
            .map_err(public);
        if let Some(active) = &state.version_reserve.agent.active {
            if let Some(lane) = active.lane.upgrade() {
                forward(&lane);
            }
        }
        state.version_reserve.agent.main_access(result?)
    }
    fn agent_reserve_claim(&self) -> Result<Option<requests::Claim>, BridgeError> {
        let mut state = self.lock();
        let Some(service) = service(&state)? else {
            return Ok(None);
        };
        if state.version_reserve.agent.relay_lost {
            return Ok(None);
        }
        service.native_history_current().map_err(public)?;
        let claim = service.version_reserve_requests().claim().map_err(public)?;
        if let Some(claim) = &claim {
            state.version_reserve.agent.pending = Some(claim.entry().clone());
        }
        Ok(claim)
    }
    fn agent_reserve_release_current(
        &self,
        link: &Arc<requests::NativeLink>,
    ) -> Result<(), BridgeError> {
        let state = self.lock();
        let scope = link.scope();
        let (_, native) = self.reserve_review_native(&state, &scope.runtime_id,
            &scope.review_id, scope.review_revision, Some(link))?;
        let grant = state
            .version_reserve
            .agent
            .grant
            .as_ref()
            .ok_or_else(p::refused)?;
        if !same_native(&grant.native, &native) {
            return Err(p::refused());
        }
        Ok(())
    }
    fn agent_reserve_tick(&self) {
        let mut state = self.lock();
        if state.stopping
            || state.lost_observed
            || !state.lifetime.original_bound()
            || state.unknown
        {
            stop(&mut state, Instant::now());
        }
        if let Some(active) = &state.version_reserve.agent.active {
            if let Some(lane) = active.lane.upgrade().filter(|l| !l.returned()) {
                let _ = current(&state, &lane);
            }
        }
    }
    fn agent_reserve_close(&self, lost: bool) {
        let mut state = self.lock();
        stop(&mut state, Instant::now());
        if let Ok(Some(s)) = service(&state) {
            s.version_reserve_requests().close(Instant::now());
        }
        if lost {
            state.version_reserve.agent.relay_lost = true;
            if let Some(link)=&state.version_reserve.agent.review_pending {if link.entry.pending(){link.entry.unknown();}}
            if let Some(entry) = &state.version_reserve.agent.pending {
                entry.unknown();
            }
            if let Some(active) = &state.version_reserve.agent.active {
                if let Some(lane) = active.lane.upgrade().filter(|l| !l.returned()) {
                    lane.control.unknown();
                }
            }
        }
    }
    async fn run_agent_reserve(
        &self,
        mut claim: requests::Claim,
        app_data: PathBuf,
    ) -> Result<(), ()> {
        let link = claim.link().clone();
        let preentry = (|| {
            link.current(false).map_err(public)?;
            let (original, native) = {
                let state = self.lock();
                let grant = state
                    .version_reserve
                    .agent
                    .grant
                    .as_ref()
                    .ok_or_else(p::refused)?;
                if !Arc::ptr_eq(&grant.scope, link.scope()) {
                    return Err(p::refused());
                }
                (
                    service(&state)?.ok_or_else(p::unavailable)?,
                    grant.native.clone(),
                )
            };
            let host = self
                .inner
                .bridge
                .application_service
                .identity_request_service(&native)
                .map_err(public)?;
            if !Arc::ptr_eq(&host, &original) {
                return Err(p::refused());
            }
            original
                .version_reserve_original_current(link.scope())
                .map_err(public)?;
            self.reserve_begin(
                &link.scope().runtime_id,
                link.scope().review_id.as_str(),
                Some(link.clone()),
            )
        })();
        let lane = match preentry {
            Ok(lane) => lane,
            Err(e) => return claim.not_admitted(error(&e)).map_err(|_| ()),
        };
        let mut guard = WaitGuard {
            lane: lane.clone(),
            returned: false,
        };
        let outcome = self.reserve_run(&lane, &app_data).await;
        let status = self.reserve_finish(&lane, outcome).await.map_err(|_| ())?;
        if !lane.returned() {
            return Err(());
        }
        guard.returned = true;
        let result = match status
            .reservation
            .filter(|v| v.id == lane.id && matches!(status.phase, p::Phase::Reserved))
        {
            Some(v) => requests::Final::Reserved(wire::Reservation {
                candidate_id: v.candidate_id,
                name: v.name,
                build: v.build,
                ci: Some(v.ci),
            }),
            None => requests::Final::Refused,
        };
        claim.native_returned(&lane.id, result).map_err(|_| ())
    }
}

#[cfg(test)]
#[path = "asset_session_agent_version_reserve_tests.rs"]
mod tests;
