//! The existing Asset/UploadKey owners remain the only native execution.
//! This fixed facade retains one original claim and MAIN-reviewed comparison.
use super::*;
use crate::{
    application_service::ApplicationService,
    application_service_host::NativeProject,
    edit_owner::SavedEditStamp,
    service_protocol::{Error, Id},
    service_upload_key_protocol as p, service_upload_key_requests as requests,
};
use serde::Deserialize;
use std::sync::atomic::AtomicU64;

#[path = "asset_session_agent_upload_key_relay.rs"]
mod relay;
pub(crate) use relay::UploadKeyRelay;
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
#[path = "asset_session_agent_upload_key_reuse.rs"]
mod reuse;
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
pub(super) use reuse::{attach_prepared, prepare_completion, prepared_reply};
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )
))]
use vault::upload_key_controls::delegation as proof;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Allow {
    project_id: String,
    consent_id: Id,
    context_revision: u32,
    expected_status_revision: u32,
    selection: p::Selection,
    consent_version: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Revoke {
    consent_id: Id,
}
fn decode<T: for<'a> Deserialize<'a>>(bytes: &[u8]) -> Result<T, BridgeError> {
    if bytes.is_empty() || bytes.len().saturating_add(96) > p::RAW_LIMIT {
        return Err(BridgeError::invalid());
    }
    let value = crate::protocol::strict_json(bytes)?;
    T::deserialize(&value).map_err(|_| BridgeError::invalid())
}
pub(crate) fn decode_allow(bytes: &[u8]) -> Result<Allow, BridgeError> {
    let a: Allow = decode(bytes)?;
    if !crate::protocol::valid_id(&a.project_id)
        || !(1..u32::MAX).contains(&a.context_revision)
        || !(1..u32::MAX).contains(&a.expected_status_revision)
        || !a.selection.valid()
        || a.consent_version != a.selection.kind().consent()
    {
        return Err(BridgeError::invalid());
    }
    Ok(a)
}
pub(crate) fn decode_revoke(bytes: &[u8]) -> Result<Revoke, BridgeError> {
    decode(bytes)
}
pub(crate) fn decode_empty(bytes: &[u8]) -> Result<(), BridgeError> {
    let value: Value = decode(bytes)?;
    if value.as_object().is_some_and(|o| o.is_empty()) {
        Ok(())
    } else {
        Err(BridgeError::invalid())
    }
}
struct Grant {
    id: Id,
    identity: Arc<()>,
    scope: Arc<requests::NativeScope>,
    native: NativeProject,
    edit: SavedEditStamp,
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )
    ))]
    proof: proof::Proof,
}
#[derive(Default)]
pub(super) struct State {
    service: Option<Weak<ApplicationService>>,
    grant: Option<Arc<Grant>>,
    active: Option<Arc<requests::NativeLink>>,
    pending_allow: Option<Id>,
    spent_consents: Vec<Id>,
    epoch: AtomicU64,
    lost: bool,
}
impl State {
    fn allow_available(&self, id: &Id) -> Result<(), Error> {
        if self.pending_allow.is_some()
            || self.epoch.load(Ordering::SeqCst) == u64::MAX
            || self.spent_consents.contains(id)
        {
            return Err(Error::Conflict);
        }
        if self.spent_consents.len() >= p::CONSENT_LIMIT {
            return Err(Error::Busy);
        }
        Ok(())
    }
    fn remember_consent(&mut self, id: &Id) -> Result<(), Error> {
        if self.spent_consents.contains(id) {
            return Ok(());
        }
        if self.spent_consents.len() >= p::CONSENT_LIMIT {
            return Err(Error::Busy);
        }
        self.spent_consents
            .try_reserve_exact(1)
            .map_err(|_| Error::Busy)?;
        self.spent_consents.push(id.clone());
        Ok(())
    }
    fn begin_allow(&mut self, id: &Id) -> Result<u64, Error> {
        self.allow_available(id)?;
        self.remember_consent(id)?;
        self.pending_allow = Some(id.clone());
        Ok(self.epoch.load(Ordering::SeqCst))
    }
    fn revoke_consent(&mut self, id: &Id) -> Result<(), Error> {
        // Revoke can reach this Doc before the queued Allow reaches its first
        // cut. Retain THAT nonce before returning off, even with no lease yet.
        // Capacity failure is not an acknowledgment of revocation.
        self.remember_consent(id)?;
        if self.pending_allow.as_ref() == Some(id) {
            let _ = self.epoch.fetch_update(
                Ordering::SeqCst,
                Ordering::SeqCst,
                |n| Some(n.saturating_add(1)),
            );
            self.pending_allow = None;
        }
        Ok(())
    }
}
pub(super) fn retained_bytes(state: &DocumentState) -> Option<usize> {
    let a = &state.agent_upload_key;
    let mut n = std::mem::size_of::<State>()
        .checked_add(relay::BACKING)?
        .checked_add(p::CONSENT_LIMIT * (std::mem::size_of::<Id>() + 32))?
        .checked_add(2 * p::VIEW_LIMIT)?; // Exact native DTO conversion/MAIN reply scratch.
    if let Some(g) = &a.grant {
        n = n
            .checked_add(
                std::mem::size_of::<Grant>()
                    + std::mem::size_of::<()>()
                    + 4 * std::mem::size_of::<usize>()
                    + g.id.as_str().len(),
            )?
            .checked_add(g.native.runtime_id.capacity())?
            .checked_add(g.native.canonical_root.as_os_str().len())?;
        #[cfg(any(
            all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
            all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )
        ))]
        {
            n = n.checked_add(g.proof.retained_bytes())?;
        }
    }
    Some(n)
}
fn public(e: Error) -> BridgeError {
    application_service::public_error(e)
}
pub(super) fn pending(state: &DocumentState) -> bool {
    state.agent_upload_key.lost
        || state
            .agent_upload_key
            .active
            .as_ref()
            .is_some_and(|l| l.entry().pending())
}
fn refused() -> AssetError {
    AssetError::new(Reason::ContextStale)
}
fn service(s: &DocumentState) -> Result<Option<Arc<ApplicationService>>, Error> {
    s.agent_upload_key
        .service
        .as_ref()
        .map(|w| w.upgrade().ok_or(Error::StateUnknown))
        .transpose()
}
pub(super) fn gui_available(s: &DocumentState) -> Result<(), AssetError> {
    if s.agent_upload_key.lost
        || service(s)
            .map_err(|_| refused())?
            .is_some_and(|s| s.upload_key_requests().blocks_action().unwrap_or(true))
    {
        Err(AssetError::new(Reason::Busy))
    } else {
        Ok(())
    }
}
pub(super) fn stop(state: &DocumentState, at: Instant) {
    let a = &state.agent_upload_key;
    let _ = a
        .epoch
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            Some(n.saturating_add(1))
        });
    if let (Some(s), Some(g)) = (a.service.as_ref().and_then(Weak::upgrade), &a.grant) {
        let _ = s.upload_key_requests().revoke(&g.id, at);
    }
    if let Some(link) = &a.active {
        link.entry().cancel(p::Reason::ContextChanged, at);
    }
}
pub(super) fn forward(state: &mut DocumentState) {
    let Some(link) = state.agent_upload_key.active.clone() else {
        return;
    };
    match link.entry().first_stop() {
        Ok(Some((reason, at))) => {
            if let Some(slot) = state.slot.as_mut().filter(|s| {
                s.owner
                    .agent_upload_key
                    .get()
                    .is_some_and(|v| Arc::ptr_eq(v, &link))
            }) {
                slot.stop(
                    if reason == p::Reason::Expired {
                        Reason::Deadline
                    } else {
                        Reason::UserCancelled
                    },
                    at,
                );
            }
        }
        Ok(None) => {}
        Err(_) => {
            if let Some(slot) = state.slot.as_mut().filter(|s| {
                s.owner
                    .agent_upload_key
                    .get()
                    .is_some_and(|v| Arc::ptr_eq(v, &link))
            }) {
                slot.stop(Reason::CleanupUnknown, Instant::now());
            }
        }
    }
}
pub(super) fn consume(
    document: &DocumentBinding,
    state: &DocumentState,
    link: &Arc<requests::NativeLink>,
    kind: p::Kind,
) -> Result<(), AssetError> {
    let a = &state.agent_upload_key;
    let grant = a.grant.as_ref().ok_or_else(refused)?;
    if a.lost
        || !a.active.as_ref().is_some_and(|v| Arc::ptr_eq(v, link))
        || grant.id != *link.entry().grant_id()
        || !Arc::ptr_eq(&grant.scope, link.entry().scope())
        || grant.scope.kind != kind
    {
        return Err(refused());
    }
    link.current().map_err(|_| refused())?;
    document
        .service_allow_current_locked(state, &grant.native, &grant.edit)
        .map_err(|_| refused())?;
    service(state)
        .map_err(|_| refused())?
        .ok_or_else(refused)?
        .native_history_current()
        .map_err(|_| refused())?;
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )
    ))]
    {
        grant.proof.current(document, state)?;
    }
    link.attempted().map_err(|_| refused())
}
pub(super) fn attach(
    state: &DocumentState,
    owner: &Arc<OriginalWork>,
    link: &Arc<requests::NativeLink>,
) -> Result<(), AssetError> {
    if !state
        .agent_upload_key
        .active
        .as_ref()
        .is_some_and(|v| Arc::ptr_eq(v, link))
        || owner.agent_upload_key.get().is_some()
    {
        return Err(refused());
    }
    // Retain even when a later current/arm check fails. No generated output or
    // request can become an unowned successor because GO was never opened.
    owner
        .agent_upload_key
        .set(link.clone())
        .map_err(|_| refused())?;
    link.arm(owner.id).map_err(|_| refused())
}
pub(super) fn before_install(
    state: &DocumentState,
    slot: &Slot,
    cleanup_only: bool,
) -> Result<(), AssetError> {
    if cleanup_only {
        return Ok(());
    }
    if let Some(link) = slot.owner.agent_upload_key.get() {
        if state
            .agent_upload_key
            .active
            .as_ref()
            .is_none_or(|v| !Arc::ptr_eq(v, link))
        {
            return Err(refused());
        }
        link.current().map_err(|_| refused())
    } else {
        gui_available(state)
    }
}

/// Minted only at the actual original native result cut below. PrepareExisting
/// means joined Load/assessment with its normal live Preview, NOT private
/// payload retirement. All other actions still require their original final
/// publication/retirement. Never constructed from service/CLI DATA.
pub(crate) struct UploadKeyAgentRetired {
    entry: Weak<requests::Entry>,
    id: u32,
    state: p::State,
    reason: p::Reason,
    key: Option<p::KeyReference>,
}
impl UploadKeyAgentRetired {
    pub(crate) fn for_entry(
        &self,
        entry: &Arc<requests::Entry>,
    ) -> Option<(u32, p::State, p::Reason, Option<p::KeyReference>)> {
        (self.entry.as_ptr() == Arc::as_ptr(entry))
            .then(|| (self.id, self.state, self.reason, self.key.clone()))
    }
}
pub(super) fn retired(document: &DocumentBinding, state: &DocumentState) {
    let Some(slot) = &state.slot else {
        return;
    };
    let Some(link) = slot.owner.agent_upload_key.get() else {
        return;
    };
    match link.entry().needs_native_retirement(slot.owner.id) {
        Ok(false) => return,
        Ok(true) => {}
        Err(_) => {
            link.entry().unknown();
            return;
        }
    }
    if state.unknown || matches!(slot.settlement, Settlement::Unknown | Settlement::LateKnown) {
        link.entry().unknown();
        return;
    }
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )
    ))]
    if let Some((outcome, reason, key)) = proof::completion(document, state, slot) {
        let witness = UploadKeyAgentRetired {
            entry: Arc::downgrade(link.entry()),
            id: slot.owner.id,
            state: outcome,
            reason,
            key,
        };
        if let Some((id, outcome, reason, key)) = witness.for_entry(link.entry()) {
            link.entry().native_retired(id, outcome, reason, key);
        } else {
            link.entry().unknown();
        }
    }
}

impl DocumentBinding {
    pub(crate) fn agent_upload_key_access(&self, window: &str) -> Result<p::Access, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let s = service(&self.lock()).map_err(public)?;
        let value = s.map_or(Ok(p::Access::empty()), |s| {
            s.upload_key_requests().access(None).map_err(public)
        })?;
        #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
            all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
        let value = reuse::access(self, value);
        Ok(value)
    }
    pub(crate) fn revoke_agent_upload_key(
        &self,
        window: &str,
        args: Revoke,
    ) -> Result<p::Access, BridgeError> {
        if window != MAIN {
            return Err(BridgeError::invalid());
        }
        let mut state = self.lock();
        state
            .agent_upload_key
            .revoke_consent(&args.consent_id)
            .map_err(public)?;
        let s = service(&state).map_err(public)?;
        let result = s.map_or(Ok(p::Access::empty()), |s| {
            s.upload_key_requests()
                .revoke(&args.consent_id, Instant::now())
                .map_err(public)
        });
        forward(&mut state);
        result
    }
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    pub(crate) fn allow_agent_upload_key(
        &self,
        window: &str,
        args: Allow,
    ) -> Result<p::Access, BridgeError> {
        if window != MAIN || args.consent_version != args.selection.kind().consent() {
            return Err(BridgeError::invalid());
        }
        self.reconcile();
        let (proof, native, stamp, epoch, end) = {
            let mut state = self.lock();
            self.expire(&mut state, Instant::now());
            self.durable_gate(&state, true)
                .map_err(|_| public(Error::Unavailable))?;
            gui_available(&state).map_err(|_| public(Error::Busy))?;
            state
                .agent_upload_key
                .allow_available(&args.consent_id)
                .map_err(public)?;
            let proof = proof::capture(
                self,
                &state,
                &args.selection,
                args.context_revision,
                args.expected_status_revision,
            )
            .map_err(|_| public(Error::Conflict))?;
            let native = self.service_project_locked(&state, &args.project_id)?;
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)?;
            let context = state.context.as_ref().ok_or_else(BridgeError::invalid)?;
            self.upload_key_saved_input(&state, context, &edit)?;
            let stamp = edit.stamp()?;
            drop(edit);
            let live = lookup_memory::retained_document_bytes(&self.inner, &state)
                .map_err(|_| public(Error::Busy))?
                .checked_add(proof.retained_bytes())
                .and_then(|n| {
                    n.checked_add(
                        std::mem::size_of::<Grant>()
                            + 4 * std::mem::size_of::<usize>()
                            + 32
                            + native.runtime_id.capacity()
                            + native.canonical_root.as_os_str().len(),
                    )
                })
                .ok_or_else(|| public(Error::Busy))?;
            if live > crate::vault_store::RESIDENT_BYTES {
                return Err(public(Error::Busy));
            }
            let epoch = state
                .agent_upload_key
                .begin_allow(&args.consent_id)
                .map_err(public)?;
            let end = proof.end(Instant::now());
            (proof, native, stamp, epoch, end)
        };
        // Actual Host/Service can touch its original private state. No Doc,
        // Edit, Inbox or relay guard survives this source/current lookup.
        let result = (|| {
            let service = self
                .inner
                .bridge
                .application_service
                .identity_request_service(&native)
                .map_err(public)?;
            let point = service
                .upload_key_point(&native.runtime_id)
                .map_err(public)?;
            if point.saved.root != native.canonical_root
                || (point.saved.device, point.saved.inode) != (native.device, native.inode)
            {
                return Err(public(Error::Conflict));
            }
            let mut state = self.lock();
            if state.agent_upload_key.epoch.load(Ordering::SeqCst) != epoch
                || state.agent_upload_key.pending_allow.as_ref() != Some(&args.consent_id)
                || state
                    .agent_upload_key
                    .service
                    .as_ref()
                    .is_some_and(|w| w.as_ptr() != Arc::as_ptr(&service))
            {
                return Err(public(Error::Conflict));
            }
            self.service_allow_current_locked(&state, &native, &stamp)?;
            proof
                .current(self, &state)
                .map_err(|_| public(Error::Conflict))?;
            let identity = Arc::new(());
            let scope = Arc::new(requests::NativeScope {
                project_id: point.saved.project_id,
                runtime_id: native.runtime_id.clone(),
                kind: proof.kind(),
                end: end.min(point.read.end()),
                read: point.read,
                identity: Arc::downgrade(&identity),
                changes: self.inner.changes.clone(),
            });
            let access = service
                .upload_key_requests()
                .allow(scope.clone(), args.consent_id.clone())
                .map_err(public)?;
            state.agent_upload_key.grant = Some(Arc::new(Grant {
                id: args.consent_id.clone(),
                identity,
                scope,
                native,
                edit: stamp,
                proof,
            }));
            state.agent_upload_key.service = Some(Arc::downgrade(&service));
            state.agent_upload_key.pending_allow = None;
            Ok(access)
        })();
        if result.is_err() {
            let mut state = self.lock();
            if state.agent_upload_key.pending_allow.as_ref() == Some(&args.consent_id) {
                state.agent_upload_key.pending_allow = None;
            }
        }
        result
    }
    #[cfg(not(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    )))]
    pub(crate) fn allow_agent_upload_key(
        &self,
        _window: &str,
        _args: Allow,
    ) -> Result<p::Access, BridgeError> {
        Err(public(Error::Unavailable))
    }

    pub(super) fn agent_upload_key_claim(&self) -> Result<Option<requests::Claim>, Error> {
        let s = {
            let state = self.lock();
            if state.agent_upload_key.lost || state.stopping {
                return Ok(None);
            }
            service(&state)?
        };
        let Some(s) = s else {
            return Ok(None);
        };
        s.native_history_current()?;
        let claim = s.upload_key_requests().claim()?;
        if let Some(c) = &claim {
            let mut state = self.lock();
            if state
                .agent_upload_key
                .active
                .as_ref()
                .is_some_and(|l| l.entry().pending())
            {
                c.link().entry().unknown();
                return Err(Error::StateUnknown);
            }
            state.agent_upload_key.active = Some(c.link().clone());
        }
        Ok(claim)
    }
    pub(super) fn run_agent_upload_key(&self, claim: &requests::Claim, #[cfg(feature = "desktop-shell")] app: tauri::AppHandle) -> Result<Option<u32>, Error> {
        let link = claim.link().clone();
        (|| {
            let grant = self
                .lock()
                .agent_upload_key
                .grant
                .clone()
                .ok_or(Error::Conflict)?;
            if grant.id != *link.entry().grant_id()
                || !Arc::ptr_eq(&grant.scope, link.entry().scope())
            {
                return Err(Error::Conflict);
            }
            link.current()?;
            #[cfg(any(
                all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
                all(
                    target_os = "macos",
                    target_pointer_width = "64",
                    any(target_arch = "aarch64", target_arch = "x86_64")
                )
            ))]
            {
                grant.proof.run(self, link, #[cfg(feature = "desktop-shell")] app).map_err(|_| Error::Conflict)
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
                Err(Error::Unavailable)
            }
        })()
    }
    pub(super) fn agent_upload_key_tick(&self) {
        self.reconcile();
        let mut state = self.lock();
        if let Some(g) = state.agent_upload_key.grant.clone() {
            if self
                .service_allow_current_locked(&state, &g.native, &g.edit)
                .is_err()
            {
                stop(&state, Instant::now());
            }
        }
        forward(&mut state);
        retired(self, &state);
    }
    pub(super) fn agent_upload_key_close(&self, lost: bool) {
        let mut state = self.lock();
        stop(&state, Instant::now());
        if lost {
            state.agent_upload_key.lost = true;
            if let Some(l) = &state.agent_upload_key.active {
                l.entry().unknown();
            }
        }
        let _ =
            state
                .agent_upload_key
                .epoch
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    Some(n.saturating_add(1))
                });
        state.agent_upload_key.pending_allow = None;
        forward(&mut state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_revoke_before_first_allow_cut_is_retained_without_stopping_another_nonce() {
        // Actual used State methods, no Document/native grant or receipt is
        // manufactured. A queued RAW Allow has not entered its first cut yet.
        let mut state = State::default();
        let a = Id::parse(&"a".repeat(32)).unwrap();
        let b = Id::parse(&"b".repeat(32)).unwrap();
        state.revoke_consent(&a).unwrap();
        assert_eq!(state.allow_available(&a), Err(Error::Conflict));
        assert_eq!(state.begin_allow(&a), Err(Error::Conflict));
        assert!(state.pending_allow.is_none());
        assert_eq!(state.spent_consents, vec![a.clone()]);
        state.revoke_consent(&a).unwrap();
        assert_eq!(state.spent_consents.len(), 1);

        let epoch = state.begin_allow(&b).unwrap();
        state.revoke_consent(&a).unwrap();
        assert_eq!(state.pending_allow, Some(b.clone()));
        assert_eq!(state.epoch.load(Ordering::SeqCst), epoch);
        state.revoke_consent(&b).unwrap();
        assert!(state.pending_allow.is_none());
        assert_eq!(state.epoch.load(Ordering::SeqCst), epoch + 1);
        assert_eq!(state.begin_allow(&b), Err(Error::Conflict));

        for n in 0..p::CONSENT_LIMIT - 2 {
            state
                .revoke_consent(&Id::parse(&format!("{:032x}", n + 1)).unwrap())
                .unwrap();
        }
        assert_eq!(state.spent_consents.len(), p::CONSENT_LIMIT);
        let c = Id::parse(&"c".repeat(32)).unwrap();
        assert_eq!(state.revoke_consent(&c), Err(Error::Busy));
        assert!(!state.spent_consents.contains(&c));
        assert_eq!(state.begin_allow(&c), Err(Error::Busy));
        state.revoke_consent(&a).unwrap(); // An already recorded exact revoke still works at capacity.
    }
    #[test]
    fn main_requests_are_small_explicit_action_and_consent_pairs_not_status_authority() {
        for (selection, consent) in [
            (
                serde_json::json!({"kind":"prepare-existing","recordId":"c".repeat(32),"expectedRevision":1}),
                p::Kind::PrepareExisting.consent(),
            ),
            (
                serde_json::json!({"kind":"generate-new","declaration":p::DECLARATION}),
                p::Kind::GenerateNew.consent(),
            ),
            (
                serde_json::json!({"kind":"bind-reviewed","previewOperationId":7,"previewToken":"a".repeat(32)}),
                p::Kind::BindReviewed.consent(),
            ),
            (
                serde_json::json!({"kind":"backup-encrypted","recordId":"c".repeat(32),"expectedRevision":1}),
                p::Kind::BackupEncrypted.consent(),
            ),
            (
                serde_json::json!({"kind":"restore-encrypted","declaration":p::RESTORE_DECLARATION}),
                p::Kind::RestoreEncrypted.consent(),
            ),
        ] {
            let mut value = serde_json::json!({"projectId":"project-1","consentId":"b".repeat(32),"contextRevision":1,"expectedStatusRevision":2,"selection":selection,"consentVersion":consent});
            assert!(decode_allow(&serde_json::to_vec(&value).unwrap()).is_ok());
            value["consentVersion"] = "old-or-other-action".into();
            assert!(decode_allow(&serde_json::to_vec(&value).unwrap()).is_err());
            value["consentVersion"] = consent.into();
            for extra in [
                "path", "fields", "password", "recordId", "key", "tool", "backup", "assigned",
            ] {
                value[extra] = "forged".into();
                assert!(decode_allow(&serde_json::to_vec(&value).unwrap()).is_err());
                value.as_object_mut().unwrap().remove(extra);
            }
            value["expectedStatusRevision"] = 0.into();
            assert!(decode_allow(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        assert!(decode_allow(&vec![b' '; p::RAW_LIMIT]).is_err());
        assert!(decode_empty(br#"{"enabled":true}"#).is_err());
        assert!(decode_empty(b"{}").is_ok());
    }
    #[test]
    fn exact_revoke_is_an_address_only_and_duplicate_or_foreign_fields_refuse() {
        let good = format!("{{\"consentId\":\"{}\"}}", "a".repeat(32));
        assert!(decode_revoke(good.as_bytes()).is_ok());
        for value in [
            serde_json::json!({"requestId":"a".repeat(32)}),
            serde_json::json!({"consentId":"a".repeat(32),"renew":true}),
            serde_json::json!({"consentId":"0".repeat(32)}),
        ] {
            assert!(decode_revoke(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        let duplicate = format!(
            "{{\"consentId\":\"{}\",\"consentId\":\"{}\"}}",
            "a".repeat(32),
            "a".repeat(32)
        );
        assert!(decode_revoke(duplicate.as_bytes()).is_err());
    }
}
