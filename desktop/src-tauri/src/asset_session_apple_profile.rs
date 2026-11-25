//! Fixed profile-source and NEW-save work on the existing Asset coordinator.
//! SavedCommand owns provider work and final journal jobs; this original owns
//! the selected native vault checks and the one optional private profile save.
use super::*;
use crate::{
    credential_setup::KeyReference,
    saved_command_owner::{AppleProfileSavePermit, AppleProfileSession, AppleProvisioningClock},
};
use std::sync::OnceLock;
use vault::profile_sources::{self, AppleProfileSources, CheckPoint};

pub(super) struct Work {
    parent: Weak<AppleProfileSession>,
    sources: Mutex<Option<Arc<AppleProfileSources>>>,
    destination: OnceLock<Weak<AppleProfileDestination>>,
    installed: AtomicBool,
    no_dispatch: AtomicBool,
    save_received: AtomicBool,
}
pub(super) struct Request {
    parent: Arc<AppleProfileSession>,
    sources: Arc<AppleProfileSources>,
    receive: oneshot::Receiver<Option<AppleProfileSavePermit>>,
}
impl Work {
    fn parent(&self) -> Option<Arc<AppleProfileSession>> {
        self.parent.upgrade()
    }
    fn sources(&self) -> Result<Arc<AppleProfileSources>, Reason> {
        self.sources
            .try_lock()
            .map_err(|_| Reason::CleanupUnknown)?
            .as_ref()
            .cloned()
            .ok_or(Reason::SourceChanged)
    }
    fn same_parent(&self, parent: &AppleProfileSession) -> bool {
        self.parent()
            .is_some_and(|same| std::ptr::eq(same.as_ref(), parent))
    }
    fn no_more_work(&self, owner: &Arc<OriginalWork>) -> bool {
        self.parent()
            .is_some_and(|parent| parent.no_more_work(owner))
    }
    pub(super) fn own_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
    pub(super) fn census_sources(&self) -> Result<Option<Arc<AppleProfileSources>>, Reason> {
        self.sources
            .try_lock()
            .map(|value| value.clone())
            .map_err(|_| Reason::CleanupUnknown)
    }
}

impl OriginalWork {
    // Only the retained parent clock calls this fixed STOP-only edge.
    pub(crate) fn request_apple_profile_stop(&self) {
        self.signal_stop();
    }
    pub(crate) fn apple_profile_source_checked(&self, parent: &AppleProfileSession) -> bool {
        self.apple_profile.get().is_some_and(|work| {
            work.same_parent(parent)
                && work.sources().is_ok_and(|sources| {
                    sources.owner().is_some_and(|original| {
                        std::ptr::eq(original.as_ref(), self)
                            && sources.initially_checked(&original)
                    })
                })
        })
    }
    pub(super) fn apple_profile_clock(&self) -> Option<&Arc<AppleProvisioningClock>> {
        self.apple_profile_clock.get()
    }
    pub(super) fn apple_profile_stop(&self, reason: Reason, at: Instant) -> Option<Instant> {
        let clock = self.apple_profile_clock()?;
        clock.observe_failure_at(reason, at);
        Some(clock.cleanup_end())
    }
    /// The original no-GO branch calls this, before staging its known refusal.
    /// A status, missing file or dropped invoke cannot set this fact.
    pub(super) fn apple_profile_no_dispatch(&self) {
        if let Some(work) = self.apple_profile.get() {
            work.no_dispatch.store(true, Ordering::SeqCst);
        }
    }
}

fn known_controls(owner: &Arc<OriginalWork>, allow_not_started: bool) -> bool {
    let Some(work) = owner.apple_profile.get() else {
        return false;
    };
    let no_dispatch = allow_not_started && work.no_dispatch.load(Ordering::SeqCst);
    owner.coordinator.try_lock().is_ok_and(|book| {
        book.handle.is_none()
            && (book.receipt == JoinReceipt::Returned
                || no_dispatch
                    && !work.installed.load(Ordering::SeqCst)
                    && book.receipt == JoinReceipt::New)
    }) && owner.child.try_lock().is_ok_and(|book| {
        book.handle.is_none()
            && (book.receipt == JoinReceipt::Returned
                || no_dispatch && book.receipt == JoinReceipt::New)
    }) && owner
        .source
        .try_lock()
        .is_ok_and(|book| book.not_started() || book.settled())
        && owner.gui.settled()
        && owner
            .keyring
            .try_lock()
            .is_ok_and(|book| book.resources_settled())
        && owner.backup_selection.get().is_none()
        && owner.installation.is_none()
}

/// Used only by Apple currentness, never by an unrelated Store/Asset gate.
pub(super) fn current_slot(slot: &Slot, sources: &Arc<AppleProfileSources>) -> bool {
    slot.operation == Operation::AppleProfileSetup
        && slot.target.is_none()
        && slot.reason == Reason::None
        && slot.cleanup_end.is_none()
        && !slot.owner.interrupted()
        && slot.owner.apple_profile.get().is_some_and(|work| {
            work.installed.load(Ordering::SeqCst)
                && work.sources().is_ok_and(|same| Arc::ptr_eq(&same, sources))
        })
}

pub(super) fn retirement_deferred(slot: &Slot) -> bool {
    slot.owner
        .apple_profile
        .get()
        .is_some_and(|work| !work.no_more_work(&slot.owner))
}
pub(super) fn release_deferred(owner: &Arc<OriginalWork>) -> bool {
    owner
        .apple_profile
        .get()
        .is_some_and(|work| !work.no_more_work(owner))
}

/// Read-only or failed-before-destination work has no destination permit.
/// Its SAME completed parent still has to relinquish the selected source
/// checks before the existing vault release continuation may run.
pub(super) fn source_release_ready(slot: &Slot) -> bool {
    slot.operation == Operation::AppleProfileSetup
        && slot.owner.apple_profile.get().is_some_and(|work| {
            work.destination.get().is_none()
                && !work.save_received.load(Ordering::SeqCst)
                && work.no_more_work(&slot.owner)
                && known_controls(&slot.owner, true)
        })
}

/// Keep already-returned, non-publishing DATA in the SAME slot while its
/// original cleanup-only continuation closes the vault. Requiring it to be
/// removed first would cycle with private retirement, which needs that close.
/// `retained` is the actual source/destination parent proof computed by the
/// existing vault gate, not a status or a caller's claim of settlement.
pub(super) fn cleanup_staged_allowed(slot: &Slot, retained: bool) -> bool {
    slot.staged.is_none()
        || retained
            && slot.operation == Operation::AppleProfileSetup
            && matches!(
                slot.staged.as_ref(),
                Some(Staged::Refused(_)) | Some(Staged::Committed { bind: None })
            )
}

/// The actual original retirement calls this OFF Doc, after all work-capable
/// jobs and actual child/coordinator joins. It never releases a native Store
/// handle by dropping an Arc; the original vault continuation does that first.
pub(super) fn dispose_sources(owner: &Arc<OriginalWork>) -> bool {
    let Some(work) = owner.apple_profile.get() else {
        return true;
    };
    if !work.no_more_work(owner) || !known_controls(owner, true) {
        return false;
    }
    let Ok(vault) = owner.vault.try_lock() else {
        return false;
    };
    if !vault.settled() || vault.apple_profile_blocks_reuse() {
        return false;
    }
    drop(vault);
    let Ok(mut sources) = work.sources.try_lock() else {
        return false;
    };
    sources.take();
    true
}

#[cfg(feature = "desktop-shell")]
impl DocumentBinding {
    pub(in crate::asset_session) fn attach_apple_profile(
        &self,
        state: &mut DocumentState,
        input: &Arc<AppleProvisioningDocumentInput>,
        parent: &Arc<AppleProfileSession>,
    ) -> Result<oneshot::Sender<()>, BridgeError> {
        let sources = input
            .profile_sources()
            .ok_or_else(crate::apple_provisioning_protocol::invalid)?
            .clone();
        if !sources.current(self, state) {
            return Err(profile_error(Reason::ContextStale));
        }
        let id = self
            .next_operation(state)
            .map_err(|e| profile_error(e.reason))?;
        let owner = OriginalWork::new(id, false, Arc::downgrade(&self.inner));
        // The actual SavedSession and its reserved private receiver already
        // exist. Keep this Arc in the original input before reservation/install
        // can fail; no new destination can be abandoned by an invoke waiter.
        input.retain_profile_asset(&owner)?;
        let (dispatch, receive) = oneshot::channel();
        parent.attach(&owner, dispatch)?;
        owner
            .apple_profile_clock
            .set(parent.clock().clone())
            .map_err(|_| BridgeError::cleanup_unknown())?;
        owner
            .apple_profile
            .set(Work {
                parent: Arc::downgrade(parent),
                sources: Mutex::new(Some(sources.clone())),
                destination: OnceLock::new(),
                installed: AtomicBool::new(false),
                no_dispatch: AtomicBool::new(false),
                save_received: AtomicBool::new(false),
            })
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if let Err(reason) = profile_sources::attach(state, &owner, &sources) {
            owner.apple_profile_no_dispatch();
            parent.clock().observe_failure_at(reason, Instant::now());
            return Err(profile_error(reason));
        }
        let mut slot = Slot::new(
            owner.clone(),
            Operation::AppleProfileSetup,
            Some(sources.native().clone()),
            None,
            None,
        );
        slot.kind = input
            .context()
            .mode
            .profile_save()
            .then_some(Kind::AppleProfile);
        let request = Request {
            parent: parent.clone(),
            sources: sources.clone(),
            receive,
        };
        let start = match self.install(state, slot, Job::AppleProfile(request)) {
            Ok(start) => start,
            Err(error) => {
                // Only a genuinely unregistered original is a known no-GO.
                // Partial install/retirement failure retains the actual Arc.
                if owner
                    .coordinator
                    .try_lock()
                    .is_ok_and(|book| book.receipt == JoinReceipt::New && book.handle.is_none())
                    && owner.retired.load(Ordering::SeqCst)
                    && state
                        .slot
                        .as_ref()
                        .is_none_or(|slot| !Arc::ptr_eq(&slot.owner, &owner))
                {
                    owner.apple_profile_no_dispatch();
                }
                parent
                    .clock()
                    .observe_failure_at(error.reason, Instant::now());
                return Err(profile_error(error.reason));
            }
        };
        owner
            .apple_profile
            .get()
            .ok_or_else(BridgeError::cleanup_unknown)?
            .installed
            .store(true, Ordering::SeqCst);
        if input.context().mode.profile_save() {
            let destination = AppleProfileDestination::reserve(
                self,
                state,
                &owner,
                sources.p12().clone(),
                crate::bridge::ProjectRoster {
                    generation: sources.roster().generation,
                    roots: sources.roster().roots.clone(),
                },
                crate::vault_crypto::APPLE_PROFILE_CRYPTO_BYTES,
            )
            .map_err(|reason| {
                parent.clock().observe_failure_at(reason, Instant::now());
                profile_error(reason)
            })?;
            // Reserve BEFORE provider GO, but attach both original owners before
            // exposing its comparison reference. Neither reference grants save.
            owner
                .vault
                .try_lock()
                .map_err(|_| BridgeError::cleanup_unknown())?
                .attach_apple_profile(destination.clone())
                .map_err(profile_error)?;
            parent.attach_destination(&owner, &destination)?;
            owner
                .apple_profile
                .get()
                .ok_or_else(BridgeError::cleanup_unknown)?
                .destination
                .set(Arc::downgrade(&destination))
                .map_err(|_| BridgeError::cleanup_unknown())?;
        }
        Ok(start)
    }
}

fn profile_error(reason: Reason) -> BridgeError {
    if reason == Reason::CleanupUnknown {
        BridgeError::cleanup_unknown()
    } else {
        BridgeError::new("apple_provisioning_credentials", "The selected signing files changed or their secure operation did not finish. Check the original task before trying again.")
    }
}

#[cfg(feature = "desktop-shell")]
pub(super) async fn run(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
    request: Request,
) -> Staged {
    if owner.interrupted() {
        owner.apple_profile_no_dispatch();
        return Staged::Refused(Reason::UserCancelled);
    }
    if let Err(reason) =
        profile_sources::check(document, owner, &request.sources, CheckPoint::Initial).await
    {
        if reason != Reason::CleanupUnknown
            && request.sources.no_child_entered()
            && owner
                .child
                .try_lock()
                .is_ok_and(|book| book.receipt == JoinReceipt::New && book.handle.is_none())
        {
            owner.apple_profile_no_dispatch();
        }
        request
            .parent
            .clock()
            .observe_failure_at(reason, Instant::now());
        return Staged::Refused(reason);
    }
    if request.parent.source_check_returned(owner).is_err() {
        return Staged::Refused(Reason::ContextStale);
    }
    let mut receive = request.receive;
    // This waits on the already-registered original. Normal terminal pipe STOP
    // is unrelated; the shared clock records actual user/native first-F only.
    let permit = loop {
        let notified = owner.wake.notified();
        if owner.interrupted() {
            return Staged::Refused(Reason::UserCancelled);
        }
        tokio::select! { biased;
            result = &mut receive => match result {
                Ok(value) => break value,
                Err(_) => return Staged::Refused(Reason::CleanupUnknown),
            },
            _ = tokio::time::sleep_until(request.parent.clock().work_end().into()) => {
                request.parent.clock().observe_failure_at(Reason::Deadline, request.parent.clock().work_end());
                return Staged::Refused(Reason::Deadline);
            },
            _ = notified => {},
        }
    };
    let Some(permit) = permit else {
        // This is a no-save return, not credential assignment or provider
        // success. The Saved parent still owns its separate result and finality.
        return Staged::Committed { bind: None };
    };
    let Some(work) = owner.apple_profile.get() else {
        return Staged::Refused(Reason::CleanupUnknown);
    };
    work.save_received.store(true, Ordering::SeqCst);
    let Some(destination) = work.destination.get().and_then(Weak::upgrade) else {
        return Staged::Refused(Reason::CleanupUnknown);
    };
    let save = match destination.claim_save(owner, permit) {
        Ok(save) => save,
        Err(reason) => return Staged::Refused(reason),
    };
    match vault::apple_profile::run(document, owner, save).await {
        Ok(staged) => staged,
        Err(reason) => Staged::Refused(reason),
    }
}

#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) async fn recheck(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
    point: CheckPoint,
) -> Result<(), BridgeError> {
    let sources = owner
        .apple_profile
        .get()
        .ok_or_else(BridgeError::cleanup_unknown)?
        .sources()
        .map_err(profile_error)?;
    profile_sources::check(document, owner, &sources, point)
        .await
        .map_err(profile_error)
}

#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) async fn joined(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
) -> Result<Option<KeyReference>, BridgeError> {
    let work = owner
        .apple_profile
        .get()
        .ok_or_else(BridgeError::cleanup_unknown)?;
    let parent = work.parent().ok_or_else(BridgeError::cleanup_unknown)?;
    loop {
        let notify = owner.wake.notified();
        document.reconcile();
        if known_controls(owner, true) {
            let saved = work
                .destination
                .get()
                .and_then(Weak::upgrade)
                .and_then(|d| d.saved_reference_data());
            if work.save_received.load(Ordering::SeqCst) && saved.is_none() {
                return Err(BridgeError::cleanup_unknown());
            }
            return Ok(saved);
        }
        if Instant::now() >= parent.clock().cleanup_end() {
            return Err(BridgeError::cleanup_unknown());
        }
        tokio::select! {
            _ = notify => {},
            _ = tokio::time::sleep(Duration::from_millis(20)) => {},
        }
    }
}

#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) async fn retired(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
) -> Result<(), BridgeError> {
    let work = owner
        .apple_profile
        .get()
        .ok_or_else(BridgeError::cleanup_unknown)?;
    let parent = work.parent().ok_or_else(BridgeError::cleanup_unknown)?;
    if !parent.no_more_work(owner) {
        return Err(BridgeError::cleanup_unknown());
    }
    loop {
        let notify = owner.wake.notified();
        document.reconcile();
        if !work.installed.load(Ordering::SeqCst) {
            // Exact failed-before-install branch: no coordinator or child was
            // registered and no destination exists. Release only borrowed
            // DATA; the original Document still owns its unchanged StoreBook.
            if work.no_dispatch.load(Ordering::SeqCst)
                && known_controls(owner, true)
                && work.destination.get().is_none()
                && !work.save_received.load(Ordering::SeqCst)
                && profile_sources::retire_unentered(owner)
                && dispose_sources(owner)
            {
                return Ok(());
            }
            return Err(BridgeError::cleanup_unknown());
        }
        if owner.resources_settled()
            && owner
                .retirement
                .try_lock()
                .is_ok_and(|r| lookup_memory::retirement_empty(&r))
            && dispose_sources(owner)
        {
            return Ok(());
        }
        if Instant::now() >= parent.clock().cleanup_end() {
            return Err(BridgeError::cleanup_unknown());
        }
        tokio::select! {
            _ = notify => {},
            _ = tokio::time::sleep(Duration::from_millis(20)) => {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot() -> Slot {
        Slot::new(
            OriginalWork::new(77, false, Weak::new()),
            Operation::AppleProfileSetup,
            None,
            None,
            None,
        )
    }

    #[test]
    fn cleanup_retains_only_the_two_closed_profile_data_shapes() {
        // Actual Slot DATA and the used guard, not a forged parent join or a
        // native release. The real caller obtains `retained` from originals.
        for staged in [
            Staged::Refused(Reason::UserCancelled),
            Staged::Committed { bind: None },
        ] {
            let mut slot = slot();
            slot.staged = Some(staged);
            slot.stop(Reason::Shutdown, Instant::now());
            assert!(!cleanup_staged_allowed(&slot, false));
            let before = slot.staged.as_ref().unwrap() as *const Staged;
            assert!(cleanup_staged_allowed(&slot, true));
            assert_eq!(before, slot.staged.as_ref().unwrap() as *const Staged);
            assert!(slot.owner.stopped()); // Cleanup never clears STOP.
            slot.operation = Operation::Commit;
            assert!(!cleanup_staged_allowed(&slot, true));
        }
    }

    #[test]
    fn unknown_or_vault_publication_cannot_use_the_cleanup_exception() {
        let mut slot = slot();
        slot.staged = Some(Staged::Refused(Reason::CleanupUnknown));
        slot.phase = Phase::Unknown;
        assert!(!cleanup_staged_allowed(&slot, false));
        slot.staged = Some(Staged::Vault(vault::Staged::Released));
        assert!(!cleanup_staged_allowed(&slot, true));
        assert!(matches!(slot.staged, Some(Staged::Vault(_))));
        slot.staged = None;
        assert!(cleanup_staged_allowed(&slot, false)); // Old empty-slot path.
    }
}
