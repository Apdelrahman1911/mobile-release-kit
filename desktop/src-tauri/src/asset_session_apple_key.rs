//! One local key operation on the existing Asset coordinator. The original
//! SavedSession owns the generator, private receive and journal; this exact
//! original owns the complete vault checks and optional NEW+readback child.
use super::*;
use crate::{
    credential_setup::KeyReference,
    saved_command_owner::{AppleKeySavePermit, AppleKeySession},
};
use std::sync::OnceLock;
use vault::{
    distribution_key::{self, AppleDistributionKeyInventory, InventoryPoint},
    key_sources::{self, AppleKeySources},
};

pub(super) struct Work {
    parent: Weak<AppleKeySession>,
    sources: Mutex<Option<Arc<AppleKeySources>>>,
    destination: OnceLock<Weak<AppleDistributionKeyDestination>>,
    installed: AtomicBool,
    no_dispatch: AtomicBool,
    save_received: AtomicBool,
}
pub(super) struct Request {
    parent: Arc<AppleKeySession>,
    sources: Arc<AppleKeySources>,
    receive: oneshot::Receiver<Option<AppleKeySavePermit>>,
    prepare: bool,
}
impl Work {
    fn parent(&self) -> Option<Arc<AppleKeySession>> {
        self.parent.upgrade()
    }
    fn sources(&self) -> Result<Arc<AppleKeySources>, Reason> {
        self.sources
            .try_lock()
            .map_err(|_| Reason::CleanupUnknown)?
            .as_ref()
            .cloned()
            .ok_or(Reason::SourceChanged)
    }
    fn same_parent(&self, parent: &AppleKeySession) -> bool {
        self.parent()
            .is_some_and(|same| std::ptr::eq(same.as_ref(), parent))
    }
    fn no_more_work(&self, owner: &Arc<OriginalWork>) -> bool {
        self.parent()
            .is_some_and(|parent| parent.no_more_work(owner))
    }
    pub(super) fn census_sources(&self) -> Result<Option<Arc<AppleKeySources>>, Reason> {
        self.sources
            .try_lock()
            .map(|held| held.clone())
            .map_err(|_| Reason::CleanupUnknown)
    }
    pub(super) fn own_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}
impl OriginalWork {
    pub(in crate::asset_session) fn apple_key_parent(&self) -> Option<Arc<AppleKeySession>> {
        self.apple_key.get()?.parent()
    }
    pub(crate) fn apple_key_source_checked(&self, parent: &AppleKeySession) -> bool {
        self.apple_key_checked(parent, InventoryPoint::Initial)
    }
    pub(crate) fn apple_key_before_pending_checked(&self, parent: &AppleKeySession) -> bool {
        self.apple_key_checked(parent, InventoryPoint::BeforePending)
    }
    fn apple_key_checked(&self, parent: &AppleKeySession, point: InventoryPoint) -> bool {
        self.apple_key.get().is_some_and(|work| {
            work.same_parent(parent)
                && work.sources().is_ok_and(|sources| {
                    sources.owner().is_some_and(|owner| {
                        std::ptr::eq(owner.as_ref(), self) && sources.checked(&owner, point)
                    })
                })
        })
    }
    pub(super) fn apple_key_no_dispatch(&self) {
        if let Some(work) = self.apple_key.get() {
            work.no_dispatch.store(true, Ordering::SeqCst);
        }
    }
}
fn known_controls(owner: &Arc<OriginalWork>, allow_not_started: bool) -> bool {
    let Some(work) = owner.apple_key.get() else {
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
pub(super) fn current_slot(slot: &Slot, sources: &Arc<AppleKeySources>) -> bool {
    slot.operation == Operation::PrepareAppleDistributionKey
        && slot.target.is_none()
        && slot.reason == Reason::None
        && slot.cleanup_end.is_none()
        && !slot.owner.interrupted()
        && slot.owner.apple_key.get().is_some_and(|work| {
            work.installed.load(Ordering::SeqCst)
                && work.sources().is_ok_and(|same| Arc::ptr_eq(&same, sources))
        })
}
pub(super) fn retirement_deferred(slot: &Slot) -> bool {
    slot.owner
        .apple_key
        .get()
        .is_some_and(|work| !work.no_more_work(&slot.owner))
}
pub(super) fn release_deferred(owner: &Arc<OriginalWork>) -> bool {
    owner
        .apple_key
        .get()
        .is_some_and(|work| !work.no_more_work(owner))
}
pub(super) fn source_release_ready(slot: &Slot) -> bool {
    slot.operation == Operation::PrepareAppleDistributionKey
        && slot.owner.apple_key.get().is_some_and(|work| {
            work.destination.get().is_none()
                && !work.save_received.load(Ordering::SeqCst)
                && work.no_more_work(&slot.owner)
                && known_controls(&slot.owner, true)
        })
}
pub(super) fn cleanup_staged_allowed(slot: &Slot, retained: bool) -> bool {
    slot.staged.is_none()
        || retained
            && slot.operation == Operation::PrepareAppleDistributionKey
            && matches!(
                slot.staged.as_ref(),
                Some(Staged::Refused(_)) | Some(Staged::Committed { bind: None })
            )
}
pub(super) fn dispose_sources(owner: &Arc<OriginalWork>) -> bool {
    let Some(work) = owner.apple_key.get() else {
        return true;
    };
    if !work.no_more_work(owner) || !known_controls(owner, true) {
        return false;
    }
    let Ok(vault) = owner.vault.try_lock() else {
        return false;
    };
    if !vault.settled() || vault.apple_distribution_key_blocks_reuse() {
        return false;
    }
    drop(vault);
    let Ok(mut sources) = work.sources.try_lock() else {
        return false;
    };
    sources.take();
    true
}
fn key_error(reason: Reason) -> BridgeError {
    if reason == Reason::CleanupUnknown {
        BridgeError::cleanup_unknown()
    } else {
        BridgeError::new("apple_provisioning_key", "The selected secure store changed or key preparation did not finish. Preserve the previous setup and check its status.")
    }
}
#[cfg(feature = "desktop-shell")]
fn refused(parent: &AppleKeySession, reason: Reason) -> Staged {
    // Record every loss before handing the same coordinator its staged
    // result. A prior known STOP must not hide a later source/unknown failure.
    parent.clock().observe_failure_at(reason, Instant::now());
    Staged::Refused(reason)
}

#[cfg(feature = "desktop-shell")]
impl DocumentBinding {
    pub(in crate::asset_session) fn attach_apple_key(
        &self,
        state: &mut DocumentState,
        input: &Arc<AppleProvisioningDocumentInput>,
        parent: &Arc<AppleKeySession>,
    ) -> Result<oneshot::Sender<()>, BridgeError> {
        if !input.context().mode.local_key() {
            return Err(crate::apple_provisioning_protocol::invalid());
        }
        let sources = input
            .key_sources()
            .ok_or_else(crate::apple_provisioning_protocol::invalid)?
            .clone();
        if !sources.current(self, state) {
            return Err(key_error(Reason::ContextStale));
        }
        let id = self
            .next_operation(state)
            .map_err(|error| key_error(error.reason))?;
        let owner = OriginalWork::new(id, false, Arc::downgrade(&self.inner));
        input.retain_key_asset(&owner)?; // Retained BEFORE attachment/reservation/install.
        let (dispatch, receive) = oneshot::channel();
        parent.attach(&owner, dispatch)?;
        owner
            .apple_profile_clock
            .set(parent.clock().clone())
            .map_err(|_| BridgeError::cleanup_unknown())?;
        owner
            .apple_key
            .set(Work {
                parent: Arc::downgrade(parent),
                sources: Mutex::new(Some(sources.clone())),
                destination: OnceLock::new(),
                installed: AtomicBool::new(false),
                no_dispatch: AtomicBool::new(false),
                save_received: AtomicBool::new(false),
            })
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if let Err(reason) = key_sources::attach(state, &owner, &sources) {
            owner.apple_key_no_dispatch();
            parent.clock().observe_failure_at(reason, Instant::now());
            return Err(key_error(reason));
        }
        let prepare = input.context().mode == crate::apple_provisioning_protocol::Mode::KeyPrepare;
        let mut slot = Slot::new(
            owner.clone(),
            Operation::PrepareAppleDistributionKey,
            Some(sources.native().clone()),
            None,
            None,
        );
        slot.kind = prepare.then_some(Kind::AppleDistributionKey);
        let start = match self.install(
            state,
            slot,
            Job::AppleKey(Request {
                parent: parent.clone(),
                sources: sources.clone(),
                receive,
                prepare,
            }),
        ) {
            Ok(start) => start,
            Err(error) => {
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
                    owner.apple_key_no_dispatch();
                }
                parent
                    .clock()
                    .observe_failure_at(error.reason, Instant::now());
                return Err(key_error(error.reason));
            }
        };
        owner
            .apple_key
            .get()
            .ok_or_else(BridgeError::cleanup_unknown)?
            .installed
            .store(true, Ordering::SeqCst);
        // This captures DATA only; Initial runs the actual original full-EOF,
        // ACL/read-witness check after this coordinator's GO. No destination
        // is reserved until that genuine initial child has joined.
        let inventory = AppleDistributionKeyInventory::capture(
            self,
            state,
            &owner,
            crate::bridge::ProjectRoster {
                generation: sources.roster().generation,
                roots: sources.roster().roots.clone(),
            },
        )
        .map_err(key_error)?;
        sources
            .bind_inventory(&owner, inventory)
            .map_err(key_error)?;
        Ok(start)
    }
}

#[cfg(feature = "desktop-shell")]
pub(super) async fn run(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
    request: Request,
) -> Staged {
    if owner.interrupted() {
        owner.apple_key_no_dispatch();
        return refused(
            &request.parent,
            request
                .parent
                .clock()
                .failure()
                .map(|(reason, _)| reason)
                .unwrap_or(Reason::Deadline),
        );
    }
    let Some(inventory) = request.sources.inventory() else {
        return refused(&request.parent, Reason::CleanupUnknown);
    };
    if let Err(reason) =
        distribution_key::check_inventory(document, owner, inventory, InventoryPoint::Initial).await
    {
        request
            .parent
            .clock()
            .observe_failure_at(reason, Instant::now());
        return Staged::Refused(reason);
    }
    if request.prepare {
        let reserved = (|| {
            let mut state = document.lock();
            if !request.sources.current(document, &state) || !inventory.generation_empty(owner) {
                return Err(Reason::SourceChanged);
            }
            // Destination construction is within the original already charged
            // fixed key quote. It neither writes nor creates a private key.
            let destination = AppleDistributionKeyDestination::reserve(
                document,
                &mut state,
                owner,
                inventory.clone(),
                crate::vault_crypto::APPLE_KEY_CRYPTO_BYTES,
            )?;
            owner
                .vault
                .try_lock()
                .map_err(|_| Reason::CleanupUnknown)?
                .attach_apple_distribution_key(destination.clone())?;
            request
                .parent
                .attach_destination(owner, &destination)
                .map_err(|_| Reason::CleanupUnknown)?;
            owner
                .apple_key
                .get()
                .ok_or(Reason::CleanupUnknown)?
                .destination
                .set(Arc::downgrade(&destination))
                .map_err(|_| Reason::CleanupUnknown)
        })();
        if let Err(reason) = reserved {
            request
                .parent
                .clock()
                .observe_failure_at(reason, Instant::now());
            return Staged::Refused(reason);
        }
    }
    if request.parent.source_check_returned(owner).is_err() {
        return refused(&request.parent, Reason::ContextStale);
    }
    let mut receive = request.receive;
    let permit = loop {
        let notified = owner.wake.notified();
        let now = Instant::now();
        if now >= request.parent.clock().work_end() && request.parent.clock().failure().is_none() {
            request
                .parent
                .clock()
                .observe_failure_at(Reason::Deadline, request.parent.clock().work_end());
        }
        let end = if request.prepare {
            // Only the predeclared one-use slot waits through a known STOP.
            // The opaque permit's full path independently decides whether a
            // returned key can still be preserved. No generator GO reopens.
            let Some(end) = request.parent.clock().key_preservation_end() else {
                return refused(
                    &request.parent,
                    request
                        .parent
                        .clock()
                        .failure()
                        .map(|(reason, _)| reason)
                        .unwrap_or(Reason::CleanupUnknown),
                );
            };
            end
        } else {
            if owner.interrupted() {
                return refused(
                    &request.parent,
                    request
                        .parent
                        .clock()
                        .failure()
                        .map(|(reason, _)| reason)
                        .unwrap_or(Reason::Deadline),
                );
            }
            request.parent.clock().work_end()
        };
        if now >= end {
            return refused(&request.parent, Reason::Deadline);
        }
        tokio::select! { biased;
            returned = &mut receive => match returned {
                Ok(permit) => break permit,
                Err(_) => return refused(&request.parent, Reason::CleanupUnknown),
            },
            _ = tokio::time::sleep_until(end.into()) => {},
            _ = notified => {},
        }
    };
    let Some(permit) = permit else {
        return Staged::Committed { bind: None };
    };
    if !request.prepare {
        return refused(&request.parent, Reason::CleanupUnknown);
    }
    let Some(work) = owner.apple_key.get() else {
        return refused(&request.parent, Reason::CleanupUnknown);
    };
    work.save_received.store(true, Ordering::SeqCst);
    let Some(destination) = work.destination.get().and_then(Weak::upgrade) else {
        return refused(&request.parent, Reason::CleanupUnknown);
    };
    let save = match destination.claim_save(owner, permit) {
        Ok(value) => value,
        Err(reason) => return refused(&request.parent, reason),
    };
    match distribution_key::key_store::run(document, owner, save).await {
        Ok(staged) => staged,
        Err(reason) => refused(&request.parent, reason),
    }
}

#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) async fn recheck_before_pending(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
) -> Result<(), BridgeError> {
    let work = owner
        .apple_key
        .get()
        .ok_or_else(BridgeError::cleanup_unknown)?;
    let sources = work.sources().map_err(key_error)?;
    let inventory = sources
        .inventory()
        .ok_or_else(BridgeError::cleanup_unknown)?;
    distribution_key::check_inventory(document, owner, inventory, InventoryPoint::BeforePending)
        .await
        .map_err(key_error)?;
    work.parent()
        .ok_or_else(BridgeError::cleanup_unknown)?
        .before_pending_check_returned(owner)
}

#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) async fn joined(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
) -> Result<Option<KeyReference>, BridgeError> {
    let work = owner
        .apple_key
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
                .and_then(|destination| destination.published_reference_data(owner));
            // Full readback alone is insufficient: the original coordinator
            // must have published this exact NEW row under its same guard.
            if work.save_received.load(Ordering::SeqCst) && saved.is_none() {
                return Err(BridgeError::cleanup_unknown());
            }
            return Ok(saved);
        }
        if Instant::now() >= parent.clock().cleanup_end() {
            return Err(BridgeError::cleanup_unknown());
        }
        tokio::select! { _ = notify => {}, _ = tokio::time::sleep(Duration::from_millis(20)) => {} }
    }
}

#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) async fn retired(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
) -> Result<(), BridgeError> {
    let work = owner
        .apple_key
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
            if work.no_dispatch.load(Ordering::SeqCst)
                && known_controls(owner, true)
                && work.destination.get().is_none()
                && !work.save_received.load(Ordering::SeqCst)
                && key_sources::retire_unentered(owner)
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
                .is_ok_and(|retired| lookup_memory::retirement_empty(&retired))
            && dispose_sources(owner)
        {
            return Ok(());
        }
        if Instant::now() >= parent.clock().cleanup_end() {
            return Err(BridgeError::cleanup_unknown());
        }
        tokio::select! { _ = notify => {}, _ = tokio::time::sleep(Duration::from_millis(20)) => {} }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot() -> Slot {
        Slot::new(
            OriginalWork::new(79, false, Weak::new()),
            Operation::PrepareAppleDistributionKey,
            None,
            None,
            None,
        )
    }

    #[test]
    fn original_cleanup_guard_keeps_staged_data_and_stop_without_minting_no_generation() {
        // The real caller obtains `retained` from the actual parent and Asset
        // books. This only tests its closed staged-DATA guard, not those joins.
        for staged in [
            Staged::Refused(Reason::UserCancelled),
            Staged::Committed { bind: None },
        ] {
            let mut slot = slot();
            slot.staged = Some(staged);
            slot.stop(Reason::Shutdown, Instant::now());
            let retained = slot.staged.as_ref().unwrap() as *const Staged;
            assert!(!cleanup_staged_allowed(&slot, false));
            assert!(cleanup_staged_allowed(&slot, true));
            assert_eq!(retained, slot.staged.as_ref().unwrap() as *const Staged);
            assert!(slot.owner.stopped());
            assert!(!source_release_ready(&slot)); // No original parent/joins.
            slot.operation = Operation::UseAppleDistributionKey;
            assert!(!cleanup_staged_allowed(&slot, true));
        }
    }

    #[test]
    fn missing_original_or_vault_publication_never_becomes_the_key_cleanup_cut() {
        let mut slot = slot();
        slot.staged = Some(Staged::Refused(Reason::CleanupUnknown));
        slot.phase = Phase::Unknown;
        slot.settlement = Settlement::Unknown;
        assert!(!known_controls(&slot.owner, true));
        assert!(!source_release_ready(&slot));
        assert!(!cleanup_staged_allowed(&slot, false));
        slot.staged = Some(Staged::Vault(vault::Staged::Released));
        assert!(!cleanup_staged_allowed(&slot, true));
        assert!(matches!(slot.staged, Some(Staged::Vault(_))));
        slot.staged = None;
        assert!(cleanup_staged_allowed(&slot, false)); // Existing empty path.
    }
}
