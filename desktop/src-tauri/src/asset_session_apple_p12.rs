//! Fixed P12 arm of the ORIGINAL Apple key Asset coordinator. No new task,
//! channel, vault session, clock, source walk, or assignment is created here.
use super::*;
use crate::apple_provisioning_protocol as wire;
use crate::saved_command_owner::AppleP12SavePermit;
use vault::{distribution_key::p12::AppleP12Destination, key_sources::p12::CheckPoint};

pub(super) struct P12Work {
    destination: OnceLock<Weak<AppleP12Destination>>,
}
impl P12Work {
    pub(super) fn new() -> Self {
        Self {
            destination: OnceLock::new(),
        }
    }
    fn destination(&self) -> Option<Arc<AppleP12Destination>> {
        self.destination.get()?.upgrade()
    }
    pub(super) fn has_destination(&self) -> bool {
        self.destination.get().is_some()
    }
}

/// The same coordinator has already completed the genuine stored-key Load
/// and source check. P12 selection checks and the complete NEW inventory use
/// its existing native Child and returned receipt, never a snapshot DTO.
#[cfg(feature = "desktop-shell")]
pub(super) async fn initial(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
    request: &Request,
) -> Result<(), Reason> {
    if !request.p12 || request.parent.p12_mode().is_none() {
        return Err(Reason::SourceRefused);
    }
    key_sources::p12::check(document, owner, &request.sources, CheckPoint::BeforeWork).await?;
    if request.parent.p12_mode() != Some(wire::Mode::P12Save) {
        return Ok(());
    }
    let loan = request
        .sources
        .certificate_loan()
        .ok_or(Reason::SourceRefused)?;
    let inventory = {
        let state = document.lock();
        if !request.sources.current(document, &state) {
            return Err(Reason::ContextStale);
        }
        AppleDistributionKeyInventory::capture_p12(document, &state, owner, &loan)?
    };
    request.sources.bind_inventory(owner, inventory.clone())?;
    distribution_key::check_inventory(document, owner, &inventory, InventoryPoint::Initial).await?;
    let mut state = document.lock();
    if !request.sources.current(document, &state) {
        return Err(Reason::ContextStale);
    }
    let destination = AppleP12Destination::reserve(document, &mut state, owner, loan, inventory)?;
    // The real vault Work retains the destination/password BEFORE publishing
    // either weak parent link or making the private writer available.
    owner
        .vault
        .try_lock()
        .map_err(|_| Reason::CleanupUnknown)?
        .attach_apple_p12_destination(destination.clone())?;
    let work = owner.apple_key.get().ok_or(Reason::CleanupUnknown)?;
    work.p12
        .as_ref()
        .ok_or(Reason::CleanupUnknown)?
        .destination
        .set(Arc::downgrade(&destination))
        .map_err(|_| Reason::CleanupUnknown)?;
    request
        .parent
        .attach_p12_destination(owner, &destination)
        .map_err(|_| Reason::CleanupUnknown)
}

pub(super) fn source_checked(owner: &OriginalWork, parent: &AppleKeySession) -> bool {
    owner.apple_key.get().is_some_and(|work| {
        work.p12.is_some()
            && work.same_parent(parent)
            && work.sources().is_ok_and(|sources| {
                sources.owner().is_some_and(|original| {
                    std::ptr::eq(original.as_ref(), owner)
                        && sources.certificate_checked(
                            &original,
                            key_sources::certificate::CheckPoint::Initial,
                        )
                        && sources.p12_checked(&original, CheckPoint::BeforeWork)
                        && (parent.p12_mode() != Some(wire::Mode::P12Save)
                            || sources.checked(&original, InventoryPoint::Initial)
                                && work.p12.as_ref().is_some_and(|p12| p12.has_destination()))
                })
            })
    })
}

impl OriginalWork {
    pub(in crate::asset_session) fn apple_p12_source_matches_p8(
        &self,
        source: &vault::BoundLoan,
    ) -> bool {
        self.apple_key.get().is_some_and(|work| {
            work.p12.is_some()
                && work
                    .sources()
                    .is_ok_and(|sources| sources.p12_matches_p8(source))
        })
    }
    pub(crate) fn apple_p12_before_pending_checked(&self, parent: &AppleKeySession) -> bool {
        source_checked(self, parent)
            && self.apple_key.get().is_some_and(|work| {
                work.sources().is_ok_and(|sources| {
                    sources.owner().is_some_and(|owner| {
                        std::ptr::eq(owner.as_ref(), self)
                            && sources.checked(&owner, InventoryPoint::BeforePending)
                            && sources.certificate_checked(
                                &owner,
                                key_sources::certificate::CheckPoint::BeforePending,
                            )
                    })
                })
            })
    }
}

#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) async fn before_pending(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
) -> Result<(), BridgeError> {
    let work = owner
        .apple_key
        .get()
        .ok_or_else(BridgeError::cleanup_unknown)?;
    let parent = work.parent().ok_or_else(BridgeError::cleanup_unknown)?;
    if parent.p12_mode() != Some(wire::Mode::P12Save) || work.p12.is_none() {
        return Err(wire::invalid());
    }
    let sources = work.sources().map_err(key_error)?;
    key_sources::certificate::check(
        document,
        owner,
        &sources,
        key_sources::certificate::CheckPoint::BeforePending,
    )
    .await
    .map_err(key_error)?;
    let inventory = sources.inventory().ok_or_else(wire::invalid)?;
    distribution_key::check_inventory(document, owner, inventory, InventoryPoint::BeforePending)
        .await
        .map_err(key_error)?;
    parent.p12_before_pending_returned(owner)
}

#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) async fn after_worker(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
) -> Result<(), BridgeError> {
    let work = owner
        .apple_key
        .get()
        .ok_or_else(BridgeError::cleanup_unknown)?;
    if work.p12.is_none() {
        return Err(wire::invalid());
    }
    key_sources::p12::check(
        document,
        owner,
        &work.sources().map_err(key_error)?,
        CheckPoint::AfterWorker,
    )
    .await
    .map_err(key_error)
}

#[cfg(feature = "desktop-shell")]
pub(super) async fn save(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
    request: &Request,
    permit: AppleP12SavePermit,
) -> Staged {
    if !request.p12 || request.parent.p12_mode() != Some(wire::Mode::P12Save) {
        return refused(&request.parent, Reason::CleanupUnknown);
    }
    let Some(work) = owner.apple_key.get() else {
        return refused(&request.parent, Reason::CleanupUnknown);
    };
    // A delivered permit is an attempted save claim, even if its following
    // original-state comparison fails. It cannot later become NoSave.
    work.save_received.store(true, Ordering::SeqCst);
    let Some(destination) = work.p12.as_ref().and_then(P12Work::destination) else {
        return refused(&request.parent, Reason::CleanupUnknown);
    };
    let save = match destination.claim(owner, permit) {
        Ok(value) => value,
        Err(reason) => return refused(&request.parent, reason),
    };
    match distribution_key::p12::p12_store::run(document, owner, save).await {
        Ok(staged) => staged,
        Err(reason) => refused(&request.parent, reason),
    }
}

pub(super) fn published(owner: &Arc<OriginalWork>) -> Option<KeyReference> {
    owner
        .apple_key
        .get()?
        .p12
        .as_ref()?
        .destination()?
        .published_reference_data(owner)
}
