//! Bundle-ID provisioning on the original SavedCommand Session.
//!
//! These two facts deliberately have different cut points. They are private
//! parent capabilities, never child/status/journal JSON and never restored
//! after restart. Only this child may construct them after the corresponding
//! original resource roster has actually joined.

use std::sync::Arc;

use crate::{apple_provisioning_journal::OriginalReservation, application_state_store::NativeUse};

use super::*;
use crate::apple_provisioning_protocol as apple_wire;
#[path="saved_command_apple_profile_review.rs"]
mod profile_review;
#[path = "saved_command_apple_profile_recovery.rs"]
mod profile_recovery;

/// Worker/provider/source and material CONSUMERS, driver/manager and all
/// PRE-final-CAS jobs have joined. The same material loan remains retained for
/// the final observer/watchdog; requiring its later retirement here would
/// create a cycle. The final journal CAS is deliberately not covered by this.
pub(crate) struct AppleProvisioningNativeJoined {
    native_use: Arc<NativeUse>,
    reservation: Arc<OriginalReservation>,
}

impl AppleProvisioningNativeJoined {
    pub(crate) fn matches(
        &self,
        native_use: &NativeUse,
        reservation: &OriginalReservation,
    ) -> bool {
        std::ptr::eq(self.native_use.as_ref(), native_use)
            && std::ptr::eq(self.reservation.as_ref(), reservation)
    }
}

/// All finite journal jobs, INCLUDING final CAS or its proven not-entered
/// slot, have joined and the roster is sealed against any future writer.
/// Only this later fact may release the original Store's native-use token.
pub(crate) struct AppleProvisioningAllJobsJoined {
    native_use: Arc<NativeUse>,
}

impl AppleProvisioningAllJobsJoined {
    pub(crate) fn matches(&self, native_use: &NativeUse) -> bool {
        std::ptr::eq(self.native_use.as_ref(), native_use)
    }
}

/// One privately issued, bounded review token. It does NOT retain the finished
/// Session/runtime/process graph. Only the actual positive original retirement
/// below can issue it; status/journal/IDs cannot reconstruct it.
pub(crate) struct AppleProvisioningReview {
    input: Arc<crate::asset_session::AppleProvisioningDocumentInput>,
    reference: apple_wire::Reference,
    observed_at: String,
    before_sha256: String,
    expires: Instant,
    used: AtomicBool,
}
impl AppleProvisioningReview {
    fn matches(
        &self,
        input: &crate::asset_session::AppleProvisioningDocumentInput,
        now: Instant,
    ) -> bool {
        !self.used.load(Ordering::SeqCst)
            && now < self.expires
            && input.context().mode == apple_wire::Mode::Register
            && input.context().reference.as_ref() == Some(&self.reference)
            && self.input.same_selection(input)
    }
    fn claim(
        &self,
        input: &crate::asset_session::AppleProvisioningDocumentInput,
        now: Instant,
    ) -> Result<(), BridgeError> {
        if !self.matches(input, now) {
            return Err(apple_wire::invalid());
        }
        self.used
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| ())
            .map_err(|_| apple_wire::invalid())
    }
}

pub(super) struct Intent {
    input: Arc<crate::asset_session::AppleProvisioningDocumentInput>,
    review: Option<Arc<AppleProvisioningReview>>,
    profile_review: Option<Arc<profile_review::Review>>,
}
#[derive(Default)]
pub(super) struct Registry {
    review: Option<Arc<AppleProvisioningReview>>,
    recovery: Option<RecoveryPublication>,
    profile_review: Option<Arc<profile_review::Review>>,
    profile_saved: Option<profile_review::SavedPublication>,
    profile_recovery: Option<profile_recovery::Publication>,
}

// Detached historical DATA only. It must not keep a finished Session,
// NativeUse, material loan or runtime alive after original retirement.
struct RecoveryPublication {
    reference: apple_wire::Reference,
    context: apple_wire::Context,
    history: apple_wire::RecoveryHistory,
}

impl Reason {
    pub(super) fn from_apple(reason: apple_wire::Reason) -> Self {
        use apple_wire::Reason as A;
        match reason {
            A::None => Self::None,
            A::Cancelled => Self::Cancelled,
            A::ContextChanged => Self::ContextChanged,
            A::DocumentLost => Self::DocumentLost,
            A::Shutdown => Self::Shutdown,
            A::TimedOut => Self::TimedOut,
            A::ProtocolError => Self::ProtocolError,
            A::RuntimeUnavailable => Self::RuntimeUnavailable,
            A::IntentExpired | A::ReviewExpired => Self::IntentExpired,
            A::StaleIntent => Self::StaleIntent,
            A::SavedSourceChanged => Self::SavedSourceChanged,
            A::SavedSourceInvalid => Self::SavedSourceInvalid,
            A::CredentialsUnavailable => Self::CredentialsUnavailable,
            A::QueryPrerequisites => Self::QueryPrerequisites,
            A::CommandIncomplete => Self::CommandIncomplete,
            A::CleanupUnknown => Self::CleanupUnknown,
            A::JournalUnavailable => Self::JournalUnavailable,
            A::RegistrationBlocked => Self::ManualRequired,
        }
    }
    fn apple(self) -> apple_wire::Reason {
        use apple_wire::Reason as A;
        match self {
            Self::None => A::None,
            Self::Cancelled => A::Cancelled,
            Self::ContextChanged => A::ContextChanged,
            Self::DocumentLost => A::DocumentLost,
            Self::Shutdown => A::Shutdown,
            Self::TimedOut => A::TimedOut,
            Self::ProtocolError => A::ProtocolError,
            Self::RuntimeUnavailable => A::RuntimeUnavailable,
            Self::IntentExpired => A::IntentExpired,
            Self::StaleIntent => A::StaleIntent,
            Self::SavedSourceChanged => A::SavedSourceChanged,
            Self::SavedSourceInvalid => A::SavedSourceInvalid,
            Self::CredentialsUnavailable => A::CredentialsUnavailable,
            Self::QueryPrerequisites => A::QueryPrerequisites,
            Self::CleanupUnknown => A::CleanupUnknown,
            Self::JournalUnavailable => A::JournalUnavailable,
            Self::ManualRequired => A::RegistrationBlocked,
            _ => A::CommandIncomplete,
        }
    }
}
impl Status {
    fn apple(self) -> Result<apple_wire::Status, BridgeError> {
        match self {
            Self::AppleProvisioning(status) => Ok(status),
            _ => Err(BridgeError::protocol()),
        }
    }
}
impl RunProjection {
    pub(super) fn apple(self) -> Result<apple_wire::Projection, BridgeError> {
        let Context::AppleProvisioning(context) = self.context else {
            return Err(BridgeError::protocol());
        };
        if self.stage.is_some() {
            return Err(BridgeError::protocol());
        }
        let result = match self.result {
            Some(Terminal::AppleProvisioning(terminal))
                if self.phase == Phase::Terminal
                    && self.outcome == Some(Outcome::Complete)
                    && self.reason == Reason::None =>
            {
                terminal.result
            }
            Some(Terminal::AppleProvisioning(_)) | None => None,
            Some(_) => return Err(BridgeError::protocol()),
        };
        Ok(apple_wire::Projection {
            operation_id: self.operation_id,
            owner_generation: self.owner_generation,
            context,
            phase: self.phase.store(),
            intent_usable: self.intent_usable,
            outcome: self.outcome.map(Outcome::store),
            reason: self.reason.apple(),
            result,
            recovery: None,
            profile_recovery: None,
            saved_profile:None,
        })
    }
}

pub(super) fn invalidate_review(registry: &mut Registry) -> bool {
    registry.review = None;
    registry.profile_review = None;
    let saved_changed=registry.profile_saved.take().is_some();
    let profile_history_changed = registry.profile_recovery.take().is_some();
    // Public historical DATA may be withdrawn, never replaced or upgraded.
    // Idle context invalidation must advance the same original status revision.
    registry.recovery.take().is_some() || saved_changed || profile_history_changed
}

pub(super) fn project_recovery(registry: &Registry, projection: &mut apple_wire::Projection) {
    profile_review::project(registry,projection);
    profile_recovery::project(registry, projection);
    projection.recovery = None;
    if let Some(stored) = &registry.recovery {
        if projection.operation_id == stored.reference.operation_id
            && projection.owner_generation == stored.reference.owner_generation
            && projection.context == stored.context
            && projection.context.mode == apple_wire::Mode::Review
            && projection.phase == apple_wire::Phase::Terminal
            && projection.outcome == Some(apple_wire::Outcome::Complete)
            && projection.reason == apple_wire::Reason::None
            && projection.result.is_some()
        {
            projection.recovery = Some(stored.history.clone());
        }
    }
}

fn recovery_backing_bytes() -> Option<usize> {
    // Original list plus its bounded construction scratch. The ordinary two
    // status copies below cover serialized/projected replies and events.
    apple_wire::RECOVERY_LIMIT
        .checked_mul(2)?
        .checked_add(apple_wire::IPC_LIMIT)?
        .checked_add(std::mem::size_of::<RecoveryPublication>())?
        .checked_add(profile_recovery::backing_bytes()?)
}

pub(crate) const APPLE_PROVISIONING_INPUT_LIMIT: usize = 128 * 1024;
/// Retained private review/last-status backing remains after the operation
/// releases its runtime. The original Document census charges this once for
/// every later admission; the active quote below subtracts that same charge.
pub(crate) fn retained_document_backing_bytes() -> Option<usize> {
    store::document_backing_bytes()?
        .checked_add(APPLE_PROVISIONING_INPUT_LIMIT)?
        .checked_add(2 * apple_wire::STATUS_LIMIT)?
        .checked_add(recovery_backing_bytes()?)?
        .checked_add(8192)?
        .checked_add(6*1024*1024)
}
/// Finite representations, NOT RSS or a replacement for the installed
/// runtime's separate control/FD admission. All jobs are serial, so reserve
/// one complete namespace decode/encode/readback scratch set, plus every
/// retained slot/ACK and the at-most-one previous review's comparison backing.
pub(crate) fn document_backing_bytes() -> Option<usize> {
    use crate::apple_provisioning_journal::{ROWS, ROW_LIMIT, STATE_LIMIT};
    let mut total = store::document_backing_bytes()?;
    for (count, size) in [
        (8usize, STATE_LIMIT),
        (2, ROWS.checked_mul(ROW_LIMIT)?),
        (11, ROW_LIMIT),
        (2, APPLE_PROVISIONING_INPUT_LIMIT),
        (2, apple_wire::REQUEST_LIMIT),
        (6, apple_wire::RESPONSE_LIMIT),
        (2, apple_wire::STATUS_LIMIT),
        (4, apple_wire::IPC_LIMIT),
        (5, apple_wire::ACK_LIMIT),
        (4, apple_wire::PROFILE_IDENTITY_LIMIT),
        (4, apple_wire::PROFILE_JSON_LIMIT),
        (1, 2*1024*1024), // fixed NEW/profile AEAD scratch; old file limits unchanged
        (2, 4*1024*1024+4096+16*1024+46), // actual private receive/worker input overlap
    ] {
        total = total.checked_add(count.checked_mul(size)?)?;
    }
    total
        .checked_add(recovery_backing_bytes()?)?
        .checked_add(std::mem::size_of::<State>())?
        .checked_add(std::mem::size_of::<Intent>())?
        .checked_add(std::mem::size_of::<AppleProvisioningReview>())?
        .checked_add(std::mem::size_of::<profile_review::Review>())?
        .checked_add(super::apple_signing::backing_bytes()?)?
        .checked_add(6*1024*1024)?
        .checked_sub(retained_document_backing_bytes()?)
}

/// The Store runtime keeps its existing original consumer/terminal rule. This
/// new domain has a bounded phase stream rather than the Access two frames.
/// No other domain is allowed to borrow this shape.
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) fn consumers_returned(
    book: &Resources,
    startup: &Startup,
    owner: &Session,
    no_child_effect: bool,
) -> bool {
    if owner.domain != SavedCommandDomain::AppleProvisioning
        || !pre_final_jobs(owner)
        || !offline_worker_returned(
            book.inspection_started,
            book.inspection_joined,
            book.inspection_failed,
            book.inspection.is_some(),
            book.inspection_error.is_some(),
        )
        || !offline_worker_returned(
            book.acquisition_started,
            book.acquisition_joined,
            book.acquisition_failed,
            book.acquisition.is_some(),
            book.acquisition_error.is_some(),
        )
    {
        return false;
    }
    let io = book.writer.is_none()
        && book.stdout.is_none()
        && book.stderr.is_none()
        && !book.write_failed
        && !book.out_failed
        && !book.err_failed
        && book.write_end.is_some()
        && book.out_end.is_some()
        && book.err_end.is_some();
    if !io || startup.child.is_some() {
        return false;
    }
    if !startup.attempted {
        return no_child_effect
            && !startup.returned
            && !startup.failed
            && book.child.is_none()
            && book.waited.is_none()
            && !book.wait_failed;
    }
    startup.returned
        && !startup.failed
        && book.inspection_joined
        && book.acquisition_joined
        && book.waited.as_ref().is_some_and(ExitStatus::success)
        && !book.wait_failed
        && book
            .write_end
            .as_ref()
            .is_some_and(|end| end.sent && end.closed && !end.failed)
        && book
            .out_end
            .as_ref()
            .is_some_and(|end| end.eof && end.closed && end.protocol_settled_for(&owner.context))
        && book
            .err_end
            .as_ref()
            .is_some_and(|end| end.eof && end.closed && !end.failed && end.frames == 0)
}

struct Route {
    received: u32,
    completed: u32,
    pending: Option<apple_wire::EventDataFrame>,
    observed: Option<(apple_wire::Observed, Instant)>,
    profile_observed: Option<(apple_wire::ProfileObserved, Instant)>,
    ack_writing: bool,
    ack_entered: [bool; 4],
    failed: bool,
}
pub(super) struct State {
    intent: Option<Arc<Intent>>,
    binding: Mutex<Option<Arc<apple_wire::RequestBinding>>>,
    route: Mutex<Route>,
    pub(super) changed: Notify,
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    native: AsyncMutex<native::Jobs>,
}
impl State {
    pub(super) fn new(intent: Option<Arc<Intent>>) -> Self {
        Self {
            intent,
            binding: Mutex::new(None),
            route: Mutex::new(Route {
                received: 0,
                completed: 0,
                pending: None,
                observed: None, profile_observed: None,
                ack_writing: false,
                ack_entered: [false; 4],
                failed: false,
            }),
            changed: Notify::new(),
            #[cfg(all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            ))]
            native: AsyncMutex::new(native::Jobs::new()),
        }
    }
    pub(super) fn input(
        &self,
    ) -> Result<&Arc<crate::asset_session::AppleProvisioningDocumentInput>, BridgeError> {
        self.intent
            .as_ref()
            .map(|intent| &intent.input)
            .ok_or_else(apple_wire::invalid)
    }
    pub(super) fn request_binding(&self) -> Result<Arc<apple_wire::RequestBinding>, BridgeError> {
        self.binding
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .clone()
            .ok_or_else(apple_wire::invalid)
    }
    /// Memory-only acceptance under the original Registry. At most one event
    /// may wait while the preceding ACK write is still returning. No filesystem
    /// call, task or second owner is created under this lock.
    pub(super) fn receive(
        &self,
        event: apple_wire::EventDataFrame,
        at: Instant,
    ) -> Result<(), BridgeError> {
        let input = self.input()?;
        let mut route = self
            .route
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if route.failed
            || route.pending.is_some()
            || route.received.checked_add(1) != Some(event.sequence)
            || event.sequence > input.context().mode.events()
            || route.received > route.completed + u32::from(route.ack_writing)
        {
            route.failed = true;
            return Err(apple_wire::invalid());
        }
        match event.data {
            apple_wire::EventData::Observed(observed)
                if input.context().mode != apple_wire::Mode::Register
                    && event.sequence == 1
                    && route.observed.is_none() =>
            {
                route.observed = Some((observed, at));
                route.received = 1;
                route.completed = 1;
            }
            data @ (apple_wire::EventData::Pending { .. } | apple_wire::EventData::Attempt(_))
                if input.context().mode == apple_wire::Mode::Register =>
            {
                route.received = event.sequence;
                route.pending = Some(apple_wire::EventDataFrame {
                    sequence: event.sequence,
                    data,
                });
            }
            apple_wire::EventData::Profile(apple_wire::ProfileEvent::Observed(observed))
                if input.context().mode.profile() && !input.context().mode.profile_save()
                    && event.sequence == 2 && route.profile_observed.is_none() => {
                route.profile_observed = Some((observed, at));
                route.received = event.sequence;
                if !route.ack_writing { route.completed = event.sequence; }
            },
            data @ apple_wire::EventData::Profile(_) if input.context().mode.profile() => {
                route.received = event.sequence;
                route.pending = Some(apple_wire::EventDataFrame { sequence: event.sequence, data });
            },
            _ => {
                route.failed = true;
                return Err(apple_wire::invalid());
            }
        }
        self.changed.notify_waiters();
        Ok(())
    }
    fn route_complete(&self) -> bool {
        self.route.lock().is_ok_and(|route| {
            !route.failed
                && route.pending.is_none()
                && !route.ack_writing
                && route.received == route.completed
        })
    }
    /// After F only an already-armed attempt may publish its bounded audit.
    /// This never admits another Pending event or authorizes provider work.
    pub(super) fn accepts_audit(&self, event: &apple_wire::EventDataFrame) -> bool {
        (matches!(&event.data, apple_wire::EventData::Attempt(_))
            && (2..=apple_wire::MAX_EVENTS).contains(&event.sequence)
            && self
                .route
                .lock()
                .is_ok_and(|route| !route.failed && route.ack_entered[0]))
            || matches!(&event.data, apple_wire::EventData::Profile(apple_wire::ProfileEvent::Attempt(_)))
                && (3..=4).contains(&event.sequence)
                && self.route.lock().is_ok_and(|route| !route.failed && route.ack_entered[1])
    }
}

pub(crate) struct AppleProvisioningAdmitted {
    status: apple_wire::Status,
    release: Option<oneshot::Sender<()>>,
    profile: Option<Arc<AppleProfileSession>>,
}
impl AppleProvisioningAdmitted {
    pub(crate) fn profile(&self) -> Option<&Arc<AppleProfileSession>> { self.profile.as_ref() }
    /// The original Document caller releases this only after dropping BOTH
    /// its Edit guard and Document lock. Losing this message is not a retry.
    pub(crate) fn release(self) -> apple_wire::Status {
        if let Some(release) = self.release {
            let _ = release.send(());
        }
        self.status
    }
}
impl SavedCommandOwner {
    pub(crate) fn apple_provisioning(runtime: RuntimeConfig) -> Self {
        Self::new(runtime, SavedCommandDomain::AppleProvisioning)
    }
    pub(crate) fn prepare_apple_provisioning(
        &self,
        input: apple_wire::Prepare,
        registration: u32,
        root: RegisteredRoot,
        gate: apple_wire::Availability,
        document: Arc<crate::asset_session::AppleProvisioningDocumentInput>,
    ) -> Result<apple_wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::AppleProvisioning)?;
        if !document.matches(&input.context, registration, &root) {
            return Err(apple_wire::invalid());
        }
        let now = Instant::now();
        let review = if input.context.mode == apple_wire::Mode::Register {
            let registry = self.inner.lock();
            Some(
                registry
                    .apple
                    .review
                    .as_ref()
                    .filter(|review| review.matches(&document, now))
                    .cloned()
                    .ok_or_else(apple_wire::invalid)?,
            )
        } else {
            None
        };
        let profile_review=if input.context.mode.profile_save() {
            let registry=self.inner.lock();
            Some(registry.apple.profile_review.as_ref().filter(|review|review.matches(&document,now))
                .cloned().ok_or_else(apple_wire::invalid)?)
        } else { None };
        let material = document.material().clone();
        let status = self.prepare_bound(
            Context::AppleProvisioning(input.context),
            registration,
            root,
            Availability::from_store(gate),
            Some(PrivateSigningMaterial::Store(material)),
            None,
        )?;
        let mut registry = self.inner.lock();
        let prepared = registry.prepared.as_mut().ok_or_else(apple_wire::invalid)?;
        if prepared.apple.is_some() {
            return Err(apple_wire::invalid());
        }
        if let Some(review) = &review {
            prepared.expires = prepared.expires.min(review.expires);
        }
        if let Some(review)=&profile_review { prepared.expires=prepared.expires.min(review.expires()); }
        prepared.apple = Some(Arc::new(Intent {
            input: document,
            review,
            profile_review,
        }));
        status.apple()
    }
    pub(crate) fn prepared_apple_provisioning_input(
        &self,
        operation: &str,
        generation: &str,
    ) -> Result<Arc<crate::asset_session::AppleProvisioningDocumentInput>, BridgeError> {
        self.require_domain(SavedCommandDomain::AppleProvisioning)?;
        let registry = self.inner.lock();
        registry
            .prepared
            .as_ref()
            .filter(|prepared| {
                prepared.projection.operation_id == operation
                    && prepared.projection.owner_generation == generation
            })
            .and_then(|prepared| prepared.apple.as_ref())
            .map(|intent| intent.input.clone())
            .ok_or_else(apple_wire::invalid)
    }
    pub(crate) fn start_apple_provisioning(
        &self,
        input: apple_wire::Start,
        admitted_at: Instant,
        registered: Option<(u32, RegisteredRoot)>,
        gate: apple_wire::Availability,
        document: Arc<crate::asset_session::AppleProvisioningDocumentInput>,
    ) -> Result<AppleProvisioningAdmitted, BridgeError> {
        self.require_domain(SavedCommandDomain::AppleProvisioning)?;
        let original =
            self.prepared_apple_provisioning_input(&input.operation_id, &input.owner_generation)?;
        if !Arc::ptr_eq(&original, &document)
            || !document.material().accepts_provisioning_consent(&input)
        {
            return Err(apple_wire::invalid());
        }
        {
            let registry = self.inner.lock();
            let intent = registry
                .prepared
                .as_ref()
                .and_then(|prepared| prepared.apple.as_ref())
                .ok_or_else(apple_wire::invalid)?;
            if let Some(review) = &intent.review {
                review.claim(&document, Instant::now())?;
            }
            if let Some(review)=&intent.profile_review { review.claim(&document,Instant::now())?; }
        }
        let admitted = self.start_bound(
            Start {
                operation_id: input.operation_id,
                owner_generation: input.owner_generation,
            },
            admitted_at,
            registered,
            Availability::from_store(gate),
            Some(PrivateSigningMaterial::Store(document.material().clone())),
        )?;
        let profile = {
            let registry = self.inner.lock();
            registry.active.as_ref().filter(|active| active.owner.apple.input().is_ok_and(|held| Arc::ptr_eq(held, &document)))
                .and_then(|active| active.owner.apple_profile.get().cloned())
        };
        if document.context().mode.profile() != profile.is_some() { return Err(apple_wire::invalid()); }
        Ok(AppleProvisioningAdmitted {
            status: admitted.status.apple()?, release: admitted.release, profile,
        })
    }
    pub(crate) fn status_apple_provisioning(
        &self,
        gate: apple_wire::Availability,
    ) -> Result<apple_wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::AppleProvisioning)?;
        self.status(Availability::from_store(gate))?.apple()
    }
    pub(crate) fn cancel_apple_provisioning(
        &self,
        operation: &str,
        generation: &str,
        gate: apple_wire::Availability,
    ) -> Result<apple_wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::AppleProvisioning)?;
        self.cancel(operation, generation, Availability::from_store(gate))?
            .apple()
    }
}

pub(super) fn decoder(owner: &Session) -> Result<apple_wire::Decoder, BridgeError> {
    if owner.domain != SavedCommandDomain::AppleProvisioning {
        return Err(apple_wire::invalid());
    }
    Ok(apple_wire::Decoder::new(owner.apple.request_binding()?))
}
pub(super) fn complete(owner: &Session) -> bool {
    owner.apple.route_complete()
}

/// ONLY called by the original positive watchdog/material retirement arm,
/// while that exact Active is still held. No status getter invokes this.
pub(super) fn retire_review(registry: &mut Registry, active: &super::Active, owner: &Arc<Session>) {
    registry.review = None;
    registry.recovery = None;
    registry.profile_review=None;registry.profile_saved=None;
    registry.profile_recovery = None;
    if owner.domain != SavedCommandDomain::AppleProvisioning
        || active.unknown
        || active.context_invalidated
        || active.first_stop.is_some()
        || !active.final_join_seen
        || !owner.watchdog_joined.load(Ordering::SeqCst)
        || owner.watchdog_failed.load(Ordering::SeqCst)
        || !owner.material_retired.load(Ordering::SeqCst)
        || owner.resource_unknown.load(Ordering::SeqCst)
    {
        return;
    }
    let Context::AppleProvisioning(context) = &owner.context else {
        return;
    };
    if active.projection.outcome != Some(Outcome::Complete) { return; }
    let Some(Terminal::AppleProvisioning(terminal)) = &active.projection.result else {
        return;
    };
    if !terminal.settled() || terminal.result.is_none() {
        return;
    }
    if !native_complete(owner) { return; }
    if context.mode.profile() {
        if owner.apple_profile.get().is_some_and(|profile|profile.clock().completed()) {
            profile_recovery::publish(registry, owner);
            profile_review::publish(registry,active,owner,terminal);
        }
        return;
    }
    if context.mode != apple_wire::Mode::Review { return; }
    // A denied/inconclusive provider query may accompany a known joined local
    // journal read. Publish only that historical DATA, never a Register review.
    if let Some(history) = native_history(owner) {
        registry.recovery = Some(RecoveryPublication {
            reference: apple_wire::Reference {
                operation_id: owner.id.clone(),
                owner_generation: owner.generation.clone(),
            },
            context: context.clone(),
            history,
        });
    }
    // Preserve the original private one-use Register-review predicate exactly.
    if terminal.result.as_ref().and_then(apple_wire::ResultData::bundle).is_none_or(|result| {
        result.observation != apple_wire::Observation::NotReturned
            || result.decision != apple_wire::Decision::ReviewRequired
    }) {
        return;
    }
    let Ok(input) = owner.apple.input() else {
        return;
    };
    let Ok(mut route) = owner.apple.route.lock() else {
        return;
    };
    if route.failed
        || route.pending.is_some()
        || route.received != 1
        || route.completed != 1
        || route.ack_writing
    {
        return;
    }
    let Some((observed, at)) = route.observed.take() else {
        return;
    };
    if observed.observation != apple_wire::Observation::NotReturned
        || observed.decision != apple_wire::Decision::ReviewRequired
        || observed.bundle.is_some()
    {
        return;
    }
    let Some(before_sha256) = observed.before_sha256 else {
        return;
    };
    let Some(expires) = at.checked_add(Duration::from_secs(300)) else {
        return;
    };
    if Instant::now() >= expires {
        return;
    }
    registry.review = Some(Arc::new(AppleProvisioningReview {
        input: input.clone(),
        reference: apple_wire::Reference {
            operation_id: owner.id.clone(),
            owner_generation: owner.generation.clone(),
        },
        observed_at: observed.observed_at,
        before_sha256,
        expires,
        used: AtomicBool::new(false),
    }));
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[path = "saved_command_apple_provisioning_native.rs"]
mod native;

pub(super) fn work_current(owner: &Session) -> Result<(), BridgeError> {
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        native::work_clear(owner)
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        let _ = owner;
        Err(apple_wire::invalid())
    }
}

pub(super) async fn initialize(
    inner: &Arc<Inner>,
    owner: &Arc<Session>,
) -> Result<(), BridgeError> {
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        native::initialize(inner, owner).await
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        let _ = (inner, owner);
        Err(apple_wire::invalid())
    }
}
pub(super) fn request(
    owner: &Session,
    profile: apple_wire::Profile,
    runtime: &VerifiedRuntime,
) -> Result<Vec<u8>, BridgeError> {
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        native::request(owner, profile, runtime)
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        let _ = (owner, profile, runtime);
        Err(apple_wire::invalid())
    }
}
pub(super) async fn write_phases(
    inner: &Arc<Inner>,
    owner: &Arc<Session>,
    writer: &mut ChildStdin,
) -> Result<(), BridgeError> {
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        native::write_phases(inner, owner, writer).await
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        let _ = (inner, owner, writer);
        Err(apple_wire::invalid())
    }
}
pub(super) fn pre_final_jobs(owner: &Session) -> bool {
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        native::pre_final_jobs(owner)
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        let _ = owner;
        false
    }
}
pub(super) async fn finish_after_manager(inner: &Arc<Inner>, owner: &Arc<Session>) -> bool {
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        native::finish_after_manager(inner, owner).await
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        let _ = (inner, owner);
        false
    }
}
pub(super) fn native_complete(owner: &Session) -> bool {
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        native::complete(owner)
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        let _ = owner;
        false
    }
}

fn native_history(owner: &Session) -> Option<apple_wire::RecoveryHistory> {
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        native::history(owner)
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        let _ = owner;
        None
    }
}

#[cfg(test)]
#[path = "saved_command_apple_provisioning_tests.rs"]
mod tests;
