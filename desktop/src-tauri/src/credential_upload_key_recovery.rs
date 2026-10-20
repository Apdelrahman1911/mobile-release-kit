//! Explicit reference-only recovery on the existing AssetSession original.
//! No key creation, replacement, restored Bind or new producer is admitted.
use super::*;
use persistence::recovery as saved;

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Action {
    AcknowledgeUnstarted,
    RememberBound,
}
pub(crate) struct RecoveryRequest {
    context_revision: u32,
    status_revision: u32,
    preference_revision: u64,
    action: Action,
}
pub(crate) fn request(value: &Value) -> Result<RecoveryRequest, AssetError> {
    let object = value
        .as_object()
        .filter(|value| value.len() == 4)
        .ok_or_else(AssetError::invalid)?;
    let revision = object
        .get("expectedPreferenceRevision")
        .and_then(Value::as_str)
        .ok_or_else(AssetError::invalid)?;
    let parsed = revision.parse::<u64>().map_err(|_| AssetError::invalid())?;
    if parsed.to_string() != revision {
        return Err(AssetError::invalid());
    }
    let action = match object.get("action").and_then(Value::as_str) {
        Some("acknowledge-unstarted") => Action::AcknowledgeUnstarted,
        Some("remember-bound") => Action::RememberBound,
        _ => return Err(AssetError::invalid()),
    };
    Ok(RecoveryRequest {
        context_revision: object
            .get("contextRevision")
            .and_then(positive)
            .ok_or_else(AssetError::invalid)?,
        status_revision: object
            .get("expectedStatusRevision")
            .and_then(positive)
            .ok_or_else(AssetError::invalid)?,
        preference_revision: parsed,
        action,
    })
}

/// Safe guidance and a genuine same-original acknowledgement. Neither this
/// DTO nor a stored reference is a loan, generation receipt or reissue permit.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecoveryStatus {
    preference_revision: Option<String>,
    state: &'static str,
    record: Option<KeyReference>,
    operation: Option<RecoveryOperation>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryOperation {
    operation_id: u32,
    action: Action,
    phase: &'static str,
    preference_revision: Option<String>,
}

// Captured ONLY from an actual settled Bind, before replacing its Slot. Keeps
// its real payload/key/witness, not a JSON ref or a restored assessment flag.
struct BoundCapture {
    context: Arc<NativeContext>,
    payload: Arc<Payload>,
    key: Arc<crypto::VaultKey>,
    store: Arc<Mutex<store::StoreBook>>,
    reference: StoredRef,
}
impl BoundCapture {
    fn capture(state: &DocumentState) -> Option<Self> {
        let reference =
            remembered_bound_reference(state, state.slot.as_ref()?, Kind::AndroidKeystore)?;
        let session = state.vault.as_ref()?;
        let loan = session.bound.iter().flatten().find(|loan| {
            same_reference(loan.reference, reference) && loan.current(state, session)
        })?;
        Some(Self {
            context: loan.context.clone(),
            payload: loan.payload.clone(),
            key: loan.key.clone(),
            store: loan.store.clone(),
            reference,
        })
    }
    fn current(&self, state: &DocumentState) -> bool {
        state.vault.as_ref().is_some_and(|session| {
            session.bound.iter().flatten().any(|loan| {
                same_reference(loan.reference, self.reference)
                    && Arc::ptr_eq(&loan.context, &self.context)
                    && Arc::ptr_eq(&loan.payload, &self.payload)
                    && Arc::ptr_eq(&loan.key, &self.key)
                    && Arc::ptr_eq(&loan.store, &self.store)
                    && loan.current(state, session)
            })
        })
    }
    fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(self.payload.bytes())?
            .checked_add(self.key.retained_bytes())?
            .checked_add(8 * std::mem::size_of::<usize>())
    }
}

pub(in crate::asset_session) struct Completion {
    owner: Weak<OriginalWork>,
    context: Weak<NativeContext>,
    action: Action,
    preference_revision: u64,
    reference: Option<StoredRef>,
    disposed: AtomicBool,
}
struct Recovery {
    owner: Weak<OriginalWork>,
    setup: Arc<PreparedSetup>,
    context: Arc<NativeContext>,
    store: Arc<Mutex<store::StoreBook>>,
    key: Arc<crypto::VaultKey>,
    observed: NativeObservation,
    roster: ProjectRoster,
    bound: Option<BoundCapture>,
    action: Action,
    preference_revision: u64,
    work_end: Instant,
    native_use: OnceLock<NativeStateLease>,
    use_retirement_claimed: AtomicBool,
    use_retired: AtomicBool,
    attempted: AtomicBool,
    io_returned: AtomicBool,
    unknown: AtomicBool,
    published: AtomicBool,
    change: Mutex<Option<saved::Change>>,
    completion: OnceLock<Arc<Completion>>,
}
impl Recovery {
    fn retained_bytes(&self) -> Option<usize> {
        // Conservatively count the actual shared loan backing here too; it
        // remains held after normal Bind-slot/context retirement. Store owner
        // and its original descriptors remain in the existing parent census.
        let mut bytes = std::mem::size_of::<Self>()
            .checked_add(4 * std::mem::size_of::<usize>())?
            .checked_add(saved::IO_RESERVATION_BYTES)?
            .checked_add(self.setup.retained_bytes()?)?
            .checked_add(self.key.retained_bytes())?
            .checked_add(
                self.bound
                    .as_ref()
                    .map_or(Some(0), BoundCapture::retained_bytes)?,
            )?
            .checked_add(std::mem::size_of::<NativeContext>())?
            .checked_add(self.context.draft.capacity())?
            .checked_add(self.context.project_id.capacity())?
            .checked_add(self.context.project.path.capacity())?
            .checked_add(
                self.observed
                    .records
                    .capacity()
                    .checked_mul(std::mem::size_of::<RecordFact>())?,
            )?
            .checked_add(
                self.roster
                    .roots
                    .capacity()
                    .checked_mul(2)?
                    .checked_mul(std::mem::size_of::<asset_source::RegisteredRoot>())?,
            )?;
        for value in [
            &self.observed.project.project_id,
            &self.observed.project.canonical_root,
            &self.observed.identity,
        ] {
            bytes = bytes.checked_add(value.capacity())?;
        }
        bytes = bytes.checked_add(self.observed.expected.as_ref().map_or(0, String::capacity))?;
        for row in &self.observed.records {
            for value in [
                &row.reference.vault_id,
                &row.reference.generation_id,
                &row.reference.record_id,
                &row.reference.revision_id,
            ] {
                bytes = bytes.checked_add(value.capacity())?;
            }
            bytes = bytes.checked_add(row.certificate.as_ref().map_or(0, String::capacity))?;
        }
        for root in &self.roster.roots {
            // Original retained roster plus its fixed native Check argument.
            bytes = bytes.checked_add(root.path.capacity().checked_mul(2)?)?;
        }
        // These fixed cells are reserved before their construction too.
        bytes.checked_add(
            std::mem::size_of::<NativeStateLease>()
                + std::mem::size_of::<crate::application_state_store::NativeUse>()
                + std::mem::size_of::<Completion>()
                + 6 * std::mem::size_of::<usize>(),
        )
    }
    fn work_current(&self, owner: &OriginalWork) -> Result<(), Reason> {
        if Instant::now() >= self.work_end {
            return Err(Reason::Deadline);
        }
        if owner.interrupted() {
            return Err(Reason::UserCancelled);
        }
        if self.unknown.load(Ordering::SeqCst) {
            return Err(Reason::VaultDurabilityUnknown);
        }
        Ok(())
    }
    fn check_use(&self, owner: &OriginalWork) -> Result<(), Reason> {
        self.work_current(owner)?;
        let lease = self.native_use.get().ok_or(Reason::VaultInterrupted)?;
        if self.use_retirement_claimed.load(Ordering::SeqCst) {
            return Err(Reason::CleanupUnknown);
        }
        lease
            .store()
            .check_native_use(lease.native_use())
            .map_err(|error| service_error(error.code).reason)?;
        self.work_current(owner)
    }
}

#[derive(Default)]
pub(in crate::asset_session) struct Work {
    held: Option<Arc<Recovery>>,
}
impl Work {
    pub(in crate::asset_session) fn empty(&self) -> bool {
        self.held.is_none()
    }
    pub(in crate::asset_session) fn blocks_reuse(&self) -> bool {
        !self.empty()
    }
    pub(in crate::asset_session) fn retained_bytes(&self) -> Option<usize> {
        self.held
            .as_ref()
            .map_or(Some(0), |held| held.retained_bytes())
    }
    pub(in crate::asset_session) fn unknown(&self) -> bool {
        self.held
            .as_ref()
            .is_some_and(|held| held.unknown.load(Ordering::SeqCst))
    }
    /// Called only in the existing off-Doc Retirement drain, after genuine
    /// original jobs. No Drop success or second NativeUse retirement is used.
    pub(in crate::asset_session) fn dispose(&mut self) -> bool {
        let Some(held) = &self.held else {
            return true;
        };
        if held.unknown.load(Ordering::SeqCst) {
            return false;
        }
        let Some(owner) = held.owner.upgrade() else {
            return false;
        };
        if !joined(&owner) || !retirement_window(held, &owner) {
            return false;
        }
        if let Some(lease) = held.native_use.get() {
            if !held.use_retired.load(Ordering::SeqCst) {
                if held.use_retirement_claimed.swap(true, Ordering::SeqCst) {
                    return false;
                }
                if lease.store().retire_native_use(lease.native_use()).is_err() {
                    held.unknown.store(true, Ordering::SeqCst);
                    return false;
                }
                held.use_retired.store(true, Ordering::SeqCst); // Actual result even if late.
            }
        }
        if !retirement_window(held, &owner) {
            held.unknown.store(true, Ordering::SeqCst);
            if let Ok(mut work) = owner.vault.try_lock() {
                work.fail(Reason::Deadline, held.work_end);
            }
            owner.signal_stop();
            return false;
        }
        let completion = held.completion.get().cloned();
        self.held = None; // Drop the real reference-only/private loan holding now.
        if let Some(completion) = completion {
            completion.disposed.store(true, Ordering::SeqCst);
        }
        true
    }
}

fn joined(owner: &OriginalWork) -> bool {
    owner.control_resources_settled()
        && owner
            .coordinator
            .try_lock()
            .is_ok_and(|book| book.handle.is_none() && book.receipt == JoinReceipt::Returned)
        && owner.child.try_lock().is_ok_and(|book| {
            book.handle.is_none()
                && matches!(book.receipt, JoinReceipt::New | JoinReceipt::Returned)
        })
        && owner.vault.try_lock().is_ok_and(|work| {
            matches!(work.original_join, None | Some(JoinReceipt::Returned))
                && work.failed_child_join.is_none()
                && work.store.as_ref().is_some_and(|storage| {
                    storage.try_lock().is_ok_and(|book| {
                        if work.release {
                            work.release_claimed && book.settled()
                        } else {
                            book.operation_quiescent()
                        }
                    })
                })
        })
}
fn retirement_window(held: &Recovery, owner: &OriginalWork) -> bool {
    retirement_window_facts(
        owner,
        held.work_end,
        held.published.load(Ordering::SeqCst),
        held.io_returned.load(Ordering::SeqCst),
    )
}
// Only the retained original calls this predicate. It is not a disposal proof:
// the caller separately requires actual joins, custody and NativeUse return.
fn retirement_window_facts(
    owner: &OriginalWork,
    work_end: Instant,
    published: bool,
    io_returned: bool,
) -> bool {
    if !io_returned {
        return false;
    }
    if owner.stopped() {
        owner.vault.try_lock().is_ok_and(|work| {
            work.first.is_some()
                && work.release
                && work.release_claimed
                && work.release_end.is_some_and(|end| Instant::now() < end)
        })
    } else {
        published
            && Instant::now() < work_end
            && owner
                .vault
                .try_lock()
                .is_ok_and(|work| work.first.is_none())
    }
}
pub(in crate::asset_session) fn retirement_ready(state: &DocumentState, slot: &Slot) -> bool {
    if state.unknown || slot.operation != Operation::RecoverUploadKey || !joined(&slot.owner) {
        return false;
    }
    slot.owner.vault.try_lock().is_ok_and(|work| {
        work.upload_key_recovery.held.as_ref().is_some_and(|held| {
            Arc::strong_count(held) == 1
                && !held.unknown.load(Ordering::SeqCst)
                && held.io_returned.load(Ordering::SeqCst)
                && (held.published.load(Ordering::SeqCst)
                    && !slot.owner.stopped()
                    && Instant::now() < held.work_end
                    || slot.owner.stopped()
                        && work.release
                        && work.release_claimed
                        && work.release_end.is_some_and(|end| Instant::now() < end))
        })
    })
}

pub(in crate::asset_session) struct Request {
    held: Arc<Recovery>,
}
#[cfg(feature = "desktop-shell")]
fn rematch(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
    held: &Arc<Recovery>,
) -> Result<(), Reason> {
    held.work_current(owner)?;
    let state = document.lock();
    current_gate(document, &state, owner)?;
    let slot = state.slot.as_ref().ok_or(Reason::Closed)?;
    if slot.operation != Operation::RecoverUploadKey
        || !owner.vault.try_lock().is_ok_and(|work| {
            work.upload_key_recovery
                .held
                .as_ref()
                .is_some_and(|same| Arc::ptr_eq(same, held))
        })
    {
        return Err(Reason::SourceChanged);
    }
    current_prepared(document, &state, &held.setup).map_err(|error| error.reason)?;
    let session = state.vault.as_ref().ok_or(Reason::Closed)?;
    if !session.writable()
        || !Arc::ptr_eq(&session.store, &held.store)
        || !session
            .key
            .as_ref()
            .is_some_and(|key| Arc::ptr_eq(key, &held.key))
        || session.identity != Some(held.key.identity())
        || state
            .context
            .as_ref()
            .is_none_or(|context| !Arc::ptr_eq(context, &held.context))
        || held
            .bound
            .as_ref()
            .is_some_and(|bound| !bound.current(&state))
        || session.rows.iter().any(|row| row.mutation_pending)
    {
        return Err(Reason::SourceChanged);
    }
    let _ = allowance(&state, owner)?; // Actual SAME original live census before IO.
    Ok(()) // All Doc/Edit/Host guards are gone before NativeUse/journal calls.
}

#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) async fn run(
    document: &DocumentBinding,
    owner: &Arc<OriginalWork>,
    request: Request,
) -> Result<crate::asset_session::Staged, Reason> {
    let held = &request.held;
    if held.attempted.swap(true, Ordering::SeqCst) {
        return Err(Reason::VaultInterrupted);
    }
    held.io_returned.store(false, Ordering::SeqCst);
    let result = async {
        rematch(document, owner, held)?;
        let lease = held
            .setup
            .ready
            .begin_use()
            .map_err(|error| service_error(error.code).reason)?;
        held.native_use
            .set(lease)
            .map_err(|_| Reason::CleanupUnknown)?;
        held.check_use(owner)?;
        let child = match &held.bound {
            Some(bound) => Child::Check {
                reference: bound.reference,
                roster: ProjectRoster {
                    generation: held.roster.generation,
                    roots: held.roster.roots.clone(),
                },
            },
            None => Child::RecoveryRoot {
                identity: held.key.identity(),
                roster: ProjectRoster {
                    generation: held.roster.generation,
                    roots: held.roster.roots.clone(),
                },
            },
        };
        match native(document, owner, child).await? {
            ChildResult::Checked => {}
            _ => return Err(Reason::CleanupUnknown),
        }
        rematch(document, owner, held)?;
        held.check_use(owner)?;
        let change = held
            .observed
            .with(|observed| match held.action {
                Action::AcknowledgeUnstarted => saved::prepare_acknowledge(
                    held.setup.ready.store(),
                    held.preference_revision,
                    &held.observed.project,
                    observed,
                    held.work_end,
                ),
                Action::RememberBound => {
                    let reference = held
                        .bound
                        .as_ref()
                        .ok_or(persistence::Failure::Data(setup::Error::Stale))?
                        .reference;
                    saved::prepare_bound(
                        held.setup.ready.store(),
                        held.preference_revision,
                        &held.observed.project,
                        KeyReference::native(
                            reference.identity,
                            reference.record,
                            reference.revision,
                        ),
                        observed,
                        held.work_end,
                    )
                }
            })
            .map_err(|error| {
                if uncertain(error) {
                    held.unknown.store(true, Ordering::SeqCst);
                }
                preference_error(error).reason
            })?;
        {
            let mut retained = held.change.try_lock().map_err(|_| Reason::CleanupUnknown)?;
            if retained.is_some() {
                return Err(Reason::CleanupUnknown);
            }
            *retained = Some(change);
        }
        rematch(document, owner, held)?;
        held.check_use(owner)?;
        let revision = {
            let mut retained = held.change.try_lock().map_err(|_| Reason::CleanupUnknown)?;
            retained
                .as_mut()
                .ok_or(Reason::CleanupUnknown)?
                .commit_once(held.setup.ready.store(), held.work_end)
                .map_err(|error| {
                    if uncertain(error) {
                        held.unknown.store(true, Ordering::SeqCst);
                    }
                    preference_error(error).reason
                })?
        };
        let completion = Arc::new(Completion {
            owner: Arc::downgrade(owner),
            context: Arc::downgrade(&held.context),
            action: held.action,
            preference_revision: revision,
            reference: held.bound.as_ref().map(|bound| bound.reference),
            disposed: AtomicBool::new(false),
        });
        held.completion
            .set(completion.clone())
            .map_err(|_| Reason::CleanupUnknown)?;
        rematch(document, owner, held)?;
        Ok(crate::asset_session::Staged::Vault(
            Staged::UploadKeyRecovered(completion),
        ))
    }
    .await;
    held.io_returned.store(true, Ordering::SeqCst); // Only this original job returns IO.
    if matches!(result, Err(Reason::Deadline)) {
        if let Ok(mut work) = owner.vault.try_lock() {
            work.fail(Reason::Deadline, held.work_end);
        }
        owner.signal_stop();
    }
    result
}
fn uncertain(error: persistence::Failure) -> bool {
    match error {
        persistence::Failure::Data(setup::Error::RecoveryRequired) => true,
        persistence::Failure::Storage(error) => {
            error.effect == crate::application_state_store::Effect::Unknown
                || error.durability == crate::application_state_store::Durability::Unknown
                || error.cleanup == crate::application_state_store::Cleanup::Unknown
                || matches!(
                    error.code,
                    crate::service_protocol::Error::RecoveryRequired
                        | crate::service_protocol::Error::StateUnknown
                )
        }
        _ => false,
    }
}

pub(in crate::asset_session) fn publish_allowed(
    document: &DocumentBinding,
    state: &DocumentState,
    slot: &Slot,
    work: &crate::asset_session::vault::Work,
    completion: &Arc<Completion>,
) -> bool {
    // The vault publisher already holds Work, so do not recursively borrow it.
    let Some(held) = &work.upload_key_recovery.held else {
        return false;
    };
    slot.operation == Operation::RecoverUploadKey
        && !held.unknown.load(Ordering::SeqCst)
        && held.io_returned.load(Ordering::SeqCst)
        && !held.published.load(Ordering::SeqCst)
        && held.work_current(&slot.owner).is_ok()
        && held.native_use.get().is_some()
        && held
            .completion
            .get()
            .is_some_and(|same| Arc::ptr_eq(same, completion))
        && completion
            .owner
            .upgrade()
            .is_some_and(|same| Arc::ptr_eq(&same, &slot.owner))
        && completion
            .context
            .upgrade()
            .is_some_and(|same| Arc::ptr_eq(&same, &held.context))
        && work.original_join.is_none()
        && work.failed_child_join.is_none()
        && slot
            .owner
            .coordinator
            .try_lock()
            .is_ok_and(|book| book.handle.is_none() && book.receipt == JoinReceipt::Returned)
        && slot
            .owner
            .child
            .try_lock()
            .is_ok_and(|book| book.handle.is_none() && book.receipt == JoinReceipt::Returned)
        && current_prepared(document, state, &held.setup).is_ok()
        && held.bound.as_ref().is_none_or(|bound| bound.current(state))
        && held.change.try_lock().is_ok_and(|change| {
            change.as_ref().is_some_and(|change| {
                change.known_revision() == Some(completion.preference_revision)
            })
        })
}
pub(in crate::asset_session) fn published(owner: &OriginalWork) -> bool {
    owner.vault.try_lock().is_ok_and(|work| {
        work.upload_key_recovery
            .held
            .as_ref()
            .is_some_and(|held| !held.published.swap(true, Ordering::SeqCst))
    })
}

pub(super) fn projection(
    document: &DocumentBinding,
    state: &DocumentState,
    observed: Option<(&persistence::PreferenceSnapshot, &NativeObservation)>,
) -> RecoveryStatus {
    let mut value = RecoveryStatus {
        preference_revision: None,
        state: "recovery-required",
        record: None,
        operation: None,
    };
    if let Some(slot) = state
        .slot
        .as_ref()
        .filter(|slot| slot.operation == Operation::RecoverUploadKey)
    {
        let completion = slot.vault.upload_key_recovery.as_ref();
        let complete = completion.is_some_and(|completion| {
            completion.disposed.load(Ordering::SeqCst)
                && completion
                    .owner
                    .upgrade()
                    .is_some_and(|same| Arc::ptr_eq(&same, &slot.owner))
                && completion.context.upgrade().is_some_and(|context| {
                    state
                        .context
                        .as_ref()
                        .is_some_and(|same| Arc::ptr_eq(same, &context))
                })
                && slot.phase == Phase::Idle
                && slot.settlement == Settlement::Known
                && slot.reason == Reason::None
                && slot.error.is_none()
                && slot.cleanup_end.is_none()
                && !slot.owner.stopped()
                && slot.owner.resources_settled()
                && slot
                    .owner
                    .vault
                    .try_lock()
                    .is_ok_and(|work| work.upload_key_recovery.empty() && work.first.is_none())
                && slot
                    .owner
                    .retirement
                    .try_lock()
                    .is_ok_and(|retired| !retired.vault.upload_key_recovery.blocks_reuse())
                && completion.reference.is_none_or(|reference| {
                    state.vault.as_ref().is_some_and(|vault| {
                        vault.identity == Some(reference.identity)
                            && vault.rows.iter().any(|row| {
                                same_reference(row.reference(reference.identity), reference)
                            })
                    })
                })
        });
        let action = completion.map(|value| value.action).or_else(|| {
            slot.owner.vault.try_lock().ok().and_then(|work| {
                work.upload_key_recovery
                    .held
                    .as_ref()
                    .map(|held| held.action)
            })
        });
        if let Some(action) = action {
            value.operation = Some(RecoveryOperation {
                operation_id: slot.owner.id,
                action,
                phase: if complete {
                    "completed"
                } else if slot.owner.stopped()
                    || slot.reason != Reason::None
                    || slot.settlement == Settlement::Unknown
                {
                    "recovery-required"
                } else {
                    "pending"
                },
                preference_revision: if complete {
                    completion.map(|value| value.preference_revision.to_string())
                } else {
                    None
                },
            });
        }
    }
    let Some((preference, native)) = observed else {
        return value;
    };
    value.preference_revision = Some(preference.store_revision.to_string());
    if native.pending
        || native.storage != Storage::Unlocked
        || native.records.iter().any(|row| row.mutation_pending)
        || !state
            .context
            .as_ref()
            .is_some_and(|context| document.context_matches(state, context).unwrap_or(false))
    {
        return value;
    }
    match &preference.preference {
        None => value.state = "none",
        Some(setup::Preference::GenerationStoppedNoGo(intent))
            if native.identity == intent.identity_sha256
                && native.vault_identity.is_some_and(|vault| {
                    vault.vault.token() == intent.vault_id
                        && vault.generation.token() == intent.generation_id
                })
                && native
                    .records
                    .iter()
                    .all(|row| row.reference.record_id != intent.record_id) =>
        {
            value.state = "acknowledge-unstarted"
        }
        Some(preference) => {
            let row = match preference {
                setup::Preference::GenerationReserved(intent)
                    if native.identity == intent.identity_sha256 =>
                {
                    native.records.iter().find(|row| {
                        row.reference.vault_id == intent.vault_id
                            && row.reference.generation_id == intent.generation_id
                            && row.reference.record_id == intent.record_id
                            && row.reference.revision_counter == 1
                    })
                }
                setup::Preference::RecordSaved(saved) | setup::Preference::Assigned(saved)
                    if native.identity == saved.identity_sha256 =>
                {
                    native
                        .records
                        .iter()
                        .find(|row| row.reference == saved.reference)
                }
                _ => None,
            };
            if let Some(row) = row {
                value.record = Some(row.reference.clone());
                value.state = if state
                    .slot
                    .as_ref()
                    .and_then(|slot| remembered_bound_reference(state, slot, Kind::AndroidKeystore))
                    .is_some_and(|bound| {
                        KeyReference::native(bound.identity, bound.record, bound.revision)
                            == row.reference
                    }) {
                    "remember-bound"
                } else {
                    "check-saved-key"
                };
            }
        }
    }
    value
}

#[cfg(feature = "desktop-shell")]
impl DocumentBinding {
    pub(crate) fn recover_upload_key(
        &self,
        request: RecoveryRequest,
    ) -> Result<UploadKeyStatus, AssetError> {
        self.reconcile();
        let mut state = self.lock();
        self.expire(&mut state, Instant::now());
        if !available(self) {
            return Err(AssetError::new(Reason::Unqualified));
        }
        self.durable_gate(&state, true)?;
        idle(&state)?;
        if state.revision != request.status_revision {
            return Err(AssetError::new(Reason::ContextStale));
        }
        let context = state
            .context
            .as_ref()
            .filter(|context| {
                context.revision == request.context_revision
                    && context.platform == Platform::Android
            })
            .ok_or_else(|| AssetError::new(Reason::ContextStale))?
            .clone();
        let prepared = state
            .vault
            .as_ref()
            .and_then(|session| session.upload_key_setup.ready.clone())
            .ok_or_else(|| AssetError::new(Reason::VaultInterrupted))?;
        current_prepared(self, &state, &prepared)?;
        let observed = self.credential_observation_for_binding(
            &state,
            prepared.ready.project_binding().clone(),
            Role::AndroidUpload,
        )?;
        if observed.pending || observed.storage != Storage::Unlocked {
            return Err(AssetError::new(Reason::VaultInterrupted));
        }
        // Capture the real Bind BEFORE the new slot retires its predecessor.
        let bound = match request.action {
            Action::AcknowledgeUnstarted => None,
            Action::RememberBound => Some(
                BoundCapture::capture(&state)
                    .ok_or_else(|| AssetError::new(Reason::SourceChanged))?,
            ),
        };
        let roster = self.vault_roster(&mut state)?;
        let mut slot = self.vault_owner(
            &mut state,
            Operation::RecoverUploadKey,
            Some(context.clone()),
            bound.as_ref().map(|bound| bound.reference.key()),
            None,
            true,
        )?;
        let owner = slot.owner.clone();
        let session = state
            .vault
            .as_ref()
            .ok_or_else(|| AssetError::new(Reason::Closed))?;
        let held = Arc::new(Recovery {
            owner: Arc::downgrade(&owner),
            setup: prepared,
            context,
            store: session.store.clone(),
            key: session
                .key
                .clone()
                .ok_or_else(|| AssetError::new(Reason::VaultKeyMissing))?,
            observed,
            roster,
            bound,
            action: request.action,
            preference_revision: request.preference_revision,
            work_end: owner
                .endpoint()
                .ok_or_else(|| AssetError::new(Reason::Deadline))?,
            native_use: OnceLock::new(),
            use_retirement_claimed: AtomicBool::new(false),
            use_retired: AtomicBool::new(false),
            attempted: AtomicBool::new(false),
            io_returned: AtomicBool::new(true),
            unknown: AtomicBool::new(false),
            published: AtomicBool::new(false),
            change: Mutex::new(None),
            completion: OnceLock::new(),
        });
        owner
            .vault
            .try_lock()
            .map_err(|_| AssetError::new(Reason::CleanupUnknown))?
            .upload_key_recovery
            .held = Some(held.clone());
        slot.kind = Some(Kind::AndroidKeystore);
        let _ = pending_allowance(&state, &slot).map_err(AssetError::new)?;
        let start = self.install(
            &mut state,
            slot,
            crate::asset_session::Job::Vault(Job::RecoverUploadKey(Request { held })),
        )?;
        let result = project(self, &state, Plan::RecoveryRequired);
        drop(state);
        let _ = start.send(());
        Ok(result)
    }
}

/// This object is created only alongside the consumed noGO cancellation proof,
/// retained in the SAME original Retirement. It is NOT an acknowledgement.
#[derive(Default)]
pub(in crate::asset_session) struct StoppedWrite {
    attempted: bool,
    change: Option<saved::Change>,
    revision: Option<u64>,
}
pub(in crate::asset_session) fn persist_stopped(
    held: &super::super::Holding,
    write: &mut StoppedWrite,
) -> bool {
    #[cfg(not(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        let _ = (held, write);
        false
    }
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        let Some(end) = super::super::cancellation::disposed_cleanup_window(held) else {
            return false;
        };
        if write.attempted {
            return write.revision.is_some();
        }
        write.attempted = true; // BEFORE first actual native-state read; never replay.
        let Some(reservation) = held.reservation.get() else {
            return false;
        };
        let Some(lease) = held.native_use.get() else {
            return false;
        };
        if held.native_use_retired.load(Ordering::SeqCst)
            || lease.store().check_native_use(lease.native_use()).is_err()
        {
            return false;
        }
        if super::super::cancellation::disposed_cleanup_window(held).is_none() {
            return false;
        }
        let Ok(change) = saved::prepare_stopped_no_go(lease.store(), reservation, end) else {
            return false;
        };
        write.change = Some(change); // Original proposal retained before CAS.
        let Some(end) = super::super::cancellation::disposed_cleanup_window(held) else {
            return false;
        };
        let result = write
            .change
            .as_mut()
            .unwrap()
            .commit_once(lease.store(), end);
        write.revision = write
            .change
            .as_ref()
            .and_then(saved::Change::known_revision);
        result.is_ok() && super::super::cancellation::disposed_cleanup_window(held).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn closed_request_requires_canonical_full_store_revision_no_paths_or_new_app_declaration() {
        let valid = json!({"contextRevision":1,"expectedStatusRevision":2,"expectedPreferenceRevision":"18446744073709551615","action":"acknowledge-unstarted"});
        assert!(request(&valid).is_ok());
        for value in [
            json!(1),
            json!("01"),
            json!("+1"),
            json!("-1"),
            json!("18446744073709551616"),
            json!(null),
        ] {
            let mut bad = valid.clone();
            bad["expectedPreferenceRevision"] = value;
            assert!(request(&bad).is_err());
        }
        for field in ["path", "password", "recordId", "declaration", "noGo"] {
            let mut bad = valid.clone();
            bad[field] = json!(true);
            assert!(request(&bad).is_err());
        }
    }
    #[test]
    fn unknown_storage_and_late_result_are_not_replay_permissions() {
        assert!(uncertain(persistence::Failure::Data(
            setup::Error::RecoveryRequired
        )));
        assert!(!uncertain(persistence::Failure::Data(setup::Error::Stale)));
        let mut error = crate::application_state_store::StateError {
            code: crate::service_protocol::Error::Conflict,
            effect: crate::application_state_store::Effect::None,
            durability: crate::application_state_store::Durability::NotApplicable,
            cleanup: crate::application_state_store::Cleanup::Known,
        };
        assert!(!uncertain(persistence::Failure::Storage(error)));
        error.effect = crate::application_state_store::Effect::Applied;
        error.durability = crate::application_state_store::Durability::Unknown;
        assert!(uncertain(persistence::Failure::Storage(error)));
    }
    #[test]
    fn captured_bind_survives_old_slot_retirement_but_not_payload_context_or_random_revision_alias()
    {
        // Reuse the existing ORIGINAL BoundLoan fixture. Its assessment/join
        // inputs are synthetic DATA, not a native key or signing qualification.
        let mut state = crate::asset_session::vault::assignment_native_regressions::bound_data();
        let captured = BoundCapture::capture(&state).expect("synthetic current Bind");
        let mut slot = state.slot.take().unwrap();
        let retired = take_retirement(&mut state, &mut slot);
        assert!(slot.vault.reference.is_none());
        drop(retired);
        state.slot = Some(slot);
        assert!(captured.current(&state));
        let old = state.vault.as_ref().unwrap().rows[0].authenticated.revision;
        state.vault.as_mut().unwrap().rows[0].authenticated.revision =
            format::Revision::new(format::Id::from_bytes([219; 16]).unwrap(), old.counter).unwrap();
        assert!(!captured.current(&state));
        state.vault.as_mut().unwrap().rows[0].authenticated.revision = old;
        assert!(captured.current(&state));
        let context = state.context.as_ref().unwrap();
        state.context = Some(Arc::new(NativeContext {
            execution_mode: context.execution_mode,
            revision: context.revision,
            project_id: context.project_id.clone(),
            project: context.project.clone(),
            registry_generation: context.registry_generation,
            draft: context.draft.clone(),
            platform: context.platform,
            stage: context.stage,
            purpose: context.purpose,
        }));
        assert!(!captured.current(&state)); // Equal DATA cannot replace the original Arc.
        state.context = Some(captured.context.clone());
        assert!(captured.current(&state));
        state
            .vault
            .as_mut()
            .unwrap()
            .bound
            .iter_mut()
            .for_each(|loan| *loan = None);
        assert!(!captured.current(&state)); // A retained payload alone is not a current Bind.
    }
    #[test]
    fn no_assessment_unknown_bind_or_failed_original_cannot_be_captured_for_reconciliation() {
        let mut state = crate::asset_session::vault::assignment_native_regressions::bound_data();
        let assessment = state.slot.as_mut().unwrap().assessment.take();
        assert!(BoundCapture::capture(&state).is_none());
        state.slot.as_mut().unwrap().assessment = assessment;
        state.slot.as_mut().unwrap().settlement = Settlement::Unknown;
        assert!(BoundCapture::capture(&state).is_none());
        state.slot.as_mut().unwrap().settlement = Settlement::Known;
        state
            .slot
            .as_ref()
            .unwrap()
            .owner
            .vault
            .lock()
            .unwrap()
            .failed_child_join = Some(JoinReceipt::Failed);
        assert!(BoundCapture::capture(&state).is_none());
    }
    #[test]
    fn post_native_use_retirement_checks_original_endpoint_and_never_renews_cleanup() {
        use std::time::Duration;
        // No NativeUse or producer receipts fabricated: exercise the actual
        // before/AFTER-return predicate with the original Work and endpoints.
        let owner = OriginalWork::new(171, false, Weak::new());
        let end = Instant::now() + Duration::from_secs(10);
        assert!(!retirement_window_facts(&owner, end, true, false));
        assert!(!retirement_window_facts(&owner, end, false, true));
        assert!(retirement_window_facts(&owner, end, true, true));
        owner.set_endpoint(None); // Generic retirement cannot erase our fixed deadline.
        assert!(!retirement_window_facts(&owner, Instant::now(), true, true));
        let first = Instant::now() - Duration::from_secs(1);
        {
            let mut work = owner.vault.lock().unwrap();
            work.fail(Reason::UserCancelled, first);
            work.release = true;
            work.release_end = Some(end);
        }
        owner.signal_stop();
        assert!(!retirement_window_facts(&owner, end, false, true));
        owner.vault.lock().unwrap().release_claimed = true;
        assert!(retirement_window_facts(&owner, end, false, true));
        owner.vault.lock().unwrap().release_end = Some(Instant::now());
        assert!(!retirement_window_facts(&owner, end, true, true));
        assert!(owner.vault.lock().unwrap().first == Some((Reason::UserCancelled, first)));
    }
}
