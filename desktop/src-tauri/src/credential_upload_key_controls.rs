//! Closed Desktop controls for the existing upload-key/vault original. Status
//! is read-only. Explicit prepare uses the actual Host startup; explicit create
//! consumes one current new-app declaration. No renderer path/secret/tool/grant
//! or producer-shaped success is admitted here.
use super::*;
use crate::application_service_host::{NativeProject, NativeStateLease, NativeStateReady};
use crate::edit_owner::SavedEditStamp;
#[path = "credential_upload_key_recovery.rs"]
pub(in crate::asset_session) mod recovery;
pub(crate) use recovery::{request as recovery_request, RecoveryRequest};

// Nonshipping selector is consumed INSIDE the same bodies. Registration alone
// cannot enable renderer status/prepare/create; ordinary qualification is unchanged.
#[cfg(feature = "desktop-shell")]
pub(in crate::asset_session) enum Qualification {
    Ordinary,
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    Installed(crate::shell::installed_observation::vault::upload_key::Selection),
}
#[derive(Default)]
struct Admission {
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    installed: Option<Arc<crate::shell::installed_observation::vault::Control>>,
}
#[cfg(feature = "desktop-shell")]
#[derive(Clone,Copy)]
pub(in crate::asset_session) enum SelectedAction { Prepare, Create, Recover }
impl Admission {
    fn qualified(&self, document: &DocumentBinding) -> bool {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
        if let Some(control)=&self.installed {return control.permits(&document.inner.session_identity);}
        available(document)
    }
    fn recovery_action(&self, action: recovery::Action) -> bool {
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
        if let Some(control) = &self.installed {
            use crate::shell::installed_observation::vault::upload_key::Case;
            return matches!((control.upload.case(control.case), action),
                (Some(Case::StopBeforeGo), recovery::Action::AcknowledgeUnstarted)
                | (Some(Case::StopAfterNew), recovery::Action::RememberBound));
        }
        let _ = action;
        true
    }
    fn same(&self, other: &Self) -> bool {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
        { return match (&self.installed,&other.installed) {(None,None)=>true,(Some(a),Some(b))=>Arc::ptr_eq(a,b),_=>false}; }
        #[allow(unreachable_code)]
        { let _=other; true }
    }
}
#[cfg(feature = "desktop-shell")]
impl Qualification {
    fn admit(self, document:&DocumentBinding, action:SelectedAction, path:Option<&std::path::Path>) -> Result<Admission,AssetError> {
        match self {
            Self::Ordinary if available(document) => Ok(Admission::default()),
            Self::Ordinary => Err(AssetError::new(Reason::Unqualified)),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
            Self::Installed(selection) => {
                use crate::shell::installed_observation::vault::upload_key::Action;
                if !matches!((action,selection.action()),
                    (SelectedAction::Prepare,Action::Prepare | Action::RecoveryPrepare | Action::BoundPrepare)
                    | (SelectedAction::Recover,Action::AcknowledgeUnstarted | Action::RememberBound))
                    && !(matches!(action,SelectedAction::Create) && selection.action().creates()) {return Err(AssetError::invalid());}
                let control=document.installed_upload_consume(selection,path)?;
                Ok(Admission{installed:Some(control)})
            },
        }
    }
}

const DECLARATION: &str = "new-application-no-existing-upload-key";

pub(crate) struct ContextRequest {
    pub(crate) context_revision: u32,
}
pub(crate) struct CreateRequest {
    context_revision: u32,
    expected_revision: u32,
}
fn positive(value: &Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0 && *value < u32::MAX)
}
pub(crate) fn context_request(value: &Value) -> Result<ContextRequest, AssetError> {
    let value = value
        .as_object()
        .filter(|value| value.len() == 1)
        .ok_or_else(AssetError::invalid)?;
    Ok(ContextRequest {
        context_revision: value
            .get("contextRevision")
            .and_then(positive)
            .ok_or_else(AssetError::invalid)?,
    })
}
pub(crate) fn create_request(value: &Value) -> Result<CreateRequest, AssetError> {
    let value = value
        .as_object()
        .filter(|value| value.len() == 3)
        .ok_or_else(AssetError::invalid)?;
    if value.get("declaration").and_then(Value::as_str) != Some(DECLARATION) {
        return Err(AssetError::invalid());
    }
    Ok(CreateRequest {
        context_revision: value
            .get("contextRevision")
            .and_then(positive)
            .ok_or_else(AssetError::invalid)?,
        expected_revision: value
            .get("expectedStatusRevision")
            .and_then(positive)
            .ok_or_else(AssetError::invalid)?,
    })
}

#[derive(Default)]
pub(in crate::asset_session) struct Setup {
    flight: Option<Arc<SetupFlight>>,
    ready: Option<Arc<PreparedSetup>>,
    failure: Option<Reason>,
}
struct SetupFlight {
    context: Arc<NativeContext>,
    original: NativeProject,
    edit: SavedEditStamp,
}
impl SetupFlight {
    fn retained_bytes(&self) -> Option<usize> {
        // Also charge this exact context when a later document context replaces
        // it. Shared current-context bytes may be conservatively counted twice;
        // they must never disappear from the census on navigation/retirement.
        std::mem::size_of::<Self>()
            .checked_add(4 * std::mem::size_of::<usize>())?
            .checked_add(self.original.runtime_id.capacity())?
            .checked_add(self.original.canonical_root.capacity())?
            .checked_add(std::mem::size_of::<NativeContext>())?
            .checked_add(self.context.draft.capacity())?
            .checked_add(self.context.project_id.capacity())?
            .checked_add(self.context.project.path.capacity())
    }
}
pub(in crate::asset_session) struct PreparedSetup {
    admission: Admission,
    flight: Arc<SetupFlight>,
    ready: Arc<NativeStateReady>,
    preference: persistence::PreferenceSnapshot,
    attempted: AtomicBool,
}
impl Setup {
    pub(in crate::asset_session) fn pending(&self) -> bool {
        self.flight.is_some()
    }
    pub(in crate::asset_session) fn retained_bytes(&self) -> Option<usize> {
        let mut bytes = 0usize;
        if let Some(flight) = &self.flight {
            bytes = bytes.checked_add(flight.retained_bytes()?)?;
        }
        if let Some(ready) = &self.ready {
            bytes = bytes.checked_add(ready.retained_bytes()?)?;
        }
        Some(bytes)
    }
}
impl PreparedSetup {
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(super) fn installed_control(&self) -> Option<&Arc<crate::shell::installed_observation::vault::Control>> {self.admission.installed.as_ref()}
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        // Preference is bounded reference DATA. Count its actual strings rather
        // than treating a serialized reference as a credential loan.
        let preference = self
            .preference
            .preference
            .as_ref()
            .map_or(Some(0), |preference| {
                let mut bytes = std::mem::size_of::<setup::Preference>();
                match preference {
                    setup::Preference::GenerationReserved(value) | setup::Preference::GenerationStoppedNoGo(value) => {
                        for text in [
                            &value.operation_id,
                            &value.vault_id,
                            &value.generation_id,
                            &value.record_id,
                            &value.identity_sha256,
                        ] {
                            bytes = bytes.checked_add(text.capacity())?;
                        }
                    }
                    setup::Preference::RecordSaved(value) | setup::Preference::Assigned(value) => {
                        for text in [
                            &value.reference.vault_id,
                            &value.reference.generation_id,
                            &value.reference.record_id,
                            &value.reference.revision_id,
                            &value.identity_sha256,
                            &value.operation_id,
                        ] {
                            bytes = bytes.checked_add(text.capacity())?;
                        }
                        bytes = bytes.checked_add(
                            value
                                .certificate_sha256
                                .as_ref()
                                .map_or(0, String::capacity),
                        )?;
                    }
                }
                Some(bytes)
            })?;
        std::mem::size_of::<Self>()
            .checked_add(self.flight.retained_bytes()?)?
            .checked_add(4 * std::mem::size_of::<usize>())?
            .checked_add(self.ready.retained_bytes()?)?
            .checked_add(preference)
    }
}

/// One closed native declaration from the genuine current setup. Its only
/// constructor is the explicit create command below; never Serialize/Clone.
pub(in crate::asset_session) struct Consent {
    prepared: Arc<PreparedSetup>,
    revision: u32,
    admission: Admission,
}
impl Consent {
    pub(super) fn qualified(&self,document:&DocumentBinding)->bool {self.admission.qualified(document) && self.admission.same(&self.prepared.admission)}
    pub(super) fn preparation(&self) -> &Arc<PreparedSetup> {
        &self.prepared
    }
    pub(super) fn project_binding(&self) -> crate::application_service::ProjectBinding {
        self.prepared.ready.project_binding().clone()
    }
    pub(super) fn service_matches(&self, service: &Arc<ApplicationService>) -> bool {
        Arc::ptr_eq(service.state_directory(), self.prepared.ready.store())
    }
    pub(super) fn preference(&self) -> &persistence::PreferenceSnapshot {
        &self.prepared.preference
    }
    pub(super) fn current(
        &self,
        document: &DocumentBinding,
        state: &DocumentState,
    ) -> Result<(), AssetError> {
        if state.revision != self.revision || !self.prepared.attempted.load(Ordering::SeqCst) {
            return Err(AssetError::new(Reason::ContextStale));
        }
        current_prepared(document, state, &self.prepared)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UploadKeyStatus {
    schema_version: u8,
    assets: AssetStatus,
    capability: Capability,
    setup: &'static str,
    plan: Plan,
    operation: Option<GenerationStatus>,
    saved: Option<KeyReference>,
    recovery: recovery::RecoveryStatus,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerationStatus {
    operation_id: u32,
    phase: &'static str,
    reason: Reason,
}

/// Called at the genuine NEW publisher before ordinary working-reference
/// retirement. This fixed nonsecret stamp is display DATA, not disposal proof.
pub(in crate::asset_session) fn publication_stamp(
    slot: &Slot,
    row: &Descriptor,
    identity: format::Identity,
) -> Option<(u32, StoredRef)> {
    if slot.operation != Operation::GenerateUploadKey {
        return None;
    }
    Some((slot.context.as_ref()?.revision, row.reference(identity)))
}
fn stored_marker(
    document: &DocumentBinding,
    state: &DocumentState,
    slot: &Slot,
) -> Option<KeyReference> {
    if !document
        .context_matches(state, state.context.as_ref()?)
        .ok()?
    {
        return None;
    }
    retained_saved_reference(state, slot)
}
// Memory-only half of the fixed status projection. The public caller above
// ALSO requires the current actual native document/root/context rematch.
fn retained_saved_reference(state: &DocumentState, slot: &Slot) -> Option<KeyReference> {
    let (revision, reference) = slot.vault.upload_key_context?;
    let context = state.context.as_ref()?;
    let session = state.vault.as_ref()?;
    let row = session
        .rows
        .iter()
        .find(|row| row.authenticated.record == reference.record)?;
    let identity = app_policy(&context.draft, Role::AndroidUpload).ok()?.0;
    if slot.operation != Operation::GenerateUploadKey
        || !slot.vault.upload_key_new_published
        || slot.phase != Phase::Idle
        || slot.settlement != Settlement::Known
        || slot.reason != Reason::None
        || slot.error.is_some()
        || slot.cleanup_end.is_some()
        || slot.vault.outcome
            != Some(store::StorageOutcome {
                effect: store::Effect::KnownApplied,
                durability: store::Durability::Confirmed,
                cleanup: store::Cleanup::Known,
            })
        || context.revision != revision
        || !slot.owner.resources_settled()
        || slot.owner.stopped()
        || !slot.owner.upload_key_clock.get().is_some_and(|clock| {
            clock.completed.load(Ordering::SeqCst) && !clock.failed.load(Ordering::SeqCst)
        })
        || !slot.owner.vault.try_lock().is_ok_and(|work| {
            work.upload_key.empty() && work.first.is_none() && original_joins(&slot.owner, &work)
        })
        || !slot
            .owner
            .retirement
            .try_lock()
            .is_ok_and(|retirement| !retirement.vault.upload_key_blocks_reuse())
        || !same_reference(reference, row.reference(reference.identity))
        || certificate_for(session, row, &identity).is_none()
    {
        return None;
    }
    Some(KeyReference::native(
        reference.identity,
        reference.record,
        reference.revision,
    ))
}
fn operation_projection(
    document: &DocumentBinding,
    state: &DocumentState,
) -> (Option<GenerationStatus>, Option<KeyReference>) {
    let Some(slot) = state
        .slot
        .as_ref()
        .filter(|slot| slot.operation == Operation::GenerateUploadKey)
    else {
        return (None, None);
    };
    if let Some(saved) = stored_marker(document, state, slot) {
        return (
            Some(GenerationStatus {
                operation_id: slot.owner.id,
                phase: "saved",
                reason: Reason::None,
            }),
            Some(saved),
        );
    }
    let phase = pending_phase(slot);
    (
        Some(GenerationStatus {
            operation_id: slot.owner.id,
            phase,
            reason: if phase == "recovery-required" {
                if slot.reason == Reason::None {
                    Reason::VaultInterrupted
                } else {
                    slot.reason
                }
            } else {
                Reason::None
            },
        }),
        None,
    )
}
// A contended progress borrow or the real Work -> Retirement transfer does
// not observe failure. Keep those windows pending; only the full marker above
// may display Saved, and actual original failures remain absorbing.
fn pending_phase(slot: &Slot) -> &'static str {
    if slot.owner.stopped()
        || slot.reason != Reason::None
        || slot.error.is_some()
        || slot.cleanup_end.is_some()
        || slot.phase == Phase::Unknown
        || matches!(slot.settlement, Settlement::Unknown | Settlement::LateKnown)
        || !slot
            .owner
            .upload_key_clock
            .get()
            .is_some_and(|clock| !clock.failed.load(Ordering::SeqCst))
    {
        return "recovery-required";
    }
    slot.owner
        .vault
        .try_lock()
        .ok()
        .and_then(|work| {
            work.upload_key.inner.as_ref().and_then(|held| {
                held.progress.try_lock().ok().map(|progress| {
                    if held.clock.failed.load(Ordering::SeqCst)
                        || progress.first.is_some()
                        || held.run.get().is_some_and(|run| run.cleanup_unknown())
                    {
                        "recovery-required"
                    } else {
                        match progress.phase {
                            ProgressPhase::Storing
                            | ProgressPhase::Stored
                            | ProgressPhase::Recording => "saving",
                            ProgressPhase::Recorded | ProgressPhase::Published => "finishing",
                            ProgressPhase::Failed => "recovery-required",
                            _ => "generating",
                        }
                    }
                })
            })
        })
        .unwrap_or("finishing")
}
fn project(document: &DocumentBinding, state: &DocumentState, plan: Plan) -> UploadKeyStatus {
    let setup = state.vault.as_ref().map(|vault| &vault.upload_key_setup);
    let (operation, saved) = operation_projection(document, state);
    UploadKeyStatus {
        schema_version: 1,
        assets: document.snapshot(state),
        capability: Capability {
            available: available(document),
            reason: if available(document) {
                Reason::None
            } else {
                Reason::Unqualified
            },
        },
        setup: match setup {
            Some(setup) if setup.flight.is_some() => "checking",
            Some(setup) if setup.failure.is_some() => "failed",
            Some(setup)
                if setup
                    .ready
                    .as_ref()
                    .is_some_and(|ready| ready.attempted.load(Ordering::SeqCst)) =>
            {
                "attempted"
            }
            Some(setup) if setup.ready.is_some() => "ready",
            _ => "required",
        },
        plan,
        operation,
        saved,
        recovery: recovery::projection(document, state, None),
    }
}

pub(super) fn current_prepared(
    document: &DocumentBinding,
    state: &DocumentState,
    prepared: &Arc<PreparedSetup>,
) -> Result<(), AssetError> {
    if !state
        .context
        .as_ref()
        .is_some_and(|context| Arc::ptr_eq(context, &prepared.flight.context))
        || !state.vault.as_ref().is_some_and(|vault| {
            vault
                .upload_key_setup
                .ready
                .as_ref()
                .is_some_and(|ready| Arc::ptr_eq(ready, prepared))
        })
        || !document.context_matches(state, &prepared.flight.context)?
    {
        return Err(AssetError::new(Reason::ContextStale));
    }
    #[cfg(feature = "desktop-shell")]
    {
        let original = document
            .service_allow_current_locked(state, &prepared.flight.original, &prepared.flight.edit)
            .map_err(|_| AssetError::new(Reason::ContextStale))?;
        document
            .inner
            .bridge
            .application_service
            .native_state_current(&prepared.ready, &original)
            .map_err(service_error)?;
        Ok(())
    }
    #[cfg(not(feature = "desktop-shell"))]
    {
        let _ = document;
        Err(AssetError::new(Reason::Unqualified))
    }
}

/// Called only in the SAME original generation coordinator, before its first
/// journal IO/private work. The cached setup snapshot only supplied comparison
/// DATA; reserve_generation now re-reads and CAS-checks the actual shared slot.
pub(super) fn begin_use(held: &Holding) -> Result<(), Reason> {
    let owner = held.owner.upgrade().ok_or(Reason::ContextStale)?;
    if owner.interrupted() {
        return Err(Reason::UserCancelled);
    }
    if held.native_use.get().is_some() {
        return Err(Reason::VaultInterrupted);
    }
    let lease = held
        .setup
        .ready
        .begin_use()
        .map_err(|error| service_error(error.code).reason)?;
    held.native_use
        .set(lease)
        .map_err(|_| Reason::CleanupUnknown)
}
pub(super) fn check_use(held: &Holding) -> Result<(), Reason> {
    let owner = held.owner.upgrade().ok_or(Reason::ContextStale)?;
    if owner.interrupted() {
        return Err(Reason::UserCancelled);
    }
    let lease = held.native_use.get().ok_or(Reason::VaultInterrupted)?;
    lease
        .store()
        .check_native_use(lease.native_use())
        .map_err(|error| service_error(error.code).reason)?;
    // A retained Store mutex may have delayed this off-Doc check. Its return
    // cannot renew the original clock or authorize a late journal/private GO.
    if owner.interrupted() {
        return Err(Reason::UserCancelled);
    }
    Ok(())
}
pub(super) fn retire_use(held: &Holding) -> bool {
    let Some(owner) = held.owner.upgrade() else {
        return false;
    };
    if !held.native_use_retired.load(Ordering::SeqCst) {
        let Some(lease) = held.native_use.get() else {
            return false;
        };
        if lease.store().retire_native_use(lease.native_use()).is_err() {
            return false;
        }
        // This is the actual Store return, not private-disposal completion.
        // Preserve it even if that blocking mutex wait crossed the deadline;
        // a later observation must not retire the same token a second time.
        held.native_use_retired.store(true, Ordering::SeqCst);
    }
    retirement_window(&owner, &held.clock)
}
// Fixed post-Store-return guard. Only the original parent's preceding genuine
// publication/private-disposal/all-join checks authorize reaching this point;
// this time check cannot create those receipts or complete a clock by itself.
fn retirement_window(owner: &OriginalWork, clock: &Arc<UploadKeyClock>) -> bool {
    if !owner
        .upload_key_clock
        .get()
        .is_some_and(|original| Arc::ptr_eq(original, clock))
    {
        return false;
    }
    if Instant::now() >= clock.work_end() {
        // Use the immutable original endpoint, never status-now/new lifetime.
        // parent_stop preserves the original Work reason and minimum first-F.
        parent_stop(owner, Reason::Deadline, clock.work_end());
        return false;
    }
    !owner.interrupted()
        && !clock.failed.load(Ordering::SeqCst)
        && !clock.completed.load(Ordering::SeqCst)
}
pub(super) fn retained_use_bytes(held: &Holding) -> Option<usize> {
    held.setup
        .retained_bytes()?
        .checked_add(if held.native_use.get().is_some() {
            std::mem::size_of::<NativeStateLease>()
                + std::mem::size_of::<crate::application_state_store::NativeUse>()
                + 2 * std::mem::size_of::<usize>()
        } else {
            0
        })
}

#[cfg(feature = "desktop-shell")]
impl DocumentBinding {
    pub(crate) fn upload_key_status(
        &self,
        request: ContextRequest,
    ) -> Result<UploadKeyStatus, AssetError> {
        self.reconcile();
        let (revision, ready, observed) = {
            let mut state = self.lock();
            self.expire(&mut state, Instant::now());
            let context = state
                .context
                .as_ref()
                .filter(|context| {
                    context.revision == request.context_revision
                        && context.platform == Platform::Android
                })
                .ok_or_else(|| AssetError::new(Reason::ContextStale))?;
            if !state.lifetime.original_bound() || !self.context_matches(&state, context)? {
                return Err(AssetError::new(Reason::ContextStale));
            }
            if !available(self) {
                return Ok(project(self, &state, Plan::Unavailable));
            }
            let setup = &state
                .vault
                .as_ref()
                .ok_or_else(|| AssetError::new(Reason::Closed))?
                .upload_key_setup;
            if setup.failure.is_some() {
                return Ok(project(self, &state, Plan::RecoveryRequired));
            }
            if setup.pending()
                || state.slot.as_ref().is_some_and(|slot| {
                    matches!(slot.operation, Operation::GenerateUploadKey | Operation::RecoverUploadKey)
                        && (slot.phase != Phase::Idle || !slot.owner.resources_settled())
                })
            {
                return Ok(project(self, &state, Plan::RecoveryRequired));
            }
            let Some(ready) = setup.ready.clone() else {
                return Ok(project(self, &state, Plan::Unavailable));
            };
            current_prepared(self, &state, &ready)?;
            let observed = self.credential_observation_for_binding(
                &state,
                ready.ready.project_binding().clone(),
                Role::AndroidUpload,
            )?;
            (state.revision, ready, observed)
        };
        // No status read starts a Host, changes a preference or confirms history.
        let preference =
            persistence::observe(ready.ready.store(), &observed.project, Role::AndroidUpload)
                .map_err(preference_error)?;
        let plan = observed
            .with(|observation| setup::classify(observation, preference.preference.as_ref()))
            .map_err(data_error)?;
        let state = self.lock();
        if state.revision != revision {
            return Err(AssetError::new(Reason::ContextStale));
        }
        current_prepared(self, &state, &ready)?;
        let mut status = project(self, &state, plan);
        status.recovery = recovery::projection(self, &state, Some((&preference, &observed)));
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn id(byte: u8) -> format::Id {
        format::Id::from_bytes([byte; 16]).unwrap()
    }
    fn reference_data() -> DocumentState {
        let mut state = crate::asset_session::vault::tests::loan_state();
        let old = state.context.take().unwrap();
        state.context = Some(Arc::new(NativeContext {
            execution_mode: old.execution_mode,
            revision: old.revision,
            project_id: old.project_id.clone(),
            project: old.project.clone(),
            registry_generation: old.registry_generation,
            draft: br#"{"android":{"applicationId":"example.inert.app"}}"#.to_vec(),
            platform: Platform::Android,
            stage: Stage::Candidate,
            purpose: Purpose::Signing,
        }));
        let identity = format::Identity::new(id(1), id(2)).unwrap();
        let record = id(3);
        let revision = format::Revision::new(id(4), 1).unwrap();
        let row = Descriptor {
            authenticated: crypto::AuthenticatedDescriptor {
                record,
                revision,
                descriptor: format::Descriptor::new(
                    Kind::AndroidKeystore,
                    None,
                    vec![true; 3],
                    true,
                )
                .unwrap(),
            },
            original: store::ReadWitness::lifecycle_data(record, revision),
            mutation_pending: false,
        };
        let mut session = Session::new(Arc::new(Mutex::new(store::StoreBook::new())), 7);
        session.identity = Some(identity);
        session.state = State::Unlocked;
        session.key = Some(Arc::new(crypto::lifecycle_data_key(identity)));
        session.upload_key_observation = Some(UploadKeyObservation {
            reference: row.reference(identity),
            identity: digest(
                &app_policy(&state.context.as_ref().unwrap().draft, Role::AndroidUpload)
                    .unwrap_or_else(|_| panic!("synthetic Android app policy was refused"))
                    .0,
            )
            .unwrap(),
            certificate: [7; 32],
            key: Arc::downgrade(session.key.as_ref().unwrap()),
            store: Arc::downgrade(&session.store),
        });
        let owner = OriginalWork::new(79, false, Weak::new());
        owner.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
        owner.child.try_lock().unwrap().receipt = JoinReceipt::Returned;
        let clock = Arc::new(UploadKeyClock::new(Instant::now()));
        // Explicit synthetic predicate inputs only. This test never invokes
        // native generation, publishes a key, or constructs a disposal proof.
        clock.completed.store(true, Ordering::SeqCst);
        assert!(owner.upload_key_clock.set(clock).is_ok());
        let mut slot = Slot::new(
            owner,
            Operation::GenerateUploadKey,
            state.context.clone(),
            None,
            None,
        );
        slot.phase = Phase::Idle;
        slot.settlement = Settlement::Known;
        slot.vault.upload_key_new_published = true;
        slot.vault.upload_key_context = publication_stamp(&slot, &row, identity);
        slot.vault.reference = Some(row.reference(identity));
        slot.vault.outcome = Some(store::StorageOutcome {
            effect: store::Effect::KnownApplied,
            durability: store::Durability::Confirmed,
            cleanup: store::Cleanup::Known,
        });
        session.rows.push(row);
        state.vault = Some(session);
        state.slot = Some(slot);
        state
    }
    fn projected(state: &DocumentState) -> Option<KeyReference> {
        retained_saved_reference(state, state.slot.as_ref().unwrap())
    }

    #[test]
    fn closed_requests_require_exact_current_revision_and_explicit_new_app_declaration() {
        assert_eq!(
            context_request(&json!({"contextRevision":1}))
                .unwrap_or_else(|_| panic!("valid context request was refused"))
                .context_revision,
            1
        );
        let request =
            json!({"contextRevision":1,"expectedStatusRevision":2,"declaration":DECLARATION});
        assert_eq!(create_request(&request).unwrap_or_else(|_| panic!("valid create request was refused")).expected_revision, 2);
        for bad in [
            json!(0),
            json!(-1),
            json!(1.5),
            json!("1"),
            json!(u32::MAX),
            Value::Null,
        ] {
            assert!(context_request(&json!({"contextRevision":bad})).is_err());
            let mut wrong = request.clone();
            wrong["expectedStatusRevision"] = bad;
            assert!(create_request(&wrong).is_err());
        }
        for name in [
            "path",
            "password",
            "fields",
            "tool",
            "replace",
            "recordId",
            "applicationId",
        ] {
            let mut wrong = request.clone();
            wrong[name] = json!("inert-refused");
            assert!(create_request(&wrong).is_err());
        }
        for bad in [json!(true), json!("existing-app"), Value::Null] {
            let mut wrong = request.clone();
            wrong["declaration"] = bad;
            assert!(create_request(&wrong).is_err());
        }
    }

    #[test]
    fn only_actual_generation_arm_can_stamp_a_saved_reference() {
        let mut state = reference_data();
        let session = state.vault.as_ref().unwrap();
        let slot = state.slot.as_mut().unwrap();
        assert!(publication_stamp(slot, &session.rows[0], session.identity.unwrap()).is_some());
        for operation in [
            Operation::Bind,
            Operation::Commit,
            Operation::ImportBackup,
            Operation::PrepareBackupExport,
        ] {
            slot.operation = operation;
            assert!(publication_stamp(slot, &session.rows[0], session.identity.unwrap()).is_none());
        }
        assert!(!NATIVE_UPLOAD_KEY_QUALIFIED);
    }

    #[test]
    fn working_reference_retirement_preserves_only_current_full_saved_reference_data() {
        let mut state = reference_data();
        let before = projected(&state).expect("synthetic fixed predicate");
        let mut slot = state.slot.take().unwrap();
        let retired = take_retirement(&mut state, &mut slot);
        assert!(slot.vault.reference.is_none());
        assert!(slot.vault.upload_key_context.is_some());
        drop(retired);
        state.slot = Some(slot);
        assert!(projected(&state).is_some_and(|current| current == before));
        state.slot.as_mut().unwrap().vault.upload_key_context = None;
        assert!(projected(&state).is_none()); // Row count/Idle is not publication.
    }

    #[test]
    fn random_revision_witness_and_current_key_changes_suppress_saved_projection() {
        let mut state = reference_data();
        assert!(projected(&state).is_some());
        let revision = state.vault.as_ref().unwrap().rows[0].authenticated.revision;
        state.vault.as_mut().unwrap().rows[0].authenticated.revision =
            format::Revision::new(id(9), revision.counter).unwrap();
        assert!(projected(&state).is_none());
        state.vault.as_mut().unwrap().rows[0].authenticated.revision = revision;
        let original = state.vault.as_ref().unwrap().rows[0].original;
        state.vault.as_mut().unwrap().rows[0].original = store::ReadWitness::lifecycle_data(
            id(3),
            format::Revision::new(id(10), revision.counter).unwrap(),
        );
        assert!(projected(&state).is_none());
        state.vault.as_mut().unwrap().rows[0].original = original;
        let session = state.vault.as_mut().unwrap();
        let _original_key = session.key.replace(Arc::new(crypto::lifecycle_data_key(
            session.identity.unwrap(),
        )));
        assert!(projected(&state).is_none());
    }

    #[test]
    fn unretired_clock_failed_original_or_held_cleanup_cannot_display_saved() {
        let mut state = reference_data();
        let owner = state.slot.as_ref().unwrap().owner.clone();
        let clock = owner.upload_key_clock.get().unwrap();
        clock.completed.store(false, Ordering::SeqCst);
        assert!(projected(&state).is_none());
        clock.completed.store(true, Ordering::SeqCst);
        assert!(projected(&state).is_some());
        owner.vault.lock().unwrap().original_join = Some(JoinReceipt::Failed);
        assert!(projected(&state).is_none());
        owner.vault.lock().unwrap().original_join = None;
        owner.vault.lock().unwrap().failed_child_join = Some(JoinReceipt::Failed);
        assert!(projected(&state).is_none());
        owner.vault.lock().unwrap().failed_child_join = None;
        {
            let _held = owner.retirement.lock().unwrap();
            assert!(projected(&state).is_none());
        }
        state
            .slot
            .as_mut()
            .unwrap()
            .vault
            .outcome
            .as_mut()
            .unwrap()
            .durability = store::Durability::Unknown;
        assert!(projected(&state).is_none());
    }

    #[test]
    fn context_or_app_change_never_relabels_an_old_generated_key_as_current() {
        let mut state = reference_data();
        assert!(projected(&state).is_some());
        let context = state.context.as_mut().unwrap();
        // Arc is still held by the original slot; build different comparison
        // DATA rather than mutate an admitted original in place.
        *context = Arc::new(NativeContext {
            execution_mode: context.execution_mode,
            revision: context.revision + 1,
            project_id: context.project_id.clone(),
            project: context.project.clone(),
            registry_generation: context.registry_generation,
            draft: context.draft.clone(),
            platform: context.platform,
            stage: context.stage,
            purpose: context.purpose,
        });
        assert!(projected(&state).is_none());
        let context = Arc::get_mut(state.context.as_mut().unwrap()).unwrap();
        context.revision -= 1;
        context.draft = br#"{"android":{"applicationId":"example.other.app"}}"#.to_vec();
        assert!(projected(&state).is_none());
        state.context = None;
        assert!(projected(&state).is_none());
    }

    #[test]
    fn post_retirement_clock_check_cannot_hide_expiry_or_replace_an_earlier_failure() {
        // Actual original clock/Work only; no native producer, join receipt,
        // key, NativeUse or disposal permission is manufactured in this test.
        let owner = OriginalWork::new(81, false, Weak::new());
        let clock = Arc::new(UploadKeyClock::new(
            Instant::now() - Duration::from_secs(wire::WORK_SECONDS + 1),
        ));
        assert!(owner.upload_key_clock.set(clock.clone()).is_ok());
        let earlier = clock.bounds().0 + Duration::from_secs(1);
        parent_stop(&owner, Reason::SourceChanged, earlier);
        assert!(!retirement_window(&owner, &clock));
        assert_eq!(owner.endpoint(), Some(clock.work_end()));
        assert!(!clock.completed.load(Ordering::SeqCst));
        assert_eq!(clock.failure_at(), Some(earlier));
        assert!(owner.vault.lock().unwrap().first == Some((Reason::SourceChanged, earlier)));

        let owner = OriginalWork::new(82, false, Weak::new());
        let clock = Arc::new(UploadKeyClock::new(
            Instant::now() - Duration::from_secs(wire::WORK_SECONDS + 1),
        ));
        assert!(owner.upload_key_clock.set(clock.clone()).is_ok());
        assert!(!retirement_window(&owner, &clock));
        assert!(owner.stopped());
        assert_eq!(clock.failure_at(), Some(clock.work_end()));
        assert!(!clock.completed.load(Ordering::SeqCst));
        // The same guard remains false; an observation cannot erase expiry.
        assert!(!retirement_window(&owner, &clock));
    }

    #[test]
    fn missing_live_progress_during_retirement_or_a_borrow_stays_pending_not_failed() {
        let owner = OriginalWork::new(83, false, Weak::new());
        let clock = Arc::new(UploadKeyClock::new(Instant::now()));
        assert!(owner.upload_key_clock.set(clock.clone()).is_ok());
        let mut slot = Slot::new(
            owner.clone(),
            Operation::GenerateUploadKey,
            None,
            None,
            None,
        );
        // The real parent uses Stopping/Pending during healthy off-lock
        // retirement too; that phase alone is not cancellation evidence.
        slot.phase = Phase::Stopping;
        slot.settlement = Settlement::Pending;
        // Empty live Work is the same observation as after its real holding
        // transfers to Retirement. Absence is neither failure nor Saved proof.
        assert_eq!(pending_phase(&slot), "finishing");
        {
            let _held = owner.vault.lock().unwrap();
            assert_eq!(pending_phase(&slot), "finishing");
        }
        assert!(!clock.failed.load(Ordering::SeqCst));
        assert!(!clock.completed.load(Ordering::SeqCst));
        slot.reason = Reason::UserCancelled;
        assert_eq!(pending_phase(&slot), "recovery-required");
        slot.reason = Reason::None;
        slot.cleanup_end = Some(clock.work_end());
        assert_eq!(pending_phase(&slot), "recovery-required");
        slot.cleanup_end = None;
        slot.settlement = Settlement::Unknown;
        assert_eq!(pending_phase(&slot), "recovery-required");
        slot.settlement = Settlement::Pending;
        clock.observe_failure(Instant::now());
        assert_eq!(pending_phase(&slot), "recovery-required");
        let _held = owner.vault.lock().unwrap();
        assert_eq!(pending_phase(&slot), "recovery-required");
    }
}

#[cfg(all(
    feature = "desktop-shell",
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    not(feature = "macos-android-registration-helper")
))]
impl DocumentBinding {
    pub(crate) async fn prepare_upload_key_setup(
        &self,
        request: ContextRequest,
        app_data: &std::path::Path,
    ) -> Result<UploadKeyStatus, AssetError> {
        self.prepare_upload_key_setup_selected(request,app_data,Qualification::Ordinary).await
    }
    pub(in crate::asset_session) async fn prepare_upload_key_setup_selected(&self,
        request:ContextRequest,app_data:&std::path::Path,selection:Qualification) -> Result<UploadKeyStatus,AssetError> {
        let admission=selection.admit(self,SelectedAction::Prepare,Some(app_data))?;
        self.reconcile();
        let (flight, ticket) = {
            let mut state = self.lock();
            self.expire(&mut state, Instant::now());
            self.durable_gate(&state, true)?;
            idle(&state)?;
            let context = state
                .context
                .as_ref()
                .filter(|context| {
                    context.revision == request.context_revision
                        && context.platform == Platform::Android
                })
                .ok_or_else(|| AssetError::new(Reason::ContextStale))?
                .clone();
            let session = state
                .vault
                .as_ref()
                .ok_or_else(|| AssetError::new(Reason::Closed))?;
            if !session.writable()
                || session.upload_key_setup.pending()
                || session.upload_key_setup.failure.is_some()
                || session
                    .upload_key_setup
                    .ready
                    .as_ref()
                    .is_some_and(|ready| ready.attempted.load(Ordering::SeqCst))
            {
                return Err(AssetError::new(Reason::VaultInterrupted));
            }
            let live = lookup_memory::retained_document_bytes(&self.inner, &state)
                .map_err(|_| AssetError::new(Reason::Capacity))?
                .checked_add(
                    installation_memory::additional_document_bytes(self, &state)
                        .map_err(AssetError::new)?,
                )
                .and_then(|bytes| {
                    bytes.checked_add(2 * 1024 * 1024 + 34 * asset_source::PATH_LIMIT)
                })
                .ok_or_else(|| AssetError::new(Reason::Capacity))?;
            if live > store::RESIDENT_BYTES {
                return Err(AssetError::new(Reason::Capacity));
            }
            let original = self
                .service_project_locked(&state, &context.project_id)
                .map_err(|_| AssetError::new(Reason::ContextStale))?;
            let edit = self
                .inner
                .bridge
                .edits
                .saved_registration_guard(&self.inner.session_identity)
                .map_err(|_| AssetError::new(Reason::ContextStale))?;
            self.upload_key_saved_input(&state, &context, &edit)
                .map_err(|_| AssetError::new(Reason::ContextStale))?;
            let stamp = edit
                .stamp()
                .map_err(|_| AssetError::new(Reason::ContextStale))?;
            let roster = self
                .inner
                .bridge
                .native_roster()
                .map_err(|_| AssetError::new(Reason::ContextStale))?;
            self.inner
                .bridge
                .application_service
                .reserve_native_state_location(app_data, &roster.roots)
                .map_err(service_error)?;
            let ticket = self
                .inner
                .bridge
                .application_service
                .begin_native_state(original.clone())
                .map_err(service_error)?;
            let flight = Arc::new(SetupFlight {
                context,
                original,
                edit: stamp,
            });
            state.vault.as_mut().unwrap().upload_key_setup.flight = Some(flight.clone());
            drop(edit);
            self.bump(&mut state);
            (flight, ticket)
        };
        // SAME Host original retains all native startup/custody on cancellation
        // or failed observation. An abandoned invoke leaves the flight pending;
        // status cannot reset it or silently begin another setup/key operation.
        let result = async {
            self.inner
                .bridge
                .application_service
                .prepare_native_state(&ticket, app_data)
                .await
                .map_err(service_error)?;
            let (ready, observed) = {
                let state = self.lock();
                if !state
                    .context
                    .as_ref()
                    .is_some_and(|context| Arc::ptr_eq(context, &flight.context))
                    || !state.vault.as_ref().is_some_and(|vault| {
                        vault
                            .upload_key_setup
                            .flight
                            .as_ref()
                            .is_some_and(|current| Arc::ptr_eq(current, &flight))
                    })
                {
                    return Err(AssetError::new(Reason::ContextStale));
                }
                let current = self
                    .service_allow_current_locked(&state, &flight.original, &flight.edit)
                    .map_err(|_| AssetError::new(Reason::ContextStale))?;
                let ready = Arc::new(
                    self.inner
                        .bridge
                        .application_service
                        .finish_native_state(ticket, &current)
                        .map_err(service_error)?,
                );
                let observed = self.credential_observation_for_binding(
                    &state,
                    ready.project_binding().clone(),
                    Role::AndroidUpload,
                )?;
                (ready, observed)
            };
            let preference =
                persistence::observe(ready.store(), &observed.project, Role::AndroidUpload)
                    .map_err(preference_error)?;
            let plan = observed
                .with(|observation| setup::classify(observation, preference.preference.as_ref()))
                .map_err(data_error)?;
            let prepared = Arc::new(PreparedSetup {
                admission,
                flight: flight.clone(),
                ready,
                preference,
                attempted: AtomicBool::new(false),
            });
            let mut state = self.lock();
            if !state
                .context
                .as_ref()
                .is_some_and(|context| Arc::ptr_eq(context, &flight.context))
                || !state.vault.as_ref().is_some_and(|vault| {
                    vault
                        .upload_key_setup
                        .flight
                        .as_ref()
                        .is_some_and(|current| Arc::ptr_eq(current, &flight))
                })
            {
                return Err(AssetError::new(Reason::ContextStale));
            }
            let current = self
                .service_allow_current_locked(&state, &flight.original, &flight.edit)
                .map_err(|_| AssetError::new(Reason::ContextStale))?;
            self.inner
                .bridge
                .application_service
                .native_state_current(&prepared.ready, &current)
                .map_err(service_error)?;
            let setup = &mut state.vault.as_mut().unwrap().upload_key_setup;
            setup.ready = Some(prepared.clone());
            setup.flight = None;
            self.bump(&mut state);
            let mut status = project(self, &state, plan);
            status.recovery = recovery::projection(self, &state, Some((&prepared.preference, &observed)));
            Ok(status)
        }
        .await;
        if let Err(error) = &result {
            let mut state = self.lock();
            if let Some(setup) = state
                .vault
                .as_mut()
                .map(|vault| &mut vault.upload_key_setup)
                .filter(|setup| {
                    setup
                        .flight
                        .as_ref()
                        .is_some_and(|current| Arc::ptr_eq(current, &flight))
                })
            {
                setup.failure = Some(error.reason);
                setup.flight = None;
                self.bump(&mut state);
            }
        }
        result
    }

    pub(crate) fn create_upload_key(
        &self,
        request: CreateRequest,
    ) -> Result<UploadKeyStatus, AssetError> {
        self.create_upload_key_selected(request,Qualification::Ordinary)
    }
    pub(in crate::asset_session) fn create_upload_key_selected(&self,request:CreateRequest,selection:Qualification)->Result<UploadKeyStatus,AssetError> {
        let admission=selection.admit(self,SelectedAction::Create,None)?;
        let (consent, service, tools) = {
            let mut state = self.lock();
            self.expire(&mut state, Instant::now());
            self.durable_gate(&state, true)?;
            idle(&state)?;
            if state.revision != request.expected_revision
                || !state
                    .context
                    .as_ref()
                    .is_some_and(|context| context.revision == request.context_revision)
            {
                return Err(AssetError::new(Reason::ContextStale));
            }
            let prepared = state
                .vault
                .as_ref()
                .and_then(|vault| vault.upload_key_setup.ready.clone())
                .ok_or_else(|| AssetError::new(Reason::ContextStale))?;
            if !admission.same(&prepared.admission) {return Err(AssetError::new(Reason::Unqualified));}
            current_prepared(self, &state, &prepared)?;
            let original = self
                .service_allow_current_locked(
                    &state,
                    &prepared.flight.original,
                    &prepared.flight.edit,
                )
                .map_err(|_| AssetError::new(Reason::ContextStale))?;
            let service = self
                .inner
                .bridge
                .application_service
                .native_state_service(&prepared.ready, &original)
                .map_err(service_error)?;
            let tools = self
                .inner
                .bridge
                .android_build
                .upload_key_tool_loan(&self.inner.session_identity)
                .map_err(|_| AssetError::new(Reason::Unqualified))?
                .ok_or_else(|| AssetError::new(Reason::Unqualified))?;
            if prepared
                .attempted
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                return Err(AssetError::new(Reason::VaultInterrupted));
            }
            (
                Consent {
                    admission,
                    prepared,
                    revision: request.expected_revision,
                },
                service,
                tools,
            )
        };
        // Existing original native grants/tool lease and parent perform EVERY
        // current check again. This call is not a reconstituted saved grant.
        self.generate_confirmed_new_upload_key(
            service,
            &self.inner.bridge.upload_key,
            tools,
            request.context_revision,
            wire::Availability::Available,
            consent,
        )?;
        let state = self.lock();
        Ok(project(self, &state, Plan::RecoveryRequired))
    }
}
