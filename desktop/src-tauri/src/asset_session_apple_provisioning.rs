//! The Bundle-ID operation borrows the SAME Document, saved lane, selected P8
//! material and explicitly initialized local-state binding. No ordinary read
//! starts the state service, grants CLI access or constructs a replacement
//! account/credential/registration capability.
use super::*;
#[cfg(any(target_os="linux",target_os="macos"))]
#[path="asset_session_agent_apple_provisioning.rs"]
pub(crate) mod agent;
#[path="asset_session_apple_p12_input.rs"]
mod p12_input;
#[cfg(test)]
#[path = "asset_session_apple_memory_fixture.rs"]
mod memory_fixture;
use crate::{
    apple_provisioning_journal::{
        AccountRef, BundleTarget, NativeProvenance, ProvisioningContext, RegisteredRootData,
    },
    apple_provisioning_protocol as wire,
    application_service_host::{NativeProject, NativeStateReady},
    edit_owner::RegisteredEditRoot,
    project_identity_edit_protocol::{NativeContinuity, Platform as IdentityPlatform},
    service_protocol::Id,
};

#[path="asset_session_apple_profile_input.rs"]
mod profile_input;
#[path="asset_session_apple_key_input.rs"]
mod key_input;

fn changed() -> BridgeError {
    BridgeError::new(
        "apple_provisioning_changed",
        "The saved app, selected key or local state changed. Review it again.",
    )
}

fn startup_error(error: crate::service_protocol::Error) -> BridgeError {
    use crate::service_protocol::Error;
    match error {
        Error::StateUnknown => BridgeError::cleanup_unknown(),
        Error::RecoveryRequired => BridgeError::new("apple_provisioning_state_recovery_required",
            "The local automation history needs recovery. Preserve its files; do not reset it."),
        Error::Busy => BridgeError::new("apple_provisioning_state_busy",
            "Another local setup operation is still finishing. Wait before preparing again."),
        Error::Conflict | Error::AccessDenied | Error::Expired => changed(),
        Error::InvalidRequest => wire::invalid(),
        Error::Unavailable | Error::UnsupportedPlatform => BridgeError::new("apple_provisioning_state_unavailable",
            "Local Apple setup is unavailable in this application environment."),
    }
}

/// Constructible only under the actual Document/Edit admission below. Public
/// request fields are comparisons. The native input retains the originals
/// which make those comparisons useful; no status/receipt can reconstruct it.
pub(crate) struct AppleProvisioningDocumentInput {
    document: Weak<Inner>,
    context: wire::Context,
    registration: u32,
    root: asset_source::RegisteredRoot,
    saved: AppleProvisioningSavedInput,
    material: Arc<SelectedStoreMaterial>,
    state: Arc<NativeStateReady>,
    account: AccountRef,
    target: BundleTarget,
    profile_asset: Mutex<Option<Arc<OriginalWork>>>,
    key_asset: Mutex<Option<Arc<OriginalWork>>>,
}
/// The same admission's owned inputs. Collect gates/material/census before
/// SavedEditGuard, then carry them through publication without re-locking Edit.
struct PreparedAppleSources {
    gate: wire::Availability,
    registration: u32,
    root: asset_source::RegisteredRoot,
    saved: AppleProvisioningSavedInput,
    material: Arc<SelectedStoreMaterial>,
}
impl AppleProvisioningDocumentInput {
    /// Memory-only snapshot of the originals retained by this same Input.
    /// No context recheck/Host call or retirement is performed under Census.
    /// A contested/poisoned cell is not an absent asset or zero retained bytes.
    pub(crate) fn census_assets(&self) -> Result<[Option<Arc<OriginalWork>>; 2], BridgeError> {
        let profile = self.profile_asset.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let key = self.key_asset.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if profile.is_some() && key.is_some() { return Err(BridgeError::cleanup_unknown()); }
        Ok([profile.clone(), key.clone()])
    }

    pub(crate) fn context(&self) -> &wire::Context {
        &self.context
    }
    pub(crate) fn material(&self) -> &Arc<SelectedStoreMaterial> {
        &self.material
    }
    pub(crate) fn ready(&self) -> &Arc<NativeStateReady> {
        &self.state
    }
    pub(crate) fn account(&self) -> &AccountRef {
        &self.account
    }
    pub(crate) fn matches(
        &self,
        context: &wire::Context,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> bool {
        &self.context == context && self.registration == registration && &self.root == root
    }
    pub(crate) fn same_selection(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.document, &other.document)
            && self.registration == other.registration
            && self.root == other.root
            && self.saved.same_binding(&other.saved)
            && self.material.same_provisioning_source(&other.material)
            && Arc::ptr_eq(&self.state, &other.state)
            && self.account == other.account
            && self.target == other.target
            && self.context.project_id == other.context.project_id
            && self.context.draft_revision == other.context.draft_revision
            && self.context.baseline_generation == other.context.baseline_generation
            && self.context.saved_config == other.context.saved_config
            && self.context.saved_version == other.context.saved_version
            && self.context.display_name == other.context.display_name
            && self.context.key_record_id == other.context.key_record_id
            && self.context.key_record_revision == other.context.key_record_revision
            && self.context.p12_record_id == other.context.p12_record_id
            && self.context.p12_record_revision == other.context.p12_record_revision
    }
    fn project(&self, document: &Arc<Inner>) -> Result<NativeProject, BridgeError> {
        let (device, inode) = self
            .root
            .identity
            .posix()
            .map_err(|_| changed())?
            .service_identity();
        Ok(NativeProject {
            runtime_id: self.context.project_id.clone(),
            canonical_root: self.root.path.clone(),
            device,
            inode,
            registration_generation: self.registration,
            document_identity: document.session_identity.clone(),
            input_revision: self.saved.epoch(),
        })
    }
    fn current_locked(
        &self,
        document: &Arc<Inner>,
        state: &DocumentState,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
    ) -> Result<(), BridgeError> {
        if !self
            .document
            .upgrade()
            .is_some_and(|original| Arc::ptr_eq(&original, document))
            || !state.lifetime.original_bound()
            || state.lost_observed
            || state.unknown
            || state.exhausted
            || state.stopping
            || state.quit_pending
            || state.retiring
            || state.lock_pending
            || state.compatibility_picker_pending
            || state.maintenance.closed()
            || !state
                .apple_provisioning_ready
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &self.state))
            || !self.saved.current_locked(
                document,
                state,
                edit,
                &self.context,
                self.registration,
                &self.root,
            )
            || !self.material.provisioning_current_locked(
                document,
                state,
                &self.context,
                self.registration,
                &self.root,
            )
        {
            return Err(changed());
        }
        document
            .bridge
            .application_service
            .native_state_current(&self.state, &self.project(document)?)
            .map_err(|error| {
                if error == crate::service_protocol::Error::StateUnknown {
                    BridgeError::cleanup_unknown()
                } else {
                    changed()
                }
            })?;
        if self.context.mode == wire::Mode::Register {
            let registered = RegisteredEditRoot {
                generation: self.registration,
                root: self.root.clone(),
            };
            if project_identity::current_continuity(
                &document.bridge,
                &self.context.project_id,
                &registered,
                Some(IdentityPlatform::Ios),
            )? != NativeContinuity::Unknown
            {
                return Err(changed());
            }
        }
        // Unknown continuity is NOT absence; the separately reviewed explicit
        // new-app declaration and same-account journal fence remain mandatory.
        let (account, target) = self.material.provisioning_account_target(
            &self.context,
            self.registration,
            &self.root,
        )?;
        if account != self.account || target != self.target {
            return Err(changed());
        }
        Ok(())
    }
    /// Memory-only TRY admission. Called BEFORE and AFTER each original IO job
    /// (never while holding its private Store/Journal lock), and just before an
    /// ACK may authorize the fixed worker's next action.
    pub(crate) fn current(&self) -> Result<(), BridgeError> {
        let document = self.document.upgrade().ok_or_else(changed)?;
        let state = document
            .state
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        // The unrelated-owner gate reads EditOwner too. Run it BEFORE taking
        // the original saved Edit guard; never recursively lock that owner.
        let binding = DocumentBinding {
            inner: document.clone(),
        };
        if binding.apple_provisioning_current_gate(&state, self.profile_sources(),self.key_sources()) != wire::Availability::Available {
            return Err(changed());
        }
        let edit = document
            .bridge
            .edits
            .saved_registration_guard(&document.session_identity)?;
        self.current_locked(&document, &state, &edit)
    }
    pub(crate) fn scope(
        &self,
        operation: &str,
        generation: &str,
        reviewed_at: Option<String>,
    ) -> Result<wire::ScopeData, BridgeError> {
        let identity = self
            .root
            .identity
            .posix()
            .map_err(|_| changed())?
            .preflight_identity();
        let provisioning = ProvisioningContext {
            project_id: self.context.project_id.clone(),
            client_id: generation.to_owned(),
            operation_id: operation.to_owned(),
            // This is the actual native credential-context observation counter,
            // not a fabricated external CLI client or a provider freshness time.
            observation_revision: self.context.credential_context_revision,
            account_ref: self.account.clone(),
            credential_record_id: self.context.record_id.clone(),
            credential_revision: self.context.record_revision,
            credential_context_revision: self.context.credential_context_revision,
        };
        let provenance = NativeProvenance {
            project_binding: self.state.project_binding().clone(),
            operation_id: Id::parse(operation).map_err(|_| changed())?,
            owner_generation: Id::parse(generation).map_err(|_| changed())?,
            registration_generation: self.registration,
            registered_root: RegisteredRootData {
                path: self.root.path.to_str().ok_or_else(changed)?.into(),
                device: identity.device.parse().map_err(|_| changed())?,
                inode: identity.inode.parse().map_err(|_| changed())?,
                mode: identity.mode,
                uid: identity.uid,
                gid: identity.gid,
            },
            draft_revision: self.context.draft_revision,
            baseline_generation: self.context.baseline_generation,
            saved_config: self.context.saved_config.clone(),
            saved_version: self.context.saved_version.clone(),
        };
        Ok(wire::ScopeData {
            provisioning,
            provenance,
            target: self.target.clone(),
            reviewed_at,
            signing: None,
            key: None, certificate: None,p12:None,
        })
    }
    fn own_backing_bytes(&self) -> Option<usize> {
        // Same material/context originals are charged by existing Store census.
        // This covers only copied comparison DATA and the retained saved lane.
        self.saved
            .retained_heap_bytes()?
            .checked_add(std::mem::size_of::<Self>())?
            .checked_add(wire::IPC_LIMIT.checked_mul(2)?)?
            .checked_add(4096)
    }
}

impl DocumentBinding {
    pub(crate) fn apple_provisioning_subscribe(&self) -> watch::Receiver<u32> {
        self.inner.bridge.apple_provisioning.subscribe()
    }
    pub(crate) fn apple_provisioning_relay_lost(&self) {
        let _state = self.lock();
        self.inner.bridge.apple_provisioning.document_lost();
    }
    fn apple_provisioning_gate(&self, state: &DocumentState) -> wire::Availability {
        self.apple_provisioning_current_gate(state,None,None)
    }
    fn apple_provisioning_current_gate(&self,state:&DocumentState,source:Option<&Arc<vault::profile_sources::AppleProfileSources>>,key:Option<&Arc<vault::key_sources::AppleKeySources>>)->wire::Availability {
        use wire::Availability;
        // The Access gate excludes its own owner. Add it explicitly here;
        // Root's reciprocal-hook patch must NOT call this gate from Access.
        if self.inner.bridge.local_store.disabled() {
            return Availability::CleanupUnknown;
        }
        if self.inner.bridge.local_store.stopping() {
            return Availability::Shutdown;
        }
        if self.inner.bridge.local_store.busy() {
            return Availability::Busy;
        }
        // local_store_gate is the original non-Apple registry/credential/setup
        // gate. The shared patch factors its unrelated-owner checks, rather
        // than making this operation reject itself through reciprocal checks.
        self.local_store_base_gate_current_profile_key(state,source,key)
    }
    /// This explicit user action prepares local state only. The Host retains
    /// its actual originals; no CLI endpoint, read grant or provider operation
    /// is created here. A dropped observer can never publish a Ready binding.
    pub(crate) async fn prepare_apple_provisioning(
        &self,
        input: wire::Prepare,
        app_data: &std::path::Path,
    ) -> Result<wire::Status, BridgeError> {
        if !input.context.valid() { return Err(wire::invalid()); }
        let host = &self.inner.bridge.application_service;
        let (project, stamp, ticket, registration, root, saved, material) = {
            let state = self.lock();
            let gate = self.apple_provisioning_gate(&state);
            if gate != wire::Availability::Available {
                return self.inner.bridge.apple_provisioning.status_apple_provisioning(gate);
            }
            let (registration, root) = self.inner.bridge.native_project(&input.context.project_id)
                .map_err(|_| changed())?;
            let material = self.review_apple_provisioning_material(&state, &input.context, registration, &root)?;
            let future = crate::saved_command_owner::apple_provisioning_document_backing_bytes(input.context.mode).ok_or_else(changed)?;
            lookup_memory::store_admission_bytes(&self.inner, &state, &material, future).map_err(|_| changed())?;
            let project = self.service_project_locked(&state, &input.context.project_id)?;
            let edit = self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
            let saved = self.apple_provisioning_saved_input(&state, &input.context, registration, &root, &edit)?;
            if let Some(ready) = &state.apple_provisioning_ready {
                match host.native_state_current(ready, &project) {
                    Ok(()) => return self.prepare_apple_provisioning_locked(&state, input, &edit,
                        PreparedAppleSources { gate, registration, root, saved, material }),
                    // Only a fresh explicit Prepare may establish a new binding.
                    Err(crate::service_protocol::Error::Conflict) => {},
                    Err(error) => return Err(startup_error(error)),
                }
            }
            let stamp = edit.stamp()?;
            let roster = self.inner.bridge.native_roster().map_err(|_| changed())?;
            host.reserve_native_state_location(app_data, &roster.roots).map_err(startup_error)?;
            let ticket = host.begin_native_state(project.clone()).map_err(startup_error)?;
            (project, stamp, ticket, registration, root, saved, material)
        };
        // No Document/Edit/Host guard is held across this original startup.
        host.prepare_native_state(&ticket, app_data).await.map_err(startup_error)?;
        let mut state = self.lock();
        let gate = self.apple_provisioning_gate(&state);
        if gate != wire::Availability::Available {
            return self.inner.bridge.apple_provisioning.status_apple_provisioning(gate);
        }
        let current = self.service_allow_current_locked(&state, &project, &stamp)?;
        self.recheck_apple_provisioning_material(&state, &material, &input.context, registration, &root)?;
        let future = crate::saved_command_owner::apple_provisioning_document_backing_bytes(input.context.mode).ok_or_else(changed)?;
        let admitted_bytes = lookup_memory::store_admission_bytes(&self.inner, &state, &material, future)
            .map_err(|_| changed())?;
        let edit = self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity)?;
        if !edit.matches(&stamp)
            || !saved.current_locked(&self.inner, &state, &edit, &input.context, registration, &root)
            || !material.provisioning_current_locked(&self.inner, &state, &input.context, registration, &root)
        { return Err(changed()); }
        let ready = Arc::new(host.finish_native_state(ticket, &current).map_err(startup_error)?);
        // Count the actual new Ready before retaining it in Document. The
        // pre-Edit census already counted any previous Ready still held here.
        let ready_bytes = lookup_memory::native_state_ready_bytes(&ready).map_err(|_| changed())?;
        if admitted_bytes.checked_add(ready_bytes).is_none_or(|bytes| bytes > SESSION_BYTES) {
            return Err(changed());
        }
        state.apple_provisioning_ready = Some(ready);
        // Same Document AND Edit originals span Ready publication and the
        // actual operation preparation. No re-locking public call or gap.
        self.prepare_apple_provisioning_locked(&state, input, &edit,
            PreparedAppleSources { gate, registration, root, saved, material })
    }
    fn prepare_apple_provisioning_locked(
        &self,
        state: &DocumentState,
        input: wire::Prepare,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
        sources: PreparedAppleSources,
    ) -> Result<wire::Status, BridgeError> {
        let PreparedAppleSources { gate, registration, root, saved, material } = sources;
        let ready = state
            .apple_provisioning_ready
            .as_ref()
            .cloned()
            .ok_or_else(|| {
                BridgeError::new(
                    "apple_provisioning_state_unavailable",
                    "Explicitly prepare local state before reviewing Bundle-ID registration.",
                )
            })?;
        let (account, target) =
            material.provisioning_account_target(&input.context, registration, &root)?;
        let original = Arc::new(AppleProvisioningDocumentInput {
            document: Arc::downgrade(&self.inner),
            context: input.context.clone(),
            registration,
            root: root.clone(),
            saved,
            material,
            state: ready,
            account,
            target,
            profile_asset: Mutex::new(None),
            key_asset: Mutex::new(None),
        });
        original.current_locked(&self.inner, state, edit)?;
        // Future quote already covers the maximum wrapper/lane; check its
        // actual current backing so a later bigger lane cannot bypass the cap.
        if original
            .own_backing_bytes()
            .is_none_or(|size| size > crate::saved_command_owner::APPLE_PROVISIONING_INPUT_LIMIT)
        {
            return Err(changed());
        }
        self.inner
            .bridge
            .apple_provisioning
            .prepare_apple_provisioning(input, registration, root, gate, original)
    }
    pub(crate) fn start_apple_provisioning(
        &self,
        input: wire::Start,
    ) -> Result<wire::Status, BridgeError> {
        self.start_apple_provisioning_delegated(input,None)
    }
    fn start_apple_provisioning_delegated(&self,input:wire::Start,
        delegated:Option<(&Arc<agent::Grant>,&Arc<crate::service_apple_provisioning_requests::Entry>)>)->Result<wire::Status,BridgeError>{
        let admitted_at=delegated.map_or_else(Instant::now,|(_,entry)|entry.submitted_at());
        let mut state = self.lock();
        let gate = self.apple_provisioning_gate(&state);
        let original = self
            .inner
            .bridge
            .apple_provisioning
            .prepared_apple_provisioning_input(&input.operation_id, &input.owner_generation)?;
        let (registration, root) = self
            .inner
            .bridge
            .native_project(&original.context.project_id)
            .map_err(|_| changed())?;
        let future = crate::saved_command_owner::apple_provisioning_document_backing_bytes(original.context.mode)
            .ok_or_else(changed)?;
        lookup_memory::store_admission_bytes(&self.inner, &state, original.material(), future)
            .map_err(|_| changed())?;
        let edit = self
            .inner
            .bridge
            .edits
            .saved_registration_guard(&self.inner.session_identity)?;
        if let Some((grant,entry))=delegated{self.agent_apple_start_current(&state,grant,entry,&edit,registration,&root)?;}
        original.current_locked(&self.inner, &state, &edit)?;
        self.recheck_apple_provisioning_material(
            &state,
            original.material(),
            original.context(),
            registration,
            &root,
        )?;
        let admitted = self
            .inner
            .bridge
            .apple_provisioning
            .start_apple_provisioning_bound(
                input,
                admitted_at,
                Some((registration, root)),
                gate,
                original.clone(),
                delegated.map(|(_,entry)|entry),
            )?;
        drop(edit);
        // All gates/census/saved originals were checked under the SAME Doc.
        // The retained SavedSession exists before any destination reservation.
        #[cfg(feature="desktop-shell")]
        let asset_start = if let Some(profile)=admitted.profile() {
            match self.attach_apple_profile(&mut state,&original,profile) {
                Ok(start)=>Some(start),
                Err(error)=> {
                    // Keep both original books, request STOP, and drop their
                    // existing GO senders. No replacement work/retry is made.
                    profile.admission_failed(&original,error.code=="cleanup_unknown",Instant::now());
                    drop(state);drop(admitted);return Err(error);
                }
            }
        } else if let Some(key)=admitted.key() {
            match self.attach_apple_key(&mut state,&original,key) {
                Ok(start)=>Some(start),
                Err(error)=> {
                    key.admission_failed(&original,error.code=="cleanup_unknown",Instant::now());
                    drop(state);drop(admitted);return Err(error);
                }
            }
        } else { None };
        #[cfg(not(feature="desktop-shell"))]
        if let Some(profile)=admitted.profile() {
            let _=profile.decline_before_asset(Reason::Unqualified,Instant::now());
            drop(state);drop(admitted);return Err(wire::invalid());
        }
        #[cfg(not(feature="desktop-shell"))]
        if let Some(key)=admitted.key() {
            let _=key.decline_before_asset(Reason::Unqualified,Instant::now());
            drop(state);drop(admitted);return Err(wire::invalid());
        }
        drop(state);
        #[cfg(feature="desktop-shell")]
        if let Some(start)=asset_start { let _=start.send(()); }
        Ok(admitted.release())
    }
    pub(crate) fn status_apple_provisioning(&self) -> Result<wire::Status, BridgeError> {
        let state = self.lock();
        self.inner
            .bridge
            .apple_provisioning
            .status_apple_provisioning(self.apple_provisioning_gate(&state))
    }
    pub(crate) fn cancel_apple_provisioning(
        &self,
        input: wire::Cancel,
    ) -> Result<wire::Status, BridgeError> {
        let state = self.lock();
        self.inner
            .bridge
            .apple_provisioning
            .cancel_apple_provisioning(
                &input.operation_id,
                &input.owner_generation,
                self.apple_provisioning_gate(&state),
            )
    }
}
