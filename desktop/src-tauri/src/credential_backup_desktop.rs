//! Narrow Desktop projection/entry gate for the existing original backup owner.
//! A publication marker is display DATA, not material access or a new receipt.
use super::*;

// The Android upload-key two-picker/two-file route has not had focused native
// Mac verification. This bit never qualifies other credential kinds. Existing
// vault qualification, codecs and backend roundtrips do not admit the pickers;
// there is no renderer setting or generic observer bypass.
const NATIVE_ANDROID_UPLOAD_KEY_BACKUP_QUALIFIED: bool = false;

pub(super) fn qualification(document: &DocumentBinding) -> Result<(), AssetError> {
    if !cfg!(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )) {
        return Err(AssetError::new(Reason::UnsupportedPlatform));
    }
    if !NATIVE_ANDROID_UPLOAD_KEY_BACKUP_QUALIFIED || !document.native_qualified() || !qualified(document) {
        return Err(AssetError::new(Reason::Unqualified));
    }
    Ok(())
}

// Native-only closed admission. Ordinary calls/projection never inspect an
// installed registration and retain the false qualification bit above.
#[derive(Clone)]
pub(in crate::asset_session) enum Qualification {
    Ordinary,
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    Installed(Arc<super::backup_picker_observation::Admission>),
}
impl Qualification {
    pub(in crate::asset_session) fn check(&self, document: &DocumentBinding) -> Result<(), AssetError> {
        match self {
            Self::Ordinary => qualification(document),
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
            Self::Installed(a) => a.current(document),
        }
    }
    pub(in crate::asset_session) fn extra_bytes(&self) -> usize {
        match self {
            Self::Ordinary => 0,
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
            Self::Installed(a) => a.retained_bytes(),
        }
    }
    pub(super) fn attach(&self, document: &DocumentBinding, state: &DocumentState, slot: &Slot,
        link: Option<&Arc<crate::service_upload_key_requests::NativeLink>>) -> Result<(), AssetError> {
        let _ = (document, state, slot, link);
        match self {
            Self::Ordinary => Ok(()),
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
            Self::Installed(a) => a.attach(document, state, slot, link),
        }
    }
}

// Closed scope comparisons only. Callers still require the SAME current
// context/full reference, native qualification and original owner gates.
pub(super) fn require_android_context(context: &NativeContext) -> Result<(), AssetError> {
    if context.platform != Platform::Android
        || context.execution_mode != commands::ExecutionMode::Local
    {
        return Err(AssetError::new(Reason::ContextStale));
    }
    Ok(())
}

pub(super) fn require_android_kind(authenticated: Kind) -> Result<(), Reason> {
    if authenticated != Kind::AndroidKeystore { return Err(Reason::SourceRefused); }
    Ok(())
}

pub(in crate::asset_session) fn project(
    document: &DocumentBinding,
    state: &DocumentState,
    status: &mut AssetStatus,
) {
    // Use the SAME qualification predicate as both original entry methods.
    let reason = if !status.capability.available {
        status.capability.reason
    } else if !status.modes.encrypted.available {
        status.modes.encrypted.reason
    } else {
        qualification(document)
            .and_then(|()| {
                require_android_context(state.context.as_deref().ok_or_else(AssetError::invalid)?)
            })
            .err()
            .map_or(Reason::None, |error| error.reason)
    };
    let available = reason == Reason::None;
    status.backup = Some(Capability { available, reason });
    if let Some(operation) = &mut status.operation {
        operation.backup_delivered = (available && delivered_current(state)).then_some(true);
    }
}

pub(super) fn delivered_current(state: &DocumentState) -> bool {
    if state.session
        || state.stopping
        || state.unknown
        || state.exhausted
        || state.lost_observed
        || state.lock_pending
        || state.quit_pending
        || state.retiring
        || state.session_owner_reason.is_some()
        || !state.lifetime.original_bound()
    {
        return false;
    }
    let Some(session) = &state.vault else {
        return false;
    };
    let Some(slot) = &state.slot else {
        return false;
    };
    let Some((revision, reference)) = slot.vault.backup_export_context else {
        return false;
    };
    if !slot.vault.backup_export_published
        || slot.operation != Operation::PrepareBackupExport
        || slot.phase != Phase::Idle
        || slot.settlement != Settlement::Known
        || slot.reason != Reason::None
        || !matches!(slot.source, SourceState::NotRun | SourceState::Captured)
        || slot.error.is_some()
        || slot.cleanup_end.is_some()
        || slot.owner.stopped()
        || !session.writable()
        || !owns(slot, session)
        || session.identity != Some(reference.identity)
        || session
            .key
            .as_ref()
            .is_none_or(|key| key.identity() != reference.identity)
        || slot.vault.generation != Some(session.registry_generation)
        || !state.context.as_ref().is_some_and(|context| {
            context.revision == revision
                && context.registry_generation == session.registry_generation
        })
        || !slot
            .target
            .as_ref()
            .is_some_and(|target| reference.matches(target))
        || !session.rows.iter().any(|row| {
            !row.mutation_pending
                && row.authenticated.record == reference.record
                && row.authenticated.revision == reference.revision
                && row.original == reference.original
                && slot.kind == Some(row.authenticated.descriptor.kind)
        })
        || !backup_native::retirement_ready(&slot.owner)
    {
        return false;
    }
    // Retirement may already have disposed the private export and working key.
    // Keep only the fixed original display stamp, not payloads or new custody.
    slot.owner.vault.try_lock().is_ok_and(|work| {
        work.first.is_none()
            && !work.release
            && work.release_end.is_none()
            && !work.backup_blocks_reuse()
            && work
                .store
                .as_ref()
                .is_some_and(|store| Arc::ptr_eq(store, &session.store))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> format::Id {
        format::Id::from_bytes([byte; 16]).unwrap()
    }
    fn context(revision: u32) -> Arc<NativeContext> {
        Arc::new(NativeContext {
            execution_mode: commands::ExecutionMode::Github,
            revision,
            project_id: "inert-project".into(),
            registry_generation: 7,
            draft: Vec::new(),
            project: asset_source::RegisteredRoot {
                path: "/inert/project".into(),
                identity: asset_source::ProjectIdentity::Posix(
                    asset_source::DirectoryIdentity::synthetic_evidence_identity(),
                ),
            },
            platform: Platform::Android,
            stage: Stage::Candidate,
            purpose: Purpose::Signing,
        })
    }
    fn model() -> DocumentState {
        // In-memory display predicates only. No bridge/RNG, private input,
        // picker, filesystem access or actual native receipt is acquired.
        let mut state = super::super::super::tests::empty_state();
        state.session = false;
        state.lifetime.crash_hook_installed();
        state.lifetime.started(true);
        state.lifetime.finished(true);
        let identity = format::Identity::new(id(1), id(2)).unwrap();
        let record = id(3);
        let revision = format::Revision::new(id(4), 1).unwrap();
        let mut session = Session::new(Arc::new(Mutex::new(store::StoreBook::new())), 7);
        session.identity = Some(identity);
        session.state = State::Unlocked;
        session.key = Some(Arc::new(crypto::lifecycle_data_key(identity)));
        let row = Descriptor {
            authenticated: crypto::AuthenticatedDescriptor {
                record,
                revision,
                descriptor: format::Descriptor::new(
                    Kind::AndroidKeystore,
                    None,
                    vec![false; 3],
                    true,
                )
                .unwrap(),
            },
            original: store::ReadWitness::lifecycle_data(record, revision),
            mutation_pending: false,
        };
        let reference = row.reference(identity);
        session.rows.push(row);
        let owner = OriginalWork::new(7, false, Weak::new());
        owner.set_endpoint(None);
        owner.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
        owner.child.try_lock().unwrap().receipt = JoinReceipt::Returned;
        owner.vault.lock().unwrap().store = Some(session.store.clone());
        let context = context(1);
        let mut slot = Slot::new(
            owner,
            Operation::PrepareBackupExport,
            Some(context.clone()),
            Some(reference.key()),
            None,
        );
        slot.kind = Some(Kind::AndroidKeystore);
        slot.phase = Phase::Idle;
        slot.settlement = Settlement::Known;
        slot.vault.lease = Some(session.store.clone());
        slot.vault.generation = Some(7);
        slot.vault.reference = Some(reference);
        slot.vault.backup_export_published = true;
        slot.vault.backup_export_context = Some((1, reference));
        state.vault = Some(session);
        state.slot = Some(slot);
        state.context = Some(context);
        state
    }

    #[test]
    fn idle_known_is_not_a_backup_publication_or_native_qualification() {
        assert!(!NATIVE_ANDROID_UPLOAD_KEY_BACKUP_QUALIFIED);
        let mut state = model();
        assert!(delivered_current(&state));
        state.slot.as_mut().unwrap().vault.backup_export_published = false;
        assert!(!delivered_current(&state));
        let status = DocumentBinding::status_data_modes(&state, true, true);
        let value = serde_json::to_value(status).unwrap();
        assert!(value["operation"].get("backupDelivered").is_none());
    }

    #[test]
    fn android_upload_key_scope_does_not_qualify_other_desktop_contexts() {
        // Scope DATA only: no picker, native qualification or source authority.
        let mut context = context(1);
        assert!(require_android_context(&context).is_err()); // GitHub mode.
        Arc::get_mut(&mut context).unwrap().execution_mode = commands::ExecutionMode::Local;
        assert!(require_android_context(&context).is_ok());
        for platform in [Platform::Ios, Platform::Both] {
            Arc::get_mut(&mut context).unwrap().platform = platform;
            assert!(require_android_context(&context).is_err());
        }
        assert!(!NATIVE_ANDROID_UPLOAD_KEY_BACKUP_QUALIFIED);
    }

    #[test]
    fn actual_reference_retirement_keeps_only_the_display_stamp_and_new_context_hides_it() {
        let mut state = model();
        let mut slot = state.slot.take().unwrap();
        let retired = take_retirement(&mut state, &mut slot);
        assert!(slot.vault.reference.is_none());
        assert!(slot.vault.backup_export_context.is_some());
        state.slot = Some(slot);
        drop(retired); // Actual off-lock disposal of synthetic empty holders.
        assert!(delivered_current(&state));
        let old = retire_context_authority(&mut state, Instant::now());
        assert!(old.is_some());
        assert!(state.slot.as_ref().unwrap().context.is_none());
        state.context = Some(context(2));
        drop(old);
        assert!(!delivered_current(&state));
    }

    #[test]
    fn equal_counter_new_random_revision_or_registry_never_matches_old_export() {
        let mut state = model();
        state.vault.as_mut().unwrap().rows[0].authenticated.revision =
            format::Revision::new(id(5), 1).unwrap();
        assert!(!delivered_current(&state));
        let mut state = model();
        state.vault.as_mut().unwrap().registry_generation = 8;
        assert!(!delivered_current(&state));
        let mut state = model();
        state.vault.as_mut().unwrap().rows[0].mutation_pending = true;
        assert!(!delivered_current(&state));
    }

    #[test]
    fn unknown_original_prior_failed_join_and_held_custody_never_project_success() {
        let mut state = model();
        state.unknown = true;
        assert!(!delivered_current(&state));
        let state = model();
        let owner = state.slot.as_ref().unwrap().owner.clone();
        owner.vault.lock().unwrap().original_join = Some(JoinReceipt::Failed);
        assert!(!delivered_current(&state));
        let state = model();
        let owner = state.slot.as_ref().unwrap().owner.clone();
        let held = owner.vault.lock().unwrap();
        assert!(!delivered_current(&state));
        drop(held);
        owner.retired.store(false, Ordering::SeqCst);
        assert!(!delivered_current(&state));
    }
}
