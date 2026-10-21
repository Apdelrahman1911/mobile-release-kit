//! Two closed Android backup comparisons in the existing vault/Asset owner.
//! No picker, material, backup grant or native retirement can be reconstructed
//! from IPC. The real two-picker Job and original private drain stay elsewhere.
use super::*;
use crate::credential_setup::KeyReference;
use crate::service_upload_key_protocol as agent;

pub(in crate::asset_session) enum Selection {
    Export(StoredRef),
    Restore(format::Identity),
}

impl Selection {
    pub(in crate::asset_session) fn capture(
        document: &DocumentBinding,
        state: &DocumentState,
        input: &agent::Selection,
    ) -> Result<Self, AssetError> {
        backup_desktop::qualification(document)?;
        let session = state.vault.as_ref().ok_or_else(AssetError::invalid)?;
        let identity = session.identity.ok_or_else(AssetError::invalid)?;
        let value = match input {
            agent::Selection::BackupEncrypted {
                record_id,
                expected_revision,
            } => {
                let key = own_record(commands::RecordRef {
                    record_id: record_id.as_str(),
                    expected_revision: *expected_revision,
                })?;
                let row = session
                    .row(&key)
                    .filter(|r| {
                        !r.mutation_pending
                            && r.authenticated.descriptor.kind == Kind::AndroidKeystore
                    })
                    .ok_or_else(|| AssetError::new(Reason::SourceRefused))?;
                Self::Export(row.reference(identity))
            }
            agent::Selection::RestoreEncrypted { .. } if input.valid() => Self::Restore(identity),
            _ => return Err(AssetError::invalid()),
        };
        value.current(document, state)?;
        Ok(value)
    }

    pub(in crate::asset_session) fn kind(&self) -> agent::Kind {
        match self {
            Self::Export(_) => agent::Kind::BackupEncrypted,
            Self::Restore(_) => agent::Kind::RestoreEncrypted,
        }
    }

    pub(in crate::asset_session) fn current(
        &self,
        document: &DocumentBinding,
        state: &DocumentState,
    ) -> Result<(), AssetError> {
        backup_desktop::qualification(document)?;
        idle(state)?;
        let context = state.context.as_ref().ok_or_else(AssetError::invalid)?;
        let session = state
            .vault
            .as_ref()
            .filter(|s| s.writable())
            .ok_or_else(AssetError::invalid)?;
        if context.platform != Platform::Android
            || context.execution_mode != commands::ExecutionMode::Local
            || !document.context_matches(state, context)?
            || context.registry_generation != session.registry_generation
        {
            return Err(AssetError::new(Reason::ContextStale));
        }
        let identity = match self {
            Self::Export(r) => r.identity,
            Self::Restore(i) => *i,
        };
        if session.identity != Some(identity)
            || session
                .key
                .as_ref()
                .is_none_or(|key| key.identity() != identity)
        {
            return Err(AssetError::new(Reason::ContextStale));
        }
        match self {
            Self::Export(reference) => {
                session_kind_gate(context, Kind::AndroidKeystore)?;
                if !session.rows.iter().any(|row| {
                    !row.mutation_pending
                        && row.authenticated.descriptor.kind == Kind::AndroidKeystore
                        && same_record(*reference, row.reference(identity))
                }) {
                    return Err(AssetError::new(Reason::SourceChanged));
                }
            }
            Self::Restore(_) if session.rows.len() >= store::DESCRIPTOR_COUNT => {
                return Err(AssetError::new(Reason::Capacity));
            }
            Self::Restore(_) => {
                session_kind_gate(context, Kind::AndroidKeystore)?;
            }
        }
        Ok(())
    }

    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    pub(in crate::asset_session) fn run(
        &self,
        document: &DocumentBinding,
        app: tauri::AppHandle,
        link: Arc<crate::service_upload_key_requests::NativeLink>,
    ) -> Result<(), AssetError> {
        let context_revision = {
            let state = document.lock();
            self.current(document, &state)?;
            state
                .context
                .as_ref()
                .ok_or_else(AssetError::invalid)?
                .revision
        };
        match self {
            Self::Export(reference) => {
                let record = reference.record.token();
                document.choose_credential_backup_export_delegated(
                    app,
                    context_revision,
                    commands::RecordRef {
                        record_id: &record,
                        expected_revision: reference.revision.counter,
                    },
                    Some(link),
                )
            }
            Self::Restore(_) => document.choose_credential_backup_import_delegated(
                app,
                context_revision,
                Some(link),
            ),
        }
        .map(|_| ())
    }
}

fn same_record(left: StoredRef, right: StoredRef) -> bool {
    left.identity == right.identity
        && left.record == right.record
        && left.revision == right.revision
        && left.original == right.original
}

fn import_kind(link: Option<agent::Kind>, authenticated: Kind) -> Result<(), Reason> {
    match link {
        None => Ok(()), // Only a genuinely ordinary, unlinked import.
        Some(agent::Kind::RestoreEncrypted) if authenticated == Kind::AndroidKeystore => Ok(()),
        _ => Err(Reason::SourceRefused),
    }
}

/// Called after THIS original BackupSources authenticated its payload and
/// BEFORE seal_new/NEW. A wrong attached kind is never an ordinary import.
pub(super) fn require_import_kind(owner: &OriginalWork, authenticated: Kind) -> Result<(), Reason> {
    import_kind(
        owner
            .agent_upload_key
            .get()
            .map(|link| link.entry().scope().kind),
        authenticated,
    )
}

/// Comparison stamp captured only while the SAME parent accepts the already
/// validated NEW/readback row. No later list/status reconstruction is used.
pub(super) fn import_publication(
    slot: &Slot,
    row: Option<&Descriptor>,
    identity: Option<format::Identity>,
) -> Result<Option<(u32, StoredRef)>, Reason> {
    let Some(link) = slot.owner.agent_upload_key.get() else {
        return Ok(None);
    };
    let row = row.ok_or(Reason::SourceChanged)?;
    import_kind(
        Some(link.entry().scope().kind),
        row.authenticated.descriptor.kind,
    )?;
    let context = slot.context.as_ref().ok_or(Reason::SourceChanged)?;
    if slot.operation != Operation::ImportBackup
        || slot.target.is_some()
        || context.platform != Platform::Android
        || context.execution_mode != commands::ExecutionMode::Local
        || row.mutation_pending
        || row.authenticated.revision.counter != 1
    {
        return Err(Reason::SourceChanged);
    }
    Ok(Some((
        context.revision,
        row.reference(identity.ok_or(Reason::SourceChanged)?),
    )))
}

fn private_returned(state: &DocumentState, slot: &Slot) -> bool {
    if state.retiring
        || !slot.owner.resources_settled()
        || !slot_private_data_empty(slot)
        || !slot
            .owner
            .coordinator
            .try_lock()
            .is_ok_and(|b| b.receipt == JoinReceipt::Returned && b.handle.is_none())
        || !slot.owner.vault.try_lock().is_ok_and(|work| {
            work.backup.empty()
                && work
                    .original_join
                    .is_none_or(|r| r == JoinReceipt::Returned)
                && work.failed_child_join.is_none()
        })
        || !slot
            .owner
            .retirement
            .try_lock()
            .is_ok_and(|holding| !holding.vault.backup_blocks_reuse())
    {
        return false;
    }
    // A declined first picker may never enter the native I/O child. Its real
    // coordinator and BOTH GUI/resource returns can close only a failed action,
    // not mint delivery, NEW, retry or any generation no-GO acknowledgment.
    let never_child = slot
        .owner
        .child
        .try_lock()
        .is_ok_and(|b| b.receipt == JoinReceipt::New && b.handle.is_none());
    never_child || backup_native::retirement_ready(&slot.owner)
}

fn restored_reference(
    document: &DocumentBinding,
    state: &DocumentState,
    slot: &Slot,
) -> Option<KeyReference> {
    let (revision, reference) = slot.vault.backup_import_context?;
    let context = state.context.as_ref()?;
    let session = state.vault.as_ref()?;
    if !slot.vault.backup_new_published
        || slot.target.is_some()
        || slot.reason != Reason::None
        || slot.error.is_some()
        || slot.cleanup_end.is_some()
        || state.session
        || state.stopping
        || state.unknown
        || state.exhausted
        || state.lost_observed
        || state.lock_pending
        || state.quit_pending
        || state.session_owner_reason.is_some()
        || !state.lifetime.original_bound()
        || slot.owner.stopped()
        || !session.writable()
        || !owns(slot, session)
        || session.identity != Some(reference.identity)
        || session
            .key
            .as_ref()
            .is_none_or(|key| key.identity() != reference.identity)
        || context.revision != revision
        || context.registry_generation != session.registry_generation
        || slot.vault.generation != Some(session.registry_generation)
        || slot
            .context
            .as_ref()
            .is_none_or(|old| !Arc::ptr_eq(old, context))
        || !document.context_matches(state, context).ok()?
        || slot
            .result_record
            .as_ref()
            .is_none_or(|key| !reference.matches(key))
        || slot.vault.outcome
            != Some(store::StorageOutcome {
                effect: store::Effect::KnownApplied,
                durability: store::Durability::Confirmed,
                cleanup: store::Cleanup::Known,
            })
        || !session.rows.iter().any(|row| {
            !row.mutation_pending
                && row.authenticated.descriptor.kind == Kind::AndroidKeystore
                && same_record(reference, row.reference(reference.identity))
        })
        || session
            .bound
            .iter()
            .flatten()
            .any(|loan| same_record(loan.reference, reference))
        || state.assignments.iter().any(|a| {
            a.record_id.0 == reference.record.token()
                && a.record_revision == reference.revision.counter
        })
    {
        return None;
    }
    // The source/wrapping key and payload have drained; only the original Store
    // lease remains. Neither physical file presence nor this stamp grants Bind.
    if !slot.owner.vault.try_lock().is_ok_and(|work| {
        work.first.is_none()
            && !work.release
            && work.release_end.is_none()
            && work
                .store
                .as_ref()
                .is_some_and(|s| Arc::ptr_eq(s, &session.store))
    }) {
        return None;
    }
    Some(KeyReference::native(
        reference.identity,
        reference.record,
        reference.revision,
    ))
}

/// Called at the actual same-Asset retirement, before that slot can be replaced.
/// The existing Entry still waits for its caller AND continuation to return.
pub(in crate::asset_session) fn completion(
    document: &DocumentBinding,
    state: &DocumentState,
    slot: &Slot,
) -> Option<(agent::State, agent::Reason, Option<KeyReference>)> {
    let link = slot.owner.agent_upload_key.get()?;
    let expected = match slot.operation {
        Operation::PrepareBackupExport => agent::Kind::BackupEncrypted,
        Operation::ImportBackup => agent::Kind::RestoreEncrypted,
        _ => return None,
    };
    if link.entry().scope().kind != expected
        || !private_returned(state, slot)
        || slot.phase != Phase::Idle
        || slot.settlement != Settlement::Known
    {
        return None;
    }
    if expected == agent::Kind::BackupEncrypted
        && backup_desktop::delivered_current(state)
        && slot.kind == Some(Kind::AndroidKeystore)
        && state
            .context
            .as_ref()
            .is_some_and(|context| document.context_matches(state, context).unwrap_or(false))
    {
        return Some((agent::State::BackupDelivered, agent::Reason::None, None));
    }
    if expected == agent::Kind::RestoreEncrypted && backup_native::retirement_ready(&slot.owner) {
        if let Some(key) = restored_reference(document, state, slot) {
            return Some((
                agent::State::RestoredUnassigned,
                agent::Reason::None,
                Some(key),
            ));
        }
    }
    Some(match slot.reason {
        Reason::UserCancelled | Reason::Shutdown => (
            agent::State::Cancelled,
            agent::Reason::PermissionRevoked,
            None,
        ),
        Reason::Deadline => (agent::State::Cancelled, agent::Reason::Expired, None),
        _ => (
            agent::State::RecoveryRequired,
            agent::Reason::RecoveryRequired,
            None,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_kind_policy_has_no_wrong_link_fallback_before_new() {
        assert!(import_kind(None, Kind::AscP8).is_ok()); // Unchanged ordinary import.
        assert!(import_kind(Some(agent::Kind::RestoreEncrypted), Kind::AndroidKeystore).is_ok());
        for selected in [
            agent::Kind::GenerateNew,
            agent::Kind::BindReviewed,
            agent::Kind::BackupEncrypted,
        ] {
            assert_eq!(
                import_kind(Some(selected), Kind::AndroidKeystore),
                Err(Reason::SourceRefused)
            );
        }
        for kind in [
            Kind::AscP8,
            Kind::AppleP12,
            Kind::AppleDistributionKey,
            Kind::GoogleServiceAccount,
        ] {
            assert_eq!(
                import_kind(Some(agent::Kind::RestoreEncrypted), kind),
                Err(Reason::SourceRefused)
            );
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn full_reference_comparison_keeps_random_revision_and_original_read_witness() {
        // Exact comparison DATA only: zero-mode witness has no native authority.
        let id = |byte| format::Id::from_bytes([byte; 16]).unwrap();
        let identity = format::Identity::new(id(1), id(2)).unwrap();
        let revision = format::Revision::new(id(4), 1).unwrap();
        let reference = StoredRef {
            identity,
            record: id(3),
            revision,
            original: store::ReadWitness::lifecycle_data(id(3), revision),
        };
        assert!(same_record(reference, reference));
        let mut changed = reference;
        changed.identity = format::Identity::new(id(1), id(5)).unwrap();
        assert!(!same_record(reference, changed));
        changed = reference;
        changed.record = id(6);
        assert!(!same_record(reference, changed));
        changed = reference;
        changed.revision = format::Revision::new(id(7), 1).unwrap();
        assert!(!same_record(reference, changed));
        changed = reference;
        changed.original =
            store::ReadWitness::lifecycle_data(id(3), format::Revision::new(id(8), 1).unwrap());
        assert!(!same_record(reference, changed));
    }

    #[test]
    fn untouched_original_cannot_supply_backup_retirement_or_an_import_stamp() {
        // DATA only: no GUI facts, storage, mutation, native receipt or key.
        let state = super::super::super::tests::empty_state();
        let owner = OriginalWork::new(1, false, Weak::new());
        let slot = Slot::new(owner, Operation::ImportBackup, None, None, None);
        assert!(!private_returned(&state, &slot));
        assert!(slot.vault.backup_import_context.is_none());
        assert!(import_publication(&slot, None, None).unwrap().is_none());
    }
}
