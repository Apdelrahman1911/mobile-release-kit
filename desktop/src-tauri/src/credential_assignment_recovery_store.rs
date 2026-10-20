//! Closed reference-only recovery writes over the SAME private state owner.
//!
//! Preparing bytes has no effect. The original native coordinator retains this
//! exact object before the one CAS attempt, rematches its native originals and
//! checks its unchanged deadline. No generic callback, path or namespace is
//! accepted and no failed/late result is retried here.
use super::*;
use std::time::Instant;

// Existing exact-file reader/decode/current/next/readback backing plus the
// bounded typed journal graph and encoder. This is a reserved transient quote,
// charged by the same parent before GO, not a second memory pool.
pub(crate) const IO_RESERVATION_BYTES: usize =
    4 * (crate::application_state_store::MAX_BYTES + 64) + 4 * super::super::JOURNAL_LIMIT;

pub(crate) struct Change {
    revision: Revision,
    bytes: Vec<u8>,
    attempted: bool,
    result: Option<Result<u64>>,
}
impl Change {
    fn prepared(revision: Revision, journal: &Journal) -> Result<Self> {
        Ok(Self {
            revision,
            bytes: journal.encode()?,
            attempted: false,
            result: None,
        })
    }
    pub(crate) fn known_revision(&self) -> Option<u64> {
        self.result.and_then(std::result::Result::ok)
    }
    pub(crate) fn actual_result(&self) -> Option<Result<u64>> {
        self.result
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(self.bytes.capacity())
    }
    pub(crate) fn commit_once(
        &mut self,
        state: &PrivateStateDirectory,
        original_end: Instant,
    ) -> Result<u64> {
        if self.attempted {
            return Err(Error::RecoveryRequired.into());
        }
        self.attempted = true; // Retained BEFORE real IO, including a refused deadline.
        if Instant::now() >= original_end {
            let result = Err(Error::Stale.into());
            self.result = Some(result);
            return result;
        }
        let result = state
            .replace(Namespace::CredentialReferences, self.revision, &self.bytes)
            .map_err(Failure::from)
            .and_then(|saved| {
                if saved.bytes != self.bytes
                    || Some(saved.revision.0) != self.revision.0.checked_add(1)
                {
                    Err(Error::RecoveryRequired.into())
                } else {
                    Ok(saved.revision.0)
                }
            });
        self.result = Some(result); // Actual applied/unknown return survives a late caller.
        if Instant::now() >= original_end {
            return Err(Error::RecoveryRequired.into());
        }
        result
    }
}

fn before(
    state: &PrivateStateDirectory,
    project: &ProjectBinding,
    expected_revision: u64,
    original_end: Instant,
) -> Result<(Revision, Journal)> {
    if Instant::now() >= original_end {
        return Err(Error::Stale.into());
    }
    project.validate()?;
    state.excludes_project(project.device, project.inode)?;
    let (revision, journal) = load(state)?;
    expected(revision, expected_revision)?;
    if Instant::now() >= original_end {
        return Err(Error::Stale.into());
    }
    Ok((revision, journal))
}

/// A reservation alone does NOT prove no-GO. The sole production caller is the
/// consumed original cancellation/disposal path, still holding NativeUse.
pub(crate) fn prepare_stopped_no_go(
    state: &PrivateStateDirectory,
    reservation: &DurableGenerationReservation,
    original_end: Instant,
) -> Result<Change> {
    let (revision, mut journal) = before(
        state,
        &reservation.project,
        reservation.store_revision.0,
        original_end,
    )?;
    journal.stopped_no_go(
        journal.sequence(),
        &reservation.project,
        &reservation.intent,
    )?;
    Change::prepared(revision, &journal)
}

pub(crate) fn prepare_acknowledge(
    state: &PrivateStateDirectory,
    expected_revision: u64,
    project: &ProjectBinding,
    observed: &Observation<'_>,
    original_end: Instant,
) -> Result<Change> {
    let (revision, mut journal) = before(state, project, expected_revision, original_end)?;
    journal.acknowledge_unstarted(journal.sequence(), project, observed)?;
    Change::prepared(revision, &journal)
}

/// The operation ID comes from the actual journal, never a renderer/new nonce.
/// The native caller supplies only its retained current BoundLoan/full witness.
pub(crate) fn prepare_bound(
    state: &PrivateStateDirectory,
    expected_revision: u64,
    project: &ProjectBinding,
    reference: super::super::KeyReference,
    observed: &Observation<'_>,
    original_end: Instant,
) -> Result<Change> {
    let (revision, mut journal) = before(state, project, expected_revision, original_end)?;
    let operation_id = match journal.preference(project, Role::AndroidUpload)? {
        Some(Preference::GenerationReserved(intent)) => intent.operation_id.clone(),
        Some(Preference::RecordSaved(saved) | Preference::Assigned(saved)) => {
            saved.operation_id.clone()
        }
        _ => return Err(Error::RecoveryRequired.into()),
    };
    let current = observed
        .records
        .iter()
        .find(|row| row.reference == &reference)
        .ok_or(Error::Stale)?;
    let saved = SavedAssignment {
        reference,
        identity_sha256: observed.identity_sha256.to_owned(),
        certificate_sha256: current.certificate_sha256.map(str::to_owned),
        operation_id,
    };
    journal.reconcile_bound(journal.sequence(), project, saved, observed)?;
    Change::prepared(revision, &journal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        application_state_store::Fixture,
        credential_setup::{Assessment, Continuity, KeyReference, RecordObservation, Storage},
    };
    use std::time::Duration;
    fn project() -> ProjectBinding {
        ProjectBinding {
            project_id: "11".repeat(16),
            canonical_root: "/synthetic/recovery".into(),
            device: 7,
            inode: 8,
        }
    }
    fn key() -> KeyReference {
        KeyReference {
            vault_id: "22".repeat(16),
            generation_id: "33".repeat(16),
            record_id: "44".repeat(16),
            revision_id: "55".repeat(16),
            revision_counter: 1,
        }
    }
    fn intent() -> GenerationIntent {
        GenerationIntent {
            operation_id: "77".repeat(16),
            vault_id: key().vault_id,
            generation_id: key().generation_id,
            record_id: key().record_id,
            identity_sha256: "66".repeat(32),
            observation_revision: 1,
        }
    }
    fn observation<'a>(
        project: &'a ProjectBinding,
        records: &'a [RecordObservation<'a>],
    ) -> Observation<'a> {
        Observation {
            project,
            role: Role::AndroidUpload,
            revision: 1,
            identity_sha256: "6666666666666666666666666666666666666666666666666666666666666666",
            expected_certificate_sha256: None,
            storage: Storage::Unlocked,
            vault_identity: Some(key().parts().unwrap().0),
            continuity: Continuity::NewApplicationConfirmed,
            operation_pending: false,
            records,
        }
    }
    fn end() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }

    #[test]
    fn real_reference_store_no_go_survives_reopen_ack_does_not_generate() {
        let fixture = Fixture::new();
        let project = project();
        let observed = observation(&project, &[]);
        let store = PrivateStateDirectory::open(&fixture.app).unwrap();
        let reservation = reserve_generation(
            &store,
            0,
            &project,
            Role::AndroidUpload,
            intent(),
            &observed,
        )
        .unwrap();
        // Synthetic caller input exercises actual namespace CAS, NOT native noGO proof.
        let mut change = prepare_stopped_no_go(&store, &reservation, end()).unwrap();
        assert_eq!(change.commit_once(&store, end()).unwrap(), 2);
        assert_eq!(change.known_revision(), Some(2));
        assert!(change.commit_once(&store, end()).is_err());
        store.close().unwrap();
        let store = PrivateStateDirectory::open(&fixture.app).unwrap();
        let current = observe(&store, &project, Role::AndroidUpload).unwrap();
        assert!(matches!(
            current.preference,
            Some(Preference::GenerationStoppedNoGo(_))
        ));
        let mut ack =
            prepare_acknowledge(&store, current.store_revision, &project, &observed, end())
                .unwrap();
        assert_eq!(ack.commit_once(&store, end()).unwrap(), 3);
        assert!(observe(&store, &project, Role::AndroidUpload)
            .unwrap()
            .preference
            .is_none());
        assert!(reserve_generation(
            &store,
            3,
            &project,
            Role::AndroidUpload,
            intent(),
            &observed
        )
        .is_err());
        store.close().unwrap();
    }
    #[test]
    fn expired_and_stale_changes_keep_actual_original_preference() {
        let fixture = Fixture::new();
        let project = project();
        let observed = observation(&project, &[]);
        let store = PrivateStateDirectory::open(&fixture.app).unwrap();
        let reservation = reserve_generation(
            &store,
            0,
            &project,
            Role::AndroidUpload,
            intent(),
            &observed,
        )
        .unwrap();
        let mut stale = prepare_stopped_no_go(&store, &reservation, end()).unwrap();
        let mut actual = prepare_stopped_no_go(&store, &reservation, end()).unwrap();
        actual.commit_once(&store, end()).unwrap();
        assert!(stale.commit_once(&store, end()).is_err());
        assert!(stale.known_revision().is_none());
        let mut ack = prepare_acknowledge(&store, 2, &project, &observed, end()).unwrap();
        assert!(ack
            .commit_once(&store, Instant::now() - Duration::from_secs(1))
            .is_err());
        assert!(ack.commit_once(&store, end()).is_err()); // No renewal of that attempt.
        assert!(matches!(
            observe(&store, &project, Role::AndroidUpload)
                .unwrap()
                .preference,
            Some(Preference::GenerationStoppedNoGo(_))
        ));
        store.close().unwrap();
    }
    #[test]
    fn explicit_current_bound_reconciliation_keeps_original_operation_and_random_revision() {
        let fixture = Fixture::new();
        let project = project();
        let key = key();
        let store = PrivateStateDirectory::open(&fixture.app).unwrap();
        reserve_generation(
            &store,
            0,
            &project,
            Role::AndroidUpload,
            intent(),
            &observation(&project, &[]),
        )
        .unwrap();
        let rows = [RecordObservation {
            reference: &key,
            certificate_sha256: None,
            assessment: Assessment::Current,
            current_assignment: true,
            mutation_pending: false,
        }];
        let observed = observation(&project, &rows);
        let mut change = prepare_bound(&store, 1, &project, key.clone(), &observed, end()).unwrap();
        change.commit_once(&store, end()).unwrap();
        store.close().unwrap();
        let store = PrivateStateDirectory::open(&fixture.app).unwrap();
        let current = observe(&store, &project, Role::AndroidUpload).unwrap();
        let saved = current.preference.as_ref().unwrap().saved().unwrap();
        assert!(saved.reference == key);
        assert_eq!(saved.operation_id, intent().operation_id);
        assert!(
            prepare_acknowledge(&store, 2, &project, &observation(&project, &[]), end()).is_err()
        );
        store.close().unwrap();
    }
}
