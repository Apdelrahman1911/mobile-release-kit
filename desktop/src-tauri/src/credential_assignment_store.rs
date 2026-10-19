//! Typed credential preferences over the SAME shared native app-data owner.
//!
//! No filesystem paths, private material, arbitrary namespace or IO callback are
//! accepted. The shared store owns its actual no-follow originals, singleton
//! lock, expected revision, durable intent fence and close/sync outcomes. These
//! preferences can help resume setup; they can never authorize a credential.
use super::{Error, GenerationIntent, Journal, Observation, Preference, ProjectBinding, Role, SavedAssignment};
use crate::application_state_store::{Namespace, PrivateStateDirectory, Revision, StateError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure { Storage(StateError), Data(Error) }
impl From<StateError> for Failure { fn from(value: StateError) -> Self { Self::Storage(value) } }
impl From<Error> for Failure { fn from(value: Error) -> Self { Self::Data(value) } }
type Result<T> = std::result::Result<T, Failure>;

pub(crate) struct PreferenceSnapshot {
    pub(crate) store_revision: u64,
    pub(crate) preference: Option<Preference>,
}

/// An actual successful reservation publication, not deserializable permit
/// DATA. The future native generation owner must consume this AND its own
/// one-use operation authorization and tool/producer originals before work.
pub(crate) struct DurableGenerationReservation {
    store_revision: Revision,
    project: ProjectBinding,
    role: Role,
    intent: GenerationIntent,
}
impl DurableGenerationReservation {
    pub(crate) fn operation_id(&self) -> &str { &self.intent.operation_id }
    pub(crate) fn target_record_id(&self) -> &str { &self.intent.record_id }
    pub(crate) fn store_revision(&self) -> u64 { self.store_revision.0 }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let mut bytes = std::mem::size_of::<Self>();
        for value in [&self.project.project_id, &self.project.canonical_root, &self.intent.operation_id,
            &self.intent.vault_id, &self.intent.generation_id, &self.intent.record_id, &self.intent.identity_sha256] {
            bytes = bytes.checked_add(value.capacity())?;
        }
        Some(bytes)
    }
    /// Recheck the full original reference-only intent, without retrying or
    /// treating absence/corruption as a new generation opportunity.
    pub(crate) fn current(&self, state: &PrivateStateDirectory) -> Result<()> {
        let (revision, journal) = load(state)?;
        if revision != self.store_revision || journal.preference(&self.project, self.role)?
            != Some(&Preference::GenerationReserved(self.intent.clone())) { return Err(Error::Stale.into()); }
        Ok(())
    }
}

fn load(state: &PrivateStateDirectory) -> Result<(Revision, Journal)> {
    let snapshot = state.read(Namespace::CredentialReferences)?;
    // This exact initially-created empty envelope is distinguished from a
    // missing namespace by the shared owner's durable reservation. A later
    // empty value is corrupt, not a reset/reinitialization instruction.
    let journal = if snapshot.revision == Revision(0) && snapshot.bytes.is_empty() {
        Journal::initialize()
    } else {
        Journal::decode(&snapshot.bytes)?
    };
    Ok((snapshot.revision, journal))
}
fn expected(actual: Revision, expected: u64) -> Result<()> {
    if actual.0 == expected { Ok(()) } else { Err(Error::Stale.into()) }
}
fn publish(state: &PrivateStateDirectory, revision: Revision, journal: &Journal) -> Result<u64> {
    let bytes = journal.encode()?;
    let saved = state.replace(Namespace::CredentialReferences, revision, &bytes)?;
    if saved.bytes != bytes || saved.revision.0 != revision.0.checked_add(1).ok_or(Error::Bounds)? {
        return Err(Error::RecoveryRequired.into());
    }
    Ok(saved.revision.0)
}

pub(crate) fn observe(state: &PrivateStateDirectory, project: &ProjectBinding, role: Role) -> Result<PreferenceSnapshot> {
    project.validate()?;
    state.excludes_project(project.device, project.inode)?;
    let (revision, journal) = load(state)?;
    Ok(PreferenceSnapshot { store_revision: revision.0, preference: journal.preference(project, role)?.cloned() })
}

pub(crate) fn reserve_generation(state: &PrivateStateDirectory, expected_store_revision: u64,
    project: &ProjectBinding, role: Role, intent: GenerationIntent, native: &Observation<'_>) -> Result<DurableGenerationReservation> {
    project.validate()?;
    state.excludes_project(project.device, project.inode)?;
    let (revision, mut journal) = load(state)?;
    expected(revision, expected_store_revision)?;
    journal.reserve(journal.sequence(), project, role, intent.clone(), native)?;
    let revision = publish(state, revision, &journal)?;
    Ok(DurableGenerationReservation { store_revision: Revision(revision), project: project.clone(), role, intent })
}

/// Called by the existing native vault owner only after original New-record
/// effect, durability AND cleanup/finality are accepted. No retry on failure.
pub(crate) fn record_saved(state: &PrivateStateDirectory, expected_store_revision: u64,
    project: &ProjectBinding, role: Role, saved: SavedAssignment) -> Result<u64> {
    project.validate()?;
    state.excludes_project(project.device, project.inode)?;
    let (revision, mut journal) = load(state)?;
    expected(revision, expected_store_revision)?;
    journal.record_saved(journal.sequence(), project, role, saved)?;
    publish(state, revision, &journal)
}

/// Native current assessment+Bind feeds this private adapter. These DATA
/// observations never replace the native owner checks or grant a material loan.
pub(crate) fn remember_bound(state: &PrivateStateDirectory, expected_store_revision: u64,
    project: &ProjectBinding, role: Role, saved: SavedAssignment, native: &Observation<'_>, reassign: bool) -> Result<u64> {
    project.validate()?;
    state.excludes_project(project.device, project.inode)?;
    let (revision, mut journal) = load(state)?;
    expected(revision, expected_store_revision)?;
    journal.assigned(journal.sequence(), project, role, saved, native, reassign)?;
    publish(state, revision, &journal)
}

#[cfg(test)]
mod tests {
    // Actual bounded reference-file IO through the shared store, with synthetic
    // comparison DATA. No vault/keyring/native producer/signing is exercised.
    use super::*;
    use crate::{application_state_store::Fixture, credential_setup::{Assessment, Continuity, KeyReference, RecordObservation, Storage, Plan, classify}};
    fn project() -> ProjectBinding { ProjectBinding { project_id: "11".repeat(16), canonical_root: "/synthetic/project".into(), device: 7, inode: 8 } }
    fn reference() -> KeyReference { KeyReference { vault_id: "22".repeat(16), generation_id: "33".repeat(16), record_id: "44".repeat(16), revision_id: "55".repeat(16), revision_counter: 1 } }
    fn saved() -> SavedAssignment { SavedAssignment { reference: reference(), identity_sha256: "66".repeat(32), certificate_sha256: None, operation_id: "77".repeat(16) } }
    fn intent() -> GenerationIntent { GenerationIntent { operation_id: saved().operation_id, vault_id: reference().vault_id, generation_id: reference().generation_id,
        record_id: reference().record_id, identity_sha256: saved().identity_sha256, observation_revision: 1 } }
    fn observation<'a>(project: &'a ProjectBinding, records: &'a [RecordObservation<'a>]) -> Observation<'a> {
        Observation { project, role: Role::AndroidUpload, revision: 1, identity_sha256: "6666666666666666666666666666666666666666666666666666666666666666",
            expected_certificate_sha256: None, storage: Storage::Unlocked, vault_identity: Some(reference().parts().unwrap().0),
            continuity: Continuity::NewApplicationConfirmed, operation_pending: false, records }
    }
    #[test]
    fn reservation_and_saved_reference_survive_real_store_close_and_reopen() {
        let fixture = Fixture::new(); let project = project(); let observed = observation(&project, &[]);
        let store = PrivateStateDirectory::open(&fixture.app).unwrap();
        let reservation = reserve_generation(&store, 0, &project, Role::AndroidUpload, intent(), &observed).unwrap();
        reservation.current(&store).unwrap();
        store.close().unwrap();
        let store = PrivateStateDirectory::open(&fixture.app).unwrap();
        let current = observe(&store, &project, Role::AndroidUpload).unwrap();
        assert_eq!(classify(&observed, current.preference.as_ref()).unwrap(), Plan::RecoveryRequired);
        assert!(reserve_generation(&store, current.store_revision, &project, Role::AndroidUpload, intent(), &observed).is_err());
        record_saved(&store, current.store_revision, &project, Role::AndroidUpload, saved()).unwrap();
        store.close().unwrap();
        let store = PrivateStateDirectory::open(&fixture.app).unwrap();
        let current = observe(&store, &project, Role::AndroidUpload).unwrap();
        assert!(matches!(&current.preference, Some(Preference::RecordSaved(_))));
        assert_eq!(classify(&observed, current.preference.as_ref()).unwrap(), Plan::ExistingKeyRequired);
        store.close().unwrap();
    }
    #[test]
    fn completed_bind_choice_persists_but_a_new_session_still_needs_assessment() {
        let fixture = Fixture::new(); let project = project(); let reference = reference();
        let records = [RecordObservation { reference: &reference, certificate_sha256: None, assessment: Assessment::Current, current_assignment: true, mutation_pending: false }];
        let store = PrivateStateDirectory::open(&fixture.app).unwrap();
        assert_eq!(remember_bound(&store, 0, &project, Role::AndroidUpload, saved(), &observation(&project, &records), false).unwrap(), 1);
        assert!(matches!(remember_bound(&store, 0, &project, Role::AndroidUpload, saved(), &observation(&project, &records), false), Err(Failure::Data(Error::Stale))));
        store.close().unwrap();
        let store = PrivateStateDirectory::open(&fixture.app).unwrap();
        let current = observe(&store, &project, Role::AndroidUpload).unwrap();
        let records = [RecordObservation { reference: &reference, certificate_sha256: None, assessment: Assessment::NotChecked, current_assignment: false, mutation_pending: false }];
        assert_eq!(classify(&observation(&project, &records), current.preference.as_ref()).unwrap(), Plan::AssessmentNeeded);
        store.close().unwrap();
    }
    #[test]
    fn noninitial_empty_or_corrupt_payload_is_never_reset() {
        for contents in [b"".as_slice(), b"{}", b"not a journal"] {
            let fixture = Fixture::new(); let store = PrivateStateDirectory::open(&fixture.app).unwrap();
            store.replace(Namespace::CredentialReferences, Revision(0), contents).unwrap();
            assert!(observe(&store, &project(), Role::AndroidUpload).is_err());
            store.close().unwrap();
        }
    }
}
