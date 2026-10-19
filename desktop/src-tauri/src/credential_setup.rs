//! Reuse-first signing setup and durable preference semantics.
//!
//! All observations come from the original native owners. A plan or persisted
//! reference is comparison DATA, never a material loan, tool lease, approval or
//! successful native operation. In particular, restart never restores Bind.
use crate::vault_format::{Id, Identity, Revision};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[path = "credential_assignment_store.rs"]
pub(crate) mod persistence;

pub(crate) const JOURNAL_LIMIT: usize = 256 * 1024;
const SLOT_LIMIT: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error { Shape, Bounds, Stale, Conflict, RecoveryRequired, Continuity, Unavailable }
pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Role { AndroidUpload, AppleDistribution, AppleSigningKey }

/// Full native vault reference. Counters alone alias across vault restarts and
/// imports; both random generations are mandatory. This object has no getter
/// for credential bytes and is not an assessment.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct KeyReference {
    pub(crate) vault_id: String,
    pub(crate) generation_id: String,
    pub(crate) record_id: String,
    pub(crate) revision_id: String,
    pub(crate) revision_counter: u32,
}
impl KeyReference {
    pub(crate) fn native(identity: Identity, record: Id, revision: Revision) -> Self {
        Self { vault_id: identity.vault.token(), generation_id: identity.generation.token(),
            record_id: record.token(), revision_id: revision.random.token(), revision_counter: revision.counter }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.parts().map(|_| ())
    }
    pub(crate) fn parts(&self) -> Result<(Identity, Id, Revision)> {
        let id = |value: &str| Id::from_token(value).map_err(|_| Error::Shape);
        let identity = Identity::new(id(&self.vault_id)?, id(&self.generation_id)?).map_err(|_| Error::Shape)?;
        let record = id(&self.record_id)?;
        let revision = Revision::new(id(&self.revision_id)?, self.revision_counter).map_err(|_| Error::Shape)?;
        if record == identity.vault || record == identity.generation || revision.random == record
            || revision.random == identity.vault || revision.random == identity.generation { return Err(Error::Shape); }
        Ok((identity, record, revision))
    }
}

/// Private native binding supplied by the shared durable project registry.
/// project_id is persisted random identity, NEVER a session ordinal. Path and
/// inode continuity must be reconciled explicitly; neither is IPC authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ProjectBinding {
    pub(crate) project_id: String,
    pub(crate) canonical_root: String,
    pub(crate) device: u64,
    pub(crate) inode: u64,
}
impl ProjectBinding {
    pub(crate) fn validate(&self) -> Result<()> {
        Id::from_token(&self.project_id).map_err(|_| Error::Shape)?;
        let path = Path::new(&self.canonical_root);
        if self.canonical_root.is_empty() || self.canonical_root.len() > 4096
            || self.canonical_root.contains('\0') || self.inode == 0 || !path.is_absolute()
            || self.canonical_root.split('/').any(|part| matches!(part, "." | ".."))
            || self.canonical_root.ends_with('/') || self.canonical_root.contains("//") {
            return Err(Error::Shape);
        }
        Ok(())
    }
    fn related(&self, other: &Self) -> bool {
        self.project_id == other.project_id || self.canonical_root == other.canonical_root
            || self.device == other.device && self.inode == other.inode
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct SavedAssignment {
    pub(crate) reference: KeyReference,
    pub(crate) identity_sha256: String,
    // A reviewed PUBLIC certificate fingerprint, not a hash of private data.
    pub(crate) certificate_sha256: Option<String>,
    pub(crate) operation_id: String,
}
impl SavedAssignment {
    fn validate(&self) -> Result<()> {
        self.reference.validate()?;
        Id::from_token(&self.operation_id).map_err(|_| Error::Shape)?;
        if !digest(&self.identity_sha256) || self.certificate_sha256.as_deref().is_some_and(|value| !digest(value)) {
            return Err(Error::Shape);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct GenerationIntent {
    pub(crate) operation_id: String,
    pub(crate) vault_id: String,
    pub(crate) generation_id: String,
    pub(crate) record_id: String,
    pub(crate) identity_sha256: String,
    pub(crate) observation_revision: u32,
}
impl GenerationIntent {
    fn validate(&self) -> Result<()> {
        let id = |value: &str| Id::from_token(value).map_err(|_| Error::Shape);
        id(&self.operation_id)?;
        let identity = Identity::new(id(&self.vault_id)?, id(&self.generation_id)?).map_err(|_| Error::Shape)?;
        let record = id(&self.record_id)?;
        if record == identity.vault || record == identity.generation || !digest(&self.identity_sha256)
            || self.observation_revision == 0 { return Err(Error::Shape); }
        Ok(())
    }
    fn matches(&self, saved: &SavedAssignment) -> bool {
        self.operation_id == saved.operation_id && self.identity_sha256 == saved.identity_sha256
            && self.vault_id == saved.reference.vault_id && self.generation_id == saved.reference.generation_id
            && self.record_id == saved.reference.record_id && saved.reference.revision_counter == 1
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "value", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Preference {
    GenerationReserved(GenerationIntent),
    RecordSaved(SavedAssignment),
    Assigned(SavedAssignment),
}
impl Preference {
    pub(crate) fn saved(&self) -> Option<&SavedAssignment> {
        match self { Self::GenerationReserved(_) => None, Self::RecordSaved(value) | Self::Assigned(value) => Some(value) }
    }
    fn validate(&self) -> Result<()> {
        match self { Self::GenerationReserved(value) => value.validate(), Self::RecordSaved(value) | Self::Assigned(value) => value.validate() }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Slot { project: ProjectBinding, role: Role, preference: Preference }

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Journal {
    schema_version: u8,
    sequence: u32,
    slots: Vec<Slot>,
}
impl Journal {
    /// Only the shared original app-data initializer may establish empty DATA.
    /// A missing/unreadable previously-known namespace is NOT this constructor.
    pub(crate) fn initialize() -> Self { Self { schema_version: 1, sequence: 1, slots: Vec::new() } }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > JOURNAL_LIMIT { return Err(Error::Bounds); }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::Shape)?;
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| Error::Shape)?;
        if bytes.len() > JOURNAL_LIMIT { return Err(Error::Bounds); }
        Ok(bytes)
    }
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1 || self.sequence == 0 || self.slots.len() > SLOT_LIMIT { return Err(Error::Bounds); }
        for (index, slot) in self.slots.iter().enumerate() {
            slot.project.validate()?; slot.preference.validate()?;
            for earlier in &self.slots[..index] {
                if earlier.project.related(&slot.project)
                    && (earlier.project != slot.project || earlier.role == slot.role) { return Err(Error::Conflict); }
            }
        }
        Ok(())
    }
    pub(crate) fn sequence(&self) -> u32 { self.sequence }
    pub(crate) fn preference(&self, project: &ProjectBinding, role: Role) -> Result<Option<&Preference>> {
        self.validate()?; project.validate()?;
        if self.slots.iter().any(|slot| slot.project.related(project) && slot.project != *project) {
            return Err(Error::Conflict); // Explicit registry migration required.
        }
        Ok(self.slots.iter().find(|slot| slot.project == *project && slot.role == role).map(|slot| &slot.preference))
    }
    fn next(&self, expected: u32) -> Result<u32> {
        if expected != self.sequence { return Err(Error::Stale); }
        self.sequence.checked_add(1).ok_or(Error::Bounds)
    }
    /// Produces one state transition for the caller's atomic store CAS. The
    /// durable reservation must return successfully BEFORE native key creation.
    pub(crate) fn reserve(&mut self, expected: u32, project: &ProjectBinding, role: Role,
        intent: GenerationIntent, observation: &Observation<'_>) -> Result<()> {
        let sequence = self.next(expected)?;
        intent.validate()?;
        let Some(identity) = observation.vault_identity else { return Err(Error::Unavailable); };
        if observation.project != project || observation.role != role || observation.identity_sha256 != intent.identity_sha256
            || identity.vault.token() != intent.vault_id || identity.generation.token() != intent.generation_id
            || observation.revision != intent.observation_revision || classify(observation, self.preference(project, role)?)? != Plan::OfferGeneration {
            return Err(Error::Continuity);
        }
        if self.slots.len() >= SLOT_LIMIT { return Err(Error::Bounds); }
        if self.slots.iter().any(|slot| match &slot.preference {
            Preference::GenerationReserved(value) => value.operation_id == intent.operation_id || value.record_id == intent.record_id,
            Preference::RecordSaved(value) | Preference::Assigned(value) => value.operation_id == intent.operation_id || value.reference.record_id == intent.record_id,
        }) { return Err(Error::Conflict); }
        self.slots.push(Slot { project: project.clone(), role, preference: Preference::GenerationReserved(intent) });
        self.sequence = sequence;
        Ok(())
    }
    /// The native adapter invokes this ONLY after full original vault save
    /// durability/finality. A result-shaped helper response is insufficient.
    pub(crate) fn record_saved(&mut self, expected: u32, project: &ProjectBinding, role: Role,
        saved: SavedAssignment) -> Result<()> {
        let sequence = self.next(expected)?;
        saved.validate()?;
        match self.preference(project, role)? {
            Some(Preference::GenerationReserved(intent)) if intent.matches(&saved) => {},
            _ => return Err(Error::Conflict),
        }
        let slot = self.slots.iter_mut().find(|slot| slot.project == *project && slot.role == role).ok_or(Error::Conflict)?;
        slot.preference = Preference::RecordSaved(saved); self.sequence = sequence;
        Ok(())
    }
    /// Save a choice AFTER current original assessment+Bind. Reassignment is an
    /// explicit separately authorized operation; it never deletes the old key.
    pub(crate) fn assigned(&mut self, expected: u32, project: &ProjectBinding, role: Role,
        mut saved: SavedAssignment, observation: &Observation<'_>, reassign: bool) -> Result<()> {
        let sequence = self.next(expected)?;
        saved.validate()?;
        if observation.project != project || observation.role != role || observation.identity_sha256 != saved.identity_sha256
            || !observation.ready() || observation.expected_certificate_sha256.is_some_and(|expected| saved.certificate_sha256.as_deref().is_some_and(|actual| actual != expected))
            || !observation.records.iter().any(|record| *record.reference == saved.reference
                && record.current_assignment && record.assessment == Assessment::Current
                && record.certificate_sha256 == saved.certificate_sha256.as_deref()) { return Err(Error::Stale); }
        let previous = self.preference(project, role)?;
        match previous {
            Some(Preference::GenerationReserved(_)) => return Err(Error::RecoveryRequired),
            Some(Preference::RecordSaved(value) | Preference::Assigned(value))
                if (value.reference != saved.reference || value.identity_sha256 != saved.identity_sha256) && !reassign => return Err(Error::Conflict),
            _ => {},
        }
        if let Some(old) = previous.and_then(Preference::saved) {
            if old.reference == saved.reference && old.certificate_sha256.as_deref().is_some_and(|old| saved.certificate_sha256.as_deref().is_some_and(|new| new != old)) {
                // An immutable full record revision cannot change its signer.
                return Err(Error::Conflict);
            }
            if saved.certificate_sha256.is_none() {
                // Retain the previously reviewed signer CONSTRAINT, including
                // restoration into a new record. This is not a current native
                // fingerprint observation and classify must still require one.
                saved.certificate_sha256 = old.certificate_sha256.clone();
            }
        }
        if let Some(slot) = self.slots.iter_mut().find(|slot| slot.project == *project && slot.role == role) {
            slot.preference = Preference::Assigned(saved);
        } else {
            if self.slots.len() >= SLOT_LIMIT { return Err(Error::Bounds); }
            self.slots.push(Slot { project: project.clone(), role, preference: Preference::Assigned(saved) });
        }
        self.sequence = sequence;
        Ok(())
    }
}

fn digest(value: &str) -> bool { value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) }

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Storage { Unavailable, Locked, RecoveryRequired, Unlocked }
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Continuity { Unknown, ExistingApplication, NewApplicationConfirmed }
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Assessment { NotChecked, Current, Mismatch, Expired }
pub(crate) struct RecordObservation<'a> {
    pub(crate) reference: &'a KeyReference,
    pub(crate) certificate_sha256: Option<&'a str>,
    pub(crate) assessment: Assessment,
    pub(crate) current_assignment: bool,
    pub(crate) mutation_pending: bool,
}
pub(crate) struct Observation<'a> {
    pub(crate) project: &'a ProjectBinding,
    pub(crate) role: Role,
    pub(crate) revision: u32,
    pub(crate) identity_sha256: &'a str,
    pub(crate) expected_certificate_sha256: Option<&'a str>,
    pub(crate) storage: Storage,
    pub(crate) vault_identity: Option<Identity>,
    pub(crate) continuity: Continuity,
    pub(crate) operation_pending: bool,
    pub(crate) records: &'a [RecordObservation<'a>],
}
impl Observation<'_> {
    fn ready(&self) -> bool { self.storage == Storage::Unlocked && self.vault_identity.is_some() && !self.operation_pending && self.revision > 0 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Plan {
    Unavailable, UnlockStorage, RecoveryRequired, ReuseReady, AssessmentNeeded,
    SelectExisting, ExistingKeyRequired, Conflict, ConfirmApplicationHistory, OfferGeneration,
}

/// Redacted guidance only. No saved root, record ID, secret, capability or
/// purported native certificate observation can enter the UI/CLI projection.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SetupStatus {
    pub(crate) schema_version: u8,
    pub(crate) project_id: String,
    pub(crate) observation_revision: u32,
    pub(crate) role: Role,
    pub(crate) plan: Plan,
}
/// Native coordinator comparison DATA. Only `status` may be sent to the UI;
/// this does not restore an authorization or even select a credential.
pub(crate) struct SetupObservation {
    pub(crate) status: SetupStatus,
    pub(crate) preference_revision: u64,
}

pub(crate) fn classify(observation: &Observation<'_>, preference: Option<&Preference>) -> Result<Plan> {
    observation.project.validate()?;
    if observation.revision == 0 || !digest(observation.identity_sha256) || observation.records.len() > format_record_limit()
        || observation.expected_certificate_sha256.is_some_and(|value| !digest(value)) { return Err(Error::Shape); }
    if let Some(preference) = preference { preference.validate()?; }
    if matches!(preference, Some(Preference::GenerationReserved(_))) || observation.operation_pending
        || observation.storage == Storage::RecoveryRequired || observation.records.iter().any(|record| record.mutation_pending) {
        return Ok(Plan::RecoveryRequired);
    }
    match observation.storage {
        Storage::Unavailable => return Ok(Plan::Unavailable),
        Storage::Locked => return Ok(Plan::UnlockStorage),
        Storage::Unlocked => {},
        Storage::RecoveryRequired => return Ok(Plan::RecoveryRequired),
    }
    if observation.vault_identity.is_none() { return Ok(Plan::Unavailable); }
    for (index, record) in observation.records.iter().enumerate() {
        let (record_identity, _, _) = record.reference.parts()?;
        if observation.vault_identity != Some(record_identity) { return Err(Error::Stale); }
        if record.certificate_sha256.is_some_and(|value| !digest(value))
            || observation.records[..index].iter().any(|earlier| earlier.reference.record_id == record.reference.record_id) {
            return Err(Error::Shape);
        }
    }
    let preferred = preference.and_then(Preference::saved);
    if let Some(preferred) = preferred {
        if preferred.identity_sha256 != observation.identity_sha256 { return Ok(Plan::Conflict); }
        let Some(record) = observation.records.iter().find(|record| *record.reference == preferred.reference) else {
            return Ok(Plan::ExistingKeyRequired);
        };
        if record.assessment == Assessment::Mismatch || record.assessment == Assessment::Expired
            || observation.expected_certificate_sha256.is_some_and(|expected| record.certificate_sha256.is_some_and(|actual| expected != actual))
            || preferred.certificate_sha256.as_deref().is_some_and(|expected| record.certificate_sha256.is_some_and(|actual| expected != actual)) {
            return Ok(Plan::Conflict);
        }
        let fingerprint_observed = observation.expected_certificate_sha256.is_none_or(|expected| record.certificate_sha256 == Some(expected))
            && preferred.certificate_sha256.as_deref().is_none_or(|expected| record.certificate_sha256 == Some(expected));
        return Ok(if record.assessment == Assessment::Current && record.current_assignment && fingerprint_observed { Plan::ReuseReady } else { Plan::AssessmentNeeded });
    }
    if observation.records.iter().any(|record| record.current_assignment && record.assessment == Assessment::Current
        && observation.expected_certificate_sha256.is_none_or(|expected| record.certificate_sha256 == Some(expected))) {
        return Ok(Plan::ReuseReady);
    }
    if !observation.records.is_empty() { return Ok(Plan::SelectExisting); }
    if observation.expected_certificate_sha256.is_some() || observation.continuity == Continuity::ExistingApplication {
        return Ok(Plan::ExistingKeyRequired);
    }
    if observation.continuity != Continuity::NewApplicationConfirmed { return Ok(Plan::ConfirmApplicationHistory); }
    Ok(Plan::OfferGeneration)
}
fn format_record_limit() -> usize { crate::vault_format::DESCRIPTOR_COUNT }

#[cfg(test)]
mod tests {
    use super::*;
    fn project() -> ProjectBinding { ProjectBinding { project_id: "11".repeat(16), canonical_root: "/synthetic/project".into(), device: 7, inode: 8 } }
    fn key() -> KeyReference { KeyReference { vault_id: "22".repeat(16), generation_id: "33".repeat(16), record_id: "44".repeat(16), revision_id: "55".repeat(16), revision_counter: 1 } }
    fn saved() -> SavedAssignment { SavedAssignment { reference: key(), identity_sha256: "66".repeat(32), certificate_sha256: Some("77".repeat(32)), operation_id: "88".repeat(16) } }
    fn intent() -> GenerationIntent { GenerationIntent { operation_id: saved().operation_id, vault_id: key().vault_id, generation_id: key().generation_id,
        record_id: key().record_id, identity_sha256: saved().identity_sha256, observation_revision: 1 } }
    fn observation<'a>(project: &'a ProjectBinding, records: &'a [RecordObservation<'a>]) -> Observation<'a> {
        Observation { project, role: Role::AndroidUpload, revision: 1, identity_sha256: "6666666666666666666666666666666666666666666666666666666666666666",
            expected_certificate_sha256: None, storage: Storage::Unlocked, vault_identity: Some(key().parts().unwrap().0),
            continuity: Continuity::NewApplicationConfirmed, operation_pending: false, records }
    }
    #[test]
    fn existing_or_unknown_history_never_offers_automatic_generation() {
        let project = project(); let mut observed = observation(&project, &[]);
        assert_eq!(classify(&observed, None).unwrap(), Plan::OfferGeneration);
        observed.continuity = Continuity::Unknown;
        assert_eq!(classify(&observed, None).unwrap(), Plan::ConfirmApplicationHistory);
        observed.continuity = Continuity::ExistingApplication;
        assert_eq!(classify(&observed, None).unwrap(), Plan::ExistingKeyRequired);
        observed.continuity = Continuity::NewApplicationConfirmed;
        observed.expected_certificate_sha256 = Some("7777777777777777777777777777777777777777777777777777777777777777");
        assert_eq!(classify(&observed, None).unwrap(), Plan::ExistingKeyRequired);
    }
    #[test]
    fn durable_reservation_prevents_rerun_even_without_material_or_assignment() {
        let project = project(); let observed = observation(&project, &[]);
        let mut journal = Journal::initialize();
        journal.reserve(1, &project, Role::AndroidUpload, intent(), &observed).unwrap();
        let persisted = journal.encode().unwrap(); let mut restarted = Journal::decode(&persisted).unwrap();
        assert_eq!(classify(&observed, restarted.preference(&project, Role::AndroidUpload).unwrap()).unwrap(), Plan::RecoveryRequired);
        assert!(restarted.reserve(2, &project, Role::AndroidUpload, intent(), &observed).is_err());
        restarted.record_saved(2, &project, Role::AndroidUpload, saved()).unwrap();
        let reopened = Journal::decode(&restarted.encode().unwrap()).unwrap();
        assert_eq!(classify(&observed, reopened.preference(&project, Role::AndroidUpload).unwrap()).unwrap(), Plan::ExistingKeyRequired);
    }
    #[test]
    fn saved_preference_never_restores_old_bind_or_accepts_random_revision_alias() {
        let project = project(); let reference = key(); let preference = Preference::Assigned(saved());
        let records = [RecordObservation { reference: &reference, certificate_sha256: None, assessment: Assessment::NotChecked, current_assignment: false, mutation_pending: false }];
        assert_eq!(classify(&observation(&project, &records), Some(&preference)).unwrap(), Plan::AssessmentNeeded);
        for changed in 0..3 {
            let mut changed_key = key();
            match changed { 0 => changed_key.vault_id = "99".repeat(16), 1 => changed_key.generation_id = "99".repeat(16), _ => changed_key.revision_id = "99".repeat(16) }
            let records = [RecordObservation { reference: &changed_key, certificate_sha256: None, assessment: Assessment::NotChecked, current_assignment: false, mutation_pending: false }];
            let found = classify(&observation(&project, &records), Some(&preference));
            assert!(found == Ok(Plan::ExistingKeyRequired) || found == Err(Error::Stale));
        }
    }
    #[test]
    fn reassign_needs_explicit_choice_and_current_native_bind() {
        let project = project(); let reference = key(); let saved = saved();
        let records = [RecordObservation { reference: &reference, certificate_sha256: saved.certificate_sha256.as_deref(), assessment: Assessment::Current, current_assignment: true, mutation_pending: false }];
        let mut journal = Journal::initialize();
        journal.assigned(1, &project, Role::AndroidUpload, saved.clone(), &observation(&project, &records), false).unwrap();
        let mut second = saved.clone(); second.reference.record_id = "aa".repeat(16);
        let second_key = second.reference.clone();
        let records = [RecordObservation { reference: &second_key, certificate_sha256: saved.certificate_sha256.as_deref(), assessment: Assessment::Current, current_assignment: true, mutation_pending: false }];
        assert!(journal.assigned(2, &project, Role::AndroidUpload, second.clone(), &observation(&project, &records), false).is_err());
        journal.assigned(2, &project, Role::AndroidUpload, second, &observation(&project, &records), true).unwrap();
        let reopened = Journal::decode(&journal.encode().unwrap()).unwrap();
        assert_eq!(reopened.sequence(), 3);
        assert!(reopened.preference(&project, Role::AndroidUpload).unwrap().unwrap().saved().unwrap().reference == second_key);
    }
    #[test]
    fn path_replacement_relocation_and_reused_project_id_require_explicit_migration() {
        let project = project(); let observed = observation(&project, &[]); let mut journal = Journal::initialize();
        journal.reserve(1, &project, Role::AndroidUpload, intent(), &observed).unwrap();
        for change in 0..4 {
            let mut changed = project.clone();
            match change { 0 => changed.inode += 1, 1 => changed.canonical_root = "/synthetic/moved".into(),
                2 => changed.project_id = "aa".repeat(16), _ => { changed.project_id = "aa".repeat(16); changed.canonical_root = "/synthetic/moved".into(); } }
            assert!(matches!(journal.preference(&changed, Role::AndroidUpload), Err(Error::Conflict)));
        }
    }
    #[test]
    fn malformed_duplicate_stale_and_pending_state_cannot_become_empty_setup() {
        for input in [b"".as_slice(), b"{}", br#"{"schemaVersion":1,"schemaVersion":1,"sequence":1,"slots":[]}"#,
            br#"{"schemaVersion":1,"sequence":1,"slots":[],"secret":"not-accepted"}"#] { assert!(Journal::decode(input).is_err()); }
        let project = project(); let mut observed = observation(&project, &[]); let mut journal = Journal::initialize();
        assert!(matches!(journal.reserve(2, &project, Role::AndroidUpload, intent(), &observed), Err(Error::Stale)));
        observed.operation_pending = true;
        assert_eq!(classify(&observed, None).unwrap(), Plan::RecoveryRequired);
        assert!(journal.reserve(1, &project, Role::AndroidUpload, intent(), &observed).is_err());
    }
    #[test]
    fn full_reference_matches_native_random_identity_separation() {
        let original = key();
        for alias in [&original.vault_id, &original.generation_id, &original.record_id] {
            let mut invalid = original.clone(); invalid.revision_id = alias.clone();
            assert!(matches!(invalid.validate(), Err(Error::Shape)));
        }
    }
    #[test]
    fn remembering_a_choice_does_not_invent_its_expected_certificate_observation() {
        let project = project(); let reference = key(); let mut saved = saved(); saved.certificate_sha256 = None;
        let records = [RecordObservation { reference: &reference, certificate_sha256: None, assessment: Assessment::Current,
            current_assignment: true, mutation_pending: false }];
        let mut observed = observation(&project, &records);
        observed.expected_certificate_sha256 = Some("7777777777777777777777777777777777777777777777777777777777777777");
        let mut journal = Journal::initialize();
        journal.assigned(1, &project, Role::AndroidUpload, saved, &observed, false).unwrap();
        assert_eq!(classify(&observed, journal.preference(&project, Role::AndroidUpload).unwrap()).unwrap(), Plan::AssessmentNeeded);
    }
    #[test]
    fn format_only_rebinding_cannot_erase_a_previously_reviewed_signer_constraint() {
        let project = project(); let reference = key(); let reviewed = saved();
        let records = [RecordObservation { reference: &reference, certificate_sha256: reviewed.certificate_sha256.as_deref(),
            assessment: Assessment::Current, current_assignment: true, mutation_pending: false }];
        let mut journal = Journal::initialize();
        journal.assigned(1, &project, Role::AndroidUpload, reviewed.clone(), &observation(&project, &records), false).unwrap();
        let mut unknown = reviewed.clone(); unknown.certificate_sha256 = None;
        let records = [RecordObservation { reference: &reference, certificate_sha256: None,
            assessment: Assessment::Current, current_assignment: true, mutation_pending: false }];
        journal.assigned(2, &project, Role::AndroidUpload, unknown, &observation(&project, &records), false).unwrap();
        let preferred = journal.preference(&project, Role::AndroidUpload).unwrap().unwrap();
        assert_eq!(preferred.saved().unwrap().certificate_sha256, reviewed.certificate_sha256);
        assert_eq!(classify(&observation(&project, &records), Some(preferred)).unwrap(), Plan::AssessmentNeeded);
        let mut retarget = reviewed.clone(); retarget.identity_sha256 = "bb".repeat(32); retarget.certificate_sha256 = None;
        let mut changed = observation(&project, &records); changed.identity_sha256 = &retarget.identity_sha256;
        assert!(matches!(journal.assigned(3, &project, Role::AndroidUpload, retarget.clone(), &changed, false), Err(Error::Conflict)));
    }
}
