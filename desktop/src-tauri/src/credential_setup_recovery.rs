//! Bounded recovery transitions in the existing reference journal.
//!
//! These are comparison DATA, not native no-GO/Bind receipts. Only the fixed
//! native originals may call the corresponding storage adapters. In particular
//! an absent record never creates StoppedNoGo, and reconciliation never claims
//! that the old key-generation operation succeeded.
use super::*;

pub(crate) const CANCELLED_LIMIT: usize = 128;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct CancelledGeneration {
    project: ProjectBinding,
    role: Role,
    intent: GenerationIntent,
}

// If the field is present it must be an array, not null. This distinguishes
// strict old schema1 (field absent) from an explicit schema2 empty history.
pub(super) fn history<'de, D: serde::Deserializer<'de>>(
    value: D,
) -> std::result::Result<Option<Vec<CancelledGeneration>>, D::Error> {
    let history = Vec::<CancelledGeneration>::deserialize(value)?;
    if history.len() > CANCELLED_LIMIT {
        return Err(serde::de::Error::custom("credential history bound"));
    }
    Ok(Some(history))
}

fn ids(preference: &Preference) -> (&str, &str) {
    match preference {
        Preference::GenerationReserved(v) | Preference::GenerationStoppedNoGo(v) => {
            (&v.operation_id, &v.record_id)
        }
        Preference::RecordSaved(v) | Preference::Assigned(v) => {
            (&v.operation_id, &v.reference.record_id)
        }
    }
}

impl Journal {
    /// V1 is read without migration or inferred cancellation. V2 explicitly
    /// carries the bounded history; malformed versions never become empty.
    pub(super) fn validate_recovery(&self) -> Result<()> {
        let history = match (self.schema_version, &self.cancelled_generations) {
            (1, None)
                if !self.slots.iter().any(|slot| {
                    matches!(slot.preference, Preference::GenerationStoppedNoGo(_))
                }) =>
            {
                &[][..]
            }
            (2, Some(history)) if history.len() <= CANCELLED_LIMIT => history.as_slice(),
            _ => return Err(Error::Shape),
        };
        for (index, slot) in self.slots.iter().enumerate() {
            if matches!(slot.preference, Preference::GenerationStoppedNoGo(_))
                && slot.role != Role::AndroidUpload
            {
                return Err(Error::Shape);
            }
            let (operation, record) = ids(&slot.preference);
            for earlier in &self.slots[..index] {
                let (old_operation, old_record) = ids(&earlier.preference);
                // Existing explicit multi-project reuse of the same assigned
                // key is legitimate. It is not another generation attempt.
                let shared_assignment = matches!((&slot.preference, &earlier.preference),
                    (Preference::Assigned(a), Preference::Assigned(b) | Preference::RecordSaved(b))
                    | (Preference::RecordSaved(a), Preference::Assigned(b)) if a.reference == b.reference);
                if operation == old_operation && !shared_assignment
                    || record == old_record && !shared_assignment
                {
                    return Err(Error::Conflict);
                }
            }
        }
        for (index, cancelled) in history.iter().enumerate() {
            cancelled.project.validate()?;
            cancelled.intent.validate()?;
            if cancelled.role != Role::AndroidUpload {
                return Err(Error::Shape);
            }
            for slot in &self.slots {
                if cancelled.project.related(&slot.project) && cancelled.project != slot.project {
                    return Err(Error::Conflict);
                }
                let (operation, record) = ids(&slot.preference);
                if operation == cancelled.intent.operation_id
                    || record == cancelled.intent.record_id
                {
                    return Err(Error::Conflict);
                }
            }
            for earlier in &history[..index] {
                if cancelled.project.related(&earlier.project)
                    && cancelled.project != earlier.project
                    || cancelled.intent.operation_id == earlier.intent.operation_id
                    || cancelled.intent.record_id == earlier.intent.record_id
                {
                    return Err(Error::Conflict);
                }
            }
        }
        Ok(())
    }

    pub(super) fn recovery_project_current(&self, project: &ProjectBinding) -> Result<()> {
        if self.cancelled_generations.as_ref().is_some_and(|history| {
            history
                .iter()
                .any(|entry| entry.project.related(project) && entry.project != *project)
        }) {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    pub(super) fn reserved_id_was_cancelled(&self, intent: &GenerationIntent) -> bool {
        self.cancelled_generations.as_ref().is_some_and(|history| {
            history.iter().any(|entry| {
                entry.intent.operation_id == intent.operation_id
                    || entry.intent.record_id == intent.record_id
            })
        })
    }

    /// Called only after the original cancellation proof actually disposed its
    /// private native book and all original joins. This adds no use permission.
    pub(crate) fn stopped_no_go(
        &mut self,
        expected: u32,
        project: &ProjectBinding,
        intent: &GenerationIntent,
    ) -> Result<()> {
        let sequence = self.next(expected)?;
        intent.validate()?;
        if self.preference(project, Role::AndroidUpload)?
            != Some(&Preference::GenerationReserved(intent.clone()))
        {
            return Err(Error::Conflict);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.project == *project && slot.role == Role::AndroidUpload)
            .ok_or(Error::Conflict)?;
        slot.preference = Preference::GenerationStoppedNoGo(intent.clone());
        if self.cancelled_generations.is_none() {
            self.cancelled_generations = Some(Vec::new());
        }
        self.schema_version = 2;
        self.sequence = sequence;
        Ok(())
    }

    /// Explicit user acknowledgement archives, never discards, the old intent.
    /// It creates no key and supplies no new-application declaration. A later
    /// reserve still repeats the ordinary reuse-first/native observation gate.
    pub(crate) fn acknowledge_unstarted(
        &mut self,
        expected: u32,
        project: &ProjectBinding,
        observed: &Observation<'_>,
    ) -> Result<()> {
        let sequence = self.next(expected)?;
        let _ = classify(observed, None)?; // Validate complete native comparison shape, not authority.
        let Some(Preference::GenerationStoppedNoGo(intent)) =
            self.preference(project, Role::AndroidUpload)?
        else {
            return Err(Error::RecoveryRequired);
        };
        if observed.project != project
            || observed.role != Role::AndroidUpload
            || !observed.ready()
            || observed.identity_sha256 != intent.identity_sha256
            || observed.vault_identity.is_none_or(|identity| {
                identity.vault.token() != intent.vault_id
                    || identity.generation.token() != intent.generation_id
            })
            || observed
                .records
                .iter()
                .any(|row| row.mutation_pending || row.reference.record_id == intent.record_id)
        {
            return Err(Error::Stale);
        }
        let entry = CancelledGeneration {
            project: project.clone(),
            role: Role::AndroidUpload,
            intent: intent.clone(),
        };
        let history = self.cancelled_generations.as_mut().ok_or(Error::Shape)?;
        if history.len() >= CANCELLED_LIMIT {
            return Err(Error::Bounds);
        }
        history.try_reserve(1).map_err(|_| Error::Bounds)?;
        history.push(entry);
        self.slots
            .retain(|slot| slot.project != *project || slot.role != Role::AndroidUpload);
        self.sequence = sequence;
        Ok(())
    }

    /// Explicit current Bind reconciliation, not `record_saved` and not a
    /// retrospective native-generation success receipt. The caller already
    /// owns the original authenticated payload and full physical read witness.
    pub(crate) fn reconcile_bound(
        &mut self,
        expected: u32,
        project: &ProjectBinding,
        mut assigned: SavedAssignment,
        observed: &Observation<'_>,
    ) -> Result<()> {
        let sequence = self.next(expected)?;
        assigned.validate()?;
        let _ = classify(observed, None)?;
        if observed.project != project
            || observed.role != Role::AndroidUpload
            || !observed.ready()
            || observed.identity_sha256 != assigned.identity_sha256
            || !observed.records.iter().any(|record| {
                record.reference == &assigned.reference
                    && record.current_assignment
                    && record.assessment == Assessment::Current
                    && !record.mutation_pending
                    && record.certificate_sha256 == assigned.certificate_sha256.as_deref()
            })
            || observed
                .expected_certificate_sha256
                .is_some_and(|expected| {
                    assigned
                        .certificate_sha256
                        .as_deref()
                        .is_some_and(|actual| actual != expected)
                })
        {
            return Err(Error::Stale);
        }
        match self.preference(project, Role::AndroidUpload)? {
            Some(Preference::GenerationReserved(intent)) if intent.matches(&assigned) => {}
            Some(Preference::RecordSaved(old) | Preference::Assigned(old))
                if old.reference == assigned.reference
                    && old.identity_sha256 == assigned.identity_sha256
                    && old.operation_id == assigned.operation_id =>
            {
                if old.certificate_sha256.as_deref().is_some_and(|old| {
                    assigned
                        .certificate_sha256
                        .as_deref()
                        .is_some_and(|new| old != new)
                }) {
                    return Err(Error::Conflict);
                }
                if assigned.certificate_sha256.is_none() {
                    assigned.certificate_sha256 = old.certificate_sha256.clone();
                }
            }
            _ => return Err(Error::Conflict),
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.project == *project && slot.role == Role::AndroidUpload)
            .ok_or(Error::Conflict)?;
        slot.preference = Preference::Assigned(assigned);
        self.sequence = sequence;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn saved() -> SavedAssignment {
        SavedAssignment {
            reference: key(),
            identity_sha256: "66".repeat(32),
            certificate_sha256: None,
            operation_id: "77".repeat(16),
        }
    }
    fn intent() -> GenerationIntent {
        GenerationIntent {
            operation_id: saved().operation_id,
            vault_id: key().vault_id,
            generation_id: key().generation_id,
            record_id: key().record_id,
            identity_sha256: saved().identity_sha256,
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
    fn reserved() -> Journal {
        let mut journal = Journal::initialize();
        journal
            .reserve(
                1,
                &project(),
                Role::AndroidUpload,
                intent(),
                &observation(&project(), &[]),
            )
            .unwrap();
        journal
    }

    #[test]
    fn legacy_absence_cannot_create_no_go_or_acknowledge_it() {
        let mut journal = reserved();
        let bytes = journal.encode().unwrap();
        let mut restarted = Journal::decode(&bytes).unwrap();
        assert_eq!(
            restarted.acknowledge_unstarted(2, &project(), &observation(&project(), &[])),
            Err(Error::RecoveryRequired)
        );
        assert_eq!(restarted.encode().unwrap(), bytes);
        assert_eq!(
            classify(
                &observation(&project(), &[]),
                journal.preference(&project(), Role::AndroidUpload).unwrap()
            )
            .unwrap(),
            Plan::RecoveryRequired
        );
        journal.stopped_no_go(2, &project(), &intent()).unwrap();
        let mut wire: serde_json::Value =
            serde_json::from_slice(&journal.encode().unwrap()).unwrap();
        wire["schemaVersion"] = 1.into();
        wire.as_object_mut().unwrap().remove("cancelledGenerations");
        assert!(Journal::decode(&serde_json::to_vec(&wire).unwrap()).is_err());
    }
    #[test]
    fn no_go_restart_requires_ack_and_a_distinct_fresh_explicit_reservation() {
        let project = project();
        let observed = observation(&project, &[]);
        let mut journal = reserved();
        journal.stopped_no_go(2, &project, &intent()).unwrap();
        let mut journal = Journal::decode(&journal.encode().unwrap()).unwrap();
        assert_eq!(
            classify(
                &observed,
                journal.preference(&project, Role::AndroidUpload).unwrap()
            )
            .unwrap(),
            Plan::RecoveryRequired
        );
        journal
            .acknowledge_unstarted(3, &project, &observed)
            .unwrap();
        let mut journal = Journal::decode(&journal.encode().unwrap()).unwrap();
        assert_eq!(journal.cancelled_generations.as_ref().unwrap().len(), 1);
        assert!(journal
            .reserve(4, &project, Role::AndroidUpload, intent(), &observed)
            .is_err());
        let mut fresh = intent();
        fresh.operation_id = "88".repeat(16);
        fresh.record_id = "99".repeat(16);
        let mut no_declaration = observation(&project, &[]);
        no_declaration.continuity = Continuity::Unknown;
        assert!(journal
            .reserve(
                4,
                &project,
                Role::AndroidUpload,
                fresh.clone(),
                &no_declaration
            )
            .is_err());
        journal
            .reserve(4, &project, Role::AndroidUpload, fresh, &observed)
            .unwrap();
        assert!(journal.cancelled_generations.as_ref().unwrap()[0].intent == intent());
    }
    #[test]
    fn no_go_ack_refuses_stale_identity_present_key_and_pending_work() {
        let project = project();
        let mut journal = reserved();
        journal.stopped_no_go(2, &project, &intent()).unwrap();
        let original = journal.encode().unwrap();
        let key = key();
        let rows = [RecordObservation {
            reference: &key,
            certificate_sha256: None,
            assessment: Assessment::NotChecked,
            current_assignment: false,
            mutation_pending: false,
        }];
        assert!(journal
            .acknowledge_unstarted(3, &project, &observation(&project, &rows))
            .is_err());
        let mut observed = observation(&project, &[]);
        observed.operation_pending = true;
        assert!(journal
            .acknowledge_unstarted(3, &project, &observed)
            .is_err());
        observed.operation_pending = false;
        observed.vault_identity = None;
        assert!(journal
            .acknowledge_unstarted(3, &project, &observed)
            .is_err());
        assert!(journal
            .acknowledge_unstarted(2, &project, &observation(&project, &[]))
            .is_err());
        assert_eq!(journal.encode().unwrap(), original);
    }
    #[test]
    fn history_decode_alias_and_related_root_changes_refuse_without_eviction() {
        let project = project();
        let mut journal = reserved();
        journal.stopped_no_go(2, &project, &intent()).unwrap();
        journal
            .acknowledge_unstarted(3, &project, &observation(&project, &[]))
            .unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&journal.encode().unwrap()).unwrap();
        let duplicate = value["cancelledGenerations"][0].clone();
        value["cancelledGenerations"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert!(Journal::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut moved = project.clone();
        moved.canonical_root = "/synthetic/moved".into();
        assert!(journal.preference(&moved, Role::AndroidUpload).is_err());
        let historical = journal.cancelled_generations.as_ref().unwrap()[0].clone();
        journal
            .cancelled_generations
            .as_mut()
            .unwrap()
            .resize(CANCELLED_LIMIT + 1, historical);
        assert!(journal.encode().is_err());
    }
    #[test]
    fn exact_history_capacity_has_no_eviction_or_generation_id_reuse() {
        let project = project();
        let observed = observation(&project, &[]);
        let mut journal = Journal::initialize();
        for index in 0..CANCELLED_LIMIT {
            let mut next = intent();
            next.operation_id = format!("{:032x}", 1000 + index);
            next.record_id = format!("{:032x}", 2000 + index);
            journal
                .reserve(
                    journal.sequence(),
                    &project,
                    Role::AndroidUpload,
                    next.clone(),
                    &observed,
                )
                .unwrap();
            journal
                .stopped_no_go(journal.sequence(), &project, &next)
                .unwrap();
            journal
                .acknowledge_unstarted(journal.sequence(), &project, &observed)
                .unwrap();
        }
        let mut journal = Journal::decode(&journal.encode().unwrap()).unwrap();
        let mut next = intent();
        next.operation_id = format!("{:032x}", 9999);
        next.record_id = format!("{:032x}", 9998);
        journal
            .reserve(
                journal.sequence(),
                &project,
                Role::AndroidUpload,
                next.clone(),
                &observed,
            )
            .unwrap();
        journal
            .stopped_no_go(journal.sequence(), &project, &next)
            .unwrap();
        let before = journal.encode().unwrap();
        assert_eq!(
            journal.acknowledge_unstarted(journal.sequence(), &project, &observed),
            Err(Error::Bounds)
        );
        assert_eq!(journal.encode().unwrap(), before);
        assert_eq!(
            journal.cancelled_generations.as_ref().unwrap().len(),
            CANCELLED_LIMIT
        );
        let mut legacy: serde_json::Value =
            serde_json::from_slice(&Journal::initialize().encode().unwrap()).unwrap();
        legacy["cancelledGenerations"] = serde_json::Value::Null;
        assert!(Journal::decode(&serde_json::to_vec(&legacy).unwrap()).is_err());
    }
    #[test]
    fn legitimate_multiple_project_assignments_keep_the_same_original_key() {
        let project = project();
        let key = key();
        let rows = [RecordObservation {
            reference: &key,
            certificate_sha256: None,
            assessment: Assessment::Current,
            current_assignment: true,
            mutation_pending: false,
        }];
        let mut journal = Journal::initialize();
        journal
            .assigned(
                1,
                &project,
                Role::AndroidUpload,
                saved(),
                &observation(&project, &rows),
                false,
            )
            .unwrap();
        let mut other = project.clone();
        other.project_id = "cc".repeat(16);
        other.canonical_root = "/synthetic/other".into();
        other.inode = 88;
        journal
            .assigned(
                2,
                &other,
                Role::AndroidUpload,
                saved(),
                &observation(&other, &rows),
                false,
            )
            .unwrap();
        let restarted = Journal::decode(&journal.encode().unwrap()).unwrap();
        assert!(restarted
            .preference(&project, Role::AndroidUpload)
            .unwrap()
            .is_some());
        assert!(restarted
            .preference(&other, Role::AndroidUpload)
            .unwrap()
            .is_some());
        assert_eq!(restarted.schema_version, 1); // No gratuitous legacy migration.
    }
    #[test]
    fn bound_reconciliation_is_not_generation_success_or_restored_assessment() {
        let project = project();
        let key = key();
        let mut journal = reserved();
        let mut rows = [RecordObservation {
            reference: &key,
            certificate_sha256: None,
            assessment: Assessment::Current,
            current_assignment: false,
            mutation_pending: false,
        }];
        assert!(journal
            .reconcile_bound(2, &project, saved(), &observation(&project, &rows))
            .is_err());
        rows[0].current_assignment = true;
        journal
            .reconcile_bound(2, &project, saved(), &observation(&project, &rows))
            .unwrap();
        assert!(matches!(
            journal.preference(&project, Role::AndroidUpload).unwrap(),
            Some(Preference::Assigned(_))
        ));
        rows[0].current_assignment = false;
        rows[0].assessment = Assessment::NotChecked;
        assert_eq!(
            classify(
                &observation(&project, &rows),
                journal.preference(&project, Role::AndroidUpload).unwrap()
            )
            .unwrap(),
            Plan::AssessmentNeeded
        );
    }
    #[test]
    fn full_revision_and_signer_constraint_are_not_lost_or_invented() {
        let project = project();
        let key = key();
        let rows = [RecordObservation {
            reference: &key,
            certificate_sha256: None,
            assessment: Assessment::Current,
            current_assignment: true,
            mutation_pending: false,
        }];
        let mut journal = reserved();
        let mut known = saved();
        known.certificate_sha256 = Some("aa".repeat(32));
        journal
            .record_saved(2, &project, Role::AndroidUpload, known.clone())
            .unwrap();
        let mut alias = saved();
        alias.reference.revision_id = "bb".repeat(16);
        assert!(journal
            .reconcile_bound(3, &project, alias, &observation(&project, &rows))
            .is_err());
        journal
            .reconcile_bound(3, &project, saved(), &observation(&project, &rows))
            .unwrap();
        assert_eq!(
            journal
                .preference(&project, Role::AndroidUpload)
                .unwrap()
                .unwrap()
                .saved()
                .unwrap()
                .certificate_sha256,
            known.certificate_sha256
        );
        assert_eq!(
            classify(
                &observation(&project, &rows),
                journal.preference(&project, Role::AndroidUpload).unwrap()
            )
            .unwrap(),
            Plan::AssessmentNeeded
        );
    }
}
