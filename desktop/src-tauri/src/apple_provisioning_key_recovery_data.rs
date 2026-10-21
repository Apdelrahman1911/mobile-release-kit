//! Immutable local verification history in the SAME bounded Apple journal.
//! This record does not finish an old NativeUse or relabel an old Pending row.
//! Every consumer still needs its own real native use and fresh selected loan.
use super::*;
use crate::credential_setup::KeyReference;

pub(crate) const KEY_RECOVERY_PROTOCOL: &str = "mrk-apple-provisioning-journal/5";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KeyRecoveryOrigin {
    pub(crate) operation_id: Id,
    pub(crate) owner_generation: Id,
    pub(crate) row_sha256: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KeyRecoveryRecord {
    pub(crate) context: ProvisioningContext,
    pub(crate) provenance: NativeProvenance,
    pub(crate) target: ProfileTarget,
    pub(crate) source_p8: KeyReference,
    pub(crate) source_key: KeyReference,
    pub(crate) original: KeyRecoveryOrigin,
    pub(crate) output: KeyOutputMetadata,
}

/// DATA eligibility, not a source/retirement witness. Unknown and an absent
/// vault record are deliberately not converted into a generation opportunity.
pub(crate) fn durable_key_row(row: &KeyPrepareRow) -> bool {
    row.validate().is_ok()
        && matches!(
            row.native_settlement,
            NativeSettlement::Pending | NativeSettlement::Known
        )
        && row.update.generation == KeyGeneration::Returned
        && row.update.save == ProfileSaveState::ReadBack
        && row.update.saved_reference.as_ref() == Some(&row.intent.destination)
        && matches!(
            row.update.disposition,
            KeyDisposition::Prepared | KeyDisposition::Cancelled | KeyDisposition::Failed
        )
        && row
            .update
            .output
            .as_ref()
            .is_some_and(KeyOutputMetadata::valid)
}

pub(crate) fn key_row_sha256(row: &KeyPrepareRow) -> Result<String> {
    row.validate()?;
    hash(row)
}

impl KeyRecoveryRecord {
    pub(crate) fn sha256(&self) -> Result<String> {
        hash(self)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        need(
            self.context.valid()
                && self.provenance.valid()
                && self.target.valid()
                && self.context.operation_id == self.provenance.operation_id.as_str()
                && self.original.operation_id != self.provenance.operation_id
                && sha(&self.original.row_sha256)
                && self.source_key.validate().is_ok()
                && self.source_p8.validate().is_ok()
                && self.source_p8.record_id == self.context.credential_record_id
                && self.source_p8.revision_counter == self.context.credential_revision
                && self.source_p8.vault_id == self.source_key.vault_id
                && self.source_p8.generation_id == self.source_key.generation_id
                && self.source_p8.record_id != self.source_key.record_id
                && self.output.valid(),
        )?;
        canonical(self, ROW_LIMIT).map(|_| ())
    }

    pub(crate) fn matches_row(&self, row: &KeyPrepareRow) -> Result<()> {
        self.validate()?;
        need(
            durable_key_row(row)
                && row.native_settlement == NativeSettlement::Pending
                && self.original.operation_id == row.intent.provenance.operation_id
                && self.original.owner_generation == row.intent.provenance.owner_generation
                && self.original.row_sha256 == key_row_sha256(row)?
                && self.context.account_ref == row.intent.context.account_ref
                && self.provenance.project_binding == row.intent.provenance.project_binding
                && self.provenance.registered_root == row.intent.provenance.registered_root
                && self.target == row.intent.target
                && self.source_key == row.intent.destination
                && row.update.saved_reference.as_ref() == Some(&self.source_key)
                && row.update.output.as_ref() == Some(&self.output),
        )
    }
}

/// Full native relation validation precedes INITIAL or policy projection.
/// Even an otherwise well-shaped duplicate/foreign association is a refusal.
pub(crate) fn validate_key_recoveries(
    records: &[KeyRecoveryRecord],
    rows: &[KeyPrepareRow],
) -> Result<()> {
    need(records.len() <= ROWS && rows.len() <= ROWS)?;
    let mut originals = std::collections::BTreeSet::new();
    for record in records {
        record.validate()?;
        need(originals.insert(record.original.operation_id.as_str()))?;
        let mut matching = rows
            .iter()
            .filter(|row| row.intent.provenance.operation_id == record.original.operation_id);
        let row = matching
            .next()
            .ok_or_else(|| StateError::from(Error::InvalidRequest))?;
        need(matching.next().is_none())?;
        record.matches_row(row)?;
    }
    Ok(())
}

pub(crate) fn key_recovery_for<'a>(
    records: &'a [KeyRecoveryRecord],
    row: &KeyPrepareRow,
) -> Result<Option<&'a KeyRecoveryRecord>> {
    let mut matching = records
        .iter()
        .filter(|record| record.original.operation_id == row.intent.provenance.operation_id);
    let result = matching.next();
    need(matching.next().is_none())?;
    if let Some(record) = result {
        record.matches_row(row)?;
    }
    Ok(result)
}

#[cfg(test)]
pub(in crate::apple_provisioning_journal) mod tests {
    use super::*;

    pub(crate) fn old_row() -> KeyPrepareRow {
        let intent = key::tests::intent();
        let mut update = key::tests::returned();
        update.sequence += 1;
        update.save = ProfileSaveState::ReadBack;
        update.saved_reference = Some(intent.destination.clone());
        update.disposition = KeyDisposition::Prepared;
        let row = KeyPrepareRow {
            intent,
            generator_armed: true,
            update,
            native_settlement: NativeSettlement::Pending,
        };
        row.validate().unwrap();
        row
    }
    pub(crate) fn record(row: &KeyPrepareRow) -> KeyRecoveryRecord {
        let mut context = row.intent.context.clone();
        context.operation_id = "9".repeat(32);
        let mut provenance = row.intent.provenance.clone();
        provenance.operation_id = Id::parse(&context.operation_id).unwrap();
        provenance.owner_generation = Id::parse(&"8".repeat(32)).unwrap();
        KeyRecoveryRecord {
            context,
            provenance,
            target: row.intent.target.clone(),
            source_p8: row.intent.source_p8.clone(),
            source_key: row.intent.destination.clone(),
            original: KeyRecoveryOrigin {
                operation_id: row.intent.provenance.operation_id.clone(),
                owner_generation: row.intent.provenance.owner_generation.clone(),
                row_sha256: key_row_sha256(row).unwrap(),
            },
            output: row.update.output.clone().unwrap(),
        }
    }

    #[test]
    fn exact_durable_reference_is_required_and_old_pending_never_changes() {
        let row = old_row();
        let old = canonical(&row, ROW_LIMIT).unwrap();
        let value = record(&row);
        value.matches_row(&row).unwrap();
        validate_key_recoveries(&[value.clone()], std::slice::from_ref(&row)).unwrap();
        assert!(row.unresolved());
        assert_eq!(canonical(&row, ROW_LIMIT).unwrap(), old);
        for change in 0..7 {
            let mut changed = value.clone();
            match change {
                0 => changed.source_key.record_id = "e".repeat(32),
                1 => changed.source_key.revision_id = "f".repeat(32),
                2 => changed.output.csr_sha256 = "a".repeat(64),
                3 => changed.output.public_key_sha256 = "b".repeat(64),
                4 => changed.output.frame_bytes += 1,
                5 => changed.original.row_sha256 = "c".repeat(64),
                _ => changed.context.account_ref = AccountRef::from_selected_issuer([9; 16]),
            }
            assert!(changed.matches_row(&row).is_err());
        }
        assert!(validate_key_recoveries(&[value.clone(), value], &[row]).is_err());
    }

    #[test]
    fn armed_written_unknown_and_foreign_scope_do_not_gain_an_association() {
        let row = old_row();
        let value = record(&row);
        for settlement in [NativeSettlement::Known, NativeSettlement::Unknown] {
            let mut changed = row.clone();
            changed.native_settlement = settlement;
            assert!(value.matches_row(&changed).is_err());
        }
        let mut written = row.clone();
        written.update.save = ProfileSaveState::Written;
        written.update.saved_reference = None;
        written.update.disposition = KeyDisposition::Running;
        assert!(!durable_key_row(&written));
        let mut armed = row.clone();
        armed.update = key::tests::initial();
        assert!(!durable_key_row(&armed));
        let mut foreign = value;
        foreign.provenance.registered_root.inode += 1;
        assert!(foreign.matches_row(&row).is_err());
    }
}
