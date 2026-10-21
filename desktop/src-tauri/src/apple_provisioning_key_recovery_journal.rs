//! One verification-history append on the original Apple journal port.
//! No recovery of old reservations, retries, workers, paths or NativeUse.
use super::*;
use crate::saved_command_owner::AppleKeyRecoveryVerified;

pub(crate) struct KeyRecoveryWrite {
    native_use: Arc<NativeUse>,
    record: KeyRecoveryRecord,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{application_state_store::Fixture, service_protocol::Id};
    use data::key_recovery::tests::{old_row, record};

    fn state() -> State {
        let mut state = State::empty();
        state.key_v3().unwrap();
        state.key_rows.as_mut().unwrap().push(old_row());
        state.validate().unwrap();
        state
    }
    #[test]
    fn recovery_v5_preserves_legacy_rows_and_only_the_exact_key_fence() {
        let mut state = state();
        let old = canonical(&state.key_rows.as_ref().unwrap()[0], ROW_LIMIT).unwrap();
        // Schema3 and schema4 canonical reads remain byte-identical.
        for revision in 3..=4 {
            if revision == 4 {
                state.p12_v4().unwrap();
            }
            let bytes = state.bytes().unwrap();
            let decoded = State::decode(&Snapshot {
                revision: Revision(7),
                bytes: bytes.clone(),
            })
            .unwrap();
            assert_eq!(decoded.bytes().unwrap(), bytes);
            assert!(decoded.key_recoveries.is_none());
        }
        let row = state.key_rows.as_ref().unwrap()[0].clone();
        assert!(state.unresolved(&row.intent.context.account_ref));
        state.key_recovery_v5().unwrap();
        state.key_recoveries.as_mut().unwrap().push(record(&row));
        state.validate().unwrap();
        let recovered_bytes = state.bytes().unwrap();
        // Later ordinary key/P12 reserve helpers must not downgrade or drop
        // the explicit schema5 relation. Their original methods are reused.
        state.key_v3().unwrap();
        state.p12_v4().unwrap();
        assert_eq!(state.bytes().unwrap(), recovered_bytes);
        assert!(!state.unresolved(&row.intent.context.account_ref));
        assert!(state.key_rows.as_ref().unwrap()[0].unresolved());
        assert_eq!(
            canonical(&state.key_rows.as_ref().unwrap()[0], ROW_LIMIT).unwrap(),
            old
        );
        // An independent certificate/Bundle/etc. obligation is NOT discharged.
        let mut intent = data::tests::intent();
        intent.context.account_ref = row.intent.context.account_ref.clone();
        intent.context.operation_id = "7".repeat(32);
        intent.provenance.operation_id = Id::parse(&intent.context.operation_id).unwrap();
        data::tests::reseal_fixture(&mut intent);
        state.rows.push(JournalRow {
            attempt: data::tests::armed(&intent),
            intent,
            send_armed: true,
            native_settlement: NativeSettlement::Pending,
        });
        state.validate().unwrap();
        assert!(state.unresolved(&row.intent.context.account_ref));
        let bytes = state.bytes().unwrap();
        assert!(bytes.len() < STATE_LIMIT);
        let decoded = State::decode(&Snapshot {
            revision: Revision(8),
            bytes: bytes.clone(),
        })
        .unwrap();
        assert_eq!(decoded.bytes().unwrap(), bytes);
        let mut bad: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        bad["keyRecoveries"][0]["original"]["rowSha256"] = serde_json::json!("f".repeat(64));
        assert!(serde_json::from_value::<State>(bad)
            .unwrap()
            .validate()
            .is_err());
        // Fallible account projections validate membership and all relations
        // even when the caller supplies a row whose raw fence is already Known.
        let mut account = AccountSnapshot {
            revision: Revision(8),
            account: row.intent.context.account_ref.clone(),
            rows: vec![],
            profile_rows: vec![],
            key_rows: vec![row.clone()],
            certificate_rows: vec![],
            p12_rows: vec![],
            key_recoveries: vec![record(&row)],
        };
        let mut foreign = row.clone();
        foreign.native_settlement = NativeSettlement::Known;
        assert!(account.key_unresolved(&foreign).is_err());
        account.key_recoveries[0].original.row_sha256 = "f".repeat(64);
        assert!(account.key_unresolved(&row).is_err());
        assert!(account.key_unresolved(&foreign).is_err());
    }
    #[test]
    fn recovery_records_share_the_original_operation_domain_and_32_row_capacity() {
        let mut state = state();
        let old = state.key_rows.as_ref().unwrap()[0].clone();
        state.key_recovery_v5().unwrap();
        state.key_recoveries.as_mut().unwrap().push(record(&old));
        for n in 1..=30u8 {
            let mut row = old.clone();
            row.intent.context.operation_id = format!("{n:032x}");
            row.intent.provenance.operation_id =
                Id::parse(&row.intent.context.operation_id).unwrap();
            data::key::tests::reseal(&mut row.intent);
            row.native_settlement = NativeSettlement::Known;
            state.key_rows.as_mut().unwrap().push(row);
        }
        state
            .key_rows
            .as_mut()
            .unwrap()
            .sort_by(|a, b| key_key(a).cmp(&key_key(b)));
        assert_eq!(state.row_count(), 32);
        state.validate().unwrap();
        let mut duplicate = state.key_recoveries.as_ref().unwrap()[0].clone();
        duplicate.context.operation_id = "6".repeat(32);
        duplicate.provenance.operation_id = Id::parse(&duplicate.context.operation_id).unwrap();
        state.key_recoveries.as_mut().unwrap().push(duplicate);
        assert!(state.validate().is_err());
        state.key_recoveries.as_mut().unwrap().pop();
        let recovery = state.key_recoveries.as_mut().unwrap().first_mut().unwrap();
        recovery.context.operation_id = format!("{:032x}", 1);
        recovery.provenance.operation_id = Id::parse(&recovery.context.operation_id).unwrap();
        assert!(state.validate().is_err());
    }
    #[test]
    fn recovery_store_write_retains_lost_ack_without_replay_or_old_row_rewrite() {
        // Real synchronous Store/CAS fixture only: this deliberately exercises
        // replace_recovery, NOT native admission or a manufactured joined proof.
        let fixture = Fixture::new();
        let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
        let native = Arc::new(store.begin_native_use().unwrap());
        store.enable_apple_provisioning(&native).unwrap();
        let mut state = state();
        let row = state.key_rows.as_ref().unwrap()[0].clone();
        let before = state.bytes().unwrap();
        store
            .replace(Namespace::AppleProvisioning, Revision(0), &before)
            .unwrap();
        state.key_recovery_v5().unwrap();
        let record = record(&row);
        state.key_recoveries.as_mut().unwrap().push(record.clone());
        let bytes = state.bytes().unwrap();
        let original = Arc::new(KeyRecoveryWrite {
            native_use: native.clone(),
            record,
        });
        let mut journal = AppleProvisioningJournal::new(store.clone(), native.clone());
        journal.key_recovery_write = Some(original.clone());
        journal.lose_next_ack = true;
        let error = journal
            .replace_recovery(Revision(1), &bytes, original.clone())
            .err()
            .unwrap();
        assert_eq!(error.code, Error::StateUnknown);
        assert!(journal.reservation_taken());
        assert!(Arc::ptr_eq(
            journal.retained_key_recovery().unwrap(),
            &original
        ));
        assert!(journal
            .replace_recovery(Revision(1), &bytes, original)
            .is_err());
        let snapshot = store.read(Namespace::AppleProvisioning).unwrap();
        assert_eq!(snapshot.revision, Revision(2));
        assert_eq!(snapshot.bytes, bytes);
        let decoded = State::decode(&snapshot).unwrap();
        assert!(decoded.key_rows.as_ref().unwrap()[0] == row && row.unresolved());
        store.retire_native_use(&native).unwrap();
        store.close().unwrap();
    }
}
impl KeyRecoveryWrite {
    pub(crate) fn record(&self) -> &KeyRecoveryRecord {
        &self.record
    }
}
pub(crate) struct KeyRecoveryJournalAck {
    pub(crate) revision: Revision,
    pub(crate) original: Arc<KeyRecoveryWrite>,
}

impl AccountSnapshot {
    /// Full relation checks are native, not inferred from the coarse pending
    /// projection that the worker receives. Every family shares one row bound.
    pub(crate) fn validate_recoveries(&self) -> Result<()> {
        let count = self
            .rows
            .len()
            .checked_add(self.profile_rows.len())
            .and_then(|n| n.checked_add(self.key_rows.len()))
            .and_then(|n| n.checked_add(self.certificate_rows.len()))
            .and_then(|n| n.checked_add(self.p12_rows.len()))
            .and_then(|n| n.checked_add(self.key_recoveries.len()));
        need(count.is_some_and(|count| count <= ROWS))?;
        validate_key_recoveries(&self.key_recoveries, &self.key_rows)?;
        let mut operations = BTreeSet::new();
        for (account, operation) in self
            .rows
            .iter()
            .map(|r| {
                (
                    &r.intent.context.account_ref,
                    r.intent.context.operation_id.as_str(),
                )
            })
            .chain(self.profile_rows.iter().map(|r| {
                (
                    &r.intent.context.account_ref,
                    r.intent.context.operation_id.as_str(),
                )
            }))
            .chain(self.key_rows.iter().map(|r| {
                (
                    &r.intent.context.account_ref,
                    r.intent.context.operation_id.as_str(),
                )
            }))
            .chain(self.certificate_rows.iter().map(|r| {
                (
                    &r.intent.context.account_ref,
                    r.intent.context.operation_id.as_str(),
                )
            }))
            .chain(self.p12_rows.iter().map(|r| {
                (
                    &r.intent.context.account_ref,
                    r.intent.context.operation_id.as_str(),
                )
            }))
            .chain(
                self.key_recoveries
                    .iter()
                    .map(|r| (&r.context.account_ref, r.context.operation_id.as_str())),
            )
        {
            need(account == &self.account && operations.insert(operation))?;
        }
        Ok(())
    }
    pub(crate) fn key_recovery(&self, row: &KeyPrepareRow) -> Result<Option<&KeyRecoveryRecord>> {
        self.validate_recoveries()?;
        need(self.key_rows.iter().any(|current| current == row))?;
        key_recovery_for(&self.key_recoveries, row)
    }
    pub(crate) fn key_unresolved(&self, row: &KeyPrepareRow) -> Result<bool> {
        let recovery = self.key_recovery(row)?;
        Ok(row.unresolved() && recovery.is_none())
    }
}

impl State {
    fn key_recovery_v5(&mut self) -> Result<()> {
        self.validate()?;
        if self.schema_version < 5 {
            self.schema_version = 5;
            self.protocol = KEY_RECOVERY_PROTOCOL.into();
            self.profile_rows.get_or_insert_with(Vec::new);
            self.key_rows.get_or_insert_with(Vec::new);
            self.certificate_rows.get_or_insert_with(Vec::new);
            self.p12_rows.get_or_insert_with(Vec::new);
            self.key_recoveries = Some(Vec::new());
        }
        self.validate()
    }
}

impl AppleProvisioningJournal {
    pub(crate) fn retained_key_recovery(&self) -> Option<&Arc<KeyRecoveryWrite>> {
        self.key_recovery_write.as_ref()
    }

    pub(crate) fn record_key_recovery(
        &mut self,
        expected: Revision,
        record: KeyRecoveryRecord,
        joined: AppleKeyRecoveryVerified,
    ) -> Result<KeyRecoveryJournalAck> {
        self.healthy()?;
        if self.reservation_taken() {
            return Err(Error::Conflict.into());
        }
        record.validate()?;
        need(joined.matches(&self.native_use, &record))?;
        let (revision, mut state) = self.load()?;
        if revision != expected || state.contains_operation(record.provenance.operation_id.as_str())
        {
            return Err(Error::Conflict.into());
        }
        let mut candidates = state
            .key_rows
            .iter()
            .flatten()
            .filter(|row| row.intent.provenance.operation_id == record.original.operation_id);
        let row = candidates
            .next()
            .ok_or_else(|| StateError::from(Error::RecoveryRequired))?;
        need(candidates.next().is_none())?;
        record.matches_row(row)?;
        if key_recovery_for(state.key_recoveries.as_deref().unwrap_or(&[]), row)?.is_some() {
            return Err(Error::Conflict.into()); // A new explicit read may compare; this call never replays.
        }
        if state.row_count() >= ROWS {
            return Err(Error::Busy.into());
        }
        state.key_recovery_v5()?;
        let records = state.key_recoveries.as_mut().ok_or_else(unknown)?;
        records.push(record.clone());
        records.sort_by(|a, b| {
            (&a.context.account_ref, a.provenance.operation_id.as_str())
                .cmp(&(&b.context.account_ref, b.provenance.operation_id.as_str()))
        });
        let bytes = state.bytes()?;
        // Claim BEFORE the original CAS. Failure/ACK loss retains this exact
        // record and native use; no subsequent read can turn it into a retry.
        let original = Arc::new(KeyRecoveryWrite {
            native_use: self.native_use.clone(),
            record,
        });
        self.key_recovery_write = Some(original.clone());
        let result = (|| {
            need(joined.matches(&original.native_use, &original.record))?;
            self.replace_recovery(expected, &bytes, original)
        })();
        self.remember(result)
    }

    // Fixed persistence mechanism shared with inert Store tests. Admission and
    // the opaque verifier/joins proof stay solely in record_key_recovery above.
    fn replace_recovery(
        &mut self,
        expected: Revision,
        bytes: &[u8],
        original: Arc<KeyRecoveryWrite>,
    ) -> Result<KeyRecoveryJournalAck> {
        self.healthy()?;
        need(
            self.key_recovery_write
                .as_ref()
                .is_some_and(|held| Arc::ptr_eq(held, &original))
                && Arc::ptr_eq(&self.native_use, &original.native_use),
        )?;
        let next = expected
            .0
            .checked_add(1)
            .map(Revision)
            .ok_or_else(unknown)?;
        let result = (|| {
            self.store.check_native_use(&original.native_use)?;
            let snapshot = self
                .store
                .replace(Namespace::AppleProvisioning, expected, bytes)?;
            if snapshot.revision != next || snapshot.bytes.as_slice() != bytes {
                return Err(unknown());
            }
            #[cfg(test)]
            if std::mem::take(&mut self.lose_next_ack) {
                return Err(unknown());
            }
            Ok(KeyRecoveryJournalAck {
                revision: snapshot.revision,
                original,
            })
        })();
        self.remember(result)
    }
}
