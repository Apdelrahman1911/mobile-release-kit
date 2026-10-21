//! Fixed local-key and certificate arms of the SAME Apple journal/CAS owner.
//! No asynchronous task, file path, new namespace or restart adoption exists.
use super::*;
use crate::saved_command_owner::{AppleCertificateNativeJoined, AppleKeyNativeJoined};

pub(crate) struct KeyOriginalReservation {
    native_use: Arc<NativeUse>,
    intent: KeyPrepareIntent,
}
impl KeyOriginalReservation {
    pub(crate) fn intent(&self) -> &KeyPrepareIntent {
        &self.intent
    }
}
pub(crate) struct KeyJournalAck {
    pub(crate) revision: Revision,
    pub(crate) row: KeyPrepareRow,
    pub(crate) original: Arc<KeyOriginalReservation>,
}
pub(crate) struct CertificateOriginalReservation {
    native_use: Arc<NativeUse>,
    intent: CertificateIssuanceIntent,
}
impl CertificateOriginalReservation {
    pub(crate) fn intent(&self) -> &CertificateIssuanceIntent {
        &self.intent
    }
}
pub(crate) struct CertificateJournalAck {
    pub(crate) revision: Revision,
    pub(crate) row: CertificateIssuanceRow,
    pub(crate) original: Arc<CertificateOriginalReservation>,
}

impl State {
    fn key_v3(&mut self) -> Result<()> {
        // Called only by an explicit local-key/certificate Start reserve. A
        // read, startup, old action or source upgrade cannot migrate state.
        self.validate()?;
        if self.schema_version < 3 {
            self.schema_version = 3;
            self.protocol = KEY_PROTOCOL.into();
            self.profile_rows.get_or_insert_with(Vec::new);
            self.key_rows = Some(Vec::new());
            self.certificate_rows = Some(Vec::new());
        }
        self.validate()
    }
}

impl AppleProvisioningJournal {
    pub(crate) fn retained_key_reservation(&self) -> Option<&Arc<KeyOriginalReservation>> {
        self.key_original.as_ref()
    }
    pub(crate) fn retained_certificate_reservation(
        &self,
    ) -> Option<&Arc<CertificateOriginalReservation>> {
        self.certificate_original.as_ref()
    }
    fn key_original(
        &self,
        original: &KeyOriginalReservation,
    ) -> Result<Arc<KeyOriginalReservation>> {
        self.healthy()?;
        let retained = self
            .key_original
            .as_ref()
            .ok_or_else(|| StateError::from(Error::Conflict))?;
        need(
            std::ptr::eq(retained.as_ref(), original)
                && Arc::ptr_eq(&self.native_use, &original.native_use),
        )?;
        Ok(retained.clone())
    }
    fn certificate_original(
        &self,
        original: &CertificateOriginalReservation,
    ) -> Result<Arc<CertificateOriginalReservation>> {
        self.healthy()?;
        let retained = self
            .certificate_original
            .as_ref()
            .ok_or_else(|| StateError::from(Error::Conflict))?;
        need(
            std::ptr::eq(retained.as_ref(), original)
                && Arc::ptr_eq(&self.native_use, &original.native_use),
        )?;
        Ok(retained.clone())
    }
    fn key_index(state: &State, original: &KeyOriginalReservation) -> Result<usize> {
        state
            .key_rows
            .as_ref()
            .and_then(|rows| rows.iter().position(|row| row.intent == original.intent))
            .ok_or_else(|| Error::Conflict.into())
    }
    fn certificate_index(
        state: &State,
        original: &CertificateOriginalReservation,
    ) -> Result<usize> {
        state
            .certificate_rows
            .as_ref()
            .and_then(|rows| rows.iter().position(|row| row.intent == original.intent))
            .ok_or_else(|| Error::Conflict.into())
    }
    fn publish_key(
        &mut self,
        expected: Revision,
        state: &State,
        row: KeyPrepareRow,
        original: Arc<KeyOriginalReservation>,
    ) -> Result<KeyJournalAck> {
        let bytes = state.bytes()?;
        let next = expected
            .0
            .checked_add(1)
            .map(Revision)
            .ok_or_else(unknown)?;
        self.healthy()?;
        let result = (|| {
            self.store.check_native_use(&self.native_use)?;
            let snapshot = self
                .store
                .replace(Namespace::AppleProvisioning, expected, &bytes)?;
            if snapshot.revision != next || snapshot.bytes != bytes {
                return Err(unknown());
            }
            #[cfg(test)]
            if std::mem::take(&mut self.lose_next_ack) {
                return Err(unknown());
            }
            Ok(KeyJournalAck {
                revision: snapshot.revision,
                row,
                original,
            })
        })();
        self.remember(result)
    }
    fn publish_certificate(
        &mut self,
        expected: Revision,
        state: &State,
        row: CertificateIssuanceRow,
        original: Arc<CertificateOriginalReservation>,
    ) -> Result<CertificateJournalAck> {
        let bytes = state.bytes()?;
        let next = expected
            .0
            .checked_add(1)
            .map(Revision)
            .ok_or_else(unknown)?;
        self.healthy()?;
        let result = (|| {
            self.store.check_native_use(&self.native_use)?;
            let snapshot = self
                .store
                .replace(Namespace::AppleProvisioning, expected, &bytes)?;
            if snapshot.revision != next || snapshot.bytes != bytes {
                return Err(unknown());
            }
            #[cfg(test)]
            if std::mem::take(&mut self.lose_next_ack) {
                return Err(unknown());
            }
            Ok(CertificateJournalAck {
                revision: snapshot.revision,
                row,
                original,
            })
        })();
        self.remember(result)
    }

    /// Durable exact destination/intent BEFORE generator admission. The ACK
    /// becomes usable only when its original native IO job has actually joined.
    pub(crate) fn reserve_key(
        &mut self,
        expected: Revision,
        intent: KeyPrepareIntent,
        update: KeyPrepareUpdate,
    ) -> Result<KeyJournalAck> {
        self.healthy()?;
        if self.reservation_taken() {
            return Err(Error::Conflict.into());
        }
        intent.validate()?;
        update.initial(&intent)?;
        let (revision, mut state) = self.load()?;
        if revision != expected || state.contains_operation(intent.provenance.operation_id.as_str())
        {
            return Err(Error::Conflict.into());
        }
        if state.unresolved(&intent.context.account_ref) {
            return Err(Error::RecoveryRequired.into());
        }
        if state.row_count() >= ROWS {
            return Err(Error::Busy.into());
        }
        let row = KeyPrepareRow {
            intent: intent.clone(),
            generator_armed: true,
            update,
            native_settlement: NativeSettlement::Pending,
        };
        row.validate()?;
        state.key_v3()?;
        let rows = state
            .key_rows
            .as_mut()
            .ok_or_else(|| StateError::from(Error::RecoveryRequired))?;
        rows.push(row.clone());
        rows.sort_by(|a, b| key_key(a).cmp(&key_key(b)));
        state.bytes()?;
        let original = Arc::new(KeyOriginalReservation {
            native_use: self.native_use.clone(),
            intent,
        });
        self.key_original = Some(original.clone()); // BEFORE entering CAS/lost ACK.
        self.publish_key(expected, &state, row, original)
    }
    pub(crate) fn record_key(
        &mut self,
        expected: Revision,
        original: &KeyOriginalReservation,
        update: KeyPrepareUpdate,
    ) -> Result<KeyJournalAck> {
        let original = self.key_original(original)?;
        let (revision, mut state) = self.load()?;
        if revision != expected {
            return Err(Error::Conflict.into());
        }
        let index = Self::key_index(&state, &original)?;
        let row = &mut state
            .key_rows
            .as_mut()
            .ok_or_else(|| StateError::from(Error::RecoveryRequired))?[index];
        need(row.native_settlement == NativeSettlement::Pending)?;
        update.follows(&row.update, &row.intent)?;
        row.update = update;
        let row = row.clone();
        self.publish_key(expected, &state, row, original)
    }
    /// Producer/private transfer and the actual save/readback work precede
    /// this witness. Final CAS and NativeUse-retire are still original jobs.
    pub(crate) fn finish_key_native(
        &mut self,
        expected: Revision,
        original: &KeyOriginalReservation,
        joined: &AppleKeyNativeJoined,
    ) -> Result<KeyJournalAck> {
        let original = self.key_original(original)?;
        if !joined.matches(&self.native_use, &original) {
            return Err(Error::Conflict.into());
        }
        let (revision, mut state) = self.load()?;
        if revision != expected {
            return Err(Error::Conflict.into());
        }
        let index = Self::key_index(&state, &original)?;
        let row = &mut state
            .key_rows
            .as_mut()
            .ok_or_else(|| StateError::from(Error::RecoveryRequired))?[index];
        need(row.native_settlement == NativeSettlement::Pending)?;
        row.native_settlement = NativeSettlement::Known;
        let row = row.clone();
        self.publish_key(expected, &state, row, original)
    }

    /// Separate explicit certificate consent, fresh stored-key verification
    /// and one armed POST. A prior keySaved row is not this operation's loan.
    pub(crate) fn reserve_certificate(
        &mut self,
        expected: Revision,
        intent: CertificateIssuanceIntent,
        update: CertificateUpdate,
    ) -> Result<CertificateJournalAck> {
        self.healthy()?;
        if self.reservation_taken() {
            return Err(Error::Conflict.into());
        }
        intent.validate()?;
        update.initial(&intent)?;
        let (revision, mut state) = self.load()?;
        if revision != expected || state.contains_operation(intent.provenance.operation_id.as_str())
        {
            return Err(Error::Conflict.into());
        }
        if state.unresolved(&intent.context.account_ref) {
            return Err(Error::RecoveryRequired.into());
        }
        if state.row_count() >= ROWS {
            return Err(Error::Busy.into());
        }
        let row = CertificateIssuanceRow {
            intent: intent.clone(),
            send_armed: true,
            update,
            native_settlement: NativeSettlement::Pending,
        };
        row.validate()?;
        state.key_v3()?;
        let rows = state
            .certificate_rows
            .as_mut()
            .ok_or_else(|| StateError::from(Error::RecoveryRequired))?;
        rows.push(row.clone());
        rows.sort_by(|a, b| certificate_key(a).cmp(&certificate_key(b)));
        state.bytes()?;
        let original = Arc::new(CertificateOriginalReservation {
            native_use: self.native_use.clone(),
            intent,
        });
        self.certificate_original = Some(original.clone());
        self.publish_certificate(expected, &state, row, original)
    }
    pub(crate) fn record_certificate(
        &mut self,
        expected: Revision,
        original: &CertificateOriginalReservation,
        update: CertificateUpdate,
    ) -> Result<CertificateJournalAck> {
        let original = self.certificate_original(original)?;
        let (revision, mut state) = self.load()?;
        if revision != expected {
            return Err(Error::Conflict.into());
        }
        let index = Self::certificate_index(&state, &original)?;
        let row = &mut state
            .certificate_rows
            .as_mut()
            .ok_or_else(|| StateError::from(Error::RecoveryRequired))?[index];
        need(row.native_settlement == NativeSettlement::Pending)?;
        update.follows(&row.update, &row.intent)?;
        row.update = update;
        let row = row.clone();
        self.publish_certificate(expected, &state, row, original)
    }
    pub(crate) fn finish_certificate_native(
        &mut self,
        expected: Revision,
        original: &CertificateOriginalReservation,
        joined: &AppleCertificateNativeJoined,
    ) -> Result<CertificateJournalAck> {
        let original = self.certificate_original(original)?;
        if !joined.matches(&self.native_use, &original) {
            return Err(Error::Conflict.into());
        }
        let (revision, mut state) = self.load()?;
        if revision != expected {
            return Err(Error::Conflict.into());
        }
        let index = Self::certificate_index(&state, &original)?;
        let row = &mut state
            .certificate_rows
            .as_mut()
            .ok_or_else(|| StateError::from(Error::RecoveryRequired))?[index];
        need(row.native_settlement == NativeSettlement::Pending)?;
        row.native_settlement = NativeSettlement::Known;
        let row = row.clone();
        self.publish_certificate(expected, &state, row, original)
    }
}

// Sibling recovery tests exercise the real migration without exposing it
// outside its owning module in production builds.
#[cfg(test)]
pub(super) fn key_v3_for_test(state: &mut State) -> Result<()> {
    state.key_v3()
}

#[cfg(test)]
#[path = "apple_provisioning_key_journal_tests.rs"]
mod tests;
