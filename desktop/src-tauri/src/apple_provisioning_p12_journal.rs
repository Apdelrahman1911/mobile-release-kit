//! Fixed local-save arm of the existing held Directory/NativeUse/CAS owner.
//! No provider-send bit, new namespace, async executor or recovery adoption.
use super::*;
use crate::saved_command_owner::AppleP12NativeJoined;

pub(crate) struct P12OriginalReservation {
    native_use: Arc<NativeUse>,
    intent: P12SaveIntent,
}
impl P12OriginalReservation {
    pub(crate) fn intent(&self) -> &P12SaveIntent {
        &self.intent
    }
}
pub(crate) struct P12JournalAck {
    pub(crate) revision: Revision,
    pub(crate) row: P12SaveRow,
    pub(crate) original: Arc<P12OriginalReservation>,
}
impl State {
    fn p12_v4(&mut self) -> Result<()> {
        self.validate()?;
        if self.schema_version < 4 {
            self.schema_version = 4;
            self.protocol = P12_PROTOCOL.into();
            self.profile_rows.get_or_insert_with(Vec::new);
            self.key_rows.get_or_insert_with(Vec::new);
            self.certificate_rows.get_or_insert_with(Vec::new);
            self.p12_rows = Some(Vec::new());
        }
        self.validate()
    }
    pub(super) fn p12_key(row: &P12SaveRow) -> (&AccountRef, &str) {
        (
            &row.intent.context.account_ref,
            row.intent.provenance.operation_id.as_str(),
        )
    }
    fn p12_index(&self, original: &P12OriginalReservation) -> Result<usize> {
        self.p12_rows
            .as_ref()
            .and_then(|rows| rows.iter().position(|row| row.intent == original.intent))
            .ok_or_else(|| Error::Conflict.into())
    }
}
impl AppleProvisioningJournal {
    pub(crate) fn retained_p12_reservation(&self) -> Option<&Arc<P12OriginalReservation>> {
        self.p12_original.as_ref()
    }
    fn p12_original(
        &self,
        original: &P12OriginalReservation,
    ) -> Result<Arc<P12OriginalReservation>> {
        self.healthy()?;
        let retained = self
            .p12_original
            .as_ref()
            .ok_or_else(|| StateError::from(Error::Conflict))?;
        need(
            std::ptr::eq(retained.as_ref(), original)
                && Arc::ptr_eq(&self.native_use, &original.native_use),
        )?;
        Ok(retained.clone())
    }
    fn publish_p12(
        &mut self,
        expected: Revision,
        state: &State,
        row: P12SaveRow,
        original: Arc<P12OriginalReservation>,
    ) -> Result<P12JournalAck> {
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
            Ok(P12JournalAck {
                revision: snapshot.revision,
                row,
                original,
            })
        })();
        self.remember(result)
    }
    /// One explicit local assembly, before its one helper invocation. The
    /// parent must join this exact job and repeat current admission before ACK.
    pub(crate) fn reserve_p12(
        &mut self,
        expected: Revision,
        intent: P12SaveIntent,
        update: P12SaveUpdate,
    ) -> Result<P12JournalAck> {
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
        // A known saved row routes to fresh readback/reuse; an unresolved or
        // known-refused attempt remains evidence, never a silently new wizard.
        if state.unresolved(&intent.context.account_ref)
            || state
                .p12_rows
                .iter()
                .flatten()
                .any(|row| row.intent.same_package(&intent))
        {
            return Err(Error::RecoveryRequired.into());
        }
        if state.row_count() >= ROWS {
            return Err(Error::Busy.into());
        }
        let row = P12SaveRow {
            intent: intent.clone(),
            assembly_armed: true,
            update,
            native_settlement: NativeSettlement::Pending,
        };
        row.validate()?;
        state.p12_v4()?;
        let rows = state
            .p12_rows
            .as_mut()
            .ok_or_else(|| StateError::from(Error::RecoveryRequired))?;
        rows.push(row.clone());
        rows.sort_by(|a, b| State::p12_key(a).cmp(&State::p12_key(b)));
        state.bytes()?;
        let original = Arc::new(P12OriginalReservation {
            native_use: self.native_use.clone(),
            intent,
        });
        self.p12_original = Some(original.clone()); // Retain BEFORE the actual CAS/lost ACK.
        self.publish_p12(expected, &state, row, original)
    }
    pub(crate) fn record_p12(
        &mut self,
        expected: Revision,
        original: &P12OriginalReservation,
        update: P12SaveUpdate,
    ) -> Result<P12JournalAck> {
        let original = self.p12_original(original)?;
        let (revision, mut state) = self.load()?;
        if revision != expected {
            return Err(Error::Conflict.into());
        }
        let index = state.p12_index(&original)?;
        let row = &mut state
            .p12_rows
            .as_mut()
            .ok_or_else(|| StateError::from(Error::RecoveryRequired))?[index];
        need(row.native_settlement == NativeSettlement::Pending)?;
        update.follows(&row.update, &row.intent)?;
        row.update = update;
        let row = row.clone();
        self.publish_p12(expected, &state, row, original)
    }
    /// NativeJoined is the original pre-FINAL-CAS cut, NOT the worker Terminal
    /// or a restart read. NativeUse retirement and private drain still follow.
    pub(crate) fn finish_p12_native(
        &mut self,
        expected: Revision,
        original: &P12OriginalReservation,
        joined: &AppleP12NativeJoined,
    ) -> Result<P12JournalAck> {
        let original = self.p12_original(original)?;
        if !joined.matches(&self.native_use, &original) {
            return Err(Error::Conflict.into());
        }
        let (revision, mut state) = self.load()?;
        if revision != expected {
            return Err(Error::Conflict.into());
        }
        let index = state.p12_index(&original)?;
        let row = &mut state
            .p12_rows
            .as_mut()
            .ok_or_else(|| StateError::from(Error::RecoveryRequired))?[index];
        need(
            row.native_settlement == NativeSettlement::Pending
                && row.update.disposition != P12Disposition::Running,
        )?;
        row.native_settlement = NativeSettlement::Known;
        let row = row.clone();
        self.publish_p12(expected, &state, row, original)
    }
}

#[cfg(test)]
#[path = "apple_provisioning_p12_journal_tests.rs"]
mod tests;
