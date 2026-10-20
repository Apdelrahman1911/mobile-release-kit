//! Profile reserve/save arm of the existing AppleProvisioningJournal.
//! Uses its SAME directory, NativeUse, canonical state/CAS and sticky failure.
//! No independent store, service, lock owner, migration task or retry exists.
use super::*;
use crate::saved_command_owner::AppleProfileNativeJoined;

/// Retained before the first schema-2 CAS, including failed/lost ACKs. The
/// reference-only state decoder cannot construct/adopt this original token.
pub(crate) struct ProfileOriginalReservation {
    native_use: Arc<NativeUse>,
    intent: ProfileSetupIntent,
}
impl ProfileOriginalReservation {
    pub(crate) fn intent(&self) -> &ProfileSetupIntent {
        &self.intent
    }
}
pub(crate) struct ProfileJournalAck {
    pub(crate) revision: Revision,
    pub(crate) row: ProfileSetupRow,
    pub(crate) original: Arc<ProfileOriginalReservation>,
}

impl AppleProvisioningJournal {
    pub(crate) fn retained_profile_reservation(&self) -> Option<&Arc<ProfileOriginalReservation>> {
        self.profile_original.as_ref()
    }
    fn profile_original(
        &self,
        original: &ProfileOriginalReservation,
    ) -> Result<Arc<ProfileOriginalReservation>> {
        self.healthy()?;
        let retained = self
            .profile_original
            .as_ref()
            .ok_or_else(|| StateError::from(Error::Conflict))?;
        if !std::ptr::eq(retained.as_ref(), original)
            || !Arc::ptr_eq(&self.native_use, &original.native_use)
        {
            return Err(Error::Conflict.into());
        }
        Ok(retained.clone())
    }
    fn profile_index(state: &State, original: &ProfileOriginalReservation) -> Result<usize> {
        state
            .profile_rows
            .as_ref()
            .and_then(|rows| rows.iter().position(|row| row.intent == original.intent))
            .ok_or_else(|| Error::Conflict.into())
    }
    fn publish_profile(
        &mut self,
        expected: Revision,
        state: &State,
        row: ProfileSetupRow,
        original: Arc<ProfileOriginalReservation>,
    ) -> Result<ProfileJournalAck> {
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
            Ok(ProfileJournalAck {
                revision: snapshot.revision,
                row,
                original,
            })
        })();
        self.remember(result)
    }

    /// The explicit profile-reuse/create Start is the ONLY caller allowed to
    /// propose this CAS. It atomically appends its immutable destination intent
    /// and opts the SAME namespace into v2. Ordinary inspection/Bundle paths
    /// do not rewrite v1. Existing Bundle rows are carried through unchanged.
    pub(crate) fn reserve_profile(
        &mut self,
        expected: Revision,
        intent: ProfileSetupIntent,
        update: ProfileUpdate,
    ) -> Result<ProfileJournalAck> {
        self.healthy()?;
        if self.original.is_some() || self.profile_original.is_some() {
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
        let row = ProfileSetupRow {
            send_armed: intent.action == ProfileAction::CreateProfile,
            intent: intent.clone(),
            update,
            native_settlement: NativeSettlement::Pending,
        };
        row.validate()?;
        if state.schema_version == 1 {
            state.schema_version = 2;
            state.protocol = PROFILE_PROTOCOL.into();
            state.profile_rows = Some(Vec::new());
        }
        let rows = state
            .profile_rows
            .as_mut()
            .ok_or_else(|| StateError::from(Error::RecoveryRequired))?;
        rows.push(row.clone());
        rows.sort_by(|a, b| profile_key(a).cmp(&profile_key(b)));
        state.bytes()?;
        let original = Arc::new(ProfileOriginalReservation {
            native_use: self.native_use.clone(),
            intent,
        });
        self.profile_original = Some(original.clone()); // BEFORE entered CAS.
        self.publish_profile(expected, &state, row, original)
    }
    /// Provider update or native local-save update, never a restored row. The
    /// parent validates provider fields against its retained worker dialogue;
    /// save/readback facts come only from the actual fixed vault job. A copied
    /// ACK/row cannot enter this method without the SAME original reservation.
    pub(crate) fn record_profile(
        &mut self,
        expected: Revision,
        original: &ProfileOriginalReservation,
        update: ProfileUpdate,
    ) -> Result<ProfileJournalAck> {
        let original = self.profile_original(original)?;
        let (revision, mut state) = self.load()?;
        if revision != expected {
            return Err(Error::Conflict.into());
        }
        let index = Self::profile_index(&state, &original)?;
        let row = &mut state
            .profile_rows
            .as_mut()
            .ok_or_else(|| StateError::from(Error::RecoveryRequired))?[index];
        need(row.native_settlement == NativeSettlement::Pending)?;
        update.follows(&row.update, &row.intent)?;
        row.update = update;
        let row = row.clone();
        self.publish_profile(expected, &state, row, original)
    }
    /// Worker/provider/CMS consumers AND actual vault save/readback jobs have
    /// joined before this fact can be minted. This final CAS is still an
    /// original job; subsequent ALL-jobs/NativeUse-retirement cuts are separate.
    pub(crate) fn finish_profile_native(
        &mut self,
        expected: Revision,
        original: &ProfileOriginalReservation,
        joined: &AppleProfileNativeJoined,
    ) -> Result<ProfileJournalAck> {
        let original = self.profile_original(original)?;
        if !joined.matches(&self.native_use, &original) {
            return Err(Error::Conflict.into());
        }
        let (revision, mut state) = self.load()?;
        if revision != expected {
            return Err(Error::Conflict.into());
        }
        let index = Self::profile_index(&state, &original)?;
        let row = &mut state
            .profile_rows
            .as_mut()
            .ok_or_else(|| StateError::from(Error::RecoveryRequired))?[index];
        need(row.native_settlement == NativeSettlement::Pending)?;
        row.native_settlement = NativeSettlement::Known;
        let row = row.clone();
        self.publish_profile(expected, &state, row, original)
    }
}

#[cfg(test)]
#[path = "apple_provisioning_profile_journal_tests.rs"]
mod tests;
