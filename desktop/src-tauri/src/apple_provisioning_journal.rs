//! Fixed Apple Bundle-ID reference journal on the SAME private state directory.
//!
//! Native callers retain this port and the original NativeUse before GO. Every
//! IO call runs outside Document/Edit/Host/Service locks, in the existing finite
//! native job owner; this module creates no task, process, service or directory.
//! A durable ACK is necessary BEFORE the single POST, never sufficient authority
//! to send it. The original parent repeats key/context/consent/STOP admission.
use crate::{
    application_state_store::{
        Cleanup, Durability, Effect, Namespace, NativeUse, PrivateStateDirectory, Revision,
        Snapshot, StateError,
    },
    protocol::strict_json,
    saved_command_owner::AppleProvisioningNativeJoined,
    service_protocol::Error,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc};

#[path = "apple_provisioning_journal_data.rs"]
mod data;
use data::{canonical, need, PROTOCOL};
pub(crate) use data::key::certificate_phase_sha256;
pub(crate) use data::profile::{profile_choice_valid, profile_entitlements_sha256,
    profile_identity_sha256, profile_unix_micros};
pub(crate) use data::{
    AccountRef, Action, AttemptReason, AttemptRecord, AttemptStatus, AttemptUpdate,
    BundleRegistrationIntent, BundleTarget, JournalRow, NativeProvenance, NativeSettlement,
    ProvisioningContext, RegisteredRootData, ATTEMPT_LIMIT, ROWS, ROW_LIMIT, STATE_LIMIT,
    ProfileAction, ProfileTarget, ProfileBundle, ProfileCertificate, ProfileSelection, ProfileSetupIntent,
    ProfileCreateAction, ProfileAttemptRecord, ProfileProvider, ProfileDownload, ProfileSaveState,
    ProfileUpdate, ProfileSetupRow, PROFILE_PROTOCOL, PROFILE_BYTES,
    KeyAlgorithm, KeyPrepareIntent, KeyOutputMetadata, KeyGeneration, KeyDisposition, KeyPrepareUpdate, KeyPrepareRow,
    CertificateIssuanceIntent, CertificateCreateAction, CertificateAttemptRecord, CertificateCreationReceipt,
    CertificateUpdate, CertificateIssuanceRow, KEY_PROTOCOL,
};
#[path = "apple_provisioning_profile_journal.rs"]
mod profile;
pub(crate) use profile::{ProfileOriginalReservation, ProfileJournalAck};
#[path = "apple_provisioning_key_journal.rs"]
mod key;
pub(crate) use key::{KeyOriginalReservation, KeyJournalAck, CertificateOriginalReservation, CertificateJournalAck};
type Result<T> = std::result::Result<T, StateError>;

fn unknown() -> StateError {
    StateError {
        code: Error::StateUnknown,
        effect: Effect::Unknown,
        durability: Durability::Unknown,
        cleanup: Cleanup::Unknown,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct State {
    schema_version: u32,
    protocol: String,
    rows: Vec<JournalRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile_rows: Option<Vec<ProfileSetupRow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_rows: Option<Vec<KeyPrepareRow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    certificate_rows: Option<Vec<CertificateIssuanceRow>>,
}
impl State {
    fn empty() -> Self {
        Self {
            schema_version: 1,
            protocol: PROTOCOL.into(),
            rows: Vec::new(),
            profile_rows: None,
            key_rows: None,
            certificate_rows: None,
        }
    }
    fn row_count(&self) -> usize {
        self.rows.len().saturating_add(self.profile_rows.as_ref().map_or(0,Vec::len))
            .saturating_add(self.key_rows.as_ref().map_or(0,Vec::len))
            .saturating_add(self.certificate_rows.as_ref().map_or(0,Vec::len))
    }
    fn contains_operation(&self, operation: &str) -> bool {
        self.rows.iter().any(|row| row.intent.context.operation_id == operation)
            || self.profile_rows.iter().flatten().any(|row| row.intent.context.operation_id == operation)
            || self.key_rows.iter().flatten().any(|row| row.intent.context.operation_id == operation)
            || self.certificate_rows.iter().flatten().any(|row| row.intent.context.operation_id == operation)
    }
    fn unresolved(&self, account: &AccountRef) -> bool {
        self.rows.iter().any(|row| &row.intent.context.account_ref == account && row.unresolved())
            || self.profile_rows.iter().flatten().any(|row| &row.intent.context.account_ref == account && row.unresolved())
            || self.key_rows.iter().flatten().any(|row| &row.intent.context.account_ref == account && row.unresolved())
            || self.certificate_rows.iter().flatten().any(|row| &row.intent.context.account_ref == account && row.unresolved())
    }
    fn validate(&self) -> Result<()> {
        need(self.row_count() <= ROWS && match self.schema_version {
            1 => self.protocol == PROTOCOL && self.profile_rows.is_none() && self.key_rows.is_none() && self.certificate_rows.is_none(),
            2 => self.protocol == PROFILE_PROTOCOL && self.profile_rows.is_some() && self.key_rows.is_none() && self.certificate_rows.is_none(),
            3 => self.protocol == KEY_PROTOCOL && self.profile_rows.is_some() && self.key_rows.is_some() && self.certificate_rows.is_some(),
            _ => false,
        })?;
        let mut operations = BTreeSet::new();
        let mut pending_accounts = BTreeSet::new();
        for row in &self.rows {
            row.validate()?;
            need(operations.insert(row.intent.provenance.operation_id.as_str()))?;
            if row.unresolved() {
                need(pending_accounts.insert(&row.intent.context.account_ref))?;
            }
        }
        for row in self.profile_rows.iter().flatten() {
            row.validate()?;
            need(operations.insert(row.intent.provenance.operation_id.as_str()))?;
            if row.unresolved() { need(pending_accounts.insert(&row.intent.context.account_ref))?; }
        }
        for row in self.key_rows.iter().flatten() {
            row.validate()?;
            need(operations.insert(row.intent.provenance.operation_id.as_str()))?;
            if row.unresolved() { need(pending_accounts.insert(&row.intent.context.account_ref))?; }
        }
        for row in self.certificate_rows.iter().flatten() {
            row.validate()?;
            need(operations.insert(row.intent.provenance.operation_id.as_str()))?;
            if row.unresolved() { need(pending_accounts.insert(&row.intent.context.account_ref))?; }
        }
        need(self.key_rows.as_ref().is_none_or(|rows| rows.windows(2)
            .all(|pair| key_key(&pair[0]) < key_key(&pair[1]))))?;
        need(self.certificate_rows.as_ref().is_none_or(|rows| rows.windows(2)
            .all(|pair| certificate_key(&pair[0]) < certificate_key(&pair[1]))))?;
        need(self.profile_rows.as_ref().is_none_or(|rows| rows.windows(2)
            .all(|pair| profile_key(&pair[0]) < profile_key(&pair[1]))))?;
        need(
            self.rows
                .windows(2)
                .all(|pair| row_key(&pair[0]) < row_key(&pair[1])),
        )
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = canonical(self, STATE_LIMIT - 1)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
    fn decode(snapshot: &Snapshot) -> Result<Self> {
        let result = (|| {
            need(snapshot.bytes.len() <= STATE_LIMIT)?;
            if snapshot.bytes.is_empty() {
                need(snapshot.revision == Revision(0))?;
                return Ok(Self::empty());
            }
            need(snapshot.revision != Revision(0))?;
            // The existing bounded duplicate-key/depth/node parser is enough
            // for 32 closed rows. No wider traversal or generic state RPC.
            let value = strict_json(&snapshot.bytes)
                .map_err(|_| StateError::from(Error::InvalidRequest))?;
            let state: Self = serde_json::from_value(value)
                .map_err(|_| StateError::from(Error::InvalidRequest))?;
            need(state.row_count() > 0 && state.bytes()? == snapshot.bytes)?;
            Ok(state)
        })();
        result.map_err(|_: StateError| Error::RecoveryRequired.into())
    }
}
fn row_key(row: &JournalRow) -> (&AccountRef, &str) {
    (
        &row.intent.context.account_ref,
        row.intent.provenance.operation_id.as_str(),
    )
}

fn profile_key(row: &ProfileSetupRow) -> (&AccountRef, &str) {
    (&row.intent.context.account_ref,row.intent.provenance.operation_id.as_str())
}

fn key_key(row: &KeyPrepareRow) -> (&AccountRef, &str) {
    (&row.intent.context.account_ref, row.intent.provenance.operation_id.as_str())
}
fn certificate_key(row: &CertificateIssuanceRow) -> (&AccountRef, &str) {
    (&row.intent.context.account_ref, row.intent.provenance.operation_id.as_str())
}

/// Original private reservation, retained in this port BEFORE the first CAS.
/// No serializer, Clone, constructor, load/adopt/retry or ID-based authority.
/// A later read-only lease cannot recreate it from even byte-identical rows.
pub(crate) struct OriginalReservation {
    native_use: Arc<NativeUse>,
    intent: BundleRegistrationIntent,
}
impl OriginalReservation {
    pub(crate) fn intent(&self) -> &BundleRegistrationIntent {
        &self.intent
    }
}

/// Actual store-call result, not a renderer DTO or a provider/native receipt.
/// Only the parent's joined original job and current admission may acknowledge
/// this to the same waiting worker. A result-shaped message cannot recreate it.
pub(crate) struct JournalAck {
    pub(crate) revision: Revision,
    pub(crate) row: JournalRow,
    pub(crate) original: Arc<OriginalReservation>,
}
pub(crate) struct AccountSnapshot {
    pub(crate) revision: Revision,
    pub(crate) account: AccountRef,
    pub(crate) rows: Vec<JournalRow>,
    pub(crate) profile_rows: Vec<ProfileSetupRow>,
    pub(crate) key_rows: Vec<KeyPrepareRow>,
    pub(crate) certificate_rows: Vec<CertificateIssuanceRow>,
}

pub(crate) struct AppleProvisioningJournal {
    store: Arc<PrivateStateDirectory>,
    native_use: Arc<NativeUse>,
    failure: Option<StateError>,
    original: Option<Arc<OriginalReservation>>,
    profile_original: Option<Arc<ProfileOriginalReservation>>,
    key_original: Option<Arc<KeyOriginalReservation>>,
    certificate_original: Option<Arc<CertificateOriginalReservation>>,
    #[cfg(test)]
    lose_next_ack: bool,
}
impl AppleProvisioningJournal {
    /// Zero IO. Both inputs come from the SAME original NativeStateLease, not
    /// paths, worker payloads or a fabricated project/client. Parent jobs retain
    /// that lease through all joins; its NativeUse blocks Store.close meanwhile.
    pub(crate) fn new(store: Arc<PrivateStateDirectory>, native_use: Arc<NativeUse>) -> Self {
        Self {
            store,
            native_use,
            failure: None,
            original: None,
            profile_original: None,
            key_original: None,
            certificate_original: None,
            #[cfg(test)]
            lose_next_ack: false,
        }
    }
    pub(crate) fn is_for(
        &self,
        store: &Arc<PrivateStateDirectory>,
        original: &Arc<NativeUse>,
    ) -> bool {
        Arc::ptr_eq(&self.store, store) && Arc::ptr_eq(&self.native_use, original)
    }
    pub(crate) fn failure(&self) -> Option<StateError> {
        self.failure
    }
    /// Retained even if an entered reserve never returned an ACK. This is for
    /// original census/cleanup, NOT permission to retry or send after failure.
    pub(crate) fn retained_reservation(&self) -> Option<&Arc<OriginalReservation>> {
        self.original.as_ref()
    }

    fn reservation_taken(&self) -> bool {
        self.original.is_some() || self.profile_original.is_some() || self.key_original.is_some() || self.certificate_original.is_some()
    }

    fn healthy(&self) -> Result<()> {
        if let Some(error) = self.failure {
            Err(error)
        } else {
            Ok(())
        }
    }
    fn remember<T>(&mut self, result: Result<T>) -> Result<T> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                self.failure.get_or_insert(error);
                Err(error)
            }
        }
    }
    fn load(&mut self) -> Result<(Revision, State)> {
        self.healthy()?;
        let result = (|| {
            self.store.check_native_use(&self.native_use)?;
            let snapshot = self.store.read(Namespace::AppleProvisioning)?;
            let state = State::decode(&snapshot)?;
            Ok((snapshot.revision, state))
        })();
        self.remember(result)
    }
    fn original(&self, original: &OriginalReservation) -> Result<Arc<OriginalReservation>> {
        self.healthy()?;
        let retained = self
            .original
            .as_ref()
            .ok_or_else(|| StateError::from(Error::Conflict))?;
        if !std::ptr::eq(retained.as_ref(), original)
            || !Arc::ptr_eq(&self.native_use, &original.native_use)
        {
            return Err(Error::Conflict.into());
        }
        Ok(retained.clone())
    }
    fn row_index(state: &State, original: &OriginalReservation) -> Result<usize> {
        state
            .rows
            .iter()
            .position(|row| row.intent == original.intent)
            .ok_or_else(|| Error::Conflict.into())
    }
    fn publish(
        &mut self,
        expected: Revision,
        state: &State,
        row: JournalRow,
        original: Arc<OriginalReservation>,
    ) -> Result<JournalAck> {
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
                // The actual original CAS completed, but its consumer did not
                // obtain a usable ACK. Do not retry or synthesize one by read.
                return Err(unknown());
            }
            Ok(JournalAck {
                revision: snapshot.revision,
                row,
                original,
            })
        })();
        self.remember(result)
    }

    /// Full account roster from the real namespace. V1/missing/corrupt state is
    /// an error, never an empty account or permission to create the namespace.
    pub(crate) fn inspect_account(&mut self, account: &AccountRef) -> Result<AccountSnapshot> {
        let (revision, state) = self.load()?;
        Ok(AccountSnapshot {
            revision,
            account: account.clone(),
            key_rows: state.key_rows.into_iter().flatten()
                .filter(|row| &row.intent.context.account_ref == account).collect(),
            certificate_rows: state.certificate_rows.into_iter().flatten()
                .filter(|row| &row.intent.context.account_ref == account).collect(),
            profile_rows: state.profile_rows.into_iter().flatten()
                .filter(|row| &row.intent.context.account_ref == account).collect(),
            rows: state
                .rows
                .into_iter()
                .filter(|row| &row.intent.context.account_ref == account)
                .collect(),
        })
    }

    /// One irreversible armed reservation per port/original operation. Parent
    /// supplies its immutable native-held intent, not an intent from a callback.
    pub(crate) fn reserve(
        &mut self,
        expected: Revision,
        intent: BundleRegistrationIntent,
        armed: AttemptUpdate,
    ) -> Result<JournalAck> {
        self.healthy()?;
        if self.reservation_taken() {
            return Err(Error::Conflict.into());
        }
        intent.validate()?;
        armed.armed(&intent)?;
        let (revision, mut state) = self.load()?;
        if revision != expected {
            return Err(Error::Conflict.into());
        }
        if state.contains_operation(intent.provenance.operation_id.as_str()) {
            return Err(Error::Conflict.into());
        }
        if state.unresolved(&intent.context.account_ref) {
            return Err(Error::RecoveryRequired.into());
        }
        if state.row_count() >= ROWS {
            return Err(Error::Busy.into());
        }
        let row = JournalRow {
            intent: intent.clone(),
            send_armed: true,
            attempt: armed,
            native_settlement: NativeSettlement::Pending,
        };
        row.validate()?;
        state.rows.push(row.clone());
        state.rows.sort_by(|a, b| row_key(a).cmp(&row_key(b)));
        // Validate complete prospective state before recording an IO attempt.
        state.bytes()?;
        let original = Arc::new(OriginalReservation {
            native_use: self.native_use.clone(),
            intent,
        });
        self.original = Some(original.clone());
        self.publish(expected, &state, row, original)
    }

    pub(crate) fn record_attempt(
        &mut self,
        expected: Revision,
        original: &OriginalReservation,
        next: AttemptUpdate,
    ) -> Result<JournalAck> {
        let original = self.original(original)?;
        let (revision, mut state) = self.load()?;
        if revision != expected {
            return Err(Error::Conflict.into());
        }
        let index = Self::row_index(&state, &original)?;
        let row = &mut state.rows[index];
        need(row.native_settlement == NativeSettlement::Pending)?;
        next.follows(&row.attempt, &row.intent)?;
        row.attempt = next;
        let row = row.clone();
        self.publish(expected, &state, row, original)
    }

    /// Parent-provided proof of the SAME actual action originals/pre-final jobs
    /// joined, never the helper's terminal status or a current GET. This final
    /// CAS is itself an original job which the separate AllJobsJoined receipt
    /// must cover before NativeUse can be retired and Store.close can succeed.
    pub(crate) fn finish_native(
        &mut self,
        expected: Revision,
        original: &OriginalReservation,
        joined: &AppleProvisioningNativeJoined,
    ) -> Result<JournalAck> {
        let original = self.original(original)?;
        if !joined.matches(self.native_use.as_ref(), original.as_ref()) {
            return Err(Error::Conflict.into());
        }
        let (revision, mut state) = self.load()?;
        if revision != expected {
            return Err(Error::Conflict.into());
        }
        let index = Self::row_index(&state, &original)?;
        let row = &mut state.rows[index];
        need(row.native_settlement == NativeSettlement::Pending)?;
        row.native_settlement = NativeSettlement::Known;
        let row = row.clone();
        self.publish(expected, &state, row, original)
    }
}

#[cfg(test)]
#[path = "apple_provisioning_journal_tests.rs"]
mod tests;
