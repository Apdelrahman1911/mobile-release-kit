//! Closed journal DATA only; native reservations/ACKs cannot be constructed.
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
pub(crate) use data::p12::*;
pub(crate) use data::key_recovery::{KeyRecoveryOrigin,KeyRecoveryRecord,KEY_RECOVERY_PROTOCOL,
    durable_key_row,key_row_sha256,key_recovery_for,validate_key_recoveries};

use std::sync::Arc;
use crate::application_state_store::Revision;
pub(crate) enum OriginalReservation {}
impl OriginalReservation { pub(crate) fn intent(&self) -> &BundleRegistrationIntent { match *self {} } }
pub(crate) enum ProfileOriginalReservation {}
impl ProfileOriginalReservation { pub(crate) fn intent(&self) -> &ProfileSetupIntent { match *self {} } }
pub(crate) enum KeyOriginalReservation {}
impl KeyOriginalReservation { pub(crate) fn intent(&self) -> &KeyPrepareIntent { match *self {} } }
pub(crate) enum CertificateOriginalReservation {}
impl CertificateOriginalReservation { pub(crate) fn intent(&self) -> &CertificateIssuanceIntent { match *self {} } }
pub(crate) enum P12OriginalReservation {}
impl P12OriginalReservation { pub(crate) fn intent(&self) -> &P12SaveIntent { match *self {} } }
pub(crate) struct ProfileJournalAck { pub(crate) revision: Revision, pub(crate) row: ProfileSetupRow, pub(crate) original: Arc<ProfileOriginalReservation> }
pub(crate) struct KeyJournalAck { pub(crate) revision: Revision, pub(crate) row: KeyPrepareRow, pub(crate) original: Arc<KeyOriginalReservation> }
pub(crate) struct CertificateJournalAck { pub(crate) revision: Revision, pub(crate) row: CertificateIssuanceRow, pub(crate) original: Arc<CertificateOriginalReservation> }
pub(crate) struct P12JournalAck { pub(crate) revision: Revision, pub(crate) row: P12SaveRow, pub(crate) original: Arc<P12OriginalReservation> }
pub(crate) enum KeyRecoveryWrite {}
impl KeyRecoveryWrite {pub(crate) fn record(&self)->&KeyRecoveryRecord {match *self {}}}
pub(crate) struct KeyRecoveryJournalAck {pub(crate) revision:Revision,pub(crate) original:Arc<KeyRecoveryWrite>}
pub(crate) enum ProvisioningStatePort {}

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
    pub(crate) p12_rows: Vec<P12SaveRow>,
    pub(crate) key_recoveries: Vec<KeyRecoveryRecord>,
}

use std::collections::BTreeSet;
type Result<T> = std::result::Result<T, crate::application_state_store::StateError>;
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
