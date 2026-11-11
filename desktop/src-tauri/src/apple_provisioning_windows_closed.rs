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
