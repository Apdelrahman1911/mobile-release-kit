//! Closed, reference-only v3 DATA in the existing Apple journal namespace.
//! Neither an armed generator row nor an output hash is proof that a key was
//! generated, saved, restored or retired. Only the original parent owns those
//! cuts. Old Bundle/Profile rows are not transformed by this module.
use super::*;
use crate::credential_setup::KeyReference;

pub(crate) const KEY_PROTOCOL: &str = "mrk-apple-provisioning-journal/3";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum KeyAlgorithm {
    // This is a fixed implementation profile, never caller-selected key size,
    // exponent, digest, subject, extension or OpenSSL arguments.
    Rsa2048Sha256,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KeyPrepareIntent {
    pub(crate) context: ProvisioningContext,
    pub(crate) provenance: NativeProvenance,
    pub(crate) target: ProfileTarget,
    pub(crate) source_p8: KeyReference,
    pub(crate) destination: KeyReference,
    pub(crate) algorithm: KeyAlgorithm,
    pub(crate) bundle: ProfileBundle,
    pub(crate) observed_at: String,
    pub(crate) valid_until: String,
    pub(crate) before_sha256: String,
    pub(crate) review_plan_sha256: String,
}
impl KeyPrepareIntent {
    pub(crate) fn review_hash(&self) -> Result<String> {
        hash(
            &json!({"context":self.context.core_value(),"target":self.target.core_value(),
            "observation":self.before_sha256,"validUntil":self.valid_until,
            "action":"prepare_csr","reason":"native_signing_key_and_csr_required",
            "request":null,"binding":null,"selection":{"bundle":self.bundle.core_hash()?,
                "certificate":null,"profile":null},"csr":null}),
        )
    }
    pub(crate) fn sha256(&self) -> Result<String> {
        hash(self)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        need(
            self.context.valid()
                && self.provenance.valid()
                && self.target.valid()
                && self.context.operation_id == self.provenance.operation_id.as_str()
                && self.source_p8.validate().is_ok()
                && self.destination.validate().is_ok()
                && self.source_p8.record_id == self.context.credential_record_id
                && self.source_p8.revision_counter == self.context.credential_revision
                && self.destination.vault_id == self.source_p8.vault_id
                && self.destination.generation_id == self.source_p8.generation_id
                && self.destination.record_id != self.source_p8.record_id
                && self.destination.revision_counter == 1
                && self.bundle.valid(&self.target)
                && sha(&self.before_sha256)
                && sha(&self.review_plan_sha256),
        )?;
        let observed = utc_micros(&self.observed_at);
        let until = utc_micros(&self.valid_until);
        need(
            observed
                .zip(until)
                .is_some_and(|(start, end)| end.checked_sub(start) == Some(300_000_000))
                && self.review_hash()? == self.review_plan_sha256,
        )?;
        // No inventory/absence booleans are accepted. The SAME original review
        // must still retain a complete provider and native-vault inventory.
        canonical(self, ROW_LIMIT).map(|_| ())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KeyOutputMetadata {
    pub(crate) frame_bytes: u32,
    pub(crate) frame_sha256: String,
    pub(crate) csr_sha256: String,
    pub(crate) public_key_sha256: String,
}
impl KeyOutputMetadata {
    pub(crate) fn sha256(&self) -> Result<String> {
        hash(self)
    }
    pub(crate) fn valid(&self) -> bool {
        self.frame_bytes as usize > b"MRK-APPLE-DISTRIBUTION-KEY/1\n".len() + 12
            && self.frame_bytes as usize <= crate::asset_commands::APPLE_KEY_PRIVATE_FRAME_LIMIT
            && sha(&self.frame_sha256)
            && sha(&self.csr_sha256)
            && sha(&self.public_key_sha256)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum KeyGeneration {
    Armed,
    NotEntered,
    Returned,
    Unknown,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum KeyDisposition {
    Running,
    Prepared,
    Cancelled,
    Failed,
    Unknown,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KeyPrepareUpdate {
    pub(crate) sequence: u32,
    pub(crate) generation: KeyGeneration,
    #[serde(deserialize_with = "required_option")]
    pub(crate) output: Option<KeyOutputMetadata>,
    pub(crate) save: ProfileSaveState,
    #[serde(deserialize_with = "required_option")]
    pub(crate) saved_reference: Option<KeyReference>,
    pub(crate) disposition: KeyDisposition,
    pub(crate) cancel_requested: bool,
}
impl KeyPrepareUpdate {
    pub(crate) fn sha256(&self) -> Result<String> {
        hash(self)
    }
    pub(crate) fn validate(&self, intent: &KeyPrepareIntent) -> Result<()> {
        need(
            (1..=ATTEMPT_LIMIT).contains(&self.sequence)
                && self.output.as_ref().is_none_or(KeyOutputMetadata::valid)
                && self
                    .saved_reference
                    .as_ref()
                    .is_none_or(|reference| reference == &intent.destination)
                && (self.disposition != KeyDisposition::Cancelled || self.cancel_requested),
        )?;
        match self.generation {
            KeyGeneration::Armed => need(
                self.output.is_none()
                    && self.save == ProfileSaveState::NotEntered
                    && self.saved_reference.is_none()
                    && self.disposition == KeyDisposition::Running,
            )?,
            KeyGeneration::NotEntered => need(
                self.output.is_none()
                    && self.save == ProfileSaveState::NotEntered
                    && self.saved_reference.is_none()
                    && matches!(
                        self.disposition,
                        KeyDisposition::Cancelled | KeyDisposition::Failed
                    ),
            )?,
            KeyGeneration::Returned => {
                need(self.output.is_some() && !matches!(self.save, ProfileSaveState::NotEntered))?
            }
            KeyGeneration::Unknown => need(
                self.disposition == KeyDisposition::Unknown
                    && matches!(
                        self.save,
                        ProfileSaveState::NotEntered | ProfileSaveState::Unknown
                    )
                    && self.saved_reference.is_none(),
            )?,
        }
        need((self.save == ProfileSaveState::ReadBack) == self.saved_reference.is_some())?;
        if self.save == ProfileSaveState::ReadBack {
            need(
                self.generation == KeyGeneration::Returned
                    && matches!(
                        self.disposition,
                        KeyDisposition::Prepared
                            | KeyDisposition::Cancelled
                            | KeyDisposition::Failed
                    ),
            )?;
        } else {
            need(self.disposition != KeyDisposition::Prepared)?;
        }
        if self.save == ProfileSaveState::Unknown {
            need(self.disposition == KeyDisposition::Unknown)?;
        }
        canonical(self, ROW_LIMIT).map(|_| ())
    }
    pub(in crate::apple_provisioning_journal) fn initial(
        &self,
        intent: &KeyPrepareIntent,
    ) -> Result<()> {
        self.validate(intent)?;
        need(
            self.sequence == 1
                && self.generation == KeyGeneration::Armed
                && self.output.is_none()
                && self.save == ProfileSaveState::NotEntered
                && self.saved_reference.is_none()
                && self.disposition == KeyDisposition::Running
                && !self.cancel_requested,
        )
    }
    pub(in crate::apple_provisioning_journal) fn follows(
        &self,
        previous: &Self,
        intent: &KeyPrepareIntent,
    ) -> Result<()> {
        self.validate(intent)?;
        previous.validate(intent)?;
        need(
            previous.sequence.checked_add(1) == Some(self.sequence)
                && (!previous.cancel_requested || self.cancel_requested)
                && previous
                    .output
                    .as_ref()
                    .is_none_or(|old| self.output.as_ref() == Some(old))
                && previous
                    .saved_reference
                    .as_ref()
                    .is_none_or(|old| self.saved_reference.as_ref() == Some(old)),
        )?;
        match previous.generation {
            KeyGeneration::Armed => need(matches!(
                self.generation,
                KeyGeneration::Armed
                    | KeyGeneration::NotEntered
                    | KeyGeneration::Returned
                    | KeyGeneration::Unknown
            ))?,
            KeyGeneration::NotEntered => need(self.generation == KeyGeneration::NotEntered)?,
            KeyGeneration::Returned => need(self.generation == KeyGeneration::Returned)?,
            KeyGeneration::Unknown => need(self.generation == KeyGeneration::Unknown)?,
        }
        // A lost/unknown output/save cannot be transformed into a second
        // generation opportunity, even if a later read finds no target file.
        match previous.save {
            ProfileSaveState::NotEntered => need(matches!(
                self.save,
                ProfileSaveState::NotEntered | ProfileSaveState::Armed | ProfileSaveState::Unknown
            ))?,
            ProfileSaveState::Armed => need(matches!(
                self.save,
                ProfileSaveState::Armed
                    | ProfileSaveState::Written
                    | ProfileSaveState::ReadBack
                    | ProfileSaveState::Unknown
            ))?,
            ProfileSaveState::Written => need(matches!(
                self.save,
                ProfileSaveState::Written | ProfileSaveState::ReadBack | ProfileSaveState::Unknown
            ))?,
            ProfileSaveState::ReadBack => need(self.save == ProfileSaveState::ReadBack)?,
            ProfileSaveState::Unknown => need(self.save == ProfileSaveState::Unknown)?,
        }
        match previous.disposition {
            KeyDisposition::Running => (),
            KeyDisposition::Prepared => need(matches!(
                self.disposition,
                KeyDisposition::Prepared | KeyDisposition::Cancelled
            ))?,
            KeyDisposition::Cancelled => need(self.disposition == KeyDisposition::Cancelled)?,
            KeyDisposition::Failed => need(self.disposition == KeyDisposition::Failed)?,
            KeyDisposition::Unknown => need(self.disposition == KeyDisposition::Unknown)?,
        }
        // Only cancellation may alter an already completed disposition. No
        // change to generation/output/save/reference is smuggled into it.
        if previous.disposition != KeyDisposition::Running {
            let mut expected = previous.clone();
            expected.sequence = self.sequence;
            expected.disposition = self.disposition;
            expected.cancel_requested = self.cancel_requested;
            need(&expected == self)?;
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KeyPrepareRow {
    pub(crate) intent: KeyPrepareIntent,
    pub(crate) generator_armed: bool,
    pub(crate) update: KeyPrepareUpdate,
    pub(crate) native_settlement: NativeSettlement,
}
impl KeyPrepareRow {
    pub(crate) fn validate(&self) -> Result<()> {
        self.intent.validate()?;
        self.update.validate(&self.intent)?;
        need(self.generator_armed)?;
        canonical(self, ROW_LIMIT).map(|_| ())
    }
    pub(crate) fn unresolved(&self) -> bool {
        self.native_settlement != NativeSettlement::Known
            || match self.update.generation {
                KeyGeneration::NotEntered => !matches!(
                    self.update.disposition,
                    KeyDisposition::Cancelled | KeyDisposition::Failed
                ),
                KeyGeneration::Returned => self.update.save != ProfileSaveState::ReadBack,
                KeyGeneration::Armed | KeyGeneration::Unknown => true,
            }
    }
}

/// A separate certificate operation always freshly reads/verifies source_key.
/// The persisted key-prepare row is history, not its keySaved/POST capability.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CertificateIssuanceIntent {
    pub(crate) context: ProvisioningContext,
    pub(crate) provenance: NativeProvenance,
    pub(crate) target: ProfileTarget,
    pub(crate) source_key: KeyReference,
    pub(crate) source_p8: KeyReference,
    pub(crate) bundle: ProfileBundle,
    pub(crate) csr_sha256: String,
    pub(crate) public_key_sha256: String,
    pub(crate) observed_at: String,
    pub(crate) valid_until: String,
    pub(crate) before_sha256: String,
    pub(crate) plan_sha256: String,
    pub(crate) request_body_sha256: String,
}
impl CertificateIssuanceIntent {
    pub(crate) fn plan_hash(&self) -> Result<String> {
        hash(
            &json!({"context":self.context.core_value(),"target":self.target.core_value(),
            "observation":self.before_sha256,"validUntil":self.valid_until,
            "action":"create_certificate","reason":"certificate_issuance_requires_approval",
            "request":{"kind":"create_certificate","method":"POST","path":"/v1/certificates",
                "query":[],"bodySha256":self.request_body_sha256},"binding":null,
            "selection":{"bundle":self.bundle.core_hash()?,"certificate":null,"profile":null},
            "csr":{"keyRef":profile::key_value(&self.source_key),"publicKeySha256":self.public_key_sha256,
                "csrSha256":self.csr_sha256}}),
        )
    }
    pub(crate) fn validate(&self) -> Result<()> {
        need(
            self.context.valid()
                && self.provenance.valid()
                && self.target.valid()
                && self.context.operation_id == self.provenance.operation_id.as_str()
                && self.source_key.validate().is_ok()
                && self.source_p8.validate().is_ok()
                && self.source_p8.record_id == self.context.credential_record_id
                && self.source_p8.revision_counter == self.context.credential_revision
                && self.source_key.vault_id == self.source_p8.vault_id
                && self.source_key.generation_id == self.source_p8.generation_id
                && self.source_key.record_id != self.source_p8.record_id
                && self.bundle.valid(&self.target)
                && sha(&self.csr_sha256)
                && sha(&self.public_key_sha256)
                && sha(&self.before_sha256)
                && sha(&self.plan_sha256)
                && sha(&self.request_body_sha256),
        )?;
        need(
            utc_micros(&self.observed_at)
                .zip(utc_micros(&self.valid_until))
                .is_some_and(|(start, end)| end.checked_sub(start) == Some(300_000_000))
                && self.plan_hash()? == self.plan_sha256,
        )?;
        // The exact request body/CSR is compared by the actual native phase
        // against its fresh original loan. A digest cannot recreate that loan.
        canonical(self, ROW_LIMIT).map(|_| ())
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CertificateCreateAction {
    CreateCertificate,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CertificateAttemptRecord {
    pub(crate) context: ProvisioningContext,
    pub(crate) plan_sha256: String,
    pub(crate) action: CertificateCreateAction,
    pub(crate) status: AttemptStatus,
    pub(crate) reason: AttemptReason,
    pub(crate) possible_send: bool,
    #[serde(deserialize_with = "required_option")]
    pub(crate) response_resource_id: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub(crate) response_resource_sha256: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub(crate) observed_resource_id: Option<String>,
    pub(crate) cancel_requested: bool,
}
impl CertificateAttemptRecord {
    fn fields(&self) -> AttemptRecord {
        // Reuse exact existing cancellation/no-send FIELDS, not its action
        // grammar, journal port, authorization or full original reservation.
        AttemptRecord {
            context: self.context.clone(),
            plan_sha256: self.plan_sha256.clone(),
            action: Action::RegisterBundleId,
            status: self.status,
            reason: self.reason,
            possible_send: self.possible_send,
            response_resource_id: self.response_resource_id.clone(),
            response_resource_sha256: self.response_resource_sha256.clone(),
            observed_resource_id: self.observed_resource_id.clone(),
            cancel_requested: self.cancel_requested,
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CertificateCreationReceipt {
    pub(crate) schema_version: u32,
    pub(crate) resource_id: String,
    #[serde(deserialize_with = "required_option")]
    pub(crate) certificate_type: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub(crate) expires_at: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub(crate) certificate_sha256: Option<String>,
}
impl CertificateCreationReceipt {
    pub(crate) fn sha256(&self) -> Result<String> {
        need(
            self.schema_version == 1
                && identifier(&self.resource_id)
                && self
                    .certificate_type
                    .as_deref()
                    .is_none_or(|kind| kind == "DISTRIBUTION")
                && self
                    .expires_at
                    .as_deref()
                    .is_none_or(|time| utc_micros(time).is_some())
                && self.certificate_sha256.as_deref().is_none_or(sha),
        )?;
        let mut digest = Sha256::new();
        digest.update(b"MRK-APPLE-CERTIFICATE-CREATION-RECEIPT/1\0");
        digest.update(canonical(self, 1024)?);
        Ok(hex(&digest.finalize()))
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CertificateUpdate {
    pub(crate) sequence: u32,
    pub(crate) record: CertificateAttemptRecord,
    #[serde(deserialize_with = "required_option")]
    pub(crate) receipt: Option<CertificateCreationReceipt>,
}
impl CertificateUpdate {
    pub(crate) fn sha256(&self) -> Result<String> {
        hash(self)
    }
    pub(crate) fn validate(&self, intent: &CertificateIssuanceIntent) -> Result<()> {
        need((1..=ATTEMPT_LIMIT).contains(&self.sequence))?;
        self.record
            .fields()
            .validate_fields(&intent.context, &intent.plan_sha256)?;
        match &self.receipt {
            Some(receipt) => need(
                self.record.response_resource_id.as_ref() == Some(&receipt.resource_id)
                    && self.record.response_resource_sha256.as_ref() == Some(&receipt.sha256()?),
            )?,
            None => need(
                self.record.response_resource_id.is_none()
                    && self.record.response_resource_sha256.is_none(),
            )?,
        }
        canonical(self, ROW_LIMIT).map(|_| ())
    }
    pub(in crate::apple_provisioning_journal) fn initial(
        &self,
        intent: &CertificateIssuanceIntent,
    ) -> Result<()> {
        self.validate(intent)?;
        need(
            self.sequence == 1
                && self.receipt.is_none()
                && self.record.status == AttemptStatus::Running
                && self.record.reason == AttemptReason::ReadbackRequired
                && self.record.possible_send
                && self.record.observed_resource_id.is_none()
                && !self.record.cancel_requested,
        )
    }
    pub(in crate::apple_provisioning_journal) fn follows(
        &self,
        old: &Self,
        intent: &CertificateIssuanceIntent,
    ) -> Result<()> {
        self.validate(intent)?;
        need(
            old.receipt
                .as_ref()
                .is_none_or(|value| self.receipt.as_ref() == Some(value)),
        )?;
        AttemptUpdate {
            sequence: self.sequence,
            record: self.record.fields(),
        }
        .follows_fields(
            &AttemptUpdate {
                sequence: old.sequence,
                record: old.record.fields(),
            },
            &intent.context,
            &intent.plan_sha256,
        )
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CertificateIssuanceRow {
    pub(crate) intent: CertificateIssuanceIntent,
    pub(crate) send_armed: bool,
    pub(crate) update: CertificateUpdate,
    pub(crate) native_settlement: NativeSettlement,
}
impl CertificateIssuanceRow {
    pub(crate) fn validate(&self) -> Result<()> {
        self.intent.validate()?;
        self.update.validate(&self.intent)?;
        need(self.send_armed)?;
        canonical(self, ROW_LIMIT).map(|_| ())
    }
    pub(crate) fn unresolved(&self) -> bool {
        self.native_settlement != NativeSettlement::Known || !self.update.record.status.terminal()
    }
}

#[cfg(test)]
#[path = "apple_provisioning_key_journal_data_tests.rs"]
pub(in crate::apple_provisioning_journal) mod tests;
