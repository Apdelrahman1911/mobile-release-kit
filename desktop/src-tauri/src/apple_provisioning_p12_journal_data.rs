//! Closed local P12-save DATA in the SAME Apple journal, not a provider POST.
//! Rows never recreate a key loan, certificate binding, native receipt or Bind.
use super::*;
use crate::credential_setup::KeyReference;

pub(crate) const P12_PROTOCOL: &str = "mrk-apple-provisioning-journal/4";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum P12LocalAction {
    AssemblePkcs12,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct P12SaveIntent {
    pub(crate) action: P12LocalAction,
    pub(crate) context: ProvisioningContext,
    pub(crate) provenance: NativeProvenance,
    pub(crate) target: ProfileTarget,
    pub(crate) source_p8: KeyReference,
    pub(crate) source_key: KeyReference,
    pub(crate) destination: KeyReference,
    pub(crate) bundle: ProfileBundle,
    pub(crate) certificate: ProfileCertificate,
    pub(crate) csr_sha256: String,
    pub(crate) before_sha256: String,
    pub(crate) request_binding_sha256: String,
    pub(crate) observed_at: String,
    pub(crate) valid_until: String,
    pub(crate) review_sha256: String,
}
impl P12SaveIntent {
    pub(crate) fn review_hash(&self) -> Result<String> {
        hash(&json!({"action":"assemble-pkcs12","target":self.target,
            "sourceP8":self.source_p8,"sourceKey":self.source_key,
            "bundle":self.bundle,"certificate":self.certificate,
            "csrSha256":self.csr_sha256,"beforeSha256":self.before_sha256,
            "observedAt":self.observed_at,"validUntil":self.valid_until}))
    }
    pub(crate) fn sha256(&self) -> Result<String> {
        hash(self)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        need(
            self.context.valid()
                && self.provenance.valid()
                && self.context.operation_id == self.provenance.operation_id.as_str()
                && [&self.source_p8, &self.source_key, &self.destination]
                    .iter()
                    .all(|reference| reference.validate().is_ok())
                && self.source_p8.record_id == self.context.credential_record_id
                && self.source_p8.revision_counter == self.context.credential_revision
                && [&self.source_key, &self.destination]
                    .iter()
                    .all(|reference| {
                        reference.vault_id == self.source_p8.vault_id
                            && reference.generation_id == self.source_p8.generation_id
                    })
                && self.source_key.record_id != self.source_p8.record_id
                && self.destination.record_id != self.source_p8.record_id
                && self.destination.record_id != self.source_key.record_id
                && self.destination.revision_counter == 1
                && self.certificate.certificate_type == "DISTRIBUTION"
                && profile::profile_choice_valid(
                    &self.target,
                    &self.bundle,
                    &self.certificate,
                    None,
                    &self.observed_at,
                )
                && sha(&self.csr_sha256)
                && sha(&self.before_sha256)
                && sha(&self.request_binding_sha256)
                && sha(&self.review_sha256),
        )?;
        need(
            utc_micros(&self.observed_at)
                .zip(utc_micros(&self.valid_until))
                .is_some_and(|(start, end)| end.checked_sub(start) == Some(300_000_000))
                && self.review_hash()? == self.review_sha256,
        )?;
        canonical(self, ROW_LIMIT).map(|_| ())
    }
    /// Duplicate/recovery comparison only, never proof that an old P12 exists
    /// or still matches the key. A fresh actual full readback/assessment is
    /// required to reuse a saved record. No old row is deleted to make room.
    pub(crate) fn same_package(&self, other: &Self) -> bool {
        self.context.account_ref == other.context.account_ref
            && self.target.team_id == other.target.team_id
            && self.certificate.certificate_sha256 == other.certificate.certificate_sha256
            && self.certificate.public_key_sha256 == other.certificate.public_key_sha256
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct P12OutputMetadata {
    pub(crate) frame_bytes: u32,
    pub(crate) frame_sha256: String,
    pub(crate) p12_bytes: u32,
    pub(crate) p12_sha256: String,
    pub(crate) certificate_sha256: String,
    pub(crate) public_key_sha256: String,
}
impl P12OutputMetadata {
    pub(crate) fn bounded(&self) -> bool {
        let header = b"MRK-APPLE-P12/1\n".len() + 4 + 64;
        self.p12_bytes > 0
            && self.p12_bytes <= 1024 * 1024
            && (self.p12_bytes as usize).checked_add(header) == Some(self.frame_bytes as usize)
            && sha(&self.frame_sha256)
            && sha(&self.p12_sha256)
            && sha(&self.certificate_sha256)
            && sha(&self.public_key_sha256)
    }
    pub(crate) fn valid(&self, intent: &P12SaveIntent) -> bool {
        self.bounded()
            && self.certificate_sha256 == intent.certificate.certificate_sha256
            && self.public_key_sha256 == intent.certificate.public_key_sha256
    }
    pub(crate) fn sha256(&self) -> Result<String> {
        hash(self)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum P12Assembly {
    Armed,
    NoOutputRetained,
    Returned,
    Unknown,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum P12Disposition {
    Running,
    SavedUnassigned,
    Refused,
    Unknown,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct P12SaveUpdate {
    pub(crate) sequence: u32,
    pub(crate) assembly: P12Assembly,
    #[serde(deserialize_with = "required_option")]
    pub(crate) output: Option<P12OutputMetadata>,
    pub(crate) save: ProfileSaveState,
    #[serde(deserialize_with = "required_option")]
    pub(crate) saved_reference: Option<KeyReference>,
    pub(crate) disposition: P12Disposition,
    pub(crate) cancel_requested: bool,
}
impl P12SaveUpdate {
    pub(crate) fn validate(&self, intent: &P12SaveIntent) -> Result<()> {
        need(
            (1..=ATTEMPT_LIMIT).contains(&self.sequence)
                && self.output.as_ref().is_none_or(|out| out.valid(intent))
                && self
                    .saved_reference
                    .as_ref()
                    .is_none_or(|reference| reference == &intent.destination)
                && (self.save == ProfileSaveState::ReadBack) == self.saved_reference.is_some(),
        )?;
        match self.assembly {
            P12Assembly::Armed => need(
                self.output.is_none()
                    && self.save == ProfileSaveState::NotEntered
                    && self.disposition == P12Disposition::Running,
            )?,
            P12Assembly::NoOutputRetained => need(
                self.output.is_none()
                    && self.save == ProfileSaveState::NotEntered
                    && self.disposition == P12Disposition::Refused,
            )?,
            P12Assembly::Returned => need(self.output.is_some())?,
            P12Assembly::Unknown => need(
                self.disposition == P12Disposition::Unknown
                    && matches!(
                        self.save,
                        ProfileSaveState::NotEntered | ProfileSaveState::Unknown
                    ),
            )?,
        }
        match self.save {
            ProfileSaveState::NotEntered => need(matches!(
                self.disposition,
                P12Disposition::Running | P12Disposition::Refused | P12Disposition::Unknown
            ))?,
            ProfileSaveState::Armed | ProfileSaveState::Written => need(
                self.assembly == P12Assembly::Returned
                    && matches!(
                        self.disposition,
                        P12Disposition::Running | P12Disposition::Unknown
                    ),
            )?,
            ProfileSaveState::ReadBack => need(
                self.assembly == P12Assembly::Returned
                    && self.disposition == P12Disposition::SavedUnassigned,
            )?,
            ProfileSaveState::Unknown => need(self.disposition == P12Disposition::Unknown)?,
        }
        if self.disposition == P12Disposition::Refused {
            need(
                matches!(
                    self.assembly,
                    P12Assembly::NoOutputRetained | P12Assembly::Returned
                ) && self.save == ProfileSaveState::NotEntered
                    && self.saved_reference.is_none(),
            )?;
        }
        canonical(self, ROW_LIMIT).map(|_| ())
    }
    pub(crate) fn sha256(&self) -> Result<String> {
        hash(self)
    }
    pub(in crate::apple_provisioning_journal) fn initial(
        &self,
        intent: &P12SaveIntent,
    ) -> Result<()> {
        self.validate(intent)?;
        need(
            self.sequence == 1
                && self.assembly == P12Assembly::Armed
                && self.disposition == P12Disposition::Running
                && !self.cancel_requested,
        )
    }
    pub(in crate::apple_provisioning_journal) fn follows(
        &self,
        old: &Self,
        intent: &P12SaveIntent,
    ) -> Result<()> {
        self.validate(intent)?;
        need(
            old.sequence.checked_add(1) == Some(self.sequence)
                && (!old.cancel_requested || self.cancel_requested)
                && old
                    .output
                    .as_ref()
                    .is_none_or(|out| self.output.as_ref() == Some(out))
                && old
                    .saved_reference
                    .as_ref()
                    .is_none_or(|reference| self.saved_reference.as_ref() == Some(reference))
                && match old.assembly {
                    P12Assembly::Armed => true,
                    P12Assembly::Returned => self.assembly == P12Assembly::Returned,
                    P12Assembly::NoOutputRetained => self.assembly == P12Assembly::NoOutputRetained,
                    P12Assembly::Unknown => self.assembly == P12Assembly::Unknown,
                }
                && match old.save {
                    ProfileSaveState::NotEntered => true,
                    ProfileSaveState::Armed => self.save != ProfileSaveState::NotEntered,
                    ProfileSaveState::Written => matches!(
                        self.save,
                        ProfileSaveState::Written
                            | ProfileSaveState::ReadBack
                            | ProfileSaveState::Unknown
                    ),
                    ProfileSaveState::ReadBack => self.save == ProfileSaveState::ReadBack,
                    ProfileSaveState::Unknown => self.save == ProfileSaveState::Unknown,
                }
                && match old.disposition {
                    P12Disposition::Running => true,
                    other => self.disposition == other,
                },
        )
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct P12SaveRow {
    pub(crate) intent: P12SaveIntent,
    pub(crate) assembly_armed: bool,
    pub(crate) update: P12SaveUpdate,
    pub(crate) native_settlement: NativeSettlement,
}
impl P12SaveRow {
    pub(crate) fn validate(&self) -> Result<()> {
        self.intent.validate()?;
        self.update.validate(&self.intent)?;
        need(
            self.assembly_armed
                && (self.native_settlement == NativeSettlement::Pending
                    || self.update.disposition != P12Disposition::Running),
        )?;
        canonical(self, ROW_LIMIT).map(|_| ())
    }
    pub(crate) fn unresolved(&self) -> bool {
        self.native_settlement != NativeSettlement::Known
            || !matches!(
                self.update.disposition,
                P12Disposition::SavedUnassigned | P12Disposition::Refused
            )
    }
}
