//! Reference-only profile arm of the SAME Apple provisioning journal.
//! Full references and hashes compare an original native review; they cannot
//! recreate that review, a P12 loan, a reserved destination or any join fact.
//! In particular before_sha256 is NOT an assertion of inventory completeness.
use super::*;
use crate::credential_setup::KeyReference;

pub(crate) const PROFILE_PROTOCOL: &str = "mrk-apple-provisioning-journal/2";
pub(crate) const PROFILE_BYTES: u32 = 1024 * 1024;

/// Closed comparison helpers for the original profile phase decoder. They
/// reuse this journal's canonical encoder/time parser; none creates an intent,
/// loan, native clock, completeness claim or permission to save.
pub(crate) fn profile_unix_micros(value: &str) -> Option<u64> {
    utc_micros(value)?.checked_sub(62_135_596_800_000_000)
}
pub(crate) fn profile_entitlements_sha256(value: &Value) -> Result<String> {
    need(value.is_object())?;
    Ok(hex(&Sha256::digest(canonical(value, 16 * 1024)?)))
}
pub(crate) fn profile_identity_sha256(value: &Value) -> Result<String> {
    // The phase codec separately admits the exact six-field identity shape.
    Ok(hex(&Sha256::digest(canonical(value, 128 * 1024)?)))
}
pub(crate) fn profile_choice_valid(
    target: &ProfileTarget,
    bundle: &ProfileBundle,
    certificate: &ProfileCertificate,
    profile: Option<&ProfileSelection>,
    observed_at: &str,
) -> bool {
    let Some(observed) = utc_micros(observed_at) else { return false; };
    target.valid() && bundle.valid(target) && certificate.valid(observed)
        && profile.is_none_or(|row| {
            identifier(&row.resource_id) && name(&row.name) && uuid(&row.uuid)
                && row.bundle_id_resource == bundle.resource_id
                && row.certificate_resource == certificate.resource_id
                && utc_micros(&row.created_at).is_some_and(|created| created <= observed)
                && utc_micros(&row.expires_at).is_some_and(|expires| observed < expires)
        })
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProfileAction {
    ReuseDownload,
    CreateProfile,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProfileTarget {
    pub(crate) bundle_id: String,
    pub(crate) team_id: String,
    pub(crate) app_id_prefix: String,
    pub(crate) display_name: String,
    pub(crate) existing_application: bool,
    pub(crate) entitlements_sha256: String,
}
impl ProfileTarget {
    fn valid(&self) -> bool {
        // Reuse the existing modern Bundle grammar without changing its
        // new-application-only rule. This copied value is validation DATA.
        BundleTarget {
            bundle_id: self.bundle_id.clone(),
            team_id: self.team_id.clone(),
            app_id_prefix: self.app_id_prefix.clone(),
            display_name: self.display_name.clone(),
            existing_application: false,
        }
        .valid()
            && sha(&self.entitlements_sha256)
    }
    fn core_value(&self) -> Value {
        json!({"bundle_id":self.bundle_id,"team_id":self.team_id,
            "app_id_prefix":self.app_id_prefix,"display_name":self.display_name,
            "existing_application":self.existing_application,
            "entitlements_json":self.entitlements_sha256})
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProfileBundle {
    pub(crate) resource_id: String,
    pub(crate) identifier: String,
    pub(crate) platform: String,
    pub(crate) seed_id: String,
}
impl ProfileBundle {
    fn valid(&self, target: &ProfileTarget) -> bool {
        identifier(&self.resource_id)
            && self.identifier == target.bundle_id
            && matches!(self.platform.as_str(), "IOS" | "UNIVERSAL")
            && self.seed_id == target.app_id_prefix
    }
    fn core_hash(&self) -> Result<String> {
        hash(&json!([
            "bundleIds",
            self.resource_id,
            self.identifier,
            self.platform,
            self.seed_id
        ]))
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProfileCertificate {
    pub(crate) resource_id: String,
    pub(crate) certificate_type: String,
    pub(crate) not_before: String,
    pub(crate) expires_at: String,
    pub(crate) certificate_sha256: String,
    pub(crate) public_key_sha256: String,
}
impl ProfileCertificate {
    fn valid(&self, observed: u64) -> bool {
        identifier(&self.resource_id)
            && matches!(
                self.certificate_type.as_str(),
                "DISTRIBUTION" | "IOS_DISTRIBUTION"
            )
            && sha(&self.certificate_sha256)
            && sha(&self.public_key_sha256)
            && utc_micros(&self.not_before).is_some_and(|before| before <= observed)
            && utc_micros(&self.expires_at).is_some_and(|after| observed < after)
    }
    fn core_hash(&self) -> Result<String> {
        hash(&json!([
            "certificates",
            self.resource_id,
            self.certificate_type,
            self.expires_at,
            self.certificate_sha256
        ]))
    }
    fn binding_value(&self, target: &ProfileTarget, key: &KeyReference) -> Value {
        json!({"certificate_id":self.resource_id,"certificate_sha256":self.certificate_sha256,
            "public_key_sha256":self.public_key_sha256,"key_ref":key_value(key),
            "team_id":target.team_id,"not_before":self.not_before,"not_after":self.expires_at})
    }
}
fn key_value(key: &KeyReference) -> Value {
    json!({"vault_id":key.vault_id,"generation_id":key.generation_id,
        "record_id":key.record_id,"revision_id":key.revision_id,
        "revision_counter":key.revision_counter})
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)
            }
        })
}
fn name(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= 128
        && !value.chars().any(|ch| ch < '\u{20}' || ch == '\u{7f}')
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProfileSelection {
    pub(crate) resource_id: String,
    pub(crate) name: String,
    pub(crate) uuid: String,
    pub(crate) created_at: String,
    pub(crate) expires_at: String,
    pub(crate) bundle_id_resource: String,
    pub(crate) certificate_resource: String,
}
impl ProfileSelection {
    fn valid(&self, intent: &ProfileSetupIntent) -> bool {
        identifier(&self.resource_id)
            && name(&self.name)
            && uuid(&self.uuid)
            && self.bundle_id_resource == intent.bundle.resource_id
            && self.certificate_resource == intent.certificate.resource_id
            && utc_micros(&self.created_at)
                .zip(utc_micros(&self.expires_at))
                .is_some_and(|(created, expires)| created < expires)
    }
    pub(crate) fn sha256(&self) -> Result<String> {
        hash(&json!([
            "profiles",
            self.resource_id,
            self.name,
            self.uuid,
            "ACTIVE",
            self.created_at,
            self.expires_at,
            self.bundle_id_resource,
            [self.certificate_resource]
        ]))
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProfileSetupIntent {
    pub(crate) context: ProvisioningContext,
    pub(crate) provenance: NativeProvenance,
    pub(crate) target: ProfileTarget,
    pub(crate) action: ProfileAction,
    pub(crate) source_key: KeyReference,
    pub(crate) destination: KeyReference,
    pub(crate) bundle: ProfileBundle,
    pub(crate) certificate: ProfileCertificate,
    #[serde(deserialize_with = "required_option")]
    pub(crate) profile: Option<ProfileSelection>,
    pub(crate) observed_at: String,
    pub(crate) valid_until: String,
    pub(crate) before_sha256: String,
    pub(crate) plan_sha256: String,
    #[serde(deserialize_with = "required_option")]
    pub(crate) request_body_sha256: Option<String>,
}
impl ProfileSetupIntent {
    pub(crate) fn profile_name(&self) -> String {
        let digest = hex(&Sha256::digest(self.context.operation_id.as_bytes()));
        format!("MRK-{}", &digest[..24])
    }
    fn request(&self) -> Result<Value> {
        match self.action {
            ProfileAction::CreateProfile => {
                let body = json!({"data":{"type":"profiles","attributes":{
                    "name":self.profile_name(),"profileType":"IOS_APP_STORE"},
                    "relationships":{"bundleId":{"data":{"type":"bundleIds","id":self.bundle.resource_id}},
                        "certificates":{"data":[{"type":"certificates","id":self.certificate.resource_id}]}}}});
                need(self.request_body_sha256.as_ref() == Some(&hash(&body)?))?;
                Ok(
                    json!({"kind":"create_profile","method":"POST","path":"/v1/profiles",
                    "query":[],"bodySha256":self.request_body_sha256}),
                )
            }
            ProfileAction::ReuseDownload => {
                let profile = self
                    .profile
                    .as_ref()
                    .ok_or_else(|| StateError::from(Error::InvalidRequest))?;
                need(self.request_body_sha256.is_none())?;
                Ok(json!({"kind":"download_profile","method":"GET",
                    "path":format!("/v1/profiles/{}",profile.resource_id),
                    "query":[["fields[profiles]","name,platform,profileType,profileState,uuid,createdDate,expirationDate,bundleId,certificates,profileContent"],
                        ["include","bundleId,certificates"],["fields[bundleIds]","identifier,platform,seedId"],
                        ["fields[certificates]","certificateType,platform,expirationDate"]],"bodySha256":null}))
            }
        }
    }
    fn plan_hash(&self) -> Result<String> {
        let (action, reason) = match self.action {
            ProfileAction::CreateProfile => {
                ("create_profile", "profile_creation_requires_approval")
            }
            ProfileAction::ReuseDownload => ("download_profile", "reuse_existing_assets"),
        };
        hash(
            &json!({"context":self.context.core_value(),"target":self.target.core_value(),
            "observation":self.before_sha256,"validUntil":self.valid_until,
            "action":action,"reason":reason,"request":self.request()?,
            "binding":self.certificate.binding_value(&self.target,&self.source_key),
            "selection":{"bundle":self.bundle.core_hash()?,"certificate":self.certificate.core_hash()?,
                "profile":self.profile.as_ref().map(ProfileSelection::sha256).transpose()?},"csr":null}),
        )
    }
    pub(crate) fn validate(&self) -> Result<()> {
        need(
            self.context.valid()
                && self.provenance.valid()
                && self.target.valid()
                && self.context.operation_id == self.provenance.operation_id.as_str()
                && sha(&self.before_sha256)
                && sha(&self.plan_sha256)
                && self.source_key.validate().is_ok()
                && self.destination.validate().is_ok()
                && self.destination.vault_id == self.source_key.vault_id
                && self.destination.generation_id == self.source_key.generation_id
                && self.destination.record_id != self.source_key.record_id
                && self.destination.revision_counter == 1
                && self.bundle.valid(&self.target),
        )?;
        let observed =
            utc_micros(&self.observed_at).ok_or_else(|| StateError::from(Error::InvalidRequest))?;
        let until =
            utc_micros(&self.valid_until).ok_or_else(|| StateError::from(Error::InvalidRequest))?;
        need(until.checked_sub(observed) == Some(300_000_000) && self.certificate.valid(observed))?;
        match (self.action, &self.profile) {
            (ProfileAction::CreateProfile, None) => (),
            (ProfileAction::ReuseDownload, Some(profile)) => need(
                profile.valid(self)
                    && utc_micros(&profile.created_at).is_some_and(|created| created <= observed)
                    && utc_micros(&profile.expires_at).is_some_and(|expires| observed < expires),
            )?,
            _ => return Err(Error::InvalidRequest.into()),
        }
        // The FULL inventory remains in the original review, not this bounded
        // row. Parent must match that original before reserve; a digest or an
        // empty profile selection cannot manufacture an absence observation.
        need(self.plan_hash()? == self.plan_sha256)?;
        canonical(self, ROW_LIMIT).map(|_| ())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProfileCreateAction {
    CreateProfile,
}

/// Exact existing ProvisioningAttempt fields with a separate closed action.
/// The old Bundle AttemptRecord grammar does NOT gain create_profile.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProfileAttemptRecord {
    pub(crate) context: ProvisioningContext,
    pub(crate) plan_sha256: String,
    pub(crate) action: ProfileCreateAction,
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
impl ProfileAttemptRecord {
    // Fixed DATA projection into the existing attempt-FIELDS validator. It
    // cannot be persisted through the Bundle port: no Bundle intent/hash is
    // constructed. Keeping that validator shared avoids divergent cancellation
    // and unknown/no-send transitions without widening its public enum.
    fn fields(&self) -> AttemptRecord {
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
    pub(crate) fn validate(&self, intent: &ProfileSetupIntent) -> Result<()> {
        need(intent.action == ProfileAction::CreateProfile)?;
        self.fields()
            .validate_fields(&intent.context, &intent.plan_sha256)
    }
    fn follows(&self, previous: &Self, intent: &ProfileSetupIntent) -> Result<()> {
        self.validate(intent)?;
        // Sequence belongs to the surrounding profile update (including local
        // save), while the unchanged provider fields reuse exact transition
        // checks. These temporary DATA values never enter a Bundle write.
        AttemptUpdate {
            sequence: 2,
            record: self.fields(),
        }
        .follows_fields(
            &AttemptUpdate {
                sequence: 1,
                record: previous.fields(),
            },
            &intent.context,
            &intent.plan_sha256,
        )
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "record",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub(crate) enum ProfileProvider {
    DownloadPending,
    DownloadReturned,
    DownloadRefused,
    DownloadUnknown,
    Creation(ProfileAttemptRecord),
}
impl ProfileProvider {
    fn terminal(&self) -> bool {
        match self {
            Self::DownloadReturned | Self::DownloadRefused => true,
            Self::Creation(value) => value.status.terminal(),
            _ => false,
        }
    }
    fn usable_download(&self) -> bool {
        matches!(self, Self::DownloadReturned)
            || matches!(self,
            Self::Creation(value) if value.status == AttemptStatus::Succeeded && !value.cancel_requested)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProfileDownload {
    pub(crate) profile: ProfileSelection,
    pub(crate) bytes: u32,
    pub(crate) sha256: String,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProfileSaveState {
    NotEntered,
    Armed,
    Written,
    ReadBack,
    Unknown,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProfileUpdate {
    pub(crate) sequence: u32,
    pub(crate) provider: ProfileProvider,
    #[serde(deserialize_with = "required_option")]
    pub(crate) download: Option<ProfileDownload>,
    pub(crate) save: ProfileSaveState,
    #[serde(deserialize_with = "required_option")]
    pub(crate) saved_reference: Option<KeyReference>,
    pub(crate) cancel_requested: bool,
}
impl ProfileUpdate {
    pub(crate) fn sha256(&self) -> Result<String> {
        hash(self)
    }
    pub(crate) fn validate(&self, intent: &ProfileSetupIntent) -> Result<()> {
        need((1..=ATTEMPT_LIMIT).contains(&self.sequence))?;
        match (&self.provider, intent.action) {
            (ProfileProvider::Creation(record), ProfileAction::CreateProfile) => {
                record.validate(intent)?;
                need(!record.cancel_requested || self.cancel_requested)?;
            }
            (ProfileProvider::Creation(_), _) | (_, ProfileAction::CreateProfile) => {
                return Err(Error::InvalidRequest.into())
            }
            _ => (),
        }
        if let Some(download) = &self.download {
            need(
                download.bytes > 0
                    && download.bytes <= PROFILE_BYTES
                    && sha(&download.sha256)
                    && download.profile.valid(intent),
            )?;
            match &self.provider {
                ProfileProvider::DownloadReturned => {
                    need(intent.profile.as_ref() == Some(&download.profile))?
                }
                ProfileProvider::Creation(record) => need(
                    record.response_resource_id.as_ref() == Some(&download.profile.resource_id)
                        && record.observed_resource_id == record.response_resource_id
                        && matches!(
                            record.status,
                            AttemptStatus::Succeeded | AttemptStatus::Cancelled
                        )
                        && matches!(
                            record.reason,
                            AttemptReason::ProviderResourceConfirmed
                                | AttemptReason::CancelledAfterSettlement
                        )
                        && download.profile.name == intent.profile_name(),
                )?,
                _ => return Err(Error::InvalidRequest.into()),
            }
        } else {
            need(!self.provider.usable_download())?;
        }
        need((self.save == ProfileSaveState::ReadBack) == self.saved_reference.is_some())?;
        if let Some(reference) = &self.saved_reference {
            need(reference == &intent.destination)?;
        }
        if self.save != ProfileSaveState::NotEntered {
            need(self.download.is_some() && self.provider.usable_download())?;
        }
        Ok(())
    }
    pub(in crate::apple_provisioning_journal) fn initial(
        &self,
        intent: &ProfileSetupIntent,
    ) -> Result<()> {
        self.validate(intent)?;
        need(
            self.sequence == 1
                && self.download.is_none()
                && self.save == ProfileSaveState::NotEntered
                && self.saved_reference.is_none(),
        )?;
        match &self.provider {
            ProfileProvider::Creation(record) => need(
                record.status == AttemptStatus::Running
                    && record.reason == AttemptReason::ReadbackRequired
                    && record.possible_send
                    && record.response_resource_id.is_none()
                    && record.observed_resource_id.is_none(),
            ),
            ProfileProvider::DownloadPending => Ok(()),
            _ => Err(Error::InvalidRequest.into()),
        }
    }
    pub(in crate::apple_provisioning_journal) fn follows(
        &self,
        previous: &Self,
        intent: &ProfileSetupIntent,
    ) -> Result<()> {
        self.validate(intent)?;
        need(
            previous.sequence.checked_add(1) == Some(self.sequence)
                && (!previous.cancel_requested || self.cancel_requested)
                && previous
                    .download
                    .as_ref()
                    .is_none_or(|old| self.download.as_ref() == Some(old))
                && previous
                    .saved_reference
                    .as_ref()
                    .is_none_or(|old| self.saved_reference.as_ref() == Some(old)),
        )?;
        if self.provider != previous.provider {
            match (&previous.provider, &self.provider) {
                (ProfileProvider::Creation(old), ProfileProvider::Creation(next)) => {
                    next.follows(old, intent)?
                }
                (
                    ProfileProvider::DownloadPending,
                    ProfileProvider::DownloadReturned
                    | ProfileProvider::DownloadRefused
                    | ProfileProvider::DownloadUnknown,
                ) => (),
                _ => return Err(Error::InvalidRequest.into()),
            }
        }
        if self.save != previous.save {
            use ProfileSaveState as S;
            need(match (previous.save, self.save) {
                (S::NotEntered, S::Armed) => {
                    !self.cancel_requested && self.provider.usable_download()
                }
                (S::Armed, S::Written | S::ReadBack | S::Unknown)
                | (S::Written, S::ReadBack | S::Unknown) => true,
                _ => false,
            })?;
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProfileSetupRow {
    pub(crate) intent: ProfileSetupIntent,
    pub(crate) send_armed: bool,
    pub(crate) update: ProfileUpdate,
    pub(crate) native_settlement: NativeSettlement,
}
impl ProfileSetupRow {
    pub(in crate::apple_provisioning_journal) fn validate(&self) -> Result<()> {
        self.intent.validate()?;
        need(self.send_armed == (self.intent.action == ProfileAction::CreateProfile))?;
        self.update.validate(&self.intent)?;
        if self.update.sequence == 1 {
            self.update.initial(&self.intent)?;
        }
        canonical(self, ROW_LIMIT).map(|_| ())
    }
    pub(crate) fn unresolved(&self) -> bool {
        self.native_settlement != NativeSettlement::Known
            || !self.update.provider.terminal()
            || matches!(
                self.update.save,
                ProfileSaveState::Armed | ProfileSaveState::Written | ProfileSaveState::Unknown
            )
    }
}

#[cfg(test)]
#[path = "apple_provisioning_profile_journal_data_tests.rs"]
pub(in crate::apple_provisioning_journal) mod tests;
