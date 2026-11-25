//! Closed key-preparation/certificate DATA of the SAME Apple protocol.
//! No body hash, saved reference or parsed review is a private-key capability.
use super::*;
use crate::{
    apple_provisioning_journal::{
        profile_entitlements_sha256, profile_unix_micros, KeyAlgorithm, KeyDisposition,
        KeyGeneration, KeyJournalAck, KeyOutputMetadata, KeyPrepareIntent, KeyPrepareUpdate,
        ProfileBundle, ProfileSaveState, ProfileTarget,
    },
    credential_setup::KeyReference,
};

pub(crate) const KEY_EVENTS: u32 = 5;
pub(crate) const KEY_JSON_LIMIT: usize = 256 * 1024;
pub(crate) const KEY_STOP: u8 = 0;

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KeyReviewChoice {
    pub(crate) bundle: ProfileBundle,
    pub(crate) before_sha256: String,
    pub(crate) plan_sha256: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyReviewData {
    pub(crate) reference: Reference,
    pub(crate) observed_at: String,
    pub(crate) valid_until: String,
    pub(crate) selection: KeyReviewChoice,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyVaultInventory {
    pub(crate) records: u32,
    pub(crate) keys: u32,
}
impl KeyVaultInventory {
    fn valid(&self) -> bool {
        self.records <= 128 && self.keys <= self.records
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyScopeData {
    pub(crate) source_p8: KeyReference,
    pub(crate) source_key: Option<KeyReference>,
    pub(crate) destination: Option<KeyReference>,
    pub(crate) entitlements: Value,
    pub(crate) review: Option<KeyReviewData>,
    // Projection of the SAME joined native inventory only. These counters
    // never grant absence, a current source loan or generation consent.
    pub(crate) vault_inventory: Option<KeyVaultInventory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovery: Option<KeyRecoverySelection>,
}
impl KeyScopeData {
    pub(crate) fn target(&self, bundle: &BundleTarget) -> Result<ProfileTarget, BridgeError> {
        Ok(ProfileTarget {
            bundle_id: bundle.bundle_id.clone(),
            team_id: bundle.team_id.clone(),
            app_id_prefix: bundle.app_id_prefix.clone(),
            display_name: bundle.display_name.clone(),
            existing_application: bundle.existing_application,
            entitlements_sha256: profile_entitlements_sha256(&self.entitlements)
                .map_err(|_| invalid())?,
        })
    }
    pub(super) fn valid(
        &self,
        context: &Context,
        target: &BundleTarget,
        reviewed: Option<&String>,
    ) -> bool {
        if !context.mode.key()
            || self.source_p8.validate().is_err()
            || self.source_p8.record_id != context.record_id
            || self.source_p8.revision_counter != context.record_revision
            || target.team_id != target.app_id_prefix
            || self.target(target).is_err()
            || self.vault_inventory.as_ref().is_some_and(|inventory| !inventory.valid())
        {
            return false;
        }
        let source_ok = match (&self.source_key, context.mode) {
            (None, Mode::KeyReview | Mode::KeyPrepare) => true,
            (
                Some(key),
                Mode::KeyRecover
                | Mode::CertificateReview
                | Mode::CertificateCreate
                | Mode::CertificateReconcile,
            ) => {
                key.validate().is_ok()
                    && key.vault_id == self.source_p8.vault_id
                    && key.generation_id == self.source_p8.generation_id
                    && key.record_id != self.source_p8.record_id
            }
            _ => false,
        };
        if !source_ok {
            return false;
        }
        if context.mode == Mode::KeyRecover {
            return self.source_key.as_ref().is_some_and(|source| context.key_record_id.as_ref() == Some(&source.record_id)
                    && context.key_record_revision == Some(source.revision_counter))
                && self.vault_inventory.is_none() && self.destination.is_none() && self.review.is_none()
                && reviewed.is_none() && self.recovery.as_ref().is_some_and(KeyRecoverySelection::valid);
        }
        if self.recovery.is_some() || self.vault_inventory.is_none() { return false; }
        if context.mode == Mode::KeyPrepare {
            let (Some(destination), Some(review)) = (&self.destination, &self.review) else {
                return false;
            };
            destination.validate().is_ok()
                && self.vault_inventory.as_ref().is_some_and(|inventory| inventory.keys == 0)
                && destination.revision_counter == 1
                && destination.vault_id == self.source_p8.vault_id
                && destination.generation_id == self.source_p8.generation_id
                && destination.record_id != self.source_p8.record_id
                && context.reference.as_ref() == Some(&review.reference)
                && reviewed == Some(&review.observed_at)
                && interval(&review.observed_at, &review.valid_until)
                && choice_valid(&review.selection, target)
        } else {
            self.destination.is_none() && self.review.is_none() && reviewed.is_none()
        }
    }
}
fn interval(before: &str, after: &str) -> bool {
    profile_unix_micros(before)
        .zip(profile_unix_micros(after))
        .is_some_and(|(before, after)| after.checked_sub(before) == Some(300_000_000))
}
fn choice_valid(value: &KeyReviewChoice, target: &BundleTarget) -> bool {
    let bundle = &value.bundle;
    resource_id(&bundle.resource_id)
        && bundle.identifier == target.bundle_id
        && matches!(bundle.platform.as_str(), "IOS" | "UNIVERSAL")
        && bundle.seed_id == target.app_id_prefix
        && sha(&value.before_sha256)
        && sha(&value.plan_sha256)
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum KeyDecision {
    PrepareReview,
    RecoverExistingKey,
    ReuseExistingIdentity,
    BundleRequired,
    Blocked,
    Produced,
    Compared,
}
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum KeyReason {
    LocalKeyRequired,
    ExistingCertificate,
    ExistingKey,
    BundleRegistrationRequired,
    AccountPending,
    InventoryUnavailable,
    ProducerReturned,
    StoredKeyChecked,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KeyObserved {
    pub(crate) observed_at: String,
    pub(crate) valid_until: String,
    pub(crate) decision: KeyDecision,
    pub(crate) reason: KeyReason,
    #[serde(deserialize_with = "required_option")]
    pub(crate) selection: Option<KeyReviewChoice>,
}
impl KeyObserved {
    fn valid(&self, binding: &RequestBinding) -> bool {
        binding.context.mode == Mode::KeyReview
            && interval(&self.observed_at, &self.valid_until)
            && match (self.decision, self.reason, &self.selection) {
                (KeyDecision::PrepareReview, KeyReason::LocalKeyRequired, Some(selection)) => {
                    choice_valid(selection, &binding.scope.target)
                }
                (
                    KeyDecision::RecoverExistingKey,
                    KeyReason::ExistingCertificate | KeyReason::ExistingKey,
                    None,
                ) => true,
                (KeyDecision::ReuseExistingIdentity, KeyReason::ExistingCertificate, None) => true,
                (KeyDecision::BundleRequired, KeyReason::BundleRegistrationRequired, None) => true,
                (
                    KeyDecision::Blocked,
                    KeyReason::AccountPending | KeyReason::InventoryUnavailable,
                    None,
                ) => true,
                _ => false,
            }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pending {
    observed_at: String,
    valid_until: String,
    before_sha256: String,
    plan_sha256: String,
    update: KeyPrepareUpdate,
}
/// Output from the fixed original generator inspector only. Native finality
/// additionally requires all original worker/runtime/IO joins; this object is
/// not itself a never-generated proof or permission to discard private bytes.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KeyNotGenerated {
    pub(crate) commands: u32,
    pub(crate) before_command: bool,
}
pub(crate) enum KeyEvent {
    Observed(KeyObserved),
    Pending {
        intent: KeyPrepareIntent,
        update: KeyPrepareUpdate,
    },
    Output(KeyOutputMetadata),
    NotGenerated(KeyNotGenerated),
    Compared(KeyRecoveryInput),
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KeyResult {
    schema_version: u32,
    scope: String,
    mode: Mode,
    pub(crate) decision: KeyDecision,
    pub(crate) reason: KeyReason,
    // Always false here. Native NEW and durable keySaved happen only AFTER
    // this worker's terminal/EOF/joins, outside the worker result.
    saved: bool,
    certificate_requested: bool,
    credential_ready: bool,
}
#[derive(Default)]
pub(super) struct KeyDecoder {
    observed: Option<KeyObserved>,
    pending: Option<KeyPrepareIntent>,
    output: Option<KeyOutputMetadata>,
    not_generated: Option<KeyNotGenerated>,
    compared: bool,
}
impl KeyDecoder {
    pub(super) fn event(
        &mut self,
        binding: &RequestBinding,
        sequence: u32,
        kind: &str,
        value: Value,
    ) -> Result<KeyEvent, BridgeError> {
        match kind {
            "key-compared" => {
                need(sequence == 1 && !self.compared && binding.context.mode == Mode::KeyRecover)?;
                let input = key_recovery_input(binding, value)?;
                self.compared = true;
                Ok(KeyEvent::Compared(input))
            }
            "key-observed" => {
                need(
                    sequence == 1
                        && self.observed.is_none()
                        && binding.context.mode == Mode::KeyReview,
                )?;
                let observed = KeyObserved::deserialize(value).map_err(|_| invalid())?;
                need(observed.valid(binding))?;
                self.observed = Some(observed.clone());
                Ok(KeyEvent::Observed(observed))
            }
            "key-pending" => {
                need(
                    sequence == 1
                        && self.pending.is_none()
                        && binding.context.mode == Mode::KeyPrepare,
                )?;
                let pending = Pending::deserialize(value).map_err(|_| invalid())?;
                let scope = binding.scope.key.as_ref().ok_or_else(invalid)?;
                let review = scope.review.as_ref().ok_or_else(invalid)?;
                need(
                    pending.observed_at == review.observed_at
                        && pending.valid_until == review.valid_until
                        && pending.before_sha256 == review.selection.before_sha256,
                )?;
                let intent = KeyPrepareIntent {
                    context: binding.scope.provisioning.clone(),
                    provenance: binding.scope.provenance.clone(),
                    target: scope.target(&binding.scope.target)?,
                    source_p8: scope.source_p8.clone(),
                    destination: scope.destination.clone().ok_or_else(invalid)?,
                    algorithm: KeyAlgorithm::Rsa2048Sha256,
                    bundle: review.selection.bundle.clone(),
                    observed_at: pending.observed_at,
                    valid_until: pending.valid_until,
                    before_sha256: pending.before_sha256,
                    review_plan_sha256: pending.plan_sha256,
                };
                intent.validate().map_err(|_| invalid())?;
                let update = &pending.update;
                update.validate(&intent).map_err(|_| invalid())?;
                need(
                    update.sequence == 1
                        && update.generation == KeyGeneration::Armed
                        && update.output.is_none()
                        && update.save == ProfileSaveState::NotEntered
                        && update.saved_reference.is_none()
                        && update.disposition == KeyDisposition::Running
                        && !update.cancel_requested,
                )?;
                self.pending = Some(intent.clone());
                Ok(KeyEvent::Pending {
                    intent,
                    update: pending.update,
                })
            }
            "key-output" => {
                need(
                    sequence == 2
                        && binding.context.mode == Mode::KeyPrepare
                        && self.pending.is_some()
                        && self.output.is_none()
                        && self.not_generated.is_none(),
                )?;
                let output = KeyOutputMetadata::deserialize(value).map_err(|_| invalid())?;
                need(output.valid())?;
                self.output = Some(output.clone());
                Ok(KeyEvent::Output(output))
            }
            "key-not-generated" => {
                need(
                    sequence == 2
                        && binding.context.mode == Mode::KeyPrepare
                        && self.pending.is_some()
                        && self.output.is_none()
                        && self.not_generated.is_none(),
                )?;
                let absent = KeyNotGenerated::deserialize(value).map_err(|_| invalid())?;
                need(
                    (6..=7).contains(&absent.commands)
                        && (!absent.before_command || absent.commands == 6),
                )?;
                self.not_generated = Some(absent.clone());
                Ok(KeyEvent::NotGenerated(absent))
            }
            _ => Err(invalid()),
        }
    }
    pub(super) fn valid_terminal(&self, result: &KeyResult, binding: &RequestBinding) -> bool {
        if result.schema_version != 1
            || result.scope != "local-ios-distribution-key"
            || result.mode != binding.context.mode
            || result.saved
            || result.certificate_requested
            || result.credential_ready
        {
            return false;
        }
        match binding.context.mode {
            Mode::KeyRecover => self.compared && result.decision == KeyDecision::Compared && result.reason == KeyReason::StoredKeyChecked,
            Mode::KeyReview => self.observed.as_ref().is_some_and(|observed| {
                result.decision == observed.decision && result.reason == observed.reason
            }),
            Mode::KeyPrepare => {
                self.pending.is_some()
                    && self.output.is_some()
                    && self.not_generated.is_none()
                    && result.decision == KeyDecision::Produced
                    && result.reason == KeyReason::ProducerReturned
            }
            _ => false,
        }
    }
    pub(super) fn lifetime_matches(&self, life: &Lifetime) -> bool {
        self.not_generated
            .as_ref()
            .is_none_or(|absent| life.commands == absent.commands)
    }
}

fn reply(
    binding: &RequestBinding,
    sequence: u32,
    kind: &str,
    revision: u64,
    digest: &str,
) -> Result<Vec<u8>, BridgeError> {
    let value = json!({"protocol":PROTOCOL,"operationId":binding.operation,"ownerGeneration":binding.generation,
        "nonce":binding.nonce,"requestSha256":binding.sha256,"sequence":sequence,"kind":kind,
        "journalRevision":revision,"ackSha256":digest});
    let mut bytes = bounded(&value, ACK_LIMIT - 1).map_err(|_| invalid())?;
    bytes.push(b'\n');
    Ok(bytes)
}
pub(crate) fn key_pending_ack(
    binding: &RequestBinding,
    ack: &KeyJournalAck,
    previous: u64,
) -> Result<Vec<u8>, BridgeError> {
    need(
        binding.context.mode == Mode::KeyPrepare
            && ack.revision.0 == previous.checked_add(1).ok_or_else(invalid)?
            && ack.row.update.sequence == 1
            && ack.original.intent().context == binding.scope.provisioning
            && ack.row.intent == *ack.original.intent(),
    )?;
    reply(
        binding,
        1,
        "key-pending-ack",
        ack.revision.0,
        &ack.row.update.sha256().map_err(|_| invalid())?,
    )
}
pub(crate) fn key_retained_ack(
    binding: &RequestBinding,
    ack: &KeyJournalAck,
    output: &KeyOutputMetadata,
    previous: u64,
) -> Result<Vec<u8>, BridgeError> {
    need(
        binding.context.mode == Mode::KeyPrepare
            && ack.revision.0 == previous.checked_add(1).ok_or_else(invalid)?
            && ack.row.update.sequence == 2
            && ack.row.update.generation == KeyGeneration::Returned
            && ack.row.update.save == ProfileSaveState::Armed
            && ack.row.update.output.as_ref() == Some(output)
            && ack.row.intent == *ack.original.intent()
            && ack.original.intent().context == binding.scope.provisioning,
    )?;
    // The actual writer separately requires its SAME private body to be fully
    // retained before serializing/writing this custody-only ACK.
    reply(
        binding,
        2,
        "key-retained",
        ack.revision.0,
        &output.sha256().map_err(|_| invalid())?,
    )
}
