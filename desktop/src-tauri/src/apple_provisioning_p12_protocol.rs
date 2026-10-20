//! Fixed P12 setup DATA on the existing Apple protocol. This grammar cannot
//! create a key/certificate/BoundLoan, grant a save or prove native retirement.
use super::*;
use crate::{
    apple_provisioning_journal::{
        profile_choice_valid, profile_unix_micros, P12Assembly, P12Disposition, P12JournalAck,
        P12OutputMetadata, P12SaveIntent, P12SaveUpdate, ProfileBundle, ProfileCertificate,
        ProfileSaveState,
    },
    credential_setup::KeyReference,
};

pub(crate) const P12_EVENTS: u32 = 8;
pub(crate) const P12_COMMANDS: u32 = 15;
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct P12Choice {
    pub(crate) bundle: ProfileBundle,
    pub(crate) certificate: ProfileCertificate,
    pub(crate) csr_sha256: String,
    pub(crate) before_sha256: String,
}
impl P12Choice {
    pub(super) fn valid(&self, scope: &ScopeData, at: &str) -> bool {
        let Some(certificate) = scope.certificate.as_ref() else {
            return false;
        };
        let Ok(target) = certificate.target(&scope.target) else {
            return false;
        };
        self.certificate.certificate_type == "DISTRIBUTION"
            && sha(&self.csr_sha256)
            && sha(&self.before_sha256)
            && profile_choice_valid(&target, &self.bundle, &self.certificate, None, at)
    }
    pub(crate) fn same_assets(&self, other: &Self) -> bool {
        self.bundle == other.bundle
            && self.certificate == other.certificate
            && self.csr_sha256 == other.csr_sha256
    }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct P12ReviewData {
    pub(crate) reference: Reference,
    pub(crate) observed_at: String,
    pub(crate) valid_until: String,
    pub(crate) selection: P12Choice,
    pub(crate) selected_p12: Option<KeyReference>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct P12HistoryHint {
    pub(crate) destination: KeyReference,
    pub(crate) certificate_sha256: String,
    pub(crate) public_key_sha256: String,
    pub(crate) unresolved: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct P12ScopeData {
    pub(crate) source_p8: KeyReference,
    pub(crate) source_key: KeyReference,
    pub(crate) selected_p12: Option<KeyReference>,
    pub(crate) expected_certificate_sha256: Option<String>,
    pub(crate) p12_sha256: Option<String>,
    pub(crate) destination: Option<KeyReference>,
    pub(crate) review: Option<P12ReviewData>,
    pub(crate) previous: Vec<P12HistoryHint>,
}
fn interval(from: &str, to: &str) -> bool {
    profile_unix_micros(from)
        .zip(profile_unix_micros(to))
        .is_some_and(|(a, b)| b.checked_sub(a) == Some(300_000_000))
}
impl P12ScopeData {
    pub(super) fn valid(&self, context: &Context, scope: &ScopeData) -> bool {
        let Some(certificate) = &scope.certificate else {
            return false;
        };
        if !context.mode.p12()
            || self.source_key != certificate.source_key
            || self.source_p8 != certificate.source_p8
            || self.previous.len() > ROWS
            || self.previous.iter().any(|h| {
                h.destination.validate().is_err()
                    || !sha(&h.certificate_sha256)
                    || !sha(&h.public_key_sha256)
            })
        {
            return false;
        }
        match (
            &self.selected_p12,
            &self.expected_certificate_sha256,
            &self.p12_sha256,
        ) {
            (Some(reference), Some(leaf), Some(p12))
                if reference.validate().is_ok()
                    && sha(leaf)
                    && sha(p12)
                    && reference.vault_id == self.source_key.vault_id
                    && reference.generation_id == self.source_key.generation_id
                    && reference.record_id != self.source_key.record_id
                    && reference.record_id != self.source_p8.record_id
                    && context.p12_record_id.as_ref() == Some(&reference.record_id)
                    && context.p12_record_revision == Some(reference.revision_counter) => {}
            (None, None, None)
                if context.p12_record_id.is_none() && context.p12_record_revision.is_none() => {}
            _ => return false,
        }
        match (context.mode, &self.destination) {
            (Mode::P12Save, Some(reference))
                if reference.validate().is_ok()
                    && reference.revision_counter == 1
                    && reference.vault_id == self.source_key.vault_id
                    && reference.generation_id == self.source_key.generation_id
                    && reference.record_id != self.source_key.record_id
                    && reference.record_id != self.source_p8.record_id
                    && self.selected_p12.is_none() => {}
            (Mode::P12Review | Mode::P12Reuse, None) => {}
            _ => return false,
        }
        if context.mode == Mode::P12Reuse && self.selected_p12.is_none() {
            return false;
        }
        if context.mode == Mode::P12Review {
            self.review.is_none() && context.reference.is_none() && scope.reviewed_at.is_none()
        } else {
            self.review.as_ref().is_some_and(|review| {
                review.reference.valid()
                    && context.reference.as_ref() == Some(&review.reference)
                    && scope.reviewed_at.as_ref() == Some(&review.observed_at)
                    && interval(&review.observed_at, &review.valid_until)
                    && review.selection.valid(scope, &review.observed_at)
                    && review.selected_p12 == self.selected_p12
            })
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum P12Decision {
    AssembleReview,
    ReuseReview,
    Assembled,
    Reused,
    Blocked,
}
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum P12Reason {
    NewPackageReview,
    CurrentPackageReview,
    ProducerReturned,
    ExistingPackage,
    AccountPending,
    InventoryUnavailable,
    CertificateRequired,
    SelectExistingPackage,
    SelectionChanged,
}
fn pair(mode: Mode, decision: P12Decision, reason: P12Reason) -> bool {
    match (mode, decision, reason) {
        (Mode::P12Review, P12Decision::AssembleReview, P12Reason::NewPackageReview)
        | (Mode::P12Review, P12Decision::ReuseReview, P12Reason::CurrentPackageReview)
        | (Mode::P12Save, P12Decision::Assembled, P12Reason::ProducerReturned)
        | (Mode::P12Reuse, P12Decision::Reused, P12Reason::ExistingPackage) => true,
        (
            m,
            P12Decision::Blocked,
            P12Reason::AccountPending
            | P12Reason::InventoryUnavailable
            | P12Reason::CertificateRequired
            | P12Reason::SelectExistingPackage
            | P12Reason::SelectionChanged,
        ) => m.p12(),
        _ => false,
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct P12Observed {
    pub(crate) observed_at: String,
    pub(crate) valid_until: String,
    pub(crate) decision: P12Decision,
    pub(crate) reason: P12Reason,
    #[serde(deserialize_with = "required_option")]
    pub(crate) selection: Option<P12Choice>,
}
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct P12ReuseComparison {
    pub(crate) source_p12: KeyReference,
    pub(crate) p12_sha256: String,
    pub(crate) certificate_sha256: String,
    pub(crate) public_key_sha256: String,
    pub(crate) policy_ack_sha256: String,
}
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct P12Result {
    schema_version: u32,
    scope: String,
    mode: Mode,
    pub(crate) decision: P12Decision,
    pub(crate) reason: P12Reason,
    #[serde(deserialize_with = "required_option")]
    pub(crate) certificate_id: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub(crate) certificate_sha256: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub(crate) public_key_sha256: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub(crate) output: Option<P12OutputMetadata>,
    #[serde(deserialize_with = "required_option")]
    pub(crate) reused: Option<P12ReuseComparison>,
    p12_saved: bool,
    profile_saved: bool,
    credential_ready: bool,
    revocation_checked: bool,
}
impl P12Result {
    pub(crate) fn positive_identity(&self) -> bool {
        matches!(
            self.decision,
            P12Decision::AssembleReview
                | P12Decision::ReuseReview
                | P12Decision::Assembled
                | P12Decision::Reused
        ) && self.certificate_id.is_some()
            && self.certificate_sha256.is_some()
            && self.public_key_sha256.is_some()
    }
}
pub(crate) enum P12Event {
    Observed(P12Observed),
    Pending {
        intent: P12SaveIntent,
        update: P12SaveUpdate,
    },
    Output(P12OutputMetadata),
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pending {
    observed_at: String,
    valid_until: String,
    selection: P12Choice,
    update: P12SaveUpdate,
}
#[derive(Default)]
pub(super) struct P12Decoder {
    observed: Option<P12Observed>,
    intent: Option<P12SaveIntent>,
    output: Option<P12OutputMetadata>,
}
impl P12Decoder {
    pub(super) fn event(
        &mut self,
        binding: &RequestBinding,
        sequence: u32,
        kind: &str,
        value: Value,
    ) -> Result<P12Event, BridgeError> {
        need(binding.context.mode.p12() && (2..=P12_EVENTS).contains(&sequence))?;
        let scope = binding.scope.p12.as_ref().ok_or_else(invalid)?;
        match kind {
            "p12-observed" => {
                let value: P12Observed = serde_json::from_value(value).map_err(|_| invalid())?;
                need(
                    binding.context.mode == Mode::P12Review
                        && sequence <= 4
                        && self.observed.is_none()
                        && self.intent.is_none()
                        && interval(&value.observed_at, &value.valid_until)
                        && pair(binding.context.mode, value.decision, value.reason)
                        && match (&value.selection, value.decision) {
                            (
                                Some(choice),
                                P12Decision::AssembleReview | P12Decision::ReuseReview,
                            ) => choice.valid(&binding.scope, &value.observed_at),
                            (None, P12Decision::Blocked) => true,
                            _ => false,
                        },
                )?;
                self.observed = Some(value.clone());
                Ok(P12Event::Observed(value))
            }
            "p12-pending" => {
                let value: Pending = serde_json::from_value(value).map_err(|_| invalid())?;
                need(
                    binding.context.mode == Mode::P12Save
                        && sequence == 4
                        && self.intent.is_none()
                        && self.observed.is_none()
                        && interval(&value.observed_at, &value.valid_until)
                        && value.selection.valid(&binding.scope, &value.observed_at)
                        && scope
                            .review
                            .as_ref()
                            .is_some_and(|r| r.selection.same_assets(&value.selection)),
                )?;
                let mut intent = P12SaveIntent {
                    action: crate::apple_provisioning_journal::P12LocalAction::AssemblePkcs12,
                    context: binding.scope.provisioning.clone(),
                    provenance: binding.scope.provenance.clone(),
                    target: binding
                        .scope
                        .certificate
                        .as_ref()
                        .ok_or_else(invalid)?
                        .target(&binding.scope.target)?,
                    source_p8: scope.source_p8.clone(),
                    source_key: scope.source_key.clone(),
                    destination: scope.destination.clone().ok_or_else(invalid)?,
                    bundle: value.selection.bundle,
                    certificate: value.selection.certificate,
                    csr_sha256: value.selection.csr_sha256,
                    before_sha256: value.selection.before_sha256,
                    request_binding_sha256: binding.sha256.clone(),
                    observed_at: value.observed_at,
                    valid_until: value.valid_until,
                    review_sha256: String::new(),
                };
                intent.review_sha256 = intent.review_hash().map_err(|_| invalid())?;
                intent.validate().map_err(|_| invalid())?;
                need(
                    value.update.sequence == 1
                        && value.update.assembly == P12Assembly::Armed
                        && value.update.disposition == P12Disposition::Running
                        && value.update.save == ProfileSaveState::NotEntered
                        && value.update.output.is_none()
                        && value.update.saved_reference.is_none()
                        && !value.update.cancel_requested,
                )?;
                value.update.validate(&intent).map_err(|_| invalid())?;
                self.intent = Some(intent.clone());
                Ok(P12Event::Pending {
                    intent,
                    update: value.update,
                })
            }
            "p12-output" => {
                let output: P12OutputMetadata =
                    serde_json::from_value(value).map_err(|_| invalid())?;
                need(
                    binding.context.mode == Mode::P12Save
                        && sequence == 5
                        && self.output.is_none()
                        && self
                            .intent
                            .as_ref()
                            .is_some_and(|intent| output.valid(intent)),
                )?;
                self.output = Some(output.clone());
                Ok(P12Event::Output(output))
            }
            _ => Err(invalid()),
        }
    }
    pub(super) fn result(
        &self,
        binding: &RequestBinding,
        value: Value,
    ) -> Result<P12Result, BridgeError> {
        let result: P12Result = serde_json::from_value(value).map_err(|_| invalid())?;
        let scope = binding.scope.p12.as_ref().ok_or_else(invalid)?;
        need(
            result.schema_version == 1
                && result.scope == "local-ios-p12-setup"
                && result.mode == binding.context.mode
                && pair(result.mode, result.decision, result.reason)
                && !result.p12_saved
                && !result.profile_saved
                && !result.credential_ready
                && !result.revocation_checked
                && result
                    .certificate_id
                    .as_ref()
                    .is_none_or(|s| resource_id(s))
                && result.certificate_sha256.as_ref().is_none_or(|s| sha(s))
                && result.public_key_sha256.as_ref().is_none_or(|s| sha(s)),
        )?;
        let positive = result.decision != P12Decision::Blocked;
        need(
            positive == result.positive_identity()
                && (positive
                    || result.certificate_id.is_none()
                        && result.certificate_sha256.is_none()
                        && result.public_key_sha256.is_none()),
        )?;
        match result.decision {
            P12Decision::Assembled => need(
                result.output.is_some() && result.output == self.output && result.reused.is_none(),
            )?,
            P12Decision::ReuseReview | P12Decision::Reused => {
                let reused = result.reused.as_ref().ok_or_else(invalid)?;
                need(
                    result.output.is_none()
                        && scope.selected_p12.as_ref() == Some(&reused.source_p12)
                        && scope.p12_sha256.as_ref() == Some(&reused.p12_sha256)
                        && scope.expected_certificate_sha256.as_ref()
                            == Some(&reused.certificate_sha256)
                        && result.certificate_sha256.as_ref() == Some(&reused.certificate_sha256)
                        && result.public_key_sha256.as_ref() == Some(&reused.public_key_sha256)
                        && sha(&reused.policy_ack_sha256),
                )?;
            }
            _ => need(result.output.is_none() && result.reused.is_none())?,
        }
        if let Some(output) = &result.output {
            need(
                result.certificate_sha256.as_ref() == Some(&output.certificate_sha256)
                    && result.public_key_sha256.as_ref() == Some(&output.public_key_sha256),
            )?;
        }
        if result.mode == Mode::P12Review {
            need(
                self.observed
                    .as_ref()
                    .is_some_and(|o| o.decision == result.decision && o.reason == result.reason),
            )?;
        }
        if result.positive_identity() {
            let choice = if result.mode == Mode::P12Review {
                self.observed.as_ref().and_then(|o| o.selection.as_ref())
            } else {
                scope.review.as_ref().map(|r| &r.selection)
            }
            .ok_or_else(invalid)?;
            need(
                result.certificate_id.as_ref() == Some(&choice.certificate.resource_id)
                    && result.certificate_sha256.as_ref()
                        == Some(&choice.certificate.certificate_sha256)
                    && result.public_key_sha256.as_ref()
                        == Some(&choice.certificate.public_key_sha256)
                    && (result.decision != P12Decision::AssembleReview
                        || scope.selected_p12.is_none()),
            )?;
        }
        Ok(result)
    }
    pub(super) fn valid_terminal(&self, result: &P12Result, binding: &RequestBinding) -> bool {
        serde_json::to_value(result)
            .ok()
            .is_some_and(|v| self.result(binding, v).is_ok_and(|same| same == *result))
    }
}
pub(crate) fn p12_journal_ack(
    binding: &RequestBinding,
    phase: u32,
    ack: &P12JournalAck,
    update: &P12SaveUpdate,
    previous: crate::application_state_store::Revision,
) -> Result<Vec<u8>, BridgeError> {
    need(
        binding.context.mode == Mode::P12Save
            && ack.revision.0 == previous.0.checked_add(1).ok_or_else(invalid)?
            && ack.row.update == *update
            && ack.row.intent.request_binding_sha256 == binding.sha256,
    )?;
    certificate_reply(
        binding,
        phase,
        "p12-pending",
        json!({"revision":ack.revision.0,
        "sequence":update.sequence,"recordSha256":update.sha256().map_err(|_|invalid())?}),
    )
    .map(|p| p.0)
}
pub(crate) fn p12_custody_ack(
    binding: &RequestBinding,
    phase: u32,
    output: &P12OutputMetadata,
) -> Result<Vec<u8>, BridgeError> {
    need(binding.context.mode == Mode::P12Save && output.bounded())?;
    certificate_reply(
        binding,
        phase,
        "p12-output",
        json!({"frameSha256":output.frame_sha256,
        "p12Sha256":output.p12_sha256,"retained":true}),
    )
    .map(|p| p.0)
}
