//! Closed public comparison DATA for existing Store Execute/Reconcile. No
//! decoded mode, receipt or consent constructs a material/owner/permission.
use super::{nullable, sha, uuid, Candidate, Kind, Platform};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Mode {
    CandidateUpload,
    ExternalTesting,
    ProductionSubmit,
    CurrentInternal,
    RecoverySettlement,
    ExternalReadiness,
}
impl Mode {
    pub(crate) fn accepts(self, kind: Kind, platform: Platform) -> bool {
        match (kind, self, platform) {
            (
                Kind::Execute,
                Self::CandidateUpload | Self::ExternalTesting | Self::ProductionSubmit,
                _,
            )
            | (Kind::Reconcile, Self::CurrentInternal, _)
            | (Kind::Reconcile, Self::RecoverySettlement, Platform::Android)
            | (Kind::Reconcile, Self::ExternalReadiness, Platform::Ios) => true,
            _ => false,
        }
    }
    pub(crate) fn consent(self, kind: Kind, platform: Platform) -> Option<&'static str> {
        match (kind, self, platform) {
            (Kind::Execute, Self::CandidateUpload, Platform::Android) => {
                Some("agent-android-store-execute-candidate-upload-once-v1")
            }
            (Kind::Execute, Self::CandidateUpload, Platform::Ios) => {
                Some("agent-ios-store-execute-candidate-upload-once-v1")
            }
            (Kind::Execute, Self::ExternalTesting, Platform::Android) => {
                Some("agent-android-store-execute-external-testing-once-v1")
            }
            (Kind::Execute, Self::ExternalTesting, Platform::Ios) => {
                Some("agent-ios-store-execute-external-testing-once-v1")
            }
            (Kind::Execute, Self::ProductionSubmit, Platform::Android) => {
                Some("agent-android-store-execute-production-submit-once-v1")
            }
            (Kind::Execute, Self::ProductionSubmit, Platform::Ios) => {
                Some("agent-ios-store-execute-production-submit-once-v1")
            }
            (Kind::Reconcile, Self::CurrentInternal, Platform::Android) => {
                Some("agent-android-store-reconcile-current-internal-once-v1")
            }
            (Kind::Reconcile, Self::CurrentInternal, Platform::Ios) => {
                Some("agent-ios-store-reconcile-current-internal-once-v1")
            }
            (Kind::Reconcile, Self::RecoverySettlement, Platform::Android) => {
                Some("agent-android-store-reconcile-recovery-settlement-once-v1")
            }
            (Kind::Reconcile, Self::ExternalReadiness, Platform::Ios) => {
                Some("agent-ios-store-reconcile-external-readiness-once-v1")
            }
            _ => None,
        }
    }
    pub(crate) fn heads(self) -> std::ops::RangeInclusive<u32> {
        match self {
            Self::CandidateUpload | Self::RecoverySettlement => 7..=513,
            Self::ExternalTesting => 11..=513,
            Self::ProductionSubmit => 15..=513,
            Self::CurrentInternal => 6..=513,
            Self::ExternalReadiness => 12..=509,
        }
    }
    pub(crate) fn target(self, platform: Platform) -> Target {
        match (self, platform) {
            (Self::ExternalTesting | Self::ExternalReadiness, Platform::Ios) => {
                Target::TestflightExternal
            }
            (Self::ExternalTesting, Platform::Android) => Target::ConfiguredPlayExternal,
            (Self::ProductionSubmit, Platform::Android) => Target::PlayProductionDraft,
            (Self::ProductionSubmit, Platform::Ios) => Target::AppStoreSubmission,
            (_, Platform::Android) => Target::PlayInternal,
            (_, Platform::Ios) => Target::TestflightInternal,
        }
    }
    pub(crate) fn limitations(self) -> Vec<Limitation> {
        use Limitation::*;
        match self {
            Self::CandidateUpload | Self::ExternalTesting | Self::ProductionSubmit => vec![
                NoAutomaticRetry,
                SavedInputsNotAtomic,
                ReceiptNotPublicAvailability,
                NoBuildOrSigning,
            ],
            Self::CurrentInternal => vec![
                NoAutomaticRetry,
                SavedInputsNotAtomic,
                TargetMatchNotPriorFinality,
                NoUploadOrPromotion,
            ],
            Self::RecoverySettlement | Self::ExternalReadiness => vec![
                NoAutomaticRetry,
                SavedInputsNotAtomic,
                TargetMatchNotPriorFinality,
                NoUploadOrPromotion,
                LocalCheckpointNotPriorFinality,
            ],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Basis {
    pub(crate) operation_id: String,
    pub(crate) receipt_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Review {
    pub(crate) mode: Mode,
    pub(crate) intent_sha256: String,
    #[serde(deserialize_with = "nullable")]
    pub(crate) stage_operation_id: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) basis: Option<Basis>,
}
impl Review {
    pub(crate) fn valid_for(&self, kind: Kind, platform: Platform, c: &Candidate) -> bool {
        if !self.mode.accepts(kind, platform)
            || !sha(&self.intent_sha256)
            || !uuid(&c.operation_id)
            || !sha(&c.sha256)
        {
            return false;
        }
        match (
            self.mode,
            self.stage_operation_id.as_deref(),
            self.basis.as_ref(),
        ) {
            (
                Mode::CandidateUpload | Mode::CurrentInternal | Mode::RecoverySettlement,
                None,
                None,
            ) => true,
            (
                Mode::ExternalTesting | Mode::ProductionSubmit | Mode::ExternalReadiness,
                Some(id),
                Some(b),
            ) => {
                uuid(id)
                    && id != c.operation_id
                    && uuid(&b.operation_id)
                    && sha(&b.receipt_sha256)
                    && match self.mode {
                        Mode::ExternalTesting => b.operation_id == c.operation_id,
                        Mode::ProductionSubmit => {
                            b.operation_id != c.operation_id && b.operation_id != id
                        }
                        Mode::ExternalReadiness => b.operation_id == id,
                        _ => false,
                    }
            }
            _ => false,
        }
    }
}

/// Semantic label, NEVER a substituted configured Android track name. The
/// exact native config and full validated receipt remain with the old owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Target {
    PlayInternal,
    TestflightInternal,
    ConfiguredPlayExternal,
    TestflightExternal,
    PlayProductionDraft,
    AppStoreSubmission,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ResultKind {
    Accepted,
    Reconciled,
    Ready,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum StoreState {
    AvailableToTesters,
    Draft,
    SubmittedForReview,
    InReview,
    Approved,
    PendingDeveloperRelease,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Limitation {
    NoAutomaticRetry,
    SavedInputsNotAtomic,
    ReceiptNotPublicAvailability,
    NoBuildOrSigning,
    TargetMatchNotPriorFinality,
    NoUploadOrPromotion,
    LocalCheckpointNotPriorFinality,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Receipt {
    pub(crate) mode: Mode,
    pub(crate) head_sequence: u32,
    pub(crate) operation_id: String,
    pub(crate) candidate_operation_id: String,
    pub(crate) candidate_sha256: String,
    pub(crate) intent_sha256: String,
    pub(crate) receipt_sha256: String,
    #[serde(deserialize_with = "nullable")]
    pub(crate) basis: Option<Basis>,
    pub(crate) target: Target,
    pub(crate) result: ResultKind,
    #[serde(deserialize_with = "nullable")]
    pub(crate) state: Option<StoreState>,
    pub(crate) limitations: Vec<Limitation>,
}
impl Receipt {
    pub(crate) fn valid_for(&self, r: &super::Review) -> bool {
        let (Some(c), Some(release)) = (&r.candidate, &r.release) else {
            return false;
        };
        if !release.valid_for(r.kind, r.platform, c)
            || self.mode != release.mode
            || !self.mode.heads().contains(&self.head_sequence)
            || self.operation_id
                != release
                    .stage_operation_id
                    .as_deref()
                    .unwrap_or(&c.operation_id)
            || self.candidate_operation_id != c.operation_id
            || self.candidate_sha256 != c.sha256
            || self.intent_sha256 != release.intent_sha256
            || !sha(&self.receipt_sha256)
            || self.basis != release.basis
            || self.target != self.mode.target(r.platform)
            || self.limitations != self.mode.limitations()
        {
            return false;
        }
        use Mode::*;
        use ResultKind::*;
        use StoreState::*;
        match (self.mode, r.platform, self.result, self.state) {
            (CandidateUpload, _, Accepted | Reconciled, None)
            | (CurrentInternal | RecoverySettlement, _, Reconciled, None)
            | (ExternalTesting, Platform::Android, Accepted, Some(AvailableToTesters))
            | (
                ExternalTesting,
                Platform::Ios,
                Accepted,
                Some(AvailableToTesters | SubmittedForReview | InReview | Approved),
            )
            | (ProductionSubmit, Platform::Android, Accepted, Some(Draft))
            | (
                ProductionSubmit,
                Platform::Ios,
                Accepted,
                Some(SubmittedForReview | InReview | Approved | PendingDeveloperRelease),
            )
            | (ExternalReadiness, Platform::Ios, Ready, Some(AvailableToTesters)) => true,
            _ => false,
        }
    }
}

// Keep the old eight-field bytes exact: even `release:null` is forbidden on
// old kinds. New kinds require the full ninth field, never a default upgrade.
impl<'de> Deserialize<'de> for super::Review {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Base {
            kind: Kind,
            platform: Platform,
            operation_id: crate::service_protocol::Id,
            owner_generation: crate::service_protocol::Id,
            status_revision: u32,
            saved_config: super::Content,
            saved_version: super::Version,
            #[serde(deserialize_with = "nullable")]
            candidate: Option<Candidate>,
        }
        let mut v = serde_json::Value::deserialize(d)?;
        let field = v
            .as_object_mut()
            .ok_or_else(|| serde::de::Error::custom("invalid Store review"))?
            .remove("release");
        let b = Base::deserialize(v).map_err(serde::de::Error::custom)?;
        let release = if matches!(b.kind, Kind::Execute | Kind::Reconcile) {
            Some(
                Review::deserialize(
                    field.ok_or_else(|| serde::de::Error::custom("missing release review"))?,
                )
                .map_err(serde::de::Error::custom)?,
            )
        } else {
            if field.is_some() {
                return Err(serde::de::Error::custom("unexpected release review"));
            }
            None
        };
        let r = Self {
            kind: b.kind,
            platform: b.platform,
            operation_id: b.operation_id,
            owner_generation: b.owner_generation,
            status_revision: b.status_revision,
            saved_config: b.saved_config,
            saved_version: b.saved_version,
            candidate: b.candidate,
            release,
        };
        if !r.valid() {
            return Err(serde::de::Error::custom("invalid Store review"));
        }
        Ok(r)
    }
}

#[cfg(test)]
#[path = "service_store_release_tests.rs"]
pub(crate) mod tests;
