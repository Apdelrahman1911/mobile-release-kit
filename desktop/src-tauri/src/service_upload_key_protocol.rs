//! Fixed Android upload-key delegation DATA. No file, material, picker result,
//! assessment, tool or credential authority crosses the installed IPC.
use crate::service_protocol::{Error, Id, Settlement};
use serde::{Deserialize, Deserializer, Serialize};

pub(crate) const REQUEST_LIMIT: usize = 32;
pub(crate) const CONSENT_LIMIT: usize = 32;
pub(crate) const RAW_LIMIT: usize = 1024;
pub(crate) const VIEW_LIMIT: usize = 4096;
pub(crate) const ALLOW_SECONDS: u64 = 300;
pub(crate) const DECLARATION: &str = "new-application-no-existing-upload-key";
pub(crate) const RESTORE_DECLARATION: &str = "restore-as-new-unassigned";

fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    GenerateNew,
    BindReviewed,
    BackupEncrypted,
    RestoreEncrypted,
}
impl Kind {
    pub(crate) fn consent(self) -> &'static str {
        match self {
            Self::GenerateNew => "agent-android-upload-key-generate-once-v1",
            Self::BindReviewed => "agent-android-upload-key-bind-once-v1",
            Self::BackupEncrypted => "agent-android-upload-key-backup-once-v1",
            Self::RestoreEncrypted => "agent-android-upload-key-restore-once-v1",
        }
    }
}

/// Main-window input ONLY. Empty struct variants retain deny_unknown_fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum Selection {
    GenerateNew {
        declaration: String,
    },
    BindReviewed {
        preview_operation_id: u32,
        preview_token: String,
    },
    BackupEncrypted {
        record_id: Id,
        expected_revision: u32,
    },
    RestoreEncrypted {
        declaration: String,
    },
}
impl Selection {
    pub(crate) fn kind(&self) -> Kind {
        match self {
            Self::GenerateNew { .. } => Kind::GenerateNew,
            Self::BindReviewed { .. } => Kind::BindReviewed,
            Self::BackupEncrypted { .. } => Kind::BackupEncrypted,
            Self::RestoreEncrypted { .. } => Kind::RestoreEncrypted,
        }
    }
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::GenerateNew { declaration } => declaration == DECLARATION,
            Self::BindReviewed {
                preview_operation_id,
                preview_token,
            } => (1..u32::MAX).contains(preview_operation_id) && Id::parse(preview_token).is_ok(),
            Self::BackupEncrypted { expected_revision, .. } => {
                (1..u32::MAX).contains(expected_revision)
            }
            Self::RestoreEncrypted { declaration } => declaration == RESTORE_DECLARATION,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub project_id: Id,
    pub service_instance: Id,
    pub request_id: Id,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Submit {
    pub origin: Query,
    pub grant_id: Id,
}

/// Same authenticated reference, comparison DATA only. It cannot Load or Bind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyReference {
    pub vault_id: Id,
    pub generation_id: Id,
    pub record_id: Id,
    pub revision_id: Id,
    pub revision_counter: u64,
}
impl KeyReference {
    pub(crate) fn valid(&self) -> bool {
        let ids = [
            &self.vault_id,
            &self.generation_id,
            &self.record_id,
            &self.revision_id,
        ];
        self.revision_counter > 0
            && self.revision_counter <= 9_007_199_254_740_991
            && ids
                .iter()
                .enumerate()
                .all(|(i, a)| ids.iter().skip(i + 1).all(|b| a != b))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Access {
    pub schema_version: u32,
    #[serde(deserialize_with = "nullable")]
    pub service_instance: Option<Id>,
    #[serde(deserialize_with = "nullable")]
    pub project_id: Option<Id>,
    #[serde(deserialize_with = "nullable")]
    pub grant_id: Option<Id>,
    #[serde(deserialize_with = "nullable")]
    pub kind: Option<Kind>,
    #[serde(deserialize_with = "nullable")]
    pub request_id: Option<Id>,
    pub enabled: bool,
    pub remaining_ms: u64,
    pub consumed: bool,
}
impl Access {
    pub(crate) fn empty() -> Self {
        Self {
            schema_version: 1,
            service_instance: None,
            project_id: None,
            grant_id: None,
            kind: None,
            request_id: None,
            enabled: false,
            remaining_ms: 0,
            consumed: false,
        }
    }
    pub fn validate(&self) -> Result<(), Error> {
        let fields = [
            self.service_instance.is_some(),
            self.project_id.is_some(),
            self.grant_id.is_some(),
            self.kind.is_some(),
        ];
        if self.schema_version != 1
            || fields.iter().any(|v| *v != fields[0])
            || self.enabled && (!fields[0] || self.remaining_ms == 0 || self.consumed)
            || !self.enabled && self.remaining_ms != 0
            || self.remaining_ms > ALLOW_SECONDS * 1000
            || self.request_id.is_some() != self.consumed
            || self.consumed && !fields[0]
        {
            Err(Error::InvalidRequest)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    Queued,
    Running,
    StopRequested,
    SavedUnassigned,
    Assigned,
    BackupDelivered,
    RestoredUnassigned,
    Refused,
    Cancelled,
    Failed,
    RecoveryRequired,
    Unknown,
}
impl State {
    pub(crate) fn success(self) -> bool {
        matches!(self, Self::SavedUnassigned | Self::Assigned | Self::BackupDelivered | Self::RestoredUnassigned)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    None,
    PermissionRevoked,
    Expired,
    ContextChanged,
    Refused,
    NativeFailure,
    RecoveryRequired,
    CleanupUnknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    pub schema_version: u32,
    pub origin: Query,
    pub grant_id: Id,
    pub kind: Kind,
    pub state: State,
    pub settlement: Settlement,
    pub reason: Reason,
    #[serde(deserialize_with = "nullable")]
    pub asset_operation_id: Option<u32>,
    #[serde(deserialize_with = "nullable")]
    pub key: Option<KeyReference>,
    pub do_not_replay: bool,
}
impl Status {
    pub fn validate(&self) -> Result<(), Error> {
        use State::*;
        let settled = matches!(
            self.state,
            SavedUnassigned | Assigned | BackupDelivered | RestoredUnassigned | Refused | Cancelled | Failed
        );
        if self.schema_version != 1
            || !self.do_not_replay
            || self
                .asset_operation_id
                .is_some_and(|v| !(1..u32::MAX).contains(&v))
            || self.key.as_ref().is_some_and(|v| !v.valid())
            || matches!(self.state, Queued | Running | StopRequested)
                && self.settlement != Settlement::Pending
            || settled && self.settlement != Settlement::Settled
            || self.state == Unknown
                && (self.settlement != Settlement::Unknown || self.reason != Reason::CleanupUnknown)
            || self.state == RecoveryRequired
                && !matches!(self.settlement, Settlement::Settled | Settlement::Unknown)
            || self.state == SavedUnassigned && self.kind != Kind::GenerateNew
            || self.state == Assigned && self.kind != Kind::BindReviewed
            || self.state == BackupDelivered && self.kind != Kind::BackupEncrypted
            || self.state == RestoredUnassigned && self.kind != Kind::RestoreEncrypted
            || self.state == RestoredUnassigned && self.key.as_ref().is_some_and(|k| k.revision_counter != 1)
            || matches!(self.state, SavedUnassigned | Assigned | RestoredUnassigned) != self.key.is_some()
            || self.state.success()
                && (self.asset_operation_id.is_none() || self.reason != Reason::None)
            || matches!(self.state, Queued | Running) && self.reason != Reason::None
            || matches!(
                self.state,
                StopRequested | Refused | Cancelled | Failed | RecoveryRequired
            ) && self.reason == Reason::None
        {
            Err(Error::InvalidRequest)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actions_require_exact_distinct_desktop_consents_and_no_private_fields() {
        let generate = serde_json::json!({"kind":"generate-new","declaration":DECLARATION});
        let g: Selection = serde_json::from_value(generate.clone()).unwrap();
        assert!(g.valid());
        assert_ne!(g.kind().consent(), Kind::BindReviewed.consent());
        for extra in ["password", "path", "fields", "recordId", "command"] {
            let mut v = generate.clone();
            v[extra] = serde_json::json!("x");
            assert!(serde_json::from_value::<Selection>(v).is_err());
        }
        assert!(serde_json::from_value::<Selection>(serde_json::json!({"kind":"bind-reviewed","previewOperationId":1,"previewToken":"a".repeat(32)})).unwrap().valid());
        assert!(
            serde_json::from_value::<Selection>(serde_json::json!({"kind":"generate-new"}))
                .is_err()
        );
    }
    #[test]
    fn access_requires_nullable_fields_and_never_renews_consumed_permission() {
        let mut v = serde_json::to_value(Access::empty()).unwrap();
        Access::empty().validate().unwrap();
        v.as_object_mut().unwrap().remove("grantId");
        assert!(serde_json::from_value::<Access>(v).is_err());
        let mut a = Access::empty();
        a.enabled = true;
        a.remaining_ms = 1;
        assert!(a.validate().is_err());
    }
}
