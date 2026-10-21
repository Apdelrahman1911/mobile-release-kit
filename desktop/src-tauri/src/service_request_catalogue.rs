//! Closed discovery DATA for the existing request inboxes. This is not
//! complete operation history, native finality, or permission to replay a job.
//! The installed client imports no Desktop, document, tool or material owner.
use crate::{
    agent_build_requests as build, agent_local_checks as local,
    service_protocol::{Error, Id, OperationState, Settlement},
};
use serde::{Deserialize, Serialize};

pub(crate) const DETAIL_LIMIT: usize = local::LIMIT + build::LIMIT;
pub(crate) const ADDITIONAL_LIMIT: usize = crate::service_git_protocol::REQUEST_LIMIT
    + crate::agent_identity_requests::LIMIT
    + crate::service_version_reserve_protocol::REQUEST_LIMIT
    + crate::service_upload_key_protocol::REQUEST_LIMIT
    + crate::service_configuration_protocol::REQUEST_LIMIT
    + crate::service_store_protocol::REQUEST_LIMIT
    + crate::service_play_cleanup_protocol::REQUEST_LIMIT
    + crate::service_apple_provisioning_protocol::REQUEST_LIMIT
    + crate::service_version_edit_protocol::REQUEST_LIMIT;
pub const LIMIT: usize = DETAIL_LIMIT + ADDITIONAL_LIMIT;
pub const VIEW_BYTES: usize = 64 * 1024;
// Same eight IPC workers: one typed view, its encoded output, finite borrowed
// inbox-handle lists and small scalar projection scratch each. Existing inbox
// owners and IPC frame/input allocations keep their original charges. No new
// persistent/inbox backing and no Report/Review clone is part of this route.
// This is named backing accounting, not an RSS estimate.
pub(crate) const DOCUMENT_BACKING: usize = 8
    * (VIEW_BYTES
        + std::mem::size_of::<Catalogue>()
        + 64
        + DETAIL_LIMIT * (std::mem::size_of::<Request>() + 3 * 32 + std::mem::size_of::<usize>())
        // The returned IDs plus ONE temporary immutable-input list. All
        // additional inboxes are copied in sequence, never held concurrently.
        + (ADDITIONAL_LIMIT + 32) * (std::mem::size_of::<AdditionalRequest>() + 32)
        + 1024);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    CurrentHostRetainedRequests,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Sampling {
    PerRequestNotAtomic,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Family {
    LocalCheck,
    AndroidBuild,
    IosArchive,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "family",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Progress {
    LocalCheck {
        request_state: local::RequestState,
    },
    AndroidBuild {
        request_state: build::RequestState,
        start_state: build::StartState,
    },
    IosArchive {
        request_state: build::RequestState,
        start_state: build::StartState,
    },
}
impl Progress {
    pub(crate) fn family(&self) -> Family {
        match self {
            Self::LocalCheck { .. } => Family::LocalCheck,
            Self::AndroidBuild { .. } => Family::AndroidBuild,
            Self::IosArchive { .. } => Family::IosArchive,
        }
    }
    fn validate(&self, has_operation: bool) -> Result<(), Error> {
        match self {
            Self::LocalCheck { request_state } => {
                if *request_state == local::RequestState::OriginalAvailable && !has_operation
                    || has_operation
                        && !matches!(
                            request_state,
                            local::RequestState::OriginalAvailable
                                | local::RequestState::AdmissionUnknown
                        )
                {
                    return Err(Error::InvalidRequest);
                }
            }
            Self::AndroidBuild {
                request_state,
                start_state,
            }
            | Self::IosArchive {
                request_state,
                start_state,
            } => {
                if (*request_state == build::RequestState::OriginalAvailable
                    || *start_state != build::StartState::NotRequested)
                    && !has_operation
                {
                    return Err(Error::InvalidRequest);
                }
            }
        }
        Ok(())
    }
}

/// Copies only the original linked IDs and last reported metadata. In
/// particular, neither a child result nor history availability settles work.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Operation {
    pub operation_id: Id,
    pub owner_generation: Id,
    pub status_revision: u32,
    pub state: OperationState,
    pub settlement: Settlement,
}
impl Operation {
    fn validate(&self) -> Result<(), Error> {
        use OperationState as S;
        use Settlement as F;
        let consistent = match self.state {
            S::Prepared | S::Running | S::CancellationRequested => self.settlement == F::Pending,
            S::Succeeded | S::Failed | S::Cancelled => self.settlement == F::Settled,
            S::Unknown => self.settlement == F::Unknown,
            S::RecoveryRequired => matches!(self.settlement, F::Settled | F::Unknown),
        };
        if self.status_revision == 0 || !consistent {
            Err(Error::InvalidRequest)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub request_id: Id,
    pub expected_observation_revision: u64,
    pub progress: Progress,
    pub operation: Option<Operation>,
    pub history_available: bool,
}
impl Request {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.expected_observation_revision == 0
            || self.history_available && self.operation.is_none()
        {
            return Err(Error::InvalidRequest);
        }
        self.progress.validate(self.operation.is_some())?;
        if let Some(operation) = &self.operation {
            operation.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdditionalFamily {
    GitIndex,
    GitCommit,
    GitRepository,
    GitRemote,
    Identity,
    VersionReservation,
    AndroidUploadKey,
    Configuration,
    Store,
    PlayCleanup,
    AppleProvisioning,
    VersionEdit,
}
impl AdditionalFamily {
    fn namespace(self) -> usize {
        match self {
            Self::GitIndex | Self::GitCommit | Self::GitRepository | Self::GitRemote => 0,
            Self::Identity => 1,
            Self::VersionReservation => 2,
            Self::AndroidUploadKey => 3,
            Self::Configuration => 4,
            Self::Store => 5,
            Self::PlayCleanup => 6,
            Self::AppleProvisioning=>7,
            Self::VersionEdit=>8,
        }
    }
    fn status_command(self) -> &'static str {
        match self {
            Self::GitIndex => "git-index-status",
            Self::GitCommit => "git-commit-status",
            Self::GitRepository => "git-repository-status",
            Self::GitRemote => "git-remote-status",
            Self::Identity => "identity-request-status",
            Self::VersionReservation => "version-reserve-status",
            Self::AndroidUploadKey => "upload-key-status",
            Self::Configuration => "configuration-status",
            Self::Store => "store-status",
            Self::PlayCleanup => "play-cleanup-status",
            Self::AppleProvisioning=>"apple-provisioning-status",
            Self::VersionEdit=>"version-edit-status",
        }
    }
}

/// Immutable original IDs only. Reading these rows must not call an inbox's
/// status method: those methods can expire or stop an original request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdditionalRequest {
    pub family: AdditionalFamily,
    pub request_id: Id,
}

// A missing field is valid ONLY for schema 1. In particular, explicit null
// cannot masquerade as an absent legacy field or an empty schema-2 response.
fn present_requests<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Vec<AdditionalRequest>>, D::Error> {
    Vec::<AdditionalRequest>::deserialize(d).map(Some)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Catalogue {
    pub schema_version: u32,
    pub scope: Scope,
    pub sampling: Sampling,
    pub service_instance: Id,
    pub project_id: Id,
    pub do_not_replay: bool,
    pub requests: Vec<Request>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present_requests")]
    pub additional_requests: Option<Vec<AdditionalRequest>>,
}
impl Catalogue {
    pub fn validate(&self) -> Result<(), Error> {
        let additional = match (self.schema_version, &self.additional_requests) {
            (1, None) => &[][..],
            (2, Some(rows)) if rows.len() <= ADDITIONAL_LIMIT => rows.as_slice(),
            _ => return Err(Error::InvalidRequest),
        };
        if !self.do_not_replay || self.requests.len() > DETAIL_LIMIT {
            return Err(Error::InvalidRequest);
        }
        let mut local_count = 0;
        for (index, row) in self.requests.iter().enumerate() {
            row.validate()?;
            let local = row.progress.family() == Family::LocalCheck;
            local_count += usize::from(local);
            // Local checks and the shared build inbox have independent IDs.
            // Android/iOS do NOT get independent ID or capacity namespaces.
            if self.requests[..index].iter().any(|old| {
                (old.progress.family() == Family::LocalCheck) == local
                    && old.request_id == row.request_id
            }) {
                return Err(Error::InvalidRequest);
            }
        }
        if local_count > local::LIMIT || self.requests.len() - local_count > build::LIMIT {
            return Err(Error::InvalidRequest);
        }
        let mut counts = [0usize; 9];
        for (index, row) in additional.iter().enumerate() {
            let namespace = row.family.namespace();
            counts[namespace] += 1;
            if additional[..index].iter().any(|old| {
                old.family.namespace() == namespace && old.request_id == row.request_id
            }) {
                return Err(Error::InvalidRequest);
            }
        }
        if counts[0] > crate::service_git_protocol::REQUEST_LIMIT
            || counts[1] > crate::agent_identity_requests::LIMIT
            || counts[2] > crate::service_version_reserve_protocol::REQUEST_LIMIT
            || counts[3] > crate::service_upload_key_protocol::REQUEST_LIMIT
            || counts[4] > crate::service_configuration_protocol::REQUEST_LIMIT
            || counts[5] > crate::service_store_protocol::REQUEST_LIMIT
            || counts[6] > crate::service_play_cleanup_protocol::REQUEST_LIMIT
            || counts[7] > crate::service_apple_provisioning_protocol::REQUEST_LIMIT
            || counts[8] > crate::service_version_edit_protocol::REQUEST_LIMIT
        {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
}

pub(crate) fn human(view: &Catalogue) -> String {
    let mut text = format!(
        "Retained requests in Desktop instance {} for project {}.\n\
         Sampled per request, not an atomic snapshot or complete operation history.\n\
         Observations are not native authority. Never replay a request from this list.\n",
        view.service_instance.as_str(),
        view.project_id.as_str()
    );
    let additional = view.additional_requests.as_deref().unwrap_or_default();
    if view.requests.is_empty() && additional.is_empty() {
        text.push_str("No requests retained in this instance. A Desktop restart does not prove earlier work settled.\n");
    }
    for row in additional {
        text.push_str(&format!(
            "\n{}  retained original request; inspect its existing status route.\n\
             \x20 Inspect: mrk {} {} {} {}\n",
            row.request_id.as_str(),
            row.family.status_command(),
            view.project_id.as_str(),
            view.service_instance.as_str(),
            row.request_id.as_str()
        ));
    }
    for row in &view.requests {
        let (command, phase) = match &row.progress {
            Progress::LocalCheck { request_state } => {
                use local::RequestState as S;
                let phase = match request_state {
                    S::Queued => "queued",
                    S::Admitting => "admission in progress",
                    S::OriginalAvailable => "original operation linked",
                    S::RefusedBeforeAdmission => "refused before admission",
                    S::CancelledBeforeAdmission => "cancelled before admission",
                    S::Expired => "expired before admission",
                    S::AdmissionUnknown => "admission unknown",
                };
                ("local-check", phase)
            }
            Progress::AndroidBuild { request_state, .. }
            | Progress::IosArchive { request_state, .. } => {
                use build::RequestState as S;
                let phase = match request_state {
                    S::Queued => "queued for preparation",
                    S::Preparing => "preparation in progress",
                    S::OriginalAvailable => "original operation linked",
                    S::RefusedBeforePreparation => "refused before preparation",
                    S::CancelledBeforePreparation => "cancelled before preparation",
                    S::Expired => "expired before preparation",
                    S::AdmissionUnknown => "admission unknown",
                };
                let command = if matches!(&row.progress, Progress::AndroidBuild { .. }) {
                    "android-build"
                } else {
                    "ios-archive"
                };
                (command, phase)
            }
        };
        text.push_str(&format!(
            "\n{}  {command}: {phase}\n",
            row.request_id.as_str()
        ));
        if let Progress::AndroidBuild { start_state, .. }
        | Progress::IosArchive { start_state, .. } = &row.progress
        {
            let start = match start_state {
                build::StartState::NotRequested => "not requested",
                build::StartState::Queued => "queued",
                build::StartState::Admitting => "admission in progress",
                build::StartState::Consumed => "original one-use Start consumed",
            };
            text.push_str(&format!(
                "  Start: {start}. This list does not authorize Start.\n"
            ));
        }
        if let Some(operation) = &row.operation {
            let state = match operation.state {
                OperationState::Prepared => "prepared",
                OperationState::Running => "running",
                OperationState::Succeeded => "succeeded",
                OperationState::Failed => "failed",
                OperationState::CancellationRequested => "cancellation requested",
                OperationState::Cancelled => "cancelled",
                OperationState::RecoveryRequired => "recovery required",
                OperationState::Unknown => "unknown",
            };
            let settlement = match operation.settlement {
                Settlement::Pending => "pending",
                Settlement::Settled => "reported settled",
                Settlement::Unknown => "unknown",
            };
            text.push_str(&format!(
                "  Operation {} / {}: {state}; settlement {settlement}; history {}.\n",
                operation.operation_id.as_str(),
                operation.owner_generation.as_str(),
                if row.history_available {
                    "reported available"
                } else {
                    "unavailable"
                }
            ));
        }
        text.push_str(&format!(
            "  Inspect: mrk {command}-status {} {} {}\n\
             \x20 Stop:    mrk {command}-cancel {} {} {}\n",
            view.project_id.as_str(),
            view.service_instance.as_str(),
            row.request_id.as_str(),
            view.project_id.as_str(),
            view.service_instance.as_str(),
            row.request_id.as_str()
        ));
    }
    text.push_str("\nUse mrk operations for separately saved history. Neither a missing row nor history grants replay.\n");
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(n: u32) -> Id {
        Id::parse(&format!("{n:032x}")).unwrap()
    }
    fn row(n: u32, progress: Progress) -> Request {
        Request {
            request_id: id(n),
            expected_observation_revision: 1,
            progress,
            operation: None,
            history_available: false,
        }
    }
    fn view(requests: Vec<Request>) -> Catalogue {
        Catalogue {
            schema_version: 1,
            scope: Scope::CurrentHostRetainedRequests,
            sampling: Sampling::PerRequestNotAtomic,
            service_instance: id(1),
            project_id: id(2),
            do_not_replay: true,
            requests,
            additional_requests: None,
        }
    }
    #[test]
    fn fixed_families_reject_reports_paths_and_authority_fields() {
        let good = view(vec![row(
            3,
            Progress::LocalCheck {
                request_state: local::RequestState::Queued,
            },
        )]);
        good.validate().unwrap();
        let data = serde_json::to_value(&good).unwrap();
        for field in ["report", "review", "root", "grant", "credential", "command"] {
            let mut changed = data.clone();
            changed["requests"][0][field] = serde_json::json!("not accepted");
            assert!(serde_json::from_value::<Catalogue>(changed).is_err());
        }
        let mut changed = data.clone();
        changed["requests"][0]["progress"]["family"] = serde_json::json!("release");
        assert!(serde_json::from_value::<Catalogue>(changed).is_err());
        let mut changed = good;
        changed.do_not_replay = false;
        assert_eq!(changed.validate(), Err(Error::InvalidRequest));
    }
    #[test]
    fn combined_build_capacity_and_id_namespace_are_not_per_family() {
        let local = || Progress::LocalCheck {
            request_state: local::RequestState::Queued,
        };
        let build = || Progress::AndroidBuild {
            request_state: build::RequestState::Queued,
            start_state: build::StartState::NotRequested,
        };
        let mut rows = (1..=32).map(|n| row(n, local())).collect::<Vec<_>>();
        rows.extend((1..=32).map(|n| row(n, build())));
        let mut data = view(rows);
        data.validate().unwrap(); // Same ID in DIFFERENT original inboxes is unambiguous.
        let mut fullest = data.clone();
        for (index, row) in fullest.requests.iter_mut().enumerate() {
            row.expected_observation_revision = u64::MAX;
            row.progress = if index < local::LIMIT {
                Progress::LocalCheck {
                    request_state: local::RequestState::AdmissionUnknown,
                }
            } else {
                Progress::AndroidBuild {
                    request_state: build::RequestState::AdmissionUnknown,
                    start_state: build::StartState::Consumed,
                }
            };
            row.operation = Some(Operation {
                operation_id: id(1000 + index as u32),
                owner_generation: id(2000 + index as u32),
                status_revision: u32::MAX,
                state: OperationState::CancellationRequested,
                settlement: Settlement::Pending,
            });
            row.history_available = true;
        }
        fullest.schema_version = 2;
        fullest.additional_requests = Some(
            [AdditionalFamily::GitIndex, AdditionalFamily::Identity, AdditionalFamily::VersionReservation, AdditionalFamily::AndroidUploadKey, AdditionalFamily::Configuration, AdditionalFamily::Store, AdditionalFamily::PlayCleanup, AdditionalFamily::AppleProvisioning, AdditionalFamily::VersionEdit]
                .into_iter()
                .flat_map(|family| (1..=32).map(move |n| AdditionalRequest { family, request_id: id(n) }))
                .collect(),
        );
        fullest.validate().unwrap();
        let response = crate::service_protocol::Response {
            version: crate::service_protocol::VERSION,
            request_id: id(10),
            service_instance: fullest.service_instance.clone(),
            client_id: id(11),
            session_id: id(12),
            response: crate::service_protocol::ResponseBody::Requests(fullest),
        };
        let encoded = crate::service_protocol::encode_response(&response).unwrap();
        assert!(encoded.len() <= VIEW_BYTES);
        assert!(DOCUMENT_BACKING < 1024 * 1024);
        data.requests[63].progress = Progress::IosArchive {
            request_state: build::RequestState::Queued,
            start_state: build::StartState::NotRequested,
        };
        data.validate().unwrap();
        data.requests[63].request_id = id(1);
        assert!(data.validate().is_err()); // Android/iOS share the one ID namespace.
        data.requests[63].request_id = id(32);
        data.requests.remove(0);
        data.requests.push(row(33, build())); // 64 total is not enough: now 33 builds.
        assert!(data.validate().is_err());
    }
    #[test]
    fn additional_ids_have_strict_schema_presence_privacy_and_original_commands() {
        let legacy = view(vec![]);
        let old = serde_json::to_value(&legacy).unwrap();
        assert!(old.get("additionalRequests").is_none());
        let accepted = |value: serde_json::Value| {
            serde_json::from_value::<Catalogue>(value).is_ok_and(|v| v.validate().is_ok())
        };
        assert!(accepted(old.clone()));
        for version in [1, 2, 3] {
            for field in [None, Some(serde_json::Value::Null), Some(serde_json::json!([]))] {
                let mut changed = old.clone();
                changed["schemaVersion"] = serde_json::json!(version);
                if let Some(value) = &field { changed["additionalRequests"] = value.clone(); }
                assert_eq!(accepted(changed), version == 1 && field.is_none()
                    || version == 2 && field.as_ref().is_some_and(|v| v.is_array()));
            }
        }
        let mut current = legacy;
        current.schema_version = 2;
        current.additional_requests = Some(vec![
            AdditionalRequest { family: AdditionalFamily::GitIndex, request_id: id(3) },
            AdditionalRequest { family: AdditionalFamily::GitCommit, request_id: id(4) },
            AdditionalRequest { family: AdditionalFamily::Identity, request_id: id(3) },
            AdditionalRequest { family: AdditionalFamily::VersionReservation, request_id: id(3) },
            AdditionalRequest { family: AdditionalFamily::AndroidUploadKey, request_id: id(3) },
            AdditionalRequest { family: AdditionalFamily::Configuration, request_id: id(3) },
            AdditionalRequest { family: AdditionalFamily::Store, request_id: id(3) },
            AdditionalRequest { family: AdditionalFamily::PlayCleanup, request_id: id(3) },
            AdditionalRequest { family: AdditionalFamily::AppleProvisioning, request_id: id(3) },
            AdditionalRequest { family: AdditionalFamily::VersionEdit, request_id: id(3) },
        ]);
        current.validate().unwrap();
        let text = human(&current);
        assert!(!text.contains("No requests retained"));
        for (command, n) in [("git-index-status",3), ("git-commit-status",4),
            ("identity-request-status",3), ("version-reserve-status",3), ("upload-key-status",3), ("configuration-status",3), ("store-status",3), ("play-cleanup-status",3), ("apple-provisioning-status",3), ("version-edit-status",3)] {
            assert!(text.contains(&format!("mrk {command} {} {} {}", id(2).as_str(), id(1).as_str(), id(n).as_str())));
        }
        let encoded = serde_json::to_value(&current).unwrap();
        assert!(accepted(encoded.clone()));
        for field in ["report", "draft", "root", "desiredIdentity", "grantId", "credential", "state", "review"] {
            let mut changed = encoded.clone();
            changed["additionalRequests"][0][field] = serde_json::json!("private sentinel");
            assert!(!accepted(changed));
        }
        let mut changed = encoded;
        changed["additionalRequests"][0]["family"] = serde_json::json!("publish");
        assert!(!accepted(changed));
        current.additional_requests.as_mut().unwrap()[1].request_id = id(3);
        assert!(current.validate().is_err()); // Stage and Commit share one namespace.
        for family in [AdditionalFamily::GitIndex, AdditionalFamily::Identity, AdditionalFamily::VersionReservation, AdditionalFamily::AndroidUploadKey, AdditionalFamily::Configuration, AdditionalFamily::Store, AdditionalFamily::PlayCleanup, AdditionalFamily::AppleProvisioning, AdditionalFamily::VersionEdit] {
            current.additional_requests = Some((1..=33).map(|n| AdditionalRequest { family, request_id: id(n) }).collect());
            assert!(current.validate().is_err());
            current.additional_requests = Some(vec![AdditionalRequest { family, request_id: id(3) }; 2]);
            assert!(current.validate().is_err());
        }
    }
    #[test]
    fn unknown_pending_and_missing_history_never_become_settlement() {
        let mut request = row(
            3,
            Progress::LocalCheck {
                request_state: local::RequestState::AdmissionUnknown,
            },
        );
        request.operation = Some(Operation {
            operation_id: id(4),
            owner_generation: id(5),
            status_revision: 2,
            state: OperationState::RecoveryRequired,
            settlement: Settlement::Unknown,
        });
        let mut data = view(vec![request]);
        data.validate().unwrap();
        let roundtrip: Catalogue =
            serde_json::from_slice(&serde_json::to_vec(&data).unwrap()).unwrap();
        assert_eq!(roundtrip, data);
        assert!(human(&data).contains("settlement unknown; history unavailable"));
        let operation = data.requests[0].operation.as_mut().unwrap();
        operation.state = OperationState::Running;
        assert!(data.validate().is_err());
        data.requests[0].operation = None;
        data.requests[0].history_available = true;
        assert!(data.validate().is_err());
    }
    #[test]
    fn missing_after_restart_is_not_permission_and_commands_keep_original_ids() {
        let empty = view(vec![]);
        assert!(human(&empty).contains("restart does not prove earlier work settled"));
        let data = view(vec![row(
            3,
            Progress::IosArchive {
                request_state: build::RequestState::AdmissionUnknown,
                start_state: build::StartState::NotRequested,
            },
        )]);
        data.validate().unwrap();
        let text = human(&data);
        assert!(text.contains(&format!(
            "mrk ios-archive-status {} {} {}",
            id(2).as_str(),
            id(1).as_str(),
            id(3).as_str()
        )));
        assert!(text.contains(&format!(
            "mrk ios-archive-cancel {} {} {}",
            id(2).as_str(),
            id(1).as_str(),
            id(3).as_str()
        )));
        assert!(
            !text.contains("mrk ios-archive-start") && !text.contains("mrk ios-archive-prepare")
        );
    }
}
