//! Closed discovery DATA for the two existing request inboxes. This is not
//! complete operation history, native finality, or permission to replay a job.
//! The installed client imports no Desktop, document, tool or material owner.
use crate::{
    agent_build_requests as build, agent_local_checks as local,
    service_protocol::{Error, Id, OperationState, Settlement},
};
use serde::{Deserialize, Serialize};

pub const LIMIT: usize = local::LIMIT + build::LIMIT;
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
        + LIMIT * (std::mem::size_of::<Request>() + 3 * 32 + std::mem::size_of::<usize>())
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
}
impl Catalogue {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1 || !self.do_not_replay || self.requests.len() > LIMIT {
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
    if view.requests.is_empty() {
        text.push_str("No requests retained in this instance. A Desktop restart does not prove earlier work settled.\n");
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
        fullest.validate().unwrap();
        let encoded = serde_json::to_vec(&fullest).unwrap();
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
