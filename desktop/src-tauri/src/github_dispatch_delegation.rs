//! Closed native MAIN inputs retained on the EXISTING family state. The CLI
//! compiles only compact references/results; it cannot construct these captures.
use super::*;
use crate::{
    asset_source::RegisteredRoot, edit_owner::SavedEditGuard, github_preflight_protocol as pf,
    github_publication_protocol as publication, github_release_protocol as rl,
};
use serde::{Deserialize, Serialize};
// Physical capacities of this one MAIN capture; the existing48KiB call envelope
// charges all simultaneous copies. No private source/Prepared is charged here.
pub(crate) const ROOT_BACKING: usize = 4096;
pub(crate) const INPUT_BACKING: usize = 2048;
pub(crate) const CONTEXT_BACKING: usize = 512;
fn sum_capacities(v: &[usize]) -> Option<usize> {
    v.iter().try_fold(0usize, |n, v| n.checked_add(*v))
}
fn release_input_heap(v: &rl::PrepareArgs) -> Option<usize> {
    sum_capacities(&[v.session_id.capacity(), v.branch.capacity(),
        v.selection.candidate_run_id.as_ref().map_or(0, String::capacity),
        v.selection.external_run_id.as_ref().map_or(0, String::capacity),
        v.selection.recovery_run_id.as_ref().map_or(0, String::capacity),
        v.selection.original_source_sha.as_ref().map_or(0, String::capacity),
        v.selection.recovery_confirmation.as_ref().map_or(0, String::capacity),
        v.selection.original_version.as_ref().map_or(0, |v| v.name.capacity())])
}
fn observe_input_heap(v: &ObserveSelection) -> Option<usize> {
    sum_capacities(&[v.session_id.capacity(),v.marker.capacity(),
        v.run_id.as_ref().map_or(0, String::capacity)])
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ObserveSelection {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) marker: String,
    pub(crate) observe: p::dispatch::Observe,
    #[serde(deserialize_with = "crate::github_connection_protocol::nullable")]
    pub(crate) run_id: Option<String>,
}
impl ObserveSelection {
    fn valid(&self) -> bool {
        crate::protocol::valid_id(&self.session_id)
            && self.expected_revision > 0
            && p::hex(&self.marker, 32)
            && (self.observe == p::dispatch::Observe::Track) == self.run_id.is_some()
            && self
                .run_id
                .as_ref()
                .is_none_or(|id| crate::github_connection_protocol::numeric_id(id))
    }
}
/// MAIN comparison input is purpose-absent. Do not serialize PrepareArgs
/// here: its unchanged optional purpose serializes null. Only the final command
/// conversion below constructs that existing native type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OrdinarySetupPrepare {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32,
    pub(crate) base: String,
}
impl OrdinarySetupPrepare {
    pub(crate) fn command_args(&self) -> publication::PrepareArgs {
        publication::PrepareArgs {
            session_id: self.session_id.clone(),
            expected_revision: self.expected_revision,
            expected_connection_revision: self.expected_connection_revision,
            base: self.base.clone(),
            purpose: None,
        }
    }
    fn valid(&self) -> bool {
        // Same original scalar/branch policy, no provider or new source claim.
        crate::protocol::valid_id(&self.session_id)
            && self.expected_revision > 0
            && self.expected_revision <= publication::LAST_REVISION
            && self.expected_connection_revision > 0
            && self.expected_connection_revision <= publication::LAST_REVISION
            && crate::github_preflight_protocol::branch(&self.base)
    }
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Selection {
    RepositoryCreate(p::PreparedSelection),
    DraftPrCreate(p::PreparedSelection),
    PrCreate(p::PreparedSelection),
    FailedJobsRetry(p::PreparedSelection),
    SetupPublish(p::PreparedSelection),
    SetupReconcile(p::PendingSelection),
    ActivityOverview(p::activity::Selection),
    PreflightPrepare(pf::PrepareArgs),
    PreflightDispatch(pf::DispatchArgs),
    PreflightPending(pf::ControlArgs),
    PreflightObserve(ObserveSelection),
    ReleasePrepare(rl::PrepareArgs),
    ReleaseDispatch(rl::DispatchArgs),
    ReleasePending(rl::ControlArgs),
    ReleaseObserve(ObserveSelection),
    SetupPrepare(OrdinarySetupPrepare),
    CounterPrepare(publication::PrepareArgs),
    CounterCreate(publication::PublishArgs),
    PublicationPending(publication::PendingArgs),
    CounterReconcile(publication::ReconcileArgs),
    CounterEnrollmentReview(p::enrollment::ReviewSelection),
    CounterEnrollmentConnect(p::enrollment::ConnectSelection),
}
impl Selection {
    pub(crate) fn enrollment_input(&self) -> Option<p::enrollment::Input> {
        Some(match self {
            Self::CounterEnrollmentReview(v) => p::enrollment::Input::CounterEnrollmentReview(v.clone()),
            Self::CounterEnrollmentConnect(v) => p::enrollment::Input::CounterEnrollmentConnect(v.clone()),
            _ => return None,
        })
    }
    pub(crate) fn prepared(&self) -> Option<&p::PreparedSelection> {
        match self {
            Self::RepositoryCreate(v)
            | Self::DraftPrCreate(v)
            | Self::PrCreate(v)
            | Self::FailedJobsRetry(v)
            | Self::SetupPublish(v) => Some(v),
            _ => None,
        }
    }
    pub(crate) fn legacy(&self) -> Option<p::Selection> {
        Some(match self {
            Self::RepositoryCreate(v) => p::Selection::RepositoryCreate(v.clone()),
            Self::DraftPrCreate(v) => p::Selection::DraftPrCreate(v.clone()),
            Self::PrCreate(v) => p::Selection::PrCreate(v.clone()),
            Self::FailedJobsRetry(v) => p::Selection::FailedJobsRetry(v.clone()),
            Self::SetupPublish(v) => p::Selection::SetupPublish(v.clone()),
            Self::SetupReconcile(v) => p::Selection::SetupReconcile(v.clone()),
            Self::ActivityOverview(v) => p::Selection::ActivityOverview(v.clone()),
            _ => return None,
        })
    }
    pub(crate) fn input(&self) -> Option<Input> {
        Some(match self {
            Self::PreflightPrepare(v) => Input::PreflightPrepare(v.clone()),
            Self::PreflightDispatch(v) => Input::PreflightDispatch(v.clone()),
            Self::PreflightPending(v) => Input::PreflightPending(v.clone()),
            Self::PreflightObserve(v) => Input::PreflightObserve(v.clone()),
            Self::ReleasePrepare(v) => Input::ReleasePrepare(v.clone()),
            Self::ReleaseDispatch(v) => Input::ReleaseDispatch(v.clone()),
            Self::ReleasePending(v) => Input::ReleasePending(v.clone()),
            Self::ReleaseObserve(v) => Input::ReleaseObserve(v.clone()),
            Self::SetupPrepare(v) => Input::SetupPrepare(v.clone()),
            Self::CounterPrepare(v) => Input::CounterPrepare(v.clone()),
            Self::CounterCreate(v) => Input::CounterCreate(v.clone()),
            Self::PublicationPending(v) => Input::PublicationPending(v.clone()),
            Self::CounterReconcile(v) => Input::CounterReconcile(v.clone()),
            _ => return None,
        })
    }
    pub(crate) fn kind(&self) -> p::Kind {
        match self {
            Self::RepositoryCreate(_) => p::Kind::RepositoryCreate,
            Self::DraftPrCreate(_) => p::Kind::DraftPrCreate,
            Self::PrCreate(_) => p::Kind::PrCreate,
            Self::FailedJobsRetry(_) => p::Kind::FailedJobsRetry,
            Self::SetupPublish(_) => p::Kind::SetupPublish,
            Self::SetupReconcile(_) => p::Kind::SetupReconcile,
            Self::ActivityOverview(_) => p::Kind::ActivityOverview,
            Self::PreflightPrepare(_) => p::Kind::PreflightPrepare,
            Self::PreflightDispatch(_) => p::Kind::PreflightDispatch,
            Self::PreflightPending(_) => p::Kind::PreflightPending,
            Self::PreflightObserve(_) => p::Kind::PreflightObserve,
            Self::ReleasePrepare(_) => p::Kind::ReleasePrepare,
            Self::ReleaseDispatch(_) => p::Kind::ReleaseDispatch,
            Self::ReleasePending(_) => p::Kind::ReleasePending,
            Self::ReleaseObserve(_) => p::Kind::ReleaseObserve,
            Self::SetupPrepare(_) => p::Kind::SetupPrepare,
            Self::CounterPrepare(_) => p::Kind::CounterPrepare,
            Self::CounterCreate(_) => p::Kind::CounterCreate,
            Self::PublicationPending(_) => p::Kind::PublicationPending,
            Self::CounterReconcile(_) => p::Kind::CounterReconcile,
            Self::CounterEnrollmentReview(_) => p::Kind::CounterEnrollmentReview,
            Self::CounterEnrollmentConnect(_) => p::Kind::CounterEnrollmentConnect,
        }
    }
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::CounterEnrollmentReview(v) => return v.valid(),
            Self::CounterEnrollmentConnect(v) => return v.valid(),
            _ => {}
        }
        self.legacy()
            .map_or_else(|| self.input().is_some_and(|v| v.valid()), |v| v.valid())
    }
    pub(crate) fn retained_fits(&self) -> bool {
        let bytes = match self {
            Self::CounterEnrollmentReview(v) => Some(v.session_id.capacity()),
            Self::CounterEnrollmentConnect(v) => v.session_id.capacity().checked_add(v.review_id.capacity()),
            Self::PreflightPrepare(v) => sum_capacities(&[v.session_id.capacity(),v.branch.capacity()]),
            Self::ReleasePrepare(v) => release_input_heap(v),
            Self::SetupPrepare(v) => sum_capacities(&[v.session_id.capacity(),v.base.capacity()]),
            Self::CounterPrepare(v) => sum_capacities(&[v.session_id.capacity(),v.base.capacity()]),
            Self::PreflightDispatch(v) => sum_capacities(&[v.session_id.capacity(),v.consent_id.capacity()]),
            Self::ReleaseDispatch(v) => sum_capacities(&[v.session_id.capacity(),v.consent_id.capacity(),v.confirmation.capacity()]),
            Self::CounterCreate(v) => sum_capacities(&[v.session_id.capacity(),v.consent_id.capacity()]),
            Self::PreflightPending(v) => Some(v.session_id.capacity()),
            Self::ReleasePending(v) => Some(v.session_id.capacity()),
            Self::PublicationPending(v) => Some(v.session_id.capacity()),
            Self::PreflightObserve(v) | Self::ReleaseObserve(v) => observe_input_heap(v),
            Self::CounterReconcile(v) => sum_capacities(&[v.session_id.capacity(),v.marker.capacity()]),
            _ => return true, // original seven native formats retain their old bounds
        };
        bytes.is_some_and(|n| n <= INPUT_BACKING)
    }
    pub(crate) fn limit(&self) -> usize {
        if matches!(
            self,
            Self::PreflightPrepare(_) | Self::ReleasePrepare(_) | Self::SetupPrepare(_) | Self::CounterPrepare(_)
        ) {
            4096
        } else {
            p::RAW_LIMIT
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(crate) enum Input {
    PreflightPrepare(pf::PrepareArgs),
    PreflightDispatch(pf::DispatchArgs),
    PreflightPending(pf::ControlArgs),
    PreflightObserve(ObserveSelection),
    ReleasePrepare(rl::PrepareArgs),
    ReleaseDispatch(rl::DispatchArgs),
    ReleasePending(rl::ControlArgs),
    ReleaseObserve(ObserveSelection),
    SetupPrepare(OrdinarySetupPrepare),
    CounterPrepare(publication::PrepareArgs),
    CounterCreate(publication::PublishArgs),
    PublicationPending(publication::PendingArgs),
    CounterReconcile(publication::ReconcileArgs),
}
impl Input {
    pub(crate) fn kind(&self) -> p::Kind {
        match self {
            Self::PreflightPrepare(_) => p::Kind::PreflightPrepare,
            Self::PreflightDispatch(_) => p::Kind::PreflightDispatch,
            Self::PreflightPending(_) => p::Kind::PreflightPending,
            Self::PreflightObserve(_) => p::Kind::PreflightObserve,
            Self::ReleasePrepare(_) => p::Kind::ReleasePrepare,
            Self::ReleaseDispatch(_) => p::Kind::ReleaseDispatch,
            Self::ReleasePending(_) => p::Kind::ReleasePending,
            Self::ReleaseObserve(_) => p::Kind::ReleaseObserve,
            Self::SetupPrepare(_) => p::Kind::SetupPrepare,
            Self::CounterPrepare(_) => p::Kind::CounterPrepare,
            Self::CounterCreate(_) => p::Kind::CounterCreate,
            Self::PublicationPending(_) => p::Kind::PublicationPending,
            Self::CounterReconcile(_) => p::Kind::CounterReconcile,
        }
    }
    pub(crate) fn session(&self) -> &str {
        match self {
            Self::PreflightPrepare(v) => &v.session_id,
            Self::PreflightDispatch(v) => &v.session_id,
            Self::PreflightPending(v) => &v.session_id,
            Self::PreflightObserve(v) => &v.session_id,
            Self::ReleasePrepare(v) => &v.session_id,
            Self::ReleaseDispatch(v) => &v.session_id,
            Self::ReleasePending(v) => &v.session_id,
            Self::ReleaseObserve(v) => &v.session_id,
            Self::SetupPrepare(v) => &v.session_id,
            Self::CounterPrepare(v) => &v.session_id,
            Self::CounterCreate(v) => &v.session_id,
            Self::PublicationPending(v) => &v.session_id,
            Self::CounterReconcile(v) => &v.session_id,
        }
    }
    pub(crate) fn revision(&self) -> u32 {
        match self {
            Self::PreflightPrepare(v) => v.expected_revision,
            Self::PreflightDispatch(v) => v.expected_revision,
            Self::PreflightPending(v) => v.expected_revision,
            Self::PreflightObserve(v) => v.expected_revision,
            Self::ReleasePrepare(v) => v.expected_revision,
            Self::ReleaseDispatch(v) => v.expected_revision,
            Self::ReleasePending(v) => v.expected_revision,
            Self::ReleaseObserve(v) => v.expected_revision,
            Self::SetupPrepare(v) => v.expected_revision,
            Self::CounterPrepare(v) => v.expected_revision,
            Self::CounterCreate(v) => v.expected_revision,
            Self::PublicationPending(v) => v.expected_revision,
            Self::CounterReconcile(v) => v.expected_revision,
        }
    }
    pub(crate) fn connection_revision(&self) -> Option<u32> {
        match self {
            Self::PreflightPrepare(v) => Some(v.expected_connection_revision),
            Self::ReleasePrepare(v) => Some(v.expected_connection_revision),
            Self::SetupPrepare(v) => Some(v.expected_connection_revision),
            Self::CounterPrepare(v) => Some(v.expected_connection_revision),
            Self::PublicationPending(v) => Some(v.expected_connection_revision),
            _ => None,
        }
    }
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::PreflightPrepare(v) => v.valid(),
            Self::PreflightDispatch(v) => v.valid(),
            Self::PreflightPending(v) => v.valid(),
            Self::PreflightObserve(v) => v.valid(),
            Self::ReleasePrepare(v) => v.valid(),
            Self::ReleaseDispatch(v) => v.valid(),
            Self::ReleasePending(v) => v.valid(),
            Self::ReleaseObserve(v) => v.valid(),
            Self::SetupPrepare(v) => v.valid(),
            Self::CounterPrepare(v) => {
                v.valid() && v.purpose == Some(publication::counter::Purpose::Counter)
            }
            Self::CounterCreate(v) => v.valid(),
            Self::PublicationPending(v) => v.valid(),
            Self::CounterReconcile(v) => v.valid(),
        }
    }
    pub(crate) fn hash(&self) -> Result<String, BridgeError> {
        hash(self)
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        let mut n = match self {
            Self::PreflightPrepare(v) => v.session_id.capacity(),
            Self::PreflightDispatch(v) => v.session_id.capacity(),
            Self::PreflightPending(v) => v.session_id.capacity(),
            Self::PreflightObserve(v) => v.session_id.capacity(),
            Self::ReleasePrepare(v) => v.session_id.capacity(),
            Self::ReleaseDispatch(v) => v.session_id.capacity(),
            Self::ReleasePending(v) => v.session_id.capacity(),
            Self::ReleaseObserve(v) => v.session_id.capacity(),
            Self::SetupPrepare(v) => v.session_id.capacity(),
            Self::CounterPrepare(v) => v.session_id.capacity(),
            Self::CounterCreate(v) => v.session_id.capacity(),
            Self::PublicationPending(v) => v.session_id.capacity(),
            Self::CounterReconcile(v) => v.session_id.capacity(),
        };
        match self {
            Self::PreflightPrepare(v) => n = n.checked_add(v.branch.capacity())?,
            Self::ReleasePrepare(v) => {
                n = n.checked_add(v.branch.capacity())?;
                for s in [
                    &v.selection.candidate_run_id,
                    &v.selection.external_run_id,
                    &v.selection.recovery_run_id,
                    &v.selection.original_source_sha,
                    &v.selection.recovery_confirmation,
                ] {
                    n = n.checked_add(s.as_ref().map_or(0, String::capacity))?;
                }
                if let Some(v) = &v.selection.original_version {
                    n = n.checked_add(v.name.capacity())?;
                }
            }
            Self::PreflightDispatch(v) => n = n.checked_add(v.consent_id.capacity())?,
            Self::ReleaseDispatch(v) => {
                n = n
                    .checked_add(v.consent_id.capacity())?
                    .checked_add(v.confirmation.capacity())?
            }
            Self::PreflightObserve(v) | Self::ReleaseObserve(v) => {
                n = n
                    .checked_add(v.marker.capacity())?
                    .checked_add(v.run_id.as_ref().map_or(0, String::capacity))?
            }
            Self::SetupPrepare(v) => n = n.checked_add(v.base.capacity())?,
            Self::CounterPrepare(v) => n = n.checked_add(v.base.capacity())?,
            Self::CounterCreate(v) => n = n.checked_add(v.consent_id.capacity())?,
            Self::CounterReconcile(v) => n = n.checked_add(v.marker.capacity())?,
            _ => {}
        }
        Some(n)
    }
}

pub(crate) fn hash<T: Serialize + ?Sized>(value: &T) -> Result<String, BridgeError> {
    let mut h = super::Hash { sha: Sha256::new() };
    serde_json::to_writer(&mut h, value).map_err(|_| BridgeError::protocol())?;
    Ok(format!("{:x}", h.sha.finalize()))
}
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Capture {
    pub(crate) input: Input,
    pub(crate) generation: u32,
    pub(crate) root: RegisteredRoot,
    pub(crate) credential_end: Instant,
    pub(crate) account: String,
    pub(crate) repository: String,
    pub(crate) coordinate: String,
    pub(crate) binding: String,
}
impl Capture {
    pub(crate) fn retained_fits(&self) -> bool {
        self.root.path.capacity() <= ROOT_BACKING
            && self.input.heap().is_some_and(|n| n <= INPUT_BACKING)
            && sum_capacities(&[self.account.capacity(),self.repository.capacity(),
                self.coordinate.capacity(),self.binding.capacity()]).is_some_and(|n| n <= CONTEXT_BACKING)
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        self.input
            .heap()?
            .checked_add(self.root.path.capacity())?
            .checked_add(self.account.capacity())?
            .checked_add(self.repository.capacity())?
            .checked_add(self.coordinate.capacity())?
            .checked_add(self.binding.capacity())
    }
}
pub(crate) struct Permission {
    pub(crate) scope: Weak<r::NativeScope>,
    pub(crate) capture: Capture,
    pub(crate) stamp: SavedEditStamp,
}
impl Permission {
    pub(crate) fn heap(&self) -> Option<usize> {
        self.capture.heap()
    }
    pub(crate) fn close(self) {
        if let Some(s) = self.scope.upgrade() {
            s.unused_closed();
        }
    }
}
pub(crate) struct Producer {
    entry: Weak<r::Entry>,
    operation: String,
}
impl Producer {
    pub(crate) fn new(entry: &Arc<r::Entry>, operation: &str) -> Self {
        Self {
            entry: Arc::downgrade(entry),
            operation: operation.into(),
        }
    }
    pub(crate) fn positive(&self) -> bool {
        self.entry
            .upgrade()
            .is_some_and(|e| e.positively_returned(&self.operation))
    }
    pub(crate) fn heap(&self) -> usize {
        self.operation.capacity()
    }
}
pub(crate) fn producer_ready(producer: &Option<Producer>) -> bool {
    producer.as_ref().is_none_or(Producer::positive)
}
/// Witness of an actual accepted original record-set, never reconstructed from
/// the compact service response or a marker alone.
pub(crate) struct Records {
    pub(crate) identity: Arc<()>,
    pub(crate) original: String,
    pub(crate) session: String,
    pub(crate) generation: u32,
    pub(crate) root: RegisteredRoot,
    pub(crate) stamp: SavedEditStamp,
    pub(crate) end: Instant,
    pub(crate) digest: String,
    pub(crate) producer: Option<Producer>,
}
impl Records {
    pub(crate) fn current<T: Serialize>(
        &self,
        rows: &T,
        operation: Option<&str>,
        session: &str,
        generation: u32,
        root: &RegisteredRoot,
        edit: &SavedEditGuard<'_>,
        now: Instant,
    ) -> bool {
        producer_ready(&self.producer)
            && now < self.end
            && self.session == session
            && self.generation == generation
            && root == &self.root
            && edit.matches(&self.stamp)
            && operation == Some(self.original.as_str())
            && hash(rows).is_ok_and(|h| h == self.digest)
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        self.original
            .capacity()
            .checked_add(self.session.capacity())?
            .checked_add(self.root.path.capacity())?
            .checked_add(self.digest.capacity())?
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(self.producer.as_ref().map_or(0, Producer::heap))
    }
}
impl ConnectionState {
    pub(crate) fn dispatch_capture(
        &self,
        input: Input,
        generation: u32,
        root: &RegisteredRoot,
        binding: &str,
        now: Instant,
    ) -> Result<Capture, BridgeError> {
        if !input.valid()
            || self.unknown
            || self.exhausted
            || self.native_work_pending()
            || self.cooldown_blocked
            || self.cooldown.is_some_and(|v| now < v)
        {
            return Err(BridgeError::invalid());
        }
        let private = self
            .private
            .as_ref()
            .filter(|v| {
                v.id == input.session()
                    && v.generation == generation
                    && v.retirement.is_none()
                    && v.token.is_some()
                    && now < v.clock.end
            })
            .ok_or_else(BridgeError::invalid)?;
        if input
            .connection_revision()
            .is_some_and(|n| n != self.status.revision)
        {
            return Err(BridgeError::invalid());
        }
        let account = self
            .status
            .account
            .value
            .as_ref()
            .filter(|v| {
                self.status.account.state == FactState::Observed
                    && private.account_pin.as_ref() == Some(&v.id)
            })
            .ok_or_else(BridgeError::invalid)?;
        let repo = self
            .status
            .repository
            .value
            .as_ref()
            .filter(|v| {
                self.status.repository.state == FactState::Observed
                    && private.repository_pin.as_ref() == Some(&v.id)
                    && private.repository.eq_ignore_ascii_case(&v.full_name)
            })
            .ok_or_else(BridgeError::invalid)?;
        Ok(Capture {
            input,
            generation,
            root: root.clone(),
            credential_end: private.clock.end,
            account: account.id.clone(),
            repository: repo.id.clone(),
            coordinate: repo.full_name.clone(),
            binding: binding.into(),
        })
    }
    pub(crate) fn dispatch_capture_current(
        &self,
        capture: &Capture,
        edit: &SavedEditGuard<'_>,
        stamp: &SavedEditStamp,
        now: Instant,
    ) -> bool {
        edit.matches(stamp)
            && self
                .dispatch_capture(
                    capture.input.clone(),
                    capture.generation,
                    &capture.root,
                    &capture.binding,
                    now,
                )
                .is_ok_and(|c| c == *capture)
    }
}
#[path = "github_preflight_delegation.rs"]
mod preflight;
#[path = "github_release_delegation.rs"]
mod release;
#[cfg(test)]
#[path = "github_dispatch_delegation_tests.rs"]
mod tests;
