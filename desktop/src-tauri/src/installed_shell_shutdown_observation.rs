//! Read-only test token for the initial, genuinely owned app-info query.
//! It observes the existing J scheduling seam; it cannot select a runtime,
//! create a query, cancel an operation or authorize native cleanup.
use super::*;

pub(crate) struct HeldAppInfo {
    inner: Arc<Inner>,
    owner: Arc<Owner>,
    endpoint: Instant,
    attempted: bool,
}

fn need(condition: bool) -> Result<(), BridgeError> {
    if condition { Ok(()) } else { Err(BridgeError::cleanup_unknown()) }
}

impl Supervisor {
    #[cfg(all(debug_assertions, feature = "custom-protocol"))]
    pub(crate) fn admit_installed_session_once(&self, identity: &Arc<()>) -> Result<(), BridgeError> {
        let owners = lock(&self.inner.owners);
        need(owners.is_empty() && self.inner.next.load(Ordering::SeqCst) == 1 && !self.stopping() && !self.disabled())?;
        self.inner.runtime.admit_installed_session_once(identity)
    }
    pub(crate) fn arm_initial_app_info_shutdown(&self) -> Result<(), BridgeError> {
        let owners = lock(&self.inner.owners);
        let mut case = lock(&self.inner.native_test.case);
        need(owners.is_empty() && self.inner.next.load(Ordering::SeqCst) == 1
            && !self.stopping() && !self.disabled() && self.passive_method_available("capabilities")
            && *case == installed_native_fixture::Case::None)?;
        *case = installed_native_fixture::Case::Shutdown;
        Ok(())
    }

    pub(crate) fn retain_held_app_info(&self) -> Result<Option<HeldAppInfo>, BridgeError> {
        if !self.inner.native_test.held.load(Ordering::SeqCst) { return Ok(None); }
        let key = lock(&self.inner.native_test.shell_owner).ok_or_else(BridgeError::cleanup_unknown)?;
        let owners = lock(&self.inner.owners);
        need(owners.len() == 1 && !self.stopping() && !self.disabled())?;
        let owner = owners.get(&key).ok_or_else(BridgeError::cleanup_unknown)?;
        let state = lock(&owner.state);
        need(matches!(owner.profile, Profile::Passive(Method::Capabilities))
            && !state.terminal && !state.unknown && state.error.is_none() && Instant::now() < state.endpoint)?;
        need(!self.inner.native_test.shell_token_issued.swap(true, Ordering::SeqCst))?;
        // The driver holds resources while the original child reader is held.
        // Retain the actual registry Arc only; do not acquire that resource lock.
        Ok(Some(HeldAppInfo { inner: self.inner.clone(), owner: owner.clone(), endpoint: state.endpoint, attempted: false }))
    }
}

impl HeldAppInfo {
    pub(crate) async fn observe_retired(&mut self, original_observation_end: Instant) -> Result<(), BridgeError> {
        need(!self.attempted)?;
        self.attempted = true;
        // Neither this observation nor a delayed GUI response renews the owner.
        let end = original_observation_end.min(self.endpoint.checked_add(CLEANUP_TIME).ok_or_else(BridgeError::cleanup_unknown)?);
        if Instant::now() >= end { return Err(BridgeError::timeout()); }
        let mut original = self.owner.observer.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let handle = original.as_mut().ok_or_else(BridgeError::cleanup_unknown)?;
        let returned = tokio::select! {
            result = handle => result,
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(end)) => return Err(BridgeError::timeout()),
        };
        // Pending or consumed-failed originals stay in their existing slot and
        // this token cannot consume them again. Only a genuine Ok is removed.
        returned.map_err(|_| BridgeError::cleanup_unknown())?;
        original.take();
        drop(original);

        let resources = self.owner.resources.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        need(resources.inspection_return == Some(ManagementJoin::Returned)
            && resources.acquisition_return == Some(ManagementJoin::Returned)
            && resources.inspection.is_none() && resources.inspection_error.is_none()
            && resources.acquisition.is_none() && resources.acquisition_error.is_none()
            && resources.child.is_none() && resources.waited.is_some() && resources.kill_attempted
            && resources.writer.is_none() && resources.stdout.is_none() && resources.stderr.is_none()
            && resources.failed_writer.is_none() && resources.failed_stdout.is_none() && resources.failed_stderr.is_none()
            && resources.write_end.is_some() && resources.out_end.is_none() && resources.err_end.is_none()
            && resources.native_started && resources.native_settlement.is_none()
            && matches!(resources.native_return.as_ref(), Some(Ok(CloseOutcome::Settled)))
            && resources.native_observation.is_none() && resources.native_observation_return == Some(ManagementJoin::Returned)
            && resources.native_snapshots.len() == 1 && resources.native_snapshots[0].environment_clear())?;
        {
            let slots = lock(resources.passive.as_ref().ok_or_else(BridgeError::cleanup_unknown)?);
            need(slots.settled() && slots.claimed_observation().is_some() && !slots.no_child_effect())?;
            let observation = slots.fixture_observation().ok_or_else(BridgeError::cleanup_unknown)?;
            need(observation.phase() == "settled" && observation.records() > 0
                && observation.positive_closes() == observation.records()
                && observation.live_originals() == 0 && observation.pending_acquisitions() == 0 && observation.uncertain_closes() == 0)?;
        }
        {
            let state = lock(&self.owner.state);
            need(state.endpoint == self.endpoint && state.terminal && !state.unknown && state.reply.is_none()
                && state.error.as_ref().is_some_and(|error| error.code == "shutting_down")
                && state.driver_end.is_none() // The genuine return was consumed by retirement, not reconstructed here.
                && state.driver_join == ManagementJoin::Returned && state.watchdog_join == ManagementJoin::Returned
                && matches!(state.watchdog_end, Some(WatchdogEnd::DriverObserved(ManagementJoin::Returned))))?;
        }
        need(self.owner.driver.try_lock().is_ok_and(|slot| slot.is_none())
            && self.owner.watchdog.try_lock().is_ok_and(|slot| slot.is_none())
            && lock(&self.owner.permit).is_none() && lock(&self.inner.owners).is_empty()
            && self.inner.stopping.load(Ordering::SeqCst) && !self.inner.disabled.load(Ordering::SeqCst)
            && self.inner.permits.available_permits() == ACTIVE_LIMIT)?;
        if Instant::now() >= end { return Err(BridgeError::timeout()); }
        installed_native_fixture::report(&resources.native_snapshots);
        Ok(())
    }
}

// Same R1 caller/owner, with a scoped scheduling observation only. Task-local
// scope does not spawn a task: it follows this actual assessor future when it
// is polled, so a concurrent AssessCredentials request cannot steal the arm.
#[cfg(all(debug_assertions, feature = "custom-protocol"))]
mod session {
    use super::*;
    use std::{future::Future, sync::Weak};
    use crate::asset_session::OriginalWork;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum SessionQueryHold { Observe, Loss, Deadline }
    struct Original {
        asset: Weak<OriginalWork>, owner: Arc<Owner>, endpoint: Instant,
        hold: SessionQueryHold, selected: bool, held: bool, asset_released: bool, attempted: bool,
    }
    #[derive(Default)]
    pub(in crate::supervisor) struct SessionQueryBook {
        armed: Option<(Weak<OriginalWork>, SessionQueryHold)>, originals: Vec<Original>,
        failed: bool, taken: bool,
    }
    tokio::task_local! { static ORIGINAL_ASSET_QUERY: Weak<OriginalWork>; }
    pub(crate) struct InstalledSessionQueries {
        originals: Vec<Original>, inner: Arc<Inner>, valid: bool, retired: bool, report_attempted: bool,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum QueryError { None, Timeout, Cleanup, Shutdown, Protocol, Engine, Io, Busy, Unavailable, Other }
    impl QueryError {
        fn stored(error: Option<&BridgeError>) -> Self {
            match error.map(|error| error.code.as_str()) {
                None => Self::None, Some("query_timeout") => Self::Timeout, Some("cleanup_unknown") => Self::Cleanup,
                Some("shutting_down") => Self::Shutdown, Some("protocol_error") => Self::Protocol,
                Some("engine_failed") => Self::Engine, Some("io_error") => Self::Io, Some("busy") => Self::Busy,
                Some("runtime_unavailable") => Self::Unavailable, Some(_) => Self::Other,
            }
        }
        fn token(self) -> &'static [u8] {
            match self {
                Self::None => b"none", Self::Timeout => b"timeout", Self::Cleanup => b"cleanup", Self::Shutdown => b"shutdown",
                Self::Protocol => b"protocol", Self::Engine => b"engine", Self::Io => b"io", Self::Busy => b"busy",
                Self::Unavailable => b"unavailable", Self::Other => b"other",
            }
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum QueryCause { None, SelectionProfile, SelectionCompile, SelectionMethod, Inspection, AcquisitionEntry,
        AcquisitionCustody, AcquisitionLock, Capability, Preparation, FinalGate, FinalClaim,
        SpawnProcessFd, SpawnSystemFd, SpawnMemory, SpawnResource, SpawnDenied, SpawnMissing, SpawnExec, SpawnOther, Response }
    impl QueryCause {
        fn stored(cause: Option<crate::error::LinuxPassiveCause>) -> Self {
            use crate::error::{LinuxPassiveCause as C, LinuxSpawnFailure as S};
            match cause {
                None => Self::None, Some(C::SelectionProfileClosed) => Self::SelectionProfile,
                Some(C::SelectionCompileBinding) => Self::SelectionCompile, Some(C::SelectionMethodOutsideProfile) => Self::SelectionMethod,
                Some(C::Inspection(_)) => Self::Inspection, Some(C::AcquisitionEntryNotReleased) => Self::AcquisitionEntry,
                Some(C::AcquisitionCustodyMissing) => Self::AcquisitionCustody, Some(C::AcquisitionLock) => Self::AcquisitionLock,
                Some(C::Capability(_)) => Self::Capability, Some(C::Preparation(_)) => Self::Preparation,
                Some(C::FinalClaimOwnerGate) => Self::FinalGate, Some(C::FinalClaim(_)) => Self::FinalClaim,
                Some(C::ReturnedSpawn(S::ProcessFdLimit)) => Self::SpawnProcessFd,
                Some(C::ReturnedSpawn(S::SystemFdLimit)) => Self::SpawnSystemFd,
                Some(C::ReturnedSpawn(S::Memory)) => Self::SpawnMemory,
                Some(C::ReturnedSpawn(S::ResourceUnavailable)) => Self::SpawnResource,
                Some(C::ReturnedSpawn(S::PermissionDenied)) => Self::SpawnDenied,
                Some(C::ReturnedSpawn(S::NotFound)) => Self::SpawnMissing,
                Some(C::ReturnedSpawn(S::ExecFormat)) => Self::SpawnExec,
                Some(C::ReturnedSpawn(S::Other)) => Self::SpawnOther, Some(C::EngineResponse) => Self::Response,
            }
        }
        fn token(self) -> &'static [u8] {
            match self {
                Self::None => b"none", Self::SelectionProfile => b"sel-profile", Self::SelectionCompile => b"sel-compile",
                Self::SelectionMethod => b"sel-method", Self::Inspection => b"inspection", Self::AcquisitionEntry => b"acq-entry",
                Self::AcquisitionCustody => b"acq-custody", Self::AcquisitionLock => b"acq-lock", Self::Capability => b"capability",
                Self::Preparation => b"prepare", Self::FinalGate => b"final-gate", Self::FinalClaim => b"final-claim",
                Self::SpawnProcessFd => b"spawn-pfd", Self::SpawnSystemFd => b"spawn-sfd", Self::SpawnMemory => b"spawn-mem",
                Self::SpawnResource => b"spawn-res", Self::SpawnDenied => b"spawn-deny", Self::SpawnMissing => b"spawn-miss",
                Self::SpawnExec => b"spawn-exec", Self::SpawnOther => b"spawn-other", Self::Response => b"response",
            }
        }
    }
    fn management_token(receipt: ManagementJoin) -> u8 {
        match receipt {
            ManagementJoin::Pending => b'p', ManagementJoin::Returned => b'r', ManagementJoin::Missing => b'm',
            ManagementJoin::Cancelled => b'c', ManagementJoin::Panicked => b'x', ManagementJoin::Failed => b'f',
            ManagementJoin::InvalidReturn => b'i',
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum QueryProjection { NotApplicable, Unregistered, Unavailable,
        Recorded { error: QueryError, cause: QueryCause, driver: ManagementJoin, watchdog: ManagementJoin } }
    impl QueryProjection {
        fn stored(state: &OwnerState) -> Self {
            Self::Recorded { error: QueryError::stored(state.error.as_ref()),
                cause: QueryCause::stored(state.error.as_ref().and_then(BridgeError::linux_passive_cause)),
                driver: state.driver_join, watchdog: state.watchdog_join }
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum WorkerStage { Inspect, Acquire, Observe, Write, Stdout, Stderr, Settle }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum WorkerJoin { Cancelled, Panicked, Failed }
    impl WorkerJoin {
        fn returned(receipt: ManagementJoin) -> Option<Self> {
            match receipt {
                ManagementJoin::Cancelled => Some(Self::Cancelled), ManagementJoin::Panicked => Some(Self::Panicked),
                ManagementJoin::Failed => Some(Self::Failed), _ => None,
            }
        }
        fn token(self, cancelled: &'static [u8], panicked: &'static [u8], failed: &'static [u8]) -> &'static [u8] {
            match self { Self::Cancelled => cancelled, Self::Panicked => panicked, Self::Failed => failed }
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum WorkerProjection { NotApplicable, Unavailable, NoneRecorded, Observation(installed_native_fixture::ObservationFailure),
        Join(WorkerStage, WorkerJoin), SettlementUnknown }
    impl WorkerProjection {
        fn stored(resources: &Resources) -> Self {
            // Fixed lifecycle order only, NOT temporal/causal first failure.
            for (stage, receipt) in [(WorkerStage::Inspect, resources.inspection_return),
                (WorkerStage::Acquire, resources.acquisition_return), (WorkerStage::Observe, resources.native_observation_return)] {
                if let Some(failed) = receipt.and_then(WorkerJoin::returned) { return Self::Join(stage, failed); }
            }
            if let Some(failure) = resources.native_observation_failure { return Self::Observation(failure); }
            // Existing IO books retain a failed original handle, not the
            // erased JoinError category. Do not repoll it or invent c/x DATA.
            for (stage, failed) in [(WorkerStage::Write, resources.failed_writer.is_some()),
                (WorkerStage::Stdout, resources.failed_stdout.is_some()), (WorkerStage::Stderr, resources.failed_stderr.is_some())] {
                if failed { return Self::Join(stage, WorkerJoin::Failed); }
            }
            match resources.native_return.as_ref() {
                Some(Ok(CloseOutcome::Unknown)) => Self::SettlementUnknown,
                Some(Err(error)) => Self::Join(WorkerStage::Settle, WorkerJoin::returned(ManagementJoin::error(error)).unwrap_or(WorkerJoin::Failed)),
                _ => Self::NoneRecorded,
            }
        }
        fn token(self) -> &'static [u8] {
            match self {
                Self::NotApplicable => b"na", Self::Unavailable => b"unavailable", Self::NoneRecorded => b"none-recorded",
                Self::Observation(failure) => failure.token(), Self::SettlementUnknown => b"settle-unknown",
                Self::Join(stage, join) => match stage {
                    WorkerStage::Inspect => join.token(b"inspect-c", b"inspect-x", b"inspect-f"),
                    WorkerStage::Acquire => join.token(b"acquire-c", b"acquire-x", b"acquire-f"),
                    WorkerStage::Observe => join.token(b"observe-c", b"observe-x", b"observe-f"),
                    WorkerStage::Write => join.token(b"write-c", b"write-x", b"write-f"),
                    WorkerStage::Stdout => join.token(b"stdout-c", b"stdout-x", b"stdout-f"),
                    WorkerStage::Stderr => join.token(b"stderr-c", b"stderr-x", b"stderr-f"),
                    WorkerStage::Settle => join.token(b"settle-c", b"settle-x", b"settle-f"),
                },
            }
        }
    }
    // Closed edge DATA, not a worker cause or another failure classification.
    // Visibility reaches only the original supervisor ancestor, not an API.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(in crate::supervisor) enum UnknownBoundary {
        NotApplicable, Unavailable, NotRecorded, Unspecified, Transfer, Inspection, Acquisition,
        NativeObserve, Settlement, Management, ObserverLoss, ReplyLoss, Clock, RetireClock,
        ChildMissing, ChildWait, Io, RestoreLimit, DevObserve,
    }
    impl UnknownBoundary {
        fn token(self) -> &'static [u8] {
            match self {
                Self::NotApplicable => b"na", Self::Unavailable => b"unavailable", Self::NotRecorded => b"not-recorded",
                Self::Unspecified => b"unspecified", Self::Transfer => b"transfer", Self::Inspection => b"inspection",
                Self::Acquisition => b"acquisition", Self::NativeObserve => b"native-observe", Self::Settlement => b"settlement",
                Self::Management => b"management", Self::ObserverLoss => b"observer-loss", Self::ReplyLoss => b"reply-loss",
                Self::Clock => b"clock", Self::RetireClock => b"retire-clock", Self::ChildMissing => b"child-missing",
                Self::ChildWait => b"child-wait", Self::Io => b"io", Self::RestoreLimit => b"restore-limit", Self::DevObserve => b"dev-observe",
            }
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(in crate::supervisor) struct FirstUnknown { worker: WorkerProjection, boundary: UnknownBoundary }
    impl FirstUnknown {
        pub(in crate::supervisor) fn capture(resources: Option<&Resources>, boundary: UnknownBoundary) -> Self {
            // A missing caller guard is unavailable, never an empty refusal
            // book. This scalar copy does not lock, own, wait or read natives.
            Self { worker: resources.map_or(WorkerProjection::Unavailable, WorkerProjection::stored), boundary }
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) struct InstalledSessionQueryDiagnostic { query: QueryProjection, worker: WorkerProjection, boundary: UnknownBoundary }
    impl InstalledSessionQueryDiagnostic {
        pub(crate) const fn not_applicable() -> Self {
            Self { query: QueryProjection::NotApplicable, worker: WorkerProjection::NotApplicable, boundary: UnknownBoundary::NotApplicable }
        }
        fn unavailable() -> Self {
            Self { query: QueryProjection::Unavailable, worker: WorkerProjection::Unavailable, boundary: UnknownBoundary::Unavailable }
        }
        pub(crate) fn query_token(self) -> ([u8; 26], usize) {
            let mut bytes = [0; 26];
            let literal: &[u8] = match self.query {
                QueryProjection::NotApplicable => b"na", QueryProjection::Unregistered => b"unregistered", QueryProjection::Unavailable => b"unavailable",
                QueryProjection::Recorded { error, cause, driver, watchdog } => {
                    let (error, cause) = (error.token(), cause.token());
                    let end = error.len() + 1 + cause.len();
                    bytes[..error.len()].copy_from_slice(error); bytes[error.len()] = b'.';
                    bytes[error.len() + 1..end].copy_from_slice(cause); bytes[end] = b'.';
                    bytes[end + 1] = management_token(driver); bytes[end + 2] = management_token(watchdog);
                    return (bytes, end + 3);
                },
            };
            bytes[..literal.len()].copy_from_slice(literal); (bytes, literal.len())
        }
        pub(crate) fn worker_token(self) -> &'static [u8] { self.worker.token() }
        pub(crate) fn unknown_boundary_token(self) -> &'static [u8] { self.boundary.token() }
        pub(crate) fn contract_sample() -> Self {
            Self { query: QueryProjection::Recorded { error: QueryError::Unavailable, cause: QueryCause::SpawnOther,
                driver: ManagementJoin::Panicked, watchdog: ManagementJoin::Failed }, worker: WorkerProjection::SettlementUnknown,
                boundary: UnknownBoundary::Settlement }
        }
    }
    fn session_query_diagnostic(originals: &Mutex<SessionQueryBook>, asset: &Weak<OriginalWork>) -> InstalledSessionQueryDiagnostic {
        let Ok(book) = originals.try_lock() else { return InstalledSessionQueryDiagnostic::unavailable(); };
        if book.failed || book.taken || book.originals.len() > 16 { return InstalledSessionQueryDiagnostic::unavailable(); }
        let mut matching = book.originals.iter().filter(|row| Weak::ptr_eq(&row.asset, asset));
        let Some(row) = matching.next() else {
            return InstalledSessionQueryDiagnostic { query: QueryProjection::Unregistered, worker: WorkerProjection::NotApplicable,
                boundary: UnknownBoundary::NotApplicable };
        };
        if matching.next().is_some() || !matches!(row.owner.profile, Profile::Passive(Method::AssessCredentials)) {
            return InstalledSessionQueryDiagnostic::unavailable();
        }
        // One exact-endpoint state snapshot, then release its guard. A failed
        // state sample cannot establish the absence of a first record. Never
        // use a later Resources sample to enrich an already-Unknown original.
        let (query, first, unknown) = {
            let Ok(state) = row.owner.state.try_lock() else { return InstalledSessionQueryDiagnostic::unavailable(); };
            if state.endpoint != row.endpoint { return InstalledSessionQueryDiagnostic::unavailable(); }
            (QueryProjection::stored(&state), state.first_unknown, state.unknown)
        };
        if let Some(first) = first {
            return InstalledSessionQueryDiagnostic { query, worker: first.worker, boundary: first.boundary };
        }
        if unknown { return InstalledSessionQueryDiagnostic::unavailable(); }
        // Only an observed pre-Unknown state retains the existing nonblocking
        // fallback. No registry/latest-slot lookup, clock, poll or native read.
        let worker = row.owner.resources.try_lock().ok().map_or(WorkerProjection::Unavailable, |resources| WorkerProjection::stored(&resources));
        InstalledSessionQueryDiagnostic { query, worker, boundary: UnknownBoundary::NotRecorded }
    }

    pub(crate) fn assert_installed_session_query_diagnostic_contract(asset: &Arc<OriginalWork>, other: &Arc<OriginalWork>) -> InstalledSessionQueryDiagnostic {
        // Existing explicit-call DATA contract only: synthetic empty books,
        // no Supervisor/runtime, original task, process, reader or native join.
        fn query(value: InstalledSessionQueryDiagnostic) -> Vec<u8> {
            let (bytes, length) = value.query_token(); bytes[..length].to_vec()
        }
        fn owner(profile: Profile, endpoint: Instant) -> Arc<Owner> {
            let (stop, _) = watch::channel(false);
            Arc::new(Owner { key: 0, id: String::new(), profile, github_receipt: None,
                state: Mutex::new(OwnerState::new(endpoint, None)), resources: AsyncMutex::new(Resources::default()),
                stop, changed: Notify::new(), permit: Mutex::new(None), driver: AsyncMutex::new(None),
                watchdog: AsyncMutex::new(None), observer: AsyncMutex::new(None) })
        }
        fn row(asset: &Arc<OriginalWork>, owner: &Arc<Owner>, endpoint: Instant) -> Original {
            Original { asset: Arc::downgrade(asset), owner: owner.clone(), endpoint, hold: SessionQueryHold::Observe,
                selected: false, held: false, asset_released: false, attempted: false }
        }
        fn associated(asset: &Arc<OriginalWork>, endpoint: Instant) -> (Arc<Owner>, Mutex<SessionQueryBook>) {
            let owner = owner(Profile::Passive(Method::AssessCredentials), endpoint);
            let book = Mutex::new(SessionQueryBook { originals: vec![row(asset, &owner, endpoint)], ..SessionQueryBook::default() });
            (owner, book)
        }
        let association = Arc::downgrade(asset);
        let book = Mutex::new(SessionQueryBook::default());
        let absent = session_query_diagnostic(&book, &association);
        assert!(query(absent) == b"unregistered" && absent.worker_token() == b"na" && absent.unknown_boundary_token() == b"na");
        let unassociated = InstalledSessionQueryDiagnostic::not_applicable();
        assert!(query(unassociated) == b"na" && unassociated.worker_token() == b"na" && unassociated.unknown_boundary_token() == b"na");
        let guard = book.try_lock().unwrap();
        let contended = session_query_diagnostic(&book, &association);
        assert!(query(contended) == b"unavailable" && contended.worker_token() == b"unavailable" && contended.unknown_boundary_token() == b"unavailable");
        drop(guard);
        let endpoint = Instant::now();
        let original = owner(Profile::Passive(Method::AssessCredentials), endpoint);
        book.try_lock().unwrap().originals.push(row(asset, &original, endpoint));
        let sampled = session_query_diagnostic(&book, &association);
        assert!(query(sampled) == b"none.none.pp" && sampled.worker_token() == b"none-recorded" && sampled.unknown_boundary_token() == b"not-recorded");
        // Equal public operation IDs are not weak identity or R1 association.
        assert!(asset.id == other.id && !Arc::ptr_eq(asset, other));
        assert!(query(session_query_diagnostic(&book, &Arc::downgrade(other))) == b"unregistered");
        let held_state = original.state.try_lock().unwrap();
        let sampled = session_query_diagnostic(&book, &association);
        assert!(sampled == InstalledSessionQueryDiagnostic::unavailable());
        drop(held_state);
        let held_resources = original.resources.try_lock().unwrap();
        let sampled = session_query_diagnostic(&book, &association);
        assert!(query(sampled) == b"none.none.pp" && sampled.worker_token() == b"unavailable" && sampled.unknown_boundary_token() == b"not-recorded");
        drop(held_resources);
        book.try_lock().unwrap().originals.push(row(asset, &original, endpoint));
        assert!(session_query_diagnostic(&book, &association) == InstalledSessionQueryDiagnostic::unavailable());
        book.try_lock().unwrap().originals.pop();
        book.try_lock().unwrap().taken = true;
        assert!(session_query_diagnostic(&book, &association) == InstalledSessionQueryDiagnostic::unavailable());
        { let mut book = book.try_lock().unwrap(); book.taken = false; book.failed = true; }
        assert!(session_query_diagnostic(&book, &association) == InstalledSessionQueryDiagnostic::unavailable());
        { let mut book = book.try_lock().unwrap(); book.failed = false;
            book.originals[0].owner = owner(Profile::Passive(Method::Capabilities), endpoint); }
        assert!(session_query_diagnostic(&book, &association) == InstalledSessionQueryDiagnostic::unavailable());
        { let mut book = book.try_lock().unwrap(); book.originals.clear();
            book.originals.push(row(asset, &original, endpoint));
            for _ in 0..16 { book.originals.push(row(other, &original, endpoint)); } }
        assert!(session_query_diagnostic(&book, &association) == InstalledSessionQueryDiagnostic::unavailable());

        use UnknownBoundary as U;
        use installed_native_fixture::ObservationFailure as F;
        // Exercise the SAME state-latch helper used by the sole Unknown body,
        // under the caller-held Resources/state guards. Policy flags below are
        // synthetic fixture DATA, not a second owner or a native Unknown run.
        let (observed, observed_book) = associated(asset, endpoint);
        let mut held = observed.resources.try_lock().unwrap();
        held.native_observation_failure = Some(F::MapsRead);
        let first = {
            let mut state = observed.state.try_lock().unwrap();
            state.record_first_unknown(Some(&held), U::NativeObserve);
            assert!(!state.unknown && !state.terminal && state.error.is_none() && state.cleanup_endpoint.is_none()
                && state.endpoint == endpoint && !state.management_ready() && state.reply.is_none());
            let first = state.first_unknown.unwrap();
            assert!(first.worker.token() == b"maps-read" && first.boundary == U::NativeObserve);
            state.unknown = true;
            state.fail_at(BridgeError::cleanup_unknown(), endpoint);
            first
        };
        let retained = session_query_diagnostic(&observed_book, &association);
        assert!(query(retained) == b"cleanup.none.pp" && retained.worker_token() == b"maps-read"
            && retained.unknown_boundary_token() == b"native-observe");
        // A later different refusal cannot overwrite K/U or renew the original
        // error/cleanup endpoint, even while the resource guard stays held.
        held.native_observation_failure = Some(F::EnvironmentCheck);
        {
            let mut state = observed.state.try_lock().unwrap();
            state.record_first_unknown(Some(&held), U::Inspection);
            state.fail_at(BridgeError::protocol(), endpoint + Duration::from_secs(1));
            assert!(state.first_unknown == Some(first) && state.unknown && !state.terminal
                && state.error.as_ref().is_some_and(|error| error.code == "cleanup_unknown")
                && state.endpoint == endpoint && state.cleanup_endpoint == Some(endpoint + CLEANUP_TIME)
                && state.driver_join == ManagementJoin::Pending && state.watchdog_join == ManagementJoin::Pending);
        }
        assert!(session_query_diagnostic(&observed_book, &association) == retained);
        drop(held);
        assert!(session_query_diagnostic(&observed_book, &association) == retained);
        let state_guard = observed.state.try_lock().unwrap();
        assert!(session_query_diagnostic(&observed_book, &association) == InstalledSessionQueryDiagnostic::unavailable());
        drop(state_guard);
        observed_book.try_lock().unwrap().originals[0].endpoint = endpoint + Duration::from_secs(1);
        assert!(session_query_diagnostic(&observed_book, &association) == InstalledSessionQueryDiagnostic::unavailable());
        observed_book.try_lock().unwrap().originals[0].endpoint = endpoint;
        assert!(session_query_diagnostic(&observed_book, &association) == retained);

        let (unavailable_owner, unavailable_book) = associated(asset, endpoint);
        let mut held = unavailable_owner.resources.try_lock().unwrap();
        held.native_observation_failure = Some(F::ChildId);
        let unavailable_first = {
            let mut state = unavailable_owner.state.try_lock().unwrap();
            state.record_first_unknown(None, U::Acquisition);
            state.unknown = true; state.fail_at(BridgeError::cleanup_unknown(), endpoint);
            state.first_unknown.unwrap()
        };
        let no_guard = session_query_diagnostic(&unavailable_book, &association);
        assert!(query(no_guard) == b"cleanup.none.pp" && no_guard.worker_token() == b"unavailable"
            && no_guard.unknown_boundary_token() == b"acquisition");
        drop(held);
        // Resources is now readable, with a known refusal. No late sample or
        // first-record backfill is permitted after the no-guard edge won.
        assert!(session_query_diagnostic(&unavailable_book, &association) == no_guard);
        let held = unavailable_owner.resources.try_lock().unwrap();
        assert!(WorkerProjection::stored(&held).token() == b"child-id");
        {
            let mut state = unavailable_owner.state.try_lock().unwrap();
            state.record_first_unknown(Some(&held), U::NativeObserve);
            assert!(state.first_unknown == Some(unavailable_first));
        }
        assert!(session_query_diagnostic(&unavailable_book, &association) == no_guard);
        drop(held);

        let (empty_owner, empty_book) = associated(asset, endpoint);
        let held = empty_owner.resources.try_lock().unwrap();
        {
            let mut state = empty_owner.state.try_lock().unwrap();
            state.record_first_unknown(Some(&held), U::Transfer);
            state.unknown = true; state.fail_at(BridgeError::cleanup_unknown(), endpoint);
        }
        let sampled_empty = session_query_diagnostic(&empty_book, &association);
        assert!(sampled_empty.worker_token() == b"none-recorded" && sampled_empty.unknown_boundary_token() == b"transfer");
        drop(held);

        let (synthetic, synthetic_book) = associated(asset, endpoint);
        let mut held = synthetic.resources.try_lock().unwrap();
        held.native_observation_failure = Some(F::Entry);
        {
            let mut state = synthetic.state.try_lock().unwrap(); state.unknown = true;
            state.record_first_unknown(Some(&held), U::NativeObserve);
            assert!(state.first_unknown.is_none());
        }
        drop(held);
        assert!(session_query_diagnostic(&synthetic_book, &association) == InstalledSessionQueryDiagnostic::unavailable());

        let mut terminal = OwnerState::new(endpoint, None); terminal.terminal = true;
        terminal.record_first_unknown(None, U::Unspecified);
        assert!(terminal.first_unknown.is_none() && !terminal.unknown && terminal.error.is_none()
            && terminal.retirement_result(endpoint + CLEANUP_TIME, true).is_none());
        let mut pending = OwnerState::new(endpoint, None);
        pending.fail_at(BridgeError::protocol(), endpoint);
        assert!(pending.retirement_result(endpoint + CLEANUP_TIME, false).is_none()
            && pending.first_unknown.is_none() && !pending.unknown && pending.cleanup_endpoint == Some(endpoint + CLEANUP_TIME));
        // The record itself is also immutable before any later flag write.
        let mut unspecified = OwnerState::new(endpoint, None);
        unspecified.record_first_unknown(None, U::Unspecified);
        let default_first = unspecified.first_unknown;
        unspecified.record_first_unknown(Some(&Resources::default()), U::Settlement);
        assert!(unspecified.first_unknown == default_first
            && default_first.is_some_and(|first| first.worker.token() == b"unavailable" && first.boundary == U::Unspecified));

        let (retiring, retiring_book) = associated(asset, endpoint);
        {
            let mut state = retiring.state.try_lock().unwrap();
            state.driver_join = ManagementJoin::Returned; state.watchdog_join = ManagementJoin::Returned;
            state.driver_end = Some(DriverEnd::Ready(Ok(ReadOutcome::Passive(Value::Null))));
            state.watchdog_end = Some(WatchdogEnd::DriverObserved(ManagementJoin::Returned));
            state.fail_at(BridgeError::protocol(), endpoint);
            let result = state.retirement_result(endpoint + CLEANUP_TIME, false);
            assert!(matches!(result, Some(Err(error)) if error.code == "cleanup_unknown"));
            assert!(state.unknown && !state.terminal && state.driver_end.is_none()
                && state.error.as_ref().is_some_and(|error| error.code == "protocol_error")
                && state.endpoint == endpoint && state.cleanup_endpoint == Some(endpoint + CLEANUP_TIME));
        }
        let retired_clock = session_query_diagnostic(&retiring_book, &association);
        assert!(query(retired_clock) == b"protocol.none.rr" && retired_clock.worker_token() == b"unavailable"
            && retired_clock.unknown_boundary_token() == b"retire-clock");
        retiring.state.try_lock().unwrap().record_first_unknown(Some(&Resources::default()), U::Settlement);
        assert!(session_query_diagnostic(&retiring_book, &association) == retired_clock);
        for (boundary, token) in [(U::NotApplicable,b"na".as_slice()), (U::Unavailable,b"unavailable"), (U::NotRecorded,b"not-recorded"),
            (U::Unspecified,b"unspecified"), (U::Transfer,b"transfer"), (U::Inspection,b"inspection"), (U::Acquisition,b"acquisition"),
            (U::NativeObserve,b"native-observe"), (U::Settlement,b"settlement"), (U::Management,b"management"),
            (U::ObserverLoss,b"observer-loss"), (U::ReplyLoss,b"reply-loss"), (U::Clock,b"clock"), (U::RetireClock,b"retire-clock"),
            (U::ChildMissing,b"child-missing"), (U::ChildWait,b"child-wait"), (U::Io,b"io"), (U::RestoreLimit,b"restore-limit"), (U::DevObserve,b"dev-observe")] {
            assert!(boundary.token() == token && token.len() <= 14 && token.is_ascii());
        }

        assert!(QueryError::stored(None).token() == b"none" && QueryCause::stored(None).token() == b"none");
        for (code, token) in [("query_timeout", b"timeout".as_slice()), ("cleanup_unknown", b"cleanup"), ("shutting_down", b"shutdown"),
            ("protocol_error", b"protocol"), ("engine_failed", b"engine"), ("io_error", b"io"), ("busy", b"busy"),
            ("runtime_unavailable", b"unavailable"), ("unlisted\nprivate", b"other")] {
            assert!(QueryError::stored(Some(&BridgeError::new(code, "not exported"))).token() == token);
            assert!(token.len() <= 11);
        }
        use crate::{error::{LinuxPassiveCause as C, LinuxSpawnFailure as S}, installed_runtime::AdmissionFailure as A};
        for (cause, token) in [(C::SelectionProfileClosed, b"sel-profile".as_slice()), (C::SelectionCompileBinding, b"sel-compile"),
            (C::SelectionMethodOutsideProfile, b"sel-method"), (C::Inspection(Some(A::Bounds)), b"inspection"),
            (C::AcquisitionEntryNotReleased, b"acq-entry"), (C::AcquisitionCustodyMissing, b"acq-custody"), (C::AcquisitionLock, b"acq-lock"),
            (C::Capability(A::Bounds), b"capability"), (C::Preparation(A::Bounds), b"prepare"),
            (C::FinalClaimOwnerGate, b"final-gate"), (C::FinalClaim(A::Bounds), b"final-claim"),
            (C::ReturnedSpawn(S::ProcessFdLimit), b"spawn-pfd"), (C::ReturnedSpawn(S::SystemFdLimit), b"spawn-sfd"),
            (C::ReturnedSpawn(S::Memory), b"spawn-mem"), (C::ReturnedSpawn(S::ResourceUnavailable), b"spawn-res"),
            (C::ReturnedSpawn(S::PermissionDenied), b"spawn-deny"), (C::ReturnedSpawn(S::NotFound), b"spawn-miss"),
            (C::ReturnedSpawn(S::ExecFormat), b"spawn-exec"), (C::ReturnedSpawn(S::Other), b"spawn-other"), (C::EngineResponse, b"response")] {
            let error = BridgeError::unavailable("not exported").with_linux_passive_cause(Some(cause));
            let mut state = original.state.try_lock().unwrap(); state.error = Some(error);
            let projected = QueryProjection::stored(&state);
            assert!(matches!(projected, QueryProjection::Recorded { error: QueryError::Unavailable, cause: value, .. } if value.token() == token));
            assert!(state.error.as_ref().and_then(BridgeError::linux_passive_cause) == Some(cause) && token.len() <= 11);
        }
        assert!(QueryCause::stored(Some(C::Inspection(None))).token() == b"inspection");
        for (receipt, token) in [(ManagementJoin::Pending,b'p'), (ManagementJoin::Returned,b'r'), (ManagementJoin::Missing,b'm'),
            (ManagementJoin::Cancelled,b'c'), (ManagementJoin::Panicked,b'x'), (ManagementJoin::Failed,b'f'), (ManagementJoin::InvalidReturn,b'i')] {
            assert!(management_token(receipt) == token);
            assert!(WorkerJoin::returned(receipt).is_some() == matches!(token, b'c' | b'x' | b'f'));
        }
        use installed_native_fixture::{MapRefusal as R, MapMetadataRefusal as M, MapRole};
        installed_native_fixture::assert_mappings_diagnostic_contract();
        let mut resources = Resources::default();
        for (failure, token) in [(F::ChildId,b"child-id".as_slice()), (F::Entry,b"observe-entry"), (F::MapsRead,b"maps-read"),
            (F::MapsCheck(R::Newline),b"map-p-nl"), (F::MapsCheck(R::Metadata(MapRole::Crypto, M::Owner)),b"map-m-owner-cr"),
            (F::MapsCheck(R::ExecutableHistoricalPayload(crate::installed_runtime::HistoricalPayloadRole::Python)),b"map-x-hist-py"),
            (F::EnvironmentRead,b"env-read"), (F::EnvironmentCheck,b"env-check"), (F::HoldRefused,b"hold-refused")] {
            resources.native_observation_failure = Some(failure);
            assert!(WorkerProjection::stored(&resources).token() == token && token.len() <= 14);
        }
        resources.acquisition_return = Some(ManagementJoin::Panicked);
        assert!(WorkerProjection::stored(&resources).token() == b"acquire-x");
        resources.inspection_return = Some(ManagementJoin::Cancelled);
        assert!(WorkerProjection::stored(&resources).token() == b"inspect-c");
        resources.inspection_return = Some(ManagementJoin::Returned); resources.acquisition_return = Some(ManagementJoin::Returned);
        resources.native_observation_return = Some(ManagementJoin::Failed);
        assert!(WorkerProjection::stored(&resources).token() == b"observe-f");
        resources.native_observation_return = Some(ManagementJoin::Returned); resources.native_observation_failure = None;
        resources.native_return = Some(Ok(CloseOutcome::Unknown));
        assert!(WorkerProjection::stored(&resources).token() == b"settle-unknown");
        resources.native_return = Some(Ok(CloseOutcome::Settled));
        assert!(WorkerProjection::stored(&resources).token() == b"none-recorded");
        assert!(query(InstalledSessionQueryDiagnostic::contract_sample()) == b"unavailable.spawn-other.xf");
        assert!(InstalledSessionQueryDiagnostic::contract_sample().query_token().1 == 26);
        assert!(InstalledSessionQueryDiagnostic::contract_sample().unknown_boundary_token() == b"settlement");
        contended
    }

    impl Supervisor {
        pub(crate) fn installed_session_query_diagnostic(&self, asset: &Weak<OriginalWork>) -> InstalledSessionQueryDiagnostic {
            session_query_diagnostic(&self.inner.native_test.session, asset)
        }
        pub(crate) fn arm_installed_session_query(&self, asset: &Arc<OriginalWork>, hold: SessionQueryHold) -> Result<(), BridgeError> {
            let mut book = lock(&self.inner.native_test.session);
            need(self.passive_method_available("credentials.assess") && !self.stopping() && !self.disabled()
                && !book.failed && !book.taken && book.armed.is_none() && book.originals.len() < 16
                && book.originals.iter().all(|row| row.asset.as_ptr() != Arc::as_ptr(asset))
                && *lock(&self.inner.native_test.case) == installed_native_fixture::Case::None)?;
            book.originals.try_reserve(1).map_err(|_| BridgeError::cleanup_unknown())?;
            book.armed = Some((Arc::downgrade(asset), hold)); Ok(())
        }
        pub(crate) async fn observe_installed_session_query<F: Future>(&self, asset: &Arc<OriginalWork>, assessor: F) -> F::Output {
            let armed = {
                let book = lock(&self.inner.native_test.session);
                !book.failed && !book.taken && book.armed.as_ref().is_some_and(|(original,_)|
                    original.as_ptr() == Arc::as_ptr(asset))
            };
            // Unrelated/direct assessments in the same test compilation do not
            // participate. Only this already-armed asset's actual future scopes
            // registration; no method-global selector can capture another R1.
            if armed { ORIGINAL_ASSET_QUERY.scope(Arc::downgrade(asset), assessor).await }
            else { assessor.await }
        }
        pub(crate) fn installed_session_query_held(&self, asset_id: u32) -> bool {
            let book = lock(&self.inner.native_test.session);
            !book.failed && book.originals.iter().any(|row| row.held && !row.asset_released
                && row.asset.upgrade().is_some_and(|asset| asset.id == asset_id && !asset.stopped())
                && Instant::now() < row.endpoint && !lock(&row.owner.state).terminal)
        }
        pub(crate) fn take_installed_session_queries(&self) -> Result<InstalledSessionQueries, BridgeError> {
            let mut book = lock(&self.inner.native_test.session);
            need(!book.taken)?; book.taken = true;
            Ok(InstalledSessionQueries { originals: std::mem::take(&mut book.originals), inner: self.inner.clone(),
                valid: !book.failed && book.armed.is_none(), retired: false, report_attempted: false })
        }
    }
    pub(in crate::supervisor) fn register_session_query(inner: &Arc<Inner>, owner: &Arc<Owner>) {
        let Ok(asset) = ORIGINAL_ASSET_QUERY.try_with(Weak::clone) else { return; };
        let mut book = lock(&inner.native_test.session);
        let valid = matches!(owner.profile, Profile::Passive(Method::AssessCredentials))
            && book.armed.as_ref().is_some_and(|(expected, _)| Weak::ptr_eq(expected, &asset) && asset.strong_count() > 0)
            && !book.failed && !book.taken && book.originals.len() < 16;
        if !valid { book.failed = true; owner.fail(BridgeError::protocol()); return; }
        let (_, hold) = book.armed.take().expect("matched original arm");
        book.originals.push(Original { asset, owner: owner.clone(), endpoint: owner.endpoint(), hold,
            selected: false, held: false, asset_released: false, attempted: false });
    }
    pub(in crate::supervisor) fn session_child_case(hooks: &installed_native_fixture::Hooks, owner: &Arc<Owner>) -> Option<installed_native_fixture::Case> {
        let mut book = lock(&hooks.session);
        let row = book.originals.iter_mut().find(|row| Arc::ptr_eq(&row.owner, owner))?;
        if row.selected { book.failed = true; return None; }
        row.selected = true;
        Some(match row.hold { SessionQueryHold::Observe => installed_native_fixture::Case::SessionObserve,
            SessionQueryHold::Loss => installed_native_fixture::Case::SessionLoss,
            SessionQueryHold::Deadline => installed_native_fixture::Case::SessionDeadline })
    }
    pub(in crate::supervisor) fn hold_session_query(inner: &Inner, key: u64, end: Instant, stop: &watch::Receiver<bool>,
        case: installed_native_fixture::Case) -> Result<(), ()> {
        let (asset, loss, delay) = {
            let mut book = lock(&inner.native_test.session);
            let row = book.originals.iter_mut().find(|row| row.owner.key == key).ok_or(())?;
            if !row.selected || row.held || row.endpoint != end || row.asset.strong_count() == 0 { return Err(()); }
            let loss = row.hold == SessionQueryHold::Loss;
            let expected = match row.hold { SessionQueryHold::Observe => installed_native_fixture::Case::SessionObserve,
                SessionQueryHold::Loss => installed_native_fixture::Case::SessionLoss,
                SessionQueryHold::Deadline => installed_native_fixture::Case::SessionDeadline };
            if case != expected { return Err(()); }
            row.held = true; (row.asset.clone(), loss, row.hold != SessionQueryHold::Observe)
        };
        while delay && Instant::now() < end && !*stop.borrow() && stop.has_changed().is_ok() {
            // Real asset STOP releases only the loss hold. Deadline uses the
            // unchanged query endpoint/STOP; neither waits for publication.
            if loss {
                let original = asset.upgrade().ok_or(())?;
                if original.stopped() {
                    let mut book = lock(&inner.native_test.session);
                    let row = book.originals.iter_mut().find(|row| row.owner.key == key).ok_or(())?;
                    row.asset_released = true; break;
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }
    impl InstalledSessionQueries {
        pub(crate) fn count(&self) -> usize { self.originals.len() }
        pub(crate) async fn observe_retired(&mut self, observation_end: Instant) -> bool {
            if !self.valid || self.retired || Instant::now() >= observation_end || self.originals.is_empty() { return false; }
            for row in &mut self.originals {
                if row.attempted || !row.selected || !row.held { return false; }
                row.attempted = true;
                // Await only the SAME original management tail AFTER retirement.
                // A successful query's work clock may already be past at final
                // app Exit; that cannot undo its recorded on-time settlement.
                // This uses the existing observation bound, never grants more
                // query/cleanup time, and retains a pending/failed original.
                if !lock(&row.owner.state).terminal { return false; }
                let Ok(mut original) = row.owner.observer.try_lock() else { return false; };
                let Some(handle) = original.as_mut() else { return false; };
                let returned = tokio::select! {
                    result = handle => result,
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(observation_end)) => return false,
                };
                if returned.is_err() { return false; }
                original.take(); drop(original);
                let Ok(resources) = row.owner.resources.try_lock() else { return false; };
                let state = lock(&row.owner.state);
                if state.endpoint != row.endpoint || !state.terminal || state.unknown || state.reply.is_some()
                    || state.driver_end.is_some() || state.driver_join != ManagementJoin::Returned || state.watchdog_join != ManagementJoin::Returned
                    || !matches!(state.watchdog_end, Some(WatchdogEnd::DriverObserved(ManagementJoin::Returned)))
                    || (if row.hold == SessionQueryHold::Deadline {
                        state.error.as_ref().map(|e| e.code.as_str()) != Some("query_timeout")
                            || state.cleanup_endpoint != Some(row.endpoint + CLEANUP_TIME)
                    } else { state.error.is_some() || state.cleanup_endpoint.is_some() })
                    || row.hold == SessionQueryHold::Loss && !row.asset_released { return false; }
                drop(state);
                if resources.inspection_return != Some(ManagementJoin::Returned) || resources.acquisition_return != Some(ManagementJoin::Returned)
                    || resources.inspection.is_some() || resources.inspection_error.is_some() || resources.acquisition.is_some() || resources.acquisition_error.is_some()
                    || resources.child.is_some() || resources.waited.is_none() || resources.writer.is_some() || resources.stdout.is_some() || resources.stderr.is_some()
                    || resources.failed_writer.is_some() || resources.failed_stdout.is_some() || resources.failed_stderr.is_some()
                    || resources.write_end.is_none() || resources.out_end.is_some() || resources.err_end.is_some()
                    || !resources.native_started || resources.native_settlement.is_some()
                    || !matches!(resources.native_return.as_ref(), Some(Ok(CloseOutcome::Settled)))
                    || resources.native_observation.is_some() || resources.native_observation_return != Some(ManagementJoin::Returned)
                    || resources.native_snapshots.len() != 1 || !resources.native_snapshots[0].environment_clear() { return false; }
                if row.hold == SessionQueryHold::Deadline {
                    if !resources.kill_attempted { return false; }
                } else if resources.kill_attempted || !resources.waited.as_ref().is_some_and(|status| status.success())
                    || !resources.write_end.is_some_and(|end| end.complete) { return false; }
                let Some(slots) = resources.passive.as_ref() else { return false; };
                let slots = lock(slots);
                let Some(observation) = slots.fixture_observation() else { return false; };
                if !slots.settled() || slots.claimed_observation().is_none() || slots.no_child_effect()
                    || observation.phase() != "settled" || observation.records() == 0
                    || observation.positive_closes() != observation.records() || observation.live_originals() != 0
                    || observation.pending_acquisitions() != 0 || observation.uncertain_closes() != 0 { return false; }
                if !row.owner.driver.try_lock().is_ok_and(|slot| slot.is_none())
                    || !row.owner.watchdog.try_lock().is_ok_and(|slot| slot.is_none()) || lock(&row.owner.permit).is_some() { return false; }
            }
            if self.inner.disabled.load(Ordering::SeqCst) || !self.inner.stopping.load(Ordering::SeqCst)
                || !lock(&self.inner.owners).is_empty() || self.inner.permits.available_permits() != ACTIVE_LIMIT
                || Instant::now() >= observation_end { return false; }
            // Keep the actual checked maps in their original resource books.
            // finish must complete the whole Exit conjunction before main may
            // emit CONTRACTS, these maps, the session receipt and success.
            self.retired = true;
            true
        }
        pub(crate) fn report_retired(&mut self) -> bool {
            if !self.valid || !self.retired || self.report_attempted { return false; }
            self.report_attempted = true;
            // Reporting is one-use DATA observation, not retirement or a new
            // query/cleanup owner. A partial write/lock failure cannot produce
            // a session receipt or success, nor authorize replay.
            for row in &self.originals {
                let Ok(resources) = row.owner.resources.try_lock() else { return false; };
                installed_native_fixture::report(&resources.native_snapshots);
            }
            true
        }
    }
}
#[cfg(all(debug_assertions, feature = "custom-protocol"))]
pub(crate) use session::{InstalledSessionQueries, InstalledSessionQueryDiagnostic, SessionQueryHold, assert_installed_session_query_diagnostic_contract};
#[cfg(all(debug_assertions, feature = "custom-protocol"))]
pub(super) use session::{FirstUnknown, UnknownBoundary, SessionQueryBook, register_session_query, session_child_case, hold_session_query};
