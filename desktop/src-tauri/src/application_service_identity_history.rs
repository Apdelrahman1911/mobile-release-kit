//! Private, bounded observations of ORIGINAL identity edits. Not an executor.
//!
//! Native admission/updates only enqueue memory. The existing retained relay
//! publishes outside Document/Edit/Control locks; the service's original store
//! still owns every write and durability fact. No request or renderer can mint
//! a capture, select an action, supply a project path, or infer finality here.
use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    OnceLock,
};

const SLOTS: usize = 32;
const PATH_BYTES: usize = 4096;
const RUNTIME_ID_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IdentityObservation {
    Running,
    Prepared,
    CancellationRequested,
    Succeeded,
    Failed,
    Cancelled,
    RecoveryRequired,
    Unknown,
}
impl IdentityObservation {
    fn wire(self) -> (p::OperationState, p::Settlement) {
        use p::{OperationState as S, Settlement as F};
        match self {
            Self::Running => (S::Running, F::Pending),
            Self::Prepared => (S::Prepared, F::Pending),
            Self::CancellationRequested => (S::CancellationRequested, F::Pending),
            Self::Succeeded => (S::Succeeded, F::Settled),
            Self::Failed => (S::Failed, F::Settled),
            Self::Cancelled => (S::Cancelled, F::Settled),
            Self::RecoveryRequired => (S::RecoveryRequired, F::Settled),
            Self::Unknown => (S::Unknown, F::Unknown),
        }
    }
    fn terminal(self) -> bool {
        !matches!(
            self,
            Self::Running | Self::Prepared | Self::CancellationRequested
        )
    }
}

/// Borrowed ONLY from the admitted native Session/RegisteredRoot and original
/// Document binding. There is deliberately no serialized form or constructor
/// from IdentityStatus. This contains no current-input/Store readiness claim.
pub(crate) struct IdentitySource<'a> {
    pub(crate) runtime_id: &'a str,
    pub(crate) root: &'a RegisteredRoot,
    pub(crate) registration: u32,
    pub(crate) document: &'a Arc<()>,
    pub(crate) session_id: &'a str,
}

struct CapturedProject {
    runtime_id: String,
    canonical_root: PathBuf,
    device: u64,
    inode: u64,
    registration: u32,
    document: Arc<()>,
}
struct Key {
    service: Arc<ApplicationService>,
    native: CapturedProject,
    operation: p::Id,
    retired: AtomicBool,
}
pub(crate) struct IdentityCapture {
    history: Arc<History>,
    key: Arc<Key>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Update {
    revision: u32,
    observation: IdentityObservation,
}
struct Row {
    key: Arc<Key>,
    latest: Update,
    acknowledged: Option<IdentityObservation>,
}
#[derive(Clone)]
struct Claim {
    index: usize,
    key: Arc<Key>,
    update: Update,
    first: bool,
}
struct Inbox {
    rows: [Option<Row>; SLOTS],
    claim: Option<Claim>,
    failure: Option<Error>,
    accepting: bool,
    closed: bool,
}
impl Default for Inbox {
    fn default() -> Self {
        Self {
            rows: std::array::from_fn(|_| None),
            claim: None,
            failure: None,
            accepting: true,
            closed: false,
        }
    }
}
impl Inbox {
    fn begin(&mut self, key: Arc<Key>, revision: u32) -> Result<bool, Error> {
        if self.closed || !self.accepting {
            return Ok(false);
        }
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self
            .rows
            .iter()
            .flatten()
            .any(|row| row.key.operation == key.operation)
        {
            return Err(Error::Conflict);
        }
        let slot = self
            .rows
            .iter_mut()
            .find(|row| row.is_none())
            .ok_or(Error::Busy)?;
        *slot = Some(Row {
            key,
            latest: Update {
                revision,
                observation: IdentityObservation::Running,
            },
            acknowledged: None,
        });
        Ok(true)
    }
    fn update(&mut self, key: &Arc<Key>, update: Update) -> Result<(), Error> {
        if key.retired.load(Ordering::Acquire) {
            return Ok(());
        }
        if self.closed || self.failure.is_some() {
            return Err(Error::Unavailable);
        }
        let row = self
            .rows
            .iter_mut()
            .flatten()
            .find(|row| Arc::ptr_eq(&row.key, key))
            .ok_or(Error::Conflict)?;
        if update.revision < row.latest.revision
            || update.revision == row.latest.revision && update != row.latest
        {
            return Err(Error::Conflict);
        }
        if row.latest.observation == IdentityObservation::Unknown {
            return Ok(());
        }
        if row.latest.observation.terminal() && update.observation != row.latest.observation {
            return Err(Error::Conflict);
        }
        row.latest = update;
        Ok(())
    }
    fn claim(&mut self) -> Result<Option<Claim>, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.closed {
            return Ok(None);
        }
        // Only the original relay/final joined-relay drain may claim a write.
        // A second observer cannot take or repeat an outstanding original.
        if self.claim.is_some() {
            return Err(Error::Busy);
        }
        for (index, row) in self.rows.iter().enumerate() {
            let Some(row) = row else {
                continue;
            };
            if row.acknowledged == Some(row.latest.observation) {
                continue;
            }
            let claim = Claim {
                index,
                key: row.key.clone(),
                update: row.latest,
                first: row.acknowledged.is_none(),
            };
            self.claim = Some(claim.clone());
            return Ok(Some(claim));
        }
        Ok(None)
    }
    fn acknowledge(&mut self, claim: &Claim) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.closed {
            return Err(Error::StateUnknown);
        }
        if !self.claim.as_ref().is_some_and(|original| {
            original.index == claim.index
                && Arc::ptr_eq(&original.key, &claim.key)
                && original.update == claim.update
                && original.first == claim.first
        }) {
            return Err(Error::StateUnknown);
        }
        let row = self
            .rows
            .get_mut(claim.index)
            .and_then(Option::as_mut)
            .ok_or(Error::StateUnknown)?;
        if !Arc::ptr_eq(&row.key, &claim.key) {
            return Err(Error::StateUnknown);
        }
        row.acknowledged = Some(claim.update.observation);
        self.claim = None;
        if claim.update.observation.terminal() {
            // Late progress can neither erase this terminal nor resurrect its
            // operation ID. A new recovery has its own original Session.id.
            row.key.retired.store(true, Ordering::Release);
            self.rows[claim.index] = None;
        }
        Ok(())
    }
}

/// Every section of this mutex is finite memory work. Never acquire Host or
/// Service locks, call an owner, or perform IO while it is held. The one service
/// binding comes only from an initially eligible native capture; it permits a
/// lock-free permanent read fence even if this inbox becomes poisoned.
pub(super) struct History {
    inbox: Mutex<Inbox>,
    service: OnceLock<Arc<ApplicationService>>,
}
impl Default for History {
    fn default() -> Self {
        Self {
            inbox: Mutex::new(Inbox::default()),
            service: OnceLock::new(),
        }
    }
}
impl History {
    fn lock(&self) -> Result<MutexGuard<'_, Inbox>, Error> {
        self.inbox.lock().map_err(|_| Error::StateUnknown)
    }
    fn bind(&self, service: &Arc<ApplicationService>) -> bool {
        let _ = self.service.set(service.clone());
        self.service
            .get()
            .is_some_and(|original| Arc::ptr_eq(original, service))
    }
    fn fence(&self, error: Error) {
        // No Service mutex, filesystem call or Host callback. Fence readers
        // BEFORE any later off-native failure reporting can block on IO.
        if let Some(service) = self.service.get() {
            service.fence_native_history();
        }
        if let Ok(mut inbox) = self.lock() {
            if error == Error::StateUnknown || inbox.failure.is_none() {
                inbox.failure = Some(error);
            }
        }
    }
    pub(super) fn retire_capture(&self) {
        let result = self.lock().map(|mut inbox| inbox.accepting = false);
        if let Err(error) = result {
            self.fence(error);
        }
    }
}

fn same_project(left: &NativeProject, right: &CapturedProject) -> bool {
    left.runtime_id == right.runtime_id
        && left.canonical_root == right.canonical_root
        && left.device == right.device
        && left.inode == right.inode
        && left.registration_generation != 0
        && right.registration != 0
        && Arc::ptr_eq(&left.document_identity, &right.document)
    // Registration is a GLOBAL roster generation. Its later increment for an
    // unrelated project is not a new root and cannot rebind/erase old history.
    // Original generations remain retained as provenance in the captured key.
}

impl IdentityCapture {
    pub(crate) fn record(&self, revision: u32, observation: IdentityObservation) {
        if self.key.retired.load(Ordering::Acquire) {
            return;
        }
        let result = (|| {
            if revision == 0 {
                return Err(Error::Conflict);
            }
            self.history.lock()?.update(
                &self.key,
                Update {
                    revision,
                    observation,
                },
            )
        })();
        if let Err(error) = result {
            self.history.fence(error);
        }
    }
    pub(crate) fn unavailable(&self) {
        self.history.fence(Error::StateUnknown);
    }
}

impl ApplicationHost {
    /// TRY-only Host admission. Existing Host methods hold Control across IO,
    /// so waiting for it inside the native registry would delay STOP. Contention
    /// skips this initial capture explicitly; no later update may backfill it.
    /// All subsequent captured updates use only the dedicated memory inbox.
    pub(crate) fn capture_identity(
        self: &Arc<Self>,
        source: IdentitySource<'_>,
        revision: u32,
    ) -> Option<IdentityCapture> {
        let operation = p::Id::parse(source.session_id).ok()?;
        if revision == 0 || source.registration == 0 {
            return None;
        }
        let path = source
            .root
            .path
            .to_str()
            .filter(|path| path.len() <= PATH_BYTES)?;
        let (device, inode) = source.root.identity.posix().ok()?.service_identity();
        let service = {
            let state = match self.control.try_lock() {
                Ok(state) => state,
                Err(std::sync::TryLockError::WouldBlock) => return None,
                Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                    // Cleanup-only reference; never adopt poisoned admission.
                    let service = poisoned.get_ref().service.clone();
                    drop(poisoned);
                    if let Some(service) = service {
                        service.fence_native_history();
                    }
                    self.history.fence(Error::StateUnknown);
                    return None;
                }
            };
            if state.available().is_err() || state.phase != Phase::Listening {
                return None;
            }
            let service = state.service.as_ref()?;
            if service.native_history_current().is_err() {
                return None;
            }
            let registered = state.registered.get(source.runtime_id)?;
            if !registered.valid()
                || registered.runtime_id != source.runtime_id
                || registered.canonical_root != source.root.path
                || registered.device != device
                || registered.inode != inode
                || !Arc::ptr_eq(&registered.document_identity, source.document)
            {
                return None;
            }
            service.clone()
        };
        // Control is released before the separate inbox. Copy only bounded
        // native metadata: no input revision/current-source readiness claim.
        let native = CapturedProject {
            runtime_id: source.runtime_id.to_owned(),
            canonical_root: PathBuf::from(path),
            device,
            inode,
            registration: source.registration,
            document: source.document.clone(),
        };
        if native.runtime_id.capacity() > RUNTIME_ID_BYTES
            || native.canonical_root.capacity() > PATH_BYTES
        {
            return None;
        }
        if !self.history.bind(&service) {
            service.fence_native_history();
            self.history.fence(Error::StateUnknown);
            return None;
        }
        let key = Arc::new(Key {
            service,
            native,
            operation,
            retired: AtomicBool::new(false),
        });
        let inserted = self
            .history
            .lock()
            .and_then(|mut inbox| inbox.begin(key.clone(), revision));
        match inserted {
            Ok(true) => Some(IdentityCapture {
                history: self.history.clone(),
                key,
            }),
            Ok(false) => None,
            Err(error) => {
                self.history.fence(error);
                None
            }
        }
    }

    fn identity_history_key(&self, state: &Control, key: &Key) -> bool {
        !matches!(state.phase, Phase::Dormant | Phase::Closed)
            && state
                .service
                .as_ref()
                .is_some_and(|service| Arc::ptr_eq(service, &key.service))
            && state
                .registered
                .get(&key.native.runtime_id)
                .is_some_and(|native| same_project(native, &key.native))
    }

    /// Relay/final-drain only, NEVER a native registry callback. The atomic
    /// service fence is already effective before waiting for Host Control.
    fn identity_history_failed(&self, error: Error) {
        self.history.fence(error);
        if let Ok(mut state) = self.lock() {
            state.remember(HostFailure::simple(HostStage::Publish, error));
            state.fence.get_or_insert(error);
            state.pending = None;
            state.prepared = None;
            // Do not call state.fail -> revoke_agent_read here: its Service
            // mutex may be held across IO. This permanent atomic fence cannot
            // be cleared by Allow and needs no grant-mutex mutation.
            if let Some(service) = &state.service {
                service.fence_native_history();
            }
        }
    }

    fn flush_identity_with(
        &self,
        publish: impl FnOnce(&Claim) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        let claimed = self.history.lock().and_then(|mut inbox| inbox.claim());
        let claim = match claimed {
            Ok(Some(claim)) => claim,
            Ok(None) => return Ok(false),
            Err(error) => {
                self.identity_history_failed(error);
                return Err(error);
            }
        };
        let mut guard = FlushGuard {
            host: self,
            returned: false,
        };
        // Waiting for existing Host IO is allowed ONLY here, outside native
        // registry/Document/inbox locks. No inbox guard spans this validation.
        let result = (|| {
            {
                let state = self.lock()?;
                if let Some(error) = state.fence {
                    return Err(error);
                }
                if !self.identity_history_key(&state, &claim.key) {
                    return Err(Error::Conflict);
                }
            }
            // No Control guard over the real synchronous service/store call.
            // The SAME relay retains this original; there is no detached task.
            publish(&claim)
        })();
        let recorded = (|| {
            result?;
            self.history.lock()?.acknowledge(&claim)?;
            Ok(true)
        })();
        if let Err(error) = recorded {
            self.identity_history_failed(error);
        }
        guard.returned = true;
        recorded
    }

    /// One fixed original-operation family, called by the existing relay only.
    pub(crate) fn publish_identity_history(&self) -> Result<bool, Error> {
        self.flush_identity_with(publish_claim)
    }

    /// Native exit hook only: AFTER all original edits finish and the SAME
    /// relay is joined, BEFORE original service/store shutdown. Errors remain
    /// in Host custody; the caller MUST still run its ordinary shutdown.
    pub(crate) fn drain_identity_history_for_exit(&self) {
        for _ in 0..SLOTS {
            match self.publish_identity_history() {
                Ok(true) => {}
                Ok(false) | Err(_) => break,
            }
        }
        let result = (|| {
            let mut inbox = self.history.lock()?;
            let error = inbox.failure.or_else(|| {
                if inbox.claim.is_some() {
                    Some(Error::StateUnknown)
                } else if inbox.rows.iter().any(Option::is_some) {
                    // No fabricated terminal to fill an observation gap. Original
                    // shutdown still runs; these retained metadata rows are not
                    // unjoined core work or evidence of a filesystem effect.
                    Some(Error::Conflict)
                } else {
                    None
                }
            });
            inbox.closed = true;
            inbox.accepting = false;
            error.map_or(Ok(()), Err)
        })();
        if let Err(error) = result {
            self.identity_history_failed(error);
        }
    }
}

fn publish_claim(claim: &Claim) -> Result<(), Error> {
    let (state, settlement) = claim.update.observation.wire();
    if claim.first {
        // Atomic require-new under the same original service mutex: even a
        // nonce collision cannot rebind an old pending record.
        claim.key.service.begin_operation(
            &claim.key.native.runtime_id,
            claim.key.operation.clone(),
            p::Action::EditProjectIdentity,
            state,
            settlement,
        )
    } else {
        claim.key.service.publish_operation(
            &claim.key.native.runtime_id,
            claim.key.operation.clone(),
            p::Action::EditProjectIdentity,
            state,
            settlement,
        )
    }
}

struct FlushGuard<'a> {
    host: &'a ApplicationHost,
    returned: bool,
}
impl Drop for FlushGuard<'_> {
    fn drop(&mut self) {
        if self.returned {
            return;
        }
        self.host.identity_history_failed(Error::StateUnknown);
    }
}

/// Count once in the existing global Document census, including idle. At most
/// 32 retained original keys, one not-yet-inserted bounded capture and one
/// acknowledged terminal key still on the original flush stack. Outstanding
/// claimed updates otherwise share row keys. No full projection, source text
/// or credential is retained; existing service/store backing is not doubled.
pub(crate) fn identity_history_document_backing_bytes() -> usize {
    std::mem::size_of::<History>() + 128 // One original link/binding and Arc headers.
        + (SLOTS + 2)
            * (PATH_BYTES
                + RUNTIME_ID_BYTES
                + 32
                + std::mem::size_of::<Key>()
                + 8 * std::mem::size_of::<usize>())
}

#[cfg(test)]
#[path = "application_service_identity_history_tests.rs"]
mod tests;
