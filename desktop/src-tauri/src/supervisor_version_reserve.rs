//! Allocating variant of the SAME SOURCE invocation and original Resources.
//! No second process, timer, reader, state store or allocation algorithm. The
//! Python allocator remains sole proposer; native jobs ACK only actual Store
//! returns. A FIN is never the native all-jobs/observer return.
use super::*;
use crate::{
    application_state_store::{Cleanup, Durability, Effect, StateError},
    version_allocation_state_native::{
        dialogue as wire, jobs,
        reserve::{Selection, StateHold},
    },
};
use std::sync::Weak;
use zeroize::Zeroizing;

pub(crate) struct VersionReserveControl {
    endpoints: Endpoints,
    stopped: AtomicBool,
    unknown: AtomicBool,
    live: AtomicBool,
    original: Mutex<Option<Weak<Owner>>>,
    cutoff: watch::Sender<Option<Instant>>,
    state_failure: Mutex<Option<StateError>>,
}
impl VersionReserveControl {
    pub(crate) fn new(started: Instant) -> Result<Self, BridgeError> {
        Ok(Self {
            endpoints: Endpoints::at(started).ok_or_else(BridgeError::timeout)?,
            stopped: AtomicBool::new(false),
            unknown: AtomicBool::new(false),
            live: AtomicBool::new(true),
            original: Mutex::new(None),
            cutoff: watch::channel(None).0,
            state_failure: Mutex::new(None),
        })
    }
    pub(crate) fn started(&self) -> Instant {
        self.endpoints.work - Duration::from_secs(60)
    }
    pub(crate) fn work_end(&self) -> Instant {
        self.endpoints.work
    }
    pub(crate) fn current(&self) -> bool {
        self.live.load(Ordering::SeqCst)
            && !self.stopped.load(Ordering::SeqCst)
            && !self.uncertain()
            && Instant::now() < self.endpoints.work
    }
    pub(crate) fn pending(&self) -> bool {
        self.live.load(Ordering::SeqCst) || self.uncertain()
    }
    pub(crate) fn uncertain(&self) -> bool {
        self.unknown.load(Ordering::SeqCst)
    }
    pub(crate) fn never_admitted(&self) -> bool {
        !self.uncertain() && self.original.lock().is_ok_and(|s| s.is_none())
    }
    pub(crate) fn stop(&self) {
        self.stop_at(Instant::now());
    }
    pub(crate) fn stop_at(&self, first: Instant) {
        self.retain_cutoff(self.endpoints.first_failure(first));
        // Poison may recover only to stop THIS original, never to release it.
        let original = match self.original.lock() {
            Ok(v) => v,
            Err(e) => {
                self.unknown.store(true, Ordering::SeqCst);
                e.into_inner()
            }
        };
        let owner = original.as_ref().and_then(Weak::upgrade);
        drop(original);
        if let Some(owner) = owner {
            let mut state = match owner.state.lock() {
                Ok(v) => v,
                Err(e) => {
                    self.unknown.store(true, Ordering::SeqCst);
                    e.into_inner()
                }
            };
            if !state.terminal {
                state.fail_at(Refusal::Cancelled.error(), first);
            }
            let cutoff = state.cleanup_endpoint;
            drop(state);
            if let Some(end) = cutoff {
                self.retain_cutoff(end);
            }
            owner.stop.send_replace(true);
            owner.changed.notify_waiters();
        }
    }
    /// Called after actual OwnerState unlock. Absolute original cutoffs only
    /// contract; no callback into retirement and no renewed stage clock.
    pub(super) fn retain_cutoff(&self, end: Instant) {
        self.stopped.store(true, Ordering::SeqCst);
        let end = end.min(self.endpoints.hard);
        self.cutoff.send_if_modified(|old| {
            if old.is_some_and(|p| p <= end) {
                false
            } else {
                *old = Some(end);
                true
            }
        });
    }
    pub(crate) fn cleanup_end(&self) -> Instant {
        (*self.cutoff.borrow()).map_or(self.endpoints.hard, |e| e.min(self.endpoints.hard))
    }
    pub(crate) fn stop_clock(&self) -> watch::Receiver<Option<Instant>> {
        self.cutoff.subscribe()
    }
    pub(crate) fn unknown(&self) {
        self.unknown.store(true, Ordering::SeqCst);
        self.stop();
    }
    pub(crate) fn state_failed(&self, error: StateError, first: Instant) {
        match self.state_failure.lock() {
            Ok(mut slot) => {
                slot.get_or_insert(error);
            }
            Err(_) => self.unknown.store(true, Ordering::SeqCst),
        }
        if error.effect == Effect::Unknown
            || error.durability == Durability::Unknown
            || error.cleanup == Cleanup::Unknown
        {
            self.unknown.store(true, Ordering::SeqCst);
        }
        self.stop_at(first);
    }
    pub(crate) fn state_failure(&self) -> Option<StateError> {
        match self.state_failure.lock() {
            Ok(v) => *v,
            Err(_) => Some(crate::version_allocation_state_native::reserve::unknown_failure()),
        }
    }
    /// After genuine Reserve retirement, only its original remaining time may
    /// be transferred to the single native edit. This never makes it live again.
    pub(crate) fn edit_window(&self) -> bool {
        !self.live.load(Ordering::SeqCst)
            && !self.stopped.load(Ordering::SeqCst)
            && !self.uncertain()
            && Instant::now() < self.endpoints.work
    }
    pub(crate) fn edit_retirement_window(&self) -> bool {
        !self.live.load(Ordering::SeqCst)
            && !self.stopped.load(Ordering::SeqCst)
            && !self.uncertain()
            && Instant::now() < self.cleanup_end()
    }
    pub(crate) fn check_cleanup(&self) -> Result<(), BridgeError> {
        if self.uncertain() || Instant::now() >= self.cleanup_end() {
            self.unknown();
            Err(BridgeError::cleanup_unknown())
        } else {
            Ok(())
        }
    }
    /// Only the original Doc after all worker/observer/state/token jobs return.
    pub(crate) fn returned(&self) -> Result<(), BridgeError> {
        self.check_cleanup()?;
        if !self.live.swap(false, Ordering::SeqCst) {
            self.unknown();
            return Err(BridgeError::cleanup_unknown());
        }
        self.check_cleanup()
    }
    pub(super) fn arm(&self, owner: &Arc<Owner>) -> Result<(), BridgeError> {
        let mut slot = self
            .original
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        need(
            slot.is_none()
                && self.current()
                && owner.version_allocation_source_endpoints.is_some_and(|v| {
                    v.work == self.endpoints.work && v.hard == self.endpoints.hard
                }),
        )?;
        *slot = Some(Arc::downgrade(owner));
        Ok(())
    }
}

pub(crate) struct VersionReserveInvocation {
    pub(crate) control: Arc<VersionReserveControl>,
    pub(crate) state: Arc<StateHold>,
    pub(crate) store_observation: Arc<crate::saved_command_owner::StoreVersionObservation>,
    template: Value,
    selection: Selection,
    account_id: String,
    repository: String,
    repository_id: String,
    request: Mutex<Option<Arc<wire::Request>>>,
    finished: Mutex<Option<wire::Finished>>,
    edit_observation: Mutex<Option<Value>>,
}
impl VersionReserveInvocation {
    /// Metadata only, retained on the original source BEFORE inspection starts.
    pub(crate) fn new(
        control: Arc<VersionReserveControl>,
        state: Arc<StateHold>,
        store_observation: Arc<crate::saved_command_owner::StoreVersionObservation>,
        template: Value,
        selection: Selection,
        account_id: String,
        repository: String,
        repository_id: String,
    ) -> Result<Self, BridgeError> {
        need(
            control.current()
                && control.never_admitted()
                && crate::github_connection_protocol::numeric_id(&account_id)
                && crate::github_connection_protocol::numeric_id(&repository_id)
                && crate::github_connection_protocol::coordinate(&repository),
        )?;
        Ok(Self {
            control,
            state,
            store_observation,
            template,
            selection,
            account_id,
            repository,
            repository_id,
            request: Mutex::new(None),
            finished: Mutex::new(None),
            edit_observation: Mutex::new(None),
        })
    }
    /// The original SOURCE inspection job has already inspected its held native
    /// provider. No Doc/native source mutex is held during these state calls.
    pub(super) fn prepare(
        &self,
        source: &mut VersionAllocationSourceRequest,
        work: u64,
        hard: u64,
    ) -> Result<(), BridgeError> {
        self.state.prepare(self.template.clone(),&self.selection,&self.repository,&self.repository_id)
            .map_err(|_|BridgeError::new("version_state_unavailable","The saved allocation state needs attention. Keep manual versions until it is resolved."))?;
        let port = self
            .state
            .port()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        let port = port.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let observation = crate::version_allocation_state_native::ios_inventory::observation_data(
            &self.store_observation,
            &port,
        )
        .map_err(|_| changed())?;
        *self
            .edit_observation
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())? = Some(observation.clone());
        let kind = if crate::version_allocation_state_native::reserve::pending(&port)
            .map_err(|_| BridgeError::cleanup_unknown())?
        {
            wire::Kind::Reconcile
        } else {
            wire::Kind::Reserve
        };
        let initial: Value = protocol::strict_json(&source.initial[..source.initial.len() - 1])?;
        let observations = if kind == wire::Kind::Reconcile {
            Vec::new()
        } else {
            vec![observation]
        };
        let request = Arc::new(wire::Request::from_source(
            &port,
            &source.id,
            kind,
            &self.account_id,
            wire::Clock::new(work, hard)?,
            &observations,
            initial["action"]["source"].clone(),
            initial["action"]["provider"].clone(),
        )?);
        drop(port);
        need(self.control.current())?;
        let mut slot = self
            .request
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        need(slot.is_none())?;
        source.initial = request.initial().to_vec();
        source.digest = request.initial_digest().into();
        source.allocation = Some(request.clone());
        *slot = Some(request);
        Ok(())
    }
    pub(crate) fn request(&self) -> Result<Arc<wire::Request>, BridgeError> {
        self.request
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .clone()
            .ok_or_else(BridgeError::cleanup_unknown)
    }
    pub(crate) fn reserved_edit_data(
        &self,
        finished: &wire::Finished,
    ) -> Result<Value, BridgeError> {
        need(self.state.retired() && finished.outcome["status"] == "reserved")?;
        let request = self.request()?;
        let initial: Value =
            crate::protocol::strict_json(&request.initial()[..request.initial().len() - 1])?;
        let observation = self
            .edit_observation
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .clone()
            .ok_or_else(BridgeError::protocol)?;
        need(finished.outcome["reservation"]["request"] == *request.selected())?;
        let data = serde_json::json!({"schemaVersion":1,"source":initial["action"]["source"],"provider":initial["action"]["provider"],
            "reservation":finished.outcome["reservation"],"authority":initial["action"]["authority"],
            "checkpoint":finished.outcome["checkpoint"],"observation":observation,"clock":initial["action"]["clock"]});
        need(crate::edit_protocol::bounded(&data, 12 * 1024).is_ok())?;
        Ok(data)
    }
    pub(crate) fn matches_request(&self, request: &Arc<wire::Request>) -> bool {
        self.request
            .lock()
            .is_ok_and(|v| v.as_ref().is_some_and(|v| Arc::ptr_eq(v, request)))
    }
    fn retain_finished(&self, finished: wire::Finished) -> Result<(), BridgeError> {
        let mut slot = self
            .finished
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        need(slot.is_none())?;
        *slot = Some(finished);
        Ok(())
    }
    /// Fixed bounded native/control backing in addition to the unchanged SOURCE
    /// and code reservation. Wire copies are counted, not described as RSS.
    pub(crate) fn reservation_bytes() -> Option<usize> {
        let go = 4usize
            .checked_mul((crate::version_allocation_state_native::reserve::STATE_BYTES + 2) / 3)?
            .checked_add(
                wire::REQUEST_LIMIT + wire::OBSERVATIONS_LIMIT + 2 * wire::TOKEN_LIMIT + 1024,
            )?;
        crate::version_allocation_state_native::reserve::RETAINED_BYTES
            .checked_add(go.checked_mul(4)?)?
            .checked_add(wire::OUTPUT_TOTAL_LIMIT.checked_mul(3)?)?
            .checked_add(256 * 1024)?
            .checked_add(
                std::mem::size_of::<Self>() + std::mem::size_of::<VersionReserveControl>(),
            )?
            .checked_add(crate::edit_owner::NativeReservedVersionHandoff::backing_bytes()?)
    }
}

/// Exists only after the SAME original SOURCE wait has joined its actual
/// management observer, and the Resources job roster has retired. No public
/// output, typed FIN or reconstructed state can construct this value.
pub(crate) struct VersionReserveJoined {
    original: Arc<VersionReserveInvocation>,
    receipt: VersionAllocationSourceReceipt,
}
impl VersionReserveJoined {
    pub(crate) fn matches(&self, control: &Arc<VersionReserveControl>, state: &StateHold) -> bool {
        Arc::ptr_eq(control, &self.original.control)
            && std::ptr::eq(state, Arc::as_ptr(&self.original.state))
            && matches!(
                self.receipt,
                VersionAllocationSourceReceipt::Settled {
                    was_unknown: false,
                    ..
                }
            )
    }
    pub(crate) fn source_receipt(&self) -> VersionAllocationSourceReceipt {
        self.receipt.clone()
    }
    pub(crate) fn same_control(&self, control: &Arc<VersionReserveControl>) -> bool {
        Arc::ptr_eq(control, &self.original.control)
    }
    pub(crate) fn request(&self) -> Result<Arc<wire::Request>, BridgeError> {
        self.original.request()
    }
    pub(crate) fn finished(&self) -> Result<wire::Finished, BridgeError> {
        self.original
            .finished
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .clone()
            .ok_or_else(BridgeError::cleanup_unknown)
    }
    pub(crate) fn outcome(&self) -> Result<(), BridgeError> {
        match &self.receipt {
            VersionAllocationSourceReceipt::Settled {
                outcome,
                was_unknown: false,
                ..
            } => outcome.as_ref().map(|_| ()).map_err(Clone::clone),
            _ => Err(BridgeError::cleanup_unknown()),
        }
    }
    pub(crate) fn settled_at(&self) -> Result<Instant, BridgeError> {
        match self.receipt {
            VersionAllocationSourceReceipt::Settled {
                settled_at,
                was_unknown: false,
                ..
            } => Ok(settled_at),
            _ => Err(BridgeError::cleanup_unknown()),
        }
    }
}
impl VersionAllocationSourceWait {
    pub(crate) async fn reserved(self) -> Result<VersionReserveJoined, BridgeError> {
        let original = self
            .owner
            .version_allocation_source
            .as_ref()
            .and_then(|s| s.reserve.clone())
            .ok_or_else(BridgeError::protocol)?;
        let receipt = self.returned().await;
        if !matches!(
            receipt,
            VersionAllocationSourceReceipt::Settled {
                was_unknown: false,
                ..
            }
        ) || original.control.uncertain()
        {
            original.control.unknown();
            return Err(BridgeError::cleanup_unknown());
        }
        original.control.check_cleanup()?;
        Ok(VersionReserveJoined { original, receipt })
    }
}

pub(super) struct StateRequest {
    step: Arc<wire::Step>,
    reply: oneshot::Sender<Result<jobs::Joined, BridgeError>>,
}
pub(super) struct RemoteJobs {
    pub(super) jobs: jobs::Jobs,
    pub(super) requests: Option<mpsc::Receiver<StateRequest>>,
    reply: Option<oneshot::Sender<Result<jobs::Joined, BridgeError>>>,
}
impl RemoteJobs {
    fn new(
        owner: &Arc<Owner>,
        request: Arc<wire::Request>,
        reserve: &Arc<VersionReserveInvocation>,
        requests: mpsc::Receiver<StateRequest>,
    ) -> Result<Self, BridgeError> {
        let jobs = jobs::Jobs::new_reserve(
            request,
            reserve
                .state
                .port()
                .map_err(|_| BridgeError::cleanup_unknown())?,
            owner.stop.subscribe(),
            owner.source_work_end(),
            reserve.control.clone(),
            reserve.state.clone(),
        )
        .map_err(|_| BridgeError::cleanup_unknown())?;
        Ok(Self {
            jobs,
            requests: Some(requests),
            reply: None,
        })
    }
    pub(super) fn pending(&self) -> bool {
        self.requests.is_some() || self.jobs.join_pending()
    }
    pub(super) fn settled(&self) -> bool {
        self.jobs.all_returned() && self.requests.is_none() && self.reply.is_none()
    }
    fn failure(owner: &Owner, failure: jobs::Failure) -> BridgeError {
        if let Some(reserve) = owner
            .version_allocation_source
            .as_ref()
            .and_then(|s| s.reserve.as_ref())
        {
            match failure {
                jobs::Failure::Native(e) => reserve.control.state_failed(e, Instant::now()),
                jobs::Failure::JoinUnknown | jobs::Failure::PortUnknown => {
                    reserve.control.unknown()
                }
                _ => reserve.control.stop(),
            }
        }
        BridgeError::cleanup_unknown()
    }
    pub(super) fn accept(
        &mut self,
        request: Option<StateRequest>,
        owner: &Arc<Owner>,
    ) -> Result<(), BridgeError> {
        self.register_request(request)
            .map_err(|e| Self::failure(owner, e))
    }
    fn register_request(&mut self, request: Option<StateRequest>) -> Result<(), jobs::Failure> {
        let Some(request) = request else {
            self.requests = None;
            return Ok(());
        };
        if self.reply.is_some() || self.jobs.join_pending() {
            return Err(jobs::Failure::Currentness);
        }
        self.reply = Some(request.reply);
        let result = self
            .jobs
            .register(request.step)
            .and_then(|_| self.jobs.release_registered());
        if result.is_err() && !self.jobs.join_pending() && self.jobs.all_returned() {
            // No job was registered: nobody can later call returned(). Release
            // the original reader with ERROR so its request sender can close.
            // A partial/registered job retains this reply until its real join.
            if let Some(reply) = self.reply.take() {
                let _ = reply.send(Err(BridgeError::cleanup_unknown()));
            }
        }
        result
    }
    pub(super) fn returned(
        &mut self,
        result: Result<jobs::Joined, jobs::Failure>,
        owner: &Arc<Owner>,
    ) -> Result<(), BridgeError> {
        let result = result.map_err(|e| Self::failure(owner, e));
        let original = result.as_ref().ok().map(|j| j.original_result());
        if let Some(Err(e)) = original {
            let error = Self::failure(owner, *e);
            owner.fail(error);
        }
        self.reply
            .take()
            .ok_or_else(BridgeError::cleanup_unknown)?
            .send(result)
            .map_err(|_| BridgeError::cleanup_unknown())
    }
}

enum Delivery {
    Ack {
        step: Arc<wire::Step>,
        joined: jobs::Joined,
        done: oneshot::Sender<Result<jobs::Joined, BridgeError>>,
    },
    Finish,
}
async fn write_reserve<W: tokio::io::AsyncWrite + Unpin>(
    mut writer: W,
    source: Arc<VersionAllocationSourceRequest>,
    ready: oneshot::Receiver<Result<(), BridgeError>>,
    go_written: oneshot::Sender<()>,
    mut deliveries: mpsc::Receiver<Delivery>,
    post_request: oneshot::Sender<oneshot::Sender<Result<(), BridgeError>>>,
    inner: Arc<Inner>,
    owner: Arc<Owner>,
    faults: mpsc::Sender<BridgeError>,
) -> WriteEnd {
    let mut stop = owner.stop.subscribe();
    let result=async {
        let invocation=owner.version_allocation_source.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        let reserve=invocation.reserve.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        let request=source.allocation.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        need(reserve.matches_request(request)&&reserve.control.current())?;
        tokio::select!{biased;_=stop.changed()=>return Err(BridgeError::shutdown()),
            value=writer.write_all(request.initial())=>value.map_err(|_|BridgeError::cleanup_unknown())?}
        tokio::select!{biased;_=stop.changed()=>return Err(BridgeError::shutdown()),value=ready=>value.map_err(|_|BridgeError::cleanup_unknown())??}
        let (reply,returned)=oneshot::channel();post_request.send(reply).map_err(|_|BridgeError::cleanup_unknown())?;
        tokio::select!{biased;_=stop.changed()=>return Err(BridgeError::shutdown()),value=returned=>value.map_err(|_|BridgeError::cleanup_unknown())??}
        // Only pure original Doc/Edit/account/Store checks here. No Resources,
        // SourceBook, Host, Store or state-port mutex is held across this gate.
        let go=invocation.gate.claim_reserve(&invocation.input,&owner.id,&source,||claim_go(&inner,&owner))?;
        need(reserve.control.current())?;
        tokio::select!{biased;_=stop.changed()=>return Err(BridgeError::shutdown()),value=writer.write_all(&go)=>value.map_err(|_|BridgeError::cleanup_unknown())?}
        drop(go);go_written.send(()).map_err(|_|BridgeError::cleanup_unknown())?;
        loop {
            let delivery=tokio::select!{biased;_=stop.changed()=>return Err(BridgeError::shutdown()),value=deliveries.recv()=>value.ok_or_else(BridgeError::cleanup_unknown)?};
            match delivery {
                Delivery::Ack{step,joined,done}=>{
                    invocation.gate.check_reserve(&invocation.input,&owner.id,&source)?;
                    let ack=joined.checked_ack(&step).map_err(|_|BridgeError::cleanup_unknown())?;
                    let raw=step.ack(request,ack)?;
                    need(reserve.control.current())?;
                    tokio::select!{biased;_=stop.changed()=>return Err(BridgeError::shutdown()),value=writer.write_all(&raw)=>value.map_err(|_|BridgeError::cleanup_unknown())?}
                    // The sole stdout cursor advances only AFTER this actual
                    // original write return, never on a parsed/native ACK alone.
                    done.send(Ok(joined)).map_err(|_|BridgeError::cleanup_unknown())?;
                },
                Delivery::Finish=>{
                    if owner.failed()||Instant::now()>=owner.source_work_end(){return Err(BridgeError::timeout());}
                    writer.shutdown().await.map_err(|_|BridgeError::cleanup_unknown())?;break;
                },
            }
        }
        Ok::<(),BridgeError>(())
    }.await;
    drop(writer);
    match result {
        Ok(()) => WriteEnd { complete: true },
        Err(error) => {
            owner.fail(error.clone());
            let _ = faults.try_send(error);
            WriteEnd { complete: false }
        }
    }
}
async fn read_reserve<R: AsyncRead + Unpin>(
    mut reader: R,
    source: Arc<VersionAllocationSourceRequest>,
    owner: Arc<Owner>,
    originals: SourceOriginals,
    ready: oneshot::Sender<Result<(), BridgeError>>,
    go_written: oneshot::Receiver<()>,
    deliveries: mpsc::Sender<Delivery>,
    state_requests: mpsc::Sender<StateRequest>,
    faults: mpsc::Sender<BridgeError>,
) -> ReadEnd {
    let mut ready = Some(ready);
    let result = async {
        let invocation = owner
            .version_allocation_source
            .as_ref()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        let reserve = invocation
            .reserve
            .as_ref()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        let request = source
            .allocation
            .as_ref()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        request.ready(&line(&mut reader, wire::READY_LIMIT).await?)?;
        ready
            .take()
            .ok_or_else(BridgeError::cleanup_unknown)?
            .send(Ok(()))
            .map_err(|_| BridgeError::cleanup_unknown())?;
        go_written
            .await
            .map_err(|_| BridgeError::cleanup_unknown())?;
        let mut cursor = wire::Cursor::new(request);
        let mut total = wire::READY_LIMIT;
        loop {
            let raw = line(&mut reader, wire::FIN_LIMIT.max(wire::STATE_FRAME_LIMIT)).await?;
            total = total
                .checked_add(raw.len())
                .ok_or_else(BridgeError::protocol)?;
            need(total <= wire::OUTPUT_TOTAL_LIMIT)?;
            // Strict parser only decides which closed frame the same Cursor
            // consumes. No competing stdout read or second in-flight job.
            let frame = protocol::strict_json(&raw[..raw.len() - 1])?;
            if frame.get("state").is_some() {
                let step = cursor.step(request, &raw)?;
                let (reply, returned) = oneshot::channel();
                state_requests
                    .send(StateRequest {
                        step: step.clone(),
                        reply,
                    })
                    .await
                    .map_err(|_| BridgeError::cleanup_unknown())?;
                let joined = returned
                    .await
                    .map_err(|_| BridgeError::cleanup_unknown())??;
                let (done, returned) = oneshot::channel();
                deliveries
                    .send(Delivery::Ack {
                        step: step.clone(),
                        joined,
                        done,
                    })
                    .await
                    .map_err(|_| BridgeError::cleanup_unknown())?;
                let joined = returned
                    .await
                    .map_err(|_| BridgeError::cleanup_unknown())??;
                cursor.applied(
                    request,
                    &step,
                    joined
                        .checked_ack(&step)
                        .map_err(|_| BridgeError::cleanup_unknown())?,
                )?;
            } else {
                let port = reserve
                    .state
                    .port()
                    .map_err(|_| BridgeError::cleanup_unknown())?;
                let finished = {
                    let port = port.lock().map_err(|_| BridgeError::cleanup_unknown())?;
                    cursor.finish(request, &port, &raw)?
                };
                let result = finished
                    .source
                    .as_ref()
                    .map(|v| {
                        serde_json::from_value::<VersionAllocationSource>(v.clone())
                            .map_err(|_| BridgeError::protocol())
                    })
                    .transpose()?;
                let failure = finished.first_failure_ns.map(|f| (Refusal::Allocation, f));
                let terminal = Terminal {
                    source: if finished.outcome["status"] == "reserved" {
                        result
                    } else {
                        None
                    },
                    failure,
                };
                reserve.retain_finished(finished)?;
                lock(&invocation.mailbox).retain_terminal(terminal)?;
                if let Some((reason, raw)) = failure {
                    let first = originals.failure_bound(raw)?;
                    owner.contract_source_failure(reason, first)?;
                }
                deliveries
                    .send(Delivery::Finish)
                    .await
                    .map_err(|_| BridgeError::cleanup_unknown())?;
                let mut byte = [0u8; 1];
                need(
                    reader
                        .read(&mut byte)
                        .await
                        .map_err(|_| BridgeError::cleanup_unknown())?
                        == 0,
                )?;
                let mut mailbox = lock(&invocation.mailbox);
                need(!mailbox.stdout_returned && mailbox.terminal_entered)?;
                mailbox.stdout_returned = true;
                break;
            }
        }
        Ok::<(), BridgeError>(())
    }
    .await;
    if let Err(error) = result {
        if let Some(ready) = ready {
            let _ = ready.send(Err(error.clone()));
        }
        let _ = faults.try_send(error);
        return ReadEnd {
            bytes: Vec::new(),
            eof: false,
            overflow: true,
        };
    }
    ReadEnd {
        bytes: Vec::new(),
        eof: true,
        overflow: false,
    }
}
pub(super) fn install_io(
    resources: &mut Resources,
    inner: &Arc<Inner>,
    owner: &Arc<Owner>,
    stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
    stderr: tokio::process::ChildStderr,
    faults: &mpsc::Sender<BridgeError>,
) -> Result<oneshot::Receiver<oneshot::Sender<Result<(), BridgeError>>>, BridgeError> {
    need(resources.writer.is_none() && resources.stdout.is_none() && resources.stderr.is_none())?;
    let invocation = owner
        .version_allocation_source
        .as_ref()
        .ok_or_else(BridgeError::cleanup_unknown)?;
    let source = invocation.request()?;
    let reserve = invocation
        .reserve
        .as_ref()
        .ok_or_else(BridgeError::cleanup_unknown)?;
    let request = source
        .allocation
        .as_ref()
        .ok_or_else(BridgeError::cleanup_unknown)?
        .clone();
    let native = resources
        .version_allocation_source
        .as_mut()
        .ok_or_else(BridgeError::cleanup_unknown)?;
    let original = native.reader_original()?;
    need(native.remote.is_none())?;
    let (state_send, state_read) = mpsc::channel(1);
    native.remote = Some(RemoteJobs::new(owner, request, reserve, state_read)?);
    let (ready_send, ready_read) = oneshot::channel();
    let (go_send, go_read) = oneshot::channel();
    let (delivery_send, delivery_read) = mpsc::channel(1);
    let (post_send, post_read) = oneshot::channel();
    let (rw, ew) = oneshot::channel();
    let (ro, eo) = oneshot::channel();
    let (re, ee) = oneshot::channel();
    let (source_copy, owner_copy, inner_copy, sender) =
        (source.clone(), owner.clone(), inner.clone(), faults.clone());
    resources.writer = Some(tokio::spawn(async move {
        if ew.await.is_err() {
            return WriteEnd { complete: false };
        }
        write_reserve(
            stdin,
            source_copy,
            ready_read,
            go_send,
            delivery_read,
            post_send,
            inner_copy,
            owner_copy,
            sender,
        )
        .await
    }));
    let (owner_copy, sender) = (owner.clone(), faults.clone());
    resources.stdout = Some(tokio::spawn(async move {
        if eo.await.is_err() {
            return ReadEnd {
                bytes: Vec::new(),
                eof: false,
                overflow: true,
            };
        }
        read_reserve(
            stdout,
            source,
            owner_copy,
            original,
            ready_send,
            go_read,
            delivery_send,
            state_send,
            sender,
        )
        .await
    }));
    let sender = faults.clone();
    resources.stderr = Some(tokio::spawn(async move {
        if ee.await.is_err() {
            return ReadEnd {
                bytes: Vec::new(),
                eof: false,
                overflow: true,
            };
        }
        read_bounded(stderr, FIN_LIMIT, sender).await
    }));
    if ro.send(()).is_err() || re.send(()).is_err() || rw.send(()).is_err() {
        return Err(BridgeError::cleanup_unknown());
    }
    Ok(post_read)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_protocol::Error;
    #[test]
    fn reserve_first_failure_and_original_cutoff_only_contract() {
        // Original clock/control DATA only, not a constructed worker or join.
        let start = Instant::now();
        let control = VersionReserveControl::new(start).unwrap();
        assert_eq!(control.started(), start);
        assert_eq!(control.work_end(), start + Duration::from_secs(60));
        control.stop_at(start + Duration::from_secs(8));
        assert_eq!(control.cleanup_end(), start + Duration::from_secs(18));
        control.retain_cutoff(start + Duration::from_secs(14));
        control.stop_at(start + Duration::from_secs(50));
        assert_eq!(control.cleanup_end(), start + Duration::from_secs(14));
        control.state_failed(Error::Conflict.into(), start + Duration::from_secs(1));
        assert_eq!(control.cleanup_end(), start + Duration::from_secs(11));
        assert!(control.pending() && !control.current() && !control.uncertain());
    }
    #[test]
    fn uncertain_state_facts_and_late_return_never_release_reserve() {
        let now = Instant::now();
        let control = VersionReserveControl::new(now).unwrap();
        let original = StateError {
            code: Error::StateUnknown,
            effect: Effect::Applied,
            durability: Durability::Unknown,
            cleanup: Cleanup::Settled,
        };
        control.state_failed(original, now);
        assert_eq!(control.state_failure(), Some(original));
        assert!(control.returned().is_err() && control.pending() && control.uncertain());
        let late = VersionReserveControl::new(now - Duration::from_secs(80)).unwrap();
        assert!(late.returned().is_err() && late.pending() && late.uncertain());
    }
    #[test]
    fn stopped_unregistered_state_request_releases_error_reply_and_drains_channel() {
        use crate::{
            application_service::ProjectBinding,
            application_state_store::{Fixture, Namespace, PrivateStateDirectory},
            service_protocol::Id,
            version_allocation_state_native::VersionAllocationStatePort,
        };
        use sha2::{Digest, Sha256};
        // Real disposable Store + original Jobs/channels. No HTTP, Source
        // admission, NativeUse or manufactured successful job/worker receipt.
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let fixture = Fixture::new();
            let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
            let authority = json!({"projectId":"11111111-1111-4111-8111-111111111111",
                "repository":"fixture/repository","repositoryId":"27",
                "ledgerId":"33333333-3333-4333-8333-333333333333",
                "genesisSha256":"a".repeat(64),"protectedBranch":true});
            let project = ProjectBinding {
                project_id: Id::parse(&"b".repeat(32)).unwrap(),
                canonical_root: "/synthetic/reserve-stop".into(),
                device: 1,
                inode: 2,
            };
            let checkpoint = json!({"sequence":0,"headSha256":"a".repeat(64),"commit":"c".repeat(40)});
            let mut port = VersionAllocationStatePort::new(store.clone(), project, authority).unwrap();
            port.load().unwrap();
            port.enroll(checkpoint.clone()).unwrap();
            port.select_new(json!({"projectId":"11111111-1111-4111-8111-111111111111",
                "identityRevision":"b".repeat(64),"source":{"commit":"d".repeat(40),"tree":"e".repeat(40),
                    "ref":"refs/heads/main","configurationSha256":"f".repeat(64),"versionSha256":"c".repeat(64)},
                "baseVersion":{"name":"1.2.3","build":40},"platforms":["android"],
                "policy":{"schemaVersion":1,"mode":"automatic","rules":[{"ref":"refs/heads/main","increment":"build"}],
                    "buildCeiling":2100000000u64,"storeMaxAgeSeconds":900}}), None).unwrap();
            let before = store.read(Namespace::VersionAllocations).unwrap();
            let request = Arc::new(wire::Request::from_port(
                &port,
                "reserve-stop-data-1",
                wire::Kind::Reserve,
                "17",
                wire::Clock::new(70_000_000_000, 80_000_000_000).unwrap(),
                &[],
            ).unwrap());
            let mut frame = json!({"protocol":wire::PROTOCOL,"id":"reserve-stop-data-1","state":{
                "requestSha256":request.initial_digest(),"sequence":1,"expectedRevision":before.revision.0,
                "payloadSha256":format!("{:x}",Sha256::digest(&before.bytes)),
                "transition":{"kind":"checkpoint","checkpoint":checkpoint}}});
            frame.sort_all_objects();
            let mut raw = serde_json::to_vec(&frame).unwrap();
            raw.push(b'\n');
            let step = wire::Cursor::new(&request).step(&request, &raw).unwrap();
            let (stop, stopped) = watch::channel(false);
            let jobs = jobs::Jobs::new(
                request,
                Arc::new(Mutex::new(port)),
                stopped,
                Instant::now() + Duration::from_secs(60),
            ).unwrap();
            let (sender, requests) = mpsc::channel(1);
            let mut remote = RemoteJobs { jobs, requests: Some(requests), reply: None };
            let (reply, mut returned) = oneshot::channel();
            sender.send(StateRequest { step, reply }).await.unwrap();
            stop.send_replace(true);
            let original = remote.requests.as_mut().unwrap().recv().await;
            assert!(matches!(remote.register_request(original), Err(jobs::Failure::Currentness)));
            assert!(!remote.jobs.join_pending() && remote.jobs.all_returned());
            assert!(matches!(returned.try_recv(), Ok(Err(_))));
            assert!(remote.reply.is_none());
            // The actual failed reader can now drop its sender; the same
            // driver's receive sees closure, without a fake joined callback.
            drop(sender);
            let closed = remote.requests.as_mut().unwrap().recv().await;
            assert!(closed.is_none());
            remote.register_request(closed).unwrap();
            assert!(remote.settled() && !remote.pending());
            let after = store.read(Namespace::VersionAllocations).unwrap();
            assert_eq!(after.revision, before.revision);
            assert_eq!(after.bytes, before.bytes);
            store.close().unwrap();
        });
    }
}
