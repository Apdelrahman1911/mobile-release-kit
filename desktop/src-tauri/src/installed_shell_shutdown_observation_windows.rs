//! Engineering-only scheduling and readback of the existing passive owner.
//! No runtime selection, request fabrication, process, timer owner, STOP or
//! cleanup replacement is introduced here. Linux/headless fixtures are separate.
use super::*;
use mrk_windows_installed_native::FullwalkFacts;

#[derive(Default)]
pub(super) struct Hooks { book: Mutex<Book> }
#[derive(Default)]
struct Book {
    armed: bool, failed: bool, hold_next_refresh: bool,
    initial: Option<Capture>, refresh: Option<Capture>,
}
struct Capture {
    owner: Arc<Owner>, endpoint: Instant, issued: bool,
    io: Arc<Mutex<Option<IoFacts>>>, hold: Option<Arc<WriterHold>>,
}
#[derive(Clone, Copy)]
struct IoFacts { stdout_eof: bool, stderr_eof: bool, overflow: bool }
pub(super) struct WriterHold {
    registered: watch::Sender<bool>, entered: AtomicBool, live: AtomicBool,
}
impl WriterHold {
    fn new() -> Self {
        let (registered, _) = watch::channel(false);
        Self { registered, entered: AtomicBool::new(false), live: AtomicBool::new(false) }
    }
}

/// Keeps the actual registry Arc and original endpoint, not a query ID receipt.
/// Only the existing final-observer tail can be joined; failures stay retained.
pub(crate) struct WindowsPassiveWitness {
    inner: Arc<Inner>, owner: Arc<Owner>, endpoint: Instant,
    io: Arc<Mutex<Option<IoFacts>>>, hold: Option<Arc<WriterHold>>, attempted: bool,
}
fn need(value: bool) -> Result<(), BridgeError> {
    if value { Ok(()) } else { Err(BridgeError::cleanup_unknown()) }
}
impl Capture {
    fn new(owner: &Arc<Owner>, endpoint: Instant, held: bool) -> Self {
        Self { owner: owner.clone(), endpoint, issued: false,
            io: Arc::new(Mutex::new(None)), hold: held.then(|| Arc::new(WriterHold::new())) }
    }
    fn witness(&mut self, inner: &Arc<Inner>) -> Result<WindowsPassiveWitness, BridgeError> {
        need(!self.issued)?; self.issued = true;
        Ok(WindowsPassiveWitness { inner: inner.clone(), owner: self.owner.clone(), endpoint: self.endpoint,
            io: self.io.clone(), hold: self.hold.clone(), attempted: false })
    }
}
impl Supervisor {
    pub(crate) fn arm_windows_ui_observation(&self) -> Result<(), BridgeError> {
        let owners = lock(&self.inner.owners);
        let mut book = lock(&self.inner.windows_ui.book);
        need(owners.is_empty() && self.inner.next.load(Ordering::SeqCst) == 1
            && !self.stopping() && !self.disabled() && !book.armed && !book.failed
            && self.passive_method_available("capabilities"))?;
        book.armed = true; Ok(())
    }
    pub(crate) fn retain_windows_initial(&self) -> Result<Option<WindowsPassiveWitness>, BridgeError> {
        let mut book = lock(&self.inner.windows_ui.book);
        need(book.armed && !book.failed)?;
        book.initial.as_mut().map(|capture| capture.witness(&self.inner)).transpose()
    }
    pub(crate) fn arm_windows_refresh_hold(&self) -> Result<(), BridgeError> {
        let owners = lock(&self.inner.owners);
        let mut book = lock(&self.inner.windows_ui.book);
        need(book.armed && !book.failed && book.initial.as_ref().is_some_and(|capture| capture.issued)
            && !book.hold_next_refresh && book.refresh.is_none() && owners.is_empty()
            && !self.stopping() && !self.disabled() && self.passive_method_available("project.snapshot"))?;
        book.hold_next_refresh = true; Ok(())
    }
    pub(crate) fn retain_windows_held_refresh(&self) -> Result<Option<WindowsPassiveWitness>, BridgeError> {
        let mut book = lock(&self.inner.windows_ui.book);
        need(book.armed && !book.failed)?;
        let Some(capture) = &mut book.refresh else { return Ok(None); };
        let hold = capture.hold.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        if !hold.entered.load(Ordering::SeqCst) { return Ok(None); }
        need(hold.live.load(Ordering::SeqCst))?;
        Ok(Some(capture.witness(&self.inner)?))
    }
}

/// Called under the existing registry lock, after insertion and before any
/// original task can enter. This retains only the two explicitly armed owners.
pub(super) fn registered(inner: &Arc<Inner>, owner: &Arc<Owner>) {
    let endpoint = owner.endpoint(); // Registry -> state; no hook lock reversal.
    let mut book = lock(&inner.windows_ui.book);
    if !book.armed { return; }
    if book.initial.is_none() {
        if owner.key != 1 || !matches!(owner.profile, Profile::Passive(Method::Capabilities)) {
            book.failed = true; return;
        }
        book.initial = Some(Capture::new(owner, endpoint, false));
    } else if book.hold_next_refresh {
        book.hold_next_refresh = false;
        if book.refresh.is_some() || !matches!(owner.profile, Profile::Passive(Method::ProjectSnapshot)) {
            book.failed = true; return;
        }
        book.refresh = Some(Capture::new(owner, endpoint, true));
    }
}
pub(super) fn writer_hold(inner: &Inner, owner: &Arc<Owner>) -> Option<Arc<WriterHold>> {
    lock(&inner.windows_ui.book).refresh.as_ref()
        .filter(|capture| Arc::ptr_eq(&capture.owner, owner)).and_then(|capture| capture.hold.clone())
}
pub(super) async fn write_request(writer: tokio::process::ChildStdin, bytes: Vec<u8>,
    mut stop: watch::Receiver<bool>, faults: mpsc::Sender<BridgeError>, hold: Option<Arc<WriterHold>>) -> WriteEnd {
    if let Some(hold) = hold {
        let mut registered = hold.registered.subscribe();
        while !*registered.borrow() && !*stop.borrow() {
            tokio::select! {
                result = registered.changed() => if result.is_err() { break; },
                _ = stop.changed() => break,
            }
        }
        if *registered.borrow() && !*stop.borrow() {
            // The real Child and ALL three original IO tasks already reside
            // in Resources. Only scheduling pauses; original STOP ends the hold.
            hold.entered.store(true, Ordering::SeqCst);
            let _ = stop.changed().await;
        }
    }
    super::write_request(writer, bytes, stop, faults).await
}
pub(super) fn after_io_registered(inner: &Inner, owner: &Arc<Owner>, resources: &mut Resources) {
    let Some(hold) = writer_hold(inner, owner) else { return; };
    let registered = resources.writer.is_some() && resources.stdout.is_some() && resources.stderr.is_some()
        && resources.waited.is_none() && !resources.kill_attempted;
    let live = match resources.child.as_mut().map(Child::try_wait) {
        Some(Ok(None)) => registered,
        Some(Ok(Some(status))) => { resources.waited = Some(status); false },
        _ => false,
    };
    hold.live.store(live, Ordering::SeqCst);
    if !live { lock(&inner.windows_ui.book).failed = true; }
    hold.registered.send_replace(true);
}
pub(super) fn settled_io(inner: &Inner, owner: &Arc<Owner>, resources: &Resources) {
    let recorded = {
        let book = lock(&inner.windows_ui.book);
        book.initial.as_ref().filter(|capture| Arc::ptr_eq(&capture.owner, owner))
            .or_else(|| book.refresh.as_ref().filter(|capture| Arc::ptr_eq(&capture.owner, owner)))
            .map(|capture| capture.io.clone())
    };
    let Some(recorded) = recorded else { return; };
    let mut io = lock(&recorded);
    if io.is_some() { drop(io); lock(&inner.windows_ui.book).failed = true; return; }
    // Read before the real driver consumes its original bounded output DTOs.
    *io = Some(IoFacts {
        stdout_eof: resources.out_end.as_ref().is_some_and(|end| end.eof),
        stderr_eof: resources.err_end.as_ref().is_some_and(|end| end.eof),
        overflow: resources.out_end.as_ref().is_none_or(|end| end.overflow)
            || resources.err_end.as_ref().is_none_or(|end| end.overflow),
    });
}
impl WindowsPassiveWitness {
    pub(crate) fn outstanding(&self) -> Result<(), BridgeError> {
        let hold = self.hold.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        let hook_failed = lock(&self.inner.windows_ui.book).failed;
        let owners = lock(&self.inner.owners);
        let state = lock(&self.owner.state);
        need(!hook_failed && !self.attempted
            && owners.get(&self.owner.key).is_some_and(|actual| Arc::ptr_eq(actual, &self.owner))
            && matches!(self.owner.profile, Profile::Passive(Method::ProjectSnapshot))
            && state.endpoint == self.endpoint && Instant::now() < self.endpoint
            && !state.terminal && !state.unknown && state.error.is_none() && state.cleanup_endpoint.is_none()
            && !*self.owner.stop.borrow() && hold.live.load(Ordering::SeqCst)
            && *hold.registered.borrow() && hold.entered.load(Ordering::SeqCst)
            && lock(&self.owner.permit).is_some()
            && !self.inner.stopping.load(Ordering::SeqCst) && !self.inner.disabled.load(Ordering::SeqCst))
        // Resources deliberately stays with its original driver during the
        // hold. The registered live sample is not a replacement resource book.
    }
    pub(crate) async fn observe_retired(&mut self, observation_end: Instant) -> Result<FullwalkFacts, BridgeError> {
        need(!self.attempted)?; self.attempted = true;
        if Instant::now() >= observation_end { return Err(BridgeError::timeout()); }
        let mut original = self.owner.observer.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let handle = original.as_mut().ok_or_else(BridgeError::cleanup_unknown)?;
        let returned = tokio::select! {
            result = handle => result,
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(observation_end)) => return Err(BridgeError::timeout()),
        };
        returned.map_err(|_| BridgeError::cleanup_unknown())?;
        original.take(); drop(original); // Only the genuine successful join.
        let resources = self.owner.resources.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let held = self.hold.is_some();
        need(resources.inspection_return == Some(ManagementJoin::Returned)
            && resources.acquisition_return == Some(ManagementJoin::Returned)
            && resources.inspection.is_none() && resources.inspection_error.is_none()
            && resources.acquisition.is_none() && resources.acquisition_error.is_none()
            && resources.child.is_none() && resources.waited.is_some()
            && (held || resources.waited.as_ref().is_some_and(|status| status.success()))
            && resources.kill_attempted == held
            && resources.writer.is_none() && resources.stdout.is_none() && resources.stderr.is_none()
            && resources.failed_writer.is_none() && resources.failed_stdout.is_none() && resources.failed_stderr.is_none()
            && resources.write_end.is_some_and(|end| end.complete != held)
            && resources.out_end.is_none() && resources.err_end.is_none()
            && resources.native_started && resources.native_settlement.is_none()
            && matches!(resources.native_return.as_ref(), Some(Ok(CloseOutcome::Settled))))?;
        need(lock(&self.io).is_some_and(|io| io.stdout_eof && io.stderr_eof && !io.overflow))?;
        let slots = lock(resources.passive.as_ref().ok_or_else(BridgeError::cleanup_unknown)?);
        need(slots.settled() && !slots.no_child_effect())?;
        let (version, _, _, claimed) = slots.settled_observation().ok_or_else(BridgeError::cleanup_unknown)?;
        need(claimed)?;
        {
            let state = lock(&self.owner.state);
            // The existing original retirement enforces its immutable operation
            // and cleanup endpoints. Later DATA readback never renews either or
            // converts an unknown/timeout into success.
            need(state.endpoint == self.endpoint && state.terminal && !state.unknown && state.reply.is_none()
                && state.driver_end.is_none() && state.driver_join == ManagementJoin::Returned
                && state.watchdog_join == ManagementJoin::Returned
                && matches!(state.watchdog_end, Some(WatchdogEnd::DriverObserved(ManagementJoin::Returned)))
                && if held { state.error.as_ref().is_some_and(|error| error.code == "shutting_down")
                    && state.cleanup_endpoint.is_some_and(|end| end <= self.endpoint + CLEANUP_TIME) }
                else { state.error.is_none() && state.cleanup_endpoint.is_none() })?;
        }
        let registry_retired = {
            let owners = lock(&self.inner.owners);
            let permit = lock(&self.owner.permit);
            owners.is_empty() && permit.is_none() && self.inner.permits.available_permits() == ACTIVE_LIMIT
        };
        let hook_failed = lock(&self.inner.windows_ui.book).failed;
        need(self.inner.stopping.load(Ordering::SeqCst) && !self.inner.disabled.load(Ordering::SeqCst)
            && self.owner.driver.try_lock().is_ok_and(|slot| slot.is_none())
            && self.owner.watchdog.try_lock().is_ok_and(|slot| slot.is_none())
            && registry_retired && !hook_failed)?;
        if Instant::now() >= observation_end { return Err(BridgeError::timeout()); }
        Ok(version)
    }
}
