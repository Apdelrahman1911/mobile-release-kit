//! Fixed state jobs for the EXISTING Supervisor Resources arm (Root wiring).
//!
//! No process, general IO callback, service opener or independent task roster.
//! Construct this object without IO, place it in the original Resources, then
//! register/release each one-shot blocking job. The driver borrows its handle
//! across await. Unknown joins/results remain here until original retirement.
//! The writer still needs its pure original Document gate before sending ACK;
//! this local job return is neither a remote grant nor whole-worker finality.
//! No available native command or replacement Supervisor is installed here.
use super::{dialogue as wire, StateError, VersionAllocationStatePort, WriteAck};
use std::{sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex}, time::Instant};
use tokio::{sync::{oneshot, watch}, task::{JoinError, JoinHandle}};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure { NotReleased, Stopped, Currentness, PortUnknown, JoinUnknown, Native(StateError) }
type Returned = std::result::Result<WriteAck, Failure>;
type Result<T> = std::result::Result<T, Failure>;

fn current(stop: &watch::Receiver<bool>, end: Instant) -> bool {
    !*stop.borrow() && stop.has_changed().is_ok() && Instant::now() < end
}
struct Job {
    step: Arc<wire::Step>,
    release: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<Returned>>,
    returned: Option<Arc<Returned>>,
    join_error: Option<JoinError>,
    released: bool,
}

/// This exact object belongs to one original Supervisor invocation. The
/// native port/request were already retained by the original admission; their
/// Arc identity and selected full request are never reconstructed from JSON.
pub(crate) struct Jobs {
    request: Arc<wire::Request>, port: Arc<Mutex<VersionAllocationStatePort>>,
    stop: watch::Receiver<bool>, end: Instant,
    slots: [Option<Job>; wire::MAX_TRANSITIONS as usize],
    active: Option<usize>, registered: u8, failed: bool,
    revoked: Arc<AtomicBool>,
    reserve: Option<(Arc<crate::supervisor::VersionReserveControl>, Arc<super::reserve::StateHold>)>,
}
impl Jobs {
    /// Pure metadata only: no port/Store/Host mutex, namespace read or worker.
    pub(crate) fn new(request: Arc<wire::Request>, port: Arc<Mutex<VersionAllocationStatePort>>,
        stop: watch::Receiver<bool>, end: Instant) -> Result<Self> {
        if !current(&stop,end) { return Err(Failure::Stopped); }
        Ok(Self { request,port,stop,end,slots:std::array::from_fn(|_|None),active:None,registered:0,failed:false,revoked:Arc::new(AtomicBool::new(false)),reserve:None })
    }
    pub(crate) fn new_reserve(request:Arc<wire::Request>,port:Arc<Mutex<VersionAllocationStatePort>>,
        stop:watch::Receiver<bool>,end:Instant,control:Arc<crate::supervisor::VersionReserveControl>,state:Arc<super::reserve::StateHold>)->Result<Self> {
        if !control.current() || end!=control.work_end() {return Err(Failure::Currentness);}
        let mut jobs=Self::new(request,port,stop,end)?;jobs.reserve=Some((control,state));Ok(jobs)
    }
    fn fail(&mut self) { self.failed = true; self.revoked.store(true,Ordering::Release); }
    /// The caller has already installed Jobs in the actual original Resources.
    /// The closure cannot touch the port until release_registered is called;
    /// its original slot and JoinHandle are installed first, even on STOP.
    pub(crate) fn register(&mut self, step: Arc<wire::Step>) -> Result<()> {
        if self.failed || self.active.is_some() || self.registered >= wire::MAX_TRANSITIONS
            || step.sequence != self.registered + 1 || !step.matches_request(&self.request)
            || !current(&self.stop,self.end) { self.fail(); return Err(Failure::Currentness); }
        self.failed = true; // A panic/failed registration cannot expose another writer.
        let index = self.registered as usize;
        let (release,enter) = oneshot::channel();
        self.slots[index] = Some(Job { step:step.clone(),release:Some(release),handle:None,returned:None,join_error:None,released:false });
        self.active = Some(index); self.registered += 1;
        let port = self.port.clone(); let request = self.request.clone(); let stop = self.stop.clone(); let end = self.end;
        let reserve=self.reserve.clone();
        let job = self.slots[index].as_mut().ok_or(Failure::Currentness)?;
        job.handle = Some(tokio::task::spawn_blocking(move || {
            let result=(||{
                enter.blocking_recv().map_err(|_|Failure::NotReleased)?;
                if !current(&stop,end) { return Err(Failure::Stopped); }
                if let Some((control,state))=&reserve {
                    if !control.current(){return Err(Failure::Stopped);}
                    state.check_use().map_err(Failure::Native)?;
                }
                let mut port = port.lock().map_err(|_|Failure::PortUnknown)?;
                if !current(&stop,end) || !request.matches_port(&port) { return Err(Failure::Currentness); }
                // Original CAS result stays on the registered job. No Doc/Edit
                // lock or fake interruption of the actual Store fsync.
                port.apply(step.expected_revision,request.selected(),step.transition()).map_err(Failure::Native)
            })();
            let at=Instant::now();
            if let (Some((control,_)),Err(error))=(&reserve,&result) {
                match error {Failure::Native(e)=>control.state_failed(*e,at),
                    Failure::JoinUnknown|Failure::PortUnknown=>control.unknown(),_=>control.stop_at(at)}
            }
            result
        }));
        self.failed = false; Ok(())
    }
    pub(crate) fn release_registered(&mut self) -> Result<()> {
        if self.failed || !current(&self.stop,self.end) { self.stop_before_release(); return Err(Failure::Stopped); }
        let job = self.active.and_then(|i|self.slots[i].as_mut()).ok_or(Failure::Currentness)?;
        if job.released || job.handle.is_none() || job.returned.is_some() || job.join_error.is_some() {
            self.fail(); return Err(Failure::Currentness);
        }
        job.released = true; // Claim before send; no second start on failure.
        let release = job.release.take().ok_or(Failure::Currentness)?;
        if release.send(()).is_err() { self.fail(); return Err(Failure::JoinUnknown); }
        Ok(())
    }
    /// STOP only releases an unstarted wait; it does not abort/drop an IO job.
    /// The original owner must still call join_current and retain any error.
    pub(crate) fn stop_before_release(&mut self) {
        self.fail();
        if let Some(job) = self.active.and_then(|i|self.slots[i].as_mut()) { job.release.take(); }
    }
    pub(crate) fn join_pending(&self) -> bool {
        self.active.is_some_and(|i|self.slots[i].as_ref().is_some_and(|j|j.handle.is_some() && j.returned.is_none() && j.join_error.is_none()))
    }
    /// Borrowed original handle, never take/drop-before-await. Driver awaits
    /// outside Document/Edit and separately keeps reader/child/STOP selectable.
    pub(crate) async fn join_current(&mut self) -> Result<Joined> {
        let index = self.active.ok_or(Failure::Currentness)?;
        let job = self.slots[index].as_mut().ok_or(Failure::Currentness)?;
        let handle = job.handle.as_mut().ok_or(Failure::JoinUnknown)?;
        let returned = handle.await;
        match returned {
            Ok(result) => {
                let result = Arc::new(result);
                job.returned = Some(result.clone());
                job.handle.take(); // Only after that exact original join returned.
                self.active = None;
                self.failed |= result.is_err() || !current(&self.stop,self.end);
                if self.failed { self.revoked.store(true,Ordering::Release); }
                Ok(Joined { step:job.step.clone(), result, stop:self.stop.clone(), end:self.end, revoked:self.revoked.clone() })
            },
            Err(error) => {
                job.join_error = Some(error); // Keep the original handle and error.
                self.active = None; self.fail(); Err(Failure::JoinUnknown)
            },
        }
    }
    pub(crate) fn failed(&self) -> bool { self.failed }
    /// Job returns only. Native StateError and whole worker finality still need
    /// their own handling; in particular an unknown Store must not be reopened.
    pub(crate) fn all_returned(&self) -> bool {
        self.active.is_none() && self.slots.iter().flatten().all(|j|j.returned.is_some() && j.join_error.is_none() && j.handle.is_none())
    }
}

/// Constructed only after this original job's actual join. Retains the native
/// return even when later STOP/currentness prevents sending an acknowledgement.
pub(crate) struct Joined {
    step: Arc<wire::Step>, result: Arc<Returned>, stop:watch::Receiver<bool>, end:Instant, revoked:Arc<AtomicBool>,
}
impl Joined {
    pub(crate) fn step(&self) -> &Arc<wire::Step> { &self.step }
    pub(crate) fn original_result(&self) -> &Returned { &self.result }
    /// Necessary but NOT sufficient for wire ACK. Drop all Resources/port/Host
    /// borrows, then rematch the genuine original Document/consent/source gate.
    pub(crate) fn checked_ack(&self, original: &Arc<wire::Step>) -> Result<&WriteAck> {
        if !Arc::ptr_eq(original,&self.step) { return Err(Failure::Currentness); }
        let ack = self.result.as_ref().as_ref().map_err(|error|*error)?;
        if self.revoked.load(Ordering::Acquire) || !current(&self.stop,self.end) { return Err(Failure::Stopped); }
        Ok(ack)
    }
}
