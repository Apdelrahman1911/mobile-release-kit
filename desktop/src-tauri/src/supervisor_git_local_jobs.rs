//! Finite GitLocal jobs INSIDE the original Supervisor Resources. No generic
//! callback, independent task roster, process owner, timeout handle drop or DB.
//! Every body waits for its retained slot's one-shot release before any IO.
use super::*;
use crate::application_service_host::{NativeStateLease, NativeStateReady, NativeStateTicket};
use crate::application_state_store::{NativeUse, Revision, StateError};
use crate::git_local_state::{Ack, GitLocalJournal, Original};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind { Publisher, Host, Open, Preparing, Candidate, Finish, RetireUse, FinishPublisher }
enum Task {
    Publisher,
    Host(Arc<NativeStateTicket>),
    Open(Arc<NativeStateReady>),
    Preparing(Revision),
    Candidate { expected:Revision, original:Arc<Original>, candidate:Arc<wire::Candidate> },
    Finish { expected:Revision, original:Arc<Original>, joined:GitLocalNativeJoined },
    RetireUse,
    FinishPublisher,
}
impl Task {
    fn kind(&self) -> Kind { match self {
        Self::Publisher=>Kind::Publisher,Self::Host(_)=>Kind::Host,Self::Open(_)=>Kind::Open,
        Self::Preparing(_)=>Kind::Preparing,Self::Candidate{..}=>Kind::Candidate,
        Self::Finish{..}=>Kind::Finish,Self::RetireUse=>Kind::RetireUse,Self::FinishPublisher=>Kind::FinishPublisher,
    } }
    fn cleanup(&self)->bool {matches!(self,Self::Finish{..}|Self::RetireUse|Self::FinishPublisher)}
}
enum Value { Unit, Revision(Revision), Ack(Arc<Ack>) }
enum Failure { Bridge(BridgeError), Store(StateError), NotReleased, JoinUnknown }
type Returned=std::result::Result<Value,Failure>;
impl Failure {
    fn bridge(&self)->BridgeError {match self {
        Self::Bridge(value)=>value.clone(),
        Self::Store(value)=>state_error(*value),
        Self::NotReleased=>BridgeError::new("cancelled","The original local Git state step was not released."),
        Self::JoinUnknown=>BridgeError::cleanup_unknown(),
    }}
}
struct Slot {
    kind:Kind, release:Option<oneshot::Sender<()>>, handle:Option<JoinHandle<Returned>>,
    returned:Option<Arc<Returned>>, join_error:Option<tokio::task::JoinError>, released:bool,
}
#[derive(Default)]
struct Held {
    lease:Option<NativeStateLease>, journal:Option<GitLocalJournal>,
    preparing:Option<Arc<Ack>>, candidate:Option<Arc<Ack>>, finished:Option<Arc<Ack>>,
    use_retired:bool,
}
/// Installed in original Resources before registering/releasing any job.
pub(super) struct Jobs {
    held:Arc<Mutex<Held>>, slots:[Option<Slot>;8], active:Option<usize>, count:usize,
    publisher_finished:bool, failed:bool, host_ticket:Option<Arc<NativeStateTicket>>,
    host_cancel_attempted:bool,host_cancel_returned:bool,
}
impl Jobs {
    pub(super) fn new()->Self {Self {held:Arc::new(Mutex::new(Held::default())),slots:std::array::from_fn(|_|None),
        active:None,count:0,publisher_finished:false,failed:false,host_ticket:None,host_cancel_attempted:false,host_cancel_returned:false}}
    pub(super) fn all_returned(&self)->bool {self.active.is_none() && self.slots.iter().flatten()
        .all(|s|s.returned.is_some() && s.handle.is_none() && s.join_error.is_none())}
    pub(super) fn complete(&self)->bool {self.all_returned() && self.publisher_finished
        && (self.host_ticket.is_none()||self.host_cancel_returned)
        && self.held.try_lock().is_ok_and(|h|h.lease.is_none()||h.use_retired)}
    fn seen(&self,kind:Kind)->bool {self.slots.iter().flatten().any(|s|s.kind==kind)}
    fn register(&mut self, owner:&Arc<Owner>, task:Task)->Result<(),BridgeError> {
        let original=owner.git_local.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        let kind=task.kind();let cleanup=task.cleanup();
        if self.active.is_some() || self.count>=self.slots.len() || self.seen(kind)
            || (!cleanup && (self.failed||owner.failed())) || lock(&owner.state).unknown
            || !within(owner,cleanup) {return Err(BridgeError::cleanup_unknown())}
        let prior_failed=self.failed;
        self.failed=true; // Unwinding registration cannot expose another slot.
        let index=self.count;self.count+=1;
        let (release,enter)=oneshot::channel();
        self.slots[index]=Some(Slot {kind,release:Some(release),handle:None,returned:None,join_error:None,released:false});
        self.active=Some(index);
        let gate=original.gate.clone();let id=owner.id.clone();let held=self.held.clone();let worker=owner.clone();
        let handle=match task {
            Task::Host(ticket)=>{
                tokio::spawn(async move {
                    enter.await.map_err(|_|Failure::NotReleased)?;
                    if worker.failed()||!within(&worker,false) {return Err(Failure::NotReleased)}
                    let host=gate.host().map_err(Failure::Bridge)?;
                    let path=gate.app_data().map_err(Failure::Bridge)?;
                    host.prepare_native_state(&ticket,&path).await.map_err(|e|Failure::Bridge(host_error(e)))?;
                    Ok(Value::Unit)
                })
            },
            other=>tokio::task::spawn_blocking(move || {
                enter.blocking_recv().map_err(|_|Failure::NotReleased)?;
                if !within(&worker,cleanup)||(!cleanup&&worker.failed()) {return Err(Failure::NotReleased)}
                match other {
                    Task::Publisher=>{gate.accept_publisher_off_document(&id).map_err(Failure::Bridge)?;Ok(Value::Unit)},
                    Task::Open(ready)=>{
                        let mut originals=held.lock().map_err(|_|Failure::JoinUnknown)?;
                        if originals.lease.is_some()||originals.journal.is_some() {return Err(Failure::JoinUnknown)}
                        // The actual use is retained before namespace IO. An
                        // interrupted return cannot be replaced from readback.
                        originals.lease=Some(ready.begin_use().map_err(Failure::Store)?);
                        let lease=originals.lease.as_ref().ok_or(Failure::JoinUnknown)?;
                        let journal=GitLocalJournal::new(lease.store().clone(),lease.native_use().clone(),lease.project_binding().clone());
                        originals.journal=Some(journal);
                        let revision=originals.journal.as_mut().ok_or(Failure::JoinUnknown)?.open().map_err(Failure::Store)?;
                        Ok(Value::Revision(revision))
                    },
                    Task::Preparing(expected)=>{
                        let review=gate.review().ok_or(Failure::JoinUnknown)?;
                        let mut originals=held.lock().map_err(|_|Failure::JoinUnknown)?;
                        if originals.preparing.is_some() {return Err(Failure::JoinUnknown)}
                        let ack=Arc::new(originals.journal.as_mut().ok_or(Failure::JoinUnknown)?
                            .prepare(expected,&id,&review).map_err(Failure::Store)?);
                        originals.preparing=Some(ack.clone());Ok(Value::Ack(ack))
                    },
                    Task::Candidate {expected,original,candidate}=>{
                        // Python is paused in its sole candidate ACK wait.
                        // This is the fixed second native source/runtime POST.
                        worker.git_local.as_ref().ok_or(Failure::JoinUnknown)?
                            .before_candidate(&worker).map_err(Failure::Bridge)?;
                        let mut originals=held.lock().map_err(|_|Failure::JoinUnknown)?;
                        if originals.candidate.is_some() {return Err(Failure::JoinUnknown)}
                        let ack=Arc::new(originals.journal.as_mut().ok_or(Failure::JoinUnknown)?
                            .candidate(expected,&original,&candidate.intent).map_err(Failure::Store)?);
                        originals.candidate=Some(ack.clone());Ok(Value::Ack(ack))
                    },
                    Task::Finish {expected,original,joined}=>{
                        let mut originals=held.lock().map_err(|_|Failure::JoinUnknown)?;
                        if originals.finished.is_some() {return Err(Failure::JoinUnknown)}
                        let ack=Arc::new(originals.journal.as_mut().ok_or(Failure::JoinUnknown)?
                            .finish(expected,&original,&joined).map_err(Failure::Store)?);
                        originals.finished=Some(ack.clone());Ok(Value::Ack(ack))
                    },
                    Task::RetireUse=>{
                        let mut originals=held.lock().map_err(|_|Failure::JoinUnknown)?;
                        let lease=originals.lease.as_ref().ok_or(Failure::JoinUnknown)?;
                        if originals.use_retired {return Err(Failure::JoinUnknown)}
                        lease.store().retire_native_use(lease.native_use()).map_err(Failure::Store)?;
                        originals.use_retired=true;Ok(Value::Unit)
                    },
                    Task::FinishPublisher=>{gate.finish_publisher_off_document().map_err(Failure::Bridge)?;Ok(Value::Unit)},
                    Task::Host(_)=>Err(Failure::JoinUnknown),
                }
            }),
        };
        self.slots[index].as_mut().ok_or_else(BridgeError::cleanup_unknown)?.handle=Some(handle);
        self.failed=prior_failed;Ok(())
    }
    fn release(&mut self,owner:&Owner,cleanup:bool)->Result<(),BridgeError> {
        let slot=self.active.and_then(|n|self.slots[n].as_mut()).ok_or_else(BridgeError::cleanup_unknown)?;
        if slot.released||slot.handle.is_none()||slot.returned.is_some()||!within(owner,cleanup)
            ||(!cleanup&&owner.failed()) {
            self.failed=true;slot.release.take();return Err(BridgeError::cleanup_unknown())
        }
        slot.released=true;
        slot.release.take().ok_or_else(BridgeError::cleanup_unknown)?.send(()).map_err(|_|BridgeError::cleanup_unknown())
    }
    fn stop_host(&mut self,owner:&Owner) {
        if self.host_cancel_attempted||self.host_ticket.is_none() {return}
        self.host_cancel_attempted=true;
        // Exact TRY-only original-ticket cancellation. A busy/unknown attempt
        // is not retried or dropped as though Host startup had been retired.
        let result=(|| {
            let ticket=self.host_ticket.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
            let host=owner.git_local.as_ref().ok_or_else(BridgeError::cleanup_unknown)?.gate.host()?;
            // Conflict can follow a partially consumed failed handoff. It
            // proves neither successful handoff nor cleanup, and must never
            // target or infer permission from a newer Host ticket.
            host.cancel_native_state_ticket(ticket).map_err(|_|BridgeError::cleanup_unknown())
        })();
        self.host_cancel_returned=result.is_ok();
        if let Err(error)=result {owner.fail(error)}
    }
    /// Borrow actual JoinHandle until it returns. STOP/expiry do NOT drop an
    /// fsync/open/startup future or pretend its result did not reach the Store.
    async fn join(&mut self,inner:&Inner,owner:&Arc<Owner>)->Result<Arc<Returned>,BridgeError> {
        let index=self.active.ok_or_else(BridgeError::cleanup_unknown)?;
        let mut stop=owner.stop.subscribe();
        loop {
            let end=owner.advance_clock(inner,Instant::now());
            if owner.failed() {self.stop_host(owner)}
            let slot=self.slots[index].as_mut().ok_or_else(BridgeError::cleanup_unknown)?;
            let handle=slot.handle.as_mut().ok_or_else(BridgeError::cleanup_unknown)?;
            let observe_stop=!*stop.borrow();
            let result=tokio::select! {
                value=handle=>Some(value), _=clock_wait(end)=>None,
                _=stop.changed(),if observe_stop=>None,
            };
            let Some(result)=result else {continue};
            match result {
                Ok(result)=>{
                    let result=Arc::new(result);slot.returned=Some(result.clone());slot.handle.take();self.active=None;
                    self.failed|=result.is_err();
                    if let Err(error)=result.as_ref() {owner.fail(error.bridge());self.stop_host(owner);}
                    return Ok(result)
                },
                Err(error)=>{slot.join_error=Some(error);self.active=None;self.failed=true;owner.unknown(inner);return Err(BridgeError::cleanup_unknown())},
            }
        }
    }
    async fn run(&mut self,inner:&Inner,owner:&Arc<Owner>,task:Task)->Result<Arc<Returned>,BridgeError> {
        let cleanup=task.cleanup();self.register(owner,task)?;
        // A refused release still has an actual registered original to join.
        if let Err(error)=self.release(owner,cleanup) {owner.fail(error)}
        self.join(inner,owner).await
    }
    pub(super) async fn startup(&mut self,inner:&Inner,owner:&Arc<Owner>)->Result<(),BridgeError> {
        let invocation=owner.git_local.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        unit(&self.run(inner,owner,Task::Publisher).await?)?;
        // Actual publisher job join precedes the same-Doc post-epoch/stamp and
        // TRY-only Host ticket. No Host/Store IO is performed under that Doc.
        let ticket=Arc::new(invocation.gate.publisher_joined_begin_host(&owner.id,owner.endpoint())?);
        self.host_ticket=Some(ticket.clone());
        unit(&self.run(inner,owner,Task::Host(ticket)).await?)?;
        // Keep the SAME ticket through TRY/currentness/handoff failure. Host
        // may clear pending before a later check fails; absence or a cancel
        // Conflict is not a successful returned handoff. Only positive
        // original Ready adoption below discharges this retained route.
        let ready=invocation.gate.host_joined(&owner.id,self.host_ticket.as_ref().ok_or_else(BridgeError::cleanup_unknown)?)?;
        self.host_ticket.take();
        let opened=self.run(inner,owner,Task::Open(ready)).await?;
        let expected=match opened.as_ref() {Ok(Value::Revision(v))=>*v,Err(e)=>return Err(e.bridge()),_=>return Err(BridgeError::cleanup_unknown())};
        invocation.gate.check_current(&owner.id)?;
        let prepared=self.run(inner,owner,Task::Preparing(expected)).await?;
        ack(&prepared)?;Ok(())
    }
    pub(super) fn preparing(&self)->Result<Arc<Ack>,BridgeError> {
        self.held.lock().map_err(|_|BridgeError::cleanup_unknown())?.preparing.clone().ok_or_else(BridgeError::cleanup_unknown)
    }
    pub(super) async fn candidate(&mut self,inner:&Inner,owner:&Arc<Owner>,candidate:Arc<wire::Candidate>)->Result<Arc<Ack>,BridgeError> {
        let preparing=self.preparing()?;
        let returned=self.run(inner,owner,Task::Candidate {expected:preparing.revision,original:preparing.original.clone(),candidate}).await?;
        Ok(ack(&returned)?.clone())
    }
    pub(super) fn original(&self)->Result<Option<(Arc<NativeUse>,Arc<Original>,Revision)>,BridgeError> {
        let held=self.held.lock().map_err(|_|BridgeError::cleanup_unknown())?;
        // A write may have reached disk before its ACK was lost. No ACK is
        // never proof of no row. Preserve the actual journal/use in that case.
        if held.journal.as_ref().is_some_and(|j|j.failure().is_some()) {return Err(BridgeError::cleanup_unknown())}
        let Some(ack)=held.candidate.as_ref().or(held.preparing.as_ref()) else {
            if held.journal.as_ref().is_some_and(|j|j.original().is_some()) {return Err(BridgeError::cleanup_unknown())}
            return Ok(None)
        };
        let lease=held.lease.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        Ok(Some((lease.native_use().clone(),ack.original.clone(),ack.revision)))
    }
    pub(super) fn candidate_ack(&self)->Result<Option<Arc<Ack>>,BridgeError> {
        if !self.all_returned() {return Err(BridgeError::cleanup_unknown())}
        Ok(self.held.lock().map_err(|_|BridgeError::cleanup_unknown())?.candidate.clone())
    }
    pub(super) async fn finalize(&mut self,inner:&Inner,owner:&Arc<Owner>,joined:Option<GitLocalNativeJoined>)->Result<(),BridgeError> {
        if !self.all_returned()||lock(&owner.state).unknown {return Err(BridgeError::cleanup_unknown())}
        if self.host_ticket.is_some() {
            self.stop_host(owner);
            if !self.host_cancel_returned {return Err(BridgeError::cleanup_unknown())}
        }
        if let Some((_,original,expected))=self.original()? {
            let joined=joined.ok_or_else(BridgeError::cleanup_unknown)?;
            let result=self.run(inner,owner,Task::Finish {expected,original,joined}).await?;ack(&result)?;
        }
        let has_use=self.held.lock().map_err(|_|BridgeError::cleanup_unknown())?.lease.is_some();
        if has_use {unit(&self.run(inner,owner,Task::RetireUse).await?)?;}
        unit(&self.run(inner,owner,Task::FinishPublisher).await?)?;
        self.publisher_finished=true;Ok(())
    }
}
fn unit(value:&Returned)->Result<(),BridgeError> {match value {Ok(Value::Unit)=>Ok(()),Err(e)=>Err(e.bridge()),_=>Err(BridgeError::cleanup_unknown())}}
fn ack(value:&Returned)->Result<&Arc<Ack>,BridgeError> {match value {Ok(Value::Ack(v))=>Ok(v),Err(e)=>Err(e.bridge()),_=>Err(BridgeError::cleanup_unknown())}}
fn within(owner:&Owner,cleanup:bool)->bool {
    let state=lock(&owner.state);let end=if cleanup {state.cleanup_endpoint.unwrap_or(state.endpoint).min(state.endpoint)} else {state.endpoint};
    !state.terminal&&!state.unknown&&Instant::now()<end
}
