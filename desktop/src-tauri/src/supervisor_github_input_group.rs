//! P2 protocol phases in the original Supervisor's registered IO tasks.
//! No new process owner, watchdog, credential store or phase-local deadline.
use super::*;
use crate::{github_input_group_protocol as wire, github_input_group_session::refused};
use zeroize::Zeroizing;

#[derive(Clone)]
pub(crate) struct ObservedRemote {pub(crate) fact:wire::RemoteFact,pub(crate) observed_at:Instant}
#[derive(Clone)]
pub(crate) struct ObservedReply {pub(crate) reply:wire::Reply,pub(crate) observed_at:Instant}
#[derive(Default)]
struct Progress {remote:Option<ObservedRemote>,reply:Option<ObservedReply>,rechecked:Option<wire::Rechecked>}
pub(super) struct Context {
    pub(super) request:wire::Request,pub(super) gate:crate::asset_session::GitHubInputGoGate,
    read:AtomicBool,go:AtomicBool,registered:AtomicBool,progress:Mutex<Progress>,
}
impl Context {
    pub(super) fn new(request:wire::Request,gate:crate::asset_session::GitHubInputGoGate) -> Self {
        Self {request,gate,read:AtomicBool::new(false),go:AtomicBool::new(false),registered:AtomicBool::new(false),progress:Mutex::new(Progress::default())}
    }
    pub(super) fn read_claimed(&self) -> bool {self.read.load(Ordering::SeqCst)}
    pub(super) fn go_claimed(&self) -> bool {self.go.load(Ordering::SeqCst)}
    pub(super) fn remote(&self) -> Option<ObservedRemote> {lock(&self.progress).remote.clone()}
    pub(super) fn observed_reply(&self) -> Option<ObservedReply> {lock(&self.progress).reply.clone()}
}
pub(super) fn claim_clear(original:bool,profile:Profile,state:&OwnerState,now:Instant,stopping:bool,disabled:bool,stop:bool) -> bool {
    original && matches!(profile,Profile::GitHubInputGroup) && !state.terminal && !state.unknown && state.error.is_none()
        && state.cleanup_endpoint.is_none() && !stopping && !disabled && !stop && now<state.endpoint
}
fn claim(inner:&Inner,owner:&Arc<Owner>,rechecked:Option<&wire::Rechecked>) -> bool {
    // Exact Document -> original registry -> original Owner -> phase progress.
    // The reader never holds progress while calling back into the Owner.
    let owners=lock(&inner.owners);let state=lock(&owner.state);
    let Some(context)=&owner.input_context else {return false;};
    if !claim_clear(owners.get(&owner.key).is_some_and(|v| Arc::ptr_eq(v,owner)),owner.profile,&state,Instant::now(),
        inner.stopping.load(Ordering::SeqCst),inner.disabled.load(Ordering::SeqCst),*owner.stop.borrow())
        || !context.registered.load(Ordering::SeqCst) {return false;}
    let progress=lock(&context.progress);
    claim_phase(context.request.kind(),&context.read,&context.go,&progress,rechecked)
}
// DATA phase predicate only. Its production caller above first holds the exact
// original registry/Owner gates; this helper cannot manufacture those gates.
fn claim_phase(kind:wire::Kind,read:&AtomicBool,go:&AtomicBool,progress:&Progress,rechecked:Option<&wire::Rechecked>) -> bool {
    if progress.reply.is_some() || progress.remote.is_some() {return false;}
    if let Some(rechecked)=rechecked {
        kind==wire::Kind::Apply && read.load(Ordering::SeqCst) && progress.rechecked.as_ref()==Some(rechecked)
            && go.compare_exchange(false,true,Ordering::SeqCst,Ordering::SeqCst).is_ok()
    } else {
        progress.rechecked.is_none() && !go.load(Ordering::SeqCst) && read.compare_exchange(false,true,Ordering::SeqCst,Ordering::SeqCst).is_ok()
    }
}

pub(super) enum Next {Rechecked(wire::Rechecked),Terminal}
pub(super) struct ReaderChannels {ready:Option<oneshot::Sender<Result<(),BridgeError>>>,next:Option<oneshot::Sender<Result<Next,BridgeError>>>}
pub(super) struct WriterChannels {start:oneshot::Receiver<()>,ready:oneshot::Receiver<Result<(),BridgeError>>,next:oneshot::Receiver<Result<Next,BridgeError>>}
pub(super) fn channels() -> (ReaderChannels,WriterChannels,oneshot::Sender<()>) {
    let (ready,ready_rx)=oneshot::channel();let(next,next_rx)=oneshot::channel();let(start,start_rx)=oneshot::channel();
    (ReaderChannels {ready:Some(ready),next:Some(next)},WriterChannels {start:start_rx,ready:ready_rx,next:next_rx},start)
}
pub(super) fn register_io(owner:&Arc<Owner>,resources:&Resources,start:oneshot::Sender<()>) {
    // This bit is published only by the original driver while holding its
    // actual Resources book with all three original JoinHandles registered.
    if resources.writer.is_none() || resources.stdout.is_none() || resources.stderr.is_none() || owner.failed() {
        owner.fail(BridgeError::cleanup_unknown());return;
    }
    if let Some(context)=&owner.input_context {context.registered.store(true,Ordering::SeqCst);}
    else {owner.fail(BridgeError::cleanup_unknown());return;}
    if start.send(()).is_err() {owner.fail(BridgeError::cleanup_unknown());}
}
#[derive(Clone,Copy,PartialEq,Eq)]
enum Phase {Ready,Observed,Rechecked,Outcome,Done}
#[derive(Clone,Copy)]
struct Claims {read:bool,go:bool}
enum Frame {Ready,Rechecked(wire::Rechecked),Outcome(wire::RemoteFact),Result(wire::Reply)}
/// Pure finite DATA parser; supplied Claims in its tests are not native grants.
/// Production reads the exact original context atomics at each received frame.
struct Framer {phase:Phase,frame:PrivateBytes,total:usize,rechecked:Option<wire::Rechecked>,remote:Option<wire::RemoteWrite>}
impl Framer {
    fn new() -> Result<Self,BridgeError> {
        let mut frame=Vec::new();frame.try_reserve_exact(wire::RESPONSE_LIMIT).map_err(|_| BridgeError::protocol())?;
        if frame.capacity()>wire::RESPONSE_LIMIT {return Err(BridgeError::protocol());}
        Ok(Self {phase:Phase::Ready,frame:PrivateBytes(frame),total:0,rechecked:None,remote:None})
    }
    fn byte(&mut self,byte:u8,id:&str,digest:&str,request:&wire::Request,claims:Claims) -> Result<Option<Frame>,BridgeError> {
        self.total=self.total.checked_add(1).ok_or_else(||BridgeError::new("stdout_limit","The input-group response exceeded its finite byte allowance."))?;
        if self.total>wire::STDOUT_LIMIT {return Err(BridgeError::new("stdout_limit","The input-group response exceeded its finite byte allowance."));}
        if self.phase==Phase::Done {return Err(BridgeError::protocol());}
        let bound=if self.phase==Phase::Ready {wire::READY_LIMIT} else {wire::RESPONSE_LIMIT};
        if self.frame.len()>=bound {return Err(BridgeError::new("stdout_limit","The input-group frame exceeded its finite byte allowance."));}
        self.frame.push(byte);if byte!=b'\n' {return Ok(None);}
        let kind=request.kind();
        let event=if self.phase==Phase::Ready {
            if claims.read || claims.go {return Err(BridgeError::protocol());}
            wire::decode_ready(&self.frame,id,digest,kind)?;self.phase=Phase::Observed;Frame::Ready
        } else {
            if !claims.read || claims.go && (kind!=wire::Kind::Apply || self.phase==Phase::Observed) {return Err(BridgeError::protocol());}
            if self.phase==Phase::Observed && kind==wire::Kind::Apply {
                let original=request.action.as_ref().and_then(|a| a.prepared.as_ref()).ok_or_else(BridgeError::protocol)?;
                if let Ok(rechecked)=wire::decode_rechecked(&self.frame,id,digest,original) {
                    if claims.go {return Err(BridgeError::protocol());}
                    self.rechecked=Some(rechecked.clone());self.phase=Phase::Rechecked;Frame::Rechecked(rechecked)
                } else {self.result(id,request,claims)?}
            } else if self.phase==Phase::Rechecked {
                let rechecked=self.rechecked.as_ref().ok_or_else(BridgeError::protocol)?;
                if let Ok(outcome)=wire::decode_outcome(&self.frame,id,rechecked) {
                    if !claims.go {return Err(BridgeError::protocol());}
                    self.remote=Some(outcome.write.clone());self.phase=Phase::Outcome;Frame::Outcome(outcome)
                } else {self.result(id,request,claims)?}
            } else {self.result(id,request,claims)?}
        };
        Ok(Some(event))
    }
    fn result(&mut self,id:&str,request:&wire::Request,claims:Claims) -> Result<Frame,BridgeError> {
        let reply=wire::decode_reply(&self.frame,id,request)?;
        let write=reply.result.as_ref().and_then(|v|v.record.as_ref()).map(|v|&v.write);
        if request.kind()==wire::Kind::Apply {
            if !claims.go && write.is_some_and(|v|*v!=wire::RemoteWrite::NotAttempted) {return Err(BridgeError::protocol());}
            // An observed write must have its exact earlier correlated OUTCOME;
            // a later RESULT alone cannot replace a missing/mismatched ACK.
            if write.is_some_and(wire::RemoteWrite::observed) && self.remote.as_ref()!=write {return Err(BridgeError::protocol());}
            if self.remote.as_ref().is_some_and(wire::RemoteWrite::observed) && self.remote.as_ref()!=write {return Err(BridgeError::protocol());}
        }
        self.phase=Phase::Done;Ok(Frame::Result(reply))
    }
    fn consume(&mut self) {self.frame.clear();}
    fn take_result(&mut self) -> Vec<u8> {std::mem::take(&mut self.frame.0)}
    fn finish(&self) -> Result<(),BridgeError> {
        if self.phase==Phase::Done && self.frame.is_empty() {Ok(())} else {Err(BridgeError::protocol())}
    }
}
fn failure(owner:&Owner,channels:&mut ReaderChannels,error:BridgeError) {
    owner.fail(error.clone());
    if let Some(ready)=channels.ready.take() {let _=ready.send(Err(error.clone()));}
    if let Some(next)=channels.next.take() {let _=next.send(Err(error));}
}
pub(super) async fn read<R:AsyncRead+Unpin>(mut reader:R,owner:Arc<Owner>,digest:String,mut channels:ReaderChannels) -> ReadEnd {
    let mut framer=match Framer::new() {Ok(f)=>f,Err(error)=>{failure(&owner,&mut channels,error);return ReadEnd {bytes:Vec::new(),eof:false,overflow:false};}};
    let mut result=Vec::new();let mut buffer=PrivateBytes(vec![0u8;8192]);let mut failed=false;let mut overflow=false;
    loop {
        let count=match reader.read(&mut buffer).await {
            Ok(0)=>{
                if !failed {if let Err(error)=framer.finish() {failure(&owner,&mut channels,error);}}
                return ReadEnd {bytes:result,eof:true,overflow};
            },
            Ok(count)=>count,
            Err(_)=>{failure(&owner,&mut channels,BridgeError::new("io_error","The original input-group output channel failed."));return ReadEnd {bytes:result,eof:false,overflow};},
        };
        // On a protocol/byte-bound fault latch STOP immediately, then discard
        // while draining this same original pipe to genuine EOF. No new reader.
        if failed {continue;}
        let Some(context)=&owner.input_context else {failure(&owner,&mut channels,BridgeError::cleanup_unknown());failed=true;continue;};
        for byte in &buffer[..count] {
            let claims=Claims {read:context.read_claimed(),go:context.go_claimed()};
            let event=match framer.byte(*byte,&owner.id,&digest,&context.request,claims) {
                Ok(None)=>continue,Ok(Some(event))=>event,
                Err(error)=>{overflow=error.code=="stdout_limit";
                    failure(&owner,&mut channels,error);failed=true;break;},
            };
            let accepted=match event {
                Frame::Ready=>channels.ready.take().is_some_and(|sender| sender.send(Ok(())).is_ok()),
                Frame::Rechecked(rechecked)=>{
                    {let mut progress=lock(&context.progress);progress.rechecked=Some(rechecked.clone());}
                    channels.next.take().is_some_and(|sender| sender.send(Ok(Next::Rechecked(rechecked))).is_ok())
                },
                Frame::Outcome(fact)=>{
                    let mut progress=lock(&context.progress);
                    if progress.remote.is_some() || progress.reply.is_some() {false}
                    else {progress.remote=Some(ObservedRemote {fact,observed_at:Instant::now()});true}
                },
                Frame::Result(reply)=>{
                    // This private result/control fact also survives later
                    // child/journal/native errors, but grants no finality.
                    {let mut progress=lock(&context.progress);progress.reply=Some(ObservedReply {reply,observed_at:Instant::now()});}
                    if let Some(next)=channels.next.take() {let _=next.send(Ok(Next::Terminal));}
                    result=framer.take_result();true
                },
            };
            framer.consume();owner.changed.notify_waiters();
            if !accepted {failure(&owner,&mut channels,BridgeError::protocol());failed=true;break;}
        }
    }
}
fn working(owner:&Owner) -> bool {!*owner.stop.borrow() && !owner.failed() && Instant::now()<owner.endpoint()}
async fn bounded_write(writer:&mut tokio::process::ChildStdin,bytes:&[u8],stop:&mut watch::Receiver<bool>,owner:&Owner) -> Result<(),BridgeError> {
    if !working(owner) {return Err(BridgeError::timeout());}
    tokio::select! {
        _=stop.changed()=>Err(BridgeError::new("cancelled","The original input-group operation was stopped.")),
        _=tokio::time::sleep_until(owner.endpoint().into())=>Err(BridgeError::timeout()),
        result=writer.write_all(bytes)=>result.map_err(|_| BridgeError::new("io_error","The original input-group writer failed.")),
    }
}
async fn close(writer:&mut tokio::process::ChildStdin,stop:&mut watch::Receiver<bool>,owner:&Owner) -> Result<(),BridgeError> {
    tokio::select! {
        _=stop.changed()=>Err(BridgeError::new("cancelled","The original input-group operation was stopped.")),
        _=tokio::time::sleep_until(owner.endpoint().into())=>Err(BridgeError::timeout()),
        result=writer.shutdown()=>result.map_err(|_| BridgeError::new("io_error","The original input-group writer did not close.")),
    }
}
async fn write_inner(writer:&mut tokio::process::ChildStdin,initial:PrivateBytes,channels:WriterChannels,inner:&Inner,owner:&Arc<Owner>) -> Result<(),BridgeError> {
    let mut stop=owner.stop.subscribe();let end=owner.endpoint();
    tokio::select! {
        _=stop.changed()=>return Err(BridgeError::new("cancelled","The original input-group operation was stopped.")),
        _=tokio::time::sleep_until(end.into())=>return Err(BridgeError::timeout()),
        result=channels.start=>result.map_err(|_| BridgeError::cleanup_unknown())?,
    };
    let context=owner.input_context.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
    let digest=wire::digest(&initial);bounded_write(writer,&initial,&mut stop,owner).await?;drop(initial);
    let ready=tokio::select! {
        _=stop.changed()=>return Err(BridgeError::new("cancelled","The original input-group operation was stopped.")),
        _=tokio::time::sleep_until(end.into())=>return Err(BridgeError::timeout()),
        result=channels.ready=>result.map_err(|_| BridgeError::protocol())?,
    };ready?;
    let loan=context.gate.read(&owner.id,&digest,&context.request,|| claim(inner,owner,None))?;
    let read=loan.frame.into_zeroizing();bounded_write(writer,&read,&mut stop,owner).await?;drop(read);
    if context.request.kind()!=wire::Kind::Apply {return close(writer,&mut stop,owner).await;}
    let next=tokio::select! {
        _=stop.changed()=>return Err(BridgeError::new("cancelled","The original input-group operation was stopped.")),
        _=tokio::time::sleep_until(end.into())=>return Err(BridgeError::timeout()),
        result=channels.next=>result.map_err(|_| BridgeError::protocol())?,
    }?;
    let Next::Rechecked(rechecked)=next else {return close(writer,&mut stop,owner).await;};
    let material=loan.material.ok_or_else(|| refused(wire::Reason::AssignmentUnavailable))?;
    if !working(owner) {return Err(BridgeError::timeout());}
    // The exact original writer owns bounded synchronous <=48 KiB sealing.
    // No document/registry/owner lock, detached task or renewed clock crosses
    // the crypto/RNG operation. Actual writer join still gates material release.
    let envelope=material.envelope()?;
    let sealed=crate::github_input_seal::seal(&envelope,&rechecked.snapshot.public_key.key,&rechecked.snapshot.public_key.key_id)
        .map_err(|_| refused(wire::Reason::SealingUnavailable))?;
    drop(envelope);
    if !working(owner) {return Err(BridgeError::timeout());}
    let frame=sealed.with_transport_body(|body| wire::encode_go(&owner.id,&rechecked,body))?;
    let frame:Zeroizing<Vec<u8>>=frame.into_zeroizing();
    // Complete body/base64/JSON/capacity checks PRECEDE the sole mutation claim.
    context.gate.claim_go(&owner.id,&context.request,&rechecked,&material,|| claim(inner,owner,Some(&rechecked)))?;
    bounded_write(writer,&frame,&mut stop,owner).await?;drop(frame);close(writer,&mut stop,owner).await
}
pub(super) async fn write(mut writer:tokio::process::ChildStdin,initial:Vec<u8>,channels:WriterChannels,inner:Arc<Inner>,owner:Arc<Owner>) -> WriteEnd {
    let result=write_inner(&mut writer,PrivateBytes(initial),channels,&inner,&owner).await;
    if let Err(error)=result {owner.fail(error);return WriteEnd {complete:false};}
    // ChildStdin, private buffers and original payload loan drop in THIS task;
    // its real registered return (not cancellation of the await) is required.
    WriteEnd {complete:true}
}

#[cfg(test)]
#[path = "supervisor_github_input_group_tests.rs"]
mod tests;
