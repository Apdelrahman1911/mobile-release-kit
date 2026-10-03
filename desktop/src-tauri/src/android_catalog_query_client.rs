//! App-side fixed authenticated query driver. One inert pre-GO native context,
//! one original inspector, one immutable clock publication and no per-row worker.
#![forbid(unsafe_code)]
use std::{sync::{Arc,OnceLock},thread,time::{Duration,Instant}};
use tokio::sync::watch;
use mrk_macos_installed_native::{
    android_catalog_query::{self as query,ClientBook,EntryCode,Kind,Payload,Phase,Reply,Request,Role,ScanRow,Signal},
    android_catalog_query_wire::decode_scan,
    android_registration::Failure as TransportFailure,
    android_service_prepare::{PeerCustody,Phase as PreparePhase},
};
use crate::android_shared_lease_macos::{Issue,OriginalClock,RawFailureData};
type Result<T>=std::result::Result<T,Issue>;
pub(crate) type OriginalClockSlot=Arc<OnceLock<Arc<OriginalClock>>>;
fn transport_issue(value:TransportFailure)->Issue{match value{
    TransportFailure::Unavailable=>Issue::Unavailable,TransportFailure::Bounds=>Issue::Bounds,
    TransportFailure::Stopped=>Issue::Stopped,_=>Issue::Unknown,
}}
/// Same-owner sequence and joined DATA are separate from work success. A
/// safely retired failed pending request may be one sequence behind, while a
/// Complete result must actually have processed the whole requested sequence.
fn terminal_data(reply:&Reply,sequence:u32)->Result<Option<(bool,bool)>>{
    if !reply.joined{return Ok(None);}
    if !reply.valid() || reply.payload!=Payload::None || reply.enqueued!=sequence
        || reply.phase==Phase::Complete && reply.processed!=sequence{return Err(Issue::Unknown);}
    let known=!reply.unknown && matches!(reply.phase,Phase::Complete|Phase::Refused);
    if !known{return Err(Issue::Unknown);}
    Ok(Some((known,reply.phase==Phase::Complete && reply.first.is_none())))
}
/// Separate Arc handles are retained by the owner's original independent
/// watchdog BEFORE GO. It can publish earliest local F as soon as the same
/// original clock appears, even while this inspector/native book is blocked.
pub(crate) struct QueryClient{
    signal:Arc<Signal>,clock:OriginalClockSlot,book:ClientBook,audit:watch::Receiver<Instant>,
    nonce:[u8;16],sequence:u32,account:u32,last:u64,entered:bool,native_entered:bool,
    begun:bool,in_call:bool,stop_sent:bool,finished_input:bool,terminal_known:bool,
    terminal_success:bool,retired:bool,first:Option<(Issue,Instant)>,
}
impl QueryClient{
    pub(crate) fn new(audit:watch::Receiver<Instant>)->Self{
        let signal=Arc::new(Signal::reserved());
        Self{book:ClientBook::new(signal.clone()),signal,clock:Arc::new(OnceLock::new()),audit,
            nonce:[0;16],sequence:0,account:0,last:0,entered:false,native_entered:false,
            begun:false,in_call:false,stop_sent:false,finished_input:false,terminal_known:false,
            terminal_success:false,retired:false,first:None}
    }
    pub(crate) fn signal(&self)->Arc<Signal>{self.signal.clone()}
    pub(crate) fn clock_slot(&self)->OriginalClockSlot{self.clock.clone()}
    pub(crate) fn clock(&self)->Option<Arc<OriginalClock>>{self.clock.get().cloned()}
    pub(crate) fn failure_data(&self)->Option<RawFailureData>{self.clock.get().map(|clock|clock.data())}
    pub(crate) fn failure(&self)->Option<(Issue,Instant)>{self.first}
    pub(crate) fn publish(&mut self,issue:Issue,at:Instant){
        if self.first.is_none_or(|(_,old)|at<old){self.first=Some((issue,at));}
        match self.clock.get(){
            Some(clock)=>{let _=clock.publish_local(at,issue.uncertain());},
            None=>self.signal.clock_unknown(),
        }
    }
    fn fail(&mut self,issue:Issue)->Issue{self.publish(issue,Instant::now());issue}
    fn point(&mut self,cleanup:bool,stop:Option<&watch::Receiver<bool>>)->Result<()>{
        if self.in_call{return Err(self.fail(Issue::Unknown));}
        if self.audit.has_changed().is_err() || stop.is_some_and(|s|s.has_changed().is_err()){
            return Err(self.fail(Issue::Unknown));
        }
        if !cleanup && stop.is_some_and(|s|*s.borrow()){return Err(self.fail(Issue::Stopped));}
        let clock=self.clock().ok_or(Issue::Unknown)?;
        if cleanup && Instant::now()>=*self.audit.borrow(){return Err(self.fail(Issue::Deadline));}
        if !clock.point(&mut self.last,cleanup,None){
            return Err(self.fail(if clock.data().unknown{Issue::Unknown}else{Issue::Stopped}));
        }Ok(())
    }
    pub(crate) fn arm(&mut self,role:Role,t:Instant,w:Instant,h:Instant,first:Option<Instant>)->Result<Arc<OriginalClock>>{
        if self.entered || self.clock.get().is_some(){return Err(self.fail(Issue::Unknown));}
        self.entered=true;
        let clock=OriginalClock::for_app(role,t,w,h,first,self.signal.clone())?;
        // Publish ONCE before any identity, client/prepare, SH or tool entry.
        self.clock.set(clock.clone()).map_err(|_|self.fail(Issue::Unknown))?;
        Ok(clock)
    }
    pub(crate) fn begin(&mut self,expected_account:u32,stop:&watch::Receiver<bool>)->Result<()>{
        if self.native_entered || self.retired || self.clock.get().is_none(){return Err(self.fail(Issue::Unknown));}
        self.point(false,Some(stop))?;
        self.in_call=true;
        let account=mrk_macos_installed_native::real_user();
        self.in_call=false;
        let account=account.map_err(|_|self.fail(Issue::Native))?;
        if account!=expected_account || account==0 || account==u32::MAX{return Err(self.fail(Issue::Refused));}
        self.account=account;
        self.point(false,Some(stop))?;self.native_entered=true;self.in_call=true;
        let begun=self.book.begin();self.in_call=false;
        begun.map_err(|value|self.fail(transport_issue(value)))?;
        self.begun=true;
        loop{
            self.point(false,Some(stop))?;self.in_call=true;
            let prepared=self.book.prepare();self.in_call=false;
            // A known nonce remains cleanup custody even if the same prepare
            // returned Stopped after binding. No replacement client is made.
            if let Some(nonce)=self.book.prepared_nonce(){self.nonce=nonce;}
            let reply=prepared.map_err(|value|self.fail(transport_issue(value)))?;
            self.point(false,Some(stop))?;
            match reply.phase{
                PreparePhase::Ready=>return Ok(()),
                PreparePhase::Pending=>thread::park_timeout(Duration::from_millis(2)),
                PreparePhase::Busy|PreparePhase::Refused=>return Err(self.fail(Issue::Refused)),
                PreparePhase::Unknown=>return Err(self.fail(Issue::Unknown)),
            }
        }
    }
    fn request(&self,kind:Kind,sequence:u32,instance:[u8;16])->Result<Request>{
        let bounds=self.clock.get().ok_or(Issue::Unknown)?.bounds();
        let request=Request{bounds,kind,sequence,nonce:self.nonce,instance,
            first:if kind==Kind::Stop{self.signal.first().ok_or(Issue::Unknown)?}else{0}};
        if request.valid(){Ok(request)}else{Err(Issue::Bounds)}
    }
    fn exchange(&mut self,request:Request,cleanup:bool,stop:Option<&watch::Receiver<bool>>)->Result<Reply>{
        self.point(cleanup,stop)?;
        if !self.begun || self.retired{return Err(self.fail(Issue::Unknown));}
        self.in_call=true;let result=self.book.exchange(request,cleanup);self.in_call=false;
        let reply=result.map_err(|value|self.fail(transport_issue(value)))?;
        if reply.account!=self.account || reply.enqueued>self.sequence
            || reply.processed>reply.enqueued{return Err(self.fail(Issue::Unknown));}
        self.point(cleanup,stop)?;Ok(reply)
    }
    fn work(&mut self,kind:Kind,key:[u8;16],stop:&watch::Receiver<bool>)->Result<Reply>{
        if self.finished_input || self.retired || !kind.work() || self.book.prepare_custody()!=PeerCustody::Ready{
            return Err(self.fail(Issue::Unknown));
        }
        self.sequence=self.sequence.checked_add(1).ok_or(Issue::Bounds)?;
        let sequence=self.sequence;let request=self.request(kind,sequence,key)?;
        let mut reply=self.exchange(request,false,Some(stop))?;
        loop{
            if reply.enqueued!=sequence || !(reply.processed==sequence || reply.processed.checked_add(1)==Some(sequence)){
                return Err(self.fail(Issue::Unknown));
            }
            if reply.processed==sequence{
                let complete=match kind{
                    Kind::Scan=>reply.phase==Phase::Candidate && reply.payload==Payload::Scan && reply.instance==[0;16],
                    Kind::ReadIntent=>reply.phase==Phase::Candidate && reply.payload==Payload::Intent && reply.instance==key,
                    Kind::Finish=>reply.payload==Payload::None && (reply.phase==Phase::InputClosed
                        || reply.joined && matches!(reply.phase,Phase::Complete|Phase::Refused|Phase::Unknown)),
                    _=>false,
                };
                if !complete{return Err(self.fail(Issue::Unknown));}
                return Ok(reply);
            }
            if reply.joined || reply.unknown || !matches!(reply.phase,Phase::Working){return Err(self.fail(Issue::Unknown));}
            self.point(false,Some(stop))?;
            thread::park_timeout(Duration::from_millis(2));
            reply=self.exchange(self.request(Kind::Status,0,[0;16])?,false,Some(stop))?;
        }
    }
    pub(crate) fn scan(&mut self,stop:&watch::Receiver<bool>)->Result<Vec<ScanRow>>{
        let reply=self.work(Kind::Scan,[0;16],stop)?;
        decode_scan(&reply.bytes).ok_or_else(||self.fail(Issue::Refused))
    }
    pub(crate) fn read_intent(&mut self,key:[u8;16],stop:&watch::Receiver<bool>)->Result<Reply>{
        let reply=self.work(Kind::ReadIntent,key,stop)?;
        if reply.code==EntryCode::Observed && reply.presence.known!=7{return Err(self.fail(Issue::Unknown));}
        Ok(reply)
    }
    fn accept_terminal(&mut self,reply:&Reply)->Result<bool>{
        let status=terminal_data(reply,self.sequence).map_err(|issue|self.fail(issue))?;
        let Some((known,success))=status else{return Ok(false);};
        self.terminal_known=known;self.terminal_success=success;Ok(true)
    }
    fn wait_terminal(&mut self,mut reply:Option<Reply>)->Result<()>{
        loop{
            if let Some(value)=reply.take(){if self.accept_terminal(&value)?{return Ok(());}}
            self.point(true,None)?;
            thread::park_timeout(Duration::from_millis(2));
            reply=Some(self.exchange(self.request(Kind::Status,0,[0;16])?,true,None)?);
        }
    }
    pub(crate) fn finish(&mut self,stop:&watch::Receiver<bool>)->Result<()>{
        let reply=self.work(Kind::Finish,[0;16],stop)?;
        self.finished_input=true;
        self.wait_terminal(Some(reply))?;
        if self.terminal_success{Ok(())}else{Err(self.fail(Issue::Refused))}
    }
    /// Called exactly once on the SAME entered inspector, including ordinary
    /// failure paths. Native client thread affinity is not delegated to a later
    /// Rust Send cleanup worker. A lost caller retains the original context.
    pub(crate) fn settle_on_inspector(&mut self)->bool{
        if self.retired{return false;}
        if self.in_call{self.fail(Issue::Unknown);return false;}
        if !self.book.peer_nonentry_known() && !self.terminal_known{
            if self.signal.first().is_none(){self.fail(Issue::Stopped);}
            if !self.stop_sent{
                self.stop_sent=true;
                if self.nonce!=[0;16] { if let Ok(request)=self.request(Kind::Stop,0,[0;16]){
                    let result=self.exchange(request,true,None);
                    if let Ok(reply)=result{let _=self.wait_terminal(Some(reply));}
                }}
            }
        }
        // Attempt safe independent releases even when a peer terminal could not
        // be proven. Unknown peer custody still vetoes the later app SH tail.
        self.in_call=true;let released=self.book.release();self.in_call=false;
        self.retired=released && self.book.settled();
        let peer=self.book.peer_nonentry_known() || self.terminal_known;
        if !self.retired || !peer{self.fail(Issue::Unknown);return false;}
        true
    }
    pub(crate) fn observations_settled(&self)->bool{
        self.retired && !self.in_call && self.book.settled() && (self.book.peer_nonentry_known() || self.terminal_known)
    }
    pub(crate) fn successful(&self)->bool{self.observations_settled() && self.terminal_success}
    pub(crate) fn retained_bytes(&self)->Option<usize>{
        std::mem::size_of::<Self>().checked_add(self.book.retained_bytes()?)
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn returned_refusal_may_retire_pending_input_but_never_becomes_complete(){
        let bounds=query::Bounds{role:Role::Start,origin:10,work:10+Role::Start.work_ns(),hard:10+Role::Start.hard_ns()};
        let mut reply=Reply{bounds,phase:Phase::Refused,account:501,nonce:[1;16],processed:0,enqueued:1,
            payload:Payload::None,code:EntryCode::Observed,instance:[0;16],bytes:Vec::new(),
            first:Some(20),cleanup:bounds.cleanup(Some(20)),unknown:false,joined:true,presence:query::Presence::default()};
        assert_eq!(terminal_data(&reply,1),Ok(Some((true,false))));
        reply.joined=false;assert_eq!(terminal_data(&reply,1),Ok(None));reply.joined=true;
        assert!(terminal_data(&reply,2).is_err());
        reply.phase=Phase::Complete;assert!(terminal_data(&reply,1).is_err());
        reply.processed=1;reply.first=None;reply.cleanup=bounds.cleanup(None);
        assert_eq!(terminal_data(&reply,1),Ok(Some((true,true))));
        reply.unknown=true;reply.phase=Phase::Unknown;assert!(terminal_data(&reply,1).is_err());
    }
}
