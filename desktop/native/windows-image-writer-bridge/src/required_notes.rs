//! Distinct Required Notes v1 bridge. The Image18 and stdio14 ABIs are unchanged.
//! Fixed trusted in-process caller only: live aligned disjoint buffers are a
//! caller obligation, not something integer range checks can prove.
//! A single strong static owner retains native originals and two pinned frames.
//! No worker, Drop close, replacement context, callback, HANDLE or DLL unload.
use mrk_windows_installed_native::required_notes::{NotesContext,wire::{
    self,Request,Reply,Info,Operation as Op,Fault,Status,flags,Result,
    INPUT_MAX,OUTPUT_MAX,BRIDGE_HEAP,RETURN_RESERVE,CALLS_PRODUCER,
    CALLS_RECOVERY,CALLS_FINALITY,CALLS_TOTAL,
}};
use std::{marker::PhantomPinned,mem::{size_of,align_of},pin::Pin,
    panic::{catch_unwind,AssertUnwindSafe},
    sync::{Mutex,TryLockError,atomic::{AtomicBool,Ordering}},thread::ThreadId};

fn bare(status:Status,error:Option<Fault>)->Reply {
    Reply{size:80,version:1,status:status as u32,error:error.map_or(0,|e|e as u32),..Reply::default()}
}
fn buffer(n:usize)->Result<Vec<u8>> {
    let mut b=Vec::new();b.try_reserve_exact(n).map_err(|_|Fault::Capacity)?;
    if b.capacity()!=n{return Err(Fault::Capacity)}b.resize(n,0);Ok(b)
}
struct Frame {
    request:Request,input:Vec<u8>,output:Vec<u8>,receipt:Reply,
    // 0 idle/prepared; 1 entered; 2 definitely returned; 3 native UNKNOWN
    // original retained; 4 bridge loss/malformed (all later entry prohibited).
    phase:u8,_pin:PhantomPinned,
}
impl Frame {
    fn new()->Result<Pin<Box<Self>>> {
        Ok(Box::pin(Self{request:Request::default(),input:buffer(INPUT_MAX)?,
            output:buffer(OUTPUT_MAX)?,receipt:bare(Status::Ok,None),phase:0,_pin:PhantomPinned}))
    }
}
struct Owner {
    thread:ThreadId,native:Option<NotesContext>,frames:[Pin<Box<Frame>>;2],
    prepared:bool,sequence:u64,used:[u64;3],normal_unknown:bool,
    finality_unknown:bool,bridge_unknown:bool,terminal:u32,last:Reply,
}
impl Owner {
    fn new()->Result<Box<Self>> {
        let owner=Box::new(Self{thread:std::thread::current().id(),native:None,
            frames:[Frame::new()?,Frame::new()?],prepared:false,sequence:0,used:[0;3],
            normal_unknown:false,finality_unknown:false,bridge_unknown:false,terminal:0,
            last:bare(Status::Ok,None)});
        let heap=size_of::<Self>()+owner.frames.iter().map(|f|size_of::<Frame>()+
            f.input.capacity()+f.output.capacity()).sum::<usize>();
        if heap.checked_add(RETURN_RESERVE).is_none_or(|n|n>BRIDGE_HEAP){return Err(Fault::Capacity)}
        Ok(owner)
    }
    fn frame_mut(&mut self,index:usize)->&mut Frame {
        // SAFETY: no pinned Frame is moved; only its fields are updated before
        // entry or after definite synchronous return. Unknown frames are not reused.
        unsafe{self.frames[index].as_mut().get_unchecked_mut()}
    }
    fn facts(&self,error:Fault)->Reply {
        let mut r=if self.prepared {
            self.native.as_ref().map_or_else(||bare(Status::Unknown,Some(Fault::NativeUnknown)),
                |n|n.bridge_status(error,self.bridge_unknown))
        }else{bare(if self.bridge_unknown{Status::Unknown}else{Status::Refused},Some(error))};
        r.sequence=self.sequence;r.flags|=self.terminal;
        if self.bridge_unknown{r.status=Status::Unknown as u32;r.flags|=flags::BRIDGE_FRAME_UNKNOWN;}
        r
    }
    fn poison(&mut self) {
        self.bridge_unknown=true;
        for f in &mut self.frames {
            // SAFETY: retain exact request, output and receipt; never move or
            // reconstruct a frame which may be borrowed by native code.
            let f=unsafe{f.as_mut().get_unchecked_mut()};
            if f.phase==1{f.phase=4;}
        }
        if let Some(n)=self.native.as_mut(){n.mark_bridge_unknown();}
        FATAL.store(true,Ordering::Release);
    }
    fn budget(&mut self,lane:usize)->Result<()> {
        let max=[CALLS_PRODUCER,CALLS_RECOVERY,CALLS_FINALITY][lane];
        if self.used[lane]>=max||self.sequence>=CALLS_TOTAL{return Err(Fault::Capacity)}
        self.used[lane]+=1;Ok(())
    }
    fn prepare(&mut self,r:Request,input:&[u8])->Reply {
        if let Err(e)=self.budget(0){return bare(Status::Refused,Some(e))}
        {let f=self.frame_mut(0);f.request=r;f.input[..input.len()].copy_from_slice(input);f.phase=1;}
        let result={
            let input=&self.frames[0].input[..input.len()];
            r.operands(Op::PrepareLease,input).and_then(|_|NotesContext::prepare(input))
        };
        match result {
            Ok(native)=>self.native=Some(native),
            Err(e)=>{let result=bare(Status::Refused,Some(e));let f=self.frame_mut(0);
                f.receipt=result;f.phase=2;self.last=result;return result}
        }
        let result={
            let (native,frames)=(&mut self.native,&mut self.frames);
            let f=unsafe{frames[0].as_mut().get_unchecked_mut()};
            native.as_mut().ok_or(Fault::Owner).and_then(|n|n.prepared(&mut f.output[..r.output_capacity as usize]))
        };
        let mut result=match result {
            Ok(result)=>result,Err(e)=>{let result=bare(Status::Refused,Some(e));
                let f=self.frame_mut(0);f.receipt=result;f.phase=2;self.last=result;return result}
        };
        result.sequence=1;self.frame_mut(0).receipt=result;
        if !valid_reply(r,Op::PrepareLease,&result,&self.frames[0].output,self.terminal) {
            self.frame_mut(0).phase=4;self.poison();return self.facts(Fault::NativeUnknown)
        }
        self.sequence=1;self.prepared=true;self.frame_mut(0).phase=2;self.last=result;result
    }
    fn run(&mut self,r:Request,op:Op,input:&[u8])->(Reply,Option<usize>) {
        if self.thread!=std::thread::current().id(){return (self.facts(Fault::Thread),None)}
        if !self.prepared||self.native.as_ref().is_none_or(|n|n.owner()!=r.owner){return (self.facts(Fault::Owner),None)}
        if self.bridge_unknown||self.finality_unknown{return (self.facts(Fault::NativeUnknown),None)}
        if self.normal_unknown&&!op.independent_finality_kind(){return (self.facts(Fault::NativeUnknown),None)}
        if self.native.as_ref().is_none_or(|n|!n.bridge_callable()) {
            self.poison();return (self.facts(Fault::NativeUnknown),None)
        }
        if let Err(e)=r.operands(op,input){return (self.facts(e),None)}
        // The native owner selects and consumes one exact immutable claim
        // BEFORE these counters advance. Global spare calls are corroboration,
        // not a fallback quota and not authority to borrow another cause's work.
        let admission=self.native.as_mut().ok_or(Fault::Owner).and_then(|n|n.bridge_admit(r,input));
        let lane=match admission{
            Ok(lane) if lane<3=>lane,
            Ok(_)=>{self.poison();return (self.facts(Fault::NativeUnknown),None)},
            Err(e)=>{
                if let Some(n)=self.native.as_mut(){n.bridge_abandon_admission(e);}
                return (self.facts(e),None)
            },
        };
        let index=usize::from(lane==2);
        if let Err(e)=self.budget(lane) {
            if let Some(n)=self.native.as_mut(){n.bridge_abandon_admission(e);}
            return (self.facts(e),None)
        }
        if self.frames[index].phase>=3 {
            if let Some(n)=self.native.as_mut(){n.bridge_abandon_admission(Fault::NativeUnknown);}
            self.poison();return (self.facts(Fault::NativeUnknown),None)
        }
        self.sequence+=1;
        {let f=self.frame_mut(index);f.request=r;f.input[..input.len()].copy_from_slice(input);f.phase=1;}
        let mut result={
            let (native,frames)=(&mut self.native,&mut self.frames);
            let f=unsafe{frames[index].as_mut().get_unchecked_mut()};
            // Strong owner and original frame were installed before this call.
            native.as_mut().expect("admitted original Notes owner").call(r,
                &f.input[..r.input_len as usize],&mut f.output[..r.output_capacity as usize])
        };
        result.sequence=self.sequence;self.frame_mut(index).receipt=result;
        // Retain irreversible native header bits BEFORE any payload validation.
        let previous_terminal=self.terminal;
        self.terminal|=result.flags&(flags::COMMITTED|flags::ROLLED_BACK);
        if !valid_reply(r,op,&result,&self.frames[index].output,previous_terminal) {
            self.frame_mut(index).phase=4;self.poison();return (self.facts(Fault::NativeUnknown),None)
        }
        self.frame_mut(index).phase=2;self.last=result;
        if result.status==Status::Unknown as u32 {
            // Fully returned native UNKNOWN is not bridge-frame loss. Preserve
            // this exact frame; only the preowned finality frame can follow it.
            if index==0{self.normal_unknown=true;self.frame_mut(index).phase=3;}
            else if result.flags&flags::PRIMITIVES_ENTERED!=0 {
                self.finality_unknown=true;self.frame_mut(index).phase=3;
            }
        }
        (result,Some(index))
    }
}
fn valid_reply(request:Request,op:Op,r:&Reply,bytes:&[u8],terminal:u32)->bool {
    if r.size!=80||r.version!=1||r.owner==0||r.reserved!=[0;3]||
        r.output_len as usize>request.output_capacity as usize||r.output_len as usize>bytes.len()||
        r.flags&!flags::ALL!=0||r.flags&flags::BRIDGE_FRAME_UNKNOWN!=0||
        r.flags&terminal!=terminal||r.status>5||
        (r.flags&flags::ALL_ENTERED_RETURNED!=0&&r.flags&flags::PRIMITIVES_ENTERED==0) {return false}
    if op!=Op::PrepareLease&&r.owner!=request.owner{return false}
    let failed=matches!(r.status,2..=4);
    if failed!=matches!(r.error,1..=16|18|19|32..=36){return false}
    if !failed&&r.error!=0{return false}
    if !matches!(r.first_failure,0..=16|18|19|32..=36){return false}
    let new_terminal=(r.flags&(flags::COMMITTED|flags::ROLLED_BACK))&!terminal;
    if new_terminal!=0&&(op!=Op::FinishMove||r.status!=0||r.output_len<8||r.count<2){return false}
    let out=&bytes[..r.output_len as usize];
    if failed {
        if out.is_empty(){return r.token==0&&r.count==0&&r.total==0}
        return r.status!=2&&op.primary_effect()&&out.len()==80&&r.count==1&&r.total==1&&
            r.token==(if op==Op::CreatePrivate{0}else{request.a})&&
            out.get(..8)==Some(b"MRKNEF1\0".as_slice())&&
            out.get(8..12)==Some(80u32.to_le_bytes().as_slice())&&
            out.get(16..24)==Some(r.owner.to_le_bytes().as_slice());
    }
    if r.status==1{return matches!(op,Op::ReadNext|Op::RosterNext)&&out.is_empty()&&r.count==0}
    if r.status==5{return op==Op::Move&&out.len()==80&&r.count==1&&r.total==1}
    if matches!(op,Op::PrepareLease|Op::EnterScope|Op::FreezeFixed|Op::FreezeVersion|Op::FreezeSelected|Op::FreezeApply) {
        return out.len()==128&&r.count==1&&r.total==1&&r.token!=0&&out.get(..8)==Some(b"MRKNFG1\0".as_slice())
    }
    if matches!(op,Op::SourceObservation|Op::RecheckSource|Op::CheckEpoch|Op::FinishMove|Op::FinishSecurity|Op::RosterNext) {
        if out.len()<8{return false}
        let count=u32::from_le_bytes([out[0],out[1],out[2],out[3]]);
        let extent=u32::from_le_bytes([out[4],out[5],out[6],out[7]]);
        return count==r.count&&extent as usize==out.len();
    }
    true
}
struct State {attempted:bool,fatal:bool,owner:Option<Box<Owner>>}
static SLOT:Mutex<State>=Mutex::new(State{attempted:false,fatal:false,owner:None});
static FATAL:AtomicBool=AtomicBool::new(false);
fn poison(state:&mut State) {
    state.fatal=true;FATAL.store(true,Ordering::Release);
    if let Some(owner)=state.owner.as_mut(){owner.poison();}
}
fn perform(state:&mut State,r:Request,op:Op,input:&[u8],output:&mut [u8])->Reply {
    if state.fatal {return state.owner.as_ref().map_or_else(||bare(Status::Unknown,Some(Fault::NativeUnknown)),|o|o.facts(Fault::NativeUnknown))}
    if op==Op::PrepareLease {
        if state.attempted{return state.owner.as_ref().map_or_else(||bare(Status::Refused,Some(Fault::OneUse)),|o|o.facts(Fault::OneUse))}
        state.attempted=true;
        match Owner::new(){Ok(owner)=>state.owner=Some(owner),Err(e)=>return bare(Status::Refused,Some(e))}
        let owner=state.owner.as_mut().expect("installed Notes bridge owner");let result=owner.prepare(r,input);
        if result.output_len!=0&&result.output_len as usize<=output.len() {
            output[..result.output_len as usize].copy_from_slice(&owner.frames[0].output[..result.output_len as usize]);
        }
        return result
    }
    let Some(owner)=state.owner.as_mut()else{return bare(Status::Refused,Some(Fault::Owner))};
    let (result,index)=owner.run(r,op,input);
    if let Some(index)=index {
        output[..result.output_len as usize].copy_from_slice(&owner.frames[index].output[..result.output_len as usize]);
    }
    result
}
fn range(address:usize,bytes:usize)->Result<(usize,usize)> {
    if address==0||bytes==0{return Err(Fault::Wire)}
    Ok((address,address.checked_add(bytes).ok_or(Fault::Bounds)?))
}
fn disjoint(ranges:&[(usize,usize)])->bool {
    ranges.iter().enumerate().all(|(i,a)|ranges.iter().skip(i+1).all(|b|a.1<=b.0||b.1<=a.0))
}
unsafe fn boundary(request:*const Request,input:*const u8,response:*mut Reply,output:*mut u8)->u32 {
    if FATAL.load(Ordering::Acquire){return Status::Unknown as u32}
    if (request as usize)%align_of::<Request>()!=0||(response as usize)%align_of::<Reply>()!=0{return Status::Refused as u32}
    let (Ok(req),Ok(rep))=(range(request as usize,size_of::<Request>()),range(response as usize,size_of::<Reply>()))else{return Status::Refused as u32};
    if !disjoint(&[req,rep]){return Status::Refused as u32}
    // SAFETY: fixed trusted caller supplies live Request/Reply storage.
    let r=unsafe{request.read()};
    let op=match r.header(r.input_len as usize,r.output_capacity as usize) {
        Ok(op)=>op,Err(e)=>{unsafe{response.write(bare(Status::Refused,Some(e)))};return Status::Refused as u32}
    };
    let mut ranges=[req,rep,(0,0),(0,0)];let mut count=2;
    for (ptr,n) in [(input as usize,r.input_len as usize),(output as usize,r.output_capacity as usize)] {
        if n!=0{let Ok(v)=range(ptr,n)else{return Status::Refused as u32};ranges[count]=v;count+=1;}
    }
    if !disjoint(&ranges[..count]){return Status::Refused as u32}
    let mut state=match SLOT.try_lock() {
        Ok(state)=>state,
        Err(TryLockError::WouldBlock)=>{unsafe{response.write(bare(Status::Refused,Some(Fault::Busy)))};return Status::Refused as u32},
        Err(TryLockError::Poisoned(p))=>{let mut state=p.into_inner();poison(&mut state);return Status::Unknown as u32},
    };
    if FATAL.load(Ordering::Acquire)||state.fatal{poison(&mut state);return Status::Unknown as u32}
    let input=if r.input_len==0{&[][..]}else{unsafe{std::slice::from_raw_parts(input,r.input_len as usize)}};
    let output=if r.output_capacity==0{&mut [][..]}else{unsafe{std::slice::from_raw_parts_mut(output,r.output_capacity as usize)}};
    let result=match catch_unwind(AssertUnwindSafe(||perform(&mut state,r,op,input,output))) {
        Ok(result)=>result,
        Err(payload)=>{poison(&mut state);std::mem::forget(payload);
            state.owner.as_ref().map_or_else(||bare(Status::Unknown,Some(Fault::NativeUnknown)),|o|o.facts(Fault::NativeUnknown))},
    };
    unsafe{response.write(result)};result.status
}
/// Fixed layout DATA only; no native acquisition.
/// # Safety
/// output is a live aligned writable Info of exactly 320 bytes.
#[no_mangle]
pub unsafe extern "system" fn mrk_notes_v1_info(output:*mut Info,bytes:u32)->u32 {
    if FATAL.load(Ordering::Acquire){return Status::Unknown as u32}
    if output.is_null()||bytes as usize!=size_of::<Info>()||(output as usize)%align_of::<Info>()!=0{return Status::Refused as u32}
    match catch_unwind(AssertUnwindSafe(||{unsafe{output.write(wire::info())};Status::Ok as u32})) {
        Ok(status)=>status,Err(payload)=>{FATAL.store(true,Ordering::Release);std::mem::forget(payload);Status::Unknown as u32}
    }
}
/// Closed Notes operations1..42. The caller retains the DLL and all originals
/// through synchronous return and positive ownership settlement; UNKNOWN is not
/// permission to unload, reopen, retry or replace an owner.
/// # Safety
/// Request/Reply are live aligned distinct values; input/output extents match
/// Request and are live, disjoint, and retained for this synchronous call.
#[no_mangle]
pub unsafe extern "system" fn mrk_notes_v1_call(request:*const Request,input:*const u8,response:*mut Reply,output:*mut u8)->u32 {
    match catch_unwind(AssertUnwindSafe(||unsafe{boundary(request,input,response,output)})) {
        Ok(status)=>status,Err(payload)=>{
            FATAL.store(true,Ordering::Release);std::mem::forget(payload);
            if let Ok(mut state)=SLOT.try_lock(){poison(&mut state);}Status::Unknown as u32
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]fn bridge_has_two_independent_bounded_original_frames() {
        let o=Owner::new().unwrap();
        assert_eq!(o.frames.len(),2);assert!(!o.prepared);assert_eq!(o.sequence,0);
        assert!(o.native.is_none());assert_eq!(o.used,[0;3]);
    }
    #[test]fn actual_zero_row_roster_progress_is_not_eof() {
        let request=Request{operation:13,owner:7,output_capacity:65536,..Request::default()};
        let r=Reply{owner:7,output_len:8,..bare(Status::Ok,None)};
        assert!(valid_reply(request,Op::RosterNext,&r,&[0,0,0,0,8,0,0,0],0));
        let eof=Reply{status:1,output_len:0,..r};
        assert!(valid_reply(request,Op::RosterNext,&eof,&[],0));
    }
}
