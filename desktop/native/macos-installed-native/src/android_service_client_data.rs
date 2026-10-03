//! Same-original client request DATA. Foundation may retain no-copy backing
//! after a synchronous reply; that fact never permits an extra request arena.
//! Native objects/books/handles are deliberately absent from this Arc graph.
use std::{cell::UnsafeCell, ffi::{c_int,c_void}, mem::ManuallyDrop, sync::Arc};
use crate::{android_registration,android_catalog_query,android_service_lease::BackingLease};
pub(crate) const REQUEST_BYTES: usize = 65_536;
enum SignalData {
    Registration(Arc<android_registration::Signal>),
    Query(Arc<android_catalog_query::Signal>),
}
pub(crate) struct ClientData {
    signal: SignalData, lease: BackingLease,
    request: UnsafeCell<Box<[u8; REQUEST_BYTES]>>,
}
// SAFETY: request is private; the only writer acquires a unique generation in
// BackingLease before copying on the original client thread. No reader receives
// its pointer except the admitted no-copy NSData until its documented backing
// relinquishment, original native returns AND borrow end. Failed proof never
// reuses it. All other state is immutable or atomic, and every native borrower
// retains this same Arc (never a raw unowned buffer).
unsafe impl Sync for ClientData {}
impl ClientData {
    pub(crate) fn registration(signal:Arc<android_registration::Signal>)->Self{
        Self{signal:SignalData::Registration(signal),lease:BackingLease::reserved(),request:UnsafeCell::new(Box::new([0;REQUEST_BYTES]))}
    }
    pub(crate) fn query(signal:Arc<android_catalog_query::Signal>)->Self{
        Self{signal:SignalData::Query(signal),lease:BackingLease::reserved(),request:UnsafeCell::new(Box::new([0;REQUEST_BYTES]))}
    }
    fn failure_at(&self,first:u64,unknown:bool){
        match &self.signal{SignalData::Registration(signal)=>signal.failure_at(first,unknown),
            SignalData::Query(signal)=>signal.failure_at(first,unknown)}
    }
    fn failure_now(&self,unknown:bool){
        match &self.signal{SignalData::Registration(signal)=>signal.failure_now(unknown),
            SignalData::Query(signal)=>signal.failure_now(unknown)}
    }
    fn admitted(&self,cleanup:bool)->bool{
        match &self.signal{SignalData::Registration(signal)=>signal.admitted(cleanup),
            SignalData::Query(signal)=>signal.admitted(cleanup)}
    }
    pub(crate) fn idle_known(&self)->bool{self.lease.idle_known()}
    pub(crate) fn uncertain(&self)->bool{self.lease.is_unknown()}
}
/// No automatic destructor drops uncertain original callback DATA. Even a last
/// producer's newly observed Unknown AFTER exclusivity remains owned/charged.
pub(crate) enum DataOwner {
    Shared(ManuallyDrop<Arc<ClientData>>),
    ExclusiveUnknown(ManuallyDrop<ClientData>),
    Retired,
}
impl DataOwner {
    pub(crate) fn new(data:ClientData)->Self{Self::Shared(ManuallyDrop::new(Arc::new(data)))}
    pub(crate) fn pointer(&self)->*const c_void{
        match self{Self::Shared(held)=>Arc::as_ptr(held).cast(),_=>std::ptr::null()}
    }
    pub(crate) fn idle_known(&self)->bool{
        match self{Self::Shared(held)=>held.idle_known(),Self::Retired=>true,_=>false}
    }
    pub(crate) fn uncertain(&self)->bool{
        match self{Self::Shared(held)=>held.uncertain(),Self::Retired=>false,_=>true}
    }
    /// Only after actual original native retirement return; never strong_count.
    /// A failed unwrap keeps the identical Arc, not a reconstructed context.
    pub(crate) fn settle(&mut self)->bool{
        if matches!(self,Self::Retired){return true;}
        if !self.idle_known(){return false;}
        let original=std::mem::replace(self,Self::Retired);
        match original{
            Self::Shared(held)=>match Arc::try_unwrap(ManuallyDrop::into_inner(held)){
                Ok(data) if data.idle_known()=>true,
                Ok(data)=>{*self=Self::ExclusiveUnknown(ManuallyDrop::new(data));false},
                Err(held)=>{*self=Self::Shared(ManuallyDrop::new(held));false},
            },
            other=>{*self=other;false},
        }
    }
}
#[repr(C)]
pub(crate) struct Api {
    pub(crate) retain:unsafe extern "C" fn(*const c_void)->*const c_void,
    pub(crate) release:unsafe extern "C" fn(*const c_void),
    pub(crate) acquire:unsafe extern "C" fn(*const c_void,*const u8,usize,*mut u64,*mut *mut u8)->c_int,
    pub(crate) backing:unsafe extern "C" fn(*const c_void,u64),
    pub(crate) finish:unsafe extern "C" fn(*const c_void,u64,u32),
    pub(crate) idle:unsafe extern "C" fn(*const c_void)->c_int,
}
pub(crate) static API:Api=Api{retain,release,acquire,backing,finish,idle};
unsafe extern "C" fn retain(context:*const c_void)->*const c_void{
    if context.is_null(){return std::ptr::null();}
    // SAFETY: native caller already holds the same Arc throughout this borrow.
    unsafe{Arc::increment_strong_count(context.cast::<ClientData>());}context
}
unsafe extern "C" fn release(context:*const c_void){
    if !context.is_null(){
        // SAFETY: consumes precisely one prior retain. No use follows this drop.
        unsafe{drop(Arc::from_raw(context.cast::<ClientData>()));}
    }
}
pub(crate) unsafe extern "C" fn notify(context:*const c_void,first:u64,unknown:u32){
    if let Some(data)=unsafe{context.cast::<ClientData>().as_ref()}{data.failure_at(first,unknown!=0);}
}
pub(crate) unsafe extern "C" fn admit(context:*const c_void,cleanup:u32)->u32{
    if cleanup>1{return 0;}
    unsafe{context.cast::<ClientData>().as_ref()}.map_or(0,|data|u32::from(data.admitted(cleanup==1)))
}
unsafe extern "C" fn acquire(context:*const c_void,input:*const u8,count:usize,ticket:*mut u64,arena:*mut *mut u8)->c_int{
    if context.is_null() || input.is_null() || ticket.is_null() || arena.is_null() || count==0 || count>REQUEST_BYTES{return 0;}
    let data=unsafe{&*context.cast::<ClientData>()};
    let Some(generation)=data.lease.claim()else{data.failure_now(data.lease.is_unknown());return 0;};
    // SAFETY: exclusive original lease obtained before the copy. Caller supplies
    // count valid input bytes and writable scalar outputs; source and arena are
    // distinct. Buffer stays immutable until ALL lease retirement facts exist.
    unsafe{
        let target=(*data.request.get()).as_mut_ptr();
        std::ptr::copy_nonoverlapping(input,target,count);*ticket=generation;*arena=target;
    }1
}
unsafe extern "C" fn backing(context:*const c_void,ticket:u64){
    if let Some(data)=unsafe{context.cast::<ClientData>().as_ref()}{
        if !data.lease.backing_relinquished(ticket){data.failure_now(true);}
    }
}
unsafe extern "C" fn finish(context:*const c_void,ticket:u64,known:u32){
    if let Some(data)=unsafe{context.cast::<ClientData>().as_ref()}{
        if known>1 || !data.lease.original_returns(ticket,known==1) || !data.lease.borrow_ended(ticket){
            data.lease.unknown();data.failure_now(true);
        }
    }
}
unsafe extern "C" fn idle(context:*const c_void)->c_int{
    unsafe{context.cast::<ClientData>().as_ref()}.map_or(0,|data|i32::from(data.idle_known()))
}
