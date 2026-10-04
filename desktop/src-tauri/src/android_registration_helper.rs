//! Fixed resident Android service: one protected payload, eight live contexts.
//! Native callbacks own only immutable context DATA. The resident original
//! supervisor owns native control and actual coordinator handles; each original
//! coordinator joins its same payload worker before terminal publication.
#![forbid(unsafe_code)]
use std::{mem::ManuallyDrop,sync::{Arc,Mutex,atomic::{AtomicU8,Ordering}},
    thread::{self,JoinHandle},time::Duration};
use mrk_macos_installed_native::{
    android_registration::TERMINAL_BYTES,
    android_service_control::LIVE_CONTEXTS,
    android_service_resident::{ServiceBook,ServiceControl,ServiceRegistry,ServiceDomain,ServiceRole,
        NativeReturn,SupervisorReturn,ResidentReturn,PumpReturn,SUPERVISOR_STACK,PAYLOAD_STACK,COORDINATOR_STACK},
};
use crate::android_registration_publisher::{Publisher,WorkerEnd};
use crate::android_catalog_query_helper::{QueryReader,QueryWorkerEnd};

const CLOSED:u8=0;
const GO:u8=1;
const ABORT:u8=2;
struct Barrier(AtomicU8);
impl Barrier{
    fn reserved()->Self{Self(AtomicU8::new(CLOSED))}
    fn publish(&self)->bool{self.0.compare_exchange(CLOSED,GO,Ordering::SeqCst,Ordering::SeqCst).is_ok()}
    fn abort(&self){let _=self.0.compare_exchange(CLOSED,ABORT,Ordering::SeqCst,Ordering::SeqCst);}
    fn enter(&self,domain:&ServiceDomain)->bool{
        loop{
            match self.0.load(Ordering::SeqCst){GO=>return true,ABORT=>return false,_=>{}}
            if !domain.work_admitted(){self.abort();return false;}
            thread::park_timeout(Duration::from_millis(2));
        }
    }
}
struct Startup{bound:AtomicU8,command:Barrier}
impl Startup{fn reserved()->Self{Self{bound:AtomicU8::new(0),command:Barrier::reserved()}}}
enum Payload{Registration(Box<Publisher>),Query(Box<QueryReader>)}
impl Payload{
    fn reserve(domain:&ServiceDomain,cap:usize)->Option<Self>{
        match domain.role()?{
            ServiceRole::Registration=>{
                let mut original=Box::new(Publisher::new(domain.registration().clone()));
                original.service_precharge(cap).ok()?;Some(Self::Registration(original))
            }
            ServiceRole::ReadOnlyQuery=>{
                let mut original=Box::new(QueryReader::new(domain.query().clone()));
                original.service_precharge(cap).ok()?;Some(Self::Query(original))
            }
        }
    }
    fn run(&mut self)->WorkerReturn{
        match self{Self::Registration(original)=>WorkerReturn::Produced(original.run()),
            Self::Query(original)=>WorkerReturn::Queried(original.run())}
    }
}
enum WorkerReturn{Unentered,Produced(WorkerEnd),Queried(QueryWorkerEnd),Lost}
struct OriginalWorker{handle:Option<ManuallyDrop<JoinHandle<WorkerReturn>>>,joined:bool}
struct PayloadInputs{payload:Arc<Mutex<Payload>>,go:Arc<Barrier>,domain:Arc<ServiceDomain>}
struct CoordinatorInputs{worker:Arc<Mutex<OriginalWorker>>,go:Arc<Barrier>,domain:Arc<ServiceDomain>}
/// Private in-process DATA. Only actual JoinHandle::join may obtain this value.
struct CoordinatorEnd{number:u64,payload_known:bool}
struct Transaction{
    domain:ManuallyDrop<Arc<ServiceDomain>>,payload:ManuallyDrop<Arc<Mutex<Payload>>>,
    worker:ManuallyDrop<Arc<Mutex<OriginalWorker>>>,go:ManuallyDrop<Arc<Barrier>>,
    coordinator:Option<ManuallyDrop<JoinHandle<CoordinatorEnd>>>,
    unpublished_worker:Option<ManuallyDrop<JoinHandle<WorkerReturn>>>,
    setup_failed:bool,coordinator_joined:bool,disposable:bool,
}
fn unknown_data()->[u8;TERMINAL_BYTES]{
    crate::android_registration_protocol::terminal::TerminalCandidate::unknown_bytes()
}
/// Independent original W/F/H watch: no payload/FD/native book lock.
fn watch_payload(domain:&ServiceDomain)->bool{
    match domain.role(){
        Some(ServiceRole::Registration)=>{
            let signal=domain.registration().signal();let _=signal.admitted(false);
            if signal.admitted(true){return true;}
            domain.registration().stop_new_input();
            match signal.cleanup(){Some(end)=>signal.failure_at(end,true),None=>signal.clock_unknown()}
        }
        Some(ServiceRole::ReadOnlyQuery)=>{
            let signal=domain.query().signal();
            if !domain.query().input_settled(){let _=signal.admitted(false);}
            if signal.admitted(true){return true;}
            domain.query().stop_new_input();
            match signal.snapshot().cleanup{Some(end)=>signal.failure_at(end,true),None=>signal.clock_unknown()}
        }
        None=>domain.failure_now(true),
    }
    false
}
fn payload_worker(input:PayloadInputs)->WorkerReturn{
    if !input.go.enter(&input.domain){return WorkerReturn::Unentered;}
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
        // Only this original worker can lock/access these original payload books.
        match input.payload.lock(){Ok(mut original)=>original.run(),Err(_)=>WorkerReturn::Lost}
    })){
        Ok(result)=>result,Err(_)=>{input.domain.failure_now(true);WorkerReturn::Lost}
    }
}
fn coordinate(input:CoordinatorInputs)->CoordinatorEnd{
    let entered=input.go.enter(&input.domain);
    let result=loop{
        if entered{let _=watch_payload(&input.domain);}
        let finished=match input.worker.try_lock(){
            Ok(original)=>original.handle.as_ref().is_some_and(|handle|handle.is_finished()),
            Err(_)=>{input.domain.failure_now(true);false},
        };
        if !finished{thread::park_timeout(Duration::from_millis(2));continue;}
        // Never consume a late/unknown join and relabel it timely. Its SAME
        // original handle stays in the shared non-dropping custody on refusal.
        if !input.domain.join_entered(false){
            return CoordinatorEnd{number:input.domain.number(),payload_known:false};
        }
        let handle=match input.worker.try_lock(){
            Ok(mut original) if !original.joined=>original.handle.take(),
            _=>{input.domain.failure_now(true);None},
        };
        let Some(handle)=handle else{
            input.domain.failure_now(true);
            return CoordinatorEnd{number:input.domain.number(),payload_known:false};
        };
        let actual=ManuallyDrop::into_inner(handle).join();
        let timely=!entered || watch_payload(&input.domain);
        input.domain.join_returned(false,actual.is_ok() && timely);
        if let Ok(mut original)=input.worker.try_lock(){original.joined=true;}
        else{input.domain.failure_now(true);}
        break if timely{actual.ok()}else{None};
    };
    // Freeze/publish payload terminal BEFORE the control epilogue; the client's
    // terminal -> invalidate path therefore cannot wait for itself.
    let payload_known=match(result,input.domain.role()){
        (Some(WorkerReturn::Unentered),_) if !entered=>true, // local no-GO, no wire success/join fiction
        (Some(WorkerReturn::Produced(result)),Some(ServiceRole::Registration)) if entered=>{
            let published=input.domain.registration().publish_joined_terminal(&result.data,result.success,result.known).is_ok();
            result.known && published
        }
        (Some(WorkerReturn::Queried(result)),Some(ServiceRole::ReadOnlyQuery)) if entered=>{
            let published=input.domain.query().publish_joined(result.success,result.known);
            result.known && published
        }
        _=>{
            input.domain.failure_now(true);
            // No payload/FD/book access follows the moved original close tail.
            match input.domain.role(){
                Some(ServiceRole::Registration) if input.domain.registration().input_settled()=>{
                    let _=input.domain.registration().publish_joined_terminal(&unknown_data(),false,false);
                }
                Some(ServiceRole::ReadOnlyQuery) if input.domain.query().input_settled()=>{
                    let _=input.domain.query().publish_joined(false,false);
                }
                _=>{},
            }
            false
        }
    };
    input.domain.payload_settled(payload_known);
    // DATA-only epilogue. It cannot await a slot reset, DATA exclusivity,
    // response backing deallocation, or another original worker/coordinator.
    loop{
        match input.domain.native_return(){
            NativeReturn::Returned|NativeReturn::Unknown=>break,
            _=>{},
        }
        if !input.domain.watch(){input.domain.failure_now(true);break;}
        thread::park_timeout(Duration::from_millis(2));
    }
    CoordinatorEnd{number:input.domain.number(),payload_known}
}
impl Transaction{
    fn reserve(domain:Arc<ServiceDomain>,cap:usize)->Option<Self>{
        let payload=Payload::reserve(&domain,cap)?;
        Some(Self{domain:ManuallyDrop::new(domain),payload:ManuallyDrop::new(Arc::new(Mutex::new(payload))),
            worker:ManuallyDrop::new(Arc::new(Mutex::new(OriginalWorker{handle:None,joined:false}))),
            go:ManuallyDrop::new(Arc::new(Barrier::reserved())),coordinator:None,unpublished_worker:None,
            setup_failed:false,coordinator_joined:false,disposable:false})
    }
    fn fail_setup(&mut self,unknown:bool){self.setup_failed=true;self.go.abort();self.domain.setup_failed(unknown);}
    fn start(&mut self){
        if !self.domain.spawn_entered(false){self.fail_setup(false);return;}
        let input=PayloadInputs{payload:Arc::clone(&self.payload),go:Arc::clone(&self.go),domain:Arc::clone(&self.domain)};
        let spawned=thread::Builder::new().name("mrk-android-original".into()).stack_size(PAYLOAD_STACK)
            .spawn(move||payload_worker(input));
        self.domain.spawn_returned(false,spawned.is_ok());
        let worker=match spawned{Ok(handle)=>handle,Err(_)=>{self.fail_setup(false);return;}};
        // Before coordinator creation, only this supervisor can access this
        // fresh worker slot. Retain the actual handle even on unexpected poison.
        let stored=match self.worker.try_lock(){
            Ok(mut original)=>{original.handle=Some(ManuallyDrop::new(worker));true},
            Err(_)=>{self.unpublished_worker=Some(ManuallyDrop::new(worker));false},
        };
        if !stored{self.fail_setup(true);return;}
        if !self.domain.spawn_entered(true){self.fail_setup(false);return;}
        let input=CoordinatorInputs{worker:Arc::clone(&self.worker),go:Arc::clone(&self.go),domain:Arc::clone(&self.domain)};
        let spawned=thread::Builder::new().name("mrk-android-coordinator".into()).stack_size(COORDINATOR_STACK)
            .spawn(move||coordinate(input));
        self.domain.spawn_returned(true,spawned.is_ok());
        match spawned{Ok(handle)=>self.coordinator=Some(ManuallyDrop::new(handle)),Err(_)=>{self.fail_setup(false);return;}}
        // The fixed CAS and Ready publication share the ORIGINAL RegistrySlots
        // maintenance cut. No caller-supplied closure or native/spawn work is
        // invoked under that DATA guard; both original spawns already returned.
        if !self.domain.publish_go_and_ready(&self.go.0){self.fail_setup(false);}
    }
    fn poll(&mut self){
        if self.disposable{return;}
        if let Some(handle)=self.coordinator.as_ref(){
            if !handle.is_finished(){return;}
            if !self.domain.join_entered(true){return;}
            let Some(handle)=self.coordinator.take()else{self.domain.failure_now(true);return;};
            let actual=ManuallyDrop::into_inner(handle).join();
            let valid=actual.as_ref().is_ok_and(|end|end.number==self.domain.number());
            self.domain.join_returned(true,valid);
            self.coordinator_joined=true;
            let known=actual.is_ok_and(|end|end.number==self.domain.number() && end.payload_known);
            self.disposable=known && self.domain.release_payload_if_settled();
            return;
        }
        if !self.setup_failed || self.coordinator_joined{return;}
        // A coordinator spawn may positively fail. Only this supervisor then
        // joins the SAME original pre-GO worker; no replacement thread is made.
        let finished=self.unpublished_worker.as_ref().is_some_and(|handle|handle.is_finished())
            || self.worker.try_lock().is_ok_and(|original|original.handle.as_ref().is_some_and(|handle|handle.is_finished()));
        if !finished{
            if self.domain.no_payload_created(){
                self.domain.payload_settled(true);
                self.disposable=self.domain.release_payload_if_settled();
            }
            return;
        }
        if !self.domain.join_entered(false){return;}
        let handle=self.unpublished_worker.take().or_else(||self.worker.try_lock().ok().and_then(|mut original|original.handle.take()));
        let Some(handle)=handle else{self.domain.failure_now(true);return;};
        let actual=ManuallyDrop::into_inner(handle).join();
        let known=matches!(actual,Ok(WorkerReturn::Unentered));
        self.domain.join_returned(false,known);
        if let Ok(mut original)=self.worker.try_lock(){original.joined=true;}
        else{self.domain.failure_now(true);}
        self.domain.payload_settled(known);
        self.disposable=known && self.domain.release_payload_if_settled();
    }
    fn drop_settled(self){
        // Only after actual required joins and positive original payload/FD
        // settlement. No payload accessor/readback is added after a close tail.
        debug_assert!(self.disposable && self.coordinator.is_none() && self.unpublished_worker.is_none());
        drop(ManuallyDrop::into_inner(self.payload));
        drop(ManuallyDrop::into_inner(self.worker));
        drop(ManuallyDrop::into_inner(self.go));
        drop(ManuallyDrop::into_inner(self.domain));
    }
}
struct Supervisor{
    native:ServiceControl,registry:Arc<ServiceRegistry>,startup:Arc<Startup>,
    active:Option<ManuallyDrop<Transaction>>,
}
impl Supervisor{
    fn run(mut self)->SupervisorReturn{
        let bound=loop{
            if let Some(bound)=self.native.bind(){break bound;}
            self.registry.watch_maintenance();thread::park_timeout(Duration::from_millis(2));
        };
        if !bound{
            self.startup.bound.store(2,Ordering::SeqCst);
            // A failed/ambiguous original bind is not an owning control return.
            // Retain this supervisor, native borrow and DATA, never exit merely
            // because startup failed while originals may still exist.
            loop{self.registry.watch_maintenance();thread::park_timeout(Duration::from_millis(2));}
        }
        self.startup.bound.store(1,Ordering::SeqCst);
        let active=loop{
            match self.startup.command.0.load(Ordering::SeqCst){GO=>break true,ABORT=>break false,_=>{}}
            self.registry.watch_maintenance();thread::park_timeout(Duration::from_millis(2));
        };
        if !active{self.registry.close_admission();}
        loop{
            self.registry.watch_maintenance();self.native.progress_reclaim();
            for index in 0..LIVE_CONTEXTS{
                let Some(domain)=self.registry.context(index)else{continue;};
                let number=domain.number();
                if !active{domain.setup_failed(false);domain.retire_at(mrk_macos_installed_native::vault_helper_wire::uptime().unwrap_or(0));}
                let _=domain.watch();
                // Native owner consumes its own original references BEFORE
                // looking for any worker/coordinator join or DATA exclusivity.
                self.native.retire(&domain);
                if active{
                    if domain.take_setup().is_some(){
                        let cap=domain.role().and_then(|role|self.registry.payload_control_cap(role));
                        if self.active.is_some(){domain.setup_failed(true);}
                        else if let Some(transaction)=cap.and_then(|cap|Transaction::reserve(domain.clone(),cap)){
                            self.active=Some(ManuallyDrop::new(transaction));
                            if let Some(original)=self.active.as_mut(){original.start();}
                        }else{
                            // Explicit local construction NeverCreated. Client
                            // Pending remains Unknown, never TerminalNoWorker.
                            domain.setup_failed(false);
                        }
                    }
                }
                if let Some(transaction)=self.active.as_mut(){
                    if transaction.domain.number()==number{transaction.poll();}
                }
                let settled=self.active.as_ref().is_some_and(|transaction|transaction.domain.number()==number && transaction.disposable);
                if settled{
                    if let Some(transaction)=self.active.take(){ManuallyDrop::into_inner(transaction).drop_settled();}
                }else if self.active.as_ref().is_none_or(|transaction|transaction.domain.number()!=number)
                    && domain.no_payload_created(){
                    domain.payload_settled(true);let _=domain.release_payload_if_settled();
                }
                // The registry's SAME original Arc is all this call may unwrap;
                // all positively settled temporary/transaction holders are gone.
                drop(domain);self.native.reclaim(index,number);
            }
            if self.active.is_none() && self.registry.control_ready_to_return(){
                match self.native.retire_original(){
                    Ok(end)=>{
                        // The same consumed supervisor actually returns. All
                        // original payload/coordinator handles are already
                        // joined and their temporary DATA holders are gone.
                        drop(self.registry);drop(self.startup);return end;
                    }
                    Err(original)=>self.native=original,
                }
            }
            thread::park_timeout(Duration::from_millis(2));
        }
    }
}
struct MainCustody{
    native:ServiceBook,supervisor:Option<ManuallyDrop<JoinHandle<SupervisorReturn>>>,startup:Arc<Startup>,
}
fn arc_bytes<T>()->usize{
    #[repr(C)] struct Allocation<T>{counts:[usize;2],data:T}
    std::mem::size_of::<Allocation<T>>()
}
fn fixed_helper_bytes()->Option<usize>{
    // Typed supplied cells/captures, separately from runtime-private thread
    // machinery. Actual explicit stacks are charged by ServiceRegistry. Payload
    // boxes/capacity/transient storage belongs to the immutable role sublimit.
    [std::mem::size_of::<MainCustody>(),std::mem::size_of::<Supervisor>(),
        std::mem::size_of::<Transaction>(),arc_bytes::<Startup>(),arc_bytes::<Barrier>(),
        arc_bytes::<Mutex<OriginalWorker>>(),arc_bytes::<Mutex<Payload>>(),
        std::mem::size_of::<PayloadInputs>(),std::mem::size_of::<CoordinatorInputs>(),
        std::mem::size_of::<WorkerReturn>(),std::mem::size_of::<CoordinatorEnd>(),std::mem::size_of::<SupervisorReturn>()]
        .into_iter().try_fold(0_usize,usize::checked_add)
}
impl MainCustody{
    fn start()->Option<Self>{Self::start_bound(None)}
    fn start_bound(host:Option<mrk_macos_installed_native::installed_image::AdmittedHost>)->Option<Self>{
        // None is possible only before ANY native book/control original entry.
        let registry=if let Some(host)=host.as_ref(){ServiceRegistry::new_image(fixed_helper_bytes()?,host)?}
            else{ServiceRegistry::new(fixed_helper_bytes()?)?};
        let startup=Arc::new(Startup::reserved());
        let native=if let Some(host)=host{ServiceBook::new_image(registry.clone(),host)}else{ServiceBook::new(registry.clone())};
        let mut original=Self{native,supervisor:None,startup};
        let control=match original.native.reserve_control(){
            Ok(control)=>control,Err(_)=>{original.native.retain_unknown();return Some(original);}
        };
        let supervisor=ManuallyDrop::new(Supervisor{native:control,registry,startup:original.startup.clone(),active:None});
        let spawned=thread::Builder::new().name("mrk-android-resident".into()).stack_size(SUPERVISOR_STACK)
            .spawn(move||ManuallyDrop::into_inner(supervisor).run());
        match spawned{
            Ok(handle)=>original.supervisor=Some(ManuallyDrop::new(handle)),
            Err(_)=>{
                // The unstarted closure's ManuallyDrop retains its original
                // control/DATA custody. Do not return an error that exits this
                // process or recreate a supervisor around the same raw book.
                original.native.retain_unknown();return Some(original);
            }
        }
        loop{
            let bound=original.startup.bound.load(Ordering::SeqCst);
            if bound==1{break;}
            if bound==2 || original.supervisor.as_ref().is_some_and(|handle|handle.is_finished()){
                original.startup.command.abort();original.native.retain_unknown();return Some(original);
            }
            thread::park_timeout(Duration::from_millis(2));
        }
        loop{
            match original.native.begin(){
                Ok(true)=>break,
                Ok(false)=>thread::park_timeout(Duration::from_millis(2)), // original native call never entered
                Err(_)=>{original.startup.command.abort();original.native.retain_unknown();return Some(original);}
            }
        }
        if !original.startup.command.publish(){
            original.startup.command.abort();original.native.retain_unknown();
        }
        Some(original)
    }
    fn drive(mut self)->ResidentReturn{
        loop{
            self.native.advance_teardown();
            if self.supervisor.as_ref().is_some_and(|handle|handle.is_finished()){
                match self.native.ready_to_join(){
                    Some(true)=>{
                        if let Some(handle)=self.supervisor.take(){
                            // Readiness is advisory. Only the boundary method
                            // actually consumes/joins this SAME original handle.
                            if let Some(same)=self.native.join_original_supervisor(ManuallyDrop::into_inner(handle)){
                                self.supervisor=Some(ManuallyDrop::new(same)); // known no-entry contention only
                            }
                            self.native.advance_teardown();
                        }
                    }
                    Some(false)=>{
                        // Panic/unexpected return is not control retirement.
                        // Preserve the original handle/book and charge.
                        self.native.retain_unknown();
                    }
                    None=>{}, // contended DATA observation, not a join attempt
                }
            }
            if self.native.has_consumed_book(){
                match self.native.try_return(){
                    Ok(original)=>return original,
                    Err(same)=>self.native=same,
                }
            }
            // CFRunLoop Finished (no sources/timers) and Stopped can return
            // immediately. Reuse the EXISTING bounded park; never empty-loop
            // spin, dispatch_main, replacement watchdog, or recursive runloop.
            match self.native.pump_once(){
                PumpReturn::TimedOut|PumpReturn::HandledSource=>{},
                PumpReturn::Finished|PumpReturn::Stopped|PumpReturn::Unavailable=>
                    thread::park_timeout(Duration::from_millis(2)),
            }
        }
    }
}
/// Fixed daemon entrypoint only: no source path, tool name or generic command
/// comes from CLI/environment. Service Enabled alone is not a release result.
pub fn run()->i32{
    if std::env::args_os().take(2).count()!=1 || nix::unistd::getuid().as_raw()!=0
        || nix::unistd::geteuid().as_raw()!=0 || !mrk_macos_installed_native::ANDROID_REGISTRATION_HELPER_BUILD{return 2;}
    let Some(resident)=MainCustody::start()else{return 2;};
    resident.drive().into_exit_code()
}
/// Safe isolated image seam. The tiny native adapter validated the fixed host
/// BEFORE any book/thread entry; this reuses the same returning main owner.
#[cfg(feature="macos-installed-resident-image")]
pub fn run_image(host:mrk_macos_installed_native::installed_image::AdmittedHost)->Option<ResidentReturn>{
    if nix::unistd::getuid().as_raw()!=0 || nix::unistd::geteuid().as_raw()!=0
        || !mrk_macos_installed_native::RESIDENT_IMAGE_BUILD{return None;}
    Some(MainCustody::start_bound(Some(host))?.drive())
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn barrier_only_publishes_once_and_abort_never_reopens(){
        let barrier=Barrier::reserved();barrier.abort();assert!(!barrier.publish());
        assert_eq!(barrier.0.load(Ordering::SeqCst),ABORT);
        let barrier=Barrier::reserved();assert!(barrier.publish());assert!(!barrier.publish());
        barrier.abort();assert_eq!(barrier.0.load(Ordering::SeqCst),GO);
    }
    #[test]
    fn helper_fixed_cells_and_role_budget_are_admitted_as_one_aggregate(){
        let registry=ServiceRegistry::new(fixed_helper_bytes().unwrap()).unwrap();
        assert!(registry.payload_control_cap(ServiceRole::Registration).unwrap()<=32*1024*1024);
        assert!(registry.payload_control_cap(ServiceRole::ReadOnlyQuery).unwrap()<=2*1024*1024);
        assert!(ServiceRegistry::new(64*1024*1024).is_none());
    }
}
