//! Actual Client/resident transport only; no ServiceManager/SM approval scope.
use nix::libc;
use std::{mem::ManuallyDrop,sync::Arc,time::Duration};
use crate::{android_maintenance_client::{Client,Drain,Progress},android_registration::{Signal,Bounds},
    android_maintenance_wire as wire,e2_fixture_diagnostic::Buffer,vault_helper_wire::uptime};
fn retain()->!{loop{std::thread::park_timeout(Duration::from_secs(1));}}
fn publish(client:Option<&Client>,checkpoint:&str){
    let value=client.map(Client::diagnostic).unwrap_or_default();
    let Some(out)=Buffer::encode_at("transport-only",client.is_some(),checkpoint,value,client.and_then(Client::fixture_cached_native_diagnostic))else{retain();};
    let name=b"maintenance-diagnostic-transport-only.json\0";
    let fd=unsafe{libc::open(name.as_ptr().cast(),libc::O_WRONLY|libc::O_CREAT|libc::O_EXCL|libc::O_NOFOLLOW|libc::O_CLOEXEC,0o600)};
    if fd<0{retain();}
    let written=unsafe{libc::write(fd,out.bytes.as_ptr().cast(),out.used)};
    if unsafe{libc::close(fd)}!=0{retain();}
    if written<0 || written as usize!=out.used{retain();}
}
fn attempt(client:&mut Client)->&'static str{
    let mut checkpoint="transport-error";
    match client.begin(){
        Ok(Drain::Started)=>loop{
            match client.step(){
                Ok(Progress::Pending)=>std::thread::park_timeout(Duration::from_millis(2)),
                Ok(Progress::TailReceived)=>{checkpoint="tail-received";break;},
                Ok(Progress::Exited)=>{checkpoint="peer-exited";break;},
                Err(_)=>break,
            }
        },
        Ok(Drain::Busy)|Ok(Drain::Refused)=>checkpoint="drain-refused",
        Err(_)=>{},
    }
    checkpoint
}
fn worker()->!{
    let Some(origin)=uptime()else{retain();};
    let signal=Arc::new(Signal::reserved());
    let Some(work)=origin.checked_add(wire::WORK_NS)else{retain();};
    let Some(hard)=origin.checked_add(wire::HARD_NS)else{retain();};
    if signal.arm(Bounds{origin,work,hard}).is_err(){retain();}
    let Some(client)=Client::new(signal,[0x44;16])else{publish(None,"client-unavailable");retain();};
    // The original is retained even when bootstrap retirement later ends the
    // disposable process. No failed/partial Client is automatically dropped.
    let mut client=ManuallyDrop::new(client);
    let checkpoint=match std::panic::catch_unwind(std::panic::AssertUnwindSafe(||attempt(&mut client))){
        Ok(checkpoint)=>checkpoint,
        Err(payload)=>{
            let _payload=ManuallyDrop::new(payload);
            publish(Some(&client),"transport-error");
            retain();
        },
    };
    publish(Some(&client),checkpoint);
    // Native output is not a join, tail admission, unregister, EOF or NOTE_EXIT
    // proof. Keep all originals until the existing fixture process owner ends
    // its one315s transport-only observation and retires this disposable group.
    retain()
}
pub fn enter()->!{
    if unsafe{libc::getuid()}==0 || unsafe{libc::getuid()}!=unsafe{libc::geteuid()}{retain();}
    std::panic::set_hook(Box::new(|_|{}));
    let worker=std::thread::Builder::new().stack_size(2*1024*1024).spawn(||worker());
    let mut worker=ManuallyDrop::new(worker);
    if let Ok(handle)=&mut *worker{let _=handle.thread().id();}
    retain()
}
