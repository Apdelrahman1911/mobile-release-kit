//! One private facade/image boundary. Host function custody stays in the native
//! book; the Registry receives only its immutable identity DATA.
use crate::{android_maintenance_wire::{Binding,Identity,Tail},android_service_resident::ResidentReturn,
    vault_helper_wire::uptime};
use std::mem::{align_of,size_of,ManuallyDrop};

pub type TakeRead=unsafe extern "C" fn(*const Binding,*mut i32)->i32;
#[repr(C)]
pub struct Host {
    version:u32,bytes:u32,role:u32,reserved:u32,instance:[u8;16],
    source:[u8;40],release:[u8;64],target:[u8;24],take_read:Option<TakeRead>,
}
#[repr(C)]
pub struct Return {
    version:u32,bytes:u32,kind:u32,reserved:u32,binding:Binding,
    ceiling:u64,retirement:u64,first:u64,cutoff:u64,returned_at:u64,last:u64,
}
const _:()=assert!(size_of::<Host>()==168 && size_of::<Return>()==320);
/// No safe constructor and no Clone. The fixed facade is its only provider.
pub struct AdmittedHost { host:Host }
impl AdmittedHost {
    pub fn identity(&self)->Identity{Identity{instance:self.host.instance,source:self.host.source,
        release:self.host.release,target:self.host.target}}
    pub(crate) fn pointer(&self)->*const Host{&self.host}
}
fn storage_separate(host:usize,out:usize)->bool{
    host!=0 && out!=0 && host%align_of::<Host>()==0 && out%align_of::<Return>()==0
        && host.checked_add(size_of::<Host>()).zip(out.checked_add(size_of::<Return>()))
            .is_some_and(|(a,b)|a<=out || b<=host)
}
/// # Safety
/// Called by the fixed C facade only: host points to its live immutable168B
/// original, and out to disjoint live writable320B zeroed output for this call.
/// Pointer arithmetic checks are not a substitute for that caller obligation.
pub unsafe fn enter(host:*const Host,out:*mut Return,run:impl FnOnce(AdmittedHost)->Option<ResidentReturn>)->i32{
    if !crate::RESIDENT_IMAGE_BUILD || !storage_separate(host as usize,out as usize){return 1;}
    let h=unsafe{&*host};
    let Some(expected)=Identity::build()else{return 1;};
    let identity=Identity{instance:h.instance,source:h.source,release:h.release,target:h.target};
    if h.version!=1 || h.bytes!=168 || h.role!=2 || h.reserved!=0 || h.take_read.is_none()
        || !identity.valid() || !identity.same_build(expected){return 1;}
    let output_bytes=unsafe{std::slice::from_raw_parts(out.cast::<u8>(),size_of::<Return>())};
    if output_bytes.iter().any(|byte|*byte!=0){return 1;}
    let admitted=AdmittedHost{host:Host{version:h.version,bytes:h.bytes,role:h.role,reserved:h.reserved,
        instance:h.instance,source:h.source,release:h.release,target:h.target,take_read:h.take_read}};
    let Some(returned)=run(admitted)else{return 1;};
    // This consuming adapter alone can inspect the private actual R return.
    let mut original=ManuallyDrop::new(returned);
    let Some((binding,window,last,returned_at))=original.image_data()else{return 1;};
    let now=uptime().unwrap_or(0);
    let Some(cutoff)=window.cutoff()else{return 1;};
    let tail=Tail{ceiling:window.ceiling,retirement:window.retirement.unwrap_or(0),
        first:window.first.unwrap_or(0),cutoff,returned_at,last,write_entered:now};
    if !binding.identity().valid() || binding.identity()!=identity || !tail.valid(binding)
        || window.unknown || window.clock_unknown || now<returned_at || !window.admits(now,true){return 1;}
    let output=Return{version:1,bytes:320,kind:1,reserved:0,binding,ceiling:window.ceiling,
        retirement:tail.retirement,first:tail.first,cutoff,returned_at,last};
    // SAFETY: facade supplies live disjoint output; all fields initialized and
    // no native resource/pointer crosses. The actual owning return is consumed.
    unsafe{std::ptr::write(out,output);ManuallyDrop::drop(&mut original);}0
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn abi_sizes_and_disjoint_original_storage_are_mandatory(){
        assert!(!storage_separate(0,512));assert!(!storage_separate(256,256));
        assert!(!storage_separate(256,400));assert!(!storage_separate(257,1024));
        assert!(storage_separate(256,1024));assert!(!storage_separate(usize::MAX-7,256));
    }
}
