//! Fixed returning resident image; never a second CLI/scheduler.
#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(not(all(target_os="macos",target_arch="aarch64")))]
compile_error!("the resident image requires native macOS ARM64");
#[cfg(not(panic="unwind"))]
compile_error!("the image boundary requires contained unwinding");
use mrk_macos_installed_native::installed_image::{self,Host,Return};
/// # Safety
/// Only the fixed facade may call this symbol with the live disjoint ABI cells.
#[no_mangle]
pub unsafe extern "C" fn mrk_resident_image_entry_v1(host:*const Host,out:*mut Return)->i32{
    let result=std::panic::catch_unwind(||unsafe{
        installed_image::enter(host,out,mobile_release_desktop::android_registration_helper::run_image)
    });
    match result{Ok(code)=>code,Err(payload)=>{
        // Unknown native/Data originals remain charged and mapped. Dropping an
        // arbitrary panic payload may unwind again; never cross the C boundary.
        let _retained=std::mem::ManuallyDrop::new(payload);
        loop{std::thread::park_timeout(std::time::Duration::from_secs(1));}
    }}
}
