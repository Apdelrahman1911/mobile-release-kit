//! Closed actual-UID account query for local history. No HOME, shell or lookup
//! by a caller-selected name. The containing Session owns the blocking call and
//! its original timeout/join; this object records entry/return, not cancellation.
use std::mem::MaybeUninit;
use nix::libc;
const SCRATCH:usize=16*1024;
const PATH:usize=4096;
pub struct Account {scratch:[u8;SCRATCH],path:[u8;PATH],length:usize,uid:u32,gid:u32,entered:bool,returned:bool,failed:bool}
impl Account {
    pub fn new()->Self{Self{scratch:[0;SCRATCH],path:[0;PATH],length:0,uid:0,gid:0,entered:false,returned:false,failed:false}}
    pub fn acquire(&mut self)->Result<(),()>{
        if self.entered{return Err(());}self.entered=true;
        let result=(||{
            let uid=crate::real_user().map_err(|_|())?;
            let gid=nix::unistd::getgid().as_raw();
            if uid==0 || nix::unistd::geteuid().as_raw()!=uid || nix::unistd::getegid().as_raw()!=gid{return Err(());}
            self.uid=uid;self.gid=gid;
            let mut value=MaybeUninit::<libc::passwd>::uninit();let mut matched=std::ptr::null_mut();
            // Same fixed16KiB getpwuid_r envelope and pointer-range validation
            // as wrapping_keychain account policy. No returned pointer escapes.
            let result=unsafe{libc::getpwuid_r(uid,value.as_mut_ptr(),self.scratch.as_mut_ptr().cast(),SCRATCH,&mut matched)};
            if result!=0 || matched!=value.as_mut_ptr(){return Err(());}
            let value=unsafe{value.assume_init()};
            if value.pw_uid!=uid || value.pw_dir.is_null(){return Err(());}
            let start=self.scratch.as_ptr() as usize;let address=value.pw_dir as usize;
            let offset=address.checked_sub(start).filter(|v|*v<SCRATCH).ok_or(())?;
            let tail=&self.scratch[offset..];let length=tail.iter().position(|b|*b==0).ok_or(())?;
            if !(2..PATH).contains(&length) || tail[0]!=b'/' || tail[length-1]==b'/'{return Err(());}
            let path=std::str::from_utf8(&tail[..length]).map_err(|_|())?;
            if path.bytes().any(|b|b<32 || b==127 || b==b'\\') || path[1..].split('/').any(|s|s.is_empty()||s=="."||s==".."||s.len()>255)
                || path[1..].split('/').count()>123{return Err(());}
            self.path[..length].copy_from_slice(&tail[..length]);self.length=length;Ok(())
        })();
        self.scratch.fill(0);self.returned=true;self.failed=result.is_err();result
    }
    pub fn selected(&self)->Result<(&str,u32,u32),()>{
        if !self.entered || !self.returned || self.failed || self.length==0{return Err(());}
        if nix::unistd::getuid().as_raw()!=self.uid || nix::unistd::geteuid().as_raw()!=self.uid
            || nix::unistd::getgid().as_raw()!=self.gid || nix::unistd::getegid().as_raw()!=self.gid{return Err(());}
        Ok((std::str::from_utf8(&self.path[..self.length]).map_err(|_|())?,self.uid,self.gid))
    }
    pub fn call_settled(&self)->bool{!self.entered || self.returned}
}
