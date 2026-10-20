//! Closed GitHub targets only. The app retains its original document admission
//! through this synchronous main-thread request; success is not browser visibility.
use std::io;
unsafe extern "C" {
    fn mrk_github_browser(kind:i32,repository:*const u8,repository_len:usize,
        first:*const u8,first_len:usize,second:*const u8,second_len:usize)->i32;
}
fn request(kind:i32,repository:&str,first:&str,second:&str)->io::Result<()> {
    if repository.is_empty()||repository.len()>140||first.is_empty()||first.len()>40||second.len()>40 {
        return Err(io::Error::from_raw_os_error(nix::libc::EINVAL));
    }
    // SAFETY: all pointers borrow live bounded UTF-8 bytes for the synchronous
    // call. The shim additionally checks exact closed ASCII grammar/main thread.
    let code=unsafe{mrk_github_browser(kind,repository.as_ptr(),repository.len(),first.as_ptr(),first.len(),second.as_ptr(),second.len())};
    if code==0{Ok(())}else{Err(io::Error::from_raw_os_error(code))}
}
pub fn pull_request(repository:&str,number:&str,files:bool)->io::Result<()> {request(if files{2}else{1},repository,number,"")}
pub fn comparison(repository:&str,base_sha:&str,head_sha:&str)->io::Result<()> {request(3,repository,base_sha,head_sha)}
