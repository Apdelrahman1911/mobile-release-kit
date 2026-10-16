//! Real Darwin kernel/OFD regression, not a Keychain or app-lifecycle proof.
//! Three direct, owned test children model the loan holders. No orphan process,
//! generic provider, native role stub, credential, Store call or random key.
use super::*;
use std::{fs::{self,File,DirBuilder,OpenOptions},io::{Read,Write},os::unix::{fs::{DirBuilderExt,OpenOptionsExt,MetadataExt},process::ExitStatusExt},
    path::PathBuf,process::{Child,ChildStdin,ChildStdout,ChildStderr,Command,Stdio},sync::Arc,time::{Duration,Instant}};
use crate::{local_keychain_wire as wire,vault_helper_wire::ClockBridge};
use zeroize::Zeroizing;
type TestResult<T=()> = Result<T,&'static str>;
const ROLE:&str="MRK_LOCAL_LEASE_TEST_ROLE";
const ENTRY:&str="local_project_lease::tests::inherited_child";
fn need(value:bool)->TestResult {if value{Ok(())}else{Err("lease fixture predicate")}}
fn before(end:Instant)->TestResult {need(Instant::now()<end)}
fn nonblocking(fd:BorrowedFd<'_>)->TestResult {
    let flags=fcntl(fd,FcntlArg::F_GETFL).map_err(|_|"pipe flags")?;
    fcntl(fd,FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags)|OFlag::O_NONBLOCK)).map_err(|_|"pipe nonblocking")?;Ok(())
}
fn write_bounded(writer:&mut impl Write,bytes:&[u8],end:Instant)->TestResult {
    let mut at=0;while at<bytes.len(){before(end)?;match writer.write(&bytes[at..]){
        Ok(0)=>return Err("zero pipe write"),Ok(n)=>at+=n,Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>std::thread::sleep(Duration::from_millis(2)),Err(_)=>return Err("pipe write"),}}
    Ok(())
}
fn read_exact_bounded(reader:&mut impl Read,bytes:&mut[u8],end:Instant)->TestResult {
    let mut at=0;while at<bytes.len(){before(end)?;match reader.read(&mut bytes[at..]){
        Ok(0)=>return Err("unexpected pipe EOF"),Ok(n)=>at+=n,Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>std::thread::sleep(Duration::from_millis(2)),Err(_)=>return Err("pipe read"),}}
    Ok(())
}
struct LeaseChild {child:Child,input:Option<ChildStdin>,output:Option<ChildStdout>,error:Option<ChildStderr>,out:Vec<u8>,err:Vec<u8>,joined:bool,success:bool,killed:bool,close_failed:bool,wait_failed:bool}
impl LeaseChild {
    fn collect(&mut self)->TestResult {
        fn drain(reader:&mut impl Read,bytes:&mut Vec<u8>)->TestResult {let mut b=[0;256];loop{match reader.read(&mut b){
            Ok(0)=>return Ok(()),Ok(n)=>{need(bytes.len()+n<=4096)?;bytes.extend_from_slice(&b[..n]);},
            Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>return Ok(()),Err(_)=>return Err("capture read"),}}}
        if let Some(output)=self.output.as_mut(){drain(output,&mut self.out)?;}
        if let Some(error)=self.error.as_mut(){drain(error,&mut self.err)?;}
        need(self.err.is_empty())
    }
    fn marker(&mut self,role:&str,kind:&str,end:Instant)->TestResult {
        let marker=format!("\nMRK-LEASE/1 {role} {kind}\n");loop{before(end)?;self.collect()?;
            let count=self.out.windows(marker.len()).filter(|v|*v==marker.as_bytes()).count();need(count<=1)?;
            if count==1{return Ok(());}need(!self.joined)?;std::thread::sleep(Duration::from_millis(2));}
    }
    fn join(&mut self,end:Instant)->TestResult {while !self.joined{before(end)?;self.collect()?;
        if let Some(exit)=self.child.try_wait().map_err(|_|{self.wait_failed=true;"child wait"})?{self.joined=true;self.success=exit.success();self.killed=exit.signal()==Some(nix::libc::SIGKILL);}
        else{std::thread::sleep(Duration::from_millis(2));}}
        self.collect()
    }
}
fn close_input(child:&mut LeaseChild)->TestResult {
    if let Some(input)=child.input.take(){unistd::close(OwnedFd::from(input)).map_err(|_|{child.close_failed=true;"input close"})?;}Ok(())
}
struct LeaseCase {path:PathBuf,created:bool,root:Option<File>,probe:Option<File>,identity:Option<ProjectRoot>,lease:Option<Arc<ProjectLease>>,
    children:[Option<LeaseChild>;3],spawn_unknown:bool,close_unknown:bool,work:Instant,hard:Instant}
impl LeaseCase {
    fn new(case:&str)->Self {let now=Instant::now();Self{path:std::env::temp_dir().join(format!("mrk-local-lease-{}-{case}",std::process::id())),created:false,
        root:None,probe:None,identity:None,lease:None,children:std::array::from_fn(|_|None),spawn_unknown:false,close_unknown:false,work:now+Duration::from_secs(10),hard:now+Duration::from_secs(12)}}
    fn acquire(&mut self)->TestResult {
        before(self.work)?;DirBuilder::new().mode(0o700).create(&self.path).map_err(|_|"new fixture directory")?;self.created=true;
        let open=||OpenOptions::new().read(true).custom_flags(nix::libc::O_DIRECTORY|nix::libc::O_NOFOLLOW|nix::libc::O_CLOEXEC).open(&self.path);
        self.root=Some(open().map_err(|_|"fixture root")?);self.probe=Some(open().map_err(|_|"independent probe")?);
        let root=self.root.as_ref().ok_or("root missing")?;let stat=fstat(root.as_fd()).map_err(|_|"root stat")?;
        let identity=ProjectRoot{device:stat.st_dev as u64,inode:stat.st_ino as u64,mode:stat.st_mode as u32,uid:stat.st_uid,gid:stat.st_gid,descriptor:root.as_raw_fd() as u32};
        self.identity=Some(identity);self.lease=Some(Arc::new(ProjectLease::new()));
        Arc::get_mut(self.lease.as_mut().ok_or("lease missing")?).ok_or("lease alias")?.enter(root.as_fd(),identity).map_err(|_|"real lease enter")?;
        self.probe(false)
    }
    fn probe(&self,free:bool)->TestResult {before(self.work)?;let probe=self.probe.as_ref().ok_or("probe missing")?;
        let result=unsafe{nix::libc::flock(probe.as_raw_fd(),nix::libc::LOCK_EX|nix::libc::LOCK_NB)};
        if free{need(result==0)}else{need(result == -1 && nix::errno::Errno::last()==nix::errno::Errno::EWOULDBLOCK)}
    }
    fn spawn(&mut self,index:usize,role:&str)->TestResult {
        before(self.work)?;need(self.children[index].is_none())?;
        let lease=self.lease.as_ref().ok_or("lease missing")?;let (_,mut root)=lease.checked().map_err(|_|"lease PRE")?;
        let mut command=Command::new(std::env::current_exe().map_err(|_|"test executable")?);
        command.env_clear().env(ROLE,role).args(["--exact",ENTRY,"--ignored","--nocapture","--test-threads=1","--color=never"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        inherit_command(&mut command,lease.clone()).map_err(|_|"real C inheritance preparation")?;
        self.spawn_unknown=true;let child=command.spawn().map_err(|_|"owned test spawn")?;
        // Retain the actual child BEFORE pipe setup, writes or READY barriers.
        self.children[index]=Some(LeaseChild{child,input:None,output:None,error:None,out:Vec::new(),err:Vec::new(),joined:false,success:false,killed:false,close_failed:false,wait_failed:false});
        self.spawn_unknown=false;drop(command); // The pre_exec closure held an Arc until this point.
        need(Arc::strong_count(lease)==1)?;need(fcntl(lease.checked().map_err(|_|"parent POST")?.0,FcntlArg::F_GETFD).map_err(|_|"parent fd flags")?==nix::libc::FD_CLOEXEC)?;
        let child=self.children[index].as_mut().ok_or("child missing")?;
        child.input=child.child.stdin.take();child.output=child.child.stdout.take();child.error=child.child.stderr.take();
        nonblocking(child.input.as_ref().ok_or("input missing")?.as_fd())?;nonblocking(child.output.as_ref().ok_or("output missing")?.as_fd())?;nonblocking(child.error.as_ref().ok_or("error missing")?.as_fd())?;
        if role=="wrong-root"{root.inode=root.inode.checked_add(1).ok_or("inode overflow")?;}
        let clock=ClockBridge::capture().ok_or("clock")?;
        let request=wire::Request{context:wire::Context::new([3;32],wire::Purpose::LocalCheckpoint,1,root).ok_or("test context")?,operation:wire::Operation::ProbeAbsent,
            nonce:[4;16],work:clock.endpoint(self.work).ok_or("clock work")?,maximum_cleanup:clock.endpoint(self.hard).ok_or("clock hard")?,value:Zeroizing::new([0;32])};
        let mut bytes=[0;wire::REQUEST_BYTES];need(request.encode(&mut bytes))?;
        write_bounded(child.input.as_mut().ok_or("input missing")?,&bytes,self.work)?;
        child.marker(role,if role=="wrong-root"||role=="cloexec"{"REFUSED"}else{"READY"},self.work)
    }
    fn retire_parent_originals(&mut self)->TestResult {
        let lease=self.lease.as_mut().ok_or("lease missing")?;need(Arc::strong_count(lease)==1)?;
        need(Arc::get_mut(lease).ok_or("lease alias")?.close())?;need(lease.settled())?;
        unistd::close(self.root.take().ok_or("root missing")?).map_err(|_|{self.close_unknown=true;"root close"})?;Ok(())
    }
    fn finish_child(&mut self,index:usize,kill:bool,role:&str)->TestResult {
        before(self.work)?;let child=self.children[index].as_mut().ok_or("child missing")?;
        if kill{child.child.kill().map_err(|_|"fixture kill")?;}else{write_bounded(child.input.as_mut().ok_or("input missing")?,b"C",self.work)?;child.marker(role,"CLOSED",self.work)?;}
        close_input(child)?;child.join(self.work)?;need(if kill{child.killed}else{child.success})
    }
    fn cleanup(&mut self)->bool {
        // One containing failure/cleanup endpoint; request every original stop
        // before waiting for any child. Never an unbounded wait or drop-as-join.
        let end=self.hard.min(Instant::now()+Duration::from_secs(2));let mut known=!self.spawn_unknown&&!self.close_unknown;
        for child in self.children.iter_mut().flatten(){known &= close_input(child).is_ok()&&!child.close_failed;if !child.joined{let _=child.child.kill();}}
        // Capture/protocol failure must not prevent joining the same child.
        for child in self.children.iter_mut().flatten(){
            while !child.joined && Instant::now()<end{
                match child.child.try_wait(){Ok(Some(exit))=>{child.joined=true;child.success=exit.success();},Ok(None)=>std::thread::sleep(Duration::from_millis(2)),Err(_)=>{child.wait_failed=true;break;},}
            }
            known &= child.joined&&!child.wait_failed;
        }
        for child in self.children.iter_mut().flatten(){
            for fd in [child.output.take().map(OwnedFd::from),child.error.take().map(OwnedFd::from)]{if let Some(fd)=fd{known &= unistd::close(fd).is_ok();}}
        }
        if let Some(lease)=self.lease.as_mut(){known &= Arc::get_mut(lease).is_some_and(|l|l.close()&&l.settled());}
        for fd in [self.root.take(),self.probe.take()]{if let Some(fd)=fd{known &= unistd::close(fd).is_ok();}}
        if known && self.created {
            let same=fs::symlink_metadata(&self.path).ok().zip(self.identity).is_some_and(|(v,i)|
                (v.dev(),v.ino(),v.mode(),v.uid(),v.gid())==(i.device,i.inode,i.mode,i.uid,i.gid));
            known &= same && fs::remove_dir(&self.path).is_ok();
        }
        known
    }
}
#[test]
fn kernel_same_ofd_survives_participant_exit(){
    for killed in [0,1]{let mut case=LeaseCase::new(if killed==0{"parent-exit"}else{"python-exit"});let result=(||{
        case.acquire()?;for index in 0..3{case.spawn(index,&index.to_string())?;}
        case.retire_parent_originals()?;case.probe(false)?;
        case.finish_child(killed,true,&killed.to_string())?;case.probe(false)?;
        let other=1-killed;case.finish_child(other,false,&other.to_string())?;case.probe(false)?;
        case.finish_child(2,false,"2")?;case.probe(true)
    })();let closed=case.cleanup();assert!(result.is_ok()&&closed,"same-OFD fixture failed or did not close");}
}
#[test]
fn kernel_inherited_root_and_cloexec_refuse(){
    for role in ["wrong-root","cloexec"]{let mut case=LeaseCase::new(role);let result=(||{
        case.acquire()?;case.spawn(0,role)?;let child=case.children[0].as_mut().ok_or("child missing")?;close_input(child)?;child.join(case.work)?;need(child.success)?;
        case.probe(false)?;case.retire_parent_originals()?;case.probe(true)
    })();let closed=case.cleanup();assert!(result.is_ok()&&closed,"refusal fixture failed or did not close");}
}
#[test]
#[ignore="fixed child entry, invoked only by the owned kernel tests"]
fn inherited_child(){
    let result=(||->TestResult{
        let role=std::env::var(ROLE).map_err(|_|"missing fixed child role")?;need(matches!(role.as_str(),"0"|"1"|"2"|"wrong-root"|"cloexec"))?;
        let mut input=std::io::stdin();nonblocking(input.as_fd())?;let mut bytes=[0;wire::REQUEST_BYTES];
        read_exact_bounded(&mut input,&mut bytes,Instant::now()+Duration::from_secs(10))?;
        let request=wire::Request::decode(&bytes).ok_or("fixed request")?;
        let clock=ClockBridge::capture().ok_or("clock")?;let end=clock.earlier_instant_data(request.work).ok_or("inherited endpoint")?;before(end)?;
        let root=request.context.project();
        if role=="cloexec"{
            // The fixture's exact inherited role only. No ownership/numeric
            // close is claimed after this deliberately invalid admission.
            let fd=unsafe{BorrowedFd::borrow_raw(root.descriptor as i32)};
            fcntl(fd,FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(|_|"fixture cloexec")?;
        }
        let mut lease=InheritedLease::new();let admitted=lease.admit(root);
        let negative=role=="wrong-root"||role=="cloexec";
        if negative{need(!admitted && lease.fd.is_none() && !lease.facts().admitted)?;print!("\nMRK-LEASE/1 {role} REFUSED\n");std::io::stdout().flush().map_err(|_|"marker flush")?;return Ok(());}
        need(admitted&&lease.post())?;print!("\nMRK-LEASE/1 {role} READY\n");std::io::stdout().flush().map_err(|_|"marker flush")?;
        let mut close=[0;1];read_exact_bounded(&mut input,&mut close,end)?;need(close==*b"C"&&lease.post())?;
        let facts=lease.finish();need(facts.admitted&&facts.postchecked&&facts.close_entered&&facts.closed)?;
        print!("\nMRK-LEASE/1 {role} CLOSED\n");std::io::stdout().flush().map_err(|_|"marker flush")?;Ok(())
    })();assert!(result.is_ok(),"fixed lease child refused or failed");
}
