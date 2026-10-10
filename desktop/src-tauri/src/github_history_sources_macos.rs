//! Fixed History source companion, nested in asset_source_macos. These are the
//! SAME SourceBook originals owned by the History runtime slot, not a picker
//! receipt or a second cleanup owner. No Drop consumes a descriptor or directory.
use super::*;
use crate::github_history_protocol as wire;
use sha2::{Digest,Sha256};

const PARENT_LIMIT:usize=56;
const SOURCE_FIXED:usize=6; // /, private anchor, release, config, tmp, created work
const WORK_PREFIX:&str="mrk-history-";
const DISK_FLOOR:u64=5*1024*1024*1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Creation { New, Entered, Absent, Created, Removing, Removed, Unknown }

pub(crate) struct HistorySources {
    book:SourceBook,
    config:Option<(usize,wire::FileIdentity,String)>,
    project:Option<(usize,RegisteredRoot)>,
    work:Option<usize>,work_parent:Option<usize>,work_name:Vec<u8>,work_path:String,
    creation:Creation, first:Option<Reason>, finished:bool, parent_reservation:usize,
}
fn directory_data(value:DirectoryIdentity)->wire::DirectoryIdentity {
    wire::DirectoryIdentity {device:value.dev.to_string(),inode:value.ino.to_string(),mode:value.mode,uid:value.uid,gid:value.gid}
}
fn file_data(value:&FileStat)->Result<wire::FileIdentity,Reason> {
    let id=file_identity(value)?;
    let data=wire::FileIdentity {device:id.common.dev.to_string(),inode:id.common.ino.to_string(),mode:id.common.mode,
        uid:id.common.uid,gid:id.common.gid,nlink:id.nlink.to_string(),bytes:id.size.to_string(),
        mtime_seconds:id.mtime.0.to_string(),ctime_seconds:id.ctime.0.to_string(),
        mtime_nanos:u32::try_from(id.mtime.1).map_err(|_|Reason::SourceRefused)?,
        ctime_nanos:u32::try_from(id.ctime.1).map_err(|_|Reason::SourceRefused)?,flags:value.st_flags};
    if !data.valid(wire::CONFIG_LIMIT,false){return Err(Reason::SourceRefused);}Ok(data)
}
fn source_reservation(depth:usize,other:usize)->Option<usize> {
    depth.checked_add(SOURCE_FIXED)?.checked_add(other).filter(|n|*n<=PARENT_LIMIT)
}
fn work_identity_is_created(identity:DirectoryIdentity,uid:u32)->bool {
    identity.mode&0o7777==0o700 && identity.uid==uid && identity.dev!=0 && identity.ino!=0
}
impl HistorySources {
    pub(crate) fn working_reservation_bytes()->Option<usize>{
        // All owned source cells/maximum original names; source config streams
        // through one fixed32KiB block, not an eager512KiB payload allocation.
        std::mem::size_of::<Self>().checked_add(PARENT_LIMIT.checked_mul(std::mem::size_of::<Descriptor>()+255)?)?
            .checked_add(4*PATH_LIMIT)?.checked_add((COMPONENT_LIMIT+2)*(std::mem::size_of::<usize>()+std::mem::size_of::<&[u8]>()))?
            .checked_add(32768+4096+2048)
    }
    #[cfg(test)]
    pub(crate) fn data_checks(){history_source_data_checks();}
    pub(crate) fn new()->Self {Self{book:SourceBook::new(),config:None,project:None,work:None,work_parent:None,
        work_name:Vec::new(),work_path:String::new(),creation:Creation::New,first:None,finished:false,parent_reservation:0}}
    pub(crate) fn not_started(&self)->bool {self.book.not_started()&&self.creation==Creation::New&&!self.finished&&self.first.is_none()}
    pub(crate) fn settled(&self)->bool {self.finished&&self.book.settled()
        &&matches!(self.creation,Creation::New|Creation::Absent|Creation::Removed)}
    pub(crate) fn pending_native(&self)->bool {
        self.book.slots.iter().any(|s|matches!(s.state,OriginalState::Acquiring|OriginalState::Closing|OriginalState::Unknown)
            ||s.acl.iter().any(|a|!a.settled())) || matches!(self.creation,Creation::Entered|Creation::Removing|Creation::Unknown)
    }
    fn fail(&mut self,reason:Reason){if self.first.is_none(){self.first=Some(reason);}}
    pub(crate) fn retained_bytes(&self)->Option<usize> {
        let mut n=self.book.retained_bytes()?.checked_add(self.work_name.capacity())?.checked_add(self.work_path.capacity())?;
        if let Some((_,root))=&self.project{n=n.checked_add(root.path.capacity())?;}
        if let Some((_,id,hash))=&self.config{n=n.checked_add(id.retained_heap_bytes()?)?.checked_add(hash.capacity())?;}
        Some(n)
    }
    pub(crate) fn parent_reservation(&self)->Option<u32>{
        if self.config.is_none()||self.work.is_none()||self.creation!=Creation::Created||self.first.is_some(){return None;}
        u32::try_from(self.parent_reservation).ok()
    }
    // Called only after this exact slot is installed in existing Supervisor
    // Resources. other is its actual runtime originals+future channels/settle,
    // not a renderer quota; no source opens before the combined reserve.
    pub(crate) fn inspect(&mut self,root:&RegisteredRoot,nonce:&str,other:usize,
        stop:&mut dyn FnMut()->bool)->Result<(),Reason>{
        if !self.not_started()||!wire::hex(nonce,32){return Err(Reason::SourceRefused);}
        let result=self.inspect_inner(root,nonce,other,stop);
        if let Err(reason)=result {self.fail(reason);}result
    }
    fn inspect_inner(&mut self,root:&RegisteredRoot,nonce:&str,other:usize,
        stop:&mut dyn FnMut()->bool)->Result<(),Reason>{
        let components=parts(&root.path)?;
        let expected=root.identity.posix()?;
        self.parent_reservation=source_reservation(components.len(),other).ok_or(Reason::Capacity)?;
        let capacity=components.len().checked_add(SOURCE_FIXED).ok_or(Reason::Capacity)?;
        self.book.begin(capacity,0,0)?;
        if self.book.slots.capacity()>capacity{return Err(Reason::Capacity);}
        self.work_name=copy_bytes(format!("{WORK_PREFIX}{nonce}").as_bytes())?;
        self.work_path=format!("/private/tmp/{WORK_PREFIX}{nonce}");
        if self.work_name.capacity()>WORK_PREFIX.len()+32||self.work_path.capacity()>PATH_LIMIT{return Err(Reason::Capacity);}
        self.book.root(stop)?;self.book.anchor_private(stop)?;
        let (chain,_)=self.book.chain(&components,false,stop)?;
        let project=*chain.last().ok_or(Reason::SourceRefused)?;
        if self.book.directory(project)?!=expected{return Err(Reason::SourceChanged);}
        self.project=Some((project,root.clone()));
        let release=self.book.child(project,b"release",false,stop)?;
        let config=self.book.child_policy(release,b"mobile-release.json",true,LeafPolicy::SavedConfiguration,stop)?;
        let actual=stat::fstat(self.book.fd(config)?).map_err(|_|Reason::SourceRefused)?;
        checkpoint(stop)?;
        let identity=file_data(&actual)?;
        self.book.private_acl(config,0,stop)?;
        // Stream actual saved bytes once. There is no canonical serialization,
        // JSON decoder, unbounded read_to_end, or second captured byte vector.
        let mut hash=Sha256::new();let mut bytes=0u64;let mut buffer=[0u8;32768];
        loop {
            checkpoint(stop)?;
            let used=unistd::read(self.book.fd(config)?,&mut buffer).map_err(|_|Reason::SourceRefused)?;
            checkpoint(stop)?;
            if used==0{break;}
            bytes=bytes.checked_add(used as u64).filter(|n|*n<=wire::CONFIG_LIMIT).ok_or(Reason::MaterialLimit)?;
            hash.update(&buffer[..used]);
        }
        if identity.bytes!=bytes.to_string(){return Err(Reason::SourceChanged);}
        self.config=Some((config,identity,format!("{:x}",hash.finalize())));
        self.post(stop)?;
        let private=self.book.anchors.as_ref().ok_or(Reason::SourceRefused)?.private;
        let tmp=self.book.child(private,b"tmp",false,stop)?;self.work_parent=Some(tmp);
        checkpoint(stop)?;
        let space=statfs::fstatfs(self.book.fd(tmp)?).map_err(|_|Reason::Capacity)?;
        checkpoint(stop)?;
        let available=u64::try_from(space.block_size()).ok().and_then(|size|size.checked_mul(space.blocks_available()));
        if available.is_none_or(|n|n<DISK_FLOOR){return Err(Reason::Capacity);}
        // Reserve original state BEFORE mkdir. Store its returned outcome before
        // any clock/metadata call; collision never grants remove authority.
        let work=self.book.reserve(Some(tmp),&self.work_name)?;
        checkpoint(stop)?;self.creation=Creation::Entered;
        let created=stat::mkdirat(self.book.fd(tmp)?,OsStr::from_bytes(&self.work_name),Mode::from_bits_truncate(0o700));
        match created {Ok(())=>self.creation=Creation::Created,Err(_)=>{self.creation=Creation::Absent;return Err(Reason::SourceRefused);}}
        checkpoint(stop)?;
        let before=stat::fstatat(self.book.fd(tmp)?,OsStr::from_bytes(&self.work_name),AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_|Reason::SourceRefused)?;
        checkpoint(stop)?;
        let expected=directory_identity(&before)?;
        if !work_identity_is_created(expected,unistd::geteuid().as_raw()){return Err(Reason::SourceRefused);}
        self.book.slots[work].state=OriginalState::Acquiring;
        let opened=fcntl::openat(self.book.fd(tmp)?,OsStr::from_bytes(&self.work_name),directory_flags(),Mode::empty());
        self.book.adopt(work,opened)?;
        checkpoint(stop)?;filesystem(self.book.fd(work)?,stop)?;
        let actual=stat::fstat(self.book.fd(work)?).map_err(|_|Reason::SourceChanged)?;
        checkpoint(stop)?;
        if directory_identity(&actual)?!=expected{return Err(Reason::SourceChanged);}
        self.book.slots[work].identity=Some(Identity::Directory(expected));self.work=Some(work);
        self.book.private_acl(work,0,stop)?;
        self.empty_work(stop)?;self.post(stop)?;
        if self.retained_bytes().zip(Self::working_reservation_bytes()).is_none_or(|(actual,reserved)|actual>reserved){return Err(Reason::Capacity);}Ok(())
    }
    pub(crate) fn post_observed(&mut self,stop:&mut dyn FnMut()->bool)->Result<(),Reason>{
        let result=self.post(stop);if let Err(reason)=result{self.fail(reason);}result
    }
    pub(crate) fn observed(&self)->Result<(wire::DirectoryIdentity,wire::FileIdentity,String,wire::DirectoryIdentity,String),Reason>{
        if self.first.is_some()||self.creation!=Creation::Created{return Err(Reason::SourceRefused);}
        let (project,_)=self.project.as_ref().ok_or(Reason::SourceRefused)?;
        let (_,file,digest)=self.config.as_ref().ok_or(Reason::SourceRefused)?;
        Ok((directory_data(self.book.directory(*project)?),file.clone(),digest.clone(),
            directory_data(self.book.directory(self.work.ok_or(Reason::SourceRefused)?)?),self.work_path.clone()))
    }
    // Repeated PRE/POST only borrows held originals. ACL phase0/phase1 is not
    // reset/reissued on each callback; phase1 is one terminal native original.
    pub(crate) fn post(&self,stop:&mut dyn FnMut()->bool)->Result<(),Reason>{
        for alias in &self.book.aliases {self.book.check_alias(alias,stop)?;}
        if let Some(anchors)=&self.book.anchors{
            for (name,expected) in [(b"var".as_slice(),anchors.var),(b"tmp".as_slice(),anchors.tmp)]{
                checkpoint(stop)?;let observed=stat::fstatat(self.book.fd(anchors.private)?,OsStr::from_bytes(name),AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_|Reason::SourceChanged)?;
                checkpoint(stop)?;if directory_identity(&observed)?!=expected{return Err(Reason::SourceChanged);}
            }
        }
        for (index,slot) in self.book.slots.iter().enumerate(){
            if self.creation==Creation::Removed&&slot.state==OriginalState::Closed&&Some(index)==self.work{continue;}
            let expected=slot.identity.ok_or(Reason::SourceChanged)?;let file=matches!(expected,Identity::File(_));
            checkpoint(stop)?;filesystem(self.book.fd(index)?,stop)?;
            let held=stat::fstat(self.book.fd(index)?).map_err(|_|Reason::SourceChanged)?;checkpoint(stop)?;
            let named=if let Some(parent)=slot.parent {stat::fstatat(self.book.fd(parent)?,OsStr::from_bytes(&slot.name),AtFlags::AT_SYMLINK_NOFOLLOW)}
                else{stat::lstat(Path::new("/"))}.map_err(|_|Reason::SourceChanged)?;
            checkpoint(stop)?;
            if identity(&held,file)?!=expected||identity(&named,file)?!=expected{return Err(Reason::SourceChanged);}
            if let Some((config,expected,_))=&self.config{if *config==index&&(file_data(&held)?!=*expected||file_data(&named)?!=*expected){return Err(Reason::SourceChanged);}}
        }
        Ok(())
    }
    fn work_post(&self,stop:&mut dyn FnMut()->bool)->Result<(),Reason>{
        let work=self.work.ok_or(Reason::SourceRefused)?;
        let parent=self.work_parent.ok_or(Reason::SourceRefused)?;
        let private=self.book.anchors.as_ref().ok_or(Reason::SourceRefused)?.private;
        for index in [0,private,parent,work]{
            let slot=&self.book.slots[index];let expected=self.book.directory(index)?;
            checkpoint(stop)?;filesystem(self.book.fd(index)?,stop)?;
            let held=stat::fstat(self.book.fd(index)?).map_err(|_|Reason::SourceChanged)?;checkpoint(stop)?;
            let named=if let Some(parent)=slot.parent{stat::fstatat(self.book.fd(parent)?,OsStr::from_bytes(&slot.name),AtFlags::AT_SYMLINK_NOFOLLOW)}
                else{stat::lstat(Path::new("/"))}.map_err(|_|Reason::SourceChanged)?;
            checkpoint(stop)?;if directory_identity(&held)?!=expected||directory_identity(&named)?!=expected{return Err(Reason::SourceChanged);}
        }
        Ok(())
    }
    fn empty_work(&self,stop:&mut dyn FnMut()->bool)->Result<(),Reason>{
        let work=self.work.ok_or(Reason::SourceRefused)?;
        checkpoint(stop)?;unistd::lseek(self.book.fd(work)?,0,unistd::Whence::SeekSet).map_err(|_|Reason::SourceRefused)?;checkpoint(stop)?;
        let mut buffer=[0u8;4096];let mut dots=0usize;
        loop {
            checkpoint(stop)?;
            let used=mrk_macos_installed_native::directory_block(self.book.fd(work)?.as_fd(),&mut buffer).map_err(|_|Reason::SourceRefused)?;
            checkpoint(stop)?;if used==0{return Ok(());}
            if used>buffer.len(){return Err(Reason::SourceRefused);}
            let mut offset=0usize;
            while offset<used {
                if used-offset<11{return Err(Reason::SourceRefused);}
                let length=usize::from(u16::from_ne_bytes([buffer[offset+9],buffer[offset+10]]));
                let next=offset.checked_add(11+length).filter(|n|*n<=used).ok_or(Reason::SourceRefused)?;
                let name=&buffer[offset+11..next];
                if !matches!(name,b"."|b"..")||buffer[offset+8]!=nix::libc::DT_DIR||dots>=2{return Err(Reason::SourceChanged);}
                dots+=1;offset=next;
            }
        }
    }
    pub(crate) fn settle(&mut self,stop:&mut dyn FnMut()->bool,failed:&mut dyn FnMut(Reason))->Result<(),Reason>{
        if self.finished{failed(Reason::CleanupUnknown);return Err(Reason::CleanupUnknown);}
        // A caller with an unjoined native operation MUST NOT enter this method.
        if self.pending_native(){self.fail(Reason::CleanupUnknown);failed(Reason::CleanupUnknown);return Err(Reason::CleanupUnknown);}
        if self.creation==Creation::Created {
            // A changed config vetoes the result, not safe retirement of this
            // separately owned empty directory. Reprove ONLY its actual fixed
            // ancestry/name/inode before the one consuming removal.
            if let Err(reason)=self.post(stop){self.fail(reason);failed(reason);}
            let result=self.work_post(stop).and_then(|_|self.empty_work(stop)).and_then(|_|{
                let work=self.work.ok_or(Reason::CleanupUnknown)?;self.book.private_acl(work,1,stop)
            });
            if let Err(reason)=result{self.fail(reason);failed(reason);}
            if result.is_ok(){
                let work=self.work.ok_or(Reason::CleanupUnknown)?;
                let slot=&mut self.book.slots[work];slot.state=OriginalState::Closing;
                match slot.fd.take().map(unistd::close){Some(Ok(()))=>slot.state=OriginalState::Closed,
                    _=>{slot.state=OriginalState::Unknown;self.fail(Reason::CleanupUnknown);failed(Reason::CleanupUnknown);}}
                if self.book.slots[work].state==OriginalState::Closed {
                    let parent=self.work_parent.ok_or(Reason::CleanupUnknown)?;
                    // Same held/name identity immediately before consuming only
                    // the actual empty created name. Never recurse/retry/adopt.
                    let remove=(||{
                        checkpoint(stop)?;
                        let named=stat::fstatat(self.book.fd(parent)?,OsStr::from_bytes(&self.work_name),AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_|Reason::SourceChanged)?;
                        checkpoint(stop)?;
                        if self.book.slots[work].identity!=Some(Identity::Directory(directory_identity(&named)?)){return Err(Reason::SourceChanged);}
                        self.creation=Creation::Removing;
                        let returned=unistd::unlinkat(self.book.fd(parent)?,OsStr::from_bytes(&self.work_name),unistd::UnlinkatFlags::RemoveDir);
                        self.creation=if returned.is_ok(){Creation::Removed}else{Creation::Unknown};
                        returned.map_err(|_|Reason::CleanupUnknown)?;checkpoint(stop)?;
                        let actual=stat::fstat(self.book.fd(parent)?).map_err(|_|Reason::SourceChanged)?;
                        checkpoint(stop)?;if directory_identity(&actual)?!=self.book.directory(parent)?{return Err(Reason::SourceChanged);}Ok(())
                    })();
                    if let Err(reason)=remove{self.fail(reason);failed(reason);}
                }
            }
        }
        if self.creation==Creation::Removed {if let Err(reason)=self.post(stop){self.fail(reason);failed(reason);}}
        if let Some((config,_,_))=&self.config {
            let result=self.book.private_acl(*config,1,stop);
            if let Err(reason)=result{self.fail(reason);failed(reason);}
        }
        // Independent known originals are consumed even after an earlier error;
        // that first error remains, while uncertain closes independently veto.
        let known=self.book.close_all_observing(failed);self.finished=true;
        if !known||!self.settled(){self.fail(Reason::CleanupUnknown);failed(Reason::CleanupUnknown);}
        if let Err(reason)=checkpoint(stop){self.fail(reason);failed(reason);}
        match self.first {Some(reason)=>Err(reason),None=>Ok(())}
    }
}

#[cfg(test)]
pub(crate) fn history_source_data_checks(){
    assert_eq!(source_reservation(20,30),Some(56));assert_eq!(source_reservation(21,30),None);
    assert_eq!(source_reservation(usize::MAX,0),None);assert_eq!(source_reservation(0,usize::MAX),None);
    let original=DirectoryIdentity{dev:1,ino:2,mode:0o40700,uid:501,gid:20};
    assert!(work_identity_is_created(original,501));assert!(!work_identity_is_created(original,502));
    assert!(!work_identity_is_created(DirectoryIdentity{mode:0o40755,..original},501));
    let book=HistorySources::new();assert!(book.not_started()&&!book.settled()&&!book.pending_native());
    assert!(book.parent_reservation().is_none()&&book.observed().is_err());
}
