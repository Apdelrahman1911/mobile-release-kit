//! Switch-only facet of the SAME GitLocalSources/SourceBook. No new native
//! owner/executor, caller FD, command runner or generic destination publisher.
//! Its one target-ref lock is held until all other original source closes are
//! known, then exact unlink/postcheck/one final FD close. Ambiguity is retained.
use super::*;
use crate::git_switch_protocol as switch;

struct Edge {parent:usize,name:Vec<u8>,original:Option<(usize,wire::Snapshot)>,maximum:u64}
struct Returned {old:Option<usize>,old_snapshot:Option<wire::Snapshot>,successor:usize,snapshot:wire::Snapshot,maximum:u64}
pub(super) struct State {
    target:Option<Edge>,packed:Option<(usize,wire::Snapshot)>,files:Vec<Edge>,log:Option<Edge>,
    lock:Option<usize>,parent_before:Option<wire::FileIdentity>,parent_locked:Option<wire::FileIdentity>,
    projection:Option<switch::Sources>,returned:Vec<Returned>,unlink_claimed:bool,unlinked:bool,
}
impl State {
    fn new()->Result<Self,Reason> {
        let mut files=Vec::new();files.try_reserve_exact(switch::MAX_FILES).map_err(|_|Reason::Capacity)?;
        let mut returned=Vec::new();returned.try_reserve_exact(switch::MAX_FILES+3).map_err(|_|Reason::Capacity)?;
        if files.capacity()>switch::MAX_FILES||returned.capacity()>switch::MAX_FILES+3 {return Err(Reason::Capacity)}
        Ok(Self {target:None,packed:None,files,log:None,lock:None,parent_before:None,parent_locked:None,
            projection:None,returned,unlink_claimed:false,unlinked:false})
    }
    pub(super) fn working_bytes()->Option<usize> {
        // SourceBook's unchanged 128-slot ceiling is already charged by its
        // parent. Additional fixed wrappers, paths/snapshots and compare copy.
        std::mem::size_of::<Self>().checked_add((switch::MAX_FILES+4)*(PATH_LIMIT+2048))?
            .checked_add((switch::MAX_FILES+3)*std::mem::size_of::<Returned>())?
            .checked_add(switch::MAX_FILES*std::mem::size_of::<Edge>())
    }
    pub(super) fn extra(review:Option<&wire::Review>)->Option<usize> {
        let Some(review)=review.and_then(wire::Review::switch_details) else {return Some(0)};
        // Existing physical parents only; over-capacity is a pre-effect
        // refusal. No credit for aliases/duplicate parents or future closes.
        let paths=review.files.iter().try_fold(0usize,|n,f|n.checked_add(f.path.split('/').count()))?;
        paths.checked_add(review.target_ref.split('/').count())?
            .checked_add(switch::MAX_FILES+10)
    }
}
fn full(stat:&FileStat)->Result<wire::FileIdentity,Reason> {
    let d=metadata_identity(stat)?;
    let nanos=|v:(i64,i64)|->Result<i64,Reason> {
        if !(0..1_000_000_000).contains(&v.1) {return Err(Reason::SourceRefused)}
        v.0.checked_mul(1_000_000_000).and_then(|s|s.checked_add(v.1)).ok_or(Reason::SourceRefused)
    };
    Ok((d.common.dev,d.common.ino,d.common.mode,d.common.uid,d.common.gid,d.nlink,d.size,nanos(d.mtime)?,nanos(d.ctime)?))
}
fn group_supported(original:wire::FileIdentity,parent:DirectoryIdentity)->bool {
    switch::replacement_group(original,(parent.dev,parent.ino,parent.mode,parent.uid,parent.gid))
}
fn publication_names(p:wire::Publication,logging:bool)->Option<&'static [&'static str]> {
    use wire::Publication::*;
    match (p,logging) {
        (SwitchCheckoutReturned,_)=>Some(&[]),(SwitchLogReturned,true)=>Some(&["logs/HEAD"]),
        (SwitchHeadReturned,true)=>Some(&["logs/HEAD","HEAD"]),(SwitchHeadReturned,false)=>Some(&["HEAD"]),
        (SwitchIndexReturned,true)=>Some(&["logs/HEAD","HEAD","index"]),(SwitchIndexReturned,false)=>Some(&["HEAD","index"]),
        _=>None,
    }
}
impl GitLocalSources {
    pub(crate) fn retain_switch_unknown(&mut self) {
        // Classification may only become more conservative. The original
        // Supervisor/ACL first-failure clocks remain untouched; retaining a
        // prior SourceChanged label here must not let close drop this lock.
        self.first=Some(Reason::CleanupUnknown);
        self.close_failed=true;
    }
    fn switch_edge(&mut self,parent:usize,name:&[u8],uid:u32,maximum:u64,stop:&mut dyn FnMut()->bool)->Result<Edge,Reason> {
        checkpoint(stop)?;
        let original=match stat::fstatat(self.book.fd(parent)?,OsStr::from_bytes(name),AtFlags::AT_SYMLINK_NOFOLLOW) {
            Err(nix::errno::Errno::ENOENT)=>None,
            Ok(_)=>{let index=self.file(parent,name,uid,maximum,false,stop)?;Some((index,self.snapshot(index,maximum,stop)?))},
            Err(_)=>return Err(Reason::SourceRefused),
        };
        checkpoint(stop)?;
        Ok(Edge {parent,name:copy_bytes(name)?,original,maximum})
    }
    fn switch_parent(&self,index:usize,stop:&mut dyn FnMut()->bool)->Result<wire::FileIdentity,Reason> {
        checkpoint(stop)?;
        let held=stat::fstat(self.book.fd(index)?).map_err(|_|Reason::SourceChanged)?;
        checkpoint(stop)?;
        if directory_identity(&held)?!=self.book.directory(index)?||held.st_flags!=0 {return Err(Reason::SourceChanged)}
        full(&held)
    }
    pub(super) fn capture_switch(&mut self,project:usize,stop:&mut dyn FnMut()->bool)->Result<(),Reason> {
        if self.switch.is_some() {return Err(Reason::SourceChanged)}
        let review=self.review.as_ref().and_then(wire::Review::switch_details).filter(|r|r.valid()).ok_or(Reason::SourceRefused)?.clone();
        let native=self.native.as_ref().ok_or(Reason::SourceRefused)?.clone();
        if native.files.head.sha256!=switch::hash(format!("ref: {}\n",review.branch).as_bytes())
            ||!native.files.index.as_ref().is_some_and(|s|s.sha256==review.expected_index&&s.identity.6<=switch::INDEX_LIMIT) {
            return Err(Reason::SourceChanged)
        }
        self.switch=Some(State::new()?); // Retained before lock acquisition/effects.
        let git=self.git.ok_or(Reason::SourceChanged)?;
        let git_parent=self.book.directory(git)?;
        if !group_supported(native.files.head.identity,git_parent)
            || !native.files.index.as_ref().is_some_and(|s|group_supported(s.identity,git_parent)) {
            return Err(Reason::SourceRefused)
        }
        let components:Vec<_>=review.target_ref.split('/').collect();
        let mut parent=git;
        for name in &components[..components.len()-1] {parent=self.book.child(parent,name.as_bytes(),false,stop)?;}
        let leaf=components.last().ok_or(Reason::SourceRefused)?.as_bytes();
        let edge=self.switch_edge(parent,leaf,native.uid,65,stop)?;
        if let Some((_,value))=&edge.original {
            if value.sha256!=switch::hash(format!("{}\n",review.target_oid).as_bytes()) {return Err(Reason::SourceChanged)}
        } else {
            // No native ref resolver: the SAME fixed core checks this complete
            // held packed source against its retained inventory/target OID.
            let packed=self.file(git,b"packed-refs",native.uid,65536,false,stop)?;
            let snapshot=self.snapshot(packed,65536,stop)?;
            self.switch.as_mut().ok_or(Reason::SourceChanged)?.packed=Some((packed,snapshot));
        }
        self.switch.as_mut().ok_or(Reason::SourceChanged)?.target=Some(edge);
        for selected in &review.files {
            let parts:Vec<_>=selected.path.split('/').collect();let mut parent=project;
            for name in &parts[..parts.len()-1] {parent=self.book.child(parent,name.as_bytes(),false,stop)?;}
            let edge=self.switch_edge(parent,parts.last().ok_or(Reason::SourceRefused)?.as_bytes(),native.uid,switch::FILE_LIMIT,stop)?;
            let (_,snapshot)=edge.original.as_ref().ok_or(Reason::SourceChanged)?;
            if snapshot.sha256!=selected.source_sha256||snapshot.identity.2!=selected.mode_bits() {return Err(Reason::SourceChanged)}
            if !group_supported(snapshot.identity,self.book.directory(parent)?) {return Err(Reason::SourceRefused)}
            let state=self.switch.as_mut().ok_or(Reason::SourceChanged)?;
            if state.files.len()>=switch::MAX_FILES {return Err(Reason::Capacity)}
            state.files.push(edge);
        }
        let logs=self.book.child(git,b"logs",false,stop)?;
        let log=self.switch_edge(logs,b"HEAD",native.uid,switch::LOG_LIMIT,stop)?;
        match (&log.original,review.log.original_kind.as_str()) {
            (Some((_,s)),"file") if s.sha256==review.log.original_sha256=>{},(None,"absent")=>{},_=>return Err(Reason::SourceChanged),
        }
        let log_parent=self.book.directory(logs)?;
        if log.original.as_ref().is_some_and(|(_,s)|!group_supported(s.identity,log_parent)) {
            return Err(Reason::SourceRefused)
        }
        self.switch.as_mut().ok_or(Reason::SourceChanged)?.log=Some(log);
        // Actual exclusive lock on the exact admitted target parent. No Git
        // command will be asked to acquire this lock, and Python cannot own it.
        let before=self.switch_parent(parent,stop)?;
        if before.3!=native.uid||before.2&0o7022!=0 {return Err(Reason::SourceRefused)}
        self.switch.as_mut().ok_or(Reason::SourceChanged)?.parent_before=Some(before);
        let name=format!("{}.lock",std::str::from_utf8(leaf).map_err(|_|Reason::SourceRefused)?);
        let index=self.book.reserve(Some(parent),name.as_bytes())?;
        self.switch.as_mut().ok_or(Reason::SourceChanged)?.lock=Some(index);
        self.book.slots[index].state=OriginalState::Acquiring;
        let opened=fcntl::openat(self.book.fd(parent)?,OsStr::from_bytes(name.as_bytes()),
            OFlag::O_WRONLY|OFlag::O_CREAT|OFlag::O_EXCL|OFlag::O_NOFOLLOW|OFlag::O_CLOEXEC,Mode::from_bits_truncate(0o600));
        self.book.adopt(index,opened)?; // Actual returned FD retained before any check/STOP.
        checkpoint(stop)?;
        let held=stat::fstat(self.book.fd(index)?).map_err(|_|Reason::SourceChanged)?;
        let identity=file_identity(&held)?;
        self.book.slots[index].identity=Some(Identity::File(identity));
        checkpoint(stop)?;
        let after=self.switch_parent(parent,stop)?;
        self.switch.as_mut().ok_or(Reason::SourceChanged)?.parent_locked=Some(after);
        if !switch::parent_transition(before,after)||identity.common.mode!=0o100600||identity.common.uid!=native.uid
            ||identity.nlink!=1||identity.size!=0||held.st_flags!=0 {return Err(Reason::SourceChanged)}
        self.check_switch_lock(stop)?;
        let state=self.switch.as_ref().ok_or(Reason::SourceChanged)?;
        let mut files=Vec::new();files.try_reserve_exact(review.files.len()).map_err(|_|Reason::Capacity)?;
        if files.capacity()>switch::MAX_FILES {return Err(Reason::Capacity)}
        for (row,edge) in review.files.iter().zip(&state.files) {
            files.push(switch::NamedSnapshot {path:row.path.clone(),snapshot:edge.original.as_ref().ok_or(Reason::SourceChanged)?.1.clone()});
        }
        let projection=switch::Sources {target_lock:switch::TargetLock {identity:full(&held)?,parent_before:before,parent_locked:after},
            head_log:state.log.as_ref().ok_or(Reason::SourceChanged)?.original.as_ref().map(|v|v.1.clone()),files};
        if !projection.valid(&native,&review) {return Err(Reason::SourceChanged)}
        self.switch.as_mut().ok_or(Reason::SourceChanged)?.projection=Some(projection);
        Ok(())
    }
    pub(crate) fn switch_projection(&self)->Result<Option<&switch::Sources>,Reason> {
        if self.finished||self.first.is_some() {return Err(Reason::SourceChanged)}
        self.switch.as_ref().map(|s|s.projection.as_ref().ok_or(Reason::SourceChanged)).transpose()
    }
    fn check_switch_lock(&self,stop:&mut dyn FnMut()->bool)->Result<(),Reason> {
        let state=self.switch.as_ref().ok_or(Reason::SourceChanged)?;
        let index=state.lock.ok_or(Reason::SourceChanged)?;
        let parent=state.target.as_ref().ok_or(Reason::SourceChanged)?.parent;
        if state.unlink_claimed||state.unlinked {return Err(Reason::CleanupUnknown)}
        let expected=match self.book.slots[index].identity {Some(Identity::File(v))=>v,_=>return Err(Reason::SourceChanged)};
        checkpoint(stop)?;
        let held=stat::fstat(self.book.fd(index)?).map_err(|_|Reason::SourceChanged)?;
        checkpoint(stop)?;
        let named=stat::fstatat(self.book.fd(parent)?,OsStr::from_bytes(&self.book.slots[index].name),AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_|Reason::SourceChanged)?;
        checkpoint(stop)?;
        if expected!=file_identity(&held)?||expected!=file_identity(&named)?||held.st_flags!=0||named.st_flags!=0
            ||Some(self.switch_parent(parent,stop)?)!=state.parent_locked {return Err(Reason::SourceChanged)}
        Ok(())
    }
    pub(super) fn switch_is_old(&self,index:usize)->bool {
        self.switch.as_ref().is_some_and(|s|s.returned.iter().any(|r|r.old==Some(index)))
    }
    pub(super) fn switch_old_identity(&self,index:usize,held:&FileStat)->Result<FileIdentity,Reason> {
        let state=self.switch.as_ref().ok_or(Reason::SourceChanged)?;
        let receipt=state.returned.iter().find(|r|r.old==Some(index)).ok_or(Reason::SourceChanged)?;
        let original=match self.book.slots[index].identity {Some(Identity::File(v))=>v,_=>return Err(Reason::SourceChanged)};
        let successor=match self.book.slots[receipt.successor].identity {Some(Identity::File(v))=>v,_=>return Err(Reason::SourceChanged)};
        let actual=file_identity(held)?;
        if receipt.old_snapshot.is_none()||!unlinked_original(actual,original,successor,held.st_flags as u64) {return Err(Reason::SourceChanged)}
        Ok(actual)
    }
    pub(super) fn switch_snapshot_original(&self,index:usize,maximum:u64,stop:&mut dyn FnMut()->bool)->Result<wire::Snapshot,Reason> {
        let receipt=self.switch.as_ref().and_then(|s|s.returned.iter().find(|r|r.old==Some(index))).ok_or(Reason::SourceChanged)?;
        checkpoint(stop)?;
        let held=stat::fstat(self.book.fd(index)?).map_err(|_|Reason::SourceChanged)?;
        let actual=self.switch_old_identity(index,&held)?;
        let hashed=self.snapshot_identity(index,actual,maximum,stop)?;
        let expected=receipt.old_snapshot.as_ref().ok_or(Reason::SourceChanged)?;
        if hashed.sha256!=expected.sha256 {return Err(Reason::SourceChanged)}
        Ok(expected.clone()) // DATA only; actual original slot/FD never replaced.
    }
    fn check_switch_edge(&self,edge:&Edge,stop:&mut dyn FnMut()->bool)->Result<(),Reason> {
        if let Some((index,original))=&edge.original {
            if self.snapshot_original(*index,edge.maximum,stop)?!=*original {return Err(Reason::SourceChanged)}
        } else if !self.switch.as_ref().is_some_and(|s|s.returned.iter().any(|r|r.old.is_none()
            &&self.book.slots[r.successor].parent==Some(edge.parent)&&self.book.slots[r.successor].name==edge.name)) {
            checkpoint(stop)?;
            if !matches!(stat::fstatat(self.book.fd(edge.parent)?,OsStr::from_bytes(&edge.name),AtFlags::AT_SYMLINK_NOFOLLOW),Err(nix::errno::Errno::ENOENT)) {
                return Err(Reason::SourceChanged)
            }
            checkpoint(stop)?;
        }
        Ok(())
    }
    pub(super) fn post_switch(&self,stop:&mut dyn FnMut()->bool)->Result<(),Reason> {
        let Some(state)=&self.switch else {return Ok(())};
        self.check_switch_lock(stop)?;
        self.check_switch_edge(state.target.as_ref().ok_or(Reason::SourceChanged)?,stop)?;
        if let Some((index,snapshot))=&state.packed {if self.snapshot(*index,65536,stop)?!=*snapshot {return Err(Reason::SourceChanged)}}
        for edge in &state.files {self.check_switch_edge(edge,stop)?;}
        self.check_switch_edge(state.log.as_ref().ok_or(Reason::SourceChanged)?,stop)?;
        for receipt in &state.returned {
            if self.snapshot(receipt.successor,receipt.maximum,stop)?!=receipt.snapshot {return Err(Reason::SourceChanged)}
        }
        self.check_switch_lock(stop)
    }
    fn switch_successor(&mut self,parent:usize,name:&[u8],old:Option<(usize,wire::Snapshot)>,maximum:u64,
        expected:&str,size:Option<u64>,mode:Option<u32>,stop:&mut dyn FnMut()->bool)->Result<(),Reason> {
        let uid=self.native.as_ref().ok_or(Reason::SourceChanged)?.uid;
        let index=self.file(parent,name,uid,maximum,false,stop)?;
        let snapshot=self.snapshot(index,maximum,stop)?;
        let group=old.as_ref().map(|v|v.1.identity.4).unwrap_or(self.book.directory(parent)?.gid);
        if snapshot.sha256!=expected||snapshot.identity.4!=group
            ||size.is_some_and(|s|s!=snapshot.identity.6)||mode.is_some_and(|m|m!=snapshot.identity.2) {
            return Err(Reason::SourceChanged)
        }
        let state=self.switch.as_mut().ok_or(Reason::SourceChanged)?;
        if state.returned.len()>=switch::MAX_FILES+3 {return Err(Reason::Capacity)}
        state.returned.push(Returned {old:old.as_ref().map(|v|v.0),old_snapshot:old.map(|v|v.1),successor:index,snapshot,maximum});
        Ok(())
    }
    pub(super) fn switch_returned(&mut self,publication:&GitLocalPublication,stop:&mut dyn FnMut()->bool)->Result<(),Reason> {
        let native=self.native.as_ref().ok_or(Reason::SourceChanged)?;
        let review=self.review.as_ref().ok_or(Reason::SourceChanged)?;
        let state=self.switch.as_ref().ok_or(Reason::SourceChanged)?;
        if !state.returned.is_empty() {return Err(Reason::SourceChanged)}
        let (intent,marker)=publication.switch_for(self.operation_id.as_deref().ok_or(Reason::SourceChanged)?,native,review,
            state.projection.as_ref().ok_or(Reason::SourceChanged)?)?;
        let intent=intent.clone();let review=review.switch_details().ok_or(Reason::SourceChanged)?.clone();
        let names=publication_names(marker,intent.log_enabled).ok_or(Reason::SourceChanged)?;
        for (at,file) in review.files.iter().enumerate() {
            let edge=&self.switch.as_ref().ok_or(Reason::SourceChanged)?.files[at];
            let (parent,name,original)=(edge.parent,edge.name.clone(),edge.original.clone());
            self.switch_successor(parent,&name,original,switch::FILE_LIMIT,&file.target_sha256,Some(file.target_size),Some(file.mode_bits()),stop)?;
        }
        for name in names {
            let native=self.native.as_ref().ok_or(Reason::SourceChanged)?;
            let (parent,leaf,original,maximum,expected)=match *name {
                "logs/HEAD"=>{let edge=self.switch.as_ref().and_then(|s|s.log.as_ref()).ok_or(Reason::SourceChanged)?;
                    (edge.parent,edge.name.clone(),edge.original.clone(),65536,intent.candidate_log.as_str())},
                "HEAD"=>(self.git.ok_or(Reason::SourceChanged)?,b"HEAD".to_vec(),Some((self.indices[1].ok_or(Reason::SourceChanged)?,native.files.head.clone())),2048,intent.candidate_head.as_str()),
                "index"=>(self.git.ok_or(Reason::SourceChanged)?,b"index".to_vec(),Some((self.indices[3].ok_or(Reason::SourceChanged)?,native.files.index.clone().ok_or(Reason::SourceChanged)?)),switch::INDEX_LIMIT,intent.candidate_index.as_str()),
                _=>return Err(Reason::SourceChanged),
            };
            let mode=Some(original.as_ref().map(|v|v.1.identity.2).unwrap_or(0o100600));
            self.switch_successor(parent,&leaf,original,maximum,expected,None,mode,stop)?;
        }
        Ok(())
    }
    pub(super) fn close_switch_book(&mut self,expired:&mut dyn FnMut(Option<(Failure,Instant)>)->bool)->bool {
        let Some(state)=self.switch.as_ref() else {return self.book.close_all()};
        let Some(index)=state.lock else {return self.book.close_all()};
        if self.book.slots[index].state==OriginalState::NoHandle {return self.book.close_all()}
        let Some(parent)=state.target.as_ref().map(|t|t.parent) else {return false};
        let first=self.first_failure();
        if expired(first)||self.check_switch_lock(&mut ||expired(first)).is_err() {return false}
        // SAME slots and one-attempt close helper; no moved-out descriptors,
        // substitute Book, vector reset or synthetic prior-close success.
        let mut known=true;
        for at in (0..self.book.slots.len()).rev() {
            if at!=index&&at!=parent {
                if expired(first) {known=false;break}
                known=SourceBook::close_slot(&mut self.book.slots[at],&mut |_| {
                    // Report to the SAME original failure/cleanup clock. No
                    // fresh timer or later retry window is introduced here.
                    expired(Some((Failure::Unknown,Instant::now())));
                })&&known;
            }
        }
        if !known||expired(first)||self.check_switch_lock(&mut ||expired(first)).is_err() {return false}
        let Some(before)=self.switch.as_ref().and_then(|s|s.parent_locked) else {return false};
        self.switch.as_mut().unwrap().unlink_claimed=true; // Retire BEFORE sole consuming unlink.
        let removed=match self.book.fd(parent) {
            Ok(fd)=>unistd::unlinkat(fd,OsStr::from_bytes(&self.book.slots[index].name),unistd::UnlinkatFlags::NoRemoveDir).is_ok(),
            Err(_)=>false,
        };
        if !removed||expired(first) {return false}
        let after=match self.switch_parent(parent,&mut ||expired(first)) {Ok(v)=>v,Err(_)=>return false};
        let absent=match self.book.fd(parent) {Ok(fd)=>matches!(stat::fstatat(fd,OsStr::from_bytes(&self.book.slots[index].name),AtFlags::AT_SYMLINK_NOFOLLOW),
            Err(nix::errno::Errno::ENOENT)),Err(_)=>false};
        if !switch::parent_transition(before,after)||!absent||expired(first)
            ||self.switch_parent(parent,&mut ||expired(first)).ok()!=Some(after) {return false}
        self.switch.as_mut().unwrap().unlinked=true;
        // Missing/uncertain post-unlink observation above keeps these ORIGINAL
        // FDs held. A close ambiguity below is never retried or called success.
        if !SourceBook::close_slot(&mut self.book.slots[index],&mut |_| {expired(Some((Failure::Unknown,Instant::now())));}) {return false}
        if expired(first)||!SourceBook::close_slot(&mut self.book.slots[parent],&mut |_| {expired(Some((Failure::Unknown,Instant::now())));}) {return false}
        self.book.terminal=true;
        !expired(first)&&self.book.settled()
    }
}

#[cfg(test)]
#[path="git_switch_source_tests.rs"]
mod tests;
