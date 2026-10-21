//! Exact optional upstream-parent facet of the original GitLocal SourceBook.
//! No recursive mkdir, adoption, ref/log/OID write, new job or quota. Original
//! Candidate CAS precedes every mkdir; a lost creation/ACK remains Unknown.
use super::*;
use crate::git_upstream_protocol as upstream;

#[derive(Clone,Copy,PartialEq,Eq)]
enum Creation { Entered, Created, Settled, Collision, Unknown }
struct Created { index:usize, state:Creation }
struct Leaf { name:String,parent:Option<usize>,leaf:Vec<u8>,original:Option<(usize,wire::Snapshot)>,maximum:u64 }
struct ConfigReturn { original:usize, original_snapshot:wire::Snapshot, successor:usize, snapshot:wire::Snapshot }
pub(super) struct State {
    action:upstream::Action, paths:Vec<String>, slots:Vec<(String,usize)>,
    original:Option<upstream::Sources>, current:Vec<upstream::Parent>, leaves:Vec<Leaf>,
    candidate:Option<upstream::Intent>, creations:Vec<Created>, creation_entered:bool,
    directory_digest:Option<String>, returned:bool, retained_scratch:bool, config:Option<ConfigReturn>,
    working_slots:Option<(usize,usize)>,
}
impl State {
    fn new(action:upstream::Action)->Result<Self,Reason> {
        if !action.valid(){return Err(Reason::SourceRefused)}
        let paths=upstream::paths(&upstream::target(&action.remote,&action.branch).ok_or(Reason::SourceRefused)?);
        let mut slots=Vec::new();slots.try_reserve_exact(paths.len()).map_err(|_|Reason::Capacity)?;
        let mut current=Vec::new();current.try_reserve_exact(paths.len()).map_err(|_|Reason::Capacity)?;
        let mut creations=Vec::new();creations.try_reserve_exact(upstream::MAX_MISSING).map_err(|_|Reason::Capacity)?;
        Ok(Self {action,paths,slots,current,creations,original:None,leaves:Vec::new(),candidate:None,
            creation_entered:false,directory_digest:None,returned:false,retained_scratch:false,config:None,working_slots:None})
    }
    pub(super) fn extra(&self)->Option<usize>{self.paths.len().checked_add(5)} // Full path/old leaves/config successor/scratch+index; no reuse credit.
    pub(super) fn working_bytes()->Option<usize>{std::mem::size_of::<Self>().checked_add(1024*1024)}
    fn index(&self,name:&str)->Option<usize>{self.slots.iter().find(|v|v.0==name).map(|v|v.1)}
}
fn full(s:&FileStat)->Result<wire::FileIdentity,Reason> {
    let v=metadata_identity(s)?;
    let ns=|p:(i64,i64)|p.0.checked_mul(1_000_000_000).and_then(|n|n.checked_add(p.1))
        .filter(|_|(0..1_000_000_000).contains(&p.1)).ok_or(Reason::SourceRefused);
    Ok((v.common.dev,v.common.ino,v.common.mode,v.common.uid,v.common.gid,v.nlink,v.size,ns(v.mtime)?,ns(v.ctime)?))
}
fn parent_name(name:&str)->(&str,&str){name.rsplit_once('/').unwrap_or((".",name))}
fn creation_result(r:&Result<(),nix::errno::Errno>)->Creation {match r {Ok(())=>Creation::Created,Err(nix::errno::Errno::EEXIST)=>Creation::Collision,Err(_)=>Creation::Unknown}}
fn parent_room(current:&[upstream::Parent],next:&upstream::Parent)->bool {
    current.iter().chain(std::iter::once(next)).try_fold((0usize,0usize),|(count,bytes),p| {
        let count=count.checked_add(p.names.len())?;
        let bytes=p.names.iter().try_fold(bytes,|n,s|n.checked_add(s.len()))?;
        (count<=upstream::MAX_NAMES&&bytes<=upstream::MAX_NAME_BYTES).then_some((count,bytes))
    }).is_some()
}
impl GitLocalSources {
    pub(crate) fn inspect_upstream(&mut self,root:&RegisteredRoot,runtime_live:usize,id:&str,action:&upstream::Action,
        review:Option<&wire::Review>,stop:&mut dyn FnMut()->bool)->Result<(),Reason> {
        if !self.not_started()||self.upstream.is_some(){return Err(Reason::CleanupUnknown)}
        self.upstream=Some(State::new(action.clone())?);
        self.inspect(root,runtime_live,id,wire::Kind::SetUpstream,review,stop)
    }
    fn upstream_parent(&self,index:usize,name:&str,stop:&mut dyn FnMut()->bool)->Result<upstream::Parent,Reason> {
        checkpoint(stop)?;let held=stat::fstat(self.book.fd(index)?).map_err(|_|Reason::SourceChanged)?;
        let identity=full(&held)?;
        if held.st_flags!=0||!upstream::directory(identity,identity.3){return Err(Reason::SourceRefused)}
        let raw=self.init_names(index,stop)?;
        if raw.len()>upstream::MAX_NAMES||raw.iter().map(Vec::len).sum::<usize>()>upstream::MAX_NAME_BYTES{return Err(Reason::Capacity)}
        // The existing reader reserves its full 4096-entry scratch vector.
        // Retain only this exact bounded roster, not that capacity per parent.
        let names=raw.into_iter().map(|v|String::from_utf8(v).map(|v|v.into_boxed_str().into_string()).map_err(|_|Reason::SourceRefused))
            .collect::<Result<Vec<_>,_>>()?.into_boxed_slice().into_vec();
        checkpoint(stop)?;
        if full(&stat::fstat(self.book.fd(index)?).map_err(|_|Reason::SourceChanged)?)?!=identity{return Err(Reason::SourceChanged)}
        let slot=&self.book.slots[index];
        if let Some(parent)=slot.parent {
            let named=stat::fstatat(self.book.fd(parent)?,OsStr::from_bytes(&slot.name),AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_|Reason::SourceChanged)?;
            if full(&named)?!=identity||named.st_flags!=0{return Err(Reason::SourceChanged)}
        }
        Ok(upstream::Parent{name:name.into(),identity,names})
    }
    pub(super) fn capture_upstream(&mut self,stop:&mut dyn FnMut()->bool)->Result<(),Reason> {
        let state=self.upstream.as_ref().ok_or(Reason::SourceRefused)?;
        if state.original.is_some(){return Err(Reason::SourceChanged)}
        let paths=state.paths.clone();let action=state.action.clone();
        let git=self.git.ok_or(Reason::SourceChanged)?;
        let native=self.native.as_ref().ok_or(Reason::SourceChanged)?.clone();
        let mut missing=Vec::new();
        for name in paths {
            let index=if name=="."{git}else{
                let (parent,leaf)=parent_name(&name);
                let Some(parent_index)=self.upstream.as_ref().and_then(|s|s.index(parent)) else {missing.push(name);continue};
                let original=self.upstream.as_ref().and_then(|s|s.current.iter().find(|v|v.name==parent)).ok_or(Reason::SourceChanged)?.clone();
                if self.upstream_parent(parent_index,parent,stop)?!=original{return Err(Reason::SourceChanged)}
                if original.names.iter().any(|n|n.eq_ignore_ascii_case(leaf)&&n!=leaf){return Err(Reason::SourceRefused)}
                checkpoint(stop)?;
                match stat::fstatat(self.book.fd(parent_index)?,leaf,AtFlags::AT_SYMLINK_NOFOLLOW) {
                    Err(nix::errno::Errno::ENOENT)=>{
                        if original.names.iter().any(|n|n==leaf)||self.upstream_parent(parent_index,parent,stop)?!=original{return Err(Reason::SourceChanged)}
                        missing.push(name);continue
                    },
                    Ok(_)=>self.book.child(parent_index,leaf.as_bytes(),false,stop)?,
                    Err(_)=>return Err(Reason::SourceRefused),
                }
            };
            let row=self.upstream_parent(index,&name,stop)?;
            if row.identity.0!=native.directories.git.0||row.identity.3!=native.uid{return Err(Reason::SourceRefused)}
            let s=self.upstream.as_mut().ok_or(Reason::CleanupUnknown)?;
            // Enforce the original aggregate cap BEFORE retaining another
            // parent, including refusal paths before final Sources validation.
            if !parent_room(&s.current,&row){return Err(Reason::Capacity)}
            s.slots.push((name,index));s.current.push(row);
        }
        let target=upstream::target(&action.remote,&action.branch).ok_or(Reason::SourceRefused)?;
        for (name,maximum) in [(target.clone(),65),(format!("logs/{target}"),128*1024)] {
            let (parent,leaf)=parent_name(&name);let parent=self.upstream.as_ref().and_then(|s|s.index(parent));
            let original=if let Some(parent)=parent {
                checkpoint(stop)?;
                match stat::fstatat(self.book.fd(parent)?,leaf,AtFlags::AT_SYMLINK_NOFOLLOW) {
                    Err(nix::errno::Errno::ENOENT)=>None,
                    Ok(_)=>{let index=self.file(parent,leaf.as_bytes(),native.uid,maximum,false,stop)?;Some((index,self.snapshot(index,maximum,stop)?))},
                    Err(_)=>return Err(Reason::SourceRefused),
                }
            }else{None};
            self.upstream.as_mut().ok_or(Reason::CleanupUnknown)?.leaves.push(Leaf{name:name.clone(),parent,leaf:leaf.as_bytes().to_vec(),original,maximum});
        }
        let s=self.upstream.as_mut().ok_or(Reason::CleanupUnknown)?;
        let projection=upstream::Sources {parents:s.current.clone(),missing,
            reference:s.leaves[0].original.as_ref().map(|v|v.1.clone()),log:s.leaves[1].original.as_ref().map(|v|v.1.clone())};
        if !projection.valid(&native,&action){return Err(Reason::SourceRefused)}
        if let Some(r)=self.review.as_ref().and_then(wire::Review::upstream_details) {
            if !r.matches(&action)||r.missing_directories!=projection.missing||r.original_config!=native.files.config.sha256{return Err(Reason::SourceChanged)}
        }
        s.original=Some(projection);Ok(())
    }
    pub(crate) fn upstream_snapshot(&self)->Result<Option<upstream::Sources>,Reason> {
        if self.first.is_some()||self.finished{return Err(Reason::SourceChanged)}
        self.upstream.as_ref().map(|s|s.original.clone().ok_or(Reason::SourceRefused)).transpose()
    }
    fn upstream_raw_config(&self,stop:&mut dyn FnMut()->bool)->Result<Vec<u8>,Reason> {
        let index=self.indices[2].ok_or(Reason::SourceChanged)?;
        let original=self.native.as_ref().ok_or(Reason::SourceChanged)?.files.config.clone();
        if original.identity.6>upstream::CONFIG_LIMIT{return Err(Reason::Capacity)}
        let mut raw=Vec::new();raw.try_reserve_exact(original.identity.6 as usize+1).map_err(|_|Reason::Capacity)?;
        unistd::lseek(self.book.fd(index)?,0,unistd::Whence::SeekSet).map_err(|_|Reason::SourceRefused)?;
        let mut buffer=[0u8;32768];
        loop {checkpoint(stop)?;let cap=buffer.len().min(original.identity.6 as usize+1-raw.len());
            let count=unistd::read(self.book.fd(index)?,&mut buffer[..cap]).map_err(|_|Reason::SourceRefused)?;
            if count==0{break}raw.extend_from_slice(&buffer[..count]);if raw.len()>original.identity.6 as usize{return Err(Reason::SourceChanged)}
        }
        if upstream::hash(&raw)!=original.sha256||self.snapshot(index,upstream::CONFIG_LIMIT,stop)?!=original{return Err(Reason::SourceChanged)}
        Ok(raw)
    }
    pub(crate) fn before_upstream_candidate(&mut self,intent:&wire::Intent,stop:&mut dyn FnMut()->bool)->Result<(),Reason> {
        let i=intent.upstream_details().ok_or(Reason::SourceRefused)?.clone();
        let r=self.review.as_ref().and_then(wire::Review::upstream_details).ok_or(Reason::SourceRefused)?.clone();
        let s=self.upstream.as_ref().ok_or(Reason::SourceRefused)?;
        if s.candidate.is_some()||!i.matches(&r){return Err(Reason::SourceChanged)}
        let root=s.original.as_ref().and_then(|v|v.parents.first()).ok_or(Reason::SourceChanged)?.clone();
        let git=self.git.ok_or(Reason::SourceChanged)?;
        let current=self.upstream_parent(git,".",stop)?;
        let mut expected=root.names.clone();expected.extend(["config.lock".into(),"index.lock".into(),"HEAD.lock".into(),i.working.scratch.clone()]);expected.sort();
        if !upstream::same_directory(root.identity,current.identity)||current.identity!=i.working.root||current.names!=expected{return Err(Reason::SourceChanged)}
        for (name,identity) in ["config.lock","index.lock","HEAD.lock"].iter().zip(i.working.locks) {
            let v=stat::fstatat(self.book.fd(git)?,*name,AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_|Reason::SourceChanged)?;
            if full(&v)?!=identity||v.st_flags!=0{return Err(Reason::SourceChanged)}
        }
        // Scratch name/inode belongs to the actual worker's candidate. Open it
        // as an original SourceBook entry so nested index comparison never
        // follows a slash through a mutable symlink. It survives worker unlink.
        let scratch=self.book.child(git,i.working.scratch.as_bytes(),false,stop)?;
        let observed=self.upstream_parent(scratch,&i.working.scratch,stop)?;
        if observed.identity!=i.working.scratch_identity||observed.names!=["index"]{return Err(Reason::SourceChanged)}
        let index=self.file(scratch,b"index",i.working.root.3,1024*1024,false,stop)?;
        let snap=self.snapshot(index,1024*1024,stop)?;
        if snap.identity!=i.working.index_identity||snap.sha256!=i.expected_index{return Err(Reason::SourceChanged)}
        let raw=self.upstream_raw_config(stop)?;
        if upstream::appended(&raw,&r.additions).is_none_or(|b|upstream::hash(&b)!=i.candidate_config){return Err(Reason::SourceChanged)}
        let s=self.upstream.as_mut().ok_or(Reason::CleanupUnknown)?;
        s.working_slots=Some((scratch,index));
        s.current[0]=current;s.candidate=Some(i);
        self.post_inner(stop)
    }
    fn upstream_create(&mut self,name:&str,stop:&mut dyn FnMut()->bool)->Result<(),Reason> {
        let (parent_name,leaf)=parent_name(name);
        let parent=self.upstream.as_ref().and_then(|s|s.index(parent_name)).ok_or(Reason::SourceChanged)?;
        let original=self.upstream.as_ref().and_then(|s|s.current.iter().find(|p|p.name==parent_name)).ok_or(Reason::SourceChanged)?.clone();
        if self.upstream_parent(parent,parent_name,stop)?!=original{return Err(Reason::SourceChanged)}
        checkpoint(stop)?;
        if !matches!(stat::fstatat(self.book.fd(parent)?,leaf,AtFlags::AT_SYMLINK_NOFOLLOW),Err(nix::errno::Errno::ENOENT)){return Err(Reason::SourceChanged)}
        let index=self.book.reserve(Some(parent),leaf.as_bytes())?;
        let s=self.upstream.as_mut().ok_or(Reason::CleanupUnknown)?;
        if s.creations.len()>=upstream::MAX_MISSING{return Err(Reason::Capacity)}
        s.creations.push(Created{index,state:Creation::Entered}); // BEFORE syscall, no lost mkdir is absence.
        let result=stat::mkdirat(self.book.fd(parent)?,leaf,Mode::from_bits_truncate(0o700));
        self.upstream.as_mut().ok_or(Reason::CleanupUnknown)?.creations.last_mut().ok_or(Reason::CleanupUnknown)?.state=creation_result(&result);
        if result.is_err(){self.book.slots[index].state=OriginalState::NoHandle;return Err(Reason::CleanupUnknown)}
        checkpoint(stop)?;
        self.book.slots[index].state=OriginalState::Acquiring;
        let opened=fcntl::openat(self.book.fd(parent)?,leaf,directory_flags(),Mode::empty());self.book.adopt(index,opened)?;
        let held=stat::fstat(self.book.fd(index)?).map_err(|_|Reason::SourceChanged)?;
        let expected=directory_identity(&held)?;
        if expected.dev!=original.identity.0||expected.uid!=original.identity.3||expected.gid!=original.identity.4
            ||expected.mode&0o7777!=0o700||held.st_flags!=0{return Err(Reason::SourceChanged)}
        self.book.slots[index].identity=Some(Identity::Directory(expected));
        filesystem(self.book.fd(index)?,stop)?;
        checkpoint(stop)?;unistd::fsync(self.book.fd(index)?).map_err(|_|Reason::SourceChanged)?;
        checkpoint(stop)?;unistd::fsync(self.book.fd(parent)?).map_err(|_|Reason::SourceChanged)?;
        let child=self.upstream_parent(index,name,stop)?;
        let successor=self.upstream_parent(parent,parent_name,stop)?;
        let mut names=original.names.clone();names.push(leaf.into());names.sort();
        if !child.names.is_empty()||!upstream::same_directory(original.identity,successor.identity)||successor.names!=names{return Err(Reason::SourceChanged)}
        let s=self.upstream.as_mut().ok_or(Reason::CleanupUnknown)?;
        s.slots.push((name.into(),index));
        *s.current.iter_mut().find(|v|v.name==parent_name).ok_or(Reason::SourceChanged)?=successor;
        s.current.push(child);
        self.post_inner(stop)?;
        self.upstream.as_mut().ok_or(Reason::CleanupUnknown)?.creations.last_mut().ok_or(Reason::CleanupUnknown)?.state=Creation::Settled;
        Ok(())
    }
    pub(crate) fn create_upstream_directories(&mut self,intent:&wire::Intent,stop:&mut dyn FnMut()->bool)->Result<String,Reason> {
        let i=intent.upstream_details().ok_or(Reason::SourceRefused)?.clone();
        let s=self.upstream.as_mut().ok_or(Reason::SourceRefused)?;
        if s.candidate.as_ref()!=Some(&i)||s.creation_entered||s.directory_digest.is_some(){return Err(Reason::CleanupUnknown)}
        s.creation_entered=true;
        for name in &i.missing_directories {if let Err(e)=self.upstream_create(name,stop){self.retain_upstream_unknown();return Err(e)}}
        if let Err(e)=self.post_inner(stop){self.retain_upstream_unknown();return Err(e)}
        let s=self.upstream.as_mut().ok_or(Reason::CleanupUnknown)?;
        let paths=&s.paths;
        s.current.sort_by_key(|p|paths.iter().position(|n|n==&p.name).unwrap_or(usize::MAX));
        let digest=upstream::directory_digest(&i,&s.original.as_ref().ok_or(Reason::SourceChanged)?.parents,&s.current).map_err(|_|Reason::SourceChanged)?;
        s.directory_digest=Some(digest.clone());Ok(digest)
    }
    pub(super) fn post_upstream(&self,stop:&mut dyn FnMut()->bool)->Result<(),Reason> {
        let Some(s)=&self.upstream else{return Ok(())};
        for p in &s.current {let index=s.index(&p.name).ok_or(Reason::SourceChanged)?;
            if self.upstream_parent(index,&p.name,stop)?!=*p{return Err(Reason::SourceChanged)}}
        let original=s.original.as_ref().ok_or(Reason::SourceChanged)?;
        for name in &original.missing {if s.index(name).is_some(){continue}let (parent,leaf)=parent_name(name);
            if let Some(parent)=s.index(parent) {checkpoint(stop)?;if !matches!(stat::fstatat(self.book.fd(parent)?,leaf,AtFlags::AT_SYMLINK_NOFOLLOW),Err(nix::errno::Errno::ENOENT)){return Err(Reason::SourceChanged)}}
        }
        for edge in &s.leaves {
            if let Some((index,snapshot))=&edge.original {if self.snapshot(*index,edge.maximum,stop)?!=*snapshot{return Err(Reason::SourceChanged)}}
            else {let parent=edge.parent.or_else(||s.index(parent_name(&edge.name).0));if let Some(parent)=parent {
                checkpoint(stop)?;if !matches!(stat::fstatat(self.book.fd(parent)?,OsStr::from_bytes(&edge.leaf),AtFlags::AT_SYMLINK_NOFOLLOW),Err(nix::errno::Errno::ENOENT)){return Err(Reason::SourceChanged)}
            }}
        }
        if let Some(c)=&s.config {
            if self.snapshot(c.successor,upstream::CONFIG_LIMIT,stop)?!=c.snapshot{return Err(Reason::SourceChanged)}
        }
        if let (Some(i),Some((scratch,index)))=(&s.candidate,s.working_slots) {
            if s.returned&&!s.retained_scratch {
                let a=stat::fstat(self.book.fd(scratch)?).map_err(|_|Reason::SourceChanged)?;
                let b=stat::fstat(self.book.fd(index)?).map_err(|_|Reason::SourceChanged)?;
                self.upstream_retired_identity(scratch,&a)?;self.upstream_retired_identity(index,&b)?;
                let hashed=self.snapshot_identity(index,file_identity(&b)?,wire::INDEX_LIMIT,stop)?;
                if hashed.sha256!=i.expected_index{return Err(Reason::SourceChanged)}
            }else{
                let row=self.upstream_parent(scratch,&i.working.scratch,stop)?;
                if row.identity!=i.working.scratch_identity||row.names!=["index"]
                    ||self.snapshot(index,wire::INDEX_LIMIT,stop)?!=(wire::Snapshot{identity:i.working.index_identity,sha256:i.expected_index.clone()}){return Err(Reason::SourceChanged)}
            }
        }
        Ok(())
    }
    pub(super) fn upstream_is_old(&self,index:usize)->bool {
        self.upstream.as_ref().is_some_and(|s|s.config.as_ref().is_some_and(|c|c.original==index))
    }
    pub(super) fn upstream_old_identity(&self,index:usize,held:&FileStat)->Result<FileIdentity,Reason> {
        let c=self.upstream.as_ref().and_then(|s|s.config.as_ref()).filter(|c|c.original==index).ok_or(Reason::SourceChanged)?;
        let Some(Identity::File(old))=self.book.slots[index].identity else{return Err(Reason::SourceChanged)};
        let Some(Identity::File(new))=self.book.slots[c.successor].identity else{return Err(Reason::SourceChanged)};
        let actual=file_identity(held)?;
        if !unlinked_original(actual,old,new,held.st_flags as u64){return Err(Reason::SourceChanged)}Ok(actual)
    }
    pub(super) fn upstream_snapshot_original(&self,index:usize,maximum:u64,stop:&mut dyn FnMut()->bool)->Result<wire::Snapshot,Reason> {
        let c=self.upstream.as_ref().and_then(|s|s.config.as_ref()).filter(|c|c.original==index).ok_or(Reason::SourceChanged)?;
        let held=stat::fstat(self.book.fd(index)?).map_err(|_|Reason::SourceChanged)?;
        let actual=self.upstream_old_identity(index,&held)?;
        if self.snapshot_identity(index,actual,maximum,stop)?.sha256!=c.original_snapshot.sha256{return Err(Reason::SourceChanged)}
        Ok(c.original_snapshot.clone())
    }
    pub(super) fn upstream_is_retired_working(&self,index:usize)->bool {
        self.upstream.as_ref().is_some_and(|s|s.returned&&!s.retained_scratch&&s.working_slots.is_some_and(|(a,b)|index==a||index==b))
    }
    pub(super) fn upstream_retired_identity(&self,index:usize,held:&FileStat)->Result<(),Reason> {
        let s=self.upstream.as_ref().filter(|_|self.upstream_is_retired_working(index)).ok_or(Reason::SourceChanged)?;
        let i=s.candidate.as_ref().ok_or(Reason::SourceChanged)?;
        let (scratch,file)=s.working_slots.ok_or(Reason::SourceChanged)?;
        let actual=full(held)?;
        let old=if index==scratch {i.working.scratch_identity}else if index==file {i.working.index_identity}else{return Err(Reason::SourceChanged)};
        if !upstream::same_directory(actual,old)||actual.5!=0||held.st_flags!=0
            || index==file && (actual.6!=old.6||actual.7!=old.7){return Err(Reason::SourceChanged)}
        // Only this original positive worker publication/cleanup grants a
        // named-absence exception. The old FD itself remains in SourceBook.
        let slot=&self.book.slots[index];let parent=slot.parent.ok_or(Reason::SourceChanged)?;
        if !matches!(stat::fstatat(self.book.fd(parent)?,OsStr::from_bytes(&slot.name),AtFlags::AT_SYMLINK_NOFOLLOW),Err(nix::errno::Errno::ENOENT)){return Err(Reason::SourceChanged)}
        Ok(())
    }
    pub(super) fn upstream_returned(&mut self,publication:&GitLocalPublication,stop:&mut dyn FnMut()->bool)->Result<(),Reason> {
        let s=self.upstream.as_ref().ok_or(Reason::SourceChanged)?;
        let (intent,final_state)=publication.upstream_for(self.operation_id.as_deref().ok_or(Reason::SourceChanged)?,
            self.native.as_ref().ok_or(Reason::SourceChanged)?,self.review.as_ref().ok_or(Reason::SourceChanged)?,
            s.original.as_ref().ok_or(Reason::SourceChanged)?)?;
        let (intent,final_state)=(intent.clone(),final_state.clone());
        if s.returned||s.candidate.as_ref()!=Some(&intent)||s.directory_digest.is_none()
            ||s.creations.iter().any(|c|c.state!=Creation::Settled){return Err(Reason::CleanupUnknown)}
        let git=self.git.ok_or(Reason::SourceChanged)?;
        let retained=final_state.retained_paths.contains(&format!(".git/{}",intent.working.scratch));
        let root=s.current.iter().find(|p|p.name==".").ok_or(Reason::SourceChanged)?.clone();
        let mut expected=root.names.clone();expected.retain(|n|!matches!(n.as_str(),"config.lock"|"index.lock"|"HEAD.lock")&&(retained||n!=&intent.working.scratch));
        let current=self.upstream_parent(git,".",stop)?;
        if !upstream::same_directory(root.identity,current.identity)||current.names!=expected{return Err(Reason::SourceChanged)}
        if final_state.effect_phase=="config-returned" {
            let old=self.indices[2].ok_or(Reason::SourceChanged)?;
            let original=self.native.as_ref().ok_or(Reason::SourceChanged)?.files.config.clone();
            let index=self.file(git,b"config",original.identity.3,upstream::CONFIG_LIMIT,false,stop)?;
            let snapshot=self.snapshot(index,upstream::CONFIG_LIMIT,stop)?;
            if snapshot.sha256!=intent.candidate_config||snapshot.identity.2!=original.identity.2
                ||snapshot.identity.3!=original.identity.3||snapshot.identity.4!=original.identity.4
                ||(snapshot.identity.0,snapshot.identity.1)==(original.identity.0,original.identity.1){return Err(Reason::SourceChanged)}
            self.upstream.as_mut().ok_or(Reason::CleanupUnknown)?.config=Some(ConfigReturn{original:old,original_snapshot:original,successor:index,snapshot});
        }
        let s=self.upstream.as_mut().ok_or(Reason::CleanupUnknown)?;
        *s.current.iter_mut().find(|p|p.name==".").ok_or(Reason::SourceChanged)?=current;
        s.retained_scratch=retained;s.returned=true;
        self.post_inner(stop)
    }
    pub(super) fn upstream_retirable(&self)->bool {
        self.upstream.as_ref().is_none_or(|s|(!s.creation_entered&&s.candidate.is_none())
            ||s.returned&&s.directory_digest.is_some()&&s.creations.iter().all(|c|c.state==Creation::Settled))
    }
    pub(crate) fn retain_upstream_unknown(&mut self){self.first.get_or_insert(Reason::CleanupUnknown);self.close_failed=true;}
}

#[cfg(test)]
#[path="git_upstream_source_tests.rs"]
mod tests;
