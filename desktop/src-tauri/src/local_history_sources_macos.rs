//! Actual held source originals, nested in asset_source_macos. This is neither a
//! picker receipt nor a new filesystem walker. Project lock is a duplicate of
//! the exact SourceBook root OFD, shared by parent, Python and local helper.
use super::*;
use std::os::fd::AsRawFd;
use mrk_macos_installed_native::{local_account::Account,local_keychain_wire::ProjectRoot,local_project_lease::ProjectLease};
pub(crate) struct LocalHistorySources {
    book:SourceBook, account:Account, project:Option<(usize,RegisteredRoot)>,home:Option<usize>,
    lease:Option<Arc<ProjectLease>>,failed:bool,finished:bool,
}
impl LocalHistorySources {
    pub(crate) fn new()->Self{Self{book:SourceBook::new(),account:Account::new(),project:None,home:None,lease:None,failed:false,finished:false}}
    pub(crate) fn acquire(&mut self,root:&RegisteredRoot,runtime_live:usize,stop:&mut dyn FnMut()->bool)->Result<(),Reason>{
        if !self.book.not_started() || self.finished || self.failed{return Err(Reason::CleanupUnknown);}
        let result=(||{
            checkpoint(stop)?;self.account.acquire().map_err(|_|Reason::SourceRefused)?;checkpoint(stop)?;
            let (home,uid,_)=self.account.selected().map_err(|_|Reason::SourceRefused)?;
            let home=PathBuf::from(home);let project_parts=parts(&root.path)?;let home_parts=parts(&home)?;
            // Distinct path opens are conservatively counted, never inode-
            // deduplicated FD slots. Reserve parent Python pipes/spawn + full
            // simultaneous helper inspection/gate/pipes, plus original lease.
            // CodeOriginals has thirteen fixed code slots plus its one gate.
            // A single Command spawn reserves three pipe pairs + its error
            // pipe. The Python child already holds three parent pipe ends.
            // Baseline/slack is conservative; this is an operation-owned
            // parent FD quote, not a whole-Tauri/RLIMIT or helper-process claim.
            const FUTURE_PARENT:usize=13+1+8+3+1+3+4;
            let slots=roster_limit([project_parts.len(),home_parts.len()],0)?;
            if slots.checked_add(runtime_live).and_then(|n|n.checked_add(FUTURE_PARENT)).is_none_or(|n|n>256){return Err(Reason::Capacity);}
            self.book.begin(slots,0,0)?;
            self.book.root(stop)?;
            let (project,_) = self.book.chain(&project_parts,false,stop)?;
            let index=*project.last().ok_or(Reason::SourceRefused)?;
            let identity=self.book.directory(index)?;
            if ProjectIdentity::Posix(identity)!=root.identity || identity.uid!=uid || identity.mode&0o7022!=0{return Err(Reason::SourceChanged);}
            self.project=Some((index,root.clone()));
            let (home,_) = self.book.chain(&home_parts,false,stop)?;
            let h=*home.last().ok_or(Reason::SourceRefused)?;let hi=self.book.directory(h)?;
            if hi.uid!=uid || hi.mode&0o7022!=0 || home.iter().any(|i|self.book.directory(*i).is_ok_and(|id|id.same_object(identity))){return Err(Reason::ProjectOverlap);}
            self.home=Some(h);self.book.terminal_check(stop)?;
            // Retain the original before acquiring any duplicate/lock effect.
            self.lease=Some(Arc::new(ProjectLease::new()));
            let lease=Arc::get_mut(self.lease.as_mut().unwrap()).ok_or(Reason::CleanupUnknown)?;
            let original=self.book.fd(index)?.as_fd();
            lease.enter(original,ProjectRoot{device:identity.dev,inode:identity.ino,mode:identity.mode,uid:identity.uid,gid:identity.gid,
                descriptor:original.as_raw_fd() as u32}).map_err(|_|Reason::SourceRefused)?;
            self.post(stop)
        })();
        if result.is_err(){self.failed=true;}result
    }
    pub(crate) fn post(&mut self,stop:&mut dyn FnMut()->bool)->Result<(),Reason>{
        if self.finished || self.failed || self.project.is_none() || self.home.is_none(){return Err(Reason::CleanupUnknown);}
        let result=(||{
            self.account.selected().map_err(|_|Reason::SourceChanged)?;self.book.terminal_check(stop)?;
            self.lease.as_ref().ok_or(Reason::CleanupUnknown)?.checked().map_err(|_|Reason::SourceChanged)?;Ok(())
        })();if result.is_err(){self.failed=true;}result
    }
    pub(crate) fn lease(&self)->Result<Arc<ProjectLease>,Reason>{
        if self.finished || self.failed{return Err(Reason::CleanupUnknown);}
        let lease=self.lease.as_ref().ok_or(Reason::CleanupUnknown)?;lease.checked().map_err(|_|Reason::SourceChanged)?;Ok(lease.clone())
    }
    pub(crate) fn home(&self)->Result<&str,Reason>{self.account.selected().map(|v|v.0).map_err(|_|Reason::SourceRefused)}
    pub(crate) fn live_count(&self)->usize{
        self.book.slots.iter().filter(|s|!matches!(s.state,OriginalState::Reserved|OriginalState::NoHandle|OriginalState::Closed)).count()
            +self.lease.as_ref().map_or(0,|l|l.active_count())
    }
    pub(crate) fn retained_bytes(&self)->Option<usize>{
        self.book.retained_bytes()?.checked_add(std::mem::size_of::<Self>())?
            .checked_add(self.project.as_ref().map_or(0,|(_,r)|r.path.capacity()))?
            .checked_add(std::mem::size_of::<ProjectLease>()+2*std::mem::size_of::<usize>())
    }
    pub(crate) fn close(&mut self,stop:&mut dyn FnMut()->bool)->Result<(),Reason>{
        if self.finished{return if self.settled(){Ok(())}else{Err(Reason::CleanupUnknown)};}
        // The same owner must first join every child/helper and retire every Arc
        // loan. Unknown still owns its debit/lock; never close it via raw number.
        let unique=self.lease.as_ref().is_none_or(|l|Arc::strong_count(l)==1);
        if !unique{self.failed=true;return Err(Reason::CleanupUnknown);}
        let post=if self.failed{Err(Reason::SourceChanged)}else if self.project.is_some(){self.post(stop)}else{Ok(())};
        self.finished=true;
        let closed=self.book.close_all();
        let lease=self.lease.as_mut().is_none_or(|l|Arc::get_mut(l).is_some_and(ProjectLease::close));
        if !closed || !lease || !self.account.call_settled(){self.failed=true;return Err(Reason::CleanupUnknown);}
        post
    }
    pub(crate) fn settled(&self)->bool{self.finished && self.book.settled() && self.account.call_settled()
        &&self.lease.as_ref().is_none_or(|l|l.settled())}
}
