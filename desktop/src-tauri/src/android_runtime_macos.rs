//! Android-only runtime accounting over the existing original Mac Book.
//! Sibling runtime facades keep their existing implementation; this module does
//! not claim their opaque ACL cleanup behavior has been corrected.
use super::*;
use std::sync::Mutex;
use native::vault_filesystem::{Expected, Failure as SnapshotFailure, Policy, SnapshotBook};

pub(super) struct Audit {
    frame: Option<SnapshotBook>, arm_entered: bool, cutoff: watch::Receiver<Instant>,
    context: Option<(Instant,Option<watch::Receiver<bool>>)>,
    first: Option<(AdmissionFailure,Instant)>,
}
fn map_failure(failure:SnapshotFailure) -> AdmissionFailure { match failure {
    SnapshotFailure::Refused=>AdmissionFailure::Ownership,
    SnapshotFailure::Native=>AdmissionFailure::Native,
    SnapshotFailure::Bounds=>AdmissionFailure::Bounds,
    SnapshotFailure::Stopped=>AdmissionFailure::Stopped,
    SnapshotFailure::Unknown=>AdmissionFailure::Unknown,
} }
// Shared deadline DATA for the existing independent FD consumers. A native
// refusal is not itself a close veto: only the original absolute cleanup
// projection (or its lost sender) denies a further positive consume.
pub(super) fn fd_cleanup_expired_at(end:Instant,cleanup:&watch::Receiver<Instant>,
    first:Option<Instant>,now:Instant) -> bool {
    let endpoint=first.and_then(|at|at.checked_add(std::time::Duration::from_secs(10)))
        .map_or(end,|at|end.min(at));
    cleanup.has_changed().is_err() || now>=endpoint.min(*cleanup.borrow())
}
impl Audit {
    /// Inert reservation only. The original registered inspector owns the sole
    /// native allocation attempt after its existing entry barrier releases.
    fn new(cutoff:watch::Receiver<Instant>) -> Self {
        Self {frame:None,arm_entered:false,cutoff,context:None,first:None}
    }
    fn first_failure(&self) -> Option<(AdmissionFailure,Instant)> {
        match(self.first,self.frame.as_ref().and_then(SnapshotBook::first_failure).map(|(f,at)|(map_failure(f),at))) {
            (Some(a),Some(b))=>Some(if a.1<=b.1{a}else{b}), (a,b)=>a.or(b),
        }
    }
    fn note(&mut self,failure:AdmissionFailure) {
        let observed=self.frame.as_ref().and_then(SnapshotBook::first_failure).map(|(f,at)|(map_failure(f),at))
            .unwrap_or((failure,Instant::now()));
        if self.first.is_none_or(|(_,at)|observed.1<at){self.first=Some(observed);}
    }
    fn arm_once(&mut self,end:Instant,stop:&watch::Receiver<bool>) -> Result<()> {
        let check=|audit:&Self| -> Result<()> {
            if audit.cutoff.has_changed().is_err(){return Err(AdmissionFailure::Unknown);}
            if Instant::now()>=end.min(*audit.cutoff.borrow()){return Err(AdmissionFailure::Deadline);}
            if *stop.borrow() || stop.has_changed().is_err(){return Err(AdmissionFailure::Stopped);}
            Ok(())
        };
        let result=(|| {
            if self.arm_entered || self.frame.is_some(){return Err(AdmissionFailure::AlreadyUsed);}
            check(self)?;
            // Entered+None is uncertain after unwind/lost return, never zero.
            // Store even an unsuccessful returned frame before any next check.
            self.arm_entered=true;
            self.frame=Some(SnapshotBook::new());
            if self.frame.as_ref().is_none_or(|frame|frame.retained_frame_bytes()==0
                || frame.retained_frame_bytes()>16_384 || !frame.not_started()){
                return Err(AdmissionFailure::Bounds);
            }
            check(self)
        })();
        if let Err(failure)=result {self.note(failure);}
        result
    }
    fn begin(&mut self,end:Instant,stop:Option<&watch::Receiver<bool>>) {
        // Context update only. Prepare/audit can never allocate another frame.
        self.context=Some((end,stop.cloned()));
    }
    pub(super) fn observe(&mut self,fd:std::os::fd::BorrowedFd<'_>,identity:Identity,flags:u32) -> Result<()> {
        let (end,stop)=self.context.clone().ok_or(AdmissionFailure::Unknown)?;
        let expected=Expected{device:u64::try_from(identity.dev).map_err(|_|AdmissionFailure::Identity)?,
            inode:identity.ino,mode:u32::from(identity.mode),owner:identity.uid,group:identity.gid,flags};
        let cutoff=self.cutoff.clone();
        let result=match self.frame.as_mut() {
            Some(frame) if self.arm_entered=>frame.observe(fd,expected,Policy::Empty,&mut || {
                cutoff.has_changed().is_err() || Instant::now()>=if stop.is_some(){end}else{end.min(*cutoff.borrow())}
                    || stop.as_ref().is_some_and(|stop|*stop.borrow() || stop.has_changed().is_err())
            }).map_err(map_failure),
            _=>Err(AdmissionFailure::Unknown),
        };
        if let Err(failure)=result {self.note(failure);}
        result
    }
    fn retained_bytes(&self) -> Option<usize> {
        match self.frame.as_ref(){
            Some(frame)=>frame.quiescent().then(||frame.retained_frame_bytes()),
            None=>(!self.arm_entered).then_some(0),
        }
    }
    fn release(&mut self,end:Instant,cleanup:&watch::Receiver<Instant>,publish:&mut dyn FnMut(AdmissionFailure,Instant)) -> bool {
        let original=self.first_failure();
        if let Some((failure,at))=original {publish(failure,at);}
        // Release follows the original cleanup projection, not the already
        // expired integrity/audit clock. No new watch channel or time grant.
        let cutoff=cleanup.clone();
        let released=match self.frame.as_mut() {
            Some(frame)=>frame.release(&mut |failure| {
                if let Some((failure,at))=failure {publish(map_failure(failure),at);}
                let first=match(original,failure) {
                    (Some((_,a)),Some((_,b)))=>Some(a.min(b)),
                    (Some((_,at)),None)|(None,Some((_,at)))=>Some(at), _=>None,
                };
                let endpoint=first.and_then(|at|at.checked_add(std::time::Duration::from_secs(10))).map_or(end,|at|end.min(at));
                cutoff.has_changed().is_err() || Instant::now()>=endpoint.min(*cutoff.borrow())
            }),
            None=>!self.arm_entered,
        };
        if !released {self.note(AdmissionFailure::Unknown);}
        if let Some((failure,at))=self.first_failure(){publish(failure,at);}
        released
    }
    pub(super) fn settled(&self) -> bool {
        match self.frame.as_ref(){
            Some(frame)=>frame.settled() && frame.retained_frame_bytes()==0,
            None=>!self.arm_entered,
        }
    }
}
impl Book {
    fn new_android(cutoff:watch::Receiver<Instant>) -> Self {
        let mut original=Self::new();
        original.android_acl=Some(Mutex::new(Audit::new(cutoff)));
        original
    }
    fn android_arm_once(&self,end:Instant,stop:&watch::Receiver<bool>) -> Result<()> {
        self.android_acl.as_ref().ok_or(AdmissionFailure::Unknown)?
            .lock().map_err(|_|AdmissionFailure::Unknown)?.arm_once(end,stop)
    }
    fn android_begin(&self,end:Instant,stop:Option<&watch::Receiver<bool>>) -> Result<()> {
        self.android_acl.as_ref().ok_or(AdmissionFailure::Unknown)?
            .lock().map_err(|_|AdmissionFailure::Unknown)?.begin(end,stop);
        Ok(())
    }
    fn android_note(&self,failure:AdmissionFailure) {
        if let Some(audit)=&self.android_acl {
            match audit.lock(){Ok(mut audit)=>audit.note(failure),Err(error)=>error.into_inner().note(AdmissionFailure::Unknown)}
        }
    }
    fn android_first_failure(&self) -> Option<(AdmissionFailure,Instant)> {
        self.android_acl.as_ref().and_then(|audit|match audit.lock() {
            Ok(audit)=>audit.first_failure(),
            Err(error)=>{let mut audit=error.into_inner();audit.note(AdmissionFailure::Unknown);audit.first_failure()},
        })
    }
    fn android_retained_bytes(&self) -> Option<usize> {
        self.android_acl.as_ref()?.try_lock().ok()?.retained_bytes()
    }
    fn android_fd_cleanup_expired(&mut self,end:Instant,cleanup:&watch::Receiver<Instant>,
        publish:&mut dyn FnMut(AdmissionFailure,Instant)) -> bool {
        let first=self.android_first_failure();
        if let Some((failure,at))=first {publish(failure,at);}
        let expired=fd_cleanup_expired_at(end,cleanup,first.map(|(_,at)|at),Instant::now());
        if expired {
            self.unknown=true;self.android_note(AdmissionFailure::Unknown);
            if let Some((failure,at))=self.android_first_failure(){publish(failure,at);}
        }
        expired
    }
    fn android_settle(&mut self,end:Instant,cleanup:&watch::Receiver<Instant>,publish:&mut dyn FnMut(AdmissionFailure,Instant)) -> CloseOutcome {
        if self.closed {publish(AdmissionFailure::Unknown,Instant::now());return CloseOutcome::Unknown;}
        let released=match &self.android_acl {
            Some(audit)=>match audit.lock() {
                Ok(mut audit)=>audit.release(end,cleanup,publish),
                Err(error)=>{self.unknown=true;let mut audit=error.into_inner();audit.note(AdmissionFailure::Unknown);audit.release(end,cleanup,publish)},
            },
            None=>false,
        };
        if !released{self.unknown=true;publish(AdmissionFailure::Unknown,Instant::now());}
        // Native refusal cannot suppress independent known, one-attempt FD
        // closes while ORIGINAL cleanup time remains. Expiry retains positives;
        // a late real return is recorded once, never retried or called settled.
        for index in (0..self.records.len()).rev() {
            if self.records[index].state==State::Owned {
                if self.android_fd_cleanup_expired(end,cleanup,publish) {continue;}
                if !self.close(index) {self.android_note(AdmissionFailure::Unknown);}
                let _=self.android_fd_cleanup_expired(end,cleanup,publish);
            } else if !self.close(index) {self.android_note(AdmissionFailure::Unknown);}
            if let Some((failure,at))=self.android_first_failure(){publish(failure,at);}
        }
        self.closed=true;
        if self.settled(){CloseOutcome::Settled}else{CloseOutcome::Unknown}
    }
}
pub(crate) struct AndroidBuildRuntimeSlots {
    inspection:Option<Book>, acquisition:Option<AndroidBuildInstalledRuntime>,
    selection:Option<VerifiedRuntime>, settlement:bool,
}
pub(crate) struct AndroidBuildInstalledRuntime { original:Book, selection:VerifiedRuntime, claimed:bool }
impl AndroidBuildInstalledRuntime {
    pub(crate) fn prepare_once(&mut self,end:Instant,stop:&watch::Receiver<bool>) -> Result<&VerifiedRuntime> {
        if self.claimed {return Err(AdmissionFailure::AlreadyUsed);}
        self.original.android_begin(end,Some(stop))?;
        if let Err(failure)=self.original.prepare(end,stop){self.original.android_note(failure);return Err(failure);}
        Ok(&self.selection)
    }
    pub(crate) fn claim_once(&mut self) -> Result<()> {
        if self.claimed || !self.original.prepared || self.original.unknown || self.original.closed
            || self.original.android_first_failure().is_some(){return Err(AdmissionFailure::AlreadyUsed);}
        self.claimed=true;Ok(())
    }
}
impl AndroidBuildRuntimeSlots {
    pub(crate) fn new(cutoff:watch::Receiver<Instant>) -> Self {
        Self {inspection:Some(Book::new_android(cutoff)),acquisition:None,selection:None,settlement:false}
    }
    pub(crate) fn never_started(&self) -> bool {
        !self.settlement && self.selection.is_none() && self.acquisition.is_none()
            && self.inspection.as_ref().is_some_and(|b|!b.started && b.records.is_empty() && !b.unknown
                && b.android_first_failure().is_none())
    }
    pub(crate) fn inspect_once(&mut self,profile:runtime::AndroidBuildInstalledProfile,end:Instant,stop:&watch::Receiver<bool>) -> std::result::Result<VerifiedRuntime,BridgeError> {
        if !self.never_started(){return Err(BridgeError::cleanup_unknown());}
        self.selection=Some(profile.selection()?);
        let selected=self.selection.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        let original=self.inspection.as_mut().ok_or_else(BridgeError::cleanup_unknown)?;
        // This method is entered only by the already registered original
        // blocking inspector after its existing GO barrier. No coordinator,
        // registry or replacement task performs the native allocation.
        let result=original.android_arm_once(end,stop)
            .and_then(|_|original.android_begin(end,Some(stop)))
            .and_then(|_|original.inspect(selected,end,stop));
        if let Err(failure)=result {
            original.android_note(failure);
            return Err(BridgeError::unavailable("The installed Mac Android runtime failed original custody inspection."));
        }
        Ok(VerifiedRuntime{python:selected.python.clone(),bootstrap:selected.bootstrap.clone(),core:selected.core.clone(),cwd:selected.cwd.clone()})
    }
    pub(crate) fn transfer_once(&mut self) -> Result<()> {
        if self.settlement || self.acquisition.is_some() || self.selection.is_none()
            || !self.inspection.as_ref().is_some_and(|b|b.inspected && !b.unknown && !b.closed && b.android_first_failure().is_none()){
            return Err(AdmissionFailure::AlreadyUsed);
        }
        let selected=self.selection.take().ok_or(AdmissionFailure::Unknown)?;
        let original=match self.inspection.take(){Some(original)=>original,None=>{self.selection=Some(selected);return Err(AdmissionFailure::Unknown);}};
        self.acquisition=Some(AndroidBuildInstalledRuntime{original,selection:selected,claimed:false});Ok(())
    }
    pub(crate) fn capability(&mut self) -> Result<&mut AndroidBuildInstalledRuntime> {
        if self.settlement{return Err(AdmissionFailure::AlreadyUsed);}
        self.acquisition.as_mut().ok_or(AdmissionFailure::AlreadyUsed)
    }
    fn original(&self) -> Option<&Book> {match(&self.inspection,&self.acquisition){
        (Some(original),None)=>Some(original),(None,Some(capability))=>Some(&capability.original),_=>None,
    }}
    pub(crate) fn first_failure(&self) -> Option<(AdmissionFailure,Instant)> {
        self.original().and_then(Book::android_first_failure)
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {self.original()?.android_retained_bytes()}
    pub(crate) fn mark_interrupted(&mut self) {
        if let Some(original)=&mut self.inspection {original.unknown=true;original.android_note(AdmissionFailure::Unknown);}
        if let Some(capability)=&mut self.acquisition {capability.original.unknown=true;capability.original.android_note(AdmissionFailure::Unknown);}
    }
    pub(crate) fn android_check_after_use(&self,end:Instant,cutoff:&watch::Receiver<Instant>) -> Result<()> {
        if self.settlement{return Err(AdmissionFailure::AlreadyUsed);}
        let original=match(&self.inspection,&self.acquisition){
            (None,Some(capability))if capability.claimed=>&capability.original,_=>return Err(AdmissionFailure::AlreadyUsed),
        };
        original.android_begin(end,None)?;
        let result=original.ios_check_after_use(end,cutoff);
        if let Err(failure)=result {original.android_note(failure);}
        result
    }
    pub(crate) fn settle_originals(&mut self,end:Instant,cleanup:&watch::Receiver<Instant>,publish:&mut dyn FnMut(AdmissionFailure,Instant)) -> CloseOutcome {
        if self.settlement {publish(AdmissionFailure::Unknown,Instant::now());return CloseOutcome::Unknown;}
        self.settlement=true;
        match(&mut self.inspection,&mut self.acquisition) {
            (Some(original),None)=>original.android_settle(end,cleanup,publish),
            (None,Some(capability))=>capability.original.android_settle(end,cleanup,publish),
            _=>{publish(AdmissionFailure::Unknown,Instant::now());CloseOutcome::Unknown},
        }
    }
    pub(crate) fn settled(&self) -> bool {self.settlement && self.original().is_some_and(Book::settled)}
}


#[cfg(test)]
pub(super) fn fd_cleanup_data_check() -> bool {
    // Synthetic entry/return clock DATA only. No descriptor, native frame,
    // consuming close or close result is constructed, executed or fabricated.
    let start=Instant::now();
    let end=start+std::time::Duration::from_secs(70);
    let (send,cleanup)=watch::channel(end);
    let entry=start+std::time::Duration::from_secs(61); // Audit end 60 has passed.
    if fd_cleanup_expired_at(end,&cleanup,None,entry)
        || !fd_cleanup_expired_at(end,&cleanup,None,end) {return false;}
    // Original scalar end and earliest F each dominate a later receiver value.
    let first=start+std::time::Duration::from_secs(20);
    if fd_cleanup_expired_at(end,&cleanup,Some(first),first+std::time::Duration::from_secs(1))
        || !fd_cleanup_expired_at(end,&cleanup,Some(first),first+std::time::Duration::from_secs(10))
        || !fd_cleanup_expired_at(entry,&cleanup,None,entry) {return false;}
    // A native refusal with time left does not deny an independent FD close.
    // During the original first-close entry/return interval the SAME sender
    // shortens cleanup. Post-return and the next entry must both refuse.
    if fd_cleanup_expired_at(end,&cleanup,None,entry) {return false;}
    let returned=entry+std::time::Duration::from_secs(1);
    send.send_replace(returned);
    if !fd_cleanup_expired_at(end,&cleanup,None,returned)
        || !fd_cleanup_expired_at(end,&cleanup,None,returned+std::time::Duration::from_millis(1)) {return false;}
    drop(send);
    fd_cleanup_expired_at(end,&cleanup,None,start)
}
#[cfg(test)]
mod inert_arm_tests {
    use super::*;
    #[test]
    fn independent_fd_consumes_keep_the_original_cleanup_endpoint() {
        assert!(fd_cleanup_data_check());
    }
    pub(super) fn android_runtime_constructor_is_inert_and_missing_entered_frame_is_not_zero_data() {
        // Control DATA only: no SnapshotBook constructor/native API is called.
        let end=Instant::now()+std::time::Duration::from_secs(30);
        let (_send,read)=watch::channel(end);
        let (_cleanup_send,cleanup)=watch::channel(end);
        let mut audit=Audit::new(read);
        assert!(audit.frame.is_none() && !audit.arm_entered);
        assert_eq!(audit.retained_bytes(),Some(0));
        assert!(audit.settled());
        audit.arm_entered=true;
        assert_eq!(audit.retained_bytes(),None);
        assert!(!audit.settled());
        let mut failure=None;
        assert!(!audit.release(end,&cleanup,&mut |reason,at|failure=Some((reason,at))));
        assert_eq!(failure.map(|(reason,_)|reason),Some(AdmissionFailure::Unknown));
        assert_eq!(audit.retained_bytes(),None);
    }
    #[test]
    fn android_runtime_constructor_is_inert_and_missing_entered_frame_is_not_zero() { android_runtime_constructor_is_inert_and_missing_entered_frame_is_not_zero_data(); }

}

// Explicit harness=false DATA bridge; ordinary libtest wrappers use these same
// inert bodies. No native custody, task, Prepare/Start or qualification is granted.
#[cfg(test)]
pub(super) fn assert_inert_arm_data_contract() {
    inert_arm_tests::android_runtime_constructor_is_inert_and_missing_entered_frame_is_not_zero_data();
}
