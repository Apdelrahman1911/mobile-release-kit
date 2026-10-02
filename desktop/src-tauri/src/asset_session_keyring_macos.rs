//! Mac driver plugged into the existing OriginalWork/ChildBook. The blocking
//!worker never acquires owner.child: child() owns that mutex through real join.
use super::*;
use crate::vault_keyring_macos::{LookupInput,Problem};
fn gate(state:&DocumentState,owner:&Arc<OriginalWork>)->Result<Instant,Problem>{
    let slot=state.slot.as_ref().filter(|s|Arc::ptr_eq(&s.owner,owner)
        && matches!(s.operation,Operation::Initialize|Operation::Unlock|Operation::Prepare)).ok_or(Problem::Interrupted)?;
    if !state.lifetime.original_bound() || state.lost_observed || state.exhausted || state.unknown || state.stopping
        || state.quit_pending || state.retiring || state.lock_pending || owner.interrupted()
        || slot.phase!=Phase::Assessing || slot.cleanup_end.is_some(){return Err(Problem::Interrupted);}
    owner.endpoint().filter(|end|Instant::now()<*end).ok_or(Problem::Interrupted)
}
impl DocumentBinding{
    fn mac_keyring_claim(&self,owner:&Arc<OriginalWork>,go:bool)->Result<(),Problem>{
        let mut state=self.lock();self.expire(&mut state,Instant::now());gate(&state,owner)?;
        let mut book=owner.keyring.try_lock().map_err(|_|Problem::CleanupUnknown)?;
        keyring_constrain_cleanup(&state,owner,&mut book);
        if go{book.claim_go()}else{book.claim_launch()}
    }
    fn mac_keyring_report(&self,owner:&Arc<OriginalWork>)->Result<(),Problem>{
        let mut state=self.lock();self.expire(&mut state,Instant::now());
        let mut book=owner.keyring.try_lock().map_err(|_|Problem::CleanupUnknown)?;
        if owner.interrupted(){book.interrupt();}
        if keyring_problem_stop(&mut state,owner,book.problem().zip(book.problem_at())){self.bump(&mut state);}
        keyring_constrain_cleanup(&state,owner,&mut book);
        let unknown=book.document_cleanup_unknown();drop(book);
        if unknown{self.coordinator_failed(&mut state,UnknownOrigin::NotRecorded,Some(owner));}
        Ok(())
    }
    #[cfg(feature="desktop-shell")]
    pub(super) async fn drive_keyring_lookup(&self,owner:&Arc<OriginalWork>,input:LookupInput)->Result<(),Problem>{
        {
            let mut state=self.lock();self.expire(&mut state,Instant::now());
            let end=gate(&state,owner)?;lookup_memory::enter(&state,owner,input,end)?;
        }
        let actual=child(owner,ChildJob::KeyringHelper(self.clone())).await;
        // No candidate exists before the actual existing blocking-child join.
        {
            let mut state=self.lock();self.expire(&mut state,Instant::now());
            let eligible=gate(&state,owner).is_ok();
            let joined=owner.child.try_lock().map_err(|_|Problem::CleanupUnknown)?;
            if joined.handle.is_some() || !matches!(joined.receipt,JoinReceipt::New|JoinReceipt::Returned){
                return Err(Problem::CleanupUnknown);
            }
            let mut book=owner.keyring.try_lock().map_err(|_|Problem::CleanupUnknown)?;
            keyring_constrain_cleanup(&state,owner,&mut book);
            if !eligible || owner.interrupted(){book.interrupt();}
            match actual{
                Ok(ChildEnd::KeyringHelper(result))=>book.child_joined(result),
                Ok(ChildEnd::Refused(_))|Err(_)=>book.child_not_started(),
                _=>book.fail(Problem::CleanupUnknown),
            }
        }
        self.mac_keyring_report(owner)?;
        let book=owner.keyring.try_lock().map_err(|_|Problem::CleanupUnknown)?;
        if !book.resources_settled(){return Err(Problem::CleanupUnknown);}
        book.problem().map_or(Ok(()),Err)
    }
}
// This is the existing original's small deadline mailbox, not document/registry
//authority and not another owner. Slot::stop and native F only shorten it.
fn cleanup_projection(owner:&OriginalWork,failure:Option<(Problem,Instant)>)->Result<Option<Instant>,Problem>{
    let work=*owner.deadline.lock().map_err(|_|Problem::CleanupUnknown)?;
    let now=Instant::now();
    let first=match(failure,work){
        (Some((_,at)),_) if at>now=>return Err(Problem::CleanupUnknown),
        (Some((_,at)),Some(end))=>Some(at.min(end)),
        (Some((_,at)),None)=>Some(at),
        (None,Some(end)) if now>=end=>Some(end),
        _=>None,
    };
    let mut original=owner.cleanup_end.lock().map_err(|_|Problem::CleanupUnknown)?;
    if let Some(at)=first{
        let end=at.checked_add(CLEANUP).ok_or(Problem::CleanupUnknown)?;
        *original=Some(original.map_or(end,|old|old.min(end)));
    }
    let inherited=*original;drop(original);
    if first.is_some(){owner.stop();}
    if owner.stopped() && inherited.is_none(){return Err(Problem::CleanupUnknown);}
    Ok(inherited)
}
pub(super) fn execute(document:&DocumentBinding,owner:&Arc<OriginalWork>)->Result<(),Problem>{
    {
        let mut book=owner.keyring.lock().map_err(|_|Problem::CleanupUnknown)?;
        book.enter_driver()?;
        if owner.interrupted(){book.interrupt();}
        else {let _=book.prepare(&mut ||owner.interrupted());}
    }
    // Release provider before acquiring document: no inverse gate/custody order.
    match document.mac_keyring_claim(owner,false){
        Ok(())=>{
            let spawned={let mut book=owner.keyring.lock().map_err(|_|Problem::CleanupUnknown)?;book.spawn_original()};
            if spawned.is_ok(){
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
                if let Err(problem) = document.installed_macos_vault_checkpoint(owner,
                    crate::shell::installed_observation::vault::Checkpoint::BeforeGo) {
                    owner.keyring.lock().map_err(|_|Problem::CleanupUnknown)?.fail(problem);
                }
                if let Err(problem)=document.mac_keyring_claim(owner,true){
                owner.keyring.lock().map_err(|_|Problem::CleanupUnknown)?.fail(problem);
            }}
        },
        Err(problem)=>owner.keyring.lock().map_err(|_|Problem::CleanupUnknown)?.fail(problem),
    }
    loop{
        if document.mac_keyring_report(owner).is_err(){
            // Preserve exact prearmed resource book through a failed coordinator/
            //document. This worker still pumps only originals it actually owns.
            owner.keyring.lock().map_err(|_|Problem::CleanupUnknown)?.fail(Problem::CleanupUnknown);
        }
        let (done,delay)={
            let mut book=owner.keyring.lock().map_err(|_|Problem::CleanupUnknown)?;
            let done=book.pump();(done,book.turn_delay())
        };
        // Test-only observation runs after releasing provider custody and BEFORE
        // the done branch: a terminal+EOF in this same pump must not skip STOP.
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
        if let Err(problem) = document.installed_macos_vault_checkpoint(owner,
            crate::shell::installed_observation::vault::Checkpoint::SuccessfulAddTerminal) {
            owner.keyring.lock().map_err(|_|Problem::CleanupUnknown)?.fail(problem);
        }
        if done{break;}
        std::thread::sleep(delay); // At most5ms; no new deadline/thread/worker.
    }
    let result=owner.keyring.lock().map_err(|_|Problem::CleanupUnknown)?.finish_driver(
        &mut ||owner.interrupted(),&mut |failure|cleanup_projection(owner,failure));
    // The coordinator reports finality only AFTER actual child() join.
    result
}
