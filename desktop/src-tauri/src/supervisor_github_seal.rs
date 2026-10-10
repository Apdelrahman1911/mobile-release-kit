//! One fixed second original subordinate to GitHub Setup. No reusable phase,
//! root/process selector, new clock, permit, retry or privileged-helper role.
use super::*;
use crate::{asset_session::{GitHubSecretMaterial,GitHubSecretFrame},github_setup_protocol as wire};
use zeroize::Zeroizing;

pub(super) enum SecretPhaseAdmission {
    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    Prepare(Arc<Mutex<crate::installed_runtime::GitHubSealSlots>>),
    Apply(SecretSealed),
}
pub(crate) struct SecretNativeAdmission {
    pub(super) material:Arc<GitHubSecretMaterial>,
    pub(super) phase:SecretPhaseAdmission,
    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(super) first:Arc<Mutex<GitHubSetupRuntimeSlots>>,
    pub(super) first_bound:usize,bytes:usize,
}
impl SecretNativeAdmission {
    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(crate) fn reserve(material:Arc<GitHubSecretMaterial>)->Result<Self,BridgeError>{
        if !crate::installed_runtime::github_seal_publisher_bound(){
            return Err(crate::github_setup_session::refused(wire::Reason::RuntimeUnavailable));
        }
        let mut slots=crate::installed_runtime::GitHubSealSlots::new();
        let mut first=GitHubSetupRuntimeSlots::new();
        let first_bound=first.reserve_secret_prepare().map_err(|_|crate::github_setup_session::refused(wire::Reason::ResourcesUnavailable))?;
        let bytes=slots.reserve_once().map_err(|_|crate::github_setup_session::refused(wire::Reason::ResourcesUnavailable))?
            .checked_add(first_bound).and_then(|v|v.checked_add(std::mem::size_of::<Owner>()))
            .and_then(|v|v.checked_add(std::mem::size_of::<Self>()))
            .and_then(|v|v.checked_add(4*std::mem::size_of::<usize>()))
            .ok_or_else(||crate::github_setup_session::refused(wire::Reason::ResourcesUnavailable))?;
        Ok(Self{material,phase:SecretPhaseAdmission::Prepare(Arc::new(Mutex::new(slots))),first:Arc::new(Mutex::new(first)),first_bound,bytes})
    }
    #[cfg(not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
    pub(crate) fn reserve(_material:Arc<GitHubSecretMaterial>)->Result<Self,BridgeError>{Err(crate::github_setup_session::refused(wire::Reason::Unqualified))}
    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(crate) fn reserve_apply(sealed:SecretSealed)->Result<Self,BridgeError>{
        // A real settled Prepare alone can construct SecretSealed. Apply moves
        // that single backing; no second helper/image/RNG or renewed read plan.
        let mut first=GitHubSetupRuntimeSlots::new();
        let first_bound=first.reserve_secret_prepare().map_err(|_|crate::github_setup_session::refused(wire::Reason::ResourcesUnavailable))?;
        let bytes=first_bound.checked_add(std::mem::size_of::<Owner>())
            .and_then(|v|v.checked_add(std::mem::size_of::<Self>()))
            .and_then(|v|v.checked_add(4*std::mem::size_of::<usize>()))
            .ok_or_else(||crate::github_setup_session::refused(wire::Reason::ResourcesUnavailable))?;
        Ok(Self{material:sealed.material.clone(),phase:SecretPhaseAdmission::Apply(sealed),
            first:Arc::new(Mutex::new(first)),first_bound,bytes})
    }
    #[cfg(not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
    pub(crate) fn reserve_apply(_sealed:SecretSealed)->Result<Self,BridgeError>{Err(crate::github_setup_session::refused(wire::Reason::Unqualified))}
    pub(super) fn kind(&self)->wire::Kind{match &self.phase{
        #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
        SecretPhaseAdmission::Prepare(_)=>wire::Kind::Prepare,
        SecretPhaseAdmission::Apply(_)=>wire::Kind::Apply,
    }}
    pub(crate) fn material(&self)->&Arc<GitHubSecretMaterial>{&self.material}
    pub(crate) fn bytes(&self)->usize{self.bytes}
}
// Ciphertext only. The one full stdout backing (including its fixed header)
// moves into consent, then is wiped on normal discard/expiry. It is never
// Clone/Debug/Serialize and no independent receipt makes it executable.
pub(crate) struct SecretSealed {
    pub(crate) material:Arc<GitHubSecretMaterial>,pub(crate) key:wire::SecretPublicKey,
    output:Zeroizing<Vec<u8>>,
}
impl SecretSealed {
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{self.output.capacity()
        .checked_add(self.key.id.capacity())?.checked_add(self.key.value.capacity())}
    pub(crate) fn ciphertext(&self)->&[u8]{&self.output[12..]}
    #[cfg(test)]
    pub(crate) fn retained_data(material:Arc<GitHubSecretMaterial>)->Self{
        // Inert retained-storage fixture only; never admitted as a helper
        // receipt, output frame, consent or current source authority.
        let mut id=String::with_capacity(31);id.push_str("inert-key");
        let mut value=String::with_capacity(71);value.extend(std::iter::repeat_n('A',43));value.push('=');
        Self{material,key:wire::SecretPublicKey{id,value},output:Zeroizing::new(Vec::with_capacity(wire::RESPONSE_LIMIT))}
    }
}
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
mod original {
use super::*;
use std::process::Stdio;
use tokio::process::Command;
#[derive(Clone,Copy)]
struct ReadReceipt {waited:bool,writer:bool,stdout:bool,stderr:bool,native:bool,timely:bool}
impl ReadReceipt {
    fn positive(self)->bool{self.waited&&self.writer&&self.stdout&&self.stderr&&self.native&&self.timely}
    fn capture(resources:&Resources,owner:&Owner)->Option<Self>{
        let proof=Self{waited:resources.waited.as_ref().is_some_and(ExitStatus::success),
            writer:resources.write_end.is_some_and(|v|v.complete),stdout:resources.out_end.as_ref().is_some_and(|v|v.eof&&!v.overflow),
            stderr:resources.err_end.as_ref().is_some_and(|v|v.eof&&!v.overflow),
            native:matches!(resources.native_return.as_ref(),Some(Ok(CloseOutcome::Settled)))&&resources.native_settlement.is_none()
                &&resources.github_setup.as_ref().is_some_and(|n|n.try_lock().is_ok_and(|s|s.settled())),
            timely:!owner.failed()&&Instant::now()<owner.endpoint()&&!*owner.stop.borrow()};
        proof.positive().then_some(proof)
    }
}
pub(in crate::supervisor) struct SealPhase {
    slots:Arc<Mutex<crate::installed_runtime::GitHubSealSlots>>,read_receipt:Option<ReadReceipt>,
    acquisition:Option<JoinHandle<Result<Child,BridgeError>>>,acquisition_return:Option<ManagementJoin>,
    acquisition_error:Option<tokio::task::JoinError>,child:Option<Child>,
    writer:Option<JoinHandle<WriteEnd>>,stdout:Option<JoinHandle<ReadEnd>>,stderr:Option<JoinHandle<ReadEnd>>,
    failed_writer:Option<JoinHandle<WriteEnd>>,failed_stdout:Option<JoinHandle<ReadEnd>>,failed_stderr:Option<JoinHandle<ReadEnd>>,
    waited:Option<ExitStatus>,write_end:Option<WriteEnd>,out_end:Option<ReadEnd>,err_end:Option<ReadEnd>,kill_attempted:bool,
    settlement:Option<JoinHandle<CloseOutcome>>,settlement_return:Option<Result<CloseOutcome,tokio::task::JoinError>>,
}
impl SealPhase {
    pub(in crate::supervisor) fn new(slots:Arc<Mutex<crate::installed_runtime::GitHubSealSlots>>)->Self{
        Self{slots,read_receipt:None,acquisition:None,acquisition_return:None,acquisition_error:None,child:None,
            writer:None,stdout:None,stderr:None,failed_writer:None,failed_stdout:None,failed_stderr:None,
            waited:None,write_end:None,out_end:None,err_end:None,kill_attempted:false,settlement:None,settlement_return:None}
    }
    pub(in crate::supervisor) fn settled_or_never_entered(&self)->bool{
        self.acquisition.is_none()&&self.acquisition_error.is_none()&&self.child.is_none()&&self.writer.is_none()
            &&self.stdout.is_none()&&self.stderr.is_none()&&self.failed_writer.is_none()&&self.failed_stdout.is_none()&&self.failed_stderr.is_none()
            &&self.settlement.is_none()&&self.slots.try_lock().is_ok_and(|s|
                if self.read_receipt.is_none(){s.never_started()&&self.acquisition_return.is_none()&&self.settlement_return.is_none()}
                else{matches!(self.settlement_return,Some(Ok(CloseOutcome::Settled)))&&s.settled()})
    }
    async fn settle(&mut self,owner:&Arc<Owner>,post_child:bool)->bool{
        if self.settlement_return.is_none(){
            if self.settlement.is_none(){
                let slots=self.slots.clone();let original=owner.clone();let(release,enter)=oneshot::channel();
                self.settlement=Some(tokio::task::spawn_blocking(move||{
                    if enter.blocking_recv().is_err(){return CloseOutcome::Unknown}
                    match slots.lock(){
                        Ok(mut s)=>{
                            // The same registered settlement original performs
                            // final named/held POST before all consuming closes.
                            // No native filesystem call runs on this coordinator.
                            if post_child {
                                let result=s.post_original_return(original.endpoint(),&original.stop.subscribe());
                                original.observe_native_failure(s.first_failure());
                                if result.is_err(){original.fail(BridgeError::unavailable("The fixed seal source changed or expired."));}
                            }
                            s.settle_originals(&mut|first|original.native_cleanup_expired(first))
                        },
                        Err(mut e)=>{let _=e.get_mut().settle_originals(&mut|first|original.native_cleanup_expired(first));CloseOutcome::Unknown},
                    }
                }));
                let _=release.send(());
            }
            let returned=join_slot(&mut self.settlement).await;
            if returned.is_ok(){self.settlement.take();}
            self.settlement_return=Some(returned);
        }
        matches!(self.settlement_return,Some(Ok(CloseOutcome::Settled)))
            &&self.slots.try_lock().is_ok_and(|s|s.settled())
    }
}
async fn write_frame(mut writer:tokio::process::ChildStdin,frame:GitHubSecretFrame,
    mut stop:watch::Receiver<bool>,faults:mpsc::Sender<BridgeError>)->WriteEnd{
    if *stop.borrow(){return WriteEnd{complete:false}}
    let returned=tokio::select!{
        _=stop.changed()=>return WriteEnd{complete:false},
        result=async{writer.write_all(frame.bytes()).await?;writer.shutdown().await}=>result,
    };
    if returned.is_err(){let _=faults.try_send(BridgeError::new("io_error","The fixed secret input pipe failed."));}
    // Frame's entire initialized Zeroizing allocation drops only after the
    // original writer returned (normal/error/cancel). No plaintext receipt.
    WriteEnd{complete:returned.is_ok()}
}
async fn read_fixed<R:AsyncRead+Unpin>(mut pipe:R,mut bytes:Vec<u8>,limit:usize,faults:mpsc::Sender<BridgeError>)->ReadEnd{
    let mut scratch=[0u8;8192];let mut overflow=false;
    loop{match pipe.read(&mut scratch).await{
        Ok(0)=>return ReadEnd{bytes,eof:true,overflow},
        Ok(n)=>{if !overflow&&n<=limit.saturating_sub(bytes.len()){bytes.extend_from_slice(&scratch[..n]);}
            else if !overflow{overflow=true;let _=faults.try_send(BridgeError::new("output_limit","The fixed seal output exceeded its bound."));}},
        Err(_)=>{let _=faults.try_send(BridgeError::new("io_error","The fixed seal output pipe failed."));return ReadEnd{bytes,eof:false,overflow}},
    }}
}
fn acquire(inner:&Arc<Inner>,owner:&Arc<Owner>,slots:&Arc<Mutex<crate::installed_runtime::GitHubSealSlots>>)->Result<Child,BridgeError>{
    let mut native=slots.lock().map_err(|_|BridgeError::cleanup_unknown())?;
    let stop=owner.stop.subscribe();
    native.inspect_once(owner.endpoint(),&stop).map_err(|_|{owner.observe_native_failure(native.first_failure());BridgeError::unavailable("The fixed seal image was refused.")})?;
    let selected=native.prepare_once_observed(owner.endpoint(),&stop,&mut|first|owner.observe_native_failure(first))
        .map_err(|_|BridgeError::unavailable("The fixed seal image could not prepare."))?;
    let mut command=Command::new(&selected.program);
    command.current_dir(&selected.cwd).env_clear().env("LC_ALL","C").env("LANG","C")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
    crate::runtime::macos_installed_environment(&mut command)
        .map_err(|_|BridgeError::new("io_error","The fixed seal environment was refused."))?;
    let material=owner.setup_material.as_ref().and_then(SetupMaterial::secret).ok_or_else(BridgeError::protocol)?;
    let gate=owner.setup_gate.as_ref().ok_or_else(BridgeError::protocol)?;
    gate.claim_secret(&owner.id,owner.setup_request.as_ref().ok_or_else(BridgeError::protocol)?,material,||{
        let owners=lock(&inner.owners);let state=lock(&owner.state);
        if !preflight_claim_clear(owners.get(&owner.key).is_some_and(|v|Arc::ptr_eq(v,owner)),owner.profile,Profile::GitHubSetup,
            &state,Instant::now(),inner.stopping.load(Ordering::SeqCst),inner.disabled.load(Ordering::SeqCst),*owner.stop.borrow()){
            return Err(state.error.clone().unwrap_or_else(BridgeError::shutdown));
        }
        // This is NOT preflight_go_claimed reset/reuse. That first token handoff
        // remains immutable true; this private Book owns exactly one helper.
        native.claim_once().map_err(|_|BridgeError::cleanup_unknown())?;
        let returned=command.spawn();let detected_at=Instant::now();
        drop(state);drop(owners);
        returned.map_err(|_|{
            let error=BridgeError::new("engine_failed","The fixed seal helper did not start.");
            owner.fail_at(error.clone(),detected_at);error
        })
    })
}
fn seal_output(value:&ReadEnd,plaintext:usize)->bool{
    let expected=plaintext.checked_add(48);
    value.eof&&!value.overflow&&value.bytes.capacity()<=wire::RESPONSE_LIMIT&&value.bytes.len()>=12
        &&&value.bytes[..8]==b"MRKBOX01"&&expected.is_some_and(|length|length<=wire::SECRET_PLAINTEXT_LIMIT+48
            &&value.bytes.len()==length+12&&u32::from_be_bytes(value.bytes[8..12].try_into().unwrap_or([0;4]))as usize==length)
}
#[cfg(test)]
pub(in crate::supervisor) fn data_checks(){
    let positive=ReadReceipt{waited:true,writer:true,stdout:true,stderr:true,native:true,timely:true};
    assert!(positive.positive());
    for i in 0..6{let mut value=positive;match i{0=>value.waited=false,1=>value.writer=false,2=>value.stdout=false,
        3=>value.stderr=false,4=>value.native=false,5=>value.timely=false,_=>unreachable!()};assert!(!value.positive());}
    let mut output=Vec::with_capacity(wire::RESPONSE_LIMIT);output.extend_from_slice(b"MRKBOX01");
    output.extend_from_slice(&52u32.to_be_bytes());output.resize(64,0);
    let mut returned=ReadEnd{bytes:output,eof:true,overflow:false};assert!(seal_output(&returned,4));
    returned.eof=false;assert!(!seal_output(&returned,4));returned.eof=true;
    returned.overflow=true;assert!(!seal_output(&returned,4));returned.overflow=false;
    returned.bytes[0]=b'X';assert!(!seal_output(&returned,4));returned.bytes[0]=b'M';
    assert!(!seal_output(&returned,5));returned.bytes.push(0);assert!(!seal_output(&returned,4));
    crate::installed_runtime::GitHubSealSlots::failure_data_checks();
    let mut slots=crate::installed_runtime::GitHubSealSlots::new();
    let debit=slots.reserve_once().unwrap();assert!(debit>=slots.retained_bytes().unwrap());
    assert!(slots.never_started());assert!(slots.reserve_once().is_err());
    let fresh=crate::installed_runtime::GitHubSealSlots::new();
    let phase=SealPhase::new(Arc::new(Mutex::new(fresh)));assert!(phase.settled_or_never_entered());
}
// This second original observes only its own six local events. The containing
// Supervisor's History-post handshake is not part of this seal select.
enum SealEvent {
    Wait(std::io::Result<ExitStatus>),
    Write(Result<WriteEnd, tokio::task::JoinError>),
    Out(Result<ReadEnd, tokio::task::JoinError>),
    Err(Result<ReadEnd, tokio::task::JoinError>),
    Fault(Option<BridgeError>),
    Stop,
}
// Only drive's actual positive first-original completion calls this function.
// First Resources fields stay intact; nothing is repurposed for the second.
pub(in crate::supervisor) async fn run(resources:&mut Resources,inner:&Arc<Inner>,owner:&Arc<Owner>,read:wire::SecretRead)->DriverEnd{
    let Some(proof)=ReadReceipt::capture(resources,owner)else{return DriverEnd::Ready(Err(BridgeError::protocol()))};
    // First stdout was decoded and its actual EOF captured above. Release its
    // raw backing before allocating the second fixed output buffer; preserve
    // the original scalar return/EOF records rather than repurpose them.
    if let Some(v)=resources.out_end.as_mut(){drop(std::mem::take(&mut v.bytes));}
    if let Some(v)=resources.err_end.as_mut(){drop(std::mem::take(&mut v.bytes));}
    let Some(phase)=resources.seal.as_mut()else{return DriverEnd::Ready(Err(BridgeError::protocol()))};
    if phase.read_receipt.is_some(){owner.unknown(inner);return DriverEnd::RetainedUnknown}
    phase.read_receipt=Some(proof);
    let Some(material)=owner.setup_material.as_ref().and_then(SetupMaterial::secret)else{return DriverEnd::Ready(Err(BridgeError::protocol()))};
    let key=match read.key.bytes(){Some(v)=>v,None=>return DriverEnd::Ready(Err(BridgeError::protocol()))};
    let mut out=Vec::new();
    if out.try_reserve_exact(wire::RESPONSE_LIMIT).is_err()||out.capacity()>wire::RESPONSE_LIMIT{
        owner.fail(crate::github_setup_session::refused(wire::Reason::ResourcesUnavailable));
        return if phase.settle(owner,false).await{DriverEnd::Ready(Err(crate::github_setup_session::refused(wire::Reason::ResourcesUnavailable)))}else{owner.unknown(inner);DriverEnd::RetainedUnknown};
    }
    // Same material Arc; one direct encoding into the already quoted frame.
    let frame=match material.frame(&key){Ok(v)=>v,Err(e)=>{owner.fail(e.clone());return if phase.settle(owner,false).await{DriverEnd::Ready(Err(e))}else{owner.unknown(inner);DriverEnd::RetainedUnknown}}};
    let original=owner.clone();let shared=inner.clone();let slots=phase.slots.clone();let(release,enter)=oneshot::channel();
    phase.acquisition=Some(tokio::task::spawn_blocking(move||{
        if enter.blocking_recv().is_err(){return Err(BridgeError::cleanup_unknown())}
        let result=acquire(&shared,&original,&slots);
        if let Err(error)=&result{
            if let Ok(native)=slots.lock(){original.observe_native_failure(native.first_failure());}
            original.fail(error.clone());
        }
        result
    }));let _=release.send(());
    match join_slot(&mut phase.acquisition).await{
        Ok(Ok(child))=>{phase.acquisition.take();phase.acquisition_return=Some(ManagementJoin::Returned);phase.child=Some(child);},
        Ok(Err(e))=>{phase.acquisition.take();phase.acquisition_return=Some(ManagementJoin::Returned);owner.fail(e.clone());drop(frame);
            return if phase.settle(owner,false).await{DriverEnd::Ready(Err(e))}else{owner.unknown(inner);DriverEnd::RetainedUnknown};},
        Err(e)=>{phase.acquisition_return=Some(ManagementJoin::error(&e));phase.acquisition_error=Some(e);owner.unknown(inner);return DriverEnd::RetainedUnknown},
    }
    let Some(child)=phase.child.as_mut()else{owner.unknown(inner);return DriverEnd::RetainedUnknown};
    let(faults,mut errors)=mpsc::channel(4);let mut open=true;let mut stop=owner.stop.subscribe();let mut stopped=false;
    if let Some(stdin)=child.stdin.take(){phase.writer=Some(tokio::spawn(write_frame(stdin,frame,owner.stop.subscribe(),faults.clone())));}
    if let Some(stdout)=child.stdout.take(){phase.stdout=Some(tokio::spawn(read_fixed(stdout,out,wire::SECRET_REPLY_LIMIT,faults.clone())));}
    if let Some(stderr)=child.stderr.take(){phase.stderr=Some(tokio::spawn(read_fixed(stderr,Vec::new(),0,faults.clone())));}
    drop(faults);
    if phase.writer.is_none()||phase.stdout.is_none()||phase.stderr.is_none(){owner.fail(BridgeError::cleanup_unknown());}
    loop{
        if Instant::now()>=owner.endpoint()&&!owner.failed(){owner.fail(BridgeError::timeout());}
        if owner.failed()&&!phase.kill_attempted&&phase.waited.is_none(){phase.kill_attempted=true;
            let Some(child)=phase.child.as_mut()else{owner.unknown(inner);return DriverEnd::RetainedUnknown};
            match child.try_wait(){Ok(Some(v))=>phase.waited=Some(v),Ok(None)=>{if child.start_kill().is_err(){owner.fail(BridgeError::cleanup_unknown());}},Err(_)=>{owner.unknown(inner);return DriverEnd::RetainedUnknown}}
        }
        let(waiting,writing,reading,diagnosing)=(phase.waited.is_none(),phase.writer.is_some(),phase.stdout.is_some(),phase.stderr.is_some());
        if !waiting&&!writing&&!reading&&!diagnosing{break}
        let event=tokio::select!{
            v=wait_original(&mut phase.child),if waiting=>SealEvent::Wait(v),
            v=join_slot(&mut phase.writer),if writing=>SealEvent::Write(v),
            v=join_slot(&mut phase.stdout),if reading=>SealEvent::Out(v),
            v=join_slot(&mut phase.stderr),if diagnosing=>SealEvent::Err(v),
            v=errors.recv(),if open=>SealEvent::Fault(v),_ =stop.changed(),if !stopped=>SealEvent::Stop,
        };
        match event{
            SealEvent::Wait(Ok(v))=>{if !v.success(){owner.fail(BridgeError::new("github_sealing_failed","The fixed seal original exited unsuccessfully."));}phase.waited=Some(v);},
            SealEvent::Wait(Err(_))=>{owner.unknown(inner);return DriverEnd::RetainedUnknown},
            SealEvent::Write(Ok(v))=>{phase.writer.take();phase.write_end=Some(v);if !v.complete{owner.fail(BridgeError::new("io_error","The fixed seal input did not close."));}},
            SealEvent::Out(Ok(v))=>{phase.stdout.take();phase.out_end=Some(v);},SealEvent::Err(Ok(v))=>{phase.stderr.take();phase.err_end=Some(v);},
            SealEvent::Write(Err(_))=>{phase.failed_writer=phase.writer.take();owner.fail(BridgeError::cleanup_unknown());},
            SealEvent::Out(Err(_))=>{phase.failed_stdout=phase.stdout.take();owner.fail(BridgeError::cleanup_unknown());},
            SealEvent::Err(Err(_))=>{phase.failed_stderr=phase.stderr.take();owner.fail(BridgeError::cleanup_unknown());},
            SealEvent::Fault(Some(e))=>owner.fail(e),SealEvent::Fault(None)=>open=false,SealEvent::Stop=>{stopped=true;if !owner.failed(){owner.fail(BridgeError::shutdown());}},
        }
    }
    if phase.failed_writer.is_some()||phase.failed_stdout.is_some()||phase.failed_stderr.is_some()
        ||!phase.out_end.as_ref().is_some_and(|v|v.eof)||!phase.err_end.as_ref().is_some_and(|v|v.eof){owner.unknown(inner);return DriverEnd::RetainedUnknown}
    if !phase.settle(owner,true).await{owner.unknown(inner);return DriverEnd::RetainedUnknown}
    let valid=!owner.failed()&&Instant::now()<owner.endpoint()&&phase.waited.as_ref().is_some_and(ExitStatus::success)
        &&phase.write_end.is_some_and(|v|v.complete)&&phase.err_end.as_ref().is_some_and(|v|v.eof&&!v.overflow&&v.bytes.is_empty())
        &&phase.out_end.as_ref().is_some_and(|v|seal_output(v,material.source().material.plaintext_bytes as usize));
    phase.child.take();phase.err_end.take();
    if !valid{phase.out_end.take();return DriverEnd::Ready(Err(BridgeError::new("github_sealing_failed","The fixed seal result was not admitted.")))}
    let Some(output)=phase.out_end.take()else{return DriverEnd::Ready(Err(BridgeError::protocol()))};
    let(reply,key)=read.into_result(&owner.id);
    let mut sealed=match owner.secret_sealed.lock(){Ok(v)=>v,Err(_)=>{owner.unknown(inner);return DriverEnd::RetainedUnknown}};
    if sealed.is_some(){owner.unknown(inner);return DriverEnd::RetainedUnknown}
    *sealed=Some(SecretSealed{material:material.clone(),key,output:Zeroizing::new(output.bytes)});
    DriverEnd::Ready(Ok(ReadOutcome::Setup(reply)))
}

}
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(super) use original::{SealPhase,run};

#[cfg(all(test,target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
pub(super) use original::data_checks;
