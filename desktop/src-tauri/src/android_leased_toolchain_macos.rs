//! Compulsory M2 app SH + existing tool/metadata readback composition.
//! Candidate results never grant a persisted or renderer lease. The owner keeps
//! the SAME group through genuine original joins and consumes ONE moved tail.
#![forbid(unsafe_code)]
use std::{sync::Arc,time::Instant};
use tokio::sync::watch;
use mrk_macos_installed_native::android_catalog_query::{EntryCode,Role,Signal};
use super::{AdmissionFailure,CloseOutcome,android_tools::{AndroidMetadataSlots,AndroidToolchainSlots}};
pub(crate) use super::android_tools::MetadataCandidate;
use crate::{
    android_build_protocol::{MacToolchainSelection,ToolchainBinding},
    android_catalog_query_client::{OriginalClockSlot,QueryClient},
    android_registration_protocol::records::Intent,
    android_shared_lease_macos::{AppCloseTail,Issue,LeaseCloseTail,OriginalClock,OriginalUseIdentity,
        RawFailureData,SharedUseLeaseSlots,ROW_LIMIT,QUERY_CONTROL_LIMIT,instance_data},
};
type Result<T>=std::result::Result<T,Issue>;
pub(crate) fn tool_issue(value:AdmissionFailure)->Issue{match value{
    AdmissionFailure::Stopped=>Issue::Stopped,AdmissionFailure::Deadline=>Issue::Deadline,
    AdmissionFailure::Bounds=>Issue::Bounds,AdmissionFailure::Native=>Issue::Native,
    AdmissionFailure::Unknown|AdmissionFailure::AlreadyUsed=>Issue::Unknown,
    AdmissionFailure::Ownership|AdmissionFailure::Inventory|AdmissionFailure::Identity=>Issue::Refused,
}}
pub(crate) fn admission_issue(value:Issue)->AdmissionFailure{match value{
    Issue::Stopped=>AdmissionFailure::Stopped,Issue::Deadline=>AdmissionFailure::Deadline,
    Issue::Bounds=>AdmissionFailure::Bounds,Issue::Native=>AdmissionFailure::Native,
    Issue::Unknown=>AdmissionFailure::Unknown,_=>AdmissionFailure::Inventory,
}}
fn selected_capacity(selected:&MacToolchainSelection)->Option<usize>{
    [&selected.instance,&selected.record_sha256,&selected.inventory_sha256,&selected.os_provider_sha256]
        .iter().try_fold(0usize,|n,s|n.checked_add(s.capacity()))
}
fn same_content(a:&MacToolchainSelection,b:&MacToolchainSelection)->bool{
    a.instance==b.instance && a.owner_uid==b.owner_uid && a.record_sha256==b.record_sha256
        && a.inventory_sha256==b.inventory_sha256 && a.os_provider_sha256==b.os_provider_sha256
}
fn account(clock:&Arc<OriginalClock>)->Result<u32>{
    let mut last=0;
    if !clock.point(&mut last,false,None){return Err(Issue::Stopped);}
    let user=mrk_macos_installed_native::real_user().map_err(|_|Issue::Native)?;
    if !clock.point(&mut last,false,None){return Err(Issue::Stopped);}
    if user==0 || user==u32::MAX{Err(Issue::Refused)}else{Ok(user)}
}
fn intent_from_reply(lease:&SharedUseLeaseSlots,reply:&mrk_macos_installed_native::android_catalog_query::Reply)->Result<Intent>{
    match reply.code{
        EntryCode::Busy=>return Err(Issue::Busy),EntryCode::Interrupted=>return Err(Issue::Interrupted),
        EntryCode::Refused=>return Err(Issue::Refused),EntryCode::Observed=>{},
    }
    if reply.presence.known!=7{return Err(Issue::Unknown);}
    let intent=lease.authenticate_intent(&reply.bytes)?;
    // Bound intent with stage/quarantine or without final destination is still
    // interrupted. Never ignore the private helper-only staging domain.
    if reply.presence.present!=1{return Err(Issue::Interrupted);}
    Ok(intent)
}

/// Original Start tool slot. No owner can reach the existing unleased tool
/// reader through this API; inspection/pre-spawn/post-use remain under this SH.
pub(crate) struct LeasedAndroidToolchainSlots{
    identity:OriginalUseIdentity,client:QueryClient,lease:[SharedUseLeaseSlots;1],
    tools:AndroidToolchainSlots,selected:MacToolchainSelection,intent:Option<Intent>,
    entered:bool,in_call:bool,inspected:bool,observations:bool,tail_taken:bool,
}
impl LeasedAndroidToolchainSlots{
    pub(crate) fn new(selected:MacToolchainSelection,audit:watch::Receiver<Instant>)->Self{
        let identity=OriginalUseIdentity::reserved();
        Self{identity:identity.clone(),client:QueryClient::new(audit.clone()),
            lease:[SharedUseLeaseSlots::new(identity)],tools:AndroidToolchainSlots::new(selected.clone(),audit),
            selected,intent:None,entered:false,in_call:false,inspected:false,observations:false,tail_taken:false}
    }
    pub(crate) fn original_identity(&self)->OriginalUseIdentity{self.identity.clone()}
    pub(crate) fn query_signal(&self)->Arc<Signal>{self.client.signal()}
    pub(crate) fn original_clock_slot(&self)->OriginalClockSlot{self.client.clock_slot()}
    pub(crate) fn original_clock(&self)->Option<Arc<OriginalClock>>{self.client.clock()}
    pub(crate) fn failure_data(&self)->Option<RawFailureData>{self.client.failure_data()}
    fn note(&mut self,issue:Issue)->Issue{
        let local=self.lease[0].failure().filter(|(failure,_)|*failure==issue)
            .or_else(||self.tools.first_failure().map(|(failure,at)|(tool_issue(failure),at)).filter(|(failure,_)|*failure==issue));
        self.client.publish(issue,local.map_or_else(Instant::now,|(_,at)|at));issue
    }
    pub(crate) fn first_failure(&self)->Option<(AdmissionFailure,Instant)>{
        [self.client.failure(),self.lease[0].failure(),self.tools.first_failure().map(|(f,t)|(tool_issue(f),t))]
            .into_iter().flatten().min_by_key(|(_,t)|*t).map(|(f,t)|(admission_issue(f),t))
    }
    fn prepare_intent(&mut self,clock:Arc<OriginalClock>,stop:&watch::Receiver<bool>)->Result<Intent>{
        let user=account(&clock)?;
        if !self.selected.valid() || self.selected.owner_uid!=user{return Err(Issue::Refused);}
        let key=instance_data(&self.selected.instance).ok_or(Issue::Refused)?;
        self.lease[0].admit_once(key,user,clock)?;
        self.client.begin(user,stop)?;
        let reply=self.client.read_intent(key,stop)?;
        let intent=intent_from_reply(&self.lease[0],&reply);
        // Finish even a safely read negative candidate. Finish is query DATA
        // finality, not success of the requested tool selection.
        self.client.finish(stop)?;
        intent
    }
    pub(crate) fn inspect_once(&mut self,t:Instant,w:Instant,h:Instant,first:Option<Instant>,
        stop:&watch::Receiver<bool>)->Result<()>{
        if self.entered || self.tail_taken{return Err(self.note(Issue::Unknown));}
        self.entered=true;self.in_call=true;
        let intent=self.client.arm(Role::Start,t,w,h,first).and_then(|clock|self.prepare_intent(clock,stop));
        if let Err(issue)=intent.as_ref(){self.note(*issue);}
        // SAME inspector native client retirement before any caller can return,
        // even when SH/intent/native input failed. A later native worker may not
        // substitute for this thread-affine release.
        let query_settled=self.client.settle_on_inspector();
        self.in_call=false;
        if !query_settled{return Err(self.note(Issue::Unknown));}
        let intent=intent?;
        self.in_call=true;
        let result=self.tools.inspect_leased_once(&intent,w,stop).map_err(tool_issue);
        self.in_call=false;
        if let Err(issue)=result{
            let issue=if issue==Issue::Refused && !crate::android_build_protocol::Profile::current().is_some_and(crate::android_supplier_macos::available_for){Issue::Unavailable}else{issue};
            return Err(self.note(issue));
        }
        self.lease[0].check_held(false).map_err(|issue|self.note(issue))?;
        self.intent=Some(intent);self.inspected=true;Ok(())
    }
    pub(crate) fn binding_data(&self)->Result<ToolchainBinding>{
        if !self.inspected || self.in_call || self.tail_taken || self.observations
            || !self.client.successful() || self.failure_data().is_none_or(|f|f.unknown || f.first.is_some()){
            return Err(Issue::Unknown);
        }
        self.tools.binding_data().map_err(tool_issue)
    }
    pub(crate) fn check_before_spawn(&mut self,end:Instant,stop:&watch::Receiver<bool>)->Result<()>{
        if !self.inspected || self.in_call || self.tail_taken || self.observations{return Err(self.note(Issue::Unknown));}
        self.lease[0].check_held(false).map_err(|issue|self.note(issue))?;
        self.in_call=true;let result=self.tools.check_before_spawn(end,stop).map_err(tool_issue);self.in_call=false;
        result.map_err(|issue|self.note(issue))?;
        self.lease[0].check_held(false).map_err(|issue|self.note(issue))
    }
    pub(crate) fn check_after_use(&mut self,end:Instant)->Result<()>{
        if !self.inspected || self.in_call || self.tail_taken || self.observations{return Err(self.note(Issue::Unknown));}
        // Ordinary joined nonzero builds may enter cleanup under first-F; this
        // integrity check does not turn their semantic Refused result into success.
        self.lease[0].check_held(true).map_err(|issue|self.note(issue))?;
        self.in_call=true;let result=self.tools.check_after_use(end).map_err(tool_issue);self.in_call=false;
        result.map_err(|issue|self.note(issue))?;
        self.lease[0].check_held(true).map_err(|issue|self.note(issue))
    }
    pub(crate) fn mark_interrupted(&mut self){self.client.publish(Issue::Unknown,Instant::now());self.in_call=true;}
    /// Intermediate only. Existing runtime/tool/native observations and every
    /// dependent original return still precede the owner's genuine joined proof.
    pub(crate) fn settle_observations(&mut self,end:Instant,cleanup:&watch::Receiver<Instant>,
        publish:&mut dyn FnMut(AdmissionFailure,Instant))->CloseOutcome{
        if self.observations || self.tail_taken || self.in_call{
            self.note(Issue::Unknown);return CloseOutcome::Unknown;
        }
        let clock=self.client.clock();
        let tools=self.tools.settle_originals(end,cleanup,&mut |failure,at|{
            if let Some(clock)=&clock{let _=clock.publish_local(at,tool_issue(failure).uncertain());}
            publish(failure,at);
        });
        let lease=self.lease[0].settle_observations();
        self.observations=tools==CloseOutcome::Settled && lease && self.client.observations_settled();
        if !self.observations{self.note(Issue::Unknown);}
        if let Some((failure,at))=self.first_failure(){publish(failure,at);}
        if self.observations{CloseOutcome::Settled}else{CloseOutcome::Unknown}
    }
    pub(crate) fn observations_settled(&self)->bool{
        self.observations && !self.tail_taken && !self.in_call && self.tools.settled()
            && self.lease[0].observations_settled() && self.client.observations_settled()
    }
    pub(crate) fn take_close_tail(&mut self)->Result<AppCloseTail>{
        if !self.observations_settled(){return Err(self.note(Issue::Unknown));}
        let clock=self.client.clock().ok_or(Issue::Unknown)?;
        let tail=LeaseCloseTail::prepare(&self.identity,clock,&mut self.lease)?;
        self.tail_taken=true;Ok(AppCloseTail::prepared(tail))
    }
    pub(crate) fn retained_bytes(&self)->Option<usize>{
        if self.in_call || self.tail_taken{return None;}
        std::mem::size_of::<Self>().checked_add(selected_capacity(&self.selected)?)?
            .checked_add(self.client.retained_bytes()?)?.checked_add(self.tools.retained_bytes()?)?
            .checked_add(self.lease[0].retained_bytes()?)?
            .checked_add(crate::android_supplier_macos::CACHE_STORAGE_BYTES)
    }
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) enum RowCode{Busy,Interrupted,Refused,RecoveryRequired,VerifiedCandidate}
#[derive(Clone,Debug)]
pub(crate) struct CatalogRow{
    pub(crate) instance:[u8;16],pub(crate) occupants:u8,pub(crate) code:RowCode,
    pub(crate) metadata:Option<MetadataCandidate>,
}
pub(crate) enum CatalogMode{Refresh,Recover(MacToolchainSelection)}
pub(crate) struct CatalogCandidate{
    pub(crate) rows:Vec<CatalogRow>,
    // Candidate only. The owner creates current-session selection ONLY after
    // actual original join, the one moved tail and unchanged finality checks.
    pub(crate) recovery:Option<MacToolchainSelection>,
}
pub(crate) struct LeasedAndroidCatalogSlots{
    identity:OriginalUseIdentity,client:QueryClient,audit:watch::Receiver<Instant>,
    leases:[SharedUseLeaseSlots;ROW_LIMIT],metadata:[AndroidMetadataSlots;ROW_LIMIT],
    recovery:Option<MacToolchainSelection>,full:Option<AndroidToolchainSlots>,full_attempted:bool,
    entered:bool,in_call:bool,observations:bool,tail_taken:bool,
}
impl LeasedAndroidCatalogSlots{
    pub(crate) fn new(mode:CatalogMode,audit:watch::Receiver<Instant>)->Self{
        let identity=OriginalUseIdentity::reserved();
        let recovery=match mode{CatalogMode::Refresh=>None,CatalogMode::Recover(selected)=>Some(selected)};
        let full=recovery.as_ref().map(|selected|AndroidToolchainSlots::new(selected.clone(),audit.clone()));
        Self{identity:identity.clone(),client:QueryClient::new(audit.clone()),audit:audit.clone(),
            leases:std::array::from_fn(|_|SharedUseLeaseSlots::new(identity.clone())),
            metadata:std::array::from_fn(|_|AndroidMetadataSlots::new(audit.clone())),recovery,full,full_attempted:false,
            entered:false,in_call:false,observations:false,tail_taken:false}
    }
    pub(crate) fn original_identity(&self)->OriginalUseIdentity{self.identity.clone()}
    pub(crate) fn query_signal(&self)->Arc<Signal>{self.client.signal()}
    pub(crate) fn original_clock_slot(&self)->OriginalClockSlot{self.client.clock_slot()}
    pub(crate) fn original_clock(&self)->Option<Arc<OriginalClock>>{self.client.clock()}
    pub(crate) fn failure_data(&self)->Option<RawFailureData>{self.client.failure_data()}
    pub(crate) fn first_failure(&self)->Option<(AdmissionFailure,Instant)>{
        // Per-row semantic negatives deliberately do NOT feed the global owner.
        self.client.failure().map(|(f,t)|(admission_issue(f),t))
    }
    fn global(&mut self,issue:Issue)->Issue{self.client.publish(issue,Instant::now());issue}
    fn read_row(&mut self,index:usize,row:mrk_macos_installed_native::android_catalog_query::ScanRow,
        account:u32,generation:u32,clock:Arc<OriginalClock>,end:Instant,stop:&watch::Receiver<bool>)->Result<CatalogRow>{
        self.leases[index].admit_once(row.instance,account,clock)?;
        let reply=self.client.read_intent(row.instance,stop)?;
        let intent=intent_from_reply(&self.leases[index],&reply)?;
        let metadata=self.metadata[index].inspect_once(row.instance,account,generation,&intent,end,stop).map_err(tool_issue)?;
        self.leases[index].check_held(false)?;
        let recover=self.recovery.as_ref().is_some_and(|selected|selected.instance==metadata.selection.instance);
        if recover{
            if self.recovery.as_ref().is_none_or(|selected|!same_content(selected,&metadata.selection)){return Err(Issue::Refused);}
            self.full_attempted=true;
            self.full.as_mut().ok_or(Issue::Unknown)?
                .inspect_leased_once(&intent,end,stop).map_err(tool_issue)?;
            self.leases[index].check_held(false)?;
        }
        Ok(CatalogRow{instance:row.instance,occupants:row.occupants,
            code:if recover{RowCode::VerifiedCandidate}else{RowCode::RecoveryRequired},metadata:Some(metadata)})
    }
    fn settle_row(&mut self,index:usize,end:Instant)->bool{
        let clock=self.client.clock();let mut global=None;
        let metadata=self.metadata[index].settle_originals(end,&self.audit,&mut |failure,at|{
            let issue=tool_issue(failure);
            if !issue.row_negative(){
                if let Some(clock)=&clock{let _=clock.publish_local(at,issue.uncertain());}
                if global.is_none_or(|(_,old)|at<old){global=Some((issue,at));}
            }
        });
        // Explicit recovery's full reader is a dependent borrower of this row.
        // Retire it immediately, not after a later sibling consumes its F+10.
        let full=if self.full_attempted{
            match self.full.as_mut(){
                Some(full) if !full.settled()=>full.settle_originals(end,&self.audit,&mut |failure,at|{
                    let issue=tool_issue(failure);
                    if let Some(clock)=&clock{let _=clock.publish_local(at,issue.uncertain());}
                    if global.is_none_or(|(_,old)|at<old){global=Some((issue,at));}
                })==CloseOutcome::Settled,
                Some(full)=>full.settled(),None=>false,
            }
        }else{true};
        let lease=self.leases[index].settle_observations();
        if let Some((issue,at))=global{self.client.publish(issue,at);}
        metadata==CloseOutcome::Settled && full && lease
    }
    fn inspect_inner(&mut self,generation:u32,t:Instant,w:Instant,h:Instant,first:Option<Instant>,
        stop:&watch::Receiver<bool>)->Result<CatalogCandidate>{
        if generation==0 || generation==u32::MAX{return Err(Issue::Refused);}
        let clock=self.client.arm(Role::Catalog,t,w,h,first)?;
        let user=account(&clock)?;self.client.begin(user,stop)?;
        let scanned=self.client.scan(stop)?;
        if scanned.len()>ROW_LIMIT{return Err(Issue::Bounds);}
        let mut rows=Vec::with_capacity(scanned.len());let mut recovery=None;
        for(index,row)in scanned.into_iter().enumerate(){
            let result=self.read_row(index,row,user,generation,clock.clone(),w,stop);
            let target=self.recovery.as_ref().is_some_and(|selected|instance_data(&selected.instance)==Some(row.instance));
            let target_failure=result.as_ref().err().copied().filter(|_|target);
            if let Some(issue)=target_failure{
                let at=[self.leases[index].failure().map(|(_,at)|at),
                    self.metadata[index].first_failure().map(|(_,at)|at),
                    self.full.as_ref().and_then(AndroidToolchainSlots::first_failure).map(|(_,at)|at)]
                    .into_iter().flatten().min().unwrap_or_else(Instant::now);
                // Requested recovery failure is operation F, unlike a routine
                // unrelated negative row. Latch the actual earliest event NOW.
                self.client.publish(issue,at);
            }
            // Native/header originals settle on this same row before siblings;
            // ALL SH operands remain retained until the single group tail.
            let safely_settled=self.settle_row(index,h);
            if !safely_settled{return Err(Issue::Unknown);}
            if let Some(issue)=target_failure{return Err(issue);}
            let output=match result{
                Ok(output)=>output,
                Err(issue) if issue.row_negative()=>CatalogRow{
                    instance:row.instance,occupants:row.occupants,code:match issue{
                        Issue::Busy=>RowCode::Busy,Issue::Interrupted=>RowCode::Interrupted,_=>RowCode::Refused},metadata:None},
                Err(issue)=>return Err(issue),
            };
            if output.code==RowCode::VerifiedCandidate{recovery=output.metadata.as_ref().map(|m|m.selection.clone());}
            rows.push(output);
        }
        self.client.finish(stop)?;
        // A missing requested recovery never becomes a successful empty scan.
        if self.recovery.is_some() && recovery.is_none(){return Err(Issue::Refused);}
        Ok(CatalogCandidate{rows,recovery})
    }
    pub(crate) fn inspect_once(&mut self,generation:u32,t:Instant,w:Instant,h:Instant,first:Option<Instant>,
        stop:&watch::Receiver<bool>)->Result<CatalogCandidate>{
        if self.entered || self.tail_taken{return Err(self.global(Issue::Unknown));}
        self.entered=true;self.in_call=true;
        let result=self.inspect_inner(generation,t,w,h,first,stop);
        if let Err(issue)=result.as_ref(){self.global(*issue);}
        let query=self.client.settle_on_inspector();self.in_call=false;
        if !query{return Err(self.global(Issue::Unknown));}result
    }
    pub(crate) fn mark_interrupted(&mut self){self.client.publish(Issue::Unknown,Instant::now());self.in_call=true;}
    pub(crate) fn settle_observations(&mut self,end:Instant,cleanup:&watch::Receiver<Instant>,
        publish:&mut dyn FnMut(AdmissionFailure,Instant))->CloseOutcome{
        if self.observations || self.tail_taken || self.in_call{
            self.global(Issue::Unknown);return CloseOutcome::Unknown;
        }
        let mut settled=self.client.observations_settled();
        for index in 0..ROW_LIMIT{
            if !self.metadata[index].settled(){
                let clock=self.client.clock();
                let outcome=self.metadata[index].settle_originals(end,cleanup,&mut |failure,at|{
                    if !tool_issue(failure).row_negative(){
                        if let Some(clock)=&clock{let _=clock.publish_local(at,tool_issue(failure).uncertain());}
                        publish(failure,at);
                    }
                });
                settled=outcome==CloseOutcome::Settled && settled;
            }
            if !self.leases[index].observations_settled(){settled=self.leases[index].settle_observations()&&settled;}
        }
        if let Some(full)=self.full.as_mut().filter(|full|!full.settled()){
            let clock=self.client.clock();
            let outcome=full.settle_originals(end,cleanup,&mut |failure,at|{
                if let Some(clock)=&clock{let _=clock.publish_local(at,tool_issue(failure).uncertain());}
                publish(failure,at);
            });
            settled=outcome==CloseOutcome::Settled && settled;
        }
        self.observations=settled;
        if !settled{self.global(Issue::Unknown);}
        if let Some((failure,at))=self.first_failure(){publish(failure,at);}
        if settled{CloseOutcome::Settled}else{CloseOutcome::Unknown}
    }
    pub(crate) fn observations_settled(&self)->bool{
        self.observations && !self.in_call && !self.tail_taken && self.client.observations_settled()
            && self.leases.iter().all(SharedUseLeaseSlots::observations_settled)
            && self.metadata.iter().all(AndroidMetadataSlots::settled)
            && self.full.as_ref().is_none_or(AndroidToolchainSlots::settled)
    }
    pub(crate) fn take_close_tail(&mut self)->Result<AppCloseTail>{
        if !self.observations_settled(){return Err(self.global(Issue::Unknown));}
        let tail=LeaseCloseTail::prepare(&self.identity,self.client.clock().ok_or(Issue::Unknown)?,&mut self.leases)?;
        self.tail_taken=true;Ok(AppCloseTail::prepared(tail))
    }
    pub(crate) fn retained_bytes(&self)->Option<usize>{
        if self.in_call || self.tail_taken{return None;}
        let mut bytes=std::mem::size_of::<Self>().checked_add(self.client.retained_bytes()?)?;
        for index in 0..ROW_LIMIT{
            bytes=bytes.checked_add(self.leases[index].retained_bytes()?)?.checked_add(self.metadata[index].retained_bytes()?)?;
        }
        // Query control has its own additive limit. Full recovery's existing
        // tool-vector/native accounting is extra, never substituted for tool64.
        bytes=bytes.checked_add(crate::android_supplier_macos::CACHE_STORAGE_BYTES)?;
        if bytes>QUERY_CONTROL_LIMIT{return None;}
        if let Some(selected)=&self.recovery{bytes=bytes.checked_add(selected_capacity(selected)?)?;}
        if let Some(full)=&self.full{bytes=bytes.checked_add(full.retained_bytes()?)?;}
        Some(bytes)
    }
}
