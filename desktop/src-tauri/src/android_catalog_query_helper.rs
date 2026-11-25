//! Fixed privileged read-only catalog role. Source paths and UIDs never enter
//! this interface: the same authenticated native connection selects the account.
//! One original reader owns every per-row/common/native book until its moved
//! aggregate SH tail; the service coordinator alone joins that original worker.
#![forbid(unsafe_code)]
use std::{collections::BTreeMap,sync::Arc,thread,time::Duration};
use mrk_macos_installed_native::{
    android_catalog_query::{self as query,Candidate,EntryCode,Ingress,Kind,Packet,Payload,Presence,Role,ScanRow},
    android_catalog_query_wire::{decode_scan,encode_scan},
    android_registration::Failure as TransportFailure,
    vault_filesystem::Policy,
};
use crate::android_shared_lease_macos::{
    consume_helper_tail,hex,instance_data,FrozenCloseData,Issue,LeaseCloseTail,
    OriginalClock,OriginalUseIdentity,ReadSlots,SharedUseLeaseSlots,ROW_LIMIT,QUERY_CONTROL_LIMIT,CLOSE_TAIL_LEDGER_BYTES,
};
type Result<T>=std::result::Result<T,Issue>;
#[derive(Clone,Copy)]
struct FixedParents{destination:Option<usize>,leases:Option<usize>,intents:Option<usize>}
pub(crate) struct QueryWorkerEnd{pub(crate) success:bool,pub(crate) known:bool}
pub(crate) struct QueryReader{
    ingress:Arc<Ingress>,identity:OriginalUseIdentity,clock:Option<Arc<OriginalClock>>,
    common:ReadSlots,parents:Option<FixedParents>,reads:[ReadSlots;ROW_LIMIT],
    leases:[SharedUseLeaseSlots;ROW_LIMIT],keys:[[u8;16];ROW_LIMIT],used:usize,
    roster:Vec<ScanRow>,scanned:bool,packet:Option<Packet>,entered:bool,
    final_data:Option<FrozenCloseData>,control_cap:usize,control_precharged:bool,
}
impl QueryReader{
    /// All arrays/native slots and the group identity are reserved before GO.
    /// No native allocator, identity/clock API, pathname or helper call is used.
    pub(crate) fn new(ingress:Arc<Ingress>)->Self{
        let identity=OriginalUseIdentity::reserved();
        Self{ingress,identity:identity.clone(),clock:None,common:ReadSlots::new(),parents:None,
            reads:std::array::from_fn(|_|ReadSlots::new()),
            leases:std::array::from_fn(|_|SharedUseLeaseSlots::new(identity.clone())),
            keys:[[0;16];ROW_LIMIT],used:0,roster:Vec::new(),scanned:false,packet:None,
            entered:false,final_data:None,control_cap:QUERY_CONTROL_LIMIT,control_precharged:false}
    }
    fn failure(&self,issue:Issue){
        self.ingress.signal().failure_now(issue.uncertain());
        if issue==Issue::Unknown{self.ingress.signal().clock_unknown();}
    }
    fn clock(&self)->Result<Arc<OriginalClock>>{self.clock.clone().ok_or(Issue::Unknown)}
    /// Called by the original service owner before any worker GO. The full
    /// fixed stack ledger is reserved against the existing control budget here,
    /// not treated as free bytes because it initializes only at tail entry.
    pub(crate) fn precharge(&self)->Result<()>{
        if self.entered || self.clock.is_some() || self.final_data.is_some(){return Err(Issue::Unknown);}
        self.accounting()
    }
    /// The complete typed-owned source census is a separate explicit pre-GO
    /// gate. The existing original-tail precharge is still required, not replaced.
    pub(crate) fn service_precharge(&mut self,cap:usize)->Result<()>{
        if self.entered || self.control_precharged || cap==0 || cap>QUERY_CONTROL_LIMIT{return Err(Issue::Bounds);}
        self.precharge()?;
        let Some(bytes)=Self::service_high_water()else{return Err(Issue::Unavailable);};
        if bytes>cap{return Err(Issue::Bounds);}
        self.roster.try_reserve_exact(ROW_LIMIT).map_err(|_|Issue::Bounds)?;
        if self.roster.capacity()!=ROW_LIMIT{return Err(Issue::Bounds);}
        self.control_cap=cap;self.control_precharged=true;Ok(())
    }
    pub(crate) fn service_high_water()->Option<usize>{
        #[repr(C)] struct ArcAllocation<T>{counts:[usize;2],data:T}
        // Self includes all65 inline ReadSlots and32 lease books. Each reader
        // owns its own retained originals/names/C frame; the group shares ONE
        // identity allocation and ONE OriginalClock allocation. Ingress/Signal
        // request/reply backing is independently counted by ServiceRegistry.
        let readers=(1usize+2*ROW_LIMIT).checked_mul(ReadSlots::service_high_water()?)?;
        let mut bytes=std::mem::size_of::<Self>().checked_add(readers)?
            .checked_add(std::mem::size_of::<ArcAllocation<()>>())?
            .checked_add(std::mem::size_of::<ArcAllocation<OriginalClock>>())?;
        for more in [
            CLOSE_TAIL_LEDGER_BYTES,std::mem::size_of::<LeaseCloseTail>(),
            2*std::mem::size_of::<FrozenCloseData>(),
            4*ROW_LIMIT*std::mem::size_of::<ScanRow>(), // roster, decode and growth transient
            // Simultaneous String/(u64,u8) roster and [u8;16]/u8 union.
            // One extra insertion/split root per tree, including tiny inputs.
            (ROW_LIMIT+1)*(1024+512)+ROW_LIMIT*255,
            2*query::REPLY_BYTES+4*8192,
            // Directory block65,536, typed Intent raw/scratch/error strings,
            // fixed decode/encode fields and temporary hex/name/native args.
            128*1024,
        ]{bytes=bytes.checked_add(more)?;}
        (bytes<=QUERY_CONTROL_LIMIT).then_some(bytes)
    }
    fn accounting(&self)->Result<()>{
        // Self already includes inline Option<FrozenCloseData>; charge it once.
        let mut bytes=std::mem::size_of::<Self>().checked_add(CLOSE_TAIL_LEDGER_BYTES)
            .and_then(|n|n.checked_add(self.roster.capacity()*std::mem::size_of::<ScanRow>()))
            .and_then(|n|n.checked_add(self.common.retained_bytes()?)).ok_or(Issue::Unknown)?;
        for index in 0..ROW_LIMIT{
            bytes=bytes.checked_add(self.reads[index].retained_bytes().ok_or(Issue::Unknown)?)
                .and_then(|n|n.checked_add(self.leases[index].retained_bytes()?)).ok_or(Issue::Bounds)?;
        }
        if bytes>self.control_cap{Err(Issue::Bounds)}else{Ok(())}
    }
    fn prepare_common(&mut self,account:u32)->Result<FixedParents>{
        if let Some(parents)=self.parents{return Ok(parents);}
        self.common.arm(self.clock()?)?;
        let support=self.common.support()?;
        let mut parent=|name:&str,mode:u16|->Result<Option<usize>>{
            match self.common.optional(support,name,true,Some(mode),Policy::Empty)?{
                Some(root)=>self.common.optional(root,&account.to_string(),true,Some(mode),Policy::Empty),
                None=>Ok(None),
            }
        };
        let parents=FixedParents{destination:parent("android",0o755)?,leases:parent("android-leases",0o755)?,
            intents:parent("android-registration",0o700)?};
        self.parents=Some(parents);Ok(parents)
    }
    fn scan(&mut self,account:u32)->Result<Candidate>{
        if self.scanned{return Err(Issue::Unknown);}
        self.scanned=true;
        let parents=self.prepare_common(account)?;
        let mut union=BTreeMap::<[u8;16],u8>::new();
        for(parent,bit,suffix,expected)in[
            (parents.destination,1,"",nix::libc::DT_DIR),
            (parents.leases,2,".lock",nix::libc::DT_REG),
            (parents.intents,4,"",nix::libc::DT_DIR),
        ]{
            let Some(parent)=parent else{continue;};
            for(name,(_,kind))in self.common.names(parent,ROW_LIMIT)?{
                let key=name.strip_suffix(suffix).and_then(instance_data).ok_or(Issue::Refused)?;
                if kind!=expected{return Err(Issue::Refused);}
                if !union.contains_key(&key) && union.len()>=ROW_LIMIT{return Err(Issue::Bounds);}
                *union.entry(key).or_default()|=bit;
            }
        }
        if !self.roster.is_empty() || union.len()>self.roster.capacity(){return Err(Issue::Bounds);}
        self.roster.extend(union.into_iter().map(|(instance,occupants)|ScanRow{instance,occupants}));
        let bytes=encode_scan(&self.roster).ok_or(Issue::Bounds)?;
        // Shared DATA codec is the only roster shape; no ready-only fallback.
        if decode_scan(&bytes).as_deref()!=Some(self.roster.as_slice()){return Err(Issue::Unknown);}
        self.accounting()?;
        Ok(Candidate{payload:Payload::Scan,instance:[0;16],code:EntryCode::Observed,
            presence:Presence::default(),bytes})
    }
    fn intent_inner(&mut self,index:usize,key:[u8;16],account:u32)->Result<Candidate>{
        let clock=self.clock()?;
        self.leases[index].admit_once(key,account,clock.clone())?;
        self.reads[index].arm(clock)?;
        let original=&mut self.reads[index];
        let support=original.support()?;
        let registrations=original.optional(support,"android-registration",true,Some(0o700),Policy::Empty)?
            .ok_or(Issue::Interrupted)?;
        let account_parent=original.optional(registrations,&account.to_string(),true,Some(0o700),Policy::Empty)?
            .ok_or(Issue::Interrupted)?;
        let instance=original.optional(account_parent,&hex(&key),true,Some(0o700),Policy::Empty)?
            .ok_or(Issue::Interrupted)?;
        let intent=original.optional(instance,"intent.json",false,Some(0o400),Policy::Empty)?
            .ok_or(Issue::Interrupted)?;
        let raw=original.read_exact(intent,crate::android_registration_protocol::records::INTENT_BYTES,false)?;
        let _bound=self.leases[index].authenticate_intent(&raw)?;
        let stage=original.child_directory_present(instance,"stage")?;
        let quarantine=original.child_directory_present(instance,"quarantine")?;
        let android=original.optional(support,"android",true,Some(0o755),Policy::Empty)?;
        let destination=if let Some(android)=android{
            if let Some(parent)=original.optional(android,&account.to_string(),true,Some(0o755),Policy::Empty)?{
                original.child_directory_present(parent,&hex(&key))?
            }else{false}
        }else{false};
        self.leases[index].check_held(false)?;
        Ok(Candidate{payload:Payload::Intent,instance:key,code:EntryCode::Observed,
            presence:Presence{known:7,present:u8::from(destination)|u8::from(stage)*2|u8::from(quarantine)*4},bytes:raw})
    }
    fn intent(&mut self,key:[u8;16],account:u32,role:Role)->Result<Candidate>{
        if self.used>=ROW_LIMIT || self.keys[..self.used].contains(&key)
            || role==Role::Catalog && (!self.scanned || !self.roster.iter().any(|row|row.instance==key)){
            return Err(Issue::Refused);
        }
        self.prepare_common(account)?;
        let index=self.used;self.keys[index]=key;self.used+=1;
        let result=self.intent_inner(index,key,account);
        // The SAME entered reader retires all this row's private nonlease/native
        // observations before returning DATA. Its own SH remains held. A semantic
        // negative is a row result only after this actual safe settlement.
        let settled=self.reads[index].settle_observations(None);
        let lease_observations=self.leases[index].settle_observations();
        if !settled || !lease_observations{return Err(Issue::Unknown);}
        let candidate=match result{
            Ok(candidate)=>candidate,
            Err(issue) if issue.row_negative()=>Candidate{
                payload:Payload::Intent,instance:key,code:match issue{
                    Issue::Busy=>EntryCode::Busy,Issue::Interrupted=>EntryCode::Interrupted,_=>EntryCode::Refused},
                presence:Presence::default(),bytes:Vec::new()},
            Err(issue)=>return Err(issue),
        };
        self.accounting()?;Ok(candidate)
    }
    fn work(&mut self)->Result<()>{
        loop{
            if !self.ingress.signal().admitted(false){return Err(Issue::Stopped);}
            let next=match self.ingress.take(){
                Ok(next)=>next,Err(TransportFailure::Busy)=>{thread::park_timeout(Duration::from_millis(2));continue;},
                Err(_)=>return Err(Issue::Unknown),
            };
            let Some(packet)=next else{thread::park_timeout(Duration::from_millis(2));continue;};
            let request=packet.request();let account=packet.account();
            self.packet=Some(packet);
            if account==0 || account==u32::MAX || self.ingress.bound_account()!=Some(account)
                || self.clock()?.bounds()!=request.bounds{return Err(Issue::Unknown);}
            let candidate=match request.kind{
                Kind::Scan=>self.scan(account)?,
                Kind::ReadIntent=>self.intent(request.instance,account,request.bounds.role)?,
                Kind::Finish=>Candidate::empty(),
                _=>return Err(Issue::Unknown),
            };
            let packet=self.packet.take().ok_or(Issue::Unknown)?;
            self.ingress.acknowledge(packet,candidate).map_err(|_|Issue::Unknown)?;
            if request.kind==Kind::Finish{
                if !self.ingress.seal() || !self.ingress.input_settled(){return Err(Issue::Unknown);}
                return Ok(());
            }
        }
    }
    pub(crate) fn run(&mut self)->QueryWorkerEnd{
        if self.entered || !self.control_precharged{self.failure(Issue::Unknown);return QueryWorkerEnd{success:false,known:false};}
        self.entered=true;
        // Prepare binds the original bounds before worker GO. Missing binding
        // is setup uncertainty, never a reason to wait for first payload/rearm.
        if self.ingress.signal().bounds().is_none(){
            self.failure(Issue::Unknown);let _=self.ingress.retire_failed_input(self.packet.take());
            return QueryWorkerEnd{success:false,known:false};
        }
        let clock=match OriginalClock::for_helper(self.ingress.signal().clone()){
            Ok(clock)=>clock,Err(issue)=>{
                self.failure(issue);let _=self.ingress.retire_failed_input(self.packet.take());
                return QueryWorkerEnd{success:false,known:false};
            }
        };
        self.clock=Some(clock.clone());
        let outcome=self.work();
        if let Err(issue)=outcome{self.failure(issue);}
        let input=if outcome.is_ok(){self.ingress.input_settled()}
            else{self.ingress.retire_failed_input(self.packet.take())};
        // Entire group settles before ANY SH consumption. Even after one failure,
        // safe independent original nonlease cleanup continues within the common
        // original deadline; no sibling is reopened or replaced.
        let mut observations=input;
        for index in 0..ROW_LIMIT{
            if !self.reads[index].settled(){
                observations=self.reads[index].settle_observations(None)&&observations;
            }
        }
        observations=self.common.settle_observations(None)&&observations;
        for original in &mut self.leases{
            if !original.observations_settled(){observations=original.settle_observations()&&observations;}
        }
        let preclose=observations && self.accounting().is_ok() && self.ingress.input_settled();
        if !preclose{self.failure(Issue::Unknown);return QueryWorkerEnd{success:false,known:false};}
        let tail=match LeaseCloseTail::prepare(&self.identity,clock,&mut self.leases){
            Ok(tail)=>tail,Err(issue)=>{self.failure(issue);return QueryWorkerEnd{success:false,known:false};}
        };
        let requested_success=outcome.is_ok();
        // LAST custody transition. Only returned frozen scalar DATA is touched
        // after this consuming tail; the same actual worker then returns. Its
        // coordinator still must consume/join the original handle before H.
        let frozen=consume_helper_tail(tail);
        let known=frozen.settled && !frozen.failure.unknown;
        let success=requested_success && known && frozen.failure.first.is_none();
        self.final_data=Some(frozen);
        QueryWorkerEnd{success,known}
    }
}

#[cfg(test)]
mod control_allocation_data_tests{
    use super::*;
    #[test]
    fn complete_query_working_set_is_known_before_original_entry(){
        let upper=QueryReader::service_high_water().unwrap();
        assert!(upper<=QUERY_CONTROL_LIMIT);
        assert!(upper>std::mem::size_of::<QueryReader>()+(1+2*ROW_LIMIT)*ReadSlots::service_high_water().unwrap());
        let mut original=QueryReader::new(Arc::new(Ingress::new()));
        assert_eq!(original.service_precharge(0),Err(Issue::Bounds));
        assert_eq!(original.service_precharge(upper-1),Err(Issue::Bounds));
        original.service_precharge(upper).unwrap();
        assert_eq!(original.roster.capacity(),ROW_LIMIT);
        assert!(!original.entered && original.clock.is_none());
        assert_eq!(original.service_precharge(upper),Err(Issue::Bounds));
    }
}
