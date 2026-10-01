//! Windows Required Notes v1 original context. Not an Image capability or a second
//! release engine: the common core drives this closed primitive/finality graph.
//! Native/installed qualification and a real compiled Notes closure are separate.
#[path="required_notes_wire.rs"] pub mod wire;
#[path="notes_security.rs"] mod security;
#[path="notes_custody.rs"] mod custody;
#[path="notes_namespace.rs"] mod namespace;
#[path="notes_reservations.rs"] mod reservations;
use wire::{Fault,Result,Request,Reply,Operation as Op,Status,flags,Cursor};
use custody::{Custody,Access,Pool,Effect,HEAP,HELPER};
use namespace::{Graph,Keys,KeyKind,Role,Edge,batch,u32s,u64s,NONE};
use security::{Descriptor,hash};
use crate::{Metadata,FileIdentity,FileKind,SlotState,DirectoryEntry};
use sha2::{Digest,Sha256};
use std::{mem::size_of,sync::Arc};


use reservations::{Credit,Ledger,Tickets,Plan as TicketPlan,Binding as TicketBinding,
    Purpose as TicketPurpose,Selector as TicketSelector,Unit as TicketUnit,PassBound};
const TICKET_CORE:u32=0;
const TICKET_RAW:u32=1;
const TICKET_SECURITY_RAW:u32=2;
const TICKET_BROAD_POST:u32=3;
const TICKET_CORRECTIVE_LEAD:u32=4;
const TICKET_DELETE_PARENT:u32=5;
const TICKET_PRELUDE:u32=6;
const TICKET_EXIT:u32=7;
const TICKET_CAPTURE_TAIL:u32=8;
#[derive(Clone,Copy)]
enum TicketFlowKind {Create,MoveRaw,Publish,SecurityRaw,BroadPost,DeleteParent,DeleteFence,RestoreRaw,CorrectiveLead}
#[derive(Clone,Copy)]
struct TicketFlow {ticket:usize,binding:TicketBinding,kind:TicketFlowKind,post:ReadCounts}
enum TicketHome {Discard,NewPass,Pass(usize)}
struct TicketActive {unit:TicketUnit,home:TicketHome,heap_before:usize,dynamic_heap:bool,operation:Op}
#[derive(Clone,Copy)]
struct ReadCounts {refresh:[u32;154],lease:u32}
impl Default for ReadCounts{fn default()->Self{Self{refresh:[0;154],lease:0}}}
impl ReadCounts {
    fn refresh(&mut self,i:usize)->Result<()>{
        let n=self.refresh.get_mut(i).ok_or(Fault::Key)?;
        *n=n.checked_add(1).ok_or(Fault::Capacity)?;Ok(())
    }
    fn lease(&mut self)->Result<()>{self.lease=self.lease.checked_add(1).ok_or(Fault::Capacity)?;Ok(())}
    fn empty(&self)->bool{self.lease==0&&self.refresh.iter().all(|n|*n==0)}
    fn add(&mut self,b:&Self)->Result<()>{
        for (n,v) in self.refresh.iter_mut().zip(b.refresh){*n=n.checked_add(v).ok_or(Fault::Capacity)?;}
        self.lease=self.lease.checked_add(b.lease).ok_or(Fault::Capacity)?;Ok(())
    }
    fn upper(&mut self,b:&Self){
        for (n,v) in self.refresh.iter_mut().zip(b.refresh){*n=(*n).max(v);}
        self.lease=self.lease.max(b.lease);
    }
    fn times(self,n:u32)->Result<Self>{
        let mut out=Self::default();
        for (to,from) in out.refresh.iter_mut().zip(self.refresh){*to=from.checked_mul(n).ok_or(Fault::Capacity)?;}
        out.lease=self.lease.checked_mul(n).ok_or(Fault::Capacity)?;Ok(out)
    }
}

#[derive(Clone)] struct Snapshot {metadata:Metadata,security:usize}
struct SecurityRecord {key:u64,object:usize,scope:u32,data:Arc<Descriptor>}
#[derive(Clone)] struct Observation {
    key:u64,object:usize,scope:u32,tag:u32,flags:u32,snapshot:Snapshot,
    epoch:u64,security_epoch:u64,effect:u64,pass:u64,content:[u8;32],roster:[u8;32],
    capture:u64,parent_object:u64,parent_observation:u64,parent_epoch:u64,cause:u64,name:String,
}
struct Object {
    key:u64,row:usize,scope:u32,creation:bool,slot:Option<usize>,attempted:bool,absent:u64,
    edge:Option<Edge>,epoch:u64,security_epoch:u64,current:Option<Snapshot>,
    capture:u64,last_emitted:u64,pending:u64,cause:u64,effect:u64,
    latest_pass:u64,write_open:bool,written:u64,write_finished:bool,
    private:Option<Arc<Descriptor>>,target:Option<Arc<Descriptor>>,target_parent:Option<Arc<Descriptor>>,expected_roster:Option<Vec<DirectoryEntry>>,
}
#[derive(Clone)] struct Presence {
    key:u64,object:usize,parent:usize,present:Option<DirectoryEntry>,pass:u64,parent_absent:u64,
    parent_observation:u64,epoch:u64,roster:[u8;32],edge_key:u64,name:String,
}
struct Pass {
    key:u64,object:usize,epoch:u64,before:Snapshot,after:Option<Snapshot>,roster:bool,
    entries:Vec<DirectoryEntry>,bytes:u64,hash:Sha256,digest:[u8;32],complete:bool,failed:bool,first:bool,
    byte_limit:u64,entry_limit:usize,native_calls:u32,native_limit:u32,dots:u8,
    credit:Option<TicketUnit>,expected_roster:Option<Vec<DirectoryEntry>>,observations:u32,
}
struct Data {key:u64,scope:u32,kind:u32,bytes:Vec<u8>}
struct Binding {key:u64,object:usize,size:u64,digest:[u8;32],bytes:Vec<u8>,complete:bool}
#[derive(Default)]struct Scope {attempted:bool,root:Option<usize>,settlement_attempted:bool,settlement:u64,joined:bool}
struct Body{token:u64,count:u32,total:u32,bytes:Vec<u8>,status:Status}
impl Body {
    fn unit(token:u64)->Self{Self{token,count:0,total:0,bytes:Vec::new(),status:Status::Ok}}
    fn one(token:u64,bytes:Vec<u8>)->Self{Self{token,count:1,total:1,bytes,status:Status::Ok}}
}
pub struct NotesContext {
    owner:u64,keys:Keys,graph:Graph,io:Custody,
    ticket_ledger:Ledger,ticket_book:Tickets,ticket_active:Option<TicketActive>,ticket_flow:Option<TicketFlow>,
    ticket_prelude:Option<usize>,ticket_finality:usize,ticket_factory:Vec<(u64,usize)>,
    root:String,drive:String,components:Vec<String>,device:Option<String>,registered:FileIdentity,
    lease_key:u64,lease_slot:Option<usize>,lease_snapshot:Option<Snapshot>,lease_begun:bool,
    group:Vec<u8>,private:Option<Arc<Descriptor>>,scopes:[Scope;3],scope:u32,
    objects:Vec<Object>,mapping:Vec<(usize,Option<usize>)>,capture_objects:Vec<usize>,
    observations:Vec<Observation>,presences:Vec<Presence>,passes:Vec<Pass>,security:Vec<SecurityRecord>,
    data:Vec<Data>,bindings:Vec<Binding>,payload:Option<(u64,[u8;32])>,
    first_failure:Option<Fault>,unknown:bool,stop:bool,deadline:bool,compensation:bool,compensation_joined:bool,
    corrective:Option<(u64,u64)>,committed_cleanup:bool,committed:u64,rolled_back:u64,
    retirement_attempted:bool,epoch:u64,active_operation:bool,
}
unsafe impl Send for NotesContext {}
impl NotesContext {
    /// Allocates one Notes-only unstarted owner. No native acquisition occurs.
    pub fn prepare(input:&[u8])->Result<Self>{
        let root=wire::RootBinding::parse(input)?;let mut keys=Keys::new();let graph=Graph::new(&mut keys)?;
        let lease_key=keys.take(KeyKind::Lease,0)?;
        let mut objects=Vec::new();objects.try_reserve_exact(154).map_err(|_|Fault::Capacity)?;
        let mut context=Self{owner:(u64::from(std::process::id())<<32)|1,keys,graph,io:Custody::new()?,
            ticket_ledger:Ledger::new(),ticket_book:Tickets::new()?,ticket_active:None,ticket_flow:None,
            ticket_prelude:None,ticket_finality:usize::MAX,ticket_factory:fixed_vec(64)?,
            root:root.root.to_owned(),drive:root.root[..2].to_owned(),components:root.root[3..].split('\\').map(str::to_owned).collect(),
            device:None,registered:FileIdentity{volume_serial:root.volume,file_id:root.file_id},lease_key,lease_slot:None,
            lease_snapshot:None,lease_begun:false,group:Vec::new(),private:None,scopes:std::array::from_fn(|_|Scope::default()),scope:0,
            objects,mapping:fixed_vec(38)?,capture_objects:fixed_vec(38)?,observations:Vec::new(),presences:Vec::new(),passes:Vec::new(),
            security:Vec::new(),data:fixed_vec(64)?,bindings:fixed_vec(4)?,payload:None,first_failure:None,unknown:false,stop:false,deadline:false,
            compensation:false,compensation_joined:false,corrective:None,committed_cleanup:false,committed:0,rolled_back:0,
            retirement_attempted:false,epoch:0,active_operation:false};
        context.ticket_bootstrap()?;context.budget(HELPER)?;Ok(context)
    }
    pub fn owner(&self)->u64{self.owner}
    pub fn mark_bridge_unknown(&mut self){self.unknown=true;self.io.mark_unknown();self.fail(Fault::NativeUnknown);}
    /// DATA classification only. An active native frame does not prevent safe
    /// retained DATA, but an unreturned context/bridge call never admits reentry.
    pub fn bridge_callable(&self)->bool{!self.active_operation}
    pub fn bridge_recovery_chosen(&self)->bool{self.compensation||self.committed_cleanup}
    pub fn bridge_record_failure(&mut self,error:Fault){self.fail(error);}
    pub fn bridge_status(&self,error:Fault,bridge_unknown:bool)->Reply{
        let status=if self.is_unknown()||bridge_unknown{Status::Unknown}else{Status::Refused};
        let mut r=self.header(status,Some(error),Op::ContextStatus,0,self.io.counters());
        if bridge_unknown{r.flags|=flags::BRIDGE_FRAME_UNKNOWN;}r
    }
    fn fail(&mut self,e:Fault){
        if self.first_failure.is_none(){self.first_failure=Some(e)}
        if e==Fault::NativeUnknown{self.unknown=true}
        if e==Fault::Cancelled{self.stop=true}if e==Fault::Deadline{self.deadline=true}
        if !self.io.frames_active(){
            // An abandoned, definitely returned read-only pass is FAILED, never
            // completed/EOF. Forfeit its remaining original credits so bounded
            // correction/finality can use fresh independent passes or closes.
            for p in self.passes.iter_mut().filter(|p|!p.complete){p.failed=true;p.credit=None;}
        }
    }
    fn is_unknown(&self)->bool{self.unknown||self.io.native_unknown()}
    fn heap_bytes(&self)->Result<usize>{
        let mut n=self.io.heap().ok_or(Fault::Capacity)?.checked_add(self.graph.heap()).ok_or(Fault::Capacity)?;
        macro_rules! add {($v:expr)=>{n=n.checked_add($v).ok_or(Fault::Capacity)?;}}
        add!(size_of::<Self>()+self.root.capacity()+self.drive.capacity()+self.group.capacity());
        add!(self.ticket_book.heap()+self.ticket_factory.capacity()*size_of::<(u64,usize)>());
        add!(self.components.capacity()*size_of::<String>()+self.components.iter().map(|s|s.capacity()).sum::<usize>());
        add!(self.device.as_ref().map_or(0,|s|s.capacity()));
        add!(self.objects.capacity()*size_of::<Object>()+self.mapping.capacity()*size_of::<(usize,Option<usize>)>()+
            self.capture_objects.capacity()*size_of::<usize>());
        add!(self.objects.iter().map(|o|o.edge.as_ref().map_or(0,|e|e.name.capacity())+o.expected_roster.as_ref().map_or(0,|r|r.capacity()*size_of::<DirectoryEntry>()+r.iter().map(|e|e.name.capacity()).sum::<usize>())).sum::<usize>());
        add!(self.observations.capacity()*size_of::<Observation>()+self.observations.iter().map(|o|o.name.capacity()).sum::<usize>());
        add!(self.presences.capacity()*size_of::<Presence>()+self.presences.iter().map(|p|p.name.capacity()+p.present.as_ref().map_or(0,|e|e.name.capacity())).sum::<usize>());
        add!(self.passes.capacity()*size_of::<Pass>()+self.passes.iter().map(|p|p.entries.capacity()*size_of::<DirectoryEntry>()+p.entries.iter().map(|e|e.name.capacity()).sum::<usize>()+p.expected_roster.as_ref().map_or(0,|r|r.capacity()*size_of::<DirectoryEntry>()+r.iter().map(|e|e.name.capacity()).sum::<usize>())).sum::<usize>());
        add!(self.security.capacity()*size_of::<SecurityRecord>()+self.security.iter().map(|s|s.data.heap()).sum::<usize>());
        add!(self.data.capacity()*size_of::<Data>()+self.data.iter().map(|d|d.bytes.capacity()).sum::<usize>());
        add!(self.bindings.capacity()*size_of::<Binding>()+self.bindings.iter().map(|b|b.bytes.capacity()).sum::<usize>());
        // Private/target derived policies not yet interned are also charged,
        // conservatively even if an Arc aliases another retained policy.
        add!(self.private.as_ref().map_or(0,|d|d.heap()));
        add!(self.objects.iter().map(|o|o.private.as_ref().map_or(0,|d|d.heap())+o.target.as_ref().map_or(0,|d|d.heap())+o.target_parent.as_ref().map_or(0,|d|d.heap())).sum::<usize>());
        if n>HEAP{Err(Fault::Capacity)}else{Ok(n)}
    }
    fn budget(&self,extra:usize)->Result<()>{
        if self.heap_bytes()?.checked_add(extra).is_none_or(|n|n>HEAP)||
            self.ticket_allowance()?.checked_add(HELPER).is_none_or(|n|extra>n){
            Err(Fault::Capacity)
        }else{Ok(())}
    }
    fn remaining(&self)->Result<usize>{self.ticket_allowance()}
    fn reserve_security(&mut self)->Result<()>{
        let remaining=self.remaining()?;grow(&mut self.security,1,remaining)
    }
    fn reserve_observation(&mut self)->Result<()>{
        let remaining=self.remaining()?;grow(&mut self.observations,1,remaining)
    }
    fn reserve_presence(&mut self)->Result<()>{
        let remaining=self.remaining()?;grow(&mut self.presences,1,remaining)
    }
    fn current_object(&self,key:u64)->Result<usize>{
        let i=self.objects.iter().position(|o|o.key==key).ok_or(Fault::Key)?;
        if self.objects[i].scope!=self.scope||self.scope==0{return Err(Fault::Stale)}Ok(i)
    }
    fn active_object(&self,row:usize)->Result<usize>{
        let (source,creation)=*self.mapping.get(row).ok_or(Fault::Key)?;Ok(creation.unwrap_or(source))
    }
    fn slot(&self,i:usize)->Result<usize>{self.objects.get(i).and_then(|o|o.slot).ok_or(Fault::Key)}
    fn owned(&self,i:usize)->Result<usize>{
        let slot=self.slot(i)?;if self.io.state(slot)?!=SlotState::Owned||
            self.graph.deletes.iter().any(|d|d.object==self.objects[i].key&&d.accepted){return Err(Fault::Phase)}Ok(slot)
    }
    fn observation(&self,key:u64)->Result<&Observation>{self.observations.iter().find(|o|o.key==key).ok_or(Fault::Key)}
    fn pass_index(&self,key:u64,complete:bool)->Result<usize>{
        let i=self.passes.iter().position(|p|p.key==key).ok_or(Fault::Key)?;let p=&self.passes[i];
        if p.failed||p.complete!=complete||self.objects[p.object].scope!=self.scope||
            self.objects[p.object].latest_pass!=key||self.objects[p.object].epoch!=p.epoch{return Err(Fault::Stale)}Ok(i)
    }
    fn current_name(&self,i:usize)->Result<String>{
        // A proved historical NoHandle source keeps its original acquisition
        // spelling. It must not be relabeled through a staged replacement of an
        // absent parent merely because active_object now selects that creation.
        let original=self.objects.get(i).ok_or(Fault::Key)?;
        if !original.creation{
            if let Some(slot)=original.slot{
                if self.io.state(slot)?==SlotState::NoHandle{
                    return Ok(self.io.book.slot(slot).map_err(custody::fault)?.canonical.clone())
                }
            }
        }
        let mut parts:Vec<String>=Vec::new();let mut at=i;
        for _ in 0..39 {
            let o=self.objects.get(at).ok_or(Fault::Key)?;
            if o.row==0{let base=self.device.as_ref().ok_or(Fault::Phase)?;
                let mut out=format!("{}\\{}",base,self.components.join("\\"));
                for name in parts.iter().rev(){out.push('\\');out.push_str(name);}return Ok(out)}
            let edge=o.edge.as_ref().ok_or(Fault::Phase)?;parts.push(edge.name.clone());at=self.active_object(edge.parent)?;
        }Err(Fault::Namespace)
    }
    fn record_security(&mut self,object:usize,data:Arc<Descriptor>)->Result<usize>{
        if let Some(i)=self.security.iter().position(|s|s.object==object&&s.data.raw==data.raw&&s.data.canonical==data.canonical){return Ok(i)}
        let i=self.security.len();self.reserve_security()?;
        self.security.push(SecurityRecord{key:self.keys.take(KeyKind::Data,self.scope)?,object,scope:self.scope,data});self.budget(HELPER)?;Ok(i)
    }
    fn snapshot(&mut self,i:usize)->Result<Snapshot>{
        self.budget(HELPER)?;let slot=self.owned(i)?;let canonical=self.current_name(i)?;
        let metadata=self.io.metadata(slot,&canonical)?;
        self.reserve_security()?;let remaining=self.remaining()?;
        let data=self.io.security(slot,remaining)?;let security=self.record_security(i,data)?;
        if metadata.identity.volume_serial!=self.registered.volume_serial{return Err(Fault::Stale)}
        Ok(Snapshot{metadata,security})
    }
    fn same(&self,a:&Snapshot,b:&Snapshot)->bool{
        a.metadata==b.metadata&&self.security[a.security].data.same(&self.security[b.security].data)
    }
    fn stable(&self,a:&Snapshot,b:&Snapshot,content:bool)->bool{
        a.metadata.identity==b.metadata.identity&&a.metadata.kind==b.metadata.kind&&a.metadata.attributes==b.metadata.attributes&&
            a.metadata.links==b.metadata.links&&a.metadata.creation==b.metadata.creation&&
            (!content||a.metadata.size==b.metadata.size)&&self.security[a.security].data.same(&self.security[b.security].data)
    }
    fn add_object(&mut self,row:usize,creation:bool,edge:Option<Edge>)->Result<usize>{
        if self.objects.len()>=154{return Err(Fault::Capacity)}
        let i=self.objects.len();let capture=if self.scope==1{0}else{self.capture_objects.get(row).and_then(|i|self.objects.get(*i)).map_or(0,|o|o.capture)};
        self.objects.push(Object{key:self.keys.take(KeyKind::Object,self.scope)?,row,scope:self.scope,creation,slot:None,attempted:false,absent:0,
            edge,epoch:0,security_epoch:0,current:None,capture,last_emitted:0,pending:0,cause:0,effect:0,latest_pass:0,
            write_open:false,written:0,write_finished:false,private:None,target:None,target_parent:None,expected_roster:None});self.ticket_original_close(i)?;Ok(i)
    }
    fn extend_mapping(&mut self)->Result<()>{
        while self.mapping.len()<self.graph.rows.len(){
            let row=self.mapping.len();let logical=&self.graph.rows[row];
            let edge=logical.parent.map(|parent|Edge{parent,name:logical.name.clone()});
            let i=self.add_object(row,logical.role.created(),edge)?;
            self.mapping.push((i,None));if self.scope==1{self.capture_objects.push(i);}
        }Ok(())
    }
    fn data(&mut self,kind:u32,bytes:Vec<u8>)->Result<u64>{
        if bytes.len()==8&&bytes[..4]==[0;4]{return Ok(0)}
        let remaining=self.remaining()?;grow(&mut self.data,1,remaining)?;
        let key=self.keys.take(KeyKind::Data,self.scope)?;self.data.push(Data{key,scope:self.scope,kind,bytes});self.budget(HELPER)?;Ok(key)
    }
    fn scope_map(&self)->Vec<u8>{batch(self.mapping.iter().enumerate().map(|(row,(source,creation))|{
        let state=|i:usize|match self.objects[i].slot.and_then(|slot|self.io.state(slot).ok()){
            None|Some(SlotState::Reserved)=>1,Some(SlotState::Owned)=>2,Some(SlotState::NoHandle)=>3,
            Some(SlotState::Closed)=>4,_=>5};
        let mut b=Vec::new();u64s(&mut b,&[self.graph.rows[row].key,self.objects[*source].key,
            creation.map_or(0,|i|self.objects[i].key),self.capture_objects.get(row).map_or(0,|i|self.objects[*i].key)]);
        u32s(&mut b,&[self.scope,state(*source),creation.map_or(0,state),0]);b}).collect())}
    fn schedule(&self)->Vec<u8>{self.ticket_ledger.table()}
    fn factory(&mut self,op:u32)->Result<Body>{
        let logical=self.data(1,self.graph.logical_table())?;
        let mapping=if self.scope==0{0}else{self.data(2,self.scope_map())?};
        let moves=self.data(3,self.graph.move_table())?;let deletes=self.data(4,self.graph.delete_table())?;
        let transitions=self.data(5,self.graph.transition_table())?;
        // Install the exact retained schedule extent before the allocation
        // snapshot, then precharge every future factory page from its original
        // DATA key. Existing kind6 pages are immutable historical snapshots.
        let schedule=self.data(6,vec![0;8+16*(4+64)])?;
        let key=self.keys.take(KeyKind::Factory,self.scope)?;
        let mut pages=Vec::new();
        for data_key in [logical,mapping,moves,deletes,transitions,schedule].into_iter().filter(|k|*k!=0){
            let size=self.data.iter().find(|d|d.key==data_key).ok_or(Fault::Key)?.bytes.len();
            pages.push((data_key,size));
        }
        self.ticket_factory_pages(key,&pages)?;
        self.ticket_flush_dynamic_heap()?;
        let allocated=self.schedule();
        let retained=self.data.iter_mut().find(|d|d.key==schedule).ok_or(Fault::Key)?;
        if retained.bytes.len()!=allocated.len(){return Err(Fault::Phase)}
        retained.bytes.copy_from_slice(&allocated);
        let mut b=Vec::with_capacity(128);
        b.extend_from_slice(b"MRKNFG1\0");u32s(&mut b,&[128,op]);u64s(&mut b,&[self.owner]);u32s(&mut b,&[self.scope,self.graph.rows.len() as u32]);
        let root=if self.scope==0{0}else{self.objects[self.mapping[0].0].key};
        u64s(&mut b,&[key,self.lease_key,root,logical,mapping,moves,deletes,transitions,schedule]);
        let mask=if self.graph.apply{15}else if self.graph.selected{3}else{0};
        u32s(&mut b,&[if mask&1!=0{self.graph.f}else{0},if mask&2!=0{self.graph.p}else{0},
            if mask&4!=0{self.graph.m}else{0},if mask&8!=0{u32::from(self.graph.backup)}else{0},mask,0]);
        Ok(Body::one(key,b))
    }

    fn lease_check(&mut self,acquire:bool)->Result<Body>{
        self.budget(HELPER)?;self.reserve_observation()?;
        if acquire {
            if self.lease_begun{return Err(Fault::OneUse)}self.lease_begun=true;self.io.observe_user()?;
            self.group=self.io.primary_group()?;let user=self.io.user()?.to_vec();
            self.private=Some(Arc::new(Descriptor::private(&user,&self.group,self.remaining()?)?));
            let device=self.io.mapping(&self.drive)?;self.device=Some(device.clone());
            let mut slots=Vec::new();let mut parent=None;let mut canonical=format!("{device}\\");
            for n in 0..=self.components.len(){
                let name=if n==0{canonical.clone()}else{
                    if !canonical.ends_with('\\'){canonical.push('\\');}canonical.push_str(&self.components[n-1]);self.components[n-1].clone()
                };
                let slot=self.io.reserve(parent,&name,canonical.clone(),true)?;slots.push(slot);
                let leaf=n==self.components.len();
                self.io.open(slot,if leaf{Access::Lease}else{Access::ReadDirectory},false,None,None)?;
                let metadata=self.io.metadata(slot,&canonical)?;self.reserve_security()?;let remaining=self.remaining()?;
                let descriptor=self.io.security(slot,remaining)?;
                let sec=self.record_security(usize::MAX,descriptor)?;
                if metadata.kind!=FileKind::Directory{return Err(Fault::Namespace)}
                if leaf{
                    if metadata.identity!=self.registered{return Err(Fault::Stale)}
                    self.lease_slot=Some(slot);self.lease_snapshot=Some(Snapshot{metadata,security:sec});
                }
                parent=Some(slot);
            }
            // Only after the actual final registered root identity/path/security
            // is retained may the original finite ancestor chain be consumed.
            for slot in slots[..slots.len()-1].iter().rev(){self.io.close(*slot,true)?;}
        }else if !self.lease_begun||self.lease_slot.is_none(){return Err(Fault::Phase)}
        self.io.check_user()?;
        if self.io.mapping(&self.drive)?!=*self.device.as_ref().ok_or(Fault::Phase)?{return Err(Fault::Stale)}
        let slot=self.lease_slot.ok_or(Fault::Phase)?;let canonical=format!("{}\\{}",self.device.as_ref().ok_or(Fault::Phase)?,self.components.join("\\"));
        let metadata=self.io.metadata(slot,&canonical)?;self.reserve_security()?;let remaining=self.remaining()?;
        let raw=self.io.security(slot,remaining)?;
        let security=self.record_security(usize::MAX,raw)?;let now=Snapshot{metadata,security};
        let before=self.lease_snapshot.as_ref().ok_or(Fault::Phase)?;
        // The lease is NOT a subtree/content lock. Native parent timestamps may
        // legitimately change through our transaction; identity+policy may not.
        if !self.stable(before,&now,false)||now.metadata.identity!=self.registered{return Err(Fault::Stale)}
        let key=self.keys.take(KeyKind::Observation,0)?;
        let obs=Observation{key,object:usize::MAX,scope:0,tag:3,flags:0,snapshot:now,epoch:0,security_epoch:0,effect:0,pass:0,
            content:[0;32],roster:[0;32],capture:0,parent_object:0,parent_observation:0,parent_epoch:0,cause:0,name:String::new()};
        let bytes=self.encode_observation(&obs)?;self.observations.push(obs);Ok(Body::one(key,batch(vec![bytes])))
    }
    fn enter_scope(&mut self,scope:u32)->Result<Body>{
        if scope!=self.scope+1||scope>3||self.first_failure.is_some()||self.retirement_attempted{return Err(Fault::Phase)}
        if self.scope!=0&&self.scopes[self.scope as usize-1].settlement==0{return Err(Fault::Incomplete)}
        self.lease_check(false)?;self.io.set_scope(scope)?;self.scope=scope;self.mapping.clear();self.extend_mapping()?;
        let i=self.mapping[0].0;self.scopes[scope as usize-1].attempted=true;self.scopes[scope as usize-1].root=Some(i);
        let canonical=self.current_name(i)?;let lease=self.lease_slot.ok_or(Fault::Phase)?;
        // Closed empty-relative original-root reopen, not a caller path. The
        // original lease prevents root replacement; same full ID is re-admitted.
        let slot=self.io.reserve(Some(lease),"",canonical,true)?;self.objects[i].slot=Some(slot);self.objects[i].attempted=true;
        self.io.open(slot,if scope==3{Access::WriteDirectory}else{Access::ReadDirectory},false,None,None)?;
        let now=self.snapshot(i)?;if now.metadata.identity!=self.registered{return Err(Fault::Stale)}
        self.objects[i].current=Some(now);self.factory(4)
    }
    fn source_anchor(&self,key:u64,row:usize,scope:u32,original_capture:bool)->Result<&Observation>{
        let o=self.observation(key)?;
        if o.object==usize::MAX||self.objects[o.object].row!=row||o.scope!=scope||o.flags&128==0||o.tag==3{return Err(Fault::Key)}
        if original_capture&&(o.tag!=1||o.capture!=o.key||self.objects[o.object].capture!=o.key){return Err(Fault::Stale)}Ok(o)
    }
    fn fixed(&mut self,root:u64)->Result<Body>{
        if self.scope!=1||self.current_object(root)?!=self.mapping[0].0{return Err(Fault::Phase)}
        self.graph.freeze_fixed(&mut self.keys)?;self.extend_mapping()?;self.factory(5)
    }
    fn version(&mut self,r:Request,input:&[u8])->Result<Body>{
        if self.scope!=1||self.current_object(r.a)?!=self.mapping[0].0{return Err(Fault::Phase)}
        let config=self.graph.rows.iter().position(|r|r.role==Role::Config).ok_or(Fault::Phase)?;
        self.source_anchor(r.b,config,1,true)?;
        let path=if r.number==0{None}else{Some(wire::relative(input)?)};
        self.graph.freeze_version(&mut self.keys,path)?;self.extend_mapping()?;self.factory(6)
    }
    fn selected(&mut self,r:Request,input:&[u8])->Result<Body>{
        if self.scope!=1||self.current_object(r.a)?!=self.mapping[0].0{return Err(Fault::Phase)}
        let config=self.graph.rows.iter().position(|r|r.role==Role::Config).ok_or(Fault::Phase)?;
        self.source_anchor(r.b,config,1,true)?;
        match self.graph.version_row {Some(row)=>{self.source_anchor(r.c,row,1,true)?;},None if r.c==0=>{},_=>return Err(Fault::Key)}
        let mut c=Cursor::new(input);let n=c.u32()? as usize;let other=c.u32()? as usize;
        let path=wire::relative(c.bytes(n)?)?;let counterpart=c.bytes(other)?;c.finish()?;
        let other=if r.count==0{None}else{Some(wire::relative(counterpart)?)};
        self.graph.freeze_selected(&mut self.keys,r.number,path,other)?;self.extend_mapping()?;self.factory(7)
    }
    fn proof(&self,key:u64,object:usize)->Result<&Presence>{
        let p=self.presences.iter().find(|p|p.key==key).ok_or(Fault::Key)?;
        if p.object!=object||self.objects[object].scope!=self.scope{return Err(Fault::Stale)}
        if p.parent_absent==0&&self.objects[p.parent].epoch!=p.epoch{return Err(Fault::Stale)}Ok(p)
    }
    fn presence(&mut self,key:u64,parent_proof:u64)->Result<Body>{
        self.reserve_presence()?;
        let i=self.current_object(key)?;let row=self.objects[i].row;
        let edge=self.objects[i].edge.clone().ok_or(Fault::Namespace)?;
        let parent=self.active_object(edge.parent)?;
        let (present,pass,parent_absent,parent_observation,epoch,roster)=
            if let Some(abs)=self.presences.iter().find(|p|p.key==parent_proof).cloned(){
                if abs.object!=parent||abs.present.is_some()||self.objects[parent].absent!=abs.key{return Err(Fault::Key)}
                (None,0,abs.key,0,0,[0;32])
            }else{
                let p=self.pass_index(parent_proof,true)?;
                if self.passes[p].object!=parent||!self.passes[p].roster{return Err(Fault::Key)}
                let entries=&self.passes[p].entries;
                let aliases:Vec<_>=entries.iter().filter(|e|e.name.eq_ignore_ascii_case(&edge.name)).collect();
                if aliases.len()>1||aliases.first().is_some_and(|e|e.name!=edge.name){return Err(Fault::Namespace)}
                let found=aliases.first().map(|e|(*e).clone());let digest=self.passes[p].digest;
                let epoch=self.objects[parent].epoch;
                let obs=self.observe_completed(parent,p,2,false,false)?;
                (found,parent_proof,0,obs,epoch,digest)
            };
        let p=Presence{key:self.keys.take(KeyKind::Presence,self.scope)?,object:i,parent,present,pass,parent_absent,
            parent_observation,epoch,roster,edge_key:self.graph.rows[row].key,name:edge.name};
        if p.present.is_none()&&!self.objects[i].attempted&&!self.objects[i].creation{
            self.objects[i].attempted=true;
            let canonical=self.current_name(i)?;
            // NoHandle is a proved original roster fact, not a failed-open->None.
            // A missing parent has no borrowable HANDLE; no OS call is attempted.
            let parent_slot=self.objects[parent].slot.filter(|s|self.io.state(*s)==Ok(SlotState::Owned));
            let slot=self.io.reserve(parent_slot,&p.name,canonical,self.graph.rows[row].role.directory())?;
            self.objects[i].slot=Some(slot);self.io.no_handle(slot)?;self.objects[i].absent=p.key;
        }
        let bytes=self.encode_presence(&p);let token=p.key;self.presences.push(p);
        Ok(Body::one(token,batch(vec![bytes])))
    }
    fn acquire(&mut self,key:u64,proof:u64)->Result<Body>{
        let i=self.current_object(key)?;if self.objects[i].attempted{return Err(Fault::OneUse)}
        let expected=self.proof(proof,i)?.present.clone().ok_or(Fault::Namespace)?;
        let row=self.objects[i].row;let role=self.graph.rows[row].role;
        if !role.source()||role==Role::Root||expected.kind!=if role.directory(){FileKind::Directory}else{FileKind::File}{return Err(Fault::Namespace)}
        let edge=self.objects[i].edge.clone().ok_or(Fault::Namespace)?;let parent=self.active_object(edge.parent)?;
        let parent_slot=self.owned(parent)?;self.io.check_user()?;
        self.objects[i].attempted=true;
        let slot=self.io.reserve(Some(parent_slot),&edge.name,self.current_name(i)?,role.directory())?;self.objects[i].slot=Some(slot);
        let access=if role.directory(){if self.scope==3&&role!=Role::OptionalMeta{Access::WriteDirectory}else{Access::ReadDirectory}}
            else if self.scope==3&&role==Role::Selected{Access::OldTarget}else{Access::ReadFile};
        self.io.open(slot,access,false,None,None)?;
        let snapshot=self.snapshot(i)?;
        if snapshot.metadata.identity.file_id!=expected.file_id||snapshot.metadata.attributes!=expected.attributes{return Err(Fault::Stale)}
        if self.objects.iter().enumerate().any(|(other,o)|other!=i&&o.scope==self.scope&&o.current.as_ref().is_some_and(|s|
            s.metadata.identity==snapshot.metadata.identity)){return Err(Fault::Namespace)}
        self.objects[i].current=Some(snapshot);self.io.check_user()?;Ok(Body::unit(key))
    }
    fn begin_pass(&mut self,key:u64,roster:bool)->Result<Body>{
        let i=self.current_object(key)?;self.owned(i)?;
        if self.passes.iter().any(|p|!p.complete&&!p.failed){return Err(Fault::Incomplete)}
        let role=self.graph.rows[self.objects[i].row].role;if role.directory()!=roster{return Err(Fault::Key)}
        if self.objects[i].write_open{return Err(Fault::Phase)}
        let remaining=self.remaining()?;grow(&mut self.passes,1,remaining)?;
        let reservation=self.ticket_active.as_ref().and_then(|a|a.unit.pass).ok_or(Fault::Phase)?;
        let expected_roster=if roster{self.ticket_known_roster(i).map(<[DirectoryEntry]>::to_vec)}else{None};
        let entries=if roster{fixed_vec(reservation.entries as usize)?}else{Vec::new()};
        self.budget(HELPER+entries.capacity()*size_of::<DirectoryEntry>())?;
        self.io.pass()?;self.io.check_user()?;let before=self.snapshot(i)?;
        let byte_limit=if roster{0}else{before.metadata.size};
        if !roster&&byte_limit>self.graph.rows[self.objects[i].row].limit{return Err(Fault::Bounds)}
        if !roster&&byte_limit>reservation.bytes{return Err(Fault::Stale)}
        let entry_limit=if roster{expected_roster.as_ref().map_or(reservation.entries as usize,Vec::len)}else{0};
        if entry_limit>reservation.entries as usize{return Err(Fault::Capacity)}
        if entry_limit>128{return Err(Fault::Capacity)}
        // A positive short read is retained as real progress, never rounded up
        // or changed into EOF/IO error. This closed per-pass policy allows one
        // extra positive read beyond full-size chunks, plus the real EOF call.
        // Exhaustion is an explicit Capacity refusal and leaves the pass failed.
        let native_limit=reservation.native_calls;
        for p in self.passes.iter_mut().filter(|p|p.object==i){p.entries=Vec::new();p.expected_roster=None;}
        let key=self.keys.take(KeyKind::Pass,self.scope)?;self.objects[i].latest_pass=key;
        self.passes.push(Pass{key,object:i,epoch:self.objects[i].epoch,before,after:None,roster,entries,
            bytes:0,hash:Sha256::new(),digest:[0;32],complete:false,failed:false,first:true,
            byte_limit,entry_limit,native_calls:0,native_limit,dots:0,
            credit:None,expected_roster,observations:reservation.observations});self.budget(HELPER)?;
        Ok(Body::unit(key))
    }
    fn next_pass(&mut self,key:u64,roster:bool)->Result<Body>{
        let p=self.pass_index(key,false)?;let i=self.passes[p].object;if self.passes[p].roster!=roster{return Err(Fault::Key)}
        let slot=self.owned(i)?;self.budget(HELPER)?;self.passes[p].failed=true;
        if self.passes[p].native_calls>=self.passes[p].native_limit{return Err(Fault::Capacity)}
        self.passes[p].native_calls+=1;
        if roster {
            let restart=self.passes[p].first;self.passes[p].first=false;
            if let Some(entries)=self.io.roster(slot,restart)?{
                if entries.is_empty(){return Err(Fault::Capacity)}
                let mut accepted=Vec::new();
                for e in entries{
                    if e.name=="."||e.name==".."{
                        if e.kind!=FileKind::Directory{return Err(Fault::Namespace)}
                        if e.name=="."&&e.file_id!=self.passes[p].before.metadata.identity.file_id{return Err(Fault::Stale)}
                        let dot=if e.name=="."{1}else{2};
                        if self.passes[p].dots&dot!=0{return Err(Fault::Capacity)}
                        self.passes[p].dots|=dot;continue
                    }
                    if self.passes[p].entries.len()>=self.passes[p].entry_limit{return Err(Fault::Stale)}
                    if self.passes[p].expected_roster.as_ref().is_some_and(|known|!known.contains(&e)){return Err(Fault::Stale)}
                    if self.passes[p].entries.iter().any(|old|old.name.eq_ignore_ascii_case(&e.name)||old.file_id==e.file_id){return Err(Fault::Namespace)}
                    self.passes[p].entries.push(e.clone());accepted.push(e);
                }
                // A nonterminal native batch containing only dot entries does
                // not become EOF. Its complete zero-row framed batch is DATA.
                let n=accepted.len() as u32;let total=self.passes[p].entries.len() as u32;
                self.passes[p].failed=false;return Ok(Body{token:key,count:n,total,bytes:encode_roster(&accepted),status:Status::Ok})
            }
        }else{
            let limit=self.passes[p].byte_limit;
            let count=(limit.saturating_sub(self.passes[p].bytes)+1).min(65536) as usize;
            let bytes=self.io.read(slot,self.passes[p].bytes,count.max(1))?;
            if !bytes.is_empty(){
                self.passes[p].bytes=self.passes[p].bytes.checked_add(bytes.len() as u64).ok_or(Fault::Capacity)?;
                if self.passes[p].bytes>limit{return Err(Fault::Stale)}
                self.passes[p].hash.update(&bytes);self.passes[p].failed=false;
                return Ok(Body{token:key,count:bytes.len() as u32,total:self.passes[p].bytes as u32,bytes,status:Status::Ok})
            }
        }
        let after=self.snapshot(i)?;
        if !self.same(&self.passes[p].before,&after){return Err(Fault::Stale)}
        if !roster&&after.metadata.size!=self.passes[p].bytes{return Err(Fault::Stale)}
        self.io.check_user()?;
        if roster{
            self.passes[p].entries.sort_by(|a,b|a.name.as_bytes().cmp(b.name.as_bytes()));
            if let Some(expected)=&self.passes[p].expected_roster{let mut expected=expected.clone();expected.sort_by(|a,b|a.name.as_bytes().cmp(b.name.as_bytes()));if expected!=self.passes[p].entries{return Err(Fault::Stale)}}
            self.passes[p].digest=hash(&encode_roster(&self.passes[p].entries));
        }else{self.passes[p].digest=self.passes[p].hash.clone().finalize().into();}
        self.passes[p].after=Some(after);self.passes[p].complete=true;self.passes[p].failed=false;
        Ok(Body{token:key,count:0,total:if roster{self.passes[p].entries.len() as u32}else{self.passes[p].bytes as u32},
            bytes:Vec::new(),status:Status::Eof})
    }
    fn observe_completed(&mut self,i:usize,p:usize,tag:u32,material:bool,delivered:bool)->Result<u64>{
        self.reserve_observation()?;
        if self.passes[p].object!=i||!self.passes[p].complete||self.passes[p].failed{return Err(Fault::Key)}
        let snapshot=self.passes[p].after.clone().ok_or(Fault::Incomplete)?;
        let current=self.snapshot(i)?;if !self.same(&snapshot,&current){return Err(Fault::Stale)}
        let row=self.objects[i].row;let role=self.graph.rows[row].role;
        let key=self.keys.take(KeyKind::Observation,self.scope)?;
        let actual=&self.security[snapshot.security].data;
        let object=&self.objects[i];
        let published=self.graph.transitions.iter().any(|t|t.object==object.key&&t.purpose==1&&t.accepted);
        let restored=self.graph.transitions.iter().any(|t|t.object==object.key&&t.purpose==2&&t.accepted);
        let policy=if !object.creation{64}
            else if restored{
                if !object.private.as_ref().is_some_and(|p|p.same(actual)){return Err(Fault::Security)}16
            }else if published{
                if !object.target.as_ref().is_some_and(|p|p.same(actual)){return Err(Fault::Security)}32
            }else{
                if !actual.is_private(self.io.user()?)||!object.private.as_ref().is_some_and(|p|p.same(actual)){return Err(Fault::Security)}16
            };
        let flags=(if role.directory(){2}else{1})|policy|(if material{128}else{0})|(if tag==2{8}else{0});
        let (parent_object,parent_observation,parent_epoch,name)=if let Some(edge)=self.objects[i].edge.clone(){
            let parent=self.active_object(edge.parent)?;(self.objects[parent].key,self.objects[parent].last_emitted,self.objects[parent].epoch,edge.name)
        }else{(0,0,0,String::new())};
        let capture=self.objects[i].capture;
        let obs=Observation{key,object:i,scope:self.scope,tag,flags,snapshot:snapshot.clone(),
            epoch:self.objects[i].epoch,security_epoch:self.objects[i].security_epoch,effect:self.objects[i].effect,
            pass:self.passes[p].key,content:if role.directory(){[0;32]}else{self.passes[p].digest},
            roster:if role.directory(){self.passes[p].digest}else{[0;32]},capture,parent_object,parent_observation,parent_epoch,
            cause:self.objects[i].cause,name};
        self.objects[i].current=Some(snapshot);
        let _=delivered; // delivery is committed only after the complete batch is encoded.
        self.observations.push(obs);Ok(key)
    }
    fn observation_body(&mut self,key:u64)->Result<Body>{let o=self.observation(key)?;let i=o.object;let bytes=batch(vec![self.encode_observation(o)?]);if i!=usize::MAX{self.objects[i].last_emitted=key;}Ok(Body::one(key,bytes))}
    fn source(&mut self,r:Request,recheck:bool)->Result<Body>{
        let i=self.current_object(r.a)?;let p=self.pass_index(if recheck{r.c}else{r.b},true)?;
        if self.passes[p].object!=i{return Err(Fault::Key)}
        let created=self.objects[i].creation;
        if !recheck&&!created&&self.scope==1&&self.objects[i].capture!=0{return Err(Fault::OneUse)}
        if recheck{
            if created||self.scope==1{return Err(Fault::Phase)}
            let original=self.observation(r.b)?.clone();
            if original.scope!=1||original.tag!=1||original.capture!=original.key||original.flags&128==0||
                self.objects[original.object].row!=self.objects[i].row{return Err(Fault::Key)}
            let now=self.passes[p].after.as_ref().ok_or(Fault::Incomplete)?;
            if !self.same(&original.snapshot,now)||(if self.passes[p].roster{original.roster}else{original.content})!=self.passes[p].digest{return Err(Fault::Stale)}
            self.objects[i].capture=original.key;
        }else if !created&&self.scope!=1{return Err(Fault::Phase)}
        let key=self.observe_completed(i,p,1,!created,true)?;
        let at=self.observations.len()-1;
        if !created&&self.scope==1 {
            if self.objects[i].capture!=0{return Err(Fault::OneUse)}
            self.objects[i].capture=key;self.observations[at].capture=key;
        }
        if recheck{self.observations[at].flags|=4;}
        self.observation_body(key)
    }
    fn check_epoch(&mut self,r:Request)->Result<Body>{
        let i=self.current_object(r.a)?;let p=self.pass_index(r.c,true)?;
        if self.passes[p].object!=i{return Err(Fault::Key)}
        let explicit=self.objects[i].pending!=0&&r.b==self.objects[i].pending;
        if !explicit{
            let ack=self.observation(r.b)?;
            if self.objects[i].last_emitted!=r.b||ack.object!=i||ack.flags&128==0||!matches!(ack.tag,1|2){return Err(Fault::Stale)}
        }
        let now=self.passes[p].after.clone().ok_or(Fault::Incomplete)?;
        if let Some(prior)=&self.objects[i].current{
            if !self.stable(prior,&now,!self.objects[i].creation){return Err(Fault::Stale)}
            if self.objects[i].pending==0&&self.objects[i].cause==0&&!self.same(prior,&now){return Err(Fault::Stale)}
        }
        self.verify_material(i,p)?;
        let key=self.observe_completed(i,p,2,true,true)?;self.objects[i].pending=0;
        if self.observation(key)?.flags&16!=0{
            let object=self.objects[i].key;
            for t in self.graph.transitions.iter_mut().filter(|t|t.object==object&&t.purpose==1&&t.attempted&&!t.accepted){
                let effect=self.io.effects.iter().find(|e|e.operation==t.key);
                if effect.is_none_or(|e|e.flags&1==0||(e.flags&3==3&&e.return_kind==2&&e.bits==0)){t.no_effect=true;}
            }
        }
        self.observation_body(key)
    }
    fn verify_material(&self,i:usize,p:usize)->Result<()>{
        let o=&self.objects[i];let row=&self.graph.rows[o.row];
        if o.creation&&!row.role.directory(){
            let expected=if row.role==Role::NewNote{self.payload.ok_or(Fault::Phase)?}
                else if row.role.control(){let b=self.bindings.iter().find(|b|b.object==i&&b.complete).ok_or(Fault::Incomplete)?;(b.size,b.digest)}
                else{(0,hash(&[]))};
            if self.passes[p].bytes!=expected.0||self.passes[p].digest!=expected.1||!o.write_finished{return Err(Fault::Stale)}
        }else if !o.creation&&o.capture!=0{
            let baseline=self.observation(o.capture)?;
            if !row.role.directory()&&baseline.content!=self.passes[p].digest{return Err(Fault::Stale)}
        }
        Ok(())
    }
    fn encode_observation(&self,o:&Observation)->Result<Vec<u8>>{
        let (object,row)=if o.object==usize::MAX{(self.lease_key,0)}else{(self.objects[o.object].key,self.objects[o.object].row)};
        let sec=&self.security[o.snapshot.security];let m=&o.snapshot.metadata;let mut b=Vec::new();
        b.extend_from_slice(b"MRKNOB1\0");u32s(&mut b,&[320,o.tag]);u64s(&mut b,&[self.owner]);u32s(&mut b,&[o.scope,o.flags]);
        u64s(&mut b,&[object,o.key,self.graph.rows[row].key,o.epoch,o.security_epoch,sec.key,self.graph.rows[row].stable_security,o.effect,o.pass,m.identity.volume_serial]);
        b.extend_from_slice(&m.identity.file_id);u32s(&mut b,&[if m.kind==FileKind::File{1}else{2},m.attributes]);
        u64s(&mut b,&[m.size,m.allocation_size]);u32s(&mut b,&[m.links,0]);u64s(&mut b,&[m.creation as u64,m.write as u64,m.change as u64]);
        // Lease tag3 is a non-material identity observation. Its native policy
        // remains held privately; the wire's four digest fields are all zero.
        if o.tag==3{b.extend_from_slice(&[0u8;128]);}
        else{b.extend_from_slice(&sec.data.canonical_hash);b.extend_from_slice(&sec.data.raw_hash);b.extend_from_slice(&o.content);b.extend_from_slice(&o.roster);}
        u64s(&mut b,&[o.capture]);
        if o.tag==2{u64s(&mut b,&[o.parent_object,o.parent_observation,o.parent_epoch,o.cause]);u32s(&mut b,&[o.name.len() as u32,0]);b.extend_from_slice(o.name.as_bytes());}
        Ok(b)
    }
    fn encode_presence(&self,p:&Presence)->Vec<u8>{
        let mut b=Vec::new();b.extend_from_slice(b"MRKNPF1\0");u32s(&mut b,&[160,if p.present.is_some(){1}else{2}]);
        u64s(&mut b,&[self.owner]);u32s(&mut b,&[self.scope,if p.parent_absent==0{1}else{2}]);
        u64s(&mut b,&[p.key,self.objects[p.object].key,self.objects[p.parent].key,p.parent_observation,p.epoch,p.pass,p.edge_key]);
        b.extend_from_slice(&p.roster);b.extend_from_slice(&p.present.as_ref().map_or([0;16],|e|e.file_id));
        u32s(&mut b,&[p.present.as_ref().map_or(0,|e|if e.kind==FileKind::File{1}else{2}),p.present.as_ref().map_or(0,|e|e.attributes),p.name.len() as u32,0]);
        u64s(&mut b,&[p.parent_absent]);b.extend_from_slice(p.name.as_bytes());b
    }

    fn freeze_apply(&mut self,r:Request,input:&[u8])->Result<Body>{
        if self.scope!=3||self.current_object(r.a)?!=self.mapping[0].0||!self.graph.selected||self.graph.apply{return Err(Fault::Phase)}
        for row in 0..self.graph.rows.len(){
            let i=self.mapping[row].0;let capture=*self.capture_objects.get(row).ok_or(Fault::Key)?;
            if self.objects[i].absent!=0{
                if self.objects[capture].absent==0{return Err(Fault::Stale)}
            }else{
                let o=self.observation(self.objects[i].last_emitted)?;
                if o.flags&128==0||o.capture==0||o.capture!=self.objects[capture].capture{return Err(Fault::Stale)}
            }
        }
        let selected=self.graph.selected_row.ok_or(Fault::Phase)?;let target=self.mapping[selected].0;
        let absent=self.objects[target].absent!=0;
        if absent{
            if r.b!=self.objects[target].absent||r.number==2{return Err(Fault::Stale)}
        }else{
            let o=self.source_anchor(r.b,selected,3,false)?;
            if o.object!=target||r.b!=self.objects[target].last_emitted||r.number==1{return Err(Fault::Stale)}
        }
        let payload=if r.number==0{None}else{Some(wire::size_digest(input,self.graph.rows[selected].limit)?)};
        let missing:Vec<_>=self.graph.rows.iter().enumerate().filter(|(row,l)|l.role==Role::Parent&&l.ancestor!=NONE&&self.objects[self.mapping[*row].0].absent!=0).map(|(i,_)|i).collect();
        let existing_policy=if !absent{
            let observation=self.observation(r.b)?;let policy=Arc::clone(&self.security[observation.snapshot.security].data);
            if r.number!=0{policy.ordinary_settable(self.io.user()?,&self.group)?;}Some(policy)
        }else{None};
        self.graph.add_apply_rows(&mut self.keys,r.number,missing,!absent&&r.number!=0)?;
        self.payload=payload;self.extend_mapping()?;
        if r.number!=0{
            let journal=self.graph.journal.ok_or(Fault::Phase)?;
            for row in self.graph.missing.clone(){
                let edge=Edge{parent:journal,name:format!("directory-{}",self.graph.rows[row].ancestor)};
                let i=self.add_object(row,true,Some(edge))?;self.mapping[row].1=Some(i);
            }
            let new=self.active_object(self.graph.new_note.ok_or(Fault::Phase)?)?;
            self.objects[new].target=existing_policy;
            let objects:Vec<_>=(0..self.graph.rows.len()).map(|row|self.active_object(row).map(|i|self.objects[i].key)).collect::<Result<_>>()?;
            let policy=if !absent{r.b}else{objects[self.graph.rows[selected].parent.ok_or(Fault::Phase)?]};
            self.graph.freeze_effects(&mut self.keys,&objects,policy)?;
        }
        let mut exits=Vec::new();self.ticket_ensure_exits(&mut exits)?;
        if !exits.is_empty(){self.ticket_admit(exits)?;}
        self.budget(HELPER)?;self.factory(18)
    }
    fn bind(&mut self,r:Request,input:&[u8],op:Op)->Result<Body>{
        let i=self.current_object(r.a)?;let role=self.graph.rows[self.objects[i].row].role;
        if self.scope!=3||!self.graph.apply||!role.control(){return Err(Fault::Phase)}
        if op==Op::BindControlBegin{
            if self.bindings.iter().any(|b|b.object==i){return Err(Fault::OneUse)}
            let (size,digest)=wire::size_digest(input,524288)?;let mut bytes=Vec::new();
            let remaining=self.remaining()?;grow(&mut self.bindings,1,remaining)?;
            self.budget(size as usize+HELPER)?;bytes.try_reserve_exact(size as usize).map_err(|_|Fault::Capacity)?;
            self.budget(bytes.capacity()+HELPER)?;
            let key=self.keys.take(KeyKind::Control,3)?;self.bindings.push(Binding{key,object:i,size,digest,bytes,complete:false});
            return Ok(Body::unit(key))
        }
        let b=self.bindings.iter_mut().find(|b|b.object==i).ok_or(Fault::Key)?;
        if b.complete{return Err(Fault::OneUse)}
        if op==Op::BindControlChunk{
            if r.number as usize!=b.bytes.len()||b.bytes.len().checked_add(input.len()).is_none_or(|n|n>b.size as usize){return Err(Fault::Bounds)}
            b.bytes.extend_from_slice(input);Ok(Body::unit(b.key))
        }else{
            if b.bytes.len()!=b.size as usize||hash(&b.bytes)!=b.digest{return Err(Fault::Stale)}
            b.complete=true;let key=b.key;
            if self.bindings.len()==4&&self.bindings.iter().all(|b|b.complete)&&self.ticket_prelude.is_none(){
                // All four immutable control sizes and selected payload are now
                // known. This is BEFORE workflow eligibility and before the last
                // control's creation, not a claim that preparation has completed.
                self.ticket_derive_targets()?;
                self.ticket_install_prelude(key)?;
            }
            Ok(Body::unit(key))
        }
    }
    fn effect(&self,kind:u32,i:usize,operation:u64,epoch:u64)->Effect{
        Effect{kind,object:self.objects[i].key,operation,epoch,..Effect::default()}
    }
    fn last_effect(&self,start:usize)->Result<Effect>{
        self.io.effects.get(start).copied().filter(|e|e.flags&1!=0).ok_or(Fault::Incomplete)
    }
    fn primary_success(e:Effect)->bool{
        e.flags&3==3&&match e.return_kind{1=>e.bits==0,2=>e.bits!=0,3=>e.bits==0,_=>false}
    }
    fn effect_body(&self,token:u64,e:Effect,status:Status)->Body{
        Body{token,count:1,total:1,bytes:e.encode(self.owner).to_vec(),status}
    }
    fn pending_parent(&mut self,parent:usize,cause:u64,effect:u64,expected:Vec<DirectoryEntry>){
        self.objects[parent].epoch=self.epoch;self.objects[parent].cause=cause;self.objects[parent].effect=effect;
        self.objects[parent].expected_roster=Some(expected);
        // Internal POST association never replaces last_emitted full anchor.
    }
    fn roster_for(&self,key:u64,parent:usize)->Result<Vec<DirectoryEntry>>{
        let p=self.pass_index(key,true)?;if self.passes[p].object!=parent||!self.passes[p].roster{return Err(Fault::Key)}
        Ok(self.passes[p].entries.clone())
    }
    fn make_entry(&self,i:usize,name:&str)->Result<DirectoryEntry>{
        let s=self.objects[i].current.as_ref().ok_or(Fault::Incomplete)?;
        Ok(DirectoryEntry{name:name.to_owned(),file_id:s.metadata.identity.file_id,kind:s.metadata.kind,attributes:s.metadata.attributes})
    }
    fn create(&mut self,r:Request)->Result<Body>{
        let i=self.current_object(r.a)?;let row=self.objects[i].row;let role=self.graph.rows[row].role;
        if !self.graph.apply||!self.objects[i].creation||self.objects[i].attempted{return Err(Fault::Phase)}
        let p=self.proof(r.b,i)?.clone();if p.present.is_some()||p.parent_absent!=0{return Err(Fault::Namespace)}
        let parent=p.parent;let mut expected=self.roster_for(p.pass,parent)?;
        let edge=self.objects[i].edge.clone().ok_or(Fault::Namespace)?;
        if role.control()&&!self.bindings.iter().any(|b|b.object==i&&b.complete){return Err(Fault::Incomplete)}
        let private=Arc::clone(self.private.as_ref().ok_or(Fault::Phase)?);
        self.io.check_user()?;let parent_before=self.snapshot(parent)?;
        let proof_obs=self.observation(p.parent_observation)?;
        if !self.same(&proof_obs.snapshot,&parent_before){return Err(Fault::Stale)}
        expected.try_reserve_exact(1).map_err(|_|Fault::Capacity)?;
        self.ticket_install_create(i,parent)?;
        self.objects[i].attempted=true;let pending=self.keys.take(KeyKind::Pending,3)?;
        let epoch=self.epoch.checked_add(1).ok_or(Fault::Capacity)?;
        let slot=self.io.reserve(Some(self.owned(parent)?),&edge.name,self.current_name(i)?,role.directory())?;self.objects[i].slot=Some(slot);
        let start=self.io.effects.len();let effect=self.effect(1,i,r.a,epoch);
        let returned=self.io.open(slot,if role.directory(){Access::PrivateDirectory}else{Access::PrivateFile},true,Some(Arc::clone(&private)),Some(effect));
        let actual=self.last_effect(start)?;
        if Self::primary_success(actual){
            self.epoch=epoch;self.objects[i].epoch=epoch;self.objects[i].effect=actual.sequence;self.objects[i].cause=r.a;
            self.objects[i].pending=pending;self.objects[i].private=Some(private);
            self.objects[i].write_open=role.control()||role==Role::NewNote;
            self.objects[i].write_finished=!self.objects[i].write_open;
            if role.directory(){self.objects[i].expected_roster=Some(Vec::new());}
        }
        returned?;
        let after=self.snapshot(i)?;
        if !self.security[after.security].data.is_private(self.io.user()?)||(!role.directory()&&after.metadata.size!=0){return Err(Fault::Security)}
        self.objects[i].private=Some(Arc::clone(&self.security[after.security].data));
        self.objects[i].current=Some(after);
        expected.push(self.make_entry(i,&edge.name)?);self.pending_parent(parent,r.a,actual.sequence,expected);
        let parent_after=self.snapshot(parent)?;
        if !self.stable(&parent_before,&parent_after,false){return Err(Fault::Stale)}
        self.objects[parent].current=Some(parent_after);self.io.check_user()?;
        Ok(self.effect_body(pending,actual,Status::Ok))
    }
    fn write(&mut self,r:Request,input:&[u8])->Result<Body>{
        let i=self.current_object(r.a)?;let row=self.objects[i].row;let role=self.graph.rows[row].role;
        if !self.objects[i].creation||!self.objects[i].write_open||self.objects[i].write_finished{return Err(Fault::Phase)}
        let (size,digest)=if role==Role::NewNote{self.payload.ok_or(Fault::Phase)?}
            else{let b=self.bindings.iter().find(|b|b.object==i&&b.complete).ok_or(Fault::Phase)?;(b.size,b.digest)};
        let _=digest;let offset=self.objects[i].written;
        if offset.checked_add(input.len() as u64).is_none_or(|end|end>size){return Err(Fault::Bounds)}
        if role.control(){
            let b=self.bindings.iter().find(|b|b.object==i).ok_or(Fault::Key)?;
            if b.bytes.get(offset as usize..offset as usize+input.len())!=Some(input){return Err(Fault::Stale)}
        }
        self.io.check_user()?;let before=self.snapshot(i)?;
        if self.objects[i].current.as_ref().is_none_or(|old|!self.same(old,&before)){return Err(Fault::Stale)}
        let epoch=self.epoch.checked_add(1).ok_or(Fault::Capacity)?;let start=self.io.effects.len();
        let effect=self.effect(2,i,r.a,epoch);let n=self.io.write(self.owned(i)?,offset,input,effect)?;
        // A known positive partial write is real progress, never a synthetic
        // full-chunk receipt. C continues only the remaining suffix.
        self.objects[i].written=offset.checked_add(n as u64).ok_or(Fault::Capacity)?;
        self.epoch=epoch;self.objects[i].epoch=epoch;self.objects[i].pending=0;self.objects[i].cause=r.a;self.objects[i].last_emitted=0;
        let actual=self.last_effect(start)?;self.objects[i].effect=actual.sequence;
        let after=self.snapshot(i)?;
        if !self.stable(&before,&after,false)||after.metadata.size!=self.objects[i].written{return Err(Fault::Stale)}
        self.objects[i].current=Some(after);Ok(self.effect_body(r.a,actual,Status::Ok))
    }
    fn finish_write(&mut self,key:u64)->Result<Body>{
        let i=self.current_object(key)?;if !self.objects[i].write_open||self.objects[i].write_finished{return Err(Fault::OneUse)}
        let row=self.objects[i].row;let expected=if self.graph.rows[row].role==Role::NewNote{self.payload.ok_or(Fault::Phase)?.0}
            else{self.bindings.iter().find(|b|b.object==i&&b.complete).ok_or(Fault::Incomplete)?.size};
        if self.objects[i].written!=expected{return Err(Fault::Incomplete)}
        self.io.check_user()?;let before=self.snapshot(i)?;self.io.fence(self.owned(i)?,None)?;
        let after=self.snapshot(i)?;if !self.same(&before,&after){return Err(Fault::Stale)}
        let pending=self.keys.take(KeyKind::Pending,3)?;self.objects[i].write_open=false;self.objects[i].write_finished=true;
        self.objects[i].pending=pending;self.objects[i].current=Some(after);Ok(Body::unit(pending))
    }
    fn fence_snapshot(&mut self,i:usize,expected:&Snapshot)->Result<()>{
        let before=self.snapshot(i)?;if !self.same(expected,&before){return Err(Fault::Stale)}
        self.io.fence(self.owned(i)?,None)?;let after=self.snapshot(i)?;
        if !self.same(expected,&after){return Err(Fault::Stale)}Ok(())
    }
    fn fence(&mut self,key:u64)->Result<Body>{
        let i=self.current_object(key)?;if self.scope!=3||self.objects[i].write_open{return Err(Fault::Phase)}
        self.io.check_user()?;let before=self.snapshot(i)?;let start=self.io.effects.len();
        self.io.fence(self.owned(i)?,Some(self.effect(3,i,key,self.epoch)))?;
        let after=self.snapshot(i)?;if !self.same(&before,&after){return Err(Fault::Stale)}
        Ok(self.effect_body(key,self.last_effect(start)?,Status::Ok))
    }
    fn move_index(&self,key:u64)->Result<usize>{self.graph.moves.iter().position(|m|m.key==key).ok_or(Fault::Key)}
    fn movement_allowed(&self,m:&namespace::Movement)->Result<()>{
        if self.scope!=3||self.graph.action==0||m.attempted{return Err(Fault::OneUse)}
        if self.compensation_joined{return Err(Fault::Phase)}
        if m.flags&8!=0&&!self.compensation{return Err(Fault::Phase)}
        if m.flags&16!=0&&self.corrective!=Some((m.forward,m.key)){return Err(Fault::Phase)}
        if self.compensation&&!matches!(m.kind,8|10|12|14|16|6|7){return Err(Fault::Phase)}
        if self.committed_cleanup&&!matches!(m.kind,6){return Err(Fault::Phase)}
        if m.forward!=0{
            let forward=self.graph.moves.iter().find(|f|f.key==m.forward).ok_or(Fault::Key)?;
            let exact_corrective=self.corrective==Some((forward.key,m.key));
            if !forward.returned||(!forward.finalized&&!exact_corrective)||forward.flags&6!=0{return Err(Fault::Phase)}
        }
        if m.private_transition!=0{
            let t=self.graph.transitions.iter().find(|t|t.key==m.private_transition).ok_or(Fault::Key)?;
            // If publication never occurred, the object's verified original
            // private policy itself supplies the same closed inverse condition.
            let published=self.graph.transitions.iter().find(|t2|t2.key==t.paired).is_some_and(|t2|t2.accepted);
            if published&&!t.finalized{return Err(Fault::Incomplete)}
        }
        Ok(())
    }
    fn movement(&mut self,r:Request)->Result<Body>{
        let mi=self.move_index(r.a)?;let m=self.graph.moves[mi].clone();self.movement_allowed(&m)?;
        let i=self.current_object(m.object)?;
        if self.objects[i].edge.as_ref()!=Some(&m.from)||self.objects[i].pending!=0||self.objects[i].last_emitted==0{return Err(Fault::Stale)}
        let ack=self.observation(self.objects[i].last_emitted)?;
        if ack.flags&128==0{return Err(Fault::Incomplete)}
        if self.corrective.is_some()||m.private_transition!=0{
            if ack.tag!=2||ack.epoch!=self.objects[i].epoch||ack.security_epoch!=self.objects[i].security_epoch||
                ack.pass!=self.objects[i].latest_pass{return Err(Fault::Stale)}
        }
        if m.private_transition!=0&&ack.flags&16==0{return Err(Fault::Security)}
        let original_ack=ack.key;
        let destination=self.active_object(m.to.parent)?;let old_parent=self.active_object(m.from.parent)?;
        let mut new_entries=self.roster_for(r.b,destination)?;
        let old_pass=self.objects[old_parent].latest_pass;let mut old_entries=self.roster_for(old_pass,old_parent)?;
        if m.publish_transition!=0{
            if self.ticket_prelude.is_none(){return Err(Fault::Incomplete)}
            self.ticket_validate_inherited_parent(i,destination)?;
        }
        let before=self.snapshot(i)?;
        if !self.same(&self.observation(original_ack)?.snapshot,&before){return Err(Fault::Stale)}
        if m.private_transition!=0&&!self.objects[i].private.as_ref().is_some_and(|p|p.same(&self.security[before.security].data)){return Err(Fault::Security)}
        let identity=before.metadata.identity.file_id;
        let from_matches:Vec<_>=old_entries.iter().filter(|e|e.name==m.from.name&&e.file_id==identity).collect();
        if from_matches.len()!=1{return Err(Fault::Stale)}
        let collision=m.flags&1!=0;
        if collision{
            let target=self.graph.rows.iter().position(|l|l.role==Role::ProbeB).ok_or(Fault::Phase)?;
            let target=self.active_object(target)?;let target_id=self.objects[target].current.as_ref().ok_or(Fault::Incomplete)?.metadata.identity.file_id;
            if !new_entries.iter().any(|e|e.name==m.to.name&&e.file_id==target_id){return Err(Fault::Stale)}
        }else if new_entries.iter().any(|e|e.name.eq_ignore_ascii_case(&m.to.name)){return Err(Fault::Namespace)}
        if matches!(m.kind,15|16){self.terminal_preflight(m.kind)?;}
        self.io.check_user()?;let epoch=self.epoch.checked_add(1).ok_or(Fault::Capacity)?;
        let next=m.to.clone();let moved=self.moving_subtree(i)?;
        let entry=self.make_entry(i,&m.to.name)?;
        old_entries.try_reserve_exact(1).map_err(|_|Fault::Capacity)?;
        new_entries.try_reserve_exact(1).map_err(|_|Fault::Capacity)?;
        self.ticket_install_move(mi)?;
        let start=self.io.effects.len();self.graph.moves[mi].attempted=true;
        self.graph.moves[mi].before_observation=original_ack;
        let actual_collision=self.io.movement(self.owned(i)?,self.owned(destination)?,&m.to.name,self.effect(4,i,r.a,if collision{self.epoch}else{epoch}))?;
        let mut actual=self.last_effect(start)?;
        if actual_collision{
            if !collision{return Err(Fault::NativeUnavailable)}
            actual.flags|=8;self.io.effects[start]=actual;self.graph.moves[mi].candidate=true;
            self.graph.moves[mi].returned=true;self.graph.moves[mi].effect=actual.sequence;
            return Ok(self.effect_body(r.a,actual,Status::ExpectedCollision))
        }
        // No allocation or fallible query separates this known native success
        // from its closed graph association. Every active descendant moves with
        // the directory/journal; old full delivered anchors remain retained but
        // no old pass/presence can certify the newly named subtree.
        self.objects[i].edge=Some(next);self.epoch=epoch;
        for (object,affected) in self.objects.iter_mut().zip(moved){
            if affected{object.epoch=epoch;object.cause=r.a;object.effect=actual.sequence;object.latest_pass=0;}
        }
        self.graph.moves[mi].returned=true;self.graph.moves[mi].effect=actual.sequence;
        old_entries.retain(|e|!(e.name==m.from.name&&e.file_id==identity));
        if old_parent==destination{old_entries.push(entry);self.pending_parent(old_parent,r.a,actual.sequence,old_entries);}
        else{new_entries.push(entry);self.pending_parent(old_parent,r.a,actual.sequence,old_entries);self.pending_parent(destination,r.a,actual.sequence,new_entries);}
        // Unexpected probe success is still this real move and epoch/delta.
        if collision{return Err(Fault::Namespace)}
        Ok(self.effect_body(r.a,actual,Status::Ok))
    }
    fn moving_subtree(&self,root:usize)->Result<[bool;154]>{
        let mut affected=[false;154];
        for (i,object) in self.objects.iter().enumerate(){
            if object.scope!=self.scope||self.active_object(object.row)?!=i{continue}
            let mut at=i;
            for depth in 0..39{
                if at==root{affected[i]=true;break}
                let Some(edge)=self.objects[at].edge.as_ref()else{break};
                at=self.active_object(edge.parent)?;
                if depth==38{return Err(Fault::Namespace)}
            }
            if affected[i]&&(self.passes.iter().any(|p|p.object==i&&!p.complete&&!p.failed)||
                self.graph.deletes.iter().any(|d|d.object==object.key&&d.accepted&&!d.closed)){return Err(Fault::Incomplete)}
        }
        if !affected[root]{return Err(Fault::Namespace)}Ok(affected)
    }
    fn terminal_preflight(&self,kind:u32)->Result<()>{
        if self.committed!=0||self.rolled_back!=0{return Err(Fault::OneUse)}
        if kind==15{
            if self.compensation||self.first_failure.is_some(){return Err(Fault::Phase)}
            for m in &self.graph.moves{
                if matches!(m.kind,9|13)&&(!m.finalized||m.publish_transition==0||!self.graph.transitions.iter().any(|t|t.key==m.publish_transition&&t.finalized)){return Err(Fault::Incomplete)}
            }
            if self.graph.backup&&!self.graph.moves.iter().any(|m|m.kind==11&&m.finalized){return Err(Fault::Incomplete)}
        }else{
            if !self.compensation{return Err(Fault::Phase)}
            for m in &self.graph.moves{
                if matches!(m.kind,9|11|13)&&m.returned&&!self.graph.moves.iter().any(|inv|inv.key==m.inverse&&inv.finalized){return Err(Fault::Incomplete)}
            }
        }Ok(())
    }
    fn finish_move(&mut self,r:Request,input:&[u8])->Result<Body>{
        let mi=self.move_index(r.a)?;let m=self.graph.moves[mi].clone();
        if !m.returned||m.finalized{return Err(Fault::Phase)}
        let i=self.current_object(m.object)?;let old_parent=self.active_object(m.from.parent)?;let new_parent=self.active_object(m.to.parent)?;
        if old_parent==new_parent&&r.b!=r.c{return Err(Fault::Key)}
        let old=self.pass_index(r.b,true)?;let new=self.pass_index(r.c,true)?;let mut c=Cursor::new(input);let own=self.pass_index(c.u64()?,true)?;c.finish()?;
        if self.passes[old].object!=old_parent||self.passes[new].object!=new_parent||self.passes[own].object!=i||
            !self.passes[old].roster||!self.passes[new].roster{return Err(Fault::Key)}
        let before=self.observation(m.before_observation)?.clone();let after=self.passes[own].after.clone().ok_or(Fault::Incomplete)?;
        if !self.stable(&before.snapshot,&after,true)||(if self.passes[own].roster{before.roster}else{before.content})!=self.passes[own].digest{return Err(Fault::Stale)}
        let id=after.metadata.identity.file_id;
        if m.candidate{
            if !self.same(&before.snapshot,&after)||!self.passes[old].entries.iter().any(|e|e.name==m.from.name&&e.file_id==id){return Err(Fault::Stale)}
            let probe=self.graph.rows.iter().position(|r|r.role==Role::ProbeB).ok_or(Fault::Phase)?;
            let probe=self.active_object(probe)?;
            self.prove_probe_peer(probe)?;
            let id_b=self.objects[probe].current.as_ref().ok_or(Fault::Incomplete)?.metadata.identity.file_id;
            if !self.passes[new].entries.iter().any(|e|e.name==m.to.name&&e.file_id==id_b){return Err(Fault::Stale)}
        }else{
            if self.passes[old].entries.iter().any(|e|e.name.eq_ignore_ascii_case(&m.from.name))||
                !self.passes[new].entries.iter().any(|e|e.name==m.to.name&&e.file_id==id){return Err(Fault::Stale)}
        }
        self.verify_material(i,own)?;self.io.check_user()?;
        for (object,pass) in [(i,own),(old_parent,old)]{
            let expected=self.passes[pass].after.clone().ok_or(Fault::Incomplete)?;self.fence_snapshot(object,&expected)?;
        }
        if new_parent!=old_parent{
            let expected=self.passes[new].after.clone().ok_or(Fault::Incomplete)?;self.fence_snapshot(new_parent,&expected)?;
        }
        self.io.check_user()?;
        let mut keys=Vec::new();
        keys.push(self.observe_completed(old_parent,old,2,true,false)?);
        if new_parent!=old_parent{keys.push(self.observe_completed(new_parent,new,2,true,false)?);}
        let object_key=self.observe_completed(i,own,2,true,false)?;keys.insert(0,object_key);
        let parent_obs=keys.iter().find(|key|self.observation(**key).is_ok_and(|o|o.object==new_parent)).copied().ok_or(Fault::Incomplete)?;
        let object_obs=self.observations.iter_mut().find(|o|o.key==object_key).ok_or(Fault::Key)?;object_obs.parent_observation=parent_obs;
        let rows=keys.iter().map(|k|self.encode_observation(self.observation(*k)?)).collect::<Result<Vec<_>>>()?;
        self.graph.moves[mi].finalized=true;
        if self.corrective==Some((m.forward,m.key)){
            let forward=self.move_index(m.forward)?;
            // Completion of the exact inverse settles that original effect;
            // it does not invent a successful forward27 receipt.
            self.graph.moves[forward].corrected=true;
        }
        if m.candidate{
            if let Some(e)=self.io.effects.iter_mut().find(|e|e.sequence==m.effect){e.flags|=4;}
        }
        // Verified original marker fact latches irreversibly BEFORE callback and
        // before later cleanup. Neither receipt nor cleanup failure can erase it.
        if m.kind==15{self.committed=m.key;}else if m.kind==16{self.rolled_back=m.key;}
        for key in &keys{let object=self.observation(*key)?.object;self.objects[object].last_emitted=*key;self.objects[object].pending=0;}
        Ok(Body{token:r.a,count:keys.len() as u32,total:keys.len() as u32,bytes:batch(rows),status:Status::Ok})
    }
    fn prove_probe_peer(&mut self,i:usize)->Result<()>{
        // The collision probes are private DIRECTORIES. A cached ProbeB ID is
        // insufficient: this SAME held original supplies its own complete empty
        // roster, exact policy/identity proof and fence, with no path reopen,
        // fourth Epoch record, or replacement of C's accepted anchor/pass.
        if self.graph.rows[self.objects[i].row].role!=Role::ProbeB||
            !self.objects[i].creation||!self.objects[i].write_finished{return Err(Fault::Phase)}
        let saved=self.objects[i].current.clone().ok_or(Fault::Incomplete)?;
        self.io.pass()?;self.io.check_user()?;
        let before=self.snapshot(i)?;
        if !self.same(&saved,&before)||before.metadata.kind!=FileKind::Directory||
            !self.objects[i].private.as_ref().is_some_and(|d|d.same(&self.security[before.security].data))||
            !self.security[before.security].data.is_private(self.io.user()?){return Err(Fault::Stale)}
        let mut dots=0u8;let mut eof=false;
        for n in 0..3{
            let Some(entries)=self.io.roster(self.owned(i)?,n==0)?else{eof=true;break};
            if entries.is_empty(){return Err(Fault::Capacity)}
            for e in entries{
                let dot=if e.name=="."{1}else if e.name==".."{2}else{return Err(Fault::Namespace)};
                if e.kind!=FileKind::Directory||dots&dot!=0{return Err(Fault::Capacity)}
                if dot==1&&e.file_id!=before.metadata.identity.file_id{return Err(Fault::Stale)}
                dots|=dot;
            }
        }
        if !eof{return Err(Fault::Capacity)}
        let after=self.snapshot(i)?;
        if !self.same(&before,&after){return Err(Fault::Stale)}
        self.io.fence(self.owned(i)?,None)?;let fenced=self.snapshot(i)?;
        if !self.same(&after,&fenced){return Err(Fault::Stale)}
        self.io.check_user()?;self.objects[i].current=Some(fenced);Ok(())
    }
    fn transition(&mut self,key:u64,restore:bool)->Result<Body>{
        let ti=self.graph.transitions.iter().position(|t|t.key==key).ok_or(Fault::Key)?;let t=self.graph.transitions[ti].clone();
        if t.attempted||t.purpose!=if restore{2}else{1}||restore&&!self.compensation{return Err(Fault::Phase)}
        let i=self.current_object(t.object)?;let row=self.objects[i].row;
        if !self.objects[i].creation||!matches!(self.graph.rows[row].role,Role::Parent|Role::NewNote){return Err(Fault::Key)}
        let movement=self.graph.moves.iter().find(|m|m.key==t.movement).ok_or(Fault::Key)?.clone();
        let forward=if restore{self.graph.moves.iter().find(|m|m.key==movement.forward).ok_or(Fault::Key)?}else{&movement};
        if !forward.finalized||self.objects[i].edge.as_ref()!=Some(&forward.to){return Err(Fault::Incomplete)}
        if restore&&!self.graph.transitions.iter().any(|p|p.key==t.paired&&p.accepted){return Err(Fault::Phase)}
        let before=self.snapshot(i)?;
        let policy=if restore{Arc::clone(self.objects[i].private.as_ref().ok_or(Fault::Phase)?)}else{
            let parent=self.active_object(forward.to.parent)?;
            self.ticket_validate_inherited_parent(i,parent)?;
            Arc::clone(self.objects[i].target.as_ref().ok_or(Fault::Phase)?)
        };
        self.io.check_user()?;let epoch=self.epoch.checked_add(1).ok_or(Fault::Capacity)?;let start=self.io.effects.len();
        self.graph.transitions[ti].attempted=true;
        self.io.set_security(self.owned(i)?,policy,self.effect(if restore{6}else{5},i,key,epoch))?;
        let actual=self.last_effect(start)?;self.epoch=epoch;self.objects[i].epoch=epoch;self.objects[i].security_epoch+=1;
        self.objects[i].cause=key;self.objects[i].effect=actual.sequence;self.graph.transitions[ti].accepted=true;self.graph.transitions[ti].effect=actual.sequence;
        // Full policy/material/edge/fence proof is separate operation30.
        let _=before;Ok(self.effect_body(key,actual,Status::Ok))
    }
    fn finish_transition(&mut self,r:Request)->Result<Body>{
        let ti=self.graph.transitions.iter().position(|t|t.key==r.a).ok_or(Fault::Key)?;let t=self.graph.transitions[ti].clone();
        if !t.accepted||t.finalized||t.purpose!=r.number{return Err(Fault::Phase)}
        let i=self.current_object(t.object)?;let own=self.pass_index(r.b,true)?;let parent_pass=self.pass_index(r.c,true)?;
        let edge=self.objects[i].edge.clone().ok_or(Fault::Phase)?;let parent=self.active_object(edge.parent)?;
        if self.passes[own].object!=i||self.passes[parent_pass].object!=parent||!self.passes[parent_pass].roster{return Err(Fault::Key)}
        let now=self.passes[own].after.clone().ok_or(Fault::Incomplete)?;
        let policy=if r.number==1{self.objects[i].target.as_ref()}else{self.objects[i].private.as_ref()}.ok_or(Fault::Phase)?;
        if !policy.same(&self.security[now.security].data){return Err(Fault::Security)}
        if self.objects[i].current.as_ref().is_some_and(|old|old.metadata.identity!=now.metadata.identity||old.metadata.kind!=now.metadata.kind||
            old.metadata.size!=now.metadata.size||old.metadata.attributes!=now.metadata.attributes||old.metadata.creation!=now.metadata.creation||old.metadata.links!=now.metadata.links){return Err(Fault::Stale)}
        self.verify_material(i,own)?;
        if !self.passes[parent_pass].entries.iter().any(|e|e.name==edge.name&&e.file_id==now.metadata.identity.file_id){return Err(Fault::Stale)}
        self.fence_snapshot(i,&now)?;let parent_now=self.passes[parent_pass].after.clone().ok_or(Fault::Incomplete)?;self.fence_snapshot(parent,&parent_now)?;
        self.io.check_user()?;
        let parent_key=self.observe_completed(parent,parent_pass,2,true,false)?;let key=self.observe_completed(i,own,2,true,false)?;
        self.observations.iter_mut().find(|o|o.key==key).ok_or(Fault::Key)?.parent_observation=parent_key;
        let rows=vec![self.encode_observation(self.observation(key)?)?,self.encode_observation(self.observation(parent_key)?)?];
        self.graph.transitions[ti].finalized=true;
        if t.purpose==2{
            let paired=self.graph.transitions.iter().position(|p|p.key==t.paired&&p.paired==t.key&&
                p.object==t.object&&p.purpose==1&&p.accepted).ok_or(Fault::Key)?;
            // Only the actual complete paired restore30 settles that earlier
            // published effect. Its missing forward30 receipt stays missing.
            self.graph.transitions[paired].corrected=true;
        }
        self.objects[i].last_emitted=key;self.objects[parent].last_emitted=parent_key;
        Ok(Body{token:r.a,count:2,total:2,bytes:batch(rows),status:Status::Ok})
    }

    fn ticket_binding(&self,purpose:TicketPurpose,cause:u64,i:usize,from:usize,to:usize)->TicketBinding{
        TicketBinding{scope:self.scope,purpose,cause,object:self.objects[i].key,
            from:self.objects[from].key,to:self.objects[to].key}
    }
    fn ticket_failure_step(error:u32)->Result<u32>{
        // Wire error numbers are not step selectors. Keep these four independent
        // finality claims inside the closed selector range, without ABI changes.
        match error{13=>Ok(1),14=>Ok(2),18=>Ok(3),19=>Ok(4),_=>Err(Fault::Wire)}
    }
    fn ticket_selector(operation:Op,original:u64,step:u32)->TicketSelector{
        TicketSelector{operation:operation as u32,original,step}
    }
    fn ticket_stage(&self,op:Op,i:Option<usize>)->u32{
        if self.compensation||self.committed_cleanup{return 14}
        if self.scope<3{return match self.scope{0=>1,1=>2,_=>3}}
        if !self.graph.apply{return 4}
        if matches!(op,Op::FreezeApply|Op::BindControlBegin|Op::BindControlChunk|Op::BindControlFinish){return 5}
        match i.map(|i|self.graph.rows[self.objects[i].row].role){
            Some(Role::ProbeA|Role::ProbeB)=>7,Some(Role::Parent)=>8,
            Some(Role::Selected)=>9,Some(Role::NewNote)=>10,
            Some(Role::Commit|Role::Rollback)=>11,_=>6,
        }
    }
    fn ticket_policy_bytes(&self,i:usize)->Result<usize>{
        let object=self.objects.get(i).ok_or(Fault::Key)?;
        let mut n=object.current.as_ref().map_or(0,|s|self.security[s.security].data.raw.len());
        for d in [object.private.as_ref(),object.target.as_ref(),self.private.as_ref()].into_iter().flatten(){
            n=n.max(d.raw.len());
        }
        if n==0{return Err(Fault::Incomplete)}
        // This is based on an ACTUAL already-admitted descriptor, not a policy
        // byte cutoff. A later larger foreign result can fail Capacity, while
        // its independent original release remains precharged before entry.
        n.checked_mul(9).and_then(|n|n.checked_add(4096)).ok_or(Fault::Capacity)
    }
    fn ticket_known_roster(&self,i:usize)->Option<&[DirectoryEntry]>{
        self.objects[i].expected_roster.as_deref().or_else(||self.passes.iter().rev()
            .find(|p|p.object==i&&p.roster&&p.complete&&!p.failed).map(|p|p.entries.as_slice()))
    }
    fn ticket_names(&self,i:usize,future:bool)->Result<(u32,usize)>{
        let empty=&[][..];
        let entries=match self.ticket_known_roster(i){Some(entries)=>entries,
            None if self.objects[i].creation&&!self.objects[i].attempted=>empty,
            None=>return Ok((128,131072)),};
        let row=self.objects[i].row;
        let mut names:Vec<&str>=entries.iter().map(|e|e.name.as_str()).collect();
        if future{
            for object in self.objects.iter().filter(|o|o.scope==self.scope&&o.creation){
                if let Some(edge)=&object.edge{if edge.parent==row&&!names.contains(&edge.name.as_str()){names.push(&edge.name);}}
            }
            for movement in &self.graph.moves{
                for edge in [&movement.from,&movement.to]{
                    if edge.parent==row&&!names.contains(&edge.name.as_str()){names.push(&edge.name);}
                }
            }
        }
        if names.len()>128{return Err(Fault::Capacity)}
        let bytes=names.iter().try_fold(0usize,|n,s|n.checked_add(s.len()).ok_or(Fault::Capacity))?;
        Ok((names.len() as u32,bytes))
    }
    fn ticket_snapshot_heap(&self,i:usize,n:usize)->Result<usize>{
        self.ticket_policy_bytes(i)?.checked_add(size_of::<SecurityRecord>())
            .and_then(|v|v.checked_mul(n)).ok_or(Fault::Capacity)
    }
    fn ticket_pass_cost(&self,i:usize,observations:u32,future:bool)->Result<(PassBound,Credit)>{
        let object=&self.objects[i];let row=&self.graph.rows[object.row];
        let (bound,names)=if row.role.directory(){
            let (entries,names)=self.ticket_names(i,future)?;
            (PassBound::roster(entries,observations)?,names)
        }else{
            let bytes=if object.creation{
                if row.role==Role::NewNote{self.payload.ok_or(Fault::Incomplete)?.0}
                else{self.bindings.iter().find(|b|b.object==i&&b.complete).ok_or(Fault::Incomplete)?.size}
            }else{object.current.as_ref().ok_or(Fault::Incomplete)?.metadata.size};
            if bytes>row.limit{return Err(Fault::Bounds)}
            (PassBound::file(bytes,observations)?,0)
        };
        let snapshots=2+observations as usize;
        let roster=if row.role.directory(){2*bound.entries as usize*size_of::<DirectoryEntry>()+2*names}else{0};
        let heap=size_of::<Pass>().checked_add(roster)
            .and_then(|n|n.checked_add(self.ticket_snapshot_heap(i,snapshots).ok()?))
            .and_then(|n|n.checked_add(observations as usize*(size_of::<Observation>()+255)))
            .ok_or(Fault::Capacity)?;
        // begin33 + final snapshot/check33 + every entered native read/roster
        // including actual EOF, plus each explicit material observation13.
        Ok((bound,Credit{passes:1,frames:66+u64::from(bound.native_calls)+13*u64::from(observations),
            checks:2,records:4,calls:1+u64::from(bound.native_calls)+u64::from(observations),
            bytes:if row.role.directory(){0}else{bound.bytes+1},
            entries:if row.role.directory(){u64::from(bound.entries)+2}else{0},
            heap:heap as u64,..Credit::ZERO}))
    }
    fn ticket_add_pass(&self,plan:&mut TicketPlan,i:usize,step:u32,count:u32,observations:u32,future:bool)->Result<()>{
        let (bound,cost)=self.ticket_pass_cost(i,observations,future)?;
        let op=if self.graph.rows[self.objects[i].row].role.directory(){Op::BeginRoster}else{Op::BeginRead};
        plan.push(Self::ticket_selector(op,self.objects[i].key,step),count,cost,Some(bound))
    }
    fn ticket_operation_cost(&self,i:usize,frames:u64,checks:u64,snapshots:usize,observations:usize)->Result<Credit>{
        let heap=self.ticket_snapshot_heap(i,snapshots)?
            .checked_add(observations*(size_of::<Observation>()+255))
            .and_then(|n|n.checked_add(4096)).ok_or(Fault::Capacity)?;
        Ok(Credit{frames,checks,records:2*checks,calls:1,heap:heap as u64,..Credit::ZERO})
    }
    fn ticket_add_counts(&self,plan:&mut TicketPlan,counts:&ReadCounts,step:u32)->Result<()>{
        if counts.lease!=0{
            let root=self.mapping[0].0;
            let cost=self.ticket_operation_cost(root,35,1,1,1)?;
            plan.push(Self::ticket_selector(Op::CheckLease,self.lease_key,step),counts.lease,cost,None)?;
        }
        for (i,count) in counts.refresh.iter().enumerate().filter(|(_,n)|**n!=0){
            self.ticket_add_pass(plan,i,step,*count,1,true)?;
        }Ok(())
    }
    fn ticket_at_logical_edge(&self,row:usize,moved:Option<(usize,&Edge)>)->Result<Option<usize>>{
        let logical=self.graph.rows.get(row).ok_or(Fault::Key)?;
        let i=self.active_object(row)?;
        if self.objects[i].slot.is_none_or(|s|self.io.state(s)!=Ok(SlotState::Owned)){return Ok(None)}
        if row==0{return Ok(Some(i))}
        let edge=if moved.is_some_and(|(j,_)|j==i){moved.map(|(_,e)|e)}else{self.objects[i].edge.as_ref()};
        let Some(edge)=edge else{return Ok(None)};
        if logical.parent!=Some(edge.parent)||logical.name!=edge.name{return Ok(None)}
        Ok(Some(i))
    }
    fn ticket_visible(&self,row:usize,moved:Option<(usize,&Edge)>)->Result<Option<usize>>{
        let Some(i)=self.ticket_at_logical_edge(row,moved)?else{return Ok(None)};
        if row!=0{
            let parent=self.graph.rows[row].parent.ok_or(Fault::Phase)?;
            if self.ticket_visible(parent,moved)?.is_none(){return Ok(None)}
        }
        Ok(Some(i))
    }
    fn ticket_path_counts(&self,row:usize,moved:Option<(usize,&Edge)>,out:&mut ReadCounts)->Result<()>{
        let mut ancestors=Vec::new();let mut parent=self.graph.rows[row].parent;
        while let Some(p)=parent{
            if p!=0{ancestors.push(p);}parent=self.graph.rows[p].parent;
            if ancestors.len()>38{return Err(Fault::Namespace)}
        }
        let mut current=Some(self.mapping[0].0);
        for row in ancestors.into_iter().rev(){
            if let Some(i)=current{
                out.refresh(i)?;current=self.ticket_visible(row,moved)?;
                if let Some(child)=current{out.refresh(child)?;}
            }
        }
        if let Some(parent)=current{
            out.refresh(parent)?;
            if let Some(child)=self.ticket_visible(row,moved)?{out.refresh(child)?;}
        }Ok(())
    }
    fn ticket_dependency_rows(&self)->Vec<usize>{
        self.graph.rows.iter().enumerate().filter(|(_,r)|
            matches!(r.role,Role::Config|Role::Ignore|Role::Version|Role::Counterpart)).map(|(i,_)|i).collect()
    }
    fn ticket_dependency_parents(&self)->Result<Vec<usize>>{
        let mut rows=Vec::new();
        // C freezes release even when it is not another dependency's ancestor.
        let release=self.graph.rows.iter().position(|r|r.role==Role::Parent&&r.path=="release").ok_or(Fault::Phase)?;
        rows.push(release);
        for row in self.ticket_dependency_rows(){
            let mut at=self.graph.rows[row].parent;
            while let Some(p)=at{
                if p!=0&&!rows.contains(&p){rows.push(p);}
                at=self.graph.rows[p].parent;
            }
        }
        rows.sort_by(|a,b|self.graph.rows[*a].path.cmp(&self.graph.rows[*b].path));Ok(rows)
    }
    fn ticket_broad_post(&self,mi:usize)->Result<ReadCounts>{
        let movement=&self.graph.moves[mi];let i=self.current_object(movement.object)?;
        let moved=if movement.flags&1!=0{None}else{Some((i,&movement.to))};
        let mut out=ReadCounts::default();out.lease()?;out.refresh(self.mapping[0].0)?;
        if let Some(meta)=self.graph.rows.iter().position(|r|r.role==Role::OptionalMeta){
            if let Some(meta)=self.ticket_visible(meta,moved)?{out.refresh(meta)?;}
        }
        for row in self.ticket_dependency_rows(){self.ticket_path_counts(row,moved,&mut out)?;}
        for row in self.ticket_dependency_parents()?{
            let source=self.mapping[row].0;
            if self.objects[source].absent==0{out.refresh(source)?;}
            else if let Some(i)=self.ticket_at_logical_edge(row,moved)?{
                if !self.objects[i].creation{return Err(Fault::Phase)}
                // C selects this exact held/public-edge replacement before its
                // dictionary/material checks. Invalid ancestry/expectations can
                // fail; they never switch this branch into Current(path).
                out.refresh(i)?;
            }else{self.ticket_path_counts(row,moved,&mut out)?;}
        }
        let changing=if matches!(movement.kind,9|10){Some(self.graph.rows[movement.row].path.as_str())}else{None};
        for (row,l) in self.graph.rows.iter().enumerate().filter(|(_,l)|l.role==Role::Parent){
            if changing.is_some_and(|p|l.path==p||l.path.strip_prefix(p).is_some_and(|tail|tail.starts_with('/'))){continue}
            self.ticket_path_counts(row,moved,&mut out)?;
        }
        Ok(out)
    }

    fn ticket_possible(&self,row:usize)->Result<Option<usize>>{
        let i=self.active_object(row)?;
        if self.objects[i].creation||self.objects[i].slot.is_some_and(|s|self.io.state(s)==Ok(SlotState::Owned)){
            Ok(Some(i))
        }else{Ok(None)}
    }
    fn ticket_possible_path(&self,row:usize,out:&mut ReadCounts)->Result<()>{
        let mut ancestors=Vec::new();let mut parent=self.graph.rows[row].parent;
        while let Some(p)=parent{
            if p!=0{ancestors.push(p);}parent=self.graph.rows[p].parent;
            if ancestors.len()>38{return Err(Fault::Namespace)}
        }
        let mut current=Some(self.mapping[0].0);
        for row in ancestors.into_iter().rev(){
            if let Some(i)=current{
                out.refresh(i)?;current=self.ticket_possible(row)?;
                if let Some(child)=current{out.refresh(child)?;}
            }
        }
        if let Some(parent)=current{
            out.refresh(parent)?;
            if let Some(child)=self.ticket_possible(row)?{out.refresh(child)?;}
        }Ok(())
    }
    fn ticket_broad_bound(&self,changing:Option<usize>)->Result<ReadCounts>{
        let mut out=ReadCounts::default();out.lease()?;out.refresh(self.mapping[0].0)?;
        if let Some(meta)=self.graph.rows.iter().position(|r|r.role==Role::OptionalMeta){
            if let Some(meta)=self.ticket_possible(meta)?{out.refresh(meta)?;}
        }
        for row in self.ticket_dependency_rows(){self.ticket_possible_path(row,&mut out)?;}
        for row in self.ticket_dependency_parents()?{
            let source=self.mapping[row].0;
            if self.objects[source].absent==0{out.refresh(source)?;}
            else{
                // These are finite alternative branches, not a forecast that
                // both execute. Their immutable credits cannot fund another
                // object or cause if the other branch is selected.
                if let Some(i)=self.ticket_possible(row)?{out.refresh(i)?;}
                self.ticket_possible_path(row,&mut out)?;
            }
        }
        let changing=changing.map(|r|self.graph.rows[r].path.as_str());
        for (row,l) in self.graph.rows.iter().enumerate().filter(|(_,l)|l.role==Role::Parent){
            if changing.is_some_and(|p|l.path==p||l.path.strip_prefix(p).is_some_and(|tail|tail.starts_with('/'))){continue}
            self.ticket_possible_path(row,&mut out)?;
        }Ok(out)
    }

    fn ticket_create_plan(&self,i:usize,parent:usize)->Result<TicketPlan>{
        let binding=self.ticket_binding(TicketPurpose::Create,self.objects[i].key,i,parent,parent);
        let stage=self.ticket_stage(Op::CreatePrivate,Some(i));
        let mut plan=TicketPlan::new(binding,stage)?;
        let mut cost=self.ticket_operation_cost(i,82,2,3,0)?;
        cost.acquisitions=1;cost.records+=1;cost.calls=0; // current bridge entry already charged
        let (_,names)=self.ticket_names(parent,true)?;
        cost.heap=cost.heap.checked_add((256*size_of::<DirectoryEntry>()+2*names) as u64).ok_or(Fault::Capacity)?;
        plan.push(Self::ticket_selector(Op::CreatePrivate,self.objects[i].key,TICKET_CORE),1,cost,None)?;
        let role=self.graph.rows[self.objects[i].row].role;
        if !role.directory(){
            let size=if role==Role::NewNote{self.payload.ok_or(Fault::Incomplete)?.0}
                else{self.bindings.iter().find(|b|b.object==i&&b.complete).ok_or(Fault::Incomplete)?.size};
            // Positive short writes are exact real progress. This original cap
            // permits one extra positive write beyond full-size chunks; another
            // call fails Capacity before entry, with cleanup/finality untouched.
            let writes=u32::try_from((size+65535)/65536+1).map_err(|_|Fault::Capacity)?;
            let cost=self.ticket_operation_cost(i,47,1,2,0)?;
            plan.push(Self::ticket_selector(Op::WriteChunk,self.objects[i].key,TICKET_CORE),writes,cost,None)?;
            plan.push(Self::ticket_selector(Op::FinishWrite,self.objects[i].key,TICKET_CORE),1,cost,None)?;
        }
        plan.push(Self::ticket_selector(Op::FullFence,self.objects[i].key,TICKET_CORE),1,
            self.ticket_operation_cost(i,47,1,2,0)?,None)?;
        self.ticket_add_pass(&mut plan,i,TICKET_RAW,1,2,false)?;Ok(plan)
    }
    fn ticket_delete_plan(&self,di:usize,recovery:bool,current_call:bool)->Result<TicketPlan>{
        let d=&self.graph.deletes[di];let i=self.current_object(d.object)?;
        // Every permitted deletion edge names the SAME retained private parent
        // original (journal or root), even when the journal itself was renamed.
        let parent=self.active_object(d.edges.first().ok_or(Fault::Key)?.parent)?;
        if d.edges.iter().any(|e|self.active_object(e.parent)!=Ok(parent)){return Err(Fault::Namespace)}
        let binding=self.ticket_binding(TicketPurpose::Delete,d.key,i,parent,parent);
        let mut plan=TicketPlan::new(binding,if recovery{14}else{self.ticket_stage(Op::Delete,Some(i))})?;
        let mut primary=self.ticket_operation_cost(i,34,1,1,0)?;
        let (_,names)=self.ticket_names(parent,true)?;
        primary.heap=primary.heap.checked_add((256*size_of::<DirectoryEntry>()+2*names) as u64).ok_or(Fault::Capacity)?;
        if current_call{primary.calls=0;}
        plan.push(Self::ticket_selector(Op::Delete,d.key,TICKET_CORE),1,primary,None)?;
        // The SDK close frame is the original acquisition's prepaid cell. This
        // claim reserves only the distinct ABI continuation, never a new close.
        plan.push(Self::ticket_selector(Op::CloseDeleted,d.key,TICKET_CORE),1,
            Credit{calls:1,..Credit::ZERO},None)?;
        self.ticket_add_pass(&mut plan,parent,TICKET_DELETE_PARENT,1,0,true)?;
        let mut finish=self.ticket_operation_cost(parent,60,1,3,1)?;
        finish.heap=finish.heap.checked_add((size_of::<Presence>()+255) as u64).ok_or(Fault::Capacity)?;
        plan.push(Self::ticket_selector(Op::FinishDelete,d.key,TICKET_CORE),1,finish,None)?;
        if recovery{
            plan.push(Self::ticket_selector(Op::FullFence,self.objects[parent].key,TICKET_CORE),1,
                self.ticket_operation_cost(parent,47,1,2,0)?,None)?;
        }Ok(plan)
    }
    fn ticket_move_plan(&self,mi:usize,recovery:bool,current_call:bool)->Result<TicketPlan>{
        let m=&self.graph.moves[mi];let i=self.current_object(m.object)?;
        let from=self.active_object(m.from.parent)?;let to=self.active_object(m.to.parent)?;
        let binding=self.ticket_binding(if m.forward==0{TicketPurpose::Move}else{TicketPurpose::Inverse},m.key,i,from,to);
        let mut plan=TicketPlan::new(binding,if recovery{13}else{self.ticket_stage(Op::Move,Some(i))})?;
        let mut primary=self.ticket_operation_cost(i,34,1,1,0)?;
        let (_,a)=self.ticket_names(from,true)?;let (_,b)=self.ticket_names(to,true)?;
        primary.heap=primary.heap.checked_add((512*size_of::<DirectoryEntry>()+2*a+2*b+1024) as u64).ok_or(Fault::Capacity)?;
        if current_call{primary.calls=0;}
        plan.push(Self::ticket_selector(Op::Move,m.key,TICKET_CORE),1,primary,None)?;
        for object in [i,from,to].into_iter().enumerate().filter_map(|(n,o)|
            if n==2&&o==from{None}else{Some(o)}){
            self.ticket_add_pass(&mut plan,object,TICKET_RAW,1,0,true)?;
        }
        let mut finish=Credit{frames:if from==to{120}else{160},checks:2,records:4,calls:1,..Credit::ZERO};
        for object in [i,from,to].into_iter().enumerate().filter_map(|(n,o)|
            if n==2&&o==from{None}else{Some(o)}){
            finish.heap=finish.heap.checked_add((self.ticket_snapshot_heap(object,3)?+size_of::<Observation>()+255) as u64).ok_or(Fault::Capacity)?;
        }
        if m.flags&1!=0{
            let peer_row=self.graph.rows.iter().position(|r|r.role==Role::ProbeB).ok_or(Fault::Phase)?;
            let peer=self.active_object(peer_row)?;
            finish=finish.add(Credit{passes:1,frames:83,checks:2,records:4,entries:2,
                heap:self.ticket_snapshot_heap(peer,3)? as u64,..Credit::ZERO})?;
        }
        plan.push(Self::ticket_selector(Op::FinishMove,m.key,TICKET_CORE),1,finish,None)?;
        let transition=if m.publish_transition!=0{Some((m.publish_transition,false,to))}
            else if m.private_transition!=0{Some((m.private_transition,true,from))}else{None};
        if let Some((key,restore,parent))=transition{
            let mut effect=self.ticket_operation_cost(i,50,1,1,0)?;
            effect.heap=effect.heap.checked_add(self.ticket_snapshot_heap(parent,1)? as u64).ok_or(Fault::Capacity)?;
            plan.push(Self::ticket_selector(if restore{Op::RestoreSecurity}else{Op::PublishSecurity},key,TICKET_CORE),1,effect,None)?;
            self.ticket_add_pass(&mut plan,i,TICKET_SECURITY_RAW,1,0,true)?;
            self.ticket_add_pass(&mut plan,parent,TICKET_SECURITY_RAW,1,0,true)?;
            let cost=Credit{frames:100,checks:1,records:2,calls:1,
                heap:(self.ticket_snapshot_heap(i,3)?+self.ticket_snapshot_heap(parent,3)?+
                    2*(size_of::<Observation>()+255)) as u64,..Credit::ZERO};
            plan.push(Self::ticket_selector(Op::FinishSecurity,key,TICKET_CORE),1,cost,None)?;
        }
        if m.forward!=0{
            plan.push(Self::ticket_selector(Op::BeginCompensation,m.forward,2),1,
                Credit{calls:1,..Credit::ZERO},None)?;
            // Narrow corrective lead-in is an immutable alternative to Fixed's
            // independently reserved scope Prelude. No broad sweep is performed
            // by C's narrow helper; its unused broad POST is later forfeited.
            self.ticket_add_pass(&mut plan,i,TICKET_CORRECTIVE_LEAD,1,1,true)?;
            if to!=i{self.ticket_add_pass(&mut plan,to,TICKET_CORRECTIVE_LEAD,1,1,true)?;}
        }
        if m.kind!=3{
            let counts=self.ticket_broad_bound(if matches!(m.kind,9|10){Some(m.row)}else{None})?;
            self.ticket_add_counts(&mut plan,&counts,TICKET_BROAD_POST)?;
        }
        Ok(plan)
    }

    fn ticket_bootstrap(&mut self)->Result<()>{
        let base=self.heap_bytes()?.checked_add(HELPER).ok_or(Fault::Capacity)?;
        self.ticket_ledger.reserve(&[(1,Credit{calls:1,heap:base as u64,..Credit::ZERO})])?;
        let binding=TicketBinding{scope:0,purpose:TicketPurpose::Finality,cause:self.lease_key,
            object:self.lease_key,from:0,to:0};
        let mut plan=TicketPlan::new(binding,16)?;
        let call=Credit{calls:1,..Credit::ZERO};
        plan.push(Self::ticket_selector(Op::Retire,self.lease_key,0),1,call,None)?;
        for scope in 1..=3{
            plan.push(Self::ticket_selector(Op::SettleScope,self.lease_key,scope),1,call,None)?;
            plan.push(Self::ticket_selector(Op::ScopeStatus,self.lease_key,scope),12,call,None)?;
        }
        for error in [13,14,18,19]{
            plan.push(Self::ticket_selector(Op::RecordFailure,self.lease_key,Self::ticket_failure_step(error)?),16,call,None)?;
        }
        plan.push(Self::ticket_selector(Op::ContextStatus,self.lease_key,0),16,call,None)?;
        // Explicit bounded retained-DATA diagnostic policy, not a predicted C
        // call graph. These calls cannot consume any close/settle/failure claim.
        plan.push(Self::ticket_selector(Op::DataPage,self.lease_key,0),512,call,None)?;
        self.ticket_finality=self.ticket_admit(vec![plan])?[0];Ok(())
    }
    fn ticket_admit(&mut self,plans:Vec<TicketPlan>)->Result<Vec<usize>>{
        self.ticket_flush_dynamic_heap()?;
        let indices=self.ticket_book.admit(&mut self.ticket_ledger,plans)?;
        self.io.book.notes_frames=self.ticket_ledger.native_frames()?;
        let current=self.heap_bytes()?;
        if let Some(a)=self.ticket_active.as_mut(){
            if a.dynamic_heap{a.heap_before=current;}
        }
        Ok(indices)
    }
    fn ticket_flush_dynamic_heap(&mut self)->Result<()>{
        let Some(a)=self.ticket_active.as_ref()else{return Ok(())};
        if !a.dynamic_heap{return Ok(())}
        let before=a.heap_before;let stage=a.unit.stage;let after=self.heap_bytes()?;
        let growth=after.saturating_sub(before);
        if growth!=0{self.ticket_ledger.reserve(&[(stage,Credit{heap:growth as u64,..Credit::ZERO})])?;}
        if let Some(a)=self.ticket_active.as_mut(){a.heap_before=after;}
        Ok(())
    }
    fn ticket_allowance(&self)->Result<usize>{
        let physical=HEAP.checked_sub(self.heap_bytes()?).and_then(|n|n.checked_sub(HELPER)).ok_or(Fault::Capacity)?;
        let reserved=usize::try_from(self.ticket_ledger.total()?.heap).map_err(|_|Fault::Capacity)?;
        let credit=if let Some(a)=self.ticket_active.as_ref(){
            let growth=self.heap_bytes()?.saturating_sub(a.heap_before);
            let capacity=if a.dynamic_heap{HEAP.checked_sub(reserved).ok_or(Fault::Capacity)?}
                else{usize::try_from(a.unit.credit.heap).map_err(|_|Fault::Capacity)?};
            capacity.checked_sub(growth).ok_or(Fault::Capacity)?
        }else{HEAP.checked_sub(reserved).ok_or(Fault::Capacity)?};
        Ok(credit.min(physical))
    }
    fn ticket_take(&mut self,ticket:usize,selector:TicketSelector)->Result<TicketUnit>{
        let binding=self.ticket_book.binding(ticket)?;
        self.ticket_book.take(ticket,binding,selector)
    }
    fn ticket_activate(&mut self,mut unit:TicketUnit,home:TicketHome,op:Op,dynamic_heap:bool,bridge_call:bool)->Result<usize>{
        if self.ticket_active.is_some(){return Err(Fault::Busy)}
        if bridge_call{unit.credit.take(Credit{calls:1,..Credit::ZERO})?;}
        let lane=reservations::pool(unit.stage)?;
        let before=self.heap_bytes()?;
        self.io.begin_credit(unit.credit,if lane==1{Pool::Recovery}else{Pool::Producer})?;
        self.ticket_active=Some(TicketActive{unit,home,heap_before:before,dynamic_heap,operation:op});Ok(lane)
    }
    fn ticket_close_active(&mut self)->Result<TicketActive>{
        // Even an accounting refusal after a DEFINITELY returned dispatch must
        // end its credit activation; otherwise it would falsely strand the
        // independent original close route as Busy. No credits are put back.
        let heap_result=self.ticket_flush_dynamic_heap();
        let remaining=self.io.end_credit();
        let mut active=self.ticket_active.take().ok_or(Fault::Phase)?;
        active.unit.credit=remaining?;
        heap_result?;
        if !active.dynamic_heap{
            let growth=self.heap_bytes()?.saturating_sub(active.heap_before);
            // A lost frame stays in the separately preowned helper allocation.
            let growth=if self.io.frames_active(){growth.saturating_sub(HELPER)}else{growth};
            active.unit.credit.take(Credit{heap:growth as u64,..Credit::ZERO})?;
        }
        Ok(active)
    }
    fn ticket_finish_call(&mut self,op:Op,result:&Result<Body>)->Result<()>{
        let active=self.ticket_close_active()?;
        if active.operation!=op{return Err(Fault::Phase)}
        let binding=active.unit.binding;let selector=active.unit.selector;
        let mut pass=None;
        match active.home{
            TicketHome::NewPass=>{
                if let Ok(body)=result{
                    pass=self.passes.iter().position(|p|p.key==body.token);
                    if pass.is_none(){return Err(Fault::NativeState)}
                }
            },
            TicketHome::Pass(i)=>pass=Some(i),
            TicketHome::Discard=>{},
        }
        if let Some(i)=pass{
            if result.is_ok()&&matches!(op,Op::SourceObservation|Op::RecheckSource|Op::CheckEpoch){
                self.passes[i].observations=self.passes[i].observations.checked_sub(1).ok_or(Fault::Phase)?;
            }
            if result.is_ok()&&(!self.passes[i].complete||self.passes[i].observations!=0){
                self.passes[i].credit=Some(active.unit);
            }else{
                self.passes[i].credit=None;
                if result.is_err(){self.passes[i].failed=true;}
            }
        }
        if result.is_ok(){self.ticket_after_call(op,binding,selector,pass)?;}
        else{self.ticket_forfeit_flow()?;}
        Ok(())
    }
    fn ticket_switch_effect(&mut self,ticket:usize,op:Op,key:u64)->Result<()>{
        let selected=self.ticket_book.binding(ticket)?;
        if self.ticket_active.as_ref().is_some_and(|a|a.unit.binding==selected){return Ok(())}
        // The current ABI entry's read-only PRE work was charged independently.
        // Retire its remaining allowance, then claim this original whole group
        // immediately BEFORE the primary effect. No SDK lies between the atomic
        // group admission and this switch.
        let _=self.ticket_close_active()?;
        let unit=self.ticket_take(ticket,Self::ticket_selector(op,key,TICKET_CORE))?;
        self.ticket_activate(unit,TicketHome::Discard,op,false,false)?;Ok(())
    }
    fn ticket_original_close(&mut self,i:usize)->Result<()>{
        let key=self.objects[i].key;
        let binding=TicketBinding{scope:self.objects[i].scope,purpose:TicketPurpose::Finality,cause:key,
            object:key,from:self.lease_key,to:self.lease_key};
        let mut plan=TicketPlan::new(binding,16)?;
        plan.push(Self::ticket_selector(Op::CloseOriginal,key,0),1,Credit{calls:1,..Credit::ZERO},None)?;
        self.ticket_admit(vec![plan])?;Ok(())
    }
    fn ticket_factory_pages(&mut self,factory:u64,keys:&[(u64,usize)])->Result<()>{
        if self.ticket_factory.len().checked_add(keys.len()).is_none_or(|n|n>64){return Err(Fault::Capacity)}
        let binding=TicketBinding{scope:self.scope,purpose:TicketPurpose::Factory,cause:factory,
            object:self.lease_key,from:self.lease_key,to:self.lease_key};
        let mut plan=TicketPlan::new(binding,self.ticket_stage(Op::DataPage,None))?;
        for (key,size) in keys{
            let pages=(*size+wire::PAGE_PAYLOAD_MAX-1)/wire::PAGE_PAYLOAD_MAX;
            plan.push(Self::ticket_selector(Op::DataPage,*key,0),pages.max(1) as u32,Credit{calls:1,..Credit::ZERO},None)?;
        }
        let index=self.ticket_admit(vec![plan])?[0];
        for (key,_) in keys{self.ticket_factory.push((*key,index));}Ok(())
    }
    fn ticket_presence_acquisition(&self,i:usize,proof:u64)->Result<bool>{
        let o=&self.objects[i];
        if o.creation||o.attempted{return Ok(false)}
        let parent=self.active_object(o.edge.as_ref().ok_or(Fault::Phase)?.parent)?;
        let absent=if let Some(p)=self.presences.iter().find(|p|p.key==proof){
            if p.object!=parent||p.present.is_some()||self.objects[parent].absent!=p.key{return Err(Fault::Key)}
            true
        }else{
            let p=self.pass_index(proof,true)?;
            if self.passes[p].object!=parent||!self.passes[p].roster{return Err(Fault::Key)}
            let name=&o.edge.as_ref().ok_or(Fault::Phase)?.name;
            let aliases:Vec<_>=self.passes[p].entries.iter().filter(|e|e.name.eq_ignore_ascii_case(name)).collect();
            if aliases.len()>1||aliases.first().is_some_and(|e|e.name!=*name){return Err(Fault::Namespace)}
            aliases.is_empty()
        };
        Ok(absent)
    }
    fn ticket_ordinary(&mut self,op:Op,r:Request)->Result<TicketUnit>{
        if self.stop||self.deadline||self.compensation||self.committed_cleanup{return Err(Fault::Phase)}
        let object=match op{
            Op::AcquireDeclared|Op::Presence|Op::BeginRead|Op::BeginRoster|Op::BindControlBegin|
            Op::BindControlChunk|Op::BindControlFinish|Op::CreatePrivate|Op::FullFence=>Some(self.current_object(r.a)?),
            Op::Move=>Some(self.current_object(self.graph.moves[self.move_index(r.a)?].object)?),
            Op::Delete=>Some(self.current_object(self.graph.deletes[self.delete_index(r.a)?].object)?),
            _=>None,
        };
        let stage=self.ticket_stage(op,object);
        let cause=self.keys.take(KeyKind::Data,self.scope)?;
        let binding=TicketBinding{scope:self.scope,purpose:TicketPurpose::Ordinary,cause,
            object:object.map_or(self.lease_key,|i|self.objects[i].key),from:self.lease_key,to:self.lease_key};
        let mut plan=TicketPlan::new(binding,stage)?;
        let mut pass=None;
        let cost=match op{
            Op::AcquireLease=>{
                let k=self.components.len() as u64+1;
                Credit{frames:62+16*k,checks:2,acquisitions:k,records:5+k,calls:1,..Credit::ZERO}
            },
            Op::CheckLease=>Credit{frames:35,checks:1,records:2,calls:1,..Credit::ZERO},
            Op::EnterScope=>Credit{frames:51,checks:1,records:3,acquisitions:1,calls:1,..Credit::ZERO},
            Op::AcquireDeclared=>Credit{frames:56,checks:2,records:5,acquisitions:1,calls:1,..Credit::ZERO},
            Op::Presence=>{
                // Only a new proved-absent source creates an original NoHandle
                // slot. Present/creation/repeated proofs must not reserve a
                // fictitious extra acquisition in the finite154-original total.
                let acquisition=u64::from(self.ticket_presence_acquisition(object.ok_or(Fault::Key)?,r.b)?);
                Credit{frames:13+acquisition,acquisitions:acquisition,records:acquisition,calls:1,..Credit::ZERO}
            },
            Op::BeginRead|Op::BeginRoster=>{
                let (bound,cost)=self.ticket_pass_cost(object.ok_or(Fault::Key)?,1,false)?;pass=Some(bound);cost
            },
            Op::CreatePrivate=>Credit{frames:33,checks:1,records:2,calls:1,..Credit::ZERO},
            // Newly derived inheritance is PRE work, never an unreserved
            // allocation after rename. SDK size/release are included in3.
            Op::Move=>Credit{frames:49,checks:1,records:2,calls:1,..Credit::ZERO},
            Op::Delete=>Credit{frames:33,checks:1,records:2,calls:1,..Credit::ZERO},
            Op::FullFence=>self.ticket_operation_cost(object.ok_or(Fault::Key)?,47,1,2,0)?,
            Op::BindControlFinish=>Credit{frames:3*(u64::from(self.graph.m)+1),calls:1,..Credit::ZERO},
            Op::PrepareLease=>Credit::ZERO,
            Op::FreezeFixed|Op::FreezeVersion|Op::FreezeSelected|Op::FreezeApply|
                Op::BindControlBegin|Op::BindControlChunk=>Credit{calls:1,..Credit::ZERO},
            // Continuations are never admitted as free-standing ordinary calls.
            // Their whole original pass/group, phase or finality claim must exist.
            _=>return Err(Fault::Phase),
        };
        let original=if r.a==0{self.lease_key}else{r.a};
        plan.push(Self::ticket_selector(op,original,0),1,cost,pass)?;
        let ticket=self.ticket_admit(vec![plan])?[0];
        self.ticket_take(ticket,Self::ticket_selector(op,original,0))
    }

    fn ticket_move_binding(&self,mi:usize)->Result<TicketBinding>{
        let m=&self.graph.moves[mi];let i=self.current_object(m.object)?;
        Ok(self.ticket_binding(if m.forward==0{TicketPurpose::Move}else{TicketPurpose::Inverse},m.key,i,
            self.active_object(m.from.parent)?,self.active_object(m.to.parent)?))
    }
    fn ticket_delete_binding(&self,di:usize)->Result<TicketBinding>{
        let d=&self.graph.deletes[di];let i=self.current_object(d.object)?;
        let parent=self.active_object(d.edges.first().ok_or(Fault::Key)?.parent)?;
        Ok(self.ticket_binding(TicketPurpose::Delete,d.key,i,parent,parent))
    }
    fn ticket_install_create(&mut self,i:usize,parent:usize)->Result<()>{
        let binding=self.ticket_binding(TicketPurpose::Create,self.objects[i].key,i,parent,parent);
        if self.stop||self.deadline||self.compensation||self.committed_cleanup{return Err(Fault::Phase)}
        let mut plans=vec![self.ticket_create_plan(i,parent)?];
        let role=self.graph.rows[self.objects[i].row].role;
        if !matches!(role,Role::ProbeA|Role::ProbeB){
            let di=self.graph.deletes.iter().position(|d|d.object==self.objects[i].key).ok_or(Fault::Key)?;
            plans.push(self.ticket_delete_plan(di,true,false)?);
        }
        self.ticket_ensure_exits(&mut plans)?;
        let ticket=self.ticket_admit(plans)?[0];
        self.ticket_switch_effect(ticket,Op::CreatePrivate,self.objects[i].key)?;
        self.ticket_flow=Some(TicketFlow{ticket,binding,kind:TicketFlowKind::Create,post:ReadCounts::default()});Ok(())
    }
    fn ticket_install_move(&mut self,mi:usize)->Result<()>{
        let binding=self.ticket_move_binding(mi)?;let m=self.graph.moves[mi].clone();
        let ticket=if let Some(ticket)=self.ticket_book.find(binding){ticket}else{
            if self.stop||self.deadline||self.compensation||self.committed_cleanup||m.forward!=0{return Err(Fault::Phase)}
            let mut plans=vec![self.ticket_move_plan(mi,false,true)?];
            if m.inverse!=0&&m.flags&6==0{
                plans.push(self.ticket_move_plan(self.move_index(m.inverse)?,true,false)?);
            }
            if m.kind==11{
                let di=self.graph.deletes.iter().position(|d|d.object==m.object&&d.kind==4).ok_or(Fault::Key)?;
                plans.push(self.ticket_delete_plan(di,true,false)?);
            }
            self.ticket_admit(plans)?[0]
        };
        if reservations::pool(self.ticket_book.stage(ticket)?)?==1&&!self.compensation&&!self.committed_cleanup{
            return Err(Fault::Phase)
        }
        let post=if m.kind==3{ReadCounts::default()}else{self.ticket_broad_post(mi)?};
        // The concrete POST chosen NOW is a subclaim of the immutable per-
        // original bound held before the associated producer. Inverses can have
        // other already-permitted directories public by this point. They never
        // obtain additional credits, swap originals, or borrow another ticket.
        for (i,n) in post.refresh.iter().enumerate().filter(|(_,n)|**n!=0){
            let op=if self.graph.rows[self.objects[i].row].role.directory(){Op::BeginRoster}else{Op::BeginRead};
            let selector=Self::ticket_selector(op,self.objects[i].key,TICKET_BROAD_POST);
            if self.ticket_book.count(ticket,selector)?<*n{return Err(Fault::Capacity)}
        }
        if self.ticket_book.count(ticket,Self::ticket_selector(Op::CheckLease,self.lease_key,TICKET_BROAD_POST))?<post.lease{
            return Err(Fault::Capacity)
        }
        self.ticket_switch_effect(ticket,Op::Move,m.key)?;
        self.ticket_flow=Some(TicketFlow{ticket,binding,kind:TicketFlowKind::MoveRaw,post});Ok(())
    }
    fn ticket_install_delete(&mut self,di:usize)->Result<()>{
        let binding=self.ticket_delete_binding(di)?;let key=self.graph.deletes[di].key;
        let ticket=if let Some(ticket)=self.ticket_book.find(binding){ticket}else{
            if self.stop||self.deadline||self.compensation||self.committed_cleanup{return Err(Fault::Phase)}
            self.ticket_admit(vec![self.ticket_delete_plan(di,false,true)?])?[0]
        };
        if reservations::pool(self.ticket_book.stage(ticket)?)?==1&&!self.compensation&&!self.committed_cleanup{
            return Err(Fault::Phase)
        }
        self.ticket_switch_effect(ticket,Op::Delete,key)?;
        self.ticket_flow=Some(TicketFlow{ticket,binding,kind:TicketFlowKind::DeleteParent,post:ReadCounts::default()});Ok(())
    }
    fn ticket_validate_inherited_parent(&mut self,i:usize,parent:usize)->Result<()>{
        let expected=self.objects[i].target_parent.clone();
        if let Some(expected)=expected{
            let actual=self.snapshot(parent)?;
            if !expected.same(&self.security[actual.security].data){return Err(Fault::Stale)}
        }
        if self.objects[i].target.is_none(){return Err(Fault::Incomplete)}Ok(())
    }
    fn ticket_derive_targets(&mut self)->Result<()>{
        let mut objects=Vec::new();
        for row in self.graph.missing.clone(){objects.push(self.active_object(row)?);}
        objects.push(self.active_object(self.graph.new_note.ok_or(Fault::Phase)?)?);
        for i in objects{
            if self.objects[i].target.is_some(){continue}
            let row=self.objects[i].row;
            // NewNote's future public parent is the selected row's parent, not
            // the journal which currently owns this private staged file.
            let parent_row=if self.graph.rows[row].role==Role::NewNote{
                self.graph.rows[self.graph.selected_row.ok_or(Fault::Phase)?].parent.ok_or(Fault::Phase)?
            }else{self.graph.rows[row].parent.ok_or(Fault::Phase)?};
            let parent=self.active_object(parent_row)?;
            let policy=if self.objects[parent].creation{
                Arc::clone(self.objects[parent].target.as_ref().ok_or(Fault::Incomplete)?)
            }else{
                let current=self.objects[parent].current.as_ref().ok_or(Fault::Incomplete)?;
                Arc::clone(&self.security[current.security].data)
            };
            let remaining=self.remaining()?;
            let target=self.io.inherited(Arc::clone(&policy),self.graph.rows[row].role.directory(),remaining)?;
            target.ordinary_settable(self.io.user()?,&self.group)?;
            self.objects[i].target_parent=Some(policy);self.objects[i].target=Some(target);
        }Ok(())
    }

    fn ticket_forfeit_flow(&mut self)->Result<()>{
        if let Some(flow)=self.ticket_flow.take(){
            self.ticket_book.close(flow.ticket,flow.binding)?;
        }
        for p in &mut self.passes{
            p.credit=None;
            if !p.complete{p.failed=true;}
        }
        Ok(())
    }
    fn ticket_finality_unit(&mut self,op:Op,r:Request)->Result<TicketUnit>{
        let (ticket,selector)=match op{
            Op::CloseOriginal=>{
                let i=self.current_object(r.a)?;let key=self.objects[i].key;
                let binding=TicketBinding{scope:self.objects[i].scope,purpose:TicketPurpose::Finality,
                    cause:key,object:key,from:self.lease_key,to:self.lease_key};
                (self.ticket_book.find(binding).ok_or(Fault::Incomplete)?,
                    Self::ticket_selector(op,key,0))
            },
            Op::SettleScope|Op::ScopeStatus=>(self.ticket_finality,Self::ticket_selector(op,self.lease_key,r.number)),
            Op::RecordFailure=>(self.ticket_finality,Self::ticket_selector(op,self.lease_key,Self::ticket_failure_step(r.number)?)),
            Op::Retire|Op::ContextStatus|Op::DataPage=>(self.ticket_finality,Self::ticket_selector(op,self.lease_key,0)),
            _=>return Err(Fault::Phase),
        };
        self.ticket_take(ticket,selector)
    }
    fn ticket_pass_unit(&mut self,op:Op,r:Request)->Result<(TicketUnit,TicketHome)>{
        let (key,complete)=match op{
            Op::ReadNext|Op::RosterNext=>(r.a,false),
            Op::SourceObservation=>(r.b,true),
            Op::RecheckSource|Op::CheckEpoch=>(r.c,true),
            _=>return Err(Fault::Phase),
        };
        let p=self.pass_index(key,complete)?;
        if complete{
            if self.passes[p].object!=self.current_object(r.a)?||self.passes[p].observations==0{return Err(Fault::Key)}
            let unit=self.passes[p].credit.as_ref().ok_or(Fault::Incomplete)?;
            if unit.binding.purpose!=TicketPurpose::Ordinary&&unit.binding.purpose!=TicketPurpose::Create&&op!=Op::CheckEpoch{
                return Err(Fault::Phase)
            }
            if unit.binding.purpose==TicketPurpose::Create{
                // This original create's first Source9 is explicitly nonmaterial;
                // only its separate Epoch16 closes the preowned write/fence pass.
                if (self.passes[p].observations==2&&op!=Op::SourceObservation)||
                    (self.passes[p].observations==1&&op!=Op::CheckEpoch){return Err(Fault::Phase)}
            }
        }else if self.passes[p].roster!=(op==Op::RosterNext){return Err(Fault::Key)}
        let unit=self.passes[p].credit.take().ok_or(Fault::Incomplete)?;
        Ok((unit,TicketHome::Pass(p)))
    }
    fn ticket_flow_unit(&mut self,op:Op,r:Request)->Result<TicketUnit>{
        let flow=self.ticket_flow.ok_or(Fault::Phase)?;
        let selector=match flow.kind{
            TicketFlowKind::Create=>{
                if matches!(op,Op::WriteChunk|Op::FinishWrite|Op::FullFence)&&r.a==flow.binding.object{
                    Self::ticket_selector(op,r.a,TICKET_CORE)
                }else if matches!(op,Op::BeginRead|Op::BeginRoster)&&r.a==flow.binding.object{
                    // The whole first pass cannot precede the original fence.
                    if self.ticket_book.available(flow.ticket,Self::ticket_selector(Op::FullFence,r.a,TICKET_CORE)){
                        return Err(Fault::Incomplete)
                    }
                    Self::ticket_selector(op,r.a,TICKET_RAW)
                }else{return Err(Fault::Phase)}
            },
            TicketFlowKind::MoveRaw=>{
                if matches!(op,Op::BeginRead|Op::BeginRoster){Self::ticket_selector(op,r.a,TICKET_RAW)}
                else if op==Op::FinishMove&&r.a==flow.binding.cause{
                    if self.ticket_book.remaining(flow.ticket,TICKET_RAW)?!=0{return Err(Fault::Incomplete)}
                    Self::ticket_selector(op,r.a,TICKET_CORE)
                }else{return Err(Fault::Phase)}
            },
            TicketFlowKind::Publish=>{
                let m=&self.graph.moves[self.move_index(flow.binding.cause)?];
                if op!=Op::PublishSecurity||r.a!=m.publish_transition{return Err(Fault::Key)}
                Self::ticket_selector(op,r.a,TICKET_CORE)
            },
            TicketFlowKind::SecurityRaw|TicketFlowKind::RestoreRaw=>{
                if matches!(op,Op::BeginRead|Op::BeginRoster){Self::ticket_selector(op,r.a,TICKET_SECURITY_RAW)}
                else if op==Op::FinishSecurity{
                    let m=&self.graph.moves[self.move_index(flow.binding.cause)?];
                    let transition=if matches!(flow.kind,TicketFlowKind::RestoreRaw){m.private_transition}else{m.publish_transition};
                    if r.a!=transition||self.ticket_book.remaining(flow.ticket,TICKET_SECURITY_RAW)?!=0{return Err(Fault::Incomplete)}
                    Self::ticket_selector(op,r.a,TICKET_CORE)
                }else{return Err(Fault::Phase)}
            },
            TicketFlowKind::BroadPost=>{
                if op==Op::CheckLease&&flow.post.lease!=0{
                    Self::ticket_selector(op,self.lease_key,TICKET_BROAD_POST)
                }else if matches!(op,Op::BeginRead|Op::BeginRoster){
                    let i=self.current_object(r.a)?;
                    if flow.post.refresh[i]==0{return Err(Fault::Phase)}
                    Self::ticket_selector(op,r.a,TICKET_BROAD_POST)
                }else{return Err(Fault::Phase)}
            },
            TicketFlowKind::DeleteParent=>{
                let d=&self.graph.deletes[self.delete_index(flow.binding.cause)?];
                if op==Op::CloseDeleted&&r.a==d.key{
                    Self::ticket_selector(op,r.a,TICKET_CORE)
                }else if op==Op::BeginRoster&&r.a==flow.binding.from&&d.closed{
                    Self::ticket_selector(op,r.a,TICKET_DELETE_PARENT)
                }else if op==Op::FinishDelete&&r.a==d.key&&d.closed{
                    if self.ticket_book.remaining(flow.ticket,TICKET_DELETE_PARENT)?!=0{return Err(Fault::Incomplete)}
                    Self::ticket_selector(op,r.a,TICKET_CORE)
                }else{return Err(Fault::Phase)}
            },
            TicketFlowKind::DeleteFence=>{
                if op!=Op::FullFence||r.a!=flow.binding.from{return Err(Fault::Key)}
                Self::ticket_selector(op,r.a,TICKET_CORE)
            },
            TicketFlowKind::CorrectiveLead=>{
                let m=&self.graph.moves[self.move_index(flow.binding.cause)?];
                if matches!(op,Op::BeginRead|Op::BeginRoster){
                    Self::ticket_selector(op,r.a,TICKET_CORRECTIVE_LEAD)
                }else if op==Op::RestoreSecurity&&r.a==m.private_transition&&r.a!=0{
                    Self::ticket_selector(op,r.a,TICKET_CORE)
                }else if op==Op::Move&&r.a==m.key{
                    Self::ticket_selector(op,r.a,TICKET_CORE)
                }else{return Err(Fault::Phase)}
            },
        };
        self.ticket_take(flow.ticket,selector)
    }
    fn ticket_inverse_unit(&mut self,op:Op,r:Request)->Result<TicketUnit>{
        let mi=if op==Op::RestoreSecurity{
            let t=self.graph.transitions.iter().find(|t|t.key==r.a&&t.purpose==2).ok_or(Fault::Key)?;
            self.move_index(t.movement)?
        }else{self.move_index(r.a)?};
        let binding=self.ticket_move_binding(mi)?;
        if binding.purpose!=TicketPurpose::Inverse{return Err(Fault::Key)}
        let ticket=self.ticket_book.find(binding).ok_or(Fault::Incomplete)?;
        // Read-only Fixed PRE has its own immutable scope claims. Selecting this
        // inverse does not transfer any of those claims into the corrective group.
        let unit=self.ticket_take(ticket,Self::ticket_selector(op,r.a,TICKET_CORE))?;
        self.ticket_flow=Some(TicketFlow{ticket,binding,kind:TicketFlowKind::CorrectiveLead,post:ReadCounts::default()});
        Ok(unit)
    }
    fn ticket_phase_unit(&mut self,op:Op,r:Request)->Result<TicketUnit>{
        if op==Op::BeginCompensation&&r.number==2{
            let mi=self.move_index(r.b)?;let m=&self.graph.moves[mi];
            if m.forward!=r.a{return Err(Fault::Key)}
            let binding=self.ticket_move_binding(mi)?;
            let ticket=self.ticket_book.find(binding).ok_or(Fault::Incomplete)?;
            return self.ticket_take(ticket,Self::ticket_selector(op,r.a,2))
        }
        let ticket=self.ticket_prelude.ok_or(Fault::Incomplete)?;
        let original=if op==Op::BeginCommittedCleanup{r.a}else{self.lease_key};
        let step=if op==Op::BeginCompensation{1}else{0};
        self.ticket_take(ticket,Self::ticket_selector(op,original,step))
    }
    fn ticket_recovery_unit(&mut self,op:Op,r:Request)->Result<TicketUnit>{
        if self.compensation_joined{return self.ticket_exit_unit(op,r,true)}
        if op==Op::RestoreSecurity{return self.ticket_inverse_unit(op,r)}
        if op==Op::Move{
            let mi=self.move_index(r.a)?;let binding=self.ticket_move_binding(mi)?;
            let ticket=self.ticket_book.find(binding).ok_or(Fault::Incomplete)?;
            return self.ticket_take(ticket,Self::ticket_selector(op,r.a,TICKET_CORE))
        }
        if op==Op::Delete{
            let binding=self.ticket_delete_binding(self.delete_index(r.a)?)?;
            let ticket=self.ticket_book.find(binding).ok_or(Fault::Incomplete)?;
            return self.ticket_take(ticket,Self::ticket_selector(op,r.a,TICKET_CORE))
        }
        let ticket=self.ticket_prelude.ok_or(Fault::Incomplete)?;
        let original=if op==Op::CheckLease{self.lease_key}else{r.a};
        match op{
            Op::CheckLease|Op::BeginRead|Op::BeginRoster|Op::FullFence=>
                self.ticket_take(ticket,Self::ticket_selector(op,original,TICKET_PRELUDE)),
            _=>Err(Fault::Phase),
        }
    }
    /// DATA admission precedes the bridge's actual-entry counters. A returned
    /// lane is corroborated by the bridge, never a request to draw from its
    /// otherwise unused global pool. No native primitive is entered here.
    pub fn bridge_admit(&mut self,r:Request,input:&[u8])->Result<usize>{
        let op=r.header(input.len(),r.output_capacity as usize)?;
        r.operands(op,input)?;
        if r.owner!=self.owner||op==Op::PrepareLease{return Err(Fault::Owner)}
        if self.ticket_active.is_some(){return Err(Fault::Busy)}
        self.allowed(op,r)?;
        let pass_op=matches!(op,Op::BeginRead|Op::BeginRoster);
        if pass_op&&self.passes.iter().any(|p|p.credit.is_some()){return Err(Fault::Incomplete)}
        let home=if pass_op{TicketHome::NewPass}else{TicketHome::Discard};
        let (unit,home,dynamic)=if matches!(op,Op::ReadNext|Op::RosterNext|Op::SourceObservation|Op::RecheckSource|Op::CheckEpoch){
            let (unit,home)=self.ticket_pass_unit(op,r)?;(unit,home,false)
        }else if matches!(op,Op::CloseOriginal|Op::SettleScope|Op::Retire|Op::ContextStatus|Op::ScopeStatus|Op::RecordFailure){
            (self.ticket_finality_unit(op,r)?,home,false)
        }else if op==Op::DataPage{
            let factory=if self.is_unknown()||self.retirement_attempted{None}else{
                self.ticket_factory.iter().find(|(key,ticket)|*key==r.b&&
                    self.ticket_book.available(*ticket,Self::ticket_selector(op,r.b,0))).map(|(_,ticket)|*ticket)
            };
            let unit=if let Some(ticket)=factory{self.ticket_take(ticket,Self::ticket_selector(op,r.b,0))?}
                else{self.ticket_finality_unit(op,r)?};
            (unit,home,false)
        }else if matches!(op,Op::BeginCompensation|Op::JoinCompensation|Op::BeginCommittedCleanup){
            (self.ticket_phase_unit(op,r)?,home,false)
        }else if self.ticket_flow.is_some(){
            (self.ticket_flow_unit(op,r)?,home,false)
        }else if self.compensation||self.committed_cleanup{
            (self.ticket_recovery_unit(op,r)?,home,false)
        }else if self.ticket_exit_ready(op)&&op!=Op::EnterScope{
            (self.ticket_exit_unit(op,r,false)?,home,false)
        }else{
            (self.ticket_ordinary(op,r)?,home,!pass_op&&op!=Op::FullFence)
        };
        self.ticket_activate(unit,home,op,dynamic,true)
    }
    /// Called only when admission succeeded but a bridge-side counter/frame
    /// corroboration refused entry. The consumed claim is forfeited, not returned.
    pub fn bridge_abandon_admission(&mut self,error:Fault){
        if self.ticket_active.is_some(){let _=self.ticket_close_active();}
        let _=self.ticket_forfeit_flow();self.fail(error);
    }

    fn ticket_end_flow(&mut self,flow:TicketFlow)->Result<()>{
        self.ticket_book.close(flow.ticket,flow.binding)?;
        self.ticket_flow=None;Ok(())
    }
    fn ticket_after_call(&mut self,op:Op,binding:TicketBinding,selector:TicketSelector,pass:Option<usize>)->Result<()>{
        if matches!(op,Op::BeginCompensation|Op::BeginCommittedCleanup){
            // Selection of a separate preowned cleanup route forfeits the
            // abandoned producer suffix; it never refills or relabels it.
            self.ticket_forfeit_flow()?;
            if op==Op::BeginCompensation&&selector.step==2{
                let (_,inverse)=self.corrective.ok_or(Fault::Phase)?;
                let mi=self.move_index(inverse)?;let selected=self.ticket_move_binding(mi)?;
                if binding!=selected{return Err(Fault::Key)}
                let ticket=self.ticket_book.find(selected).ok_or(Fault::Incomplete)?;
                self.ticket_flow=Some(TicketFlow{ticket,binding:selected,
                    kind:TicketFlowKind::CorrectiveLead,post:ReadCounts::default()});
            }
            return Ok(())
        }
        if op==Op::JoinCompensation{
            if self.ticket_flow.is_some(){return Err(Fault::Incomplete)}
            if let Some(ticket)=self.ticket_prelude.take(){
                let binding=self.ticket_book.binding(ticket)?;
                self.ticket_book.close(ticket,binding)?;
            }
            return Ok(())
        }
        let Some(mut flow)=self.ticket_flow else{return Ok(())};
        if flow.binding!=binding{return Ok(())}
        match op{
            Op::CheckLease if matches!(flow.kind,TicketFlowKind::BroadPost)&&selector.step==TICKET_BROAD_POST=>{
                flow.post.lease=flow.post.lease.checked_sub(1).ok_or(Fault::Phase)?;
                if flow.post.empty(){return self.ticket_end_flow(flow)}
            },
            Op::SourceObservation|Op::RecheckSource|Op::CheckEpoch=>{
                let p=pass.ok_or(Fault::Phase)?;
                if self.passes[p].observations==0{
                    if matches!(flow.kind,TicketFlowKind::Create){return self.ticket_end_flow(flow)}
                    if matches!(flow.kind,TicketFlowKind::BroadPost)&&selector.step==TICKET_BROAD_POST{
                        let i=self.passes[p].object;
                        flow.post.refresh[i]=flow.post.refresh[i].checked_sub(1).ok_or(Fault::Phase)?;
                        if flow.post.empty(){return self.ticket_end_flow(flow)}
                    }
                }
            },
            Op::FinishMove=>{
                if !matches!(flow.kind,TicketFlowKind::MoveRaw)||selector.original!=flow.binding.cause{return Err(Fault::Phase)}
                let m=&self.graph.moves[self.move_index(flow.binding.cause)?];
                if m.candidate||self.corrective==Some((m.forward,m.key)){return self.ticket_end_flow(flow)}
                flow.kind=if m.publish_transition!=0{TicketFlowKind::Publish}else{TicketFlowKind::BroadPost};
                if matches!(flow.kind,TicketFlowKind::BroadPost)&&flow.post.empty(){return self.ticket_end_flow(flow)}
            },
            Op::PublishSecurity=>{
                if !matches!(flow.kind,TicketFlowKind::Publish){return Err(Fault::Phase)}
                flow.kind=TicketFlowKind::SecurityRaw;
            },
            Op::RestoreSecurity=>{
                if !matches!(flow.kind,TicketFlowKind::CorrectiveLead){return Err(Fault::Phase)}
                flow.kind=TicketFlowKind::RestoreRaw;
            },
            Op::FinishSecurity=>{
                flow.kind=match flow.kind{
                    TicketFlowKind::SecurityRaw=>TicketFlowKind::BroadPost,
                    TicketFlowKind::RestoreRaw=>TicketFlowKind::CorrectiveLead,
                    _=>return Err(Fault::Phase),
                };
                if matches!(flow.kind,TicketFlowKind::BroadPost)&&flow.post.empty(){return self.ticket_end_flow(flow)}
            },
            Op::FinishDelete=>{
                if !matches!(flow.kind,TicketFlowKind::DeleteParent)||selector.original!=flow.binding.cause{return Err(Fault::Phase)}
                if reservations::pool(self.ticket_book.stage(flow.ticket)?)?==1{flow.kind=TicketFlowKind::DeleteFence;}
                else{return self.ticket_end_flow(flow)}
            },
            Op::FullFence if matches!(flow.kind,TicketFlowKind::DeleteFence)=>return self.ticket_end_flow(flow),
            _=>{},
        }
        self.ticket_flow=Some(flow);Ok(())
    }

    fn ticket_exit_binding(&self,recovery:bool)->Result<TicketBinding>{
        let root=self.mapping.first().ok_or(Fault::Phase)?.0;
        let meta=self.graph.rows.iter().position(|r|r.role==Role::OptionalMeta)
            .map(|r|self.mapping[r].0).filter(|i|self.objects[*i].current.is_some()&&self.objects[*i].absent==0);
        Ok(TicketBinding{scope:self.scope,purpose:TicketPurpose::FinalExit,
            cause:if recovery{self.lease_key}else{self.objects[root].key},
            object:self.objects[root].key,from:self.lease_key,to:meta.map_or(0,|i|self.objects[i].key)})
    }
    fn ticket_exit_plan(&self,recovery:bool)->Result<TicketPlan>{
        let binding=self.ticket_exit_binding(recovery)?;
        let stage=match self.scope{1=>2,2=>3,3=>if recovery{15}else{12},_=>return Err(Fault::Phase)};
        let mut plan=TicketPlan::new(binding,stage)?;
        let root=self.current_object(binding.object)?;
        let mut counts=ReadCounts::default();counts.lease()?;counts.refresh(root)?;
        if binding.to!=0{counts.refresh(self.current_object(binding.to)?)?;}
        self.ticket_add_counts(&mut plan,&counts,TICKET_EXIT)?;
        if self.scope==1{
            // C Capture bind_revision performs one body-only lease check after
            // all material rows, BEFORE workspace_scope's distinct exit check.
            plan.push(Self::ticket_selector(Op::CheckLease,self.lease_key,TICKET_CAPTURE_TAIL),1,
                self.ticket_operation_cost(root,35,1,1,1)?,None)?;
        }
        Ok(plan)
    }
    fn ticket_ensure_exits(&self,plans:&mut Vec<TicketPlan>)->Result<()>{
        let binding=self.ticket_exit_binding(false)?;
        if self.ticket_book.find(binding).is_none()&&!plans.iter().any(|p|p.binding==binding){
            plans.push(self.ticket_exit_plan(false)?);
        }
        if self.scope==3&&self.graph.action!=0{
            let binding=self.ticket_exit_binding(true)?;
            if self.ticket_book.find(binding).is_none()&&!plans.iter().any(|p|p.binding==binding){
                plans.push(self.ticket_exit_plan(true)?);
            }
        }
        Ok(())
    }
    fn ticket_material_closed(&self)->bool{
        if !self.graph.selected||!matches!(self.scope,1|2)||self.first_failure.is_some()||self.is_unknown(){
            return false
        }
        self.graph.rows.iter().enumerate().filter(|(_,r)|r.role.source()).all(|(row,_)|{
            let Some((source,_))=self.mapping.get(row)else{return false};
            let object=&self.objects[*source];
            if object.scope!=self.scope||object.creation||!object.attempted||object.pending!=0||object.write_open{
                return false
            }
            if object.absent!=0{
                let proof=self.presences.iter().find(|p|p.key==object.absent&&p.object==*source&&p.present.is_none());
                let baseline=self.capture_objects.get(row).and_then(|i|self.objects.get(*i));
                return object.slot.is_some_and(|s|self.io.state(s)==Ok(SlotState::NoHandle))&&proof.is_some()&&
                    baseline.is_some_and(|o|o.scope==1&&o.row==row&&o.absent!=0)
            }
            if object.slot.is_none_or(|s|self.io.state(s)!=Ok(SlotState::Owned)){return false}
            // Capture's first9 is immutable. Review's corresponding15 is a
            // separate retained proof; later16 never carries RECHECKED4.
            let Ok(capture)=self.observation(object.capture)else{return false};
            if capture.scope!=1||capture.tag!=1||capture.flags&128==0||capture.capture!=capture.key||
                capture.object==usize::MAX||self.objects[capture.object].row!=row{
                return false
            }
            let initial=if self.scope==1{
                if capture.object!=*source{return false}capture
            }else{
                let Some(initial)=self.observations.iter().find(|o|o.object==*source&&o.scope==self.scope&&
                    o.tag==1&&o.flags&(128|4)==(128|4)&&o.capture==capture.key)else{return false};
                initial
            };
            let Ok(latest)=self.observation(object.last_emitted)else{return false};
            if latest.object!=*source||latest.scope!=self.scope||latest.capture!=capture.key||latest.flags&(128|64)!=(128|64)||
                latest.epoch!=object.epoch||latest.security_epoch!=object.security_epoch{
                return false
            }
            if latest.tag==1{
                if latest.key!=initial.key{return false}
            }else if latest.tag!=2||latest.flags&(128|8|4)!=(128|8){return false}
            let Some(pass)=self.passes.iter().find(|p|p.key==latest.pass&&p.object==*source)else{return false};
            pass.key==object.latest_pass&&pass.epoch==object.epoch&&pass.complete&&!pass.failed&&
                pass.observations==0&&pass.credit.is_none()&&object.current.as_ref().is_some_and(|now|self.same(now,&latest.snapshot))
        })
    }
    fn ticket_exit_ready(&self,op:Op)->bool{
        if self.compensation_joined{return true}
        if self.scope==3{return self.graph.apply&&self.graph.action==0}
        // _ensure_source may finish the material census BEFORE read()/binding()
        // performs another ordinary refresh. Only the first actual post-census
        // lease3 selects the finite tail. Once selected, its original suffix
        // remains mandatory even after root/meta16 changes latest tags.
        self.ticket_exit_binding(false).is_ok_and(|b|self.ticket_book.find(b).is_some())||
            op==Op::CheckLease&&self.ticket_material_closed()
    }
    fn ticket_exit_unit(&mut self,op:Op,r:Request,recovery:bool)->Result<TicketUnit>{
        let binding=self.ticket_exit_binding(recovery)?;
        let ticket=if let Some(ticket)=self.ticket_book.find(binding){ticket}else{
            // Capture/Review have no user effects. Their distinct finite tail
            // is admitted before its first new read-only lease effect, after the
            // actual material census fixes the optional original meta identity.
            // Every native consuming close was already charged at acquisition.
            if recovery||self.scope==3||op!=Op::CheckLease||!self.ticket_material_closed(){
                return Err(Fault::Incomplete)
            }
            self.ticket_admit(vec![self.ticket_exit_plan(false)?])?[0]
        };
        let body=Self::ticket_selector(Op::CheckLease,self.lease_key,TICKET_CAPTURE_TAIL);
        if self.ticket_book.available(ticket,body){
            if op!=Op::CheckLease{return Err(Fault::Phase)}
            return self.ticket_take(ticket,body)
        }
        let check=Self::ticket_selector(Op::CheckLease,self.lease_key,TICKET_EXIT);
        let selector=match op{
            Op::CheckLease=>check,
            Op::BeginRoster if r.a==binding.object||r.a==binding.to&&binding.to!=0=>{
                if self.ticket_book.available(ticket,check){return Err(Fault::Incomplete)}
                Self::ticket_selector(op,r.a,TICKET_EXIT)
            },
            _=>return Err(Fault::Phase),
        };
        self.ticket_take(ticket,selector)
    }

    fn ticket_role_object(&self,role:Role)->Result<usize>{
        let row=self.graph.rows.iter().position(|r|r.role==role).ok_or(Fault::Phase)?;
        self.active_object(row)
    }
    fn ticket_refresh_counts(i:usize)->Result<ReadCounts>{
        let mut out=ReadCounts::default();out.refresh(i)?;Ok(out)
    }
    fn ticket_binding_counts(parent:usize,child:Option<usize>)->Result<ReadCounts>{
        let mut out=Self::ticket_refresh_counts(parent)?;
        if let Some(child)=child{out.refresh(child)?;}Ok(out)
    }
    fn ticket_state_counts(&self)->Result<ReadCounts>{
        let mut out=Self::ticket_refresh_counts(self.mapping[0].0)?;out.lease()?;
        if let Some(row)=self.graph.rows.iter().position(|r|r.role==Role::OptionalMeta){
            if let Some(i)=self.ticket_possible(row)?{out.refresh(i)?;}
        }
        Ok(out)
    }
    fn ticket_dependency_counts(&self)->Result<ReadCounts>{
        let mut out=ReadCounts::default();
        for row in self.ticket_dependency_rows(){self.ticket_possible_path(row,&mut out)?;}
        for row in self.ticket_dependency_parents()?{
            let source=self.mapping[row].0;
            if self.objects[source].absent==0{out.refresh(source)?;}
            else{
                // A frozen-absent parent either has this exact created original,
                // or C follows its current closed path. Component-wise original
                // counts reserve the finite alternatives, never a foreign edge.
                if let Some(i)=self.ticket_possible(row)?{out.refresh(i)?;}
                self.ticket_possible_path(row,&mut out)?;
            }
        }
        Ok(out)
    }
    fn ticket_parent_counts(&self,row:usize)->Result<ReadCounts>{
        let mut out=ReadCounts::default();
        if let Some(parent)=self.graph.rows.get(row).ok_or(Fault::Key)?.parent{
            if parent!=0{self.ticket_possible_path(parent,&mut out)?;}
        }
        Ok(out)
    }
    fn ticket_current_counts(&self,row:usize)->Result<ReadCounts>{
        let mut out=ReadCounts::default();
        if row==0{return Self::ticket_refresh_counts(self.mapping[0].0)}
        self.ticket_possible_path(row,&mut out)?;
        if Some(row)==self.graph.selected_row{
            // Current(note) can identify the retained original old target OR
            // the already-declared NewNote original. The editable note is NOT
            // promoted into the frozen dependency file set.
            out.refresh(self.active_object(self.graph.new_note.ok_or(Fault::Phase)?)?)?;
        }
        Ok(out)
    }
    fn ticket_note_binding_counts(&self)->Result<ReadCounts>{
        let row=self.graph.selected_row.ok_or(Fault::Phase)?;
        let parent=self.active_object(self.graph.rows[row].parent.ok_or(Fault::Phase)?)?;
        let mut out=Self::ticket_refresh_counts(parent)?;
        if let Some(i)=self.ticket_possible(row)?{out.refresh(i)?;}
        out.refresh(self.active_object(self.graph.new_note.ok_or(Fault::Phase)?)?)?;Ok(out)
    }
    fn ticket_load_counts(&self)->Result<ReadCounts>{
        let journal=self.ticket_role_object(Role::Journal)?;
        let mut out=Self::ticket_binding_counts(journal,Some(self.ticket_role_object(Role::Header)?))?;
        out.add(&Self::ticket_binding_counts(journal,Some(self.ticket_role_object(Role::Plan)?))?)?;
        // Whether _load rebuilds the parent dictionary depends on the bound
        // plan transition branch. Reserve its finite selected-ancestor multiset;
        // do not incorrectly equate that branch with missing-directory count M.
        for (row,_) in self.graph.rows.iter().enumerate().filter(|(_,r)|r.role==Role::Parent&&r.ancestor!=NONE){
            out.add(&self.ticket_current_counts(row)?)?;
        }
        Ok(out)
    }
    fn ticket_terminal_counts(&self)->Result<ReadCounts>{
        let journal=self.ticket_role_object(Role::Journal)?;
        let mut out=Self::ticket_refresh_counts(journal)?.times(4)?;
        // Four alias lookups, exactly one possible body per marker original.
        // COMMITTED/commit.pending and ROLLED_BACK/rollback.pending are aliases,
        // not four simultaneously live files or four new acquisition permits.
        out.refresh(self.ticket_role_object(Role::Commit)?)?;
        out.refresh(self.ticket_role_object(Role::Rollback)?)?;Ok(out)
    }
    fn ticket_locations_counts(&self)->Result<ReadCounts>{
        let journal=self.ticket_role_object(Role::Journal)?;
        let selected=self.graph.selected_row.ok_or(Fault::Phase)?;
        let new=self.active_object(self.graph.new_note.ok_or(Fault::Phase)?)?;
        let old=if self.graph.backup{Some(self.mapping[selected].0)}else{None};
        let mut out=Self::ticket_refresh_counts(journal)?;
        out.add(&self.ticket_dependency_counts()?)?;
        for (row,r) in self.graph.rows.iter().enumerate().filter(|(_,r)|r.role==Role::Parent&&r.ancestor!=NONE){
            let _=r;out.add(&self.ticket_current_counts(row)?)?;
            if self.graph.missing.contains(&row){
                let i=self.active_object(row)?;
                out.add(&Self::ticket_binding_counts(journal,Some(i))?)?;
                // A staged directory is bound, then borrowed (parent+child),
                // then listed by a separate complete child refresh.
                out.add(&Self::ticket_binding_counts(journal,Some(i))?)?;
                out.refresh(i)?;
                // Alternative installed-created trailing validation:
                // Parent(d/placeholder) has Current(d)'s traversal multiset.
                let mut parent=ReadCounts::default();self.ticket_possible_path(row,&mut parent)?;
                out.add(&parent)?;out.refresh(i)?;
            }
        }
        out.add(&self.ticket_current_counts(selected)?)?;
        out.add(&Self::ticket_binding_counts(journal,Some(new))?)?;
        out.add(&Self::ticket_binding_counts(journal,old)?)?;Ok(out)
    }
    fn ticket_move_prelude_counts(&self,i:usize,to:usize,private_proof:bool)->Result<ReadCounts>{
        // Each move group's own ticket already contains the exact full broad
        // POST. Do NOT charge it here a second time or use it for another cause.
        let mut out=self.ticket_broad_bound(None)?;
        out.refresh(i)?;out.refresh(to)?;
        if private_proof{
            // Full _perform_move refreshes once, then its no-publication branch
            // makes the additional fresh PRIVATE proof. The alternative actual
            // 29/raw/30 chain is owned by the inverse's separate suffix ticket.
            out.refresh(i)?;
        }
        Ok(out)
    }
    fn ticket_preparing_counts(&self)->Result<ReadCounts>{
        let mut out=Self::ticket_refresh_counts(self.ticket_role_object(Role::Journal)?)?;
        out.add(&self.ticket_load_counts()?)?;
        out.add(&self.ticket_locations_counts()?)?;
        out.add(&self.ticket_terminal_counts()?)?;Ok(out)
    }
    fn ticket_rollback_counts(&self)->Result<ReadCounts>{
        let journal=self.ticket_role_object(Role::Journal)?;
        let selected=self.graph.selected_row.ok_or(Fault::Phase)?;
        let destination=self.active_object(self.graph.rows[selected].parent.ok_or(Fault::Phase)?)?;
        let new=self.active_object(self.graph.new_note.ok_or(Fault::Phase)?)?;
        let old=if self.graph.backup{Some(self.mapping[selected].0)}else{None};
        let mut out=self.ticket_terminal_counts()?;
        out.add(&self.ticket_locations_counts()?)?;
        out.add(&self.ticket_parent_counts(selected)?)?;
        out.add(&self.ticket_note_binding_counts()?)?;
        out.add(&self.ticket_move_prelude_counts(new,journal,true)?)?;
        out.add(&Self::ticket_binding_counts(journal,old)?)?;
        if let Some(old)=old{out.add(&self.ticket_move_prelude_counts(old,destination,false)?)?;}
        // One reverse traversal over the exact frozen created-directory set.
        // No generic 256-item roster multiplier and no replay/rescan allowance.
        for row in self.graph.missing.iter().rev(){
            let i=self.active_object(*row)?;
            out.add(&self.ticket_parent_counts(*row)?)?;
            out.add(&self.ticket_move_prelude_counts(i,journal,true)?)?;
        }
        out.add(&self.ticket_locations_counts()?)?;
        // PublishRollbackPrelude = Terminal + binding pending + move PRE.
        out.add(&self.ticket_terminal_counts()?)?;
        let marker=self.ticket_role_object(Role::Rollback)?;
        out.add(&Self::ticket_binding_counts(journal,Some(marker))?)?;
        out.add(&self.ticket_move_prelude_counts(marker,journal,false)?)?;Ok(out)
    }
    fn ticket_cleanup_counts(&self)->Result<ReadCounts>{
        let journal=self.ticket_role_object(Role::Journal)?;let root=self.mapping[0].0;
        let selected=self.graph.selected_row.ok_or(Fault::Phase)?;
        let mut originals=Vec::new();
        for role in [Role::Header,Role::Plan,Role::Commit,Role::Rollback,Role::NewNote]{
            originals.push(self.ticket_role_object(role)?);
        }
        if self.graph.backup{originals.push(self.mapping[selected].0);}
        for row in &self.graph.missing{originals.push(self.active_object(*row)?);}
        if originals.len()!=5+self.graph.missing.len()+usize::from(self.graph.backup){return Err(Fault::Phase)}
        let mut out=self.ticket_dependency_counts()?;
        out.refresh(journal)?;out.add(&self.ticket_load_counts()?)?;
        out.refresh(journal)?;out.add(&self.ticket_terminal_counts()?)?;out.refresh(journal)?;
        for i in &originals{out.add(&Self::ticket_binding_counts(journal,Some(*i))?)?;}
        // The terminal/full-plan and nonterminal/preparing branches are
        // alternatives. Take their per-original upper envelope, not a global
        // queue or a fictitious execution of both branches.
        let mut terminal=self.ticket_load_counts()?;terminal.refresh(journal)?;
        let commit=self.ticket_role_object(Role::Commit)?;
        let rollback=self.ticket_role_object(Role::Rollback)?;
        // chosen marker + commit.pending + rollback.pending: three parent
        // lookups, at most one body of EACH marker original. The chosen public
        // alias and that same original's pending alias cannot both be present.
        terminal.add(&Self::ticket_refresh_counts(journal)?.times(3)?)?;
        terminal.refresh(commit)?;terminal.refresh(rollback)?;
        terminal.add(&self.ticket_terminal_counts()?)?;
        terminal.add(&Self::ticket_binding_counts(journal,Some(self.ticket_role_object(Role::NewNote)?))?)?;
        if self.graph.backup{terminal.add(&Self::ticket_binding_counts(journal,Some(self.mapping[selected].0))?)?;}
        for row in &self.graph.missing{
            let i=self.active_object(*row)?;
            terminal.add(&Self::ticket_binding_counts(journal,Some(i))?)?;
            terminal.add(&Self::ticket_binding_counts(journal,Some(i))?)?;terminal.refresh(i)?;
        }
        let mut nonterminal=self.ticket_preparing_counts()?;nonterminal.add(&self.ticket_load_counts()?)?;
        terminal.upper(&nonterminal);out.add(&terminal)?;
        for i in originals{
            // VerifyEntry = 2R(J)+R(i); deletion PRE = R(J)+R(i).
            // The exact31/32/raw/33 and caller25 remain in that deletion's
            // own ticket, bound before the producer which created this alias.
            out.add(&Self::ticket_refresh_counts(journal)?.times(3)?)?;
            out.add(&Self::ticket_refresh_counts(i)?.times(2)?)?;
        }
        // Final private_check+list empty, then original journal deletion PRE.
        out.add(&Self::ticket_refresh_counts(journal)?.times(3)?)?;out.refresh(root)?;Ok(out)
    }
    fn ticket_prelude_counts(&self)->Result<ReadCounts>{
        let journal=self.ticket_role_object(Role::Journal)?;
        let mut out=self.ticket_dependency_counts()?;out.add(&self.ticket_state_counts()?)?;
        let mut preparing=Self::ticket_refresh_counts(journal)?;
        preparing.add(&self.ticket_preparing_counts()?)?;
        let mut ready=Self::ticket_refresh_counts(journal)?;
        ready.add(&self.ticket_load_counts()?)?;ready.add(&self.ticket_terminal_counts()?)?;
        ready.refresh(journal)?;ready.add(&self.ticket_rollback_counts()?)?;
        preparing.upper(&ready);
        // Preparing/Ready each perform ONE state move into cleanup; an already
        // cleanup state needs neither branch. Their original upper envelope is
        // also an upper bound of that empty branch.
        preparing.add(&self.ticket_state_counts()?)?;
        preparing.add(&self.ticket_move_prelude_counts(journal,self.mapping[0].0,false)?)?;
        out.add(&preparing)?;out.add(&self.ticket_cleanup_counts()?)?;Ok(out)
    }
    fn ticket_install_prelude(&mut self,cause:u64)->Result<()>{
        if self.scope!=3||self.graph.action==0||self.ticket_prelude.is_some()||
            self.bindings.len()!=4||self.bindings.iter().any(|b|!b.complete){return Err(Fault::Phase)}
        let journal=self.ticket_role_object(Role::Journal)?;let root=self.mapping[0].0;
        let binding=self.ticket_binding(TicketPurpose::RecoveryPrelude,cause,journal,root,root);
        let mut prelude=TicketPlan::new(binding,14)?;
        self.ticket_add_counts(&mut prelude,&self.ticket_prelude_counts()?,TICKET_PRELUDE)?;
        let call=Credit{calls:1,..Credit::ZERO};
        prelude.push(Self::ticket_selector(Op::BeginCompensation,self.lease_key,1),1,call,None)?;
        prelude.push(Self::ticket_selector(Op::JoinCompensation,self.lease_key,0),1,call,None)?;
        let committed=self.graph.moves.iter().find(|m|m.kind==15).ok_or(Fault::Phase)?.key;
        prelude.push(Self::ticket_selector(Op::BeginCommittedCleanup,committed,0),1,call,None)?;
        let mut plans=vec![prelude];
        // These are future recovery effects, so their full groups are admitted
        // NOW, before the fourth control creation and before workflow eligibility.
        // No recovery effect may depend on a later successful reservation.
        for kind in [6,7,16]{
            let mi=self.graph.moves.iter().position(|m|m.kind==kind).ok_or(Fault::Phase)?;
            plans.push(self.ticket_move_plan(mi,true,false)?);
            let inverse=self.graph.moves[mi].inverse;
            if inverse!=0{plans.push(self.ticket_move_plan(self.move_index(inverse)?,true,false)?);}
        }
        self.ticket_ensure_exits(&mut plans)?;
        self.ticket_prelude=Some(self.ticket_admit(plans)?[0]);Ok(())
    }

    fn delete_index(&self,key:u64)->Result<usize>{self.graph.deletes.iter().position(|d|d.key==key).ok_or(Fault::Key)}
    fn deletion(&mut self,r:Request)->Result<Body>{
        let di=self.delete_index(r.a)?;let d=self.graph.deletes[di].clone();
        if d.attempted||self.scope!=3||!self.graph.apply||self.compensation_joined{return Err(Fault::Phase)}
        let i=self.current_object(d.object)?;let edge=self.objects[i].edge.clone().ok_or(Fault::Phase)?;
        if !d.edges.contains(&edge){return Err(Fault::Namespace)}
        let role=self.graph.rows[d.row].role;
        if matches!(d.kind,3|5)&&!self.compensation{return Err(Fault::Phase)}
        if d.kind==4&&!self.committed_cleanup{return Err(Fault::Phase)}
        if d.kind==6&&!self.compensation&&!self.committed_cleanup{return Err(Fault::Phase)}
        // Nothing at a committed public target/parent is a cleanup-owned alias.
        if (self.committed!=0&&!self.committed_cleanup)||(self.compensation&&self.committed!=0){return Err(Fault::Phase)}
        let parent=self.active_object(edge.parent)?;
        let parent_pass=self.objects[parent].latest_pass;
        let mut expected=self.roster_for(parent_pass,parent)?;
        let now=self.snapshot(i)?;let id=now.metadata.identity.file_id;
        if !expected.iter().any(|e|e.name==edge.name&&e.file_id==id){return Err(Fault::Stale)}
        if role.directory(){
            let p=self.pass_index(r.b,true)?;
            if self.passes[p].object!=i||!self.passes[p].roster||!self.passes[p].entries.is_empty(){return Err(Fault::Namespace)}
            if !self.same(&now,self.passes[p].after.as_ref().ok_or(Fault::Incomplete)?){return Err(Fault::Stale)}
        }else if r.b!=0{return Err(Fault::Wire)}
        if d.kind!=4&&!self.security[now.security].data.is_private(self.io.user()?){return Err(Fault::Security)}
        if self.graph.moves.iter().any(|m|m.object==d.object&&m.returned&&!m.finalized&&!m.corrected)||
            self.graph.transitions.iter().any(|t|t.object==d.object&&t.accepted&&!t.finalized&&!t.corrected){return Err(Fault::Incomplete)}
        self.io.check_user()?;let epoch=self.epoch.checked_add(1).ok_or(Fault::Capacity)?;let start=self.io.effects.len();
        self.ticket_install_delete(di)?;
        self.graph.deletes[di].attempted=true;self.graph.deletes[di].edge=Some(edge.clone());
        self.io.deletion(self.owned(i)?,self.effect(7,i,r.a,epoch))?;
        let actual=self.last_effect(start)?;self.epoch=epoch;self.objects[i].epoch=epoch;self.objects[i].effect=actual.sequence;self.objects[i].cause=r.a;
        self.graph.deletes[di].accepted=true;self.graph.deletes[di].effect=actual.sequence;
        expected.retain(|e|!(e.name==edge.name&&e.file_id==id));self.pending_parent(parent,r.a,actual.sequence,expected);
        Ok(self.effect_body(r.a,actual,Status::Ok))
    }
    fn close_deleted(&mut self,key:u64)->Result<Body>{
        let d=self.delete_index(key)?;let row=self.graph.deletes[d].clone();
        if !row.accepted||row.closed{return Err(Fault::Phase)}
        let i=self.current_object(row.object)?;let slot=self.slot(i)?;
        if self.close_has_dependents(slot)?{return Err(Fault::Incomplete)}self.io.close(slot,false)?;
        self.graph.deletes[d].closed=true;Ok(Body::unit(key))
    }
    fn finish_delete(&mut self,r:Request)->Result<Body>{
        self.reserve_presence()?;
        let di=self.delete_index(r.a)?;let d=self.graph.deletes[di].clone();
        if !d.accepted||!d.closed||d.finalized{return Err(Fault::Phase)}
        let i=self.current_object(d.object)?;if self.io.state(self.slot(i)?)?!=SlotState::Closed{return Err(Fault::Incomplete)}
        let edge=d.edge.clone().ok_or(Fault::Phase)?;let parent=self.active_object(edge.parent)?;
        let p=self.pass_index(r.b,true)?;if self.passes[p].object!=parent||!self.passes[p].roster{return Err(Fault::Key)}
        let id=self.objects[i].current.as_ref().ok_or(Fault::Incomplete)?.metadata.identity.file_id;
        if self.passes[p].entries.iter().any(|e|e.name.eq_ignore_ascii_case(&edge.name)||e.file_id==id){return Err(Fault::Stale)}
        let after=self.passes[p].after.clone().ok_or(Fault::Incomplete)?;self.fence_snapshot(parent,&after)?;self.io.check_user()?;
        let observation=self.observe_completed(parent,p,2,true,false)?;
        let absence=self.keys.take(KeyKind::Presence,3)?;
        self.presences.push(Presence{key:absence,object:i,parent,present:None,pass:r.b,parent_absent:0,parent_observation:observation,
            epoch:self.objects[parent].epoch,roster:self.passes[p].digest,edge_key:d.key,name:edge.name});
        self.graph.deletes[di].finalized=true;
        // Parent's native internal post proof is NOT a delivered acknowledgement.
        // Deletion72 exposes a reference only; next16 accepts the old full anchor.
        let mut b=Vec::with_capacity(72);b.extend_from_slice(b"MRKNDL1\0");u32s(&mut b,&[72,3]);
        u64s(&mut b,&[self.owner,r.a,self.objects[i].key,d.effect,self.epoch,absence,observation]);
        Ok(Body::one(r.a,b))
    }
    fn entered_primary_without_no_effect(&self,kind:u32,operation:u64)->bool{
        self.io.effects.iter().any(|e|e.kind==kind&&e.operation==operation&&e.flags&1!=0&&e.flags&4==0)
    }
    fn effects_final(&self)->bool{
        // A definitely returned failure is not automatically a proved absence
        // of an effect. In particular m.returned/d.accepted record recognized
        // successes; false cannot erase an entered failed primary receipt.
        !self.is_unknown()&&self.graph.moves.iter().all(|m|m.finalized||m.corrected||
                (!m.returned&&!self.entered_primary_without_no_effect(4,m.key)))&&
            self.graph.transitions.iter().all(|t|!t.attempted||t.finalized||t.corrected||t.no_effect)&&
            self.graph.deletes.iter().all(|d|d.finalized||
                (!d.accepted&&!self.entered_primary_without_no_effect(7,d.key)))&&
            self.objects.iter().all(|o|o.scope!=3||!o.creation||o.slot.is_none()||
                (o.slot.is_some_and(|s|matches!(self.io.state(s),Ok(SlotState::NoHandle)))&&
                    !self.io.effects.iter().any(|e|e.kind==1&&e.object==o.key&&e.flags&1!=0&&e.flags&4==0))||
                self.graph.deletes.iter().any(|d|d.object==o.key&&d.finalized)||
                (!o.write_open&&o.pending==0&&o.last_emitted!=0))
    }
    fn close_object(&mut self,key:u64)->Result<Body>{
        let i=self.current_object(key)?;
        if self.io.frames_active(){return Err(Fault::NativeUnknown)}
        if self.passes.iter().any(|p|p.object==i&&!p.complete&&!p.failed){return Err(Fault::Incomplete)}
        if self.graph.moves.iter().any(|m|m.returned&&!m.finalized&&!m.corrected&&(m.object==key||
            m.from.parent==self.objects[i].row||m.to.parent==self.objects[i].row))||
            self.graph.transitions.iter().any(|t|t.accepted&&!t.finalized&&!t.corrected&&t.object==key){return Err(Fault::Incomplete)}
        if self.graph.deletes.iter().any(|d|d.object==key&&d.accepted){return Err(Fault::Phase)}
        let slot=self.slot(i)?;if self.close_has_dependents(slot)?{return Err(Fault::Incomplete)}
        self.io.close(slot,false)?;Ok(Body::unit(key))
    }
    fn close_has_dependents(&self,slot:usize)->Result<bool>{
        // Union of immutable acquisition parents and every current/frozen Notes
        // alias parent. A successful rename never deletes an old dependency.
        if self.io.book.slots.iter().any(|s|s.parent==Some(slot)&&
            !matches!(s.state,SlotState::NoHandle|SlotState::Closed)){return Ok(true)}
        let Some(parent)=self.objects.iter().position(|o|o.slot==Some(slot))else{return Ok(false)};
        for (i,object) in self.objects.iter().enumerate(){
            if i==parent||object.scope!=self.objects[parent].scope||
                object.slot.is_none_or(|s|matches!(self.io.state(s),Ok(SlotState::NoHandle|SlotState::Closed))){continue}
            if object.edge.as_ref().is_some_and(|e|self.active_object(e.parent)==Ok(parent)){return Ok(true)}
            if self.graph.moves.iter().filter(|m|m.object==object.key).any(|m|
                self.active_object(m.from.parent)==Ok(parent)||self.active_object(m.to.parent)==Ok(parent)){return Ok(true)}
            if self.graph.deletes.iter().filter(|d|d.object==object.key).any(|d|
                d.edges.iter().any(|e|self.active_object(e.parent)==Ok(parent))){return Ok(true)}
        }
        Ok(false)
    }
    fn close_scope_originals(&mut self,scope:Option<u32>)->Result<()>{
        if self.io.frames_active(){return Err(Fault::NativeUnknown)}
        let mut failure=None;
        loop{
            let mut progressed=false;
            for slot in (0..self.io.book.slots.len()).rev(){
                if scope.is_some_and(|scope|!self.objects.iter().any(|o|o.scope==scope&&o.slot==Some(slot))){continue}
                if !matches!(self.io.state(slot),Ok(SlotState::Owned|SlotState::Reserved))||
                    self.io.close_attempted[slot]{continue}
                match self.close_has_dependents(slot){
                    Ok(true)=>continue,
                    Err(e)=>{self.fail(e);if failure.is_none(){failure=Some(e)}continue},
                    Ok(false)=>{},
                }
                progressed=true;
                if let Err(e)=self.io.close(slot,false){
                    self.fail(e);if failure.is_none(){failure=Some(e)}
                }
                // A lost original native close prohibits every further entry.
                if self.io.frames_active(){return Err(failure.unwrap_or(Fault::NativeUnknown))}
            }
            if !progressed{break}
        }
        if let Some(e)=failure{return Err(e)}Ok(())
    }
    fn scope_counts(&self,scope:u32)->(u32,u32,u32){
        let handles=self.objects.iter().filter(|o|o.scope==scope&&o.slot.is_some_and(|s|!matches!(self.io.state(s),Ok(SlotState::Closed|SlotState::NoHandle)))).count() as u32;
        let passes=self.passes.iter().filter(|p|self.objects[p.object].scope==scope&&!p.complete&&!p.failed).count() as u32;
        (handles,passes+u32::from(self.io.frames_active()),self.io.foreign_count())
    }
    fn scope_status(&self,scope:u32)->Result<Body>{
        let s=self.scopes.get(scope as usize-1).ok_or(Fault::Wire)?;if !s.attempted{return Err(Fault::Phase)}
        let (handles,frames,foreign)=self.scope_counts(scope);let mut b=Vec::with_capacity(64);b.extend_from_slice(b"MRKNSC1\0");
        u32s(&mut b,&[64,scope]);u64s(&mut b,&[self.owner,s.root.map_or(0,|i|self.objects[i].key),s.settlement,0]);
        u32s(&mut b,&[handles,frames,foreign,u32::from(s.settlement_attempted)|2*u32::from(s.settlement!=0)|4*u32::from(self.is_unknown())]);
        Ok(Body::one(s.settlement,b))
    }
    fn settle_scope(&mut self,scope:u32)->Result<Body>{
        if scope!=self.scope||self.scopes[scope as usize-1].settlement_attempted{return Err(Fault::OneUse)}
        self.scopes[scope as usize-1].settlement_attempted=true;
        if self.io.frames_active(){return Err(Fault::NativeUnknown)}
        if self.passes.iter().any(|p|self.objects[p.object].scope==scope&&!p.complete&&!p.failed){return Err(Fault::Incomplete)}
        // Consume only dependency-ready originals; an independent known close
        // failure does not skip other eligible originals or replace first failure.
        self.close_scope_originals(Some(scope))?;
        let counts=self.scope_counts(scope);
        if counts!=(0,0,0)||self.is_unknown()||(scope==3&&!self.effects_final()){return Err(Fault::Incomplete)}
        let key=self.keys.take(KeyKind::Settlement,scope)?;self.scopes[scope as usize-1].settlement=key;
        self.scope_status(scope)
    }
    fn compensation(&mut self,r:Request)->Result<Body>{
        if self.first_failure.is_none()||self.scope!=3||self.committed!=0||self.is_unknown()||self.io.frames_active()||self.compensation_joined{return Err(Fault::Phase)}
        if r.number==2{
            if self.compensation{return Err(Fault::OneUse)}
            let f=&self.graph.moves[self.move_index(r.a)?];let inv=&self.graph.moves[self.move_index(r.b)?];
            if !f.returned||f.flags&6!=0||f.inverse!=r.b||inv.forward!=r.a||inv.attempted{return Err(Fault::Key)}
            // Known original forward only. A merely declared inverse after an
            // unreturned or ambiguous native frame never acquires permission.
            self.corrective=Some((r.a,r.b));
        }else if self.compensation{
            let (_,inverse)=self.corrective.ok_or(Fault::OneUse)?;
            if !self.graph.moves[self.move_index(inverse)?].finalized{return Err(Fault::Incomplete)}
            // One corrective->fixed extension of the SAME original phase/pool,
            // not a reset, second producer, new owner or repeated inverse.
            self.corrective=None;
        }
        self.compensation=true;self.io.set_pool(Pool::Recovery);Ok(Body::unit(0))
    }
    fn join_compensation(&mut self)->Result<Body>{
        if (!self.compensation&&!self.committed_cleanup)||self.compensation_joined||self.corrective.is_some()||self.io.frames_active(){return Err(Fault::Phase)}
        if !self.effects_final()||self.ticket_flow.is_some()||self.passes.iter().any(|p|p.credit.is_some()){return Err(Fault::Incomplete)}
        self.compensation_joined=true;if self.scope!=0{self.scopes[self.scope as usize-1].joined=true;}Ok(Body::unit(0))
    }
    fn committed_cleanup(&mut self,key:u64)->Result<Body>{
        if self.committed==0||key!=self.committed||self.compensation||self.committed_cleanup||self.is_unknown(){return Err(Fault::Phase)}
        let m=&self.graph.moves[self.move_index(key)?];if m.kind!=15||!m.finalized{return Err(Fault::Key)}
        self.committed_cleanup=true;self.io.set_pool(Pool::Recovery);Ok(Body::unit(0))
    }
    fn page(&self,r:Request,output:&mut [u8])->Result<Body>{
        let (scope,bytes)=if r.number<=6{
            let d=self.data.iter().find(|d|d.key==r.b&&d.kind==r.number).ok_or(Fault::Key)?;(d.scope,d.bytes.as_slice())
        }else{
            let s=self.security.iter().find(|s|s.key==r.b).ok_or(Fault::Key)?;
            (s.scope,if r.number==7{s.data.canonical.as_slice()}else{s.data.raw.as_slice()})
        };
        let n=wire::Page{kind:r.number,owner:self.owner,scope,key:r.b,offset:r.a,complete:bytes}.encode(r.count,output)?;
        // The bounded bridge copies only this page, never the complete descriptor.
        Ok(Body{token:r.b,count:n as u32,total:bytes.len() as u32,bytes:output[..64+n].to_vec(),status:Status::Ok})
    }
    fn retire(&mut self)->Result<Body>{
        if self.retirement_attempted{return Err(Fault::OneUse)}self.retirement_attempted=true;
        if self.io.frames_active(){return Err(Fault::NativeUnknown)}
        // Includes token/root-walk slots which never reached a successful scope
        // factory. Current+immutable+frozen dependency union governs all closes.
        self.close_scope_originals(None)?;
        if !self.io.all_resources_closed(){return Err(Fault::NativeUnknown)}Ok(Body::unit(0))
    }
    fn allowed(&self,op:Op,r:Request)->Result<()>{
        if self.active_operation{return Err(Fault::Busy)}
        if self.io.frames_active()&&!op.retained_data_only(){return Err(Fault::NativeUnknown)}
        if self.retirement_attempted&&!op.retained_data_only(){return Err(Fault::Phase)}
        if self.is_unknown()&&!op.retained_data_only()&&!matches!(op,Op::SettleScope|Op::CloseOriginal|Op::Retire){return Err(Fault::NativeUnknown)}
        // STOP/deadline permanently veto new user effects and success
        // acceptance. C's cleanup route has an earlier producer cutoff and a
        // preadmitted finite settlement endpoint INSIDE the original owner hard
        // lifetime; native DATA does not invent or extend either clock.
        let corrective_key=self.corrective.map(|(_,inverse)|inverse).or_else(||
            if op==Op::BeginCompensation&&r.number==2{Some(r.b)}else{None});
        let preowned_corrective=corrective_key.is_some_and(|key|{
            let Ok(mi)=self.move_index(key)else{return false};
            let m=&self.graph.moves[mi];
            let held=self.ticket_move_binding(mi).is_ok_and(|b|self.ticket_book.find(b).is_some());
            held||(op==Op::BeginCompensation&&r.number==1&&m.finalized&&self.corrective==Some((m.forward,m.key)))
        });
        let preowned_settlement=self.ticket_prelude.is_some()&&!self.compensation_joined&&
            (if self.corrective.is_some()||op==Op::BeginCompensation&&r.number==2{preowned_corrective}
             else{self.compensation||self.committed_cleanup||
                op==Op::BeginCompensation&&r.number==1||op==Op::BeginCommittedCleanup});
        if (self.stop||self.deadline)&&!op.independent_finality_kind()&&op!=Op::RecordFailure&&!preowned_settlement{
            return Err(if self.deadline{Fault::Deadline}else{Fault::Cancelled})
        }
        if self.first_failure.is_some()&&!self.compensation&&!self.committed_cleanup&&
            !matches!(op,Op::RecordFailure|Op::BeginCompensation|Op::BeginCommittedCleanup|Op::SettleScope|Op::CloseOriginal|Op::Retire|Op::DataPage|Op::ContextStatus|Op::ScopeStatus){return Err(Fault::Phase)}
        if self.compensation_joined{
            if (self.stop||self.deadline)&&!op.independent_finality_kind()&&op!=Op::RecordFailure{
                return Err(if self.deadline{Fault::Deadline}else{Fault::Cancelled})
            }
            match op{
                Op::CheckLease|Op::SettleScope|Op::CloseOriginal|Op::Retire|Op::RecordFailure|Op::DataPage|Op::ContextStatus|Op::ScopeStatus=>{},
                Op::BeginRoster|Op::CheckEpoch=>{
                    let i=self.current_object(r.a)?;if !matches!(self.graph.rows[self.objects[i].row].role,Role::Root|Role::OptionalMeta){return Err(Fault::Phase)}
                },
                Op::RosterNext=>{
                    let p=self.pass_index(r.a,false)?;if !matches!(self.graph.rows[self.objects[self.passes[p].object].row].role,Role::Root|Role::OptionalMeta){return Err(Fault::Phase)}
                },
                _=>return Err(Fault::Phase),
            }
        }
        if let Some((forward,inverse))=self.corrective{
            if (self.stop||self.deadline)&&!op.independent_finality_kind()&&op!=Op::RecordFailure&&!preowned_settlement{
                return Err(if self.deadline{Fault::Deadline}else{Fault::Cancelled})
            }
            let movement=&self.graph.moves[self.move_index(inverse)?];
            let object=self.current_object(movement.object)?;
            let from=self.active_object(movement.from.parent)?;let to=self.active_object(movement.to.parent)?;
            let selected=|i:usize|i==object||i==from||i==to;
            match op{
                Op::BeginRead|Op::BeginRoster|Op::CheckEpoch=>{
                    if !selected(self.current_object(r.a)?){return Err(Fault::Key)}
                },
                Op::ReadNext|Op::RosterNext=>{
                    if !selected(self.passes[self.pass_index(r.a,false)?].object){return Err(Fault::Key)}
                },
                Op::Move|Op::FinishMove=>{if r.a!=inverse{return Err(Fault::Key)}},
                Op::RestoreSecurity|Op::FinishSecurity=>{
                    if movement.private_transition==0||r.a!=movement.private_transition{return Err(Fault::Key)}
                },
                Op::BeginCompensation=>{
                    if r.number!=1||!self.graph.moves[self.move_index(inverse)?].finalized||
                        self.graph.moves[self.move_index(forward)?].inverse!=inverse{return Err(Fault::Incomplete)}
                },
                Op::SettleScope|Op::CloseOriginal|Op::Retire|Op::RecordFailure|Op::DataPage|Op::ContextStatus|Op::ScopeStatus=>{},
                _=>return Err(Fault::Phase),
            }
        }
        if self.compensation||self.committed_cleanup{
            if matches!(op,Op::AcquireLease|Op::EnterScope|Op::FreezeFixed|Op::FreezeVersion|Op::FreezeSelected|Op::AcquireDeclared|Op::FreezeApply){return Err(Fault::Phase)}
            if op==Op::CreatePrivate{
                let i=self.current_object(r.a)?;if self.graph.rows[self.objects[i].row].role!=Role::Rollback||!self.compensation{return Err(Fault::Phase)}
            }
            if matches!(op,Op::BindControlBegin|Op::BindControlChunk|Op::BindControlFinish|Op::WriteChunk|Op::FinishWrite){
                let i=self.current_object(r.a)?;if self.graph.rows[self.objects[i].row].role!=Role::Rollback||!self.compensation{return Err(Fault::Phase)}
            }
        }
        if !matches!(op,Op::PrepareLease|Op::AcquireLease|Op::ContextStatus|Op::DataPage|Op::Retire)&&!self.lease_begun{return Err(Fault::Phase)}
        Ok(())
    }
    fn flags(&self,op:Op,scope:u32,before:(u64,u64))->u32{
        let (entered,returned)=self.io.counters();let any=entered>before.0;
        flags::NATIVE_UNKNOWN*u32::from(self.is_unknown())|
        flags::NATIVE_RESOURCES_SETTLED*u32::from(self.retirement_attempted&&self.io.all_resources_closed())|
        flags::EFFECTS_FINAL*u32::from(self.effects_final())|
        flags::PRIMITIVES_ENTERED*u32::from(any)|
        flags::ALL_ENTERED_RETURNED*u32::from(any&&entered-before.0==returned.saturating_sub(before.1))|
        flags::LEASE_BEGUN*u32::from(self.lease_begun)|
        flags::SCOPE_SETTLED*u32::from(matches!(op,Op::SettleScope|Op::ScopeStatus)&&(1..=3).contains(&scope)&&self.scopes[scope as usize-1].settlement!=0)|
        flags::COMPENSATION_CHOSEN*u32::from(self.compensation)|
        flags::COMMITTED_CLEANUP_CHOSEN*u32::from(self.committed_cleanup)|
        flags::COMMITTED*u32::from(self.committed!=0)|
        flags::RETIREMENT_ATTEMPTED*u32::from(self.retirement_attempted)|
        flags::ROLLED_BACK*u32::from(self.rolled_back!=0)
    }
    fn header(&self,status:Status,error:Option<Fault>,op:Op,scope:u32,before:(u64,u64))->Reply{
        Reply{size:80,version:1,status:status as u32,error:error.map_or(0,|e|e as u32),owner:self.owner,
            epoch:self.epoch,flags:self.flags(op,scope,before),first_failure:self.first_failure.map_or(0,|e|e as u32),..Reply::default()}
    }
    pub fn prepared(&mut self,output:&mut [u8])->Result<Reply>{
        let request=Request{operation:Op::PrepareLease as u32,..Request::default()};
        let unit=self.ticket_ordinary(Op::PrepareLease,request)?;
        // The one Prepare ABI call was reserved with the original bootstrap.
        self.ticket_activate(unit,TicketHome::Discard,Op::PrepareLease,true,false)?;
        let mut body=self.factory(1).and_then(|b|if b.bytes.len()<=output.len(){Ok(b)}else{Err(Fault::Capacity)});
        if let Err(e)=self.ticket_finish_call(Op::PrepareLease,&body){
            if body.is_ok(){body=Err(e);}
        }
        let body=body?;
        output[..body.bytes.len()].copy_from_slice(&body.bytes);
        let mut r=self.header(Status::Ok,None,Op::PrepareLease,0,self.io.counters());
        r.token=body.token;r.count=1;r.total=1;r.output_len=body.bytes.len() as u32;Ok(r)
    }
    /// One synchronous fixed request. The bridge retains this original object and
    /// its exact request/frame through panic/loss; no returned DATA is a HANDLE.
    pub fn call(&mut self,r:Request,input:&[u8],output:&mut [u8])->Reply{
        let before=self.io.counters();let start=self.io.effects.len();
        let op=match r.header(input.len(),output.len()).and_then(|op|r.operands(op,input).map(|_|op)){
            Ok(op)=>op,Err(e)=>{self.bridge_abandon_admission(e);return self.header(Status::Refused,Some(e),Op::ContextStatus,0,before)}
        };
        if r.owner!=self.owner||op==Op::PrepareLease{self.bridge_abandon_admission(Fault::Owner);return self.header(Status::Refused,Some(Fault::Owner),op,r.number,before)}
        if self.ticket_active.as_ref().is_none_or(|a|a.operation!=op){
            self.bridge_abandon_admission(Fault::Phase);return self.header(Status::Refused,Some(Fault::Phase),op,r.number,before)
        }
        let result=self.allowed(op,r).and_then(|_|self.budget(if op.retained_data_only(){wire::OUTPUT_MAX}else{HELPER}));
        let mut result=result.and_then(|_|{
            self.active_operation=true;
            let body=self.dispatch(op,r,input,output);
            self.active_operation=false;body
        }).and_then(|body|if body.bytes.len()<=output.len(){Ok(body)}else{Err(Fault::Capacity)});
        if let Err(e)=self.ticket_finish_call(op,&result){
            if result.is_ok(){result=Err(e);}
            let _=self.ticket_forfeit_flow();
        }
        match result{
            Ok(body) if body.bytes.len()<=output.len()=>{
                output[..body.bytes.len()].copy_from_slice(&body.bytes);
                let mut reply=self.header(body.status,None,op,r.number,before);
                reply.token=body.token;reply.count=body.count;reply.total=body.total;reply.output_len=body.bytes.len() as u32;reply
            },
            other=>{
                let error=match other{Err(e)=>e,_=>Fault::Capacity};self.fail(error);
                let entered=self.io.counters().0>before.0;
                let status=if self.is_unknown(){Status::Unknown}else if entered{Status::FailedKnown}else{Status::Refused};
                let mut reply=self.header(status,Some(error),op,r.number,before);
                let primary=self.io.effects.get(start).copied().filter(|e|e.flags&1!=0&&op.primary_effect());
                if status!=Status::Refused{
                    if let Some(effect)=primary{
                        let bytes=effect.encode(self.owner);
                        if output.len()>=80{output[..80].copy_from_slice(&bytes);reply.output_len=80;reply.count=1;reply.total=1;
                            reply.token=if op==Op::CreatePrivate{0}else{r.a};}
                    }
                }
                reply
            }
        }
    }
    fn dispatch(&mut self,op:Op,r:Request,input:&[u8],output:&mut [u8])->Result<Body>{
        match op{
            Op::PrepareLease=>Err(Fault::OneUse),Op::AcquireLease=>self.lease_check(true),Op::CheckLease=>self.lease_check(false),
            Op::EnterScope=>self.enter_scope(r.number),Op::FreezeFixed=>self.fixed(r.a),Op::FreezeVersion=>self.version(r,input),
            Op::FreezeSelected=>self.selected(r,input),Op::AcquireDeclared=>self.acquire(r.a,r.b),
            Op::SourceObservation=>self.source(r,false),Op::RecheckSource=>self.source(r,true),Op::CheckEpoch=>self.check_epoch(r),
            Op::BeginRead=>self.begin_pass(r.a,false),Op::ReadNext=>self.next_pass(r.a,false),
            Op::BeginRoster=>self.begin_pass(r.a,true),Op::RosterNext=>self.next_pass(r.a,true),
            Op::Presence=>self.presence(r.a,r.b),Op::SettleScope=>self.settle_scope(r.number),Op::FreezeApply=>self.freeze_apply(r,input),
            Op::BindControlBegin|Op::BindControlChunk|Op::BindControlFinish=>self.bind(r,input,op),
            Op::CreatePrivate=>self.create(r),Op::WriteChunk=>self.write(r,input),Op::FinishWrite=>self.finish_write(r.a),Op::FullFence=>self.fence(r.a),
            Op::Move=>self.movement(r),Op::FinishMove=>self.finish_move(r,input),
            Op::PublishSecurity=>self.transition(r.a,false),Op::RestoreSecurity=>self.transition(r.a,true),Op::FinishSecurity=>self.finish_transition(r),
            Op::Delete=>self.deletion(r),Op::CloseDeleted=>self.close_deleted(r.a),Op::FinishDelete=>self.finish_delete(r),
            Op::CloseOriginal=>self.close_object(r.a),
            Op::RecordFailure=>{let e=match r.number{13=>Fault::Core,14=>Fault::Parser,18=>Fault::Cancelled,19=>Fault::Deadline,_=>return Err(Fault::Wire)};self.fail(e);Ok(Body::unit(0))},
            Op::BeginCompensation=>self.compensation(r),Op::JoinCompensation=>self.join_compensation(),
            Op::BeginCommittedCleanup=>self.committed_cleanup(r.a),Op::DataPage=>self.page(r,output),Op::Retire=>self.retire(),
            Op::ContextStatus=>Ok(Body::unit(0)),Op::ScopeStatus=>self.scope_status(r.number),
        }
    }
}
// Ordinary retained vectors grow only after precharging their whole replacement
// allocation (old storage is still charged). Fixed DATA extents use the helper
// reserve; no geometric unbounded retained growth can follow a native effect.
fn grow<T>(values:&mut Vec<T>,additional:usize,available:usize)->Result<()>{
    let needed=values.len().checked_add(additional).ok_or(Fault::Capacity)?;
    if needed<=values.capacity(){return Ok(())}
    let bytes=needed.checked_mul(size_of::<T>()).ok_or(Fault::Capacity)?;
    if bytes>available{return Err(Fault::Capacity)}
    values.try_reserve_exact(additional).map_err(|_|Fault::Capacity)?;
    if values.capacity().checked_mul(size_of::<T>()).is_none_or(|n|n>available){return Err(Fault::Capacity)}
    Ok(())
}
fn fixed_vec<T>(capacity:usize)->Result<Vec<T>>{
    let mut out=Vec::new();out.try_reserve_exact(capacity).map_err(|_|Fault::Capacity)?;Ok(out)
}
fn encode_roster(entries:&[DirectoryEntry])->Vec<u8>{
    batch(entries.iter().map(|e|{let mut b=Vec::with_capacity(32+e.name.len());b.extend_from_slice(&e.file_id);
        u32s(&mut b,&[if e.kind==FileKind::File{1}else{2},e.attributes,e.name.len() as u32,0]);b.extend_from_slice(e.name.as_bytes());b}).collect())
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn new_notes_owner_is_data_only_and_does_not_promote_image_or_default(){
        let mut root=Vec::new();root.extend_from_slice(b"MRKNLS1\0");u32s(&mut root,&[48,0]);u64s(&mut root,&[7]);
        root.extend_from_slice(&[1;16]);u32s(&mut root,&[4,0]);root.extend_from_slice(b"C:\\x");
        let c=NotesContext::prepare(&root).unwrap();assert!(c.io.book.never_started());
        assert!(c.io.book.purpose.is_notes_namespace());assert_eq!(c.io.book.live_limit,48);
        assert_eq!(c.io.book.records_limit,32768);assert_eq!(NativeBookDefaults::values(),(48,8256));
        assert!(!c.retirement_attempted);assert_eq!(c.scope,0);assert_eq!(c.io.quota.acquisitions,0);
    }
    struct NativeBookDefaults;
    impl NativeBookDefaults{fn values()->(usize,usize){let b=crate::NativeBook::new();(b.live_limit,b.records_limit)}}
    #[test]fn reservation_pools_never_borrow_each_others_suffix(){
        let mut q=custody::Quota::default();for _ in 0..2048{q.pass(Pool::Producer).unwrap();}
        assert!(q.pass(Pool::Producer).is_err());assert_eq!(q.passes[1],0);q.pass(Pool::Recovery).unwrap();
    }
    #[test]fn keys_are_original_nonzero_typed_and_never_recycled(){
        let mut keys=Keys::new();let a=keys.take(KeyKind::Object,1).unwrap();let b=keys.take(KeyKind::Object,2).unwrap();
        let c=keys.take(KeyKind::Pending,2).unwrap();assert_ne!(a,b);assert_ne!(b,c);assert_ne!(a,0);
    }

    #[test]fn alternative_read_counts_are_per_original_maxima_not_combined_paths(){
        let mut a=ReadCounts::default();a.refresh[3]=2;a.refresh[8]=1;a.lease=1;
        let mut b=ReadCounts::default();b.refresh[3]=1;b.refresh[8]=5;b.lease=2;
        let mut envelope=a;envelope.upper(&b);
        assert_eq!(envelope.refresh[3],2);assert_eq!(envelope.refresh[8],5);assert_eq!(envelope.lease,2);
        let mut sequence=a;sequence.add(&b).unwrap();
        assert_eq!(sequence.refresh[3],3);assert_eq!(sequence.refresh[8],6);assert_eq!(sequence.lease,3);
        let twice=envelope.times(2).unwrap();
        assert_eq!(twice.refresh[3],4);assert_eq!(twice.refresh[8],10);assert_eq!(twice.lease,4);
        assert!(!twice.empty());assert!(twice.times(0).unwrap().empty());
        let mut overflow=ReadCounts::default();overflow.refresh[153]=u32::MAX;
        assert!(matches!(overflow.times(2),Err(Fault::Capacity)));
        assert_eq!(overflow.refresh(154),Err(Fault::Key));
    }
    #[test]fn capture_body_lease_and_scope_exit_lease_are_distinct_one_use_claims(){
        let mut ledger=Ledger::new();let mut tickets=Tickets::new().unwrap();
        let binding=TicketBinding{scope:1,purpose:TicketPurpose::FinalExit,cause:11,object:11,from:7,to:0};
        let body=NotesContext::ticket_selector(Op::CheckLease,7,TICKET_CAPTURE_TAIL);
        let exit=NotesContext::ticket_selector(Op::CheckLease,7,TICKET_EXIT);
        assert_ne!(body,exit);assert_eq!(body.original,exit.original);
        let mut p=TicketPlan::new(binding,2).unwrap();
        for selector in [body,exit]{p.push(selector,1,Credit{calls:1,..Credit::ZERO},None).unwrap();}
        let id=tickets.admit(&mut ledger,vec![p]).unwrap()[0];
        tickets.take(id,binding,body).unwrap();
        assert!(!tickets.available(id,body));assert!(tickets.available(id,exit));
        assert_eq!(tickets.take(id,binding,body).err(),Some(Fault::Capacity));
        tickets.take(id,binding,exit).unwrap();assert!(!tickets.available(id,exit));
    }
    #[test]fn bootstrap_binds_wire_failures_to_closed_independent_finality_steps(){
        let mut root=Vec::new();root.extend_from_slice(b"MRKNLS1\0");u32s(&mut root,&[48,0]);u64s(&mut root,&[7]);
        root.extend_from_slice(&[1;16]);u32s(&mut root,&[4,0]);root.extend_from_slice(b"C:\\x");
        let mut c=NotesContext::prepare(&root).unwrap();let before=c.ticket_ledger.table();
        for (error,step) in [(13,1),(14,2),(18,3),(19,4)]{
            assert_eq!(NotesContext::ticket_failure_step(error),Ok(step));
            for _ in 0..16{
                let unit=c.ticket_finality_unit(Op::RecordFailure,Request{number:error,..Request::default()}).unwrap();
                assert_eq!(unit.stage,16);assert_eq!(unit.selector.step,step);
                assert_eq!(unit.credit,Credit{calls:1,..Credit::ZERO});
            }
            assert_eq!(c.ticket_finality_unit(Op::RecordFailure,Request{number:error,..Request::default()}).err(),
                Some(Fault::Capacity));
        }
        assert_eq!(NotesContext::ticket_failure_step(0),Err(Fault::Wire));
        assert_eq!(NotesContext::ticket_failure_step(15),Err(Fault::Wire));
        assert_eq!(c.ticket_ledger.table(),before);assert!(c.io.book.never_started());
    }

    #[test]fn failed_primary_receipts_are_not_final_merely_because_success_flags_are_false(){
        let mut root=Vec::new();root.extend_from_slice(b"MRKNLS1\0");u32s(&mut root,&[48,0]);u64s(&mut root,&[7]);
        root.extend_from_slice(&[1;16]);u32s(&mut root,&[4,0]);root.extend_from_slice(b"C:\\x");
        let mut c=NotesContext::prepare(&root).unwrap();
        let from=Edge{parent:0,name:"a".to_owned()};let to=Edge{parent:0,name:"b".to_owned()};
        c.graph.moves.push(namespace::Movement{key:71,row:0,object:72,from:from.clone(),to,
            inverse:0,forward:0,private_transition:0,publish_transition:0,kind:1,flags:0,
            attempted:true,returned:false,candidate:false,finalized:false,corrected:false,effect:0,before_observation:0});
        // A DATA-only pre-entry refusal has no entered effect to settle.
        assert!(c.effects_final());
        c.io.effects.push(Effect{kind:4,operation:71,object:72,return_kind:1,bits:0xc0000022,
            flags:3,..Effect::default()});
        assert!(!c.effects_final());
        c.graph.moves[0].corrected=true;assert!(c.effects_final());
        c.graph.deletes.push(namespace::Deletion{key:73,row:0,object:72,kind:1,edges:vec![from],
            attempted:true,accepted:false,closed:false,finalized:false,effect:0,edge:None});
        assert!(c.effects_final());
        c.io.effects.push(Effect{kind:7,operation:73,object:72,return_kind:1,bits:0xc0000022,
            flags:3,..Effect::default()});
        assert!(!c.effects_final());
        // This test changes retained proof DATA, never calls a native deleter.
        c.graph.deletes[0].finalized=true;assert!(c.effects_final());
        assert!(c.io.book.never_started());
    }
}
