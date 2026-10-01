//! Closed Notes logical acquisition/effect graph. DATA only; no OS calls.
use super::wire::{Fault,Result,component,relative};
pub(super) const NONE:u32=u32::MAX;
#[derive(Clone,Copy,Debug,Eq,PartialEq)] #[repr(u32)]
pub(super) enum Role {Root=1,OptionalMeta=2,Parent=3,Config=4,Ignore=5,Version=6,Selected=7,Counterpart=8,
    Journal=9,Header=10,Plan=11,Commit=12,Rollback=13,ProbeA=14,ProbeB=15,NewNote=16}
impl Role {
    pub fn directory(self)->bool{matches!(self,Self::Root|Self::OptionalMeta|Self::Parent|Self::Journal|Self::ProbeA|Self::ProbeB)}
    pub fn source(self)->bool{(self as u32)<=8}
    pub fn control(self)->bool{matches!(self,Self::Header|Self::Plan|Self::Commit|Self::Rollback)}
    pub fn created(self)->bool{(self as u32)>=9}
}
#[derive(Clone,Copy)]#[repr(u8)]
pub(super) enum KeyKind{Lease=1,Logical=2,Object=3,Observation=4,Pass=5,Presence=6,Factory=7,Data=8,
    Move=9,Delete=10,Transition=11,Control=12,Pending=13,Settlement=14,StableSecurity=15}
pub(super) struct Keys{next:u64}
impl Keys{
    pub fn new()->Self{Self{next:0}}
    pub fn take(&mut self,kind:KeyKind,scope:u32)->Result<u64>{
        if self.next>=0x0000_ffff_ffff_ffff||scope>3{return Err(Fault::Capacity)}
        self.next+=1;Ok(((kind as u64)<<56)|((scope as u64)<<48)|self.next)
    }
}
#[derive(Clone)]
pub(super) struct Logical{
    pub key:u64,pub stable_security:u64,pub role:Role,pub parent:Option<usize>,
    pub path:String,pub name:String,pub limit:u64,pub ancestor:u32,
}
#[derive(Clone,Debug,Eq,PartialEq)]
pub(super) struct Edge{pub parent:usize,pub name:String}
#[derive(Clone)]
pub(super) struct Movement{
    pub key:u64,pub row:usize,pub object:u64,pub from:Edge,pub to:Edge,
    pub inverse:u64,pub forward:u64,pub private_transition:u64,pub publish_transition:u64,
    pub kind:u32,pub flags:u32,pub attempted:bool,pub returned:bool,pub candidate:bool,
    pub finalized:bool,pub corrected:bool,pub effect:u64,pub before_observation:u64,
}
#[derive(Clone)]
pub(super) struct Deletion{
    pub key:u64,pub row:usize,pub object:u64,pub kind:u32,pub edges:Vec<Edge>,
    pub attempted:bool,pub accepted:bool,pub closed:bool,pub finalized:bool,pub effect:u64,pub edge:Option<Edge>,
}
#[derive(Clone)]
pub(super) struct Transition{
    pub key:u64,pub row:usize,pub object:u64,pub paired:u64,pub movement:u64,
    pub policy:u64,pub stable:u64,pub purpose:u32,pub order:u32,
    pub attempted:bool,pub accepted:bool,pub finalized:bool,pub corrected:bool,pub no_effect:bool,pub effect:u64,
}
pub(super) struct Graph{
    pub rows:Vec<Logical>,pub moves:Vec<Movement>,pub deletes:Vec<Deletion>,pub transitions:Vec<Transition>,
    pub fixed:bool,pub version:bool,pub selected:bool,pub apply:bool,
    pub kind:u32,pub f:u32,pub p:u32,pub m:u32,pub backup:bool,pub action:u32,
    pub version_row:Option<usize>,pub selected_row:Option<usize>,pub counterpart_row:Option<usize>,
    pub journal:Option<usize>,pub new_note:Option<usize>,pub missing:Vec<usize>,
}
impl Graph{
    pub fn new(keys:&mut Keys)->Result<Self>{
        let root=Logical{key:keys.take(KeyKind::Logical,0)?,stable_security:keys.take(KeyKind::StableSecurity,0)?,
            role:Role::Root,parent:None,path:String::new(),name:String::new(),limit:0,ancestor:NONE};
        let mut rows=Vec::new();rows.try_reserve_exact(38).map_err(|_|Fault::Capacity)?;rows.push(root);
        Ok(Self{rows,moves:Vec::new(),deletes:Vec::new(),transitions:Vec::new(),fixed:false,version:false,selected:false,apply:false,
            kind:0,f:0,p:0,m:0,backup:false,action:0,version_row:None,selected_row:None,counterpart_row:None,journal:None,new_note:None,missing:Vec::new()})
    }
    pub fn add(&mut self,keys:&mut Keys,role:Role,parent:usize,name:&str,limit:u64,ancestor:u32)->Result<usize>{
        if self.rows.len()>=38||!component(name)||!self.rows.get(parent).is_some_and(|r|r.role.directory()){return Err(Fault::Namespace)}
        if self.rows.iter().any(|r|r.parent==Some(parent)&&r.name.eq_ignore_ascii_case(name)){return Err(Fault::Namespace)}
        let path=if self.rows[parent].path.is_empty(){name.to_owned()}else{format!("{}/{}",self.rows[parent].path,name)};
        // Journal internal aliases are bounded separately; external selected paths<=512.
        if path.len()>1024{return Err(Fault::Bounds)}
        let i=self.rows.len();self.rows.push(Logical{key:keys.take(KeyKind::Logical,0)?,
            stable_security:keys.take(KeyKind::StableSecurity,0)?,role,parent:Some(parent),path,name:name.to_owned(),limit,ancestor});Ok(i)
    }
    fn parents(&mut self,keys:&mut Keys,path:&str,selected:bool)->Result<(usize,String)>{
        relative(path.as_bytes())?;let parts:Vec<_>=path.split('/').collect();let mut parent=0;
        for (i,name) in parts[..parts.len()-1].iter().enumerate(){
            if let Some(index)=self.rows.iter().position(|r|r.parent==Some(parent)&&r.name==*name){
                if self.rows[index].role!=Role::Parent{return Err(Fault::Namespace)}
                if selected{self.rows[index].ancestor=i as u32;}parent=index;
            }else{parent=self.add(keys,Role::Parent,parent,name,0,if selected{i as u32}else{NONE})?;}
        }
        Ok((parent,parts.last().ok_or(Fault::Namespace)?.to_string()))
    }
    pub fn freeze_fixed(&mut self,keys:&mut Keys)->Result<()>{
        if self.fixed{return Err(Fault::OneUse)}self.fixed=true;
        self.add(keys,Role::OptionalMeta,0,".mobile-release",0,NONE)?;
        let release=self.add(keys,Role::Parent,0,"release",0,NONE)?;
        self.add(keys,Role::Config,release,"mobile-release.json",524288,NONE)?;
        self.add(keys,Role::Ignore,0,".gitignore",1048576,NONE)?;Ok(())
    }
    pub fn freeze_version(&mut self,keys:&mut Keys,path:Option<&str>)->Result<()>{
        if !self.fixed||self.version{return Err(Fault::Phase)}self.version=true;
        if let Some(path)=path{let (parent,name)=self.parents(keys,path,false)?;
            self.version_row=Some(self.add(keys,Role::Version,parent,&name,65536,NONE)?);}Ok(())
    }
    pub fn freeze_selected(&mut self,keys:&mut Keys,kind:u32,path:&str,counterpart:Option<&str>)->Result<()>{
        if !self.version||self.selected||!(1..=5).contains(&kind){return Err(Fault::Phase)}
        let cap=match kind{1|2=>2000,3|4=>32768,5=>65536,_=>return Err(Fault::Wire)};
        let (parent,name)=self.parents(keys,path,true)?;
        self.selected_row=Some(self.add(keys,Role::Selected,parent,&name,cap,NONE)?);
        if let Some(other)=counterpart{
            if kind>2{return Err(Fault::Namespace)}
            let (p,n)=self.parents(keys,other,true)?;if p!=parent||n==name{return Err(Fault::Namespace)}
            self.counterpart_row=Some(self.add(keys,Role::Counterpart,p,&n,2000,NONE)?);
        }
        self.kind=kind;self.selected=true;self.f=3+u32::from(self.version_row.is_some())+u32::from(self.counterpart_row.is_some());
        self.p=self.rows.iter().filter(|r|r.role==Role::Parent).count() as u32;
        if self.f>5||self.p>23{return Err(Fault::Capacity)}Ok(())
    }
    fn movement(&mut self,keys:&mut Keys,row:usize,object:u64,from:Edge,to:Edge,kind:u32,flags:u32)->Result<usize>{
        if self.moves.len()>=38||from==to{return Err(Fault::Capacity)}
        let i=self.moves.len();self.moves.push(Movement{key:keys.take(KeyKind::Move,3)?,row,object,from,to,inverse:0,forward:0,
            private_transition:0,publish_transition:0,kind,flags,attempted:false,returned:false,candidate:false,finalized:false,corrected:false,effect:0,before_observation:0});Ok(i)
    }
    fn pair(&mut self,a:usize,b:usize){self.moves[a].inverse=self.moves[b].key;self.moves[b].forward=self.moves[a].key;}
    fn deletion(&mut self,keys:&mut Keys,row:usize,object:u64,kind:u32,edges:Vec<Edge>)->Result<()>{
        if self.deletes.len()>=20||edges.is_empty()||edges.len()>3{return Err(Fault::Capacity)}
        self.deletes.push(Deletion{key:keys.take(KeyKind::Delete,3)?,row,object,kind,edges,attempted:false,accepted:false,closed:false,
            finalized:false,effect:0,edge:None});Ok(())
    }
    fn security_pair(&mut self,keys:&mut Keys,row:usize,object:u64,forward:usize,inverse:usize,policy:u64)->Result<()>{
        let a=keys.take(KeyKind::Transition,3)?;let b=keys.take(KeyKind::Transition,3)?;
        for (key,paired,movement,purpose,order) in [(a,b,self.moves[forward].key,1,1),(b,a,self.moves[inverse].key,2,2)]{
            self.transitions.push(Transition{key,row,object,paired,movement,policy,stable:self.rows[row].stable_security,
                purpose,order,attempted:false,accepted:false,finalized:false,corrected:false,no_effect:false,effect:0});
        }
        self.moves[forward].publish_transition=a;self.moves[inverse].private_transition=b;Ok(())
    }
    // New rows/creation originals are assigned by the context before movement
    // declarations; objects[] is the exact frozen Apply mapping, not client DATA.
    pub fn freeze_effects(&mut self,keys:&mut Keys,objects:&[u64],selected_policy:u64)->Result<()>{
        if !self.apply||self.action==0||objects.len()!=self.rows.len(){return Err(Fault::Phase)}
        let j=self.journal.ok_or(Fault::Phase)?;let new=self.new_note.ok_or(Fault::Phase)?;
        let selected=self.selected_row.ok_or(Fault::Phase)?;
        let edge=|parent,name:&str|Edge{parent,name:name.to_owned()};
        let prep=edge(0,".mobile-release-metadata-text-prepare");let ready=edge(0,".mobile-release-metadata-text");
        let cleanup=edge(0,".mobile-release-metadata-text-cleanup");
        for (from,to,kind) in [(prep.clone(),ready.clone(),5),(ready.clone(),cleanup.clone(),6),(prep.clone(),cleanup.clone(),7)]{
            let a=self.movement(keys,j,objects[j],from.clone(),to.clone(),kind,0)?;
            let b=self.movement(keys,j,objects[j],to,from,8,8|16)?;self.pair(a,b);
        }
        for (role,from,to,kind,flag) in [(Role::Header,"header.tmp","header.json",1,0),
            (Role::Plan,"plan.tmp","plan.json",2,0),(Role::Commit,"commit.pending","COMMITTED",15,2),
            (Role::Rollback,"rollback.pending","ROLLED_BACK",16,4)]{
            let row=self.rows.iter().position(|r|r.role==role).ok_or(Fault::Phase)?;
            self.movement(keys,row,objects[row],edge(j,from),edge(j,to),kind,flag)?;
            self.deletion(keys,row,objects[row],2,vec![edge(j,from),edge(j,to)])?;
        }
        let probe_a=self.rows.iter().position(|r|r.role==Role::ProbeA).ok_or(Fault::Phase)?;
        let probe_b=self.rows.iter().position(|r|r.role==Role::ProbeB).ok_or(Fault::Phase)?;
        self.movement(keys,probe_a,objects[probe_a],edge(j,"probe-a"),edge(j,"probe-b"),3,1)?;
        self.movement(keys,probe_a,objects[probe_a],edge(j,"probe-a"),edge(j,"probe-c"),4,0)?;
        self.deletion(keys,probe_a,objects[probe_a],1,vec![edge(j,"probe-a"),edge(j,"probe-c")])?;
        self.deletion(keys,probe_b,objects[probe_b],1,vec![edge(j,"probe-b")])?;
        for row in self.missing.clone(){
            let initial=edge(j,&format!("directory-{}",self.rows[row].ancestor));
            let public=edge(self.rows[row].parent.ok_or(Fault::Phase)?,&self.rows[row].name);
            let a=self.movement(keys,row,objects[row],initial.clone(),public.clone(),9,0)?;
            let b=self.movement(keys,row,objects[row],public,initial.clone(),10,8)?;self.pair(a,b);
            self.security_pair(keys,row,objects[row],a,b,objects[self.rows[row].parent.ok_or(Fault::Phase)?])?;
            self.deletion(keys,row,objects[row],5,vec![initial])?;
        }
        let target=edge(self.rows[selected].parent.ok_or(Fault::Phase)?,&self.rows[selected].name);
        if self.backup{
            let a=self.movement(keys,selected,objects[selected],target.clone(),edge(j,"old-0"),11,0)?;
            let b=self.movement(keys,selected,objects[selected],edge(j,"old-0"),target.clone(),12,8)?;self.pair(a,b);
            self.deletion(keys,selected,objects[selected],4,vec![edge(j,"old-0")])?;
        }
        let a=self.movement(keys,new,objects[new],edge(j,"new-0"),target.clone(),13,0)?;
        let b=self.movement(keys,new,objects[new],target,edge(j,"new-0"),14,8)?;self.pair(a,b);
        self.security_pair(keys,new,objects[new],a,b,selected_policy)?;
        self.deletion(keys,new,objects[new],3,vec![edge(j,"new-0")])?;
        self.deletion(keys,j,objects[j],6,vec![prep,ready,cleanup])?;
        if self.moves.len()!=14+2*self.missing.len()+2*usize::from(self.backup)
            ||self.deletes.len()!=self.missing.len()+8+usize::from(self.backup)
            ||self.transitions.len()!=2*(self.missing.len()+1){return Err(Fault::Capacity)}Ok(())
    }
    pub fn add_apply_rows(&mut self,keys:&mut Keys,action:u32,missing:Vec<usize>,backup:bool)->Result<()>{
        if !self.selected||self.apply||action>2||missing.len()>11{return Err(Fault::Phase)}
        self.apply=true;self.action=action;self.m=missing.len() as u32;self.backup=backup;self.missing=missing;
        if action==0{return Ok(())}
        let j=self.add(keys,Role::Journal,0,".mobile-release-metadata-text-prepare",0,NONE)?;self.journal=Some(j);
        for (role,name,limit) in [(Role::Header,"header.tmp",524288),(Role::Plan,"plan.tmp",524288),
            (Role::Commit,"commit.pending",524288),(Role::Rollback,"rollback.pending",524288),
            (Role::ProbeA,"probe-a",0),(Role::ProbeB,"probe-b",0)] {self.add(keys,role,j,name,limit,NONE)?;}
        let cap=self.rows[self.selected_row.ok_or(Fault::Phase)?].limit;
        self.new_note=Some(self.add(keys,Role::NewNote,j,"new-0",cap,NONE)?);Ok(())
    }
    pub fn logical_table(&self)->Vec<u8>{
        batch(self.rows.iter().map(|r|{
            let flags=u32::from(r.role.directory())|u32::from(r.role.source())*2|
                u32::from(r.role.created()||self.missing.iter().any(|i|self.rows[*i].key==r.key))*4|
                u32::from(r.role.created()||r.role==Role::Selected)*8|
                u32::from(r.role.control()||r.role==Role::NewNote)*16|
                u32::from(r.role.directory()&&r.role!=Role::OptionalMeta)*32|
                u32::from(matches!(r.role,Role::OptionalMeta|Role::Parent|Role::Selected|Role::Counterpart))*64;
            let mut b=Vec::new();u32s(&mut b,&[(56+r.path.len()+r.name.len()) as u32,r.role as u32]);
            u64s(&mut b,&[r.key,r.parent.map_or(0,|i|self.rows[i].key),r.limit]);
            u32s(&mut b,&[flags,r.ancestor,r.path.len() as u32,r.name.len() as u32]);u64s(&mut b,&[r.stable_security]);
            b.extend_from_slice(r.path.as_bytes());b.extend_from_slice(r.name.as_bytes());b
        }).collect())
    }
    pub fn move_table(&self)->Vec<u8>{batch(self.moves.iter().map(|m|{
        let mut b=Vec::new();u64s(&mut b,&[m.key,self.rows[m.row].key,m.object,self.rows[m.from.parent].key,
            self.rows[m.to.parent].key,m.inverse,m.forward,m.private_transition,m.publish_transition]);
        u32s(&mut b,&[m.from.name.len() as u32,m.to.name.len() as u32,m.kind,m.flags]);
        b.extend_from_slice(m.from.name.as_bytes());b.extend_from_slice(m.to.name.as_bytes());b}).collect())}
    pub fn delete_table(&self)->Vec<u8>{batch(self.deletes.iter().map(|d|{
        let mut b=Vec::new();u64s(&mut b,&[d.key,self.rows[d.row].key,d.object]);u32s(&mut b,&[d.kind,d.edges.len() as u32]);
        for e in &d.edges{u64s(&mut b,&[self.rows[e.parent].key]);u32s(&mut b,&[e.name.len() as u32,0]);b.extend_from_slice(e.name.as_bytes());}b}).collect())}
    pub fn transition_table(&self)->Vec<u8>{batch(self.transitions.iter().map(|t|{
        let mut b=Vec::new();u64s(&mut b,&[t.key,self.rows[t.row].key,t.object,t.paired,t.movement,t.policy,t.stable]);
        u32s(&mut b,&[t.purpose,t.order]);b}).collect())}
    pub fn heap(&self)->usize{
        std::mem::size_of::<Self>()+self.rows.capacity()*std::mem::size_of::<Logical>()+
            self.rows.iter().map(|r|r.path.capacity()+r.name.capacity()).sum::<usize>()+
            self.moves.capacity()*std::mem::size_of::<Movement>()+
            self.moves.iter().map(|m|m.from.name.capacity()+m.to.name.capacity()).sum::<usize>()+
            self.deletes.capacity()*std::mem::size_of::<Deletion>()+
            self.deletes.iter().map(|d|d.edges.capacity()*std::mem::size_of::<Edge>()+d.edges.iter().map(|e|e.name.capacity()).sum::<usize>()).sum::<usize>()+
            self.transitions.capacity()*std::mem::size_of::<Transition>()+self.missing.capacity()*std::mem::size_of::<usize>()
    }
}
pub(super) fn u32s(out:&mut Vec<u8>,values:&[u32]){for n in values{out.extend_from_slice(&n.to_le_bytes());}}
pub(super) fn u64s(out:&mut Vec<u8>,values:&[u64]){for n in values{out.extend_from_slice(&n.to_le_bytes());}}
pub(super) fn batch(rows:Vec<Vec<u8>>)->Vec<u8>{
    let total=8+rows.iter().map(|r|4+r.len()).sum::<usize>();let mut out=Vec::with_capacity(total);
    u32s(&mut out,&[rows.len() as u32,total as u32]);for row in rows{u32s(&mut out,&[row.len() as u32]);out.extend_from_slice(&row);}out
}
