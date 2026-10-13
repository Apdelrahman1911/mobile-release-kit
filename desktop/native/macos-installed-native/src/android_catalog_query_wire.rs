//! Closed read-only Android query DATA. No path/UID/FD/tool/worker authority.
//! This file is native-independent so its DATA regressions can run locally.
pub const REQUEST_BYTES: usize = 128;
pub const CONTROL_BYTES: usize = 256;
pub const PAYLOAD_BYTES: usize = 8192;
pub const REPLY_BYTES: usize = CONTROL_BYTES + PAYLOAD_BYTES;
pub const ENTRY_LIMIT: usize = 32;
pub const MAX_RAW: u64 = (1_u64 << 61) - 1;
pub const CLEANUP_NS: u64 = 10_000_000_000;
const REQUEST_MAGIC: &[u8;8] = b"MRKAQ001";
const REPLY_MAGIC: &[u8;8] = b"MRKAQR01";

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[repr(u32)]
pub enum Role { Catalog=1, Start=2 }
impl Role {
    fn decode(v:u32)->Option<Self>{match v{1=>Some(Self::Catalog),2=>Some(Self::Start),_=>None}}
    pub fn work_ns(self)->u64 {match self{Self::Catalog=>60_000_000_000,Self::Start=>3_000_000_000_000}}
    pub fn hard_ns(self)->u64 {self.work_ns()+CLEANUP_NS}
    pub fn sequence_limit(self)->u32 {match self{Self::Catalog=>34,Self::Start=>2}}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Bounds {pub role:Role,pub origin:u64,pub work:u64,pub hard:u64}
impl Bounds {
    pub fn valid(self)->bool{
        self.origin!=0 && self.hard<=MAX_RAW
            && self.origin.checked_add(self.role.work_ns())==Some(self.work)
            && self.origin.checked_add(self.role.hard_ns())==Some(self.hard)
    }
    pub fn accepts_event(self,event:u64,now:u64,last:u64)->bool {
        self.valid() && now>=last && now>=self.origin && now<=MAX_RAW
            && event>=self.origin && event<=now
    }
    pub fn cleanup(self,first:Option<u64>)->Option<u64>{
        if !self.valid(){return None;}
        match first {None=>Some(self.hard),Some(at) if at>=self.origin && at<=MAX_RAW=>
            at.checked_add(CLEANUP_NS).map(|end|end.min(self.hard)),_=>None}
    }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[repr(u32)]
pub enum Kind { Scan=1, ReadIntent=2, Finish=3, Status=4, Stop=5 }
impl Kind {
    fn decode(v:u32)->Option<Self>{match v{1=>Some(Self::Scan),2=>Some(Self::ReadIntent),
        3=>Some(Self::Finish),4=>Some(Self::Status),5=>Some(Self::Stop),_=>None}}
    pub fn work(self)->bool{matches!(self,Self::Scan|Self::ReadIntent|Self::Finish)}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Request {
    pub bounds:Bounds,pub kind:Kind,pub sequence:u32,pub nonce:[u8;16],
    pub instance:[u8;16],pub first:u64,
}
fn word(raw:&[u8],at:usize)->u32{u32::from_be_bytes(raw[at..at+4].try_into().expect("fixed word"))}
fn wide(raw:&[u8],at:usize)->u64{u64::from_be_bytes(raw[at..at+8].try_into().expect("fixed wide"))}
fn put(raw:&mut[u8],at:usize,value:u32){raw[at..at+4].copy_from_slice(&value.to_be_bytes());}
fn big(raw:&mut[u8],at:usize,value:u64){raw[at..at+8].copy_from_slice(&value.to_be_bytes());}
impl Request {
    pub fn valid(self)->bool{
        if !self.bounds.valid() || self.nonce==[0;16] {return false;}
        if self.kind.work() {
            if self.sequence==0 || self.sequence>self.bounds.role.sequence_limit() || self.first!=0{return false;}
        }else if self.sequence!=0{return false;}
        if self.kind==Kind::ReadIntent {
            if self.instance==[0;16]{return false;}
        }else if self.instance!=[0;16]{return false;}
        match self.kind {
            Kind::Scan=>self.bounds.role==Role::Catalog && self.sequence==1,
            Kind::ReadIntent=>match self.bounds.role{Role::Start=>self.sequence==1,Role::Catalog=>self.sequence>=2 && self.sequence<self.bounds.role.sequence_limit()},
            Kind::Finish=>self.sequence>=2,
            Kind::Status=>self.first==0,
            Kind::Stop=>self.first>=self.bounds.origin && self.first<=MAX_RAW,
        }
    }
    pub fn encode(self)->Option<[u8;REQUEST_BYTES]>{
        if !self.valid(){return None;}
        let mut raw=[0;REQUEST_BYTES];raw[..8].copy_from_slice(REQUEST_MAGIC);
        for(at,v)in[(8,1),(12,self.kind as u32),(16,self.bounds.role as u32),(20,self.sequence)]{put(&mut raw,at,v);}
        raw[24..40].copy_from_slice(&self.nonce);
        for(at,v)in[(40,self.bounds.origin),(48,self.bounds.work),(56,self.bounds.hard),(80,self.first)]{big(&mut raw,at,v);}
        raw[64..80].copy_from_slice(&self.instance);Some(raw)
    }
    pub fn decode(raw:&[u8])->Option<Self>{
        if raw.len()!=REQUEST_BYTES || &raw[..8]!=REQUEST_MAGIC || word(raw,8)!=1
            || raw[88..].iter().any(|v|*v!=0){return None;}
        let item=Self{kind:Kind::decode(word(raw,12))?,sequence:word(raw,20),
            bounds:Bounds{role:Role::decode(word(raw,16))?,origin:wide(raw,40),work:wide(raw,48),hard:wide(raw,56)},
            nonce:raw[24..40].try_into().ok()?,instance:raw[64..80].try_into().ok()?,first:wide(raw,80)};
        item.valid().then_some(item)
    }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[repr(u32)]
pub enum Phase { Working=1,Candidate=2,InputClosed=3,Complete=4,Refused=5,Busy=6,Unknown=7 }
impl Phase {
    fn decode(v:u32)->Option<Self>{match v{1=>Some(Self::Working),2=>Some(Self::Candidate),
        3=>Some(Self::InputClosed),4=>Some(Self::Complete),5=>Some(Self::Refused),
        6=>Some(Self::Busy),7=>Some(Self::Unknown),_=>None}}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[repr(u32)]
pub enum Payload { None=0,Scan=1,Intent=2 }
impl Payload {fn decode(v:u32)->Option<Self>{match v{0=>Some(Self::None),1=>Some(Self::Scan),2=>Some(Self::Intent),_=>None}}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[repr(u32)]
pub enum EntryCode { Observed=0,Busy=1,Interrupted=2,Refused=3 }
impl EntryCode {fn decode(v:u32)->Option<Self>{match v{0=>Some(Self::Observed),1=>Some(Self::Busy),
    2=>Some(Self::Interrupted),3=>Some(Self::Refused),_=>None}}}
/// Only fixed destination/stage/quarantine presence. Unknown is not absence.
#[derive(Clone,Copy,Debug,Default,PartialEq,Eq)]
pub struct Presence {pub known:u8,pub present:u8}
impl Presence {
    pub const DESTINATION:u8=1;pub const STAGE:u8=2;pub const QUARANTINE:u8=4;
    pub fn valid(self)->bool{self.known&!7==0 && self.present&!self.known==0}
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct Reply {
    pub bounds:Bounds,pub phase:Phase,pub account:u32,pub nonce:[u8;16],
    pub processed:u32,pub enqueued:u32,pub payload:Payload,pub code:EntryCode,
    pub instance:[u8;16],pub first:Option<u64>,pub cleanup:Option<u64>,
    pub unknown:bool,pub joined:bool,pub presence:Presence,pub bytes:Vec<u8>,
}
impl Reply {
    pub fn valid(&self)->bool{
        if !self.bounds.valid() || self.account==0 || self.account==u32::MAX || self.nonce==[0;16]
            || self.enqueued>self.bounds.role.sequence_limit() || self.processed>self.enqueued
            || self.enqueued-self.processed>1
            || self.bytes.len()>PAYLOAD_BYTES || !self.presence.valid()
            || self.first.is_some_and(|at|at<self.bounds.origin || at>MAX_RAW)
            || self.cleanup!=self.bounds.cleanup(self.first) && !(self.unknown && self.cleanup.is_none())
            || self.phase==Phase::Complete && (!self.joined || self.unknown || self.first.is_some())
            || self.joined && (!matches!(self.phase,Phase::Complete|Phase::Refused|Phase::Unknown) || self.payload!=Payload::None)
            || self.payload!=Payload::None && !matches!(self.phase,Phase::Candidate|Phase::Unknown)
            || self.phase==Phase::Candidate && (self.processed==0 || self.processed!=self.enqueued)
            || self.phase==Phase::Complete && self.processed!=self.enqueued
        {return false;}
        match self.payload {
            Payload::None=>self.bytes.is_empty() && self.instance==[0;16]
                && self.code==EntryCode::Observed && self.presence==Presence::default(),
            Payload::Scan=>self.instance==[0;16] && self.code==EntryCode::Observed
                && self.bounds.role==Role::Catalog && decode_scan(&self.bytes).is_some(),
            Payload::Intent=>self.instance!=[0;16] && match self.code{
                EntryCode::Observed=>!self.bytes.is_empty() && self.presence.known==7,
                _=>self.bytes.is_empty(),
            },
        }
    }
    pub fn encode(&self)->Option<[u8;REPLY_BYTES]>{
        if !self.valid(){return None;}
        let mut raw=[0;REPLY_BYTES];raw[..8].copy_from_slice(REPLY_MAGIC);
        for(at,v)in[(8,1),(12,self.phase as u32),(16,self.bounds.role as u32),(20,self.account),
            (64,self.processed),(68,self.payload as u32),(72,self.bytes.len() as u32),(76,self.code as u32),
            (112,u32::from(self.unknown)),(116,u32::from(self.joined)),(120,u32::from(self.presence.known)|(u32::from(self.presence.present)<<8)),
            (124,self.enqueued)]{put(&mut raw,at,v);}
        raw[24..40].copy_from_slice(&self.nonce);raw[80..96].copy_from_slice(&self.instance);
        for(at,v)in[(40,self.bounds.origin),(48,self.bounds.work),(56,self.bounds.hard),
            (96,self.first.unwrap_or(0)),(104,self.cleanup.unwrap_or(0))]{big(&mut raw,at,v);}
        raw[CONTROL_BYTES..CONTROL_BYTES+self.bytes.len()].copy_from_slice(&self.bytes);Some(raw)
    }
    pub fn decode(raw:&[u8])->Option<Self>{
        if raw.len()!=REPLY_BYTES || &raw[..8]!=REPLY_MAGIC || word(raw,8)!=1
            || raw[128..CONTROL_BYTES].iter().any(|v|*v!=0)
            || word(raw,112)>1 || word(raw,116)>1 || word(raw,120)&0xffff0000!=0{return None;}
        let n=usize::try_from(word(raw,72)).ok()?;
        if n>PAYLOAD_BYTES || raw[CONTROL_BYTES+n..].iter().any(|v|*v!=0){return None;}
        let optional=|v|if v==0{None}else{Some(v)};
        let value=Self{bounds:Bounds{role:Role::decode(word(raw,16))?,origin:wide(raw,40),work:wide(raw,48),hard:wide(raw,56)},
            phase:Phase::decode(word(raw,12))?,account:word(raw,20),nonce:raw[24..40].try_into().ok()?,
            processed:word(raw,64),enqueued:word(raw,124),payload:Payload::decode(word(raw,68))?,
            code:EntryCode::decode(word(raw,76))?,instance:raw[80..96].try_into().ok()?,
            first:optional(wide(raw,96)),cleanup:optional(wide(raw,104)),unknown:word(raw,112)==1,
            joined:word(raw,116)==1,presence:Presence{known:word(raw,120)as u8,present:(word(raw,120)>>8)as u8},
            bytes:raw[CONTROL_BYTES..CONTROL_BYTES+n].to_vec()};
        value.valid().then_some(value)
    }
}
/// Scan contains names/types only; bits1/2/4 mean destination/lease/intent-root.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct ScanRow {pub instance:[u8;16],pub occupants:u8}
pub fn encode_scan(rows:&[ScanRow])->Option<Vec<u8>>{
    if rows.len()>ENTRY_LIMIT{return None;}
    let mut previous=None;
    let mut raw=vec![0;4+rows.len()*20];put(&mut raw,0,rows.len()as u32);
    for(index,row)in rows.iter().enumerate(){
        if row.instance==[0;16] || row.occupants==0 || row.occupants&!7!=0
            || previous.is_some_and(|v|v>=row.instance){return None;}
        previous=Some(row.instance);
        let at=4+index*20;raw[at..at+16].copy_from_slice(&row.instance);raw[at+16]=row.occupants;
    }Some(raw)
}
pub fn decode_scan(raw:&[u8])->Option<Vec<ScanRow>>{
    if raw.len()<4{return None;}let count=usize::try_from(word(raw,0)).ok()?;
    if count>ENTRY_LIMIT || raw.len()!=4+count*20{return None;}
    let mut rows=Vec::with_capacity(count);
    for index in 0..count{let at=4+index*20;if raw[at+17..at+20].iter().any(|v|*v!=0){return None;}
        rows.push(ScanRow{instance:raw[at..at+16].try_into().ok()?,occupants:raw[at+16]});}
    (encode_scan(&rows)?==raw).then_some(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bounds(role:Role)->Bounds{let origin=10;Bounds{role,origin,work:origin+role.work_ns(),hard:origin+role.hard_ns()}}
    fn request(role:Role,kind:Kind,sequence:u32)->Request{Request{bounds:bounds(role),kind,sequence,
        nonce:[1;16],instance:if kind==Kind::ReadIntent{[2;16]}else{[0;16]},first:0}}
    #[test]
    fn query_keeps_original_roles_clocks_and_closed_request_without_path_or_account(){
        for q in[request(Role::Catalog,Kind::Scan,1),request(Role::Start,Kind::ReadIntent,1),
            request(Role::Start,Kind::Finish,2)]{assert_eq!(Request::decode(&q.encode().unwrap()),Some(q));}
        assert!(request(Role::Start,Kind::Scan,1).encode().is_none());
        let mut q=request(Role::Catalog,Kind::Scan,1);q.bounds.work+=1;assert!(q.encode().is_none());
        q=request(Role::Catalog,Kind::Scan,1);let mut raw=q.encode().unwrap();raw[88]=1;
        assert!(Request::decode(&raw).is_none());
        q.sequence=0;assert!(q.encode().is_none());
        let b=bounds(Role::Start);assert!(b.accepts_event(10,15,14));
        assert!(!b.accepts_event(9,15,14));assert!(!b.accepts_event(16,15,14));assert!(!b.accepts_event(10,15,16));
        assert_eq!(b.cleanup(Some(10)),Some(10+CLEANUP_NS));
        assert_eq!(b.cleanup(Some(0)),None);
    }
    #[test]
    fn bounded_union_preserves_orphans_refuses_overflow_duplicates_and_aliases(){
        let rows=vec![ScanRow{instance:[1;16],occupants:1},ScanRow{instance:[2;16],occupants:2},
            ScanRow{instance:[3;16],occupants:4},ScanRow{instance:[4;16],occupants:7}];
        assert_eq!(decode_scan(&encode_scan(&rows).unwrap()),Some(rows.clone()));
        let mut duplicate=rows.clone();duplicate[1]=duplicate[0];assert!(encode_scan(&duplicate).is_none());
        let large=vec![rows[0];33];assert!(encode_scan(&large).is_none());
        let mut raw=encode_scan(&rows).unwrap();raw[23]=1;assert!(decode_scan(&raw).is_none());
    }
    #[test]
    fn candidate_bytes_join_and_unknown_presence_are_distinct_and_strict(){
        let mut r=Reply{bounds:bounds(Role::Start),phase:Phase::Candidate,account:501,nonce:[1;16],
            processed:1,enqueued:1,payload:Payload::Intent,code:EntryCode::Observed,instance:[2;16],
            first:None,cleanup:Some(bounds(Role::Start).hard),unknown:false,joined:false,
            presence:Presence{known:7,present:1},bytes:b"intent-candidate-data".to_vec()};
        assert_eq!(Reply::decode(&r.encode().unwrap()),Some(r.clone()));
        r.phase=Phase::Complete;assert!(r.encode().is_none());r.joined=true;assert!(r.encode().is_none());
        // Joined terminal cannot retain row bytes as if they were selection/H authority.
        r.payload=Payload::None;r.instance=[0;16];r.bytes.clear();r.presence=Presence::default();
        assert!(r.encode().is_some());
        r.unknown=true;assert!(r.encode().is_none());r.phase=Phase::Unknown;assert!(r.encode().is_some());
        r.presence=Presence{known:0,present:1};assert!(r.encode().is_none());
        r.joined=false;r.payload=Payload::Intent;r.instance=[2;16];
        r.presence=Presence::default();r.code=EntryCode::Interrupted;r.bytes.clear();
        let mut raw=r.encode().unwrap();raw[CONTROL_BYTES]=1;assert!(Reply::decode(&raw).is_none());
    }
}
