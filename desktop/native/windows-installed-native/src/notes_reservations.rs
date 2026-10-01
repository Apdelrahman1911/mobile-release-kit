//! Notes-only precharged resource ledger. DATA, not a native execution log.
//! The sixteen rows are cumulative credits actually allocated by this owner;
//! unused credits are forfeited, never refunded, reset or moved between pools.
//! A credit is permission to attempt bounded work, NOT proof that a future native
//! call returns, that a complete pass succeeds, or that a transaction completes.
use super::{wire::{Fault,Result},namespace::{batch,u32s,u64s}};
pub(super) const TICKETS:usize=4608;
pub(super) const CLAIMS:usize=512;
pub(super) const STAGES:usize=16;
#[derive(Clone,Copy,Default,Debug,Eq,PartialEq)]
pub(super) struct Credit {
    pub passes:u64,pub frames:u64,pub checks:u64,pub acquisitions:u64,pub records:u64,
    pub calls:u64,pub bytes:u64,pub entries:u64,pub heap:u64,
}
impl Credit {
    pub const ZERO:Self=Self{passes:0,frames:0,checks:0,acquisitions:0,records:0,calls:0,bytes:0,entries:0,heap:0};
    pub fn add(self,b:Self)->Result<Self>{
        macro_rules! plus{($f:ident)=>{self.$f.checked_add(b.$f).ok_or(Fault::Capacity)?}}
        Ok(Self{passes:plus!(passes),frames:plus!(frames),checks:plus!(checks),
            acquisitions:plus!(acquisitions),records:plus!(records),calls:plus!(calls),
            bytes:plus!(bytes),entries:plus!(entries),heap:plus!(heap)})
    }
    pub fn times(self,n:u64)->Result<Self>{
        macro_rules! mul{($f:ident)=>{self.$f.checked_mul(n).ok_or(Fault::Capacity)?}}
        Ok(Self{passes:mul!(passes),frames:mul!(frames),checks:mul!(checks),
            acquisitions:mul!(acquisitions),records:mul!(records),calls:mul!(calls),
            bytes:mul!(bytes),entries:mul!(entries),heap:mul!(heap)})
    }
    pub fn fits(self,b:Self)->bool{
        self.passes>=b.passes&&self.frames>=b.frames&&self.checks>=b.checks&&
            self.acquisitions>=b.acquisitions&&self.records>=b.records&&self.calls>=b.calls&&
            self.bytes>=b.bytes&&self.entries>=b.entries&&self.heap>=b.heap
    }
    pub fn take(&mut self,b:Self)->Result<()>{
        if !self.fits(b){return Err(Fault::Capacity)}
        self.passes-=b.passes;self.frames-=b.frames;self.checks-=b.checks;
        self.acquisitions-=b.acquisitions;self.records-=b.records;self.calls-=b.calls;
        self.bytes-=b.bytes;self.entries-=b.entries;self.heap-=b.heap;Ok(())
    }
}
pub(super) fn pool(stage:u32)->Result<usize>{
    match stage{1..=12=>Ok(0),13..=15=>Ok(1),16=>Ok(2),_=>Err(Fault::Phase)}
}
#[derive(Clone)]
pub(super) struct Ledger {rows:[Credit;STAGES]}
impl Ledger {
    pub fn new()->Self{Self{rows:[Credit::ZERO;STAGES]}}
    fn checked(rows:[Credit;STAGES])->Result<Self>{
        let mut sums=[Credit::ZERO;3];let mut total=Credit::ZERO;
        for (at,value) in rows.iter().enumerate(){
            let p=pool(at as u32+1)?;
            if p==2&&(value.passes!=0||value.frames!=0||value.checks!=0||value.acquisitions!=0||
                value.records!=0||value.bytes!=0||value.entries!=0){return Err(Fault::Phase)}
            sums[p]=sums[p].add(*value)?;total=total.add(*value)?;
        }
        for (at,s) in sums.iter().enumerate(){
            if s.calls>if at==2{1024}else{65536}||
                s.frames>32768||s.passes>2048||s.checks>7680||s.bytes>536_870_912{return Err(Fault::Capacity)}
        }
        if total.acquisitions>154||total.records>32768||total.entries>524_288||
            total.heap>33_554_432||total.calls>132_096{return Err(Fault::Capacity)}
        Ok(Self{rows})
    }
    /// All-or-nothing reservation of the producer group AND its separately bound
    /// recovery/close/finality group. No mutation occurs on a refused admission.
    pub fn reserve(&mut self,requests:&[(u32,Credit)])->Result<()>{
        let mut rows=self.rows;
        for (stage,amount) in requests{
            pool(*stage)?;let at=(*stage-1) as usize;rows[at]=rows[at].add(*amount)?;
        }
        *self=Self::checked(rows)?;Ok(())
    }
    pub fn total(&self)->Result<Credit>{
        self.rows.iter().try_fold(Credit::ZERO,|sum,value|sum.add(*value))
    }
    pub fn native_frames(&self)->Result<[u32;2]>{
        let mut out=[0;2];
        for (i,r) in self.rows.iter().enumerate(){
            let p=pool(i as u32+1)?;if p<2{out[p]+=r.frames as u32;}
        }Ok(out)
    }
    pub fn table(&self)->Vec<u8>{
        batch(self.rows.iter().enumerate().map(|(at,v)|{
            let mut b=Vec::with_capacity(64);
            // checked() bounds every conversion. The final word is reserved0;
            // heap is held native resident-growth credit, not a per-call echo
            // of the shared helper or a claim about completed execution.
            u32s(&mut b,&[at as u32+1,if at<12{1}else if at<15{2}else{3},
                v.passes as u32,v.frames as u32,v.checks as u32,
                v.acquisitions as u32,v.records as u32,v.calls as u32]);
            u64s(&mut b,&[v.bytes,v.entries,v.heap,0]);b
        }).collect())
    }
}

/// A closed native-only selector. `original` is an original object/effect/data key,
/// never a caller-selected path or a newly minted bridge scheduling token.
/// `step` separates a mandatory raw suffix, a broad POST, and protected
/// recovery lead-in even when they read the same original.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub(super) struct Selector {pub operation:u32,pub original:u64,pub step:u32}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub(super) struct PassBound {
    pub bytes:u64,pub entries:u32,pub native_calls:u32,pub observations:u32,
}
impl PassBound {
    pub fn file(bytes:u64,observations:u32)->Result<Self>{
        let chunks=bytes.checked_add(65535).ok_or(Fault::Capacity)?/65536;
        Ok(Self{bytes,entries:0,native_calls:u32::try_from(chunks+2).map_err(|_|Fault::Capacity)?,observations})
    }
    pub fn roster(entries:u32,observations:u32)->Result<Self>{
        if entries>128{return Err(Fault::Capacity)}
        Ok(Self{bytes:0,entries,native_calls:entries+3,observations})
    }
}
#[derive(Clone)]
pub(super) struct Claim {
    pub selector:Selector,pub count:u32,pub unit:Credit,pub pass:Option<PassBound>,
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub(super) enum Purpose {Ordinary,Create,Move,Inverse,Delete,RecoveryPrelude,FinalExit,Factory,Finality}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub(super) struct Binding {
    pub scope:u32,pub purpose:Purpose,pub cause:u64,pub object:u64,pub from:u64,pub to:u64,
}
pub(super) struct Plan {pub binding:Binding,pub stage:u32,pub claims:Vec<Claim>}
impl Plan {
    pub fn new(binding:Binding,stage:u32)->Result<Self>{
        pool(stage)?;Ok(Self{binding,stage,claims:Vec::new()})
    }
    pub fn push(&mut self,selector:Selector,count:u32,unit:Credit,pass:Option<PassBound>)->Result<()>{
        if count==0{return Ok(())}
        if selector.original==0||!(1..=42).contains(&selector.operation)||selector.step>8{return Err(Fault::Key)}
        if self.claims.len()>=CLAIMS||self.claims.iter().any(|c|c.selector==selector){return Err(Fault::Capacity)}
        self.claims.try_reserve_exact(1).map_err(|_|Fault::Capacity)?;
        self.claims.push(Claim{selector,count,unit,pass});Ok(())
    }
    pub fn amount(&self)->Result<Credit>{
        let mut out=Credit{heap:(self.claims.capacity()*std::mem::size_of::<Claim>()) as u64,..Credit::ZERO};
        for c in &self.claims{out=out.add(c.unit.times(u64::from(c.count))?)?;}
        Ok(out)
    }
}
struct Ticket {binding:Binding,stage:u32,claims:Vec<Claim>,closed:bool}
/// The one-use descendant of exactly one admitted claim. The context retains this
/// value across ABI returns for a real pass. There is no put-back/refill API.
pub(super) struct Unit {
    pub ticket:usize,pub binding:Binding,pub selector:Selector,pub stage:u32,
    pub credit:Credit,pub pass:Option<PassBound>,
}
pub(super) struct Tickets {values:Vec<Ticket>}
impl Tickets {
    pub fn new()->Result<Self>{
        let mut values=Vec::new();values.try_reserve_exact(TICKETS).map_err(|_|Fault::Capacity)?;
        Ok(Self{values})
    }
    pub fn heap(&self)->usize{
        self.values.capacity()*std::mem::size_of::<Ticket>()+
            self.values.iter().map(|t|t.claims.capacity()*std::mem::size_of::<Claim>()).sum::<usize>()
    }
    /// No producer is admitted unless every requested corrective/cleanup/finality
    /// ticket fits atomically. All fallible storage allocation precedes ledger
    /// commit. The original total budgets and previously allocated rows persist.
    pub fn admit(&mut self,ledger:&mut Ledger,plans:Vec<Plan>)->Result<Vec<usize>>{
        if plans.is_empty()||self.values.len().checked_add(plans.len()).is_none_or(|n|n>TICKETS){return Err(Fault::Capacity)}
        for (n,p) in plans.iter().enumerate(){
            if p.binding.cause==0||p.binding.object==0||p.binding.scope>3||
                self.values.iter().any(|t|t.binding==p.binding)||
                plans[..n].iter().any(|q|q.binding==p.binding){return Err(Fault::OneUse)}
        }
        let mut reservations=Vec::new();reservations.try_reserve_exact(plans.len()).map_err(|_|Fault::Capacity)?;
        let mut indices=Vec::new();indices.try_reserve_exact(plans.len()).map_err(|_|Fault::Capacity)?;
        for p in &plans{reservations.push((p.stage,p.amount()?));}
        // Vec capacity was installed with this original owner, before native
        // acquisitions. Push cannot reallocate or fail after the atomic commit.
        ledger.reserve(&reservations)?;
        for p in plans{
            indices.push(self.values.len());
            self.values.push(Ticket{binding:p.binding,stage:p.stage,claims:p.claims,closed:false});
        }Ok(indices)
    }
    pub fn find(&self,binding:Binding)->Option<usize>{
        self.values.iter().position(|t|!t.closed&&t.binding==binding)
    }
    pub fn stage(&self,ticket:usize)->Result<u32>{
        self.values.get(ticket).filter(|t|!t.closed).map(|t|t.stage).ok_or(Fault::Key)
    }
    pub fn binding(&self,ticket:usize)->Result<Binding>{
        self.values.get(ticket).filter(|t|!t.closed).map(|t|t.binding).ok_or(Fault::Key)
    }
    pub fn available(&self,ticket:usize,selector:Selector)->bool{
        self.values.get(ticket).is_some_and(|t|!t.closed&&t.claims.iter().any(|c|c.selector==selector&&c.count!=0))
    }
    pub fn take(&mut self,ticket:usize,binding:Binding,selector:Selector)->Result<Unit>{
        let t=self.values.get_mut(ticket).ok_or(Fault::Key)?;
        if t.closed||t.binding!=binding{return Err(Fault::Stale)}
        let c=t.claims.iter_mut().find(|c|c.selector==selector).ok_or(Fault::Key)?;
        if c.count==0{return Err(Fault::Capacity)}
        c.count-=1;
        Ok(Unit{ticket,binding,selector,stage:t.stage,credit:c.unit,pass:c.pass})
    }
    pub fn count(&self,ticket:usize,selector:Selector)->Result<u32>{
        let t=self.values.get(ticket).ok_or(Fault::Key)?;
        if t.closed{return Err(Fault::OneUse)}
        Ok(t.claims.iter().find(|c|c.selector==selector).map_or(0,|c|c.count))
    }
    pub fn remaining(&self,ticket:usize,step:u32)->Result<u32>{
        let t=self.values.get(ticket).ok_or(Fault::Key)?;
        if t.closed{return Err(Fault::OneUse)}
        t.claims.iter().filter(|c|c.selector.step==step).try_fold(0u32,|n,c|n.checked_add(c.count).ok_or(Fault::Capacity))
    }
    pub fn close(&mut self,ticket:usize,binding:Binding)->Result<()>{
        let t=self.values.get_mut(ticket).ok_or(Fault::Key)?;
        if t.closed||t.binding!=binding{return Err(Fault::OneUse)}
        // Unused rows remain allocated in Ledger forever. Closing a logical
        // group never returns its credits to another cause or another pool.
        t.closed=true;Ok(())
    }
}
#[cfg(test)]
mod tests{
    use super::*;
    fn binding(cause:u64,purpose:Purpose)->Binding{
        Binding{scope:3,purpose,cause,object:7,from:8,to:9}
    }
    fn plan(cause:u64,stage:u32,frames:u64)->Plan{
        let mut p=Plan::new(binding(cause,if stage<13{Purpose::Move}else{Purpose::Inverse}),stage).unwrap();
        p.push(Selector{operation:26,original:cause,step:0},1,
            Credit{frames,calls:1,..Credit::ZERO},None).unwrap();p
    }
    #[test]fn producer_and_its_recovery_are_admitted_atomically(){
        let mut ledger=Ledger::new();let mut tickets=Tickets::new().unwrap();
        ledger.reserve(&[(1,Credit{frames:32767,..Credit::ZERO})]).unwrap();
        let before=ledger.table();
        assert_eq!(tickets.admit(&mut ledger,vec![plan(1,7,2),plan(2,13,20)]).err(),Some(Fault::Capacity));
        assert_eq!(ledger.table(),before);assert!(tickets.values.is_empty());
    }
    #[test]fn scope_cause_original_and_step_cannot_be_swapped(){
        let mut ledger=Ledger::new();let mut tickets=Tickets::new().unwrap();
        let selected=tickets.admit(&mut ledger,vec![plan(1,7,20),plan(2,13,20)]).unwrap();
        let s=Selector{operation:26,original:1,step:0};
        assert!(tickets.take(selected[0],binding(2,Purpose::Move),s).is_err());
        assert!(tickets.take(selected[0],binding(1,Purpose::Move),Selector{step:1,..s}).is_err());
        let u=tickets.take(selected[0],binding(1,Purpose::Move),s).unwrap();
        assert_eq!(u.stage,7);assert_eq!(u.credit.frames,20);
        assert!(tickets.take(selected[0],binding(1,Purpose::Move),s).is_err());
        assert!(tickets.available(selected[1],Selector{original:2,..s}));
    }
    #[test]fn unused_closed_credits_are_never_refunded(){
        let mut ledger=Ledger::new();let mut tickets=Tickets::new().unwrap();
        let ids=tickets.admit(&mut ledger,vec![plan(1,7,32768)]).unwrap();
        let before=ledger.table();tickets.close(ids[0],binding(1,Purpose::Move)).unwrap();
        assert_eq!(ledger.table(),before);
        assert!(tickets.admit(&mut ledger,vec![plan(2,7,1)]).is_err());
    }
    #[test]fn progress_caps_are_attempt_bounds_not_fake_eof(){
        assert_eq!(PassBound::file(65536,1).unwrap().native_calls,3);
        assert_eq!(PassBound::file(0,1).unwrap().native_calls,2);
        assert_eq!(PassBound::roster(0,1).unwrap().native_calls,3);
        assert!(PassBound::roster(129,1).is_err());
    }
    #[test]fn page6_is_sixteen_actual_ordered_snapshot_rows(){
        let mut ledger=Ledger::new();
        ledger.reserve(&[(7,Credit{passes:3,frames:400,calls:14,..Credit::ZERO})]).unwrap();
        let raw=ledger.table();
        assert_eq!(u32::from_le_bytes(raw[..4].try_into().unwrap()),16);
        assert_eq!(raw.len(),8+16*(4+64));
        for at in 0..16{
            let start=8+at*68;assert_eq!(u32::from_le_bytes(raw[start..start+4].try_into().unwrap()),64);
            assert_eq!(u32::from_le_bytes(raw[start+4..start+8].try_into().unwrap()),at as u32+1);
        }
        let row7=8+6*68+4;
        assert_eq!(u32::from_le_bytes(raw[row7+8..row7+12].try_into().unwrap()),3);
    }

    #[test]fn a_whole_pass_keeps_the_same_one_use_unit_across_returns(){
        let mut ledger=Ledger::new();let mut tickets=Tickets::new().unwrap();
        let b=binding(31,Purpose::Ordinary);
        let s=Selector{operation:10,original:b.object,step:0};
        let bound=PassBound::file(3,1).unwrap();
        let allocation=Credit{passes:1,frames:5,checks:2,calls:5,bytes:4,heap:64,..Credit::ZERO};
        let mut p=Plan::new(b,2).unwrap();p.push(s,1,allocation,Some(bound)).unwrap();
        let id=tickets.admit(&mut ledger,vec![p]).unwrap()[0];
        let allocated=ledger.table();
        let mut retained=Some(tickets.take(id,b,s).unwrap());
        // These are DATA debits, not simulated native successes or EOF facts.
        for debit in [
            Credit{passes:1,frames:1,checks:1,calls:1,..Credit::ZERO},
            Credit{frames:1,calls:1,bytes:2,..Credit::ZERO},
            Credit{frames:1,calls:1,bytes:1,..Credit::ZERO},
            Credit{frames:1,checks:1,calls:1,..Credit::ZERO},
            Credit{frames:1,calls:1,..Credit::ZERO},
        ]{
            let mut unit=retained.take().unwrap();
            assert_eq!(unit.ticket,id);assert_eq!(unit.binding,b);
            assert_eq!(unit.selector,s);assert_eq!(unit.stage,2);assert_eq!(unit.pass,Some(bound));
            unit.credit.take(debit).unwrap();
            assert!(!tickets.available(id,s));
            assert_eq!(tickets.take(id,b,s).err(),Some(Fault::Capacity));
            retained=Some(unit);
        }
        let mut unit=retained.take().unwrap();
        assert_eq!(unit.credit.calls,0);assert_eq!(unit.credit.frames,0);
        assert_eq!(unit.credit.passes,0);assert_eq!(unit.credit.bytes,1);
        assert_eq!(unit.credit.take(Credit{calls:1,..Credit::ZERO}),Err(Fault::Capacity));
        assert_eq!(ledger.table(),allocated);
    }
    #[test]fn credit_refusal_is_atomic_and_spare_dimensions_cannot_substitute(){
        let mut credit=Credit{frames:8,calls:1,bytes:12,..Credit::ZERO};
        let before=credit;
        assert_eq!(credit.take(Credit{frames:1,calls:2,..Credit::ZERO}),Err(Fault::Capacity));
        assert_eq!(credit,before);
        assert_eq!(credit.take(Credit{checks:1,..Credit::ZERO}),Err(Fault::Capacity));
        assert_eq!(credit,before);
    }
    #[test]fn exhausting_producer_never_borrows_recovery_or_finality(){
        let mut ledger=Ledger::new();
        ledger.reserve(&[(1,Credit{calls:65536,..Credit::ZERO})]).unwrap();
        let before=ledger.table();
        assert_eq!(ledger.reserve(&[(12,Credit{calls:1,..Credit::ZERO})]),Err(Fault::Capacity));
        assert_eq!(ledger.table(),before);
        ledger.reserve(&[(13,Credit{calls:65536,..Credit::ZERO}),
            (16,Credit{calls:1024,..Credit::ZERO})]).unwrap();
        assert_eq!(ledger.total().unwrap().calls,132096);
        let full=ledger.table();
        for stage in [1,13,16]{
            assert_eq!(ledger.reserve(&[(stage,Credit{calls:1,..Credit::ZERO})]),Err(Fault::Capacity));
            assert_eq!(ledger.table(),full);
        }
    }
    #[test]fn finality_owns_only_calls_and_heap_not_native_work(){
        let mut ledger=Ledger::new();
        ledger.reserve(&[(16,Credit{calls:1,heap:64,..Credit::ZERO})]).unwrap();
        let before=ledger.table();
        for denied in [
            Credit{passes:1,..Credit::ZERO},Credit{frames:1,..Credit::ZERO},
            Credit{checks:1,..Credit::ZERO},Credit{acquisitions:1,..Credit::ZERO},
            Credit{records:1,..Credit::ZERO},Credit{bytes:1,..Credit::ZERO},
            Credit{entries:1,..Credit::ZERO},
        ]{
            assert_eq!(ledger.reserve(&[(16,denied)]),Err(Fault::Phase));
            assert_eq!(ledger.table(),before);
        }
        assert_eq!(pool(0),Err(Fault::Phase));assert_eq!(pool(17),Err(Fault::Phase));
    }
    #[test]fn selectors_reject_unbound_originals_and_outside_operations_or_steps(){
        let mut p=Plan::new(binding(41,Purpose::Ordinary),2).unwrap();
        let s=Selector{operation:10,original:7,step:0};
        for denied in [
            Selector{original:0,..s},Selector{operation:0,..s},
            Selector{operation:43,..s},Selector{step:9,..s},
        ]{
            assert_eq!(p.push(denied,1,Credit{calls:1,..Credit::ZERO},None),Err(Fault::Key));
        }
        assert!(p.claims.is_empty());
    }
}
