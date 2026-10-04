//! Closed maintenance comparison DATA. Decoding a genuine frame is not tail,
//! unregister, native-original or process-finality authority.
#![forbid(unsafe_code)]
pub const BYTES:usize=384;
pub const WORK_NS:u64=300_000_000_000;
pub const HARD_NS:u64=310_000_000_000;
pub const CLEANUP_NS:u64=10_000_000_000;
pub const MAX_RAW:u64=(1_u64<<61)-1;
const MAGIC:&[u8;8]=b"MRKMNT01";
const TARGET:&[u8]=b"aarch64-apple-darwin";
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Bounds{pub origin:u64,pub work:u64,pub hard:u64}
impl Bounds{
    pub fn valid(self)->bool{self.origin!=0 && self.hard<=MAX_RAW
        && self.work.checked_sub(self.origin)==Some(WORK_NS)
        && self.hard.checked_sub(self.origin)==Some(HARD_NS)}
    pub fn admits(self,now:u64)->bool{self.valid() && now>=self.origin && now<self.work}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Identity{pub instance:[u8;16],pub source:[u8;40],pub release:[u8;64],pub target:[u8;24]}
fn source_valid(source:&[u8;40])->bool{source.iter().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    && source.iter().any(|b|*b!=b'0')}
fn release_valid(release:&[u8;64])->bool{
    let end=release.iter().position(|b|*b==0).unwrap_or(64);
    end>0 && end<64 && release[end..].iter().all(|b|*b==0)
        && release[..end].iter().all(|b|b.is_ascii_alphanumeric() || matches!(*b,b'-'|b'_'|b'.'))
}
fn target_valid(target:&[u8;24])->bool{target[..TARGET.len()]==*TARGET
    && target[TARGET.len()..].iter().all(|b|*b==0)}
impl Identity{
    pub fn valid(self)->bool{self.instance!=[0;16] && source_valid(&self.source)
        && release_valid(&self.release) && target_valid(&self.target)}
    pub(crate) fn build()->Option<Self>{
        let source=option_env!("MRK_IMAGE_SOURCE_COMMIT")?.as_bytes();
        let release=option_env!("MRK_IMAGE_RELEASE_ID")?.as_bytes();
        if source.len()!=40 || release.is_empty() || release.len()>=64{return None;}
        let mut out=Self{instance:[0;16],source:source.try_into().ok()?,release:[0;64],target:[0;24]};
        out.release[..release.len()].copy_from_slice(release);out.target[..TARGET.len()].copy_from_slice(TARGET);
        (source_valid(&out.source) && release_valid(&out.release)).then_some(out)
    }
    pub fn same_build(self,other:Self)->bool{self.source==other.source && self.release==other.release && self.target==other.target}
}
/// Native fixed POD too; it carries DATA only, never FD/callback/native custody.
/// Encoding below is explicit BE, not a copy of this native representation.
#[repr(C)]
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Binding{
    pub version:u32,pub bytes:u32,pub instance:[u8;16],pub operation:[u8;16],pub nonce:[u8;16],
    pub number:u64,pub account:u32,pub slot:u32,pub acceptance:u64,
    pub origin:u64,pub work:u64,pub hard:u64,pub cut:u64,pub cutoff:u64,
    pub source:[u8;40],pub release:[u8;64],pub target:[u8;24],pub reserved:[u8;8],
}
const _:()=assert!(std::mem::size_of::<Binding>()==256);
impl Binding{
    pub fn request(identity:Identity,operation:[u8;16],bounds:Bounds)->Option<Self>{
        let value=Self{version:1,bytes:256,instance:[0;16],operation,nonce:[0;16],number:0,account:0,slot:0,
            acceptance:0,origin:bounds.origin,work:bounds.work,hard:bounds.hard,cut:0,cutoff:0,
            source:identity.source,release:identity.release,target:identity.target,reserved:[0;8]};
        value.request_valid().then_some(value)
    }
    pub fn bounds(self)->Bounds{Bounds{origin:self.origin,work:self.work,hard:self.hard}}
    pub fn identity(self)->Identity{Identity{instance:self.instance,source:self.source,release:self.release,target:self.target}}
    fn common(self)->bool{self.version==1 && self.bytes==256 && self.operation!=[0;16] && self.reserved==[0;8]
        && self.bounds().valid() && source_valid(&self.source) && release_valid(&self.release) && target_valid(&self.target)}
    pub fn request_valid(self)->bool{self.common() && self.instance==[0;16] && self.nonce==[0;16]
        && self.number==0 && self.account==0 && self.slot==0 && self.acceptance==0 && self.cut==0 && self.cutoff==0}
    pub fn challenge_valid(self)->bool{
        if !self.common() || !self.identity().valid() || self.number==0 || self.account==0 || self.account==u32::MAX
            || self.slot>=8 || self.acceptance<self.origin || self.acceptance>=self.work || self.cut!=0 || self.cutoff!=0{return false;}
        let mut nonce=[0;16];nonce[..8].copy_from_slice(b"MRKACTX1");nonce[8..].copy_from_slice(&self.number.to_be_bytes());
        self.nonce==nonce
    }
    pub fn started_valid(self)->bool{
        let challenge=Self{cut:0,cutoff:0,..self};
        challenge.challenge_valid() && self.cut>=self.acceptance && self.cut<self.work && self.cut<self.cutoff
            && self.cutoff<=self.hard && self.cut.checked_add(CLEANUP_NS).is_some_and(|end|self.cutoff<=end)
    }
    pub fn same_challenge(self,other:Self)->bool{Self{cut:0,cutoff:0,..self}==Self{cut:0,cutoff:0,..other}}
    pub fn matches_request(self,request:Self,account:u32)->bool{
        request.request_valid() && self.challenge_valid() && self.operation==request.operation
            && self.bounds()==request.bounds() && self.identity().same_build(request.identity()) && self.account==account
    }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[repr(u32)]
pub enum Kind{ChallengeA=1,ChallengeAReply=2,ChallengeB=3,ChallengeBReply=4,BeginDrain=5,BeginDrainReply=6,TailReceived=7,Tail=8}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[repr(u32)]
pub enum Code{Accepted=0,Busy=1,Refused=2,Unknown=3}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Tail{pub ceiling:u64,pub retirement:u64,pub first:u64,pub cutoff:u64,pub returned_at:u64,pub last:u64,pub write_entered:u64}
impl Tail{
    pub fn valid(self,binding:Binding)->bool{
        if !binding.started_valid() || self.ceiling!=binding.hard || self.retirement!=binding.cut
            || self.last<binding.cut || self.returned_at<self.last || self.returned_at>MAX_RAW
            || self.write_entered<self.returned_at || self.write_entered>=self.cutoff
            || self.first!=0 && (self.first<binding.acceptance || self.first>self.returned_at){return false;}
        let Some(retired)=self.retirement.checked_add(CLEANUP_NS)else{return false;};
        let mut cutoff=self.ceiling.min(retired);
        if self.first!=0{let Some(failed)=self.first.checked_add(CLEANUP_NS)else{return false;};cutoff=cutoff.min(failed);}
        self.cutoff==cutoff && self.cutoff<=binding.cutoff && self.returned_at<self.cutoff
    }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Frame{pub kind:Kind,pub code:Code,pub binding:Binding,pub tail:Option<Tail>}
fn get32(bytes:&[u8],at:usize)->u32{u32::from_be_bytes(bytes[at..at+4].try_into().expect("fixed frame bound"))}
fn get64(bytes:&[u8],at:usize)->u64{u64::from_be_bytes(bytes[at..at+8].try_into().expect("fixed frame bound"))}
fn put32(bytes:&mut[u8],at:usize,value:u32){bytes[at..at+4].copy_from_slice(&value.to_be_bytes());}
fn put64(bytes:&mut[u8],at:usize,value:u64){bytes[at..at+8].copy_from_slice(&value.to_be_bytes());}
impl Frame{
    pub fn valid(self)->bool{
        let reply=matches!(self.kind,Kind::ChallengeAReply|Kind::ChallengeBReply|Kind::BeginDrainReply);
        if !reply && self.code!=Code::Accepted{return false;}
        if self.kind==Kind::Tail{return self.code==Code::Accepted && self.tail.is_some_and(|tail|tail.valid(self.binding));}
        if self.tail.is_some(){return false;}
        match self.kind{
            Kind::ChallengeA=>self.binding.request_valid(),
            Kind::BeginDrainReply if self.code==Code::Accepted=>self.binding.started_valid(),
            Kind::TailReceived=>self.binding.started_valid(),
            _=>self.binding.challenge_valid(),
        }
    }
    pub fn encode(self)->Option<[u8;BYTES]>{
        if !self.valid(){return None;}
        let mut out=[0;BYTES];out[..8].copy_from_slice(MAGIC);
        put32(&mut out,8,1);put32(&mut out,12,self.kind as u32);put32(&mut out,16,BYTES as u32);put32(&mut out,20,self.code as u32);
        let b=self.binding;put32(&mut out,24,b.version);put32(&mut out,28,b.bytes);
        out[32..48].copy_from_slice(&b.instance);out[48..64].copy_from_slice(&b.operation);out[64..80].copy_from_slice(&b.nonce);
        put64(&mut out,80,b.number);put32(&mut out,88,b.account);put32(&mut out,92,b.slot);
        for(at,value)in[(96,b.acceptance),(104,b.origin),(112,b.work),(120,b.hard),(128,b.cut),(136,b.cutoff)]{put64(&mut out,at,value);}
        out[144..184].copy_from_slice(&b.source);out[184..248].copy_from_slice(&b.release);out[248..272].copy_from_slice(&b.target);
        if let Some(t)=self.tail{for(at,value)in[(280,t.ceiling),(288,t.retirement),(296,t.first),(304,t.cutoff),
            (312,t.returned_at),(320,t.last),(328,t.write_entered)]{put64(&mut out,at,value);}}
        Some(out)
    }
    pub fn decode(bytes:&[u8])->Option<Self>{
        if bytes.len()!=BYTES || &bytes[..8]!=MAGIC || get32(bytes,8)!=1 || get32(bytes,16)!=BYTES as u32
            || bytes[272..280]!=[0;8] || bytes[336..]!=[0;48]{return None;}
        let kind=match get32(bytes,12){1=>Kind::ChallengeA,2=>Kind::ChallengeAReply,3=>Kind::ChallengeB,4=>Kind::ChallengeBReply,
            5=>Kind::BeginDrain,6=>Kind::BeginDrainReply,7=>Kind::TailReceived,8=>Kind::Tail,_=>return None};
        let code=match get32(bytes,20){0=>Code::Accepted,1=>Code::Busy,2=>Code::Refused,3=>Code::Unknown,_=>return None};
        let binding=Binding{version:get32(bytes,24),bytes:get32(bytes,28),instance:bytes[32..48].try_into().ok()?,
            operation:bytes[48..64].try_into().ok()?,nonce:bytes[64..80].try_into().ok()?,number:get64(bytes,80),
            account:get32(bytes,88),slot:get32(bytes,92),acceptance:get64(bytes,96),origin:get64(bytes,104),
            work:get64(bytes,112),hard:get64(bytes,120),cut:get64(bytes,128),cutoff:get64(bytes,136),
            source:bytes[144..184].try_into().ok()?,release:bytes[184..248].try_into().ok()?,
            target:bytes[248..272].try_into().ok()?,reserved:[0;8]};
        let tail=if kind==Kind::Tail{Some(Tail{ceiling:get64(bytes,280),retirement:get64(bytes,288),first:get64(bytes,296),
            cutoff:get64(bytes,304),returned_at:get64(bytes,312),last:get64(bytes,320),write_entered:get64(bytes,328)})}
            else{if bytes[280..336]!=[0;56]{return None;}None};
        let out=Self{kind,code,binding,tail};out.valid().then_some(out)
    }
}
#[cfg(test)]
mod tests{
    use super::*;
    fn identity()->Identity{let mut target=[0;24];target[..TARGET.len()].copy_from_slice(TARGET);
        let mut release=[0;64];release[..7].copy_from_slice(b"fixture");
        Identity{instance:[1;16],source:*b"1111111111111111111111111111111111111111",release,target}}
    fn bound()->Binding{
        let mut b=Binding::request(identity(),[2;16],Bounds{origin:100,work:100+WORK_NS,hard:100+HARD_NS}).unwrap();
        b.instance=identity().instance;b.number=9;b.account=501;b.slot=2;b.acceptance=110;
        b.nonce[..8].copy_from_slice(b"MRKACTX1");b.nonce[8..].copy_from_slice(&b.number.to_be_bytes());b
    }
    #[test]
    fn stage_binding_zero_fields_and_closed_codes_are_not_interchangeable(){
        let binding=bound();
        let request=Binding::request(identity(),[2;16],binding.bounds()).unwrap();
        let a=Frame{kind:Kind::ChallengeA,code:Code::Accepted,binding:request,tail:None};
        assert_eq!(Frame::decode(&a.encode().unwrap()),Some(a));
        assert!(Frame{binding,..a}.encode().is_none());
        let reply=Frame{kind:Kind::ChallengeAReply,binding,..a};
        let bytes=reply.encode().unwrap();assert_eq!(Frame::decode(&bytes),Some(reply));
        for at in [20,272,280,336,383]{let mut changed=bytes;changed[at]=255;assert!(Frame::decode(&changed).is_none());}
        assert!(!binding.matches_request(request,502));
        assert!(!Binding{nonce:[9;16],..binding}.challenge_valid());
        assert!(!Binding{acceptance:99,..binding}.challenge_valid());
    }
    #[test]
    fn e1_tail_offsets_and_genuine_failure_remain_data_not_unregistration_permission(){
        let mut binding=bound();binding.cut=200;binding.cutoff=200+CLEANUP_NS;
        let tail=Tail{ceiling:binding.hard,retirement:200,first:0,cutoff:binding.cutoff,returned_at:300,last:280,write_entered:310};
        let frame=Frame{kind:Kind::Tail,code:Code::Accepted,binding,tail:Some(tail)};
        let bytes=frame.encode().unwrap();
        assert_eq!(get32(&bytes,12),8);assert_eq!(get64(&bytes,80),9);
        assert_eq!(get64(&bytes,128),200);assert_eq!(get64(&bytes,280),binding.hard);
        assert_eq!(get64(&bytes,304),binding.cutoff);assert_eq!(get64(&bytes,328),310);
        assert_eq!(Frame::decode(&bytes),Some(frame));
        let failed=Frame{tail:Some(Tail{first:120,cutoff:120+CLEANUP_NS,..tail}),..frame};
        // An authentic failed tail can be syntactically valid. Only the original
        // owning client's no-F gate can authorize the later main action.
        assert_eq!(Frame::decode(&failed.encode().unwrap()),Some(failed));
        for bad in [Tail{retirement:201,..tail},Tail{write_entered:299,..tail},
            Tail{cutoff:binding.cutoff+1,..tail},Tail{first:109,..tail}]{
            assert!(Frame{tail:Some(bad),..frame}.encode().is_none());
        }
    }
}
