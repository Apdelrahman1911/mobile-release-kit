//! Complete, bounded-by-owner Notes security DATA. No Image/runtime decoder reuse.
//! Raw descriptor layout and canonical policy are separately retained and hashed.
//! No 64KiB descriptor/2048-ACE policy cutoff: SDK u16 ACL structure and the
//! caller's actual remaining aggregate heap are the only size/count bounds.
use super::wire::{Fault, Result};
use sha2::{Digest, Sha256};
use windows_sys::Win32::{Foundation as F, Security as S, Storage::FileSystem as FS};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Ace { pub allow: bool, pub flags: u8, pub mask: u32, pub sid: Vec<u8> }
#[derive(Debug)]
pub(super) struct Descriptor {
    pub raw: Vec<u8>, pub canonical: Vec<u8>, pub owner: Vec<u8>, pub group: Vec<u8>,
    pub control: u16, pub revision: u8, pub aces: Vec<Ace>,
    pub raw_hash: [u8;32], pub canonical_hash: [u8;32],
}
fn need(ok: bool) -> Result<()> { if ok { Ok(()) } else { Err(Fault::Security) } }
fn span(raw: &[u8], at: usize, n: usize) -> Result<&[u8]> {
    raw.get(at..at.checked_add(n).ok_or(Fault::Capacity)?).ok_or(Fault::Security)
}
fn u16at(raw: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(span(raw,at,2)?.try_into().map_err(|_|Fault::Security)?))
}
fn u32at(raw: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(span(raw,at,4)?.try_into().map_err(|_|Fault::Security)?))
}
pub(super) fn sid(raw: &[u8], at: usize, end: usize) -> Result<Vec<u8>> {
    let head=span(raw,at,8)?; need(head[0]==1 && head[1]<=15)?;
    let length=8+usize::from(head[1])*4;
    need(at.checked_add(length).is_some_and(|n|n<=end))?;
    Ok(span(raw,at,length)?.to_vec())
}
fn overlap(a:(usize,usize),b:(usize,usize))->bool { a.0<b.1 && b.0<a.1 }
fn rights(mask:u32)->Result<u32> {
    let generic=F::GENERIC_READ|F::GENERIC_WRITE|F::GENERIC_EXECUTE|F::GENERIC_ALL;
    need(mask & !(generic|FS::FILE_ALL_ACCESS)==0)?;
    let mut out=mask & !generic;
    for (flag,actual) in [(F::GENERIC_READ,FS::FILE_GENERIC_READ),
        (F::GENERIC_WRITE,FS::FILE_GENERIC_WRITE),(F::GENERIC_EXECUTE,FS::FILE_GENERIC_EXECUTE),
        (F::GENERIC_ALL,FS::FILE_ALL_ACCESS)] {
        if mask&flag!=0 { out|=actual; }
    }
    Ok(out)
}
pub(super) fn hash(raw:&[u8])->[u8;32] { Sha256::digest(raw).into() }
impl Descriptor {
    pub fn parse(raw:Vec<u8>, remaining:usize)->Result<Self> {
        // Charge worst simultaneous raw/canonical/SID/ACE representation BEFORE
        // allocation; the actual capacities below are checked again.
        need(raw.len()>=20)?;
        if raw.len().checked_mul(8).and_then(|n|n.checked_add(4096)).is_none_or(|n|n>remaining) {
            return Err(Fault::Capacity);
        }
        let revision=raw[0]; let control=u16at(&raw,2)?;
        let supported=S::SE_OWNER_DEFAULTED|S::SE_GROUP_DEFAULTED|S::SE_DACL_PRESENT|
            S::SE_DACL_DEFAULTED|S::SE_DACL_AUTO_INHERIT_REQ|S::SE_DACL_AUTO_INHERITED|
            S::SE_DACL_PROTECTED|S::SE_SELF_RELATIVE;
        need(revision==1 && raw[1]==0 && control & !supported==0)?;
        need(control&(S::SE_SELF_RELATIVE|S::SE_DACL_PRESENT)==(S::SE_SELF_RELATIVE|S::SE_DACL_PRESENT))?;
        need(u32at(&raw,12)?==0)?;
        let owner_at=u32at(&raw,4)? as usize; let group_at=u32at(&raw,8)? as usize;
        let acl_at=u32at(&raw,16)? as usize;
        need([owner_at,group_at,acl_at].iter().all(|n|*n>=20 && n%4==0))?;
        let owner=sid(&raw,owner_at,raw.len())?; let group=sid(&raw,group_at,raw.len())?;
        let acl=span(&raw,acl_at,8)?;
        let acl_revision=acl[0]; need(matches!(acl_revision,2|4) && acl[1]==0 && u16at(acl,6)?==0)?;
        let acl_size=u16at(acl,2)? as usize; let count=u16at(acl,4)? as usize;
        need(acl_size>=8 && acl_size%4==0)?;
        span(&raw,acl_at,acl_size)?;
        let acl_end=acl_at+acl_size; let own=(owner_at,owner_at+owner.len()); let grp=(group_at,group_at+group.len());
        need(!overlap(own,(acl_at,acl_end)) && !overlap(grp,(acl_at,acl_end)) && (own==grp || !overlap(own,grp)))?;
        // A structurally complete ACE is at least header+mask+SID header (16).
        need(count<=(acl_size-8)/16)?;
        let mut aces=Vec::new(); aces.try_reserve_exact(count).map_err(|_|Fault::Capacity)?;
        let mut at=acl_at+8;
        for _ in 0..count {
            let h=span(&raw,at,8)?; let length=u16at(h,2)? as usize;
            need(length>=16 && length%4==0 && at.checked_add(length).is_some_and(|n|n<=acl_end))?;
            let allow=match h[0] {0=>true,1=>false,_=>return Err(Fault::Security)};
            let flags=h[1]; let known=(S::OBJECT_INHERIT_ACE|S::CONTAINER_INHERIT_ACE|
                S::NO_PROPAGATE_INHERIT_ACE|S::INHERIT_ONLY_ACE|S::INHERITED_ACE) as u8;
            need(flags & !known==0)?;
            need(flags & (S::NO_PROPAGATE_INHERIT_ACE|S::INHERIT_ONLY_ACE) as u8==0
                || flags & (S::OBJECT_INHERIT_ACE|S::CONTAINER_INHERIT_ACE) as u8!=0)?;
            let mask=u32at(h,4)?; rights(mask)?;
            let who=sid(&raw,at+8,at+length)?; need(8+who.len()==length)?;
            aces.push(Ace{allow,flags,mask,sid:who}); at+=length;
        }
        need(at<=acl_end && raw[at..acl_end].iter().all(|b|*b==0))?;
        // Canonical fixed56 then owner/group SID and ordered records. No raw
        // offsets/padding are mistaken for policy. Every accepted control bit,
        // ACL revision, ACE type/flags/mask/SID and order remains represented.
        let total=56+owner.len()+group.len()+aces.iter().map(|a|16+a.sid.len()).sum::<usize>();
        let mut canonical=Vec::new(); canonical.try_reserve_exact(total).map_err(|_|Fault::Capacity)?;
        canonical.extend_from_slice(b"MRKNSF1\0");
        for n in [56u32,1,u32::from(revision),u32::from(control),u32::from(acl_revision),
            owner.len() as u32,group.len() as u32,count as u32,total as u32,0,0,0] {
            canonical.extend_from_slice(&n.to_le_bytes());
        }
        canonical.extend_from_slice(&owner); canonical.extend_from_slice(&group);
        for ace in &aces {
            for n in [u32::from(!ace.allow),u32::from(ace.flags),ace.mask,ace.sid.len() as u32] {
                canonical.extend_from_slice(&n.to_le_bytes());
            }
            canonical.extend_from_slice(&ace.sid);
        }
        need(canonical.len()==total)?;
        let result=Self{raw_hash:hash(&raw),canonical_hash:hash(&canonical),raw,canonical,
            owner,group,control,revision,aces};
        if result.heap()>remaining {return Err(Fault::Capacity);} Ok(result)
    }
    pub fn heap(&self)->usize {
        2*std::mem::size_of::<usize>()+std::mem::size_of::<Self>()+self.raw.capacity()+self.canonical.capacity()+
            self.owner.capacity()+self.group.capacity()+self.aces.capacity()*std::mem::size_of::<Ace>()+
            self.aces.iter().map(|a|a.sid.capacity()).sum::<usize>()
    }
    pub fn same(&self,other:&Self)->bool { self.canonical==other.canonical }
    pub fn is_private(&self,user:&[u8])->bool {
        self.owner==user && self.control&S::SE_DACL_PROTECTED!=0 &&
        self.aces.iter().all(|a|!a.allow || a.flags&S::INHERIT_ONLY_ACE as u8!=0 ||
            a.sid==user || rights(a.mask).is_ok_and(|r|
                r & !(FS::READ_CONTROL|FS::SYNCHRONIZE|FS::FILE_READ_ATTRIBUTES)==0))
    }
    pub fn ordinary_settable(&self,user:&[u8],group:&[u8])->Result<()> {
        // Never require an unavailable take-ownership/group privilege.
        need(self.owner==user && self.group==group)
    }
    pub fn private(user:&[u8],group:&[u8],remaining:usize)->Result<Self> {
        need(sid(user,0,user.len())?==user && sid(group,0,group.len())?==group)?;
        let owner_at=20usize; let group_at=owner_at+user.len(); let acl_at=group_at+group.len();
        let acl_size=8+8+user.len(); need(acl_size<=u16::MAX as usize)?;
        if (acl_at+acl_size).checked_mul(8).and_then(|n|n.checked_add(4096)).is_none_or(|n|n>remaining){return Err(Fault::Capacity)}
        let mut raw=vec![0u8;acl_at+acl_size]; raw[0]=1;
        raw[2..4].copy_from_slice(&(S::SE_SELF_RELATIVE|S::SE_DACL_PRESENT|S::SE_DACL_PROTECTED).to_le_bytes());
        for (at,n) in [(4,owner_at),(8,group_at),(16,acl_at)] {raw[at..at+4].copy_from_slice(&(n as u32).to_le_bytes());}
        raw[owner_at..group_at].copy_from_slice(user);raw[group_at..acl_at].copy_from_slice(group);
        raw[acl_at]=2;raw[acl_at+2..acl_at+4].copy_from_slice(&(acl_size as u16).to_le_bytes());
        raw[acl_at+4..acl_at+6].copy_from_slice(&1u16.to_le_bytes());
        let a=acl_at+8;raw[a+2..a+4].copy_from_slice(&((8+user.len()) as u16).to_le_bytes());
        raw[a+4..a+8].copy_from_slice(&FS::FILE_ALL_ACCESS.to_le_bytes());raw[a+8..].copy_from_slice(user);
        Self::parse(raw,remaining)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn private_has_full_owner_group_and_ordered_canonical() {
        let user=[1,1,0,0,0,0,0,5,21,0,0,0];
        let group=[1,1,0,0,0,0,0,5,22,0,0,0];
        let d=Descriptor::private(&user,&group,1<<20).unwrap();
        assert!(d.is_private(&user)); assert_eq!(d.group,group);
        assert_eq!(&d.canonical[..8],b"MRKNSF1\0"); assert_ne!(d.raw_hash,d.canonical_hash);
    }
    #[test] fn unknown_and_null_policy_never_becomes_private() {
        let user=[1,1,0,0,0,0,0,5,21,0,0,0];
        let d=Descriptor::private(&user,&user,1<<20).unwrap();
        let mut raw=d.raw.clone();raw[16..20].fill(0);
        assert!(Descriptor::parse(raw,1<<20).is_err());
    }
}
