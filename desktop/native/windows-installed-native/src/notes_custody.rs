//! Private Notes native boundary. One book, pinned original outputs, no Drop close.
//! All paths/access/classes below are selected by the closed Notes context; this
//! module is not public and never accepts a renderer HANDLE or callback.
use super::{wire::{Fault,Result}, security::{Descriptor,hash},reservations::Credit};
use crate::{NativeBook,LivePurpose,Original,Kind,SlotState,FileKind,Metadata,
    DirectoryEntry,Phase,Held,Returned,Aligned,BUFFER,NAME_UNITS,Call};
use std::{cell::{Cell,UnsafeCell},marker::PhantomPinned,
    mem::{size_of,offset_of,ManuallyDrop},pin::Pin,ptr::{null,null_mut},sync::Arc};
use windows_sys::Wdk::{Foundation::OBJECT_ATTRIBUTES,Storage::FileSystem as N};
use windows_sys::Win32::{Foundation as F,Security as S,Storage::FileSystem as FS};
use windows_sys::Win32::Security::Authorization as A;
use windows_sys::Win32::System::{IO,WindowsProgramming as WP};

pub(super) const HEAP:usize=33_554_432;
pub(super) const HELPER:usize=1_114_112;
// DATA corroboration only. A matched failure Information is not NO_EFFECT,
// and no caller may use it as an acquired HANDLE or a success disposition.
fn nt_failure_information(status:i32,ios_status:i32,information:usize,max:usize)->Result<usize>{
    if status==F::STATUS_SUCCESS||(status as u32>>30)!=3||ios_status!=status||information>max{
        Err(Fault::NativeUnknown)
    }else{Ok(information)}
}
pub(super) fn fault(e:crate::Error)->Fault {match e {
    crate::Error::Unavailable=>Fault::NativeUnavailable,crate::Error::Unsafe=>Fault::NativeUnsafe,
    crate::Error::Bounds=>Fault::NativeBounds,crate::Error::State=>Fault::NativeState,
    crate::Error::Unknown=>Fault::NativeUnknown,
}}
#[derive(Clone,Copy,Debug,Eq,PartialEq)] pub(super) enum Pool{Producer,Recovery}
impl Pool{fn index(self)->usize{match self{Self::Producer=>0,Self::Recovery=>1}}}
#[derive(Default)]
pub(super) struct Quota {
    pub passes:[u32;2],pub checks:[u32;2],
    pub bytes:[u64;2],pub entries:u64,pub acquisitions:u32,
}
impl Quota {
    pub fn pass(&mut self,p:Pool)->Result<()> {let n=&mut self.passes[p.index()];if *n>=2048{return Err(Fault::Capacity)}*n+=1;Ok(())}
    fn check(&mut self,p:Pool)->Result<()> {let n=&mut self.checks[p.index()];if *n>=7680{return Err(Fault::Capacity)}*n+=1;Ok(())}
    pub fn read(&mut self,p:Pool,n:u64)->Result<()> {
        let v=&mut self.bytes[p.index()];*v=v.checked_add(n).ok_or(Fault::Capacity)?;
        if *v>536_870_912{Err(Fault::Capacity)}else{Ok(())}
    }
    pub fn entries(&mut self,n:usize)->Result<()>{
        self.entries=self.entries.checked_add(n as u64).ok_or(Fault::Capacity)?;
        if self.entries>524_288{Err(Fault::Capacity)}else{Ok(())}
    }
}
#[derive(Clone,Copy)]
pub(super) enum Access { Lease,ReadDirectory,WriteDirectory,ReadFile,OldTarget,PrivateDirectory,PrivateFile }
impl Access {
    fn directory(self)->bool{matches!(self,Self::Lease|Self::ReadDirectory|Self::WriteDirectory|Self::PrivateDirectory)}
    fn mask(self)->u32{
        let r=FS::SYNCHRONIZE|FS::READ_CONTROL|FS::FILE_READ_ATTRIBUTES;
        let di=r|FS::FILE_LIST_DIRECTORY|FS::FILE_TRAVERSE;
        match self {
            Self::Lease=>r,Self::ReadDirectory=>di,Self::WriteDirectory=>di|FS::FILE_GENERIC_WRITE,
            Self::ReadFile=>r|FS::FILE_READ_DATA,
            Self::OldTarget=>r|FS::FILE_READ_DATA|FS::FILE_GENERIC_WRITE|FS::DELETE,
            Self::PrivateDirectory=>di|FS::FILE_GENERIC_WRITE|FS::DELETE|FS::WRITE_DAC|FS::WRITE_OWNER,
            Self::PrivateFile=>r|FS::FILE_READ_DATA|FS::FILE_GENERIC_WRITE|FS::DELETE|FS::WRITE_DAC|FS::WRITE_OWNER,
        }
    }
    fn share(self)->u32{if matches!(self,Self::Lease){FS::FILE_SHARE_READ|FS::FILE_SHARE_WRITE}else{FS::FILE_SHARE_READ}}
}
#[derive(Clone,Copy,Default)]
pub(super) struct Effect {
    pub kind:u32,pub object:u64,pub sequence:u64,pub epoch:u64,pub operation:u64,
    pub return_kind:u32,pub bits:u32,pub error:u32,pub flags:u32,pub information:u64,
}
impl Effect {
    pub fn encode(self,owner:u64)->[u8;80] {
        let mut out=[0;80]; out[..8].copy_from_slice(b"MRKNEF1\0");
        out[8..12].copy_from_slice(&80u32.to_le_bytes());out[12..16].copy_from_slice(&self.kind.to_le_bytes());
        for (at,n) in [(16,owner),(24,self.object),(32,self.sequence),(40,self.epoch),(48,self.operation),(72,self.information)]{out[at..at+8].copy_from_slice(&n.to_le_bytes());}
        for (at,n) in [(56,self.return_kind),(60,self.bits),(64,self.error),(68,self.flags)]{out[at..at+4].copy_from_slice(&n.to_le_bytes());}out
    }
}
#[derive(Clone)]
enum Api {
    Open{slot:usize,access:Access,create:bool,descriptor:Option<Arc<Descriptor>>},
    Read{slot:usize,count:usize,offset:u64},Write{slot:usize,count:usize,offset:u64},
    Roster{slot:usize,restart:bool},Fence{slot:usize},
    Move{slot:usize,parent:usize,name:String},Delete{slot:usize},
    Security{slot:usize},SetSecurity{slot:usize,descriptor:Arc<Descriptor>},
    Inherit{parent:Arc<Descriptor>,directory:bool},PrimaryGroup,
}
struct Frame {
    api:Api,phase:Cell<Phase>,returned:Cell<Option<Returned>>,effect:Option<usize>,
    handle:F::HANDLE,output_handle:*mut F::HANDLE,input:Vec<u16>,
    unicode:F::UNICODE_STRING,attributes:OBJECT_ATTRIBUTES,offset:i64,length:u32,
    bytes:UnsafeCell<Aligned>,count:UnsafeCell<u32>,iosb:UnsafeCell<IO::IO_STATUS_BLOCK>,
    foreign:UnsafeCell<S::PSECURITY_DESCRIPTOR>,foreign_owned:Cell<bool>,
    foreign_length:Cell<Option<u32>>,foreign_size_entered:Cell<bool>,foreign_size_returned:Cell<bool>,
    release_attempted:Cell<bool>,release_returned:Cell<bool>,release_bits:Cell<usize>,release_error:Cell<u32>,foreign_original:Cell<usize>,
    mapping:S::GENERIC_MAPPING,_pin:PhantomPinned,
}
impl Frame {
    fn buffer(&self)->*mut u8{self.bytes.get().cast()}
    fn heap(&self)->Option<usize>{
        let dynamic=match &self.api{
            Api::Move{name,..}=>name.capacity(),
            Api::Open{descriptor:Some(d),..}|Api::SetSecurity{descriptor:d,..}=>d.heap(),
            Api::Inherit{parent,..}=>parent.heap(),_=>0,
        };
        size_of::<Self>().checked_add(self.input.capacity().checked_mul(size_of::<u16>())?)?
            .checked_add(dynamic)?.checked_add(if self.foreign_owned.get(){self.foreign_length.get().unwrap_or(0) as usize}else{0})
    }
}
struct Complete{frame:Pin<Box<Frame>>}
impl Complete {
    fn bytes(&self,n:usize)->Result<&[u8]>{
        if self.frame.phase.get()!=Phase::Complete || n>BUFFER{return Err(Fault::NativeUnknown)}
        // SAFETY: Complete exists only after definite completion, never pending.
        Ok(unsafe{std::slice::from_raw_parts(self.frame.buffer(),n)})
    }
    fn information(&self)->usize{unsafe{(*self.frame.iosb.get()).Information}}
}
pub(super) struct Custody {
    pub book:NativeBook,pub quota:Quota,pub effects:Vec<Effect>,
    active:Option<Held<Frame>>,pub pool:Pool,pub unknown:bool,credit:Option<Credit>,
    pub close_attempted:Vec<bool>,pub scope:u32,
}
unsafe impl Send for Custody {}
impl Custody {
    pub fn new()->Result<Self>{
        let mut book=NativeBook::with_purpose(LivePurpose::NotesNamespace48);
        book.records_limit=32768;book.slots.try_reserve_exact(32768).map_err(|_|Fault::Capacity)?;
        let mut effects=Vec::new();effects.try_reserve_exact(65536).map_err(|_|Fault::Capacity)?;
        let mut close_attempted=Vec::new();close_attempted.try_reserve_exact(32768).map_err(|_|Fault::Capacity)?;
        close_attempted.resize(32768,false);
        Ok(Self{book,quota:Quota::default(),effects,active:None,pool:Pool::Producer,unknown:false,credit:None,close_attempted,scope:0})
    }
    pub fn heap(&self)->Option<usize>{
        self.book.public_image_retained_heap_bytes()?.checked_add(size_of::<Self>())?
            .checked_add(self.effects.capacity()*size_of::<Effect>())?
            .checked_add(self.close_attempted.capacity())?
            .checked_add(match &self.active{Some(frame)=>frame.heap()?,None=>0})
    }
    pub fn idle(&self)->Result<()>{
        if self.active.is_some()||self.book.active.is_some()||self.unknown||self.book.is_unknown(){Err(Fault::NativeUnknown)}else{Ok(())}
    }
    pub fn frames_active(&self)->bool{self.active.is_some()||self.book.active.is_some()}
    pub fn foreign_count(&self)->u32{u32::from(self.active.as_ref().is_some_and(|f|matches!(&f.api,Api::Security{..}|Api::Inherit{..})))}
    pub fn counters(&self)->(u64,u64){(self.book.notes_entered,self.book.notes_returned)}
    pub fn native_unknown(&self)->bool{self.unknown||self.book.is_unknown()||self.active.is_some()}
    pub fn mark_unknown(&mut self){self.unknown=true;self.book.mark_interrupted();}
    // Only the original context can select a precharged ticket. These methods
    // never increase total reservations or turn unused credits into a new pool.
    pub fn begin_credit(&mut self,credit:Credit,pool:Pool)->Result<()>{
        if self.credit.is_some(){return Err(Fault::Busy)}
        self.book.notes_begin_credit(u32::try_from(credit.frames).map_err(|_|Fault::Capacity)?,
            u32::try_from(credit.records).map_err(|_|Fault::Capacity)?).map_err(fault)?;
        self.set_pool(pool);self.credit=Some(credit);Ok(())
    }
    pub fn end_credit(&mut self)->Result<Credit>{
        let (frames,records)=self.book.notes_end_credit().map_err(fault)?;
        let mut credit=self.credit.take().ok_or(Fault::Phase)?;
        credit.frames=u64::from(frames);credit.records=u64::from(records);Ok(credit)
    }
    fn debit(&mut self,amount:Credit)->Result<()>{
        self.credit.as_mut().ok_or(Fault::Phase)?.take(amount)
    }
    pub fn pass(&mut self)->Result<()>{
        self.debit(Credit{passes:1,..Credit::ZERO})?;self.quota.pass(self.pool)
    }
    pub fn observe_user(&mut self)->Result<()>{
        self.idle()?;self.debit(Credit{checks:1,..Credit::ZERO})?;self.quota.check(self.pool)?;self.book.observe_user_once().map(|_|()).map_err(fault)
    }
    pub fn check_user(&mut self)->Result<()>{
        self.idle()?;self.debit(Credit{checks:1,..Credit::ZERO})?;self.quota.check(self.pool)?;self.book.recheck_user().map_err(fault)
    }
    pub fn mapping(&mut self,drive:&str)->Result<String>{self.idle()?;self.book.mapping(drive).map_err(fault)}
    pub fn user(&self)->Result<&[u8]>{self.book.user.as_ref().map(|u|u.user.bytes()).ok_or(Fault::Phase)}
    pub fn set_pool(&mut self,pool:Pool){self.pool=pool;self.book.notes_pool=pool.index();}
    pub fn set_scope(&mut self,scope:u32)->Result<()>{
        self.idle()?;if scope!=self.scope+1||scope>3{return Err(Fault::Phase)}
        self.scope=scope;self.book.notes_scope_start=self.book.slots.len();Ok(())
    }
    pub fn reserve(&mut self,parent:Option<usize>,name:&str,canonical:String,directory:bool)->Result<usize>{
        self.idle()?;self.debit(Credit{acquisitions:1,..Credit::ZERO})?;if self.quota.acquisitions>=154{return Err(Fault::Capacity)}
        self.quota.acquisitions+=1;
        let original=self.book.reserve(if directory{Kind::Directory}else{Kind::File},parent,name,canonical).map_err(fault)?;
        Ok(original.index)
    }
    pub fn no_handle(&mut self,slot:usize)->Result<()>{
        if self.book.slot(slot).map_err(fault)?.state!=SlotState::Reserved{return Err(Fault::Phase)}
        self.book.slot_mut(slot).map_err(fault)?.state=SlotState::NoHandle;Ok(())
    }
    pub fn state(&self,slot:usize)->Result<SlotState>{Ok(self.book.slot(slot).map_err(fault)?.state)}
    pub fn original(&self,slot:usize)->Original{Original{book:Arc::clone(&self.book.identity),index:slot}}
    pub fn metadata(&mut self,slot:usize,canonical:&str)->Result<Metadata>{
        self.idle()?;let original=self.original(slot);
        self.book.local_ntfs(&original).map_err(fault)?;
        // The private caller supplies its own current closed graph path; no
        // external path can reach this seam. Acquisition Slot fields stay fixed.
        let data=self.book.metadata_with_canonical(&original,crate::MetadataObservationProfile::Ordinary,Some(canonical)).map_err(fault)?;
        self.book.no_alternate_streams(&original).map_err(fault)?;Ok(data)
    }
    pub fn open(&mut self,slot:usize,access:Access,create:bool,descriptor:Option<Arc<Descriptor>>,effect:Option<Effect>)->Result<()>{
        self.invoke(Api::Open{slot,access,create,descriptor},&[],effect)?;
        self.book.noninherited(slot).map_err(fault)
    }
    pub fn read(&mut self,slot:usize,offset:u64,count:usize)->Result<Vec<u8>>{
        let before=self.book.slot(slot).map_err(fault)?.read_bytes;
        if self.credit.as_ref().is_none_or(|credit|credit.bytes<count as u64){return Err(Fault::Capacity)}
        let pooled=self.quota.bytes[self.pool.index()];
        if before.checked_add(count as u64).is_none_or(|n|n>536_870_912)||
            pooled.checked_add(count as u64).is_none_or(|n|n>536_870_912){return Err(Fault::Capacity)}
        let c=self.invoke(Api::Read{slot,offset,count},&[],None)?;
        if matches!(c.frame.returned.get(),Some(Returned::Nt(F::STATUS_END_OF_FILE))){return Ok(Vec::new())}
        let n=c.information();if n==0{return Err(Fault::Io)}
        self.debit(Credit{bytes:n as u64,..Credit::ZERO})?;self.quota.read(self.pool,n as u64)?;
        let after=before.checked_add(n as u64).ok_or(Fault::Capacity)?;
        self.book.slot_mut(slot).map_err(fault)?.read_bytes=after;
        if after>536_870_912{return Err(Fault::Capacity)}Ok(c.bytes(n)?.to_vec())
    }
    pub fn roster(&mut self,slot:usize,restart:bool)->Result<Option<Vec<DirectoryEntry>>>{
        let c=self.invoke(Api::Roster{slot,restart},&[],None)?;
        if matches!(c.frame.returned.get(),Some(Returned::Boolean(0,F::ERROR_NO_MORE_FILES))){return Ok(None)}
        let entries=crate::decode::directory(c.bytes(BUFFER)?).map_err(fault)?;
        self.debit(Credit{entries:entries.len() as u64,..Credit::ZERO})?;
        self.quota.entries(entries.len())?;Ok(Some(entries))
    }
    pub fn write(&mut self,slot:usize,offset:u64,bytes:&[u8],effect:Effect)->Result<usize>{
        self.invoke(Api::Write{slot,offset,count:bytes.len()},bytes,Some(effect)).map(|c|c.information())
    }
    pub fn fence(&mut self,slot:usize,effect:Option<Effect>)->Result<()>{
        self.invoke(Api::Fence{slot},&[],effect).map(|_|())
    }
    pub fn movement(&mut self,slot:usize,parent:usize,name:&str,effect:Effect)->Result<bool>{
        let c=self.invoke(Api::Move{slot,parent,name:name.to_owned()},&[],Some(effect))?;
        Ok(matches!(c.frame.returned.get(),Some(Returned::Nt(F::STATUS_OBJECT_NAME_COLLISION))))
    }
    pub fn deletion(&mut self,slot:usize,effect:Effect)->Result<()>{self.invoke(Api::Delete{slot},&[],Some(effect)).map(|_|())}
    pub fn set_security(&mut self,slot:usize,descriptor:Arc<Descriptor>,effect:Effect)->Result<()>{
        self.invoke(Api::SetSecurity{slot,descriptor},&[],Some(effect)).map(|_|())
    }
    pub fn security(&mut self,slot:usize,remaining:usize)->Result<Arc<Descriptor>>{
        self.foreign(Api::Security{slot},remaining)
    }
    pub fn inherited(&mut self,parent:Arc<Descriptor>,directory:bool,remaining:usize)->Result<Arc<Descriptor>>{
        self.foreign(Api::Inherit{parent,directory},remaining)
    }
    pub fn primary_group(&mut self)->Result<Vec<u8>>{
        let c=self.invoke(Api::PrimaryGroup,&[],None)?;
        let n=unsafe{*c.frame.count.get()} as usize;let raw=c.bytes(n)?;
        let at=offset_of!(S::TOKEN_PRIMARY_GROUP,PrimaryGroup);
        let pointer=usize::from_ne_bytes(raw.get(at..at+size_of::<usize>()).ok_or(Fault::Security)?.try_into().map_err(|_|Fault::Security)?);
        let offset=pointer.checked_sub(c.frame.buffer() as usize).ok_or(Fault::Security)?;
        if offset<size_of::<S::TOKEN_PRIMARY_GROUP>()||offset%4!=0{return Err(Fault::Security)}
        super::security::sid(raw,offset,n)
    }
    fn frame(&self)->Result<&Frame>{self.active.as_ref().map(|f|f.as_ref().get_ref()).ok_or(Fault::NativeUnknown)}
    fn finish_frame(&mut self)->Result<Complete>{
        self.frame()?.phase.set(Phase::Complete);
        let frame=self.active.take().ok_or(Fault::NativeUnknown)?;
        Ok(Complete{frame:ManuallyDrop::into_inner(frame)})
    }
    fn unknown<T>(&mut self)->Result<T>{self.mark_unknown();Err(Fault::NativeUnknown)}
    fn invoke(&mut self,api:Api,input:&[u8],primary:Option<Effect>)->Result<Complete>{
        self.idle()?;self.book.notes_admit_frame().map_err(fault)?;
        if input.len()>BUFFER{return Err(Fault::Bounds)}
        let mut frame=Box::pin(Frame{api,phase:Cell::new(Phase::Prepared),returned:Cell::new(None),effect:None,
            handle:null_mut(),output_handle:null_mut(),input:Vec::new(),unicode:F::UNICODE_STRING::default(),
            attributes:OBJECT_ATTRIBUTES::default(),offset:0,length:0,bytes:UnsafeCell::new(Aligned([0;BUFFER])),
            count:UnsafeCell::new(u32::MAX),iosb:UnsafeCell::new(IO::IO_STATUS_BLOCK{
                Anonymous:IO::IO_STATUS_BLOCK_0{Status:F::STATUS_PENDING},Information:usize::MAX}),
            foreign:UnsafeCell::new(null_mut()),foreign_owned:Cell::new(false),foreign_length:Cell::new(None),
            foreign_size_entered:Cell::new(false),foreign_size_returned:Cell::new(false),
            release_attempted:Cell::new(false),release_returned:Cell::new(false),release_bits:Cell::new(usize::MAX),release_error:Cell::new(0),foreign_original:Cell::new(0),
            mapping:S::GENERIC_MAPPING{GenericRead:FS::FILE_GENERIC_READ,GenericWrite:FS::FILE_GENERIC_WRITE,
                GenericExecute:FS::FILE_GENERIC_EXECUTE,GenericAll:FS::FILE_ALL_ACCESS},_pin:PhantomPinned});
        let a=unsafe{frame.as_mut().get_unchecked_mut()};
        match &a.api {
            Api::Open{slot,access,create,descriptor}=>{
                let original=self.book.slot(*slot).map_err(fault)?;
                if original.state!=SlotState::Reserved||(*create!=descriptor.is_some()){return Err(Fault::Phase)}
                if access.directory()!=(original.kind==Kind::Directory){return Err(Fault::Key)}
                a.output_handle=original.output.get();a.input=original.name.clone();
                a.unicode.Length=u16::try_from((a.input.len()-1)*2).map_err(|_|Fault::Bounds)?;
                a.unicode.MaximumLength=u16::try_from(a.input.len()*2).map_err(|_|Fault::Bounds)?;
                a.unicode.Buffer=a.input.as_mut_ptr();a.attributes.Length=size_of::<OBJECT_ATTRIBUTES>() as u32;
                a.attributes.RootDirectory=original.parent.map(|p|self.book.handle(p).map_err(fault)).transpose()?.unwrap_or(null_mut());
                a.attributes.ObjectName=&a.unicode;a.attributes.Attributes=F::OBJ_DONT_REPARSE;
                a.attributes.SecurityDescriptor=descriptor.as_ref().map_or(null_mut(),|d|d.raw.as_ptr() as S::PSECURITY_DESCRIPTOR);
            },
            Api::Read{slot,count,offset}|Api::Write{slot,count,offset}=>{
                if *count==0||*count>BUFFER||*offset>i64::MAX as u64{return Err(Fault::Bounds)}
                a.handle=self.book.handle(*slot).map_err(fault)?;a.offset=*offset as i64;a.length=*count as u32;
                if matches!(&a.api,Api::Write{..}){if input.len()!=*count{return Err(Fault::Wire)}
                    unsafe{(&mut (*a.bytes.get()).0)[..input.len()].copy_from_slice(input)}}
            },
            Api::Move{slot,parent,name}=>{
                a.handle=self.book.handle(*slot).map_err(fault)?;let dest=self.book.handle(*parent).map_err(fault)?;
                if !super::wire::component(name){return Err(Fault::Namespace)}
                a.input=name.encode_utf16().collect();let n=a.input.len()*2;let start=offset_of!(N::FILE_RENAME_INFORMATION,FileName);
                a.length=u32::try_from((start+n).max(size_of::<N::FILE_RENAME_INFORMATION>())).map_err(|_|Fault::Bounds)?;
                if a.length as usize>BUFFER{return Err(Fault::Bounds)}
                let data=unsafe{&mut (*a.bytes.get()).0};
                let root=offset_of!(N::FILE_RENAME_INFORMATION,RootDirectory);let len=offset_of!(N::FILE_RENAME_INFORMATION,FileNameLength);
                data[root..root+size_of::<F::HANDLE>()].copy_from_slice(&(dest as usize).to_ne_bytes());
                data[len..len+4].copy_from_slice(&(n as u32).to_ne_bytes());
                for (i,v) in a.input.iter().enumerate(){data[start+2*i..start+2*i+2].copy_from_slice(&v.to_ne_bytes());}
            },
            Api::Delete{slot}=>{
                a.handle=self.book.handle(*slot).map_err(fault)?;a.length=size_of::<N::FILE_DISPOSITION_INFORMATION>() as u32;
                unsafe{(&mut (*a.bytes.get()).0)[offset_of!(N::FILE_DISPOSITION_INFORMATION,DeleteFile)]=1;}
            },
            Api::Roster{slot,..}|Api::Fence{slot}|Api::Security{slot}|Api::SetSecurity{slot,..}=>{a.handle=self.book.handle(*slot).map_err(fault)?;},
            Api::PrimaryGroup|Api::Inherit{..}=>{a.handle=self.book.handle(self.book.process_token.ok_or(Fault::Phase)?).map_err(fault)?;},
        }
        if let Some(mut effect)=primary{
            if self.effects.len()>=65536{return Err(Fault::Capacity)}
            effect.sequence=self.effects.len() as u64+1;effect.flags=0;
            a.effect=Some(self.effects.len());self.effects.push(effect);
        }
        self.active=Some(ManuallyDrop::new(frame));
        if let Api::Open{slot,..}=&self.frame()?.api {let slot=*slot;self.book.slot_mut(slot).map_err(fault)?.state=SlotState::Acquiring;}
        self.book.started=true;self.book.notes_entered+=1;
        let a=self.frame()?;a.phase.set(Phase::Entered);
        if let Some(index)=a.effect{self.effects[index].flags|=1;}
        let a=self.frame()?;
        // SAFETY: every HANDLE/output/name/buffer/descriptor belongs to this
        // original pinned frame/book before entry. No external pointer persists.
        let returned=unsafe{match &a.api {
            Api::Open{access,create,..}=>Returned::Nt(N::NtCreateFile(a.output_handle,access.mask(),&a.attributes,a.iosb.get(),null(),0,
                access.share(),if *create{N::FILE_CREATE}else{N::FILE_OPEN},
                N::FILE_SYNCHRONOUS_IO_NONALERT|if access.directory(){N::FILE_DIRECTORY_FILE}else{N::FILE_NON_DIRECTORY_FILE},null(),0)),
            Api::Read{..}=>Returned::Nt(N::NtReadFile(a.handle,null_mut(),None,null(),a.iosb.get(),a.buffer().cast(),a.length,&a.offset,null())),
            Api::Write{..}=>Returned::Nt(N::NtWriteFile(a.handle,null_mut(),None,null(),a.iosb.get(),a.buffer().cast(),a.length,&a.offset,null())),
            Api::Roster{restart,..}=>crate::boolean(FS::GetFileInformationByHandleEx(a.handle,
                if *restart{FS::FileIdExtdDirectoryRestartInfo}else{FS::FileIdExtdDirectoryInfo},a.buffer().cast(),BUFFER as u32)),
            Api::Fence{..}=>Returned::Nt(N::NtFlushBuffersFileEx(a.handle,0,null(),0,a.iosb.get())),
            Api::Move{..}=>Returned::Nt(N::NtSetInformationFile(a.handle,a.iosb.get(),a.buffer().cast(),a.length,N::FileRenameInformation)),
            Api::Delete{..}=>Returned::Nt(N::NtSetInformationFile(a.handle,a.iosb.get(),a.buffer().cast(),a.length,N::FileDispositionInformation)),
            Api::Security{..}=>Returned::Scalar(A::GetSecurityInfo(a.handle,A::SE_FILE_OBJECT,
                S::OWNER_SECURITY_INFORMATION|S::GROUP_SECURITY_INFORMATION|S::DACL_SECURITY_INFORMATION,
                null_mut(),null_mut(),null_mut(),null_mut(),a.foreign.get())),
            Api::SetSecurity{descriptor,..}=>{
                let control=if descriptor.control&S::SE_DACL_PROTECTED!=0{S::PROTECTED_DACL_SECURITY_INFORMATION}else{S::UNPROTECTED_DACL_SECURITY_INFORMATION};
                crate::boolean(S::SetKernelObjectSecurity(a.handle,S::OWNER_SECURITY_INFORMATION|S::GROUP_SECURITY_INFORMATION|
                    S::DACL_SECURITY_INFORMATION|control,descriptor.raw.as_ptr() as S::PSECURITY_DESCRIPTOR))
            },
            Api::Inherit{parent,directory}=>crate::boolean(S::CreatePrivateObjectSecurityEx(
                parent.raw.as_ptr() as S::PSECURITY_DESCRIPTOR,null_mut(),a.foreign.get(),null(),
                i32::from(*directory),S::SEF_DACL_AUTO_INHERIT,a.handle,&a.mapping)),
            Api::PrimaryGroup=>crate::boolean(S::GetTokenInformation(a.handle,S::TokenPrimaryGroup,a.buffer().cast(),BUFFER as u32,a.count.get())),
        }};
        a.returned.set(Some(returned));a.phase.set(Phase::Returned);
        if matches!(&a.api,Api::Security{..}|Api::Inherit{..}){
            a.foreign_original.set(unsafe{*a.foreign.get()} as usize);
        }
        self.book.notes_returned+=1;
        if let Some(index)=self.frame()?.effect{
            let e=&mut self.effects[index];e.flags|=2;
            match returned{Returned::Nt(v)=>{e.return_kind=1;e.bits=v as u32},
                Returned::Boolean(v,error)=>{e.return_kind=2;e.bits=v as u32;e.error=error},
                Returned::Scalar(v)=>{e.return_kind=3;e.bits=v},_=>return self.unknown()}
        }
        self.finish(returned)
    }
    fn finish(&mut self,returned:Returned)->Result<Complete>{
        match returned{
            Returned::Nt(v) if v!=F::STATUS_SUCCESS && (v as u32>>30)!=3=>return self.unknown(),
            Returned::Boolean(0,F::ERROR_IO_PENDING)=>return self.unknown(),_=>{},
        }
        let api=self.frame()?.api.clone();
        // A failed NT write can still expose meaningful actual progress. Retain
        // the original status/IOSB Information, never infer NO_EFFECT from zero,
        // and never drop an uncorroborated sentinel/pending original frame.
        if let (Api::Write{count,..},Returned::Nt(status))=(&api,returned){
            if status!=F::STATUS_SUCCESS{
                let a=self.frame()?;
                let (ios_status,information)=unsafe{((*a.iosb.get()).Anonymous.Status,(*a.iosb.get()).Information)};
                if nt_failure_information(status,ios_status,information,*count).is_err(){return self.unknown()}
                if let Some(index)=self.frame()?.effect{self.effects[index].information=information as u64;}
                self.finish_frame()?;return Err(Fault::NativeUnavailable)
            }
        }
        if let Api::Open{slot,create,..}=api {
            let status=match returned{Returned::Nt(v)=>v,_=>return self.unknown()};
            let handle=unsafe{*self.book.slot(slot).map_err(fault)?.output.get()};
            if status!=F::STATUS_SUCCESS{
                let a=self.frame()?;
                let (ios_status,information)=unsafe{((*a.iosb.get()).Anonymous.Status,(*a.iosb.get()).Information)};
                // This lane deliberately rejects untouched/pending/mismatching
                // failed-open IOSB DATA. It does NOT assert that every Windows
                // synchronous failure is required to write the IOSB.
                if !handle.is_null()||nt_failure_information(status,ios_status,information,
                    WP::FILE_DOES_NOT_EXIST as usize).is_err(){return self.unknown()}
                if let Some(index)=self.frame()?.effect{self.effects[index].information=information as u64;}
                // Known absence of a returned original HANDLE is distinct from
                // absence of a filesystem effect. No NO_EFFECT flag is created.
                self.book.slot_mut(slot).map_err(fault)?.state=SlotState::NoHandle;
                self.finish_frame()?;return Err(Fault::NativeUnavailable)
            }
            let info=self.corroborate(None)?;
            if !crate::valid_handle(handle)||info!=if create{WP::FILE_CREATED as usize}else{WP::FILE_OPENED as usize}
                ||self.book.duplicate_live(slot,handle){return self.unknown()}
            self.book.slot_mut(slot).map_err(fault)?.state=SlotState::Owned;
            return self.finish_frame();
        }
        match (&api,returned) {
            (Api::Security{..},Returned::Scalar(code))=>{
                let ptr=unsafe{*self.frame()?.foreign.get()};
                if code!=0{if !ptr.is_null(){return self.unknown()}self.finish_frame()?;return Err(Fault::NativeUnavailable)}
                if ptr.is_null(){return self.unknown()}self.frame()?.foreign_owned.set(true);
                // Do not take/drop this foreign owner. foreign() consumes it.
                Err(Fault::Incomplete)
            },
            (Api::Inherit{..},Returned::Boolean(value,_))=>{
                let ptr=unsafe{*self.frame()?.foreign.get()};
                if value==0{if !ptr.is_null(){return self.unknown()}self.finish_frame()?;return Err(Fault::NativeUnavailable)}
                if ptr.is_null(){return self.unknown()}self.frame()?.foreign_owned.set(true);Err(Fault::Incomplete)
            },
            (Api::Move{..},Returned::Nt(F::STATUS_OBJECT_NAME_COLLISION))=>self.finish_frame(),
            (Api::Read{..},Returned::Nt(F::STATUS_END_OF_FILE))=>self.finish_frame(),
            (Api::Read{count,..}|Api::Write{count,..},Returned::Nt(F::STATUS_SUCCESS))=>{
                let n=self.corroborate(Some(*count))?;
                if matches!(&api,Api::Write{..})&&n==0{self.finish_frame()?;return Err(Fault::Io)}
                self.finish_frame()
            },
            (Api::Fence{..}|Api::Move{..}|Api::Delete{..},Returned::Nt(F::STATUS_SUCCESS))=>{self.corroborate(Some(0))?;self.finish_frame()},
            (Api::Roster{..},Returned::Boolean(0,F::ERROR_NO_MORE_FILES))=>self.finish_frame(),
            (Api::Roster{..}|Api::SetSecurity{..},Returned::Boolean(v,_))if v!=0=>self.finish_frame(),
            (Api::PrimaryGroup,Returned::Boolean(v,_))if v!=0=>{
                let n=unsafe{*self.frame()?.count.get()} as usize;if n==0||n>BUFFER{return self.unknown()}self.finish_frame()
            },
            _=>{self.finish_frame()?;Err(Fault::NativeUnavailable)},
        }
    }
    fn corroborate(&mut self,max:Option<usize>)->Result<usize>{
        let a=self.frame()?;let (status,n)=unsafe{((*a.iosb.get()).Anonymous.Status,(*a.iosb.get()).Information)};
        if status!=F::STATUS_SUCCESS||max.is_some_and(|max|n>max){return self.unknown()}
        if let Some(index)=self.frame()?.effect{self.effects[index].information=n as u64;}Ok(n)
    }
    fn foreign(&mut self,api:Api,remaining:usize)->Result<Arc<Descriptor>>{
        // The foreign allocator's original bytes coexist with the complete
        // owned raw/canonical representation. Inherit additionally pins its
        // original parent Arc (conservatively charged by Frame::heap).
        let remaining=remaining.checked_sub(match &api{Api::Inherit{parent,..}=>parent.heap(),_=>0}).ok_or(Fault::Capacity)?;
        self.book.notes_admit_frame().map_err(fault)?;self.book.notes_admit_frame().map_err(fault)?; // original size/release suffix reserved before acquisition
        let started=self.invoke(api,&[],None);
        if !matches!(started,Err(Fault::Incomplete)){return started.and_then(|_|Err(Fault::NativeState))}
        let a=self.frame()?;if !a.foreign_owned.get(){return self.unknown()}
        let ptr=unsafe{*a.foreign.get()};
        a.foreign_size_entered.set(true);self.book.notes_entered+=1;
        let length=unsafe{S::GetSecurityDescriptorLength(ptr)};
        let a=self.frame()?;a.foreign_length.set(Some(length));a.foreign_size_returned.set(true);self.book.notes_returned+=1;
        // Establish the independent release attempt before DATA parsing. Even a
        // capacity/format error cannot erase or skip this original release.
        let body=if length<20 || (length as usize).checked_mul(9).and_then(|n|n.checked_add(4096)).is_none_or(|n|n>remaining){
            Err(Fault::Capacity)
        }else{
            // SAFETY: successful original documented allocator returned a valid
            // descriptor; recorded SDK length is bounded before the owned copy.
            let raw=unsafe{std::slice::from_raw_parts(ptr.cast::<u8>(),length as usize)}.to_vec();
            Descriptor::parse(raw,remaining-length as usize).map(Arc::new)
        };
        let inherited=matches!(&self.frame()?.api,Api::Inherit{..});
        self.frame()?.release_attempted.set(true);self.book.notes_entered+=1;
        let (ok,bits,error)=unsafe{
            if inherited{
                let a=self.frame()?;let v=S::DestroyPrivateObjectSecurity(a.foreign.get());
                let error=if v==0{F::GetLastError()}else{0};(v!=0,v as usize,error)
            }else{
                let v=F::LocalFree(ptr);let error=if v.is_null(){0}else{F::GetLastError()};(v.is_null(),v as usize,error)
            }
        };
        let a=self.frame()?;a.release_bits.set(bits);a.release_error.set(error);a.release_returned.set(true);self.book.notes_returned+=1;
        if !ok{self.mark_unknown();return body.and(Err(Fault::NativeUnknown))}
        self.frame()?.foreign_owned.set(false);self.finish_frame()?;
        body
    }
    pub fn close(&mut self,slot:usize,walk_ancestor:bool)->Result<()>{
        if self.frames_active(){return self.unknown()}
        if *self.close_attempted.get(slot).ok_or(Fault::Key)?{return Err(Fault::OneUse)}
        let state=self.book.slot(slot).map_err(fault)?.state;
        if matches!(state,SlotState::NoHandle|SlotState::Closed){return Err(Fault::OneUse)}
        self.close_attempted[slot]=true;
        if walk_ancestor{
            // Only the original verified lease walk uses this narrow consuming
            // exception; acquisition parent fields are not edited or relabeled.
            if self.scope!=0||state!=SlotState::Owned{return Err(Fault::Phase)}
            let handle=self.book.handle(slot).map_err(fault)?;
            self.book.call(Call::Close(slot),handle,Vec::new()).map(|_|()).map_err(fault)
        }else{self.book.close_index(slot).map_err(fault)}
    }
    pub fn all_resources_closed(&self)->bool{
        !self.native_unknown()&&!self.frames_active()&&self.book.slots.iter().all(|s|matches!(s.state,SlotState::NoHandle|SlotState::Closed))
    }
}
// No custom Drop: active is ManuallyDrop; NativeBook itself never closes in Drop.
// The original context/bridge registry retains Custody even after Unknown/panic.


#[cfg(test)]
mod failure_data_tests{
    use super::*;
    #[test]fn failed_write_keeps_actual_progress_but_never_invents_no_effect(){
        let failed=F::STATUS_ACCESS_DENIED;
        assert_eq!(nt_failure_information(failed,failed,7,8),Ok(7));
        assert_eq!(nt_failure_information(failed,failed,0,8),Ok(0));
        assert_eq!(nt_failure_information(failed,failed,9,8),Err(Fault::NativeUnknown));
        assert_eq!(nt_failure_information(failed,F::STATUS_PENDING,usize::MAX,8),Err(Fault::NativeUnknown));
    }
    #[test]fn failed_open_corroboration_is_only_data_not_a_success_disposition(){
        let failed=F::STATUS_OBJECT_NAME_COLLISION;
        assert_eq!(nt_failure_information(failed,failed,WP::FILE_EXISTS as usize,WP::FILE_DOES_NOT_EXIST as usize),
            Ok(WP::FILE_EXISTS as usize));
        assert_eq!(nt_failure_information(failed,F::STATUS_PENDING,usize::MAX,WP::FILE_DOES_NOT_EXIST as usize),
            Err(Fault::NativeUnknown));
        assert_eq!(nt_failure_information(F::STATUS_SUCCESS,F::STATUS_SUCCESS,0,5),Err(Fault::NativeUnknown));
    }
}
