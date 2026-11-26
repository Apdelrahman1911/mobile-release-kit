// Original Rust policy/close bodies over inert observations. No OS/file access.
#![allow(dead_code)]
use std::{cell::{Cell,RefCell},path::Path,time::Instant};
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum AdmissionFailure { Identity,Ownership,Bounds,Native,Unknown,Stopped,Deadline }
type Result<T> = std::result::Result<T,AdmissionFailure>;
fn native_error<T>(_:T)->AdmissionFailure {AdmissionFailure::Native}
mod macos_install_paths {
    pub const APP_NAME:&str="Mobile Release Kit.app";
    pub const PAYLOAD_NAME:&str="MobileReleaseKitPayload.app";
}
mod macos_existing_app_metadata {
    pub const MACL_BYTES_LIMIT:usize=1024;
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    pub struct SnapshotData {length:usize,bytes:[u8;1024]}
    impl SnapshotData {
        pub fn from_observed_bytes_data(value:&[u8])->Option<Self> {
            if value.len()>1024{return None;}
            let mut bytes=[0;1024];bytes[..value.len()].copy_from_slice(value);
            Some(Self{length:value.len(),bytes})
        }
    }
}
mod zeroize {
    pub struct Zeroizing<T>(T);
    impl<T> Zeroizing<T>{pub fn new(value:T)->Self{Self(value)}}
    impl<T> std::ops::Deref for Zeroizing<T>{type Target=T;fn deref(&self)->&T{&self.0}}
    impl<T> std::ops::DerefMut for Zeroizing<T>{fn deref_mut(&mut self)->&mut T{&mut self.0}}
}
mod watch {pub struct Receiver<T>(pub T);}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct Identity {dev:i32,ino:u64,mode:u16,uid:u32,gid:u32,flags:u32,ctime:i64}
struct FileStat {identity:Identity,st_flags:u32}
impl From<Identity> for FileStat {fn from(identity:Identity)->Self{Self{identity,st_flags:identity.flags}}}
impl Identity {fn of(s:&FileStat)->Self{s.identity}}
fn identity(ino:u64)->Identity {Identity{dev:1,ino,mode:0o040555,uid:0,gid:0,flags:0,ctime:1}}
#[derive(Clone,Copy,PartialEq,Eq)]
enum State {Reserved,Acquiring,Owned,NoHandle,Closing,Closed,Unknown}
#[derive(Clone)] enum Attributes {Absent,Macl(Vec<u8>),Other,Error}
struct Record {
    name:String,parent:Option<usize>,identity:Option<Identity>,android_flags:Option<u32>,
    actual:Cell<Identity>,named:Cell<Identity>,attributes:RefCell<Attributes>,
    fd:Option<usize>,state:State,replace_during_read:Cell<bool>,change_during_read:Cell<bool>,
}
struct Book {
    records:Vec<Record>,bundle_metadata:[Option<(Identity,macos_existing_app_metadata::SnapshotData)>;3],
    unknown:bool,stopped:Cell<bool>,acl_refused:Cell<bool>,native_reads:Cell<usize>,
}
#[derive(Clone,Copy)] struct Fd<'a>{book:&'a Book,index:usize}
impl<'a> Fd<'a>{fn as_fd(self)->Self{self}}
#[allow(non_camel_case_types)] enum AtFlags {AT_SYMLINK_NOFOLLOW}
mod stat {
    use super::*;
    pub fn fstat(fd:Fd<'_>)->std::result::Result<FileStat,()>{Ok(fd.book.records[fd.index].actual.get().into())}
    pub fn fstatat(fd:Fd<'_>,name:&str,_:AtFlags)->std::result::Result<FileStat,()>{
        fd.book.records.iter().rev().find(|r|r.parent==Some(fd.index)&&r.name==name).map(|r|r.named.get().into()).ok_or(())
    }
    pub fn lstat(_: &Path)->std::result::Result<FileStat,()>{Ok(identity(1).into())}
}
mod native {
    use super::*;
    pub fn no_xattrs(fd:Fd<'_>)->std::result::Result<(),()>{
        if matches!(*fd.book.records[fd.index].attributes.borrow(),Attributes::Absent){Ok(())}else{Err(())}
    }
    pub fn existing_app_macl(fd:Fd<'_>,bytes:&mut[u8;1024])->std::result::Result<usize,()>{
        fd.book.native_reads.set(fd.book.native_reads.get()+1);
        let record=&fd.book.records[fd.index];
        if record.actual.get().mode&0o170000!=0o040000{return Err(());}
        let used=match &*record.attributes.borrow(){
            Attributes::Absent=>0,
            Attributes::Macl(value) if !value.is_empty() && value.len()<=1024=>{
                bytes[..value.len()].copy_from_slice(value);value.len()
            },_=>return Err(()),
        };
        if record.replace_during_read.replace(false){
            let mut changed=record.named.get();changed.ino+=99;record.named.set(changed);
        }
        if record.change_during_read.replace(false){
            let mut changed=record.actual.get();changed.ctime+=1;
            record.actual.set(changed);record.named.set(changed);
        }
        Ok(used)
    }
}
thread_local! {static CLOSES:Cell<usize>=const{Cell::new(0)};static CLOSE_FAIL:Cell<bool>=const{Cell::new(false)};}
mod unistd {
    pub fn close(_:usize)->std::result::Result<(),()>{
        super::CLOSES.with(|n|n.set(n.get()+1));
        if super::CLOSE_FAIL.with(|n|n.get()){Err(())}else{Ok(())}
    }
}
impl Book {
    fn new()->Self{Self{records:vec![],bundle_metadata:[None;3],unknown:false,
        stopped:Cell::new(false),acl_refused:Cell::new(false),native_reads:Cell::new(0)}}
    fn push(&mut self,parent:Option<usize>,name:&str)->usize{
        let index=self.records.len();let id=identity(index as u64+1);
        self.records.push(Record{name:name.into(),parent,identity:Some(id),android_flags:None,
            actual:Cell::new(id),named:Cell::new(id),attributes:RefCell::new(Attributes::Absent),fd:Some(index),
            state:State::Owned,replace_during_read:Cell::new(false),change_during_read:Cell::new(false)});index
    }
    fn fd(&self,index:usize)->Result<Fd<'_>>{
        self.records.get(index).filter(|r|r.fd.is_some()).map(|_|Fd{book:self,index}).ok_or(AdmissionFailure::Unknown)
    }
    fn point(&self,_:Instant,_:&watch::Receiver<bool>)->Result<()>{
        if self.stopped.get(){Err(AdmissionFailure::Stopped)}else{Ok(())}
    }
    fn filesystem(&self,_:usize,_:Identity,stop:&mut dyn FnMut()->bool)->Result<()>{
        if stop(){Err(AdmissionFailure::Stopped)}else if self.acl_refused.get(){Err(AdmissionFailure::Ownership)}else{Ok(())}
    }
    fn check_name(&self,index:usize,end:Instant,stop:&watch::Receiver<bool>)->Result<()>{
        self.check_name_with(index,&mut ||self.point(end,stop))
    }
    /* MRK_BOOK_POLICY_ORIGINAL */
    /* MRK_BOOK_CLOSE_ORIGINAL */
}
struct AndroidServiceIdentitySlots;
impl AndroidServiceIdentitySlots {
    /* MRK_SERVICE_MODE_ORIGINAL */
}
fn fixture()->(Book,[usize;3]) {
    let mut book=Book::new();let mut parent=None;
    for name in ["/","Library","Application Support","MobileReleaseKit",macos_install_paths::APP_NAME] {
        parent=Some(book.push(parent,name));
    }
    let app=parent.unwrap();let contents=book.push(Some(app),"Contents");let helpers=book.push(Some(contents),"Helpers");
    let payload=book.push(Some(helpers),macos_install_paths::PAYLOAD_NAME);
    let launcher=book.push(Some(helpers),"MobileReleaseKitLauncher.app");
    (book,[app,payload,launcher])
}
fn set_identity(book:&mut Book,index:usize,id:Identity){
    let r=&mut book.records[index];r.identity=Some(id);r.actual.set(id);r.named.set(id);
}
fn main(){
    let now=Instant::now();let stop=watch::Receiver(false);
    // All three exact roles accept absence or bounded MACL; every other role stays strict.
    for slot in 0..3 {for length in [0,1,72,1024] {
        let (mut book,roots)=fixture();let root=roots[slot];
        assert_eq!(book.installed_bundle_slot(root),Some(slot));
        if length>0{*book.records[root].attributes.borrow_mut()=Attributes::Macl(vec![7;length]);}
        assert_eq!(AndroidServiceIdentitySlots::mode(&mut book,root,0o555,now,&stop),Ok(()));
        assert_eq!(book.check_name(root,now,&stop),Ok(()));
        assert!(book.bundle_metadata[slot].is_some());
        CLOSES.with(|n|n.set(0));assert!(book.close(root,&mut |_|false));assert!(book.close(root,&mut |_|false));
        CLOSES.with(|n|assert_eq!(n.get(),1));
    }}
    for slot in 0..3 {for value in [Attributes::Macl(vec![]),Attributes::Macl(vec![7;1025]),Attributes::Other,Attributes::Error] {
        let (mut book,roots)=fixture();*book.records[roots[slot]].attributes.borrow_mut()=value;
        assert!(book.installed_attributes(roots[slot],now,&stop).is_err());
        assert!(book.bundle_metadata[slot].is_none());
    }}
    // Every ancestor spelling is material, including the product root and slash.
    for index in 0..8 {
        let (mut book,roots)=fixture();book.records[index].name.push('x');let root=roots[1];
        *book.records[root].attributes.borrow_mut()=Attributes::Macl(vec![7;72]);
        assert_eq!(book.installed_bundle_slot(root),None);
        assert!(book.installed_attributes(root,now,&stop).is_err());assert_eq!(book.native_reads.get(),0);
    }
    let (mut book,roots)=fixture();let fake=book.push(Some(roots[0]),"Unrelated.app");
    for root in [0,1,2,3,5,6,fake] {
        *book.records[root].attributes.borrow_mut()=Attributes::Macl(vec![7;72]);
        assert!(book.installed_attributes(root,now,&stop).is_err());
    }
    // Canonical spelling cannot admit a file, bad owner/group/mode, or flags.
    for change in 0..5 {
        let (mut book,roots)=fixture();let root=roots[0];let mut id=book.records[root].identity.unwrap();
        match change{0=>id.mode=0o100555,1=>id.uid=501,2=>id.gid=20,3=>id.mode=0o040755,_=>id.flags=1}
        set_identity(&mut book,root,id);
        assert_eq!(book.installed_attributes(root,now,&stop),Err(AdmissionFailure::Ownership));
    }
    for initial in [false,true] {for changed in [Attributes::Absent,Attributes::Macl(vec![8;72]),Attributes::Macl(vec![7;73]),Attributes::Other] {
        let (mut book,roots)=fixture();let root=roots[0];
        if initial{*book.records[root].attributes.borrow_mut()=Attributes::Macl(vec![7;72]);}
        assert_eq!(book.installed_attributes(root,now,&stop),Ok(()));
        if !initial && matches!(changed,Attributes::Absent){continue;}
        *book.records[root].attributes.borrow_mut()=changed;
        assert!(book.check_name(root,now,&stop).is_err());
        assert!(book.installed_attributes(root,now,&stop).is_err());
        CLOSES.with(|n|n.set(0));assert!(!book.close(root,&mut |_|false));assert!(!book.close(root,&mut |_|false));
        CLOSES.with(|n|assert_eq!(n.get(),1));
    }}
    for fault in 0..4 {
        let (mut book,roots)=fixture();let root=roots[0];
        match fault {0=>book.stopped.set(true),1=>book.acl_refused.set(true),
            2=>book.records[root].replace_during_read.set(true),_=>book.records[root].change_during_read.set(true)}
        assert!(book.installed_attributes(root,now,&stop).is_err());
    }
    // Reopen the same role: neither a new inode nor new metadata becomes baseline.
    for changed_inode in [false,true] {
        let (mut book,roots)=fixture();let old=roots[0];
        *book.records[old].attributes.borrow_mut()=Attributes::Macl(vec![7;72]);
        assert_eq!(book.installed_attributes(old,now,&stop),Ok(()));assert!(book.close(old,&mut |_|false));
        let root=book.push(Some(3),macos_install_paths::APP_NAME);let mut id=book.records[old].identity.unwrap();
        if changed_inode{id.ino+=99;}set_identity(&mut book,root,id);
        *book.records[root].attributes.borrow_mut()=Attributes::Macl(vec![8;72]);
        assert!(book.installed_attributes(root,now,&stop).is_err());
    }
    // Expiry before/during the added read retains the original FD; it never
    // permits a close after that late read or reports a settled original.
    for state in [State::Reserved,State::Acquiring,State::NoHandle,State::Closing,State::Closed,State::Unknown] {
        let (mut book,roots)=fixture();let root=roots[0];
        assert_eq!(book.installed_attributes(root,now,&stop),Ok(()));
        book.records[root].state=state;let reads=book.native_reads.get();
        CLOSES.with(|n|n.set(0));
        let _=book.close(root,&mut |_|panic!("non-owned record must not sample a close clock"));
        assert_eq!(book.native_reads.get(),reads);assert!(book.records[root].fd.is_some());
        CLOSES.with(|n|assert_eq!(n.get(),0));
    }
    for expire_at in [1,2,6] {
        let (mut book,roots)=fixture();let root=roots[0];
        assert_eq!(book.installed_attributes(root,now,&stop),Ok(()));
        let reads=book.native_reads.get();let mut samples=0;
        CLOSES.with(|n|n.set(0));
        assert!(!book.close(root,&mut |_|{samples+=1;samples>=expire_at}));
        assert!(book.records[root].fd.is_some());assert!(book.records[root].state==State::Owned);
        CLOSES.with(|n|assert_eq!(n.get(),0));
        if expire_at==1{assert_eq!(book.native_reads.get(),reads);}
    }
    let (mut book,roots)=fixture();let root=roots[0];
    assert_eq!(book.installed_attributes(root,now,&stop),Ok(()));
    CLOSES.with(|n|n.set(0));CLOSE_FAIL.with(|n|n.set(true));
    assert!(!book.close(root,&mut |_|false));assert!(!book.close(root,&mut |_|false));CLOSES.with(|n|assert_eq!(n.get(),1));
    println!("MRK_CANONICAL_BUNDLE_METADATA_DATA=PASS");
}
