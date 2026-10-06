//! One nonshipping synchronous packaging child, not a process supervisor.
//! Its parent owns command admission/finality and MUST keep the directory
//! private unless this original child returns0 with the complete final record.
//! Sidecars are outside their own hashed package. No installer authority here.
#![forbid(unsafe_code)]

#[cfg(all(feature="macos-package-producer",target_os="macos",target_pointer_width="64",
    any(target_arch="aarch64",target_arch="x86_64")))]
mod emitter {
    use std::{collections::BTreeMap,ffi::OsString,mem::ManuallyDrop,
        os::{fd::{AsFd,OwnedFd},unix::ffi::OsStrExt},path::{Path,PathBuf},time::{Duration,Instant}};
    use nix::{fcntl::{self,AtFlags,OFlag},sys::{stat::{self,FileStat,Mode},uio::pread},unistd};
    use sha2::{Digest,Sha256};
    use mobile_release_desktop::{macos_install_paths as paths,macos_install_maintenance::MaintenanceTargetData,
        macos_install_producer::{ProducerData,EmissionBindingData,DESCRIPTOR_FILENAME,SIGNATURE_FILENAME,DESCRIPTOR_LIMIT}};
    use mrk_macos_installed_native::{self as native,android_service_management::Decision,
        install_producer::{self,PackageProducerSigner,PackageSignResult,ProducerVerifier,SignatureResult,ProducerCheckpoint}};

    type Result<T> = std::result::Result<T,&'static str>;
    const PACKAGE_LIMIT:u64=512*1024*1024;
    const ORIGINAL_LIMIT:usize=80; // <=64 path directories +4 files + bounded roster opens
    const READ_LIMIT:u64=2*1024*1024*1024;
    fn need(value:bool,reason:&'static str)->Result<()> {if value {Ok(())} else {Err(reason)}}
    fn hash(bytes:&[u8])->String {format!("{:x}",Sha256::digest(bytes))}
    fn target()->MaintenanceTargetData {
        #[cfg(target_arch="aarch64")] {MaintenanceTargetData::Arm64}
        #[cfg(target_arch="x86_64")] {MaintenanceTargetData::Intel}
    }
    fn components(path:&Path)->Result<Vec<String>> {
        let raw=path.as_os_str().as_bytes();
        need(raw.len()>1&&raw.len()<=1024&&raw[0]==b'/'&&!raw.contains(&0),"path-shape")?;
        let parts:Vec<_>=std::str::from_utf8(&raw[1..]).map_err(|_|"path-encoding")?.split('/').collect();
        need(parts.len()<=32&&parts.iter().all(|p|!p.is_empty()&&*p!="."&&*p!=".."&&p.len()<=255),"path-components")?;
        Ok(parts.into_iter().map(str::to_owned).collect())
    }
    fn arguments(args:&[OsString])->Result<(PathBuf,PathBuf)> {
        need(args.len()==4&&args[0]=="--package-root"&&args[2]=="--descriptor-input","arguments")?;
        let root=PathBuf::from(&args[1]);let input=PathBuf::from(&args[3]);
        components(&root)?;components(&input)?;
        need(!input.starts_with(&root),"descriptor-outside-package-root")?;Ok((root,input))
    }
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    struct Identity {dev:i64,ino:u64,mode:u32,uid:u32,gid:u32,links:u64,size:i64,
        mtime:i64,mtime_ns:i64,ctime:i64,ctime_ns:i64,flags:u32}
    impl Identity {
        fn of(s:&FileStat)->Self {Self{dev:i64::from(s.st_dev),ino:s.st_ino,mode:u32::from(s.st_mode),uid:s.st_uid,gid:s.st_gid,
            links:u64::from(s.st_nlink),size:s.st_size,mtime:s.st_mtime,mtime_ns:s.st_mtime_nsec,
            ctime:s.st_ctime,ctime_ns:s.st_ctime_nsec,flags:s.st_flags}}
        fn object(self,other:Self)->bool {self.dev==other.dev&&self.ino==other.ino
            &&self.mode&0o170000==other.mode&0o170000&&self.uid==other.uid&&self.gid==other.gid}
        fn ancestor(self,other:Self)->bool {self.object(other)&&self.mode==other.mode&&self.links==other.links&&self.flags==other.flags}
    }
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    enum State {Reserved,Acquiring,Owned,Closing,Closed,Absent,Unknown}
    fn final_ready_data(unknown:bool,pending:bool,within:bool,states:&[State])->bool {
        !unknown&&!pending&&within&&states.iter().all(|state|matches!(state,State::Closed|State::Absent))
    }
    struct Original {fd:Option<ManuallyDrop<OwnedFd>>,state:State,parent:Option<usize>,name:String,
        identity:Option<Identity>,exact:bool}
    struct Book {originals:Vec<Original>,work:Instant,final_end:Instant,cleanup:bool,
        unknown:bool,pending:bool,issued:u64,uid:u32}
    impl Book {
        fn new(start:Instant)->Result<Self> {
            let uid=unistd::getuid().as_raw();
            need(uid!=0&&uid==unistd::geteuid().as_raw()&&unistd::getgid()==unistd::getegid(),"ordinary-user")?;
            Ok(Self{originals:Vec::with_capacity(ORIGINAL_LIMIT),work:start.checked_add(Duration::from_secs(110)).ok_or("clock")?,
                final_end:start.checked_add(Duration::from_secs(120)).ok_or("clock")?,cleanup:false,unknown:false,pending:false,issued:0,uid})
        }
        fn tick(&self)->Result<()> {
            need(!self.unknown&&!self.pending,"original-unknown")?;
            need(Instant::now()<if self.cleanup {self.final_end} else {self.work},"deadline")
        }
        fn fd(&self,n:usize)->Result<&OwnedFd> {
            let row=self.originals.get(n).ok_or("original-slot")?;
            need(row.state==State::Owned,"original-not-owned")?;
            row.fd.as_deref().ok_or("original-no-handle")
        }
        fn id(&self,n:usize)->Result<Identity> {self.originals.get(n).and_then(|r|r.identity).ok_or("original-unbound")}
        fn observed(&mut self,n:usize)->Result<Identity> {
            self.tick()?;self.pending=true;
            let result=stat::fstat(self.fd(n)?);self.pending=false;
            let value=Identity::of(&result.map_err(|_|"original-stat")?);self.tick()?;Ok(value)
        }
        fn named(&mut self,parent:Option<usize>,name:&str)->Result<Identity> {
            self.tick()?;self.pending=true;
            let result=if let Some(parent)=parent {stat::fstatat(self.fd(parent)?,name,AtFlags::AT_SYMLINK_NOFOLLOW)}
                else {stat::lstat(Path::new("/"))};self.pending=false;
            let value=Identity::of(&result.map_err(|_|"original-name")?);self.tick()?;Ok(value)
        }
        fn check(&mut self,n:usize)->Result<()> {
            let row=&self.originals[n];let (parent,name,exact)=(row.parent,row.name.clone(),row.exact);
            let expected=self.id(n)?;let held=self.observed(n)?;let named=self.named(parent,&name)?;
            need(held==named&&if exact {held==expected} else {expected.ancestor(held)},"original-post")
        }
        fn all(&mut self)->Result<()> {
            self.tick()?;
            for n in 0..self.originals.len() {
                if self.originals[n].state==State::Owned {self.check(n)?;}
                else {need(matches!(self.originals[n].state,State::Reserved|State::Closed|State::Absent),"original-pending")?;}
            }
            self.tick()
        }
        fn reserve(&mut self,parent:Option<usize>,name:&str,exact:bool)->Result<usize> {
            self.tick()?;need(self.originals.len()<ORIGINAL_LIMIT,"original-limit")?;
            let n=self.originals.len();self.originals.push(Original{fd:None,state:State::Reserved,parent,name:name.to_owned(),identity:None,exact});Ok(n)
        }
        fn adopt(&mut self,n:usize,result:nix::Result<OwnedFd>)->Result<()> {
            match result {
                Ok(fd)=>{self.originals[n].fd=Some(ManuallyDrop::new(fd));self.originals[n].state=State::Owned;Ok(())},
                Err(_)=>{self.originals[n].state=State::Absent;Err("original-open")},
            }
        }
        fn open(&mut self,parent:Option<usize>,name:&str,directory:bool,exact:bool)->Result<usize> {
            let n=self.reserve(parent,name,exact)?;let before=self.named(parent,name)?;
            let kind=if directory {0o040000} else {0o100000};
            need(before.mode&0o170000==kind&&(directory||before.links==1),"original-type")?;
            self.originals[n].identity=Some(before);self.tick()?;self.originals[n].state=State::Acquiring;
            let flags=OFlag::O_RDONLY|OFlag::O_NOFOLLOW|OFlag::O_CLOEXEC|OFlag::O_NONBLOCK
                |if directory {OFlag::O_DIRECTORY} else {OFlag::empty()};
            let result=if let Some(parent)=parent {fcntl::openat(self.fd(parent)?,name,flags,Mode::empty())}
                else {fcntl::open(Path::new("/"),flags,Mode::empty())};
            self.adopt(n,result)?;self.check(n)?;Ok(n)
        }
        fn parents(&mut self,path:&Path,final_directory:bool)->Result<usize> {
            let parts=components(path)?;let count=parts.len()-usize::from(!final_directory);
            let mut n=self.open(None,"/",true,false)?;let mut at=PathBuf::from("/");self.parent_policy(n,&at)?;
            for part in &parts[..count] {
                n=self.open(Some(n),part,true,false)?;at.push(part);self.parent_policy(n,&at)?;
            }
            Ok(n)
        }
        fn parent_policy(&mut self,n:usize,path:&Path)->Result<()> {
            let id=self.id(n)?;
            // Shared trusted ancestors may change directory timestamps; bind
            // their original inode/type/owner/mode/links/flags, not others' files.
            let sticky=path==Path::new("/private/tmp")&&id.uid==0&&id.mode&0o7777==0o1777;
            need(id.mode&0o170000==0o040000&&(id.uid==0||id.uid==self.uid)
                &&(id.mode&0o7022==0||sticky),"parent-protection")
        }
        fn private_root(&mut self,n:usize)->Result<()> {
            let id=self.observed(n)?;need(id.uid==self.uid&&id.mode&0o177777==0o040700&&id.flags==0,"private-root")?;
            self.originals[n].identity=Some(id);self.originals[n].exact=true;self.attributes(n)?;self.check(n)
        }
        fn attributes(&mut self,n:usize)->Result<()> {
            self.tick()?;self.pending=true;
            let acl=native::empty_acl_observed(self.fd(n)?.as_fd());self.pending=false;
            if let Err(error)=acl {
                if error.free_result!=0||error.refusal_code.is_none() {self.unknown=true;}
                return Err("private-acl");
            }
            self.tick()?;self.pending=true;let result=native::no_xattrs(self.fd(n)?.as_fd());self.pending=false;
            result.map_err(|_|"private-attributes")?;self.tick()
        }
        fn file_policy(&mut self,n:usize,limit:u64)->Result<()> {
            let id=self.id(n)?;
            need(id.mode&0o177777==0o100444&&id.uid==self.uid&&id.links==1&&id.flags==0
                &&id.size>0&&id.size as u64<=limit,"private-file")?;self.attributes(n)?;self.check(n)
        }
        fn read(&mut self,n:usize,keep:bool)->Result<(String,Vec<u8>)> {
            self.check(n)?;let size=u64::try_from(self.id(n)?.size).map_err(|_|"read-size")?;
            need(size<=PACKAGE_LIMIT&&(!keep||size<=DESCRIPTOR_LIMIT as u64),"read-limit")?;
            let mut saved=Vec::with_capacity(if keep {size as usize} else {0});
            let mut sha=Sha256::new();let mut offset=0u64;let mut buffer=[0u8;65536];
            loop {
                self.tick()?;let wanted=usize::try_from((size-offset).min(buffer.len() as u64)).map_err(|_|"read-size")?;
                let wanted=if wanted==0 {1} else {wanted};
                self.issued=self.issued.checked_add(wanted as u64).ok_or("read-budget")?;need(self.issued<=READ_LIMIT,"read-budget")?;
                self.pending=true;let result=pread(self.fd(n)?,&mut buffer[..wanted],offset as i64);self.pending=false;
                let count=result.map_err(|_|"read-original")?;self.tick()?;
                if count==0 {need(offset==size,"read-short")?;break;}
                need(offset+count as u64<=size,"read-extent")?;
                if offset==0&&!keep {need(count>=4&&&buffer[..4]==b"xar!","completed-package-magic")?;}
                sha.update(&buffer[..count]);if keep {saved.extend_from_slice(&buffer[..count]);}offset+=count as u64;
            }
            self.check(n)?;Ok((format!("{:x}",sha.finalize()),saved))
        }
        fn close(&mut self,n:usize)->bool {
            if self.unknown||self.pending {return false;}
            if matches!(self.originals[n].state,State::Closed|State::Absent) {return true;}
            if self.originals[n].state==State::Reserved {self.originals[n].state=State::Absent;return true;}
            if self.originals[n].state!=State::Owned {self.unknown=true;return false;}
            let post=self.check(n).is_ok();
            if self.unknown||self.pending {return false;}
            // A known POST refusal does not invent FD uncertainty; close this
            // original, but retain the overall failure. Never retry a close.
            if self.tick().is_err() {self.unknown=true;return false;}
            self.originals[n].state=State::Closing;
            let Some(fd)=self.originals[n].fd.take() else {self.unknown=true;return false;};
            let result=unistd::close(ManuallyDrop::into_inner(fd));
            self.originals[n].state=if result.is_ok() {State::Closed} else {State::Unknown};
            if result.is_err()||self.tick().is_err() {self.unknown=true;return false;}
            post
        }
        fn finish(&mut self)->bool {
            self.cleanup=true;let mut ok=self.all().is_ok();
            for n in (0..self.originals.len()).rev() {ok=self.close(n)&&ok;}
            let states:[State;ORIGINAL_LIMIT]=std::array::from_fn(|n|self.originals.get(n).map_or(State::Absent,|row|row.state));
            ok&&final_ready_data(self.unknown,self.pending,Instant::now()<self.final_end,&states)
        }
        fn roster(&mut self,root:usize,wanted:&[(&str,u64)])->Result<()> {
            self.check(root)?;let row=&self.originals[root];let(parent,name)=(row.parent,row.name.clone());
            let reader=self.open(parent,&name,true,true)?;need(self.id(reader)?==self.id(root)?,"roster-original")?;
            let result=(||->Result<()> {
                let mut found=BTreeMap::new();let mut buffer=[0u8;65536];
                for turn in 0..2 {
                    self.tick()?;self.pending=true;let result=native::directory_block(self.fd(reader)?.as_fd(),&mut buffer);self.pending=false;
                    let used=result.map_err(|_|"root-roster")?;self.tick()?;
                    if used==0 {
                        need(found.len()==wanted.len()&&wanted.iter().all(|(name,ino)|found.get(*name)==Some(ino)),"root-roster")?;
                        return Ok(());
                    }
                    need(turn==0,"root-roster-bound")?;let mut offset=0;
                    while offset<used {
                        need(used-offset>=11,"root-roster-record")?;
                        let ino=u64::from_ne_bytes(buffer[offset..offset+8].try_into().map_err(|_|"root-roster-record")?);
                        let kind=buffer[offset+8];let len=usize::from(u16::from_ne_bytes([buffer[offset+9],buffer[offset+10]]));
                        let end=offset.checked_add(11+len).filter(|end|*end<=used).ok_or("root-roster-record")?;
                        let name=std::str::from_utf8(&buffer[offset+11..end]).map_err(|_|"root-roster-name")?;offset=end;
                        if name=="."||name==".." {continue;}
                        need(kind==nix::libc::DT_REG&&wanted.iter().any(|(value,_)|*value==name)&&found.len()<3
                            &&ino!=0&&found.insert(name.to_owned(),ino).is_none(),"root-roster-member")?;
                    }
                }
                Err("root-roster-eof")
            })();
            let closed=self.close(reader);result?;need(closed,"root-roster-close")?;self.check(root)
        }
        fn create(&mut self,root:usize,name:&str,bytes:&[u8])->Result<usize> {
            need(matches!(name,DESCRIPTOR_FILENAME|SIGNATURE_FILENAME)&&!bytes.is_empty()&&bytes.len()<=DESCRIPTOR_LIMIT,"sidecar-shape")?;
            self.all()?;let n=self.reserve(Some(root),name,true)?;let root_before=self.id(root)?;
            self.originals[n].state=State::Acquiring;
            let flags=OFlag::O_RDWR|OFlag::O_CREAT|OFlag::O_EXCL|OFlag::O_NOFOLLOW|OFlag::O_CLOEXEC|OFlag::O_NONBLOCK;
            let result=fcntl::openat(self.fd(root)?,name,flags,Mode::from_bits_truncate(0o600));self.adopt(n,result)?;
            let initial=self.observed(n)?;need(initial.uid==self.uid&&initial.mode&0o177777==0o100600
                &&initial.links==1&&initial.size==0&&initial.flags==0,"sidecar-created")?;
            self.originals[n].identity=Some(initial);
            let now=self.observed(root)?;need(root_before.ancestor(now),"created-root-original")?;
            self.originals[root].identity=Some(now);self.check(root)?;self.check(n)?;
            let mut offset=0;
            while offset<bytes.len() {
                self.check(n)?;self.tick()?;self.pending=true;let result=unistd::write(self.fd(n)?,&bytes[offset..]);self.pending=false;
                let written=result.map_err(|_|"sidecar-write")?;need(written>0&&written<=bytes.len()-offset,"sidecar-write-bound")?;
                offset+=written;let observed=self.observed(n)?;
                need(initial.ancestor(observed)&&observed.size==offset as i64,"sidecar-written-original")?;
                self.originals[n].identity=Some(observed);self.check(n)?;
            }
            self.tick()?;self.pending=true;let sealed=stat::fchmod(self.fd(n)?,Mode::from_bits_truncate(0o444));self.pending=false;
            sealed.map_err(|_|"sidecar-mode")?;
            let observed=self.observed(n)?;need(initial.object(observed)&&observed.mode&0o177777==0o100444
                &&observed.links==1&&observed.flags==0&&observed.size==bytes.len() as i64,"sidecar-sealed-original")?;
            self.originals[n].identity=Some(observed);self.check(n)?;self.attributes(n)?;
            self.tick()?;self.pending=true;let persisted=native::sync(self.fd(n)?.as_fd(),true);self.pending=false;
            persisted.map_err(|_|"sidecar-persist")?;self.check(n)?;
            let (digest,readback)=self.read(n,true)?;need(digest==hash(bytes)&&readback==bytes,"sidecar-readback")?;
            Ok(n)
        }
        fn native_point(&mut self,point:ProducerCheckpoint)->Decision {
            let (phase,at,custody)=match point {ProducerCheckpoint::Before{phase,custody}=>(phase,None,custody),
                ProducerCheckpoint::Returned{phase,at,custody}=>(phase,Some(at),custody)};
            self.cleanup=phase.is_cleanup();
            if custody.unknown||custody.in_call||custody.gate_entered {self.unknown=true;return Decision::Unknown;}
            if at.is_some_and(|at|at>=if self.cleanup {self.final_end} else {self.work}) {return Decision::Stop;}
            if self.all().is_ok() {Decision::Proceed} else if self.unknown||self.pending {Decision::Unknown} else {Decision::Stop}
        }
    }
    // This synchronous child never adopts or deletes a partially emitted root.
    // ManuallyDrop retains uncertain originals; process exit is not a pass.
    pub fn run()->Result<()> {
        let start=Instant::now();let args:Vec<_>=std::env::args_os().skip(1).take(5).collect();let(root_path,input_path)=arguments(&args)?;
        let mut book=Book::new(start)?;
        let result=(||->Result<(String,String,String,usize,usize)> {
            book.tick()?;book.pending=true;let platform=native::platform();book.pending=false;platform.map_err(|_|"platform")?;
            book.tick()?;book.pending=true;let source=install_producer::source_signer_data();book.pending=false;
            let source=source.ok_or("source-signer-unavailable")?;book.tick()?;
            let root=book.parents(&root_path,true)?;book.private_root(root)?;
            let package=book.open(Some(root),"Install.pkg",false,true)?;book.file_policy(package,PACKAGE_LIMIT)?;
            book.roster(root,&[("Install.pkg",book.id(package)?.ino)])?;
            let parent=book.parents(&input_path,false)?;
            let input_name=input_path.file_name().and_then(|v|v.to_str()).ok_or("descriptor-name")?;
            let input=book.open(Some(parent),input_name,false,true)?;book.file_policy(input,DESCRIPTOR_LIMIT as u64)?;
            let (package_hash,_)=book.read(package,false)?;let(descriptor_hash,descriptor)=book.read(input,true)?;
            let data=ProducerData::parse_data(&descriptor,target()).map_err(|_|"descriptor-data")?;
            let expected=EmissionBindingData{target:target(),release:paths::RELEASE,package_version:paths::PACKAGE_VERSION,
                source_commit:option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT").ok_or("source-current-unavailable")?,
                protocol_sha256:paths::PROTOCOL_SHA,
                runtime_manifest_sha256:option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256").ok_or("source-runtime-unavailable")?,
                inventory_sha256:option_env!("MRK_MACOS_INSTALL_INVENTORY_SHA256").ok_or("source-inventory-unavailable")?,
                completed_package_sha256:&package_hash,team:source.team_data(),leaf_sha1:source.leaf_sha1_data(),leaf_sha256:source.leaf_sha256_data()};
            data.validate_emission_data(&expected).map_err(|_|"emission-binding")?;
            let mut signer=PackageProducerSigner::new();
            let signed=signer.sign_and_close(&descriptor,&mut |point|book.native_point(point));
            if !signer.settled() {book.unknown=true;return Err("signer-finality");}
            let PackageSignResult::SignatureCreated(signature)=signed else {return Err("signature-not-created");};
            let mut verifier=ProducerVerifier::new();
            let verified=verifier.verify_and_close(&descriptor,signature.as_bytes(),&mut |point|book.native_point(point));
            if !verifier.settled() {book.unknown=true;return Err("verification-finality");}
            need(verified==SignatureResult::SignatureVerified,"signature-verification")?;
            book.cleanup=false;book.all()?;
            need(book.read(package,false)?.0==package_hash&&book.read(input,true)?==(descriptor_hash.clone(),descriptor.clone()),"signed-input-post")?;
            let json=book.create(root,DESCRIPTOR_FILENAME,&descriptor)?;
            book.roster(root,&[("Install.pkg",book.id(package)?.ino),(DESCRIPTOR_FILENAME,book.id(json)?.ino)])?;
            let sig=book.create(root,SIGNATURE_FILENAME,signature.as_bytes())?;
            book.roster(root,&[("Install.pkg",book.id(package)?.ino),(DESCRIPTOR_FILENAME,book.id(json)?.ino),(SIGNATURE_FILENAME,book.id(sig)?.ino)])?;
            book.tick()?;book.pending=true;let persisted=native::sync(book.fd(root)?.as_fd(),false);book.pending=false;
            persisted.map_err(|_|"sidecar-root-persist")?;
            need(book.read(package,false)?.0==package_hash&&book.read(input,true)?==(descriptor_hash.clone(),descriptor.clone()),"final-input-post")?;
            book.all()?;
            Ok((package_hash,descriptor_hash,hash(signature.as_bytes()),descriptor.len(),signature.as_bytes().len()))
        })();
        let settled=book.finish();
        let(package,descriptor,signature,descriptor_bytes,signature_bytes)=result?;need(settled,"file-finality")?;
        // Only bounded public digests/lengths, emitted after actual consuming
        // native/file closes. The parent still must observe original child0.
        use std::io::Write;
        let line=format!("{{\"schemaVersion\":1,\"kind\":\"mrk-package-producer-emitted\",\"packageSha256\":\"{package}\",\"descriptorSha256\":\"{descriptor}\",\"signatureSha256\":\"{signature}\",\"descriptorBytes\":{descriptor_bytes},\"signatureBytes\":{signature_bytes}}}\n");
        need(line.len()<=512&&Instant::now()<book.final_end,"final-report-bound")?;
        let mut stdout=std::io::stdout().lock();stdout.write_all(line.as_bytes()).map_err(|_|"final-report-write")?;
        stdout.flush().map_err(|_|"final-report-flush")?;need(Instant::now()<book.final_end,"final-report-deadline")
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn fixed_cli_and_original_state_data_refuse_ambient_or_partial_routes() {
            let good=["--package-root","/private/tmp/task/final","--descriptor-input","/private/tmp/task/descriptor-input.json"].map(OsString::from);
            assert!(arguments(&good).is_ok());
            for path in ["relative","/","/a/../b","/a//b","/a/./b","/a/","/a\0b"] {assert!(components(Path::new(path)).is_err());}
            assert!(components(Path::new(&format!("/{}","a/".repeat(33)))).is_err());
            for index in [0,2] {let mut bad=good.clone();bad[index]=OsString::from("--identity");assert!(arguments(&bad).is_err());}
            let mut inside=good.clone();inside[3]=OsString::from("/private/tmp/task/final/producer.json");assert!(arguments(&inside).is_err());
            assert!(arguments(&good[..3]).is_err());
            assert!(final_ready_data(false,false,true,&[]));
            assert!(final_ready_data(false,false,true,&[State::Closed,State::Absent]));
            for state in [State::Reserved,State::Acquiring,State::Owned,State::Closing,State::Unknown] {
                assert!(!final_ready_data(false,false,true,&[State::Closed,state]));
            }
            // Fixed Original states, no actual file, Keychain or process calls.
            for (unknown,pending,within) in [(true,false,true),(false,true,true),(false,false,false)] {
                assert!(!final_ready_data(unknown,pending,within,&[State::Closed,State::Absent]));
            }
        }
    }
}

fn main()->std::process::ExitCode {
    #[cfg(all(feature="macos-package-producer",target_os="macos",target_pointer_width="64",
        any(target_arch="aarch64",target_arch="x86_64")))]
    {match emitter::run() {Ok(())=>std::process::ExitCode::SUCCESS,Err(_)=>{
        eprintln!("package-producer-refused");std::process::ExitCode::from(78)}}}
    #[cfg(not(all(feature="macos-package-producer",target_os="macos",target_pointer_width="64",
        any(target_arch="aarch64",target_arch="x86_64"))))]
    {eprintln!("package-producer-unavailable");std::process::ExitCode::from(78)}
}
