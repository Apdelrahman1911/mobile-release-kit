//! Fixed nonprivileged seal-image originals, subordinate to one Setup owner.
//! No runtime path/argv/keyring/provider selector or independent deadline.
use super::*;

const HELPER_NAME:&str="mrk-github-seal";
const MAX_HELPER_BYTES:u64=16*1024*1024;
const RESERVED_ROWS:usize=8256;
const RESERVED_NAME_BYTES:usize=65536;

pub(crate) fn publisher_bound()->bool{expected().is_ok()}
fn expected()->Result<(&'static str,u64)>{
    let digest=option_env!("MRK_MACOS_GITHUB_SEAL_SHA256").filter(|v|sha(v)).ok_or(AdmissionFailure::Inventory)?;
    let bytes=option_env!("MRK_MACOS_GITHUB_SEAL_BYTES").and_then(|v|v.parse::<u64>().ok())
        .filter(|v|*v>0&&*v<=MAX_HELPER_BYTES).ok_or(AdmissionFailure::Inventory)?;
    Ok((digest,bytes))
}
// Strings are produced only from the genuine protected Contents ancestor.
// They are not cloneable launch authority and never leave this private module.
pub(crate) struct GitHubSealLaunch {pub(crate) program:PathBuf,pub(crate) cwd:PathBuf}
pub(crate) struct GitHubSealSlots {
    original:Book,helper:Option<usize>,launch:Option<GitHubSealLaunch>,
    reserved:bool,reservation:usize,inspected:bool,prepared:bool,claimed:bool,postchecked:bool,settlement:bool,
    first:Option<(AdmissionFailure,Instant)>,
}
impl GitHubSealSlots {
    pub(crate) fn new()->Self{Self{original:Book::new(),helper:None,launch:None,reserved:false,reservation:0,inspected:false,
        prepared:false,claimed:false,postchecked:false,settlement:false,first:None}}
    fn fail(&mut self,failure:AdmissionFailure)->AdmissionFailure{if self.first.is_none(){self.first=Some((failure,Instant::now()));}failure}
    pub(crate) fn first_failure(&self)->Option<(AdmissionFailure,Instant)>{match(self.first,self.original.first_failure()){
        (Some(a),Some(b))=>Some(if a.1<=b.1{a}else{b}),(a,b)=>a.or(b),}}
    pub(crate) fn never_started(&self)->bool{!self.inspected&&!self.claimed&&!self.settlement&&self.original.never_started()}
    pub(crate) fn reserve_once(&mut self)->Result<usize>{
        if self.reserved||!self.never_started(){return Err(self.fail(AdmissionFailure::AlreadyUsed))}
        self.original.records.try_reserve_exact(RESERVED_ROWS).map_err(|_|self.fail(AdmissionFailure::Bounds))?;
        self.reserved=true;
        self.reservation=self.retained_bytes()?.checked_add(RESERVED_NAME_BYTES)
            .and_then(|v|v.checked_add(native::vault_filesystem::SNAPSHOT_FRAME_BYTES)).ok_or(AdmissionFailure::Bounds)?;
        Ok(self.reservation)
    }
    pub(crate) fn retained_bytes(&self)->Result<usize>{
        let mut value=std::mem::size_of::<Self>().checked_add(self.original.retained_heap_bytes().ok_or(AdmissionFailure::Bounds)?)
            .ok_or(AdmissionFailure::Bounds)?;
        if let Some(launch)=&self.launch{value=value.checked_add(launch.program.capacity()).and_then(|n|n.checked_add(launch.cwd.capacity()))
            .ok_or(AdmissionFailure::Bounds)?;}
        Ok(value)
    }
    pub(crate) fn retained_original_count(&self)->Option<usize>{self.original.retained_original_count()}
    pub(crate) fn inspect_once(&mut self,end:Instant,stop:&watch::Receiver<bool>)->Result<()>{
        if !self.reserved||!self.never_started(){return Err(self.fail(AdmissionFailure::AlreadyUsed))}
        self.inspected=true;
        let result=(||{
            let (digest,size)=expected()?;
            self.original.arm_acl_once(end,stop)?;
            let protected=self.original.protected_app_once(end,stop)?;
            let helpers=self.original.open(Some(protected.contents),"Helpers",true,end,stop)?;
            self.original.fixed_code_mode(helpers,0o555,end,stop)?;
            let helper=self.original.open(Some(helpers),HELPER_NAME,false,end,stop)?;
            self.helper=Some(helper);self.original.fixed_code_mode(helper,0o555,end,stop)?;
            let id=self.original.records[helper].identity.ok_or(AdmissionFailure::Identity)?;
            if id.size<0||id.size as u64!=size{return Err(AdmissionFailure::Inventory)}
            let (actual,body)=self.original.read(helper,size,false,end,stop)?;
            if actual!=digest||!body.is_empty(){return Err(AdmissionFailure::Inventory)}
            let contents=Path::new(crate::macos_install_paths::PAYLOAD_EXECUTABLE).parent().and_then(Path::parent)
                .ok_or(AdmissionFailure::Inventory)?;
            self.launch=Some(GitHubSealLaunch{program:contents.join("Helpers").join(HELPER_NAME),cwd:contents.to_owned()});
            self.original.inspected=true;
            // Verify actual original Vec/name/path/ACL backing against the
            // predispatch debit before any helper or plaintext writer exists.
            if self.retained_bytes()?>self.reservation{return Err(AdmissionFailure::Bounds)}
            self.post(end,stop)
        })();
        result.map_err(|e|self.fail(e))
    }
    fn post(&self,end:Instant,stop:&watch::Receiver<bool>)->Result<()>{
        self.original.point(end,stop)?;
        for (i,row) in self.original.records.iter().enumerate(){if row.state==State::Owned{self.original.check_name(i,end,stop)?;}}
        self.original.point(end,stop)
    }
    pub(crate) fn prepare_once_observed(&mut self,end:Instant,stop:&watch::Receiver<bool>,
        observed:&mut dyn FnMut(Option<(AdmissionFailure,Instant)>))->Result<&GitHubSealLaunch>{
        let result=(||{
            if !self.inspected||self.prepared||self.claimed||self.first_failure().is_some(){return Err(AdmissionFailure::AlreadyUsed)}
            self.original.prepare(end,stop)?;
            if self.launch.is_none(){return Err(AdmissionFailure::Unknown)}
            self.prepared=true;Ok(())
        })();
        if let Err(failure)=result{self.fail(failure);}
        // Publish genuine F before this synchronous acquisition hands off any
        // result. An arbitrarily delayed task join cannot restart cleanup.
        observed(self.first_failure());
        result?;self.launch.as_ref().ok_or(AdmissionFailure::Unknown)
    }
    pub(crate) fn claim_once(&mut self)->Result<()>{
        if !self.prepared||self.claimed||self.first_failure().is_some()||self.settlement{return Err(self.fail(AdmissionFailure::AlreadyUsed))}
        self.claimed=true;Ok(())
    }
    pub(crate) fn post_original_return(&mut self,end:Instant,stop:&watch::Receiver<bool>)->Result<()>{
        if !self.claimed||self.postchecked||self.settlement{return Err(self.fail(AdmissionFailure::AlreadyUsed))}
        self.postchecked=true;let result=self.post(end,stop);result.map_err(|e|self.fail(e))
    }
    pub(crate) fn settle_originals(&mut self,expired:&mut dyn FnMut(Option<(AdmissionFailure,Instant)>)->bool)->CloseOutcome{
        if self.settlement{return CloseOutcome::Unknown}
        self.settlement=true;
        // Command path storage is retired after the consuming child admission;
        // original file rows retain their identity/close evidence independently.
        self.launch=None;
        let first=self.first;
        self.original.settle(&mut|book_first|expired(earliest_failure(first,book_first)))
    }
    pub(crate) fn settled(&self)->bool{self.settlement&&self.launch.is_none()&&self.original.settled()}
    #[cfg(test)]
    pub(crate) fn failure_data_checks(){
        let mut slots=Self::new();let(_,stop)=watch::channel(false);let before=Instant::now();
        let mut observed=None;let mut published_at=None;
        assert!(slots.prepare_once_observed(before+std::time::Duration::from_secs(10),&stop,&mut|first|{
            observed=first;published_at=Some(Instant::now());
        }).is_err());
        let(failure,at)=observed.unwrap();assert_eq!(failure,AdmissionFailure::AlreadyUsed);
        assert!(before<=at&&at<=published_at.unwrap());assert_eq!(slots.first_failure(),observed);
        let mut calls=0;
        assert_eq!(slots.settle_originals(&mut|first|{calls+=1;assert_eq!(first,observed);false}),CloseOutcome::Settled);
        assert!(calls>0);assert_eq!(slots.first_failure(),observed);
    }
}

// Secret-only preparation of the EXISTING first Setup slot. Its closed rows
// survive the first original closes while the helper executes; they are not
// silently refunded as an empty/retired Book. Ordinary Setup never calls this.
impl GitHubSetupRuntimeSlots {
    pub(crate) fn reserve_secret_prepare(&mut self)->Result<usize>{self.reserve_setup_material()}
    pub(crate) fn reserve_variable(&mut self)->Result<usize>{self.reserve_setup_material()}
    fn reserve_setup_material(&mut self)->Result<usize>{
        if !self.never_started(){return Err(AdmissionFailure::AlreadyUsed)}
        let book=self.inspection.as_mut().ok_or(AdmissionFailure::Unknown)?;
        if book.records.capacity()!=0{return Err(AdmissionFailure::AlreadyUsed)}
        book.records.try_reserve_exact(RESERVED_ROWS).map_err(|_|AdmissionFailure::Bounds)?;
        // safe_payload_path limits each runtime path (therefore each leaf) to
        // 512 bytes; fixed installed ancestors are shorter. Original/path
        // allocations are measured after inspection before any credential GO.
        self.retained_bytes().ok_or(AdmissionFailure::Bounds)?
            .checked_add(RESERVED_ROWS.checked_mul(512).ok_or(AdmissionFailure::Bounds)?)
            .and_then(|v|v.checked_add(native::vault_filesystem::SNAPSHOT_FRAME_BYTES))
            // Four selected paths plus the one actual inspection return copy.
            .and_then(|v|v.checked_add(8*1024)).ok_or(AdmissionFailure::Bounds)
    }
}
