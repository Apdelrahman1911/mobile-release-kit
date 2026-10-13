//! Sealed History runtime slot under the existing Supervisor. Nested in
//! installed_runtime_macos to reuse its actual Book, native ACL and close ledger.
//! User-project source policy remains in the distinct SourceBook companion.
use super::*;
use crate::{github_history_protocol as wire,github_history_session::Nomination};
use std::sync::Arc;
use crate::asset_source::HistorySources;

const PROVIDER_PROFILE:&str=include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/../packaging/macos-history-provider.profile"));
const SOURCE_FUTURE_ORIGINALS:usize=8; // existing child/stdin/stdout/stderr + startup/settlement reserve
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct ProfileData {schema_version:u32,version:String,
    #[serde(deserialize_with="crate::github_connection_protocol::nullable")] source_manifest_sha256:Option<String>,targets:Targets}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Targets {
    #[serde(rename="aarch64-apple-darwin",deserialize_with="crate::github_connection_protocol::nullable")] arm64:Option<String>,
    #[serde(rename="x86_64-apple-darwin",deserialize_with="crate::github_connection_protocol::nullable")] x86_64:Option<String>,
}
#[derive(Clone,PartialEq,Eq)]
pub(crate) struct ProviderNomination {source_sha:String,executable_sha:String,profile:wire::NativeProfile}
impl ProviderNomination {
    fn parse(raw:&[u8],profile:wire::NativeProfile)->std::result::Result<Option<Self>,BridgeError>{
        if raw.len()>2048{return Err(BridgeError::protocol());}
        let value=strict_json(raw)?;
        if !value.is_object()||!value.get("targets").is_some_and(serde_json::Value::is_object){return Err(BridgeError::protocol());}
        let data:ProfileData=serde_json::from_value(value).map_err(|_|BridgeError::protocol())?;
        if data.schema_version!=1||data.version!="2.88.1"{return Err(BridgeError::protocol());}
        match (data.source_manifest_sha256,data.targets.arm64,data.targets.x86_64){
            (None,None,None)=>Ok(None),
            (Some(source),Some(arm),Some(intel)) if [&source,&arm,&intel].iter().all(|s|wire::hex(s,64))=>
                Ok(Some(Self{source_sha:source,executable_sha:if profile==wire::NativeProfile::Arm64{arm}else{intel},profile})),
            _=>Err(BridgeError::protocol()),
        }
    }
    pub(crate) fn compiled()->std::result::Result<Option<Self>,BridgeError>{
        let profile=if cfg!(target_arch="aarch64"){wire::NativeProfile::Arm64}else{wire::NativeProfile::X86_64};
        Self::parse(PROVIDER_PROFILE.as_bytes(),profile)
    }
    pub(crate) fn profile(&self)->wire::NativeProfile{self.profile}
    pub(super) fn retained_bytes(&self)->Option<usize>{self.source_sha.capacity().checked_add(self.executable_sha.capacity())}
    fn matches_manifest(&self,file:&PayloadFile)->bool{file.path=="tools/gh"&&file.sha256==self.executable_sha&&file.size>0&&file.size<=wire::PROVIDER_LIMIT}
    fn provider(&self,id:Identity)->Result<wire::Provider>{
        let identity=wire::FileIdentity{device:u64::try_from(id.dev).map_err(native_error)?.to_string(),inode:id.ino.to_string(),mode:u32::from(id.mode),
            uid:id.uid,gid:id.gid,nlink:id.links.to_string(),bytes:u64::try_from(id.size).map_err(native_error)?.to_string(),mtime_seconds:id.mtime.to_string(),
            ctime_seconds:id.ctime.to_string(),mtime_nanos:u32::try_from(id.mtime_ns).map_err(native_error)?,ctime_nanos:u32::try_from(id.ctime_ns).map_err(native_error)?,flags:id.flags};
        let value=wire::Provider{relative_path:"tools/gh".into(),version:"2.88.1".into(),target:self.profile.target().into(),
            source_manifest_sha256:self.source_sha.clone(),sha256:self.executable_sha.clone(),identity};
        if !value.valid(self.profile){return Err(AdmissionFailure::Identity);}Ok(value)
    }
}

// Shared inventory SHAPE check only. All roles already audit every manifest
// member; ordinary roles must not reject a genuinely nominated 0555 provider
// in that same runtime. Only the explicit History Book retains/lends it.
pub(super) fn provider_inventory_mode(path:&str,file:Option<&PayloadFile>)->Result<bool>{
    if path!="tools/gh"{return Ok(false);}
    let nomination=ProviderNomination::compiled().map_err(native_error)?.ok_or(AdmissionFailure::Inventory)?;
    if !file.is_some_and(|file|nomination.matches_manifest(file)){return Err(AdmissionFailure::Inventory);}Ok(true)
}
pub(super) fn provider_retained(book:&Book,path:&str)->bool{
    book.history_nomination.is_some()&&(path=="tools"||path=="tools/gh")
}
pub(super) fn provider_observed(book:&mut Book,path:&str,index:usize,file:Option<&PayloadFile>)->Result<()>{
    if path!="tools/gh"{return Ok(());}
    if let Some(nomination)=&book.history_nomination{
        if book.history_provider.is_some()||!file.is_some_and(|f|nomination.matches_manifest(f)){return Err(AdmissionFailure::Inventory);}
        nomination.provider(book.records[index].identity.ok_or(AdmissionFailure::Identity)?)?;
        book.history_provider=Some(index);
    }
    Ok(())
}

// The History-only containing debit is first-party owned/control storage,
// not allocator/Go/OS RSS. It keeps the existing64MiB Document cap unchanged.
// Preparse:1MiB raw+bounded20k Value nodes/keys and their byte copies; native
// original8256 records+names and SnapshotBook frame; checked prospective tree
// strings/containers24MiB;17 walk blocks+read/hash+framing. Actual allocations
// are measured again. Deep/unusually duplicated prefixes refuse before sets.
const TREE_CONTROL_LIMIT:usize=24*1024*1024;
const CODE_CONTROL_RESERVE:usize=48*1024*1024;
pub(super) fn history_manifest_reserve(files:&[PayloadFile])->Result<usize>{
    let mut names=0usize;let mut bytes=0usize;
    for file in files{
        if !runtime::safe_payload_path(&file.path)||file.path.len()>512{return Err(AdmissionFailure::Bounds);}
        let mut path=file.path.as_str();
        loop{
            names=names.checked_add(1).ok_or(AdmissionFailure::Bounds)?;
            bytes=bytes.checked_add(path.len()).ok_or(AdmissionFailure::Bounds)?;
            if names>8192{return Err(AdmissionFailure::Bounds);}
            match path.rsplit_once('/') {Some((parent,_))=>path=parent,None=>break}
        }
    }
    // Files/dirs/folded/observed/local and original names. Charge duplicate
    // prefixes too: no credit is inferred from later BTree de-duplication.
    let total=bytes.checked_mul(6).and_then(|v|v.checked_add(names.checked_mul(6*256)?))
        .and_then(|v|v.checked_add(files.len().checked_mul(std::mem::size_of::<PayloadFile>()+64)?))
        .ok_or(AdmissionFailure::Bounds)?;
    if total>TREE_CONTROL_LIMIT{return Err(AdmissionFailure::Bounds);}Ok(total)
}
pub(super) fn history_prefix_insert_allowed(book:&Book,names:usize,already_present:bool)->Result<()>{
    if book.history_nomination.is_some()&&!already_present&&names>=8192{return Err(AdmissionFailure::Bounds);}Ok(())
}

// One allocation, shared by actual slot and owner. Its constructor stays here
// after real inspection; no public/caller Context+digest factory exists.
pub(crate) struct SealedHistoryRequest {initial:wire::Initial,raw:Vec<u8>,digest:String}
impl SealedHistoryRequest {
    pub(crate) fn initial(&self)->&wire::Initial{&self.initial}
    pub(crate) fn raw(&self)->&[u8]{&self.raw}
    pub(crate) fn digest(&self)->&str{&self.digest}
    pub(crate) fn retained_bytes(&self)->Option<usize>{std::mem::size_of::<Self>().checked_add(self.initial.retained_heap_bytes()?)?
        .checked_add(self.raw.capacity())?.checked_add(self.digest.capacity())}
}
struct Original {code:Book,sources:HistorySources,selection:Option<VerifiedRuntime>,sealed:Option<Arc<SealedHistoryRequest>>,claimed:bool,no_effect:bool}
impl Original {
    fn new()->Self{Self{code:Book::new(),sources:HistorySources::new(),selection:None,sealed:None,claimed:false,no_effect:false}}
    fn retained_bytes(&self)->Option<usize>{std::mem::size_of::<Self>().checked_add(self.code.retained_heap_bytes()?)?
        .checked_add(self.sources.retained_bytes()?)?.checked_add(self.selection.as_ref().map_or(Some(0),selection_heap_bytes)?)?
        .checked_add(self.sealed.as_ref().map_or(Some(0),|v|v.retained_bytes())?)}
}
pub(crate) struct GitHubHistoryInstalledRuntime {original:Original}
pub(crate) struct GitHubHistoryRuntimeSlots {inspection:Option<Original>,acquisition:Option<GitHubHistoryInstalledRuntime>,settlement:bool}
fn source_error(reason:crate::asset_commands::Reason)->BridgeError{
    use crate::asset_commands::Reason;
    match reason{Reason::CleanupUnknown=>BridgeError::cleanup_unknown(),Reason::Capacity|Reason::MaterialLimit=>
        BridgeError::new("history_resources_unavailable","The fixed History source budget was not admitted."),
        Reason::UserCancelled=>BridgeError::new("cancelled","The original History source read was stopped."),
        _=>BridgeError::new("history_source_changed","The original registered History source did not remain admissible.")}
}
impl GitHubHistoryRuntimeSlots {
    pub(crate) fn working_reservation_bytes()->Option<usize>{
        CODE_CONTROL_RESERVE.checked_add(std::mem::size_of::<Self>())?
            .checked_add(HistorySources::working_reservation_bytes()?)?
            .checked_add(wire::CONFIG_LIMIT as usize)?.checked_add(wire::WIRE_COPY_RESERVE)
    }
    pub(crate) fn reserve_once(&mut self)->Result<usize>{
        if !self.never_started(){return Err(AdmissionFailure::AlreadyUsed);}
        let original=self.original_mut()?;
        original.code.records.try_reserve_exact(8256).map_err(native_error)?;
        if original.code.records.capacity()>8256{return Err(AdmissionFailure::Bounds);}
        Self::working_reservation_bytes().ok_or(AdmissionFailure::Bounds)
    }
    pub(crate) fn new()->Self{Self{inspection:Some(Original::new()),acquisition:None,settlement:false}}
    fn original(&self)->Result<&Original>{match (&self.inspection,&self.acquisition){(Some(v),None)=>Ok(v),(None,Some(v))=>Ok(&v.original),_=>Err(AdmissionFailure::Unknown)}}
    fn original_mut(&mut self)->Result<&mut Original>{match (&mut self.inspection,&mut self.acquisition){(Some(v),None)=>Ok(v),(None,Some(v))=>Ok(&mut v.original),_=>Err(AdmissionFailure::Unknown)}}
    pub(crate) fn never_started(&self)->bool{!self.settlement&&self.acquisition.is_none()&&self.inspection.as_ref().is_some_and(|v|
        v.code.never_started()&&v.sources.not_started()&&v.selection.is_none()&&v.sealed.is_none())}
    pub(crate) fn first_failure(&self)->Option<(AdmissionFailure,Instant)>{self.original().ok().and_then(|v|v.code.first_failure())}
    pub(crate) fn retained_bytes(&self)->Option<usize>{std::mem::size_of::<Self>().checked_add(self.original().ok()?.retained_bytes()?)}
    pub(crate) fn arm_acl_once(&mut self,end:Instant,stop:&watch::Receiver<bool>)->Result<()>{
        if !self.never_started(){return Err(AdmissionFailure::AlreadyUsed);}self.original_mut()?.code.arm_acl_once(end,stop)
    }
    pub(crate) fn inspect_once(&mut self,profile:runtime::GitHubHistoryInstalledProfile,nomination:&Nomination,id:&str,
        clock:wire::Clock,end:Instant,stop:&watch::Receiver<bool>)->std::result::Result<VerifiedRuntime,BridgeError>{
        if self.settlement||self.acquisition.is_some(){return Err(BridgeError::cleanup_unknown());}
        let original=self.inspection.as_mut().filter(|v|v.selection.is_none()&&v.sealed.is_none()&&v.code.inspection_ready()).ok_or_else(BridgeError::cleanup_unknown)?;
        let provider=profile.provider_nomination()?;
        original.code.history_nomination=Some(provider.clone());
        original.selection=Some(profile.selection()?);
        let selection=original.selection.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
        original.code.inspect(selection,end,stop).map_err(|e|{original.code.note_acl(e,Instant::now());BridgeError::unavailable("The History runtime source failed original inspection.")})?;
        let index=original.code.history_provider.ok_or_else(||BridgeError::new("history_provider_unavailable","The fixed managed History provider is absent."))?;
        let provider=provider.provider(original.code.records[index].identity.ok_or_else(BridgeError::cleanup_unknown)?).map_err(|_|BridgeError::cleanup_unknown())?;
        let other=original.code.retained_original_count().and_then(|n|n.checked_add(SOURCE_FUTURE_ORIGINALS)).ok_or_else(BridgeError::cleanup_unknown)?;
        if let Err(reason)=original.sources.inspect(&nomination.root,&nomination.work_nonce,other,&mut ||checkpoint(end,stop).is_err()){
            original.code.note_acl(checkpoint(end,stop).err().unwrap_or(AdmissionFailure::Identity),Instant::now());return Err(source_error(reason));
        }
        let (root_identity,config_identity,raw_sha,work_identity,work_root)=original.sources.observed().map_err(source_error)?;
        let context=nomination.context(&raw_sha);
        let initial=wire::Initial{protocol:wire::PROTOCOL.into(),id:id.into(),owner_generation:nomination.owner_generation.clone(),context,
            native:wire::Native{profile:provider_nomination_profile(&provider)?,project_root:nomination.root.path.to_str().ok_or_else(BridgeError::invalid)?.into(),
                root_identity,config_identity,work_root,work_identity,provider,parent_descriptor_reservation:original.sources.parent_reservation().ok_or_else(BridgeError::cleanup_unknown)?,clock}};
        let raw=initial.encode()?;let digest=wire::request_digest(&raw);
        original.sealed=Some(Arc::new(SealedHistoryRequest{initial,raw,digest}));
        original.code.point(end,stop).map_err(|_|BridgeError::cleanup_unknown())?;
        if original.retained_bytes().zip(Self::working_reservation_bytes()).is_none_or(|(actual,maximum)|actual>maximum){
            original.code.note_acl(AdmissionFailure::Bounds,Instant::now());return Err(BridgeError::new("history_resources_unavailable","The actual History source storage exceeded its containing debit."));
        }
        Ok(VerifiedRuntime{python:selection.python.clone(),bootstrap:selection.bootstrap.clone(),core:selection.core.clone(),cwd:selection.cwd.clone()})
    }
    pub(crate) fn sealed(&self)->Result<Arc<SealedHistoryRequest>>{self.original()?.sealed.clone().ok_or(AdmissionFailure::AlreadyUsed)}
    pub(crate) fn transfer_once(&mut self)->Result<()>{
        if self.settlement||self.acquisition.is_some()||!self.inspection.as_ref().is_some_and(|v|v.code.inspected&&v.code.admission_custody_ready()&&v.sealed.is_some()){
            return Err(AdmissionFailure::AlreadyUsed);}
        let original=self.inspection.take().ok_or(AdmissionFailure::Unknown)?;
        self.acquisition=Some(GitHubHistoryInstalledRuntime{original});Ok(())
    }
    pub(crate) fn capability(&mut self)->Result<&mut GitHubHistoryInstalledRuntime>{if self.settlement{return Err(AdmissionFailure::AlreadyUsed);}
        self.acquisition.as_mut().ok_or(AdmissionFailure::AlreadyUsed)}
    pub(crate) fn no_child_effect(&self)->bool{self.original().is_ok_and(|v|!v.claimed||v.no_effect)}
    pub(crate) fn mark_interrupted(&mut self){if let Ok(v)=self.original_mut(){v.code.unknown=true;}}
    pub(crate) fn settle_originals(&mut self,expired:&mut dyn FnMut(Option<(AdmissionFailure,Instant)>)->bool)->CloseOutcome{
        if self.settlement{return CloseOutcome::Unknown;}self.settlement=true;
        let Ok(v)=self.original_mut()else{return CloseOutcome::Unknown;};
        if v.sources.pending_native(){v.code.unknown=true;return CloseOutcome::Unknown;}
        // Same clock closure and first native failure; source consuming closes
        // precede code close and all calls remain in this registered original.
        let first=Cell::new(v.code.first_failure());
        let source=v.sources.settle(&mut ||expired(first.get()),&mut |reason|{
            let failure=if reason==crate::asset_commands::Reason::CleanupUnknown{AdmissionFailure::Unknown}else{AdmissionFailure::Native};
            first.set(earliest_failure(first.get(),Some((failure,Instant::now()))));
        });
        if let Some((failure,at))=first.get(){v.code.note_acl(failure,at);}
        if source.is_err()&&!v.sources.settled(){v.code.unknown=true;}
        let code=v.code.settle(expired);
        if code==CloseOutcome::Settled&&v.sources.settled(){CloseOutcome::Settled}else{CloseOutcome::Unknown}
    }
    pub(crate) fn settled(&self)->bool{self.settlement&&self.original().is_ok_and(|v|v.code.settled()&&v.sources.settled())}
}
fn provider_nomination_profile(provider:&wire::Provider)->std::result::Result<wire::NativeProfile,BridgeError>{
    match provider.target.as_str(){"aarch64-apple-darwin"=>Ok(wire::NativeProfile::Arm64),"x86_64-apple-darwin"=>Ok(wire::NativeProfile::X86_64),_=>Err(BridgeError::protocol())}
}
impl GitHubHistoryInstalledRuntime {
    pub(crate) fn prepare_once_observed(&mut self,end:Instant,stop:&watch::Receiver<bool>,publish:&mut dyn FnMut(Option<(AdmissionFailure,Instant)>))->Result<&VerifiedRuntime>{
        let result=if self.original.claimed{Err(AdmissionFailure::AlreadyUsed)}else{self.original.code.prepare(end,stop)};
        if let Err(failure)=&result{self.original.code.note_acl(*failure,Instant::now());}
        publish(self.original.code.first_failure());result?;
        let source=self.original.sources.post_observed(&mut ||checkpoint(end,stop).is_err())
            .map_err(|_|checkpoint(end,stop).err().unwrap_or(AdmissionFailure::Identity));
        if let Err(failure)=source{self.original.code.note_acl(failure,Instant::now());}
        publish(self.original.code.first_failure());source?;
        self.original.selection.as_ref().ok_or(AdmissionFailure::Unknown)
    }
    pub(crate) fn post_source(&mut self,end:Instant,stop:&watch::Receiver<bool>)->Result<()>{
        let result=(||{
            self.original.code.point(end,stop)?;
            for (index,row) in self.original.code.records.iter().enumerate(){if row.state==State::Owned{self.original.code.check_name(index,end,stop)?;}}
            self.original.sources.post_observed(&mut ||checkpoint(end,stop).is_err())
                .map_err(|_|checkpoint(end,stop).err().unwrap_or(AdmissionFailure::Identity))
        })();
        if let Err(failure)=result{self.original.code.note_acl(failure,Instant::now());}result
    }
    pub(crate) fn claim_once(&mut self)->Result<()>{
        if self.original.claimed||!self.original.code.prepared||!self.original.code.admission_custody_ready()||self.original.sealed.is_none(){return Err(AdmissionFailure::AlreadyUsed);}
        self.original.claimed=true;Ok(())
    }
    pub(crate) fn record_closed_spawn_gate(&mut self){self.original.no_effect=true;}
}
#[cfg(test)]
pub(crate) fn history_installed_slot_data_checks(){
    let slot=GitHubHistoryRuntimeSlots::new();assert!(slot.never_started()&&!slot.settled()&&slot.no_child_effect());
    assert!(slot.sealed().is_err());
    let absent=br#"{"schemaVersion":1,"version":"2.88.1","sourceManifestSha256":null,"targets":{"aarch64-apple-darwin":null,"x86_64-apple-darwin":null}}"#;
    assert!(ProviderNomination::parse(absent,wire::NativeProfile::Arm64).unwrap().is_none());
    assert!(ProviderNomination::compiled().is_ok());
    let raw=serde_json::json!({"schemaVersion":1,"version":"2.88.1","sourceManifestSha256":"a".repeat(64),
        "targets":{"aarch64-apple-darwin":"b".repeat(64),"x86_64-apple-darwin":"c".repeat(64)}});
    let nomination=ProviderNomination::parse(&serde_json::to_vec(&raw).unwrap(),wire::NativeProfile::Arm64).unwrap().unwrap();
    let file=PayloadFile{path:"tools/gh".into(),sha256:"b".repeat(64),size:1};assert!(nomination.matches_manifest(&file));
    assert!(!nomination.matches_manifest(&PayloadFile{path:"tools/other".into(),..file}));
    let mut partial=raw.clone();partial["targets"]["x86_64-apple-darwin"]=serde_json::Value::Null;
    assert!(ProviderNomination::parse(&serde_json::to_vec(&partial).unwrap(),wire::NativeProfile::Arm64).is_err());
    let stale=PayloadFile{path:"tools/gh".into(),sha256:"d".repeat(64),size:1};assert!(!nomination.matches_manifest(&stale));
    let too_large=PayloadFile{path:"tools/gh".into(),sha256:"b".repeat(64),size:wire::PROVIDER_LIMIT+1};assert!(!nomination.matches_manifest(&too_large));
    let simple=PayloadFile{path:"core.zip".into(),sha256:"e".repeat(64),size:1};assert!(history_manifest_reserve(&[simple]).is_ok());
    let deep=PayloadFile{path:(0..40).map(|_|"component").collect::<Vec<_>>().join("/"),sha256:"e".repeat(64),size:1};
    let repeated=(0..2048).map(|_|PayloadFile{path:deep.path.clone(),sha256:deep.sha256.clone(),size:deep.size}).collect::<Vec<_>>();
    assert!(history_manifest_reserve(&repeated).is_err());
    let mut ordinary=Book::new();assert!(history_prefix_insert_allowed(&ordinary,8192,false).is_ok());
    ordinary.history_nomination=Some(nomination.clone());assert!(history_prefix_insert_allowed(&ordinary,8192,false).is_err());
    assert!(history_prefix_insert_allowed(&ordinary,8192,true).is_ok());
    let mut sequence=raw;sequence["targets"]=serde_json::json!(["b".repeat(64),"c".repeat(64)]);
    assert!(ProviderNomination::parse(&serde_json::to_vec(&sequence).unwrap(),wire::NativeProfile::Arm64).is_err());
}
