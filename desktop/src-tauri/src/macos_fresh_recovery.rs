//! Closed output-enrollment DATA. These records do not own a file, gate,
//! producer, writer or rename and never authorize no-history recovery.
use std::collections::{BTreeMap,BTreeSet};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use crate::{macos_install_maintenance::{ActionData,MaintenanceTargetData,ReleaseData,ReleaseSetData},
    macos_install_record as record,macos_install_transaction::{self as transaction,FreshBirthData,FreshBirthIdentityData,IntentData},
    macos_persistent_identity::VolumeUuid,protocol::strict_json,runtime::safe_macos_install_path};

pub const ORIGIN_NAME:&str="fresh-output-origin-v1.json";
pub const JOURNAL_NAME:&str="fresh-output-enrollment-v1";
pub const ORIGIN_LIMIT:usize=transaction::INTENT_LIMIT;
pub const ENTRY_LIMIT:usize=2048;
pub const ENTRY_MIN:usize=256;
pub const JOURNAL_LIMIT:usize=record::INVENTORY_LIMIT;
pub const ENROLLMENT_LIMIT:usize=record::ENTRY_LIMIT;
pub const PHASE_NAMES:[&str;4]=["staging-created.json","prepared.json","runtime-publication-confirmed.json","both-publications-confirmed.json"];
type Result<T>=std::result::Result<T,&'static str>;
fn need(ok:bool,why:&'static str)->Result<()>{if ok{Ok(())}else{Err(why)}}
fn hex(v:&str,n:usize)->bool{v.len()==n&&v.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))&&v.bytes().any(|b|b!=b'0')}
fn digest(raw:&[u8])->String{format!("{:x}",Sha256::digest(raw))}
fn encode<T:Serialize>(value:&T,limit:usize)->Result<Vec<u8>>{
    let mut raw=serde_json::to_vec(value).map_err(|_|"fresh-output-json")?;raw.push(b'\n');
    need(raw.len()<=limit,"fresh-output-bound")?;Ok(raw)
}
fn value(raw:&[u8],limit:usize)->Result<serde_json::Value>{
    need(!raw.is_empty()&&raw.len()<=limit,"fresh-output-bound")?;
    let v=strict_json(raw).map_err(|_|"fresh-output-json")?;
    need(v.is_object(),"fresh-output-shape")?;Ok(v)
}
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct IdentityWire{device:i64,inode:u64,birth_seconds:i64,birth_nanoseconds:i64,volume_uuid:VolumeUuid}
impl IdentityWire{
    fn from_data(v:FreshBirthIdentityData)->Self{let(device,inode,birth_seconds,birth_nanoseconds,volume_uuid)=v.fields_data();Self{device,inode,birth_seconds,birth_nanoseconds,volume_uuid}}
    fn data(self)->Result<FreshBirthIdentityData>{FreshBirthIdentityData::from_original_fields_data(self.device,self.inode,self.birth_seconds,self.birth_nanoseconds,self.volume_uuid).map_err(|_|"fresh-output-identity")}
    fn key(self)->([u8;16],u64,i64,i64){(self.volume_uuid.bytes_data(),self.inode,self.birth_seconds,self.birth_nanoseconds)}
}
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct OriginWire{
    schema_version:u32,kind:String,target:String,invocation:String,request_id:String,intent_sha256:String,
    next:ReleaseData,fresh_birth:serde_json::Value,
    stage:IdentityWire,origin_file:IdentityWire,enrollment_file:IdentityWire,intent_file:IdentityWire,
}
/// Immutable canonical origin with its own pre-write reserved file identity.
pub struct OutputOriginData{wire:OriginWire,birth:FreshBirthData,sha256:String}
impl OutputOriginData{
    fn validate(mut wire:OriginWire,intent:&IntentData,selected:&ReleaseSetData)->Result<Self>{
        need(wire.schema_version==1&&wire.kind=="mrk-macos-fresh-output-origin-v1"
            &&wire.target==selected.target_data().target()&&intent.action_data()==ActionData::FreshInstall
            &&wire.invocation==intent.invocation_data()&&wire.request_id==intent.request_id_data()
            &&wire.intent_sha256==intent.digest_data()&&wire.next==*intent.next_data()
            &&selected.contains_data(&wire.next),"fresh-output-origin-binding")?;
        let birth=FreshBirthData::parse_data(&serde_json::to_vec(&wire.fresh_birth).map_err(|_|"fresh-output-origin-birth")?)
            .map_err(|_|"fresh-output-origin-birth")?;
        need(intent.fresh_birth_data().as_ref()==Some(&birth),"fresh-output-origin-birth")?;
        // Specify the embedded Value order even if another dependency enables
        // serde_json/preserve_order. Birth itself was already closed/validated.
        let mut ordered=serde_json::Map::new();
        for (key,value) in wire.fresh_birth.as_object().ok_or("fresh-output-origin-birth")?.iter().collect::<BTreeMap<_,_>>(){
            let value=if let Some(fields)=value.as_object(){
                let mut row=serde_json::Map::new();
                for (key,value) in fields.iter().collect::<BTreeMap<_,_>>(){row.insert(key.clone(),value.clone());}
                serde_json::Value::Object(row)
            }else{value.clone()};
            ordered.insert(key.clone(),value);
        }
        wire.fresh_birth=serde_json::Value::Object(ordered);
        let mut seen=BTreeSet::new();
        for identity in birth.identities_data().into_iter().map(IdentityWire::from_data)
            .chain([wire.stage,wire.origin_file,wire.enrollment_file,wire.intent_file]){
            identity.data()?;
            need(identity.volume_uuid==wire.stage.volume_uuid&&seen.insert(identity.key()),"fresh-output-origin-alias")?;
        }
        let sha256=digest(&encode(&wire,ORIGIN_LIMIT)?);Ok(Self{wire,birth,sha256})
    }
    /// Identities are comparison inputs; native constructors must supply actual
    /// held/name observations after exclusive creation and before body writes.
    pub fn new_data(intent:&IntentData,selected:&ReleaseSetData,identities:[FreshBirthIdentityData;4])->Result<Self>{
        let birth=intent.fresh_birth_data().ok_or("fresh-output-birth-required")?;
        let fresh_birth=strict_json(&birth.canonical_bytes_data().map_err(|_|"fresh-output-origin-birth")?)
            .map_err(|_|"fresh-output-origin-birth")?;
        let [stage,origin_file,enrollment_file,intent_file]=identities.map(IdentityWire::from_data);
        Self::validate(OriginWire{schema_version:1,kind:"mrk-macos-fresh-output-origin-v1".into(),
            target:selected.target_data().target().into(),invocation:intent.invocation_data().into(),
            request_id:intent.request_id_data().into(),intent_sha256:intent.digest_data().into(),
            next:intent.next_data().clone(),fresh_birth,stage,origin_file,enrollment_file,intent_file},intent,selected)
    }
    pub fn parse_data(raw:&[u8],intent:&IntentData,selected:&ReleaseSetData)->Result<Self>{
        let v=value(raw,ORIGIN_LIMIT)?;
        for name in ["next","freshBirth","stage","originFile","enrollmentFile","intentFile"]{
            need(v.get(name).is_some_and(serde_json::Value::is_object),"fresh-output-origin-shape")?;
        }
        let wire=serde_json::from_value(v).map_err(|_|"fresh-output-origin-shape")?;
        let result=Self::validate(wire,intent,selected)?;
        need(result.canonical_bytes_data()?==raw,"fresh-output-origin-canonical")?;Ok(result)
    }
    pub fn canonical_bytes_data(&self)->Result<Vec<u8>>{encode(&self.wire,ORIGIN_LIMIT)}
    pub fn digest_data(&self)->&str{&self.sha256}
    pub fn intent_digest_data(&self)->&str{&self.wire.intent_sha256}
    pub fn invocation_data(&self)->&str{&self.wire.invocation}
    pub fn request_data(&self)->&str{&self.wire.request_id}
    pub fn identities_data(&self)->[FreshBirthIdentityData;4]{
        [self.wire.stage,self.wire.origin_file,self.wire.enrollment_file,self.wire.intent_file]
            .map(|v|v.data().expect("validated output origin identity"))
    }
    pub fn birth_data(&self)->&FreshBirthData{&self.birth}
}
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
pub enum OutputRoleData{PayloadFile,PayloadDirectory,ReleaseDirectory,MetadataFile,StageReceipt,RootControl}
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct EntryWire{
    sequence:u32,previous_sha256:String,role:OutputRoleData,path:String,parent:IdentityWire,identity:IdentityWire,
    expected_bytes:Option<u64>,expected_sha256:Option<String>,
}
pub struct OutputEnrollmentData{wire:EntryWire,raw:Vec<u8>,sha256:String}
/// Conservative encoded-size quote using only maximal DATA scalars. These
/// inert identities are never returned as records or supplied to native IO.
pub fn entry_quote_data(role:OutputRoleData,path:&str)->Result<usize>{
    let identity=IdentityWire{device:i64::MAX,inode:u64::MAX,birth_seconds:i64::MAX,
        birth_nanoseconds:999_999_999,volume_uuid:VolumeUuid::from_bytes_data([255;16]).ok_or("fresh-output-quote")?};
    let directory=matches!(role,OutputRoleData::PayloadDirectory|OutputRoleData::ReleaseDirectory);
    let wire=EntryWire{sequence:u32::MAX,previous_sha256:"f".repeat(64),role,path:path.into(),parent:identity,identity,
        expected_bytes:(!directory).then_some(record::PAYLOAD_LIMIT),expected_sha256:(!directory).then(||"f".repeat(64))};
    encode(&wire,ENTRY_LIMIT)?.len().checked_add(4).ok_or("fresh-output-quote")
}
impl OutputEnrollmentData{
    pub fn role_data(&self)->OutputRoleData{self.wire.role}
    pub fn path_data(&self)->&str{&self.wire.path}
    pub fn identity_data(&self)->FreshBirthIdentityData{self.wire.identity.data().expect("validated enrollment identity")}
    pub fn parent_data(&self)->FreshBirthIdentityData{self.wire.parent.data().expect("validated enrollment parent")}
    pub fn expected_file_data(&self)->Option<(u64,&str)>{self.wire.expected_bytes.zip(self.wire.expected_sha256.as_deref())}
    pub fn frame_data(&self)->Result<Vec<u8>>{
        let mut out=Vec::with_capacity(self.raw.len()+4);out.extend_from_slice(&(self.raw.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.raw);Ok(out)
    }
}
/// Streaming chain and membership index. Its equality is DATA, never creator
/// ownership; a native consumer must compare every actual enrolled original.
pub struct OutputEnrollmentIndexData{
    origin:OutputOriginData,rows:BTreeMap<String,OutputEnrollmentData>,
    identities:BTreeSet<([u8;16],u64,i64,i64)>,head:String,bytes:usize,
}
impl OutputEnrollmentIndexData{
    pub fn new_data(origin:OutputOriginData)->Self{
        let identities=origin.birth.identities_data().into_iter().chain(origin.identities_data())
            .map(|v|IdentityWire::from_data(v).key()).collect();
        let head=origin.sha256.clone();Self{origin,rows:BTreeMap::new(),identities,head,bytes:0}
    }
    pub fn origin_data(&self)->&OutputOriginData{&self.origin}
    pub fn bytes_data(&self)->usize{self.bytes}
    pub fn len_data(&self)->usize{self.rows.len()}
    pub fn head_data(&self)->&str{&self.head}
    pub fn rows_data(&self)->impl Iterator<Item=&OutputEnrollmentData>{self.rows.values()}
    pub fn find_data(&self,path:&str)->Option<&OutputEnrollmentData>{self.rows.get(path)}
    fn target(&self)->Result<MaintenanceTargetData>{match self.origin.wire.target.as_str(){
        "aarch64-apple-darwin"=>Ok(MaintenanceTargetData::Arm64),"x86_64-apple-darwin"=>Ok(MaintenanceTargetData::Intel),
        _=>Err("fresh-output-target")}}
    fn validate(&self,wire:&EntryWire)->Result<()>{
        need(self.rows.len()<ENROLLMENT_LIMIT&&wire.sequence as usize==self.rows.len()
            &&wire.previous_sha256==self.head&&hex(&wire.previous_sha256,64)
            &&!wire.path.is_empty()&&wire.path.len()<=1024&&!self.rows.contains_key(&wire.path),"fresh-output-chain")?;
        wire.parent.data()?;wire.identity.data()?;
        need(wire.identity.volume_uuid==self.origin.wire.stage.volume_uuid
            &&wire.parent.volume_uuid==wire.identity.volume_uuid&&!self.identities.contains(&wire.identity.key()),
            "fresh-output-enrollment-alias")?;
        let directory=matches!(wire.role,OutputRoleData::PayloadDirectory|OutputRoleData::ReleaseDirectory);
        need(if directory{wire.expected_bytes.is_none()&&wire.expected_sha256.is_none()}else{
            wire.expected_bytes.is_some_and(|n|n<=record::PAYLOAD_LIMIT)
                &&wire.expected_sha256.as_deref().is_some_and(|s|hex(s,64))},"fresh-output-expected-file")?;
        let roots=self.origin.birth.identities_data();
        let parent=match wire.role{
            OutputRoleData::PayloadFile|OutputRoleData::PayloadDirectory=>{
                need(safe_macos_install_path(&wire.path)&&(wire.path=="app"||wire.path=="runtime"
                    ||wire.path.starts_with("app/")||wire.path.starts_with("runtime/")),"fresh-output-payload-path")?;
                if let Some((parent,_))=wire.path.rsplit_once('/'){
                    let entry=self.rows.get(parent).ok_or("fresh-output-parent-not-enrolled")?;
                    need(entry.wire.role==OutputRoleData::PayloadDirectory,"fresh-output-parent-role")?;entry.wire.identity
                }else{need(directory,"fresh-output-payload-root")?;self.origin.wire.stage}
            },
            OutputRoleData::ReleaseDirectory=>{need(wire.path=="release","fresh-output-release-path")?;IdentityWire::from_data(roots[1])},
            OutputRoleData::MetadataFile=>{
                need(matches!(wire.path.as_str(),"release/install-inventory.json"|"release/installation-v1.json"),"fresh-output-metadata-path")?;
                self.rows.get("release").ok_or("fresh-output-release-not-enrolled")?.wire.identity
            },
            OutputRoleData::StageReceipt=>{
                let leaf=wire.path.strip_prefix("stage/").ok_or("fresh-output-stage-path")?;
                need(PHASE_NAMES.contains(&leaf)||leaf==format!("launcher-{}.json",self.origin.wire.invocation),"fresh-output-stage-path")?;self.origin.wire.stage
            },
            OutputRoleData::RootControl=>{
                let leaf=wire.path.strip_prefix("control/").ok_or("fresh-output-control-path")?;
                let pair=crate::macos_install_producer::installed_control_names_data(self.target()?,self.origin.wire.next.binding_data().release)
                    .map_err(|_|"fresh-output-control-path")?;
                let capsule=transaction::capsule_name_data(&self.origin.wire.invocation).map_err(|_|"fresh-output-control-path")?;
                need(leaf==transaction::STATE_NAME||leaf==pair.0||leaf==pair.1||leaf==capsule,"fresh-output-control-path")?;
                IdentityWire::from_data(roots[0])
            },
        };
        // DATA persistent correspondence may tolerate device renumbering.
        // Native enrollment and readback additionally compare live device.
        need(parent.key()==wire.parent.key(),"fresh-output-parent-binding")
    }
    pub fn next_data(&self,role:OutputRoleData,path:&str,parent:FreshBirthIdentityData,identity:FreshBirthIdentityData,
        expected:Option<(u64,&str)>)->Result<OutputEnrollmentData>{
        let wire=EntryWire{sequence:self.rows.len() as u32,previous_sha256:self.head.clone(),role,path:path.into(),
            parent:IdentityWire::from_data(parent),identity:IdentityWire::from_data(identity),
            expected_bytes:expected.map(|v|v.0),expected_sha256:expected.map(|v|v.1.into())};
        self.validate(&wire)?;let raw=encode(&wire,ENTRY_LIMIT)?;need(raw.len()>=ENTRY_MIN,"fresh-output-entry-minimum")?;let sha256=digest(&raw);
        need(self.bytes.checked_add(raw.len()+4).is_some_and(|n|n<=JOURNAL_LIMIT),"fresh-output-journal-bound")?;
        Ok(OutputEnrollmentData{wire,raw,sha256})
    }
    pub fn parse_next_data(&self,raw:&[u8])->Result<OutputEnrollmentData>{
        need(raw.len()>=ENTRY_MIN,"fresh-output-entry-minimum")?;
        let v=value(raw,ENTRY_LIMIT)?;
        need(v.get("role").is_some_and(serde_json::Value::is_string)
            &&v.get("parent").is_some_and(serde_json::Value::is_object)
            &&v.get("identity").is_some_and(serde_json::Value::is_object)
            &&v.get("expectedBytes").is_some()&&v.get("expectedSha256").is_some(),"fresh-output-entry-shape")?;
        let wire:EntryWire=serde_json::from_value(v).map_err(|_|"fresh-output-entry-shape")?;
        self.validate(&wire)?;
        need(encode(&wire,ENTRY_LIMIT)?==raw&&self.bytes.checked_add(raw.len()+4).is_some_and(|n|n<=JOURNAL_LIMIT),
            "fresh-output-entry-canonical")?;
        Ok(OutputEnrollmentData{wire,raw:raw.to_vec(),sha256:digest(raw)})
    }
    /// Commit comparison state only. Native callers do this after actual
    /// write/persistence/readback; this function performs no IO or settlement.
    pub fn append_data(&mut self,entry:OutputEnrollmentData)->Result<()>{
        self.validate(&entry.wire)?;
        self.bytes=self.bytes.checked_add(entry.raw.len()+4).filter(|n|*n<=JOURNAL_LIMIT).ok_or("fresh-output-journal-bound")?;
        self.head=entry.sha256.clone();self.identities.insert(entry.wire.identity.key());
        self.rows.insert(entry.wire.path.clone(),entry);Ok(())
    }
    pub fn parse_stream_data(mut self,length:usize,mut read:impl FnMut(usize,&mut[u8])->Result<usize>)->Result<Self>{
        need(length<=JOURNAL_LIMIT,"fresh-output-journal-bound")?;
        let mut at=0usize;let mut body=[0u8;ENTRY_LIMIT];let mut header=[0u8;4];
        while at<length{
            need(length-at>=4,"fresh-output-torn-header")?;read_exact_data(at,&mut header,&mut read)?;at+=4;
            let count=u32::from_be_bytes(header) as usize;
            need(count>=ENTRY_MIN&&count<=ENTRY_LIMIT&&count<=length-at,"fresh-output-torn-entry")?;
            read_exact_data(at,&mut body[..count],&mut read)?;at+=count;
            let entry=self.parse_next_data(&body[..count])?;self.append_data(entry)?;
        }
        need(at==length&&self.bytes==length&&read(length,&mut header[..1])?==0,"fresh-output-journal-eof")?;Ok(self)
    }
}
fn read_exact_data(mut at:usize,mut out:&mut[u8],read:&mut impl FnMut(usize,&mut[u8])->Result<usize>)->Result<()>{
    while !out.is_empty(){let used=read(at,out)?;need(used>0&&used<=out.len(),"fresh-output-short-read")?;
        at=at.checked_add(used).ok_or("fresh-output-bound")?;out=&mut out[used..];}Ok(())
}


// Proposed addition to a reviewed successor of macos_fresh_recovery.rs only.
// Compile-time fixture paths must be exact manifest-bound local DATA files.
#[cfg(test)]
mod output_enrollment_tests {
    use super::*;
    use serde_json::Value;
    fn corpus()->Value {serde_json::from_str(include_str!(env!("MRK_OUTPUT_DATA_CORPUS"))).unwrap()}
    fn unhex(value:&str)->Vec<u8>{
        assert_eq!(value.len()%2,0);
        value.as_bytes().chunks_exact(2).map(|v|u8::from_str_radix(std::str::from_utf8(v).unwrap(),16).unwrap()).collect()
    }
    fn context<'a>(all:&'a Value,case:&Value)->&'a Value {
        all["contexts"].as_array().unwrap().iter().find(|row|row["name"]==case["context"]).unwrap()
    }
    fn inputs(row:&Value)->(ReleaseSetData,IntentData){
        let target=match row["target"].as_str().unwrap(){"aarch64-apple-darwin"=>MaintenanceTargetData::Arm64,
            "x86_64-apple-darwin"=>MaintenanceTargetData::Intel,_=>panic!("closed target")};
        let selected=ReleaseSetData::parse_for_target_data(&serde_json::to_vec(&row["releaseSet"]).unwrap(),target).unwrap();
        let intent=IntentData::parse_canonical_data(row["intent"].as_str().unwrap().as_bytes(),&selected,false).unwrap();
        (selected,intent)
    }
    #[test]
    fn origin_closed_corpus_36(){
        let all=corpus();let mut count=0;
        for case in all["cases"].as_array().unwrap().iter().filter(|row|row["operation"]=="origin"){
            let ctx=context(&all,case);let(selected,intent)=inputs(ctx);
            let raw=case["originHex"].as_str().map(unhex).unwrap_or_else(||case["origin"].as_str().unwrap().as_bytes().to_vec());
            assert_eq!(OutputOriginData::parse_data(&raw,&intent,&selected).is_ok(),case["accept"].as_bool().unwrap(),"{}",case["id"]);
            count+=1;
        }assert_eq!(count,36);
    }
    #[test]
    fn current_chain_corpus_85(){
        let all=corpus();let mut count=0;let mut calls=0usize;let mut io=0usize;
        for case in all["cases"].as_array().unwrap().iter().filter(|row|row["operation"]!="origin"){
            let ctx=context(&all,case);let(selected,intent)=inputs(ctx);
            let raw=ctx["origin"].as_str().unwrap().as_bytes();
            let origin=OutputOriginData::parse_data(raw,&intent,&selected).unwrap();
            assert_eq!(origin.canonical_bytes_data().unwrap(),raw);
            let mut journal=unhex(case["journalHex"].as_str().unwrap_or(ctx["journalHex"].as_str().unwrap()));
            if case["operation"]=="prefix"{journal.truncate(case["bytes"].as_u64().unwrap() as usize);}
            let length=case["declaredLength"].as_u64().map(|n|n as usize).unwrap_or(journal.len());
            let mode=case["callback"].as_str().unwrap_or("ordinary");let mut local_calls=0;
            let result=OutputEnrollmentIndexData::new_data(origin).parse_stream_data(length,|at,out|{
                calls+=1;local_calls+=1;assert!(calls<=100000);assert!(out.len()<=ENTRY_LIMIT);
                assert_ne!(mode,"must-not-be-called");
                if at==length{
                    if mode=="nonempty-eof"{out[0]=b'x';io+=1;return Ok(1);}return Ok(0);
                }
                if mode=="overreturn"{return Ok(out.len()+1);}
                if mode=="error-at-19"&&at>=19{return Err("fixture-reader-error");}
                if mode=="zero-at-19"&&at>=19{return Ok(0);}
                let mut size=out.len().min(journal.len().saturating_sub(at));
                if mode=="chunk-1"{size=size.min(1);}if mode=="chunk-7"{size=size.min(7);}
                if matches!(mode,"zero-at-19"|"error-at-19"){size=size.min(19-at);}
                out[..size].copy_from_slice(&journal[at..at+size]);io+=size;assert!(io<=4*1024*1024);Ok(size)
            });
            assert_eq!(result.is_ok(),case["accept"].as_bool().unwrap(),"{}",case["id"]);
            if let Ok(index)=result{
                assert_eq!(index.bytes_data(),journal.len());
                if let Some(n)=case["entries"].as_u64(){assert_eq!(index.len_data(),n as usize);assert_eq!(index.head_data(),case["headSha256"].as_str().unwrap());}
                if let Some(n)=case["expectedEntries"].as_u64(){assert_eq!(index.len_data(),n as usize);}
                if case["section"]=="valid"{
                    let rebuilt_origin=OutputOriginData::new_data(&intent,&selected,index.origin_data().identities_data()).unwrap();
                    assert_eq!(rebuilt_origin.canonical_bytes_data().unwrap(),raw);
                    let mut rebuilt=OutputEnrollmentIndexData::new_data(rebuilt_origin);let mut encoded=Vec::new();
                    for expected in ctx["entries"].as_array().unwrap(){
                        let path=expected["path"].as_str().unwrap();let observed=index.find_data(path).unwrap();
                        let entry=rebuilt.next_data(observed.role_data(),path,observed.parent_data(),observed.identity_data(),observed.expected_file_data()).unwrap();
                        encoded.extend(entry.frame_data().unwrap());rebuilt.append_data(entry).unwrap();
                    }
                    assert_eq!(encoded,journal);assert_eq!(rebuilt.head_data(),index.head_data());
                }
                if let Some(hash)=case["journalSha256"].as_str().or(case["expectedSha256"].as_str()){
                    assert_eq!(digest(&journal),hash);
                }
            }
            if mode=="must-not-be-called"{assert_eq!(local_calls,0);}count+=1;
        }assert_eq!(count,85);
    }
    #[test]
    fn full_public_inventory_path_quotes_8521(){
        let raw=include_bytes!(env!("MRK_OUTPUT_DATA_INVENTORY"));
        assert_eq!(digest(raw),"beb7a406091cef70e0e7799450bab1cd90a969436d7c1ae231b3c49b133a350a");
        let document:Value=serde_json::from_slice(raw).unwrap();
        let inventory=record::Inventory::parse_for_release(raw,document["runtimeManifestSha256"].as_str().unwrap(),document["release"].as_str().unwrap()).unwrap();
        let index=inventory.index().unwrap();assert_eq!((index.files.len(),index.directories.len(),index.payload_bytes),(7230,1279,331902994));
        let rows:Value=serde_json::from_str(include_str!(env!("MRK_OUTPUT_DATA_PATH_QUOTES"))).unwrap();
        assert_eq!(rows.as_array().unwrap().len(),8521);let mut sum=0;
        let mut quoted_files=BTreeSet::new();let mut quoted_dirs=BTreeSet::new();
        for row in rows.as_array().unwrap(){
            let role:OutputRoleData=serde_json::from_value(row["role"].clone()).unwrap();let path=row["path"].as_str().unwrap();
            let actual=entry_quote_data(role,path).unwrap();assert_eq!(actual,row["frameQuote"].as_u64().unwrap() as usize);sum+=actual;
            if role==OutputRoleData::PayloadFile{assert!(quoted_files.insert(path.to_owned()));}
            if role==OutputRoleData::PayloadDirectory{assert!(quoted_dirs.insert(path.to_owned()));}
        }
        assert_eq!(quoted_files,index.files.keys().cloned().collect());assert_eq!(quoted_dirs,index.directories);
        assert_eq!(sum,5813198);assert!(sum<=JOURNAL_LIMIT);
    }
}
