//! Closed one-field secret DATA. No material, credential lookup or process owner.
use super::*;

pub(crate) const SECRET_PREPARED_LIMIT: usize = 8192;
pub(crate) const SECRET_FACTS_LIMIT: usize = 2048;
pub(crate) const SECRET_READ_LIMIT: usize = 8192;
pub(crate) const SECRET_PLAINTEXT_LIMIT: usize = 49152;
pub(crate) const SECRET_RAW_FILE_LIMIT: usize = 36864;
pub(crate) const SECRET_REQUEST_LIMIT: usize = 49196;
pub(crate) const SECRET_REPLY_LIMIT: usize = 49212;
pub(crate) const SECRET_PREPARE_BUFFERS: usize = 249993;
pub(crate) const SECRET_APPLY_GO_LIMIT:usize = 73728;
pub(crate) const SECRET_APPLY_BUFFERS:usize = 815345;
pub(crate) const SECRET_CONFIGURATION_WORK_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const SECRET_CONFIRMATION: &str = "Send this exact required secret to GitHub? GitHub cannot show or compare the existing value. This create-or-update request can overwrite a concurrent change or recreate a deleted secret; there is no atomic compare-and-set. A returned acceptance does not verify the secret value or prove a build or release works. Cancel does not undo a sent request.";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SecretMode { Create, Replace }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SecretEncoding { Base64, Utf8 }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SecretPlatform { Android, Ios, Project }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SecretPurpose { Full, Signing, Store }

// The field/name association is canonical DATA, never a generic vault export.
macro_rules! requirements {
    ($(($variant:ident,$name:literal,$kind:literal,$field:literal,$encoding:ident,$platform:ident)),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
        pub(crate) enum SecretRequirement { $(#[serde(rename=$name)] $variant),+ }
        impl SecretRequirement {
            pub(crate) fn name(self)->&'static str { match self { $(Self::$variant=>$name),+ } }
            pub(crate) fn record_kind(self)->&'static str { match self { $(Self::$variant=>$kind),+ } }
            pub(crate) fn field(self)->&'static str { match self { $(Self::$variant=>$field),+ } }
            pub(crate) fn encoding(self)->SecretEncoding { match self { $(Self::$variant=>SecretEncoding::$encoding),+ } }
            pub(crate) fn platform(self)->SecretPlatform { match self { $(Self::$variant=>SecretPlatform::$platform),+ } }
        }
    }
}
requirements!(
    (AndroidKeystore,"MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64","android-keystore","file",Base64,Android),
    (AndroidStorePassword,"MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD","android-keystore","storePassword",Utf8,Android),
    (AndroidKeyPassword,"MOBILE_RELEASE_ANDROID_KEY_PASSWORD","android-keystore","keyPassword",Utf8,Android),
    (AndroidFirebase,"MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64","android-firebase","file",Base64,Android),
    (AppleP12,"MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64","apple-p12","file",Base64,Ios),
    (ApplePassword,"MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD","apple-p12","password",Utf8,Ios),
    (AppleProfile,"MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64","apple-profile","file",Base64,Ios),
    (IosFirebase,"MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64","ios-firebase","file",Base64,Ios),
    (AscP8,"MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64","asc-p8","file",Base64,Ios),
    (ProjectReadToken,"MOBILE_RELEASE_PROJECT_READ_TOKEN","project-read-token","token",Utf8,Project),
);
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct SecretRecord { pub(crate) record_id:String, pub(crate) record_revision:u32, pub(crate) context_revision:u32 }
impl SecretRecord {
    pub(crate) fn valid(&self)->bool { hex(&self.record_id,32) }
    pub(crate) fn retained_heap_bytes(&self)->usize { self.record_id.capacity() }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct SecretSelection {
    pub(crate) mode:SecretMode, pub(crate) stage:EnvironmentStage,
    pub(crate) requirement:SecretRequirement, pub(crate) source:SecretRecord,
}
impl SecretSelection {
    pub(crate) fn valid(&self)->bool { self.source.valid() }
    pub(crate) fn retained_heap_bytes(&self)->usize { self.source.retained_heap_bytes() }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct SecretMetadata {pub(crate) created_at:String,pub(crate) updated_at:String}
impl SecretMetadata {
    fn valid(&self)->bool {utc(&self.created_at)&&utc(&self.updated_at)}
    fn retained_heap_bytes(&self)->Option<usize>{self.created_at.capacity().checked_add(self.updated_at.capacity())}
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct SecretFacts {
    pub(crate) environment_name:String,pub(crate) environment_id:String,pub(crate) name:String,
    #[serde(deserialize_with="nullable")] pub(crate) metadata:Option<SecretMetadata>,
}
impl SecretFacts {
    pub(crate) fn valid_for(&self,selection:&SecretSelection)->bool {
        environment_id(&self.environment_id)&&self.environment_name==selection.stage.name()
            &&self.name==selection.requirement.name()&&self.metadata.as_ref().is_none_or(SecretMetadata::valid)
            &&serde_json::to_vec(self).is_ok_and(|v|v.len()<=SECRET_FACTS_LIMIT)
    }
    pub(crate) fn before_for(&self,selection:&SecretSelection)->bool {
        self.valid_for(selection)&&match selection.mode {SecretMode::Create=>self.metadata.is_none(),SecretMode::Replace=>self.metadata.is_some()}
    }
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{self.environment_name.capacity().checked_add(self.environment_id.capacity())?
        .checked_add(self.name.capacity())?.checked_add(self.metadata.as_ref().map_or(Some(0),SecretMetadata::retained_heap_bytes)?)}
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecretContent {pub(crate) bytes:u32,pub(crate) sha256:String}
impl SecretContent {pub(crate) fn valid(&self)->bool{(1..=524288).contains(&self.bytes)&&hex(&self.sha256,64)}}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct SecretConfiguration {pub(crate) saved_config:SecretContent,pub(crate) canonical_config:SecretContent}
impl SecretConfiguration {
    pub(crate) fn valid(&self)->bool{self.saved_config.valid()&&self.canonical_config.valid()}
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{self.saved_config.sha256.capacity().checked_add(self.canonical_config.sha256.capacity())}
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct SecretAfter {pub(crate) name:String,pub(crate) encoding:SecretEncoding,pub(crate) plaintext_bytes:u32}
impl SecretAfter {
    fn valid_for(&self,selection:&SecretSelection)->bool{self.name==selection.requirement.name()&&self.encoding==selection.requirement.encoding()
        &&(1..=SECRET_PLAINTEXT_LIMIT as u32).contains(&self.plaintext_bytes)
        &&(self.encoding!=SecretEncoding::Base64||self.plaintext_bytes%4==0)}
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct SecretPrepared {
    pub(crate) target:Target,pub(crate) before:SecretFacts,pub(crate) after:SecretAfter,
    pub(crate) configuration:SecretConfiguration,pub(crate) observed_at:String,pub(crate) confirmation:String,
}
impl SecretPrepared {
    pub(crate) fn valid(&self)->bool {
        let Selection::Secret(selection)=&self.target.selection else{return false};
        self.target.valid()&&self.before.before_for(selection)&&self.after.valid_for(selection)
            &&self.configuration.valid()&&utc(&self.observed_at)&&self.confirmation==SECRET_CONFIRMATION
            &&serde_json::to_vec(self).is_ok_and(|v|v.len()<=SECRET_PREPARED_LIMIT)
    }
    pub(crate) fn matches_after(&self,facts:&SecretFacts)->bool {
        let Selection::Secret(selection)=&self.target.selection else{return false};
        facts.valid_for(selection)&&facts.metadata.is_some()&&facts.environment_id==self.before.environment_id
    }
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{self.target.retained_heap_bytes()?.checked_add(self.before.retained_heap_bytes()?)?
        .checked_add(self.after.name.capacity())?.checked_add(self.configuration.retained_heap_bytes()?)?
        .checked_add(self.observed_at.capacity())?.checked_add(self.confirmation.capacity())}
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecretRootIdentity {pub(crate) device:String,pub(crate) inode:String,pub(crate) mode:u32,pub(crate) uid:u32,pub(crate) gid:u32}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct SecretMaterialFacts {pub(crate) encoding:SecretEncoding,pub(crate) plaintext_bytes:u32}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all="camelCase")]
pub(crate) struct SecretSource {
    pub(crate) root:String,pub(crate) root_identity:SecretRootIdentity,pub(crate) draft:SecretContent,
    pub(crate) platform:SecretPlatform,pub(crate) purpose:SecretPurpose,pub(crate) material:SecretMaterialFacts,
}
impl SecretSource {
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{self.root.capacity().checked_add(self.root_identity.device.capacity())?
        .checked_add(self.root_identity.inode.capacity())?.checked_add(self.draft.sha256.capacity())}
}

pub(super) fn secret_selection_shape(value:&Value)->bool {
    value.is_object() && (value.get("kind").and_then(Value::as_str)!=Some("environment_secret")
        ||value.get("source").is_some_and(Value::is_object))
}
fn secret_target_shape(value:&Value)->bool {value.is_object()&&value.get("selection").is_some_and(secret_selection_shape)}
fn secret_facts_shape(value:&Value)->bool {
    value.is_object()&&value.get("metadata").is_some_and(|v|v.is_null()||v.is_object())
}
fn configuration_shape(value:&Value)->bool {
    value.is_object()&&value.get("savedConfig").is_some_and(Value::is_object)
        &&value.get("canonicalConfig").is_some_and(Value::is_object)
}
fn secret_prepared_shape(value:&Value)->bool {
    value.is_object()&&value.get("target").is_some_and(secret_target_shape)
        &&value.get("before").is_some_and(secret_facts_shape)&&value.get("after").is_some_and(Value::is_object)
        &&value.get("configuration").is_some_and(configuration_shape)
}
pub(super) fn secret_reply_shape(value:&Value)->bool {
    value.get("result").is_some_and(|result|result.is_object()
        &&result.get("control").is_some_and(Value::is_object)
        &&result.get("prepared").is_some_and(|v|v.is_null()||secret_prepared_shape(v))
        &&result.get("observed").is_some_and(|v|v.is_null()||secret_facts_shape(v)))
}
impl SecretSource {
    fn valid_for(&self,selection:&SecretSelection)->bool {
        let decimal=|v:&str|v.parse::<u64>().is_ok_and(|number|number.to_string()==v);
        self.root.starts_with('/')&&self.root.len()<=4096&&!self.root.chars().any(char::is_control)
            &&decimal(&self.root_identity.device)&&decimal(&self.root_identity.inode)
            &&self.root_identity.mode&0o170000==0o040000&&self.draft.valid()
            &&self.platform==selection.requirement.platform()&&self.material.encoding==selection.requirement.encoding()
            &&(1..=SECRET_PLAINTEXT_LIMIT as u32).contains(&self.material.plaintext_bytes)
            &&(self.material.encoding!=SecretEncoding::Base64||self.material.plaintext_bytes%4==0)
    }
}
pub(crate) fn encode_secret_initial(id:&str,request:&Request,source:&SecretSource)->Result<Vec<u8>,BridgeError> {
    let Selection::Secret(selection)=&request.target.selection else{return Err(BridgeError::invalid())};
    if !valid_id(id)||!request.valid()||!source.valid_for(selection) {
        return Err(BridgeError::invalid());
    }
    if request.kind==Kind::Apply && !matches!(&request.prepared,Some(Prepared::Secret(v))
        if v.configuration.canonical_config==source.draft && v.after.encoding==source.material.encoding
            &&v.after.plaintext_bytes==source.material.plaintext_bytes){return Err(BridgeError::invalid())}
    let value=serde_json::json!({"protocol":PROTOCOL,"id":id,"action":{
        "kind":request.kind,"target":request.target,"prepared":request.prepared,"source":source}});
    if !bounds(&value,INITIAL_LIMIT-1,256,8){return Err(BridgeError::invalid())}
    let mut raw=serde_json::to_vec(&value).map_err(|_|BridgeError::invalid())?;raw.push(b'\n');
    if raw.len()>INITIAL_LIMIT{return Err(BridgeError::invalid())}Ok(raw)
}
// Measure the complete escaped frame using the same encoder before any
// credential/ciphertext buffer allocation. The admitted reservation is fixed;
// actual spare capacity is checked before writing into it.
struct SecretFrameCount(usize);
impl std::io::Write for SecretFrameCount {
    fn write(&mut self,bytes:&[u8])->std::io::Result<usize>{
        self.0=self.0.checked_add(bytes.len()).ok_or_else(||std::io::Error::other("fixed frame overflow"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self)->std::io::Result<()>{Ok(())}
}
fn secret_apply_frame(out:&mut impl std::io::Write,id:&str,digest:&str,token:&str,key:&SecretPublicKey,cipher:&[u8])->Result<(),BridgeError>{
    macro_rules! raw {($v:expr)=>{out.write_all($v).map_err(|_|BridgeError::invalid())?};}
    macro_rules! string {($v:expr)=>{serde_json::to_writer(&mut *out,$v).map_err(|_|BridgeError::invalid())?};}
    raw!(b"{\"protocol\":\"mrk-github-setup/1\",\"id\":");string!(id);
    raw!(b",\"go\":{\"requestSha256\":");string!(digest);raw!(b",\"token\":");string!(token);
    raw!(b",\"sealed\":{\"key\":{\"id\":");string!(&key.id);raw!(b",\"value\":");string!(&key.value);
    raw!(b"},\"encryptedValue\":\"");
    const B64:&[u8;64]=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for chunk in cipher.chunks(3){
        let a=chunk[0];let b=chunk.get(1).copied().unwrap_or(0);let c=chunk.get(2).copied().unwrap_or(0);
        let row=[B64[(a>>2)as usize],B64[(((a&3)<<4)|(b>>4))as usize],
            if chunk.len()>1{B64[(((b&15)<<2)|(c>>6))as usize]}else{b'='},
            if chunk.len()>2{B64[(c&63)as usize]}else{b'='}];raw!(&row);
    }
    raw!(b"\"}}}\n");Ok(())
}
pub(crate) fn encode_secret_apply_go(id:&str,digest:&str,token:&str,key:&SecretPublicKey,cipher:&[u8],expected:usize)
    ->Result<Vec<u8>,BridgeError>{
    if !valid_id(id)||!hex(digest,64)||token.is_empty()||token.len()>4096||!token.bytes().all(|b|(0x21..=0x7e).contains(&b))
        ||key.bytes().is_none()||!(1..=SECRET_PLAINTEXT_LIMIT).contains(&expected)||cipher.len()!=expected+48 {
        return Err(BridgeError::invalid())
    }
    let mut count=SecretFrameCount(0);secret_apply_frame(&mut count,id,digest,token,key,cipher)?;
    if count.0>SECRET_APPLY_GO_LIMIT{return Err(BridgeError::invalid())}
    let mut raw=Vec::new();raw.try_reserve_exact(SECRET_APPLY_GO_LIMIT).map_err(|_|BridgeError::invalid())?;
    if raw.capacity()>SECRET_APPLY_GO_LIMIT{return Err(BridgeError::invalid())}
    secret_apply_frame(&mut raw,id,digest,token,key,cipher)?;
    if raw.len()!=count.0{return Err(BridgeError::invalid())}Ok(raw)
}

// Fixed canonical padded Base64 for one public GitHub key, not cryptography.
// No acceptance of URL alphabet, whitespace, alternate padding or nonzero tail.
fn key_bytes(value:&str)->Option<[u8;32]> {
    fn digit(v:u8)->Option<u8>{match v {b'A'..=b'Z'=>Some(v-b'A'),b'a'..=b'z'=>Some(v-b'a'+26),
        b'0'..=b'9'=>Some(v-b'0'+52),b'+'=>Some(62),b'/'=>Some(63),_=>None}}
    let raw=value.as_bytes();if raw.len()!=44||raw[43]!=b'=' {return None}
    let mut result=[0u8;32];
    for block in 0..10 {let i=block*4;let a=digit(raw[i])?;let b=digit(raw[i+1])?;
        let c=digit(raw[i+2])?;let d=digit(raw[i+3])?;
        result[block*3]=(a<<2)|(b>>4);result[block*3+1]=(b<<4)|(c>>2);result[block*3+2]=(c<<6)|d;}
    let a=digit(raw[40])?;let b=digit(raw[41])?;let c=digit(raw[42])?;if c&3!=0{return None}
    result[30]=(a<<2)|(b>>4);result[31]=(b<<4)|(c>>2);Some(result)
}
#[derive(Debug,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecretPublicKey {pub(crate) id:String,pub(crate) value:String}
impl SecretPublicKey {
    pub(crate) fn bytes(&self)->Option<[u8;32]>{
        if self.id.is_empty()||self.id.len()>128||!self.id.bytes().all(|b|(0x21..=0x7e).contains(&b)){return None}
        key_bytes(&self.value)
    }
    fn retained_heap_bytes(&self)->Option<usize>{self.id.capacity().checked_add(self.value.capacity())}
}
#[derive(Debug,Deserialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct SecretRead {
    schema_version:u32,pub(crate) target:Target,pub(crate) before:SecretFacts,
    pub(crate) configuration:SecretConfiguration,pub(crate) material:SecretMaterialFacts,
    pub(crate) key:SecretPublicKey,pub(crate) observed_at:String,pub(crate) control:GitHubReadControl,
}
impl SecretRead {
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{self.target.retained_heap_bytes()?
        .checked_add(self.before.retained_heap_bytes()?)?.checked_add(self.configuration.retained_heap_bytes()?)?
        .checked_add(self.key.retained_heap_bytes()?)?.checked_add(self.observed_at.capacity())?
        .checked_add(self.control.credential_expires_at.as_ref().map_or(0,String::capacity))}
    fn valid_for(&self,request:&Request,source:&SecretSource)->bool {
        let Selection::Secret(selection)=&request.target.selection else{return false};
        self.schema_version==1&&request.kind==Kind::Prepare&&request.valid()&&self.target==request.target
            &&source.valid_for(selection)&&self.before.before_for(selection)&&self.configuration.valid()
            &&self.configuration.canonical_config==source.draft&&self.material==source.material
            &&self.key.bytes().is_some()&&utc(&self.observed_at)&&self.control.valid()
            &&self.control.reason==connection::Reason::None
            &&self.retained_heap_bytes().is_some_and(|v|v<=16384)
    }
    // Called only by the original owner AFTER fixed helper return and all its
    // native/pipe originals. This move does not itself grant public consent.
    pub(crate) fn into_result(self,id:&str)->(Reply,SecretPublicKey) {
        let name=match &self.target.selection {Selection::Secret(v)=>v.requirement.name(),_=>""};
        let prepared=SecretPrepared {target:self.target,before:self.before.clone(),
            after:SecretAfter{name:name.into(),encoding:self.material.encoding,plaintext_bytes:self.material.plaintext_bytes},
            configuration:self.configuration,observed_at:self.observed_at,confirmation:SECRET_CONFIRMATION.into()};
        (Reply{protocol:PROTOCOL.into(),id:id.into(),result:Outcome{schema_version:1,action:Kind::Prepare,
            reason:Reason::None,effect:Effect::NotStarted,write_claimed:false,write_acknowledged:false,
            prepared:Some(Prepared::Secret(prepared)),observed:Some(Observation::Secret(self.before)),control:self.control}},self.key)
    }
}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct SecretReadEnvelope {protocol:String,id:String,secret_read:SecretRead}
pub(crate) enum SecretReadReturn {Refused(Reply),Observed(SecretRead)}
pub(crate) fn decode_secret_read(id:&str,raw:&[u8],request:&Request,source:&SecretSource)->Result<SecretReadReturn,BridgeError> {
    if !matches!(&request.target.selection,Selection::Secret(_))||request.kind!=Kind::Prepare{return Err(BridgeError::protocol())}
    let value=frame(raw,SECRET_READ_LIMIT,256,8)?;
    if value.get("result").is_some(){return decode_reply(id,raw,request).map(SecretReadReturn::Refused)}
    let row=value.get("secretRead").filter(|v|v.is_object()).ok_or_else(BridgeError::protocol)?;
    if !row.get("target").is_some_and(secret_target_shape)||!row.get("before").is_some_and(secret_facts_shape)
        ||!row.get("configuration").is_some_and(configuration_shape)||!row.get("material").is_some_and(Value::is_object)
        ||!row.get("key").is_some_and(Value::is_object)||!row.get("control").is_some_and(Value::is_object) {
        return Err(BridgeError::protocol());
    }
    let reply:SecretReadEnvelope=serde_json::from_value(value).map_err(|_|BridgeError::protocol())?;
    if reply.protocol!=PROTOCOL||reply.id!=id||!reply.secret_read.valid_for(request,source){return Err(BridgeError::protocol())}
    Ok(SecretReadReturn::Observed(reply.secret_read))
}
pub(super) fn secret_future_status_fits(request:&Request,session:&str)->bool {
    let Selection::Secret(selection)=&request.target.selection else{return false};
    // Size-only ceiling. Never admitted as a remote fact, native material or
    // consent. All variable public strings use their actual/fixed maxima.
    let facts=serde_json::json!({"environmentName":"mobile-external-testing","environmentId":"9223372036854775807",
        "name":selection.requirement.name(),"metadata":{"createdAt":"9999-12-31T23:59:59Z","updatedAt":"9999-12-31T23:59:59Z"}});
    let digest=serde_json::json!({"bytes":524288,"sha256":"a".repeat(64)});
    let prepared=serde_json::json!({"target":request.target,"before":facts,"after":{"name":selection.requirement.name(),
        "encoding":"base64","plaintextBytes":49152},"configuration":{"savedConfig":digest,"canonicalConfig":digest},
        "observedAt":"9999-12-31T23:59:59Z","confirmation":SECRET_CONFIRMATION});
    let value=serde_json::json!({"schemaVersion":1,"revision":LAST_REVISION,"sessionId":session,"available":false,
        "reason":"not-found-or-inaccessible","operation":{"id":"x".repeat(64),"kind":"prepare","phase":"cleanup-unknown",
        "reason":"not-found-or-inaccessible","effect":"accepted-not-value-verified","writeClaimed":true,"writeAcknowledged":true},
        "consent":{"id":"a".repeat(32),"expiresAt":"9999-12-31T23:59:59Z","prepared":prepared},"observed":facts});
    bounds(&value,RESPONSE_LIMIT-512,1024,12)
}

// Appended to the existing protocol DATA group; no credential or original IO.
#[cfg(test)]
pub(super) fn data_checks(){
    use serde_json::json;
    let selection=SecretSelection{mode:SecretMode::Create,stage:EnvironmentStage::Candidate,
        requirement:SecretRequirement::AndroidStorePassword,source:SecretRecord{record_id:"1".repeat(32),record_revision:2,context_revision:3}};
    let target=Target{project_binding:"a".repeat(64),repository:"owner/repo".into(),account_id:"1".into(),repository_id:"2".into(),
        selection:Selection::Secret(selection.clone())};
    let request=Request{kind:Kind::Prepare,target:target.clone(),prepared:None};
    let content=SecretContent{bytes:27,sha256:"b".repeat(64)};
    let source=SecretSource{root:"/inert/project".into(),root_identity:SecretRootIdentity{device:"1".into(),inode:"2".into(),mode:0o40700,uid:1,gid:1},
        draft:content.clone(),platform:SecretPlatform::Android,purpose:SecretPurpose::Signing,
        material:SecretMaterialFacts{encoding:SecretEncoding::Utf8,plaintext_bytes:4}};
    assert!(encode_initial("secret-1",&request).is_err());
    let initial=encode_secret_initial("secret-1",&request,&source).unwrap();
    assert!(initial.len()<=INITIAL_LIMIT);
    let frame_json:Value=serde_json::from_slice(&initial).unwrap();
    assert!(frame_json.get("request").is_none());assert_eq!(frame_json["action"]["source"]["material"]["plaintextBytes"],4);
    let prepared_args=json!({"sessionId":"1".repeat(32),"expectedRevision":1,"expectedConnectionRevision":2,"selection":target.selection});
    assert!(decode_command("github_remote_setup_prepare",&prepared_args).is_ok());
    let mut positional=prepared_args.clone();positional["selection"]["source"]=json!(["1".repeat(32),2,3]);
    assert!(decode_command("github_remote_setup_prepare",&positional).is_err());
    let now="2026-10-09T12:00:00Z";
    let raw_value=json!({"protocol":PROTOCOL,"id":"secret-1","secretRead":{"schemaVersion":1,"target":target,
        "before":{"environmentName":"mobile-candidate","environmentId":"3","name":selection.requirement.name(),"metadata":null},
        "configuration":{"savedConfig":content,"canonicalConfig":content},"material":source.material,
        "key":{"id":"inert-public-key","value":"A".repeat(43)+"="},"observedAt":now,
        "control":{"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false}}});
    let line=|v:&Value|{let mut bytes=serde_json::to_vec(v).unwrap();bytes.push(b'\n');bytes};
    let read=match decode_secret_read("secret-1",&line(&raw_value),&request,&source).unwrap(){SecretReadReturn::Observed(v)=>v,_=>panic!("read expected")};
    assert!(read.retained_heap_bytes().unwrap()<=16384);
    let(reply,key)=read.into_result("secret-1");
    assert_eq!(key.bytes(),Some([0;32]));assert!(reply.result.valid(&request));
    assert!(matches!(&reply.result.prepared,Some(Prepared::Secret(v))if v.valid()));
    // This native-only construction is NEVER admissible from Python stdout.
    let forged=json!({"protocol":PROTOCOL,"id":"secret-1","result":{"schemaVersion":1,"action":"prepare","reason":"none",
        "effect":"not-started","writeClaimed":false,"writeAcknowledged":false,"prepared":reply.result.prepared,
        "observed":reply.result.observed,"control":{"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false}}});
    assert!(decode_secret_read("secret-1",&line(&forged),&request,&source).is_err());
    for pointer in ["/secretRead","/secretRead/target","/secretRead/target/selection/source","/secretRead/before",
        "/secretRead/configuration","/secretRead/configuration/savedConfig","/secretRead/material","/secretRead/key","/secretRead/control"] {
        let mut changed=raw_value.clone();*changed.pointer_mut(pointer).unwrap()=json!([]);
        assert!(decode_secret_read("secret-1",&line(&changed),&request,&source).is_err(),"{pointer}");
    }
    for(pointer,bad)in[("/secretRead/material/plaintextBytes",json!(true)),("/secretRead/configuration/savedConfig/bytes",json!(true)),
        ("/secretRead/target/selection/source/recordRevision",json!(true)),("/secretRead/before/environmentId",json!(3)),
        ("/secretRead/key/value",json!("A".repeat(42)+"B=")),("/secretRead/key/id",json!("bad key"))]{
        let mut changed=raw_value.clone();*changed.pointer_mut(pointer).unwrap()=bad;
        assert!(decode_secret_read("secret-1",&line(&changed),&request,&source).is_err());
    }
    let mut stale=source.clone();stale.draft.bytes+=1;
    assert!(decode_secret_read("secret-1",&line(&raw_value),&request,&stale).is_err());
    let mut too_large=source.clone();too_large.material.plaintext_bytes=49153;
    assert!(encode_secret_initial("secret-1",&request,&too_large).is_err());
    assert!(secret_future_status_fits(&request,&"a".repeat(32)));
    assert_eq!(SECRET_PREPARE_BUFFERS,49196+65536+16384+98397+16384+4096);
    assert_eq!(SECRET_CONFIGURATION_WORK_BYTES,16*1024*1024);
    assert_eq!(SECRET_APPLY_BUFFERS,73728+65600+73729+73728+73728+65600+49200+65600+69632+69632+69632+32768+16384+8192+8192);
    let applying=Request{kind:Kind::Apply,target:request.target.clone(),prepared:reply.result.prepared.clone()};
    assert!(encode_secret_initial("secret-apply",&applying,&source).is_ok());
    let cipher=vec![0u8;52];let digest="c".repeat(64);
    let go=encode_secret_apply_go("secret-apply",&digest,"inert",&key,&cipher,4).unwrap();
    let decoded:Value=serde_json::from_slice(&go).unwrap();
    assert_eq!(decoded["go"]["sealed"]["encryptedValue"].as_str().unwrap().len(),72);
    assert_eq!(decoded["go"]["requestSha256"],digest);assert!(decoded["go"].get("value").is_none());
    assert!(encode_secret_apply_go("secret-apply",&digest,"inert",&key,&cipher,5).is_err());
    let maximum=vec![0u8;SECRET_PLAINTEXT_LIMIT+48];
    let go=encode_secret_apply_go("secret-apply",&digest,&"x".repeat(4096),&key,&maximum,SECRET_PLAINTEXT_LIMIT).unwrap();
    assert!(go.len()<=SECRET_APPLY_GO_LIMIT&&go.len()>GO_LIMIT);
    assert!(encode_secret_apply_go("secret-apply",&digest,&"\"".repeat(4096),&key,&maximum,SECRET_PLAINTEXT_LIMIT).is_err());
    assert!(encode_go("secret-apply",&digest,&"x".repeat(4097)).is_err());
    assert!(decode_secret_read("secret-apply",&line(&raw_value),&applying,&source).is_err());
    let applied=json!({"protocol":PROTOCOL,"id":"secret-apply","result":{"schemaVersion":1,"action":"apply","reason":"none",
        "effect":"accepted-not-value-verified","writeClaimed":true,"writeAcknowledged":true,"prepared":null,
        "observed":{"environmentName":"mobile-candidate","environmentId":"3","name":selection.requirement.name(),
            "metadata":{"createdAt":now,"updatedAt":now}},
        "control":{"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false}}});
    assert!(decode_reply("secret-apply",&line(&applied),&applying).is_ok());
    for(pointer,bad)in[("/result/writeClaimed",json!(false)),("/result/writeAcknowledged",json!(0)),
        ("/result/observed/environmentId",json!("4")),("/result/observed/metadata",json!(null)),
        ("/result/effect",json!("readback-confirmed"))]{
        let mut changed=applied.clone();*changed.pointer_mut(pointer).unwrap()=bad;
        assert!(decode_reply("secret-apply",&line(&changed),&applying).is_err());
    }
    let failure=json!({"protocol":PROTOCOL,"id":"secret-1","result":{"schemaVersion":1,"action":"prepare","reason":"resources-unavailable",
        "effect":"not-started","writeClaimed":false,"writeAcknowledged":false,"prepared":null,"observed":null,
        "control":{"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false}}});
    assert!(matches!(decode_secret_read("secret-1",&line(&failure),&request,&source),Ok(SecretReadReturn::Refused(_))));
}
