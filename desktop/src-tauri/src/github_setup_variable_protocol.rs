//! Five NONSECRET assigned identifiers. No lookup, sealing or process authority.
//! Included by the existing Setup protocol; shared variant wiring is separate.
use super::*;

pub(crate) const VARIABLE_VALUE_LIMIT:usize=4096;
pub(crate) const VARIABLE_FACTS_LIMIT:usize=2048;
pub(crate) const VARIABLE_PREPARED_LIMIT:usize=8192;
pub(crate) const VARIABLE_WIRE_BUFFERS:usize=663554;
pub(crate) const VARIABLE_CONFIRMATION:&str="Send this exact required variable to GitHub? Variables are not secrets and can be read by permitted GitHub users and workflows. This action uses the selected assigned field. There is no atomic compare-and-set: another actor can change or delete the variable after these observations. Cancel does not undo a sent request. Readback confirms the observed value only; it does not prove a build or release works.";

#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="lowercase")]
pub(crate) enum VariableMode{Create,Replace}
macro_rules! variable_requirements {
    ($(($variant:ident,$name:literal,$kind:literal,$field:literal,$platform:ident)),+ $(,)?)=>{
        #[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
        pub(crate) enum VariableRequirement{$(#[serde(rename=$name)] $variant),+}
        impl VariableRequirement {
            pub(crate) fn name(self)->&'static str{match self{$(Self::$variant=>$name),+}}
            pub(crate) fn record_kind(self)->&'static str{match self{$(Self::$variant=>$kind),+}}
            pub(crate) fn field(self)->&'static str{match self{$(Self::$variant=>$field),+}}
            pub(crate) fn platform(self)->SecretPlatform{match self{$(Self::$variant=>SecretPlatform::$platform),+}}
        }
    }
}
variable_requirements!(
    (AndroidKeyAlias,"MOBILE_RELEASE_ANDROID_KEY_ALIAS","android-keystore","keyAlias",Android),
    (GoogleWifProvider,"MOBILE_RELEASE_GOOGLE_WIF_PROVIDER","google-wif","provider",Android),
    (GoogleServiceAccount,"MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT","google-wif","serviceAccount",Android),
    (AscKeyId,"MOBILE_RELEASE_ASC_KEY_ID","asc-p8","keyId",Ios),
    (AscIssuerId,"MOBILE_RELEASE_ASC_ISSUER_ID","asc-p8","issuerId",Ios),
);
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct VariableSelection {
    pub(crate) mode:VariableMode,pub(crate) stage:EnvironmentStage,
    pub(crate) requirement:VariableRequirement,pub(crate) source:SecretRecord,
}
impl VariableSelection {
    pub(crate) fn valid(&self)->bool{self.source.valid()}
    pub(crate) fn retained_heap_bytes(&self)->usize{self.source.retained_heap_bytes()}
}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct VariableFingerprint{pub(crate) bytes:u32,pub(crate) sha256:String}
impl VariableFingerprint {
    fn valid(&self)->bool{self.bytes<=49152&&hex(&self.sha256,64)
        &&(self.bytes!=0||self.sha256==format!("{:x}",Sha256::digest([])))}
    pub(crate) fn matches(&self,value:&str)->bool{self.bytes as usize==value.len()
        &&self.sha256==format!("{:x}",Sha256::digest(value.as_bytes()))}
}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct VariableMetadata{pub(crate) created_at:String,pub(crate) updated_at:String}
impl VariableMetadata {
    fn valid(&self)->bool{utc(&self.created_at)&&utc(&self.updated_at)}
    fn retained_heap_bytes(&self)->Option<usize>{self.created_at.capacity().checked_add(self.updated_at.capacity())}
}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct VariableFacts {
    pub(crate) environment_name:String,pub(crate) environment_id:String,pub(crate) name:String,
    #[serde(deserialize_with="nullable")]pub(crate) value:Option<VariableFingerprint>,
    #[serde(deserialize_with="nullable")]pub(crate) metadata:Option<VariableMetadata>,
}
impl VariableFacts {
    pub(crate) fn valid_for(&self,selection:&VariableSelection)->bool {
        environment_id(&self.environment_id)&&self.environment_name==selection.stage.name()
            &&self.name==selection.requirement.name()&&self.value.is_none()==self.metadata.is_none()
            &&self.value.as_ref().is_none_or(VariableFingerprint::valid)
            &&self.metadata.as_ref().is_none_or(VariableMetadata::valid)
            &&serde_json::to_vec(self).is_ok_and(|v|v.len()<=VARIABLE_FACTS_LIMIT)
    }
    fn before_for(&self,selection:&VariableSelection)->bool{self.valid_for(selection)&&match selection.mode{
        VariableMode::Create=>self.value.is_none(),VariableMode::Replace=>self.value.is_some()}}
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{self.environment_name.capacity().checked_add(self.environment_id.capacity())?
        .checked_add(self.name.capacity())?.checked_add(self.value.as_ref().map_or(0,|v|v.sha256.capacity()))?
        .checked_add(self.metadata.as_ref().map_or(Some(0),VariableMetadata::retained_heap_bytes)?)}
}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct VariableDesired{pub(crate) text:String,pub(crate) bytes:u32,pub(crate) sha256:String}
impl VariableDesired {
    fn valid(&self)->bool{(1..=VARIABLE_VALUE_LIMIT).contains(&self.text.len())
        &&self.bytes as usize==self.text.len()&&hex(&self.sha256,64)
        &&self.sha256==format!("{:x}",Sha256::digest(self.text.as_bytes()))}
    fn retained_heap_bytes(&self)->Option<usize>{self.text.capacity().checked_add(self.sha256.capacity())}
}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct VariableAfter{pub(crate) name:String,pub(crate) value:VariableDesired}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct VariablePrepared {
    pub(crate) target:Target,pub(crate) before:VariableFacts,pub(crate) after:VariableAfter,
    pub(crate) configuration:SecretConfiguration,pub(crate) observed_at:String,pub(crate) confirmation:String,
}
impl VariablePrepared {
    pub(crate) fn valid(&self)->bool {
        let Selection::Variable(selected)=&self.target.selection else{return false};
        self.target.valid()&&self.before.before_for(selected)&&self.after.name==selected.requirement.name()
            &&self.after.value.valid()&&!self.before.value.as_ref().is_some_and(|v|v.matches(&self.after.value.text))
            &&self.configuration.valid()&&utc(&self.observed_at)&&self.confirmation==VARIABLE_CONFIRMATION
            &&serde_json::to_vec(self).is_ok_and(|v|v.len()<=VARIABLE_PREPARED_LIMIT)
        // Actual credential_format_error/requiredness remains the shared core
        // policy. The native owner separately binds this exact text to its loan.
    }
    pub(crate) fn matches_after(&self,facts:&VariableFacts)->bool {
        let Selection::Variable(selected)=&self.target.selection else{return false};
        facts.valid_for(selected)&&facts.environment_id==self.before.environment_id
            &&facts.value.as_ref().is_some_and(|v|v.matches(&self.after.value.text))
    }
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{self.target.retained_heap_bytes()?.checked_add(self.before.retained_heap_bytes()?)?
        .checked_add(self.after.name.capacity())?.checked_add(self.after.value.retained_heap_bytes()?)?
        .checked_add(self.configuration.retained_heap_bytes()?)?.checked_add(self.observed_at.capacity())?
        .checked_add(self.confirmation.capacity())}
}
#[derive(Clone,Debug,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase")]
pub(crate) struct VariableSource {
    pub(crate) root:String,pub(crate) root_identity:SecretRootIdentity,pub(crate) draft:SecretContent,
    pub(crate) platform:SecretPlatform,pub(crate) purpose:SecretPurpose,pub(crate) material:VariableFingerprint,
}
impl VariableSource {
    pub(crate) fn valid_for(&self,selected:&VariableSelection)->bool {
        let decimal=|v:&str|v.parse::<u64>().is_ok_and(|n|n.to_string()==v);
        self.root.starts_with('/')&&self.root.len()<=4096&&!self.root.chars().any(char::is_control)
            &&decimal(&self.root_identity.device)&&decimal(&self.root_identity.inode)
            &&self.root_identity.mode&0o170000==0o040000&&self.draft.valid()
            &&self.platform==selected.requirement.platform()&&self.material.valid()
            &&(1..=VARIABLE_VALUE_LIMIT as u32).contains(&self.material.bytes)
    }
    pub(crate) fn retained_heap_bytes(&self)->Option<usize>{self.root.capacity().checked_add(self.root_identity.device.capacity())?
        .checked_add(self.root_identity.inode.capacity())?.checked_add(self.draft.sha256.capacity())?
        .checked_add(self.material.sha256.capacity())}
}
pub(super) fn variable_selection_shape(value:&Value)->bool{value.is_object()
    &&(value.get("kind").and_then(Value::as_str)!=Some("environment_variable")||value.get("source").is_some_and(Value::is_object))}
fn variable_target_shape(value:&Value)->bool{value.is_object()&&value.get("selection").is_some_and(variable_selection_shape)}
fn variable_facts_shape(value:&Value)->bool{value.is_object()
    &&value.get("value").is_some_and(|v|v.is_null()||v.is_object())
    &&value.get("metadata").is_some_and(|v|v.is_null()||v.is_object())}
fn variable_configuration_shape(value:&Value)->bool{value.is_object()
    &&value.get("savedConfig").is_some_and(Value::is_object)&&value.get("canonicalConfig").is_some_and(Value::is_object)}
fn variable_prepared_shape(value:&Value)->bool{value.is_object()
    &&value.get("target").is_some_and(variable_target_shape)&&value.get("before").is_some_and(variable_facts_shape)
    &&value.get("after").is_some_and(|v|v.is_object()&&v.get("value").is_some_and(Value::is_object))
    &&value.get("configuration").is_some_and(variable_configuration_shape)}
pub(super) fn variable_reply_shape(value:&Value)->bool{value.get("result").is_some_and(|result|result.is_object()
    &&result.get("control").is_some_and(Value::is_object)
    &&result.get("prepared").is_some_and(|v|v.is_null()||variable_prepared_shape(v))
    &&result.get("observed").is_some_and(|v|v.is_null()||variable_facts_shape(v)))}

pub(crate) fn encode_variable_initial(id:&str,request:&Request,source:&VariableSource)->Result<Vec<u8>,BridgeError>{
    let Selection::Variable(selected)=&request.target.selection else{return Err(BridgeError::invalid())};
    if !valid_id(id)||!request.valid()||!source.valid_for(selected){return Err(BridgeError::invalid())}
    if let Some(prepared)=&request.prepared{
        let Prepared::Variable(prepared)=prepared else{return Err(BridgeError::invalid())};
        if prepared.configuration.canonical_config!=source.draft||!source.material.matches(&prepared.after.value.text){return Err(BridgeError::invalid())}
    }
    let value=serde_json::json!({"protocol":PROTOCOL,"id":id,"action":{
        "kind":request.kind,"target":request.target,"prepared":request.prepared,"source":source}});
    if !bounds(&value,INITIAL_LIMIT-1,256,8){return Err(BridgeError::invalid())}
    let mut raw=serde_json::to_vec(&value).map_err(|_|BridgeError::invalid())?;raw.push(b'\n');
    if raw.len()>INITIAL_LIMIT{return Err(BridgeError::invalid())}Ok(raw)
}

// Same ordinary GO cap. No token or value Value/String clone, no secret frame
// and no helper. Bound every extension before it can grow the charged backing.
pub(crate) fn encode_variable_go(id:&str,digest:&str,token:&str,value:&str)->Result<Vec<u8>,BridgeError>{
    if !valid_id(id)||!hex(digest,64)||token.is_empty()||token.len()>4096
        ||!token.bytes().all(|b|(0x21..=0x7e).contains(&b))
        ||!(1..=VARIABLE_VALUE_LIMIT).contains(&value.len()){return Err(BridgeError::invalid())}
    struct Fixed(Vec<u8>);
    impl std::io::Write for Fixed{
        fn write(&mut self,bytes:&[u8])->std::io::Result<usize>{
            if self.0.len().checked_add(bytes.len()).is_none_or(|n|n>GO_LIMIT){
                return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));}
            self.0.extend_from_slice(bytes);Ok(bytes.len())
        }
        fn flush(&mut self)->std::io::Result<()>{Ok(())}
    }
    use std::io::Write;
    let mut raw=Vec::new();raw.try_reserve_exact(GO_LIMIT).map_err(|_|BridgeError::invalid())?;
    if raw.capacity()>GO_LIMIT{return Err(BridgeError::invalid())}let mut out=Fixed(raw);
    out.write_all(b"{\"protocol\":\"mrk-github-setup/1\",\"id\":").map_err(|_|BridgeError::invalid())?;
    serde_json::to_writer(&mut out,id).map_err(|_|BridgeError::invalid())?;
    out.write_all(b",\"go\":{\"requestSha256\":").map_err(|_|BridgeError::invalid())?;
    serde_json::to_writer(&mut out,digest).map_err(|_|BridgeError::invalid())?;
    out.write_all(b",\"token\":").map_err(|_|BridgeError::invalid())?;
    serde_json::to_writer(&mut out,token).map_err(|_|BridgeError::invalid())?;
    out.write_all(b",\"value\":").map_err(|_|BridgeError::invalid())?;
    serde_json::to_writer(&mut out,value).map_err(|_|BridgeError::invalid())?;
    out.write_all(b"}}\n").map_err(|_|BridgeError::invalid())?;Ok(out.0)
}

#[cfg(test)]
pub(super) fn variable_contract_checks(){
    // Called from the existing Setup codec group after shared integration.
    // These are DATA fixtures, not native material or remote evidence.
    let cases=[(VariableRequirement::AndroidKeyAlias,"release.key-1"),
        (VariableRequirement::GoogleWifProvider,"projects/123/locations/global/workloadIdentityPools/release/providers/github"),
        (VariableRequirement::GoogleServiceAccount,"release-bot@example-project.iam.gserviceaccount.com"),
        (VariableRequirement::AscKeyId,"A1B2C3D4E5"),
        (VariableRequirement::AscIssuerId,"12345678-1234-5678-abcd-123456789abc")];
    for (requirement,text) in cases{
        for mode in [VariableMode::Create,VariableMode::Replace]{
            let selection=VariableSelection{mode,stage:EnvironmentStage::Candidate,requirement,
                source:SecretRecord{record_id:"a".repeat(32),record_revision:3,context_revision:9}};
            let selected=serde_json::json!({"kind":"environment_variable","mode":mode,"stage":"candidate",
                "requirement":requirement,"source":{"recordId":"a".repeat(32),"recordRevision":3,"contextRevision":9}});
            assert!(variable_selection_shape(&selected));
            let mut array=selected.clone();array["source"]=serde_json::json!(["a".repeat(32),3,9]);
            assert!(!variable_selection_shape(&array));
            let target:Target=serde_json::from_value(serde_json::json!({"projectBinding":"b".repeat(64),
                "repository":"Owner/Repo","accountId":"11","repositoryId":"22","selection":selected})).unwrap();
            let prior=if mode==VariableMode::Replace{Some(VariableFingerprint{bytes:3,sha256:format!("{:x}",Sha256::digest(b"old"))})}else{None};
            let metadata=prior.as_ref().map(|_|VariableMetadata{created_at:"2026-10-09T12:00:00Z".into(),updated_at:"2026-10-09T12:00:00Z".into()});
            let before=VariableFacts{environment_name:selection.stage.name().into(),environment_id:"33".into(),
                name:requirement.name().into(),value:prior,metadata};
            let configuration=SecretConfiguration{saved_config:SecretContent{bytes:100,sha256:"c".repeat(64)},
                canonical_config:SecretContent{bytes:120,sha256:"d".repeat(64)}};
            let prepared=VariablePrepared{target:target.clone(),before:before.clone(),after:VariableAfter{
                name:requirement.name().into(),value:VariableDesired{text:text.into(),bytes:text.len()as u32,sha256:format!("{:x}",Sha256::digest(text.as_bytes()))}},
                configuration:configuration.clone(),observed_at:"2026-10-09T12:00:01Z".into(),confirmation:VARIABLE_CONFIRMATION.into()};
            assert!(prepared.valid());
            let mut wrong=prepared.clone();wrong.after.value.sha256="e".repeat(64);assert!(!wrong.valid());
            let mut after=before.clone();after.value=Some(VariableFingerprint{bytes:text.len()as u32,
                sha256:prepared.after.value.sha256.clone()});after.metadata=Some(VariableMetadata{
                created_at:"2026-10-09T12:00:00Z".into(),updated_at:"2026-10-09T12:00:01Z".into()});
            assert!(prepared.matches_after(&after));after.value.as_mut().unwrap().sha256="e".repeat(64);assert!(!prepared.matches_after(&after));
            let source=VariableSource{root:"/inert/project".into(),root_identity:SecretRootIdentity{device:"1".into(),inode:"2".into(),mode:0o40700,uid:1,gid:1},
                draft:configuration.canonical_config,platform:requirement.platform(),purpose:SecretPurpose::Full,
                material:VariableFingerprint{bytes:text.len()as u32,sha256:prepared.after.value.sha256.clone()}};
            let prepare=Request{kind:Kind::Prepare,target:target.clone(),prepared:None};
            let raw=encode_variable_initial("setup-1",&prepare,&source).unwrap();assert!(raw.len()<=INITIAL_LIMIT);
            let apply=Request{kind:Kind::Apply,target,prepared:Some(Prepared::Variable(prepared.clone()))};
            assert!(encode_variable_initial("setup-1",&apply,&source).is_ok());
            let mut wrong=source.clone();wrong.material.sha256="e".repeat(64);assert!(encode_variable_initial("setup-1",&apply,&wrong).is_err());
            let go=encode_variable_go("setup-1",&request_digest(&raw),"inert-token",text).unwrap();
            assert!(go.len()<=GO_LIMIT);let value:Value=serde_json::from_slice(&go).unwrap();assert_eq!(value["go"]["value"],text);
            let mut envelope=serde_json::json!({"result":{"control":{},"prepared":prepared,"observed":before}});
            assert!(variable_reply_shape(&envelope));
            for pointer in ["/result","/result/control","/result/prepared","/result/prepared/target",
                "/result/prepared/target/selection","/result/prepared/target/selection/source","/result/prepared/before",
                "/result/prepared/after","/result/prepared/after/value","/result/prepared/configuration",
                "/result/prepared/configuration/savedConfig","/result/prepared/configuration/canonicalConfig","/result/observed"]{
                let mut bad=envelope.clone();*bad.pointer_mut(pointer).unwrap()=serde_json::json!([]);assert!(!variable_reply_shape(&bad),"{pointer}");
            }
            // Present nullable object nodes must also reject positional arrays.
            envelope["result"]["observed"]["value"]=serde_json::json!([]);assert!(!variable_reply_shape(&envelope));
            // Exercise the actual shared reply/command/future-status codecs,
            // not only the isolated shape helper. No native source is claimed.
            let line=|v:&Value|{let mut raw=serde_json::to_vec(v).unwrap();raw.push(b'\n');raw};
            let control=serde_json::json!({"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false});
            let reply=serde_json::json!({"protocol":PROTOCOL,"id":"setup-1","result":{
                "schemaVersion":1,"action":"prepare","reason":"none","effect":"not-started",
                "writeClaimed":false,"writeAcknowledged":false}});
            let mut reply=reply;
            reply["result"]["prepared"]=serde_json::to_value(&prepared).unwrap();
            reply["result"]["observed"]=serde_json::to_value(&before).unwrap();reply["result"]["control"]=control.clone();
            assert!(decode_reply("setup-1",&line(&reply),&prepare).is_ok());
            assert!(decode_reply("setup-1",&line(&reply),&apply).is_err());
            assert!(future_status_fits(&prepare,"session-1")&&future_status_fits(&apply,"session-1"));
            assert!(encode_initial("setup-1",&prepare).is_err());
            let args=serde_json::json!({"sessionId":"session-1","expectedRevision":1,"expectedConnectionRevision":1,"selection":selected});
            assert!(decode_command("github_remote_setup_prepare",&args).is_ok());
            let mut bad=args.clone();bad["selection"]["source"]=serde_json::json!(["a".repeat(32),3,9]);
            assert!(decode_command("github_remote_setup_prepare",&bad).is_err());
            for pointer in ["/result","/result/control","/result/prepared","/result/prepared/target",
                "/result/prepared/target/selection","/result/prepared/target/selection/source","/result/prepared/before",
                "/result/prepared/after","/result/prepared/after/value","/result/prepared/configuration",
                "/result/prepared/configuration/savedConfig","/result/prepared/configuration/canonicalConfig","/result/observed"]{
                let mut bad=reply.clone();*bad.pointer_mut(pointer).unwrap()=serde_json::json!([]);
                assert!(decode_reply("setup-1",&line(&bad),&prepare).is_err(),"{pointer}");
            }
            let mut bad=reply.clone();bad["result"]["prepared"]["after"]["value"]["text"]=serde_json::json!("changed");
            assert!(decode_reply("setup-1",&line(&bad),&prepare).is_err());
            after.value.as_mut().unwrap().sha256=prepared.after.value.sha256.clone();
            let mut committed=reply.clone();committed["result"]["action"]=serde_json::json!("apply");
            committed["result"]["effect"]=serde_json::json!("readback-confirmed");committed["result"]["prepared"]=Value::Null;
            committed["result"]["writeClaimed"]=serde_json::json!(true);committed["result"]["writeAcknowledged"]=serde_json::json!(true);
            committed["result"]["observed"]=serde_json::to_value(&after).unwrap();
            assert!(decode_reply("setup-1",&line(&committed),&apply).is_ok());
            let mut bad=committed.clone();bad["result"]["effect"]=serde_json::json!("accepted-not-value-verified");
            assert!(decode_reply("setup-1",&line(&bad),&apply).is_err());
            let mut bad=committed.clone();bad["result"]["observed"]["environmentId"]=serde_json::json!("34");
            assert!(decode_reply("setup-1",&line(&bad),&apply).is_err());
            for reason in ["variable-changed","variable-exists","variable-missing","configuration-changed","resources-unavailable"]{
                let mut failed=committed.clone();failed["result"]["reason"]=serde_json::json!(reason);
                failed["result"]["effect"]=serde_json::json!("unknown");failed["result"]["observed"]=Value::Null;
                assert!(decode_reply("setup-1",&line(&failed),&apply).is_ok());
                failed["result"]["reason"]=serde_json::json!("secret-key-changed");
                assert!(decode_reply("setup-1",&line(&failed),&apply).is_err());
            }
        }
    }
    assert_eq!(VariableRequirement::AndroidKeyAlias.field(),"keyAlias");
    assert!(serde_json::from_str::<VariableRequirement>("\"OPERATION_COMMITMENT_KEY_VERSION\"").is_err());
    let hash="b".repeat(64);
    assert!(encode_variable_go("setup-1",&hash,&"x".repeat(4096),&"y".repeat(4096)).is_err());
    assert!(encode_variable_go("setup-1",&hash,"inert",&"\\".repeat(4096)).is_err());
    for token in ["","has space","bad\n"]{assert!(encode_variable_go("setup-1",&hash,token,"release").is_err());}
    assert!(encode_go("setup-1",&hash,"inert").is_ok());
    assert_eq!(VARIABLE_WIRE_BUFFERS,8192+8192+8193+8192+8192+8193+8192+8192+4096+4096+49152+49152+8192+8192+8192+65536+65536+335872);
}
