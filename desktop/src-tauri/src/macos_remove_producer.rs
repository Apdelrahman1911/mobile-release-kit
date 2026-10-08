//! Closed remove-purpose DATA, never signature, peer, exclusion or deletion authority.
//! The current installed INSTALL producer remains independently authenticated.
#![forbid(unsafe_code)]
use serde::Deserialize;
use sha2::{Digest,Sha256};
use crate::{macos_install_producer::ProducerData,macos_install_maintenance::MaintenanceTargetData,protocol::strict_json};

pub const DESCRIPTOR_FILENAME:&str="remove-producer.json";
pub const SIGNATURE_FILENAME:&str="remove-producer.sig";
pub const DESCRIPTOR_LIMIT:usize=16*1024;
pub const SIGNED_DOMAIN:&[u8]=b"MobileReleaseKit-remove-producer-v1\0";
pub const REMOVER_EXECUTABLE:&str="mrk-macos-remove";
pub const REMOVER_IDENTIFIER:&str="dev.mobile-release-kit.desktop.remove";
const DOMAIN:&str="MobileReleaseKit-remove-producer-v1";
const KIND:&str="mrk-macos-remove-producer-v1";
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum DataError{Limit,Shape,Binding,Installed,Policy}
type Result<T>=std::result::Result<T,DataError>;
fn need(ok:bool,why:DataError)->Result<()>{if ok{Ok(())}else{Err(why)}}
fn hex(value:&str,size:usize)->bool{value.len()==size&&value.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
    &&value.bytes().any(|b|b!=b'0')}
fn hash(bytes:&[u8])->String{format!("{:x}",Sha256::digest(bytes))}
fn version(value:&str)->bool{
    if value.len()>32{return false;}
    let parts:Vec<_>=value.split('.').collect();parts.len()==3&&parts.iter().all(|p|!p.is_empty()
        &&p.bytes().all(|b|b.is_ascii_digit())&&(p.len()==1||!p.starts_with('0'))&&p.parse::<u32>().is_ok())
}
#[derive(Debug,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Wire{
    schema_version:u32,kind:String,domain:String,target:String,source_commit:String,release:String,
    protocol_sha256:String,installed_producer_sha256:String,installed_inventory_sha256:String,
    signing_policy_sha256:String,package_identifier:String,package_version:String,package_sha256:String,
    remover_executable_sha256:String,
}
#[derive(Debug)]
pub struct RemovalData{wire:Wire,target:MaintenanceTargetData}
/// Read-only values, not a current-attempt removal or permission token.
#[derive(Clone,Copy)]
pub struct BindingData<'a>{
    pub target:MaintenanceTargetData,pub source_commit:&'a str,pub release:&'a str,pub protocol_sha256:&'a str,
    pub installed_producer_sha256:&'a str,pub installed_inventory_sha256:&'a str,pub signing_policy_sha256:&'a str,
    pub package_version:&'a str,pub package_sha256:&'a str,pub remover_executable_sha256:&'a str,
}
/// Independently SOURCE-selected/current final originals. Never fill from the
/// descriptor being checked or destination discovery. Actual signatures/roles
/// and same-original POST/close remain caller obligations.
pub struct EmissionBindingData<'a>{
    pub target:MaintenanceTargetData,pub source_commit:&'a str,pub release:&'a str,pub protocol_sha256:&'a str,
    pub installed_producer_sha256:&'a str,pub installed_inventory_sha256:&'a str,pub package_version:&'a str,
    pub completed_package_sha256:&'a str,pub remover_executable_sha256:&'a str,
    pub team:&'a [u8;10],pub leaf_sha1:&'a [u8;20],pub leaf_sha256:&'a [u8;32],
}
impl RemovalData{
    pub fn parse_data(bytes:&[u8],target:MaintenanceTargetData)->Result<Self>{
        need(!bytes.is_empty()&&bytes.len()<=DESCRIPTOR_LIMIT,DataError::Limit)?;
        let raw=strict_json(bytes).map_err(|_|DataError::Shape)?;
        let wire:Wire=serde_json::from_value(raw).map_err(|_|DataError::Shape)?;
        need(wire.schema_version==1&&wire.kind==KIND&&wire.domain==DOMAIN&&wire.target==target.target()
            &&wire.package_identifier==REMOVER_IDENTIFIER,DataError::Binding)?;
        need(hex(&wire.source_commit,40)&&version(&wire.package_version)&&wire.release.len()<=128
            &&wire.release.starts_with(target.release_prefix())&&wire.release.len()>target.release_prefix().len()
            &&wire.release.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b"-_.".contains(&b))
            &&wire.release.as_bytes().last().is_some_and(|b|b.is_ascii_lowercase()||b.is_ascii_digit())
            &&[&wire.protocol_sha256,&wire.installed_producer_sha256,&wire.installed_inventory_sha256,
                &wire.signing_policy_sha256,&wire.package_sha256,&wire.remover_executable_sha256].iter().all(|v|hex(v,64)),
            DataError::Binding)?;
        Ok(Self{wire,target})
    }
    pub fn binding_data(&self)->BindingData<'_>{let w=&self.wire;BindingData{target:self.target,source_commit:&w.source_commit,
        release:&w.release,protocol_sha256:&w.protocol_sha256,installed_producer_sha256:&w.installed_producer_sha256,
        installed_inventory_sha256:&w.installed_inventory_sha256,signing_policy_sha256:&w.signing_policy_sha256,
        package_version:&w.package_version,package_sha256:&w.package_sha256,remover_executable_sha256:&w.remover_executable_sha256}}
    /// Exact RAW installed descriptor and current tuple, never a predecessor.
    /// This returns parsed INSTALL DATA only, not its signature or live tree.
    pub fn installed_data(&self,raw_installed:&[u8])->Result<ProducerData>{
        need(!raw_installed.is_empty()&&raw_installed.len()<=crate::macos_install_producer::DESCRIPTOR_LIMIT,
            DataError::Limit)?;
        need(hash(raw_installed)==self.wire.installed_producer_sha256,DataError::Installed)?;
        let data=ProducerData::parse_data(raw_installed,self.target).map_err(|_|DataError::Installed)?;
        let current=data.release_set_data().current_data().binding_data();let w=&self.wire;
        need(current.source_commit==w.source_commit&&current.release==w.release&&current.protocol_sha256==w.protocol_sha256
            &&current.inventory_sha256==w.installed_inventory_sha256&&current.signing_policy_sha256==w.signing_policy_sha256
            &&current.package_version==w.package_version,DataError::Installed)?;
        Ok(data)
    }
    pub fn validate_emission_data(&self,expected:&EmissionBindingData<'_>,raw_installed:&[u8])->Result<()>{
        let w=&self.wire;
        need(self.target==expected.target&&w.source_commit==expected.source_commit&&w.release==expected.release
            &&w.protocol_sha256==expected.protocol_sha256&&w.installed_producer_sha256==expected.installed_producer_sha256
            &&w.installed_inventory_sha256==expected.installed_inventory_sha256&&w.package_version==expected.package_version
            &&w.package_sha256==expected.completed_package_sha256&&w.remover_executable_sha256==expected.remover_executable_sha256,
            DataError::Binding)?;
        let installed=self.installed_data(raw_installed)?;
        need(installed.signing_policy_data().matches_source_data(expected.team,expected.leaf_sha1,expected.leaf_sha256),DataError::Policy)
    }
}
/// Original raw bytes; the fixed remover native constructor uses this SAME
/// domain. This allocation alone never verifies or signs anything.
pub fn message_data(descriptor:&[u8])->Result<Vec<u8>>{
    need(!descriptor.is_empty()&&descriptor.len()<=DESCRIPTOR_LIMIT,DataError::Limit)?;
    let mut bytes=Vec::with_capacity(SIGNED_DOMAIN.len()+descriptor.len());bytes.extend_from_slice(SIGNED_DOMAIN);
    bytes.extend_from_slice(descriptor);Ok(bytes)
}
#[cfg(test)]
mod tests{
    use super::*;use serde_json::{json,Value};
    fn fixtures(target:MaintenanceTargetData)->(Value,Vec<u8>){
        let policy_text=format!("{{\"schemaVersion\":1,\"kind\":\"mrk-macos-developer-id-code-policy-v1\",\"teamIdentifier\":\"TEAM000001\",\"leafCertificateSha1\":\"{}\",\"leafCertificateSha256\":\"{}\",\"hardenedRuntime\":true,\"entitlements\":\"empty\"}}","01".repeat(20),"02".repeat(32));
        let policy=hash(policy_text.as_bytes());let release=format!("{}remove-data",target.release_prefix());
        let install=json!({"schemaVersion":2,"kind":"mrk-macos-install-producer-v2","domain":"MobileReleaseKit-package-producer-v2",
            "target":target.target(),"releaseSet":{"schemaVersion":2,"current":{
                "profile":if target==MaintenanceTargetData::Arm64{"fixed-macos26-arm64-maintenance-v2"}else{"fixed-macos26-x86_64-maintenance-v2"},
                "packageIdentifier":"dev.mobile-release-kit.desktop.installed","bundleIdentifier":"dev.mobile-release-kit.desktop",
                "packageVersion":"0.9.1","release":release,"sourceCommit":"1".repeat(40),"protocolSha256":"2".repeat(64),
                "runtimeManifestSha256":"3".repeat(64),"inventorySha256":"4".repeat(64),"signingPolicySha256":policy,"packageSha256":"5".repeat(64)},
                "acceptedPredecessors":[]},"signingPolicies":[{"sha256":policy,"policy":serde_json::from_str::<Value>(&policy_text).unwrap()}]});
        let raw=serde_json::to_vec(&install).unwrap();
        (json!({"schemaVersion":1,"kind":KIND,"domain":DOMAIN,"target":target.target(),"sourceCommit":"1".repeat(40),
            "release":release,"protocolSha256":"2".repeat(64),"installedProducerSha256":hash(&raw),"installedInventorySha256":"4".repeat(64),
            "signingPolicySha256":policy,"packageIdentifier":REMOVER_IDENTIFIER,"packageVersion":"0.9.1","packageSha256":"6".repeat(64),
            "removerExecutableSha256":"7".repeat(64)}),raw)
    }
    fn parse(v:&Value,target:MaintenanceTargetData)->Result<RemovalData>{RemovalData::parse_data(&serde_json::to_vec(v).unwrap(),target)}
    #[test]
    fn fixed_remove_domain_raw_installed_current_and_final_package_are_distinct(){
        for target in [MaintenanceTargetData::Arm64,MaintenanceTargetData::Intel]{
            let(v,raw)=fixtures(target);let data=parse(&v,target).unwrap();let b=data.binding_data();
            let expected=EmissionBindingData{target,source_commit:b.source_commit,release:b.release,protocol_sha256:b.protocol_sha256,
                installed_producer_sha256:b.installed_producer_sha256,installed_inventory_sha256:b.installed_inventory_sha256,
                package_version:b.package_version,completed_package_sha256:b.package_sha256,remover_executable_sha256:b.remover_executable_sha256,
                team:b"TEAM000001",leaf_sha1:&[1;20],leaf_sha256:&[2;32]};
            data.validate_emission_data(&expected,&raw).unwrap();
            assert_eq!(data.installed_data(&raw).unwrap().completed_package_sha256_data(),"5".repeat(64));
            assert_ne!(b.package_sha256,"5".repeat(64));
            let pretty=serde_json::to_vec_pretty(&v).unwrap();let message=message_data(&pretty).unwrap();
            assert_eq!(&message[..SIGNED_DOMAIN.len()],SIGNED_DOMAIN);assert_eq!(&message[SIGNED_DOMAIN.len()..],pretty);
            assert_ne!(message,crate::macos_install_producer::message_data(&pretty).unwrap());
            assert!(ProducerData::parse_data(&pretty,target).is_err());assert!(RemovalData::parse_data(&raw,target).is_err());
            let installed:Value=serde_json::from_slice(&raw).unwrap();let reserialized=serde_json::to_vec_pretty(&installed).unwrap();
            assert!(data.installed_data(&reserialized).is_err());
            for key in ["sourceCommit","release","protocolSha256","installedProducerSha256","installedInventorySha256",
                "signingPolicySha256","packageVersion","packageSha256","removerExecutableSha256"]{
                let mut changed=v.clone();changed[key]=match key{"sourceCommit"=>json!("8".repeat(40)),"release"=>json!(format!("{}other",target.release_prefix())),
                    "packageVersion"=>json!("0.9.2"),_=>json!("8".repeat(64))};
                let changed=parse(&changed,target).unwrap();assert!(changed.validate_emission_data(&expected,&raw).is_err(),"{key}");
            }
            let bad=EmissionBindingData{team:b"OTHER00001",..expected};assert!(data.validate_emission_data(&bad,&raw).is_err());
        }
    }
    #[test]
    fn closed_remove_shape_limits_and_current_only_binding_refuse_mixed_authority(){
        let target=MaintenanceTargetData::Arm64;let(v,raw)=fixtures(target);
        assert!(parse(&v,MaintenanceTargetData::Intel).is_err());
        for key in v.as_object().unwrap().keys(){let mut missing=v.clone();missing.as_object_mut().unwrap().remove(key);assert!(parse(&missing,target).is_err());}
        for(key,value)in [("schemaVersion",json!(2)),("schemaVersion",json!(true)),("kind",json!("mrk-macos-install-producer-v2")),
            ("domain",json!("MobileReleaseKit-package-producer-v2")),("packageIdentifier",json!("dev.mobile-release-kit.desktop.installed")),
            ("sourceCommit",json!("0".repeat(40))),("release",json!("../release")),("packageVersion",json!("01.2.3")),
            ("packageSha256",json!("A".repeat(64))),("incomingApp",json!("/not-a-capability"))]{let mut bad=v.clone();bad[key]=value;assert!(parse(&bad,target).is_err());}
        let encoded=serde_json::to_vec(&v).unwrap();let mut duplicate=encoded.clone();duplicate.pop();duplicate.extend_from_slice(b",\"schemaVersion\":1}");
        assert!(RemovalData::parse_data(&duplicate,target).is_err());assert!(message_data(&[]).is_err());
        assert!(RemovalData::parse_data(&vec![b' ';DESCRIPTOR_LIMIT+1],target).is_err());assert!(message_data(&vec![b' ';DESCRIPTOR_LIMIT+1]).is_err());
        let mut installed:Value=serde_json::from_slice(&raw).unwrap();let old=installed["releaseSet"]["current"].clone();
        installed["releaseSet"]["current"]["release"]=json!(format!("{}next",target.release_prefix()));
        installed["releaseSet"]["current"]["packageVersion"]=json!("0.9.2");installed["releaseSet"]["current"]["packageSha256"]=json!("9".repeat(64));
        installed["releaseSet"]["acceptedPredecessors"]=json!([old]);let raw=serde_json::to_vec(&installed).unwrap();
        assert!(ProducerData::parse_data(&raw,target).is_ok());let mut changed=v;changed["installedProducerSha256"]=json!(hash(&raw));
        assert!(parse(&changed,target).unwrap().installed_data(&raw).is_err());
    }
}
