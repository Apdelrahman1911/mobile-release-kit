//! Closed completed-package producer DATA. Parsing, policy hashes and accessors
//! are not signature, Developer-ID, package, original-file or finality authority.
//! The caller must authenticate the exact raw descriptor and verify the current
//! SOURCE-selected product's Developer-ID purpose before using this release set.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::{macos_install_maintenance::{MaintenanceTargetData, ReleaseData, ReleaseSetData},
    protocol::strict_json};

pub const DESCRIPTOR_FILENAME: &str = "producer.json";
pub const SIGNATURE_FILENAME: &str = "producer.sig";
pub const DESCRIPTOR_LIMIT: usize = 64 * 1024;
pub const SIGNATURE_LIMIT: usize = 16 * 1024;
pub const CERTIFICATE_LIMIT: usize = 16 * 1024;
pub const POLICY_LIMIT: usize = 9;
pub const SIGNED_DOMAIN: &[u8] = b"MobileReleaseKit-package-producer-v2\0";
const DOMAIN: &str = "MobileReleaseKit-package-producer-v2";
const KIND: &str = "mrk-macos-install-producer-v2";
const POLICY_KIND: &str = "mrk-macos-developer-id-code-policy-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataError { Limit, Shape, Binding, Policy, Membership }
type Result<T> = std::result::Result<T, DataError>;
fn require(ok: bool, error: DataError) -> Result<()> { if ok { Ok(()) } else { Err(error) } }
fn hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}
fn digest(bytes: &[u8]) -> String { Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect() }

// Declaration order is the v1 canonical policy encoding, not arbitrary JSON
// property ordering. This hash is NOT the old signing.profile text-file hash.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyWire {
    schema_version: u32,
    kind: String,
    team_identifier: String,
    leaf_certificate_sha1: String,
    leaf_certificate_sha256: String,
    hardened_runtime: bool,
    entitlements: String,
}
impl PolicyWire {
    fn validate(&self) -> Result<()> {
        require(self.schema_version == 1 && self.kind == POLICY_KIND
            && self.team_identifier.len() == 10
            && self.team_identifier.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            && hex(&self.leaf_certificate_sha1, 40) && hex(&self.leaf_certificate_sha256, 64)
            && self.hardened_runtime && self.entitlements == "empty", DataError::Policy)
    }
}

/// An authenticated descriptor may nominate this policy for an explicitly
/// accepted old release; it never chooses arbitrary requirements, paths or code
/// roles. Actual fixed-role static-code/purpose/DER validation is still native.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningPolicyData { wire: PolicyWire, canonical: Vec<u8>, sha256: String }
impl SigningPolicyData {
    pub fn team_identifier_data(&self) -> &str { &self.wire.team_identifier }
    pub fn leaf_certificate_sha1_data(&self) -> &str { &self.wire.leaf_certificate_sha1 }
    pub fn leaf_certificate_sha256_data(&self) -> &str { &self.wire.leaf_certificate_sha256 }
    pub fn canonical_bytes_data(&self) -> &[u8] { &self.canonical }
    pub fn sha256_data(&self) -> &str { &self.sha256 }
    pub fn requires_hardened_runtime_data(&self) -> bool { self.wire.hardened_runtime }
    pub fn requires_empty_entitlements_data(&self) -> bool { self.wire.entitlements == "empty" }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyRow { sha256: String, policy: PolicyWire }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProducerWire {
    schema_version: u32, kind: String, domain: String, target: String,
    release_set: serde_json::Value, signing_policies: Vec<PolicyRow>,
}

/// Private fields deliberately prevent serde or a caller from constructing a
/// validated wrapper without closed shape, target and policy correspondence.
#[derive(Debug)]
pub struct ProducerData {
    releases: ReleaseSetData,
    policies: Vec<SigningPolicyData>,
    current_policy: usize,
}
impl ProducerData {
    pub fn parse_data(bytes: &[u8], target: MaintenanceTargetData) -> Result<Self> {
        require(!bytes.is_empty() && bytes.len() <= DESCRIPTOR_LIMIT, DataError::Limit)?;
        let raw = strict_json(bytes).map_err(|_| DataError::Shape)?;
        require(raw.is_object() && raw.get("releaseSet").is_some_and(serde_json::Value::is_object), DataError::Shape)?;
        let rows = raw.get("signingPolicies").and_then(serde_json::Value::as_array).ok_or(DataError::Shape)?;
        require(!rows.is_empty() && rows.len() <= POLICY_LIMIT, DataError::Limit)?;
        require(rows.iter().all(|row| row.is_object()
            && row.get("policy").is_some_and(serde_json::Value::is_object)), DataError::Shape)?;
        let wire: ProducerWire = serde_json::from_value(raw).map_err(|_| DataError::Shape)?;
        require(wire.schema_version == 2 && wire.kind == KIND && wire.domain == DOMAIN
            && wire.target == target.target(), DataError::Binding)?;
        let release_bytes = serde_json::to_vec(&wire.release_set).map_err(|_| DataError::Shape)?;
        let releases = ReleaseSetData::parse_for_target_data(&release_bytes, target).map_err(|_| DataError::Binding)?;
        let mut policies: Vec<SigningPolicyData> = Vec::with_capacity(wire.signing_policies.len());
        for row in wire.signing_policies {
            row.policy.validate()?;
            let canonical = serde_json::to_vec(&row.policy).map_err(|_| DataError::Shape)?;
            require(hex(&row.sha256, 64) && digest(&canonical) == row.sha256
                && policies.last().is_none_or(|previous| previous.sha256 < row.sha256), DataError::Policy)?;
            policies.push(SigningPolicyData { wire: row.policy, canonical, sha256: row.sha256 });
        }
        let mut referenced = [false; POLICY_LIMIT];
        let mut current_policy = None;
        for (index, release) in std::iter::once(releases.current_data()).chain(releases.predecessor_data()).enumerate() {
            let selected = policies.iter().position(|policy| policy.sha256 == release.binding_data().signing_policy_sha256)
                .ok_or(DataError::Policy)?;
            referenced[selected] = true;
            if index == 0 { current_policy = Some(selected); }
        }
        require(referenced[..policies.len()].iter().all(|used| *used), DataError::Policy)?;
        Ok(Self { releases, policies, current_policy: current_policy.ok_or(DataError::Policy)? })
    }
    pub fn release_set_data(&self) -> &ReleaseSetData { &self.releases }
    pub fn completed_package_sha256_data(&self) -> &str { self.releases.current_data().binding_data().package_sha256 }
    pub fn signing_policy_data(&self) -> &SigningPolicyData { &self.policies[self.current_policy] }
    pub fn policy_for_release_data(&self, release: &ReleaseData) -> Result<&SigningPolicyData> {
        require(self.releases.contains_data(release), DataError::Membership)?;
        self.policies.iter().find(|policy| policy.sha256 == release.binding_data().signing_policy_sha256)
            .ok_or(DataError::Policy)
    }
}

/// Bounded message construction only. Whitespace and property order remain the
/// original signed bytes. A successful DATA parse does not validate a signature.
pub fn message_data(descriptor: &[u8]) -> Result<Vec<u8>> {
    require(!descriptor.is_empty() && descriptor.len() <= DESCRIPTOR_LIMIT, DataError::Limit)?;
    let mut bytes = Vec::with_capacity(SIGNED_DOMAIN.len() + descriptor.len());
    bytes.extend_from_slice(SIGNED_DOMAIN); bytes.extend_from_slice(descriptor); Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    // Synthetic tuple/policy DATA only, not a signed package or trusted signer.
    fn policy(number: u8) -> Value {
        let n = char::from(b'1' + number);
        let canonical = format!("{{\"schemaVersion\":1,\"kind\":\"mrk-macos-developer-id-code-policy-v1\",\"teamIdentifier\":\"TEAM000001\",\"leafCertificateSha1\":\"{}\",\"leafCertificateSha256\":\"{}\",\"hardenedRuntime\":true,\"entitlements\":\"empty\"}}",
            n.to_string().repeat(40), n.to_string().repeat(64));
        json!({"sha256": digest(canonical.as_bytes()), "policy": serde_json::from_str::<Value>(&canonical).unwrap()})
    }
    fn release(target: MaintenanceTargetData, n: u32, policy: &Value) -> Value {
        let (profile, prefix) = match target {
            MaintenanceTargetData::Arm64 => ("fixed-macos26-arm64-maintenance-v2", "macos26-arm64-"),
            MaintenanceTargetData::Intel => ("fixed-macos26-x86_64-maintenance-v2", "macos26-x86_64-"),
        };
        json!({"profile":profile,"packageIdentifier":"dev.mobile-release-kit.desktop.installed",
            "bundleIdentifier":"dev.mobile-release-kit.desktop","packageVersion":format!("0.{n}.0"),
            "release":format!("{prefix}producer-data-{n}"),"sourceCommit":format!("{n:040x}"),
            "protocolSha256":"a".repeat(64),"runtimeManifestSha256":format!("{n:064x}"),
            "inventorySha256":"b".repeat(64),"signingPolicySha256":policy["sha256"],
            "packageSha256":format!("{:064x}", n + 10)})
    }
    fn document(target: MaintenanceTargetData) -> Value {
        let policy = policy(0);
        json!({"schemaVersion":2,"kind":KIND,"domain":DOMAIN,"target":target.target(),
            "releaseSet":{"schemaVersion":2,"current":release(target,3,&policy),"acceptedPredecessors":[]},
            "signingPolicies":[policy]})
    }
    fn parse(value: &Value, target: MaintenanceTargetData) -> Result<ProducerData> {
        ProducerData::parse_data(&serde_json::to_vec(value).unwrap(), target)
    }

    #[test]
    fn paired_descriptor_preserves_original_message_and_completed_package_binding() {
        for target in [MaintenanceTargetData::Arm64, MaintenanceTargetData::Intel] {
            let value = document(target); let data = parse(&value, target).unwrap();
            assert_eq!(data.release_set_data().target_data(), target);
            assert_eq!(data.completed_package_sha256_data(), value["releaseSet"]["current"]["packageSha256"].as_str().unwrap());
            assert_eq!(data.signing_policy_data().team_identifier_data(), "TEAM000001");
            assert!(data.signing_policy_data().requires_hardened_runtime_data());
            assert!(data.signing_policy_data().requires_empty_entitlements_data());
            let raw = serde_json::to_vec_pretty(&value).unwrap();
            assert!(ProducerData::parse_data(&raw,target).is_ok());
            let message = message_data(&raw).unwrap();
            assert_eq!(&message[..SIGNED_DOMAIN.len()], b"MobileReleaseKit-package-producer-v2\0");
            assert_eq!(&message[SIGNED_DOMAIN.len()..], raw);
            assert_ne!(message, message_data(&serde_json::to_vec(&value).unwrap()).unwrap());
        }
        assert_eq!(message_data(&[]),Err(DataError::Limit));
        assert_eq!(message_data(&vec![b' ';DESCRIPTOR_LIMIT+1]),Err(DataError::Limit));
        assert_eq!(message_data(&vec![b' ';DESCRIPTOR_LIMIT]).unwrap().len(),DESCRIPTOR_LIMIT+SIGNED_DOMAIN.len());
    }

    #[test]
    fn strict_shapes_duplicates_types_and_resource_limits_refuse() {
        let target = MaintenanceTargetData::Arm64; let good = document(target);
        for bytes in [b"".to_vec(),vec![b' ';DESCRIPTOR_LIMIT+1],b"[]".to_vec(),b"null".to_vec(),
            b"{\"schemaVersion\":2,\"schemaVersion\":2}".to_vec(),b"{\"schemaVersion\":NaN}".to_vec()] {
            assert!(ProducerData::parse_data(&bytes,target).is_err());
        }
        for key in ["schemaVersion","kind","domain","target","releaseSet","signingPolicies"] {
            let mut bad=good.clone(); bad.as_object_mut().unwrap().remove(key); assert!(parse(&bad,target).is_err());
            let mut bad=good.clone(); bad[key]=json!(null); assert!(parse(&bad,target).is_err());
        }
        for replacement in [json!(true),json!(2.0),json!("2"),json!(1)] {
            let mut bad=good.clone();bad["schemaVersion"]=replacement;assert!(parse(&bad,target).is_err());
        }
        let mut bad=good.clone();bad["unknown"]=json!(true);assert!(parse(&bad,target).is_err());
        for replacement in [json!([]),json!([[]]),json!([{"sha256":"a".repeat(64),"policy":[]}]),json!(vec![policy(0);10])] {
            let mut bad=good.clone();bad["signingPolicies"]=replacement;assert!(parse(&bad,target).is_err());
        }
        let bytes=serde_json::to_vec(&good).unwrap();let text=String::from_utf8(bytes).unwrap();
        let duplicate=text.replacen("\"teamIdentifier\":", "\"teamIdentifier\":\"TEAM000001\",\"teamIdentifier\":",1);
        assert_eq!(ProducerData::parse_data(duplicate.as_bytes(),target).unwrap_err(),DataError::Shape);
    }

    #[test]
    fn canonical_policy_hash_and_closed_source_target_correspondence_refuse_swaps() {
        let target=MaintenanceTargetData::Arm64;let good=document(target);let data=parse(&good,target).unwrap();
        let canonical=String::from_utf8(data.signing_policy_data().canonical_bytes_data().to_vec()).unwrap();
        assert!(canonical.starts_with("{\"schemaVersion\":1,\"kind\":\"mrk-macos-developer-id-code-policy-v1\",\"teamIdentifier\":"));
        assert!(canonical.ends_with(",\"hardenedRuntime\":true,\"entitlements\":\"empty\"}"));
        assert_eq!(digest(canonical.as_bytes()),good["signingPolicies"][0]["sha256"].as_str().unwrap());
        for (key,value) in [("teamIdentifier",json!("lowercase1")),("leafCertificateSha1",json!("0".repeat(40))),
            ("leafCertificateSha256",json!("A".repeat(64))),("hardenedRuntime",json!(false)),
            ("entitlements",json!("any")),("kind",json!("generic-codesign")),("schemaVersion",json!(2))] {
            let mut bad=good.clone();bad["signingPolicies"][0]["policy"][key]=value;assert!(parse(&bad,target).is_err());
        }
        for field in ["sha256","policy"] {let mut bad=good.clone();bad["signingPolicies"][0].as_object_mut().unwrap().remove(field);assert!(parse(&bad,target).is_err());}
        let mut bad=good.clone();bad["signingPolicies"][0]["policy"]["extra"]=json!(0);assert!(parse(&bad,target).is_err());
        let mut bad=good.clone();bad["signingPolicies"][0]["sha256"]=json!("f".repeat(64));assert!(parse(&bad,target).is_err());
        let mut bad=good.clone();bad["releaseSet"]["current"]["signingPolicySha256"]=json!("f".repeat(64));assert!(parse(&bad,target).is_err());
        assert!(parse(&good,MaintenanceTargetData::Intel).is_err());
        let mut bad=good.clone();bad["target"]=json!("x86_64-apple-darwin");assert!(parse(&bad,MaintenanceTargetData::Intel).is_err());
        for key in ["kind","domain"] {let mut bad=good.clone();bad[key]=json!("wrong-domain");assert!(parse(&bad,target).is_err());}
    }

    #[test]
    fn explicit_rotated_predecessor_policies_require_membership_and_no_unused_rows() {
        let target=MaintenanceTargetData::Intel;let mut value=document(target);let old=policy(1);
        value["releaseSet"]["acceptedPredecessors"]=json!([release(target,2,&old)]);
        let rows=value["signingPolicies"].as_array_mut().unwrap();rows.push(old);
        rows.sort_by(|a,b|a["sha256"].as_str().cmp(&b["sha256"].as_str()));
        let data=parse(&value,target).unwrap();let previous=&data.release_set_data().predecessor_data()[0];
        assert_ne!(data.policy_for_release_data(previous).unwrap().leaf_certificate_sha256_data(),
            data.signing_policy_data().leaf_certificate_sha256_data());
        assert_eq!(data.policy_for_release_data(data.release_set_data().current_data()).unwrap(),data.signing_policy_data());
        let mut outsider=document(target);outsider["releaseSet"]["current"]["release"]=json!("macos26-x86_64-outsider");
        let outsider=parse(&outsider,target).unwrap();
        assert_eq!(data.policy_for_release_data(outsider.release_set_data().current_data()),Err(DataError::Membership));
        let mut bad=value.clone();bad["signingPolicies"].as_array_mut().unwrap().reverse();assert!(parse(&bad,target).is_err());
        let mut bad=value.clone();let duplicate=bad["signingPolicies"][0].clone();bad["signingPolicies"].as_array_mut().unwrap().push(duplicate);assert!(parse(&bad,target).is_err());
        let mut bad=value.clone();bad["releaseSet"]["acceptedPredecessors"]=json!([]);assert!(parse(&bad,target).is_err());
        let mut bad=value.clone();bad["signingPolicies"].as_array_mut().unwrap().remove(0);assert!(parse(&bad,target).is_err());
        let mut bad=value.clone();bad["releaseSet"]["acceptedPredecessors"][0]["packageVersion"]=json!("0.4.0");assert!(parse(&bad,target).is_err());
    }
}
