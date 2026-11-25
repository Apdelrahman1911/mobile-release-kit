//! Closed signed-Android public DATA. No payload, credential selection or
//! native permission can be reconstructed from these comparisons.
use crate::service_protocol::Id;
use serde::{Deserialize, Serialize};

pub const CONSENT: &str = "agent-saved-android-local-sign-v1";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningMode { LocalUploadKey }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind { AndroidKeystore, AndroidFirebase }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Assignment {
    pub kind: Kind,
    pub record_id: Id,
    pub record_revision: u32,
    pub context_revision: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Selection { pub mode: SigningMode, pub assignments: Vec<Assignment> }
impl Selection {
    pub fn valid(&self) -> bool {
        (1..=2).contains(&self.assignments.len())
            && self.assignments.iter().enumerate().all(|(i, row)| {
                row.kind == [Kind::AndroidKeystore, Kind::AndroidFirebase][i]
                    && (1..u32::MAX).contains(&row.record_revision)
                    && (1..u32::MAX).contains(&row.context_revision)
                    && row.context_revision == self.assignments[0].context_revision
            })
            && (self.assignments.len() == 1 || self.assignments[0].record_id != self.assignments[1].record_id)
    }
    pub(crate) fn heap_bytes(&self) -> Option<usize> {
        self.assignments.iter().try_fold(self.assignments.capacity().checked_mul(std::mem::size_of::<Assignment>())?,
            |n, a| n.checked_add(a.record_id.retained_bytes()))
    }
    pub(crate) fn capacity_valid(&self) -> bool {
        self.assignments.capacity() <= 2
            && self.assignments.iter().all(|a| a.record_id.retained_bytes() <= 64)
    }
}
pub(crate) const SELECTION_HEAP: usize = 2 * (std::mem::size_of::<Assignment>() + 64);
pub(crate) fn present<'de, D, T>(decoder: D) -> Result<Option<T>, D::Error>
where D: serde::Deserializer<'de>, T: Deserialize<'de> { T::deserialize(decoder).map(Some) }

/// Canonical PUBLIC comparison only. The native Context and saved input keep
/// the exact original string; this never rewrites the saved signing policy.
pub(crate) fn fingerprint(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    if bytes.len() == 64 && bytes.iter().all(u8::is_ascii_hexdigit) {
        return Some(raw.to_ascii_lowercase());
    }
    if bytes.len() != 95 || bytes.iter().enumerate().any(|(i, b)| {
        if i % 3 == 2 { *b != b':' } else { !b.is_ascii_hexdigit() }
    }) { return None; }
    let mut value = String::with_capacity(64);
    for (i, b) in bytes.iter().enumerate() { if i % 3 != 2 { value.push(b.to_ascii_lowercase() as char); } }
    Some(value)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Signature { Passed, Failed, NotChecked }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Signer { MatchesSavedUploadCertificate, Failed, NotChecked }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Report {
    pub mode: SigningMode,
    pub upload_certificate_sha256: String,
    pub signature: Signature,
    pub signer: Signer,
}
impl Report {
    pub fn valid(&self) -> bool {
        super::hash(&self.upload_certificate_sha256)
            && self.signature == Signature::Passed && self.signer == Signer::MatchesSavedUploadCertificate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fingerprint_normalization_is_closed_and_does_not_rewrite_raw_policy() {
        let raw = ["AF"; 32].join(":");
        assert_eq!(fingerprint(&raw), Some("af".repeat(32)));
        assert_eq!(raw, ["AF"; 32].join(":"));
        assert_eq!(fingerprint(&"AF".repeat(32)), Some("af".repeat(32)));
        for value in ["f".into(), format!(" {}", "af".repeat(32)), "::".repeat(32),
            format!("{}:", "af".repeat(32)), format!("{}ag", "af".repeat(31))] {
            assert!(fingerprint(&value).is_none());
        }
    }
    #[test]
    fn signed_review_never_upgrades_old_bytes_and_explicit_null_is_not_absence() {
        let old = serde_json::json!({"mode":"saved-android-build-structure-and-version",
            "savedConfig":{"bytes":100,"sha256":"a".repeat(64)},"savedVersion":{"bytes":32,"sha256":"b".repeat(64),"name":"1.2","build":7},
            "tools":{"instance":"c".repeat(32),"catalogGeneration":1,"recordSha256":"d".repeat(64)}});
        let original: super::super::Review = serde_json::from_value(old.clone()).unwrap();
        assert!(original.valid()); assert_eq!(serde_json::to_value(&original).unwrap(),old);
        let mut value=old.clone();value["mode"]=serde_json::json!("saved-android-local-upload-key-sign");
        assert!(!serde_json::from_value::<super::super::Review>(value.clone()).unwrap().valid());
        value["signing"]=serde_json::json!({"mode":"local-upload-key","assignments":[{"kind":"android-keystore","recordId":"e".repeat(32),"recordRevision":1,"contextRevision":2}]});
        value["uploadCertificateSha256"]=serde_json::json!("f".repeat(64));
        let signed: super::super::Review=serde_json::from_value(value.clone()).unwrap();assert!(signed.valid());
        value["mode"]=old["mode"].clone();assert!(!serde_json::from_value::<super::super::Review>(value).unwrap().valid());
        for field in ["signing","uploadCertificateSha256"] {
            let mut v=old.clone();v[field]=serde_json::Value::Null;assert!(serde_json::from_value::<super::super::Review>(v).is_err());
        }
    }

}
