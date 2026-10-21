//! Closed public DATA for the signed-export variant of the existing iOS build
//! family. No native module, credential record, path or execution authority.
use serde::{Deserialize, Deserializer, Serialize};

pub const CONSENT: &str = "agent-saved-ios-signed-export-v1";

// Absence preserves the old unsigned wire bytes; explicit null is not another
// spelling of an absent signing policy or a successfully validated export.
pub(super) fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Review {
    pub team_id: String,
    pub distribution_certificate_sha256: String,
    pub firebase: bool,
    pub project_read_token: bool,
}
impl Review {
    pub fn valid(&self) -> bool {
        self.team_id.len() == 10
            && self
                .team_id
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            && self.distribution_certificate_sha256.len() == 64
            && self
                .distribution_certificate_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    pub(crate) fn capacity_valid(&self) -> bool {
        self.team_id.capacity() <= 10 && self.distribution_certificate_sha256.capacity() <= 64
    }
    pub(crate) fn heap_bytes(&self) -> Option<usize> {
        self.team_id
            .capacity()
            .checked_add(self.distribution_certificate_sha256.capacity())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Pairing {
    pub native_paths: u32,
    pub native_identities: u32,
    pub present_symbol_slices: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Export {
    pub ipa_bytes: u64,
    pub pairing: Pairing,
}
impl Export {
    pub fn valid(&self) -> bool {
        (1..=4 * 1024u64.pow(3)).contains(&self.ipa_bytes)
            && (1..=100_000).contains(&self.pairing.native_paths)
            && (1..=100_000).contains(&self.pairing.native_identities)
            && self.pairing.present_symbol_slices <= 100_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_ios_archive as ios;
    use serde_json::{json, Value};

    fn review(signed: bool) -> Value {
        let mut value = json!({"mode":"saved-ios-unsigned-archive",
            "savedConfig":{"bytes":20,"sha256":"a".repeat(64)},
            "savedVersion":{"bytes":30,"sha256":"b".repeat(64),"name":"1.2","build":7}});
        if signed {
            value["mode"] = json!("saved-ios-signed-export");
            value["signing"] = json!({"teamId":"ABCDE12345","distributionCertificateSha256":"c".repeat(64),
                "firebase":false,"projectReadToken":true});
        }
        value
    }

    #[test]
    fn signed_review_is_closed_and_cannot_upgrade_old_unsigned_bytes() {
        let old = review(false);
        let unsigned: ios::Review = serde_json::from_value(old.clone()).unwrap();
        assert!(unsigned.valid());
        assert_eq!(serde_json::to_value(&unsigned).unwrap(), old);
        let value = review(true);
        let signed: ios::Review = serde_json::from_value(value.clone()).unwrap();
        assert!(signed.valid());
        assert!(signed.signing.as_ref().unwrap().capacity_valid());
        assert_eq!(signed.signing.as_ref().unwrap().heap_bytes(), Some(74));
        let mut invalid = value.clone();
        invalid["mode"] = json!("saved-ios-unsigned-archive");
        assert!(!serde_json::from_value::<ios::Review>(invalid)
            .unwrap()
            .valid());
        for unsupported in [
            "ios-candidate-inputs",
            "ios-signing-inputs-check",
            "ios-local-recovery",
        ] {
            let mut invalid = value.clone();
            invalid["mode"] = json!(unsupported);
            assert!(serde_json::from_value::<ios::Review>(invalid).is_err());
        }
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove("signing");
        assert!(!serde_json::from_value::<ios::Review>(missing)
            .unwrap()
            .valid());
        let mut null = old;
        null["signing"] = Value::Null;
        assert!(serde_json::from_value::<ios::Review>(null).is_err());
        for (field, bad) in [
            ("teamId", json!("ABCDE12345\n")),
            (
                "distributionCertificateSha256",
                json!(format!("{}\n", "c".repeat(64))),
            ),
        ] {
            let mut v = value.clone();
            v["signing"][field] = bad;
            assert!(!serde_json::from_value::<ios::Review>(v).unwrap().valid());
        }
        for field in [
            "password",
            "p12",
            "profile",
            "token",
            "recordId",
            "root",
            "nativeAvailable",
        ] {
            let mut v = value.clone();
            v["signing"][field] = json!("not-authority");
            assert!(serde_json::from_value::<ios::Review>(v).is_err());
        }
    }

    #[test]
    fn signed_result_is_only_bounded_original_counts_not_private_or_recovery_authority() {
        let value = json!({"ipaBytes":128,"pairing":{"nativePaths":3,"nativeIdentities":2,"presentSymbolSlices":0}});
        assert!(serde_json::from_value::<Export>(value.clone())
            .unwrap()
            .valid());
        for bytes in [0, 4 * 1024u64.pow(3) + 1] {
            let mut v = value.clone();
            v["ipaBytes"] = json!(bytes);
            assert!(!serde_json::from_value::<Export>(v).unwrap().valid());
        }
        for field in ["nativePaths", "nativeIdentities", "presentSymbolSlices"] {
            let mut v = value.clone();
            v["pairing"][field] = json!(100_001);
            assert!(!serde_json::from_value::<Export>(v).unwrap().valid());
        }
        for field in [
            "ipa",
            "archive",
            "sha256",
            "teamId",
            "recovery",
            "credentialReady",
            "candidateId",
        ] {
            let mut v = value.clone();
            v[field] = json!("not-authority");
            assert!(serde_json::from_value::<Export>(v).is_err());
        }
    }
    #[test]
    fn signed_admission_unknown_can_omit_operation_without_reusing_an_older_success() {
        let mut value = json!({"origin":{"projectId":"a".repeat(32),"serviceInstance":"b".repeat(32),"requestId":"c".repeat(32)},
            "expectedObservationRevision":1,"requestState":"admission-unknown","startState":"consumed",
            "review":review(true),"operation":null,"historyAvailable":false,"doNotReplay":true});
        let status: ios::Status = serde_json::from_value(value.clone()).unwrap();
        status.validate().unwrap();
        for field in ["historyAvailable", "doNotReplay"] {
            value[field] = json!(field == "historyAvailable");
            assert!(serde_json::from_value::<ios::Status>(value.clone())
                .unwrap()
                .validate()
                .is_err());
            value[field] = json!(field != "historyAvailable");
        }
        value["requestState"] = json!("original-available");
        assert!(serde_json::from_value::<ios::Status>(value)
            .unwrap()
            .validate()
            .is_err());
    }
}
