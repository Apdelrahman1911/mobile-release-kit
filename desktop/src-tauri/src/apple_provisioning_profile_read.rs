//! Profile/reference metadata DATA on the existing Store-preflight owner.
//! No private key, certificate trust, authenticated profile or readiness grant.
use super::{bundle_read::Observation, CheckId, Limitation, ResultData};
use serde::{Deserialize, Deserializer, Serialize};

pub(super) const CONSENT: &str = "local-ios-profile-reuse-read-v1";
pub(super) const SCOPE: &str = "local-ios-profile-reuse-metadata-read";
pub(super) const LIMITATIONS: [Limitation; 13] = [
    Limitation::NonPublishing,
    Limitation::NoProjectCommands,
    Limitation::NoBuildOrSigning,
    Limitation::NoReleaseReadiness,
    Limitation::PointInTimeAccountAccess,
    Limitation::SavedInputsNotAtomic,
    Limitation::NoTeamVerification,
    Limitation::NoGlobalAvailabilityClaim,
    Limitation::NoProvisioningChanges,
    Limitation::MetadataOnly,
    Limitation::NoPrivateKeyMatch,
    Limitation::NoProfileAuthentication,
    Limitation::NoAccountCertificateInventory,
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Counts {
    matching_profiles: u16,
    active_profiles: u16,
    current_metadata_candidates: u16,
    related_certificates: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Summary {
    observation: Observation,
    // Present-null is required for unconfirmed reads; omitted fields are not
    // another spelling of a well-formed negative observation.
    #[serde(deserialize_with = "required_optional")]
    counts: Option<Counts>,
    #[serde(deserialize_with = "required_optional")]
    checked_at: Option<String>,
}

fn required_optional<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}

pub(super) fn optional_summary<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Summary>, D::Error> {
    Summary::deserialize(deserializer).map(Some)
}

fn checked_at(value: &str) -> bool {
    // Exact UTC microseconds from the worker comparison, not a native clock
    // proof. Reuse the already maintained date parser for calendar validity.
    let b = value.as_bytes();
    if b.len() != 27
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'.'
        || b[26] != b'Z'
        || b.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19 | 26) && !byte.is_ascii_digit()
        })
    {
        return false;
    }
    let number = |start: usize, len: usize| -> u16 {
        b[start..start + len]
            .iter()
            .fold(0u16, |sum, byte| sum * 10 + u16::from(byte - b'0'))
    };
    der_07::DateTime::new(
        number(0, 4),
        number(5, 2) as u8,
        number(8, 2) as u8,
        number(11, 2) as u8,
        number(14, 2) as u8,
        number(17, 2) as u8,
    )
    .is_ok()
}

impl Summary {
    fn valid(&self) -> bool {
        match self.observation {
            Observation::Found | Observation::NotReturned => {
                let (Some(counts), Some(time)) = (&self.counts, &self.checked_at) else {
                    return false;
                };
                if !checked_at(time)
                    || counts.matching_profiles > 200
                    || counts.active_profiles > counts.matching_profiles
                    || counts.current_metadata_candidates > counts.active_profiles
                    || counts.related_certificates > 400
                {
                    return false;
                }
                if self.observation == Observation::NotReturned {
                    counts.matching_profiles == 0 && counts.related_certificates == 0
                } else {
                    counts.matching_profiles > 0 && counts.related_certificates > 0
                }
            }
            _ => self.counts.is_none() && self.checked_at.is_none(),
        }
    }
}

pub(super) fn valid_result(value: &ResultData) -> bool {
    value.schema_version == 1
        && value.scope == SCOPE
        && value.observation.is_none()
        && value.profile_reuse.as_ref().is_some_and(Summary::valid)
        && value.limitations.as_slice() == LIMITATIONS
        && value.findings.len() <= 16
        && value
            .findings
            .iter()
            .all(|finding| finding.check != CheckId::StoreAccess)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_store_preflight_protocol as wire;
    use serde_json::{json, Value};

    fn input() -> Value {
        let mut value = serde_json::to_value(wire::tests::context()).unwrap();
        value.as_object_mut().unwrap().remove("operation");
        value["platform"] = json!("ios");
        value["query"] = json!("app-store-profile-reuse");
        value
    }

    fn summary() -> Value {
        json!({"observation":"found","counts":{"matchingProfiles":2,"activeProfiles":2,
            "currentMetadataCandidates":1,"relatedCertificates":1},"checkedAt":"2026-10-19T12:30:00.123456Z"})
    }

    fn terminal(context: &wire::Context) -> Value {
        let mut value = wire::tests::complete();
        value["context"] = json!(context);
        value["lifetime"]["commands"] = json!(7);
        value["result"] = json!({"schemaVersion":1,"scope":SCOPE,"findings":[],
            "limitations":LIMITATIONS,"profileReuse":summary()});
        value
    }

    #[test]
    fn only_explicit_profile_query_and_its_own_consent_are_admitted() {
        let prepared = input();
        let context = wire::prepare(&prepared).unwrap().context();
        for consent in [
            wire::CONSENT,
            wire::APPLE_CONSENT,
            super::super::bundle_read::CONSENT,
            CONSENT,
        ] {
            let start = wire::start(
                &json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),
                "consentVersion":consent}),
            )
            .unwrap();
            assert_eq!(start.matches_context(&context), consent == CONSENT);
            assert!(!wire::start(
                &json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),
                "consentVersion":CONSENT})
            )
            .unwrap()
            .matches_context(&wire::tests::context()));
        }
        for (key, bad) in [
            ("platform", json!("android")),
            ("query", Value::Null),
            ("query", json!("download-profile")),
            ("certificateId", json!("not-an-input")),
        ] {
            let mut value = prepared.clone();
            value[key] = bad;
            assert!(wire::prepare(&value).is_err());
        }
    }

    #[test]
    fn counts_and_comparison_date_are_bounded_consistent_data() {
        assert!(Summary::deserialize(&summary()).unwrap().valid());
        for time in [
            "2026-02-30T12:30:00.123456Z",
            "1969-10-19T12:30:00.123456Z",
            "2026-10-19T24:00:00.000000Z",
            "2026-10-19T12:30:00Z",
            "2026-10-19T12:30:00.123456+00:00",
        ] {
            let mut value = summary();
            value["checkedAt"] = json!(time);
            assert!(!Summary::deserialize(&value).unwrap().valid());
        }
        for (key, number) in [
            ("matchingProfiles", 201),
            ("activeProfiles", 3),
            ("currentMetadataCandidates", 3),
            ("relatedCertificates", 401),
            ("relatedCertificates", 0),
        ] {
            let mut value = summary();
            value["counts"][key] = json!(number);
            assert!(!Summary::deserialize(&value).unwrap().valid());
        }
        for field in ["counts", "checkedAt"] {
            let mut value = json!({"observation":"inconclusive","counts":null,"checkedAt":null});
            value.as_object_mut().unwrap().remove(field);
            assert!(Summary::deserialize(&value).is_err());
        }
    }

    #[test]
    fn denied_or_partial_reads_cannot_contain_counts_or_an_absence_claim() {
        for observation in ["inconclusive", "not-permitted", "not-checked"] {
            let good = json!({"observation":observation,"counts":null,"checkedAt":null});
            assert!(Summary::deserialize(&good).unwrap().valid());
            let mut bad = summary();
            bad["observation"] = json!(observation);
            assert!(!Summary::deserialize(&bad).unwrap().valid());
        }
        let mut empty = summary();
        empty["observation"] = json!("not-returned");
        assert!(!Summary::deserialize(&empty).unwrap().valid());
        empty["counts"] = json!({"matchingProfiles":0,"activeProfiles":0,"currentMetadataCandidates":0,"relatedCertificates":0});
        assert!(Summary::deserialize(&empty).unwrap().valid());
    }

    #[test]
    fn result_is_scoped_to_this_read_without_provider_or_signing_authority() {
        let context = wire::prepare(&input()).unwrap().context();
        let original = terminal(&context);
        assert!(wire::Terminal::deserialize(&original)
            .unwrap()
            .valid(&context));
        for (key, value) in [
            ("observation", json!("found")),
            ("providerBody", json!("private")),
            ("profileReuse", Value::Null),
        ] {
            let mut bad = original.clone();
            bad["result"][key] = value;
            assert!(match wire::Terminal::deserialize(&bad) {
                Err(_) => true,
                Ok(terminal) => !terminal.valid(&context),
            });
        }
        let mut wrong = original.clone();
        wrong["result"]["scope"] = json!(super::super::bundle_read::SCOPE);
        assert!(!wire::Terminal::deserialize(&wrong).unwrap().valid(&context));
        let mut misleading = original;
        misleading["result"]["findings"] = json!([{"check":"store-access","status":"PASS"}]);
        assert!(!wire::Terminal::deserialize(&misleading)
            .unwrap()
            .valid(&context));
    }

    #[test]
    fn metadata_success_never_substitutes_for_original_lifetime_joins() {
        let context = wire::prepare(&input()).unwrap().context();
        for field in [
            "complete",
            "contained",
            "inputClosed",
            "handlersRestored",
            "invocationClosed",
        ] {
            let mut value = terminal(&context);
            value["lifetime"][field] = json!(false);
            assert!(!wire::Terminal::deserialize(&value).unwrap().valid(&context));
            value["outcome"] = json!("unknown");
            value["reason"] = json!("cleanup-unknown");
            value["result"] = Value::Null;
            assert!(wire::Terminal::deserialize(&value).unwrap().valid(&context));
        }
    }
}
