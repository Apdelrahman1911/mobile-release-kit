//! Closed Bundle-ID query DATA child of local_store_preflight_protocol.
//!
//! This is not a provider/key lease or a second operation owner. The parent
//! retains the same original Session, selected P8, context and native joins.
use serde::{Deserialize, Deserializer, Serialize};

pub(crate) const CONSENT: &str = "local-ios-bundle-id-read-v1";
pub(crate) const SCOPE: &str = "local-ios-bundle-id-registration-read";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) enum Query {
    #[serde(rename = "bundle-id-registration")]
    BundleIdRegistration,
    #[serde(rename = "app-store-profile-reuse")]
    AppStoreProfileReuse,
    #[serde(rename = "ios-current-versions")]
    IOSCurrentVersions,
    #[serde(rename = "android-current-versions")]
    AndroidCurrentVersions,
    #[serde(rename="paired-current-versions")]
    PairedCurrentVersions,
}

impl Query {
    pub(super) fn platform(self)->super::AccessPlatform { match self { Self::AndroidCurrentVersions=>super::AccessPlatform::Android,Self::PairedCurrentVersions=>super::AccessPlatform::Both,_=>super::AccessPlatform::Ios } }
    pub(super) fn consent(self) -> &'static str {
        match self {
            Self::BundleIdRegistration => CONSENT,
            Self::AppStoreProfileReuse => super::profile_read::CONSENT,
            Self::IOSCurrentVersions => super::store_versions::CONSENT,
            Self::AndroidCurrentVersions => super::play_versions::CONSENT,
            Self::PairedCurrentVersions => super::paired_versions::CONSENT,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Observation {
    Found,
    NotReturned,
    NotPermitted,
    Inconclusive,
    NotChecked,
}

// Missing optional fields retain the old access grammar. Explicit null is not
// another spelling of "old operation" or "observation unavailable".
pub(super) fn optional_query<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Query>, D::Error> {
    Query::deserialize(deserializer).map(Some)
}

pub(super) fn optional_observation<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Observation>, D::Error> {
    Observation::deserialize(deserializer).map(Some)
}

pub(super) const LIMITATIONS: [super::Limitation; 9] = [
    super::Limitation::NonPublishing,
    super::Limitation::NoProjectCommands,
    super::Limitation::NoBuildOrSigning,
    super::Limitation::NoReleaseReadiness,
    super::Limitation::PointInTimeAccountAccess,
    super::Limitation::SavedInputsNotAtomic,
    super::Limitation::NoTeamVerification,
    super::Limitation::NoGlobalAvailabilityClaim,
    super::Limitation::NoProvisioningChanges,
];

pub(super) fn valid_result(value: &super::ResultData) -> bool {
    value.schema_version == 1
        && value.scope == SCOPE
        && value.observation.is_some()
        && value.profile_reuse.is_none() && value.current_versions.is_none()
        && value.limitations.as_slice() == LIMITATIONS
        && value.findings.len() <= 16
        && value
            .findings
            .iter()
            .all(|finding| finding.check != super::CheckId::StoreAccess)
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
        value["query"] = json!("bundle-id-registration");
        value
    }

    fn terminal(context: &wire::Context) -> Value {
        let mut value = wire::tests::complete();
        value["context"] = json!(context);
        value["result"] = json!({"schemaVersion":1,"scope":SCOPE,"findings":[
            {"check":"credential-format","status":"PASS"}],"limitations":LIMITATIONS,"observation":"not-returned"});
        value["lifetime"]["commands"] = json!(7);
        value
    }

    #[test]
    fn only_explicit_ios_query_is_admitted_and_old_context_is_unchanged() {
        let input = input();
        let context = wire::prepare(&input).unwrap().context();
        assert_eq!(context.query, Some(Query::BundleIdRegistration));
        assert!(serde_json::to_value(wire::tests::context())
            .unwrap()
            .get("query")
            .is_none());
        for (key, bad) in [
            ("platform", json!("android")),
            ("platform", Value::Null),
            ("query", Value::Null),
            ("query", json!("create-bundle-id")),
            ("privateKey", json!("not-an-input")),
        ] {
            let mut changed = input.clone();
            changed[key] = bad;
            assert!(wire::prepare(&changed).is_err());
        }
        let mut context_json = json!(context);
        context_json["query"] = Value::Null;
        assert!(wire::Context::deserialize(&context_json).is_err());
    }

    #[test]
    fn consent_matches_retained_query_not_just_apple_platform() {
        let query = wire::prepare(&input()).unwrap().context();
        let mut access_input = input();
        access_input.as_object_mut().unwrap().remove("query");
        let access = wire::prepare(&access_input).unwrap().context();
        for consent in [wire::CONSENT, wire::APPLE_CONSENT, CONSENT] {
            let start = wire::start(&json!({"operationId":"a".repeat(32),
                "ownerGeneration":"b".repeat(32),"consentVersion":consent}))
            .unwrap();
            assert_eq!(start.matches_context(&query), consent == CONSENT);
            assert_eq!(
                start.matches_context(&access),
                consent == wire::APPLE_CONSENT
            );
            assert_eq!(
                start.matches_context(&wire::tests::context()),
                consent == wire::CONSENT
            );
        }
    }

    #[test]
    fn result_keeps_no_team_availability_or_provisioning_authority() {
        let context = wire::prepare(&input()).unwrap().context();
        let value = terminal(&context);
        assert!(wire::Terminal::deserialize(&value).unwrap().valid(&context));
        for observation in [
            "found",
            "not-returned",
            "not-permitted",
            "inconclusive",
            "not-checked",
        ] {
            let mut changed = value.clone();
            changed["result"]["observation"] = json!(observation);
            assert!(wire::Terminal::deserialize(&changed)
                .unwrap()
                .valid(&context));
        }
        for observation in [Value::Null, json!("available"), json!(true)] {
            let mut changed = value.clone();
            changed["result"]["observation"] = observation;
            assert!(wire::Terminal::deserialize(&changed).is_err());
        }
        let mut missing = value.clone();
        missing["result"]
            .as_object_mut()
            .unwrap()
            .remove("observation");
        assert!(!wire::Terminal::deserialize(&missing)
            .unwrap()
            .valid(&context));
        let mut access = value.clone();
        access["result"]["scope"] = json!("local-ios-store-access-no-publishing");
        assert!(!wire::Terminal::deserialize(&access)
            .unwrap()
            .valid(&context));
        let mut leaked = value.clone();
        leaked["result"]["providerBody"] = json!("private");
        assert!(wire::Terminal::deserialize(&leaked).is_err());
        let mut misleading = value.clone();
        misleading["result"]["findings"][0]["check"] = json!("store-access");
        assert!(!wire::Terminal::deserialize(&misleading)
            .unwrap()
            .valid(&context));
    }

    #[test]
    fn original_finality_is_still_mandatory_for_query_results() {
        let context = wire::prepare(&input()).unwrap().context();
        let value = terminal(&context);
        for field in [
            "complete",
            "contained",
            "inputClosed",
            "handlersRestored",
            "invocationClosed",
        ] {
            let mut changed = value.clone();
            changed["lifetime"][field] = json!(false);
            assert!(!wire::Terminal::deserialize(&changed)
                .unwrap()
                .valid(&context));
            changed["outcome"] = json!("unknown");
            changed["reason"] = json!("cleanup-unknown");
            changed["result"] = Value::Null;
            assert!(wire::Terminal::deserialize(&changed)
                .unwrap()
                .valid(&context));
        }
        let mut excessive = value;
        excessive["lifetime"]["commands"] = json!(8);
        assert!(!wire::Terminal::deserialize(&excessive)
            .unwrap()
            .valid(&context));
    }
}
