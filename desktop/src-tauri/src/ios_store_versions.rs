//! Current-visible iOS version DATA on the ORIGINAL Store-preflight owner.
//! Complete pagination is neither an atomic snapshot nor historical uniqueness.
use super::{CheckId, Context, Limitation, ResultData, Terminal};
use serde::{Deserialize, Deserializer, Serialize};

pub(crate) const QUERY: &str = "ios-current-versions";
pub(crate) const CONSENT: &str = "local-ios-current-versions-read-v1";
pub(crate) const SCOPE: &str = "local-ios-current-version-inventory";
pub(crate) const COVERAGE: &str = "asc-ios-current-inventory/1";
pub(crate) const LIMITATIONS: [Limitation; 10] = [
    Limitation::NonPublishing,
    Limitation::NoProjectCommands,
    Limitation::NoBuildOrSigning,
    Limitation::NoReleaseReadiness,
    Limitation::PointInTimeAccountAccess,
    Limitation::SavedInputsNotAtomic,
    Limitation::CurrentVisibleOnly,
    Limitation::NotAtomicStoreSnapshot,
    Limitation::HistoricalUniquenessNotEstablished,
    Limitation::ExternalUploadersNotCoordinated,
];

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Observation {
    Observed,
    NotChecked,
    NotPermitted,
    Inconclusive,
    TooMany,
    UnsupportedFormat,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Counts {
    pub(crate) builds: u16,
    pub(crate) build_uploads: u16,
    pub(crate) app_store_versions: u16,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Summary {
    pub(crate) observation: Observation,
    coverage: String,
    #[serde(deserialize_with = "required_optional")]
    pub(crate) revision: Option<String>,
    #[serde(deserialize_with = "required_optional")]
    pub(crate) counts: Option<Counts>,
    #[serde(deserialize_with = "required_optional")]
    pub(crate) max_build: Option<u32>,
    #[serde(deserialize_with = "required_optional")]
    pub(crate) marketing_version: Option<String>,
    historical_uniqueness: String,
}
fn required_optional<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
pub(super) fn optional_summary<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<Summary>, D::Error> {
    Summary::deserialize(d).map(Some)
}
fn numeric_version(value: &str) -> bool {
    let mut count = 0;
    !value.is_empty()
        && value.len() <= 64
        && value.split('.').all(|part| {
            count += 1;
            !part.is_empty()
                && (part.len() == 1 || !part.starts_with('0'))
                && part.bytes().all(|b| b.is_ascii_digit())
        })
        && (2..=3).contains(&count)
}
impl Summary {
    pub(crate) fn observed(&self) -> bool {
        self.observation == Observation::Observed && self.valid()
    }
    pub(crate) fn valid(&self) -> bool {
        if self.coverage != COVERAGE || self.historical_uniqueness != "not-established" {
            return false;
        }
        if self.observation != Observation::Observed {
            return self.revision.is_none()
                && self.counts.is_none()
                && self.max_build.is_none()
                && self.marketing_version.is_none();
        }
        let (Some(revision), Some(counts), Some(build)) =
            (&self.revision, self.counts, self.max_build)
        else {
            return false;
        };
        super::sha(revision)
            && counts.builds <= 400
            && counts.build_uploads <= 400
            && counts.app_store_versions <= 400
            && build <= 2_100_000_000
            && ((counts.builds == 0 && counts.build_uploads == 0) == (build == 0))
            && ((counts.builds == 0 && counts.build_uploads == 0 && counts.app_store_versions == 0)
                == self.marketing_version.is_none())
            && self
                .marketing_version
                .as_deref()
                .is_none_or(numeric_version)
    }
}
pub(super) fn valid_result(value: &ResultData) -> bool {
    value.schema_version == 1
        && value.scope == SCOPE
        && value.observation.is_none()
        && value.profile_reuse.is_none()
        && value.current_versions.as_ref().and_then(super::play_versions::Inventory::ios).is_some_and(Summary::valid)
        && value.limitations.as_slice() == LIMITATIONS
        && value.findings.len() <= 16
        && value.findings.iter().all(|f| {
            f.check != CheckId::StoreAccess
                && (!value
                    .current_versions
                    .as_ref()
                    .and_then(super::play_versions::Inventory::ios)
                    .is_some_and(Summary::observed)
                    || !matches!(
                        f.status,
                        super::CoreStatus::Fail
                            | super::CoreStatus::Missing
                            | super::CoreStatus::Blocked
                            | super::CoreStatus::Invalid
                    ))
        })
}
pub(crate) fn selected(context: &Context) -> bool {
    context.platform == super::AccessPlatform::Ios
        && context.query == Some(super::bundle_read::Query::IOSCurrentVersions)
}
impl Terminal {
    /// DATA checked only from the real final native retirement; this function
    /// is deliberately not a finality or credential/Store receipt constructor.
    pub(crate) fn current_versions_data(&self, context: &Context) -> Option<&Summary> {
        if !selected(context)
            || !self.valid(context)
            || self.outcome != super::Outcome::Complete
            || self.reason != super::Reason::None
            || self.lifetime.commands != 7
            || self.lifetime.command_dispatched != Some(true)
        {
            return None;
        }
        self.result
            .as_ref()?
            .current_versions
            .as_ref()
            .and_then(super::play_versions::Inventory::ios)
            .filter(|s| s.observed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_store_preflight_protocol as wire;
    use serde_json::{json, Value};

    pub(super) fn summary() -> Value {
        json!({"observation":"observed","coverage":COVERAGE,"revision":"a".repeat(64),
            "counts":{"builds":0,"buildUploads":0,"appStoreVersions":1},"maxBuild":0,
            "marketingVersion":"2.0.0","historicalUniqueness":"not-established"})
    }
    fn input() -> Value {
        let mut value = json!(wire::tests::context());
        value.as_object_mut().unwrap().remove("operation");
        value["platform"] = json!("ios");
        value["query"] = json!(QUERY);
        value
    }
    #[test]
    fn closed_ios_query_and_consent_never_widen_access_or_other_platforms() {
        let context = wire::prepare(&input()).unwrap().context();
        for consent in [
            wire::CONSENT,
            wire::APPLE_CONSENT,
            super::super::bundle_read::CONSENT,
            super::super::profile_read::CONSENT,
            CONSENT,
        ] {
            let start = wire::start(
                &json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),
                "consentVersion":consent}),
            )
            .unwrap();
            assert_eq!(start.matches_context(&context), consent == CONSENT);
        }
        for (key, bad) in [
            ("platform", json!("android")),
            ("query", Value::Null),
            ("query", json!("ios-all-history")),
            ("appStoreAppId", json!("123")),
        ] {
            let mut value = input();
            value[key] = bad;
            assert!(wire::prepare(&value).is_err());
        }
    }
    #[test]
    fn marketing_only_is_valid_but_unavailable_is_not_zero_floor() {
        assert!(Summary::deserialize(summary()).unwrap().observed());
        for name in [
            "not-checked",
            "not-permitted",
            "inconclusive",
            "too-many",
            "unsupported-format",
        ] {
            let mut value = summary();
            value["observation"] = json!(name);
            assert!(!Summary::deserialize(&value).unwrap().valid());
            for key in ["counts", "revision", "maxBuild", "marketingVersion"] {
                value[key] = Value::Null;
            }
            let parsed = Summary::deserialize(&value).unwrap();
            assert!(parsed.valid());
            assert!(!parsed.observed());
        }
        for (key, bad) in [
            ("maxBuild", json!(1)),
            ("marketingVersion", json!("2.0b1")),
            ("marketingVersion", json!("2.00")),
            ("coverage", json!("application-all-builds")),
            ("historicalUniqueness", json!("established")),
        ] {
            let mut value = summary();
            value[key] = bad;
            assert!(!Summary::deserialize(&value).unwrap().valid());
        }
        let mut missing = summary();
        missing.as_object_mut().unwrap().remove("maxBuild");
        assert!(Summary::deserialize(missing).is_err());
    }
    #[test]
    fn terminal_data_needs_all_original_command_and_lifetime_fields() {
        let context = wire::prepare(&input()).unwrap().context();
        let mut value = wire::tests::complete();
        value["context"] = json!(context);
        value["lifetime"]["commands"] = json!(7);
        value["lifetime"]["commandDispatched"] = json!(true);
        value["result"] = json!({"schemaVersion":1,"scope":SCOPE,"findings":[],"limitations":LIMITATIONS,
            "currentVersions":summary()});
        assert!(Terminal::deserialize(&value)
            .unwrap()
            .current_versions_data(&context)
            .is_some());
        for status in ["FAIL", "MISSING", "BLOCKED", "INVALID"] {
            let mut bad = value.clone();
            bad["result"]["findings"] = json!([{"check":"credential-format","status":status}]);
            assert!(Terminal::deserialize(bad)
                .unwrap()
                .current_versions_data(&context)
                .is_none());
        }
        for field in [
            "complete",
            "contained",
            "commandDispatched",
            "inputClosed",
            "handlersRestored",
            "invocationClosed",
        ] {
            let mut bad = value.clone();
            bad["lifetime"][field] = json!(false);
            assert!(Terminal::deserialize(&bad)
                .unwrap()
                .current_versions_data(&context)
                .is_none());
        }
        for count in [0, 6, 8] {
            let mut bad = value.clone();
            bad["lifetime"]["commands"] = json!(count);
            assert!(Terminal::deserialize(&bad)
                .unwrap()
                .current_versions_data(&context)
                .is_none());
        }
        let mut wrong = context.clone();
        wrong.credential_context_revision += 1;
        assert!(Terminal::deserialize(value)
            .unwrap()
            .current_versions_data(&wrong)
            .is_none());
    }
}
