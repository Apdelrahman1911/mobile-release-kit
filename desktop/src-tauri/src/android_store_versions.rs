//! Current Play temporary-edit inventory DATA, on the original Store owner.
//! No credential, receipt constructor or independent external-operation owner.
use super::{Context, ResultData, Terminal};
use serde::{Deserialize, Deserializer, Serialize};

pub(crate) const QUERY: &str = "android-current-versions";
pub(crate) const CONSENT: &str = "local-android-current-versions-edit-v1";
pub(crate) const SCOPE: &str = "local-android-current-version-inventory";
pub(crate) const COVERAGE: &str = "play-android-current-inventory/1";
pub(crate) const LIMITATIONS: [super::Limitation; 12] = [
    super::Limitation::NonPublishing,
    super::Limitation::NoProjectCommands,
    super::Limitation::NoBuildOrSigning,
    super::Limitation::NoReleaseReadiness,
    super::Limitation::PointInTimeAccountAccess,
    super::Limitation::SavedInputsNotAtomic,
    super::Limitation::CurrentVisibleOnly,
    super::Limitation::NotAtomicStoreSnapshot,
    super::Limitation::HistoricalUniquenessNotEstablished,
    super::Limitation::ExternalUploadersNotCoordinated,
    super::Limitation::TemporaryPlayEdit,
    super::Limitation::MayInvalidateAnotherPlayEdit,
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
    TemporaryEditUnconfirmed,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Edit {
    NotStarted,
    Deleted,
    Unconfirmed,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Counts {
    pub(crate) tracks: u16,
    pub(crate) releases: u16,
    pub(crate) version_codes: u16,
    pub(crate) bundles: u16,
    pub(crate) apks: u16,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Summary {
    observation: Observation,
    coverage: String,
    #[serde(deserialize_with = "required_optional")]
    pub(crate) revision: Option<String>,
    #[serde(deserialize_with = "required_optional")]
    pub(crate) counts: Option<Counts>,
    #[serde(deserialize_with = "required_optional")]
    pub(crate) max_build: Option<u32>,
    #[serde(deserialize_with = "required_optional")]
    marketing_version: Option<String>,
    temporary_edit: Edit,
    historical_uniqueness: String,
}
fn required_optional<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
impl Summary {
    pub(crate) fn observed(&self) -> bool {
        self.observation == Observation::Observed && self.valid()
    }
    pub(crate) fn valid(&self) -> bool {
        if self.coverage != COVERAGE
            || self.historical_uniqueness != "not-established"
            || self.marketing_version.is_some()
        {
            return false;
        }
        if self.observation != Observation::Observed {
            return self.revision.is_none()
                && self.counts.is_none()
                && self.max_build.is_none()
                && ((self.observation == Observation::TemporaryEditUnconfirmed)
                    == (self.temporary_edit == Edit::Unconfirmed));
        }
        let (Some(revision), Some(counts), Some(build)) =
            (&self.revision, self.counts, self.max_build)
        else {
            return false;
        };
        self.temporary_edit == Edit::Deleted
            && super::sha(revision)
            && counts.tracks <= 400
            && counts.releases <= 400
            && counts.version_codes <= 4000
            && counts.bundles <= 400
            && counts.apks <= 400
            && build <= 2_100_000_000
            && ((counts.version_codes == 0 && counts.bundles == 0 && counts.apks == 0)
                == (build == 0))
    }
}
// Exact two DATA shapes. iOS fields/serialization are unchanged. The Android
// shape has an additional required temporaryEdit field and a distinct coverage;
// the typed context below forbids borrowing the other platform's observation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum Inventory {
    Ios(super::store_versions::Summary),
    Android(Summary),
    Pair(super::paired_versions::Summary),
}
impl Inventory {
    pub(crate) fn pair(&self)->Option<&super::paired_versions::Summary>{if let Self::Pair(v)=self{Some(v)}else{None}}
    pub(crate) fn ios(&self) -> Option<&super::store_versions::Summary> {
        if let Self::Ios(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub(crate) fn android(&self) -> Option<&Summary> {
        if let Self::Android(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub(crate) fn observed(&self) -> bool {
        match self {
            Self::Ios(v) => v.observed(),
            Self::Android(v) => v.observed(),
            Self::Pair(v) => v.observed(),
        }
    }
}
pub(super) fn optional_inventory<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<Inventory>, D::Error> {
    Inventory::deserialize(d).map(Some)
}
pub(crate) fn selected(context: &Context) -> bool {
    context.platform == super::AccessPlatform::Android
        && context.query == Some(super::bundle_read::Query::AndroidCurrentVersions)
}
pub(super) fn valid_result(value: &ResultData) -> bool {
    value.schema_version == 1
        && value.scope == SCOPE
        && value.observation.is_none()
        && value.profile_reuse.is_none()
        && value
            .current_versions
            .as_ref()
            .and_then(Inventory::android)
            .is_some_and(Summary::valid)
        && value.limitations.as_slice() == LIMITATIONS
        && value.findings.len() <= 16
        && value.findings.iter().all(|f| {
            !value
                .current_versions
                .as_ref()
                .is_some_and(Inventory::observed)
                || f.check != super::CheckId::StoreAccess
                    && !matches!(
                        f.status,
                        super::CoreStatus::Fail
                            | super::CoreStatus::Missing
                            | super::CoreStatus::Blocked
                            | super::CoreStatus::Invalid
                    )
        })
}
impl Terminal {
    /// Still DATA: only actual SavedCommandOwner final retirement mints a receipt.
    pub(crate) fn current_inventory_data(&self, context: &Context) -> Option<&Inventory> {
        if !(selected(context) || super::store_versions::selected(context) || super::paired_versions::selected(context))
            || !self.valid(context)
            || self.outcome != super::Outcome::Complete
            || self.reason != super::Reason::None
            || self.lifetime.commands != context.platform.commands()
            || self.lifetime.command_dispatched != Some(true)
        {
            return None;
        }
        self.result
            .as_ref()?
            .current_versions
            .as_ref()
            .filter(|s| s.observed())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    fn summary() -> Value {
        json!({"observation":"observed","coverage":COVERAGE,"revision":"a".repeat(64),
        "counts":{"tracks":2,"releases":3,"versionCodes":5,"bundles":1,"apks":1},"maxBuild":21,
        "marketingVersion":null,"temporaryEdit":"deleted","historicalUniqueness":"not-established"})
    }
    #[test]
    fn play_current_inventory_requires_explicit_temporary_edit_and_no_marketing_guess() {
        let value: Inventory = serde_json::from_value(summary()).unwrap();
        assert!(value.android().unwrap().observed());
        assert!(value.ios().is_none());
        for (key, bad) in [
            ("temporaryEdit", json!("unconfirmed")),
            ("marketingVersion", json!("9.9.9")),
            ("maxBuild", json!(0)),
            ("coverage", json!(super::super::store_versions::COVERAGE)),
        ] {
            let mut v = summary();
            v[key] = bad;
            assert!(!serde_json::from_value::<Inventory>(v).unwrap().observed());
        }
        let mut value = summary();
        value.as_object_mut().unwrap().remove("temporaryEdit");
        assert!(serde_json::from_value::<Summary>(value).is_err());
    }
    #[test]
    fn play_query_and_consent_cannot_enter_old_access_or_ios_operations() {
        let mut input = json!(super::super::tests::context());
        input.as_object_mut().unwrap().remove("operation");
        input["query"] = json!(QUERY);
        input["platform"] = json!("android");
        let c = super::super::prepare(&input).unwrap().context();
        assert!(selected(&c));
        assert_eq!(c.query.unwrap().consent(), CONSENT);
        let mut start = json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":CONSENT});
        assert!(super::super::start(&start).unwrap().matches_context(&c));
        for consent in [super::super::CONSENT, super::super::store_versions::CONSENT] {
            start["consentVersion"] = json!(consent);
            assert!(!super::super::start(&start).unwrap().matches_context(&c));
        }
        input["platform"] = json!("ios");
        assert!(super::super::prepare(&input).is_err());
        input["platform"] = json!("android");
        input.as_object_mut().unwrap().remove("query");
        assert!(super::super::prepare(&input).is_err()); // Legacy Android shape is unchanged.
    }
    #[test]
    fn failed_delete_has_no_floor_even_if_all_current_lists_were_read() {
        let mut value = summary();
        value["temporaryEdit"] = json!("unconfirmed");
        assert!(!serde_json::from_value::<Summary>(value.clone())
            .unwrap()
            .valid());
        value["observation"] = json!("temporary-edit-unconfirmed");
        for k in ["revision", "counts", "maxBuild"] {
            value[k] = Value::Null;
        }
        let s: Summary = serde_json::from_value(value).unwrap();
        assert!(s.valid());
        assert!(!s.observed());
    }
}
