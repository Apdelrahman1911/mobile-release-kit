//! One paired inventory DATA shape on the existing Store owner. No two-receipt
//! adoption, material provider, cleanup authority or historical-usage claim.
use super::{Context, ResultData};
use serde::{Deserialize, Deserializer, Serialize};
pub(crate) const QUERY: &str = "paired-current-versions";
pub(crate) const CONSENT: &str = "local-paired-current-versions-edit-v1";
pub(crate) const SCOPE: &str = "local-shared-current-version-inventory";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Record {
    pub(crate) record_id: String,
    pub(crate) record_revision: u32,
}
impl Record {
    pub(crate) fn valid(&self, primary: &str) -> bool {
        super::token(&self.record_id)
            && self.record_id != primary
            && self.record_revision > 0
            && self.record_revision < u32::MAX
    }
}
pub(super) fn optional_record<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Record>, D::Error> {
    Record::deserialize(d).map(Some)
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Summary {
    pub(crate) android: super::play_versions::Summary,
    pub(crate) ios: super::store_versions::Summary,
}
impl Summary {
    pub(crate) fn valid(&self) -> bool {
        self.android.valid() && self.ios.valid()
    }
    pub(crate) fn observed(&self) -> bool {
        self.android.observed() && self.ios.observed()
    }
}
pub(crate) fn selected(c: &Context) -> bool {
    c.platform == super::AccessPlatform::Both
        && c.query == Some(super::bundle_read::Query::PairedCurrentVersions)
        && c.ios_record.as_ref().is_some_and(|r| r.valid(&c.record_id))
}
pub(super) fn valid_result(v: &ResultData) -> bool {
    v.schema_version == 1
        && v.scope == SCOPE
        && v.observation.is_none()
        && v.profile_reuse.is_none()
        && v.current_versions
            .as_ref()
            .and_then(super::play_versions::Inventory::pair)
            .is_some_and(Summary::valid)
        && v.limitations.as_slice() == super::play_versions::LIMITATIONS
        && v.findings.len() <= 16
        && v.findings.iter().all(|f| {
            !v.current_versions
                .as_ref()
                .is_some_and(super::play_versions::Inventory::observed)
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn pair_requires_two_distinct_records_and_only_its_explicit_consent() {
        let mut v = json!(super::super::tests::context());
        v.as_object_mut().unwrap().remove("operation");
        v["platform"] = json!("both");
        v["query"] = json!(QUERY);
        v["iosRecord"] = json!({"recordId":"c".repeat(32),"recordRevision":1});
        let c = super::super::prepare(&v).unwrap().context();
        assert!(selected(&c));
        for consent in [
            CONSENT,
            super::super::CONSENT,
            super::super::APPLE_CONSENT,
            super::super::store_versions::CONSENT,
            super::super::play_versions::CONSENT,
        ] {
            let start=super::super::start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":consent})).unwrap();
            assert_eq!(start.matches_context(&c), consent == CONSENT);
        }
        for platform in ["android", "ios"] {
            let mut bad = v.clone();
            bad["platform"] = json!(platform);
            assert!(super::super::prepare(&bad).is_err());
        }
        let mut bad = v.clone();
        bad["iosRecord"]["recordId"] = v["recordId"].clone();
        assert!(super::super::prepare(&bad).is_err());
        v["iosRecord"] = serde_json::Value::Null;
        assert!(super::super::prepare(&v).is_err());
        v.as_object_mut().unwrap().remove("iosRecord");
        assert!(super::super::prepare(&v).is_err());
    }
}
