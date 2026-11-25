//! Current-visible Store DATA only. This shared CLI codec has no native
//! receipt, credentials, runtime, Store client or version-allocation authority.
use crate::service_store_protocol as store;
use serde::{Deserialize, Deserializer, Serialize};

fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Edit {
    NotStarted,
    Deleted,
    Unconfirmed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct IosCounts {
    pub builds: u16,
    pub build_uploads: u16,
    pub app_store_versions: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AndroidCounts {
    pub tracks: u16,
    pub releases: u16,
    pub version_codes: u16,
    pub bundles: u16,
    pub apks: u16,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Ios {
    pub observation: Observation,
    pub coverage: String,
    #[serde(deserialize_with = "nullable")]
    pub revision: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub counts: Option<IosCounts>,
    #[serde(deserialize_with = "nullable")]
    pub max_build: Option<u32>,
    #[serde(deserialize_with = "nullable")]
    pub marketing_version: Option<String>,
    pub historical_uniqueness: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Android {
    pub observation: Observation,
    pub coverage: String,
    #[serde(deserialize_with = "nullable")]
    pub revision: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub counts: Option<AndroidCounts>,
    #[serde(deserialize_with = "nullable")]
    pub max_build: Option<u32>,
    #[serde(deserialize_with = "nullable")]
    pub marketing_version: Option<String>,
    pub temporary_edit: Edit,
    pub historical_uniqueness: String,
}
impl Ios {
    pub fn valid(&self) -> bool {
        if self.coverage != "asc-ios-current-inventory/1"
            || self.historical_uniqueness != "not-established"
            || self.observation == Observation::TemporaryEditUnconfirmed
        {
            return false;
        }
        if self.observation != Observation::Observed {
            return self.revision.is_none()
                && self.counts.is_none()
                && self.max_build.is_none()
                && self.marketing_version.is_none();
        }
        let (Some(r), Some(c), Some(n)) = (&self.revision, self.counts, self.max_build) else {
            return false;
        };
        store::sha(r)
            && c.builds <= 400
            && c.build_uploads <= 400
            && c.app_store_versions <= 400
            && n <= 2_100_000_000
            && ((c.builds == 0 && c.build_uploads == 0) == (n == 0))
            && ((c.builds == 0 && c.build_uploads == 0 && c.app_store_versions == 0)
                == self.marketing_version.is_none())
            && self.marketing_version.as_deref().is_none_or(|v| {
                let mut parts = 0;
                !v.is_empty()
                    && v.len() <= 64
                    && v.split('.').all(|p| {
                        parts += 1;
                        !p.is_empty()
                            && (p.len() == 1 || !p.starts_with('0'))
                            && p.bytes().all(|b| b.is_ascii_digit())
                    })
                    && (2..=3).contains(&parts)
            })
    }
}
impl Android {
    pub fn valid(&self) -> bool {
        if self.coverage != "play-android-current-inventory/1"
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
        let (Some(r), Some(c), Some(n)) = (&self.revision, self.counts, self.max_build) else {
            return false;
        };
        self.temporary_edit == Edit::Deleted
            && store::sha(r)
            && c.tracks <= 400
            && c.releases <= 400
            && c.version_codes <= 4000
            && c.bundles <= 400
            && c.apks <= 400
            && n <= 2_100_000_000
            && ((c.version_codes == 0 && c.bundles == 0 && c.apks == 0) == (n == 0))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Inventory {
    Ios { current: Ios },
    Android { current: Android },
    Both { android: Android, ios: Ios },
}
impl Inventory {
    pub fn valid(&self) -> bool {
        match self {
            Self::Ios { current } => current.valid(),
            Self::Android { current } => current.valid(),
            Self::Both { android, ios } => android.valid() && ios.valid(),
        }
    }
    /// These are owned public summaries, never a borrowed provider body.
    /// A short value with an excessive retained capacity is not a small row.
    pub(crate) fn bounded_capacity(&self) -> bool {
        fn ios(v: &Ios) -> bool {
            v.coverage.capacity() <= 64
                && v.historical_uniqueness.capacity() <= 32
                && v.revision.as_ref().is_none_or(|v| v.capacity() <= 64)
                && v.marketing_version
                    .as_ref()
                    .is_none_or(|v| v.capacity() <= 64)
        }
        fn android(v: &Android) -> bool {
            v.coverage.capacity() <= 64
                && v.historical_uniqueness.capacity() <= 32
                && v.revision.as_ref().is_none_or(|v| v.capacity() <= 64)
                && v.marketing_version.is_none()
        }
        self.valid()
            && match self {
                Self::Ios { current } => ios(current),
                Self::Android { current } => android(current),
                Self::Both { android: a, ios: i } => android(a) && ios(i),
            }
    }
}
