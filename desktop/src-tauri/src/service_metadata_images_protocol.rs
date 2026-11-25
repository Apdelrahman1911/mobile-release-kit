//! Compact DATA for one already Desktop-prepared local image import. No paths,
//! image bytes, picker inputs, replacement choices or full native Status in IPC.
pub use crate::service_configuration_protocol::{Effect, Journal, Query};
use crate::service_protocol::{Error, Id, Settlement};
use serde::{Deserialize, Serialize};

pub const REQUEST_BYTES: usize = 4096;
pub const STATUS_BYTES: usize = 8192;
pub const REVIEW_BYTES: usize = 2048;
pub const CONSENT: &str = "agent-exact-metadata-images-preview-v1";
pub const EVENT: &str = "mrk:agent-metadata-images";
pub(crate) use crate::service_version_edit_protocol::bounded;
fn nullable<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Original {
    pub session_id: Id,
    pub owner_generation: Id,
    pub revision: Id,
    pub plan_token: Id,
    pub draft_revision: u32,
    pub baseline_generation: u32,
}
impl Original {
    pub fn validate(&self) -> Result<(), Error> {
        if self.draft_revision == u32::MAX
            || self.baseline_generation == u32::MAX
            || self.revision == self.plan_token
        {
            Err(Error::InvalidRequest)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Android,
    Ios,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Review {
    pub original: Original,
    pub native_status_revision: u32,
    pub platform: Platform,
    pub locale: String,
    pub asset_type: String,
    pub file_count: u32,
    pub create_count: u32,
    pub replace_count: u32,
    pub preserve_count: u32,
    pub selected_bytes: u32,
    pub prepared_sha256: String,
}
impl Review {
    pub fn validate(&self) -> Result<(), Error> {
        self.original.validate()?;
        let count = self
            .create_count
            .checked_add(self.replace_count)
            .and_then(|n| n.checked_add(self.preserve_count));
        if self.native_status_revision == u32::MAX
            || !crate::service_metadata_text_protocol::locale(&self.locale)
            || self.asset_type.is_empty()
            || self.asset_type.len() > 64
            || !self
                .asset_type
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_')
            || !(1..=10).contains(&self.file_count)
            || count != Some(self.file_count)
            || !(1..=25165824).contains(&self.selected_bytes)
            || !crate::service_version_edit_protocol::hex(&self.prepared_sha256)
        {
            return Err(Error::InvalidRequest);
        }
        bounded(self, REVIEW_BYTES)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Submit {
    pub origin: Query,
    pub grant_id: Id,
    pub reviewed: bool,
}
impl Submit {
    pub fn validate(&self) -> Result<(), Error> {
        if !self.reviewed {
            return Err(Error::InvalidRequest);
        }
        bounded(self, REQUEST_BYTES)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Scope {
    pub project_id: Id,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    Queued,
    Admitting,
    Applying,
    Stopping,
    Final,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Final {
    pub effect: Effect,
    pub journal: Journal,
    pub cancelled: bool,
    pub apply_submitted: bool,
    pub completed: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    pub schema_version: u32,
    pub origin: Query,
    pub grant_id: Id,
    pub revision: u32,
    pub phase: Phase,
    pub settlement: Settlement,
    pub review: Review,
    pub cancel_requested: bool,
    #[serde(deserialize_with = "nullable")]
    pub result: Option<Final>,
    pub do_not_replay: bool,
}
impl Status {
    pub fn validate(&self) -> Result<(), Error> {
        self.review.validate()?;
        if self.schema_version != 1
            || self.revision == 0
            || self.revision == u32::MAX
            || !self.do_not_replay
            || (self.phase == Phase::Unknown) != (self.settlement == Settlement::Unknown)
            || (self.phase == Phase::Final) != (self.settlement == Settlement::Settled)
            || (self.phase == Phase::Final) != self.result.is_some()
        {
            return Err(Error::InvalidRequest);
        }
        if let Some(f) = &self.result {
            if f.completed
                && (!f.apply_submitted
                    || f.cancelled
                    || !matches!(
                        (f.effect, f.journal),
                        (Effect::Committed, Journal::Clean)
                            | (Effect::Unchanged, Journal::NotCreated)
                    ))
                || !f.apply_submitted
                    && (f.effect != Effect::NotStarted || f.journal != Journal::NotCreated)
                || f.effect == Effect::Unchanged
                    && (self.review.create_count != 0
                        || self.review.replace_count != 0
                        || f.journal != Journal::NotCreated)
                || matches!(f.effect, Effect::Committed | Effect::RolledBack)
                    && self.review.create_count + self.review.replace_count == 0
            {
                return Err(Error::InvalidRequest);
            }
        }
        bounded(self, STATUS_BYTES / 2)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Access {
    pub schema_version: u32,
    pub service_instance: Id,
    #[serde(deserialize_with = "nullable")]
    pub project_id: Option<Id>,
    #[serde(deserialize_with = "nullable")]
    pub grant_id: Option<Id>,
    #[serde(deserialize_with = "nullable")]
    pub nonce: Option<Id>,
    #[serde(deserialize_with = "nullable")]
    pub review: Option<Review>,
    pub live: bool,
    pub remaining_ms: u64,
    #[serde(deserialize_with = "nullable")]
    pub request: Option<Status>,
}
impl Access {
    pub(crate) fn empty(instance: Id) -> Self {
        Self {
            schema_version: 1,
            service_instance: instance,
            project_id: None,
            grant_id: None,
            nonce: None,
            review: None,
            live: false,
            remaining_ms: 0,
            request: None,
        }
    }
    pub fn validate(&self) -> Result<(), Error> {
        let full = self.project_id.is_some()
            && self.grant_id.is_some()
            && self.nonce.is_some()
            && self.review.is_some();
        let empty = self.project_id.is_none()
            && self.grant_id.is_none()
            && self.nonce.is_none()
            && self.review.is_none();
        if self.schema_version != 1
            || !(full || empty)
            || self.remaining_ms > 900000
            || self.live != (self.remaining_ms > 0)
            || self.live && (!full || self.request.is_some())
            || empty && self.request.is_some()
        {
            return Err(Error::InvalidRequest);
        }
        if let Some(r) = &self.review {
            r.validate()?;
        }
        if let Some(r) = &self.request {
            r.validate()?;
            if r.origin.service_instance != self.service_instance
                || Some(&r.origin.project_id) != self.project_id.as_ref()
                || Some(&r.grant_id) != self.grant_id.as_ref()
                || Some(&r.review) != self.review.as_ref()
            {
                return Err(Error::InvalidRequest);
            }
        }
        bounded(self, STATUS_BYTES)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Revoked {
    pub nonce: Id,
    pub access: Access,
}
impl Revoked {
    pub fn validate(&self) -> Result<(), Error> {
        self.access.validate()?;
        bounded(self, STATUS_BYTES)
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    pub(crate) fn id(c: char) -> Id {
        Id::parse(&c.to_string().repeat(32)).unwrap()
    }
    pub(crate) fn original() -> Original {
        Original {
            session_id: id('a'),
            owner_generation: id('b'),
            revision: id('c'),
            plan_token: id('d'),
            draft_revision: 1,
            baseline_generation: 1,
        }
    }
    pub(crate) fn review() -> Review {
        Review {
            original: original(),
            native_status_revision: 4,
            platform: Platform::Android,
            locale: "en-US".into(),
            asset_type: "phoneScreenshots".into(),
            file_count: 2,
            create_count: 1,
            replace_count: 0,
            preserve_count: 1,
            selected_bytes: 4096,
            prepared_sha256: "e".repeat(64),
        }
    }
    pub(crate) fn query() -> Query {
        Query {
            service_instance: id('1'),
            project_id: id('2'),
            request_id: id('3'),
        }
    }
    pub(crate) fn status() -> Status {
        Status {
            schema_version: 1,
            origin: query(),
            grant_id: id('4'),
            revision: 1,
            phase: Phase::Queued,
            settlement: Settlement::Pending,
            review: review(),
            cancel_requested: false,
            result: None,
            do_not_replay: true,
        }
    }
    pub(crate) fn done() -> Final {
        Final {
            effect: Effect::Committed,
            journal: Journal::Clean,
            cancelled: false,
            apply_submitted: true,
            completed: true,
        }
    }
    pub(crate) fn access() -> Access {
        Access {
            schema_version: 1,
            service_instance: id('1'),
            project_id: Some(id('2')),
            grant_id: Some(id('4')),
            nonce: Some(id('5')),
            review: Some(review()),
            live: true,
            remaining_ms: 900000,
            request: None,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use fixtures::*;
    #[test]
    fn closed_image_submit_contains_no_source_bytes_paths_choices_or_recovery() {
        let input = Submit {
            origin: query(),
            grant_id: id('4'),
            reviewed: true,
        };
        let value = serde_json::to_value(&input).unwrap();
        assert_eq!(
            serde_json::from_value::<Submit>(value.clone()).unwrap(),
            input
        );
        for field in [
            "paths",
            "images",
            "choices",
            "recovery",
            "target",
            "token",
            "preparedSha256",
        ] {
            let mut bad = value.clone();
            bad[field] = serde_json::json!([]);
            assert!(serde_json::from_value::<Submit>(bad).is_err());
        }
        let mut no = input;
        no.reviewed = false;
        assert!(no.validate().is_err());
        let mut bad = value;
        bad["origin"]["requestId"] = serde_json::json!("0".repeat(32));
        assert!(serde_json::from_value::<Submit>(bad).is_err());
    }
    #[test]
    fn image_access_requires_exact_nullable_group_and_same_original_review() {
        let access = access();
        assert!(access.validate().is_ok());
        let raw = serde_json::to_value(&access).unwrap();
        for field in ["projectId", "grantId", "nonce", "review", "request"] {
            let mut bad = raw.clone();
            bad.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Access>(bad).is_err());
        }
        let mut a = access.clone();
        a.review.as_mut().unwrap().file_count = 3;
        assert!(a.validate().is_err());
        let mut a = access.clone();
        a.live = false;
        a.remaining_ms = 0;
        a.request = Some(status());
        assert!(a.validate().is_ok());
        a.request.as_mut().unwrap().review.original.plan_token = id('f');
        assert!(a.validate().is_err());
        let mut a = access.clone();
        a.review.as_mut().unwrap().selected_bytes = 25165825;
        assert!(a.validate().is_err());
        let mut a = access;
        a.review.as_mut().unwrap().locale = "en\n".into();
        assert!(a.validate().is_err());
    }
    #[test]
    fn original_image_effect_and_finality_cannot_be_manufactured_from_display_counts() {
        let mut s = status();
        assert!(s.validate().is_ok());
        s.result = Some(done());
        assert!(s.validate().is_err());
        s.phase = Phase::Final;
        s.settlement = Settlement::Settled;
        assert!(s.validate().is_ok());
        s.result.as_mut().unwrap().apply_submitted = false;
        assert!(s.validate().is_err());
        s.result = Some(done());
        s.result.as_mut().unwrap().effect = Effect::Unchanged;
        s.result.as_mut().unwrap().journal = Journal::NotCreated;
        assert!(s.validate().is_err());
        s.review.create_count = 0;
        s.review.preserve_count = 2;
        assert!(s.validate().is_ok());
        s.phase = Phase::Unknown;
        s.settlement = Settlement::Unknown;
        assert!(s.validate().is_err());
        s.result = None;
        assert!(s.validate().is_ok());
        assert!(serde_json::to_vec(&s).unwrap().len() < STATUS_BYTES / 2);
        assert_eq!((REQUEST_BYTES, STATUS_BYTES), (4096, 8192));
    }
}
