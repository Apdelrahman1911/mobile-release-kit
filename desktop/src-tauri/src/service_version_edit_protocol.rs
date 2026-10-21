//! Compact comparison DATA for an already prepared, separately approved version
//! edit. No file contents, paths to open, credential, or writer authority enter IPC.
use crate::service_protocol::{Error, Id, Settlement};
use serde::{Deserialize, Serialize};

pub const REQUEST_LIMIT: usize = 32;
pub const REQUEST_BYTES: usize = 1024;
pub const STATUS_BYTES: usize = 8192;
pub const CONSENT: &str = "agent-exact-prepared-version-apply-v1";

fn nullable<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}
pub(crate) fn bounded<T: Serialize>(v: &T, n: usize) -> Result<(), Error> {
    struct Count {
        n: usize,
        max: usize,
    }
    impl std::io::Write for Count {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.n = self
                .n
                .checked_add(b.len())
                .filter(|n| *n <= self.max)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Count { n: 0, max: n }, v).map_err(|_| Error::InvalidRequest)
}
pub(crate) fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub project_id: Id,
    pub service_instance: Id,
    pub request_id: Id,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Original {
    pub session_id: Id,
    pub owner_generation: Id,
    pub revision: Id,
    pub plan_token: Id,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Submit {
    pub origin: Query,
    pub grant_id: Id,
    pub session_id: Id,
    pub plan_token: Id,
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
pub struct Review {
    pub original: Original,
    pub native_status_revision: u32,
    pub name: String,
    pub build: String,
    pub source: String,
    pub before_bytes: u32,
    pub before_sha256: String,
    pub after_bytes: u32,
    pub after_sha256: String,
    #[serde(deserialize_with = "nullable")]
    pub candidate_id: Option<String>,
}
impl Review {
    pub fn validate(&self) -> Result<(), Error> {
        let path = &self.source;
        let candidate = self.candidate_id.as_ref().is_none_or(|s| {
            s.len() == 36
                && s.bytes().enumerate().all(|(i, c)| {
                    if [8, 13, 18, 23].contains(&i) {
                        c == b'-'
                    } else {
                        c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
                    }
                })
        });
        if self.native_status_revision == u32::MAX
            || self.name.is_empty()
            || self.name.len() > 64
            || !self.name.bytes().all(|c| (0x20..0x7f).contains(&c))
            || self.build.is_empty()
            || self.build.len() > 10
            || !self.build.bytes().all(|c| c.is_ascii_digit())
            || path.is_empty()
            || path.len() > 512
            || path.starts_with('/')
            || path.contains(['\\', ':'])
            || !path.bytes().all(|c| (0x20..0x7f).contains(&c))
            || path
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
            || self.before_bytes == 0
            || self.after_bytes == 0
            || self.before_bytes > 64 * 1024
            || self.after_bytes > 64 * 1024
            || !hex(&self.before_sha256)
            || !hex(&self.after_sha256)
            || !candidate
        {
            return Err(Error::InvalidRequest);
        }
        bounded(self, 4096)
    }
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Effect {
    NotStarted,
    Unchanged,
    RolledBack,
    Committed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Journal {
    NotCreated,
    Clean,
    RecoveryRequired,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Final {
    pub effect: Effect,
    pub journal: Journal,
    pub cancelled: bool,
    pub apply_submitted: bool,
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
        bounded(self, STATUS_BYTES)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Access {
    pub schema_version: u32,
    #[serde(deserialize_with = "nullable")]
    pub service_instance: Option<Id>,
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
    pub(crate) fn empty() -> Self {
        Self {
            schema_version: 1,
            service_instance: None,
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
        let complete = self.service_instance.is_some()
            && self.project_id.is_some()
            && self.grant_id.is_some()
            && self.nonce.is_some()
            && self.review.is_some();
        let empty = self.service_instance.is_none()
            && self.project_id.is_none()
            && self.grant_id.is_none()
            && self.nonce.is_none()
            && self.review.is_none();
        if self.schema_version != 1
            || !(complete || empty)
            || self.remaining_ms > 900_000
            || self.live != (self.remaining_ms > 0)
            || self.live && (!complete || self.request.is_some())
            || empty && self.request.is_some()
        {
            return Err(Error::InvalidRequest);
        }
        if let Some(r) = &self.request {
            if self.service_instance.as_ref() != Some(&r.origin.service_instance)
                || self.project_id.as_ref() != Some(&r.origin.project_id)
                || self.grant_id.as_ref() != Some(&r.grant_id)
                || self.review.as_ref() != Some(&r.review)
            {
                return Err(Error::InvalidRequest);
            }
        }
        if let Some(r) = &self.review {
            r.validate()?
        }
        if let Some(r) = &self.request {
            r.validate()?
        }
        bounded(self, 2 * STATUS_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(n: char) -> Id {
        Id::parse(&n.to_string().repeat(32)).unwrap()
    }
    #[test]
    fn exact_submit_cannot_supply_path_values_or_borrow_other_consent() {
        let submit = Submit {
            origin: Query {
                project_id: id('1'),
                service_instance: id('2'),
                request_id: id('3'),
            },
            grant_id: id('4'),
            session_id: id('5'),
            plan_token: id('6'),
            reviewed: true,
        };
        let request = crate::service_protocol::Request {
            version: crate::service_protocol::VERSION,
            request_id: id('7'),
            request: crate::service_protocol::RequestBody::VersionEditSubmit(submit),
        };
        let raw = crate::service_protocol::encode_request(&request).unwrap();
        assert!(raw.len() <= REQUEST_BYTES);
        let original: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        for field in ["root", "values", "candidateId", "token", "window"] {
            let mut v = original.clone();
            v["request"]["params"][field] = serde_json::json!("not authority");
            assert!(
                crate::service_protocol::decode_request(&serde_json::to_vec(&v).unwrap()).is_err()
            );
        }
        let mut no = original.clone();
        no["request"]["params"]["reviewed"] = serde_json::json!(false);
        assert!(
            crate::service_protocol::decode_request(&serde_json::to_vec(&no).unwrap()).is_err()
        );
        let mut extra = raw;
        extra.extend(std::iter::repeat_n(b' ', REQUEST_BYTES + 1));
        assert!(crate::service_protocol::decode_request(&extra).is_err());
    }
    #[test]
    fn access_requires_exact_nulls_and_bound_result_never_empty_success() {
        let empty = Access::empty();
        empty.validate().unwrap();
        let value = serde_json::to_value(&empty).unwrap();
        for field in [
            "serviceInstance",
            "projectId",
            "grantId",
            "nonce",
            "review",
            "request",
        ] {
            let mut v = value.clone();
            v.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Access>(v).is_err());
        }
        let mut mixed = empty;
        mixed.project_id = Some(id('1'));
        assert!(mixed.validate().is_err());
        assert!(bounded(&"x".repeat(STATUS_BYTES), STATUS_BYTES).is_err());
    }
}
