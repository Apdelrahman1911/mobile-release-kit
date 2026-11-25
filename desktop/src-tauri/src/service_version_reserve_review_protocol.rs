//! A read proposal, never a source witness, Store query, Reserve grant or
//! candidate. This closed DATA module is also used by the transport-only CLI.
use crate::{
    service_protocol::{Error, Settlement},
    service_version_reserve_protocol as reserve,
};
pub(crate) use reserve::Query;
use serde::{Deserialize, Serialize};
pub(crate) const REQUEST_BYTES: usize = 1024;
pub(crate) const STATUS_BYTES: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Increment {
    Build,
    Patch,
    Minor,
    Major,
}

/// The original SOURCE branch grammar, shared rather than a CLI policy parser.
pub(crate) fn branch(value: &str) -> bool {
    let Some(name) = value.strip_prefix("refs/heads/") else {
        return false;
    };
    !name.is_empty()
        && name.len() <= 200
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
        && !name.contains("..")
        && !name.starts_with("refs/")
        && name.split('/').count() <= 16
        && name.split('/').all(|p| {
            !p.is_empty() && !p.starts_with('.') && !p.ends_with('.') && !p.ends_with(".lock")
        })
}
fn tag<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Options {
    pub(crate) reference: String,
    pub(crate) increment: Increment,
    pub(crate) new_candidate: bool,
    pub(crate) acknowledge_limitations: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "tag"
    )]
    pub(crate) future_tag: Option<String>,
}
impl Options {
    pub(crate) fn valid(&self) -> bool {
        branch(&self.reference) && self.acknowledge_limitations
            // Only bounded comparison DATA here. The real native Review also
            // validates the original future-tag grammar before source admission.
            && self.future_tag.as_deref().is_none_or(|v|v.len()<=210 && v.strip_prefix("refs/tags/")
                .is_some_and(|name|branch(&format!("refs/heads/{name}"))))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) origin: Query,
    pub(crate) options: Options,
}
impl Request {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if !self.options.valid() {
            return Err(Error::InvalidRequest);
        }
        bounded(self, REQUEST_BYTES)
    }
}
pub(crate) fn bounded(value: &impl Serialize, limit: usize) -> Result<(), Error> {
    if serde_json::to_vec(value)
        .map_err(|_| Error::InvalidRequest)?
        .len()
        > limit
    {
        Err(Error::InvalidRequest)
    } else {
        Ok(())
    }
}
fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase {
    Queued,
    Reading,
    Finishing,
    ReviewReady,
    Refused,
    Stopping,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Review {
    pub(crate) id: crate::service_protocol::Id,
    pub(crate) revision: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Status {
    pub(crate) schema_version: u32,
    pub(crate) origin: Query,
    pub(crate) runtime_project_id: String,
    pub(crate) options: Options,
    pub(crate) revision: u32,
    pub(crate) phase: Phase,
    pub(crate) settlement: Settlement,
    #[serde(deserialize_with = "nullable")]
    pub(crate) operation_id: Option<crate::service_protocol::Id>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) review: Option<Review>,
    pub(crate) remaining_ms: u64,
    #[serde(deserialize_with = "nullable")]
    pub(crate) reason: Option<reserve::Reason>,
    pub(crate) do_not_replay: bool,
}
impl Status {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1
            || self.revision == 0
            || self.revision == u32::MAX
            || !self.do_not_replay
            || self.runtime_project_id.is_empty()
            || self.runtime_project_id.len() > 64
            || !self
                .runtime_project_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || !self.options.valid()
            || self.remaining_ms > reserve::REVIEW_MS
            || (self.phase == Phase::Unknown) != (self.settlement == Settlement::Unknown)
            || matches!(self.phase, Phase::ReviewReady | Phase::Refused)
                != (self.settlement == Settlement::Settled)
            || (self.phase == Phase::ReviewReady) != self.review.is_some()
            || self.phase != Phase::ReviewReady && self.remaining_ms != 0
            || self.review.as_ref().is_some_and(|r| {
                r.revision == 0
                    || r.revision == u32::MAX
                    || self.operation_id.as_ref() != Some(&r.id)
            })
            || self.phase == Phase::ReviewReady && self.reason.is_some()
            || self.phase == Phase::Unknown && self.reason != Some(reserve::Reason::CleanupUnknown)
        {
            return Err(Error::InvalidRequest);
        }
        bounded(self, STATUS_BYTES - 128)
    }
}

#[cfg(test)]
#[path = "service_version_reserve_review_protocol_tests.rs"]
mod tests;
