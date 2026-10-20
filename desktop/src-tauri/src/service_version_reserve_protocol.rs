//! Closed Reserve-only delegation DATA. No source, Store, account or edit
//! authority is accepted from IPC. Required nullable fields may not be omitted.
use crate::service_protocol::{Error, Id, Settlement};
use serde::{Deserialize, Deserializer, Serialize};

pub(crate) const CONSENT: &str = "agent-version-reserve-once-v1";
pub(crate) const REQUEST_LIMIT: usize = 32;
pub(crate) const RAW_LIMIT: usize = 1024;
pub(crate) const STATUS_LIMIT: usize = 2048;
pub(crate) const REVIEW_MS: u64 = 120_000;
pub(crate) const CI_SETTINGS_LIMIT: usize = 768;

/// Copyable CI preparation DATA only. The installed CLI deliberately does not
/// link the native allocator/ledger decoder; the workflow validates these
/// protected settings and the exact row against the full shared ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CiReference {
    pub(crate) authority_settings: String,
    pub(crate) commit_trailer: String,
}
impl CiReference {
    pub(crate) fn valid(&self, candidate: &str) -> bool {
        // Bounded display grammar, never repository/Store/native authority.
        !self.authority_settings.is_empty()
            && self.authority_settings.len() <= CI_SETTINGS_LIMIT
            && self.authority_settings.bytes().all(|b| (0x20..=0x7e).contains(&b))
            && self.commit_trailer.strip_prefix("MRK-Version-Reservation: ")
                .and_then(|v| v.split_once(' ')).is_some_and(|(id, hash)|
                    id == candidate && hash.len() == 64
                        && hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    }
}

fn required_nullable<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Query {
    pub(crate) project_id: Id,
    pub(crate) service_instance: Id,
    pub(crate) request_id: Id,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Submit {
    pub(crate) origin: Query,
    pub(crate) grant_id: Id,
    pub(crate) review_id: Id,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Access {
    #[serde(deserialize_with = "required_nullable")]
    pub(crate) service_instance: Option<Id>,
    #[serde(deserialize_with = "required_nullable")]
    pub(crate) project_id: Option<Id>,
    #[serde(deserialize_with = "required_nullable")]
    pub(crate) grant_id: Option<Id>,
    #[serde(deserialize_with = "required_nullable")]
    pub(crate) review_id: Option<Id>,
    #[serde(deserialize_with = "required_nullable")]
    pub(crate) review_revision: Option<u32>,
    pub(crate) enabled: bool,
    pub(crate) remaining_ms: u64,
    pub(crate) consumed: bool,
    #[serde(deserialize_with = "required_nullable")]
    pub(crate) request_id: Option<Id>,
    #[serde(deserialize_with = "required_nullable")]
    pub(crate) completed_operation_id: Option<Id>,
}
impl Access {
    pub(crate) fn empty() -> Self {
        Self {
            service_instance: None,
            project_id: None,
            grant_id: None,
            review_id: None,
            review_revision: None,
            enabled: false,
            remaining_ms: 0,
            consumed: false,
            request_id: None,
            completed_operation_id: None,
        }
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let group = [
            self.service_instance.is_some(),
            self.project_id.is_some(),
            self.grant_id.is_some(),
            self.review_id.is_some(),
            self.review_revision.is_some(),
        ];
        let present = group.iter().all(|v| *v);
        if (!present && group.iter().any(|v| *v))
            || self
                .review_revision
                .is_some_and(|v| v == 0 || v == u32::MAX)
            || self.remaining_ms > REVIEW_MS
            || self.enabled != (present && !self.consumed && self.remaining_ms > 0)
            || !self.enabled && self.remaining_ms != 0
            || self.consumed != self.request_id.is_some()
            || !present && (self.consumed || self.completed_operation_id.is_some())
            || self.completed_operation_id.is_some() && (!self.consumed || self.enabled)
        {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum State {
    Queued,
    Reserving,
    Stopping,
    Finishing,
    Reserved,
    Refused,
    Cancelled,
    Expired,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    UserCancelled,
    PermissionRevoked,
    Expired,
    ContextChanged,
    Shutdown,
    Busy,
    Unavailable,
    NativeRefused,
    CleanupUnknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Reservation {
    pub(crate) candidate_id: String,
    pub(crate) name: String,
    pub(crate) build: u64,
    // Older completed observations remain useful but cannot fabricate a CI
    // export. New exports originate only at the real joined native finish.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ci: Option<CiReference>,
}
impl Reservation {
    fn valid(&self) -> bool {
        // Native allocator already checks the full canonical request. This is
        // only the bounded, nonsecret result grammar for public comparison.
        self.candidate_id.len() == 36
            && self.candidate_id.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }
            })
            && (1..=32).contains(&self.name.len())
            && self.name.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            && (1..=2_100_000_000).contains(&self.build)
            && self.ci.as_ref().is_none_or(|v| v.valid(&self.candidate_id))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Status {
    pub(crate) origin: Query,
    pub(crate) grant_id: Id,
    pub(crate) review_id: Id,
    pub(crate) revision: u32,
    pub(crate) state: State,
    #[serde(deserialize_with = "required_nullable")]
    pub(crate) operation_id: Option<Id>,
    pub(crate) settlement: Settlement,
    #[serde(deserialize_with = "required_nullable")]
    pub(crate) reason: Option<Reason>,
    #[serde(deserialize_with = "required_nullable")]
    pub(crate) reservation: Option<Reservation>,
    pub(crate) do_not_replay: bool,
}
impl Status {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let terminal = matches!(
            self.state,
            State::Reserved | State::Refused | State::Cancelled | State::Expired
        );
        if self.revision == 0
            || self.revision == u32::MAX
            || !self.do_not_replay
            || (self.state == State::Unknown) != (self.settlement == Settlement::Unknown)
            || terminal != (self.settlement == Settlement::Settled)
            || (self.state == State::Reserved) != self.reservation.is_some()
            || self.reservation.as_ref().is_some_and(|v| !v.valid())
            || matches!(self.state, State::Reserved | State::Reserving)
                && self.operation_id.is_none()
            || self.state == State::Reserved && self.reason.is_some()
            || self.state == State::Unknown && self.reason != Some(Reason::CleanupUnknown)
        {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "service_version_reserve_protocol_tests.rs"]
mod tests;
