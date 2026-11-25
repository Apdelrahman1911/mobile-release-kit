//! Installed-CLI DATA only. No native Setup/Connection/ledger imports.
use crate::service_protocol::{Error, Id, Settlement};
use serde::{Deserialize, Deserializer, Serialize};

pub(crate) const REQUEST_LIMIT: usize = 32;
pub(crate) const RAW_LIMIT: usize = 1024;
pub(crate) const STATUS_LIMIT: usize = 2048;
pub(crate) const REVIEW_MS: u64 = 120_000;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Purpose { #[default] PlayCleanup, VersionTag }
impl Purpose { pub(crate) fn is_cleanup(&self) -> bool { *self == Self::PlayCleanup } }

fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Query {
    pub(crate) project_id: Id,
    pub(crate) service_instance: Id,
    pub(crate) request_id: Id,
    #[serde(default, skip_serializing_if = "Purpose::is_cleanup")]
    pub(crate) purpose: Purpose,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Submit {
    pub(crate) origin: Query,
    pub(crate) consent_id: Id,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Access {
    pub(crate) service_instance: Id,
    pub(crate) project_id: Id,
    pub(crate) consent_id: Id,
    pub(crate) enabled: bool,
    pub(crate) remaining_ms: u64,
    #[serde(default, skip_serializing_if = "Purpose::is_cleanup")]
    pub(crate) purpose: Purpose,
}
impl Access {
    pub(crate) fn valid(&self) -> bool {
        self.remaining_ms <= REVIEW_MS && self.enabled == (self.remaining_ms > 0)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum State {
    Queued,
    Dispatching,
    Stopping,
    Settled,
    Refused,
    Cancelled,
    Expired,
    Unknown,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Effect {
    NotSent,
    PotentiallyApplied,
    AcknowledgedUnconfirmed,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Status {
    pub(crate) origin: Query,
    pub(crate) consent_id: Id,
    pub(crate) revision: u32,
    pub(crate) state: State,
    pub(crate) settlement: Settlement,
    // Supervisor-local text, always correlated with this service+request.
    #[serde(deserialize_with = "nullable")]
    pub(crate) operation_id: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) reason: Option<Reason>,
    pub(crate) effect: Effect,
    pub(crate) do_not_replay: bool,
}
pub(crate) fn operation_id(value: &str) -> bool {
    value.strip_prefix("github-play-cleanup-").is_some_and(|s| {
        !s.is_empty()
            && s.len() <= 20
            && !s.starts_with('0')
            && s.bytes().all(|b| b.is_ascii_digit())
            && s.parse::<u64>().is_ok()
    })
}
impl Status {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let terminal = matches!(
            self.state,
            State::Settled | State::Refused | State::Cancelled | State::Expired
        );
        if self.revision == 0
            || self.revision == u32::MAX
            || !self.do_not_replay
            || terminal != (self.settlement == Settlement::Settled)
            || (self.state == State::Unknown) != (self.settlement == Settlement::Unknown)
            || self.operation_id.as_ref().is_some_and(|s| !operation_id(s))
            || matches!(self.state, State::Dispatching | State::Settled)
                && self.operation_id.is_none()
            || self.state == State::Queued && self.operation_id.is_some()
            || self.effect != Effect::NotSent && self.operation_id.is_none()
            || self.effect == Effect::AcknowledgedUnconfirmed
                && !matches!(
                    self.state,
                    State::Settled | State::Cancelled | State::Expired | State::Unknown
                )
            || self.state == State::Unknown && self.reason != Some(Reason::CleanupUnknown)
        {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "service_play_cleanup_protocol_tests.rs"]
mod tests;
