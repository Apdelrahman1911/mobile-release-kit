//! IDs-only local preparation. This never carries an Apple Context or material.
use crate::{
    service_apple_provisioning_protocol as apple,
    service_protocol::{Error, Id, Settlement},
};
use serde::{Deserialize, Serialize};

pub(crate) const CONSENT: &str = "agent-apple-prepare-once-v1";
pub(crate) const EVENT: &str = "mrk-agent-apple-preparation";
pub(crate) const STARTUP_SECONDS: u64 = 30;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Submit {
    pub(crate) origin: apple::Query,
    pub(crate) grant_id: Id,
    pub(crate) scope_id: Id,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase {
    Queued,
    Preparing,
    Finishing,
    Prepared,
    Refused,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Status {
    pub(crate) origin: apple::Query,
    pub(crate) grant_id: Id,
    pub(crate) scope_id: Id,
    pub(crate) mode: apple::Mode,
    pub(crate) revision: u32,
    pub(crate) phase: Phase,
    pub(crate) settlement: Settlement,
    pub(crate) reason: apple::Reason,
    pub(crate) prepared: Option<apple::Review>,
    /// Comparison only; native rechecks the exact retained Intent at Start.
    pub(crate) usable: bool,
    pub(crate) handed_off: bool,
}
impl Status {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if !(1..u32::MAX).contains(&self.revision)
            || self
                .prepared
                .as_ref()
                .is_some_and(|r| !r.valid() || r.mode != self.mode)
            || self.usable
                && (self.phase != Phase::Prepared
                    || self.handed_off
                    || self.reason != apple::Reason::None)
            || self.handed_off && self.phase != Phase::Prepared
        {
            return Err(Error::InvalidRequest);
        }
        let valid = match self.phase {
            Phase::Unknown => {
                self.settlement == Settlement::Unknown
                    && !self.usable
                    && !self.handed_off
                    && self.prepared.is_none()
                    && matches!(
                        self.reason,
                        apple::Reason::CleanupUnknown | apple::Reason::HistoryUnavailable
                    )
            }
            Phase::Prepared => {
                self.settlement == Settlement::Settled
                    && self.prepared.is_some()
                    && !matches!(
                        self.reason,
                        apple::Reason::CleanupUnknown | apple::Reason::HistoryUnavailable
                    )
            }
            Phase::Refused => {
                self.settlement == Settlement::Settled
                    && self.prepared.is_none()
                    && !self.usable
                    && !self.handed_off
                    && !matches!(
                        self.reason,
                        apple::Reason::None
                            | apple::Reason::CleanupUnknown
                            | apple::Reason::HistoryUnavailable
                    )
            }
            _ => {
                self.settlement == Settlement::Pending
                    && self.prepared.is_none()
                    && !self.usable
                    && !self.handed_off
                    && !matches!(
                        self.reason,
                        apple::Reason::CleanupUnknown | apple::Reason::HistoryUnavailable
                    )
            }
        };
        if !valid
            || serde_json::to_vec(self)
                .map_err(|_| Error::InvalidRequest)?
                .len()
                > apple::STATUS_LIMIT
        {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Access {
    pub(crate) service_instance: Option<Id>,
    pub(crate) project_id: Option<Id>,
    pub(crate) grant_id: Option<Id>,
    pub(crate) scope_id: Option<Id>,
    pub(crate) mode: Option<apple::Mode>,
    pub(crate) enabled: bool,
    pub(crate) remaining_ms: u64,
    pub(crate) status: Option<Status>,
}
impl Access {
    pub(crate) fn empty() -> Self {
        Self {
            service_instance: None,
            project_id: None,
            grant_id: None,
            scope_id: None,
            mode: None,
            enabled: false,
            remaining_ms: 0,
            status: None,
        }
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let all = self.service_instance.is_some()
            && self.project_id.is_some()
            && self.grant_id.is_some()
            && self.scope_id.is_some()
            && self.mode.is_some();
        let none = self.service_instance.is_none()
            && self.project_id.is_none()
            && self.grant_id.is_none()
            && self.scope_id.is_none()
            && self.mode.is_none();
        if !all && !none
            || !self.enabled && self.remaining_ms != 0
            || self.remaining_ms > apple::INTENT_MS
            || self.enabled != (all && self.status.is_none() && self.remaining_ms > 0)
            || self.status.as_ref().is_some_and(|s| {
                s.validate().is_err()
                    || Some(&s.origin.service_instance) != self.service_instance.as_ref()
                    || Some(&s.origin.project_id) != self.project_id.as_ref()
                    || Some(&s.grant_id) != self.grant_id.as_ref()
                    || Some(&s.scope_id) != self.scope_id.as_ref()
                    || Some(s.mode) != self.mode
            })
        {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prepare_wire_is_only_scalar_addresses_not_context_or_start_permission() {
        let q = serde_json::json!({"projectId":"1".repeat(32),"serviceInstance":"2".repeat(32),"requestId":"3".repeat(32)});
        let v = serde_json::json!({"origin":q,"grantId":"4".repeat(32),"scopeId":"5".repeat(32)});
        assert!(serde_json::from_value::<Submit>(v.clone()).is_ok());
        for key in [
            "mode",
            "context",
            "path",
            "recordId",
            "credential",
            "password",
            "reference",
            "consentVersion",
        ] {
            let mut bad = v.clone();
            bad[key] = serde_json::json!("forbidden");
            assert!(serde_json::from_value::<Submit>(bad).is_err());
        }
        assert!(Access::empty().validate().is_ok());
    }
}
