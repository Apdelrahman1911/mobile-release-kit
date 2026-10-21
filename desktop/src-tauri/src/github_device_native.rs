//! Finite DATA bookkeeping used by the original device registration, NOT a
//! receipt. Native worker/runtime/HTTP retirement is checked separately.
use crate::{
    error::BridgeError,
    github_device_protocol::{self as wire, Phase, Reason},
};
use std::time::{Duration, Instant};
pub(crate) struct Clock {
    pub(crate) hard: Instant,
    pub(crate) end: Instant,
    pub(crate) cleanup: Option<Instant>,
    pub(crate) first: Option<Instant>,
    pub(crate) interval: u32,
    pub(crate) next: Instant,
    pub(crate) polls: u32,
}
impl Clock {
    pub(crate) fn new(now: Instant) -> Option<Self> {
        let hard = now.checked_add(Duration::from_secs(600))?;
        Some(Self {
            hard,
            end: hard.checked_sub(Duration::from_secs(10))?,
            cleanup: None,
            first: None,
            interval: 5,
            next: now,
            polls: 0,
        })
    }
    pub(crate) fn code(
        &mut self,
        admitted: Instant,
        returned: Instant,
        expires: u32,
        interval: u32,
    ) -> Result<(), BridgeError> {
        if self.first.is_some()
            || self.polls != 0
            || !(1..=900).contains(&expires)
            || !(5..=900).contains(&interval)
        {
            return Err(BridgeError::protocol());
        }
        self.end = self.end.min(
            admitted
                .checked_add(Duration::from_secs(u64::from(expires)))
                .ok_or_else(BridgeError::timeout)?,
        );
        self.interval = interval;
        self.next = returned
            .checked_add(Duration::from_secs(u64::from(interval)))
            .ok_or_else(BridgeError::timeout)?;
        if returned >= self.end {
            return Err(BridgeError::timeout());
        }
        Ok(())
    }
    pub(crate) fn poll(&mut self, now: Instant) -> Result<u32, BridgeError> {
        if self.first.is_some() || now < self.next || self.polls >= 120 {
            return Err(BridgeError::new(
                "device_wait",
                "Wait before checking the same device code.",
            ));
        }
        if now
            .checked_add(Duration::from_secs(24))
            .is_none_or(|end| end > self.end)
        {
            return Err(BridgeError::timeout());
        }
        self.polls += 1;
        Ok(self.polls)
    }
    pub(crate) fn pending(&mut self, now: Instant, slow: bool) -> Result<(), BridgeError> {
        if self.first.is_some() || now >= self.end {
            return Err(BridgeError::timeout());
        }
        if slow {
            self.interval = self
                .interval
                .checked_add(5)
                .ok_or_else(BridgeError::timeout)?;
        }
        self.next = now
            .checked_add(Duration::from_secs(u64::from(self.interval)))
            .ok_or_else(BridgeError::timeout)?;
        Ok(())
    }
    pub(crate) fn fail(&mut self, at: Instant) {
        self.first = Some(self.first.map_or(at, |old| old.min(at)));
        let end = at
            .checked_add(Duration::from_secs(10))
            .unwrap_or(self.hard)
            .min(self.hard);
        self.cleanup = Some(self.cleanup.map_or(end, |old| old.min(end)));
    }
    pub(crate) fn handoff(&self, now: Instant) -> bool {
        self.first.is_none()
            && now
                .checked_add(Duration::from_secs(12))
                .is_some_and(|end| end <= self.end)
    }
    pub(crate) fn code_view(&self, user: &str, now: Instant) -> wire::Code {
        wire::Code {
            user_code: user.into(),
            verification_uri: wire::VERIFY,
            remaining_seconds: self.end.saturating_duration_since(now).as_secs().min(600) as u32,
            check_after_seconds: self
                .next
                .saturating_duration_since(now)
                .as_millis()
                .div_ceil(1000)
                .min(1500) as u32,
        }
    }
}
pub(crate) fn public_reason(error: &BridgeError) -> Reason {
    match error.code.as_str() {
        "device_unconfigured" => Reason::PublisherUnconfigured,
        "runtime_unavailable" => Reason::RuntimeUnavailable,
        "device_stale" => Reason::TargetChanged,
        "busy" => Reason::Busy,
        "device_wait" => Reason::Waiting,
        "cancelled" | "shutting_down" => Reason::Cancelled,
        "query_timeout" => Reason::Expired,
        "cleanup_unknown" => Reason::CleanupUnknown,
        "unavailable" => Reason::RuntimeUnavailable,
        _ => Reason::ResponseInvalid,
    }
}
pub(crate) fn terminal(phase: Phase) -> bool {
    matches!(
        phase,
        Phase::Settled | Phase::Failed | Phase::CleanupUnknown
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_slow_down_retains_original_expiry_without_first_failure() {
        let now = Instant::now();
        let mut c = Clock::new(now).unwrap();
        c.code(now, now + Duration::from_secs(1), 60, 5).unwrap();
        let end = c.end;
        assert!(c.poll(now + Duration::from_secs(5)).is_err());
        assert_eq!(c.poll(now + Duration::from_secs(6)).unwrap(), 1);
        c.pending(now + Duration::from_secs(7), true).unwrap();
        assert_eq!(c.interval, 10);
        assert!(c.first.is_none());
        assert_eq!(c.end, end);
        assert!(c.poll(now + Duration::from_secs(16)).is_err());
        assert_eq!(c.poll(now + Duration::from_secs(17)).unwrap(), 2);
        assert!(c.poll(now + Duration::from_secs(37)).is_err());
        assert!(c.handoff(now + Duration::from_secs(48)));
        assert!(!c.handoff(now + Duration::from_secs(49)));
    }
    #[test]
    fn original_first_failure_and_hard_ceiling_cannot_renew_on_status_or_stop() {
        let now = Instant::now();
        let mut c = Clock::new(now).unwrap();
        c.fail(now + Duration::from_secs(5));
        let end = c.cleanup;
        c.fail(now + Duration::from_secs(50));
        assert_eq!(c.cleanup, end);
        assert!(!c.handoff(now));
        assert!(c.pending(now, false).is_err());
        assert!(c.poll(now + Duration::from_secs(100)).is_err());
    }
}
