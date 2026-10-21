//! Activity facet of the SAME Entry, row, claim and history-return cut.
use super::*;
pub(super) fn snapshot_for(
    review: &p::Review,
    reason: p::Reason,
    snapshot: Option<&p::activity::Snapshot>,
) -> bool {
    match (review, snapshot) {
        (p::Review::ActivityOverview(reference), Some(s)) => {
            reason == p::Reason::None && s.valid() && s.matches(reference)
        }
        (p::Review::ActivityOverview(_), None) => reason != p::Reason::None,
        (_, None) => true,
        _ => false,
    }
}
impl Entry {
    /// T is the original Submit, before waiting in this same inbox. The grant's
    /// admission-only expiry does not restart work or the credential clock.
    pub(crate) fn activity_end(
        &self,
        credential_end: Instant,
        now: Instant,
    ) -> Result<Instant, Error> {
        if self.scope.review.kind() != p::Kind::ActivityOverview {
            return Err(Error::Conflict);
        }
        self.current(false)?;
        let end = self
            .submitted
            .checked_add(std::time::Duration::from_secs(60))
            .ok_or(Error::StateUnknown)?
            .min(self.scope.read.end())
            .min(credential_end);
        if now >= end {
            return Err(Error::AccessDenied);
        }
        Ok(end)
    }
    /// Invoked ONLY at the tail of the original Connection's Activity accept.
    /// The native caller already compacted borrowed validated DATA; the original row mutex
    /// publishes it with the native fact. Caller/history are still separate.
    pub(crate) fn activity_returned(
        &self,
        id: &str,
        mut reason: p::Reason,
        snapshot: Option<p::activity::Snapshot>,
    ) {
        if reason == p::Reason::None {
            match self.first() {
                Ok(Some((why, _))) => reason = why,
                Ok(None) => {}
                Err(_) => {
                    self.unknown(p::Reason::CleanupUnknown);
                    return;
                }
            }
        }
        let snapshot = if reason == p::Reason::None {
            match snapshot {
                Some(s) => Some(Arc::new(s)),
                None => {
                    reason = p::Reason::NativeRefused;
                    None
                }
            }
        } else {
            None
        };
        self.returned_native_snapshot(id, reason, p::Effect::None, snapshot)
    }
}

#[cfg(test)]
#[path = "service_github_activity_requests_tests.rs"]
mod tests;
