//! A producer receipt is a query over the SAME native/caller/history facts.
//! It is NOT the consumed scope's currentness, a synthetic consent or new owner.
use super::*;
pub(super) enum Snapshot {
    Activity(p::activity::Snapshot),
    Dispatch(p::dispatch::Snapshot),
}
impl Entry {
    pub(crate) fn positively_returned(&self, operation: &str) -> bool {
        self.lock().is_ok_and(|r| {
            Self::ended(&r)
                && !self.scope.failed.load(Ordering::Acquire)
                && r.operation.as_deref() == Some(operation)
                && r.fact.as_ref().is_some_and(|f| {
                    f.admission == Admission::Returned && f.reason == p::Reason::None
                })
        })
    }
    /// Called only after actual original Connection acceptance/control/retirement.
    /// A compact result cannot finish the relay or its independent history write.
    pub(crate) fn dispatch_returned(
        &self,
        id: &str,
        mut reason: p::Reason,
        effect: p::Effect,
        result: Option<p::dispatch::Snapshot>,
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
        let result = if reason == p::Reason::None {
            result.map(Snapshot::Dispatch).map(Arc::new)
        } else {
            None
        };
        self.returned_native_value(id, reason, effect, result)
    }
}
pub(super) fn valid(review: &p::Review, reason: p::Reason, snapshot: Option<&Snapshot>) -> bool {
    match snapshot {
        Some(Snapshot::Activity(s)) => activity::snapshot_for(review, reason, Some(s)),
        Some(Snapshot::Dispatch(p::dispatch::Snapshot::Enrollment(s))) => s.valid_for(review.kind())
            && (s.phase != p::enrollment::Phase::Refused) == (reason == p::Reason::None)
            && !matches!(reason, p::Reason::CleanupUnknown | p::Reason::HistoryUnavailable),
        Some(Snapshot::Dispatch(s)) => reason == p::Reason::None && s.valid_for(review.kind()),
        None => {
            activity::snapshot_for(review, reason, None)
                && (reason != p::Reason::None || !p::dispatch::requires_result(review.kind()))
        }
    }
}
#[cfg(test)]
#[path = "service_github_dispatch_requests_tests.rs"]
mod tests;

impl NativeScope {
    // Requests remains CLI-safe. Native MAIN adds its own actual ABI cells and
    // bounded captures to this complete unused-scope term, not a new Doc debit.
    pub(crate) fn unused_main_backing() -> Option<usize> {
        memory::unused_scope_bytes()
    }
}
