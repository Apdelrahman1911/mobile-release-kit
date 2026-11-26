//! A foreground claim in the SAME GitHub Book32. No native owner or new queue.
use super::*;

impl NativeScope {
    /// The original Control may latch this while holding a native currentness
    /// guard. No Entry/Doc/Host/Owner callback is made from that inner cut.
    pub(crate) fn enrollment_unknown(&self) {
        self.failed.store(true, Ordering::Release);
        self.changes.send_modify(|_| {});
    }
}

impl Inbox {
    pub(crate) fn claim_enrollment(
        &self,
        query: &p::Query,
        document: &Arc<()>,
        runtime: &str,
        kind: p::Kind,
        review_id: Option<&str>,
    ) -> Result<Claim, Error> {
        if !kind.enrollment_family() {
            return Err(Error::InvalidRequest);
        }
        let book = self.lock()?;
        if book.closed || query.service_instance != self.instance {
            return Err(Error::Unavailable);
        }
        let entry = book
            .entries
            .iter()
            .find(|e| e.origin() == query)
            .ok_or(Error::Conflict)?;
        let same_input = match &entry.scope.review {
            p::Review::CounterEnrollmentReview(_) => review_id.is_none(),
            p::Review::CounterEnrollmentConnect(value) => {
                review_id == Some(value.review_id.as_str())
            }
            _ => false,
        };
        if !same_input
            || entry.scope.review.kind() != kind
            || entry.scope.runtime_id != runtime
            || entry
                .scope
                .document
                .upgrade()
                .is_none_or(|d| !Arc::ptr_eq(&d, document))
            || !book.lease.as_ref().is_some_and(|lease| {
                Arc::ptr_eq(&lease.scope, &entry.scope)
                    && lease
                        .entry
                        .as_ref()
                        .and_then(Weak::upgrade)
                        .is_some_and(|e| Arc::ptr_eq(&e, entry))
            })
        {
            return Err(Error::AccessDenied);
        }
        entry.scope.current(false)?;
        let mut row = entry.lock()?;
        if row.claimed
            || row.entered
            || row.operation.is_some()
            || row.fact.is_some()
            || row.unknown.is_some()
        {
            return Err(Error::Conflict);
        }
        row.claimed = true;
        entry.change(&mut row)?;
        Ok(Claim {
            entry: entry.clone(),
            returned: false,
        })
    }
}

impl Entry {
    /// Attachment and operation ID are written only by the actual Lane install
    /// cut, not by public status or by an Err classification in the RAW wrapper.
    pub(crate) fn enrollment_attached(&self, operation: &str) -> Result<(), Error> {
        if !self.scope.review.kind().enrollment_family() {
            return Err(Error::InvalidRequest);
        }
        self.entering()?;
        self.arm(operation)
    }

    pub(crate) fn enrollment_has_attachment(&self) -> bool {
        self.lock().is_ok_and(|r| r.entered)
    }

    /// The old permission may be withdrawn after ALL three real returns. This
    /// does not use its expired/revoked scope as a fresh authority and does not
    /// infer completion from the current native phase.
    pub(crate) fn enrollment_retired(&self, operation: &str) -> bool {
        self.scope.review.kind().enrollment_family()
            && self.lock().is_ok_and(|r| {
                Self::ended(&r)
                    && !self.scope.failed.load(Ordering::Acquire)
                    && r.operation.as_deref() == Some(operation)
                    && r.fact
                        .as_ref()
                        .is_some_and(|f| f.admission == Admission::Returned)
            })
    }

    pub(crate) fn enrollment_returned(
        &self,
        operation: &str,
        mut reason: p::Reason,
        mut effect: p::Effect,
        mut result: Option<p::enrollment::Snapshot>,
    ) {
        if !self.scope.review.kind().enrollment_family() {
            self.unknown(p::Reason::CleanupUnknown);
            return;
        }
        if reason == p::Reason::None {
            match self.first() {
                Ok(Some((why, _))) => {
                    reason = why;
                    result = None;
                    if effect == p::Effect::LocalMappingObserved {
                        effect = p::Effect::PotentiallyApplied;
                    }
                }
                Ok(None) => {}
                Err(_) => {
                    self.unknown(p::Reason::CleanupUnknown);
                    return;
                }
            }
        }
        let value = result
            .map(p::dispatch::Snapshot::Enrollment)
            .map(dispatch::Snapshot::Dispatch)
            .map(Arc::new);
        self.returned_native_value(operation, reason, effect, value);
    }
}

#[cfg(test)]
#[path = "service_counter_enrollment_tests.rs"]
mod tests;
