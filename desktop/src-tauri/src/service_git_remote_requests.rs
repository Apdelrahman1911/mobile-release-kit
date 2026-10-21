//! Remote-only completion cuts inside the SAME Row/Lease/NativeLink. A native
//! receipt is not the selected Connection's return, and neither is the relay
//! invocation returning. All three originals must return before Ready/finality.
//! No callback below touches Doc, Store, a runtime, network or filesystem.
use super::*;
use crate::service_git_remote_protocol as remote;

pub(super) struct Retirement {
    phase: Phase,
    caller_returned: bool,
    native: Option<OperationState>,
    connection_returned: bool,
    withdrawn: bool,
    candidate: Option<(shared::Reviewed, Instant)>,
    pending_result: Option<remote::Outcome>,
    result: Option<remote::Outcome>,
    published: bool,
}
impl Retirement {
    pub(super) fn new() -> Self {
        Self {
            phase: Phase::Prepare,
            caller_returned: false,
            native: None,
            connection_returned: false,
            withdrawn: false,
            candidate: None,
            pending_result: None,
            result: None,
            published: false,
        }
    }
}
pub(super) fn armed(row: &mut Row, phase: Phase) -> Result<(), Error> {
    let Some(r) = &mut row.remote else {
        return Ok(());
    };
    if phase == Phase::Apply {
        if r.phase != Phase::Prepare
            || !r.published
            || !r.caller_returned
            || !r.connection_returned
            || r.native != Some(OperationState::Succeeded)
        {
            return Err(Error::StateUnknown);
        }
        *r = Retirement {
            phase: Phase::Apply,
            ..Retirement::new()
        };
    } else if r.native.is_some() || r.connection_returned || r.caller_returned {
        return Err(Error::StateUnknown);
    }
    Ok(())
}

// Called with only the original Row mutex. In particular no finish callback or
// Doc re-entry hides here. Every native fact was recorded by its own caller.
fn publish(row: &mut Row) -> Result<(), Error> {
    if row.status.state == p::State::Unknown || ended(row) {
        return Ok(());
    }
    let Some(r) = &mut row.remote else {
        return Ok(());
    };
    let Some(native) = r.native else {
        return Ok(());
    };
    if !r.caller_returned || !r.connection_returned || row.claimed.is_some() {
        return Ok(());
    }
    if r.phase == Phase::Prepare && native == OperationState::Succeeded {
        let now = Instant::now();
        let unavailable = r.withdrawn
            || row.stop.is_some()
            || row.lease.as_ref().is_none_or(|l| !l.live(now))
            || r.candidate.as_ref().is_none_or(|(_, end)| now >= *end);
        if unavailable {
            r.candidate = None;
            let reason = row.stop.map_or(
                if r.withdrawn {
                    p::Reason::ContextChanged
                } else {
                    p::Reason::Expired
                },
                |s| s.0,
            );
            row.status.reason = Some(reason);
            let (state, outcome) = stopped_state(reason);
            return close(row, state, outcome);
        }
        if !r.published {
            let (review, end) = r.candidate.as_ref().ok_or(Error::StateUnknown)?;
            row.review = Some((review.clone(), *end));
            row.status.review = Some(review.clone());
            row.status.state = p::State::Prepared;
            r.published = true;
            change(row)?;
        }
        return Ok(());
    }
    if r.published {
        return Ok(());
    }
    r.published = true;
    r.candidate = None;
    r.result = r.pending_result.take();
    if native == OperationState::RecoveryRequired {
        row.status.reason = Some(p::Reason::RecoveryRequired);
    }
    close(row, p::State::Finished, native)
}

pub(super) fn retired(link: &NativeLink, native: OperationState) -> bool {
    if !link.is_remote() {
        return false;
    }
    let result = (|| {
        let mut row = link.entry.lock()?;
        if row.status.state == p::State::Unknown {
            return Ok(());
        }
        if !link.armed.load(Ordering::Acquire) {
            return Err(Error::StateUnknown);
        }
        let r = row.remote.as_mut().ok_or(Error::StateUnknown)?;
        if r.phase != link.phase || r.native.is_some() {
            return Err(Error::StateUnknown);
        }
        r.native = Some(native);
        if link.phase == Phase::Prepare {
            if row.prepare_joined {
                return Err(Error::StateUnknown);
            }
            row.prepare_joined = true;
        } else {
            if row.apply_joined {
                return Err(Error::StateUnknown);
            }
            row.apply_joined = true;
        }
        publish(&mut row)
    })();
    if result.is_err() {
        link.entry.unknown();
    }
    true
}
pub(super) fn review_removed(link: &NativeLink) -> bool {
    if !link.is_remote() {
        return false;
    }
    let result = (|| {
        let mut row = link.entry.lock()?;
        row.review = None;
        row.status.review = None;
        let r = row.remote.as_mut().ok_or(Error::StateUnknown)?;
        if r.phase == Phase::Prepare {
            r.withdrawn = true;
            r.candidate = None;
        }
        // Dropping the consumed Prepare review during an armed Apply cannot
        // retire that different original phase or invent its Connection return.
        publish(&mut row)
    })();
    if result.is_err() {
        link.entry.unknown();
    }
    true
}
pub(super) fn caller_returned(row: &mut Row, phase: Phase) -> Result<(), Error> {
    let Some(r) = &mut row.remote else {
        return Ok(());
    };
    if r.phase == phase {
        r.caller_returned = true;
    }
    // An exact unarmed Apply refusal may close its already-returned Prepare;
    // an armed Apply has reset the phase and requires its own three returns.
    publish(row)
}

impl NativeLink {
    pub(crate) fn is_remote(&self) -> bool {
        self.entry.family == Family::Remote
    }
    /// Sole production caller: GitLocal::reconcile, AFTER same-ticket
    /// Connection.finish returned AND same Doc knownness was checked. This
    /// method cannot call finish, create a review, or settle an unjoined owner.
    /// True means retain that SAME private ReadyReview, not public permission:
    /// a still-pending original claim keeps the inbox Preparing.
    pub(crate) fn remote_connection_returned(
        &self,
        candidate: Option<(remote::Review, Instant)>,
        result: Option<remote::Outcome>,
    ) -> Result<bool, Error> {
        if !self.is_remote() || !self.armed.load(Ordering::Acquire) {
            return Err(Error::StateUnknown);
        }
        let mut row = self.entry.lock()?;
        if row.status.state == p::State::Unknown {
            return Ok(false);
        }
        let shared::Summary::Remote(selection) = &row.status.selection else {
            return Err(Error::StateUnknown);
        };
        if candidate.as_ref().is_some_and(|(r, _)| {
            self.phase != Phase::Prepare
                || !r.matches(selection)
                || r.review_id.strip_suffix("-review") != row.status.prepare_operation_id.as_deref()
                || r.document_revision != self.lease.scope.document_revision
                || r.registration_generation != self.lease.scope.registration
        }) || result.as_ref().is_some_and(|r| {
            self.phase != Phase::Apply
                || !r.valid()
                || r.action != selection.action.kind()
                || row.status.apply_operation_id.as_deref() != Some(r.operation_id.as_str())
        }) {
            return Err(Error::StateUnknown);
        }
        let stop = row.stop.is_some();
        let lease_live = self.lease.live(Instant::now());
        let r = row.remote.as_mut().ok_or(Error::StateUnknown)?;
        if r.phase != self.phase || r.native.is_none() || r.connection_returned {
            return Err(Error::StateUnknown);
        }
        // Record the irreversible return before any later comparison/refusal.
        r.connection_returned = true;
        if result.as_ref().is_some_and(|v| {
            r.native
                != Some(match v.state {
                    remote::EffectState::Succeeded => OperationState::Succeeded,
                    remote::EffectState::Failed => OperationState::Failed,
                    remote::EffectState::RecoveryRequired => OperationState::RecoveryRequired,
                })
        }) {
            return Err(Error::StateUnknown);
        }
        if self.phase == Phase::Apply
            && r.native == Some(OperationState::Succeeded)
            && result.is_none()
        {
            return Err(Error::StateUnknown);
        }
        r.pending_result = result;
        let keep = self.phase == Phase::Prepare
            && r.native == Some(OperationState::Succeeded)
            && !r.withdrawn
            && !stop
            && lease_live
            && candidate
                .as_ref()
                .is_some_and(|(_, end)| Instant::now() < *end);
        if keep {
            r.candidate = candidate.map(|(r, end)| (r.into(), end));
        } else {
            r.withdrawn = true;
            r.candidate = None;
        }
        publish(&mut row)?;
        Ok(keep && row.status.settlement != Settlement::Settled)
    }
}
impl Entry {
    fn remote_status(&self) -> Result<remote::Status, Error> {
        self.expire(Instant::now());
        let row = self.lock()?;
        let mut status = row.status.clone();
        status.history_available = !row.history_failed && row.history_ack == Some(status.revision);
        let result = if status.settlement == Settlement::Settled {
            row.remote.as_ref().and_then(|r| r.result.clone())
        } else {
            None
        };
        status.remote(result)
    }
}
impl Inbox {
    pub(crate) fn allow_remote(&self, scope: Arc<NativeScope>) -> Result<remote::Access, Error> {
        self.allow_for(scope, Family::Remote)?.remote()
    }
    pub(crate) fn remote_access(&self) -> Result<remote::Access, Error> {
        let book = self.lock()?;
        access(&book, None, Family::Remote)?.remote()
    }
    pub(crate) fn revoke_remote(&self) -> Result<remote::Access, Error> {
        self.revoke_for(Family::Remote)?.remote()
    }
    pub(crate) fn remote_scope(&self, project: &Id) -> Result<remote::Scope, Error> {
        let book = self.lock()?;
        let value = remote::Scope {
            service_instance: self.instance.clone(),
            project_id: project.clone(),
            access: access(&book, Some(project), Family::Remote)?.remote()?,
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn prepare_remote(&self, input: remote::Prepare) -> Result<remote::Status, Error> {
        self.prepare_for(input.clone(), Family::Remote)?;
        let book = self.lock()?;
        self.find(&book, &input.origin, Family::Remote)?
            .remote_status()
    }
    pub(crate) fn start_remote(&self, input: &remote::Start) -> Result<remote::Status, Error> {
        let book = self.lock()?;
        let entry = self.find(&book, &input.origin, Family::Remote)?;
        entry.request_start(input)?;
        entry.remote_status()
    }
    pub(crate) fn query_remote(
        &self,
        input: &remote::Query,
        cancel: bool,
    ) -> Result<remote::Status, Error> {
        let book = self.lock()?;
        let entry = self.find(&book, input, Family::Remote)?;
        if cancel {
            entry.cancel(p::Reason::UserCancelled, Instant::now());
        }
        entry.remote_status()
    }
}

#[cfg(test)]
#[path = "service_git_remote_requests_tests.rs"]
mod tests;
