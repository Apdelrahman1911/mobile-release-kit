//! One immutable MAIN-approved draft, transferred to the actual diagnostics
//! Session. This is not a saved-file witness or an editor freshness claim.
use super::*;
use crate::{
    service_protocol::Id, service_tool_setup_protocol as p, service_tool_setup_requests as req,
};
use std::sync::Weak;
pub(crate) struct Approval {
    owner: Weak<Inner>,
    context: Context,
    registration: u32,
    root: PathBuf,
    expires: Instant,
    input: Mutex<Option<Start>>,
    input_bytes: usize,
    review: p::Review,
}
pub(crate) struct Binding {
    approval: Arc<Approval>,
    link: Arc<req::NativeLink>,
}
fn invalid() -> BridgeError {
    wire::invalid()
}
// Borrow-only census. serde_json currently uses BTreeMap without preserve_order:
// 1024 bytes per entry conservatively covers an underfilled node/edges, including
// single-entry maps; String/Vec capacities are added separately. No serialized
// length is treated as the Value's heap, and depth/node limits stay original.
fn heap(v: &Value, depth: usize, nodes: &mut usize) -> Option<usize> {
    *nodes = nodes.checked_add(1)?;
    if depth > crate::protocol::DEPTH_LIMIT || *nodes > crate::protocol::NODE_LIMIT {
        return None;
    }
    match v {
        Value::String(s) => Some(s.capacity()),
        Value::Array(a) => {
            let mut n = a.capacity().checked_mul(std::mem::size_of::<Value>())?;
            for v in a {
                n = n.checked_add(heap(v, depth + 1, nodes)?)?;
            }
            Some(n)
        }
        Value::Object(o) => {
            *nodes = nodes.checked_add(o.len())?;
            if *nodes > crate::protocol::NODE_LIMIT {
                return None;
            }
            let mut n = o.len().checked_mul(1024)?;
            for (k, v) in o {
                n = n
                    .checked_add(k.capacity())?
                    .checked_add(heap(v, depth + 1, nodes)?)?;
            }
            Some(n)
        }
        _ => Some(0),
    }
}
fn input_backing(input: &Start) -> Option<usize> {
    let typed = std::mem::size_of::<Start>()
        .checked_add(input.project_id.capacity())?
        .checked_add(heap(&input.draft, 0, &mut 0)?)?;
    typed.checked_mul(3)?.checked_add(3 * wire::REQUEST_LIMIT)
}
impl Approval {
    pub(crate) fn review(&self) -> &p::Review {
        &self.review
    }
    pub(crate) fn project(&self) -> &str {
        &self.context.project_id
    }
    pub(crate) fn expires(&self) -> Instant {
        self.expires
    }
    pub(crate) fn matches_root(&self, g: u32, r: &crate::asset_source::RegisteredRoot) -> bool {
        g == self.registration && r.path == self.root
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(4 * std::mem::size_of::<usize>())?
            .checked_add(self.root.capacity())?
            .checked_add(self.context.project_id.capacity())?
            .checked_add(self.input_bytes)
    }
}
impl Binding {
    pub(crate) fn link(&self) -> &Arc<req::NativeLink> {
        &self.link
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let base = std::mem::size_of::<Self>() + 4 * std::mem::size_of::<usize>();
        if self.link.scope().retired.load(Ordering::Acquire) {
            base.checked_add(std::mem::size_of::<Approval>())?
                .checked_add(self.approval.root.capacity())?
                .checked_add(self.approval.context.project_id.capacity())
        } else {
            base.checked_add(self.approval.retained_bytes()?)
        }
    }
    fn take(&self, e: &Arc<req::Entry>) -> Result<Start, BridgeError> {
        self.link.consume(e).map_err(|_| invalid())?;
        self.approval
            .input
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .take()
            .ok_or_else(invalid)
    }
}
impl EnvironmentDiagnosticsOwner {
    pub(crate) fn tool_setup_doctor_approval(
        &self,
        input: Start,
        g: u32,
        root: PathBuf,
        now: Instant,
    ) -> Result<Arc<Approval>, BridgeError> {
        crate::protocol::check_value(&input.draft)?;
        crate::edit_protocol::bounded(&input.draft, 512 * 1024)?;
        let context = input.context();
        let input_bytes = input_backing(&input).ok_or_else(invalid)?;
        let r = self.inner.lock();
        if self.inner.availability(&r, Availability::Available) != Availability::Available
            || r.agent
                .as_ref()
                .is_some_and(|b| !b.link.scope().retired.load(Ordering::Acquire))
        {
            return Err(busy());
        }
        let review = p::Review {
            kind: p::Kind::Doctor,
            platform: if context.platform == wire::Platform::Android {
                p::Platform::Android
            } else {
                p::Platform::Ios
            },
            draft_revision: context.draft_revision,
            baseline_generation: context.baseline_generation,
            prepared: None,
            sources: None,
            acquisition: None,
        };
        if !review.valid() || !root.is_absolute() {
            return Err(invalid());
        }
        // The quote survives transfer: original writer can hold this Value and
        // cloned request-building Value plus its encoded frame simultaneously.
        Ok(Arc::new(Approval {
            owner: Arc::downgrade(&self.inner),
            context,
            registration: g,
            root,
            expires: now + Duration::from_millis(p::INTENT_MS),
            input: Mutex::new(Some(input)),
            input_bytes,
            review,
        }))
    }
    pub(crate) fn tool_setup_doctor_current(&self, a: &Approval) -> bool {
        let r = self.inner.lock();
        a.owner.as_ptr() == Arc::as_ptr(&self.inner)
            && Instant::now() < a.expires
            && self.inner.availability(&r, Availability::Available) == Availability::Available
            && a.input.lock().is_ok_and(|v| v.is_some())
    }
    pub(crate) fn bind_tool_setup_doctor(
        &self,
        a: Arc<Approval>,
        link: Arc<req::NativeLink>,
    ) -> Result<Arc<Binding>, BridgeError> {
        if !self.tool_setup_doctor_current(&a)
            || link.scope().review != a.review
            || link.scope().expires > a.expires
            || link.scope().current(false, Instant::now()).is_err()
        {
            return Err(invalid());
        }
        let mut r = self.inner.lock();
        if r.active.is_some()
            || r.agent
                .as_ref()
                .is_some_and(|b| !b.link.scope().retired.load(Ordering::Acquire))
        {
            return Err(busy());
        }
        let b = Arc::new(Binding { approval: a, link });
        r.agent = Some(b.clone());
        Ok(b)
    }
    pub(crate) fn tool_setup_doctor_input(
        &self,
        b: &Arc<Binding>,
        e: &Arc<req::Entry>,
    ) -> Result<(Ticket, Start), BridgeError> {
        {
            let r = self.inner.lock();
            if !r.agent.as_ref().is_some_and(|old| Arc::ptr_eq(old, b)) {
                return Err(invalid());
            }
        }
        let input = b.take(e)?;
        let mut ticket = self.ticket_at(e.submitted_at())?;
        ticket.agent = Some(b.clone());
        Ok((ticket, input))
    }
    pub(crate) fn stop_tool_setup_doctor(&self, b: &Binding, reason: p::Reason, at: Instant) {
        b.link.cancel(reason, at);
        let mut r = self.inner.lock();
        if let Some(o) = r
            .active
            .as_ref()
            .filter(|a| {
                a.owner
                    .agent
                    .as_ref()
                    .is_some_and(|old| std::ptr::eq(old.as_ref(), b))
            })
            .map(|a| a.owner.clone())
        {
            self.inner
                .stop_locked(&mut r, &o, native_reason(reason), at);
        } else if r
            .agent
            .as_ref()
            .is_some_and(|old| std::ptr::eq(old.as_ref(), b))
            && b.link.unentered_caller_returned()
        {
            // Actual same admission caller has returned before this path. No
            // IO/task exists before Registry.active; dropping a Ticket is not a
            // claim about a spawned worker. Any poisoned registry stays Unknown.
            if self.inner.poisoned.load(Ordering::SeqCst) {
                b.link.unknown();
                return;
            }
            match b.approval.input.lock() {
                Ok(mut input) => {
                    input.take();
                    b.link.refused_unentered(reason)
                }
                Err(_) => b.link.unknown(),
            }
        } else if b.link.has_entered() && !b.link.scope().retired.load(Ordering::Acquire) {
            b.link.unknown();
        }
    }
}

#[cfg(test)]
impl EnvironmentDiagnosticsOwner {
    // Numeric representation test only: no Approval, Binding, Ticket, native
    // availability, source lease or permission is constructed by this method.
    pub(crate) fn tool_setup_doctor_allocation_data(
        input: &Start,
        root: &PathBuf,
    ) -> Option<usize> {
        input_backing(input)?
            .checked_add(std::mem::size_of::<Approval>() + std::mem::size_of::<Binding>())?
            .checked_add(8 * std::mem::size_of::<usize>())?
            .checked_add(root.capacity())?
            .checked_add(input.project_id.capacity())
    }
}
fn native_reason(r: p::Reason) -> Reason {
    match r {
        p::Reason::ContextChanged => Reason::ContextChanged,
        p::Reason::Shutdown => Reason::Shutdown,
        p::Reason::TimedOut => Reason::TimedOut,
        p::Reason::CleanupUnknown | p::Reason::HistoryUnavailable => Reason::CleanupUnknown,
        _ => Reason::Cancelled,
    }
}
fn reason(r: Reason, b: &Binding) -> p::Reason {
    match r {
        Reason::None => p::Reason::None,
        Reason::Cancelled => b
            .link
            .scope()
            .control
            .first()
            .ok()
            .flatten()
            .map_or(p::Reason::UserCancelled, |(r, _)| r),
        Reason::ContextChanged | Reason::DocumentLost => p::Reason::ContextChanged,
        Reason::Shutdown => p::Reason::Shutdown,
        Reason::TimedOut => p::Reason::TimedOut,
        Reason::RuntimeUnavailable => p::Reason::Unavailable,
        Reason::CleanupUnknown => p::Reason::CleanupUnknown,
        _ => p::Reason::CommandFailed,
    }
}
pub(super) fn start_matches(
    r: &Registry,
    t: &Ticket,
    input: &Start,
    g: u32,
    root: &PathBuf,
) -> bool {
    match (&r.agent, &t.agent) {
        (None, None) => true,
        (Some(b), None) => b.link.scope().retired.load(Ordering::Acquire),
        (Some(b), Some(t)) => {
            Arc::ptr_eq(b, t)
                && b.approval.registration == g
                && b.approval.root == *root
                && b.approval.context == input.context()
                && b.link.scope().current(false, Instant::now()).is_ok()
        }
        _ => false,
    }
}
pub(super) fn entered(o: &Session) {
    if let Some(b) = &o.agent {
        if b.link.scope().control.attach(&o.stop).is_err() {
            b.link.unknown();
            return;
        }
        match (Id::parse(&o.id), Id::parse(&o.generation)) {
            (Ok(id), Ok(g)) => b.link.entered(p::Operation {
                operation_id: id,
                owner_generation: Some(g),
                registration_generation: None,
            }),
            _ => b.link.unknown(),
        }
    }
}
pub(super) fn advance(o: &Session, at: Instant) -> Option<(Reason, Instant)> {
    o.agent
        .as_ref()?
        .link
        .stop_at(at)
        .map(|(r, t)| (native_reason(r), t))
}
/// Same original wait, not a grant timer/task. Ignore already-observed past
/// expiry when selecting a quantum; advance imports its exact timestamp.
pub(super) fn wait_end(o: &Session, end: Option<Instant>) -> Option<Instant> {
    let end = end?;
    let Some(b) = &o.agent else {
        return Some(end);
    };
    let now = Instant::now();
    let mut next = end.min(now + req::CONTROL_POLL);
    let read = b.link.scope().read.end();
    if read > now {
        next = next.min(read);
    }
    Some(next)
}
pub(super) fn changed(r: &Registry) {
    if let Some(a) = &r.active {
        if a.unknown {
            if let Some(b) = &a.owner.agent {
                b.link.unknown();
            }
        }
    }
}
pub(super) fn retired(a: &Active) {
    let Some(b) = &a.owner.agent else {
        return;
    };
    let p = &a.projection;
    if a.unknown || p.phase != Phase::Settled || p.finality != Finality::Settled {
        b.link.unknown();
        return;
    }
    let out = match p.outcome {
        Some(Outcome::Complete) => p::Outcome::Complete,
        Some(Outcome::Cancelled) => p::Outcome::Cancelled,
        Some(Outcome::TimedOut) => p::Outcome::TimedOut,
        Some(Outcome::Unavailable) => p::Outcome::Refused,
        Some(Outcome::Partial | Outcome::Failed) => p::Outcome::Failed,
        None => {
            b.link.unknown();
            return;
        }
    };
    let result = if out == p::Outcome::Complete {
        let Some(t) = &p.result else {
            b.link.unknown();
            return;
        };
        Some(p::Report::Doctor {
            checks: t.tool_setup_summary(),
        })
    } else {
        None
    };
    let (Ok(id), Ok(g)) = (Id::parse(&a.owner.id), Id::parse(&a.owner.generation)) else {
        b.link.unknown();
        return;
    };
    b.link.publish(
        Some(p::Operation {
            operation_id: id,
            owner_generation: Some(g),
            registration_generation: None,
        }),
        Some(out),
        reason(p.reason, b),
        result,
        true,
    );
}

#[cfg(test)]
#[path = "environment_diagnostics_agent_tests.rs"]
mod tests;
