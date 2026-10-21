//! Delegation INSIDE the original ToolAcquisition child. Weak comparisons only;
//! the actual Prepared/Intent owns its source/census and the same worker jobs.
use super::*;
use crate::{
    service_protocol::Id, service_tool_setup_protocol as p, service_tool_setup_requests as req,
};
#[path = "saved_command_agent_tool_inspect.rs"]
pub(crate) mod inspect;
fn refused() -> BridgeError {
    wire::invalid()
}
pub(crate) struct Approval {
    owner: Weak<Inner>,
    intent: Weak<Intent>,
    context: wire::Context,
    registration: u32,
    root: RegisteredRoot,
    expires: Instant,
    review: p::Review,
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
    pub(crate) fn matches_root(&self, g: u32, r: &RegisteredRoot) -> bool {
        g == self.registration && *r == self.root
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(6 * std::mem::size_of::<usize>())?
            .checked_add(self.root.path.capacity())?
            .checked_add(self.context.project_id.capacity())?
            .checked_add(self.context.saved_config.sha256.capacity())?
            .checked_add(self.context.review.as_ref().map_or(0, |r| {
                r.operation_id.capacity()
                    + r.owner_generation.capacity()
                    + r.requirements_sha256.capacity()
            }))
    }
    fn matches(&self, owner: &Arc<Inner>, p: &Prepared) -> bool {
        self.owner.as_ptr() == Arc::as_ptr(owner)
            && self.matches_root(p.registration, &p.project)
            && p.expires == self.expires
            && p.projection.context == Context::ToolAcquisition(self.context.clone())
            && self.review.prepared.as_ref().is_some_and(|r| {
                p.projection.operation_id == r.operation_id.as_str()
                    && p.projection.owner_generation == r.owner_generation.as_str()
            })
            && p.tools
                .as_ref()
                .is_some_and(|i| self.intent.as_ptr() == Arc::as_ptr(i) && i.current())
    }
}
pub(crate) struct Binding {
    approval: Arc<Approval>,
    link: Arc<req::NativeLink>,
}
impl Binding {
    pub(crate) fn link(&self) -> &Arc<req::NativeLink> {
        &self.link
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        self.approval
            .retained_bytes()?
            .checked_add(std::mem::size_of::<Self>() + 4 * std::mem::size_of::<usize>())
    }
}
fn prepared_binding(p: &Prepared) -> Option<&Arc<Binding>> {
    p.tools.as_ref()?.agent.get()
}
fn session_binding(p: &Session) -> Option<&Arc<Binding>> {
    p.tools.intent.as_ref()?.agent.get()
}
pub(in crate::saved_command_owner) fn start_matches(
    p: &Prepared,
    e: Option<&Arc<req::Entry>>,
) -> bool {
    match (prepared_binding(p), e) {
        (None, None) => true,
        (Some(b), Some(e)) => {
            b.link.matches(e)
                && p.tools
                    .as_ref()
                    .is_some_and(|i| b.approval.intent.as_ptr() == Arc::as_ptr(i))
        }
        _ => false,
    }
}
pub(in crate::saved_command_owner) fn consume(
    p: &Prepared,
    e: Option<&Arc<req::Entry>>,
) -> Result<(), BridgeError> {
    match (prepared_binding(p), e) {
        (None, None) => Ok(()),
        (Some(b), Some(e)) => b.link.consume(e).map_err(|_| refused()),
        _ => Err(refused()),
    }
}
pub(in crate::saved_command_owner) fn stop_prepared(
    p: &Prepared,
    now: Instant,
) -> Option<(Reason, Instant)> {
    prepared_binding(p)?
        .link
        .stop_at(now)
        .map(|(r, t)| (native_reason(r), t))
}
pub(in crate::saved_command_owner) fn stop_at(
    p: &Session,
    now: Instant,
) -> Option<(Reason, Instant)> {
    session_binding(p)?
        .link
        .stop_at(now)
        .map(|(r, t)| (native_reason(r), t))
}
pub(in crate::saved_command_owner) fn poll(p: &Session) -> Option<Duration> {
    session_binding(p).map(|_| req::CONTROL_POLL)
}
pub(in crate::saved_command_owner) fn read_end(p: &Session) -> Option<Instant> {
    session_binding(p).map(|b| b.link.scope().read.end())
}
pub(in crate::saved_command_owner) fn attach_stop(
    p: &Prepared,
    s: &watch::Sender<bool>,
) -> Result<(), BridgeError> {
    if let Some(b) = prepared_binding(p) {
        b.link.scope().control.attach(s).map_err(|_| refused())?;
    }
    Ok(())
}
fn operation(p: &RunProjection) -> Option<p::Operation> {
    Some(p::Operation {
        operation_id: Id::parse(&p.operation_id).ok()?,
        owner_generation: Some(Id::parse(&p.owner_generation).ok()?),
        registration_generation: None,
    })
}
pub(in crate::saved_command_owner) fn entered(p: &Session) {
    if let Some(b) = session_binding(p) {
        match (Id::parse(&p.id), Id::parse(&p.generation)) {
            (Ok(id), Ok(g)) => b.link.entered(p::Operation {
                operation_id: id,
                owner_generation: Some(g),
                registration_generation: None,
            }),
            _ => b.link.unknown(),
        }
    }
}
fn native_reason(r: p::Reason) -> Reason {
    match r {
        p::Reason::Expired => Reason::IntentExpired,
        p::Reason::ContextChanged => Reason::ContextChanged,
        p::Reason::Shutdown => Reason::Shutdown,
        p::Reason::CleanupUnknown | p::Reason::HistoryUnavailable => Reason::CleanupUnknown,
        p::Reason::TimedOut => Reason::TimedOut,
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
        Reason::ContextChanged
        | Reason::DocumentLost
        | Reason::StaleIntent
        | Reason::SavedSourceChanged
        | Reason::SavedSourceInvalid => p::Reason::ContextChanged,
        Reason::Shutdown => p::Reason::Shutdown,
        Reason::IntentExpired => p::Reason::Expired,
        Reason::TimedOut => p::Reason::TimedOut,
        Reason::CleanupUnknown => p::Reason::CleanupUnknown,
        Reason::RuntimeUnavailable | Reason::ResourcesUnavailable => p::Reason::Unavailable,
        Reason::CommandFailed => p::Reason::CommandFailed,
        _ => p::Reason::NativeRefused,
    }
}
fn components(v: wire::components::Partition) -> Vec<p::Component> {
    [
        p::Component::Jdk,
        p::Component::AndroidPlatform,
        p::Component::AndroidBuildTools,
        p::Component::Gradle,
    ]
    .into_iter()
    .enumerate()
    .filter_map(|(i, c)| (!v.is_compatible(i)).then_some(c))
    .collect()
}
fn retired_projection(b: &Binding, p: &RunProjection) {
    if p.phase == Phase::Unknown
        || p.outcome == Some(Outcome::Unknown)
        || p.phase != Phase::Terminal
    {
        b.link.unknown();
        return;
    }
    let outcome = match p.outcome {
        Some(Outcome::Complete) => p::Outcome::Complete,
        Some(Outcome::Cancelled) => p::Outcome::Cancelled,
        Some(Outcome::Refused) => p::Outcome::Refused,
        Some(Outcome::TimedOut) => p::Outcome::TimedOut,
        Some(Outcome::Failed) => p::Outcome::Failed,
        _ => {
            b.link.unknown();
            return;
        }
    };
    let result = if outcome == p::Outcome::Complete {
        let Some(Terminal::ToolAcquisition(t)) = p.result.as_ref() else {
            b.link.unknown();
            return;
        };
        let partition = if b.approval.review.kind == p::Kind::AcquireMissing {
            // Acquire's terminal intentionally has no observer projection.
            // Borrow the SAME private original Inspection retained by Intent.
            b.approval
                .intent
                .upgrade()
                .and_then(|i| i.inspection.as_ref().and_then(|v| v.terminal.components()))
                .filter(|parts| {
                    t.result
                        .as_ref()
                        .is_some_and(|v| wire::staged_matches_partition(v, *parts))
                })
        } else {
            t.components()
        };
        let Some(partition) = partition else {
            b.link.unknown();
            return;
        };
        Some(match b.approval.review.kind {
            p::Kind::InspectRequirements => p::Report::InspectRequirements {
                missing: components(partition),
            },
            p::Kind::InspectSavedRequirements => p::Report::InspectSavedRequirements {
                missing: components(partition),
            },
            p::Kind::AcquireMissing => p::Report::AcquireMissing {
                staged: components(partition),
            },
            _ => {
                b.link.unknown();
                return;
            }
        })
    } else {
        None
    };
    b.link.publish(
        if b.link.has_entered() || b.approval.review.kind == p::Kind::InspectSavedRequirements {
            // The original Prepared retirement may precede Session/entered.
            // Its identity is comparison DATA, not a Start receipt.
            operation(p)
        } else {
            None
        },
        Some(outcome),
        reason(p.reason, b),
        result,
        true,
    );
}
pub(in crate::saved_command_owner) fn retired_prepared(p: &Prepared, r: Reason) {
    if let Some(b) = prepared_binding(p) {
        retired_projection(b, &retire(p.projection.clone(), r));
    }
}
pub(in crate::saved_command_owner) fn retired(a: &Active, disabled: bool) {
    if let Some(b) = session_binding(&a.owner) {
        if disabled || a.unknown || !original_joined(&a.owner) {
            b.link.unknown();
            return;
        }
        retired_projection(b, &a.projection);
    }
}
pub(in crate::saved_command_owner) fn changed(r: &super::super::Registry) {
    if let Some(a) = &r.active {
        if let Some(b) = session_binding(&a.owner) {
            if a.unknown || a.projection.phase == Phase::Unknown {
                b.link.unknown();
            }
        }
    }
}
impl SavedCommandOwner {
    pub(crate) fn tool_setup_acquisition_approval(
        &self,
        kind: p::Kind,
        ids: &p::Prepared,
    ) -> Result<Arc<Approval>, BridgeError> {
        self.require_domain(SavedCommandDomain::ToolAcquisition)?;
        let mut r = self.inner.lock();
        self.inner.expire_prepared(&mut r, Instant::now());
        if r.disabled
            || r.stopping
            || r.document_lost
            || self.inner.poisoned.load(Ordering::SeqCst)
            || r.revision != ids.status_revision
        {
            return Err(refused());
        }
        let prepared = r
            .prepared
            .as_ref()
            .filter(|p| {
                p.projection.intent_usable
                    && p.projection.phase == Phase::AwaitingConsent
                    && p.projection.operation_id == ids.operation_id.as_str()
                    && p.projection.owner_generation == ids.owner_generation.as_str()
            })
            .ok_or_else(refused)?;
        let Context::ToolAcquisition(c) = &prepared.projection.context else {
            return Err(refused());
        };
        if (c.action == wire::Action::Inspect && kind != p::Kind::InspectRequirements)
            || (c.action == wire::Action::Acquire && kind != p::Kind::AcquireMissing)
        {
            return Err(refused());
        }
        let intent = prepared
            .tools
            .as_ref()
            .filter(|i| i.agent.get().is_none() && i.current())
            .ok_or_else(refused)?;
        Ok(Arc::new(Approval {
            owner: Arc::downgrade(&self.inner),
            intent: Arc::downgrade(intent),
            context: c.clone(),
            registration: prepared.registration,
            root: prepared.project.clone(),
            expires: prepared.expires,
            review: p::Review {
                kind,
                platform: p::Platform::Android,
                draft_revision: c.draft_revision,
                baseline_generation: c.baseline_generation,
                prepared: Some(ids.clone()),
                sources: None,
            },
        }))
    }
    pub(crate) fn bind_tool_setup_acquisition(
        &self,
        a: Arc<Approval>,
        link: Arc<req::NativeLink>,
    ) -> Result<Arc<Binding>, BridgeError> {
        let mut r = self.inner.lock();
        self.inner.expire_prepared(&mut r, Instant::now());
        let p = r
            .prepared
            .as_ref()
            .filter(|p| {
                a.matches(&self.inner, p)
                    && r.revision == a.review.prepared.as_ref().map_or(0, |i| i.status_revision)
            })
            .ok_or_else(refused)?;
        if link.scope().review != a.review
            || link.scope().expires > a.expires
            || link.scope().current(false, Instant::now()).is_err()
        {
            return Err(refused());
        }
        let b = Arc::new(Binding { approval: a, link });
        p.tools
            .as_ref()
            .ok_or_else(refused)?
            .agent
            .set(b.clone())
            .map_err(|_| refused())?;
        Ok(b)
    }
    pub(crate) fn tool_setup_acquisition_current(&self, a: &Approval) -> bool {
        let r = self.inner.lock();
        !r.disabled
            && !r.stopping
            && !r.document_lost
            && !self.inner.poisoned.load(Ordering::SeqCst)
            && r.prepared
                .as_ref()
                .is_some_and(|p| a.matches(&self.inner, p))
    }
    pub(crate) fn stop_tool_setup_acquisition(&self, b: &Binding, why: p::Reason, at: Instant) {
        b.link.cancel(why, at);
        let mut r = self.inner.lock();
        if r.prepared
            .as_ref()
            .is_some_and(|p| prepared_binding(p).is_some_and(|v| std::ptr::eq(v.as_ref(), b)))
        {
            self.inner.retire_prepared(&mut r, native_reason(why));
        } else if let Some(o) = r
            .active
            .as_ref()
            .filter(|a| session_binding(&a.owner).is_some_and(|v| std::ptr::eq(v.as_ref(), b)))
            .map(|a| a.owner.clone())
        {
            self.inner.stop_locked(&mut r, &o, native_reason(why), at);
        } else if !b.link.scope().retired.load(Ordering::Acquire) {
            b.link.unknown();
        }
    }
}
