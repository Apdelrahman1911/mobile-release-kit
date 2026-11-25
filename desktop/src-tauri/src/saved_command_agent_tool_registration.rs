//! Delegation comparison on the SAME picked-source registration owner. Allow
//! captures NO Snapshot/cohort/worker; Register lends the actual private Review.
use super::*;
use crate::{
    service_protocol::Id, service_tool_setup_protocol as p, service_tool_setup_requests as req,
};
pub(crate) struct Approval {
    owner: Weak<Inner>,
    document: Weak<()>,
    request: Request,
    registration: u32,
    root: RegisteredRoot,
    roots: [RegisteredRoot; 3],
    pickers: [Weak<crate::asset_session::OriginalWork>; 3],
    saved: crate::asset_session::ToolDelegationSavedWitness,
    reviewed: Option<Weak<Review>>,
    expires: Instant,
    review: p::Review,
}
pub(crate) struct Binding {
    approval: Arc<Approval>,
    link: Arc<req::NativeLink>,
}
impl Approval {
    pub(crate) fn review(&self) -> &p::Review {
        &self.review
    }
    pub(crate) fn context(&self) -> &android_wire::Prepare {
        self.request.context()
    }
    pub(crate) fn project(&self) -> &str {
        &self.context().project_id
    }
    pub(crate) fn expires(&self) -> Instant {
        self.expires
    }
    pub(crate) fn matches_root(&self, g: u32, r: &RegisteredRoot) -> bool {
        g == self.registration && *r == self.root
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let b = std::mem::size_of::<Self>()
            .checked_add(12 * std::mem::size_of::<usize>())?
            .checked_add(self.root.path.capacity())?
            .checked_add(self.request.retained_heap_bytes()?)?;
        self.roots
            .iter()
            .try_fold(b, |b, r| b.checked_add(r.path.capacity()))
    }
    fn source_matches(&self, s: &SourceSnapshot) -> bool {
        s.registration == self.registration
            && s.project == self.root
            && s.project_id == self.project()
            && s.generation == self.request.source_generation()
            && s.roots() == &self.roots
            && self
                .pickers
                .iter()
                .zip(s.picker_originals())
                .all(|(a, b)| a.as_ptr() == Arc::as_ptr(b))
    }
    fn current(
        &self,
        inner: &Arc<Inner>,
        registry: &super::super::Registry,
        saved: &crate::asset_session::ValidatedSavedInput,
        now: Instant,
    ) -> bool {
        if self.owner.as_ptr() != Arc::as_ptr(inner)
            || now >= self.expires
            || !self.saved.matches(saved)
            || registry.android_registration.generation != self.request.generation()
        {
            return false;
        }
        let Some(source) = registry.android_sources.snapshot() else {
            return false;
        };
        if !self.source_matches(&source) {
            return false;
        }
        match (&self.request, &self.reviewed) {
            (Request::Inspect(_), None) => true,
            (Request::Register(i), Some(before)) => registry
                .android_registration
                .same_review(i, &source, now)
                .is_some_and(|now| before.as_ptr() == Arc::as_ptr(&now)),
            _ => false,
        }
    }
}
impl Binding {
    pub(crate) fn context(&self) -> &android_wire::Prepare {
        self.approval.context()
    }
    pub(crate) fn link(&self) -> &Arc<req::NativeLink> {
        &self.link
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        self.approval
            .retained_bytes()?
            .checked_add(std::mem::size_of::<Self>() + 4 * std::mem::size_of::<usize>())
    }
}
impl SavedCommandOwner {
    pub(crate) fn tool_setup_registration_approval(
        &self,
        document: &Arc<()>,
        kind: p::Kind,
        ids: &p::Sources,
        context: android_wire::Prepare,
        g: u32,
        root: RegisteredRoot,
        saved: &crate::asset_session::ValidatedSavedInput,
        now: Instant,
        gate: android_wire::Availability,
    ) -> Result<Arc<Approval>, BridgeError> {
        let request = match kind {
            p::Kind::InspectPickedSources if ids.review_id.is_none() => {
                Request::Inspect(wire::Inspect {
                    registration_generation: ids.registration_generation,
                    source_generation: ids.source_generation,
                    context,
                })
            }
            p::Kind::RegisterReviewedSources => Request::Register(wire::Register {
                registration_generation: ids.registration_generation,
                source_generation: ids.source_generation,
                review_id: ids
                    .review_id
                    .as_ref()
                    .ok_or_else(wire::invalid)?
                    .as_str()
                    .into(),
                context,
            }),
            _ => return Err(wire::invalid()),
        };
        let registry = self.inner.lock();
        if self.registration_gate(&registry, Availability::from_android(gate))
            != Availability::Available
            || !self.inner.android_original_document_matches(Some(document))
            || registry
                .android_registration
                .agent
                .as_ref()
                .is_some_and(|b| !b.link.scope().retired.load(Ordering::Acquire))
        {
            return Err(wire::unavailable());
        }
        let source = registry
            .android_sources
            .snapshot()
            .ok_or_else(wire::unavailable)?;
        if source.registration != g
            || source.project != root
            || source.project_id != request.context().project_id
            || source.generation != ids.source_generation
            || registry.android_registration.generation != ids.registration_generation
            || !saved.matches(document, g, &root, request.context())
        {
            return Err(wire::invalid());
        }
        let reviewed = match &request {
            Request::Inspect(_) => None,
            Request::Register(i) => Some(
                registry
                    .android_registration
                    .same_review(i, &source, now)
                    .ok_or_else(wire::invalid)?,
            ),
        };
        let expires = reviewed
            .as_ref()
            .map_or(now + REVIEW, |r| r.expires.min(now + REVIEW));
        let review = p::Review {
            kind,
            platform: p::Platform::Android,
            draft_revision: request.context().draft_revision,
            baseline_generation: request.context().baseline_generation,
            prepared: None,
            sources: Some(ids.clone()),
            acquisition: None,
        };
        if !review.valid() {
            return Err(wire::invalid());
        }
        Ok(Arc::new(Approval {
            owner: Arc::downgrade(&self.inner),
            document: Arc::downgrade(document),
            request,
            registration: g,
            root,
            roots: source.roots().clone(),
            pickers: std::array::from_fn(|i| Arc::downgrade(&source.picker_originals()[i])),
            saved: saved.tool_delegation_witness(),
            reviewed: reviewed.as_ref().map(Arc::downgrade),
            expires,
            review,
        }))
    }
    pub(crate) fn bind_tool_setup_registration(
        &self,
        a: Arc<Approval>,
        link: Arc<req::NativeLink>,
        saved: &crate::asset_session::ValidatedSavedInput,
    ) -> Result<Arc<Binding>, BridgeError> {
        let mut r = self.inner.lock();
        if !a.current(&self.inner, &r, saved, Instant::now())
            || link.scope().review != a.review
            || link.scope().expires > a.expires
            || link.scope().current(false, Instant::now()).is_err()
            || r.android_registration
                .agent
                .as_ref()
                .is_some_and(|b| !b.link.scope().retired.load(Ordering::Acquire))
        {
            return Err(wire::invalid());
        }
        let b = Arc::new(Binding { approval: a, link });
        r.android_registration.agent = Some(b.clone());
        Ok(b)
    }
    pub(crate) fn tool_setup_registration_snapshot(
        &self,
        b: &Binding,
        e: &Arc<req::Entry>,
        document: &Arc<()>,
        g: u32,
        root: RegisteredRoot,
        saved: crate::asset_session::ValidatedSavedInput,
        gate: android_wire::Availability,
    ) -> Result<Snapshot, BridgeError> {
        b.link.consume(e).map_err(|_| wire::invalid())?;
        self.registration_snapshot_agent(
            document,
            e.submitted_at(),
            match &b.approval.request {
                Request::Inspect(i) => Request::Inspect(i.clone()),
                Request::Register(i) => Request::Register(i.clone()),
            },
            g,
            root,
            saved,
            gate,
            Some(b),
        )
    }
    pub(crate) fn stop_tool_setup_registration(&self, b: &Binding, why: p::Reason, at: Instant) {
        b.link.cancel(why, at);
        let r = self.inner.lock();
        if let Some(o) = r.android_registration.active.as_ref().filter(|o| {
            o.control
                .agent
                .as_ref()
                .is_some_and(|l| Arc::ptr_eq(l, &b.link))
        }) {
            o.control.stop_at(native_reason(why), at);
        } else if r
            .android_registration
            .agent
            .as_ref()
            .is_some_and(|old| std::ptr::eq(old.as_ref(), b))
            && b.link.unentered_caller_returned()
        {
            // Actual Snapshot/Checked/admission caller has returned. The SAME
            // cohort book must show no unresolved admission or entered control.
            let slot = &self.inner.android_registration_control;
            let Ok(book) = slot.book.try_lock() else {
                return;
            };
            if !slot.is_unknown()
                && !self.inner.poisoned.load(Ordering::SeqCst)
                && book.admission.is_none()
                && book.original.is_none()
                && book.cohort.is_none()
            {
                b.link.refused_unentered(why);
            } else if slot.is_unknown() || self.inner.poisoned.load(Ordering::SeqCst) {
                b.link.unknown();
            }
        } else if b.link.has_entered() && !b.link.scope().retired.load(Ordering::Acquire) {
            b.link.unknown();
        }
    }
}
pub(super) fn admission_binding(
    inner: &Arc<Inner>,
    r: &super::super::Registry,
    b: Option<&Binding>,
    saved: &crate::asset_session::ValidatedSavedInput,
    request: &Request,
) -> Result<Option<Arc<req::NativeLink>>, BridgeError> {
    match (r.android_registration.agent.as_ref(), b) {
        (None, None) => Ok(None),
        (Some(old), None) if old.link.scope().retired.load(Ordering::Acquire) => Ok(None),
        (Some(old), Some(b))
            if std::ptr::eq(old.as_ref(), b)
                && b.approval.current(inner, r, saved, Instant::now())
                && request.context() == b.approval.context()
                && request.generation() == b.approval.request.generation()
                && request.source_generation() == b.approval.request.source_generation()
                && b.link.scope().current(false, Instant::now()).is_ok() =>
        {
            Ok(Some(b.link.clone()))
        }
        _ => Err(wire::invalid()),
    }
}
pub(super) fn current_checked(
    inner: &Arc<Inner>,
    r: &super::super::Registry,
    s: &Snapshot,
    current: &crate::asset_session::ValidatedSavedInput,
) -> bool {
    match (&s.agent, r.android_registration.agent.as_ref()) {
        (None, None) => true,
        (None, Some(b)) => b.link.scope().retired.load(Ordering::Acquire),
        (Some(link), Some(b)) => {
            Arc::ptr_eq(link, &b.link)
                && b.approval.current(inner, r, current, Instant::now())
                && link.scope().current(false, Instant::now()).is_ok()
        }
        _ => false,
    }
}
fn native_reason(r: p::Reason) -> wire::Reason {
    match r {
        p::Reason::CleanupUnknown | p::Reason::HistoryUnavailable => wire::Reason::CleanupUnknown,
        p::Reason::TimedOut => wire::Reason::TimedOut,
        p::Reason::ContextChanged => wire::Reason::ContextChanged,
        _ => wire::Reason::Cancelled,
    }
}
pub(super) fn advance(c: &Control, at: Instant) {
    if let Some(l) = &c.agent {
        if let Some((r, t)) = l.stop_at(at) {
            c.stop_at(native_reason(r), t);
            if matches!(r, p::Reason::CleanupUnknown | p::Reason::HistoryUnavailable) {
                c.mark_unknown(t);
            }
        }
    }
}
pub(super) fn wait_end(c: &Control, end: Instant) -> Instant {
    if let Some(l) = &c.agent {
        let now = Instant::now();
        let mut end = end.min(now + req::CONTROL_POLL);
        let read = l.scope().read.end();
        if read > now {
            end = end.min(read);
        }
        end
    } else {
        end
    }
}
pub(super) fn entered(o: &Operation) {
    if let Some(l) = &o.control.agent {
        if l.scope().control.attach(&o.control.stop).is_err() {
            l.unknown();
            return;
        }
        match Id::parse(&o.data.operation_id) {
            Ok(id) => l.entered(p::Operation {
                operation_id: id,
                owner_generation: None,
                registration_generation: Some(o.data.registration_generation),
            }),
            Err(_) => l.unknown(),
        }
    }
}
pub(super) fn unknown(c: &Control) {
    if let Some(l) = &c.agent {
        if !l.scope().retired.load(Ordering::Acquire) {
            l.unknown();
        }
    }
}
fn sources(s: &[wire::Source]) -> Vec<p::Source> {
    s.iter()
        .map(|s| p::Source {
            role: match s.role {
                crate::android_tool_sources::Role::Jdk => p::Role::Jdk,
                crate::android_tool_sources::Role::Sdk => p::Role::Sdk,
                crate::android_tool_sources::Role::Gradle => p::Role::Gradle,
            },
            logical_bytes: s.logical_bytes,
            files: s.files,
            entries: s.entries,
            aliases: s.aliases,
            complete: s.complete,
            compatible: s.compatibility == wire::Compatibility::Compatible,
        })
        .collect()
}
// ONLY after known_return, real joined_at, actual Review/Last publication,
// accepted=true and the original control/cohort have been retired together.
pub(super) fn retired(r: &Registration, o: &Operation) {
    let Some(l) = &o.control.agent else {
        return;
    };
    if !o.accepted.load(Ordering::SeqCst)
        || !o.known_return()
        || o.control.unknown.load(Ordering::SeqCst)
    {
        l.unknown();
        return;
    }
    let (out, reason, result) = if let Some(review) = r
        .review
        .as_ref()
        .filter(|v| std::ptr::eq(v.original.as_ref(), o))
    {
        (
            p::Outcome::Complete,
            p::Reason::None,
            Some(p::Report::InspectPickedSources {
                sources: sources(&review.public.sources),
            }),
        )
    } else if let Some(last) = r.last.as_ref().filter(|v| v.data == o.data) {
        let reason = match last.reason {
            wire::Reason::None => p::Reason::None,
            wire::Reason::Cancelled => l
                .scope()
                .control
                .first()
                .ok()
                .flatten()
                .map_or(p::Reason::UserCancelled, |(r, _)| r),
            wire::Reason::TimedOut => p::Reason::TimedOut,
            wire::Reason::ContextChanged => p::Reason::ContextChanged,
            wire::Reason::CleanupUnknown => {
                l.unknown();
                return;
            }
            _ => p::Reason::NativeRefused,
        };
        match last.phase {
            wire::Phase::Complete => {
                let Some(report) = &last.report else {
                    l.unknown();
                    return;
                };
                (
                    p::Outcome::Complete,
                    reason,
                    Some(p::Report::RegisterReviewedSources {
                        copy: match report.protected_copy {
                            wire::ProtectedCopy::NotCreated => p::CopyState::NotCreated,
                            wire::ProtectedCopy::Published => p::CopyState::Published,
                            wire::ProtectedCopy::RetainedPartial => p::CopyState::RetainedPartial,
                        },
                        sources: sources(&report.sources),
                    }),
                )
            }
            wire::Phase::Cancelled => (p::Outcome::Cancelled, reason, None),
            wire::Phase::Refused => (p::Outcome::Refused, reason, None),
            _ => {
                l.unknown();
                return;
            }
        }
    } else {
        l.unknown();
        return;
    };
    let Ok(id) = Id::parse(&o.data.operation_id) else {
        l.unknown();
        return;
    };
    l.publish(
        Some(p::Operation {
            operation_id: id,
            owner_generation: None,
            registration_generation: Some(o.data.registration_generation),
        }),
        Some(out),
        reason,
        result,
        true,
    );
}

#[cfg(test)]
#[path = "saved_command_agent_tool_registration_tests.rs"]
mod tests;
