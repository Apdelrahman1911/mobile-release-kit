//! Exact CLI facet of the ORIGINAL release-project Initialization owner. No worker, source
//! reader, runtime selection, cleanup owner or synthetic main window lives here.
use super::agent_configuration::memory::initialization as memory;
use super::*;
use crate::{
    application_service::ApplicationService,
    application_service_host::NativeProject,
    asset_session::InitializationAgentGate,
    service_initialization_protocol as p,
    service_initialization_requests::{Entry, Kind},
    service_protocol::Id,
};
use std::sync::{OnceLock, Weak};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    Open,
    Opened,
    Prepare,
    Prepared,
    Apply,
    Terminal,
    Retired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Bound,
    Opening,
    Editing,
    Preparing,
    Reviewing,
    Applying,
    Finalizing,
    Returned,
}
fn successor(stage: Stage, step: Step) -> Option<Stage> {
    use Step as S;
    Some(match (stage, step) {
        (Stage::Bound, S::Open) => Stage::Opening,
        (Stage::Opening, S::Opened) => Stage::Editing,
        (Stage::Editing, S::Prepare) => Stage::Preparing,
        (Stage::Preparing, S::Prepared) => Stage::Reviewing,
        (Stage::Reviewing, S::Apply) => Stage::Applying,
        (Stage::Applying, S::Terminal) => Stage::Finalizing,
        (Stage::Finalizing, S::Retired) => Stage::Returned,
        _ => return None,
    })
}
struct Chain {
    epoch: u64,
    stage: Stage,
    pending: Option<(u64, u64, Step)>,
    failed: bool,
}
impl Chain {
    fn begin(&mut self, publisher: &RegistrationPublisher, step: Step) -> Result<(), BridgeError> {
        let usable = !self.failed
            && self.pending.is_none()
            && !publisher.accepted()
            && successor(self.stage, step).is_some();
        self.failed = true;
        if !usable || publisher.tool_source_epoch()? != self.epoch {
            return Err(invalid_owner());
        }
        self.pending = Some((self.epoch, publisher.reserved_version_serial()?, step));
        self.failed = false;
        Ok(())
    }
    fn accepted(
        &mut self,
        publisher: &RegistrationPublisher,
        step: Step,
    ) -> Result<(), BridgeError> {
        let usable = !self.failed && publisher.accepted();
        self.failed = true;
        let expected = self.epoch.checked_add(1).ok_or_else(edit_unknown)?;
        if !usable
            || self.pending != Some((self.epoch, publisher.reserved_version_serial()?, step))
            || publisher.tool_source_epoch()? != expected
        {
            return Err(invalid_owner());
        }
        self.stage = successor(self.stage, step).ok_or_else(invalid_owner)?;
        self.epoch = expected;
        self.pending = None;
        self.failed = false;
        Ok(())
    }
}
pub(crate) struct Link {
    pub(crate) entry: Arc<Entry>,
    owner: Weak<Inner>,
    service: Weak<ApplicationService>,
    gate: InitializationAgentGate,
    project: NativeProject,
    generation: Id,
    counters: (u32, u32),
    tooling: (String, String),
    marker: Arc<()>,
    session: OnceLock<Weak<Session>>,
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    native_code: OnceLock<Weak<Mutex<InstalledEditSlots>>>,
    chain: Mutex<Chain>,
}
impl Link {
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(super) fn bind_native_code(
        &self,
        original: &Arc<Mutex<InstalledEditSlots>>,
    ) -> Result<(), BridgeError> {
        if self.session.get().is_some() || self.native_code.get().is_some() {
            return Err(invalid_owner());
        }
        {
            let mut slots = original.try_lock().map_err(|_| invalid_owner())?;
            match &mut *slots {
                InstalledEditSlots::ProjectInitialization(slots) => slots
                    .bind_initialization_agent_inspection()
                    .map_err(|_| invalid_owner())?,
                _ => return Err(invalid_owner()),
            }
        }
        // Created from the exact original Arc before Session admission/arm.
        // Resources remains its sole retained strong owner. This alias cannot
        // be rebound and is never a receipt or authority to enter native code.
        self.native_code
            .set(Arc::downgrade(original))
            .map_err(|_| invalid_owner())
    }
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(super) fn native_code_retained_bytes(
        &self,
        active: &ActiveOwner,
    ) -> Result<usize, BridgeError> {
        if !self.active(active)
            || !active
                .session
                .agent_initialization
                .as_deref()
                .is_some_and(|link| std::ptr::eq(link, self))
        {
            return Err(invalid_owner());
        }
        native_code_bytes(self.native_code.get().ok_or_else(invalid_owner)?)
    }
    fn input_matches(&self, input: &initialization_wire::Open) -> bool {
        matches!(input,initialization_wire::Open::Initialize{project_id,draft_revision,baseline_generation,tooling_repository,tooling_sha,..}
            if project_id==&self.project.runtime_id&&(*draft_revision,*baseline_generation)==self.counters&&tooling_repository==&self.tooling.0&&tooling_sha==&self.tooling.1)
    }
    pub(crate) fn cleanup_poll_end(&self, end: Instant, now: Instant) -> Instant {
        end.min(now + Duration::from_millis(100))
    }
    fn chain(&self) -> Result<MutexGuard<'_, Chain>, BridgeError> {
        self.chain.lock().map_err(|_| {
            self.entry.unknown();
            edit_unknown()
        })
    }
    pub(crate) fn begin(
        &self,
        publisher: &RegistrationPublisher,
        step: Step,
    ) -> Result<(), BridgeError> {
        if !self.gate.same_publisher(publisher)
            || !self.entry.live(Instant::now())
            || self
                .service
                .upgrade()
                .is_none_or(|s| s.native_history_current().is_err())
        {
            return Err(invalid_owner());
        }
        self.chain()?.begin(publisher, step)
    }
    pub(crate) fn accepted(
        &self,
        publisher: &RegistrationPublisher,
        step: Step,
    ) -> Result<(), BridgeError> {
        if !self.gate.same_publisher(publisher) || !self.entry.live(Instant::now()) {
            return Err(invalid_owner());
        }
        self.chain()?.accepted(publisher, step)
    }
    fn publication(
        &self,
        publication: &mut EditPublication<'_>,
        step: Step,
    ) -> Result<(), BridgeError> {
        if let Some(p) = publication.owned.as_mut() {
            self.begin(p, step)?;
            p.accept(crate::android_registration_app_protocol::Reason::ContextChanged)?;
            self.accepted(p, step)
        } else if let Some(p) = publication.borrowed {
            let c = self.chain()?;
            let want = match step {
                Step::Open => Stage::Opening,
                Step::Prepare => Stage::Preparing,
                Step::Apply => Stage::Applying,
                _ => return Err(invalid_owner()),
            };
            if !self.gate.same_publisher(p)
                || !p.accepted()
                || c.failed
                || c.pending.is_some()
                || c.stage != want
                || p.tool_source_epoch()? != c.epoch
            {
                return Err(invalid_owner());
            }
            Ok(())
        } else {
            Err(invalid_owner())
        }
    }
    fn active(&self, a: &ActiveOwner) -> bool {
        a.session.domain == EditDomain::ProjectInitialization
            && a.projection
                .initialization
                .as_ref()
                .is_some_and(|d| d.intent == initialization_wire::Intent::Initialize)
            && a.projection.project_id == self.project.runtime_id
            && a.projection.owner_generation == self.generation.as_str()
            && self
                .session
                .get()
                .is_some_and(|s| s.as_ptr() == Arc::as_ptr(&a.session))
            && self
                .entry
                .bound(&a.session.id, &a.projection.owner_generation)
    }
    pub(crate) fn epoch_ready(
        &self,
        publisher: Option<&RegistrationPublisher>,
    ) -> Result<bool, BridgeError> {
        if !self.entry.live(Instant::now())
            || self
                .service
                .upgrade()
                .is_none_or(|s| s.native_history_current().is_err())
        {
            return Err(invalid_owner());
        }
        let c = self.chain()?;
        if c.failed {
            return Err(invalid_owner());
        }
        if c.pending.is_some() {
            return Ok(false);
        }
        let epoch = if let Some(p) = publisher {
            if !self.gate.same_publisher(p) {
                return Err(invalid_owner());
            }
            p.reserved_version_epoch()?
        } else {
            match self.gate.epoch() {
                Ok(v) => Some(v),
                Err(e) if e.code == "busy" => None,
                Err(e) => return Err(e),
            }
        };
        match epoch {
            None => Ok(false),
            Some(e) if e == c.epoch => Ok(true),
            _ => Err(invalid_owner()),
        }
    }
    pub(crate) fn document_current(
        &self,
        publisher: Option<&RegistrationPublisher>,
    ) -> Result<(), BridgeError> {
        if !self.epoch_ready(publisher)? {
            return Err(BridgeError::new(
                "busy",
                "Wait for the original initialization publication.",
            ));
        }
        self.gate.current(&self.project)
    }
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
fn native_code_bytes(original: &Weak<Mutex<InstalledEditSlots>>) -> Result<usize, BridgeError> {
    let original = original.upgrade().ok_or_else(invalid_owner)?;
    let slots = original.try_lock().map_err(|_| invalid_owner())?;
    match &*slots {
        InstalledEditSlots::ProjectInitialization(slots) => slots
            .initialization_agent_retained_bytes()
            .ok_or_else(invalid_owner),
        _ => Err(invalid_owner()),
    }
}
impl EditOwner {
    pub(crate) fn initialization_agent_link(
        &self,
        window: &str,
        entry: Arc<Entry>,
        service: &Arc<ApplicationService>,
        project: NativeProject,
        gate: InitializationAgentGate,
        input: &initialization_wire::Open,
    ) -> Result<Arc<Link>, BridgeError> {
        let r = self.inner.lock();
        self.inner
            .admission(&r, window, EditDomain::ProjectInitialization)?;
        if r.active.is_some()
            || !entry.admitting(Kind::Open)
            || entry.source.runtime_id != project.runtime_id
            || entry.source.root != project.canonical_root
            || entry.source.device != project.device
            || entry.source.inode != project.inode
            || service.native_history_current().is_err()
        {
            return Err(invalid_owner());
        }
        let initialization_wire::Open::Initialize {
            draft_revision,
            baseline_generation,
            tooling_repository,
            tooling_sha,
            ..
        } = input
        else {
            return Err(invalid_owner());
        };
        if !input.valid() {
            return Err(invalid_owner());
        }
        Ok(Arc::new(Link {
            counters: (*draft_revision, *baseline_generation),
            tooling: (tooling_repository.clone(), tooling_sha.clone()),
            entry,
            owner: Arc::downgrade(&self.inner),
            service: Arc::downgrade(service),
            gate,
            chain: Mutex::new(Chain {
                epoch: project.input_revision,
                stage: Stage::Bound,
                pending: None,
                failed: false,
            }),
            project,
            generation: Id::parse(&r.generation).map_err(|_| invalid_owner())?,
            marker: Arc::new(()),
            session: OnceLock::new(),
            #[cfg(all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            ))]
            native_code: OnceLock::new(),
        }))
    }
    pub(crate) fn initialization_agent_access(
        &self,
        window: &str,
        entry: &Arc<Entry>,
    ) -> Result<Arc<Link>, BridgeError> {
        let r = self.inner.lock();
        self.inner
            .admission(&r, window, EditDomain::ProjectInitialization)?;
        let a = r.active.as_ref().ok_or_else(invalid_owner)?;
        let link = a
            .session
            .agent_initialization
            .as_ref()
            .ok_or_else(invalid_owner)?;
        if !Arc::ptr_eq(&link.entry, entry)
            || !link.active(a)
            || a.unknown
            || a.cleanup_start.is_some()
            || a.terminal
            || !entry.live(Instant::now())
        {
            return Err(invalid_owner());
        }
        Ok(link.clone())
    }
    pub(crate) fn open_agent_initialization(
        &self,
        publisher: &RegistrationPublisher,
        window: &str,
        link: Arc<Link>,
        mut ticket: RegisteredOpenTicket,
        registration: RegisteredEditRoot,
    ) -> Result<InitializationStatus, BridgeError> {
        let input = ticket.initialization.as_ref().ok_or_else(invalid_owner)?;
        if !link.input_matches(input) || ticket.agent_initialization.is_some() {
            return Err(invalid_owner());
        }
        ticket.agent_initialization = Some(link.clone());
        self.open_initialization_published(
            publisher,
            window,
            link.project.runtime_id.clone(),
            registration,
            ticket,
        )
    }
    pub(crate) fn prepare_agent_initialization(
        &self,
        publisher: &RegistrationPublisher,
        window: &str,
        link: Arc<Link>,
        registration: RegisteredEditRoot,
    ) -> Result<InitializationStatus, BridgeError> {
        let original = link.entry.original().map_err(|_| invalid_owner())?;
        self.prepare_domain_initialization(
            Some(publisher),
            window,
            EditDomain::ProjectInitialization,
            original.session_id.as_str(),
            original.revision.as_str(),
            link.counters,
            json!({"revision":original.revision.as_str(),"intent":"initialize"}),
            Some(registration),
            Some(SavedTextSubmission::Initialization(
                initialization_wire::Intent::Initialize,
            )),
            None,
            None,
            None,
            None,
            None,
            Some(&link.entry),
        )?
        .initialization()
    }
    pub(crate) fn apply_agent_initialization(
        &self,
        publisher: &RegistrationPublisher,
        window: &str,
        link: Arc<Link>,
        registration: RegisteredEditRoot,
    ) -> Result<InitializationStatus, BridgeError> {
        let original = link.entry.original().map_err(|_| invalid_owner())?;
        let review = link.entry.review().map_err(|_| invalid_owner())?;
        self.apply_domain_initialization(
            Some(publisher),
            window,
            EditDomain::ProjectInitialization,
            original.session_id.as_str(),
            review.plan_token.as_str(),
            Some(registration),
            false,
            None,
            None,
            None,
            None,
            None,
            Some(&link.entry),
        )?
        .initialization()
    }
    fn initialization_agent_review(
        &self,
        window: &str,
        entry: &Arc<Entry>,
        args: &p::Allow,
    ) -> Result<Instant, BridgeError> {
        let r = self.inner.lock();
        self.inner
            .admission(&r, window, EditDomain::ProjectInitialization)?;
        let a = r.active.as_ref().ok_or_else(invalid_owner)?;
        let link = a
            .session
            .agent_initialization
            .as_ref()
            .ok_or_else(invalid_owner)?;
        if !Arc::ptr_eq(&link.entry, entry)
            || !link.active(a)
            || a.projection.phase != Phase::Reviewing
            || a.cleanup_start.is_some()
            || a.unknown
            || !a.prepared
            || r.revision != args.expected_native_status_revision
            || a.projection.plan_token() != Some(args.plan_token.as_str())
            || !link.epoch_ready(None)?
            || a.projection.revision() != Some(args.original.revision.as_str())
            || a.projection.owner_generation != args.original.owner_generation.as_str()
            || a.session.id != args.original.session_id.as_str()
        {
            return Err(invalid_owner());
        }
        Ok(a.review_end)
    }
    pub(crate) fn reserve_agent_initialization(
        &self,
        window: &str,
        entry: &Arc<Entry>,
        args: &p::Allow,
    ) -> Result<u32, BridgeError> {
        self.initialization_agent_review(window, entry, args)?;
        entry.reserve_allow(args).map_err(|_| invalid_owner())
    }
    pub(crate) fn allow_agent_initialization(
        &self,
        window: &str,
        entry: &Arc<Entry>,
        args: &p::Allow,
        ticket: u32,
    ) -> Result<(), BridgeError> {
        let end = self.initialization_agent_review(window, entry, args)?;
        entry.allow(ticket, end).map_err(|_| invalid_owner())
    }
    /// Called under the original Document admission guard BEFORE a losing GUI
    /// invocation could invalidate peers or enter a mismatched-token STOP tail.
    pub(crate) fn initialization_agent_origin(
        &self,
        window: &str,
        entry: Option<&Arc<Entry>>,
    ) -> Result<(), BridgeError> {
        let r = self.inner.lock();
        if r.window.as_deref() != Some(window) {
            return Err(invalid_owner());
        }
        match (
            r.active
                .as_ref()
                .and_then(|a| a.session.agent_initialization.as_ref()),
            entry,
        ) {
            (None, None) => Ok(()),
            (Some(l), Some(e)) if Arc::ptr_eq(&l.entry, e) => Ok(()),
            _ => Err(invalid_owner()),
        }
    }
    pub(crate) fn cancel_agent_initialization(
        &self,
        window: &str,
        entry: &Arc<Entry>,
        at: Instant,
    ) -> Result<(), BridgeError> {
        {
            let r = self.inner.lock();
            if r.window.as_deref() != Some(window) {
                return Err(invalid_owner());
            }
        }
        entry.cancel(at).map_err(|_| edit_unknown())?;
        let mut publication = self.inner.mandatory_publication();
        let result = (|| {
            let mut r = self.inner.lock();
            if r.window.as_deref() != Some(window) {
                return Err(invalid_owner());
            }
            if let Some(a) = r.active.as_ref().filter(|a| {
                a.session
                    .agent_initialization
                    .as_ref()
                    .is_some_and(|l| Arc::ptr_eq(&l.entry, entry) && l.active(a))
            }) {
                let id = a.session.id.clone();
                self.inner
                    .expire_locked(&mut publication, &mut r, &id, Instant::now());
            }
            Ok(())
        })();
        publication.finish();
        result
    }
    /// Signal the SAME installed Entry before the caller may wait for Host IO
    /// or a publication. This does not admit/replace a session, and the native
    /// watchdog observes its original minimum STOP even if that wait is long.
    pub(crate) fn signal_agent_initialization_cancel(
        &self,
        window: &str,
        origin: &p::Query,
        at: Instant,
    ) -> Result<(), BridgeError> {
        let entry = {
            let r = self.inner.lock();
            if r.window.as_deref() != Some(window) {
                return Err(invalid_owner());
            }
            r.active
                .as_ref()
                .and_then(|a| a.session.agent_initialization.as_ref())
                .filter(|link| &link.entry.input.origin == origin)
                .map(|link| link.entry.clone())
        };
        if let Some(entry) = entry {
            entry.cancel(at).map_err(|_| edit_unknown())?;
        }
        Ok(())
    }
    pub(crate) fn initialization_agent_relay_lost(&self, at: Instant) {
        let entry = self
            .inner
            .lock()
            .active
            .as_ref()
            .and_then(|a| a.session.agent_initialization.as_ref())
            .map(|link| link.entry.clone());
        if let Some(entry) = entry {
            let _ = entry.cancel(at);
        }
    }
}
pub(super) fn before_claim(
    inner: &Arc<Inner>,
    r: &Registry,
    session: &Session,
    project: &str,
    publication: &mut EditPublication<'_>,
) -> Result<(), BridgeError> {
    let Some(link) = &session.agent_initialization else {
        return Ok(());
    };
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    if link.native_code.get().is_none() {
        return Err(invalid_owner());
    }
    if session.domain != EditDomain::ProjectInitialization
        || link.owner.as_ptr() != Arc::as_ptr(inner)
        || r.generation != link.generation.as_str()
        || project != link.project.runtime_id
        || link.session.get().is_some()
        || !link.entry.admitting(Kind::Open)
    {
        return Err(invalid_owner());
    }
    link.publication(publication, Step::Open)?;
    link.entry.claim_open().map_err(|_| invalid_owner())
}
pub(super) fn linked(r: &Registry) -> Result<(), BridgeError> {
    let Some(a) = &r.active else { return Ok(()) };
    let Some(link) = &a.session.agent_initialization else {
        return Ok(());
    };
    if link.session.set(Arc::downgrade(&a.session)).is_err() {
        link.entry.unknown();
        return Err(edit_unknown());
    }
    link.entry
        .bind(
            Id::parse(&a.session.id).map_err(|_| edit_unknown())?,
            link.generation.clone(),
            Arc::downgrade(&link.marker),
            &a.session.wake,
        )
        .map_err(|_| {
            link.entry.unknown();
            edit_unknown()
        })
}
pub(super) fn consume(
    a: &ActiveOwner,
    entry: Option<&Arc<Entry>>,
    kind: Kind,
    publication: &mut EditPublication<'_>,
) -> bool {
    match (a.session.agent_initialization.as_ref(), entry) {
        (None, None) => true,
        (Some(link), Some(e)) => {
            Arc::ptr_eq(&link.entry, e)
                && link.active(a)
                && e.admitting(kind)
                && link
                    .publication(
                        publication,
                        if kind == Kind::Prepare {
                            Step::Prepare
                        } else {
                            Step::Apply
                        },
                    )
                    .is_ok()
                && e.consume(kind).is_ok()
        }
        _ => false,
    }
}
pub(super) fn cancellation_at(session: &Session, now: Instant) -> Option<(Instant, Reason)> {
    let link = session.agent_initialization.as_ref()?;
    match link.entry.stop_at(now) {
        Ok(Some(at)) => Some((at, Reason::Cancelled)),
        Err(_) => Some((now, Reason::CleanupUnknown)),
        Ok(None) => {
            if link
                .service
                .upgrade()
                .is_none_or(|s| s.native_history_current().is_err())
            {
                link.entry.unknown();
                return Some((now, Reason::CallerLost));
            }
            match link.epoch_ready(None) {
                Err(e) if e.code != "busy" => Some((now, Reason::CallerLost)),
                _ => None,
            }
        }
    }
}
pub(super) async fn wait_command(owner: &Session) -> Result<(), BridgeError> {
    let Some(link) = &owner.agent_initialization else {
        return Ok(());
    };
    loop {
        if *owner.stop.borrow() {
            return Err(invalid_owner());
        }
        match link.document_current(None) {
            Ok(()) => return Ok(()),
            Err(e) if e.code == "busy" => {}
            Err(e) => return Err(e),
        }
        // SAME original writer/watchdog. No new timer owner or renewed end.
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}
pub(super) fn preclaim(
    inner: &Inner,
    session: &str,
    entry: Option<&Arc<Entry>>,
    kind: Kind,
) -> Result<(), BridgeError> {
    let r = inner.lock();
    match (
        r.active
            .as_ref()
            .and_then(|a| a.session.agent_initialization.as_ref()),
        entry,
    ) {
        (None, None) => Ok(()),
        (Some(l), Some(e))
            if Arc::ptr_eq(&l.entry, e)
                && r.active
                    .as_ref()
                    .is_some_and(|a| l.active(a) && a.session.id == session)
                && e.admitting(kind) =>
        {
            Ok(())
        }
        _ => Err(invalid_owner()),
    }
}
pub(super) fn unknown(owner: &Session) {
    if let Some(l) = &owner.agent_initialization {
        l.entry.unknown();
    }
}
pub(super) fn frame(
    active: &ActiveOwner,
    frame: &ChildFrame,
    publication: &mut EditPublication<'_>,
) -> Result<(), BridgeError> {
    let Some(link) = &active.session.agent_initialization else {
        return Ok(());
    };
    memory::prospective(&active.projection, frame)?;
    let step = match frame {
        ChildFrame::InitializationOpened(initialization_wire::Opened::Initialize { .. }) => {
            Step::Opened
        }
        ChildFrame::InitializationPrepared(initialization_wire::PreparedReply::Initialize {
            view,
            ..
        }) => {
            if view.tooling.repository != link.tooling.0 || view.tooling.sha != link.tooling.1 {
                return Err(invalid_owner());
            }
            Step::Prepared
        }
        ChildFrame::InitializationTerminal(_, result)
            if result.intent() == initialization_wire::Intent::Initialize =>
        {
            let core = result.outcome();
            if !matches!(core.effect, Effect::Committed | Effect::Unchanged)
                || core.resources != ResourceState::Settled
            {
                return Ok(());
            }
            Step::Terminal
        }
        _ => return Err(invalid_owner()),
    };
    link.publication(publication, step)
}
fn review(pj: &EditProjection, revision: u32) -> Result<p::Review, BridgeError> {
    let Some(initialization_wire::Prepared::Initialize {
        plan_token,
        draft_revision,
        baseline_generation,
        view,
        ..
    }) = pj.initialization.as_ref().and_then(|d| d.prepared.as_ref())
    else {
        return Err(invalid_owner());
    };
    let count = |action| view.files.iter().filter(|f| f.action == action).count() as u32;
    let r = p::Review {
        plan_token: Id::parse(plan_token).map_err(|_| invalid_owner())?,
        native_status_revision: revision,
        draft_revision: *draft_revision,
        baseline_generation: *baseline_generation,
        file_count: view.files.len() as u32,
        created_files: count(initialization_wire::Action::Create),
        preserved_files: count(initialization_wire::Action::Preserve),
        appended_files: count(initialization_wire::Action::Append),
        created_directories: view.create_directories.len() as u32,
        tooling_repository: view.tooling.repository.clone(),
        tooling_sha: view.tooling.sha.clone(),
    };
    r.validate().map_err(|_| invalid_owner())?;
    Ok(r)
}
pub(super) fn changed(r: &Registry) {
    let Some(a) = &r.active else { return };
    let Some(link) = &a.session.agent_initialization else {
        return;
    };
    let result = (|| {
        if !link.active(a) {
            return Err(invalid_owner());
        }
        if a.unknown || a.projection.native_finality == NativeFinality::Unknown {
            link.entry.unknown();
            return Ok(());
        }
        let detail = a
            .projection
            .initialization
            .as_ref()
            .ok_or_else(invalid_owner)?;
        if detail.intent != initialization_wire::Intent::Initialize
            || detail.counters != link.counters
        {
            return Err(invalid_owner());
        }
        if let Some(initialization_wire::Checkout::Initialize { revision, .. }) = &detail.checkout {
            link.entry
                .opened(p::Original {
                    session_id: Id::parse(&a.session.id).map_err(|_| invalid_owner())?,
                    owner_generation: link.generation.clone(),
                    revision: Id::parse(revision).map_err(|_| invalid_owner())?,
                })
                .map_err(|_| invalid_owner())?;
        }
        if a.projection.phase == Phase::Reviewing {
            link.entry
                .prepared(review(&a.projection, r.revision)?)
                .map_err(|_| invalid_owner())?;
        }
        Ok(())
    })();
    if result.is_err() {
        link.entry.unknown();
    }
}
fn final_data(pj: &EditProjection, unknown: bool) -> Option<p::Final> {
    if unknown || pj.phase != Phase::Final || pj.native_finality != NativeFinality::Settled {
        return None;
    }
    known_outcome(pj)
}
fn known_outcome(pj: &EditProjection) -> Option<p::Final> {
    let core = pj.core_outcome.as_ref()?;
    if core.resources != ResourceState::Settled {
        return None;
    }
    let effect = match core.effect {
        Effect::NotStarted => p::Effect::NotStarted,
        Effect::Unchanged => p::Effect::Unchanged,
        Effect::RolledBack => p::Effect::RolledBack,
        Effect::Committed => p::Effect::Committed,
        Effect::Unknown => return None,
    };
    let journal = match core.journal {
        Journal::NotCreated => p::Journal::NotCreated,
        Journal::Clean => p::Journal::Clean,
        Journal::RecoveryRequired => p::Journal::RecoveryRequired,
        Journal::Unknown => return None,
    };
    Some(p::Final {
        effect,
        journal,
        cancelled: pj.native_reason != Reason::None,
        apply_submitted: pj.apply_submitted,
    })
}
fn fence_retirement(pj: &mut EditProjection, unknown: &mut bool, chain_current: bool) {
    if !chain_current && known_outcome(pj).as_ref().is_some_and(p::Final::saved) {
        // Original resource/core facts remain intact. What is lost is positive
        // attribution to the exact delegated preview, not a physical join.
        *unknown = true;
        if pj.native_reason == Reason::None {
            pj.native_reason = Reason::CallerLost;
        }
    }
}
pub(super) fn retirement_publication(
    active: &mut ActiveOwner,
    publication: &mut EditPublication<'_>,
) -> bool {
    let Some(link) = &active.session.agent_initialization else {
        return true;
    };
    // Failed/cancelled originals still retain their actual known native cleanup;
    // only a positive saved outcome needs the uninterrupted seven-step chain.
    let stopped = link
        .entry
        .stop_at(Instant::now())
        .is_ok_and(|v| v.is_some());
    let chain_current = !stopped && link.publication(publication, Step::Retired).is_ok();
    // Must precede native phase/finality, installed attribution and r.last/bump;
    // waiting for Entry::retired would leave an optimistic native event race.
    fence_retirement(&mut active.projection, &mut active.unknown, chain_current);
    chain_current
}
pub(super) fn retired(r: &Registry, owner: &Session, unknown: bool, chain_current: bool) {
    let Some(link) = &owner.agent_initialization else {
        return;
    };
    let Some(pj) = &r.last else {
        link.entry.unknown();
        return;
    };
    let mut result = final_data(pj, unknown);
    if result.as_ref().is_some_and(p::Final::saved) && !chain_current {
        result = None
    }
    if link.entry.retired(result).is_err() {
        link.entry.unknown()
    }
}

#[cfg(test)]
#[path = "edit_owner_service_initialization_tests.rs"]
mod tests;
