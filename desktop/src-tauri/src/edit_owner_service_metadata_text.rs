//! Exact CLI proposal facet of the ORIGINAL Config owner. No worker, source
//! reader, runtime selection, cleanup owner or synthetic main window lives here.
use super::agent_configuration::memory;
use super::*;
use crate::{
    application_service::ApplicationService,
    application_service_host::NativeProject,
    asset_session::MetadataTextAgentGate,
    service_metadata_text_protocol as p,
    service_metadata_text_requests::{Entry, Kind},
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
    gate: MetadataTextAgentGate,
    project: NativeProject,
    generation: Id,
    marker: Arc<()>,
    session: OnceLock<Weak<Session>>,
    chain: Mutex<Chain>,
}
impl Link {
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
        a.session.domain == EditDomain::MetadataText
            && !a.session.saved_text_recovery
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
                "Wait for the original metadata_text publication.",
            ));
        }
        self.gate.current(&self.project)
    }
}
impl EditOwner {
    pub(crate) fn metadata_text_agent_link(
        &self,
        window: &str,
        entry: Arc<Entry>,
        service: &Arc<ApplicationService>,
        project: NativeProject,
        gate: MetadataTextAgentGate,
    ) -> Result<Arc<Link>, BridgeError> {
        let r = self.inner.lock();
        self.inner.admission(&r, window, EditDomain::MetadataText)?;
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
        Ok(Arc::new(Link {
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
        }))
    }
    pub(crate) fn metadata_text_agent_access(
        &self,
        window: &str,
        entry: &Arc<Entry>,
    ) -> Result<Arc<Link>, BridgeError> {
        let r = self.inner.lock();
        self.inner.admission(&r, window, EditDomain::MetadataText)?;
        let a = r.active.as_ref().ok_or_else(invalid_owner)?;
        let link = a
            .session
            .agent_metadata_text
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
    pub(crate) fn open_agent_metadata_text(
        &self,
        publisher: &RegistrationPublisher,
        window: &str,
        link: Arc<Link>,
        registration: RegisteredEditRoot,
    ) -> Result<MetadataTextEditStatus, BridgeError> {
        let mut ticket = self.metadata_text_open_ticket(window)?;
        ticket.agent_metadata_text = Some(link.clone());
        let context = metadata_wire::Context {
            platform: platform(link.entry.input().platform),
            locale: link.entry.input().locale.clone(),
        };
        self.open_domain(
            Some(publisher),
            window,
            link.project.runtime_id.clone(),
            registration.root.path.clone(),
            EditDomain::MetadataText,
            Some(registration),
            Some(ticket),
            Some(context),
            None,
        )?
        .metadata_text()
    }
    pub(crate) fn prepare_agent_metadata_text(
        &self,
        publisher: &RegistrationPublisher,
        window: &str,
        link: Arc<Link>,
        registration: RegisteredEditRoot,
    ) -> Result<MetadataTextEditStatus, BridgeError> {
        let original = link.entry.original().map_err(|_| invalid_owner())?;
        let proposal = link.entry.proposal().map_err(|_| invalid_owner())?;
        let (baseline, fields) = {
            let r = self.inner.lock();
            let a = r
                .active
                .as_ref()
                .filter(|a| link.active(a))
                .ok_or_else(invalid_owner)?;
            let checkout = a
                .projection
                .metadata_text
                .as_ref()
                .and_then(|m| m.checkout.as_ref())
                .ok_or_else(invalid_owner)?;
            if a.projection.phase != Phase::Editing
                || checkout.revision != original.revision.as_str()
            {
                return Err(invalid_owner());
            }
            check_baseline(&link.entry, &checkout.metadata_root, &checkout.baseline)?;
            let bytes =
                p::encoded(&proposal.fields, p::STDIN_BYTES).map_err(|_| invalid_owner())?;
            let fields: Vec<metadata_wire::TextField> =
                serde_json::from_slice(&bytes).map_err(|_| invalid_owner())?;
            (checkout.baseline.clone(), fields)
        };
        let params = json!({"revision":original.revision.as_str(),"expectedBaseline":&baseline,"fields":&fields});
        p::bounded(&params, p::NATIVE_COMMAND_BYTES - 1024).map_err(|_| invalid_owner())?;
        let submission = metadata_wire::Submission {
            expected_baseline: baseline,
            fields,
        };
        self.prepare_domain_metadata(
            Some(publisher),
            window,
            EditDomain::MetadataText,
            original.session_id.as_str(),
            original.revision.as_str(),
            (0, 0),
            params,
            Some(registration),
            Some(SavedTextSubmission::MetadataText(submission)),
            None,
            None,
            Some(&link.entry),
        )?
        .metadata_text()
    }
    pub(crate) fn apply_agent_metadata_text(
        &self,
        publisher: &RegistrationPublisher,
        window: &str,
        link: Arc<Link>,
        registration: RegisteredEditRoot,
    ) -> Result<MetadataTextEditStatus, BridgeError> {
        let original = link.entry.original().map_err(|_| invalid_owner())?;
        let review = link.entry.review().map_err(|_| invalid_owner())?;
        self.apply_domain_metadata(
            Some(publisher),
            window,
            EditDomain::MetadataText,
            original.session_id.as_str(),
            review.plan_token.as_str(),
            Some(registration),
            false,
            None,
            None,
            None, // Existing reserved/manual VersionEdit claim is never borrowed.
            Some(&link.entry),
        )?
        .metadata_text()
    }
    pub(crate) fn allow_agent_metadata_text(
        &self,
        window: &str,
        entry: &Arc<Entry>,
        args: &p::Allow,
    ) -> Result<p::Status, BridgeError> {
        let r = self.inner.lock();
        self.inner.admission(&r, window, EditDomain::MetadataText)?;
        let a = r.active.as_ref().ok_or_else(invalid_owner)?;
        let link = a
            .session
            .agent_metadata_text
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
        entry.allow(args, a.review_end).map_err(|_| invalid_owner())
    }
    pub(crate) fn cancel_agent_metadata_text(
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
                    .agent_metadata_text
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
    pub(crate) fn signal_agent_metadata_text_cancel(
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
                .and_then(|a| a.session.agent_metadata_text.as_ref())
                .filter(|link| &link.entry.input().origin == origin)
                .map(|link| link.entry.clone())
        };
        if let Some(entry) = entry {
            entry.cancel(at).map_err(|_| edit_unknown())?;
        }
        Ok(())
    }
    pub(crate) fn metadata_text_agent_relay_lost(&self, at: Instant) {
        let entry = self
            .inner
            .lock()
            .active
            .as_ref()
            .and_then(|a| a.session.agent_metadata_text.as_ref())
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
    let Some(link) = &session.agent_metadata_text else {
        return Ok(());
    };
    if session.domain != EditDomain::MetadataText
        || session.saved_text_recovery
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
    let Some(link) = &a.session.agent_metadata_text else {
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
    match (a.session.agent_metadata_text.as_ref(), entry) {
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
    let link = session.agent_metadata_text.as_ref()?;
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
    let Some(link) = &owner.agent_metadata_text else {
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

fn platform(v: p::Platform) -> metadata_wire::Platform {
    match v {
        p::Platform::Android => metadata_wire::Platform::Android,
        p::Platform::Ios => metadata_wire::Platform::Ios,
    }
}
fn check_baseline(
    entry: &Entry,
    root: &str,
    baseline: &metadata_wire::Baseline,
) -> Result<(), BridgeError> {
    let original = entry.load().map_err(|_| invalid_owner())?;
    if !baseline_matches(&original, root, baseline)? {
        return Err(BridgeError::new("cli_access_changed","Public text changed after Load. Preserve this request and inspect the original; it will not reload or merge."));
    }
    Ok(())
}
// Comparison only. Its sole production caller first obtains Entry::load(),
// which requires that exact original passive owner and RAW caller to return.
fn baseline_matches(
    original: &p::Observation,
    root: &str,
    baseline: &metadata_wire::Baseline,
) -> Result<bool, BridgeError> {
    let expected: metadata_wire::Baseline =
        serde_json::from_slice(&p::encoded(&original.baseline, 8192).map_err(|_| invalid_owner())?)
            .map_err(|_| invalid_owner())?;
    Ok(root == original.metadata_root && *baseline == expected)
}
pub(super) fn frame(
    active: &ActiveOwner,
    frame: &ChildFrame,
    publication: &mut EditPublication<'_>,
) -> Result<(), BridgeError> {
    let Some(link) = &active.session.agent_metadata_text else {
        return Ok(());
    };
    memory::metadata_prospective(&active.projection, frame)?;
    let step = match frame {
        ChildFrame::MetadataTextOpened(c) => {
            check_baseline(&link.entry, &c.metadata_root, &c.baseline)?;
            Step::Opened
        }
        ChildFrame::MetadataTextPrepared(_) => Step::Prepared,
        ChildFrame::MetadataTextTerminal(_, c)
            if matches!(c.outcome().effect, Effect::Committed | Effect::Unchanged)
                && c.outcome().resources == ResourceState::Settled =>
        {
            Step::Terminal
        }
        ChildFrame::MetadataTextTerminal(_, _) => return Ok(()),
        _ => return Err(invalid_owner()),
    };
    link.publication(publication, step)
}
fn review(pj: &EditProjection, entry: &Entry, revision: u32) -> Result<p::Review, BridgeError> {
    let detail = pj.metadata_text.as_ref().ok_or_else(invalid_owner)?;
    let checkout = detail.checkout.as_ref().ok_or_else(invalid_owner)?;
    let prepared = detail.prepared.as_ref().ok_or_else(invalid_owner)?;
    check_baseline(entry, &checkout.metadata_root, &checkout.baseline)?;
    let proposal = entry.proposal().map_err(|_| invalid_owner())?;
    if prepared.view.files.len() != proposal.fields.len()
        || !prepared
            .view
            .files
            .iter()
            .zip(&proposal.fields)
            .all(|(f, p)| f.after.text == p.text)
    {
        return Err(invalid_owner());
    }
    let files = prepared
        .view
        .files
        .iter()
        .zip(entry.input().platform.ids())
        .map(|(f, id)| p::File {
            id: (*id).into(),
            action: match f.action {
                metadata_wire::Action::Create => "create",
                metadata_wire::Action::Replace => "replace",
                metadata_wire::Action::Preserve => "preserve",
            }
            .into(),
            before_bytes: match &f.before {
                metadata_wire::Before::Absent {} => None,
                metadata_wire::Before::Present { byte_length, .. } => Some(*byte_length),
            },
            after_bytes: f.after.byte_length,
            after_sha256: f.after.sha256.clone(),
        })
        .collect();
    let review = p::Review {
        plan_token: Id::parse(&prepared.plan_token).map_err(|_| invalid_owner())?,
        native_status_revision: revision,
        proposal_sha256: proposal.digest().map_err(|_| invalid_owner())?,
        files,
    };
    review
        .validate(entry.input().platform)
        .map_err(|_| invalid_owner())?;
    Ok(review)
}
pub(super) fn changed(r: &Registry) {
    let Some(a) = &r.active else { return };
    let Some(link) = &a.session.agent_metadata_text else {
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
        if let Some(c) = a
            .projection
            .metadata_text
            .as_ref()
            .and_then(|m| m.checkout.as_ref())
        {
            link.entry
                .opened(p::Original {
                    session_id: Id::parse(&a.session.id).map_err(|_| invalid_owner())?,
                    owner_generation: link.generation.clone(),
                    revision: Id::parse(&c.revision).map_err(|_| invalid_owner())?,
                })
                .map_err(|_| invalid_owner())?;
        }
        if a.projection.phase == Phase::Reviewing {
            link.entry
                .prepared(review(&a.projection, &link.entry, r.revision)?)
                .map_err(|_| invalid_owner())?;
        }
        Ok(())
    })();
    if result.is_err() {
        link.entry.unknown()
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
    let Some(link) = &active.session.agent_metadata_text else {
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
    let Some(link) = &owner.agent_metadata_text else {
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

impl EditOwner {
    pub(crate) fn metadata_text_agent_manual(&self) -> Result<(), BridgeError> {
        if self
            .inner
            .lock()
            .active
            .as_ref()
            .is_some_and(|a| a.session.agent_metadata_text.is_some())
        {
            Err(invalid_owner())
        } else {
            Ok(())
        }
    }
}
pub(super) fn preclaim(
    inner: &Inner,
    session: &str,
    entry: Option<&Arc<Entry>>,
    kind: Kind,
) -> Result<(), BridgeError> {
    let r = inner.lock();
    let actual = r
        .active
        .as_ref()
        .filter(|a| a.session.id == session)
        .and_then(|a| a.session.agent_metadata_text.as_ref());
    match (actual, entry) {
        (None, None) => Ok(()),
        (Some(l), Some(e)) if Arc::ptr_eq(&l.entry, e) && e.admitting(kind) => Ok(()),
        _ => Err(invalid_owner()),
    }
}

#[cfg(test)]
#[path = "edit_owner_service_metadata_text_tests.rs"]
mod tests;
