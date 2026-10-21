//! Combined CLI Open/Prepare is a facet of the ORIGINAL Version EditOwner.
//! The entry is comparison/READ/caller custody, never a handoff or a writer.
use super::agent_configuration::memory;
use super::*;
use crate::{
    application_service::ApplicationService,
    application_service_host::NativeProject,
    asset_session::VersionPrepareGate,
    service_protocol::Id,
    service_version_edit_prepare_protocol as p,
    service_version_edit_prepare_requests::{Entry, Kind},
};
use std::sync::{OnceLock, Weak};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Step {
    Open,
    Opened,
    Prepare,
    Prepared,
    Apply,
    Terminal,
    Retired,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
    Some(match (stage, step) {
        (Stage::Bound, Step::Open) => Stage::Opening,
        (Stage::Opening, Step::Opened) => Stage::Editing,
        (Stage::Editing, Step::Prepare) => Stage::Preparing,
        (Stage::Preparing, Step::Prepared) => Stage::Reviewing,
        (Stage::Reviewing, Step::Apply) => Stage::Applying,
        (Stage::Applying, Step::Terminal) => Stage::Finalizing,
        (Stage::Finalizing, Step::Retired) => Stage::Returned,
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
    fn begin(&mut self, p: &RegistrationPublisher, step: Step) -> Result<(), BridgeError> {
        let live = !self.failed
            && self.pending.is_none()
            && !p.accepted()
            && successor(self.stage, step).is_some();
        self.failed = true;
        if !live || p.tool_source_epoch()? != self.epoch {
            return Err(invalid_owner());
        }
        self.pending = Some((self.epoch, p.reserved_version_serial()?, step));
        self.failed = false;
        Ok(())
    }
    fn accepted(&mut self, p: &RegistrationPublisher, step: Step) -> Result<(), BridgeError> {
        let live = !self.failed && p.accepted();
        self.failed = true;
        let next = self.epoch.checked_add(1).ok_or_else(edit_unknown)?;
        if !live
            || self.pending != Some((self.epoch, p.reserved_version_serial()?, step))
            || p.tool_source_epoch()? != next
        {
            return Err(invalid_owner());
        }
        self.stage = successor(self.stage, step).ok_or_else(invalid_owner)?;
        self.epoch = next;
        self.pending = None;
        self.failed = false;
        Ok(())
    }
}
pub(crate) struct Link {
    pub(crate) entry: Arc<Entry>,
    pub(crate) project: NativeProject,
    owner: Weak<Inner>,
    service: Weak<ApplicationService>,
    pub(crate) gate: VersionPrepareGate,
    generation: Id,
    session: OnceLock<Weak<Session>>,
    claimed: AtomicBool,
    // Reserved originals retain their existing handoff chain EXCLUSIVELY.
    chain: Option<Mutex<Chain>>,
}
impl Link {
    pub(crate) fn reserved(&self) -> bool {
        self.chain.is_none()
    }
    fn permission(&self) -> bool {
        self.entry.gui_owned()
            || self.entry.live()
                && self
                    .service
                    .upgrade()
                    .is_some_and(|s| s.native_history_current().is_ok())
    }
    fn chain(&self) -> Result<MutexGuard<'_, Chain>, BridgeError> {
        self.chain
            .as_ref()
            .ok_or_else(invalid_owner)?
            .lock()
            .map_err(|_| {
                self.entry.unknown();
                edit_unknown()
            })
    }
    pub(crate) fn claim_open(&self) -> Result<(), BridgeError> {
        if !self.claimed.swap(true, Ordering::SeqCst) {
            self.entry.claim_open().map_err(|_| invalid_owner())?;
        }
        if !self.entry.admitting(Kind::Open) || !self.permission() {
            return Err(invalid_owner());
        }
        Ok(())
    }
    pub(crate) fn begin(&self, p: &RegistrationPublisher, step: Step) -> Result<(), BridgeError> {
        if !self.gate.same_publisher(p) || !self.permission() {
            return Err(invalid_owner());
        }
        self.chain()?.begin(p, step)
    }
    pub(crate) fn accepted(
        &self,
        p: &RegistrationPublisher,
        step: Step,
    ) -> Result<(), BridgeError> {
        if !self.gate.same_publisher(p) || !self.permission() {
            return Err(invalid_owner());
        }
        self.chain()?.accepted(p, step)
    }
    fn publication(&self, p: &mut EditPublication<'_>, step: Step) -> Result<(), BridgeError> {
        if self.reserved() {
            return Ok(());
        } // actual NativeReservedVersionHandoff already owns this cut
        if let Some(p) = p.owned.as_mut() {
            self.begin(p, step)?;
            p.accept(crate::android_registration_app_protocol::Reason::ContextChanged)?;
            self.accepted(p, step)
        } else if let Some(p) = p.borrowed {
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
        a.session.domain == EditDomain::ReleaseVersion
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
            && self.reserved() == a.session.reserved_version.is_some()
    }
    pub(crate) fn epoch_ready(
        &self,
        p: Option<&RegistrationPublisher>,
    ) -> Result<bool, BridgeError> {
        if !self.permission() {
            return Err(invalid_owner());
        }
        if self.reserved() {
            return Ok(true);
        } // same Session's handoff supplies its full clock/source check
        let c = self.chain()?;
        if c.failed {
            return Err(invalid_owner());
        }
        if c.pending.is_some() {
            return Ok(false);
        }
        let epoch = if let Some(p) = p {
            if !self.gate.same_publisher(p) {
                return Err(invalid_owner());
            }
            p.reserved_version_epoch()?
        } else {
            match self.gate.epoch() {
                Ok(e) => Some(e),
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
        p: Option<&RegistrationPublisher>,
    ) -> Result<(), BridgeError> {
        if !self.epoch_ready(p)? {
            return Err(BridgeError::new(
                "busy",
                "Wait for the original version publication.",
            ));
        }
        self.gate.current(&self.project)
    }
    pub(crate) fn cleanup_poll_end(&self, end: Instant, now: Instant) -> Instant {
        if self.entry.gui_owned() {
            end
        } else {
            end.min(now + Duration::from_millis(100))
        }
    }
}
impl RegisteredOpenTicket {
    pub(crate) fn version_preparation(&mut self, link: Arc<Link>) -> Result<(), BridgeError> {
        if self.domain != EditDomain::ReleaseVersion
            || self.saved_text_recovery
            || self.agent_version_prepare.is_some()
        {
            return Err(invalid_owner());
        }
        self.agent_version_prepare = Some(link);
        Ok(())
    }
}
impl EditOwner {
    pub(crate) fn version_preparation_active(&self) -> bool {
        self.inner
            .lock()
            .active
            .as_ref()
            .is_some_and(|a| a.session.agent_version_prepare.is_some())
    }
    pub(crate) fn version_preparation_manual(&self) -> Result<(), BridgeError> {
        if self.version_preparation_active() {
            Err(invalid_owner())
        } else {
            Ok(())
        }
    }
    pub(crate) fn version_prepare_link(
        &self,
        window: &str,
        entry: Arc<Entry>,
        service: &Arc<ApplicationService>,
        project: NativeProject,
        gate: VersionPrepareGate,
    ) -> Result<Arc<Link>, BridgeError> {
        let r = self.inner.lock();
        self.inner
            .admission(&r, window, EditDomain::ReleaseVersion)?;
        if r.active.is_some()
            || !entry.unclaimed_open()
            || entry.scope.saved.runtime_id != project.runtime_id
            || entry.scope.saved.root != project.canonical_root
            || entry.scope.saved.device != project.device
            || entry.scope.saved.inode != project.inode
            || service.native_history_current().is_err()
        {
            return Err(invalid_owner());
        }
        let reserved = matches!(entry.input.selection, p::Selection::Reserved { .. });
        Ok(Arc::new(Link {
            entry,
            chain: (!reserved).then(|| {
                Mutex::new(Chain {
                    epoch: project.input_revision,
                    stage: Stage::Bound,
                    pending: None,
                    failed: false,
                })
            }),
            owner: Arc::downgrade(&self.inner),
            service: Arc::downgrade(service),
            gate,
            project,
            generation: Id::parse(&r.generation).map_err(|_| invalid_owner())?,
            session: OnceLock::new(),
            claimed: AtomicBool::new(false),
        }))
    }
    pub(crate) fn version_prepare_access(
        &self,
        window: &str,
        entry: &Arc<Entry>,
    ) -> Result<Arc<Link>, BridgeError> {
        let r = self.inner.lock();
        self.inner
            .admission(&r, window, EditDomain::ReleaseVersion)?;
        let a = r.active.as_ref().ok_or_else(invalid_owner)?;
        let l = a
            .session
            .agent_version_prepare
            .as_ref()
            .ok_or_else(invalid_owner)?;
        if !Arc::ptr_eq(&l.entry, entry)
            || !l.active(a)
            || a.unknown
            || a.cleanup_start.is_some()
            || a.terminal
            || !l.permission()
        {
            return Err(invalid_owner());
        }
        Ok(l.clone())
    }
    pub(crate) fn version_prepare_for_session(
        &self,
        window: &str,
        session: &str,
    ) -> Result<Option<Arc<Link>>, BridgeError> {
        let r = self.inner.lock();
        self.inner
            .admission(&r, window, EditDomain::ReleaseVersion)?;
        let a = r
            .active
            .as_ref()
            .filter(|a| a.session.id == session)
            .ok_or_else(invalid_owner)?;
        match &a.session.agent_version_prepare {
            Some(l) if !l.active(a) => Err(invalid_owner()),
            v => Ok(v.clone()),
        }
    }
    pub(crate) fn prepare_agent_version(
        &self,
        publisher: &RegistrationPublisher,
        window: &str,
        link: &Arc<Link>,
        registration: RegisteredEditRoot,
    ) -> Result<ReleaseVersionEditStatus, BridgeError> {
        let (original, opened, values, counters) =
            link.entry.prepare_data().map_err(|_| invalid_owner())?;
        let submission = {
            let r = self.inner.lock();
            let a = r
                .active
                .as_ref()
                .filter(|a| link.active(a))
                .ok_or_else(invalid_owner)?;
            let c = a
                .projection
                .release_version
                .as_ref()
                .and_then(|d| d.checkout.as_ref())
                .ok_or_else(invalid_owner)?;
            if a.projection.phase != Phase::Editing || checkout(c)? != opened {
                return Err(invalid_owner());
            }
            let expected = proposed(&a.session)?;
            if expected != values {
                return Err(invalid_owner());
            }
            version_wire::Submission {
                expected_baseline: c.baseline.clone(),
                intent: version_wire::Intent::Edit,
                values: version_wire::Values {
                    name: values.name,
                    build: values.build,
                },
            }
        };
        let params = json!({"revision":opened.revision.as_str(),"expectedBaseline":&submission.expected_baseline,"intent":"edit","values":&submission.values});
        self.prepare_domain_version(
            Some(publisher),
            window,
            EditDomain::ReleaseVersion,
            original.session_id.as_str(),
            opened.revision.as_str(),
            counters,
            params,
            Some(registration),
            Some(SavedTextSubmission::ReleaseVersion(submission)),
            None,
            None,
            None,
            Some(&link.entry),
        )?
        .release_version()
    }
    pub(crate) fn version_prepare_cancel(
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
        let session = self
            .inner
            .lock()
            .active
            .as_ref()
            .filter(|a| {
                a.session
                    .agent_version_prepare
                    .as_ref()
                    .is_some_and(|l| Arc::ptr_eq(&l.entry, entry))
            })
            .map(|a| a.session.clone());
        if let Some(s) = session {
            if !entry.gui_owned() {
                s.wake.notify_waiters();
                self.inner.expire(&s.id, at);
            }
        }
        Ok(())
    }
}
fn checkout(c: &version_wire::Checkout) -> Result<p::Checkout, BridgeError> {
    scalar_checkout(
        &c.revision,
        &c.source,
        c.ios_enabled,
        c.values.as_ref(),
        &c.baseline,
    )
}
fn scalar_checkout(
    revision: &str,
    source: &str,
    ios_enabled: bool,
    values: Option<&version_wire::Values>,
    baseline: &version_wire::Baseline,
) -> Result<p::Checkout, BridgeError> {
    let version_wire::BaselineFile::Present { bytes, sha256 } = &baseline.saved_version else {
        return Err(invalid_owner());
    };
    let values = values.ok_or_else(invalid_owner)?;
    let result = p::Checkout {
        revision: Id::parse(revision).map_err(|_| invalid_owner())?,
        source: source.into(),
        ios_enabled,
        values: p::Values {
            name: values.name.clone(),
            build: values.build.clone(),
        },
        config_bytes: baseline.saved_config.bytes,
        config_sha256: baseline.saved_config.sha256.clone(),
        version_bytes: *bytes,
        version_sha256: sha256.clone(),
    };
    if !result.valid() {
        return Err(invalid_owner());
    }
    Ok(result)
}
fn proposed(s: &Session) -> Result<p::Values, BridgeError> {
    let link = s.agent_version_prepare.as_ref().ok_or_else(invalid_owner)?;
    let v = match (&link.entry.input.selection, &s.reserved_version) {
        (p::Selection::Manual { values }, None) => values.clone(),
        (p::Selection::Reserved { .. }, Some(h)) => {
            let v = h.proposed_values()?;
            p::Values {
                name: v.name,
                build: v.build,
            }
        }
        _ => return Err(invalid_owner()),
    };
    // Opened has already validated the complete source/config/platform tuple.
    if !v.valid() {
        return Err(invalid_owner());
    }
    Ok(v)
}
pub(super) fn before_claim(
    inner: &Arc<Inner>,
    r: &Registry,
    s: &Session,
    project: &str,
    publication: &mut EditPublication<'_>,
) -> Result<(), BridgeError> {
    let Some(l) = &s.agent_version_prepare else {
        return Ok(());
    };
    if s.domain != EditDomain::ReleaseVersion
        || s.saved_text_recovery
        || l.owner.as_ptr() != Arc::as_ptr(inner)
        || r.generation != l.generation.as_str()
        || project != l.project.runtime_id
        || l.session.get().is_some()
        || l.reserved() != s.reserved_version.is_some()
    {
        return Err(invalid_owner());
    }
    l.claim_open()?;
    l.publication(publication, Step::Open)
}
pub(super) fn linked(r: &Registry) -> Result<(), BridgeError> {
    let Some(a) = &r.active else { return Ok(()) };
    let Some(l) = &a.session.agent_version_prepare else {
        return Ok(());
    };
    l.session
        .set(Arc::downgrade(&a.session))
        .map_err(|_| edit_unknown())?;
    l.entry
        .bind(
            p::Original {
                session_id: Id::parse(&a.session.id).map_err(|_| edit_unknown())?,
                owner_generation: l.generation.clone(),
            },
            Arc::downgrade(&a.session.wake),
        )
        .map_err(|_| {
            l.entry.unknown();
            edit_unknown()
        })
}
pub(super) fn preclaim(
    inner: &Inner,
    session: &str,
    entry: Option<&Arc<Entry>>,
) -> Result<(), BridgeError> {
    let r = inner.lock();
    let link = r
        .active
        .as_ref()
        .filter(|a| a.session.id == session)
        .and_then(|a| a.session.agent_version_prepare.as_ref());
    match (link, entry) {
        (None, None) => Ok(()),
        (Some(l), Some(e)) if Arc::ptr_eq(&l.entry, e) && e.admitting(Kind::Prepare) => Ok(()),
        _ => Err(invalid_owner()),
    }
}
pub(super) fn consume(
    a: &ActiveOwner,
    entry: Option<&Arc<Entry>>,
    p: &mut EditPublication<'_>,
) -> Result<(), BridgeError> {
    match (&a.session.agent_version_prepare, entry) {
        (None, None) => Ok(()),
        (Some(l), Some(e))
            if Arc::ptr_eq(&l.entry, e) && l.active(a) && e.admitting(Kind::Prepare) =>
        {
            l.publication(p, Step::Prepare)
        }
        _ => Err(invalid_owner()),
    }
}
pub(super) fn apply_publication(
    a: &ActiveOwner,
    p: &mut EditPublication<'_>,
) -> Result<(), BridgeError> {
    if let Some(l) = &a.session.agent_version_prepare {
        if !l.active(a) {
            return Err(invalid_owner());
        }
        l.publication(p, Step::Apply)?;
    }
    Ok(())
}
pub(super) fn cancellation_at(s: &Session, now: Instant) -> Option<(Instant, Reason)> {
    let l = s.agent_version_prepare.as_ref()?;
    match l.entry.stop_at(now) {
        Ok(Some(at)) => Some((at, Reason::Cancelled)),
        Err(_) => {
            s.resource_unknown.store(true, Ordering::SeqCst);
            Some((now, Reason::CleanupUnknown))
        }
        Ok(None) => {
            if !l.entry.gui_owned()
                && l.service
                    .upgrade()
                    .is_none_or(|s| s.native_history_current().is_err())
            {
                l.entry.unknown();
                return Some((now, Reason::CallerLost));
            }
            match l.epoch_ready(None) {
                Err(e) if e.code != "busy" => Some((now, Reason::CallerLost)),
                _ => None,
            }
        }
    }
}
pub(super) async fn wait_command(s: &Session) -> Result<(), BridgeError> {
    let Some(l) = &s.agent_version_prepare else {
        return Ok(());
    };
    loop {
        if *s.stop.borrow() {
            return Err(invalid_owner());
        }
        match l.document_current(None) {
            Ok(()) => return Ok(()),
            Err(e) if e.code == "busy" => (),
            Err(e) => return Err(e),
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}
pub(super) fn frame(
    a: &ActiveOwner,
    frame: &ChildFrame,
    p: &mut EditPublication<'_>,
) -> Result<(), BridgeError> {
    let Some(l) = &a.session.agent_version_prepare else {
        return Ok(());
    };
    memory::version_prepare_prospective(&a.projection, frame)?;
    if a.cleanup_start.is_some() {
        return Ok(());
    } // Bound late-frame adoption too; never renew its publication.
    let step = match frame {
        ChildFrame::ReleaseVersionOpened(c) => {
            scalar_checkout(
                &c.revision,
                &c.source,
                c.ios_enabled,
                c.values.as_ref(),
                &c.baseline,
            )?;
            proposed(&a.session)?;
            Step::Opened
        }
        ChildFrame::ReleaseVersionPrepared(_) => Step::Prepared,
        ChildFrame::ReleaseVersionTerminal(_, c)
            if matches!(c.outcome().effect, Effect::Committed | Effect::Unchanged)
                && c.outcome().resources == ResourceState::Settled =>
        {
            Step::Terminal
        }
        ChildFrame::ReleaseVersionTerminal(_, _) => return Ok(()),
        _ => return Err(invalid_owner()),
    };
    l.publication(p, step)
}
pub(super) fn changed(r: &Registry) {
    let Some(a) = &r.active else { return };
    let Some(l) = &a.session.agent_version_prepare else {
        return;
    };
    let result = (|| {
        if !l.active(a) {
            return Err(invalid_owner());
        }
        if a.unknown || a.projection.native_finality == NativeFinality::Unknown {
            l.entry.unknown();
            return Ok(());
        }
        if a.cleanup_start.is_some() {
            return Ok(());
        }
        if let Some(c) = a
            .projection
            .release_version
            .as_ref()
            .and_then(|d| d.checkout.as_ref())
        {
            l.entry
                .opened(checkout(c)?, proposed(&a.session)?)
                .map_err(|_| invalid_owner())?;
        }
        if a.projection.phase == Phase::Reviewing && !l.entry.has_review() {
            l.entry
                .prepared(agent_version_edit::review(a, r.revision)?)
                .map_err(|_| invalid_owner())?;
        }
        Ok(())
    })();
    if result.is_err() {
        l.entry.unknown();
    }
}
pub(super) fn unknown(s: &Session) {
    if let Some(l) = &s.agent_version_prepare {
        l.entry.unknown();
    }
}
pub(super) fn retirement_publication(a: &mut ActiveOwner, p: &mut EditPublication<'_>) -> bool {
    let Some(l) = &a.session.agent_version_prepare else {
        return true;
    };
    if l.reserved() {
        return true;
    } // original reserved retirement is independently mandatory
    let current = l.publication(p, Step::Retired).is_ok();
    if !current
        && a.projection.core_outcome.as_ref().is_some_and(|c| {
            c.resources == ResourceState::Settled
                && matches!(c.effect, Effect::Committed | Effect::Unchanged)
        })
    {
        a.unknown = true;
        if a.projection.native_reason == Reason::None {
            a.projection.native_reason = Reason::CallerLost;
        }
    }
    current
}
pub(super) fn retired(r: &Registry, s: &Session, unknown: bool, chain_current: bool) {
    let Some(l) = &s.agent_version_prepare else {
        return;
    };
    let service_current = l.entry.gui_owned()
        || l.service
            .upgrade()
            .is_some_and(|s| s.native_history_current().is_ok());
    let mut result = agent_version_edit::final_data(r, s, unknown, service_current);
    if !chain_current
        && result.as_ref().is_some_and(|v| {
            matches!(
                v.effect,
                crate::service_version_edit_protocol::Effect::Committed
                    | crate::service_version_edit_protocol::Effect::Unchanged
            )
        })
    {
        result = None;
    }
    if l.entry.retired(result).is_err() {
        l.entry.unknown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manual_publication_chain_has_only_the_original_seven_successors() {
        let edges = [
            (Stage::Bound, Step::Open, Stage::Opening),
            (Stage::Opening, Step::Opened, Stage::Editing),
            (Stage::Editing, Step::Prepare, Stage::Preparing),
            (Stage::Preparing, Step::Prepared, Stage::Reviewing),
            (Stage::Reviewing, Step::Apply, Stage::Applying),
            (Stage::Applying, Step::Terminal, Stage::Finalizing),
            (Stage::Finalizing, Step::Retired, Stage::Returned),
        ];
        for (before, step, after) in edges {
            assert_eq!(successor(before, step), Some(after));
            assert_eq!(successor(after, step), None);
            for other in [
                Step::Open,
                Step::Opened,
                Step::Prepare,
                Step::Prepared,
                Step::Apply,
                Step::Terminal,
                Step::Retired,
            ] {
                if other != step {
                    assert_eq!(successor(before, other), None);
                }
            }
        }
        for step in [
            Step::Open,
            Step::Opened,
            Step::Prepare,
            Step::Prepared,
            Step::Apply,
            Step::Terminal,
            Step::Retired,
        ] {
            assert_eq!(successor(Stage::Returned, step), None);
        }
    }
    #[test]
    fn compact_opened_uses_actual_present_baselines_and_never_constructs_a_handoff() {
        let revision = "a".repeat(32);
        let values = version_wire::Values {
            name: "1.2".into(),
            build: "10000".into(),
        };
        let baseline = version_wire::Baseline {
            saved_config: version_wire::ContentDigest {
                bytes: 100,
                sha256: "b".repeat(64),
            },
            saved_version: version_wire::BaselineFile::Present {
                bytes: 40,
                sha256: "c".repeat(64),
            },
        };
        for ios in [false, true] {
            let c = scalar_checkout(
                &revision,
                "public/version.properties",
                ios,
                Some(&values),
                &baseline,
            )
            .unwrap();
            assert_eq!(c.ios_enabled, ios);
            assert_eq!(c.config_sha256, "b".repeat(64));
            assert_eq!(c.version_sha256, "c".repeat(64));
            assert_eq!(c.values.build, "10000"); // format DATA; original core owns platform policy
        }
        assert!(scalar_checkout(
            &revision,
            "public/version.properties",
            false,
            None,
            &baseline
        )
        .is_err());
        for source in [
            "/foreign/version.properties",
            "../version.properties",
            "public//version.properties",
            "public\\version.properties",
        ] {
            assert!(scalar_checkout(&revision, source, false, Some(&values), &baseline).is_err());
        }
        let mut absent = baseline.clone();
        absent.saved_version = version_wire::BaselineFile::Absent {};
        assert!(scalar_checkout(&revision, "v.properties", false, Some(&values), &absent).is_err());
        let mut corrupt = baseline.clone();
        corrupt.saved_config.sha256 = "not-a-hash".into();
        assert!(
            scalar_checkout(&revision, "v.properties", false, Some(&values), &corrupt).is_err()
        );
        corrupt = baseline.clone();
        corrupt.saved_version = version_wire::BaselineFile::Present {
            bytes: 40,
            sha256: "wrong".into(),
        };
        assert!(
            scalar_checkout(&revision, "v.properties", false, Some(&values), &corrupt).is_err()
        );
        let mut over = baseline;
        over.saved_config.bytes = 512 * 1024 + 1;
        assert!(scalar_checkout(&revision, "v.properties", false, Some(&values), &over).is_err());
    }
}
