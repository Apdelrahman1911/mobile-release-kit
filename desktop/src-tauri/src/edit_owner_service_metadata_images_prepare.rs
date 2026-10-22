//! Inspection/Prepare of the SAME already opened Import. The weak identity
//! belongs to that actual Session; no path, bytes, new owner or cold adoption.
use super::*;
use crate::{
    application_service::ApplicationService, application_service_host::NativeProject,
    asset_session::MetadataImagesAgentGate, service_metadata_images_prepare_protocol as p,
    service_metadata_images_prepare_requests::Entry, service_protocol::Id,
};
use sha2::{Digest, Sha256};
use std::sync::Weak;
pub(crate) struct Link {
    pub(crate) entry: Arc<Entry>,
    pub(crate) project: NativeProject,
    service: Weak<ApplicationService>,
    gate: MetadataImagesAgentGate,
    session: Weak<Session>,
    chain: Mutex<Chain>,
}
struct Chain {
    epoch: u64,
    stage: u8,
    pending: Option<(u64, u8)>,
    failed: bool,
}
pub(crate) struct Claim {
    pub(crate) link: Arc<Link>,
    args: images_wire::PrepareMetadataImagesEdit,
}
pub(crate) struct GuiClaim {
    session: Arc<Session>,
}
fn id(s: &str) -> Result<Id, BridgeError> {
    Id::parse(s).map_err(|_| invalid_owner())
}
fn public(e: crate::service_protocol::Error) -> BridgeError {
    crate::asset_session::application_service::public_error(e)
}
fn window(r: &Registry, w: &str) -> Result<(), BridgeError> {
    if r.window.as_deref() != Some(w)
        || !r.document_bound
        || r.document_lost
        || r.disabled
        || r.stopping
        || r.exhausted
    {
        Err(invalid_owner())
    } else {
        Ok(())
    }
}
fn editing(a: &ActiveOwner) -> Result<&images_wire::Details, BridgeError> {
    if !a.session.image_prepare_profile
        || a.session.domain != EditDomain::MetadataImages
        || a.projection.phase != Phase::Editing
        || a.projection.native_reason != Reason::None
        || a.projection.native_finality != NativeFinality::Pending
        || a.projection.apply_submitted
        || a.cleanup_start.is_some()
        || a.unknown
        || !a.opened
        || a.prepared
        || a.prepare_counters.is_some()
        || a.claimed_seq != 0
        || *a.session.stop.borrow()
        || a.session.image_written.load(Ordering::Acquire) != 1
        || Instant::now() >= a.review_end
    {
        return Err(invalid_owner());
    }
    let d = a
        .projection
        .metadata_images
        .as_ref()
        .ok_or_else(invalid_owner)?;
    let c = d.checkout.as_ref().ok_or_else(invalid_owner)?;
    if d.intent != images_wire::Intent::Import
        || d.submission.is_some()
        || d.prepared.is_some()
        || !d.opened_view_matches(&c.view)
        || c.view.get("valid").and_then(Value::as_bool) != Some(true)
    {
        return Err(invalid_owner());
    }
    Ok(d)
}
struct HashWriter {
    hash: Sha256,
    bytes: usize,
}
impl std::io::Write for HashWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(b.len())
            .filter(|n| *n <= images_wire::RESPONSE_LIMIT)
            .ok_or_else(|| std::io::Error::other("bounded image checkout"))?;
        self.hash.update(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn observation(
    a: &ActiveOwner,
    revision: u32,
    baseline: u32,
) -> Result<p::Observation, BridgeError> {
    let d = editing(a)?;
    let c = d.checkout.as_ref().ok_or_else(invalid_owner)?;
    let context = d.context.as_ref().ok_or_else(invalid_owner)?;
    if !context.valid() {
        return Err(invalid_owner());
    }
    let files = c.view["files"].as_array().ok_or_else(invalid_owner)?;
    let mut items = Vec::new();
    items
        .try_reserve_exact(files.len())
        .map_err(|_| invalid_owner())?;
    for (file, selected) in files.iter().zip(&d.selected) {
        items.push(p::Item {
            item_id: id(&selected.item_id)?,
            display_name: selected.display_name.clone(),
            selected_bytes: selected.byte_length,
            selected_sha256: selected.sha256.clone(),
            before_sha256: if file["before"].is_null() {
                None
            } else {
                Some(
                    file["before"]["sha256"]
                        .as_str()
                        .ok_or_else(invalid_owner)?
                        .to_owned(),
                )
            },
            can_replace: file["canReplace"].as_bool().ok_or_else(invalid_owner)?,
            replace_existing: false,
        });
    }
    let mut h = HashWriter {
        hash: Sha256::new(),
        bytes: 0,
    };
    serde_json::to_writer(&mut h, &(&c.baseline, &c.view)).map_err(|_| invalid_owner())?;
    let o = p::Observation {
        original: p::Original {
            session_id: id(&a.session.id)?,
            owner_generation: id(&a.projection.owner_generation)?,
            revision: id(&c.revision)?,
            native_status_revision: revision,
            baseline_generation: baseline,
        },
        platform: match context.platform {
            metadata_wire::Platform::Android => {
                crate::service_metadata_images_protocol::Platform::Android
            }
            metadata_wire::Platform::Ios => crate::service_metadata_images_protocol::Platform::Ios,
        },
        locale: context.locale.clone(),
        asset_type: context.asset_type.clone(),
        opened_sha256: format!("{:x}", h.hash.finalize()),
        items,
    };
    o.validate().map_err(public)?;
    Ok(o)
}
impl Link {
    fn same(&self, a: &ActiveOwner) -> bool {
        self.session.as_ptr() == Arc::as_ptr(&a.session)
            && a.projection.project_id == self.project.runtime_id
            && a.session
                .image_identity
                .as_ref()
                .is_some_and(|v| self.entry.bound(v))
    }
    fn control(&self) -> Result<(), BridgeError> {
        if self
            .entry
            .stop_at(Instant::now())
            .map_err(public)?
            .is_some()
            || self
                .service
                .upgrade()
                .is_none_or(|s| s.native_history_current().is_err())
        {
            return Err(invalid_owner());
        }
        Ok(())
    }
    pub(crate) fn begin(&self, p: &RegistrationPublisher, step: u8) -> Result<(), BridgeError> {
        self.control()?;
        if !self.gate.same_publisher(p) {
            return Err(invalid_owner());
        }
        let mut c = self.chain.lock().map_err(|_| edit_unknown())?;
        let good = !c.failed
            && c.pending.is_none()
            && c.stage == step
            && !p.accepted()
            && p.tool_source_epoch()? == c.epoch;
        c.failed = true;
        if !good {
            return Err(invalid_owner());
        }
        c.pending = Some((p.reserved_version_serial()?, step));
        c.failed = false;
        Ok(())
    }
    pub(crate) fn accepted(&self, p: &RegistrationPublisher, step: u8) -> Result<(), BridgeError> {
        self.control()?;
        let mut c = self.chain.lock().map_err(|_| edit_unknown())?;
        let good = !c.failed
            && self.gate.same_publisher(p)
            && p.accepted()
            && c.pending == Some((p.reserved_version_serial()?, step))
            && c.epoch.checked_add(1) == Some(p.tool_source_epoch()?);
        c.failed = true;
        if !good {
            return Err(invalid_owner());
        }
        c.epoch = p.tool_source_epoch()?;
        c.stage += 1;
        c.pending = None;
        c.failed = false;
        Ok(())
    }
    fn publication(&self, p: &mut EditPublication<'_>, step: u8) -> Result<(), BridgeError> {
        if let Some(p) = p.owned.as_mut() {
            self.begin(p, step)?;
            p.accept(crate::android_registration_app_protocol::Reason::ContextChanged)?;
            self.accepted(p, step)
        } else if let Some(p) = p.borrowed {
            let c = self.chain.lock().map_err(|_| edit_unknown())?;
            if step != 0
                || !self.gate.same_publisher(p)
                || !p.accepted()
                || c.failed
                || c.pending.is_some()
                || c.stage != 1
                || p.tool_source_epoch()? != c.epoch
            {
                Err(invalid_owner())
            } else {
                Ok(())
            }
        } else {
            Err(invalid_owner())
        }
    }
}
impl EditOwner {
    pub(crate) fn inspect_agent_images(
        &self,
        w: &str,
        e: &Arc<Entry>,
        expected: &p::Original,
    ) -> Result<(), BridgeError> {
        let r = self.inner.lock();
        window(&r, w)?;
        let a = r.active.as_ref().ok_or_else(invalid_owner)?;
        if a.projection.project_id != e.scope.saved.runtime_id
            || a.session.agent_metadata_images_prepare.get().is_some()
            || a.session.agent_metadata_images.get().is_some()
        {
            return Err(invalid_owner());
        }
        let o = observation(a, r.revision, expected.baseline_generation)?;
        if o.original != *expected {
            return Err(invalid_owner());
        }
        let marker = a
            .session
            .image_identity
            .as_ref()
            .ok_or_else(invalid_owner)?;
        e.observed(o, marker, &a.session.wake, a.review_end)
            .map_err(public)
    }
    pub(crate) fn images_prepare_origin(
        &self,
        w: &str,
        session: &str,
        e: Option<&Arc<Entry>>,
    ) -> Result<(), BridgeError> {
        let r = self.inner.lock();
        window(&r, w)?;
        origin(&r, session, e)
    }
    pub(crate) fn claim_agent_images_prepare(
        &self,
        w: &str,
        e: Arc<Entry>,
        project: NativeProject,
        service: &Arc<ApplicationService>,
        gate: MetadataImagesAgentGate,
    ) -> Result<Claim, BridgeError> {
        let observed = e.observation().map_err(public)?;
        let proposed = e.proposal().map_err(public)?;
        let r = self.inner.lock();
        window(&r, w)?;
        let a = r.active.as_ref().ok_or_else(invalid_owner)?;
        let d = editing(a)?;
        let marker = a
            .session
            .image_identity
            .as_ref()
            .ok_or_else(invalid_owner)?;
        if a.session.agent_metadata_images_prepare.get().is_some()
            || a.session.agent_metadata_images.get().is_some()
            || !e.bound(marker)
            || observation(a, r.revision, observed.original.baseline_generation)? != observed
            || !proposed.matches(&observed)
            || a.projection.project_id != project.runtime_id
            || gate.epoch()? != project.input_revision
        {
            return Err(invalid_owner());
        }
        let args = images_wire::PrepareMetadataImagesEdit {
            session_id: a.session.id.clone(),
            revision: observed.original.revision.as_str().into(),
            draft_revision: 1,
            baseline_generation: observed.original.baseline_generation,
            expected_baseline: d
                .checkout
                .as_ref()
                .ok_or_else(invalid_owner)?
                .baseline
                .clone(),
            choices: proposed
                .choices
                .iter()
                .map(|c| images_wire::Choice {
                    item_id: c.item_id.as_str().into(),
                    replace_existing: c.replace_existing,
                })
                .collect(),
        };
        let link = Arc::new(Link {
            entry: e.clone(),
            project: project.clone(),
            service: Arc::downgrade(service),
            gate,
            session: Arc::downgrade(&a.session),
            chain: Mutex::new(Chain {
                epoch: project.input_revision,
                stage: 0,
                pending: None,
                failed: false,
            }),
        });
        e.claim(marker).map_err(public)?;
        if a.session
            .agent_metadata_images_prepare
            .set(link.clone())
            .is_err()
        {
            e.unknown();
            a.session.resource_unknown.store(true, Ordering::SeqCst);
            a.session.wake.notify_waiters();
            return Err(edit_unknown());
        }
        a.session.wake.notify_waiters();
        Ok(Claim { link, args })
    }
    pub(crate) fn prepare_agent_images(
        &self,
        p: &RegistrationPublisher,
        w: &str,
        claim: Claim,
        root: RegisteredEditRoot,
    ) -> Result<MetadataImagesEditStatus, BridgeError> {
        let a = claim.args;
        let submission = images_wire::Submission {
            expected_baseline: a.expected_baseline,
            choices: a.choices,
        };
        let params = json!({"revision":&a.revision,"expectedBaseline":&submission.expected_baseline,"choices":&submission.choices});
        self.prepare_domain_images(
            Some(p),
            w,
            EditDomain::MetadataImages,
            &a.session_id,
            &a.revision,
            (a.draft_revision, a.baseline_generation),
            params,
            Some(root),
            Some(SavedTextSubmission::MetadataImages(submission)),
            None,
            None,
            None,
            None,
            Some(&claim.link.entry),
        )?
        .metadata_images()
    }
    pub(crate) fn images_prepare_tick(&self, e: &Arc<Entry>) -> Result<(), BridgeError> {
        if !e.claimed() || e.transferred() || e.status().map_err(public)?.review.is_some() {
            return Ok(());
        }
        let r = self.inner.lock();
        let Some(a) = r.active.as_ref() else {
            return Ok(());
        };
        let Some(l) = a
            .session
            .agent_metadata_images_prepare
            .get()
            .filter(|l| Arc::ptr_eq(&l.entry, e))
        else {
            return Ok(());
        };
        if a.cleanup_start.is_some()
            || a.unknown
            || a.projection.phase != Phase::Reviewing
            || a.session.image_written.load(Ordering::Acquire) != 2
        {
            return Ok(());
        }
        let chain = l.chain.lock().map_err(|_| edit_unknown())?;
        if !l.same(a)
            || chain.failed
            || chain.pending.is_some()
            || chain.stage != 2
            || l.gate.epoch()? != chain.epoch
        {
            return Err(invalid_owner());
        }
        let review = agent_metadata_images::review(a, r.revision)?;
        e.native_prepared(review).map_err(public)
    }
    pub(crate) fn images_prepare_failed(&self, w: &str, e: &Arc<Entry>) {
        let _ = e.cancel(Instant::now());
        if e.claimed() && !e.transferred() {
            if let Ok(o) = e.observation() {
                let _ = self.close_metadata_images(w, o.original.session_id.as_str());
            }
        }
    }
    pub(crate) fn images_prepare_gui_apply(
        &self,
        w: &str,
        session: &str,
        plan: &str,
    ) -> Result<Option<GuiClaim>, BridgeError> {
        let r = self.inner.lock();
        window(&r, w)?;
        let a = r
            .active
            .as_ref()
            .filter(|a| a.session.id == session)
            .ok_or_else(invalid_owner)?;
        if let Some(l) = a.session.agent_metadata_images_prepare.get() {
            let review = agent_metadata_images::review(a, r.revision)?;
            if review.original.plan_token.as_str() != plan
                || !l.same(a)
                || a.session.agent_metadata_images.get().is_some()
            {
                return Err(invalid_owner());
            }
            let claim = GuiClaim {
                session: a.session.clone(),
            };
            if let Err(error) = l.entry.transfer(None, &review) {
                let crossed = l.entry.transferred();
                drop(r);
                if crossed {
                    self.images_prepare_gui_failed(&claim);
                }
                return Err(public(error));
            }
            return Ok(Some(claim));
        }
        Ok(None)
    }
    pub(crate) fn images_prepare_gui_failed(&self, claim: &GuiClaim) {
        // Only THIS actual winning invocation can stop its transferred
        // original. A late predecessor cancellation cannot call this path.
        self.inner
            .trigger(&claim.session.id, Reason::CallerLost, Instant::now());
    }
}
fn origin(r: &Registry, session: &str, e: Option<&Arc<Entry>>) -> Result<(), BridgeError> {
    let Some(a) = r.active.as_ref().filter(|a| a.session.id == session) else {
        return if e.is_some() {
            Err(invalid_owner())
        } else {
            Ok(())
        };
    };
    match (a.session.agent_metadata_images_prepare.get(), e) {
        (None, None) => Ok(()),
        (Some(l), Some(e)) if Arc::ptr_eq(e, &l.entry) && l.same(a) && !e.transferred() => {
            l.control()
        }
        _ => Err(invalid_owner()),
    }
}
pub(super) fn preclaim(
    inner: &Inner,
    session: &str,
    e: Option<&Arc<Entry>>,
) -> Result<(), BridgeError> {
    origin(&inner.lock(), session, e)
}
pub(super) fn consume(
    a: &ActiveOwner,
    e: Option<&Arc<Entry>>,
    p: &mut EditPublication<'_>,
) -> Result<(), BridgeError> {
    let Some(l) = a.session.agent_metadata_images_prepare.get() else {
        return if e.is_none() {
            Ok(())
        } else {
            Err(invalid_owner())
        };
    };
    if !e.is_some_and(|e| Arc::ptr_eq(e, &l.entry)) || !l.same(a) {
        return Err(invalid_owner());
    }
    l.publication(p, 0)?;
    l.entry.enqueued().map_err(public)
}
pub(super) fn apply_allowed(a: &ActiveOwner) -> bool {
    let Some(l) = a.session.agent_metadata_images_prepare.get() else {
        return true;
    };
    let next = a
        .session
        .agent_metadata_images
        .get()
        .filter(|x| !x.entry.gui_owned())
        .map(|x| &x.entry);
    l.same(a) && l.entry.transferred_to(next)
}
pub(super) fn frame(
    a: &ActiveOwner,
    f: &ChildFrame,
    p: &mut EditPublication<'_>,
) -> Result<(), BridgeError> {
    let Some(l) = a.session.agent_metadata_images_prepare.get() else {
        return Ok(());
    };
    if l.entry.transferred() {
        return Ok(());
    }
    if !l.same(a) {
        return Err(invalid_owner());
    }
    match f {
        ChildFrame::MetadataImagesPrepared(_) => {
            if a.cleanup_start.is_some() {
                Ok(())
            } else {
                l.publication(p, 1)
            }
        }
        ChildFrame::MetadataImagesTerminal(_, _) => Ok(()),
        _ => Err(invalid_owner()),
    }
}
pub(super) fn cancellation_at(s: &Session, now: Instant) -> Option<(Instant, Reason)> {
    let l = s.agent_metadata_images_prepare.get()?;
    if l.entry.transferred() {
        return None;
    }
    if l.service
        .upgrade()
        .is_none_or(|service| service.native_history_current().is_err())
    {
        l.entry.unknown();
        s.resource_unknown.store(true, Ordering::SeqCst);
        return Some((now, Reason::CleanupUnknown));
    }
    match l.entry.native_stop(now) {
        Ok(t) => t.map(|at| (at, Reason::Cancelled)),
        Err(_) => {
            l.entry.unknown();
            s.resource_unknown.store(true, Ordering::SeqCst);
            Some((now, Reason::CleanupUnknown))
        }
    }
}
pub(super) fn unknown(s: &Session) {
    if let Some(l) = s.agent_metadata_images_prepare.get() {
        l.entry.unknown();
    }
}
pub(super) fn retired(r: &Registry, s: &Session, unknown: bool) {
    if let Some(l) = s.agent_metadata_images_prepare.get() {
        let known = !unknown
            && r.last.as_ref().is_some_and(|p| {
                p.session_id == s.id
                    && p.domain == EditDomain::MetadataImages
                    && p.phase == Phase::Final
                    && p.native_finality == NativeFinality::Settled
                    && !p.late_settled
            });
        if l.entry.retired(known).is_err() {
            l.entry.unknown();
        }
    }
}
