//! A private link on an already prepared Import in the ORIGINAL EditOwner.
//! Only transient PreparedOriginal/Claim hold Session; the Config row does not.
use super::*;
use crate::{
    application_service::ApplicationService, application_service_host::NativeProject,
    asset_session::MetadataImagesAgentGate, service_metadata_images_protocol as p,
    service_metadata_images_requests as requests, service_protocol::Id,
};
use sha2::{Digest, Sha256};
use std::sync::Weak;

pub(crate) struct Link {
    pub entry: Arc<requests::Entry>,
    pub project: NativeProject,
    service: Weak<ApplicationService>,
    gate: MetadataImagesAgentGate,
    chain: Mutex<Chain>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    Apply,
    Terminal,
    Retired,
}
struct Chain {
    epoch: u64,
    stage: u8,
    pending: Option<(u64, Step)>,
    failed: bool,
}
pub(crate) struct PreparedOriginal {
    session: Arc<Session>,
    pub review: p::Review,
    pub end: Instant,
}
pub(crate) struct Claim {
    session: Arc<Session>,
    entry: Option<Arc<requests::Entry>>,
}
pub(crate) enum Decision {
    Observe,
    Apply(Claim),
}
fn public(e: crate::service_protocol::Error) -> BridgeError {
    crate::asset_session::application_service::public_error(e)
}
fn id(s: &str) -> Result<Id, BridgeError> {
    Id::parse(s).map_err(|_| invalid_owner())
}
fn window(r: &Registry, w: &str) -> Result<(), BridgeError> {
    if r.window.as_deref() != Some(w)
        || !r.document_bound
        || r.document_lost
        || r.disabled
        || r.exhausted
        || r.stopping
    {
        Err(invalid_owner())
    } else {
        Ok(())
    }
}
// A writer into a fixed hash/count, not an allocation of image/preview bytes.
struct Hasher {
    hash: Sha256,
    bytes: usize,
}
impl std::io::Write for Hasher {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(b.len())
            .filter(|n| *n <= images_wire::VIEW_LIMIT)
            .ok_or_else(|| std::io::Error::other("bounded image preview"))?;
        self.hash.update(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(super) fn review(a: &ActiveOwner, revision: u32) -> Result<p::Review, BridgeError> {
    if a.session.domain != EditDomain::MetadataImages
        || a.projection.phase != Phase::Reviewing
        || a.projection.native_reason != Reason::None
        || a.projection.native_finality != NativeFinality::Pending
        || a.projection.apply_submitted
        || a.cleanup_start.is_some()
        || a.unknown
        || !a.opened
        || !a.prepared
        || a.claimed_seq != 1
        || a.session.image_written.load(Ordering::Acquire) != 2
        || *a.session.stop.borrow()
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
    let prepared = d.prepared.as_ref().ok_or_else(invalid_owner)?;
    let context = d.context.as_ref().ok_or_else(invalid_owner)?;
    if d.intent != images_wire::Intent::Import
        || !context.valid()
        || !d.prepared_view_matches(&prepared.view)
        || prepared.revision != c.revision
        || d.selected.is_empty()
    {
        return Err(invalid_owner());
    }
    let files = prepared.view["files"]
        .as_array()
        .ok_or_else(invalid_owner)?;
    let mut counts = [0u32; 3];
    for f in files {
        let n = match f["action"].as_str() {
            Some("create") => 0,
            Some("replace") => 1,
            Some("preserve") => 2,
            _ => return Err(invalid_owner()),
        };
        counts[n] += 1;
    }
    let mut hash = Hasher {
        hash: Sha256::new(),
        bytes: 0,
    };
    serde_json::to_writer(&mut hash, &prepared.view).map_err(|_| invalid_owner())?;
    let r = p::Review {
        original: p::Original {
            session_id: id(&a.session.id)?,
            owner_generation: id(&a.projection.owner_generation)?,
            revision: id(&c.revision)?,
            plan_token: id(&prepared.plan_token)?,
            draft_revision: prepared.draft_revision,
            baseline_generation: prepared.baseline_generation,
        },
        native_status_revision: revision,
        platform: match context.platform {
            metadata_wire::Platform::Android => p::Platform::Android,
            metadata_wire::Platform::Ios => p::Platform::Ios,
        },
        locale: context.locale.clone(),
        asset_type: context.asset_type.clone(),
        file_count: files.len() as u32,
        create_count: counts[0],
        replace_count: counts[1],
        preserve_count: counts[2],
        selected_bytes: d
            .selected
            .iter()
            .try_fold(0u32, |sum, x| sum.checked_add(x.byte_length))
            .ok_or_else(invalid_owner)?,
        prepared_sha256: format!("{:x}", hash.hash.finalize()),
    };
    r.validate().map_err(public)?;
    Ok(r)
}
impl Link {
    fn chain(&self) -> Result<MutexGuard<'_, Chain>, BridgeError> {
        self.chain.lock().map_err(|_| {
            self.entry.unknown();
            edit_unknown()
        })
    }
    pub(crate) fn begin(&self, p: &RegistrationPublisher, step: Step) -> Result<(), BridgeError> {
        if self.entry.gui_owned() {
            return Ok(());
        }
        if !self.gate.same_publisher(p)
            || self
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
        let mut c = self.chain()?;
        let next = match step {
            Step::Apply => 0,
            Step::Terminal => 1,
            Step::Retired => 2,
        };
        let good = !c.failed
            && c.pending.is_none()
            && c.stage == next
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
    pub(crate) fn accepted(
        &self,
        p: &RegistrationPublisher,
        step: Step,
    ) -> Result<(), BridgeError> {
        if self.entry.gui_owned() {
            return Ok(());
        }
        let mut c = self.chain()?;
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
    fn publication(&self, p: &mut EditPublication<'_>, step: Step) -> Result<(), BridgeError> {
        if self.entry.gui_owned() {
            return Ok(());
        }
        if let Some(p) = p.owned.as_mut() {
            self.begin(p, step)?;
            p.accept(crate::android_registration_app_protocol::Reason::ContextChanged)?;
            self.accepted(p, step)
        } else if let Some(p) = p.borrowed {
            let c = self.chain()?;
            if step != Step::Apply
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
    pub(crate) fn images_has_lease(&self, session: &str) -> bool {
        self.inner.lock().active.as_ref().is_some_and(|a| {
            a.session.id == session && a.session.agent_metadata_images.get().is_some()
        })
    }
    pub(crate) fn images_prepared(
        &self,
        w: &str,
        expected: &p::Original,
        revision: u32,
    ) -> Result<PreparedOriginal, BridgeError> {
        let r = self.inner.lock();
        window(&r, w)?;
        let a = r.active.as_ref().ok_or_else(invalid_owner)?;
        let current = review(a, r.revision)?;
        if a.session.agent_metadata_images_prepare.get().is_some_and(|l|!l.entry.reviewing(&current)){return Err(invalid_owner());}
        if current.original != *expected
            || revision != r.revision
            || a.session.agent_metadata_images.get().is_some()
        {
            return Err(invalid_owner());
        }
        Ok(PreparedOriginal {
            session: a.session.clone(),
            review: current,
            end: a.review_end,
        })
    }
    pub(crate) fn images_install(
        &self,
        w: &str,
        original: PreparedOriginal,
        project: NativeProject,
        scope: requests::Scope,
        nonce: Id,
        service: &Arc<ApplicationService>,
        gate: MetadataImagesAgentGate,
    ) -> Result<(), BridgeError> {
        let epoch = gate.epoch()?;
        if epoch != project.input_revision {
            return Err(invalid_owner());
        }
        let grant = requests::Grant {
            id: Id::random().map_err(public)?,
            end: original.end.min(scope.read.end()),
            scope,
            review: original.review.clone(),
            wake: Arc::downgrade(&original.session.wake),
        };
        let preparation={
            let r=self.inner.lock();let a=r.active.as_ref().filter(|a|Arc::ptr_eq(&a.session,&original.session)).ok_or_else(invalid_owner)?;
            a.session.agent_metadata_images_prepare.get().map(|l|l.entry.clone())
        };
        service
            .configuration_requests()
            .images_install_with_preparation(nonce, grant, preparation.as_ref(), |entry| {
                let r = self.inner.lock();
                window(&r, w).map_err(|_| crate::service_protocol::Error::Conflict)?;
                let a = r
                    .active
                    .as_ref()
                    .filter(|a| Arc::ptr_eq(&a.session, &original.session))
                    .ok_or(crate::service_protocol::Error::Conflict)?;
                if review(a, r.revision).map_err(|_| crate::service_protocol::Error::Conflict)?
                    != original.review
                    || a.projection.project_id != project.runtime_id
                    || gate.epoch().ok() != Some(epoch)
                {
                    return Err(crate::service_protocol::Error::Conflict);
                }
                a.session
                    .agent_metadata_images
                    .set(Arc::new(Link {
                        entry: entry.clone(),
                        project,
                        gate,
                        service: Arc::downgrade(service),
                        chain: Mutex::new(Chain {
                            epoch,
                            stage: 0,
                            pending: None,
                            failed: false,
                        }),
                    }))
                    .map_err(|_| crate::service_protocol::Error::Conflict)
            })
            .map_err(public)?;
        original.session.wake.notify_waiters();
        Ok(())
    }
    pub(crate) fn images_link(&self, w: &str, session: &str) -> Result<Arc<Link>, BridgeError> {
        let r = self.inner.lock();
        window(&r, w)?;
        r.active
            .as_ref()
            .filter(|a| a.session.domain == EditDomain::MetadataImages && a.session.id == session)
            .and_then(|a| a.session.agent_metadata_images.get())
            .cloned()
            .ok_or_else(invalid_owner)
    }
    pub(crate) fn images_preclaim(
        &self,
        w: &str,
        session: &str,
        plan: &str,
        entry: Option<&Arc<requests::Entry>>,
    ) -> Result<Decision, BridgeError> {
        let r = self.inner.lock();
        window(&r, w)?;
        let a = r
            .active
            .as_ref()
            .filter(|a| a.session.id == session)
            .ok_or_else(invalid_owner)?;
        let link = a
            .session
            .agent_metadata_images
            .get()
            .ok_or_else(invalid_owner)?;
        let g = link.entry.grant.as_ref().ok_or_else(invalid_owner)?;
        if g.review.original.plan_token.as_str() != plan {
            return Err(invalid_owner());
        }
        if let Some(e) = entry {
            if !Arc::ptr_eq(e, &link.entry) {
                return Err(invalid_owner());
            }
            if !e.pending().map_err(public)? {
                return Ok(Decision::Observe);
            }
        }
        if review(a, r.revision)? != g.review {
            return Err(invalid_owner());
        }
        if let Some(e) = entry {
            if !e.preclaim().map_err(public)? {
                return Ok(Decision::Observe);
            }
        } else {
            link.entry.gui_claim().map_err(public)?;
        }
        let claim = Claim { session: a.session.clone(), entry: entry.cloned() };
        if let Some(p)=a.session.agent_metadata_images_prepare.get(){
            // Both real rows already exist. Under this SAME Registry cut the
            // predecessor retires only its control; the successor keeps READ.
            // A cancellation/overflow at transfer after the real winning
            // preclaim must STOP that original, never orphan/rearm its claim.
            if let Err(error) = p.entry.transfer(entry,&g.review) {
                drop(r);
                self.images_claim_failed(&claim);
                return Err(public(error));
            }
        }
        Ok(Decision::Apply(claim))
    }
    pub(crate) fn apply_images_claimed(
        &self,
        publisher: &RegistrationPublisher,
        w: &str,
        session: &str,
        plan: &str,
        root: RegisteredEditRoot,
        claim: &Claim,
    ) -> Result<MetadataImagesEditStatus, BridgeError> {
        self.apply_domain_images(
            Some(publisher),
            w,
            EditDomain::MetadataImages,
            session,
            plan,
            Some(root),
            false,
            None,
            None,
            None,
            None,
            Some(claim),
        )?
        .metadata_images()
    }
    pub(crate) fn images_claim_failed(&self, claim: &Claim) {
        if let Some(e) = &claim.entry {
            let _ = e.cancel(Instant::now());
        }
        self.inner
            .trigger(&claim.session.id, Reason::CallerLost, Instant::now());
    }
    pub(crate) fn images_relay_lost(&self) {
        if let Some(l) = self
            .inner
            .lock()
            .active
            .as_ref()
            .and_then(|a| a.session.agent_metadata_images.get())
        {
            let _ = l.entry.revoke(Instant::now());
        }
    }
}
pub(super) fn consume(
    a: &ActiveOwner,
    claim: Option<&Claim>,
    publication: &mut EditPublication<'_>,
) -> bool {
    let Some(l) = a.session.agent_metadata_images.get() else {
        return claim.is_none();
    };
    let Some(c) = claim.filter(|c| Arc::ptr_eq(&c.session, &a.session)) else {
        return false;
    };
    match &c.entry {
        Some(e) if Arc::ptr_eq(e, &l.entry) => {
            l.publication(publication, Step::Apply).is_ok() && e.enqueue().is_ok()
        }
        None => l.entry.gui_owned(),
        _ => false,
    }
}
pub(super) fn cancellation_at(session: &Session, now: Instant) -> Option<(Instant, Reason)> {
    let l = session.agent_metadata_images.get()?;
    if l.entry.input().is_none() || l.entry.gui_owned() {
        return None;
    }
    if l.service
        .upgrade()
        .is_none_or(|s| s.native_history_current().is_err())
    {
        l.entry.unknown();
        session.resource_unknown.store(true, Ordering::SeqCst);
        return Some((now, Reason::CleanupUnknown));
    }
    match l.entry.stop_at(now) {
        Ok(t) => t.map(|t| (t, Reason::Cancelled)),
        Err(_) => {
            l.entry.unknown();
            session.resource_unknown.store(true, Ordering::SeqCst);
            Some((now, Reason::CleanupUnknown))
        }
    }
}
pub(super) fn unknown(session: &Session) {
    if let Some(l) = session.agent_metadata_images.get() {
        l.entry.unknown();
    }
}
pub(super) fn frame(
    a: &ActiveOwner,
    frame: &ChildFrame,
    p: &mut EditPublication<'_>,
) -> Result<(), BridgeError> {
    let Some(l) = a.session.agent_metadata_images.get() else {
        return Ok(());
    };
    if l.entry.gui_owned() {
        return Ok(());
    }
    if let ChildFrame::MetadataImagesTerminal(_, result) = frame {
        let c = result.outcome();
        if c.reason == CoreReason::None
            && matches!(c.effect, Effect::Committed | Effect::Unchanged)
            && c.resources == ResourceState::Settled
        {
            return l.publication(p, Step::Terminal);
        }
        Ok(())
    } else {
        Err(invalid_owner())
    }
}
fn completed(p: &EditProjection) -> bool {
    p.apply_submitted
        && p.native_reason == Reason::None
        && p.core_outcome.as_ref().is_some_and(|c| {
            c.reason == CoreReason::None
                && c.resources == ResourceState::Settled
                && p.metadata_images.as_ref().is_some_and(|d| {
                    d.intent == images_wire::Intent::Import
                        && d.terminal_admissible(true, c)
                        && d.prepared
                            .as_ref()
                            .and_then(|r| images_wire::expected_success(&r.view))
                            == Some((c.effect.clone(), c.journal.clone()))
                })
        })
}
pub(super) fn retirement_publication(a: &mut ActiveOwner, p: &mut EditPublication<'_>) -> bool {
    let Some(l) = a.session.agent_metadata_images.get() else {
        return true;
    };
    if l.entry.gui_owned() {
        return true;
    }
    let current = l.entry.stop_at(Instant::now()).is_ok_and(|v| v.is_none())
        && l.publication(p, Step::Retired).is_ok();
    if !current && completed(&a.projection) {
        a.unknown = true;
        a.projection.native_reason = Reason::CallerLost;
    }
    current
}
fn final_data(pj: &EditProjection, unknown: bool, current: bool) -> Option<p::Final> {
    if unknown
        || pj.domain != EditDomain::MetadataImages
        || pj.phase != Phase::Final
        || pj.native_finality != NativeFinality::Settled
        || pj.late_settled
    {
        return None;
    }
    let done = completed(pj);
    if done && !current {
        return None;
    }
    let (effect, journal) = match pj.core_outcome.as_ref() {
        Some(c)
            if c.resources == ResourceState::Settled
                && pj
                    .metadata_images
                    .as_ref()
                    .is_some_and(|d| d.terminal_admissible(pj.apply_submitted, c)) =>
        {
            (
                match c.effect {
                    Effect::NotStarted => p::Effect::NotStarted,
                    Effect::Unchanged => p::Effect::Unchanged,
                    Effect::Committed => p::Effect::Committed,
                    Effect::RolledBack => p::Effect::RolledBack,
                    Effect::Unknown => return None,
                },
                match c.journal {
                    Journal::NotCreated => p::Journal::NotCreated,
                    Journal::Clean => p::Journal::Clean,
                    Journal::RecoveryRequired => p::Journal::RecoveryRequired,
                    Journal::Unknown => return None,
                },
            )
        }
        None if !pj.apply_submitted => (p::Effect::NotStarted, p::Journal::NotCreated),
        _ => return None,
    };
    Some(p::Final {
        effect,
        journal,
        cancelled: pj.native_reason != Reason::None,
        apply_submitted: pj.apply_submitted,
        completed: done,
    })
}
pub(super) fn retired(r: &Registry, session: &Session, unknown: bool, current: bool) {
    let Some(l) = session.agent_metadata_images.get() else {
        return;
    };
    let original = r.last.as_ref().filter(|p| p.session_id == session.id);
    let service_current = l.entry.input().is_none()
        || l.entry.gui_owned()
        || l.service
            .upgrade()
            .is_some_and(|s| s.native_history_current().is_ok());
    let result = original.and_then(|p| final_data(p, unknown, current && service_current));
    if l.entry.retired(result).is_err() {
        l.entry.unknown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p::fixtures::{id as test_id, original};
    fn projection() -> EditProjection {
        EditProjection {
            domain: EditDomain::MetadataImages,
            project_id: "project".into(),
            session_id: "a".repeat(32),
            owner_generation: "b".repeat(32),
            phase: Phase::Reviewing,
            review_remaining_ms: 900000,
            checkout: None,
            prepared: None,
            recovery: None,
            workflow: None,
            metadata_text: None,
            release_version: None,
            metadata_images: None,
            initialization: None,
            identity: None,
            apply_submitted: false,
            core_outcome: None,
            native_reason: Reason::None,
            native_finality: NativeFinality::Pending,
            late_settled: false,
        }
    }
    fn details(preserve: bool) -> images_wire::Details {
        let item = "f".repeat(32);
        let digest = "9".repeat(64);
        let path = "public/store/android/en-US/images/phoneScreenshots/01.png";
        let summary = json!({"byteLength":1,"sha256":digest,"format":"png","width":1,"height":1,"headerChecked":true});
        let before = if preserve {
            summary.clone()
        } else {
            Value::Null
        };
        let view = json!({"kind":"import","policy":"metadata-images-v1","platform":"android","locale":"en-US","assetType":"phoneScreenshots",
            "metadataRoot":"public/store","folder":"public/store/android/en-US/images/phoneScreenshots",
            "files":[{"itemId":item,"displayName":"01.png","path":path,"action":if preserve{"preserve"}else{"create"},"before":before,"selected":summary,"after":summary,"canReplace":false,"issues":[]}],
            "existing":if preserve{json!([{"path":path,"summary":summary}])}else{json!([])},"finalOrder":[path],"valid":true,"issues":[],
            "assurance":{"localCopyOnly":true,"sourceFilesUnchanged":true,"storeContacted":false,"fullDecode":false,"contentApproved":false,"storeAccepted":false}});
        let baseline = images_wire::Baseline {
            config: images_wire::ContentDigest {
                byte_length: 2,
                sha256: "1".repeat(64),
            },
            ignore: images_wire::ContentDigest {
                byte_length: 0,
                sha256: "2".repeat(64),
            },
            inventory_sha256: "3".repeat(64),
        };
        images_wire::Details {
            intent: images_wire::Intent::Import,
            context: Some(images_wire::Context {
                platform: metadata_wire::Platform::Android,
                locale: "en-US".into(),
                asset_type: "phoneScreenshots".into(),
            }),
            selected: vec![images_wire::SelectedItem {
                item_id: item.clone(),
                display_name: "01.png".into(),
                byte_length: 1,
                sha256: digest,
            }],
            checkout: Some(images_wire::Checkout {
                revision: "c".repeat(32),
                baseline: baseline.clone(),
                view: view.clone(),
            }),
            submission: Some(images_wire::Submission {
                expected_baseline: baseline,
                choices: vec![images_wire::Choice {
                    item_id: item,
                    replace_existing: false,
                }],
            }),
            prepared: Some(images_wire::Prepared {
                revision: "c".repeat(32),
                plan_token: "d".repeat(32),
                draft_revision: 1,
                baseline_generation: 1,
                view,
            }),
        }
    }
    #[test]
    fn no_actual_image_original_or_retained_status_can_mint_private_apply_lease() {
        let owner = EditOwner::new(RuntimeConfig::packaged(PathBuf::from(
            "/never-opened-image-original",
        )));
        owner.initial_document("main").unwrap();
        let o = original();
        assert!(owner.images_prepared("main", &o, 0).is_err());
        assert!(owner
            .images_preclaim("main", o.session_id.as_str(), o.plan_token.as_str(), None)
            .is_err());
        assert!(!owner.images_has_lease(o.session_id.as_str()));
        let mut p = projection();
        p.metadata_images = Some(details(false));
        owner.inner.lock().last = Some(p);
        assert!(owner.images_prepared("main", &o, 0).is_err());
        assert!(owner.inner.lock().active.is_none());
    }
    #[test]
    fn completed_image_data_needs_exact_import_effect_and_actual_retirement_axes() {
        for preserve in [false, true] {
            let mut p = projection();
            let d = details(preserve);
            assert!(d.prepared_view_matches(&d.prepared.as_ref().unwrap().view));
            p.metadata_images = Some(d);
            p.apply_submitted = true;
            let (effect, journal) = if preserve {
                (Effect::Unchanged, Journal::NotCreated)
            } else {
                (Effect::Committed, Journal::Clean)
            };
            p.core_outcome = Some(wire::CoreEditOutcome {
                effect: effect.clone(),
                journal: journal.clone(),
                resources: ResourceState::Settled,
                reason: CoreReason::None,
            });
            assert!(final_data(&p, false, true).is_none());
            p.phase = Phase::Final;
            p.native_finality = NativeFinality::Settled;
            assert!(final_data(&p, false, true).unwrap().completed);
            assert!(final_data(&p, true, true).is_none());
            assert!(final_data(&p, false, false).is_none());
            p.late_settled = true;
            assert!(final_data(&p, false, true).is_none());
            p.late_settled = false;
            p.core_outcome.as_mut().unwrap().effect = if preserve {
                Effect::Committed
            } else {
                Effect::Unchanged
            };
            assert!(final_data(&p, false, true).is_none());
            p.core_outcome.as_mut().unwrap().effect = effect;
            p.apply_submitted = false;
            assert!(final_data(&p, false, true).is_none());
        }
        let mut p = projection();
        p.phase = Phase::Final;
        p.native_finality = NativeFinality::Settled;
        p.metadata_images = Some(images_wire::Details::recovery());
        assert!(!final_data(&p, false, true).is_some_and(|f| f.completed));
        let mut o = original();
        o.plan_token = test_id('c');
        assert!(o.validate().is_err());
    }
    #[test]
    fn image_original_buffer_helper_advances_only_after_owned_buffer_return() {
        // Actual fixed drop+Release helper, not an async write/STOP/EOF proof.
        // Only write_requests calls it after its SAME successful future returns.
        let counter = std::sync::atomic::AtomicUsize::new(0);
        let other = std::sync::atomic::AtomicUsize::new(0);
        let open = vec![1u8; 1024];
        assert_eq!(counter.load(Ordering::Acquire), 0);
        image_buffer_returned(&counter, open, 1);
        assert_eq!(counter.load(Ordering::Acquire), 1);
        let prepare = vec![2u8; 1024];
        assert_ne!(counter.load(Ordering::Acquire), 2);
        // Holding/dropping an unrelated or partially-written buffer does not
        // enter the helper or change the original counter.
        drop(vec![3u8; 1024]);
        assert_eq!(counter.load(Ordering::Acquire), 1);
        image_buffer_returned(&counter, prepare, 2);
        assert_eq!(counter.load(Ordering::Acquire), 2);
        assert_eq!(other.load(Ordering::Acquire), 0);
    }
}
