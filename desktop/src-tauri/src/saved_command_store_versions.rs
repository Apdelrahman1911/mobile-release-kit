//! One current-iOS-inventory observation on the existing SavedCommandOwner.
//! Native final retirement is the only mint; summary DATA cannot construct it.
use super::*;
use crate::{
    asset_session::StoreVersionMaterial, local_store_preflight_protocol::store_versions as wire,
};
use std::{
    sync::Weak,
    time::{SystemTime, UNIX_EPOCH},
};

struct Clock {
    admitted: Instant,
    sampled: Instant,
    wall: SystemTime,
    observed_at: u64,
}
impl Clock {
    fn sample(admitted: Instant, sampled: Instant, wall: SystemTime) -> Option<Self> {
        // The earliest native admission, not end-of-query receipt time. Rounding
        // down only ages the observation; no new max-age window is minted.
        let elapsed = sampled.checked_duration_since(admitted)?;
        let observed_at = wall
            .checked_sub(elapsed)?
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_secs();
        if observed_at > i64::MAX as u64 {
            return None;
        }
        Some(Self {
            admitted,
            sampled,
            wall,
            observed_at,
        })
    }
    fn fresh(&self, now: Instant, wall: SystemTime, max_age: u64) -> bool {
        if !(1..=3600).contains(&max_age) {
            return false;
        }
        let (Some(age), Some(elapsed), Ok(wall_elapsed)) = (
            now.checked_duration_since(self.admitted),
            now.checked_duration_since(self.sampled),
            wall.duration_since(self.wall),
        ) else {
            return false;
        };
        // Both native clocks must still agree. Clock rollback/jumps refuse;
        // never replace the original endpoint or infer freshness from a GET.
        age < Duration::from_secs(max_age)
            && elapsed.abs_diff(wall_elapsed) <= Duration::from_secs(1)
    }
}
struct Pending {
    original: Weak<Session>,
    material: StoreVersionMaterial,
    clock: Clock,
}
fn original_veto(active: &Active, owner: &Session) -> bool {
    // owner.stop is also the normal transport signal sent after a successful
    // terminal to close finished stdin. Only the original failure/currentness
    // facts veto this read; the independent final-join checks remain below.
    active.unknown
        || active.context_invalidated
        || active.first_stop.is_some()
        || active.projection.reason != Reason::None
        || owner.resource_unknown.load(Ordering::SeqCst)
}
pub(crate) struct StoreVersionObservation {
    context: store_wire::Context,
    registration: u32,
    project: RegisteredRoot,
    summary: wire::Summary,
    material: StoreVersionMaterial,
    clock: Clock,
    invalid: AtomicBool,
}
impl StoreVersionObservation {
    pub(crate) fn context(&self) -> &store_wire::Context {
        &self.context
    }
    pub(crate) fn summary(&self) -> &wire::Summary {
        &self.summary
    }
    pub(crate) fn observed_at(&self) -> u64 {
        self.clock.observed_at
    }
    pub(crate) fn material(&self) -> &StoreVersionMaterial {
        &self.material
    }
    pub(crate) fn matches_root(&self, registration: u32, project: &RegisteredRoot) -> bool {
        self.registration == registration && self.project == *project
    }
    pub(crate) fn current(&self, now: Instant, wall: SystemTime, max_age: u64) -> bool {
        !self.invalid.load(Ordering::SeqCst) && self.clock.fresh(now, wall, max_age)
    }
}
#[derive(Default)]
pub(super) struct Slot {
    pending: Option<Pending>,
    observation: Option<Arc<StoreVersionObservation>>,
}
impl Slot {
    pub(super) fn invalidate(&mut self) {
        if let Some(original) = self.observation.take() {
            original.invalid.store(true, Ordering::SeqCst);
        }
        // Pending has no jobs, key material or close authority; the original
        // Session remains independently retained by Registry until real joins.
        self.pending = None;
    }
    pub(super) fn arm(&mut self, original: &Arc<Session>, material: StoreVersionMaterial) -> bool {
        self.invalidate();
        let Context::LocalStorePreflight(context) = &original.context else {
            return false;
        };
        if original.domain != SavedCommandDomain::LocalStorePreflight
            || !wire::selected(context)
            || !material.matches_context(context)
        {
            return false;
        }
        let Some(clock) =
            Clock::sample(original.clocks.admitted, Instant::now(), SystemTime::now())
        else {
            return false;
        };
        self.pending = Some(Pending {
            original: Arc::downgrade(original),
            material,
            clock,
        });
        true
    }
    /// Called ONLY after the original successful watchdog return has been
    /// recorded, clock checked and material retired in reconcile(). No public
    /// terminal/status or a replacement same-ID session can enter this method.
    pub(super) fn record_original(&mut self, active: &Active, owner: &Arc<Session>, allowed: bool) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        let Context::LocalStorePreflight(context) = &owner.context else {
            return;
        };
        let Some(Terminal::LocalStorePreflight(terminal)) = &active.projection.result else {
            return;
        };
        if !allowed
            || !pending
                .original
                .upgrade()
                .is_some_and(|original| Arc::ptr_eq(&original, owner))
            || !Arc::ptr_eq(&active.owner, owner)
            || original_veto(active, owner)
            || !active.accepted
            || !active.terminal
            || !active.final_join_seen
            || active.projection.phase != Phase::Terminal
            || active.projection.outcome != Some(Outcome::Complete)
            || active.projection.context != owner.context
            || active.projection.operation_id != owner.id
            || active.projection.owner_generation != owner.generation
            || !owner.watchdog_joined.load(Ordering::SeqCst)
            || owner.watchdog_failed.load(Ordering::SeqCst)
            || owner.manager_failed.load(Ordering::SeqCst)
            || !owner.material_retired.load(Ordering::SeqCst)
            || !owner
                .watchdog_return
                .lock()
                .is_ok_and(|value| matches!(value.as_ref(), Some(Ok(true))))
            || !pending.material.matches_context(context)
            || !pending.clock.fresh(Instant::now(), SystemTime::now(), 3600)
        {
            return;
        }
        let Some(summary) = terminal.current_versions_data(context) else {
            return;
        };
        self.observation = Some(Arc::new(StoreVersionObservation {
            context: context.clone(),
            registration: owner.registration,
            project: owner.project.clone(),
            summary: summary.clone(),
            material: pending.material,
            clock: pending.clock,
            invalid: AtomicBool::new(false),
        }));
    }
}
impl SavedCommandOwner {
    /// Native-only original. Caller must additionally rematch its actual Doc,
    /// source and weak credential assignment immediately before CAS and edit.
    pub(crate) fn current_store_versions(
        &self,
        context: &store_wire::Context,
        registration: u32,
        project: &RegisteredRoot,
    ) -> Result<Arc<StoreVersionObservation>, BridgeError> {
        self.require_domain(SavedCommandDomain::LocalStorePreflight)?;
        self.reconcile();
        let r = self.inner.lock();
        if r.disabled
            || r.exhausted
            || r.stopping
            || r.document_lost
            || r.active.is_some()
            || r.prepared.is_some()
            || self.inner.poisoned.load(Ordering::SeqCst)
        {
            return Err(store_wire::invalid());
        }
        r.store_versions
            .observation
            .as_ref()
            .filter(|o| {
                o.context == *context
                    && o.matches_root(registration, project)
                    && o.current(Instant::now(), SystemTime::now(), 3600)
            })
            .cloned()
            .ok_or_else(store_wire::invalid)
    }
}
pub(crate) fn document_backing_bytes() -> Option<usize> {
    // One pending input, one latest receipt + one possible admitted consumer.
    // Both copies stay conservatively reserved even after invalidation. These
    // are bounded native cells/DATA, not child Python/Ruby heap/RSS or code128M.
    let one = std::mem::size_of::<StoreVersionObservation>()
        .checked_add(StoreVersionMaterial::backing_bytes())?
        .checked_add(store_wire::IPC_LIMIT)?
        .checked_add(crate::asset_source::PATH_LIMIT)?
        .checked_add(2048)?;
    std::mem::size_of::<Slot>()
        .checked_add(std::mem::size_of::<Pending>())?
        .checked_add(std::mem::size_of::<Session>())?
        .checked_add(one.checked_mul(3)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn earliest_clock_not_receipt_time_controls_freshness() {
        let admitted = Instant::now();
        let sampled = admitted + Duration::from_secs(30);
        let wall = UNIX_EPOCH + Duration::from_secs(2000);
        let clock = Clock::sample(admitted, sampled, wall).unwrap();
        assert_eq!(clock.observed_at, 1970);
        assert!(clock.fresh(sampled, wall, 31));
        assert!(!clock.fresh(sampled, wall, 30));
        assert!(!clock.fresh(
            sampled + Duration::from_secs(1),
            wall - Duration::from_secs(1),
            900
        ));
        assert!(!clock.fresh(
            sampled + Duration::from_secs(1),
            wall + Duration::from_secs(9),
            900
        ));
        assert!(Clock::sample(sampled, admitted, wall).is_none());
        assert!(Clock::sample(admitted, sampled, UNIX_EPOCH + Duration::from_secs(1)).is_none());
    }
    #[test]
    fn weak_slot_has_no_receipt_from_dto_or_new_read() {
        let mut slot = Slot::default();
        assert!(slot.observation.is_none());
        slot.invalidate();
        assert!(slot.pending.is_none());
        assert!(slot.observation.is_none());
        assert!(document_backing_bytes().is_some_and(|b| b < 256 * 1024));
    }
    #[test]
    fn normal_terminal_transport_close_is_not_a_failure_or_receipt() {
        // Existing inert Session DATA and the ACTUAL terminal/stop handlers.
        // No runtime, credential, watchdog join or positive receipt is made.
        let mut input = serde_json::to_value(store_wire::tests::context()).unwrap();
        input.as_object_mut().unwrap().remove("operation");
        input["platform"] = serde_json::json!("ios");
        input["query"] = serde_json::json!(wire::QUERY);
        let context = store_wire::prepare(&input).unwrap().context();
        let application = SavedCommandOwner::new(
            RuntimeConfig::packaged("/unopened-store-version-runtime".into()),
            SavedCommandDomain::LocalStorePreflight,
        );
        let (application, owner) = super::super::tests::active_with_context(
            application,
            Context::LocalStorePreflight(context.clone()),
        );
        let mut value = store_wire::tests::complete();
        value["context"] = serde_json::json!(context);
        value["lifetime"]["commands"] = serde_json::json!(7);
        value["lifetime"]["commandDispatched"] = serde_json::json!(true);
        value["result"] = serde_json::json!({"schemaVersion":1,"scope":wire::SCOPE,
            "findings":[],"limitations":wire::LIMITATIONS,"currentVersions":{
                "observation":"observed","coverage":wire::COVERAGE,"revision":"a".repeat(64),
                "counts":{"builds":0,"buildUploads":0,"appStoreVersions":0},"maxBuild":0,
                "marketingVersion":null,"historicalUniqueness":"not-established"}});
        let terminal: store_wire::Terminal = serde_json::from_value(value).unwrap();
        assert!(terminal.current_versions_data(&context).is_some());
        application.inner.accept(
            &owner,
            Frame::LocalStorePreflight(store_wire::Frame::Accepted),
        );
        application.inner.accept(
            &owner,
            Frame::LocalStorePreflight(store_wire::Frame::Terminal(terminal)),
        );
        {
            let r = application.inner.lock();
            let active = r.active.as_ref().unwrap();
            assert!(*owner.stop.borrow()); // Actual normal terminal closes input.
            assert!(active.first_stop.is_none());
            assert!(!original_veto(active, &owner));
            assert!(!active.final_join_seen && !owner.watchdog_joined.load(Ordering::SeqCst));
            assert!(owner.watchdog_return.lock().unwrap().is_none());
            assert!(r.store_versions.observation.is_none());
        }
        // A genuine cancellation still vetoes even though transport STOP was
        // already true. It does not need a second watch-channel transition.
        application.inner.stop(&owner, Reason::Cancelled);
        let r = application.inner.lock();
        let active = r.active.as_ref().unwrap();
        assert!(active.first_stop.is_some());
        assert!(original_veto(active, &owner));
        assert!(r.store_versions.observation.is_none());
    }
}
