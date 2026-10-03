//! Test-build-only DATA taps on this exact saved owner. Inspect and Recover
//! retain distinct original Sessions; Registry.last is never their authority.
use super::*;
use crate::shell::installed_observation::recovery::{Admission, Control, Snapshot};

struct Original {
    owner: Arc<Session>, retired: bool, accepted: bool, terminal: Option<recovery_wire::Terminal>,
    projection: Option<recovery_wire::Projection>, review_minted: bool,
}
pub(super) struct Observation { control: Arc<Control>, originals: [Option<Original>; 2] }
fn index(action: recovery_wire::Action) -> usize { if action == recovery_wire::Action::Inspect { 0 } else { 1 } }

pub(super) fn qualified(inner: &Inner) -> bool {
    inner.domain == SavedCommandDomain::ProjectRecovery && inner.recovery_installed_selected()
        && inner.recovery_observation.lock().is_ok_and(|slot| slot.as_ref().is_some_and(|o| o.control.permits()))
}
pub(super) fn prepare(inner: &Inner, registry: &Registry, context: &Context) -> Result<(), BridgeError> {
    let slot = inner.recovery_observation.lock().map_err(|_| BridgeError::cleanup_unknown())?;
    let Some(observation) = slot.as_ref() else { return Ok(()); };
    let Context::ProjectRecovery(context) = context else { return Err(inner.domain.unavailable()); };
    let i = index(context.action);
    if inner.domain != SavedCommandDomain::ProjectRecovery || observation.originals[i].is_some()
        || (i == 0 && observation.originals[1].is_some())
        || (i == 1 && (!observation.originals[0].as_ref().is_some_and(|original|
            original.retired && original.review_minted && original.accepted
                && original.terminal.as_ref().is_some_and(|t| t.settled() && t.outcome == recovery_wire::Outcome::Complete))
            || registry.recovery_review.is_none())) {
        return Err(inner.domain.invalid_owner());
    }
    observation.control.claim(context.action)
}
pub(super) fn bind(inner: &Inner, owner: &Arc<Session>) -> Result<(), BridgeError> {
    let mut slot = inner.recovery_observation.lock().map_err(|_| BridgeError::cleanup_unknown())?;
    let Some(observation) = slot.as_mut() else { return Ok(()); };
    let Context::ProjectRecovery(context) = &owner.context else { return Err(inner.domain.unavailable()); };
    let i = index(context.action);
    if owner.domain != SavedCommandDomain::ProjectRecovery || observation.originals[i].is_some()
        || !observation.control.claimed(context.action)
        || observation.originals[1 - i].as_ref().is_some_and(|other| Arc::ptr_eq(&other.owner, owner)
            || other.owner.id == owner.id || other.owner.generation == owner.generation) {
        return Err(inner.domain.invalid_owner());
    }
    observation.originals[i] = Some(Original { owner: owner.clone(), retired: false, accepted: false,
        terminal: None, projection: None, review_minted: false });
    Ok(())
}
pub(super) fn retire(inner: &Inner, active: &Active, owner: &Arc<Session>, review_minted: bool) {
    if owner.domain != SavedCommandDomain::ProjectRecovery { return; }
    let Ok(mut slot) = inner.recovery_observation.lock() else { return; };
    let Some(observation) = slot.as_mut() else { return; };
    let Some(original) = observation.originals.iter_mut().flatten().find(|o| Arc::ptr_eq(&o.owner, owner)) else {
        observation.control.unavailable_witness(); return;
    };
    if original.retired || original.projection.is_some() { observation.control.unavailable_witness(); return; }
    original.retired = true;
    original.accepted = active.accepted && active.terminal;
    original.terminal = match &active.projection.result { Some(Terminal::ProjectRecovery(t)) => Some(t.clone()), _ => None };
    original.projection = active.projection.public().recovery().ok();
    original.review_minted = review_minted;
}

fn facts(inner: &Inner, owner: &Session, book: &Resources, retired: bool, accepted: bool,
    terminal: Option<&recovery_wire::Terminal>) -> Option<crate::shell::installed_observation::recovery::OriginalFacts> {
    use crate::shell::installed_observation::recovery::OriginalFacts;
    if owner.domain != SavedCommandDomain::ProjectRecovery || !book.recovery_selected { return None; }
    let startup = owner.startup.try_lock().ok()?;
    let native = book.recovery_installed.as_ref()?.try_lock().ok()?;
    let r = inner.lock();
    let active = r.active.as_ref().filter(|a| std::ptr::eq(Arc::as_ptr(&a.owner), owner));
    Some(OriginalFacts {
        domain: "project-recovery", id: owner.id.clone(), generation: owner.generation.clone(),
        inspection_joined: book.inspection_started && book.inspection_joined && !book.inspection_failed
            && book.inspection.is_none() && book.inspection_error.is_none(),
        acquisition_joined: book.acquisition_started && book.acquisition_joined && !book.acquisition_failed
            && book.acquisition.is_none() && book.acquisition_error.is_none(),
        attempted: startup.attempted,
        no_child: !startup.attempted && !startup.returned && !startup.failed && startup.child.is_none()
            && !book.acquisition_started && book.acquisition.is_none() && book.child.is_none() && native.no_child_effect(),
        child_waited_success: startup.returned && !startup.failed && book.child.is_some() && !book.wait_failed
            && book.waited.as_ref().is_some_and(ExitStatus::success),
        stdin_closed: book.write_end.as_ref().is_some_and(|v| v.sent && v.closed && !v.failed),
        stdout_eof_closed: book.out_end.as_ref().is_some_and(|v| v.frames == 2 && v.eof && v.closed && !v.failed && v.decoder_settled),
        stderr_eof_closed: book.err_end.as_ref().is_some_and(|v| v.frames == 0 && v.eof && v.closed && !v.failed),
        io_joined: book.writer.is_none() && book.stdout.is_none() && book.stderr.is_none()
            && !book.write_failed && !book.out_failed && !book.err_failed
            && book.write_end.is_some() && book.out_end.is_some() && book.err_end.is_some(),
        core_lifetime_settled: accepted && terminal.is_some_and(recovery_wire::Terminal::settled),
        runtime_ledger_settled: native.settled(),
        runtime_settlement_joined: book.recovery_started && book.recovery_joined && !book.recovery_failed
            && book.recovery_settlement.is_none() && matches!(book.recovery_return.as_ref(), Some(Ok(CloseOutcome::Settled))),
        driver_joined: owner.driver_joined.load(Ordering::SeqCst) && matches!(owner.driver_return.try_lock().ok()?.as_ref(), Some(Ok(()))),
        manager_joined: !owner.manager_failed.load(Ordering::SeqCst) && matches!(owner.manager_return.try_lock().ok()?.as_ref(), Some(Ok(()))),
        observer_joined: matches!(owner.observer_return.try_lock().ok()?.as_ref(), Some(Ok(true))),
        watchdog_joined: owner.watchdog_joined.load(Ordering::SeqCst) && !owner.watchdog_failed.load(Ordering::SeqCst)
            && matches!(owner.watchdog_return.try_lock().ok()?.as_ref(), Some(Ok(true))),
        retired_before_cutoff: retired, active_retained: active.is_some(),
        resource_unknown: owner.resource_unknown.load(Ordering::SeqCst) || active.is_some_and(|a| a.unknown)
            || inner.poisoned.load(Ordering::SeqCst),
    })
}
fn snapshot_with_book(inner: &Inner, owner: &Session, book: &Resources, original: Option<&Original>) -> Option<Snapshot> {
    let (accepted, terminal, projection, retired, review_minted) = {
        let r = inner.lock();
        if let Some(original) = original.filter(|o| o.retired) {
            (original.accepted, original.terminal.clone(), original.projection.clone()?, true, original.review_minted)
        } else {
            let active = r.active.as_ref().filter(|a| std::ptr::eq(Arc::as_ptr(&a.owner), owner))?;
            let terminal = match &active.projection.result { Some(Terminal::ProjectRecovery(t)) => Some(t.clone()), _ => None };
            (active.accepted && active.terminal, terminal, active.projection.public().recovery().ok()?, false, false)
        }
    };
    Some(Snapshot { facts: facts(inner, owner, book, retired, accepted, terminal.as_ref())?, projection,
        accepted, core_terminal: terminal.is_some(), core_fatal: terminal.as_ref().is_some_and(|t| t.lifetime.retained_failure()), review_minted })
}
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(super) fn settlement_hold(inner: &Inner, owner: &Session, book: &Resources) -> Option<Arc<Control>> {
    let control = {
        let slot = inner.recovery_observation.lock().ok()?;
        let observation = slot.as_ref()?;
        let original = observation.originals[1].as_ref()?;
        if !std::ptr::eq(Arc::as_ptr(&original.owner), owner) || !observation.control.cancel_case() { return None; }
        observation.control.clone()
    };
    if snapshot_with_book(inner, owner, book, None).is_some_and(|snapshot| control.prepare_hold(snapshot)) { Some(control) }
    else { control.unavailable_witness(); None } // Never suppress actual original closure.
}

impl SavedCommandOwner {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn observe_installed_recovery_selection(&self) -> Result<(), BridgeError> {
        let r = self.inner.lock();
        if self.inner.domain != SavedCommandDomain::ProjectRecovery || r.revision != 0 || r.active.is_some()
            || r.prepared.is_some() || r.last.is_some() || r.recovery_review.is_some() || r.disabled || r.stopping
            || r.document_lost || r.exhausted || self.inner.poisoned.load(Ordering::SeqCst)
            || !self.inner.recovery_installed_selected() {
            return Err(self.inner.domain.unavailable());
        }
        let slot = self.inner.recovery_observation.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if slot.is_some() { return Err(self.inner.domain.unavailable()); }
        // This is exactly ordinary Mac selection, before any observer token.
        Ok(())
    }
    pub(crate) fn installed_recovery_identity(&self) -> std::sync::Weak<()> { Arc::downgrade(&self.inner.observation_identity) }
    pub(crate) fn admit_installed_recovery_observation(&self, token: Admission) -> Result<(), BridgeError> {
        let r = self.inner.lock();
        if self.inner.domain != SavedCommandDomain::ProjectRecovery || !self.inner.recovery_installed_selected()
            || r.revision != 0 || r.active.is_some() || r.prepared.is_some() || r.last.is_some() || r.recovery_review.is_some()
            || r.disabled || r.stopping || r.document_lost || r.exhausted || self.inner.poisoned.load(Ordering::SeqCst) {
            return Err(self.inner.domain.unavailable());
        }
        let mut slot = self.inner.recovery_observation.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if slot.is_some() { return Err(self.inner.domain.unavailable()); }
        *slot = Some(Observation { control: token.consume(&self.inner.observation_identity)?, originals: [None, None] });
        Ok(())
    }
    pub(crate) fn installed_recovery_snapshot(&self, action: recovery_wire::Action) -> Option<Snapshot> {
        // Clone only these original identities/data, never a replacement owner
        // or a reconstructed finality receipt from the latest public operation.
        let original = {
            let slot = self.inner.recovery_observation.lock().ok()?;
            let original = slot.as_ref()?.originals[index(action)].as_ref()?;
            Original { owner: original.owner.clone(), retired: original.retired, accepted: original.accepted,
                terminal: original.terminal.clone(), projection: original.projection.clone(), review_minted: original.review_minted }
        };
        let book = original.owner.resources.try_lock().ok()?;
        snapshot_with_book(&self.inner, &original.owner, &book, Some(&original))
    }
}
