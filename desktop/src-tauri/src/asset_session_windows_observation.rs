//! Read-only C qualification projections of the original Windows document.
//! This module is compiled only by the exact installed-observer cfg in its
//! parent. No owner, admission grant, result setter, join, or native action.
use super::*;

pub(crate) struct WindowsSessionSnapshot {
    pub(crate) status: Value,
    pub(crate) owner: Option<Arc<OriginalWork>>,
    pub(crate) next_operation: u32,
    pub(crate) payloads: Vec<(String, u32, usize)>,
    pub(crate) owner_settled: bool,
    pub(crate) source_started: bool,
    pub(crate) source_settled: bool,
    pub(crate) empty: bool,
}
fn belongs(document: &Arc<Inner>, owner: &Arc<OriginalWork>) -> bool {
    owner.gui.document.upgrade().is_some_and(|actual| Arc::ptr_eq(document, &actual))
        && owner.gui.owner().is_some_and(|actual| Arc::ptr_eq(owner, &actual))
        && owner.id != 0
}
fn joined(document: &Arc<Inner>, owner: &Arc<OriginalWork>) -> bool {
    // All reads are nonwaiting. No observation calls join_if_ended, reconciles
    // the document, or replaces the original retirement mechanism.
    belongs(document, owner) && owner.ended.load(Ordering::SeqCst)
        && owner.retired.load(Ordering::SeqCst)
        && owner.coordinator.try_lock().is_ok_and(|book| book.handle.is_none() && book.receipt == JoinReceipt::Returned)
        && owner.child.try_lock().is_ok_and(|book| book.handle.is_none() && matches!(book.receipt, JoinReceipt::New | JoinReceipt::Returned))
        && owner.source.try_lock().is_ok_and(|book| book.not_started() || book.settled())
        && owner.gui.facts.try_lock().is_ok_and(|g| g.selected.is_none() && g.released && g.refusal.is_none()
            && (g.not_created || g.created && !g.constructing && !g.showing && g.response && g.destroyed && g.close_ack))
        && owner.gui.selected_images.try_lock().is_ok_and(|images| images.is_none())
}
impl DocumentBinding {
    // None means only temporary lock contention. Poisoned/unknown/exhausted
    // originals are an immediate observation refusal, not a retry-until-timeout.
    pub(crate) fn windows_session_snapshot(&self) -> Result<Option<WindowsSessionSnapshot>, ()> {
        let state = match self.inner.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(()),
        };
        if state.unknown || state.exhausted || state.next_operation > 32 { return Err(()); }
        let owner = state.slot.as_ref().map(|slot| slot.owner.clone());
        let (owner_settled, source_started, source_settled) = match &owner {
            Some(original) => {
                if !belongs(&self.inner, original) { return Err(()); }
                let source = match original.source.try_lock() {
                    Ok(source) => source,
                    Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
                    Err(std::sync::TryLockError::Poisoned(_)) => return Err(()),
                };
                let pair = (!source.not_started(), source.settled()); drop(source);
                (joined(&self.inner, original), pair.0, pair.1)
            },
            // Absence is only absence. It cannot be native finality evidence.
            None => (false, false, false),
        };
        Ok(Some(WindowsSessionSnapshot { status: serde_json::to_value(self.snapshot(&state)).map_err(|_| ())?, owner,
            next_operation: state.next_operation,
            payloads: state.records.iter().map(|record| (record.key.id.0.clone(), record.key.revision, Arc::as_ptr(&record.payload) as usize)).collect(), owner_settled, source_started, source_settled,
            empty: !state.session && !state.retiring && !state.lock_pending && session_data_empty(&state) }))
    }
    pub(crate) fn windows_original_settled(&self, owner: &Arc<OriginalWork>) -> bool { joined(&self.inner, owner) }
    pub(crate) fn windows_file_original_settled(&self, owner: &Arc<OriginalWork>, accepted: bool) -> bool {
        joined(&self.inner, owner)
            && owner.child.try_lock().is_ok_and(|book| book.handle.is_none() && book.receipt == JoinReceipt::Returned)
            && owner.source.try_lock().is_ok_and(|book| if accepted { !book.not_started() && book.settled() } else { book.not_started() })
            && owner.gui.facts.try_lock().is_ok_and(|g| g.dispatched && g.created && !g.not_created
                && g.response && g.accepted == accepted && !g.declined && g.accepted_at.is_some() == accepted
                && g.close_queued && g.release_queued && g.selected.is_none())
    }
    pub(crate) fn windows_session_final(&self, originals: &[Arc<OriginalWork>], quit: &Arc<OriginalWork>) -> bool {
        let Ok(state) = self.inner.state.try_lock() else { return false; };
        !state.unknown && !state.exhausted && state.stopping && state.quit_accepted
            && state.quit_cleanup_end.is_some() && !state.session && !state.retiring && !state.lock_pending
            && state.context.is_none() && state.records.is_empty() && state.assignments.is_empty()
            && session_data_empty(&state) && !state.github.native_work_pending() && state.github.material_settled()
            && !originals.is_empty() && originals.len() < 32
            && state.next_operation as usize == originals.len() + 1
            && originals.iter().enumerate().all(|(index, original)| original.id as usize == index + 1 && joined(&self.inner, original))
            && quit.id == state.next_operation && state.quit.as_ref().is_some_and(|actual| Arc::ptr_eq(actual, quit))
            && joined(&self.inner, quit) && quit.stopped()
            && quit.gui.facts.try_lock().is_ok_and(|g| g.dispatched && g.created && !g.not_created && g.response
                && g.accepted && !g.declined && g.accepted_at.is_some() && g.close_queued && g.release_queued)
    }
}
