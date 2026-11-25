//! Nonshipping observations of the SAME tool SavedOwner. No fake Session,
//! source snapshot, runtime permit, second clock, or qualification factory.
use super::*;
use crate::shell::installed_observation::tool_setup::{Case, Control, Registration};
use std::path::PathBuf;

/// Fixed DATA copied only at the original owner's accepted retirement point.
/// This is not a join/copy/picker permission, and retains no original Session.
#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Sample {
    #[serde(skip)]
    operation: [u8; 32],
    #[serde(skip)]
    generation: [u8; 32],
    pub(crate) action: wire::Action,
    pub(crate) outcome: Option<wire::Outcome>,
    pub(crate) reason: wire::Reason,
    pub(crate) first_failure: bool,
    pub(crate) same_active: bool,
    pub(crate) accepted: bool,
    pub(crate) terminal: bool,
    pub(crate) current: bool,
    pub(crate) all_joined: bool,
    pub(crate) source_inspected: bool,
    pub(crate) source_failure: Option<wire::Reason>,
    pub(crate) source_closed: bool,
    pub(crate) cache_closed: bool,
    pub(crate) runtime_closed: bool,
    pub(crate) cache_attempted: bool,
    pub(crate) ca_armed: bool,
    pub(crate) transfer_attempted: bool,
    pub(crate) child_attempted: bool,
    pub(crate) child_waited: bool,
    pub(crate) io_joined: bool,
    pub(crate) complete_sdk_location: bool,
    pub(crate) reuse_selected: bool,
}
impl Sample {
    pub(crate) fn original_ids(&self) -> ([u8;32],[u8;32]) { (self.operation,self.generation) }
    pub(crate) fn cancelled_in_transfer(&self) -> bool {
        self.originals() && self.action == wire::Action::Acquire && self.source_inspected
            && self.source_failure.is_none() && self.first_failure && self.accepted && self.terminal
            && self.outcome == Some(wire::Outcome::Cancelled) && self.reason == wire::Reason::Cancelled
            && self.cache_attempted && self.ca_armed && self.transfer_attempted
            && self.child_attempted && self.child_waited && self.io_joined
            && !self.complete_sdk_location && !self.reuse_selected
    }
    pub(crate) fn same_operation(&self, operation: &[u8; 32], generation: &[u8; 32]) -> bool {
        &self.operation == operation && &self.generation == generation
    }
    pub(crate) fn matches(&self, projection: &wire::Projection) -> bool {
        projection.operation_id.as_bytes() == self.operation
            && projection.owner_generation.as_bytes() == self.generation
            && projection.context.action == self.action
            && projection.outcome == self.outcome
            && projection.reason == self.reason
            && projection.phase == wire::Phase::Terminal
    }
    fn originals(&self) -> bool {
        self.same_active
            && self.all_joined
            && self.source_closed
            && self.cache_closed
            && self.runtime_closed
    }
    pub(crate) fn complete(&self) -> bool {
        self.originals()
            && self.accepted
            && self.terminal
            && self.current
            && !self.first_failure
            && self.outcome == Some(wire::Outcome::Complete)
            && self.reason == wire::Reason::None
            && self.child_attempted
            && self.child_waited
            && self.io_joined
    }
    pub(crate) fn initial(&self) -> bool {
        self.complete()
            && self.action == wire::Action::Inspect
            && self.source_inspected
            && self.source_failure.is_none()
            && !self.reuse_selected
            && !self.cache_attempted
            && !self.ca_armed
            && !self.complete_sdk_location
    }
    pub(crate) fn acquired(&self) -> bool {
        self.complete()
            && self.action == wire::Action::Acquire
            && self.source_inspected
            && self.source_failure.is_none()
            && self.cache_attempted
            && self.ca_armed
            && self.transfer_attempted
            && self.complete_sdk_location
            && !self.reuse_selected
    }
    pub(crate) fn reused(&self) -> bool {
        self.complete()
            && self.action == wire::Action::Inspect
            && !self.source_inspected
            && self.source_failure.is_none()
            && self.reuse_selected
            && !self.cache_attempted
            && !self.ca_armed
            && !self.complete_sdk_location
    }
    pub(crate) fn cancelled_before_transfer(&self) -> bool {
        self.originals()
            && self.action == wire::Action::Acquire
            && self.source_inspected
            && self.source_failure.is_none()
            && self.first_failure
            && self.outcome == Some(wire::Outcome::Cancelled)
            && self.reason == wire::Reason::Cancelled
            && !self.transfer_attempted
            && !self.child_attempted
            && !self.child_waited
            && !self.complete_sdk_location
            && !self.reuse_selected
    }
    pub(crate) fn refused_source(&self) -> bool {
        self.originals()
            && self.action == wire::Action::Acquire
            && self.source_inspected
            && self.source_failure == Some(self.reason)
            && self.first_failure
            && matches!(
                self.outcome,
                Some(wire::Outcome::Refused | wire::Outcome::Failed)
            )
            && matches!(
                self.reason,
                wire::Reason::ExistingToolsIncompatible | wire::Reason::Stale
            )
            && !self.cache_attempted
            && !self.ca_armed
            && !self.transfer_attempted
            && !self.child_attempted
            && !self.child_waited
            && !self.complete_sdk_location
            && !self.reuse_selected
    }
}

fn control(inner: &Inner) -> Option<Arc<Control>> {
    let binding = inner.tool_acquisition.get()?;
    let control = binding.observation.get()?.upgrade()?;
    let document = binding.document.upgrade()?;
    control.bound(&document).then_some(control)
}
pub(super) fn selected(inner: &Inner) -> bool {
    let Some(binding) = inner.tool_acquisition.get() else {
        return false;
    };
    control(inner)
        .zip(binding.document.upgrade())
        .is_some_and(|(c, d)| c.permits(&d))
}
pub(super) fn charge(inner: &Inner) -> Option<usize> {
    let Some(binding) = inner.tool_acquisition.get() else {
        return Some(0);
    };
    let Some(weak) = binding.observation.get() else {
        return Some(0);
    };
    weak.upgrade()?.retained_bytes()
}
pub(super) fn claim_prepare(inner: &Inner, context: &wire::Context, root: &RegisteredRoot) -> bool {
    if NATIVE_QUALIFIED
        && inner
            .tool_acquisition
            .get()
            .is_none_or(|b| b.observation.get().is_none())
    {
        return true;
    }
    control(inner)
        .is_some_and(|c| selected(inner) && root.path == c.project() && c.claim_prepare(context))
}

/// Called by the existing driver after its inspection handle returned, before
/// runtime transfer/spawn. No Document, IO or native Book lock is taken here.
pub(in crate::saved_command_owner) fn before_transfer(
    book: &super::super::Resources,
    inner: &Inner,
    owner: &Session,
) -> bool {
    let Some(control) = control(inner) else {
        return true;
    };
    if control.case() != Case::CancelBeforeTransfer
        || !matches!(&owner.context, Context::ToolAcquisition(c) if c.action == wire::Action::Acquire)
    {
        return true;
    }
    if !selected(inner)
        || !book.tools.selected
        || !book.inspection_started
        || !book.inspection_joined
        || book.inspection_failed
        || book.inspection_error.is_some()
        || book.inspection.is_some()
        || book.acquisition_started
        || book.acquisition_joined
        || book.acquisition.is_some()
        || !control.cancel_checkpoint(&owner.id, &owner.generation)
    {
        inner.stop(owner, Reason::ContextChanged);
        return false;
    }
    // SAME owner/clock/first-F path as a real Cancel. Never set a fake finality
    // bit, force a cleanup result, or reinterpret normal input shutdown STOP.
    inner.stop(owner, Reason::Cancelled);
    false
}

pub(super) fn returned(
    inner: &Inner,
    r: &super::super::Registry,
    active: &Active,
    owner: &Arc<Session>,
) {
    let Some(intent) = &owner.tools.intent else {
        return;
    };
    let Some(control) = control(inner) else {
        return;
    };
    let result = (|| {
        let Context::ToolAcquisition(context) = &owner.context else {
            return None;
        };
        let current =
            !active.context_invalidated && !r.document_lost && !r.stopping && intent.current();
        let complete_sdk_location = r
            .tool_acquisition
            .completed_sources
            .as_ref()
            .is_some_and(|c| c.observed_sdk(&owner.id, &owner.generation).is_some());
        let book = owner.resources.try_lock().ok()?;
        let original = book.tools.original.as_ref()?.try_lock().ok()?;
        let (
            source_inspected,
            source_failure,
            source_closed,
            runtime_closed,
            cache_closed,
            cache_attempted,
            ca_armed,
            transfer_attempted,
        ) = original.observation();
        let startup = owner.startup.try_lock().ok()?;
        let io_joined = book.writer.is_none()
            && book.stdout.is_none()
            && book.stderr.is_none()
            && !book.write_failed
            && !book.out_failed
            && !book.err_failed
            && book
                .write_end
                .as_ref()
                .is_some_and(|v| v.sent && v.closed && !v.failed)
            && book
                .out_end
                .as_ref()
                .is_some_and(|v| v.eof && v.closed && !v.failed && v.decoder_settled)
            && book
                .err_end
                .as_ref()
                .is_some_and(|v| v.eof && v.closed && !v.failed && v.decoder_settled);
        let sample = Sample {
            operation: owner.id.as_bytes().try_into().ok()?,
            generation: owner.generation.as_bytes().try_into().ok()?,
            action: context.action,
            outcome: active.projection.outcome.map(Outcome::tools),
            reason: active.projection.reason.tools().ok()?,
            first_failure: active.first_stop.is_some(),
            same_active: Arc::ptr_eq(&active.owner, owner),
            accepted: active.accepted,
            terminal: active.terminal,
            current,
            all_joined: false,
            source_inspected,
            source_failure,
            source_closed,
            runtime_closed,
            cache_closed,
            cache_attempted,
            ca_armed,
            transfer_attempted,
            child_attempted: startup.attempted,
            child_waited: book.waited.is_some() && !book.wait_failed && book.child.is_none(),
            io_joined,
            complete_sdk_location,
            reuse_selected: matches!(&active.projection.result, Some(Terminal::ToolAcquisition(t))
                if t.protected_tools() == Some(wire::ProtectedTools::ReuseSelected)
                    && t.components() == Some(wire::components::Partition::compatible_all())),
        };
        drop(startup);
        drop(original);
        drop(book);
        Some(Sample {
            all_joined: !active.unknown && active.final_join_seen && original_joined(owner),
            ..sample
        })
    })();
    if let Some(sample) = result {
        control.record(sample);
    } else {
        control.fail();
    }
}

impl SavedCommandOwner {
    pub(crate) fn bind_installed_tool_setup(
        &self,
        document: &Arc<()>,
        token: Registration,
    ) -> Result<Arc<Control>, BridgeError> {
        self.require_domain(SavedCommandDomain::ToolAcquisition)?;
        let binding = self
            .inner
            .tool_acquisition
            .get()
            .ok_or_else(wire::invalid)?;
        let r = self
            .inner
            .registry
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if binding.document.as_ptr() != Arc::as_ptr(document)
            || r.active.is_some()
            || r.prepared.is_some()
            || r.last.is_some()
            || r.disabled
            || r.stopping
            || r.document_lost
            || r.exhausted
            || binding.observation.get().is_some()
        {
            return Err(wire::invalid());
        }
        let control = token.consume(document)?;
        binding
            .observation
            .set(Arc::downgrade(&control))
            .map_err(|_| wire::invalid())?;
        // No native call, execution, source read, or new runtime admission.
        Ok(control)
    }
    pub(crate) fn installed_tool_setup_control(&self, document: &Arc<()>) -> Option<Arc<Control>> {
        control(&self.inner).filter(|control| control.bound(document))
    }
    pub(crate) fn installed_tool_setup_all_locations(
        &self, document: &Arc<()>, operation: &str, generation: &str,
    ) -> Option<[PathBuf;3]> {
        let control = self.installed_tool_setup_control(document)?;
        if !control.permits(document) || control.case() != Case::ColdWarm { return None; }
        self.inner.registry.try_lock().ok()?.tool_acquisition.completed_sources.as_ref()?
            .observed_all(operation,generation)
    }
    pub(crate) fn installed_tool_setup_sdk_location(
        &self,
        document: &Arc<()>,
        operation: &str,
        generation: &str,
    ) -> Option<PathBuf> {
        let control = self.installed_tool_setup_control(document)?;
        if !control.permits(document) || control.case() != Case::RoundTrip {
            return None;
        }
        let r = self.inner.registry.try_lock().ok()?;
        r.tool_acquisition
            .completed_sources
            .as_ref()?
            .observed_sdk(operation, generation)
    }
}
