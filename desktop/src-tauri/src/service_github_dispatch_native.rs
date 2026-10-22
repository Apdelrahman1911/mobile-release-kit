//! Typed adapters into the existing three native paths; no runner or private
//! input comes from an ID-only CLI Submit. The shell supplies original app-data.
use super::*;
impl DocumentBinding {
    pub(super) fn github_dispatch_agent_start(
        &self,
        entry: &Arc<r::Entry>,
        app_data: Option<std::path::PathBuf>,
    ) -> Result<(), BridgeError> {
        use p::Kind as K;
        let kind = entry.scope().review.kind();
        let input = {
            let s = self.lock();
            match kind {
                K::PreflightPrepare
                | K::PreflightDispatch
                | K::PreflightPending
                | K::PreflightObserve => s.github.preflight_agent_input(entry),
                K::ReleasePrepare | K::ReleaseDispatch | K::ReleasePending | K::ReleaseObserve => {
                    s.github.release_agent_input(entry)
                }
                K::CounterPrepare
                | K::CounterCreate
                | K::PublicationPending
                | K::CounterReconcile => s.github.counter_agent_input(entry),
                _ => Err(BridgeError::invalid()),
            }
        }?;
        if input.kind() != kind {
            return Err(BridgeError::invalid());
        }
        match kind {
            K::PreflightPrepare
            | K::PreflightDispatch
            | K::PreflightPending
            | K::PreflightObserve => {
                self.github_preflight_execute(input.preflight_command()?, Some(entry.clone()))?;
            }
            K::ReleasePrepare | K::ReleaseDispatch | K::ReleasePending | K::ReleaseObserve => {
                self.github_release_execute(input.release_command()?, Some(entry.clone()))?;
            }
            K::CounterPrepare | K::CounterCreate | K::PublicationPending | K::CounterReconcile => {
                if matches!(kind, K::CounterPrepare | K::CounterCreate) && app_data.is_none() {
                    return Err(BridgeError::invalid());
                }
                self.github_publication_execute(
                    input.counter_command()?,
                    app_data,
                    Some(entry.clone()),
                )?;
            }
            _ => return Err(BridgeError::invalid()),
        }
        Ok(())
    }
}

/// Same48KiB MAIN allowance, with actual native typed cells. The new family
/// refuses an unsupported ABI; it does not borrow a retained row or IPC worker.
pub(super) fn main_call_bytes() -> Option<usize> {
    use std::mem::size_of;
    use native::dispatch::{ROOT_BACKING, INPUT_BACKING, CONTEXT_BACKING};
    [
        // First Capture+NativeProject, then current root/Capture/NativeProject.
        // The current pair is explicitly dropped before constructing the scope.
        5 * ROOT_BACKING,
        // Immutable Allow and both captures; valid() only borrows their fields.
        3 * INPUT_BACKING,
        2 * CONTEXT_BACKING,
        4096, // original MAIN raw argument, still owned by the same Tauri caller
        r::NativeScope::unused_main_backing()?,
        2 * size_of::<native::Review>(),
        2 * size_of::<NativeProject>(),
        size_of::<crate::asset_source::RegisteredRoot>(),
        size_of::<Allow>(),
        2 * size_of::<crate::edit_owner::SavedEditStamp>(),
        2048, // bounded fixed hashes/IDs, validation temporaries and stack control
    ].into_iter().try_fold(0usize, |n,v| n.checked_add(v))
}
pub(super) fn main_call_fits() -> bool {
    main_call_bytes().is_some_and(|n| n <= p::MAIN_CALL_BACKING)
}
