//! Weak same-assignment witness for a joined current-iOS-inventory read.
//! Child of the original material module: no key bytes, new loan or authority.
use super::*;
use std::sync::Weak;

pub(crate) struct StoreVersionMaterial {
    native: Weak<NativeContext>,
    payload: Weak<Payload>,
    key: RecordKey,
    context: wire::Context,
}
impl SelectedStoreMaterial {
    pub(crate) fn version_inventory_witness(
        &self,
    ) -> Result<Option<StoreVersionMaterial>, BridgeError> {
        let Some(StoreCommand::Access(context)) = &self.command else {
            return Err(refused());
        };
        if !wire::store_versions::selected(context) {
            return Ok(None);
        }
        if !self.matches(
            context,
            self.native.registry_generation,
            &self.native.project,
        ) || apple_parts(&self.payload).is_none()
            || self.supplemental.iter().any(Option::is_some)
        {
            return Err(refused());
        }
        Ok(Some(StoreVersionMaterial {
            native: Arc::downgrade(&self.native),
            payload: Arc::downgrade(&self.payload),
            key: self.key.clone(),
            context: context.clone(),
        }))
    }
}
impl StoreVersionMaterial {
    pub(crate) fn matches_context(&self, context: &wire::Context) -> bool {
        &self.context == context
    }
    fn current(
        &self,
        state: &DocumentState,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> bool {
        let (Some(native), Some(payload)) = (self.native.upgrade(), self.payload.upgrade()) else {
            return false;
        };
        state
            .context
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &native))
            && native.execution_mode == commands::ExecutionMode::Local
            && native.platform == Platform::Ios
            && matches!(native.purpose, Purpose::Store | Purpose::Full)
            && native.project_id == self.context.project_id
            && native.registry_generation == registration
            && native.project == *root
            && native.revision == self.context.credential_context_revision
            && self.key.id.0 == self.context.record_id
            && self.key.revision == self.context.record_revision
            && github_secret::assigned(state, &self.key, Kind::AscP8, &native)
                .is_some_and(|assigned| Arc::ptr_eq(assigned, &payload))
            && apple_parts(&payload).is_some()
    }
    pub(crate) fn backing_bytes() -> usize {
        // A Weak may keep its original Arc allocation, but never the dropped
        // Payload fields/material or NativeContext heap. Include those cells.
        std::mem::size_of::<Self>()
            + std::mem::size_of::<NativeContext>()
            + std::mem::size_of::<Payload>()
            + 6 * std::mem::size_of::<usize>()
            + wire::IPC_LIMIT
            + 32
    }
}
impl DocumentBinding {
    /// Called by the eventual allocation admission/ACK/edit gates while THEY
    /// hold this actual Doc lock. No IO, second read or public receipt input.
    pub(in crate::asset_session) fn current_store_version_observation(
        &self,
        state: &DocumentState,
        original: &crate::saved_command_owner::StoreVersionObservation,
        registration: u32,
        root: &asset_source::RegisteredRoot,
        max_age: u64,
    ) -> bool {
        !state.unknown
            && !state.exhausted
            && !state.stopping
            && !state.retiring
            && !state.quit_pending
            && !state.lock_pending
            && self.native_qualified()
            && (!encrypted_mode(state) || self.persistence_qualified())
            && original.current(Instant::now(), std::time::SystemTime::now(), max_age)
            && original.matches_root(registration, root)
            && original.material().matches_context(original.context())
            && original.material().current(state, registration, root)
    }
}

#[cfg(all(
    test,
    any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )
    )
))]
mod tests {
    use super::*;
    // Existing synthetic assigned-P8 model; this tests WEAK custody only, not
    // a native read, authenticated key or a mintable Store observation.
    #[test]
    fn weak_version_material_does_not_keep_private_payload_or_allow_context_aba() {
        let mut state = super::super::tests::apple_model();
        let mut context = wire::tests::context();
        context.project_id = "inert-project".into();
        context.platform = wire::AccessPlatform::Ios;
        context.credential_context_revision = 2;
        context.record_id = "a".repeat(32);
        context.record_revision = 1;
        let mut input = serde_json::json!(context);
        input.as_object_mut().unwrap().remove("operation");
        input["query"] = serde_json::json!(wire::store_versions::QUERY);
        let context = wire::prepare(&input).unwrap().context();
        let root = state.context.as_ref().unwrap().project.clone();
        let loan = borrow_preflight_material(&state, &context, 7, &root).unwrap();
        let witness = loan.version_inventory_witness().unwrap().unwrap();
        let weak = witness.payload.clone();
        assert!(witness.current(&state, 7, &root));
        let old = state.context.take().unwrap();
        state.context = Some(Arc::new(NativeContext {
            revision: old.revision,
            execution_mode: old.execution_mode,
            project_id: old.project_id.clone(),
            project: old.project.clone(),
            registry_generation: old.registry_generation,
            draft: old.draft.clone(),
            platform: old.platform,
            stage: old.stage,
            purpose: old.purpose,
        }));
        assert!(!witness.current(&state, 7, &root));
        state.context = Some(old);
        assert!(witness.current(&state, 7, &root));
        drop(loan);
        state.records.clear();
        state.assignments.clear();
        assert!(weak.upgrade().is_none());
        assert!(!witness.current(&state, 7, &root));
    }
}
