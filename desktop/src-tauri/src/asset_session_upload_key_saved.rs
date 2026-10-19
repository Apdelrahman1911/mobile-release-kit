//! Upload-key comparison loan of the SAME original returned saved observation.
//! Child of asset_session_saved_observation; no reader, process or DTO authority.
use super::*;
use sha2::{Digest, Sha256};

pub(crate) struct UploadKeySavedInput {
    document: Weak<Inner>,
    lane: Arc<SavedObservationLane>,
    native: Arc<NativeContext>,
    config_bytes: u32,
    config_sha256: String,
    draft_sha256: String,
}
impl UploadKeySavedInput {
    pub(crate) fn config_bytes(&self) -> u32 {
        self.config_bytes
    }
    pub(crate) fn config_sha256(&self) -> &str {
        &self.config_sha256
    }
    pub(crate) fn draft_sha256(&self) -> &str {
        &self.draft_sha256
    }
    /// Atomic original-lane veto only. Full Document/Edit rematch occurs in
    /// the original parent gate. No mutex/IO is introduced under native Start.
    pub(crate) fn current(&self) -> bool {
        self.document.upgrade().is_some_and(|document| {
            self.lane.returned()
                && document
                    .android_registration_control
                    .matches_epoch(self.lane.epoch)
                && document.bridge.registry_generation() == self.lane.registration
        })
    }
    pub(crate) fn matches(
        &self,
        document: &Arc<()>,
        registration: u32,
        root: &asset_source::RegisteredRoot,
        runtime_project: &str,
    ) -> bool {
        self.current()
            && self.lane.registration == registration
            && &self.lane.root == root
            && self.lane.project_id == runtime_project
            && self
                .document
                .upgrade()
                .is_some_and(|original| Arc::ptr_eq(&original.session_identity, document))
    }
    pub(crate) fn same_original(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.document, &other.document)
            && Arc::ptr_eq(&self.lane, &other.lane)
            && Arc::ptr_eq(&self.native, &other.native)
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        // Conservative separate producer charge even though the Doc also owns
        // these originals. Never substitute zero after a lost census borrow.
        std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<NativeContext>())?
            .checked_add(self.native.draft.capacity())?
            .checked_add(self.native.project_id.capacity())?
            .checked_add(self.native.project.path.capacity())?
            .checked_add(self.config_sha256.capacity())?
            .checked_add(self.draft_sha256.capacity())?
            .checked_add(std::mem::size_of::<SavedObservationLane>())?
            .checked_add(self.lane.retained_heap_bytes()?)?
            .checked_add(8 * std::mem::size_of::<usize>())
    }
}
impl DocumentBinding {
    pub(in crate::asset_session) fn upload_key_saved_input(
        &self,
        state: &DocumentState,
        native: &Arc<NativeContext>,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
    ) -> Result<Arc<UploadKeySavedInput>, BridgeError> {
        let binding = state.saved_input.as_ref().ok_or_else(stale)?;
        if native.platform != Platform::Android
            || native.draft.is_empty()
            || native.draft.len() > commands::DRAFT_LIMIT
            || !state
                .context
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, native))
            || !state
                .saved_observation
                .as_ref()
                .is_some_and(|lane| Arc::ptr_eq(lane, &binding.lane))
            || !binding.lane.returned()
            || !edit.matches(&binding.lane.stamp)
            || binding.lane.project_id != native.project_id
            || binding.lane.registration != native.registry_generation
            || binding.lane.root != native.project
            || !self
                .inner
                .android_registration_control
                .matches_epoch(binding.lane.epoch)
            || !self
                .inner
                .bridge
                .native_project(&native.project_id)
                .is_ok_and(|(g, r)| g == binding.lane.registration && r == binding.lane.root)
        {
            return Err(stale());
        }
        let saved = Arc::new(UploadKeySavedInput {
            document: Arc::downgrade(&self.inner),
            lane: binding.lane.clone(),
            native: native.clone(),
            config_bytes: binding.comparison.config_bytes,
            config_sha256: crate::service_protocol::hex(&binding.comparison.config_sha256),
            draft_sha256: format!("{:x}", Sha256::digest(&native.draft)),
        });
        if !(1..=512 * 1024).contains(&saved.config_bytes) || !saved.current() {
            return Err(stale());
        }
        Ok(saved)
    }
    pub(in crate::asset_session) fn recheck_upload_key_saved_input(
        &self,
        state: &DocumentState,
        saved: &Arc<UploadKeySavedInput>,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
    ) -> Result<(), BridgeError> {
        // Equal bytes from a replacement observation are not this original.
        let binding = state.saved_input.as_ref().ok_or_else(stale)?;
        if !Arc::ptr_eq(&saved.lane, &binding.lane)
            || !state
                .saved_observation
                .as_ref()
                .is_some_and(|lane| Arc::ptr_eq(lane, &saved.lane))
            || !state
                .context
                .as_ref()
                .is_some_and(|native| Arc::ptr_eq(native, &saved.native))
            || !edit.matches(&saved.lane.stamp)
            || !saved.matches(
                &self.inner.session_identity,
                saved.native.registry_generation,
                &saved.native.project,
                &saved.native.project_id,
            )
            || !self
                .inner
                .bridge
                .native_project(&saved.native.project_id)
                .is_ok_and(|(g, r)| g == saved.lane.registration && r == saved.lane.root)
        {
            return Err(stale());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn equal_returned_lane_bytes_are_not_original_binding() {
        let (first, _) = SavedObservationCompletion::control_fixture();
        let (second, _) = SavedObservationCompletion::control_fixture();
        assert_eq!(first.lane.project_id, second.lane.project_id);
        assert!(first.lane.root == second.lane.root);
        assert!(!Arc::ptr_eq(&first.lane, &second.lane));
        // No positive native observation is minted by this inert fixture.
        assert!(!first.lane.returned() && !second.lane.returned());
    }
}
