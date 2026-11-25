//! Narrow borrower of the original SavedObservation lane and Edit stamp.
//! No Android request is fabricated to obtain a saved-input grant. The copied
//! digests/counters are comparisons; only the same retained lane can match.
use super::*;
use crate::apple_provisioning_protocol as provisioning;

fn comparison_matches(comparison: &SavedComparisonData, context: &provisioning::Context) -> bool {
    context.saved_config.bytes == comparison.config_bytes
        && SavedComparisonData::digest(&context.saved_config.sha256)
            == Some(comparison.config_sha256)
        && context.saved_version.bytes == comparison.version_bytes
        && SavedComparisonData::digest(&context.saved_version.sha256)
            == Some(comparison.version_sha256)
        && context.saved_version.source.as_bytes()
            == &comparison.source[..usize::from(comparison.source_len)]
        && context.saved_version.name.as_bytes()
            == &comparison.name[..usize::from(comparison.name_len)]
        && context.saved_version.build == comparison.build
}

pub(crate) struct AppleProvisioningSavedInput {
    document: Weak<Inner>,
    lane: Arc<SavedObservationLane>,
    comparison: SavedComparisonData,
}
impl AppleProvisioningSavedInput {
    #[cfg(test)]
    pub(in crate::asset_session) fn unreturned_census_data() -> Self {
        // Existing control fixture retains its original RESERVED lane; never
        // call arm/complete/returned or install a saved-input observation.
        let (completion, probe) = SavedObservationCompletion::control_fixture();
        assert!(!probe.returned() && !probe.completion_returned() && !probe.has_binding());
        let lane = Arc::clone(&completion.lane);
        drop((completion, probe));
        assert!(!lane.returned());
        Self { document: Weak::new(), lane, comparison: SavedComparisonData {
            source: [0; 512], source_len: 0, name: [0; 64], name_len: 0, build: 0,
            config_bytes: 0, config_sha256: [0; 32], version_bytes: 0, version_sha256: [0; 32] } }
    }

    pub(in crate::asset_session) fn same_binding(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.document, &other.document)
            && Arc::ptr_eq(&self.lane, &other.lane)
            && self.lane.returned()
            && other.lane.returned()
    }
    pub(in crate::asset_session) fn current_locked(
        &self,
        document: &Arc<Inner>,
        state: &DocumentState,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
        context: &provisioning::Context,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> bool {
        self.document
            .upgrade()
            .is_some_and(|original| Arc::ptr_eq(&original, document))
            && self.lane.returned()
            && self.lane.project_id == context.project_id
            && self.lane.registration == registration
            && self.lane.root == *root
            && state.saved_input.as_ref().is_some_and(|current| {
                Arc::ptr_eq(&current.lane, &self.lane)
                    && comparison_matches(&current.comparison, context)
            })
            && comparison_matches(&self.comparison, context)
            && edit.matches(&self.lane.stamp)
            && document
                .android_registration_control
                .matches_epoch(self.lane.epoch)
            && document.bridge.registry_generation() == registration
    }
    pub(in crate::asset_session) fn epoch(&self) -> u64 {
        self.lane.epoch
    }
    pub(in crate::asset_session) fn retained_heap_bytes(&self) -> Option<usize> {
        self.lane
            .retained_heap_bytes()?
            .checked_add(std::mem::size_of::<Self>())
    }
}

impl DocumentBinding {
    pub(in crate::asset_session) fn apple_provisioning_saved_input(
        &self,
        state: &DocumentState,
        context: &provisioning::Context,
        registration: u32,
        root: &asset_source::RegisteredRoot,
        edit: &crate::edit_owner::SavedEditGuard<'_>,
    ) -> Result<AppleProvisioningSavedInput, BridgeError> {
        let original = state
            .saved_input
            .as_ref()
            .filter(|input| input.lane.returned())
            .ok_or_else(stale)?;
        let input = AppleProvisioningSavedInput {
            document: Arc::downgrade(&self.inner),
            lane: original.lane.clone(),
            comparison: original.comparison,
        };
        if !input.current_locked(&self.inner, state, edit, context, registration, root) {
            return Err(stale());
        }
        Ok(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn native_saved_comparison_includes_config_and_whole_version_without_minting_lane() {
        let context = provisioning::prepare(&json!({"projectId":"fixture","draftRevision":1,"baselineGeneration":1,
            "savedConfig":{"bytes":20,"sha256":"a".repeat(64)},
            "savedVersion":{"source":"version.properties","bytes":25,"sha256":"b".repeat(64),"name":"1.2.3","build":2},
            "credentialContextRevision":1,"recordId":"c".repeat(32),"recordRevision":1,"executionMode":"local","platform":"ios",
            "mode":"review","reference":null,"newApplication":false,"displayName":"Exact label"})).unwrap().context;
        let mut source = [0u8; 512];
        source[..18].copy_from_slice(b"version.properties");
        let mut name = [0u8; 64];
        name[..5].copy_from_slice(b"1.2.3");
        let comparison = SavedComparisonData {
            source,
            source_len: 18,
            name,
            name_len: 5,
            build: 2,
            config_bytes: 20,
            config_sha256: [0xaa; 32],
            version_bytes: 25,
            version_sha256: [0xbb; 32],
        };
        assert!(comparison_matches(&comparison, &context));
        for part in 0..6 {
            let mut changed = context.clone();
            match part {
                0 => changed.saved_config.bytes += 1,
                1 => changed.saved_config.sha256 = "d".repeat(64),
                2 => changed.saved_version.sha256 = "d".repeat(64),
                3 => changed.saved_version.source = "other.properties".into(),
                4 => changed.saved_version.name = "1.2.4".into(),
                _ => changed.saved_version.build += 1,
            }
            assert!(!comparison_matches(&comparison, &changed));
        }
    }
}
