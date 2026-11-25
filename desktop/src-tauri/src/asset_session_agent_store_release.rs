//! Closed release dispatch under the SAME Document, grant and Saved owner.
use super::*;

impl DocumentBinding {
    pub(super) fn agent_store_release_material(
        &self,
        state: &DocumentState,
        approval: &AgentStoreApproval,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> Result<Arc<SelectedStoreMaterial>, BridgeError> {
        let r = approval.review();
        match r.kind {
            p::Kind::Execute => {
                let m = self
                    .inner
                    .bridge
                    .local_store_execute
                    .prepared_material(r.operation_id.as_str(), r.owner_generation.as_str())?;
                self.recheck_store_execute_material(state, &m, registration, root)?;
                self.store_execute_budget(state, &m)?;
                Ok(m)
            }
            p::Kind::Reconcile => {
                let m = self
                    .inner
                    .bridge
                    .local_store_reconcile
                    .prepared_material(r.operation_id.as_str(), r.owner_generation.as_str())?;
                self.recheck_store_reconcile_material(state, &m, registration, root)?;
                self.store_reconcile_budget(state, &m)?;
                Ok(m)
            }
            _ => Err(BridgeError::invalid()),
        }
    }
    pub(super) fn start_agent_store_release(
        &self,
        state: &DocumentState,
        entry: &Arc<requests::Entry>,
        registered: Option<(u32, asset_source::RegisteredRoot)>,
        gate: crate::local_store_preflight_protocol::Availability,
        material: Arc<SelectedStoreMaterial>,
    ) -> Result<crate::saved_command_owner::AgentStoreAdmitted, BridgeError> {
        let owner = self.store_delegate_owner(entry.scope().review.kind);
        match entry.scope().review.kind {
            p::Kind::Execute => {
                // Borrow the original locked Doc/material admission; there is
                // no agent-specific substitute or independently minted budget.
                let budget = self.store_execute_budget(state, &material)?;
                owner.start_agent_store_release(
                    entry,
                    registered,
                    gate,
                    material.clone(),
                    Some(&budget),
                )
            }
            p::Kind::Reconcile => {
                self.store_reconcile_budget(state, &material)?;
                owner.start_agent_store_release(entry, registered, gate, material, None)
            }
            _ => Err(BridgeError::invalid()),
        }
    }
}
