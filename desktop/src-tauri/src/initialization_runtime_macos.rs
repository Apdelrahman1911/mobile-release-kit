//! Initialization-CLI-only census of the SAME installed runtime Book. This
//! opts its existing inspection into the existing bounded inventory planner;
//! it does not produce a runtime, a native receipt, or another clock/owner.
use super::*;

impl ProjectInitializationRuntimeSlots {
    pub(crate) fn initialization_agent_code_peak() -> Option<usize> {
        crate::macos_history_inventory::code_storage_bytes(
            std::mem::size_of::<Record>(),
            native::vault_filesystem::SNAPSHOT_FRAME_BYTES,
        )?
        .checked_add(std::mem::size_of::<Self>())?
        // Fixed selected paths can be held in the slot and returned worker.
        .checked_add(8 * 4096)
        .filter(|bytes| *bytes <= crate::macos_history_inventory::CODE_CONTROL_RESERVE)
    }

    pub(crate) fn bind_initialization_agent_inspection(&mut self) -> Result<()> {
        if !self.never_started() || Self::initialization_agent_code_peak().is_none() {
            return Err(AdmissionFailure::AlreadyUsed);
        }
        let original = self.inspection.as_mut().ok_or(AdmissionFailure::Unknown)?;
        if original.initialization_agent_inspection
            || original.records.capacity() > crate::macos_install_record::RUNTIME_RECORD_LIMIT
        {
            return Err(AdmissionFailure::AlreadyUsed);
        }
        // Immutable before the original arm/inspect: no public input, callback,
        // status, or later admission can opt a running Book into this profile.
        original.initialization_agent_inspection = true;
        Ok(())
    }

    pub(crate) fn initialization_agent_retained_bytes(&self) -> Option<usize> {
        let original = match (&self.inspection, &self.acquisition) {
            (Some(book), None) => book,
            (None, Some(capability)) => &capability.original,
            _ => return None,
        };
        if !original.initialization_agent_inspection
            || original.records.capacity() > crate::macos_install_record::RUNTIME_RECORD_LIMIT
        {
            return None;
        }
        // The existing accessor checks actual retained record/path/ACL-frame
        // backing and original quiescence. Busy/Unknown is not zero storage.
        let peak = Self::initialization_agent_code_peak()?;
        self.retained_bytes().filter(|bytes| *bytes <= peak)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialization_agent_code_quote_uses_actual_target_records_and_native_frame() {
        let lower = crate::macos_history_inventory::code_storage_bytes(
            std::mem::size_of::<Record>(),
            native::vault_filesystem::SNAPSHOT_FRAME_BYTES,
        )
        .unwrap();
        let peak = ProjectInitializationRuntimeSlots::initialization_agent_code_peak().unwrap();
        assert_eq!(
            peak,
            lower + std::mem::size_of::<ProjectInitializationRuntimeSlots>() + 8 * 4096
        );
        assert!(peak <= crate::macos_history_inventory::CODE_CONTROL_RESERVE);
        assert!(crate::macos_history_inventory::admission_bytes(
            crate::macos_history_inventory::SHARED_DATA_LIMIT,
            crate::macos_history_inventory::CODE_CONTROL_RESERVE,
        )
        .is_some());
        assert!(crate::macos_history_inventory::admission_bytes(
            crate::macos_history_inventory::SHARED_DATA_LIMIT + 1,
            crate::macos_history_inventory::CODE_CONTROL_RESERVE,
        )
        .is_none());
    }

    #[test]
    fn initialization_agent_slot_binding_is_once_before_entry_and_failed_capacity_is_not_zero() {
        let mut slots = ProjectInitializationRuntimeSlots::new();
        assert!(slots.never_started());
        assert!(slots.initialization_agent_retained_bytes().is_none());
        slots.bind_initialization_agent_inspection().unwrap();
        assert!(slots.never_started()); // No ACL/FD/native entry was fabricated.
        assert!(slots.bind_initialization_agent_inspection().is_err());
        assert_eq!(
            slots.initialization_agent_retained_bytes(),
            Some(std::mem::size_of::<ProjectInitializationRuntimeSlots>())
        );
        slots.inspection.as_mut().unwrap().records =
            Vec::with_capacity(crate::macos_install_record::RUNTIME_RECORD_LIMIT + 1);
        let capacity = slots.inspection.as_ref().unwrap().records.capacity();
        assert!(slots.initialization_agent_retained_bytes().is_none());
        assert_eq!(
            slots.inspection.as_ref().unwrap().records.capacity(),
            capacity
        );
        slots.inspection.as_mut().unwrap().records = Vec::new();
        slots.inspection.as_mut().unwrap().unknown = true;
        assert!(slots.initialization_agent_retained_bytes().is_none());
        let ordinary = ProjectInitializationRuntimeSlots::new();
        assert!(
            !ordinary
                .inspection
                .as_ref()
                .unwrap()
                .initialization_agent_inspection
        );
        assert!(ordinary.never_started());
    }
}
