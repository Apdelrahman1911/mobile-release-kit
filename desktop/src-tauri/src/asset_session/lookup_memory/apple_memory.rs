//! Original Apple inputs join the existing Document census, not a second
//! allocator or a six-MiB reservation for an absent prior review.
use super::*;

impl Census<'_> {
    pub(super) fn apple_retained_document(&mut self, document: &Arc<Inner>) -> Result<(), Problem> {
        // The SAME current SourceBook/Retirement remain borrowed by Census.
        // The Saved registry guard is released before any Source/vault visit.
        let snapshot = document
            .bridge
            .apple_provisioning
            .apple_retained_census(self.current.map(|(original, _, _)| original))
            .map_err(|error| {
                if error.code == "apple_provisioning_busy" {
                    Problem::Unavailable
                } else {
                    Problem::CleanupUnknown
                }
            })?;
        for (input, original) in snapshot.members() {
            // Input/context/comparison wrapper bounds remain in the original
            // saved-owner quote. These are the separately retained descendants,
            // visited by the SAME Seen sets as current records/vault/retirement.
            self.selected_store_material(input.material())?;
            self.apple_state_ready(input.ready())?;
            if let Some(original) = original {
                self.owner(original)?;
            }
        }
        Ok(())
    }

    pub(super) fn apple_state_ready(
        &mut self,
        ready: &Arc<crate::application_service_host::NativeStateReady>,
    ) -> Result<(), Problem> {
        // A previous Ready may be distinct from state.apple_provisioning_ready;
        // identical live Arc allocations cannot have different data addresses.
        if self.contexts.insert(ready)? {
            self.add(native_state_ready_bytes(ready)?)?;
        }
        Ok(())
    }

    pub(super) fn selected_store_material(
        &mut self,
        loan: &Arc<SelectedStoreMaterial>,
    ) -> Result<(), Problem> {
        if !self.secret_loans.insert(loan)? {
            return Ok(());
        }
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64"),
            not(feature = "macos-android-registration-helper")
        ))]
        if let Some((bytes, pickers)) = loan.execute_census().ok_or(Problem::CleanupUnknown)? {
            self.add(bytes)?;
            for picker in pickers.iter().flatten() {
                self.owner(picker)?;
            }
        }
        let (context, payload) = loan.census_parts();
        self.context(context)?;
        self.payload(payload)?;
        for (_, payload) in loan.supplemental_census() {
            self.payload(payload)?;
        }
        if let Some(sources) = loan.profile_sources() {
            self.profile_sources(sources)?;
        }
        if let Some(sources) = loan.key_sources() {
            self.key_sources(sources)?;
        }
        self.arc_cells::<SelectedStoreMaterial>()?;
        self.add(loan.own_retained_heap_bytes().ok_or(Problem::Capacity)?)
        // supplemental_frame_bytes is a NEW operation's writer scratch, not
        // retained loan storage. Its original admission caller still adds it.
    }
}

#[cfg(test)]
#[path = "apple_memory_tests.rs"]
mod tests;
