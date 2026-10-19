//! Bundle-ID provisioning on the original SavedCommand Session.
//!
//! These two facts deliberately have different cut points. They are private
//! parent capabilities, never child/status/journal JSON and never restored
//! after restart. Only this child may construct them after the corresponding
//! original resource roster has actually joined.

use std::sync::Arc;

use crate::{
    apple_provisioning_journal::OriginalReservation,
    application_state_store::NativeUse,
};

/// Worker/provider/source/material/driver/manager and all PRE-final-CAS jobs
/// have joined. The final journal CAS is deliberately not covered by this.
pub(crate) struct AppleProvisioningNativeJoined {
    native_use: Arc<NativeUse>,
    reservation: Arc<OriginalReservation>,
}

impl AppleProvisioningNativeJoined {
    pub(crate) fn matches(&self, native_use: &NativeUse, reservation: &OriginalReservation) -> bool {
        std::ptr::eq(self.native_use.as_ref(), native_use)
            && std::ptr::eq(self.reservation.as_ref(), reservation)
    }
}

/// All finite journal jobs, INCLUDING final CAS or its proven not-entered
/// slot, have joined and the roster is sealed against any future writer.
/// Only this later fact may release the original Store's native-use token.
pub(crate) struct AppleProvisioningAllJobsJoined {
    native_use: Arc<NativeUse>,
}

impl AppleProvisioningAllJobsJoined {
    pub(crate) fn matches(&self, native_use: &NativeUse) -> bool {
        std::ptr::eq(self.native_use.as_ref(), native_use)
    }
}
