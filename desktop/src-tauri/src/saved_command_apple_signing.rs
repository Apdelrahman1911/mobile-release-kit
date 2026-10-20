//! Profile facts of the SAME SavedCommand Apple Session. A journal row cannot
//! construct these capabilities; no constructor is exported to a codec, IPC
//! caller, restored reservation or test fixture.
use std::sync::Arc;

use crate::{
    apple_provisioning_journal::ProfileOriginalReservation, application_state_store::NativeUse,
};

/// The original worker/provider/CMS/private receive consumers AND the fixed
/// vault save/readback jobs have returned and joined. This fact deliberately
/// excludes the final journal CAS and subsequent native-use retirement job.
/// Those remain on the SAME original parent's finite roster.
pub(crate) struct AppleProfileNativeJoined {
    native_use: Arc<NativeUse>,
    reservation: Arc<ProfileOriginalReservation>,
}

impl AppleProfileNativeJoined {
    pub(crate) fn matches(
        &self,
        native_use: &Arc<NativeUse>,
        reservation: &Arc<ProfileOriginalReservation>,
    ) -> bool {
        Arc::ptr_eq(&self.native_use, native_use) && Arc::ptr_eq(&self.reservation, reservation)
    }
}
