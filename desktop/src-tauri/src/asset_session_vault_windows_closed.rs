//! Windows has no Apple vault owner. These uninhabited capability types preserve
//! borrowed DATA API paths only; no constructor, acquisition, persistence, or
//! settlement can exist on this platform. Every receiver is impossible.
use super::*;
use crate::credential_setup::KeyReference;
use crate::saved_command_owner::*;
pub(super) mod profile_sources { pub(crate) enum AppleProfileSources {} impl AppleProfileSources {pub(in crate::asset_session) fn same_selection(&self, other:&Self)->bool {match *self {}}} }
pub(super) mod key_sources { pub(crate) enum AppleKeySources {} impl AppleKeySources {pub(in crate::asset_session) fn same_selection(&self, other:&Self)->bool {match *self {}}} }
pub(crate) enum AppleP12Loan {}
pub(crate) enum AppleProfileDestination {}
impl AppleProfileDestination {
pub(crate) fn descriptor(&self) -> KeyReference { match *self {} }
pub(crate) fn source_reference(&self) -> KeyReference { match *self {} }
pub(crate) fn recheck_source(&self, owner: &Arc<OriginalWork>) -> Result<(), Reason> { match *self {} }
pub(crate) fn retirement_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool { match *self {} }
pub(crate) fn no_save_candidate_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool { match *self {} }
pub(crate) fn no_save_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool { match *self {} }
pub(crate) fn accept_no_save(
        &self,
        owner: &Arc<OriginalWork>,
        witness: AppleProfileNoSaveJoined,
    ) -> Result<(), Reason> { match *self {} }
pub(crate) fn retained_bytes(&self) -> Option<usize> { match *self {} }
pub(crate) fn saved_reference_data(&self) -> Option<KeyReference> { match *self {} }
}
pub(crate) enum AppleDistributionKeyDestination {}
impl AppleDistributionKeyDestination {
pub(crate) fn descriptor(&self) -> KeyReference { match *self {} }
pub(crate) fn retirement_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool { match *self {} }
pub(crate) fn never_generated_candidate_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool { match *self {} }
pub(crate) fn never_generated_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool { match *self {} }
pub(crate) fn accept_never_generated(
        &self,
        owner: &Arc<OriginalWork>,
        proof: AppleKeyNeverGeneratedJoined,
    ) -> Result<(), Reason> { match *self {} }
pub(crate) fn saved_reference_data(&self) -> Option<KeyReference> { match *self {} }
pub(crate) fn published_reference_data(
        &self,
        owner: &Arc<OriginalWork>,
    ) -> Option<KeyReference> { match *self {} }
pub(crate) fn parent_retirement_ready(&self, owner: &Arc<OriginalWork>) -> bool { match *self {} }
pub(crate) fn retained_bytes(&self) -> Option<usize> { match *self {} }
}
pub(crate) enum AppleDistributionKeyLoan {}
impl AppleDistributionKeyLoan {
pub(crate) fn reference(&self) -> KeyReference { match *self {} }
pub(crate) fn recheck(&self, owner: &Arc<OriginalWork>) -> Result<(), Reason> { match *self {} }
pub(crate) fn matches_public_material(
        &self,
        owner: &Arc<OriginalWork>,
        csr: &[u8],
        spki: &[u8],
    ) -> bool { match *self {} }
pub(crate) fn matches_recovery_frame(&self, owner: &Arc<OriginalWork>, bytes:u32, sha256:&str) -> bool { match *self {} }
pub(crate) fn accept_joined(
        &self,
        owner: &Arc<OriginalWork>,
        proof: AppleKeyUseJoined,
    ) -> Result<(), Reason> { match *self {} }
pub(crate) fn original_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool { match *self {} }
}
pub(crate) enum AppleP12Destination {}
impl AppleP12Destination {
pub(crate) fn descriptor(&self) -> KeyReference { match *self {} }
pub(crate) fn source_reference(&self) -> KeyReference { match *self {} }
pub(crate) fn same_source(&self, loan: &Arc<AppleDistributionKeyLoan>) -> bool { match *self {} }
pub(crate) fn retirement_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool { match *self {} }
pub(crate) fn no_save_candidate(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool { match *self {} }
pub(crate) fn no_save_binding(
        &self,
        owner: &Arc<OriginalWork>,
        reference: &KeyReference,
    ) -> bool { match *self {} }
pub(crate) fn accept_no_save(
        &self,
        owner: &Arc<OriginalWork>,
        proof: AppleP12NoSaveJoined,
    ) -> Result<(), Reason> { match *self {} }
pub(crate) fn published_reference_data(
        &self,
        owner: &Arc<OriginalWork>,
    ) -> Option<KeyReference> { match *self {} }
pub(crate) fn parent_retirement_ready(&self, owner: &Arc<OriginalWork>) -> bool { match *self {} }
pub(crate) fn own_retained_bytes(&self) -> Option<usize> { match *self {} }
}

impl AppleProfileDestination {
pub(crate) fn record_pending(
        &self,
        owner: &Arc<OriginalWork>,
        ack: AppleProfilePendingAck,
    ) -> Result<(), Reason> { match *self {} }
}

impl AppleDistributionKeyDestination {
pub(crate) fn record_pending(
        &self,
        owner: &Arc<OriginalWork>,
        ack: AppleKeyPendingAck,
    ) -> Result<(), Reason> { match *self {} }
}

impl AppleP12Destination {
pub(crate) fn record_pending(
        &self,
        owner: &Arc<OriginalWork>,
        ack: AppleP12PendingAck,
    ) -> Result<(), Reason> { match *self {} }
}

impl AppleP12Destination {
pub(crate) fn password_original(
        &self,
        owner: &Arc<OriginalWork>,
    ) -> Result<Arc<commands::AppleP12Password>, Reason> { match *self {} }
}
