//! Pure pre-GO project-owned high-water, separate from native custody/finality.
//!
//! Scope successor accepted by Root and the independent plan reviewer on
//! 2026-10-02: project cells, supplied backing and captures are byte-bounded.
//! Framework-private/runtime/OS graphs are explicitly unmeasured/outside this
//! claim, NOT zero, and no RSS/all-Foundation ceiling is asserted. Native
//! references/calls/backing still require their separate original lifetime proof.
#![forbid(unsafe_code)]
use crate::android_service_client_data::ClientData;
pub const CLIENT_INLINE_MAX: usize = 16_384;
pub const CLIENT_REQUEST_BACKING_MAX: usize = 65_536;
// Already INSIDE the C client inline cell; never added as a second allocation.
pub const CLIENT_REPLY_BACKING_MAX: usize = 8_448;
const CLIENT_CAPTURE_MAX: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unavailable { ProjectCapacityUnknown, Overflow }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientRequirements {
    inline_max: usize, request_backing_max: usize,
    data_allocation: Option<usize>, capture_max: usize,
}
impl ClientRequirements {
    /// This component only. Caller-owned input/encoder/worker/Signal/book cells
    /// are still charged in their own exact-identity aggregate census.
    pub fn known_bytes(self) -> Option<usize> {
        self.inline_max.checked_add(self.request_backing_max)?
            .checked_add(self.data_allocation?)?.checked_add(self.capture_max)
    }
    pub fn admitted_upper_bound(self) -> Result<usize, Unavailable> {
        self.data_allocation.ok_or(Unavailable::ProjectCapacityUnknown)?;
        self.known_bytes().ok_or(Unavailable::Overflow)
    }
    /// Reference counts are not converted to invented framework-byte sizes.
    pub fn native_reference_slots(self) -> usize { 8 }
    pub fn request_arena_slots(self) -> usize { 1 }
}

/// Arc's source-bound two reference-count cells plus payload/alignment. This is
/// allocation-layout accounting, never use of strong_count as a lifetime proof.
#[repr(C)]
struct ArcAllocation<T> { counts: [usize; 2], value: T }
pub fn client_requirements() -> ClientRequirements {
    // C static assertions enforce the inline and supplied capture maxima;
    // ClientData owns exactly one Box<[u8;65536]>, whose bytes are charged here.
    // The pointer/lease/Signal handle are already in size_of<ClientData>.
    ClientRequirements { inline_max: CLIENT_INLINE_MAX,
        request_backing_max: CLIENT_REQUEST_BACKING_MAX,
        data_allocation: Some(std::mem::size_of::<ArcAllocation<ClientData>>()),
        capture_max: CLIENT_CAPTURE_MAX }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_data_and_capture_high_water_are_real_and_inline_reply_is_once() {
        let requirements = client_requirements();
        assert_eq!(requirements.admitted_upper_bound(), Some(CLIENT_INLINE_MAX)
            .and_then(|n| n.checked_add(CLIENT_REQUEST_BACKING_MAX))
            .and_then(|n| n.checked_add(std::mem::size_of::<ArcAllocation<ClientData>>()))
            .and_then(|n| n.checked_add(CLIENT_CAPTURE_MAX)).ok_or(Unavailable::Overflow));
        let missing = ClientRequirements { data_allocation: None, ..requirements };
        assert_eq!(missing.admitted_upper_bound(), Err(Unavailable::ProjectCapacityUnknown));
        let overflow = ClientRequirements { inline_max: usize::MAX, ..requirements };
        assert_eq!(overflow.admitted_upper_bound(), Err(Unavailable::Overflow));
        assert_eq!(requirements.request_arena_slots(), 1);
    }
}
