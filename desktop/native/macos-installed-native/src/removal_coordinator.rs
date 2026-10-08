//! Fixed removal-peer ownership. This initial slice provides only the immutable
//! cutoff proof type; the real peer admission/native implementation is unfinished.
//! No production caller can manufacture a ParentCutoff from DATA.
use std::{mem::size_of, sync::Arc};

const PARENT_WORK_NS: u64 = 110_000_000_000;
const PARENT_HARD_NS: u64 = 120_000_000_000;
// Same representable first-failure ceiling as the existing Android Signal.
const MAX_RAW: u64 = (1_u64 << 61) - 1;

struct AuthenticatedCutoffOriginal {
    request_id: [u8; 16],
    root_nonce: [u8; 16],
    start: u64,
    work: u64,
    hard: u64,
}
impl AuthenticatedCutoffOriginal {
    fn valid(&self) -> bool {
        self.request_id != [0; 16] && self.root_nonce != [0; 16]
            && self.start != 0 && self.hard <= MAX_RAW
            && self.work.checked_sub(self.start) == Some(PARENT_WORK_NS)
            && self.hard.checked_sub(self.start) == Some(PARENT_HARD_NS)
    }
}
// Match the existing source-bound Arc accounting convention in
// android_service_budget. Allocator/framework private memory is not claimed.
#[repr(C)]
struct ArcAllocation<T> { counts: [usize; 2], value: T }

/// A cloned reference preserves this SAME authenticated original, not merely
/// an equal deadline. No Serialize/Deserialize, public constructor or setter.
/// Keeping this proof does not prove peer/channel close, exit, or completion.
#[derive(Clone)]
pub struct ParentCutoff { original: Arc<AuthenticatedCutoffOriginal> }
impl ParentCutoff {
    // Only the eventual native peer's verified original may enter here. No
    // production factory is supplied in this partial slice; live authentication
    // and admission must be implemented/reviewed before that callsite exists.
    fn from_authenticated_original(original: AuthenticatedCutoffOriginal) -> Option<Self> {
        original.valid().then(|| Self { original: Arc::new(original) })
    }
    pub fn start_ns(&self) -> u64 { self.original.start }
    pub fn work_ns(&self) -> u64 { self.original.work }
    pub fn hard_ns(&self) -> u64 { self.original.hard }
    pub fn same_original(&self, other: &Self) -> bool { Arc::ptr_eq(&self.original, &other.original) }
    /// Includes the handle plus one original allocation. Multiple handles to
    /// this original must be identity-deduplicated by their enclosing census.
    pub fn project_owned_upper_bound() -> Option<usize> {
        size_of::<Self>().checked_add(size_of::<ArcAllocation<AuthenticatedCutoffOriginal>>())
    }
    // Native crate tests only: cannot construct a Peer or confirmation proof,
    // and is absent from production and external app-crate test compilation.
    #[cfg(test)]
    pub(crate) fn test_original(start: u64) -> Option<Self> {
        Self::from_authenticated_original(AuthenticatedCutoffOriginal {
            request_id: [1; 16], root_nonce: [2; 16], start,
            work: start.checked_add(PARENT_WORK_NS)?,
            hard: start.checked_add(PARENT_HARD_NS)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cutoff_preserves_same_original_not_equal_data_and_fixed_endpoints() {
        let first = ParentCutoff::test_original(5).unwrap();
        let cloned = first.clone();
        let separate = ParentCutoff::test_original(5).unwrap();
        assert!(first.same_original(&cloned));
        assert!(!first.same_original(&separate));
        assert_eq!((first.start_ns(), first.work_ns(), first.hard_ns()),
            (5, 5 + PARENT_WORK_NS, 5 + PARENT_HARD_NS));
        drop(first);
        assert_eq!(cloned.hard_ns(), 5 + PARENT_HARD_NS);
        assert!(ParentCutoff::test_original(0).is_none());
        assert!(ParentCutoff::test_original(u64::MAX).is_none());
        assert!(ParentCutoff::test_original(MAX_RAW - PARENT_HARD_NS).is_some());
        assert!(ParentCutoff::test_original(MAX_RAW - PARENT_HARD_NS + 1).is_none());
        for (request_id, root_nonce, work, hard) in [
            ([0; 16], [2; 16], 5 + PARENT_WORK_NS, 5 + PARENT_HARD_NS),
            ([1; 16], [0; 16], 5 + PARENT_WORK_NS, 5 + PARENT_HARD_NS),
            ([1; 16], [2; 16], 5 + PARENT_WORK_NS - 1, 5 + PARENT_HARD_NS),
            ([1; 16], [2; 16], 5 + PARENT_WORK_NS, 5 + PARENT_HARD_NS + 1),
        ] {
            assert!(ParentCutoff::from_authenticated_original(AuthenticatedCutoffOriginal {
                request_id, root_nonce, start: 5, work, hard,
            }).is_none());
        }
        assert!(ParentCutoff::project_owned_upper_bound().unwrap() <= 128);
    }
}
