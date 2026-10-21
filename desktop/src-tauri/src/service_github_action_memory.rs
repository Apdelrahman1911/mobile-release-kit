//! Retained GH inbox DATA, independent of the shared IPC reply allocation.
//! Native Consent/Intent/Connection material stays on its original owner.
use super::*;
use std::mem::size_of;

const ANCILLARY_LIMIT: usize = 128 * 1024;
const UNASSIGNED_SLACK: usize = 128 * 1024;
const ARC_HEADER: usize = 2 * size_of::<usize>();
// NativeScope::valid/Review::retained_fits check physical capacities, not just
// string lengths. Submit IDs are rebuilt by Id::parse; the operation is fixed
// by Kind::operation before entry. No row stores a full Prepared or payload.
const SCOPE_HEAP: usize = 64 + 128 + 8192 + 128 + 64 + 128;
const OUTPUT_HEAP: usize = 4 * 64 + 128 + 64 + 128 + 84;

fn sum(values: &[usize]) -> Option<usize> {
    values.iter().try_fold(0usize, |n, v| n.checked_add(*v))
}

fn row_bytes() -> Option<usize> {
    sum(&[
        SCOPE_HEAP,
        4 * 64,             // actual immutable Submit IDs
        64,                 // original fixed operation ID
        2 * OUTPUT_HEAP,    // retained projection/history transition copies
        size_of::<Entry>(), // includes the actual Mutex<Row> and enum padding
        size_of::<NativeScope>(),
        size_of::<Claim>(),
        size_of::<History>(),
        2 * size_of::<Fact>(),
        size_of::<crate::service_version_reserve_requests::ReadPermission>(),
        2 * size_of::<p::Status>(),
        // Arc headers, read/document/identity/watch bookkeeping and small
        // allocator/mutex cells. No native task or runtime is credited away.
        12 * ARC_HEADER,
        2048,
    ])
}

fn ancillary_bytes() -> Option<usize> {
    sum(&[
        size_of::<Inbox>(),
        size_of::<Book>(),
        64, // instance ID allocation
        p::REQUEST_LIMIT.checked_mul(size_of::<Arc<Entry>>())?,
        4 * size_of::<Lease>(),
        // One unused/current scope/lease plus its off-Doc Allow transition.
        // Old claimed scopes are still fully included in every retained row.
        2 * p::ROW_BACKING,
        4 * (size_of::<p::Access>() + size_of::<p::Status>() + 2 * OUTPUT_HEAP),
        4 * (3 * p::STATUS_LIMIT), // existing GUI/history encoding growth
        32 * ARC_HEADER,
        16 * (size_of::<tokio::sync::watch::Sender<u32>>()
            + size_of::<tokio::sync::watch::Receiver<u32>>()),
        16 * 1024, // fixed control/lock/weak/reader/scalar scratch, not IPC8
    ])
}

fn checked_backing(row: usize, ancillary: usize) -> Option<usize> {
    if row > p::ROW_BACKING || ancillary > ANCILLARY_LIMIT {
        return None;
    }
    let bytes = sum(&[
        p::REQUEST_LIMIT.checked_mul(p::ROW_BACKING)?,
        ANCILLARY_LIMIT,
        UNASSIGNED_SLACK,
    ])?;
    (bytes == p::DOCUMENT_BACKING).then_some(bytes)
}

pub(crate) fn retained_document_backing() -> Option<usize> {
    checked_backing(row_bytes()?, ancillary_bytes()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_retained_row_and_ancillary_have_real_typed_bounds_not_response_size() {
        let row = row_bytes().unwrap();
        let ancillary = ancillary_bytes().unwrap();
        assert!(row <= p::ROW_BACKING, "actual row={row}");
        assert!(ancillary <= ANCILLARY_LIMIT, "actual ancillary={ancillary}");
        assert_eq!(retained_document_backing(), Some(786_432));
        assert_eq!(p::REQUEST_LIMIT, 32);
        assert_eq!(
            p::DOCUMENT_BACKING,
            32 * p::ROW_BACKING + ANCILLARY_LIMIT + UNASSIGNED_SLACK
        );
        println!(
            "GH retained row={row} ancillary={ancillary} debit={}",
            p::DOCUMENT_BACKING
        );
    }

    #[test]
    fn retained_ceiling_failure_never_borrows_a_retired_row_or_worker_credit() {
        assert_eq!(
            checked_backing(p::ROW_BACKING, ANCILLARY_LIMIT),
            Some(p::DOCUMENT_BACKING)
        );
        assert_eq!(checked_backing(p::ROW_BACKING + 1, 0), None);
        assert_eq!(checked_backing(0, ANCILLARY_LIMIT + 1), None);
        assert_eq!(checked_backing(usize::MAX, usize::MAX), None);
        assert_eq!(sum(&[usize::MAX, 1]), None);
    }
}
