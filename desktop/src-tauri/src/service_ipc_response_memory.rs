//! Allocation backing for the SAME eight original installed IPC workers.
//!
//! This is a census, not a permit, allocator, scheduler or native receipt.
//! `installed_cli_ipc::run` counts finished-but-unjoined workers in its JoinSet.
//! Its one Metadata lease survives the cancelled exchange future and the sole
//! stream close. No retained row, history, native loan or Store snapshot is
//! credited here. A bad typed bound refuses the existing Document census.
use crate::{service_metadata_text_protocol as metadata, service_protocol as p};
use std::mem::size_of;

const KIB: usize = 1024;
const COMMON_LIMIT: usize = 96 * KIB;
// Closed enum/ID grammar, including a 512-byte outer envelope. There are no
// user names, paths, issue messages or arbitrary JSON values in either view.
const PROJECT_WIRE_BYTES: usize = 512 + p::PROJECT_LIMIT * (1863 + 1);
const OPERATION_WIRE_BYTES: usize = 512 + p::OPERATION_LIMIT * (254 + 1);

#[derive(Clone, Copy, Debug)]
struct Cells {
    request: usize,
    response: usize,
    client: usize,
    project: usize,
    operation: usize,
    platform: usize,
    requirement: usize,
}
impl Cells {
    fn actual() -> Self {
        Self {
            request: size_of::<p::Request>(),
            response: size_of::<p::Response>(),
            client: size_of::<super::ClientSession>(),
            project: size_of::<p::ProjectObservation>(),
            operation: size_of::<p::OperationObservation>(),
            platform: size_of::<crate::service_setup_guidance::Platform>(),
            requirement: size_of::<crate::service_setup_guidance::Requirement>(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Quote {
    common: usize,
    ordinary_body: usize,
    ordinary: usize,
    metadata: usize,
    all_ordinary: usize,
    mixed: usize,
    bytes: usize,
}

fn sum(values: &[usize]) -> Option<usize> {
    values
        .iter()
        .try_fold(0usize, |n, value| n.checked_add(*value))
}

fn common(c: Cells) -> Option<usize> {
    // Raw input is explicitly dropped before dispatch. Keep FOUR request
    // cells anyway (decoded request, cloned parameter, small Metadata reparse,
    // dispatch return slots). EIGHT Response cells conservatively include the
    // entire largest enum, Result/closure/async return slots and inline padding.
    // Their heap is in the route quotes, never inferred from sizeof(Response).
    // Unchanged <=16KiB validators still use growable to_vec: reserve old+new
    // allocations (3*16KiB). Those buffers drop before exact outer encoding.
    // 8KiB also keeps the fixed handshake, IDs/serde ID clones, Vec/Arc/watch,
    // scalar/result/clock and borrowed-original wrapper scratch.
    let bytes = sum(&[
        3 * 16 * KIB,
        c.request.checked_mul(4)?,
        c.response.checked_mul(8)?,
        c.client,
        8 * KIB,
    ])?
    .max(64 * KIB);
    (bytes <= COMMON_LIMIT).then_some(bytes)
}

fn project_peak(c: Cells) -> Option<usize> {
    // Two vector capacities bound old/new growth. Every cloned row includes
    // one32-byte ID, one64-byte digest, two platform and twenty requirement
    // enum cells. The borrowed validation BTreeSet gets128 bytes per row;
    // it contains no owned name/root/material and drops before serialization.
    sum(&[
        PROJECT_WIRE_BYTES,
        c.project.checked_mul(2 * p::PROJECT_LIMIT)?,
        sum(&[
            96,
            c.platform.checked_mul(2)?,
            c.requirement.checked_mul(20)?,
            128,
        ])?
        .checked_mul(p::PROJECT_LIMIT)?,
    ])
}

fn operation_peak(c: Cells) -> Option<usize> {
    sum(&[
        OPERATION_WIRE_BYTES,
        c.operation.checked_mul(2 * p::OPERATION_LIMIT)?,
        // Two32-byte IDs plus borrowed BTreeSet backing per row.
        (64usize + 128).checked_mul(p::OPERATION_LIMIT)?,
    ])
}

fn quote_with(c: Cells) -> Option<Quote> {
    let workers = crate::installed_cli_ipc::CLIENTS;
    if workers != 8 {
        return None; // The proof is for the unchanged original eight, not a new cap.
    }
    crate::service_github_action_requests::retained_document_backing()?;
    crate::service_store_requests::history::retained_document_backing()?;
    let common = common(c)?;
    let small = sum(&[
        metadata::INPUT_NODES.checked_mul(1024)?,
        p::REQUEST_BYTES.checked_mul(16)?,
        c.request.checked_mul(2)?,
    ])?;
    let git = crate::service_git_requests::IPC_WORKER_BACKING;
    let terms = [
        git,
        crate::service_request_catalogue::IPC_WORKER_BACKING,
        small,
        project_peak(c)?,
        operation_peak(c)?,
        // A's immutable retained reports keep their separate original debit.
        // Only one owned Status plus its exact public encoding is pooled.
        crate::agent_local_checks::REPORT_LIMIT
            .checked_add(crate::agent_local_checks::STATUS_HEAP_BYTES)?,
        crate::agent_android_build::REPORT_LIMIT
            .checked_add(crate::agent_build_requests::STATUS_HEAP_BYTES)?,
        crate::service_version_reserve_requests::IPC_WORKER_BACKING,
        crate::service_version_reserve_review_requests::IPC_WORKER_BACKING,
        crate::service_play_cleanup_requests::IPC_WORKER_BACKING,
        crate::service_upload_key_requests::IPC_WORKER_BACKING,
        crate::service_version_edit_requests::IPC_WORKER_BACKING,
        crate::service_version_edit_prepare_requests::IPC_WORKER_BACKING,
        crate::service_configuration_requests::IPC_WORKER_BACKING,
        crate::service_metadata_images_requests::IPC_WORKER_BACKING,
        crate::service_metadata_images_prepare_requests::IPC_WORKER_BACKING,
        crate::service_store_requests::history::IPC_WORKER_BACKING,
        crate::service_tool_setup_requests::IPC_WORKER_BACKING,
        crate::service_apple_provisioning_protocol::IPC_WORKER_BACKING,
        crate::service_github_action_protocol::IPC_WORKER_BACKING,
    ];
    let ordinary_body = *terms.iter().max()?;
    // Source-selected closed layouts must really fit G. Do not truncate a
    // larger typed layout or turn a size-of estimate into an allocation limit.
    if ordinary_body > git {
        return None;
    }
    let ordinary = ordinary_body.checked_add(common)?;
    // One Metadata original + its small-parse phase + the same common cells.
    // M0 already includes raw/Seed/decoded/validator/exact-output overlap.
    let metadata = sum(&[metadata::IPC_PEAK, small, common])?;
    let all_ordinary = ordinary.checked_mul(workers)?;
    let mixed = metadata.checked_add(ordinary.checked_mul(workers.checked_sub(1)?)?)?;
    Some(Quote {
        common,
        ordinary_body,
        ordinary,
        metadata,
        all_ordinary,
        mixed,
        bytes: all_ordinary.max(mixed),
    })
}

pub(crate) fn document_backing() -> Option<usize> {
    quote_with(Cells::actual()).map(|v| v.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_typed_routes_and_inline_enum_cells_fit_the_closed_worker_quote() {
        let c = Cells::actual();
        let q = quote_with(c).expect("actual closed IPC layout");
        assert_eq!(q.common, common(c).unwrap());
        assert!(q.common <= COMMON_LIMIT);
        assert!(project_peak(c).unwrap() <= q.ordinary_body);
        assert!(operation_peak(c).unwrap() <= q.ordinary_body);
        assert!(metadata::SMALL_INPUT_PEAK <= q.ordinary_body);
        assert!(crate::service_request_catalogue::IPC_WORKER_BACKING <= q.ordinary_body);
        assert!(crate::service_metadata_images_requests::IPC_WORKER_BACKING <= q.ordinary_body);
        assert_eq!(
            q.ordinary_body,
            crate::service_git_requests::IPC_WORKER_BACKING
        );
        assert_eq!(document_backing(), Some(q.bytes));
        println!(
            "IPC typed R={} Q={} H={} O={} M={} eight={} mixed={} debit={}",
            c.request,
            c.response,
            q.common,
            q.ordinary,
            q.metadata,
            q.all_ordinary,
            q.mixed,
            q.bytes
        );
    }

    #[test]
    fn same_eight_workers_allow_one_metadata_not_a_ninth_or_second_large_exchange() {
        let q = quote_with(Cells::actual()).unwrap();
        assert_eq!(crate::installed_cli_ipc::CLIENTS, 8);
        assert_eq!(q.all_ordinary, 8 * q.ordinary);
        assert_eq!(q.mixed, q.metadata + 7 * q.ordinary);
        assert_eq!(q.bytes, q.all_ordinary.max(q.mixed));
        for occupied in 0..=8 {
            assert!(occupied * q.ordinary <= q.bytes);
            if occupied > 0 {
                assert!(q.metadata + (occupied - 1) * q.ordinary <= q.bytes);
            }
        }
        // These are deliberately NOT admitted by the original JoinSet/lease.
        assert!(q.metadata + 8 * q.ordinary > q.bytes);
        assert!(2 * q.metadata + 6 * q.ordinary > q.bytes);
    }

    #[test]
    fn layout_growth_and_checked_overflow_refuse_instead_of_clamping_or_dropping_cells() {
        let c = Cells::actual();
        assert!(quote_with(Cells {
            response: COMMON_LIMIT,
            ..c
        })
        .is_none());
        assert!(quote_with(Cells {
            project: usize::MAX,
            ..c
        })
        .is_none());
        assert!(quote_with(Cells {
            operation: usize::MAX,
            ..c
        })
        .is_none());
        assert!(quote_with(Cells {
            request: usize::MAX,
            ..c
        })
        .is_none());
        assert!(sum(&[usize::MAX, 1]).is_none());
    }

    #[test]
    fn transferred_ipc_terms_leave_metadata_active_rows_and_github_tombstones_charged() {
        assert_eq!(
            crate::service_metadata_text_requests::DOCUMENT_BACKING,
            crate::service_metadata_text_requests::ROW_BACKING
                + crate::service_metadata_text_requests::ACTIVE_BACKING
                + crate::installed_cli_ipc::METADATA_CONTROL_BACKING
        );
        assert_eq!(
            crate::service_github_action_requests::retained_document_backing(),
            Some(786_432)
        );
        assert_eq!(crate::service_github_action_protocol::REQUEST_LIMIT, 32);
        // These are A's unchanged public-view routes, not a second851968 debit.
        assert_eq!(
            crate::agent_local_checks::REPORT_LIMIT + crate::agent_local_checks::STATUS_HEAP_BYTES,
            73_728
        );
        assert_eq!(
            crate::agent_android_build::REPORT_LIMIT
                + crate::agent_build_requests::STATUS_HEAP_BYTES,
            32_768
        );
        assert_eq!(
            crate::service_version_edit_prepare_requests::IPC_WORKER_BACKING,
            17_408
        );
    }

    #[test]
    fn only_the_named_old_worker_allocations_are_replaced_by_the_mixed_maximum() {
        let old_small = [
            crate::service_git_requests::IPC_WORKER_BACKING,
            crate::service_version_reserve_requests::IPC_WORKER_BACKING,
            crate::service_play_cleanup_requests::IPC_WORKER_BACKING,
            crate::service_upload_key_requests::IPC_WORKER_BACKING,
            crate::service_version_edit_requests::IPC_WORKER_BACKING,
            crate::service_configuration_requests::IPC_WORKER_BACKING,
            crate::service_tool_setup_requests::IPC_WORKER_BACKING,
            crate::service_apple_provisioning_protocol::IPC_WORKER_BACKING,
        ];
        let old = 8 * sum(&old_small).unwrap()
            + crate::service_request_catalogue::DOCUMENT_BACKING
            + metadata::IPC_BACKING
            + 8 * crate::service_github_action_protocol::IPC_WORKER_BACKING
            + 8 * crate::service_version_edit_prepare_requests::IPC_WORKER_BACKING;
        let q = quote_with(Cells::actual()).unwrap();
        // ReserveReview was added after the pooled census. It must fit the
        // current worker maximum, but cannot increase the historical saving.
        assert!(
            crate::service_version_reserve_review_requests::IPC_WORKER_BACKING <= q.ordinary_body
        );
        let saved = old.checked_sub(q.bytes).expect("a real allocation saving");
        // No Local/Build worker saving here: A already removes that term once.
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(8 * sum(&old_small).unwrap(), 2_699_264);
            assert!(crate::service_request_catalogue::IPC_WORKER_BACKING >= 96 * KIB);
            assert!(
                saved
                    >= 2_807_296
                        + 14 * size_of::<p::Request>()
                        + 8 * crate::service_version_edit_prepare_requests::IPC_WORKER_BACKING
            );
        }
        println!(
            "IPC removed-only={old} replacement={} saved={saved}",
            q.bytes
        );
    }
}
