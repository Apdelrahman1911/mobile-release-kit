//! Borrowed initialization census in the ORIGINAL EditOwner. No snapshots,
//! recensus adoption, serialization, status-as-join or retained-row credit.
use super::*;

// The valid configurationPreview is CLOSED by edit_protocol::preview:
// 36 fixed map entries +64*8 requirements +64*(4+2*3) changes +64*4 fields.
// There are at most64+64*64+64+64 array elements. Inventory uses <=256
// FileView/parent paths and four workflow bodies. All dynamic strings together
// are bounded by the already-enforced768KiB serialized view; factor2 retains
// real capacity rounding. Small-container BTree slack is the SAME Heap1024.
const PREVIEW_MAP_ENTRIES: usize = 36 + 64 * 8 + 64 * (4 + 2 * 3) + 64 * 4;
const PREVIEW_ARRAY_ELEMENTS: usize = 64 + 64 * 64 + 64 + 64;
pub(in crate::edit_owner) const REPRESENTATION: usize = PREVIEW_MAP_ENTRIES * 1024
    + 2 * n::VIEW_LIMIT
    + 2 * PREVIEW_ARRAY_ELEMENTS * size_of::<Value>()
    + 512 * (size_of::<n::FileView>() + size_of::<String>())
    + 8 * size_of::<n::WorkflowView>()
    + 64 * 1024
    + size_of::<EditProjection>();

// Both arbitrary malformed frames and valid frames keep the original1MiB/
// 20,000-key-inclusive-node/depth32 limits. Seed's transient duplicate-key set
// is within the same1024/map-entry allowance; strings/escape scratch and raw
// Vec's old+new reallocations are separate. check_value's stack does not run
// concurrently with Seed. Owned Value->Content->typed conversion retains a
// container frontier (<=128/node), NOT a second cloned string/tree graph.
const PARSE: usize = crate::protocol::NODE_LIMIT * 512 + 7 * n::RESPONSE_LIMIT;
const CHECK: usize = crate::protocol::NODE_LIMIT * 512
    + 4 * n::RESPONSE_LIMIT
    + 2 * crate::protocol::NODE_LIMIT * size_of::<(&Value, usize)>();
const CONVERT: usize = crate::protocol::NODE_LIMIT * (512 + 128) + 4 * n::RESPONSE_LIMIT;
const DECODE: usize = if PARSE > CHECK {
    if PARSE > CONVERT {
        PARSE
    } else {
        CONVERT
    }
} else if CHECK > CONVERT {
    CHECK
} else {
    CONVERT
};
// A native initialization active projection contains ONE <=VIEW_LIMIT view
// (Initialize checkout is only counters/Observed), plus bounded scalar fields.
// Last-domain projections are charged independently below, including recovery's
// TWO full views. The native2MiB Status ceiling is unchanged. Six wire terms
// preserve two independent Status encoders including each old+new Vec peak.
const ACTIVE_STATUS_WIRE: usize = n::VIEW_LIMIT + 16 * 1024;
const CONTROL: usize = 1024 * 1024
    + size_of::<Session>()
    + size_of::<Resources>()
    + size_of::<ActiveOwner>()
    + size_of::<agent_initialization::Link>()
    + 3 * size_of::<crate::service_initialization_requests::Call>()
    + 4 * (size_of::<crate::application_service_host::NativeProject>() + 4096 + 128)
    + 4 * (size_of::<tokio::sync::oneshot::Sender<Result<(), BridgeError>>>()
        + size_of::<tokio::sync::oneshot::Receiver<Result<(), BridgeError>>>()
        + 256);
// Reader accepts THREE TOTAL frames. Before a third decode, at most two full
// frames can be waiting. A full positive active projection requires the first
// (small) Initialize Opened frame already consumed, leaving one prior full
// projection plus two independently returned Status copies =3 representations.
// Three hostile full frames cannot coexist with an adopted Initialize Prepared.
// After conversion/validation, at most4 full representations (incl2 Status)
// coexist; its3*VIEW validation Vec peak is below the arbitrary decode peak.
const RUN_DECODE: usize = 3 * REPRESENTATION + DECODE + 6 * ACTIVE_STATUS_WIRE;
const RUN_VALID: usize =
    4 * REPRESENTATION + 3 * n::VIEW_LIMIT + 3 * n::RESPONSE_LIMIT + 6 * ACTIVE_STATUS_WIRE;
// RAW original body is dropped before entering the native owner. That owner
// moves Open.draft into params and drops params before installing the Session.
// No child/reader can run while those original input trees remain. This phase
// still reserves both bounded8k drafts plus real request encoding/queue peaks.
const OPEN_INPUT: usize =
    2 * (8000 * 512 + 2 * 512 * 1024) + 3 * c::REQUEST_LIMIT + 6 * ACTIVE_STATUS_WIRE;
const RUN: usize = if RUN_DECODE > RUN_VALID {
    RUN_DECODE
} else {
    RUN_VALID
};
pub(in crate::edit_owner) const FUTURE: usize =
    (if RUN > OPEN_INPUT { RUN } else { OPEN_INPUT }) + CONTROL;
// The complete installed code inspector is NOT DATA, a one-MiB scalar or an
// absent-active credit. Reuse the original128MiB code partition, independently
// of the unchanged64MiB full Document+initialization DATA ceiling.
const CODE: usize = crate::macos_history_inventory::CODE_CONTROL_RESERVE;

pub(in crate::edit_owner) fn prospective(
    p: &EditProjection,
    frame: &ChildFrame,
) -> Result<(), BridgeError> {
    let mut bytes = Usage {
        bytes: size_of::<EditProjection>(),
        nodes: 0,
    };
    p.heap(&mut bytes)?;
    match frame {
        ChildFrame::InitializationOpened(n::Opened::Initialize { revision, .. }) => {
            revision.heap(&mut bytes)?
        }
        ChildFrame::InitializationPrepared(n::PreparedReply::Initialize {
            revision,
            plan_token,
            view,
            ..
        }) => {
            revision.heap(&mut bytes)?;
            plan_token.heap(&mut bytes)?;
            view.heap(&mut bytes)?;
        }
        ChildFrame::InitializationTerminal(_, _) => (),
        _ => return Err(invalid_owner()),
    }
    if bytes.bytes > REPRESENTATION {
        Err(invalid_owner())
    } else {
        Ok(())
    }
}
fn last_status_wire(p: &EditProjection) -> Result<usize, BridgeError> {
    if p.domain != EditDomain::ProjectInitialization {
        return Ok(0);
    }
    let d = p.initialization.as_ref().ok_or_else(invalid_owner)?;
    // Each original view passed the native VIEW_LIMIT; do not assume recovery
    // is a scalar or drop a previous active/failed projection to admit a new one.
    let views = usize::from(matches!(d.checkout, Some(n::Checkout::Recover { .. })))
        + usize::from(d.prepared.is_some());
    Ok(views * n::VIEW_LIMIT + 16 * 1024)
}
impl EditOwner {
    pub(crate) fn initialization_agent_edit_backing(&self) -> Result<usize, BridgeError> {
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        ProjectInitializationRuntimeSlots::initialization_agent_code_peak()
            .ok_or_else(invalid_owner)?;
        let r = self
            .inner
            .registry
            .try_lock()
            .map_err(|_| invalid_owner())?;
        if self.inner.poisoned.load(Ordering::SeqCst) || r.exhausted {
            return Err(edit_unknown());
        }
        let mut bytes = Usage {
            bytes: size_of::<Registry>(),
            nodes: 0,
        };
        r.generation.heap(&mut bytes)?;
        r.loss_generation.heap(&mut bytes)?;
        r.window.heap(&mut bytes)?;
        for keys in [
            &r.blocked_projects,
            &r.image_recovery_projects,
            &r.workflow_recovery_projects,
        ] {
            bytes.add(keys.len().checked_mul(1024).ok_or_else(invalid_owner)?)?;
            for key in keys {
                key.heap(&mut bytes)?;
            }
        }
        bytes.add(
            r.domain_blocks
                .0
                .len()
                .checked_mul(4096)
                .ok_or_else(invalid_owner)?,
        )?;
        for key in r.domain_blocks.0.keys() {
            key.heap(&mut bytes)?;
        }
        if let Some(p) = &r.last {
            bytes.add(
                projection(p)?
                    .checked_mul(if p.domain == EditDomain::ProjectInitialization {
                        3
                    } else {
                        1
                    })
                    .ok_or_else(invalid_owner)?,
            )?;
            bytes.add(
                last_status_wire(p)?
                    .checked_mul(6)
                    .ok_or_else(invalid_owner)?,
            )?;
        }
        if let Some(a) = &r.active {
            if a.session.domain != EditDomain::ProjectInitialization
                || a.session.agent_initialization.is_none()
                || projection(&a.projection)? > REPRESENTATION
            {
                return Err(invalid_owner());
            }
            // Census the SAME runtime original, never a status-based estimate
            // or zero for busy/Unknown. Its whole retained source/ACL graph is
            // inside the separately reserved CODE (not added twice as DATA).
            #[cfg(all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            ))]
            {
                // The original driver legitimately holds Resources throughout
                // review. Borrow the once-bound Weak to its SAME installed Arc,
                // not that held Resources mutex or a copied/guessed runtime.
                let actual = a
                    .session
                    .agent_initialization
                    .as_ref()
                    .ok_or_else(invalid_owner)?
                    .native_code_retained_bytes(a)?;
                if actual > CODE {
                    return Err(invalid_owner());
                }
            }
            #[cfg(not(all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )))]
            {
                return Err(invalid_owner());
            }
            // The SAME original active/queued/status DATA is already in FUTURE.
            // No other domain or ordinary active receives either reservation.
        }
        bytes.add(FUTURE)?;
        CODE.checked_add(bytes.bytes).ok_or_else(invalid_owner)
    }
}
#[cfg(test)]
#[path = "edit_owner_service_initialization_memory_tests.rs"]
mod tests;
