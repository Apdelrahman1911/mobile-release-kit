//! Workflow-CLI-only borrowed census of the ORIGINAL EditOwner. The installed
//! code inspection is the same separately bounded128MiB CODE, not DATA credit.
use super::*;

// Four native files: generated<=64KiB AND actual previous<=64KiB. String
// capacity rounding is separate from the eight typed file/path/hash cells.
// Checkout/conflict and both fixed recovery views (4096 each) remain counted.
pub(in crate::edit_owner) const REPRESENTATION: usize = 2 * 128 * 1024
    + 4 * (size_of::<w::FileView>() + 8 * 128)
    + 32 * 1024 + size_of::<EditProjection>();
const ACTIVE_STATUS_WIRE: usize = w::RESPONSE_LIMIT + 32 * 1024;
// Existing strict_json can parse20k nodes before raw's8k/depth16 validation.
// Existing Workflow decoder clones raw into owned serde: count BOTH8k trees
// plus the container conversion frontier, not a claimed zero-allocation move.
const PARSE: usize = crate::protocol::NODE_LIMIT * 512 + 7 * w::RESPONSE_LIMIT;
const CHECK: usize = crate::protocol::NODE_LIMIT * 512 + 4 * w::RESPONSE_LIMIT
    + 2 * crate::protocol::NODE_LIMIT * size_of::<(&Value, usize)>();
const CONVERT: usize = 2 * (8000 * 512 + 2 * w::RESPONSE_LIMIT) + 8000 * 128 + 1024;
const DECODE: usize = if PARSE > CHECK { if PARSE > CONVERT {PARSE} else {CONVERT} }
    else if CHECK > CONVERT {CHECK} else {CONVERT};
// Three TOTAL frames, checked BEFORE decode. Opened is only four observations.
// A prepared active + two independent Status clones =3 full representations;
// after a hostile third conversion,4 representations and validation Vec peaks
// are accounted independently. A channel capacity is NOT this total bound.
const RUN_DECODE: usize = 3 * REPRESENTATION + DECODE + 6 * ACTIVE_STATUS_WIRE;
const RUN_VALID: usize = 4 * REPRESENTATION + 6 * w::RESPONSE_LIMIT + 6 * ACTIVE_STATUS_WIRE;
const RUN: usize = if RUN_DECODE > RUN_VALID {RUN_DECODE} else {RUN_VALID};
// The typed Prepare is the ONLY full draft input. Unlike Init's Open, it can
// overlap the original live reader. Keep input AND run, not max(input,run).
// Original RAW body/value is dropped before entering the native owner; its
// typed params are moved through request_bytes and destroyed before queue send.
const INPUT_TREE: usize = 8000 * 512 + 2 * 512 * 1024;
const RAW_PARSE: usize = crate::protocol::NODE_LIMIT * 512 + 7 * c::REQUEST_LIMIT;
const RAW_TYPED: usize = crate::protocol::NODE_LIMIT * 512 + 4 * c::REQUEST_LIMIT + INPUT_TREE;
const INPUT: usize = if RAW_PARSE > RAW_TYPED {RAW_PARSE} else {RAW_TYPED};
const CONTROL: usize = 1024 * 1024
    + size_of::<Session>() + size_of::<Resources>() + size_of::<ActiveOwner>()
    + size_of::<agent_workflow_edit::Link>()
    + 3 * size_of::<crate::service_workflow_edit_requests::Call>()
    + 4 * (size_of::<crate::application_service_host::NativeProject>() + 4096 + 128)
    + 4 * (size_of::<tokio::sync::oneshot::Sender<Result<(), BridgeError>>>()
        + size_of::<tokio::sync::oneshot::Receiver<Result<(), BridgeError>>>() + 256);
pub(in crate::edit_owner) const FUTURE: usize = INPUT + RUN + CONTROL + 2 * c::REQUEST_LIMIT;
const CODE: usize = crate::macos_history_inventory::CODE_CONTROL_RESERVE;

pub(in crate::edit_owner) fn prospective(p:&EditProjection,frame:&ChildFrame)->Result<(),BridgeError>{
    let mut bytes=Usage{bytes:size_of::<EditProjection>(),nodes:0}; p.heap(&mut bytes)?;
    match frame {
        ChildFrame::WorkflowOpened(v)=>{v.revision.heap(&mut bytes)?;v.observed.heap(&mut bytes)?;},
        ChildFrame::WorkflowPrepared(v)=>{v.revision.heap(&mut bytes)?;v.plan_token.heap(&mut bytes)?;v.view.heap(&mut bytes)?;},
        ChildFrame::WorkflowTerminal(_,_)=>(),
        _=>return Err(invalid_owner()),
    }
    if bytes.bytes>REPRESENTATION{Err(invalid_owner())}else{Ok(())}
}
fn last_status_wire(p:&EditProjection)->Result<usize,BridgeError>{
    if p.domain!=EditDomain::GitHubWorkflows{return Ok(0)}
    p.workflow.as_ref().ok_or_else(invalid_owner)?;
    // A normal full view<=256KiB; two fixed recovery views<=8KiB combined.
    // Keep checkout/conflict/scalar overhead and both independently encoded
    // statuses. No old projection is cleared or treated as a native receipt.
    Ok(ACTIVE_STATUS_WIRE)
}
impl EditOwner {
    pub(crate) fn workflow_edit_agent_edit_backing(&self) -> Result<usize, BridgeError> {
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        GitHubWorkflowRuntimeSlots::workflow_edit_agent_code_peak()
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
                    .checked_mul(if p.domain == EditDomain::GitHubWorkflows {
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
            if a.session.domain != EditDomain::GitHubWorkflows
                || a.session.agent_workflow_edit.is_none()
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
                    .agent_workflow_edit
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
#[path = "edit_owner_service_workflow_edit_memory_tests.rs"]
mod tests;
