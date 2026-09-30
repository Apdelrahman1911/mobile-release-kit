//! B1 boundary DATA tests only. Native primitive/NTFS qualification remains
//! in the existing writer tests and a separately admitted Windows route.
use super::*;

fn plan_bytes() -> Vec<u8> {
    let mut bytes = b"MRKIW1\0\0".to_vec();
    for n in [0u32, 0, 0, 10] { bytes.extend_from_slice(&n.to_le_bytes()); }
    bytes.extend_from_slice(b"C:\\project"); bytes
}
fn owner() -> Result<Box<Owner>, u32> { Owner::prepare(&plan(&plan_bytes())?, 17) }
fn request(operation: u32) -> Request {
    Request { size: 64, version: 1, operation, output_capacity: OUTPUT_MAX as u32, ..Request::default() }
}

#[test]
fn b01_c_layout_sizes_offsets_and_closed_limits() {
    let value = info();
    assert_eq!(value.size, 168); assert_eq!(value.version, 1);
    assert_eq!(value.request_size, 64); assert_eq!(value.reply_size, 80);
    assert_eq!(value.request_align, 8); assert_eq!(value.reply_align, 8);
    assert_eq!(value.request_offsets, [0, 4, 8, 12, 16, 24, 32, 40, 48, 52, 56, 60]);
    assert_eq!(value.reply_offsets, [0, 4, 8, 12, 16, 24, 32, 40, 48, 52, 56, 60, 64, 68]);
    assert_eq!((value.input_max, value.output_max), (65_536, 65_536));
    assert_eq!((value.max_children, value.max_moves, value.max_deletes, value.max_passes), (38, 16, 38, 32));
    assert_eq!(value.operations, 18); assert_eq!(value.reserved, 0);
}
#[test]
fn b02_malformed_plan_closed_tags_counts_ascii_and_trailing_bytes_refuse() {
    assert!(plan(&plan_bytes()).is_ok());
    let mut bytes = plan_bytes(); bytes.push(0); assert!(plan(&bytes).is_err());
    let mut bytes = plan_bytes(); bytes[8..12].copy_from_slice(&39u32.to_le_bytes()); assert!(plan(&bytes).is_err());
    let mut bytes = plan_bytes(); bytes[24] = 0xff; assert!(plan(&bytes).is_err());
    assert!(plan(&vec![0u8; INPUT_MAX + 1]).is_err());
    assert!(role(0).is_err()); assert!(role(11).is_err());
    assert!(matches!(role(9), Ok(ImageRole::StagedImage)));
}
#[test]
fn b03_every_header_capacity_and_reserved_check_precedes_entry() -> Result<(), u32> {
    let owner = owner()?;
    let before = owner.native.costs().map_err(native_error)?;
    for operation in [0, 19, u32::MAX] {
        assert_eq!(header(request(operation)), Err(WIRE));
    }
    let mut r = request(6); r.output_capacity = OUTPUT_MAX as u32 - 1;
    assert_eq!(header(r), Err(BOUNDS));
    let mut r = request(1); r.input_len = INPUT_MAX as u32 + 1;
    assert_eq!(header(r), Err(BOUNDS));
    let mut r = request(2); r.reserved = 1; assert_eq!(header(r), Err(WIRE));
    let mut r = request(1); r.owner = 17; assert_eq!(header(r), Err(WIRE));
    let after = owner.native.costs().map_err(native_error)?;
    assert_eq!((before.native_records, before.effects_entered), (after.native_records, after.effects_entered));
    assert_eq!(owner.sequence, 0); assert_eq!(owner.frame.phase, 0);
    Ok(())
}
#[test]
fn b04_wrong_owner_wrong_kind_and_unissued_keys_never_resolve() -> Result<(), u32> {
    let mut value = owner()?; value.begun = true; // DATA-only preflight state; no native call.
    let mut r = request(3); r.owner = 18; r.a = value.images[0].value;
    assert!(matches!(value.preflight(r), Err(OWNER)));
    r.owner = 17; r.a = u64::MAX; assert!(matches!(value.preflight(r), Err(TOKEN)));
    r.operation = 11; r.a = value.images[0].value;
    assert!(matches!(value.preflight(r), Err(TOKEN)));
    assert_eq!(value.native.costs().map_err(native_error)?.effects_entered, 0);
    assert_eq!(value.sequence, 0); Ok(())
}
#[test]
fn b05_pass_generation_kind_eof_and_actual_key_are_all_required() -> Result<(), u32> {
    let mut owner = owner()?;
    let pass = Pass { value: 99, key: None, image: 0, generation: 2, kind: 2, complete: true };
    assert!(pass_matches(&pass, 99, 2, true, 2));
    assert!(!pass_matches(&pass, 99, 2, true, 3));
    assert!(!pass_matches(&pass, 99, 1, true, 2));
    assert!(!pass_matches(&pass, 99, 2, false, 2));
    assert!(!pass_matches(&pass, 100, 2, true, 2));
    owner.latest[0] = 2; owner.passes[0] = Some(pass);
    // Correct DATA alone cannot manufacture the original private PassKey.
    assert_eq!(owner.pass(99, 2, true), Err(TOKEN)); Ok(())
}
#[test]
fn b06_nonblocking_admission_does_not_wait_or_mutate_the_original() {
    let slot = Mutex::new(State { attempted: false, fatal: false, owner: None });
    let Ok(guard) = slot.try_lock() else { panic!("initial admission"); };
    assert!(matches!(slot.try_lock(), Err(TryLockError::WouldBlock)));
    assert!(!guard.attempted && !guard.fatal && guard.owner.is_none());
}
#[test]
fn b07_panic_retains_owner_pinned_frame_result_and_absorbing_unknown() -> Result<(), u32> {
    let mut state = State { attempted: true, fatal: false, owner: Some(owner()?) };
    let Some(original) = state.owner.as_mut() else { panic!("missing owner"); };
    original.frame_mut().input[0] = 77;
    original.frame_mut().phase = 1;
    original.frame_mut().receipt.sequence = 19;
    let owner_address = (&**original) as *const Owner as usize;
    let frame_address = original.frame.as_ref().get_ref() as *const Frame as usize;
    let result = catch_unwind(AssertUnwindSafe(|| panic!("fixed simulated boundary panic")));
    assert!(result.is_err()); poison(&mut state);
    let Some(original) = state.owner.as_ref() else { panic!("lost owner"); };
    assert_eq!((&**original) as *const Owner as usize, owner_address);
    assert_eq!(original.frame.as_ref().get_ref() as *const Frame as usize, frame_address);
    assert_eq!(original.frame.input[0], 77); assert_eq!(original.frame.phase, 3);
    assert_eq!(original.frame.receipt.sequence, 19); assert!(original.unknown);
    let mut r = request(2); r.owner = 17;
    assert!(matches!(original.preflight(r), Err(USED)));
    assert!(!original.native.settled()); Ok(())
}
#[test]
fn b08_response_bounds_aliases_and_wrap_are_pure_refusals() {
    assert_eq!(range(usize::MAX - 1, 4), Err(BOUNDS));
    assert_eq!(range(0, 4), Err(WIRE));
    assert!(!disjoint(&[(10, 20), (19, 30)]));
    assert!(disjoint(&[(10, 20), (20, 30)]));
    let mut bytes = [0u8; 4];
    let mut out = Encoder { data: &mut bytes, at: 0 };
    assert!(out.u64(9).is_err()); assert_eq!(out.at, 0);
}
#[test]
fn b09_observation_is_data_not_settlement_and_does_not_reset_unknown_frame() -> Result<(), u32> {
    let mut value = owner()?; value.unknown = true; value.frame_mut().phase = 3;
    value.frame_mut().input[0] = 23;
    let mut bytes = vec![0u8; OUTPUT_MAX];
    let r = value.observe(1, 0, 0, &mut bytes)?;
    assert_eq!(r.status, OK); assert_ne!(r.flags & BRIDGE_UNKNOWN, 0);
    assert_eq!(r.flags & HANDLES_SETTLED, 0); assert_eq!(r.output_len, 96);
    assert_eq!(value.frame.input[0], 23); assert_eq!(value.frame.phase, 3);
    assert!(value.unknown); assert_eq!(value.sequence, 0); Ok(())
}
#[test]
fn b10_prepared_keys_are_bounded_and_prepare_is_not_an_activation() -> Result<(), u32> {
    let mut value = owner()?; let mut bytes = vec![0u8; OUTPUT_MAX];
    let result = value.prepared_output(&mut bytes)?;
    assert_eq!(result.owner, 17); assert_eq!(result.count, 1);
    assert_eq!(result.output_len, 16); assert_eq!(result.flags & OWNER_BEGUN, 0);
    assert_eq!(value.native.costs().map_err(native_error)?.native_live, 0);
    assert!(value.heap_bytes() + RETURN_RESERVE <= BRIDGE_HEAP); Ok(())
}

#[test]
fn b11_settlement_reserve_is_closed_and_never_overrides_unknown_or_total_budget() -> Result<(), u32> {
    let mut value = owner()?;
    value.begun = true; // DATA-only bridge state; no primitive/handle operation.
    value.sequence = CALLS - FINAL_CALLS;
    let before = value.native.costs().map_err(native_error)?;
    for operation in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15] {
        let mut r = request(operation); r.owner = 17;
        assert!(matches!(value.preflight(r), Err(USED)));
    }
    // No issued DeleteKey: 14 passes only the settlement-budget gate, not key admission.
    let mut r = request(14); r.owner = 17;
    assert!(matches!(value.preflight(r), Err(TOKEN)));
    r.operation = 16; r.a = value.images[0].value;
    assert!(matches!(value.preflight(r), Ok(Call::Close(0))));
    r.operation = 17; r.a = 0;
    assert!(matches!(value.preflight(r), Ok(Call::Retire)));
    value.unknown = true;
    for operation in [14, 16, 17] {
        r.operation = operation;
        assert!(matches!(value.preflight(r), Err(USED)));
    }
    value.unknown = false; value.sequence = CALLS;
    for operation in [14, 16, 17] {
        r.operation = operation;
        assert!(matches!(value.preflight(r), Err(USED)));
    }
    let after = value.native.costs().map_err(native_error)?;
    assert_eq!((before.native_live, before.effects_entered), (after.native_live, after.effects_entered));
    assert_eq!(value.frame.phase, 0); Ok(())
}
