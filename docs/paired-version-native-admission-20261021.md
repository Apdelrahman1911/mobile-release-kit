# Paired current-inventory native admission correction

Base: `d2be161d2845a57ba6139956bdec235ab1d53d62`. This isolated packet changes
only two existing native admission sites and their existing test modules.
Root independently approved this scope; Git is the distinct source reviewer.

## Defect and exact correction

The paired request/ledger codec already accepts the ordered platforms
`["android", "ios"]`, policy schema 4 and
`require-current-shared-inventory`. The actual paired Store observation is
already serialized by the original Supervisor, and Python's existing reserved
edit parser/writer already accepts that reservation. Two stale native guards
nevertheless accepted only iOS/schema 2 and Android/schema 3:

1. `version_allocation_state_native::dialogue::Request::from_source` rejected
   the genuine bounded paired request before Reserve could start.
2. `edit_owner::version_reserve::NativeReservedVersionHandoff::new` rejected
   the paired reservation after the caller had consumed its one-use edit claim
   and taken the original handoff DATA.

Both guards now admit exactly the ordered pair with policy schema 4, in
addition to their unchanged two single-platform cases. The handoff's existing
DATA checks are factored into a private predicate so tests can exercise the
actual branch without inventing a gate, control, session or native receipt.
That predicate is not a standalone reservation parser or authority.

Unchanged: native source ref/config/version hashes, provider
`macos-clt-git/1`, bounded native state (256 KiB), outer handoff schema 1 and
12 KiB bound, current edit window, original gate/registration, and the sole
Open/Opened/Prepare/Prepared/Apply/Terminal/Retired publisher chain. The caller
still latches `edit_claimed` and takes `edit_data` once; rejection does not
reset either, select another candidate or authorize a retry.

The bounded caller inspection also checked the existing Both template and
Store observation dispatch, exact returned-reservation/request comparison,
reserved edit source rechecks and the Python paired writer. No additional
paired rejection was found in those paths. This is not a claim that all
single-platform or native execution paths have been qualified.

## Focused verification

Executed on this source tree with `PYTHONPATH=src:tests/unit`, Python 3.12.3,
`-B`, and a 90-second containing timeout: **3 existing tests PASS, 1.130 s**.

```
tests.unit.test_paired_store_versions.PairedReserveEditTests.test_pair_reserve_real_preview_apply_and_restart_same_candidate_one_put
tests.unit.test_paired_store_versions.PairedReserveEditTests.test_stale_either_inventory_refuses_before_put_without_single_platform_fallback
tests.unit.test_paired_store_versions.PairedPolicyTests.test_exact_order_same_earliest_clock_context_and_both_complete_required
```

These use synthetic observations, a fake provider/ACK and task-owned temporary
source/Init files. The first exercises the existing real preview/apply and
borrowed filesystem lock, refuses repeated Apply, and retains the same
candidate on restart with one fake PUT. They do **not** execute Rust or prove
native Store, GitHub, credential, process or remote authority.

Both changed Rust files were syntax-parsed with rustfmt (`--emit stdout`, no
source rewrite). **The following five new Rust tests are uncompiled/unrun.**
They are in the existing Linux/macOS test graph; no desktop-shell feature is
required. The first two are memory-only DATA. The last three use the existing
`application_state_store::Fixture`: private disposable directory, original
bounded load/enrollment/selection and local state readback. UUID randomness
and local private-state writes occur; no subprocess, socket, provider, native
grant, vault, Store API or secret operation occurs. Each closes the original
store; the existing fixture removes only its owned directory.

```
edit_owner::version_reserve::tests::reserved_handoff_data_admits_only_exact_current_inventory_platform_policies
edit_owner::version_reserve::tests::paired_handoff_retains_original_envelope_provider_and_byte_bound
version_allocation_state_native::dialogue::tests::native_source_admits_paired_v4_without_changing_original_v2_v3_selection
version_allocation_state_native::dialogue::tests::paired_native_source_refuses_foreign_source_provider_or_partial_observations
version_allocation_state_native::dialogue::tests::paired_native_selection_rejects_mixed_policy_platforms_without_replacing_candidate
```

The actual `from_source` fixture checks all three valid platform/policy
combinations and the retained candidate/state. Negative cases cover source
and provider mismatches, missing/reversed/duplicate/partial or mismatched
paired observations, swapped/duplicate/singleton schema-4 platforms,
pair/schema-2-or-3 substitutions, and foreign policy scope. Failed selection
must leave the original candidate, revision and durable bytes unchanged.
The handoff tests additionally refuse malformed schema/provider/envelope and
oversized DATA. Existing publisher-chain tests remain byte-for-byte unchanged.

Task evidence and exact before/after source copies are retained under
`.task-paired-handoff/`, including the raw patch, file pins and the Python/
syntax logs. No Cargo, native/provider operation, workflow edit or CI dispatch
was performed. Root must compile and execute the new Rust cases before
claiming those paths tested.
