# Android Execute: fixed query-prepare role

## Confirmed product defect

The same mismatch exists in public source `bf9d397bde641aae4b4cd205f3c962e899557650`
and the current integration source:

1. `saved_command_execute_native::ExecuteNativeBooks::new` selects
   `LeasedAndroidToolchainSlots::new_execute`.
2. `android_leased_toolchain_macos::inspect_selected` uses query
   `Role::LocalStoreExecute` (query value **3**).
3. Native `android_catalog_query::ClientBook::prepare` maps it to prepare
   `Role::LocalStoreExecute` (prepare value **4**) in the fixed 64-byte request.
4. `android_registration.m::client_exchange` accepts only prepare **2/3** on
   query transport **2**. It rejects Execute before the XPC `prepare` call.
   The original Rust `ClientAttempt` has already entered; a zero return is
   correctly retained as unknown, not assumed to prove peer non-entry.
5. The resident's existing `prepared_reply` already accepts prepare **4** and
   binds query **3**. Its original `QueryReader` supports the exact selected
   `ReadIntent` then `Finish` route, with cleanup `Stop`/`Status`.

These are three different enums. The native **transport** roles remain exactly
registration=1, query=2, maintenance=3. Do not raise that transport limit.
Execute query permits `ReadIntent` sequence1 and `Finish` sequence2, not `Scan`
or any registration/publish/Store request. App, prepare and query clocks agree:
1200-second work, 1210-second hard bound, and earlier first-failure+10 cleanup.
No clock, protocol version, retry, peer requirement or native ownership changes
are needed.

This is not an intentional unavailable flag. Installed Execute admission uses
the real Mac compiled runtime anchors, supplier profile, original registered
tool selection and separate source/material/provenance gates. Development,
unconfigured and unsupported profiles remain unavailable. Fixing this predicate
does not satisfy those other gates or authorize a Store operation.

## Root-only patch

Apply `android-execute-prepare-role-20261019.patch` to the two existing native
files. It extracts only the role predicate into a pure C function actually used
by `client_exchange`, admitting query prepare **2/3/4** and no other role.
All existing length, magic, cleanup, client/callback/data custody and peer checks
remain in place.

The added Mac-only test lives in the existing `android_registration.rs` FFI
test module, not the unsafe-forbidden prepare codec module. It calls that same
production predicate across all 256 prepare bytes and registration/query/
maintenance/unknown transport values. It acquires no client, clock, service,
credential, tool or filesystem state. Exact test filter:

`android_registration::tests::native_prepare_role_predicate_matches_closed_rust_roles`

Root separately composes Project's new Generate prepare5/query4 change. Only
after that enum/mapping is present, add its named prepare variant to this test's
query array and permit5 in the same C predicate. It is **not** a new transport5.

## Evidence and remaining native check

Author: source trace and patch apply-check passed. No Cargo, compiled/native
test, XPC, tool, Store, install or hosted operation was run. Existing codec
regressions already cover exact role clocks and malformed/reserved fields;
they are not evidence that this C gate admitted Execute.

Smallest later functional check uses the existing actual query/SH owners with
a genuinely registered, current tool selection: arm Execute's original clock,
prepare on the fixed signed helper, read the exact selected intent, finish,
and require actual helper and app native joins/one-close retirement. Do not
start `StoreRuntimeSlots`, the Execute Python worker, credential acquisition or
a Store request. A known stopped/refused branch must still retain original
cleanup and never be relabeled success. There is no existing Mac Execute-query
lifecycle test to claim already passed; Root must approve that narrow check
before execution. No new workflow, broad suite or UI automation is required.

The completed Xcode companion run39301915324 is a separate graph. This app-side
Android correction neither invalidates that result nor repairs its own shipped
app binary without the later actual Mac app build and verification.
