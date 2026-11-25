# Reuse conventional Android tool folders

This slice extends the existing **Check this computer / Prepare build
environment** path. It adds no task owner, native command, listener, grant,
transport, installer, global setting or qualification flag.

## Closed lookup and precedence

1. A current selected, protected full tuple still wins. This path performs no
   conventional-source, cache, CA or download work.
2. Each explicit JDK/SDK/Gradle picker selection wins for that role.
3. Only an unchosen role checks its one fixed Mac location:
   - `/Library/Java/JavaVirtualMachines/temurin-17.jdk`
   - the original actual-UID account home plus `/Library/Android/sdk`
   - `/opt/gradle/gradle-8.14.5`

The account comes from the existing native `local_account::Account`, not HOME,
PATH or a renderer path. There is no filesystem scan, Homebrew/SDKMAN lookup,
wrapper execution or version command. Exact supported supplier bytes, versions,
SDK revisions and metadata remain compulsory; a merely similar version does
not become compatible. The original saved project requirements must also match
the protected profile before a useful finding is published.

## Original source and failure handling

The existing saved-owner inspection worker retains the same `SourceSlots`
before any read. New `DiscoveryWork` is a child of that book, not a new owner.
It retains its native account call, at most three private paths, and exact
negative edges. All directory opens, no-follow/APFS/ownership/ACL checks,
roster/hash/mode checks, SDK optional metadata and source POSTs use the existing
source implementation. The original clock, STOP, consuming closes and
worker/driver/runtime/final joins remain unchanged.

Only successful ENOENT at the held, rechecked parent records absence. A present
wrong installation is incompatible; an unreadable/unsafe source is refused;
stale input, STOP and unknown closure retain their original meanings. The first
source reason and original F are recorded before generic cleanup normalization.
No refusal offers overwrite, deletion, permission weakening or automatic retry.

The account is retained before `getpwuid_r`; its actual call-return state is
included in source settlement. A call or close that is unknown cannot publish a
finding. All source IO/closure stays outside Document/Registry guards.

## Same controller and ordinary picker

After actual positive joins, the native parent may append closed
`discoveredSources` DATA to its Inspect result: fixed scope, searched roles,
present roles and compatible components only. The child cannot supply this
field. No path, UID, native source, copy role or lease reaches the renderer.
Old Inspect result shapes remain accepted by the frontend.

Compatible unchosen components prevent a native download Review. Fresh Acquire
also repeats the original source read and refuses an unchosen compatible copy
before cache/CA effects. The compact **Found existing tools** view offers
**Use found JDK/SDK/Gradle…**, using the same two retained controllers and
ordinary native picker initialized from the private observed location. It does
not select automatically. **Choose another installation** remains available,
and **Check remaining tools** resumes without clearing the original choices.

The existing `CompletedSources`/`SourceNomination` route distinguishes acquired
and discovered origins by original operation/generation. Discovery has no
cache-producer role. Same Doc, saved lane, root/registration, catalogue and exact
own-picker publication checks still apply, including repeated role selection.
Unrelated project/API/source change, cancellation, loss or unknown retires the
shortcut, not the original status/cancel owner. A directory nomination is only
a starting location; the fresh picker, Source inspection, explicit Review and
protected-copy registration remain necessary.

A partial SDK is reported honestly. After the user selects it, the already
integrated grouped-SDK path copies only its checked required package into a new
prepared SDK and downloads only its missing partner. Existing SDK siblings stay
unchanged. Licenses, NDK/CMake/emulator/platform-tools and unsupported versions
remain manual; no new SDK assembly or download machinery is added here.

## Capacity and Root hooks

Existing quotas are unchanged. If `W` is the same SourceSlots read reservation,
`S` its transient workspace and `P` its later retained bound, `W = P + S` still
holds. The bounded path walk adds 4096 bytes to `S`; three retained path/negative
name capacities add at most `3 * (4096 + 255)` to `P`. The native Account's fixed
20KiB buffers are inline in `SourceSlots` and included by its original size
charge. Actual old source books stay counted. No workspace is excluded until
the original read/close returned and measured retained bytes fit `P`.

The existing retained-session census already visits `CompletedSources.original`
and deduplicates that same Session. It now counts its three private nominated
locations. Existing picker-original traversal counts every retained picker;
there is no inferred Document coverage or new budget.

`tool-source-discovery-root-hooks-20261020.patch` contains exactly18 existing
paths against Root `5dbd047fc8d603b51b7433a7a4576de2665c96e7`: nine Rust source
hooks, seven frontend hooks and two existing focused test files. It declares
the two new Rust children through their current parents. No lib, shell, bridge,
workflow, ACL, runtime profile or manifest hook is needed. Apply alongside the
five new source/test leaves in this commit.

## Verification and limits

Actual author verification: **66 fake-port/DATA Node tests passed**, zero
failures/skips, and full composed frontend `tsc --noEmit` passed using the
existing dependency cache. Rustfmt parsed the11 affected Rust sources only;
that is not Rust compilation. Python/vendor/source-copy implementations were
unchanged and not rerun. Private logs/projections stay task-local.

Root test selectors (defined, **not run here**):

- `tool_acquisition_protocol::discovery::tests::` — two portable DATA cases.
- `tool_acquisition_protocol::tests::discovered_sources_require_native_postjoin_component_projection_and_reject_child_forgery`
- `android_tool_sources::tests::discovered_location_ids_are_exclusive_and_cannot_borrow_an_acquired_or_arbitrary_path`
- Mac: `saved_command_owner::tool_acquisition::picked::tests::source_diagnostic_keeps_original_first_failure_through_generic_cleanup_normalization`
- Mac: `installed_runtime::android_registration_source::acquisition::discovery::tests::fixed_lookup_paths_require_native_account_home_and_keep_unentered_account_settled`
- Affected existing Mac DATA: `installed_runtime::android_registration_source::acquisition::tests::both_compiled_rosters_reserve_one_read_phase_not_registration_authority`

The Mac tests above contain no actual native lookup/source/picker or download.
Installed native execution, real conventional-source lookup, grouped SDK copy,
download and protected registration still require Root-scheduled qualification.
`NATIVE_QUALIFIED` remains false. Source/test success is not a readiness or
installed-tool claim.
