# Prepared tool folders → ordinary native picker

Plan reviewed independently by SetupUI. This slice adds a starting-directory
convenience, **not** installation, source approval, a tool lease, or readiness.
All existing qualification flags remain unchanged, including
`saved_command_tool_acquisition::NATIVE_QUALIFIED = false`.

## Integration

Apply `tool-acquisition-source-picker-hooks-20261019.patch` to Root's current
integration, together with these new sources:

- `desktop/src-tauri/src/saved_command_tool_acquisition_sources.rs`
- `desktop/src/toolAcquisitionSourcePicker.ts`
- `desktop/src/components/PreparedToolSourceFolders.tsx`
- `desktop/tests/tool-acquisition-source-picker.test.mjs`

The patch modifies only operation-specific hooks in 20 existing files. It adds
no IPC command, event, permission, dependency, native purpose ID, clock,
transport, process owner, directory walker, download, or automatic approval.
Root alone applies these shared hooks. No other worktree was edited.

Existing `choose_android_tool_source` keeps its strict 1024-byte raw parser and
current `sourceGeneration`, project and role. The only extension is an optional
`acquired: { operationId, ownerGeneration }`. Omission keeps ordinary Browse;
explicit null, paths, URLs, duplicates, extra fields and malformed IDs refuse.
The four acquisition commands/event themselves are unchanged.

## Original native path

1. Only the existing `after_final` positive accepted, complete Acquire branch
   may retain `CompletedSources`. It rechecks the same original Session's
   child/driver/watchdog/runtime/cache joins, original complete terminal, SAME
   Active's first failure/context/unknown state and original intent. The common
   owner sets its STOP signal for normal terminal input closure too: that signal
   is **not** cancellation/success authority here. Failed cache attempts/application-root nominations are
   not successful-source nominations. New preparation/finality retires the old
   shortcut; the bounded original producers remain preserved.
2. The native path comes solely from that original cache book:
   `<appdata>/tool-cache-v1/archives/tool-<operation>/sources/` followed by exactly
   `jdk.jdk`, `android-sdk` or `gradle`. Renderer/report `cacheJob` is never used
   as a path. SDK nomination requires both platform and build-tools members.
3. The same Document admits the ordinary Android picker. Before acceptance it
   rematches the completed original IDs, exact native document, full registered
   root/roster/generation, SAME returned saved-observation lane and original
   `SavedEditStamp`, current source generation and peer-owner gates.
4. Source selection intentionally retires the old acquisition input. A separate
   bounded continuation records only the exact existing control epoch advanced
   by this original AndroidSource admission and its successful selected-source
   publication. It keeps only a weak reference to that exact `OriginalWork`.
   It does not renew the acquisition intent, saved input or old consent.
   That original admission intentionally retires the empty catalogue: the
   continuation compares only the SAME retained catalogue original/generation,
   no new publication/selection, exact `CatalogChanged` retirement and unchanged
   pristine registration generation. It never restores catalogue trust.
5. `Publisher::tool_source_epoch` is read-only and accepts only its actual
   slot/index/serial/accepted state, with exactly that one pending publisher,
   no cancel/unknown and no finished publisher. General `ControlSlot::epoch`
   remains unchanged. Status polls, arbitrary increments, unrelated publishers,
   changed stamps/lanes, failures and unknown outcomes cannot advance a shortcut.
6. The nomination is bound to the same original installed picker with GO still
   closed. Same-lane/stamp/root checks repeat before GO. Doc/Edit guards drop
   before GO or GUI work. The fixed `start_android_source` accepts only existing
   panel kinds 10–12 and uses the SAME initial-directory setter, native object,
   completion, close/release and coordinator joins. Generic Android+Some(path)
   routing stays refused.
7. The user must still select a folder. The original fresh `SourceBook` probe,
   selected-source publication, Inspect, Review and explicit protected-copy
   Register are unchanged. No pre-picker probe is invented: this is a
   point-in-time **location**, not current contents or a continuing lease.

An interrupted, refused, cancelled or unconfirmed pick does not silently fall
back to ordinary Browse or replay the nomination. Its existing Android
status/cancel controls retain the operation. A later manual selection is a
separate explicit action through the existing gates.

## Lock order and capacity

Existing publisher reservation precedes reconciliation/Doc. The new lookup uses
only memory-only `try_lock` observations of tool/Android registries and already
joined original books; it never reacquires Doc or performs Host/service/FS IO.
The Doc helper obtains the native roster before its brief borrowed Edit guard.
No owner/census gate runs while that Edit guard is held.

There is one completed-source record and one current continuation, not another
owner registry. Its original Session is already in the bounded producer roster
and is included in the existing deduplicated retained traversal. New record,
root/path capacities, Arc/Weak/OnceLock storage, per-pick nomination and the
bounded main-thread path clone are charged through the existing tool and
Document installation-memory traversals. Paths stay <=4096 bytes. These are
finite-buffer counts, not RSS/allocator/AppKit bounds. No existing memory cap is
increased and no descriptor/task/lease is fabricated.

## UI behavior

The app-held `ToolAcquisitionController` captures the convenience only on an
explicit click from its already current, post-invoke-read completed result.
Its separate handoff survives only the expected original source-picker
generation progression. Acquisition intent/consent remains stale. API,
project/draft/baseline/snapshot, observation, catalogue or registration
replacement retires the handoff, including same-looking replacements and ABA.
The sole projection exception follows a claimed original pick: same catalogue
identity/generation, empty-ready → empty-refused/`catalog-changed`, and otherwise
unchanged idle registration. It permits only their original availability plus
transient busy, never promotes an unqualified registration prerequisite. Their
separate relays may arrive before or after the chooser reply. The next pick
waits for those expected settled projections and the same source's revision to
catch up. Unexpected observations either retire the convenience or remain
blocked by the original Android controller's sticky protocol/unknown state.

Each click goes to the existing `AndroidBuildController.chooseToolSource` with
the current source generation. A one-use UI claim and a final synchronous check
after its notifications prevent reentrant selection changes from forwarding a
stale request. If that check stops it before invoke, only the known-uninvoked
local attempt is cleared. Actual invoked/lost/unknown operations are untouched.
An unresolved chooser promise blocks the next prepared-folder click even if a
terminal event arrives first. No new listener or async ownership machinery is
introduced. The existing app-level Android controls remain available.

Normal guidance shows three simple prepared-folder buttons, followed by Inspect
& review. Incomplete SDK data offers only the existing complete-SDK/manual route.
No path appears in the UI. Existing installations and ordinary Browse remain
available through their unchanged controls; no wrapper command or global Java
change is suggested.

## Verification and limits

Author ran **20 new + 23 existing Node tests, all passing, zero skipped**, using
a task-owned public-source projection containing the exact shared patch and new
sources. Existing tests: `tool-acquisition-controller.test.mjs` and
`android-tool-sources.test.mjs`. No native service/tool, process, network or
filesystem source was exercised by those fake-port/DATA tests.

The new tests cover the real two-controller JDK→SDK path, stale old acquisition
intent, source-generation/identity checks, unresolved invoke retention, both
notification→invoke project-switch gaps, lost reply/original cancellation,
manual selection, incomplete SDK, unavailable picker, closed request encoding
and snapshot/API/catalogue/registration retirement. The real-controller tests
also cover both sibling-relay orders, a reply before those relays, peer revision
catch-up, the expected original catalogue retirement and unrelated catalogue or
registration changes. These replace the earlier unrealistic static-catalogue
fixture; no native positive close/join is fabricated.

Root should run after applying the patch:

```text
node --experimental-strip-types --test desktop/tests/tool-acquisition-source-picker.test.mjs \
  desktop/tests/tool-acquisition-controller.test.mjs desktop/tests/android-tool-sources.test.mjs
```

Author checked `git apply --check` against Root's integration, diff whitespace
and Rust syntax via the existing rustfmt binary. **No Rust compilation or Rust
tests were run by the author.** Root's next actual graph should include these
five new library test definitions:

- `acquire_terminal_input_shutdown_is_not_an_original_cancel`
- `prepared_folder_roles_do_not_promote_a_partial_sdk_or_duplicate_group`
- `folder_location_is_fixed_component_data_not_a_renderer_path_or_source_receipt`
- `acquired_source_nomination_is_optional_closed_ids_not_a_path_or_null`
- `tool_source_epoch_only_observes_its_exact_sole_publisher`

The terminal regression reuses the existing inert original-owner fixture and
actual strict frame decoder, `Inner::accept_at` and `stop_locked`. It distinguishes
normal terminal input closure from cancellation before/after that terminal;
both set the same STOP signal. No native positive joins or cache permit are
invented, and actual source capture remains refused without those joins. The
regression is defined for Root's combined graph, not reported as run here.

Also retain the existing same-lane, full-roster and real saved-Edit-stamp
regressions: `equal_saved_bytes_in_a_replacement_lane_are_not_the_original`,
`changed_selected_root_or_complete_roster_cannot_reuse_prepare`, and
`original_idle_edit_mutation_invalidates_the_actual_saved_stamp_and_epoch`.
The separate native-crate test
`only_fixed_android_source_purposes_accept_the_bounded_initial_location` is
defined for Root's actual Mac native graph; it is not a Linux pass or native
panel verification.

Root still owns integrated TypeScript and actual Mac compilation/picker/profile
qualification. No availability flag is enabled by source review or fake tests.
The separate corrected Xcode companion delivery uses bf9d397b; none of this
uncommitted automation graph is substituted into that hosted source tuple.
