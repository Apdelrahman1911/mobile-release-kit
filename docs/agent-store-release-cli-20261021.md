# Existing Store Execute / Reconcile through the installed CLI

Source handoff against `5e061ca34d984daed17a20cfe56e25c01a07a142`.
The accepted plan is `agent-store-release-cli-plan-20261021.md`, SHA256
`92f38f1faef3efe8fc0cbf7f6b787a2445601275df8fdd7db792ff3f03cb241e`.
Project reviewed the plan; SetupUI reviews this implementation independently.
No provider operation or native availability/qualification is asserted here.

## Delivered source boundary

The existing Store permission card, inbox, relay, Saved owner and bundled
`mrk store-submit/store-status/store-cancel` now cover all ten supported
Execute/Reconcile platform/mode pairs in the plan. No new command, credential
input, transport, namespace, Document field, process owner or runtime flag.

* Execute: candidate upload, external testing and production submission on
  Android and iOS. The existing native Prepare remains mandatory.
* Reconcile: current internal target on both platforms, Android recovery
  settlement and iOS external readiness. These do not resend a release or
  establish an earlier operation's finality. Live Unknown still fences work.
* Old basic AccessCheck and candidate-only CandidatePrepare keep their exact
  eight-field Review and old consent strings. Only the new kinds require the
  ninth `release` field and their distinct platform/kind/mode consent.

The agent still receives only opaque IDs and bounded comparison metadata.
The original full Context, exact saved config/candidate/intent/lineage,
credential/supplemental loans and native consent are rematched. Execute also
borrows the existing `ExecuteMemoryAdmission`; no generic Start bypass.
Android custom external tracks stay in the native config/receipt. Public
`configured-play-external` is expressly a semantic label, not a replacement
track name. Draft, review, tester availability and manual release remain
distinct, and no receipt is permission to retry or proof of public release.

One grant across all four kinds retains the original 300-second admission
expiry and Submit's 1200/1210 clocks. The immutable READ end, Store-only
watchdog and earliest STOP are unchanged. A known service terminal still
requires **relay return, positive original Saved retirement and actual service
history return**, in either order. Status cannot replace any of these returns.

The same mounted permission controller handles all four panels. Only the
selected, genuinely returned private Attempt is exempted from its own peer
busy reason. Other pending, reading, historical, conflicting or Unknown owners
remain busy. The monotone delegation clears that Attempt's GUI timer/Start,
not native consent, Started or finality. Its private pin survives removing
the selectable review, and callbacks must pass the original context/API/
revoke/peer recheck before the sole Allow call. Lost/refused Allow never rearms
the GUI review. Check, Cancel, context STOP and Quit remain original-bound.

## Files and exact integration

New production leaves:

* `service_store_release_protocol.rs`, a child of the existing
  `service_store_protocol` in the library, CLI and installed observer;
* `saved_command_agent_store_release.rs`, a child of the existing Saved facet;
* `asset_session_agent_store_release.rs`, a child of the existing Doc facet;
* `agentStoreRelease.ts`, closed comparison/presentation helpers, no new owner.

Four Rust test leaves and one Node file cover the actual existing methods.
The complete 24-parent delta is
`agent-store-release-cli-hooks-20261021.patch`. Its exact before/after copies
and SHA256 roster are under `.task-store-release-cli/{before,after}` and
`parents.json`. All before files are the named base, not current Root files.
Root must compose only the deltas, preserving later backup and other edits.
No new crate-root declarations or neutral Document/Saved constructor fields
are needed. The three existing roots are already in all three native graphs.

The 13 Rust parents are the Store protocol and Saved/Doc facets, Saved export,
two typed-owner accessors, two budget visibility changes, three existing test
parents, and the existing CLI parser/help. The 11 frontend parents are the
Store protocol/controller/card, four original local controllers, Execute and
Reconcile components, App and package test roster. The two old controllers
gain a comparison accessor only; their existing delegation behavior is intact.

## Unchanged retained reservation

No new allowance: the existing Store **2 MiB** debit remains inside the shared
Document reservation, with all 32 rows and eight IPC workers retained. A
conservative same-reservation decomposition (bytes) is:

| Retained backing | Quote |
| --- | ---: |
| 32 rows: 8 KiB Entry/Scope plus two 8 KiB latest/history copies | 786,432 |
| Eight worker requests/typed/encoded replies: 4 KiB + two 8 KiB | 163,840 |
| Two bounded native-result conversions, projected metadata backing | 163,840 |
| Sole grant/Approval/full Context/weak link/relay/collection backing | 131,072 |
| **Total** | **1,245,184** |
| Remaining within 2,097,152, not credited from retirement | 851,968 |

Each closed review and projected report remains at most 2 KiB; the 8 KiB
per-copy quote also covers typed/string/vector backing rather than just wire
bytes. The one review comparison copier permits 52 nodes (the full new shape
uses at most 47), still under the original 2 KiB cap. Old eight-field grammar
does not change. Native private material/source/history reservations remain
charged by their original owners; this table neither replaces nor discounts
them. The new worst-valid DATA test checks concrete type plus conservative
retained serialization/string backing, not `sizeof` alone.

## Focused evidence and limitations

* New Node **14 PASS**, affected existing AgentStore/Execute/Reconcile
  **54 PASS**, no ignored tests. Actual controllers and parsers with inert
  ports/timers only; no native, provider or IPC authority is fabricated.
* Initial new-test run was **8 PASS / 6 FAIL**: the test supplied an explicit
  Android platform where the existing candidate-history ABI requires omission.
  Only that fixture was corrected. The failure log/source and projection are
  preserved; no production parser was loosened.
* Composed strict full `tsc --noEmit` **PASS**, 18.252 seconds. Same public
  source plus all nine API DATA files and exact frontend hooks. Nonroot
  private projection, retained read-only dependencies, no installs, heap
  768 MiB; minimum available RAM 8,036,855,808 bytes. Original caller joined
  exit 0, and its exact successful projection/dependency link were removed.
* Seven new Rust files and 13 parent after-copies passed rustfmt syntax parsing
  only. **17 new Rust tests and one changed capability test remain UNRUN**.
  Exact selectors are in `.task-store-release-cli/rust-selectors.txt`.
* No Cargo, native/installed CLI execution, actual Store/credential call,
  installer, workflow or availability flag change. Root's later composed
  compile/test/native work is still required.

Concise logs, exits, tested-source manifests and cleanup receipts remain in
`.task-store-release-cli/results`. Successful Node and TS original callers
are joined; only the known failed Node fixture remains for diagnosis.
