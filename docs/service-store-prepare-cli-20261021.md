# Store Prepare and current-inventory CLI delegation

This adds two separately approved phases to the existing Store Inbox/Saved
owners. It does not add a provider transport, queue, runner or native nomination.

## User boundary

Desktop Advanced selects one fixed action: Android/iOS access, Android/iOS
candidate preparation, Android/iOS current-version inventory, or paired current
inventory. It captures the actual saved project, current assigned credential
material and original native input. Both requires the same current context and
two genuine original loans; cached preferences/list/status are not material.

1. Explicit **Prepare permission** permits only the existing native Prepare.
2. After the original Prepare call really returns and its Prepared is attached,
   Desktop displays that exact review and can grant a separate **Start permission**.
3. The installed CLI invokes only the separately granted phase. No automatic
   Start, retry, restore, Execute, Reconcile or version allocation follows.

```
mrk store-prepare PROJECT INSTANCE GRANT SELECTION --reviewed --json
mrk store-start PROJECT INSTANCE REQUEST GRANT REVIEW --reviewed --json
mrk store-status PROJECT INSTANCE REQUEST --json
mrk store-cancel PROJECT INSTANCE REQUEST --json
```

Old `store-submit` and its existing Access/Prepare/Execute/Reconcile contracts
are unchanged. Its grants cannot authorize a new Prepare or inventory query.
Android and paired inventory require their own explicit temporary-Play-edit
consent. An unobserved/inconclusive summary keeps required-null fields even when
its operation completed; it is not current inventory, readiness or allocation
authority. Reports contain bounded public counts/digests only, no credentials,
private paths, provider bodies or fabricated receipts.

## Original ownership and finality

- The original Store Book retains at most **32 total old/new rows**, including
  terminal and Unknown tombstones. One new preparation retains the same request
  ID through both phases; each phase has its own consumed permission.
- Main-window Allow captures only actual native inputs/current weak identities.
  READ/service identity and saved observation are rechecked off/under the
  original locks. Current material is freshly borrowed before native admission;
  it is not copied into every row. Original Store/Document budgets remain gates.
- The new optional link is installed by the **existing Saved Prepare
  construction before publication**. Actual attached/installed facts distinguish
  a post-commit error from never-admitted refusal. A lost call is Unknown.
- Both outer ordinary GUI Start frontdoors check linked origin **before** their
  destructive context/material tail; the common Saved Start checks it before
  take/consume. A foreign/GUI call cannot steal or retire a service-created
  Prepared. Ordinary unlinked requests use the old path.
- A query's original inventory witness is captured and armed on the same native
  owner before releasing GO. All original material checks, clocks, first-F,
  STOP, finality and history behavior remain. The existing linked-only 5ms READ
  sampler also covers this exact link, including earlier revoke after STOP.
- Settlement requires the original Prepare/Start callers, actual native
  retirement and the exact existing history return. Progress or terminal-shaped
  DATA, GUI hiding, status, process exit and a newer coalesced row do not join
  anything. Failed history retains its claim; Unknown is absorbing/no replay.
- The UI retains its real Allow/Start-permission promises and original API.
  A native event or cold status cannot create an old GUI Attempt or recreate
  permission. Both old native controllers still own their existing behavior.

## Actual-review corrections

The final packet includes both missing observer crate roots; the same existing
per-project pre-send recheck for old StoreRequest and new StorePreparation;
exact four AppManifest/MAIN-window permission entries; and separate original
platform cfgs on both fields in the affected inert constructor. An existing
RAW test checks the real manifest/ACL, while an existing real Service regression
covers the reused project/alias/revoke helper.

The report adapter consults the SAME Binding context and original
`current_inventory_data` predicate. If its exact command/dispatch or paired
observation cut is absent, otherwise-observed fields become required-null
Inconclusive DATA. Real temporary-edit-unconfirmed/partial-pair warnings survive;
there is no new receipt or cleanup/Unknown inference. The existing actual core
decoder test covers short/false-dispatch and full6/7/13-command cases. Finally,
frontend correlation pins the original Prepare grant and selection across the
later separate Start grant, including when the original permission has no row.

## Complete retained bound

No memory/IPC/row/time limit increases. The existing Store **2MiB** backing
continues to include old/new mixed rows, failed claims, weak tombstones and all
public/nonworker copies. New DATA assertions check these conservative terms:

| Concurrent reservation | Bytes |
| --- | ---: |
| 32 rows, each <=8KiB complete Scope/Entry plus two <=8KiB report heaps | 786,432 |
| eight original IPC workers: 4KiB request + two 8KiB public forms each | 163,840 |
| native/history conversion and off-IPC public copies | 163,840 |
| fixed grants/inputs/bindings: <=96KiB Document + <=32KiB Saved | 131,072 |
| separate native RAW original plus three bounded 128-node forms | 204,800 |
| **Sum (no shared-worker or early-retirement credit)** | **1,449,984** |

Capacity, not just length, is checked before retaining selection/scope/report.
The fixed RAW path uses the same strict duplicate-key parser with 8KiB, 128 nodes
and depth8. Its crate-private parser visibility is the only parser change; old
callers/limits are unchanged. The assertions are **authored, not executed**; they
do not claim measured target layout or current complete Document admission.
Material/source descendants remain in the original native census, including
paired inputs; no old source/review/pending reservation is removed.

## Packet and evidence

- Author base: `f6b8b885584e2706466b5fd55a9c260350f3b519`.
- 14 new source/test leaves plus this guide and the detached 36-target patch.
  **Only these 16 new paths belong in the author commit.** Existing tracked
  sources in the worktree are untouched; shared files are Root-only hooks.
- Current before/after images: `.task-store-prepare/current-hooks/`, based on
  `55489017562b4099c5fe011c1275a3354cde7875`. They preserve A+B+C,95ef and stored-key
  reuse. One current Apple-memory fixture receives only the required `None`
  constructor field. Original author/test images remain under `hooks/`.
- Root applies contextual hooks once, preserving any later Images/other union;
  never overwrite current parents with entire after-images.
  At Root21cbb the later Images/catalogue changes cause only package.json and
  installed_cli.rs context conflicts; Root owns their surgical union. Other34
  targets apply. No stale full-file replacement is authorized.
- Node: **16 unique new cases passed** cumulatively (14 in v2, the sole remaining
  actual two-controller case in v3, and the new original-grant correlation case
  alone in v4:1pass/0skip, actual exit0). v1 11/15 and v2 14/15 failed attempts are
  retained. The final fixture stopped calling an intentionally disabled old
  GUI Start; it checks disabled Start/hide/clock without changing old behavior.
- One complete composed strict TypeScript `--noEmit` check passed, actual caller
  joined exit0. It covered the retained author projection; this is not a claim
  of another TS run after Root's later App/package union or the narrow
  original-grant comparison correction (which has its focused Node pass).
- Successful projection/link/cache was exact-rematched and retired after both
  original callers returned. v4 also rematched all373 source files and removed
  only its projection/link after its caller exited; failed v1/v2 remain.
- **17 new Rust DATA tests remain unrun**:9 Inbox/history/capacity,3 actual Saved
  guard/core-decoder,3 real installed-CLI parser/codec,2 native RAW/typed-census.
  Exact new plus seven affected selectors are in `.task-store-prepare/test-selectors.json`.
  The code parses with the pinned rustfmt only, not a compiler/typecheck result.
- No native launch, credentials, Store/provider call, network, UI automation,
  Cargo, installer or qualification run was performed for this packet. Genuine
  current-loan/native/provider journeys and composed target admission still need
  Root's applicable verification; existing availability gates remain enforced.
