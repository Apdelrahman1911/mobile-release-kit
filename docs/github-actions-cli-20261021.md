# Installed CLI: three existing GitHub actions

Source implementation of independently accepted plan
`19a17dd75dd88d07635451a0c92aa03ceec304a6d5d6aa7a814117889582fc51`
(SetupUI PLAN, Root GO). **Native/provider execution and availability are not
qualified by this packet.** No runtime/profile nomination or workflow changes.

## Delivered scope

One existing-service permission and one 32-row inbox cover only:

* `repository-create`: the exact returned native empty-repository review,
  including user/organization and private/public visibility. No files, Git
  initialization, commit, remote, push or workflow publication.
* `draft-pr-create`: the exact same-repository draft PR review. Original private
  title/body, base/head SHAs and CI-effects warning stay with the original owner.
* `failed-jobs-retry`: the exact original run/attempt/head retry of failed **and
  dependent** jobs. An accepted request does not mean the jobs passed.

```
mrk github-submit PROJECT_ID SERVICE_INSTANCE GRANT_ID --reviewed [--json]
mrk github-status PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]
mrk github-cancel PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]
```

No CLI Prepare, token/path/URL/draft/provider arguments, generic dispatch,
non-draft PR, merge or automatic retry. Publication/counter and future-tag
remain separate features; future publication siblings must reuse this same
pool with separately reviewed reference/effect grammar, not impersonate one
of these three mutation consents. Reconnect observes the same request; it does
not submit it again. Native pending/reconciliation remains in the original GUI.

## Actual ownership and finality

The MAIN native Allow captures actual private `Consent` identity, streaming
prepared hash, Connection/project/Edit witness and immutable service READ
facet. It uses Doc capture, **off-Doc** original Host/service checks, then exact
Doc/Edit/epoch rematch. The original consent/READ minimum is not renewed.
The revoke epoch is present before even the first off-Doc Allow. Pending/lost
Allow or Revoke cannot be replaced by another permission.

The existing relay claims one row and enters the existing typed Create/Retry
adapter. Ordinary GUI `None` cannot consume a delegated Consent. The original
Supervisor owner arms the exact Entry under its owners lock before spawn;
the same GO checks it immediately before actual native token claim. Errors
after entering registration are not rewritten as NotSent. The original work
endpoint (at most 60s) and two-second earliest-failure cleanup remain unchanged.
The existing watchdog samples READ expiry/revocation, including after STOP,
and its existing endpoint also includes the immutable READ end. No new task.

The callback runs only after genuine original ticket retirement **and** the
same Connection `accept_*` has applied control/currentness and final effect.
Three independent returns are required: native acceptance, actual relay caller,
and matching service-history publication. An earlier progress ACK cannot settle
a later final revision. Missing caller/retirement/history, close failure or
unknown remain fenced; a returned public status is never a native witness.
Known pre-entry refusal has a distinct NeverAdmitted/NotSent fact, still waiting
for caller and history; it does not fabricate a Supervisor receipt.

The existing IPC pre-send recheck binds a copied GitHub status to the same
service READ grant **and current project alias**, after encoding and before
writing. Alias removal/rebinding or a renewed READ cannot authorize disclosure
through the old client. This is the existing project-scoped predicate, not a
new transport or a status-derived operation permission.

One collapsed **Advanced** component owns permission across the three ordinary
visible panels. Only the exact private returned review is exempted from peer
busy. Delegation is monotone before Allow; synchronous listeners are followed
by exact context/peer/API/epoch rechecks. No fake GUI Start/StartJoined or rearm
on lost Allow. Original warnings, Check, Stop and Close remain reachable.
An exact original-request query survives coalesced latest-lease updates. GUI
release additionally waits for its actual original native Check promise; neither
service final alone nor a replacement operation supplies that return.

## Closed backing, not a quota increase

The original Document census adds **one 1MiB** debit, not one per kind. Its
conservative reserved table is 896KiB, leaving 128KiB inside that same debit:

| Retained item | Bound charged |
| --- | ---: |
| All 32 Entry/Scope/tombstones, native/history facts and wrapper copies | 32 × 16KiB |
| All eight existing IPC workers' additional typed/input/encoded copies | 8 × 32KiB |
| One lease/book/vector, three native tiny links, original-Doc Allow/rematch/status transient backing | 128KiB |

Each scope admits root length ≤4096 and **capacity ≤8192**, runtime/session
capacity ≤128 each, consent ≤64, digest ≤128, project ID ≤64; Id parsing itself
copies exactly 32 bytes. The row table also includes four input IDs, two bounded
redacted outputs, actual Row/Scope/Claim/History/read-facet structs and 2KiB of
Arc/mutex/allocator headroom per row. It does not follow weak pointers into
private material or count them as new copies. Existing private Consent,
credentials, native source/runtime, shared full IPC frames and all other
Document families retain their **unchanged original** charges; no discarded or
retired-row credit is used.

The new MAIN 1KiB decoder deserializes only closed `Allow`/`Query`/`Empty` structs
directly with serde. Unknown/duplicate fields, unexpected containers and trailing
JSON refuse without constructing a generic Value tree. Eight-worker quote
includes the original 4KiB input again conservatively, actual Request/Response
structs, three typed+encoded 2KiB outputs with vector-growth allowance and 4KiB
additional headroom. The 128KiB fixed part covers simultaneous original/current
project and redacted-review copies under the one pending Allow plus status and
lease bookkeeping. Capacity/table/full32 tests are authored; Rust is unrun.
Actual whole-Document admission may still refuse if other originals fill it.
There is no local cap change or claim of spare capacity.

Catalogue namespace **9** shares all three actions; global retained count is
384. VersionEdit stays8; FutureTag remains an alias of **the one** Cleanup6 pool.
The existing 64KiB request-list limit and 32KiB compiled capability limit remain.
Full-family encoding, alias encoding, duplicates and per-pool overflow are
covered by the affected existing catalogue methods (unrun Rust).

## Precise source composition

Worktree base `5e2352ad9e9b04f38cc79fefa57a8d20ace602d2`. Root-only patch:
`docs/github-actions-cli-hooks-20261021.patch` (28 existing parents).
Exact before/after images and pins are in `.task-github-actions-cli/hooks`.
Before images reuse accepted AppleCLI16 parents where present. Exactly three
catalogue/CLI parents instead use committed Root
`d4a639b396eaa60385b223a154710e99a2862e67`, preserving accepted VersionEdit and
FutureTag source/tests (only its redundant global-count assertion is removed;
the complete capacity test remains authoritative). The additional IPC parent
uses the same committed Root source and adds one pre-send match arm. Root must
merge only the delta into other current shared parents; never copy a stale
complete file over newer siblings.
Read-only current-Root apply-check identifies six such composition parents:
`package.json`, `App.tsx`, `bridge.ts`, `application_service.rs`,
`service_protocol.rs`, and `supervisor.rs`. The other 22 hooks apply as written.
Literal forward/reverse checks against all 28 captured images pass; this is not
a claim that the six newer Root parents were overwritten or compiled.

* New roots: service protocol/requests only, declared in library, installed CLI
  main **and** standalone installed observer. Native helpers are children of
  existing Connection, Supervisor and AssetSession modules.
* Native parents: three session Consent/Active/accept paths, their three original
  typed/GO adapters, Connection module, Supervisor, AssetSession and relay/shell.
* Service parents: protocol, ApplicationService, catalogue, installed CLI and
  its existing project-scoped IPC pre-send match.
* Frontend parents: existing three controllers, App, bridge/types, package.
* Fixed RAW permission commands are included in existing build/capability lists.
  No new binary, transport, journal, CLI grant bypass or observer activation.

## Evidence and remaining qualification

* **15 new inert Node tests PASS**, 494.286ms; **63 affected tests PASS**,
  705.932ms. Original callers returned0. Fixed nonroot65534/private0700/env-i
  projection, network/process APIs forbidden, per-test10s, core0, heap768MiB.
* **Composed strict TypeScript PASS**, returned0 in18.287s. Source was base5e +
  accepted Apple frontend + this exact frontend/hooks; no claim it typechecked
  later unrelated VersionEdit/FutureTag frontend. Retained dependencies were
  read-only. Entry/floor resource guard respected; minimum available7604MiB.
  Original caller53764 joined, projection/dependency link removed, slot returned.
* **32 Rust files source-parsed only.** No Cargo/build/native/provider execution.
  28 new Rust tests (4 protocol,15 inbox,3 CLI,3 private review/origin,2 MAIN
  decoder,1 Service pre-send regression), plus three affected catalogue methods,
  remain **UNRUN**. Private EditOwner tests use its existing unentered memory
  setup, not a worker/receipt. The new Service regression uses the actual bounded
  private StatePort fixture, registration, READ/client and dispatch methods; it
  creates no socket, native operation or provider call and fabricates no native
  receipt. It checks copied status after alias removal/rebinding and old READ
  revocation/renewal, retaining a single queued row and unchanged saved bytes.
* Concise logs/exits/source pins are `.task-github-actions-cli/results`.
  A preparatory bare-`python` command was unavailable (127); no functional test
  failure was converted into success. Fixed `/usr/bin/python3` preparation then
  succeeded. Tests were not rerun after Rust-only changes.

Root still owns current-source composition, actual library/CLI/observer build,
selected Rust tests, whole-Document admission and any installed functional or
provider qualification. No actual GitHub operation was performed by this task.
