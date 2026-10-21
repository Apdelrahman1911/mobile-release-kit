# CLI version source review

This adds the missing **Review precursor**, not another allocator. Manual versions remain the default. Counter creation, enrollment, reservation recovery and version editing remain separate existing flows.

## Use

Keep Desktop open on the same saved project, select automatic versions, enable its existing read access, and obtain the required current Store-inventory observation through the existing controls. Then submit only the proposed options:

```sh
printf '%s' '{"reference":"refs/heads/main","increment":"build","newCandidate":false,"acknowledgeLimitations":true}' |
  mrk version-reserve-review PROJECT_ID SERVICE_INSTANCE --stdin --json
```

`increment` is `build`, `patch`, `minor` or `major`. The optional `futureTag` uses the existing future-tag policy; it is not permission to create a tag. Input is bounded to 512 bytes. Source paths, platform/account identities, candidates, credentials and deadlines are not CLI inputs.

Keep the returned original request ID. Existing `version-reserve-status` and `version-reserve-cancel` select the stored Review or Reserve kind; a lost reply does not permit resubmission. The request appears under **Advanced · CLI version source review**. Its exact options remain separate from the user's form. A cold optional-service read failure does not disable the ordinary manual/GUI flow.

Review reads the genuine saved source and checks the already-held Store inventory; it does **not** query a Store, reserve a number, create a counter, enroll, edit a version, or authorize publishing. Missing/stale inventory still requires the existing inventory flow. Only the original returned Review can feed the separate CLI permission: click the existing **Check CLI request**, then acknowledge and **Allow one CLI reservation**, followed by `version-reserve-submit ... --reviewed`. Alternatively use an explicit ordinary GUI Reserve, which needs no CLI permission or Check. The CLI review request itself supplies no Reserve grant.

## Original boundaries retained

- Same Reserve inbox and physical 32-row limit, one active original/lease, immutable request IDs and tombstones. Review and Reserve cannot borrow each other's rows or approval. The existing request catalogue namespace does not change.
- Real MAIN window/controller calls the existing native Review. The actual Entry/SOURCE association precedes Supervisor GO and publication; exceptions at the two existing GUI-admission checks require that exact association.
- The original submission clock is captured before Service waiting. SOURCE keeps its existing 60-second work / 70-second hard limit and first-failure cleanup; the same watchdog samples the original READ/STOP during work and known cleanup. No renewal, replacement timer, or Unknown retry.
- Uncertainty in that actual READ control observation is absorbing even after an earlier STOP; later native/caller returns cannot erase it. No status poll is required to retain this fence.
- CLI Allow acknowledgement retains the MAIN-issued revision from the actual explicit Check, tied to the same API/project/private Review. Allow does not fetch a new stamp. Native consumes the exact revision once before Host waiting and checks its private successor afterward; Revoke invalidates even before a Service/grant exists. Exhaustion remains stopped/Unknown, never wraps. This is a comparison field in the bounded MAIN envelope, not a new grant/owner; existing CLI Access/Submit bytes, source/review proofs and deadlines are unchanged.
- Private Review construction still follows actual SOURCE/runtime/IO returns and current source/config/version/Store comparisons. Existing inventory freshness is at most 900 seconds; Review lasts at most its original 120 seconds and the old READ end. Native metadata/event alone is not the actual MAIN promise return or Reserve permission.
- Same-old-before-next controller reconciliation, original API promise retention, early-reentrant vetoes, manual/dirty/ABA preservation, and cold/status-only non-adoption. A consumed Review cannot later use its old READ to stop an unrelated GUI winner.
- Whole Document includes the existing additional retained-observation census plus the unchanged actual SOURCE future quote under 64 MiB. Existing separate code/source limits remain. Shared 32-row max, off-row/caller backing and enum growth are charged; the bounded IPC term joins the existing eight-worker maximum rather than creating another pool. No fit/native qualification is inferred from source arithmetic.

## Integration packet

Base: `658d8cbd397d764dd668c4b1f83990d216ac874c`. Independent PLAN: `8afffedba21a5ad4d147f930b9fca82c571566958e4d124fff569e6f06839766` (Git). Actual implementation review is separate.

The 13 owned source/test leaves, this guide and `service-version-reserve-review-cli-hooks-20261021.patch` form the scoped packet. The patch contains 34 existing-parent hooks only: actual native/source/service/CLI/relay/watchdog composition, both MAIN capability lists and both crate graphs, same shared IPC quote, and frontend integration, including the inherited Allow/revoke correction. Full before/after images, exact rosters, hashes and source selectors are retained in `.task-version-reserve-review/`. Existing-parent test copies stay unstaged. The exact original 15/30 freeze remains in `review-v1/`; its completed source review is reused, with only the READ-poison and Allow-revision successor sent for delta review. Root must preserve newer App/installed-CLI additions when composing those two shared parents.

## Evidence and remaining qualification

All logs are in `.task-version-reserve-review/results/`:

| Check | Actual result |
| --- | --- |
| Initial new controller + existing Reserve/agent controllers | `node-v1`: 38 passed, 0 failed/skipped, 1.234 s caller |
| Cold optional-service failure reproduction against preserved old controller | `node-cold-v1`: 1 failed as expected; failure retained |
| Corrected new controller module | `node-v2`: 11 passed, 0 failed/skipped, 0.757 s caller |
| READ/Allow-review successor's affected controllers | `node-revision-v1`: **41 passed**, 0 failed/skipped, 0.667 s caller; 13 new + 28 existing, not the sum of repeated runs |
| Composed frontend `tsc --noEmit --incremental false` | `typescript-v1`: exit 0, 19.228 s; before the subsequent type-unchanged cold-read catch/comment correction. Root explicitly waived an equivalent rerun. |
| Successor composed frontend | `typescript-revision-v1`: exit 0, 19.544 s, including the MAIN Access/port type addition; exact source hashes unchanged. |
| Rust source syntax | `rust-syntax-v1/v2/v3/v4`: 33 unique files parsed; not compilation or tests |

Node and TypeScript used the existing `run_owned` boundary, UID 65534, networkless public projections and fixed resource caps; actual callers returned, source hashes matched, and only their own temporary projections were removed. Shared dependency cache was not modified.

**17 new Rust tests are authored but UNCOMPILED/UNRUN.** Exact selectors and effects are in `rust-selectors.json`: 15 inert DATA/census tests, including the real original READ poison/earlier-STOP methods, native revocation-counter cuts and Mac-only actual Document + two distinct payload-metadata/SOURCE-fit regression; two reuse actual private Service/Store fixtures without sockets, native jobs or providers. The existing closed MAIN Allow-decoder test also covers the required canonical revision. That compiled 64-MiB fit, old affected controls, actual CLI/shell/observer compilation and native behavior remain Root's pending checks. No provider, Store, allocation, installed/native or hosted success is claimed.
