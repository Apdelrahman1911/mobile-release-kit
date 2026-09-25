# Private desktop configuration edit adapter

This source is a **configuration-only create/save building block**, not an
enabled passive API or a shipping/platform qualification. The ordinary desktop
API and disposable read-only engine still reject `config.save`,
`project.initialize` and `assets.import`. A separate configuration-only installed
Linux x86-64 profile now connects this adapter to the existing native edit owner;
its installed Save observation is still pending. The general packaged resolver,
other edit domains and Windows mutation gates remain closed. Native-owner, UI
and hosted filesystem verification are separate prerequisites; inert tests are
not that evidence.

## Fixed scope and original authority

`mobile_release.config_edit` is used only by the dedicated main-thread owner:

1. `capture_config_edit(lease)` returns a `ConfigCheckout` after the short native
   scope settles. Its `.base` is a fresh parsed copy or authoritative `None`;
   `.revision` is an opaque token, not a public digest or snapshot revision.
2. `prepare_config_edit(lease, checkout, expected_revision, expected_base, draft)`
   consumes that checkout's one prepare attempt. The same concrete lease and
   original checkout are required, even if another parsed document is equal.
   Invalid input also exhausts the attempt; there is no rebase or retry.
3. `apply_config_edit(lease, plan)` consumes the exact `PreparedConfigEdit`
   **before** acquisition. No new data, paths or flags are accepted at Apply.
4. `discard_config_edit(checkout_or_plan)` idempotently retires authentic
   in-memory authority only. It never closes native handles, deletes a journal,
   or runs recovery. The original native owner must settle those resources.

Only `release/mobile-release.json` and root `.gitignore` are observed/delegated,
in that order. `release` is the only possible new application directory. An
invalid, unknown-version or unsafe existing configuration is never treated as
absence. No workflows, metadata skeleton, version source, build, asset, Git,
Store or credential operation is authorized by this adapter.

The concrete `InitRootLease` owns root anchoring, single-link input admission,
the fresh original common lock description, both init/build-input pending
namespace checks, and immutable raw/ancestor revision rechecks. The adapter
does not reopen paths or populate a new workspace parent map. Every later scope
uses the **same original `RootedRevision` object**. No lock spans UI editing or
review, and original-child finality cannot be reconstructed by another process.

The picker registers a pathname, not continuous write custody. Open checks the
project currently at that path and creates the fresh original `InitRootLease`.
Prepare and Apply retain that same lease/revision; a prior snapshot or matching
expected configuration is not inode authority. The UI shows the submitted
project path in review and confirmation. A folder replaced before Open can be a
different admissible project; after Open, original lease/revision checks govern.

## Preparation, bounds and review

Preparation first admits/copies bounded exact JSON and derives bytes in memory.
It then rechecks the original revision in a fresh short native scope. Only after
that scope actually settles is a plan/token minted and published. A pure input
refusal before acquisition says nothing about global project cleanliness.
Preparation never calls the writing `InitWorkspace._prepare`, native apply,
filesystem probes, recovery, or a CLI handler.

- Original/expected/draft configuration: 512 KiB per document, depth 28 and
  8,000 nodes including keys. Expected base plus draft: 768 KiB/16,000 nodes.
- Pretty serialized configuration: an independent 512 KiB bound.
- Ignore original and result: valid UTF-8, at most 1 MiB each.
- Complete review view, **including** preview and inventory: 128 KiB. Refuse
  overflow; never truncate the proposed review.

The checkout retains immutable JSON bytes, and file observations retain owned
tuples/bytes rather than mutable `ObservedFile.before` dictionaries. The plan
retains immutable payloads/view bytes and an original-object association.
Constructing, copying, serializing or supplying lookalikes does not reconstruct
authority. `.base` and `.view` return fresh parsed data for local UI use, not the
retained state. Opaque tokens are meaningful only in the original live owner.

Semantic equality is type-exact, object-order-insensitive and array-order-
sensitive. A semantic configuration no-op supplies `payload=None`, preserving
the actual original bytes/inode through the transaction. A changed configuration
uses the CLI's existing UTF-8, indent-2, `ensure_ascii=False`, final-LF bytes.
No-op formatting is not rewritten just to match that serializer.

The review view has exactly:

```text
schemaVersion: 1
files: [
  {path: "release/mobile-release.json", action: create|replace|preserve,
   beforeBytes: integer|null, afterBytes: integer},
  {path: ".gitignore", action: create|append|preserve,
   beforeBytes: integer|null, afterBytes: integer}
]
createReleaseDirectory: boolean
rewritesConfigFormatting: boolean
ignoreAdditions: fixed ordered ignore-line subset
preview: existing ConfigPreview result
```

Null byte counts mean original absence. Preserve counts are original **raw**
sizes, not reconstructed JSON lengths. Directory creation is true only for a
config create with originally absent `release`; formatting rewrite is true only
for existing-config replacement. The preview uses the captured base and exact
validated final draft. It is not another file revision or mutation authority.

## Conservative ignore behavior

The ten fixed `init_transaction.IGNORE_LINES` are the only permitted rules:
the original evidence/init/metadata seven plus `.mobile-release-version-prepare/`,
`.mobile-release-version/` and `.mobile-release-version-cleanup/`. Configuration
still has exactly its two writable destinations; metadata or version Save cannot
add rules. Metadata explicitly retains its original seven-rule proof; only the
separate [saved-version VALUE writer](desktop-release-version-edit.md) requires
all ten. These source changes do not enable that writer.
Unprefixed or root-prefixed exact positive directory lines count as sufficient
coverage. LF/optional preceding CR split patterns; leading spaces are meaningful.
Any later syntactic negation (`!` in column zero) invalidates earlier proofs.

- Complete existing proof, including a complete suffix after negations:
  preserve exact bytes and use `payload=None`.
- Missing coverage, with no syntactic negation anywhere: append only uncovered
  fixed rules, retaining all original bytes/comments/CRLF behavior.
- Missing coverage **and any** syntactic negation, even an unrelated one:
  refuse `ignore_conflict`; do not override uncertain existing intent.
- Escaped `\!` and space-prefixed ` !` are not syntactic negations.

A config no-op can still require a reviewed ignore append. Whole-operation
no-op requires both payloads to be `None`. The CLI's default exact-spelling
append behavior is deliberately unchanged; only the editor uses sufficient-
coverage filtering. The shared one-directory proof retains build-input policy.

## Effects are not overall completion

Capture/prepare failures raise redacted `ConfigEditFailure.outcome`. Apply
returns `CoreEditOutcome`, copied/merged only **outside** native scope exit:

| Field | Closed values |
| --- | --- |
| `effect` | `not_started`, `unchanged`, `rolled_back`, `committed`, `unknown` |
| `journal` | `not_created`, `clean`, `recovery_required`, `unknown` |
| `resources` | `settled`, `unknown` |
| `reason` | `none`, `invalid_params`, `invalid_config`, `ignore_conflict`, `stale_revision`, `pending_state`, `busy`, `cancelled`, `filesystem_error`, `custody_unknown`, `unsupported_platform` |

No exception text is parsed into these codes. Unknown native types/combinations
fail closed, with no duck-typed backend or legacy apply/recovery fallback.
Previously known commit/rollback facts and the first primary failure survive
later close failure. A genuine committed decision can precede durable cleanup;
`committed` alone, or any non-`none` reason, is not a successful save.

These resource facts cover only the short native scope. The outer owner must
also prove retained lease/guard settlement, original-child wait/reap, real
stdout/stderr EOF and owned task settlement before reporting final success.
Timeout, STOP, child exit, response loss or a new observer is not rollback proof.
Uncertain settlement blocks further mutation; the GUI receives no recovery
authority. Reports contain fixed codes/paths, not raw ignore content, unknown
input keys, argv values, absolute paths or original identity digests.

## Evidence boundaries

`tests/desktop/test_config_payloads.py` specifies pure CLI byte parity and
ignore/equality cases. `tests/desktop/test_config_edit.py` installs explicitly
inert concrete seam classes and guards IO/native imports. It specifies bounded
input/output, create/save/no-op inventory, exact authority, consumption,
deep-copy isolation, typed outcomes, close failure and passive-gate cases.
Neither suite executes a real root lease, file transaction or child owner, nor
proves inode preservation, native cancellation safety, platform support or
packaged readiness. Those require separately reviewed hosted checks.
