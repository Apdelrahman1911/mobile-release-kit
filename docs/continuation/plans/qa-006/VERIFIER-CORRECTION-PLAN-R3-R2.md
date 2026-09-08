# QA-006 verifier correction plan R3-R2

**PROPOSED — plan authoring only; independent exact-hash approval required.**
This replaces neither an approval nor an executed proof. Do not implement from
this proposal until the distinct plan reviewer accepts it. It authorizes no
first-party edit, final acceptance/freeze/dispatch, VM/container operation, Store
call, commit, push, or QA-007 runtime change.

## 1. Findings, evidence, and selected solution

This revision addresses all three requests in
`plan-review-verifier-r3/PLAN-REVIEW.md` (SHA256
`a2420a0a0482769397315991d1fa272b1aac6586fc895e9b97c07da033d14f51`).
The reviewed R3 plan is preserved at SHA256
`6e3ab0f887fc85142c389e3089eab1ea37d1b03ffb358fe7d6ed87dad67d3f2c`.

Re-read the original QA-006 finding and plan, VRI-01/VRI-02 independent
implementation review, R2 approval, R3, the independent R3 requests, current
helpers/callers, and the historical 25-case driver. The causes remain:

- **VRI-01:** freely repeated/unordered `ps` suffixes and `startswith("Z")`
  conflate valid stopped evidence, malformed records, and indeterminate states.
  Actual synthetic queries accepted ZE, ZEs, Z++, ZNN, and Z+E as CLEAR.
- **VRI-02:** computing a tree OID without supplying its actual objects cannot
  satisfy the later native Git consumer. Its fresh-repository exit128 remains a
  confirmed failure. The historical no-index exploration also remains failed:
  clean differences exited1 and whitespace differences3, contrary to its
  asserted0. Preserve those raw results; this revision does not relabel them.
- **PR3-01:** capture-then-check is not a streaming limit, and the new native
  reader needs a whole-lifetime budget/ownership/cancellation contract.
- **PR3-02:** isolated Git behavior and typed closure must be executable
  requirements, not assumptions about a source-repository command.
- **PR3-03:** `?` changes from wrongly rejected syntax to recognized
  indeterminate syntax; the historical driver's assertion must be migrated
  without deleting its obligation or altering its historical evidence.

Retain R3's **complete, exclusively owned object store**, early preparation,
late native whitespace check, and final conditional deletion. Preserve all43
baseline obligations; preparation plus cleanup produce exactly45 gates.

### Narrow source-storage applicability

Use a bounded **loose-object-only** reader for this ignored, single-snapshot
verifier, not a pack decoder or a general Git implementation. Read-only author
inspection found the shared source `.git/objects/pack` and
`.git/objects/info` empty and both HEADs on loose local branch refs. This is
only an observation, **not proof that the required closure is complete**.

Before any final freeze, explicitly prove the complete required raw HEAD,
tree, and blob closure is present, correctly typed, bounded, and rehashed.
Reject packed-only/missing objects, nonempty pack/info storage, alternates,
promisor material, reftable/packed-only refs, unsupported index forms, SHA-256
object format, and unsupported tree modes. Never unpack, fetch, invoke a helper,
change Git configuration, or repair the source as a fallback. Such a rejection
is an unwaived prerequisite failure with retained evidence, not a skipped gate
or permission to silently widen support. Root has agreed only that this narrow
choice may be proposed; independent review still decides approval.

## 2. Scope and implementation map

Changes are confined to `verification-final-r1/` and new ignored proof/report
directories. Retain originals, the rejected20-entry snapshot, every failed run,
and the historical preparation archives.

| Component | Planned change |
|---|---|
| `process_gate.py` | Strict state syntax, distinct indeterminate classification, scope and original-cutoff checks. Preserve reservation-only stop authority. |
| New `native_reader.py` | Shared bounded direct-child reader and action budget used for native Git/metadata/tool observations; not Store or application execution. |
| New `git_readonly.py` | Raw descriptor-bound Git metadata/loose-object input, typed closure, controlled standalone views, isolated native Git policy. No import cycle with cleanup/bindings. |
| New `frozen_diff.py` | Explicit `--prepare`, `--check`, and `--cleanup` entry points for the owned frozen forest and evidence lifecycle. |
| `bindings.py` | Replace unsafe source-Git introspection and unbounded `read_command`; streamed source hashing; bind policy, exact leaf Git executable, helpers and unchanged source/index observations. |
| `freeze.py` | Whole-lifetime cancellation context and absent-output preconditions, including new store/owner/seal/failure/cleanup paths. No acceptance shortcut. |
| `gate_list.py` | Exactly the routing in section9; retain protocols and every baseline command obligation. |
| `owned_outputs.py` | Reuse actual `prior_workers` and descriptor-bound inventory deletion for the new cleanup; do not weaken either guard. A small reusable ownership utility may be factored without changing behavior. |
| `verify-process-gate.py` and new `verify-frozen-diff.py` | Preserve original controller controls; add state-to-cleanup, bounded-reader, isolated-Git and real-object proofs under the existing verification-process-ownership gate. No46th gate. |
| `verify-all.py`, `run-once.sh` | Only any necessary explicit native-scope/setup/publication plumbing and helper routing bindings. Preserve actual wrapper-exit, cancellation, log and one-dispatch contracts. |
| `CONFIG.json`, helper/static inventory | Bind the selected actual Git leaf and policy/cap version. Enumerate all new executable helpers; unexpected helpers remain errors. |
| New copied proof driver and reports | Migrate25 historical obligations as section10 specifies; retain old bytes/results unchanged. |

Inspect and update every caller of `read_command`, `git`, `snapshot`,
`git_tree`, `collect`, `check_frozen`, and the cleanup/bootstrap helpers.
Existing non-Git version observations cannot keep the capture-then-limit path
under a new name. No production package/API/schema/workflow/template changes
are part of this verifier correction.

## 3. VRI-01 state contract

1. Parse ASCII numeric rows with exactly five fields. Preserve rejection of
   duplicate PIDs, invalid/nonpositive PID/PGID, invalid PPID/UID, malformed
   rows, non-ASCII bytes, nonzero/diagnostic query results, and empty global
   output. The existing query byte/time limits remain2MiB/2s.
2. Accept precisely base `[RSDTtZXIWUH?]` followed by the ordered,
   nonrepeated suffix grammar `[<N]?X?E?V?L?s?l?\+?`.
   Reject every zombie-with-E combination, even if the regex matches.
3. Syntactically valid Z without E is stopped. Base ?, H, X, or an E modifier
   is **INDETERMINATE**, never stopped/readiness. Other supported states are
   LIVE. A row must first pass syntax; classification must not accept an
   independently supplied malformed Z-shaped row.
4. Validate the whole table's syntax/identity before classifying the recorded
   group. Valid unrelated indeterminate rows do not invalidate a clear target.
   Foreign UID or the reappeared original leader remains an immediate UNKNOWN
   identity conflict; do not downgrade these conflicts to retryable liveness.
5. `_group_completion` may reobserve LIVE/INDETERMINATE within its original3s
   cutoff. Each query receives only the remaining allowance (at most2s).
   Recheck monotonic time immediately after query return: even CLEAR obtained
   or published after the cutoff fails. Never refresh the allowance per row,
   state transition, query, or sleep. Persistent uncertainty fails/retains.
6. `observe_groups` may map any target INDETERMINATE/LIVE to overall UNKNOWN
   immediately for cleanup. Numeric observations remain **observation-only**:
   zero PID/group signal authority is derived from rows, names, or files.

Do not widen existing production/native runtime deadlines or redesign QA-007
ownership here. The unchanged original controller cancellation/ownership proofs
remain required in addition to these classification proofs.

## 4. Concrete resource and time limits (PR3-01)

All limits are hard, immutable constants included in reviewed helper hashes.
MiB means1,048,576 bytes; KiB means1,024. Rejection never retries with a larger
limit. These are verifier applicability bounds, not claims about the product's
supported application sizes.

| Resource | Limit |
|---|---:|
| One blob / one proposed regular file | 8MiB uncompressed |
| One tree object | 2MiB uncompressed |
| Raw HEAD commit anchor | 256KiB uncompressed |
| Loose compressed input | 8MiB +64KiB per file, additionally bounded by declared type/body |
| Unique object forest (base/proposed/empty attribute tree; anchor charged when present in a metadata view) | 64MiB uncompressed, 4,096 distinct objects |
| Traversed tree-entry references | 32,768, including repeated references |
| Tree nesting / component / relative path | 64 levels /255 bytes /1,024 bytes |
| Source/index names per snapshot | 4,096 |
| Raw copied index | 16MiB |
| HEAD/ref/gitdir/commondir record | 4KiB each; no recursive symbolic-ref chain |
| One framed object header | 96 bytes including newline |
| One pipe read/write/hash/compression chunk | At most64KiB |
| Non-object native stdout (metadata, version, diff) | 2MiB per command |
| Native stderr | 256KiB per command |
| Cat-file stdout | 64MiB +4,096×97 bytes per complete forest read |
| Aggregate object/source/native payload processing | 256MiB per top-level action |
| Actual native launches / simultaneously live native children | 64 /1 per action |
| Simultaneously active metadata views / created views | 1 /8 per action |
| Stored loose forest | 72MiB logical bytes per view/store |
| New owned data / retained diagnostic data | 192MiB /8MiB per action |
| One structured action/failure record | 4MiB |

Check both declared size and actual bytes. No allocation, `read_bytes()`,
`communicate()`, or `subprocess.run(capture_output=...)` may first absorb
an unbounded stream. Header readers stop at97 observed bytes; object bodies
stream through hashes/compression or discard/readback sinks. Tree parsing may
buffer at most its already validated2MiB body. Count deduplicated objects and
all traversed references separately so repetition cannot evade limits.

A top-level collect/prepare/check/cleanup native scope starts **one120s monotonic
work cutoff before acquisition or filesystem reading**. Each command has at
most30s and also the remaining shared cutoff. Bytes, commands, view creation,
graph nodes and reference counts never reset within that scope. Preparation's
file hashing, compression, native checks, readback, fsync and seal publication
all consume that same work allowance. Nested calls use the same context, not
fresh120s budgets. A first failure poisons the scope; no next native command.

A single additional **5s stop/join allowance** is permitted only to dispose of
an actually known, unreaped direct child after failure/cancellation. It cannot
turn an expired work result into success. The outer gate's existing900s limit,
and the original numeric group/query limits, are not widened. Check time again
after actual reap, writes/fsync and immediately before/after publication.

Maintain prefix length, prefix hash and an explicit truncation/overflow flag
when a diagnostic overflows; never call a prefix the hash of complete output.
Keep bounded raw diagnostics in private ignored evidence, not blob bodies in
stdout. Short/extra frames, child nonzero status, unexpected diagnostics, output
overflow, read error, missing EOF, deadline expiry, failed flush/close/reap or
late cancellation all prohibit a successful result or seal acceptance.

## 5. Native process ownership and cancellation (PR3-01)

- Spawn a fixed absolute executable and list argv, no shell/preexec function.
  Use `start_new_session=False`, no new PGID, `close_fds=True`, and no
  inherited extra descriptors. Git receives only its intended stdin/stdout/
  stderr. Owned filesystem descriptors are CLOEXEC.
- Git therefore remains in its invoking gate/proof's private group; it must
  not escape the outer `execute` reservation in a new session. A hard-stop of
  that still-owned outer gate group includes the new reader. Git builtins and
  the controlled environment below must not launch application/helper workers.
- Track acquisition, actual returned Popen object, pipe ownership, reading,
  EOF, native exit, reap, close, publication and handler restoration separately.
  No thread or second waiter may reap a known native child behind this reader.
  Close the write end after the final request and drain both output pipes using
  selectors/nonblocking bounded reads; never block on a full diagnostic pipe.
- On a normal exception, deadline or cancellation with an actual unambiguously
  unreaped handle, close the input, make one last actual poll, then, only if
  still reserved, stop **that direct child** and join inside the5s allowance.
  Do not reuse `_stop_reserved`'s killpg for a Git child that is not a leader.
  An already reaped child has irreversibly lost signal authority.
- Acquisition/reap exceptions that leave identity or wait ownership ambiguous
  are UNKNOWN/failure, never an opportunity to guess a PID/group or reclassify
  observations into a handle. Close descriptors actually owned, retain failure
  state, prohibit seal/cleanup/readiness, and explicitly record any unresolved
  worker instead of claiming it joined. Unknown-handle fault proofs retain an
  independent fixture owner/EOF fallback and join through that owner; this is
  proof cleanup, **not authority available to the failing verifier**.
- A known-handle read/protocol failure must not escape through a broad exception
  handler without the above stop/join. If stop/join itself becomes ambiguous,
  preserve that distinction and fail; no second guessed signal or endless wait.
- Install/share one INT/TERM flag before native acquisition and keep it through
  all result/owner/seal writes and handler restoration. Handlers set a flag;
  they do not raise halfway through successful acquisition or reap publication.
  Nested collections reuse the flag. Recheck it after the final write and after
  restoration. No acquisition occurs when cancellation is already pending.
- Record actual argv, sanitized environment policy/values, phase, measured
  bytes/time, direct child status, signal authority and actual exit. A printed
  PASS, complete-looking seal, or partial failure report does not override a
  failed/absent actual action and wrapper result.

True OS/process-ownership ambiguity is fail/retain, not guaranteed cleanup.
Generic group observations still do not prove containment of arbitrary escaped
descendants. The relevant assurance added here is that **new Git readers do not
create escaped sessions**, and known normal-error/cancel paths close and join
their actual children. No broad ps-name/PID-file/pkill cleanup is permitted.

## 6. Source reads and native Git isolation (PR3-02)

### 6.1 Raw source identity and loose closure

Do not run native Git against the real gitdir, common object directory or
index, even for the old `snapshot()` metadata calls.

Resolve the two supported layouts structurally: the root's actual `.git`
directory and QA-006's regular `.git` locator plus regular `commondir`.
Require the canonical targets already bound by WORKSPACE/owner ancestry.
A linked-worktree backpointer must identify the expected source `.git`.
Use no-follow descriptor traversal, before/after fstat identity/size checks,
and bounded reads. Do not discover another repository by walking parents.
For the real refs, accept only the configured local branch and its regular
loose40-hex-SHA1 ref. A direct40-hex HEAD may be used in a declared synthetic
detached-HEAD proof. Reject extra records, unexpected indirection, cycles,
symlinked parents/files, conflicting layouts, reftable or packed-only refs.

Read raw HEAD's object by its **actual raw40-hex ID**, not
`rev-parse HEAD^{tree}`. Stream/decompress the corresponding loose file at
`objects/<first2>/<remaining38>`; no alternate lookup. Validate the canonical
`commit <decimal-size>\0` header before body storage; independently calculate
SHA-1 over header+body and SHA256 over retained anchor bytes. Require type
commit, exact declared length, zlib EOF, no trailing compressed stream/data,
and exact filename/OID match. The commit must have one first `tree <OID>`
header and no duplicate tree header. Parse headers without executing signature
or other metadata. Retain its raw bytes/hash/type/root binding as bounded
evidence. Parent history is not traversed: the promised closure is the complete
**tree/blob forest anchored by this raw commit**, not all commit ancestry.

Traverse every referenced tree/blob through the same raw reader. Allow only
`40000 -> tree`, `100644 -> blob`, `100755 -> blob`.
Reject120000 symlinks,160000 gitlinks, noncanonical/unknown modes, wrong object
type, missing bodies, duplicate names, NUL/slash/dot/dot-dot components,
noncanonical Git byte ordering, path/count/depth overflow and recursion cycles.
Use Git's directory-aware ordering (directory names compare with a virtual
trailing slash), not ordinary decoded-string sorting. Hash/tree name handling
must preserve original bytes and the current source path encoding round trip.
Never extract a source/tree path into another directory.

Before and after graph acquisition, require the bound source pack/info
directories still empty; none of alternates, http-alternates, promisor packs,
multi-pack indexes or auxiliary object stores may be adopted. Unrelated loose
objects are neither copied nor treated as required closure. Changes to raw
HEAD/ref/index/locator/object read identities during acquisition fail. No
external/configured lookup, lazy fetch, reflog update, repair or source write.

### 6.2 Existing snapshot consumers are also isolated

Replace, rather than leave behind, `bindings.git(root,...)`'s real-repository
commands. For each snapshot use one exclusively created temporary read view
under the bound final-tmp owner. Populate its own minimal standalone Git
scaffolding, the independently checked base tree/blob forest and any required
raw commit anchor, and a bounded **copy** of the actual index. Never point
`GIT_INDEX_FILE` or `GIT_OBJECT_DIRECTORY` at real source storage.

Run native `ls-files --stage --sparse -z` on the copied index and compare every stage0
mode/OID/name to the independently parsed HEAD tree map. Reject unmerged/staged
differences, missing entries, sparse/split/external index forms, and unsupported
flags/records; never use the comparison to change the index. In particular,
--sparse must expose and reject any directory entry rather than silently expand
it. A second `ls-files -v --sparse -z` must report exactly the same paths with
normal H flags; skip-worktree/assume-unchanged or unknown flags fail. Never copy
sharedindex files: a split-index dependency must fail in the standalone view,
not resolve against source or get silently converted. A missing index
can represent an empty index only for an explicitly empty HEAD-tree fixture.
Obtain tracked/untracked names through isolated native ls-files with explicit
`--exclude-per-directory=.gitignore` and root `/.git` exclusion, not source
info/exclude, global excludes, config-driven commands, or repository discovery.
AGENTS remains explicitly excluded from proposed source but separately hashed.

Only the source's real per-directory .gitignore rules retain their intended
read-only inventory role. Their bytes and tracked status are source-bound;
they cannot import helpers or override whitespace. Verify symlinked ignore/
directory controls fail safely without reading an external target. Compare the
resulting complete file set with the exact accepted snapshot and preserved
QA-003 snapshot; a difference due to previously inherited ignore configuration
is a failure to investigate, not a reason to silently drop files or rewrite
the old acceptance. Compute proposed blob hashes by bounded descriptor reads,
including untracked additions and explicit deletions, with byte/mode checks
before and after. Empty and unchanged proposed trees remain supported.

Each temporary view has a distinct owner and exact scaffolding/object/index
inventory. Preserve its bounded command/closure/hash evidence before deleting
only its owned copies after all its actual known children join and local checks
succeed. Do not require or fabricate a final PASS ledger for this local
short-lived metadata view. Failed/ambiguous view preparation retains the view
and fails the action/final-tmp check; do not adopt it on a later invocation.
Only one temporary view is active at a time. Later source rechecks may create
these independent metadata views but may **never repair the frozen diff store**.

### 6.3 Exact native executable, argv, environment and attributes

Select and bind the actual leaf
`/Applications/Xcode.app/Contents/Developer/usr/bin/git` for this local config,
including canonical path, lstat/fstat identity, mode, SHA256 and actual version.
The observed `/usr/bin/git` is a launcher; its hash alone is insufficient.
Other hosts need their own explicitly reviewed leaf binding. Do not silently
fall back to PATH, xcrun, the launcher, or another Git. Existing tool bindings
remain; add the actual leaf and compare its identity before/after use. The Git
version observation also uses this leaf under the controlled environment; it
must not keep invoking a differently resolved PATH command as its evidence.

Construct each standalone view without `git init`, templates or copied source
config. Minimal fixed scaffolding contains HEAD with an unborn private ref,
the exact minimal SHA-1/bare config, refs/heads, refs/tags, objects/info and
objects/pack (both empty), and content-addressed loose objects. A metadata view
may additionally have its explicitly copied index and anchor/ref; the final
diff view has neither an index nor copied source refs/commit history. Keep
empty HOME/XDG/hooks/exec/tmp directories as separately enumerated control
scaffolding. No symlinks/hardlinks, packs, alternates, source configs, hooks,
attributes, grafts, replacements or borrowed object directories are allowed.

Use a **new environment dictionary**, not a scrubbed inherited one:

- `LC_ALL=C`, `LANG=C`; HOME/XDG_CONFIG_HOME/TMPDIR point to the view's owned
  empty controls; PATH and GIT_EXEC_PATH point to the owned empty exec directory.
- `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_SYSTEM=/dev/null`,
  `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_ATTR_NOSYSTEM=1`,
  `GIT_NO_REPLACE_OBJECTS=1`, `GIT_NO_LAZY_FETCH=1`,
  `GIT_OPTIONAL_LOCKS=0`, `GIT_TERMINAL_PROMPT=0`,
  and `GIT_ALLOW_PROTOCOL=` (empty).
- `GIT_ATTR_SOURCE` is the independently materialized canonical empty-tree
  OID. Do not inherit GIT_CONFIG_PARAMETERS/COUNT, object/index directories,
  alternates, worktree, SSH/askpass, pager, diff/filter, tracing, credential or
  proxy variables. Explicit invocation paths replace discovery.

Prefix every allowed Git builtin with the exact leaf,
`--no-pager --no-replace-objects --git-dir=<owned-view>`, and reviewed
`-c` overrides:
`core.bare=true`, `core.hooksPath=<empty-hooks>`,
`core.attributesFile=/dev/null`, `core.excludesFile=/dev/null`,
`core.fsmonitor=false`, `core.untrackedCache=false`,
`core.preloadIndex=false`, `core.multiPackIndex=false`,
`core.commitGraph=false`, `gc.auto=0`, `maintenance.auto=false`,
`protocol.allow=never`, `color.ui=false`, `core.pager=false`,
`diff.renames=false`, and
`core.whitespace=blank-at-eol,blank-at-eof,space-before-tab,tabwidth=8`.
Only metadata ls-files receives an explicit source worktree and the corresponding
`core.bare=false` override. It still uses the owned gitdir/index/config.

Allow only the required native builtins: bounded ls-files, cat-file,
hash-object **without -w and with --no-filters**, and tree-to-tree diff.
The leaf's non-repository `--version` is the explicit version-observation
exception. Synthetic setup/independent fixture-only ls-tree probes have their
own explicit proof allowlist and cannot expand the final-view command policy.
No checkout/update-index/write-tree/update-ref/config/fetch/gc/maintenance
command is allowed against real or final views. Object creation is only the
reviewed Python serializer in newly owned storage. Pin whitespace semantics
rather than inheriting host settings. `--no-ext-diff --no-textconv --no-renames`
and the empty attribute source prevent proposed .gitattributes from disabling
the required check or loading drivers. Required flags/environment behavior must
be proven on the bound leaf; unsupported behavior fails rather than dropping
a control. The zero-ref standalone layout and absence of source/promisor config,
not only a version-sensitive environment flag, prevent lazy fetching.

Record the actual full argv and environment policy/owned values with each native
result. Hashes demonstrate binding, not permission to trust source callbacks.
There is no network-capable or application-code path in this reader contract.

## 7. Complete object creation, native consumption and sealing

1. Recheck source/review/helper/tool/owner bindings and absent final destinations.
   Exclusively mkdir a0700 `<owner>/final-frozen-diff-r1`; record root/parent
   ancestry, identity, nonce, intended paths and proposed-tree binding in
   `FROZEN-DIFF-OWNER.json`. Existing directory, owner, seal, failure or cleanup
   records conflict; no resume/adoption.
2. Materialize canonical loose objects for every base tree/blob and proposed
   tree/blob, plus the canonical empty attribute tree. Build proposed tree
   payloads from every frozen nondeleted file's actual bounded bytes and mode.
   The resulting proposed root must equal the independently reviewed source
   tree, not an object calculated from a smaller tracked-only set. Deduplicate
   only an identical type/length/content/OID; a conflict fails. Use exclusive,
   no-follow output creation, fstat nlink1, bounded zlib and fsync. No source
   pathname is an output name: loose paths use only validated hex IDs.
3. Build the exact typed forest manifest from those roots, not by blessing
   whatever appeared on disk. Rewalk all trees and required blobs. Independently
   decompress/read back and rehash every owned object with complete length/type/
   zlib-tail checks. Compare exact set, content, modes and identities; reject
   missing, extra, corrupt, wrong-type, replaced or linked objects.
4. Run actual native `cat-file --batch` against only the owned store. Issue
   one expected40-hex request at a time and validate its bounded header's exact
   requested OID/type/canonical decimal length **before reading the body**.
   Stream exactly that length, require the one framing newline, independently
   hash/compare the body, and only then issue the next request. On final input
   close require EOF without extra header/body bytes and actual exit0. Missing,
   ambiguous, short, overlong, wrong-header/type and nonzero native replies
   fail. Native input/output is also charged to the shared byte/time budget.
5. Use real native nonwriting `hash-object -t tree --no-filters --stdin`
   for the base/proposed/empty root payloads and compare returned IDs. The
   native cat-file round trip covers **every** object; root hashing and native
   diff are independent consumers, not a second call to the Python calculator.
6. Execute the exact native command, after the fixed prefix, equivalent to
   `diff --check --no-ext-diff --no-textconv --no-renames --no-color BASE_TREE PROPOSED_TREE --`.
   Require actual exit0 and no unexpected diagnostics. Nonzero remains failure
   regardless of whether a particular Git represents whitespace as1,2 or3.
   Keep bounded raw diagnostics. Empty/identical trees legitimately exit0.
7. Check source/raw metadata/tool bindings again, full store/control inventory,
   deadlines, actual native reaps, no pending cancellation and absence of any
   errors. Only then write/fsync a new `FROZEN-DIFF-SEAL.json`. It binds the
   raw HEAD anchor/root, both consumed roots, empty attribute tree, exact typed
   object map, separate exact scaffolding inventory, owner identity/nonce/hash,
   source/index/helper/policy/tool hashes, and actual native records/diagnostics.
   Keep the raw commit anchor as separate bounded evidence, not a promise to
   copy all parent history.
8. Seal publication is not success by itself. Check time/cancellation after
   publication/restoration and require the actual successful prepare gate
   record/log and wrapper result. A partial owner/loose object/complete-looking
   seal after any failure remains conflict evidence. A later check cannot
   rehabilitate it or issue a fresh successful prepare in the same namespace.

Git scaffolding and required graph objects are separate inventory classes.
Only explicitly required fanout directories and objects, fixed controls/config/
HEAD and explicitly allowed metadata-view files are accepted. No unexpected
pack/config/index/lock/replace/ref/attribute/symlink/temporary file is adopted.
Do not call native Git fsck over an incomplete parent history and mistake that
for the promised tree/blob proof.

## 8. Late check, deletion, failure and recovery

`--check` is read-only with respect to the prepared store. Require the exact
successful earlier prepare ledger/log/owner/seal, independently bound source,
and identical full store inventory before native use. Rehash/decompress/read
every required object and repeat the same native batch/root/diff observations
under a new bounded action scope. Source metadata views may be temporary, but
missing/changed frozen store bytes are never regenerated or substituted.

`--cleanup` runs only at its exact RUNNING slot. Execute the actual
`prior_workers(evidence, "cleanup-frozen-diff")`: require the exact45-route
ledger, actual PASS/reap/exit/deadline/cancel/group/log evidence for all preceding
gates and a fresh complete numeric observation. A graph digest or owner nonce
does not prove lack of workers. No patch or bypass of this consumer is permitted.

Require source/tool/owner/seal/inventory agreement again; preserve a full
cleanup-intent inventory and worker result before unlinking. Use descriptor-bound
`delete_inventory` with no-follow traversal, per-file identity/content checks,
exact root/parent identity and no unknown children. Delete only this owned
disposable store. Preserve source and both real Git stores/indexes/refs,
neighbor controls, required wheels, commit anchor, diagnostics, owner/seal,
cleanup records, reviews and historical failures.

Pre-deletion drift/unknown evidence means **zero deletion**. Cancellation or
replacement discovered after some validated owned entries were deleted is a
failed **partial cleanup**, never atomic/successful cleanup: retain the rest and
a bounded failure record, never unlink a substituted/foreign entry or resume.
Private ownership assumes no arbitrary hostile same-UID writer; hash/FD checks
are not a sandbox against such a writer.

No failure/cancel/network/repair retry is introduced: these are local one-shot
verification outputs, not Store operations. Interrupted preparation/check/
cleanup remains visibly failed/unknown. Preserve unresolved evidence and worker
state. A future new verification attempt requires an explicit reviewed owner/
namespace decision; it cannot erase or relabel this invocation. Failed source
prerequisites must be resolved/reviewed separately, not fixed by this reader.

## 9. Exact45-gate routing and applicability

Keep the current protocols/argv for all baseline obligations except replacing
the broken late diff consumer with `frozen_diff.py --check`. Extend the existing
verification-process-ownership helper to execute its added synthetic verifier
proofs; do not replace its original10 controls. Exactly:

| # | Gate |
|---:|---|
| 1 | freeze-before |
| 2 | verification-process-ownership |
| 3 | verification-result-protocols |
| 4 | **prepare-frozen-diff** — new `frozen_diff.py --prepare` |
| 5 | prepare-owned-build |
| 6 | editable-install |
| 7 | bundle-install |
| 8 | bundle-check |
| 9 | python-full |
| 10 | init-transactions |
| 11 | ios-entitlements |
| 12 | ios-profile-authority |
| 13 | default-cancellation |
| 14 | profile-process-containment |
| 15 | native-ci-aggregate |
| 16 | ios-binary-plist |
| 17 | ios-native-correspondence |
| 18 | native-profile-gate |
| 19 | ruby-support |
| 20 | ruby-native-capture |
| 21 | ruby-play_store |
| 22 | ruby-play_lanes |
| 23 | ruby-apple_store |
| 24 | ruby-apple_lanes |
| 25 | ruby-apple_production |
| 26 | ruby-apple_production_lane |
| 27 | ruby-apple_asset_upload |
| 28 | ruby-ios_upload_validation |
| 29 | ruby-android_upload_validation |
| 30 | ruby-workflow-yaml |
| 31 | ruby-supply-wif |
| 32 | fastfile-validate |
| 33 | actionlint |
| 34 | dependency-pins |
| 35 | wheel-install |
| 36 | pip-check |
| 37 | jdk21-signature-policy |
| 38 | diff-check — corrected `frozen_diff.py --check` |
| 39 | freeze-before-cleanup |
| 40 | owned-worker-observation |
| 41 | cleanup-generated-build |
| 42 | cleanup-wheel-installation |
| 43 | **cleanup-frozen-diff** — new `frozen_diff.py --cleanup` |
| 44 | freeze-after |
| 45 | empty-final-tmp |

Assert exact IDs, order, protocols, full expected Ruby inventory and absence of
the QA-003-only matrix on this baseline. Any added first-party test/interface
changes require explicit coverage reconciliation, not automatic omission.
Retain the WIF-specific terminal protocol, nonempty/no-skip unittest/Minitest
checks, late-cancel/storage/wrapper-status controls and source preservation.

This list records obligations, **not permission to run QA-007-affected Ruby
paths on the shared host**. The separate safe isolation/hosted delivery plan
must account for every obligation and platform without calling filtered or
guarded subsets full passes. Required protected Linux/macOS coverage, actual
main CI and later QA-003 matrix remain outstanding and are not45 local passes.

## 10. Proof migration and required adversarial verification (PR3-03)

### 10.1 Preserve history and change the obsolete assertion transparently

Preserve `verification-correction-r1/prove-corrections.py` byte-for-byte at
SHA256 `aa8dade2af946eb317d22b321dbf3381c41376ac841b5b30116a503f24b2ac05`,
its25 results, raw logs and cleanup records. Copy to a new clearly versioned
preparation-only directory/driver; record old/new hashes and a per-case mapping.

Retain every old obligation (six ledger/cancel/storage controls; real numeric
table/malformed/empty/valid/output/deadline cases; unknown-group/classifier
cases; helper/owner drift; positive/negative build cleanup; wheel corruption;
source-tree control). Specifically replace old `numeric-unknown-state`'s
invalid expectation with **recognized-indeterminate**: an actual query emits
valid `?`, parses successfully, and a matching target is INDETERMINATE, not
CLEAR. Add distinct actual target cleanup-denial, unrelated-indeterminate
positive, and genuinely malformed-state controls. Therefore the revised count
is not forced to25: publish the **actual count and mapping**, including added
cases. Do not mark the historical driver's now-obsolete assertion as passing.

Wheel/state cleanup proofs must no longer stub `prior_workers` or return canned
CLEAR. Run actual syntax -> classification -> `observe_groups` ->
`prior_workers` -> actual guarded deletion. Only accepted-source/setup seams
may differ: a copied preparation namespace may bind a small explicit synthetic
gate routing and synthetic accepted snapshot, then produce its preceding
ledger/log rows by running real owned children through `run_gates`.
Document/hash that routing/setup difference; it is not an executed45-gate run.
The dangerous parser/classifier/worker decision/inventory/delete modules must
be the reviewed bytes. Never replace their result with a mock. Independently
check the actual production45 routing and ledger-mismatch rejection.

### 10.2 Required proof matrix

Execute preparation-only copies in new, exclusively owned namespaces after
implementation approval to test, not a final freeze/dispatch. Retain actual
commands, stdout/stderr bounds, exits, phase traces, child ownership, hashes and
cleanup. Tests must include:

**State and cleanup consumption**

- All five reproduced malformed Z states; repeated/out-of-order/conflicting
  suffixes; valid Z/Z+/Zs; supported live states; ?, ?E, ?Es, H, X and exiting.
- Non-ASCII, missing/extra fields, duplicate/nonpositive PID/PGID, malformed
  PPID/UID, empty table, query stderr/nonzero and byte/time overflow.
- Valid unrelated indeterminate plus absent/stopped target succeeds; matching
  indeterminate fails readiness/cleanup; foreign UID and reused leader fail.
- Real indeterminate-to-stopped transition inside one cutoff; persistent
  indeterminate; late query/CLEAR publication after that original cutoff fails.
  Query text may be synthetic, but no canned classification or frozen clock.
- Full worker-to-deletion negative cases preserve complete before inventory;
  positive actual joined-child case deletes only its own output. Zero signals
  to historical groups in all numeric-observation controls.

**Bounded native reader and ownership**

- Actual synthetic child output just below/at/above each stdout/stderr cap;
  simultaneous pipe pressure, endless producer, blocked stdin and early EOF.
- Overlong header, excessive declared size/type, wrong requested OID, short
  body, missing/extra delimiter, extra terminal output, nonzero after valid
  body, stderr after successful body, and child failure before/after EOF.
- Exception after actual acquisition; known-child read/write/selector/close
  failure; post-reap delayed publication beyond original deadline; fail rather
  than resetting budgets per object/request.
- Cancellation before acquisition, after actual returned handle, during read,
  after reap, during owner/object/seal write/fsync, immediately after a full
  seal, and at handler restoration. Late full-looking output cannot pass.
- Unknown acquisition with no fixture child; hidden acquisition and reap
  publication faults with independent retained fixture handles/EOF cleanup.
  Verify UNKNOWN/no guessed signals and actual independent fixture join.
- An actual owned outer gate starts a real Git cat-file reader in the same
  group; a controlled outer timeout/hard-stop cannot leave it in a separate
  session. Retain actual initial group/readiness and bounded post-stop numeric
  evidence. The outer failure stays failure; no successful inner reap is
  invented when its parent was killed. No arbitrary-process kill probes.
- Every known ordinary-failure/cancel child is closed/joined; no background
  thread/waiter/control writer remains. Do not use canned Popen return results
  for successful native Git or framing proofs.

**Actual Git, input isolation and graph closure**

- Fresh synthetic repositories whose proposed root and children were never
  written to source: modification, deletion, untracked addition, executable
  bit change, nested directories, empty files/trees and identical trees.
  Real native batch/root hash/diff must consume the prepared objects.
- Native whitespace rejection for both changed and newly added files, including
  trailing blanks and EOF blank lines; clean positive controls really exit0.
- Raw HEAD that is not commit, substituted/malformed/duplicate tree header,
  wrong typed child, missing/corrupt object, invalid compressed header/size,
  zlib truncation/extra stream, duplicate/unsorted tree names, unsupported
  symlink/gitlink/mode, path/count/depth/aggregate size limits and source drift.
- Packed-only/alternate/promisor/missing loose inputs reject before native Git
  can use source storage. Assert no fetch, fallback, index/ref/object change.
- Hostile source/local/global/system config, include, whitespace overrides,
  fsmonitor/helper settings, source replacement refs and tree .gitattributes
  cannot alter the raw anchor, trigger a callback or suppress whitespace.
  Fixtures use synthetic config and **nonexistent/nonexecutable callback
  targets**, not real callbacks or usable remote endpoints. Promisor/alternate
  fixtures are rejected before any lookup; do not permit a network attempt to
  prove it would fail. Bind actual sanitized argv/environment and successful
  real-native behavior; no reads of the user's private global config.
- Copied-index staged/unmerged/sparse/split/foreign forms fail; no real index
  changes. Correct linked-worktree and root-directory layouts work; malformed
  .git/commondir/backpointers, external/symlink refs or objects fail.
- Empty attribute source and --no-filters/no-ext-diff/no-textconv enforced on
  the exact leaf; real .gitattributes whitespace/binary/driver overrides do not
  weaken the intended text whitespace controls.
- Source/head/index/ref/instruction hashes and identities before/after every
  proof; no real Git object creation. Synthetic setup writes only its own
  fixture repository. Native nonwriting root hashes/cat-file/ls-tree readback
  can independently validate fixtures, not just repeat the Python serializer.

**Lifecycle, inventory and one-shot evidence**

- Partial owner creation, object write/readback failure, native failure before/
  after complete materialization, fsync/record storage failure, cancellation
  after native diff before seal and after a complete-looking seal.
- Existing/partial owner/store/seal/failure records conflict, never adopted;
  no expensive gate may follow failed prepare.
- Late missing/corrupt/replaced object, extra pack/config/index/ref/link/file,
  altered owner/seal/tool/policy/source, symlinked root/ancestor and neighbor
  canary controls. Check must fail without regenerating data.
- Cleanup with any prior gate FAIL/BLOCKED/skip/cancel/nonzero/unreaped/late/
  changed-log/changed-route/unknown group denies deletion. Exact positive
  control preserves retained wheel/evidence/source/neighbors.
- Replacement or cancellation during deletion records failed partial owned
  cleanup and preserves foreign/substituted content. Do not assert cleanup
  atomicity that the implementation does not provide.

Rerun all original10 controller and24 protocol cases, the revised mapped
adverse driver, actual wrapper-exit/dispatch-collision proof, safe-path startup
under -P/PYTHONSAFEPATH and -I/-B, shell syntax, helper AST checks, helper/owner
binding drift controls, and exact45-gate applicability checks. Record counts
and real exits; no first-party/full-suite pass is inferred from these proofs.

## 11. Compatibility, security, documentation and acceptance sequence

This changes ignored verification mechanics only. Actual reviewed source/tree,
application/toolkit provenance, Store build reuse, credentials, signing, manual
publication and package contracts are not weakened. SHA1 here is Git object
identity coupled with SHA256 byte bindings and independent accepted snapshots;
neither digest supplies ownership or authenticity by itself.

Principal regression risks are incomplete source inventory, overbroad/incorrect
state syntax, deadline renewal, unbounded compressed/native output, index or
config leakage, accidental object substitution, a Git child escaping the gate,
premature seal success and unowned deletion. Sections3–10 specify separate
negative/positive proofs for each. New source-storage restrictions are explicit
narrow verifier applicability failures, not supported product limitations.

Update ignored implementation report, source/helper diffs, cap/policy records,
proof mapping/results, cleanup records and coverage ledger. Document retained
failure/UNKNOWN cases and no-retry semantics. Preserve AGENTS byte-for-byte,
all original audit/remediation evidence and the root QA-003 pending work.
Do not touch other tasks' processes, Colima profiles, source files, caches,
shared installations or required artifacts.

Sequence:

1. Distinct reviewer approves this exact proposed plan or requests revision.
2. Only then implement the scoped helper corrections and new copied proofs.
3. A **different** independent implementation reviewer reads the actual diff,
   final callers, raw native proofs and this contract; fix/review every objection.
4. Obtain separate first-party implementation acceptance and a safe complete
   isolation/hosted verification contract. Verifier acceptance does not imply
   either and does not fix QA-007.
5. Only after explicit final authorization, freeze a freshly accepted exact
   source/helper/tool/owner snapshot and execute every applicable obligation
   from zero in the still-unused final namespace. Stop acceptance on any failure.
6. Preserve required evidence; stop/join only owned workers and remove only
   proven disposable outputs. Unknown/foreign/required outputs are retained.
   Do not mark unavailable or unexecuted checks as passed.
7. Protected delivery/main CI, subsequent QA-003 full matrix, remaining issue
   remediation, the new whole-repository production audit and full feature
   inventory remain required. This plan supplies no READY verdict.

**Authoring outcome:** no helpers/source/index/object/ref were changed, no
native proof or final gate ran, no worker/build/VM was started, and there are no
owned background workers or disposable build outputs from this plan authoring.
Only this new ignored proposal is the intended deliverable.
