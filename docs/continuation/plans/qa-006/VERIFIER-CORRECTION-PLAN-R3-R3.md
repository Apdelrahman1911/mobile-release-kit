# QA-006 verifier correction plan R3-R3

**PROPOSED — plan authoring only; independent exact-hash approval required.**
This replaces neither an approval nor an executed proof. Do not implement from
this proposal until the distinct plan reviewer accepts it. It authorizes no
first-party edit, final acceptance/freeze/dispatch, VM/container operation, Store
call, commit, push, or QA-007 runtime change.

## 1. Findings, evidence, and selected solution

This is a complete revised proposal, not an addendum or conditional approval.
It incorporates the exact three requests in the final independent R3-R2 report:
`plan-review-verifier-r3-r2/PLAN-REVIEW.md`, SHA256
`8136548bca5d77f7259ad27f1f12617ddbd0e0dafdc7f713a6ab9677d73990ad`.
Its `DECISION.json`, SHA256
`2912324754570f2313d49a1cf059fb7c1dd5f83ebfe9db49ff312e5aa19336b6`,
says REQUEST_REVISION_PLAN_ONLY, with PR3R2-01/02/03 and no additional requests.
Preserve the reviewed R3-R2 proposal at SHA256
`6e37fbfc2ab17dfa0fcca524696d18ab69246fe61ea459a3a84edf14c5dcd318`.

The earlier R3 requests and original selected architecture remain incorporated:
`plan-review-verifier-r3/PLAN-REVIEW.md`, SHA256
`a2420a0a0482769397315991d1fa272b1aac6586fc895e9b97c07da033d14f51`;
original R3 plan SHA256
`6e3ab0f887fc85142c389e3089eab1ea37d1b03ffb358fe7d6ed87dad67d3f2c`.

Re-read the original QA-006 finding and plan, VRI-01/VRI-02 independent
implementation review, R2 approval, R3/R3-R2, both independent plan decisions,
the actual shared I/O/collection/cleanup/controller/wrapper consumers, and the
historical25-case driver. The causes and precision corrections are:

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
- **PR3R2-01:** a prepare child cannot require its own future completed row, and
  intermediate check/cleanup cannot require the future global wrapper exit.
  Actual parent-observed prepare-child completion is the later-stage authority.
- **PR3R2-02:** the existing shared digest/read_json/inventory/delete helpers
  bypass the proposed action budget. Their real filesystem/parser loops and
  every participating caller must share limits/cancellation, not only Git.
- **PR3R2-03:** comparing fresh temporary-view paths/nonces/PIDs/timings, or
  hashes of those observations, would reject an unchanged source freeze.
  Stable input authority and separately retained fresh observations need
  explicit schemas and different validation responsibilities.

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
| New `action_io.py` | Lowest-level explicit action context and bounded filesystem/JSON/digest primitives; no bindings/cleanup import cycle, no implicit fresh budget inside utilities. |
| New `native_reader.py` | Bounded direct-child reader sharing action_io's context with native Git/metadata/tool and all participating filesystem work; not Store or application execution. |
| New `git_readonly.py` | Raw descriptor-bound Git metadata/loose-object input, typed closure, controlled standalone views, isolated native Git policy. No import cycle with cleanup/bindings. |
| New `frozen_diff.py` | Explicit `--prepare`, `--check`, and `--cleanup` entry points for the owned frozen forest and evidence lifecycle. |
| `bindings.py` | Replace unsafe source-Git introspection and unbounded I/O; expose complete stable projection plus separately hashed fresh observations; bounded freeze-envelope loading; bind source/index/owner/helper/tool/policy/reviews without volatile equality. |
| `freeze.py` | Whole-lifetime cancellation context and absent-output preconditions, including new store/owner/seal/failure/cleanup paths. No acceptance shortcut. |
| `gate_list.py` | Exactly the routing in section9; retain protocols and every baseline command obligation. |
| `owned_outputs.py` and its entry wrappers | Thread the same action context through actual prior_workers, records/logs, inventories, identity/content checks and descriptor-bound deletion. Preserve all guards and failed-partial-cleanup semantics. |
| `verify-process-gate.py` and new `verify-frozen-diff.py` | Preserve original controller controls; add state-to-cleanup, bounded-reader, isolated-Git and real-object proofs under the existing verification-process-ownership gate. No46th gate. |
| `verify-all.py`, `run-once.sh` | Bounded setup/accounting and new freeze-envelope plumbing; parent binds completed prepare child's actual exit/reap/log/seal observation after return. Keep global wrapper exit as final-only authority, cancellation and one-dispatch contracts. |
| `CONFIG.json`, helper/static inventory | Bind the selected actual Git leaf and policy/cap version. Enumerate all new executable helpers; unexpected helpers remain errors. |
| New copied proof driver and reports | Migrate25 historical obligations as section10 specifies; retain old bytes/results unchanged. |

Inspect and update every caller of `read_command`, `git`, `snapshot`,
`git_tree`, `collect`, `check_frozen`, `digest`, `read_json`,
`write_new`, `inventory`, `delete_inventory`, and `prior_workers`.
This includes prepare/cleanup-build, cleanup-wheel, owned-output wheel entry
points, observe-owned-workers, proof scripts and controller record/log paths.
Replace direct legacy final-freeze JSON indexing with the explicit bounded
freeze loader wherever the envelope changes; never lose head/tree authority.
Existing non-Git version observations and shared non-native callers cannot keep
unbounded utility paths or silently start one budget per file. Preserve their
existing checks. No production package/API/schema/workflow/template changes
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
| One pipe or filesystem read/write/hash/compression/serialization chunk | At most64KiB |
| Non-object native stdout (metadata, version, diff) | 2MiB per command |
| Native stderr | 256KiB per command |
| Cat-file stdout | 64MiB +4,096×97 bytes per complete forest read |
| Aggregate object/source/native payload processing | 256MiB per top-level action; remains a tighter independent subset quota |
| Actual native launches / simultaneously live native children | 64 /1 per action |
| Simultaneously active metadata views / created views | 1 /8 per action |
| Stored loose forest | 72MiB logical bytes per view/store |
| New owned data / retained diagnostic data | 192MiB /8MiB per action |
| One structured JSON/action/failure record | 4MiB, depth64, 262,144 tokens/nodes, 128KiB per string token |
| Tool executable file / tool hash-byte reads | 512MiB per file /4GiB per action |
| Participating ordinary log / other non-source regular file | 64MiB /512MiB per file; narrower role-specific bounds always win |
| All filesystem bytes read/written/hashed plus native payload processing | 8GiB per action, counting repeated passes and independently of subset quotas |
| One owned inventory / directory fanout / total visited entries | 32,768 entries /4,096 names /131,072 per action |
| Non-Git filesystem ancestry/path depth | 64 components |

Check both declared size and actual bytes. No allocation, `read_bytes()`,
`communicate()`, or `subprocess.run(capture_output=...)` may first absorb
an unbounded stream. Header readers stop at97 observed bytes; object bodies
stream through hashes/compression or discard/readback sinks. Tree parsing may
buffer at most its already validated2MiB body. Count deduplicated objects and
all traversed references separately so repetition cannot evade limits.

A top-level collect/prepare/check/cleanup action starts **one120s monotonic
work cutoff before its first configuration read, acquisition or filesystem
operation**. Each command has at most30s and also the remaining shared cutoff.
All participating native, filesystem, JSON, hash, graph, inventory and deletion
work shares that same context. Bytes, commands, view creation, graph nodes,
record tokens and traversal counts never reset in nested utilities. A first
failure poisons ordinary work; no next native command or destructive step.

These limits do not misclassify large pinned executables as source blobs.
Authoring performed read-only size metadata inspection, not a tool/proof run:
the selected clang is290,664,032 bytes, dsymutil97,964,848 bytes, and the31
existing-plus-leaf executable bindings total462,448,382 bytes per complete
hashing pass (counting repeated paths). The separate512MiB per-tool and4GiB
tool-byte quota permits finite repeated validation of those actual bindings.
The8GiB encompassing I/O quota additionally covers prior-gate logs and reused
cleanup passes. Neither quota enlarges the8MiB source/blob,64MiB graph,
256MiB graph/source/native-payload, native pipe or120s work bounds.
Do not exempt tools, reuse unverified cached hashes, or raise a limit after
failure. Actual counters/preflight must prove applicability; these size
observations are not evidence that a future complete action will pass.

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

### 4.1 Shared filesystem consumers (PR3R2-02)

Every participating entry point creates one action context at its outer
boundary and passes it explicitly through collection and teardown. A utility
without the required context fails instead of silently constructing a fresh
cutoff. A standalone proof/API caller supplies its own explicitly bounded
context; nested source checks, view cleanup and prior-log verification reuse
it. For the long-lived controller, setup and each explicit completed-gate
accounting operation have their own top-level I/O scopes, sharing its existing
cancellation flag. This does not reset a child's original900s execution
deadline or impose120s on the entire45-gate dispatcher.

Implement the real shared primitives, not wrappers that check after their old
unbounded bodies:

- `digest` takes a role-specific per-file limit and the action context. Open
  regular files through validated no-follow descriptors, check declared size
  before reading, and verify fstat/identity/size again afterward. Every read
  is at most64KiB and charged before the next read/hash step; detect a growing
  file at cap+1 without first hashing it all. Tool files use the finite tool
  category; source, object, record and log files use their tighter categories.
- `read_json` performs the same bounded descriptor read, never `read_text`
  first. Before allocating parsed containers, a bounded UTF-8/JSON lexical
  preflight checks depth, token/node/string limits and the action deadline in
  at most64KiB work slices. Reject invalid constants and duplicate keys.
  The actual decoder consumes only that bounded input and is checked before/
  after and at bounded object-hook iterations. Cap JSON encoding/writing too;
  a single large iterencode fragment is sliced into at most64KiB writes.
  Unknown/missing contract fields still reject at each consumer.
- `inventory` uses bounded descriptor-relative iteration with no-follow
  child checks. Cap and charge names while enumerating, **before** list/sort
  allocation. No unbounded os.walk/listdir/sorted call may discover an
  unlimited directory first. Check the same context at each entry and hash
  actual files through bounded digest; enforce full ownership/nlink/type and
  path guards and exact expected inventory before destructive work.
- `delete_inventory` validates the complete bounded supplied inventory,
  retains all existing descriptor/ancestry/root/per-entry identity checks,
  and rehashes each regular file with at most64KiB reads in the same scope.
  Check cancellation/time/counters immediately before and after each
  open/read/hash/unlink/rmdir/close and each parent traversal. Do not remove
  any entry when cancellation was already pending before deletion. A later
  interruption/replacement fails with explicit partial owned-removal counts;
  no substituted entry is removed and no success/resume is manufactured.
- `prior_workers`' configuration/freeze/ledger/seal/log reads and hash checks,
  fresh process query and all local metadata-view teardown consume the same
  action context. Numeric observation receives only its remaining allowance;
  its original stricter query/group cutoffs also apply. Reading a large
  prior log may not escape the action budget through the old digest.
- `write_new`, atomic controller saves, owner/seal/observation/cleanup record
  writes, flush/fsync, rename, directory creation and finalization all use
  bounded writes and pre/post checks. An expired/cancelled successful-looking
  write never counts as success. Preserve existing exclusive/no-overwrite or
  explicitly owned atomic-ledger-replacement semantics and no-follow guards.
  Revalidate and charge bounded in-memory projection/JSON/inventory traversals
  too; a short native call cannot reset or hide expensive filesystem work.

Cancellation poisons successful publication/deletion. Where original time and
byte allowance remain, a narrowly typed **failure-only** record operation may
persist FAIL/UNKNOWN diagnostics despite the already latched cancellation.
It cannot write a success, seal, new owner, evidence adoption or resource
deletion, and it cannot obtain a new budget. If time/storage/limits are
exhausted, retain the earlier incomplete evidence and return actual failure
even without a final failure record. Descriptor close and known-child
stop/join disposition do not grant new ordinary work; the sole extra5s
allowance remains child disposition only.
Mandatory owned-descriptor closes remain in finally paths even when a pending
flag/deadline was detected immediately beforehand: record that condition,
attempt the close, then propagate failure. A checkpoint must not skip its
own descriptor close. This exception permits no new read, unlink or adoption.

These are cooperative pre/post syscall limits, not a claim that Python can
preempt an indefinitely stuck kernel filesystem call. A late-returning
read/fsync/unlink still fails and cannot publish readiness. The existing
owned outer gate bound and unknown/failure accounting remain applicable.
Do not add detached timeout threads or claim unresolved kernel/process work
joined. All previous identity/no-follow/content/partial-cleanup guards remain.

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
  failed/absent actual action result. The prepare-child versus final-global
  wrapper completion boundaries are distinct, as sections7–8 require.

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
inventory. Preserve its bounded command/closure/hash evidence separately from
the stable freeze projection, as section6.4 specifies, before deleting only
its owned copies after all its actual known children join and local checks
succeed. Use the same action context for record writing, complete inventories,
content rehashing and descriptor-relative teardown, not a new cleanup budget. Do not require or fabricate a final PASS ledger for this local
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

### 6.4 Complete stable projection and separate volatile observations (PR3R2-03)

The existing whole-collection equality in `check_frozen` must be replaced
with **schema-defined complete stable equality**, not a generic deletion of
keys called pid/path/nonce/time. An explicit collection result has two parts:

1. `stable`: the deterministic, complete authority projection below.
2. `observation`: a reference to separately retained immutable bytes for
   this particular real collection/action, with exact path, size and SHA256.

An unchanged input collected twice must yield identical stable canonical
bytes, while its temporary views/process observations differ. Required
stable schema fields include all of:

- exact source root identity, complete included/deleted file set, source byte
  hashes/executable modes, source regular-file identities, raw HEAD and branch,
  and independently computed proposed tree;
- both repositories' validated Git layouts/locator/commondir/backpointer,
  HEAD/ref/index raw byte hashes and real file/path identities, typed raw
  HEAD/tree/blob closure content and required loose-object identity bindings,
  plus the enforced absent pack/alternate/promisor/index-form conditions;
- preserved root source snapshot, its immutable historical freeze reference,
  exact user AGENTS bytes, and every former preservation comparison;
- permanent workspace/source/user-root/final-tmp/evidence ancestry/owner
  identities and fixed marker bytes, configuration identity and content,
  complete helper/static inventory including file modes, and reviewed policy;
- each effective tool's selected/resolved path, file identity/mode/content
  hash, strictly parsed actual version and applicable fixed tool configuration;
- full accepted implementation/verifier records and immutable referenced
  review/snapshot hashes, plus all required applicability/hosted distinctions;
- explicit projection schema version and the complete static Git/FS/native
  cap, command/environment template, role/path and interpretation policies.

Keep the legacy logical `head/branch/files` shape needed to validate already
accepted implementation snapshots and the preserved historical QA-003 freeze.
Record additional physical source/metadata identities in separately named
stable fields; do not silently rewrite those historical files or accept a
subset because a new field was added. Historical record parsing is explicitly
versioned and byte-bound, not a permissive fallback for a malformed new freeze.

Stable source/metadata/file identities include the input's real canonical path,
device/inode, type, UID, mode, size and required byte hash; do not include
read-access time. Permanent directory ownership uses the existing device/
inode/type/UID/mode ancestry identity, not directory mtime/size/nlink that
changes when an owned temporary child is created. Before/after operation
fstat consistency remains mandatory independently of equality. New temporary
view identities are **not** substituted for any real source/owner identity.

The volatile record retains the actual action ID, fresh view paths/nonces/
inodes, copied-index/temporary-file identities, native child PIDs/PGIDs,
timings/deadlines/counters, actual argv/environment with resolved temporary
paths, raw-output/diagnostic references, real status/exit/reap/ownership/
protocol results, and view cleanup disposition. It binds the canonical
stable-projection digest it observed and the exact helper/tool/policy versions.
Store these records under unique exclusive `native-observation-<nonce>`
names in the already identity-bound ignored evidence directory, outside
final-tmp, with bounded sidecar logs as necessary. Preserve original records
unchanged; do not replace them to make equality succeed.

The stable policy contains full argv/environment **templates with explicitly
typed owned-view placeholders**, not actual fresh paths. Validate each actual
argv/environment against that policy and its actual owned view identity.
Do not erase arbitrary path strings or ignore command differences. Stable
typed versions must still be derived from real successful native reads;
record each raw observation independently, even where version output happens
to be deterministic.

No freshly generated observation, its hash, whole new collection hash or hash
of fresh temporary inventory may be put into stable equality. In contrast,
an already immutable accepted review/owner record is still a stable authority
input even if its fixed historical content mentions an old nonce/timing.
The distinction is explicit record role/lifetime, not substring-based
redaction. In particular, a final frozen-diff owner's nonce is created once,
then checked against its original seal; it is never dropped as "volatile."

Write the new final freeze as an exact-schema envelope:
`{schemaVersion, stable, stableSha256, creationObservation}`.
Hash the canonical `stable` only for stableSha256. creationObservation is a
sibling reference to the separately retained original collection observation.
It is **not part of stable equality** and there is no self-hash cycle.
Downstream owner/seal/gate records may bind the immutable original envelope's
exact bytes as an artifact reference; never compare that reference to the
hash of a newly generated envelope/observation.

`check_frozen` must, under one action context:

1. Load and structurally validate the original bounded freeze envelope, its
   full stable projection and canonical stable digest. Verify the referenced
   immutable creation observation bytes/ownership/relationship, without
   regenerating or editing them.
2. Execute a new **real** collection with fresh owned metadata views and
   bounded native/source reads. Validate this action's own successful native
   child/protocol/ownership/readback evidence and the temporary teardown.
   Missing/failed/unknown/late observation is failure, even if stable hashes
   match; no old observation can stand in for a new execution.
3. Require complete schema equality of `saved.stable` and `current.stable`,
   including every field above. Unknown/missing stable fields reject.
   Preserve and byte-bind the new observation separately; its stable digest
   must match the actual current projection. A mismatching stable input
   cannot be hidden by changing a volatile field or record hash.
4. Return the validated stable projection to consumers that require head/
   proposedTree/files; expose the new observation reference separately.
   Do not add it to the object that those consumers compare for stable
   identity, or compare entire fresh CollectionResult values.

Update all freeze/controller/owned-output callers to load this envelope
explicitly. In particular, `prior_workers` cannot feed the envelope's outer
keys into `gate_list.commands` in place of the stable head/tree fields.
Controller ledgers/prepare receipts may reference observations, but freeze
comparison still uses the complete stable authority, not merely a tree hash.

Freeze-create checks the forbidden one-shot output state before its first
collection can create observation files; it must not reject its own newly
created receipt afterward. Preexisting final/attempt observation state remains
a conflict at freeze-create, while subsequent checks intentionally append
new uniquely owned receipts. Cleanup preserves all required receipts, including
the original creation observation. Failed new observations remain visible and
never rehabilitate the invocation.

## 7. Complete object creation, native consumption and sealing

1. Recheck the complete stable source/review/helper/tool/owner/policy bindings,
   actual current observation and absent final destinations under one context.
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
   complete stable projection digest and original freeze-envelope byte
   reference, source/index/helper/policy/tool hashes, and separately byte-bound
   actual preparation/native observations/diagnostics. Keep raw commit anchor
   as separate bounded evidence, not a promise to copy all parent history.
8. The prepare child checks time/cancellation after publication/restoration
   and **returns its actual result**. It neither requires nor manufactures
   its own not-yet-completed controller row or the future global wrapper exit.
   Seal publication alone is only internally completed preparation, not
   parent-observed successful preparation. A partial owner/loose object/
   complete-looking seal after any error/cancellation remains failure evidence.
9. Only after the child's actual return/reap may the controller record its
   completed prepare row/log and bind that row to the exact prepared seal and
   observation bytes. Subsequent check/cleanup require that predecessor
   evidence under section8. Neither stage can rehabilitate a failed prepare,
   regenerate a seal, or run a fresh prepare in the same namespace.

Git scaffolding and required graph objects are separate inventory classes.
Only explicitly required fanout directories and objects, fixed controls/config/
HEAD and explicitly allowed metadata-view files are accepted. No unexpected
pack/config/index/lock/replace/ref/attribute/symlink/temporary file is adopted.
Do not call native Git fsck over an incomplete parent history and mistake that
for the promised tree/blob proof.

## 8. Completed-child authority, late check, cleanup and recovery

### 8.1 Exact predecessor and final-wrapper boundary (PR3R2-01)

The actual state sequence is:

`prepare RUNNING -> child native/readback/seal work -> child returns ->
controller observes real exit/reap/group/log -> completed prepare PASS row ->
later check RUNNING -> cleanup RUNNING -> remaining gates ->
controller final ledger/return -> shell writes actual-controller.exit`.

No transition depends on a record that can exist only afterward.

The controller uses its actual `process_gate.execute` result, not a child-
reported exit. It checks real zero exit, reaped ownership, deadline/cancel/
error/group conditions and the retained log/protocol result before saving a
completed PASS row. For prepare, after that successful child return it reads/
validates the bounded known seal and preparation observation and binds their
exact hashes/paths/sizes to the completed row, together with the real log hash
and exact expected command/protocol. A failed/incomplete child must not acquire
these bindings as successful evidence. Failure to save completed accounting
stops dispatch; no later stage is authorized by the child's seal alone.

Before `--check` or `--cleanup` uses the store, a real shared predecessor
consumer must verify, under that stage's action context:

- exact expected complete45 routing and candidate stable head/tree/freeze
  reference, the current stage's RUNNING slot, and the unique preceding
  prepare-frozen-diff slot4 with its exact command/protocol;
- the completed prepare child row is PASS/reaped/actual exit0, not timed out,
  not cancelled, no execution/log/close error, with CLEAR group proof and
  successful actual protocol result; UNKNOWN/unstarted/RUNNING or a row for
  another stage is not completion;
- the expected regular owned prepare log is unchanged at its exact bounded
  hash/path, and the completed row's seal/preparation-observation bindings
  match the actual immutable bytes, owner and original frozen stable inputs;
- preparation's recorded native/closure/readback checks really succeeded,
  rather than adopting a complete-looking seal from failure or accepting a
  new observation that describes another source/owner/tool/view.

Treat the controller's row as trusted only in the existing identity-bound,
one-dispatch, reviewed-helper evidence scope; a checksum beside arbitrary
copied content is not independent authenticity. Preserve all current ledger/
log/owner constraints; only the controller can produce its actual completed
child result. Any absent, wrong-slot, late, failed, changed-log, changed-route
or mismatched completion fails even if a syntactically complete seal exists.

**Do not require, write early, fabricate or infer `actual-controller.exit`
inside prepare/check/cleanup.** Its absence during successful intermediate
stages is expected. A supplied global exit file can never replace missing
prepare evidence. Only after the shell wrapper actually finishes must final
verification/delivery require its observed successful return, its correctly
persisted exit0 file, the full PASS ledger/logs/frozen bindings and required
external gates. Preserve wrapper-tail/tee/storage failure behavior: a later
global failure invalidates overall verification even if earlier cleanup had
legitimately completed. Cleanup is not a declaration of final delivery.

### 8.2 Actual late native check and conditional deletion

`--check` is read-only with respect to the prepared store. After section8.1,
require a new complete stable freeze check plus separately valid fresh
observations and identical full store inventory before native use.
Rehash/decompress/read every required object and repeat the same native batch/
root/diff observations under that stage's single120s action context. Source
metadata views may be temporary, but missing/changed frozen store bytes are
never regenerated or substituted. Preserve the fresh check observation and
actual eventual child result independently of the original prepare observation.

`--cleanup` runs only at its exact RUNNING slot. In addition to section8.1,
execute the actual `prior_workers(evidence, "cleanup-frozen-diff")`: require
the exact45-route ledger, actual PASS/reap/exit/deadline/cancel/group/log
evidence for **all** preceding gates and a fresh complete numeric observation.
Read the freeze envelope through the new loader. The ledger/record/log
validation, fresh source collection, inventories and local metadata-view
teardown all share cleanup's original context. A graph digest or owner nonce
does not prove lack of workers; do not patch or bypass this consumer.

Require complete stable source/tool/policy/owner/seal/inventory agreement again.
Preserve a bounded full cleanup-intent inventory and worker result before any
unlink. The real context-aware `delete_inventory` retains no-follow traversal,
bounded per-file content rehashing, exact root/parent identity and rejection
of unknown children; check cancellation/time immediately before/after every
side effect. Delete only this owned disposable store. Preserve source and
both real Git stores/indexes/refs, neighbor controls, required wheels, raw
commit anchor, all original/fresh observations and diagnostics, owner/seal,
cleanup records, reviews and historical failures.

Pre-deletion drift/unknown evidence or already pending cancellation means
**zero deletion**. Cancellation, limit exhaustion or replacement discovered
after some validated owned entries were deleted is a failed **partial
cleanup**, never atomic/successful cleanup: retain the rest and bounded
failure evidence where the original budget permits. Never unlink a substituted/
foreign entry, extend the budget to finish removal, resume, or report success
because the root happened to disappear before late failure. Private ownership
does not sandbox an arbitrary hostile same-UID writer.

No failure/cancel/network/repair retry is introduced: these are local one-shot
verification outputs, not Store operations. Interrupted preparation/check/
cleanup remains visibly failed/unknown, including an unavailable final failure
record after exhausted storage/time. Preserve unresolved evidence and worker
state. A future attempt requires an explicit reviewed owner/namespace decision;
it cannot erase or relabel this invocation. Failed source prerequisites must
be resolved/reviewed separately, not fixed by this reader.

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

**Real reused filesystem, parser and action-budget controls (PR3R2-02)**

- Execute the actual updated digest/read_json/inventory/delete_inventory and
  prior-log consumers, not mocks returning digests/inventories. A real
  instrumented descriptor/read wrapper may record/limit each request while
  forwarding the actual I/O; assert no request exceeds64KiB.
- At-limit/over-limit and growing regular files, JSON byte/depth/token/string/
  duplicate-key failures, directory fanout/inventory/traversal overflow,
  decompression/graph and cumulative subset/global exhaustion. A sequence of
  individually small reads must exhaust the shared counter rather than get
  a fresh budget per nested utility.
- Already expired action before opening/reading/creating; actual real-time
  exhaustion during repeated chunks/traversal/readback and delayed fsync/
  finalization. Native success before expiry cannot conceal later filesystem
  failure or permit a successful seal.
- Pending cancellation before actual deletion gives zero removals. Inject
  real cancellation between validated owned removals and a separate
  replacement control; assert failed partial accounting, preserved remaining/
  foreign entries and no resumed cleanup. Preserve source/index/tool/owner/
  neighbor controls and original exact-content/no-follow guards.
- Exercise failure-only finalization with remaining budget and with exhausted
  budget. No successful-looking write/late cancellation/overflow or missing
  failure record rehabilitates a seal; actual exit remains failure.
- A bounded large tool-file control demonstrates use of the reviewed finite
  tool quota, not source/blob8MiB or an unlimited exception. Actual pinned
  tool metadata/hashes remain real in collection proofs.

**Complete stable projection and independently retained observations (PR3R2-03)**

- In one new preparation-only owned fixture namespace, run two consecutive
  **real** collect operations and at least two actual unchanged check_frozen
  calls against one byte-bound synthetic freeze envelope. Create new actual
  views each time, execute real selected Git/tool observations, then perform
  actual context-aware view teardown. Only declared workspace/source/config/
  acceptance setup may be synthetic; do not stub collect, projection,
  check_frozen, native completion or deletion. Supply a genuine isolated
  fixture interpreter/venv if the existing owner/interpreter relationship
  requires it; unavailable tooling is not replaced with a canned success.
- Assert canonical stable projections/digests are equal and complete, while
  newly owned view paths/nonces, complete owner records and observation record
  hashes are genuinely distinct. Record actual inodes/PIDs; do not require
  those individual OS numbers to differ if legitimately reused. Verify every
  old receipt byte/hash is unchanged,
  all successful temporary views are gone and final-tmp is actually empty.
- Independently change source bytes/mode/file set, raw HEAD/ref/index or
  locator, preserved root/instructions, actual tool bytes/identity/version,
  helper/config/policy, permanent owner identity and accepted-review record/
  referenced bytes. Each stable-input drift must reject. Use fixture copies,
  never mutate real tools/source/review records for a negative test.
- Change a stable field while altering/removing a volatile field/reference/
  receipt hash, or remove an allegedly inconvenient stable schema field.
  Complete equality and required-schema validation must still reject.
  Conversely, valid newly owned temporary identities alone must not fail.
- Corrupt/miss a retained original or fresh observation; supply a copied old
  observation for a new collection, wrong stable relationship, failed native
  completion or unknown/unclean temporary worker outcome. Stable equality
  alone must not pass these invalid observations. A nonce-changing final
  frozen-diff owner is stable artifact drift, not an excluded temporary field.

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

- A real small `run_gates` fixture route executes prepare, later check and
  cleanup in order while `actual-controller.exit` does not yet exist.
  No prepare self-completion row is required. Forward actual child execution/
  reap and real predecessor/log/seal consumption; only explicitly declared
  source/acceptance/routing setup is synthetic, not child results or dangerous
  consumers. Preserve the original separate wrapper-tail/global-delivery proof.
- A complete-looking seal with failed/absent/RUNNING/wrong-slot/nonzero/
  unreaped/late/cancelled prepare completion, changed log or mismatched
  owner/observation/freeze/route rejects. A fabricated global exit0 file must
  not replace the missing successful prepare child.
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
state syntax, renewed/bypassed native or filesystem budgets, hidden stable
drift or falsely unequal volatile observations, prepare self/future-wrapper
cycles, index/config leakage, object substitution, escaped Git children,
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

**Authoring outcome:** only this new ignored full proposal is written by its
author. Original plans/reviews and all20 existing helper/static bindings,
historical driver and user AGENTS are preserved. Read-only source/caller,
hash and tool-size metadata inspection is not runtime verification. No
native proof, test, final gate, build, VM/container or Store operation ran;
no index/ref/object/source/helper was changed and no owned background
workers or disposable build outputs remain from this plan authoring.
