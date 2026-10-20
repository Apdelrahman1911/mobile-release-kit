# Local current-branch rename — bounded GitLocal facet

This packet adds one action to the existing GitLocal review/Apply/Check/Stop/
Close flow. It does **not** introduce a command runner, remote operation, service
grant, source owner, deadline, database, automatic recovery or availability flag.
Root approved this scope; the Git lane confirmed disjoint local ownership.

## Supported operation

`branch-rename` takes exactly `kind`, `expectedRevision`,
`expectedReferenceRevision`, and `name`. Both revisions come from the existing
observed checkout and branch list. Old ref, current commit, index, local
committer, logging policy and configuration are captured from the actual source,
not supplied by the renderer. Prepare does not make a rename candidate. Apply
recaptures the same source and exact review before any private candidate work.

The checkout must be born, attached to the selected **loose current branch**,
and have an existing index. Old and new names use the existing conservative
ASCII branch-name parser and the same existing ref/log parent. The selected ref
must have no packed shadow. Target files, empty directories, case aliases and
prefix/config/log collisions refuse; there is no force flag. Linked worktrees,
worktree administration, sparse/unsupported layouts, active operations,
required hooks/signing and ambiguous local identity/configuration refuse under
the existing policy. The actual repository-local committer is required; no
ambient identity is invented.

Existing dirty files and staged changes are allowed and retained. The index,
HEAD commit OID, working files, other refs and upstream **values** do not change.
An exact canonical `[branch "old"]` header can become `[branch "new"]`, keeping
its values, comments and all other configuration bytes. Missing old section is
a supported **no configuration rewrite**, not a missing-state repair. Duplicate,
escaped, legacy or case-aliased branch sections refuse. Original configuration
and its candidate are at most 60 KiB; each log including its candidate is at
most 60 KiB; the unchanged index is at most 1 MiB. Existing core/native limits
still apply before these narrower checks.

Branch and HEAD logs must either both exist or both be absent with explicit
logging disabled. Missing/mismatched logs or missing log parents refuse. Existing
logs preserve every original byte and append exactly the stock rename entry
with the actual local committer and same old/new commit OID. No log is truncated
or reconstructed. Upstream settings move under the new local branch name; no
remote ref, push, fetch or server-side branch is changed.

## Original lifecycle and publication

```
existing GitRead observation + branch list
  -> explicit GitLocal Prepare -> original joined review
  -> explicit reviewed Apply
  -> same native source/clock/gate + NativeUse + durable Preparing
  -> private stock Git candidates -> durable exact candidate ACK
  -> finite original metadata publications
  -> original worker/C-A-W/source/runtime/management joins
  -> same journal final CAS + actual native-use retirement
```

The original 45-second work / 55-second finality endpoints and first-failure
contraction remain unchanged. All I/O remains in the existing original worker
and source jobs, not under Document/Host locks. The original signed/protected
Git runtime and shell/IPC/consent path are reused unchanged.

The existing LocalTransaction owns HEAD/index/config locks, scratch index and
private execution directory. The native SourceBook acquires and retains two
exact empty 0600 ref locks (old and new names), with full original-parent
comparison. Python only borrows their comparisons; it cannot unlink/close them.
Portable synthetic tests use the existing ConfigLock ownership primitive for
these two locks instead; that is not native qualification.

Stock Git is invoked **only in the owned private execution view**:

1. `branch -m -- OLD NEW`
2. If the original section exists, `config --file PRIVATE --no-includes
   --rename-section branch.OLD branch.NEW`
3. `config --file PRIVATE --no-includes --null --list`

The original argv/environment comparator, original pending command and actual
owned-process return are mandatory. No stock `branch -m` runs against the real
Git directory while its locks are held. Output is bounded; log/config bodies
and the committer never enter public result fields. Every candidate is compared
against the exact permitted transform; extra private Git changes fail closed.

After the same durable candidate ACK, the fixed positive prefix is:

| Condition | Ordered original steps |
| --- | --- |
| Existing logs | new log, old log unlink, ref move, HEAD log, HEAD, optional config |
| Logs absent/disabled | ref move, HEAD, optional config |

Each step is claimed before its syscall. New log/ref publications use the
existing no-replace syscall primitive, not a new transaction owner. The ref
move preserves its exact inode/content/mode/group and link count one. The old
log/HEAD/config original descriptors stay retained with link count zero after
their exact positive successor. Returned phase data alone grants no exception:
both Python and native source checks require the same original transaction,
review, candidate ACK, request and private returned-publication association.

The native source facet reserves its maximum additional source slots before
acquisition: `2 * ref-component-count + 19`, still inside the existing 128-slot
cap. Wrapper/path/snapshot/ref-lock backing is included in existing source
working-byte accounting. No future close/dedup credit is taken. Both ref locks
remain until the actual runtime and all other original source descriptors have
closed; only then can the original sole checked unlink/close routes retire them.
Failed rematch, uncertain syscall/close or unknown runtime retains custody.

There is no rollback, replay or blind inventory refresh. A partial known prefix
and retained candidate paths are recovery guidance, **not** a complete cleanup
inventory or proof the rename completed. An unknown/lost ACK cannot become a
second Apply. Manual recovery must use the original evidence and a Git client;
this slice does not clear an interrupted journal after restart.

## Journal and UI compatibility

Only an actual rename Preparing write introduces schema 4 in the existing
GitOperations namespace. Canonical schema 1–3 reads and rows remain unchanged;
new rename fields are omitted for old rows. A persisted candidate cannot finish
as harmless failed/cancelled. Success requires the exact final metadata step,
unchanged commit and all original joins; a mere ref move is not success.

The existing repository controller owns the project-local rename draft.
The existing local controller captures that draft, branch list, observation,
native context and API for Prepare/Apply. Source/draft/context/ABA changes retire
consent, including reentrant changes before native handoff. Reviews and drafts
are kept for explicit Close. Check/Stop and every original Promise remain on
the same controller; result-shaped DATA cannot release a pending invocation.
The new component only renders this flow. No mount effect, automatic refresh,
native selector, DOM automation or blanket CLI write permission is added.

Root's Stage/Unstage-only `Action::index` factory stays unchanged and rejects
rename. The existing five raw GitLocal commands and their permissions stay
unchanged. The helper package uses existing setuptools source discovery and
the complete `_source_package`/installed-package byte comparison; the four
new Python leaves do not need a separate packaged file allowlist.

## Files and Root integration

The branch is `task/automation-git-rename-20261020`, worktree base `35d4f37d`.
Only fourteen new source/test leaves plus this guide and
`git-branch-rename-hooks-20261020.patch` are deliverables. No existing source
file is edited in this worktree. Task-owned public source projections and logs
are under `.task-git-rename/` and are not committed.

Apply the accompanying patch **once** after the new leaves. Its seventeen
targets are the two Python GitLocal parents; Rust protocol/state/supervisor/
source parents; lib and installed-observer module rosters; two former-unknown
schema-version tests; the Stage/Unstage factory rejection table; five existing
frontend controller/protocol/component files; and the ordinary npm test list.
Captured contexts still match Root `2c63d14d`; apply-check passed. Root owns
composition with any later shared changes. No workflow, native selector,
credential, lockfile, new dependency or public service protocol changes occur.

## Focused evidence and remaining limits

Author results on the exact public-source projection:

- `PYTHONPATH=.task-git-rename/python:tests/unit python3 -B -m unittest -q
  test_git_repository_rename test_desktop_git_rename`: **21 PASS, 8.412 s**.
  Real tiny held files/FDs and the actual worker/dispatch are used; Git and
  C-A-W returns are explicitly inert and `Popen` is forbidden. Cases include
  exact upstream/config/log preservation, missing config and disabled absent
  logs, finite bounds, unexpected private changes, stale/STOP/lost ACK,
  destination collision, moved versus unlinked original FDs and partial prefix.
- New `git-rename.test.mjs`: **13 PASS, 239.590 ms**, real controllers with inert
  promises. The first run had one invalid unsorted branch-list fixture; that
  fixture was corrected, not a parser relaxation. Its failed log is retained.
- Existing Git local/branches/switch/repository tests on the same amended
  frontend projection: **83 PASS, 415.278 ms**.
- Targeted actual TypeScript noEmit graph: **PASS**, seven changed/new entry
  modules plus their real dependencies under strict original tsconfig options,
  original caller joined. One temporary dependency link and the exact owned
  compiler cache were removed after return. No dependency installation.
- New **9 portable Rust DATA tests and 3 Mac-gated DATA tests are UNRUN**.
  Own Rust formatting and five complete changed-parent syntax parses passed;
  that is not compilation. Root should include `git_rename_protocol::tests`,
  `git_local_state::rename_tests`, the original branch/switch canonical tests,
  and on Mac the nested `rename_sources::tests` in its existing affected batch.
- Whitespace and current-Root patch apply checks passed. AST/packaging source
  inspection does not qualify a wheel or installed native runtime.

No actual Git subprocess, native rename, Store, credentials, build, Cargo,
signing, network, GUI automation or CI was run by this lane. Root's graph
compilation, actual stock-Git candidate semantics and installed SourceBook/
runtime/journal/STOP behavior remain to verify before any native qualification.
In particular a synthetic appended reflog is **not** evidence of Apple Git's
actual return or the same installed operation's finality. Existing availability
flags and product readiness claims remain unchanged.
