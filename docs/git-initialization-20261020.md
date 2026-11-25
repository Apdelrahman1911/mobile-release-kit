# Local Git initialization — source packet

Tools independently approved the plan. This packet implements only initialization
of an already-selected, non-Git project. It does **not** stage files, commit, push,
download tools, change account permissions, or enable a native qualification flag.

## Existing end-to-end route

The Git panel uses the same `GitLocalController`, five RAW commands, retained
Promises/review, explicit unchecked approval, Apply, Check, Close and Stop. The new
closed action is only `{kind: "initialize"}`. There is no caller-selected branch,
tool, directory, expected Git index or fabricated GitRead observation. The native
review fixes an unborn `main` branch and SHA-1 object format. A missing GitRead
observation is **not** evidence of absence: original native Prepare must establish
that separately. Busy/unknown/read-failure gates are not relaxed.

The existing Document/root/SavedEditStamp admission, Supervisor, source/runtime
lease, Store `NativeUse`, jobs, first-failure clock and finality remain authoritative:

1. Prepare inspects the held project/ancestors and protected stock-Git identity.
   It makes no directories and executes no Git command. It refuses a present or
   case-alias `.git`, enclosing repository, submodule/bare markers, stale source,
   unsupported filesystem/layout or retained earlier initialization candidate.
2. Explicit Apply first obtains the **original durable Preparing ACK**. Only then
   the same SourceBook reserves and exclusively creates a one-attempt
   `.mrk-git-init-<32hex>` directory in the project, containing `worktree/.git` and
   an empty template. Original slots precede every mkdir/open. Collisions are
   refused, never adopted or retried; ambiguous mkdir outcomes retain custody.
3. The same protected `/Library/Developer/CommandLineTools/usr/bin/git` runs the
   fixed `init --quiet --initial-branch=main --object-format=sha1 --template=…`
   inside that private worktree, then fixed `config --file … --no-includes --null
   --list`. The final original dispatch rechecks argv, child-only environment,
   cwd and held tool/source identity. Two calls at most, at most ten seconds each,
   using the remaining original 45/55-second budget. No inherited Git config,
   identity, hooks, credential helper, protocol access or separate-git-dir mode.
4. Core and the original native candidate job capture a complete finite tree:
   seven directories and only `HEAD`/`config`. The config must be relocatable;
   worktree paths, includes, remotes, alternates and extension dependencies refuse.
   Native capture/check precedes the **original durable Candidate ACK**.
5. The same candidate is rematched; one existing no-replace rename publishes its
   held `.git` into the still-absent project destination. Attempt is retained
   before the syscall; returned move before fsync/checkpoints. Lost return, late
   result, changed source or uncertain close never becomes a retry permission.
6. Only the original joined worker's matching returned publication permits the
   native old-FD mapping to the new `.git` name. Original postchecks, source/runtime
   closes, native joins, final journal CAS and NativeUse retirement still decide
   completion. Cleanup may remove only exact newly-owned **empty private**
   directories. It never consumes the published `.git`, recursively clears a
   candidate, deletes user files, or presents a worker frame as native finality.

Failed/unknown candidates remain fenced by the existing recovery path; this slice
does not add a reset, abandon or automatic initialization retry. Apply never
refreshes GitRead or infers a current observation. The user can explicitly refresh
after a genuinely settled result. Draft/source/API changes and synchronous UI
listener reentry retire consent without discarding the original pending calls.

## Bounds and shared contracts

The existing source limit (128), complete source/runtime FD limit (256), global
census and job limits are unchanged. Init needs twelve additional **existing
SourceBook slots**: four created directories, six generated child directories and
two files. Its same admission reservation adds 1 MiB before source inspection for
the bounded 4096-entry/256-KiB name scan, 64-KiB native block, vector slots,
manifest and retained copies. Pending/unknown original charge remains unavailable,
not zero; no cleanup or worker message refunds unreturned backing.

`git_local_protocol::Request.native` becomes optional only to distinguish the
closed init native facet from the existing repository facet. Ordinary factories
still require genuine repository data. Review/intent expected-index accessors are
optional; Init uses explicit null, while old rows preserve their exact string
serialization. No public/manual native-data input or new IPC permission is added.

The same `mrk-git-operations/1` journal adds the optional `initialization` field and
schema 7 only on actual Preparing reservation. Old rows remain byte-canonical on
read and preserve fields. This patch is composed against Root **d98d6927** including
fast-forward schema 5. Fetch schema 6 is another author's pending integration:
Root must union its typed field/minimum-version gate/constructors, never replace
them or rewrite prior rows. Unknown fields/invalid pending rows are retained as
recovery, not silently dropped.

## Delivery and Root graph

Eleven owned code/test leaves plus this guide and
`git-initialization-root-hooks-20261020.patch`. The patch changes exactly 18 existing
paths: two Python worker/protocol files; GitLocal protocol/state/source/Supervisor/
Document, four affected private DATA test callers, lib and installed-observer
module rosters; existing GitLocal frontend protocol/controller/panel, App and the
existing package test literal. No shared production file was edited in this lane.

Apply the patch once to current Root, preserving Fetch6 additions. The current
normal stager's `current_core_matches` includes all `src/mobile_release/` members
and checks their exact bytes; the three Python leaves need no alternate bootstrap
or supplier. This is packaging-source compatibility, not an installed runtime
receipt. No build.rs, capability, command list or provider-path change is required.

## Actual evidence and limits

Task-local logs/manifests are in `.task-git-init-hooks/` (not delivery source).

- Current d98 + composed hooks: **46 Python tests PASS** in 4.115 s (25 Init,
  13 existing local protocol, 8 existing fast-forward). The Init fixtures use
  actual private files/held FDs/no-replace moves, but explicitly fake Git and
  C/A/W; Popen is forbidden. They check readonly Prepare, exact config/manifest,
  source/target/tool drift, lost ACK, attempted/lost move and one-use behavior.
- Current composed frontend: **91 Node tests PASS**, zero skips, in 515.388 ms
  (13 Init and affected local/rename/switch/branches/fast-forward tests).
- Full current frontend noEmit: **PASS**, original caller 67593 joined exit 0,
  max-old-space 768 MiB/120-second bound. Earlier composed checks truthfully
  caught the required fast-forward `Capture.tracking` field; Init now explicitly
  retains null. Failed logs remain. Read-only dependencies were not modified.
- Syntax only: **14 Rust files** parsed and seven Python files AST-parsed. **No
  Rust compilation or tests were run by this author.** Seven portable and two
  macOS DATA tests are authored; none creates native receipts or a fake join.
- Every test/compiler caller joined. Exact public projections and the sole
  dependency symlink/private compiler scratch were retired by manifest/inode/hash
  rematch; logs and before/after hook source remain.

Root's focused Rust selectors: `git_init_protocol::tests::` (4),
`git_local_state::init_tests::` (3), and on macOS
`git_local_sources_macos::init_sources::tests::` (2). Recheck affected original
switch/rename/fast-forward protocol tests because their private request facet is
now optional. Normal/lib/CLI/observer graphs and actual protected stock-Git init
must still be compiled/exercised by Root. No real Git, macOS, installed behavior,
credential, Store/provider, or native readiness claim accompanies this packet.
