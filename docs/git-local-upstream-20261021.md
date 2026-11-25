# Local Git upstream setup — source packet, 2026-10-21

## Scope and integration

This is a **local**, explicit `set-upstream` sibling of the existing GitLocal
Prepare/Check/Apply/Stop/Close owner. It does not sign in, perform HTTP, create a
remote repository/branch, manufacture a tracking OID, or run Fetch/Push. A live
GitHub connection still requires an explicit close under ordinary local admission.
The existing desktop Repository permission family also supports the action; the
Remote permission family and all five ID-only CLI verbs are unchanged.

Owned sources: four `git_repository_upstream*.py` leaves; protocol/state/Mac source
plus three `git_upstream_*tests.rs` leaves; `gitUpstreamProtocol.ts`,
`GitUpstreamSetup.tsx`, and the focused Node/Python tests (15 source/test files).
These two documents complete the 17-path packet. Shared source is PATCH ONLY:
`git-local-upstream-hooks-20261021.patch` has 33 targets. Its before/after images
and exact inventory are retained in `.task-upstream/{before,after}` and
`changed-files.json`. Final before images are current Root
`420db551a18925d759994548ef747fdff995e139`, including create-only Push and RemoteCLI.

Apply the owned leaves, then the patch, rather than replacing complete shared
files. Schema 9 is the joint existing schema: original fields, `push_new_branch`,
then typed optional `upstream`, each skip-none. Old schemas 1–8 preserve their
bytes; there is no schema 10, peer placeholder, new journal or arbitrary future
DATA. The current `Initialize {}` wire correction, `GitPushNewBranch` service
action, Push observer dispatch, Apple P12 App bindings and Remote CLI remain.
No provider/native qualification flag changes.

## Supported behavior

- A positively joined current Observe or Branches supplies the actual attached,
  born branch/head/revision/reference revision. The remote alias and canonical
  GitHub owner/repository are explicit draft input. The remote branch has the
  same name as the current local branch; URL is fixed HTTPS.
- `remote.<alias>.{url,fetch}` and `branch.<name>.{remote,merge}` are added only
  when wholly absent, or preserved when complete and identical. Partial,
  conflicting, duplicate, ambiguous/case-alias settings are refused, not repaired.
- Existing valid repository-local name/email stay unchanged. If both are absent,
  both must be explicitly supplied and reviewed. Partial identity refuses; no
  global Git/account/previous-author inference.
- At most six fixed stock-Git `config --file PRIVATE --no-includes --add` calls
  update only the original private candidate. Original config bytes are an exact
  prefix; native and Python recompute the closed canonical additions/hash. The
  complete parsed map, original mode/group and 60 KiB limit are checked. No
  chmod/chown of existing metadata, extra commands or system/global config edits.
- Required ref/reflog **parent directories only** may be created; no tracking
  reference or log entry. Existing complete config with missing parents is still
  an explicit effect. Config, identity and all parents already complete means
  **Close-only**: both GUI Apply and the actual shared CLI Start predicate refuse.
- After genuine completion, explicitly Refresh, then use ordinary Fetch with its
  existing missing-target support. No automatic query, grant, Fetch or Push.

## Original custody and ordering

1. Prepare only reads through the original registered root, protected stock Git,
   SourceBook/account/ACL and complete parent roster. Missing means genuine
   no-follow ENOENT under an actually held, rematched parent, not `None` DATA.
2. Apply retains the existing private transaction/config.lock/index.lock/HEAD.lock
   and candidate, preserving working files/index/refs. Candidate content and
   missing-parent intent are checked before any parent creation.
3. The **same existing Candidate job** performs source POST, durable original
   Candidate CAS, retains that ACK, then releases the Store mutex. Only then it
   runs the native directory operation, without holding Doc/Registry/Store locks
   and without a ninth job or waiting for worker/final-CAS completion.
4. Every fixed mkdir is prearmed in the same SourceBook before syscall. It is
   exclusive/no-follow, actual UID/GID/fs/0700 and ACL checked, then child+parent
   fsynced and forward edges/entries/currentness rechecked. Collision, failed
   acquisition, partial create, STOP or unknown cannot be adopted/retried/deleted.
5. The original <=512-byte ACK binds request, candidate, revision and SHA256 of
   the closed before-parent to final-created roster. Nested new directories may
   contain only exact planned children; leaves are empty. Python compares only
   those original paths/identities, never rescans arbitrary current metadata to
   infer a native receipt. Digest comparison grants no closure or new authority.
6. Only this matching ACK allows original config publication/fsync/full readback.
   Old config FD and actual successor FD remain separate; original unlinked FD
   exceptions require the exact private publication witness, not path absence.
   Source POST, C/A/W, jobs, final journal CAS, NativeUse and every original close
   retain their original clocks/first failure. A partial or uncertain effect
   preserves pending/candidate/custody; there is no rollback or replay.

The new source facet uses the original 45/55-second operation, local 160 MiB
admission, eight jobs, SourceBook 128 and actual `capacity + runtime_live + 32 <=
256` constraints. If `P` is the full parent-path count, its extra reservation is
`P + 5` (both chains, optional old leaves, config successor, scratch/index;
no reuse/close credit). For the ordinary `main` example, P=8 and the unchanged
roster formula is `1 + project_parts(3) + tool_parent_parts(5) + 42 + 13 = 64`
before any preexisting scope-specific extras. Longer chains must fit or refuse.

The source working quote adds `sizeof(State) + 1 MiB` through the existing full
`Sources::working_bytes`/Doc admission. Missing components <=64 and total path
bytes <=2048. Captured original names aggregate <=1024 / 32768 bytes, checked
**before retaining each parent**, including refusal paths. Per-parent strings
and vectors are compacted rather than retaining the old 4096-entry scratch
capacity for every parent. Current/candidate roster, bounded JSON/hash/config
buffers and the one existing directory-read scratch remain charged; old source
wrappers/held reviews receive no credit. No quota is raised or RSS guarantee
claimed. Existing request/candidate/ACK/output limits remain 96 KiB/4 KiB/512 B/
2 MiB; an over-limit candidate refuses before native directory creation.

## Executed evidence and limits

All author tests used public source projections, not a native/product receipt:

- **20 new inert Python tests**, 5.956 s: actual core/worker/source/ACK code using
  existing task-file fixtures and fixed fake Git/C-A-W (Popen forbidden).
  `python-worker-final.log/.exit`.
- **97 affected inert Python tests**, 18.283 s: existing local protocol/worker,
  Branch/Switch/Rename/FF/Init/Push/Remote protocol modules. `python-affected.*`.
  Total **117 unique**, not cumulative reruns.
- **12 new + 210 affected Node tests = 222**, 0 skipped, 1.609 s, actual existing
  controllers/permission codecs with inert ports. `node-final.log/.exit`.
- Whole composed TypeScript `--noEmit`: **exit 0**, `typescript-final.*`; only the
  existing retained dependency tree was linked, and the own link was removed.
- **27 Rust files parsed** with rustfmt, not compiled. Two final Rust-only source
  capacity files were reparsed after the compact-retention refinement;
  `rust-syntax-final.*` and `rust-syntax-cap.*`. No Rust test was executed.

Executed projection was Root 51740965 plus this feature. Its exact source pins
remain `.task-upstream/pre420/source-current-pins.json`. Final 420db551 rebase only
preserves the four intervening Root additions in App, service action and Push
observer hooks; no executed Python/Node feature source changed. The final
Rust-only aggregate-bound test is authored, unrun. Earlier failed logs are kept.

No real Git invocation, native SourceBook/mkdir, Store write, installed CLI,
provider call, Fetch/Push or native qualification was performed by the author.
Rust compile and the actual Mac config/parent/ACK/native lifecycle remain pending.
This is not a claim that a completed upstream exists or that remote access works.

## Exact targeted selectors for Root's existing batch

Portable Rust (7 + 2 = **9**; plain prefix filters, not `--exact`):

- `git_upstream_protocol::tests::`
- `git_local_state::upstream_tests::`

Mac DATA only (2; no IO/syscall/receipt or fixture required):

- `asset_source::macos::git_local_sources::upstream_sources::tests::attempted_or_ambiguous_directory_creation_is_not_retirement_or_retry`
- `asset_source::macos::git_local_sources::upstream_sources::tests::upstream_roster_charges_both_full_chains_and_working_originals_without_close_credit`

The protocol seven cover exact native/local-CLI wire shapes and family isolation,
actual shared CLI Close-only, original absence, config prefix, ACK identity and
private/public result separation. State two cover old schema preservation and
retained candidate/partial directories. Thus **11 newly authored Rust cases**.

New Node: `desktop/tests/git-upstream.test.mjs` (12). Affected selections used:
`git-local`, `git-fetch`, `git-push`, `git-push-new-branch`, `git-branches`,
`git-switch`, `git-rename`, `git-fast-forward`, `git-init`, `git-repository`,
`service-git-repository-permission`, `service-git-remote-permission`,
`service-git-permission`, `service-git-commit-permission` (all `.test.mjs`).
The existing package test list adds only the new literal.

New Python: `test_git_repository_upstream`, `test_desktop_git_upstream` (20).
Affected: `test_desktop_git_local_protocol`, `test_desktop_git_local`,
`test_desktop_git_branches`, `test_desktop_git_switch`, `test_desktop_git_rename`,
`test_desktop_git_fast_forward`, `test_desktop_git_init`,
`test_desktop_git_push_protocol`, `test_desktop_git_remote_protocol` (97).
No new runner, workflow, permissions or verification framework is included.
