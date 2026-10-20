# Local content-only branch switch: core slice

This slice extends the original GitLocal operation, not its authority. It does
not implement rename, a general checkout engine, remote operations, native
activation or a separate journal. Root integration remains mandatory.

## Supported scope and refusals

- A normal full `.git` directory; born attached HEAD and an existing different
  local target. The complete source/target tracked regular-file **path and mode
  rosters must be identical**. No add/delete/directory creation, symlink,
  gitlink/submodule, linked worktree, sparse/partial/promisor or in-progress Git.
- Index exactly equals source HEAD; every tracked file's actual bytes equal its
  source blob. No staged changes, hidden assume-unchanged/skip-worktree changes
  or dirty tracked files. Ignored/untracked entries are preserved, not staged,
  removed or stashed. Applicable existing ancestry and affected-parent names
  are checked before every possible checkout/publication.
- At most256 tracked files,8 changed files,8MiB compared bytes,1MiB index,
  256 parents,512 preserved direct entries and60KiB existing HEAD reflog.
  Changed ordinary file modes must be0644/0755. Shared-repository mode and other
  unsupported policy use the user's Git client; they are not silently changed.
- Required/executable hooks including post-checkout, signing, filters, text/EOL,
  ident or encoding conversions and LFS pointers refuse. Both worktree and
  cached attributes are checked. Then a private highest-priority fixed
  no-conversion attribute rule closes configuration/attribute execution races.
  This does not claim repository hooks were executed or their policy satisfied.
- Reflog identity comes only from the exact supported original local identity
  validator. No ambient/global identity or invented MRK identity. Existing log
  content remains private and unchanged as a prefix; log creation policy is
  retained. Missing original log parents are unsupported.
- An empty **non-executable**0666-mode probe in the original private scratch
  must be created0644. This detects restrictive read/write masks before Git
  checkout. The operation never reads by changing or sets process/global umask.
  Existing C/A/W inherits the same mask. Final complete permission bits are
  still checked; a later/unexpected mismatch is not success.

Sensitive-path/content refusal is bounded heuristic protection, not proof that
arbitrary repository content contains no secrets. No raw contents, reflogs,
local committer identity or absolute repository paths enter the public review.

## Exact original transaction

1. Native Apply must already own its publisher, current project/session, exact
   one-use review/consent and persisted Preparing row. This core does not open
   the Store or fabricate a NativeUse. All calls share original45/55 endpoints.
2. Retain original config/index/HEAD controls. The SAME native SourceBook owns
   the exact target ref lock through final source closure; Python receives a
   comparison-only `BorrowedTargetLock`. Portable core fixtures use the small
   `TargetLock` route instead; it is not a native nomination.
3. Retain the read facet's immutable private reference/config view. A second
   bounded execution view and execution index use stock Git without conflicting
   with the original locks. Objects/worktree are the admitted original inputs;
   no executable original config is loaded by these commands.
4. Fixed `read-tree -m OLD TARGET` computes the exact candidate index, verified
   by fixed `ls-files --stage -z`. Fixed `symbolic-ref -m` computes candidate HEAD
   and the MRK reflog entry using the original identity. Reset **only this
   operation's private execution HEAD/log/index**, never originals. Candidate
   index stat hints can be stale; its complete target entry roster is verified.
   No handwritten Git object/index/reflog serializer is introduced.
5. The SAME row's single candidate ACK binds old/new refs/OIDs, expected and
   candidate index, HEAD and log hashes, review and worktree footprint. Check
   owner/STOP/current inputs again after ACK, immediately before effects.
6. Exactly one stock `switch --no-guess --no-recurse-submodules
   --no-overwrite-ignore -- NAME` in the private execution view performs the
   bounded worktree content change. Positive command return is followed by exact
   bytes/mode/ancestry/preserved-name checks, fsyncs and repeated comparisons.
   Private execution metadata is not blindly published/adopted.
7. Publish only the exact pre-ACK candidate `logs/HEAD`, then `HEAD`, then index
   through their held locks. Before each rename, recheck originals and STOP.
   After rename, directory fsync/close and exact named/held inode/content/parent
   checks must return before a positive metadata receipt exists. Source-view
   HEAD/cache updates admit only this exact positive successor.
8. A `CheckoutReturn`, metadata receipt or candidate-shaped frame is comparison
   evidence, **not native/process/journal finality**. The original worker/native
   joins and final same-row CAS remain mandatory before public success.

The candidate HEAD log uses stock Git's fixed `MRK: switch to reviewed local
branch` entry, not guessed timestamps or committer fields. The private switch's
own checkout entry is separately checked; no timestamp equality is assumed.
Same-tree switching still performs and verifies HEAD/reflog/index publication.

## Partial outcomes and original closure

Fixed phases distinguish candidates-ready, checkout-entered/returned,
log-published, head-published and index-published. A failure after candidate ACK
retains private candidates and phase for explicit recovery; no automatic
rollback, repeat checkout or retry. Known partial worktree/log/HEAD changes may
remain. An uncertain command, rename, postcheck or close is absorbing UNKNOWN.
Never turn matching target bytes or HEAD into a positive returned operation.

Old source descriptors must remain held and readable through each positively
proved successor, then receive their **own** one-attempt close. The native
switch extension must not replace old descriptor slots with new ones. The
target-lock last closure is separate: after other originals are known closed,
check held lock/parent, unlink once, check same parent plus named absence, only
then attempt the final close. An ambiguous unlink/postcheck retains the FD;
an ambiguous close is never retried. Python cannot release a native lock.

Ordinary Git locks coordinate ordinary Git writers, not arbitrary editors or
hostile same-UID namespace/ABA changes. Immediate checks and fixed postconditions
detect observed drift but are not an atomic exclusion guarantee for unmanaged
concurrent writes. No stronger claim is made by this bounded cooperative scope.

## Files, shared hook and validation scope

New core leaves: `git_repository_switch.py`, `git_switch_transaction.py`.
`git-switch-core-hooks-20261020.patch` extracts the **unchanged** local identity
validator from existing branch creation; old logging behavior is unchanged.
No shared parent has been edited in this worktree.

`test_git_repository_switch.py` contains only new inert private-file/fake-Git
tests; Popen is forbidden. Cases cover policy/roster/bytes, one ACK, same-tree,
ignored/untracked preservation, STOP/drift, private candidate tampering, strict
mode and077 pre-effect refusal, partial publication, lost fsync/close return,
positive-receipt ordering, retained old index and comparison-only native lock.
They do not prove stock Git semantics, native source admission or finality.

`test_git_switch_owned.py` covers exactly4 real Git cases: content switch
preserving ignored/untracked bytes; dirty/staged refusal; stale target/foreign
lock refusal; same-tree HEAD/log/index. **All4 passed on Linux in187.340s after
distinct source/safety acceptance and Root authorization** (author `d9f5f338`,
unchanged dependencies plus the exact identity-extraction hook). The original
caller joined with exit0 and the successful private projection was retired;
prior failures remain retained. The28 passive cases also passed. This is not
Mac/native/Store qualification. The run used the prior public-source projection,
UID/GID65534, cleared groups/caps/no-new-privs, env-i, fixed Git/Python,0700 HOME
and TMPDIR, core dumps off. Explicit022 creation mask only for this private
test invocation. The old120s fixture/160calls/5s call,45s action and600s outer
bounds remain. Every actual child must join; only passing exact-inventory
fixtures/projection are removed. Failed/unknown originals and evidence remain.

Worker/public protocol, same-row schema3, original native switch source child,
receipt-bound postcheck/last target-lock close and UI arms are a separate next
packet. Nothing in this core packet enables them or changes availability.
