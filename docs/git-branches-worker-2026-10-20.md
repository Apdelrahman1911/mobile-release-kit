# Local branch list/create worker increment

Scope: list local branch refs and create one **absent** branch at reviewed HEAD.
No checkout, rename, upstream, reset, delete, force, remote or provider command.
The existing GitRead and GitLocal original owners, fixed CLT provider profile,
source snapshots, C/A/W, single candidate ACK and 45/55s clock remain in use.
This packet is not an availability flag or native qualification result.

## Exact hooks

`git-branches-python-hooks-2026-10-20.patch` changes only four existing Python
worker/protocol files. It was composed from Root `736a90b5`; unrelated changes
to runtime, Store and Version owners are not included or overwritten.

* GitRead adds `branches` to its existing four-key action. It requires a current
  core revision, empty paths and `staged:false`. Only the exact branch repository
  and session types enter this read arm. The result contains revision,
  referenceRevision, HEAD/current branch, bounded `{ref,oid}` rows and the basis
  `local-refs-no-fetch`. No messages, identities, reflogs or remote URLs.
* GitLocal adds the exact tagged action `{kind:"branch-create",expectedRevision,
  expectedReferenceRevision,name}`. The required stage/unstage/commit shapes
  remain unchanged; branch actions do not gain their message/identity/path keys.
* Both Prepare and Apply perform a genuine fresh core preparation. Apply
  compares the retained complete digest and uses the existing private input's
  one-candidate ACK. A serialized plan or review does not authorize execution.
* Branch Prepare returns `{review}` only. No empty diff is fabricated.
  The ref review binds name/target, original core and ref revisions, HEAD,
  original branch/index and its private review digest.
* Branch Apply has a separate `branch-ref-returned` positive receipt label.
  The helper requires the actual transaction, exact original operation,
  acknowledged candidate and exact positive core publication object. A matching
  ref, candidate frame, old `published` bit or generic command result is not it.
  The original index remains unchanged and is still closed by its original FD
  route. The native owner must separately verify its ref-edge successor and join
  the process/source/runtime/management work before public finality.
* The only additional refusal reasons are `branch-exists`,
  `branch-parent-missing`, `branch-identity-required` and `unborn-head`. They
  remain scoped to branch creation, not an expansion of other operations.

Actual supported local `user.name`/`user.email` provide the reflog committer.
Missing/ambiguous/unsupported identity is an actionable refusal, never a guessed
application identity. Existing log policy is retained; unsupported/missing
namespace/log parents and any existing target directory or ref refuse before
publication. Empty original ref directories cannot be consumed as absence.

## Verification and remaining graph

Core source was independently reviewed, then the four authorized disposable
Linux Git fixtures passed in **147.419s**, exit0, using UID65534, fixed Git,
private HOME/TMPDIR and the original bounded runner. All original callers
returned; exact successful projection cleanup removed 15 files/7 directories.
Previous failed local-write evidence was retained. These fixtures exercise the
portable core/C/A/W path, not the native saved-command domain or Store.

The new worker's **11 passive tests passed in 3.367s**, zero skips. They use the
four complete projected parent sources plus current Root original control and
runner modules. Popen is forbidden; synthetic private files, inert Git and
explicit fake ledger entries are not native/Store/finality evidence. Tests
exercise strict old/new wire shapes, selected binding, distinct publication,
actual Read/Prepare/Apply worker paths, unchanged index FD closure and lost ACK
no-publication/no-retry. No old suites or real Git fixtures were rerun for this
worker packet.

Still required before use: Root's native tagged protocol/source/journal schema2
and renderer/controller hooks, actual graph compilation, distinct implementation
review and installed qualification. Schema1 pending rows must remain fenced;
the new target's expected absence/successor must use the same native SourceBook.
No new bootstrap or HTTP transport is needed. Switch/rename remain a later,
separately reviewed worktree/config-changing increment.
