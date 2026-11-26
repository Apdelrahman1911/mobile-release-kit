# Content-only switch: fixed GitLocal worker amendment

This is the worker part of the approved clean content-only switch. The native
SourceBook, private request factory/publication witness, existing journal and
Desktop arms are a separate required successor. Nothing here enables a route,
adopts a caller's tool/path, or qualifies a native operation.

## Exact composition

`git-switch-worker-hooks-20261020.patch` changes only
`_desktop_git_local_protocol.py` and `desktop_git_local.py`. It adds one tagged
`branch-switch` arm, preserving each old action's exact required fields. The
same five RAW commands, original operation class, SavedCommandInput, C/A/W
runner, candidate ACK and 45/55-second endpoints remain in use. There is no
additional engine, process role, credential access or public command endpoint.

The switch-only private request includes required `switch: null` for Prepare;
Apply includes native-captured target-lock/parent comparisons, the old HEAD log
(or exact absence), and at most eight changed-file snapshots. These projections
do not create native authority. The future native source child must mint them
from the same retained joined review after Preparing and before GO. Python
does not acquire, remove, close or take over the native lock.

Apply makes one actual fresh core capture, compares the complete retained
review and sealed originals, and invokes the existing switch transaction with
its same one-use owner. Four fixed private transaction commands are admitted:
`read-tree`, `ls-files`, `symbolic-ref`, `switch`. Ordinary bounded source and
policy reads still use their original fixed Git commands. The worker calls the
transaction's returned-command hook only after the real pending command and
C/A/W ledger returned, before the original source postcheck; a shaped process
result alone cannot satisfy that route.

## Original descriptors, partial effects and finality

The new source facet merely adds slots to the original GitLocalOperation's
existing acquisition and one-attempt close roster. A positive checkout or
metadata publication receipt may admit a separate successor FD. Its old FD
remains held, with exact original bytes, mode, owner, size, mtime and inode;
only the actual operation's unlink changes nlink/ctime. Matching a new named
file without that receipt refuses. No inventory is reset and no old FD is
reopened or discarded. The target-ref lock remains comparison-only through all
Python cleanup, for the native SourceBook's separately joined final close.

Apply results add fixed `effectPhase` and at most five project-relative retained
candidate paths. A known partial checkout/HEAD-log/HEAD publication is
`recovery-required`, never success and never an automatic retry or rollback.
These paths name only the original `.git/mrk-git-*/` fixed candidates; no raw
contents, author identity, stderr, absolute paths or arbitrary recovery targets
cross the public result. Candidate/scratch contents remain on disk when the
core intentionally preserves a known partial operation. Uncertain commands,
publication/close failures, or STOP whose effects lack the required positive
native witness remain Unknown. Existing ControlClosed cancellation proof is
not widened to authorize any publication.

`switch-index-returned` is necessary but insufficient for success. The original
native child wait/EOF/IO/source/runtime/driver/watchdog jobs, final journal CAS,
NativeUse retirement and publisher settlement still determine finality.

## Verification

- Core6: `d9f5f338bcf5be82aefa44c0c02cf0c805bf9604`, distinct Tools source review.
- Core's 28 passive tests passed. Its separately authorized four real disposable
  Linux Git cases passed in 187.340s; exit 0, caller joined, exact successful
  nonroot source projection removed. These are not Mac/native qualification.
- New worker/codec **16 passive tests pass in 7.274s**, zero skips. Tests load
  the actual two patched parent sources and actual accepted identity helper,
  use disposable files and the original worker/control call paths, forbid Popen,
  and explicitly substitute inert Git replies/ledger facts. No native or
  process qualification is inferred. Old suites were not rerun.
- Regressions cover old exact shapes, lock/source bounds, fresh-review binding,
  four private calls, one ACK, old FD preservation/sole close, absent log,
  same-tree metadata, lost ACK, post-ACK STOP, missing C/A/W return, unreceipted
  replacement refusal, and known partial phase/candidate retention.
- Initial passive failures were test assertions only: the original read-source
  validator uses its own fixed ProtocolError, and a command-roster assertion
  initially sat in the Prepare test. Both logs remain; production checks were
  not weakened. Rust/native/Store/UI successor validation remains pending.
