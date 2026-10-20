# Fixed Fetch worker and private helper — source handoff

This is the cohesive Python half of the accepted stateless Fetch plan
(`22efc84c…`). It is **not an available native Fetch route**. Root's original
GitLocal/Connection/SourceBook/Store/runtime integration and an actually
nominated CLT Git remain required. No real remote or credential was used.

## Supported operation

One selected existing GitHub HTTPS remote and full branch, ordinary full SHA-1
`.git` directory, existing tracking-ref parent. Prepare performs a real metadata
request; Apply rechecks the same reviewed advertised OID and makes one bounded
isolated fetch. Equal-tip Prepare remains a held review; Apply refuses before
object or network work. No tags, prune, FETCH_HEAD, local HEAD/index/worktree
change, push, merge, LFS or submodule transfer.

The existing GitRead/Local policy/currentness and frozen all-command view are
reused. Original hooks/hooksPath, signing, filters, alternate/shallow/partial
layouts and ambiguous remote configuration are refused, not run or silently
overridden. The reflog uses the supported existing local identity, never an
invented committer. Reference publication is one standard expected-old
`update-ref --no-deref`, with no conflicting custom selected-ref lock held.

## Actual process/HTTP ownership path

`git_remote_bootstrap.py` enters `desktop_git_remote.py` under the existing
SavedCommandInput/DefaultCancellation/CleanupScope owners. Ordinary fixed Git
commands use unchanged `run_owned`. Only its one metadata/fetch command uses the
already-reviewed original map-v2 C/A/W path and W CORE0/FSIZE32MiB effect.
`docs/git-fetch-worker-hooks-20261020.patch` adds exactly the closed GitRemote
domain/type/command-validation arms to two shared Python files, plus the narrow
GitRemote-only failure observer in the existing HTTP transport. It changes no
ordinary process runner, cancellation owner or other HTTP profile.

`_git_remote_input_channel.py` retains both real socketpair leases before
validation, uses the existing native Acquisition/call/close ledger, and binds
the exact OriginalChannel to this input and one command. There is no listener,
UID-as-capability, generic `pass_fds`, new thread or process owner. Get is spent
before currentness/token access; store/erase are bounded discard operations.
The selected token arrives only on the original native-private GO and inherited
FD8. It never enters argv, environment, a file, normal output or errors.

The shipped helper advertises only `stateless-connect git-upload-pack`. It
reuses the same GitHub `_make_live_exchange`/TLS/CA/clock owner and the accepted
finite v2 firewall. The streaming destination is the same helper-to-Git pipe,
not a third pack spool. The helper's original 0/1/2 are closed once; FD8 is raw
borrowed only (no duplicate, socket wrapper/destructor or explicit close).
The helper bootstrap calls `_exit` after its private returned frame, with no
ordinary buffered flush or atexit work after that frame.

The <=512B returned frame binds the original request and reports only helper
HTTP/ordinary-IO outcome, its original first-F/cleanup clock, and the existing
private HTTP control fields. The parent
merges an earlier helper F before final drain/close; receipt time cannot renew
the window. Missing, future-clock, late, partial, duplicate, trailing or unknown
return is non-success even if stock Git returns zero. The same aggregate8KiB
parser handles polling and final drain. Actual C/A/W return must precede the
original client close; all-copy EOF and the original peer close are additional
requirements. None is inferred from Git exit or the returned frame alone.

The same helper Entry records fixed HTTP/body/STOP failure before the shared
transport's response/connection finalizers, including stdlib early-close paths.
Converted failure results cannot delay the first F until after a slow close.
Observer error/reentry still attempts every original sole close and remains
unknown; no raw exception text, body or credential enters this callback.

Python private copies are bounded, **not claimed zeroized**. The actual native
Connection still owns credential/account/repository/consent/currentness and
must keep its original backing through the complete operation.

## Objects, durable candidate and publication

`git_fetch_transaction.py` creates one same-filesystem private bare view with
empty ODB and two fixed quoted `/bin/sh` exec entries. Native must admit that
shell, exact bundled helper/Python/core/CA and original protected Git; paths are
comparison DATA, not an executable admission. No remote-https or alternate
helper is present in the private executable roster.

The stock command is fixed `fetch --keep`, one refspec, no tags/submodules,
automatic maintenance, commit-graph or FETCH_HEAD. Source-selected Git has one
index-pack and at most one pack+idx inode, each under W's32MiB file limit, plus
bounded fixed metadata. The native staging reservation is80MiB; a postscan is
not its enforcement mechanism. The source-selected behavior still needs an
actual matching CLT nomination. This is not a hard RSS limit or a general
untrusted-Git disk sandbox.

The exact output roster, owned file descriptors/hashes, fixed `verify-pack`,
strict full `fsck`, selected commit and bounded tree are verified before the
candidate. One SAME-row candidate ACK follows the private command's real
return, and precedes every original pack link. The native SourceBook must then
create/fsync the exact O_EXCL keep marker; Python receives comparison DATA,
never authority to close/unlink that native descriptor. Original pack/index
publication is no-clobber hard links with exact inode/nlink checks and fsync,
followed by expected-old tracking-ref CAS and actual ref/reflog durability.

Only positive returned publication/close checkpoints produce receipt DATA.
Unknown links/closes/CAS remain unknown, even if matching bytes appear later.
Known partial effects preserve their phase and <=5 relative recovery paths;
there is no retry, rollback, automatic cleanup adoption or repair endpoint.
Late STOP/source-post refusal after a returned core result becomes joined
recovery DATA, never success or a false no-effect cancellation. Native source
postchecks/joins/final CAS remain separately mandatory.

## Native integration still required

* Same GitLocal five RAW calls/public context and Publisher reservation, exact
  selected Connection/current consent/one-use review (no new public endpoint).
* Preparing-before-GO and Fetch6 candidate/final CAS in GitOperations, preserving
  FF5/legacy rows and all pending/unknown rows; ordinary reads do not upgrade.
* Actual SourceBook pack/ref/log footprint, keep creation/ACK and exact positive
  successor exceptions; source POST, same runtime/management joins, remaining
  source closes, sole keep unlink/postcheck/last close under original45/55.
* Exact bootstrap/helper/CA/CLT/shell runtime roster, protected source nomination,
  private zeroizing native GO writer, original FD/census admission and outcome
  finality. Parent channel8MiB and helper-call backing16MiB are fixed conservative
  reservations, not permission to widen existing owner quotas implicitly.
* SetupUI's separately reviewed Fetch frontend targets unchanged public protocol
  SHA4a06b41a. Its mount remains held until this native path genuinely exists.

## Focused evidence

All tests below are inert composition/FD-on-task-files tests: fake Git PACK and
C/A/W/HTTP replies, no socket, native resource effect, real Git or credentials.
No native/finality/Store/source nomination is established by them.

| Selected cases | Result | Retained task evidence |
| --- | --- | --- |
| Core25 + metadata3 + private request11 |39PASS7.990s|`fetch-core-protocol-inert-v3`|
| Worker/control13, including late STOP/unknown closes |13PASS8.075s|`fetch-worker-terminal-inert-v2`|
| Private channel19 + helper entry9 |28PASS0.177s|`fetch-return-clock-inert-v2`|
| Borrowed FD/actual short-write loop4 |4PASS0.004s|`fetch-helper-borrowed-io-inert-v1`|
| Earlier HTTP failure amendment:7 new +13 affected |20PASS0.260s|`fetch-failure-clock-inert-v3`|

The original84 cases and this overlapping20-case amendment were selected
separately, not a full suite. All actual callers joined. Logs and exits are in
`.task-git-local`; two initial amendment fixture errors (mocked factory and
shadowed module alias) remain recorded, corrected without production relaxation.
Native/Cargo/real-Git Fetch remains unexecuted. The exact source manifest and
three parent before/after pins accompany this handoff.

## Private HTTP control successor

`git_remote_control.py` conservatively merges the existing four-field private
control grammar: minimum canonical expiry DATA, maximum cooldown, blocked OR,
and sticky fatal refusal. A cooldown plus another refusal is response-invalid,
not an invalid unauthorized+delay tuple. The original live HTTP owner still
emits null expiry and rejects expiry headers; this adds no new clock/parser.
The same <=512B helper return and <=32KiB worker terminal carry this control
separately from cleanup-unknown. Malformed/late/duplicate control cannot erase
known cooldown or restore success, EOF, close, or native finality.

The same private exchange supplies `_git_remote_control` before its original
finalizers. GitRemote alone parses validated header control in FixedResponse
before stdlib can close inside getresponse; response processing reuses that
single original wall sample. Known refusal does not start an error-body read.
The same first-F observer is notified before an early close, never at a later
receipt time. Callback error/reentry cannot skip either original close and
becomes unknown. Actual selected-account/repository mismatch is folded into
the transport's retained control, not only its top-level error. Other profiles
retain their original defaults and cannot supply these private callbacks.

Native composition must consume it only from the exact original joined ticket
and use the existing Connection `apply_control` at the actual settled Instant.
No renderer field, restart row or public result grants this authority. That
native composition remains unfinished in this source handoff.

Successor evidence: twelve new inert merge/helper/channel/terminal and actual
factory cases pass (0.144s), including wrong identity, 429 plus response/socket
close failure, stdlib early close, callback error/reentry, one wall sample and
worst-valid control within512B. Twenty-four directly affected earlier-failure,
helper/borrowed-IO and original-factory cases pass (0.265s). Earlier unchanged
channel/entry/codec39PASS0.198s is reused, not a new full-suite run. All actual
callers returned0; no sockets/native/network/Git/credential operations were
performed. The initial eleven-case run's early-close failure remains recorded;
the one-sample header fix addresses it without relaxing custody or deadlines.
