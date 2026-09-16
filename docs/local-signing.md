# Local signing ownership and recovery

Production use is **NOT READY until** remediation verification and a new comprehensive
production-readiness audit pass;
see [preparation status](../README.md#preparation-status).

## Scope and admission

Signed iOS **build** preflight temporarily changes the macOS account's keychain
default/search list and installs an authenticated profile. An exclusive account
lease covers the inner preflight, before doctor, private validation, project
checks or preparation. Concurrent toolkit commands in different projects using
the same account fail before those operations; they do not queue, take over a
PID, or borrow another context's installed profile. Retry after the owner exits.
The outer invocation first reserves its process environment, then acquires this
account lease, then admits the project directory. The same actual cancellation
guard and original lifetime ledger span these owners.

Standalone signed `materialize_build_inputs` calls acquire the same lease before
private-input inspection or client-file changes and retain it through teardown.
An explicitly supplied lease is borrowed, not reacquired or released; another
active signing context is rejected before materialization. This admission does
not transfer project-file ownership to the account lease. A separate finite
[build-input owner](build-inputs-recovery.md) retains the project, original client
files and decoded scratch through inner signing and consumer cleanup.

Production admission requires macOS, a non-root account with equal real/effective
UID, its password-database home, and writable local APFS/HFS+ storage. A conflicting
`HOME`, unsafe directory permissions/links or unsupported native ABI/filesystem
fails closed. There is no CLI/configuration override for the home or lease path.
The internal synthetic-home test seam is not a consumer option.

Android-only, offline, online and signing `--skip-builds` paths do not activate
account-global iOS signing state and do not acquire this lease. These paths retain
their own validation. All offline/signing preflight, including skip-builds, still
holds project admission and the environment reservation; online reserves only the
environment. Independent GitHub-hosted runners have separate accounts;
Store-only jobs do not acquire this lease or receive signing assets. Release
workflow permissions, Store authorization, candidate identity and evidence schemas
are unchanged. CI-only read permissions are added for matrix execution proofs.

## Normal lifetime

The persistent mode-0700 `~/.mobile-release-signing/` directory is the lock inode.
**Never remove/recreate it**, even when idle. One randomly named `session-<32hex>/`
directory holds an immutable write-before-use intent, observed checkpoints and
the temporary native keychain directory. Controls use exclusive mode-0600
staging, fsync and inode-checked atomic replacement; stages are not authority.

The intent retains the complete original ordered search list/default, original
profile identity/hash, private directory identities and reserved stage names.
Each version-2 command generation has a monotonic sequence and fresh nonce.
Durable `PREPARED`, `ARMED` and `SETTLED` checkpoints are distinct from a request,
an attempted grant, successful execution or complete cleanup. The original
custodian reservation is bound before one-use worker-creation/tool-run grants;
an attempted or partly written grant is never replayed. Completed native
transactions can replace the keychain DB inode;
read-only commands cannot authorize that replacement. Unknown native files or
unconfirmed post-effect ownership remain pending instead of being adopted.

Cleanup observes both native preferences before and after changes:

- Restore the original default only while it still points to the owned keychain.
- Restore the original search list only while the exact owned active list remains;
  otherwise remove only the owned entry, preserving foreign entries/order/deletions.
- Detach and verify preferences before deleting the identified owned database.
- Remove only an owned unchanged profile/stage. Reused profiles are never owned.
  A foreign replacement is preserved and reported as a conflict. Same-inode edits
  or unknown stage ownership require explicit resolution.

Profile use/removal binds bounded bytes to the **same observed file**: device,
inode, mode, links, owner, size and modification/change times must agree across
inspection and the final no-follow pathname check. Access time is excluded because
reading can change it. A fresh post-stage-unlink snapshot validates admission;
equal bytes from a different inode are not deletion authority. Borrowed profiles
receive the same checks, including the last terminal recovery observation.
Identical profiles found during no-clobber linking remain borrowed; cleanup does
not inspect them again as an unrelated owned-stage identity.

An installer observation/cleanup conflict is remembered across both cleanup owners.
Other independently owned resources are still cleaned where safe, but the conflicted
name is not retried, and a later fresh read cannot silently finalize that signing
invocation. Its original session remains pending for explicit recovery. Ordinary
setup-stage inspection/removal I/O errors also retain that session, even when
the failed unlink may already have removed the stage. Independently verified
owned-file disappearance is safely absent; borrowed disappearance is a conflict.
An unknown reserved stage stays pending, while recovery can preserve a foreign
destination and finish with `recovered-with-conflict`. Fresh explicit recovery
rechecks original inode/hash; historical file metadata is not persisted authority.

A settlement fence can be published only by the original custodian, after its
actual descendants are sealed. Its exact intent/session/generation binding,
no-clobber linked names and recorded inode/bytes constrain later recovery.
There is no polling process which fabricates that fence. The account's original
locked open-file description is loaned only to custodian/anchor helpers; the
arbitrary tool and profile workers never inherit it. Exports retire before close,
and helper loans are released only after their required ownership tail settles.

If the custodian's stop crosses the anchor's already-sent producer-completion
report, the anchor latches failure and keeps the original or tighter cutoff while
awaiting the custodian's actual group-retirement confirmation. Stop alone cannot
confirm cleanup, renew time or make the command successful. Duplicate/malformed
controls, missing confirmation or unknown original waits still prevent settlement.

A self-contained completion marker survives teardown. Resumed terminal cleanup
never restores historical preferences again or forgets an original profile inode.
After safely resolving owned resources, a foreign conflict can clear the session
while still returning failure; a fresh operation snapshots the current user state.

## Status and recovery

Run these commands from any directory; no project configuration is needed:

```bash
mobile-release local-signing status
mobile-release local-signing recover --session <32hex> \
  --confirm account-signing-is-idle-and-restore-owned-state
```

`status` takes the same lock and returns sanitized JSON: `idle`, `busy`, or a
`pending` session/phase. It does not read native preferences or print saved
keychain paths/profile bytes. Exit 0 means idle; busy/pending returns 1.
Invalid/unsafe state returns the CLI's fixed error and exit 2.

Before recovery, stop **your exact** abandoned build normally and wait for its
signing/export/service work to finish. The exact confirmation asserts account
quiescence; it is not inode ownership or cryptographic authentication. Recovery
never probes or signals a recorded PID/group. A live inherited account hold
returns busy. After exclusive reacquisition, durable no-grant evidence or the
matching original-custodian fence must settle the command generation before
native reconciliation. Missing, contradictory or incomplete evidence stays
pending; an empty process listing or a lost command return cannot replace it.

Recovery reuses the original intent/identities, without credentials, a keychain
password, rebuilding, uploading or changing a Store. It reconciles normal partial
setup, profile links, native cleanup, interrupted checkpoint writes and final
control removal. It may require repeated invocation after an I/O error; it never
blindly repeats an ambiguous native mutation. `recovered` or already `absent`
returns 0; `recovered-with-conflict` returns 1. The first actual cancellation
returns 130 and leaves remaining ownership recoverable, even if cleanup later
fails. Lifetime uncertainty is still fatal to that invocation and never permits
successful recovery JSON or another operation. Without an earlier interruption,
unconfirmed resource/handler cleanup is an error (exit 2).
An error is not successful cleanup. A failure after terminal removal can leave
no session; fresh status may then be `idle` and recovery `absent`, but that does
not retroactively make the failed invocation successful.

### Exceptional owner resolution

An interrupted native transaction can leave an unrecorded inode/staging file;
an interrupted profile-stage open can precede its inode checkpoint. Absence of a
worker does not confer ownership of those files. Preserve unfamiliar content.

Use the same recovery command with `--manual` only in an interactive TTY. It
holds the account lock, prints the exact local-only session/profile paths and
waits for `recheck <32hex>`. In another window, inspect those resources locally,
retain/move unfamiliar files, and detach only this session's references using
Keychain Access. Remove/move only independently identified abandoned resources.
Recheck reruns the production ownership/absence predicates. It runs no shell or
arbitrary command and cannot force past a conflict. Wrong input, EOF or cancellation
preserves the remaining controls. Non-TTY manual recovery is rejected.
An explicit locked `recheck` is a new owner-confirmed observation attempt, unlike
the prohibited implicit retry within a failed signing context.

Manual recheck can resolve an ordinary ownership/content conflict; it cannot
override a fatal process, descriptor or signal-owner cleanup failure. Such a
failure stops the invocation before another prompt, reload or recovery attempt,
even when a producer has settled. Already-registered independent cleanup
still runs where safe; ambiguous work is not replayed. End the failed process,
establish its exact resources are idle, then recover the **same** remaining
session from a fresh invocation. A retained lease handle can keep status `busy`
until that process exits; unresolved controls otherwise remain `pending`.

Settled workers do not make an ambiguous signing operation or failed journal
safe to reuse. That original normal lease is permanently barred from new work,
including previously issued sources/scopes, even if the caller catches the
error or closes the session. Closing an opened but unfinished session also
revokes normal use, including preserved profile conflicts without a process
failure. Clean reuse requires the original session's successful disposal and
directory sync; later path absence or a snapshot reload is not that proof.
This admission rule does not invent a process-cleanup failure or suppress
independent cleanup. Recovery still needs a fresh explicitly authorized lease.

**Do not edit/delete journals to obtain clearance.** Corrupt committed controls,
unknown versions or replaced private namespaces are not interrupted staging.
Neither normal nor manual recovery can invent their lost authority; retain the
evidence and use an isolated fresh OS account/runner pending supported forensic
recovery. Never remove broad temporary-directory patterns or unrelated profiles.
Legacy version-1 controls are read-only: `status` reports unsupported legacy
recovery and neither automatic nor manual recovery silently migrates or deletes
them. A fresh recovery invocation is separately authorized and bound to the
current original controls; loading a snapshot never resets a failed live owner.

## Processes, signals and external limits

Synchronous native, Git discovery, Android build/final-copy signing, preparation,
project-check and preflight-identity commands use
a bounded native command owner, separate from the profile decoder. An outer
caller, original custodian, pinned anchor and worker separate grant, exec and
cleanup authority. Private request/result frames are local IPC, not release
attestations. Native output is discarded for builds/checks; captures are bounded
(2 MiB for private tools, up to 16 MiB for build settings). Byte arguments and the
explicit command environment are preserved without a shell. Only the intended
tool receives those inputs; helper startup uses a fixed guarded loader.

Original creator publication/join, child waits, clean stream EOFs and independent
descriptor/handler settlement are all required. Cleanup starts on failure or
deadline without waiting for a success handshake. It operates only on an owned,
still-reserved group, retiring numeric authority before consuming its leader's
wait. A frame, PID, error flag or apparent absence is not lifecycle authority.
Independent deadlines are never renewed by late results or repeated cancellation.

Offline/signing preflight stops at the first failed prerequisite, private
validation or platform build/cleanup. A later platform is not started after a
failure. Already completed outputs remain on disk but are **not** thereby
validated or approved. Static project selection inside builds does not execute
Git hooks. Independent final-artifact validators keep their separate boundary.

Unconfirmed selector, stream, descriptor, scratch or signal-owner cleanup is
fatal even when the command group is absent. Do not continue with another
command in that invocation. End it and establish that its exact resources are
idle before retrying. An early failure has no signing intent and cannot invent
one for recovery; only an original pending session authorizes local recovery.
If failure occurred after recorded dispatch, its original intent remains pending
until that session's recovery predicates pass. No automatic ambiguous retry is
added.

Online preflight remains independent: it can query ownership for an unverified
identity despite unrelated signing/build/metadata gaps, but it never runs
application commands or builds. Query-specific identity, version, credential and
material prerequisites still gate every Store request. Missing local ADC is
reported without opening private files or invoking P8 tools. Fatal command or
cleanup uncertainty stops online checks too. A passing ownership query does not
clear other failing report findings or approve a release.

Nested profile/signing/process and outer build-input owners use the same actual cancellation guard.
Default main-thread tokens allow implicit borrowing; fixed worker/custom-handler
callers forward that owner explicitly. They preserve custom/foreign handlers, reject mixed owners, and
relinquish inherited descriptors after fork without unlocking or deleting parent
resources. Profile scratch has explicit PID-bound custody, not a GC finalizer.
Custom handlers and worker threads retain host cancellation semantics.

The lease coordinates toolkit peers, not hostile same-UID programs. Uncooperating
Keychain Access/other apps have no cross-application compare-and-swap API: observed
edits are preserved, but a concurrent external read/write race cannot be excluded.
The final pathname check is not atomic compare-and-unlink; non-cooperating writes
after that check cannot be ruled out. Already-observed contradictions are rejected.
Do not modify account signing preferences during an active build. Applications
must use synchronous commands; detached/escaping background work that keeps using
signing state after its client finishes is unsupported. Ordinary idle shared
securityd, XCBuildService or Gradle services are not a failure and must not be
killed. Ambiguous in-session service completion requires truthful owner quiescence.

Hard termination/power loss cannot run local cleanup. The journal deliberately
survives for recovery; native keychain/private scratch can remain. It contains
private local paths and public profile identifiers/hashes, **not** passwords,
profile/certificate/key bytes, Store credentials or release evidence. Never commit,
upload, cache, attest or attach this directory to a report. Profile authentication
scratch outside it follows its [own cleanup limits](ios-profile-authority.md).

Project-input cleanup independently restores admitted original client-file objects
and exact modes only while its parent/backup/publication bindings remain intact.
Foreign edits are not overwritten; possibly used scratch survives unknown consumers.
If account recovery is needed, finish it first, outside the project lock, then follow
[build-input status/recovery](build-inputs-recovery.md) for the original project/session.
Project recovery never acquires the account lease. Its terminal control authorizes
residual metadata removal only, without reopening or restoring current client files.
Project pending state may contain original files/private material and must not be shared.

These prepared outer-owner changes still need their qualified verification and
delivered-source rebind. A protected non-public archive/export rehearsal with the
consumer's supported profiles and pinned Xcode remains an external activation
requirement; fictional native models and repository tests cannot establish actual
credential suitability.

## Verification

`test_local_signing*.py` covers account/process/thread/fork admission, real Darwin
ABI/flock, full-preflight borrowing, stateful native rename transactions, foreign
state preservation and production recovery. `test_local_signing_failures.py`
injects actual retained/reused descriptors, selector-close failures, detached
cleanup exceptions and handler-restoration failures through recovery/CLI, then
recovers unchanged original journals in a fresh process. The bare-home crash fixture
adds seven complementary cuts: before/after each of three successful profile-directory
creations and one partial empty-native cleanup-state write after profile resolution.
Those cuts require automatic production recovery; unexpected refusal retains the
case and fails the test. The layered matrix below owns primitive protocol I/O cuts,
semantic caller/recovery cases and the delegated regression variants rather than
duplicating each complete native lifetime at every primitive operation.
`test_owned_process*.py` plus profile resource/process tests
exercise real descendants, deadlines, cancellation, malformed frames and cleanup.
The required macOS source and installed-wheel gates include these tests without
skips; none reads a real keychain or mutates a Store.

`test_local_signing_profile_identity.py` performs actual file moves, replacements,
metadata/content edits and disappearance at stat/read/close boundaries. It exercises
both composing owners, initial/EEXIST/final admission, terminal borrowed recovery,
one-shot setup/cleanup errors, original-session recovery and stable hardlink controls.
Real-EEXIST tests validate the actual last borrowed observation and preserve owned
link cleanup when linking succeeded before its result was interrupted.

An additional mandatory layered matrix uses one source-defined coverage catalog:

- Seventeen primitive algorithm components execute every observed before/after
  edge (plus real partial writes) and the fixed failure variants, without native
  commands. These are algorithm obligations, not claims that the historical
  full-context crash inventory was replayed.
- 131 semantic cases cover explicit seeds, fresh recovery, focused conflicts,
  original command boundaries, the healthy caller-context map and three actual
  native database/lock/transaction-stage write prefixes.
- 160 Linux or 170 Darwin original-regression executions preserve 84 or 86
  original method obligations. Eighteen specialized semantic contributions reuse
  the corresponding actual semantic evidence; they are not extra executions or
  fabricated unittest successes. An original method remains pending until all
  its required variants/contributions complete.

Native cases use fictional tools with real journal/profile/filesystem effects.
Each fresh recovery process reloads the preferences and native resources left by
the killed process; it cannot invent a clean baseline. Every explicit preparation,
active, partial-restoration, pending-control, terminal and manual-recheck seed is
replayed separately, without treating equal traces as equivalent ownership states.
Cuts occur before/after actual operations and during real partial writes, including
the profile's buffered writer and native DB inode replacement. Unknown resources
remain refused until independently authorized owner resolution under the lease.
Foreign replacements and their references are preserved even by the fictional
owner; automatic success, safe conflicts and unresolved/manual outcomes are distinct.

Use the credential-free `test-signing-matrix` jobs in the reviewed `ci.yml`, not
the historical raw `--all`/`--wheel-python` launcher. `verify_ci.py` admits the
finite `signing-matrix` scope with explicit repository/commit/run/attempt/job/OS/
shard metadata and invokes each source/wheel phase through its original ordinary
Session capture. Missing metadata cannot silently select a local fallback.
Native/process suites and isolation setup must not run on a shared VPS.

Before the full matrix, the reviewed workflow's manual `signing-adapter` target
can run five fixed source/wheel checks on each disposable Linux/macOS runner:
real model-command completion, original case wait/EOF/crash/deadline settlement,
an original C-fence prefix cut followed by fresh recovery, and active-versus-pending
account exclusion, followed by the existing PREPARED/no-target original-fence and
same-lease cleanup case. `signing-adapter-linux` and `signing-adapter-macos` select
the same checks on just the named platform. It emits only adapter results, never a matrix proof or a full
CI pass. A case's original C recovery debt is registered before its seed; an
anchor/worker/group receipt alone cannot authorize deletion. Outstanding debt or
UNKNOWN must fail teardown, not merely retain files while reporting success.

Each package/shard phase has a 420-second deadline; each source/wheel pair must
complete within 900 seconds, including parsing, accounting and proof publication.
These endpoints also cover scope-specific preparation and teardown; preceding
offline-input/install/catalog gates retain their original aggregate deadline.
Independent case watchdogs cover deadlines, blocked I/O and launcher/outer-owner
death. The real case worker, not a simulated return value, exits at the selected
cut; only the original command custodian writes its genuine settlement fence.
Private two-FIFO observations identify reached effects without granting cleanup.
An observed kernel-visible write prefix is not a power-loss durability claim.
Unknown custody fails the shard and preserves paths. Original finality plus
production recovery predicates, never a recorded-PID absence check, constrain
case disposal. Expected worker exit 73 cannot authorize whole-phase residual
disposal or remove retained product UNKNOWN.

CI requires the full Linux/macOS × forty-eight-shard × source/wheel product, in addition
to the native authority/ABI checks. The phase executes only its source-defined
assignment, without a repeated native discovery prefix. Deterministic scheduling
weights are planning estimates, not measured capacity; complete packing must be
qualified before a full dispatch.

Version-2 compact proofs bind the independently recomputed catalog and assignment,
typed actual evidence, exact regression contributions, package/test hashes, OS,
shard, run, commit and producing attempt. Old version-1 proofs cannot discharge
this contract. Each case's validated evidence is persisted before identity-bound
disposal. The exact private phase output is `catalog.json`, `matrix-result.json`
and `results.jsonl.gz`; extra retained paths prevent phase success. The aggregate
checks every proof before selecting the latest
complete cell, rejects invalid later evidence rather than falling back silently,
and proves the disjoint complete executed union. Older successful cells of the
same run/commit need not be rerun merely because a sibling's attempt changed.
Raw fictional observations stay private inside the test domain; only the compact
proof is published. No credential or real binary is included. These CI records
cannot authorize a release or replace GitHub release
attestations. Local Darwin results do not imply that hosted Linux checks ran.

This modeled coverage does not prove real Apple credential suitability, asynchronous
OS-service quiescence, power-loss durability, or a consumer's Xcode build/export.
Those remain separate protected, non-public activation checks.

The verification runner gives the two positive raw-fork prerequisites (the real
model-command bridge and prepared-no-target account lifetime) fresh original
captures. This prevents earlier tests' retained native command histories from
becoming inherited state in an unrelated fixture. Production fork quarantine is
unchanged; these clean captures require ordinary cleanup and complete original
finality, never the retained-domain disposal used by intentional-UNKNOWN tests.
