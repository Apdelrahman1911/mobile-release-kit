# QA-003 independent combined-plan review — R2 + final R3

**Verdict: APPROVED for implementation of this combined plan.**

This is independent plan approval only. It is NOT implementation approval, a
verification pass, delivery, closure of QA-003, or an overall READY verdict.
All mandatory behavior/tests below are part of the approved plan, not optional
follow-up improvements.

## Reviewed snapshot and approved inputs

- HEAD/main: `2beb37336fa8002b69f598fe431082606368310d`
- Git tree: `00f3acee00c994e6e81470cc76e42f1f2108fcdb`
- Branch: `fix/qa-003-local-signing-lease`
- Version: 0.3.0; tracked implementation and index unchanged.
- `PLAN-R2.md` SHA256:
  `606890bf83d2276d62c5f25a149052550e37a378f6f82b5f9d4be17725582466`
- Final `PLAN-R3-SUPPLEMENT.md` SHA256:
  `8ea214ed1fef3454b9b512712c4884c8c08f48de18f3ee7315a7d5d204b227f6`

R3's explicit overrides take precedence over contradictory R2 wording. The last
normative cancellation/fork clarification was reread and is included in approval.
The originally submitted R3 hash `3c414581...` is not the approved final version.

## Independent review basis

Re-read the original finding and actual affected signing/profile/native/caller
paths during R1/R2 review. Independently reran the original current-source
synthetic overlap probe. Independently traced pinned public Apple DB atomic
transactions and native sidecars. Additional actual-filesystem and fork probes
confirmed preexisting-profile replacement and inherited-cleanup issues; evidence
and all prior refusal reports are preserved beside this report.

For this final review, read the complete R3 supplement against R2 and both prior
mandatory-correction lists, then checked the broadened caller and cleanup
contracts against unchanged source. Reviewed author-supplied synchronized real
descendant and public Darwin filesystem ABI probes and their limitations. No real
keychain, private credential/profile, Store operation or application build was used.

## Reconciliation of mandatory corrections

### 1. Correct lifetime and consumer admission

The plan now admits a signed-iOS-build preflight before any credential/native/
application work, borrowing one account lease through its nested signing context.
It excludes Android-only and nonmutating paths, rejects a second active context,
does not use a project lock, and never takes over by PID. Canonical real-account
home/UID checks, persistent no-follow directory identity, local APFS/HFS+ checks,
nonblocking actual flock and explicit fork invalidation are concrete.

### 2. Native state and resource identity

Native keychain DB identity may change only through whitelisted owned operations.
Immutable owned directory authority is separate from checkpointed DB/lock inodes.
Public-source atomic rename and .fl sidecars are accounted for; read-only queries
cannot refresh ownership. Outside-window replacement/unknown staging is preserved,
not recursively removed or silently adopted.

Complete ordered search/default observations require bounded literal parsing,
successful return and empty stderr. Creation compatibility, activation, independent
foreign changes, empty search restoration, detach-before-delete and full post-delete
readback are explicit. An observed conflict never becomes a success claim.

### 3. Process completion and service ambiguity

The fixed isolated supervisor has bounded private request/result IPC, a
pre-dispatch journal handoff, deadlines, unconditional owned-group termination,
complete terminal framing and reaped-leader/observed-group-absence requirements.
All synchronous preflight entry points are mapped, including the first preparation
before signing, effective identities and project checks. Those early read-only
operations do not require an intent whose baseline they are still collecting.

Once shared signing resources are active/intended, commands cannot dispatch
without the recorded operation/worker handoff. Proved pre-dispatch failure differs
from ambiguous post-dispatch failure. Native timeout/readback cannot silently
authorize a repeated mutation or stranded-resource cleanup.

The plan correctly does not promise to kill securityd/shared build services or
hostile escaped workers. Standard synchronous clients with idle shared services
remain supported; ambiguous in-session service work requires truthful owner
quiescence and recovery. This is an explicit external boundary, not a waiver of
ordinary cooperating descendant containment.

### 4. Practical recovery and conflict clearance

The real status/recover interface holds the same account lease and has fixed
session/confirmation requirements, no arbitrary command/home/force-reset option,
and no Store action. Exceptional manual work is held under the lock and followed
by production predicates, not journal deletion as evidence.

R3 corrects historical profile equality: a never-owned preexisting file's
external replacement/removal is preserved. After every genuinely owned resource
is resolved, cleanup can finish with a conflict result and admit a new baseline.
Demonstrably replaced owned destinations are likewise not deletion authority.
Same-inode corruption and unproven stage ownership remain conservative.

Reserved metadata stages are distinguished from native/profile resources.
Partial metadata bytes are never adopted as authority. The original committed
state controls recovery after failed checkpoint writes.

The self-contained immutable completion marker and specified teardown order
cover every ordinary stage/finalization cut point. Resumed terminal cleanup never
restores stale historical preferences. Marker-only, partially removed controls,
empty terminal directories and no-session layouts each have defined safe behavior.
Deliberate corruption of committed authority is separated from normal interrupted
writes, rather than making routine crash recovery a future unsupported feature.

### 5. Cancellation, actual ownership and fork finalization

Every profile entry without explicit cancellation uses exact active-owner
borrowing. This covers both early credential validation and later artifact
profile validation under the broader root guard. Existing two-level registered
cleanup, interrupted setup behavior and ambiguous-close nonretry rules remain.

Actual cleanup callbacks, not just lease methods, check creating PID. Child
resource copies are relinquished before inherited exact toolkit handlers are reset.
Parent scratch finalizers must not execute in child GC/interpreter shutdown.
A child cannot remove a parent's profile, change its journal/preferences, unlock
the shared flock description or kill its group.

Restoration preserves/reports a current foreign handler rather than overwriting
it. Mixed toolkit ownership is rejected; a custom TERM beside toolkit-owned INT
stays custom. Child independent admission owns a new guard, never a parent's.
The final normative clarification addresses both explicit inherited exits and
ordinary child shutdown/GC, including allocation/handoff windows.

## Required implementation evidence

The dangerous-case tests specified in R2/R3 are mandatory:

- actual full-preflight busy admission, competing processes/projects/UUIDs,
  reverse exit and retry;
- transaction-faithful native model with real rename/inode and sidecar operations,
  every unrelated preference entry preserved, partial-stderr rejection;
- production recovery driven from actual partial stage/checkpoint/terminal layouts
  at every relevant filesystem boundary, including manual recheck and interruption;
- real descendant startup/return/timeout/cancellation/parent-death tests through the
  actual preflight/private/build callers, checked before fixture cleanup;
- real signal acquisition/handoff/cleanup-dispatch tests under full borrowed
  consumer composition, plus custom/intervening-handler preservation;
- actual forked inherited cleanup and normal interpreter-exit/GC cases proving
  parent resources remain usable and no shared lock is unlocked;
- native ABI/flock and installed-wheel execution outside the repository;
- existing issuer/signature/entitlement/provenance/recovery/workflow gates retained.

Mocks must not bypass the safety predicate being tested. A stateful native model
does not prove a real credentialed Xcode export; describe that external rehearsal
boundary honestly. No production Store mutation is authorized by this review.

## Remaining scope and approval limits

No further plan-level blocker was identified after the final clarification.
Implementation must still be inspected by a DISTINCT actual-diff reviewer, tested
against adversarial probes, corrected when needed, frozen and verified with the
complete project suite before scoped protected delivery.

QA-004 remains separate and open: this plan does not claim to repair all outer
materialization scratch/client restoration or its inherited-fork obligations.
Other original findings and the fresh all-file/all-release-path audit remain
mandatory. Approval does not accept them as limitations or close any finding.

Reviewer changed only ignored review/evidence files. Source, index, refs and user
AGENTS.md are unchanged. AGENTS SHA256 remains
`7a520b569d674ad637be886c400f88d38c294b36f925595ca1f3b479526757eb`.
Reviewer-owned probes/workers/temporary files were cleaned; no build daemon was
started. Required evidence and the shared verification environment are preserved.
