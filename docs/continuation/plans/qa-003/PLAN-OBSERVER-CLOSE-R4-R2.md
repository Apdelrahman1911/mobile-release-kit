# QA-003 R4-R2 correction plan — PROPOSED, not implementation approval

Baseline main2beb373/tree00f3acee; entire implementation r1 still unchanged and
under independent whole-diff review. Supersedes R4 after independent plan objections.
Read with approved R2/final R3. This closes
an introduced failure-composition defect; no original issue is waived or closed.

## Reanalysis and concrete root cause

`credentials.py:1069–1084` retries `fstat` on the still-owned stage descriptor when
its first ownership inspection failed. R1 added the fallible `stage-created`
observer/checkpoint at1077, but descriptor close follows the observer rather than
an unconditional finally. CredentialError/KeyboardInterrupt/other non-OSError
from that callback skips close. Outer cleanup1022–1028 only closes the directory.
Its owned stage unlink can succeed while an unlinked descriptor remains open.

Independent real-filesystem probe is in implementation-review-r1/profile_close_probe.py.
Root reran it unchanged: author-profile-observer-fd-r1.json, SHA256
3f5f04516d9f6fa5ed2aba1c58aff710934d8267f815687a9a2ff5998fa7f7c0.
Two fstat attempts, a raised stage-created observer, still-open FD with nlink0;
only fixture-owned fallback then closed that descriptor. No native commands,
credentials, Store effects or background workers. Source/inventory/AGENTS unchanged.

The actual production caller is SigningSession.profile_event → checkpoint →
_write. It can raise a typed control/ownership/bounded-write validation error,
not only OSError. Deferring default signals does not make that callback infallible.
Known inode registration in memory remains necessary for safe cleanup even when
its durable checkpoint fails; suppressing the checkpoint error is not a fix.

## Exact correction

1. Put retry-fstat + observer in a try whose unconditional finally takes the stage
   FD out of the owned slot BEFORE attempting close, exactly once. Catch/report
   close uncertainty using existing failed_cleanup semantics; never retry a
   possibly successful close or discard an observer error as success.
2. Outer installer cleanup must always relinquish BOTH still-owned raw descriptor
   and directory, including retain/quarantine, observer exception, cancelled setup
   and partial acquisition. Reuse the existing two-level close_copies helper,
   which clears each slot before close and attempts directory close even if the
   stage close raises. Catch its typed cleanup failure into failed_cleanup; no
   recursive retry of a claimed close. REMOVE the early return for retain(): skip
   only the file-mutation/observer body when retention is requested, then run the
   same unconditional close and final error check. A pending Python return must
   never bypass cleanup-failure reporting. A retain callback exception still
   unwinds through both close attempts and cannot yield success.
3. Keep inode/hash checks, stage/link journal ordering, fail-closed installation,
   exact borrowed guard and creator-PID/fork protection unchanged. Never yield or
   link after failed ownership/checkpoint/close. Retention preserves file resources
   for unresolved consumers, not open installer write handles. Other owners keep
   their own handles and lease.
4. Keep original error precedence on active failures where possible; cleanup
   uncertainty cannot produce a success result. An observer failure must not stop
   independent handle release. Unknown inode/file remains private/pending rather
   than acquiring deletion authority from its name or a confirmation token.

## Files, tests and verification

- Production: src/mobile_release/credentials.py only for this correction.
- Regression: tests/unit/test_ios_profile_installation.py plus, if clearer,
  tests/unit/test_local_signing_recovery.py (already in full/native/wheel gates).
- Standalone observer failure after initial fstat failure: real FD allocation and
  close observation; exception variants CredentialError/OSError/KeyboardInterrupt.
  Assert body/link never ran, exact FD closed before fallback, no unrelated file
  changed, handlers restored and directory handles closed. Include failing resolved
  observer/retention paths to prove the outer unconditional owner as applicable.
- Actual borrowed session composition: use real lease/session.profile_event/_write,
  inject first stage fstat failure and a real failed state-control write/validation
  at the retry checkpoint. Do not replace checkpoint with a success mock. Verify
  the FD is already closed, journal failure remains pending, original authority is
  retained, subsequent admission fails, and production recovery reconciles the
  actual surviving controls/resources without journal editing or native mutation.
- Combined close uncertainty: close may fail before effect OR close successfully
  and numeric FD be reused by a fixture-owned foreign file before error. Assert
  only one close attempt, explicit failure, foreign descriptor still usable, and
  exact fallback only after evidence. Explicitly include retained normal-body
  success with directory close failure both before effect and after a completed
  close/reused foreign FD: retained files must stay unchanged, both close cases
  must return failure (not a successful early return), and foreign handles remain
  usable. Include retention-callback failure as well.
  Retain all existing close/fork/default-signal
  tests; no assertion may equate a cleared Python field with a closed real handle.
- Rerun original independent probe; preserve its failing r1 result unchanged.
  Run all affected installer/session/cancellation/fork tests, distinct whole-diff
  implementation re-review against a revised inventory, then the complete37-gate
  frozen suite plus protected per-issue commit/PR/main CI. Any further corrective
  source change invalidates that freeze and requires relevant re-review.

## Compatibility, security, recovery, documentation and regression risks

No configuration/CLI/schema/Store/receipt/provenance/credential-scope changes.
This fulfills existing handle-cleanup promises; no new public lifecycle behavior.
Keep original abandoned-resource manual recovery where durable inode is unknown;
never remove an unrelated profile to close a descriptor leak. The principal risks
are double-closing a recycled FD, skipped directory close on a second failure,
masking failure as success, and invoking parent cleanup after raw fork. The tests
above target actual resource state, not helper call text. No new runtime dependency.
Record corrected failure/retry semantics and evidence in implementation notes;
public documentation needs no changed promise for this localized correction.
The separately identified active-native crash-matrix coverage requirement remains
under review and will be addressed before approval/freeze, not waived by R4.

No implementation before this plan's independent approval. Reviewers may require
amendment; record approval hash and exact tested diff. Continue QA-004/MRK-008/009
only after QA-003 protected delivery, then mandatory fresh entire-repository audit.
